#include "tracing_internal.h"

#include <dlfcn.h>
#include <fstream>
#include <iomanip>
#include <limits.h>
#include <link.h>
#include <malloc.h>
#include <math.h>
#include <ostream>
#include <pthread.h>
#include <shared_mutex>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

namespace memtrace {

thread_local bool t_allocation_in_map = false;
thread_local const void *t_stack_end = nullptr;
storage *storage::s_storage = nullptr;
bool storage::s_use_memory_tracing = false;
bool storage::s_usable_size = false;
bool storage::s_unw = true;

// Jenkins hash function
uint64_t hash_32(uint64_t key)
{
    uint32_t a = static_cast<uint32_t>(key);
    a = (a+0x7ed55d16) + (a<<12);
    a = (a^0xc761c23c) ^ (a>>19);
    a = (a+0x165667b1) + (a<<5);
    a = (a+0xd3a2646c) ^ (a<<9);
    a = (a+0xfd7046c5) + (a<<3);
    a = (a^0xb55a4f09) ^ (a>>16);
    return a;
}

// two different hashes required to better hashing after slicing
static uint64_t hash_32_small(uint64_t key)
{
    uint32_t a = static_cast<uint32_t>(key);
    a = (a + 0x7ed55d16) + (a << 12);
    a = (a ^ 0xc761c23c) ^ (a >> 19);
    return a;
}

bool stack_view::operator==(const stack_view &sv) const
{
    if (m_length != sv.m_length) {
        return false;
    }

    // empty stacks
    if (m_length == 0) {
        return true;
    }

    // skip the latest frame
    uint64_t lenght = m_length - 1;
    for (uint64_t i = 0; i < lenght; ++i) {
        if (m_stack[i] != sv.m_stack[i]) {
            return false;
        }
    }
    return true;
}

uint64_t stack_view::get_hash_value() const
{
    if (UNLIKELY(m_length == 0)) {
        return 0;
    }

    // skip the latest frame
    uint64_t half = ((m_length >> 1) == (m_length - 1) ? 0 : (m_length >> 1));
    return hash_32(m_stack[half] ^ m_length);
}

uint64_t stack_view::get_small_hash_value() const
{
    if (UNLIKELY(m_length == 0)) {
        return 0;
    }

    // skip the latest frame
    uint64_t half = ((m_length >> 1) == (m_length - 1) ? 0 : (m_length >> 1));
    return hash_32_small(m_stack[half] ^ m_length);
}


void statistics::add_allocation(uint64_t size)
{
    m_all.fetch_add(size, std::memory_order_relaxed);

    uint64_t in_mememory = m_in_memory.fetch_add(size, std::memory_order_relaxed) + size;
    uint64_t peak = m_peak.load(std::memory_order_relaxed);
    while (in_mememory > peak) {
        if (m_peak.compare_exchange_weak(peak, in_mememory, std::memory_order_relaxed, std::memory_order_relaxed)) {
            break;
        }
    }
}


uint64_t storage::get_slice(void *ptr)
{
    uint64_t hash = reinterpret_cast<uint64_t>(ptr);
    return hash_32(hash) % s_slicing_count;
}

uint64_t storage::get_slice(stack_view sv)
{
    return sv.get_small_hash_value() % s_slicing_count;
}

void storage::alloc_ptr_i(void *ptr, stack_view &sv, size_t size)
{
    stack_info *info = nullptr;
    uint64_t map_number = get_slice(sv);

    auto &map = m_storage[map_number];
    {
        // uint64_t hash = sv.get_hash_value();
        std::shared_lock<std::shared_mutex> lock(m_mutexes[map_number]);
        auto it = map.find(sv);
        if (map.end() != it) {
            info = it->second;
        }
    }

    // double lock and double find in the worst case.
    if (!info) {
        // allocate trace
        info = new stack_info(sv);
        sv = info->get_stack_view();

        std::unique_lock<std::shared_mutex> lock(m_mutexes[map_number]);
        auto [it, emplaced] = map.try_emplace(sv, info);
        if (!emplaced) {
            delete info;
            info = it->second;
        }
    }

    if (s_usable_size) {
        size = malloc_usable_size(ptr);
    }

    m_statistics.add_allocation(size);
    info->add_allocation(size);

    uint64_t ptr_map_number = get_slice(ptr);
    std::unique_lock<std::mutex> lock(m_pointer_mutexes[ptr_map_number]);
    m_pointers[ptr_map_number][ptr] = {size, info};
}

void storage::free_ptr_i(void *ptr)
{
    pointer_info ptr_info;

    // find an allocation
    uint64_t map_number = get_slice(ptr);
    {
        std::lock_guard<std::mutex> lock(m_pointer_mutexes[map_number]);

        pointer_map_t &map = m_pointers[map_number];
        auto it = map.find(ptr);
        if (map.end() != it) {
            ptr_info = it->second;
            map.erase(it);
        }
    }

    // if the allocation happens after tracing start
    if (ptr_info.sinfo) {
        ptr_info.sinfo->add_free(ptr_info.size);
        m_statistics.add_free(ptr_info.size);
        return;
    }

    // if the allocation happens before tracing start
    std::uint64_t size = malloc_usable_size(ptr);
    m_statistics.add_free_no_alloc(size);

    uintptr_t stack[s_max_stack_length];
    stack_view sv = s_unw ? get_stack_unw(stack) : get_stack(stack);

    stack_info *info = nullptr;
    map_number = get_slice(sv);

    auto &map = m_free_storage[map_number];
    {
        // uint64_t hash = sv.get_hash_value();
        std::shared_lock<std::shared_mutex> lock(m_free_mutexes[map_number]);
        auto it = map.find(sv);
        if (map.end() != it) {
            info = it->second;
        }
    }

    // double lock and double find in the worst case.
    if (!info) {
        // allocate trace
        info = new stack_info(sv);
        sv = info->get_stack_view();

        std::unique_lock<std::shared_mutex> lock(m_free_mutexes[map_number]);
        auto [it, emplaced] = map.try_emplace(sv, info);
        if (!emplaced) {
            delete info;
            info = it->second;
        }
    }

    info->add_free(size);
}

storage::storage()
{
    for (size_t i = 0; i < m_pointers.size(); ++i) {
        m_pointers[i].reserve(s_pointer_map_reserve);
    }

    for (size_t i = 0; i < m_storage.size(); ++i) {
        m_storage[i].reserve(s_allocation_map_reserve);
    }
}

void storage::clear()
{
    // do not clean maps during tracing
    if (s_use_memory_tracing) {
        return;
    }

    for (size_t i = 0; i < m_pointers.size(); ++i) {
        std::unique_lock<std::mutex> guard(m_pointer_mutexes[i]);
        m_pointers[i].clear();
    }
    for (size_t i = 0; i < m_storage.size(); ++i) {
        std::unique_lock<std::shared_mutex> guard(m_mutexes[i]);
        for (const auto &[view, info] : m_storage[i]) {
            delete info;
        }
        m_storage[i].clear();
    }

    m_statistics.clear();
    m_shared_data.clear();
}

void dump_uint64_t(std::ostream &strm, uint64_t data)
{
    strm.write(reinterpret_cast<const char *>(&data), sizeof(uint64_t));
}

void dump_uint8_t(std::ostream &strm, char data)
{
    strm.write(reinterpret_cast<const char *>(&data), sizeof(uint8_t));
}

void storage::dump(std::ostream &strm) const
{
    dump_uint8_t(strm, 'v');
    dump_uint64_t(strm, m_version);

    bool usable_size = s_usable_size;
    dump_uint8_t(strm, usable_size);

    // dump statistics
    dump_uint64_t(strm, m_statistics.get_now_in_memory());
    dump_uint64_t(strm, m_statistics.get_all_allocations());
    dump_uint64_t(strm, m_statistics.get_memory_peak());
    dump_uint64_t(strm, m_statistics.get_free_no_alloc());

    time_t dump_time = std::time(nullptr);
    dump_uint64_t(strm, m_shared_data.start_time);
    dump_uint64_t(strm, dump_time);

    uint64_t ptr_count = 0;
    for (uint64_t i = 0; i < m_pointers.size(); ++i) {
        std::unique_lock<std::mutex> lock(m_pointer_mutexes[i]);
        ptr_count += m_pointers[i].bucket_count();
    }

    // TODO: abseil is replaced by std::unordered map
    // From abseil documentation.
    // The container uses O((sizeof(std::pair<const K, V>) + 1) * bucket_count()) bytes.
    uint64_t ptr_overhead = ptr_count * (sizeof(std::pair<void*, pointer_info>) + 1);
    dump_uint64_t(strm, ptr_overhead);

    uint64_t frame_count = 0;
    uint64_t stack_count = 0;
    for (uint64_t i = 0; i < m_storage.size(); ++i) {
        std::shared_lock<std::shared_mutex> lock(m_mutexes[i]);
        for (const auto &[_, info] : m_storage[i]) {
            frame_count += info->get_stack_view().get_length();
        }
        stack_count += m_storage[i].bucket_count();
    }
    uint64_t stack_overhead = (frame_count * sizeof(void *)) + (stack_count * (sizeof(std::pair<stack_view, stack_info *>) + 1));
    dump_uint64_t(strm, stack_overhead);

    for (size_t i = 0; i < m_storage.size(); ++i) {
        std::shared_lock<std::shared_mutex> lock(m_mutexes[i]);

        for (const auto &[sv, info] : m_storage[i]) {
            uint64_t size = sv.get_length();
            if (0 != size) {
                strm.put('m');
                dump_uint64_t(strm, info->get_alloc_size());
                dump_uint64_t(strm, info->get_alloc_counter());
                dump_uint64_t(strm, info->get_free_size());
                dump_uint64_t(strm, info->get_free_counter());
                dump_uint64_t(strm, size);
                strm.write(reinterpret_cast<const char *>(sv.get_stack_ptr()), sizeof(uint64_t) * size);
            }
        }
    }

    for (size_t i = 0; i < m_free_storage.size(); ++i) {
        std::shared_lock<std::shared_mutex> lock(m_free_mutexes[i]);

        for (const auto &[sv, info] : m_free_storage[i]) {
            uint64_t size = sv.get_length();
            if (0 != size) {
                strm.put('f');
                dump_uint64_t(strm, info->get_free_size());
                dump_uint64_t(strm, info->get_free_counter());
                dump_uint64_t(strm, size);
                strm.write(reinterpret_cast<const char *>(sv.get_stack_ptr()), sizeof(uint64_t) * size);
            }
        }
    }
}

static storage *get_storage()
{
    static storage instance;
    return &instance;
}

const char *storage::enable_tracing(bool usable_size, bool unw)
{
#define ERROR_STR(str) str "\0\0\0\0\0\0\0";
    if (UNLIKELY(s_use_memory_tracing)) {
        return ERROR_STR("Tracing has already enabled");
    }
#undef ERROR_STR

    s_use_memory_tracing = true;
    s_usable_size = usable_size;
    s_unw = unw;

    if (UNLIKELY(s_use_memory_tracing && !s_storage)) {
        s_storage = get_storage();
    }
    s_storage->m_shared_data.start_time = std::time(nullptr);

    return nullptr;
}

struct File
{
    File(std::ofstream &_file)
        : file(_file)
    {}

    void dump(uint64_t base_addr, uint64_t v_addr, uint64_t memsize, uint64_t path_lenght, const char *path)
    {
        file.put('s');
        file.write(reinterpret_cast<const char *>(&base_addr), sizeof(uint64_t));
        file.write(reinterpret_cast<const char *>(&v_addr), sizeof(uint64_t));
        file.write(reinterpret_cast<const char *>(&memsize), sizeof(uint64_t));
        file.write(reinterpret_cast<const char *>(&path_lenght), sizeof(uint64_t));
        file.write(path, path_lenght);
    }

    std::ofstream &file;
    // Only the first phdr without name is considered as the program executable.
    bool is_first = true;
};

/**
 * walk on list of shared objects;
 * dump information required by symbolizer
 */
static int dump_bin_info(struct dl_phdr_info *info, size_t size, void *data)
{
    static_cast<void>(size);

    File *dd = static_cast<File *>(data);
    char resolved_path[PATH_MAX];
    size_t path_len = 0;

    // Skip not loadable segments
    int i = 0;
    for (; i < info->dlpi_phnum; ++i) {
        if (PT_LOAD == info->dlpi_phdr[i].p_type) {
            if (0x5 == info->dlpi_phdr[i].p_flags) {
                break;
            }
        }
    }

    if (i >= info->dlpi_phnum) {
        // Cannot find loadable segment
        return 0;
    }

    // Calculate virtual memory address
    uint64_t base_addr = info->dlpi_addr;
    uint64_t v_addr = info->dlpi_phdr[i].p_vaddr;
    uint64_t memsize = info->dlpi_phdr[i].p_memsz;

    if (nullptr == info->dlpi_name || '\0' == info->dlpi_name[0]) {
        if (!dd->is_first) {
            return 0;
        }
        // Our bin file
        dd->is_first = false;
        path_len = readlink("/proc/self/exe", resolved_path, PATH_MAX - 1);
        if (path_len <= 0) {
            return 0;
        }
        resolved_path[path_len] = '\0';
    }
    else if (realpath(info->dlpi_name, resolved_path)) {
        path_len = strlen(resolved_path);
    }
    else {
        // cannot find realpath of library
        return 0;
    }

    dd->dump(base_addr, v_addr, memsize, path_len, resolved_path);
    return 0;
}

const char *storage::dump_tracing(bool disable)
{
    if (!s_use_memory_tracing) {
        return "tracing is not enabled";
    }

    if (disable) {
        s_use_memory_tracing = false;
    }
    t_allocation_in_map = true;

    if (!s_storage) {
        t_allocation_in_map = false;
        return "storage is not initialized";
    }

    std::string trace_file(s_storage->m_shared_data.data);
    std::ofstream file(trace_file, std::ios::out | std::ios::binary);
    if (!file.is_open()) {
        t_allocation_in_map = false;
        return "Cannot create tracing file";
    }

    s_storage->dump(file);
    if (disable) {
        s_storage->clear();
    }

    File file_wrapper(file);
    dl_iterate_phdr(dump_bin_info, &file_wrapper);
    t_allocation_in_map = false;

    return nullptr;
}

void *storage::get_shared_data()
{
    if (s_use_memory_tracing && s_storage) {
        SharedData *sd = &(s_storage->m_shared_data);
        sd->now_in_memory = s_storage->m_statistics.get_now_in_memory();
        sd->all_allocations = s_storage->m_statistics.get_all_allocations();
        sd->memory_peak = s_storage->m_statistics.get_memory_peak();
        return reinterpret_cast<void *>(sd);
    }
    return nullptr;
}

const char *storage::set_tracing_file(const char *file_name)
{
#define ERROR_STR(str) str "\0\0\0\0\0\0\0";
    if (!s_use_memory_tracing || !s_storage) {
        return ERROR_STR("tracing is not enabled");
    }
#undef ERROR_STR
    SharedData *sd = &(s_storage->m_shared_data);
    std::memset(sd->data, 0, s_shared_size);
    uint64_t len = std::strlen(file_name);
    std::memcpy(sd->data, file_name, std::min(s_shared_size - 1, len));
    return nullptr;
}

}

extern "C" {

const void *enable_memory_tracing(bool usable_size, bool unw)
{
    return memtrace::storage::enable_tracing(usable_size, unw);
}

const void *disable_memory_tracing()
{
    return memtrace::storage::dump_tracing(true);
}

const void *dump_memory_tracing()
{
    return memtrace::storage::dump_tracing(false);
}

void *get_tracing_shared_data()
{
    return memtrace::storage::get_shared_data();
}

const void *set_memory_tracing_file(const char *file_name)
{
    return memtrace::storage::set_tracing_file(file_name);
}

}
