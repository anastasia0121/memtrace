#pragma once

#include <dlfcn.h>
#include <fstream>
#include <iomanip>
#include <limits.h>
#include <link.h>
#include <math.h>
#include <ostream>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

#define UNW_LOCAL_ONLY
#include "libunwind.h"

#define LIKELY(e) __builtin_expect(!!(e), 1)
#define UNLIKELY(e) __builtin_expect(!!(e), 0)

namespace memtrace {

struct stack_info;

// Skip allocations during tracing
extern thread_local bool t_allocation_in_map;
// Bottom of the stack
extern thread_local const void *t_stack_end;

/**
 * From glibc:
 * This is the stack layout we see with every stack frame
 * if not compiled without frame pointer.
 *
 *         +-----------------+       +-----------------+
 *  %fp -> | %fp last frame--------> | %fp last frame--->...
 *         |                 |       |                 |
 *         | return address  |       | return address  |
 *         +-----------------+       +-----------------+
 */
struct frame_info
{
    frame_info *next = nullptr;
    void *ret_addr = nullptr;
};

/**
 * As there is no information about freed size,
 * it stores extra inforamtion about allocated size by pointer.
 */
struct pointer_info
{
    size_t size = 0;             // allocated by pointer
    stack_info *sinfo = nullptr; // stack related information
};

/**
 * View of stack trace.
 */
struct stack_view
{
    stack_view() = default;

    stack_view(uintptr_t *stack, uint64_t length)
        : m_stack(stack)
        , m_length(length)
    {
    }

    // hash table related functions
    bool operator==(const stack_view &sv) const;

    /**
     * To hash allocations by stacks.
     */
    uint64_t get_hash_value() const;

    /**
     * To calculate a slice number.
     */
    uint64_t get_small_hash_value() const;

    uint64_t get_length() const { return m_length; }

    uintptr_t *get_stack_ptr() const { return m_stack; }

private:
    friend struct stack;

private:
    uintptr_t *m_stack = nullptr;
    uint64_t m_length = 0;
};

}

namespace std {
template <>
struct hash<memtrace::stack_view>
{
    using argument_type = memtrace::stack_view;
    using result_type = size_t;

    result_type operator()(const argument_type &data) const
    {
        return data.get_hash_value();
    }
};
}

namespace memtrace {

/**
 * Stack implementation.
 */
struct stack
{
    stack() = default;

    stack(const stack_view &view)
        : m_length(view.m_length)
    {
        uint64_t size = m_length * sizeof(uint64_t);
        m_stack = (uintptr_t *)std::malloc(size);
        memcpy(m_stack, view.m_stack, size);
    }

    stack(stack &&s)
        : m_stack(s.m_stack),
          m_length(s.m_length)
    {
        s.m_length = 0;
        s.m_stack = nullptr;
    }

    stack &operator=(stack &&s)
    {
        if (this != &s) {
            m_stack = s.m_stack;
            m_length = s.m_length;

            s.m_stack = nullptr;
            s.m_length = 0;
        }
        return *this;
    }

    ~stack()
    {
        if (m_stack) {
            free(m_stack);
        }
    }

    stack_view get_view() const
    {
        return stack_view(m_stack, m_length);
    }

private:
    uintptr_t *m_stack = nullptr;
    unsigned m_length = 0;
};

/**
 * All allocations and free for specified stack.
 */
struct stack_info
{
    stack_info(stack_view sv)
        : m_stack(sv)
    {}

    void add_allocation(uint64_t size)
    {
        m_allocated.fetch_add(size, std::memory_order_relaxed);
        m_allocation_counter.fetch_add(1, std::memory_order_relaxed);
    }

    void add_free(uint64_t size)
    {
        m_freed.fetch_add(size, std::memory_order_relaxed);
        m_freed_counter.fetch_add(1, std::memory_order_relaxed);
    }

    uint64_t get_not_freed_mem() const
    {
        return m_allocated - m_freed;
    }

    uint64_t get_not_freed_counts() const
    {
        return m_allocation_counter - m_freed_counter;
    }

    uint64_t get_alloc_size() const { return m_allocated; }

    uint64_t get_free_size() const { return m_freed; }

    uint64_t get_alloc_counter() const { return m_allocation_counter; }

    uint64_t get_free_counter() const { return m_freed_counter; }

    stack_view get_stack_view() const { return m_stack.get_view(); }

private:
    std::atomic<uint64_t> m_allocated = 0;          // total allocated size
    std::atomic<uint64_t> m_freed = 0;              // total freed size
    std::atomic<uint64_t> m_allocation_counter = 0; // total counter of allocations
    std::atomic<uint64_t> m_freed_counter = 0;      // total counter of free
    stack m_stack;
};

/**
 * current measure statistic
 */
struct statistics
{
    std::uint64_t get_all_allocations() const { return m_all; }

    std::uint64_t get_now_in_memory() const { return m_in_memory; }

    std::uint64_t get_memory_peak() const { return m_peak; }

    std::uint64_t get_free_no_alloc() const { return m_free_no_alloc; }

    void add_allocation(std::uint64_t size);

    void add_free(std::uint64_t size)
    {
        m_in_memory.fetch_sub(size, std::memory_order_relaxed);
    }

    void add_free_no_alloc(std::uint64_t size)
    {
        m_free_no_alloc.fetch_add(size, std::memory_order_relaxed);
    }

    void clear()
    {
        m_all = m_in_memory = m_peak = m_free_no_alloc = 0;
    }

private:
    std::atomic<std::uint64_t> m_all = 0;
    std::atomic<std::uint64_t> m_in_memory = 0;
    std::atomic<std::uint64_t> m_peak = 0;
    std::atomic<std::uint64_t> m_free_no_alloc = 0;
};

/**
 * storage of stacks
 */
struct storage
{
public:
    storage();

    static const char *enable_tracing(bool usable_size, bool unw);

    static const char *dump_tracing(bool disable);

    static void *get_shared_data();

    static const char *set_tracing_file(const char *file_name);

public:
    static __attribute__((always_inline)) inline
    void alloc_ptr(void *old_ptr, size_t size, void *new_ptr);

    static __attribute__((always_inline)) inline
    void free_ptr(void *ptr);

private:
    static __attribute__((always_inline)) inline
    bool init_stack_bound();

    static __attribute__((always_inline)) inline
    stack_view get_stack(uintptr_t *stack_ptr);

    static __attribute__((always_inline)) inline
    stack_view get_stack_unw(uintptr_t *stack_ptr);

    uint64_t get_slice(void *ptr);

    uint64_t get_slice(stack_view sv);

    void free_ptr_i(void *ptr);

    void alloc_ptr_i(void *ptr, stack_view &sv, size_t size);

    void clear();

    void dump(std::ostream &strm) const;

private:
    static constexpr uint64_t s_slicing_count = 32;
    static constexpr uint64_t s_pointer_map_reserve = 300000;
    static constexpr uint64_t s_allocation_map_reserve = 63000;
    static constexpr uint64_t s_max_stack_length = 128;

    // Stack traces storage
    static storage *s_storage;
    // Enable or disable tracing flag
    static bool s_use_memory_tracing;
    // Take in attention the real backet size
    static bool s_usable_size;
    // use libunwind
    static bool s_unw;

    uint64_t m_version = 2;

    using allocation_map_t = std::unordered_map<stack_view, stack_info *>;
    std::array<allocation_map_t, s_slicing_count> m_storage;
    mutable std::array<std::shared_mutex, s_slicing_count> m_mutexes;

    using pointer_map_t = std::unordered_map<void *, pointer_info>;
    std::array<pointer_map_t, s_slicing_count> m_pointers;
    mutable std::array<std::mutex, s_slicing_count> m_pointer_mutexes;

    std::array<allocation_map_t, s_slicing_count> m_free_storage;
    mutable std::array<std::shared_mutex, s_slicing_count> m_free_mutexes;

    statistics m_statistics;

    // shared data between the libary and client
    static constexpr uint64_t s_shared_size = 1024;
    struct  __attribute__((__packed__)) SharedData
    {
        char data[s_shared_size] = {0};
        uint64_t start_time = 0;
        uint64_t now_in_memory = 0;
        uint64_t all_allocations = 0;
        uint64_t memory_peak = 0;

        void clear()
        {
            std::memset(data, 0, s_shared_size);
            start_time = 0;
            now_in_memory = 0;
            all_allocations = 0;
            memory_peak = 0;
        }
    };
    SharedData m_shared_data;
};

bool storage::init_stack_bound()
{
    const void *c_incomplete_init = reinterpret_cast<const void *>(0x13);

    if (UNLIKELY(c_incomplete_init == t_stack_end)) {
        return false; // allocation from pthread_attr_getstack
    }

    if (UNLIKELY(!t_stack_end)) {
        t_stack_end = c_incomplete_init;

        pthread_attr_t attr;
        int ret = pthread_getattr_np(pthread_self(), &attr);
        if (LIKELY(ret == 0)) {
            size_t stacksize = 0;
            void *stackaddr = nullptr;
            pthread_attr_getstack(&attr, &stackaddr, &stacksize);
            pthread_attr_destroy(&attr);
            t_stack_end = static_cast<char *>(stackaddr) + stacksize;
            return true;
        }

        t_stack_end = nullptr;
        return false;
    }

    return true;
}

stack_view storage::get_stack_unw(uintptr_t *stack_ptr)
{
    unw_context_t uc;
    unw_cursor_t cursor;
    if (unw_getcontext(&uc) || unw_init_local(&cursor, &uc)) {
        return stack_view();
    }

    unsigned i = 0;
    while ((i < s_max_stack_length) && (unw_step(&cursor) > 0)) {
        unw_word_t ip;
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        if (0 == ip) {
             return stack_view(stack_ptr, i);
        }
        stack_ptr[i++] = ip;
     }

    return stack_view(stack_ptr, i);
}

stack_view storage::get_stack(uintptr_t *stack_ptr)
{
    if (UNLIKELY(!init_stack_bound())) {
        return stack_view();
    }

    // the current stack frame addres
    void *top_frame = __builtin_frame_address(0);
    // top of the thread stack
    void *top_stack = ({ char __csf; &__csf; });
    // current frame
    frame_info *current = static_cast<frame_info *>(top_frame);

    for (uint64_t i = 0; i < s_max_stack_length; ++i) {
        if (UNLIKELY((current < top_stack) || (current >= t_stack_end))) {
            return stack_view(stack_ptr, i);
        }
        stack_ptr[i] = reinterpret_cast<uintptr_t>(current->ret_addr);
        current = current->next;
    }
    return stack_view(stack_ptr, s_max_stack_length);
}

void storage::alloc_ptr(void *old_ptr, size_t size, void *new_ptr)
{
    if (LIKELY((uintptr_t)new_ptr < 4096)) {
        return;
    }

    // usual tracing is disable
    if (LIKELY(!s_use_memory_tracing || t_allocation_in_map || !s_storage)) {
        return;
    }

    t_allocation_in_map = true;

    // realloc
    if (old_ptr) {
        s_storage->free_ptr_i(old_ptr);
    }

    // malloc, realloc
    if (LIKELY(new_ptr)) {
        uintptr_t stack[s_max_stack_length];
        stack_view sv = s_unw ? get_stack_unw(stack) : get_stack(stack);
        s_storage->alloc_ptr_i(new_ptr, sv, size);
    }

    t_allocation_in_map = false;
}

void storage::free_ptr(void *ptr)
{
    // Guard against recursive free during thread teardown
    // update_get_addr (ti=0x707a1991df70, gen=<optimized out>) at ../elf/dl-tls.c:916
    // __tls_get_addr () at ../sysdeps/x86_64/tls_get_addr.S:55
    // free () from libmemtrace.so
    // free (ptr=<optimized out>) at ../include/rtld-malloc.h:50
    // _dl_update_slotinfo (req_modid=1, new_gen=2) at ../elf/dl-tls.c:822
    if (LIKELY((uintptr_t)ptr < 4096)) {
        return;
    }

    if (LIKELY(!s_use_memory_tracing || t_allocation_in_map || !s_storage)) {
        return;
    }

    if (LIKELY(ptr)) {
        t_allocation_in_map = true;
        s_storage->free_ptr_i(ptr);
        t_allocation_in_map = false;
    }
}

}
