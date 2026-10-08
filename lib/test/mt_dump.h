#pragma once

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace memtrace_test {

/**
 * Content of a *.mt file, the format is described in storage::dump()
 * and in the python client (mt_parser.py).
 */
struct mt_dump
{
    struct alloc_record
    {
        uint64_t allocated = 0;
        uint64_t allocated_count = 0;
        uint64_t freed = 0;
        uint64_t freed_count = 0;
        std::vector<uint64_t> stack;
    };

    struct free_record
    {
        uint64_t freed = 0;
        uint64_t freed_count = 0;
        std::vector<uint64_t> stack;
    };

    uint64_t version = 0;
    uint64_t now_in_memory = 0;
    uint64_t all_allocated = 0;
    uint64_t memory_peak = 0;
    uint64_t free_no_alloc = 0;

    std::vector<alloc_record> allocs;
    std::vector<free_record> frees;
    std::vector<std::string> binaries;

    bool valid = false;
};

inline uint64_t read_u64(std::ifstream &file)
{
    uint64_t value = 0;
    file.read(reinterpret_cast<char *>(&value), sizeof(value));
    return value;
}

inline std::vector<uint64_t> read_stack(std::ifstream &file)
{
    std::vector<uint64_t> stack(read_u64(file));
    for (auto &frame : stack) {
        frame = read_u64(file);
    }
    return stack;
}

inline mt_dump parse_mt_dump(const std::string &path)
{
    mt_dump dump;
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return dump;
    }

    char type = 0;
    while (file.get(type)) {
        if ('v' == type) {
            dump.version = read_u64(file);
            char usable_size = 0;
            file.get(usable_size);
            dump.now_in_memory = read_u64(file);
            dump.all_allocated = read_u64(file);
            dump.memory_peak = read_u64(file);
            dump.free_no_alloc = read_u64(file);
            read_u64(file); // start time
            read_u64(file); // dump time
            read_u64(file); // pointers overhead
            read_u64(file); // stacks overhead
        }
        else if ('m' == type) {
            mt_dump::alloc_record record;
            record.allocated = read_u64(file);
            record.allocated_count = read_u64(file);
            record.freed = read_u64(file);
            record.freed_count = read_u64(file);
            record.stack = read_stack(file);
            dump.allocs.push_back(std::move(record));
        }
        else if ('f' == type) {
            mt_dump::free_record record;
            record.freed = read_u64(file);
            record.freed_count = read_u64(file);
            record.stack = read_stack(file);
            dump.frees.push_back(std::move(record));
        }
        else if ('s' == type) {
            read_u64(file); // mapped address
            read_u64(file); // virtual address
            read_u64(file); // memory size
            std::string binary(read_u64(file), '\0');
            file.read(binary.data(), static_cast<std::streamsize>(binary.size()));
            dump.binaries.push_back(std::move(binary));
        }
        else {
            return dump;
        }
    }

    dump.valid = file.eof();
    return dump;
}

} // namespace memtrace_test
