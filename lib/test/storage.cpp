#include "mt_dump.h"
#include "tracing_internal.h"

#include "gtest/gtest.h"

#include <malloc.h>
#include <unistd.h>

#include <filesystem>
#include <string>

using namespace memtrace;
using memtrace_test::mt_dump;
using memtrace_test::parse_mt_dump;

namespace {

/**
 * The tests call the storage directly, without malloc interception:
 * the real malloc/realloc/free are used and the results are reported to the storage by hand.
 */
class storage_test : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_dir = std::filesystem::temp_directory_path() /
                ("memtrace_test_" + std::to_string(getpid()) + "_" +
                 ::testing::UnitTest::GetInstance()->current_test_info()->name());
        std::filesystem::create_directories(m_dir);
    }

    void TearDown() override
    {
        // a failed test must not leave the tracing enabled for the next one
        if (storage::is_tracing_enabled()) {
            storage::set_tracing_file(file("teardown").c_str());
            storage::dump_tracing(true);
        }
        std::filesystem::remove_all(m_dir);
    }

    std::string file(const std::string &name) const
    {
        return (m_dir / (name + ".mt")).string();
    }

    void enable(bool unw = true)
    {
        ASSERT_EQ(nullptr, storage::enable_tracing(false, unw));
    }

    // set the file, stop tracing and read the file
    mt_dump disable(const std::string &name)
    {
        EXPECT_EQ(nullptr, storage::set_tracing_file(file(name).c_str()));
        EXPECT_EQ(nullptr, storage::dump_tracing(true));
        EXPECT_FALSE(storage::is_tracing_enabled());

        mt_dump dump = parse_mt_dump(file(name));
        EXPECT_TRUE(dump.valid);
        EXPECT_EQ(2, dump.version);
        return dump;
    }

    std::filesystem::path m_dir;
};

TEST_F(storage_test, alloc_and_free)
{
    enable();

    void *ptr = malloc(100);
    storage::alloc_ptr(100, ptr);
    storage::free_ptr(ptr);
    free(ptr);

    mt_dump dump = disable("alloc_and_free");
    ASSERT_EQ(1, dump.allocs.size());
    EXPECT_EQ(100, dump.allocs[0].allocated);
    EXPECT_EQ(1, dump.allocs[0].allocated_count);
    EXPECT_EQ(100, dump.allocs[0].freed);
    EXPECT_EQ(1, dump.allocs[0].freed_count);
    EXPECT_FALSE(dump.allocs[0].stack.empty());
    EXPECT_EQ(100, dump.all_allocated);
    EXPECT_EQ(0, dump.now_in_memory);
    EXPECT_EQ(0, dump.free_no_alloc);
    EXPECT_TRUE(dump.frees.empty());
}

TEST_F(storage_test, not_freed)
{
    enable();

    void *ptr = malloc(64);
    storage::alloc_ptr(64, ptr);

    mt_dump dump = disable("not_freed");
    free(ptr);

    EXPECT_EQ(64, dump.now_in_memory);
    ASSERT_EQ(1, dump.allocs.size());
    EXPECT_EQ(64, dump.allocs[0].allocated - dump.allocs[0].freed);
}

TEST_F(storage_test, free_of_pointer_allocated_before_tracing)
{
    void *ptr = malloc(48);
    const size_t usable = malloc_usable_size(ptr);

    enable();
    storage::free_ptr(ptr);
    free(ptr);

    mt_dump dump = disable("free_before");
    EXPECT_EQ(usable, dump.free_no_alloc);
    ASSERT_EQ(1, dump.frees.size());
    EXPECT_EQ(usable, dump.frees[0].freed);
    EXPECT_EQ(1, dump.frees[0].freed_count);
    EXPECT_TRUE(dump.allocs.empty());
}

// realloc releases the old block, its size can not be taken after the call
TEST_F(storage_test, realloc_uses_size_taken_before)
{
    void *old_ptr = malloc(64);
    const size_t old_usable = malloc_usable_size(old_ptr);
    const size_t new_size = 1024 * 1024; // the block is moved and the old one is freed
    // the old address is only a key after realloc, the block is never touched
    volatile uintptr_t old_addr = reinterpret_cast<uintptr_t>(old_ptr);

    enable();
    void *new_ptr = realloc(old_ptr, new_size);
    ASSERT_NE(nullptr, new_ptr);
    storage::realloc_ptr(reinterpret_cast<void *>(old_addr), old_usable, new_size, new_ptr);
    storage::free_ptr(new_ptr);
    free(new_ptr);

    mt_dump dump = disable("realloc");
    EXPECT_EQ(old_usable, dump.free_no_alloc);
    EXPECT_EQ(new_size, dump.all_allocated);
    EXPECT_EQ(0, dump.now_in_memory);
}

TEST_F(storage_test, realloc_of_traced_pointer)
{
    enable();

    void *old_ptr = malloc(64);
    storage::alloc_ptr(64, old_ptr);

    const size_t old_usable = malloc_usable_size(old_ptr);
    volatile uintptr_t old_addr = reinterpret_cast<uintptr_t>(old_ptr);
    void *new_ptr = realloc(old_ptr, 4096);
    ASSERT_NE(nullptr, new_ptr);
    storage::realloc_ptr(reinterpret_cast<void *>(old_addr), old_usable, 4096, new_ptr);

    storage::free_ptr(new_ptr);
    free(new_ptr);

    mt_dump dump = disable("realloc_traced");
    // the old block was traced, so its release is not a free without allocation
    EXPECT_EQ(0, dump.free_no_alloc);
    EXPECT_EQ(64 + 4096, dump.all_allocated);
    EXPECT_EQ(0, dump.now_in_memory);
}

TEST_F(storage_test, failed_realloc_keeps_the_old_block)
{
    enable();

    void *ptr = malloc(64);
    storage::alloc_ptr(64, ptr);

    // realloc returned null and the old block is alive
    storage::realloc_ptr(ptr, malloc_usable_size(ptr), static_cast<size_t>(-1) / 2, nullptr);

    storage::free_ptr(ptr);
    free(ptr);

    mt_dump dump = disable("failed_realloc");
    // if the old block had been forgotten, the free above would be a free without allocation
    EXPECT_EQ(0, dump.free_no_alloc);
    EXPECT_TRUE(dump.frees.empty());
    EXPECT_EQ(64, dump.all_allocated);
    EXPECT_EQ(0, dump.now_in_memory);
}

TEST_F(storage_test, realloc_to_zero_releases_the_block)
{
    enable();

    void *ptr = malloc(64);
    storage::alloc_ptr(64, ptr);

    // realloc(ptr, 0) frees the block and returns null
    storage::realloc_ptr(ptr, malloc_usable_size(ptr), 0, nullptr);
    free(ptr);

    mt_dump dump = disable("realloc_zero");
    EXPECT_EQ(0, dump.now_in_memory);
    EXPECT_EQ(0, dump.free_no_alloc);
}

// frees of the blocks allocated before tracing must not go to the next session
TEST_F(storage_test, sessions_do_not_share_frees)
{
    void *ptr = malloc(32);

    enable();
    storage::free_ptr(ptr);
    free(ptr);
    mt_dump first = disable("first");
    EXPECT_EQ(1, first.frees.size());
    EXPECT_GT(first.free_no_alloc, 0);

    enable();
    mt_dump second = disable("second");
    EXPECT_TRUE(second.frees.empty());
    EXPECT_TRUE(second.allocs.empty());
    EXPECT_EQ(0, second.free_no_alloc);
}

// The tracing is stopped even if the file cannot be created.
// The data is kept, so the file can be dumped after that.
TEST_F(storage_test, failed_disable_stops_tracing_and_keeps_data)
{
    enable();

    void *ptr = malloc(16);
    storage::alloc_ptr(16, ptr);

    const std::string bad_file = (m_dir / "no_such_dir" / "file.mt").string();
    ASSERT_EQ(nullptr, storage::set_tracing_file(bad_file.c_str()));
    EXPECT_NE(nullptr, storage::dump_tracing(true));
    EXPECT_FALSE(storage::is_tracing_enabled());

    // it is not traced any more
    void *other = malloc(8);
    storage::alloc_ptr(8, other);

    ASSERT_EQ(nullptr, storage::set_tracing_file(file("later").c_str()));
    ASSERT_EQ(nullptr, storage::dump_tracing(false));
    mt_dump dump = parse_mt_dump(file("later"));
    EXPECT_TRUE(dump.valid);

    ASSERT_EQ(1, dump.allocs.size());
    EXPECT_EQ(16, dump.allocs[0].allocated);
    EXPECT_EQ(16, dump.all_allocated);

    // the final disable saves the data (to the same file) and closes the session
    ASSERT_EQ(nullptr, storage::dump_tracing(true));
    EXPECT_STREQ("There is nothing to dump", storage::dump_tracing(true));

    free(ptr);
    free(other);
}

// disable_memory_tracing_not_dump: stop now, save later
TEST_F(storage_test, stop_without_dump_and_dump_later)
{
    enable();

    void *ptr = malloc(24);
    storage::alloc_ptr(24, ptr);

    storage::disable_tracing();
    EXPECT_FALSE(storage::is_tracing_enabled());

    // nothing is traced after the stop
    void *other = malloc(8);
    storage::alloc_ptr(8, other);

    ASSERT_EQ(nullptr, storage::set_tracing_file(file("later").c_str()));
    ASSERT_EQ(nullptr, storage::dump_tracing(true));

    mt_dump dump = parse_mt_dump(file("later"));
    ASSERT_EQ(1, dump.allocs.size());
    EXPECT_EQ(24, dump.allocs[0].allocated);
    EXPECT_EQ(24, dump.all_allocated);

    free(ptr);
    free(other);
}

// An enabled session can be dumped even if nothing was allocated yet,
// but after a stop there is nothing to save if nothing was collected.
TEST_F(storage_test, stopped_empty_session_has_nothing_to_dump)
{
    enable();
    EXPECT_TRUE(storage::has_data_to_dump());
    EXPECT_NE(nullptr, storage::get_shared_data());

    storage::disable_tracing();
    EXPECT_FALSE(storage::has_data_to_dump());
    EXPECT_STREQ("There is nothing to dump", storage::dump_tracing(true));
}

TEST_F(storage_test, second_disable_has_nothing_to_dump)
{
    enable();
    disable("first");

    EXPECT_STREQ("There is nothing to dump", storage::dump_tracing(true));
    EXPECT_STREQ("There is nothing to dump", storage::dump_tracing(false));
    EXPECT_NE(nullptr, storage::set_tracing_file(file("again").c_str()));
    EXPECT_EQ(nullptr, storage::get_shared_data());
    EXPECT_FALSE(std::filesystem::exists(file("again")));
}

TEST_F(storage_test, dump_without_file_name_stops_tracing)
{
    enable();

    void *ptr = malloc(8);
    storage::alloc_ptr(8, ptr);
    free(ptr);

    EXPECT_NE(nullptr, storage::dump_tracing(true));
    EXPECT_FALSE(storage::is_tracing_enabled());

    // the name can be set and the file dumped later
    ASSERT_EQ(nullptr, storage::set_tracing_file(file("named").c_str()));
    EXPECT_EQ(nullptr, storage::dump_tracing(false));
    EXPECT_TRUE(parse_mt_dump(file("named")).valid);
}

// The data that was not saved must not go to the next session.
TEST_F(storage_test, unsaved_data_does_not_go_to_the_next_session)
{
    enable();

    void *ptr = malloc(16);
    storage::alloc_ptr(16, ptr);
    EXPECT_NE(nullptr, storage::dump_tracing(true)); // there is no file name

    enable();
    mt_dump dump = disable("clean");
    free(ptr);

    EXPECT_TRUE(dump.allocs.empty());
    EXPECT_EQ(0, dump.all_allocated);
}

TEST_F(storage_test, enable_twice)
{
    enable();
    EXPECT_NE(nullptr, storage::enable_tracing(false, true));
    disable("twice");
}

TEST_F(storage_test, binaries_include_the_executable)
{
    enable();
    mt_dump dump = disable("binaries");

    ASSERT_FALSE(dump.binaries.empty());
    // the first binary is the executable, it is taken from /proc/self/exe
    EXPECT_EQ(std::filesystem::read_symlink("/proc/self/exe").string(), dump.binaries.front());
}

// The libunwind and the frame pointer stacks have to be collected in the same way
// if the code has frame pointers (the tests are built with -fno-omit-frame-pointer).
__attribute__((noinline)) void allocate_in_nested_call(void *ptr)
{
    storage::alloc_ptr(32, ptr);
    __asm__ volatile("" ::: "memory");
}

class storage_stack_test : public storage_test, public ::testing::WithParamInterface<bool>
{
};

TEST_P(storage_stack_test, stack_is_collected)
{
    enable(GetParam());

    void *ptr = malloc(32);
    allocate_in_nested_call(ptr);

    mt_dump dump = disable("stack");
    free(ptr);

    ASSERT_EQ(1, dump.allocs.size());
    const auto &stack = dump.allocs[0].stack;
    ASSERT_FALSE(stack.empty());
    EXPECT_LE(stack.size(), 128);
    for (uint64_t frame : stack) {
        EXPECT_NE(0, frame);
    }
}

INSTANTIATE_TEST_SUITE_P(unwind_and_frame_pointers, storage_stack_test, ::testing::Bool());

} // namespace
