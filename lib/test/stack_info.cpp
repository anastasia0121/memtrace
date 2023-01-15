#include "tracing_internal.h"

#include "gtest/gtest.h"

using namespace memtrace;

namespace {

TEST(stack_info, empty)
{
    stack_info info({});

    EXPECT_EQ(0, info.get_not_freed_mem());
    EXPECT_EQ(0, info.get_not_freed_counts());
    EXPECT_EQ(0, info.get_alloc_size());
    EXPECT_EQ(0, info.get_free_size());
    EXPECT_EQ(0, info.get_alloc_counter());
    EXPECT_EQ(0, info.get_free_counter());
    EXPECT_EQ(0, info.get_stack_view().get_length());
}

TEST(stack_info, add_allocation)
{
    stack_info info({});
    info.add_allocation(1);

    EXPECT_EQ(1, info.get_not_freed_mem());
    EXPECT_EQ(1, info.get_not_freed_counts());
    EXPECT_EQ(1, info.get_alloc_size());
    EXPECT_EQ(0, info.get_free_size());
    EXPECT_EQ(1, info.get_alloc_counter());
    EXPECT_EQ(0, info.get_free_counter());
}

TEST(stack_info, add_free)
{
    stack_info info({});
    info.add_allocation(1);
    info.add_allocation(1);
    info.add_free(1);

    EXPECT_EQ(1, info.get_not_freed_mem());
    EXPECT_EQ(1, info.get_not_freed_counts());
    EXPECT_EQ(2, info.get_alloc_size());
    EXPECT_EQ(1, info.get_free_size());
    EXPECT_EQ(2, info.get_alloc_counter());
    EXPECT_EQ(1, info.get_free_counter());
    EXPECT_EQ(0, info.get_stack_view().get_length());
}

}
