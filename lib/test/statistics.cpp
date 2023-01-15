#include "tracing_internal.h"

#include "gtest/gtest.h"

using namespace memtrace;

namespace {

TEST(statistics, empty)
{
    statistics stats;
    EXPECT_EQ(0, stats.get_all_allocations());
    EXPECT_EQ(0, stats.get_now_in_memory());
    EXPECT_EQ(0, stats.get_memory_peak());
}

TEST(statistics, add_allocation)
{
    statistics stats;
    stats.add_allocation(1);
    EXPECT_EQ(1, stats.get_all_allocations());
    EXPECT_EQ(1, stats.get_now_in_memory());
    EXPECT_EQ(1, stats.get_memory_peak());
}

TEST(statistics, add_free)
{
    statistics stats;
    stats.add_allocation(1);
    stats.add_free(1);

    EXPECT_EQ(1, stats.get_all_allocations());
    EXPECT_EQ(0, stats.get_now_in_memory());
    EXPECT_EQ(1, stats.get_memory_peak());
}

TEST(statistics, clear)
{
    statistics stats;
    stats.add_allocation(1);
    stats.clear();

    EXPECT_EQ(0, stats.get_all_allocations());
    EXPECT_EQ(0, stats.get_now_in_memory());
    EXPECT_EQ(0, stats.get_memory_peak());
}

}
