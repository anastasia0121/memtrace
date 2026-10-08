#include "tracing_internal.h"

#include "gtest/gtest.h"

#include <vector>

using namespace memtrace;

namespace {

TEST(stack, empty_view)
{
    // an empty view has no pointer, it must not be copied
    stack s{stack_view()};
    EXPECT_EQ(0, s.get_view().get_length());
    EXPECT_EQ(nullptr, s.get_view().get_stack_ptr());
}

TEST(stack, copy_of_view)
{
    uintptr_t frames[] = {1, 2, 3};
    stack s{stack_view(frames, 3)};

    stack_view view = s.get_view();
    ASSERT_EQ(3, view.get_length());
    EXPECT_NE(frames, view.get_stack_ptr());
    EXPECT_EQ(1, view.get_stack_ptr()[0]);
    EXPECT_EQ(2, view.get_stack_ptr()[1]);
    EXPECT_EQ(3, view.get_stack_ptr()[2]);
}

TEST(stack, move)
{
    uintptr_t frames[] = {1, 2};
    stack a{stack_view(frames, 2)};
    stack b{std::move(a)};

    EXPECT_EQ(0, a.get_view().get_length());
    EXPECT_EQ(2, b.get_view().get_length());
}

TEST(stack_view, equal)
{
    uintptr_t a[] = {1, 2, 3};
    uintptr_t b[] = {1, 2, 3};
    EXPECT_TRUE(stack_view(a, 3) == stack_view(b, 3));
}

TEST(stack_view, different_length)
{
    uintptr_t a[] = {1, 2, 3};
    uintptr_t b[] = {1, 2, 3, 4};
    EXPECT_FALSE(stack_view(a, 3) == stack_view(b, 4));
}

TEST(stack_view, different_frame)
{
    uintptr_t a[] = {1, 2, 3};
    uintptr_t b[] = {1, 9, 3};
    EXPECT_FALSE(stack_view(a, 3) == stack_view(b, 3));
}

TEST(stack_view, the_last_frame_is_ignored)
{
    // the outermost frame does not take part in the comparison and in the hash
    uintptr_t a[] = {1, 2, 3, 100};
    uintptr_t b[] = {1, 2, 3, 200};
    stack_view va(a, 4);
    stack_view vb(b, 4);

    EXPECT_TRUE(va == vb);
    EXPECT_EQ(va.get_hash_value(), vb.get_hash_value());
    EXPECT_EQ(va.get_small_hash_value(), vb.get_small_hash_value());
}

TEST(stack_view, empty)
{
    stack_view a;
    stack_view b;
    EXPECT_TRUE(a == b);
    EXPECT_EQ(0, a.get_hash_value());
    EXPECT_EQ(0, a.get_small_hash_value());
}

TEST(stack_view, hash_of_short_stacks)
{
    for (uintptr_t length = 1; length <= 4; ++length) {
        std::vector<uintptr_t> frames(length, 7);
        stack_view view(frames.data(), length);
        EXPECT_EQ(view.get_hash_value(), stack_view(frames.data(), length).get_hash_value());
    }
}

} // namespace
