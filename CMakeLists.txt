cmake_minimum_required(VERSION 3.10.2)

project(memory_tracing
        DESCRIPTION "tracing library")

set(CMAKE_CXX_FLAGS "-fno-omit-frame-pointer -fPIC -Wall -Wextra -Wshadow \
                     -Wpointer-arith -m64")

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEB -march=native -mtune=native")
set(CMAKE_CXX_FLAGS_DEBUG "-DDEBUG -g")

set(CMAKE_CXX_STANDARD 17)


# libmemtrace
set(LIB memtrace)
set(LIB_DIR "${CMAKE_BINARY_DIR}/lib")

file(GLOB SOURCES lib/src/*.cpp)
add_library(${LIB} SHARED ${SOURCES})

target_include_directories(${LIB} PRIVATE lib/src)
target_link_libraries(${LIB} PRIVATE absl::flat_hash_map libunwind.a)
set_target_properties(${LIB} PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${LIB_DIR})


# tests
option(ENABLE_TESTS "Enable tests" OFF)
if (${ENABLE_TESTS})
  enable_testing()

  set(TEST_EXE ${LIB}_test)
  set(TEST_DIR "${CMAKE_BINARY_DIR}/test")

  file(GLOB TEST_SOURCES lib/test/*.cpp)
  add_executable(${TEST_EXE} ${TEST_SOURCES})

  target_include_directories(${TEST_EXE} PRIVATE lib/src)
  target_link_libraries(${TEST_EXE} PRIVATE gtest absl::flat_hash_map ${LIB})
  set_target_properties(${TEST_EXE} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${TEST_DIR})

  add_test(NAME ${TEST_EXE} COMMAND ${TEST_EXE} WORKING_DIRECTORY ${TEST_DIR})

  add_custom_command(TARGET ${TEST_EXE} POST_BUILD
    COMMAND ctest --output-on-failure)

endif()


# dependencies
set(ABSL_PROPAGATE_CXX_STD ON)
add_subdirectory(thd/abseil-cpp)
add_subdirectory(thd/googletest)
