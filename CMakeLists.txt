cmake_minimum_required(VERSION 3.23)

project(memory_tracing DESCRIPTION "tracing library")

set(CMAKE_CXX_FLAGS "-fno-omit-frame-pointer -fPIC -Wall -Wextra -Wshadow -Wpointer-arith -m64")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -g")
set(CMAKE_CXX_FLAGS_DEBUG "-DDEBUG -g")
set(CMAKE_CXX_STANDARD 23)

# libmemtrace
add_library(memtrace SHARED)

file(GLOB SOURCES lib/src/*.cpp)
target_sources(memtrace
  PRIVATE ${SOURCES}
  PUBLIC
    FILE_SET public_headers
    TYPE HEADERS
    BASE_DIRS lib/include
    FILES lib/include/memtrace.h
)

find_library(UNWIND_LIB NAMES unwind libunwind.so REQUIRED)
find_path(UNWIND_INCLUDE_DIR NAMES libunwind.h REQUIRED)
target_include_directories(memtrace PRIVATE ${UNWIND_INCLUDE_DIR})
target_link_libraries(memtrace PRIVATE ${UNWIND_LIB})

include(GNUInstallDirs)
install(TARGETS memtrace 
    EXPORT memtrace-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    FILE_SET public_headers DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(EXPORT memtrace-targets
    FILE memtrace-config.cmake
    NAMESPACE memtrace::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/memtrace
)

# tests
#   cmake -B build -DENABLE_TESTS=ON
#   cmake --build build --target memtrace_check
option(ENABLE_TESTS "Enable tests" OFF)
if (${ENABLE_TESTS})
  enable_testing()

  find_package(GTest REQUIRED)

  set(TEST_EXE memtrace_test)
  file(GLOB TEST_SOURCES lib/test/*.cpp)
  add_executable(${TEST_EXE} EXCLUDE_FROM_ALL ${TEST_SOURCES} lib/src/tracing.cpp)
  target_include_directories(${TEST_EXE} PRIVATE lib/src lib/test ${UNWIND_INCLUDE_DIR})
  target_link_libraries(${TEST_EXE} PRIVATE ${UNWIND_LIB} GTest::gtest)

  add_test(NAME ${TEST_EXE} COMMAND ${TEST_EXE})
  add_custom_target(memtrace_check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS ${TEST_EXE})
endif()

