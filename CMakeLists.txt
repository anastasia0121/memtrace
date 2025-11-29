cmake_minimum_required(VERSION 3.10.2)

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
find_path(UNWIND_INCLUDE_DIR NAMES libunwind.h)
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
option(ENABLE_TESTS "Enable tests" OFF)
if (${ENABLE_TESTS})
  enable_testing()

  add_subdirectory(thd/googletest)

  set(TEST_EXE ${LIB}_test)
  file(GLOB TEST_SOURCES lib/test/*.cpp)
  add_executable(${TEST_EXE} ${TEST_SOURCES})
  target_include_directories(${TEST_EXE} PRIVATE lib/src)
  
  add_test(NAME ${TEST_EXE} COMMAND ${TEST_EXE})
  add_custom_command(TARGET ${TEST_EXE} POST_BUILD
    COMMAND ctest --output-on-failure)
endif()

