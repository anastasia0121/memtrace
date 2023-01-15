# memtrcae
memtrace is a tool to trace allocations in c++ applications.

# How to use
1. make you application with -fno-omit-frame-pointer
2. launch the application with LD_PRELOAD. LD_PRELOAD=/path/to/libmemtrace.so application
3. launch memtrace client with required options
```
Usage: memtrace.py [options]

Options:
  -h, --help            show this help message and exit
  -p PID, --pid=PID     process identifier
  -f FILE, --file=FILE  existing mt file
  -g, --gdb             use gdb instead of manual ptrace calls

  Actions:
    Tracing use interactiv mode by default. If only enable/disable/stats
    required. Set one of following options:

    -e, --enable        enable tracing
    -d, --disable       disable tracing
    -s, --status        current status of tracing
```

# build
Compile c++ library only
cmake -B build && cmake --build build

If you want to build the memtrace tests, you have to pass -DENABLE_TESTS=ON when configuring your project with CMake.
