# memtrace
**memtrace** is a tool to trace allocations in c++ applications.

# Requirements
1. memtrace can be used on x86_64-linux only.
2. To use the tool a traced application has to be build with frame pointers, \
i.e. with -fno-omit-frame-pointer or in debug mode (as frame pointers omits by default at -O1 and higher).
3. Pre-installed llvm-symbolizer and python3

# Build c++ library
```cmake -B build && cmake --build build```

If you want to build the memtrace tests, you have to pass `-DENABLE_TESTS=ON` when configuring your project with CMake.

# How to use
1. make you application with -fno-omit-frame-pointer
2. launch the application with LD_PRELOAD. \
`LD_PRELOAD=/path/to/libmemtrace.so application`
3. launch memtrace client with required options.
```
$ python3 -m memtrace --help
usage: memtrace [-h] [-p PID] [-f FILE] [-g] [-e] [-d] [-s]

memtrace is a tool to trace allocations in c++ applications.

options:
  -h, --help            show this help message and exit
  -p PID, --pid PID     process identifier
  -f FILE, --file FILE  existing mt file
  -g, --gdb             use gdb instead of manual ptrace calls

Actions:
  Tracing use interactiv mode by default. If only enable/disable/status are
  required. Set one of following options:

  -e, --enable          enable tracing
  -d, --disable         disable tracing
  -s, --status          current status of tracing
```

# Results
The program made some allocations in `main()` at tracing time. \
3 of them were not freed. \
Allocated but not freed size is 12 bytes, 4 bytes average per allocation.
```
Connection to process. Please wait.
Tracing is enabled.
Press Ctrl+C to stop tracing.
^CYou pressed Ctrl+C.
mt file is /home/anastasia/git/memtrace/26326-01222023-210617.mt.
Allocated 12 bytes in 3 allocations (4 bytes average)
        operator new(unsigned long)     at ??:0:0
        main    at ??:0:0
        __libc_start_call_main  at ./csu/../sysdeps/nptl/libc_start_call_main.h:58:16
```
