# memtrace
**memtrace** is a tool to trace allocations in c++ applications.

# Requirements
1. memtrace can be used on x86_64-linux only.
2. To use the tool a traced application has to be build with frame pointers, \
i.e. with -fno-omit-frame-pointer or in debug mode (as frame pointers omits by default at -O1 and higher).
3. Pre-installed llvm-symbolizer and python3

# Build c++ library
```cmake -B build && cmake --build build```

## Tests
The tests are neither built nor run by default. They need an installed googletest:
```
cmake -B build -DENABLE_TESTS=ON
cmake --build build --target memtrace_check
```

# How to use
1. make you application with -fno-omit-frame-pointer
2. launch the application with LD_PRELOAD. \
`LD_PRELOAD=/path/to/libmemtrace.so application`
3. launch memtrace client with required options.
```
$ python3 -m memtrace --help
usage: memtrace [-h] [-p PID] [-a | --all | --no-all] [-f FILE] [-b]
                [-g | --gdb | --no-gdb]
                [-u | --libunwind | --no-libunwind] [-s SYMBOLIZER] [-e] [-d]
                [-t]

memtrace is a tool to trace allocations in c++ applications.

options:
  -h, --help            show this help message and exit
  -p PID, --pid PID     process identifier
  -a, --all, --no-all   Show all allocations without free
  -f FILE, --file FILE  existing mt file
  -b, --binaries        print paths of all binaries from the mt file (-f is
                        required) and exit, use it to check that all of them
                        exist on the host where the file is parsed
  -g, --gdb, --no-gdb   use gdb to attach to the process (default). --no-gdb
                        attaches with ptrace, no heavy gdb process is needed.
                        It is VERY experimental: the process can hang
  -u, --libunwind, --no-libunwind
                        Collect stacks with libunwind (default). --no-
                        libunwind uses frame pointers, it is faster, but the
                        application has to be built with -fno-omit-frame-
                        pointer
  -s SYMBOLIZER, --symbolizer SYMBOLIZER
                        path to llvm symbolizer

Actions:
  Tracing use interactiv mode by default. If only enable/disable/status are
  required. Set one of following options:

  -e, --enable          enable tracing
  -d, --disable         disable tracing

Output:
  Output options.

  -t, --tree            out as tree, required rich
```

The client can also be started directly, without `python3 -m`:
`bin/memtrace -f file.mt`.

## Parse an mt file on another host
To check that all binaries of the traced application are available on the host
where the mt file is parsed, print their paths (allocation data is not parsed):
```
$ memtrace -f file.mt -b | xargs ls -1 > /dev/null
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
