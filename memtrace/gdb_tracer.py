"""
Enable tracing via gdb.
"""
from subprocess import Popen, PIPE

# (gdb) p (const char *)enable_memory_tracing(0)
# $1 = 0x0
# (gdb) p (const char *)enable_memory_tracing(0)
# $2 = 0x7f7b6afe1738 "Tracing has already enabled"
# (gdb) p (const char *)get_tracing_shared_data(0)
# $6 = 0x55bee213fd40 ""
# (gdb) p (const char *)set_memory_tracing_file("FILE")
# $7 = 0x0
# (gdb) p (const char *)disable_memory_tracing()
# $8 = 0x0


class GDBTracer:
    """
    hack to enable tracing
    """
    def __init__(self, pid):
        self.pid = pid
        self.gdb = None

    def enable(self):
        self.gdb = Popen(["gdb", "attach", str(self.pid), 
            "-ex", "p (const char *)enable_memory_tracing(0)",
            "-ex", "detach",
            "-ex", "set confirm off",
            "-ex", "q"],
            stdin=PIPE, stdout=PIPE, stderr=PIPE,
            universal_newlines=True, bufsize=1)
        self.gdb.wait()
        self.gdb = None
        
    def get_shared_data_addr(self):
        self.attach()
        cmd = f"p (const char *)get_tracing_shared_data(0)"
        print(cmd, file=self.gdb.stdin, flush=True)
        line = self.gdb.stdout.readline()
        addr_idx = line.find("0x")
        if -1 != addr_idx:
            return int(line[addr_idx: -1].split()[0], 16)
        return 0

    def disable(self, mt_fname):
        self.gdb = Popen(["gdb", "attach", str(self.pid),
            "-ex", f"p (const char *)set_memory_tracing_file(\"{mt_fname}\")",
            "-ex", "p (const char *)disable_memory_tracing()",
            "-ex", "detach",
            "-ex", "set confirm off",
            "-ex", "q"],
            stdin=PIPE, stdout=PIPE, stderr=PIPE,
            universal_newlines=True, bufsize=1)
        self.gdb.wait()
        self.gdb = None

    def attach(self):
        """
        Attach to process via gdb.
        """
        self.gdb = Popen(["gdb", "attach", str(self.pid), "-ex", "p \"I am ready\""],
                         stdin=PIPE, stdout=PIPE, stderr=PIPE,
                         universal_newlines=True, bufsize=1)

        while True:
            line = self.gdb.stdout.readline()
            if (not line) or (line == "") or ("I am ready" in line):
                break

    def detach(self):
        """
        Detach.
        """
        cmd = "q"
        print(cmd, file=self.gdb.stdin, flush=True)
        cmd = "y"
        print(cmd, file=self.gdb.stdin, flush=True)

    def call_function(self, func_addr, arg=0):
        """
        Call function in tracee process.

        :func_addr: function address to call
        :arg: the first (and only) argument
        :return: return value of callable function
        """
        cmd = f"p ((void *(*)()){func_addr})({arg})"
        print(cmd, file=self.gdb.stdin, flush=True)
        line = self.gdb.stdout.readline()
        addr_idx = line.find("0x")
        if -1 != addr_idx:
            return int(line[addr_idx: -1].split()[0], 16)
        return 0

    def write_string(self, addr, data):
        """
        Write string into tracee process memory.

        :addr: start address to write
        :data: string to write
        """
        if not addr:
            return
        cmd = f"p strcpy({addr}, \"{data}\")"
        print(cmd, file=self.gdb.stdin, flush=True)
        _line = self.gdb.stdout.readline()

    def read_string(self, addr):
        """
        Read string from tracee process memory.

        :addr: start address to read
        :return: read string
        """
        if not addr:
            return ""
        cmd = f"p (const char *){addr}"
        print(cmd, file=self.gdb.stdin, flush=True)
        line = self.gdb.stdout.readline()
        return line
