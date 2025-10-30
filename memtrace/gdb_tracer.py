"""
Enable tracing via gdb.
"""
from subprocess import Popen, PIPE

# (gdb) p (const char *)enable_memory_tracing(0, 1)
# $1 = 0x0
# (gdb) p (const char *)enable_memory_tracing(0, 1)
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
            "-ex", "p (const char *)enable_memory_tracing(0, 1)",
            "-ex", "detach",
            "-ex", "set confirm off",
            "-ex", "q"],
            stdin=PIPE, stdout=PIPE, stderr=PIPE,
            universal_newlines=True, bufsize=1)
        self.gdb.wait()
        self.gdb = None

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
