from subprocess import Popen, PIPE


# hack to enable tracing
class GDBTracer:
    def __init__(self, pid):
        self.pid = pid
        self.attached = False

    def __del__(self):
        if self.attached:
            self.detach()

    def attach(self):
        self.gdb = Popen(["gdb", "attach", str(self.pid), "-ex", "p \"I am ready\""],
                         stdin=PIPE, stdout=PIPE, stderr=PIPE,
                         universal_newlines=True, bufsize=1)

        while True:
            line = self.gdb.stdout.readline()
            if not line or line == "":
                break
            if "I am ready" in line:
                self.attached = True
                break

    def detach(self):
        cmd = "q"
        print(cmd, file=self.gdb.stdin, flush=True)
        cmd = "y"
        print(cmd, file=self.gdb.stdin, flush=True)
        self.attached = False

    def call_function(self, func_addr, arg=0):
        cmd = f"p ((void *(*)()){func_addr})({arg})"
        print(cmd, file=self.gdb.stdin, flush=True)
        line = self.gdb.stdout.readline()
        addr_idx = line.find("0x")
        if -1 != addr_idx:
            return int(line[addr_idx: -1].split()[0], 16)
        return 0

    def write_data(self, addr, data):
        if not addr:
            return
        str_data = data.decode("utf-8")
        cmd = f"p strcpy({addr}, \"{str_data}\")"
        print(cmd, file=self.gdb.stdin, flush=True)
        _line = self.gdb.stdout.readline()

    def read_data(self, addr):
        if not addr:
            return ""
        cmd = f"p (const char *){addr}"
        print(cmd, file=self.gdb.stdin, flush=True)
        line = self.gdb.stdout.readline()
        return line
