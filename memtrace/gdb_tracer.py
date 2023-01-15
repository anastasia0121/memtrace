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
            line =  self.gdb.stdout.readline()
            if not line or line == "":
                break
            if "I am ready" in line:
                self.attached = True
                break

    def detach(self):
        input = "q"
        print(input, file=self.gdb.stdin, flush=True)
        input = "y"
        print(input, file=self.gdb.stdin, flush=True)
        self.attached = False

    def call_function(self, func_addr, arg=0):
        input = "p ((void *(*)()){})({})".format(func_addr, arg)
        print(input, file=self.gdb.stdin, flush=True)
        line =  self.gdb.stdout.readline()
        addr_idx = line.find("0x")
        if -1 != addr_idx:
            return int(line[addr_idx: -1].split()[0], 16)
        return 0

    def write_data(self, addr, data):
        if not addr:
            return
        input = "p strcpy({}, \"{}\")".format(addr, data.decode("utf-8"))
        print(input, file=self.gdb.stdin, flush=True)
        line = self.gdb.stdout.readline()

    def read_data(self, addr):
        if not addr:
            return ""
        input = "p (const char *){}".format(addr)
        print(input, file=self.gdb.stdin, flush=True)
        line = self.gdb.stdout.readline()
        return line
