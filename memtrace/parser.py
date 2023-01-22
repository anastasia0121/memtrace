from functools import cmp_to_key
from os.path import basename
from subprocess import Popen, PIPE
import os
import signal


def read_int(fh):
        data = fh.read(8)
        if data:
            return int.from_bytes(data, byteorder='little', signed=False)
        return 0

def cmp_stacks(a, b):
    a_not_freed = a.info.allocated - a.info.freed
    b_not_freed = b.info.allocated - b.info.freed
    if (a_not_freed == b_not_freed) and (a.info.allocated == b.info.allocated):
        return 0
    if a_not_freed != b_not_freed:
        return -1 if b_not_freed < a_not_freed else 1
    else:
        return -1 if b.info.allocated < a.info.allocated else 1

class AllocationPoint(object):
    def __init__(self, allocated, allocated_count, freed, freed_count, stack):
        self.info = Statistics(allocated, allocated_count, freed, freed_count)
        self.stack = stack


class LinkedLibrary(object):
    def __init__(self):
        self.mapped_addr = 0
        self.begin = 0
        self.end = 0
        self.path = ""
        self.symbols = []


class Statistics(object):
    def __init__(self, allocated = 0, allocated_count = 0, freed = 0, freed_count = 0):
        self.allocated = allocated
        self.allocated_count = allocated_count
        self.freed = freed
        self.freed_count = freed_count

    def add_info(self, info):
        self.allocated_count += info.allocated_count
        self.allocated += info.allocated
        self.freed += info.freed
        self.freed_count += info.freed_count


class DataStorage(object):
    def __init__(self):
        self.stats = Statistics()
        self.duration = 0
        self.mapper = []
        self.stacks_info = []
        self.version = 1

    def add_lib_info(self, mapped_addr, v_addr, memsize, path):
        lib = LinkedLibrary()
        lib.mapped_addr = mapped_addr
        lib.v_addr = v_addr
        lib.memsize = memsize
        lib.path = path
        lib.begin = lib.mapped_addr + lib.v_addr
        lib.end = lib.begin + lib.memsize
        self.mapper.append(lib)

    def add_alloc_info(self, allocated, allocated_count, freed, freed_count, stack):
        alloc_info = AllocationPoint(allocated, allocated_count, freed, freed_count, stack)
        self.stats.add_info(alloc_info.info)
        self.stacks_info.append(alloc_info)

    def init_from_file(self, fname):
        with open(fname, 'rb') as fh:
            while True:
                type = fh.read(1)
                if not type:
                    return

                if type == b'v':
                    # read common information: v, version
                    version = read_int(fh)
                    if version > self.version:
                        print("Server version is heigher than the memtrace version.")
                        print("Please, update memtrace utility.")
                        exit()

                    usableSize = fh.read(1)
                    read_int(fh)
                    read_int(fh)
                    read_int(fh)
                    read_int(fh)
                    read_int(fh)

                elif type == b's':
                    # read library: s, addr, size of path, path
                    mapped_addr = read_int(fh)
                    v_addr = read_int(fh)
                    memsize = read_int(fh)
                    size = read_int(fh)

                    path = fh.read(size).decode("utf-8")
                    self.add_lib_info(mapped_addr, v_addr, memsize, path);

                elif type == b'm':
                    # m, aggregated info (allocated, allocation counter, freed, freed counter),
                    # size of stack, stack

                    allocated = read_int(fh)
                    allocated_count = read_int(fh)
                    freed = read_int(fh)
                    freed_count = read_int(fh)
                    
                    stack_lenght = read_int(fh)
                    if stack_lenght == 0:
                        print("Cannot recognize stack")
                    elif stack_lenght > 128:
                        print("Size of a stack is too huge, the data file is broken")
                        exit()
                    else:
                        stack = []
                        for i in range(stack_lenght):
                            frame = read_int(fh)
                            stack.append(frame)

                        self.add_alloc_info(allocated, allocated_count, freed, freed_count, stack)
                else:
                    print("Cannot recognize type")
                    exit()

        sorted_stacks_info = sorted(self.stacks_info, key=cmp_to_key(cmp_stacks))
        self.stacks_info = sorted_stacks_info


class Symbolizer(object):
    def __init__(self):
        self.symbolizer = Popen('llvm-symbolizer-14',
                                stdin=PIPE, stdout=PIPE, stderr=PIPE,
                                universal_newlines=True, bufsize=1)

    def __del__(self):
        os.kill(self.symbolizer.pid, signal.SIGKILL)

    def symbolize(self, stack, mapper):
        output = ""
        for addr in stack:
            lib = next((l for l in mapper if (l.begin < addr) and (l.end > addr)), None)
            if not lib:
                output += "\t << stack pointer broken >>\n"
                continue

            local_addr = addr - lib.mapped_addr
            symbols = self.get_symbols(lib, local_addr)
            for i in range(0, len(symbols), 2):
                if symbols[i + 1] == 0:
                    output += "\t{}\tfrom {}\n".format(symbols[i], lib.path)
                else:
                    output += "\t{}\tat {}\n".format(symbols[i], symbols[i + 1])
        return output

    def get_symbols(self, lib, offset):
        input = "{} {}\n".format(lib.path, hex(offset))
        print(input, file=self.symbolizer.stdin, flush=True)
        pout = []
        while True:
            line = self.symbolizer.stdout.readline()
            # double white line
            if len(line) == 1:
                self.symbolizer.stdout.readline()
                break
            pout.append(line.strip())
        return pout


class Parser(object):
    def __init__(self, mt_fname):
        self.ds = DataStorage()
        self.ds.init_from_file(mt_fname)

    def report(self):
        ds = self.ds
        symbolizer = Symbolizer()

        for stack_info in ds.stacks_info:
            not_freed = stack_info.info.allocated - stack_info.info.freed
            if not not_freed:
                continue
            not_freed_count = stack_info.info.allocated_count - stack_info.info.freed_count
            average = int(not_freed / not_freed_count)

            allocated_str = "Allocated {allocated} bytes in {allocated_count} allocations ({average} bytes average)"
            print(allocated_str.format(allocated = not_freed, allocated_count = not_freed_count, average = average))

            output = symbolizer.symbolize(stack_info.stack, ds.mapper)
            print(output)

        not_freed_count = ds.stats.allocated_count - ds.stats.freed_count;
        not_freed = ds.stats.allocated - ds.stats.freed;
        total_str = "Total: allocation {allocated_count} of total size {allocated}\n";
