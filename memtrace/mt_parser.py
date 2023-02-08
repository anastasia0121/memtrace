"""
*.mt file parser
"""
import contextlib
import os
import signal
import sys

from functools import cmp_to_key
from subprocess import Popen, PIPE

class MTFile:
    """
    Wrapper to open mt file.
    """
    def __init__(self, fname):
        self.mt_file = open(fname, "rb")

    def close(self):
        """
        Close mt file.
        """
        if self.mt_file:
            self.mt_file.close()
            self.mt_file = None

    def read_int(self):
        """
        Read uint64_t value from the file.

        :return: read value or 0
        """
        size = 8
        data = self.mt_file.read(size)
        return int.from_bytes(data, byteorder='little', signed=False) if data else 0

    def read_byte(self):
        """
        Read uint8_t value from the file.

        :return: read value
        """
        return self.mt_file.read(1)

    def read_string(self):
        """
        Read uint64_t value as string size.
        Read string value.

        :return: read string
        """
        size = self.read_int()
        return self.mt_file.read(size).decode("utf-8")

    def read_stack_of_fail(self, max_lenght=128):
        """
        Read uint64_t value as stack length.
        Read uint64_t * stack length as frames.

        :return: list of frames or None
        """
        stack_lenght = self.read_int()
        if stack_lenght == 0:
            print("Cannot recognize stack")
            return None

        if stack_lenght > max_lenght:
            sys.exit("Size of a stack is too huge, the data file is broken")

        stack = []
        for _i in range(stack_lenght):
            frame = self.read_int()
            stack.append(frame)
        return stack


def cmp_stacks(a, b):
    """
    Comorator for allocation points.
    1. Compare not freed memory
    2. Compare allocated memory (freed and not freed)

    :a: value to compare
    :b: value to compare
    :return: -1 (a > b) / 1 (a < b) / 0 (a == b)
    """
    a_not_freed = a.info.allocated - a.info.freed
    b_not_freed = b.info.allocated - b.info.freed
    if (a_not_freed == b_not_freed) and (a.info.allocated == b.info.allocated):
        return 0
    if a_not_freed != b_not_freed:
        return -1 if b_not_freed < a_not_freed else 1
    return -1 if b.info.allocated < a.info.allocated else 1


class AllocationPoint:
    """
    Information about a code point where malloc() was called.
    """
    def __init__(self, allocated, allocated_count, freed, freed_count, stack):
        """
        :allocated: size of all allocations
        :allocated_count: number of allocations
        :freed: size of all deallocations
        :freed_count: number of deallocations
        :stack: code point
        """
        self.info = Statistics(allocated, allocated_count, freed, freed_count)
        self.stack = stack


class SharedLibrary:
    """
    Shared library description.
    """
    def __init__(self, mapped_addr=0, v_addr=0, memsize=0, path=""):
        self.mapped_addr = mapped_addr
        self.path = path
        self.begin = mapped_addr + v_addr
        self.end = self.begin + memsize
        self.symbols = []


class Statistics:
    """
    Statistics about allocation(s)/deallocation(s)
    """
    def __init__(self, allocated=0, allocated_count=0, freed=0, freed_count=0):
        self.allocated = allocated
        self.allocated_count = allocated_count
        self.freed = freed
        self.freed_count = freed_count

    def add_info(self, info):
        """
        Append strtistics.
        """
        self.allocated_count += info.allocated_count
        self.allocated += info.allocated
        self.freed += info.freed
        self.freed_count += info.freed_count


class DataStorage:
    """
    Data about all allocations/deallocations.
    Data about all loaded libraries.
    """
    def __init__(self):
        self.stats = Statistics()
        self.duration = 0
        self.mapper = []
        self.stacks_info = []
        self.version = 1

    def add_lib_info(self, mapped_addr, v_addr, memsize, path):
        """
        Add information about shared library.
        """
        lib = SharedLibrary(mapped_addr, v_addr, memsize, path)
        self.mapper.append(lib)

    def add_alloc_info(self, allocated, allocated_count, freed, freed_count, stack):
        """
        Add information code point and
        all allocations/deallocations in the point.
        """
        alloc_info = AllocationPoint(allocated, allocated_count,
                                     freed, freed_count,
                                     stack)
        self.stats.add_info(alloc_info.info)
        self.stacks_info.append(alloc_info)

    def init_from_file(self, fname):
        """
        Load data from file.

        :fname: *.mt file
        :return: nothing
        """
        with contextlib.closing(MTFile(fname)) as mt_file:
            while True:
                record_type = mt_file.read_byte()
                if not record_type:
                    return

                if record_type == b'v':
                    # read common information: v, version
                    version = mt_file.read_int()
                    if version > self.version:
                        sys.exit("Libmetrace version is heigher than the client."
                                 "Please, update memtrace utility.")

                    _usable_size = mt_file.read_byte()
                    _now_in_mem = mt_file.read_int()
                    _all_allocated = mt_file.read_int()
                    _memory_peak = mt_file.read_int()
                    _ptr_overhead = mt_file.read_int()
                    _stack_overhead = mt_file.read_int()

                elif record_type == b's':
                    # s, addr, v_addr, so_memsize, size of path, path
                    mapped_addr = mt_file.read_int()
                    v_addr = mt_file.read_int()
                    memsize = mt_file.read_int()
                    path = mt_file.read_string()
                    self.add_lib_info(mapped_addr, v_addr, memsize, path)

                elif record_type == b'm':
                    # m, aggregated info
                    # (allocated, allocation counter,
                    # freed, freed counter),
                    # size of stack, stack

                    allocated = mt_file.read_int()
                    allocated_count = mt_file.read_int()
                    freed = mt_file.read_int()
                    freed_count = mt_file.read_int()
                    stack = mt_file.read_stack_of_fail()
                    if stack:
                        self.add_alloc_info(allocated, allocated_count,
                                            freed, freed_count, stack)

                else:
                    sys.exit("Cannot recognize record type")

        sorted_stacks_info = sorted(self.stacks_info, key=cmp_to_key(cmp_stacks))
        self.stacks_info = sorted_stacks_info


class Symbolizer:
    """
    Read input addresses and return
    corresponding source code locations.
    """
    def __init__(self):
        self.symbolizer = Popen("llvm-symbolizer",
                                stdin=PIPE, stdout=PIPE, stderr=PIPE,
                                universal_newlines=True, bufsize=1)

    def close(self):
        """
        Kill symbolizer process.
        """
        if self.symbolizer:
            os.kill(self.symbolizer.pid, signal.SIGKILL)
            self.symbolizer = None

    def symbolize(self, stack, mapper):
        """
        Translate adressed to human readable stack.

        :stack: list with integer numbers
        :mapper: libraries information
        :return: symbols for stack
        """
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
                    output += f"\t{symbols[i]}\tfrom {lib.path}\n"
                else:
                    output += f"\t{symbols[i]}\tat {symbols[i+1]}\n"
        return output

    def get_symbols(self, lib, offset):
        """
        :return: symbols by offset
        """
        in_str = f"{lib.path} {hex(offset)}\n"
        print(in_str, file=self.symbolizer.stdin, flush=True)
        pout = []
        while True:
            line = self.symbolizer.stdout.readline()
            # double white line
            if len(line) == 1:
                self.symbolizer.stdout.readline()
                break
            pout.append(line.strip())
        return pout


class Parser:
    def __init__(self, mt_fname):
        self.storage = DataStorage()
        self.storage.init_from_file(mt_fname)

    def report_stack(self, symbolizer, stack_info):
        memsize = stack_info.info.allocated - stack_info.info.freed
        if not memsize:
            return
        cnt = stack_info.info.allocated_count - stack_info.info.freed_count
        avg = int(memsize / cnt)
        print(f"Allocated {memsize} bytes in {cnt} allocations ({avg} bytes average)")

        output = symbolizer.symbolize(stack_info.stack, self.storage.mapper)
        print(output)

        memsize = self.storage.stats.allocated_count - self.storage.stats.freed_count
        cnt = self.storage.stats.allocated - self.storage.stats.freed
        print(f"Total: allocation {memsize} of total size {cnt}")

    def report(self):
        with contextlib.closing(Symbolizer()) as symbolizer:
            for stack_info in self.storage.stacks_info:
                self.report_stack(symbolizer, stack_info)
