"""
Llvm symbolyzer wrapper.
"""
import contextlib
import os
import signal
import sys

from subprocess import Popen, PIPE

class Symbolizer:
    """
    Read input addresses and return
    corresponding source code locations.
    """
    def __init__(self, symbolizer_path, prefix="\t"):
        self.prefix = prefix
        self.symbolizer = Popen(symbolizer_path,
                                stdin=PIPE, stdout=PIPE, stderr=PIPE,
                                universal_newlines=True, bufsize=1)

    def close(self):
        """
        Kill symbolizer process.
        """
        if self.symbolizer:
            os.kill(self.symbolizer.pid, signal.SIGKILL)
            self.symbolizer = None

    def symbolize_addr(self, addr, mapper):
        """
        Translate address to human readable stack.

        :addr: integer value
        :mapper: libraries information
        :return: symbols for address
        """
        lib = next((so for so in mapper if so.has(addr)), None)
        if not lib:
            return f"{self.prefix}<< stack pointer broken >>\n"

        local_addr = addr - lib.mapped_addr
        symbols = self.get_symbols(lib, local_addr)
        output = ""
        for i in range(0, len(symbols), 2):
            if symbols[i+1] == 0:
                output += f"{self.prefix}{symbols[i]} from {lib.path}\n"
            else:
                file_name = os.path.basename(symbols[i+1])
                output += f"{self.prefix}{symbols[i]} at {file_name}\n"
        return output

    def symbolize(self, stack, mapper):
        """
        Translate addresses to human readable stack.

        :stack: list with integer numbers
        :mapper: libraries information
        :return: symbols for stack
        """
        output = ""
        for addr in stack:
            output += self.symbolize_addr(addr, mapper)
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
