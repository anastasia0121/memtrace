"""
Llvm symbolyzer wrapper.
"""
import contextlib
import os
import signal
import sys
import json

from subprocess import Popen, PIPE

class Symbolizer:
    """
    Read input addresses and return
    corresponding source code locations.
    """
    def __init__(self, symbolizer_path, prefix="\t"):
        self.prefix = prefix
        self.symbolizer = Popen([symbolizer_path, "--output-style=JSON", "-s"],
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
        return self.get_symbols(lib, local_addr)

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

        line = self.symbolizer.stdout.readline().strip()

        symbol_json = json.loads(line)
        if (not "Address" in symbol_json) or (not len(symbol_json["Symbol"])):
            print("WARNING: empty address")
            return f"{offset} from {lib}"

        # read empty
        self.symbolizer.stdout.readline()

        # {"Address":"0xf5219",
        #  "ModuleName":"mylib.so",
        #  "Symbol":[{"Column":5, "Discriminator":0, "FileName":"file.c", "FunctionName":"func",
        #             "Line":26781,"StartAddress":"0xf5200", "StartFileName":"file.c", "StartLine":26767}]}
        out = ""
        for symbol in symbol_json["Symbol"]:
            func_name = symbol['FunctionName'] or hex(offset)
            file_name = symbol['FileName']
            file_line = symbol['Line']
            if file_name:
                out += f"{self.prefix}{func_name} at {file_name}:{file_line}\n"
            else:
                out += f"{self.prefix}{func_name} from {lib}\n"

        return out
