"""
Common functions.
"""
import ctypes
import sys
import os
from elftools.elf.elffile import ELFFile


def fail_program(pid, action, error=""):
    """
    Print error and exit.

    :pid: process identifier
    :action: function name or code description
    :error: error message,
            errno will be used if the error is empty
    """
    error = error if error else os.strerror(ctypes.get_errno())
    sys.exit(f"error: pid={pid}, {action}, {error}")


def find_libs_segments(pid, lib_name):
    """
    Search rx segments of libar(y/ies)
    with required name or part of the name.

    :pid: process identifier
    :lib_name: library name
    :return: addresses of segments
    """
    ret = []
    with open(f"/proc/{pid}/maps", "r") as maps:
        for line in maps:
            tokens = line.strip().split()
            addr = int(tokens[0].split("-")[0], 16)
            permissions = tokens[1]
            name = tokens[5] if len(tokens) > 5 else ""

            if (lib_name in name) and ("r-xp" in permissions):
                ret.append({"addr":  addr, "name":  name})

    # several libs with similar name
    return ret


def find_function_addr(func_name, libs):
    """
    Search the first function with required name
    in the libraries.

    :func_name: function name
    :libs: list of code segments of libraries.
    :return: function address
    """
    for lib in libs:
        with open(lib["name"], "rb") as libfile:
            elffile = ELFFile(libfile)

            segments = elffile.iter_segments()
            # permissions = R E
            vaddr = [s.header["p_vaddr"] for s in segments if s.header["p_flags"] == 0x5]

            symtab = elffile.get_section_by_name(".symtab")
            symbols = [s for s in symtab.iter_symbols() if s.name == func_name]
            if not symbols:
                return 0

            addr = lib["addr"] + symbols[0].entry["st_value"] - vaddr[0]

            return addr


def find_function_or_fail(pid, func_name, libs):
    """
    Search the first function with required name
    in the libraries.
    Print error and exit if cannot find.

    :func_name: function name
    :libs: list of code segments of libraries.
    :return: function address
    """
    func_addr = find_function_addr(func_name, libs)
    if not func_addr:
        fail_program(pid, "find_function_addr", f"Cannot find {func_name}.")
    return func_addr
