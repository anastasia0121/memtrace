#!/usr/bin/env python3

import ctypes
import sys
import os
import errno
import copy
from elftools.elf.elffile import ELFFile
import signal
from datetime import datetime
from pathlib import Path
from optparse import OptionParser
from optparse import OptionGroup

from parser import Parser
from gdb_tracer import GDBTracer
from ptrace import PtraceTracer
from util import fail_program, print_error

def signal_handler(sig, frame):
    print("You pressed Ctrl+C.")

def find_lib_segment(pid, lib_name):
    ret = []
    with open("/proc/{}/maps".format(pid), "r") as maps:
        for line in maps:
            tokens = line.strip().split()
            addr = int(tokens[0].split("-")[0], 16)
            permissions = tokens[1]
            name = tokens[5] if len(tokens) > 5 else ""

            if (lib_name in name) and ("r-xp" in permissions):
                ret.append({"addr":  addr, "name":  name })

    # several libs with similar name
    return ret

def find_function_addr(func_name, libs):
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

def find_tracing_functions(pid):
    # check if tracing libary is loaded
    lib_name = "libmemtrace.so"
    libs = find_lib_segment(pid, lib_name)
    if not libs:
        fail_program(pid, "find_lib_segment",
                     "{} is not loaded.".format(lib_name))

    # find required function
    enable_func_name = "enable_memory_tracing"
    enable_func_addr = find_function_addr(enable_func_name, libs)
    if not enable_func_addr:
        fail_program(pid, "find_function_addr",
                     "Cannot find {} in {}.".format(enable_func_name, lib_name))
    disable_func_name = "disable_memory_tracing"
    disable_func_addr = find_function_addr(disable_func_name, libs)
    if not disable_func_addr:
        fail_program(pid, "find_function_addr",
                     "Cannot find {} in {}.".format(disable_func_name, lib_name))

    get_data_func_name = "get_tracing_shared_data"
    get_data_func_addr = find_function_addr(get_data_func_name, libs)
    if not get_data_func_addr:
        fail_program(pid, "find_function_addr",
                     "Cannot find {} in {}.".format(get_data_func_name, lib_name))

    return enable_func_addr, disable_func_addr, get_data_func_addr


#if __name__ == "__main__":
def main_func(argv):
    parser = OptionParser()

    parser.add_option("-p", "--pid",
                      dest="pid", action="store", type="int", help="process identifier")
    parser.add_option("-f", "--file",
                      dest="mt_fname", action="store", metavar="FILE", help="existing mt file")
    parser.add_option("-g", "--gdb",
                      dest="gdb", action="store_true", help="use gdb instead of manual ptrace calls")

    actions_group = OptionGroup(parser, "Actions",
                    "Tracing use interactiv mode by default. "
                    "If only enable/disable/status are required. "
                    "Set one of following options:")
    parser.add_option_group(actions_group)

    actions_group.add_option("-e", "--enable",
                      dest="enable", action="store_true", help="enable tracing")
    actions_group.add_option("-d", "--disable",
                      dest="disable", action="store_true", help="disable tracing")
    actions_group.add_option("-s", "--status",
                      dest="status", action="store_true", help="current status of tracing")

    (options, args) = parser.parse_args()

    pid = options.pid
    gdb = options.gdb
    enable = options.enable
    disable = options.disable
    status = options.status
    interactive = (not disable) and (not enable) and (not status)
    mt_fname = options.mt_fname

    if mt_fname and (pid or enable or disable or status or gdb):
        fail_program(0, "parse_args", "file option cannot be set with other options together")

    if (not pid) and (not mt_fname):
        fail_program(0, "parse_args", "Pid is not specified.")


    if (enable and disable) or (disable and status) or (enable and status):
        fail_program(pid, "parse_args",
                     "More than one actions (enable/disable/stats) are specified.")

    if pid and (not Path("/proc/{}/maps".format(pid)).exists()):
        fail_program(pid, "find_proc_map",
                     "There is no map for {}".format(pid))

    # handel the exsisting mt file without tracing process
    if mt_fname:
        parser = Parser(mt_fname)
        parser.report()
        exit(0)

    # if we kill tracer, we can kill child process
    signal.signal(signal.SIGINT, signal_handler)

    print("Connection to process. Please wait.")

    enable_func_addr, disable_func_addr, get_shared_data_addr = find_tracing_functions(pid)
    tracer = GDBTracer(pid) if gdb else PtraceTracer(pid);

    # inject enable
    if (enable or interactive):
        tracer.attach()
        tracer.call_function(enable_func_addr, 0)
        tracer.detach()

    # wait some time
    if interactive:
        print("Tracing is enabled.")
        print("Press Ctrl+C to stop tracing.")
        signal.pause()

    # tracing status
    if status:
        tracer.attach()
        ret = tracer.call_function(get_shared_data_addr)
        if not ret:
            print("Tracing for {} is disabled.".format(pid))
        else:
            print("")
        tracer.detach()

    # inject disable
    if interactive or disable:
        tracer.attach()

        # we need a filename
        fname = "{}-%m%d%Y-%H%M%S.mt".format(pid)
        trace_dir = Path(os.getcwd())
        mt_fname = trace_dir / datetime.now().strftime(fname)
        mt_fname_addr = tracer.call_function(get_shared_data_addr, 0)
        tracer.write_data(mt_fname_addr, bytes(str(mt_fname), encoding="utf-8"))

        ret = tracer.call_function(disable_func_addr)
        if 0 != ret:
            error = tracer.read_data(ret)
            if error:
                fail_program(pid, "disable_memory_tracing", error)

        tracer.detach()
        
        print("mt file is {}.".format(mt_fname))

        parser = Parser(mt_fname)
        parser.report()

main_func(sys.argv)
