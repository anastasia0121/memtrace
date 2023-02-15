#!/usr/bin/env python3

import argparse
import os
import platform
import signal
import sys

from datetime import datetime
from pathlib import Path

from gdb_tracer import GDBTracer
from report import Report
from ptrace import PtraceTracer
from util import fail_program, find_libs_segments, find_function_or_fail


def signal_handler(_sig, _frame):
    print("You pressed Ctrl+C.")


def find_tracing_functions(pid):
    """
    Check if libmemtrace is loaded
    in a process with pid.
    Find enable_memory_tracing(),
         disable_memory_tracing(),
         get_tracing_shared_data()
    in the library.
    Return adresses of functions.
    """
    # check if tracing libary is loaded
    lib_name = "libmemtrace.so"
    libs = find_libs_segments(pid, lib_name)
    if not libs:
        fail_program(pid, "find_lib_segment",
                     f"{lib_name} is not loaded.")

    # find required function
    enable_addr = find_function_or_fail(pid, "enable_memory_tracing", libs)
    disable_addr = find_function_or_fail(pid, "disable_memory_tracing", libs)
    get_data_addr = find_function_or_fail(pid, "get_tracing_shared_data", libs)

    return enable_addr, disable_addr, get_data_addr


def generate_mt_fname(pid):
    """
    Generate name for the new mt file.
    """
    fname = f"{pid}-%m%d%Y-%H%M%S.mt\0"
    trace_dir = Path(os.getcwd())
    mt_fname = trace_dir / datetime.now().strftime(fname)

    return mt_fname


def report(mt_fname, tree):
    report = Report(mt_fname)
    if tree:
        report.report_tree()
    else:
        report.report_txt()
    report.report_flame()

def main_func():
    if platform.uname()[4] != "x86_64":
        print("only x86_64 is supported")

    parser = argparse.ArgumentParser(
        prog = "memtrace",
        description = "memtrace is a tool to trace allocations in c++ applications.")

    parser.add_argument("-p", "--pid",
                        dest="pid", action="store", type=int,
                        help="process identifier")
    parser.add_argument("-f", "--file",
                        dest="mt_fname", action="store", metavar="FILE",
                        help="existing mt file")
    parser.add_argument("-g", "--gdb",
                        dest="gdb", action="store_true",
                        help="use gdb instead of manual ptrace calls")

    actions_group = parser.add_argument_group(
        "Actions",
        "Tracing use interactiv mode by default. "
        "If only enable/disable/status are required. "
        "Set one of following options:")
    actions_group.add_argument("-e", "--enable",
                               dest="enable", action="store_true",
                               help="enable tracing")
    actions_group.add_argument("-d", "--disable",
                               dest="disable", action="store_true",
                               help="disable tracing")
    actions_group.add_argument("-s", "--status",
                               dest="status", action="store_true",
                               help="current status of tracing")

    actions_group = parser.add_argument_group(
        "Output",
        "Output options.")
    actions_group.add_argument("-t", "--tree",
                               dest="tree", action="store_true",
                               help="out as tree")

    options = parser.parse_args()

    pid = options.pid
    gdb = options.gdb
    enable = options.enable
    disable = options.disable
    status = options.status
    interactive = (not disable) and (not enable) and (not status)
    mt_fname = options.mt_fname
    tree = options.tree

    if mt_fname and (pid or enable or disable or status or gdb):
        fail_program(0, "parse_args",
                     "file option cannot be set with other options together")

    if (not pid) and (not mt_fname):
        fail_program(0, "parse_args", "Pid is not specified.")

    if tree and (not interactive) and (not disable) and (not mt_fname):
        fail_program(pid, "parse_args", "Tree option with not output launch.")

    if (enable and disable) or (disable and status) or (enable and status):
        fail_program(pid, "parse_args",
                     "More than one actions (enable/disable/stats) are specified.")

    if pid and (not Path(f"/proc/{pid}/maps").exists()):
        fail_program(pid, "find_proc_map",
                     f"There is no map for {pid}")

    # handel the exsisting mt file without tracing process
    if mt_fname:
        report(mt_fname, tree)
        sys.exit(0)

    # if we kill tracer, we can kill child process
    signal.signal(signal.SIGINT, signal_handler)

    print("Connection to process. Please wait.")

    enable_addr, disable_addr, get_shared_data_addr = find_tracing_functions(pid)
    tracer = GDBTracer(pid) if gdb else PtraceTracer(pid)

    # inject enable
    if (enable or interactive):
        tracer.attach()
        tracer.call_function(enable_addr, 0)
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
            print(f"Tracing for {pid} is disabled.")
        else:
            print(f"Tracing for {pid} is enabled.")
        tracer.detach()

    # inject disable
    if interactive or disable:
        tracer.attach()

        mt_fname = generate_mt_fname(pid)
        mt_fname_addr = tracer.call_function(get_shared_data_addr, 0)
        if not mt_fname_addr:
            fail_program(pid, "disable_memory_tracing", "return address is empty.")
        tracer.write_string(mt_fname_addr, str(mt_fname))

        ret = tracer.call_function(disable_addr)
        if 0 != ret:
            error = tracer.read_string(ret)
            if error:
                fail_program(pid, "disable_memory_tracing", error)

        tracer.detach()

        print(f"mt file is {mt_fname}")

        report(mt_fname, tree)

main_func()
