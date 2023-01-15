import ctypes
import sys
import os
import errno

def print_error(pid, action, error=""):
    error = error if error else os.strerror(ctypes.get_errno())
    print("error: pid={}, {}, {}".format(pid, action, error))

def fail_program(pid, action, error=""):
    print_error(pid, action, error)
    sys.exit(1)
