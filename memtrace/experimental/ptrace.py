"""
Attach and call functions in tracee process.
"""
import copy
import ctypes
import ctypes.util
import errno
import os
import signal
import sys

from util import fail_program, find_libs_segments, find_function_or_fail

PTRACE_PEEKDATA = 2
PTRACE_POKEDATA = 5
PTRACE_CONT = 7
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_GETFPREGS = 14
PTRACE_SETFPREGS = 15
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_GETREGSET = 0x4204
PTRACE_SETREGSET = 0x4205

WALL = 0x40000000

NT_X86_XSTATE = 0x202
# Big enough for any xsave layout the kernel reports (AMX included).
# The kernel writes the real size back into iov_len.
XSTATE_BUF_SIZE = 32 * 1024

WSIZE = ctypes.sizeof(ctypes.c_long)

RED_ZONE = 128
EFLAGS_TF = 0x100
EFLAGS_DF = 0x400
# orig_rax value that tells the kernel "not in a syscall": no syscall restart
# and no rip correction on resume.
NO_SYSCALL = 0xffffffffffffffff
INT3 = 0xcc
# x86-64 SysV integer argument registers
ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
# Synchronous signals: the called function itself caused them, do not pass them on.
FAULT_SIGNALS = (signal.SIGSEGV, signal.SIGBUS, signal.SIGILL,
                 signal.SIGFPE, signal.SIGTRAP)


class UserFpregsStruct(ctypes.Structure):
    """
    Floating-point registers. From user.h
    """
    _fields_ = [
        ("cwd", ctypes.c_ushort),
        ("swd", ctypes.c_ushort),
        ("ftw", ctypes.c_ushort),
        ("fop", ctypes.c_ushort),
        ("rip", ctypes.c_ulonglong),
        ("rdp", ctypes.c_ulonglong),
        ("mxcsr", ctypes.c_uint),
        ("mxcr_mask", ctypes.c_uint),
        ("st_space", ctypes.c_uint * 32),  # 8*16 for each FP-reg = 128 B
        ("xmm_space", ctypes.c_uint * 64),  # 16*16 for each XMM-reg = 256 B
        ("padding", ctypes.c_uint * 24)
    ]


class UserRegsStruct(ctypes.Structure):
    """
    General registers. From user.h
    """
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]


class Iovec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_ulong)
    ]

    def __init__(self, size):
        self.iov_len = size
        self.buf = ctypes.create_string_buffer(bytes(size))
        self.iov_base = ctypes.cast(ctypes.byref(self.buf), ctypes.c_void_p)


class RegCache:
    """
    All registers.
    """
    def __init__(self, pid, libc):
        self.pid = pid
        self.libc = libc
        self.gpr = UserRegsStruct()

        self.use_xsave = False  # set if ptrace succeeds
        self.xsave_area = Iovec(XSTATE_BUF_SIZE)

        self.use_fxsave = False
        self.fpr = UserFpregsStruct()

    def save_regs(self):
        """
        Save general purpose registers into gpr.
        Save all refisters into xsave area, if xsave is supported.
        Save floating-point registers into fpr, if xsave is not supported.
        """
        if 0 != self.libc.ptrace(PTRACE_GETREGS, self.pid, None, ctypes.byref(self.gpr)):
            fail_program(self.pid, "ptrace_getregs")

        # as we call function somewhere in the middle of another function,
        # it is better to save all regs
        # A fresh iovec on every save: the kernel shrinks iov_len to the real size.
        self.use_xsave = False
        self.xsave_area = Iovec(XSTATE_BUF_SIZE)
        if 0 == self.libc.ptrace(PTRACE_GETREGSET, self.pid,
                                 NT_X86_XSTATE, ctypes.byref(self.xsave_area)):
            self.use_xsave = True

        # xsave area include fxsave
        # amd64, FXSAVE
        self.use_fxsave = False
        if not self.use_xsave:
            if 0 == self.libc.ptrace(PTRACE_GETFPREGS, self.pid,
                                     None, ctypes.byref(self.fpr)):
                self.use_fxsave = True

    def restore_regs(self):
        """
        Restore programm registers state from saved values.
        """
        if 0 != self.libc.ptrace(PTRACE_SETREGS, self.pid, None, ctypes.byref(self.gpr)):
            fail_program(self.pid, "ptrace_setregs")

        if self.use_xsave:
            if 0 != self.libc.ptrace(PTRACE_SETREGSET, self.pid,
                                     NT_X86_XSTATE, ctypes.byref(self.xsave_area)):
                fail_program(self.pid, "ptrace_setregset")

        if self.use_fxsave:
            if 0 != self.libc.ptrace(PTRACE_SETFPREGS, self.pid, None, ctypes.byref(self.fpr)):
                fail_program(self.pid, "ptrace_setfpregs")


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


class PtraceTracer:
    def __init__(self, pid, unw=True):
        """
        :pid: process identifier
        :unw: collect stacks with libunwind, frame pointers otherwise
        """
        self.pid = pid
        self.unw = unw
        self.tids = []
        self.libc = self.setup_ptrace_call()
        self.reg_cache = RegCache(self.pid, self.libc)
        self.used_memory = []

        self.enable_addr, self.disable_addr, self.get_data_addr = find_tracing_functions(pid)

    def enable(self):
        self.attach()
        try:
            # enable_memory_tracing(usable_size=false, unw), as in the gdb tracer
            ret = self.call_function(self.enable_addr, 0, int(self.unw))
            if ret:
                fail_program(self.pid, "enable_memory_tracing", self.read_string(ret))
        finally:
            self.detach()

    def disable(self, mt_fname):
        self.attach()
        try:
            mt_fname_addr = self.call_function(self.get_data_addr)
            if not mt_fname_addr:
                fail_program(self.pid, "disable_memory_tracing", "return address is empty.")
            self.write_string(mt_fname_addr, str(mt_fname))

            ret = self.call_function(self.disable_addr)
            if 0 != ret:
                error = self.read_string(ret)
                if error:
                    fail_program(self.pid, "disable_memory_tracing", error)
        finally:
            self.detach()

    def setup_ptrace_call(self):
        """
        Find c library and initialize ptrace function.
        """
        libc_path = ctypes.util.find_library("c")
        if not libc_path:
            fail_program(self.pid, "find_library", "Cannot find libc.")

        libc = ctypes.CDLL(libc_path, use_errno=True)
        libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64,
                                ctypes.c_void_p, ctypes.c_void_p]
        libc.ptrace.restype = ctypes.c_uint64

        return libc

    def find_process_threads(self):
        """
        Find all threads identifiers.

        :return: list of threads identifiers
        """
        task_dir = f"/proc/{self.pid}/task"
        task_dirs = os.listdir(task_dir)
        tids = [int(d)
                for d in task_dirs
                if os.path.isdir(os.path.join(task_dir, d))
                and d.isdigit()]

        return tids

    def wait_stop(self, tid):
        """
        Wait for the thread stop.

        :tid: thread identifier
        :return: stop signal or None if the thread is gone
        """
        try:
            _, stat = os.waitpid(tid, WALL)
        except ChildProcessError:
            return None
        if os.WIFSTOPPED(stat):
            return os.WSTOPSIG(stat)
        return None

    def attach_thread(self, tid):
        """
        Attach to one thread and wait until it is stopped by SIGSTOP.
        Other signals that arrive first are passed on to the thread.

        :tid: thread identifier
        :return: False if the thread has already exited
        """
        if 0 != self.libc.ptrace(PTRACE_ATTACH, tid, None, None):
            if ctypes.get_errno() == errno.ESRCH:
                return False
            fail_program(self.pid, f"ptrace_attach({tid})")

        stop_sig = self.wait_stop(tid)
        while stop_sig is not None and stop_sig != signal.SIGSTOP:
            if 0 != self.libc.ptrace(PTRACE_CONT, tid, None, stop_sig):
                fail_program(self.pid, f"ptrace_cont({tid})")
            stop_sig = self.wait_stop(tid)

        if stop_sig is None:
            return False
        self.tids.append(tid)
        return True

    def attach(self):
        """
        Attach to process.
        Stop all threads.
        """
        self.tids = []
        seen = set()
        try:
            # threads can be created while we are attaching,
            # repeat until every thread is stopped
            while True:
                new_tids = [tid for tid in self.find_process_threads() if tid not in seen]
                if not new_tids:
                    break
                for tid in new_tids:
                    seen.add(tid)
                    self.attach_thread(tid)
        except BaseException:
            self.detach()
            raise

    def detach(self):
        """
        Detach from all threads.
        """
        tids, self.tids = self.tids, []
        for tid in tids:
            if 0 != self.libc.ptrace(PTRACE_DETACH, tid, None, None):
                if ctypes.get_errno() != errno.ESRCH:
                    print(f"warning: ptrace_detach({tid}): {os.strerror(ctypes.get_errno())}",
                          file=sys.stderr)

    def get_regs(self):
        """
        :return: general purpose registers of the process main thread
        """
        regs = UserRegsStruct()
        if 0 != self.libc.ptrace(PTRACE_GETREGS, self.pid, None, ctypes.byref(regs)):
            fail_program(self.pid, "ptrace_getregs")
        return regs

    def setup_call(self, func_addr, args):
        """
        Prepare stack and regs to function call.

        :func_addr: addres of callable function
        :args: integer arguments of the function
        :return: address where the function returns to
        """
        if len(args) > len(ARG_REGS):
            fail_program(self.pid, "setup_call", "too many arguments")

        regs = copy.deepcopy(self.reg_cache.gpr)

        # setup stack, the red zone belongs to the interrupted function:
        #   aligned - 128: end of the red zone
        #   trap word: the function returns here
        #   return address slot: rsp at the function entry (rsp % 16 == 8)
        rsp = regs.rsp & 0xfffffffffffffff0
        red_zone_end = rsp - RED_ZONE
        trap_addr = red_zone_end - WSIZE
        ret_slot = red_zone_end - 3 * WSIZE

        regs.rsp = ret_slot
        regs.rip = func_addr
        # not in a syscall: the kernel must neither restart it nor move rip
        regs.orig_rax = NO_SYSCALL
        regs.rax = 0
        for reg, value in zip(ARG_REGS, args):
            setattr(regs, reg, value)
        regs.eflags &= ~(EFLAGS_TF | EFLAGS_DF)

        # RESTORE state
        self.save_word(ret_slot)
        self.write_word(ret_slot, trap_addr)

        # The stack is not executable: the return fails with SIGSEGV at trap_addr.
        # If it is executable, int3 raises SIGTRAP instead.
        self.save_word(trap_addr)
        self.write_word(trap_addr, INT3)

        if 0 != self.libc.ptrace(PTRACE_SETREGS, self.pid, None, ctypes.byref(regs)):
            fail_program(self.pid, "setup_call, ptrace_setregs")

        return trap_addr

    def save_word(self, addr):
        """
        Save word from tracee process memory.

        :addr: addres where word is placed
        """
        word = self.read_word(addr)
        self.used_memory.append((addr, word))

    def restore_words(self):
        """
        Restore all memorized words, the last saved first.
        """
        used_memory, self.used_memory = self.used_memory, []
        for addr, word in reversed(used_memory):
            self.write_word(addr, word)

    def call_function(self, func_addr, *args):
        """
        Call function in tracee process.
        Registers and memory of the process are restored in any case.

        :func_addr: function address to call
        :args: integer arguments of the function
        :return: return value of callable function
        """
        self.reg_cache.save_regs()
        try:
            trap_addr = self.setup_call(func_addr, args)

            sig = 0
            while True:
                if 0 != self.libc.ptrace(PTRACE_CONT, self.pid, None, sig):
                    fail_program(self.pid, "ptrace_cont")

                stop_sig = self.wait_stop(self.pid)
                if stop_sig is None:
                    fail_program(self.pid, "call_function", "process exited during the call")

                regs = self.get_regs()
                if ((stop_sig == signal.SIGSEGV and regs.rip == trap_addr) or
                        (stop_sig == signal.SIGTRAP and regs.rip == trap_addr + 1)):
                    return regs.rax

                if stop_sig in FAULT_SIGNALS:
                    fail_program(self.pid, "call_function",
                                 f"function failed with {signal.Signals(stop_sig).name} "
                                 f"at {hex(regs.rip)}")

                # an ordinary signal (SIGCHLD, SIGALRM...) was sent to the process
                # during the call: pass it on, SIGSTOP is our own
                sig = 0 if stop_sig == signal.SIGSTOP else stop_sig
        finally:
            self.reg_cache.restore_regs()
            self.restore_words()

    def write_word(self, addr, word):
        """
        Write word into tracee process memory.

        :addr: address to write
        :word: word to write
        """
        if not addr:
            print("write_word(): addr is empty")
            return

        if 0 != self.libc.ptrace(PTRACE_POKEDATA, self.pid, addr, word):
            fail_program(self.pid, f"ptrace_pokedata(addr={addr}, word={word})")

    def write_string(self, addr, data, limit=1024):
        """
        Write zero terminated string into tracee process memory.

        :addr: start address to write
        :data: string to write
        :limit: size of the buffer in the process, terminator included.
                1024 by default
        """
        if not addr:
            print("write_data(): addr is empty")
            return

        bdata = bytes(data, encoding="utf-8") + b"\0"
        if len(bdata) > limit:
            fail_program(self.pid, "write_data", "limit overflow")

        # the last word is padded with zeros
        bdata += bytes(-len(bdata) % WSIZE)
        for offset in range(0, len(bdata), WSIZE):
            word = int.from_bytes(bdata[offset:offset + WSIZE], byteorder="little")
            self.write_word(addr + offset, word)

    def read_word(self, addr):
        """
        Read word from tracee process memory.

        :addr: address to read
        :return: read word
        """
        if not addr:
            return 0

        # -1 is a valid word, only errno tells about an error
        ctypes.set_errno(0)
        word = self.libc.ptrace(PTRACE_PEEKDATA, self.pid, addr, None)
        if 0 != ctypes.get_errno():
            fail_program(self.pid, f"ptrace_peekdata({addr})")

        return word

    def read_string(self, addr, limit=1024):
        """
        Read zero terminated string from tracee process memory.

        :addr: start address to read
        :limit: max string length. 1024 by default
        :return: read string
        """
        if not addr:
            return ""

        ret = b""
        for offset in range(0, limit, WSIZE):
            chunk = self.read_word(addr + offset).to_bytes(WSIZE, byteorder='little')
            end = chunk.find(b"\0")
            if end >= 0:
                ret += chunk[:end]
                break
            ret += chunk

        return ret.decode("utf-8", errors="replace")
