import ctypes
import ctypes.util
import mmap
import os
import signal
import copy

from util import fail_program

PTRACE_PEEKTEXT   = 1
PTRACE_PEEKDATA   = 2
PTRACE_POKETEXT   = 4
PTRACE_POKEDATA   = 5
PTRACE_CONT       = 7
PTRACE_GETREGS    = 12
PTRACE_SETREGS    = 13
PTRACE_GETFPREGS  = 14
PTRACE_SETFPREGS  = 15
PTRACE_ATTACH     = 16
PTRACE_DETACH     = 17
PTRACE_SETOPTIONS = 0x4200
PTRACE_GETSIGINFO = 0x4202
PTRACE_SETSIGINFO = 0x4203
PTRACE_GETREGSET  = 0x4204
PTRACE_SETREGSET  = 0x4205
PTRACE_SEIZE = 0x4206
PTRACE_INTERRUPT = 0x4207

PTRACE_O_TRACESYSGOOD = 0x1
PTRACE_O_TRACEFORK    = 0x2,
PTRACE_O_TRACEVFORK   = 0x4,
PTRACE_O_TRACECLONE   = 0x8,
PTRACE_O_TRACEEXEC    = 0x10,
PTRACE_O_TRACEVFORKDONE = 0x20,
PTRACE_O_TRACEEXIT    = 0x40,
PTRACE_O_TRACESECCOMP = 0x80,
PTRACE_O_EXITKILL = 0x100000,
PTRACE_O_SUSPEND_SECCOMP = 0x200000,
PTRACE_O_MASK     = 0x3000ff

WALL = 0x40000000

SI_MAX_SIZE = 128
SI_MAX_COUNT = int(SI_MAX_SIZE / ctypes.sizeof(ctypes.c_int))
SI_USER = 0

class user_fpregs_struct(ctypes.Structure):
    _fields_ = [
        ("cwd", ctypes.c_ushort),
        ("swd", ctypes.c_ushort),
        ("ftw", ctypes.c_ushort),
        ("fop", ctypes.c_ushort),
        ("rip", ctypes.c_ulonglong),
        ("rdp", ctypes.c_ulonglong),
        ("mxcsr", ctypes.c_uint),
        ("mxcr_mask", ctypes.c_uint),
        ("st_space", ctypes.c_uint * 32),  # 8*16 bytes for each FP-reg = 128 bytes
        ("xmm_space", ctypes.c_uint * 64), # 16*16 bytes for each XMM-reg = 256 bytes
        ("padding", ctypes.c_uint * 24)
    ]


class user_regs_struct(ctypes.Structure):
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


class iovec_struct(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_ulong)
    ]


class si_pad_struct(ctypes.Structure):
    _fields_ = [
        ("si_pad", ctypes.c_int * SI_MAX_COUNT),
    ]

class si_sigsegv_struct(ctypes.Structure):
    _fields_ = [
        ("si_signo", ctypes.c_int),
        ("si_errno", ctypes.c_int),
        ("si_code", ctypes.c_int),
        ("si_addr", ctypes.c_void_p),
    ]

class si_sigint_struct(ctypes.Structure):
    _fields_ = [
        ("si_signo", ctypes.c_int),
        ("si_errno", ctypes.c_int),
        ("si_code", ctypes.c_int),
        ("si_pid", ctypes.c_int),
        ("si_uid", ctypes.c_int),
    ]

class siginfo_struct(ctypes.Union):
    _fields_ = [
        ("pad", si_pad_struct),
        ("sigsegv", si_sigsegv_struct),
        ("sigint", si_sigint_struct),
    ]


def xsave_area_size():
    # __cpuid_count(...); ret ebx;
    # 31 c9                   xor    %ecx,%ecx
    # b8 0d 00 00 00          mov    $0xd,%eax
    # 49 87 d8                xchg   %rbx,%r8
    # 0f a2                   cpuid
    # 49 87 d8                xchg   %rbx,%r8
    # 44 89 c0                mov    %r8d,%eax
    # c3                      ret

    buf = mmap.mmap(-1, mmap.PAGESIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    code = bytes.fromhex("31c9b80d0000004987d80fa24987d84489c0c300f30f1efa4883ec084883c408c3");
    buf.write(code)

    ftype = ctypes.CFUNCTYPE(ctypes.c_int)
    fpointer = ctypes.c_void_p.from_buffer(buf)
    f = ftype(ctypes.addressof(fpointer))
    return f()


class PtraceTracer:
    def __init__(self, pid):
        self.pid = pid
        self.libc = self.setup_ptrace_call()
        self.xsave_area_size = xsave_area_size()

    def setup_ptrace_call(self):
        libc_path = ctypes.util.find_library("c")
        if not libc_path:
            fail_program(self.pid, "find_library", "Cannot find libc library")

        libc = ctypes.CDLL(libc_path, use_errno=True)
        libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
        libc.ptrace.restype = ctypes.c_uint64

        return libc

    def find_process_threads(self):
        task_dir = "/proc/{}/task".format(self.pid)
        tids = [int(d) for d in os.listdir(task_dir) if os.path.isdir(task_dir + "/" + d) and d.isdigit()]

        return tids

    def attach(self):
        # stop all threads
        self.tids = self.find_process_threads()
        for tid in self.tids:
            if 0 != self.libc.ptrace(PTRACE_ATTACH, tid, None, None):
                fail_program(self.pid, "ptrace_attach({})".format(tid))

            stat = os.waitpid(tid, WALL)
            if os.WIFSTOPPED(stat[1]):
                s = os.WSTOPSIG(stat[1])
                if (signal.SIGSTOP.value != s):
                    fail_program(self.pid, "ptrace_attach",
                                 "Wrong signal is {}".format(signal.Signals(s)))

    def detach(self):
        # detach
        for tid in self.tids:
            if 0 != self.libc.ptrace(PTRACE_DETACH, tid, None, None):
                fail_program(self.pid, "ptrace_detach({})".format("tid"))

    def save_regs(self):
        self.gpr = user_regs_struct()
        if 0 != self.libc.ptrace(PTRACE_GETREGS, self.pid, None, ctypes.byref(self.gpr)):
            fail_program(self.pid, "ptrace_getregs")

        # as we call function somewhere in the middle of another function,
        # it is better to save all regs
        self.use_xsave = False
        if self.xsave_area_size:
            buf = ctypes.create_string_buffer(bytes(self.xsave_area_size))
            self.iov = iovec_struct(ctypes.cast(ctypes.byref(buf), ctypes.c_void_p), self.xsave_area_size)
            if 0 == self.libc.ptrace(PTRACE_GETREGSET, self.pid, NT_X86_XSTATE, ctypes.byref(self.iov)):
                self.xsave_support = True

        # xsave area include fxsave
        self.use_fxsave = False
        if not self.use_xsave:
            # amd64, FXSAVE
            self.fpr = user_fpregs_struct()
            if 0 == self.libc.ptrace(PTRACE_GETFPREGS, self.pid, None, ctypes.byref(self.fpr)):
                self.support_fpr = True

    def setup_call(self, func_addr, arg):
        rsp = self.gpr.rsp
        rsp = rsp & 0xfffffffffffffff0 # align
        rsp = rsp - 128 # red zone
        return_addr = rsp - 1
        rsp = rsp - 16 # stay align
        rsp = rsp - 8 # return addr

        self.write_word(rsp, return_addr)
        self.write_word(return_addr, int("cc", base=16)) # SIGSEGV + SEGV_ACCERR

        #if 0 != self.libc.ptrace(PTRACE_POKETEXT, self.pid, ctypes.c_void_p(self.addr), self.old_code):
        #    fail_program(self.pid, "ptrace_poketext")

        regs = copy.deepcopy(self.gpr)
        regs.rsp = rsp
        regs.rbp = rsp
        regs.rip = func_addr + 2
        regs.rdi = arg
        regs.orig_eax = -1

        if 0 != self.libc.ptrace(PTRACE_SETREGS, self.pid, None, ctypes.byref(regs)):
            fail_program(self.pid, "setup_call, ptrace_setregs")

    def restore_regs(self):
        if 0 != self.libc.ptrace(PTRACE_SETREGS, self.pid, None, ctypes.byref(self.gpr)):
            fail_program(self.pid, "ptrace_setregs")

        if self.use_xsave:
            if 0 != self.libc.ptrace(PTRACE_SETREGSET, self.pid, NT_X86_XSTATE, ctypes.byref(self.iov)):
                fail_program(self.pid, "ptrace_setregset")

        if self.use_fxsave:
            if 0 != self.libc.ptrace(PTRACE_SETFPREGS, self.pid, None, ctypes.byref(self.fpr)):
                fail_program(self.pid, "ptrace_setfpregs")

    def replace_sigsegv(self):
        siginfo = siginfo_struct()
        if 0 != self.libc.ptrace(PTRACE_GETSIGINFO, self.pid, None, ctypes.byref(siginfo)):
            fail_program(self.pid, "ptrace_getsiginfo")

        if signal.SIGSEGV.value == siginfo.sigsegv.si_signo:
            print(siginfo.sigsegv.si_code, hex(siginfo.sigsegv.si_addr))

        siginfo = siginfo_struct()
        siginfo.si_signo = signal.SIGINT.value
        siginfo.si_pid = self.pid
        siginfo.si_uid = 1001 # FIX user identifiers
        siginfo.si_code = SI_USER
        if 0 != self.libc.ptrace(PTRACE_SETSIGINFO, self.pid, None, ctypes.byref(siginfo)):
            fail_program(self.pid, "ptrace_setsiginfo")

    def get_return_value(self):
        regs = user_regs_struct()
        if 0 != self.libc.ptrace(PTRACE_GETREGS, self.pid, None, ctypes.byref(regs)):
            fail_program(self.pid, "ptrace_getregs")

        return regs.rax;

    def call_function(self, func_addr, arg=0):
        self.save_regs()
        self.setup_call(func_addr, arg)

        # continue execution until SIGSEGV
        if 0 != self.libc.ptrace(PTRACE_CONT, self.pid, None, None):
            fail_program(self.pid, "ptrace_cont")

        stat = os.waitpid(self.pid, WALL)
        if os.WIFSTOPPED(stat[1]):
            s = os.WSTOPSIG(stat[1])
            if (signal.SIGSEGV.value != s):
                fail_program(self.pid, "ptrace_cont",
                             "Wrong signal is {}".format(signal.Signals(s)))

        self.replace_sigsegv()

        ret = self.get_return_value()

        self.restore_regs()

        return ret

    def write_word(self, addr, word):
        if not addr:
            print("write_word(): addr is empty")
            return

        if 0 != self.libc.ptrace(PTRACE_POKEDATA, self.pid, addr, word):
            fail_program(self.pid, "ptrace_pokedata(addr={}, word={})".format(addr, word))

    def write_data(self, addr, data, limit = 1024):
        if not addr:
            print("write_data(): addr is empty")
            return

        if len(data) > limit:
            fail_program(self.pid, "write_data", "limit overflow")

        wsize = ctypes.sizeof(ctypes.c_long)
        words = [data[i:i + wsize] for i in range(0, len(data), wsize)]
        for w in words:
            i = int.from_bytes(w, byteorder="little")
            if 0 != self.libc.ptrace(PTRACE_POKEDATA, self.pid, addr, i):
                fail_program(self.pid, "ptrace_pokedata")
            addr += wsize

    def read_raw_data(self, addr, is_string = True, limit = 1024):
        if not addr:
            return b""

        max_addr = addr + limit
        wsize = ctypes.sizeof(ctypes.c_long)
        ret = b""
        while addr < max_addr:
            word = self.libc.ptrace(PTRACE_PEEKDATA, self.pid, addr, None)
            if -1 == word:
                fail_program(self.pid, "ptrace_peekdata")
            if is_string and (0 == word):
                break
            addr += wsize

            ret += word.to_bytes(wsize, byteorder='little')

        return ret

    def read_data(self, addr, is_string = True, limit = 1024):
        bdata = self.read_raw_data(addr, is_string, limit)
        return bdata.decode("utf-8")
