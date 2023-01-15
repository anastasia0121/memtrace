import ctypes
import mmap
import os
import signal
import copy

from util import fail_program


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


class iovec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_ulong)
    ]


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
PTRACE_GETREGSET  = 0x4204
PTRACE_SETREGSET  = 0x4205

NT_X86_XSTATE = 0x202


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
        # setup ptrace call
        libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
        if not os.path.isfile(libc_path):
            fail_program(self.pid, "libc_path", "Cannot find libc library")
        libc = ctypes.CDLL(libc_path, use_errno=True)
        libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64,
                                ctypes.c_void_p, ctypes.c_void_p]
        libc.ptrace.restype = ctypes.c_uint64

        return libc

    def attach(self):
        # attach to process
        if 0 != self.libc.ptrace(PTRACE_ATTACH, self.pid, None, None):
            fail_program(self.pid, "ptrace_attach")

        stat = os.waitpid(self.pid, 0)
        if os.WIFSTOPPED(stat[1]):
            s = os.WSTOPSIG(stat[1])
            if (signal.SIGSTOP.value != s):
                fail_program(self.pid, "ptrace_attach",
                             "Wrong signal is {}".format(signal.Signals(s)))

    def detach(self):
        # detach
        if 0 != self.libc.ptrace(PTRACE_DETACH, self.pid, None, None):
            fail_program(self.pid, "ptrace_detach")

    def save_state(self):
        self.gpr = user_regs_struct()
        if 0 != self.libc.ptrace(PTRACE_GETREGS, self.pid, None, ctypes.byref(self.gpr)):
            fail_program(self.pid, "ptrace_getregs")

        # as we call function somewhere in the middle of another function,
        # it is better to save all regs
        self.use_xsave = False
        if self.xsave_area_size:
            buf = ctypes.create_string_buffer(bytes(self.xsave_area_size))
            self.iov = iovec(ctypes.cast(ctypes.byref(buf), ctypes.c_void_p), self.xsave_area_size)
            if 0 == self.libc.ptrace(PTRACE_GETREGSET, self.pid, NT_X86_XSTATE, ctypes.byref(self.iov)):
                self.xsave_support = True
                #s = ctypes.cast(self.iov.iov_base, ctypes.POINTER(ctypes.c_uint*self.iov.iov_len)).contents

        # xsave area include fxsave
        self.use_fxsave = False
        if not self.use_xsave:
            # amd64, FXSAVE
            self.fpr = user_fpregs_struct()
            if 0 == self.libc.ptrace(PTRACE_GETFPREGS, self.pid, None, ctypes.byref(self.fpr)):
                self.support_fpr = True

        # backup code
        addr = self.gpr.rip
        self.old_code = self.libc.ptrace(PTRACE_PEEKTEXT, self.pid, ctypes.c_void_p(addr), None)
        if -1 == self.old_code:
            fail_program(self.pid, "ptrace_peektext")

        return self.gpr

    def restore_state(self):
        if 0 != self.libc.ptrace(PTRACE_SETREGS, self.pid, None, ctypes.byref(self.gpr)):
            fail_program(self.pid, "ptrace_setregs")

        if self.use_xsave:
            if 0 != self.libc.ptrace(PTRACE_SETREGSET, self.pid, NT_X86_XSTATE, ctypes.byref(self.iov)):
                fail_program(self.pid, "ptrace_setregset")

        if self.use_fxsave:
            if 0 != self.libc.ptrace(PTRACE_SETFPREGS, self.pid, None, ctypes.byref(self.fpr)):
                fail_program(self.pid, "ptrace_setfpregs")

        addr = self.gpr.rip
        if 0 != self.libc.ptrace(PTRACE_POKETEXT, self.pid, ctypes.c_void_p(addr), self.old_code):
            fail_program(self.pid, "ptrace_poketext")

    def call_function(self, func_addr, arg=0):
        # backup registers
        old_regs = self.save_state()
        regs = copy.deepcopy(old_regs)

        # set the new registers
        addr = regs.rip
        regs.rsi = func_addr
        regs.rdi = arg
        if 0 != self.libc.ptrace(PTRACE_SETREGS, self.pid, None, ctypes.byref(regs)):
            fail_program(self.pid, "ptrace_setregs")

        # set the new code and regs
        # ff d6 call   *%rsi
        # cc    int3
        code = int("ccd6ff", base=16)
        if 0 != self.libc.ptrace(PTRACE_POKETEXT, self.pid, ctypes.c_void_p(addr), code):
            fail_program(self.pid, "ptrace_poketext")

        # continue execution
        if 0 != self.libc.ptrace(PTRACE_CONT, self.pid, None, None):
            fail_program(self.pid, "ptrace_cont")

        stat = os.waitpid(self.pid, 0)
        if os.WIFSTOPPED(stat[1]):
            s = os.WSTOPSIG(stat[1])
            if (signal.SIGTRAP.value != s):
                fail_program(self.pid, "ptrace_cont",
                             "Wrong signal is {}".format(signal.Signals(s)))

        # receive return value
        if 0 != self.libc.ptrace(PTRACE_GETREGS, self.pid, None, ctypes.byref(regs)):
            fail_program(self.pid, "ptrace_getregs")

        ret = regs.rax;

        # restore program state
        self.restore_state()

        return ret

    
    def write_data(self, addr, data):
        if not addr:
            return

        # buffer is hardcoded in cpp
        if len(data) > 1024:
            fail_program(self.pid, "ptrace_pokedata", "mt file name is too long.")
        wsize = ctypes.sizeof(ctypes.c_long)
        words = [data[i:i + wsize] for i in range(0, len(data), wsize)]
        for w in words:
            i = int.from_bytes(w, byteorder="little")
            if 0 != self.libc.ptrace(PTRACE_POKEDATA, self.pid, addr, i):
                fail_program(self.pid, "ptrace_pokedata")
            addr += wsize

    def read_data(self, addr):
        if not addr:
            return ""

        max_addr = addr + 1024
        wsize = ctypes.sizeof(ctypes.c_long)
        ret = b""
        while addr < max_addr:
            word = self.libc.ptrace(PTRACE_PEEKDATA, self.pid, addr, None)
            if -1 == word:
                fail_program(self.pid, "ptrace_peekdata")
            if 0 == word:
                break
            addr += wsize

            ret += word.to_bytes(wsize, byteorder='little')

        return ret.decode("utf-8")
