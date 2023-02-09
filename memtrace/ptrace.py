"""
Attach and call functions in tracee process.
"""
import copy
import ctypes
import ctypes.util
import mmap
import os
import signal

from util import fail_program

PTRACE_PEEKTEXT = 1
PTRACE_PEEKDATA = 2
PTRACE_POKETEXT = 4
PTRACE_POKEDATA = 5
PTRACE_CONT = 7
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_GETFPREGS = 14
PTRACE_SETFPREGS = 15
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_SETOPTIONS = 0x4200
PTRACE_GETSIGINFO = 0x4202
PTRACE_SETSIGINFO = 0x4203
PTRACE_GETREGSET = 0x4204
PTRACE_SETREGSET = 0x4205
PTRACE_SEIZE = 0x4206
PTRACE_INTERRUPT = 0x4207

PTRACE_O_TRACESYSGOOD = 0x1

WALL = 0x40000000

NT_X86_XSTATE = 0x202

SI_MAX_SIZE = 128
SI_PAD_SIZE = int(SI_MAX_SIZE / ctypes.sizeof(ctypes.c_int))
SI_USER = 0

WSIZE = ctypes.sizeof(ctypes.c_long)

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
        self.xsave_area_size = self.get_xsave_area_size()
        self.xsave_area = Iovec(self.xsave_area_size)

        self.use_fxsave = False
        self.fpr = UserFpregsStruct()

    def get_xsave_area_size(self):
        """
        Check if xsave is supported.

        :return: size of xsave area
        """
        # cpuid_count(0xd, 0, eax, ebx, ecx, edx); ret ebx;
        # 31 c9                   xor    %ecx,%ecx
        # b8 0d 00 00 00          mov    $0xd,%eax
        # 49 87 d8                xchg   %rbx,%r8
        # 0f a2                   cpuid
        # 49 87 d8                xchg   %rbx,%r8
        # 44 89 c0                mov    %r8d,%eax
        # c3                      ret
        buf = mmap.mmap(-1, mmap.PAGESIZE,
                        prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        code = bytes.fromhex("31c9b80d0000004987d80fa24987d84489c0c3")
        buf.write(code)

        ftype = ctypes.CFUNCTYPE(ctypes.c_int)
        fpointer = ctypes.c_void_p.from_buffer(buf)
        function = ftype(ctypes.addressof(fpointer))
        return function()

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
        if self.xsave_area_size:
            if 0 == self.libc.ptrace(PTRACE_GETREGSET, self.pid,
                                     NT_X86_XSTATE, ctypes.byref(self.xsave_area)):
                self.use_xsave = True

        # xsave area include fxsave
        # amd64, FXSAVE
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

    def clear(self):
        """
        Clear gpr, fpr, xsave_area values.
        """
        self.gpr = UserRegsStruct()

        self.use_xsave = False  # set if ptrace succeeds
        self.xsave_area = Iovec(self.xsave_area_size)

        self.use_fxsave = False
        self.fpr = UserFpregsStruct()


class SISigsegv(ctypes.Structure):
    """
    SIGSEGV fields. From signal.h
    """
    _fields_ = [
        ("si_signo", ctypes.c_int),
        ("si_errno", ctypes.c_int),
        ("si_code", ctypes.c_int),
        # faulting insn/memory ref.
        ("si_addr", ctypes.c_void_p),
    ]


class SISigint(ctypes.Structure):
    """
    SIGINT fields. From signal.h
    """
    _fields_ = [
        ("si_signo", ctypes.c_int),
        ("si_errno", ctypes.c_int),
        ("si_code", ctypes.c_int),
        ("si_pid", ctypes.c_int),
        ("si_uid", ctypes.c_int),
    ]


class Siginfo(ctypes.Union):
    """
    Signal description. From signal.h
    """
    # _anonymous_ = ("sigsegv", "sigint",)
    _fields_ = [
        ("si_pad", ctypes.c_int * SI_PAD_SIZE),
        ("sigsegv", SISigsegv),
        ("sigint", SISigint),
    ]


class PtraceTracer:
    def __init__(self, pid):
        self.pid = pid
        self.tids = []
        self.libc = self.setup_ptrace_call()
        self.reg_cache = RegCache(self.pid, self.libc)
        self.used_memory = []

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

    def waitpid_or_fail(self, tid, expected):
        """
        Waitpid and exit if recieved signal is wrong.

        :tid: thread identifier
        :expected: expected signal
        """
        stat = os.waitpid(tid, WALL)
        if os.WIFSTOPPED(stat[1]):
            s = os.WSTOPSIG(stat[1])
            if expected.value != s:
                sname = signal.Signals(s)
                fail_program(self.pid, "waitpid", f"Wrong signal is {sname}")

    def attach(self):
        """
        Attach to process.
        Stop all threads.
        """
        self.tids = self.find_process_threads()
        for tid in self.tids:
            if 0 != self.libc.ptrace(PTRACE_ATTACH, tid, None, None):
                fail_program(self.pid, f"ptrace_attach({tid})")
            self.waitpid_or_fail(tid, signal.SIGSTOP)

    def detach(self):
        """
        Detach.
        """
        for tid in self.tids:
            if 0 != self.libc.ptrace(PTRACE_DETACH, tid, None, None):
                fail_program(self.pid, f"ptrace_detach({tid})")

    def setup_call(self, func_addr, arg):
        """
        Prepare stack and regs to function call.

        :func_addr: addres of callable function
        :arg: argument of the function
        """
        regs = copy.deepcopy(self.reg_cache.gpr)

        # setup stack
        rsp = regs.rsp
        rsp = rsp & 0xfffffffffffffff0  # align
        rsp = rsp - 128  # red zone
        return_addr = rsp - 1
        rsp = rsp - 16  # stay align
        rsp = rsp - 8  # return addr

        regs.rsp = rsp
        regs.rbp = rsp
        regs.rip = func_addr + 2
        regs.rdi = arg
        regs.orig_eax = -1

        # RESTORE state
        self.save_word(rsp)
        self.write_word(rsp, return_addr)

        # SIGSEGV + SEGV_ACCERR
        self.save_word(return_addr)
        int3 = int("cc", base=16)
        self.write_word(return_addr, int3)

        if 0 != self.libc.ptrace(PTRACE_SETREGS, self.pid, None, ctypes.byref(regs)):
            fail_program(self.pid, "setup_call, ptrace_setregs")

    def save_word(self, addr):
        """
        Save word from tracee process memory.

        :addr: addres where word is placed
        """
        word = self.read_word(addr)
        self.used_memory.append((addr, word))

    def restore_words(self):
        """
        Restore all memorized words.
        """
        for addr, word in self.used_memory:
            self.write_word(addr, word)

    def replace_sigsegv(self):
        """
        Replace SIGSEGV for tracee process.
        """
        siginfo = Siginfo()
        if 0 != self.libc.ptrace(PTRACE_GETSIGINFO, self.pid, None, ctypes.byref(siginfo)):
            fail_program(self.pid, "ptrace_getsiginfo")

        # if signal.SIGSEGV.value == siginfo.sigsegv.si_signo:
        #     print(siginfo.sigsegv.si_code, hex(siginfo.sigsegv.si_addr))

        siginfo = Siginfo()
        siginfo.si_signo = signal.SIGINT.value
        siginfo.si_pid = self.pid
        siginfo.si_uid = 1001 # FIX user identifiers
        siginfo.si_code = SI_USER
        if 0 != self.libc.ptrace(PTRACE_SETSIGINFO, self.pid, None, ctypes.byref(siginfo)):
            fail_program(self.pid, "ptrace_setsiginfo")

    def get_return_value(self):
        """
        Recieve return value after function call.

        :return: rax register content
        """
        regs = UserRegsStruct()
        if 0 != self.libc.ptrace(PTRACE_GETREGS, self.pid, None, ctypes.byref(regs)):
            fail_program(self.pid, "ptrace_getregs")

        return regs.rax

    def call_function(self, func_addr, arg=0):
        """
        Call function in tracee process.

        :func_addr: function address to call
        :arg: the first (and only) argument
        :return: return value of callable function
        """
        self.reg_cache.save_regs()
        self.setup_call(func_addr, arg)

        # continue execution until SIGSEGV
        if 0 != self.libc.ptrace(PTRACE_CONT, self.pid, None, None):
            fail_program(self.pid, "ptrace_cont")

        self.waitpid_or_fail(self.pid, signal.SIGSEGV)
        self.replace_sigsegv()

        ret = self.get_return_value()

        self.reg_cache.restore_regs()
        self.restore_words()

        return ret

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
        Write string into tracee process memory.

        :addr: start address to write
        :data: string to write
        :limit: max string length. 1024 by default
        """
        if not addr:
            print("write_data(): addr is empty")
            return

        bdata = bytes(data, encoding="utf-8")
        if len(bdata) > limit:
            fail_program(self.pid, "write_data", "limit overflow")

        words = [bdata[i:i + WSIZE] for i in range(0, len(bdata), WSIZE)]
        for word_bytes in words:
            word = int.from_bytes(word_bytes, byteorder="little")
            self.write_word(addr, word)
            addr += WSIZE

    def read_word(self, addr):
        """
        Read word from tracee process memory.

        :addr: address to read
        :return: read word
        """
        if not addr:
            return 0

        word = self.libc.ptrace(PTRACE_PEEKDATA, self.pid, addr, None)
        if -1 == word:
            fail_program(self.pid, f"ptrace_peekdata({addr})")

        return word

    def read_string(self, addr, limit=1024):
        """
        Read string from tracee process memory.

        :addr: start address to read
        :limit: max string length. 1024 by default
        :return: read string
        """
        if not addr:
            return ""

        max_addr = addr + limit
        ret = b""
        while addr < max_addr:
            word = self.read_word(addr)
            if 0 == word:
                break
            addr += WSIZE
            ret += word.to_bytes(WSIZE, byteorder='little')

        return ret.decode("utf-8")
