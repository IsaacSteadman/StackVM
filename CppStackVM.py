import ctypes
import os
import struct

_lib_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "cpp", "stack_vm.dylib"
)
_lib_path = os.environ.get("STACKVM_CPP_LIB", _lib_path)
_lib = ctypes.CDLL(_lib_path)


class _SimpleStruct(ctypes.Structure):
    """Mirrors StackVM_TrapException::SimpleStruct — passed to virt_syscall callbacks."""

    _fields_ = [
        ("arg0", ctypes.c_uint64),
        ("arg1", ctypes.c_uint64),
        ("arg2", ctypes.c_uint64),
        ("arg3", ctypes.c_uint64),
    ]


# ctypes type for the virt_syscall function pointer:
#   void fn(uint64_t syscall_n, SimpleStruct *err)
VirtSyscallType = ctypes.CFUNCTYPE(None, ctypes.c_uint64, ctypes.POINTER(_SimpleStruct))


def _proto(name, restype, *argtypes):
    fn = getattr(_lib, name)
    fn.restype = restype
    fn.argtypes = list(argtypes)
    return fn


_make_stack_vm = _proto("make_stack_vm", ctypes.c_void_p, ctypes.c_size_t)
_destroy_stack_vm = _proto("destroy_stack_vm", None, ctypes.c_void_p)
_vm_get_sp = _proto("vm_get_sp", ctypes.c_uint64, ctypes.c_void_p)
_vm_set_sp = _proto("vm_set_sp", None, ctypes.c_void_p, ctypes.c_uint64)
_vm_get_bp = _proto("vm_get_bp", ctypes.c_uint64, ctypes.c_void_p)
_vm_set_bp = _proto("vm_set_bp", None, ctypes.c_void_p, ctypes.c_uint64)
_vm_get_ip = _proto("vm_get_ip", ctypes.c_uint64, ctypes.c_void_p)
_vm_set_ip = _proto("vm_set_ip", None, ctypes.c_void_p, ctypes.c_uint64)
_vm_get_ax = _proto("vm_get_ax", ctypes.c_uint64, ctypes.c_void_p)
_vm_get_running = _proto("vm_get_running", ctypes.c_uint8, ctypes.c_void_p)
_vm_set_running = _proto("vm_set_running", None, ctypes.c_void_p, ctypes.c_uint8)
_vm_get_memory = _proto("vm_get_memory", ctypes.c_void_p, ctypes.c_void_p)
_vm_get_memsize = _proto("vm_get_memsize", ctypes.c_size_t, ctypes.c_void_p)
_vm_get_sysreg = _proto(
    "vm_get_sysreg", ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint8
)
_vm_set_sysreg = _proto(
    "vm_set_sysreg", None, ctypes.c_void_p, ctypes.c_uint8, ctypes.c_uint64
)
_vm_set_flags = _proto("vm_set_flags", None, ctypes.c_void_p, ctypes.c_uint64)
_vm_set_virt_syscall = _proto(
    "vm_set_virt_syscall", None, ctypes.c_void_p, ctypes.c_void_p
)
_vm_post_interrupt = _proto(
    "vm_post_interrupt",
    None,
    ctypes.c_void_p,
    ctypes.c_uint8,
    ctypes.c_uint64,
    ctypes.c_uint64,
    ctypes.c_uint64,
    ctypes.c_uint64,
)
_vm_tlb_insert = _proto(
    "vm_tlb_insert",
    None,
    ctypes.c_void_p,
    ctypes.c_uint64,
    ctypes.c_uint64,
    ctypes.c_uint64,
    ctypes.c_uint8,
)
_vm_tlb_has_entry = _proto(
    "vm_tlb_has_entry",
    ctypes.c_uint8,
    ctypes.c_void_p,
    ctypes.c_uint64,
    ctypes.c_uint64,
)
_vm_tlb_size = _proto("vm_tlb_size", ctypes.c_size_t, ctypes.c_void_p)
_vm_tlb_invalidate_range = _proto(
    "vm_tlb_invalidate_range",
    None,
    ctypes.c_void_p,
    ctypes.c_uint64,
    ctypes.c_uint64,
    ctypes.c_uint64,
)
_vm_step = _proto("vm_step", None, ctypes.c_void_p)
_vm_execute = _proto("vm_execute", None, ctypes.c_void_p)
_make_stack_vm_multicore = _proto(
    "make_stack_vm_multicore", ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t
)
_destroy_stack_vm_multicore = _proto("destroy_stack_vm_multicore", None, ctypes.c_void_p)
_multicore_get_core = _proto(
    "multicore_get_core", ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t
)
_multicore_get_memory = _proto(
    "multicore_get_memory", ctypes.c_void_p, ctypes.c_void_p
)
_multicore_get_memory_size = _proto(
    "multicore_get_memory_size", ctypes.c_size_t, ctypes.c_void_p
)
_multicore_get_core_count = _proto(
    "multicore_get_core_count", ctypes.c_size_t, ctypes.c_void_p
)
_multicore_step_round = _proto(
    "multicore_step_round", ctypes.c_size_t, ctypes.c_void_p
)


class _SysRegsProxy:
    """Array-like proxy so vm.sys_regs[n] reads/writes system register n."""

    __slots__ = ("_ptr",)

    def __init__(self, vm_ptr):
        self._ptr = vm_ptr

    def __getitem__(self, n: int) -> int:
        return _vm_get_sysreg(self._ptr, n)

    def __setitem__(self, n: int, v: int):
        _vm_set_sysreg(self._ptr, n, v)


class VirtualMachine:
    def __init__(self, mem_size: int, _ptr=None, _owner: bool = True):
        self.void_ptr_inst = _ptr if _ptr is not None else _make_stack_vm(mem_size)
        if not self.void_ptr_inst:
            raise MemoryError("Failed to allocate StackVM (mem_size=%d)" % mem_size)
        self.sys_regs = _SysRegsProxy(self.void_ptr_inst)
        self._virt_syscall_ref = None  # keeps ctypes callback alive
        self._owner = _owner

    def __del__(self):
        if self.void_ptr_inst and self._owner:
            _destroy_stack_vm(self.void_ptr_inst)
            self.void_ptr_inst = 0

    # ── Core registers ───────────────────────────────────────────────────────

    @property
    def sp(self) -> int:
        return _vm_get_sp(self.void_ptr_inst)

    @sp.setter
    def sp(self, v: int):
        _vm_set_sp(self.void_ptr_inst, v)

    @property
    def bp(self) -> int:
        return _vm_get_bp(self.void_ptr_inst)

    @bp.setter
    def bp(self, v: int):
        _vm_set_bp(self.void_ptr_inst, v)

    @property
    def ip(self) -> int:
        return _vm_get_ip(self.void_ptr_inst)

    @ip.setter
    def ip(self, v: int):
        _vm_set_ip(self.void_ptr_inst, v)

    @property
    def ax(self) -> int:
        return _vm_get_ax(self.void_ptr_inst)

    @property
    def running(self) -> int:
        return _vm_get_running(self.void_ptr_inst)

    @running.setter
    def running(self, v: int):
        _vm_set_running(self.void_ptr_inst, v)

    # ── Memory ───────────────────────────────────────────────────────────────

    @property
    def memory(self):
        """Returns a ctypes array backed by the VM's internal memory buffer."""
        ptr = _vm_get_memory(self.void_ptr_inst)
        size = _vm_get_memsize(self.void_ptr_inst)
        return (ctypes.c_uint8 * size).from_address(ptr)

    # ── Flags / privilege ────────────────────────────────────────────────────

    def set_flags(self, flags: int):
        """Write the FLAGS system register and re-derive priority/priv_lvl/mem_mode."""
        _vm_set_flags(self.void_ptr_inst, flags)

    # ── Virt-syscall callback ─────────────────────────────────────────────────

    def set_virt_syscall(self, fn):
        """
        Register a Python callable as the virtualized-syscall handler.

        Signature:  fn(syscall_n: int, err: ctypes.POINTER(_SimpleStruct))

        Pass None to disable (full-emulation mode: the VM will set up a kernel
        frame and jump to SVSR_SYS_FN instead).
        A reference to the wrapped ctypes callback is kept alive automatically.
        """
        if fn is None:
            _vm_set_virt_syscall(self.void_ptr_inst, None)
            self._virt_syscall_ref = None
        else:
            cb = VirtSyscallType(fn)
            _vm_set_virt_syscall(self.void_ptr_inst, cb)
            self._virt_syscall_ref = cb

    # ── Execution ─────────────────────────────────────────────────────────────

    def step(self):
        """Execute one instruction (with trap handling)."""
        _vm_step(self.void_ptr_inst)

    def execute(self):
        """Run until the VM halts (BC_HLT or running == 0)."""
        _vm_execute(self.void_ptr_inst)

    # ── PyStackVM compatibility shim ──────────────────────────────────────────
    # These attributes and methods mirror the PyStackVM interface used by
    # run_in_vm, add_cmd_argv_vm, and the Debugger so that both backends can
    # be driven by the same code.

    @property
    def priv_lvl(self) -> int:
        return (self.sys_regs[0] >> 8) & 1

    @property
    def virt_mem_mode(self) -> int:
        return (self.sys_regs[0] >> 10) & 0xF

    def load_program(self, program, at_addr: int = 0):
        """Write bytecode into VM memory starting at at_addr."""
        mem = self.memory
        for i, b in enumerate(program):
            mem[at_addr + i] = b

    def set_bytes(self, addr: int, data) -> bool:
        """Write a sequence of bytes into VM memory at addr."""
        mem = self.memory
        for i, b in enumerate(data):
            mem[addr + i] = b
        return True

    _SET_FMTS = {1: "<B", 2: "<H", 4: "<I", 8: "<Q"}

    def set(self, sz: int, addr: int, val: int) -> bool:
        """Write an unsigned integer of sz bytes into VM memory at addr."""
        bs = struct.pack(self._SET_FMTS[sz], val & ((1 << (sz * 8)) - 1))
        mem = self.memory
        for i, b in enumerate(bs):
            mem[addr + i] = b
        return True

    def push(self, sz: int, val: int, typ: int = 0) -> bool:
        """Decrement sp by sz bytes then write val; mirrors PyStackVM.push."""
        self.sp = self.sp - sz
        return self.set(sz, self.sp, val)

    def post_interrupt(self, int_n: int, a0: int = 0, a1: int = 0, a2: int = 0, a3: int = 0):
        _vm_post_interrupt(self.void_ptr_inst, int_n, a0, a1, a2, a3)

    def tlb_insert(self, tlptr: int, vaddr: int, phys: int, mask: int):
        _vm_tlb_insert(self.void_ptr_inst, tlptr, vaddr, phys, mask)

    def tlb_has_entry(self, tlptr: int, vaddr: int) -> bool:
        return bool(_vm_tlb_has_entry(self.void_ptr_inst, tlptr, vaddr))

    def tlb_size(self) -> int:
        return int(_vm_tlb_size(self.void_ptr_inst))

    def tlb_invalidate_range(self, tlptr: int, vaddr_base: int, page_count: int):
        _vm_tlb_invalidate_range(self.void_ptr_inst, tlptr, vaddr_base, page_count)


class MultiCoreMachine:
    def __init__(self, core_count: int, memory_size: int):
        self.void_ptr_inst = _make_stack_vm_multicore(core_count, memory_size)
        if not self.void_ptr_inst:
            raise MemoryError("Failed to allocate C++ StackVM SMP machine")
        self.cores = [
            VirtualMachine(memory_size, _ptr=_multicore_get_core(self.void_ptr_inst, i), _owner=False)
            for i in range(core_count)
        ]

    def __del__(self):
        if self.void_ptr_inst:
            _destroy_stack_vm_multicore(self.void_ptr_inst)
            self.void_ptr_inst = 0

    @property
    def core_count(self) -> int:
        return int(_multicore_get_core_count(self.void_ptr_inst))

    @property
    def memory(self):
        ptr = _multicore_get_memory(self.void_ptr_inst)
        size = _multicore_get_memory_size(self.void_ptr_inst)
        return (ctypes.c_uint8 * size).from_address(ptr)

    def load_program(self, program, at_addr: int = 0, core_ids=None):
        mem = self.memory
        for i, b in enumerate(program):
            mem[at_addr + i] = b
        targets = range(self.core_count) if core_ids is None else core_ids
        for core_id in targets:
            self.cores[int(core_id)].ip = at_addr

    def step_round(self) -> int:
        return int(_multicore_step_round(self.void_ptr_inst))
