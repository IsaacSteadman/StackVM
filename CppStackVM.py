import ctypes
import os

_lib_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "cpp", "stack_vm.dylib"
)
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
_vm_step = _proto("vm_step", None, ctypes.c_void_p)
_vm_execute = _proto("vm_execute", None, ctypes.c_void_p)


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
    def __init__(self, mem_size: int):
        self.void_ptr_inst = _make_stack_vm(mem_size)
        if not self.void_ptr_inst:
            raise MemoryError("Failed to allocate StackVM (mem_size=%d)" % mem_size)
        self.sys_regs = _SysRegsProxy(self.void_ptr_inst)
        self._virt_syscall_ref = None  # keeps ctypes callback alive

    def __del__(self):
        if self.void_ptr_inst:
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
