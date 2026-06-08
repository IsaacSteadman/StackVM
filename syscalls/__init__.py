"""
StackVM syscall dispatcher.

Usage (Python VM)::

    from StackVM.syscalls import build_dispatcher

    dispatcher = build_dispatcher(["os", "pygame"])
    dispatcher.attach_to_py_vm(vm)
    vm.execute()

Usage (C++ VM)::

    dispatcher = build_dispatcher(["os"])
    dispatcher.attach_to_cpp_vm(vm)   # calls vm.set_virt_syscall(...)
    vm.execute()

The function ``build_dispatcher`` accepts a list of set names:
    ``"os"``     — SYS_EXIT, SYS_WRITE, SYS_READ, SYS_OPEN, SYS_CLOSE,
                   SYS_SEEK, SYS_MMAP, SYS_MUNMAP, SYS_CLOCK_NS, SYS_SLEEP_NS,
                   plus legacy 0x01 / 0x21 print helpers.
    ``"pygame"`` — SYS_PYG_* (0x02–0x0C), requires PyGame installed.
    ``"paravirt"`` — kernel-only D4 paravirt device hypercalls via the
                     CALL_E/IS_INT doorbell INT_PARAVIRT (0x12).
    ``"all"``    — shorthand for ["os", "pygame"].
    ``"none"``   — empty dispatcher (unrecognised syscalls emit a warning).
"""

from __future__ import annotations

import sys
from typing import Callable, Dict, List, Optional

from .base import BaseSyscallSet, SyscallContext


class SyscallDispatcher:
    """
    Aggregates multiple BaseSyscallSet instances and routes syscall numbers to
    the appropriate handler.
    """

    def __init__(self, sets: Optional[List[BaseSyscallSet]] = None) -> None:
        self._handlers: Dict[int, Callable[[SyscallContext], None]] = {}
        self._hypercall_handlers: Dict[int, Callable] = {}
        for s in sets or []:
            self.register_set(s)

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_set(self, s: BaseSyscallSet) -> None:
        """Add all handlers from *s*, overriding any existing ones with the same number."""
        self._handlers.update(s.handlers)
        self._hypercall_handlers.update(getattr(s, "hypercall_handlers", {}))

    def register(self, n: int, fn: Callable[[SyscallContext], None]) -> None:
        """Register a single handler for syscall number *n*."""
        self._handlers[n] = fn

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def dispatch(self, vm: object, n: int) -> None:
        ctx = SyscallContext(vm)
        handler = self._handlers.get(n)
        if handler is None:
            print(f"WARN: unrecognized syscall number 0x{n:02X}", file=sys.stderr)
            return
        handler(ctx)

    def dispatch_hypercall(self, vm: object, _int_n: int) -> None:
        from ..paravirt import dispatch_paravirt_hypercall  # noqa: PLC0415

        dispatch_paravirt_hypercall(vm, self._hypercall_handlers)

    # ------------------------------------------------------------------
    # VM attachment — PyStackVM
    # ------------------------------------------------------------------

    def attach_to_py_vm(self, vm: object) -> None:
        """
        Attach enabled service lanes to a Python VM.  User syscall handlers
        replace ``vm.virt_syscall``; paravirt hypercall handlers install the
        separate ``vm.paravirt_hypercall`` doorbell callback.
        """
        dispatcher = self

        if self._handlers:
            # Store a reference to self so the closure captures it correctly.
            def _virt_syscall(n: int) -> None:
                dispatcher.dispatch(vm, n)

            vm.virt_syscall = _virt_syscall

        if self._hypercall_handlers:
            def _paravirt_hypercall(vm_inst: object, int_n: int) -> None:
                dispatcher.dispatch_hypercall(vm_inst, int_n)

            vm.paravirt_hypercall = _paravirt_hypercall

    # ------------------------------------------------------------------
    # VM attachment — CppStackVM
    # ------------------------------------------------------------------

    def attach_to_cpp_vm(self, vm: object) -> None:
        """
        Wrap this dispatcher as a ctypes callback and call
        ``vm.set_virt_syscall(callback)``.

        CppStackVM callback signature:
            fn(syscall_n: c_uint64, args: POINTER(_SimpleStruct)) → None

        The _SimpleStruct contains pre-extracted args (arg0..arg3, all uint64).
        The return value should be written to ``args.contents.arg0``.

        NOTE: the ctypes callback object is stored on *vm* as
        ``vm._syscall_callback`` to prevent premature garbage collection.
        """
        if self._hypercall_handlers:
            raise NotImplementedError(
                "paravirt hypercalls are implemented for PyStackVM; C++ parity "
                "is tracked separately"
            )
        try:
            from ..CppStackVM import VirtSyscallType, _SimpleStruct  # type: ignore[attr-defined]
        except ImportError as exc:
            raise RuntimeError("CppStackVM is not available") from exc

        dispatcher = self

        def _cpp_handler(syscall_n: int, args_ptr) -> None:
            struct = args_ptr.contents

            class _CppSyscallContext:  # lightweight inner class — constructed once per call
                __slots__ = ("_struct", "_vm")

                def __init__(self_inner) -> None:
                    self_inner._struct = struct
                    self_inner._vm = vm

                def arg(self_inner, n: int) -> int:
                    return getattr(self_inner._struct, f"arg{n}")

                def set_result(self_inner, val: int) -> None:
                    self_inner._struct.arg0 = val & 0xFFFFFFFFFFFFFFFF

                def read_zstr(self_inner, ptr: int, encoding: str = "utf-8") -> str:
                    mem = self_inner._vm.memory
                    end = ptr
                    while mem[end] != 0:
                        end += 1
                    return bytes(mem[ptr:end]).decode(encoding)

                def read_bytes(self_inner, ptr: int, n: int) -> bytes:
                    return bytes(self_inner._vm.memory[ptr : ptr + n])

                def write_bytes(self_inner, ptr: int, data: bytes) -> None:
                    self_inner._vm.memory[ptr : ptr + len(data)] = data

                @property
                def vm(self_inner) -> object:
                    return self_inner._vm

            ctx = _CppSyscallContext()
            handler = dispatcher._handlers.get(syscall_n)
            if handler is None:
                print(
                    f"WARN: unrecognized syscall number 0x{syscall_n:02X}",
                    file=sys.stderr,
                )
                return
            handler(ctx)

        callback = VirtSyscallType(_cpp_handler)
        vm._syscall_callback = callback  # prevent GC
        vm.set_virt_syscall(callback)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_dispatcher(names: List[str]) -> SyscallDispatcher:
    """
    Build a SyscallDispatcher from a list of set names.

    Valid names: ``"none"``, ``"os"``, ``"pygame"``, ``"paravirt"``, ``"all"``.
    """
    sets: List[BaseSyscallSet] = []
    if "all" in names:
        names = ["os", "pygame"]

    for name in names:
        if name == "none":
            continue
        elif name == "os":
            from .os_sys import OsSyscallSet  # noqa: PLC0415

            sets.append(OsSyscallSet())
        elif name == "pygame":
            from .pygame_sys import PygameSyscallSet  # noqa: PLC0415

            sets.append(PygameSyscallSet())
        elif name == "paravirt":
            from ..paravirt import ParavirtDeviceSet  # noqa: PLC0415

            sets.append(ParavirtDeviceSet())
        else:
            raise ValueError(
                f"Unknown syscall set name: {name!r}. "
                f"Valid names: none, os, pygame, paravirt, all"
            )

    return SyscallDispatcher(sets)
