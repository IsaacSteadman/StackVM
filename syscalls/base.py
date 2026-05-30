"""
StackVM syscall base classes.

SyscallContext
--------------
Wraps a PyStackVM VirtualMachine instance and provides a clean interface for
reading syscall arguments and writing the return value.

Stack layout at the time a CALL_E/BCCE_SYSCALL fires (sp points to top):
    vm.sp +  0  : num_bytes_of_args (u64) — always 32 for the 4-arg ABI
    vm.sp +  8  : arg0 (u64)
    vm.sp + 16  : arg1 (u64)
    vm.sp + 24  : arg2 (u64)
    vm.sp + 32  : arg3 (u64) — ALSO the return value slot

BaseSyscallSet
--------------
Base class for groups of related syscall handlers.  Subclasses define
``handlers: dict[int, Callable[[SyscallContext], None]]``.
"""

from __future__ import annotations

import sys
from typing import Callable, Dict


class SyscallContext:
    """Provides argument access and result-writing for a single syscall invocation."""

    __slots__ = ("_vm",)

    def __init__(self, vm: object) -> None:
        self._vm = vm

    # ------------------------------------------------------------------
    # Argument accessors
    # ------------------------------------------------------------------

    def arg(self, n: int) -> int:
        """Return the nth syscall argument (0-indexed, 0..3) as an unsigned 64-bit int."""
        return self._vm.get(8, self._vm.sp + 8 + n * 8)

    # ------------------------------------------------------------------
    # Memory helpers
    # ------------------------------------------------------------------

    def read_zstr(self, ptr: int, encoding: str = "utf-8") -> str:
        """Read a null-terminated string from VM memory at *ptr*."""
        return self._vm.extract_zstr(ptr, encoding)

    def read_bytes(self, ptr: int, n: int) -> bytes:
        """Read *n* raw bytes from VM memory at *ptr*."""
        return bytes(self._vm.memory[ptr : ptr + n])

    def write_bytes(self, ptr: int, data: bytes) -> None:
        """Write *data* into VM memory at *ptr*."""
        self._vm.memory[ptr : ptr + len(data)] = data

    # ------------------------------------------------------------------
    # Return value
    # ------------------------------------------------------------------

    def set_result(self, val: int) -> None:
        """Write *val* (unsigned 64-bit) into the return-value slot (vm.sp + 32)."""
        self._vm.set(8, self._vm.sp + 32, val & 0xFFFFFFFFFFFFFFFF)

    # ------------------------------------------------------------------
    # Raw VM access
    # ------------------------------------------------------------------

    @property
    def vm(self) -> object:
        return self._vm


class BaseSyscallSet:
    """
    Mixin base for a named group of syscall handlers.

    Subclasses should populate ``self.handlers`` in ``__init__`` as
    ``{syscall_number: method}``.
    """

    name: str = "unnamed"

    def __init__(self) -> None:
        self.handlers: Dict[int, Callable[[SyscallContext], None]] = {}
