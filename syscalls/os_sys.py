"""
OS syscall set  (0x10–0x19).

Handles process control, stdio/file I/O, heap growth, clocks, and sleep.
Also registers the legacy 0x21 (print string) and 0x01 (debug print) handlers
so that programs compiled against the old ABI keep working.
"""

from __future__ import annotations

import io
import os
import sys
import time

from .base import BaseSyscallSet, SyscallContext
from .numbers import (
    FD_STDERR,
    FD_STDIN,
    FD_STDOUT,
    OPEN_READ,
    OPEN_READWRITE,
    OPEN_WRITE,
    OPEN_WRITE_NEW,
    SEEK_CUR,
    SEEK_END,
    SEEK_SET,
    SYS_CLOCK_NS,
    SYS_CLOSE,
    SYS_EXIT,
    SYS_MMAP,
    SYS_MUNMAP,
    SYS_OPEN,
    SYS_READ,
    SYS_SEEK,
    SYS_SLEEP_NS,
    SYS_WRITE,
)

_WHENCE_MAP = {SEEK_SET: 0, SEEK_CUR: 1, SEEK_END: 2}

_OPEN_MODE_MAP = {
    OPEN_READ: "rb",
    OPEN_WRITE: "wb",
    OPEN_READWRITE: "r+b",
    OPEN_WRITE_NEW: "w+b",
}

# Syscall numbers for legacy compat (not in numbers.py because they predate
# the os syscall set).
_SYS_LEGACY_PRINT = 0x21
_SYS_LEGACY_DEBUG = 0x01


class OsSyscallSet(BaseSyscallSet):
    """
    Provides basic OS-level services to StackVM programs.

    File-descriptor table:
        0 = sys.stdin.buffer
        1 = sys.stdout.buffer
        2 = sys.stderr.buffer
        ≥3 = opened via SYS_OPEN
    """

    name = "os"

    def __init__(self) -> None:
        super().__init__()
        # fd_table: fd → file-like with read/write/seek
        self._fd_table: dict[int, io.RawIOBase] = {
            FD_STDIN: sys.stdin.buffer,
            FD_STDOUT: sys.stdout.buffer,
            FD_STDERR: sys.stderr.buffer,
        }
        self._next_fd: int = 3

        self.handlers = {
            SYS_EXIT: self._sys_exit,
            SYS_WRITE: self._sys_write,
            SYS_READ: self._sys_read,
            SYS_OPEN: self._sys_open,
            SYS_CLOSE: self._sys_close,
            SYS_SEEK: self._sys_seek,
            SYS_MMAP: self._sys_mmap,
            SYS_MUNMAP: self._sys_munmap,
            SYS_CLOCK_NS: self._sys_clock_ns,
            SYS_SLEEP_NS: self._sys_sleep_ns,
            # Legacy compat
            _SYS_LEGACY_PRINT: self._legacy_print,
            _SYS_LEGACY_DEBUG: self._legacy_debug,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_fd(self, fd: int) -> io.RawIOBase | None:
        return self._fd_table.get(fd)

    def _alloc_fd(self, f: io.RawIOBase) -> int:
        fd = self._next_fd
        self._fd_table[fd] = f
        self._next_fd += 1
        return fd

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    def _sys_exit(self, ctx: SyscallContext) -> None:
        raise SystemExit(ctx.arg(0) & 0xFFFFFFFF)

    def _sys_write(self, ctx: SyscallContext) -> None:
        fd = ctx.arg(0)
        buf_ptr = ctx.arg(1)
        length = ctx.arg(2)
        f = self._get_fd(fd)
        if f is None:
            ctx.set_result(0xFFFFFFFFFFFFFFFF)  # -1 (error)
            return
        data = ctx.read_bytes(buf_ptr, length)
        try:
            n = f.write(data)
            if n is None:
                n = len(data)
            f.flush()
        except OSError:
            n = 0xFFFFFFFFFFFFFFFF  # -1
        ctx.set_result(n)

    def _sys_read(self, ctx: SyscallContext) -> None:
        fd = ctx.arg(0)
        buf_ptr = ctx.arg(1)
        length = ctx.arg(2)
        f = self._get_fd(fd)
        if f is None:
            ctx.set_result(0xFFFFFFFFFFFFFFFF)
            return
        try:
            data = f.read(length)
        except OSError:
            ctx.set_result(0xFFFFFFFFFFFFFFFF)
            return
        if data is None:
            data = b""
        ctx.write_bytes(buf_ptr, data)
        ctx.set_result(len(data))

    def _sys_open(self, ctx: SyscallContext) -> None:
        path_ptr = ctx.arg(0)
        flags = ctx.arg(1)
        path = ctx.read_zstr(path_ptr)
        mode = _OPEN_MODE_MAP.get(flags, "rb")
        try:
            f = open(path, mode)  # noqa: SIM115,WPS515
            ctx.set_result(self._alloc_fd(f))
        except OSError:
            ctx.set_result(0xFFFFFFFFFFFFFFFF)

    def _sys_close(self, ctx: SyscallContext) -> None:
        fd = ctx.arg(0)
        if fd in (FD_STDIN, FD_STDOUT, FD_STDERR):
            return  # don't close standard streams
        f = self._fd_table.pop(fd, None)
        if f is not None:
            try:
                f.close()
            except OSError:
                pass

    def _sys_seek(self, ctx: SyscallContext) -> None:
        fd = ctx.arg(0)
        offset = ctx.arg(1)
        whence = _WHENCE_MAP.get(ctx.arg(2), 0)
        f = self._get_fd(fd)
        if f is None:
            ctx.set_result(0xFFFFFFFFFFFFFFFF)
            return
        try:
            pos = f.seek(offset, whence)
            ctx.set_result(pos)
        except OSError:
            ctx.set_result(0xFFFFFFFFFFFFFFFF)

    def _sys_mmap(self, ctx: SyscallContext) -> None:
        """
        Grow the VM's physical memory by *size* bytes and return the address of
        the new region.  Returns 0 if virtual memory is enabled (unsupported) or
        if the VM's memory is not a mutable bytearray.
        """
        vm = ctx.vm
        # Virtual-memory mode: we can't safely extend the address space here.
        if getattr(vm, "virt_mem_mode", 0) != 0:
            ctx.set_result(0)
            return
        size = ctx.arg(0)
        if size == 0:
            ctx.set_result(0)
            return
        memory = vm.memory
        if not isinstance(memory, bytearray):
            ctx.set_result(0)
            return
        base = len(memory)
        memory.extend(b"\x00" * size)
        ctx.set_result(base)

    def _sys_munmap(self, ctx: SyscallContext) -> None:
        # Heap shrinking is not supported; this is a no-op stub.
        ctx.set_result(0)

    def _sys_clock_ns(self, ctx: SyscallContext) -> None:
        ctx.set_result(time.time_ns())

    def _sys_sleep_ns(self, ctx: SyscallContext) -> None:
        ns = ctx.arg(0)
        time.sleep(ns / 1_000_000_000)

    # ------------------------------------------------------------------
    # Legacy compat
    # ------------------------------------------------------------------

    def _legacy_print(self, ctx: SyscallContext) -> None:
        """0x21: write null-terminated string at arg0 to stdout."""
        addr = ctx.arg(0)
        if addr:
            sys.stdout.write(ctx.read_zstr(addr))

    def _legacy_debug(self, ctx: SyscallContext) -> None:
        """0x01: print arg0..arg3 and return 1234."""
        a = ctx.arg(0)
        b = ctx.arg(1)
        c = ctx.arg(2)
        d = ctx.arg(3)
        print(a, b, c, d)
        ctx.set_result(1234)
