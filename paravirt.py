"""Paravirtual device hypercalls for early kernel bring-up.

D4 deliberately avoids the normal CALL_E/SYSCALL path: virtualized syscalls are
user-originated, while these services are for the guest kernel before the MMIO
device model exists.  The guest rings the paravirt doorbell with
``CALL_E``/``IS_INT`` vector ``INT_PARAVIRT`` (0x12), and the host reads the
hypercall frame from the guest stack.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Callable, Iterable, Optional, Union

from .PyStackVM import INT_PARAVIRT, VM_DISABLED
from .syscalls.base import BaseSyscallSet

PV_DOORBELL_INT = INT_PARAVIRT
PV_ARG_BYTES = 32

PVH_CONSOLE_WRITE = 0x00
PVH_CONSOLE_READ = 0x01
PVH_BLOCK_READ = 0x02
PVH_BLOCK_WRITE = 0x03
PVH_RTC_NOW_NS = 0x04
PVH_ENTROPY = 0x05

_U64_MASK = (1 << 64) - 1
PV_EIO = (-5) & _U64_MASK
PV_ENODEV = (-19) & _U64_MASK
PV_EINVAL = (-22) & _U64_MASK
PV_ENOSPC = (-28) & _U64_MASK
PV_ENOSYS = (-38) & _U64_MASK


class HypercallContext:
    """Access to one paravirt hypercall frame on the guest stack.

    Frame layout at doorbell entry (all fields little-endian u64)::

        sp +  0: hypercall number
        sp +  8: argument byte count (currently 32)
        sp + 16: arg0
        sp + 24: arg1
        sp + 32: arg2
        sp + 40: arg3, also the return-value slot
    """

    __slots__ = ("_vm", "_base")

    def __init__(self, vm: object) -> None:
        self._vm = vm
        self._base = vm.sp

    @property
    def vm(self) -> object:
        return self._vm

    @property
    def number(self) -> int:
        return self._read_u64(self._base)

    @property
    def arg_bytes(self) -> int:
        return self._read_u64(self._base + 8)

    def arg(self, n: int) -> int:
        if n < 0 or n > 3:
            raise IndexError("paravirt hypercalls expose exactly four arguments")
        return self._read_u64(self._base + 16 + n * 8)

    def set_result(self, val: int) -> None:
        self._write_u64(self._base + 40, val)

    def read_bytes(self, ptr: int, length: int) -> bytes:
        return _read_guest_bytes(self._vm, ptr, length)

    def write_bytes(self, ptr: int, data: Union[bytes, bytearray, memoryview]) -> None:
        _write_guest_bytes(self._vm, ptr, bytes(data))

    def _read_u64(self, addr: int) -> int:
        val = self._vm.get(8, addr)
        if val is None:
            raise RuntimeError("could not read paravirt hypercall frame")
        return val

    def _write_u64(self, addr: int, val: int) -> None:
        if not self._vm.set(8, addr, val & _U64_MASK):
            raise RuntimeError("could not write paravirt hypercall result")


class MemoryBlockDevice:
    """Fixed-size in-memory block backend used by the phase-1 paravirt layer."""

    __slots__ = ("data",)

    def __init__(self, data: Union[bytes, bytearray, memoryview, int]) -> None:
        if isinstance(data, int):
            self.data = bytearray(data)
        else:
            self.data = bytearray(data)

    @property
    def size(self) -> int:
        return len(self.data)

    def read(self, offset: int, length: int) -> bytes:
        if offset >= len(self.data):
            return b""
        end = min(offset + length, len(self.data))
        return bytes(self.data[offset:end])

    def write(self, offset: int, data: bytes) -> int:
        if offset >= len(self.data):
            return 0
        end = min(offset + len(data), len(self.data))
        real_len = end - offset
        self.data[offset:end] = data[:real_len]
        return real_len


class ParavirtDeviceSet(BaseSyscallSet):
    """Host-backed early devices exposed through the paravirt doorbell."""

    name = "paravirt"

    def __init__(
        self,
        *,
        console_input: Union[bytes, bytearray, memoryview] = b"",
        console_output: Optional[object] = None,
        block_devices: Optional[
            Iterable[Union[MemoryBlockDevice, bytes, bytearray, memoryview, int]]
        ] = None,
        rtc_ns: Optional[Callable[[], int]] = None,
        entropy: Optional[Callable[[int], bytes]] = None,
    ) -> None:
        super().__init__()
        self.console_input = bytearray(console_input)
        self.console_output = (
            sys.stdout.buffer if console_output is None else console_output
        )
        self.block_devices = [
            dev if isinstance(dev, MemoryBlockDevice) else MemoryBlockDevice(dev)
            for dev in (block_devices or [])
        ]
        self.rtc_ns = time.time_ns if rtc_ns is None else rtc_ns
        self.entropy = os.urandom if entropy is None else entropy
        self.hypercall_handlers = {
            PVH_CONSOLE_WRITE: self._console_write,
            PVH_CONSOLE_READ: self._console_read,
            PVH_BLOCK_READ: self._block_read,
            PVH_BLOCK_WRITE: self._block_write,
            PVH_RTC_NOW_NS: self._rtc_now_ns,
            PVH_ENTROPY: self._entropy,
        }

    def _console_write(self, ctx: HypercallContext) -> None:
        buf = ctx.arg(0)
        length = ctx.arg(1)
        data = ctx.read_bytes(buf, length)
        out = self.console_output
        if isinstance(out, bytearray):
            out.extend(data)
            written = len(data)
        else:
            written = out.write(data)
            if written is None:
                written = len(data)
            flush = getattr(out, "flush", None)
            if flush is not None:
                flush()
        ctx.set_result(written)

    def _console_read(self, ctx: HypercallContext) -> None:
        buf = ctx.arg(0)
        length = ctx.arg(1)
        real_len = min(length, len(self.console_input))
        data = bytes(self.console_input[:real_len])
        del self.console_input[:real_len]
        ctx.write_bytes(buf, data)
        ctx.set_result(real_len)

    def _block_read(self, ctx: HypercallContext) -> None:
        dev = self._block_device(ctx.arg(0))
        if dev is None:
            ctx.set_result(PV_ENODEV)
            return
        offset = ctx.arg(1)
        buf = ctx.arg(2)
        length = ctx.arg(3)
        data = dev.read(offset, length)
        ctx.write_bytes(buf, data)
        ctx.set_result(len(data))

    def _block_write(self, ctx: HypercallContext) -> None:
        dev = self._block_device(ctx.arg(0))
        if dev is None:
            ctx.set_result(PV_ENODEV)
            return
        offset = ctx.arg(1)
        buf = ctx.arg(2)
        length = ctx.arg(3)
        data = ctx.read_bytes(buf, length)
        written = dev.write(offset, data)
        ctx.set_result(written if written or length == 0 else PV_ENOSPC)

    def _rtc_now_ns(self, ctx: HypercallContext) -> None:
        ctx.set_result(int(self.rtc_ns()))

    def _entropy(self, ctx: HypercallContext) -> None:
        buf = ctx.arg(0)
        length = ctx.arg(1)
        flags = ctx.arg(2)
        if flags != 0:
            ctx.set_result(PV_EINVAL)
            return
        data = bytes(self.entropy(length))
        if len(data) > length:
            data = data[:length]
        ctx.write_bytes(buf, data)
        ctx.set_result(len(data))

    def _block_device(self, dev_id: int) -> Optional[MemoryBlockDevice]:
        if dev_id >= len(self.block_devices):
            return None
        return self.block_devices[dev_id]


def dispatch_paravirt_hypercall(vm: object, handlers: dict[int, Callable]) -> None:
    """Dispatch one doorbell frame from *vm* through *handlers*."""
    ctx = HypercallContext(vm)
    if ctx.arg_bytes < PV_ARG_BYTES:
        ctx.set_result(PV_EINVAL)
        return
    handler = handlers.get(ctx.number)
    if handler is None:
        ctx.set_result(PV_ENOSYS)
        return
    try:
        handler(ctx)
    except OSError:
        ctx.set_result(PV_EIO)


def _check_guest_range(vm: object, ptr: int, length: int) -> None:
    if ptr < 0 or length < 0 or ptr + length > len(vm.memory):
        raise IndexError(
            "guest memory range out of bounds: ptr=%#x length=%#x" % (ptr, length)
        )


def _read_guest_bytes(vm: object, ptr: int, length: int) -> bytes:
    if length == 0:
        return b""
    if getattr(vm, "virt_mem_mode", VM_DISABLED) == VM_DISABLED:
        _check_guest_range(vm, ptr, length)
        return bytes(vm.memory[ptr : ptr + length])
    out = bytearray()
    for off in range(length):
        val = vm.get(1, ptr + off)
        if val is None:
            raise RuntimeError("could not read guest memory")
        out.append(val)
    return bytes(out)


def _write_guest_bytes(vm: object, ptr: int, data: bytes) -> None:
    if not data:
        return
    if getattr(vm, "virt_mem_mode", VM_DISABLED) == VM_DISABLED:
        _check_guest_range(vm, ptr, len(data))
        vm.memory[ptr : ptr + len(data)] = data
        return
    for off, val in enumerate(data):
        if not vm.set(1, ptr + off, val):
            raise RuntimeError("could not write guest memory")
