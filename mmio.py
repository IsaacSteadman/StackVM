"""MMIO device framework for the Python StackVM reference emulator.

The bus in this module sits above the VM's physical ``bytearray`` memory: once
the CPU has translated a guest address to a physical address, accesses that fall
inside a registered MMIO window are dispatched to the owning device instead of
touching RAM.
"""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Tuple, Union

from .PyStackVM import INT_HW_IO

U64_MASK = (1 << 64) - 1

SVM_MMIO_BASE = 0xFFFF0000
SVM_MMIO_UART0_BASE = SVM_MMIO_BASE + 0x0000
SVM_MMIO_IC_BASE = SVM_MMIO_BASE + 0x1000
SVM_MMIO_RTC_BASE = SVM_MMIO_BASE + 0x2000
SVM_MMIO_VIRTIO_BLK0_BASE = SVM_MMIO_BASE + 0x3000
SVM_MMIO_VIRTIO_NET0_BASE = SVM_MMIO_BASE + 0x4000
SVM_MMIO_FRAMEBUFFER0_BASE = SVM_MMIO_BASE + 0x5000
SVM_MMIO_FRAMEBUFFER0_PIXELS_BASE = SVM_MMIO_BASE + 0x100000

SVM_MMIO_WINDOW_SIZE = 0x1000

SVM_IRQ_UART0 = 1
SVM_IRQ_VIRTIO_BLK0 = 2
SVM_IRQ_RTC = 3
SVM_IRQ_VIRTIO_NET0 = 4

# UART register offsets.
UART_REG_DATA = 0x00
UART_REG_STATUS = 0x08
UART_REG_IRQ_ENABLE = 0x10
UART_REG_IRQ_STATUS = 0x18
UART_REG_IRQ_ACK = 0x20

UART_STATUS_RX_READY = 1 << 0
UART_STATUS_TX_READY = 1 << 1
UART_IRQ_RX = 1 << 0

# Interrupt-controller register offsets.
IC_REG_PENDING = 0x00
IC_REG_ENABLE = 0x08
IC_REG_CLAIM = 0x10
IC_REG_EOI = 0x18
IC_REG_ROUTE_BASE = 0x100
IC_REG_PRIORITY_BASE = 0x300
IC_NO_PENDING = 0xFFFFFFFFFFFFFFFF

# RTC register offsets.
RTC_REG_NOW_NS = 0x00
RTC_REG_NOW_SEC = 0x08

# Simple framebuffer register offsets.
FB_REG_WIDTH = 0x00
FB_REG_HEIGHT = 0x08
FB_REG_STRIDE = 0x10
FB_REG_FORMAT = 0x18
FB_REG_PIXEL_BASE = 0x20
FB_REG_PIXEL_SIZE = 0x28
FB_REG_DIRTY_SEQ = 0x30
FB_REG_FLUSH = 0x38

SVM_FB_FORMAT_XRGB8888 = 1

# Virtio-MMIO-ish transport register offsets.  This is intentionally compact,
# but the queue descriptor and avail/used rings follow virtio's shape closely
# enough for guest drivers to share the same mechanics.
VIRTIO_REG_MAGIC = 0x00
VIRTIO_REG_VERSION = 0x04
VIRTIO_REG_DEVICE_ID = 0x08
VIRTIO_REG_STATUS = 0x0C
VIRTIO_REG_QUEUE_DESC = 0x10
VIRTIO_REG_QUEUE_AVAIL = 0x18
VIRTIO_REG_QUEUE_USED = 0x20
VIRTIO_REG_QUEUE_NUM = 0x28
VIRTIO_REG_QUEUE_NOTIFY = 0x30
VIRTIO_REG_INTERRUPT_STATUS = 0x38
VIRTIO_REG_INTERRUPT_ACK = 0x40
VIRTIO_REG_DRIVER_FEATURES = 0x48
VIRTIO_REG_DEVICE_FEATURES = 0x50
VIRTIO_REG_QUEUE_SEL = 0x58

VIRTIO_MAGIC = 0x74726976  # "virt", little-endian as an integer
VIRTIO_VERSION = 2
VIRTIO_DEVICE_NET = 1
VIRTIO_DEVICE_BLOCK = 2

VIRTQ_DESC_SIZE = 16
VIRTQ_DESC_F_NEXT = 1
VIRTQ_DESC_F_WRITE = 2

VIRTIO_BLK_SECTOR_SIZE = 512
VIRTIO_BLK_T_IN = 0
VIRTIO_BLK_T_OUT = 1
VIRTIO_BLK_S_OK = 0
VIRTIO_BLK_S_IOERR = 1

VIRTIO_NET_HDR_SIZE = 10


def _mask_for_size(size: int) -> int:
    if size <= 0:
        raise ValueError("MMIO access size must be positive")
    return (1 << (8 * size)) - 1


def _read_le(mem: bytearray, addr: int, size: int) -> int:
    if addr < 0 or addr + size > len(mem):
        raise IndexError("guest memory access out of range")
    return int.from_bytes(mem[addr : addr + size], "little")


def _write_le(mem: bytearray, addr: int, size: int, value: int) -> None:
    if addr < 0 or addr + size > len(mem):
        raise IndexError("guest memory access out of range")
    mem[addr : addr + size] = (value & _mask_for_size(size)).to_bytes(size, "little")


def _read_guest(vm: object, addr: int, length: int) -> bytes:
    mem = vm.memory
    if addr < 0 or length < 0 or addr + length > len(mem):
        raise IndexError("guest memory access out of range")
    return bytes(mem[addr : addr + length])


def _write_guest(vm: object, addr: int, data: Union[bytes, bytearray, memoryview]) -> None:
    mem = vm.memory
    data = bytes(data)
    if addr < 0 or addr + len(data) > len(mem):
        raise IndexError("guest memory access out of range")
    mem[addr : addr + len(data)] = data


@dataclass(frozen=True)
class MmioRegion:
    base: int
    size: int
    device: "MmioDevice"
    name: str

    @property
    def end(self) -> int:
        return self.base + self.size


class MmioDevice:
    """Base class for one device attached to an :class:`MmioBus`."""

    size = SVM_MMIO_WINDOW_SIZE

    def __init__(self) -> None:
        self.bus: Optional[MmioBus] = None
        self.base = 0

    def attach(self, bus: "MmioBus", base: int) -> None:
        self.bus = bus
        self.base = base

    def attach_vm(self, vm: object) -> None:
        """Hook called when the bus is attached to a VM."""

    def service_interrupts(self) -> None:
        """Hook called when the VM has an APIC and pending IRQs may be posted."""

    def read(self, offset: int, size: int) -> int:
        return 0

    def write(self, offset: int, size: int, value: int) -> None:
        return None


class MmioBus:
    """Physical-address MMIO dispatch table."""

    def __init__(self) -> None:
        self.regions: List[MmioRegion] = []
        self.vm: Optional[object] = None

    def add_region(
        self, base: int, size: int, device: MmioDevice, name: Optional[str] = None
    ) -> MmioDevice:
        if size <= 0:
            raise ValueError("MMIO region size must be positive")
        end = base + size
        for region in self.regions:
            if base < region.end and end > region.base:
                raise ValueError(
                    "MMIO region %#x..%#x overlaps %s %#x..%#x"
                    % (base, end, region.name, region.base, region.end)
                )
        region_name = name or device.__class__.__name__
        device.attach(self, base)
        self.regions.append(MmioRegion(base, size, device, region_name))
        self.regions.sort(key=lambda r: r.base)
        if self.vm is not None:
            device.attach_vm(self.vm)
        return device

    def attach_vm(self, vm: object) -> None:
        self.vm = vm
        for region in self.regions:
            region.device.attach_vm(vm)

    def handles(self, addr: int, size: int) -> bool:
        end = addr + size
        for region in self.regions:
            if addr < region.end and end > region.base:
                return True
        return False

    def _find_region(self, addr: int, size: int) -> MmioRegion:
        end = addr + size
        for region in self.regions:
            if region.base <= addr and end <= region.end:
                return region
        raise IndexError("MMIO access %#x..%#x does not fit one device window" % (addr, end))

    def read(self, addr: int, size: int) -> int:
        region = self._find_region(addr, size)
        value = region.device.read(addr - region.base, size)
        return value & _mask_for_size(size)

    def write(self, addr: int, size: int, value: int) -> None:
        region = self._find_region(addr, size)
        region.device.write(addr - region.base, size, value & _mask_for_size(size))

    def read_bytes(self, addr: int, length: int) -> bytes:
        return bytes(self.read(addr + i, 1) for i in range(length))

    def write_bytes(self, addr: int, data: Union[bytes, bytearray, memoryview]) -> None:
        for i, value in enumerate(bytes(data)):
            self.write(addr + i, 1, value)

    def service_interrupts(self) -> None:
        for region in self.regions:
            region.device.service_interrupts()


class MmioInterruptController(MmioDevice):
    """Small local interrupt-controller model for MMIO devices.

    Devices raise numbered IRQ lines here.  Enabled pending lines are routed to
    the VM's ``AdvProgIntCtl`` as architectural interrupt vectors.  The guest can
    inspect pending bits, enable/mask lines, claim the delivered IRQ, complete it
    with EOI, and route each line to a vector.
    """

    def __init__(self, max_irqs: int = 64, default_vector: int = INT_HW_IO) -> None:
        super().__init__()
        self.max_irqs = max_irqs
        self.default_vector = default_vector
        self.enable_mask = 0
        self.pending_mask = 0
        self.posted_mask = 0
        self.in_service_mask = 0
        self.routes = [default_vector] * max_irqs
        self.priorities: List[Optional[int]] = [None] * max_irqs
        self.args: List[Tuple[int, int, int]] = [(0, 0, 0)] * max_irqs
        self.vm: Optional[object] = None
        self.apic: Optional[object] = None

    def attach_vm(self, vm: object) -> None:
        self.vm = vm

    def connect_apic(self, apic: object) -> None:
        self.apic = apic
        self.service_interrupts()

    def _line_bit(self, irq: int) -> int:
        irq = int(irq)
        if irq < 0 or irq >= self.max_irqs:
            raise ValueError("IRQ line out of range: %r" % irq)
        return 1 << irq

    def _current_apic(self) -> Optional[object]:
        if self.apic is not None:
            return self.apic
        if self.vm is not None:
            return getattr(self.vm, "apic", None)
        return None

    def raise_irq(
        self,
        irq: int,
        arg0: int = 0,
        arg1: int = 0,
        arg2: int = 0,
        priority: Optional[int] = None,
    ) -> None:
        bit = self._line_bit(irq)
        self.pending_mask |= bit
        self.args[irq] = (arg0 & U64_MASK, arg1 & U64_MASK, arg2 & U64_MASK)
        if priority is not None:
            self.priorities[irq] = priority & 0xFF
        self._post_if_enabled(irq)

    def _post_if_enabled(self, irq: int) -> None:
        bit = 1 << irq
        if not (self.pending_mask & bit):
            return
        if not (self.enable_mask & bit):
            return
        if self.posted_mask & bit:
            return
        if self.in_service_mask & bit:
            return
        apic = self._current_apic()
        if apic is None:
            return
        a0, a1, a2 = self.args[irq]
        apic.trigger(
            self.routes[irq],
            irq,
            a0,
            a1,
            a2,
            priority=self.priorities[irq],
        )
        self.posted_mask |= bit

    def service_interrupts(self) -> None:
        enabled_pending = self.pending_mask & self.enable_mask
        for irq in range(self.max_irqs):
            if enabled_pending & (1 << irq):
                self._post_if_enabled(irq)

    def _claim(self) -> int:
        eligible = self.pending_mask & self.enable_mask
        for irq in range(self.max_irqs):
            bit = 1 << irq
            if eligible & bit:
                self.pending_mask &= ~bit
                self.posted_mask &= ~bit
                self.in_service_mask |= bit
                return irq
        return IC_NO_PENDING

    def _eoi(self, irq: int) -> None:
        bit = self._line_bit(irq)
        self.in_service_mask &= ~bit
        self.posted_mask &= ~bit
        if self.pending_mask & bit:
            self._post_if_enabled(irq)

    def read(self, offset: int, size: int) -> int:
        if offset == IC_REG_PENDING:
            return self.pending_mask
        if offset == IC_REG_ENABLE:
            return self.enable_mask
        if offset == IC_REG_CLAIM:
            return self._claim()
        if IC_REG_ROUTE_BASE <= offset < IC_REG_ROUTE_BASE + self.max_irqs * 8:
            irq = (offset - IC_REG_ROUTE_BASE) // 8
            return self.routes[irq]
        if IC_REG_PRIORITY_BASE <= offset < IC_REG_PRIORITY_BASE + self.max_irqs * 8:
            irq = (offset - IC_REG_PRIORITY_BASE) // 8
            priority = self.priorities[irq]
            return IC_NO_PENDING if priority is None else priority
        return 0

    def write(self, offset: int, size: int, value: int) -> None:
        if offset == IC_REG_PENDING:
            self.pending_mask &= ~value
            self.posted_mask &= ~value
            return
        if offset == IC_REG_ENABLE:
            self.enable_mask = value & ((1 << self.max_irqs) - 1)
            self.service_interrupts()
            return
        if offset == IC_REG_CLAIM or offset == IC_REG_EOI:
            if value != IC_NO_PENDING:
                self._eoi(int(value))
            return
        if IC_REG_ROUTE_BASE <= offset < IC_REG_ROUTE_BASE + self.max_irqs * 8:
            irq = (offset - IC_REG_ROUTE_BASE) // 8
            self.routes[irq] = value & 0xFF
            return
        if IC_REG_PRIORITY_BASE <= offset < IC_REG_PRIORITY_BASE + self.max_irqs * 8:
            irq = (offset - IC_REG_PRIORITY_BASE) // 8
            self.priorities[irq] = None if value == IC_NO_PENDING else (value & 0xFF)


class UartSerialDevice(MmioDevice):
    """Byte-oriented UART: TX writes append to host output, RX can raise IRQs."""

    def __init__(
        self,
        *,
        irq_controller: Optional[MmioInterruptController] = None,
        irq: int = SVM_IRQ_UART0,
        output: Optional[object] = None,
        input_bytes: Union[bytes, bytearray, memoryview] = b"",
    ) -> None:
        super().__init__()
        self.irq_controller = irq_controller
        self.irq = irq
        self.output = bytearray() if output is None else output
        self.rx = bytearray(input_bytes)
        self.irq_enable = 0

    def inject_rx(self, data: Union[bytes, bytearray, memoryview]) -> None:
        self.rx.extend(bytes(data))
        self._maybe_raise_rx_irq()

    def _write_output(self, value: int) -> None:
        data = bytes([value & 0xFF])
        out = self.output
        if isinstance(out, bytearray):
            out.extend(data)
        else:
            written = out.write(data)
            if written is None:
                written = len(data)
            flush = getattr(out, "flush", None)
            if flush is not None:
                flush()

    def _maybe_raise_rx_irq(self) -> None:
        if self.rx and (self.irq_enable & UART_IRQ_RX) and self.irq_controller is not None:
            self.irq_controller.raise_irq(self.irq, len(self.rx), 0, 0)

    def read(self, offset: int, size: int) -> int:
        if offset == UART_REG_DATA:
            if not self.rx:
                return 0
            value = self.rx.pop(0)
            if self.rx:
                self._maybe_raise_rx_irq()
            return value
        if offset == UART_REG_STATUS:
            status = UART_STATUS_TX_READY
            if self.rx:
                status |= UART_STATUS_RX_READY
            return status
        if offset == UART_REG_IRQ_ENABLE:
            return self.irq_enable
        if offset == UART_REG_IRQ_STATUS:
            return UART_IRQ_RX if self.rx else 0
        return 0

    def write(self, offset: int, size: int, value: int) -> None:
        if offset == UART_REG_DATA:
            self._write_output(value)
        elif offset == UART_REG_IRQ_ENABLE:
            self.irq_enable = value & UART_IRQ_RX
            self._maybe_raise_rx_irq()
        elif offset == UART_REG_IRQ_ACK:
            return


class RtcDevice(MmioDevice):
    """Read-only wall-clock device returning nanoseconds/seconds."""

    def __init__(self, time_ns: Optional[Callable[[], int]] = None) -> None:
        super().__init__()
        self.time_ns = time.time_ns if time_ns is None else time_ns

    def read(self, offset: int, size: int) -> int:
        now = int(self.time_ns())
        if offset == RTC_REG_NOW_NS:
            return now
        if offset == RTC_REG_NOW_SEC:
            return now // 1000000000
        return 0


class FramebufferPixelDevice(MmioDevice):
    """MMIO pixel aperture for :class:`FramebufferDevice`."""

    def __init__(self, framebuffer: "FramebufferDevice") -> None:
        super().__init__()
        self.framebuffer = framebuffer

    def read(self, offset: int, size: int) -> int:
        return self.framebuffer.read_pixels(offset, size)

    def write(self, offset: int, size: int, value: int) -> None:
        self.framebuffer.write_pixels(offset, size, value)


class FramebufferDevice(MmioDevice):
    """A simple XRGB8888 framebuffer with a register window and pixel aperture."""

    def __init__(
        self,
        width: int = 640,
        height: int = 480,
        *,
        pixel_base: int = SVM_MMIO_FRAMEBUFFER0_PIXELS_BASE,
        format: int = SVM_FB_FORMAT_XRGB8888,
        pixels: Optional[Union[bytes, bytearray, memoryview]] = None,
    ) -> None:
        super().__init__()
        if width <= 0 or height <= 0:
            raise ValueError("framebuffer dimensions must be positive")
        self.width = int(width)
        self.height = int(height)
        self.format = int(format)
        self.stride = self.width * 4
        self.pixel_base = int(pixel_base)
        pixel_size = self.stride * self.height
        if pixels is None:
            self.pixels = bytearray(pixel_size)
        else:
            self.pixels = bytearray(pixels)
            if len(self.pixels) != pixel_size:
                raise ValueError("initial framebuffer bytes do not match dimensions")
        self.dirty_seq = 0
        self.dirty_ranges: List[Tuple[int, int]] = []
        self.flush_count = 0
        self.pixel_device = FramebufferPixelDevice(self)

    @property
    def pixel_size(self) -> int:
        return len(self.pixels)

    def read(self, offset: int, size: int) -> int:
        if offset == FB_REG_WIDTH:
            return self.width
        if offset == FB_REG_HEIGHT:
            return self.height
        if offset == FB_REG_STRIDE:
            return self.stride
        if offset == FB_REG_FORMAT:
            return self.format
        if offset == FB_REG_PIXEL_BASE:
            return self.pixel_base
        if offset == FB_REG_PIXEL_SIZE:
            return self.pixel_size
        if offset == FB_REG_DIRTY_SEQ:
            return self.dirty_seq
        return 0

    def write(self, offset: int, size: int, value: int) -> None:
        if offset == FB_REG_FLUSH:
            self.flush()

    def read_pixels(self, offset: int, size: int) -> int:
        if offset < 0 or offset + size > len(self.pixels):
            raise IndexError("framebuffer pixel read out of range")
        return int.from_bytes(self.pixels[offset : offset + size], "little")

    def write_pixels(self, offset: int, size: int, value: int) -> None:
        if offset < 0 or offset + size > len(self.pixels):
            raise IndexError("framebuffer pixel write out of range")
        self.pixels[offset : offset + size] = (value & _mask_for_size(size)).to_bytes(
            size, "little"
        )
        self.dirty_seq = (self.dirty_seq + 1) & U64_MASK
        self.dirty_ranges.append((offset, offset + size))

    def flush(self) -> None:
        self.flush_count += 1
        self.dirty_ranges.clear()

    def snapshot(self) -> bytes:
        return bytes(self.pixels)


class HostBlockImage:
    """Persistent host file used as a virtio-blk backing image."""

    def __init__(self, path: str, size: Optional[int] = None) -> None:
        self.path = path
        if size is not None and size < 0:
            raise ValueError("block image size must be non-negative")
        if not os.path.exists(path):
            with open(path, "wb") as f:
                if size:
                    f.truncate(size)
        elif size is not None and os.path.getsize(path) < size:
            with open(path, "r+b") as f:
                f.truncate(size)
        self.fixed_size = size

    @property
    def size(self) -> int:
        if self.fixed_size is not None:
            return self.fixed_size
        return os.path.getsize(self.path)

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("negative block access")
        if offset >= self.size:
            return b"\0" * length
        real_len = min(length, self.size - offset)
        with open(self.path, "rb") as f:
            f.seek(offset)
            data = f.read(real_len)
        if len(data) < length:
            data += b"\0" * (length - len(data))
        return data

    def write(self, offset: int, data: Union[bytes, bytearray, memoryview]) -> int:
        data = bytes(data)
        if offset < 0:
            raise ValueError("negative block access")
        if self.fixed_size is not None:
            if offset >= self.fixed_size:
                return 0
            data = data[: self.fixed_size - offset]
        with open(self.path, "r+b") as f:
            f.seek(offset)
            f.write(data)
        return len(data)


class MemoryBlockImage:
    """In-memory block backend with the same API as :class:`HostBlockImage`."""

    def __init__(self, data: Union[int, bytes, bytearray, memoryview]) -> None:
        self.data = bytearray(data if not isinstance(data, int) else b"\0" * data)

    @property
    def size(self) -> int:
        return len(self.data)

    def read(self, offset: int, length: int) -> bytes:
        if offset >= len(self.data):
            return b"\0" * length
        out = bytes(self.data[offset : offset + length])
        if len(out) < length:
            out += b"\0" * (length - len(out))
        return out

    def write(self, offset: int, data: Union[bytes, bytearray, memoryview]) -> int:
        data = bytes(data)
        if offset >= len(self.data):
            return 0
        real_len = min(len(data), len(self.data) - offset)
        self.data[offset : offset + real_len] = data[:real_len]
        return real_len


@dataclass
class VirtQueueState:
    desc: int = 0
    avail: int = 0
    used: int = 0
    num: int = 0
    last_avail_idx: int = 0


@dataclass
class VirtqDesc:
    addr: int
    length: int
    flags: int
    next: int
    index: int


class VirtioMmioDevice(MmioDevice):
    """Base class for a compact virtio-MMIO transport."""

    device_id = 0

    def __init__(
        self,
        *,
        irq_controller: Optional[MmioInterruptController] = None,
        irq: int,
        queue_count: int = 1,
        features: int = 0,
    ) -> None:
        super().__init__()
        self.irq_controller = irq_controller
        self.irq = irq
        self.features = features
        self.driver_features = 0
        self.status = 0
        self.interrupt_status = 0
        self.queue_sel = 0
        self.queues = [VirtQueueState() for _ in range(queue_count)]
        self.vm: Optional[object] = None

    def attach_vm(self, vm: object) -> None:
        self.vm = vm

    def _queue(self) -> VirtQueueState:
        return self.queues[self.queue_sel]

    def read(self, offset: int, size: int) -> int:
        q = self._queue()
        if offset == VIRTIO_REG_MAGIC:
            return VIRTIO_MAGIC
        if offset == VIRTIO_REG_VERSION:
            return VIRTIO_VERSION
        if offset == VIRTIO_REG_DEVICE_ID:
            return self.device_id
        if offset == VIRTIO_REG_STATUS:
            return self.status
        if offset == VIRTIO_REG_QUEUE_DESC:
            return q.desc
        if offset == VIRTIO_REG_QUEUE_AVAIL:
            return q.avail
        if offset == VIRTIO_REG_QUEUE_USED:
            return q.used
        if offset == VIRTIO_REG_QUEUE_NUM:
            return q.num
        if offset == VIRTIO_REG_INTERRUPT_STATUS:
            return self.interrupt_status
        if offset == VIRTIO_REG_DRIVER_FEATURES:
            return self.driver_features
        if offset == VIRTIO_REG_DEVICE_FEATURES:
            return self.features
        if offset == VIRTIO_REG_QUEUE_SEL:
            return self.queue_sel
        return 0

    def write(self, offset: int, size: int, value: int) -> None:
        q = self._queue()
        if offset == VIRTIO_REG_STATUS:
            self.status = value & 0xFF
        elif offset == VIRTIO_REG_QUEUE_DESC:
            q.desc = value
        elif offset == VIRTIO_REG_QUEUE_AVAIL:
            q.avail = value
        elif offset == VIRTIO_REG_QUEUE_USED:
            q.used = value
        elif offset == VIRTIO_REG_QUEUE_NUM:
            q.num = int(value)
        elif offset == VIRTIO_REG_QUEUE_NOTIFY:
            self.process_queue(int(value))
        elif offset == VIRTIO_REG_INTERRUPT_ACK:
            self.interrupt_status &= ~value
        elif offset == VIRTIO_REG_DRIVER_FEATURES:
            self.driver_features = value
        elif offset == VIRTIO_REG_QUEUE_SEL:
            if value >= len(self.queues):
                raise ValueError("virtio queue index out of range: %r" % value)
            self.queue_sel = int(value)

    def _read_desc(self, queue: VirtQueueState, index: int) -> VirtqDesc:
        if index < 0 or index >= queue.num:
            raise IndexError("virtio descriptor index out of range")
        mem = self.vm.memory
        base = queue.desc + index * VIRTQ_DESC_SIZE
        addr = _read_le(mem, base, 8)
        length = _read_le(mem, base + 8, 4)
        flags = _read_le(mem, base + 12, 2)
        next_idx = _read_le(mem, base + 14, 2)
        return VirtqDesc(addr, length, flags, next_idx, index)

    def _descriptor_chain(self, queue: VirtQueueState, head: int) -> List[VirtqDesc]:
        chain = []
        seen = set()
        idx = head
        while True:
            if idx in seen:
                raise ValueError("virtio descriptor loop at index %r" % idx)
            seen.add(idx)
            desc = self._read_desc(queue, idx)
            chain.append(desc)
            if not (desc.flags & VIRTQ_DESC_F_NEXT):
                return chain
            idx = desc.next

    def process_queue(self, queue_index: int) -> None:
        if self.vm is None:
            raise RuntimeError("virtio device is not attached to a VM")
        if queue_index < 0 or queue_index >= len(self.queues):
            raise ValueError("virtio queue index out of range: %r" % queue_index)
        q = self.queues[queue_index]
        if q.num <= 0 or q.desc == 0 or q.avail == 0 or q.used == 0:
            return
        mem = self.vm.memory
        avail_idx = _read_le(mem, q.avail + 2, 2)
        while q.last_avail_idx != avail_idx:
            ring_pos = q.last_avail_idx % q.num
            head = _read_le(mem, q.avail + 4 + ring_pos * 2, 2)
            chain = self._descriptor_chain(q, head)
            used_len = self.handle_chain(queue_index, head, chain)
            if used_len is None:
                break
            used_idx = _read_le(mem, q.used + 2, 2)
            used_pos = used_idx % q.num
            used_ent = q.used + 4 + used_pos * 8
            _write_le(mem, used_ent, 4, head)
            _write_le(mem, used_ent + 4, 4, used_len)
            _write_le(mem, q.used + 2, 2, (used_idx + 1) & 0xFFFF)
            q.last_avail_idx = (q.last_avail_idx + 1) & 0xFFFF
            self._post_interrupt()

    def handle_chain(
        self, queue_index: int, head: int, chain: List[VirtqDesc]
    ) -> Optional[int]:
        raise NotImplementedError

    def _post_interrupt(self) -> None:
        self.interrupt_status |= 1
        if self.irq_controller is not None:
            self.irq_controller.raise_irq(self.irq, self.device_id, 0, 0)


class VirtioBlockDevice(VirtioMmioDevice):
    device_id = VIRTIO_DEVICE_BLOCK

    def __init__(
        self,
        backend: Union[HostBlockImage, MemoryBlockImage],
        *,
        irq_controller: Optional[MmioInterruptController] = None,
        irq: int = SVM_IRQ_VIRTIO_BLK0,
    ) -> None:
        super().__init__(irq_controller=irq_controller, irq=irq, queue_count=1)
        self.backend = backend

    def handle_chain(
        self, queue_index: int, head: int, chain: List[VirtqDesc]
    ) -> Optional[int]:
        if len(chain) < 3:
            return 0
        header, data_desc, status_desc = chain[0], chain[1], chain[-1]
        status = VIRTIO_BLK_S_OK
        used_len = 1
        try:
            req = _read_guest(self.vm, header.addr, 16)
            req_type, _reserved, sector = struct.unpack("<IIQ", req)
            offset = sector * VIRTIO_BLK_SECTOR_SIZE
            if req_type == VIRTIO_BLK_T_IN:
                data = self.backend.read(offset, data_desc.length)
                _write_guest(self.vm, data_desc.addr, data[: data_desc.length])
                used_len += data_desc.length
            elif req_type == VIRTIO_BLK_T_OUT:
                data = _read_guest(self.vm, data_desc.addr, data_desc.length)
                written = self.backend.write(offset, data)
                if written != len(data):
                    status = VIRTIO_BLK_S_IOERR
                used_len += written
            else:
                status = VIRTIO_BLK_S_IOERR
        except (OSError, ValueError, IndexError):
            status = VIRTIO_BLK_S_IOERR
        if status_desc.flags & VIRTQ_DESC_F_WRITE:
            _write_guest(self.vm, status_desc.addr, bytes([status]))
        return used_len


class InMemoryNetBackend:
    """Deterministic host-side packet backend for virtio-net tests and user-net."""

    def __init__(self, rx_packets: Optional[Iterable[bytes]] = None) -> None:
        self.rx_packets = [bytes(p) for p in (rx_packets or [])]
        self.tx_packets: List[bytes] = []

    def send(self, packet: bytes) -> None:
        self.tx_packets.append(bytes(packet))

    def recv(self) -> Optional[bytes]:
        if not self.rx_packets:
            return None
        return self.rx_packets.pop(0)

    def inject_rx(self, packet: bytes) -> None:
        self.rx_packets.append(bytes(packet))


class VirtioNetDevice(VirtioMmioDevice):
    device_id = VIRTIO_DEVICE_NET

    def __init__(
        self,
        backend: Optional[InMemoryNetBackend] = None,
        *,
        irq_controller: Optional[MmioInterruptController] = None,
        irq: int = SVM_IRQ_VIRTIO_NET0,
    ) -> None:
        super().__init__(irq_controller=irq_controller, irq=irq, queue_count=2)
        self.backend = InMemoryNetBackend() if backend is None else backend

    def inject_rx(self, packet: bytes) -> None:
        self.backend.inject_rx(packet)
        self.process_queue(0)

    def handle_chain(
        self, queue_index: int, head: int, chain: List[VirtqDesc]
    ) -> Optional[int]:
        if queue_index == 0:
            packet = self.backend.recv()
            if packet is None:
                return None
            for desc in chain:
                if desc.flags & VIRTQ_DESC_F_WRITE:
                    data = packet[: desc.length]
                    _write_guest(self.vm, desc.addr, data)
                    return len(data)
            self.backend.inject_rx(packet)
            return None
        if queue_index == 1:
            pieces = []
            for desc in chain:
                if not (desc.flags & VIRTQ_DESC_F_WRITE):
                    pieces.append(_read_guest(self.vm, desc.addr, desc.length))
            packet = b"".join(pieces)
            if len(packet) >= VIRTIO_NET_HDR_SIZE:
                packet = packet[VIRTIO_NET_HDR_SIZE:]
            self.backend.send(packet)
            return sum(len(p) for p in pieces)
        return 0


@dataclass
class MmioMachine:
    bus: MmioBus
    interrupt_controller: MmioInterruptController
    uart: UartSerialDevice
    rtc: RtcDevice
    block: Optional[VirtioBlockDevice]
    net: Optional[VirtioNetDevice]
    framebuffer: Optional[FramebufferDevice] = None

    def attach_to_vm(self, vm: object) -> "MmioMachine":
        vm.attach_mmio_bus(self.bus)
        return self


def build_default_mmio_machine(
    *,
    block_backend: Optional[Union[HostBlockImage, MemoryBlockImage]] = None,
    net_backend: Optional[InMemoryNetBackend] = None,
    uart_output: Optional[object] = None,
    uart_input: Union[bytes, bytearray, memoryview] = b"",
    rtc_ns: Optional[Callable[[], int]] = None,
    framebuffer: bool = False,
    framebuffer_width: int = 640,
    framebuffer_height: int = 480,
) -> MmioMachine:
    ic = MmioInterruptController()
    bus = MmioBus()
    uart = UartSerialDevice(
        irq_controller=ic,
        irq=SVM_IRQ_UART0,
        output=uart_output,
        input_bytes=uart_input,
    )
    rtc = RtcDevice(rtc_ns)
    block = (
        VirtioBlockDevice(block_backend, irq_controller=ic, irq=SVM_IRQ_VIRTIO_BLK0)
        if block_backend is not None
        else None
    )
    net = (
        VirtioNetDevice(net_backend, irq_controller=ic, irq=SVM_IRQ_VIRTIO_NET0)
        if net_backend is not None
        else None
    )
    fb = (
        FramebufferDevice(framebuffer_width, framebuffer_height)
        if framebuffer
        else None
    )

    bus.add_region(SVM_MMIO_IC_BASE, SVM_MMIO_WINDOW_SIZE, ic, "interrupt-controller")
    bus.add_region(SVM_MMIO_UART0_BASE, SVM_MMIO_WINDOW_SIZE, uart, "uart0")
    bus.add_region(SVM_MMIO_RTC_BASE, SVM_MMIO_WINDOW_SIZE, rtc, "rtc")
    if block is not None:
        bus.add_region(SVM_MMIO_VIRTIO_BLK0_BASE, SVM_MMIO_WINDOW_SIZE, block, "virtio-blk0")
    if net is not None:
        bus.add_region(SVM_MMIO_VIRTIO_NET0_BASE, SVM_MMIO_WINDOW_SIZE, net, "virtio-net0")
    if fb is not None:
        bus.add_region(
            SVM_MMIO_FRAMEBUFFER0_BASE,
            SVM_MMIO_WINDOW_SIZE,
            fb,
            "framebuffer0",
        )
        bus.add_region(
            fb.pixel_base,
            fb.pixel_size,
            fb.pixel_device,
            "framebuffer0-pixels",
        )
    return MmioMachine(bus, ic, uart, rtc, block, net, fb)
