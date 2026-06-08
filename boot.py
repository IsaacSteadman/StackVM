"""StackVM boot protocol + kernel launch path (Workstream D1).

This is the kernel-boot counterpart of the user-program argv path in
``runner.add_cmd_argv_vm`` / ``runner.run_in_vm``.  Where the user path pushes
``argc``/``argv`` for ``main()``, the *boot* path:

  1. lays a ``struct StartupData`` (and its sub-tables: the physical memory map,
     kernel command line, devicetree/boot-params blob and initramfs) out in
     physical memory,
  2. points the boot-pointer system register ``SVSR_SDP`` (0x02) at it, and
  3. enters a freestanding kernel image (``vmlinux``) in **kernel mode** with the
     **MMU off**, with a kernel stack at the top of RAM.

The in-memory layout mirrors ``StackVM/include/stackvm_boot.h`` byte-for-byte;
the two must be kept in sync.  ``read_startup_data`` parses the structure back
out of VM memory (used by consumers and the test-suite to validate a boot).

Memory layout produced by :func:`boot_kernel` (ascending physical address)::

    [0, kernel_base)            SVMEM_RESERVED  (null guard / low memory)
    [kernel_base, kernel_end)   SVMEM_KERNEL    (the loaded kernel image)
    [.., initramfs_end)         SVMEM_INITRAMFS (optional)
    [.., bootdata_end)          SVMEM_BOOTDATA  (StartupData + sub-tables)
    [bootdata_end, vm_size)     SVMEM_RAM       (free RAM; the kernel stack lives
                                                 at the very top, growing down)

Every region is page aligned and the memory map covers ``[0, vm_size)`` with no
gaps.  Only the pure-Python ``PyStackVM`` backend is supported here; bringing the
C++ core to parity is tracked as D8.
"""

from __future__ import annotations

import struct as _struct
from dataclasses import dataclass, field
from typing import List, Optional, Union

# ---------------------------------------------------------------------------
# Boot-ABI constants (mirror StackVM/include/stackvm_boot.h)
# ---------------------------------------------------------------------------

# Little-endian encoding of the ASCII bytes b"SVMBOOT1".
SVSD_MAGIC = 0x31544F4F424D5653
SVSD_VERSION = 1

SVSD_FLAG_NONE = 0

# MemMapEntry.type values.
SVMEM_RAM = 1
SVMEM_RESERVED = 2
SVMEM_KERNEL = 3
SVMEM_INITRAMFS = 4
SVMEM_BOOTDATA = 5

# struct StartupData / struct MemMapEntry binary layouts.  "<" => little-endian,
# tightly packed (matches the natural layout of the all-8/4-byte C structs).
_SD_FORMAT = "<QIIQQQQQQQQQQQ"
STARTUP_DATA_SIZE = _struct.calcsize(_SD_FORMAT)  # 104
_MM_FORMAT = "<QQII"
MEM_MAP_ENTRY_SIZE = _struct.calcsize(_MM_FORMAT)  # 24

# Page size used to align the boot regions (the kernel boots with the MMU off,
# but page-aligning keeps the layout compatible with later paging set-up).
BOOT_PAGE_SIZE = 4096

_U64_MASK = (1 << 64) - 1


def _align_up(value: int, align: int) -> int:
    return (value + align - 1) & ~(align - 1)


# ---------------------------------------------------------------------------
# Parsed/return types
# ---------------------------------------------------------------------------


@dataclass
class MemMapEntry:
    """One physical memory region (mirrors ``struct MemMapEntry``)."""

    base: int
    size: int
    type: int
    reserved: int = 0

    @property
    def end(self) -> int:
        return self.base + self.size


@dataclass
class StartupData:
    """Parsed view of ``struct StartupData`` plus its resolved sub-tables."""

    magic: int
    version: int
    flags: int
    struct_size: int
    core_count: int
    boot_core_id: int
    mem_map_ptr: int
    mem_map_count: int
    initramfs_base: int
    initramfs_size: int
    cmdline_ptr: int
    cmdline_size: int
    dtb_ptr: int
    dtb_size: int
    mem_map: List[MemMapEntry] = field(default_factory=list)
    cmdline: Optional[bytes] = None
    dtb: Optional[bytes] = None

    @property
    def is_valid(self) -> bool:
        return self.magic == SVSD_MAGIC and self.struct_size >= STARTUP_DATA_SIZE


@dataclass
class BootImage:
    """The chosen physical layout of a boot, returned by :func:`build_boot_image`."""

    vm_size: int
    kernel_base: int
    kernel_end: int
    initramfs_base: int
    initramfs_size: int
    bootdata_base: int
    bootdata_end: int
    startup_data_addr: int
    mem_map: List[MemMapEntry]
    cmdline_bytes: bytes
    dtb_bytes: bytes
    core_count: int
    boot_core_id: int


# ---------------------------------------------------------------------------
# Memory-map composition
# ---------------------------------------------------------------------------


def _compose_mem_map(
    vm_size: int, reserved: List[MemMapEntry]
) -> List[MemMapEntry]:
    """Cover ``[0, vm_size)`` exactly once, filling gaps between *reserved*
    regions with SVMEM_RAM.  *reserved* must be non-overlapping; it is sorted
    here by base address."""
    ordered = sorted(reserved, key=lambda e: e.base)
    out: List[MemMapEntry] = []
    cursor = 0
    for region in ordered:
        if region.size == 0:
            continue
        if region.base < cursor:
            raise ValueError(
                "reserved boot regions overlap: %#x < %#x" % (region.base, cursor)
            )
        if region.base > cursor:
            out.append(MemMapEntry(cursor, region.base - cursor, SVMEM_RAM))
        out.append(MemMapEntry(region.base, region.size, region.type))
        cursor = region.end
    if cursor > vm_size:
        raise ValueError(
            "boot regions exceed VM memory: %#x > %#x" % (cursor, vm_size)
        )
    if cursor < vm_size:
        out.append(MemMapEntry(cursor, vm_size - cursor, SVMEM_RAM))
    return out


# ---------------------------------------------------------------------------
# Layout planning + population
# ---------------------------------------------------------------------------


def build_boot_image(
    vm_size: int,
    kernel_len: int,
    *,
    kernel_base: int = BOOT_PAGE_SIZE,
    cmdline: Union[str, bytes] = "",
    initramfs: bytes = b"",
    dtb: bytes = b"",
    core_count: int = 1,
    boot_core_id: int = 0,
) -> BootImage:
    """Plan the physical layout for a boot without touching VM memory.

    The command line is always materialised as a NUL-terminated string (so the
    kernel always receives a valid ``cmdline`` pointer, possibly to an empty
    string).  ``initramfs``/``dtb`` are optional; absent ones get a NULL pointer
    and a zero size in StartupData.
    """
    if kernel_base % BOOT_PAGE_SIZE != 0:
        raise ValueError("kernel_base must be page aligned")
    if core_count < 1:
        raise ValueError("core_count must be >= 1")

    if isinstance(cmdline, str):
        cmdline_bytes = cmdline.encode("utf-8") + b"\0"
    else:
        cmdline_bytes = bytes(cmdline)
        if not cmdline_bytes.endswith(b"\0"):
            cmdline_bytes += b"\0"

    kernel_end = _align_up(kernel_base + kernel_len, BOOT_PAGE_SIZE)

    if initramfs:
        initramfs_base = kernel_end
        initramfs_end = _align_up(initramfs_base + len(initramfs), BOOT_PAGE_SIZE)
    else:
        initramfs_base = 0
        initramfs_end = kernel_end

    bootdata_base = initramfs_end

    # The number of memory-map entries is bounded by the regions we carve out
    # (low-reserved, kernel, initramfs, bootdata) plus the trailing free RAM.
    # Sizing the bootdata region with this upper bound guarantees the real map
    # (which never has more entries) fits, regardless of trailing-RAM presence.
    max_entries = 2  # bootdata + (at least one of: trailing RAM / kernel)
    if kernel_base > 0:
        max_entries += 1  # low reserved
    max_entries += 1  # kernel
    if initramfs:
        max_entries += 1  # initramfs
    bootdata_size = (
        STARTUP_DATA_SIZE
        + max_entries * MEM_MAP_ENTRY_SIZE
        + len(cmdline_bytes)
        + len(dtb)
    )
    bootdata_end = _align_up(bootdata_base + bootdata_size, BOOT_PAGE_SIZE)
    if bootdata_end > vm_size:
        raise ValueError(
            "VM memory too small for boot image: need %#x, have %#x"
            % (bootdata_end, vm_size)
        )

    reserved: List[MemMapEntry] = []
    if kernel_base > 0:
        reserved.append(MemMapEntry(0, kernel_base, SVMEM_RESERVED))
    reserved.append(MemMapEntry(kernel_base, kernel_end - kernel_base, SVMEM_KERNEL))
    if initramfs:
        reserved.append(
            MemMapEntry(initramfs_base, initramfs_end - initramfs_base, SVMEM_INITRAMFS)
        )
    reserved.append(
        MemMapEntry(bootdata_base, bootdata_end - bootdata_base, SVMEM_BOOTDATA)
    )
    mem_map = _compose_mem_map(vm_size, reserved)

    return BootImage(
        vm_size=vm_size,
        kernel_base=kernel_base,
        kernel_end=kernel_end,
        initramfs_base=initramfs_base,
        initramfs_size=len(initramfs) if initramfs else 0,
        bootdata_base=bootdata_base,
        bootdata_end=bootdata_end,
        startup_data_addr=bootdata_base,
        mem_map=mem_map,
        cmdline_bytes=cmdline_bytes,
        dtb_bytes=bytes(dtb),
        core_count=core_count,
        boot_core_id=boot_core_id,
    )


def populate_startup_data(
    memory: bytearray,
    image: BootImage,
    *,
    initramfs: bytes = b"",
) -> int:
    """Write StartupData and its sub-tables into *memory* per *image*.

    The kernel image and initramfs payloads themselves are written by the
    caller; this writes the bootdata region (StartupData struct, memory-map
    array, command line, devicetree blob) and the initramfs (when provided here
    for convenience).  Returns the StartupData address.
    """
    if initramfs:
        memory[image.initramfs_base : image.initramfs_base + len(initramfs)] = initramfs

    # bootdata sub-table addresses, laid out immediately after the struct.
    mem_map_addr = image.bootdata_base + STARTUP_DATA_SIZE
    cmdline_addr = mem_map_addr + len(image.mem_map) * MEM_MAP_ENTRY_SIZE
    dtb_addr = cmdline_addr + len(image.cmdline_bytes)
    dtb_end = dtb_addr + len(image.dtb_bytes)
    if dtb_end > image.bootdata_end:
        raise ValueError("bootdata sub-tables overflow the bootdata region")

    # Memory map.
    for i, entry in enumerate(image.mem_map):
        _struct.pack_into(
            _MM_FORMAT,
            memory,
            mem_map_addr + i * MEM_MAP_ENTRY_SIZE,
            entry.base & _U64_MASK,
            entry.size & _U64_MASK,
            entry.type & 0xFFFFFFFF,
            0,
        )

    # Command line (always present, NUL-terminated).
    memory[cmdline_addr : cmdline_addr + len(image.cmdline_bytes)] = image.cmdline_bytes

    # Devicetree / boot-params blob (optional).
    if image.dtb_bytes:
        memory[dtb_addr : dtb_addr + len(image.dtb_bytes)] = image.dtb_bytes

    # StartupData struct itself.
    _struct.pack_into(
        _SD_FORMAT,
        memory,
        image.startup_data_addr,
        SVSD_MAGIC,
        SVSD_VERSION,
        SVSD_FLAG_NONE,
        STARTUP_DATA_SIZE,
        image.core_count,
        image.boot_core_id,
        mem_map_addr,
        len(image.mem_map),
        image.initramfs_base,
        image.initramfs_size,
        cmdline_addr,
        len(image.cmdline_bytes),
        dtb_addr if image.dtb_bytes else 0,
        len(image.dtb_bytes),
    )
    return image.startup_data_addr


def read_startup_data(
    memory: Union[bytearray, bytes, memoryview], addr: int
) -> StartupData:
    """Parse a ``struct StartupData`` (and its sub-tables) out of *memory*."""
    fields = _struct.unpack_from(_SD_FORMAT, memory, addr)
    sd = StartupData(
        magic=fields[0],
        version=fields[1],
        flags=fields[2],
        struct_size=fields[3],
        core_count=fields[4],
        boot_core_id=fields[5],
        mem_map_ptr=fields[6],
        mem_map_count=fields[7],
        initramfs_base=fields[8],
        initramfs_size=fields[9],
        cmdline_ptr=fields[10],
        cmdline_size=fields[11],
        dtb_ptr=fields[12],
        dtb_size=fields[13],
    )
    for i in range(sd.mem_map_count):
        base, size, typ, _res = _struct.unpack_from(
            _MM_FORMAT, memory, sd.mem_map_ptr + i * MEM_MAP_ENTRY_SIZE
        )
        sd.mem_map.append(MemMapEntry(base, size, typ))
    if sd.cmdline_ptr and sd.cmdline_size:
        raw = bytes(memory[sd.cmdline_ptr : sd.cmdline_ptr + sd.cmdline_size])
        sd.cmdline = raw.split(b"\0", 1)[0]
    if sd.dtb_ptr and sd.dtb_size:
        sd.dtb = bytes(memory[sd.dtb_ptr : sd.dtb_ptr + sd.dtb_size])
    return sd


# ---------------------------------------------------------------------------
# Kernel launch path
# ---------------------------------------------------------------------------


def boot_kernel(
    kernel_image: Union[bytes, bytearray],
    *,
    vm_size: int = 1 << 20,
    kernel_base: int = BOOT_PAGE_SIZE,
    cmdline: Union[str, bytes] = "",
    initramfs: bytes = b"",
    dtb: bytes = b"",
    core_count: int = 1,
    boot_core_id: int = 0,
    backend: str = "python",
):
    """Create a VM, install *kernel_image* + StartupData, and prepare to boot.

    Returns ``(vm, image)`` with the VM halted at the kernel entry point in
    kernel mode (priv 0), MMU off, ``SVSR_SDP`` pointing at the StartupData and a
    kernel stack at the top of RAM.  The caller runs it (``vm.execute()`` or via
    the debugger).  Only the Python backend is supported (C++ parity = D8).
    """
    if backend != "python":
        raise NotImplementedError(
            "boot_kernel only supports the 'python' backend; C++ boot/SMP parity "
            "is tracked as workstream D8"
        )

    from .PyStackVM import (
        VM_DISABLED,
        SVSR_CORE_ID,
        SVSR_FLAGS,
        SVSR_KERNEL_BP,
        SVSR_KERNEL_SP,
        SVSR_SDP,
        VirtualMachine,
    )

    kernel_image = bytes(kernel_image)
    image = build_boot_image(
        vm_size,
        len(kernel_image),
        kernel_base=kernel_base,
        cmdline=cmdline,
        initramfs=initramfs,
        dtb=dtb,
        core_count=core_count,
        boot_core_id=boot_core_id,
    )

    vm = VirtualMachine(vm_size, 0)
    if len(vm.memory) < vm_size:
        # Defensive: ensure the full physical address space is backed.
        vm.memory.extend(b"\0" * (vm_size - len(vm.memory)))

    # MMU off => physical == virtual; write payloads straight into memory.
    vm.memory[kernel_base : kernel_base + len(kernel_image)] = kernel_image
    populate_startup_data(vm.memory, image, initramfs=initramfs)

    # Enter the kernel: kernel privilege, MMU off, interrupts disabled, SDP set,
    # entry at the start of the image, kernel stack at the top of RAM.
    vm.priv_lvl = 0
    vm.virt_mem_mode = VM_DISABLED
    vm.priority = 255
    vm.sys_regs[SVSR_FLAGS] = vm.priority | (vm.priv_lvl << 8)
    vm.sys_regs[SVSR_SDP] = image.startup_data_addr
    vm.sys_regs[SVSR_CORE_ID] = boot_core_id
    vm.sys_regs[SVSR_KERNEL_SP] = vm_size
    vm.sys_regs[SVSR_KERNEL_BP] = vm_size
    vm.ip = kernel_base
    vm.sp = vm_size
    vm.bp = vm_size
    return vm, image


def run_boot_in_vm(
    kernel_image: Union[bytes, bytearray],
    *,
    vm_size: int = 1 << 20,
    kernel_base: int = BOOT_PAGE_SIZE,
    cmdline: Union[str, bytes] = "",
    initramfs: bytes = b"",
    dtb: bytes = b"",
    core_count: int = 1,
    use_debugger: bool = False,
    syscall_sets: Optional[List[str]] = None,
):
    """Boot a kernel image and run it (or launch the debugger).

    Mirrors :func:`runner.run_in_vm` for the kernel-boot path.
    """
    vm, image = boot_kernel(
        kernel_image,
        vm_size=vm_size,
        kernel_base=kernel_base,
        cmdline=cmdline,
        initramfs=initramfs,
        dtb=dtb,
        core_count=core_count,
    )

    if syscall_sets:
        from .syscalls import build_dispatcher

        build_dispatcher(syscall_sets).attach_to_py_vm(vm)

    if use_debugger:
        from .runner import _load_debugger

        Debugger = _load_debugger()
        if Debugger is None:
            print(
                "Warning: Debugger class not available in standalone mode; "
                "falling back to execute()."
            )
            vm.execute()
        else:
            Debugger(vm, image.kernel_base, image.kernel_end, {}).debug()
    else:
        vm.execute()
    return vm, image
