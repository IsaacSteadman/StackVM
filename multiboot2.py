"""Multiboot2 boot protocol for StackVM (Workstream D1b.5).

This is the *standardized-boot* counterpart to the bespoke D1 ``StartupData``
handoff: it lets a stock **Multiboot2** kernel image (the format GRUB hands off
to) boot on StackVM.  A Multiboot2 kernel carries a small header in its first
32 KiB describing how it wants to be loaded; the bootloader (here, the emulator
acting as firmware) parses that header, lays the kernel + modules out in
physical memory, builds the **Multiboot2 information** (MBI) structure (memory
map, command line, modules, framebuffer, EFI tables, …), and enters the kernel
with the Multiboot2 *bootloader magic*.

StackVM has no general-purpose registers, so the x86 ``eax = magic; ebx = mbi``
convention is mapped onto the native StackVM handoff:

* the kernel is entered in **kernel mode (priv 0) with the MMU off**, interrupts
  disabled, and a stack at the top of RAM (exactly like :func:`boot.boot_kernel`);
* the **bootloader magic** (:data:`MULTIBOOT2_BOOTLOADER_MAGIC`) and the **MBI
  physical address** are delivered both
  - on the stack as the two native C-ABI arguments of ``kmain(magic, mbi)``
    (magic at ``sp``, mbi at ``sp+8`` — the same layout the UEFI entry uses), and
  - in the read-only interrupt-argument system registers ``SVSR_INT_ARG0`` /
    ``SVSR_INT_ARG1`` for a register-style read.

The byte layout of every header/MBI tag follows the Multiboot2 specification
field-for-field so an unmodified GRUB-built kernel sees what it expects.
"""

from __future__ import annotations

import struct as _struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Union

from .boot import (
    BOOT_PAGE_SIZE,
    MemMapEntry,
    SVMEM_RAM,
    _align_up,
    _compose_mem_map,
)

# ---------------------------------------------------------------------------
# Multiboot2 constants (mirror the Multiboot2 specification)
# ---------------------------------------------------------------------------

#: Magic the kernel image's header begins with.
MULTIBOOT2_HEADER_MAGIC = 0xE85250D6
#: Magic the bootloader passes to the kernel at entry (x86 would put it in eax).
MULTIBOOT2_BOOTLOADER_MAGIC = 0x36D76289

#: Architectures (header field).
MULTIBOOT_ARCHITECTURE_I386 = 0
MULTIBOOT_ARCHITECTURE_MIPS32 = 4

#: Header tag types.
MULTIBOOT_HEADER_TAG_END = 0
MULTIBOOT_HEADER_TAG_INFORMATION_REQUEST = 1
MULTIBOOT_HEADER_TAG_ADDRESS = 2
MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS = 3
MULTIBOOT_HEADER_TAG_CONSOLE_FLAGS = 4
MULTIBOOT_HEADER_TAG_FRAMEBUFFER = 5
MULTIBOOT_HEADER_TAG_MODULE_ALIGN = 6
MULTIBOOT_HEADER_TAG_EFI_BS = 7
MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS_EFI32 = 8
MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS_EFI64 = 9
MULTIBOOT_HEADER_TAG_RELOCATABLE = 10

MULTIBOOT_HEADER_TAG_OPTIONAL = 1  # flag bit: tag is optional

#: MBI (boot information) tag types.
MULTIBOOT_TAG_TYPE_END = 0
MULTIBOOT_TAG_TYPE_CMDLINE = 1
MULTIBOOT_TAG_TYPE_BOOT_LOADER_NAME = 2
MULTIBOOT_TAG_TYPE_MODULE = 3
MULTIBOOT_TAG_TYPE_BASIC_MEMINFO = 4
MULTIBOOT_TAG_TYPE_BOOTDEV = 5
MULTIBOOT_TAG_TYPE_MMAP = 6
MULTIBOOT_TAG_TYPE_VBE = 7
MULTIBOOT_TAG_TYPE_FRAMEBUFFER = 8
MULTIBOOT_TAG_TYPE_ELF_SECTIONS = 9
MULTIBOOT_TAG_TYPE_APM = 10
MULTIBOOT_TAG_TYPE_EFI32 = 11
MULTIBOOT_TAG_TYPE_EFI64 = 12
MULTIBOOT_TAG_TYPE_ACPI_OLD = 14
MULTIBOOT_TAG_TYPE_ACPI_NEW = 15
MULTIBOOT_TAG_TYPE_EFI_MMAP = 17
MULTIBOOT_TAG_TYPE_EFI_BS = 18
MULTIBOOT_TAG_TYPE_EFI32_IH = 19
MULTIBOOT_TAG_TYPE_EFI64_IH = 20
MULTIBOOT_TAG_TYPE_LOAD_BASE_ADDR = 21

#: Multiboot2 memory-map entry types.
MULTIBOOT_MEMORY_AVAILABLE = 1
MULTIBOOT_MEMORY_RESERVED = 2
MULTIBOOT_MEMORY_ACPI_RECLAIMABLE = 3
MULTIBOOT_MEMORY_NVS = 4
MULTIBOOT_MEMORY_BADRAM = 5

#: Framebuffer types.
MULTIBOOT_FRAMEBUFFER_TYPE_INDEXED = 0
MULTIBOOT_FRAMEBUFFER_TYPE_RGB = 1
MULTIBOOT_FRAMEBUFFER_TYPE_EGA_TEXT = 2

_U32_MASK = 0xFFFFFFFF
_U64_MASK = (1 << 64) - 1

_HEADER_STRUCT = _struct.Struct("<IIII")  # magic, architecture, length, checksum
_TAG_STRUCT = _struct.Struct("<HHI")  # header tag: type, flags, size
_MBI_TAG_STRUCT = _struct.Struct("<II")  # mbi tag: type, size


def _align8(value: int) -> int:
    return (value + 7) & ~7


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------


@dataclass
class Multiboot2AddressTag:
    header_addr: int
    load_addr: int
    load_end_addr: int
    bss_end_addr: int


@dataclass
class Multiboot2Header:
    """Parsed Multiboot2 header found in a kernel image."""

    magic: int
    architecture: int
    header_length: int
    checksum: int
    header_offset: int
    information_request: List[int] = field(default_factory=list)
    address: Optional[Multiboot2AddressTag] = None
    entry_addr: Optional[int] = None
    console_flags: Optional[int] = None
    framebuffer: Optional[Tuple[int, int, int]] = None
    module_align: bool = False
    efi_boot_services: bool = False
    relocatable: Optional[Tuple[int, int, int, int]] = None

    @property
    def checksum_valid(self) -> bool:
        total = (
            self.magic + self.architecture + self.header_length + self.checksum
        ) & _U32_MASK
        return total == 0


def parse_multiboot2_header(
    image: Union[bytes, bytearray, memoryview], *, search_limit: int = 32768
) -> Optional[Multiboot2Header]:
    """Scan the first *search_limit* bytes of *image* for a Multiboot2 header.

    The header must be 8-byte aligned within the first 32 KiB and its checksum
    must be valid (per spec).  Returns the parsed :class:`Multiboot2Header`, or
    ``None`` when the image is not Multiboot2.
    """
    data = bytes(image)
    limit = min(len(data) - _HEADER_STRUCT.size, search_limit)
    for offset in range(0, limit + 1, 8):
        magic = _struct.unpack_from("<I", data, offset)[0]
        if magic != MULTIBOOT2_HEADER_MAGIC:
            continue
        magic, arch, length, checksum = _HEADER_STRUCT.unpack_from(data, offset)
        if (magic + arch + length + checksum) & _U32_MASK != 0:
            continue
        if offset + length > len(data):
            continue
        header = Multiboot2Header(
            magic=magic,
            architecture=arch,
            header_length=length,
            checksum=checksum,
            header_offset=offset,
        )
        _parse_header_tags(data, offset + _HEADER_STRUCT.size, offset + length, header)
        return header
    return None


def _parse_header_tags(data: bytes, start: int, end: int, header: Multiboot2Header) -> None:
    pos = start
    while pos + _TAG_STRUCT.size <= end:
        tag_type, tag_flags, tag_size = _TAG_STRUCT.unpack_from(data, pos)
        if tag_size < _TAG_STRUCT.size:
            break
        body = data[pos + _TAG_STRUCT.size : pos + tag_size]
        if tag_type == MULTIBOOT_HEADER_TAG_END:
            break
        elif tag_type == MULTIBOOT_HEADER_TAG_INFORMATION_REQUEST:
            count = len(body) // 4
            header.information_request = list(_struct.unpack_from("<%dI" % count, body, 0)) if count else []
        elif tag_type == MULTIBOOT_HEADER_TAG_ADDRESS:
            ha, la, lea, bea = _struct.unpack_from("<IIII", body, 0)
            header.address = Multiboot2AddressTag(ha, la, lea, bea)
        elif tag_type == MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS:
            header.entry_addr = _struct.unpack_from("<I", body, 0)[0]
        elif tag_type == MULTIBOOT_HEADER_TAG_CONSOLE_FLAGS:
            header.console_flags = _struct.unpack_from("<I", body, 0)[0]
        elif tag_type == MULTIBOOT_HEADER_TAG_FRAMEBUFFER:
            header.framebuffer = _struct.unpack_from("<III", body, 0)
        elif tag_type == MULTIBOOT_HEADER_TAG_MODULE_ALIGN:
            header.module_align = True
        elif tag_type == MULTIBOOT_HEADER_TAG_EFI_BS:
            header.efi_boot_services = True
        elif tag_type == MULTIBOOT_HEADER_TAG_RELOCATABLE:
            header.relocatable = _struct.unpack_from("<IIII", body, 0)
        pos += _align8(tag_size)


# ---------------------------------------------------------------------------
# Boot-information (MBI) construction
# ---------------------------------------------------------------------------


@dataclass
class Multiboot2Module:
    start: int
    end: int
    string: str = ""


class Multiboot2InfoBuilder:
    """Assemble a Multiboot2 information (MBI) blob tag-by-tag."""

    def __init__(self) -> None:
        self._tags: List[bytes] = []

    def _add(self, tag_type: int, body: bytes) -> None:
        size = _MBI_TAG_STRUCT.size + len(body)
        tag = _MBI_TAG_STRUCT.pack(tag_type, size) + body
        tag += b"\0" * (_align8(size) - size)
        self._tags.append(tag)

    def add_cmdline(self, cmdline: str) -> None:
        self._add(MULTIBOOT_TAG_TYPE_CMDLINE, cmdline.encode("utf-8") + b"\0")

    def add_bootloader_name(self, name: str) -> None:
        self._add(MULTIBOOT_TAG_TYPE_BOOT_LOADER_NAME, name.encode("utf-8") + b"\0")

    def add_module(self, module: Multiboot2Module) -> None:
        body = _struct.pack(
            "<II", module.start & _U32_MASK, module.end & _U32_MASK
        ) + module.string.encode("utf-8") + b"\0"
        self._add(MULTIBOOT_TAG_TYPE_MODULE, body)

    def add_basic_meminfo(self, mem_lower_kb: int, mem_upper_kb: int) -> None:
        self._add(
            MULTIBOOT_TAG_TYPE_BASIC_MEMINFO,
            _struct.pack("<II", mem_lower_kb & _U32_MASK, mem_upper_kb & _U32_MASK),
        )

    def add_memory_map(self, entries: List[Tuple[int, int, int]]) -> None:
        entry_size = 24
        entry_version = 0
        body = _struct.pack("<II", entry_size, entry_version)
        for base, length, typ in entries:
            body += _struct.pack(
                "<QQII", base & _U64_MASK, length & _U64_MASK, typ & _U32_MASK, 0
            )
        self._add(MULTIBOOT_TAG_TYPE_MMAP, body)

    def add_framebuffer(
        self,
        addr: int,
        pitch: int,
        width: int,
        height: int,
        bpp: int,
        fb_type: int = MULTIBOOT_FRAMEBUFFER_TYPE_RGB,
    ) -> None:
        body = _struct.pack(
            "<QIIIBBH",
            addr & _U64_MASK,
            pitch & _U32_MASK,
            width & _U32_MASK,
            height & _U32_MASK,
            bpp & 0xFF,
            fb_type & 0xFF,
            0,
        )
        # XRGB8888 colour-info: 8/8/8 at 16/8/0 (+ 1 reserved byte for alignment).
        body += _struct.pack("<BBBBBB", 0, 16, 8, 8, 8, 0)[:6]
        self._add(MULTIBOOT_TAG_TYPE_FRAMEBUFFER, body)

    def add_efi64_system_table(self, addr: int) -> None:
        self._add(MULTIBOOT_TAG_TYPE_EFI64, _struct.pack("<Q", addr & _U64_MASK))

    def add_efi64_image_handle(self, handle: int) -> None:
        self._add(MULTIBOOT_TAG_TYPE_EFI64_IH, _struct.pack("<Q", handle & _U64_MASK))

    def add_load_base_addr(self, addr: int) -> None:
        self._add(MULTIBOOT_TAG_TYPE_LOAD_BASE_ADDR, _struct.pack("<I", addr & _U32_MASK))

    def build(self) -> bytes:
        body = b"".join(self._tags)
        # End tag.
        body += _MBI_TAG_STRUCT.pack(MULTIBOOT_TAG_TYPE_END, _MBI_TAG_STRUCT.size)
        total_size = _align8(8 + len(body))
        blob = _struct.pack("<II", total_size, 0) + body
        blob += b"\0" * (total_size - len(blob))
        return blob


def _mb2_type_for(svmem_type: int) -> int:
    return MULTIBOOT_MEMORY_AVAILABLE if svmem_type == SVMEM_RAM else MULTIBOOT_MEMORY_RESERVED


# ---------------------------------------------------------------------------
# Layout + launch
# ---------------------------------------------------------------------------


@dataclass
class Multiboot2Image:
    """The chosen physical layout of a Multiboot2 boot."""

    vm_size: int
    load_base: int
    kernel_end: int
    module_base: int
    module_size: int
    mbi_base: int
    mbi_end: int
    entry: int
    mem_map: List[MemMapEntry]
    mbi_bytes: bytes


def plan_multiboot2_image(
    kernel_image: Union[bytes, bytearray],
    *,
    vm_size: int = 1 << 20,
    load_base: int = 0x100000,
    cmdline: str = "",
    modules: Optional[List[Tuple[bytes, str]]] = None,
    bootloader_name: str = "StackVM Multiboot2",
    efi_system_table: Optional[int] = None,
    efi_image_handle: Optional[int] = None,
    framebuffer: Optional[Tuple[int, int, int, int, int]] = None,
) -> Multiboot2Image:
    """Plan a Multiboot2 physical layout and build the MBI without touching a VM.

    *modules* is a list of ``(payload, string)`` (the first is typically the
    initramfs).  *framebuffer* is ``(addr, pitch, width, height, bpp)``.
    """
    if load_base % BOOT_PAGE_SIZE != 0:
        raise ValueError("load_base must be page aligned")
    header = parse_multiboot2_header(kernel_image)
    if header is None:
        raise ValueError("image is not a Multiboot2 kernel (no valid header found)")

    kernel_image = bytes(kernel_image)
    kernel_end = _align_up(load_base + len(kernel_image), BOOT_PAGE_SIZE)

    modules = modules or []
    module_records: List[Multiboot2Module] = []
    cursor = kernel_end
    first_module_base = kernel_end
    first_module_size = 0
    for index, (payload, string) in enumerate(modules):
        start = cursor
        end = start + len(payload)
        module_records.append(Multiboot2Module(start, end, string))
        if index == 0:
            first_module_base = start
            first_module_size = len(payload)
        cursor = _align_up(end, BOOT_PAGE_SIZE)
    mbi_base = cursor

    entry = header.entry_addr if header.entry_addr is not None else load_base

    def build(mbi_region_size: int) -> bytes:
        reserved = [MemMapEntry(0, load_base, 2)] if load_base > 0 else []
        reserved.append(MemMapEntry(load_base, kernel_end - load_base, 3))  # SVMEM_KERNEL
        for rec in module_records:
            reserved.append(
                MemMapEntry(rec.start, _align_up(rec.end, BOOT_PAGE_SIZE) - rec.start, 4)
            )
        if mbi_region_size:
            reserved.append(MemMapEntry(mbi_base, mbi_region_size, 5))  # SVMEM_BOOTDATA
        mem_map = _compose_mem_map(vm_size, reserved)

        builder = Multiboot2InfoBuilder()
        builder.add_bootloader_name(bootloader_name)
        builder.add_cmdline(cmdline)
        mem_lower = min(640, vm_size // 1024)
        mem_upper = max(0, (vm_size - 0x100000) // 1024)
        builder.add_basic_meminfo(mem_lower, mem_upper)
        builder.add_memory_map(
            [(e.base, e.size, _mb2_type_for(e.type)) for e in mem_map]
        )
        for rec in module_records:
            builder.add_module(rec)
        if framebuffer is not None:
            fb_addr, pitch, width, height, bpp = framebuffer
            builder.add_framebuffer(fb_addr, pitch, width, height, bpp)
        if efi_system_table is not None:
            builder.add_efi64_system_table(efi_system_table)
        if efi_image_handle is not None:
            builder.add_efi64_image_handle(efi_image_handle)
        builder.add_load_base_addr(load_base)
        return builder.build(), mem_map

    # First pass with an empty MBI region to size the blob, then reserve a
    # page-aligned region with slack and rebuild so the embedded memory map
    # describes exactly the region the MBI ships in.
    provisional, _ = build(0)
    mbi_region_size = _align_up(len(provisional) + 256, BOOT_PAGE_SIZE)
    mbi_bytes, mem_map = build(mbi_region_size)
    if len(mbi_bytes) > mbi_region_size:  # pragma: no cover - slack guards this
        mbi_region_size = _align_up(len(mbi_bytes) + 256, BOOT_PAGE_SIZE)
        mbi_bytes, mem_map = build(mbi_region_size)

    mbi_end = _align_up(mbi_base + mbi_region_size, BOOT_PAGE_SIZE)
    if mbi_end > vm_size:
        raise ValueError(
            "VM memory too small for Multiboot2 image: need %#x, have %#x"
            % (mbi_end, vm_size)
        )

    return Multiboot2Image(
        vm_size=vm_size,
        load_base=load_base,
        kernel_end=kernel_end,
        module_base=first_module_base,
        module_size=first_module_size,
        mbi_base=mbi_base,
        mbi_end=mbi_end,
        entry=entry,
        mem_map=mem_map,
        mbi_bytes=mbi_bytes,
    )


def boot_multiboot2(
    kernel_image: Union[bytes, bytearray],
    *,
    vm_size: int = 1 << 20,
    load_base: int = 0x100000,
    cmdline: str = "",
    modules: Optional[List[Tuple[bytes, str]]] = None,
    bootloader_name: str = "StackVM Multiboot2",
    efi_system_table: Optional[int] = None,
    efi_image_handle: Optional[int] = None,
    framebuffer: Optional[Tuple[int, int, int, int, int]] = None,
):
    """Load a Multiboot2 kernel + modules and prepare to enter it.

    Returns ``(vm, image)`` with the VM halted at the kernel entry point, in
    kernel mode (priv 0), MMU off, the Multiboot2 bootloader magic + MBI pointer
    delivered on the stack and in ``SVSR_INT_ARG0``/``SVSR_INT_ARG1`` (see the
    module docstring), and a kernel stack at the top of RAM.  The caller runs the
    VM (``vm.execute()``).
    """
    from .PyStackVM import (
        VM_DISABLED,
        SVSR_FLAGS,
        SVSR_INT_ARG0,
        SVSR_INT_ARG1,
        SVSR_KERNEL_BP,
        SVSR_KERNEL_SP,
        VirtualMachine,
    )

    image = plan_multiboot2_image(
        kernel_image,
        vm_size=vm_size,
        load_base=load_base,
        cmdline=cmdline,
        modules=modules,
        bootloader_name=bootloader_name,
        efi_system_table=efi_system_table,
        efi_image_handle=efi_image_handle,
        framebuffer=framebuffer,
    )

    kernel_image = bytes(kernel_image)
    vm = VirtualMachine(vm_size, 0)
    if len(vm.memory) < vm_size:
        vm.memory.extend(b"\0" * (vm_size - len(vm.memory)))

    vm.memory[load_base : load_base + len(kernel_image)] = kernel_image
    # Module payloads.
    cursor = image.kernel_end
    for payload, _string in (modules or []):
        vm.memory[cursor : cursor + len(payload)] = payload
        cursor = _align_up(cursor + len(payload), BOOT_PAGE_SIZE)
    # MBI blob.
    vm.memory[image.mbi_base : image.mbi_base + len(image.mbi_bytes)] = image.mbi_bytes

    flags = 255 | (0 << 8) | (VM_DISABLED << 10)
    vm.priv_lvl = 0
    vm.virt_mem_mode = VM_DISABLED
    vm.priority = 255
    vm.sys_regs[SVSR_FLAGS] = flags
    vm.sys_regs[SVSR_INT_ARG0] = MULTIBOOT2_BOOTLOADER_MAGIC
    vm.sys_regs[SVSR_INT_ARG1] = image.mbi_base
    vm.sys_regs[SVSR_KERNEL_SP] = vm_size
    vm.sys_regs[SVSR_KERNEL_BP] = vm_size
    vm.ip = image.entry
    vm.sp = vm_size
    vm.bp = vm_size
    # kmain(magic, mbi): magic at sp, mbi at sp+8 (native C-ABI argument order).
    vm.push(8, 0)  # return-address placeholder
    vm.push(8, image.mbi_base)
    vm.push(8, MULTIBOOT2_BOOTLOADER_MAGIC)
    return vm, image


def run_multiboot2_in_vm(
    kernel_image: Union[bytes, bytearray],
    **kwargs,
):
    """Boot a Multiboot2 kernel image and run it to completion."""
    vm, image = boot_multiboot2(kernel_image, **kwargs)
    vm.execute()
    return vm, image


# ---------------------------------------------------------------------------
# MBI reader (for consumers / tests)
# ---------------------------------------------------------------------------


def parse_multiboot2_info(memory: Union[bytes, bytearray, memoryview], addr: int) -> dict:
    """Parse a Multiboot2 information blob at *addr* into a dict keyed by tag."""
    total_size, _reserved = _struct.unpack_from("<II", memory, addr)
    out: dict = {"total_size": total_size, "modules": [], "tags": []}
    pos = addr + 8
    end = addr + total_size
    while pos + _MBI_TAG_STRUCT.size <= end:
        tag_type, tag_size = _MBI_TAG_STRUCT.unpack_from(memory, pos)
        if tag_type == MULTIBOOT_TAG_TYPE_END:
            break
        if tag_size < _MBI_TAG_STRUCT.size:
            break
        body = bytes(memory[pos + _MBI_TAG_STRUCT.size : pos + tag_size])
        out["tags"].append(tag_type)
        if tag_type == MULTIBOOT_TAG_TYPE_CMDLINE:
            out["cmdline"] = body.split(b"\0", 1)[0].decode("utf-8", "replace")
        elif tag_type == MULTIBOOT_TAG_TYPE_BOOT_LOADER_NAME:
            out["bootloader_name"] = body.split(b"\0", 1)[0].decode("utf-8", "replace")
        elif tag_type == MULTIBOOT_TAG_TYPE_BASIC_MEMINFO:
            lower, upper = _struct.unpack_from("<II", body, 0)
            out["basic_meminfo"] = (lower, upper)
        elif tag_type == MULTIBOOT_TAG_TYPE_MMAP:
            entry_size, _ver = _struct.unpack_from("<II", body, 0)
            entries = []
            off = 8
            while off + 24 <= len(body):
                base, length, typ, _res = _struct.unpack_from("<QQII", body, off)
                entries.append((base, length, typ))
                off += entry_size
            out["mmap"] = entries
        elif tag_type == MULTIBOOT_TAG_TYPE_MODULE:
            mod_start, mod_end = _struct.unpack_from("<II", body, 0)
            string = body[8:].split(b"\0", 1)[0].decode("utf-8", "replace")
            out["modules"].append((mod_start, mod_end, string))
        elif tag_type == MULTIBOOT_TAG_TYPE_FRAMEBUFFER:
            fb_addr, pitch, width, height, bpp, fb_type, _r = _struct.unpack_from(
                "<QIIIBBH", body, 0
            )
            out["framebuffer"] = (fb_addr, pitch, width, height, bpp, fb_type)
        elif tag_type == MULTIBOOT_TAG_TYPE_EFI64:
            out["efi64_system_table"] = _struct.unpack_from("<Q", body, 0)[0]
        elif tag_type == MULTIBOOT_TAG_TYPE_EFI64_IH:
            out["efi64_image_handle"] = _struct.unpack_from("<Q", body, 0)[0]
        elif tag_type == MULTIBOOT_TAG_TYPE_LOAD_BASE_ADDR:
            out["load_base_addr"] = _struct.unpack_from("<I", body, 0)[0]
        pos += _align8(tag_size)
    return out


def build_multiboot2_header(
    *,
    architecture: int = MULTIBOOT_ARCHITECTURE_I386,
    entry_addr: Optional[int] = None,
    information_request: Optional[List[int]] = None,
    request_framebuffer: Optional[Tuple[int, int, int]] = None,
    module_align: bool = False,
    request_efi_bs: bool = False,
) -> bytes:
    """Build a valid Multiboot2 header (handy for tests / freestanding kernels)."""
    tags = b""
    if information_request:
        body = _struct.pack("<%dI" % len(information_request), *information_request)
        size = _TAG_STRUCT.size + len(body)
        tag = _TAG_STRUCT.pack(MULTIBOOT_HEADER_TAG_INFORMATION_REQUEST, 0, size) + body
        tags += tag + b"\0" * (_align8(size) - size)
    if request_framebuffer is not None:
        w, h, d = request_framebuffer
        body = _struct.pack("<III", w, h, d)
        size = _TAG_STRUCT.size + len(body)
        tags += _TAG_STRUCT.pack(MULTIBOOT_HEADER_TAG_FRAMEBUFFER, 0, size) + body
        tags += b"\0" * (_align8(size) - size)
    if module_align:
        tags += _TAG_STRUCT.pack(MULTIBOOT_HEADER_TAG_MODULE_ALIGN, 0, _TAG_STRUCT.size)
    if request_efi_bs:
        tags += _TAG_STRUCT.pack(MULTIBOOT_HEADER_TAG_EFI_BS, 0, _TAG_STRUCT.size)
    if entry_addr is not None:
        body = _struct.pack("<I", entry_addr & _U32_MASK)
        size = _TAG_STRUCT.size + len(body)
        tags += _TAG_STRUCT.pack(MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS, 0, size) + body
        tags += b"\0" * (_align8(size) - size)
    # End tag.
    tags += _TAG_STRUCT.pack(MULTIBOOT_HEADER_TAG_END, 0, _TAG_STRUCT.size)

    header_length = _HEADER_STRUCT.size + len(tags)
    checksum = (-(MULTIBOOT2_HEADER_MAGIC + architecture + header_length)) & _U32_MASK
    return _HEADER_STRUCT.pack(
        MULTIBOOT2_HEADER_MAGIC, architecture, header_length, checksum
    ) + tags
