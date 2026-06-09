"""Minimal StackVM UEFI firmware model (D1b.3/D1b.4).

This module is the Python reference implementation of the custom firmware path:
it builds UEFI system/boot/runtime-service tables in guest memory, exposes a
small handle/protocol database backed by the existing StackVM devices, loads a
PE32+ EFI image, applies its base relocations, and enters the image at
``efi_main(ImageHandle, SystemTable)``.

The service methods are callable from the host test harness and future firmware
thunks can dispatch through ``call_service`` using the same service-pointer map.
"""

from __future__ import annotations

import base64
import datetime as _datetime
import json
import os
import struct
import time
import uuid
import zlib
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Tuple, Union

from ..code_gen.stackvm_binutils.executable_file import (
    StackVMExecutable,
    apply_base_fixups,
)
from ..code_gen.stackvm_binutils.pe_file import (
    IMAGE_SCN_MEM_DISCARDABLE,
    dumps_pe_executable,
    loads_pe_executable,
    read_pe_image,
)
from .boot import (
    SVMEM_BOOTDATA,
    SVMEM_INITRAMFS,
    SVMEM_KERNEL,
    SVMEM_RAM,
    SVMEM_RESERVED,
    STARTUP_DATA_SIZE,
    MEM_MAP_ENTRY_SIZE,
    plan_boot_image,
    populate_startup_data,
    read_startup_data,
)
from .mmio import (
    FramebufferDevice,
    HostBlockImage,
    MemoryBlockImage,
    SVM_FB_FORMAT_XRGB8888,
    build_default_mmio_machine,
)
from .PyStackVM import (
    AdvProgIntCtl,
    BC_HLT,
    ProgrammableIntervalTimer,
    SVSR_FLAGS,
    VM_DISABLED,
    VirtualMachine,
)

U64_MASK = (1 << 64) - 1
EFI_PAGE_SIZE = 4096

EFI_SUCCESS = 0
EFI_LOAD_ERROR = 0x8000000000000001
EFI_INVALID_PARAMETER = 0x8000000000000002
EFI_UNSUPPORTED = 0x8000000000000003
EFI_BAD_BUFFER_SIZE = 0x8000000000000004
EFI_BUFFER_TOO_SMALL = 0x8000000000000005
EFI_NOT_READY = 0x8000000000000006
EFI_NOT_FOUND = 0x800000000000000E
EFI_OUT_OF_RESOURCES = 0x8000000000000009

EFI_REVISION = (2 << 16) | 70
EFI_TABLE_HEADER_SIZE = 24
EFI_SYSTEM_TABLE_SIZE = 0x78
EFI_MEMORY_DESCRIPTOR_SIZE = 40
EFI_MEMORY_DESCRIPTOR_VERSION = 1

EFI_SYSTEM_TABLE_SIGNATURE = 0x5453595320494249
EFI_BOOT_SERVICES_SIGNATURE = 0x56524553544F4F42
EFI_RUNTIME_SERVICES_SIGNATURE = 0x56524553544E5552

EFI_RESERVED_MEMORY_TYPE = 0
EFI_LOADER_CODE = 1
EFI_LOADER_DATA = 2
EFI_BOOT_SERVICES_CODE = 3
EFI_BOOT_SERVICES_DATA = 4
EFI_RUNTIME_SERVICES_CODE = 5
EFI_RUNTIME_SERVICES_DATA = 6
EFI_CONVENTIONAL_MEMORY = 7
EFI_MEMORY_MAPPED_IO = 11

EFI_MEMORY_WB = 0x0000000000000008
EFI_MEMORY_UC = 0x0000000000000001
EFI_MEMORY_RUNTIME = 0x8000000000000000

EVT_TIMER = 0x80000000
EVT_RUNTIME = 0x40000000
EVT_NOTIFY_WAIT = 0x00000100
EVT_NOTIFY_SIGNAL = 0x00000200
EVT_SIGNAL_EXIT_BOOT_SERVICES = 0x00000201

TIMER_CANCEL = 0
TIMER_PERIODIC = 1
TIMER_RELATIVE = 2

# Task Priority Levels (mapped onto the D2 interrupt priority mask, see Uefi.html).
TPL_APPLICATION = 4
TPL_CALLBACK = 8
TPL_NOTIFY = 16
TPL_HIGH_LEVEL = 31

# Memory types used by AllocateXxx and the firmware page allocator.
ALLOCATE_ANY_PAGES = 0
ALLOCATE_MAX_ADDRESS = 1
ALLOCATE_ADDRESS = 2

# Sentinel returned by an in-VM service marshaller to signal that it has already
# redirected control (e.g. chain-load via StartImage, or stopped the VM via
# Exit/ResetSystem) and the generic trap must *not* write a return slot or unwind.
_NO_RETURN = object()

EFI_SIMPLE_TEXT_INPUT_PROTOCOL_GUID = uuid.UUID(
    "387477c1-69c7-11d2-8e39-00a0c969723b"
)
EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID = uuid.UUID(
    "387477c2-69c7-11d2-8e39-00a0c969723b"
)
EFI_LOADED_IMAGE_PROTOCOL_GUID = uuid.UUID("5b1b31a1-9562-11d2-8e3f-00a0c969723b")
EFI_BLOCK_IO_PROTOCOL_GUID = uuid.UUID("964e5b21-6459-11d2-8e39-00a0c969723b")
EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID = uuid.UUID(
    "0964e5b2-6459-11d2-8e39-00a0c969723b"
)
EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID = uuid.UUID(
    "9042a9de-23dc-4a38-96fb-7aded080516a"
)
EFI_DTB_TABLE_GUID = uuid.UUID("b1b621d5-f19c-41a5-830b-d9152c69aae0")

_TABLE_HEADER = struct.Struct("<QIIII")
_MEMORY_DESCRIPTOR = struct.Struct("<IIQQQQ")

_BOOT_SERVICE_NAMES = [
    "RaiseTPL",
    "RestoreTPL",
    "AllocatePages",
    "FreePages",
    "GetMemoryMap",
    "AllocatePool",
    "FreePool",
    "CreateEvent",
    "SetTimer",
    "WaitForEvent",
    "SignalEvent",
    "CloseEvent",
    "CheckEvent",
    "InstallProtocolInterface",
    "ReinstallProtocolInterface",
    "UninstallProtocolInterface",
    "HandleProtocol",
    "Reserved",
    "RegisterProtocolNotify",
    "LocateHandle",
    "LocateDevicePath",
    "InstallConfigurationTable",
    "LoadImage",
    "StartImage",
    "Exit",
    "UnloadImage",
    "ExitBootServices",
    "GetNextMonotonicCount",
    "Stall",
    "SetWatchdogTimer",
    "ConnectController",
    "DisconnectController",
    "OpenProtocol",
    "CloseProtocol",
    "OpenProtocolInformation",
    "ProtocolsPerHandle",
    "LocateHandleBuffer",
    "LocateProtocol",
    "InstallMultipleProtocolInterfaces",
    "UninstallMultipleProtocolInterfaces",
    "CalculateCrc32",
    "CopyMem",
    "SetMem",
    "CreateEventEx",
]

_RUNTIME_SERVICE_NAMES = [
    "GetTime",
    "SetTime",
    "GetWakeupTime",
    "SetWakeupTime",
    "SetVirtualAddressMap",
    "ConvertPointer",
    "GetVariable",
    "GetNextVariableName",
    "SetVariable",
    "GetNextHighMonotonicCount",
    "ResetSystem",
    "UpdateCapsule",
    "QueryCapsuleCapabilities",
    "QueryVariableInfo",
]

# EFIAPI argument counts (excluding the caller-allocated return slot) for every
# service, used by the in-VM service trap to read the right number of 8-byte
# argument slots and to locate the return slot at bp + 16 + 8*arity.  Protocol
# methods count their leading ``This`` pointer.  Kept exhaustive so an in-VM call
# to any table member unwinds correctly even when the marshaller is a stub.
_BOOT_SERVICE_ARITY = {
    "RaiseTPL": 1,
    "RestoreTPL": 1,
    "AllocatePages": 4,
    "FreePages": 2,
    "GetMemoryMap": 5,
    "AllocatePool": 3,
    "FreePool": 1,
    "CreateEvent": 5,
    "SetTimer": 3,
    "WaitForEvent": 3,
    "SignalEvent": 1,
    "CloseEvent": 1,
    "CheckEvent": 1,
    "InstallProtocolInterface": 4,
    "ReinstallProtocolInterface": 4,
    "UninstallProtocolInterface": 3,
    "HandleProtocol": 3,
    "Reserved": 0,
    "RegisterProtocolNotify": 3,
    "LocateHandle": 5,
    "LocateDevicePath": 3,
    "InstallConfigurationTable": 2,
    "LoadImage": 6,
    "StartImage": 3,
    "Exit": 4,
    "UnloadImage": 1,
    "ExitBootServices": 2,
    "GetNextMonotonicCount": 1,
    "Stall": 1,
    "SetWatchdogTimer": 4,
    "ConnectController": 4,
    "DisconnectController": 3,
    "OpenProtocol": 6,
    "CloseProtocol": 4,
    "OpenProtocolInformation": 4,
    "ProtocolsPerHandle": 3,
    "LocateHandleBuffer": 5,
    "LocateProtocol": 3,
    "InstallMultipleProtocolInterfaces": 2,
    "UninstallMultipleProtocolInterfaces": 2,
    "CalculateCrc32": 3,
    "CopyMem": 3,
    "SetMem": 3,
    "CreateEventEx": 6,
}

_RUNTIME_SERVICE_ARITY = {
    "GetTime": 2,
    "SetTime": 1,
    "GetWakeupTime": 3,
    "SetWakeupTime": 2,
    "SetVirtualAddressMap": 4,
    "ConvertPointer": 2,
    "GetVariable": 5,
    "GetNextVariableName": 3,
    "SetVariable": 5,
    "GetNextHighMonotonicCount": 1,
    "ResetSystem": 4,
    "UpdateCapsule": 3,
    "QueryCapsuleCapabilities": 4,
    "QueryVariableInfo": 4,
}


@dataclass
class LoadedEfiImage:
    """A PE32+ image loaded by ``LoadImage`` (firmware boot service)."""

    handle: int
    base: int
    size: int
    entry: int
    started: bool = False


def _align_up(value: int, align: int) -> int:
    return (value + align - 1) & ~(align - 1)


def pack_guid(value: Union[uuid.UUID, str]) -> bytes:
    return (value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))).bytes_le


def unpack_guid(data: bytes) -> uuid.UUID:
    return uuid.UUID(bytes_le=bytes(data[:16]))


def _utf16le_z(text: str) -> bytes:
    return text.encode("utf-16-le") + b"\0\0"


def _decode_char16(value: Union[str, bytes, bytearray, memoryview]) -> str:
    if isinstance(value, str):
        return value
    raw = bytes(value)
    if len(raw) % 2:
        raw += b"\0"
    end = raw.find(b"\0\0")
    if end >= 0:
        raw = raw[: end + (end & 1)]
    return raw.decode("utf-16-le", "replace")


def _write_u64(memory: bytearray, addr: int, value: int) -> None:
    memory[addr : addr + 8] = (value & U64_MASK).to_bytes(8, "little")


def _write_u32(memory: bytearray, addr: int, value: int) -> None:
    memory[addr : addr + 4] = (value & 0xFFFFFFFF).to_bytes(4, "little")


def _read_cstr(memory: bytearray, addr: int) -> bytes:
    end = addr
    while end < len(memory) and memory[end]:
        end += 1
    return bytes(memory[addr:end])


def _read_char16(memory: bytearray, addr: int, max_chars: int = 4096) -> str:
    """Read a NUL-terminated CHAR16 (UTF-16LE) string out of guest memory."""
    out = bytearray()
    end = addr
    limit = addr + max_chars * 2
    while end + 1 < len(memory) and end < limit:
        unit = memory[end] | (memory[end + 1] << 8)
        if unit == 0:
            break
        out += memory[end : end + 2]
        end += 2
    return bytes(out).decode("utf-16-le", "replace")


def _entry_offset_from_pe(data: bytes) -> int:
    pe = read_pe_image(data)
    loadable = [
        s
        for s in pe.sections
        if s.name not in (".svmmeta", ".reloc") and not s.is_discardable
    ]
    if not loadable:
        return 0
    section_base = min(s.virtual_address for s in loadable)
    return pe.entry_point - section_base


@dataclass
class UefiMemoryDescriptor:
    type: int
    physical_start: int
    number_of_pages: int
    attribute: int = EFI_MEMORY_WB
    virtual_start: int = 0

    @property
    def end(self) -> int:
        return self.physical_start + self.number_of_pages * EFI_PAGE_SIZE

    def pack(self) -> bytes:
        return _MEMORY_DESCRIPTOR.pack(
            self.type,
            0,
            self.physical_start & U64_MASK,
            self.virtual_start & U64_MASK,
            self.number_of_pages & U64_MASK,
            self.attribute & U64_MASK,
        )


@dataclass
class UefiLaunch:
    vm: VirtualMachine
    image: object
    image_handle: int
    system_table_addr: int
    boot_services_addr: int
    runtime_services_addr: int
    configuration_table_addr: int
    dtb_addr: int
    app_base: int
    entry_addr: int
    stack_args_addr: int


class _GuestAllocator:
    def __init__(self, memory: bytearray, start: int, end: int) -> None:
        self.memory = memory
        self.start = start
        self.end = end
        self.cursor = start

    def alloc(self, size: int, align: int = 8, fill: int = 0) -> int:
        addr = _align_up(self.cursor, align)
        end = addr + size
        if end > self.end:
            raise MemoryError("firmware bootdata allocator exhausted")
        if fill is not None:
            self.memory[addr:end] = bytes([fill & 0xFF]) * size
        self.cursor = end
        return addr

    def bytes(self, data: bytes, align: int = 8) -> int:
        addr = self.alloc(len(data), align)
        self.memory[addr : addr + len(data)] = data
        return addr

    def char16(self, text: str) -> int:
        return self.bytes(_utf16le_z(text), 2)


class UefiVariableStore:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path
        self.variables: Dict[Tuple[str, str], Tuple[int, bytes]] = {}
        if path and os.path.exists(path):
            self._load()

    def _load(self) -> None:
        with open(self.path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        self.variables.clear()
        for item in raw.get("variables", []):
            key = (item["name"], str(uuid.UUID(item["guid"])))
            attrs = int(item["attributes"])
            data = base64.b64decode(item["data"].encode("ascii"))
            self.variables[key] = (attrs, data)

    def _save(self) -> None:
        if not self.path:
            return
        payload = {
            "variables": [
                {
                    "name": name,
                    "guid": guid,
                    "attributes": attrs,
                    "data": base64.b64encode(data).decode("ascii"),
                }
                for (name, guid), (attrs, data) in sorted(self.variables.items())
            ]
        }
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, sort_keys=True)
        os.replace(tmp, self.path)

    def get_variable(
        self, name: str, vendor_guid: Union[uuid.UUID, str]
    ) -> Tuple[int, int, bytes]:
        key = (name, str(uuid.UUID(str(vendor_guid))))
        if key not in self.variables:
            return EFI_NOT_FOUND, 0, b""
        attrs, data = self.variables[key]
        return EFI_SUCCESS, attrs, data

    def set_variable(
        self,
        name: str,
        vendor_guid: Union[uuid.UUID, str],
        data: Union[bytes, bytearray, memoryview],
        attributes: int = 7,
    ) -> int:
        key = (name, str(uuid.UUID(str(vendor_guid))))
        data = bytes(data)
        if not data:
            self.variables.pop(key, None)
        else:
            self.variables[key] = (int(attributes), data)
        self._save()
        return EFI_SUCCESS

    def next_variable_name(
        self, previous: Optional[Tuple[str, Union[uuid.UUID, str]]] = None
    ) -> Tuple[int, Optional[str], Optional[uuid.UUID]]:
        keys = sorted(self.variables)
        if previous is None:
            index = 0
        else:
            prev_key = (previous[0], str(uuid.UUID(str(previous[1]))))
            try:
                index = keys.index(prev_key) + 1
            except ValueError:
                return EFI_NOT_FOUND, None, None
        if index >= len(keys):
            return EFI_NOT_FOUND, None, None
        name, guid = keys[index]
        return EFI_SUCCESS, name, uuid.UUID(guid)


class UefiSimpleFileSystem:
    MAGIC = b"SVMFS1\0\0"

    def __init__(
        self, backend: Optional[Union[HostBlockImage, MemoryBlockImage]] = None
    ) -> None:
        self.backend = backend
        self.files: Dict[str, bytes] = {}
        if backend is not None:
            self._load()

    @staticmethod
    def _norm(path: str) -> str:
        path = path.replace("/", "\\")
        while "\\\\" in path:
            path = path.replace("\\\\", "\\")
        return path.upper()

    def _load(self) -> None:
        raw = self.backend.read(0, min(self.backend.size, 1 << 20))
        if not raw.startswith(self.MAGIC):
            return
        if len(raw) < 12:
            return
        length = int.from_bytes(raw[8:12], "little")
        payload = raw[12 : 12 + length]
        if len(payload) != length:
            return
        data = json.loads(payload.decode("utf-8"))
        self.files = {
            self._norm(name): base64.b64decode(value.encode("ascii"))
            for name, value in data.get("files", {}).items()
        }

    def _sync(self) -> None:
        if self.backend is None:
            return
        payload = json.dumps(
            {
                "files": {
                    name: base64.b64encode(data).decode("ascii")
                    for name, data in sorted(self.files.items())
                }
            },
            sort_keys=True,
        ).encode("utf-8")
        blob = self.MAGIC + len(payload).to_bytes(4, "little") + payload
        if len(blob) > self.backend.size:
            raise OSError("simple filesystem image is full")
        self.backend.write(0, blob)

    def read_file(self, path: str) -> Tuple[int, bytes]:
        key = self._norm(path)
        if key not in self.files:
            return EFI_NOT_FOUND, b""
        return EFI_SUCCESS, self.files[key]

    def write_file(self, path: str, data: Union[bytes, bytearray, memoryview]) -> int:
        self.files[self._norm(path)] = bytes(data)
        self._sync()
        return EFI_SUCCESS

    def list_files(self) -> List[str]:
        return sorted(self.files)


class UefiTextInputProtocol:
    def __init__(self, input_bytes: Union[bytes, bytearray, memoryview] = b"") -> None:
        self.input = bytearray(input_bytes)

    def read_key_stroke(self) -> Tuple[int, Optional[int]]:
        if not self.input:
            return EFI_NOT_READY, None
        return EFI_SUCCESS, self.input.pop(0)


class UefiTextOutputProtocol:
    def __init__(self, output: object) -> None:
        self.output = output

    def output_string(self, text: Union[str, bytes, bytearray, memoryview]) -> int:
        decoded = _decode_char16(text)
        data = decoded.encode("utf-8")
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
        return EFI_SUCCESS


class UefiBlockIoProtocol:
    def __init__(
        self,
        backend: Union[HostBlockImage, MemoryBlockImage],
        block_size: int = 512,
    ) -> None:
        self.backend = backend
        self.block_size = block_size
        self.media_id = 1

    @property
    def last_block(self) -> int:
        if self.backend.size == 0:
            return 0
        return (self.backend.size - 1) // self.block_size

    def read_blocks(self, media_id: int, lba: int, buffer_size: int) -> Tuple[int, bytes]:
        if media_id != self.media_id or buffer_size % self.block_size:
            return EFI_INVALID_PARAMETER, b""
        return EFI_SUCCESS, self.backend.read(lba * self.block_size, buffer_size)

    def write_blocks(
        self,
        media_id: int,
        lba: int,
        data: Union[bytes, bytearray, memoryview],
    ) -> int:
        data = bytes(data)
        if media_id != self.media_id or len(data) % self.block_size:
            return EFI_INVALID_PARAMETER
        written = self.backend.write(lba * self.block_size, data)
        return EFI_SUCCESS if written == len(data) else EFI_BAD_BUFFER_SIZE


class UefiGraphicsOutputProtocol:
    def __init__(self, framebuffer: FramebufferDevice) -> None:
        self.framebuffer = framebuffer

    def mode_info(self) -> Dict[str, int]:
        return {
            "width": self.framebuffer.width,
            "height": self.framebuffer.height,
            "stride": self.framebuffer.stride,
            "format": self.framebuffer.format,
            "framebuffer_base": self.framebuffer.pixel_base,
            "framebuffer_size": self.framebuffer.pixel_size,
        }

    def write_pixel(self, x: int, y: int, color: int) -> int:
        if x < 0 or y < 0 or x >= self.framebuffer.width or y >= self.framebuffer.height:
            return EFI_INVALID_PARAMETER
        offset = y * self.framebuffer.stride + x * 4
        self.framebuffer.write_pixels(offset, 4, color)
        return EFI_SUCCESS

    def blt_fill(self, color: int) -> int:
        pixel = (color & 0xFFFFFFFF).to_bytes(4, "little")
        for off in range(0, self.framebuffer.pixel_size, 4):
            self.framebuffer.write_pixels(off, 4, int.from_bytes(pixel, "little"))
        return EFI_SUCCESS


@dataclass
class UefiEvent:
    handle: int
    type: int
    tpl: int
    notify: Optional[Callable[["UefiEvent"], None]] = None
    context: int = 0
    signaled: bool = False
    trigger_time: Optional[int] = None
    period: Optional[int] = None


class MinimalUefiFirmware:
    def __init__(
        self,
        *,
        vm_size: int = 1 << 20,
        app_base: int = 0x1000,
        cmdline: Union[str, bytes] = "",
        initramfs: bytes = b"",
        dtb: bytes = b"",
        generate_dtb: bool = True,
        core_count: int = 1,
        console_input: Union[bytes, bytearray, memoryview] = b"",
        console_output: Optional[object] = None,
        block_backend: Optional[Union[HostBlockImage, MemoryBlockImage]] = None,
        nvram_path: Optional[str] = None,
        rtc_ns: Optional[Callable[[], int]] = None,
        framebuffer_width: int = 640,
        framebuffer_height: int = 480,
        boot_image_payload: Union[bytes, bytearray] = b"",
    ) -> None:
        self.vm_size = vm_size
        self.app_base = app_base
        self.cmdline = cmdline
        self.initramfs = initramfs
        self.explicit_dtb = dtb
        self.generate_dtb = generate_dtb
        self.core_count = core_count
        # The default boot image on the "device" (what LoadImage returns when an
        # EFI bootloader asks for the boot image with no SourceBuffer).
        self.boot_image_payload = bytes(boot_image_payload)
        self.console_output = bytearray() if console_output is None else console_output
        self.rtc_ns = time.time_ns if rtc_ns is None else rtc_ns
        self.block_backend = block_backend
        self.variables = UefiVariableStore(nvram_path)
        self.simple_file_system = UefiSimpleFileSystem(block_backend)
        self.text_in = UefiTextInputProtocol(console_input)
        self.text_out = UefiTextOutputProtocol(self.console_output)
        self.mmio_machine = build_default_mmio_machine(
            block_backend=block_backend,
            uart_output=self.console_output,
            uart_input=console_input,
            rtc_ns=self.rtc_ns,
            framebuffer=True,
            framebuffer_width=framebuffer_width,
            framebuffer_height=framebuffer_height,
        )
        self.framebuffer = self.mmio_machine.framebuffer
        self.gop = UefiGraphicsOutputProtocol(self.framebuffer)
        self.block_io = (
            UefiBlockIoProtocol(block_backend) if block_backend is not None else None
        )

        self.vm: Optional[VirtualMachine] = None
        self.launch: Optional[UefiLaunch] = None
        self.apic: Optional[AdvProgIntCtl] = None
        self.timer: Optional[ProgrammableIntervalTimer] = None
        self.image_handle = 0
        self.system_table_addr = 0
        self.boot_services_addr = 0
        self.runtime_services_addr = 0
        self.configuration_table_addr = 0
        self.protocols: Dict[int, Dict[uuid.UUID, int]] = {}
        self.protocol_objects: Dict[Tuple[int, uuid.UUID], object] = {}
        self.service_pointers: Dict[str, int] = {}
        self.service_dispatch: Dict[int, Callable] = {}
        # In-VM EFIAPI dispatch: service pointer -> (arity, marshaller(vm, args)).
        self._vm_marshallers: Dict[int, Tuple[int, Callable]] = {}
        self.events: Dict[int, UefiEvent] = {}
        self.boot_services_active = True
        self.map_key = 1
        self.tpl = TPL_APPLICATION
        self.exited = False
        self.exit_status: Optional[int] = None
        self._monotonic = 0
        self.loaded_images: Dict[int, LoadedEfiImage] = {}
        self._allocations: Dict[int, Tuple[int, int]] = {}
        self._free_ranges: List[List[int]] = []
        self._current_time_100ns = 0
        self._next_service_ptr = 0xFFF000000000

    # ------------------------------------------------------------------
    # Service pointer registry and protocol DB
    # ------------------------------------------------------------------

    def _service_pointer(
        self,
        name: str,
        fn: Optional[Callable] = None,
        *,
        arity: int = 0,
        marshaller: Optional[Callable] = None,
    ) -> int:
        if name in self.service_pointers:
            return self.service_pointers[name]
        ptr = self._next_service_ptr
        self._next_service_ptr += 0x10
        self.service_pointers[name] = ptr
        self.service_dispatch[ptr] = fn or self._unsupported_service
        # Every table member is registered so an in-VM call to it is recognised
        # as a firmware trap rather than executed as bytecode at 0xFFF...; ones
        # without a real marshaller fall back to EFI_UNSUPPORTED but still unwind.
        self._vm_marshallers[ptr] = (arity, marshaller or self._efi_default)
        return ptr

    def call_service(self, pointer: int, *args):
        if pointer not in self.service_dispatch:
            return EFI_UNSUPPORTED
        return self.service_dispatch[pointer](*args)

    def _unsupported_service(self, *args):
        return EFI_UNSUPPORTED

    # ------------------------------------------------------------------
    # In-VM EFIAPI service dispatch (firmware run loop + trap)
    # ------------------------------------------------------------------

    def run(self, *, max_steps: int = 5_000_000, interrupts: bool = False) -> int:
        """Execute the loaded EFI image, trapping in-VM calls to firmware service
        pointers and dispatching them through the EFIAPI marshallers.

        The firmware service tables hold synthetic pointers outside RAM; whenever
        the VM's ``ip`` lands on one, the call is serviced by the firmware instead
        of fetched as bytecode.  Returns the number of dispatch steps executed.
        """
        vm = self.vm
        if vm is None:
            raise RuntimeError("no EFI image loaded; call load_efi_app() first")
        saved_apic, saved_timer = vm.apic, vm.timer
        if not interrupts:
            # Keep the loop deterministic: no async timer/APIC delivery (the EFI
            # event/timer model is driven explicitly via advance_time_100ns).
            vm.apic = None
            vm.timer = None
        try:
            steps = 0
            while vm.running and steps < max_steps:
                marshaller = self._vm_marshallers.get(vm.ip)
                if marshaller is not None:
                    self._service_trap(vm.ip)
                else:
                    vm.step()
                steps += 1
            if vm.running and steps >= max_steps:
                raise RuntimeError(
                    "EFI image exceeded max_steps (%d) without halting" % max_steps
                )
            return steps
        finally:
            vm.apic, vm.timer = saved_apic, saved_timer

    def _service_trap(self, ptr: int) -> None:
        """Service one in-VM EFIAPI call landing on firmware service *ptr*.

        On entry (immediately after the guest's ``CALL``) ``bp == sp`` points at
        the saved return ip; the EFIAPI frame is::

            [bp+0]  return ip      [bp+8]  saved bp
            [bp+16] arg0 ...       [bp+16+8*arity] caller-reserved return slot
        """
        vm = self.vm
        arity, marshaller = self._vm_marshallers[ptr]
        bp = vm.bp
        args = [vm.get(8, bp + 16 + 8 * i) for i in range(arity)]
        result = marshaller(vm, args)
        if result is _NO_RETURN:
            # The marshaller redirected control (chain-load) or halted the VM.
            return
        status = EFI_SUCCESS if result is None else (result & U64_MASK)
        vm.set(8, bp + 16 + 8 * arity, status)
        vm.ret()

    def _new_runtime_handle(self) -> int:
        status, addr = self.allocate_pool(8)
        if status != EFI_SUCCESS:
            raise MemoryError("could not allocate firmware handle")
        _write_u64(self.vm.memory, addr, 0)
        self.protocols.setdefault(addr, {})
        return addr

    # ---- EFIAPI marshallers ------------------------------------------------
    # Each takes (vm, args) where args are the 8-byte argument slots, reads/writes
    # guest memory for pointer parameters, and returns the EFI_STATUS (or _NO_RETURN).

    def _efi_default(self, vm, args):
        return EFI_UNSUPPORTED

    def _efi_noop_success(self, vm, args):
        return EFI_SUCCESS

    def _efi_output_string(self, vm, args):
        text = _read_char16(vm.memory, args[1]) if args[1] else ""
        return self.text_out.output_string(text)

    def _efi_read_key_stroke(self, vm, args):
        status, ch = self.text_in.read_key_stroke()
        if status == EFI_SUCCESS and args[1]:
            vm.set(2, args[1], 0)  # ScanCode
            vm.set(2, args[1] + 2, ch or 0)  # UnicodeChar
        return status

    def _efi_get_memory_map(self, vm, args):
        map_size_ptr, map_ptr, key_ptr, dsize_ptr, dver_ptr = args
        buf_size = vm.get(8, map_size_ptr) if map_size_ptr else 0
        status, required, key, dsize, dver, data = self.get_memory_map(buf_size)
        if map_size_ptr:
            vm.set(8, map_size_ptr, required)
        if dsize_ptr:
            vm.set(8, dsize_ptr, dsize)
        if dver_ptr:
            vm.set(4, dver_ptr, dver)
        if key_ptr:
            vm.set(8, key_ptr, key)
        if status == EFI_SUCCESS and map_ptr and data:
            vm.memory[map_ptr : map_ptr + len(data)] = data
        return status

    def _efi_exit_boot_services(self, vm, args):
        status = self.exit_boot_services(args[0], args[1])
        if status == EFI_SUCCESS:
            # Boot-time timer event torn down; the OS owns the controller now.
            self.tpl = TPL_APPLICATION
        return status

    def _efi_allocate_pages(self, vm, args):
        _typ, memtype, pages, mem_ptr = args
        status, addr = self.allocate_pages(pages, memtype)
        if status == EFI_SUCCESS and mem_ptr:
            vm.set(8, mem_ptr, addr)
        return status

    def _efi_free_pages(self, vm, args):
        return self.free_pages(args[0], args[1])

    def _efi_allocate_pool(self, vm, args):
        _pooltype, size, buf_ptr = args
        status, addr = self.allocate_pool(size)
        if status == EFI_SUCCESS and buf_ptr:
            vm.set(8, buf_ptr, addr)
        return status

    def _efi_free_pool(self, vm, args):
        return self.free_pool(args[0])

    def _efi_handle_protocol(self, vm, args):
        handle, guid_ptr, iface_ptr = args
        guid = unpack_guid(vm.memory[guid_ptr : guid_ptr + 16])
        status, iface = self.handle_protocol(handle, guid)
        if status == EFI_SUCCESS and iface_ptr:
            vm.set(8, iface_ptr, iface)
        return status

    def _efi_locate_protocol(self, vm, args):
        guid_ptr, _registration, iface_ptr = args
        guid = unpack_guid(vm.memory[guid_ptr : guid_ptr + 16])
        status, _handle, iface = self.locate_protocol(guid)
        if status == EFI_SUCCESS and iface_ptr:
            vm.set(8, iface_ptr, iface)
        return status

    def _efi_get_time(self, vm, args):
        status, t = self.get_time()
        time_ptr = args[0]
        if status == EFI_SUCCESS and time_ptr:
            struct.pack_into(
                "<HBBBBBBIhBB",
                vm.memory,
                time_ptr,
                t["year"],
                t["month"],
                t["day"],
                t["hour"],
                t["minute"],
                t["second"],
                0,
                t["nanosecond"],
                0,
                0,
                0,
            )
        return status

    def _efi_stall(self, vm, args):
        self.advance_time_100ns(int(args[0]) * 10)  # 1 us == 10 * 100ns
        return EFI_SUCCESS

    def _efi_copy_mem(self, vm, args):
        dst, src, length = args
        vm.memory[dst : dst + length] = bytes(vm.memory[src : src + length])
        return EFI_SUCCESS

    def _efi_set_mem(self, vm, args):
        buf, size, value = args
        vm.memory[buf : buf + size] = bytes([value & 0xFF]) * size
        return EFI_SUCCESS

    def _efi_raise_tpl(self, vm, args):
        old = self.tpl
        self.tpl = args[0]
        return old  # RaiseTPL returns the previous TPL in the status slot

    def _efi_restore_tpl(self, vm, args):
        self.tpl = args[0]
        return EFI_SUCCESS

    def _efi_calculate_crc32(self, vm, args):
        data_ptr, size, crc_ptr = args
        if not data_ptr or not crc_ptr or size == 0:
            return EFI_INVALID_PARAMETER
        crc = zlib.crc32(bytes(vm.memory[data_ptr : data_ptr + size])) & 0xFFFFFFFF
        vm.set(4, crc_ptr, crc)
        return EFI_SUCCESS

    def _efi_get_next_monotonic_count(self, vm, args):
        self._monotonic += 1
        if args[0]:
            vm.set(8, args[0], self._monotonic)
        return EFI_SUCCESS

    def _efi_create_event(self, vm, args):
        event_type, tpl, _notify_fn, context, event_ptr = args
        # Guest notify callbacks are not invoked (they would be guest bytecode);
        # the event is still created so SetTimer/CheckEvent/WaitForEvent work.
        status, handle = self.create_event(event_type, tpl, None, context)
        if status == EFI_SUCCESS and event_ptr:
            vm.set(8, event_ptr, handle)
        return status

    def _efi_set_timer(self, vm, args):
        return self.set_timer(args[0], args[1], args[2])

    def _efi_signal_event(self, vm, args):
        return self.signal_event(args[0])

    def _efi_check_event(self, vm, args):
        return self.check_event(args[0])

    def _efi_close_event(self, vm, args):
        return self.close_event(args[0])

    def _efi_reset_system(self, vm, args):
        self.exit_status = args[1]
        self.exited = True
        vm.running = 0
        return _NO_RETURN

    def _efi_exit(self, vm, args):
        self.exit_status = args[1]
        self.exited = True
        vm.running = 0
        return _NO_RETURN

    def _efi_block_read(self, vm, args):
        if self.block_io is None:
            return EFI_UNSUPPORTED
        _this, media_id, lba, buffer_size, buffer = args
        status, data = self.block_io.read_blocks(media_id, lba, buffer_size)
        if status == EFI_SUCCESS and buffer and data:
            vm.memory[buffer : buffer + len(data)] = data
        return status

    def _efi_block_write(self, vm, args):
        if self.block_io is None:
            return EFI_UNSUPPORTED
        _this, media_id, lba, buffer_size, buffer = args
        data = bytes(vm.memory[buffer : buffer + buffer_size]) if buffer else b""
        return self.block_io.write_blocks(media_id, lba, data)

    def _efi_load_image(self, vm, args):
        _policy, _parent, _devpath, src_buf, src_size, out_ptr = args
        if src_buf and src_size:
            pe_bytes = bytes(vm.memory[src_buf : src_buf + src_size])
        elif self.boot_image_payload:
            pe_bytes = self.boot_image_payload
        else:
            return EFI_NOT_FOUND
        try:
            executable = loads_pe_executable(pe_bytes)
            entry_offset = _entry_offset_from_pe(pe_bytes)
        except Exception:
            return EFI_LOAD_ERROR
        size = len(executable.memory)
        pages = max(1, _align_up(size, EFI_PAGE_SIZE) // EFI_PAGE_SIZE)
        status, base = self.allocate_pages(pages, EFI_LOADER_CODE)
        if status != EFI_SUCCESS:
            return EFI_OUT_OF_RESOURCES
        app_memory = bytearray(executable.memory)
        apply_base_fixups(app_memory, executable.base_relocations, base)
        vm.memory[base : base + len(app_memory)] = app_memory
        handle = self._new_runtime_handle()
        self.loaded_images[handle] = LoadedEfiImage(handle, base, size, base + entry_offset)
        if out_ptr:
            vm.set(8, out_ptr, handle)
        return EFI_SUCCESS

    def _efi_start_image(self, vm, args):
        handle = args[0]
        record = self.loaded_images.get(handle)
        if record is None:
            return EFI_INVALID_PARAMETER
        record.started = True
        # Chain-load: hand control to the new image's efi_main with a fresh stack.
        # The bootloader that called StartImage does not regain control (it has
        # transferred ownership to the loaded kernel), matching GRUB chain-load.
        self.image_handle = handle
        vm.sp = self.vm_size
        vm.bp = self.vm_size
        vm.push(8, 0)
        vm.push(8, self.system_table_addr)
        vm.push(8, handle)
        vm.ip = record.entry
        return _NO_RETURN

    def _new_handle(self, alloc: _GuestAllocator, name: str) -> int:
        addr = alloc.alloc(8, 8)
        _write_u64(alloc.memory, addr, 0)
        self.protocols[addr] = {}
        return addr

    def install_protocol(
        self,
        handle: int,
        guid: Union[uuid.UUID, str],
        interface_addr: int,
        obj: Optional[object] = None,
    ) -> int:
        guid = guid if isinstance(guid, uuid.UUID) else uuid.UUID(str(guid))
        self.protocols.setdefault(handle, {})[guid] = interface_addr
        if obj is not None:
            self.protocol_objects[(handle, guid)] = obj
        return EFI_SUCCESS

    def handle_protocol(
        self, handle: int, guid: Union[uuid.UUID, str]
    ) -> Tuple[int, int]:
        guid = guid if isinstance(guid, uuid.UUID) else uuid.UUID(str(guid))
        interface = self.protocols.get(handle, {}).get(guid)
        if interface is None:
            return EFI_NOT_FOUND, 0
        return EFI_SUCCESS, interface

    def locate_protocol(self, guid: Union[uuid.UUID, str]) -> Tuple[int, int, int]:
        guid = guid if isinstance(guid, uuid.UUID) else uuid.UUID(str(guid))
        for handle, protocols in self.protocols.items():
            if guid in protocols:
                return EFI_SUCCESS, handle, protocols[guid]
        return EFI_NOT_FOUND, 0, 0

    # ------------------------------------------------------------------
    # Memory services
    # ------------------------------------------------------------------

    def _init_free_ranges(self, image) -> None:
        self._free_ranges = []
        for entry in image.mem_map:
            if entry.type != SVMEM_RAM:
                continue
            base = _align_up(entry.base, EFI_PAGE_SIZE)
            end = entry.end & ~(EFI_PAGE_SIZE - 1)
            if end > base:
                self._free_ranges.append([base, end])

    def allocate_pages(
        self, pages: int, memory_type: int = EFI_BOOT_SERVICES_DATA
    ) -> Tuple[int, int]:
        pages = int(pages)
        if pages <= 0:
            return EFI_INVALID_PARAMETER, 0
        size = pages * EFI_PAGE_SIZE
        for i, (base, end) in enumerate(self._free_ranges):
            addr = _align_up(base, EFI_PAGE_SIZE)
            if addr + size > end:
                continue
            new_ranges = []
            if base < addr:
                new_ranges.append([base, addr])
            if addr + size < end:
                new_ranges.append([addr + size, end])
            self._free_ranges[i : i + 1] = new_ranges
            self._allocations[addr] = (size, memory_type)
            self.map_key += 1
            return EFI_SUCCESS, addr
        return EFI_OUT_OF_RESOURCES, 0

    def free_pages(self, addr: int, pages: int) -> int:
        size = int(pages) * EFI_PAGE_SIZE
        if self._allocations.get(addr, (None, None))[0] != size:
            return EFI_INVALID_PARAMETER
        del self._allocations[addr]
        self._free_ranges.append([addr, addr + size])
        self._free_ranges.sort()
        merged: List[List[int]] = []
        for base, end in self._free_ranges:
            if merged and merged[-1][1] >= base:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([base, end])
        self._free_ranges = merged
        self.map_key += 1
        return EFI_SUCCESS

    def allocate_pool(self, size: int) -> Tuple[int, int]:
        pages = _align_up(size, EFI_PAGE_SIZE) // EFI_PAGE_SIZE
        return self.allocate_pages(pages, EFI_BOOT_SERVICES_DATA)

    def free_pool(self, addr: int) -> int:
        alloc = self._allocations.get(addr)
        if alloc is None:
            return EFI_INVALID_PARAMETER
        pages = alloc[0] // EFI_PAGE_SIZE
        return self.free_pages(addr, pages)

    def _base_descriptors(self) -> List[UefiMemoryDescriptor]:
        if self.launch is None:
            return []
        type_map = {
            SVMEM_RESERVED: EFI_RESERVED_MEMORY_TYPE,
            SVMEM_KERNEL: EFI_LOADER_CODE,
            SVMEM_INITRAMFS: EFI_LOADER_DATA,
            SVMEM_BOOTDATA: EFI_BOOT_SERVICES_DATA,
            SVMEM_RAM: EFI_CONVENTIONAL_MEMORY,
        }
        out = []
        for entry in self.launch.image.mem_map:
            pages = _align_up(entry.size, EFI_PAGE_SIZE) // EFI_PAGE_SIZE
            if pages:
                out.append(
                    UefiMemoryDescriptor(
                        type_map.get(entry.type, EFI_RESERVED_MEMORY_TYPE),
                        entry.base,
                        pages,
                    )
                )
        if self.framebuffer is not None:
            out.append(
                UefiMemoryDescriptor(
                    EFI_MEMORY_MAPPED_IO,
                    self.framebuffer.pixel_base,
                    _align_up(self.framebuffer.pixel_size, EFI_PAGE_SIZE)
                    // EFI_PAGE_SIZE,
                    EFI_MEMORY_UC,
                )
            )
        return out

    def memory_descriptors(self) -> List[UefiMemoryDescriptor]:
        descriptors = self._base_descriptors()
        for addr, (size, typ) in sorted(self._allocations.items()):
            alloc_end = addr + size
            next_descriptors: List[UefiMemoryDescriptor] = []
            for desc in descriptors:
                if desc.type != EFI_CONVENTIONAL_MEMORY:
                    next_descriptors.append(desc)
                    continue
                base, end = desc.physical_start, desc.end
                if alloc_end <= base or addr >= end:
                    next_descriptors.append(desc)
                    continue
                if base < addr:
                    next_descriptors.append(
                        UefiMemoryDescriptor(
                            EFI_CONVENTIONAL_MEMORY,
                            base,
                            (addr - base) // EFI_PAGE_SIZE,
                            desc.attribute,
                        )
                    )
                next_descriptors.append(
                    UefiMemoryDescriptor(
                        typ,
                        addr,
                        size // EFI_PAGE_SIZE,
                        EFI_MEMORY_WB,
                    )
                )
                if alloc_end < end:
                    next_descriptors.append(
                        UefiMemoryDescriptor(
                            EFI_CONVENTIONAL_MEMORY,
                            alloc_end,
                            (end - alloc_end) // EFI_PAGE_SIZE,
                            desc.attribute,
                        )
                    )
            descriptors = [d for d in next_descriptors if d.number_of_pages > 0]
        descriptors.sort(key=lambda d: d.physical_start)
        return descriptors

    def get_memory_map(self, buffer_size: int = 0) -> Tuple[int, int, int, int, int, bytes]:
        data = b"".join(desc.pack() for desc in self.memory_descriptors())
        required = len(data)
        if buffer_size < required:
            return (
                EFI_BUFFER_TOO_SMALL,
                required,
                self.map_key,
                EFI_MEMORY_DESCRIPTOR_SIZE,
                EFI_MEMORY_DESCRIPTOR_VERSION,
                b"",
            )
        return (
            EFI_SUCCESS,
            required,
            self.map_key,
            EFI_MEMORY_DESCRIPTOR_SIZE,
            EFI_MEMORY_DESCRIPTOR_VERSION,
            data,
        )

    def write_memory_map(self, addr: int, buffer_size: int) -> Tuple[int, int, int, int, int]:
        status, required, key, desc_size, version, data = self.get_memory_map(buffer_size)
        if status == EFI_SUCCESS and self.vm is not None:
            self.vm.memory[addr : addr + len(data)] = data
        return status, required, key, desc_size, version

    def exit_boot_services(self, image_handle: int, map_key: int) -> int:
        if image_handle != self.image_handle or map_key != self.map_key:
            return EFI_INVALID_PARAMETER
        self.boot_services_active = False
        return EFI_SUCCESS

    # ------------------------------------------------------------------
    # Runtime services and events
    # ------------------------------------------------------------------

    def get_time(self) -> Tuple[int, Dict[str, int]]:
        ns = int(self.rtc_ns())
        dt = _datetime.datetime.fromtimestamp(
            ns / 1_000_000_000,
            _datetime.UTC,
        )
        return EFI_SUCCESS, {
            "year": dt.year,
            "month": dt.month,
            "day": dt.day,
            "hour": dt.hour,
            "minute": dt.minute,
            "second": dt.second,
            "nanosecond": ns % 1_000_000_000,
        }

    def create_event(
        self,
        event_type: int,
        tpl: int = 0,
        notify: Optional[Callable[[UefiEvent], None]] = None,
        context: int = 0,
    ) -> Tuple[int, int]:
        if self.vm is None:
            return EFI_NOT_READY, 0
        handle = self._alloc_runtime_handle()
        self.events[handle] = UefiEvent(handle, event_type, tpl, notify, context)
        return EFI_SUCCESS, handle

    def _alloc_runtime_handle(self) -> int:
        status, addr = self.allocate_pool(8)
        if status != EFI_SUCCESS:
            raise MemoryError("could not allocate firmware handle")
        return addr

    def set_timer(self, event_handle: int, timer_type: int, trigger_time_100ns: int) -> int:
        event = self.events.get(event_handle)
        if event is None:
            return EFI_INVALID_PARAMETER
        if timer_type == TIMER_CANCEL:
            event.trigger_time = None
            event.period = None
            return EFI_SUCCESS
        if not (event.type & EVT_TIMER):
            return EFI_INVALID_PARAMETER
        delay = int(trigger_time_100ns)
        if timer_type == TIMER_RELATIVE:
            event.trigger_time = self._current_time_100ns + delay
            event.period = None
        elif timer_type == TIMER_PERIODIC:
            event.trigger_time = self._current_time_100ns + delay
            event.period = delay
        else:
            return EFI_INVALID_PARAMETER
        if self.timer is not None:
            cycles = max(1, delay // 10_000)
            self.timer.program(cycles, periodic=(timer_type == TIMER_PERIODIC), enabled=True)
        return EFI_SUCCESS

    def advance_time_100ns(self, delta: int) -> None:
        self._current_time_100ns += int(delta)
        for event in list(self.events.values()):
            if event.trigger_time is None:
                continue
            if self._current_time_100ns < event.trigger_time:
                continue
            self.signal_event(event.handle)
            if event.period:
                while event.trigger_time <= self._current_time_100ns:
                    event.trigger_time += event.period
            else:
                event.trigger_time = None

    def signal_event(self, event_handle: int) -> int:
        event = self.events.get(event_handle)
        if event is None:
            return EFI_INVALID_PARAMETER
        event.signaled = True
        if event.notify is not None:
            event.notify(event)
        return EFI_SUCCESS

    def check_event(self, event_handle: int) -> int:
        event = self.events.get(event_handle)
        if event is None:
            return EFI_INVALID_PARAMETER
        if not event.signaled:
            return EFI_NOT_READY
        event.signaled = False
        return EFI_SUCCESS

    def wait_for_event(self, handles: Iterable[int]) -> Tuple[int, Optional[int]]:
        for index, handle in enumerate(handles):
            event = self.events.get(handle)
            if event is not None and event.signaled:
                event.signaled = False
                return EFI_SUCCESS, index
        return EFI_NOT_READY, None

    def close_event(self, event_handle: int) -> int:
        if event_handle not in self.events:
            return EFI_INVALID_PARAMETER
        del self.events[event_handle]
        self.free_pool(event_handle)
        return EFI_SUCCESS

    # ------------------------------------------------------------------
    # Table construction
    # ------------------------------------------------------------------

    def _finalize_table(
        self, memory: bytearray, addr: int, size: int, signature: int
    ) -> None:
        memory[addr : addr + EFI_TABLE_HEADER_SIZE] = _TABLE_HEADER.pack(
            signature,
            EFI_REVISION,
            size,
            0,
            0,
        )
        crc = zlib.crc32(bytes(memory[addr : addr + size])) & 0xFFFFFFFF
        _write_u32(memory, addr + 16, crc)

    def _build_boot_services_table(self, alloc: _GuestAllocator) -> int:
        size = EFI_TABLE_HEADER_SIZE + len(_BOOT_SERVICE_NAMES) * 8
        addr = alloc.alloc(size, 8)
        service_impls = {
            "AllocatePages": self.allocate_pages,
            "FreePages": self.free_pages,
            "GetMemoryMap": self.get_memory_map,
            "AllocatePool": self.allocate_pool,
            "FreePool": self.free_pool,
            "CreateEvent": self.create_event,
            "SetTimer": self.set_timer,
            "WaitForEvent": self.wait_for_event,
            "SignalEvent": self.signal_event,
            "CloseEvent": self.close_event,
            "CheckEvent": self.check_event,
            "HandleProtocol": self.handle_protocol,
            "LocateProtocol": self.locate_protocol,
            "ExitBootServices": self.exit_boot_services,
            "CalculateCrc32": lambda data: zlib.crc32(bytes(data)) & 0xFFFFFFFF,
        }
        # In-VM EFIAPI marshallers (read stack args + guest memory, write outputs).
        vm_marshallers = {
            "RaiseTPL": self._efi_raise_tpl,
            "RestoreTPL": self._efi_restore_tpl,
            "AllocatePages": self._efi_allocate_pages,
            "FreePages": self._efi_free_pages,
            "GetMemoryMap": self._efi_get_memory_map,
            "AllocatePool": self._efi_allocate_pool,
            "FreePool": self._efi_free_pool,
            "CreateEvent": self._efi_create_event,
            "SetTimer": self._efi_set_timer,
            "SignalEvent": self._efi_signal_event,
            "CloseEvent": self._efi_close_event,
            "CheckEvent": self._efi_check_event,
            "HandleProtocol": self._efi_handle_protocol,
            "InstallConfigurationTable": self._efi_noop_success,
            "LoadImage": self._efi_load_image,
            "StartImage": self._efi_start_image,
            "Exit": self._efi_exit,
            "ExitBootServices": self._efi_exit_boot_services,
            "GetNextMonotonicCount": self._efi_get_next_monotonic_count,
            "Stall": self._efi_stall,
            "SetWatchdogTimer": self._efi_noop_success,
            "LocateProtocol": self._efi_locate_protocol,
            "CalculateCrc32": self._efi_calculate_crc32,
            "CopyMem": self._efi_copy_mem,
            "SetMem": self._efi_set_mem,
        }
        for index, name in enumerate(_BOOT_SERVICE_NAMES):
            ptr = self._service_pointer(
                "BootServices." + name,
                service_impls.get(name),
                arity=_BOOT_SERVICE_ARITY.get(name, 0),
                marshaller=vm_marshallers.get(name),
            )
            _write_u64(alloc.memory, addr + EFI_TABLE_HEADER_SIZE + index * 8, ptr)
        self._finalize_table(alloc.memory, addr, size, EFI_BOOT_SERVICES_SIGNATURE)
        return addr

    def _build_runtime_services_table(self, alloc: _GuestAllocator) -> int:
        size = EFI_TABLE_HEADER_SIZE + len(_RUNTIME_SERVICE_NAMES) * 8
        addr = alloc.alloc(size, 8)
        service_impls = {
            "GetTime": self.get_time,
            "GetVariable": self.variables.get_variable,
            "GetNextVariableName": self.variables.next_variable_name,
            "SetVariable": self.variables.set_variable,
            "QueryVariableInfo": lambda attrs: (EFI_SUCCESS, 1 << 20, 1 << 20, 1024),
        }
        vm_marshallers = {
            "GetTime": self._efi_get_time,
            "GetNextHighMonotonicCount": self._efi_get_next_monotonic_count,
            "ResetSystem": self._efi_reset_system,
        }
        for index, name in enumerate(_RUNTIME_SERVICE_NAMES):
            ptr = self._service_pointer(
                "RuntimeServices." + name,
                service_impls.get(name),
                arity=_RUNTIME_SERVICE_ARITY.get(name, 0),
                marshaller=vm_marshallers.get(name),
            )
            _write_u64(alloc.memory, addr + EFI_TABLE_HEADER_SIZE + index * 8, ptr)
        self._finalize_table(alloc.memory, addr, size, EFI_RUNTIME_SERVICES_SIGNATURE)
        return addr

    def _build_protocols(self, alloc: _GuestAllocator, app_base: int, app_size: int) -> None:
        memory = alloc.memory
        self.image_handle = self._new_handle(alloc, "image")
        con_in_handle = self._new_handle(alloc, "console-in")
        con_out_handle = self._new_handle(alloc, "console-out")
        block_handle = self._new_handle(alloc, "block")
        fb_handle = self._new_handle(alloc, "framebuffer")

        con_in = alloc.alloc(24, 8)
        _write_u64(
            memory,
            con_in,
            self._service_pointer("ConIn.Reset", arity=2, marshaller=self._efi_noop_success),
        )
        _write_u64(
            memory,
            con_in + 8,
            self._service_pointer(
                "ConIn.ReadKeyStroke",
                self.text_in.read_key_stroke,
                arity=2,
                marshaller=self._efi_read_key_stroke,
            ),
        )
        wait_event_status, wait_event = self.create_event(EVT_NOTIFY_WAIT)
        _write_u64(memory, con_in + 16, wait_event if wait_event_status == EFI_SUCCESS else 0)
        self.install_protocol(
            con_in_handle,
            EFI_SIMPLE_TEXT_INPUT_PROTOCOL_GUID,
            con_in,
            self.text_in,
        )

        con_out_mode = alloc.alloc(24, 8)
        _write_u32(memory, con_out_mode, 1)
        _write_u32(memory, con_out_mode + 4, 0)
        _write_u32(memory, con_out_mode + 8, 0x07)
        _write_u32(memory, con_out_mode + 20, 1)
        con_out = alloc.alloc(88, 8)
        names = [
            ("Reset", None, 2, self._efi_noop_success),
            ("OutputString", self.text_out.output_string, 2, self._efi_output_string),
            ("TestString", lambda text: EFI_SUCCESS, 2, self._efi_noop_success),
            ("QueryMode", None, 4, None),
            ("SetMode", None, 2, self._efi_noop_success),
            ("SetAttribute", None, 2, self._efi_noop_success),
            ("ClearScreen", None, 1, self._efi_noop_success),
            ("SetCursorPosition", None, 3, self._efi_noop_success),
            ("EnableCursor", None, 2, self._efi_noop_success),
        ]
        for index, (name, fn, arity, marshaller) in enumerate(names):
            _write_u64(
                memory,
                con_out + index * 8,
                self._service_pointer(
                    "ConOut." + name, fn, arity=arity, marshaller=marshaller
                ),
            )
        _write_u64(memory, con_out + 72, con_out_mode)
        self.install_protocol(
            con_out_handle,
            EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID,
            con_out,
            self.text_out,
        )

        if self.block_io is not None:
            media = alloc.alloc(40, 8)
            _write_u32(memory, media, self.block_io.media_id)
            memory[media + 4] = 0  # RemovableMedia
            memory[media + 5] = 1  # MediaPresent
            _write_u32(memory, media + 12, self.block_io.block_size)
            _write_u64(memory, media + 24, self.block_io.last_block)
            block = alloc.alloc(48, 8)
            _write_u64(memory, block, 0x00010000)
            _write_u64(memory, block + 8, media)
            _write_u64(
                memory,
                block + 16,
                self._service_pointer("BlockIo.Reset", arity=2, marshaller=self._efi_noop_success),
            )
            _write_u64(
                memory,
                block + 24,
                self._service_pointer(
                    "BlockIo.ReadBlocks",
                    self.block_io.read_blocks,
                    arity=5,
                    marshaller=self._efi_block_read,
                ),
            )
            _write_u64(
                memory,
                block + 32,
                self._service_pointer(
                    "BlockIo.WriteBlocks",
                    self.block_io.write_blocks,
                    arity=5,
                    marshaller=self._efi_block_write,
                ),
            )
            _write_u64(
                memory,
                block + 40,
                self._service_pointer(
                    "BlockIo.FlushBlocks", lambda: EFI_SUCCESS, arity=1, marshaller=self._efi_noop_success
                ),
            )
            self.install_protocol(block_handle, EFI_BLOCK_IO_PROTOCOL_GUID, block, self.block_io)

            simple_fs = alloc.alloc(16, 8)
            _write_u64(memory, simple_fs, 0x00010000)
            _write_u64(memory, simple_fs + 8, self._service_pointer("SimpleFileSystem.OpenVolume", lambda: EFI_SUCCESS))
            self.install_protocol(
                block_handle,
                EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID,
                simple_fs,
                self.simple_file_system,
            )

        gop_info = alloc.alloc(36, 8)
        _write_u32(memory, gop_info, 0)
        _write_u32(memory, gop_info + 4, self.framebuffer.width)
        _write_u32(memory, gop_info + 8, self.framebuffer.height)
        _write_u32(memory, gop_info + 12, SVM_FB_FORMAT_XRGB8888)
        _write_u32(memory, gop_info + 32, self.framebuffer.width)
        gop_mode = alloc.alloc(40, 8)
        _write_u32(memory, gop_mode, 1)
        _write_u32(memory, gop_mode + 4, 0)
        _write_u64(memory, gop_mode + 8, gop_info)
        _write_u64(memory, gop_mode + 16, 36)
        _write_u64(memory, gop_mode + 24, self.framebuffer.pixel_base)
        _write_u64(memory, gop_mode + 32, self.framebuffer.pixel_size)
        gop = alloc.alloc(32, 8)
        _write_u64(memory, gop, self._service_pointer("Gop.QueryMode", self.gop.mode_info))
        _write_u64(memory, gop + 8, self._service_pointer("Gop.SetMode"))
        _write_u64(memory, gop + 16, self._service_pointer("Gop.BltFill", self.gop.blt_fill))
        _write_u64(memory, gop + 24, gop_mode)
        self.install_protocol(fb_handle, EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID, gop, self.gop)

        load_options = alloc.bytes(
            _utf16le_z(
                _read_cstr(memory, self._startup_data.cmdline_ptr).decode(
                    "utf-8",
                    "replace",
                )
                if self._startup_data.cmdline_ptr
                else ""
            ),
            2,
        )
        loaded = alloc.alloc(104, 8)
        _write_u32(memory, loaded, 0x1000)
        _write_u64(memory, loaded + 8, self.system_table_addr)
        _write_u64(memory, loaded + 16, block_handle if self.block_io is not None else 0)
        _write_u32(memory, loaded + 48, len(_utf16le_z("")))
        _write_u64(memory, loaded + 56, load_options)
        _write_u64(memory, loaded + 64, app_base)
        _write_u64(memory, loaded + 72, app_size)
        _write_u32(memory, loaded + 80, EFI_LOADER_CODE)
        _write_u32(memory, loaded + 84, EFI_LOADER_DATA)
        self.install_protocol(
            self.image_handle,
            EFI_LOADED_IMAGE_PROTOCOL_GUID,
            loaded,
            {
                "image_base": app_base,
                "image_size": app_size,
                "load_options": load_options,
            },
        )

        self._console_in_handle = con_in_handle
        self._console_out_handle = con_out_handle
        self._con_in_addr = con_in
        self._con_out_addr = con_out

    def _build_system_table(self, alloc: _GuestAllocator, dtb_addr: int) -> int:
        memory = alloc.memory
        vendor = alloc.char16("StackVM")
        self.boot_services_addr = self._build_boot_services_table(alloc)
        self.runtime_services_addr = self._build_runtime_services_table(alloc)

        self.configuration_table_addr = alloc.alloc(24, 8)
        memory[self.configuration_table_addr : self.configuration_table_addr + 16] = pack_guid(
            EFI_DTB_TABLE_GUID
        )
        _write_u64(memory, self.configuration_table_addr + 16, dtb_addr)

        addr = alloc.alloc(EFI_SYSTEM_TABLE_SIZE, 8)
        _write_u64(memory, addr + 0x18, vendor)
        _write_u32(memory, addr + 0x20, 1)
        _write_u64(memory, addr + 0x28, self._console_in_handle)
        _write_u64(memory, addr + 0x30, self._con_in_addr)
        _write_u64(memory, addr + 0x38, self._console_out_handle)
        _write_u64(memory, addr + 0x40, self._con_out_addr)
        _write_u64(memory, addr + 0x48, self._console_out_handle)
        _write_u64(memory, addr + 0x50, self._con_out_addr)
        _write_u64(memory, addr + 0x58, self.runtime_services_addr)
        _write_u64(memory, addr + 0x60, self.boot_services_addr)
        _write_u64(memory, addr + 0x68, 1)
        _write_u64(memory, addr + 0x70, self.configuration_table_addr)
        self._finalize_table(memory, addr, EFI_SYSTEM_TABLE_SIZE, EFI_SYSTEM_TABLE_SIGNATURE)
        self.system_table_addr = addr
        return addr

    def _patch_system_table_console_fields(self, memory: bytearray) -> None:
        addr = self.system_table_addr
        _write_u64(memory, addr + 0x28, self._console_in_handle)
        _write_u64(memory, addr + 0x30, self._con_in_addr)
        _write_u64(memory, addr + 0x38, self._console_out_handle)
        _write_u64(memory, addr + 0x40, self._con_out_addr)
        _write_u64(memory, addr + 0x48, self._console_out_handle)
        _write_u64(memory, addr + 0x50, self._con_out_addr)
        _write_u32(memory, addr + 16, 0)
        crc = zlib.crc32(bytes(memory[addr : addr + EFI_SYSTEM_TABLE_SIZE])) & 0xFFFFFFFF
        _write_u32(memory, addr + 16, crc)

    # ------------------------------------------------------------------
    # Launch path
    # ------------------------------------------------------------------

    def load_efi_app(
        self,
        app_image: Union[bytes, bytearray, StackVMExecutable],
        *,
        execute: bool = False,
    ) -> UefiLaunch:
        if isinstance(app_image, StackVMExecutable):
            executable = app_image
            pe_bytes = dumps_pe_executable(executable, entry=0)
            entry_offset = 0
        else:
            pe_bytes = bytes(app_image)
            executable = loads_pe_executable(pe_bytes)
            entry_offset = _entry_offset_from_pe(pe_bytes)

        image = plan_boot_image(
            self.vm_size,
            len(executable.memory),
            kernel_base=self.app_base,
            cmdline=self.cmdline,
            initramfs=self.initramfs,
            dtb=self.explicit_dtb,
            generate_dtb=self.generate_dtb and not self.explicit_dtb,
            core_count=self.core_count,
        )
        vm = VirtualMachine(self.vm_size, 0)
        if len(vm.memory) < self.vm_size:
            vm.memory.extend(b"\0" * (self.vm_size - len(vm.memory)))
        app_memory = bytearray(executable.memory)
        apply_base_fixups(app_memory, executable.base_relocations, self.app_base)
        vm.memory[self.app_base : self.app_base + len(app_memory)] = app_memory
        populate_startup_data(vm.memory, image, initramfs=self.initramfs)
        self._startup_data = read_startup_data(vm.memory, image.startup_data_addr)

        self.vm = vm
        self.apic = AdvProgIntCtl()
        self.timer = ProgrammableIntervalTimer(self.apic)
        vm.apic = self.apic
        vm.timer = self.timer
        self.mmio_machine.attach_to_vm(vm)
        self._init_free_ranges(image)
        self.boot_services_active = True

        subtable_start = (
            image.bootdata_base
            + STARTUP_DATA_SIZE
            + len(image.mem_map) * MEM_MAP_ENTRY_SIZE
            + len(image.cmdline_bytes)
            + len(image.dtb_bytes)
        )
        alloc = _GuestAllocator(vm.memory, _align_up(subtable_start, 8), image.bootdata_end)

        # Build protocol structs first.  The system-table address is patched into
        # LoadedImage after the table exists; console fields are patched after the
        # protocol addresses exist.
        self.system_table_addr = 0
        self._build_protocols(alloc, self.app_base, len(executable.memory))
        self._build_system_table(alloc, self._startup_data.dtb_ptr)
        self._patch_system_table_console_fields(vm.memory)

        loaded_status, loaded_addr = self.handle_protocol(
            self.image_handle,
            EFI_LOADED_IMAGE_PROTOCOL_GUID,
        )
        if loaded_status == EFI_SUCCESS:
            _write_u64(vm.memory, loaded_addr + 8, self.system_table_addr)

        flags = 255 | (0 << 8) | (VM_DISABLED << 10)
        vm.priv_lvl = 0
        vm.virt_mem_mode = VM_DISABLED
        vm.priority = 255
        vm.sys_regs[SVSR_FLAGS] = flags
        vm.ip = self.app_base + entry_offset
        vm.sp = self.vm_size
        vm.bp = self.vm_size
        vm.push(8, 0)
        vm.push(8, self.system_table_addr)
        vm.push(8, self.image_handle)

        self.launch = UefiLaunch(
            vm=vm,
            image=image,
            image_handle=self.image_handle,
            system_table_addr=self.system_table_addr,
            boot_services_addr=self.boot_services_addr,
            runtime_services_addr=self.runtime_services_addr,
            configuration_table_addr=self.configuration_table_addr,
            dtb_addr=self._startup_data.dtb_ptr,
            app_base=self.app_base,
            entry_addr=vm.ip,
            stack_args_addr=vm.sp,
        )
        if execute:
            # The firmware run loop dispatches in-VM EFIAPI service calls (which
            # target synthetic pointers outside RAM) instead of fetching them as
            # bytecode, so it is the correct driver for any real EFI image.
            self.run()
        return self.launch


def boot_uefi_app(
    app_image: Union[bytes, bytearray, StackVMExecutable],
    **kwargs,
) -> Tuple[VirtualMachine, UefiLaunch, MinimalUefiFirmware]:
    firmware = MinimalUefiFirmware(**kwargs)
    launch = firmware.load_efi_app(app_image)
    return launch.vm, launch, firmware


def run_uefi_app(
    app_image: Union[bytes, bytearray, StackVMExecutable],
    *,
    max_steps: int = 5_000_000,
    **kwargs,
) -> Tuple[VirtualMachine, UefiLaunch, MinimalUefiFirmware]:
    """Load *app_image* under the minimal firmware and run it to completion,
    dispatching its in-VM EFIAPI service calls.  Returns ``(vm, launch, firmware)``.

    This is the standardized-boot entry point for both a Linux-style EFI-stub
    kernel (which calls ``GetMemoryMap``/``ExitBootServices`` and continues) and a
    GRUB-style EFI bootloader (which ``LoadImage``/``StartImage`` chain-loads the
    next image)."""
    firmware = MinimalUefiFirmware(**kwargs)
    launch = firmware.load_efi_app(app_image)
    firmware.run(max_steps=max_steps)
    return launch.vm, launch, firmware
