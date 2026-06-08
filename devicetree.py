"""Flattened devicetree (FDT/DTB) read+write core — Workstream D1a.1.

This is a small, self-contained *libfdt-equivalent*: it parses and generates
flattened devicetree blobs (the binary ``.dtb`` form), with a builder API for
constructing a tree (add node / set typed properties) and a reader API used by
tests, the StackVM DT bindings (:mod:`StackVM.dt_bindings`), and the boot path
(:mod:`StackVM.boot`, D1a.3).

The on-disk layout follows the Devicetree Specification (v0.4):

  * a fixed 40-byte big-endian header (magic ``0xD00DFEED``, ``totalsize``,
    the offsets/sizes of the structure and strings blocks, the offset of the
    memory-reservation block, and version/last_comp_version),
  * a memory-reservation block: ``(address, size)`` u64 pairs terminated by an
    all-zero entry,
  * a structure block of 32-bit big-endian tokens
    (``FDT_BEGIN_NODE``/``END_NODE``/``PROP``/``NOP``/``END``), and
  * a deduplicated strings block holding the property names.

All multi-byte integers in a DTB are **big-endian** regardless of host. A DT
"cell" is a big-endian u32; a u64 is the high cell followed by the low cell,
which is exactly ``struct.pack(">Q", value)``.
"""

from __future__ import annotations

import struct as _struct
from collections import OrderedDict
from typing import Dict, Iterator, List, Optional, Sequence, Tuple, Union

# ---------------------------------------------------------------------------
# On-disk constants (Devicetree Specification v0.4)
# ---------------------------------------------------------------------------

FDT_MAGIC = 0xD00DFEED

# Structure-block tokens.
FDT_BEGIN_NODE = 0x00000001
FDT_END_NODE = 0x00000002
FDT_PROP = 0x00000003
FDT_NOP = 0x00000004
FDT_END = 0x00000009

# The format this writer emits.  Readers gate on ``last_comp_version``.
FDT_VERSION = 17
FDT_LAST_COMP_VERSION = 16

# struct fdt_header is ten big-endian u32s.
_HEADER_FORMAT = ">10I"
FDT_HEADER_SIZE = _struct.calcsize(_HEADER_FORMAT)  # 40

_U32_MASK = (1 << 32) - 1
_U64_MASK = (1 << 64) - 1


def _align4(value: int) -> int:
    return (value + 3) & ~3


# ---------------------------------------------------------------------------
# Typed property encoders / decoders
# ---------------------------------------------------------------------------
#
# A devicetree property value is an opaque byte string; its interpretation is
# by binding convention.  These helpers cover the common typed forms.


def encode_u32(value: int) -> bytes:
    return _struct.pack(">I", value & _U32_MASK)


def encode_u64(value: int) -> bytes:
    return _struct.pack(">Q", value & _U64_MASK)


def encode_string(value: str) -> bytes:
    return value.encode("utf-8") + b"\0"


def encode_stringlist(values: Sequence[str]) -> bytes:
    return b"".join(v.encode("utf-8") + b"\0" for v in values)


def encode_cells(values: Sequence[int]) -> bytes:
    """Encode a list of 32-bit cells (the ``<a b c>`` DTS form)."""
    return b"".join(encode_u32(v) for v in values)


def decode_u32(raw: bytes) -> int:
    if len(raw) != 4:
        raise ValueError("u32 property must be 4 bytes, got %d" % len(raw))
    return _struct.unpack(">I", raw)[0]


def decode_u64(raw: bytes) -> int:
    if len(raw) != 8:
        raise ValueError("u64 property must be 8 bytes, got %d" % len(raw))
    return _struct.unpack(">Q", raw)[0]


def decode_string(raw: bytes) -> str:
    # Strip the trailing NUL (and anything after it).
    return raw.split(b"\0", 1)[0].decode("utf-8")


def decode_stringlist(raw: bytes) -> List[str]:
    body = raw[:-1] if raw.endswith(b"\0") else raw
    if body == b"":
        return []
    return [part.decode("utf-8") for part in body.split(b"\0")]


def decode_cells(raw: bytes) -> List[int]:
    if len(raw) % 4 != 0:
        raise ValueError("cell property length %d is not a multiple of 4" % len(raw))
    return [_struct.unpack_from(">I", raw, i)[0] for i in range(0, len(raw), 4)]


# ---------------------------------------------------------------------------
# Builder/reader node type
# ---------------------------------------------------------------------------


class FdtNode:
    """One devicetree node: a name, ordered properties, and ordered children.

    Property *values* are stored as raw bytes (already encoded); the typed
    ``set_*`` setters and ``get_*`` accessors handle the conversions.
    """

    __slots__ = ("name", "props", "children")

    def __init__(self, name: str = ""):
        self.name = name
        self.props: "OrderedDict[str, bytes]" = OrderedDict()
        self.children: List["FdtNode"] = []

    # -- construction -------------------------------------------------------

    def add_subnode(self, name: str) -> "FdtNode":
        """Append a child node and return it.

        A node name must be unique among its siblings (the DT spec forbids two
        siblings with the same name).
        """
        if any(c.name == name for c in self.children):
            raise ValueError("duplicate child node name: %r" % name)
        node = FdtNode(name)
        self.children.append(node)
        return node

    def set_prop(self, name: str, value: bytes) -> "FdtNode":
        """Set a property to a raw byte value.  Returns *self* for chaining."""
        self.props[name] = bytes(value)
        return self

    def set_empty(self, name: str) -> "FdtNode":
        """Set a boolean/empty property (present with a zero-length value)."""
        return self.set_prop(name, b"")

    def set_u32(self, name: str, value: int) -> "FdtNode":
        return self.set_prop(name, encode_u32(value))

    def set_u64(self, name: str, value: int) -> "FdtNode":
        return self.set_prop(name, encode_u64(value))

    def set_string(self, name: str, value: str) -> "FdtNode":
        return self.set_prop(name, encode_string(value))

    def set_stringlist(self, name: str, values: Sequence[str]) -> "FdtNode":
        return self.set_prop(name, encode_stringlist(values))

    def set_cells(self, name: str, values: Sequence[int]) -> "FdtNode":
        return self.set_prop(name, encode_cells(values))

    def set_phandle(self, name: str, value: int) -> "FdtNode":
        return self.set_u32(name, value)

    # -- inspection ---------------------------------------------------------

    def get_prop(self, name: str) -> Optional[bytes]:
        return self.props.get(name)

    def has_prop(self, name: str) -> bool:
        return name in self.props

    def get_u32(self, name: str) -> int:
        return decode_u32(self._require(name))

    def get_u64(self, name: str) -> int:
        return decode_u64(self._require(name))

    def get_string(self, name: str) -> str:
        return decode_string(self._require(name))

    def get_stringlist(self, name: str) -> List[str]:
        return decode_stringlist(self._require(name))

    def get_cells(self, name: str) -> List[int]:
        return decode_cells(self._require(name))

    def get_child(self, name: str) -> Optional["FdtNode"]:
        for c in self.children:
            if c.name == name:
                return c
        return None

    def _require(self, name: str) -> bytes:
        raw = self.props.get(name)
        if raw is None:
            raise KeyError("node %r has no property %r" % (self.name, name))
        return raw

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return "FdtNode(%r, props=%d, children=%d)" % (
            self.name,
            len(self.props),
            len(self.children),
        )


# ---------------------------------------------------------------------------
# The flattened devicetree (tree + reservations + header metadata)
# ---------------------------------------------------------------------------


class FlattenedDeviceTree:
    """An in-memory devicetree that can be flattened to / parsed from a DTB."""

    def __init__(
        self,
        root: Optional[FdtNode] = None,
        reservations: Optional[List[Tuple[int, int]]] = None,
        boot_cpuid_phys: int = 0,
    ):
        self.root = root if root is not None else FdtNode("")
        # Memory-reservation entries: (address, size) physical regions the
        # kernel must not use (the all-zero terminator is implicit).
        self.reservations: List[Tuple[int, int]] = list(reservations or [])
        self.boot_cpuid_phys = boot_cpuid_phys

    # -- reservation block --------------------------------------------------

    def add_reservation(self, address: int, size: int) -> None:
        if size == 0:
            raise ValueError("a memory reservation must have a non-zero size")
        self.reservations.append((address & _U64_MASK, size & _U64_MASK))

    # -- path lookup --------------------------------------------------------

    def get_node(self, path: str) -> Optional[FdtNode]:
        """Resolve an absolute path (``"/"``, ``"/chosen"``, ``"/soc/serial@..."``)."""
        if not path.startswith("/"):
            raise ValueError("devicetree paths must be absolute (start with '/')")
        node = self.root
        for part in path.split("/"):
            if part == "":
                continue
            node = node.get_child(part)
            if node is None:
                return None
        return node

    def walk(self) -> Iterator[Tuple[str, FdtNode]]:
        """Yield ``(absolute_path, node)`` for every node, depth-first."""

        def _walk(node: FdtNode, prefix: str) -> Iterator[Tuple[str, FdtNode]]:
            path = "/" if node is self.root else prefix
            yield path, node
            base = "" if node is self.root else path
            for child in node.children:
                yield from _walk(child, base + "/" + child.name)

        yield from _walk(self.root, "/")

    # -- flatten ------------------------------------------------------------

    def to_dtb(self) -> bytes:
        """Serialise the tree to a flattened devicetree blob."""
        strings = bytearray()
        string_offsets: Dict[str, int] = {}

        def intern(name: str) -> int:
            cached = string_offsets.get(name)
            if cached is not None:
                return cached
            off = len(strings)
            string_offsets[name] = off
            strings.extend(name.encode("utf-8"))
            strings.append(0)
            return off

        struct_block = bytearray()

        def emit(node: FdtNode) -> None:
            struct_block.extend(encode_u32(FDT_BEGIN_NODE))
            struct_block.extend(node.name.encode("utf-8"))
            struct_block.append(0)
            while len(struct_block) % 4 != 0:
                struct_block.append(0)
            for prop_name, prop_val in node.props.items():
                struct_block.extend(encode_u32(FDT_PROP))
                struct_block.extend(encode_u32(len(prop_val)))
                struct_block.extend(encode_u32(intern(prop_name)))
                struct_block.extend(prop_val)
                while len(struct_block) % 4 != 0:
                    struct_block.append(0)
            for child in node.children:
                emit(child)
            struct_block.extend(encode_u32(FDT_END_NODE))

        emit(self.root)
        struct_block.extend(encode_u32(FDT_END))

        rsv_block = bytearray()
        for address, size in self.reservations:
            rsv_block.extend(_struct.pack(">QQ", address & _U64_MASK, size & _U64_MASK))
        rsv_block.extend(_struct.pack(">QQ", 0, 0))  # terminator

        # The header is 40 bytes (8-aligned), so the reservation block that
        # follows is 8-aligned; it is a multiple of 16 bytes, keeping the
        # structure block 4-aligned, and the structure block is 4-aligned by
        # construction so the strings block needs no extra padding.
        off_mem_rsvmap = FDT_HEADER_SIZE
        off_dt_struct = off_mem_rsvmap + len(rsv_block)
        off_dt_strings = off_dt_struct + len(struct_block)
        totalsize = off_dt_strings + len(strings)

        header = _struct.pack(
            _HEADER_FORMAT,
            FDT_MAGIC,
            totalsize,
            off_dt_struct,
            off_dt_strings,
            off_mem_rsvmap,
            FDT_VERSION,
            FDT_LAST_COMP_VERSION,
            self.boot_cpuid_phys & _U32_MASK,
            len(strings),
            len(struct_block),
        )
        return bytes(header) + bytes(rsv_block) + bytes(struct_block) + bytes(strings)

    # -- parse --------------------------------------------------------------

    @classmethod
    def from_dtb(cls, blob: Union[bytes, bytearray, memoryview]) -> "FlattenedDeviceTree":
        """Parse a flattened devicetree blob into a tree."""
        blob = bytes(blob)
        if len(blob) < FDT_HEADER_SIZE:
            raise ValueError("buffer too small to contain an FDT header")
        (
            magic,
            totalsize,
            off_dt_struct,
            off_dt_strings,
            off_mem_rsvmap,
            version,
            last_comp_version,
            boot_cpuid_phys,
            size_dt_strings,
            size_dt_struct,
        ) = _struct.unpack_from(_HEADER_FORMAT, blob, 0)

        if magic != FDT_MAGIC:
            raise ValueError("bad FDT magic %#010x (expected %#010x)" % (magic, FDT_MAGIC))
        if last_comp_version > FDT_VERSION:
            raise ValueError(
                "FDT last_comp_version %d is newer than supported %d"
                % (last_comp_version, FDT_VERSION)
            )
        if totalsize > len(blob):
            raise ValueError(
                "FDT totalsize %d exceeds buffer length %d" % (totalsize, len(blob))
            )

        # Memory-reservation block (terminated by an all-zero entry).
        reservations: List[Tuple[int, int]] = []
        pos = off_mem_rsvmap
        while True:
            address, size = _struct.unpack_from(">QQ", blob, pos)
            pos += 16
            if address == 0 and size == 0:
                break
            reservations.append((address, size))

        strings = blob[off_dt_strings : off_dt_strings + size_dt_strings]

        def string_at(offset: int) -> str:
            end = strings.index(b"\0", offset)
            return strings[offset:end].decode("utf-8")

        struct_end = off_dt_struct + size_dt_struct
        pos = off_dt_struct
        root: Optional[FdtNode] = None
        stack: List[FdtNode] = []
        seen_end = False

        while pos < struct_end:
            (token,) = _struct.unpack_from(">I", blob, pos)
            pos += 4
            if token == FDT_BEGIN_NODE:
                name_end = blob.index(b"\0", pos)
                name = blob[pos:name_end].decode("utf-8")
                pos = _align4(name_end + 1)
                node = FdtNode(name)
                if stack:
                    stack[-1].children.append(node)
                elif root is None:
                    root = node
                else:
                    raise ValueError("FDT has more than one root node")
                stack.append(node)
            elif token == FDT_END_NODE:
                if not stack:
                    raise ValueError("FDT_END_NODE without a matching FDT_BEGIN_NODE")
                stack.pop()
            elif token == FDT_PROP:
                prop_len, name_off = _struct.unpack_from(">II", blob, pos)
                pos += 8
                value = bytes(blob[pos : pos + prop_len])
                pos = _align4(pos + prop_len)
                if not stack:
                    raise ValueError("FDT_PROP outside of any node")
                stack[-1].props[string_at(name_off)] = value
            elif token == FDT_NOP:
                continue
            elif token == FDT_END:
                seen_end = True
                break
            else:
                raise ValueError("unknown FDT token %#010x at offset %d" % (token, pos - 4))

        if not seen_end:
            raise ValueError("FDT structure block missing FDT_END token")
        if stack:
            raise ValueError("FDT structure block has unbalanced node tokens")
        if root is None:
            raise ValueError("FDT structure block has no root node")

        return cls(root, reservations, boot_cpuid_phys)
