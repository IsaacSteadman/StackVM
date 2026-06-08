"""StackVM platform devicetree bindings — Workstream D1a.2.

This module is the machine-readable counterpart of
``StackVM/Documentation/Devicetree.html``: it defines the StackVM *platform
bindings* (the ``compatible`` strings, the standard node layout, and the
property conventions) and provides :func:`build_stackvm_fdt`, the reference
implementation that emits a binding-conformant flattened devicetree using the
:mod:`StackVM.devicetree` core (D1a.1).

The boot path (:mod:`StackVM.boot`) will call this to describe the configured
machine and point ``StartupData.dtb`` at the result; that wiring + the optional
``StartupData`` slimming is tracked separately as D1a.3.

Bindings overview (see the HTML doc for the normative text)::

    / {
        #address-cells = <2>;  #size-cells = <2>;
        compatible = "stackvm,virt";
        chosen { bootargs; stdout-path; linux,initrd-start/-end }
        memory@<base> { device_type="memory"; reg=<base size ...> }
        reserved-memory { kernel@..; bootdata@.. (no-map) }
        cpus { cpu@N { reg = <SVSR_CORE_ID> } }  (one per core)
        soc {
            interrupt-controller@ffff1000 { stackvm,intc; #interrupt-cells=<1> }
            serial@ffff0000 { stackvm,uart;  interrupts=<1> }
            rtc@ffff2000    { stackvm,rtc;   interrupts=<3> }
            virtio@ffff3000 { virtio,mmio;   interrupts=<2> }  (block)
            virtio@ffff4000 { virtio,mmio;   interrupts=<4> }  (net)
        }
    };

Addresses span the full 64-bit physical space (MMIO lives at 0xFFFF0000+), so
the root and ``/soc`` use ``#address-cells = <2>`` / ``#size-cells = <2>``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .devicetree import FdtNode, FlattenedDeviceTree, encode_u64
from .mmio import (
    SVM_IRQ_RTC,
    SVM_IRQ_UART0,
    SVM_IRQ_VIRTIO_BLK0,
    SVM_IRQ_VIRTIO_NET0,
    SVM_MMIO_IC_BASE,
    SVM_MMIO_RTC_BASE,
    SVM_MMIO_UART0_BASE,
    SVM_MMIO_VIRTIO_BLK0_BASE,
    SVM_MMIO_VIRTIO_NET0_BASE,
    SVM_MMIO_WINDOW_SIZE,
)

# ---------------------------------------------------------------------------
# Binding constants (the normative names live in the HTML doc)
# ---------------------------------------------------------------------------

# Machine / root node.
COMPAT_MACHINE = "stackvm,virt"
MODEL = "StackVM Virtual Machine"

# Per-core CPU nodes.
COMPAT_CPU = "stackvm,cpu"

# SoC devices.
COMPAT_INTC = "stackvm,intc"  # MMIO interrupt controller (D5)
COMPAT_UART = "stackvm,uart"  # MMIO serial console (D5)
COMPAT_RTC = "stackvm,rtc"  # MMIO real-time clock (D5)
COMPAT_VIRTIO_MMIO = "virtio,mmio"  # virtio-blk / virtio-net transport (D5)
COMPAT_FRAMEBUFFER = "simple-framebuffer"  # reserved for D1b.3 (not yet a device)
COMPAT_SIMPLE_BUS = "simple-bus"

# The single interrupt controller gets a fixed phandle so device nodes can name
# it as their ``interrupt-parent``.
PHANDLE_INTC = 1

# Address/size cell counts for the root and the /soc bus.  Physical addresses
# are 64-bit, so two cells each.
ROOT_ADDRESS_CELLS = 2
ROOT_SIZE_CELLS = 2

# The interrupt controller uses a single cell per interrupt (the IRQ line).
INTC_INTERRUPT_CELLS = 1


# ---------------------------------------------------------------------------
# Device description
# ---------------------------------------------------------------------------


@dataclass
class DtDevice:
    """A SoC MMIO device to enumerate under ``/soc``."""

    node_name: str  # unit-addressed name, e.g. "serial@ffff0000"
    compatible: Tuple[str, ...]
    reg_base: int
    reg_size: int
    interrupts: Tuple[int, ...] = ()
    is_intc: bool = False
    extra_props: Dict[str, bytes] = field(default_factory=dict)


def _hex_unit(base: int) -> str:
    """Devicetree unit address: lowercase hex, no ``0x`` prefix."""
    return "%x" % base


def default_soc_devices() -> List[DtDevice]:
    """The standard StackVM D5 MMIO device set (mirrors ``stackvm_mmio.h``)."""
    win = SVM_MMIO_WINDOW_SIZE
    return [
        DtDevice(
            "interrupt-controller@" + _hex_unit(SVM_MMIO_IC_BASE),
            (COMPAT_INTC,),
            SVM_MMIO_IC_BASE,
            win,
            is_intc=True,
        ),
        DtDevice(
            "serial@" + _hex_unit(SVM_MMIO_UART0_BASE),
            (COMPAT_UART,),
            SVM_MMIO_UART0_BASE,
            win,
            interrupts=(SVM_IRQ_UART0,),
        ),
        DtDevice(
            "rtc@" + _hex_unit(SVM_MMIO_RTC_BASE),
            (COMPAT_RTC,),
            SVM_MMIO_RTC_BASE,
            win,
            interrupts=(SVM_IRQ_RTC,),
        ),
        DtDevice(
            "virtio@" + _hex_unit(SVM_MMIO_VIRTIO_BLK0_BASE),
            (COMPAT_VIRTIO_MMIO,),
            SVM_MMIO_VIRTIO_BLK0_BASE,
            win,
            interrupts=(SVM_IRQ_VIRTIO_BLK0,),
        ),
        DtDevice(
            "virtio@" + _hex_unit(SVM_MMIO_VIRTIO_NET0_BASE),
            (COMPAT_VIRTIO_MMIO,),
            SVM_MMIO_VIRTIO_NET0_BASE,
            win,
            interrupts=(SVM_IRQ_VIRTIO_NET0,),
        ),
    ]


def _reg_cells(base: int, size: int) -> bytes:
    """A ``reg`` entry under #address-cells=2 / #size-cells=2."""
    return encode_u64(base) + encode_u64(size)


# ---------------------------------------------------------------------------
# Deriving DT regions from a D1 boot memory map
# ---------------------------------------------------------------------------

# RAM-backed memory-map types (everything that is physical DRAM the kernel sees,
# as opposed to the low reserved/firmware guard region).
_RAM_BACKED = None  # populated lazily to avoid a hard import cycle at module load


def _ram_backed_types() -> frozenset:
    global _RAM_BACKED
    if _RAM_BACKED is None:
        from .boot import (
            SVMEM_BOOTDATA,
            SVMEM_INITRAMFS,
            SVMEM_KERNEL,
            SVMEM_RAM,
        )

        _RAM_BACKED = frozenset(
            {SVMEM_RAM, SVMEM_KERNEL, SVMEM_INITRAMFS, SVMEM_BOOTDATA}
        )
    return _RAM_BACKED


def dt_regions_from_mem_map(
    mem_map,
) -> Tuple[List[Tuple[int, int]], List[Tuple[str, int, int]]]:
    """Split a D1 boot memory map into (/memory regions, /reserved-memory regions).

    ``/memory`` advertises every RAM-backed region (contiguous runs coalesced);
    ``/reserved-memory`` carves out the in-use kernel image and bootdata so the
    kernel does not allocate over them.  *mem_map* is the contiguous, sorted
    list of :class:`StackVM.boot.MemMapEntry` produced by ``build_boot_image``.
    """
    from .boot import SVMEM_BOOTDATA, SVMEM_KERNEL

    ram_types = _ram_backed_types()
    memory: List[Tuple[int, int]] = []
    for entry in mem_map:
        if entry.type not in ram_types:
            continue
        if memory and memory[-1][0] + memory[-1][1] == entry.base:
            base, size = memory[-1]
            memory[-1] = (base, size + entry.size)
        else:
            memory.append((entry.base, entry.size))

    reserved: List[Tuple[str, int, int]] = []
    for entry in mem_map:
        if entry.type == SVMEM_KERNEL:
            reserved.append(("kernel", entry.base, entry.size))
        elif entry.type == SVMEM_BOOTDATA:
            reserved.append(("bootdata", entry.base, entry.size))
    return memory, reserved


# ---------------------------------------------------------------------------
# The reference binding builder
# ---------------------------------------------------------------------------


def build_stackvm_fdt(
    *,
    memory_regions: Sequence[Tuple[int, int]],
    core_count: int,
    boot_core_id: int = 0,
    cmdline: str = "",
    initramfs_base: int = 0,
    initramfs_size: int = 0,
    reserved_regions: Optional[Sequence[Tuple[str, int, int]]] = None,
    devices: Optional[Sequence[DtDevice]] = None,
    stdout_path: Optional[str] = None,
    model: str = MODEL,
) -> FlattenedDeviceTree:
    """Build a binding-conformant :class:`FlattenedDeviceTree` for a machine.

    *memory_regions* / *reserved_regions* are typically produced by
    :func:`dt_regions_from_mem_map`.  *devices* defaults to
    :func:`default_soc_devices`.  *stdout_path* defaults to the first
    UART-compatible device's full path.
    """
    if core_count < 1:
        raise ValueError("core_count must be >= 1")
    if not memory_regions:
        raise ValueError("at least one /memory region is required")
    if devices is None:
        devices = default_soc_devices()

    fdt = FlattenedDeviceTree(boot_cpuid_phys=boot_core_id)
    root = fdt.root
    root.set_u32("#address-cells", ROOT_ADDRESS_CELLS)
    root.set_u32("#size-cells", ROOT_SIZE_CELLS)
    root.set_string("compatible", COMPAT_MACHINE)
    root.set_string("model", model)

    # /memory
    first_base = memory_regions[0][0]
    memory = root.add_subnode("memory@" + _hex_unit(first_base))
    memory.set_string("device_type", "memory")
    memory.set_prop(
        "reg", b"".join(_reg_cells(base, size) for base, size in memory_regions)
    )

    # /reserved-memory
    if reserved_regions:
        resv = root.add_subnode("reserved-memory")
        resv.set_u32("#address-cells", ROOT_ADDRESS_CELLS)
        resv.set_u32("#size-cells", ROOT_SIZE_CELLS)
        resv.set_empty("ranges")
        for name, base, size in reserved_regions:
            child = resv.add_subnode(name + "@" + _hex_unit(base))
            child.set_prop("reg", _reg_cells(base, size))
            child.set_empty("no-map")

    # /cpus
    cpus = root.add_subnode("cpus")
    cpus.set_u32("#address-cells", 1)
    cpus.set_u32("#size-cells", 0)
    for core in range(core_count):
        cpu = cpus.add_subnode("cpu@" + _hex_unit(core))
        cpu.set_string("device_type", "cpu")
        cpu.set_string("compatible", COMPAT_CPU)
        cpu.set_u32("reg", core)

    # /soc
    soc = root.add_subnode("soc")
    soc.set_u32("#address-cells", ROOT_ADDRESS_CELLS)
    soc.set_u32("#size-cells", ROOT_SIZE_CELLS)
    soc.set_string("compatible", COMPAT_SIMPLE_BUS)
    soc.set_empty("ranges")

    intc_path: Optional[str] = None
    for dev in devices:
        node = soc.add_subnode(dev.node_name)
        if len(dev.compatible) == 1:
            node.set_string("compatible", dev.compatible[0])
        else:
            node.set_stringlist("compatible", list(dev.compatible))
        node.set_prop("reg", _reg_cells(dev.reg_base, dev.reg_size))
        if dev.is_intc:
            node.set_empty("interrupt-controller")
            node.set_u32("#interrupt-cells", INTC_INTERRUPT_CELLS)
            node.set_phandle("phandle", PHANDLE_INTC)
            intc_path = "/soc/" + dev.node_name
        if dev.interrupts:
            node.set_cells("interrupts", list(dev.interrupts))
            node.set_phandle("interrupt-parent", PHANDLE_INTC)
        for prop_name, prop_val in dev.extra_props.items():
            node.set_prop(prop_name, prop_val)

    # /chosen
    chosen = root.add_subnode("chosen")
    chosen.set_string("bootargs", cmdline)
    if stdout_path is None:
        for dev in devices:
            if COMPAT_UART in dev.compatible:
                stdout_path = "/soc/" + dev.node_name
                break
    if stdout_path is not None:
        chosen.set_string("stdout-path", stdout_path)
    if initramfs_size:
        chosen.set_u64("linux,initrd-start", initramfs_base)
        chosen.set_u64("linux,initrd-end", initramfs_base + initramfs_size)

    return fdt
