"""Phased boot/runtime milestones (Workstream E2).

Each milestone is a small, self-contained *mini-kernel image* that proves one
capability of the StackVM platform end-to-end on the Python reference emulator,
so the capability can be validated in CI without the full (out-of-scope) Linux
source.  The eight milestones mirror the plan:

  1. Toolchain-built freestanding image boots in kernel mode and prints via the
     paravirt console (D1 boot + D4 paravirt).
  2. Timer IRQ fires and is serviced under correct enable/priority gating
     (D2 + D3).
  3. MMU enabled; a deliberate page fault is delivered to a handler and the
     faulting access is retried after demand-mapping (regression-lock).
  4. Early printk over the MMIO UART serial console (D5).
  5. initramfs handed off via StartupData is located and an embedded init
     program ("/bin/sh") is entered (D1 initramfs).  *Reduced:* the full
     cpio/dynamic-loader/libc path is deferred per C3/B2.
  6. Block-backed persistent root fs over MMIO virtio-blk, persisting across two
     kernel runs (D5).
  7. SMP: a secondary core is brought online; an IPI and a remote-interrupt TLB
     shootdown are serviced + acknowledged between cores (D6 + D7).
  8. Networking: virtio-net TX and RX through a host backend (D5).

Every milestone is a real run of hand-assembled StackVM bytecode (the
"mini-kernel image") on a VM in kernel-entry state, driving the same device
models the dedicated subsystem tests use.  ``run_milestone(n)`` returns a
:class:`MilestoneResult`; ``run_all_milestones()`` runs the whole sequence.  The
boot ABI these images target is documented in
``StackVM/Documentation/BootAbi.html``.
"""

from __future__ import annotations

import os
import struct
import tempfile
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from ..code_gen.stackvm_binutils.emit_load_i_const import emit_load_i_const
from .boot import boot_kernel, read_startup_data
from .paravirt import PVH_CONSOLE_WRITE, ParavirtDeviceSet
from .PyStackVM import (
    AdvProgIntCtl,
    BC_ADD8,
    BC_ADD1,
    BC_HLT,
    BC_INVTLB,
    BC_JMP,
    BC_LOAD,
    BC_NOP,
    BC_RET_E,
    BC_STOR,
    BCCE_IS_INT,
    BCRE_IS_INT,
    BCR_ABS_A8,
    BCR_ABS_S8,
    BCR_SYSREG,
    BC_CALL_E,
    FLAGS_INT_ENABLE,
    INT_PAGE_FAULT,
    INT_PARAVIRT,
    INT_TIMER,
    INT_TLB_SHOOTDOWN,
    INT_TLB_SHOOTDOWN_DONE,
    INVTLB_ACK,
    INVTLB_F_ASYNC,
    INVTLB_F_REMOTE_INT,
    INVTLB_LOCAL,
    MultiCoreMachine,
    ProgrammableIntervalTimer,
    SVSR_CYCLE_COUNT,
    SVSR_INT_ARG0,
    SVSR_INT_ARG1,
    SVSR_INT_ARG2,
    SVSR_INT_ARG3,
    SVSR_IPI,
    SVSR_ISR,
    SVSR_KERNEL_TLPTR,
    SVSR_PAGE_FAULT_ADDR,
    SVSR_SDP,
    SVSR_USER_TLPTR,
    TLBP_R,
    VM_4_LVL_9_BIT,
    VM_DISABLED,
    VirtualMachine,
)
from .mmio import (
    HostBlockImage,
    IC_REG_ENABLE,
    InMemoryNetBackend,
    MmioBus,
    MmioInterruptController,
    SVM_IRQ_VIRTIO_BLK0,
    SVM_IRQ_VIRTIO_NET0,
    SVM_MMIO_IC_BASE,
    SVM_MMIO_UART0_BASE,
    SVM_MMIO_VIRTIO_BLK0_BASE,
    SVM_MMIO_VIRTIO_NET0_BASE,
    UART_REG_DATA,
    UART_REG_STATUS,
    UART_STATUS_TX_READY,
    UartSerialDevice,
    VIRTIO_BLK_S_OK,
    VIRTIO_BLK_SECTOR_SIZE,
    VIRTIO_BLK_T_IN,
    VIRTIO_BLK_T_OUT,
    VIRTIO_NET_HDR_SIZE,
    VIRTIO_REG_QUEUE_AVAIL,
    VIRTIO_REG_QUEUE_DESC,
    VIRTIO_REG_QUEUE_NOTIFY,
    VIRTIO_REG_QUEUE_NUM,
    VIRTIO_REG_QUEUE_SEL,
    VIRTIO_REG_QUEUE_USED,
    VIRTQ_DESC_F_NEXT,
    VIRTQ_DESC_F_WRITE,
    VIRTQ_DESC_SIZE,
    VirtioBlockDevice,
    VirtioNetDevice,
)
from .syscalls import SyscallDispatcher

_U64 = 0xFFFFFFFFFFFFFFFF
# IRET = RET_E with IS_SYS (0x80) | IS_INT.
IRET_BYTE = 0x80 | BCRE_IS_INT
# Page-table entry permission bits (see walk_page / VirtualMemory.html).
PTE_VALID = 0x1
PTE_WRITE = 0x2
PTE_EXEC = 0x4
PTE_HUGE = 0x10


# ---------------------------------------------------------------------------
# Bytecode emission helpers
# ---------------------------------------------------------------------------

_SZ_CLS = {1: 0, 2: 1, 4: 2, 8: 3}


def _sz_flag(size: int) -> int:
    """Operand-byte size field (bits 5-7) for a memory access of *size* bytes."""
    return _SZ_CLS[size] << 5


def emit_push_imm(code: bytearray, value: int, size: int = 8) -> None:
    emit_load_i_const(code, value & _U64, sz_cls=_SZ_CLS[size])


def emit_load_abs(code: bytearray, addr: int, size: int = 8) -> None:
    code += bytes([BC_LOAD, BCR_ABS_A8 | _sz_flag(size)]) + (addr & _U64).to_bytes(8, "little")


def emit_store_abs(code: bytearray, addr: int, size: int = 8) -> None:
    code += bytes([BC_STOR, BCR_ABS_A8 | _sz_flag(size)]) + (addr & _U64).to_bytes(8, "little")


def emit_store_imm(code: bytearray, addr: int, value: int, size: int = 8) -> None:
    emit_push_imm(code, value, size)
    emit_store_abs(code, addr, size)


def emit_load_sysreg(code: bytearray, reg: int, size: int = 8) -> None:
    code += bytes([BC_LOAD, BCR_SYSREG | _sz_flag(size), reg])


def emit_store_sysreg(code: bytearray, reg: int, size: int = 8) -> None:
    code += bytes([BC_STOR, BCR_SYSREG | _sz_flag(size), reg])


def emit_load_indirect(code: bytearray, size: int = 8) -> None:
    """Pop an address, push the *size*-byte value loaded from it (LOAD ABS_S8)."""
    code += bytes([BC_LOAD, BCR_ABS_S8 | _sz_flag(size)])


def emit_hlt(code: bytearray) -> None:
    code += bytes([BC_HLT])


def emit_iret(code: bytearray) -> None:
    code += bytes([BC_RET_E, IRET_BYTE])


def emit_pv_hypercall(
    code: bytearray, number: int, a0: int = 0, a1: int = 0, a2: int = 0, a3: int = 0
) -> None:
    """Emit a paravirt doorbell call.  Pushes the six-u64 hypercall frame (arg3
    .. number, so ``number`` lands on top) and rings INT_PARAVIRT."""
    for value in (a3, a2, a1, a0, 32, number):  # 32 == PV_ARG_BYTES
        emit_push_imm(code, value, 8)
    code += bytes([BC_CALL_E, BCCE_IS_INT, INT_PARAVIRT])


# ---------------------------------------------------------------------------
# Small kernel "loader"
# ---------------------------------------------------------------------------


def _make_kernel_vm(
    vm_size: int,
    blobs: Dict[int, bytes],
    entry: int,
    *,
    enable_interrupts: bool = False,
    isr_base: Optional[int] = None,
    mmio_bus: Optional[object] = None,
    apic: Optional[object] = None,
    kernel_tlptr: Optional[int] = None,
    virt_mode: int = VM_DISABLED,
    sp: Optional[int] = None,
) -> VirtualMachine:
    """Build a VM in kernel-entry state with *blobs* placed at fixed addresses.

    This is the minimal "loader" the subsystem mini-kernels share: it mirrors
    the architectural kernel-entry contract (priv 0, kernel stack at the top of
    RAM) without the full StartupData handoff, which milestone 1 exercises via
    the real :func:`boot_kernel` path.
    """
    vm = VirtualMachine(vm_size, 0)
    for addr, data in blobs.items():
        vm.memory[addr : addr + len(data)] = data
    vm.ip = entry
    vm.sp = vm.bp = vm_size if sp is None else sp
    vm.running = 1
    if isr_base is not None:
        vm.sys_regs[SVSR_ISR] = isr_base
    if kernel_tlptr is not None:
        vm.sys_regs[SVSR_KERNEL_TLPTR] = kernel_tlptr
    if mmio_bus is not None:
        vm.attach_mmio_bus(mmio_bus)
    if apic is not None:
        vm.apic = apic
    flags = 0xFF | (FLAGS_INT_ENABLE if enable_interrupts else 0) | (virt_mode << 10)
    vm.set_flags(flags)
    return vm


def _install_isr(memory: bytearray, isr_base: int, vec: int, handler: int, run_flags: int = 0x10) -> None:
    base = isr_base + vec * 16
    memory[base : base + 8] = (run_flags & _U64).to_bytes(8, "little")
    memory[base + 8 : base + 16] = (handler & _U64).to_bytes(8, "little")


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class MilestoneResult:
    number: int
    name: str
    passed: bool
    detail: Dict[str, object] = field(default_factory=dict)

    def __str__(self) -> str:  # pragma: no cover - convenience only
        status = "PASS" if self.passed else "FAIL"
        return f"[{status}] milestone {self.number}: {self.name}"


# ---------------------------------------------------------------------------
# Milestone 1 — boot in kernel mode + paravirt console
# ---------------------------------------------------------------------------


def milestone_1_boot_console(vm_size: int = 1 << 20) -> MilestoneResult:
    """A freestanding image is booted via the StartupData ABI and prints a
    banner through the paravirt console doorbell."""
    message = b"Hello from StackVM milestone 1\n"
    msg_addr = vm_size - 0x800

    code = bytearray()
    emit_pv_hypercall(code, PVH_CONSOLE_WRITE, a0=msg_addr, a1=len(message))
    emit_hlt(code)

    vm, image = boot_kernel(
        bytes(code),
        vm_size=vm_size,
        kernel_base=0x1000,
        cmdline="console=pv milestone=1",
    )
    vm.memory[msg_addr : msg_addr + len(message)] = message

    console = bytearray()
    SyscallDispatcher([ParavirtDeviceSet(console_output=console)]).attach_to_py_vm(vm)
    vm.execute()

    sd = read_startup_data(vm.memory, vm.sys_regs[SVSR_SDP])
    passed = (
        bytes(console) == message
        and vm.priv_lvl == 0
        and vm.virt_mem_mode == VM_DISABLED
        and sd.is_valid
        and vm.running == 0
    )
    return MilestoneResult(
        1,
        "boot in kernel mode + paravirt console",
        passed,
        {
            "console": bytes(console),
            "startupdata_valid": sd.is_valid,
            "entry_priv": vm.priv_lvl,
            "mmu_off": vm.virt_mem_mode == VM_DISABLED,
        },
    )


# ---------------------------------------------------------------------------
# Milestone 2 — timer IRQ under enable/priority gating
# ---------------------------------------------------------------------------


def _timer_handler(counter_addr: int) -> bytes:
    h = bytearray()
    emit_load_abs(h, counter_addr, 1)
    emit_push_imm(h, 1, 1)
    h += bytes([BC_ADD1])
    emit_store_abs(h, counter_addr, 1)
    emit_iret(h)
    return bytes(h)


def _run_timer_scenario(vm_size, isr_base, handler_addr, counter_addr, *, enable):
    main = bytes([BC_NOP] * 64 + [BC_HLT])
    vm = _make_kernel_vm(
        vm_size,
        {0: main, handler_addr: _timer_handler(counter_addr)},
        entry=0,
        isr_base=isr_base,
        enable_interrupts=enable,
    )
    _install_isr(vm.memory, isr_base, INT_TIMER, handler_addr, run_flags=0x10)
    apic = AdvProgIntCtl()
    timer = ProgrammableIntervalTimer(apic, interval=8, enabled=True)
    vm.execute_with_interrupts(apic, timer)
    return vm, apic, timer


def milestone_2_timer(vm_size: int = 0x10000) -> MilestoneResult:
    isr_base, handler_addr, counter = 0x4000, 0x6000, 0x3000

    on_vm, on_apic, on_timer = _run_timer_scenario(
        vm_size, isr_base, handler_addr, counter, enable=True
    )
    serviced = on_vm.memory[counter] >= 1 and on_timer.fire_count >= 1

    off_vm, off_apic, off_timer = _run_timer_scenario(
        vm_size, isr_base, handler_addr, counter, enable=False
    )
    held = (
        off_vm.memory[counter] == 0
        and off_timer.fire_count >= 1
        and off_apic.pending()
        and off_apic.which_int == INT_TIMER
    )

    return MilestoneResult(
        2,
        "timer IRQ serviced under enable/priority gating",
        serviced and held,
        {
            "ticks_when_enabled": on_vm.memory[counter],
            "fires_when_enabled": on_timer.fire_count,
            "ticks_when_disabled": off_vm.memory[counter],
            "pending_when_disabled": off_apic.pending(),
        },
    )


# ---------------------------------------------------------------------------
# Milestone 3 — MMU page fault delivered + handled (demand paging)
# ---------------------------------------------------------------------------

# Physical layout (all < 2 MiB so the identity huge-page maps it).
_M3_ENTRY = 0x1000
_M3_ISR = 0x10000
_M3_HANDLER = 0x12000
_M3_COUNTER = 0x13000  # 1 byte: page-fault count
_M3_FAULT_ADDR = 0x13008  # 8 bytes: faulting vaddr recorded by the handler
_M3_RESULT = 0x13010  # 8 bytes: value read back through the demand-mapped page
_M3_P4 = 0x20000
_M3_P3 = 0x21000
_M3_P2 = 0x22000
_M3_P1 = 0x23000  # level-1 table for the 2 MiB slot containing the fault target
_M3_FRAME = 0x24000  # physical frame the handler maps in
_M3_FAULT_VADDR = 0x200000  # first address above the identity huge-page
_M3_SENTINEL = 0x5A5AA5A5
_M3_VM_SIZE = 0x200000


def _m3_paging(memory: bytearray) -> int:
    """Identity-map [0, 2 MiB) with one huge PTE and leave a level-1 table for
    the [2 MiB, 4 MiB) slot whose leaf entry starts *not present*."""
    rwx = PTE_VALID | PTE_WRITE | PTE_EXEC
    memory[_M3_P4 : _M3_P4 + 8] = (_M3_P3 | rwx).to_bytes(8, "little")
    memory[_M3_P3 : _M3_P3 + 8] = (_M3_P2 | rwx).to_bytes(8, "little")
    # p2[0]: huge identity map of the low 2 MiB (covers code/stack/tables).
    memory[_M3_P2 : _M3_P2 + 8] = (0 | rwx | PTE_HUGE).to_bytes(8, "little")
    # p2[1]: points at a level-1 table for the slot holding the fault target.
    memory[_M3_P2 + 8 : _M3_P2 + 16] = (_M3_P1 | rwx).to_bytes(8, "little")
    # p1[0] (leaf for 0x200000) left zero == not present -> demand fault.
    return _M3_P4 | rwx


def _m3_handler() -> bytes:
    h = bytearray()
    # Record the architectural faulting address (SVSR_INT_ARG3 carries it).
    emit_load_sysreg(h, SVSR_INT_ARG3, 8)
    emit_store_abs(h, _M3_FAULT_ADDR, 8)
    # fault_count += 1
    emit_load_abs(h, _M3_COUNTER, 1)
    emit_push_imm(h, 1, 1)
    h += bytes([BC_ADD1])
    emit_store_abs(h, _M3_COUNTER, 1)
    # Demand-map the page: p1[0] = frame | valid|write|exec.
    emit_store_imm(h, _M3_P1, _M3_FRAME | PTE_VALID | PTE_WRITE | PTE_EXEC, 8)
    emit_iret(h)
    return bytes(h)


def _m3_main() -> bytes:
    c = bytearray()
    # *(0x200000) = SENTINEL  -> faults, handler maps, instruction retries.
    emit_store_imm(c, _M3_FAULT_VADDR, _M3_SENTINEL, 8)
    # result = *(0x200000)    -> now mapped, reads SENTINEL back.
    emit_load_abs(c, _M3_FAULT_VADDR, 8)
    emit_store_abs(c, _M3_RESULT, 8)
    emit_hlt(c)
    return bytes(c)


def _run_with_sync_faults(vm: VirtualMachine, max_steps: int = 200000) -> int:
    """Run *vm*, delivering synchronous CPU faults (page/protection) to the ISR
    table instead of aborting.  A faulting load/store rewinds ``ip`` to the
    faulting instruction, so after the handler IRETs the access is retried.
    Returns the number of faults delivered."""
    pending: List[tuple] = []

    def trap_shim(int_n, a0=0, a1=0, a2=0, a3=0):
        vm.sys_regs[SVSR_PAGE_FAULT_ADDR] = a3 & _U64
        pending.append((int_n, a0, a1, a2, a3))

    vm.trap = trap_shim
    delivered = 0
    steps = 0
    while vm.running and steps < max_steps:
        steps += 1
        code = vm.get_instr_dat(1, 0)
        if code is None:
            if not pending:
                break
        else:
            vm.BC_Dispatch[code](vm)
            vm.sys_regs[SVSR_CYCLE_COUNT] = (vm.sys_regs[SVSR_CYCLE_COUNT] + 1) & _U64
        if pending:
            int_n, a0, a1, a2, a3 = pending.pop(0)
            delivered += 1
            vm.switch_to_interrupt_direct(int_n, a0, a1, a2, a3)
    return delivered


def milestone_3_page_fault(vm_size: int = _M3_VM_SIZE) -> MilestoneResult:
    blobs = {_M3_ENTRY: _m3_main(), _M3_HANDLER: _m3_handler()}
    vm = _make_kernel_vm(
        vm_size,
        blobs,
        entry=_M3_ENTRY,
        isr_base=_M3_ISR,
        virt_mode=VM_4_LVL_9_BIT,
    )
    tlptr = _m3_paging(vm.memory)
    vm.sys_regs[SVSR_KERNEL_TLPTR] = tlptr
    # The page-fault handler runs in kernel mode with the MMU still on.
    _install_isr(vm.memory, _M3_ISR, INT_PAGE_FAULT, _M3_HANDLER, run_flags=0x10 | (VM_4_LVL_9_BIT << 10))

    delivered = _run_with_sync_faults(vm)

    fault_addr = int.from_bytes(vm.memory[_M3_FAULT_ADDR : _M3_FAULT_ADDR + 8], "little")
    result = int.from_bytes(vm.memory[_M3_RESULT : _M3_RESULT + 8], "little")
    frame = int.from_bytes(vm.memory[_M3_FRAME : _M3_FRAME + 8], "little")
    passed = (
        delivered == 1
        and vm.memory[_M3_COUNTER] == 1
        and fault_addr == _M3_FAULT_VADDR
        and result == _M3_SENTINEL
        and frame == _M3_SENTINEL
        and vm.running == 0
    )
    return MilestoneResult(
        3,
        "MMU page fault delivered + demand-mapped",
        passed,
        {
            "faults_delivered": delivered,
            "fault_addr": fault_addr,
            "value_roundtrip": result == _M3_SENTINEL,
            "backing_frame_written": frame == _M3_SENTINEL,
        },
    )


# ---------------------------------------------------------------------------
# Milestone 4 — early printk over the MMIO UART
# ---------------------------------------------------------------------------


def milestone_4_uart_printk(vm_size: int = 0x10000) -> MilestoneResult:
    message = b"[    0.000000] StackVM: early console online\n"
    status_slot = 0x100

    uart_data = SVM_MMIO_UART0_BASE + UART_REG_DATA
    uart_status = SVM_MMIO_UART0_BASE + UART_REG_STATUS

    code = bytearray()
    # Poll the UART status (a real driver checks TX_READY first).
    emit_load_abs(code, uart_status, 8)
    emit_store_abs(code, status_slot, 8)
    for byte in message:
        emit_store_imm(code, uart_data, byte, 1)
    emit_hlt(code)

    output = bytearray()
    bus = MmioBus()
    bus.add_region(SVM_MMIO_UART0_BASE, 0x100, UartSerialDevice(output=output), "uart0")
    vm = _make_kernel_vm(vm_size, {0x2000: bytes(code)}, entry=0x2000, mmio_bus=bus)
    vm.execute()

    status = int.from_bytes(vm.memory[status_slot : status_slot + 8], "little")
    passed = bytes(output) == message and bool(status & UART_STATUS_TX_READY)
    return MilestoneResult(
        4,
        "early printk over MMIO UART",
        passed,
        {"output": bytes(output), "status": status, "tx_ready": bool(status & UART_STATUS_TX_READY)},
    )


# ---------------------------------------------------------------------------
# Milestone 5 — initramfs handoff: locate + enter an embedded /bin/sh
# ---------------------------------------------------------------------------

_M5_NAME = b"/bin/sh\0"
_M5_HEADER_SIZE = 16  # name padded to a 16-byte header; the program follows


def _m5_init_program(msg_addr: int, message: bytes) -> bytes:
    p = bytearray()
    emit_pv_hypercall(p, PVH_CONSOLE_WRITE, a0=msg_addr, a1=len(message))
    emit_hlt(p)
    return bytes(p)


def milestone_5_initramfs(vm_size: int = 1 << 20) -> MilestoneResult:
    message = b"init: /bin/sh started\n"
    msg_addr = vm_size - 0x800
    base_slot = vm_size - 0x400  # kernel stashes initramfs_base here for verification

    # The "init" program is embedded in the initramfs after a 16-byte header
    # whose first bytes name it "/bin/sh".  It is position-independent.
    init_prog = _m5_init_program(msg_addr, message)
    initramfs = _M5_NAME + b"\0" * (_M5_HEADER_SIZE - len(_M5_NAME)) + init_prog

    # Kernel: read initramfs_base from StartupData (offset 56), stash it, then
    # jump into the embedded program at base + header_size.
    code = bytearray()
    # stash base
    emit_load_sysreg(code, SVSR_SDP, 8)
    emit_push_imm(code, 56, 8)
    code += bytes([BC_ADD8])
    emit_load_indirect(code, 8)
    emit_store_abs(code, base_slot, 8)
    # jump to base + header
    emit_load_sysreg(code, SVSR_SDP, 8)
    emit_push_imm(code, 56, 8)
    code += bytes([BC_ADD8])
    emit_load_indirect(code, 8)
    emit_push_imm(code, _M5_HEADER_SIZE, 8)
    code += bytes([BC_ADD8])
    code += bytes([BC_JMP])

    vm, image = boot_kernel(
        bytes(code),
        vm_size=vm_size,
        kernel_base=0x1000,
        cmdline="rdinit=/bin/sh",
        initramfs=initramfs,
    )
    vm.memory[msg_addr : msg_addr + len(message)] = message

    console = bytearray()
    SyscallDispatcher([ParavirtDeviceSet(console_output=console)]).attach_to_py_vm(vm)
    vm.execute()

    read_base = int.from_bytes(vm.memory[base_slot : base_slot + 8], "little")
    passed = (
        read_base == image.initramfs_base
        and image.initramfs_size == len(initramfs)
        and bytes(console) == message
        and vm.running == 0
    )
    return MilestoneResult(
        5,
        "initramfs handoff: locate + enter /bin/sh",
        passed,
        {
            "initramfs_base_read": read_base,
            "initramfs_base_expected": image.initramfs_base,
            "console": bytes(console),
            "note": "reduced: full cpio/dynamic-loader/libc deferred per C3/B2",
        },
    )


# ---------------------------------------------------------------------------
# virtio MMIO helpers shared by milestones 6 + 8
# ---------------------------------------------------------------------------


def _write_desc(memory, desc_base, index, addr, length, flags=0, next_index=0):
    base = desc_base + index * VIRTQ_DESC_SIZE
    memory[base : base + VIRTQ_DESC_SIZE] = struct.pack(
        "<QIHH", addr, length, flags, next_index
    )


def _clear_rings(memory, avail, used, num):
    memory[avail : avail + 4 + num * 2] = b"\0" * (4 + num * 2)
    memory[used : used + 4 + num * 8] = b"\0" * (4 + num * 8)


def _submit_one(memory, avail, head, idx=1):
    memory[avail + 2 : avail + 4] = idx.to_bytes(2, "little")
    memory[avail + 4 : avail + 6] = head.to_bytes(2, "little")


def _used_idx(memory, used):
    return int.from_bytes(memory[used + 2 : used + 4], "little")


def _emit_queue_program(code, dev_base, queue, desc, avail, used, num):
    """Kernel-side MMIO programming of one virtqueue, ending with a NOTIFY kick."""
    emit_store_imm(code, dev_base + VIRTIO_REG_QUEUE_SEL, queue, 8)
    emit_store_imm(code, dev_base + VIRTIO_REG_QUEUE_DESC, desc, 8)
    emit_store_imm(code, dev_base + VIRTIO_REG_QUEUE_AVAIL, avail, 8)
    emit_store_imm(code, dev_base + VIRTIO_REG_QUEUE_USED, used, 8)
    emit_store_imm(code, dev_base + VIRTIO_REG_QUEUE_NUM, num, 8)
    emit_store_imm(code, dev_base + VIRTIO_REG_QUEUE_NOTIFY, queue, 8)


# ---------------------------------------------------------------------------
# Milestone 6 — block-backed persistent root fs (virtio-blk, persists)
# ---------------------------------------------------------------------------

_M6_DESC = 0x800
_M6_AVAIL = 0xC00
_M6_USED = 0xD00
_M6_HDR = 0xE00
_M6_DATA = 0x1000
_M6_STATUS = 0x1200
_M6_NUM = 8


def _m6_prepare_request(memory, req_type, sector, payload_len):
    memory[_M6_HDR : _M6_HDR + 16] = struct.pack("<IIQ", req_type, 0, sector)
    memory[_M6_STATUS] = 0xFF
    _clear_rings(memory, _M6_AVAIL, _M6_USED, _M6_NUM)
    _write_desc(memory, _M6_DESC, 0, _M6_HDR, 16, VIRTQ_DESC_F_NEXT, 1)
    data_flags = VIRTQ_DESC_F_NEXT | (VIRTQ_DESC_F_WRITE if req_type == VIRTIO_BLK_T_IN else 0)
    _write_desc(memory, _M6_DESC, 1, _M6_DATA, payload_len, data_flags, 2)
    _write_desc(memory, _M6_DESC, 2, _M6_STATUS, 1, VIRTQ_DESC_F_WRITE, 0)
    _submit_one(memory, _M6_AVAIL, 0)


def _m6_run(backend, req_type, sector, payload_len, data=None, vm_size=0x20000):
    ic = MmioInterruptController()
    apic = AdvProgIntCtl()
    blk = VirtioBlockDevice(backend, irq_controller=ic, irq=SVM_IRQ_VIRTIO_BLK0)
    bus = MmioBus()
    bus.add_region(SVM_MMIO_IC_BASE, 0x1000, ic, "ic")
    bus.add_region(SVM_MMIO_VIRTIO_BLK0_BASE, 0x1000, blk, "blk")

    code = bytearray()
    _emit_queue_program(code, SVM_MMIO_VIRTIO_BLK0_BASE, 0, _M6_DESC, _M6_AVAIL, _M6_USED, _M6_NUM)
    emit_hlt(code)

    vm = _make_kernel_vm(vm_size, {0x2000: bytes(code)}, entry=0x2000, mmio_bus=bus, apic=apic)
    vm.set(8, SVM_MMIO_IC_BASE + IC_REG_ENABLE, 1 << SVM_IRQ_VIRTIO_BLK0)
    if data is not None:
        vm.memory[_M6_DATA : _M6_DATA + len(data)] = data
    _m6_prepare_request(vm.memory, req_type, sector, payload_len)
    vm.execute()
    return vm, apic


def milestone_6_block(vm_size: int = 0x20000) -> MilestoneResult:
    payload = b"persistent-rootfs-superblock"
    sector = 1
    with tempfile.TemporaryDirectory() as td:
        image_path = os.path.join(td, "rootfs.img")

        # Run 1: a kernel writes the superblock to the persistent host image.
        write_vm, _ = _m6_run(
            HostBlockImage(image_path, size=4096),
            VIRTIO_BLK_T_OUT,
            sector,
            len(payload),
            data=payload,
            vm_size=vm_size,
        )
        wrote_ok = write_vm.memory[_M6_STATUS] == VIRTIO_BLK_S_OK and _used_idx(write_vm.memory, _M6_USED) == 1
        with open(image_path, "rb") as fl:
            fl.seek(VIRTIO_BLK_SECTOR_SIZE * sector)
            on_disk = fl.read(len(payload))

        # Run 2: a *fresh* VM + block device reads it back from the same image.
        read_vm, _ = _m6_run(
            HostBlockImage(image_path, size=4096),
            VIRTIO_BLK_T_IN,
            sector,
            len(payload),
            vm_size=vm_size,
        )
        read_back = bytes(read_vm.memory[_M6_DATA : _M6_DATA + len(payload)])
        read_ok = read_vm.memory[_M6_STATUS] == VIRTIO_BLK_S_OK

    passed = wrote_ok and read_ok and on_disk == payload and read_back == payload
    return MilestoneResult(
        6,
        "block-backed persistent root fs (virtio-blk)",
        passed,
        {"wrote_ok": wrote_ok, "read_ok": read_ok, "persisted": on_disk == payload, "read_back": read_back},
    )


# ---------------------------------------------------------------------------
# Milestone 7 — SMP: secondary core online, IPI + TLB shootdown
# ---------------------------------------------------------------------------


def milestone_7_smp(vm_size: int = 0x10000) -> MilestoneResult:
    # Part A: an IPI from the boot core is serviced by the secondary core's ISR.
    ipi_ok = _m7_ipi()
    # Part B: a remote-interrupt TLB shootdown is serviced + acked.
    shootdown_ok = _m7_shootdown()
    return MilestoneResult(
        7,
        "SMP: secondary core online, IPI + TLB shootdown",
        ipi_ok and shootdown_ok,
        {"ipi_serviced": ipi_ok, "shootdown_serviced_and_acked": shootdown_ok},
    )


def _m7_ipi() -> bool:
    machine = MultiCoreMachine(2, 0x10000, stack_size=0x1000)
    c0, c1 = machine.cores
    c0.set_flags(0xFF)
    c1.set_flags(0xFF | FLAGS_INT_ENABLE)
    c1.sys_regs[SVSR_ISR] = 0x4000

    irq, marker, handler = 0x31, 0x3000, 0x6000
    _install_isr(machine.memory, 0x4000, irq, handler)
    h = bytearray()
    emit_push_imm(h, 1, 1)
    emit_store_abs(h, marker, 1)
    emit_iret(h)
    machine.memory[handler : handler + len(h)] = bytes(h)

    p0 = bytearray()
    emit_push_imm(p0, (irq << 8) | 1, 8)  # (irq << 8) | target_core_id
    emit_store_sysreg(p0, SVSR_IPI, 8)
    emit_hlt(p0)
    machine.memory[0x0000 : 0x0000 + len(p0)] = bytes(p0)
    machine.memory[0x0100 : 0x0100 + 13] = bytes([BC_NOP] * 12 + [BC_HLT])
    c0.ip, c1.ip = 0x0000, 0x0100

    machine.run_round_robin(max_rounds=64)
    return machine.memory[marker] == 1 and not c1.apic.pending()


def _m7_shootdown() -> bool:
    machine = MultiCoreMachine(2, 0x10000, stack_size=0x1000)
    c0, c1 = machine.cores
    c0.set_flags(0xFF)
    c1.set_flags(0xFF | FLAGS_INT_ENABLE)
    c1.sys_regs[SVSR_ISR] = 0x4000

    table = 0x7000
    c0.sys_regs[SVSR_USER_TLPTR] = table
    c1.sys_regs[SVSR_USER_TLPTR] = table
    c1.tlb[(table, 0x2000)] = [0x9000, TLBP_R]

    handler = 0x6100
    _install_isr(machine.memory, 0x4000, INT_TLB_SHOOTDOWN, handler)
    h = bytearray()
    h += bytes([BC_LOAD, BCR_SYSREG | (3 << 5), SVSR_INT_ARG0])
    h += bytes([BC_LOAD, BCR_SYSREG | (3 << 5), SVSR_INT_ARG1])
    h += bytes([BC_LOAD, BCR_SYSREG | (3 << 5), SVSR_INT_ARG2])
    h += bytes([BC_INVTLB, INVTLB_LOCAL])
    h += bytes([BC_LOAD, BCR_SYSREG | (3 << 5), SVSR_INT_ARG3])
    h += bytes([BC_INVTLB, INVTLB_ACK])
    emit_iret(h)
    machine.memory[handler : handler + len(h)] = bytes(h)
    machine.memory[0x0100 : 0x0100 + 13] = bytes([BC_NOP] * 12 + [BC_HLT])
    c1.ip = 0x0100

    c0.tlb_shootdown(
        [(table, 0x2000, 1)], INVTLB_F_ASYNC | INVTLB_F_REMOTE_INT, done_core=0
    )
    machine.run_round_robin(max_rounds=64)
    return (
        (table, 0x2000) not in c1.tlb
        and c0.apic.pending()
        and c0.apic.which_int == INT_TLB_SHOOTDOWN_DONE
    )


# ---------------------------------------------------------------------------
# Milestone 8 — networking: virtio-net TX + RX
# ---------------------------------------------------------------------------

_M8_TX_DESC = 0x1800
_M8_TX_AVAIL = 0x1A00
_M8_TX_USED = 0x1B00
_M8_RX_DESC = 0x1C00
_M8_RX_AVAIL = 0x1E00
_M8_RX_USED = 0x1F00
_M8_TX_BUF = 0x1000
_M8_RX_BUF = 0x2200
_M8_NUM = 8


def milestone_8_net(vm_size: int = 0x20000) -> MilestoneResult:
    payload = b"hello-net"
    incoming = b"frame-from-the-wire"
    backend = InMemoryNetBackend([incoming])

    ic = MmioInterruptController()
    apic = AdvProgIntCtl()
    net = VirtioNetDevice(backend, irq_controller=ic, irq=SVM_IRQ_VIRTIO_NET0)
    bus = MmioBus()
    bus.add_region(SVM_MMIO_IC_BASE, 0x1000, ic, "ic")
    bus.add_region(SVM_MMIO_VIRTIO_NET0_BASE, 0x1000, net, "net")

    code = bytearray()
    # TX on queue 1, then RX on queue 0 (the device keys config by QUEUE_SEL).
    _emit_queue_program(code, SVM_MMIO_VIRTIO_NET0_BASE, 1, _M8_TX_DESC, _M8_TX_AVAIL, _M8_TX_USED, _M8_NUM)
    _emit_queue_program(code, SVM_MMIO_VIRTIO_NET0_BASE, 0, _M8_RX_DESC, _M8_RX_AVAIL, _M8_RX_USED, _M8_NUM)
    emit_hlt(code)

    vm = _make_kernel_vm(vm_size, {0x3000: bytes(code)}, entry=0x3000, mmio_bus=bus, apic=apic)
    vm.set(8, SVM_MMIO_IC_BASE + IC_REG_ENABLE, 1 << SVM_IRQ_VIRTIO_NET0)

    # TX buffer: virtio-net header + payload, one read-only descriptor.
    tx_packet = b"\0" * VIRTIO_NET_HDR_SIZE + payload
    vm.memory[_M8_TX_BUF : _M8_TX_BUF + len(tx_packet)] = tx_packet
    _clear_rings(vm.memory, _M8_TX_AVAIL, _M8_TX_USED, _M8_NUM)
    _write_desc(vm.memory, _M8_TX_DESC, 0, _M8_TX_BUF, len(tx_packet), 0, 0)
    _submit_one(vm.memory, _M8_TX_AVAIL, 0)

    # RX buffer: one writable descriptor for the device to fill.
    _clear_rings(vm.memory, _M8_RX_AVAIL, _M8_RX_USED, _M8_NUM)
    _write_desc(vm.memory, _M8_RX_DESC, 0, _M8_RX_BUF, 64, VIRTQ_DESC_F_WRITE, 0)
    _submit_one(vm.memory, _M8_RX_AVAIL, 0)

    vm.execute()

    rx_data = bytes(vm.memory[_M8_RX_BUF : _M8_RX_BUF + len(incoming)])
    tx_ok = backend.tx_packets == [payload] and _used_idx(vm.memory, _M8_TX_USED) == 1
    rx_ok = rx_data == incoming and _used_idx(vm.memory, _M8_RX_USED) == 1
    passed = tx_ok and rx_ok
    return MilestoneResult(
        8,
        "networking: virtio-net TX + RX",
        passed,
        {"tx_ok": tx_ok, "rx_ok": rx_ok, "tx_packets": list(backend.tx_packets), "rx_data": rx_data},
    )


# ---------------------------------------------------------------------------
# Registry / runner
# ---------------------------------------------------------------------------

MILESTONES: Dict[int, Callable[[], MilestoneResult]] = {
    1: milestone_1_boot_console,
    2: milestone_2_timer,
    3: milestone_3_page_fault,
    4: milestone_4_uart_printk,
    5: milestone_5_initramfs,
    6: milestone_6_block,
    7: milestone_7_smp,
    8: milestone_8_net,
}


def run_milestone(number: int) -> MilestoneResult:
    if number not in MILESTONES:
        raise ValueError(f"unknown milestone {number}; valid: {sorted(MILESTONES)}")
    return MILESTONES[number]()


def run_all_milestones() -> List[MilestoneResult]:
    return [run_milestone(n) for n in sorted(MILESTONES)]
