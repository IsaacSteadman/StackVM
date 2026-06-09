"""
StackVM command-line interface.

Invocable as::

    python -m IsaacCompiler.StackVM run   program.sbc [-- argv...]
    python -m IsaacCompiler.StackVM disassemble program.sbc [-o out.sasm]
    python -m IsaacCompiler.StackVM uefi  app.efi [--cmdline ...]

run
---
Load a compiled .sbc binary and execute it in the StackVM.

  positional:
    input            .sbc file to run
    program_args     arguments forwarded to the program (after --)

  options:
    --vm-size N      total VM memory in bytes (default: 65536)
    --virt-mem       enable 4-level virtual memory (PyStackVM only)
    --debug          launch the interactive debugger
    --backend {python,cpp}
    --syscalls {os,pygame,all,none} [...]
                     enable syscall emulation sets (default: none)

disassemble
-----------
Disassemble a .sbc binary to human-readable StackVM assembly.

  positional:
    input            .sbc file to disassemble

  options:
    -o / --output    output file (default: stdout)
    --addresses      include byte-offset addresses

uefi
----
Launch a PE32+ EFI application through the minimal StackVM UEFI firmware.
"""

from __future__ import annotations

import argparse
import sys

from .runner import load_sbc, run_in_vm

# ---------------------------------------------------------------------------
# Shared VM flags (inherited by subparsers via parents=)
# ---------------------------------------------------------------------------
_vm_flags = argparse.ArgumentParser(add_help=False)
_vm_flags.add_argument(
    "--vm-size",
    metavar="N",
    type=int,
    default=65536,
    dest="vm_size",
    help="total StackVM memory in bytes (default: 65536)",
)
_vm_flags.add_argument(
    "--virt-mem",
    action="store_true",
    dest="virt_mem",
    help="enable 4-level virtual memory (PyStackVM only)",
)
_vm_flags.add_argument(
    "--debug",
    action="store_true",
    help="launch the interactive debugger instead of running to completion",
)
_vm_flags.add_argument(
    "--backend",
    choices=["python", "cpp"],
    default="python",
    dest="backend",
    help="VM backend: 'python' (default) or 'cpp' (native via ctypes)",
)
_vm_flags.add_argument(
    "--syscalls",
    nargs="*",
    metavar="SET",
    default=[],
    dest="syscalls",
    help=(
        "syscall/device sets to enable: os, pygame, paravirt, all, none "
        "(default: none — the VM's built-in virt_syscall is used)"
    ),
)

# ---------------------------------------------------------------------------
# Top-level parser
# ---------------------------------------------------------------------------
_parser = argparse.ArgumentParser(
    prog="python -m IsaacCompiler.StackVM",
    description="StackVM runtime — run or disassemble .sbc binaries",
)
_subparsers = _parser.add_subparsers(dest="subcommand")
_subparsers.required = True

# ---------------------------------------------------------------------------
# 'run' subcommand
# ---------------------------------------------------------------------------
_run_parser = _subparsers.add_parser(
    "run",
    help="run a compiled .sbc binary in the StackVM",
    parents=[_vm_flags],
)
_run_parser.add_argument(
    "input",
    metavar="input",
    help=".sbc binary to run",
)
_run_parser.add_argument(
    "program_args",
    nargs=argparse.REMAINDER,
    help="arguments forwarded to the program (after --)",
)

# ---------------------------------------------------------------------------
# 'disassemble' subcommand
# ---------------------------------------------------------------------------
_dis_parser = _subparsers.add_parser(
    "disassemble",
    help="disassemble a .sbc binary to StackVM assembly",
)
_dis_parser.add_argument(
    "input",
    metavar="input",
    help=".sbc binary to disassemble",
)
_dis_parser.add_argument(
    "-o",
    "--output",
    metavar="output",
    default=None,
    help="output file (default: stdout)",
)
_dis_parser.add_argument(
    "--addresses",
    action="store_true",
    help="prefix each instruction with its byte-offset address",
)

# ---------------------------------------------------------------------------
# 'boot' subcommand
# ---------------------------------------------------------------------------
_boot_parser = _subparsers.add_parser(
    "boot",
    help="boot a freestanding kernel image (vmlinux) via the StartupData ABI",
)
_boot_parser.add_argument(
    "input",
    metavar="input",
    help="flat kernel binary to load and enter in kernel mode",
)
_boot_parser.add_argument(
    "--vm-size",
    metavar="N",
    type=int,
    default=1 << 20,
    dest="vm_size",
    help="total StackVM physical memory in bytes (default: 1 MiB)",
)
_boot_parser.add_argument(
    "--kernel-base",
    metavar="ADDR",
    type=lambda s: int(s, 0),
    default=0x1000,
    dest="kernel_base",
    help="page-aligned physical load/entry address (default: 0x1000)",
)
_boot_parser.add_argument(
    "--cmdline",
    metavar="STR",
    default="",
    help="kernel command line string",
)
_boot_parser.add_argument(
    "--initramfs",
    metavar="FILE",
    default=None,
    help="initramfs image to place in memory and describe in StartupData",
)
_boot_parser.add_argument(
    "--dtb",
    metavar="FILE",
    default=None,
    help="devicetree / boot-params blob to place in memory",
)
_boot_parser.add_argument(
    "--generate-dtb",
    action="store_true",
    dest="generate_dtb",
    help="auto-generate a devicetree describing the configured machine "
    "(cores, memory map, devices) and point StartupData.dtb at it",
)
_boot_parser.add_argument(
    "--slim",
    action="store_true",
    help="use the DTB-authoritative (slim) StartupData handoff: the memory map, "
    "cmdline and initramfs are described only by the devicetree (implies "
    "--generate-dtb when no --dtb is given)",
)
_boot_parser.add_argument(
    "--cores",
    metavar="N",
    type=int,
    default=1,
    dest="cores",
    help="online core count reported in StartupData (default: 1)",
)
_boot_parser.add_argument(
    "--debug",
    action="store_true",
    help="launch the interactive debugger instead of running to completion",
)
_boot_parser.add_argument(
    "--syscalls",
    nargs="*",
    metavar="SET",
    default=[],
    dest="syscalls",
    help="syscall/device sets to enable: os, pygame, paravirt, all, none (default: none)",
)

# ---------------------------------------------------------------------------
# 'uefi' subcommand
# ---------------------------------------------------------------------------
_uefi_parser = _subparsers.add_parser(
    "uefi",
    help="launch a PE32+ EFI application through the minimal UEFI firmware",
)
_uefi_parser.add_argument(
    "input",
    metavar="input",
    help="PE32+ StackVM EFI image (.efi) to load",
)
_uefi_parser.add_argument(
    "--vm-size",
    metavar="N",
    type=int,
    default=1 << 20,
    dest="vm_size",
    help="total StackVM physical memory in bytes (default: 1 MiB)",
)
_uefi_parser.add_argument(
    "--app-base",
    metavar="ADDR",
    type=lambda s: int(s, 0),
    default=0x1000,
    dest="app_base",
    help="page-aligned physical EFI image load address (default: 0x1000)",
)
_uefi_parser.add_argument(
    "--cmdline",
    metavar="STR",
    default="",
    help="load-options / kernel command line string",
)
_uefi_parser.add_argument(
    "--initramfs",
    metavar="FILE",
    default=None,
    help="initramfs image to place in memory and describe in the DTB",
)
_uefi_parser.add_argument(
    "--dtb",
    metavar="FILE",
    default=None,
    help="explicit devicetree blob to publish in the UEFI configuration table",
)
_uefi_parser.add_argument(
    "--nvram",
    metavar="FILE",
    default=None,
    help="host JSON file used for persistent UEFI variables",
)
_uefi_parser.add_argument(
    "--block-image",
    metavar="FILE",
    default=None,
    dest="block_image",
    help="host file used as the virtio-blk / Simple File System backing image",
)
_uefi_parser.add_argument(
    "--block-size",
    metavar="N",
    type=int,
    default=None,
    dest="block_size",
    help="create/extend --block-image to at least this many bytes",
)
_uefi_parser.add_argument(
    "--prepare-only",
    action="store_true",
    help="build firmware tables and print launch state without entering the EFI app",
)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _main() -> None:
    args = _parser.parse_args()

    if args.subcommand == "boot":
        try:
            with open(args.input, "rb") as fl:
                kernel_image = fl.read()
            initramfs = b""
            if args.initramfs:
                with open(args.initramfs, "rb") as fl:
                    initramfs = fl.read()
            dtb = b""
            if args.dtb:
                with open(args.dtb, "rb") as fl:
                    dtb = fl.read()
        except OSError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc

        from .boot import run_boot_in_vm

        print(f"Booting kernel: {args.input}")
        print(
            f"  kernel_base = {args.kernel_base:#010x}\n"
            f"  vm_size     = {args.vm_size:#010x}\n"
            f"  initramfs   = {len(initramfs)} bytes\n"
            f"  cmdline     = {args.cmdline!r}\n"
            f"  cores       = {args.cores}\n"
            f"  dtb         = {'supplied' if dtb else ('generated' if (args.generate_dtb or args.slim) else 'none')}"
            f"{' (slim handoff)' if args.slim else ''}"
        )
        try:
            run_boot_in_vm(
                kernel_image,
                vm_size=args.vm_size,
                kernel_base=args.kernel_base,
                cmdline=args.cmdline,
                initramfs=initramfs,
                dtb=dtb,
                generate_dtb=args.generate_dtb,
                slim=args.slim,
                core_count=args.cores,
                use_debugger=args.debug,
                syscall_sets=args.syscalls or None,
            )
        except (ValueError, NotImplementedError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc

    elif args.subcommand == "uefi":
        try:
            with open(args.input, "rb") as fl:
                app_image = fl.read()
            initramfs = b""
            if args.initramfs:
                with open(args.initramfs, "rb") as fl:
                    initramfs = fl.read()
            dtb = b""
            if args.dtb:
                with open(args.dtb, "rb") as fl:
                    dtb = fl.read()
        except OSError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc

        from .mmio import HostBlockImage
        from .uefi import MinimalUefiFirmware

        block_backend = (
            HostBlockImage(args.block_image, size=args.block_size)
            if args.block_image
            else None
        )
        firmware = MinimalUefiFirmware(
            vm_size=args.vm_size,
            app_base=args.app_base,
            cmdline=args.cmdline,
            initramfs=initramfs,
            dtb=dtb,
            generate_dtb=not bool(dtb),
            nvram_path=args.nvram,
            block_backend=block_backend,
        )
        try:
            launch = firmware.load_efi_app(app_image, execute=not args.prepare_only)
        except (ValueError, MemoryError, OSError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc

        print(f"UEFI image: {args.input}")
        print(
            f"  app_base     = {launch.app_base:#010x}\n"
            f"  entry        = {launch.entry_addr:#010x}\n"
            f"  image_handle = {launch.image_handle:#010x}\n"
            f"  system_table = {launch.system_table_addr:#010x}\n"
            f"  dtb          = {launch.dtb_addr:#010x}\n"
            f"  status       = {'prepared' if args.prepare_only else 'returned/halted'}"
        )
        if isinstance(firmware.console_output, bytearray) and firmware.console_output:
            sys.stdout.buffer.write(firmware.console_output)

    elif args.subcommand == "run":
        program_args: list[str] = args.program_args
        if program_args and program_args[0] == "--":
            program_args = program_args[1:]

        syscall_sets: list[str] = args.syscalls or []

        print(f"Loading: {args.input}")
        try:
            memory, code_segment_end, data_segment_start = load_sbc(args.input)
        except (OSError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc

        print(
            f"  code_segment_end   = {code_segment_end:#010x}\n"
            f"  data_segment_start = {data_segment_start:#010x}\n"
            f"  memory_size        = {len(memory):#010x}"
        )
        print("Running in StackVM")
        run_in_vm(
            memory,
            code_segment_end,
            data_segment_start,
            {},  # no debug symbols available from bare .sbc binary
            program_args,
            args.vm_size,
            args.virt_mem,
            args.debug,
            args.backend,
            syscall_sets if syscall_sets else None,
        )

    elif args.subcommand == "disassemble":
        try:
            memory, code_segment_end, _ds = load_sbc(args.input)
        except (OSError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc

        # Debugger.py and disassemble live outside StackVM; import lazily.
        try:
            from ..code_gen.stackvm_binutils.disassemble import disassemble
        except ImportError:
            print(
                "Error: disassemble module not available in standalone mode.",
                file=sys.stderr,
            )
            raise SystemExit(1)

        address_fmt: str | None = None
        if args.addresses:
            address_fmt = f"  0x%0{len(f'{code_segment_end - 1:X}')}X: %s"

        text = disassemble(memory, None, code_segment_end, {}, address_fmt, None)

        if args.output:
            with open(args.output, "w") as fl:
                fl.write(text)
            print(f"Disassembly written to {args.output}")
        else:
            print(text)


_main()
