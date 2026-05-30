"""
StackVM command-line interface.

Invocable as::

    python -m IsaacCompiler.StackVM run   program.sbc [-- argv...]
    python -m IsaacCompiler.StackVM disassemble program.sbc [-o out.sasm]

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
        "syscall sets to enable: os, pygame, all, none "
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
# Entry point
# ---------------------------------------------------------------------------


def _main() -> None:
    args = _parser.parse_args()

    if args.subcommand == "run":
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
