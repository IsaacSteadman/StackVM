"""
StackVM program runner.

Provides ``add_cmd_argv_vm`` and ``run_in_vm``, shared by both
``IsaacCompiler.__main__`` (compile-then-run) and ``StackVM.__main__``
(run a bare .sbc binary).
"""

from __future__ import annotations

import struct as _struct
from typing import Dict, List, Optional, Tuple


def add_cmd_argv_vm(vm_inst, i_end_prog: int, lst_args: List[str]):
    """Write argv strings into VM memory and push argc/argv onto the stack.

    Strings start at *i_end_prog* (immediately past the loaded program image).
    After this call the stack matches the C convention expected by
    ``main(int argc, char **argv)``.
    """
    argc = len(lst_args)
    lst_arg_ptrs: List[int] = [0] * argc
    bytes_args = bytearray()
    for i, arg in enumerate(lst_args):
        lst_arg_ptrs[i] = i_end_prog + len(bytes_args)
        bytes_args.extend((arg + "\0").encode("utf-8"))
    vm_inst.set_bytes(i_end_prog, bytes_args)
    argv = i_end_prog + len(bytes_args)
    ptr_cur = argv
    for ptr in lst_arg_ptrs:
        vm_inst.set(8, ptr_cur, ptr)
        ptr_cur += 8
    vm_inst.push(8, argv)
    vm_inst.push(4, argc, 1)
    return vm_inst


def run_in_vm(
    memory: bytearray,
    code_segment_end: int,
    data_segment_start: int,
    named_indices: Dict,
    program_args: List[str],
    vm_size: int,
    use_virt_mem: bool,
    use_debugger: bool,
    backend: str = "python",
    syscall_sets: Optional[List[str]] = None,
) -> None:
    """Create a VirtualMachine, load the program, and execute or debug it.

    Parameters
    ----------
    memory:
        Full bytecode image loaded from the .sbc file.
    code_segment_end:
        Byte offset where the code segment ends (= data segment boundary).
    data_segment_start:
        Byte offset where read-only data starts.
    named_indices:
        ``{address: (symbol_name, is_src)}`` mapping for the debugger.
        Pass ``{}`` when no debug symbols are available.
    program_args:
        ``argv`` list passed to the compiled program (``argv[0]`` = program name).
    vm_size:
        Total StackVM memory size in bytes.
    use_virt_mem:
        Enable 4-level paging (PyStackVM only).
    use_debugger:
        Launch the interactive debugger instead of running to completion.
    backend:
        ``"python"`` — pure-Python PyStackVM (default).
        ``"cpp"``    — native CppStackVM via ctypes.
    syscall_sets:
        List of syscall-set names to enable, e.g. ``["os", "pygame"]``.
        ``None`` or ``[]`` means no custom syscall handling (the VM's built-in
        ``virt_syscall`` is used unchanged).
    """
    if backend == "cpp":
        from .CppStackVM import VirtualMachine as _CppVM  # type: ignore[attr-defined]

        vm = _CppVM(vm_size)
        if use_virt_mem:
            print(
                "Warning: --virt-mem is not supported with --backend cpp; "
                "virtual memory will be disabled.",
            )
    else:
        from .PyStackVM import VirtualMachine, PageAllocator, enable_virt_mem

        vm = VirtualMachine(vm_size)
        if use_virt_mem:
            vm_alloc = PageAllocator(len(vm.memory) >> 12)
            # data_segment_start is used for both code_segment_end and
            # data_segment_start so that alignment padding bytes are also
            # mapped as executable.
            enable_virt_mem(
                vm,
                vm_alloc,
                vm.priv_lvl,
                0,
                data_segment_start,
                data_segment_start,
                None,
            )

    # Attach syscall dispatcher if requested
    if syscall_sets:
        from .syscalls import build_dispatcher

        dispatcher = build_dispatcher(syscall_sets)
        if backend == "cpp":
            dispatcher.attach_to_cpp_vm(vm)
        else:
            dispatcher.attach_to_py_vm(vm)

    vm.load_program(memory, 0)
    i_end_prog = len(memory)
    vm.push(4, 0)  # return-value slot for main()
    add_cmd_argv_vm(vm, i_end_prog, program_args)

    if use_debugger:
        Debugger = _load_debugger()
        if Debugger is None:
            print(
                "Warning: Debugger class not available in standalone mode; "
                "falling back to execute()."
            )
            vm.execute()
        else:
            dbg = Debugger(vm, 0, code_segment_end, named_indices)
            dbg.debug()
    else:
        vm.execute()


def _load_debugger():
    """Import Debugger lazily; returns None if unavailable (e.g. standalone StackVM)."""
    try:
        from ..code_gen.stackvm_binutils.Debugger import Debugger  # type: ignore[import]

        return Debugger
    except (ImportError, ValueError):
        pass
    # Fallback: try absolute import (useful when the package is installed)
    try:
        from IsaacCompiler.code_gen.stackvm_binutils.Debugger import (
            Debugger,
        )  # noqa: PLC0415

        return Debugger
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# .sbc file I/O helpers
# ---------------------------------------------------------------------------

_SVC_MAGIC = b"\xf7SVE\0\0\0\0"


def load_sbc(path: str) -> Tuple[bytearray, int, int]:
    """Load a .sbc binary file.

    Returns
    -------
    (memory, code_segment_end, data_segment_start)
    """
    with open(path, "rb") as fl:
        magic = fl.read(8)
        if magic != _SVC_MAGIC:
            raise ValueError(
                f"Invalid .sbc magic: expected {_SVC_MAGIC!r}, got {magic!r}"
            )
        header = fl.read(24)
        if len(header) != 24:
            raise ValueError("Binary file too short to contain a valid header")
        code_segment_end, data_segment_start, total_memory_length = _struct.unpack(
            "<QQQ", header
        )
        memory = bytearray(fl.read(total_memory_length))
    if len(memory) != total_memory_length:
        raise ValueError(
            f"Binary file truncated: expected {total_memory_length} bytes, "
            f"got {len(memory)}"
        )
    return memory, code_segment_end, data_segment_start
