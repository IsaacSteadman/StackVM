/*
 * stackvm_memory.h — Heap management for StackVM programs.
 *
 * Provides:
 *   - sys_mmap()    grow the VM's physical memory and return a pointer to the
 *                   new region (analogous to sbrk / anonymous mmap).
 *   - sys_munmap()  release a previously mapped region (no-op in current impl).
 *
 * Syscall numbers (host-side implementation in StackVM/syscalls/os_sys.py):
 *
 *   SYS_MMAP     0x16
 *   SYS_MUNMAP   0x17
 *
 * NOTE: sys_mmap is only functional when the StackVM is running WITHOUT virtual
 * memory (--virt-mem flag not set).  With virtual memory enabled, sys_mmap
 * returns NULL because the page tables are not updated automatically.
 */

#ifndef STACKVM_MEMORY_H
#define STACKVM_MEMORY_H

#include "stackvm.h"

#define SYS_MMAP 0x16
#define SYS_MUNMAP 0x17

/*
 * Extend the StackVM heap by *size* bytes.
 * Returns a pointer to the start of the new region, or NULL on failure.
 *
 * The returned region is zero-initialised.
 */
static inline void *sys_mmap(size_t size)
{
    size_t ptr = syscall(SYS_MMAP, size, 0, 0, 0);
    return ptr ? (void *)ptr : NULL;
}

/*
 * Release a region previously allocated by sys_mmap.
 * Currently a no-op; included for ABI completeness.
 */
static inline void sys_munmap(void *ptr, size_t size)
{
    syscall(SYS_MUNMAP, (size_t)ptr, size, 0, 0);
}

#endif /* STACKVM_MEMORY_H */
