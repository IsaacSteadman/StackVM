/*
 * stackvm_boot.h - StackVM boot protocol (the `struct StartupData` ABI).
 *
 * When the emulator launches a freestanding kernel image (`vmlinux`) it enters
 * the image in kernel mode with the MMU off, and points the boot-pointer system
 * register SVSR_SDP (0x02) at an instance of `struct StartupData` placed in
 * physical memory.  This header is the authoritative C definition of that
 * structure; the emulator-side builder/populator lives in StackVM/boot.py and
 * must stay byte-for-byte compatible with the layout below.
 *
 * The boot contract:
 *
 *   - SVSR_SDP holds the physical address of a `struct StartupData`.
 *   - All pointers inside StartupData are physical addresses (the MMU is off at
 *     entry, so physical == virtual for the early kernel).
 *   - StartupData.magic == SVSD_MAGIC and StartupData.struct_size == the size
 *     the loader wrote; a kernel must check both before trusting the rest, and
 *     must only read fields within struct_size for forward compatibility.
 *   - The memory map is an array of `struct MemMapEntry` describing every byte
 *     of physical RAM exactly once (regions are contiguous, sorted, and
 *     non-overlapping; gaps between reserved regions are reported as SVMEM_RAM).
 *
 * This is the kernel-boot counterpart of the user-program argv launch path; see
 * StackVM/runner.py (add_cmd_argv_vm) for the user side and Documentation/
 * stack_vm.md (SVSR_SDP, register 0x02) for the register reference.
 */

#ifndef STACKVM_BOOT_H
#define STACKVM_BOOT_H

#include "stackvm.h"

/*
 * Identifies a valid StartupData.  Equal to the little-endian encoding of the
 * ASCII bytes "SVMBOOT1" (0x53 'S' is the least-significant byte).
 */
#define SVSD_MAGIC 0x31544F4F424D5653ULL

/* StartupData ABI version.  Bumped when fields are appended; readers gate on
 * struct_size, so appends are backward compatible. */
#define SVSD_VERSION 1u

/* StartupData.flags bits (all currently reserved / zero). */
#define SVSD_FLAG_NONE 0u

/* MemMapEntry.type values. */
#define SVMEM_RAM 1u       /* usable RAM, free for the kernel allocator */
#define SVMEM_RESERVED 2u  /* reserved firmware/low memory; do not allocate */
#define SVMEM_KERNEL 3u    /* occupied by the loaded kernel image */
#define SVMEM_INITRAMFS 4u /* occupied by the initramfs blob */
#define SVMEM_BOOTDATA 5u  /* occupied by StartupData and its sub-tables */

/*
 * Phase-1 paravirt device doorbell.
 *
 * Guest kernels use CALL_E with IS_SYS=0, IS_INT=1 and immediate interrupt
 * vector SVM_INT_PARAVIRT while running in kernel mode.  This is separate from
 * CALL_E/SYSCALL, which remains a user->kernel syscall transition.
 *
 * The stack frame at doorbell entry is six little-endian uint64_t values:
 *
 *   sp +  0: hypercall number (SVMPV_HCALL_*)
 *   sp +  8: argument byte count (SVMPV_ARG_BYTES, currently 32)
 *   sp + 16: arg0
 *   sp + 24: arg1
 *   sp + 32: arg2
 *   sp + 40: arg3, also the return-value slot
 */
#define SVM_INT_PARAVIRT 0x12u
#define SVMPV_ARG_BYTES 32u

#define SVMPV_HCALL_CONSOLE_WRITE 0x00u /* (buf, len, 0, 0) -> bytes */
#define SVMPV_HCALL_CONSOLE_READ 0x01u  /* (buf, len, 0, 0) -> bytes */
#define SVMPV_HCALL_BLOCK_READ 0x02u    /* (dev, offset, buf, len) -> bytes */
#define SVMPV_HCALL_BLOCK_WRITE 0x03u   /* (dev, offset, buf, len) -> bytes */
#define SVMPV_HCALL_RTC_NOW_NS 0x04u    /* () -> Unix time in nanoseconds */
#define SVMPV_HCALL_ENTROPY 0x05u       /* (buf, len, flags=0, 0) -> bytes */

#define SVMPV_EIO ((uint64_t)-5)
#define SVMPV_ENODEV ((uint64_t)-19)
#define SVMPV_EINVAL ((uint64_t)-22)
#define SVMPV_ENOSPC ((uint64_t)-28)
#define SVMPV_ENOSYS ((uint64_t)-38)

/*
 * One physical memory region.  The map covers [0, total_ram) with no gaps.
 */
struct MemMapEntry {
    uint64_t base; /* physical base address */
    uint64_t size; /* size in bytes */
    uint32_t type; /* one of SVMEM_* */
    uint32_t reserved;
};

/*
 * The boot information block.  Pointed to by SVSR_SDP at kernel entry.
 */
struct StartupData {
    uint64_t magic;       /* == SVSD_MAGIC */
    uint32_t version;     /* == SVSD_VERSION */
    uint32_t flags;       /* SVSD_FLAG_* */
    uint64_t struct_size; /* sizeof(struct StartupData) the loader wrote */

    uint64_t core_count;   /* number of online cores (>= 1) */
    uint64_t boot_core_id; /* core that entered the kernel (SVSR_CORE_ID) */

    uint64_t mem_map;       /* phys ptr to MemMapEntry[mem_map_count] */
    uint64_t mem_map_count; /* number of memory-map entries */

    uint64_t initramfs_base; /* phys base of initramfs, or 0 if none */
    uint64_t initramfs_size; /* initramfs size in bytes, or 0 if none */

    uint64_t cmdline;      /* phys ptr to NUL-terminated cmdline, or 0 */
    uint64_t cmdline_size; /* cmdline length incl. NUL, or 0 */

    uint64_t dtb;      /* phys ptr to devicetree/boot-params blob, or 0 */
    uint64_t dtb_size; /* blob size in bytes, or 0 if none */
};

#endif /* STACKVM_BOOT_H */
