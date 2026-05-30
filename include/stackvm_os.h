/*
 * stackvm_os.h — Basic OS services for StackVM programs.
 *
 * Provides:
 *   - Standard file-descriptor constants (FD_STDIN, FD_STDOUT, FD_STDERR)
 *   - Process control: sys_exit()
 *   - I/O:            sys_write(), sys_read()
 *   - File I/O:       sys_open(), sys_close(), sys_seek()
 *
 * Syscall numbers (host-side implementation in StackVM/syscalls/os_sys.py):
 *
 *   SYS_EXIT     0x10
 *   SYS_WRITE    0x11
 *   SYS_READ     0x12
 *   SYS_OPEN     0x13
 *   SYS_CLOSE    0x14
 *   SYS_SEEK     0x15
 */

#ifndef STACKVM_OS_H
#define STACKVM_OS_H

#include "stackvm.h"

/* ---- File descriptors -------------------------------------------------- */
#define FD_STDIN 0
#define FD_STDOUT 1
#define FD_STDERR 2

/* ---- sys_open flags ----------------------------------------------------- */
#define OPEN_READ 0      /* open for reading only */
#define OPEN_WRITE 1     /* open for writing only (must exist) */
#define OPEN_READWRITE 2 /* open for reading and writing */
#define OPEN_WRITE_NEW 3 /* create/truncate for writing */

/* ---- sys_seek whence values -------------------------------------------- */
#define SEEK_SET 0 /* from start of file */
#define SEEK_CUR 1 /* from current position */
#define SEEK_END 2 /* from end of file */

/* ---- Error sentinel ----------------------------------------------------- */
#define SYS_ERROR ((size_t)(-1)) /* syscall returned an error */

/* ---- Syscall numbers ---------------------------------------------------- */
#define SYS_EXIT 0x10
#define SYS_WRITE 0x11
#define SYS_READ 0x12
#define SYS_OPEN 0x13
#define SYS_CLOSE 0x14
#define SYS_SEEK 0x15

/* ========================================================================= */
/* Inline wrappers                                                            */
/* ========================================================================= */

/* Terminate the process with *exit_code*. */
static inline void sys_exit(int exit_code)
{
    syscall(SYS_EXIT, (size_t)exit_code, 0, 0, 0);
}

/*
 * Write *len* bytes from *buf* to file descriptor *fd*.
 * Returns the number of bytes written, or SYS_ERROR on failure.
 */
static inline ssize_t sys_write(size_t fd, const void *buf, size_t len)
{
    return (ssize_t)syscall(SYS_WRITE, fd, (size_t)buf, len, 0);
}

/*
 * Read up to *len* bytes from file descriptor *fd* into *buf*.
 * Returns the number of bytes read (0 = EOF), or SYS_ERROR on failure.
 */
static inline ssize_t sys_read(size_t fd, void *buf, size_t len)
{
    return (ssize_t)syscall(SYS_READ, fd, (size_t)buf, len, 0);
}

/*
 * Open the file at *path* with *flags* (see OPEN_* constants).
 * Returns a file descriptor >= 3, or SYS_ERROR on failure.
 */
static inline size_t sys_open(const char *path, size_t flags)
{
    return syscall(SYS_OPEN, (size_t)path, flags, 0, 0);
}

/*
 * Close file descriptor *fd*.
 * No-op for FD_STDIN / FD_STDOUT / FD_STDERR.
 */
static inline void sys_close(size_t fd)
{
    syscall(SYS_CLOSE, fd, 0, 0, 0);
}

/*
 * Reposition the read/write offset of *fd* by *offset* bytes from *whence*
 * (SEEK_SET / SEEK_CUR / SEEK_END).
 * Returns the new byte offset, or SYS_ERROR on failure.
 */
static inline ssize_t sys_seek(size_t fd, ssize_t offset, size_t whence)
{
    return (ssize_t)syscall(SYS_SEEK, fd, (size_t)offset, whence, 0);
}

/* ---- Convenience: write a null-terminated string to stdout -------------- */
static inline void print_str(const char *s)
{
    /* Count length */
    size_t len = 0;
    while (s[len])
        len++;
    sys_write(FD_STDOUT, s, len);
}

#endif /* STACKVM_OS_H */
