/*
 * stackvm_time.h — Clock and sleep services for StackVM programs.
 *
 * Provides:
 *   - sys_clock_ns()  nanoseconds since the Unix epoch (time.time_ns()).
 *   - sys_sleep_ns()  sleep for a given number of nanoseconds.
 *
 * Syscall numbers (host-side implementation in StackVM/syscalls/os_sys.py):
 *
 *   SYS_CLOCK_NS   0x18
 *   SYS_SLEEP_NS   0x19
 */

#ifndef STACKVM_TIME_H
#define STACKVM_TIME_H

#include "stackvm.h"

#define SYS_CLOCK_NS 0x18
#define SYS_SLEEP_NS 0x19

/*
 * Return the current wall-clock time in nanoseconds since the Unix epoch.
 * Wraps Python's time.time_ns().
 */
static inline uint64_t sys_clock_ns(void)
{
    return (uint64_t)syscall(SYS_CLOCK_NS, 0, 0, 0, 0);
}

/*
 * Sleep for *ns* nanoseconds.
 */
static inline void sys_sleep_ns(uint64_t ns)
{
    syscall(SYS_SLEEP_NS, ns, 0, 0, 0);
}

/* Convenience: sleep for *ms* milliseconds. */
static inline void sys_sleep_ms(uint64_t ms)
{
    sys_sleep_ns(ms * 1000000ULL);
}

/* Convenience: sleep for *s* seconds (integer). */
static inline void sys_sleep_s(uint64_t s)
{
    sys_sleep_ns(s * 1000000000ULL);
}

#endif /* STACKVM_TIME_H */
