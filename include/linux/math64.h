#ifndef LINUX_MATH64_H
#define LINUX_MATH64_H

#include "../stackvm.h"

uint64_t div64_u64(uint64_t dividend, uint64_t divisor);
uint64_t div_u64_rem(uint64_t dividend, uint32_t divisor, uint32_t *remainder);

#endif /* LINUX_MATH64_H */
