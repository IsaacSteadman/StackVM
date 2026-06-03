#ifndef STDATOMIC_H
#define STDATOMIC_H

#include "stackvm.h"
#include "stdbool.h"

/*
 * StackVM currently exposes a 2-bit ordering byte:
 *   0 = relaxed
 *   1 = acquire
 *   2 = release
 *   3 = seq_cst
 *
 * C11 orders that do not have a distinct StackVM encoding are conservatively
 * aliased to the nearest stronger supported mode.
 */
typedef unsigned char memory_order;

#define memory_order_relaxed 0
#define memory_order_consume 1
#define memory_order_acquire 1
#define memory_order_release 2
#define memory_order_acq_rel 3
#define memory_order_seq_cst 3

#define ATOMIC_VAR_INIT(value) (value)
#define atomic_init(obj, value) ((void)(*(obj) = (value)))

typedef _Atomic _Bool atomic_bool;
typedef _Atomic char atomic_char;
typedef _Atomic signed char atomic_schar;
typedef _Atomic unsigned char atomic_uchar;
typedef _Atomic short atomic_short;
typedef _Atomic unsigned short atomic_ushort;
typedef _Atomic int atomic_int;
typedef _Atomic unsigned int atomic_uint;
typedef _Atomic long atomic_long;
typedef _Atomic unsigned long atomic_ulong;
typedef _Atomic long long atomic_llong;
typedef _Atomic unsigned long long atomic_ullong;
typedef _Atomic size_t atomic_size_t;
typedef _Atomic ptrdiff_t atomic_ptrdiff_t;
typedef _Atomic uintptr_t atomic_uintptr_t;

#define atomic_store_explicit(obj, value, order) \
    __svm_atomic_store_explicit((obj), (value), (order))
#define atomic_load_explicit(obj, order) \
    __svm_atomic_load_explicit((obj), (order))
#define atomic_exchange_explicit(obj, value, order) \
    __svm_atomic_exchange_explicit((obj), (value), (order))
#define atomic_compare_exchange_strong_explicit(obj, expected, desired, succ, fail) \
    __svm_atomic_compare_exchange_strong_explicit( \
        (obj), (expected), (desired), (succ), (fail))
#define atomic_compare_exchange_weak_explicit(obj, expected, desired, succ, fail) \
    atomic_compare_exchange_strong_explicit((obj), (expected), (desired), (succ), (fail))
#define atomic_fetch_add_explicit(obj, value, order) \
    __svm_atomic_fetch_add_explicit((obj), (value), (order))
#define atomic_fetch_sub_explicit(obj, value, order) \
    __svm_atomic_fetch_sub_explicit((obj), (value), (order))
#define atomic_fetch_and_explicit(obj, value, order) \
    __svm_atomic_fetch_and_explicit((obj), (value), (order))
#define atomic_fetch_or_explicit(obj, value, order) \
    __svm_atomic_fetch_or_explicit((obj), (value), (order))
#define atomic_fetch_xor_explicit(obj, value, order) \
    __svm_atomic_fetch_xor_explicit((obj), (value), (order))

#define atomic_store(obj, value) \
    atomic_store_explicit((obj), (value), memory_order_seq_cst)
#define atomic_load(obj) \
    atomic_load_explicit((obj), memory_order_seq_cst)
#define atomic_exchange(obj, value) \
    atomic_exchange_explicit((obj), (value), memory_order_seq_cst)
#define atomic_compare_exchange_strong(obj, expected, desired) \
    atomic_compare_exchange_strong_explicit( \
        (obj), (expected), (desired), memory_order_seq_cst, memory_order_seq_cst)
#define atomic_compare_exchange_weak(obj, expected, desired) \
    atomic_compare_exchange_weak_explicit( \
        (obj), (expected), (desired), memory_order_seq_cst, memory_order_seq_cst)
#define atomic_fetch_add(obj, value) \
    atomic_fetch_add_explicit((obj), (value), memory_order_seq_cst)
#define atomic_fetch_sub(obj, value) \
    atomic_fetch_sub_explicit((obj), (value), memory_order_seq_cst)
#define atomic_fetch_and(obj, value) \
    atomic_fetch_and_explicit((obj), (value), memory_order_seq_cst)
#define atomic_fetch_or(obj, value) \
    atomic_fetch_or_explicit((obj), (value), memory_order_seq_cst)
#define atomic_fetch_xor(obj, value) \
    atomic_fetch_xor_explicit((obj), (value), memory_order_seq_cst)

#endif /* STDATOMIC_H */
