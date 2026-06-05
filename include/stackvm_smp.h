#ifndef STACKVM_SMP_H
#define STACKVM_SMP_H

#include "stackvm.h"

#define __percpu __attribute__((section(".data..percpu")))
#define DEFINE_PER_CPU(type, name) type __percpu name
#define DECLARE_PER_CPU(type, name) extern type __percpu name

#define __stackvm_percpu_ptr(var) \
    ((typeof(var) *)__stackvm_percpu_addr(&(var)))

#define get_cpu_var(var) (*__stackvm_percpu_ptr(var))
#define put_cpu_var(var) (0)

#endif /* STACKVM_SMP_H */
