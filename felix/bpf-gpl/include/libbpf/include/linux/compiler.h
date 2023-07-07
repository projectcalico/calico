/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

#ifndef __LINUX_COMPILER_H
#define __LINUX_COMPILER_H

#define likely(x)		__builtin_expect(!!(x), 1)
#define unlikely(x)		__builtin_expect(!!(x), 0)

#define READ_ONCE(x)		(*(volatile typeof(x) *)&x)
#define WRITE_ONCE(x, v)	(*(volatile typeof(x) *)&x) = (v)

#define barrier()		asm volatile("" ::: "memory")

#if defined(__x86_64__)

# define smp_rmb()		barrier()
# define smp_wmb()		barrier()
# define smp_mb()		asm volatile("lock; addl $0,-132(%%rsp)" ::: "memory", "cc")

# define smp_store_release(p, v)		\
do {						\
	barrier();				\
	WRITE_ONCE(*p, v);			\
} while (0)

# define smp_load_acquire(p)			\
({						\
	typeof(*p) ___p = READ_ONCE(*p);	\
	barrier();				\
	___p;					\
})

#elif defined(__aarch64__)

# define smp_rmb()		asm volatile("dmb ishld" ::: "memory")
# define smp_wmb()		asm volatile("dmb ishst" ::: "memory")
# define smp_mb()		asm volatile("dmb ish" ::: "memory")

#endif

#ifndef smp_mb
# define smp_mb()		__sync_synchronize()
#endif

#ifndef smp_rmb
# define smp_rmb()		smp_mb()
#endif

#ifndef smp_wmb
# define smp_wmb()		smp_mb()
#endif

#ifndef smp_store_release
# define smp_store_release(p, v)		\
do {						\
	smp_mb();				\
	WRITE_ONCE(*p, v);			\
} while (0)
#endif

#ifndef smp_load_acquire
# define smp_load_acquire(p)			\
({						\
	typeof(*p) ___p = READ_ONCE(*p);	\
	smp_mb();				\
	___p;					\
})
#endif

#endif /* __LINUX_COMPILER_H */
