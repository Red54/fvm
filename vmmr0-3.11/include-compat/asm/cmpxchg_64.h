
#ifndef CMPXCHG_64_H_
#define CMPXCHG_64_H_

static inline void set_64bit(volatile u64 *ptr, u64 val)
{
	*ptr = val;
}

#define __HAVE_ARCH_CMPXCHG 1

#define cmpxchg64(ptr, o, n)						\
({									\
	cmpxchg((ptr), (o), (n));					\
})

#define cmpxchg64_local(ptr, o, n)					\
({									\
	cmpxchg_local((ptr), (o), (n));					\
})

#define cmpxchg16b(ptr, o1, o2, n1, n2)				\
({								\
	char __ret;						\
	__typeof__(o2) __junk;					\
	__typeof__(*(ptr)) __old1 = (o1);			\
	__typeof__(o2) __old2 = (o2);				\
	__typeof__(*(ptr)) __new1 = (n1);			\
	__typeof__(o2) __new2 = (n2);				\
	asm volatile(LOCK_PREFIX "cmpxchg16b %2;setz %1"	\
		       : "=d"(__junk), "=a"(__ret), "+m" (*ptr)	\
		       : "b"(__new1), "c"(__new2),		\
		         "a"(__old1), "d"(__old2));		\
	__ret; })


#define cmpxchg16b_local(ptr, o1, o2, n1, n2)			\
({								\
	char __ret;						\
	__typeof__(o2) __junk;					\
	__typeof__(*(ptr)) __old1 = (o1);			\
	__typeof__(o2) __old2 = (o2);				\
	__typeof__(*(ptr)) __new1 = (n1);			\
	__typeof__(o2) __new2 = (n2);				\
	asm volatile("cmpxchg16b %2;setz %1"			\
		       : "=d"(__junk), "=a"(__ret), "+m" (*ptr)	\
		       : "b"(__new1), "c"(__new2),		\
		         "a"(__old1), "d"(__old2));		\
	__ret; })

#define cmpxchg_double(ptr, o1, o2, n1, n2)				\
({									\
	cmpxchg16b((ptr), (o1), (o2), (n1), (n2));			\
})

#define cmpxchg_double_local(ptr, o1, o2, n1, n2)			\
({									\
	cmpxchg16b_local((ptr), (o1), (o2), (n1), (n2));		\
})


#endif /* CMPXCHG_64_H_ */
