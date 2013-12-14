#ifndef CMPXCHG_32_H_
#define CMPXCHG_32_H_

static inline void set_64bit(volatile u64 *ptr, u64 value)
{
	u32 low  = value;
	u32 high = value >> 32;
	u64 prev = *ptr;

	asm volatile("\n1:\t"
		     "lock cmpxchg8b %0\n\t"
		     "jnz 1b"
		     : "=m" (*ptr), "+A" (prev)
		     : "b" (low), "c" (high)
		     : "memory");
}

#define cmpxchg64(ptr, o, n)						\
	((__typeof__(*(ptr)))__cmpxchg64((ptr), (unsigned long long)(o), \
					 (unsigned long long)(n)))
#define cmpxchg64_local(ptr, o, n)					\
	((__typeof__(*(ptr)))__cmpxchg64_local((ptr), (unsigned long long)(o), \
					       (unsigned long long)(n)))

static inline u64 __cmpxchg64(volatile u64 *ptr, u64 old, u64 thenew)
{
	u64 prev;
	asm volatile("lock cmpxchg8b %1"
		     : "=A" (prev),
		       "+m" (*ptr)
		     : "b" ((u32)thenew),
		       "c" ((u32)(thenew >> 32)),
		       "0" (old)
		     : "memory");
	return prev;
}

static inline u64 __cmpxchg64_local(volatile u64 *ptr, u64 old, u64 thenew)
{
	u64 prev;
	asm volatile("cmpxchg8b %1"
		     : "=A" (prev),
		       "+m" (*ptr)
		     : "b" ((u32)thenew),
		       "c" ((u32)(thenew >> 32)),
		       "0" (old)
		     : "memory");
	return prev;
}


#define cmpxchg8b(ptr, o1, o2, n1, n2)				\
({								\
	char __ret;						\
	__typeof__(o2) __dummy;					\
	__typeof__(*(ptr)) __old1 = (o1);			\
	__typeof__(o2) __old2 = (o2);				\
	__typeof__(*(ptr)) __new1 = (n1);			\
	__typeof__(o2) __new2 = (n2);				\
	asm volatile(LOCK_PREFIX "cmpxchg8b %2; setz %1"	\
		       : "=d"(__dummy), "=a" (__ret), "+m" (*ptr)\
		       : "a" (__old1), "d"(__old2),		\
		         "b" (__new1), "c" (__new2)		\
		       : "memory");				\
	__ret; })


#define cmpxchg8b_local(ptr, o1, o2, n1, n2)			\
({								\
	char __ret;						\
	__typeof__(o2) __dummy;					\
	__typeof__(*(ptr)) __old1 = (o1);			\
	__typeof__(o2) __old2 = (o2);				\
	__typeof__(*(ptr)) __new1 = (n1);			\
	__typeof__(o2) __new2 = (n2);				\
	asm volatile("cmpxchg8b %2; setz %1"			\
		       : "=d"(__dummy), "=a"(__ret), "+m" (*ptr)\
		       : "a" (__old), "d"(__old2),		\
		         "b" (__new1), "c" (__new2),		\
		       : "memory");				\
	__ret; })


#define cmpxchg_double(ptr, o1, o2, n1, n2)				\
({									\
	cmpxchg8b((ptr), (o1), (o2), (n1), (n2));			\
})

#define cmpxchg_double_local(ptr, o1, o2, n1, n2)			\
({									\
       cmpxchg16b_local((ptr), (o1), (o2), (n1), (n2));			\
})



#endif /* CMPXCHG_32_H_ */
