#ifndef BITS_OPERATION_H_
#define BITS_OPERATION_H_

#include "bit_defs.h"

static inline void set_bit(unsigned int nr, volatile unsigned long *addr)
{
	if (IS_IMMEDIATE(nr))
	{
		asm volatile(LOCK_PREFIX "orb %1,%0"
			: CONST_MASK_ADDR(nr, addr)
			: "iq" ((u8)CONST_MASK(nr))
			: "memory");
	}
	else
	{
		asm volatile(LOCK_PREFIX "bts %1,%0"
			: BITOP_ADDR(addr) : "Ir" (nr) : "memory");
	}
}

static inline void __set_bit(int nr, volatile unsigned long *addr)
{
	asm volatile("bts %1,%0" : ADDR : "Ir" (nr) : "memory");
}

static inline void clear_bit(int nr, volatile unsigned long *addr)
{
	if (IS_IMMEDIATE(nr))
	{
		asm volatile(LOCK_PREFIX "andb %1,%0"
			: CONST_MASK_ADDR(nr, addr)
			: "iq" ((u8)~CONST_MASK(nr)));
	}
	else
	{
		asm volatile(LOCK_PREFIX "btr %1,%0"
			: BITOP_ADDR(addr)
			: "Ir" (nr));
	}
}

static inline void clear_bit_unlock(unsigned nr, volatile unsigned long *addr)
{
	barrier();
	clear_bit(nr, addr);
}

static inline void __clear_bit(int nr, volatile unsigned long *addr)
{
	asm volatile("btr %1,%0" : ADDR : "Ir" (nr));
}

static inline void __clear_bit_unlock(unsigned nr, volatile unsigned long *addr)
{
	barrier();
	__clear_bit(nr, addr);
}

#define smp_mb__before_clear_bit()	barrier()
#define smp_mb__after_clear_bit()	barrier()

static inline void __change_bit(int nr, volatile unsigned long *addr)
{
	asm volatile("btc %1,%0" : ADDR : "Ir" (nr));
}

static inline void change_bit(int nr, volatile unsigned long *addr)
{
	if (IS_IMMEDIATE(nr))
	{
		asm volatile(LOCK_PREFIX "xorb %1,%0"
			: CONST_MASK_ADDR(nr, addr)
			: "iq" ((u8)CONST_MASK(nr)));
	}
	else
	{
		asm volatile(LOCK_PREFIX "btc %1,%0"
			: BITOP_ADDR(addr)
			: "Ir" (nr));
	}
}

static inline int test_and_set_bit(int nr, volatile unsigned long *addr)
{
	int oldbit;

	asm volatile(LOCK_PREFIX "bts %2,%1\n\t"
		     "sbb %0,%0" : "=r" (oldbit), ADDR : "Ir" (nr) : "memory");

	return oldbit;
}

static inline int test_and_set_bit_lock(int nr, volatile unsigned long *addr)
{
	return test_and_set_bit(nr, addr);
}

static inline int __test_and_set_bit(int nr, volatile unsigned long *addr)
{
	int oldbit;

	asm("bts %2,%1\n\t"
	    "sbb %0,%0"
	    : "=r" (oldbit), ADDR
	    : "Ir" (nr));
	return oldbit;
}

static inline int test_and_clear_bit(int nr, volatile unsigned long *addr)
{
	int oldbit;

	asm volatile(LOCK_PREFIX "btr %2,%1\n\t"
		     "sbb %0,%0"
		     : "=r" (oldbit), ADDR : "Ir" (nr) : "memory");

	return oldbit;
}

static inline int __test_and_clear_bit(int nr, volatile unsigned long *addr)
{
	int oldbit;

	asm volatile("btr %2,%1\n\t"
		     "sbb %0,%0"
		     : "=r" (oldbit), ADDR
		     : "Ir" (nr));
	return oldbit;
}

static inline int __test_and_change_bit(int nr, volatile unsigned long *addr)
{
	int oldbit;

	asm volatile("btc %2,%1\n\t"
		     "sbb %0,%0"
		     : "=r" (oldbit), ADDR
		     : "Ir" (nr) : "memory");

	return oldbit;
}

static inline int test_and_change_bit(int nr, volatile unsigned long *addr)
{
	int oldbit;

	asm volatile(LOCK_PREFIX "btc %2,%1\n\t"
		     "sbb %0,%0"
		     : "=r" (oldbit), ADDR : "Ir" (nr) : "memory");

	return oldbit;
}

#define BITOP_LE_SWIZZLE 0
static inline int test_and_set_bit_le(int nr, void *addr)
{
        return test_and_set_bit(nr ^ BITOP_LE_SWIZZLE, (volatile unsigned long *)(addr));
}

static inline int constant_test_bit(unsigned int nr, const volatile unsigned long *addr)
{
	return ((VMMR0_LPULL(1) << (nr % BITS_PER_LONG)) &
		(addr[nr / BITS_PER_LONG])) != 0;
}

static inline int variable_test_bit(int nr, volatile const unsigned long *addr)
{
	int oldbit;

	asm volatile("bt %2,%1\n\t"
		     "sbb %0,%0"
		     : "=r" (oldbit)
		     : "m" (*(unsigned long *)addr), "Ir" (nr));

	return oldbit;
}


#define test_bit(nr, addr)			\
	(__builtin_constant_p((nr))		\
	 ? constant_test_bit((nr), (addr))	\
	 : variable_test_bit((nr), (addr)))


static inline unsigned long __ffs(unsigned long word)
{
	asm("bsf %1,%0"
		: "=r" (word)
		: "rm" (word));
	return word;
}

static inline unsigned long ffz(unsigned long word)
{
	asm("bsf %1,%0"
		: "=r" (word)
		: "r" (~word));
	return word;
}

static inline unsigned long __fls(unsigned long word)
{
	asm("bsr %1,%0"
	    : "=r" (word)
	    : "rm" (word));
	return word;
}

static inline int ffs(int x)
{
	int r;
	__asm__("bsfl %1,%0\n\t"
	    "jnz 1f\n\t"
	    "movl $-1,%0\n"
	    "1:" : "=r" (r) : "rm" (x));
	return r + 1;
}

/**
 * fls - find last set bit in word
 * @x: the word to search
 *
 * This is defined in a similar way as the libc and compiler builtin
 * ffs, but returns the position of the most significant set bit.
 *
 * fls(value) returns 0 if value is 0 or the position of the last
 * set bit if value is nonzero. The last (most significant) bit is
 * at position 32.
 */
static inline int fls(int x)
{
	int r;
	__asm__("bsrl %1,%0\n\t"
	    "jnz 1f\n\t"
	    "movl $-1,%0\n"
	    "1:" : "=r" (r) : "rm" (x));
	return r + 1;
}

#if BITS_PER_LONG == 32
static inline int fls64(__u64 x)
{
	__u32 h = x >> 32;
	if (h)
	{
		return fls(h) + 32;
	}
	return fls(x);
}
#elif BITS_PER_LONG == 64
static inline int fls64(__u64 x)
{
	if (x == 0)
	{
		return 0;
	}
	return __fls(x) + 1;
}
#else
#error BITS_PER_LONG not 32 or 64
#endif

static inline unsigned fls_long(unsigned long l)
{
	if (sizeof(l) == 4)
	{
		return fls(l);
	}
	return fls64(l);
}

#define BITOP_WORD(nr)        ((nr) / BITS_PER_LONG)

static inline unsigned long find_next_bit(const unsigned long *addr, unsigned long size, unsigned long offset)
{
	const unsigned long *p = addr + BITOP_WORD(offset);
	unsigned long result = offset & ~(BITS_PER_LONG-1);
	unsigned long tmp;

	if (offset >= size)
	{
		return size;
	}
	size -= result;
	offset %= BITS_PER_LONG;
	if (offset)
	{
		tmp = *(p++);
		tmp &= (~VMMR0_LPULL(0) << offset);
		if (size < BITS_PER_LONG)
		{
			goto found_first;
		}
		if (tmp)
		{
			goto found_middle;
		}
		size -= BITS_PER_LONG;
		result += BITS_PER_LONG;
	}
	while (size & ~(BITS_PER_LONG-1))
	{
		if ((tmp = *(p++)))
		{
			goto found_middle;
		}
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
	{
		return result;
	}
	tmp = *p;

found_first:
	tmp &= (~VMMR0_LPULL(0) >> (BITS_PER_LONG - size));
	if (tmp == VMMR0_LPULL(0))		/** Are any bits set? */
	{
		return result + size;	/** Nope. */
	}
found_middle:
	return result + __ffs(tmp);
}

static inline unsigned long find_next_zero_bit(const unsigned long *addr, unsigned long size, unsigned long offset)
{
	const unsigned long *p = addr + BITOP_WORD(offset);
	unsigned long result = offset & ~(BITS_PER_LONG-1);
	unsigned long tmp;

	if (offset >= size)
	{
		return size;
	}
	size -= result;
	offset %= BITS_PER_LONG;
	if (offset)
	{
		tmp = *(p++);
		tmp |= ~VMMR0_LPULL(0) >> (BITS_PER_LONG - offset);
		if (size < BITS_PER_LONG)
		{
			goto found_first;
		}
		if (~tmp)
		{
			goto found_middle;
		}
		size -= BITS_PER_LONG;
		result += BITS_PER_LONG;
	}
	while (size & ~(BITS_PER_LONG-1))
	{
		if (~(tmp = *(p++)))
		{
			goto found_middle;
		}
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
	{
		return result;
	}
	tmp = *p;

found_first:
	tmp |= ~VMMR0_LPULL(0) << size;
	if (tmp == ~VMMR0_LPULL(0))	/** Are any bits zero? */
	{
		return result + size;	/** Nope. */
	}
found_middle:
	return result + ffz(tmp);
}

static inline unsigned long find_first_bit(const unsigned long *addr, unsigned long size)
{
	const unsigned long *p = addr;
	unsigned long result = 0;
	unsigned long tmp;

	while (size & ~(BITS_PER_LONG-1))
	{
		if ((tmp = *(p++)))
		{
			goto found;
		}
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
	{
		return result;
	}

	tmp = (*p) & (~VMMR0_LPULL(0) >> (BITS_PER_LONG - size));
	if (tmp == VMMR0_LPULL(0))		/** Are any bits set? */
	{
		return result + size;	/** Nope. */
	}
found:
	return result + __ffs(tmp);
}

static inline unsigned long find_first_zero_bit(const unsigned long *addr, unsigned long size)
{
	const unsigned long *p = addr;
	unsigned long result = 0;
	unsigned long tmp;

	while (size & ~(BITS_PER_LONG-1))
	{
		if (~(tmp = *(p++)))
		{
			goto found;
		}
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
	{
		return result;
	}

	tmp = (*p) | (~VMMR0_LPULL(0) << size);
	if (tmp == ~VMMR0_LPULL(0))	/** Are any bits zero? */
	{
		return result + size;	/** Nope. */
	}
found:
	return result + ffz(tmp);
}

#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size)); \
	     (bit) < (size); \
	     (bit) = find_next_bit((addr), (size), (bit) + 1))


#endif /* BITS_OPERATION_H_ */
