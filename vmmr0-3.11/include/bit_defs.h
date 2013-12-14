/*
 * bit_defs.h
 *
 */

#ifndef BIT_DEFS_H_
#define BIT_DEFS_H_


#ifdef CONFIG_64BIT
#define BITS_PER_LONG 64
#else
#define BITS_PER_LONG 32
#endif /* CONFIG_64BIT */

#define	DIV_ROUND_UP(x,y)	(((x) + ((y) - 1)) / (y))

#define BIT(nr)				(VMMR0_LPUL(1) << (nr))
#define BIT_MASK(nr)		(VMMR0_LPUL(1) << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define BITS_PER_BYTE		8
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

#if __GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 1)

#define BITOP_ADDR(x) "=m" (*(volatile long *) (x))
#else
#define BITOP_ADDR(x) "+m" (*(volatile long *) (x))
#endif

#define ADDR				BITOP_ADDR(addr)


#define IS_IMMEDIATE(nr)		(__builtin_constant_p(nr))
#define CONST_MASK_ADDR(nr, addr)	BITOP_ADDR((void *)(addr) + ((nr)>>3))
#define CONST_MASK(nr)			(1 << ((nr) & 7))

#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))
#define lower_32_bits(n) ((u32)(n))


#endif /* BIT_DEFS_H_ */
