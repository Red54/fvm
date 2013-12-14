/*
 * bitmap.h
 */

#ifndef BITMAP_H_
#define BITMAP_H_

#include "bits_operation.h"

#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]

#define BITMAP_FIRST_WORD_MASK(start) (~VMMR0_LPUL(0) << ((start) % BITS_PER_LONG))
#define BITMAP_LAST_WORD_MASK(nbits)					\
(														\
	((nbits) % BITS_PER_LONG) ?							\
		(VMMR0_LPUL(1)<<((nbits) % BITS_PER_LONG))-1 : ~VMMR0_LPUL(0)		\
)

#define small_const_nbits(nbits) \
	(__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG)

static inline void bitmap_zero(unsigned long *dst, int nbits)
{
	if (small_const_nbits(nbits))
	{
		*dst = VMMR0_LPUL(0);
	}
	else
	{
		int len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
		memset(dst, 0, len);
	}
}

static inline void bitmap_fill(unsigned long *dst, int nbits)
{
	size_t nlongs = BITS_TO_LONGS(nbits);
	if (!small_const_nbits(nbits))
	{
		int len = (nlongs - 1) * sizeof(unsigned long);
		memset(dst, 0xff,  len);
	}
	dst[nlongs - 1] = BITMAP_LAST_WORD_MASK(nbits);
}

static inline void bitmap_copy(unsigned long *dst, const unsigned long *src,
			int nbits)
{
	if (small_const_nbits(nbits))
	{
		*dst = *src;
	}
	else
	{
		int len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
		memcpy(dst, src, len);
	}
}

static inline int __bitmap_empty(const unsigned long *bitmap, int bits)
{
	int k, lim = bits/BITS_PER_LONG;
	for (k = 0; k < lim; ++k)
	{
		if (bitmap[k])
		{
			return 0;
		}
	}

	if (bits % BITS_PER_LONG)
	{
		if (bitmap[k] & BITMAP_LAST_WORD_MASK(bits))
		{
			return 0;
		}
	}

	return 1;
}

static inline int __bitmap_full(const unsigned long *bitmap, int bits)
{
	int k, lim = bits/BITS_PER_LONG;
	for (k = 0; k < lim; ++k)
	{
		if (~bitmap[k])
		{
			return 0;
		}
	}

	if (bits % BITS_PER_LONG)
	{
		if (~bitmap[k] & BITMAP_LAST_WORD_MASK(bits))
		{
			return 0;
		}
	}

	return 1;
}

static inline int __bitmap_equal(const unsigned long *bitmap1,
		const unsigned long *bitmap2, int bits)
{
	int k, lim = bits/BITS_PER_LONG;
	for (k = 0; k < lim; ++k)
	{
		if (bitmap1[k] != bitmap2[k])
		{
			return 0;
		}
	}

	if (bits % BITS_PER_LONG)
	{
		if ((bitmap1[k] ^ bitmap2[k]) & BITMAP_LAST_WORD_MASK(bits))
		{
			return 0;
		}
	}

	return 1;
}

static inline int bitmap_empty(const unsigned long *src, int nbits)
{
	if (small_const_nbits(nbits))
	{
		return ! (*src & BITMAP_LAST_WORD_MASK(nbits));
	}
	else
	{
		return __bitmap_empty(src, nbits);
	}
}

static inline int bitmap_full(const unsigned long *src, int nbits)
{
	if (small_const_nbits(nbits))
	{
		return ! (~(*src) & BITMAP_LAST_WORD_MASK(nbits));
	}
	else
	{
		return __bitmap_full(src, nbits);
	}
}

static inline int bitmap_equal(const unsigned long *src1,
			const unsigned long *src2, int nbits)
{
	if (small_const_nbits(nbits))
	{
		return ! ((*src1 ^ *src2) & BITMAP_LAST_WORD_MASK(nbits));
	}
	else
	{
		return __bitmap_equal(src1, src2, nbits);
	}
}

#endif /* BITMAP_H_ */
