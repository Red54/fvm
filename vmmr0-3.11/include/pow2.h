#ifndef POW2_H_
#define POW2_H_
#include "bits_operation.h"

static inline int __ilog2_u32(u32 n)
{
	return fls(n) - 1;
}

static inline int __ilog2_u64(u64 n)
{
	return fls64(n) - 1;
}

static inline __attribute__((const))
bool is_power_of_2(unsigned long n)
{
	return (n != 0 && ((n & (n - 1)) == 0));
}

static inline unsigned long __roundup_pow_of_two(unsigned long n)
{
	return VMMR0_LPUL(1) << fls_long(n - 1);
}

static inline unsigned long __rounddown_pow_of_two(unsigned long n)
{
	return VMMR0_LPUL(1) << (fls_long(n) - 1);
}

#define ilog2(n)				\
(						\
	__builtin_constant_p(n) ? (		\
		(n) < 1 ? ____ilog2_NaN() :	\
		(n) & (VMMR0_LPULL(1) << 63) ? 63 :	\
		(n) & (VMMR0_LPULL(1) << 62) ? 62 :	\
		(n) & (VMMR0_LPULL(1) << 61) ? 61 :	\
		(n) & (VMMR0_LPULL(1) << 60) ? 60 :	\
		(n) & (VMMR0_LPULL(1) << 59) ? 59 :	\
		(n) & (VMMR0_LPULL(1) << 58) ? 58 :	\
		(n) & (VMMR0_LPULL(1) << 57) ? 57 :	\
		(n) & (VMMR0_LPULL(1) << 56) ? 56 :	\
		(n) & (VMMR0_LPULL(1) << 55) ? 55 :	\
		(n) & (VMMR0_LPULL(1) << 54) ? 54 :	\
		(n) & (VMMR0_LPULL(1) << 53) ? 53 :	\
		(n) & (VMMR0_LPULL(1) << 52) ? 52 :	\
		(n) & (VMMR0_LPULL(1) << 51) ? 51 :	\
		(n) & (VMMR0_LPULL(1) << 50) ? 50 :	\
		(n) & (VMMR0_LPULL(1) << 49) ? 49 :	\
		(n) & (VMMR0_LPULL(1) << 48) ? 48 :	\
		(n) & (VMMR0_LPULL(1) << 47) ? 47 :	\
		(n) & (VMMR0_LPULL(1) << 46) ? 46 :	\
		(n) & (VMMR0_LPULL(1) << 45) ? 45 :	\
		(n) & (VMMR0_LPULL(1) << 44) ? 44 :	\
		(n) & (VMMR0_LPULL(1) << 43) ? 43 :	\
		(n) & (VMMR0_LPULL(1) << 42) ? 42 :	\
		(n) & (VMMR0_LPULL(1) << 41) ? 41 :	\
		(n) & (VMMR0_LPULL(1) << 40) ? 40 :	\
		(n) & (VMMR0_LPULL(1) << 39) ? 39 :	\
		(n) & (VMMR0_LPULL(1) << 38) ? 38 :	\
		(n) & (VMMR0_LPULL(1) << 37) ? 37 :	\
		(n) & (VMMR0_LPULL(1) << 36) ? 36 :	\
		(n) & (VMMR0_LPULL(1) << 35) ? 35 :	\
		(n) & (VMMR0_LPULL(1) << 34) ? 34 :	\
		(n) & (VMMR0_LPULL(1) << 33) ? 33 :	\
		(n) & (VMMR0_LPULL(1) << 32) ? 32 :	\
		(n) & (VMMR0_LPULL(1) << 31) ? 31 :	\
		(n) & (VMMR0_LPULL(1) << 30) ? 30 :	\
		(n) & (VMMR0_LPULL(1) << 29) ? 29 :	\
		(n) & (VMMR0_LPULL(1) << 28) ? 28 :	\
		(n) & (VMMR0_LPULL(1) << 27) ? 27 :	\
		(n) & (VMMR0_LPULL(1) << 26) ? 26 :	\
		(n) & (VMMR0_LPULL(1) << 25) ? 25 :	\
		(n) & (VMMR0_LPULL(1) << 24) ? 24 :	\
		(n) & (VMMR0_LPULL(1) << 23) ? 23 :	\
		(n) & (VMMR0_LPULL(1) << 22) ? 22 :	\
		(n) & (VMMR0_LPULL(1) << 21) ? 21 :	\
		(n) & (VMMR0_LPULL(1) << 20) ? 20 :	\
		(n) & (VMMR0_LPULL(1) << 19) ? 19 :	\
		(n) & (VMMR0_LPULL(1) << 18) ? 18 :	\
		(n) & (VMMR0_LPULL(1) << 17) ? 17 :	\
		(n) & (VMMR0_LPULL(1) << 16) ? 16 :	\
		(n) & (VMMR0_LPULL(1) << 15) ? 15 :	\
		(n) & (VMMR0_LPULL(1) << 14) ? 14 :	\
		(n) & (VMMR0_LPULL(1) << 13) ? 13 :	\
		(n) & (VMMR0_LPULL(1) << 12) ? 12 :	\
		(n) & (VMMR0_LPULL(1) << 11) ? 11 :	\
		(n) & (VMMR0_LPULL(1) << 10) ? 10 :	\
		(n) & (VMMR0_LPULL(1) <<  9) ?  9 :	\
		(n) & (VMMR0_LPULL(1) <<  8) ?  8 :	\
		(n) & (VMMR0_LPULL(1) <<  7) ?  7 :	\
		(n) & (VMMR0_LPULL(1) <<  6) ?  6 :	\
		(n) & (VMMR0_LPULL(1) <<  5) ?  5 :	\
		(n) & (VMMR0_LPULL(1) <<  4) ?  4 :	\
		(n) & (VMMR0_LPULL(1) <<  3) ?  3 :	\
		(n) & (VMMR0_LPULL(1) <<  2) ?  2 :	\
		(n) & (VMMR0_LPULL(1) <<  1) ?  1 :	\
		(n) & (VMMR0_LPULL(1) <<  0) ?  0 :	\
		____ilog2_NaN()			\
				   ) :		\
	(sizeof(n) <= 4) ?			\
	__ilog2_u32(n) :			\
	__ilog2_u64(n)				\
 )

#define roundup_pow_of_two(n)			\
(						\
	__builtin_constant_p(n) ? (		\
		(n == 1) ? 1 :			\
		(VMMR0_LPUL(1) << (ilog2((n) - 1) + 1))	\
				   ) :		\
	__roundup_pow_of_two(n)			\
 )

#define rounddown_pow_of_two(n)			\
(						\
	__builtin_constant_p(n) ? (		\
		(VMMR0_LPUL(1) << ilog2(n))) :		\
	__rounddown_pow_of_two(n)		\
 )


#endif /* POW2_H_ */
