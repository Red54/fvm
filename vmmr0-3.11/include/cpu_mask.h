/*
 * cpu_mask.h
 */

#ifndef CPU_MASK_H_
#define CPU_MASK_H_

#define NR_CPUS VMMR0_MAX_VCPU_NUM

typedef struct cpumask { DECLARE_BITMAP(bits, NR_CPUS); } cpumask_t;

typedef struct cpumask *cpumask_var_t;

#define cpu_online_mask (&cpu_online_map)

#define cpu_possible_mask cpu_online_mask

#define nr_cpumask_bits	NR_CPUS


#define cpumask_bits(maskp) ((maskp)->bits)

static inline unsigned int cpumask_check(unsigned int cpu)
{
	return cpu;
}

static inline unsigned int cpumask_first(const struct cpumask *srcp)
{
	return find_first_bit(cpumask_bits(srcp), nr_cpumask_bits);
}

static inline unsigned int cpumask_next(int n, const struct cpumask *srcp)
{
	if (n != -1)
	{
		cpumask_check(n);
	}
	return find_next_bit(cpumask_bits(srcp), nr_cpumask_bits, n+1);
}

static inline unsigned int cpumask_next_zero(int n, const struct cpumask *srcp)
{
	if (n != -1)
	{
		cpumask_check(n);
	}
	return find_next_zero_bit(cpumask_bits(srcp), nr_cpumask_bits, n+1);
}

#define for_each_cpu(cpu, mask)					\
	for ((cpu) = -1;							\
		(cpu) = cpumask_next((cpu), (mask)),	\
		(cpu) < nr_cpu_ids;)

#define for_each_cpu_not(cpu, mask)					\
	for ((cpu) = -1;								\
		(cpu) = cpumask_next_zero((cpu), (mask)),	\
		(cpu) < nr_cpu_ids;)

#define for_each_cpu_and(cpu, mask, and)					\
	for ((cpu) = -1;										\
		(cpu) = cpumask_next_and((cpu), (mask), (and)),		\
		(cpu) < nr_cpu_ids;)

static inline size_t cpumask_size(void)
{
	return BITS_TO_LONGS(NR_CPUS) * sizeof(long);
}

static inline void cpumask_clear(struct cpumask *dstp)
{
	bitmap_zero(cpumask_bits(dstp), nr_cpumask_bits);
}

static inline void cpumask_set_cpu(unsigned int cpu, struct cpumask *dstp)
{
	set_bit(cpumask_check(cpu), cpumask_bits(dstp));
}

static inline void cpumask_clear_cpu(int cpu, struct cpumask *dstp)
{
	clear_bit(cpumask_check(cpu), cpumask_bits(dstp));
}

#define cpumask_test_cpu(cpu, cpumask) \
	test_bit(cpumask_check(cpu), cpumask_bits((cpumask)))


static inline int cpumask_test_and_set_cpu(int cpu, struct cpumask *cpumask)
{
	return test_and_set_bit(cpumask_check(cpu), cpumask_bits(cpumask));
}

static inline int cpumask_test_and_clear_cpu(int cpu, struct cpumask *cpumask)
{
	return test_and_clear_bit(cpumask_check(cpu), cpumask_bits(cpumask));
}

static inline void cpumask_setall(struct cpumask *dstp)
{
	bitmap_fill(cpumask_bits(dstp), nr_cpumask_bits);
}

static inline int cpumask_and(struct cpumask *dstp,
			       const struct cpumask *src1p,
			       const struct cpumask *src2p)
{
	return bitmap_and(cpumask_bits(dstp), cpumask_bits(src1p),
				       cpumask_bits(src2p), nr_cpumask_bits);
}

static inline void cpumask_or(struct cpumask *dstp, const struct cpumask *src1p,
			      const struct cpumask *src2p)
{
	bitmap_or(cpumask_bits(dstp), cpumask_bits(src1p),
				      cpumask_bits(src2p), nr_cpumask_bits);
}

static inline void cpumask_xor(struct cpumask *dstp,
			       const struct cpumask *src1p,
			       const struct cpumask *src2p)
{
	bitmap_xor(cpumask_bits(dstp), cpumask_bits(src1p),
				       cpumask_bits(src2p), nr_cpumask_bits);
}

static inline int cpumask_andnot(struct cpumask *dstp,
				  const struct cpumask *src1p,
				  const struct cpumask *src2p)
{
	return bitmap_andnot(cpumask_bits(dstp), cpumask_bits(src1p),
					  cpumask_bits(src2p), nr_cpumask_bits);
}

static inline void cpumask_complement(struct cpumask *dstp,
				      const struct cpumask *srcp)
{
	bitmap_complement(cpumask_bits(dstp), cpumask_bits(srcp),
					      nr_cpumask_bits);
}

static inline bool cpumask_equal(const struct cpumask *src1p,
				const struct cpumask *src2p)
{
	return bitmap_equal(cpumask_bits(src1p), cpumask_bits(src2p),
						 nr_cpumask_bits);
}

static inline bool cpumask_intersects(const struct cpumask *src1p,
				     const struct cpumask *src2p)
{
	return bitmap_intersects(cpumask_bits(src1p), cpumask_bits(src2p),
						      nr_cpumask_bits);
}

static inline int cpumask_subset(const struct cpumask *src1p,
				 const struct cpumask *src2p)
{
	return bitmap_subset(cpumask_bits(src1p), cpumask_bits(src2p),
						  nr_cpumask_bits);
}

static inline bool cpumask_empty(const struct cpumask *srcp)
{
	return bitmap_empty(cpumask_bits(srcp), nr_cpumask_bits);
}

static inline bool cpumask_full(const struct cpumask *srcp)
{
	return bitmap_full(cpumask_bits(srcp), nr_cpumask_bits);
}

static inline unsigned int cpumask_weight(const struct cpumask *srcp)
{
	return bitmap_weight(cpumask_bits(srcp), nr_cpumask_bits);
}

static inline void cpumask_shift_right(struct cpumask *dstp,
				       const struct cpumask *srcp, int n)
{
	bitmap_shift_right(cpumask_bits(dstp), cpumask_bits(srcp), n,
					       nr_cpumask_bits);
}

static inline void cpumask_shift_left(struct cpumask *dstp,
				      const struct cpumask *srcp, int n)
{
	bitmap_shift_left(cpumask_bits(dstp), cpumask_bits(srcp), n,
					      nr_cpumask_bits);
}

static inline void cpumask_copy(struct cpumask *dstp,
				const struct cpumask *srcp)
{
	bitmap_copy(cpumask_bits(dstp), cpumask_bits(srcp), nr_cpumask_bits);
}

#define cpumask_any(srcp) cpumask_first(srcp)

#define cpumask_first_and(src1p, src2p) cpumask_next_and(-1, (src1p), (src2p))

#define cpumask_any_and(mask1, mask2) cpumask_first_and((mask1), (mask2))

#define cpumask_of(cpu) (get_cpu_mask(cpu))

int vmmr0_smp_call_function_mask(cpumask_t mask,
			       void (*func) (void *info), void *info, int wait);
#define smp_call_function_mask vmmr0_smp_call_function_mask

static inline int smp_call_function_many(cpumask_var_t cpus,
					 void (*func)(void *data), void *data,
					 int sync)
{
	return smp_call_function_mask(*cpus, func, data, sync);
}

#define for_each_possible_cpu(cpu) for_each_cpu((cpu), cpu_possible_mask)

static inline bool alloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
{
	*mask = kmalloc(cpumask_size(), flags);

	if (*mask)
	{
		unsigned char *ptr = (unsigned char *)cpumask_bits(*mask);
		unsigned int tail;
		tail = BITS_TO_LONGS(NR_CPUS - nr_cpumask_bits) * sizeof(long);
		memset(ptr + cpumask_size() - tail, 0, tail);
	}

	return *mask != NULL;
}

static inline bool zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
{
	bool ret;

	ret = alloc_cpumask_var(mask, flags);

	if (ret)
	{
		cpumask_clear(*mask);
	}
	return ret;
}

static inline void free_cpumask_var(cpumask_var_t mask)
{
	kfree(mask);
}

/*
typedef cpumask_t cpumask_var_t[1];
#define cpumask_any(m) first_cpu(*(m))
static inline bool alloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
{
	return 1;
}

static inline void free_cpumask_var(cpumask_var_t mask)
{
}

static inline void cpumask_set_cpu(int cpu, cpumask_var_t mask)
{
}

static inline int cpumask_empty(cpumask_var_t mask)
{
	return 0;
}

static inline int cpumask_test_cpu(int cpu, cpumask_var_t mask)
{
	return 0;
}

static inline void cpumask_clear_cpu(int cpu, cpumask_var_t mask)
{
}*/

#endif /* CPU_MASK_H_ */
