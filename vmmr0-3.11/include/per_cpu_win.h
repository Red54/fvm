/*
 * per_cpu_win.h
 *
 *      Author: fw1
 */

#ifndef PER_CPU_WIN_H_
#define PER_CPU_WIN_H_

#include <ddk/ntddk.h>

extern cpumask_t cpu_online_map;
extern int nr_cpu_ids;

unsigned int get_processor_num(void);
unsigned int get_processor_num_affinity(PKAFFINITY aff);

#ifdef CONFIG_X86_64
#define raw_smp_processor_id() KeGetCurrentProcessorNumberEx(0)
#else
#define raw_smp_processor_id KeGetCurrentProcessorNumber
#endif

#define smp_processor_id raw_smp_processor_id

#define get_cpu()		({ preempt_disable(); smp_processor_id(); })
#define put_cpu()		preempt_enable()


#define DECLARE_PER_CPU(type, name)					\
		extern type name[NR_CPUS]

#define DEFINE_PER_CPU(type, name)					\
		type name[NR_CPUS]

#define per_cpu(var, cpu) (var[cpu])
#define __get_cpu_var(var) (var[smp_processor_id()])


static inline void init_per_cpu_win(void)
{
	unsigned long cpus;

#ifdef CONFIG_X86_64
	KAFFINITY affinity;
	unsigned int bit;
	cpus = get_processor_num_affinity(&affinity);
	nr_cpu_ids = cpus;
	bitmap_zero((unsigned long*)&cpu_online_map, NR_CPUS);
//	cpu_online_map = affinity;
	for_each_set_bit(bit, &affinity, sizeof(affinity) * 8)
	{
		set_bit(bit, (unsigned long*)&cpu_online_map);
	}

#else
	unsigned long i;
	//NR_CPUS = get_processor_num();
	cpus = get_processor_num();
	nr_cpu_ids = cpus;
	bitmap_zero((unsigned long*)&cpu_online_map, NR_CPUS);

	for(i = 0; i < cpus; ++i)
	{
		set_bit(cpus, (unsigned long*)&cpu_online_map);
	}
#endif
}

#define cpu_online(x) 1

#endif /* PER_CPU_WIN_H_ */
