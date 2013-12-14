#ifndef GET_CPU_X_H_
#define GET_CPU_X_H_


#ifdef HOST_LINUX
#define native_cpuid __cpuid
#endif

static inline unsigned int get_cpu_feature(unsigned int index, unsigned int exx)
{
	unsigned int foo[4];
	foo[0] = index;
	foo[2] = 0;
	native_cpuid(&foo[0], &foo[1], &foo[2], &foo[3]);
	return foo[exx];
}

static inline unsigned int get_cpu_family(void)
{
	return boot_cpu_data.x86;
}

static inline bool cpu_support_osvw(void)
{
#ifdef HOST_LINUX
	return cpu_has(&boot_cpu_data, X86_FEATURE_OSVW);
#else
	unsigned int foo = get_cpu_feature(0x80000001, 2);
	return foo & BIT(9);
#endif
}

extern u64 vmmr0_tsc_khz;

static inline u64 get_tsc_khz(void)
{
#ifdef HOST_LINUX
	return tsc_khz;
#else
	u64 tick1,tick2;
	u64 ret = 0;
	KIRQL irql;
	KeRaiseIrql(DISPATCH_LEVEL, &irql);
	rdtscll(tick1);
	mdelay(50);
	rdtscll(tick2);
	KeLowerIrql(irql);
	ret = tick2 - tick1;
	do_div(ret, 50);
	return ret;
#endif
}

#endif /* GET_CPU_X_H_ */
