
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)

unsigned int vmmr0_xstate_size;

void vmmr0_xstate_size_init(void)
{
	unsigned int eax, ebx, ecx, edx;

	/*  vmmr0 only uses xstate_size if xsave is supported */
	if (cpu_has_xsave) {
		cpuid_count(0xd, 0, &eax, &ebx, &ecx, &edx);
		vmmr0_xstate_size = ebx;
		BUG_ON(vmmr0_xstate_size > sizeof(union vmmr0_thread_xstate));
	}
}

#endif /* < 2.6.36 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)

const int vmmr0_amd_erratum_383[] =
	AMD_OSVW_ERRATUM(3, AMD_MODEL_RANGE(0x10, 0, 0, 0xff, 0xf));


#endif /* < 2.6.36 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38) && defined(CONFIG_KVM_GUEST)
void vmmr0_async_pf_task_wait(u32 token)
{
	BUG();
}

void vmmr0_async_pf_task_wake(u32 token)
{
	BUG();
}

u32 vmmr0_read_and_reset_pf_reason(void)
{
	return 0;
}

#endif /* < 2.6.38 && CONFIG_KVM_GUEST */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)

#ifndef SVM_CPUID_FUNC
#define SVM_CPUID_FUNC 0x8000000a
#endif

#define SVM_FEATURE_NPT            (1 <<  0)
#define SVM_FEATURE_LBRV           (1 <<  1)
#define SVM_FEATURE_NRIP           (1 <<  3)
#define SVM_FEATURE_FLUSH_ASID     (1 <<  6)
#define SVM_FEATURE_DECODE_ASSIST  (1 <<  7)
#define SVM_FEATURE_PAUSE_FILTER   (1 << 10)

bool vmmr0_boot_cpu_has(unsigned int bit)
{
	static u32 svm_features;
	static bool initialized;

	if (!initialized) {
		svm_features = cpuid_edx(SVM_CPUID_FUNC);
		initialized = true;
	}
	switch (bit) {
	case X86_FEATURE_NPT:
		return svm_features & SVM_FEATURE_NPT;
	case X86_FEATURE_LBRV:
		return svm_features & SVM_FEATURE_LBRV;
	case X86_FEATURE_NRIPS:
		return svm_features & SVM_FEATURE_NRIP;
	case X86_FEATURE_FLUSHBYASID:
		return svm_features & SVM_FEATURE_FLUSH_ASID;
	case X86_FEATURE_DECODEASSISTS:
		return svm_features & SVM_FEATURE_DECODE_ASSIST;
	case X86_FEATURE_PAUSEFILTER:
		return svm_features & SVM_FEATURE_PAUSE_FILTER;
	default:
		return boot_cpu_has(bit);
	}
}
#endif /* < 2.6.37 */
