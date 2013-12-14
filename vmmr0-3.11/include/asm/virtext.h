#ifndef KVM_UNIFDEF_H
#define KVM_UNIFDEF_H

#ifdef __i386__
#ifndef CONFIG_X86_32
#define CONFIG_X86_32 1
#endif
#endif

#ifdef __x86_64__
#ifndef CONFIG_X86_64
#define CONFIG_X86_64 1
#endif
#endif

#if defined(__i386__) || defined (__x86_64__)
#ifndef CONFIG_X86
#define CONFIG_X86 1
#endif
#endif


#endif

#ifndef _ASM_X86_VIRTEX_H
#define _ASM_X86_VIRTEX_H


#include "os_interface.h"

#include <asm/vmx.h>
#include <asm/svm.h>

/*
 * VMX functions:
 */

static inline int cpu_has_vmx(void)
{
	unsigned long ecx = cpuid_ecx(1);
	return test_bit(5, &ecx); /* CPUID.1:ECX.VMX[bit 5] -> VT */
}


/** Disable VMX on the current CPU
 *
 * vmxoff causes a undefined-opcode exception if vmxon was not run
 * on the CPU previously. Only call this function if you know VMX
 * is enabled.
 */
static inline void cpu_vmxoff(void)
{
	asm volatile (ASM_VMX_VMXOFF : : : "cc");
	write_cr4(read_cr4() & ~X86_CR4_VMXE);
}

static inline int cpu_vmx_enabled(void)
{
	return read_cr4() & X86_CR4_VMXE;
}

/** Disable VMX if it is enabled on the current CPU
 *
 * You shouldn't call this if cpu_has_vmx() returns 0.
 */
static inline void __cpu_emergency_vmxoff(void)
{
	if (cpu_vmx_enabled())
	{
		cpu_vmxoff();
	}
}

/** Disable VMX if it is supported and enabled on the current CPU
 */
static inline void cpu_emergency_vmxoff(void)
{
	if (cpu_has_vmx())
	{
		__cpu_emergency_vmxoff();
	}
}



static inline void get_cpu_vendor(char *in)
{
	unsigned int foo[4];
	foo[0] = 0;
	foo[2] = 0;
	if(!in)
	{
		return;
	}
	native_cpuid(&foo[0], &foo[1], &foo[2], &foo[3]);
	*((unsigned int *)in) = foo[1];
	*((unsigned int *)in + 1) = foo[3];
	*((unsigned int *)in + 2) = foo[2];
	in[12] = '\0';
}

static inline bool is_amd_cpu(void)
{
	char vendor[128];
	get_cpu_vendor(vendor);
	if(!strcmp("AuthenticAMD", vendor))
	{
		return true;
	}
	return false;
}
/*
 * SVM functions:
 */

/** Check if the CPU has SVM support
 *
 */
static inline int cpu_has_svm(void)
{
	uint32_t eax, ebx, ecx, edx;

	if (!is_amd_cpu())
	{
		return 0;
	}

	cpuid(0x80000000, &eax, &ebx, &ecx, &edx);
	if (eax < SVM_CPUID_FUNC)
	{

		return 0;
	}

	cpuid(0x80000001, &eax, &ebx, &ecx, &edx);
	if (!(ecx & (1 << SVM_CPUID_FEATURE_SHIFT)))
	{

		return 0;
	}
	return 1;
}


/** Disable SVM on the current CPU
 *
 * You should call this only if cpu_has_svm() returned true.
 */
static inline void cpu_svm_disable(void)
{
	uint64_t efer;

	wrmsrl(MSR_VM_HSAVE_PA, 0);
	rdmsrl(MSR_EFER, efer);
	wrmsrl(MSR_EFER, efer & ~EFER_SVME);
}

/** Makes sure SVM is disabled, if it is supported on the CPU
 */
static inline void cpu_emergency_svm_disable(void)
{
	if (cpu_has_svm())
	{
		cpu_svm_disable();
	}
}

#endif /* _ASM_X86_VIRTEX_H */
