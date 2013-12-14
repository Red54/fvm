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
#ifndef __LINUX_KVM_PARA_H
#define __LINUX_KVM_PARA_H

/*
 * This header file provides a method for making a hypercall to the host
 * Architectures should define:
 * - vmmr0_hypercall0, vmmr0_hypercall1...
 * - vmmr0_arch_para_features
 * - vmmr0_para_available
 */

/* Return values for hypercalls */
#define KVM_ENOSYS		1000
#define KVM_EFAULT		EFAULT
#define KVM_E2BIG		E2BIG
#define KVM_EPERM		EPERM

#define KVM_HC_VAPIC_POLL_IRQ		1
#define KVM_HC_MMU_OP			2
#define KVM_HC_FEATURES			3
#define KVM_HC_PPC_MAP_MAGIC_PAGE	4

/*
 * hypercalls use architecture specific
 */
#include <asm/vmmr0_para.h>

#ifdef __KERNEL__

static inline int vmmr0_para_has_feature(unsigned int feature)
{
	if (vmmr0_arch_para_features() & (VMMR0_LPUL(1) << feature))
		return 1;
	return 0;
}
#endif /* __KERNEL__ */
#endif /* __LINUX_KVM_PARA_H */
