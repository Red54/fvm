#ifndef ARCH_X86_KVM_CPUID_H
#define ARCH_X86_KVM_CPUID_H

#include "x86.h"

void vmmr0_update_cpuid(struct vmmr0_vcpu *vcpu);
struct vmmr0_cpuid_entry2 *vmmr0_find_cpuid_entry(struct vmmr0_vcpu *vcpu,
					      u32 function, u32 index);
int vmmr0_dev_ioctl_get_supported_cpuid(struct vmmr0_cpuid2 *cpuid,
				      struct vmmr0_cpuid_entry2 __user *entries);
int vmmr0_vcpu_ioctl_set_cpuid(struct vmmr0_vcpu *vcpu,
			     struct vmmr0_cpuid *cpuid,
			     struct vmmr0_cpuid_entry __user *entries);
int vmmr0_vcpu_ioctl_set_cpuid2(struct vmmr0_vcpu *vcpu,
			      struct vmmr0_cpuid2 *cpuid,
			      struct vmmr0_cpuid_entry2 __user *entries);
int vmmr0_vcpu_ioctl_get_cpuid2(struct vmmr0_vcpu *vcpu,
			      struct vmmr0_cpuid2 *cpuid,
			      struct vmmr0_cpuid_entry2 __user *entries);


static inline bool guest_cpuid_has_xsave(struct vmmr0_vcpu *vcpu)
{
	struct vmmr0_cpuid_entry2 *best;

	best = vmmr0_find_cpuid_entry(vcpu, 1, 0);
	return best && (best->ecx & bit(X86_FEATURE_XSAVE));
}

static inline bool guest_cpuid_has_smep(struct vmmr0_vcpu *vcpu)
{
	struct vmmr0_cpuid_entry2 *best;

	best = vmmr0_find_cpuid_entry(vcpu, 7, 0);
	return best && (best->ebx & bit(X86_FEATURE_SMEP));
}

static inline bool guest_cpuid_has_fsgsbase(struct vmmr0_vcpu *vcpu)
{
	struct vmmr0_cpuid_entry2 *best;

	best = vmmr0_find_cpuid_entry(vcpu, 7, 0);
	return best && (best->ebx & bit(X86_FEATURE_FSGSBASE));
}

static inline bool guest_cpuid_has_osvw(struct vmmr0_vcpu *vcpu)
{
	struct vmmr0_cpuid_entry2 *best;

	best = vmmr0_find_cpuid_entry(vcpu, 0x80000001, 0);
	return best && (best->ecx & bit(X86_FEATURE_OSVW));
}

#endif
