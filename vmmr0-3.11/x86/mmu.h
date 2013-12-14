#ifndef __KVM_X86_MMU_H
#define __KVM_X86_MMU_H

#include "os_interface.h"

#include <linux/vmmr0_host.h>
#include "vmmr0_cache_regs.h"

#define PT64_PT_BITS 9
#define PT64_ENT_PER_PAGE (1 << PT64_PT_BITS)
#define PT32_PT_BITS 10
#define PT32_ENT_PER_PAGE (1 << PT32_PT_BITS)

#define PT_WRITABLE_SHIFT 1

#define PT_PRESENT_MASK (1ULL << 0)
#define PT_WRITABLE_MASK (1ULL << PT_WRITABLE_SHIFT)
#define PT_USER_MASK (1ULL << 2)
#define PT_PWT_MASK (1ULL << 3)
#define PT_PCD_MASK (1ULL << 4)
#define PT_ACCESSED_SHIFT 5
#define PT_ACCESSED_MASK (1ULL << PT_ACCESSED_SHIFT)
#define PT_DIRTY_MASK (1ULL << 6)
#define PT_PAGE_SIZE_MASK (1ULL << 7)
#define PT_PAT_MASK (1ULL << 7)
#define PT_GLOBAL_MASK (1ULL << 8)
#define PT64_NX_SHIFT 63
#define PT64_NX_MASK (1ULL << PT64_NX_SHIFT)

#define PT_PAT_SHIFT 7
#define PT_DIR_PAT_SHIFT 12
#define PT_DIR_PAT_MASK (1ULL << PT_DIR_PAT_SHIFT)

#define PT32_DIR_PSE36_SIZE 4
#define PT32_DIR_PSE36_SHIFT 13
#define PT32_DIR_PSE36_MASK \
	(((1ULL << PT32_DIR_PSE36_SIZE) - 1) << PT32_DIR_PSE36_SHIFT)

#define PT64_ROOT_LEVEL 4
#define PT32_ROOT_LEVEL 2
#define PT32E_ROOT_LEVEL 3

#define PT_PDPE_LEVEL 3
#define PT_DIRECTORY_LEVEL 2
#define PT_PAGE_TABLE_LEVEL 1

#define PFERR_PRESENT_MASK (1U << 0)
#define PFERR_WRITE_MASK (1U << 1)
#define PFERR_USER_MASK (1U << 2)
#define PFERR_RSVD_MASK (1U << 3)
#define PFERR_FETCH_MASK (1U << 4)

int vmmr0_mmu_get_spte_hierarchy(struct vmmr0_vcpu *vcpu, u64 addr,
		u64 sptes[4]);
void vmmr0_mmu_set_mmio_spte_mask(u64 mmio_mask);
int handle_mmio_page_fault_common(struct vmmr0_vcpu *vcpu, u64 addr,
		bool direct);
int vmmr0_init_shadow_mmu(struct vmmr0_vcpu *vcpu, struct vmmr0_mmu *context);

static inline unsigned int vmmr0_mmu_available_pages(struct vm *pvm)
{
	return pvm->arch.n_max_mmu_pages - pvm->arch.n_used_mmu_pages;
}

static inline void vmmr0_mmu_free_some_pages(struct vmmr0_vcpu *vcpu)
{
	if (unlikely(vmmr0_mmu_available_pages(vcpu->pvm) < KVM_MIN_FREE_MMU_PAGES))
	{
		__vmmr0_mmu_free_some_pages(vcpu);
	}
}

static inline int vmmr0_mmu_reload(struct vmmr0_vcpu *vcpu)
{
	if (likely(vcpu->arch.mmu.root_hpa != INVALID_PAGE))
	{
		return 0;
	}

	return vmmr0_mmu_load(vcpu);
}

static inline int is_present_gpte(unsigned long pte)
{
	return pte & PT_PRESENT_MASK;
}

static inline int is_writable_pte(unsigned long pte)
{
	return pte & PT_WRITABLE_MASK;
}

static inline bool is_write_protection(struct vmmr0_vcpu *vcpu)
{
	return vmmr0_read_cr0_bits(vcpu, X86_CR0_WP);
}

static inline bool check_write_user_access(struct vmmr0_vcpu *vcpu,
		bool write_fault, bool user_fault, unsigned long pte)
{
	if (unlikely(
			write_fault && !is_writable_pte(pte)
					&& (user_fault || is_write_protection(vcpu))))
	{
		return false;
	}

	if (unlikely(user_fault && !(pte & PT_USER_MASK)))
	{
		return false;
	}

	return true;
}
#endif
