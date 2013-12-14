#ifndef ARCH_X86_KVM_X86_H
#define ARCH_X86_KVM_X86_H

#include <linux/vmmr0_host.h>
#include "vmmr0_cache_regs.h"

static inline void vmmr0_clear_exception_queue(struct vmmr0_vcpu *vcpu)
{
	vcpu->arch.exception.pending = false;
}

static inline void vmmr0_queue_interrupt(struct vmmr0_vcpu *vcpu, u8 vector,
	bool soft)
{
	vcpu->arch.interrupt.pending = true;
	vcpu->arch.interrupt.soft = soft;
	vcpu->arch.interrupt.nr = vector;
}

static inline void vmmr0_clear_interrupt_queue(struct vmmr0_vcpu *vcpu)
{
	vcpu->arch.interrupt.pending = false;
}

static inline bool vmmr0_event_needs_reinjection(struct vmmr0_vcpu *vcpu)
{
	return vcpu->arch.exception.pending || vcpu->arch.interrupt.pending ||
		vcpu->arch.nmi_injected;
}

static inline bool vmmr0_exception_is_soft(unsigned int nr)
{
	return (nr == BP_VECTOR) || (nr == OF_VECTOR);
}

static inline bool is_protmode(struct vmmr0_vcpu *vcpu)
{
	return vmmr0_read_cr0_bits(vcpu, X86_CR0_PE);
}

static inline int is_long_mode(struct vmmr0_vcpu *vcpu)
{
#ifdef CONFIG_X86_64
	return vcpu->arch.efer & EFER_LMA;
#else
	return 0;
#endif
}

static inline bool mmu_is_nested(struct vmmr0_vcpu *vcpu)
{
	return vcpu->arch.walk_mmu == &vcpu->arch.nested_mmu;
}

static inline int is_pae(struct vmmr0_vcpu *vcpu)
{
	return vmmr0_read_cr4_bits(vcpu, X86_CR4_PAE);
}

static inline int is_pse(struct vmmr0_vcpu *vcpu)
{
	return vmmr0_read_cr4_bits(vcpu, X86_CR4_PSE);
}

static inline int is_paging(struct vmmr0_vcpu *vcpu)
{
	return vmmr0_read_cr0_bits(vcpu, X86_CR0_PG);
}

static inline u32 bit(int bitno)
{
	return 1 << (bitno & 31);
}

static inline void vcpu_cache_mmio_info(struct vmmr0_vcpu *vcpu,
					gva_t gva, gfn_t gfn, unsigned access)
{
	vcpu->arch.mmio_gva = gva & PAGE_MASK;
	vcpu->arch.access = access;
	vcpu->arch.mmio_gfn = gfn;
}

/*
 * Clear the mmio cache info for the given gva,
 * specially, if gva is ~0ul, we clear all mmio cache info.
 */
static inline void vcpu_clear_mmio_info(struct vmmr0_vcpu *vcpu, gva_t gva)
{
	if (gva != (~VMMR0_LPUL(0)) && vcpu->arch.mmio_gva != (gva & PAGE_MASK))
		return;

	vcpu->arch.mmio_gva = 0;
}

static inline bool vcpu_match_mmio_gva(struct vmmr0_vcpu *vcpu, unsigned long gva)
{
	if (vcpu->arch.mmio_gva && vcpu->arch.mmio_gva == (gva & PAGE_MASK))
		return true;

	return false;
}

static inline bool vcpu_match_mmio_gpa(struct vmmr0_vcpu *vcpu, gpa_t gpa)
{
	if (vcpu->arch.mmio_gfn && vcpu->arch.mmio_gfn == gpa >> PAGE_SHIFT)
		return true;

	return false;
}

u64 get_kernel_ns(void);
void vmmr0_before_handle_nmi(struct vmmr0_vcpu *vcpu);
void vmmr0_after_handle_nmi(struct vmmr0_vcpu *vcpu);
int vmmr0_inject_realmode_interrupt(struct vmmr0_vcpu *vcpu, int irq, int inc_eip);

void vmmr0_write_tsc(struct vmmr0_vcpu *vcpu, u64 data);

int vmmr0_read_guest_virt(struct x86_emulate_ctxt *ctxt,
	gva_t addr, void *val, unsigned int bytes,
	struct x86_exception *exception);

int vmmr0_write_guest_virt_system(struct x86_emulate_ctxt *ctxt,
	gva_t addr, void *val, unsigned int bytes,
	struct x86_exception *exception);

extern u64 host_xcr0;

#endif
