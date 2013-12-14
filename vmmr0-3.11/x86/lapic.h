#ifndef __KVM_X86_LAPIC_H
#define __KVM_X86_LAPIC_H

#include "os_interface.h"

#include "iodev.h"
#include "vmmr0_timer.h"

#include <linux/vmmr0_host.h>

#ifdef CONFIG_HAVE_KVM_IRQCHIP
struct vmmr0_lapic
{
	unsigned long base_address;
	struct vmmr0_io_device dev;
	struct vmmr0_timer lapic_timer;
	u32 divide_count;
	struct vmmr0_vcpu *vcpu;
	bool irr_pending;
	void *regs;
	gpa_t vapic_addr;
	struct page *vapic_page;
};
int vmmr0_create_lapic(struct vmmr0_vcpu *vcpu);
void vmmr0_free_lapic(struct vmmr0_vcpu *vcpu);

int vmmr0_apic_has_interrupt(struct vmmr0_vcpu *vcpu);
int vmmr0_apic_accept_pic_intr(struct vmmr0_vcpu *vcpu);
int vmmr0_get_apic_interrupt(struct vmmr0_vcpu *vcpu);
void vmmr0_lapic_reset(struct vmmr0_vcpu *vcpu);
u64 vmmr0_lapic_get_cr8(struct vmmr0_vcpu *vcpu);
void vmmr0_lapic_set_tpr(struct vmmr0_vcpu *vcpu, unsigned long cr8);
void vmmr0_lapic_set_eoi(struct vmmr0_vcpu *vcpu);
void vmmr0_lapic_set_base(struct vmmr0_vcpu *vcpu, u64 value);
u64 vmmr0_lapic_get_base(struct vmmr0_vcpu *vcpu);
void vmmr0_apic_set_version(struct vmmr0_vcpu *vcpu);

int vmmr0_apic_match_physical_addr(struct vmmr0_lapic *apic, u16 dest);
int vmmr0_apic_match_logical_addr(struct vmmr0_lapic *apic, u8 mda);
int vmmr0_apic_set_irq(struct vmmr0_vcpu *vcpu, struct vmmr0_lapic_irq *irq);
int vmmr0_apic_local_deliver(struct vmmr0_lapic *apic, int lvt_type);

u64 vmmr0_get_apic_base(struct vmmr0_vcpu *vcpu);
void vmmr0_set_apic_base(struct vmmr0_vcpu *vcpu, u64 data);
void vmmr0_apic_post_state_restore(struct vmmr0_vcpu *vcpu);
int vmmr0_lapic_enabled(struct vmmr0_vcpu *vcpu);
bool vmmr0_apic_present(struct vmmr0_vcpu *vcpu);
int vmmr0_lapic_find_highest_irr(struct vmmr0_vcpu *vcpu);

u64 vmmr0_get_lapic_tscdeadline_msr(struct vmmr0_vcpu *vcpu);
void vmmr0_set_lapic_tscdeadline_msr(struct vmmr0_vcpu *vcpu, u64 data);

void vmmr0_lapic_set_vapic_addr(struct vmmr0_vcpu *vcpu, gpa_t vapic_addr);
void vmmr0_lapic_sync_from_vapic(struct vmmr0_vcpu *vcpu);
void vmmr0_lapic_sync_to_vapic(struct vmmr0_vcpu *vcpu);

int vmmr0_x2apic_msr_write(struct vmmr0_vcpu *vcpu, u32 msr, u64 data);
int vmmr0_x2apic_msr_read(struct vmmr0_vcpu *vcpu, u32 msr, u64 *data);

int vmmr0_hv_vapic_msr_write(struct vmmr0_vcpu *vcpu, u32 msr, u64 data);
int vmmr0_hv_vapic_msr_read(struct vmmr0_vcpu *vcpu, u32 msr, u64 *data);

static inline bool vmmr0_hv_vapic_assist_page_enabled(struct vmmr0_vcpu *vcpu)
{
	return vcpu->arch.hv_vapic & HV_X64_MSR_APIC_ASSIST_PAGE_ENABLE;
}
#else
int vmmr0_create_lapic(struct vmmr0_vcpu *vcpu);
void vmmr0_free_lapic(struct vmmr0_vcpu *vcpu);
void vmmr0_lapic_reset(struct vmmr0_vcpu *vcpu);
void vmmr0_lapic_sync_from_vapic(struct vmmr0_vcpu *vcpu);
void vmmr0_lapic_sync_to_vapic(struct vmmr0_vcpu *vcpu);
int vmmr0_lapic_enabled(struct vmmr0_vcpu *vcpu);
int vmmr0_lapic_find_highest_irr(struct vmmr0_vcpu *vcpu);
u64 vmmr0_get_lapic_tscdeadline_msr(struct vmmr0_vcpu *vcpu);
int vmmr0_x2apic_msr_read(struct vmmr0_vcpu *vcpu, u32 msr, u64 *data);
int vmmr0_x2apic_msr_write(struct vmmr0_vcpu *vcpu, u32 msr, u64 data);
int vmmr0_hv_vapic_msr_read(struct vmmr0_vcpu *vcpu, u32 msr, u64 *data);
int vmmr0_hv_vapic_msr_write(struct vmmr0_vcpu *vcpu, u32 msr, u64 data);
void vmmr0_set_lapic_tscdeadline_msr(struct vmmr0_vcpu *vcpu, u64 data);
u64 vmmr0_lapic_get_cr8(struct vmmr0_vcpu *vcpu);
void vmmr0_lapic_set_tpr(struct vmmr0_vcpu *vcpu, unsigned long cr8);
void vmmr0_lapic_set_base(struct vmmr0_vcpu *vcpu, u64 value);
void vmmr0_lapic_set_eoi(struct vmmr0_vcpu *vcpu);
void vmmr0_apic_set_version(struct vmmr0_vcpu *vcpu);
u64 vmmr0_get_apic_base(struct vmmr0_vcpu *vcpu);
void vmmr0_set_apic_base(struct vmmr0_vcpu *vcpu, u64 data);
#endif //CONFIG_HAVE_KVM_IRQCHIP
#endif
