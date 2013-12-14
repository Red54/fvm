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

/*
 * irq.c
 *
 * this code is based on kvm-kmod.
 *
 * author : 
 *   范文一 （Wincy Van） <fanwenyi0529@live.com> <QQ:362478911>
 *   Yaozu (Eddie) Dong <Eddie.dong@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * From: kvm-kmod-3.4
 */
 
#include "os_interface.h"
#include <linux/vmmr0_host.h>


#ifdef CONFIG_HAVE_KVM_IRQCHIP

#include "irq.h"
#include "i8254.h"
#include "x86.h"

/*
 * check if there are pending timer events
 * to be processed.
 */
int vmmr0_cpu_has_pending_timer(struct vmmr0_vcpu *vcpu)
{
	return apic_has_pending_timer(vcpu);
}

/*
 * check if there is pending interrupt without
 * intack.
 */
int vmmr0_cpu_has_interrupt(struct vmmr0_vcpu *v)
{
	struct vmmr0_pic *s;

	if (!irqchip_in_kernel(v->pvm))
		return v->arch.interrupt.pending;

	if (vmmr0_apic_has_interrupt(v) == -1) {	/* LAPIC */
		if (vmmr0_apic_accept_pic_intr(v)) {
			s = pic_irqchip(v->pvm);	/* PIC */
			return s->output;
		} else
			return 0;
	}
	return 1;
}

/*
 * Read pending interrupt vector and intack.
 */
int vmmr0_cpu_get_interrupt(struct vmmr0_vcpu *v)
{
	struct vmmr0_pic *s;
	int vector;

	if (!irqchip_in_kernel(v->pvm))
		return v->arch.interrupt.nr;

	vector = vmmr0_get_apic_interrupt(v);	/* APIC */
	if (vector == -1) {
		if (vmmr0_apic_accept_pic_intr(v)) {
			s = pic_irqchip(v->pvm);
			s->output = 0;		/* PIC */
			vector = vmmr0_pic_read_irq(v->pvm);
		}
	}
	return vector;
}

void vmmr0_inject_pending_timer_irqs(struct vmmr0_vcpu *vcpu)
{
	vmmr0_inject_apic_timer_irqs(vcpu);
	/* TODO: PIT, RTC etc. */
}

void __vmmr0_migrate_timers(struct vmmr0_vcpu *vcpu)
{
	__vmmr0_migrate_apic_timer(vcpu);
	__vmmr0_migrate_pit_timer(vcpu);
}
#else
void vmmr0_inject_pending_timer_irqs(struct vmmr0_vcpu *vcpu){ }
void __vmmr0_migrate_timers(struct vmmr0_vcpu *vcpu){ }
/*
 * check if there are pending timer events
 * to be processed.
 */
int vmmr0_cpu_has_pending_timer(struct vmmr0_vcpu *vcpu)
{
	return 0;
}

/*
 * Read pending interrupt vector and intack.
 */
int vmmr0_cpu_get_interrupt(struct vmmr0_vcpu *v)
{
	return v->arch.interrupt.nr;
}
/*
 * check if there is pending interrupt without
 * intack.
 */
int vmmr0_cpu_has_interrupt(struct vmmr0_vcpu *v)
{
	return v->arch.interrupt.pending;
}
#endif //CONFIG_HAVE_KVM_IRQCHIP
