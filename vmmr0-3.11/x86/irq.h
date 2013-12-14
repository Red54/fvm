/*
 * irq.h: in kernel interrupt controller related definitions
 * Copyright (c) 2007, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 * Authors:
 *   Yaozu (Eddie) Dong <Eddie.dong@intel.com>
 *
 */

#ifndef __IRQ_H
#define __IRQ_H

#include "os_interface.h"

#include "iodev.h"
#include "ioapic.h"
#include "lapic.h"

#ifdef CONFIG_HAVE_KVM_IRQCHIP

#define PIC_NUM_PINS 16
#define SELECT_PIC(irq) \
	((irq) < 8 ? KVM_IRQCHIP_PIC_MASTER : KVM_IRQCHIP_PIC_SLAVE)

struct vm;
struct vmmr0_vcpu;

struct vmmr0_kpic_state
{
	u8 last_irr; /* edge detection */
	u8 irr; /* interrupt request register */
	u8 imr; /* interrupt mask register */
	u8 isr; /* interrupt service register */
	u8 priority_add; /* highest irq priority */
	u8 irq_base;
	u8 read_reg_select;
	u8 poll;
	u8 special_mask;
	u8 init_state;
	u8 auto_eoi;
	u8 rotate_on_auto_eoi;
	u8 special_fully_nested_mode;
	u8 init4; /* true if 4 byte init */
	u8 elcr; /* PIIX edge/trigger selection */
	u8 elcr_mask;
	u8 isr_ack; /* interrupt ack detection */
	struct vmmr0_pic *pics_state;
};

struct vmmr0_pic
{
	spinlock_t lock;
	bool wakeup_needed;
	unsigned pending_acks;
	struct vm *pvm;
	struct vmmr0_kpic_state pics[2]; /* 0 is master pic, 1 is slave pic */
	int output; /* intr from master PIC */
	struct vmmr0_io_device dev_master;
	struct vmmr0_io_device dev_slave;
	struct vmmr0_io_device dev_eclr;
	void (*ack_notifier)(void *opaque, int irq);
	unsigned long irq_states[16];
};

struct vmmr0_pic *vmmr0_create_pic(struct vm *pvm);
void vmmr0_destroy_pic(struct vm *pvm);
int vmmr0_pic_read_irq(struct vm *pvm);
void vmmr0_pic_update_irq(struct vmmr0_pic *s);

static inline struct vmmr0_pic *pic_irqchip(struct vm *pvm)
{
	return pvm->arch.vpic;
}

static inline int irqchip_in_kernel(struct vm *pvm)
{
	int ret;

	ret = (pic_irqchip(pvm) != NULL);
	smp_rmb();
	return ret;
}

void vmmr0_pic_reset(struct vmmr0_kpic_state *s);

void vmmr0_inject_pending_timer_irqs(struct vmmr0_vcpu *vcpu);
void vmmr0_inject_apic_timer_irqs(struct vmmr0_vcpu *vcpu);
void vmmr0_apic_nmi_wd_deliver(struct vmmr0_vcpu *vcpu);
void __vmmr0_migrate_apic_timer(struct vmmr0_vcpu *vcpu);
void __vmmr0_migrate_pit_timer(struct vmmr0_vcpu *vcpu);
void __vmmr0_migrate_timers(struct vmmr0_vcpu *vcpu);

int apic_has_pending_timer(struct vmmr0_vcpu *vcpu);

#else
void vmmr0_inject_pending_timer_irqs(struct vmmr0_vcpu *vcpu);
void __vmmr0_migrate_timers(struct vmmr0_vcpu *vcpu);
static inline int irqchip_in_kernel(struct vm *pvm)
{
	return 0;
}
#endif //CONFIG_HAVE_KVM_IRQCHIP
#endif
