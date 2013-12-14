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
 * irq_comm.c
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

#include "ioapic.h"


static inline int vmmr0_irq_line_state(unsigned long *irq_state,
				     int irq_source_id, int level)
{
	/* Logical OR for level trig interrupt */
	if (level)
		set_bit(irq_source_id, irq_state);
	else
		clear_bit(irq_source_id, irq_state);

	return !!(*irq_state);
}

static int vmmr0_set_pic_irq(struct vmmr0_kernel_irq_routing_entry *e,
			   struct vm *pvm, int irq_source_id, int level)
{

	struct vmmr0_pic *pic = pic_irqchip(pvm);
	level = vmmr0_irq_line_state(&pic->irq_states[e->irqchip.pin],
				   irq_source_id, level);
	return vmmr0_pic_set_irq(pic, e->irqchip.pin, level);
}

static int vmmr0_set_ioapic_irq(struct vmmr0_kernel_irq_routing_entry *e,
			      struct vm *pvm, int irq_source_id, int level)
{
	struct vmmr0_ioapic *ioapic = pvm->arch.vioapic;
	level = vmmr0_irq_line_state(&ioapic->irq_states[e->irqchip.pin],
				   irq_source_id, level);

	return vmmr0_ioapic_set_irq(ioapic, e->irqchip.pin, level);
}

inline static bool vmmr0_is_dm_lowest_prio(struct vmmr0_lapic_irq *irq)
{
	return irq->delivery_mode == APIC_DM_LOWEST;
}

int vmmr0_irq_delivery_to_apic(struct vm *pvm, struct vmmr0_lapic *src,
		struct vmmr0_lapic_irq *irq)
{
	int i, r = -1;
	struct vmmr0_vcpu *vcpu, *lowest = NULL;

	if (irq->dest_mode == 0 && irq->dest_id == 0xff &&
			vmmr0_is_dm_lowest_prio(irq))
		printk(KERN_INFO "vmmr0: apic: phys broadcast and lowest prio\n");

	vmmr0_for_each_vcpu(i, vcpu, pvm) {
		if (!vmmr0_apic_present(vcpu))
			continue;

		if (!vmmr0_apic_match_dest(vcpu, src, irq->shorthand,
					irq->dest_id, irq->dest_mode))
			continue;

		if (!vmmr0_is_dm_lowest_prio(irq)) {
			if (r < 0)
				r = 0;
			r += vmmr0_apic_set_irq(vcpu, irq);
		} else if (vmmr0_lapic_enabled(vcpu)) {
			if (!lowest)
				lowest = vcpu;
			else if (vmmr0_apic_compare_prio(vcpu, lowest) < 0)
				lowest = vcpu;
		}
	}

	if (lowest)
		r = vmmr0_apic_set_irq(lowest, irq);

	return r;
}

int vmmr0_set_msi(struct vmmr0_kernel_irq_routing_entry *e,
		struct vm *pvm, int irq_source_id, int level)
{
	struct vmmr0_lapic_irq irq;

	if (!level)
		return -1;

	irq.dest_id = (e->msi.address_lo &
			MSI_ADDR_DEST_ID_MASK) >> MSI_ADDR_DEST_ID_SHIFT;
	irq.vector = (e->msi.data &
			MSI_DATA_VECTOR_MASK) >> MSI_DATA_VECTOR_SHIFT;
	irq.dest_mode = (1 << MSI_ADDR_DEST_MODE_SHIFT) & e->msi.address_lo;
	irq.trig_mode = (1 << MSI_DATA_TRIGGER_SHIFT) & e->msi.data;
	irq.delivery_mode = e->msi.data & 0x700;
	irq.level = 1;
	irq.shorthand = 0;

	/* TODO Deal with RH bit of MSI message address */
	return vmmr0_irq_delivery_to_apic(pvm, NULL, &irq);
}

/*
 * Return value:
 *  < 0   Interrupt was ignored (masked or not delivered for other reasons)
 *  = 0   Interrupt was coalesced (previous irq is still pending)
 *  > 0   Number of CPUs interrupt was delivered to
 */
int vmmr0_set_irq(struct vm *pvm, int irq_source_id, u32 irq, int level)
{
	struct vmmr0_kernel_irq_routing_entry *e, irq_set[KVM_NR_IRQCHIPS];
	int ret = -1, i = 0;
	struct vmmr0_irq_routing_table *irq_rt;

#ifdef HOST_LINUX_OPTIMIZED
	rcu_read_lock();
	irq_rt = rcu_dereference(pvm->irq_routing);
	if (irq < irq_rt->nr_rt_entries)
		hlist_for_each_entry(e, &irq_rt->map[irq], link)
			irq_set[i++] = *e;
	rcu_read_unlock();
#else
	mutex_lock(&pvm->irq_lock);
	irq_rt = pvm->irq_routing;
	if (irq < irq_rt->nr_rt_entries)
		hlist_for_each_entry(e, &irq_rt->map[irq], link)
			irq_set[i++] = *e;
	mutex_unlock(&pvm->irq_lock);
#endif

	while(i--) {
		int r;
		r = irq_set[i].set(&irq_set[i], pvm, irq_source_id, level);
		if (r < 0)
			continue;

		ret = r + ((ret < 0) ? 0 : ret);
	}

	return ret;
}

void vmmr0_notify_acked_irq(struct vm *pvm, unsigned irqchip, unsigned pin)
{
	struct vmmr0_irq_ack_notifier *kian;
	int gsi;

#ifdef HOST_LINUX_OPTIMIZED
	rcu_read_lock();
	gsi = rcu_dereference(pvm->irq_routing)->chip[irqchip][pin];
	if (gsi != -1)
		hlist_for_each_entry_rcu(kian, &pvm->irq_ack_notifier_list,
					 link)
			if (kian->gsi == gsi)
				kian->irq_acked(kian);
	rcu_read_unlock();
#else
	spin_lock(&pvm->irq_ack_notifier_list_lock);
	gsi = pvm->irq_routing->chip[irqchip][pin];
	if (gsi != -1)
		hlist_for_each_entry(kian, &pvm->irq_ack_notifier_list,
					 link)
			if (kian->gsi == gsi)
				kian->irq_acked(kian);
	spin_unlock(&pvm->irq_ack_notifier_list_lock);
#endif
}

void vmmr0_register_irq_ack_notifier(struct vm *pvm,
				   struct vmmr0_irq_ack_notifier *kian)
{
#ifdef HOST_LINUX_OPTIMIZED
	mutex_lock(&pvm->irq_lock);
	hlist_add_head_rcu(&kian->link, &pvm->irq_ack_notifier_list);
	mutex_unlock(&pvm->irq_lock);
#else
	mutex_lock(&pvm->irq_lock);
	spin_lock(&pvm->irq_ack_notifier_list_lock);
	hlist_add_head(&kian->link, &pvm->irq_ack_notifier_list);
	spin_unlock(&pvm->irq_ack_notifier_list_lock);
	mutex_unlock(&pvm->irq_lock);
#endif
}

void vmmr0_unregister_irq_ack_notifier(struct vm *pvm,
				    struct vmmr0_irq_ack_notifier *kian)
{
#ifdef HOST_LINUX_OPTIMIZED
	mutex_lock(&pvm->irq_lock);
	hlist_del_init_rcu(&kian->link);
	mutex_unlock(&pvm->irq_lock);
	synchronize_rcu();
#else
	mutex_lock(&pvm->irq_lock);
	spin_lock(&pvm->irq_ack_notifier_list_lock);
	hlist_del_init(&kian->link);
	spin_unlock(&pvm->irq_ack_notifier_list_lock);
	mutex_unlock(&pvm->irq_lock);
#endif
}

int vmmr0_request_irq_source_id(struct vm *pvm)
{
	unsigned long *bitmap = &pvm->arch.irq_sources_bitmap;
	int irq_source_id;

	mutex_lock(&pvm->irq_lock);
	irq_source_id = find_first_zero_bit(bitmap, BITS_PER_LONG);

	if (irq_source_id >= BITS_PER_LONG) {
		printk(KERN_WARNING "pvm: exhaust allocatable IRQ sources!\n");
		irq_source_id = -EFAULT;
		goto unlock;
	}

	ASSERT(irq_source_id != KVM_USERSPACE_IRQ_SOURCE_ID);
	set_bit(irq_source_id, bitmap);
unlock:
	mutex_unlock(&pvm->irq_lock);

	return irq_source_id;
}

void vmmr0_free_irq_source_id(struct vm *pvm, int irq_source_id)
{
	int i;

	ASSERT(irq_source_id != KVM_USERSPACE_IRQ_SOURCE_ID);

	mutex_lock(&pvm->irq_lock);
	if (irq_source_id < 0 ||
	    irq_source_id >= BITS_PER_LONG) {
		printk(KERN_ERR "pvm: IRQ source ID out of range!\n");
		goto unlock;
	}
	clear_bit(irq_source_id, &pvm->arch.irq_sources_bitmap);
	if (!irqchip_in_kernel(pvm))
		goto unlock;

	for (i = 0; i < KVM_IOAPIC_NUM_PINS; i++) {
		clear_bit(irq_source_id, &pvm->arch.vioapic->irq_states[i]);
		if (i >= 16)
			continue;

		clear_bit(irq_source_id, &pic_irqchip(pvm)->irq_states[i]);

	}
unlock:
	mutex_unlock(&pvm->irq_lock);
}

void vmmr0_register_irq_mask_notifier(struct vm *pvm, int irq,
				    struct vmmr0_irq_mask_notifier *kimn)
{
#ifdef HOST_LINUX_OPTIMIZED
	mutex_lock(&pvm->irq_lock);
	kimn->irq = irq;
	hlist_add_head_rcu(&kimn->link, &pvm->mask_notifier_list);
	mutex_unlock(&pvm->irq_lock);
#else
	mutex_lock(&pvm->irq_lock);
	spin_lock(&pvm->mask_notifier_list_lock);
	kimn->irq = irq;
	hlist_add_head(&kimn->link, &pvm->mask_notifier_list);
	spin_unlock(&pvm->mask_notifier_list_lock);
	mutex_unlock(&pvm->irq_lock);
#endif
}

void vmmr0_unregister_irq_mask_notifier(struct vm *pvm, int irq,
				      struct vmmr0_irq_mask_notifier *kimn)
{
#ifdef HOST_LINUX_OPTIMIZED
	mutex_lock(&pvm->irq_lock);
	hlist_del_rcu(&kimn->link);
	mutex_unlock(&pvm->irq_lock);
	synchronize_rcu();
#else
	mutex_lock(&pvm->irq_lock);
	spin_lock(&pvm->mask_notifier_list_lock);
	hlist_del(&kimn->link);
	spin_unlock(&pvm->mask_notifier_list_lock);
	mutex_unlock(&pvm->irq_lock);
#endif
}

void vmmr0_fire_mask_notifiers(struct vm *pvm, unsigned irqchip, unsigned pin,
			     bool mask)
{
	struct vmmr0_irq_mask_notifier *kimn;
	int gsi;

#ifdef HOST_LINUX_OPTIMIZED
	rcu_read_lock();
	gsi = rcu_dereference(pvm->irq_routing)->chip[irqchip][pin];
	if (gsi != -1)
		hlist_for_each_entry_rcu(kimn, &pvm->mask_notifier_list, link)
			if (kimn->irq == gsi)
				kimn->func(kimn, mask);
	rcu_read_unlock();
#else
	spin_lock(&pvm->mask_notifier_list_lock);
	gsi = pvm->irq_routing->chip[irqchip][pin];
	if (gsi != -1)
		hlist_for_each_entry(kimn, &pvm->mask_notifier_list, link)
			if (kimn->irq == gsi)
				kimn->func(kimn, mask);
	spin_unlock(&pvm->mask_notifier_list_lock);
#endif
}

void vmmr0_free_irq_routing(struct vm *pvm)
{
	/* Called only during vm destruction. Nobody can use the pointer
	   at this stage */
	kfree(pvm->irq_routing);
}

static int setup_routing_entry(struct vmmr0_irq_routing_table *rt,
			       struct vmmr0_kernel_irq_routing_entry *e,
			       const struct vmmr0_irq_routing_entry *ue)
{
	int r = -EINVAL;
	int delta;
	unsigned max_pin;
	struct vmmr0_kernel_irq_routing_entry *ei;

	/*
	 * Do not allow GSI to be mapped to the same irqchip more than once.
	 * Allow only one to one mapping between GSI and MSI.
	 */
	hlist_for_each_entry(ei, &rt->map[ue->gsi], link)
	{
		if (ei->type == KVM_IRQ_ROUTING_MSI ||
		    ue->u.irqchip.irqchip == ei->irqchip.irqchip)
		{
			return r;
		}
	}

	e->gsi = ue->gsi;
	e->type = ue->type;
	switch (ue->type) {
	case KVM_IRQ_ROUTING_IRQCHIP:
		delta = 0;
		switch (ue->u.irqchip.irqchip) {
		case KVM_IRQCHIP_PIC_MASTER:
			e->set = vmmr0_set_pic_irq;
			max_pin = 16;
			break;
		case KVM_IRQCHIP_PIC_SLAVE:
			e->set = vmmr0_set_pic_irq;
			max_pin = 16;
			delta = 8;
			break;
		case KVM_IRQCHIP_IOAPIC:
			max_pin = KVM_IOAPIC_NUM_PINS;
			e->set = vmmr0_set_ioapic_irq;
			break;
		default:
			goto out;
		}
		e->irqchip.irqchip = ue->u.irqchip.irqchip;
		e->irqchip.pin = ue->u.irqchip.pin + delta;
		if (e->irqchip.pin >= max_pin)
		{
			goto out;
		}
		rt->chip[ue->u.irqchip.irqchip][e->irqchip.pin] = ue->gsi;
		break;
	case KVM_IRQ_ROUTING_MSI:
		e->set = vmmr0_set_msi;
		e->msi.address_lo = ue->u.msi.address_lo;
		e->msi.address_hi = ue->u.msi.address_hi;
		e->msi.data = ue->u.msi.data;
		break;
	default:
		goto out;
	}

	hlist_add_head(&e->link, &rt->map[e->gsi]);
	r = 0;
out:
	return r;
}


int vmmr0_set_irq_routing(struct vm *pvm,
			const struct vmmr0_irq_routing_entry *ue,
			unsigned nr,
			unsigned flags)
{
	struct vmmr0_irq_routing_table *new, *old;
	u32 i, j, nr_rt_entries = 0;
	int r;

	for (i = 0; i < nr; ++i) {
		if (ue[i].gsi >= KVM_MAX_IRQ_ROUTES)
			return -EINVAL;
		nr_rt_entries = max(nr_rt_entries, ue[i].gsi);
	}

	nr_rt_entries += 1;

	new = kzalloc(sizeof(*new) + (nr_rt_entries * sizeof(struct hlist_head))
		      + (nr * sizeof(struct vmmr0_kernel_irq_routing_entry)),
		      GFP_KERNEL);

	if (!new)
		return -ENOMEM;

	new->rt_entries = (void *)&new->map[nr_rt_entries];

	new->nr_rt_entries = nr_rt_entries;
	for (i = 0; i < 3; i++)
		for (j = 0; j < KVM_IOAPIC_NUM_PINS; j++)
			new->chip[i][j] = -1;

	for (i = 0; i < nr; ++i) {
		r = -EINVAL;
		if (ue->flags)
		{
			goto out;
		}
		r = setup_routing_entry(new, &new->rt_entries[i], ue);
		if (r)
		{
			goto out;
		}
		++ue;
	}

#ifdef HOST_LINUX_OPTIMIZED
	mutex_lock(&pvm->irq_lock);
	old = pvm->irq_routing;
	vmmr0_irq_routing_update(pvm, new);
	mutex_unlock(&pvm->irq_lock);

	synchronize_rcu();
#else
	mutex_lock(&pvm->irq_lock);
	old = pvm->irq_routing;
	vmmr0_irq_routing_update(pvm, new);
	mutex_unlock(&pvm->irq_lock);
#endif

	new = old;
	r = 0;

out:
	kfree(new);
	return r;
}

#define IOAPIC_ROUTING_ENTRY(irq) \
	{ .gsi = irq, .type = KVM_IRQ_ROUTING_IRQCHIP,	\
	  .u.irqchip.irqchip = KVM_IRQCHIP_IOAPIC, .u.irqchip.pin = (irq) }
#define ROUTING_ENTRY1(irq) IOAPIC_ROUTING_ENTRY(irq)

#ifdef CONFIG_X86
#  define PIC_ROUTING_ENTRY(irq) \
	{ .gsi = irq, .type = KVM_IRQ_ROUTING_IRQCHIP,	\
	  .u.irqchip.irqchip = SELECT_PIC(irq), .u.irqchip.pin = (irq) % 8 }
#  define ROUTING_ENTRY2(irq) \
	IOAPIC_ROUTING_ENTRY(irq), PIC_ROUTING_ENTRY(irq)
#else
#  define ROUTING_ENTRY2(irq) \
	IOAPIC_ROUTING_ENTRY(irq)
#endif

static const struct vmmr0_irq_routing_entry default_routing[] = {
	ROUTING_ENTRY2(0), ROUTING_ENTRY2(1),
	ROUTING_ENTRY2(2), ROUTING_ENTRY2(3),
	ROUTING_ENTRY2(4), ROUTING_ENTRY2(5),
	ROUTING_ENTRY2(6), ROUTING_ENTRY2(7),
	ROUTING_ENTRY2(8), ROUTING_ENTRY2(9),
	ROUTING_ENTRY2(10), ROUTING_ENTRY2(11),
	ROUTING_ENTRY2(12), ROUTING_ENTRY2(13),
	ROUTING_ENTRY2(14), ROUTING_ENTRY2(15),
	ROUTING_ENTRY1(16), ROUTING_ENTRY1(17),
	ROUTING_ENTRY1(18), ROUTING_ENTRY1(19),
	ROUTING_ENTRY1(20), ROUTING_ENTRY1(21),
	ROUTING_ENTRY1(22), ROUTING_ENTRY1(23),
#ifdef CONFIG_IA64
	ROUTING_ENTRY1(24), ROUTING_ENTRY1(25),
	ROUTING_ENTRY1(26), ROUTING_ENTRY1(27),
	ROUTING_ENTRY1(28), ROUTING_ENTRY1(29),
	ROUTING_ENTRY1(30), ROUTING_ENTRY1(31),
	ROUTING_ENTRY1(32), ROUTING_ENTRY1(33),
	ROUTING_ENTRY1(34), ROUTING_ENTRY1(35),
	ROUTING_ENTRY1(36), ROUTING_ENTRY1(37),
	ROUTING_ENTRY1(38), ROUTING_ENTRY1(39),
	ROUTING_ENTRY1(40), ROUTING_ENTRY1(41),
	ROUTING_ENTRY1(42), ROUTING_ENTRY1(43),
	ROUTING_ENTRY1(44), ROUTING_ENTRY1(45),
	ROUTING_ENTRY1(46), ROUTING_ENTRY1(47),
#endif
};

int vmmr0_setup_default_irq_routing(struct vm *pvm)
{
	return vmmr0_set_irq_routing(pvm, default_routing,
				   ARRAY_SIZE(default_routing), 0);
}
#endif
