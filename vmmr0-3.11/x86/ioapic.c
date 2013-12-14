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
 * ioapic.c
 *
 * this code is based on kvm-kmod.
 *
 * author : 
 *  范文一 （Wincy Van） <fanwenyi0529@live.com> <QQ:362478911>
 *  Yunhong Jiang <yunhong.jiang@intel.com>
 *  Yaozu (Eddie) Dong <eddie.dong@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * From: kvm-kmod-3.4
 */
 
#include "os_interface.h"

#include <linux/vmmr0_host.h>
#include <linux/vmmr0.h>


#ifdef CONFIG_HAVE_KVM_IRQCHIP


#include "ioapic.h"
#include "lapic.h"
#include "irq.h"

#if 0
#define ioapic_debug(fmt,arg...) printk(KERN_WARNING fmt,##arg)
#else
#define ioapic_debug(fmt, arg...)
#endif
static int ioapic_deliver(struct vmmr0_ioapic *vioapic, int irq);

static unsigned long ioapic_read_indirect(struct vmmr0_ioapic *ioapic,
					  unsigned long addr,
					  unsigned long length)
{
	unsigned long result = 0;

	switch (ioapic->ioregsel) {
	case IOAPIC_REG_VERSION:
		result = ((((IOAPIC_NUM_PINS - 1) & 0xff) << 16)
			  | (IOAPIC_VERSION_ID & 0xff));
		break;

	case IOAPIC_REG_APIC_ID:
	case IOAPIC_REG_ARB_ID:
		result = ((ioapic->id & 0xf) << 24);
		break;

	default:
		{
			u32 redir_index = (ioapic->ioregsel - 0x10) >> 1;
			u64 redir_content;

			ASSERT(redir_index < IOAPIC_NUM_PINS);

			redir_content = ioapic->redirtbl[redir_index].bits;
			result = (ioapic->ioregsel & 0x1) ?
			    (redir_content >> 32) & 0xffffffff :
			    redir_content & 0xffffffff;
			break;
		}
	}

	return result;
}

static int ioapic_service(struct vmmr0_ioapic *ioapic, unsigned int idx)
{
	union vmmr0_ioapic_redirect_entry *pent;
	int injected = -1;

	pent = &ioapic->redirtbl[idx];

	if (!pent->fields.mask) {
		injected = ioapic_deliver(ioapic, idx);
		if (injected && pent->fields.trig_mode == IOAPIC_LEVEL_TRIG)
			pent->fields.remote_irr = 1;
	}

	return injected;
}

static void update_handled_vectors(struct vmmr0_ioapic *ioapic)
{
	DECLARE_BITMAP(handled_vectors, 256);
	int i;

	memset(handled_vectors, 0, sizeof(handled_vectors));
	for (i = 0; i < IOAPIC_NUM_PINS; ++i)
		__set_bit(ioapic->redirtbl[i].fields.vector, handled_vectors);
	memcpy(ioapic->handled_vectors, handled_vectors,
	       sizeof(handled_vectors));
	smp_wmb();
}

static void ioapic_write_indirect(struct vmmr0_ioapic *ioapic, u32 val)
{
	unsigned index;
	bool mask_before, mask_after;
	union vmmr0_ioapic_redirect_entry *e;

	switch (ioapic->ioregsel) {
	case IOAPIC_REG_VERSION:
		/* Writes are ignored. */
		break;

	case IOAPIC_REG_APIC_ID:
		ioapic->id = (val >> 24) & 0xf;
		break;

	case IOAPIC_REG_ARB_ID:
		break;

	default:
		index = (ioapic->ioregsel - 0x10) >> 1;

		ioapic_debug("change redir index %x val %x\n", index, val);
		if (index >= IOAPIC_NUM_PINS)
			return;
		e = &ioapic->redirtbl[index];
		mask_before = e->fields.mask;
		if (ioapic->ioregsel & 1) {
			e->bits &= 0xffffffff;
			e->bits |= (u64) val << 32;
		} else {
			e->bits &= ~0xffffffffULL;
			e->bits |= (u32) val;
			e->fields.remote_irr = 0;
		}
		update_handled_vectors(ioapic);
		mask_after = e->fields.mask;
		if (mask_before != mask_after)
			vmmr0_fire_mask_notifiers(ioapic->pvm, KVM_IRQCHIP_IOAPIC, index, mask_after);
		if (e->fields.trig_mode == IOAPIC_LEVEL_TRIG
		    && ioapic->irr & (1 << index))
			ioapic_service(ioapic, index);
		break;
	}
}

static int ioapic_deliver(struct vmmr0_ioapic *ioapic, int irq)
{
	union vmmr0_ioapic_redirect_entry *entry = &ioapic->redirtbl[irq];
	struct vmmr0_lapic_irq irqe;

	ioapic_debug("dest=%x dest_mode=%x delivery_mode=%x "
		     "vector=%x trig_mode=%x\n",
		     entry->fields.dest_id, entry->fields.dest_mode,
		     entry->fields.delivery_mode, entry->fields.vector,
		     entry->fields.trig_mode);

	irqe.dest_id = entry->fields.dest_id;
	irqe.vector = entry->fields.vector;
	irqe.dest_mode = entry->fields.dest_mode;
	irqe.trig_mode = entry->fields.trig_mode;
	irqe.delivery_mode = entry->fields.delivery_mode << 8;
	irqe.level = 1;
	irqe.shorthand = 0;

#ifdef CONFIG_X86
	/* Always delivery PIT interrupt to vcpu 0 */
	if (irq == 0) {
		irqe.dest_mode = 0; /* Physical mode. */
		/* need to read apic_id from apic regiest since
		 * it can be rewritten */
		irqe.dest_id = ioapic->pvm->bsp_vcpu_id;
	}
#endif
	return vmmr0_irq_delivery_to_apic(ioapic->pvm, NULL, &irqe);
}

int vmmr0_ioapic_set_irq(struct vmmr0_ioapic *ioapic, int irq, int level)
{
	u32 old_irr;
	u32 mask = 1 << irq;
	union vmmr0_ioapic_redirect_entry entry;
	int ret = 1;

	spin_lock(&ioapic->lock);
	old_irr = ioapic->irr;
	if (irq >= 0 && irq < IOAPIC_NUM_PINS) {
		entry = ioapic->redirtbl[irq];
		level ^= entry.fields.polarity;
		if (!level)
			ioapic->irr &= ~mask;
		else {
			int edge = (entry.fields.trig_mode == IOAPIC_EDGE_TRIG);
			ioapic->irr |= mask;
			if ((edge && old_irr != ioapic->irr) ||
			    (!edge && !entry.fields.remote_irr))
				ret = ioapic_service(ioapic, irq);
			else
				ret = 0; /* report coalesced interrupt */
		}
	}
	spin_unlock(&ioapic->lock);

	return ret;
}

static void __vmmr0_ioapic_update_eoi(struct vmmr0_ioapic *ioapic, int vector,
				     int trigger_mode)
{
	int i;

	for (i = 0; i < IOAPIC_NUM_PINS; i++) {
		union vmmr0_ioapic_redirect_entry *ent = &ioapic->redirtbl[i];

		if (ent->fields.vector != vector)
			continue;

		/*
		 * We are dropping lock while calling ack notifiers because ack
		 * notifier callbacks for assigned devices call into IOAPIC
		 * recursively. Since remote_irr is cleared only after call
		 * to notifiers if the same vector will be delivered while lock
		 * is dropped it will be put into irr and will be delivered
		 * after ack notifier returns.
		 */
		spin_unlock(&ioapic->lock);
		vmmr0_notify_acked_irq(ioapic->pvm, KVM_IRQCHIP_IOAPIC, i);
		spin_lock(&ioapic->lock);

		if (trigger_mode != IOAPIC_LEVEL_TRIG)
			continue;

		ASSERT(ent->fields.trig_mode == IOAPIC_LEVEL_TRIG);
		ent->fields.remote_irr = 0;
		if (!ent->fields.mask && (ioapic->irr & (1 << i)))
			ioapic_service(ioapic, i);
	}
}

void vmmr0_ioapic_update_eoi(struct vm *pvm, int vector, int trigger_mode)
{
	struct vmmr0_ioapic *ioapic = pvm->arch.vioapic;

	smp_rmb();
	if (!test_bit(vector, ioapic->handled_vectors))
		return;
	spin_lock(&ioapic->lock);
	__vmmr0_ioapic_update_eoi(ioapic, vector, trigger_mode);
	spin_unlock(&ioapic->lock);
}

static inline struct vmmr0_ioapic *to_ioapic(struct vmmr0_io_device *dev)
{
	return container_of(dev, struct vmmr0_ioapic, dev);
}

static inline int ioapic_in_range(struct vmmr0_ioapic *ioapic, gpa_t addr)
{
	return ((addr >= ioapic->base_address &&
		 (addr < ioapic->base_address + IOAPIC_MEM_LENGTH)));
}

static int ioapic_mmio_read(struct vmmr0_io_device *this, gpa_t addr, int len,
			    void *val)
{
	struct vmmr0_ioapic *ioapic = to_ioapic(this);
	u32 result;
	if (!ioapic_in_range(ioapic, addr))
		return -EOPNOTSUPP;

	ioapic_debug("addr %lx\n", (unsigned long)addr);
	ASSERT(!(addr & 0xf));	/* check alignment */

	addr &= 0xff;
	spin_lock(&ioapic->lock);
	switch (addr) {
	case IOAPIC_REG_SELECT:
		result = ioapic->ioregsel;
		break;

	case IOAPIC_REG_WINDOW:
		result = ioapic_read_indirect(ioapic, addr, len);
		break;

	default:
		result = 0;
		break;
	}
	spin_unlock(&ioapic->lock);

	switch (len) {
	case 8:
		*(u64 *) val = result;
		break;
	case 1:
	case 2:
	case 4:
		memcpy(val, (char *)&result, len);
		break;
	default:
		printk(KERN_WARNING "ioapic: wrong length %d\n", len);
	}
	return 0;
}

static int ioapic_mmio_write(struct vmmr0_io_device *this, gpa_t addr, int len,
			     const void *val)
{
	struct vmmr0_ioapic *ioapic = to_ioapic(this);
	u32 data;
	if (!ioapic_in_range(ioapic, addr))
		return -EOPNOTSUPP;

	ioapic_debug("ioapic_mmio_write addr=%p len=%d val=%p\n",
		     (void*)addr, len, val);
	ASSERT(!(addr & 0xf));	/* check alignment */

	switch (len) {
	case 8:
	case 4:
		data = *(u32 *) val;
		break;
	case 2:
		data = *(u16 *) val;
		break;
	case 1:
		data = *(u8  *) val;
		break;
	default:
		printk(KERN_WARNING "ioapic: Unsupported size %d\n", len);
		return 0;
	}

	addr &= 0xff;
	spin_lock(&ioapic->lock);
	switch (addr) {
	case IOAPIC_REG_SELECT:
		ioapic->ioregsel = data & 0xFF; /* 8-bit register */
		break;

	case IOAPIC_REG_WINDOW:
		ioapic_write_indirect(ioapic, data);
		break;
#ifdef	CONFIG_IA64
	case IOAPIC_REG_EOI:
		__vmmr0_ioapic_update_eoi(ioapic, data, IOAPIC_LEVEL_TRIG);
		break;
#endif

	default:
		break;
	}
	spin_unlock(&ioapic->lock);
	return 0;
}

void vmmr0_ioapic_reset(struct vmmr0_ioapic *ioapic)
{
	int i;

	for (i = 0; i < IOAPIC_NUM_PINS; i++)
		ioapic->redirtbl[i].fields.mask = 1;
	ioapic->base_address = IOAPIC_DEFAULT_BASE_ADDRESS;
	ioapic->ioregsel = 0;
	ioapic->irr = 0;
	ioapic->id = 0;
	update_handled_vectors(ioapic);
}

static const struct vmmr0_io_device_ops ioapic_mmio_ops = {
	.read     = ioapic_mmio_read,
	.write    = ioapic_mmio_write,
};

int vmmr0_ioapic_init(struct vm *pvm)
{
	struct vmmr0_ioapic *ioapic;
	int ret;

	ioapic = kzalloc(sizeof(struct vmmr0_ioapic), GFP_KERNEL);
	if (!ioapic)
		return -ENOMEM;
	spin_lock_init(&ioapic->lock);
	pvm->arch.vioapic = ioapic;
	vmmr0_ioapic_reset(ioapic);
	vmmr0_iodevice_init(&ioapic->dev, &ioapic_mmio_ops);
	ioapic->pvm = pvm;
	mutex_lock(&pvm->slots_lock);
	ret = vmmr0_io_bus_register_dev(pvm, KVM_MMIO_BUS, ioapic->base_address,
				      IOAPIC_MEM_LENGTH, &ioapic->dev);
	mutex_unlock(&pvm->slots_lock);
	if (ret < 0) {
		pvm->arch.vioapic = NULL;
		kfree(ioapic);
	}

	return ret;
}

void vmmr0_ioapic_destroy(struct vm *pvm)
{
	struct vmmr0_ioapic *ioapic = pvm->arch.vioapic;

	if (ioapic) {
		vmmr0_io_bus_unregister_dev(pvm, KVM_MMIO_BUS, &ioapic->dev);
		pvm->arch.vioapic = NULL;
		kfree(ioapic);
	}
}

int vmmr0_get_ioapic(struct vm *pvm, struct vmmr0_ioapic_state *state)
{
	struct vmmr0_ioapic *ioapic = ioapic_irqchip(pvm);
	if (!ioapic)
		return -EINVAL;

	spin_lock(&ioapic->lock);
	memcpy(state, ioapic, sizeof(struct vmmr0_ioapic_state));
	spin_unlock(&ioapic->lock);
	return 0;
}

int vmmr0_set_ioapic(struct vm *pvm, struct vmmr0_ioapic_state *state)
{
	struct vmmr0_ioapic *ioapic = ioapic_irqchip(pvm);
	if (!ioapic)
		return -EINVAL;

	spin_lock(&ioapic->lock);
	memcpy(ioapic, state, sizeof(struct vmmr0_ioapic_state));
	update_handled_vectors(ioapic);
	spin_unlock(&ioapic->lock);
	return 0;
}
#endif
