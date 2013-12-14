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
 * i8259.c
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

#ifdef HOST_LINUX
#define pr_pic_unimpl(fmt, ...)	\
	pr_err_ratelimited("vmmr0: pic: " fmt, ## __VA_ARGS__)
#else
#define pr_pic_unimpl(fmt, ...)	\
	printk("vmmr0: pic: " fmt, ## __VA_ARGS__)
#endif

static void pic_irq_request(struct vm *pvm, int level);

static void pic_lock(struct vmmr0_pic *s)
	__acquires(&s->lock)
{
	spin_lock(&s->lock);
}

static void pic_unlock(struct vmmr0_pic *s)
	__releases(&s->lock)
{
	bool wakeup = s->wakeup_needed;
	struct vmmr0_vcpu *vcpu, *found = NULL;
	int i;

	s->wakeup_needed = false;

	spin_unlock(&s->lock);

	if (wakeup) {
		vmmr0_for_each_vcpu(i, vcpu, s->pvm) {
			if (vmmr0_apic_accept_pic_intr(vcpu)) {
				found = vcpu;
				break;
			}
		}

		if (!found)
			return;

		vmmr0_make_request(KVM_REQ_EVENT, found);
		vmmr0_vcpu_kick(found);
	}
}

static void pic_clear_isr(struct vmmr0_kpic_state *s, int irq)
{
	s->isr &= ~(1 << irq);
	if (s != &s->pics_state->pics[0])
		irq += 8;
	/*
	 * We are dropping lock while calling ack notifiers since ack
	 * notifier callbacks for assigned devices call into PIC recursively.
	 * Other interrupt may be delivered to PIC while lock is dropped but
	 * it should be safe since PIC state is already updated at this stage.
	 */
	pic_unlock(s->pics_state);
	vmmr0_notify_acked_irq(s->pics_state->pvm, SELECT_PIC(irq), irq);
	pic_lock(s->pics_state);
}

/*
 * set irq level. If an edge is detected, then the IRR is set to 1
 */
static inline int pic_set_irq1(struct vmmr0_kpic_state *s, int irq, int level)
{
	int mask, ret = 1;
	mask = 1 << irq;
	if (s->elcr & mask)	/* level triggered */
		if (level) {
			ret = !(s->irr & mask);
			s->irr |= mask;
			s->last_irr |= mask;
		} else {
			s->irr &= ~mask;
			s->last_irr &= ~mask;
		}
	else	/* edge triggered */
		if (level) {
			if ((s->last_irr & mask) == 0) {
				ret = !(s->irr & mask);
				s->irr |= mask;
			}
			s->last_irr |= mask;
		} else
			s->last_irr &= ~mask;

	return (s->imr & mask) ? -1 : ret;
}

/*
 * return the highest priority found in mask (highest = smallest
 * number). Return 8 if no irq
 */
static inline int get_priority(struct vmmr0_kpic_state *s, int mask)
{
	int priority;
	if (mask == 0)
		return 8;
	priority = 0;
	while ((mask & (1 << ((priority + s->priority_add) & 7))) == 0)
		priority++;
	return priority;
}

/*
 * return the pic wanted interrupt. return -1 if none
 */
static int pic_get_irq(struct vmmr0_kpic_state *s)
{
	int mask, cur_priority, priority;

	mask = s->irr & ~s->imr;
	priority = get_priority(s, mask);
	if (priority == 8)
		return -1;
	/*
	 * compute current priority. If special fully nested mode on the
	 * master, the IRQ coming from the slave is not taken into account
	 * for the priority computation.
	 */
	mask = s->isr;
	if (s->special_fully_nested_mode && s == &s->pics_state->pics[0])
		mask &= ~(1 << 2);
	cur_priority = get_priority(s, mask);
	if (priority < cur_priority)
		/*
		 * higher priority found: an irq should be generated
		 */
		return (priority + s->priority_add) & 7;
	else
		return -1;
}

/*
 * raise irq to CPU if necessary. must be called every time the active
 * irq may change
 */
static void pic_update_irq(struct vmmr0_pic *s)
{
	int irq2, irq;

	irq2 = pic_get_irq(&s->pics[1]);
	if (irq2 >= 0) {
		/*
		 * if irq request by slave pic, signal master PIC
		 */
		pic_set_irq1(&s->pics[0], 2, 1);
		pic_set_irq1(&s->pics[0], 2, 0);
	}
	irq = pic_get_irq(&s->pics[0]);
	pic_irq_request(s->pvm, irq >= 0);
}

void vmmr0_pic_update_irq(struct vmmr0_pic *s)
{
	pic_lock(s);
	pic_update_irq(s);
	pic_unlock(s);
}

int vmmr0_pic_set_irq(void *opaque, int irq, int level)
{
	struct vmmr0_pic *s = opaque;
	int ret = -1;

	pic_lock(s);
	if (irq >= 0 && irq < PIC_NUM_PINS) {
		ret = pic_set_irq1(&s->pics[irq >> 3], irq & 7, level);
		pic_update_irq(s);
	}
	pic_unlock(s);

	return ret;
}

/*
 * acknowledge interrupt 'irq'
 */
static inline void pic_intack(struct vmmr0_kpic_state *s, int irq)
{
	s->isr |= 1 << irq;
	/*
	 * We don't clear a level sensitive interrupt here
	 */
	if (!(s->elcr & (1 << irq)))
		s->irr &= ~(1 << irq);

	if (s->auto_eoi) {
		if (s->rotate_on_auto_eoi)
			s->priority_add = (irq + 1) & 7;
		pic_clear_isr(s, irq);
	}

}

int vmmr0_pic_read_irq(struct vm *pvm)
{
	int irq, irq2, intno;
	struct vmmr0_pic *s = pic_irqchip(pvm);

	pic_lock(s);
	irq = pic_get_irq(&s->pics[0]);
	if (irq >= 0) {
		pic_intack(&s->pics[0], irq);
		if (irq == 2) {
			irq2 = pic_get_irq(&s->pics[1]);
			if (irq2 >= 0)
				pic_intack(&s->pics[1], irq2);
			else
				/*
				 * spurious IRQ on slave controller
				 */
				irq2 = 7;
			intno = s->pics[1].irq_base + irq2;
			irq = irq2 + 8;
		} else
			intno = s->pics[0].irq_base + irq;
	} else {
		/*
		 * spurious IRQ on host controller
		 */
		irq = 7;
		intno = s->pics[0].irq_base + irq;
	}
	pic_update_irq(s);
	pic_unlock(s);

	return intno;
}

void vmmr0_pic_reset(struct vmmr0_kpic_state *s)
{
	int irq, i;
	struct vmmr0_vcpu *vcpu;
	u8 irr = s->irr, isr = s->imr;
	bool found = false;

	s->last_irr = 0;
	s->irr = 0;
	s->imr = 0;
	s->isr = 0;
	s->priority_add = 0;
	s->irq_base = 0;
	s->read_reg_select = 0;
	s->poll = 0;
	s->special_mask = 0;
	s->init_state = 0;
	s->auto_eoi = 0;
	s->rotate_on_auto_eoi = 0;
	s->special_fully_nested_mode = 0;
	s->init4 = 0;

	vmmr0_for_each_vcpu(i, vcpu, s->pics_state->pvm)
		if (vmmr0_apic_accept_pic_intr(vcpu)) {
			found = true;
			break;
		}


	if (!found)
		return;

	for (irq = 0; irq < PIC_NUM_PINS/2; irq++)
		if (irr & (1 << irq) || isr & (1 << irq))
			pic_clear_isr(s, irq);
}

static void pic_ioport_write(void *opaque, u32 addr, u32 val)
{
	struct vmmr0_kpic_state *s = opaque;
	int priority, cmd, irq;

	addr &= 1;
	if (addr == 0) {
		if (val & 0x10) {
			s->init4 = val & 1;
			s->last_irr = 0;
			s->irr &= s->elcr;
			s->imr = 0;
			s->priority_add = 0;
			s->special_mask = 0;
			s->read_reg_select = 0;
			if (!s->init4) {
				s->special_fully_nested_mode = 0;
				s->auto_eoi = 0;
			}
			s->init_state = 1;
			if (val & 0x02)
				pr_pic_unimpl("single mode not supported");
			if (val & 0x08)
				pr_pic_unimpl(
					"level sensitive irq not supported");
		} else if (val & 0x08) {
			if (val & 0x04)
				s->poll = 1;
			if (val & 0x02)
				s->read_reg_select = val & 1;
			if (val & 0x40)
				s->special_mask = (val >> 5) & 1;
		} else {
			cmd = val >> 5;
			switch (cmd) {
			case 0:
			case 4:
				s->rotate_on_auto_eoi = cmd >> 2;
				break;
			case 1:	/* end of interrupt */
			case 5:
				priority = get_priority(s, s->isr);
				if (priority != 8) {
					irq = (priority + s->priority_add) & 7;
					if (cmd == 5)
						s->priority_add = (irq + 1) & 7;
					pic_clear_isr(s, irq);
					pic_update_irq(s->pics_state);
				}
				break;
			case 3:
				irq = val & 7;
				pic_clear_isr(s, irq);
				pic_update_irq(s->pics_state);
				break;
			case 6:
				s->priority_add = (val + 1) & 7;
				pic_update_irq(s->pics_state);
				break;
			case 7:
				irq = val & 7;
				s->priority_add = (irq + 1) & 7;
				pic_clear_isr(s, irq);
				pic_update_irq(s->pics_state);
				break;
			default:
				break;	/* no operation */
			}
		}
	} else
		switch (s->init_state) {
		case 0: { /* normal mode */
			u8 imr_diff = s->imr ^ val,
				off = (s == &s->pics_state->pics[0]) ? 0 : 8;
			s->imr = val;
			for (irq = 0; irq < PIC_NUM_PINS/2; irq++)
				if (imr_diff & (1 << irq))
					vmmr0_fire_mask_notifiers(
						s->pics_state->pvm,
						SELECT_PIC(irq + off),
						irq + off,
						!!(s->imr & (1 << irq)));
			pic_update_irq(s->pics_state);
			break;
		}
		case 1:
			s->irq_base = val & 0xf8;
			s->init_state = 2;
			break;
		case 2:
			if (s->init4)
				s->init_state = 3;
			else
				s->init_state = 0;
			break;
		case 3:
			s->special_fully_nested_mode = (val >> 4) & 1;
			s->auto_eoi = (val >> 1) & 1;
			s->init_state = 0;
			break;
		}
}

static u32 pic_poll_read(struct vmmr0_kpic_state *s, u32 addr1)
{
	int ret;

	ret = pic_get_irq(s);
	if (ret >= 0) {
		if (addr1 >> 7) {
			s->pics_state->pics[0].isr &= ~(1 << 2);
			s->pics_state->pics[0].irr &= ~(1 << 2);
		}
		s->irr &= ~(1 << ret);
		pic_clear_isr(s, ret);
		if (addr1 >> 7 || ret != 2)
			pic_update_irq(s->pics_state);
	} else {
		ret = 0x07;
		pic_update_irq(s->pics_state);
	}

	return ret;
}

static u32 pic_ioport_read(void *opaque, u32 addr1)
{
	struct vmmr0_kpic_state *s = opaque;
	unsigned int addr;
	int ret;

	addr = addr1;
	addr &= 1;
	if (s->poll) {
		ret = pic_poll_read(s, addr1);
		s->poll = 0;
	} else
		if (addr == 0)
			if (s->read_reg_select)
				ret = s->isr;
			else
				ret = s->irr;
		else
			ret = s->imr;
	return ret;
}

static void elcr_ioport_write(void *opaque, u32 addr, u32 val)
{
	struct vmmr0_kpic_state *s = opaque;
	s->elcr = val & s->elcr_mask;
}

static u32 elcr_ioport_read(void *opaque, u32 addr1)
{
	struct vmmr0_kpic_state *s = opaque;
	return s->elcr;
}

static int picdev_in_range(gpa_t addr)
{
	switch (addr) {
	case 0x20:
	case 0x21:
	case 0xa0:
	case 0xa1:
	case 0x4d0:
	case 0x4d1:
		return 1;
	default:
		return 0;
	}
}

static int picdev_write(struct vmmr0_pic *s,
			 gpa_t addr, int len, const void *val)
{
	unsigned char data = *(unsigned char *)val;
	if (!picdev_in_range(addr))
		return -EOPNOTSUPP;

	if (len != 1) {
		pr_pic_unimpl("non byte write\n");
		return 0;
	}
	pic_lock(s);
	switch (addr) {
	case 0x20:
	case 0x21:
	case 0xa0:
	case 0xa1:
		pic_ioport_write(&s->pics[addr >> 7], addr, data);
		break;
	case 0x4d0:
	case 0x4d1:
		elcr_ioport_write(&s->pics[addr & 1], addr, data);
		break;
	}
	pic_unlock(s);
	return 0;
}

static int picdev_read(struct vmmr0_pic *s,
		       gpa_t addr, int len, void *val)
{
	unsigned char data = 0;
	if (!picdev_in_range(addr))
		return -EOPNOTSUPP;

	if (len != 1) {
		pr_pic_unimpl("non byte read\n");
		return 0;
	}
	pic_lock(s);
	switch (addr) {
	case 0x20:
	case 0x21:
	case 0xa0:
	case 0xa1:
		data = pic_ioport_read(&s->pics[addr >> 7], addr);
		break;
	case 0x4d0:
	case 0x4d1:
		data = elcr_ioport_read(&s->pics[addr & 1], addr);
		break;
	}
	*(unsigned char *)val = data;
	pic_unlock(s);
	return 0;
}

static int picdev_master_write(struct vmmr0_io_device *dev,
			       gpa_t addr, int len, const void *val)
{
	return picdev_write(container_of(dev, struct vmmr0_pic, dev_master),
			    addr, len, val);
}

static int picdev_master_read(struct vmmr0_io_device *dev,
			      gpa_t addr, int len, void *val)
{
	return picdev_read(container_of(dev, struct vmmr0_pic, dev_master),
			    addr, len, val);
}

static int picdev_slave_write(struct vmmr0_io_device *dev,
			      gpa_t addr, int len, const void *val)
{
	return picdev_write(container_of(dev, struct vmmr0_pic, dev_slave),
			    addr, len, val);
}

static int picdev_slave_read(struct vmmr0_io_device *dev,
			     gpa_t addr, int len, void *val)
{
	return picdev_read(container_of(dev, struct vmmr0_pic, dev_slave),
			    addr, len, val);
}

static int picdev_eclr_write(struct vmmr0_io_device *dev,
			     gpa_t addr, int len, const void *val)
{
	return picdev_write(container_of(dev, struct vmmr0_pic, dev_eclr),
			    addr, len, val);
}

static int picdev_eclr_read(struct vmmr0_io_device *dev,
			    gpa_t addr, int len, void *val)
{
	return picdev_read(container_of(dev, struct vmmr0_pic, dev_eclr),
			    addr, len, val);
}

/*
 * callback when PIC0 irq status changed
 */
static void pic_irq_request(struct vm *pvm, int level)
{
	struct vmmr0_pic *s = pic_irqchip(pvm);

	if (!s->output)
		s->wakeup_needed = true;
	s->output = level;
}

static const struct vmmr0_io_device_ops picdev_master_ops = {
	.read     = picdev_master_read,
	.write    = picdev_master_write,
};

static const struct vmmr0_io_device_ops picdev_slave_ops = {
	.read     = picdev_slave_read,
	.write    = picdev_slave_write,
};

static const struct vmmr0_io_device_ops picdev_eclr_ops = {
	.read     = picdev_eclr_read,
	.write    = picdev_eclr_write,
};

struct vmmr0_pic *vmmr0_create_pic(struct vm *pvm)
{
	struct vmmr0_pic *s;
	int ret;

	s = kzalloc(sizeof(struct vmmr0_pic), GFP_KERNEL);
	if (!s)
		return NULL;
	spin_lock_init(&s->lock);
	s->pvm = pvm;
	s->pics[0].elcr_mask = 0xf8;
	s->pics[1].elcr_mask = 0xde;
	s->pics[0].pics_state = s;
	s->pics[1].pics_state = s;

	/*
	 * Initialize PIO device
	 */
	vmmr0_iodevice_init(&s->dev_master, &picdev_master_ops);
	vmmr0_iodevice_init(&s->dev_slave, &picdev_slave_ops);
	vmmr0_iodevice_init(&s->dev_eclr, &picdev_eclr_ops);
	mutex_lock(&pvm->slots_lock);
	ret = vmmr0_io_bus_register_dev(pvm, KVM_PIO_BUS, 0x20, 2,
				      &s->dev_master);
	if (ret < 0)
		goto fail_unlock;

	ret = vmmr0_io_bus_register_dev(pvm, KVM_PIO_BUS, 0xa0, 2, &s->dev_slave);
	if (ret < 0)
		goto fail_unreg_2;

	ret = vmmr0_io_bus_register_dev(pvm, KVM_PIO_BUS, 0x4d0, 2, &s->dev_eclr);
	if (ret < 0)
		goto fail_unreg_1;

	mutex_unlock(&pvm->slots_lock);

	return s;

fail_unreg_1:
	vmmr0_io_bus_unregister_dev(pvm, KVM_PIO_BUS, &s->dev_slave);

fail_unreg_2:
	vmmr0_io_bus_unregister_dev(pvm, KVM_PIO_BUS, &s->dev_master);

fail_unlock:
	mutex_unlock(&pvm->slots_lock);

	kfree(s);

	return NULL;
}

void vmmr0_destroy_pic(struct vm *pvm)
{
	struct vmmr0_pic *vpic = pvm->arch.vpic;

	if (vpic) {
		vmmr0_io_bus_unregister_dev(pvm, KVM_PIO_BUS, &vpic->dev_master);
		vmmr0_io_bus_unregister_dev(pvm, KVM_PIO_BUS, &vpic->dev_slave);
		vmmr0_io_bus_unregister_dev(pvm, KVM_PIO_BUS, &vpic->dev_eclr);
		pvm->arch.vpic = NULL;
		kfree(vpic);
	}
}
#endif
