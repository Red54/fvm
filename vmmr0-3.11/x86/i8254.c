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
 * i8254.c
 *
 * this code is based on kvm-kmod.
 *
 * author : 
 *   范文一 （Wincy Van） <fanwenyi0529@live.com> <QQ:362478911>
 *   Sheng Yang <sheng.yang@intel.com>
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

#ifndef CONFIG_X86_64
#define mod_64(x, y) ((x) - (y) * div64_u64(x, y))
#else
#define mod_64(x, y) ((x) % (y))
#endif

#define RW_STATE_LSB 1
#define RW_STATE_MSB 2
#define RW_STATE_WORD0 3
#define RW_STATE_WORD1 4

/* Compute with 96 bit intermediate result: (a*b)/c */
static u64 muldiv64(u64 a, u32 b, u32 c)
{
	union {
		u64 ll;
		struct {
			u32 low, high;
		} l;
	} u, res;
	u64 rl, rh;

	u.ll = a;
	rl = (u64)u.l.low * (u64)b;
	rh = (u64)u.l.high * (u64)b;
	rh += (rl >> 32);
	res.l.high = div64_u64(rh, c);
	res.l.low = div64_u64(((mod_64(rh, c) << 32) + (rl & 0xffffffff)), c);
	return res.ll;
}

static void pit_set_gate(struct vm *pvm, int channel, u32 val)
{
	struct vmmr0_kpit_channel_state *c =
		&pvm->arch.vpit->pit_state.channels[channel];

	WARN_ON(!mutex_is_locked(&pvm->arch.vpit->pit_state.lock));

	switch (c->mode) {
	default:
	case 0:
	case 4:
		/* XXX: just disable/enable counting */
		break;
	case 1:
	case 2:
	case 3:
	case 5:
		/* Restart counting on rising edge. */
		if (c->gate < val)
			c->count_load_time = ktime_get();
		break;
	}

	c->gate = val;
}

static int pit_get_gate(struct vm *pvm, int channel)
{
	WARN_ON(!mutex_is_locked(&pvm->arch.vpit->pit_state.lock));

	return pvm->arch.vpit->pit_state.channels[channel].gate;
}

static s64 __kpit_elapsed(struct vm *pvm)
{
	s64 elapsed;
	ktime_t remaining;
	struct vmmr0_kpit_state *ps = &pvm->arch.vpit->pit_state;

	if (!ps->pit_timer.period)
		return 0;

	/*
	 * The Counter does not stop when it reaches zero. In
	 * Modes 0, 1, 4, and 5 the Counter ``wraps around'' to
	 * the highest count, either FFFF hex for binary counting
	 * or 9999 for BCD counting, and continues counting.
	 * Modes 2 and 3 are periodic; the Counter reloads
	 * itself with the initial count and continues counting
	 * from there.
	 */
	remaining = hrtimer_get_remaining(&ps->pit_timer.timer);
	elapsed = ps->pit_timer.period - ktime_to_ns(remaining);
	elapsed = mod_64(elapsed, ps->pit_timer.period);

	return elapsed;
}

static s64 kpit_elapsed(struct vm *pvm, struct vmmr0_kpit_channel_state *c,
			int channel)
{
	if (channel == 0)
		return __kpit_elapsed(pvm);

	return ktime_to_ns(ktime_sub(ktime_get(), c->count_load_time));
}

static int pit_get_count(struct vm *pvm, int channel)
{
	struct vmmr0_kpit_channel_state *c =
		&pvm->arch.vpit->pit_state.channels[channel];
	s64 d, t;
	int counter;

	WARN_ON(!mutex_is_locked(&pvm->arch.vpit->pit_state.lock));

	t = kpit_elapsed(pvm, c, channel);
	d = muldiv64(t, KVM_PIT_FREQ, NSEC_PER_SEC);

	switch (c->mode) {
	case 0:
	case 1:
	case 4:
	case 5:
		counter = (c->count - d) & 0xffff;
		break;
	case 3:
		/* XXX: may be incorrect for odd counts */
		counter = c->count - (mod_64((2 * d), c->count));
		break;
	default:
		counter = c->count - mod_64(d, c->count);
		break;
	}
	return counter;
}

static int pit_get_out(struct vm *pvm, int channel)
{
	struct vmmr0_kpit_channel_state *c =
		&pvm->arch.vpit->pit_state.channels[channel];
	s64 d, t;
	int out;

	WARN_ON(!mutex_is_locked(&pvm->arch.vpit->pit_state.lock));

	t = kpit_elapsed(pvm, c, channel);
	d = muldiv64(t, KVM_PIT_FREQ, NSEC_PER_SEC);

	switch (c->mode) {
	default:
	case 0:
		out = (d >= c->count);
		break;
	case 1:
		out = (d < c->count);
		break;
	case 2:
		out = ((mod_64(d, c->count) == 0) && (d != 0));
		break;
	case 3:
		out = (mod_64(d, c->count) < ((c->count + 1) >> 1));
		break;
	case 4:
	case 5:
		out = (d == c->count);
		break;
	}

	return out;
}

static void pit_latch_count(struct vm *pvm, int channel)
{
	struct vmmr0_kpit_channel_state *c =
		&pvm->arch.vpit->pit_state.channels[channel];

	WARN_ON(!mutex_is_locked(&pvm->arch.vpit->pit_state.lock));

	if (!c->count_latched) {
		c->latched_count = pit_get_count(pvm, channel);
		c->count_latched = c->rw_mode;
	}
}

static void pit_latch_status(struct vm *pvm, int channel)
{
	struct vmmr0_kpit_channel_state *c =
		&pvm->arch.vpit->pit_state.channels[channel];

	WARN_ON(!mutex_is_locked(&pvm->arch.vpit->pit_state.lock));

	if (!c->status_latched) {
		/* TODO: Return NULL COUNT (bit 6). */
		c->status = ((pit_get_out(pvm, channel) << 7) |
				(c->rw_mode << 4) |
				(c->mode << 1) |
				c->bcd);
		c->status_latched = 1;
	}
}

static void vmmr0_pit_ack_irq(struct vmmr0_irq_ack_notifier *kian)
{
	struct vmmr0_kpit_state *ps = container_of(kian, struct vmmr0_kpit_state,
						 irq_ack_notifier);
	int value;

	spin_lock(&ps->inject_lock);
	value = atomic_dec_return(&ps->pit_timer.pending);
	if (value < 0)
		/* spurious acks can be generated if, for example, the
		 * PIC is being reset.  Handle it gracefully here
		 */
		atomic_inc(&ps->pit_timer.pending);
	else if (value > 0)
		/* in this case, we had multiple outstanding pit interrupts
		 * that we needed to inject.  Reinject
		 */
		queue_work(ps->pit->wq, &ps->pit->expired);
	ps->irq_ack = 1;
	spin_unlock(&ps->inject_lock);
}

void __vmmr0_migrate_pit_timer(struct vmmr0_vcpu *vcpu)
{
	struct vmmr0_pit *pit = vcpu->pvm->arch.vpit;
	struct hrtimer *timer;

	if (!vmmr0_vcpu_is_bsp(vcpu) || !pit)
		return;

	timer = &pit->pit_state.pit_timer.timer;
	if (hrtimer_cancel(timer))
		vmmr0_hrtimer_start_expires(timer, HRTIMER_MODE_ABS);
}

static void destroy_pit_timer(struct vmmr0_pit *pit)
{
	hrtimer_cancel(&pit->pit_state.pit_timer.timer);
	cancel_work_sync(&pit->expired);
}

static bool kpit_is_periodic(struct vmmr0_timer *ktimer)
{
	struct vmmr0_kpit_state *ps = container_of(ktimer, struct vmmr0_kpit_state,
						 pit_timer);
	return ps->is_periodic;
}

static struct vmmr0_timer_ops kpit_ops = {
	.is_periodic = kpit_is_periodic,
};

static void pit_do_work(struct work_struct *work)
{
	struct vmmr0_pit *pit = container_of(work, struct vmmr0_pit, expired);
	struct vm *pvm = pit->pvm;
	struct vmmr0_vcpu *vcpu;
	int i;
	struct vmmr0_kpit_state *ps = &pit->pit_state;
	int inject = 0;

	/* Try to inject pending interrupts when
	 * last one has been acked.
	 */
	spin_lock(&ps->inject_lock);
	if (ps->irq_ack) {
		ps->irq_ack = 0;
		inject = 1;
	}
	spin_unlock(&ps->inject_lock);
	if (inject) {
		vmmr0_set_irq(pvm, pvm->arch.vpit->irq_source_id, 0, 1);
		vmmr0_set_irq(pvm, pvm->arch.vpit->irq_source_id, 0, 0);

		/*
		 * Provides NMI watchdog support via Virtual Wire mode.
		 * The route is: PIT -> PIC -> LVT0 in NMI mode.
		 *
		 * Note: Our Virtual Wire implementation is simplified, only
		 * propagating PIT interrupts to all VCPUs when they have set
		 * LVT0 to NMI delivery. Other PIC interrupts are just sent to
		 * VCPU0, and only if its LVT0 is in EXTINT mode.
		 */
		if (pvm->arch.vapics_in_nmi_mode > 0)
			vmmr0_for_each_vcpu(i, vcpu, pvm)
				vmmr0_apic_nmi_wd_deliver(vcpu);
	}
}

static enum hrtimer_restart pit_timer_fn(struct hrtimer *data)
{
	struct vmmr0_timer *ktimer = container_of(data, struct vmmr0_timer, timer);
	struct vmmr0_pit *pt = ktimer->pvm->arch.vpit;

	if (ktimer->reinject || !atomic_read(&ktimer->pending)) {
		atomic_inc(&ktimer->pending);
		queue_work(pt->wq, &pt->expired);
	}

	if (ktimer->t_ops->is_periodic(ktimer)) {
		vmmr0_hrtimer_add_expires_ns(&ktimer->timer, ktimer->period);
		return HRTIMER_RESTART;
	} else
		return HRTIMER_NORESTART;
}

static void create_pit_timer(struct vm *pvm, u32 val, int is_period)
{
	struct vmmr0_kpit_state *ps = &pvm->arch.vpit->pit_state;
	struct vmmr0_timer *pt = &ps->pit_timer;
	s64 interval;

	if (!irqchip_in_kernel(pvm) || ps->flags & KVM_PIT_FLAGS_HPET_LEGACY)
		return;

	interval = muldiv64(val, NSEC_PER_SEC, KVM_PIT_FREQ);

	pr_debug("pit: " "create pit timer, interval is %llu nsec\n", interval);

	/* TODO The new value only affected after the retriggered */
	hrtimer_cancel(&pt->timer);
	cancel_work_sync(&ps->pit->expired);
	pt->period = interval;
	ps->is_periodic = is_period;

	pt->timer.function = pit_timer_fn;
	pt->t_ops = &kpit_ops;
	pt->pvm = ps->pit->pvm;

	atomic_set(&pt->pending, 0);
	ps->irq_ack = 1;

	hrtimer_start(&pt->timer, ktime_add_ns(ktime_get(), interval),
		      HRTIMER_MODE_ABS);
}

static void pit_load_count(struct vm *pvm, int channel, u32 val)
{
	struct vmmr0_kpit_state *ps = &pvm->arch.vpit->pit_state;

	WARN_ON(!mutex_is_locked(&ps->lock));

	pr_debug("pit: " "load_count val is %d, channel is %d\n", val, channel);

	/*
	 * The largest possible initial count is 0; this is equivalent
	 * to 216 for binary counting and 104 for BCD counting.
	 */
	if (val == 0)
		val = 0x10000;

	ps->channels[channel].count = val;

	if (channel != 0) {
		ps->channels[channel].count_load_time = ktime_get();
		return;
	}

	/* Two types of timer
	 * mode 1 is one shot, mode 2 is period, otherwise del timer */
	switch (ps->channels[0].mode) {
	case 0:
	case 1:
        /* FIXME: enhance mode 4 precision */
	case 4:
		create_pit_timer(pvm, val, 0);
		break;
	case 2:
	case 3:
		create_pit_timer(pvm, val, 1);
		break;
	default:
		destroy_pit_timer(pvm->arch.vpit);
	}
}

void vmmr0_pit_load_count(struct vm *pvm, int channel, u32 val, int hpet_legacy_start)
{
	u8 saved_mode;
	if (hpet_legacy_start) {
		/* save existing mode for later reenablement */
		saved_mode = pvm->arch.vpit->pit_state.channels[0].mode;
		pvm->arch.vpit->pit_state.channels[0].mode = 0xff; /* disable timer */
		pit_load_count(pvm, channel, val);
		pvm->arch.vpit->pit_state.channels[0].mode = saved_mode;
	} else {
		pit_load_count(pvm, channel, val);
	}
}

static inline struct vmmr0_pit *dev_to_pit(struct vmmr0_io_device *dev)
{
	return container_of(dev, struct vmmr0_pit, dev);
}

static inline struct vmmr0_pit *speaker_to_pit(struct vmmr0_io_device *dev)
{
	return container_of(dev, struct vmmr0_pit, speaker_dev);
}

static inline int pit_in_range(gpa_t addr)
{
	return ((addr >= KVM_PIT_BASE_ADDRESS) &&
		(addr < KVM_PIT_BASE_ADDRESS + KVM_PIT_MEM_LENGTH));
}

static int pit_ioport_write(struct vmmr0_io_device *this,
			    gpa_t addr, int len, const void *data)
{
	struct vmmr0_pit *pit = dev_to_pit(this);
	struct vmmr0_kpit_state *pit_state = &pit->pit_state;
	struct vm *pvm = pit->pvm;
	int channel, access;
	struct vmmr0_kpit_channel_state *s;
	u32 val = *(u32 *) data;
	if (!pit_in_range(addr))
		return -EOPNOTSUPP;

	val  &= 0xff;
	addr &= KVM_PIT_CHANNEL_MASK;

	mutex_lock(&pit_state->lock);

	if (val != 0)
		pr_debug("pit: " "write addr is 0x%x, len is %d, val is 0x%x\n",
			 (unsigned int)addr, len, val);

	if (addr == 3) {
		channel = val >> 6;
		if (channel == 3) {
			/* Read-Back Command. */
			for (channel = 0; channel < 3; channel++) {
				s = &pit_state->channels[channel];
				if (val & (2 << channel)) {
					if (!(val & 0x20))
						pit_latch_count(pvm, channel);
					if (!(val & 0x10))
						pit_latch_status(pvm, channel);
				}
			}
		} else {
			/* Select Counter <channel>. */
			s = &pit_state->channels[channel];
			access = (val >> 4) & KVM_PIT_CHANNEL_MASK;
			if (access == 0) {
				pit_latch_count(pvm, channel);
			} else {
				s->rw_mode = access;
				s->read_state = access;
				s->write_state = access;
				s->mode = (val >> 1) & 7;
				if (s->mode > 5)
					s->mode -= 4;
				s->bcd = val & 1;
			}
		}
	} else {
		/* Write Count. */
		s = &pit_state->channels[addr];
		switch (s->write_state) {
		default:
		case RW_STATE_LSB:
			pit_load_count(pvm, addr, val);
			break;
		case RW_STATE_MSB:
			pit_load_count(pvm, addr, val << 8);
			break;
		case RW_STATE_WORD0:
			s->write_latch = val;
			s->write_state = RW_STATE_WORD1;
			break;
		case RW_STATE_WORD1:
			pit_load_count(pvm, addr, s->write_latch | (val << 8));
			s->write_state = RW_STATE_WORD0;
			break;
		}
	}

	mutex_unlock(&pit_state->lock);
	return 0;
}

static int pit_ioport_read(struct vmmr0_io_device *this,
			   gpa_t addr, int len, void *data)
{
	struct vmmr0_pit *pit = dev_to_pit(this);
	struct vmmr0_kpit_state *pit_state = &pit->pit_state;
	struct vm *pvm = pit->pvm;
	int ret, count;
	struct vmmr0_kpit_channel_state *s;
	if (!pit_in_range(addr))
		return -EOPNOTSUPP;

	addr &= KVM_PIT_CHANNEL_MASK;
	if (addr == 3)
		return 0;

	s = &pit_state->channels[addr];

	mutex_lock(&pit_state->lock);

	if (s->status_latched) {
		s->status_latched = 0;
		ret = s->status;
	} else if (s->count_latched) {
		switch (s->count_latched) {
		default:
		case RW_STATE_LSB:
			ret = s->latched_count & 0xff;
			s->count_latched = 0;
			break;
		case RW_STATE_MSB:
			ret = s->latched_count >> 8;
			s->count_latched = 0;
			break;
		case RW_STATE_WORD0:
			ret = s->latched_count & 0xff;
			s->count_latched = RW_STATE_MSB;
			break;
		}
	} else {
		switch (s->read_state) {
		default:
		case RW_STATE_LSB:
			count = pit_get_count(pvm, addr);
			ret = count & 0xff;
			break;
		case RW_STATE_MSB:
			count = pit_get_count(pvm, addr);
			ret = (count >> 8) & 0xff;
			break;
		case RW_STATE_WORD0:
			count = pit_get_count(pvm, addr);
			ret = count & 0xff;
			s->read_state = RW_STATE_WORD1;
			break;
		case RW_STATE_WORD1:
			count = pit_get_count(pvm, addr);
			ret = (count >> 8) & 0xff;
			s->read_state = RW_STATE_WORD0;
			break;
		}
	}

	if (len > sizeof(ret))
		len = sizeof(ret);
	memcpy(data, (char *)&ret, len);

	mutex_unlock(&pit_state->lock);
	return 0;
}

static int speaker_ioport_write(struct vmmr0_io_device *this,
				gpa_t addr, int len, const void *data)
{
	struct vmmr0_pit *pit = speaker_to_pit(this);
	struct vmmr0_kpit_state *pit_state = &pit->pit_state;
	struct vm *pvm = pit->pvm;
	u32 val = *(u32 *) data;
	if (addr != KVM_SPEAKER_BASE_ADDRESS)
		return -EOPNOTSUPP;

	mutex_lock(&pit_state->lock);
	pit_state->speaker_data_on = (val >> 1) & 1;
	pit_set_gate(pvm, 2, val & 1);
	mutex_unlock(&pit_state->lock);
	return 0;
}

static int speaker_ioport_read(struct vmmr0_io_device *this,
			       gpa_t addr, int len, void *data)
{
	struct vmmr0_pit *pit = speaker_to_pit(this);
	struct vmmr0_kpit_state *pit_state = &pit->pit_state;
	struct vm *pvm = pit->pvm;
	unsigned int refresh_clock;
	int ret;
	if (addr != KVM_SPEAKER_BASE_ADDRESS)
		return -EOPNOTSUPP;

	/* Refresh clock toggles at about 15us. We approximate as 2^14ns. */
	refresh_clock = ((unsigned int)ktime_to_ns(ktime_get()) >> 14) & 1;

	mutex_lock(&pit_state->lock);
	ret = ((pit_state->speaker_data_on << 1) | pit_get_gate(pvm, 2) |
		(pit_get_out(pvm, 2) << 5) | (refresh_clock << 4));
		
	if (len > sizeof(ret))
		len = sizeof(ret);
	memcpy(data, (char *)&ret, len);
	mutex_unlock(&pit_state->lock);
	return 0;
}

void vmmr0_pit_reset(struct vmmr0_pit *pit)
{
	int i;
	struct vmmr0_kpit_channel_state *c;

	mutex_lock(&pit->pit_state.lock);
	pit->pit_state.flags = 0;
	for (i = 0; i < 3; i++) {
		c = &pit->pit_state.channels[i];
		c->mode = 0xff;
		c->gate = (i != 2);
		pit_load_count(pit->pvm, i, 0);
	}
	mutex_unlock(&pit->pit_state.lock);

	atomic_set(&pit->pit_state.pit_timer.pending, 0);
	pit->pit_state.irq_ack = 1;
}

static void pit_mask_notifer(struct vmmr0_irq_mask_notifier *kimn, bool mask)
{
	struct vmmr0_pit *pit = container_of(kimn, struct vmmr0_pit, mask_notifier);

	if (!mask) {
		atomic_set(&pit->pit_state.pit_timer.pending, 0);
		pit->pit_state.irq_ack = 1;
	}
}

static const struct vmmr0_io_device_ops pit_dev_ops = {
	.read     = pit_ioport_read,
	.write    = pit_ioport_write,
};

static const struct vmmr0_io_device_ops speaker_dev_ops = {
	.read     = speaker_ioport_read,
	.write    = speaker_ioport_write,
};

/* Caller must hold slots_lock */
struct vmmr0_pit *vmmr0_create_pit(struct vm *pvm, u32 flags)
{
	struct vmmr0_pit *pit;
	struct vmmr0_kpit_state *pit_state;
	int ret;

	pit = kzalloc(sizeof(struct vmmr0_pit), GFP_KERNEL);
	if (!pit)
		return NULL;

	pit->irq_source_id = vmmr0_request_irq_source_id(pvm);
	if (pit->irq_source_id < 0) {
		kfree(pit);
		return NULL;
	}

	mutex_init(&pit->pit_state.lock);
	mutex_lock(&pit->pit_state.lock);
	spin_lock_init(&pit->pit_state.inject_lock);

	pit->wq = create_singlethread_workqueue("pvm-pit-wq");
	if (!pit->wq) {
		mutex_unlock(&pit->pit_state.lock);
		vmmr0_free_irq_source_id(pvm, pit->irq_source_id);
		kfree(pit);
		return NULL;
	}
	INIT_WORK(&pit->expired, pit_do_work);

	pvm->arch.vpit = pit;
	pit->pvm = pvm;

	pit_state = &pit->pit_state;
	pit_state->pit = pit;
	hrtimer_init(&pit_state->pit_timer.timer,
		     CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	pit_state->irq_ack_notifier.gsi = 0;
	pit_state->irq_ack_notifier.irq_acked = vmmr0_pit_ack_irq;
	vmmr0_register_irq_ack_notifier(pvm, &pit_state->irq_ack_notifier);
	pit_state->pit_timer.reinject = true;
	mutex_unlock(&pit->pit_state.lock);

	vmmr0_pit_reset(pit);

	pit->mask_notifier.func = pit_mask_notifer;
	vmmr0_register_irq_mask_notifier(pvm, 0, &pit->mask_notifier);

	vmmr0_iodevice_init(&pit->dev, &pit_dev_ops);
	ret = vmmr0_io_bus_register_dev(pvm, KVM_PIO_BUS, KVM_PIT_BASE_ADDRESS,
				      KVM_PIT_MEM_LENGTH, &pit->dev);
	if (ret < 0)
		goto fail;

	if (flags & KVM_PIT_SPEAKER_DUMMY) {
		vmmr0_iodevice_init(&pit->speaker_dev, &speaker_dev_ops);
		ret = vmmr0_io_bus_register_dev(pvm, KVM_PIO_BUS,
					      KVM_SPEAKER_BASE_ADDRESS, 4,
					      &pit->speaker_dev);
		if (ret < 0)
			goto fail_unregister;
	}

	return pit;

fail_unregister:
	vmmr0_io_bus_unregister_dev(pvm, KVM_PIO_BUS, &pit->dev);

fail:
	vmmr0_unregister_irq_mask_notifier(pvm, 0, &pit->mask_notifier);
	vmmr0_unregister_irq_ack_notifier(pvm, &pit_state->irq_ack_notifier);
	vmmr0_free_irq_source_id(pvm, pit->irq_source_id);
	destroy_workqueue(pit->wq);
	kfree(pit);
	return NULL;
}

void vmmr0_free_pit(struct vm *pvm)
{
	struct hrtimer *timer;

	if (pvm->arch.vpit) {
		vmmr0_io_bus_unregister_dev(pvm, KVM_PIO_BUS, &pvm->arch.vpit->dev);
		vmmr0_io_bus_unregister_dev(pvm, KVM_PIO_BUS,
					      &pvm->arch.vpit->speaker_dev);
		vmmr0_unregister_irq_mask_notifier(pvm, 0,
					       &pvm->arch.vpit->mask_notifier);
		vmmr0_unregister_irq_ack_notifier(pvm,
				&pvm->arch.vpit->pit_state.irq_ack_notifier);
		mutex_lock(&pvm->arch.vpit->pit_state.lock);
		timer = &pvm->arch.vpit->pit_state.pit_timer.timer;
		hrtimer_cancel(timer);
		cancel_work_sync(&pvm->arch.vpit->expired);
		vmmr0_free_irq_source_id(pvm, pvm->arch.vpit->irq_source_id);
		mutex_unlock(&pvm->arch.vpit->pit_state.lock);
		destroy_workqueue(pvm->arch.vpit->wq);
		kfree(pvm->arch.vpit);
	}
}
#else
void vmmr0_free_pit(struct vm *pvm){ }
#endif //CONFIG_HAVE_KVM_IRQCHIP
