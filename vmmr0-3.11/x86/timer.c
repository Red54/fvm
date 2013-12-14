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
 * timer.c
 *
 * this code is based on kvm-kmod.
 *
 * authors : 
 *     范文一 （Wincy Van） <fanwenyi0529@live.com> <QQ:362478911>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * From: kvm-kmod-3.4
 */
 
#include "os_interface.h"

#include <linux/vmmr0_host.h>
#include <linux/vmmr0.h>

#include "vmmr0_timer.h"

#ifdef CONFIG_HAVE_KVM_IRQCHIP
enum hrtimer_restart vmmr0_timer_fn(struct hrtimer *data)
{
	struct vmmr0_timer *ktimer = container_of(data, struct vmmr0_timer, timer);
	struct vmmr0_vcpu *vcpu = ktimer->vcpu;

#ifdef HOST_LINUX_OPTIMIZED
	wait_queue_head_t *q = &vcpu->wq;
#endif
	/*
	 * There is a race window between reading and incrementing, but we do
	 * not care about potentially losing timer events in the !reinject
	 * case anyway. Note: KVM_REQ_PENDING_TIMER is implicitly checked
	 * in vcpu_enter_guest.
	 */
	if (ktimer->reinject || !atomic_read(&ktimer->pending)) {
		atomic_inc(&ktimer->pending);
		/* FIXME: this code should not know anything about vcpus */
		vmmr0_make_request(KVM_REQ_PENDING_TIMER, vcpu);
	}

#ifdef HOST_LINUX
	if (waitqueue_active(q))
	{
		wake_up_interruptible(q);
	}
#elif defined(HOST_WINDOWS)
	if(vcpu->blocked)
	{
		KeSetEvent(vcpu->kick_event, IO_NO_INCREMENT, FALSE);
	}
#else
#error invalid host
#endif


	if (ktimer->t_ops->is_periodic(ktimer)) {
		vmmr0_hrtimer_add_expires_ns(&ktimer->timer, ktimer->period);
		return HRTIMER_RESTART;
	} else
		return HRTIMER_NORESTART;
}
#endif
