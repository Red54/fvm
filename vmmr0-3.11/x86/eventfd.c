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
 * eventfd.c
 *
 * this code is based on kvm-kmod.
 *
 * authors : 
 *  范文一 （Wincy Van） <fanwenyi0529@live.com> <QQ:362478911>
 *	Gregory Haskins <ghaskins@novell.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * From: kvm-kmod-3.4
 */
 
 
#include "os_interface.h"

#include <linux/vmmr0_host.h>
#include <linux/vmmr0.h>


#ifdef CONFIG_HAVE_KVM_EVENTFD
#include "iodev.h"

#ifdef HOST_LINUX
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
struct _irqfd {
	/* Used for MSI fast-path */
	struct vm *pvm;
	wait_queue_t wait;
	/* Update side is protected by irqfds.lock */
	struct vmmr0_kernel_irq_routing_entry __rcu *irq_entry;
	/* Used for level IRQ fast-path */
	int gsi;
	struct work_struct inject;
	/* Used for setup/shutdown */
	struct eventfd_ctx *eventfd;
	struct list_head list;
	poll_table pt;
	struct work_struct shutdown;
};

static struct workqueue_struct *irqfd_cleanup_wq;

static void
irqfd_inject(struct work_struct *work)
{
	struct _irqfd *irqfd = container_of(work, struct _irqfd, inject);
	struct vm *pvm = irqfd->pvm;

	vmmr0_set_irq(pvm, KVM_USERSPACE_IRQ_SOURCE_ID, irqfd->gsi, 1);
	vmmr0_set_irq(pvm, KVM_USERSPACE_IRQ_SOURCE_ID, irqfd->gsi, 0);
}

/*
 * Race-free decouple logic (ordering is critical)
 */
static void
irqfd_shutdown(struct work_struct *work)
{
	struct _irqfd *irqfd = container_of(work, struct _irqfd, shutdown);
	u64 cnt;

	/*
	 * Synchronize with the wait-queue and unhook ourselves to prevent
	 * further events.
	 */
	eventfd_ctx_remove_wait_queue(irqfd->eventfd, &irqfd->wait, &cnt);

	/*
	 * We know no new events will be scheduled at this point, so block
	 * until all previously outstanding events have completed
	 */
	flush_work_sync(&irqfd->inject);

	/*
	 * It is now safe to release the object's resources
	 */
	eventfd_ctx_put(irqfd->eventfd);
	kfree(irqfd);
}


static bool
irqfd_is_active(struct _irqfd *irqfd)
{
	return list_empty(&irqfd->list) ? false : true;
}


static void
irqfd_deactivate(struct _irqfd *irqfd)
{
	BUG_ON(!irqfd_is_active(irqfd));

	list_del_init(&irqfd->list);

	queue_work(irqfd_cleanup_wq, &irqfd->shutdown);
}

/*
 * Called with wqh->lock held and interrupts disabled
 */
static int
irqfd_wakeup(wait_queue_t *wait, unsigned mode, int sync, void *key)
{
	struct _irqfd *irqfd = container_of(wait, struct _irqfd, wait);
	unsigned long flags = (unsigned long)key;
	struct vmmr0_kernel_irq_routing_entry *irq;
	struct vm *pvm = irqfd->pvm;

	if (flags & POLLIN) {
		rcu_read_lock();
		irq = rcu_dereference(irqfd->irq_entry);
		/* An event has been signaled, inject an interrupt */
		if (irq)
			vmmr0_set_msi(irq, pvm, KVM_USERSPACE_IRQ_SOURCE_ID, 1);
		else
			schedule_work(&irqfd->inject);
		rcu_read_unlock();
	}

	if (flags & POLLHUP) {
		/* The eventfd is closing, detach from KVM */
		unsigned long flags;

		spin_lock_irqsave(&pvm->irqfds.lock, flags);

		/*
		 * We must check if someone deactivated the irqfd before
		 * we could acquire the irqfds.lock since the item is
		 * deactivated from the KVM side before it is unhooked from
		 * the wait-queue.  If it is already deactivated, we can
		 * simply return knowing the other side will cleanup for us.
		 * We cannot race against the irqfd going away since the
		 * other side is required to acquire wqh->lock, which we hold
		 */
		if (irqfd_is_active(irqfd))
			irqfd_deactivate(irqfd);

		spin_unlock_irqrestore(&pvm->irqfds.lock, flags);
	}

	return 0;
}

static void
irqfd_ptable_queue_proc(struct file *file, wait_queue_head_t *wqh,
			poll_table *pt)
{
	struct _irqfd *irqfd = container_of(pt, struct _irqfd, pt);
	add_wait_queue(wqh, &irqfd->wait);
}

/* Must be called under irqfds.lock */
static void irqfd_update(struct vm *pvm, struct _irqfd *irqfd,
			 struct vmmr0_irq_routing_table *irq_rt)
{
	struct vmmr0_kernel_irq_routing_entry *e;

	if (irqfd->gsi >= irq_rt->nr_rt_entries) {
		rcu_assign_pointer(irqfd->irq_entry, NULL);
		return;
	}

	hlist_for_each_entry(e, &irq_rt->map[irqfd->gsi], link) {
		/* Only fast-path MSI. */
		if (e->type == KVM_IRQ_ROUTING_MSI)
			rcu_assign_pointer(irqfd->irq_entry, e);
		else
			rcu_assign_pointer(irqfd->irq_entry, NULL);
	}
}

static int
vmmr0_irqfd_assign(struct vm *pvm, int fd, int gsi)
{
	struct vmmr0_irq_routing_table *irq_rt;
	struct _irqfd *irqfd, *tmp;
	struct file *file = NULL;
	struct eventfd_ctx *eventfd = NULL;
	int ret;
	unsigned int events;

	irqfd = kzalloc(sizeof(*irqfd), GFP_KERNEL);
	if (!irqfd)
		return -ENOMEM;

	irqfd->pvm = pvm;
	irqfd->gsi = gsi;
	INIT_LIST_HEAD(&irqfd->list);
	INIT_WORK(&irqfd->inject, irqfd_inject);
	INIT_WORK(&irqfd->shutdown, irqfd_shutdown);

	file = eventfd_fget(fd);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto fail;
	}

	eventfd = eventfd_ctx_fileget(file);
	if (IS_ERR(eventfd)) {
		ret = PTR_ERR(eventfd);
		goto fail;
	}

	irqfd->eventfd = eventfd;

	/*
	 * Install our own custom wake-up handling so we are notified via
	 * a callback whenever someone signals the underlying eventfd
	 */
	init_waitqueue_func_entry(&irqfd->wait, irqfd_wakeup);
	init_poll_funcptr(&irqfd->pt, irqfd_ptable_queue_proc);

	spin_lock_irq(&pvm->irqfds.lock);

	ret = 0;
	list_for_each_entry(tmp, &pvm->irqfds.items, list) {
		if (irqfd->eventfd != tmp->eventfd)
			continue;
		/* This fd is used for another irq already. */
		ret = -EBUSY;
		spin_unlock_irq(&pvm->irqfds.lock);
		goto fail;
	}

	irq_rt = rcu_dereference_protected(pvm->irq_routing,
					   lockdep_is_held(&pvm->irqfds.lock));
	irqfd_update(pvm, irqfd, irq_rt);

	events = file->f_op->poll(file, &irqfd->pt);

	list_add_tail(&irqfd->list, &pvm->irqfds.items);

	/*
	 * Check if there was an event already pending on the eventfd
	 * before we registered, and trigger it as if we didn't miss it.
	 */
	if (events & POLLIN)
		schedule_work(&irqfd->inject);

	spin_unlock_irq(&pvm->irqfds.lock);

	/*
	 * do not drop the file until the irqfd is fully initialized, otherwise
	 * we might race against the POLLHUP
	 */
	fput(file);

	return 0;

fail:
	if (eventfd && !IS_ERR(eventfd))
		eventfd_ctx_put(eventfd);

	if (!IS_ERR(file))
		fput(file);

	kfree(irqfd);
	return ret;
}

void
vmmr0_eventfd_init(struct vm *pvm)
{
	spin_lock_init(&pvm->irqfds.lock);
	INIT_LIST_HEAD(&pvm->irqfds.items);
	INIT_LIST_HEAD(&pvm->ioeventfds);
}

/*
 * shutdown any irqfd's that match fd+gsi
 */
static int
vmmr0_irqfd_deassign(struct vm *pvm, int fd, int gsi)
{
	struct _irqfd *irqfd, *tmp;
	struct eventfd_ctx *eventfd;

	eventfd = eventfd_ctx_fdget(fd);
	if (IS_ERR(eventfd))
		return PTR_ERR(eventfd);

	spin_lock_irq(&pvm->irqfds.lock);

	list_for_each_entry_safe(irqfd, tmp, &pvm->irqfds.items, list) {
		if (irqfd->eventfd == eventfd && irqfd->gsi == gsi) {
			/*
			 * This rcu_assign_pointer is needed for when
			 * another thread calls vmmr0_irq_routing_update before
			 * we flush workqueue below (we synchronize with
			 * vmmr0_irq_routing_update using irqfds.lock).
			 * It is paired with synchronize_rcu done by caller
			 * of that function.
			 */
			rcu_assign_pointer(irqfd->irq_entry, NULL);
			irqfd_deactivate(irqfd);
		}
	}

	spin_unlock_irq(&pvm->irqfds.lock);
	eventfd_ctx_put(eventfd);

	/*
	 * Block until we know all outstanding shutdown jobs have completed
	 * so that we guarantee there will not be any more interrupts on this
	 * gsi once this deassign function returns.
	 */
	flush_workqueue(irqfd_cleanup_wq);

	return 0;
}

int
vmmr0_irqfd(struct vm *pvm, int fd, int gsi, int flags)
{
	if (flags & KVM_IRQFD_FLAG_DEASSIGN)
		return vmmr0_irqfd_deassign(pvm, fd, gsi);

	return vmmr0_irqfd_assign(pvm, fd, gsi);
}

/*
 * This function is called as the pvm VM fd is being released. Shutdown all
 * irqfds that still remain open
 */
void
vmmr0_irqfd_release(struct vm *pvm)
{
	struct _irqfd *irqfd, *tmp;

	spin_lock_irq(&pvm->irqfds.lock);

	list_for_each_entry_safe(irqfd, tmp, &pvm->irqfds.items, list)
		irqfd_deactivate(irqfd);

	spin_unlock_irq(&pvm->irqfds.lock);

	flush_workqueue(irqfd_cleanup_wq);

}

/*
 * Change irq_routing and irqfd.
 * Caller must invoke synchronize_rcu afterwards.
 */
void vmmr0_irq_routing_update(struct vm *pvm,
			    struct vmmr0_irq_routing_table *irq_rt)
{
	struct _irqfd *irqfd;

	spin_lock_irq(&pvm->irqfds.lock);

	rcu_assign_pointer(pvm->irq_routing, irq_rt);

	list_for_each_entry(irqfd, &pvm->irqfds.items, list)
		irqfd_update(pvm, irqfd, irq_rt);

	spin_unlock_irq(&pvm->irqfds.lock);
}

/*
 * create a host-wide workqueue for issuing deferred shutdown requests
 * aggregated from all vm* instances. We need our own isolated single-thread
 * queue to prevent deadlock against flushing the normal work-queue.
 */
int __init irqfd_module_init(void)
{
	irqfd_cleanup_wq = create_singlethread_workqueue("pvm-irqfd-cleanup");
	if (!irqfd_cleanup_wq)
		return -ENOMEM;

	return 0;
}

void __exit irqfd_module_exit(void)
{
	destroy_workqueue(irqfd_cleanup_wq);
}


/*
 * --------------------------------------------------------------------
 * ioeventfd: translate a PIO/MMIO memory write to an eventfd signal.
 *
 * userspace can register a PIO/MMIO address with an eventfd for receiving
 * notification when the memory has been touched.
 * --------------------------------------------------------------------
 */

struct _ioeventfd {
	struct list_head     list;
	u64                  addr;
	int                  length;
	struct eventfd_ctx  *eventfd;
	u64                  datamatch;
	struct vmmr0_io_device dev;
	bool                 wildcard;
};

static inline struct _ioeventfd *
to_ioeventfd(struct vmmr0_io_device *dev)
{
	return container_of(dev, struct _ioeventfd, dev);
}

static void
ioeventfd_release(struct _ioeventfd *p)
{
	eventfd_ctx_put(p->eventfd);
	list_del(&p->list);
	kfree(p);
}

static bool
ioeventfd_in_range(struct _ioeventfd *p, gpa_t addr, int len, const void *val)
{
	u64 _val;

	if (!(addr == p->addr && len == p->length))
		/* address-range must be precise for a hit */
		return false;

	if (p->wildcard)
		/* all else equal, wildcard is always a hit */
		return true;

	/* otherwise, we have to actually compare the data */

	BUG_ON(!IS_ALIGNED((unsigned long)val, len));

	switch (len) {
	case 1:
		_val = *(u8 *)val;
		break;
	case 2:
		_val = *(u16 *)val;
		break;
	case 4:
		_val = *(u32 *)val;
		break;
	case 8:
		_val = *(u64 *)val;
		break;
	default:
		return false;
	}

	return _val == p->datamatch ? true : false;
}

/* MMIO/PIO writes trigger an event if the addr/val match */
static int
ioeventfd_write(struct vmmr0_io_device *this, gpa_t addr, int len,
		const void *val)
{
	struct _ioeventfd *p = to_ioeventfd(this);

	if (!ioeventfd_in_range(p, addr, len, val))
		return -EOPNOTSUPP;

	eventfd_signal(p->eventfd, 1);
	return 0;
}

/*
 * This function is called as KVM is completely shutting down.  We do not
 * need to worry about locking just nuke anything we have as quickly as possible
 */
static void
ioeventfd_destructor(struct vmmr0_io_device *this)
{
	struct _ioeventfd *p = to_ioeventfd(this);

	ioeventfd_release(p);
}

static const struct vmmr0_io_device_ops ioeventfd_ops = {
	.write      = ioeventfd_write,
	.destructor = ioeventfd_destructor,
};

static bool
ioeventfd_check_collision(struct vm *pvm, struct _ioeventfd *p)
{
	struct _ioeventfd *_p;

	list_for_each_entry(_p, &pvm->ioeventfds, list)
		if (_p->addr == p->addr && _p->length == p->length &&
		    (_p->wildcard || p->wildcard ||
		     _p->datamatch == p->datamatch))
			return true;

	return false;
}

static int
vmmr0_assign_ioeventfd(struct vm *pvm, struct vmmr0_ioeventfd *args)
{
	int                       pio = args->flags & KVM_IOEVENTFD_FLAG_PIO;
	enum vmmr0_bus              bus_idx = pio ? KVM_PIO_BUS : KVM_MMIO_BUS;
	struct _ioeventfd        *p;
	struct eventfd_ctx       *eventfd;
	int                       ret;

	/* must be natural-word sized */
	switch (args->len) {
	case 1:
	case 2:
	case 4:
	case 8:
		break;
	default:
		return -EINVAL;
	}

	/* check for range overflow */
	if (args->addr + args->len < args->addr)
		return -EINVAL;

	/* check for extra flags that we don't understand */
	if (args->flags & ~KVM_IOEVENTFD_VALID_FLAG_MASK)
		return -EINVAL;

	eventfd = eventfd_ctx_fdget(args->fd);
	if (IS_ERR(eventfd))
		return PTR_ERR(eventfd);

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p) {
		ret = -ENOMEM;
		goto fail;
	}

	INIT_LIST_HEAD(&p->list);
	p->addr    = args->addr;
	p->length  = args->len;
	p->eventfd = eventfd;

	/* The datamatch feature is optional, otherwise this is a wildcard */
	if (args->flags & KVM_IOEVENTFD_FLAG_DATAMATCH)
		p->datamatch = args->datamatch;
	else
		p->wildcard = true;

	mutex_lock(&pvm->slots_lock);

	/* Verify that there isn't a match already */
	if (ioeventfd_check_collision(pvm, p)) {
		ret = -EEXIST;
		goto unlock_fail;
	}

	vmmr0_iodevice_init(&p->dev, &ioeventfd_ops);

	ret = vmmr0_io_bus_register_dev(pvm, bus_idx, p->addr, p->length,
				      &p->dev);
	if (ret < 0)
		goto unlock_fail;

	list_add_tail(&p->list, &pvm->ioeventfds);

	mutex_unlock(&pvm->slots_lock);

	return 0;

unlock_fail:
	mutex_unlock(&pvm->slots_lock);

fail:
	kfree(p);
	eventfd_ctx_put(eventfd);

	return ret;
}

static int
vmmr0_deassign_ioeventfd(struct vm *pvm, struct vmmr0_ioeventfd *args)
{
	int                       pio = args->flags & KVM_IOEVENTFD_FLAG_PIO;
	enum vmmr0_bus              bus_idx = pio ? KVM_PIO_BUS : KVM_MMIO_BUS;
	struct _ioeventfd        *p, *tmp;
	struct eventfd_ctx       *eventfd;
	int                       ret = -ENOENT;

	eventfd = eventfd_ctx_fdget(args->fd);
	if (IS_ERR(eventfd))
		return PTR_ERR(eventfd);

	mutex_lock(&pvm->slots_lock);

	list_for_each_entry_safe(p, tmp, &pvm->ioeventfds, list) {
		bool wildcard = !(args->flags & KVM_IOEVENTFD_FLAG_DATAMATCH);

		if (p->eventfd != eventfd  ||
		    p->addr != args->addr  ||
		    p->length != args->len ||
		    p->wildcard != wildcard)
			continue;

		if (!p->wildcard && p->datamatch != args->datamatch)
			continue;

		vmmr0_io_bus_unregister_dev(pvm, bus_idx, &p->dev);
		ioeventfd_release(p);
		ret = 0;
		break;
	}

	mutex_unlock(&pvm->slots_lock);

	eventfd_ctx_put(eventfd);

	return ret;
}

int
vmmr0_ioeventfd(struct vm *pvm, struct vmmr0_ioeventfd *args)
{
	if (args->flags & KVM_IOEVENTFD_FLAG_DEASSIGN)
		return vmmr0_deassign_ioeventfd(pvm, args);

	return vmmr0_assign_ioeventfd(pvm, args);
}
#else
void vmmr0_eventfd_init(struct vm *pvm) { }
void vmmr0_irqfd_release(struct vm *pvm) { }
void vmmr0_irq_routing_update(struct vm *pvm,
                            struct vmmr0_irq_routing_table *irq_rt)
{
	rcu_assign_pointer(pvm->irq_routing, irq_rt);
}
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
#else
void vmmr0_eventfd_init(struct vm *pvm) { }
void vmmr0_irqfd_release(struct vm *pvm) { }
void vmmr0_irq_routing_update(struct vm *pvm,
                            struct vmmr0_irq_routing_table *irq_rt)
{
	rcu_assign_pointer(pvm->irq_routing, irq_rt);
}
int irqfd_module_init(void)
{
	return 0;
}

void __exit irqfd_module_exit(void)
{
}
#endif //HOST_LINUX
#endif //CONFIG_HAVE_KVM_EVENTFD
