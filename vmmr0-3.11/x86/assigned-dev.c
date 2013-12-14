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
 * assigned-dev.c
 *
 * this code is based on kvm-kmod.
 *
 * author : Wincy Van <fanwenyi0529@live.com> <QQ:362478911>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * From: kvm-kmod-3.4
 */
 
 
#include "os_interface.h"

#include <linux/vmmr0_host.h>
#include <linux/vmmr0.h>

#ifdef CONFIG_HAVE_ASSIGNED_DEV

#include "irq.h"

static struct vmmr0_assigned_dev_kernel *vmmr0_find_assigned_dev(struct list_head *head,
						      int assigned_dev_id)
{
	struct list_head *ptr;
	struct vmmr0_assigned_dev_kernel *match;

	list_for_each(ptr, head) {
		match = list_entry(ptr, struct vmmr0_assigned_dev_kernel, list);
		if (match->assigned_dev_id == assigned_dev_id)
			return match;
	}
	return NULL;
}

#ifdef HOST_LINUX

static int find_index_from_host_irq(struct vmmr0_assigned_dev_kernel
				    *assigned_dev, int irq)
{
	int i, index;
	struct msix_entry *host_msix_entries;

	host_msix_entries = assigned_dev->host_msix_entries;

	index = -1;
	for (i = 0; i < assigned_dev->entries_nr; i++)
		if (irq == host_msix_entries[i].vector) {
			index = i;
			break;
		}
	if (index < 0)
		printk(KERN_WARNING "Fail to find correlated MSI-X entry!\n");

	return index;
}

static irqreturn_t vmmr0_assigned_dev_intx(int irq, void *dev_id)
{
	struct vmmr0_assigned_dev_kernel *assigned_dev = dev_id;
	int ret;

	spin_lock(&assigned_dev->intx_lock);
	if (pci_check_and_mask_intx(assigned_dev->dev)) {
		assigned_dev->host_irq_disabled = true;
		ret = IRQ_WAKE_THREAD;
	} else
		ret = IRQ_NONE;
	spin_unlock(&assigned_dev->intx_lock);

	return ret;
}

static void
vmmr0_assigned_dev_raise_guest_irq(struct vmmr0_assigned_dev_kernel *assigned_dev,
				 int vector)
{
	if (unlikely(assigned_dev->irq_requested_type &
		     KVM_DEV_IRQ_GUEST_INTX)) {
		spin_lock(&assigned_dev->intx_mask_lock);
		if (!(assigned_dev->flags & KVM_DEV_ASSIGN_MASK_INTX))
			vmmr0_set_irq(assigned_dev->pvm,
				    assigned_dev->irq_source_id, vector, 1);
		spin_unlock(&assigned_dev->intx_mask_lock);
	} else
		vmmr0_set_irq(assigned_dev->pvm, assigned_dev->irq_source_id,
			    vector, 1);
}

static irqreturn_t vmmr0_assigned_dev_thread_intx(int irq, void *dev_id)
{
	struct vmmr0_assigned_dev_kernel *assigned_dev = dev_id;

	if (!(assigned_dev->flags & KVM_DEV_ASSIGN_PCI_2_3)) {
		spin_lock_irq(&assigned_dev->intx_lock);
		disable_irq_nosync(irq);
		assigned_dev->host_irq_disabled = true;
		spin_unlock_irq(&assigned_dev->intx_lock);
	}

	vmmr0_assigned_dev_raise_guest_irq(assigned_dev,
					 assigned_dev->guest_irq);

	return IRQ_HANDLED;
}
#endif //HOST_LINUX

#ifdef __KVM_HAVE_MSI
static irqreturn_t vmmr0_assigned_dev_thread_msi(int irq, void *dev_id)
{
	struct vmmr0_assigned_dev_kernel *assigned_dev = dev_id;

	vmmr0_assigned_dev_raise_guest_irq(assigned_dev,
					 assigned_dev->guest_irq);

	return IRQ_HANDLED;
}
#endif

#ifdef __KVM_HAVE_MSIX
static irqreturn_t vmmr0_assigned_dev_thread_msix(int irq, void *dev_id)
{
	struct vmmr0_assigned_dev_kernel *assigned_dev = dev_id;
	int index = find_index_from_host_irq(assigned_dev, irq);
	u32 vector;

	if (index >= 0) {
		vector = assigned_dev->guest_msix_entries[index].vector;
		vmmr0_assigned_dev_raise_guest_irq(assigned_dev, vector);
	}

	return IRQ_HANDLED;
}
#endif

#ifdef HOST_LINUX
/* Ack the irq line for an assigned device */
static void vmmr0_assigned_dev_ack_irq(struct vmmr0_irq_ack_notifier *kian)
{
	struct vmmr0_assigned_dev_kernel *dev =
		container_of(kian, struct vmmr0_assigned_dev_kernel,
			     ack_notifier);

	vmmr0_set_irq(dev->pvm, dev->irq_source_id, dev->guest_irq, 0);

	spin_lock(&dev->intx_mask_lock);

	if (!(dev->flags & KVM_DEV_ASSIGN_MASK_INTX)) {
		bool reassert = false;

		spin_lock_irq(&dev->intx_lock);
		/*
		 * The guest IRQ may be shared so this ack can come from an
		 * IRQ for another guest device.
		 */
		if (dev->host_irq_disabled) {
			if (!(dev->flags & KVM_DEV_ASSIGN_PCI_2_3))
				enable_irq(dev->host_irq);
			else if (!pci_check_and_unmask_intx(dev->dev))
				reassert = true;
			dev->host_irq_disabled = reassert;
		}
		spin_unlock_irq(&dev->intx_lock);

		if (reassert)
			vmmr0_set_irq(dev->pvm, dev->irq_source_id,
				    dev->guest_irq, 1);
	}

	spin_unlock(&dev->intx_mask_lock);
}

static void deassign_guest_irq(struct vm *pvm,
			       struct vmmr0_assigned_dev_kernel *assigned_dev)
{
	if (assigned_dev->ack_notifier.gsi != -1)
		vmmr0_unregister_irq_ack_notifier(pvm,
						&assigned_dev->ack_notifier);

	vmmr0_set_irq(assigned_dev->pvm, assigned_dev->irq_source_id,
		    assigned_dev->guest_irq, 0);

	if (assigned_dev->irq_source_id != -1)
		vmmr0_free_irq_source_id(pvm, assigned_dev->irq_source_id);
	assigned_dev->irq_source_id = -1;
	assigned_dev->irq_requested_type &= ~(KVM_DEV_IRQ_GUEST_MASK);
}

/* The function implicit hold pvm->lock mutex due to cancel_work_sync() */
static void deassign_host_irq(struct vm *pvm,
			      struct vmmr0_assigned_dev_kernel *assigned_dev)
{
	/*
	 * We disable irq here to prevent further events.
	 *
	 * Notice this maybe result in nested disable if the interrupt type is
	 * INTx, but it's OK for we are going to free it.
	 *
	 * If this function is a part of VM destroy, please ensure that till
	 * now, the pvm state is still legal for probably we also have to wait
	 * on a currently running IRQ handler.
	 */
	if (assigned_dev->irq_requested_type & KVM_DEV_IRQ_HOST_MSIX) {
		int i;
		for (i = 0; i < assigned_dev->entries_nr; i++)
			disable_irq(assigned_dev->host_msix_entries[i].vector);

		for (i = 0; i < assigned_dev->entries_nr; i++)
			free_irq(assigned_dev->host_msix_entries[i].vector,
				 assigned_dev);

		assigned_dev->entries_nr = 0;
		kfree(assigned_dev->host_msix_entries);
		kfree(assigned_dev->guest_msix_entries);
		pci_disable_msix(assigned_dev->dev);
	} else {
		/* Deal with MSI and INTx */
		if ((assigned_dev->irq_requested_type &
		     KVM_DEV_IRQ_HOST_INTX) &&
		    (assigned_dev->flags & KVM_DEV_ASSIGN_PCI_2_3)) {
			spin_lock_irq(&assigned_dev->intx_lock);
			pci_intx(assigned_dev->dev, false);
			spin_unlock_irq(&assigned_dev->intx_lock);
			synchronize_irq(assigned_dev->host_irq);
		} else
			disable_irq(assigned_dev->host_irq);

		free_irq(assigned_dev->host_irq, assigned_dev);

		if (assigned_dev->irq_requested_type & KVM_DEV_IRQ_HOST_MSI)
			pci_disable_msi(assigned_dev->dev);
	}

	assigned_dev->irq_requested_type &= ~(KVM_DEV_IRQ_HOST_MASK);
}

static int vmmr0_deassign_irq(struct vm *pvm,
			    struct vmmr0_assigned_dev_kernel *assigned_dev,
			    unsigned long irq_requested_type)
{
	unsigned long guest_irq_type, host_irq_type;

	if (!irqchip_in_kernel(pvm))
		return -EINVAL;
	/* no irq assignment to deassign */
	if (!assigned_dev->irq_requested_type)
		return -ENXIO;

	host_irq_type = irq_requested_type & KVM_DEV_IRQ_HOST_MASK;
	guest_irq_type = irq_requested_type & KVM_DEV_IRQ_GUEST_MASK;

	if (host_irq_type)
		deassign_host_irq(pvm, assigned_dev);
	if (guest_irq_type)
		deassign_guest_irq(pvm, assigned_dev);

	return 0;
}

static void vmmr0_free_assigned_irq(struct vm *pvm,
				  struct vmmr0_assigned_dev_kernel *assigned_dev)
{
	vmmr0_deassign_irq(pvm, assigned_dev, assigned_dev->irq_requested_type);
}

static void vmmr0_free_assigned_device(struct vm *pvm,
				     struct vmmr0_assigned_dev_kernel
				     *assigned_dev)
{
	vmmr0_free_assigned_irq(pvm, assigned_dev);

	pci_reset_function(assigned_dev->dev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
	if (pci_load_and_free_saved_state(assigned_dev->dev,
					  &assigned_dev->pci_saved_state))
		printk(KERN_INFO "%s: Couldn't reload %s saved state\n",
		       __func__, dev_name(&assigned_dev->dev->dev));
	else
		pci_restore_state(assigned_dev->dev);
#endif

	assigned_dev->dev->dev_flags &= ~PCI_DEV_FLAGS_ASSIGNED;

	pci_release_regions(assigned_dev->dev);
	pci_disable_device(assigned_dev->dev);
	pci_dev_put(assigned_dev->dev);

	list_del(&assigned_dev->list);
	kfree(assigned_dev);
}

void vmmr0_free_all_assigned_devices(struct vm *pvm)
{
	struct list_head *ptr, *ptr2;
	struct vmmr0_assigned_dev_kernel *assigned_dev;

	list_for_each_safe(ptr, ptr2, &pvm->arch.assigned_dev_head) {
		assigned_dev = list_entry(ptr,
					  struct vmmr0_assigned_dev_kernel,
					  list);

		vmmr0_free_assigned_device(pvm, assigned_dev);
	}
}

static int assigned_device_enable_host_intx(struct vm *pvm,
					    struct vmmr0_assigned_dev_kernel *dev)
{
	irq_handler_t irq_handler;
	unsigned long flags;

	dev->host_irq = dev->dev->irq;

	/*
	 * We can only share the IRQ line with other host devices if we are
	 * able to disable the IRQ source at device-level - independently of
	 * the guest driver. Otherwise host devices may suffer from unbounded
	 * IRQ latencies when the guest keeps the line asserted.
	 */
	if (dev->flags & KVM_DEV_ASSIGN_PCI_2_3) {
		irq_handler = vmmr0_assigned_dev_intx;
		flags = IRQF_SHARED;
	} else {
		irq_handler = NULL;
		flags = IRQF_ONESHOT;
	}
	if (vmmr0_request_threaded_irq(dev->host_irq, irq_handler,
				 vmmr0_assigned_dev_thread_intx, flags,
				 dev->irq_name, dev))
		return -EIO;

	if (dev->flags & KVM_DEV_ASSIGN_PCI_2_3) {
		spin_lock_irq(&dev->intx_lock);
		pci_intx(dev->dev, true);
		spin_unlock_irq(&dev->intx_lock);
	}
	return 0;
}
#endif //HOST_LINUX


#ifdef __KVM_HAVE_MSI
static int assigned_device_enable_host_msi(struct vm *pvm,
					   struct vmmr0_assigned_dev_kernel *dev)
{
	int r;

	if (!dev->dev->msi_enabled) {
		r = pci_enable_msi(dev->dev);
		if (r)
			return r;
	}

	dev->host_irq = dev->dev->irq;
	if (vmmr0_request_threaded_irq(dev->host_irq, NULL,
				 vmmr0_assigned_dev_thread_msi, 0,
				 dev->irq_name, dev)) {
		pci_disable_msi(dev->dev);
		return -EIO;
	}

	return 0;
}
#endif

#ifdef __KVM_HAVE_MSIX
static int assigned_device_enable_host_msix(struct vm *pvm,
					    struct vmmr0_assigned_dev_kernel *dev)
{
	int i, r = -EINVAL;

	/* host_msix_entries and guest_msix_entries should have been
	 * initialized */
	if (dev->entries_nr == 0)
		return r;

	r = pci_enable_msix(dev->dev, dev->host_msix_entries, dev->entries_nr);
	if (r)
		return r;

	for (i = 0; i < dev->entries_nr; i++) {
		r = vmmr0_request_threaded_irq(dev->host_msix_entries[i].vector,
					 NULL, vmmr0_assigned_dev_thread_msix,
					 0, dev->irq_name, dev);
		if (r)
			goto err;
	}

	return 0;
err:
	for (i -= 1; i >= 0; i--)
		free_irq(dev->host_msix_entries[i].vector, dev);
	pci_disable_msix(dev->dev);
	return r;
}

#endif

#ifdef HOST_LINUX
static int assigned_device_enable_guest_intx(struct vm *pvm,
				struct vmmr0_assigned_dev_kernel *dev,
				struct vmmr0_assigned_irq *irq)
{
	dev->guest_irq = irq->guest_irq;
	dev->ack_notifier.gsi = irq->guest_irq;
	return 0;
}
#endif //HOST_LINUX

#ifdef __KVM_HAVE_MSI
static int assigned_device_enable_guest_msi(struct vm *pvm,
			struct vmmr0_assigned_dev_kernel *dev,
			struct vmmr0_assigned_irq *irq)
{
	dev->guest_irq = irq->guest_irq;
	dev->ack_notifier.gsi = -1;
	return 0;
}
#endif

#ifdef __KVM_HAVE_MSIX
static int assigned_device_enable_guest_msix(struct vm *pvm,
			struct vmmr0_assigned_dev_kernel *dev,
			struct vmmr0_assigned_irq *irq)
{
	dev->guest_irq = irq->guest_irq;
	dev->ack_notifier.gsi = -1;
	return 0;
}
#endif

#ifdef HOST_LINUX
static int assign_host_irq(struct vm *pvm,
			   struct vmmr0_assigned_dev_kernel *dev,
			   __u32 host_irq_type)
{
	int r = -EEXIST;

	if (dev->irq_requested_type & KVM_DEV_IRQ_HOST_MASK)
		return r;

	snprintf(dev->irq_name, sizeof(dev->irq_name), "vmmr0:%s",
		 pci_name(dev->dev));

	switch (host_irq_type) {
	case KVM_DEV_IRQ_HOST_INTX:
		r = assigned_device_enable_host_intx(pvm, dev);
		break;
#ifdef __KVM_HAVE_MSI
	case KVM_DEV_IRQ_HOST_MSI:
		r = assigned_device_enable_host_msi(pvm, dev);
		break;
#endif
#ifdef __KVM_HAVE_MSIX
	case KVM_DEV_IRQ_HOST_MSIX:
		r = assigned_device_enable_host_msix(pvm, dev);
		break;
#endif
	default:
		r = -EINVAL;
	}
	dev->host_irq_disabled = false;

	if (!r)
		dev->irq_requested_type |= host_irq_type;

	return r;
}

static int assign_guest_irq(struct vm *pvm,
			    struct vmmr0_assigned_dev_kernel *dev,
			    struct vmmr0_assigned_irq *irq,
			    unsigned long guest_irq_type)
{
	int id;
	int r = -EEXIST;

	if (dev->irq_requested_type & KVM_DEV_IRQ_GUEST_MASK)
		return r;

	id = vmmr0_request_irq_source_id(pvm);
	if (id < 0)
		return id;

	dev->irq_source_id = id;

	switch (guest_irq_type) {
	case KVM_DEV_IRQ_GUEST_INTX:
		r = assigned_device_enable_guest_intx(pvm, dev, irq);
		break;
#ifdef __KVM_HAVE_MSI
	case KVM_DEV_IRQ_GUEST_MSI:
		r = assigned_device_enable_guest_msi(pvm, dev, irq);
		break;
#endif
#ifdef __KVM_HAVE_MSIX
	case KVM_DEV_IRQ_GUEST_MSIX:
		r = assigned_device_enable_guest_msix(pvm, dev, irq);
		break;
#endif
	default:
		r = -EINVAL;
	}

	if (!r) {
		dev->irq_requested_type |= guest_irq_type;
		if (dev->ack_notifier.gsi != -1)
			vmmr0_register_irq_ack_notifier(pvm, &dev->ack_notifier);
	} else
		vmmr0_free_irq_source_id(pvm, dev->irq_source_id);

	return r;
}

/* TODO Deal with KVM_DEV_IRQ_ASSIGNED_MASK_MSIX */
static int vmmr0_vm_ioctl_assign_irq(struct vm *pvm,
				   struct vmmr0_assigned_irq *assigned_irq)
{
	int r = -EINVAL;
	struct vmmr0_assigned_dev_kernel *match;
	unsigned long host_irq_type, guest_irq_type;

	if (!irqchip_in_kernel(pvm))
		return r;

	mutex_lock(&pvm->lock);
	r = -ENODEV;
	match = vmmr0_find_assigned_dev(&pvm->arch.assigned_dev_head,
				      assigned_irq->assigned_dev_id);
	if (!match)
		goto out;

	host_irq_type = (assigned_irq->flags & KVM_DEV_IRQ_HOST_MASK);
	guest_irq_type = (assigned_irq->flags & KVM_DEV_IRQ_GUEST_MASK);

	r = -EINVAL;
	/* can only assign one type at a time */
	if (hweight_long(host_irq_type) > 1)
		goto out;
	if (hweight_long(guest_irq_type) > 1)
		goto out;
	if (host_irq_type == 0 && guest_irq_type == 0)
		goto out;

	r = 0;
	if (host_irq_type)
		r = assign_host_irq(pvm, match, host_irq_type);
	if (r)
		goto out;

	if (guest_irq_type)
		r = assign_guest_irq(pvm, match, assigned_irq, guest_irq_type);
out:
	mutex_unlock(&pvm->lock);
	return r;
}

static int vmmr0_vm_ioctl_deassign_dev_irq(struct vm *pvm,
					 struct vmmr0_assigned_irq
					 *assigned_irq)
{
	int r = -ENODEV;
	struct vmmr0_assigned_dev_kernel *match;
	unsigned long irq_type;

	mutex_lock(&pvm->lock);

	match = vmmr0_find_assigned_dev(&pvm->arch.assigned_dev_head,
				      assigned_irq->assigned_dev_id);
	if (!match)
		goto out;

	irq_type = assigned_irq->flags & (KVM_DEV_IRQ_HOST_MASK |
					  KVM_DEV_IRQ_GUEST_MASK);
	r = vmmr0_deassign_irq(pvm, match, irq_type);
out:
	mutex_unlock(&pvm->lock);
	return r;
}
#endif //HOST_LINUX

/*
 * We want to test whether the caller has been granted permissions to
 * use this device.  To be able to configure and control the device,
 * the user needs access to PCI configuration space and BAR resources.
 * These are accessed through PCI sysfs.  PCI config space is often
 * passed to the process calling this ioctl via file descriptor, so we
 * can't rely on access to that file.  We can check for permissions
 * on each of the BAR resource files, which is a pretty clear
 * indicator that the user has been granted access to the device.
 */
static int probe_sysfs_permissions(struct pci_dev *dev)
{
#ifdef CONFIG_SYSFS
	int i;
	bool bar_found = false;

	for (i = PCI_STD_RESOURCES; i <= PCI_STD_RESOURCE_END; i++) {
		char *kpath, *syspath;
		struct path path;
		struct inode *inode;
		int r;

		if (!pci_resource_len(dev, i))
			continue;

		kpath = kobject_get_path(&dev->dev.kobj, GFP_KERNEL);
		if (!kpath)
			return -ENOMEM;

		/* Per sysfs-rules, sysfs is always at /sys */
		syspath = kasprintf(GFP_KERNEL, "/sys%s/resource%d", kpath, i);
		kfree(kpath);
		if (!syspath)
			return -ENOMEM;

		r = vmmr0_kern_path(syspath, LOOKUP_FOLLOW, &path);
		kfree(syspath);
		if (r)
			return r;

		inode = path.dentry->d_inode;

		r = vmmr0_inode_permission(inode, MAY_READ | MAY_WRITE | MAY_ACCESS);
		vmmr0_path_put(&path);
		if (r)
			return r;

		bar_found = true;
	}

	/* If no resources, probably something special */
	if (!bar_found)
		return -EPERM;

	return 0;
#else
	return -EINVAL; /* No way to control the device without sysfs */
#endif
}

#ifdef HOST_LINUX
static int vmmr0_vm_ioctl_assign_device(struct vm *pvm,
				      struct vmmr0_assigned_pci_dev *assigned_dev)
{
	int r = 0, idx;
	struct vmmr0_assigned_dev_kernel *match;
	struct pci_dev *dev;
	u8 header_type;

	if (!(assigned_dev->flags & KVM_DEV_ASSIGN_ENABLE_IOMMU))
		return -EINVAL;

	mutex_lock(&pvm->lock);
	idx = srcu_read_lock(&pvm->srcu);

	match = vmmr0_find_assigned_dev(&pvm->arch.assigned_dev_head,
				      assigned_dev->assigned_dev_id);
	if (match) {
		/* device already assigned */
		r = -EEXIST;
		goto out;
	}

	match = kzalloc(sizeof(struct vmmr0_assigned_dev_kernel), GFP_KERNEL);
	if (match == NULL) {
		printk(KERN_INFO "%s: Couldn't allocate memory\n",
		       __func__);
		r = -ENOMEM;
		goto out;
	}
	dev = pci_get_domain_bus_and_slot(assigned_dev->segnr,
				   assigned_dev->busnr,
				   assigned_dev->devfn);
	if (!dev) {
		printk(KERN_INFO "%s: host device not found\n", __func__);
		r = -EINVAL;
		goto out_free;
	}

	/* Don't allow bridges to be assigned */
	pci_read_config_byte(dev, PCI_HEADER_TYPE, &header_type);
	if ((header_type & PCI_HEADER_TYPE) != PCI_HEADER_TYPE_NORMAL) {
		r = -EPERM;
		goto out_put;
	}

	r = probe_sysfs_permissions(dev);
	if (r)
		goto out_put;

	if (pci_enable_device(dev)) {
		printk(KERN_INFO "%s: Could not enable PCI device\n", __func__);
		r = -EBUSY;
		goto out_put;
	}
	r = pci_request_regions(dev, "vmmr0_assigned_device");
	if (r) {
		printk(KERN_INFO "%s: Could not get access to device regions\n",
		       __func__);
		goto out_disable;
	}

	pci_reset_function(dev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
	pci_save_state(dev);
	match->pci_saved_state = pci_store_saved_state(dev);
	if (!match->pci_saved_state)
		printk(KERN_DEBUG "%s: Couldn't store %s saved state\n",
		       __func__, dev_name(&dev->dev));
#endif

	if (!pci_intx_mask_supported(dev))
		assigned_dev->flags &= ~KVM_DEV_ASSIGN_PCI_2_3;

	match->assigned_dev_id = assigned_dev->assigned_dev_id;
	match->host_segnr = assigned_dev->segnr;
	match->host_busnr = assigned_dev->busnr;
	match->host_devfn = assigned_dev->devfn;
	match->flags = assigned_dev->flags;
	match->dev = dev;
	spin_lock_init(&match->intx_lock);
	spin_lock_init(&match->intx_mask_lock);
	match->irq_source_id = -1;
	match->pvm = pvm;
	match->ack_notifier.irq_acked = vmmr0_assigned_dev_ack_irq;

	list_add(&match->list, &pvm->arch.assigned_dev_head);

	if (!pvm->arch.iommu_domain) {
		r = vmmr0_iommu_map_guest(pvm);
		if (r)
			goto out_list_del;
	}
	r = vmmr0_assign_device(pvm, match);
	if (r)
		goto out_list_del;

out:
	srcu_read_unlock(&pvm->srcu, idx);
	mutex_unlock(&pvm->lock);
	return r;
out_list_del:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
	if (pci_load_and_free_saved_state(dev, &match->pci_saved_state))
		printk(KERN_INFO "%s: Couldn't reload %s saved state\n",
		       __func__, dev_name(&dev->dev));
#endif
	list_del(&match->list);
	pci_release_regions(dev);
out_disable:
	pci_disable_device(dev);
out_put:
	pci_dev_put(dev);
out_free:
	kfree(match);
	srcu_read_unlock(&pvm->srcu, idx);
	mutex_unlock(&pvm->lock);
	return r;
}

static int vmmr0_vm_ioctl_deassign_device(struct vm *pvm,
		struct vmmr0_assigned_pci_dev *assigned_dev)
{
	int r = 0;
	struct vmmr0_assigned_dev_kernel *match;

	mutex_lock(&pvm->lock);

	match = vmmr0_find_assigned_dev(&pvm->arch.assigned_dev_head,
				      assigned_dev->assigned_dev_id);
	if (!match) {
		printk(KERN_INFO "%s: device hasn't been assigned before, "
		  "so cannot be deassigned\n", __func__);
		r = -EINVAL;
		goto out;
	}

	vmmr0_deassign_device(pvm, match);

	vmmr0_free_assigned_device(pvm, match);

out:
	mutex_unlock(&pvm->lock);
	return r;
}
#endif //HOST_LINUX

#ifdef __KVM_HAVE_MSIX
static int vmmr0_vm_ioctl_set_msix_nr(struct vm *pvm,
				    struct vmmr0_assigned_msix_nr *entry_nr)
{
	int r = 0;
	struct vmmr0_assigned_dev_kernel *adev;

	mutex_lock(&pvm->lock);

	adev = vmmr0_find_assigned_dev(&pvm->arch.assigned_dev_head,
				      entry_nr->assigned_dev_id);
	if (!adev) {
		r = -EINVAL;
		goto msix_nr_out;
	}

	if (adev->entries_nr == 0) {
		adev->entries_nr = entry_nr->entry_nr;
		if (adev->entries_nr == 0 ||
		    adev->entries_nr > KVM_MAX_MSIX_PER_DEV) {
			r = -EINVAL;
			goto msix_nr_out;
		}

		adev->host_msix_entries = kzalloc(sizeof(struct msix_entry) *
						entry_nr->entry_nr,
						GFP_KERNEL);
		if (!adev->host_msix_entries) {
			r = -ENOMEM;
			goto msix_nr_out;
		}
		adev->guest_msix_entries =
			kzalloc(sizeof(struct msix_entry) * entry_nr->entry_nr,
				GFP_KERNEL);
		if (!adev->guest_msix_entries) {
			kfree(adev->host_msix_entries);
			r = -ENOMEM;
			goto msix_nr_out;
		}
	} else /* Not allowed set MSI-X number twice */
		r = -EINVAL;
msix_nr_out:
	mutex_unlock(&pvm->lock);
	return r;
}

static int vmmr0_vm_ioctl_set_msix_entry(struct vm *pvm,
				       struct vmmr0_assigned_msix_entry *entry)
{
	int r = 0, i;
	struct vmmr0_assigned_dev_kernel *adev;

	mutex_lock(&pvm->lock);

	adev = vmmr0_find_assigned_dev(&pvm->arch.assigned_dev_head,
				      entry->assigned_dev_id);

	if (!adev) {
		r = -EINVAL;
		goto msix_entry_out;
	}

	for (i = 0; i < adev->entries_nr; i++)
		if (adev->guest_msix_entries[i].vector == 0 ||
		    adev->guest_msix_entries[i].entry == entry->entry) {
			adev->guest_msix_entries[i].entry = entry->entry;
			adev->guest_msix_entries[i].vector = entry->gsi;
			adev->host_msix_entries[i].entry = entry->entry;
			break;
		}
	if (i == adev->entries_nr) {
		r = -ENOSPC;
		goto msix_entry_out;
	}

msix_entry_out:
	mutex_unlock(&pvm->lock);

	return r;
}
#endif

static int vmmr0_vm_ioctl_set_pci_irq_mask(struct vm *pvm,
		struct vmmr0_assigned_pci_dev *assigned_dev)
{
	int r = 0;
#ifdef HOST_LINUX
	struct vmmr0_assigned_dev_kernel *match;

	mutex_lock(&pvm->lock);

	match = vmmr0_find_assigned_dev(&pvm->arch.assigned_dev_head,
				      assigned_dev->assigned_dev_id);
	if (!match) {
		r = -ENODEV;
		goto out;
	}

	spin_lock(&match->intx_mask_lock);

	match->flags &= ~KVM_DEV_ASSIGN_MASK_INTX;
	match->flags |= assigned_dev->flags & KVM_DEV_ASSIGN_MASK_INTX;

	if (match->irq_requested_type & KVM_DEV_IRQ_GUEST_INTX) {
		if (assigned_dev->flags & KVM_DEV_ASSIGN_MASK_INTX) {
			vmmr0_set_irq(match->pvm, match->irq_source_id,
				    match->guest_irq, 0);
			/*
			 * Masking at hardware-level is performed on demand,
			 * i.e. when an IRQ actually arrives at the host.
			 */
		} else if (!(assigned_dev->flags & KVM_DEV_ASSIGN_PCI_2_3)) {
			/*
			 * Unmask the IRQ line if required. Unmasking at
			 * device level will be performed by user space.
			 */
			spin_lock_irq(&match->intx_lock);
			if (match->host_irq_disabled) {
				enable_irq(match->host_irq);
				match->host_irq_disabled = false;
			}
			spin_unlock_irq(&match->intx_lock);
		}
	}

	spin_unlock(&match->intx_mask_lock);

out:
	mutex_unlock(&pvm->lock);
#endif //HOST_LINUX

	return r;
}

long vmmr0_vm_ioctl_assigned_device(struct vm *pvm, unsigned ioctl,
				  unsigned long arg)
{
	void   *argp = (void   *)arg;
	int r;

	switch (ioctl) {
#ifdef HOST_LINUX
	case KVM_ASSIGN_PCI_DEVICE: {
		struct vmmr0_assigned_pci_dev assigned_dev;

		r = -EFAULT;
		if (copy_from_user(&assigned_dev, argp, sizeof assigned_dev))
			goto out;
		r = vmmr0_vm_ioctl_assign_device(pvm, &assigned_dev);
		if (r)
			goto out;
		break;
	}
#endif //HOST_LINUX
	case KVM_ASSIGN_IRQ: {
		r = -EOPNOTSUPP;
		break;
	}
#ifdef HOST_LINUX
	case KVM_ASSIGN_DEV_IRQ: {
		struct vmmr0_assigned_irq assigned_irq;

		r = -EFAULT;
		if (copy_from_user(&assigned_irq, argp, sizeof assigned_irq))
			goto out;
		r = vmmr0_vm_ioctl_assign_irq(pvm, &assigned_irq);
		if (r)
			goto out;
		break;
	}
	case KVM_DEASSIGN_DEV_IRQ: {
		struct vmmr0_assigned_irq assigned_irq;

		r = -EFAULT;
		if (copy_from_user(&assigned_irq, argp, sizeof assigned_irq))
			goto out;
		r = vmmr0_vm_ioctl_deassign_dev_irq(pvm, &assigned_irq);
		if (r)
			goto out;
		break;
	}
	case KVM_DEASSIGN_PCI_DEVICE: {
		struct vmmr0_assigned_pci_dev assigned_dev;

		r = -EFAULT;
		if (copy_from_user(&assigned_dev, argp, sizeof assigned_dev))
			goto out;
		r = vmmr0_vm_ioctl_deassign_device(pvm, &assigned_dev);
		if (r)
			goto out;
		break;
	}
#endif //HOST_LINUX
#ifdef KVM_CAP_IRQ_ROUTING
	case KVM_SET_GSI_ROUTING: {
		struct vmmr0_irq_routing routing;
		struct vmmr0_irq_routing   *urouting;
		struct vmmr0_irq_routing_entry *entries;

		r = -EFAULT;
		if (copy_from_user(&routing, argp, sizeof(routing)))
			goto out;
		r = -EINVAL;
		if (routing.nr >= KVM_MAX_IRQ_ROUTES)
			goto out;
		if (routing.flags)
			goto out;
		r = -ENOMEM;
		entries = vmalloc(routing.nr * sizeof(*entries));
		if (!entries)
			goto out;
		r = -EFAULT;
		urouting = argp;
		if (copy_from_user(entries, urouting->entries,
				   routing.nr * sizeof(*entries)))
			goto out_free_irq_routing;
		r = vmmr0_set_irq_routing(pvm, entries, routing.nr,
					routing.flags);
	out_free_irq_routing:
		vfree(entries);
		break;
	}
#endif /* KVM_CAP_IRQ_ROUTING */
#ifdef __KVM_HAVE_MSIX
	case KVM_ASSIGN_SET_MSIX_NR: {
		struct vmmr0_assigned_msix_nr entry_nr;
		r = -EFAULT;
		if (copy_from_user(&entry_nr, argp, sizeof entry_nr))
			goto out;
		r = vmmr0_vm_ioctl_set_msix_nr(pvm, &entry_nr);
		if (r)
			goto out;
		break;
	}
	case KVM_ASSIGN_SET_MSIX_ENTRY: {
		struct vmmr0_assigned_msix_entry entry;
		r = -EFAULT;
		if (copy_from_user(&entry, argp, sizeof entry))
			goto out;
		r = vmmr0_vm_ioctl_set_msix_entry(pvm, &entry);
		if (r)
			goto out;
		break;
	}
#endif
	case KVM_ASSIGN_SET_INTX_MASK: {
		struct vmmr0_assigned_pci_dev assigned_dev;

		r = -EFAULT;
		if (copy_from_user(&assigned_dev, argp, sizeof assigned_dev))
			goto out;
		r = vmmr0_vm_ioctl_set_pci_irq_mask(pvm, &assigned_dev);
		break;
	}
	default:
		r = -ENOTTY;
		break;
	}
out:
	return r;
}
#endif //CONFIG_HAVE_ASSIGNED_DEV
