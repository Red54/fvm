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
 * iommu.c
 *
 * this code is based on kvm-kmod.
 *
 * authors : 
 *     范文一 （Wincy Van） <fanwenyi0529@live.com> <QQ:362478911>
 *     Allen M. Kay <allen.m.kay@intel.com>
 *     Weidong Han <weidong.han@intel.com>
 *     Ben-Ami Yassour <benami@il.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * From: kvm-kmod-3.4
 */
 
#include "os_interface.h"


#include <linux/vmmr0_host.h>

#ifdef CONFIG_IOMMU_API

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
static int allow_unsafe_assigned_interrupts;
#else
static bool allow_unsafe_assigned_interrupts;
#endif


static int vmmr0_iommu_unmap_memslots(struct vm *pvm);
static void vmmr0_iommu_put_pages(struct vm *pvm,
				gfn_t base_gfn, unsigned long npages);

static pfn_t vmmr0_pin_pages(struct vm *pvm, struct vmmr0_memory_slot *slot,
			   gfn_t gfn, unsigned long size)
{
	gfn_t end_gfn;
	pfn_t pfn;

	pfn     = mmu_gfn_to_pfn_memslot(pvm, slot, gfn);
	end_gfn = gfn + (size >> PAGE_SHIFT);
	gfn    += 1;

	if (is_error_pfn(pfn))
		return pfn;

	while (gfn < end_gfn)
		mmu_gfn_to_pfn_memslot(pvm, slot, gfn++);

	return pfn;
}

int vmmr0_iommu_map_pages(struct vm *pvm, struct vmmr0_memory_slot *slot)
{
	gfn_t gfn, end_gfn;
	pfn_t pfn;
	int r = 0;
	struct iommu_domain *domain = pvm->arch.iommu_domain;
	int flags;

	/* check if iommu exists and in use */
	if (!domain)
		return 0;

	gfn     = slot->base_gfn;
	end_gfn = gfn + slot->npages;

	flags = IOMMU_READ | IOMMU_WRITE;
	if (pvm->arch.iommu_flags & KVM_IOMMU_CACHE_COHERENCY)
		flags |= IOMMU_CACHE;


	while (gfn < end_gfn) {
		unsigned long page_size;

		/* Check if already mapped */
		if (iommu_iova_to_phys(domain, gfn_to_gpa(gfn))) {
			gfn += 1;
			continue;
		}

		/* Get the page size we could use to map */
		page_size = vmmr0_host_page_size(pvm, gfn);

		/* Make sure the page_size does not exceed the memslot */
		while ((gfn + (page_size >> PAGE_SHIFT)) > end_gfn)
			page_size >>= 1;

		/* Make sure gfn is aligned to the page size we want to map */
		while ((gfn << PAGE_SHIFT) & (page_size - 1))
			page_size >>= 1;

		/*
		 * Pin all pages we are about to map in memory. This is
		 * important because we unmap and unpin in 4kb steps later.
		 */
		pfn = vmmr0_pin_pages(pvm, slot, gfn, page_size);
		if (is_error_pfn(pfn)) {
			gfn += 1;
			continue;
		}

		/* Map into IO address space */
		r = vmmr0_iommu_map(domain, gfn_to_gpa(gfn), pfn_to_hpa(pfn),
			      page_size, flags);
		if (r) {
			printk(KERN_ERR "vmmr0_iommu_map_address:"
			       "iommu failed to map pfn=%llx\n", pfn);
			goto unmap_pages;
		}

		gfn += page_size >> PAGE_SHIFT;


	}

	return 0;

unmap_pages:
	vmmr0_iommu_put_pages(pvm, slot->base_gfn, gfn);
	return r;
}

static int vmmr0_iommu_map_memslots(struct vm *pvm)
{
	int idx, r = 0;
	struct vmmr0_memslots *slots;
	struct vmmr0_memory_slot *memslot;

	idx = srcu_read_lock(&pvm->srcu);
	slots = vmmr0_memslots(pvm);

	vmmr0_for_each_memslot(memslot, slots) {
		r = vmmr0_iommu_map_pages(pvm, memslot);
		if (r)
			break;
	}
	srcu_read_unlock(&pvm->srcu, idx);

	return r;
}

#ifdef CONFIG_HAVE_ASSIGNED_DEV
int vmmr0_assign_device(struct vm *pvm,
		      struct vmmr0_assigned_dev_kernel *assigned_dev)
{
	struct pci_dev *pdev = NULL;
	struct iommu_domain *domain = pvm->arch.iommu_domain;
	int r, last_flags;

	/* check if iommu exists and in use */
	if (!domain)
		return 0;

	pdev = assigned_dev->dev;
	if (pdev == NULL)
		return -ENODEV;

	r = iommu_attach_device(domain, &pdev->dev);
	if (r) {
		printk(KERN_ERR "assign device %x:%x:%x.%x failed",
			pci_domain_nr(pdev->bus),
			pdev->bus->number,
			PCI_SLOT(pdev->devfn),
			PCI_FUNC(pdev->devfn));
		return r;
	}

	last_flags = pvm->arch.iommu_flags;
	if (iommu_domain_has_cap(pvm->arch.iommu_domain,
				 IOMMU_CAP_CACHE_COHERENCY))
		pvm->arch.iommu_flags |= KVM_IOMMU_CACHE_COHERENCY;

	/* Check if need to update IOMMU page table for guest memory */
	if ((last_flags ^ pvm->arch.iommu_flags) ==
			KVM_IOMMU_CACHE_COHERENCY) {
		vmmr0_iommu_unmap_memslots(pvm);
		r = vmmr0_iommu_map_memslots(pvm);
		if (r)
			goto out_unmap;
	}

	pdev->dev_flags |= PCI_DEV_FLAGS_ASSIGNED;

	printk(KERN_DEBUG "assign device %x:%x:%x.%x\n",
		assigned_dev->host_segnr,
		assigned_dev->host_busnr,
		PCI_SLOT(assigned_dev->host_devfn),
		PCI_FUNC(assigned_dev->host_devfn));

	return 0;
out_unmap:
	vmmr0_iommu_unmap_memslots(pvm);
	return r;
}

int vmmr0_deassign_device(struct vm *pvm,
			struct vmmr0_assigned_dev_kernel *assigned_dev)
{
	struct iommu_domain *domain = pvm->arch.iommu_domain;
	struct pci_dev *pdev = NULL;

	/* check if iommu exists and in use */
	if (!domain)
		return 0;

	pdev = assigned_dev->dev;
	if (pdev == NULL)
		return -ENODEV;

	iommu_detach_device(domain, &pdev->dev);

	pdev->dev_flags &= ~PCI_DEV_FLAGS_ASSIGNED;

	printk(KERN_DEBUG "deassign device %x:%x:%x.%x\n",
		assigned_dev->host_segnr,
		assigned_dev->host_busnr,
		PCI_SLOT(assigned_dev->host_devfn),
		PCI_FUNC(assigned_dev->host_devfn));

	return 0;
}
#endif //CONFIG_HAVE_ASSIGNED_DEV

int vmmr0_iommu_map_guest(struct vm *pvm)
{
	int r;

	if (!iommu_present(&pci_bus_type)) {
		printk(KERN_ERR "%s: iommu not found\n", __func__);
		return -ENODEV;
	}

	mutex_lock(&pvm->slots_lock);

	pvm->arch.iommu_domain = iommu_domain_alloc(&pci_bus_type);
	if (!pvm->arch.iommu_domain) {
		r = -ENOMEM;
		goto out_unlock;
	}

	if (!allow_unsafe_assigned_interrupts &&
	    !iommu_domain_has_cap(pvm->arch.iommu_domain,
				  IOMMU_CAP_INTR_REMAP)) {
		printk(KERN_WARNING "%s: No interrupt remapping support,"
		       " disallowing device assignment."
		       " Re-enble with \"allow_unsafe_assigned_interrupts=1\""
		       " module option.\n", __func__);
		iommu_domain_free(pvm->arch.iommu_domain);
		pvm->arch.iommu_domain = NULL;
		r = -EPERM;
		goto out_unlock;
	}

	r = vmmr0_iommu_map_memslots(pvm);
	if (r)
		vmmr0_iommu_unmap_memslots(pvm);

out_unlock:
	mutex_unlock(&pvm->slots_lock);
	return r;
}

static void vmmr0_unpin_pages(struct vm *pvm, pfn_t pfn, unsigned long npages)
{
	unsigned long i;

	for (i = 0; i < npages; ++i)
		vmmr0_release_pfn_clean(pfn + i);
}

static void vmmr0_iommu_put_pages(struct vm *pvm,
				gfn_t base_gfn, unsigned long npages)
{
	struct iommu_domain *domain;
	gfn_t end_gfn, gfn;
	pfn_t pfn;
	u64 phys;

	domain  = pvm->arch.iommu_domain;
	end_gfn = base_gfn + npages;
	gfn     = base_gfn;

	/* check if iommu exists and in use */
	if (!domain)
		return;

	while (gfn < end_gfn) {
		unsigned long unmap_pages;
		size_t size;

		/* Get physical address */
		phys = iommu_iova_to_phys(domain, gfn_to_gpa(gfn));
		pfn  = phys >> PAGE_SHIFT;

		/* Unmap address from IO address space */
		size       = vmmr0_iommu_unmap(domain, gfn_to_gpa(gfn), PAGE_SIZE);
		unmap_pages = 1ULL << get_order(size);

		/* Unpin all pages we just unmapped to not leak any memory */
		vmmr0_unpin_pages(pvm, pfn, unmap_pages);

		gfn += unmap_pages;
	}
}

void vmmr0_iommu_unmap_pages(struct vm *pvm, struct vmmr0_memory_slot *slot)
{
	vmmr0_iommu_put_pages(pvm, slot->base_gfn, slot->npages);
}

static int vmmr0_iommu_unmap_memslots(struct vm *pvm)
{
	int idx;
	struct vmmr0_memslots *slots;
	struct vmmr0_memory_slot *memslot;

	idx = srcu_read_lock(&pvm->srcu);
	slots = vmmr0_memslots(pvm);

	vmmr0_for_each_memslot(memslot, slots)
		vmmr0_iommu_unmap_pages(pvm, memslot);

	srcu_read_unlock(&pvm->srcu, idx);

	return 0;
}

int vmmr0_iommu_unmap_guest(struct vm *pvm)
{
	struct iommu_domain *domain = pvm->arch.iommu_domain;

	/* check if iommu exists and in use */
	if (!domain)
		return 0;

	mutex_lock(&pvm->slots_lock);
	vmmr0_iommu_unmap_memslots(pvm);
	pvm->arch.iommu_domain = NULL;
	mutex_unlock(&pvm->slots_lock);

	iommu_domain_free(domain);
	return 0;
}

#endif
