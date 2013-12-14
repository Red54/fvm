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
 * coalesced_mmio.c
 *
 * this code is based on kvm-kmod.
 *
 * author : 
 *     范文一 （Wincy Van） <fanwenyi0529@live.com> <QQ:362478911>
 *     Laurent Vivier <Laurent.Vivier@bull.net>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * From: kvm-kmod-3.4
 */

#include "os_interface.h"

#include "iodev.h"

#include <linux/vmmr0_host.h>
#include <linux/vmmr0.h>

#include "coalesced_mmio.h"

static inline struct vmmr0_coalesced_mmio_dev *to_mmio(struct vmmr0_io_device *dev)
{
	return container_of(dev, struct vmmr0_coalesced_mmio_dev, dev);
}

static int coalesced_mmio_in_range(struct vmmr0_coalesced_mmio_dev *dev,
				   gpa_t addr, int len)
{
	/* is it in a batchable area ?
	 * (addr,len) is fully included in
	 * (zone->addr, zone->size)
	 */
	if (len < 0)
		return 0;
	if (addr + len < addr)
		return 0;
	if (addr < dev->zone.addr)
		return 0;
	if (addr + len > dev->zone.addr + dev->zone.size)
		return 0;
	return 1;
}

static int coalesced_mmio_has_room(struct vmmr0_coalesced_mmio_dev *dev)
{
	struct vmmr0_coalesced_mmio_ring *ring;
	unsigned avail;

	/* Are we able to batch it ? */

	/* last is the first free entry
	 * check if we don't meet the first used entry
	 * there is always one unused entry in the buffer
	 */
	ring = dev->pvm->coalesced_mmio_ring;
	avail = (ring->first - ring->last - 1) % KVM_COALESCED_MMIO_MAX;
	if (avail == 0) {
		/* full */
		return 0;
	}

	return 1;
}

static int coalesced_mmio_write(struct vmmr0_io_device *this,
				gpa_t addr, int len, const void *val)
{
	struct vmmr0_coalesced_mmio_dev *dev = to_mmio(this);
	struct vmmr0_coalesced_mmio_ring *ring = dev->pvm->coalesced_mmio_ring;

	if (!coalesced_mmio_in_range(dev, addr, len))
		return -EOPNOTSUPP;

	spin_lock(&dev->pvm->ring_lock);

	if (!coalesced_mmio_has_room(dev)) {
		spin_unlock(&dev->pvm->ring_lock);
		return -EOPNOTSUPP;
	}

	/* copy data in first free entry of the ring */

	ring->coalesced_mmio[ring->last].phys_addr = addr;
	ring->coalesced_mmio[ring->last].len = len;
	memcpy(ring->coalesced_mmio[ring->last].data, val, len);
	smp_wmb();
	ring->last = (ring->last + 1) % KVM_COALESCED_MMIO_MAX;
	spin_unlock(&dev->pvm->ring_lock);
	return 0;
}

static void coalesced_mmio_destructor(struct vmmr0_io_device *this)
{
	struct vmmr0_coalesced_mmio_dev *dev = to_mmio(this);

	list_del(&dev->list);

	kfree(dev);
}

static const struct vmmr0_io_device_ops coalesced_mmio_ops = {
	.write      = coalesced_mmio_write,
	.destructor = coalesced_mmio_destructor,
};

int vmmr0_coalesced_mmio_init(struct vm *pvm)
{
	struct page *page;
	int ret;

	ret = -ENOMEM;
	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
		goto out_err;

	ret = 0;
	pvm->coalesced_mmio_ring = page_address(page);

	spin_lock_init(&pvm->ring_lock);
	INIT_LIST_HEAD(&pvm->coalesced_zones);

out_err:
	return ret;
}

void vmmr0_coalesced_mmio_free(struct vm *pvm)
{
	if (pvm->coalesced_mmio_ring)
		free_page((unsigned long)pvm->coalesced_mmio_ring);
}

int vmmr0_vm_ioctl_register_coalesced_mmio(struct vm *pvm,
					 struct vmmr0_coalesced_mmio_zone *zone)
{
	int ret;
	struct vmmr0_coalesced_mmio_dev *dev;

	dev = kzalloc(sizeof(struct vmmr0_coalesced_mmio_dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	vmmr0_iodevice_init(&dev->dev, &coalesced_mmio_ops);
	dev->pvm = pvm;
	dev->zone = *zone;

	mutex_lock(&pvm->slots_lock);
	ret = vmmr0_io_bus_register_dev(pvm, KVM_MMIO_BUS, zone->addr,
				      zone->size, &dev->dev);
	if (ret < 0)
		goto out_free_dev;
	list_add_tail(&dev->list, &pvm->coalesced_zones);
	mutex_unlock(&pvm->slots_lock);

	return ret;

out_free_dev:
	mutex_unlock(&pvm->slots_lock);

	kfree(dev);

	if (dev == NULL)
		return -ENXIO;

	return 0;
}

int vmmr0_vm_ioctl_unregister_coalesced_mmio(struct vm *pvm,
					   struct vmmr0_coalesced_mmio_zone *zone)
{
	struct vmmr0_coalesced_mmio_dev *dev, *tmp;

	mutex_lock(&pvm->slots_lock);

	list_for_each_entry_safe(dev, tmp, &pvm->coalesced_zones, list)
		if (coalesced_mmio_in_range(dev, zone->addr, zone->size)) {
			vmmr0_io_bus_unregister_dev(pvm, KVM_MMIO_BUS, &dev->dev);
			vmmr0_iodevice_destructor(&dev->dev);
		}

	mutex_unlock(&pvm->slots_lock);

	return 0;
}
