/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef __KVM_IODEV_H__
#define __KVM_IODEV_H__

#include "os_interface.h"

#include <linux/vmmr0_types.h>

struct vmmr0_io_device;

/**
 * vmmr0_io_device_ops are called under vmmr0 slots_lock.
 * read and write handlers return 0 if the transaction has been handled,
 * or non-zero to have it passed to the next device.
 **/
struct vmmr0_io_device_ops
{
	int (*read)(struct vmmr0_io_device *thethis,
		    gpa_t addr,
		    int len,
		    void *val);
	int (*write)(struct vmmr0_io_device *thethis,
		     gpa_t addr,
		     int len,
		     const void *val);
	void (*destructor)(struct vmmr0_io_device *thethis);
};


struct vmmr0_io_device
{
	const struct vmmr0_io_device_ops *ops;
};

static inline void vmmr0_iodevice_init(struct vmmr0_io_device *dev,
				     const struct vmmr0_io_device_ops *ops)
{
	dev->ops = ops;
}

static inline int vmmr0_iodevice_read(struct vmmr0_io_device *dev,
				    gpa_t addr, int l, void *v)
{
	return dev->ops->read ? dev->ops->read(dev, addr, l, v) : -EOPNOTSUPP;
}

static inline int vmmr0_iodevice_write(struct vmmr0_io_device *dev,
				     gpa_t addr, int l, const void *v)
{
	return dev->ops->write ? dev->ops->write(dev, addr, l, v) : -EOPNOTSUPP;
}

static inline void vmmr0_iodevice_destructor(struct vmmr0_io_device *dev)
{
	if (dev->ops->destructor)
		dev->ops->destructor(dev);
}

#endif /* __KVM_IODEV_H__ */
