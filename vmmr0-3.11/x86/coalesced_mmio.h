#ifndef __KVM_COALESCED_MMIO_H__
#define __KVM_COALESCED_MMIO_H__


#ifdef CONFIG_KVM_MMIO


struct vmmr0_coalesced_mmio_dev
{
	struct list_head list;
	struct vmmr0_io_device dev;
	struct vm *pvm;
	struct vmmr0_coalesced_mmio_zone zone;
};

int vmmr0_coalesced_mmio_init(struct vm *pvm);
void vmmr0_coalesced_mmio_free(struct vm *pvm);
int vmmr0_vm_ioctl_register_coalesced_mmio(struct vm *pvm,
                                       struct vmmr0_coalesced_mmio_zone *zone);
int vmmr0_vm_ioctl_unregister_coalesced_mmio(struct vm *pvm,
                                         struct vmmr0_coalesced_mmio_zone *zone);

#else

static inline int vmmr0_coalesced_mmio_init(struct vm *pvm) { return 0; }
static inline void vmmr0_coalesced_mmio_free(struct vm *pvm) { }

int vmmr0_vm_ioctl_register_coalesced_mmio(struct vm *pvm,
                                       struct vmmr0_coalesced_mmio_zone *zone)
{
	return 1;
}

int vmmr0_vm_ioctl_unregister_coalesced_mmio(struct vm *pvm,
                                         struct vmmr0_coalesced_mmio_zone *zone)
{
	return 1;
}

#endif

#endif
