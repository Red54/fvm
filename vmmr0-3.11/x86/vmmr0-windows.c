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
 * vmmr0-windows.c
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
#include "iodev.h"

#include <linux/vmmr0_host.h>
#include <linux/vmmr0.h>

#include <asm/virtext.h>

#include "coalesced_mmio.h"
#include "async_pf.h"


/*
 * Ordering of locks:
 *
 * 		vmmr0->lock --> vmmr0->slots_lock --> vmmr0->irq_lock
 */

DEFINE_RAW_SPINLOCK( vmmr0_lock);
DEFINE_RAW_SPINLOCK( vmmr0_vm_slot_lock);
DEFINE_RAW_SPINLOCK( vmmr0_vcpu_slot_lock);

LIST_HEAD( vm_list);
LIST_HEAD( vm_slot_list);
LIST_HEAD( vcpu_slot_list);

DEFINE_PER_CPU(mutex, vmm_lock);
DEFINE_PER_CPU(KAFFINITY, old_affinity);
DEFINE_PER_CPU(KAFFINITY, new_affinity);

enum
{
	VMX_AVAILABLE, SVM_AVAILABLE, NOTHING_AVAILABLE
};

static int hwacc_available = VMX_AVAILABLE;

static cpumask_var_t cpus_hardware_enabled;
static int vmmr0_usage_count = 0;
static atomic_t hardware_enable_failed;


struct dentry *vmmr0_debugfs_dir;

static long vmmr0_vcpu_ioctl(struct file *file, unsigned int ioctl,
		unsigned long arg);
		
static int hardware_enable_all(void);
static void hardware_disable_all(void);

static void vmmr0_io_bus_destroy(struct vmmr0_io_bus *bus);

int get_vmfd(struct vm* pvm);
int put_vmfd(struct vm* pvm);
struct vm* vmfd_to_pvm(int fd);

int get_vcpufd(struct vmmr0_vcpu* vcpu);
int put_vcpufd(struct vmmr0_vcpu* vcpu);
struct vmmr0_vcpu* vcpufd_to_vcpu(int fd);

bool vmmr0_rebooting;

static bool largepages_enabled = true;

static struct page *hwpoison_page;
static pfn_t hwpoison_pfn;

struct page *fault_page;
pfn_t fault_pfn;

int current_vm_num = 0;

inline int vmmr0_is_mmio_pfn(pfn_t pfn)
{
	//always false on windows.
	return false;
}

//Switches to specified vcpu, until a matching vcpu_put()

void vcpu_load(struct vmmr0_vcpu *vcpu)
{
	int cpu;

	mutex_lock(&vcpu->mutex);

	cpu = get_cpu();
	vmmr0_arch_vcpu_load(vcpu, cpu);
	put_cpu();
}

void vcpu_put(struct vmmr0_vcpu *vcpu)
{
	preempt_disable();
	vmmr0_arch_vcpu_put(vcpu);
	vmmr0_fire_urn();
	preempt_enable();
	mutex_unlock(&vcpu->mutex);
}

static void ack_flush(void *_completed)
{
}

static bool make_all_cpus_request(struct vm *pvm, unsigned int req)
{
	int i, cpu, me;
	cpumask_var_t cpus;
	bool called = true;
	struct vmmr0_vcpu *vcpu;

	zalloc_cpumask_var(&cpus, GFP_ATOMIC);

	me = get_cpu();
	vmmr0_for_each_vcpu(i, vcpu, pvm)
	{
		vmmr0_make_request(req, vcpu);
		cpu = vcpu->cpu;

		/* Set ->requests bit before we read ->mode */
		smp_mb();

		if (cpus != NULL && cpu != -1 && cpu != me
				&& vmmr0_vcpu_exiting_guest_mode(vcpu) != OUTSIDE_GUEST_MODE)
			cpumask_set_cpu(cpu, cpus);
	}
	if (unlikely(cpus == NULL))
	{
		smp_call_function_many(cpu_online_mask, ack_flush, NULL, 1);
	}
	else if (!cpumask_empty(cpus))
	{
		smp_call_function_many(cpus, ack_flush, NULL, 1);
	}
	else
	{
		called = false;
	}
	put_cpu();
	free_cpumask_var(cpus);
	return called;
}

void vmmr0_flush_remote_tlbs(struct vm *pvm)
{
	long dirty_count = pvm->tlbs_dirty;

	smp_mb();
	if (make_all_cpus_request(pvm, KVM_REQ_TLB_FLUSH))
	{
		++pvm->stat.remote_tlb_flush;
	}
	cmpxchg(&pvm->tlbs_dirty, dirty_count, 0);
}

void vmmr0_reload_remote_mmus(struct vm *pvm)
{
	make_all_cpus_request(pvm, KVM_REQ_MMU_RELOAD);
}

int vmmr0_vcpu_init(struct vmmr0_vcpu *vcpu, struct vm *pvm, unsigned id)
{
	int r;

	mutex_init(&vcpu->mutex);
	vcpu->cpu = -1;
	vcpu->pvm = pvm;
	vcpu->vcpu_id = id;
	vmmr0_async_pf_vcpu_init(vcpu);

	vcpu->run = kzalloc(7 * PAGE_SIZE, GFP_KERNEL);

	r = vmmr0_arch_vcpu_init(vcpu);
	if (r < 0)
	{
		goto fail_free_run;
	}
	return 0;

	fail_free_run:
	kfree(vcpu->run);

	fail: return r;
}

void vmmr0_vcpu_uninit(struct vmmr0_vcpu *vcpu)
{
	vmmr0_arch_vcpu_uninit(vcpu);
	kfree(vcpu->run);
}

static int vmmr0_init_mmu_notifier(struct vm *pvm)
{
	return 0;
}

static void vmmr0_init_memslots_id(struct vm *pvm)
{
	int i;
	struct vmmr0_memslots *slots = pvm->memslots;

	for (i = 0; i < KVM_MEM_SLOTS_NUM; i++)
	{
		slots->id_to_index[i] = slots->memslots[i].id = i;
	}
}

static struct vm *vmmr0_create_vm(unsigned long type)
{
	int r, i;
	struct vm *pvm = vmmr0_arch_alloc_vm();

	if (!pvm)
	{
		return ERR_PTR(-ENOMEM);
	}

	pvm->proc = IoGetCurrentProcess();
	pvm->open_count = 0;

	r = vmmr0_arch_init_vm(pvm, type);
	if (r)
	{
		goto out_err_nodisable;
	}

	r = hardware_enable_all();

	if (r)
	{
		goto out_err_nodisable;
	}

#ifdef CONFIG_HAVE_KVM_IRQCHIP
	INIT_HLIST_HEAD(&pvm->mask_notifier_list);
	INIT_HLIST_HEAD(&pvm->irq_ack_notifier_list);
	spin_lock_init(&pvm->mask_notifier_list_lock);
	spin_lock_init(&pvm->irq_ack_notifier_list_lock);
#endif

	r = -ENOMEM;
	pvm->memslots = kzalloc(sizeof(struct vmmr0_memslots), GFP_KERNEL);
	if (!pvm->memslots)
	{
		goto out_err_nosrcu;
	}

	vmmr0_init_memslots_id(pvm);
	if (init_srcu_struct(&pvm->srcu))
	{
		goto out_err_nosrcu;
	}

	for (i = 0; i < KVM_NR_BUSES; i++)
	{
		pvm->buses[i] = kzalloc(sizeof(struct vmmr0_io_bus), GFP_KERNEL);
		if (!pvm->buses[i])
		{
			goto out_err;
		}
	}

	spin_lock_init(&pvm->mmu_lock);
	raw_spin_lock_init(&pvm->raw_mmu_lock);
	vmmr0_eventfd_init(pvm);
	mutex_init(&pvm->lock);
	mutex_init(&pvm->irq_lock);
	mutex_init(&pvm->slots_lock);
	atomic_set(&pvm->users_count, 1);

	r = vmmr0_init_mmu_notifier(pvm);
	if (r)
		goto out_err;

	raw_spin_lock(&vmmr0_lock);
	list_add(&pvm->vm_list, &vm_list);
	raw_spin_unlock(&vmmr0_lock);

	return pvm;

	out_err:
	cleanup_srcu_struct(&pvm->srcu);

	out_err_nosrcu:
	hardware_disable_all();

	out_err_nodisable:
	for (i = 0; i < KVM_NR_BUSES; i++)
	{
		kfree(pvm->buses[i]);
	}

	kfree(pvm->memslots);
	vmmr0_arch_free_vm(pvm);
	return ERR_PTR(r);
}

static void vmmr0_destroy_dirty_bitmap(struct vmmr0_memory_slot *memslot)
{
	if (!memslot->dirty_bitmap)
	{
		return;
	}

	vmmr0_kvfree(memslot->dirty_bitmap_head);

	memslot->dirty_bitmap = NULL;
	memslot->dirty_bitmap_head = NULL;
}

/*
 * Free any memory in @free but not in @dont.
 */
static void vmmr0_free_physmem_slot(struct vmmr0_memory_slot *free,
		struct vmmr0_memory_slot *dont)
{
	if (!dont || free->rmap != dont->rmap)
	{
		vmmr0_kvfree(free->rmap);
	}

	if (!dont || free->dirty_bitmap != dont->dirty_bitmap)
	{
		vmmr0_destroy_dirty_bitmap(free);
	}

	vmmr0_arch_free_memslot(free, dont);

	free->npages = 0;
	free->rmap = NULL;
}

void vmmr0_free_physmem(struct vm *pvm)
{
	struct vmmr0_memslots *slots = pvm->memslots;
	struct vmmr0_memory_slot *memslot;

	vmmr0_for_each_memslot(memslot, slots)
		vmmr0_free_physmem_slot(memslot, NULL);

	kfree(pvm->memslots);
}

static void vmmr0_destroy_vm(struct vm *pvm)
{
	int i;

	put_vmfd(pvm);
	vmmr0_arch_sync_events(pvm);
	raw_spin_lock(&vmmr0_lock);
	list_del(&pvm->vm_list);
	raw_spin_unlock(&vmmr0_lock);
	vmmr0_free_irq_routing(pvm);

	for (i = 0; i < KVM_NR_BUSES; i++)
	{
		vmmr0_io_bus_destroy(pvm->buses[i]);
	}

	vmmr0_coalesced_mmio_free(pvm);
	vmmr0_arch_flush_shadow(pvm);
	vmmr0_arch_destroy_vm(pvm);
	vmmr0_free_physmem(pvm);
	cleanup_srcu_struct(&pvm->srcu);
	vmmr0_arch_free_vm(pvm);
	hardware_disable_all();
}

void vmmr0_get_vm(struct vm *pvm)
{
	atomic_inc(&pvm->users_count);
}

void vmmr0_put_vm(struct vm *pvm)
{
	if (atomic_dec_and_test(&pvm->users_count))
	{
		vmmr0_destroy_vm(pvm);
	}
}

/*
 * Allocation size is twice as large as the actual dirty bitmap size.
 * This makes it possible to do double buffering: see x86's
 * vmmr0_vm_ioctl_get_dirty_log().
 */
static int vmmr0_create_dirty_bitmap(struct vmmr0_memory_slot *memslot)
{
	unsigned long dirty_bytes = 2 * vmmr0_dirty_bitmap_bytes(memslot);

	memslot->dirty_bitmap = vmmr0_kvzalloc(dirty_bytes);

	if (!memslot->dirty_bitmap)
	{
		return -ENOMEM;
	}

	memslot->dirty_bitmap_head = memslot->dirty_bitmap;
	memslot->nr_dirty_pages = 0;
	return 0;
}

static int cmp_memslot(const void *slot1, const void *slot2)
{
	struct vmmr0_memory_slot *s1, *s2;

	s1 = (struct vmmr0_memory_slot *) slot1;
	s2 = (struct vmmr0_memory_slot *) slot2;

	if (s1->npages < s2->npages)
	{
		return 1;
	}
	if (s1->npages > s2->npages)
	{
		return -1;
	}
	return 0;
}

/*
 * Sort the memslots base on its size, so the larger slots
 * will get better fit.
 */
static void sort_memslots(struct vmmr0_memslots *slots)
{
	int i;

	sort(slots->memslots, KVM_MEM_SLOTS_NUM, sizeof(struct vmmr0_memory_slot),
			cmp_memslot, NULL);

	for (i = 0; i < KVM_MEM_SLOTS_NUM; i++)
	{
		slots->id_to_index[slots->memslots[i].id] = i;
	}
}

void update_memslots(struct vmmr0_memslots *slots,
		struct vmmr0_memory_slot *new)
{
	if (new)
	{
		int id = new->id;
		struct vmmr0_memory_slot *old = id_to_memslot(slots, id);
		unsigned long npages = old->npages;

		*old = *new;
		if (new->npages != npages)
		{
			sort_memslots(slots);
		}
	}

	slots->generation++;
}

int __vmmr0_set_memory_region(struct vm *pvm,
		struct vmmr0_userspace_memory_region *mem, int user_alloc)
{
	int r;
	gfn_t base_gfn;
	unsigned long npages;
	unsigned long i;
	struct vmmr0_memory_slot *memslot;
	struct vmmr0_memory_slot old, new;
	struct vmmr0_memslots *slots, *old_memslots;

	r = -EINVAL;

	if (mem->memory_size & (PAGE_SIZE - 1))
	{
		goto out;
	}

	if (mem->guest_phys_addr & (PAGE_SIZE - 1))
	{
		goto out;
	}


	if (user_alloc
			&& ((mem->userspace_addr & (PAGE_SIZE - 1))
					|| !access_ok(VERIFY_WRITE,
							(unsigned long) mem->userspace_addr,
							mem->memory_size)))
	{
		goto out;
	}

	if (mem->slot >= KVM_MEM_SLOTS_NUM)
	{
		goto out;
	}

	if (mem->guest_phys_addr + mem->memory_size < mem->guest_phys_addr)
	{
		goto out;
	}


	memslot = id_to_memslot(pvm->memslots, mem->slot);
	base_gfn = mem->guest_phys_addr >> PAGE_SHIFT;
	npages = mem->memory_size >> PAGE_SHIFT;

	r = -EINVAL;
	if (npages > KVM_MEM_MAX_NR_PAGES)
	{
		goto out;
	}


	if (!npages)
	{
		mem->flags &= ~KVM_MEM_LOG_DIRTY_PAGES;
	}


	new = old = *memslot;

	new.id = mem->slot;
	new.base_gfn = base_gfn;
	new.npages = npages;
	new.flags = mem->flags;

	r = -EINVAL;
	if (npages && old.npages && npages != old.npages)
	{
		goto out_free;
	}

	//check overlap
	r = -EEXIST;
	for (i = 0; i < KVM_MEMORY_SLOTS; ++i)
	{
		struct vmmr0_memory_slot *s = &pvm->memslots->memslots[i];

		if (s == memslot || !s->npages)
		{
			continue;
		}

		if (!((base_gfn + npages <= s->base_gfn)
				|| (base_gfn >= s->base_gfn + s->npages)))
		{
			goto out_free;
		}

	}

	if (!(new.flags & KVM_MEM_LOG_DIRTY_PAGES))
	{
		new.dirty_bitmap = NULL;
	}


	r = -ENOMEM;

	//alloc a slot
	if (npages && !old.npages)
	{
		new.user_alloc = user_alloc;
		new.userspace_addr = mem->userspace_addr;

		new.rmap = vmmr0_kvzalloc(npages * sizeof(*new.rmap));
		if (!new.rmap)
		{
			goto out_free;
		}

		if (vmmr0_arch_create_memslot(&new, npages))
		{
			goto out_free;
		}

	}

	if ((new.flags & KVM_MEM_LOG_DIRTY_PAGES) && !new.dirty_bitmap)
	{
		if (vmmr0_create_dirty_bitmap(&new) < 0)
		{
			goto out_free;
		}

	}

	if (!npages)
	{
		struct vmmr0_memory_slot *slot;

		r = -ENOMEM;
		slots = kmemdup(pvm->memslots, sizeof(struct vmmr0_memslots),
				GFP_KERNEL);
		if (!slots)
		{
			goto out_free;
		}

		slot = id_to_memslot(slots, mem->slot);
		slot->flags |= KVM_MEMSLOT_INVALID;

		update_memslots(slots, NULL);

		old_memslots = pvm->memslots;
		rcu_assign_pointer(pvm->memslots, slots);
		vmmr0_synchronize_srcu_expedited(&pvm->srcu);

		vmmr0_arch_flush_shadow(pvm);
		kfree(old_memslots);
	}

	r = vmmr0_arch_prepare_memory_region(pvm, &new, old, mem, user_alloc);
	if (r)
	{
		goto out_free;
	}


	// map/unmap iommu page table
	if (npages)
	{
		r = vmmr0_iommu_map_pages(pvm, &new);
		if (r)
		{
			goto out_free;
		}

	}
	else
	{
		vmmr0_iommu_unmap_pages(pvm, &old);
	}

	r = -ENOMEM;
	slots = kmemdup(pvm->memslots, sizeof(struct vmmr0_memslots), GFP_KERNEL);
	if (!slots)
	{
		goto out_free;
	}

	if (!npages)
	{
		new.rmap = NULL;
		new.dirty_bitmap = NULL;
		memset(&new.arch, 0, sizeof(new.arch));
	}

	update_memslots(slots, &new);
	old_memslots = pvm->memslots;
	rcu_assign_pointer(pvm->memslots, slots);
	vmmr0_synchronize_srcu_expedited(&pvm->srcu);

	vmmr0_arch_commit_memory_region(pvm, mem, old, user_alloc);

	if (npages && old.base_gfn != mem->guest_phys_addr >> PAGE_SHIFT)
	{
		vmmr0_arch_flush_shadow(pvm);
	}

	vmmr0_free_physmem_slot(&old, &new);
	kfree(old_memslots);

	return 0;

	out_free: vmmr0_free_physmem_slot(&new, &old);
	out: return r;

}

int vmmr0_set_memory_region(struct vm *pvm,
		struct vmmr0_userspace_memory_region *mem, int user_alloc)
{
	int r;

	mutex_lock(&pvm->slots_lock);
	r = __vmmr0_set_memory_region(pvm, mem, user_alloc);
	mutex_unlock(&pvm->slots_lock);
	return r;
}

int vmmr0_vm_ioctl_set_memory_region(struct vm *pvm,
		struct vmmr0_userspace_memory_region *mem, int user_alloc)
{
	if (mem->slot >= KVM_MEMORY_SLOTS)
	{
		return -EINVAL;
	}
	return vmmr0_set_memory_region(pvm, mem, user_alloc);
}

int vmmr0_get_dirty_log(struct vm *pvm, struct vmmr0_dirty_log *log,
		int *is_dirty)
{
	struct vmmr0_memory_slot *memslot;
	int r, i;
	unsigned long n;
	unsigned long any = 0;

	r = -EINVAL;
	if (log->slot >= KVM_MEMORY_SLOTS)
	{
		goto out;
	}


	memslot = id_to_memslot(pvm->memslots, log->slot);
	r = -ENOENT;
	if (!memslot->dirty_bitmap)
		goto out;

	n = vmmr0_dirty_bitmap_bytes(memslot);

	for (i = 0; !any && i < n / sizeof(long); ++i)
		any = memslot->dirty_bitmap[i];

	r = -EFAULT;
	if (copy_to_user(log->dirty_bitmap, memslot->dirty_bitmap, n))
	{
		goto out;
	}

	if (any)
	{
		*is_dirty = 1;
	}

	r = 0;
	out: return r;
}

bool vmmr0_largepages_enabled(void)
{
	return largepages_enabled;
}

void vmmr0_disable_largepages(void)
{
	largepages_enabled = false;
}

int is_error_page(struct page *page)
{
	return page == bad_page || page == hwpoison_page || page == fault_page;
}

int is_error_pfn(pfn_t pfn)
{
	return pfn == bad_pfn || pfn == hwpoison_pfn || pfn == fault_pfn;
}

int is_hwpoison_pfn(pfn_t pfn)
{
	return pfn == hwpoison_pfn;
}

int is_fault_pfn(pfn_t pfn)
{
	return pfn == fault_pfn;
}

int is_noslot_pfn(pfn_t pfn)
{
	return pfn == bad_pfn;
}

int is_invalid_pfn(pfn_t pfn)
{
	return pfn == hwpoison_pfn || pfn == fault_pfn;
}

static inline unsigned long bad_hva(void)
{
	return PAGE_OFFSET;
}

int vmmr0_is_error_hva(unsigned long addr)
{
	return addr == bad_hva();
}

struct vmmr0_memory_slot *mmu_gfn_to_memslot(struct vm *pvm, gfn_t gfn)
{
	return __gfn_to_memslot(vmmr0_memslots(pvm), gfn);
}

int vmmr0_is_visible_gfn(struct vm *pvm, gfn_t gfn)
{
	struct vmmr0_memory_slot *memslot = mmu_gfn_to_memslot(pvm, gfn);

	if (!memslot || memslot->id >= KVM_MEMORY_SLOTS
			|| memslot->flags & KVM_MEMSLOT_INVALID)
	{
		return 0;
	}

	return 1;
}

unsigned long vmmr0_host_page_size(struct vm *pvm, gfn_t gfn)
{
	return PAGE_SIZE;
}

static unsigned long gfn_to_hva_many(struct vmmr0_memory_slot *slot, gfn_t gfn,
		gfn_t *nr_pages)
{
	if (!slot || slot->flags & KVM_MEMSLOT_INVALID)
	{
		return bad_hva();
	}

	if (nr_pages)
	{
		*nr_pages = slot->npages - (gfn - slot->base_gfn);
	}

	return gfn_to_hva_memslot(slot, gfn);
}

unsigned long mmu_gfn_to_hva(struct vm *pvm, gfn_t gfn)
{
	return gfn_to_hva_many(mmu_gfn_to_memslot(pvm, gfn), gfn, NULL);
}

static pfn_t hva_to_pfn(struct vm *pvm, unsigned long addr, bool atomic,
		bool *async, bool write_fault, bool *writable)
{
	pfn_t pfn;
	PHYSICAL_ADDRESS addrphy;
	/*
	 *	TODO:
	 *	on windows, the guest memory will no longer allocate by malloc family, because we dont
	 *	know when would the windows kernel swap out the guest pages. We allocate guest memory
	 *	with Address Windowing Extention (AWE). The AWE memory will not be swaped out, so
	 *	we should implement a swapper to swap the guest page to disk, just like VMware WorkStation.
	 */

	addrphy = MmGetPhysicalAddress((void*)addr);
	pfn = addrphy.QuadPart >> PAGE_SHIFT;
	return pfn;
}

pfn_t hva_to_pfn_atomic(struct vm *pvm, unsigned long addr)
{
	return hva_to_pfn(pvm, addr, true, NULL, true, NULL);
}

static pfn_t __gfn_to_pfn(struct vm *pvm, gfn_t gfn, bool atomic,
		bool *async, bool write_fault, bool *writable)
{
	unsigned long addr;

	if (async)
	{
		*async = false;
	}

	addr = mmu_gfn_to_hva(pvm, gfn);
	if (vmmr0_is_error_hva(addr))
	{
		get_page(bad_page);
		return page_to_pfn(bad_page);
	}

	return hva_to_pfn(pvm, addr, atomic, async, write_fault, writable);
}

pfn_t mmu_gfn_to_pfn_atomic(struct vm *pvm, gfn_t gfn)
{
	return __gfn_to_pfn(pvm, gfn, true, NULL, true, NULL);
}

pfn_t mmu_gfn_to_pfn_async(struct vm *pvm, gfn_t gfn, bool *async,
		bool write_fault, bool *writable)
{
	return __gfn_to_pfn(pvm, gfn, false, async, write_fault, writable);
}

pfn_t mmu_gfn_to_pfn(struct vm *pvm, gfn_t gfn)
{
	return __gfn_to_pfn(pvm, gfn, false, NULL, true, NULL);
}

pfn_t mmu_gfn_to_pfn_prot(struct vm *pvm, gfn_t gfn, bool write_fault,
		bool *writable)
{
	return __gfn_to_pfn(pvm, gfn, false, NULL, write_fault, writable);
}

pfn_t mmu_gfn_to_pfn_memslot(struct vm *pvm, struct vmmr0_memory_slot *slot,
		gfn_t gfn)
{
	unsigned long addr = gfn_to_hva_memslot(slot, gfn);
	return hva_to_pfn(pvm, addr, false, NULL, true, NULL);
}

int mmu_gfn_to_page_many_atomic(struct vm *pvm, gfn_t gfn,
		struct page **pages, int nr_pages)
{
	unsigned long addr;
	gfn_t entry;

	addr = gfn_to_hva_many(mmu_gfn_to_memslot(pvm, gfn), gfn, &entry);
	if (vmmr0_is_error_hva(addr))
	{
		return -1;
	}

	if (entry < nr_pages)
	{
		return 0;
	}

	return vmmr0___get_user_pages_fast(addr, nr_pages, 1, pages);
}

struct page *mmu_gfn_to_page(struct vm *pvm, gfn_t gfn)
{
	pfn_t pfn;

	pfn = mmu_gfn_to_pfn(pvm, gfn);
	if (!vmmr0_is_mmio_pfn(pfn))
	{
		return pfn_to_page(pfn);
	}

	WARN_ON(vmmr0_is_mmio_pfn(pfn));

	get_page(bad_page);
	return bad_page;
}

void vmmr0_release_page_clean(struct page *page)
{
	vmmr0_release_pfn_clean(page_to_pfn(page));
}

void vmmr0_release_pfn_clean(pfn_t pfn)
{
	if (!vmmr0_is_mmio_pfn(pfn))
	{
		put_page(pfn_to_page(pfn));
	}
}

void vmmr0_release_page_dirty(struct page *page)
{
	vmmr0_release_pfn_dirty(page_to_pfn(page));
}

void vmmr0_release_pfn_dirty(pfn_t pfn)
{
	vmmr0_set_pfn_dirty(pfn);
	vmmr0_release_pfn_clean(pfn);
}

void vmmr0_set_page_dirty(struct page *page)
{
	vmmr0_set_pfn_dirty(page_to_pfn(page));
}

void vmmr0_set_pfn_dirty(pfn_t pfn)
{
}

void vmmr0_set_pfn_accessed(pfn_t pfn)
{
}

void vmmr0_get_pfn(pfn_t pfn)
{
	if (!vmmr0_is_mmio_pfn(pfn))
	{
		get_page(pfn_to_page(pfn));
	}
}

static int next_segment(unsigned long len, int offset)
{
	if (len > PAGE_SIZE - offset)
	{
		return PAGE_SIZE - offset;
	}
	else
	{
		return len;
	}
}

int vmmr0_read_guest_page(struct vm *pvm, gfn_t gfn, void *data,
		int offset, int len)
{
	int r;
	unsigned long addr;

	addr = mmu_gfn_to_hva(pvm, gfn);
	if (vmmr0_is_error_hva(addr))
	{
		return -EFAULT;
	}
	r = __copy_from_user(data, (void *) addr + offset, len);
	if (r)
	{
		return -EFAULT;
	}
	return 0;
}

int vmmr0_read_guest(struct vm *pvm, gpa_t gpa, void *data,
		unsigned long len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0)
	{
		ret = vmmr0_read_guest_page(pvm, gfn, data, offset, seg);
		if (ret < 0)
		{
			return ret;
		}
		offset = 0;
		len -= seg;
		data += seg;
		++gfn;
	}
	return 0;
}

int vmmr0_read_guest_atomic(struct vm *pvm, gpa_t gpa, void *data,
		unsigned long len)
{
	int r;
	unsigned long addr;
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int offset = offset_in_page(gpa);

	addr = mmu_gfn_to_hva(pvm, gfn);
	if (vmmr0_is_error_hva(addr))
	{
		return -EFAULT;
	}
	pagefault_disable();
	r = __copy_from_user_inatomic(data, (void *) addr + offset, len);
	pagefault_enable();
	if (r)
	{
		return -EFAULT;
	}
	return 0;
}

int vmmr0_write_guest_page(struct vm *pvm, gfn_t gfn, const void *data,
		int offset, int len)
{
	int r;
	unsigned long addr;

	addr = mmu_gfn_to_hva(pvm, gfn);
	if (vmmr0_is_error_hva(addr))
	{
		return -EFAULT;
	}

	r = __copy_to_user((void *) addr + offset, data, len);
	if (r)
	{
		return -EFAULT;
	}

	mark_page_dirty(pvm, gfn);
	return 0;
}

int vmmr0_write_guest(struct vm *pvm, gpa_t gpa, const void *data,
		unsigned long len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0)
	{
		ret = vmmr0_write_guest_page(pvm, gfn, data, offset, seg);
		if (ret < 0)
		{
			return ret;
		}
		offset = 0;
		len -= seg;
		data += seg;
		++gfn;
	}
	return 0;
}

int vmmr0_gfn_to_hva_cache_init(struct vm *pvm,
		struct gfn_to_hva_cache *ghc, gpa_t gpa)
{
	struct vmmr0_memslots *slots = vmmr0_memslots(pvm);
	int offset = offset_in_page(gpa);
	gfn_t gfn = gpa >> PAGE_SHIFT;

	ghc->gpa = gpa;
	ghc->generation = slots->generation;
	ghc->memslot = mmu_gfn_to_memslot(pvm, gfn);
	ghc->hva = gfn_to_hva_many(ghc->memslot, gfn, NULL);
	if (!vmmr0_is_error_hva(ghc->hva))
	{
		ghc->hva += offset;
	}
	else
	{
		return -EFAULT;
	}

	return 0;
}

int vmmr0_write_guest_cached(struct vm *pvm, struct gfn_to_hva_cache *ghc,
		void *data, unsigned long len)
{
	struct vmmr0_memslots *slots = vmmr0_memslots(pvm);
	int r;

	if (slots->generation != ghc->generation)
	{
		vmmr0_gfn_to_hva_cache_init(pvm, ghc, ghc->gpa);
	}

	if (vmmr0_is_error_hva(ghc->hva))
	{
		return -EFAULT;
	}

	r = __copy_to_user((void *) ghc->hva, data, len);
	if (r)
	{
		return -EFAULT;
	}
	mark_page_dirty_in_slot(pvm, ghc->memslot, ghc->gpa >> PAGE_SHIFT);

	return 0;
}

int vmmr0_read_guest_cached(struct vm *pvm, struct gfn_to_hva_cache *ghc,
		void *data, unsigned long len)
{
	struct vmmr0_memslots *slots = vmmr0_memslots(pvm);
	int r;

	if (slots->generation != ghc->generation)
	{
		vmmr0_gfn_to_hva_cache_init(pvm, ghc, ghc->gpa);
	}

	if (vmmr0_is_error_hva(ghc->hva))
	{
		return -EFAULT;
	}

	r = __copy_from_user(data, (void *) ghc->hva, len);
	if (r)
	{
		return -EFAULT;
	}

	return 0;
}

int vmmr0_clear_guest_page(struct vm *pvm, gfn_t gfn, int offset, int len)
{
	return vmmr0_write_guest_page(pvm, gfn, (const void *) empty_zero_page,
			offset, len);
}

int vmmr0_clear_guest(struct vm *pvm, gpa_t gpa, unsigned long len)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0)
	{
		ret = vmmr0_clear_guest_page(pvm, gfn, offset, seg);
		if (ret < 0)
		{
			return ret;
		}
		offset = 0;
		len -= seg;
		++gfn;
	}
	return 0;
}

void mark_page_dirty_in_slot(struct vm *pvm,
		struct vmmr0_memory_slot *memslot, gfn_t gfn)
{
	if (memslot && memslot->dirty_bitmap)
	{
		unsigned long rel_gfn = gfn - memslot->base_gfn;

		if (!test_and_set_bit_le(rel_gfn, memslot->dirty_bitmap))
		{
			memslot->nr_dirty_pages++;
		}
	}
}

void mark_page_dirty(struct vm *pvm, gfn_t gfn)
{
	struct vmmr0_memory_slot *memslot;

	memslot = mmu_gfn_to_memslot(pvm, gfn);
	mark_page_dirty_in_slot(pvm, memslot, gfn);
}

static void hardware_enable_nolock(void *junk);
static void hardware_disable_nolock(void *junk);

/*
 * The vCPU has executed a HLT instruction with in-kernel mode enabled.
 */
int vmmr0_vcpu_block(struct vmmr0_vcpu *vcpu)
{
	KIRQL irql;
	LARGE_INTEGER expire;
	expire.QuadPart = -1000000ULL;
	vcpu->blocked = 1;
	for (;;)
	{
		if (vmmr0_arch_vcpu_runnable(vcpu))
		{
			vmmr0_make_request(KVM_REQ_UNHALT, vcpu);
			break;
		}
		if (vmmr0_cpu_has_pending_timer(vcpu))
		{
			break;
		}
		if (vcpu->run->exit_request)
		{
			break;
		}
		vcpu_put(vcpu);
		hardware_disable_nolock(0);
		mutex_unlock(&__get_cpu_var(vmm_lock));
		KeRevertToUserAffinityThreadEx(__get_cpu_var(old_affinity));
		if (STATUS_SUCCESS != KeWaitForSingleObject(vcpu->kick_event, Executive, KernelMode, FALSE, &expire))
		{
			vcpu->run->exit_request = 1;
		}
		KeRaiseIrql(DISPATCH_LEVEL, &irql);
		__get_cpu_var(new_affinity) = 1 << smp_processor_id();
		__get_cpu_var(old_affinity) = KeSetSystemAffinityThreadEx(__get_cpu_var(new_affinity));
		KeLowerIrql(PASSIVE_LEVEL);
		mutex_lock(&__get_cpu_var(vmm_lock));
		hardware_enable_nolock(0);
		vcpu_load(vcpu);
	}
	vcpu->blocked = 0;
	return 0;
}

void vmmr0_vcpu_on_spin(struct vmmr0_vcpu *me)
{
}

static int create_vcpu_fd(struct vmmr0_vcpu *vcpu)
{
	return get_vcpufd(vcpu);
}

static int vmmr0_vm_ioctl_create_vcpu(struct vm *pvm, u32 id)
{
	int r;
	struct vmmr0_vcpu *vcpu, *v;

	vcpu = vmmr0_arch_vcpu_create(pvm, id);
	if (IS_ERR(vcpu))
	{
		return PTR_ERR(vcpu);
	}

	r = vmmr0_arch_vcpu_setup(vcpu);
	if (r)
	{
		goto vcpu_destroy;
	}

	mutex_lock(&pvm->lock);
	if (!vmmr0_vcpu_compatible(vcpu))
	{
		r = -EINVAL;
		goto unlock_vcpu_destroy;
	}
	if (atomic_read(&pvm->online_vcpus) == VMMR0_MAX_VCPU_NUM)
	{
		r = -EINVAL;
		goto unlock_vcpu_destroy;
	}

	vmmr0_for_each_vcpu(r, v, pvm)
	{
		if (v->vcpu_id == id)
		{
			r = -EEXIST;
			goto unlock_vcpu_destroy;
		}
	}

	BUG_ON(pvm->vcpus[atomic_read(&pvm->online_vcpus)]);

	vmmr0_get_vm(pvm);
	r = create_vcpu_fd(vcpu);
	if (r < 0)
	{
		vmmr0_put_vm(pvm);
		goto unlock_vcpu_destroy;
	}

	pvm->vcpus[atomic_read(&pvm->online_vcpus)] = vcpu;
	smp_wmb();
	atomic_inc(&pvm->online_vcpus);

	mutex_unlock(&pvm->lock);
	return r;

	unlock_vcpu_destroy:
	mutex_unlock(&pvm->lock);

	vcpu_destroy:
	vmmr0_arch_vcpu_destroy(vcpu);

	return r;
}

static int vmmr0_vcpu_ioctl_set_sigmask(struct vmmr0_vcpu *vcpu,
		sigset_t *sigset)
{
	return 0;
}

static long vmmr0_vcpu_ioctl(struct file *filp, unsigned int ioctl,
		unsigned long arg)
{
	struct vmmr0_vcpu *vcpu = filp->private_data;
	void *argp = (void *) arg;
	int r;
	struct vmmr0_fpu *fpu = NULL;
	struct vmmr0_sregs *vmmr0_sregs = NULL;


	vcpu_load(vcpu);
	switch (ioctl)
	{
	case KVM_RUN:
	{
		r = -EINVAL;
		if (arg)
		{
			goto out;
		}
		r = vmmr0_arch_vcpu_ioctl_run(vcpu, vcpu->run);
		break;
	}
	case KVM_GET_REGS:
	{
		struct vmmr0_regs *vmmr0_regs;

		r = -ENOMEM;
		vmmr0_regs = kzalloc(sizeof(struct vmmr0_regs), GFP_KERNEL);
		if (!vmmr0_regs)
		{
			goto out;
		}
		r = vmmr0_arch_vcpu_ioctl_get_regs(vcpu, vmmr0_regs);
		if (r)
		{
			goto out_free1;
		}
		r = -EFAULT;
		if (copy_to_user(argp, vmmr0_regs, sizeof(struct vmmr0_regs)))
		{
			goto out_free1;
		}
		r = 0;

		out_free1:
		kfree(vmmr0_regs);

		break;
	}
	case KVM_SET_REGS:
	{
		struct vmmr0_regs *vmmr0_regs;

		r = -ENOMEM;
		vmmr0_regs = memdup_user(argp, sizeof(*vmmr0_regs));
		if (IS_ERR(vmmr0_regs))
		{
			r = PTR_ERR(vmmr0_regs);
			goto out;
		}
		r = vmmr0_arch_vcpu_ioctl_set_regs(vcpu, vmmr0_regs);
		if (r)
		{
			goto out_free2;
		}
		r = 0;

		out_free2:
		kfree(vmmr0_regs);
		break;
	}
	case KVM_GET_SREGS:
	{
		vmmr0_sregs = kzalloc(sizeof(struct vmmr0_sregs), GFP_KERNEL);
		r = -ENOMEM;
		if (!vmmr0_sregs)
		{
			goto out;
		}

		r = vmmr0_arch_vcpu_ioctl_get_sregs(vcpu, vmmr0_sregs);
		if (r)
		{
			goto out;
		}

		r = -EFAULT;
		if (copy_to_user(argp, vmmr0_sregs, sizeof(struct vmmr0_sregs)))
		{
			goto out;
		}

		r = 0;
		break;
	}
	case KVM_SET_SREGS:
	{
		vmmr0_sregs = memdup_user(argp, sizeof(*vmmr0_sregs));
		if (IS_ERR(vmmr0_sregs))
		{
			r = PTR_ERR(vmmr0_sregs);
			goto out;
		}
		r = vmmr0_arch_vcpu_ioctl_set_sregs(vcpu, vmmr0_sregs);
		if (r)
		{
			goto out;
		}

		r = 0;
		break;
	}
	case KVM_GET_MP_STATE:
	{
		struct vmmr0_mp_state mp_state;

		r = vmmr0_arch_vcpu_ioctl_get_mpstate(vcpu, &mp_state);
		if (r)
		{
			goto out;
		}

		r = -EFAULT;
		if (copy_to_user(argp, &mp_state, sizeof mp_state))
		{
			goto out;
		}

		r = 0;
		break;
	}
	case KVM_SET_MP_STATE:
	{
		struct vmmr0_mp_state mp_state;

		r = -EFAULT;
		if (copy_from_user(&mp_state, argp, sizeof mp_state))
		{
			goto out;
		}

		r = vmmr0_arch_vcpu_ioctl_set_mpstate(vcpu, &mp_state);
		if (r)
		{
			goto out;
		}

		r = 0;
		break;
	}
	case KVM_TRANSLATE:
	{
		struct vmmr0_translation tr;

		r = -EFAULT;
		if (copy_from_user(&tr, argp, sizeof tr))
		{
			goto out;
		}
		r = vmmr0_arch_vcpu_ioctl_translate(vcpu, &tr);
		if (r)
		{
			goto out;
		}

		r = -EFAULT;
		if (copy_to_user(argp, &tr, sizeof tr))
		{
			goto out;
		}

		r = 0;
		break;
	}
	case KVM_SET_GUEST_DEBUG:
	{
		struct vmmr0_guest_debug dbg;

		r = -EFAULT;
		if (copy_from_user(&dbg, argp, sizeof dbg))
		{
			goto out;
		}

		r = vmmr0_arch_vcpu_ioctl_set_guest_debug(vcpu, &dbg);
		if (r)
		{
			goto out;
		}

		r = 0;
		break;
	}
	case KVM_SET_SIGNAL_MASK:
	{
		struct vmmr0_signal_mask *sigmask_arg = argp;
		struct vmmr0_signal_mask vmmr0_sigmask;
		sigset_t sigset, *p;

		p = NULL;
		if (argp)
		{
			r = -EFAULT;
			if (copy_from_user(&vmmr0_sigmask, argp, sizeof vmmr0_sigmask))
			{
				goto out;
			}

			r = -EINVAL;
			if (vmmr0_sigmask.len != sizeof sigset)
			{
				goto out;
			}

			r = -EFAULT;
			if (copy_from_user(&sigset, sigmask_arg->sigset, sizeof sigset))
			{
				goto out;
			}

			p = &sigset;
		}
		r = vmmr0_vcpu_ioctl_set_sigmask(vcpu, p);
		break;
	}
	case KVM_GET_FPU:
	{
		fpu = kzalloc(sizeof(struct vmmr0_fpu), GFP_KERNEL);
		r = -ENOMEM;
		if (!fpu)
		{
			goto out;
		}

		r = vmmr0_arch_vcpu_ioctl_get_fpu(vcpu, fpu);
		if (r)
		{
			goto out;
		}

		r = -EFAULT;
		if (copy_to_user(argp, fpu, sizeof(struct vmmr0_fpu)))
		{
			goto out;
		}

		r = 0;
		break;
	}
	case KVM_SET_FPU:
	{
		fpu = memdup_user(argp, sizeof(*fpu));
		if (IS_ERR(fpu))
		{
			r = PTR_ERR(fpu);
			goto out;
		}
		r = vmmr0_arch_vcpu_ioctl_set_fpu(vcpu, fpu);
		if (r)
		{
			goto out;
		}

		r = 0;
		break;
	}
	default:
	{
		r = vmmr0_arch_vcpu_ioctl(filp, ioctl, arg);
		break;
	}
	}
	out: vcpu_put(vcpu);
	kfree(fpu);
	kfree(vmmr0_sregs);
	return r;
}

static long vmmr0_vm_ioctl(struct file *filp, unsigned int ioctl,
		unsigned long arg)
{
	struct vm *pvm = filp->private_data;
	void *argp = (void *) arg;
	int r;

	switch (ioctl)
	{
	case KVM_CREATE_VCPU:
		r = vmmr0_vm_ioctl_create_vcpu(pvm, arg);
		if (r < 0)
		{
			goto out;
		}
		break;
	case KVM_SET_USER_MEMORY_REGION:
	{
		struct vmmr0_userspace_memory_region vmmr0_userspace_mem;

		r = -EFAULT;
		if (copy_from_user(&vmmr0_userspace_mem, argp,
				sizeof vmmr0_userspace_mem))
		{
			goto out;
		}

		r = vmmr0_vm_ioctl_set_memory_region(pvm, &vmmr0_userspace_mem, 1);
		if (r)
		{
			goto out;
		}

		break;
	}
	case KVM_GET_DIRTY_LOG:
	{
		struct vmmr0_dirty_log log;

		r = -EFAULT;
		if (copy_from_user(&log, argp, sizeof log))
		{
			goto out;
		}
		r = vmmr0_vm_ioctl_get_dirty_log(pvm, &log);
		if (r)
		{
			goto out;
		}

		break;
	}
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
	case KVM_REGISTER_COALESCED_MMIO:
	{
		struct vmmr0_coalesced_mmio_zone zone;
		r = -EFAULT;
		if (copy_from_user(&zone, argp, sizeof zone))
		{
			goto out;
		}
		r = vmmr0_vm_ioctl_register_coalesced_mmio(pvm, &zone);
		if (r)
		{
			goto out;
		}
		r = 0;
		break;
	}
	case KVM_UNREGISTER_COALESCED_MMIO:
	{
		struct vmmr0_coalesced_mmio_zone zone;
		r = -EFAULT;
		if (copy_from_user(&zone, argp, sizeof zone))
		{
			goto out;
		}
		r = vmmr0_vm_ioctl_unregister_coalesced_mmio(pvm, &zone);
		if (r)
		{
			goto out;
		}
		r = 0;
		break;
	}
#endif
#ifdef CONFIG_KVM_APIC_ARCHITECTURE
		case KVM_SET_BOOT_CPU_ID:
		r = 0;
		mutex_lock(&pvm->lock);
		if (atomic_read(&pvm->online_vcpus) != 0)
		{
			r = -EBUSY;
		}
		else
		{
			pvm->bsp_vcpu_id = arg;
		}
		mutex_unlock(&pvm->lock);
		break;
#endif
	default:
	{
		r = vmmr0_arch_vm_ioctl(filp, ioctl, arg);
		if (r == -ENOTTY)
		{
			r = vmmr0_vm_ioctl_assigned_device(pvm, ioctl, arg);
		}
		break;
	}
	}
	out: return r;
}

static int vmmr0_dev_ioctl_create_vm(unsigned long type)
{
	int r;
	struct vm *pvm;

	pvm = vmmr0_create_vm(type);
	if (IS_ERR(pvm))
	{
		return PTR_ERR(pvm);
	}
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
	r = vmmr0_coalesced_mmio_init(pvm);
	if (r < 0)
	{
		vmmr0_put_vm(pvm);
		return r;
	}
#endif
	r = get_vmfd(pvm);
	if (r < 0)
	{
		vmmr0_put_vm(pvm);
	}

	return r;
}

static long vmmr0_dev_ioctl_check_extension_generic(long arg)
{
	switch (arg)
	{
	case KVM_CAP_USER_MEMORY:
	case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
	case KVM_CAP_JOIN_MEMORY_REGIONS_WORKS:
#ifdef CONFIG_KVM_APIC_ARCHITECTURE
		case KVM_CAP_SET_BOOT_CPU_ID:
#endif
	case KVM_CAP_INTERNAL_ERROR_DATA:
		return 1;
#ifdef CONFIG_HAVE_KVM_IRQCHIP
		case KVM_CAP_IRQ_ROUTING:
		return KVM_MAX_IRQ_ROUTES;
#endif
	default:
		break;
	}
	return vmmr0_dev_ioctl_check_extension(arg);
}

static long vmmr0_dev_ioctl(struct file *filp, unsigned int ioctl,
		unsigned long arg)
{
	long r = -EINVAL;

	switch (ioctl)
	{
	case KVM_GET_API_VERSION:
		r = -EINVAL;
		if (arg)
		{
			goto out;
		}
		r = KVM_API_VERSION;
		break;
	case KVM_CREATE_VM:
		r = vmmr0_dev_ioctl_create_vm(arg);
		break;
	case KVM_CHECK_EXTENSION:
		r = vmmr0_dev_ioctl_check_extension_generic(arg);
		break;
	case KVM_GET_VCPU_MMAP_SIZE:
		r = -EINVAL;
		if (arg)
		{
			goto out;
		}
		r = PAGE_SIZE; /* struct vmmr0_run */
#ifdef CONFIG_X86
		r += PAGE_SIZE; /* pio data page */
#endif
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
		r += PAGE_SIZE; /* coalesced mmio ring page */
#endif
		break;
	default:
		return vmmr0_arch_dev_ioctl(filp, ioctl, arg);
	}
	out: return r;
}

static void hardware_enable_nolock(void *junk)
{
	int cpu = raw_smp_processor_id();
	int r;

	if (cpumask_test_cpu(cpu, cpus_hardware_enabled))
	{
		return;
	}

	cpumask_set_cpu(cpu, cpus_hardware_enabled);

	r = vmmr0_arch_hardware_enable(NULL);

	if (r)
	{
		cpumask_clear_cpu(cpu, cpus_hardware_enabled);
		atomic_inc(&hardware_enable_failed);
		printk(KERN_INFO "vmmr0: enabling hwacc on "
			"CPU%d failed\n", cpu);
	}
}

static void hardware_enable(void *junk)
{
	raw_spin_lock(&vmmr0_lock);
	hardware_enable_nolock(junk);
	raw_spin_unlock(&vmmr0_lock);
}

static void hardware_disable_nolock(void *junk)
{
	int cpu = raw_smp_processor_id();

	if (!cpumask_test_cpu(cpu, cpus_hardware_enabled))
	{
		return;
	}
	cpumask_clear_cpu(cpu, cpus_hardware_enabled);
	vmmr0_arch_hardware_disable(NULL);
}

static void hardware_disable(void *junk)
{
	raw_spin_lock(&vmmr0_lock);
	hardware_disable_nolock(junk);
	raw_spin_unlock(&vmmr0_lock);
}

static void hardware_disable_all_nolock(void)
{
	BUG_ON(!vmmr0_usage_count);

	vmmr0_usage_count--;
	if (!vmmr0_usage_count)
	{
		vmmr0_on_each_cpu(hardware_disable_nolock, NULL, 1);
	}
}

static void hardware_disable_all(void)
{
	raw_spin_lock(&vmmr0_lock);
	hardware_disable_all_nolock();
	raw_spin_unlock(&vmmr0_lock);
}

static int hardware_enable_all(void)
{
	int r = 0;

	raw_spin_lock(&vmmr0_lock);

	vmmr0_usage_count++;
	if (vmmr0_usage_count == 1)
	{
		atomic_set(&hardware_enable_failed, 0);
		vmmr0_on_each_cpu(hardware_enable_nolock, NULL, 1);

		if (atomic_read(&hardware_enable_failed))
		{
			hardware_disable_all_nolock();
			r = -EBUSY;
		}
	}

	raw_spin_unlock(&vmmr0_lock);

	return r;
}

asmlinkage void vmmr0_spurious_fault(void)
{
	BUG();
}

static int vmmr0_reboot(void)
{
	/*
	 * Some (well, at least mine) BIOSes hang on reboot if
	 * in vmx root mode.
	 *
	 * And Intel TXT required VMX off for all cpu when system shutdown.
	 */
	printk(KERN_INFO "vmmr0: exiting hwacc\n");
	vmmr0_rebooting = true;
	vmmr0_on_each_cpu(hardware_disable_nolock, NULL, 1);
	return 0;
}

static void vmmr0_io_bus_destroy(struct vmmr0_io_bus *bus)
{
	int i;

	for (i = 0; i < bus->dev_count; i++)
	{
		struct vmmr0_io_device *pos = bus->range[i].dev;

		vmmr0_iodevice_destructor(pos);
	}
	kfree(bus);
}

int vmmr0_io_bus_sort_cmp(const void *p1, const void *p2)
{
	const struct vmmr0_io_range *r1 = p1;
	const struct vmmr0_io_range *r2 = p2;

	if (r1->addr < r2->addr)
	{
		return -1;
	}

	if (r1->addr + r1->len > r2->addr + r2->len)
	{
		return 1;
	}

	return 0;
}

int vmmr0_io_bus_insert_dev(struct vmmr0_io_bus *bus,
		struct vmmr0_io_device *dev, gpa_t addr, int len)
{
	if (bus->dev_count == NR_IOBUS_DEVS)
	{
		return -ENOSPC;
	}

	bus->range[bus->dev_count++] = (struct vmmr0_io_range)
			{
				.addr = addr,
				.len = len,
				.dev = dev,
			};

	sort(bus->range, bus->dev_count, sizeof(struct vmmr0_io_range),
			vmmr0_io_bus_sort_cmp, NULL);

	return 0;
}

int vmmr0_io_bus_get_first_dev(struct vmmr0_io_bus *bus, gpa_t addr, int len)
{
	struct vmmr0_io_range *range, key;
	int off;

	key = (struct vmmr0_io_range)
			{
				.addr = addr,
				.len = len,
			};

	
	range = (struct vmmr0_io_range *)bsearch(&key, bus->range, bus->dev_count,
			sizeof(struct vmmr0_io_range), vmmr0_io_bus_sort_cmp);
	if (range == NULL)
	{
		return -ENOENT;
	}

	off = range - bus->range;

	while (off > 0 && vmmr0_io_bus_sort_cmp(&key, &bus->range[off - 1]) == 0)
	{
		off--;
	}

	return off;
}

int vmmr0_io_bus_write(struct vm *pvm, enum vmmr0_bus bus_idx, gpa_t addr,
		int len, const void *val)
{
	int idx;
	struct vmmr0_io_bus *bus;
	struct vmmr0_io_range range;

	range = (struct vmmr0_io_range)
			{
				.addr = addr,
				.len = len,
			};

	bus = srcu_dereference(pvm->buses[bus_idx], &pvm->srcu);
	idx = vmmr0_io_bus_get_first_dev(bus, addr, len);
	if (idx < 0)
	{
		return -EOPNOTSUPP;
	}

	while (idx < bus->dev_count
			&& vmmr0_io_bus_sort_cmp(&range, &bus->range[idx]) == 0)
	{
		if (!vmmr0_iodevice_write(bus->range[idx].dev, addr, len, val))
		{
			return 0;
		}
		idx++;
	}

	return -EOPNOTSUPP;
}

int vmmr0_io_bus_read(struct vm *pvm, enum vmmr0_bus bus_idx, gpa_t addr,
		int len, void *val)
{
	int idx;
	struct vmmr0_io_bus *bus;
	struct vmmr0_io_range range;

	range = (struct vmmr0_io_range)
			{
				.addr = addr,
				.len = len,
			};

	bus = srcu_dereference(pvm->buses[bus_idx], &pvm->srcu);
	idx = vmmr0_io_bus_get_first_dev(bus, addr, len);
	if (idx < 0)
	{
		return -EOPNOTSUPP;
	}

	while (idx < bus->dev_count
			&& vmmr0_io_bus_sort_cmp(&range, &bus->range[idx]) == 0)
	{
		if (!vmmr0_iodevice_read(bus->range[idx].dev, addr, len, val))
		{
			return 0;
		}
		idx++;
	}

	return -EOPNOTSUPP;
}

int vmmr0_io_bus_register_dev(struct vm *pvm, enum vmmr0_bus bus_idx,
		gpa_t addr, int len, struct vmmr0_io_device *dev)
{
	struct vmmr0_io_bus *new_bus, *bus;

	bus = pvm->buses[bus_idx];
	if (bus->dev_count > NR_IOBUS_DEVS - 1)
	{
		return -ENOSPC;
	}

	new_bus = kmemdup(bus, sizeof(struct vmmr0_io_bus), GFP_KERNEL);
	if (!new_bus)
	{
		return -ENOMEM;
	}
	vmmr0_io_bus_insert_dev(new_bus, dev, addr, len);
	rcu_assign_pointer(pvm->buses[bus_idx], new_bus);
	vmmr0_synchronize_srcu_expedited(&pvm->srcu);
	kfree(bus);

	return 0;
}

int vmmr0_io_bus_unregister_dev(struct vm *pvm, enum vmmr0_bus bus_idx,
		struct vmmr0_io_device *dev)
{
	int i, r;
	struct vmmr0_io_bus *new_bus, *bus;

	bus = pvm->buses[bus_idx];

	new_bus = kmemdup(bus, sizeof(*bus), GFP_KERNEL);
	if (!new_bus)
	{
		return -ENOMEM;
	}

	r = -ENOENT;
	for (i = 0; i < new_bus->dev_count; i++)
	{
		if (new_bus->range[i].dev == dev)
		{
			r = 0;
			new_bus->dev_count--;
			new_bus->range[i] = new_bus->range[new_bus->dev_count];
			sort(new_bus->range, new_bus->dev_count,
					sizeof(struct vmmr0_io_range), vmmr0_io_bus_sort_cmp, NULL);
			break;
		}
	}

	if (r)
	{
		kfree(new_bus);
		return r;
	}

	rcu_assign_pointer(pvm->buses[bus_idx], new_bus);
	vmmr0_synchronize_srcu_expedited(&pvm->srcu);
	kfree(bus);
	return r;
}

struct page *bad_page;
pfn_t bad_pfn;

extern int __init vmx_init(void);
extern void __exit vmx_exit(void);

extern int __init svm_init(void);
extern void __exit svm_exit(void);


void vmmr0_check_hwacc(void)
{
	if (cpu_has_vmx())
	{
		printk(KERN_EMERG"vmmr0: vmmr0_check_hwacc: vmx is available\n");
		hwacc_available = VMX_AVAILABLE;
	}
	else if (cpu_has_svm())
	{
		printk(KERN_EMERG"vmmr0: vmmr0_check_hwacc: svm is available\n");
		hwacc_available = SVM_AVAILABLE;
	}
	else
	{
		printk(KERN_EMERG"vmmr0: vmmr0_check_hwacc: both vmx and svm are unavailable!\n");
		hwacc_available = NOTHING_AVAILABLE;
	}
}

int vmmr0_module_init(void)
{
	vmmr0_check_hwacc();

	if(hwacc_available == VMX_AVAILABLE)
	{
		return vmx_init();
	}
	else if(hwacc_available == SVM_AVAILABLE)
	{
		return svm_init();
	}
	else
	{
		printk(KERN_EMERG"vmmr0: module init error, both vmx and svm are unavailable!\n");
		return -EINVAL;
	}
}

void vmmr0_module_exit(void)
{
	if(hwacc_available == VMX_AVAILABLE)
	{
		vmx_exit();
	}
	else if(hwacc_available == SVM_AVAILABLE)
	{
		svm_exit();
	}
	else
	{
		//won`t be here
	}
}

int vmmr0_init(void *opaque, unsigned vcpu_size, unsigned vcpu_align)
{
	int r;
	int cpu;

	memset(&empty_zero_page, 0, PAGE_SIZE);

	raw_spin_lock_init(&vmmr0_lock);
	raw_spin_lock_init(&vmmr0_vm_slot_lock);
	raw_spin_lock_init(&vmmr0_vcpu_slot_lock);

	r = vmmr0_init_srcu();
	if (r)
	{
		return r;
	}

	r = vmmr0_arch_init(opaque);
	if (r)
	{
		goto out_fail;
	}

	bad_page = alloc_page(GFP_KERNEL | __GFP_ZERO);

	if (bad_page == NULL)
	{
		r = -ENOMEM;
		goto out;
	}

	
	bad_pfn = page_to_pfn(bad_page);

	hwpoison_page = alloc_page(GFP_KERNEL | __GFP_ZERO);

	if (hwpoison_page == NULL)
	{
		r = -ENOMEM;
		goto out_free_0;
	}

	hwpoison_pfn = page_to_pfn(hwpoison_page);

	fault_page = alloc_page(GFP_KERNEL | __GFP_ZERO);

	if (fault_page == NULL)
	{
		r = -ENOMEM;
		goto out_free_0;
	}

	fault_pfn = page_to_pfn(fault_page);

	if (!zalloc_cpumask_var(&cpus_hardware_enabled, GFP_KERNEL))
	{
		r = -ENOMEM;
		goto out_free_0;
	}

	r = vmmr0_arch_hardware_setup();
	if (r < 0)
	{
		goto out_free_0a;
	}

	if (!vcpu_align)
	{
		vcpu_align = __alignof__(struct vmmr0_vcpu);
	}

	r = vmmr0_async_pf_init();
	if (r)
	{
		goto out_free;
	}


	printk("loaded vmmr0-3.11\n");

	vmmr0_clock_warn_suspend_bug();

	return 0;


	out_unreg:
	vmmr0_async_pf_deinit();

	out_free:

	out_free_3:

	out_free_2:
	out_free_1:
	vmmr0_arch_hardware_unsetup();

	out_free_0a:
	free_cpumask_var(cpus_hardware_enabled);

	out_free_0:
	if (fault_page)
	{
		__free_page(fault_page);
	}
	if (hwpoison_page)
	{
		__free_page(hwpoison_page);
	}
	__free_page(bad_page);

	out:
	vmmr0_arch_exit();

	out_fail:
	vmmr0_exit_srcu();
	return r;
}

void vmmr0_exit(void)
{
	vmmr0_async_pf_deinit();

	vmmr0_on_each_cpu(hardware_disable_nolock, NULL, 1);
	vmmr0_arch_hardware_unsetup();
	vmmr0_arch_exit();
	free_cpumask_var(cpus_hardware_enabled);
	__free_page(hwpoison_page);
	__free_page(bad_page);
	vmmr0_exit_srcu();
}

static NTSTATUS bind_vcpu_kick_event(struct vmmr0_vcpu* vcpu, HANDLE event_handle)
{
	NTSTATUS status = 0;
	status = ObReferenceObjectByHandle(event_handle, GENERIC_ALL, NULL, KernelMode, (void **)&vcpu->kick_event, NULL); 
	return status;
}

int vm_slot_index = 0;

typedef struct vmmr0_vm_slot
{
	int in_use;
	int index;
	struct vm* pvm;
	struct list_head list;
}vmmr0_vm_slot;

int get_vmfd(struct vm* pvm)
{
	struct list_head* i;
	struct vmmr0_vm_slot* vmmr0_vm_slot;

	raw_spin_lock(&vmmr0_vm_slot_lock);
	list_for_each(i, &vm_slot_list)
	{
		vmmr0_vm_slot = list_entry(i, struct vmmr0_vm_slot, list);
		if(vmmr0_vm_slot->in_use == 0)
		{
			pvm->vmfd = vmmr0_vm_slot->index;
			vmmr0_vm_slot->in_use = 1;
			vmmr0_vm_slot->pvm = pvm;
			raw_spin_unlock(&vmmr0_vm_slot_lock);
			return pvm->vmfd;
		}
	}
	vmmr0_vm_slot = kmalloc(sizeof(*vmmr0_vm_slot), GFP_KERNEL);

	vmmr0_vm_slot->index = vm_slot_index;
	vmmr0_vm_slot->in_use = 1;
	vmmr0_vm_slot->pvm = pvm;

	pvm->vmfd = vmmr0_vm_slot->index;

	list_add_tail(&vmmr0_vm_slot->list, &vm_slot_list);

	vm_slot_index++;
	current_vm_num++;
	raw_spin_unlock(&vmmr0_vm_slot_lock);
	return pvm->vmfd;
}

int put_vmfd(struct vm* pvm)
{
	struct list_head* i;
	struct vmmr0_vm_slot* vmmr0_vm_slot;
	raw_spin_lock(&vmmr0_vm_slot_lock);

	list_for_each(i, &vm_slot_list)
	{
		vmmr0_vm_slot = list_entry(i, struct vmmr0_vm_slot, list);
		if(vmmr0_vm_slot->pvm == pvm)
		{
			vmmr0_vm_slot->in_use = 0;
			vmmr0_vm_slot->pvm = 0;
			goto out;
		}
	}
	out:
	current_vm_num--;
	raw_spin_unlock(&vmmr0_vm_slot_lock);
	return 0;
}

struct vm* vmfd_to_pvm(int vmfd)
{
	struct list_head* i;
	struct vmmr0_vm_slot* vmmr0_vm_slot;
	raw_spin_lock(&vmmr0_vm_slot_lock);

	list_for_each(i, &vm_slot_list)
	{
		vmmr0_vm_slot = list_entry(i, struct vmmr0_vm_slot, list);
		if(vmmr0_vm_slot->pvm)
		{
			if(vmmr0_vm_slot->pvm->vmfd == vmfd && vmmr0_vm_slot->in_use)
			{
				raw_spin_unlock(&vmmr0_vm_slot_lock);
				return vmmr0_vm_slot->pvm;
			}
		}
	}

	raw_spin_unlock(&vmmr0_vm_slot_lock);
	return 0;
}

int vcpu_slot_index = 0;

typedef struct vmmr0_vcpu_slot
{
	int in_use;
	int index;
	struct vmmr0_vcpu* vcpu;
	struct list_head list;
}vmmr0_vcpu_slot;

int get_vcpufd(struct vmmr0_vcpu* vcpu)
{
	struct list_head* i;
	struct vmmr0_vcpu_slot* vmmr0_vcpu_slot;

	raw_spin_lock(&vmmr0_vcpu_slot_lock);
	list_for_each(i, &vcpu_slot_list)
	{
		vmmr0_vcpu_slot = list_entry(i, struct vmmr0_vcpu_slot, list);
		if(vmmr0_vcpu_slot->in_use == 0)
		{
			vcpu->vcpufd = vmmr0_vcpu_slot->index;
			vmmr0_vcpu_slot->in_use = 1;
			vmmr0_vcpu_slot->vcpu = vcpu;
			raw_spin_unlock(&vmmr0_vcpu_slot_lock);
			return vcpu->vcpufd;
		}
	}
	vmmr0_vcpu_slot = kmalloc(sizeof(*vmmr0_vcpu_slot), GFP_KERNEL);

	vmmr0_vcpu_slot->index = vcpu_slot_index;
	vmmr0_vcpu_slot->in_use = 1;
	vmmr0_vcpu_slot->vcpu = vcpu;

	vcpu->vcpufd = vmmr0_vcpu_slot->index;

	list_add_tail(&vmmr0_vcpu_slot->list, &vcpu_slot_list);

	vcpu_slot_index++;
	raw_spin_unlock(&vmmr0_vcpu_slot_lock);
	return vcpu->vcpufd;
}

int put_vcpufd(struct vmmr0_vcpu* vcpu)
{
	struct list_head* i;
	struct vmmr0_vcpu_slot* vmmr0_vcpu_slot;
	raw_spin_lock(&vmmr0_vcpu_slot_lock);

	list_for_each(i, &vcpu_slot_list)
	{
		vmmr0_vcpu_slot = list_entry(i, struct vmmr0_vcpu_slot, list);
		if(vmmr0_vcpu_slot->vcpu == vcpu)
		{
			vmmr0_vcpu_slot->in_use = 0;
			vmmr0_vcpu_slot->vcpu = 0;
			goto out;
		}
	}
	out:
	raw_spin_unlock(&vmmr0_vcpu_slot_lock);
	return 0;
}

struct vmmr0_vcpu* vcpufd_to_vcpu(int vcpufd)
{
	struct list_head* i;
	struct vmmr0_vcpu_slot* vmmr0_vcpu_slot;
	raw_spin_lock(&vmmr0_vcpu_slot_lock);

	list_for_each(i, &vcpu_slot_list)
	{
		vmmr0_vcpu_slot = list_entry(i, struct vmmr0_vcpu_slot, list);
		if(vmmr0_vcpu_slot->vcpu)
		{
			if(vmmr0_vcpu_slot->vcpu->vcpufd == vcpufd && vmmr0_vcpu_slot->in_use)
			{
				raw_spin_unlock(&vmmr0_vcpu_slot_lock);
				return vmmr0_vcpu_slot->vcpu;
			}
		}
	}

	raw_spin_unlock(&vmmr0_vcpu_slot_lock);
	return 0;
}

typedef struct ioctl_arg
{
	void* arg;
	int fd;
}ioctl_arg;

typedef struct vmem_list
{
	PMDL pmdl;
	PEPROCESS proc;
	int type;
	struct list_head list;
}vmem_list;

#define VMMR0_VMEM_TYPE_MAP    1
#define VMMR0_VMEM_TYPE_LOCK   2

typedef struct kmap_map
{
	u64 addr_virt;
	u64 size;
}kmap_map;

extern u64 max_mdl_describe_length;
extern struct list_head global_vmem_list;
DECLARE_RAW_SPINLOCK(global_vmem_lock);

static int vmmr0_add_vmem_list(PMDL pmdl, int type)
{
	int r = 0;
	struct vmem_list* vmem_list;
	vmem_list = ExAllocatePool(NonPagedPool, sizeof(*vmem_list));
	if(!vmem_list)
	{
		goto out_error;
	}
	vmem_list->pmdl = pmdl;
	vmem_list->proc = IoGetCurrentProcess();
	vmem_list->type = type;
	raw_spin_lock(&global_vmem_lock);
	list_add_tail(&vmem_list->list, &global_vmem_list);
	raw_spin_unlock(&global_vmem_lock);
	return r;

	out_error:
	r = -1;
	return r;
}

static unsigned long vmmr0_map_pages(void* addr, unsigned long size)
{
	PMDL pmdl = 0;
	PVOID user_va = 0;
	struct vmem_list* vmem_list;

	pmdl = IoAllocateMdl(addr, size, 0, 0, 0);
	if(!pmdl)
	{
		goto out_error;
	}
	MmBuildMdlForNonPagedPool(pmdl);
	user_va = MmMapLockedPagesSpecifyCache(pmdl, UserMode, MmNonCached, 0, 0, NormalPagePriority);
	if(!user_va)
	{
		goto out_free_mdl;
	}
	if(vmmr0_add_vmem_list(pmdl, VMMR0_VMEM_TYPE_MAP))
	{
		goto out_free_mdl;
	}
	return (unsigned long)user_va;

	out_free_mdl:
	IoFreeMdl(pmdl);
	out_error:
	user_va = 0;
	return (unsigned long)user_va;
}

static unsigned long map_vmmr0_run(struct vmmr0_vcpu* vcpu)
{
	return vmmr0_map_pages(vcpu->run, 7 * PAGE_SIZE);
}

static unsigned long map_vmmr0_coalesced_mmio(struct vmmr0_vcpu* vcpu)
{
	return vmmr0_map_pages(vcpu->pvm->coalesced_mmio_ring, PAGE_SIZE);
}

static int vmmr0_lock_user_pages(PVOID addr, ULONG length)
{
	int r;
	PMDL pmdl;
	HANDLE h;
	pmdl = IoAllocateMdl(addr, length, 0, 0, 0);
	if(!pmdl)
	{
		goto out_err;
	}
	MmProbeAndLockPages(pmdl, UserMode, IoModifyAccess);
	if(!(pmdl->MdlFlags & MDL_PAGES_LOCKED))
	{
		goto out_free_mdl;
	}
	h = MmSecureVirtualMemory(addr, length, PAGE_READWRITE);
	if(h == NULL)
	{
		goto out_free_mdl;
	}

	r = vmmr0_add_vmem_list(pmdl, VMMR0_VMEM_TYPE_LOCK);
	return r;

	out_free_mdl:
	IoFreeMdl(pmdl);
	out_err:
	r = -1;
	return r;
}

static int vmmr0_lock_user_memory(struct kmap_map* kmap_map)
{
	int r;
	struct vmem_list* vmem_list;
	PMDL pmdl;
	PVOID per_addr = 0;
	u64 remain_size = 0;
	u64 per_size = 0;

	if(!kmap_map)
	{
		r = -1;
		goto out;
	}
	per_addr = (PVOID)(unsigned long)(kmap_map->addr_virt);
	remain_size = kmap_map->size;

	while(remain_size > 0)
	{
		if(remain_size > max_mdl_describe_length)
		{
			per_size = max_mdl_describe_length;
		}
		else
		{
			per_size = remain_size;
		}
		remain_size -= per_size;
		r = vmmr0_lock_user_pages(per_addr, per_size);
		if(r)
		{
			goto out;
		}
		per_addr += per_size;
	}
	r = set_user_pages(kmap_map->addr_virt, kmap_map->size);
	out:
	return r;
}

static int vmmr0_set_user_memory(struct kmap_map* kmap_map)
{
	int r;
	if(!kmap_map)
	{
		r = -1;
		goto out;
	}
	r = set_user_pages(kmap_map->addr_virt, kmap_map->size);
	out:
	return r;
}

static void vmmr0_unlock_user_memory(PEPROCESS current_proc)
{
	struct vmem_list* vmem_list;
	struct list_head* i, *n;
	raw_spin_lock(&global_vmem_lock);
	list_for_each_safe(i, n, &global_vmem_list)
	{
		vmem_list = list_entry(i, struct vmem_list, list);
		if (vmem_list->proc == current_proc)
		{
			switch(vmem_list->type)
			{
			case VMMR0_VMEM_TYPE_MAP:
				IoFreeMdl(vmem_list->pmdl);
				list_del(&vmem_list->list);
				ExFreePool(vmem_list);
				break;
			case VMMR0_VMEM_TYPE_LOCK:
				MmUnlockPages(vmem_list->pmdl);
				IoFreeMdl(vmem_list->pmdl);
				list_del(&vmem_list->list);
				ExFreePool(vmem_list);
				break;
			default:
				break;
			}
		}
	}
	raw_spin_unlock(&global_vmem_lock);
	clean_user_pages();
}

static void vmmr0_cleanup_vm(PEPROCESS current_proc)
{
	struct vm *pvm;
	raw_spin_lock(&vmmr0_lock);
	list_for_each_entry(pvm, &vm_list, vm_list)
	{
		if(pvm->proc == current_proc)
		{
			pvm->open_count--;
			if(!pvm->open_count)
			{
				raw_spin_unlock(&vmmr0_lock);
				vmmr0_destroy_vm(pvm);
				vmmr0_unlock_user_memory(current_proc);
			}
			else
			{
				raw_spin_unlock(&vmmr0_lock);
			}
			return;
		}
	}
	raw_spin_unlock(&vmmr0_lock);
}

static void vmmr0_cleanup(void)
{
	vmmr0_cleanup_vm(IoGetCurrentProcess());
}

static void vmmr0_increase_open_count(void)
{
	struct vm *pvm;
	PEPROCESS current_proc = IoGetCurrentProcess();

	raw_spin_lock(&vmmr0_lock);
	list_for_each_entry(pvm, &vm_list, vm_list)
	{
		if(pvm->proc == current_proc)
		{
			pvm->open_count++;
			raw_spin_unlock(&vmmr0_lock);
			return;
		}
	}
	raw_spin_unlock(&vmmr0_lock);
}

#define VMMModuleName "\\\\.\\vmmr0"
#define VMMR0ServiceName "vmmr0"
#define VMMR0ServicePath "vmmr0.sys"
#define NT_DEVICE_NAME           L"\\Device\\vmmr0"
#define DOS_DEVICE_NAME          L"\\DosDevices\\vmmr0"

typedef struct _DEVICE_EXTENSION
{
	PDEVICE_OBJECT pDevice;
	UNICODE_STRING ustrDeviceName;
	UNICODE_STRING ustrSymLinkName;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

NTSTATUS __stdcall vmmr0_dispatch_routine(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;	// bytes xfered
	IoCompleteRequest( pIrp, IO_NO_INCREMENT );
	return status;
}

NTSTATUS __stdcall vmmr0_dispatch_create(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;

	vmmr0_increase_open_count();

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;	// bytes xfered
	IoCompleteRequest( pIrp, IO_NO_INCREMENT );
	return status;
}

NTSTATUS __stdcall vmmr0_dispatch_cleanup(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;	// bytes xfered
	IoCompleteRequest( pIrp, IO_NO_INCREMENT );
	return status;
}

NTSTATUS __stdcall vmmr0_dispatch_close(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	int cpu;

	KAFFINITY old_affinity;
	KAFFINITY new_affinity;
	KIRQL irql;

	KeRaiseIrql(DISPATCH_LEVEL, &irql);

	new_affinity = 1 << smp_processor_id();
	old_affinity = KeSetSystemAffinityThreadEx(new_affinity);

	KeLowerIrql(PASSIVE_LEVEL);

	KeRaiseIrql(DISPATCH_LEVEL, &irql);
	for_each_possible_cpu(cpu)
	{
		mutex_lock(&vmm_lock[cpu]);
	}

	hardware_enable_nolock(0);
	vmmr0_cleanup();
	hardware_disable_nolock(0);

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;	// bytes xfered
	IoCompleteRequest( pIrp, IO_NO_INCREMENT );

	for_each_possible_cpu(cpu)
	{
		mutex_unlock(&vmm_lock[cpu]);
	}

	KeLowerIrql(PASSIVE_LEVEL);
	KeRevertToUserAffinityThreadEx(old_affinity);
	return status;

}

NTSTATUS __stdcall vmmr0_dispatch_ioctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	int r;
	struct file file;
	struct ioctl_arg* argp;
	NTSTATUS ntStatus = STATUS_SUCCESS;//STATUS_UNSUCCESSFUL;//
	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	ULONG inBufLength = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG outBufLength =pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	PVOID OutputBuffer = pIrp->UserBuffer;
	PVOID InputBuffer  = pIrp->AssociatedIrp.SystemBuffer;

	argp = InputBuffer;

	KIRQL irql;

	KeRaiseIrql(DISPATCH_LEVEL, &irql);

	__get_cpu_var(new_affinity) = 1 << smp_processor_id();
	__get_cpu_var(old_affinity) = KeSetSystemAffinityThreadEx(__get_cpu_var(new_affinity));

	KeLowerIrql(PASSIVE_LEVEL);

	mutex_lock(&__get_cpu_var(vmm_lock));

	hardware_enable_nolock(0);

	switch(uIoControlCode)
	{
	case KVM_RUN:
	case KVM_GET_REGS:
	case KVM_SET_REGS:
	case KVM_GET_SREGS:
	case KVM_SET_SREGS:
	case KVM_GET_MP_STATE:
	case KVM_SET_MP_STATE:
	case KVM_TRANSLATE:
	case KVM_SET_GUEST_DEBUG:
	case KVM_SET_SIGNAL_MASK:
	case KVM_GET_FPU:
	case KVM_SET_FPU:
	case KVM_GET_LAPIC:
	case KVM_SET_LAPIC:
	case KVM_INTERRUPT:
	case KVM_NMI:
	case KVM_SET_CPUID:
	case KVM_SET_CPUID2:
	case KVM_GET_CPUID2:
	case KVM_GET_MSRS:
	case KVM_SET_MSRS:
	case KVM_TPR_ACCESS_REPORTING:
	case KVM_SET_VAPIC_ADDR:
	case KVM_X86_SETUP_MCE:
	case KVM_X86_SET_MCE:
	case KVM_GET_VCPU_EVENTS:
	case KVM_SET_VCPU_EVENTS:
	case KVM_GET_DEBUGREGS:
	case KVM_SET_DEBUGREGS:
	case KVM_GET_XSAVE:
	case KVM_SET_XSAVE:
	case KVM_GET_XCRS:
	case KVM_SET_XCRS:
	case KVM_SET_TSC_KHZ:
	case KVM_GET_TSC_KHZ:
		file.private_data = vcpufd_to_vcpu(argp->fd);
		if(file.private_data)
		{
			r = vmmr0_vcpu_ioctl(&file, uIoControlCode, (unsigned long)argp->arg);
		}
		else
		{
			printk("vmmr0: fatal: vcpufd_to_vcpu return 0, ioctl code = %x\n", uIoControlCode);
			r = -1;
		}
		break;
	case KVM_GET_KVM_RUN:
		file.private_data = vcpufd_to_vcpu(argp->fd);
		if(file.private_data)
		{
			*(unsigned long* )OutputBuffer = map_vmmr0_run((struct vmmr0_vcpu*)file.private_data);
			*(unsigned long* )InputBuffer = *(unsigned long* )OutputBuffer;
			goto out;
		}
		else
		{
			printk("vmmr0: fatal: vcpufd_to_vcpu return 0, ioctl code = %x\n", uIoControlCode);
			r = -1;
		}
		break;
	case KVM_GET_KVM_COALESCED_MMIO:
		file.private_data = vcpufd_to_vcpu(argp->fd);
		if(file.private_data)
		{
			*(unsigned long* )OutputBuffer = map_vmmr0_coalesced_mmio((struct vmmr0_vcpu*)file.private_data);
			*(unsigned long* )InputBuffer = *(unsigned long* )OutputBuffer;
			goto out;
		}
		else
		{
			printk("vmmr0: fatal: vcpufd_to_vcpu return 0, ioctl code = %x\n", uIoControlCode);
			r = -1;
		}
		break;
	case KVM_BIND_EVENT:
		file.private_data = vcpufd_to_vcpu(argp->fd);
		if(file.private_data)
		{
			ntStatus = bind_vcpu_kick_event((struct vmmr0_vcpu*)file.private_data, *(HANDLE *)argp->arg);
			goto out;
		}
		else
		{
			printk("vmmr0: fatal: vcpufd_to_vcpu return 0, ioctl code = %x\n", uIoControlCode);
			r = -1;
		}
		break;
	case KVM_ALLOC_KMEM:
		*(unsigned long* )OutputBuffer = vmmr0_set_user_memory((struct kmap_map *)argp->arg);
		*(unsigned long* )InputBuffer = *(unsigned long* )OutputBuffer;
		goto out;
		break;
	case KVM_FREE_KMEM:
		//not here
		break;
	case KVM_GET_API_VERSION:
	case KVM_CREATE_VM:
	case KVM_CHECK_EXTENSION:
	case KVM_GET_VCPU_MMAP_SIZE:
	case KVM_GET_MSR_INDEX_LIST:
	case KVM_GET_SUPPORTED_CPUID:
	case KVM_X86_GET_MCE_CAP_SUPPORTED:
		r = vmmr0_dev_ioctl(&file, uIoControlCode, (unsigned long)argp->arg);
		break;
	case KVM_CREATE_VCPU:
	case KVM_SET_USER_MEMORY_REGION:
	case KVM_GET_DIRTY_LOG:
	case KVM_REGISTER_COALESCED_MMIO:
	case KVM_UNREGISTER_COALESCED_MMIO:
	case KVM_IRQFD:
	case KVM_IOEVENTFD:
	case KVM_SET_BOOT_CPU_ID:
	case KVM_SET_TSS_ADDR:
	case KVM_SET_IDENTITY_MAP_ADDR:
	case KVM_SET_NR_MMU_PAGES:
	case KVM_GET_NR_MMU_PAGES:
	case KVM_CREATE_IRQCHIP:
	case KVM_CREATE_PIT:
	case KVM_CREATE_PIT2:
	case KVM_IRQ_LINE_STATUS:
	case KVM_IRQ_LINE:
	case KVM_GET_IRQCHIP:
	case KVM_SET_IRQCHIP:
	case KVM_GET_PIT:
	case KVM_SET_PIT:
	case KVM_GET_PIT2:
	case KVM_SET_PIT2:
	case KVM_REINJECT_CONTROL:
	case KVM_SET_CLOCK:
	case KVM_GET_CLOCK:
	case KVM_ASSIGN_PCI_DEVICE:
	case KVM_ASSIGN_IRQ:
	case KVM_ASSIGN_DEV_IRQ:
	case KVM_DEASSIGN_DEV_IRQ:
	case KVM_DEASSIGN_PCI_DEVICE:
	case KVM_SET_GSI_ROUTING:
	case KVM_ASSIGN_SET_MSIX_NR:
	case KVM_ASSIGN_SET_MSIX_ENTRY:
	case KVM_ASSIGN_SET_INTX_MASK:
		file.private_data = vmfd_to_pvm(argp->fd);
		if(file.private_data)
		{
			r = vmmr0_vm_ioctl(&file, uIoControlCode, (unsigned long)argp->arg);
		}
		else
		{
			printk("vmmr0: fatal: vmfd_to_pvm return 0, ioctl code = %x\n", uIoControlCode);
			r = -1;
		}
		break;
	default:
		DbgPrint("IOConTrolCode:  %d\nInBuffer:  %d\n", uIoControlCode, *(unsigned int*)(pIrp->AssociatedIrp.SystemBuffer));
	}

	*(int* )OutputBuffer = r;
	*(int* )InputBuffer = r;

out:
	pIrp->IoStatus.Status = ntStatus;
	pIrp->IoStatus.Information = outBufLength;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	hardware_disable_nolock(0);
	mutex_unlock(&__get_cpu_var(vmm_lock));
	KeRevertToUserAffinityThreadEx(__get_cpu_var(old_affinity));
	return ntStatus;
}

void __stdcall DriverUnload (PDRIVER_OBJECT pDriverObject)
{
	PDEVICE_OBJECT    pDeviceObject = pDriverObject->DeviceObject;
	UNICODE_STRING    uniSymLink;
	RtlInitUnicodeString(&uniSymLink, DOS_DEVICE_NAME);

	IoDeleteSymbolicLink(&uniSymLink);
	IoDeleteDevice(pDeviceObject);

	printk("vmmr0 unload");
	vmmr0_module_exit();
	uninit_windows_runtime();
}

NTSTATUS __stdcall DriverEntry (
			 PDRIVER_OBJECT pDriverObject,
			 PUNICODE_STRING pRegistryPath	)
{
	int i;
	NTSTATUS status;
	UNICODE_STRING   uniDeviceName;
	UNICODE_STRING   uniSymLink;
	PDEVICE_OBJECT   pDeviceObject = NULL;
	RtlInitUnicodeString(&uniDeviceName, NT_DEVICE_NAME);
	RtlInitUnicodeString(&uniSymLink, DOS_DEVICE_NAME);


	printk("vmmr0 load");

	if(init_windows_runtime())
	{
		status = STATUS_NOT_SUPPORTED;
		goto out_error;
	}

	if(vmmr0_module_init())
	{
		status = STATUS_NOT_SUPPORTED;
		goto out_error_uninit;
	}

	for(i = 0; i < NR_CPUS; i++)
	{
		mutex_init(&vmm_lock[i]);
	}

	pDriverObject->DriverUnload=DriverUnload;
	pDriverObject->MajorFunction[IRP_MJ_CLEANUP] = vmmr0_dispatch_cleanup;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = vmmr0_dispatch_create;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = vmmr0_dispatch_close;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = vmmr0_dispatch_routine;
	pDriverObject->MajorFunction[IRP_MJ_READ] = vmmr0_dispatch_routine;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = vmmr0_dispatch_ioctl;

	status = IoCreateDevice(pDriverObject, 0,&uniDeviceName,FILE_DEVICE_UNKNOWN,
									FILE_DEVICE_SECURE_OPEN, FALSE,&pDeviceObject);
	if (!NT_SUCCESS(status))
	{
		goto out_error_uninit;
	}

	status = IoCreateSymbolicLink(&uniSymLink, &uniDeviceName);

	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDeviceObject);
		goto out_error_uninit;
	}

    return STATUS_SUCCESS;

	out_error_uninit:
	uninit_windows_runtime();
	out_error:
	return status;
}
