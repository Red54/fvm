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
 * vmmr0-linux.c
 *
 * this code is based on kvm-kmod.
 *
 * author : 
 *   范文一 （Wincy Van） <fanwenyi0529@live.com> <QQ:362478911>
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
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

#define VMMR0_MINOR MISC_DYNAMIC_MINOR

MODULE_INFO(version, "vmmr0-0.1");
MODULE_AUTHOR("fw1");
MODULE_LICENSE("GPL");

/*
 * Ordering of locks:
 *
 * 		vmmr0->lock --> vmmr0->slots_lock --> vmmr0->irq_lock
 */

DEFINE_RAW_SPINLOCK( vmmr0_lock);
LIST_HEAD( vm_list);

enum
{
	VMX_AVAILABLE, SVM_AVAILABLE, NOTHING_AVAILABLE
};

static int hwacc_available = VMX_AVAILABLE;

static cpumask_var_t cpus_hardware_enabled;
static int vmmr0_usage_count = 0;
static atomic_t hardware_enable_failed;

#ifdef HOST_LINUX_OPTIMIZED
struct kmem_cache *vmmr0_vcpu_cache;
#endif

static __read_mostly struct preempt_ops vmmr0_preempt_ops;

struct dentry *vmmr0_debugfs_dir;

static long vmmr0_vcpu_ioctl(struct file *file, unsigned int ioctl,
		unsigned long arg);
#ifdef CONFIG_COMPAT
static long vmmr0_vcpu_compat_ioctl(struct file *file, unsigned int ioctl,
		unsigned long arg);
#endif
static int hardware_enable_all(void);
static void hardware_disable_all(void);

static void vmmr0_io_bus_destroy(struct vmmr0_io_bus *bus);

bool vmmr0_rebooting;

static bool largepages_enabled = true;

static struct page *hwpoison_page;
static pfn_t hwpoison_pfn;

struct page *fault_page;
pfn_t fault_pfn;

inline int vmmr0_is_mmio_pfn(pfn_t pfn)
{
	if (pfn_valid(pfn))
	{
		int reserved;
		struct page *tail = pfn_to_page(pfn);
		struct page *head = compound_trans_head(tail);
		reserved = PageReserved(head);
		if (head != tail)
		{
			smp_rmb();
			if (PageTail(tail))
			{
				return reserved;
			}
		}
		return PageReserved(tail);
	}

	return true;
}

//Switches to specified vcpu, until a matching vcpu_put()

void vcpu_load(struct vmmr0_vcpu *vcpu)
{
	int cpu;

	mutex_lock(&vcpu->mutex);
#ifdef OS_LINUX_OPTIMIZED_PID
	if (unlikely(vcpu->pid != current->pids[PIDTYPE_PID].pid))
	{
		// The thread running this VCPU changed.
		struct pid *oldpid = vcpu->pid;
		struct pid *newpid = vmmr0_get_task_pid(current, PIDTYPE_PID);
		rcu_assign_pointer(vcpu->pid, newpid);
		synchronize_rcu();
		vmmr0_put_pid(oldpid);
	}
#endif

	cpu = get_cpu();
	preempt_notifier_register(&vcpu->preempt_notifier);
	vmmr0_arch_vcpu_load(vcpu, cpu);
	put_cpu();
}

void vcpu_put(struct vmmr0_vcpu *vcpu)
{
	preempt_disable();
	vmmr0_arch_vcpu_put(vcpu);
	vmmr0_fire_urn();
	preempt_notifier_unregister(&vcpu->preempt_notifier);
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
	struct page *page;
	int r;

	mutex_init(&vcpu->mutex);
	vcpu->cpu = -1;
	vcpu->pvm = pvm;
	vcpu->vcpu_id = id;
#ifdef OS_LINUX_OPTIMIZED_PID
	vcpu->pid = NULL;
#endif

#ifdef HOST_LINUX_OPTIMIZED
	init_waitqueue_head(&vcpu->wq);
#endif

	vmmr0_async_pf_vcpu_init(vcpu);

	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
	{
		r = -ENOMEM;
		goto fail;
	}
	vcpu->run = page_address(page);

	r = vmmr0_arch_vcpu_init(vcpu);
	if (r < 0)
	{
		goto fail_free_run;
	}
	return 0;

	fail_free_run:
	free_page((unsigned long) vcpu->run);

	fail: return r;
}

void vmmr0_vcpu_uninit(struct vmmr0_vcpu *vcpu)
{
#ifdef OS_LINUX_OPTIMIZED_PID
	vmmr0_put_pid(vcpu->pid);
#endif
	vmmr0_arch_vcpu_uninit(vcpu);
	free_page((unsigned long) vcpu->run);
}

#if defined(CONFIG_MMU_NOTIFIER) && defined(KVM_ARCH_WANT_MMU_NOTIFIER)
static inline struct vm *mmu_notifier_to_vm(struct mmu_notifier *mn)
{
	return container_of(mn, struct vm, mmu_notifier);
}

static void vmmr0_mmu_notifier_invalidate_page(struct mmu_notifier *mn,
		struct mm_struct *mm,
		unsigned long address)
{
	struct vm *pvm = mmu_notifier_to_vm(mn);
	int need_tlb_flush, idx;

	//printk(KERN_EMERG"vmmr0: vmmr0_mmu_notifier_invalidate_page\n");
	/*
	 * When ->invalidate_page runs, the linux pte has been zapped
	 * already but the page is still allocated until
	 * ->invalidate_page returns. So if we increase the sequence
	 * here the vmmr0 page fault will notice if the spte can't be
	 * established because the page is going to be freed. If
	 * instead the vmmr0 page fault establishes the spte before
	 * ->invalidate_page runs, vmmr0_unmap_hva will release it
	 * before returning.
	 *
	 * The sequence increase only need to be seen at spin_unlock
	 * time, and not at spin_lock time.
	 *
	 * Increasing the sequence after the spin_unlock would be
	 * unsafe because the vmmr0 page fault could then establish the
	 * pte after vmmr0_unmap_hva returned, without noticing the page
	 * is going to be freed.
	 */
	idx = srcu_read_lock(&pvm->srcu);
	spin_lock(&pvm->mmu_lock);

	pvm->mmu_notifier_seq++;
	need_tlb_flush = vmmr0_unmap_hva(pvm, address) | pvm->tlbs_dirty;
	/* we've to flush the tlb before the pages can be freed */
	if (need_tlb_flush)
	{
		vmmr0_flush_remote_tlbs(pvm);
	}

	spin_unlock(&pvm->mmu_lock);
	srcu_read_unlock(&pvm->srcu, idx);
}

#ifdef MMU_NOTIFIER_HAS_CHANGE_PTE
static
#endif
void vmmr0_mmu_notifier_change_pte(struct mmu_notifier *mn,
		struct mm_struct *mm,
		unsigned long address,
		pte_t pte)
{
	struct vm *pvm = mmu_notifier_to_vm(mn);
	int idx;

	//printk(KERN_EMERG"vmmr0: vmmr0_mmu_notifier_change_pte\n");

	idx = srcu_read_lock(&pvm->srcu);
	spin_lock(&pvm->mmu_lock);
	pvm->mmu_notifier_seq++;
	vmmr0_set_spte_hva(pvm, address, pte);
	spin_unlock(&pvm->mmu_lock);
	srcu_read_unlock(&pvm->srcu, idx);
}

static void vmmr0_mmu_notifier_invalidate_range_start(struct mmu_notifier *mn,
		struct mm_struct *mm,
		unsigned long start,
		unsigned long end)
{
	struct vm *pvm = mmu_notifier_to_vm(mn);
	int need_tlb_flush = 0, idx;

	//printk(KERN_EMERG"vmmr0: vmmr0_mmu_notifier_invalidate_range_start\n");

	idx = srcu_read_lock(&pvm->srcu);
	spin_lock(&pvm->mmu_lock);
	/*
	 * The count increase must become visible at unlock time as no
	 * spte can be established without taking the mmu_lock and
	 * count is also read inside the mmu_lock critical section.
	 */
	pvm->mmu_notifier_count++;
	for (; start < end; start += PAGE_SIZE)
	{
		need_tlb_flush |= vmmr0_unmap_hva(pvm, start);
	}
	need_tlb_flush |= pvm->tlbs_dirty;
	/* we've to flush the tlb before the pages can be freed */
	if (need_tlb_flush)
	{
		vmmr0_flush_remote_tlbs(pvm);
	}

	spin_unlock(&pvm->mmu_lock);
	srcu_read_unlock(&pvm->srcu, idx);
}

static void vmmr0_mmu_notifier_invalidate_range_end(struct mmu_notifier *mn,
		struct mm_struct *mm,
		unsigned long start,
		unsigned long end)
{
	struct vm *pvm = mmu_notifier_to_vm(mn);

	//printk(KERN_EMERG"vmmr0: vmmr0_mmu_notifier_invalidate_range_end\n");

	spin_lock(&pvm->mmu_lock);
	/*
	 * This sequence increase will notify the vmmr0 page fault that
	 * the page that is going to be mapped in the spte could have
	 * been freed.
	 */
	pvm->mmu_notifier_seq++;
	smp_wmb();
	/*
	 * The above sequence increase must be visible before the
	 * below count decrease, which is ensured by the smp_wmb above
	 * in conjunction with the smp_rmb in mmu_notifier_retry().
	 */
	pvm->mmu_notifier_count--;
	spin_unlock(&pvm->mmu_lock);

	BUG_ON(pvm->mmu_notifier_count < 0);
}

static int vmmr0_mmu_notifier_clear_flush_young(struct mmu_notifier *mn,
		struct mm_struct *mm,
		unsigned long address)
{
	struct vm *pvm = mmu_notifier_to_vm(mn);
	int young, idx;

	//printk(KERN_EMERG"vmmr0: vmmr0_mmu_notifier_clear_flush_young\n");

	idx = srcu_read_lock(&pvm->srcu);
	spin_lock(&pvm->mmu_lock);

	young = vmmr0_age_hva(pvm, address);
	if (young)
	vmmr0_flush_remote_tlbs(pvm);

	spin_unlock(&pvm->mmu_lock);
	srcu_read_unlock(&pvm->srcu, idx);

	return young;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38)
static int vmmr0_mmu_notifier_test_young(struct mmu_notifier *mn,
		struct mm_struct *mm,
		unsigned long address)
{
	struct vm *pvm = mmu_notifier_to_vm(mn);
	int young, idx;

	//printk(KERN_EMERG"vmmr0: vmmr0_mmu_notifier_test_young\n");

	idx = srcu_read_lock(&pvm->srcu);
	spin_lock(&pvm->mmu_lock);
	young = vmmr0_test_age_hva(pvm, address);
	spin_unlock(&pvm->mmu_lock);
	srcu_read_unlock(&pvm->srcu, idx);

	return young;
}
#endif

static void vmmr0_mmu_notifier_release(struct mmu_notifier *mn,
		struct mm_struct *mm)
{
	struct vm *pvm = mmu_notifier_to_vm(mn);
	int idx;

	//printk(KERN_EMERG"vmmr0: vmmr0_mmu_notifier_release\n");

	idx = srcu_read_lock(&pvm->srcu);
	vmmr0_arch_flush_shadow(pvm);
	srcu_read_unlock(&pvm->srcu, idx);
}

static const struct mmu_notifier_ops vmmr0_mmu_notifier_ops =
{
	.invalidate_page = vmmr0_mmu_notifier_invalidate_page,
	.invalidate_range_start = vmmr0_mmu_notifier_invalidate_range_start,
	.invalidate_range_end = vmmr0_mmu_notifier_invalidate_range_end,
	.clear_flush_young = vmmr0_mmu_notifier_clear_flush_young,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38)
	.test_young = vmmr0_mmu_notifier_test_young,
#endif
#ifdef MMU_NOTIFIER_HAS_CHANGE_PTE
	.change_pte = vmmr0_mmu_notifier_change_pte,
#endif
	.release = vmmr0_mmu_notifier_release,
};

static int vmmr0_init_mmu_notifier(struct vm *pvm)
{
	pvm->mmu_notifier.ops = &vmmr0_mmu_notifier_ops;
	return mmu_notifier_register(&pvm->mmu_notifier, current->mm);
}

#else  /* !(CONFIG_MMU_NOTIFIER && KVM_ARCH_WANT_MMU_NOTIFIER) */

static int vmmr0_init_mmu_notifier(struct vm *pvm)
{
	return 0;
}

#endif /* CONFIG_MMU_NOTIFIER && KVM_ARCH_WANT_MMU_NOTIFIER */

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
#ifdef OS_LINUX_OPTIMIZED_MM
	pvm->mm = current->mm;
	mmget(&pvm->mm->mm_count);
#endif
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
#ifdef OS_LINUX_OPTIMIZED_MM
	struct mm_struct *mm = pvm->mm;
#endif

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

#if defined(CONFIG_MMU_NOTIFIER) && defined(KVM_ARCH_WANT_MMU_NOTIFIER)
	mmu_notifier_unregister(&pvm->mmu_notifier, pvm->mm);
#else
	vmmr0_arch_flush_shadow(pvm);
#endif
	vmmr0_arch_destroy_vm(pvm);
	vmmr0_free_physmem(pvm);
	cleanup_srcu_struct(&pvm->srcu);
	vmmr0_arch_free_vm(pvm);
	hardware_disable_all();
#ifdef OS_LINUX_OPTIMIZED_MM
	mmdrop(mm);
#endif
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

static int vmmr0_vm_release(struct inode *inode, struct file *filp)
{
	struct vm *pvm = filp->private_data;

	vmmr0_irqfd_release(pvm);

	vmmr0_put_vm(pvm);
	return 0;
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
							(void *) (unsigned long) mem->userspace_addr,
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
	struct vm_area_struct *vma;
	unsigned long addr, size;

	size = PAGE_SIZE;

	addr = mmu_gfn_to_hva(pvm, gfn);
	if (vmmr0_is_error_hva(addr))
	{
		return PAGE_SIZE;
	}

	down_read(&current->mm->mmap_sem);
	vma = find_vma(current->mm, addr);
	if (!vma)
	{
		goto out;
	}

	size = vmmr0_vma_kernel_pagesize(vma);

	out:
	up_read(&current->mm->mmap_sem);

	return size;
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

static pfn_t get_fault_pfn(void)
{
	get_page(fault_page);
	return fault_pfn;
}

int get_user_page_nowait(struct task_struct *tsk, struct mm_struct *mm,
		unsigned long start, int write, struct page **page)
{
	int flags = FOLL_TOUCH | FOLL_NOWAIT | FOLL_HWPOISON | FOLL_GET;

	if (write)
	{
		flags |= FOLL_WRITE;
	}

	return __get_user_pages(tsk, mm, start, 1, flags, page, NULL, NULL);
}

static inline int check_user_page_hwpoison(unsigned long addr)
{
	int rc, flags = FOLL_TOUCH | FOLL_HWPOISON | FOLL_WRITE;

	rc = __get_user_pages(current, current->mm, addr, 1, flags, NULL, NULL,
			NULL);
	return rc == -EHWPOISON;
}

static pfn_t hva_to_pfn(struct vm *pvm, unsigned long addr, bool atomic,
		bool *async, bool write_fault, bool *writable)
{
	struct page *page[1];
	int npages = 0;
	pfn_t pfn;

	/* we can do it either atomically or asynchronously, not both */
	BUG_ON(atomic && async);

	BUG_ON(!write_fault && !writable);

	if (writable)
	{
		*writable = true;
	}

	if (atomic || async)
	{
		npages = vmmr0___get_user_pages_fast(addr, 1, 1, page);
	}

	if (unlikely(npages != 1) && !atomic)
	{
		might_sleep();

		if (writable)
		{
			*writable = write_fault;
		}

		if (async)
		{
			down_read(&current->mm->mmap_sem);
			npages = get_user_page_nowait(current, current->mm, addr,
					write_fault, page);
			up_read(&current->mm->mmap_sem);
		}
		else
		{
			npages = get_user_pages_fast(addr, 1, write_fault, page);
		}

		if (unlikely(!write_fault) && npages == 1)
		{
			struct page *wpage[1];

			npages = vmmr0___get_user_pages_fast(addr, 1, 1, wpage);
			if (npages == 1)
			{
				*writable = true;
				put_page(page[0]);
				page[0] = wpage[0];
			}
			npages = 1;
		}
	}

	if (unlikely(npages != 1))
	{
		struct vm_area_struct *vma;

		if (atomic)
		{
			return get_fault_pfn();
		}

		down_read(&current->mm->mmap_sem);
		if (npages == -EHWPOISON || (!async && check_user_page_hwpoison(addr)))
		{
			up_read(&current->mm->mmap_sem);
			get_page(hwpoison_page);
			return page_to_pfn(hwpoison_page);
		}

		vma = find_vma_intersection(current->mm, addr, addr + 1);

		if (vma == NULL)
		{
			pfn = get_fault_pfn();
		}
		else if ((vma->vm_flags & VM_PFNMAP))
		{
			pfn = ((addr - vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff;
			BUG_ON(!vmmr0_is_mmio_pfn(pfn));
		}
		else
		{
			if (async && (vma->vm_flags & VM_WRITE))
			{
				*async = true;
			}
			pfn = get_fault_pfn();
		}
		up_read(&current->mm->mmap_sem);
	}
	else
	{
		pfn = page_to_pfn(page[0]);
	}

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
	async = NULL;
#endif
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
	if (!vmmr0_is_mmio_pfn(pfn))
	{
		struct page *page = pfn_to_page(pfn);
		if (!PageReserved(page))
		{
			SetPageDirty(page);
		}
	}
}

void vmmr0_set_pfn_accessed(pfn_t pfn)
{
	if (!vmmr0_is_mmio_pfn(pfn))
	{
		mark_page_accessed(pfn_to_page(pfn));
	}
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

/*
 * The vCPU has executed a HLT instruction with in-kernel mode enabled.
 */
int vmmr0_vcpu_block(struct vmmr0_vcpu *vcpu)
{
#ifdef HOST_LINUX_OPTIMIZED
	DEFINE_WAIT(wait);

	for (;;)
	{
		prepare_to_wait(&vcpu->wq, &wait, TASK_INTERRUPTIBLE);

		if (vmmr0_arch_vcpu_runnable(vcpu))
		{
			vmmr0_make_request(KVM_REQ_UNHALT, vcpu);
			break;
		}
		if (vmmr0_cpu_has_pending_timer(vcpu))
		{
			break;
		}
		if (signal_pending(current))
		{
			break;
		}

		schedule();
	}

	finish_wait(&vcpu->wq, &wait);
	return 0;
#else
	if (vmmr0_arch_vcpu_runnable(vcpu))
	{
		vmmr0_make_request(KVM_REQ_UNHALT, vcpu);
		return 0;
	}
	if (vmmr0_cpu_has_pending_timer(vcpu))
	{
		return 0;
	}
	return 1;
#endif

}

#ifdef HOST_LINUX_OPTIMIZED
void vmmr0_resched(struct vmmr0_vcpu *vcpu)
{
	if (!need_resched())
	{
		return;
	}
	cond_resched();
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
void vmmr0_vcpu_on_spin(struct vmmr0_vcpu *me)
{
#ifdef HOST_LINUX_OPTIMIZED
	struct vm *pvm = me->pvm;
	struct vmmr0_vcpu *vcpu;
	int last_boosted_vcpu = me->pvm->last_boosted_vcpu;
	int yielded = 0;
	int pass;
	int i;

	/*
	 * We boost the priority of a VCPU that is runnable but not
	 * currently running, because it got preempted by something
	 * else and called schedule in __vcpu_run.  Hopefully that
	 * VCPU is holding the lock that we need and will release it.
	 * We approximate round-robin by starting at the last boosted VCPU.
	 */
	for (pass = 0; pass < 2 && !yielded; pass++)
	{
		vmmr0_for_each_vcpu(i, vcpu, pvm)
		{
			struct task_struct *task = NULL;
			struct pid *pid;
			if (!pass && i < last_boosted_vcpu)
			{
				i = last_boosted_vcpu;
				continue;
			}

			else if (pass && i > last_boosted_vcpu)
			{
				break;
			}
			if (vcpu == me)
			{
				continue;
			}
			if (waitqueue_active(&vcpu->wq))
			{
				continue;
			}

			rcu_read_lock();
			pid = rcu_dereference(vcpu->pid);
			if (pid)
			{
				task = get_pid_task(vcpu->pid, PIDTYPE_PID);
			}
			rcu_read_unlock();
			if (!task)
			{
				continue;
			}
			if (task->flags & PF_VCPU)
			{
				put_task_struct(task);
				continue;
			}
			if (yield_to(task, 1))
			{
				put_task_struct(task);
				pvm->last_boosted_vcpu = i;
				yielded = 1;
				break;
			}
			put_task_struct(task);
		}
	}
#endif
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)

#include <linux/vmmr0_host.h>

void vmmr0_vcpu_on_spin(struct vmmr0_vcpu *vcpu)
{
#ifdef HOST_LINUX_OPTIMIZED
	ktime_t expires;
	DEFINE_WAIT(wait);

	prepare_to_wait(&vcpu->wq, &wait, TASK_INTERRUPTIBLE);

	/* Sleep for 100 us, and hope lock-holder got scheduled */
	expires = ktime_add_ns(ktime_get(), 100000UL);
	schedule_hrtimeout(&expires, HRTIMER_MODE_ABS);

	finish_wait(&vcpu->wq, &wait);
#endif
}
#endif /* < 2.6.39 */

static int vmmr0_vcpu_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct vmmr0_vcpu *vcpu = vma->vm_file->private_data;
	struct page *page;

	if (vmf->pgoff == 0)
	{
		page = virt_to_page(vcpu->run);
	}
#ifdef CONFIG_X86
	else if (vmf->pgoff == KVM_PIO_PAGE_OFFSET)
	{
		page = virt_to_page(vcpu->arch.pio_data);
	}
#endif
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
	else if (vmf->pgoff == KVM_COALESCED_MMIO_PAGE_OFFSET)
	{
		page = virt_to_page(vcpu->pvm->coalesced_mmio_ring);
	}
#endif
	else
	{
		return vmmr0_arch_vcpu_fault(vcpu, vmf);
	}
	get_page(page);
	vmf->page = page;
	return 0;
}

static struct vm_operations_struct vmmr0_vcpu_vm_ops =
{ .fault = vmmr0_vcpu_fault, };

static int vmmr0_vcpu_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &vmmr0_vcpu_vm_ops;
	return 0;
}

static int vmmr0_vcpu_release(struct inode *inode, struct file *filp)
{
	struct vmmr0_vcpu *vcpu = filp->private_data;

	vmmr0_put_vm(vcpu->pvm);
	return 0;
}

static struct file_operations vmmr0_vcpu_fops =
{
		.release = vmmr0_vcpu_release,
		.unlocked_ioctl = vmmr0_vcpu_ioctl,
#ifdef CONFIG_COMPAT
		.compat_ioctl = vmmr0_vcpu_compat_ioctl,
#endif
		.mmap = vmmr0_vcpu_mmap,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
		.llseek = noop_llseek,
#endif
		};


static int create_vcpu_fd(struct vmmr0_vcpu *vcpu)
{
	return vmmr0_anon_inode_getfd("vmmr0-vcpu", &vmmr0_vcpu_fops, vcpu, O_RDWR);
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

	preempt_notifier_init(&vcpu->preempt_notifier, &vmmr0_preempt_ops);

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
	if (sigset)
	{
		sigdelsetmask(sigset, sigmask(SIGKILL) | sigmask(SIGSTOP));
		vcpu->sigset_active = 1;
		vcpu->sigset = *sigset;
	}
	else
	{
		vcpu->sigset_active = 0;
	}
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

#ifdef OS_LINUX_OPTIMIZED_MM
	if (vcpu->pvm->mm != current->mm)
	{
		return -EIO;
	}
#endif

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

#ifdef CONFIG_COMPAT
static long vmmr0_vcpu_compat_ioctl(struct file *filp,
		unsigned int ioctl, unsigned long arg)
{
	struct vmmr0_vcpu *vcpu = filp->private_data;
	void *argp = compat_ptr(arg);
	int r;

#ifdef OS_LINUX_OPTIMIZED_MM
	if (vcpu->pvm->mm != current->mm)
	return -EIO;
#endif

	switch (ioctl)
	{
		case KVM_SET_SIGNAL_MASK:
		{
			struct vmmr0_signal_mask *sigmask_arg = argp;
			struct vmmr0_signal_mask vmmr0_sigmask;
			compat_sigset_t csigset;
			sigset_t sigset;

			if (argp)
			{
				r = -EFAULT;
				if (copy_from_user(&vmmr0_sigmask, argp,
								sizeof vmmr0_sigmask))
				{
					goto out;
				}
				r = -EINVAL;
				if (vmmr0_sigmask.len != sizeof csigset)
				{
					goto out;
				}
				r = -EFAULT;
				if (copy_from_user(&csigset, sigmask_arg->sigset,
								sizeof csigset))
				{
					goto out;
				}
			}
			vmmr0_sigset_from_compat(&sigset, &csigset);
			r = vmmr0_vcpu_ioctl_set_sigmask(vcpu, &sigset);
			break;
		}
		default:
		r = vmmr0_vcpu_ioctl(filp, ioctl, arg);
	}

	out:
	return r;
}
#endif

static long vmmr0_vm_ioctl(struct file *filp, unsigned int ioctl,
		unsigned long arg)
{
	struct vm *pvm = filp->private_data;
	void *argp = (void *) arg;
	int r;

#ifdef OS_LINUX_OPTIMIZED_MM
	if (pvm->mm != current->mm)
	{
		return -EIO;
	}
#endif

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
	case KVM_IRQFD:
	{
		struct vmmr0_irqfd data;

		r = -EFAULT;
		if (copy_from_user(&data, argp, sizeof data))
		{
			goto out;
		}

		r = vmmr0_irqfd(pvm, data.fd, data.gsi, data.flags);
		break;
	}
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
	case KVM_IOEVENTFD:
	{
		struct vmmr0_ioeventfd data;

		r = -EFAULT;
		if (copy_from_user(&data, argp, sizeof data))
		{
			goto out;
		}
		r = vmmr0_ioeventfd(pvm, &data);
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
#ifdef CONFIG_HAVE_ASSIGNED_DEV
			r = vmmr0_vm_ioctl_assigned_device(pvm, ioctl, arg);
#else
			r = 0;
#endif
		}
		break;
	}
	}
	out: return r;
}

#ifdef CONFIG_COMPAT
struct compat_vmmr0_dirty_log
{
	__u32 slot;
	__u32 padding1;
	union
	{
		compat_uptr_t dirty_bitmap; /* one bit per page */
		__u64 padding2;
	};
};

static long vmmr0_vm_compat_ioctl(struct file *filp,
		unsigned int ioctl, unsigned long arg)
{
	struct vm *pvm = filp->private_data;
	int r;

#ifdef OS_LINUX_OPTIMIZED_MM
	if (pvm->mm != current->mm)
	return -EIO;
#endif

	switch (ioctl)
	{
		case KVM_GET_DIRTY_LOG:
		{
			struct compat_vmmr0_dirty_log compat_log;
			struct vmmr0_dirty_log log;

			r = -EFAULT;
			if (copy_from_user(&compat_log, (void *)arg,
							sizeof(compat_log)))
			{
				goto out;
			}
			log.slot = compat_log.slot;
			log.padding1 = compat_log.padding1;
			log.padding2 = compat_log.padding2;
			log.dirty_bitmap = compat_ptr(compat_log.dirty_bitmap);

			r = vmmr0_vm_ioctl_get_dirty_log(pvm, &log);
			if (r)
			{
				goto out;
			}
			break;
		}
		default:
		r = vmmr0_vm_ioctl(filp, ioctl, arg);
	}

	out:
	return r;
}
#endif

static int vmmr0_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page[1];
	unsigned long addr;
	int npages;
	gfn_t gfn = vmf->pgoff;
	struct vm *pvm = vma->vm_file->private_data;

	addr = mmu_gfn_to_hva(pvm, gfn);
	if (vmmr0_is_error_hva(addr))
	{
		return VM_FAULT_SIGBUS;
	}

	npages = get_user_pages(current, current->mm, addr, 1, 1, 0, page, NULL);
	if (unlikely(npages != 1))
	{
		return VM_FAULT_SIGBUS;
	}

	vmf->page = page[0];
	return 0;
}

static struct vm_operations_struct vmmr0_vm_vm_ops =
{ .fault = vmmr0_vm_fault, };

static int vmmr0_vm_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &vmmr0_vm_vm_ops;
	return 0;
}

static struct file_operations vmmr0_vm_fops =
{ .release = vmmr0_vm_release, .unlocked_ioctl = vmmr0_vm_ioctl,
#ifdef CONFIG_COMPAT
		.compat_ioctl = vmmr0_vm_compat_ioctl,
#endif
		.mmap = vmmr0_vm_mmap,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
		.llseek = noop_llseek,
#endif
		};

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
	r = vmmr0_anon_inode_getfd("vmmr0-vm", &vmmr0_vm_fops, pvm, O_RDWR);
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

static struct file_operations vmmr0_chardev_ops =
{
		.unlocked_ioctl = vmmr0_dev_ioctl, .compat_ioctl = vmmr0_dev_ioctl,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
		.llseek = noop_llseek,
#endif
};

static struct miscdevice vmmr0_dev =
{
		VMMR0_MINOR,
		"vmmr0",
		&vmmr0_chardev_ops,
};

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

static int vmmr0_cpu_hotplug(struct notifier_block *notifier, unsigned long val,
		void *v)
{
	int cpu = (long) v;

	if (!vmmr0_usage_count)
	{
		return NOTIFY_OK;
	}

	val &= ~CPU_TASKS_FROZEN;
	switch (val)
	{
	case CPU_DYING:
	{
		printk(KERN_INFO "vmmr0: disabling hwacc on CPU%d\n",
				cpu);
		hardware_disable(NULL);
		break;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
	case CPU_STARTING:
#else
		case CPU_ONLINE:
#endif
		printk(KERN_INFO "vmmr0: enabling hwacc on CPU%d\n",
				cpu);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
		hardware_enable(NULL);
#else
		smp_call_function_single(cpu, hardware_enable, NULL, 1);
#endif
		break;
	}
	return NOTIFY_OK;
}

asmlinkage void vmmr0_spurious_fault(void)
{
	BUG();
}

static int vmmr0_reboot(struct notifier_block *notifier, unsigned long val,
		void *v)
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
	return NOTIFY_OK;
}

static struct notifier_block vmmr0_reboot_notifier =
{
		.notifier_call = vmmr0_reboot,
		.priority = 0,
};

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

	range = bsearch(&key, bus->range, bus->dev_count,
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

static struct notifier_block vmmr0_cpu_notifier =
{
		.notifier_call = vmmr0_cpu_hotplug,
};

struct page *bad_page;
pfn_t bad_pfn;

static inline struct vmmr0_vcpu *preempt_notifier_to_vcpu(struct preempt_notifier *pn)
{
	return container_of(pn, struct vmmr0_vcpu, preempt_notifier);
}

static void vmmr0_sched_in(struct preempt_notifier *pn, int cpu)
{
	struct vmmr0_vcpu *vcpu = preempt_notifier_to_vcpu(pn);

	vmmr0_arch_vcpu_load(vcpu, cpu);
}

static void vmmr0_sched_out(struct preempt_notifier *pn,
		struct task_struct *next)
{
	struct vmmr0_vcpu *vcpu = preempt_notifier_to_vcpu(pn);

	vmmr0_arch_vcpu_put(vcpu);
	vmmr0_fire_urn();
}

extern int __init vmx_init(void);
extern void __exit vmx_exit(void);

extern int __init svm_init(void);
extern void __exit svm_exit(void);

extern int __init irqfd_module_init(void);
extern void __exit irqfd_module_exit(void);

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

int __init vmmr0_module_init(void)
{
	vmmr0_check_hwacc();
#ifdef CONFIG_HAVE_KVM_IRQCHIP
	irqfd_module_init();
#endif
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

void __exit vmmr0_module_exit(void)
{
#ifdef CONFIG_HAVE_KVM_IRQCHIP
	irqfd_module_exit();
#endif
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

module_init( vmmr0_module_init)
module_exit( vmmr0_module_exit)

int vmmr0_init(void *opaque, unsigned vcpu_size, unsigned vcpu_align)
{
	int r;
	int cpu;

	vmmr0_tsc_khz = get_tsc_khz();
	printk(KERN_EMERG"vmmr0: get_tsc_khz: vmmr0_tsc_khz = %lld\n", vmmr0_tsc_khz);

	r = vmmr0_init_srcu();
	if (r)
	{
		return r;
	}

	preempt_notifier_sys_init();

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

	for_each_online_cpu(cpu)
	{
		smp_call_function_single(cpu, vmmr0_arch_check_processor_compat, &r, 1);
		if (r < 0)
		{
			goto out_free_1;
		}
	}

	r = register_cpu_notifier(&vmmr0_cpu_notifier);
	if (r)
	{
		goto out_free_2;
	}
	register_reboot_notifier(&vmmr0_reboot_notifier);

	if (!vcpu_align)
	{
		vcpu_align = __alignof__(struct vmmr0_vcpu);
	}

#ifdef HOST_LINUX_OPTIMIZED
	vmmr0_vcpu_cache = kmem_cache_create("vmmr0_vcpu", vcpu_size, vcpu_align, 0, NULL);
	if (!vmmr0_vcpu_cache)
	{
		r = -ENOMEM;
		goto out_free_3;
	}
#endif
	r = vmmr0_async_pf_init();
	if (r)
	{
		goto out_free;
	}
	r = misc_register(&vmmr0_dev);
	if (r)
	{
		printk(KERN_ERR "vmmr0: misc device register failed\n");
		goto out_unreg;
	}


	vmmr0_preempt_ops.sched_in = vmmr0_sched_in;
	vmmr0_preempt_ops.sched_out = vmmr0_sched_out;


	printk("loaded vmmr0-3.11\n");

	vmmr0_clock_warn_suspend_bug();

	return 0;


	out_unreg:
	vmmr0_async_pf_deinit();

	out_free:
#ifdef HOST_LINUX_OPTIMIZED
	kmem_cache_destroy(vmmr0_vcpu_cache);

	out_free_3:
#endif
	unregister_reboot_notifier(&vmmr0_reboot_notifier);
	unregister_cpu_notifier(&vmmr0_cpu_notifier);

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
	preempt_notifier_sys_exit();
	vmmr0_exit_srcu();
	return r;
}

void vmmr0_exit(void)
{
	misc_deregister(&vmmr0_dev);

#ifdef HOST_LINUX_OPTIMIZED
	kmem_cache_destroy(vmmr0_vcpu_cache);
#endif
	vmmr0_async_pf_deinit();


	unregister_reboot_notifier(&vmmr0_reboot_notifier);
	unregister_cpu_notifier(&vmmr0_cpu_notifier);
	vmmr0_on_each_cpu(hardware_disable_nolock, NULL, 1);
	vmmr0_arch_hardware_unsetup();
	vmmr0_arch_exit();
	free_cpumask_var(cpus_hardware_enabled);
	__free_page(hwpoison_page);
	__free_page(bad_page);
	preempt_notifier_sys_exit();
	vmmr0_exit_srcu();
}

