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
 * async_pf.c
 *
 * this code is based on kvm-kmod.
 *
 * authors : 
 *     范文一 （Wincy Van） <fanwenyi0529@live.com> <QQ:362478911>
 *     Gleb Natapov <gleb@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * From: kvm-kmod-3.4
 */
 
 
#include "os_interface.h"

#include <linux/vmmr0_host.h>

#include "async_pf.h"

#ifdef CONFIG_KVM_ASYNC_PF
static struct kmem_cache *async_pf_cache;

int vmmr0_async_pf_init(void)
{
	async_pf_cache = KMEM_CACHE(vmmr0_async_pf, 0);

	if (!async_pf_cache)
	{
		return -ENOMEM;
	}

	return 0;
}

void vmmr0_async_pf_deinit(void)
{
	if (async_pf_cache)
	{
		kmem_cache_destroy(async_pf_cache);
	}
	async_pf_cache = NULL;
}

void vmmr0_async_pf_vcpu_init(struct vmmr0_vcpu *vcpu)
{
	INIT_LIST_HEAD(&vcpu->async_pf.done);
	INIT_LIST_HEAD(&vcpu->async_pf.queue);
	spin_lock_init(&vcpu->async_pf.lock);
}

static void async_pf_execute(struct work_struct *work)
{
	struct page *page = NULL;
	struct vmmr0_async_pf *apf =
		container_of(work, struct vmmr0_async_pf, work);
	struct mm_struct *mm = apf->mm;
	struct vmmr0_vcpu *vcpu = apf->vcpu;
	unsigned long addr = apf->addr;

	might_sleep();

	vmmr0_use_mm(mm);
	down_read(&mm->mmap_sem);
	get_user_pages(current, mm, addr, 1, 1, 0, &page, NULL);
	up_read(&mm->mmap_sem);
	vmmr0_unuse_mm(mm);

	spin_lock(&vcpu->async_pf.lock);
	list_add_tail(&apf->link, &vcpu->async_pf.done);
	apf->page = page;
	apf->done = true;
	spin_unlock(&vcpu->async_pf.lock);

	if (waitqueue_active(&vcpu->wq))
		wake_up_interruptible(&vcpu->wq);

	mmdrop(mm);
	vmmr0_put_vm(vcpu->pvm);
}

void vmmr0_clear_async_pf_completion_queue(struct vmmr0_vcpu *vcpu)
{
	/* cancel outstanding work queue item */
	while (!list_empty(&vcpu->async_pf.queue)) {
		struct vmmr0_async_pf *work =
			list_entry(vcpu->async_pf.queue.next,
				   typeof(*work), queue);
		cancel_work_sync(&work->work);
		list_del(&work->queue);
		if (!work->done) /* work was canceled */
			kmem_cache_free(async_pf_cache, work);
	}

	spin_lock(&vcpu->async_pf.lock);
	while (!list_empty(&vcpu->async_pf.done)) {
		struct vmmr0_async_pf *work =
			list_entry(vcpu->async_pf.done.next,
				   typeof(*work), link);
		list_del(&work->link);
		if (work->page)
			put_page(work->page);
		kmem_cache_free(async_pf_cache, work);
	}
	spin_unlock(&vcpu->async_pf.lock);

	vcpu->async_pf.queued = 0;
}

void vmmr0_check_async_pf_completion(struct vmmr0_vcpu *vcpu)
{
	struct vmmr0_async_pf *work;

	while (!list_empty_careful(&vcpu->async_pf.done) &&
	      vmmr0_arch_can_inject_async_page_present(vcpu)) {
		spin_lock(&vcpu->async_pf.lock);
		work = list_first_entry(&vcpu->async_pf.done, typeof(*work),
					      link);
		list_del(&work->link);
		spin_unlock(&vcpu->async_pf.lock);

		if (work->page)
			vmmr0_arch_async_page_ready(vcpu, work);
		vmmr0_arch_async_page_present(vcpu, work);

		list_del(&work->queue);
		vcpu->async_pf.queued--;
		if (work->page)
			put_page(work->page);
		kmem_cache_free(async_pf_cache, work);
	}
}

int vmmr0_setup_async_pf(struct vmmr0_vcpu *vcpu, gva_t gva, gfn_t gfn,
		       struct vmmr0_arch_async_pf *arch)
{
	struct vmmr0_async_pf *work;

	if (vcpu->async_pf.queued >= ASYNC_PF_PER_VCPU)
		return 0;

	/* setup delayed work */

	/*
	 * do alloc nowait since if we are going to sleep anyway we
	 * may as well sleep faulting in page
	 */
	work = kmem_cache_zalloc(async_pf_cache, GFP_NOWAIT);
	if (!work)
		return 0;

	work->page = NULL;
	work->done = false;
	work->vcpu = vcpu;
	work->gva = gva;
	work->addr = mmu_gfn_to_hva(vcpu->pvm, gfn);
	work->arch = *arch;
	work->mm = current->mm;
	atomic_inc(&work->mm->mm_count);
	vmmr0_get_vm(work->vcpu->pvm);

	/* this can't really happen otherwise mmu_gfn_to_pfn_async
	   would succeed */
	if (unlikely(vmmr0_is_error_hva(work->addr)))
		goto retry_sync;

	INIT_WORK(&work->work, async_pf_execute);
	if (!schedule_work(&work->work))
		goto retry_sync;

	list_add_tail(&work->queue, &vcpu->async_pf.queue);
	vcpu->async_pf.queued++;
	vmmr0_arch_async_page_not_present(vcpu, work);
	return 1;
retry_sync:
	vmmr0_put_vm(work->vcpu->pvm);
	mmdrop(work->mm);
	kmem_cache_free(async_pf_cache, work);
	return 0;
}

int vmmr0_async_pf_wakeup_all(struct vmmr0_vcpu *vcpu)
{
	struct vmmr0_async_pf *work;

	if (!list_empty_careful(&vcpu->async_pf.done))
		return 0;

	work = kmem_cache_zalloc(async_pf_cache, GFP_ATOMIC);
	if (!work)
		return -ENOMEM;

	work->page = bad_page;
	get_page(bad_page);
	INIT_LIST_HEAD(&work->queue); /* for list_del to work */

	spin_lock(&vcpu->async_pf.lock);
	list_add_tail(&work->link, &vcpu->async_pf.done);
	spin_unlock(&vcpu->async_pf.lock);

	vcpu->async_pf.queued++;
	return 0;
}
#else
void vmmr0_clear_async_pf_completion_queue(struct vmmr0_vcpu *vcpu)
{
}
void vmmr0_check_async_pf_completion(struct vmmr0_vcpu *vcpu)
{
}
int vmmr0_setup_async_pf(struct vmmr0_vcpu *vcpu, gva_t gva, gfn_t gfn,
		struct vmmr0_arch_async_pf *arch)
{
	return 0;
}
int vmmr0_async_pf_wakeup_all(struct vmmr0_vcpu *vcpu)
{
	return 0;
}
#endif
