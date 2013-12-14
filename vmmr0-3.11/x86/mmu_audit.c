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
 * mmu_audit.c
 *
 * this code is based on kvm-kmod.
 *
 * authors : 
 *   范文一 （Wincy Van） <fanwenyi0529@live.com> <QQ:362478911>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *   Avi Kivity   <avi@qumranet.com>
 *   Marcelo Tosatti <mtosatti@redhat.com>
 *   Xiao Guangrong <xiaoguangrong@cn.fujitsu.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * From: kvm-kmod-3.4
 */
 
#include "os_interface.h"

#ifdef OS_LINUX_OPTIMIZED_MMU_AUDIT
char const *audit_point_name[] =
{
	"pre page fault",
	"post page fault",
	"pre pte write",
	"post pte write",
	"pre sync",
	"post sync"
};

#define audit_printk(vmmr0, fmt, args...)		\
	printk(KERN_ERR "audit: (%s) error: "	\
		fmt, audit_point_name[vmmr0->arch.audit_point], ##args)

typedef void (*inspect_spte_fn) (struct vmmr0_vcpu *vcpu, u64 *sptep, int level);

static void __mmu_spte_walk(struct vmmr0_vcpu *vcpu, struct vmmr0_mmu_page *sp,
			    inspect_spte_fn fn, int level)
{
	int i;

	for (i = 0; i < PT64_ENT_PER_PAGE; ++i) {
		u64 *ent = sp->spt;

		fn(vcpu, ent + i, level);

		if (is_shadow_present_pte(ent[i]) &&
		      !is_last_spte(ent[i], level)) {
			struct vmmr0_mmu_page *child;

			child = page_header(ent[i] & PT64_BASE_ADDR_MASK);
			__mmu_spte_walk(vcpu, child, fn, level - 1);
		}
	}
}

static void mmu_spte_walk(struct vmmr0_vcpu *vcpu, inspect_spte_fn fn)
{
	int i;
	struct vmmr0_mmu_page *sp;

	if (!VALID_PAGE(vcpu->arch.mmu.root_hpa))
		return;

	if (vcpu->arch.mmu.root_level == PT64_ROOT_LEVEL) {
		hpa_t root = vcpu->arch.mmu.root_hpa;

		sp = page_header(root);
		__mmu_spte_walk(vcpu, sp, fn, PT64_ROOT_LEVEL);
		return;
	}

	for (i = 0; i < 4; ++i) {
		hpa_t root = vcpu->arch.mmu.pae_root[i];

		if (root && VALID_PAGE(root)) {
			root &= PT64_BASE_ADDR_MASK;
			sp = page_header(root);
			__mmu_spte_walk(vcpu, sp, fn, 2);
		}
	}

	return;
}

typedef void (*sp_handler) (struct vm *pvm, struct vmmr0_mmu_page *sp);

static void walk_all_active_sps(struct vm *pvm, sp_handler fn)
{
	struct vmmr0_mmu_page *sp;

	list_for_each_entry(sp, &vmmr0->arch.active_mmu_pages, link)
		fn(vmmr0, sp);
}

static void audit_mappings(struct vmmr0_vcpu *vcpu, u64 *sptep, int level)
{
	struct vmmr0_mmu_page *sp;
	gfn_t gfn;
	pfn_t pfn;
	hpa_t hpa;

	sp = page_header(__pa(sptep));

	if (sp->unsync) {
		if (level != PT_PAGE_TABLE_LEVEL) {
			audit_printk(vcpu->vmmr0, "unsync sp: %p "
				     "level = %d\n", sp, level);
			return;
		}
	}

	if (!is_shadow_present_pte(*sptep) || !is_last_spte(*sptep, level))
		return;

#ifdef HOST_LINUX_OPTIMIZED
	gfn = vmmr0_mmu_page_get_gfn(sp, sptep - sp->spt);
#else
	gfn = vmmr0_mmu_page_get_gfn(sp, (u64*)__pa(sptep) - (u64*)__pa(sp->spt));
#endif
	pfn = mmu_gfn_to_pfn_atomic(vcpu->vmmr0, gfn);

	if (is_error_pfn(pfn)) {
		vmmr0_release_pfn_clean(pfn);
		return;
	}

	hpa =  pfn << PAGE_SHIFT;
	if ((*sptep & PT64_BASE_ADDR_MASK) != hpa)
		audit_printk(vcpu->vmmr0, "levels %d pfn %llx hpa %llx "
			     "ent %llxn", vcpu->arch.mmu.root_level, pfn,
			     hpa, *sptep);
}

static void inspect_spte_has_rmap(struct vm *pvm, u64 *sptep)
{
	static DEFINE_RATELIMIT_STATE(ratelimit_state, 5 * HZ, 10);
	unsigned long *rmapp;
	struct vmmr0_mmu_page *rev_sp;
	gfn_t gfn;

	rev_sp = page_header(__pa(sptep));
#ifdef HOST_LINUX_OPTIMIZED
	gfn = vmmr0_mmu_page_get_gfn(rev_sp, sptep - rev_sp->spt);
#else
	gfn = vmmr0_mmu_page_get_gfn(rev_sp, (u64*)__pa(sptep) - (u64*)__pa(rev_sp->spt));
#endif

	if (!mmu_gfn_to_memslot(vmmr0, gfn)) {
		if (!__ratelimit(&ratelimit_state))
			return;
		audit_printk(vmmr0, "no memslot for gfn %llx\n", gfn);
		audit_printk(vmmr0, "index %ld of sp (gfn=%llx)\n",
		       (long int)(sptep - rev_sp->spt), rev_sp->gfn);
		dump_stack();
		return;
	}

	rmapp = gfn_to_rmap(vmmr0, gfn, rev_sp->role.level);
	if (!*rmapp) {
		if (!__ratelimit(&ratelimit_state))
			return;
		audit_printk(vmmr0, "no rmap for writable spte %llx\n",
			     *sptep);
		dump_stack();
	}
}

static void audit_sptes_have_rmaps(struct vmmr0_vcpu *vcpu, u64 *sptep, int level)
{
	if (is_shadow_present_pte(*sptep) && is_last_spte(*sptep, level))
		inspect_spte_has_rmap(vcpu->vmmr0, sptep);
}

static void audit_spte_after_sync(struct vmmr0_vcpu *vcpu, u64 *sptep, int level)
{
	struct vmmr0_mmu_page *sp = page_header(__pa(sptep));

	if (vcpu->vmmr0->arch.audit_point == AUDIT_POST_SYNC && sp->unsync)
		audit_printk(vcpu->vmmr0, "meet unsync sp(%p) after sync "
			     "root.\n", sp);
}

static void check_mappings_rmap(struct vm *pvm, struct vmmr0_mmu_page *sp)
{
	int i;

	if (sp->role.level != PT_PAGE_TABLE_LEVEL)
		return;

	for (i = 0; i < PT64_ENT_PER_PAGE; ++i) {
		if (!is_rmap_spte(sp->spt[i]))
			continue;

		inspect_spte_has_rmap(vmmr0, sp->spt + i);
	}
}

static void audit_write_protection(struct vm *pvm, struct vmmr0_mmu_page *sp)
{
	struct vmmr0_memory_slot *slot;
	unsigned long *rmapp;
	u64 *spte;

	if (sp->role.direct || sp->unsync || sp->role.invalid)
		return;

	slot = mmu_gfn_to_memslot(vmmr0, sp->gfn);
	rmapp = &slot->rmap[sp->gfn - slot->base_gfn];

	spte = rmap_next(rmapp, NULL);
	while (spte) {
		if (is_writable_pte(*spte))
			audit_printk(vmmr0, "shadow page has writable "
				     "mappings: gfn %llx role %x\n",
				     sp->gfn, sp->role.word);
		spte = rmap_next(rmapp, spte);
	}
}

static void audit_sp(struct vm *pvm, struct vmmr0_mmu_page *sp)
{
	check_mappings_rmap(vmmr0, sp);
	audit_write_protection(vmmr0, sp);
}

static void audit_all_active_sps(struct vm *pvm)
{
	walk_all_active_sps(vmmr0, audit_sp);
}

static void audit_spte(struct vmmr0_vcpu *vcpu, u64 *sptep, int level)
{
	audit_sptes_have_rmaps(vcpu, sptep, level);
	audit_mappings(vcpu, sptep, level);
	audit_spte_after_sync(vcpu, sptep, level);
}

static void audit_vcpu_spte(struct vmmr0_vcpu *vcpu)
{
	mmu_spte_walk(vcpu, audit_spte);
}

static bool mmu_audit;
static struct static_key mmu_audit_key;

static void __vmmr0_mmu_audit(struct vmmr0_vcpu *vcpu, int point)
{
	static DEFINE_RATELIMIT_STATE(ratelimit_state, 5 * HZ, 10);

	if (!__ratelimit(&ratelimit_state))
		return;

	vcpu->vmmr0->arch.audit_point = point;
	audit_all_active_sps(vcpu->vmmr0);
	audit_vcpu_spte(vcpu);
}

static inline void vmmr0_mmu_audit(struct vmmr0_vcpu *vcpu, int point)
{
	if (static_key_false((&mmu_audit_key)))
		__vmmr0_mmu_audit(vcpu, point);
}

static void mmu_audit_enable(void)
{
	if (mmu_audit)
		return;

	static_key_slow_inc(&mmu_audit_key);
	mmu_audit = true;
}

static void mmu_audit_disable(void)
{
	if (!mmu_audit)
		return;

	static_key_slow_dec(&mmu_audit_key);
	mmu_audit = false;
}

static int mmu_audit_set(const char *val, const struct kernel_param *kp)
{
	int ret;
	unsigned long enable;

	ret = strict_strtoul(val, 10, &enable);
	if (ret < 0)
		return -EINVAL;

	switch (enable) {
	case 0:
		mmu_audit_disable();
		break;
	case 1:
		mmu_audit_enable();
		break;
	default:
		return -EINVAL;
	}

	return 0;
}
#endif //OS_LINUX_OPTIMIZED_MMU_AUDIT
