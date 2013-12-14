
#include <linux/compiler.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/vmmr0.h>
#include <linux/vmmr0_para.h>
#include <linux/cpu.h>
#include <linux/time.h>
#include <asm/processor.h>
#include <linux/hrtimer.h>
#include <asm/bitops.h>

#include "vmmr0-config.h"

/*
 * 2.6.16 does not have GFP_NOWAIT
 */

#include <linux/gfp.h>

#ifndef GFP_NOWAIT
#define GFP_NOWAIT (GFP_ATOMIC & ~__GFP_HIGH)
#endif

/*
 * smp_call_function_single() is not exported below 2.6.20, and has different
 * semantics below 2.6.23.  The 'nonatomic' argument was removed in 2.6.27.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)

int vmmr0_smp_call_function_single(int cpu, void (*func)(void *info),
				 void *info, int wait);
#undef smp_call_function_single
#define smp_call_function_single vmmr0_smp_call_function_single

#endif

/* on_each_cpu() lost an argument in 2.6.27. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)

#define vmmr0_on_each_cpu(func, info, wait) on_each_cpu(func, info, 0, wait)

#else

#define vmmr0_on_each_cpu(func, info, wait) on_each_cpu(func, info, wait)

#endif

#include <linux/notifier.h>
#ifndef CPU_TASKS_FROZEN

#define CPU_TASKS_FROZEN       0x0010
#define CPU_ONLINE_FROZEN      (CPU_ONLINE | CPU_TASKS_FROZEN)
#define CPU_UP_PREPARE_FROZEN  (CPU_UP_PREPARE | CPU_TASKS_FROZEN)
#define CPU_UP_CANCELED_FROZEN (CPU_UP_CANCELED | CPU_TASKS_FROZEN)
#define CPU_DOWN_PREPARE_FROZEN        (CPU_DOWN_PREPARE | CPU_TASKS_FROZEN)
#define CPU_DOWN_FAILED_FROZEN (CPU_DOWN_FAILED | CPU_TASKS_FROZEN)
#define CPU_DEAD_FROZEN                (CPU_DEAD | CPU_TASKS_FROZEN)

#endif

#ifndef CPU_DYING
#define CPU_DYING 0x000A
#define CPU_DYING_FROZEN (CPU_DYING | CPU_TASKS_FROZEN)
#endif

struct inode;

#include <linux/fs.h>
#include <linux/anon_inodes.h>

/* anon_inodes on RHEL >= 5.2 is equivalent to 2.6.27 version */
#ifdef RHEL_RELEASE_CODE
#  if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(5,2)) && defined(CONFIG_ANON_INODES)
#    define RHEL_ANON_INODES
#  endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26) && !defined(RHEL_ANON_INODES)

static inline int vmmr0_anon_inode_getfd(const char *name,
				       const struct file_operations *fops,
				       void *priv, int flags)
{
	int r;
	int fd;
	struct inode *inode;
	struct file *file;

	r = anon_inode_getfd(&fd, &inode, &file, name, fops, priv);
	if (r < 0)
		return r;
	return fd;
}

#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,26) && !defined(RHEL_ANON_INODES)

#define vmmr0_anon_inode_getfd(name, fops, priv, flags) \
	anon_inode_getfd(name, fops, priv)
}

#else /* > 2.6.26 || RHEL_ANON_INODES */

#define vmmr0_anon_inode_getfd	anon_inode_getfd

#endif /* > 2.6.26 || RHEL_ANON_INODES */

/* div64_u64 is fairly new */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)

#define div64_u64 vmmr0_div64_u64

#ifdef CONFIG_64BIT

static inline uint64_t div64_u64(uint64_t dividend, uint64_t divisor)
{
	return dividend / divisor;
}

#else

uint64_t div64_u64(uint64_t dividend, uint64_t divisor);

#endif

#endif

/*
 * PF_VCPU is a Linux 2.6.24 addition
 */

#include <linux/sched.h>

#ifndef PF_VCPU
#define PF_VCPU 0
#endif

/*
 * smp_call_function_mask() is not defined/exported below 2.6.24 on all
 * targets and below 2.6.26 on x86-64
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24) || \
    (defined CONFIG_X86_64 && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26))

int vmmr0_smp_call_function_mask(cpumask_t mask, void (*func) (void *info),
			       void *info, int wait);

#define smp_call_function_mask vmmr0_smp_call_function_mask

void vmmr0_smp_send_reschedule(int cpu);

#else

#define vmmr0_smp_send_reschedule smp_send_reschedule

#endif

/* empty_zero_page isn't exported in all kernels */
#include <asm/pgtable.h>

#define empty_zero_page vmmr0_empty_zero_page

static char empty_zero_page[PAGE_SIZE];

static inline void blahblah(void)
{
	(void)empty_zero_page[0];
}

/* __mmdrop() is not exported before 2.6.25 */
#include <linux/sched.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)

#define mmdrop(x) do { (void)(x); } while (0)
#define mmget(x) do { (void)(x); } while (0)

#else

#define mmget(x) do { atomic_inc(x); } while (0)

#endif

#ifdef KVM_NEED_PAGEFAULT_DISABLE

static inline void pagefault_disable(void)
{
	inc_preempt_count();
	/*
	 * make sure to have issued the store before a pagefault
	 * can hit.
	 */
	barrier();
}

static inline void pagefault_enable(void)
{
	/*
	 * make sure to issue those last loads/stores before enabling
	 * the pagefault handler again.
	 */
	barrier();
	dec_preempt_count();
	/*
	 * make sure we do..
	 */
	barrier();
	preempt_check_resched();
}

#endif

/* simple vfs attribute getter signature has changed to add a return code */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)

#define MAKE_SIMPLE_ATTRIBUTE_GETTER(x)       \
	static u64 x(void *v)                 \
	{				      \
		u64 ret = 0;		      \
					      \
		__##x(v, &ret);		      \
		return ret;		      \
	}

#else

#define MAKE_SIMPLE_ATTRIBUTE_GETTER(x)       \
	static int x(void *v, u64 *val)	      \
	{				      \
		return __##x(v, val);	      \
	}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
#ifndef FASTCALL
#define FASTCALL(x)	x
#define fastcall
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)

static inline void flush_work(struct work_struct *work)
{
	cancel_work_sync(work);
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)

#include <linux/mm.h>

static inline int vmmr0___get_user_pages_fast(unsigned long start, int nr_pages,
					    int write, struct page **pages)
{
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)

static inline int get_user_pages_fast(unsigned long start, int nr_pages,
				      int write, struct page **pages)
{
	int npages;

	down_read(&current->mm->mmap_sem);
	npages = get_user_pages(current, current->mm, start, nr_pages, write,
				0, pages, NULL);
	up_read(&current->mm->mmap_sem);

	return npages;
}

#endif /* < 2.6.27 */

#else /* >= 2.6.37 */

#define vmmr0___get_user_pages_fast	__get_user_pages_fast

#endif /* >= 2.6.37 */

/* spin_needbreak() was called something else in 2.6.24 */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24)

#define spin_needbreak need_lockbreak

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)

static inline void vmmr0_hrtimer_add_expires_ns(struct hrtimer *timer, u64 delta)
{
	timer->expires = ktime_add_ns(timer->expires, delta);
}

static inline ktime_t vmmr0_hrtimer_get_expires(struct hrtimer *timer)
{
	return timer->expires;
}

static inline u64 vmmr0_hrtimer_get_expires_ns(struct hrtimer *timer)
{
	return ktime_to_ns(timer->expires);
}

static inline void vmmr0_hrtimer_start_expires(struct hrtimer *timer, int mode)
{
	hrtimer_start(timer, timer->expires, mode);
}

static inline ktime_t vmmr0_hrtimer_expires_remaining(const struct hrtimer *timer)
{
    return ktime_sub(timer->expires, timer->base->get_time());
}

#else

#define vmmr0_hrtimer_add_expires_ns hrtimer_add_expires_ns
#define vmmr0_hrtimer_get_expires hrtimer_get_expires
#define vmmr0_hrtimer_get_expires_ns hrtimer_get_expires_ns
#define vmmr0_hrtimer_start_expires hrtimer_start_expires
#define vmmr0_hrtimer_expires_remaining hrtimer_expires_remaining

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
#include <linux/pci.h>

static inline int __pci_reset_function(struct pci_dev *dev)
{
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
static inline int pci_reset_function(struct pci_dev *dev)
{
	return 0;
}
#endif /* < 2.6.28 */
#endif /* < 2.6.31 */

/* dynamically allocated cpu masks introduced in 2.6.28 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)

typedef cpumask_t cpumask_var_t[1];

static inline bool alloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
{
	return 1;
}

static inline void free_cpumask_var(cpumask_var_t mask)
{
}

static inline void cpumask_clear(cpumask_var_t mask)
{
	cpus_clear(*mask);
}

static inline void cpumask_set_cpu(int cpu, cpumask_var_t mask)
{
	cpu_set(cpu, *mask);
}

static inline int smp_call_function_many(cpumask_var_t cpus,
					 void (*func)(void *data), void *data,
					 int sync)
{
	return smp_call_function_mask(*cpus, func, data, sync);
}

static inline int cpumask_empty(cpumask_var_t mask)
{
	return cpus_empty(*mask);
}

static inline int cpumask_test_cpu(int cpu, cpumask_var_t mask)
{
	return cpu_isset(cpu, *mask);
}

static inline void cpumask_clear_cpu(int cpu, cpumask_var_t mask)
{
	cpu_clear(cpu, *mask);
}

#define cpu_online_mask (&cpu_online_map)

#define cpumask_any(m) first_cpu(*(m))

#endif

/* A zeroing constructor was added late 2.6.30 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)

static inline bool zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
{
	bool ret;

	ret = alloc_cpumask_var(mask, flags);
	if (ret)
		cpumask_clear(*mask);
	return ret;
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)

#define IF_ANON_INODES_DOES_REFCOUNTS(x)

#else

#define IF_ANON_INODES_DOES_REFCOUNTS(x) x

#endif


/* Macro introduced only on newer kernels: */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
#define marker_synchronize_unregister() synchronize_sched()
#endif

#ifdef NEED_COMPOUND_HEAD

static inline struct page *compound_head(struct page *page)
{
	if (PageCompound(page))
		page = (struct page *)page_private(page);
	return page;
}

#endif

#include <linux/iommu.h>
#ifndef IOMMU_CACHE

#define IOMMU_CACHE	(4)
#define IOMMU_CAP_CACHE_COHERENCY	0x1
static inline int iommu_domain_has_cap(struct iommu_domain *domain,
				       unsigned long cap)
{
	return 0;
}

#endif

#ifndef IOMMU_CAP_INTR_REMAP
#define IOMMU_CAP_INTR_REMAP		0x2	/* isolates device intrs */
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)

#define alloc_pages_exact_node alloc_pages_node

#endif

#include <linux/hugetlb.h>

/* vma_kernel_pagesize, exported since 2.6.32 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)

#if defined(CONFIG_HUGETLB_PAGE) && LINUX_VERSION_CODE > KERNEL_VERSION(2,6,26)
static inline
unsigned long vmmr0_vma_kernel_pagesize(struct vm_area_struct *vma)
{
	struct hstate *hstate;

	if (!is_vm_hugetlb_page(vma))
		return PAGE_SIZE;

	hstate = hstate_vma(vma);

	return 1UL << (hstate->order + PAGE_SHIFT);
}
#else /* !CONFIG_HUGETLB_SIZE || <= 2.6.26 */
#define vmmr0_vma_kernel_pagesize(v) PAGE_SIZE
#endif

#else /* >= 2.6.32 */

#define vmmr0_vma_kernel_pagesize vma_kernel_pagesize

#endif

#ifndef printk_once
/*
 * Print a one-time message (analogous to WARN_ONCE() et al):
 */
#define printk_once(x...) ({			\
	static int __print_once = 1;		\
						\
	if (__print_once) {			\
		__print_once = 0;		\
		printk(x);			\
	}					\
})
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32) && !defined(CONFIG_CPU_FREQ)
static inline unsigned int cpufreq_get(unsigned int cpu)
{
	return 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
int schedule_hrtimeout(ktime_t *expires, const enum hrtimer_mode mode);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
#ifndef CONFIG_MMU_NOTIFIER
struct mmu_notifier {};
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
static inline void hlist_del_init_rcu(struct hlist_node *n)
{
	if (!hlist_unhashed(n)) {
		__hlist_del(n);
		n->pprev = NULL;
	}
}
#endif

#ifndef CONFIG_USER_RETURN_NOTIFIER

#include <linux/percpu.h>

struct vmmr0_user_return_notifier {
	void (*on_user_return)(struct vmmr0_user_return_notifier *urn);
};

DECLARE_PER_CPU(struct vmmr0_user_return_notifier *, vmmr0_urn);

static inline void
vmmr0_user_return_notifier_register(struct vmmr0_user_return_notifier *urn)
{
	__get_cpu_var(vmmr0_urn) = urn;
}

static inline void
vmmr0_user_return_notifier_unregister(struct vmmr0_user_return_notifier *urn)
{
	__get_cpu_var(vmmr0_urn) = NULL;
}

static inline void vmmr0_fire_urn(void)
{
	struct vmmr0_user_return_notifier *urn = __get_cpu_var(vmmr0_urn);

	if (urn)
		urn->on_user_return(urn);
}

#else /* CONFIG_USER_RETURN_NOTIFIER */

#define vmmr0_user_return_notifier		user_return_notifier
#define vmmr0_user_return_notifier_register	user_return_notifier_register
#define vmmr0_user_return_notifier_unregister	user_return_notifier_unregister

static inline void vmmr0_fire_urn(void) {}

#endif /* CONFIG_USER_RETURN_NOTIFIER */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)

#ifdef CONFIG_SMP
void vmmr0_synchronize_srcu_expedited(struct srcu_struct *sp);
#else
static inline void vmmr0_synchronize_srcu_expedited(struct srcu_struct *sp) { }
#endif

#else

#define vmmr0_synchronize_srcu_expedited synchronize_srcu_expedited

#endif

int vmmr0_init_srcu(void);
void vmmr0_exit_srcu(void);

#ifndef WARN_ONCE
#define WARN_ONCE(condition, format...)	({			\
	static bool __warned;					\
	int __ret_warn_once = !!(condition);			\
								\
	if (unlikely(__ret_warn_once))				\
		if (WARN_ON(!__warned)) 			\
			__warned = true;			\
	unlikely(__ret_warn_once);				\
})
#endif

#ifndef WARN
#define WARN(condition, format...)	WARN_ON(condition)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#define get_online_cpus lock_cpu_hotplug
#define put_online_cpus unlock_cpu_hotplug
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32) || \
    (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32) && KERNEL_EXTRAVERSION < 9)
static inline void vmmr0_getboottime(struct timespec *ts)
{
	struct timespec sys, now = current_kernel_time();
	ktime_get_ts(&sys);
	*ts = ns_to_timespec(timespec_to_ns(&now) - timespec_to_ns(&sys));
}
#define vmmr0_monotonic_to_bootbased(ts)
#else
#define vmmr0_getboottime			getboottime
#define vmmr0_monotonic_to_bootbased	monotonic_to_bootbased
#endif

static inline void vmmr0_clock_warn_suspend_bug(void)
{
#if defined(CONFIG_SUSPEND) && \
    (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32) || \
     (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32) && KERNEL_EXTRAVERSION < 9))
	printk("vmmr0: paravirtual wallclock will not work reliably "
	       "accross host suspend/resume\n");
#endif
}

#if defined(CONFIG_PCI) && LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33) && \
    (!defined(CONFIG_SUSE_KERNEL) || LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32))
#include <linux/pci.h>
static inline struct pci_dev *
pci_get_domain_bus_and_slot(int domain, unsigned int bus, unsigned int devfn)
{
	if (domain != 0)
		return NULL;
	return pci_get_bus_and_slot(bus, devfn);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)

#define DEFINE_RAW_SPINLOCK		DEFINE_SPINLOCK
#define raw_spinlock_t			spinlock_t
#define raw_spin_lock_init		spin_lock_init
#define raw_spin_lock			spin_lock
#define raw_spin_lock_irqsave		spin_lock_irqsave
#define raw_spin_unlock			spin_unlock
#define raw_spin_unlock_irqrestore	spin_unlock_irqrestore
#define raw_spin_is_locked		spin_is_locked

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
struct perf_guest_info_callbacks {
	int (*is_in_guest) (void);
	int (*is_user_mode) (void);
	unsigned long (*get_guest_ip) (void);
};

static inline int
perf_register_guest_info_callbacks(struct perf_guest_info_callbacks *cbs)
{
	return 0;
}

static inline int
perf_unregister_guest_info_callbacks(struct perf_guest_info_callbacks *cbs)
{
	return 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
#define rcu_dereference_check(p, sp)	rcu_dereference(p)
#define rcu_dereference_protected(p, c)	rcu_dereference(p)
#define srcu_dereference(p, sp)		rcu_dereference(p)
#define srcu_read_lock_held(sp)		(1)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#define lockdep_is_held(m)		(1)
#endif

#ifdef CONFIG_IOMMU_API
#include <linux/iommu.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)

#define vmmr0_iommu_map	iommu_map
#define vmmr0_iommu_unmap	iommu_unmap

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)

static inline int vmmr0_iommu_map(struct iommu_domain *domain,
				unsigned long iova, phys_addr_t paddr,
				size_t size, int prot)
{
	return iommu_map(domain, iova, paddr, get_order(size), prot);
}

static inline int vmmr0_iommu_unmap(struct iommu_domain *domain,
				  unsigned long iova, size_t size)
{
	return PAGE_SIZE << iommu_unmap(domain, iova, get_order(size));
}

#else /* < 2.6.35 */

static inline int vmmr0_iommu_map(struct iommu_domain *domain,
				unsigned long iova, phys_addr_t paddr,
				size_t size, int prot)
{
	return iommu_map_range(domain, iova, paddr, size, prot);
}

static inline int vmmr0_iommu_unmap(struct iommu_domain *domain,
				  unsigned long iova, size_t size)
{
	iommu_unmap_range(domain, iova, size);

	return size;
}
#endif /* < 2.6.35 */

#endif /* CONFIG_IOMMU_API */

#ifndef lower_32_bits
#define lower_32_bits(n) ((u32)(n))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
#define EHWPOISON	133	/* Memory page has hardware error */
#define FOLL_HWPOISON	0x100	/* check page is hwpoisoned */

static inline int 
__get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
		 unsigned long start, int len, unsigned int foll_flags,
		 struct page **pages, struct vm_area_struct **vmas,
		 int *nonblocking)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
	return is_hwpoison_address(start) ? -EHWPOISON : -ENOSYS;
#else
	return -ENOSYS;
#endif
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#include <asm/siginfo.h>

typedef struct {
	int si_signo;
	int si_errno;
	int si_code;

	union {
		int _pad[SI_PAD_SIZE];

		struct _sigfault {
			void __user *_addr; /* faulting insn/memory ref. */
#ifdef __ARCH_SI_TRAPNO
			int _trapno;	/* TRAP # which caused the signal */
#endif
			short _addr_lsb; /* LSB of the reported address */
		} _sigfault;
	} _sifields;
} vmmr0_siginfo_t;

#define si_addr_lsb	_sifields._sigfault._addr_lsb
#define BUS_MCEERR_AR	(__SI_FAULT|4)

#else

#define vmmr0_siginfo_t	siginfo_t

#endif

#include <linux/mm.h>

/* Services below are only referenced by code unused in older kernels */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
static inline void vmmr0_use_mm(struct mm_struct *mm)
{
	BUG();
}

static inline void vmmr0_unuse_mm(struct mm_struct *mm)
{
	BUG();
}
#else
#define vmmr0_use_mm	use_mm
#define vmmr0_unuse_mm	unuse_mm
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
static inline u32 hash_32(u32 val, unsigned int bits)
{
	BUG();
	return 0;
}
#define order_base_2(n)	({ BUG(); 0; })
#endif

#ifndef __rcu
#define __rcu
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37) && \
    (!defined(CONFIG_FEDORA_KERNEL) || \
     (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,35) && \
      KERNEL_EXTRAVERSION < 11) || \
     LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
#include <linux/vmalloc.h>
static inline void *vzalloc(unsigned long size)
{
	void *addr = vmalloc(size);
	if (addr)
		memset(addr, 0, size);
	return addr;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#include <linux/interrupt.h>

#define IRQF_ONESHOT	0x00002000

static inline int
vmmr0_request_threaded_irq(unsigned int irq, irq_handler_t handler,
                         irq_handler_t thread_fn,
                         unsigned long flags, const char *name, void *dev)
{
	return -ENOSYS;
}
#else
#define vmmr0_request_threaded_irq	request_threaded_irq
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38)
#define compound_trans_head(page) compound_head(page)

static inline int PageTransCompound(struct page *page)
{
        return 0;
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,33)
#define vmmr0___this_cpu_read(n)		__get_cpu_var(n)
#define vmmr0___this_cpu_write(n, v)	__get_cpu_var(n) = v
#else /* > 2.6.33 */
#define vmmr0___this_cpu_read		__this_cpu_read
#define vmmr0___this_cpu_write		__this_cpu_write
#endif /* > 2.6.33 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
#define vmmr0_get_task_pid(t, pt)	(t)->pids[pt].pid
#define vmmr0_put_pid(p)		p = p
#else /* >= 2.6.39 */
#define vmmr0_get_task_pid	get_task_pid
#define vmmr0_put_pid		put_pid
#endif /* >= 2.6.39 */

#ifndef __noclone
#if defined(__GNUC__) && __GNUC__ >= 4 && __GNUC_MINOR__ >= 5
#define __noclone	__attribute__((__noclone__))
#else /* !GCC || GCC < 4.5 */
#define __noclone
#endif /* !GCC || GCC < 4.5 */
#endif /* !__noclone */

#ifndef FOLL_NOWAIT
#define FOLL_NOWAIT	0x20
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
#include <linux/delay.h>

static inline void flush_work_sync(struct work_struct *work)
{
	flush_work(work);
	/* pragmatic sync as we have no way to wait explicitly */
	msleep(100);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
#define __set_bit_le	ext2_set_bit
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
static inline void set_bit_le(int nr, void *addr)
{
        set_bit(nr ^ BITOP_LE_SWIZZLE, addr);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
static inline void rcu_virt_note_context_switch(int cpu)
{
}
#endif

#ifdef CONFIG_COMPAT
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
#include <linux/compat.h>
static inline
void vmmr0_sigset_from_compat(sigset_t *set, compat_sigset_t *compat)
{
	switch (_NSIG_WORDS) {
	case 4: set->sig[3] = compat->sig[6] | (((long)compat->sig[7]) << 32 );
	case 3: set->sig[2] = compat->sig[4] | (((long)compat->sig[5]) << 32 );
	case 2: set->sig[1] = compat->sig[2] | (((long)compat->sig[3]) << 32 );
	case 1: set->sig[0] = compat->sig[0] | (((long)compat->sig[1]) << 32 );
	}
}
#else /* >= 3.1 */
#define vmmr0_sigset_from_compat	sigset_from_compat
#endif /* >= 3.1 */
#endif /* CONFIG_COMPAT */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)

#ifdef CONFIG_PRINTK
#define printk_ratelimited(fmt, ...)					\
({									\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
									\
	if (__ratelimit(&_rs))						\
		printk(fmt, ##__VA_ARGS__);				\
})
#else
#define printk_ratelimited(fmt, ...)
#endif

#define pr_err_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_ERR fmt, ##__VA_ARGS__)
#define pr_warn_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_WARNING fmt, ##__VA_ARGS__)
#define pr_info_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_INFO fmt, ##__VA_ARGS__)
#if defined(DEBUG)
#define pr_debug_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_DEBUG fmt, ##__VA_ARGS__)
#else
#define pr_debug_ratelimited(fmt, ...)
#endif

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)

#define pr_warn_ratelimited	pr_warning_ratelimited

#endif /* < 2.6.35 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
static inline int vmmr0_sched_info_on(void)
{
#ifdef CONFIG_SCHEDSTATS
        return 1;
#else
        return 0;
#endif
}
#else /* >= 3.1 */
#define vmmr0_sched_info_on sched_info_on
#endif /* >= 3.1 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
#define PCI_DEV_FLAGS_ASSIGNED	0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)
#define iommu_present(x)	iommu_found()
#define iommu_domain_alloc(x)	iommu_domain_alloc()
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
static inline int test_and_set_bit_le(int nr, void *addr)
{
        return test_and_set_bit(nr ^ BITOP_LE_SWIZZLE, addr);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
#define for_each_set_bit(bit, addr, size) for_each_bit(bit, addr, size)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
struct vmmr0_x86_pmu_capability {
	int		version;
	int		num_counters_gp;
	int		num_counters_fixed;
	int		bit_width_gp;
	int		bit_width_fixed;
	unsigned int	events_mask;
	int		events_mask_len;
};

static inline void
vmmr0_perf_get_x86_pmu_capability(struct vmmr0_x86_pmu_capability *cap)
{
	memset(cap, 0, sizeof(*cap));
}
#else /* >= 3.3 */
#define vmmr0_x86_pmu_capability		x86_pmu_capability
#define vmmr0_perf_get_x86_pmu_capability	perf_get_x86_pmu_capability
#endif /* >= 3.3 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
#define PCI_STD_RESOURCES	0
#define PCI_STD_RESOURCE_END	5
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
static inline int
vmmr0_path_put(struct path *path)
{
	BUG();
	return -EPERM;
}
#else /* >= 2.6.25 */
#define vmmr0_path_put		path_put
#endif /* >= 2.6.25 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
static inline int vmmr0_inode_permission(struct inode *inode, int mask)
{
	BUG();
	return -EPERM;
}
#else /* >= 2.6.28 */
#define vmmr0_inode_permission	inode_permission
#endif /* >= 2.6.28 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
static inline int
vmmr0_kern_path(const char *name, unsigned int flags, struct path *path)
{
	return -EPERM;
}
#else /* >= 2.6.28 */
#define vmmr0_kern_path		kern_path
#endif /* >= 2.6.28 */

#ifndef MAY_ACCESS
#define MAY_ACCESS		0x00000010
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#include <linux/uaccess.h>
static inline void *memdup_user(const void __user *user, size_t size)
{
	void *buf = kzalloc(size, GFP_KERNEL);

	if (!buf)
		return ERR_PTR(-ENOMEM);
	if (copy_from_user(buf, user, size))
		return ERR_PTR(-EFAULT);
	return buf;
}
#endif /* < 2.6.30 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
static inline void debugfs_remove_recursive(struct dentry *dentry)
{
	WARN("vmmr0-kmod: leaving some debugfs entries behind");
}
#endif /* < 2.6.27 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
static inline bool pci_intx_mask_supported(struct pci_dev *dev)
{
	return false;
}

static inline bool pci_check_and_mask_intx(struct pci_dev *dev)
{
	BUG();
	return false;
}

static inline bool pci_check_and_unmask_intx(struct pci_dev *dev)
{
	BUG();
	return false;
}
#endif /* < 3.3 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#define IRQ_WAKE_THREAD		IRQ_NONE	/* will never be used */
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
struct x86_cpu_id { };
#define X86_FEATURE_MATCH(x) { }
#endif /* < 3.4 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
#define vmmr0_kmap_atomic(page)	kmap_atomic(page, KM_USER0)
#define vmmr0_kunmap_atomic(page)	kunmap_atomic(page, KM_USER0)
#else /* >= 2.6.37 */
#define vmmr0_kmap_atomic		kmap_atomic
#define vmmr0_kunmap_atomic	kunmap_atomic
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
#include <linux/workqueue.h>
#define kthread_worker			workqueue_struct *
#define kthread_work			work_struct
#define queue_kthread_work(q, w)	queue_work(*(q), w)
#define flush_kthread_work		cancel_work_sync
#define init_kthread_work		INIT_WORK
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
static inline unsigned long vm_mmap(struct file *file, unsigned long addr,
				    unsigned long len, unsigned long prot,
				    unsigned long flag, unsigned long offset)
{
	unsigned long ret;
	struct mm_struct *mm = current->mm;

	down_write(&mm->mmap_sem);
	ret = do_mmap(file, addr, len, prot, flag, offset);
	up_write(&mm->mmap_sem);
	return ret;
}

static inline int vm_munmap(unsigned long start, size_t len)
{
	struct mm_struct *mm = current->mm;
	int ret;

	down_write(&mm->mmap_sem);
	ret = do_munmap(mm, start, len);
	up_write(&mm->mmap_sem);
	return ret;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
#define vtime_account_system                    account_system_vtime
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
#define vtime_account_system                    vtime_account
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
#define vtime_account_system                    vtime_account_system_irqsafe
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
#include <linux/pci.h>
#include <linux/list.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
#include <linux/rculist.h>
#endif

#define hlist_entry_safe(ptr, type, member) \
        (ptr) ? hlist_entry(ptr, type, member) : NULL

#undef hlist_for_each_entry
#define hlist_for_each_entry(pos, head, member)                                 \
        for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), member);\
             pos;                                                       \
             pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
#define hlist_first_rcu(head)   (*((struct hlist_node __rcu **)(&(head)->first)))
#define hlist_next_rcu(node)    (*((struct hlist_node __rcu **)(&(node)->next)))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
#define rcu_dereference_raw     rcu_dereference
#endif

#undef hlist_for_each_entry_rcu
#define hlist_for_each_entry_rcu(pos, head, member)                     \
        for (pos = hlist_entry_safe (rcu_dereference_raw(hlist_first_rcu(head)),\
                        typeof(*(pos)), member);                        \
                pos;                                                    \
                pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(\
                        &(pos)->member)), typeof(*(pos)), member))
#endif /* < 3.9 */

#ifndef __percpu
#define __percpu
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#if defined(CONFIG_CONTEXT_TRACKING) && LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
extern void guest_enter(void);
extern void guest_exit(void);

#else /* !CONFIG_CONTEXT_TRACKING */
static inline void guest_enter(void)
{
        vtime_account_system(current);
        current->flags |= PF_VCPU;
}

static inline void guest_exit(void)
{
        vtime_account_system(current);
        current->flags &= ~PF_VCPU;
}
#endif /* !CONFIG_CONTEXT_TRACKING */
#endif /* < 3.10 */

