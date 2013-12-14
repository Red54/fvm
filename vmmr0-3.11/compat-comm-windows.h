#include "os_interface.h"


#include <linux/vmmr0.h>
#include <linux/vmmr0_para.h>

#include "vmmr0-config.h"

#ifndef GFP_NOWAIT
#define GFP_NOWAIT 0
#endif




int vmmr0_smp_call_function_single(int cpu, void (*func)(void *info),
				 void *info, int wait);


#define smp_call_function_single vmmr0_smp_call_function_single


#define vmmr0_on_each_cpu(func, info, wait) on_each_cpu(func, info, wait)


#ifdef CONFIG_64BIT

static inline uint64_t div64_u64(uint64_t dividend, uint64_t divisor)
{
	return dividend / divisor;
}

#else

uint64_t div64_u64(uint64_t dividend, uint64_t divisor);

#endif


#ifndef PF_VCPU
#define PF_VCPU 0
#endif

#define empty_zero_page vmmr0_empty_zero_page

static char empty_zero_page[PAGE_SIZE];

#define mmdrop(x) do { (void)(x); } while (0)
#define mmget(x) do { (void)(x); } while (0)


#define MAKE_SIMPLE_ATTRIBUTE_GETTER(x)       \
	static int x(void *v, u64 *val)	      \
	{				      \
		return __##x(v, val);	      \
	}


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

static inline unsigned int cpufreq_get(unsigned int cpu)
{
	return 0;
}

#ifndef CONFIG_MMU_NOTIFIER
struct mmu_notifier {};
#endif

struct vmmr0_user_return_notifier
{
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
	{
		urn->on_user_return(urn);
	}
}

#ifndef WARN_ONCE
#define WARN_ONCE(condition, format...)
#endif

#ifndef WARN
#define WARN(condition, format...)	WARN_ON(condition)
#endif


#define rcu_dereference_check(p, sp)	rcu_dereference(p)
#define rcu_dereference_protected(p, c)	rcu_dereference(p)
#define srcu_dereference(p, sp)		rcu_dereference(p)
#define srcu_read_lock_held(sp)		(1)

#define lockdep_is_held(m)		(1)


#ifndef lower_32_bits
#define lower_32_bits(n) ((u32)(n))
#endif

#define EHWPOISON	133	/* Memory page has hardware error */
#define FOLL_HWPOISON	0x100	/* check page is hwpoisoned */

#ifndef __rcu
#define __rcu
#endif

#define compound_trans_head(page) compound_head(page)

static inline int PageTransCompound(struct page *page)
{
        return 0;
}

#define vmmr0___this_cpu_read(n)		__get_cpu_var(n)
#define vmmr0___this_cpu_write(n, v)	__get_cpu_var(n) = v

#ifndef __noclone
#define __noclone	__attribute__((__noclone__))
#endif

#ifndef FOLL_NOWAIT
#define FOLL_NOWAIT	0x20
#endif

struct vmmr0_x86_pmu_capability
{
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

#define PCI_STD_RESOURCES	0
#define PCI_STD_RESOURCE_END	5


#ifndef MAY_ACCESS
#define MAY_ACCESS		0x00000010
#endif

static inline void *memdup_user(const void *user, size_t size)
{
	void *buf = kzalloc(size, GFP_KERNEL);

	if (!buf)
		return ERR_PTR(-ENOMEM);
	if (copy_from_user(buf, user, size))
		return ERR_PTR(-EFAULT);
	return buf;
}


struct x86_cpu_id { };
#define X86_FEATURE_MATCH(x) { }

#define PROT_READ	0x1		/* page can be read */
#define PROT_WRITE	0x2		/* page can be written */
#define PROT_EXEC	0x4		/* page can be executed */
#define PROT_SEM	0x8		/* page may be used for atomic ops */
#define PROT_NONE	0x0		/* page can not be accessed */
#define PROT_GROWSDOWN	0x01000000	/* mprotect flag: extend change to start of growsdown vma */
#define PROT_GROWSUP	0x02000000	/* mprotect flag: extend change to end of growsup vma */

#define MAP_SHARED	0x01		/* Share changes */
#define MAP_PRIVATE	0x02		/* Changes are private */
#define MAP_TYPE	0x0f		/* Mask for type of mapping */
#define MAP_FIXED	0x10		/* Interpret addr exactly */
#define MAP_ANONYMOUS	0x20		/* don't use a file */
#define MAP_UNINITIALIZED 0x0		/* Don't support this flag */

typedef struct vmmr0_mmap_node
{
	PMDL pMDL;
	PVOID pMem;
	PVOID UserVA;
	struct list_head list;
}vmmr0_mmap_node;

extern struct list_head vmmr0_mmap_list;
DECLARE_RAW_SPINLOCK(vmmr0_mmap_lock);

static inline unsigned long vm_mmap(struct file *file, unsigned long addr,
				    unsigned long len, unsigned long prot,
				    unsigned long flag, unsigned long offset)
{

	//vm_mmap(void* pR0, void* pR3, u64 SizeInByte, PMDL* pPMDL/*, _POOL_TYPE Type*/)

	PMDL pMDL = NULL;
	PVOID pMem = NULL;
	PVOID UserVA = NULL;
	struct vmmr0_mmap_node *node = ExAllocatePool(NonPagedPool, sizeof(struct vmmr0_mmap_node));
	if(!node)
	{
		printk(("vmmr0:vm_mmap: ExAllocatePool Failed!\n"));
		return (unsigned long)NULL;
	}
	pMem = ExAllocatePool(NonPagedPool,len);
	if(pMem)
	{
		printk("vmmr0:pMem: %X%X\n",*((ULONG*)&pMem+1),*((ULONG*)&pMem));
		memset(pMem,0,len);
	}
	else
	{
		printk(("vmmr0:vm_mmap: ExAllocatePool Failed!\n"));
		return (unsigned long)NULL;
	}
	pMDL = IoAllocateMdl(pMem,len,FALSE,FALSE,NULL);
	if(pMDL)
	{
		printk("vmmr0:MDL: ByteCount:%X, ByteOffset:%X,MappedSystemVa:%X%X, StartVa:%X%X, Size %X\n",
			      pMDL->ByteCount,
				  pMDL->ByteOffset,
				  *((ULONG*)&pMDL->MappedSystemVa+1),*((ULONG*)&pMDL->MappedSystemVa),
				  *((ULONG*)&pMDL->StartVa+1),*((ULONG*)&pMDL->StartVa),
				  pMDL->Size);
	}
	else
	{
		printk(("vmmr0:MDL Allocate Failed!\n"));
		ExFreePool(pMem);
		return (unsigned long)NULL;
	}
	MmBuildMdlForNonPagedPool(pMDL);
	UserVA = MmMapLockedPagesSpecifyCache(pMDL,UserMode,MmNonCached,0,0,NormalPagePriority);

	if(UserVA)
	{
		printk("vmmr0:UserVA: %X%X\n",*((ULONG*)&UserVA+1),*((ULONG*)&UserVA));
	}
	else
	{
		printk(("vmmr0:MmMapLockedPagesSpecifyCache Failed!\n"));
		IoFreeMdl(pMDL);
		ExFreePool(pMem);
		return (unsigned long)NULL;
	}
	node->UserVA = UserVA;
	node->pMDL = pMDL;
	node->pMem = pMem;

	raw_spin_lock(&vmmr0_mmap_lock);
	list_add_tail(&node->list, &vmmr0_mmap_list);
	raw_spin_unlock(&vmmr0_mmap_lock);
	return (unsigned long)UserVA;
}

static inline int vm_munmap(unsigned long start, size_t len)
{
	struct vmmr0_mmap_node* node;
	struct list_head* i;
	int find = 0;
	raw_spin_lock(&vmmr0_mmap_lock);
	list_for_each(i, &vmmr0_mmap_list)
	{
		node = list_entry(i, struct vmmr0_mmap_node, list);
		if (node->UserVA == (PVOID)start)
		{
			find = 1;
			break;
		}
	}
	raw_spin_unlock(&vmmr0_mmap_lock);
	if(!find)
	{
		return -1;
	}
	if(node->pMDL)
	{
		IoFreeMdl(node->pMDL);
	}
	if(node->pMem)
	{
		ExFreePool(node->pMem);
	}
	ExFreePool(node);
	return 0;
}

