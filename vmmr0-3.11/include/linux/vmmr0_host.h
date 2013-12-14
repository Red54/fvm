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
#ifndef __KVM_HOST_H
#define __KVM_HOST_H

/*
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */
#include "os_interface.h"

#include <linux/vmmr0.h>
#include <linux/vmmr0_para.h>

#include <linux/vmmr0_types.h>

#include <asm/vmmr0_host.h>

#ifndef KVM_MMIO_SIZE
#define KVM_MMIO_SIZE 8
#endif

/*
 * vcpu->requests bit members
 */
#define KVM_REQ_TLB_FLUSH          0
#define KVM_REQ_MIGRATE_TIMER      1
#define KVM_REQ_REPORT_TPR_ACCESS  2
#define KVM_REQ_MMU_RELOAD         3
#define KVM_REQ_TRIPLE_FAULT       4
#define KVM_REQ_PENDING_TIMER      5
#define KVM_REQ_UNHALT             6
#define KVM_REQ_MMU_SYNC           7
#define KVM_REQ_CLOCK_UPDATE       8
#define KVM_REQ_KICK               9
#define KVM_REQ_DEACTIVATE_FPU    10
#define KVM_REQ_EVENT             11
#define KVM_REQ_APF_HALT          12
#define KVM_REQ_STEAL_UPDATE      13
#define KVM_REQ_NMI               14
#define KVM_REQ_IMMEDIATE_EXIT    15
#define KVM_REQ_PMU               16
#define KVM_REQ_PMI               17

#define KVM_USERSPACE_IRQ_SOURCE_ID	0

struct vm;
struct vmmr0_vcpu;

//#define HOST_LINUX_OPTIMIZED
#ifndef HOST_LINUX_OPTIMIZED
#undef CONFIG_KVM_ASYNC_PF
#endif

#ifdef HOST_LINUX_OPTIMIZED
extern struct kmem_cache *vmmr0_vcpu_cache;
#endif

struct vmmr0_io_range
{
	gpa_t addr;
	int len;
	struct vmmr0_io_device *dev;
};

struct vmmr0_io_bus
{
	int dev_count;
#define NR_IOBUS_DEVS 300
	struct vmmr0_io_range range[NR_IOBUS_DEVS];
};

enum vmmr0_bus
{
	KVM_MMIO_BUS, KVM_PIO_BUS, KVM_NR_BUSES
};

int vmmr0_io_bus_write(struct vm *pvm, enum vmmr0_bus bus_idx, gpa_t addr,
		int len, const void *val);
int vmmr0_io_bus_read(struct vm *pvm, enum vmmr0_bus bus_idx, gpa_t addr,
		int len, void *val);
int vmmr0_io_bus_register_dev(struct vm *pvm, enum vmmr0_bus bus_idx,
		gpa_t addr, int len, struct vmmr0_io_device *dev);
int vmmr0_io_bus_unregister_dev(struct vm *pvm, enum vmmr0_bus bus_idx,
		struct vmmr0_io_device *dev);

#ifdef CONFIG_KVM_ASYNC_PF
struct vmmr0_async_pf
{
	struct work_struct work;
	struct list_head link;
	struct list_head queue;
	struct vmmr0_vcpu *vcpu;
	struct mm_struct *mm;
	gva_t gva;
	unsigned long addr;
	struct vmmr0_arch_async_pf arch;
	struct page *page;
	bool done;
};
#endif
void vmmr0_clear_async_pf_completion_queue(struct vmmr0_vcpu *vcpu);
void vmmr0_check_async_pf_completion(struct vmmr0_vcpu *vcpu);
int vmmr0_setup_async_pf(struct vmmr0_vcpu *vcpu, gva_t gva, gfn_t gfn,
		struct vmmr0_arch_async_pf *arch);
int vmmr0_async_pf_wakeup_all(struct vmmr0_vcpu *vcpu);


enum
{
	OUTSIDE_GUEST_MODE, IN_GUEST_MODE, EXITING_GUEST_MODE
};

struct vmmr0_vcpu
{
	struct vm *pvm;
#ifdef CONFIG_PREEMPT_NOTIFIERS
	struct preempt_notifier preempt_notifier;
#endif
	int cpu;
	int vcpu_id;
	int srcu_idx;
	int mode;
	unsigned long requests;
	unsigned long guest_debug;

	struct mutex mutex;
	struct vmmr0_run *run;

	int fpu_active;
	int guest_fpu_loaded, guest_xcr0_loaded;
#if defined(HOST_LINUX)
	wait_queue_head_t wq;
#elif defined(HOST_WINDOWS)
	PRKEVENT kick_event;
	u64 blocked;
#endif

#ifdef OS_LINUX_OPTIMIZED_PID
	struct pid *pid;
#endif

	int sigset_active;
	sigset_t sigset;
	struct vmmr0_vcpu_stat stat;

#ifdef CONFIG_HAS_IOMEM
	int mmio_needed;
	int mmio_read_completed;
	int mmio_is_write;
	int mmio_size;
	int mmio_index;
	unsigned char mmio_data[KVM_MMIO_SIZE];
	gpa_t mmio_phys_addr;
#endif

#ifdef CONFIG_KVM_ASYNC_PF
	struct
	{
		u32 queued;
		struct list_head queue;
		struct list_head done;
		spinlock_t lock;
	}async_pf;
#endif

	struct vmmr0_vcpu_arch arch;
	int vcpufd;
};

static inline int vmmr0_vcpu_exiting_guest_mode(struct vmmr0_vcpu *vcpu)
{
	return cmpxchg(&vcpu->mode, IN_GUEST_MODE, EXITING_GUEST_MODE);
}

/*
 * Some of the bitops functions do not support too long bitmaps.
 * This number must be determined not to exceed such limits.
 */
#define KVM_MEM_MAX_NR_PAGES ((VMMR0_LPUL(1) << 31) - 1)

struct vmmr0_memory_slot
{
	gfn_t base_gfn;
	unsigned long npages;
	unsigned long flags;
	unsigned long *rmap;
	unsigned long *dirty_bitmap;
	unsigned long *dirty_bitmap_head;
	unsigned long nr_dirty_pages;
	struct vmmr0_arch_memory_slot arch;
	unsigned long userspace_addr;
	int user_alloc;
	int id;
};

static inline unsigned long vmmr0_dirty_bitmap_bytes(
		struct vmmr0_memory_slot *memslot)
{
	return ALIGN(memslot->npages, BITS_PER_LONG) / 8;
}

#ifdef CONFIG_HAVE_KVM_IRQCHIP
struct vmmr0_kernel_irq_routing_entry
{
	u32 gsi;
	u32 type;
	int (*set)(struct vmmr0_kernel_irq_routing_entry *e, struct vm *pvm,
			int irq_source_id, int level);
	union
	{
		struct
		{
			unsigned irqchip;
			unsigned pin;
		} irqchip;
		struct msi_msg msi;
	};
	struct hlist_node link;
};
#endif

#ifdef __KVM_HAVE_IOAPIC

struct vmmr0_irq_routing_table
{
	int chip[KVM_NR_IRQCHIPS][KVM_IOAPIC_NUM_PINS];
	struct vmmr0_kernel_irq_routing_entry *rt_entries;
	u32 nr_rt_entries;
	/*
	 * Array indexed by gsi. Each entry contains list of irq chips
	 * the gsi is connected to.
	 */
	struct hlist_head map[0];
};

#else

struct vmmr0_irq_routing_table
{};

#endif

#ifndef KVM_MEM_SLOTS_NUM
#define KVM_MEM_SLOTS_NUM (KVM_MEMORY_SLOTS + KVM_PRIVATE_MEM_SLOTS)
#endif

/*
 * Note:
 * memslots are not sorted by id anymore, please use id_to_memslot()
 * to get the memslot by its id.
 */
struct vmmr0_memslots
{
	u64 generation;
	struct vmmr0_memory_slot memslots[KVM_MEM_SLOTS_NUM];
	/* The mapping table from slot id to the index in memslots[]. */
	int id_to_index[KVM_MEM_SLOTS_NUM];
};

struct vm
{
	spinlock_t mmu_lock;
	struct mutex slots_lock;
#ifdef OS_LINUX_OPTIMIZED_MM
	struct mm_struct *mm; /* userspace tied to this vm */
#endif
	struct vmmr0_memslots *memslots;
	struct srcu_struct srcu;
#ifdef CONFIG_KVM_APIC_ARCHITECTURE
	u32 bsp_vcpu_id;
#endif
	struct vmmr0_vcpu *vcpus[VMMR0_MAX_VCPU_NUM];
	atomic_t online_vcpus;
	int last_boosted_vcpu;
	struct list_head vm_list;
	struct mutex lock;
	struct vmmr0_io_bus *buses[KVM_NR_BUSES];
#ifdef CONFIG_HAVE_KVM_EVENTFD
	struct
	{
		spinlock_t lock;
		struct list_head items;
	}irqfds;
	struct list_head ioeventfds;
#endif
	struct vmmr0_vm_stat stat;
	struct vmmr0_arch arch;
	atomic_t users_count;
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
	struct vmmr0_coalesced_mmio_ring *coalesced_mmio_ring;
	spinlock_t ring_lock;
	struct list_head coalesced_zones;
#endif

	struct mutex irq_lock;
#ifdef CONFIG_HAVE_KVM_IRQCHIP
	/*
	 * Update side is protected by irq_lock and,
	 * if configured, irqfds.lock.
	 */
	struct vmmr0_irq_routing_table __rcu *irq_routing;
	struct hlist_head mask_notifier_list;
	struct hlist_head irq_ack_notifier_list;
	spinlock_t mask_notifier_list_lock;
	spinlock_t irq_ack_notifier_list_lock;
#endif

#ifdef KVM_ARCH_WANT_MMU_NOTIFIER
	struct mmu_notifier mmu_notifier;
	unsigned long mmu_notifier_seq;
	long mmu_notifier_count;
#endif
	long tlbs_dirty;
	int vmfd;
#ifdef HOST_WINDOWS
	PEPROCESS proc;
	raw_spinlock_t raw_mmu_lock;
	u64 open_count;
#endif
};

/* The guest did something we don't support. */
#define pr_unimpl(vcpu, fmt, ...)					\
	pr_err_ratelimited("vmmr0: %i: cpu%i " fmt,			\
			   current->tgid, (vcpu)->vcpu_id , ## __VA_ARGS__)

#define vmmr0_printf(vmmr0, fmt ...) printk(KERN_DEBUG fmt)
#define vcpu_printf(vcpu, fmt...) vmmr0_printf(vcpu->vmmr0, fmt)

static inline struct vmmr0_vcpu *vmmr0_get_vcpu(struct vm *pvm, int i)
{
	smp_rmb();
	return pvm->vcpus[i];
}

#define vmmr0_for_each_vcpu(idx, vcpup, vmmr0) \
	for (idx = 0; \
	     idx < atomic_read(&vmmr0->online_vcpus) && \
	     (vcpup = vmmr0_get_vcpu(vmmr0, idx)) != NULL; \
	     idx++)

#define vmmr0_for_each_memslot(memslot, slots)	\
	for (memslot = &slots->memslots[0];	\
	      memslot < slots->memslots + KVM_MEM_SLOTS_NUM && memslot->npages;\
		memslot++)

int vmmr0_vcpu_init(struct vmmr0_vcpu *vcpu, struct vm *pvm, unsigned id);
void vmmr0_vcpu_uninit(struct vmmr0_vcpu *vcpu);

void vcpu_load(struct vmmr0_vcpu *vcpu);
void vcpu_put(struct vmmr0_vcpu *vcpu);

int vmmr0_init(void *opaque, unsigned vcpu_size, unsigned vcpu_align);
void vmmr0_exit(void);

void vmmr0_get_vm(struct vm *pvm);
void vmmr0_put_vm(struct vm *pvm);
void update_memslots(struct vmmr0_memslots *slots, struct vmmr0_memory_slot *thenew);

static inline struct vmmr0_memslots *vmmr0_memslots(struct vm *pvm)
{
#ifdef HOST_LINUX_OPTIMIZED
	return rcu_dereference_check(pvm->memslots,
			srcu_read_lock_held(&pvm->srcu)
					|| lockdep_is_held(&pvm->slots_lock));
#else
	return pvm->memslots;
#endif
}

static inline struct vmmr0_memory_slot *id_to_memslot(struct vmmr0_memslots *slots, int id)
{
	int index = slots->id_to_index[id];
	struct vmmr0_memory_slot *slot;

	slot = &slots->memslots[index];

	WARN_ON(slot->id != id);
	return slot;
}

#define HPA_MSB ((sizeof(hpa_t) * 8) - 1)
#define HPA_ERR_MASK ((hpa_t)1 << HPA_MSB)
static inline int is_error_hpa(hpa_t hpa)
{
	return hpa >> HPA_MSB;
}

extern struct page *bad_page;
extern struct page *fault_page;

extern pfn_t bad_pfn;
extern pfn_t fault_pfn;

#ifdef HOST_LINUX_OPTIMIZED
void vmmr0_resched(struct vmmr0_vcpu *vcpu);
#endif


int is_error_page(struct page *page);
int is_error_pfn(pfn_t pfn);
int is_hwpoison_pfn(pfn_t pfn);
int is_fault_pfn(pfn_t pfn);
int is_noslot_pfn(pfn_t pfn);
int is_invalid_pfn(pfn_t pfn);
int vmmr0_is_error_hva(unsigned long addr);
int vmmr0_set_memory_region(struct vm *pvm,
		struct vmmr0_userspace_memory_region *mem, int user_alloc);
int __vmmr0_set_memory_region(struct vm *pvm,
		struct vmmr0_userspace_memory_region *mem, int user_alloc);
void vmmr0_arch_free_memslot(struct vmmr0_memory_slot *free,
		struct vmmr0_memory_slot *dont);
int vmmr0_arch_create_memslot(struct vmmr0_memory_slot *slot,
		unsigned long npages);
int vmmr0_arch_prepare_memory_region(struct vm *pvm,
		struct vmmr0_memory_slot *memslot, struct vmmr0_memory_slot old,
		struct vmmr0_userspace_memory_region *mem, int user_alloc);
void vmmr0_arch_commit_memory_region(struct vm *pvm,
		struct vmmr0_userspace_memory_region *mem, struct vmmr0_memory_slot old,
		int user_alloc);
bool vmmr0_largepages_enabled(void);
void vmmr0_disable_largepages(void);
void vmmr0_arch_flush_shadow(struct vm *pvm);

int mmu_gfn_to_page_many_atomic(struct vm *pvm, gfn_t gfn, struct page **pages,
		int nr_pages);

struct page *mmu_gfn_to_page(struct vm *pvm, gfn_t gfn);
unsigned long mmu_gfn_to_hva(struct vm *pvm, gfn_t gfn);
void vmmr0_release_page_clean(struct page *page);
void vmmr0_release_page_dirty(struct page *page);
void vmmr0_set_page_dirty(struct page *page);
void vmmr0_set_page_accessed(struct page *page);

pfn_t hva_to_pfn_atomic(struct vm *pvm, unsigned long addr);
pfn_t mmu_gfn_to_pfn_atomic(struct vm *pvm, gfn_t gfn);
pfn_t mmu_gfn_to_pfn_async(struct vm *pvm, gfn_t gfn, bool *async,
		bool write_fault, bool *writable);
pfn_t mmu_gfn_to_pfn(struct vm *pvm, gfn_t gfn);
pfn_t mmu_gfn_to_pfn_prot(struct vm *pvm, gfn_t gfn, bool write_fault,
		bool *writable);
pfn_t mmu_gfn_to_pfn_memslot(struct vm *pvm, struct vmmr0_memory_slot *slot,
		gfn_t gfn);
void vmmr0_release_pfn_dirty(pfn_t);
void vmmr0_release_pfn_clean(pfn_t pfn);
void vmmr0_set_pfn_dirty(pfn_t pfn);
void vmmr0_set_pfn_accessed(pfn_t pfn);
void vmmr0_get_pfn(pfn_t pfn);

int vmmr0_read_guest_page(struct vm *pvm, gfn_t gfn, void *data, int offset,
		int len);
int vmmr0_read_guest_atomic(struct vm *pvm, gpa_t gpa, void *data,
		unsigned long len);
int vmmr0_read_guest(struct vm *pvm, gpa_t gpa, void *data, unsigned long len);
int vmmr0_read_guest_cached(struct vm *pvm, struct gfn_to_hva_cache *ghc,
		void *data, unsigned long len);
int vmmr0_write_guest_page(struct vm *pvm, gfn_t gfn, const void *data,
		int offset, int len);
int vmmr0_write_guest(struct vm *pvm, gpa_t gpa, const void *data,
		unsigned long len);
int vmmr0_write_guest_cached(struct vm *pvm, struct gfn_to_hva_cache *ghc,
		void *data, unsigned long len);
int vmmr0_gfn_to_hva_cache_init(struct vm *pvm, struct gfn_to_hva_cache *ghc,
		gpa_t gpa);
int vmmr0_clear_guest_page(struct vm *pvm, gfn_t gfn, int offset, int len);
int vmmr0_clear_guest(struct vm *pvm, gpa_t gpa, unsigned long len);
struct vmmr0_memory_slot *mmu_gfn_to_memslot(struct vm *pvm, gfn_t gfn);
int vmmr0_is_visible_gfn(struct vm *pvm, gfn_t gfn);
unsigned long vmmr0_host_page_size(struct vm *pvm, gfn_t gfn);
void mark_page_dirty(struct vm *pvm, gfn_t gfn);
void mark_page_dirty_in_slot(struct vm *pvm, struct vmmr0_memory_slot *memslot,
		gfn_t gfn);

int vmmr0_vcpu_block(struct vmmr0_vcpu *vcpu);
void vmmr0_vcpu_on_spin(struct vmmr0_vcpu *vcpu);
void vmmr0_load_guest_fpu(struct vmmr0_vcpu *vcpu);
void vmmr0_put_guest_fpu(struct vmmr0_vcpu *vcpu);

void vmmr0_flush_remote_tlbs(struct vm *pvm);
void vmmr0_reload_remote_mmus(struct vm *pvm);

long vmmr0_arch_dev_ioctl(struct file *filp, unsigned int ioctl,
		unsigned long arg);
long vmmr0_arch_vcpu_ioctl(struct file *filp, unsigned int ioctl,
		unsigned long arg);
int vmmr0_arch_vcpu_fault(struct vmmr0_vcpu *vcpu, struct vm_fault *vmf);

int vmmr0_dev_ioctl_check_extension(long ext);

int vmmr0_get_dirty_log(struct vm *pvm, struct vmmr0_dirty_log *log,
		int *is_dirty);
int vmmr0_vm_ioctl_get_dirty_log(struct vm *pvm, struct vmmr0_dirty_log *log);

int vmmr0_vm_ioctl_set_memory_region(struct vm *pvm,
		struct vmmr0_userspace_memory_region *mem, int user_alloc);
long vmmr0_arch_vm_ioctl(struct file *filp, unsigned int ioctl,
		unsigned long arg);

int vmmr0_arch_vcpu_ioctl_get_fpu(struct vmmr0_vcpu *vcpu,
		struct vmmr0_fpu *fpu);
int vmmr0_arch_vcpu_ioctl_set_fpu(struct vmmr0_vcpu *vcpu,
		struct vmmr0_fpu *fpu);

int vmmr0_arch_vcpu_ioctl_translate(struct vmmr0_vcpu *vcpu,
		struct vmmr0_translation *tr);

int vmmr0_arch_vcpu_ioctl_get_regs(struct vmmr0_vcpu *vcpu,
		struct vmmr0_regs *regs);
int vmmr0_arch_vcpu_ioctl_set_regs(struct vmmr0_vcpu *vcpu,
		struct vmmr0_regs *regs);
int vmmr0_arch_vcpu_ioctl_get_sregs(struct vmmr0_vcpu *vcpu,
		struct vmmr0_sregs *sregs);
int vmmr0_arch_vcpu_ioctl_set_sregs(struct vmmr0_vcpu *vcpu,
		struct vmmr0_sregs *sregs);
int vmmr0_arch_vcpu_ioctl_get_mpstate(struct vmmr0_vcpu *vcpu,
		struct vmmr0_mp_state *mp_state);
int vmmr0_arch_vcpu_ioctl_set_mpstate(struct vmmr0_vcpu *vcpu,
		struct vmmr0_mp_state *mp_state);
int vmmr0_arch_vcpu_ioctl_set_guest_debug(struct vmmr0_vcpu *vcpu,
		struct vmmr0_guest_debug *dbg);
int vmmr0_arch_vcpu_ioctl_run(struct vmmr0_vcpu *vcpu,
		struct vmmr0_run *vmmr0_run);

int vmmr0_arch_init(void *opaque);
void vmmr0_arch_exit(void);

int vmmr0_arch_vcpu_init(struct vmmr0_vcpu *vcpu);
void vmmr0_arch_vcpu_uninit(struct vmmr0_vcpu *vcpu);

void vmmr0_arch_vcpu_free(struct vmmr0_vcpu *vcpu);
void vmmr0_arch_vcpu_load(struct vmmr0_vcpu *vcpu, int cpu);
void vmmr0_arch_vcpu_put(struct vmmr0_vcpu *vcpu);
struct vmmr0_vcpu *vmmr0_arch_vcpu_create(struct vm *pvm, unsigned int id);
int vmmr0_arch_vcpu_setup(struct vmmr0_vcpu *vcpu);
void vmmr0_arch_vcpu_destroy(struct vmmr0_vcpu *vcpu);

int vmmr0_arch_vcpu_reset(struct vmmr0_vcpu *vcpu);
int vmmr0_arch_hardware_enable(void *garbage);
void vmmr0_arch_hardware_disable(void *garbage);
int vmmr0_arch_hardware_setup(void);
void vmmr0_arch_hardware_unsetup(void);
void vmmr0_arch_check_processor_compat(void *rtn);
int vmmr0_arch_vcpu_runnable(struct vmmr0_vcpu *vcpu);

void vmmr0_free_physmem(struct vm *pvm);

#ifndef __KVM_HAVE_ARCH_VM_ALLOC
static inline struct vm *vmmr0_arch_alloc_vm(void)
{
	return kzalloc(sizeof(struct vm), GFP_KERNEL);
}

static inline void vmmr0_arch_free_vm(struct vm *pvm)
{
	kfree(pvm);
}
#endif

int vmmr0_arch_init_vm(struct vm *pvm, unsigned long type);
void vmmr0_arch_destroy_vm(struct vm *pvm);
void vmmr0_free_all_assigned_devices(struct vm *pvm);
void vmmr0_arch_sync_events(struct vm *pvm);

int vmmr0_cpu_has_pending_timer(struct vmmr0_vcpu *vcpu);
void vmmr0_vcpu_kick(struct vmmr0_vcpu *vcpu);

int vmmr0_is_mmio_pfn(pfn_t pfn);

struct vmmr0_irq_ack_notifier
{
	struct hlist_node link;
	unsigned gsi;
	void (*irq_acked)(struct vmmr0_irq_ack_notifier *kian);
};

#ifdef CONFIG_HAVE_ASSIGNED_DEV
struct vmmr0_assigned_dev_kernel
{
	struct vmmr0_irq_ack_notifier ack_notifier;
	struct list_head list;
	int assigned_dev_id;
	int host_segnr;
	int host_busnr;
	int host_devfn;
	unsigned int entries_nr;
	int host_irq;
	bool host_irq_disabled;
	bool pci_2_3;
	struct msix_entry *host_msix_entries;
	int guest_irq;
	struct msix_entry *guest_msix_entries;
	unsigned long irq_requested_type;
	int irq_source_id;
	int flags;
	struct pci_dev *dev;
	struct vm *pvm;
	spinlock_t intx_lock;
	spinlock_t intx_mask_lock;
	char irq_name[32];
	struct pci_saved_state *pci_saved_state;
};
#endif

struct vmmr0_irq_mask_notifier
{
	void (*func)(struct vmmr0_irq_mask_notifier *kimn, bool masked);
	int irq;
	struct hlist_node link;
};

void vmmr0_register_irq_mask_notifier(struct vm *pvm, int irq,
		struct vmmr0_irq_mask_notifier *kimn);
void vmmr0_unregister_irq_mask_notifier(struct vm *pvm, int irq,
		struct vmmr0_irq_mask_notifier *kimn);
void vmmr0_fire_mask_notifiers(struct vm *pvm, unsigned irqchip, unsigned pin,
		bool mask);

#ifdef __KVM_HAVE_IOAPIC
void vmmr0_get_intr_delivery_bitmask(struct vmmr0_ioapic *ioapic,
		union vmmr0_ioapic_redirect_entry *entry,
		unsigned long *deliver_bitmask);
#endif
#ifdef CONFIG_HAVE_KVM_IRQCHIP
int vmmr0_set_irq(struct vm *pvm, int irq_source_id, u32 irq, int level);
int vmmr0_set_msi(struct vmmr0_kernel_irq_routing_entry *irq_entry,
		struct vm *pvm, int irq_source_id, int level);
void vmmr0_notify_acked_irq(struct vm *pvm, unsigned irqchip, unsigned pin);
void vmmr0_register_irq_ack_notifier(struct vm *pvm,
		struct vmmr0_irq_ack_notifier *kian);
void vmmr0_unregister_irq_ack_notifier(struct vm *pvm,
		struct vmmr0_irq_ack_notifier *kian);
int vmmr0_request_irq_source_id(struct vm *pvm);
void vmmr0_free_irq_source_id(struct vm *pvm, int irq_source_id);
#endif
/* For vcpu->arch.iommu_flags */
#define KVM_IOMMU_CACHE_COHERENCY	0x1

#ifdef CONFIG_IOMMU_API
int vmmr0_iommu_map_pages(struct vm *pvm, struct vmmr0_memory_slot *slot);
void vmmr0_iommu_unmap_pages(struct vm *pvm, struct vmmr0_memory_slot *slot);
int vmmr0_iommu_map_guest(struct vm *pvm);
int vmmr0_iommu_unmap_guest(struct vm *pvm);
#ifdef CONFIG_HAVE_ASSIGNED_DEV
int vmmr0_assign_device(struct vm *pvm,
		struct vmmr0_assigned_dev_kernel *assigned_dev);
int vmmr0_deassign_device(struct vm *pvm,
		struct vmmr0_assigned_dev_kernel *assigned_dev);
#endif
#else /* CONFIG_IOMMU_API */
static inline int vmmr0_iommu_map_pages(struct vm *pvm,
		struct vmmr0_memory_slot *slot)
{
	return 0;
}

static inline void vmmr0_iommu_unmap_pages(struct vm *pvm,
		struct vmmr0_memory_slot *slot)
{
}

static inline int vmmr0_iommu_map_guest(struct vm *pvm)
{
	return -ENODEV;
}

static inline int vmmr0_iommu_unmap_guest(struct vm *pvm)
{
	return 0;
}

#ifdef CONFIG_HAVE_ASSIGNED_DEV
static inline int vmmr0_assign_device(struct vm *pvm,
		struct vmmr0_assigned_dev_kernel *assigned_dev)
{
	return 0;
}

static inline int vmmr0_deassign_device(struct vm *pvm,
		struct vmmr0_assigned_dev_kernel *assigned_dev)
{
	return 0;
}
#endif //CONFIG_HAVE_ASSIGNED_DEV
#endif /* CONFIG_IOMMU_API */

static inline void vmmr0_guest_enter(void)
{
#ifdef HOST_LINUX
	unsigned long flags;
	BUG_ON(preemptible());

	local_irq_save(flags);
	guest_enter();
	local_irq_restore(flags);
	
	rcu_virt_note_context_switch(smp_processor_id());
#endif
}

static inline void vmmr0_guest_exit(void)
{
#ifdef HOST_LINUX
	unsigned long flags;
	
	local_irq_save(flags);
	guest_exit();
	local_irq_restore(flags);
#endif
}

/*
 * search_memslots() and __gfn_to_memslot() are here because they are
 * used in non-modular code in arch/powerpc/vmmr0/book3s_hv_rm_mmu.c.
 * mmu_gfn_to_memslot() itself isn't here as an inline because that would
 * bloat other code too much.
 */
static inline struct vmmr0_memory_slot *
search_memslots(struct vmmr0_memslots *slots, gfn_t gfn)
{
	struct vmmr0_memory_slot *memslot;

	vmmr0_for_each_memslot(memslot, slots)
	{
		if (gfn >= memslot->base_gfn
				&& gfn < memslot->base_gfn + memslot->npages)
		{
			return memslot;
		}
	}

	return NULL;
}

static inline struct vmmr0_memory_slot *
__gfn_to_memslot(struct vmmr0_memslots *slots, gfn_t gfn)
{
	return search_memslots(slots, gfn);
}

static inline int memslot_id(struct vm *pvm, gfn_t gfn)
{
	return mmu_gfn_to_memslot(pvm, gfn)->id;
}

static inline gfn_t gfn_to_index(gfn_t gfn, gfn_t base_gfn, int level)
{
	/* KVM_HPAGE_GFN_SHIFT(PT_PAGE_TABLE_LEVEL) must be 0. */
	return (gfn >> KVM_HPAGE_GFN_SHIFT(level))
			- (base_gfn >> KVM_HPAGE_GFN_SHIFT(level));
}

static inline unsigned long gfn_to_hva_memslot(struct vmmr0_memory_slot *slot,
		gfn_t gfn)
{
	return slot->userspace_addr + (gfn - slot->base_gfn) * PAGE_SIZE;
}

static inline gpa_t gfn_to_gpa(gfn_t gfn)
{
	return (gpa_t) gfn << PAGE_SHIFT;
}

static inline gfn_t gpa_to_gfn(gpa_t gpa)
{
	return (gfn_t) (gpa >> PAGE_SHIFT);
}

static inline hpa_t pfn_to_hpa(pfn_t pfn)
{
	return (hpa_t) pfn << PAGE_SHIFT;
}

static inline void vmmr0_migrate_timers(struct vmmr0_vcpu *vcpu)
{
	set_bit(KVM_REQ_MIGRATE_TIMER, &vcpu->requests);
}

enum vmmr0_stat_kind
{
	VMMR0_VM_STATUS, VMMR0_VCPU_STATUS,
};

#ifdef HOST_LINUX_OPTIMIZED
struct vmmr0_stats_debugfs_item
{
	const char *name;
	int offset;
	enum vmmr0_stat_kind kind;
	struct dentry *dentry;
};
extern struct vmmr0_stats_debugfs_item debugfs_entries[];
extern struct dentry *vmmr0_debugfs_dir;
#endif

#ifdef KVM_ARCH_WANT_MMU_NOTIFIER
static inline int mmu_notifier_retry(struct vmmr0_vcpu *vcpu,
		unsigned long mmu_seq)
{
	if (unlikely(vcpu->pvm->mmu_notifier_count))
		return 1;
	/*
	 * Ensure the read of mmu_notifier_count happens before the read
	 * of mmu_notifier_seq.  This interacts with the smp_wmb() in
	 * mmu_notifier_invalidate_range_end to make sure that the caller
	 * either sees the old (non-zero) value of mmu_notifier_count or
	 * the new (incremented) value of mmu_notifier_seq.
	 * PowerPC Book3s HV KVM calls this under a per-page lock
	 * rather than under vmmr0->mmu_lock, for scalability, so
	 * can't rely on vmmr0->mmu_lock to keep things ordered.
	 */
	smp_rmb();
	if (vcpu->pvm->mmu_notifier_seq != mmu_seq)
	{
		return 1;
	}
	return 0;
}
#endif

#ifdef CONFIG_HAVE_KVM_IRQCHIP

#define KVM_MAX_IRQ_ROUTES 1024

int vmmr0_setup_default_irq_routing(struct vm *pvm);
int vmmr0_set_irq_routing(struct vm *pvm,
		const struct vmmr0_irq_routing_entry *entries,
		unsigned nr,
		unsigned flags);
void vmmr0_free_irq_routing(struct vm *pvm);

#else

static inline void vmmr0_free_irq_routing(struct vm *pvm)
{
}

#endif

#ifdef CONFIG_HAVE_KVM_EVENTFD

void vmmr0_eventfd_init(struct vm *pvm);
int vmmr0_irqfd(struct vm *pvm, int fd, int gsi, int flags);
void vmmr0_irqfd_release(struct vm *pvm);
void vmmr0_irq_routing_update(struct vm *, struct vmmr0_irq_routing_table *);
int vmmr0_ioeventfd(struct vm *pvm, struct vmmr0_ioeventfd *args);

#else
static inline void vmmr0_eventfd_init(struct vm *pvm)
{
}

static inline int vmmr0_irqfd(struct vm *pvm, int fd, int gsi, int flags)
{
	return -EINVAL;
}

static inline void vmmr0_irqfd_release(struct vm *pvm)
{
}

#ifdef CONFIG_HAVE_KVM_IRQCHIP
static inline void vmmr0_irq_routing_update(struct vm *pvm,
		struct vmmr0_irq_routing_table *irq_rt)
{
	rcu_assign_pointer(vmmr0->irq_routing, irq_rt);
}
#endif

static inline int vmmr0_ioeventfd(struct vm *pvm, struct vmmr0_ioeventfd *args)
{
	return -ENOSYS;
}

#endif /* CONFIG_HAVE_KVM_EVENTFD */

#ifdef CONFIG_KVM_APIC_ARCHITECTURE
static inline bool vmmr0_vcpu_is_bsp(struct vmmr0_vcpu *vcpu)
{
	return vcpu->pvm->bsp_vcpu_id == vcpu->vcpu_id;
}

bool vmmr0_vcpu_compatible(struct vmmr0_vcpu *vcpu);

#else

static inline bool vmmr0_vcpu_compatible(struct vmmr0_vcpu *vcpu)
{
	return true;
}

#endif

#ifdef __KVM_HAVE_DEVICE_ASSIGNMENT

long vmmr0_vm_ioctl_assigned_device(struct vm *pvm, unsigned ioctl,
		unsigned long arg);

#else

static inline long vmmr0_vm_ioctl_assigned_device(struct vm *pvm, unsigned ioctl,
		unsigned long arg)
{
	return -ENOTTY;
}

#endif

static inline void vmmr0_make_request(int req, struct vmmr0_vcpu *vcpu)
{
	set_bit(req, &vcpu->requests);
}

static inline bool vmmr0_check_request(int req, struct vmmr0_vcpu *vcpu)
{
	if (test_bit(req, &vcpu->requests))
	{
		clear_bit(req, &vcpu->requests);
		return true;
	}
	else
	{
		return false;
	}
}

#ifdef HOST_LINUX
static inline void *vmmr0_kvzalloc(unsigned long size)
{
	if (size > PAGE_SIZE)
	{
		return vzalloc(size);
	}
	else
	{
		return kzalloc(size, GFP_KERNEL);
	}
}

static inline void vmmr0_kvfree(const void *addr)
{
	if (is_vmalloc_addr(addr))
	{
		vfree((void *)addr);
	}
	else
	{
		kfree(addr);
	}
}
#else
#define vmmr0_kvzalloc vzalloc
#define vmmr0_kvfree vfree
#endif

#endif

