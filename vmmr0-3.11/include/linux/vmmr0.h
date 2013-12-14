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
#ifndef __LINUX_KVM_H
#define __LINUX_KVM_H

/*
 * Userspace interface for /dev/vmmr0 - kernel based virtual machine
 *
 * Note: you must update KVM_API_VERSION if you change this interface.
 */

#include "os_interface.h"

#include <asm/vmmr0.h>

#define KVM_API_VERSION 12

/* *** Deprecated interfaces *** */

#define KVM_TRC_SHIFT           16

#define KVM_TRC_ENTRYEXIT       (1 << KVM_TRC_SHIFT)
#define KVM_TRC_HANDLER         (1 << (KVM_TRC_SHIFT + 1))

#define KVM_TRC_VMENTRY         (KVM_TRC_ENTRYEXIT + 0x01)
#define KVM_TRC_VMEXIT          (KVM_TRC_ENTRYEXIT + 0x02)
#define KVM_TRC_PAGE_FAULT      (KVM_TRC_HANDLER + 0x01)

#define KVM_TRC_HEAD_SIZE       12
#define KVM_TRC_CYCLE_SIZE      8
#define KVM_TRC_EXTRA_MAX       7

#define KVM_TRC_INJ_VIRQ         (KVM_TRC_HANDLER + 0x02)
#define KVM_TRC_REDELIVER_EVT    (KVM_TRC_HANDLER + 0x03)
#define KVM_TRC_PEND_INTR        (KVM_TRC_HANDLER + 0x04)
#define KVM_TRC_IO_READ          (KVM_TRC_HANDLER + 0x05)
#define KVM_TRC_IO_WRITE         (KVM_TRC_HANDLER + 0x06)
#define KVM_TRC_CR_READ          (KVM_TRC_HANDLER + 0x07)
#define KVM_TRC_CR_WRITE         (KVM_TRC_HANDLER + 0x08)
#define KVM_TRC_DR_READ          (KVM_TRC_HANDLER + 0x09)
#define KVM_TRC_DR_WRITE         (KVM_TRC_HANDLER + 0x0A)
#define KVM_TRC_MSR_READ         (KVM_TRC_HANDLER + 0x0B)
#define KVM_TRC_MSR_WRITE        (KVM_TRC_HANDLER + 0x0C)
#define KVM_TRC_CPUID            (KVM_TRC_HANDLER + 0x0D)
#define KVM_TRC_INTR             (KVM_TRC_HANDLER + 0x0E)
#define KVM_TRC_NMI              (KVM_TRC_HANDLER + 0x0F)
#define KVM_TRC_VMMCALL          (KVM_TRC_HANDLER + 0x10)
#define KVM_TRC_HLT              (KVM_TRC_HANDLER + 0x11)
#define KVM_TRC_CLTS             (KVM_TRC_HANDLER + 0x12)
#define KVM_TRC_LMSW             (KVM_TRC_HANDLER + 0x13)
#define KVM_TRC_APIC_ACCESS      (KVM_TRC_HANDLER + 0x14)
#define KVM_TRC_TDP_FAULT        (KVM_TRC_HANDLER + 0x15)
#define KVM_TRC_GTLB_WRITE       (KVM_TRC_HANDLER + 0x16)
#define KVM_TRC_STLB_WRITE       (KVM_TRC_HANDLER + 0x17)
#define KVM_TRC_STLB_INVAL       (KVM_TRC_HANDLER + 0x18)
#define KVM_TRC_PPC_INSTR        (KVM_TRC_HANDLER + 0x19)


#define __KVM_DEPRECATED_MAIN_0x07 _IO(KVMIO, 0x07)
#define __KVM_DEPRECATED_MAIN_0x08 _IO(KVMIO, 0x08)

#define __KVM_DEPRECATED_VM_R_0x70 _IOR(KVMIO, 0x70, struct vmmr0_assigned_irq)

struct vmmr0_breakpoint
{
	__u32 enabled;
	__u32 padding;
	__u64 address;
};

struct vmmr0_debug_guest
{
	__u32 enabled;
	__u32 pad;
	struct vmmr0_breakpoint breakpoints[4];
	__u32 singlestep;
};

#define __KVM_DEPRECATED_VCPU_W_0x87 _IOW(KVMIO, 0x87, struct vmmr0_debug_guest)

/* *** End of deprecated interfaces *** */


/* for KVM_CREATE_MEMORY_REGION */
struct vmmr0_memory_region
{
	__u32 slot;
	__u32 flags;
	__u64 guest_phys_addr;
	__u64 memory_size; /* bytes */
};

/* for KVM_SET_USER_MEMORY_REGION */
struct vmmr0_userspace_memory_region
{
	__u32 slot;
	__u32 flags;
	__u64 guest_phys_addr;
	__u64 memory_size; /* bytes */
	__u64 userspace_addr; /* start of the userspace allocated memory */
};

/* for vmmr0_memory_region::flags */
#define KVM_MEM_LOG_DIRTY_PAGES  VMMR0_LPUL(1)
#define KVM_MEMSLOT_INVALID      (VMMR0_LPUL(1) << 1)

/* for KVM_IRQ_LINE */
struct vmmr0_irq_level
{
	/*
	 * ACPI gsi notion of irq.
	 * For IA-64 (APIC model) IOAPIC0: irq 0-23; IOAPIC1: irq 24-47..
	 * For X86 (standard AT mode) PIC0/1: irq 0-15. IOAPIC0: 0-23..
	 */
	union
	{
		__u32 irq;
		__s32 status;
	};
	__u32 level;
};


struct vmmr0_irqchip
{
	__u32 chip_id;
	__u32 pad;
    union
    {
		char dummy[512];  /* reserving space */
#ifdef __KVM_HAVE_PIT
		struct vmmr0_pic_state pic;
#endif
#ifdef __KVM_HAVE_IOAPIC
		struct vmmr0_ioapic_state ioapic;
#endif
	} chip;
};

/* for KVM_CREATE_PIT2 */
struct vmmr0_pit_config
{
	__u32 flags;
	__u32 pad[15];
};

#define KVM_PIT_SPEAKER_DUMMY     1

#define KVM_EXIT_UNKNOWN          0
#define KVM_EXIT_EXCEPTION        1
#define KVM_EXIT_IO               2
#define KVM_EXIT_HYPERCALL        3
#define KVM_EXIT_DEBUG            4
#define KVM_EXIT_HLT              5
#define KVM_EXIT_MMIO             6
#define KVM_EXIT_IRQ_WINDOW_OPEN  7
#define KVM_EXIT_SHUTDOWN         8
#define KVM_EXIT_FAIL_ENTRY       9
#define KVM_EXIT_INTR             10
#define KVM_EXIT_SET_TPR          11
#define KVM_EXIT_TPR_ACCESS       12
#define KVM_EXIT_S390_SIEIC       13
#define KVM_EXIT_S390_RESET       14
#define KVM_EXIT_DCR              15
#define KVM_EXIT_NMI              16
#define KVM_EXIT_INTERNAL_ERROR   17
#define KVM_EXIT_OSI              18
#define KVM_EXIT_PAPR_HCALL	  19
#define KVM_EXIT_S390_UCONTROL	  20

/* For KVM_EXIT_INTERNAL_ERROR */
#define KVM_INTERNAL_ERROR_EMULATION 1
#define KVM_INTERNAL_ERROR_SIMUL_EX 2

/* for KVM_RUN, returned by mmap(vcpu_fd, offset=0) */
struct vmmr0_run
{
	/* in */
	__u8 request_interrupt_window;
	__u8 padding1[7];

	/* out */
	__u32 exit_reason;
	__u8 ready_for_interrupt_injection;
	__u8 if_flag;
	__u8 padding2[2];

	/* in (pre_vmmr0_run), out (post_vmmr0_run) */
	__u64 cr8;
	__u64 apic_base;

	union
	{
		/* KVM_EXIT_UNKNOWN */
		struct
		{
			__u64 hardware_exit_reason;
		} hw;
		/* KVM_EXIT_FAIL_ENTRY */
		struct
		{
			__u64 hardware_entry_failure_reason;
		} fail_entry;
		/* KVM_EXIT_EXCEPTION */
		struct
		{
			__u32 exception;
			__u32 error_code;
		} ex;
		/* KVM_EXIT_IO */
		struct
		{
#define KVM_EXIT_IO_IN  0
#define KVM_EXIT_IO_OUT 1
			__u8 direction;
			__u8 size; /* bytes */
			__u16 port;
			__u32 count;
			__u64 data_offset; /* relative to vmmr0_run start */
		} io;
		struct
		{
			struct vmmr0_debug_exit_arch arch;
		} debug;
		/* KVM_EXIT_MMIO */
		struct
		{
			__u64 phys_addr;
			__u8  data[8];
			__u32 len;
			__u8  is_write;
		} mmio;
		/* KVM_EXIT_HYPERCALL */
		struct
		{
			__u64 nr;
			__u64 args[6];
			__u64 ret;
			__u32 longmode;
			__u32 pad;
		} hypercall;
		/* KVM_EXIT_TPR_ACCESS */
		struct
		{
			__u64 rip;
			__u32 is_write;
			__u32 pad;
		} tpr_access;

		/* KVM_EXIT_DCR */
		struct
		{
			__u32 dcrn;
			__u32 data;
			__u8  is_write;
		} dcr;
		struct
		{
			__u32 suberror;
			/* Available with KVM_CAP_INTERNAL_ERROR_DATA: */
			__u32 ndata;
			__u64 data[16];
		} internal;
		/* KVM_EXIT_OSI */
		struct
		{
			__u64 gprs[32];
		} osi;
		struct
		{
			__u64 nr;
			__u64 ret;
			__u64 args[9];
		} papr_hcall;
		/* Fix the size of the union. */
		char padding[256];
	};

	/*
	 * shared registers between vmmr0 and userspace.
	 * vmmr0_valid_regs specifies the register classes set by the host
	 * vmmr0_dirty_regs specified the register classes dirtied by userspace
	 * struct vmmr0_sync_regs is architecture specific, as well as the
	 * bits for vmmr0_valid_regs and vmmr0_dirty_regs
	 */
	__u64 vmmr0_valid_regs;
	__u64 vmmr0_dirty_regs;
	union
	{
		struct vmmr0_sync_regs regs;
		char padding[1024];
	} s;
#ifdef HOST_WINDOWS
	__u64 exit_request;
#endif
};

/* for KVM_REGISTER_COALESCED_MMIO / KVM_UNREGISTER_COALESCED_MMIO */

struct vmmr0_coalesced_mmio_zone
{
	__u64 addr;
	__u32 size;
	__u32 pad;
};

struct vmmr0_coalesced_mmio
{
	__u64 phys_addr;
	__u32 len;
	__u32 pad;
	__u8  data[8];
};

struct vmmr0_coalesced_mmio_ring
{
	__u32 first, last;
	struct vmmr0_coalesced_mmio coalesced_mmio[0];
};

#define KVM_COALESCED_MMIO_MAX \
	((PAGE_SIZE - sizeof(struct vmmr0_coalesced_mmio_ring)) / \
	 sizeof(struct vmmr0_coalesced_mmio))

/* for KVM_TRANSLATE */
struct vmmr0_translation
{
	/* in */
	__u64 linear_address;

	/* out */
	__u64 physical_address;
	__u8  valid;
	__u8  writeable;
	__u8  usermode;
	__u8  pad[5];
};

/* for KVM_INTERRUPT */
struct vmmr0_interrupt
{
	/* in */
	__u32 irq;
};

/* for KVM_GET_DIRTY_LOG */
struct vmmr0_dirty_log
{
	__u32 slot;
	__u32 padding1;
	union
	{
		void   *dirty_bitmap; /* one bit per page */
		__u64 padding2;
	};
};

/* for KVM_SET_SIGNAL_MASK */
struct vmmr0_signal_mask
{
	__u32 len;
	__u8  sigset[0];
};

/* for KVM_TPR_ACCESS_REPORTING */
struct vmmr0_tpr_access_ctl
{
	__u32 enabled;
	__u32 flags;
	__u32 reserved[8];
};

/* for KVM_SET_VAPIC_ADDR */
struct vmmr0_vapic_addr
{
	__u64 vapic_addr;
};

/* for KVM_SET_MPSTATE */

#define KVM_MP_STATE_RUNNABLE          0
#define KVM_MP_STATE_UNINITIALIZED     1
#define KVM_MP_STATE_INIT_RECEIVED     2
#define KVM_MP_STATE_HALTED            3
#define KVM_MP_STATE_SIPI_RECEIVED     4

struct vmmr0_mp_state
{
	__u32 mp_state;
};


/* for KVM_SET_GUEST_DEBUG */

#define KVM_GUESTDBG_ENABLE		    0x00000001
#define KVM_GUESTDBG_SINGLESTEP		0x00000002

struct vmmr0_guest_debug
{
	__u32 control;
	__u32 pad;
	struct vmmr0_guest_debug_arch arch;
};

enum
{
	vmmr0_ioeventfd_flag_nr_datamatch,
	vmmr0_ioeventfd_flag_nr_pio,
	vmmr0_ioeventfd_flag_nr_deassign,
	vmmr0_ioeventfd_flag_nr_max,
};

#define KVM_IOEVENTFD_FLAG_DATAMATCH (1 << vmmr0_ioeventfd_flag_nr_datamatch)
#define KVM_IOEVENTFD_FLAG_PIO       (1 << vmmr0_ioeventfd_flag_nr_pio)
#define KVM_IOEVENTFD_FLAG_DEASSIGN  (1 << vmmr0_ioeventfd_flag_nr_deassign)

#define KVM_IOEVENTFD_VALID_FLAG_MASK  ((1 << vmmr0_ioeventfd_flag_nr_max) - 1)

struct vmmr0_ioeventfd
{
	__u64 datamatch;
	__u64 addr;        /* legal pio/mmio address */
	__u32 len;         /* 1, 2, 4, or 8 bytes    */
	__s32 fd;
	__u32 flags;
	__u8  pad[36];
};

/* for KVM_ENABLE_CAP */
struct vmmr0_enable_cap
{
	/* in */
	__u32 cap;
	__u32 flags;
	__u64 args[4];
	__u8  pad[64];
};

#define KVMIO 0xAE

/* machine type bits, to be used as argument to KVM_CREATE_VM */
#define KVM_VM_S390_UCONTROL	1


/*
 * ioctls for /dev/vmmr0 fds:
 */
#define KVM_GET_API_VERSION       _IO(KVMIO,   0x00)
#define KVM_CREATE_VM             _IO(KVMIO,   0x01) /* returns a VM fd */
#define KVM_GET_MSR_INDEX_LIST    _IOWR(KVMIO, 0x02, struct vmmr0_msr_list)

/*
 * Check if a vmmr0 extension is available.  Argument is extension number,
 * return is 1 (yes) or 0 (no, sorry).
 */
#define KVM_CHECK_EXTENSION       _IO(KVMIO,   0x03)
/*
 * Get size for mmap(vcpu_fd)
 */
#define KVM_GET_VCPU_MMAP_SIZE    _IO(KVMIO,   0x04) /* in bytes */
#define KVM_GET_SUPPORTED_CPUID   _IOWR(KVMIO, 0x05, struct vmmr0_cpuid2)

/*
 * Extension capability list.
 */
#define KVM_CAP_IRQCHIP	  0
#define KVM_CAP_HLT	  1
#define KVM_CAP_MMU_SHADOW_CACHE_CONTROL 2
#define KVM_CAP_USER_MEMORY 3
#define KVM_CAP_SET_TSS_ADDR 4
#define KVM_CAP_VAPIC 6
#define KVM_CAP_EXT_CPUID 7
#define KVM_CAP_CLOCKSOURCE 8
#define KVM_CAP_NR_VCPUS 9       /* returns recommended max vcpus per vm */
#define KVM_CAP_NR_MEMSLOTS 10   /* returns max memory slots per vm */
#define KVM_CAP_PIT 11
#define KVM_CAP_NOP_IO_DELAY 12
#define KVM_CAP_PV_MMU 13
#define KVM_CAP_MP_STATE 14
#define KVM_CAP_COALESCED_MMIO 15
#define KVM_CAP_SYNC_MMU 16  /* Changes to host mmap are reflected in guest */
#ifdef __KVM_HAVE_DEVICE_ASSIGNMENT
#define KVM_CAP_DEVICE_ASSIGNMENT 17
#endif
#ifdef CONFIG_IOMMU_API
#define KVM_CAP_IOMMU 18
#endif
#ifdef __KVM_HAVE_MSI
#define KVM_CAP_DEVICE_MSI 20
#endif
/* Bug in KVM_SET_USER_MEMORY_REGION fixed: */
#define KVM_CAP_DESTROY_MEMORY_REGION_WORKS 21
#ifdef __KVM_HAVE_USER_NMI
#define KVM_CAP_USER_NMI 22
#endif
#ifdef __KVM_HAVE_GUEST_DEBUG
#define KVM_CAP_SET_GUEST_DEBUG 23
#endif
#ifdef __KVM_HAVE_PIT
#define KVM_CAP_REINJECT_CONTROL 24
#endif
#ifdef __KVM_HAVE_IOAPIC
#define KVM_CAP_IRQ_ROUTING 25
#endif
#define KVM_CAP_IRQ_INJECT_STATUS 26
#ifdef __KVM_HAVE_DEVICE_ASSIGNMENT
#define KVM_CAP_DEVICE_DEASSIGNMENT 27
#endif
#ifdef __KVM_HAVE_MSIX
#define KVM_CAP_DEVICE_MSIX 28
#endif
#define KVM_CAP_ASSIGN_DEV_IRQ 29
/* Another bug in KVM_SET_USER_MEMORY_REGION fixed: */
#define KVM_CAP_JOIN_MEMORY_REGIONS_WORKS 30
#ifdef __KVM_HAVE_MCE
#define KVM_CAP_MCE 31
#endif
#define KVM_CAP_IRQFD 32
#ifdef __KVM_HAVE_PIT
#define KVM_CAP_PIT2 33
#endif
#define KVM_CAP_SET_BOOT_CPU_ID 34
#ifdef __KVM_HAVE_PIT_STATE2
#define KVM_CAP_PIT_STATE2 35
#endif
#define KVM_CAP_IOEVENTFD 36
#define KVM_CAP_SET_IDENTITY_MAP_ADDR 37

#define KVM_CAP_ADJUST_CLOCK 39
#define KVM_CAP_INTERNAL_ERROR_DATA 40
#ifdef __KVM_HAVE_VCPU_EVENTS
#define KVM_CAP_VCPU_EVENTS 41
#endif
#define KVM_CAP_S390_PSW 42
#define KVM_CAP_PPC_SEGSTATE 43
#define KVM_CAP_HYPERV 44
#define KVM_CAP_HYPERV_VAPIC 45
#define KVM_CAP_HYPERV_SPIN 46
#define KVM_CAP_PCI_SEGMENT 47
#define KVM_CAP_PPC_PAIRED_SINGLES 48
#define KVM_CAP_INTR_SHADOW 49
#ifdef __KVM_HAVE_DEBUGREGS
#define KVM_CAP_DEBUGREGS 50
#endif
#define KVM_CAP_X86_ROBUST_SINGLESTEP 51
#define KVM_CAP_PPC_OSI 52
#define KVM_CAP_PPC_UNSET_IRQ 53
#define KVM_CAP_ENABLE_CAP 54
#ifdef __KVM_HAVE_XSAVE
#define KVM_CAP_XSAVE 55
#endif
#ifdef __KVM_HAVE_XCRS
#define KVM_CAP_XCRS 56
#endif
#define KVM_CAP_PPC_GET_PVINFO 57
#define KVM_CAP_PPC_IRQ_LEVEL 58
#define KVM_CAP_ASYNC_PF 59
#define KVM_CAP_TSC_CONTROL 60
#define KVM_CAP_GET_TSC_KHZ 61
#define KVM_CAP_PPC_BOOKE_SREGS 62
#define KVM_CAP_SPAPR_TCE 63
#define KVM_CAP_PPC_SMT 64
#define KVM_CAP_PPC_RMA	65
#define KVM_CAP_MAX_VCPUS 66       /* returns max vcpus per vm */
#define KVM_CAP_PPC_HIOR 67
#define KVM_CAP_PPC_PAPR 68
#define KVM_CAP_SW_TLB 69
#define KVM_CAP_ONE_REG 70
#define KVM_CAP_S390_GMAP 71
#define KVM_CAP_TSC_DEADLINE_TIMER 72
#define KVM_CAP_S390_UCONTROL 73
#define KVM_CAP_SYNC_REGS 74
#define KVM_CAP_PCI_2_3 75

#ifdef KVM_CAP_IRQ_ROUTING

struct vmmr0_irq_routing_irqchip
{
	__u32 irqchip;
	__u32 pin;
};

struct vmmr0_irq_routing_msi
{
	__u32 address_lo;
	__u32 address_hi;
	__u32 data;
	__u32 pad;
};

/* gsi routing entry types */
#define KVM_IRQ_ROUTING_IRQCHIP 1
#define KVM_IRQ_ROUTING_MSI 2

struct vmmr0_irq_routing_entry
{
	__u32 gsi;
	__u32 type;
	__u32 flags;
	__u32 pad;
	union
	{
		struct vmmr0_irq_routing_irqchip irqchip;
		struct vmmr0_irq_routing_msi msi;
		__u32 pad[8];
	} u;
};

struct vmmr0_irq_routing
{
	__u32 nr;
	__u32 flags;
	struct vmmr0_irq_routing_entry entries[0];
};

#endif

#ifdef KVM_CAP_MCE
/* x86 MCE */
struct vmmr0_x86_mce
{
	__u64 status;
	__u64 addr;
	__u64 misc;
	__u64 mcg_status;
	__u8 bank;
	__u8 pad1[7];
	__u64 pad2[3];
};
#endif

#define KVM_IRQFD_FLAG_DEASSIGN (1 << 0)

struct vmmr0_irqfd
{
	__u32 fd;
	__u32 gsi;
	__u32 flags;
	__u8  pad[20];
};

struct vmmr0_clock_data
{
	__u64 clock;
	__u32 flags;
	__u32 pad[9];
};

#define KVM_MMU_FSL_BOOKE_NOHV		0
#define KVM_MMU_FSL_BOOKE_HV		1

struct vmmr0_config_tlb
{
	__u64 params;
	__u64 array;
	__u32 mmu_type;
	__u32 array_len;
};

struct vmmr0_dirty_tlb
{
	__u64 bitmap;
	__u32 num_dirty;
};

/* Available with KVM_CAP_ONE_REG */

#define KVM_REG_ARCH_MASK	VMMR0_LPULL(0xff00000000000000)
#define KVM_REG_GENERIC		VMMR0_LPULL(0x0000000000000000)

/*
 * Architecture specific registers are to be defined in arch headers and
 * ORed with the arch identifier.
 */
#define KVM_REG_PPC		VMMR0_LPULL(0x1000000000000000)
#define KVM_REG_X86		VMMR0_LPULL(0x2000000000000000)
#define KVM_REG_IA64		VMMR0_LPULL(0x3000000000000000)
#define KVM_REG_ARM		VMMR0_LPULL(0x4000000000000000)
#define KVM_REG_S390		VMMR0_LPULL(0x5000000000000000)

#define KVM_REG_SIZE_SHIFT	52
#define KVM_REG_SIZE_MASK	VMMR0_LPULL(0x00f0000000000000)
#define KVM_REG_SIZE_U8		VMMR0_LPULL(0x0000000000000000)
#define KVM_REG_SIZE_U16	VMMR0_LPULL(0x0010000000000000)
#define KVM_REG_SIZE_U32	VMMR0_LPULL(0x0020000000000000)
#define KVM_REG_SIZE_U64	VMMR0_LPULL(0x0030000000000000)
#define KVM_REG_SIZE_U128	VMMR0_LPULL(0x0040000000000000)
#define KVM_REG_SIZE_U256	VMMR0_LPULL(0x0050000000000000)
#define KVM_REG_SIZE_U512	VMMR0_LPULL(0x0060000000000000)
#define KVM_REG_SIZE_U1024	VMMR0_LPULL(0x0070000000000000)

struct vmmr0_one_reg
{
	__u64 id;
	__u64 addr;
};

/*
 * ioctls for VM fds
 */
#define KVM_SET_MEMORY_REGION     			_IOW(KVMIO,  0x770, struct vmmr0_memory_region)
/*
 * KVM_CREATE_VCPU receives as a parameter the vcpu slot, and returns
 * a vcpu fd.
 */
#define KVM_CREATE_VCPU                     _IO(KVMIO,   0x771)
#define KVM_GET_DIRTY_LOG                   _IOW(KVMIO,  0x772, struct vmmr0_dirty_log)
/* KVM_SET_MEMORY_ALIAS is obsolete: */
#define KVM_SET_MEMORY_ALIAS                _IOW(KVMIO,  0x773, struct vmmr0_memory_alias)
#define KVM_SET_NR_MMU_PAGES                _IO(KVMIO,   0x774)
#define KVM_GET_NR_MMU_PAGES                _IO(KVMIO,   0x775)
#define KVM_SET_USER_MEMORY_REGION          _IOW(KVMIO,  0x776, struct vmmr0_userspace_memory_region)
#define KVM_SET_TSS_ADDR                    _IO(KVMIO,   0x777)
#define KVM_SET_IDENTITY_MAP_ADDR           _IOW(KVMIO,  0x778, __u64)


/* Device model IOC */
#define KVM_CREATE_IRQCHIP                  _IO(KVMIO,   0x779)
#define KVM_IRQ_LINE                        _IOW(KVMIO,  0x77a, struct vmmr0_irq_level)
#define KVM_GET_IRQCHIP                     _IOWR(KVMIO, 0x77b, struct vmmr0_irqchip)
#define KVM_SET_IRQCHIP                     _IOR(KVMIO,  0x77c, struct vmmr0_irqchip)
#define KVM_CREATE_PIT                      _IO(KVMIO,   0x77d)
#define KVM_GET_PIT                         _IOWR(KVMIO, 0x77e, struct vmmr0_pit_state)
#define KVM_SET_PIT                         _IOR(KVMIO,  0x77f, struct vmmr0_pit_state)
#define KVM_IRQ_LINE_STATUS                 _IOWR(KVMIO, 0x780, struct vmmr0_irq_level)
#define KVM_REGISTER_COALESCED_MMIO 		_IOW(KVMIO,  0x781, struct vmmr0_coalesced_mmio_zone)
#define KVM_UNREGISTER_COALESCED_MMIO 		_IOW(KVMIO,  0x782, struct vmmr0_coalesced_mmio_zone)
#define KVM_ASSIGN_PCI_DEVICE    			_IOR(KVMIO,  0x783, struct vmmr0_assigned_pci_dev)
#define KVM_SET_GSI_ROUTING       			_IOW(KVMIO,  0x784, struct vmmr0_irq_routing)
/* deprecated, replaced by KVM_ASSIGN_DEV_IRQ */
#define KVM_ASSIGN_IRQ            			__KVM_DEPRECATED_VM_R_0x70
#define KVM_ASSIGN_DEV_IRQ        			_IOW(KVMIO,  0x785, struct vmmr0_assigned_irq)
#define KVM_REINJECT_CONTROL      			_IO(KVMIO,   0x786)
#define KVM_DEASSIGN_PCI_DEVICE   			_IOW(KVMIO,  0x787, struct vmmr0_assigned_pci_dev)
#define KVM_ASSIGN_SET_MSIX_NR   			_IOW(KVMIO,  0x788, struct vmmr0_assigned_msix_nr)
#define KVM_ASSIGN_SET_MSIX_ENTRY 			_IOW(KVMIO,  0x789, struct vmmr0_assigned_msix_entry)
#define KVM_DEASSIGN_DEV_IRQ      			_IOW(KVMIO,  0x78a, struct vmmr0_assigned_irq)
#define KVM_IRQFD                 			_IOW(KVMIO,  0x78b, struct vmmr0_irqfd)
#define KVM_CREATE_PIT2		  				_IOW(KVMIO,  0x78c, struct vmmr0_pit_config)
#define KVM_SET_BOOT_CPU_ID       			_IO(KVMIO,   0x78d)
#define KVM_IOEVENTFD            			_IOW(KVMIO,  0x78e, struct vmmr0_ioeventfd)
#define KVM_SET_CLOCK             			_IOW(KVMIO,  0x78f, struct vmmr0_clock_data)
#define KVM_GET_CLOCK             			_IOR(KVMIO,  0x790, struct vmmr0_clock_data)
/* Available with KVM_CAP_PIT_STATE2 */
#define KVM_GET_PIT2              			_IOR(KVMIO,  0x791, struct vmmr0_pit_state2)
#define KVM_SET_PIT2              			_IOW(KVMIO,  0x792, struct vmmr0_pit_state2)

/* Available with KVM_CAP_TSC_CONTROL */
#define KVM_SET_TSC_KHZ          			_IO(KVMIO,   0x793)
#define KVM_GET_TSC_KHZ           			_IO(KVMIO,   0x794)
/* Available with KVM_CAP_PCI_2_3 */
#define KVM_ASSIGN_SET_INTX_MASK  			_IOW(KVMIO,  0x795, struct vmmr0_assigned_pci_dev)

/*
 * ioctls for vcpu fds
 */
#define KVM_RUN                   			_IO(KVMIO,   0x796)
#define KVM_GET_REGS                        _IOR(KVMIO,  0x797, struct vmmr0_regs)
#define KVM_SET_REGS                        _IOW(KVMIO,  0x798, struct vmmr0_regs)
#define KVM_GET_SREGS                       _IOR(KVMIO,  0x799, struct vmmr0_sregs)
#define KVM_SET_SREGS                       _IOW(KVMIO,  0x79a, struct vmmr0_sregs)
#define KVM_TRANSLATE                       _IOWR(KVMIO, 0x79b, struct vmmr0_translation)
#define KVM_INTERRUPT                       _IOW(KVMIO,  0x79c, struct vmmr0_interrupt)
/* KVM_DEBUG_GUEST is no longer supported, use KVM_SET_GUEST_DEBUG instead */
#define KVM_DEBUG_GUEST                     __KVM_DEPRECATED_VCPU_W_0x87
#define KVM_GET_MSRS                        _IOWR(KVMIO, 0x79d, struct vmmr0_msrs)
#define KVM_SET_MSRS                        _IOW(KVMIO,  0x79e, struct vmmr0_msrs)
#define KVM_SET_CPUID                       _IOW(KVMIO,  0x79f, struct vmmr0_cpuid)
#define KVM_SET_SIGNAL_MASK                 _IOW(KVMIO,  0x7a0, struct vmmr0_signal_mask)
#define KVM_GET_FPU                         _IOR(KVMIO,  0x7a1, struct vmmr0_fpu)
#define KVM_SET_FPU                         _IOW(KVMIO,  0x7a2, struct vmmr0_fpu)
#define KVM_GET_LAPIC                       _IOR(KVMIO,  0x7a3, struct vmmr0_lapic_state)
#define KVM_SET_LAPIC                       _IOW(KVMIO,  0x7a4, struct vmmr0_lapic_state)
#define KVM_SET_CPUID2                      _IOW(KVMIO,  0x7a5, struct vmmr0_cpuid2)
#define KVM_GET_CPUID2                      _IOWR(KVMIO, 0x7a6, struct vmmr0_cpuid2)
/* Available with KVM_CAP_VAPIC */
#define KVM_TPR_ACCESS_REPORTING            _IOWR(KVMIO, 0x7a7, struct vmmr0_tpr_access_ctl)
/* Available with KVM_CAP_VAPIC */
#define KVM_SET_VAPIC_ADDR                  _IOW(KVMIO,  0x7a8, struct vmmr0_vapic_addr)

#define KVM_GET_MP_STATE                    _IOR(KVMIO,  0x7a9, struct vmmr0_mp_state)
#define KVM_SET_MP_STATE                    _IOW(KVMIO,  0x7aa, struct vmmr0_mp_state)
/* Available with KVM_CAP_NMI */
#define KVM_NMI                             _IO(KVMIO,   0x7ab)
/* Available with KVM_CAP_SET_GUEST_DEBUG */
#define KVM_SET_GUEST_DEBUG       			_IOW(KVMIO,  0x7ac, struct vmmr0_guest_debug)
/* MCE for x86 */
#define KVM_X86_SETUP_MCE         			_IOW(KVMIO,  0x7ad, __u64)
#define KVM_X86_GET_MCE_CAP_SUPPORTED 		_IOR(KVMIO,  0x7ae, __u64)
#define KVM_X86_SET_MCE           			_IOW(KVMIO,  0x7af, struct vmmr0_x86_mce)
/* Available with KVM_CAP_VCPU_EVENTS */
#define KVM_GET_VCPU_EVENTS       			_IOR(KVMIO,  0x7b0, struct vmmr0_vcpu_events)
#define KVM_SET_VCPU_EVENTS       			_IOW(KVMIO,  0x7b1, struct vmmr0_vcpu_events)
/* Available with KVM_CAP_DEBUGREGS */
#define KVM_GET_DEBUGREGS         			_IOR(KVMIO,  0x7b2, struct vmmr0_debugregs)
#define KVM_SET_DEBUGREGS         			_IOW(KVMIO,  0x7b3, struct vmmr0_debugregs)
#define KVM_ENABLE_CAP            			_IOW(KVMIO,  0x7b4, struct vmmr0_enable_cap)
/* Available with KVM_CAP_XSAVE */
#define KVM_GET_XSAVE		  				_IOR(KVMIO,  0x7b5, struct vmmr0_xsave)
#define KVM_SET_XSAVE		  				_IOW(KVMIO,  0x7b6, struct vmmr0_xsave)
/* Available with KVM_CAP_XCRS */
#define KVM_GET_XCRS		  				_IOR(KVMIO,  0x7b7, struct vmmr0_xcrs)
#define KVM_SET_XCRS		  				_IOW(KVMIO,  0x7b8, struct vmmr0_xcrs)
#define KVM_CREATE_SPAPR_TCE	  			_IOW(KVMIO,  0x7b9, struct vmmr0_create_spapr_tce)
/* Available with KVM_CAP_RMA */
#define KVM_ALLOCATE_RMA	  				_IOR(KVMIO,  0x7ba, struct vmmr0_allocate_rma)
/* Available with KVM_CAP_SW_TLB */
#define KVM_DIRTY_TLB		  				_IOW(KVMIO,  0x7bb, struct vmmr0_dirty_tlb)
/* Available with KVM_CAP_ONE_REG */
#define KVM_GET_ONE_REG		  				_IOW(KVMIO,  0x7bc, struct vmmr0_one_reg)
#define KVM_SET_ONE_REG		  				_IOW(KVMIO,  0x7bd, struct vmmr0_one_reg)

//on windows
#define KVM_GET_KVM_RUN		  				_IOWR(KVMIO,  0x7be, __u64)
#define KVM_ALLOC_KMEM		  				_IOWR(KVMIO,  0x7bf, __u64)
#define KVM_FREE_KMEM		  				_IOWR(KVMIO,  0x7c0, __u64)
#define KVM_BIND_EVENT            			_IOWR(KVMIO,  0x7c2, __u64)

#define KVM_DEV_ASSIGN_ENABLE_IOMMU	(1 << 0)
#define KVM_DEV_ASSIGN_PCI_2_3		(1 << 1)
#define KVM_DEV_ASSIGN_MASK_INTX	(1 << 2)

struct vmmr0_assigned_pci_dev
{
	__u32 assigned_dev_id;
	__u32 busnr;
	__u32 devfn;
	__u32 flags;
	__u32 segnr;
	union
	{
		__u32 reserved[11];
	};
};

#define KVM_DEV_IRQ_HOST_INTX    (1 << 0)
#define KVM_DEV_IRQ_HOST_MSI     (1 << 1)
#define KVM_DEV_IRQ_HOST_MSIX    (1 << 2)

#define KVM_DEV_IRQ_GUEST_INTX   (1 << 8)
#define KVM_DEV_IRQ_GUEST_MSI    (1 << 9)
#define KVM_DEV_IRQ_GUEST_MSIX   (1 << 10)

#define KVM_DEV_IRQ_HOST_MASK	 0x00ff
#define KVM_DEV_IRQ_GUEST_MASK   0xff00

struct vmmr0_assigned_irq
{
	__u32 assigned_dev_id;
	__u32 host_irq; /* ignored (legacy field) */
	__u32 guest_irq;
	__u32 flags;
	union
	{
		__u32 reserved[12];
	};
};


struct vmmr0_assigned_msix_nr
{
	__u32 assigned_dev_id;
	__u16 entry_nr;
	__u16 padding;
};

#define KVM_MAX_MSIX_PER_DEV		256
struct vmmr0_assigned_msix_entry
{
	__u32 assigned_dev_id;
	__u32 gsi;
	__u16 entry; /* The index of entry in the MSI-X table */
	__u16 padding[3];
};

#endif /* __LINUX_KVM_H */
