
/*
 * Compatibility header for building as an external module.
 */


typedef u64 phys_addr_t;


#include "../compat-comm-windows.h"

DECLARE_PER_CPU(unsigned long, cpu_tsc_khz);

#ifdef CONFIG_X86_64
#define DECLARE_ARGS(val, low, high)	unsigned low, high
#define EAX_EDX_VAL(val, low, high)	((low) | ((u64)(high) << 32))
#define EAX_EDX_ARGS(val, low, high)	"a" (low), "d" (high)
#define EAX_EDX_RET(val, low, high)	"=a" (low), "=d" (high)
#else
#define DECLARE_ARGS(val, low, high)	unsigned long long val
#define EAX_EDX_VAL(val, low, high)	(val)
#define EAX_EDX_ARGS(val, low, high)	"A" (val)
#define EAX_EDX_RET(val, low, high)	"=A" (val)
#endif

#ifndef __ASM_EX_SEC
# define __ASM_EX_SEC	" .section __ex_table,\"a\"\n"
#endif


#ifndef _ASM_EXTABLE
# define _ASM_EXTABLE(from,to) \
        __ASM_EX_SEC    \
        _ASM_ALIGN "\n" \
        _ASM_PTR #from "," #to "\n" \
        " .previous\n"
#endif

#ifndef __ASM_SEL
#ifdef CONFIG_X86_32
# define __ASM_SEL(a,b) __ASM_FORM(a)
#else
# define __ASM_SEL(a,b) __ASM_FORM(b)
#endif
#endif

#ifndef __ASM_FORM
# define __ASM_FORM(x)	" " #x " "
#endif

#ifndef _ASM_PTR
#define _ASM_PTR	__ASM_SEL(.long, .quad)
#endif

#ifndef _ASM_ALIGN
#define _ASM_ALIGN	__ASM_SEL(.balign 4, .balign 8)
#endif

void init_boot_cpu_data(void);

void sort(void *base, size_t num, size_t size,
	  int (*cmp_func)(const void *, const void *),
	  void (*swap_func)(void *, void *, int size));


typedef void (*smp_call_func_t)(void *info);

static inline u64 native_read_msr(unsigned int msr)
{
	DECLARE_ARGS(val, low, high);

	asm volatile("rdmsr" : EAX_EDX_RET(val, low, high) : "c" (msr));
	return EAX_EDX_VAL(val, low, high);
}

static inline void native_write_msr(unsigned int msr,
				    unsigned low, unsigned high)
{
	asm volatile("wrmsr" : : "c" (msr), "a"(low), "d" (high) : "memory");
}

typedef struct seh_read_msr
{
	u64* ret;
	unsigned int msr;
}seh_read_msr;

typedef struct seh_write_msr
{
	unsigned int msr;
	unsigned low;
	unsigned high;
}seh_write_msr;

static inline void call_seh_native_read_msr(void* p)
{
	seh_read_msr* psrm = (seh_read_msr*)p;
	*psrm->ret = native_read_msr(psrm->msr);
}

static inline void call_seh_native_write_msr(void* p)
{
	seh_write_msr* pswm = (seh_write_msr*)p;
	native_write_msr(pswm->msr, pswm->low, pswm->high);
}

static inline u64 native_read_msr_safe(unsigned int msr,
						      int *err)
{
	u64 ret;
	seh_fn fn;
	seh_read_msr srm;

	fn = (seh_fn)call_seh_native_read_msr;

	srm.ret = &ret;
	srm.msr = msr;
	*err = 0;

	if(call_seh(fn, &srm))
	{
		pr_warn_ratelimited("vmmr0: native_read_msr_safe: read msr %x failed\n", msr);
		*err = -EIO;
	}
	return ret;
}

/* Can be uninlined because referenced by paravirt */
static inline int native_write_msr_safe(unsigned int msr,
					unsigned low, unsigned high)
{
	seh_fn fn;
	seh_write_msr swm;

	fn = (seh_fn)call_seh_native_write_msr;

	swm.msr = msr;
	swm.low = low;
	swm.high = high;

	if(call_seh(fn, &swm))
	{
		pr_warn_ratelimited("vmmr0: native_write_msr_safe: write msr %x failed\n", msr);
		return -EIO;
	}
	return 0;
}

#define vmmr0_native_write_msr_safe native_write_msr_safe

static u64 __native_read_tsc(void)
{
	DECLARE_ARGS(val, low, high);

	asm volatile("rdtsc" : EAX_EDX_RET(val, low, high));

	return EAX_EDX_VAL(val, low, high);
}

static inline u64 native_read_pmc(int counter)
{
	DECLARE_ARGS(val, low, high);

	asm volatile("rdpmc" : EAX_EDX_RET(val, low, high) : "c" (counter));
	return EAX_EDX_VAL(val, low, high);
}


#define rdtscl(low)						\
	((low) = (u32)__native_read_tsc())

#define rdtscll(val)						\
	((val) = __native_read_tsc())


#define rdmsr(msr, val1, val2)					\
do \
{								\
	u64 __val = native_read_msr((msr));			\
	(void)((val1) = (u32)__val);				\
	(void)((val2) = (u32)(__val >> 32));			\
} while (0)

static inline void wrmsr(unsigned msr, unsigned low, unsigned high)
{
	native_write_msr(msr, low, high);
}

#define rdmsrl(msr, val)			\
	((val) = native_read_msr((msr)))

#define wrmsrl(msr, val)						\
	native_write_msr((msr), (u32)((u64)(val)), (u32)((u64)(val) >> 32))


static inline int wrmsr_safe(unsigned msr, unsigned low, unsigned high)
{
	return native_write_msr_safe(msr, low, high);
}

#define rdmsr_safe(msr, p1, p2)					\
({								\
	int __err;						\
	u64 __val = native_read_msr_safe((msr), &__err);	\
	(*p1) = (u32)__val;					\
	(*p2) = (u32)(__val >> 32);				\
	__err;							\
})

static inline int rdmsrl_safe(unsigned msr, u64 *p)
{
	int err;

	*p = native_read_msr_safe(msr, &err);
	return err;
}

static inline u64 vmmr0_native_read_tsc(void)
{
	DECLARE_ARGS(val, low, high);

	asm volatile("rdtsc" : EAX_EDX_RET(val, low, high));
	return EAX_EDX_VAL(val, low, high);
}


#ifndef MSR_KERNEL_GS_BASE
#define MSR_KERNEL_GS_BASE              0xc0000102
#endif

#ifndef MSR_TSC_AUX
#define MSR_TSC_AUX                     0xc0000103
#endif

#ifndef MSR_VM_CR
#define MSR_VM_CR                       0xc0010114
#endif

#ifndef MSR_VM_HSAVE_PA
#define MSR_VM_HSAVE_PA                 0xc0010117
#endif

#ifndef _EFER_SVME
#define _EFER_SVME		12
#define EFER_SVME		(1<<_EFER_SVME)
#endif

#ifndef _EFER_FFXSR
#define _EFER_FFXSR		14 /* Enable Fast FXSAVE/FXRSTOR */
#define EFER_FFXSR		(1<<_EFER_FFXSR)
#endif

#ifndef MSR_STAR
#define MSR_STAR                0xc0000081
#endif

#ifndef MSR_K8_INT_PENDING_MSG
#define MSR_K8_INT_PENDING_MSG  0xc0010055
#endif

#ifndef X86_FEATURE_FXSR_OPT
#define X86_FEATURE_FXSR_OPT	(1*32+25)
#endif

#ifndef X86_FEATURE_GBPAGES
#define X86_FEATURE_GBPAGES	(1*32+26) /* GB pages */
#endif

#ifndef X86_FEATURE_NX
#define X86_FEATURE_NX		(1*32+20) /* Execute Disable */
#endif

#ifndef X86_FEATURE_PCLMULQDQ
#define X86_FEATURE_PCLMULQDQ	(4*32+ 1) /* PCLMULQDQ instruction */
#endif

#ifndef X86_FEATURE_VMX
#define X86_FEATURE_VMX		(4*32+ 5) /* Hardware virtualization */
#endif

#ifndef X86_FEATURE_SSSE3
#define X86_FEATURE_SSSE3	(4*32+ 9) /* Supplemental SSE-3 */
#endif

#ifndef X86_FEATURE_FMA
#define X86_FEATURE_FMA		(4*32+12) /* Fused multiply-add */
#endif

#ifndef X86_FEATURE_XMM4_1
#define X86_FEATURE_XMM4_1	(4*32+19) /* "sse4_1" SSE-4.1 */
#endif

#ifndef X86_FEATURE_XMM4_2
#define X86_FEATURE_XMM4_2	(4*32+20) /* "sse4_2" SSE-4.2 */
#endif

#ifndef X86_FEATURE_X2APIC
#define X86_FEATURE_X2APIC	(4*32+21) /* x2APIC */
#endif

#ifndef X86_FEATURE_MOVBE
#define X86_FEATURE_MOVBE	(4*32+22) /* MOVBE instruction */
#endif

#ifndef X86_FEATURE_POPCNT
#define X86_FEATURE_POPCNT	(4*32+23) /* POPCNT instruction */
#endif

#ifndef X86_FEATURE_TSC_DEADLINE_TIMER
#define X86_FEATURE_TSC_DEADLINE_TIMER	(4*32+24) /* Tsc deadline timer */
#endif

#ifndef X86_FEATURE_AES
#define X86_FEATURE_AES		(4*32+25) /* AES instructions */
#endif

#ifndef X86_FEATURE_XSAVE
#define X86_FEATURE_XSAVE	(4*32+26) /* XSAVE/XRSTOR/XSETBV/XGETBV */
#endif

#ifndef X86_FEATURE_OSXSAVE
#define X86_FEATURE_OSXSAVE	(4*32+27) /* "" XSAVE enabled in the OS */
#endif

#ifndef X86_FEATURE_AVX
#define X86_FEATURE_AVX		(4*32+28) /* Advanced Vector Extensions */
#endif

#ifndef X86_FEATURE_F16C
#define X86_FEATURE_F16C	(4*32+29) /* 16-bit fp conversions */
#endif

#ifndef X86_FEATURE_RDRAND
#define X86_FEATURE_RDRAND	(4*32+30) /* The RDRAND instruction */
#endif

#ifndef X86_FEATURE_SVM
#define X86_FEATURE_SVM		(6*32+ 2) /* Secure virtual machine */
#endif

#ifndef X86_FEATURE_CR8_LEGACY
#define X86_FEATURE_CR8_LEGACY	(6*32+ 4) /* CR8 in 32-bit mode */
#endif

#ifndef X86_FEATURE_ABM
#define X86_FEATURE_ABM		(6*32+ 5) /* Advanced bit manipulation */
#endif

#ifndef X86_FEATURE_SSE4A
#define X86_FEATURE_SSE4A	(6*32+ 6) /* SSE-4A */
#endif

#ifndef X86_FEATURE_MISALIGNSSE
#define X86_FEATURE_MISALIGNSSE (6*32+ 7) /* Misaligned SSE mode */
#endif

#ifndef X86_FEATURE_3DNOWPREFETCH
#define X86_FEATURE_3DNOWPREFETCH (6*32+ 8) /* 3DNow prefetch instructions */
#endif

#ifndef X86_FEATURE_OSVW
#define X86_FEATURE_OSVW	(6*32+ 9) /* OS Visible Workaround */
#endif

#ifndef X86_FEATURE_XOP
#define X86_FEATURE_XOP		(6*32+11) /* extended AVX instructions */
#endif

#ifndef X86_FEATURE_FMA4
#define X86_FEATURE_FMA4	(6*32+16) /* 4 operands MAC instructions */
#endif

#ifndef X86_FEATURE_TBM
#define X86_FEATURE_TBM		(6*32+21) /* trailing bit manipulations */
#endif

#ifndef X86_FEATURE_NPT
#define X86_FEATURE_NPT		(8*32+ 5) /* AMD Nested Page Table support */
#endif

#ifndef X86_FEATURE_LBRV
#define X86_FEATURE_LBRV	(8*32+ 6) /* AMD LBR Virtualization support */
#endif

#ifndef X86_FEATURE_NRIPS
#define X86_FEATURE_NRIPS	(8*32+ 8) /* "nrip_save" AMD SVM next_rip save */
#endif

#ifndef X86_FEATURE_TSCRATEMSR
#define X86_FEATURE_TSCRATEMSR  (8*32+ 9) /* "tsc_scale" AMD TSC scaling support */
#endif

#ifndef X86_FEATURE_FLUSHBYASID
#define X86_FEATURE_FLUSHBYASID (8*32+11) /* AMD flush-by-ASID support */
#endif

#ifndef X86_FEATURE_DECODEASSISTS
#define X86_FEATURE_DECODEASSISTS (8*32+12) /* AMD Decode Assists support */
#endif

#ifndef X86_FEATURE_PAUSEFILTER
#define X86_FEATURE_PAUSEFILTER (8*32+13) /* AMD filtered pause intercept */
#endif

#ifndef X86_FEATURE_FSGSBASE
#define X86_FEATURE_FSGSBASE	(9*32+ 0) /* {RD/WR}{FS/GS}BASE instructions*/
#endif

#ifndef X86_FEATURE_BMI1
#define X86_FEATURE_BMI1	(9*32+ 3) /* 1st group bit manipulation extensions */
#endif

#ifndef X86_FEATURE_HLE
#define X86_FEATURE_HLE		(9*32+ 4) /* Hardware Lock Elision */
#endif

#ifndef X86_FEATURE_AVX2
#define X86_FEATURE_AVX2	(9*32+ 5) /* AVX2 instructions */
#endif

#ifndef X86_FEATURE_SMEP
#define X86_FEATURE_SMEP	(9*32+ 7) /* Supervisor Mode Execution Protection */
#endif

#ifndef X86_FEATURE_BMI2
#define X86_FEATURE_BMI2	(9*32+ 8) /* 2nd group bit manipulation extensions */
#endif

#ifndef X86_FEATURE_ERMS
#define X86_FEATURE_ERMS	(9*32+ 9) /* Enhanced REP MOVSB/STOSB */
#endif

#ifndef X86_FEATURE_RTM
#define X86_FEATURE_RTM		(9*32+11) /* Restricted Transactional Memory */
#endif

#ifndef MSR_AMD64_PATCH_LOADER
#define MSR_AMD64_PATCH_LOADER         0xc0010020
#endif

#ifndef MSR_AMD64_TSC_RATIO
#define MSR_AMD64_TSC_RATIO		0xc0000104
#endif


#ifndef X86_CR0_PE
#define X86_CR0_PE 0x00000001
#endif

#ifndef X86_CR0_MP
#define X86_CR0_MP 0x00000002
#endif

#ifndef X86_CR0_EM
#define X86_CR0_EM 0x00000004
#endif

#ifndef X86_CR0_TS
#define X86_CR0_TS 0x00000008
#endif

#ifndef X86_CR0_ET
#define X86_CR0_ET 0x00000010
#endif

#ifndef X86_CR0_NE
#define X86_CR0_NE 0x00000020
#endif

#ifndef X86_CR0_WP
#define X86_CR0_WP 0x00010000
#endif

#ifndef X86_CR0_AM
#define X86_CR0_AM 0x00040000
#endif

#ifndef X86_CR0_NW
#define X86_CR0_NW 0x20000000
#endif

#ifndef X86_CR0_CD
#define X86_CR0_CD 0x40000000
#endif

#ifndef X86_CR0_PG
#define X86_CR0_PG 0x80000000
#endif

#ifndef X86_CR3_PWT
#define X86_CR3_PWT 0x00000008
#endif

#ifndef X86_CR3_PCD
#define X86_CR3_PCD 0x00000010
#endif

#ifndef X86_CR4_VMXE
#define X86_CR4_VMXE 0x00002000
#endif

#ifndef X86_CR4_RDWRGSFS
#define X86_CR4_RDWRGSFS 0x00010000 /* enable RDWRGSFS support */
#endif

#ifndef X86_CR4_OSXSAVE
#define X86_CR4_OSXSAVE 0x00040000
#endif

#ifndef X86_CR4_SMEP
#define X86_CR4_SMEP 0x00100000
#endif

#undef X86_CR8_TPR
#define X86_CR8_TPR 0x0f


/* CONFIG_HAS_IOMEM is apparently fairly new too (2.6.21 for x86_64). */
#ifndef CONFIG_HAS_IOMEM
#define CONFIG_HAS_IOMEM 1
#endif

#ifndef cpu_has_xsave
#define cpu_has_xsave boot_cpu_has(X86_FEATURE_XSAVE)
#endif

/* EFER_LMA and EFER_LME are missing in pre 2.6.24 i386 kernels */
#ifndef EFER_LME
#define _EFER_LME           8  /* Long mode enable */
#define _EFER_LMA           10 /* Long mode active (read-only) */
#define EFER_LME            (1<<_EFER_LME)
#define EFER_LMA            (1<<_EFER_LMA)
#endif

#ifndef EFER_LMSLE
#define _EFER_LMSLE		13 /* Long Mode Segment Limit Enable */
#define EFER_LMSLE		(1<<_EFER_LMSLE)
#endif

#pragma pack(push)
#pragma pack(1)
struct vmmr0_desc_struct 
{
	union 
	{
		struct 
		{ 
			unsigned int a, b; 
		};
		struct 
		{
			u16 limit0;
			u16 base0;
			unsigned base1: 8, type: 4, s: 1, dpl: 2, p: 1;
			unsigned limit: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8;
		};

	};
} __attribute__((packed));

struct vmmr0_ldttss_desc64 
{
	u16 limit0;
	u16 base0;
	unsigned base1 : 8, type : 5, dpl : 2, p : 1;
	unsigned limit1 : 4, zero0 : 3, g : 1, base2 : 8;
	u32 base3;
	u32 zero1;
} __attribute__((packed));

struct vmmr0_desc_ptr 
{
	unsigned short size;
	unsigned long address;
} __attribute__((packed));

#pragma pack(pop)
static inline unsigned long
vmmr0_get_desc_base(const struct vmmr0_desc_struct *desc)
{
	return (unsigned)(desc->base0 | ((desc->base1) << 16) | ((desc->base2) << 24));
}

static inline void
vmmr0_set_desc_base(struct vmmr0_desc_struct *desc, unsigned long base)
{
	desc->base0 = base & 0xffff;
	desc->base1 = (base >> 16) & 0xff;
	desc->base2 = (base >> 24) & 0xff;
}

static inline unsigned long
vmmr0_get_desc_limit(const struct vmmr0_desc_struct *desc)
{
	return desc->limit0 | (desc->limit << 16);
}

static inline void
vmmr0_set_desc_limit(struct vmmr0_desc_struct *desc, unsigned long limit)
{
	desc->limit0 = limit & 0xffff;
	desc->limit = (limit >> 16) & 0xf;
}

static inline void vmmr0_load_gdt(const struct vmmr0_desc_ptr *dtr)
{
	asm volatile("lgdt %0"::"m" (*dtr));
}

#define vmmr0_store_gdt	vmmr0_native_store_gdt

static inline void vmmr0_native_store_gdt(struct vmmr0_desc_ptr *dtr)
{
	asm volatile("sgdt %0":"=m" (*dtr));
}

static inline void vmmr0_native_store_idt(struct vmmr0_desc_ptr *dtr)
{
	asm volatile("sidt %0":"=m" (*dtr));
}

#ifndef MSR_FS_BASE
#define MSR_FS_BASE 0xc0000100
#endif
#ifndef MSR_GS_BASE
#define MSR_GS_BASE 0xc0000101
#endif

#ifndef NMI_VECTOR
#define NMI_VECTOR 2
#endif

#ifndef MSR_MTRRcap
#define MSR_MTRRcap            0x0fe
#define MSR_MTRRfix64K_00000   0x250
#define MSR_MTRRfix16K_80000   0x258
#define MSR_MTRRfix16K_A0000   0x259
#define MSR_MTRRfix4K_C0000    0x268
#define MSR_MTRRfix4K_C8000    0x269
#define MSR_MTRRfix4K_D0000    0x26a
#define MSR_MTRRfix4K_D8000    0x26b
#define MSR_MTRRfix4K_E0000    0x26c
#define MSR_MTRRfix4K_E8000    0x26d
#define MSR_MTRRfix4K_F0000    0x26e
#define MSR_MTRRfix4K_F8000    0x26f
#define MSR_MTRRdefType        0x2ff
#endif

#ifndef MSR_IA32_CR_PAT
#define MSR_IA32_CR_PAT        0x00000277
#endif

#ifndef MSR_VM_IGNNE
#define MSR_VM_IGNNE                    0xc0010115
#endif

/* Define DEBUGCTLMSR bits */
#ifndef DEBUGCTLMSR_LBR

#define _DEBUGCTLMSR_LBR	0 /* last branch recording */
#define _DEBUGCTLMSR_BTF	1 /* single-step on branches */

#define DEBUGCTLMSR_LBR		(VMMR0_LPUL(1) << _DEBUGCTLMSR_LBR)
#define DEBUGCTLMSR_BTF		(VMMR0_LPUL(1) << _DEBUGCTLMSR_BTF)

#endif

#ifndef MSR_FAM10H_MMIO_CONF_BASE
#define MSR_FAM10H_MMIO_CONF_BASE      0xc0010058
#endif

#ifndef MSR_AMD64_NB_CFG
#define MSR_AMD64_NB_CFG               0xc001001f
#endif

#ifndef __ASM_SIZE
# define ____ASM_FORM(x) " " #x " "
# ifdef CONFIG_X86_64
#  define __ASM_SIZE(inst) ____ASM_FORM(inst##q)
# else
#  define __ASM_SIZE(inst) ____ASM_FORM(inst##l)
# endif
#endif

#ifndef _ASM_PTR
# ifdef CONFIG_X86_64
#  define _ASM_PTR ".quad"
# else
#  define _ASM_PTR ".long"
# endif
#endif

/* Intel VT MSRs */
#ifndef MSR_IA32_VMX_BASIC
#define MSR_IA32_VMX_BASIC              0x00000480
#define MSR_IA32_VMX_PINBASED_CTLS      0x00000481
#define MSR_IA32_VMX_PROCBASED_CTLS     0x00000482
#define MSR_IA32_VMX_EXIT_CTLS          0x00000483
#define MSR_IA32_VMX_ENTRY_CTLS         0x00000484
#define MSR_IA32_VMX_MISC               0x00000485
#define MSR_IA32_VMX_CR0_FIXED0         0x00000486
#define MSR_IA32_VMX_CR0_FIXED1         0x00000487
#define MSR_IA32_VMX_CR4_FIXED0         0x00000488
#define MSR_IA32_VMX_CR4_FIXED1         0x00000489
#define MSR_IA32_VMX_VMCS_ENUM          0x0000048a
#define MSR_IA32_VMX_PROCBASED_CTLS2    0x0000048b
#define MSR_IA32_VMX_EPT_VPID_CAP       0x0000048c
#endif

#ifndef MSR_IA32_FEATURE_CONTROL
#define MSR_IA32_FEATURE_CONTROL        0x0000003a

#define FEATURE_CONTROL_LOCKED		(1<<0)
#define FEATURE_CONTROL_VMXON_ENABLED	(1<<2)
#endif

#ifndef FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX
#define FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX	(1<<1)
#define FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX	(1<<2)
#endif

#ifndef MSR_IA32_TSC
#define MSR_IA32_TSC                    0x00000010
#endif

#ifndef MSR_K7_HWCR
#define MSR_K7_HWCR                     0xc0010015
#endif

#ifndef MSR_K8_SYSCFG
#define MSR_K8_SYSCFG                   0xc0010010
#endif

#define set_debugreg(value, register) \
	__asm__("mov %0,%%db" #register \
		: /* no output */ \
		:"r" ((unsigned long)value))


#define vmmr0_compat_debugreg(x) debugreg[x]


struct mtrr_var_range
{
	u32 base_lo;
	u32 base_hi;
	u32 mask_lo;
	u32 mask_hi;
};

/* In the Intel processor's MTRR interface, the MTRR type is always held in
   an 8 bit field: */
typedef u8 mtrr_type;

#define MTRR_NUM_FIXED_RANGES 88
#define MTRR_MAX_VAR_RANGES 256

#define MTRR_TYPE_UNCACHABLE 0
#define MTRR_TYPE_WRCOMB     1
/*#define MTRR_TYPE_         2*/
/*#define MTRR_TYPE_         3*/
#define MTRR_TYPE_WRTHROUGH  4
#define MTRR_TYPE_WRPROT     5
#define MTRR_TYPE_WRBACK     6
#define MTRR_NUM_TYPES       7

struct mtrr_state_type
{
	struct mtrr_var_range var_ranges[MTRR_MAX_VAR_RANGES];
	mtrr_type fixed_ranges[MTRR_NUM_FIXED_RANGES];
	unsigned char enabled;
	unsigned char have_fixed;
	mtrr_type def_type;
};



#ifndef MCG_CTL_P
#define MCG_CTL_P        (VMMR0_LPULL(1)<<8)
#define MCG_STATUS_MCIP  (VMMR0_LPULL(1)<<2)
#define MCI_STATUS_VAL   (VMMR0_LPULL(1)<<63)
#define MCI_STATUS_OVER  (VMMR0_LPULL(1)<<62)
#define MCI_STATUS_UC    (VMMR0_LPULL(1)<<61)
#endif

#ifndef MCG_SER_P
#define MCG_SER_P	 	(VMMR0_LPULL(1)<<24)   /* MCA recovery/new status bits */
#endif

/* do_machine_check() exported in 2.6.31 */


static inline void vmmr0_do_machine_check(struct pt_regs *regs, long error_code)
{
	printk(("vmmr0 machine check!\n"));
}

/* pt_regs.flags was once pt_regs.eflags */


#define vmmr0_pt_regs_flags eflags

#  ifdef CONFIG_X86_64
#    define vmmr0_pt_regs_cs cs
#  else
#    define vmmr0_pt_regs_cs xcs
#  endif


#define vmmr0_x86_phys_bits (boot_cpu_data.x86_phys_bits)

#ifndef APIC_BASE_MSR
#define APIC_BASE_MSR    0x800
#endif

#ifndef APIC_SPIV_DIRECTED_EOI
#define APIC_SPIV_DIRECTED_EOI          (1 << 12)
#endif

#ifndef APIC_LVR_DIRECTED_EOI
#define APIC_LVR_DIRECTED_EOI   (1 << 24)
#endif

#ifndef APIC_SELF_IPI
#define APIC_SELF_IPI    0x3F0
#endif

#ifndef X2APIC_ENABLE
#define X2APIC_ENABLE    (VMMR0_LPUL(1) << 10)
#endif


static inline int hw_breakpoint_active(void)
{
	return 0;
}

static inline void hw_breakpoint_restore(void)
{
}

#define vmmr0_check_tsc_unstable()	1


#define percpu_read(t)		__get_cpu_var(t)
#define percpu_write(t, v)	__get_cpu_var(t) = v


#define vmmr0_tboot_enabled()	0

#pragma pack(push)
#pragma pack(1)
struct vmmr0_pvclock_vcpu_time_info
{
	u32   version;
	u32   pad0;
	u64   tsc_timestamp;
	u64   system_time;
	u32   tsc_to_system_mul;
	s8    tsc_shift;
	u8    flags;
	u8    pad[2];
} __attribute__((__packed__)); /* 32 bytes */

#ifndef MSR_AMD64_DC_CFG
#define MSR_AMD64_DC_CFG		0xc0011022
#endif

#ifndef MSR_IA32_MCx_STATUS
#define MSR_IA32_MCx_STATUS(x)		(MSR_IA32_MC0_STATUS + 4*(x))
#endif


struct vmmr0_i387_fxsave_struct
{
	u16	cwd;
	u16	swd;
	u16	twd;
	u16	fop;
	u64	rip;
	u64	rdp;
	u32	mxcsr;
	u32	mxcsr_mask;
	u32	st_space[32];	/* 8*16 bytes for each FP-reg = 128 bytes */
	u32	xmm_space[64];	/* 16*16 bytes for each XMM-reg = 256 bytes */
	u32	padding[12 + 12];
}__attribute__ ((__aligned__ (16)));

struct vmmr0_ymmh_struct
{
	/* 16 * 16 bytes for each YMMH-reg = 256 bytes */
	u32 ymmh_space[64];
};

struct vmmr0_xsave_hdr_struct
{
	u64 xstate_bv;
	u64 reserved1[2];
	u64 reserved2[5];
} __attribute__((packed));

struct vmmr0_xsave_struct
{
	struct vmmr0_i387_fxsave_struct i387;
	struct vmmr0_xsave_hdr_struct xsave_hdr;
	struct vmmr0_ymmh_struct ymmh;
	/* new processor state extensions will go here */
} __attribute__ ((packed, aligned (64)));

#pragma pack(pop)
union vmmr0_thread_xstate
{
	struct vmmr0_i387_fxsave_struct fxsave;
	struct vmmr0_xsave_struct xsave;
};


struct vmmr0_compat_fpu
{
	union vmmr0_thread_xstate state_buffer;
	union vmmr0_thread_xstate *state;
};

static inline int vmmr0_fpu_alloc(struct vmmr0_compat_fpu *fpu)
{
	fpu->state = &fpu->state_buffer;
	return 0;
}

static inline void vmmr0_fpu_free(struct vmmr0_compat_fpu *fpu)
{
}

static inline void vmmr0_fx_save(struct vmmr0_i387_fxsave_struct *image)
{
	asm("fxsave (%0)":: "r" (image));
}

static inline void vmmr0_fx_restore(struct vmmr0_i387_fxsave_struct *image)
{
	asm("fxrstor (%0)":: "r" (image));
}

static inline void vmmr0_fx_finit(void)
{
	asm("finit");
}

static inline void vmmr0_fpu_finit(struct vmmr0_compat_fpu *fpu)
{
	unsigned after_mxcsr_mask;

	preempt_disable();
	vmmr0_fx_finit();
	vmmr0_fx_save(&fpu->state->fxsave);
	preempt_enable();

	after_mxcsr_mask = offsetof(struct vmmr0_i387_fxsave_struct, st_space);
	fpu->state->fxsave.mxcsr = 0x1f80;
	memset((void *)&fpu->state->fxsave + after_mxcsr_mask,
	       0, sizeof(struct vmmr0_i387_fxsave_struct) - after_mxcsr_mask);
}

static inline int vmmr0_fpu_restore_checking(struct vmmr0_compat_fpu *fpu)
{
	vmmr0_fx_restore(&fpu->state->fxsave);
	return 0;
}

static inline void vmmr0_fpu_save_init(struct vmmr0_compat_fpu *fpu)
{
	vmmr0_fx_save(&fpu->state->fxsave);
}

extern unsigned int vmmr0_xstate_size;

void vmmr0_xstate_size_init(void);


static inline int vmmr0_init_fpu(struct task_struct *tsk)
{
	__asm__ ("movups %xmm0, %xmm0");
	return 0;
}


#ifndef XSTATE_FP
#define XSTATE_FP       0x1
#define XSTATE_SSE      0x2
#define XSTATE_FPSSE    (XSTATE_FP | XSTATE_SSE)
#endif

#ifndef XSTATE_YMM
#define XSTATE_YMM      0x4
#endif

#ifndef XSAVE_HDR_OFFSET
#define XSAVE_HDR_OFFSET    512
#endif

#define vmmr0_cpu_has_xsave	boot_cpu_has(X86_FEATURE_XSAVE)



#ifndef AMD_OSVW_ERRATUM
#define AMD_OSVW_ERRATUM(osvw_id, ...)	{ osvw_id, __VA_ARGS__, 0 }
#endif

#ifndef AMD_MODEL_RANGE
#define AMD_MODEL_RANGE(f, m_start, s_start, m_end, s_end) \
	((f << 24) | (m_start << 16) | (s_start << 12) | (m_end << 4) | (s_end))
#define AMD_MODEL_RANGE_FAMILY(range)	(((range) >> 24) & 0xff)
#define AMD_MODEL_RANGE_START(range)	(((range) >> 12) & 0xfff)
#define AMD_MODEL_RANGE_END(range)	((range) & 0xfff)
#endif

#ifndef MSR_AMD64_OSVW_ID_LENGTH
#define MSR_AMD64_OSVW_ID_LENGTH	0xc0010140
#define MSR_AMD64_OSVW_STATUS		0xc0010141
#endif

extern const int vmmr0_amd_erratum_383[];


static inline bool vmmr0_cpu_has_amd_erratum(const int *erratum)
{

	return false;
}


static inline u64 pvclock_scale_delta(u64 delta, u32 mul_frac, int shift)
{
	u64 product;
#ifdef __i386__
	u32 tmp1, tmp2;
#else
	ulong tmp;
#endif

	if (shift < 0)
		delta >>= -shift;
	else
		delta <<= shift;

#ifdef __i386__
	__asm__ (
		"mul  %5       ; "
		"mov  %4,%%eax ; "
		"mov  %%edx,%4 ; "
		"mul  %5       ; "
		"xor  %5,%5    ; "
		"add  %4,%%eax ; "
		"adc  %5,%%edx ; "
		: "=A" (product), "=r" (tmp1), "=r" (tmp2)
		: "a" ((u32)delta), "1" ((u32)(delta >> 32)), "2" (mul_frac) );
#elif defined(__x86_64__)
	__asm__ (
		"mulq %[mul_frac] ; shrd $32, %[hi], %[lo]"
		: [lo]"=a"(product),
		  [hi]"=d"(tmp)
		: "0"(delta),
		  [mul_frac]"rm"((u64)mul_frac));
#else
#error implement me!
#endif

	return product;
}


#define vmmr0_set_64bit(ptr, val)	set_64bit((unsigned long *)ptr, val)


#ifndef MSR_EBC_FREQUENCY_ID
#define MSR_EBC_FREQUENCY_ID	0x0000002c
#endif



#define static_cpu_has(bit) boot_cpu_has(bit)


#ifndef MSR_IA32_BBL_CR_CTL3
#define MSR_IA32_BBL_CR_CTL3	0x0000011e
#endif

bool vmmr0_boot_cpu_has(unsigned int bit);

#ifndef MSR_IA32_VMX_TRUE_PINBASED_CTLS
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS  0x0000048d
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS 0x0000048e
#define MSR_IA32_VMX_TRUE_EXIT_CTLS      0x0000048f
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS     0x00000490

#define VMX_BASIC_VMCS_SIZE_SHIFT	32
#define VMX_BASIC_MEM_TYPE_SHIFT	50
#define VMX_BASIC_MEM_TYPE_WB	6LLU
#endif

#ifndef MSR_IA32_TSCDEADLINE
#define MSR_IA32_TSCDEADLINE		0x000006e0
#endif

#ifndef APIC_LVT_TIMER_ONESHOT
#define APIC_LVT_TIMER_ONESHOT		(0 << 17)
#endif

#ifndef APIC_LVT_TIMER_TSCDEADLINE
#define APIC_LVT_TIMER_TSCDEADLINE	(2 << 17)
#endif

#ifndef MSR_IA32_MISC_ENABLE_FAST_STRING
#define MSR_IA32_MISC_ENABLE_FAST_STRING	(VMMR0_LPULL(1) << 0)
#endif

struct perf_guest_switch_msr
{
	unsigned msr;
	u64 host, guest;
};

static inline struct perf_guest_switch_msr *perf_guest_get_msrs(int *nr)
{
	*nr = 0;
	return NULL;
}


#ifndef X86_PMC_MAX_GENERIC
#define X86_PMC_MAX_GENERIC				       32
#endif

#ifndef X86_PMC_MAX_FIXED
#define X86_PMC_MAX_FIXED					3
#endif

union vmmr0_cpuid10_eax
{
	struct 
	{
		unsigned int version_id:8;
		unsigned int num_counters:8;
		unsigned int bit_width:8;
		unsigned int mask_length:8;
	} split;
	unsigned int full;
};

union vmmr0_cpuid10_edx
{
	struct 
	{
		unsigned int num_counters_fixed:5;
		unsigned int bit_width_fixed:8;
		unsigned int reserved:19;
	} split;
	unsigned int full;
};


static inline int user_has_fpu(void)
{
	return 1;
}

static inline void amd_pmu_enable_virt(void) { }
static inline void amd_pmu_disable_virt(void) { }

#ifndef ARCH_PERFMON_EVENTSEL_PIN_CONTROL
#define ARCH_PERFMON_EVENTSEL_PIN_CONTROL		(VMMR0_LPULL(1) << 19)
#endif


#ifndef PVCLOCK_GUEST_STOPPED
#define PVCLOCK_GUEST_STOPPED	(1 << 1)
#endif

static inline void native_cpuid(unsigned int *eax, unsigned int *ebx,
				unsigned int *ecx, unsigned int *edx)
{
	/* ecx is often an input as well as an output. */
	asm volatile("cpuid"
	    : "=a" (*eax),
	      "=b" (*ebx),
	      "=c" (*ecx),
	      "=d" (*edx)
	    : "0" (*eax), "2" (*ecx)
	    : "memory");
}

static inline void cpuid(unsigned int op,
			 unsigned int *eax, unsigned int *ebx,
			 unsigned int *ecx, unsigned int *edx)
{
	*eax = op;
	*ecx = 0;
	native_cpuid(eax, ebx, ecx, edx);
}

/* Some CPUID calls want 'count' to be placed in ecx */
static inline void cpuid_count(unsigned int op, int count,
			       unsigned int *eax, unsigned int *ebx,
			       unsigned int *ecx, unsigned int *edx)
{
	*eax = op;
	*ecx = count;
	native_cpuid(eax, ebx, ecx, edx);
}

/*
 * CPUID functions returning a single datum
 */
static inline unsigned int cpuid_eax(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);

	return eax;
}

static inline unsigned int cpuid_ebx(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);

	return ebx;
}

static inline unsigned int cpuid_ecx(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);

	return ecx;
}

static inline unsigned int cpuid_edx(unsigned int op)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(op, &eax, &ebx, &ecx, &edx);

	return edx;
}

#ifdef CONFIG_X86_64
# define do_div(n,base) ({					\
	uint64_t __base = (base);				\
	uint64_t __rem;						\
	__rem = ((uint64_t)(n)) % __base;			\
	(n) = ((uint64_t)(n)) / __base;				\
	__rem;							\
})
#else
#define do_div(n, base)						\
({								\
	unsigned long __upper, __low, __high, __mod, __base;	\
	__base = (base);					\
	asm("":"=a" (__low), "=d" (__high) : "A" (n));		\
	__upper = __high;					\
	if (__high) {						\
		__upper = __high % (__base);			\
		__high = __high / (__base);			\
	}							\
	asm("divl %2":"=a" (__low), "=d" (__mod)		\
	    : "rm" (__base), "0" (__low), "1" (__upper));	\
	asm("":"=A" (n) : "a" (__low), "d" (__high));		\
	__mod;							\
})
#endif

#define __X86_CASE_B	1
#define __X86_CASE_W	2
#define __X86_CASE_L	4
#define __X86_CASE_Q	8

#define __xchg(x, ptr, size)						\
({									\
	__typeof(*(ptr)) __x = (x);					\
	switch (size) {							\
	case __X86_CASE_B:						\
	{								\
		volatile u8 *__ptr = (volatile u8 *)(ptr);		\
		asm volatile("xchgb %0,%1"				\
			     : "=q" (__x), "+m" (*__ptr)		\
			     : "0" (__x)				\
			     : "memory");				\
		break;							\
	}								\
	case __X86_CASE_W:						\
	{								\
		volatile u16 *__ptr = (volatile u16 *)(ptr);		\
		asm volatile("xchgw %0,%1"				\
			     : "=r" (__x), "+m" (*__ptr)		\
			     : "0" (__x)				\
			     : "memory");				\
		break;							\
	}								\
	case __X86_CASE_L:						\
	{								\
		volatile u32 *__ptr = (volatile u32 *)(ptr);		\
		asm volatile("xchgl %0,%1"				\
			     : "=r" (__x), "+m" (*__ptr)		\
			     : "0" (__x)				\
			     : "memory");				\
		break;							\
	}								\
	case __X86_CASE_Q:						\
	{								\
		volatile u64 *__ptr = (volatile u64 *)(ptr);		\
		asm volatile("xchgq %0,%1"				\
			     : "=r" (__x), "+m" (*__ptr)		\
			     : "0" (__x)				\
			     : "memory");				\
		break;							\
	}								\
	default:							\
		break;            \
	}								\
	__x;								\
})

#define xchg(ptr, v)							\
	__xchg((v), (ptr), sizeof(*ptr))


#define __raw_cmpxchg(ptr, old, new, size, lock)			\
({									\
	__typeof__(*(ptr)) __ret;					\
	__typeof__(*(ptr)) __old = (old);				\
	__typeof__(*(ptr)) __new = (new);				\
	switch (size) {							\
	case __X86_CASE_B:						\
	{								\
		volatile u8 *__ptr = (volatile u8 *)(ptr);		\
		asm volatile(lock "cmpxchgb %2,%1"			\
			     : "=a" (__ret), "+m" (*__ptr)		\
			     : "q" (__new), "0" (__old)			\
			     : "memory");				\
		break;							\
	}								\
	case __X86_CASE_W:						\
	{								\
		volatile u16 *__ptr = (volatile u16 *)(ptr);		\
		asm volatile(lock "cmpxchgw %2,%1"			\
			     : "=a" (__ret), "+m" (*__ptr)		\
			     : "r" (__new), "0" (__old)			\
			     : "memory");				\
		break;							\
	}								\
	case __X86_CASE_L:						\
	{								\
		volatile u32 *__ptr = (volatile u32 *)(ptr);		\
		asm volatile(lock "cmpxchgl %2,%1"			\
			     : "=a" (__ret), "+m" (*__ptr)		\
			     : "r" (__new), "0" (__old)			\
			     : "memory");				\
		break;							\
	}								\
	case __X86_CASE_Q:						\
	{								\
		volatile u64 *__ptr = (volatile u64 *)(ptr);		\
		asm volatile(lock "cmpxchgq %2,%1"			\
			     : "=a" (__ret), "+m" (*__ptr)		\
			     : "r" (__new), "0" (__old)			\
			     : "memory");				\
		break;							\
	}								\
	default:							\
		break;        \
	}								\
	__ret;								\
})

#define __cmpxchg(ptr, old, new, size)					\
	__raw_cmpxchg((ptr), (old), (new), (size), LOCK_PREFIX)

#define __sync_cmpxchg(ptr, old, new, size)				\
	__raw_cmpxchg((ptr), (old), (new), (size), "lock; ")

#define __cmpxchg_local(ptr, old, new, size)				\
	__raw_cmpxchg((ptr), (old), (new), (size), "")


#define cmpxchg(ptr, old, new)						\
	__cmpxchg((ptr), (old), (new), sizeof(*ptr))


#ifdef CONFIG_X86_32
# include "cmpxchg_32.h"
#else
# include "cmpxchg_64.h"
#endif

/* 
 * An exchange-type operation, which takes a value and a pointer, and
 * returns a the old value.
 */
#define __xchg_op(ptr, arg, op, lock)					\
	({								\
	        __typeof__ (*(ptr)) __ret = (arg);			\
		switch (sizeof(*(ptr))) {				\
		case __X86_CASE_B:					\
			asm volatile (lock #op "b %b0, %1\n"		\
				      : "+q" (__ret), "+m" (*(ptr))	\
				      : : "memory", "cc");		\
			break;						\
		case __X86_CASE_W:					\
			asm volatile (lock #op "w %w0, %1\n"		\
				      : "+r" (__ret), "+m" (*(ptr))	\
				      : : "memory", "cc");		\
			break;						\
		case __X86_CASE_L:					\
			asm volatile (lock #op "l %0, %1\n"		\
				      : "+r" (__ret), "+m" (*(ptr))	\
				      : : "memory", "cc");		\
			break;						\
		case __X86_CASE_Q:					\
			asm volatile (lock #op "q %q0, %1\n"		\
				      : "+r" (__ret), "+m" (*(ptr))	\
				      : : "memory", "cc");		\
			break;						\
		default:						\
			__ ## op ## _wrong_size();			\
		}							\
		__ret;							\
	})
	
#define __xadd(ptr, inc, lock)	__xchg_op((ptr), (inc), xadd, lock)
#define xadd(ptr, inc)		__xadd((ptr), (inc), LOCK_PREFIX)
#define xadd_sync(ptr, inc)	__xadd((ptr), (inc), "lock; ")
#define xadd_local(ptr, inc)	__xadd((ptr), (inc), "")

#define ATOMIC_INIT(i)	{ (i) }

static inline int atomic_read(const atomic_t *v)
{
	return (*(volatile int *)&(v)->counter);
}
static inline void atomic_set(atomic_t *v, int i)
{
	v->counter = i;
}

static inline void atomic_add(int i, atomic_t *v)
{
	asm volatile(LOCK_PREFIX "addl %1,%0"
		     : "+m" (v->counter)
		     : "ir" (i));
}

static inline void atomic_sub(int i, atomic_t *v)
{
	asm volatile(LOCK_PREFIX "subl %1,%0"
		     : "+m" (v->counter)
		     : "ir" (i));
}

static inline int atomic_sub_and_test(int i, atomic_t *v)
{
	unsigned char c;

	asm volatile(LOCK_PREFIX "subl %2,%0; sete %1"
		     : "+m" (v->counter), "=qm" (c)
		     : "ir" (i) : "memory");
	return c;
}

static inline void atomic_inc(atomic_t *v)
{
	asm volatile(LOCK_PREFIX "incl %0"
		     : "+m" (v->counter));
}

static inline void atomic_dec(atomic_t *v)
{
	asm volatile(LOCK_PREFIX "decl %0"
		     : "+m" (v->counter));
}

static inline int atomic_dec_and_test(atomic_t *v)
{
	unsigned char c;

	asm volatile(LOCK_PREFIX "decl %0; sete %1"
		     : "+m" (v->counter), "=qm" (c)
		     : : "memory");
	return c != 0;
}

static inline int atomic_inc_and_test(atomic_t *v)
{
	unsigned char c;

	asm volatile(LOCK_PREFIX "incl %0; sete %1"
		     : "+m" (v->counter), "=qm" (c)
		     : : "memory");
	return c != 0;
}

static inline int atomic_add_negative(int i, atomic_t *v)
{
	unsigned char c;

	asm volatile(LOCK_PREFIX "addl %2,%0; sets %1"
		     : "+m" (v->counter), "=qm" (c)
		     : "ir" (i) : "memory");
	return c;
}

static inline int atomic_cmpxchg(atomic_t *v, int old, int thenew)
{
	return cmpxchg(&v->counter, old, thenew);
}

static inline int atomic_xchg(atomic_t *v, int thenew)
{
	return xchg(&v->counter, thenew);
}

static inline short int atomic_inc_short(short int *v)
{
	asm(LOCK_PREFIX "addw $1, %0" : "+m" (*v));
	return *v;
}

#ifdef CONFIG_X86_64
static inline void atomic_or_long(unsigned long *v1, unsigned long v2)
{
	asm(LOCK_PREFIX "orq %1, %0" : "+m" (*v1) : "r" (v2));
}
#endif

/**
 * atomic_add_return - add integer and return
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v and returns @i + @v
 */
static inline int atomic_add_return(int i, atomic_t *v)
{
	return i + xadd(&v->counter, i);
}

/**
 * atomic_sub_return - subtract integer and return
 * @v: pointer of type atomic_t
 * @i: integer value to subtract
 *
 * Atomically subtracts @i from @v and returns @v - @i
 */
static inline int atomic_sub_return(int i, atomic_t *v)
{
	return atomic_add_return(-i, v);
}

#define atomic_inc_return(v)  (atomic_add_return(1, v))
#define atomic_dec_return(v)  (atomic_sub_return(1, v))

static inline int vmmr0_sched_info_on(void)
{
        return 0;
}

static inline void native_clts(void)
{
	asm volatile("clts");
}

static unsigned long __force_order;

static inline unsigned long native_read_cr0(void)
{
	unsigned long val;
	asm volatile("mov %%cr0,%0\n\t" : "=r" (val), "=m" (__force_order));
	return val;
}

static inline void native_write_cr0(unsigned long val)
{
	asm volatile("mov %0,%%cr0": : "r" (val), "m" (__force_order));
}

static inline unsigned long native_read_cr2(void)
{
	unsigned long val;
	asm volatile("mov %%cr2,%0\n\t" : "=r" (val), "=m" (__force_order));
	return val;
}

static inline void native_write_cr2(unsigned long val)
{
	asm volatile("mov %0,%%cr2": : "r" (val), "m" (__force_order));
}

static inline unsigned long native_read_cr3(void)
{
	unsigned long val;
	asm volatile("mov %%cr3,%0\n\t" : "=r" (val), "=m" (__force_order));
	return val;
}

static inline void native_write_cr3(unsigned long val)
{
	asm volatile("mov %0,%%cr3": : "r" (val), "m" (__force_order));
}

static inline unsigned long native_read_cr4(void)
{
	unsigned long val;
	asm volatile("mov %%cr4,%0\n\t" : "=r" (val), "=m" (__force_order));
	return val;
}

static inline unsigned long native_read_cr4_safe(void)
{
	unsigned long val;

#ifdef CONFIG_X86_32
	asm volatile("1: mov %%cr4, %0\n"
		     "2:\n"
		     _ASM_EXTABLE(1b, 2b)
		     : "=r" (val), "=m" (__force_order) : "0" (0));
#else
	val = native_read_cr4();
#endif
	return val;
}

static inline void native_write_cr4(unsigned long val)
{
	asm volatile("mov %0,%%cr4": : "r" (val), "m" (__force_order));
}

#ifdef CONFIG_X86_64
static inline unsigned long native_read_cr8(void)
{
	unsigned long cr8;
	asm volatile("movq %%cr8,%0" : "=r" (cr8));
	return cr8;
}

static inline void native_write_cr8(unsigned long val)
{
	asm volatile("movq %0,%%cr8" :: "r" (val) : "memory");
}
#endif

static inline void native_wbinvd(void)
{
	asm volatile("wbinvd": : :"memory");
}

static inline unsigned long read_cr0(void)
{
	return native_read_cr0();
}

static inline void write_cr0(unsigned long x)
{
	native_write_cr0(x);
}

static inline unsigned long read_cr2(void)
{
	return native_read_cr2();
}

static inline void write_cr2(unsigned long x)
{
	native_write_cr2(x);
}

static inline unsigned long read_cr3(void)
{
	return native_read_cr3();
}

static inline void write_cr3(unsigned long x)
{
	native_write_cr3(x);
}

static inline unsigned long read_cr4(void)
{
	return native_read_cr4();
}

static inline unsigned long read_cr4_safe(void)
{
	return native_read_cr4_safe();
}

static inline void write_cr4(unsigned long x)
{
	native_write_cr4(x);
}

static inline void wbinvd(void)
{
	native_wbinvd();
}

#ifdef CONFIG_X86_64

static inline unsigned long read_cr8(void)
{
	return native_read_cr8();
}

static inline void write_cr8(unsigned long x)
{
	native_write_cr8(x);
}

static inline void native_load_gs_index(unsigned selector)
{
	asm volatile("mov %0,%%gs" :: "r" (selector) : "memory");
}

static inline void load_gs_index(unsigned selector)
{
	native_load_gs_index(selector);
}

#endif

static inline void clts(void)
{
	native_clts();
}

#define stts() write_cr0(read_cr0() | X86_CR0_TS)

#ifndef BUS_MCEERR_AR
#define BUS_MCEERR_AR 4
#endif
#ifndef BUS_MCEERR_AO
#define BUS_MCEERR_AO 5
#endif

void* kmemdup(void* src, unsigned long len, unsigned long flag);

static inline unsigned long native_save_fl(void)
{
	unsigned long flags;

	asm volatile("# __raw_save_flags\n\t"
		     "pushf ; pop %0"
		     : "=rm" (flags)
		     : /* no input */
		     : "memory");

	return flags;
}

static inline void native_restore_fl(unsigned long flags)
{
	asm volatile("push %0 ; popf"
		     : /* no output */
		     :"g" (flags)
		     :"memory", "cc");
}

static inline void native_irq_disable(void)
{
	asm volatile("cli": : :"memory");
}

static inline void native_irq_enable(void)
{
	asm volatile("sti": : :"memory");
}

static inline void local_irq_disable(void)
{
	native_irq_disable();
}

static inline void local_irq_enable(void)
{
	native_irq_enable();
}

static inline unsigned long arch_local_irq_save(void)
{
	unsigned long flags = native_save_fl();
	local_irq_disable();
	return flags;
}

static inline void arch_local_irq_restore(unsigned long flags)
{
	native_restore_fl(flags);
}

#define raw_local_irq_save(flags)			\
	do 										\
	{										\
		flags = arch_local_irq_save();		\
	} while (0)

#define raw_local_irq_restore(flags)			\
	do 										\
	{										\
		arch_local_irq_restore(flags);			\
	} while (0)

#define local_irq_save    raw_local_irq_save
#define local_irq_restore raw_local_irq_restore

static inline void __flush_tlb_all(void)
{
	unsigned long flags;
	unsigned long cr4;
	raw_local_irq_save(flags);

	native_write_cr3(native_read_cr3());

	cr4 = native_read_cr4();
	/* clear PGE */
	native_write_cr4(cr4 & ~X86_CR4_PGE);
	/* write old PGE again and flush TLBs */
	native_write_cr4(cr4);

	raw_local_irq_restore(flags);
}

static inline int get_order(unsigned long size)
{
	int order;

	size = (size - 1) >> (PAGE_SHIFT - 1);
	order = -1;
	do
	{
		size >>= 1;
		order++;
	} while (size);
	return order;
}

#define vmmr0_memcmp memcmp
#define XCR_XFEATURE_ENABLED_MASK	0x00000000

static inline u64 xgetbv(u32 index)
{
	u32 eax, edx;

	asm volatile(".byte 0x0f,0x01,0xd0" /* xgetbv */
		     : "=a" (eax), "=d" (edx)
		     : "c" (index));
	return eax + ((u64)edx << 32);
}

static inline void xsetbv(u32 index, u64 value)
{
	u32 eax = value;
	u32 edx = value >> 32;

	asm volatile(".byte 0x0f,0x01,0xd1" /* xsetbv */
		     : : "a" (eax), "d" (edx), "c" (index));
}

#define vmmr0___get_user_pages_fast	__get_user_pages_fast

#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)

#define __rcu_assign_pointer(p, v, space)	 \
	({										 \
		smp_wmb(); 							 \
		(p) = (typeof(*v) space *)(v);		 \
	})

#define rcu_assign_pointer(p, v) \
	__rcu_assign_pointer((p), (v), __rcu)

static inline int init_srcu_struct(struct srcu_struct* srcu)
{
	srcu->raised = 0;
	return 0;
}

static inline void cleanup_srcu_struct(struct srcu_struct* srcu)
{
}

static inline int srcu_read_lock(struct srcu_struct* srcu)
{
	if(KeGetCurrentIrql() < DISPATCH_LEVEL)
	{
		KeRaiseIrql(DISPATCH_LEVEL, &srcu->old_irql);
		srcu->raised = 1;
	}
	return 0;
}

static inline void srcu_read_unlock(struct srcu_struct* srcu, int idx)
{
	if(srcu->raised)
	{
	    KeLowerIrql(srcu->old_irql);
	}
}

static inline int smp_call_function(smp_call_func_t func, void *info, int wait)
{
	preempt_disable();
	smp_call_function_many(cpu_online_mask, func, info, wait);
	preempt_enable();

	return 0;
}

static inline int on_each_cpu(void (*func) (void *info), void *info, int wait)
{
	unsigned long flags;
	int ret = 0;

	preempt_disable();
	ret = smp_call_function(func, info, wait);
	preempt_enable();
	return ret;
}

static inline void mdelay(unsigned long mseconds)
{
	KeStallExecutionProcessor(mseconds * 1000);
}

#define raw_spin_lock_irqsave(lock, flags)			\
	do {											\
		flags = _raw_spin_lock_irqsave(lock);		\
	} while (0)

#define raw_spin_unlock_irqrestore(lock, flags)		\
	do {											\
		_raw_spin_unlock_irqrestore(lock, flags);	\
	} while (0)

static inline unsigned long _raw_spin_lock_irqsave(raw_spinlock_t *lock)
{
	unsigned long flags;

	preempt_disable();
	local_irq_save(flags);
	raw_spin_lock(lock);
	return flags;
}

static inline void _raw_spin_unlock_irqrestore(raw_spinlock_t *lock,
					    unsigned long flags)
{
	raw_spin_unlock(lock);
	local_irq_restore(flags);
	preempt_enable();
}

#define __kernel_fpu_begin()	do { } while (0)
#define __kernel_fpu_end()	do { } while (0)

struct msi_msg 
{
	u32	address_lo;	/* low 32 bits of msi message address */
	u32	address_hi;	/* high 32 bits of msi message address */
	u32	data;		/* 16 bits of msi message data */
};

union ktime 
{
	s64	tv64;
#if BITS_PER_LONG != 64 && !defined(CONFIG_KTIME_SCALAR)
	struct {
# ifdef __BIG_ENDIAN
	s32	sec, nsec;
# else
	s32	nsec, sec;
# endif
	} tv;
#endif
};

typedef union ktime ktime_t;

#define KTIME_MAX			((s64)~((u64)1 << 63))
#if (BITS_PER_LONG == 64)
# define KTIME_SEC_MAX			(KTIME_MAX / NSEC_PER_SEC)
#else
# define KTIME_SEC_MAX			LONG_MAX
# error KTIME_SEC_MAX
#endif


#if (BITS_PER_LONG == 64)

static inline ktime_t ktime_set(const long secs, const unsigned long nsecs)
{
#if (BITS_PER_LONG == 64)
	if (unlikely(secs >= KTIME_SEC_MAX))
		return (ktime_t){ .tv64 = KTIME_MAX };
#endif
	return (ktime_t) { .tv64 = (s64)secs * NSEC_PER_SEC + (s64)nsecs };
}

/* Subtract two ktime_t variables. rem = lhs -rhs: */
#define ktime_sub(lhs, rhs) \
		({ (ktime_t){ .tv64 = (lhs).tv64 - (rhs).tv64 }; })

/* Add two ktime_t variables. res = lhs + rhs: */
#define ktime_add(lhs, rhs) \
		({ (ktime_t){ .tv64 = (lhs).tv64 + (rhs).tv64 }; })

/*
 * Add a ktime_t variable and a scalar nanosecond value.
 * res = kt + nsval:
 */
#define ktime_add_ns(kt, nsval) \
		({ (ktime_t){ .tv64 = (kt).tv64 + (nsval) }; })

/*
 * Subtract a scalar nanosecod from a ktime_t variable
 * res = kt - nsval:
 */
#define ktime_sub_ns(kt, nsval) \
		({ (ktime_t){ .tv64 = (kt).tv64 - (nsval) }; })


/* Map the ktime_t to timespec conversion to ns_to_timespec function */
#define ktime_to_timespec(kt)		ns_to_timespec((kt).tv64)

/* Map the ktime_t to timeval conversion to ns_to_timeval function */
#define ktime_to_timeval(kt)		ns_to_timeval((kt).tv64)

/* Convert ktime_t to nanoseconds - NOP in the scalar storage format: */
#define ktime_to_ns(kt)			((kt).tv64)
#else
#error "32 bit host not supported"
#endif

static inline int ktime_equal(const ktime_t cmp1, const ktime_t cmp2)
{
	return cmp1.tv64 == cmp2.tv64;
}

/**
 * ktime_compare - Compares two ktime_t variables for less, greater or equal
 * @cmp1:	comparable1
 * @cmp2:	comparable2
 *
 * Returns ...
 *   cmp1  < cmp2: return <0
 *   cmp1 == cmp2: return 0
 *   cmp1  > cmp2: return >0
 */
static inline int ktime_compare(const ktime_t cmp1, const ktime_t cmp2)
{
	if (cmp1.tv64 < cmp2.tv64)
		return -1;
	if (cmp1.tv64 > cmp2.tv64)
		return 1;
	return 0;
}

static inline ktime_t ktime_add_us(const ktime_t kt, const u64 usec)
{
	return ktime_add_ns(kt, usec * 1000);
}

static inline ktime_t ktime_sub_us(const ktime_t kt, const u64 usec)
{
	return ktime_sub_ns(kt, usec * 1000);
}

static inline ktime_t ns_to_ktime(u64 ns)
{
	static const ktime_t ktime_zero = { .tv64 = 0 };
	return ktime_add_ns(ktime_zero, ns);
}

static inline ktime_t ktime_get(void)
{
	/*
	s64 nsecs;
	u32 tinc;
	LARGE_INTEGER time;
	KeQueryTickCount(&time);
	nsecs = time.QuadPart;
	tinc = KeQueryTimeIncrement();
	nsecs *= tinc;
    nsecs *= 100;
	*/
	s64 nsecs = 0;
	LARGE_INTEGER time;
	KeQuerySystemTime(&time);
	nsecs = time.QuadPart;
	nsecs *= 100;
	
	return (ktime_t){.tv64 = nsecs};
}
typedef unsigned long clockid_t;
#define CLOCK_REALTIME			0
#define CLOCK_MONOTONIC			1
#define CLOCK_PROCESS_CPUTIME_ID	2
#define CLOCK_THREAD_CPUTIME_ID		3
#define CLOCK_MONOTONIC_RAW		4
#define CLOCK_REALTIME_COARSE		5
#define CLOCK_MONOTONIC_COARSE		6
#define CLOCK_BOOTTIME			7
#define CLOCK_REALTIME_ALARM		8
#define CLOCK_BOOTTIME_ALARM		9

enum hrtimer_mode 
{
	HRTIMER_MODE_ABS = 0x0,		/* Time value is absolute */
	HRTIMER_MODE_REL = 0x1,		/* Time value is relative to now */
	HRTIMER_MODE_PINNED = 0x02,	/* Timer is bound to CPU */
	HRTIMER_MODE_ABS_PINNED = 0x02,
	HRTIMER_MODE_REL_PINNED = 0x03,
};

enum hrtimer_restart 
{
	HRTIMER_NORESTART,	/* Timer is not restarted */
	HRTIMER_RESTART,	/* Timer must be restarted */
};

struct timerqueue_node 
{
	ktime_t expires;
};

struct hrtimer_clock_base 
{
	int			index;
	ktime_t			resolution;
	ktime_t			(*get_time)(void);
	ktime_t			softirq_time;
	ktime_t			offset;
};

struct hrtimer 
{
	struct timerqueue_node		node;
	ktime_t				_softexpires;
	enum hrtimer_restart		(*function)(struct hrtimer *);
	struct hrtimer_clock_base	*base;
	unsigned long			state;
	KTIMER                  ktimer;
	KDPC                    kdpc;
	LARGE_INTEGER           due_time;
	struct hrtimer_clock_base	base_hack;
};

void hrtimer_init(struct hrtimer *timer, clockid_t clock_id, enum hrtimer_mode mode);
int hrtimer_start(struct hrtimer *timer, ktime_t tim, const enum hrtimer_mode mode);
int hrtimer_cancel(struct hrtimer *timer);
int vmmr0_hrtimer_restart(struct hrtimer* timer);

static inline void vmmr0_hrtimer_add_expires_ns(struct hrtimer *timer, u64 delta)
{
	timer->node.expires = ktime_add_ns(timer->node.expires, delta);
}

static inline ktime_t vmmr0_hrtimer_get_expires(struct hrtimer *timer)
{
	return timer->node.expires;
}

static inline u64 vmmr0_hrtimer_get_expires_ns(struct hrtimer *timer)
{
	return ktime_to_ns(timer->node.expires);
}

static inline void vmmr0_hrtimer_start_expires(struct hrtimer *timer, int mode)
{
	hrtimer_start(timer, timer->node.expires, mode);
}

static inline ktime_t vmmr0_hrtimer_expires_remaining(const struct hrtimer *timer)
{
    return ktime_sub(timer->node.expires, timer->base->get_time());
}

static inline ktime_t hrtimer_expires_remaining(const struct hrtimer *timer)
{
	return ktime_sub(timer->node.expires, timer->base->get_time());
}

static inline ktime_t hrtimer_get_remaining(const struct hrtimer *timer)
{
	unsigned long flags;
	ktime_t rem;
	rem = vmmr0_hrtimer_expires_remaining(timer);
	return rem;
}

struct work_struct;

typedef void (*work_func_t)(struct work_struct *work);

struct workqueue_struct 
{
	HANDLE thread_handle;
	struct list_head work_list;
	u64 exit_request;
	u64 modify_work_pending;
	KEVENT can_exit;
	KEVENT do_work_pending;
	spinlock_t work_lock;
	spinlock_t modify_list_lock;
};

struct work_struct 
{
	struct list_head entry;
	work_func_t func;
	struct workqueue_struct* wq;
};

#define INIT_WORK(_work, _func)						\
	do {								\
		vmmr0_init_work((_work), (_func));			\
	} while (0)

static inline void vmmr0_init_work(struct work_struct* work, work_func_t fn)
{
	work->wq = 0;
	work->func = fn;
}

static inline bool queue_work(struct workqueue_struct *wq, struct work_struct *work)
{
	if(!wq)
	{
		return false;
	}
	if (work->wq)
	{
		return false;
	}
	spin_lock(&wq->modify_list_lock);
	wq->modify_work_pending = 1;
	spin_lock(&wq->work_lock);
	work->wq = wq;
	list_add_tail(&work->entry, &wq->work_list);
	wq->modify_work_pending = 0;
	spin_unlock(&wq->work_lock);
	KeSetEvent(&wq->do_work_pending, IO_NO_INCREMENT, FALSE);
	spin_unlock(&wq->modify_list_lock);
	return true;
}

static inline bool cancel_work_sync(struct work_struct *work)
{
	struct workqueue_struct *wq = work->wq;
	if(!work)
	{
		return false;
	}
	if(!wq)
	{
		return false;
	}
	spin_lock(&wq->modify_list_lock);
	wq->modify_work_pending = 1;
	spin_lock(&wq->work_lock);
	work->wq = 0;
	list_del_init(&work->entry);
	wq->modify_work_pending = 0;
	spin_unlock(&wq->work_lock);
	KeSetEvent(&wq->do_work_pending, IO_NO_INCREMENT, FALSE);
	spin_unlock(&wq->modify_list_lock);
	return true;
}

void vmmr0_workqueue_thread_fn(void* p);

static inline struct workqueue_struct* create_singlethread_workqueue(const char* name)
{
	NTSTATUS status;
	struct workqueue_struct* wq = ExAllocatePool(NonPagedPool, sizeof(struct workqueue_struct));
	if (!wq)
	{
		goto out_error;
	}
	
	spin_lock_init(&wq->work_lock);
	spin_lock_init(&wq->modify_list_lock);
	KeInitializeEvent(&wq->can_exit, SynchronizationEvent, FALSE);
	KeInitializeEvent(&wq->do_work_pending, SynchronizationEvent, FALSE);
	wq->exit_request = 0;
	wq->modify_work_pending = 0;
	INIT_LIST_HEAD(&wq->work_list);
	
	status = PsCreateSystemThread(&wq->thread_handle, 
		(ACCESS_MASK)THREAD_ALL_ACCESS, 
		NULL, NULL, NULL, 
		(PKSTART_ROUTINE)vmmr0_workqueue_thread_fn, wq);
	
	if (status != STATUS_SUCCESS) {
		goto out_free;
	}
	
	return wq;
	
	out_free:
	ExFreePool(wq);
	out_error:
	return 0;
}

static inline void destroy_workqueue(struct workqueue_struct *wq)
{
	if(!wq)
	{
		return;
	}
	
	wq->exit_request = 1;
	
	KeSetEvent(&wq->do_work_pending, IO_NO_INCREMENT, FALSE);
	KeWaitForSingleObject(&wq->can_exit, Executive, KernelMode, FALSE, NULL);
	
	ExFreePool(wq);
}