

#ifndef CPU_FEATURES_H_
#define CPU_FEATURES_H_

#define NCAPINTS	10	/* N 32-bit words worth of info */

/*
 * Note: If the comment begins with a quoted string, that string is used
 * in /proc/cpuinfo instead of the macro name.  If the string is "",
 * this feature bit is not displayed in /proc/cpuinfo at all.
 */

/* Intel-defined CPU features, CPUID level 0x00000001 (edx), word 0 */
#define X86_FEATURE_FPU		(0*32+ 0) /* Onboard FPU */
#define X86_FEATURE_VME		(0*32+ 1) /* Virtual Mode Extensions */
#define X86_FEATURE_DE		(0*32+ 2) /* Debugging Extensions */
#define X86_FEATURE_PSE		(0*32+ 3) /* Page Size Extensions */
#define X86_FEATURE_TSC		(0*32+ 4) /* Time Stamp Counter */
#define X86_FEATURE_MSR		(0*32+ 5) /* Model-Specific Registers */
#define X86_FEATURE_PAE		(0*32+ 6) /* Physical Address Extensions */
#define X86_FEATURE_MCE		(0*32+ 7) /* Machine Check Exception */
#define X86_FEATURE_CX8		(0*32+ 8) /* CMPXCHG8 instruction */
#define X86_FEATURE_APIC	(0*32+ 9) /* Onboard APIC */
#define X86_FEATURE_SEP		(0*32+11) /* SYSENTER/SYSEXIT */
#define X86_FEATURE_MTRR	(0*32+12) /* Memory Type Range Registers */
#define X86_FEATURE_PGE		(0*32+13) /* Page Global Enable */
#define X86_FEATURE_MCA		(0*32+14) /* Machine Check Architecture */
#define X86_FEATURE_CMOV	(0*32+15) /* CMOV instructions */
					  /* (plus FCMOVcc, FCOMI with FPU) */
#define X86_FEATURE_PAT		(0*32+16) /* Page Attribute Table */
#define X86_FEATURE_PSE36	(0*32+17) /* 36-bit PSEs */
#define X86_FEATURE_PN		(0*32+18) /* Processor serial number */
#define X86_FEATURE_CLFLSH	(0*32+19) /* "clflush" CLFLUSH instruction */
#define X86_FEATURE_DS		(0*32+21) /* "dts" Debug Store */
#define X86_FEATURE_ACPI	(0*32+22) /* ACPI via MSR */
#define X86_FEATURE_MMX		(0*32+23) /* Multimedia Extensions */
#define X86_FEATURE_FXSR	(0*32+24) /* FXSAVE/FXRSTOR, CR4.OSFXSR */
#define X86_FEATURE_XMM		(0*32+25) /* "sse" */
#define X86_FEATURE_XMM2	(0*32+26) /* "sse2" */
#define X86_FEATURE_SELFSNOOP	(0*32+27) /* "ss" CPU self snoop */
#define X86_FEATURE_HT		(0*32+28) /* Hyper-Threading */
#define X86_FEATURE_ACC		(0*32+29) /* "tm" Automatic clock control */
#define X86_FEATURE_IA64	(0*32+30) /* IA-64 processor */
#define X86_FEATURE_PBE		(0*32+31) /* Pending Break Enable */

/* AMD-defined CPU features, CPUID level 0x80000001, word 1 */
/* Don't duplicate feature flags which are redundant with Intel! */
#define X86_FEATURE_SYSCALL	(1*32+11) /* SYSCALL/SYSRET */
#define X86_FEATURE_MP		(1*32+19) /* MP Capable. */
#define X86_FEATURE_NX		(1*32+20) /* Execute Disable */
#define X86_FEATURE_MMXEXT	(1*32+22) /* AMD MMX extensions */
#define X86_FEATURE_FXSR_OPT	(1*32+25) /* FXSAVE/FXRSTOR optimizations */
#define X86_FEATURE_GBPAGES	(1*32+26) /* "pdpe1gb" GB pages */
#define X86_FEATURE_RDTSCP	(1*32+27) /* RDTSCP */
#define X86_FEATURE_LM		(1*32+29) /* Long Mode (x86-64) */
#define X86_FEATURE_3DNOWEXT	(1*32+30) /* AMD 3DNow! extensions */
#define X86_FEATURE_3DNOW	(1*32+31) /* 3DNow! */

/* Transmeta-defined CPU features, CPUID level 0x80860001, word 2 */
#define X86_FEATURE_RECOVERY	(2*32+ 0) /* CPU in recovery mode */
#define X86_FEATURE_LONGRUN	(2*32+ 1) /* Longrun power control */
#define X86_FEATURE_LRTI	(2*32+ 3) /* LongRun table interface */

/* Other features, Linux-defined mapping, word 3 */
/* This range is used for feature bits which conflict or are synthesized */
#define X86_FEATURE_CXMMX	(3*32+ 0) /* Cyrix MMX extensions */
#define X86_FEATURE_K6_MTRR	(3*32+ 1) /* AMD K6 nonstandard MTRRs */
#define X86_FEATURE_CYRIX_ARR	(3*32+ 2) /* Cyrix ARRs (= MTRRs) */
#define X86_FEATURE_CENTAUR_MCR	(3*32+ 3) /* Centaur MCRs (= MTRRs) */
/* cpu types for specific tunings: */
#define X86_FEATURE_K8		(3*32+ 4) /* "" Opteron, Athlon64 */
#define X86_FEATURE_K7		(3*32+ 5) /* "" Athlon */
#define X86_FEATURE_P3		(3*32+ 6) /* "" P3 */
#define X86_FEATURE_P4		(3*32+ 7) /* "" P4 */
#define X86_FEATURE_CONSTANT_TSC (3*32+ 8) /* TSC ticks at a constant rate */
#define X86_FEATURE_UP		(3*32+ 9) /* smp kernel running on up */
#define X86_FEATURE_FXSAVE_LEAK (3*32+10) /* "" FXSAVE leaks FOP/FIP/FOP */
#define X86_FEATURE_ARCH_PERFMON (3*32+11) /* Intel Architectural PerfMon */
#define X86_FEATURE_PEBS	(3*32+12) /* Precise-Event Based Sampling */
#define X86_FEATURE_BTS		(3*32+13) /* Branch Trace Store */
#define X86_FEATURE_SYSCALL32	(3*32+14) /* "" syscall in ia32 userspace */
#define X86_FEATURE_SYSENTER32	(3*32+15) /* "" sysenter in ia32 userspace */
#define X86_FEATURE_REP_GOOD	(3*32+16) /* rep microcode works well */
#define X86_FEATURE_MFENCE_RDTSC (3*32+17) /* "" Mfence synchronizes RDTSC */
#define X86_FEATURE_LFENCE_RDTSC (3*32+18) /* "" Lfence synchronizes RDTSC */
#define X86_FEATURE_11AP	(3*32+19) /* "" Bad local APIC aka 11AP */
#define X86_FEATURE_NOPL	(3*32+20) /* The NOPL (0F 1F) instructions */
					  /* 21 available, was AMD_C1E */
#define X86_FEATURE_XTOPOLOGY	(3*32+22) /* cpu topology enum extensions */
#define X86_FEATURE_TSC_RELIABLE (3*32+23) /* TSC is known to be reliable */
#define X86_FEATURE_NONSTOP_TSC	(3*32+24) /* TSC does not stop in C states */
#define X86_FEATURE_CLFLUSH_MONITOR (3*32+25) /* "" clflush reqd with monitor */
#define X86_FEATURE_EXTD_APICID	(3*32+26) /* has extended APICID (8 bits) */
#define X86_FEATURE_AMD_DCM     (3*32+27) /* multi-node processor */
#define X86_FEATURE_APERFMPERF	(3*32+28) /* APERFMPERF */
#define X86_FEATURE_EAGER_FPU	(3*32+29) /* "eagerfpu" Non lazy FPU restore */

/* Intel-defined CPU features, CPUID level 0x00000001 (ecx), word 4 */
#define X86_FEATURE_XMM3	(4*32+ 0) /* "pni" SSE-3 */
#define X86_FEATURE_PCLMULQDQ	(4*32+ 1) /* PCLMULQDQ instruction */
#define X86_FEATURE_DTES64	(4*32+ 2) /* 64-bit Debug Store */
#define X86_FEATURE_MWAIT	(4*32+ 3) /* "monitor" Monitor/Mwait support */
#define X86_FEATURE_DSCPL	(4*32+ 4) /* "ds_cpl" CPL Qual. Debug Store */
#define X86_FEATURE_VMX		(4*32+ 5) /* Hardware virtualization */
#define X86_FEATURE_SMX		(4*32+ 6) /* Safer mode */
#define X86_FEATURE_EST		(4*32+ 7) /* Enhanced SpeedStep */
#define X86_FEATURE_TM2		(4*32+ 8) /* Thermal Monitor 2 */
#define X86_FEATURE_SSSE3	(4*32+ 9) /* Supplemental SSE-3 */
#define X86_FEATURE_CID		(4*32+10) /* Context ID */
#define X86_FEATURE_FMA		(4*32+12) /* Fused multiply-add */
#define X86_FEATURE_CX16	(4*32+13) /* CMPXCHG16B */
#define X86_FEATURE_XTPR	(4*32+14) /* Send Task Priority Messages */
#define X86_FEATURE_PDCM	(4*32+15) /* Performance Capabilities */
#define X86_FEATURE_PCID	(4*32+17) /* Process Context Identifiers */
#define X86_FEATURE_DCA		(4*32+18) /* Direct Cache Access */
#define X86_FEATURE_XMM4_1	(4*32+19) /* "sse4_1" SSE-4.1 */
#define X86_FEATURE_XMM4_2	(4*32+20) /* "sse4_2" SSE-4.2 */
#define X86_FEATURE_X2APIC	(4*32+21) /* x2APIC */
#define X86_FEATURE_MOVBE	(4*32+22) /* MOVBE instruction */
#define X86_FEATURE_POPCNT      (4*32+23) /* POPCNT instruction */
#define X86_FEATURE_TSC_DEADLINE_TIMER	(4*32+24) /* Tsc deadline timer */
#define X86_FEATURE_AES		(4*32+25) /* AES instructions */
#define X86_FEATURE_XSAVE	(4*32+26) /* XSAVE/XRSTOR/XSETBV/XGETBV */
#define X86_FEATURE_OSXSAVE	(4*32+27) /* "" XSAVE enabled in the OS */
#define X86_FEATURE_AVX		(4*32+28) /* Advanced Vector Extensions */
#define X86_FEATURE_F16C	(4*32+29) /* 16-bit fp conversions */
#define X86_FEATURE_RDRAND	(4*32+30) /* The RDRAND instruction */
#define X86_FEATURE_HYPERVISOR	(4*32+31) /* Running on a hypervisor */

/* VIA/Cyrix/Centaur-defined CPU features, CPUID level 0xC0000001, word 5 */
#define X86_FEATURE_XSTORE	(5*32+ 2) /* "rng" RNG present (xstore) */
#define X86_FEATURE_XSTORE_EN	(5*32+ 3) /* "rng_en" RNG enabled */
#define X86_FEATURE_XCRYPT	(5*32+ 6) /* "ace" on-CPU crypto (xcrypt) */
#define X86_FEATURE_XCRYPT_EN	(5*32+ 7) /* "ace_en" on-CPU crypto enabled */
#define X86_FEATURE_ACE2	(5*32+ 8) /* Advanced Cryptography Engine v2 */
#define X86_FEATURE_ACE2_EN	(5*32+ 9) /* ACE v2 enabled */
#define X86_FEATURE_PHE		(5*32+10) /* PadLock Hash Engine */
#define X86_FEATURE_PHE_EN	(5*32+11) /* PHE enabled */
#define X86_FEATURE_PMM		(5*32+12) /* PadLock Montgomery Multiplier */
#define X86_FEATURE_PMM_EN	(5*32+13) /* PMM enabled */

/* More extended AMD flags: CPUID level 0x80000001, ecx, word 6 */
#define X86_FEATURE_LAHF_LM	(6*32+ 0) /* LAHF/SAHF in long mode */
#define X86_FEATURE_CMP_LEGACY	(6*32+ 1) /* If yes HyperThreading not valid */
#define X86_FEATURE_SVM		(6*32+ 2) /* Secure virtual machine */
#define X86_FEATURE_EXTAPIC	(6*32+ 3) /* Extended APIC space */
#define X86_FEATURE_CR8_LEGACY	(6*32+ 4) /* CR8 in 32-bit mode */
#define X86_FEATURE_ABM		(6*32+ 5) /* Advanced bit manipulation */
#define X86_FEATURE_SSE4A	(6*32+ 6) /* SSE-4A */
#define X86_FEATURE_MISALIGNSSE (6*32+ 7) /* Misaligned SSE mode */
#define X86_FEATURE_3DNOWPREFETCH (6*32+ 8) /* 3DNow prefetch instructions */
#define X86_FEATURE_OSVW	(6*32+ 9) /* OS Visible Workaround */
#define X86_FEATURE_IBS		(6*32+10) /* Instruction Based Sampling */
#define X86_FEATURE_XOP		(6*32+11) /* extended AVX instructions */
#define X86_FEATURE_SKINIT	(6*32+12) /* SKINIT/STGI instructions */
#define X86_FEATURE_WDT		(6*32+13) /* Watchdog timer */
#define X86_FEATURE_LWP		(6*32+15) /* Light Weight Profiling */
#define X86_FEATURE_FMA4	(6*32+16) /* 4 operands MAC instructions */
#define X86_FEATURE_TCE		(6*32+17) /* translation cache extension */
#define X86_FEATURE_NODEID_MSR	(6*32+19) /* NodeId MSR */
#define X86_FEATURE_TBM		(6*32+21) /* trailing bit manipulations */
#define X86_FEATURE_TOPOEXT	(6*32+22) /* topology extensions CPUID leafs */
#define X86_FEATURE_PERFCTR_CORE (6*32+23) /* core performance counter extensions */

/*
 * Auxiliary flags: Linux defined - For features scattered in various
 * CPUID levels like 0x6, 0xA etc, word 7
 */
#define X86_FEATURE_IDA		(7*32+ 0) /* Intel Dynamic Acceleration */
#define X86_FEATURE_ARAT	(7*32+ 1) /* Always Running APIC Timer */
#define X86_FEATURE_CPB		(7*32+ 2) /* AMD Core Performance Boost */
#define X86_FEATURE_EPB		(7*32+ 3) /* IA32_ENERGY_PERF_BIAS support */
#define X86_FEATURE_XSAVEOPT	(7*32+ 4) /* Optimized Xsave */
#define X86_FEATURE_PLN		(7*32+ 5) /* Intel Power Limit Notification */
#define X86_FEATURE_PTS		(7*32+ 6) /* Intel Package Thermal Status */
#define X86_FEATURE_DTHERM	(7*32+ 7) /* Digital Thermal Sensor */
#define X86_FEATURE_HW_PSTATE	(7*32+ 8) /* AMD HW-PState */

/* Virtualization flags: Linux defined, word 8 */
#define X86_FEATURE_TPR_SHADOW  (8*32+ 0) /* Intel TPR Shadow */
#define X86_FEATURE_VNMI        (8*32+ 1) /* Intel Virtual NMI */
#define X86_FEATURE_FLEXPRIORITY (8*32+ 2) /* Intel FlexPriority */
#define X86_FEATURE_EPT         (8*32+ 3) /* Intel Extended Page Table */
#define X86_FEATURE_VPID        (8*32+ 4) /* Intel Virtual Processor ID */
#define X86_FEATURE_NPT		(8*32+ 5) /* AMD Nested Page Table support */
#define X86_FEATURE_LBRV	(8*32+ 6) /* AMD LBR Virtualization support */
#define X86_FEATURE_SVML	(8*32+ 7) /* "svm_lock" AMD SVM locking MSR */
#define X86_FEATURE_NRIPS	(8*32+ 8) /* "nrip_save" AMD SVM next_rip save */
#define X86_FEATURE_TSCRATEMSR  (8*32+ 9) /* "tsc_scale" AMD TSC scaling support */
#define X86_FEATURE_VMCBCLEAN   (8*32+10) /* "vmcb_clean" AMD VMCB clean bits support */
#define X86_FEATURE_FLUSHBYASID (8*32+11) /* AMD flush-by-ASID support */
#define X86_FEATURE_DECODEASSISTS (8*32+12) /* AMD Decode Assists support */
#define X86_FEATURE_PAUSEFILTER (8*32+13) /* AMD filtered pause intercept */
#define X86_FEATURE_PFTHRESHOLD (8*32+14) /* AMD pause filter threshold */


/* Intel-defined CPU features, CPUID level 0x00000007:0 (ebx), word 9 */
#define X86_FEATURE_FSGSBASE	(9*32+ 0) /* {RD/WR}{FS/GS}BASE instructions*/
#define X86_FEATURE_TSC_ADJUST	(9*32+ 1) /* TSC adjustment MSR 0x3b */
#define X86_FEATURE_BMI1	(9*32+ 3) /* 1st group bit manipulation extensions */
#define X86_FEATURE_HLE		(9*32+ 4) /* Hardware Lock Elision */
#define X86_FEATURE_AVX2	(9*32+ 5) /* AVX2 instructions */
#define X86_FEATURE_SMEP	(9*32+ 7) /* Supervisor Mode Execution Protection */
#define X86_FEATURE_BMI2	(9*32+ 8) /* 2nd group bit manipulation extensions */
#define X86_FEATURE_ERMS	(9*32+ 9) /* Enhanced REP MOVSB/STOSB */
#define X86_FEATURE_INVPCID	(9*32+10) /* Invalidate Processor Context ID */
#define X86_FEATURE_RTM		(9*32+11) /* Restricted Transactional Memory */
#define X86_FEATURE_RDSEED	(9*32+18) /* The RDSEED instruction */
#define X86_FEATURE_ADX		(9*32+19) /* The ADCX and ADOX instructions */
#define X86_FEATURE_SMAP	(9*32+20) /* Supervisor Mode Access Prevention */


/* CPU model specific register (MSR) numbers */

/* x86-64 specific MSRs */
#define MSR_EFER		0xc0000080 /* extended feature register */
#define MSR_STAR		0xc0000081 /* legacy mode SYSCALL target */
#define MSR_LSTAR		0xc0000082 /* long mode SYSCALL target */
#define MSR_CSTAR		0xc0000083 /* compat mode SYSCALL target */
#define MSR_SYSCALL_MASK	0xc0000084 /* EFLAGS mask for syscall */
#define MSR_FS_BASE		0xc0000100 /* 64bit FS base */
#define MSR_GS_BASE		0xc0000101 /* 64bit GS base */
#define MSR_KERNEL_GS_BASE	0xc0000102 /* SwapGS GS shadow */
#define MSR_TSC_AUX		0xc0000103 /* Auxiliary TSC */

/* EFER bits: */
#define _EFER_SCE		0  /* SYSCALL/SYSRET */
#define _EFER_LME		8  /* Long mode enable */
#define _EFER_LMA		10 /* Long mode active (read-only) */
#define _EFER_NX		11 /* No execute enable */
#define _EFER_SVME		12 /* Enable virtualization */
#define _EFER_LMSLE		13 /* Long Mode Segment Limit Enable */
#define _EFER_FFXSR		14 /* Enable Fast FXSAVE/FXRSTOR */

#define EFER_SCE		(1<<_EFER_SCE)
#define EFER_LME		(1<<_EFER_LME)
#define EFER_LMA		(1<<_EFER_LMA)
#define EFER_NX			(1<<_EFER_NX)
#define EFER_SVME		(1<<_EFER_SVME)
#define EFER_LMSLE		(1<<_EFER_LMSLE)
#define EFER_FFXSR		(1<<_EFER_FFXSR)

/* Intel MSRs. Some also available on other CPUs */
#define MSR_IA32_PERFCTR0		0x000000c1
#define MSR_IA32_PERFCTR1		0x000000c2
#define MSR_FSB_FREQ			0x000000cd

#define MSR_NHM_SNB_PKG_CST_CFG_CTL	0x000000e2
#define NHM_C3_AUTO_DEMOTE		(VMMR0_LPUL(1) << 25)
#define NHM_C1_AUTO_DEMOTE		(VMMR0_LPUL(1) << 26)
#define ATM_LNC_C6_AUTO_DEMOTE		(VMMR0_LPUL(1) << 25)

#define MSR_MTRRcap			0x000000fe
#define MSR_IA32_BBL_CR_CTL		0x00000119
#define MSR_IA32_BBL_CR_CTL3		0x0000011e

#define MSR_IA32_SYSENTER_CS		0x00000174
#define MSR_IA32_SYSENTER_ESP		0x00000175
#define MSR_IA32_SYSENTER_EIP		0x00000176

#define MSR_IA32_MCG_CAP		0x00000179
#define MSR_IA32_MCG_STATUS		0x0000017a
#define MSR_IA32_MCG_CTL		0x0000017b

#define MSR_OFFCORE_RSP_0		0x000001a6
#define MSR_OFFCORE_RSP_1		0x000001a7

#define MSR_IA32_PEBS_ENABLE		0x000003f1
#define MSR_IA32_DS_AREA		0x00000600
#define MSR_IA32_PERF_CAPABILITIES	0x00000345

#define MSR_MTRRfix64K_00000		0x00000250
#define MSR_MTRRfix16K_80000		0x00000258
#define MSR_MTRRfix16K_A0000		0x00000259
#define MSR_MTRRfix4K_C0000		0x00000268
#define MSR_MTRRfix4K_C8000		0x00000269
#define MSR_MTRRfix4K_D0000		0x0000026a
#define MSR_MTRRfix4K_D8000		0x0000026b
#define MSR_MTRRfix4K_E0000		0x0000026c
#define MSR_MTRRfix4K_E8000		0x0000026d
#define MSR_MTRRfix4K_F0000		0x0000026e
#define MSR_MTRRfix4K_F8000		0x0000026f
#define MSR_MTRRdefType			0x000002ff

#define MSR_IA32_CR_PAT			0x00000277

#define MSR_IA32_DEBUGCTLMSR		0x000001d9
#define MSR_IA32_LASTBRANCHFROMIP	0x000001db
#define MSR_IA32_LASTBRANCHTOIP		0x000001dc
#define MSR_IA32_LASTINTFROMIP		0x000001dd
#define MSR_IA32_LASTINTTOIP		0x000001de

/* DEBUGCTLMSR bits (others vary by model): */
#define DEBUGCTLMSR_LBR			(VMMR0_LPUL(1) <<  0) /* last branch recording */
#define DEBUGCTLMSR_BTF			(VMMR0_LPUL(1) <<  1) /* single-step on branches */
#define DEBUGCTLMSR_TR			(VMMR0_LPUL(1) <<  6)
#define DEBUGCTLMSR_BTS			(VMMR0_LPUL(1) <<  7)
#define DEBUGCTLMSR_BTINT		(VMMR0_LPUL(1) <<  8)
#define DEBUGCTLMSR_BTS_OFF_OS		(VMMR0_LPUL(1) <<  9)
#define DEBUGCTLMSR_BTS_OFF_USR		(VMMR0_LPUL(1) << 10)
#define DEBUGCTLMSR_FREEZE_LBRS_ON_PMI	(VMMR0_LPUL(1) << 11)

#define MSR_IA32_MC0_CTL		0x00000400
#define MSR_IA32_MC0_STATUS		0x00000401
#define MSR_IA32_MC0_ADDR		0x00000402
#define MSR_IA32_MC0_MISC		0x00000403

#define MSR_AMD64_MC0_MASK		0xc0010044

#define MSR_IA32_MCx_CTL(x)		(MSR_IA32_MC0_CTL + 4*(x))
#define MSR_IA32_MCx_STATUS(x)		(MSR_IA32_MC0_STATUS + 4*(x))
#define MSR_IA32_MCx_ADDR(x)		(MSR_IA32_MC0_ADDR + 4*(x))
#define MSR_IA32_MCx_MISC(x)		(MSR_IA32_MC0_MISC + 4*(x))

#define MSR_AMD64_MCx_MASK(x)		(MSR_AMD64_MC0_MASK + (x))

/* These are consecutive and not in the normal 4er MCE bank block */
#define MSR_IA32_MC0_CTL2		0x00000280
#define MSR_IA32_MCx_CTL2(x)		(MSR_IA32_MC0_CTL2 + (x))

#define MSR_P6_PERFCTR0			0x000000c1
#define MSR_P6_PERFCTR1			0x000000c2
#define MSR_P6_EVNTSEL0			0x00000186
#define MSR_P6_EVNTSEL1			0x00000187

/* AMD64 MSRs. Not complete. See the architecture manual for a more
   complete list. */

#define MSR_AMD64_PATCH_LEVEL		0x0000008b
#define MSR_AMD64_TSC_RATIO		0xc0000104
#define MSR_AMD64_NB_CFG		0xc001001f
#define MSR_AMD64_PATCH_LOADER		0xc0010020
#define MSR_AMD64_OSVW_ID_LENGTH	0xc0010140
#define MSR_AMD64_OSVW_STATUS		0xc0010141
#define MSR_AMD64_DC_CFG		0xc0011022
#define MSR_AMD64_IBSFETCHCTL		0xc0011030
#define MSR_AMD64_IBSFETCHLINAD		0xc0011031
#define MSR_AMD64_IBSFETCHPHYSAD	0xc0011032
#define MSR_AMD64_IBSOPCTL		0xc0011033
#define MSR_AMD64_IBSOPRIP		0xc0011034
#define MSR_AMD64_IBSOPDATA		0xc0011035
#define MSR_AMD64_IBSOPDATA2		0xc0011036
#define MSR_AMD64_IBSOPDATA3		0xc0011037
#define MSR_AMD64_IBSDCLINAD		0xc0011038
#define MSR_AMD64_IBSDCPHYSAD		0xc0011039
#define MSR_AMD64_IBSCTL		0xc001103a
#define MSR_AMD64_IBSBRTARGET		0xc001103b

/* Fam 15h MSRs */
#define MSR_F15H_PERF_CTL		0xc0010200
#define MSR_F15H_PERF_CTR		0xc0010201

/* Fam 10h MSRs */
#define MSR_FAM10H_MMIO_CONF_BASE	0xc0010058
#define FAM10H_MMIO_CONF_ENABLE		(1<<0)
#define FAM10H_MMIO_CONF_BUSRANGE_MASK	0xf
#define FAM10H_MMIO_CONF_BUSRANGE_SHIFT 2
#define FAM10H_MMIO_CONF_BASE_MASK	VMMR0_LPULL(0xfffffff)
#define FAM10H_MMIO_CONF_BASE_SHIFT	20
#define MSR_FAM10H_NODE_ID		0xc001100c

/* K8 MSRs */
#define MSR_K8_TOP_MEM1			0xc001001a
#define MSR_K8_TOP_MEM2			0xc001001d
#define MSR_K8_SYSCFG			0xc0010010
#define MSR_K8_INT_PENDING_MSG		0xc0010055
/* C1E active bits in int pending message */
#define K8_INTP_C1E_ACTIVE_MASK		0x18000000
#define MSR_K8_TSEG_ADDR		0xc0010112
#define K8_MTRRFIXRANGE_DRAM_ENABLE	0x00040000 /* MtrrFixDramEn bit    */
#define K8_MTRRFIXRANGE_DRAM_MODIFY	0x00080000 /* MtrrFixDramModEn bit */
#define K8_MTRR_RDMEM_WRMEM_MASK	0x18181818 /* Mask: RdMem|WrMem    */

/* K7 MSRs */
#define MSR_K7_EVNTSEL0			0xc0010000
#define MSR_K7_PERFCTR0			0xc0010004
#define MSR_K7_EVNTSEL1			0xc0010001
#define MSR_K7_PERFCTR1			0xc0010005
#define MSR_K7_EVNTSEL2			0xc0010002
#define MSR_K7_PERFCTR2			0xc0010006
#define MSR_K7_EVNTSEL3			0xc0010003
#define MSR_K7_PERFCTR3			0xc0010007
#define MSR_K7_CLK_CTL			0xc001001b
#define MSR_K7_HWCR			0xc0010015
#define MSR_K7_FID_VID_CTL		0xc0010041
#define MSR_K7_FID_VID_STATUS		0xc0010042

/* K6 MSRs */
#define MSR_K6_WHCR			0xc0000082
#define MSR_K6_UWCCR			0xc0000085
#define MSR_K6_EPMR			0xc0000086
#define MSR_K6_PSOR			0xc0000087
#define MSR_K6_PFIR			0xc0000088

/* Centaur-Hauls/IDT defined MSRs. */
#define MSR_IDT_FCR1			0x00000107
#define MSR_IDT_FCR2			0x00000108
#define MSR_IDT_FCR3			0x00000109
#define MSR_IDT_FCR4			0x0000010a

#define MSR_IDT_MCR0			0x00000110
#define MSR_IDT_MCR1			0x00000111
#define MSR_IDT_MCR2			0x00000112
#define MSR_IDT_MCR3			0x00000113
#define MSR_IDT_MCR4			0x00000114
#define MSR_IDT_MCR5			0x00000115
#define MSR_IDT_MCR6			0x00000116
#define MSR_IDT_MCR7			0x00000117
#define MSR_IDT_MCR_CTRL		0x00000120

/* VIA Cyrix defined MSRs*/
#define MSR_VIA_FCR			0x00001107
#define MSR_VIA_LONGHAUL		0x0000110a
#define MSR_VIA_RNG			0x0000110b
#define MSR_VIA_BCR2			0x00001147

/* Transmeta defined MSRs */
#define MSR_TMTA_LONGRUN_CTRL		0x80868010
#define MSR_TMTA_LONGRUN_FLAGS		0x80868011
#define MSR_TMTA_LRTI_READOUT		0x80868018
#define MSR_TMTA_LRTI_VOLT_MHZ		0x8086801a

/* Intel defined MSRs. */
#define MSR_IA32_P5_MC_ADDR		0x00000000
#define MSR_IA32_P5_MC_TYPE		0x00000001
#define MSR_IA32_TSC			0x00000010
#define MSR_IA32_PLATFORM_ID		0x00000017
#define MSR_IA32_EBL_CR_POWERON		0x0000002a
#define MSR_EBC_FREQUENCY_ID		0x0000002c
#define MSR_IA32_FEATURE_CONTROL        0x0000003a

#define FEATURE_CONTROL_LOCKED				(1<<0)
#define FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX	(1<<1)
#define FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX	(1<<2)

#define MSR_IA32_APICBASE		0x0000001b
#define MSR_IA32_APICBASE_BSP		(1<<8)
#define MSR_IA32_APICBASE_ENABLE	(1<<11)
#define MSR_IA32_APICBASE_BASE		(0xfffff<<12)

#define MSR_IA32_TSCDEADLINE		0x000006e0

#define MSR_IA32_UCODE_WRITE		0x00000079
#define MSR_IA32_UCODE_REV		0x0000008b

#define MSR_IA32_PERF_STATUS		0x00000198
#define MSR_IA32_PERF_CTL		0x00000199

#define MSR_IA32_MPERF			0x000000e7
#define MSR_IA32_APERF			0x000000e8

#define MSR_IA32_THERM_CONTROL		0x0000019a
#define MSR_IA32_THERM_INTERRUPT	0x0000019b

#define THERM_INT_HIGH_ENABLE		(1 << 0)
#define THERM_INT_LOW_ENABLE		(1 << 1)
#define THERM_INT_PLN_ENABLE		(1 << 24)

#define MSR_IA32_THERM_STATUS		0x0000019c

#define THERM_STATUS_PROCHOT		(1 << 0)
#define THERM_STATUS_POWER_LIMIT	(1 << 10)

#define MSR_THERM2_CTL			0x0000019d

#define MSR_THERM2_CTL_TM_SELECT	(VMMR0_LPULL(1) << 16)

#define MSR_IA32_MISC_ENABLE		0x000001a0

#define MSR_IA32_TEMPERATURE_TARGET	0x000001a2

#define MSR_IA32_ENERGY_PERF_BIAS	0x000001b0
#define ENERGY_PERF_BIAS_PERFORMANCE	0
#define ENERGY_PERF_BIAS_NORMAL		6
#define ENERGY_PERF_BIAS_POWERSAVE	15

#define MSR_IA32_PACKAGE_THERM_STATUS		0x000001b1

#define PACKAGE_THERM_STATUS_PROCHOT		(1 << 0)
#define PACKAGE_THERM_STATUS_POWER_LIMIT	(1 << 10)

#define MSR_IA32_PACKAGE_THERM_INTERRUPT	0x000001b2

#define PACKAGE_THERM_INT_HIGH_ENABLE		(1 << 0)
#define PACKAGE_THERM_INT_LOW_ENABLE		(1 << 1)
#define PACKAGE_THERM_INT_PLN_ENABLE		(1 << 24)

/* Thermal Thresholds Support */
#define THERM_INT_THRESHOLD0_ENABLE    (1 << 15)
#define THERM_SHIFT_THRESHOLD0        8
#define THERM_MASK_THRESHOLD0          (0x7f << THERM_SHIFT_THRESHOLD0)
#define THERM_INT_THRESHOLD1_ENABLE    (1 << 23)
#define THERM_SHIFT_THRESHOLD1        16
#define THERM_MASK_THRESHOLD1          (0x7f << THERM_SHIFT_THRESHOLD1)
#define THERM_STATUS_THRESHOLD0        (1 << 6)
#define THERM_LOG_THRESHOLD0           (1 << 7)
#define THERM_STATUS_THRESHOLD1        (1 << 8)
#define THERM_LOG_THRESHOLD1           (1 << 9)

/* MISC_ENABLE bits: architectural */
#define MSR_IA32_MISC_ENABLE_FAST_STRING	(VMMR0_LPULL(1) << 0)
#define MSR_IA32_MISC_ENABLE_TCC		(VMMR0_LPULL(1) << 1)
#define MSR_IA32_MISC_ENABLE_EMON		(VMMR0_LPULL(1) << 7)
#define MSR_IA32_MISC_ENABLE_BTS_UNAVAIL	(VMMR0_LPULL(1) << 11)
#define MSR_IA32_MISC_ENABLE_PEBS_UNAVAIL	(VMMR0_LPULL(1) << 12)
#define MSR_IA32_MISC_ENABLE_ENHANCED_SPEEDSTEP	(VMMR0_LPULL(1) << 16)
#define MSR_IA32_MISC_ENABLE_MWAIT		(VMMR0_LPULL(1) << 18)
#define MSR_IA32_MISC_ENABLE_LIMIT_CPUID	(VMMR0_LPULL(1) << 22)
#define MSR_IA32_MISC_ENABLE_XTPR_DISABLE	(VMMR0_LPULL(1) << 23)
#define MSR_IA32_MISC_ENABLE_XD_DISABLE		(VMMR0_LPULL(1) << 34)

/* MISC_ENABLE bits: model-specific, meaning may vary from core to core */
#define MSR_IA32_MISC_ENABLE_X87_COMPAT		(VMMR0_LPULL(1) << 2)
#define MSR_IA32_MISC_ENABLE_TM1		(VMMR0_LPULL(1) << 3)
#define MSR_IA32_MISC_ENABLE_SPLIT_LOCK_DISABLE	(VMMR0_LPULL(1) << 4)
#define MSR_IA32_MISC_ENABLE_L3CACHE_DISABLE	(VMMR0_LPULL(1) << 6)
#define MSR_IA32_MISC_ENABLE_SUPPRESS_LOCK	(VMMR0_LPULL(1) << 8)
#define MSR_IA32_MISC_ENABLE_PREFETCH_DISABLE	(VMMR0_LPULL(1) << 9)
#define MSR_IA32_MISC_ENABLE_FERR		(VMMR0_LPULL(1) << 10)
#define MSR_IA32_MISC_ENABLE_FERR_MULTIPLEX	(VMMR0_LPULL(1) << 10)
#define MSR_IA32_MISC_ENABLE_TM2		(VMMR0_LPULL(1) << 13)
#define MSR_IA32_MISC_ENABLE_ADJ_PREF_DISABLE	(VMMR0_LPULL(1) << 19)
#define MSR_IA32_MISC_ENABLE_SPEEDSTEP_LOCK	(VMMR0_LPULL(1) << 20)
#define MSR_IA32_MISC_ENABLE_L1D_CONTEXT	(VMMR0_LPULL(1) << 24)
#define MSR_IA32_MISC_ENABLE_DCU_PREF_DISABLE	(VMMR0_LPULL(1) << 37)
#define MSR_IA32_MISC_ENABLE_TURBO_DISABLE	(VMMR0_LPULL(1) << 38)
#define MSR_IA32_MISC_ENABLE_IP_PREF_DISABLE	(VMMR0_LPULL(1) << 39)

/* P4/Xeon+ specific */
#define MSR_IA32_MCG_EAX		0x00000180
#define MSR_IA32_MCG_EBX		0x00000181
#define MSR_IA32_MCG_ECX		0x00000182
#define MSR_IA32_MCG_EDX		0x00000183
#define MSR_IA32_MCG_ESI		0x00000184
#define MSR_IA32_MCG_EDI		0x00000185
#define MSR_IA32_MCG_EBP		0x00000186
#define MSR_IA32_MCG_ESP		0x00000187
#define MSR_IA32_MCG_EFLAGS		0x00000188
#define MSR_IA32_MCG_EIP		0x00000189
#define MSR_IA32_MCG_RESERVED		0x0000018a

/* Pentium IV performance counter MSRs */
#define MSR_P4_BPU_PERFCTR0		0x00000300
#define MSR_P4_BPU_PERFCTR1		0x00000301
#define MSR_P4_BPU_PERFCTR2		0x00000302
#define MSR_P4_BPU_PERFCTR3		0x00000303
#define MSR_P4_MS_PERFCTR0		0x00000304
#define MSR_P4_MS_PERFCTR1		0x00000305
#define MSR_P4_MS_PERFCTR2		0x00000306
#define MSR_P4_MS_PERFCTR3		0x00000307
#define MSR_P4_FLAME_PERFCTR0		0x00000308
#define MSR_P4_FLAME_PERFCTR1		0x00000309
#define MSR_P4_FLAME_PERFCTR2		0x0000030a
#define MSR_P4_FLAME_PERFCTR3		0x0000030b
#define MSR_P4_IQ_PERFCTR0		0x0000030c
#define MSR_P4_IQ_PERFCTR1		0x0000030d
#define MSR_P4_IQ_PERFCTR2		0x0000030e
#define MSR_P4_IQ_PERFCTR3		0x0000030f
#define MSR_P4_IQ_PERFCTR4		0x00000310
#define MSR_P4_IQ_PERFCTR5		0x00000311
#define MSR_P4_BPU_CCCR0		0x00000360
#define MSR_P4_BPU_CCCR1		0x00000361
#define MSR_P4_BPU_CCCR2		0x00000362
#define MSR_P4_BPU_CCCR3		0x00000363
#define MSR_P4_MS_CCCR0			0x00000364
#define MSR_P4_MS_CCCR1			0x00000365
#define MSR_P4_MS_CCCR2			0x00000366
#define MSR_P4_MS_CCCR3			0x00000367
#define MSR_P4_FLAME_CCCR0		0x00000368
#define MSR_P4_FLAME_CCCR1		0x00000369
#define MSR_P4_FLAME_CCCR2		0x0000036a
#define MSR_P4_FLAME_CCCR3		0x0000036b
#define MSR_P4_IQ_CCCR0			0x0000036c
#define MSR_P4_IQ_CCCR1			0x0000036d
#define MSR_P4_IQ_CCCR2			0x0000036e
#define MSR_P4_IQ_CCCR3			0x0000036f
#define MSR_P4_IQ_CCCR4			0x00000370
#define MSR_P4_IQ_CCCR5			0x00000371
#define MSR_P4_ALF_ESCR0		0x000003ca
#define MSR_P4_ALF_ESCR1		0x000003cb
#define MSR_P4_BPU_ESCR0		0x000003b2
#define MSR_P4_BPU_ESCR1		0x000003b3
#define MSR_P4_BSU_ESCR0		0x000003a0
#define MSR_P4_BSU_ESCR1		0x000003a1
#define MSR_P4_CRU_ESCR0		0x000003b8
#define MSR_P4_CRU_ESCR1		0x000003b9
#define MSR_P4_CRU_ESCR2		0x000003cc
#define MSR_P4_CRU_ESCR3		0x000003cd
#define MSR_P4_CRU_ESCR4		0x000003e0
#define MSR_P4_CRU_ESCR5		0x000003e1
#define MSR_P4_DAC_ESCR0		0x000003a8
#define MSR_P4_DAC_ESCR1		0x000003a9
#define MSR_P4_FIRM_ESCR0		0x000003a4
#define MSR_P4_FIRM_ESCR1		0x000003a5
#define MSR_P4_FLAME_ESCR0		0x000003a6
#define MSR_P4_FLAME_ESCR1		0x000003a7
#define MSR_P4_FSB_ESCR0		0x000003a2
#define MSR_P4_FSB_ESCR1		0x000003a3
#define MSR_P4_IQ_ESCR0			0x000003ba
#define MSR_P4_IQ_ESCR1			0x000003bb
#define MSR_P4_IS_ESCR0			0x000003b4
#define MSR_P4_IS_ESCR1			0x000003b5
#define MSR_P4_ITLB_ESCR0		0x000003b6
#define MSR_P4_ITLB_ESCR1		0x000003b7
#define MSR_P4_IX_ESCR0			0x000003c8
#define MSR_P4_IX_ESCR1			0x000003c9
#define MSR_P4_MOB_ESCR0		0x000003aa
#define MSR_P4_MOB_ESCR1		0x000003ab
#define MSR_P4_MS_ESCR0			0x000003c0
#define MSR_P4_MS_ESCR1			0x000003c1
#define MSR_P4_PMH_ESCR0		0x000003ac
#define MSR_P4_PMH_ESCR1		0x000003ad
#define MSR_P4_RAT_ESCR0		0x000003bc
#define MSR_P4_RAT_ESCR1		0x000003bd
#define MSR_P4_SAAT_ESCR0		0x000003ae
#define MSR_P4_SAAT_ESCR1		0x000003af
#define MSR_P4_SSU_ESCR0		0x000003be
#define MSR_P4_SSU_ESCR1		0x000003bf /* guess: not in manual */

#define MSR_P4_TBPU_ESCR0		0x000003c2
#define MSR_P4_TBPU_ESCR1		0x000003c3
#define MSR_P4_TC_ESCR0			0x000003c4
#define MSR_P4_TC_ESCR1			0x000003c5
#define MSR_P4_U2L_ESCR0		0x000003b0
#define MSR_P4_U2L_ESCR1		0x000003b1

#define MSR_P4_PEBS_MATRIX_VERT		0x000003f2

/* Intel Core-based CPU performance counters */
#define MSR_CORE_PERF_FIXED_CTR0	0x00000309
#define MSR_CORE_PERF_FIXED_CTR1	0x0000030a
#define MSR_CORE_PERF_FIXED_CTR2	0x0000030b
#define MSR_CORE_PERF_FIXED_CTR_CTRL	0x0000038d
#define MSR_CORE_PERF_GLOBAL_STATUS	0x0000038e
#define MSR_CORE_PERF_GLOBAL_CTRL	0x0000038f
#define MSR_CORE_PERF_GLOBAL_OVF_CTRL	0x00000390

/* Geode defined MSRs */
#define MSR_GEODE_BUSCONT_CONF0		0x00001900

/* Intel VT MSRs */
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
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS  0x0000048d
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS 0x0000048e
#define MSR_IA32_VMX_TRUE_EXIT_CTLS      0x0000048f
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS     0x00000490

/* VMX_BASIC bits and bitmasks */
#define VMX_BASIC_VMCS_SIZE_SHIFT	32
#define VMX_BASIC_64		0x0001000000000000LLU
#define VMX_BASIC_MEM_TYPE_SHIFT	50
#define VMX_BASIC_MEM_TYPE_MASK	0x003c000000000000LLU
#define VMX_BASIC_MEM_TYPE_WB	6LLU
#define VMX_BASIC_INOUT		0x0040000000000000LLU

/* AMD-V MSRs */

#define MSR_VM_CR                       0xc0010114
#define MSR_VM_IGNNE                    0xc0010115
#define MSR_VM_HSAVE_PA                 0xc0010117

#define XCR_XFEATURE_ENABLED_MASK	0x00000000

#ifndef CONFIG_MATH_EMULATION
# define NEED_FPU	(1<<(X86_FEATURE_FPU & 31))
#else
# define NEED_FPU	0
#endif

#if defined(CONFIG_X86_PAE) || defined(CONFIG_X86_64)
# define NEED_PAE	(1<<(X86_FEATURE_PAE & 31))
#else
# define NEED_PAE	0
#endif

# define NEED_CX8	(1<<(X86_FEATURE_CX8 & 31))

#if defined(CONFIG_X86_CMOV) || defined(CONFIG_X86_64)
# define NEED_CMOV	(1<<(X86_FEATURE_CMOV & 31))
#else
# define NEED_CMOV	0
#endif

# define NEED_3DNOW	(1<<(X86_FEATURE_3DNOW & 31))

#if defined(CONFIG_X86_P6_NOP) || defined(CONFIG_X86_64)
# define NEED_NOPL	(1<<(X86_FEATURE_NOPL & 31))
#else
# define NEED_NOPL	0
#endif

#ifdef CONFIG_X86_64
#define NEED_PSE	(1<<(X86_FEATURE_PSE) & 31)
#define NEED_PGE	(1<<(X86_FEATURE_PGE) & 31)
#define NEED_MSR	(1<<(X86_FEATURE_MSR & 31))
#define NEED_FXSR	(1<<(X86_FEATURE_FXSR & 31))
#define NEED_XMM	(1<<(X86_FEATURE_XMM & 31))
#define NEED_XMM2	(1<<(X86_FEATURE_XMM2 & 31))
#define NEED_LM		(1<<(X86_FEATURE_LM & 31))
#else
#define NEED_PSE	0
#define NEED_MSR	0
#define NEED_PGE	0
#define NEED_FXSR	0
#define NEED_XMM	0
#define NEED_XMM2	0
#define NEED_LM		0
#endif

#define REQUIRED_MASK0	(NEED_FPU|NEED_PSE|NEED_MSR|NEED_PAE|\
			 NEED_CX8|NEED_PGE|NEED_FXSR|NEED_CMOV|\
			 NEED_XMM|NEED_XMM2)
#define SSE_MASK	(NEED_XMM|NEED_XMM2)

#define REQUIRED_MASK1	(NEED_LM|NEED_3DNOW)

#define REQUIRED_MASK2	0
#define REQUIRED_MASK3	(NEED_NOPL)
#define REQUIRED_MASK4	0
#define REQUIRED_MASK5	0
#define REQUIRED_MASK6	0
#define REQUIRED_MASK7	0
#define REQUIRED_MASK8	0
#define REQUIRED_MASK9	0

struct cpuinfo_x86 {
	__u8			x86;		/* CPU family */
	__u8			x86_vendor;	/* CPU vendor */
	__u8			x86_model;
	__u8			x86_mask;
#ifdef CONFIG_X86_32
	char			wp_works_ok;	/* It doesn't on 386's */

	/* Problems on some 486Dx4's and old 386's: */
	char			hlt_works_ok;
	char			hard_math;
	char			rfu;
	char			fdiv_bug;
	char			f00f_bug;
	char			coma_bug;
	char			pad0;
#else
	/* Number of 4K pages in DTLB/ITLB combined(in pages): */
	int			x86_tlbsize;
#endif
	__u8			x86_virt_bits;
	__u8			x86_phys_bits;
	/* CPUID returned core id bits: */
	__u8			x86_coreid_bits;
	/* Max extended CPUID function supported: */
	__u32			extended_cpuid_level;
	/* Maximum supported CPUID level, -1=no CPUID: */
	int			cpuid_level;
	__u32			x86_capability[NCAPINTS];
	char			x86_vendor_id[16];
	char			x86_model_id[64];
	/* in KB - valid for CPUS which support this call: */
	int			x86_cache_size;
	int			x86_cache_alignment;	/* In bytes */
	int			x86_power;
	unsigned long		loops_per_jiffy;
	/* cpuid returned max cores value: */
	u16			 x86_max_cores;
	u16			apicid;
	u16			initial_apicid;
	u16			x86_clflush_size;
	/* number of cores as seen by the OS: */
	u16			booted_cores;
	/* Physical processor id: */
	u16			phys_proc_id;
	/* Core id: */
	u16			cpu_core_id;
	/* Compute unit id */
	u8			compute_unit_id;
	/* Index into per_cpu list: */
	u16			cpu_index;
	u32			microcode;
};

#define X86_VENDOR_INTEL	0
#define X86_VENDOR_CYRIX	1
#define X86_VENDOR_AMD		2
#define X86_VENDOR_UMC		3
#define X86_VENDOR_CENTAUR	5
#define X86_VENDOR_TRANSMETA	7
#define X86_VENDOR_NSC		8
#define X86_VENDOR_NUM		9

#define X86_VENDOR_UNKNOWN	0xff

extern struct cpuinfo_x86	boot_cpu_data;

#define set_cpu_cap(c, bit)	set_bit(bit, (unsigned long *)((c)->x86_capability))
#define clear_cpu_cap(c, bit)	clear_bit(bit, (unsigned long *)((c)->x86_capability))
#define test_cpu_cap(c, bit)						\
	 test_bit(bit, (unsigned long *)((c)->x86_capability))

#define REQUIRED_MASK_BIT_SET(bit)					\
	 ( (((bit)>>5)==0 && (VMMR0_LPUL(1)<<((bit)&31) & REQUIRED_MASK0)) ||	\
	   (((bit)>>5)==1 && (VMMR0_LPUL(1)<<((bit)&31) & REQUIRED_MASK1)) ||	\
	   (((bit)>>5)==2 && (VMMR0_LPUL(1)<<((bit)&31) & REQUIRED_MASK2)) ||	\
	   (((bit)>>5)==3 && (VMMR0_LPUL(1)<<((bit)&31) & REQUIRED_MASK3)) ||	\
	   (((bit)>>5)==4 && (VMMR0_LPUL(1)<<((bit)&31) & REQUIRED_MASK4)) ||	\
	   (((bit)>>5)==5 && (VMMR0_LPUL(1)<<((bit)&31) & REQUIRED_MASK5)) ||	\
	   (((bit)>>5)==6 && (VMMR0_LPUL(1)<<((bit)&31) & REQUIRED_MASK6)) ||	\
	   (((bit)>>5)==7 && (VMMR0_LPUL(1)<<((bit)&31) & REQUIRED_MASK7)) ||	\
	   (((bit)>>5)==8 && (VMMR0_LPUL(1)<<((bit)&31) & REQUIRED_MASK8)) ||	\
	   (((bit)>>5)==9 && (VMMR0_LPUL(1)<<((bit)&31) & REQUIRED_MASK9)) )

#define cpu_has(c, bit)							\
	(__builtin_constant_p(bit) && REQUIRED_MASK_BIT_SET(bit) ? 1 :	\
	 test_cpu_cap(c, bit))

#define boot_cpu_has(bit)	cpu_has(&boot_cpu_data, bit)

#endif /* CPU_FEATURES_H_ */
