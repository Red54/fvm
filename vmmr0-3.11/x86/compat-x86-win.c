/*
 * compat-x86-win.c
 *
 * host compatible code for windows on x86 arch.
 *
 * authors : 
 *     范文一 （Wincy Van） <fanwenyi0529@live.com> <QQ:362478911>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

unsigned int vmmr0_xstate_size;
struct cpuinfo_x86	boot_cpu_data;

void vmmr0_xstate_size_init(void)
{
	unsigned int eax, ebx, ecx, edx;

	/*  vmmr0 only uses xstate_size if xsave is supported */
	if (cpu_has_xsave)
	{
		cpuid_count(0xd, 0, &eax, &ebx, &ecx, &edx);
		vmmr0_xstate_size = ebx;
		BUG_ON(vmmr0_xstate_size > sizeof(union vmmr0_thread_xstate));
	}
}


const int vmmr0_amd_erratum_383[] =
	AMD_OSVW_ERRATUM(3, AMD_MODEL_RANGE(0x10, 0, 0, 0xff, 0xf));


#ifdef CONFIG_KVM_GUEST

void vmmr0_async_pf_task_wait(u32 token)
{
	BUG();
}

void vmmr0_async_pf_task_wake(u32 token)
{
	BUG();
}

u32 vmmr0_read_and_reset_pf_reason(void)
{
	return 0;
}
#endif

#ifndef SVM_CPUID_FUNC
#define SVM_CPUID_FUNC 0x8000000a
#endif

#define SVM_FEATURE_NPT            (1 <<  0)
#define SVM_FEATURE_LBRV           (1 <<  1)
#define SVM_FEATURE_NRIP           (1 <<  3)
#define SVM_FEATURE_FLUSH_ASID     (1 <<  6)
#define SVM_FEATURE_DECODE_ASSIST  (1 <<  7)
#define SVM_FEATURE_PAUSE_FILTER   (1 << 10)

bool vmmr0_boot_cpu_has(unsigned int bit)
{
	static u32 svm_features;
	static bool initialized;

	if (!initialized)
	{
		svm_features = cpuid_edx(SVM_CPUID_FUNC);
		initialized = true;
	}
	switch (bit)
	{
	case X86_FEATURE_NPT:
		return svm_features & SVM_FEATURE_NPT;
	case X86_FEATURE_LBRV:
		return svm_features & SVM_FEATURE_LBRV;
	case X86_FEATURE_NRIPS:
		return svm_features & SVM_FEATURE_NRIP;
	case X86_FEATURE_FLUSHBYASID:
		return svm_features & SVM_FEATURE_FLUSH_ASID;
	case X86_FEATURE_DECODEASSISTS:
		return svm_features & SVM_FEATURE_DECODE_ASSIST;
	case X86_FEATURE_PAUSEFILTER:
		return svm_features & SVM_FEATURE_PAUSE_FILTER;
	default:
		return boot_cpu_has(bit);
	}
}

struct cpu_model_info
{
	int		vendor;
	int		family;
	const char	*model_names[16];
};

/* attempt to consolidate cpu attributes */
struct cpu_dev
{
	const char	*c_vendor;
	/* some have two possibilities for cpuid string */
	const char	*c_ident[2];
	struct		cpu_model_info c_models[4];
	int		    c_x86_vendor;
};

static const struct cpu_dev default_cpu =
{
	.c_vendor	= "Unknown",
	.c_x86_vendor	= X86_VENDOR_UNKNOWN,
};

static const struct cpu_dev intel_cpu_dev = {
	.c_vendor	= "Intel",
	.c_ident	= { "GenuineIntel" },
#ifdef CONFIG_X86_32
	.c_models = {
		{ .vendor = X86_VENDOR_INTEL, .family = 4, .model_names =
		  {
			  [0] = "486 DX-25/33",
			  [1] = "486 DX-50",
			  [2] = "486 SX",
			  [3] = "486 DX/2",
			  [4] = "486 SL",
			  [5] = "486 SX/2",
			  [7] = "486 DX/2-WB",
			  [8] = "486 DX/4",
			  [9] = "486 DX/4-WB"
		  }
		},
		{ .vendor = X86_VENDOR_INTEL, .family = 5, .model_names =
		  {
			  [0] = "Pentium 60/66 A-step",
			  [1] = "Pentium 60/66",
			  [2] = "Pentium 75 - 200",
			  [3] = "OverDrive PODP5V83",
			  [4] = "Pentium MMX",
			  [7] = "Mobile Pentium 75 - 200",
			  [8] = "Mobile Pentium MMX"
		  }
		},
		{ .vendor = X86_VENDOR_INTEL, .family = 6, .model_names =
		  {
			  [0] = "Pentium Pro A-step",
			  [1] = "Pentium Pro",
			  [3] = "Pentium II (Klamath)",
			  [4] = "Pentium II (Deschutes)",
			  [5] = "Pentium II (Deschutes)",
			  [6] = "Mobile Pentium II",
			  [7] = "Pentium III (Katmai)",
			  [8] = "Pentium III (Coppermine)",
			  [10] = "Pentium III (Cascades)",
			  [11] = "Pentium III (Tualatin)",
		  }
		},
		{ .vendor = X86_VENDOR_INTEL, .family = 15, .model_names =
		  {
			  [0] = "Pentium 4 (Unknown)",
			  [1] = "Pentium 4 (Willamette)",
			  [2] = "Pentium 4 (Northwood)",
			  [4] = "Pentium 4 (Foster)",
			  [5] = "Pentium 4 (Foster)",
		  }
		},
	},
#endif
	.c_x86_vendor	= X86_VENDOR_INTEL,
};

static const struct cpu_dev cyrix_cpu_dev =
{
	.c_vendor	= "Cyrix",
	.c_ident	= { "CyrixInstead" },
	.c_x86_vendor	= X86_VENDOR_CYRIX,
};

static const struct cpu_dev amd_cpu_dev = {
	.c_vendor	= "AMD",
	.c_ident	= { "AuthenticAMD" },
#ifdef CONFIG_X86_32
	.c_models = {
		{ .vendor = X86_VENDOR_AMD, .family = 4, .model_names =
		  {
			  [3] = "486 DX/2",
			  [7] = "486 DX/2-WB",
			  [8] = "486 DX/4",
			  [9] = "486 DX/4-WB",
			  [14] = "Am5x86-WT",
			  [15] = "Am5x86-WB"
		  }
		},
	},
#endif
	.c_x86_vendor	= X86_VENDOR_AMD,
};

static const struct cpu_dev umc_cpu_dev =
{
	.c_vendor	= "UMC",
	.c_ident	= { "UMC UMC UMC" },
	.c_models = {
		{ .vendor = X86_VENDOR_UMC, .family = 4, .model_names =
		  {
			  [1] = "U5D",
			  [2] = "U5S",
		  }
		},
	},
	.c_x86_vendor	= X86_VENDOR_UMC,
};

static const struct cpu_dev centaur_cpu_dev =
{
	.c_vendor	= "Centaur",
	.c_ident	= { "CentaurHauls" },
	.c_x86_vendor	= X86_VENDOR_CENTAUR,
};

static const struct cpu_dev transmeta_cpu_dev =
{
	.c_vendor	= "Transmeta",
	.c_ident	= { "GenuineTMx86", "TransmetaCPU" },
	.c_x86_vendor	= X86_VENDOR_TRANSMETA,
};

static const struct cpu_dev nsc_cpu_dev =
{
	.c_vendor	= "NSC",
	.c_ident	= { "Geode by NSC" },
	.c_x86_vendor	= X86_VENDOR_NSC,
};

static const struct cpu_dev *this_cpu = &default_cpu;
static const struct cpu_dev * cpu_devs[X86_VENDOR_NUM] =
{
		&intel_cpu_dev,
		&cyrix_cpu_dev,
		&amd_cpu_dev,
		&umc_cpu_dev,
		&centaur_cpu_dev,
		&transmeta_cpu_dev,
		&nsc_cpu_dev,
		0
};

void native_get_max_addr(struct cpuinfo_x86 *c)
{
	unsigned int eaxret = get_cpu_feature(0x80000008, 0);
	c->x86_phys_bits = (__u8)(eaxret & 0xff);
	c->x86_virt_bits = (__u8)((eaxret >> 8) & 0xff);
}

void native_cpu_detect(struct cpuinfo_x86 *c)
{
	//vendor name
	cpuid(0x00000000, (unsigned int *)&c->cpuid_level,
	      (unsigned int *)&c->x86_vendor_id[0],
	      (unsigned int *)&c->x86_vendor_id[8],
	      (unsigned int *)&c->x86_vendor_id[4]);

	c->x86 = 4;
	if (c->cpuid_level >= 0x00000001)
	{
		u32 junk, tfms, cap0, misc;

		cpuid(0x00000001, &tfms, &misc, &junk, &cap0);
		c->x86 = (tfms >> 8) & 0xf;
		c->x86_model = (tfms >> 4) & 0xf;
		c->x86_mask = tfms & 0xf;

		if (c->x86 == 0xf)
		{
			c->x86 += (tfms >> 20) & 0xff;
		}
		if (c->x86 >= 0x6)
		{
			c->x86_model += ((tfms >> 16) & 0xf) << 4;
		}

		if (cap0 & (1<<19))
		{
			c->x86_clflush_size = ((misc >> 8) & 0xff) * 8;
			c->x86_cache_alignment = c->x86_clflush_size;
		}
	}
}

void native_get_cpu_vendor(struct cpuinfo_x86 *c)
{
	char *v = c->x86_vendor_id;
	int i;

	for (i = 0; i < X86_VENDOR_NUM; i++)
	{
		if (!cpu_devs[i])
		{
			break;
		}

		if (!strcmp(v, cpu_devs[i]->c_ident[0]) ||
		    (cpu_devs[i]->c_ident[1] &&
		     !strcmp(v, cpu_devs[i]->c_ident[1])))
		{

			this_cpu = cpu_devs[i];
			c->x86_vendor = this_cpu->c_x86_vendor;
			return;
		}
	}

	c->x86_vendor = X86_VENDOR_UNKNOWN;
	this_cpu = &default_cpu;
}

struct cpuid_bit {
	u16 feature;
	u8 reg;
	u8 bit;
	u32 level;
	u32 sub_leaf;
};

enum cpuid_regs {
	CR_EAX = 0,
	CR_ECX,
	CR_EDX,
	CR_EBX
};

void init_scattered_cpuid_features(struct cpuinfo_x86 *c)
{
	u32 max_level;
	u32 regs[4];
	const struct cpuid_bit *cb;

	static const struct cpuid_bit cpuid_bits[] =
	{
		{ X86_FEATURE_DTHERM,		CR_EAX, 0, 0x00000006, 0 },
		{ X86_FEATURE_IDA,		CR_EAX, 1, 0x00000006, 0 },
		{ X86_FEATURE_ARAT,		CR_EAX, 2, 0x00000006, 0 },
		{ X86_FEATURE_PLN,		CR_EAX, 4, 0x00000006, 0 },
		{ X86_FEATURE_PTS,		CR_EAX, 6, 0x00000006, 0 },
		{ X86_FEATURE_APERFMPERF,	CR_ECX, 0, 0x00000006, 0 },
		{ X86_FEATURE_EPB,		CR_ECX, 3, 0x00000006, 0 },
		{ X86_FEATURE_XSAVEOPT,		CR_EAX,	0, 0x0000000d, 1 },
		{ X86_FEATURE_CPB,		CR_EDX, 9, 0x80000007, 0 },
		{ X86_FEATURE_HW_PSTATE,	CR_EDX, 7, 0x80000007, 0 },
		{ X86_FEATURE_NPT,		CR_EDX, 0, 0x8000000a, 0 },
		{ X86_FEATURE_LBRV,		CR_EDX, 1, 0x8000000a, 0 },
		{ X86_FEATURE_SVML,		CR_EDX, 2, 0x8000000a, 0 },
		{ X86_FEATURE_NRIPS,		CR_EDX, 3, 0x8000000a, 0 },
		{ X86_FEATURE_TSCRATEMSR,	CR_EDX, 4, 0x8000000a, 0 },
		{ X86_FEATURE_VMCBCLEAN,	CR_EDX, 5, 0x8000000a, 0 },
		{ X86_FEATURE_FLUSHBYASID,	CR_EDX, 6, 0x8000000a, 0 },
		{ X86_FEATURE_DECODEASSISTS,	CR_EDX, 7, 0x8000000a, 0 },
		{ X86_FEATURE_PAUSEFILTER,	CR_EDX,10, 0x8000000a, 0 },
		{ X86_FEATURE_PFTHRESHOLD,	CR_EDX,12, 0x8000000a, 0 },
		{ 0, 0, 0, 0, 0 }
	};

	for (cb = cpuid_bits; cb->feature; cb++)
	{

		/* Verify that the level is valid */
		max_level = cpuid_eax(cb->level & 0xffff0000);
		if (max_level < cb->level ||
		    max_level > (cb->level | 0xffff))
		{
			continue;
		}

		cpuid_count(cb->level, cb->sub_leaf, &regs[CR_EAX],
			    &regs[CR_EBX], &regs[CR_ECX], &regs[CR_EDX]);

		if (regs[cb->reg] & (1 << cb->bit))
		{
			set_cpu_cap(c, cb->feature);
		}
	}
}

void native_get_cpu_cap(struct cpuinfo_x86 *c)
{
	u32 tfms, xlvl;
	u32 ebx;

	/* Intel-defined flags: level 0x00000001 */
	if (c->cpuid_level >= 0x00000001)
	{
		u32 capability, excap;

		cpuid(0x00000001, &tfms, &ebx, &excap, &capability);
		c->x86_capability[0] = capability;
		c->x86_capability[4] = excap;
	}

	/* Additional Intel-defined flags: level 0x00000007 */
	if (c->cpuid_level >= 0x00000007)
	{
		u32 eax, ebx, ecx, edx;

		cpuid_count(0x00000007, 0, &eax, &ebx, &ecx, &edx);

		c->x86_capability[9] = ebx;
	}

	/* AMD-defined flags: level 0x80000001 */
	xlvl = cpuid_eax(0x80000000);
	c->extended_cpuid_level = xlvl;

	if ((xlvl & 0xffff0000) == 0x80000000)
	{
		if (xlvl >= 0x80000001)
		{
			c->x86_capability[1] = cpuid_edx(0x80000001);
			c->x86_capability[6] = cpuid_ecx(0x80000001);
		}
	}

	if (c->extended_cpuid_level >= 0x80000008)
	{
		u32 eax = cpuid_eax(0x80000008);

		c->x86_virt_bits = (eax >> 8) & 0xff;
		c->x86_phys_bits = eax & 0xff;
	}
#ifdef CONFIG_X86_32
	else if (cpu_has(c, X86_FEATURE_PAE) || cpu_has(c, X86_FEATURE_PSE36))
	{
		c->x86_phys_bits = 36;
	}
#endif

	if (c->extended_cpuid_level >= 0x80000007)
	{
		c->x86_power = cpuid_edx(0x80000007);
	}

	init_scattered_cpuid_features(c);
}

void init_boot_cpu_data(void)
{
	native_cpu_detect(&boot_cpu_data);
	native_get_cpu_vendor(&boot_cpu_data);
	native_get_max_addr(&boot_cpu_data);
	native_get_cpu_cap(&boot_cpu_data);
}

