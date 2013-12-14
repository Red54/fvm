#ifndef SEGMENT_H_
#define SEGMENT_H_

#define GDT_ENTRY(flags, base, limit)			\
	((((base)  & _AC(0xff000000,ULL)) << (56-24)) |	\
	 (((flags) & _AC(0x0000f0ff,ULL)) << 40) |	\
	 (((limit) & _AC(0x000f0000,ULL)) << (48-16)) |	\
	 (((base)  & _AC(0x00ffffff,ULL)) << 16) |	\
	 (((limit) & _AC(0x0000ffff,ULL))))

#ifdef CONFIG_X86_32

#define GDT_ENTRY_TLS_MIN	6
#define GDT_ENTRY_TLS_MAX 	(GDT_ENTRY_TLS_MIN + GDT_ENTRY_TLS_ENTRIES - 1)

#define GDT_ENTRY_DEFAULT_USER_CS	14

#define GDT_ENTRY_DEFAULT_USER_DS	15

#define GDT_ENTRY_KERNEL_BASE		(12)

#define GDT_ENTRY_KERNEL_CS		(GDT_ENTRY_KERNEL_BASE+0)

#define GDT_ENTRY_KERNEL_DS		(GDT_ENTRY_KERNEL_BASE+1)

#define GDT_ENTRY_TSS			(GDT_ENTRY_KERNEL_BASE+4)
#define GDT_ENTRY_LDT			(GDT_ENTRY_KERNEL_BASE+5)


#define GDT_ENTRY_DOUBLEFAULT_TSS	31

/*
 * The GDT has 32 entries
 */
#define GDT_ENTRIES 32

/* Bottom two bits of selector give the ring privilege level */
#define SEGMENT_RPL_MASK	0x3
/* Bit 2 is table indicator (LDT/GDT) */
#define SEGMENT_TI_MASK		0x4

/* User mode is privilege level 3 */
#define USER_RPL		0x3
/* LDT segment has TI set, GDT has it cleared */
#define SEGMENT_LDT		0x4
#define SEGMENT_GDT		0x0

#else

#define GDT_ENTRY_KERNEL32_CS 1
#define GDT_ENTRY_KERNEL_CS 2
#define GDT_ENTRY_KERNEL_DS 3

#define __KERNEL32_CS   (GDT_ENTRY_KERNEL32_CS * 8)

#define GDT_ENTRY_DEFAULT_USER32_CS 4
#define GDT_ENTRY_DEFAULT_USER_DS 5
#define GDT_ENTRY_DEFAULT_USER_CS 6
#define __USER32_CS   (GDT_ENTRY_DEFAULT_USER32_CS*8+3)
#define __USER32_DS	__USER_DS

#define GDT_ENTRY_TSS 8	/* needs two entries */
#define GDT_ENTRY_LDT 10 /* needs two entries */
#define GDT_ENTRY_TLS_MIN 12
#define GDT_ENTRY_TLS_MAX 14

#define GDT_ENTRY_PER_CPU 15	/* Abused to load per CPU data from limit */
#define __PER_CPU_SEG	(GDT_ENTRY_PER_CPU * 8 + 3)

#define FS_TLS 0
#define GS_TLS 1

#define GS_TLS_SEL ((GDT_ENTRY_TLS_MIN+GS_TLS)*8 + 3)
#define FS_TLS_SEL ((GDT_ENTRY_TLS_MIN+FS_TLS)*8 + 3)

#define GDT_ENTRIES 16

#endif

#define __KERNEL_CS	(GDT_ENTRY_KERNEL_CS*8)
#define __KERNEL_DS	(GDT_ENTRY_KERNEL_DS*8)
#define __USER_DS	(GDT_ENTRY_DEFAULT_USER_DS*8+3)
#define __USER_CS	(GDT_ENTRY_DEFAULT_USER_CS*8+3)

/* LDT segment has TI set, GDT has it cleared */
#define SEGMENT_LDT		0x4
#define SEGMENT_GDT		0x0

/* Bottom two bits of selector give the ring privilege level */
#define SEGMENT_RPL_MASK	0x3
/* Bit 2 is table indicator (LDT/GDT) */
#define SEGMENT_TI_MASK		0x4

#define IDT_ENTRIES 256
#define NUM_EXCEPTION_VECTORS 32
#define GDT_SIZE (GDT_ENTRIES * 8)
#define GDT_ENTRY_TLS_ENTRIES 3
#define TLS_SIZE (GDT_ENTRY_TLS_ENTRIES * 8)


#define loadsegment(seg, value)							\
do {													\
	unsigned short __val = (value);						\
														\
	asm volatile("								\n"		\
		     "1:	movl %k0,%%" #seg "			\n"		\
														\
		     "2:	xorl %k0,%k0				\n"		\
		     "		jmp 1b						\n"		\
														\
		     : "+r" (__val) : : "memory");				\
} while (0)

#define savesegment(seg, value)						\
	asm("mov %%" #seg ",%0":"=r" (value) : : "memory")



#endif /* SEGMENT_H_ */
