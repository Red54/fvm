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


#ifndef __KVM_TYPES_H__
#define __KVM_TYPES_H__

#include "os_interface.h"

/*
 * Address types:
 *
 *  gva - guest virtual address
 *  gpa - guest physical address
 *  gfn - guest frame number
 *  hva - host virtual address
 *  hpa - host physical address
 *  hfn - host frame number
 */

typedef unsigned long  gva_t;
typedef u64            gpa_t;
typedef u64            gfn_t;

typedef unsigned long  hva_t;
typedef u64            hpa_t;
typedef u64            hfn_t;

typedef hfn_t pfn_t;

union vmmr0_ioapic_redirect_entry
{
	u64 bits;
	struct 
	{
		u8 vector;
		u8 delivery_mode:3;
		u8 dest_mode:1;
		u8 delivery_status:1;
		u8 polarity:1;
		u8 remote_irr:1;
		u8 trig_mode:1;
		u8 mask:1;
		u8 reserve:7;
		u8 reserved[4];
		u8 dest_id;
	} fields;
};

struct vmmr0_lapic_irq 
{
	u32 vector;
	u32 delivery_mode;
	u32 dest_mode;
	u32 level;
	u32 trig_mode;
	u32 shorthand;
	u32 dest_id;
};

struct gfn_to_hva_cache 
{
	u64 generation;
	gpa_t gpa;
	unsigned long hva;
	struct vmmr0_memory_slot *memslot;
};

#endif /* __KVM_TYPES_H__ */
