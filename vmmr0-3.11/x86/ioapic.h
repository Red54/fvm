#ifndef __KVM_IO_APIC_H
#define __KVM_IO_APIC_H

#include <linux/vmmr0_host.h>

#include "iodev.h"

#ifdef CONFIG_HAVE_KVM_IRQCHIP
struct vm;
struct vmmr0_vcpu;

#define IOAPIC_NUM_PINS  KVM_IOAPIC_NUM_PINS
#define IOAPIC_VERSION_ID 0x11	/* IOAPIC version */
#define IOAPIC_EDGE_TRIG  0
#define IOAPIC_LEVEL_TRIG 1

#define IOAPIC_DEFAULT_BASE_ADDRESS  0xfec00000
#define IOAPIC_MEM_LENGTH            0x100

/* Direct registers. */
#define IOAPIC_REG_SELECT  0x00
#define IOAPIC_REG_WINDOW  0x10
#define IOAPIC_REG_EOI     0x40	/* IA64 IOSAPIC only */

/* Indirect registers. */
#define IOAPIC_REG_APIC_ID 0x00	/* x86 IOAPIC only */
#define IOAPIC_REG_VERSION 0x01
#define IOAPIC_REG_ARB_ID  0x02	/* x86 IOAPIC only */

/*ioapic delivery mode*/
#define	IOAPIC_FIXED			0x0
#define	IOAPIC_LOWEST_PRIORITY		0x1
#define	IOAPIC_PMI			0x2
#define	IOAPIC_NMI			0x4
#define	IOAPIC_INIT			0x5
#define	IOAPIC_EXTINT			0x7

struct vmmr0_ioapic
{
	u64 base_address;
	u32 ioregsel;
	u32 id;
	u32 irr;
	u32 pad;
	union vmmr0_ioapic_redirect_entry redirtbl[IOAPIC_NUM_PINS];
	unsigned long irq_states[IOAPIC_NUM_PINS];
	struct vmmr0_io_device dev;
	struct vm *pvm;
	void (*ack_notifier)(void *opaque, int irq);
	spinlock_t lock;
	DECLARE_BITMAP(handled_vectors, 256);
};

#ifdef HOST_LINUX
#ifdef DEBUG
#define ASSERT(x)  											\
do {														\
	if (!(x)) 												\
	{														\
		printk(KERN_EMERG "assertion failed %s: %d: %s\n",	\
		       __FILE__, __LINE__, #x);						\
		BUG();												\
	}														\
} while (0)
#else
#define ASSERT(x) do { } while (0)
#endif
#endif

static inline struct vmmr0_ioapic *ioapic_irqchip(struct vm *pvm)
{
	return pvm->arch.vioapic;
}

int vmmr0_apic_match_dest(struct vmmr0_vcpu *vcpu, struct vmmr0_lapic *source,
		int short_hand, int dest, int dest_mode);
int vmmr0_apic_compare_prio(struct vmmr0_vcpu *vcpu1, struct vmmr0_vcpu *vcpu2);
void vmmr0_ioapic_update_eoi(struct vm *pvm, int vector, int trigger_mode);
int vmmr0_ioapic_init(struct vm *pvm);
void vmmr0_ioapic_destroy(struct vm *pvm);
int vmmr0_ioapic_set_irq(struct vmmr0_ioapic *ioapic, int irq, int level);
void vmmr0_ioapic_reset(struct vmmr0_ioapic *ioapic);
int vmmr0_irq_delivery_to_apic(struct vm *pvm, struct vmmr0_lapic *src,
		struct vmmr0_lapic_irq *irq);
int vmmr0_get_ioapic(struct vm *pvm, struct vmmr0_ioapic_state *state);
int vmmr0_set_ioapic(struct vm *pvm, struct vmmr0_ioapic_state *state);

#endif //CONFIG_HAVE_KVM_IRQCHIP
#endif
