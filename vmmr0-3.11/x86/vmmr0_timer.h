#include "os_interface.h"

#ifdef CONFIG_HAVE_KVM_IRQCHIP
struct vmmr0_timer
{
	struct hrtimer timer;
	s64 period; 				/* unit: ns */
	u32 timer_mode_mask;
	u64 tscdeadline;
	atomic_t pending;			/* accumulated triggered timers */
	bool reinject;
	struct vmmr0_timer_ops *t_ops;
	struct vm *pvm;
	struct vmmr0_vcpu *vcpu;
};

struct vmmr0_timer_ops
{
	bool (*is_periodic)(struct vmmr0_timer *);
};

enum hrtimer_restart vmmr0_timer_fn(struct hrtimer *data);
#endif
