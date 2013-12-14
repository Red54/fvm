#ifndef __KVM_ASYNC_PF_H__
#define __KVM_ASYNC_PF_H__

#ifdef CONFIG_KVM_ASYNC_PF
int vmmr0_async_pf_init(void);
void vmmr0_async_pf_deinit(void);
void vmmr0_async_pf_vcpu_init(struct vmmr0_vcpu *vcpu);
#else
#define vmmr0_async_pf_init() (0)
#define vmmr0_async_pf_deinit() do{}while(0)
#define vmmr0_async_pf_vcpu_init(C) do{}while(0)
#endif

#endif
