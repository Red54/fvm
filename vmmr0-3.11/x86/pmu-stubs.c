bool vmmr0_pmu_msr(struct vmmr0_vcpu *vcpu, u32 msr)
{
	return false;
}

int vmmr0_pmu_read_pmc(struct vmmr0_vcpu *vcpu, unsigned pmc, u64 *data)
{
	return 1;
}

int vmmr0_pmu_get_msr(struct vmmr0_vcpu *vcpu, u32 index, u64 *data)
{
	BUG();
	return -1;
}

int vmmr0_pmu_set_msr(struct vmmr0_vcpu *vcpu, u32 index, u64 data)
{
	BUG();
	return -1;
}

void vmmr0_deliver_pmi(struct vmmr0_vcpu *vcpu)
{
	BUG();
}

void vmmr0_pmu_cpuid_update(struct vmmr0_vcpu *vcpu)
{
}

void vmmr0_pmu_init(struct vmmr0_vcpu *vcpu)
{
#ifdef CONFIG_HAVE_PMU
	struct vmmr0_pmu *pmu = &vcpu->arch.pmu;

	memset(pmu, 0, sizeof(*pmu));
#endif
}

void vmmr0_pmu_reset(struct vmmr0_vcpu *vcpu)
{
}

void vmmr0_pmu_destroy(struct vmmr0_vcpu *vcpu)
{
}

void vmmr0_handle_pmu_event(struct vmmr0_vcpu *vcpu)
{
	BUG();
}
