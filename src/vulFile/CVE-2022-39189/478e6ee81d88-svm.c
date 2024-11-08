

















































MODULE_AUTHOR("Qumranet");
MODULE_LICENSE("GPL");


static const struct x86_cpu_id svm_cpu_id[] = {
	X86_MATCH_FEATURE(X86_FEATURE_SVM, NULL), {}
};
MODULE_DEVICE_TABLE(x86cpu, svm_cpu_id);





static bool erratum_383_found __read_mostly;

u32 msrpm_offsets[MSRPM_OFFSETS] __read_mostly;


static uint64_t osvw_len = 4, osvw_status;

static DEFINE_PER_CPU(u64, current_tsc_ratio);

static const struct svm_direct_access_msrs {
	u32 index;   
	bool always; 
} direct_access_msrs[MAX_DIRECT_ACCESS_MSRS] = {
	{ .index = MSR_STAR,				.always = true  }, { .index = MSR_IA32_SYSENTER_CS,		.always = true  }, { .index = MSR_IA32_SYSENTER_EIP,		.always = false }, { .index = MSR_IA32_SYSENTER_ESP,		.always = false },  { .index = MSR_GS_BASE,				.always = true  }, { .index = MSR_FS_BASE,				.always = true  }, { .index = MSR_KERNEL_GS_BASE,			.always = true  }, { .index = MSR_LSTAR,				.always = true  }, { .index = MSR_CSTAR,				.always = true  }, { .index = MSR_SYSCALL_MASK,			.always = true  },  { .index = MSR_IA32_SPEC_CTRL,			.always = false }, { .index = MSR_IA32_PRED_CMD,			.always = false }, { .index = MSR_IA32_LASTBRANCHFROMIP,		.always = false }, { .index = MSR_IA32_LASTBRANCHTOIP,		.always = false }, { .index = MSR_IA32_LASTINTFROMIP,		.always = false }, { .index = MSR_IA32_LASTINTTOIP,		.always = false }, { .index = MSR_EFER,				.always = false }, { .index = MSR_IA32_CR_PAT,			.always = false }, { .index = MSR_AMD64_SEV_ES_GHCB,		.always = true  }, { .index = MSR_TSC_AUX,				.always = false }, { .index = MSR_INVALID,				.always = false }, };

























static unsigned short pause_filter_thresh = KVM_DEFAULT_PLE_GAP;
module_param(pause_filter_thresh, ushort, 0444);

static unsigned short pause_filter_count = KVM_SVM_DEFAULT_PLE_WINDOW;
module_param(pause_filter_count, ushort, 0444);


static unsigned short pause_filter_count_grow = KVM_DEFAULT_PLE_WINDOW_GROW;
module_param(pause_filter_count_grow, ushort, 0444);


static unsigned short pause_filter_count_shrink = KVM_DEFAULT_PLE_WINDOW_SHRINK;
module_param(pause_filter_count_shrink, ushort, 0444);


static unsigned short pause_filter_count_max = KVM_SVM_DEFAULT_PLE_WINDOW_MAX;
module_param(pause_filter_count_max, ushort, 0444);


bool npt_enabled = true;
module_param_named(npt, npt_enabled, bool, 0444);


static int nested = true;
module_param(nested, int, S_IRUGO);


static int nrips = true;
module_param(nrips, int, 0444);


static int vls = true;
module_param(vls, int, 0444);


int vgif = true;
module_param(vgif, int, 0444);


static int lbrv = true;
module_param(lbrv, int, 0444);

static int tsc_scaling = true;
module_param(tsc_scaling, int, 0444);


static bool avic;
module_param(avic, bool, 0444);

static bool force_avic;
module_param_unsafe(force_avic, bool, 0444);

bool __read_mostly dump_invalid_vmcb;
module_param(dump_invalid_vmcb, bool, 0644);


bool intercept_smi = true;
module_param(intercept_smi, bool, 0444);


static bool svm_gp_erratum_intercept = true;

static u8 rsm_ins_bytes[] = "\x0f\xaa";

static unsigned long iopm_base;

struct kvm_ldttss_desc {
	u16 limit0;
	u16 base0;
	unsigned base1:8, type:5, dpl:2, p:1;
	unsigned limit1:4, zero0:3, g:1, base2:8;
	u32 base3;
	u32 zero1;
} __attribute__((packed));

DEFINE_PER_CPU(struct svm_cpu_data *, svm_data);


static int tsc_aux_uret_slot __read_mostly = -1;

static const u32 msrpm_ranges[] = {0, 0xc0000000, 0xc0010000};





u32 svm_msrpm_offset(u32 msr)
{
	u32 offset;
	int i;

	for (i = 0; i < NUM_MSR_MAPS; i++) {
		if (msr < msrpm_ranges[i] || msr >= msrpm_ranges[i] + MSRS_IN_RANGE)
			continue;

		offset  = (msr - msrpm_ranges[i]) / 4; 
		offset += (i * MSRS_RANGE_SIZE);       

		
		return offset / 4;
	}

	
	return MSR_INVALID;
}

static void svm_flush_tlb_current(struct kvm_vcpu *vcpu);

static int get_npt_level(void)
{

	return pgtable_l5_enabled() ? PT64_ROOT_5LEVEL : PT64_ROOT_4LEVEL;

	return PT32E_ROOT_LEVEL;

}

int svm_set_efer(struct kvm_vcpu *vcpu, u64 efer)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	u64 old_efer = vcpu->arch.efer;
	vcpu->arch.efer = efer;

	if (!npt_enabled) {
		
		efer |= EFER_NX;

		if (!(efer & EFER_LMA))
			efer &= ~EFER_LME;
	}

	if ((old_efer & EFER_SVME) != (efer & EFER_SVME)) {
		if (!(efer & EFER_SVME)) {
			svm_leave_nested(vcpu);
			svm_set_gif(svm, true);
			
			if (!enable_vmware_backdoor)
				clr_exception_intercept(svm, GP_VECTOR);

			
			if (!is_smm(vcpu))
				svm_free_nested(svm);

		} else {
			int ret = svm_allocate_nested(svm);

			if (ret) {
				vcpu->arch.efer = old_efer;
				return ret;
			}

			
			if (svm_gp_erratum_intercept && !sev_guest(vcpu->kvm))
				set_exception_intercept(svm, GP_VECTOR);
		}
	}

	svm->vmcb->save.efer = efer | EFER_SVME;
	vmcb_mark_dirty(svm->vmcb, VMCB_CR);
	return 0;
}

static int is_external_interrupt(u32 info)
{
	info &= SVM_EVTINJ_TYPE_MASK | SVM_EVTINJ_VALID;
	return info == (SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_INTR);
}

static u32 svm_get_interrupt_shadow(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	u32 ret = 0;

	if (svm->vmcb->control.int_state & SVM_INTERRUPT_SHADOW_MASK)
		ret = KVM_X86_SHADOW_INT_STI | KVM_X86_SHADOW_INT_MOV_SS;
	return ret;
}

static void svm_set_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	if (mask == 0)
		svm->vmcb->control.int_state &= ~SVM_INTERRUPT_SHADOW_MASK;
	else svm->vmcb->control.int_state |= SVM_INTERRUPT_SHADOW_MASK;

}

static int svm_skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	
	if (sev_es_guest(vcpu->kvm))
		goto done;

	if (nrips && svm->vmcb->control.next_rip != 0) {
		WARN_ON_ONCE(!static_cpu_has(X86_FEATURE_NRIPS));
		svm->next_rip = svm->vmcb->control.next_rip;
	}

	if (!svm->next_rip) {
		if (!kvm_emulate_instruction(vcpu, EMULTYPE_SKIP))
			return 0;
	} else {
		kvm_rip_write(vcpu, svm->next_rip);
	}

done:
	svm_set_interrupt_shadow(vcpu, 0);

	return 1;
}

static void svm_queue_exception(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	unsigned nr = vcpu->arch.exception.nr;
	bool has_error_code = vcpu->arch.exception.has_error_code;
	u32 error_code = vcpu->arch.exception.error_code;

	kvm_deliver_exception_payload(vcpu);

	if (nr == BP_VECTOR && !nrips) {
		unsigned long rip, old_rip = kvm_rip_read(vcpu);

		
		(void)svm_skip_emulated_instruction(vcpu);
		rip = kvm_rip_read(vcpu);
		svm->int3_rip = rip + svm->vmcb->save.cs.base;
		svm->int3_injected = rip - old_rip;
	}

	svm->vmcb->control.event_inj = nr | SVM_EVTINJ_VALID | (has_error_code ? SVM_EVTINJ_VALID_ERR : 0)

		| SVM_EVTINJ_TYPE_EXEPT;
	svm->vmcb->control.event_inj_err = error_code;
}

static void svm_init_erratum_383(void)
{
	u32 low, high;
	int err;
	u64 val;

	if (!static_cpu_has_bug(X86_BUG_AMD_TLB_MMATCH))
		return;

	
	val = native_read_msr_safe(MSR_AMD64_DC_CFG, &err);
	if (err)
		return;

	val |= (1ULL << 47);

	low  = lower_32_bits(val);
	high = upper_32_bits(val);

	native_write_msr_safe(MSR_AMD64_DC_CFG, low, high);

	erratum_383_found = true;
}

static void svm_init_osvw(struct kvm_vcpu *vcpu)
{
	
	vcpu->arch.osvw.length = (osvw_len >= 3) ? (osvw_len) : 3;
	vcpu->arch.osvw.status = osvw_status & ~(6ULL);

	
	if (osvw_len == 0 && boot_cpu_data.x86 == 0x10)
		vcpu->arch.osvw.status |= 1;
}

static int has_svm(void)
{
	const char *msg;

	if (!cpu_has_svm(&msg)) {
		printk(KERN_INFO "has_svm: %s\n", msg);
		return 0;
	}

	if (cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT)) {
		pr_info("KVM is unsupported when running as an SEV guest\n");
		return 0;
	}

	return 1;
}

void __svm_write_tsc_multiplier(u64 multiplier)
{
	preempt_disable();

	if (multiplier == __this_cpu_read(current_tsc_ratio))
		goto out;

	wrmsrl(MSR_AMD64_TSC_RATIO, multiplier);
	__this_cpu_write(current_tsc_ratio, multiplier);
out:
	preempt_enable();
}

static void svm_hardware_disable(void)
{
	
	if (tsc_scaling)
		__svm_write_tsc_multiplier(SVM_TSC_RATIO_DEFAULT);

	cpu_svm_disable();

	amd_pmu_disable_virt();
}

static int svm_hardware_enable(void)
{

	struct svm_cpu_data *sd;
	uint64_t efer;
	struct desc_struct *gdt;
	int me = raw_smp_processor_id();

	rdmsrl(MSR_EFER, efer);
	if (efer & EFER_SVME)
		return -EBUSY;

	if (!has_svm()) {
		pr_err("%s: err EOPNOTSUPP on %d\n", __func__, me);
		return -EINVAL;
	}
	sd = per_cpu(svm_data, me);
	if (!sd) {
		pr_err("%s: svm_data is NULL on %d\n", __func__, me);
		return -EINVAL;
	}

	sd->asid_generation = 1;
	sd->max_asid = cpuid_ebx(SVM_CPUID_FUNC) - 1;
	sd->next_asid = sd->max_asid + 1;
	sd->min_asid = max_sev_asid + 1;

	gdt = get_current_gdt_rw();
	sd->tss_desc = (struct kvm_ldttss_desc *)(gdt + GDT_ENTRY_TSS);

	wrmsrl(MSR_EFER, efer | EFER_SVME);

	wrmsrl(MSR_VM_HSAVE_PA, __sme_page_pa(sd->save_area));

	if (static_cpu_has(X86_FEATURE_TSCRATEMSR)) {
		
		__svm_write_tsc_multiplier(SVM_TSC_RATIO_DEFAULT);
	}


	
	if (cpu_has(&boot_cpu_data, X86_FEATURE_OSVW)) {
		uint64_t len, status = 0;
		int err;

		len = native_read_msr_safe(MSR_AMD64_OSVW_ID_LENGTH, &err);
		if (!err)
			status = native_read_msr_safe(MSR_AMD64_OSVW_STATUS, &err);

		if (err)
			osvw_status = osvw_len = 0;
		else {
			if (len < osvw_len)
				osvw_len = len;
			osvw_status |= status;
			osvw_status &= (1ULL << osvw_len) - 1;
		}
	} else osvw_status = osvw_len = 0;

	svm_init_erratum_383();

	amd_pmu_enable_virt();

	return 0;
}

static void svm_cpu_uninit(int cpu)
{
	struct svm_cpu_data *sd = per_cpu(svm_data, cpu);

	if (!sd)
		return;

	per_cpu(svm_data, cpu) = NULL;
	kfree(sd->sev_vmcbs);
	__free_page(sd->save_area);
	kfree(sd);
}

static int svm_cpu_init(int cpu)
{
	struct svm_cpu_data *sd;
	int ret = -ENOMEM;

	sd = kzalloc(sizeof(struct svm_cpu_data), GFP_KERNEL);
	if (!sd)
		return ret;
	sd->cpu = cpu;
	sd->save_area = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!sd->save_area)
		goto free_cpu_data;

	ret = sev_cpu_init(sd);
	if (ret)
		goto free_save_area;

	per_cpu(svm_data, cpu) = sd;

	return 0;

free_save_area:
	__free_page(sd->save_area);
free_cpu_data:
	kfree(sd);
	return ret;

}

static int direct_access_msr_slot(u32 msr)
{
	u32 i;

	for (i = 0; direct_access_msrs[i].index != MSR_INVALID; i++)
		if (direct_access_msrs[i].index == msr)
			return i;

	return -ENOENT;
}

static void set_shadow_msr_intercept(struct kvm_vcpu *vcpu, u32 msr, int read, int write)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	int slot = direct_access_msr_slot(msr);

	if (slot == -ENOENT)
		return;

	
	if (read)
		set_bit(slot, svm->shadow_msr_intercept.read);
	else clear_bit(slot, svm->shadow_msr_intercept.read);

	if (write)
		set_bit(slot, svm->shadow_msr_intercept.write);
	else clear_bit(slot, svm->shadow_msr_intercept.write);
}

static bool valid_msr_intercept(u32 index)
{
	return direct_access_msr_slot(index) != -ENOENT;
}

static bool msr_write_intercepted(struct kvm_vcpu *vcpu, u32 msr)
{
	u8 bit_write;
	unsigned long tmp;
	u32 offset;
	u32 *msrpm;

	msrpm = is_guest_mode(vcpu) ? to_svm(vcpu)->nested.msrpm:
				      to_svm(vcpu)->msrpm;

	offset    = svm_msrpm_offset(msr);
	bit_write = 2 * (msr & 0x0f) + 1;
	tmp       = msrpm[offset];

	BUG_ON(offset == MSR_INVALID);

	return !!test_bit(bit_write,  &tmp);
}

static void set_msr_interception_bitmap(struct kvm_vcpu *vcpu, u32 *msrpm, u32 msr, int read, int write)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	u8 bit_read, bit_write;
	unsigned long tmp;
	u32 offset;

	
	WARN_ON(!valid_msr_intercept(msr));

	
	if (read && !kvm_msr_allowed(vcpu, msr, KVM_MSR_FILTER_READ))
		read = 0;

	if (write && !kvm_msr_allowed(vcpu, msr, KVM_MSR_FILTER_WRITE))
		write = 0;

	offset    = svm_msrpm_offset(msr);
	bit_read  = 2 * (msr & 0x0f);
	bit_write = 2 * (msr & 0x0f) + 1;
	tmp       = msrpm[offset];

	BUG_ON(offset == MSR_INVALID);

	read  ? clear_bit(bit_read,  &tmp) : set_bit(bit_read,  &tmp);
	write ? clear_bit(bit_write, &tmp) : set_bit(bit_write, &tmp);

	msrpm[offset] = tmp;

	svm_hv_vmcb_dirty_nested_enlightenments(vcpu);
	svm->nested.force_msr_bitmap_recalc = true;
}

void set_msr_interception(struct kvm_vcpu *vcpu, u32 *msrpm, u32 msr, int read, int write)
{
	set_shadow_msr_intercept(vcpu, msr, read, write);
	set_msr_interception_bitmap(vcpu, msrpm, msr, read, write);
}

u32 *svm_vcpu_alloc_msrpm(void)
{
	unsigned int order = get_order(MSRPM_SIZE);
	struct page *pages = alloc_pages(GFP_KERNEL_ACCOUNT, order);
	u32 *msrpm;

	if (!pages)
		return NULL;

	msrpm = page_address(pages);
	memset(msrpm, 0xff, PAGE_SIZE * (1 << order));

	return msrpm;
}

void svm_vcpu_init_msrpm(struct kvm_vcpu *vcpu, u32 *msrpm)
{
	int i;

	for (i = 0; direct_access_msrs[i].index != MSR_INVALID; i++) {
		if (!direct_access_msrs[i].always)
			continue;
		set_msr_interception(vcpu, msrpm, direct_access_msrs[i].index, 1, 1);
	}
}


void svm_vcpu_free_msrpm(u32 *msrpm)
{
	__free_pages(virt_to_page(msrpm), get_order(MSRPM_SIZE));
}

static void svm_msr_filter_changed(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	u32 i;

	
	for (i = 0; direct_access_msrs[i].index != MSR_INVALID; i++) {
		u32 msr = direct_access_msrs[i].index;
		u32 read = test_bit(i, svm->shadow_msr_intercept.read);
		u32 write = test_bit(i, svm->shadow_msr_intercept.write);

		set_msr_interception_bitmap(vcpu, svm->msrpm, msr, read, write);
	}
}

static void add_msr_offset(u32 offset)
{
	int i;

	for (i = 0; i < MSRPM_OFFSETS; ++i) {

		
		if (msrpm_offsets[i] == offset)
			return;

		
		if (msrpm_offsets[i] != MSR_INVALID)
			continue;

		
		msrpm_offsets[i] = offset;

		return;
	}

	
	BUG();
}

static void init_msrpm_offsets(void)
{
	int i;

	memset(msrpm_offsets, 0xff, sizeof(msrpm_offsets));

	for (i = 0; direct_access_msrs[i].index != MSR_INVALID; i++) {
		u32 offset;

		offset = svm_msrpm_offset(direct_access_msrs[i].index);
		BUG_ON(offset == MSR_INVALID);

		add_msr_offset(offset);
	}
}

void svm_copy_lbrs(struct vmcb *to_vmcb, struct vmcb *from_vmcb)
{
	to_vmcb->save.dbgctl		= from_vmcb->save.dbgctl;
	to_vmcb->save.br_from		= from_vmcb->save.br_from;
	to_vmcb->save.br_to		= from_vmcb->save.br_to;
	to_vmcb->save.last_excp_from	= from_vmcb->save.last_excp_from;
	to_vmcb->save.last_excp_to	= from_vmcb->save.last_excp_to;

	vmcb_mark_dirty(to_vmcb, VMCB_LBR);
}

static void svm_enable_lbrv(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	svm->vmcb->control.virt_ext |= LBR_CTL_ENABLE_MASK;
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_LASTBRANCHFROMIP, 1, 1);
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_LASTBRANCHTOIP, 1, 1);
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_LASTINTFROMIP, 1, 1);
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_LASTINTTOIP, 1, 1);

	
	if (is_guest_mode(vcpu))
		svm_copy_lbrs(svm->vmcb, svm->vmcb01.ptr);
}

static void svm_disable_lbrv(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	svm->vmcb->control.virt_ext &= ~LBR_CTL_ENABLE_MASK;
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_LASTBRANCHFROMIP, 0, 0);
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_LASTBRANCHTOIP, 0, 0);
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_LASTINTFROMIP, 0, 0);
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_LASTINTTOIP, 0, 0);

	
	if (is_guest_mode(vcpu))
		svm_copy_lbrs(svm->vmcb01.ptr, svm->vmcb);
}

static int svm_get_lbr_msr(struct vcpu_svm *svm, u32 index)
{
	
	struct vmcb *vmcb = (svm->vmcb->control.virt_ext & LBR_CTL_ENABLE_MASK) ? svm->vmcb : svm->vmcb01.ptr;


	switch (index) {
	case MSR_IA32_DEBUGCTLMSR:
		return vmcb->save.dbgctl;
	case MSR_IA32_LASTBRANCHFROMIP:
		return vmcb->save.br_from;
	case MSR_IA32_LASTBRANCHTOIP:
		return vmcb->save.br_to;
	case MSR_IA32_LASTINTFROMIP:
		return vmcb->save.last_excp_from;
	case MSR_IA32_LASTINTTOIP:
		return vmcb->save.last_excp_to;
	default:
		KVM_BUG(false, svm->vcpu.kvm, "%s: Unknown MSR 0x%x", __func__, index);
		return 0;
	}
}

void svm_update_lbrv(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	bool enable_lbrv = svm_get_lbr_msr(svm, MSR_IA32_DEBUGCTLMSR) & DEBUGCTLMSR_LBR;

	bool current_enable_lbrv = !!(svm->vmcb->control.virt_ext & LBR_CTL_ENABLE_MASK);

	if (unlikely(is_guest_mode(vcpu) && svm->lbrv_enabled))
		if (unlikely(svm->nested.ctl.virt_ext & LBR_CTL_ENABLE_MASK))
			enable_lbrv = true;

	if (enable_lbrv == current_enable_lbrv)
		return;

	if (enable_lbrv)
		svm_enable_lbrv(vcpu);
	else svm_disable_lbrv(vcpu);
}

void disable_nmi_singlestep(struct vcpu_svm *svm)
{
	svm->nmi_singlestep = false;

	if (!(svm->vcpu.guest_debug & KVM_GUESTDBG_SINGLESTEP)) {
		
		if (!(svm->nmi_singlestep_guest_rflags & X86_EFLAGS_TF))
			svm->vmcb->save.rflags &= ~X86_EFLAGS_TF;
		if (!(svm->nmi_singlestep_guest_rflags & X86_EFLAGS_RF))
			svm->vmcb->save.rflags &= ~X86_EFLAGS_RF;
	}
}

static void grow_ple_window(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct vmcb_control_area *control = &svm->vmcb->control;
	int old = control->pause_filter_count;

	if (kvm_pause_in_guest(vcpu->kvm) || !old)
		return;

	control->pause_filter_count = __grow_ple_window(old, pause_filter_count, pause_filter_count_grow, pause_filter_count_max);



	if (control->pause_filter_count != old) {
		vmcb_mark_dirty(svm->vmcb, VMCB_INTERCEPTS);
		trace_kvm_ple_window_update(vcpu->vcpu_id, control->pause_filter_count, old);
	}
}

static void shrink_ple_window(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct vmcb_control_area *control = &svm->vmcb->control;
	int old = control->pause_filter_count;

	if (kvm_pause_in_guest(vcpu->kvm) || !old)
		return;

	control->pause_filter_count = __shrink_ple_window(old, pause_filter_count, pause_filter_count_shrink, pause_filter_count);



	if (control->pause_filter_count != old) {
		vmcb_mark_dirty(svm->vmcb, VMCB_INTERCEPTS);
		trace_kvm_ple_window_update(vcpu->vcpu_id, control->pause_filter_count, old);
	}
}

static void svm_hardware_unsetup(void)
{
	int cpu;

	sev_hardware_unsetup();

	for_each_possible_cpu(cpu)
		svm_cpu_uninit(cpu);

	__free_pages(pfn_to_page(iopm_base >> PAGE_SHIFT), get_order(IOPM_SIZE));
	iopm_base = 0;
}

static void init_seg(struct vmcb_seg *seg)
{
	seg->selector = 0;
	seg->attrib = SVM_SELECTOR_P_MASK | SVM_SELECTOR_S_MASK | SVM_SELECTOR_WRITE_MASK;
	seg->limit = 0xffff;
	seg->base = 0;
}

static void init_sys_seg(struct vmcb_seg *seg, uint32_t type)
{
	seg->selector = 0;
	seg->attrib = SVM_SELECTOR_P_MASK | type;
	seg->limit = 0xffff;
	seg->base = 0;
}

static u64 svm_get_l2_tsc_offset(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	return svm->nested.ctl.tsc_offset;
}

static u64 svm_get_l2_tsc_multiplier(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	return svm->tsc_ratio_msr;
}

static void svm_write_tsc_offset(struct kvm_vcpu *vcpu, u64 offset)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	svm->vmcb01.ptr->control.tsc_offset = vcpu->arch.l1_tsc_offset;
	svm->vmcb->control.tsc_offset = offset;
	vmcb_mark_dirty(svm->vmcb, VMCB_INTERCEPTS);
}

static void svm_write_tsc_multiplier(struct kvm_vcpu *vcpu, u64 multiplier)
{
	__svm_write_tsc_multiplier(multiplier);
}



static void svm_recalc_instruction_intercepts(struct kvm_vcpu *vcpu, struct vcpu_svm *svm)
{
	
	if (kvm_cpu_cap_has(X86_FEATURE_INVPCID)) {
		if (!npt_enabled || !guest_cpuid_has(&svm->vcpu, X86_FEATURE_INVPCID))
			svm_set_intercept(svm, INTERCEPT_INVPCID);
		else svm_clr_intercept(svm, INTERCEPT_INVPCID);
	}

	if (kvm_cpu_cap_has(X86_FEATURE_RDTSCP)) {
		if (guest_cpuid_has(vcpu, X86_FEATURE_RDTSCP))
			svm_clr_intercept(svm, INTERCEPT_RDTSCP);
		else svm_set_intercept(svm, INTERCEPT_RDTSCP);
	}
}

static inline void init_vmcb_after_set_cpuid(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	if (guest_cpuid_is_intel(vcpu)) {
		
		svm_set_intercept(svm, INTERCEPT_VMLOAD);
		svm_set_intercept(svm, INTERCEPT_VMSAVE);
		svm->vmcb->control.virt_ext &= ~VIRTUAL_VMLOAD_VMSAVE_ENABLE_MASK;

		set_msr_interception(vcpu, svm->msrpm, MSR_IA32_SYSENTER_EIP, 0, 0);
		set_msr_interception(vcpu, svm->msrpm, MSR_IA32_SYSENTER_ESP, 0, 0);

		svm->v_vmload_vmsave_enabled = false;
	} else {
		
		if (vls) {
			svm_clr_intercept(svm, INTERCEPT_VMLOAD);
			svm_clr_intercept(svm, INTERCEPT_VMSAVE);
			svm->vmcb->control.virt_ext |= VIRTUAL_VMLOAD_VMSAVE_ENABLE_MASK;
		}
		
		set_msr_interception(vcpu, svm->msrpm, MSR_IA32_SYSENTER_EIP, 1, 1);
		set_msr_interception(vcpu, svm->msrpm, MSR_IA32_SYSENTER_ESP, 1, 1);
	}
}

static void init_vmcb(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct vmcb *vmcb = svm->vmcb01.ptr;
	struct vmcb_control_area *control = &vmcb->control;
	struct vmcb_save_area *save = &vmcb->save;

	svm_set_intercept(svm, INTERCEPT_CR0_READ);
	svm_set_intercept(svm, INTERCEPT_CR3_READ);
	svm_set_intercept(svm, INTERCEPT_CR4_READ);
	svm_set_intercept(svm, INTERCEPT_CR0_WRITE);
	svm_set_intercept(svm, INTERCEPT_CR3_WRITE);
	svm_set_intercept(svm, INTERCEPT_CR4_WRITE);
	if (!kvm_vcpu_apicv_active(vcpu))
		svm_set_intercept(svm, INTERCEPT_CR8_WRITE);

	set_dr_intercepts(svm);

	set_exception_intercept(svm, PF_VECTOR);
	set_exception_intercept(svm, UD_VECTOR);
	set_exception_intercept(svm, MC_VECTOR);
	set_exception_intercept(svm, AC_VECTOR);
	set_exception_intercept(svm, DB_VECTOR);
	
	if (enable_vmware_backdoor && !sev_guest(vcpu->kvm))
		set_exception_intercept(svm, GP_VECTOR);

	svm_set_intercept(svm, INTERCEPT_INTR);
	svm_set_intercept(svm, INTERCEPT_NMI);

	if (intercept_smi)
		svm_set_intercept(svm, INTERCEPT_SMI);

	svm_set_intercept(svm, INTERCEPT_SELECTIVE_CR0);
	svm_set_intercept(svm, INTERCEPT_RDPMC);
	svm_set_intercept(svm, INTERCEPT_CPUID);
	svm_set_intercept(svm, INTERCEPT_INVD);
	svm_set_intercept(svm, INTERCEPT_INVLPG);
	svm_set_intercept(svm, INTERCEPT_INVLPGA);
	svm_set_intercept(svm, INTERCEPT_IOIO_PROT);
	svm_set_intercept(svm, INTERCEPT_MSR_PROT);
	svm_set_intercept(svm, INTERCEPT_TASK_SWITCH);
	svm_set_intercept(svm, INTERCEPT_SHUTDOWN);
	svm_set_intercept(svm, INTERCEPT_VMRUN);
	svm_set_intercept(svm, INTERCEPT_VMMCALL);
	svm_set_intercept(svm, INTERCEPT_VMLOAD);
	svm_set_intercept(svm, INTERCEPT_VMSAVE);
	svm_set_intercept(svm, INTERCEPT_STGI);
	svm_set_intercept(svm, INTERCEPT_CLGI);
	svm_set_intercept(svm, INTERCEPT_SKINIT);
	svm_set_intercept(svm, INTERCEPT_WBINVD);
	svm_set_intercept(svm, INTERCEPT_XSETBV);
	svm_set_intercept(svm, INTERCEPT_RDPRU);
	svm_set_intercept(svm, INTERCEPT_RSM);

	if (!kvm_mwait_in_guest(vcpu->kvm)) {
		svm_set_intercept(svm, INTERCEPT_MONITOR);
		svm_set_intercept(svm, INTERCEPT_MWAIT);
	}

	if (!kvm_hlt_in_guest(vcpu->kvm))
		svm_set_intercept(svm, INTERCEPT_HLT);

	control->iopm_base_pa = __sme_set(iopm_base);
	control->msrpm_base_pa = __sme_set(__pa(svm->msrpm));
	control->int_ctl = V_INTR_MASKING_MASK;

	init_seg(&save->es);
	init_seg(&save->ss);
	init_seg(&save->ds);
	init_seg(&save->fs);
	init_seg(&save->gs);

	save->cs.selector = 0xf000;
	save->cs.base = 0xffff0000;
	
	save->cs.attrib = SVM_SELECTOR_READ_MASK | SVM_SELECTOR_P_MASK | SVM_SELECTOR_S_MASK | SVM_SELECTOR_CODE_MASK;
	save->cs.limit = 0xffff;

	save->gdtr.base = 0;
	save->gdtr.limit = 0xffff;
	save->idtr.base = 0;
	save->idtr.limit = 0xffff;

	init_sys_seg(&save->ldtr, SEG_TYPE_LDT);
	init_sys_seg(&save->tr, SEG_TYPE_BUSY_TSS16);

	if (npt_enabled) {
		
		control->nested_ctl |= SVM_NESTED_CTL_NP_ENABLE;
		svm_clr_intercept(svm, INTERCEPT_INVLPG);
		clr_exception_intercept(svm, PF_VECTOR);
		svm_clr_intercept(svm, INTERCEPT_CR3_READ);
		svm_clr_intercept(svm, INTERCEPT_CR3_WRITE);
		save->g_pat = vcpu->arch.pat;
		save->cr3 = 0;
	}
	svm->current_vmcb->asid_generation = 0;
	svm->asid = 0;

	svm->nested.vmcb12_gpa = INVALID_GPA;
	svm->nested.last_vmcb12_gpa = INVALID_GPA;

	if (!kvm_pause_in_guest(vcpu->kvm)) {
		control->pause_filter_count = pause_filter_count;
		if (pause_filter_thresh)
			control->pause_filter_thresh = pause_filter_thresh;
		svm_set_intercept(svm, INTERCEPT_PAUSE);
	} else {
		svm_clr_intercept(svm, INTERCEPT_PAUSE);
	}

	svm_recalc_instruction_intercepts(vcpu, svm);

	
	if (boot_cpu_has(X86_FEATURE_V_SPEC_CTRL))
		set_msr_interception(vcpu, svm->msrpm, MSR_IA32_SPEC_CTRL, 1, 1);

	if (kvm_vcpu_apicv_active(vcpu))
		avic_init_vmcb(svm, vmcb);

	if (vgif) {
		svm_clr_intercept(svm, INTERCEPT_STGI);
		svm_clr_intercept(svm, INTERCEPT_CLGI);
		svm->vmcb->control.int_ctl |= V_GIF_ENABLE_MASK;
	}

	if (sev_guest(vcpu->kvm)) {
		svm->vmcb->control.nested_ctl |= SVM_NESTED_CTL_SEV_ENABLE;
		clr_exception_intercept(svm, UD_VECTOR);

		if (sev_es_guest(vcpu->kvm)) {
			
			sev_es_init_vmcb(svm);
		}
	}

	svm_hv_init_vmcb(vmcb);
	init_vmcb_after_set_cpuid(vcpu);

	vmcb_mark_all_dirty(vmcb);

	enable_gif(svm);
}

static void __svm_vcpu_reset(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	svm_vcpu_init_msrpm(vcpu, svm->msrpm);

	svm_init_osvw(vcpu);
	vcpu->arch.microcode_version = 0x01000065;
	svm->tsc_ratio_msr = kvm_default_tsc_scaling_ratio;

	if (sev_es_guest(vcpu->kvm))
		sev_es_vcpu_reset(svm);
}

static void svm_vcpu_reset(struct kvm_vcpu *vcpu, bool init_event)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	svm->spec_ctrl = 0;
	svm->virt_spec_ctrl = 0;

	init_vmcb(vcpu);

	if (!init_event)
		__svm_vcpu_reset(vcpu);
}

void svm_switch_vmcb(struct vcpu_svm *svm, struct kvm_vmcb_info *target_vmcb)
{
	svm->current_vmcb = target_vmcb;
	svm->vmcb = target_vmcb->ptr;
}

static int svm_vcpu_create(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm;
	struct page *vmcb01_page;
	struct page *vmsa_page = NULL;
	int err;

	BUILD_BUG_ON(offsetof(struct vcpu_svm, vcpu) != 0);
	svm = to_svm(vcpu);

	err = -ENOMEM;
	vmcb01_page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!vmcb01_page)
		goto out;

	if (sev_es_guest(vcpu->kvm)) {
		
		vmsa_page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
		if (!vmsa_page)
			goto error_free_vmcb_page;

		
		fpstate_set_confidential(&vcpu->arch.guest_fpu);
	}

	err = avic_init_vcpu(svm);
	if (err)
		goto error_free_vmsa_page;

	svm->msrpm = svm_vcpu_alloc_msrpm();
	if (!svm->msrpm) {
		err = -ENOMEM;
		goto error_free_vmsa_page;
	}

	svm->vmcb01.ptr = page_address(vmcb01_page);
	svm->vmcb01.pa = __sme_set(page_to_pfn(vmcb01_page) << PAGE_SHIFT);
	svm_switch_vmcb(svm, &svm->vmcb01);

	if (vmsa_page)
		svm->sev_es.vmsa = page_address(vmsa_page);

	svm->guest_state_loaded = false;

	return 0;

error_free_vmsa_page:
	if (vmsa_page)
		__free_page(vmsa_page);
error_free_vmcb_page:
	__free_page(vmcb01_page);
out:
	return err;
}

static void svm_clear_current_vmcb(struct vmcb *vmcb)
{
	int i;

	for_each_online_cpu(i)
		cmpxchg(&per_cpu(svm_data, i)->current_vmcb, vmcb, NULL);
}

static void svm_vcpu_free(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	
	svm_clear_current_vmcb(svm->vmcb);

	svm_free_nested(svm);

	sev_free_vcpu(vcpu);

	__free_page(pfn_to_page(__sme_clr(svm->vmcb01.pa) >> PAGE_SHIFT));
	__free_pages(virt_to_page(svm->msrpm), get_order(MSRPM_SIZE));
}

static void svm_prepare_switch_to_guest(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct svm_cpu_data *sd = per_cpu(svm_data, vcpu->cpu);

	if (sev_es_guest(vcpu->kvm))
		sev_es_unmap_ghcb(svm);

	if (svm->guest_state_loaded)
		return;

	
	vmsave(__sme_page_pa(sd->save_area));
	if (sev_es_guest(vcpu->kvm)) {
		struct vmcb_save_area *hostsa;
		hostsa = (struct vmcb_save_area *)(page_address(sd->save_area) + 0x400);

		sev_es_prepare_switch_to_guest(hostsa);
	}

	if (tsc_scaling)
		__svm_write_tsc_multiplier(vcpu->arch.tsc_scaling_ratio);

	if (likely(tsc_aux_uret_slot >= 0))
		kvm_set_user_return_msr(tsc_aux_uret_slot, svm->tsc_aux, -1ull);

	svm->guest_state_loaded = true;
}

static void svm_prepare_host_switch(struct kvm_vcpu *vcpu)
{
	to_svm(vcpu)->guest_state_loaded = false;
}

static void svm_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct svm_cpu_data *sd = per_cpu(svm_data, cpu);

	if (sd->current_vmcb != svm->vmcb) {
		sd->current_vmcb = svm->vmcb;
		indirect_branch_prediction_barrier();
	}
	if (kvm_vcpu_apicv_active(vcpu))
		__avic_vcpu_load(vcpu, cpu);
}

static void svm_vcpu_put(struct kvm_vcpu *vcpu)
{
	if (kvm_vcpu_apicv_active(vcpu))
		__avic_vcpu_put(vcpu);

	svm_prepare_host_switch(vcpu);

	++vcpu->stat.host_state_reload;
}

static unsigned long svm_get_rflags(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	unsigned long rflags = svm->vmcb->save.rflags;

	if (svm->nmi_singlestep) {
		
		if (!(svm->nmi_singlestep_guest_rflags & X86_EFLAGS_TF))
			rflags &= ~X86_EFLAGS_TF;
		if (!(svm->nmi_singlestep_guest_rflags & X86_EFLAGS_RF))
			rflags &= ~X86_EFLAGS_RF;
	}
	return rflags;
}

static void svm_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags)
{
	if (to_svm(vcpu)->nmi_singlestep)
		rflags |= (X86_EFLAGS_TF | X86_EFLAGS_RF);

       
	to_svm(vcpu)->vmcb->save.rflags = rflags;
}

static bool svm_get_if_flag(struct kvm_vcpu *vcpu)
{
	struct vmcb *vmcb = to_svm(vcpu)->vmcb;

	return sev_es_guest(vcpu->kvm)
		? vmcb->control.int_state & SVM_GUEST_INTERRUPT_MASK : kvm_get_rflags(vcpu) & X86_EFLAGS_IF;
}

static void svm_cache_reg(struct kvm_vcpu *vcpu, enum kvm_reg reg)
{
	kvm_register_mark_available(vcpu, reg);

	switch (reg) {
	case VCPU_EXREG_PDPTR:
		
		if (npt_enabled)
			load_pdptrs(vcpu, kvm_read_cr3(vcpu));
		break;
	default:
		KVM_BUG_ON(1, vcpu->kvm);
	}
}

static void svm_set_vintr(struct vcpu_svm *svm)
{
	struct vmcb_control_area *control;

	
	WARN_ON(kvm_vcpu_apicv_activated(&svm->vcpu));

	svm_set_intercept(svm, INTERCEPT_VINTR);

	
	control = &svm->vmcb->control;
	control->int_vector = 0x0;
	control->int_ctl &= ~V_INTR_PRIO_MASK;
	control->int_ctl |= V_IRQ_MASK | (( 0xf) << V_INTR_PRIO_SHIFT);
	vmcb_mark_dirty(svm->vmcb, VMCB_INTR);
}

static void svm_clear_vintr(struct vcpu_svm *svm)
{
	svm_clr_intercept(svm, INTERCEPT_VINTR);

	
	svm->vmcb->control.int_ctl &= ~V_IRQ_INJECTION_BITS_MASK;
	if (is_guest_mode(&svm->vcpu)) {
		svm->vmcb01.ptr->control.int_ctl &= ~V_IRQ_INJECTION_BITS_MASK;

		WARN_ON((svm->vmcb->control.int_ctl & V_TPR_MASK) != (svm->nested.ctl.int_ctl & V_TPR_MASK));

		svm->vmcb->control.int_ctl |= svm->nested.ctl.int_ctl & V_IRQ_INJECTION_BITS_MASK;

		svm->vmcb->control.int_vector = svm->nested.ctl.int_vector;
	}

	vmcb_mark_dirty(svm->vmcb, VMCB_INTR);
}

static struct vmcb_seg *svm_seg(struct kvm_vcpu *vcpu, int seg)
{
	struct vmcb_save_area *save = &to_svm(vcpu)->vmcb->save;
	struct vmcb_save_area *save01 = &to_svm(vcpu)->vmcb01.ptr->save;

	switch (seg) {
	case VCPU_SREG_CS: return &save->cs;
	case VCPU_SREG_DS: return &save->ds;
	case VCPU_SREG_ES: return &save->es;
	case VCPU_SREG_FS: return &save01->fs;
	case VCPU_SREG_GS: return &save01->gs;
	case VCPU_SREG_SS: return &save->ss;
	case VCPU_SREG_TR: return &save01->tr;
	case VCPU_SREG_LDTR: return &save01->ldtr;
	}
	BUG();
	return NULL;
}

static u64 svm_get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	struct vmcb_seg *s = svm_seg(vcpu, seg);

	return s->base;
}

static void svm_get_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg)
{
	struct vmcb_seg *s = svm_seg(vcpu, seg);

	var->base = s->base;
	var->limit = s->limit;
	var->selector = s->selector;
	var->type = s->attrib & SVM_SELECTOR_TYPE_MASK;
	var->s = (s->attrib >> SVM_SELECTOR_S_SHIFT) & 1;
	var->dpl = (s->attrib >> SVM_SELECTOR_DPL_SHIFT) & 3;
	var->present = (s->attrib >> SVM_SELECTOR_P_SHIFT) & 1;
	var->avl = (s->attrib >> SVM_SELECTOR_AVL_SHIFT) & 1;
	var->l = (s->attrib >> SVM_SELECTOR_L_SHIFT) & 1;
	var->db = (s->attrib >> SVM_SELECTOR_DB_SHIFT) & 1;

	
	var->g = s->limit > 0xfffff;

	
	var->unusable = !var->present;

	switch (seg) {
	case VCPU_SREG_TR:
		
		var->type |= 0x2;
		break;
	case VCPU_SREG_DS:
	case VCPU_SREG_ES:
	case VCPU_SREG_FS:
	case VCPU_SREG_GS:
		
		if (!var->unusable)
			var->type |= 0x1;
		break;
	case VCPU_SREG_SS:
		
		if (var->unusable)
			var->db = 0;
		
		var->dpl = to_svm(vcpu)->vmcb->save.cpl;
		break;
	}
}

static int svm_get_cpl(struct kvm_vcpu *vcpu)
{
	struct vmcb_save_area *save = &to_svm(vcpu)->vmcb->save;

	return save->cpl;
}

static void svm_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l)
{
	struct kvm_segment cs;

	svm_get_segment(vcpu, &cs, VCPU_SREG_CS);
	*db = cs.db;
	*l = cs.l;
}

static void svm_get_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	dt->size = svm->vmcb->save.idtr.limit;
	dt->address = svm->vmcb->save.idtr.base;
}

static void svm_set_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	svm->vmcb->save.idtr.limit = dt->size;
	svm->vmcb->save.idtr.base = dt->address ;
	vmcb_mark_dirty(svm->vmcb, VMCB_DT);
}

static void svm_get_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	dt->size = svm->vmcb->save.gdtr.limit;
	dt->address = svm->vmcb->save.gdtr.base;
}

static void svm_set_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	svm->vmcb->save.gdtr.limit = dt->size;
	svm->vmcb->save.gdtr.base = dt->address ;
	vmcb_mark_dirty(svm->vmcb, VMCB_DT);
}

static void sev_post_set_cr3(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	
	if (sev_es_guest(vcpu->kvm)) {
		svm->vmcb->save.cr3 = cr3;
		vmcb_mark_dirty(svm->vmcb, VMCB_CR);
	}
}

void svm_set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	u64 hcr0 = cr0;
	bool old_paging = is_paging(vcpu);


	if (vcpu->arch.efer & EFER_LME && !vcpu->arch.guest_state_protected) {
		if (!is_paging(vcpu) && (cr0 & X86_CR0_PG)) {
			vcpu->arch.efer |= EFER_LMA;
			svm->vmcb->save.efer |= EFER_LMA | EFER_LME;
		}

		if (is_paging(vcpu) && !(cr0 & X86_CR0_PG)) {
			vcpu->arch.efer &= ~EFER_LMA;
			svm->vmcb->save.efer &= ~(EFER_LMA | EFER_LME);
		}
	}

	vcpu->arch.cr0 = cr0;

	if (!npt_enabled) {
		hcr0 |= X86_CR0_PG | X86_CR0_WP;
		if (old_paging != is_paging(vcpu))
			svm_set_cr4(vcpu, kvm_read_cr4(vcpu));
	}

	
	if (kvm_check_has_quirk(vcpu->kvm, KVM_X86_QUIRK_CD_NW_CLEARED))
		hcr0 &= ~(X86_CR0_CD | X86_CR0_NW);

	svm->vmcb->save.cr0 = hcr0;
	vmcb_mark_dirty(svm->vmcb, VMCB_CR);

	
	if (sev_es_guest(vcpu->kvm))
		return;

	if (hcr0 == cr0) {
		
		svm_clr_intercept(svm, INTERCEPT_CR0_READ);
		svm_clr_intercept(svm, INTERCEPT_CR0_WRITE);
	} else {
		svm_set_intercept(svm, INTERCEPT_CR0_READ);
		svm_set_intercept(svm, INTERCEPT_CR0_WRITE);
	}
}

static bool svm_is_valid_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	return true;
}

void svm_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	unsigned long host_cr4_mce = cr4_read_shadow() & X86_CR4_MCE;
	unsigned long old_cr4 = vcpu->arch.cr4;

	if (npt_enabled && ((old_cr4 ^ cr4) & X86_CR4_PGE))
		svm_flush_tlb_current(vcpu);

	vcpu->arch.cr4 = cr4;
	if (!npt_enabled) {
		cr4 |= X86_CR4_PAE;

		if (!is_paging(vcpu))
			cr4 &= ~(X86_CR4_SMEP | X86_CR4_SMAP | X86_CR4_PKE);
	}
	cr4 |= host_cr4_mce;
	to_svm(vcpu)->vmcb->save.cr4 = cr4;
	vmcb_mark_dirty(to_svm(vcpu)->vmcb, VMCB_CR);

	if ((cr4 ^ old_cr4) & (X86_CR4_OSXSAVE | X86_CR4_PKE))
		kvm_update_cpuid_runtime(vcpu);
}

static void svm_set_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct vmcb_seg *s = svm_seg(vcpu, seg);

	s->base = var->base;
	s->limit = var->limit;
	s->selector = var->selector;
	s->attrib = (var->type & SVM_SELECTOR_TYPE_MASK);
	s->attrib |= (var->s & 1) << SVM_SELECTOR_S_SHIFT;
	s->attrib |= (var->dpl & 3) << SVM_SELECTOR_DPL_SHIFT;
	s->attrib |= ((var->present & 1) && !var->unusable) << SVM_SELECTOR_P_SHIFT;
	s->attrib |= (var->avl & 1) << SVM_SELECTOR_AVL_SHIFT;
	s->attrib |= (var->l & 1) << SVM_SELECTOR_L_SHIFT;
	s->attrib |= (var->db & 1) << SVM_SELECTOR_DB_SHIFT;
	s->attrib |= (var->g & 1) << SVM_SELECTOR_G_SHIFT;

	
	if (seg == VCPU_SREG_SS)
		
		svm->vmcb->save.cpl = (var->dpl & 3);

	vmcb_mark_dirty(svm->vmcb, VMCB_SEG);
}

static void svm_update_exception_bitmap(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	clr_exception_intercept(svm, BP_VECTOR);

	if (vcpu->guest_debug & KVM_GUESTDBG_ENABLE) {
		if (vcpu->guest_debug & KVM_GUESTDBG_USE_SW_BP)
			set_exception_intercept(svm, BP_VECTOR);
	}
}

static void new_asid(struct vcpu_svm *svm, struct svm_cpu_data *sd)
{
	if (sd->next_asid > sd->max_asid) {
		++sd->asid_generation;
		sd->next_asid = sd->min_asid;
		svm->vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
		vmcb_mark_dirty(svm->vmcb, VMCB_ASID);
	}

	svm->current_vmcb->asid_generation = sd->asid_generation;
	svm->asid = sd->next_asid++;
}

static void svm_set_dr6(struct vcpu_svm *svm, unsigned long value)
{
	struct vmcb *vmcb = svm->vmcb;

	if (svm->vcpu.arch.guest_state_protected)
		return;

	if (unlikely(value != vmcb->save.dr6)) {
		vmcb->save.dr6 = value;
		vmcb_mark_dirty(vmcb, VMCB_DR);
	}
}

static void svm_sync_dirty_debug_regs(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	if (vcpu->arch.guest_state_protected)
		return;

	get_debugreg(vcpu->arch.db[0], 0);
	get_debugreg(vcpu->arch.db[1], 1);
	get_debugreg(vcpu->arch.db[2], 2);
	get_debugreg(vcpu->arch.db[3], 3);
	
	vcpu->arch.dr6 = svm->vmcb->save.dr6;
	vcpu->arch.dr7 = svm->vmcb->save.dr7;
	vcpu->arch.switch_db_regs &= ~KVM_DEBUGREG_WONT_EXIT;
	set_dr_intercepts(svm);
}

static void svm_set_dr7(struct kvm_vcpu *vcpu, unsigned long value)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	if (vcpu->arch.guest_state_protected)
		return;

	svm->vmcb->save.dr7 = value;
	vmcb_mark_dirty(svm->vmcb, VMCB_DR);
}

static int pf_interception(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	u64 fault_address = svm->vmcb->control.exit_info_2;
	u64 error_code = svm->vmcb->control.exit_info_1;

	return kvm_handle_page_fault(vcpu, error_code, fault_address, static_cpu_has(X86_FEATURE_DECODEASSISTS) ? svm->vmcb->control.insn_bytes : NULL, svm->vmcb->control.insn_len);


}

static int npf_interception(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	u64 fault_address = svm->vmcb->control.exit_info_2;
	u64 error_code = svm->vmcb->control.exit_info_1;

	trace_kvm_page_fault(fault_address, error_code);
	return kvm_mmu_page_fault(vcpu, fault_address, error_code, static_cpu_has(X86_FEATURE_DECODEASSISTS) ? svm->vmcb->control.insn_bytes : NULL, svm->vmcb->control.insn_len);


}

static int db_interception(struct kvm_vcpu *vcpu)
{
	struct kvm_run *kvm_run = vcpu->run;
	struct vcpu_svm *svm = to_svm(vcpu);

	if (!(vcpu->guest_debug & (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP)) && !svm->nmi_singlestep) {

		u32 payload = svm->vmcb->save.dr6 ^ DR6_ACTIVE_LOW;
		kvm_queue_exception_p(vcpu, DB_VECTOR, payload);
		return 1;
	}

	if (svm->nmi_singlestep) {
		disable_nmi_singlestep(svm);
		
		kvm_make_request(KVM_REQ_EVENT, vcpu);
	}

	if (vcpu->guest_debug & (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP)) {
		kvm_run->exit_reason = KVM_EXIT_DEBUG;
		kvm_run->debug.arch.dr6 = svm->vmcb->save.dr6;
		kvm_run->debug.arch.dr7 = svm->vmcb->save.dr7;
		kvm_run->debug.arch.pc = svm->vmcb->save.cs.base + svm->vmcb->save.rip;
		kvm_run->debug.arch.exception = DB_VECTOR;
		return 0;
	}

	return 1;
}

static int bp_interception(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct kvm_run *kvm_run = vcpu->run;

	kvm_run->exit_reason = KVM_EXIT_DEBUG;
	kvm_run->debug.arch.pc = svm->vmcb->save.cs.base + svm->vmcb->save.rip;
	kvm_run->debug.arch.exception = BP_VECTOR;
	return 0;
}

static int ud_interception(struct kvm_vcpu *vcpu)
{
	return handle_ud(vcpu);
}

static int ac_interception(struct kvm_vcpu *vcpu)
{
	kvm_queue_exception_e(vcpu, AC_VECTOR, 0);
	return 1;
}

static bool is_erratum_383(void)
{
	int err, i;
	u64 value;

	if (!erratum_383_found)
		return false;

	value = native_read_msr_safe(MSR_IA32_MC0_STATUS, &err);
	if (err)
		return false;

	
	value &= ~(1ULL << 62);

	if (value != 0xb600000000010015ULL)
		return false;

	
	for (i = 0; i < 6; ++i)
		native_write_msr_safe(MSR_IA32_MCx_STATUS(i), 0, 0);

	value = native_read_msr_safe(MSR_IA32_MCG_STATUS, &err);
	if (!err) {
		u32 low, high;

		value &= ~(1ULL << 2);
		low    = lower_32_bits(value);
		high   = upper_32_bits(value);

		native_write_msr_safe(MSR_IA32_MCG_STATUS, low, high);
	}

	
	__flush_tlb_all();

	return true;
}

static void svm_handle_mce(struct kvm_vcpu *vcpu)
{
	if (is_erratum_383()) {
		
		pr_err("KVM: Guest triggered AMD Erratum 383\n");

		kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);

		return;
	}

	
	kvm_machine_check();
}

static int mc_interception(struct kvm_vcpu *vcpu)
{
	return 1;
}

static int shutdown_interception(struct kvm_vcpu *vcpu)
{
	struct kvm_run *kvm_run = vcpu->run;
	struct vcpu_svm *svm = to_svm(vcpu);

	
	if (sev_es_guest(vcpu->kvm))
		return -EINVAL;

	
	clear_page(svm->vmcb);
	kvm_vcpu_reset(vcpu, true);

	kvm_run->exit_reason = KVM_EXIT_SHUTDOWN;
	return 0;
}

static int io_interception(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	u32 io_info = svm->vmcb->control.exit_info_1; 
	int size, in, string;
	unsigned port;

	++vcpu->stat.io_exits;
	string = (io_info & SVM_IOIO_STR_MASK) != 0;
	in = (io_info & SVM_IOIO_TYPE_MASK) != 0;
	port = io_info >> 16;
	size = (io_info & SVM_IOIO_SIZE_MASK) >> SVM_IOIO_SIZE_SHIFT;

	if (string) {
		if (sev_es_guest(vcpu->kvm))
			return sev_es_string_io(svm, size, port, in);
		else return kvm_emulate_instruction(vcpu, 0);
	}

	svm->next_rip = svm->vmcb->control.exit_info_2;

	return kvm_fast_pio(vcpu, size, port, in);
}

static int nmi_interception(struct kvm_vcpu *vcpu)
{
	return 1;
}

static int smi_interception(struct kvm_vcpu *vcpu)
{
	return 1;
}

static int intr_interception(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.irq_exits;
	return 1;
}

static int vmload_vmsave_interception(struct kvm_vcpu *vcpu, bool vmload)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct vmcb *vmcb12;
	struct kvm_host_map map;
	int ret;

	if (nested_svm_check_permissions(vcpu))
		return 1;

	ret = kvm_vcpu_map(vcpu, gpa_to_gfn(svm->vmcb->save.rax), &map);
	if (ret) {
		if (ret == -EINVAL)
			kvm_inject_gp(vcpu, 0);
		return 1;
	}

	vmcb12 = map.hva;

	ret = kvm_skip_emulated_instruction(vcpu);

	if (vmload) {
		svm_copy_vmloadsave_state(svm->vmcb, vmcb12);
		svm->sysenter_eip_hi = 0;
		svm->sysenter_esp_hi = 0;
	} else {
		svm_copy_vmloadsave_state(vmcb12, svm->vmcb);
	}

	kvm_vcpu_unmap(vcpu, &map, true);

	return ret;
}

static int vmload_interception(struct kvm_vcpu *vcpu)
{
	return vmload_vmsave_interception(vcpu, true);
}

static int vmsave_interception(struct kvm_vcpu *vcpu)
{
	return vmload_vmsave_interception(vcpu, false);
}

static int vmrun_interception(struct kvm_vcpu *vcpu)
{
	if (nested_svm_check_permissions(vcpu))
		return 1;

	return nested_svm_vmrun(vcpu);
}

enum {
	NONE_SVM_INSTR, SVM_INSTR_VMRUN, SVM_INSTR_VMLOAD, SVM_INSTR_VMSAVE, };





static int svm_instr_opcode(struct kvm_vcpu *vcpu)
{
	struct x86_emulate_ctxt *ctxt = vcpu->arch.emulate_ctxt;

	if (ctxt->b != 0x1 || ctxt->opcode_len != 2)
		return NONE_SVM_INSTR;

	switch (ctxt->modrm) {
	case 0xd8: 
		return SVM_INSTR_VMRUN;
	case 0xda: 
		return SVM_INSTR_VMLOAD;
	case 0xdb: 
		return SVM_INSTR_VMSAVE;
	default:
		break;
	}

	return NONE_SVM_INSTR;
}

static int emulate_svm_instr(struct kvm_vcpu *vcpu, int opcode)
{
	const int guest_mode_exit_codes[] = {
		[SVM_INSTR_VMRUN] = SVM_EXIT_VMRUN, [SVM_INSTR_VMLOAD] = SVM_EXIT_VMLOAD, [SVM_INSTR_VMSAVE] = SVM_EXIT_VMSAVE, };


	int (*const svm_instr_handlers[])(struct kvm_vcpu *vcpu) = {
		[SVM_INSTR_VMRUN] = vmrun_interception, [SVM_INSTR_VMLOAD] = vmload_interception, [SVM_INSTR_VMSAVE] = vmsave_interception, };


	struct vcpu_svm *svm = to_svm(vcpu);
	int ret;

	if (is_guest_mode(vcpu)) {
		
		ret = nested_svm_simple_vmexit(svm, guest_mode_exit_codes[opcode]);
		if (ret)
			return ret;
		return 1;
	}
	return svm_instr_handlers[opcode](vcpu);
}


static int gp_interception(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	u32 error_code = svm->vmcb->control.exit_info_1;
	int opcode;

	
	if (error_code)
		goto reinject;

	
	if (x86_decode_emulated_instruction(vcpu, 0, NULL, 0) != EMULATION_OK)
		goto reinject;

	opcode = svm_instr_opcode(vcpu);

	if (opcode == NONE_SVM_INSTR) {
		if (!enable_vmware_backdoor)
			goto reinject;

		
		if (!is_guest_mode(vcpu))
			return kvm_emulate_instruction(vcpu, EMULTYPE_VMWARE_GP | EMULTYPE_NO_DECODE);
	} else {
		
		if (svm->vmcb->save.rax & ~PAGE_MASK)
			goto reinject;

		return emulate_svm_instr(vcpu, opcode);
	}

reinject:
	kvm_queue_exception_e(vcpu, GP_VECTOR, error_code);
	return 1;
}

void svm_set_gif(struct vcpu_svm *svm, bool value)
{
	if (value) {
		
		if (vgif)
			svm_clr_intercept(svm, INTERCEPT_STGI);
		if (svm_is_intercept(svm, INTERCEPT_VINTR))
			svm_clear_vintr(svm);

		enable_gif(svm);
		if (svm->vcpu.arch.smi_pending || svm->vcpu.arch.nmi_pending || kvm_cpu_has_injectable_intr(&svm->vcpu))

			kvm_make_request(KVM_REQ_EVENT, &svm->vcpu);
	} else {
		disable_gif(svm);

		
		if (!vgif)
			svm_clear_vintr(svm);
	}
}

static int stgi_interception(struct kvm_vcpu *vcpu)
{
	int ret;

	if (nested_svm_check_permissions(vcpu))
		return 1;

	ret = kvm_skip_emulated_instruction(vcpu);
	svm_set_gif(to_svm(vcpu), true);
	return ret;
}

static int clgi_interception(struct kvm_vcpu *vcpu)
{
	int ret;

	if (nested_svm_check_permissions(vcpu))
		return 1;

	ret = kvm_skip_emulated_instruction(vcpu);
	svm_set_gif(to_svm(vcpu), false);
	return ret;
}

static int invlpga_interception(struct kvm_vcpu *vcpu)
{
	gva_t gva = kvm_rax_read(vcpu);
	u32 asid = kvm_rcx_read(vcpu);

	
	if (!is_long_mode(vcpu))
		gva = (u32)gva;

	trace_kvm_invlpga(to_svm(vcpu)->vmcb->save.rip, asid, gva);

	
	kvm_mmu_invlpg(vcpu, gva);

	return kvm_skip_emulated_instruction(vcpu);
}

static int skinit_interception(struct kvm_vcpu *vcpu)
{
	trace_kvm_skinit(to_svm(vcpu)->vmcb->save.rip, kvm_rax_read(vcpu));

	kvm_queue_exception(vcpu, UD_VECTOR);
	return 1;
}

static int task_switch_interception(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	u16 tss_selector;
	int reason;
	int int_type = svm->vmcb->control.exit_int_info & SVM_EXITINTINFO_TYPE_MASK;
	int int_vec = svm->vmcb->control.exit_int_info & SVM_EVTINJ_VEC_MASK;
	uint32_t type = svm->vmcb->control.exit_int_info & SVM_EXITINTINFO_TYPE_MASK;
	uint32_t idt_v = svm->vmcb->control.exit_int_info & SVM_EXITINTINFO_VALID;
	bool has_error_code = false;
	u32 error_code = 0;

	tss_selector = (u16)svm->vmcb->control.exit_info_1;

	if (svm->vmcb->control.exit_info_2 & (1ULL << SVM_EXITINFOSHIFT_TS_REASON_IRET))
		reason = TASK_SWITCH_IRET;
	else if (svm->vmcb->control.exit_info_2 & (1ULL << SVM_EXITINFOSHIFT_TS_REASON_JMP))
		reason = TASK_SWITCH_JMP;
	else if (idt_v)
		reason = TASK_SWITCH_GATE;
	else reason = TASK_SWITCH_CALL;

	if (reason == TASK_SWITCH_GATE) {
		switch (type) {
		case SVM_EXITINTINFO_TYPE_NMI:
			vcpu->arch.nmi_injected = false;
			break;
		case SVM_EXITINTINFO_TYPE_EXEPT:
			if (svm->vmcb->control.exit_info_2 & (1ULL << SVM_EXITINFOSHIFT_TS_HAS_ERROR_CODE)) {
				has_error_code = true;
				error_code = (u32)svm->vmcb->control.exit_info_2;
			}
			kvm_clear_exception_queue(vcpu);
			break;
		case SVM_EXITINTINFO_TYPE_INTR:
			kvm_clear_interrupt_queue(vcpu);
			break;
		default:
			break;
		}
	}

	if (reason != TASK_SWITCH_GATE || int_type == SVM_EXITINTINFO_TYPE_SOFT || (int_type == SVM_EXITINTINFO_TYPE_EXEPT && (int_vec == OF_VECTOR || int_vec == BP_VECTOR))) {


		if (!svm_skip_emulated_instruction(vcpu))
			return 0;
	}

	if (int_type != SVM_EXITINTINFO_TYPE_SOFT)
		int_vec = -1;

	return kvm_task_switch(vcpu, tss_selector, int_vec, reason, has_error_code, error_code);
}

static int iret_interception(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	++vcpu->stat.nmi_window_exits;
	vcpu->arch.hflags |= HF_IRET_MASK;
	if (!sev_es_guest(vcpu->kvm)) {
		svm_clr_intercept(svm, INTERCEPT_IRET);
		svm->nmi_iret_rip = kvm_rip_read(vcpu);
	}
	kvm_make_request(KVM_REQ_EVENT, vcpu);
	return 1;
}

static int invlpg_interception(struct kvm_vcpu *vcpu)
{
	if (!static_cpu_has(X86_FEATURE_DECODEASSISTS))
		return kvm_emulate_instruction(vcpu, 0);

	kvm_mmu_invlpg(vcpu, to_svm(vcpu)->vmcb->control.exit_info_1);
	return kvm_skip_emulated_instruction(vcpu);
}

static int emulate_on_interception(struct kvm_vcpu *vcpu)
{
	return kvm_emulate_instruction(vcpu, 0);
}

static int rsm_interception(struct kvm_vcpu *vcpu)
{
	return kvm_emulate_instruction_from_buffer(vcpu, rsm_ins_bytes, 2);
}

static bool check_selective_cr0_intercepted(struct kvm_vcpu *vcpu, unsigned long val)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	unsigned long cr0 = vcpu->arch.cr0;
	bool ret = false;

	if (!is_guest_mode(vcpu) || (!(vmcb12_is_intercept(&svm->nested.ctl, INTERCEPT_SELECTIVE_CR0))))
		return false;

	cr0 &= ~SVM_CR0_SELECTIVE_MASK;
	val &= ~SVM_CR0_SELECTIVE_MASK;

	if (cr0 ^ val) {
		svm->vmcb->control.exit_code = SVM_EXIT_CR0_SEL_WRITE;
		ret = (nested_svm_exit_handled(svm) == NESTED_EXIT_DONE);
	}

	return ret;
}



static int cr_interception(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	int reg, cr;
	unsigned long val;
	int err;

	if (!static_cpu_has(X86_FEATURE_DECODEASSISTS))
		return emulate_on_interception(vcpu);

	if (unlikely((svm->vmcb->control.exit_info_1 & CR_VALID) == 0))
		return emulate_on_interception(vcpu);

	reg = svm->vmcb->control.exit_info_1 & SVM_EXITINFO_REG_MASK;
	if (svm->vmcb->control.exit_code == SVM_EXIT_CR0_SEL_WRITE)
		cr = SVM_EXIT_WRITE_CR0 - SVM_EXIT_READ_CR0;
	else cr = svm->vmcb->control.exit_code - SVM_EXIT_READ_CR0;

	err = 0;
	if (cr >= 16) { 
		cr -= 16;
		val = kvm_register_read(vcpu, reg);
		trace_kvm_cr_write(cr, val);
		switch (cr) {
		case 0:
			if (!check_selective_cr0_intercepted(vcpu, val))
				err = kvm_set_cr0(vcpu, val);
			else return 1;

			break;
		case 3:
			err = kvm_set_cr3(vcpu, val);
			break;
		case 4:
			err = kvm_set_cr4(vcpu, val);
			break;
		case 8:
			err = kvm_set_cr8(vcpu, val);
			break;
		default:
			WARN(1, "unhandled write to CR%d", cr);
			kvm_queue_exception(vcpu, UD_VECTOR);
			return 1;
		}
	} else { 
		switch (cr) {
		case 0:
			val = kvm_read_cr0(vcpu);
			break;
		case 2:
			val = vcpu->arch.cr2;
			break;
		case 3:
			val = kvm_read_cr3(vcpu);
			break;
		case 4:
			val = kvm_read_cr4(vcpu);
			break;
		case 8:
			val = kvm_get_cr8(vcpu);
			break;
		default:
			WARN(1, "unhandled read from CR%d", cr);
			kvm_queue_exception(vcpu, UD_VECTOR);
			return 1;
		}
		kvm_register_write(vcpu, reg, val);
		trace_kvm_cr_read(cr, val);
	}
	return kvm_complete_insn_gp(vcpu, err);
}

static int cr_trap(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	unsigned long old_value, new_value;
	unsigned int cr;
	int ret = 0;

	new_value = (unsigned long)svm->vmcb->control.exit_info_1;

	cr = svm->vmcb->control.exit_code - SVM_EXIT_CR0_WRITE_TRAP;
	switch (cr) {
	case 0:
		old_value = kvm_read_cr0(vcpu);
		svm_set_cr0(vcpu, new_value);

		kvm_post_set_cr0(vcpu, old_value, new_value);
		break;
	case 4:
		old_value = kvm_read_cr4(vcpu);
		svm_set_cr4(vcpu, new_value);

		kvm_post_set_cr4(vcpu, old_value, new_value);
		break;
	case 8:
		ret = kvm_set_cr8(vcpu, new_value);
		break;
	default:
		WARN(1, "unhandled CR%d write trap", cr);
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	return kvm_complete_insn_gp(vcpu, ret);
}

static int dr_interception(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	int reg, dr;
	unsigned long val;
	int err = 0;

	if (vcpu->guest_debug == 0) {
		
		clr_dr_intercepts(svm);
		vcpu->arch.switch_db_regs |= KVM_DEBUGREG_WONT_EXIT;
		return 1;
	}

	if (!boot_cpu_has(X86_FEATURE_DECODEASSISTS))
		return emulate_on_interception(vcpu);

	reg = svm->vmcb->control.exit_info_1 & SVM_EXITINFO_REG_MASK;
	dr = svm->vmcb->control.exit_code - SVM_EXIT_READ_DR0;
	if (dr >= 16) { 
		dr -= 16;
		val = kvm_register_read(vcpu, reg);
		err = kvm_set_dr(vcpu, dr, val);
	} else {
		kvm_get_dr(vcpu, dr, &val);
		kvm_register_write(vcpu, reg, val);
	}

	return kvm_complete_insn_gp(vcpu, err);
}

static int cr8_write_interception(struct kvm_vcpu *vcpu)
{
	int r;

	u8 cr8_prev = kvm_get_cr8(vcpu);
	
	r = cr_interception(vcpu);
	if (lapic_in_kernel(vcpu))
		return r;
	if (cr8_prev <= kvm_get_cr8(vcpu))
		return r;
	vcpu->run->exit_reason = KVM_EXIT_SET_TPR;
	return 0;
}

static int efer_trap(struct kvm_vcpu *vcpu)
{
	struct msr_data msr_info;
	int ret;

	
	msr_info.host_initiated = false;
	msr_info.index = MSR_EFER;
	msr_info.data = to_svm(vcpu)->vmcb->control.exit_info_1 & ~EFER_SVME;
	ret = kvm_set_msr_common(vcpu, &msr_info);

	return kvm_complete_insn_gp(vcpu, ret);
}

static int svm_get_msr_feature(struct kvm_msr_entry *msr)
{
	msr->data = 0;

	switch (msr->index) {
	case MSR_F10H_DECFG:
		if (boot_cpu_has(X86_FEATURE_LFENCE_RDTSC))
			msr->data |= MSR_F10H_DECFG_LFENCE_SERIALIZE;
		break;
	case MSR_IA32_PERF_CAPABILITIES:
		return 0;
	default:
		return KVM_MSR_RET_INVALID;
	}

	return 0;
}

static int svm_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	switch (msr_info->index) {
	case MSR_AMD64_TSC_RATIO:
		if (!msr_info->host_initiated && !svm->tsc_scaling_enabled)
			return 1;
		msr_info->data = svm->tsc_ratio_msr;
		break;
	case MSR_STAR:
		msr_info->data = svm->vmcb01.ptr->save.star;
		break;

	case MSR_LSTAR:
		msr_info->data = svm->vmcb01.ptr->save.lstar;
		break;
	case MSR_CSTAR:
		msr_info->data = svm->vmcb01.ptr->save.cstar;
		break;
	case MSR_KERNEL_GS_BASE:
		msr_info->data = svm->vmcb01.ptr->save.kernel_gs_base;
		break;
	case MSR_SYSCALL_MASK:
		msr_info->data = svm->vmcb01.ptr->save.sfmask;
		break;

	case MSR_IA32_SYSENTER_CS:
		msr_info->data = svm->vmcb01.ptr->save.sysenter_cs;
		break;
	case MSR_IA32_SYSENTER_EIP:
		msr_info->data = (u32)svm->vmcb01.ptr->save.sysenter_eip;
		if (guest_cpuid_is_intel(vcpu))
			msr_info->data |= (u64)svm->sysenter_eip_hi << 32;
		break;
	case MSR_IA32_SYSENTER_ESP:
		msr_info->data = svm->vmcb01.ptr->save.sysenter_esp;
		if (guest_cpuid_is_intel(vcpu))
			msr_info->data |= (u64)svm->sysenter_esp_hi << 32;
		break;
	case MSR_TSC_AUX:
		msr_info->data = svm->tsc_aux;
		break;
	case MSR_IA32_DEBUGCTLMSR:
	case MSR_IA32_LASTBRANCHFROMIP:
	case MSR_IA32_LASTBRANCHTOIP:
	case MSR_IA32_LASTINTFROMIP:
	case MSR_IA32_LASTINTTOIP:
		msr_info->data = svm_get_lbr_msr(svm, msr_info->index);
		break;
	case MSR_VM_HSAVE_PA:
		msr_info->data = svm->nested.hsave_msr;
		break;
	case MSR_VM_CR:
		msr_info->data = svm->nested.vm_cr_msr;
		break;
	case MSR_IA32_SPEC_CTRL:
		if (!msr_info->host_initiated && !guest_has_spec_ctrl_msr(vcpu))
			return 1;

		if (boot_cpu_has(X86_FEATURE_V_SPEC_CTRL))
			msr_info->data = svm->vmcb->save.spec_ctrl;
		else msr_info->data = svm->spec_ctrl;
		break;
	case MSR_AMD64_VIRT_SPEC_CTRL:
		if (!msr_info->host_initiated && !guest_cpuid_has(vcpu, X86_FEATURE_VIRT_SSBD))
			return 1;

		msr_info->data = svm->virt_spec_ctrl;
		break;
	case MSR_F15H_IC_CFG: {

		int family, model;

		family = guest_cpuid_family(vcpu);
		model  = guest_cpuid_model(vcpu);

		if (family < 0 || model < 0)
			return kvm_get_msr_common(vcpu, msr_info);

		msr_info->data = 0;

		if (family == 0x15 && (model >= 0x2 && model < 0x20))
			msr_info->data = 0x1E;
		}
		break;
	case MSR_F10H_DECFG:
		msr_info->data = svm->msr_decfg;
		break;
	default:
		return kvm_get_msr_common(vcpu, msr_info);
	}
	return 0;
}

static int svm_complete_emulated_msr(struct kvm_vcpu *vcpu, int err)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	if (!err || !sev_es_guest(vcpu->kvm) || WARN_ON_ONCE(!svm->sev_es.ghcb))
		return kvm_complete_insn_gp(vcpu, err);

	ghcb_set_sw_exit_info_1(svm->sev_es.ghcb, 1);
	ghcb_set_sw_exit_info_2(svm->sev_es.ghcb, X86_TRAP_GP | SVM_EVTINJ_TYPE_EXEPT | SVM_EVTINJ_VALID);


	return 1;
}

static int svm_set_vm_cr(struct kvm_vcpu *vcpu, u64 data)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	int svm_dis, chg_mask;

	if (data & ~SVM_VM_CR_VALID_MASK)
		return 1;

	chg_mask = SVM_VM_CR_VALID_MASK;

	if (svm->nested.vm_cr_msr & SVM_VM_CR_SVM_DIS_MASK)
		chg_mask &= ~(SVM_VM_CR_SVM_LOCK_MASK | SVM_VM_CR_SVM_DIS_MASK);

	svm->nested.vm_cr_msr &= ~chg_mask;
	svm->nested.vm_cr_msr |= (data & chg_mask);

	svm_dis = svm->nested.vm_cr_msr & SVM_VM_CR_SVM_DIS_MASK;

	
	if (svm_dis && (vcpu->arch.efer & EFER_SVME))
		return 1;

	return 0;
}

static int svm_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	int r;

	u32 ecx = msr->index;
	u64 data = msr->data;
	switch (ecx) {
	case MSR_AMD64_TSC_RATIO:

		if (!svm->tsc_scaling_enabled) {

			if (!msr->host_initiated)
				return 1;
			
			if (data != 0 && data != svm->tsc_ratio_msr)
				return 1;
			break;
		}

		if (data & SVM_TSC_RATIO_RSVD)
			return 1;

		svm->tsc_ratio_msr = data;

		if (svm->tsc_scaling_enabled && is_guest_mode(vcpu))
			nested_svm_update_tsc_ratio_msr(vcpu);

		break;
	case MSR_IA32_CR_PAT:
		if (!kvm_mtrr_valid(vcpu, MSR_IA32_CR_PAT, data))
			return 1;
		vcpu->arch.pat = data;
		svm->vmcb01.ptr->save.g_pat = data;
		if (is_guest_mode(vcpu))
			nested_vmcb02_compute_g_pat(svm);
		vmcb_mark_dirty(svm->vmcb, VMCB_NPT);
		break;
	case MSR_IA32_SPEC_CTRL:
		if (!msr->host_initiated && !guest_has_spec_ctrl_msr(vcpu))
			return 1;

		if (kvm_spec_ctrl_test_value(data))
			return 1;

		if (boot_cpu_has(X86_FEATURE_V_SPEC_CTRL))
			svm->vmcb->save.spec_ctrl = data;
		else svm->spec_ctrl = data;
		if (!data)
			break;

		
		set_msr_interception(vcpu, svm->msrpm, MSR_IA32_SPEC_CTRL, 1, 1);
		break;
	case MSR_IA32_PRED_CMD:
		if (!msr->host_initiated && !guest_has_pred_cmd_msr(vcpu))
			return 1;

		if (data & ~PRED_CMD_IBPB)
			return 1;
		if (!boot_cpu_has(X86_FEATURE_IBPB))
			return 1;
		if (!data)
			break;

		wrmsrl(MSR_IA32_PRED_CMD, PRED_CMD_IBPB);
		set_msr_interception(vcpu, svm->msrpm, MSR_IA32_PRED_CMD, 0, 1);
		break;
	case MSR_AMD64_VIRT_SPEC_CTRL:
		if (!msr->host_initiated && !guest_cpuid_has(vcpu, X86_FEATURE_VIRT_SSBD))
			return 1;

		if (data & ~SPEC_CTRL_SSBD)
			return 1;

		svm->virt_spec_ctrl = data;
		break;
	case MSR_STAR:
		svm->vmcb01.ptr->save.star = data;
		break;

	case MSR_LSTAR:
		svm->vmcb01.ptr->save.lstar = data;
		break;
	case MSR_CSTAR:
		svm->vmcb01.ptr->save.cstar = data;
		break;
	case MSR_KERNEL_GS_BASE:
		svm->vmcb01.ptr->save.kernel_gs_base = data;
		break;
	case MSR_SYSCALL_MASK:
		svm->vmcb01.ptr->save.sfmask = data;
		break;

	case MSR_IA32_SYSENTER_CS:
		svm->vmcb01.ptr->save.sysenter_cs = data;
		break;
	case MSR_IA32_SYSENTER_EIP:
		svm->vmcb01.ptr->save.sysenter_eip = (u32)data;
		
		svm->sysenter_eip_hi = guest_cpuid_is_intel(vcpu) ? (data >> 32) : 0;
		break;
	case MSR_IA32_SYSENTER_ESP:
		svm->vmcb01.ptr->save.sysenter_esp = (u32)data;
		svm->sysenter_esp_hi = guest_cpuid_is_intel(vcpu) ? (data >> 32) : 0;
		break;
	case MSR_TSC_AUX:
		
		preempt_disable();
		r = kvm_set_user_return_msr(tsc_aux_uret_slot, data, -1ull);
		preempt_enable();
		if (r)
			return 1;

		svm->tsc_aux = data;
		break;
	case MSR_IA32_DEBUGCTLMSR:
		if (!lbrv) {
			vcpu_unimpl(vcpu, "%s: MSR_IA32_DEBUGCTL 0x%llx, nop\n", __func__, data);
			break;
		}
		if (data & DEBUGCTL_RESERVED_BITS)
			return 1;

		if (svm->vmcb->control.virt_ext & LBR_CTL_ENABLE_MASK)
			svm->vmcb->save.dbgctl = data;
		else svm->vmcb01.ptr->save.dbgctl = data;

		svm_update_lbrv(vcpu);

		break;
	case MSR_VM_HSAVE_PA:
		
		if (!msr->host_initiated && !page_address_valid(vcpu, data))
			return 1;

		svm->nested.hsave_msr = data & PAGE_MASK;
		break;
	case MSR_VM_CR:
		return svm_set_vm_cr(vcpu, data);
	case MSR_VM_IGNNE:
		vcpu_unimpl(vcpu, "unimplemented wrmsr: 0x%x data 0x%llx\n", ecx, data);
		break;
	case MSR_F10H_DECFG: {
		struct kvm_msr_entry msr_entry;

		msr_entry.index = msr->index;
		if (svm_get_msr_feature(&msr_entry))
			return 1;

		
		if (data & ~msr_entry.data)
			return 1;

		
		if (!msr->host_initiated && (data ^ msr_entry.data))
			return 1;

		svm->msr_decfg = data;
		break;
	}
	default:
		return kvm_set_msr_common(vcpu, msr);
	}
	return 0;
}

static int msr_interception(struct kvm_vcpu *vcpu)
{
	if (to_svm(vcpu)->vmcb->control.exit_info_1)
		return kvm_emulate_wrmsr(vcpu);
	else return kvm_emulate_rdmsr(vcpu);
}

static int interrupt_window_interception(struct kvm_vcpu *vcpu)
{
	kvm_make_request(KVM_REQ_EVENT, vcpu);
	svm_clear_vintr(to_svm(vcpu));

	
	kvm_clear_apicv_inhibit(vcpu->kvm, APICV_INHIBIT_REASON_IRQWIN);

	++vcpu->stat.irq_window_exits;
	return 1;
}

static int pause_interception(struct kvm_vcpu *vcpu)
{
	bool in_kernel;
	
	in_kernel = !sev_es_guest(vcpu->kvm) && svm_get_cpl(vcpu) == 0;

	grow_ple_window(vcpu);

	kvm_vcpu_on_spin(vcpu, in_kernel);
	return kvm_skip_emulated_instruction(vcpu);
}

static int invpcid_interception(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	unsigned long type;
	gva_t gva;

	if (!guest_cpuid_has(vcpu, X86_FEATURE_INVPCID)) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	
	type = svm->vmcb->control.exit_info_2;
	gva = svm->vmcb->control.exit_info_1;

	return kvm_handle_invpcid(vcpu, type, gva);
}

static int (*const svm_exit_handlers[])(struct kvm_vcpu *vcpu) = {
	[SVM_EXIT_READ_CR0]			= cr_interception, [SVM_EXIT_READ_CR3]			= cr_interception, [SVM_EXIT_READ_CR4]			= cr_interception, [SVM_EXIT_READ_CR8]			= cr_interception, [SVM_EXIT_CR0_SEL_WRITE]		= cr_interception, [SVM_EXIT_WRITE_CR0]			= cr_interception, [SVM_EXIT_WRITE_CR3]			= cr_interception, [SVM_EXIT_WRITE_CR4]			= cr_interception, [SVM_EXIT_WRITE_CR8]			= cr8_write_interception, [SVM_EXIT_READ_DR0]			= dr_interception, [SVM_EXIT_READ_DR1]			= dr_interception, [SVM_EXIT_READ_DR2]			= dr_interception, [SVM_EXIT_READ_DR3]			= dr_interception, [SVM_EXIT_READ_DR4]			= dr_interception, [SVM_EXIT_READ_DR5]			= dr_interception, [SVM_EXIT_READ_DR6]			= dr_interception, [SVM_EXIT_READ_DR7]			= dr_interception, [SVM_EXIT_WRITE_DR0]			= dr_interception, [SVM_EXIT_WRITE_DR1]			= dr_interception, [SVM_EXIT_WRITE_DR2]			= dr_interception, [SVM_EXIT_WRITE_DR3]			= dr_interception, [SVM_EXIT_WRITE_DR4]			= dr_interception, [SVM_EXIT_WRITE_DR5]			= dr_interception, [SVM_EXIT_WRITE_DR6]			= dr_interception, [SVM_EXIT_WRITE_DR7]			= dr_interception, [SVM_EXIT_EXCP_BASE + DB_VECTOR]	= db_interception, [SVM_EXIT_EXCP_BASE + BP_VECTOR]	= bp_interception, [SVM_EXIT_EXCP_BASE + UD_VECTOR]	= ud_interception, [SVM_EXIT_EXCP_BASE + PF_VECTOR]	= pf_interception, [SVM_EXIT_EXCP_BASE + MC_VECTOR]	= mc_interception, [SVM_EXIT_EXCP_BASE + AC_VECTOR]	= ac_interception, [SVM_EXIT_EXCP_BASE + GP_VECTOR]	= gp_interception, [SVM_EXIT_INTR]				= intr_interception, [SVM_EXIT_NMI]				= nmi_interception, [SVM_EXIT_SMI]				= smi_interception, [SVM_EXIT_VINTR]			= interrupt_window_interception, [SVM_EXIT_RDPMC]			= kvm_emulate_rdpmc, [SVM_EXIT_CPUID]			= kvm_emulate_cpuid, [SVM_EXIT_IRET]                         = iret_interception, [SVM_EXIT_INVD]                         = kvm_emulate_invd, [SVM_EXIT_PAUSE]			= pause_interception, [SVM_EXIT_HLT]				= kvm_emulate_halt, [SVM_EXIT_INVLPG]			= invlpg_interception, [SVM_EXIT_INVLPGA]			= invlpga_interception, [SVM_EXIT_IOIO]				= io_interception, [SVM_EXIT_MSR]				= msr_interception, [SVM_EXIT_TASK_SWITCH]			= task_switch_interception, [SVM_EXIT_SHUTDOWN]			= shutdown_interception, [SVM_EXIT_VMRUN]			= vmrun_interception, [SVM_EXIT_VMMCALL]			= kvm_emulate_hypercall, [SVM_EXIT_VMLOAD]			= vmload_interception, [SVM_EXIT_VMSAVE]			= vmsave_interception, [SVM_EXIT_STGI]				= stgi_interception, [SVM_EXIT_CLGI]				= clgi_interception, [SVM_EXIT_SKINIT]			= skinit_interception, [SVM_EXIT_RDTSCP]			= kvm_handle_invalid_op, [SVM_EXIT_WBINVD]                       = kvm_emulate_wbinvd, [SVM_EXIT_MONITOR]			= kvm_emulate_monitor, [SVM_EXIT_MWAIT]			= kvm_emulate_mwait, [SVM_EXIT_XSETBV]			= kvm_emulate_xsetbv, [SVM_EXIT_RDPRU]			= kvm_handle_invalid_op, [SVM_EXIT_EFER_WRITE_TRAP]		= efer_trap, [SVM_EXIT_CR0_WRITE_TRAP]		= cr_trap, [SVM_EXIT_CR4_WRITE_TRAP]		= cr_trap, [SVM_EXIT_CR8_WRITE_TRAP]		= cr_trap, [SVM_EXIT_INVPCID]                      = invpcid_interception, [SVM_EXIT_NPF]				= npf_interception, [SVM_EXIT_RSM]                          = rsm_interception, [SVM_EXIT_AVIC_INCOMPLETE_IPI]		= avic_incomplete_ipi_interception, [SVM_EXIT_AVIC_UNACCELERATED_ACCESS]	= avic_unaccelerated_access_interception, [SVM_EXIT_VMGEXIT]			= sev_handle_vmgexit, };







































































static void dump_vmcb(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct vmcb_control_area *control = &svm->vmcb->control;
	struct vmcb_save_area *save = &svm->vmcb->save;
	struct vmcb_save_area *save01 = &svm->vmcb01.ptr->save;

	if (!dump_invalid_vmcb) {
		pr_warn_ratelimited("set kvm_amd.dump_invalid_vmcb=1 to dump internal KVM state.\n");
		return;
	}

	pr_err("VMCB %p, last attempted VMRUN on CPU %d\n", svm->current_vmcb->ptr, vcpu->arch.last_vmentry_cpu);
	pr_err("VMCB Control Area:\n");
	pr_err("%-20s%04x\n", "cr_read:", control->intercepts[INTERCEPT_CR] & 0xffff);
	pr_err("%-20s%04x\n", "cr_write:", control->intercepts[INTERCEPT_CR] >> 16);
	pr_err("%-20s%04x\n", "dr_read:", control->intercepts[INTERCEPT_DR] & 0xffff);
	pr_err("%-20s%04x\n", "dr_write:", control->intercepts[INTERCEPT_DR] >> 16);
	pr_err("%-20s%08x\n", "exceptions:", control->intercepts[INTERCEPT_EXCEPTION]);
	pr_err("%-20s%08x %08x\n", "intercepts:", control->intercepts[INTERCEPT_WORD3], control->intercepts[INTERCEPT_WORD4]);

	pr_err("%-20s%d\n", "pause filter count:", control->pause_filter_count);
	pr_err("%-20s%d\n", "pause filter threshold:", control->pause_filter_thresh);
	pr_err("%-20s%016llx\n", "iopm_base_pa:", control->iopm_base_pa);
	pr_err("%-20s%016llx\n", "msrpm_base_pa:", control->msrpm_base_pa);
	pr_err("%-20s%016llx\n", "tsc_offset:", control->tsc_offset);
	pr_err("%-20s%d\n", "asid:", control->asid);
	pr_err("%-20s%d\n", "tlb_ctl:", control->tlb_ctl);
	pr_err("%-20s%08x\n", "int_ctl:", control->int_ctl);
	pr_err("%-20s%08x\n", "int_vector:", control->int_vector);
	pr_err("%-20s%08x\n", "int_state:", control->int_state);
	pr_err("%-20s%08x\n", "exit_code:", control->exit_code);
	pr_err("%-20s%016llx\n", "exit_info1:", control->exit_info_1);
	pr_err("%-20s%016llx\n", "exit_info2:", control->exit_info_2);
	pr_err("%-20s%08x\n", "exit_int_info:", control->exit_int_info);
	pr_err("%-20s%08x\n", "exit_int_info_err:", control->exit_int_info_err);
	pr_err("%-20s%lld\n", "nested_ctl:", control->nested_ctl);
	pr_err("%-20s%016llx\n", "nested_cr3:", control->nested_cr3);
	pr_err("%-20s%016llx\n", "avic_vapic_bar:", control->avic_vapic_bar);
	pr_err("%-20s%016llx\n", "ghcb:", control->ghcb_gpa);
	pr_err("%-20s%08x\n", "event_inj:", control->event_inj);
	pr_err("%-20s%08x\n", "event_inj_err:", control->event_inj_err);
	pr_err("%-20s%lld\n", "virt_ext:", control->virt_ext);
	pr_err("%-20s%016llx\n", "next_rip:", control->next_rip);
	pr_err("%-20s%016llx\n", "avic_backing_page:", control->avic_backing_page);
	pr_err("%-20s%016llx\n", "avic_logical_id:", control->avic_logical_id);
	pr_err("%-20s%016llx\n", "avic_physical_id:", control->avic_physical_id);
	pr_err("%-20s%016llx\n", "vmsa_pa:", control->vmsa_pa);
	pr_err("VMCB State Save Area:\n");
	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n", "es:", save->es.selector, save->es.attrib, save->es.limit, save->es.base);


	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n", "cs:", save->cs.selector, save->cs.attrib, save->cs.limit, save->cs.base);


	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n", "ss:", save->ss.selector, save->ss.attrib, save->ss.limit, save->ss.base);


	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n", "ds:", save->ds.selector, save->ds.attrib, save->ds.limit, save->ds.base);


	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n", "fs:", save01->fs.selector, save01->fs.attrib, save01->fs.limit, save01->fs.base);


	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n", "gs:", save01->gs.selector, save01->gs.attrib, save01->gs.limit, save01->gs.base);


	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n", "gdtr:", save->gdtr.selector, save->gdtr.attrib, save->gdtr.limit, save->gdtr.base);


	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n", "ldtr:", save01->ldtr.selector, save01->ldtr.attrib, save01->ldtr.limit, save01->ldtr.base);


	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n", "idtr:", save->idtr.selector, save->idtr.attrib, save->idtr.limit, save->idtr.base);


	pr_err("%-5s s: %04x a: %04x l: %08x b: %016llx\n", "tr:", save01->tr.selector, save01->tr.attrib, save01->tr.limit, save01->tr.base);


	pr_err("cpl:            %d                efer:         %016llx\n", save->cpl, save->efer);
	pr_err("%-15s %016llx %-13s %016llx\n", "cr0:", save->cr0, "cr2:", save->cr2);
	pr_err("%-15s %016llx %-13s %016llx\n", "cr3:", save->cr3, "cr4:", save->cr4);
	pr_err("%-15s %016llx %-13s %016llx\n", "dr6:", save->dr6, "dr7:", save->dr7);
	pr_err("%-15s %016llx %-13s %016llx\n", "rip:", save->rip, "rflags:", save->rflags);
	pr_err("%-15s %016llx %-13s %016llx\n", "rsp:", save->rsp, "rax:", save->rax);
	pr_err("%-15s %016llx %-13s %016llx\n", "star:", save01->star, "lstar:", save01->lstar);
	pr_err("%-15s %016llx %-13s %016llx\n", "cstar:", save01->cstar, "sfmask:", save01->sfmask);
	pr_err("%-15s %016llx %-13s %016llx\n", "kernel_gs_base:", save01->kernel_gs_base, "sysenter_cs:", save01->sysenter_cs);

	pr_err("%-15s %016llx %-13s %016llx\n", "sysenter_esp:", save01->sysenter_esp, "sysenter_eip:", save01->sysenter_eip);

	pr_err("%-15s %016llx %-13s %016llx\n", "gpat:", save->g_pat, "dbgctl:", save->dbgctl);
	pr_err("%-15s %016llx %-13s %016llx\n", "br_from:", save->br_from, "br_to:", save->br_to);
	pr_err("%-15s %016llx %-13s %016llx\n", "excp_from:", save->last_excp_from, "excp_to:", save->last_excp_to);

}

static bool svm_check_exit_valid(u64 exit_code)
{
	return (exit_code < ARRAY_SIZE(svm_exit_handlers) && svm_exit_handlers[exit_code]);
}

static int svm_handle_invalid_exit(struct kvm_vcpu *vcpu, u64 exit_code)
{
	vcpu_unimpl(vcpu, "svm: unexpected exit reason 0x%llx\n", exit_code);
	dump_vmcb(vcpu);
	vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
	vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_UNEXPECTED_EXIT_REASON;
	vcpu->run->internal.ndata = 2;
	vcpu->run->internal.data[0] = exit_code;
	vcpu->run->internal.data[1] = vcpu->arch.last_vmentry_cpu;
	return 0;
}

int svm_invoke_exit_handler(struct kvm_vcpu *vcpu, u64 exit_code)
{
	if (!svm_check_exit_valid(exit_code))
		return svm_handle_invalid_exit(vcpu, exit_code);


	if (exit_code == SVM_EXIT_MSR)
		return msr_interception(vcpu);
	else if (exit_code == SVM_EXIT_VINTR)
		return interrupt_window_interception(vcpu);
	else if (exit_code == SVM_EXIT_INTR)
		return intr_interception(vcpu);
	else if (exit_code == SVM_EXIT_HLT)
		return kvm_emulate_halt(vcpu);
	else if (exit_code == SVM_EXIT_NPF)
		return npf_interception(vcpu);

	return svm_exit_handlers[exit_code](vcpu);
}

static void svm_get_exit_info(struct kvm_vcpu *vcpu, u32 *reason, u64 *info1, u64 *info2, u32 *intr_info, u32 *error_code)

{
	struct vmcb_control_area *control = &to_svm(vcpu)->vmcb->control;

	*reason = control->exit_code;
	*info1 = control->exit_info_1;
	*info2 = control->exit_info_2;
	*intr_info = control->exit_int_info;
	if ((*intr_info & SVM_EXITINTINFO_VALID) && (*intr_info & SVM_EXITINTINFO_VALID_ERR))
		*error_code = control->exit_int_info_err;
	else *error_code = 0;
}

static int svm_handle_exit(struct kvm_vcpu *vcpu, fastpath_t exit_fastpath)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct kvm_run *kvm_run = vcpu->run;
	u32 exit_code = svm->vmcb->control.exit_code;

	trace_kvm_exit(vcpu, KVM_ISA_SVM);

	
	if (!sev_es_guest(vcpu->kvm)) {
		if (!svm_is_intercept(svm, INTERCEPT_CR0_WRITE))
			vcpu->arch.cr0 = svm->vmcb->save.cr0;
		if (npt_enabled)
			vcpu->arch.cr3 = svm->vmcb->save.cr3;
	}

	if (is_guest_mode(vcpu)) {
		int vmexit;

		trace_kvm_nested_vmexit(vcpu, KVM_ISA_SVM);

		vmexit = nested_svm_exit_special(svm);

		if (vmexit == NESTED_EXIT_CONTINUE)
			vmexit = nested_svm_exit_handled(svm);

		if (vmexit == NESTED_EXIT_DONE)
			return 1;
	}

	if (svm->vmcb->control.exit_code == SVM_EXIT_ERR) {
		kvm_run->exit_reason = KVM_EXIT_FAIL_ENTRY;
		kvm_run->fail_entry.hardware_entry_failure_reason = svm->vmcb->control.exit_code;
		kvm_run->fail_entry.cpu = vcpu->arch.last_vmentry_cpu;
		dump_vmcb(vcpu);
		return 0;
	}

	if (is_external_interrupt(svm->vmcb->control.exit_int_info) && exit_code != SVM_EXIT_EXCP_BASE + PF_VECTOR && exit_code != SVM_EXIT_NPF && exit_code != SVM_EXIT_TASK_SWITCH && exit_code != SVM_EXIT_INTR && exit_code != SVM_EXIT_NMI)


		printk(KERN_ERR "%s: unexpected exit_int_info 0x%x " "exit_code 0x%x\n", __func__, svm->vmcb->control.exit_int_info, exit_code);



	if (exit_fastpath != EXIT_FASTPATH_NONE)
		return 1;

	return svm_invoke_exit_handler(vcpu, exit_code);
}

static void reload_tss(struct kvm_vcpu *vcpu)
{
	struct svm_cpu_data *sd = per_cpu(svm_data, vcpu->cpu);

	sd->tss_desc->type = 9; 
	load_TR_desc();
}

static void pre_svm_run(struct kvm_vcpu *vcpu)
{
	struct svm_cpu_data *sd = per_cpu(svm_data, vcpu->cpu);
	struct vcpu_svm *svm = to_svm(vcpu);

	
	if (unlikely(svm->current_vmcb->cpu != vcpu->cpu)) {
		svm->current_vmcb->asid_generation = 0;
		vmcb_mark_all_dirty(svm->vmcb);
		svm->current_vmcb->cpu = vcpu->cpu;
        }

	if (sev_guest(vcpu->kvm))
		return pre_sev_run(svm, vcpu->cpu);

	
	if (svm->current_vmcb->asid_generation != sd->asid_generation)
		new_asid(svm, sd);
}

static void svm_inject_nmi(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	svm->vmcb->control.event_inj = SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_NMI;
	vcpu->arch.hflags |= HF_NMI_MASK;
	if (!sev_es_guest(vcpu->kvm))
		svm_set_intercept(svm, INTERCEPT_IRET);
	++vcpu->stat.nmi_injections;
}

static void svm_inject_irq(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	BUG_ON(!(gif_set(svm)));

	trace_kvm_inj_virq(vcpu->arch.interrupt.nr);
	++vcpu->stat.irq_injections;

	svm->vmcb->control.event_inj = vcpu->arch.interrupt.nr | SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_INTR;
}

void svm_complete_interrupt_delivery(struct kvm_vcpu *vcpu, int delivery_mode, int trig_mode, int vector)
{
	
	bool in_guest_mode = (smp_load_acquire(&vcpu->mode) == IN_GUEST_MODE);

	if (!READ_ONCE(vcpu->arch.apicv_active)) {
		
		kvm_make_request(KVM_REQ_EVENT, vcpu);
		kvm_vcpu_kick(vcpu);
		return;
	}

	trace_kvm_apicv_accept_irq(vcpu->vcpu_id, delivery_mode, trig_mode, vector);
	if (in_guest_mode) {
		
		avic_ring_doorbell(vcpu);
	} else {
		
		kvm_vcpu_wake_up(vcpu);
	}
}

static void svm_deliver_interrupt(struct kvm_lapic *apic,  int delivery_mode, int trig_mode, int vector)
{
	kvm_lapic_set_irr(vector, apic);

	
	smp_mb__after_atomic();
	svm_complete_interrupt_delivery(apic->vcpu, delivery_mode, trig_mode, vector);
}

static void svm_update_cr8_intercept(struct kvm_vcpu *vcpu, int tpr, int irr)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	
	if (sev_es_guest(vcpu->kvm))
		return;

	if (nested_svm_virtualize_tpr(vcpu))
		return;

	svm_clr_intercept(svm, INTERCEPT_CR8_WRITE);

	if (irr == -1)
		return;

	if (tpr >= irr)
		svm_set_intercept(svm, INTERCEPT_CR8_WRITE);
}

bool svm_nmi_blocked(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct vmcb *vmcb = svm->vmcb;
	bool ret;

	if (!gif_set(svm))
		return true;

	if (is_guest_mode(vcpu) && nested_exit_on_nmi(svm))
		return false;

	ret = (vmcb->control.int_state & SVM_INTERRUPT_SHADOW_MASK) || (vcpu->arch.hflags & HF_NMI_MASK);

	return ret;
}

static int svm_nmi_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	if (svm->nested.nested_run_pending)
		return -EBUSY;

	if (svm_nmi_blocked(vcpu))
		return 0;

	
	if (for_injection && is_guest_mode(vcpu) && nested_exit_on_nmi(svm))
		return -EBUSY;
	return 1;
}

static bool svm_get_nmi_mask(struct kvm_vcpu *vcpu)
{
	return !!(vcpu->arch.hflags & HF_NMI_MASK);
}

static void svm_set_nmi_mask(struct kvm_vcpu *vcpu, bool masked)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	if (masked) {
		vcpu->arch.hflags |= HF_NMI_MASK;
		if (!sev_es_guest(vcpu->kvm))
			svm_set_intercept(svm, INTERCEPT_IRET);
	} else {
		vcpu->arch.hflags &= ~HF_NMI_MASK;
		if (!sev_es_guest(vcpu->kvm))
			svm_clr_intercept(svm, INTERCEPT_IRET);
	}
}

bool svm_interrupt_blocked(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct vmcb *vmcb = svm->vmcb;

	if (!gif_set(svm))
		return true;

	if (is_guest_mode(vcpu)) {
		
		if ((svm->nested.ctl.int_ctl & V_INTR_MASKING_MASK)
		    ? !(svm->vmcb01.ptr->save.rflags & X86_EFLAGS_IF)
		    : !(kvm_get_rflags(vcpu) & X86_EFLAGS_IF))
			return true;

		
		if (nested_exit_on_intr(svm))
			return false;
	} else {
		if (!svm_get_if_flag(vcpu))
			return true;
	}

	return (vmcb->control.int_state & SVM_INTERRUPT_SHADOW_MASK);
}

static int svm_interrupt_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	if (svm->nested.nested_run_pending)
		return -EBUSY;

	if (svm_interrupt_blocked(vcpu))
		return 0;

	
	if (for_injection && is_guest_mode(vcpu) && nested_exit_on_intr(svm))
		return -EBUSY;

	return 1;
}

static void svm_enable_irq_window(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	
	if (vgif || gif_set(svm)) {
		
		if (!is_guest_mode(vcpu))
			kvm_set_apicv_inhibit(vcpu->kvm, APICV_INHIBIT_REASON_IRQWIN);

		svm_set_vintr(svm);
	}
}

static void svm_enable_nmi_window(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	if ((vcpu->arch.hflags & (HF_NMI_MASK | HF_IRET_MASK)) == HF_NMI_MASK)
		return; 

	if (!gif_set(svm)) {
		if (vgif)
			svm_set_intercept(svm, INTERCEPT_STGI);
		return; 
	}

	
	svm->nmi_singlestep_guest_rflags = svm_get_rflags(vcpu);
	svm->nmi_singlestep = true;
	svm->vmcb->save.rflags |= (X86_EFLAGS_TF | X86_EFLAGS_RF);
}

static void svm_flush_tlb_current(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	
	if (static_cpu_has(X86_FEATURE_FLUSHBYASID))
		svm->vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ASID;
	else svm->current_vmcb->asid_generation--;
}

static void svm_flush_tlb_gva(struct kvm_vcpu *vcpu, gva_t gva)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	invlpga(gva, svm->vmcb->control.asid);
}

static inline void sync_cr8_to_lapic(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	if (nested_svm_virtualize_tpr(vcpu))
		return;

	if (!svm_is_intercept(svm, INTERCEPT_CR8_WRITE)) {
		int cr8 = svm->vmcb->control.int_ctl & V_TPR_MASK;
		kvm_set_cr8(vcpu, cr8);
	}
}

static inline void sync_lapic_to_cr8(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	u64 cr8;

	if (nested_svm_virtualize_tpr(vcpu) || kvm_vcpu_apicv_active(vcpu))
		return;

	cr8 = kvm_get_cr8(vcpu);
	svm->vmcb->control.int_ctl &= ~V_TPR_MASK;
	svm->vmcb->control.int_ctl |= cr8 & V_TPR_MASK;
}

static void svm_complete_interrupts(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	u8 vector;
	int type;
	u32 exitintinfo = svm->vmcb->control.exit_int_info;
	unsigned int3_injected = svm->int3_injected;

	svm->int3_injected = 0;

	
	if ((vcpu->arch.hflags & HF_IRET_MASK) && (sev_es_guest(vcpu->kvm) || kvm_rip_read(vcpu) != svm->nmi_iret_rip)) {

		vcpu->arch.hflags &= ~(HF_NMI_MASK | HF_IRET_MASK);
		kvm_make_request(KVM_REQ_EVENT, vcpu);
	}

	vcpu->arch.nmi_injected = false;
	kvm_clear_exception_queue(vcpu);
	kvm_clear_interrupt_queue(vcpu);

	if (!(exitintinfo & SVM_EXITINTINFO_VALID))
		return;

	kvm_make_request(KVM_REQ_EVENT, vcpu);

	vector = exitintinfo & SVM_EXITINTINFO_VEC_MASK;
	type = exitintinfo & SVM_EXITINTINFO_TYPE_MASK;

	switch (type) {
	case SVM_EXITINTINFO_TYPE_NMI:
		vcpu->arch.nmi_injected = true;
		break;
	case SVM_EXITINTINFO_TYPE_EXEPT:
		
		if (vector == X86_TRAP_VC)
			break;

		
		if (kvm_exception_is_soft(vector)) {
			if (vector == BP_VECTOR && int3_injected && kvm_is_linear_rip(vcpu, svm->int3_rip))
				kvm_rip_write(vcpu, kvm_rip_read(vcpu) - int3_injected);
			break;
		}
		if (exitintinfo & SVM_EXITINTINFO_VALID_ERR) {
			u32 err = svm->vmcb->control.exit_int_info_err;
			kvm_requeue_exception_e(vcpu, vector, err);

		} else kvm_requeue_exception(vcpu, vector);
		break;
	case SVM_EXITINTINFO_TYPE_INTR:
		kvm_queue_interrupt(vcpu, vector, false);
		break;
	default:
		break;
	}
}

static void svm_cancel_injection(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct vmcb_control_area *control = &svm->vmcb->control;

	control->exit_int_info = control->event_inj;
	control->exit_int_info_err = control->event_inj_err;
	control->event_inj = 0;
	svm_complete_interrupts(vcpu);
}

static int svm_vcpu_pre_run(struct kvm_vcpu *vcpu)
{
	return 1;
}

static fastpath_t svm_exit_handlers_fastpath(struct kvm_vcpu *vcpu)
{
	if (to_svm(vcpu)->vmcb->control.exit_code == SVM_EXIT_MSR && to_svm(vcpu)->vmcb->control.exit_info_1)
		return handle_fastpath_set_msr_irqoff(vcpu);

	return EXIT_FASTPATH_NONE;
}

static noinstr void svm_vcpu_enter_exit(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	unsigned long vmcb_pa = svm->current_vmcb->pa;

	guest_state_enter_irqoff();

	if (sev_es_guest(vcpu->kvm)) {
		__svm_sev_es_vcpu_run(vmcb_pa);
	} else {
		struct svm_cpu_data *sd = per_cpu(svm_data, vcpu->cpu);

		
		vmload(svm->vmcb01.pa);
		__svm_vcpu_run(vmcb_pa, (unsigned long *)&vcpu->arch.regs);
		vmsave(svm->vmcb01.pa);

		vmload(__sme_page_pa(sd->save_area));
	}

	guest_state_exit_irqoff();
}

static __no_kcsan fastpath_t svm_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	trace_kvm_entry(vcpu);

	svm->vmcb->save.rax = vcpu->arch.regs[VCPU_REGS_RAX];
	svm->vmcb->save.rsp = vcpu->arch.regs[VCPU_REGS_RSP];
	svm->vmcb->save.rip = vcpu->arch.regs[VCPU_REGS_RIP];

	
	if (svm->nmi_singlestep && svm->vmcb->control.event_inj) {
		
		disable_nmi_singlestep(svm);
		smp_send_reschedule(vcpu->cpu);
	}

	pre_svm_run(vcpu);

	sync_lapic_to_cr8(vcpu);

	if (unlikely(svm->asid != svm->vmcb->control.asid)) {
		svm->vmcb->control.asid = svm->asid;
		vmcb_mark_dirty(svm->vmcb, VMCB_ASID);
	}
	svm->vmcb->save.cr2 = vcpu->arch.cr2;

	svm_hv_update_vp_id(svm->vmcb, vcpu);

	
	if (unlikely(vcpu->arch.switch_db_regs & KVM_DEBUGREG_WONT_EXIT))
		svm_set_dr6(svm, vcpu->arch.dr6);
	else svm_set_dr6(svm, DR6_ACTIVE_LOW);

	clgi();
	kvm_load_guest_xsave_state(vcpu);

	kvm_wait_lapic_expire(vcpu);

	
	if (!static_cpu_has(X86_FEATURE_V_SPEC_CTRL))
		x86_spec_ctrl_set_guest(svm->spec_ctrl, svm->virt_spec_ctrl);

	svm_vcpu_enter_exit(vcpu);

	
	if (!static_cpu_has(X86_FEATURE_V_SPEC_CTRL) && unlikely(!msr_write_intercepted(vcpu, MSR_IA32_SPEC_CTRL)))
		svm->spec_ctrl = native_read_msr(MSR_IA32_SPEC_CTRL);

	if (!sev_es_guest(vcpu->kvm))
		reload_tss(vcpu);

	if (!static_cpu_has(X86_FEATURE_V_SPEC_CTRL))
		x86_spec_ctrl_restore_host(svm->spec_ctrl, svm->virt_spec_ctrl);

	if (!sev_es_guest(vcpu->kvm)) {
		vcpu->arch.cr2 = svm->vmcb->save.cr2;
		vcpu->arch.regs[VCPU_REGS_RAX] = svm->vmcb->save.rax;
		vcpu->arch.regs[VCPU_REGS_RSP] = svm->vmcb->save.rsp;
		vcpu->arch.regs[VCPU_REGS_RIP] = svm->vmcb->save.rip;
	}
	vcpu->arch.regs_dirty = 0;

	if (unlikely(svm->vmcb->control.exit_code == SVM_EXIT_NMI))
		kvm_before_interrupt(vcpu, KVM_HANDLING_NMI);

	kvm_load_host_xsave_state(vcpu);
	stgi();

	

	if (unlikely(svm->vmcb->control.exit_code == SVM_EXIT_NMI))
		kvm_after_interrupt(vcpu);

	sync_cr8_to_lapic(vcpu);

	svm->next_rip = 0;
	if (is_guest_mode(vcpu)) {
		nested_sync_control_from_vmcb02(svm);

		
		if (svm->nested.nested_run_pending && svm->vmcb->control.exit_code != SVM_EXIT_ERR)
                        ++vcpu->stat.nested_run;

		svm->nested.nested_run_pending = 0;
	}

	svm->vmcb->control.tlb_ctl = TLB_CONTROL_DO_NOTHING;
	vmcb_mark_all_clean(svm->vmcb);

	
	if (svm->vmcb->control.exit_code == SVM_EXIT_EXCP_BASE + PF_VECTOR)
		vcpu->arch.apf.host_apf_flags = kvm_read_and_reset_apf_flags();

	vcpu->arch.regs_avail &= ~SVM_REGS_LAZY_LOAD_SET;

	
	if (unlikely(svm->vmcb->control.exit_code == SVM_EXIT_EXCP_BASE + MC_VECTOR))
		svm_handle_mce(vcpu);

	svm_complete_interrupts(vcpu);

	if (is_guest_mode(vcpu))
		return EXIT_FASTPATH_NONE;

	return svm_exit_handlers_fastpath(vcpu);
}

static void svm_load_mmu_pgd(struct kvm_vcpu *vcpu, hpa_t root_hpa, int root_level)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	unsigned long cr3;

	if (npt_enabled) {
		svm->vmcb->control.nested_cr3 = __sme_set(root_hpa);
		vmcb_mark_dirty(svm->vmcb, VMCB_NPT);

		hv_track_root_tdp(vcpu, root_hpa);

		cr3 = vcpu->arch.cr3;
	} else if (vcpu->arch.mmu->root_role.level >= PT64_ROOT_4LEVEL) {
		cr3 = __sme_set(root_hpa) | kvm_get_active_pcid(vcpu);
	} else {
		
		WARN_ON_ONCE(kvm_get_active_pcid(vcpu));
		cr3 = root_hpa;
	}

	svm->vmcb->save.cr3 = cr3;
	vmcb_mark_dirty(svm->vmcb, VMCB_CR);
}

static int is_disabled(void)
{
	u64 vm_cr;

	rdmsrl(MSR_VM_CR, vm_cr);
	if (vm_cr & (1 << SVM_VM_CR_SVM_DISABLE))
		return 1;

	return 0;
}

static void svm_patch_hypercall(struct kvm_vcpu *vcpu, unsigned char *hypercall)
{
	
	hypercall[0] = 0x0f;
	hypercall[1] = 0x01;
	hypercall[2] = 0xd9;
}

static int __init svm_check_processor_compat(void)
{
	return 0;
}


static bool svm_has_emulated_msr(struct kvm *kvm, u32 index)
{
	switch (index) {
	case MSR_IA32_MCG_EXT_CTL:
	case MSR_IA32_VMX_BASIC ... MSR_IA32_VMX_VMFUNC:
		return false;
	case MSR_IA32_SMBASE:
		
		if (kvm && sev_es_guest(kvm))
			return false;
		break;
	default:
		break;
	}

	return true;
}

static u64 svm_get_mt_mask(struct kvm_vcpu *vcpu, gfn_t gfn, bool is_mmio)
{
	return 0;
}

static void svm_vcpu_after_set_cpuid(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct kvm_cpuid_entry2 *best;
	struct kvm *kvm = vcpu->kvm;

	vcpu->arch.xsaves_enabled = guest_cpuid_has(vcpu, X86_FEATURE_XSAVE) && boot_cpu_has(X86_FEATURE_XSAVE) && boot_cpu_has(X86_FEATURE_XSAVES);


	
	svm->nrips_enabled = kvm_cpu_cap_has(X86_FEATURE_NRIPS) && guest_cpuid_has(vcpu, X86_FEATURE_NRIPS);

	svm->tsc_scaling_enabled = tsc_scaling && guest_cpuid_has(vcpu, X86_FEATURE_TSCRATEMSR);
	svm->lbrv_enabled = lbrv && guest_cpuid_has(vcpu, X86_FEATURE_LBRV);

	svm->v_vmload_vmsave_enabled = vls && guest_cpuid_has(vcpu, X86_FEATURE_V_VMSAVE_VMLOAD);

	svm->pause_filter_enabled = kvm_cpu_cap_has(X86_FEATURE_PAUSEFILTER) && guest_cpuid_has(vcpu, X86_FEATURE_PAUSEFILTER);

	svm->pause_threshold_enabled = kvm_cpu_cap_has(X86_FEATURE_PFTHRESHOLD) && guest_cpuid_has(vcpu, X86_FEATURE_PFTHRESHOLD);

	svm->vgif_enabled = vgif && guest_cpuid_has(vcpu, X86_FEATURE_VGIF);

	svm_recalc_instruction_intercepts(vcpu, svm);

	
	if (sev_guest(vcpu->kvm)) {
		best = kvm_find_cpuid_entry(vcpu, 0x8000001F, 0);
		if (best)
			vcpu->arch.reserved_gpa_bits &= ~(1UL << (best->ebx & 0x3f));
	}

	if (kvm_vcpu_apicv_active(vcpu)) {
		
		if (guest_cpuid_has(vcpu, X86_FEATURE_X2APIC))
			kvm_set_apicv_inhibit(kvm, APICV_INHIBIT_REASON_X2APIC);
	}
	init_vmcb_after_set_cpuid(vcpu);
}

static bool svm_has_wbinvd_exit(void)
{
	return true;
}





static const struct __x86_intercept {
	u32 exit_code;
	enum x86_intercept_stage stage;
} x86_intercept_map[] = {
	[x86_intercept_cr_read]		= POST_EX(SVM_EXIT_READ_CR0), [x86_intercept_cr_write]	= POST_EX(SVM_EXIT_WRITE_CR0), [x86_intercept_clts]		= POST_EX(SVM_EXIT_WRITE_CR0), [x86_intercept_lmsw]		= POST_EX(SVM_EXIT_WRITE_CR0), [x86_intercept_smsw]		= POST_EX(SVM_EXIT_READ_CR0), [x86_intercept_dr_read]		= POST_EX(SVM_EXIT_READ_DR0), [x86_intercept_dr_write]	= POST_EX(SVM_EXIT_WRITE_DR0), [x86_intercept_sldt]		= POST_EX(SVM_EXIT_LDTR_READ), [x86_intercept_str]		= POST_EX(SVM_EXIT_TR_READ), [x86_intercept_lldt]		= POST_EX(SVM_EXIT_LDTR_WRITE), [x86_intercept_ltr]		= POST_EX(SVM_EXIT_TR_WRITE), [x86_intercept_sgdt]		= POST_EX(SVM_EXIT_GDTR_READ), [x86_intercept_sidt]		= POST_EX(SVM_EXIT_IDTR_READ), [x86_intercept_lgdt]		= POST_EX(SVM_EXIT_GDTR_WRITE), [x86_intercept_lidt]		= POST_EX(SVM_EXIT_IDTR_WRITE), [x86_intercept_vmrun]		= POST_EX(SVM_EXIT_VMRUN), [x86_intercept_vmmcall]		= POST_EX(SVM_EXIT_VMMCALL), [x86_intercept_vmload]		= POST_EX(SVM_EXIT_VMLOAD), [x86_intercept_vmsave]		= POST_EX(SVM_EXIT_VMSAVE), [x86_intercept_stgi]		= POST_EX(SVM_EXIT_STGI), [x86_intercept_clgi]		= POST_EX(SVM_EXIT_CLGI), [x86_intercept_skinit]		= POST_EX(SVM_EXIT_SKINIT), [x86_intercept_invlpga]		= POST_EX(SVM_EXIT_INVLPGA), [x86_intercept_rdtscp]		= POST_EX(SVM_EXIT_RDTSCP), [x86_intercept_monitor]		= POST_MEM(SVM_EXIT_MONITOR), [x86_intercept_mwait]		= POST_EX(SVM_EXIT_MWAIT), [x86_intercept_invlpg]		= POST_EX(SVM_EXIT_INVLPG), [x86_intercept_invd]		= POST_EX(SVM_EXIT_INVD), [x86_intercept_wbinvd]		= POST_EX(SVM_EXIT_WBINVD), [x86_intercept_wrmsr]		= POST_EX(SVM_EXIT_MSR), [x86_intercept_rdtsc]		= POST_EX(SVM_EXIT_RDTSC), [x86_intercept_rdmsr]		= POST_EX(SVM_EXIT_MSR), [x86_intercept_rdpmc]		= POST_EX(SVM_EXIT_RDPMC), [x86_intercept_cpuid]		= PRE_EX(SVM_EXIT_CPUID), [x86_intercept_rsm]		= PRE_EX(SVM_EXIT_RSM), [x86_intercept_pause]		= PRE_EX(SVM_EXIT_PAUSE), [x86_intercept_pushf]		= PRE_EX(SVM_EXIT_PUSHF), [x86_intercept_popf]		= PRE_EX(SVM_EXIT_POPF), [x86_intercept_intn]		= PRE_EX(SVM_EXIT_SWINT), [x86_intercept_iret]		= PRE_EX(SVM_EXIT_IRET), [x86_intercept_icebp]		= PRE_EX(SVM_EXIT_ICEBP), [x86_intercept_hlt]		= POST_EX(SVM_EXIT_HLT), [x86_intercept_in]		= POST_EX(SVM_EXIT_IOIO), [x86_intercept_ins]		= POST_EX(SVM_EXIT_IOIO), [x86_intercept_out]		= POST_EX(SVM_EXIT_IOIO), [x86_intercept_outs]		= POST_EX(SVM_EXIT_IOIO), [x86_intercept_xsetbv]		= PRE_EX(SVM_EXIT_XSETBV), };



















































static int svm_check_intercept(struct kvm_vcpu *vcpu, struct x86_instruction_info *info, enum x86_intercept_stage stage, struct x86_exception *exception)


{
	struct vcpu_svm *svm = to_svm(vcpu);
	int vmexit, ret = X86EMUL_CONTINUE;
	struct __x86_intercept icpt_info;
	struct vmcb *vmcb = svm->vmcb;

	if (info->intercept >= ARRAY_SIZE(x86_intercept_map))
		goto out;

	icpt_info = x86_intercept_map[info->intercept];

	if (stage != icpt_info.stage)
		goto out;

	switch (icpt_info.exit_code) {
	case SVM_EXIT_READ_CR0:
		if (info->intercept == x86_intercept_cr_read)
			icpt_info.exit_code += info->modrm_reg;
		break;
	case SVM_EXIT_WRITE_CR0: {
		unsigned long cr0, val;

		if (info->intercept == x86_intercept_cr_write)
			icpt_info.exit_code += info->modrm_reg;

		if (icpt_info.exit_code != SVM_EXIT_WRITE_CR0 || info->intercept == x86_intercept_clts)
			break;

		if (!(vmcb12_is_intercept(&svm->nested.ctl, INTERCEPT_SELECTIVE_CR0)))
			break;

		cr0 = vcpu->arch.cr0 & ~SVM_CR0_SELECTIVE_MASK;
		val = info->src_val  & ~SVM_CR0_SELECTIVE_MASK;

		if (info->intercept == x86_intercept_lmsw) {
			cr0 &= 0xfUL;
			val &= 0xfUL;
			
			if (cr0 & X86_CR0_PE)
				val |= X86_CR0_PE;
		}

		if (cr0 ^ val)
			icpt_info.exit_code = SVM_EXIT_CR0_SEL_WRITE;

		break;
	}
	case SVM_EXIT_READ_DR0:
	case SVM_EXIT_WRITE_DR0:
		icpt_info.exit_code += info->modrm_reg;
		break;
	case SVM_EXIT_MSR:
		if (info->intercept == x86_intercept_wrmsr)
			vmcb->control.exit_info_1 = 1;
		else vmcb->control.exit_info_1 = 0;
		break;
	case SVM_EXIT_PAUSE:
		
		if (info->rep_prefix != REPE_PREFIX)
			goto out;
		break;
	case SVM_EXIT_IOIO: {
		u64 exit_info;
		u32 bytes;

		if (info->intercept == x86_intercept_in || info->intercept == x86_intercept_ins) {
			exit_info = ((info->src_val & 0xffff) << 16) | SVM_IOIO_TYPE_MASK;
			bytes = info->dst_bytes;
		} else {
			exit_info = (info->dst_val & 0xffff) << 16;
			bytes = info->src_bytes;
		}

		if (info->intercept == x86_intercept_outs || info->intercept == x86_intercept_ins)
			exit_info |= SVM_IOIO_STR_MASK;

		if (info->rep_prefix)
			exit_info |= SVM_IOIO_REP_MASK;

		bytes = min(bytes, 4u);

		exit_info |= bytes << SVM_IOIO_SIZE_SHIFT;

		exit_info |= (u32)info->ad_bytes << (SVM_IOIO_ASIZE_SHIFT - 1);

		vmcb->control.exit_info_1 = exit_info;
		vmcb->control.exit_info_2 = info->next_rip;

		break;
	}
	default:
		break;
	}

	
	if (static_cpu_has(X86_FEATURE_NRIPS))
		vmcb->control.next_rip  = info->next_rip;
	vmcb->control.exit_code = icpt_info.exit_code;
	vmexit = nested_svm_exit_handled(svm);

	ret = (vmexit == NESTED_EXIT_DONE) ? X86EMUL_INTERCEPTED : X86EMUL_CONTINUE;

out:
	return ret;
}

static void svm_handle_exit_irqoff(struct kvm_vcpu *vcpu)
{
}

static void svm_sched_in(struct kvm_vcpu *vcpu, int cpu)
{
	if (!kvm_pause_in_guest(vcpu->kvm))
		shrink_ple_window(vcpu);
}

static void svm_setup_mce(struct kvm_vcpu *vcpu)
{
	
	vcpu->arch.mcg_cap &= 0x1ff;
}

bool svm_smi_blocked(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	
	if (!gif_set(svm))
		return true;

	return is_smm(vcpu);
}

static int svm_smi_allowed(struct kvm_vcpu *vcpu, bool for_injection)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	if (svm->nested.nested_run_pending)
		return -EBUSY;

	if (svm_smi_blocked(vcpu))
		return 0;

	
	if (for_injection && is_guest_mode(vcpu) && nested_exit_on_smi(svm))
		return -EBUSY;

	return 1;
}

static int svm_enter_smm(struct kvm_vcpu *vcpu, char *smstate)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct kvm_host_map map_save;
	int ret;

	if (!is_guest_mode(vcpu))
		return 0;

	
	put_smstate(u64, smstate, 0x7ed8, 1);
	
	put_smstate(u64, smstate, 0x7ee0, svm->nested.vmcb12_gpa);

	svm->vmcb->save.rax = vcpu->arch.regs[VCPU_REGS_RAX];
	svm->vmcb->save.rsp = vcpu->arch.regs[VCPU_REGS_RSP];
	svm->vmcb->save.rip = vcpu->arch.regs[VCPU_REGS_RIP];

	ret = nested_svm_simple_vmexit(svm, SVM_EXIT_SW);
	if (ret)
		return ret;

	
	if (kvm_vcpu_map(vcpu, gpa_to_gfn(svm->nested.hsave_msr), &map_save) == -EINVAL)
		return 1;

	BUILD_BUG_ON(offsetof(struct vmcb, save) != 0x400);

	svm_copy_vmrun_state(map_save.hva + 0x400, &svm->vmcb01.ptr->save);

	kvm_vcpu_unmap(vcpu, &map_save, true);
	return 0;
}

static int svm_leave_smm(struct kvm_vcpu *vcpu, const char *smstate)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct kvm_host_map map, map_save;
	u64 saved_efer, vmcb12_gpa;
	struct vmcb *vmcb12;
	int ret;

	if (!guest_cpuid_has(vcpu, X86_FEATURE_LM))
		return 0;

	
	if (!GET_SMSTATE(u64, smstate, 0x7ed8))
		return 0;

	if (!guest_cpuid_has(vcpu, X86_FEATURE_SVM))
		return 1;

	saved_efer = GET_SMSTATE(u64, smstate, 0x7ed0);
	if (!(saved_efer & EFER_SVME))
		return 1;

	vmcb12_gpa = GET_SMSTATE(u64, smstate, 0x7ee0);
	if (kvm_vcpu_map(vcpu, gpa_to_gfn(vmcb12_gpa), &map) == -EINVAL)
		return 1;

	ret = 1;
	if (kvm_vcpu_map(vcpu, gpa_to_gfn(svm->nested.hsave_msr), &map_save) == -EINVAL)
		goto unmap_map;

	if (svm_allocate_nested(svm))
		goto unmap_save;

	

	svm_copy_vmrun_state(&svm->vmcb01.ptr->save, map_save.hva + 0x400);

	

	vmcb_mark_all_dirty(svm->vmcb01.ptr);

	vmcb12 = map.hva;
	nested_copy_vmcb_control_to_cache(svm, &vmcb12->control);
	nested_copy_vmcb_save_to_cache(svm, &vmcb12->save);
	ret = enter_svm_guest_mode(vcpu, vmcb12_gpa, vmcb12, false);

	if (ret)
		goto unmap_save;

	svm->nested.nested_run_pending = 1;

unmap_save:
	kvm_vcpu_unmap(vcpu, &map_save, true);
unmap_map:
	kvm_vcpu_unmap(vcpu, &map, true);
	return ret;
}

static void svm_enable_smi_window(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	if (!gif_set(svm)) {
		if (vgif)
			svm_set_intercept(svm, INTERCEPT_STGI);
		
	} else {
		
	}
}

static bool svm_can_emulate_instruction(struct kvm_vcpu *vcpu, int emul_type, void *insn, int insn_len)
{
	bool smep, smap, is_user;
	unsigned long cr4;
	u64 error_code;

	
	if (!sev_guest(vcpu->kvm))
		return true;

	
	WARN_ON_ONCE(emul_type & (EMULTYPE_TRAP_UD | EMULTYPE_TRAP_UD_FORCED | EMULTYPE_VMWARE_GP));


	
	if (sev_es_guest(vcpu->kvm))
		return false;

	
	if (emul_type & EMULTYPE_NO_DECODE)
		return true;

	
	if (unlikely(!insn)) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return false;
	}

	
	if (likely(insn_len))
		return true;

	
	error_code = to_svm(vcpu)->vmcb->control.exit_info_1;
	if (error_code & (PFERR_GUEST_PAGE_MASK | PFERR_FETCH_MASK))
		goto resume_guest;

	cr4 = kvm_read_cr4(vcpu);
	smep = cr4 & X86_CR4_SMEP;
	smap = cr4 & X86_CR4_SMAP;
	is_user = svm_get_cpl(vcpu) == 3;
	if (smap && (!smep || is_user)) {
		pr_err_ratelimited("KVM: SEV Guest triggered AMD Erratum 1096\n");

		
		if (is_user)
			kvm_inject_gp(vcpu, 0);
		else kvm_make_request(KVM_REQ_TRIPLE_FAULT, vcpu);
	}

resume_guest:
	
	return false;
}

static bool svm_apic_init_signal_blocked(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	
	return !gif_set(svm) || (vmcb_is_intercept(&svm->vmcb->control, INTERCEPT_INIT));
}

static void svm_vcpu_deliver_sipi_vector(struct kvm_vcpu *vcpu, u8 vector)
{
	if (!sev_es_guest(vcpu->kvm))
		return kvm_vcpu_deliver_sipi_vector(vcpu, vector);

	sev_vcpu_deliver_sipi_vector(vcpu, vector);
}

static void svm_vm_destroy(struct kvm *kvm)
{
	avic_vm_destroy(kvm);
	sev_vm_destroy(kvm);
}

static int svm_vm_init(struct kvm *kvm)
{
	if (!pause_filter_count || !pause_filter_thresh)
		kvm->arch.pause_in_guest = true;

	if (enable_apicv) {
		int ret = avic_vm_init(kvm);
		if (ret)
			return ret;
	}

	return 0;
}

static struct kvm_x86_ops svm_x86_ops __initdata = {
	.name = "kvm_amd",  .hardware_unsetup = svm_hardware_unsetup, .hardware_enable = svm_hardware_enable, .hardware_disable = svm_hardware_disable, .has_emulated_msr = svm_has_emulated_msr,  .vcpu_create = svm_vcpu_create, .vcpu_free = svm_vcpu_free, .vcpu_reset = svm_vcpu_reset,  .vm_size = sizeof(struct kvm_svm), .vm_init = svm_vm_init, .vm_destroy = svm_vm_destroy,  .prepare_switch_to_guest = svm_prepare_switch_to_guest, .vcpu_load = svm_vcpu_load, .vcpu_put = svm_vcpu_put, .vcpu_blocking = avic_vcpu_blocking, .vcpu_unblocking = avic_vcpu_unblocking,  .update_exception_bitmap = svm_update_exception_bitmap, .get_msr_feature = svm_get_msr_feature, .get_msr = svm_get_msr, .set_msr = svm_set_msr, .get_segment_base = svm_get_segment_base, .get_segment = svm_get_segment, .set_segment = svm_set_segment, .get_cpl = svm_get_cpl, .get_cs_db_l_bits = svm_get_cs_db_l_bits, .set_cr0 = svm_set_cr0, .post_set_cr3 = sev_post_set_cr3, .is_valid_cr4 = svm_is_valid_cr4, .set_cr4 = svm_set_cr4, .set_efer = svm_set_efer, .get_idt = svm_get_idt, .set_idt = svm_set_idt, .get_gdt = svm_get_gdt, .set_gdt = svm_set_gdt, .set_dr7 = svm_set_dr7, .sync_dirty_debug_regs = svm_sync_dirty_debug_regs, .cache_reg = svm_cache_reg, .get_rflags = svm_get_rflags, .set_rflags = svm_set_rflags, .get_if_flag = svm_get_if_flag,  .flush_tlb_all = svm_flush_tlb_current, .flush_tlb_current = svm_flush_tlb_current, .flush_tlb_gva = svm_flush_tlb_gva, .flush_tlb_guest = svm_flush_tlb_current,  .vcpu_pre_run = svm_vcpu_pre_run, .vcpu_run = svm_vcpu_run, .handle_exit = svm_handle_exit, .skip_emulated_instruction = svm_skip_emulated_instruction, .update_emulated_instruction = NULL, .set_interrupt_shadow = svm_set_interrupt_shadow, .get_interrupt_shadow = svm_get_interrupt_shadow, .patch_hypercall = svm_patch_hypercall, .inject_irq = svm_inject_irq, .inject_nmi = svm_inject_nmi, .queue_exception = svm_queue_exception, .cancel_injection = svm_cancel_injection, .interrupt_allowed = svm_interrupt_allowed, .nmi_allowed = svm_nmi_allowed, .get_nmi_mask = svm_get_nmi_mask, .set_nmi_mask = svm_set_nmi_mask, .enable_nmi_window = svm_enable_nmi_window, .enable_irq_window = svm_enable_irq_window, .update_cr8_intercept = svm_update_cr8_intercept, .refresh_apicv_exec_ctrl = avic_refresh_apicv_exec_ctrl, .check_apicv_inhibit_reasons = avic_check_apicv_inhibit_reasons, .apicv_post_state_restore = avic_apicv_post_state_restore,  .get_mt_mask = svm_get_mt_mask, .get_exit_info = svm_get_exit_info,  .vcpu_after_set_cpuid = svm_vcpu_after_set_cpuid,  .has_wbinvd_exit = svm_has_wbinvd_exit,  .get_l2_tsc_offset = svm_get_l2_tsc_offset, .get_l2_tsc_multiplier = svm_get_l2_tsc_multiplier, .write_tsc_offset = svm_write_tsc_offset, .write_tsc_multiplier = svm_write_tsc_multiplier,  .load_mmu_pgd = svm_load_mmu_pgd,  .check_intercept = svm_check_intercept, .handle_exit_irqoff = svm_handle_exit_irqoff,  .request_immediate_exit = __kvm_request_immediate_exit,  .sched_in = svm_sched_in,  .nested_ops = &svm_nested_ops,  .deliver_interrupt = svm_deliver_interrupt, .pi_update_irte = avic_pi_update_irte, .setup_mce = svm_setup_mce,  .smi_allowed = svm_smi_allowed, .enter_smm = svm_enter_smm, .leave_smm = svm_leave_smm, .enable_smi_window = svm_enable_smi_window,  .mem_enc_ioctl = sev_mem_enc_ioctl, .mem_enc_register_region = sev_mem_enc_register_region, .mem_enc_unregister_region = sev_mem_enc_unregister_region, .guest_memory_reclaimed = sev_guest_memory_reclaimed,  .vm_copy_enc_context_from = sev_vm_copy_enc_context_from, .vm_move_enc_context_from = sev_vm_move_enc_context_from,  .can_emulate_instruction = svm_can_emulate_instruction,  .apic_init_signal_blocked = svm_apic_init_signal_blocked,  .msr_filter_changed = svm_msr_filter_changed, .complete_emulated_msr = svm_complete_emulated_msr,  .vcpu_deliver_sipi_vector = svm_vcpu_deliver_sipi_vector, .vcpu_get_apicv_inhibit_reasons = avic_vcpu_get_apicv_inhibit_reasons, };




























































































































static __init void svm_adjust_mmio_mask(void)
{
	unsigned int enc_bit, mask_bit;
	u64 msr, mask;

	
	if (cpuid_eax(0x80000000) < 0x8000001f)
		return;

	
	rdmsrl(MSR_AMD64_SYSCFG, msr);
	if (!(msr & MSR_AMD64_SYSCFG_MEM_ENCRYPT))
		return;

	enc_bit = cpuid_ebx(0x8000001f) & 0x3f;
	mask_bit = boot_cpu_data.x86_phys_bits;

	
	if (enc_bit == mask_bit)
		mask_bit++;

	
	mask = (mask_bit < 52) ? rsvd_bits(mask_bit, 51) | PT_PRESENT_MASK : 0;

	kvm_mmu_set_mmio_spte_mask(mask, mask, PT_WRITABLE_MASK | PT_USER_MASK);
}

static __init void svm_set_cpu_caps(void)
{
	kvm_set_cpu_caps();

	supported_xss = 0;

	
	if (nested) {
		kvm_cpu_cap_set(X86_FEATURE_SVM);
		kvm_cpu_cap_set(X86_FEATURE_VMCBCLEAN);

		if (nrips)
			kvm_cpu_cap_set(X86_FEATURE_NRIPS);

		if (npt_enabled)
			kvm_cpu_cap_set(X86_FEATURE_NPT);

		if (tsc_scaling)
			kvm_cpu_cap_set(X86_FEATURE_TSCRATEMSR);

		if (vls)
			kvm_cpu_cap_set(X86_FEATURE_V_VMSAVE_VMLOAD);
		if (lbrv)
			kvm_cpu_cap_set(X86_FEATURE_LBRV);

		if (boot_cpu_has(X86_FEATURE_PAUSEFILTER))
			kvm_cpu_cap_set(X86_FEATURE_PAUSEFILTER);

		if (boot_cpu_has(X86_FEATURE_PFTHRESHOLD))
			kvm_cpu_cap_set(X86_FEATURE_PFTHRESHOLD);

		if (vgif)
			kvm_cpu_cap_set(X86_FEATURE_VGIF);

		
		kvm_cpu_cap_set(X86_FEATURE_SVME_ADDR_CHK);
	}

	
	if (boot_cpu_has(X86_FEATURE_LS_CFG_SSBD) || boot_cpu_has(X86_FEATURE_AMD_SSBD))
		kvm_cpu_cap_set(X86_FEATURE_VIRT_SSBD);

	
	if (enable_pmu && boot_cpu_has(X86_FEATURE_PERFCTR_CORE))
		kvm_cpu_cap_set(X86_FEATURE_PERFCTR_CORE);

	
	sev_set_cpu_caps();
}

static __init int svm_hardware_setup(void)
{
	int cpu;
	struct page *iopm_pages;
	void *iopm_va;
	int r;
	unsigned int order = get_order(IOPM_SIZE);

	
	if (!boot_cpu_has(X86_FEATURE_NX)) {
		pr_err_ratelimited("NX (Execute Disable) not supported\n");
		return -EOPNOTSUPP;
	}
	kvm_enable_efer_bits(EFER_NX);

	iopm_pages = alloc_pages(GFP_KERNEL, order);

	if (!iopm_pages)
		return -ENOMEM;

	iopm_va = page_address(iopm_pages);
	memset(iopm_va, 0xff, PAGE_SIZE * (1 << order));
	iopm_base = page_to_pfn(iopm_pages) << PAGE_SHIFT;

	init_msrpm_offsets();

	supported_xcr0 &= ~(XFEATURE_MASK_BNDREGS | XFEATURE_MASK_BNDCSR);

	if (boot_cpu_has(X86_FEATURE_FXSR_OPT))
		kvm_enable_efer_bits(EFER_FFXSR);

	if (tsc_scaling) {
		if (!boot_cpu_has(X86_FEATURE_TSCRATEMSR)) {
			tsc_scaling = false;
		} else {
			pr_info("TSC scaling supported\n");
			kvm_has_tsc_control = true;
		}
	}
	kvm_max_tsc_scaling_ratio = SVM_TSC_RATIO_MAX;
	kvm_tsc_scaling_ratio_frac_bits = 32;

	tsc_aux_uret_slot = kvm_add_user_return_msr(MSR_TSC_AUX);

	
	if (!boot_cpu_has(X86_FEATURE_PAUSEFILTER)) {
		pause_filter_count = 0;
		pause_filter_thresh = 0;
	} else if (!boot_cpu_has(X86_FEATURE_PFTHRESHOLD)) {
		pause_filter_thresh = 0;
	}

	if (nested) {
		printk(KERN_INFO "kvm: Nested Virtualization enabled\n");
		kvm_enable_efer_bits(EFER_SVME | EFER_LMSLE);
	}

	
	if (!IS_ENABLED(CONFIG_X86_64) && !IS_ENABLED(CONFIG_X86_PAE))
		npt_enabled = false;

	if (!boot_cpu_has(X86_FEATURE_NPT))
		npt_enabled = false;

	
	kvm_configure_mmu(npt_enabled, get_npt_level(), get_npt_level(), PG_LEVEL_1G);
	pr_info("kvm: Nested Paging %sabled\n", npt_enabled ? "en" : "dis");

	
	kvm_mmu_set_me_spte_mask(sme_me_mask, sme_me_mask);

	
	sev_hardware_setup();

	svm_hv_hardware_setup();

	svm_adjust_mmio_mask();

	for_each_possible_cpu(cpu) {
		r = svm_cpu_init(cpu);
		if (r)
			goto err;
	}

	if (nrips) {
		if (!boot_cpu_has(X86_FEATURE_NRIPS))
			nrips = false;
	}

	enable_apicv = avic = avic && npt_enabled && (boot_cpu_has(X86_FEATURE_AVIC) || force_avic);

	if (enable_apicv) {
		if (!boot_cpu_has(X86_FEATURE_AVIC)) {
			pr_warn("AVIC is not supported in CPUID but force enabled");
			pr_warn("Your system might crash and burn");
		} else pr_info("AVIC enabled\n");

		amd_iommu_register_ga_log_notifier(&avic_ga_log_notifier);
	} else {
		svm_x86_ops.vcpu_blocking = NULL;
		svm_x86_ops.vcpu_unblocking = NULL;
		svm_x86_ops.vcpu_get_apicv_inhibit_reasons = NULL;
	}

	if (vls) {
		if (!npt_enabled || !boot_cpu_has(X86_FEATURE_V_VMSAVE_VMLOAD) || !IS_ENABLED(CONFIG_X86_64)) {

			vls = false;
		} else {
			pr_info("Virtual VMLOAD VMSAVE supported\n");
		}
	}

	if (boot_cpu_has(X86_FEATURE_SVME_ADDR_CHK))
		svm_gp_erratum_intercept = false;

	if (vgif) {
		if (!boot_cpu_has(X86_FEATURE_VGIF))
			vgif = false;
		else pr_info("Virtual GIF supported\n");
	}

	if (lbrv) {
		if (!boot_cpu_has(X86_FEATURE_LBRV))
			lbrv = false;
		else pr_info("LBR virtualization supported\n");
	}

	if (!enable_pmu)
		pr_info("PMU virtualization is disabled\n");

	svm_set_cpu_caps();

	
	allow_smaller_maxphyaddr = !npt_enabled;

	return 0;

err:
	svm_hardware_unsetup();
	return r;
}


static struct kvm_x86_init_ops svm_init_ops __initdata = {
	.cpu_has_kvm_support = has_svm, .disabled_by_bios = is_disabled, .hardware_setup = svm_hardware_setup, .check_processor_compatibility = svm_check_processor_compat,  .runtime_ops = &svm_x86_ops, .pmu_ops = &amd_pmu_ops, };







static int __init svm_init(void)
{
	__unused_size_checks();

	return kvm_init(&svm_init_ops, sizeof(struct vcpu_svm), __alignof__(struct vcpu_svm), THIS_MODULE);
}

static void __exit svm_exit(void)
{
	kvm_exit();
}

module_init(svm_init)
module_exit(svm_exit)
