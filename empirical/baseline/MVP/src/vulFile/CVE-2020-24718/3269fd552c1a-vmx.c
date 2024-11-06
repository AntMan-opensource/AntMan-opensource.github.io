


__FBSDID("$FreeBSD$");





















































































static MALLOC_DEFINE(M_VMX, "vmx", "vmx");
static MALLOC_DEFINE(M_VLAPIC, "vlapic", "vlapic");

SYSCTL_DECL(_hw_vmm);
SYSCTL_NODE(_hw_vmm, OID_AUTO, vmx, CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, NULL);

int vmxon_enabled[MAXCPU];
static char vmxon_region[MAXCPU][PAGE_SIZE] __aligned(PAGE_SIZE);

static uint32_t pinbased_ctls, procbased_ctls, procbased_ctls2;
static uint32_t exit_ctls, entry_ctls;

static uint64_t cr0_ones_mask, cr0_zeros_mask;
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, cr0_ones_mask, CTLFLAG_RD, &cr0_ones_mask, 0, NULL);
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, cr0_zeros_mask, CTLFLAG_RD, &cr0_zeros_mask, 0, NULL);

static uint64_t cr4_ones_mask, cr4_zeros_mask;
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, cr4_ones_mask, CTLFLAG_RD, &cr4_ones_mask, 0, NULL);
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, cr4_zeros_mask, CTLFLAG_RD, &cr4_zeros_mask, 0, NULL);

static int vmx_initialized;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, initialized, CTLFLAG_RD, &vmx_initialized, 0, "Intel VMX initialized");


static SYSCTL_NODE(_hw_vmm_vmx, OID_AUTO, cap, CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, NULL);


static int cap_halt_exit;
SYSCTL_INT(_hw_vmm_vmx_cap, OID_AUTO, halt_exit, CTLFLAG_RD, &cap_halt_exit, 0, "HLT triggers a VM-exit");

static int cap_pause_exit;
SYSCTL_INT(_hw_vmm_vmx_cap, OID_AUTO, pause_exit, CTLFLAG_RD, &cap_pause_exit, 0, "PAUSE triggers a VM-exit");

static int cap_rdpid;
SYSCTL_INT(_hw_vmm_vmx_cap, OID_AUTO, rdpid, CTLFLAG_RD, &cap_rdpid, 0, "Guests are allowed to use RDPID");

static int cap_rdtscp;
SYSCTL_INT(_hw_vmm_vmx_cap, OID_AUTO, rdtscp, CTLFLAG_RD, &cap_rdtscp, 0, "Guests are allowed to use RDTSCP");

static int cap_unrestricted_guest;
SYSCTL_INT(_hw_vmm_vmx_cap, OID_AUTO, unrestricted_guest, CTLFLAG_RD, &cap_unrestricted_guest, 0, "Unrestricted guests");

static int cap_monitor_trap;
SYSCTL_INT(_hw_vmm_vmx_cap, OID_AUTO, monitor_trap, CTLFLAG_RD, &cap_monitor_trap, 0, "Monitor trap flag");

static int cap_invpcid;
SYSCTL_INT(_hw_vmm_vmx_cap, OID_AUTO, invpcid, CTLFLAG_RD, &cap_invpcid, 0, "Guests are allowed to use INVPCID");

static int tpr_shadowing;
SYSCTL_INT(_hw_vmm_vmx_cap, OID_AUTO, tpr_shadowing, CTLFLAG_RD, &tpr_shadowing, 0, "TPR shadowing support");

static int virtual_interrupt_delivery;
SYSCTL_INT(_hw_vmm_vmx_cap, OID_AUTO, virtual_interrupt_delivery, CTLFLAG_RD, &virtual_interrupt_delivery, 0, "APICv virtual interrupt delivery support");

static int posted_interrupts;
SYSCTL_INT(_hw_vmm_vmx_cap, OID_AUTO, posted_interrupts, CTLFLAG_RD, &posted_interrupts, 0, "APICv posted interrupt support");

static int pirvec = -1;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, posted_interrupt_vector, CTLFLAG_RD, &pirvec, 0, "APICv posted interrupt vector");

static struct unrhdr *vpid_unr;
static u_int vpid_alloc_failed;
SYSCTL_UINT(_hw_vmm_vmx, OID_AUTO, vpid_alloc_failed, CTLFLAG_RD, &vpid_alloc_failed, 0, NULL);

int guest_l1d_flush;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, l1d_flush, CTLFLAG_RD, &guest_l1d_flush, 0, NULL);
int guest_l1d_flush_sw;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, l1d_flush_sw, CTLFLAG_RD, &guest_l1d_flush_sw, 0, NULL);

static struct msr_entry msr_load_list[1] __aligned(16);



SDT_PROBE_DEFINE3(vmm, vmx, exit, entry, "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE4(vmm, vmx, exit, taskswitch, "struct vmx *", "int", "struct vm_exit *", "struct vm_task_switch *");

SDT_PROBE_DEFINE4(vmm, vmx, exit, craccess, "struct vmx *", "int", "struct vm_exit *", "uint64_t");

SDT_PROBE_DEFINE4(vmm, vmx, exit, rdmsr, "struct vmx *", "int", "struct vm_exit *", "uint32_t");

SDT_PROBE_DEFINE5(vmm, vmx, exit, wrmsr, "struct vmx *", "int", "struct vm_exit *", "uint32_t", "uint64_t");

SDT_PROBE_DEFINE3(vmm, vmx, exit, halt, "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, mtrap, "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, pause, "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, intrwindow, "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE4(vmm, vmx, exit, interrupt, "struct vmx *", "int", "struct vm_exit *", "uint32_t");

SDT_PROBE_DEFINE3(vmm, vmx, exit, nmiwindow, "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, inout, "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, cpuid, "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE5(vmm, vmx, exit, exception, "struct vmx *", "int", "struct vm_exit *", "uint32_t", "int");

SDT_PROBE_DEFINE5(vmm, vmx, exit, nestedfault, "struct vmx *", "int", "struct vm_exit *", "uint64_t", "uint64_t");

SDT_PROBE_DEFINE4(vmm, vmx, exit, mmiofault, "struct vmx *", "int", "struct vm_exit *", "uint64_t");

SDT_PROBE_DEFINE3(vmm, vmx, exit, eoi, "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, apicaccess, "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE4(vmm, vmx, exit, apicwrite, "struct vmx *", "int", "struct vm_exit *", "struct vlapic *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, xsetbv, "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, monitor, "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, mwait, "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE3(vmm, vmx, exit, vminsn, "struct vmx *", "int", "struct vm_exit *");

SDT_PROBE_DEFINE4(vmm, vmx, exit, unknown, "struct vmx *", "int", "struct vm_exit *", "uint32_t");

SDT_PROBE_DEFINE4(vmm, vmx, exit, return, "struct vmx *", "int", "struct vm_exit *", "int");




static int vmx_getdesc(void *arg, int vcpu, int reg, struct seg_desc *desc);
static int vmx_getreg(void *arg, int vcpu, int reg, uint64_t *retval);
static int vmxctx_setreg(struct vmxctx *vmxctx, int reg, uint64_t val);
static void vmx_inject_pir(struct vlapic *vlapic);

static int vmx_restore_tsc(void *arg, int vcpu, uint64_t now);


static inline bool host_has_rdpid(void)
{
	return ((cpu_stdext_feature2 & CPUID_STDEXT2_RDPID) != 0);
}

static inline bool host_has_rdtscp(void)
{
	return ((amd_feature & AMDID_RDTSCP) != 0);
}


static const char * exit_reason_to_str(int reason)
{
	static char reasonbuf[32];

	switch (reason) {
	case EXIT_REASON_EXCEPTION:
		return "exception";
	case EXIT_REASON_EXT_INTR:
		return "extint";
	case EXIT_REASON_TRIPLE_FAULT:
		return "triplefault";
	case EXIT_REASON_INIT:
		return "init";
	case EXIT_REASON_SIPI:
		return "sipi";
	case EXIT_REASON_IO_SMI:
		return "iosmi";
	case EXIT_REASON_SMI:
		return "smi";
	case EXIT_REASON_INTR_WINDOW:
		return "intrwindow";
	case EXIT_REASON_NMI_WINDOW:
		return "nmiwindow";
	case EXIT_REASON_TASK_SWITCH:
		return "taskswitch";
	case EXIT_REASON_CPUID:
		return "cpuid";
	case EXIT_REASON_GETSEC:
		return "getsec";
	case EXIT_REASON_HLT:
		return "hlt";
	case EXIT_REASON_INVD:
		return "invd";
	case EXIT_REASON_INVLPG:
		return "invlpg";
	case EXIT_REASON_RDPMC:
		return "rdpmc";
	case EXIT_REASON_RDTSC:
		return "rdtsc";
	case EXIT_REASON_RSM:
		return "rsm";
	case EXIT_REASON_VMCALL:
		return "vmcall";
	case EXIT_REASON_VMCLEAR:
		return "vmclear";
	case EXIT_REASON_VMLAUNCH:
		return "vmlaunch";
	case EXIT_REASON_VMPTRLD:
		return "vmptrld";
	case EXIT_REASON_VMPTRST:
		return "vmptrst";
	case EXIT_REASON_VMREAD:
		return "vmread";
	case EXIT_REASON_VMRESUME:
		return "vmresume";
	case EXIT_REASON_VMWRITE:
		return "vmwrite";
	case EXIT_REASON_VMXOFF:
		return "vmxoff";
	case EXIT_REASON_VMXON:
		return "vmxon";
	case EXIT_REASON_CR_ACCESS:
		return "craccess";
	case EXIT_REASON_DR_ACCESS:
		return "draccess";
	case EXIT_REASON_INOUT:
		return "inout";
	case EXIT_REASON_RDMSR:
		return "rdmsr";
	case EXIT_REASON_WRMSR:
		return "wrmsr";
	case EXIT_REASON_INVAL_VMCS:
		return "invalvmcs";
	case EXIT_REASON_INVAL_MSR:
		return "invalmsr";
	case EXIT_REASON_MWAIT:
		return "mwait";
	case EXIT_REASON_MTF:
		return "mtf";
	case EXIT_REASON_MONITOR:
		return "monitor";
	case EXIT_REASON_PAUSE:
		return "pause";
	case EXIT_REASON_MCE_DURING_ENTRY:
		return "mce-during-entry";
	case EXIT_REASON_TPR:
		return "tpr";
	case EXIT_REASON_APIC_ACCESS:
		return "apic-access";
	case EXIT_REASON_GDTR_IDTR:
		return "gdtridtr";
	case EXIT_REASON_LDTR_TR:
		return "ldtrtr";
	case EXIT_REASON_EPT_FAULT:
		return "eptfault";
	case EXIT_REASON_EPT_MISCONFIG:
		return "eptmisconfig";
	case EXIT_REASON_INVEPT:
		return "invept";
	case EXIT_REASON_RDTSCP:
		return "rdtscp";
	case EXIT_REASON_VMX_PREEMPT:
		return "vmxpreempt";
	case EXIT_REASON_INVVPID:
		return "invvpid";
	case EXIT_REASON_WBINVD:
		return "wbinvd";
	case EXIT_REASON_XSETBV:
		return "xsetbv";
	case EXIT_REASON_APIC_WRITE:
		return "apic-write";
	default:
		snprintf(reasonbuf, sizeof(reasonbuf), "%d", reason);
		return (reasonbuf);
	}
}


static int vmx_allow_x2apic_msrs(struct vmx *vmx)
{
	int i, error;

	error = 0;

	
	error += guest_msr_ro(vmx, MSR_APIC_ID);
	error += guest_msr_ro(vmx, MSR_APIC_VERSION);
	error += guest_msr_ro(vmx, MSR_APIC_LDR);
	error += guest_msr_ro(vmx, MSR_APIC_SVR);

	for (i = 0; i < 8; i++)
		error += guest_msr_ro(vmx, MSR_APIC_ISR0 + i);

	for (i = 0; i < 8; i++)
		error += guest_msr_ro(vmx, MSR_APIC_TMR0 + i);

	for (i = 0; i < 8; i++)
		error += guest_msr_ro(vmx, MSR_APIC_IRR0 + i);

	error += guest_msr_ro(vmx, MSR_APIC_ESR);
	error += guest_msr_ro(vmx, MSR_APIC_LVT_TIMER);
	error += guest_msr_ro(vmx, MSR_APIC_LVT_THERMAL);
	error += guest_msr_ro(vmx, MSR_APIC_LVT_PCINT);
	error += guest_msr_ro(vmx, MSR_APIC_LVT_LINT0);
	error += guest_msr_ro(vmx, MSR_APIC_LVT_LINT1);
	error += guest_msr_ro(vmx, MSR_APIC_LVT_ERROR);
	error += guest_msr_ro(vmx, MSR_APIC_ICR_TIMER);
	error += guest_msr_ro(vmx, MSR_APIC_DCR_TIMER);
	error += guest_msr_ro(vmx, MSR_APIC_ICR);

	
	error += guest_msr_rw(vmx, MSR_APIC_TPR);
	error += guest_msr_rw(vmx, MSR_APIC_EOI);
	error += guest_msr_rw(vmx, MSR_APIC_SELF_IPI);

	return (error);
}

u_long vmx_fix_cr0(u_long cr0)
{

	return ((cr0 | cr0_ones_mask) & ~cr0_zeros_mask);
}

u_long vmx_fix_cr4(u_long cr4)
{

	return ((cr4 | cr4_ones_mask) & ~cr4_zeros_mask);
}

static void vpid_free(int vpid)
{
	if (vpid < 0 || vpid > 0xffff)
		panic("vpid_free: invalid vpid %d", vpid);

	

	if (vpid > VM_MAXCPU)
		free_unr(vpid_unr, vpid);
}

static void vpid_alloc(uint16_t *vpid, int num)
{
	int i, x;

	if (num <= 0 || num > VM_MAXCPU)
		panic("invalid number of vpids requested: %d", num);

	
	if ((procbased_ctls2 & PROCBASED2_ENABLE_VPID) == 0) {
		for (i = 0; i < num; i++)
			vpid[i] = 0;
		return;
	}

	
	for (i = 0; i < num; i++) {
		x = alloc_unr(vpid_unr);
		if (x == -1)
			break;
		else vpid[i] = x;
	}

	if (i < num) {
		atomic_add_int(&vpid_alloc_failed, 1);

		
		while (i-- > 0)
			vpid_free(vpid[i]);

		for (i = 0; i < num; i++)
			vpid[i] = i + 1;
	}
}

static void vpid_init(void)
{
	
	vpid_unr = new_unrhdr(VM_MAXCPU + 1, 0xffff, NULL);
}

static void vmx_disable(void *arg __unused)
{
	struct invvpid_desc invvpid_desc = { 0 };
	struct invept_desc invept_desc = { 0 };

	if (vmxon_enabled[curcpu]) {
		
		invvpid(INVVPID_TYPE_ALL_CONTEXTS, invvpid_desc);
		invept(INVEPT_TYPE_ALL_CONTEXTS, invept_desc);
		vmxoff();
	}
	load_cr4(rcr4() & ~CR4_VMXE);
}

static int vmx_cleanup(void)
{

	if (pirvec >= 0)
		lapic_ipi_free(pirvec);

	if (vpid_unr != NULL) {
		delete_unrhdr(vpid_unr);
		vpid_unr = NULL;
	}

	if (nmi_flush_l1d_sw == 1)
		nmi_flush_l1d_sw = 0;

	smp_rendezvous(NULL, vmx_disable, NULL, NULL);

	return (0);
}

static void vmx_enable(void *arg __unused)
{
	int error;
	uint64_t feature_control;

	feature_control = rdmsr(MSR_IA32_FEATURE_CONTROL);
	if ((feature_control & IA32_FEATURE_CONTROL_LOCK) == 0 || (feature_control & IA32_FEATURE_CONTROL_VMX_EN) == 0) {
		wrmsr(MSR_IA32_FEATURE_CONTROL, feature_control | IA32_FEATURE_CONTROL_VMX_EN | IA32_FEATURE_CONTROL_LOCK);

	}

	load_cr4(rcr4() | CR4_VMXE);

	*(uint32_t *)vmxon_region[curcpu] = vmx_revision();
	error = vmxon(vmxon_region[curcpu]);
	if (error == 0)
		vmxon_enabled[curcpu] = 1;
}

static void vmx_restore(void)
{

	if (vmxon_enabled[curcpu])
		vmxon(vmxon_region[curcpu]);
}

static int vmx_init(int ipinum)
{
	int error;
	uint64_t basic, fixed0, fixed1, feature_control;
	uint32_t tmp, procbased2_vid_bits;

	
	if (!(cpu_feature2 & CPUID2_VMX)) {
		printf("vmx_init: processor does not support VMX operation\n");
		return (ENXIO);
	}

	
	feature_control = rdmsr(MSR_IA32_FEATURE_CONTROL);
	if ((feature_control & IA32_FEATURE_CONTROL_LOCK) == 1 && (feature_control & IA32_FEATURE_CONTROL_VMX_EN) == 0) {
		printf("vmx_init: VMX operation disabled by BIOS\n");
		return (ENXIO);
	}

	
	basic = rdmsr(MSR_VMX_BASIC);
	if ((basic & (1UL << 54)) == 0) {
		printf("vmx_init: processor does not support desired basic " "capabilities\n");
		return (EINVAL);
	}

	
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS, MSR_VMX_TRUE_PROCBASED_CTLS, PROCBASED_CTLS_ONE_SETTING, PROCBASED_CTLS_ZERO_SETTING, &procbased_ctls);


	if (error) {
		printf("vmx_init: processor does not support desired primary " "processor-based controls\n");
		return (error);
	}

	
	procbased_ctls &= ~PROCBASED_CTLS_WINDOW_SETTING;

	
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2, MSR_VMX_PROCBASED_CTLS2, PROCBASED_CTLS2_ONE_SETTING, PROCBASED_CTLS2_ZERO_SETTING, &procbased_ctls2);


	if (error) {
		printf("vmx_init: processor does not support desired secondary " "processor-based controls\n");
		return (error);
	}

	
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2, MSR_VMX_PROCBASED_CTLS2, PROCBASED2_ENABLE_VPID, 0, &tmp);
	if (error == 0)
		procbased_ctls2 |= PROCBASED2_ENABLE_VPID;

	
	error = vmx_set_ctlreg(MSR_VMX_PINBASED_CTLS, MSR_VMX_TRUE_PINBASED_CTLS, PINBASED_CTLS_ONE_SETTING, PINBASED_CTLS_ZERO_SETTING, &pinbased_ctls);


	if (error) {
		printf("vmx_init: processor does not support desired " "pin-based controls\n");
		return (error);
	}

	
	error = vmx_set_ctlreg(MSR_VMX_EXIT_CTLS, MSR_VMX_TRUE_EXIT_CTLS, VM_EXIT_CTLS_ONE_SETTING, VM_EXIT_CTLS_ZERO_SETTING, &exit_ctls);


	if (error) {
		printf("vmx_init: processor does not support desired " "exit controls\n");
		return (error);
	}

	
	error = vmx_set_ctlreg(MSR_VMX_ENTRY_CTLS, MSR_VMX_TRUE_ENTRY_CTLS, VM_ENTRY_CTLS_ONE_SETTING, VM_ENTRY_CTLS_ZERO_SETTING, &entry_ctls);

	if (error) {
		printf("vmx_init: processor does not support desired " "entry controls\n");
		return (error);
	}

	
	cap_halt_exit = (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS, MSR_VMX_TRUE_PROCBASED_CTLS, PROCBASED_HLT_EXITING, 0, &tmp) == 0);



	cap_monitor_trap = (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS, MSR_VMX_PROCBASED_CTLS, PROCBASED_MTF, 0, &tmp) == 0);



	cap_pause_exit = (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS, MSR_VMX_TRUE_PROCBASED_CTLS, PROCBASED_PAUSE_EXITING, 0, &tmp) == 0);



	
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2, MSR_VMX_PROCBASED_CTLS2, PROCBASED2_ENABLE_RDTSCP, 0, &tmp);

	cap_rdpid = error == 0 && host_has_rdpid();
	cap_rdtscp = error == 0 && host_has_rdtscp();
	if (cap_rdpid || cap_rdtscp)
		procbased_ctls2 |= PROCBASED2_ENABLE_RDTSCP;

	cap_unrestricted_guest = (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2, MSR_VMX_PROCBASED_CTLS2, PROCBASED2_UNRESTRICTED_GUEST, 0, &tmp) == 0);



	cap_invpcid = (vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2, MSR_VMX_PROCBASED_CTLS2, PROCBASED2_ENABLE_INVPCID, 0, &tmp) == 0);


	
	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS, MSR_VMX_TRUE_PROCBASED_CTLS, PROCBASED_USE_TPR_SHADOW, 0, &tmp);

	if (error == 0) {
		tpr_shadowing = 1;
		TUNABLE_INT_FETCH("hw.vmm.vmx.use_tpr_shadowing", &tpr_shadowing);
	}

	if (tpr_shadowing) {
		procbased_ctls |= PROCBASED_USE_TPR_SHADOW;
		procbased_ctls &= ~PROCBASED_CR8_LOAD_EXITING;
		procbased_ctls &= ~PROCBASED_CR8_STORE_EXITING;
	}

	
	procbased2_vid_bits = (PROCBASED2_VIRTUALIZE_APIC_ACCESSES | PROCBASED2_VIRTUALIZE_X2APIC_MODE | PROCBASED2_APIC_REGISTER_VIRTUALIZATION | PROCBASED2_VIRTUAL_INTERRUPT_DELIVERY);



	error = vmx_set_ctlreg(MSR_VMX_PROCBASED_CTLS2, MSR_VMX_PROCBASED_CTLS2, procbased2_vid_bits, 0, &tmp);
	if (error == 0 && tpr_shadowing) {
		virtual_interrupt_delivery = 1;
		TUNABLE_INT_FETCH("hw.vmm.vmx.use_apic_vid", &virtual_interrupt_delivery);
	}

	if (virtual_interrupt_delivery) {
		procbased_ctls |= PROCBASED_USE_TPR_SHADOW;
		procbased_ctls2 |= procbased2_vid_bits;
		procbased_ctls2 &= ~PROCBASED2_VIRTUALIZE_X2APIC_MODE;

		
		error = vmx_set_ctlreg(MSR_VMX_PINBASED_CTLS, MSR_VMX_TRUE_PINBASED_CTLS, PINBASED_POSTED_INTERRUPT, 0, &tmp);

		if (error == 0) {
			pirvec = lapic_ipi_alloc(pti ? &IDTVEC(justreturn1_pti) :
			    &IDTVEC(justreturn));
			if (pirvec < 0) {
				if (bootverbose) {
					printf("vmx_init: unable to allocate " "posted interrupt vector\n");
				}
			} else {
				posted_interrupts = 1;
				TUNABLE_INT_FETCH("hw.vmm.vmx.use_apic_pir", &posted_interrupts);
			}
		}
	}

	if (posted_interrupts)
		    pinbased_ctls |= PINBASED_POSTED_INTERRUPT;

	
	error = ept_init(ipinum);
	if (error) {
		printf("vmx_init: ept initialization failed (%d)\n", error);
		return (error);
	}

	guest_l1d_flush = (cpu_ia32_arch_caps & IA32_ARCH_CAP_SKIP_L1DFL_VMENTRY) == 0;
	TUNABLE_INT_FETCH("hw.vmm.l1d_flush", &guest_l1d_flush);

	
	if (guest_l1d_flush) {
		if ((cpu_stdext_feature3 & CPUID_STDEXT3_L1D_FLUSH) == 0) {
			guest_l1d_flush_sw = 1;
			TUNABLE_INT_FETCH("hw.vmm.l1d_flush_sw", &guest_l1d_flush_sw);
		}
		if (guest_l1d_flush_sw) {
			if (nmi_flush_l1d_sw <= 1)
				nmi_flush_l1d_sw = 1;
		} else {
			msr_load_list[0].index = MSR_IA32_FLUSH_CMD;
			msr_load_list[0].val = IA32_FLUSH_CMD_L1D;
		}
	}

	
	fixed0 = rdmsr(MSR_VMX_CR0_FIXED0);
	fixed1 = rdmsr(MSR_VMX_CR0_FIXED1);
	cr0_ones_mask = fixed0 & fixed1;
	cr0_zeros_mask = ~fixed0 & ~fixed1;

	
	if (cap_unrestricted_guest)
		cr0_ones_mask &= ~(CR0_PG | CR0_PE);

	
	cr0_zeros_mask |= (CR0_NW | CR0_CD);

	fixed0 = rdmsr(MSR_VMX_CR4_FIXED0);
	fixed1 = rdmsr(MSR_VMX_CR4_FIXED1);
	cr4_ones_mask = fixed0 & fixed1;
	cr4_zeros_mask = ~fixed0 & ~fixed1;

	vpid_init();

	vmx_msr_init();

	
	smp_rendezvous(NULL, vmx_enable, NULL, NULL);

	vmx_initialized = 1;

	return (0);
}

static void vmx_trigger_hostintr(int vector)
{
	uintptr_t func;
	struct gate_descriptor *gd;

	gd = &idt[vector];

	KASSERT(vector >= 32 && vector <= 255, ("vmx_trigger_hostintr: " "invalid vector %d", vector));
	KASSERT(gd->gd_p == 1, ("gate descriptor for vector %d not present", vector));
	KASSERT(gd->gd_type == SDT_SYSIGT, ("gate descriptor for vector %d " "has invalid type %d", vector, gd->gd_type));
	KASSERT(gd->gd_dpl == SEL_KPL, ("gate descriptor for vector %d " "has invalid dpl %d", vector, gd->gd_dpl));
	KASSERT(gd->gd_selector == GSEL(GCODE_SEL, SEL_KPL), ("gate descriptor " "for vector %d has invalid selector %d", vector, gd->gd_selector));
	KASSERT(gd->gd_ist == 0, ("gate descriptor for vector %d has invalid " "IST %d", vector, gd->gd_ist));

	func = ((long)gd->gd_hioffset << 16 | gd->gd_looffset);
	vmx_call_isr(func);
}

static int vmx_setup_cr_shadow(int which, struct vmcs *vmcs, uint32_t initial)
{
	int error, mask_ident, shadow_ident;
	uint64_t mask_value;

	if (which != 0 && which != 4)
		panic("vmx_setup_cr_shadow: unknown cr%d", which);

	if (which == 0) {
		mask_ident = VMCS_CR0_MASK;
		mask_value = cr0_ones_mask | cr0_zeros_mask;
		shadow_ident = VMCS_CR0_SHADOW;
	} else {
		mask_ident = VMCS_CR4_MASK;
		mask_value = cr4_ones_mask | cr4_zeros_mask;
		shadow_ident = VMCS_CR4_SHADOW;
	}

	error = vmcs_setreg(vmcs, 0, VMCS_IDENT(mask_ident), mask_value);
	if (error)
		return (error);

	error = vmcs_setreg(vmcs, 0, VMCS_IDENT(shadow_ident), initial);
	if (error)
		return (error);

	return (0);
}



static void * vmx_vminit(struct vm *vm, pmap_t pmap)
{
	uint16_t vpid[VM_MAXCPU];
	int i, error;
	struct vmx *vmx;
	struct vmcs *vmcs;
	uint32_t exc_bitmap;
	uint16_t maxcpus;

	vmx = malloc(sizeof(struct vmx), M_VMX, M_WAITOK | M_ZERO);
	if ((uintptr_t)vmx & PAGE_MASK) {
		panic("malloc of struct vmx not aligned on %d byte boundary", PAGE_SIZE);
	}
	vmx->vm = vm;

	vmx->eptp = eptp(vtophys((vm_offset_t)pmap->pm_pmltop));

	
	ept_invalidate_mappings(vmx->eptp);

	msr_bitmap_initialize(vmx->msr_bitmap);

	
	if (guest_msr_rw(vmx, MSR_GSBASE) || guest_msr_rw(vmx, MSR_FSBASE) || guest_msr_rw(vmx, MSR_SYSENTER_CS_MSR) || guest_msr_rw(vmx, MSR_SYSENTER_ESP_MSR) || guest_msr_rw(vmx, MSR_SYSENTER_EIP_MSR) || guest_msr_rw(vmx, MSR_EFER) || guest_msr_ro(vmx, MSR_TSC) || ((cap_rdpid || cap_rdtscp) && guest_msr_ro(vmx, MSR_TSC_AUX)))






		panic("vmx_vminit: error setting guest msr access");

	vpid_alloc(vpid, VM_MAXCPU);

	if (virtual_interrupt_delivery) {
		error = vm_map_mmio(vm, DEFAULT_APIC_BASE, PAGE_SIZE, APIC_ACCESS_ADDRESS);
		
		KASSERT(error == 0, ("vm_map_mmio(apicbase) error %d", error));
	}

	maxcpus = vm_get_maxcpus(vm);
	for (i = 0; i < maxcpus; i++) {
		vmcs = &vmx->vmcs[i];
		vmcs->identifier = vmx_revision();
		error = vmclear(vmcs);
		if (error != 0) {
			panic("vmx_vminit: vmclear error %d on vcpu %d\n", error, i);
		}

		vmx_msr_guest_init(vmx, i);

		error = vmcs_init(vmcs);
		KASSERT(error == 0, ("vmcs_init error %d", error));

		VMPTRLD(vmcs);
		error = 0;
		error += vmwrite(VMCS_HOST_RSP, (u_long)&vmx->ctx[i]);
		error += vmwrite(VMCS_EPTP, vmx->eptp);
		error += vmwrite(VMCS_PIN_BASED_CTLS, pinbased_ctls);
		error += vmwrite(VMCS_PRI_PROC_BASED_CTLS, procbased_ctls);
		error += vmwrite(VMCS_SEC_PROC_BASED_CTLS, procbased_ctls2);
		error += vmwrite(VMCS_EXIT_CTLS, exit_ctls);
		error += vmwrite(VMCS_ENTRY_CTLS, entry_ctls);
		error += vmwrite(VMCS_MSR_BITMAP, vtophys(vmx->msr_bitmap));
		error += vmwrite(VMCS_VPID, vpid[i]);

		if (guest_l1d_flush && !guest_l1d_flush_sw) {
			vmcs_write(VMCS_ENTRY_MSR_LOAD, pmap_kextract( (vm_offset_t)&msr_load_list[0]));
			vmcs_write(VMCS_ENTRY_MSR_LOAD_COUNT, nitems(msr_load_list));
			vmcs_write(VMCS_EXIT_MSR_STORE, 0);
			vmcs_write(VMCS_EXIT_MSR_STORE_COUNT, 0);
		}

		
		if (vcpu_trace_exceptions(vm, i))
			exc_bitmap = 0xffffffff;
		else exc_bitmap = 1 << IDT_MC;
		error += vmwrite(VMCS_EXCEPTION_BITMAP, exc_bitmap);

		vmx->ctx[i].guest_dr6 = DBREG_DR6_RESERVED1;
		error += vmwrite(VMCS_GUEST_DR7, DBREG_DR7_RESERVED1);

		if (tpr_shadowing) {
			error += vmwrite(VMCS_VIRTUAL_APIC, vtophys(&vmx->apic_page[i]));
		}

		if (virtual_interrupt_delivery) {
			error += vmwrite(VMCS_APIC_ACCESS, APIC_ACCESS_ADDRESS);
			error += vmwrite(VMCS_EOI_EXIT0, 0);
			error += vmwrite(VMCS_EOI_EXIT1, 0);
			error += vmwrite(VMCS_EOI_EXIT2, 0);
			error += vmwrite(VMCS_EOI_EXIT3, 0);
		}
		if (posted_interrupts) {
			error += vmwrite(VMCS_PIR_VECTOR, pirvec);
			error += vmwrite(VMCS_PIR_DESC, vtophys(&vmx->pir_desc[i]));
		}
		VMCLEAR(vmcs);
		KASSERT(error == 0, ("vmx_vminit: error customizing the vmcs"));

		vmx->cap[i].set = 0;
		vmx->cap[i].set |= cap_rdpid != 0 ? 1 << VM_CAP_RDPID : 0;
		vmx->cap[i].set |= cap_rdtscp != 0 ? 1 << VM_CAP_RDTSCP : 0;
		vmx->cap[i].proc_ctls = procbased_ctls;
		vmx->cap[i].proc_ctls2 = procbased_ctls2;
		vmx->cap[i].exc_bitmap = exc_bitmap;

		vmx->state[i].nextrip = ~0;
		vmx->state[i].lastcpu = NOCPU;
		vmx->state[i].vpid = vpid[i];

		
		error = vmx_setup_cr0_shadow(vmcs, 0x60000010);
		if (error != 0)
			panic("vmx_setup_cr0_shadow %d", error);

		error = vmx_setup_cr4_shadow(vmcs, 0);
		if (error != 0)
			panic("vmx_setup_cr4_shadow %d", error);

		vmx->ctx[i].pmap = pmap;
	}

	return (vmx);
}

static int vmx_handle_cpuid(struct vm *vm, int vcpu, struct vmxctx *vmxctx)
{
	int handled, func;

	func = vmxctx->guest_rax;

	handled = x86_emulate_cpuid(vm, vcpu, (uint32_t*)(&vmxctx->guest_rax), (uint32_t*)(&vmxctx->guest_rbx), (uint32_t*)(&vmxctx->guest_rcx), (uint32_t*)(&vmxctx->guest_rdx));



	return (handled);
}

static __inline void vmx_run_trace(struct vmx *vmx, int vcpu)
{

	VCPU_CTR1(vmx->vm, vcpu, "Resume execution at %#lx", vmcs_guest_rip());

}

static __inline void vmx_exit_trace(struct vmx *vmx, int vcpu, uint64_t rip, uint32_t exit_reason, int handled)

{

	VCPU_CTR3(vmx->vm, vcpu, "%s %s vmexit at 0x%0lx", handled ? "handled" : "unhandled", exit_reason_to_str(exit_reason), rip);


}

static __inline void vmx_astpending_trace(struct vmx *vmx, int vcpu, uint64_t rip)
{

	VCPU_CTR1(vmx->vm, vcpu, "astpending vmexit at 0x%0lx", rip);

}

static VMM_STAT_INTEL(VCPU_INVVPID_SAVED, "Number of vpid invalidations saved");
static VMM_STAT_INTEL(VCPU_INVVPID_DONE, "Number of vpid invalidations done");


static __inline void vmx_invvpid(struct vmx *vmx, int vcpu, pmap_t pmap, int running)
{
	struct vmxstate *vmxstate;
	struct invvpid_desc invvpid_desc;

	vmxstate = &vmx->state[vcpu];
	if (vmxstate->vpid == 0)
		return;

	if (!running) {
		
		vmxstate->lastcpu = NOCPU;
		return;
	}

	KASSERT(curthread->td_critnest > 0, ("%s: vcpu %d running outside " "critical section", __func__, vcpu));

	
	if (pmap->pm_eptgen == vmx->eptgen[curcpu]) {
		invvpid_desc._res1 = 0;
		invvpid_desc._res2 = 0;
		invvpid_desc.vpid = vmxstate->vpid;
		invvpid_desc.linear_addr = 0;
		invvpid(INVVPID_TYPE_SINGLE_CONTEXT, invvpid_desc);
		vmm_stat_incr(vmx->vm, vcpu, VCPU_INVVPID_DONE, 1);
	} else {
		
		vmm_stat_incr(vmx->vm, vcpu, VCPU_INVVPID_SAVED, 1);
	}
}

static void vmx_set_pcpu_defaults(struct vmx *vmx, int vcpu, pmap_t pmap)
{
	struct vmxstate *vmxstate;

	vmxstate = &vmx->state[vcpu];
	if (vmxstate->lastcpu == curcpu)
		return;

	vmxstate->lastcpu = curcpu;

	vmm_stat_incr(vmx->vm, vcpu, VCPU_MIGRATIONS, 1);

	vmcs_write(VMCS_HOST_TR_BASE, vmm_get_host_trbase());
	vmcs_write(VMCS_HOST_GDTR_BASE, vmm_get_host_gdtrbase());
	vmcs_write(VMCS_HOST_GS_BASE, vmm_get_host_gsbase());
	vmx_invvpid(vmx, vcpu, pmap, 1);
}


CTASSERT((PROCBASED_CTLS_ONE_SETTING & PROCBASED_INT_WINDOW_EXITING) != 0);

static void __inline vmx_set_int_window_exiting(struct vmx *vmx, int vcpu)
{

	if ((vmx->cap[vcpu].proc_ctls & PROCBASED_INT_WINDOW_EXITING) == 0) {
		vmx->cap[vcpu].proc_ctls |= PROCBASED_INT_WINDOW_EXITING;
		vmcs_write(VMCS_PRI_PROC_BASED_CTLS, vmx->cap[vcpu].proc_ctls);
		VCPU_CTR0(vmx->vm, vcpu, "Enabling interrupt window exiting");
	}
}

static void __inline vmx_clear_int_window_exiting(struct vmx *vmx, int vcpu)
{

	KASSERT((vmx->cap[vcpu].proc_ctls & PROCBASED_INT_WINDOW_EXITING) != 0, ("intr_window_exiting not set: %#x", vmx->cap[vcpu].proc_ctls));
	vmx->cap[vcpu].proc_ctls &= ~PROCBASED_INT_WINDOW_EXITING;
	vmcs_write(VMCS_PRI_PROC_BASED_CTLS, vmx->cap[vcpu].proc_ctls);
	VCPU_CTR0(vmx->vm, vcpu, "Disabling interrupt window exiting");
}

static void __inline vmx_set_nmi_window_exiting(struct vmx *vmx, int vcpu)
{

	if ((vmx->cap[vcpu].proc_ctls & PROCBASED_NMI_WINDOW_EXITING) == 0) {
		vmx->cap[vcpu].proc_ctls |= PROCBASED_NMI_WINDOW_EXITING;
		vmcs_write(VMCS_PRI_PROC_BASED_CTLS, vmx->cap[vcpu].proc_ctls);
		VCPU_CTR0(vmx->vm, vcpu, "Enabling NMI window exiting");
	}
}

static void __inline vmx_clear_nmi_window_exiting(struct vmx *vmx, int vcpu)
{

	KASSERT((vmx->cap[vcpu].proc_ctls & PROCBASED_NMI_WINDOW_EXITING) != 0, ("nmi_window_exiting not set %#x", vmx->cap[vcpu].proc_ctls));
	vmx->cap[vcpu].proc_ctls &= ~PROCBASED_NMI_WINDOW_EXITING;
	vmcs_write(VMCS_PRI_PROC_BASED_CTLS, vmx->cap[vcpu].proc_ctls);
	VCPU_CTR0(vmx->vm, vcpu, "Disabling NMI window exiting");
}

int vmx_set_tsc_offset(struct vmx *vmx, int vcpu, uint64_t offset)
{
	int error;

	if ((vmx->cap[vcpu].proc_ctls & PROCBASED_TSC_OFFSET) == 0) {
		vmx->cap[vcpu].proc_ctls |= PROCBASED_TSC_OFFSET;
		vmcs_write(VMCS_PRI_PROC_BASED_CTLS, vmx->cap[vcpu].proc_ctls);
		VCPU_CTR0(vmx->vm, vcpu, "Enabling TSC offsetting");
	}

	error = vmwrite(VMCS_TSC_OFFSET, offset);

	if (error == 0)
		error = vm_set_tsc_offset(vmx->vm, vcpu, offset);

	return (error);
}




static void vmx_inject_nmi(struct vmx *vmx, int vcpu)
{
	uint32_t gi, info;

	gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
	KASSERT((gi & NMI_BLOCKING) == 0, ("vmx_inject_nmi: invalid guest " "interruptibility-state %#x", gi));

	info = vmcs_read(VMCS_ENTRY_INTR_INFO);
	KASSERT((info & VMCS_INTR_VALID) == 0, ("vmx_inject_nmi: invalid " "VM-entry interruption information %#x", info));

	
	info = IDT_NMI | VMCS_INTR_T_NMI | VMCS_INTR_VALID;
	vmcs_write(VMCS_ENTRY_INTR_INFO, info);

	VCPU_CTR0(vmx->vm, vcpu, "Injecting vNMI");

	
	vm_nmi_clear(vmx->vm, vcpu);
}

static void vmx_inject_interrupts(struct vmx *vmx, int vcpu, struct vlapic *vlapic, uint64_t guestrip)

{
	int vector, need_nmi_exiting, extint_pending;
	uint64_t rflags, entryinfo;
	uint32_t gi, info;

	if (vmx->state[vcpu].nextrip != guestrip) {
		gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
		if (gi & HWINTR_BLOCKING) {
			VCPU_CTR2(vmx->vm, vcpu, "Guest interrupt blocking " "cleared due to rip change: %#lx/%#lx", vmx->state[vcpu].nextrip, guestrip);

			gi &= ~HWINTR_BLOCKING;
			vmcs_write(VMCS_GUEST_INTERRUPTIBILITY, gi);
		}
	}

	if (vm_entry_intinfo(vmx->vm, vcpu, &entryinfo)) {
		KASSERT((entryinfo & VMCS_INTR_VALID) != 0, ("%s: entry " "intinfo is not valid: %#lx", __func__, entryinfo));

		info = vmcs_read(VMCS_ENTRY_INTR_INFO);
		KASSERT((info & VMCS_INTR_VALID) == 0, ("%s: cannot inject " "pending exception: %#lx/%#x", __func__, entryinfo, info));

		info = entryinfo;
		vector = info & 0xff;
		if (vector == IDT_BP || vector == IDT_OF) {
			
			info &= ~VMCS_INTR_T_MASK;
			info |= VMCS_INTR_T_SWEXCEPTION;
		}

		if (info & VMCS_INTR_DEL_ERRCODE)
			vmcs_write(VMCS_ENTRY_EXCEPTION_ERROR, entryinfo >> 32);

		vmcs_write(VMCS_ENTRY_INTR_INFO, info);
	}

	if (vm_nmi_pending(vmx->vm, vcpu)) {
		
		need_nmi_exiting = 1;
		gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
		if ((gi & (HWINTR_BLOCKING | NMI_BLOCKING)) == 0) {
			info = vmcs_read(VMCS_ENTRY_INTR_INFO);
			if ((info & VMCS_INTR_VALID) == 0) {
				vmx_inject_nmi(vmx, vcpu);
				need_nmi_exiting = 0;
			} else {
				VCPU_CTR1(vmx->vm, vcpu, "Cannot inject NMI " "due to VM-entry intr info %#x", info);
			}
		} else {
			VCPU_CTR1(vmx->vm, vcpu, "Cannot inject NMI due to " "Guest Interruptibility-state %#x", gi);
		}

		if (need_nmi_exiting)
			vmx_set_nmi_window_exiting(vmx, vcpu);
	}

	extint_pending = vm_extint_pending(vmx->vm, vcpu);

	if (!extint_pending && virtual_interrupt_delivery) {
		vmx_inject_pir(vlapic);
		return;
	}

	
	if ((vmx->cap[vcpu].proc_ctls & PROCBASED_INT_WINDOW_EXITING) != 0) {
		VCPU_CTR0(vmx->vm, vcpu, "Skip interrupt injection due to " "pending int_window_exiting");
		return;
	}

	if (!extint_pending) {
		
		if (!vlapic_pending_intr(vlapic, &vector))
			return;

		
		KASSERT(vector >= 16 && vector <= 255, ("invalid vector %d from local APIC", vector));
	} else {
		
		vatpic_pending_intr(vmx->vm, &vector);

		
		KASSERT(vector >= 0 && vector <= 255, ("invalid vector %d from INTR", vector));
	}

	
	rflags = vmcs_read(VMCS_GUEST_RFLAGS);
	if ((rflags & PSL_I) == 0) {
		VCPU_CTR2(vmx->vm, vcpu, "Cannot inject vector %d due to " "rflags %#lx", vector, rflags);
		goto cantinject;
	}

	gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
	if (gi & HWINTR_BLOCKING) {
		VCPU_CTR2(vmx->vm, vcpu, "Cannot inject vector %d due to " "Guest Interruptibility-state %#x", vector, gi);
		goto cantinject;
	}

	info = vmcs_read(VMCS_ENTRY_INTR_INFO);
	if (info & VMCS_INTR_VALID) {
		
		VCPU_CTR2(vmx->vm, vcpu, "Cannot inject vector %d due to " "VM-entry intr info %#x", vector, info);
		goto cantinject;
	}

	
	info = VMCS_INTR_T_HWINTR | VMCS_INTR_VALID;
	info |= vector;
	vmcs_write(VMCS_ENTRY_INTR_INFO, info);

	if (!extint_pending) {
		
		vlapic_intr_accepted(vlapic, vector);
	} else {
		vm_extint_clear(vmx->vm, vcpu);
		vatpic_intr_accepted(vmx->vm, vector);

		
		vmx_set_int_window_exiting(vmx, vcpu);
	}

	VCPU_CTR1(vmx->vm, vcpu, "Injecting hwintr at vector %d", vector);

	return;

cantinject:
	
	vmx_set_int_window_exiting(vmx, vcpu);
}


static void vmx_restore_nmi_blocking(struct vmx *vmx, int vcpuid)
{
	uint32_t gi;

	VCPU_CTR0(vmx->vm, vcpuid, "Restore Virtual-NMI blocking");
	gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
	gi |= VMCS_INTERRUPTIBILITY_NMI_BLOCKING;
	vmcs_write(VMCS_GUEST_INTERRUPTIBILITY, gi);
}

static void vmx_clear_nmi_blocking(struct vmx *vmx, int vcpuid)
{
	uint32_t gi;

	VCPU_CTR0(vmx->vm, vcpuid, "Clear Virtual-NMI blocking");
	gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
	gi &= ~VMCS_INTERRUPTIBILITY_NMI_BLOCKING;
	vmcs_write(VMCS_GUEST_INTERRUPTIBILITY, gi);
}

static void vmx_assert_nmi_blocking(struct vmx *vmx, int vcpuid)
{
	uint32_t gi;

	gi = vmcs_read(VMCS_GUEST_INTERRUPTIBILITY);
	KASSERT(gi & VMCS_INTERRUPTIBILITY_NMI_BLOCKING, ("NMI blocking is not in effect %#x", gi));
}

static int vmx_emulate_xsetbv(struct vmx *vmx, int vcpu, struct vm_exit *vmexit)
{
	struct vmxctx *vmxctx;
	uint64_t xcrval;
	const struct xsave_limits *limits;

	vmxctx = &vmx->ctx[vcpu];
	limits = vmm_get_xsave_limits();

	

	
	if (vmxctx->guest_rcx != 0) {
		vm_inject_gp(vmx->vm, vcpu);
		return (HANDLED);
	}

	
	if (!limits->xsave_enabled || !(vmcs_read(VMCS_GUEST_CR4) & CR4_XSAVE)) {
		vm_inject_ud(vmx->vm, vcpu);
		return (HANDLED);
	}

	xcrval = vmxctx->guest_rdx << 32 | (vmxctx->guest_rax & 0xffffffff);
	if ((xcrval & ~limits->xcr0_allowed) != 0) {
		vm_inject_gp(vmx->vm, vcpu);
		return (HANDLED);
	}

	if (!(xcrval & XFEATURE_ENABLED_X87)) {
		vm_inject_gp(vmx->vm, vcpu);
		return (HANDLED);
	}

	
	if (xcrval & XFEATURE_ENABLED_AVX && (xcrval & XFEATURE_AVX) != XFEATURE_AVX) {
		vm_inject_gp(vmx->vm, vcpu);
		return (HANDLED);
	}

	
	if (xcrval & XFEATURE_AVX512 && (xcrval & (XFEATURE_AVX512 | XFEATURE_AVX)) != (XFEATURE_AVX512 | XFEATURE_AVX)) {

		vm_inject_gp(vmx->vm, vcpu);
		return (HANDLED);
	}

	
	if (((xcrval & XFEATURE_ENABLED_BNDREGS) != 0) != ((xcrval & XFEATURE_ENABLED_BNDCSR) != 0)) {
		vm_inject_gp(vmx->vm, vcpu);
		return (HANDLED);
	}

	
	load_xcr(0, xcrval);
	return (HANDLED);
}

static uint64_t vmx_get_guest_reg(struct vmx *vmx, int vcpu, int ident)
{
	const struct vmxctx *vmxctx;

	vmxctx = &vmx->ctx[vcpu];

	switch (ident) {
	case 0:
		return (vmxctx->guest_rax);
	case 1:
		return (vmxctx->guest_rcx);
	case 2:
		return (vmxctx->guest_rdx);
	case 3:
		return (vmxctx->guest_rbx);
	case 4:
		return (vmcs_read(VMCS_GUEST_RSP));
	case 5:
		return (vmxctx->guest_rbp);
	case 6:
		return (vmxctx->guest_rsi);
	case 7:
		return (vmxctx->guest_rdi);
	case 8:
		return (vmxctx->guest_r8);
	case 9:
		return (vmxctx->guest_r9);
	case 10:
		return (vmxctx->guest_r10);
	case 11:
		return (vmxctx->guest_r11);
	case 12:
		return (vmxctx->guest_r12);
	case 13:
		return (vmxctx->guest_r13);
	case 14:
		return (vmxctx->guest_r14);
	case 15:
		return (vmxctx->guest_r15);
	default:
		panic("invalid vmx register %d", ident);
	}
}

static void vmx_set_guest_reg(struct vmx *vmx, int vcpu, int ident, uint64_t regval)
{
	struct vmxctx *vmxctx;

	vmxctx = &vmx->ctx[vcpu];

	switch (ident) {
	case 0:
		vmxctx->guest_rax = regval;
		break;
	case 1:
		vmxctx->guest_rcx = regval;
		break;
	case 2:
		vmxctx->guest_rdx = regval;
		break;
	case 3:
		vmxctx->guest_rbx = regval;
		break;
	case 4:
		vmcs_write(VMCS_GUEST_RSP, regval);
		break;
	case 5:
		vmxctx->guest_rbp = regval;
		break;
	case 6:
		vmxctx->guest_rsi = regval;
		break;
	case 7:
		vmxctx->guest_rdi = regval;
		break;
	case 8:
		vmxctx->guest_r8 = regval;
		break;
	case 9:
		vmxctx->guest_r9 = regval;
		break;
	case 10:
		vmxctx->guest_r10 = regval;
		break;
	case 11:
		vmxctx->guest_r11 = regval;
		break;
	case 12:
		vmxctx->guest_r12 = regval;
		break;
	case 13:
		vmxctx->guest_r13 = regval;
		break;
	case 14:
		vmxctx->guest_r14 = regval;
		break;
	case 15:
		vmxctx->guest_r15 = regval;
		break;
	default:
		panic("invalid vmx register %d", ident);
	}
}

static int vmx_emulate_cr0_access(struct vmx *vmx, int vcpu, uint64_t exitqual)
{
	uint64_t crval, regval;

	
	if ((exitqual & 0xf0) != 0x00)
		return (UNHANDLED);

	regval = vmx_get_guest_reg(vmx, vcpu, (exitqual >> 8) & 0xf);

	vmcs_write(VMCS_CR0_SHADOW, regval);

	crval = regval | cr0_ones_mask;
	crval &= ~cr0_zeros_mask;
	vmcs_write(VMCS_GUEST_CR0, crval);

	if (regval & CR0_PG) {
		uint64_t efer, entry_ctls;

		
		efer = vmcs_read(VMCS_GUEST_IA32_EFER);
		if (efer & EFER_LME) {
			efer |= EFER_LMA;
			vmcs_write(VMCS_GUEST_IA32_EFER, efer);
			entry_ctls = vmcs_read(VMCS_ENTRY_CTLS);
			entry_ctls |= VM_ENTRY_GUEST_LMA;
			vmcs_write(VMCS_ENTRY_CTLS, entry_ctls);
		}
	}

	return (HANDLED);
}

static int vmx_emulate_cr4_access(struct vmx *vmx, int vcpu, uint64_t exitqual)
{
	uint64_t crval, regval;

	
	if ((exitqual & 0xf0) != 0x00)
		return (UNHANDLED);

	regval = vmx_get_guest_reg(vmx, vcpu, (exitqual >> 8) & 0xf);

	vmcs_write(VMCS_CR4_SHADOW, regval);

	crval = regval | cr4_ones_mask;
	crval &= ~cr4_zeros_mask;
	vmcs_write(VMCS_GUEST_CR4, crval);

	return (HANDLED);
}

static int vmx_emulate_cr8_access(struct vmx *vmx, int vcpu, uint64_t exitqual)
{
	struct vlapic *vlapic;
	uint64_t cr8;
	int regnum;

	
	if ((exitqual & 0xe0) != 0x00) {
		return (UNHANDLED);
	}

	vlapic = vm_lapic(vmx->vm, vcpu);
	regnum = (exitqual >> 8) & 0xf;
	if (exitqual & 0x10) {
		cr8 = vlapic_get_cr8(vlapic);
		vmx_set_guest_reg(vmx, vcpu, regnum, cr8);
	} else {
		cr8 = vmx_get_guest_reg(vmx, vcpu, regnum);
		vlapic_set_cr8(vlapic, cr8);
	}

	return (HANDLED);
}


static int vmx_cpl(void)
{
	uint32_t ssar;

	ssar = vmcs_read(VMCS_GUEST_SS_ACCESS_RIGHTS);
	return ((ssar >> 5) & 0x3);
}

static enum vm_cpu_mode vmx_cpu_mode(void)
{
	uint32_t csar;

	if (vmcs_read(VMCS_GUEST_IA32_EFER) & EFER_LMA) {
		csar = vmcs_read(VMCS_GUEST_CS_ACCESS_RIGHTS);
		if (csar & 0x2000)
			return (CPU_MODE_64BIT);	
		else return (CPU_MODE_COMPATIBILITY);
	} else if (vmcs_read(VMCS_GUEST_CR0) & CR0_PE) {
		return (CPU_MODE_PROTECTED);
	} else {
		return (CPU_MODE_REAL);
	}
}

static enum vm_paging_mode vmx_paging_mode(void)
{
	uint64_t cr4;

	if (!(vmcs_read(VMCS_GUEST_CR0) & CR0_PG))
		return (PAGING_MODE_FLAT);
	cr4 = vmcs_read(VMCS_GUEST_CR4);
	if (!(cr4 & CR4_PAE))
		return (PAGING_MODE_32);
	if (vmcs_read(VMCS_GUEST_IA32_EFER) & EFER_LME) {
		if (!(cr4 & CR4_LA57))
			return (PAGING_MODE_64);
		return (PAGING_MODE_64_LA57);
	} else return (PAGING_MODE_PAE);
}

static uint64_t inout_str_index(struct vmx *vmx, int vcpuid, int in)
{
	uint64_t val;
	int error;
	enum vm_reg_name reg;

	reg = in ? VM_REG_GUEST_RDI : VM_REG_GUEST_RSI;
	error = vmx_getreg(vmx, vcpuid, reg, &val);
	KASSERT(error == 0, ("%s: vmx_getreg error %d", __func__, error));
	return (val);
}

static uint64_t inout_str_count(struct vmx *vmx, int vcpuid, int rep)
{
	uint64_t val;
	int error;

	if (rep) {
		error = vmx_getreg(vmx, vcpuid, VM_REG_GUEST_RCX, &val);
		KASSERT(!error, ("%s: vmx_getreg error %d", __func__, error));
	} else {
		val = 1;
	}
	return (val);
}

static int inout_str_addrsize(uint32_t inst_info)
{
	uint32_t size;

	size = (inst_info >> 7) & 0x7;
	switch (size) {
	case 0:
		return (2);	
	case 1:
		return (4);	
	case 2:
		return (8);	
	default:
		panic("%s: invalid size encoding %d", __func__, size);
	}
}

static void inout_str_seginfo(struct vmx *vmx, int vcpuid, uint32_t inst_info, int in, struct vm_inout_str *vis)

{
	int error, s;

	if (in) {
		vis->seg_name = VM_REG_GUEST_ES;
	} else {
		s = (inst_info >> 15) & 0x7;
		vis->seg_name = vm_segment_name(s);
	}

	error = vmx_getdesc(vmx, vcpuid, vis->seg_name, &vis->seg_desc);
	KASSERT(error == 0, ("%s: vmx_getdesc error %d", __func__, error));
}

static void vmx_paging_info(struct vm_guest_paging *paging)
{
	paging->cr3 = vmcs_guest_cr3();
	paging->cpl = vmx_cpl();
	paging->cpu_mode = vmx_cpu_mode();
	paging->paging_mode = vmx_paging_mode();
}

static void vmexit_inst_emul(struct vm_exit *vmexit, uint64_t gpa, uint64_t gla)
{
	struct vm_guest_paging *paging;
	uint32_t csar;

	paging = &vmexit->u.inst_emul.paging;

	vmexit->exitcode = VM_EXITCODE_INST_EMUL;
	vmexit->inst_length = 0;
	vmexit->u.inst_emul.gpa = gpa;
	vmexit->u.inst_emul.gla = gla;
	vmx_paging_info(paging);
	switch (paging->cpu_mode) {
	case CPU_MODE_REAL:
		vmexit->u.inst_emul.cs_base = vmcs_read(VMCS_GUEST_CS_BASE);
		vmexit->u.inst_emul.cs_d = 0;
		break;
	case CPU_MODE_PROTECTED:
	case CPU_MODE_COMPATIBILITY:
		vmexit->u.inst_emul.cs_base = vmcs_read(VMCS_GUEST_CS_BASE);
		csar = vmcs_read(VMCS_GUEST_CS_ACCESS_RIGHTS);
		vmexit->u.inst_emul.cs_d = SEG_DESC_DEF32(csar);
		break;
	default:
		vmexit->u.inst_emul.cs_base = 0;
		vmexit->u.inst_emul.cs_d = 0;
		break;
	}
	vie_init(&vmexit->u.inst_emul.vie, NULL, 0);
}

static int ept_fault_type(uint64_t ept_qual)
{
	int fault_type;

	if (ept_qual & EPT_VIOLATION_DATA_WRITE)
		fault_type = VM_PROT_WRITE;
	else if (ept_qual & EPT_VIOLATION_INST_FETCH)
		fault_type = VM_PROT_EXECUTE;
	else fault_type= VM_PROT_READ;

	return (fault_type);
}

static bool ept_emulation_fault(uint64_t ept_qual)
{
	int read, write;

	
	if (ept_qual & EPT_VIOLATION_INST_FETCH)
		return (false);

	
	read = ept_qual & EPT_VIOLATION_DATA_READ ? 1 : 0;
	write = ept_qual & EPT_VIOLATION_DATA_WRITE ? 1 : 0;
	if ((read | write) == 0)
		return (false);

	
	if ((ept_qual & EPT_VIOLATION_GLA_VALID) == 0 || (ept_qual & EPT_VIOLATION_XLAT_VALID) == 0) {
		return (false);
	}

	return (true);
}

static __inline int apic_access_virtualization(struct vmx *vmx, int vcpuid)
{
	uint32_t proc_ctls2;

	proc_ctls2 = vmx->cap[vcpuid].proc_ctls2;
	return ((proc_ctls2 & PROCBASED2_VIRTUALIZE_APIC_ACCESSES) ? 1 : 0);
}

static __inline int x2apic_virtualization(struct vmx *vmx, int vcpuid)
{
	uint32_t proc_ctls2;

	proc_ctls2 = vmx->cap[vcpuid].proc_ctls2;
	return ((proc_ctls2 & PROCBASED2_VIRTUALIZE_X2APIC_MODE) ? 1 : 0);
}

static int vmx_handle_apic_write(struct vmx *vmx, int vcpuid, struct vlapic *vlapic, uint64_t qual)

{
	int error, handled, offset;
	uint32_t *apic_regs, vector;
	bool retu;

	handled = HANDLED;
	offset = APIC_WRITE_OFFSET(qual);

	if (!apic_access_virtualization(vmx, vcpuid)) {
		
		if (x2apic_virtualization(vmx, vcpuid) && offset == APIC_OFFSET_SELF_IPI) {
			apic_regs = (uint32_t *)(vlapic->apic_page);
			vector = apic_regs[APIC_OFFSET_SELF_IPI / 4];
			vlapic_self_ipi_handler(vlapic, vector);
			return (HANDLED);
		} else return (UNHANDLED);
	}

	switch (offset) {
	case APIC_OFFSET_ID:
		vlapic_id_write_handler(vlapic);
		break;
	case APIC_OFFSET_LDR:
		vlapic_ldr_write_handler(vlapic);
		break;
	case APIC_OFFSET_DFR:
		vlapic_dfr_write_handler(vlapic);
		break;
	case APIC_OFFSET_SVR:
		vlapic_svr_write_handler(vlapic);
		break;
	case APIC_OFFSET_ESR:
		vlapic_esr_write_handler(vlapic);
		break;
	case APIC_OFFSET_ICR_LOW:
		retu = false;
		error = vlapic_icrlo_write_handler(vlapic, &retu);
		if (error != 0 || retu)
			handled = UNHANDLED;
		break;
	case APIC_OFFSET_CMCI_LVT:
	case APIC_OFFSET_TIMER_LVT ... APIC_OFFSET_ERROR_LVT:
		vlapic_lvt_write_handler(vlapic, offset);
		break;
	case APIC_OFFSET_TIMER_ICR:
		vlapic_icrtmr_write_handler(vlapic);
		break;
	case APIC_OFFSET_TIMER_DCR:
		vlapic_dcr_write_handler(vlapic);
		break;
	default:
		handled = UNHANDLED;
		break;
	}
	return (handled);
}

static bool apic_access_fault(struct vmx *vmx, int vcpuid, uint64_t gpa)
{

	if (apic_access_virtualization(vmx, vcpuid) && (gpa >= DEFAULT_APIC_BASE && gpa < DEFAULT_APIC_BASE + PAGE_SIZE))
		return (true);
	else return (false);
}

static int vmx_handle_apic_access(struct vmx *vmx, int vcpuid, struct vm_exit *vmexit)
{
	uint64_t qual;
	int access_type, offset, allowed;

	if (!apic_access_virtualization(vmx, vcpuid))
		return (UNHANDLED);

	qual = vmexit->u.vmx.exit_qualification;
	access_type = APIC_ACCESS_TYPE(qual);
	offset = APIC_ACCESS_OFFSET(qual);

	allowed = 0;
	if (access_type == 0) {
		
		switch (offset) {
		case APIC_OFFSET_APR:
		case APIC_OFFSET_PPR:
		case APIC_OFFSET_RRR:
		case APIC_OFFSET_CMCI_LVT:
		case APIC_OFFSET_TIMER_CCR:
			allowed = 1;
			break;
		default:
			break;
		}
	} else if (access_type == 1) {
		
		switch (offset) {
		case APIC_OFFSET_VER:
		case APIC_OFFSET_APR:
		case APIC_OFFSET_PPR:
		case APIC_OFFSET_RRR:
		case APIC_OFFSET_ISR0 ... APIC_OFFSET_ISR7:
		case APIC_OFFSET_TMR0 ... APIC_OFFSET_TMR7:
		case APIC_OFFSET_IRR0 ... APIC_OFFSET_IRR7:
		case APIC_OFFSET_CMCI_LVT:
		case APIC_OFFSET_TIMER_CCR:
			allowed = 1;
			break;
		default:
			break;
		}
	}

	if (allowed) {
		vmexit_inst_emul(vmexit, DEFAULT_APIC_BASE + offset, VIE_INVALID_GLA);
	}

	
	return (UNHANDLED);
}

static enum task_switch_reason vmx_task_switch_reason(uint64_t qual)
{
	int reason;

	reason = (qual >> 30) & 0x3;
	switch (reason) {
	case 0:
		return (TSR_CALL);
	case 1:
		return (TSR_IRET);
	case 2:
		return (TSR_JMP);
	case 3:
		return (TSR_IDT_GATE);
	default:
		panic("%s: invalid reason %d", __func__, reason);
	}
}

static int emulate_wrmsr(struct vmx *vmx, int vcpuid, u_int num, uint64_t val, bool *retu)
{
	int error;

	if (lapic_msr(num))
		error = lapic_wrmsr(vmx->vm, vcpuid, num, val, retu);
	else error = vmx_wrmsr(vmx, vcpuid, num, val, retu);

	return (error);
}

static int emulate_rdmsr(struct vmx *vmx, int vcpuid, u_int num, bool *retu)
{
	struct vmxctx *vmxctx;
	uint64_t result;
	uint32_t eax, edx;
	int error;

	if (lapic_msr(num))
		error = lapic_rdmsr(vmx->vm, vcpuid, num, &result, retu);
	else error = vmx_rdmsr(vmx, vcpuid, num, &result, retu);

	if (error == 0) {
		eax = result;
		vmxctx = &vmx->ctx[vcpuid];
		error = vmxctx_setreg(vmxctx, VM_REG_GUEST_RAX, eax);
		KASSERT(error == 0, ("vmxctx_setreg(rax) error %d", error));

		edx = result >> 32;
		error = vmxctx_setreg(vmxctx, VM_REG_GUEST_RDX, edx);
		KASSERT(error == 0, ("vmxctx_setreg(rdx) error %d", error));
	}

	return (error);
}

static int vmx_exit_process(struct vmx *vmx, int vcpu, struct vm_exit *vmexit)
{
	int error, errcode, errcode_valid, handled, in;
	struct vmxctx *vmxctx;
	struct vlapic *vlapic;
	struct vm_inout_str *vis;
	struct vm_task_switch *ts;
	uint32_t eax, ecx, edx, idtvec_info, idtvec_err, intr_info, inst_info;
	uint32_t intr_type, intr_vec, reason;
	uint64_t exitintinfo, qual, gpa;
	bool retu;

	CTASSERT((PINBASED_CTLS_ONE_SETTING & PINBASED_VIRTUAL_NMI) != 0);
	CTASSERT((PINBASED_CTLS_ONE_SETTING & PINBASED_NMI_EXITING) != 0);

	handled = UNHANDLED;
	vmxctx = &vmx->ctx[vcpu];

	qual = vmexit->u.vmx.exit_qualification;
	reason = vmexit->u.vmx.exit_reason;
	vmexit->exitcode = VM_EXITCODE_BOGUS;

	vmm_stat_incr(vmx->vm, vcpu, VMEXIT_COUNT, 1);
	SDT_PROBE3(vmm, vmx, exit, entry, vmx, vcpu, vmexit);

	
	if (__predict_false(reason == EXIT_REASON_MCE_DURING_ENTRY)) {
		VCPU_CTR0(vmx->vm, vcpu, "Handling MCE during VM-entry");
		__asm __volatile("int $18");
		return (1);
	}

	
	idtvec_info = vmcs_idt_vectoring_info();
	if (idtvec_info & VMCS_IDT_VEC_VALID) {
		idtvec_info &= ~(1 << 12); 
		exitintinfo = idtvec_info;
		if (idtvec_info & VMCS_IDT_VEC_ERRCODE_VALID) {
			idtvec_err = vmcs_idt_vectoring_err();
			exitintinfo |= (uint64_t)idtvec_err << 32;
		}
		error = vm_exit_intinfo(vmx->vm, vcpu, exitintinfo);
		KASSERT(error == 0, ("%s: vm_set_intinfo error %d", __func__, error));

		
		intr_type = idtvec_info & VMCS_INTR_T_MASK;
		if (intr_type == VMCS_INTR_T_NMI) {
			if (reason != EXIT_REASON_TASK_SWITCH)
				vmx_clear_nmi_blocking(vmx, vcpu);
			else vmx_assert_nmi_blocking(vmx, vcpu);
		}

		
		if (intr_type == VMCS_INTR_T_SWINTR || intr_type == VMCS_INTR_T_PRIV_SWEXCEPTION || intr_type == VMCS_INTR_T_SWEXCEPTION) {

			vmcs_write(VMCS_ENTRY_INST_LENGTH, vmexit->inst_length);
		}
	}

	switch (reason) {
	case EXIT_REASON_TASK_SWITCH:
		ts = &vmexit->u.task_switch;
		ts->tsssel = qual & 0xffff;
		ts->reason = vmx_task_switch_reason(qual);
		ts->ext = 0;
		ts->errcode_valid = 0;
		vmx_paging_info(&ts->paging);
		
		if (ts->reason == TSR_IDT_GATE) {
			KASSERT(idtvec_info & VMCS_IDT_VEC_VALID, ("invalid idtvec_info %#x for IDT task switch", idtvec_info));

			intr_type = idtvec_info & VMCS_INTR_T_MASK;
			if (intr_type != VMCS_INTR_T_SWINTR && intr_type != VMCS_INTR_T_SWEXCEPTION && intr_type != VMCS_INTR_T_PRIV_SWEXCEPTION) {

				
				ts->ext = 1;
				vmexit->inst_length = 0;
				if (idtvec_info & VMCS_IDT_VEC_ERRCODE_VALID) {
					ts->errcode_valid = 1;
					ts->errcode = vmcs_idt_vectoring_err();
				}
			}
		}
		vmexit->exitcode = VM_EXITCODE_TASK_SWITCH;
		SDT_PROBE4(vmm, vmx, exit, taskswitch, vmx, vcpu, vmexit, ts);
		VCPU_CTR4(vmx->vm, vcpu, "task switch reason %d, tss 0x%04x, " "%s errcode 0x%016lx", ts->reason, ts->tsssel, ts->ext ? "external" : "internal", ((uint64_t)ts->errcode << 32) | ts->errcode_valid);


		break;
	case EXIT_REASON_CR_ACCESS:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_CR_ACCESS, 1);
		SDT_PROBE4(vmm, vmx, exit, craccess, vmx, vcpu, vmexit, qual);
		switch (qual & 0xf) {
		case 0:
			handled = vmx_emulate_cr0_access(vmx, vcpu, qual);
			break;
		case 4:
			handled = vmx_emulate_cr4_access(vmx, vcpu, qual);
			break;
		case 8:
			handled = vmx_emulate_cr8_access(vmx, vcpu, qual);
			break;
		}
		break;
	case EXIT_REASON_RDMSR:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_RDMSR, 1);
		retu = false;
		ecx = vmxctx->guest_rcx;
		VCPU_CTR1(vmx->vm, vcpu, "rdmsr 0x%08x", ecx);
		SDT_PROBE4(vmm, vmx, exit, rdmsr, vmx, vcpu, vmexit, ecx);
		error = emulate_rdmsr(vmx, vcpu, ecx, &retu);
		if (error) {
			vmexit->exitcode = VM_EXITCODE_RDMSR;
			vmexit->u.msr.code = ecx;
		} else if (!retu) {
			handled = HANDLED;
		} else {
			
			KASSERT(vmexit->exitcode != VM_EXITCODE_BOGUS, ("emulate_rdmsr retu with bogus exitcode"));
		}
		break;
	case EXIT_REASON_WRMSR:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_WRMSR, 1);
		retu = false;
		eax = vmxctx->guest_rax;
		ecx = vmxctx->guest_rcx;
		edx = vmxctx->guest_rdx;
		VCPU_CTR2(vmx->vm, vcpu, "wrmsr 0x%08x value 0x%016lx", ecx, (uint64_t)edx << 32 | eax);
		SDT_PROBE5(vmm, vmx, exit, wrmsr, vmx, vmexit, vcpu, ecx, (uint64_t)edx << 32 | eax);
		error = emulate_wrmsr(vmx, vcpu, ecx, (uint64_t)edx << 32 | eax, &retu);
		if (error) {
			vmexit->exitcode = VM_EXITCODE_WRMSR;
			vmexit->u.msr.code = ecx;
			vmexit->u.msr.wval = (uint64_t)edx << 32 | eax;
		} else if (!retu) {
			handled = HANDLED;
		} else {
			
			KASSERT(vmexit->exitcode != VM_EXITCODE_BOGUS, ("emulate_wrmsr retu with bogus exitcode"));
		}
		break;
	case EXIT_REASON_HLT:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_HLT, 1);
		SDT_PROBE3(vmm, vmx, exit, halt, vmx, vcpu, vmexit);
		vmexit->exitcode = VM_EXITCODE_HLT;
		vmexit->u.hlt.rflags = vmcs_read(VMCS_GUEST_RFLAGS);
		if (virtual_interrupt_delivery)
			vmexit->u.hlt.intr_status = vmcs_read(VMCS_GUEST_INTR_STATUS);
		else vmexit->u.hlt.intr_status = 0;
		break;
	case EXIT_REASON_MTF:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_MTRAP, 1);
		SDT_PROBE3(vmm, vmx, exit, mtrap, vmx, vcpu, vmexit);
		vmexit->exitcode = VM_EXITCODE_MTRAP;
		vmexit->inst_length = 0;
		break;
	case EXIT_REASON_PAUSE:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_PAUSE, 1);
		SDT_PROBE3(vmm, vmx, exit, pause, vmx, vcpu, vmexit);
		vmexit->exitcode = VM_EXITCODE_PAUSE;
		break;
	case EXIT_REASON_INTR_WINDOW:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_INTR_WINDOW, 1);
		SDT_PROBE3(vmm, vmx, exit, intrwindow, vmx, vcpu, vmexit);
		vmx_clear_int_window_exiting(vmx, vcpu);
		return (1);
	case EXIT_REASON_EXT_INTR:
		
		intr_info = vmcs_read(VMCS_EXIT_INTR_INFO);
		SDT_PROBE4(vmm, vmx, exit, interrupt, vmx, vcpu, vmexit, intr_info);

		
		if (!(intr_info & VMCS_INTR_VALID))
			return (1);
		KASSERT((intr_info & VMCS_INTR_VALID) != 0 && (intr_info & VMCS_INTR_T_MASK) == VMCS_INTR_T_HWINTR, ("VM exit interruption info invalid: %#x", intr_info));

		vmx_trigger_hostintr(intr_info & 0xff);

		
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_EXTINT, 1);
		return (1);
	case EXIT_REASON_NMI_WINDOW:
		SDT_PROBE3(vmm, vmx, exit, nmiwindow, vmx, vcpu, vmexit);
		
		if (vm_nmi_pending(vmx->vm, vcpu))
			vmx_inject_nmi(vmx, vcpu);
		vmx_clear_nmi_window_exiting(vmx, vcpu);
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_NMI_WINDOW, 1);
		return (1);
	case EXIT_REASON_INOUT:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_INOUT, 1);
		vmexit->exitcode = VM_EXITCODE_INOUT;
		vmexit->u.inout.bytes = (qual & 0x7) + 1;
		vmexit->u.inout.in = in = (qual & 0x8) ? 1 : 0;
		vmexit->u.inout.string = (qual & 0x10) ? 1 : 0;
		vmexit->u.inout.rep = (qual & 0x20) ? 1 : 0;
		vmexit->u.inout.port = (uint16_t)(qual >> 16);
		vmexit->u.inout.eax = (uint32_t)(vmxctx->guest_rax);
		if (vmexit->u.inout.string) {
			inst_info = vmcs_read(VMCS_EXIT_INSTRUCTION_INFO);
			vmexit->exitcode = VM_EXITCODE_INOUT_STR;
			vis = &vmexit->u.inout_str;
			vmx_paging_info(&vis->paging);
			vis->rflags = vmcs_read(VMCS_GUEST_RFLAGS);
			vis->cr0 = vmcs_read(VMCS_GUEST_CR0);
			vis->index = inout_str_index(vmx, vcpu, in);
			vis->count = inout_str_count(vmx, vcpu, vis->inout.rep);
			vis->addrsize = inout_str_addrsize(inst_info);
			inout_str_seginfo(vmx, vcpu, inst_info, in, vis);
		}
		SDT_PROBE3(vmm, vmx, exit, inout, vmx, vcpu, vmexit);
		break;
	case EXIT_REASON_CPUID:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_CPUID, 1);
		SDT_PROBE3(vmm, vmx, exit, cpuid, vmx, vcpu, vmexit);
		handled = vmx_handle_cpuid(vmx->vm, vcpu, vmxctx);
		break;
	case EXIT_REASON_EXCEPTION:
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_EXCEPTION, 1);
		intr_info = vmcs_read(VMCS_EXIT_INTR_INFO);
		KASSERT((intr_info & VMCS_INTR_VALID) != 0, ("VM exit interruption info invalid: %#x", intr_info));

		intr_vec = intr_info & 0xff;
		intr_type = intr_info & VMCS_INTR_T_MASK;

		
		if ((idtvec_info & VMCS_IDT_VEC_VALID) == 0 && (intr_vec != IDT_DF) && (intr_info & EXIT_QUAL_NMIUDTI) != 0)

			vmx_restore_nmi_blocking(vmx, vcpu);

		
		if (intr_type == VMCS_INTR_T_NMI)
			return (1);

		
		if (intr_vec == IDT_MC) {
			VCPU_CTR0(vmx->vm, vcpu, "Vectoring to MCE handler");
			__asm __volatile("int $18");
			return (1);
		}

		
		if (intr_type == VMCS_INTR_T_SWEXCEPTION && intr_vec == IDT_BP && (vmx->cap[vcpu].set & (1 << VM_CAP_BPT_EXIT))) {
			vmexit->exitcode = VM_EXITCODE_BPT;
			vmexit->u.bpt.inst_length = vmexit->inst_length;
			vmexit->inst_length = 0;
			break;
		}

		if (intr_vec == IDT_PF) {
			error = vmxctx_setreg(vmxctx, VM_REG_GUEST_CR2, qual);
			KASSERT(error == 0, ("%s: vmxctx_setreg(cr2) error %d", __func__, error));
		}

		
		if (intr_type == VMCS_INTR_T_SWEXCEPTION)
			vmcs_write(VMCS_ENTRY_INST_LENGTH, vmexit->inst_length);

		
		errcode_valid = errcode = 0;
		if (intr_info & VMCS_INTR_DEL_ERRCODE) {
			errcode_valid = 1;
			errcode = vmcs_read(VMCS_EXIT_INTR_ERRCODE);
		}
		VCPU_CTR2(vmx->vm, vcpu, "Reflecting exception %d/%#x into " "the guest", intr_vec, errcode);
		SDT_PROBE5(vmm, vmx, exit, exception, vmx, vcpu, vmexit, intr_vec, errcode);
		error = vm_inject_exception(vmx->vm, vcpu, intr_vec, errcode_valid, errcode, 0);
		KASSERT(error == 0, ("%s: vm_inject_exception error %d", __func__, error));
		return (1);

	case EXIT_REASON_EPT_FAULT:
		
		gpa = vmcs_gpa();
		if (vm_mem_allocated(vmx->vm, vcpu, gpa) || apic_access_fault(vmx, vcpu, gpa)) {
			vmexit->exitcode = VM_EXITCODE_PAGING;
			vmexit->inst_length = 0;
			vmexit->u.paging.gpa = gpa;
			vmexit->u.paging.fault_type = ept_fault_type(qual);
			vmm_stat_incr(vmx->vm, vcpu, VMEXIT_NESTED_FAULT, 1);
			SDT_PROBE5(vmm, vmx, exit, nestedfault, vmx, vcpu, vmexit, gpa, qual);
		} else if (ept_emulation_fault(qual)) {
			vmexit_inst_emul(vmexit, gpa, vmcs_gla());
			vmm_stat_incr(vmx->vm, vcpu, VMEXIT_INST_EMUL, 1);
			SDT_PROBE4(vmm, vmx, exit, mmiofault, vmx, vcpu, vmexit, gpa);
		}
		
		if ((idtvec_info & VMCS_IDT_VEC_VALID) == 0 && (qual & EXIT_QUAL_NMIUDTI) != 0)
			vmx_restore_nmi_blocking(vmx, vcpu);
		break;
	case EXIT_REASON_VIRTUALIZED_EOI:
		vmexit->exitcode = VM_EXITCODE_IOAPIC_EOI;
		vmexit->u.ioapic_eoi.vector = qual & 0xFF;
		SDT_PROBE3(vmm, vmx, exit, eoi, vmx, vcpu, vmexit);
		vmexit->inst_length = 0;	
		break;
	case EXIT_REASON_APIC_ACCESS:
		SDT_PROBE3(vmm, vmx, exit, apicaccess, vmx, vcpu, vmexit);
		handled = vmx_handle_apic_access(vmx, vcpu, vmexit);
		break;
	case EXIT_REASON_APIC_WRITE:
		
		vmexit->inst_length = 0;
		vlapic = vm_lapic(vmx->vm, vcpu);
		SDT_PROBE4(vmm, vmx, exit, apicwrite, vmx, vcpu, vmexit, vlapic);
		handled = vmx_handle_apic_write(vmx, vcpu, vlapic, qual);
		break;
	case EXIT_REASON_XSETBV:
		SDT_PROBE3(vmm, vmx, exit, xsetbv, vmx, vcpu, vmexit);
		handled = vmx_emulate_xsetbv(vmx, vcpu, vmexit);
		break;
	case EXIT_REASON_MONITOR:
		SDT_PROBE3(vmm, vmx, exit, monitor, vmx, vcpu, vmexit);
		vmexit->exitcode = VM_EXITCODE_MONITOR;
		break;
	case EXIT_REASON_MWAIT:
		SDT_PROBE3(vmm, vmx, exit, mwait, vmx, vcpu, vmexit);
		vmexit->exitcode = VM_EXITCODE_MWAIT;
		break;
	case EXIT_REASON_TPR:
		vlapic = vm_lapic(vmx->vm, vcpu);
		vlapic_sync_tpr(vlapic);
		vmexit->inst_length = 0;
		handled = HANDLED;
		break;
	case EXIT_REASON_VMCALL:
	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMLAUNCH:
	case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST:
	case EXIT_REASON_VMREAD:
	case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_VMXOFF:
	case EXIT_REASON_VMXON:
		SDT_PROBE3(vmm, vmx, exit, vminsn, vmx, vcpu, vmexit);
		vmexit->exitcode = VM_EXITCODE_VMINSN;
		break;
	default:
		SDT_PROBE4(vmm, vmx, exit, unknown, vmx, vcpu, vmexit, reason);
		vmm_stat_incr(vmx->vm, vcpu, VMEXIT_UNKNOWN, 1);
		break;
	}

	if (handled) {
		
		vmexit->rip += vmexit->inst_length;
		vmexit->inst_length = 0;
		vmcs_write(VMCS_GUEST_RIP, vmexit->rip);
	} else {
		if (vmexit->exitcode == VM_EXITCODE_BOGUS) {
			
			vmexit->exitcode = VM_EXITCODE_VMX;
			vmexit->u.vmx.status = VM_SUCCESS;
			vmexit->u.vmx.inst_type = 0;
			vmexit->u.vmx.inst_error = 0;
		} else {
			
		}
	}

	SDT_PROBE4(vmm, vmx, exit, return, vmx, vcpu, vmexit, handled);
	return (handled);
}

static __inline void vmx_exit_inst_error(struct vmxctx *vmxctx, int rc, struct vm_exit *vmexit)
{

	KASSERT(vmxctx->inst_fail_status != VM_SUCCESS, ("vmx_exit_inst_error: invalid inst_fail_status %d", vmxctx->inst_fail_status));


	vmexit->inst_length = 0;
	vmexit->exitcode = VM_EXITCODE_VMX;
	vmexit->u.vmx.status = vmxctx->inst_fail_status;
	vmexit->u.vmx.inst_error = vmcs_instruction_error();
	vmexit->u.vmx.exit_reason = ~0;
	vmexit->u.vmx.exit_qualification = ~0;

	switch (rc) {
	case VMX_VMRESUME_ERROR:
	case VMX_VMLAUNCH_ERROR:
	case VMX_INVEPT_ERROR:
		vmexit->u.vmx.inst_type = rc;
		break;
	default:
		panic("vm_exit_inst_error: vmx_enter_guest returned %d", rc);
	}
}


static __inline void vmx_exit_handle_nmi(struct vmx *vmx, int vcpuid, struct vm_exit *vmexit)
{
	uint32_t intr_info;

	KASSERT((read_rflags() & PSL_I) == 0, ("interrupts enabled"));

	if (vmexit->u.vmx.exit_reason != EXIT_REASON_EXCEPTION)
		return;

	intr_info = vmcs_read(VMCS_EXIT_INTR_INFO);
	KASSERT((intr_info & VMCS_INTR_VALID) != 0, ("VM exit interruption info invalid: %#x", intr_info));

	if ((intr_info & VMCS_INTR_T_MASK) == VMCS_INTR_T_NMI) {
		KASSERT((intr_info & 0xff) == IDT_NMI, ("VM exit due " "to NMI has invalid vector: %#x", intr_info));
		VCPU_CTR0(vmx->vm, vcpuid, "Vectoring to NMI handler");
		__asm __volatile("int $2");
	}
}

static __inline void vmx_dr_enter_guest(struct vmxctx *vmxctx)
{
	register_t rflags;

	
	vmxctx->host_dr7 = rdr7();
	vmxctx->host_debugctl = rdmsr(MSR_DEBUGCTLMSR);

	
	load_dr7(0);
	wrmsr(MSR_DEBUGCTLMSR, 0);

	
	rflags = read_rflags();
	vmxctx->host_tf = rflags & PSL_T;
	write_rflags(rflags & ~PSL_T);

	
	vmxctx->host_dr0 = rdr0();
	vmxctx->host_dr1 = rdr1();
	vmxctx->host_dr2 = rdr2();
	vmxctx->host_dr3 = rdr3();
	vmxctx->host_dr6 = rdr6();

	
	load_dr0(vmxctx->guest_dr0);
	load_dr1(vmxctx->guest_dr1);
	load_dr2(vmxctx->guest_dr2);
	load_dr3(vmxctx->guest_dr3);
	load_dr6(vmxctx->guest_dr6);
}

static __inline void vmx_dr_leave_guest(struct vmxctx *vmxctx)
{

	
	vmxctx->guest_dr0 = rdr0();
	vmxctx->guest_dr1 = rdr1();
	vmxctx->guest_dr2 = rdr2();
	vmxctx->guest_dr3 = rdr3();
	vmxctx->guest_dr6 = rdr6();

	
	load_dr0(vmxctx->host_dr0);
	load_dr1(vmxctx->host_dr1);
	load_dr2(vmxctx->host_dr2);
	load_dr3(vmxctx->host_dr3);
	load_dr6(vmxctx->host_dr6);
	wrmsr(MSR_DEBUGCTLMSR, vmxctx->host_debugctl);
	load_dr7(vmxctx->host_dr7);
	write_rflags(read_rflags() | vmxctx->host_tf);
}

static int vmx_run(void *arg, int vcpu, register_t rip, pmap_t pmap, struct vm_eventinfo *evinfo)

{
	int rc, handled, launched;
	struct vmx *vmx;
	struct vm *vm;
	struct vmxctx *vmxctx;
	struct vmcs *vmcs;
	struct vm_exit *vmexit;
	struct vlapic *vlapic;
	uint32_t exit_reason;
	struct region_descriptor gdtr, idtr;
	uint16_t ldt_sel;

	vmx = arg;
	vm = vmx->vm;
	vmcs = &vmx->vmcs[vcpu];
	vmxctx = &vmx->ctx[vcpu];
	vlapic = vm_lapic(vm, vcpu);
	vmexit = vm_exitinfo(vm, vcpu);
	launched = 0;

	KASSERT(vmxctx->pmap == pmap, ("pmap %p different than ctx pmap %p", pmap, vmxctx->pmap));

	vmx_msr_guest_enter(vmx, vcpu);

	VMPTRLD(vmcs);

	
	vmcs_write(VMCS_HOST_CR3, rcr3());

	vmcs_write(VMCS_GUEST_RIP, rip);
	vmx_set_pcpu_defaults(vmx, vcpu, pmap);
	do {
		KASSERT(vmcs_guest_rip() == rip, ("%s: vmcs guest rip mismatch " "%#lx/%#lx", __func__, vmcs_guest_rip(), rip));

		handled = UNHANDLED;
		
		disable_intr();
		vmx_inject_interrupts(vmx, vcpu, vlapic, rip);

		
		if (vcpu_suspended(evinfo)) {
			enable_intr();
			vm_exit_suspended(vmx->vm, vcpu, rip);
			break;
		}

		if (vcpu_rendezvous_pending(evinfo)) {
			enable_intr();
			vm_exit_rendezvous(vmx->vm, vcpu, rip);
			break;
		}

		if (vcpu_reqidle(evinfo)) {
			enable_intr();
			vm_exit_reqidle(vmx->vm, vcpu, rip);
			break;
		}

		if (vcpu_should_yield(vm, vcpu)) {
			enable_intr();
			vm_exit_astpending(vmx->vm, vcpu, rip);
			vmx_astpending_trace(vmx, vcpu, rip);
			handled = HANDLED;
			break;
		}

		if (vcpu_debugged(vm, vcpu)) {
			enable_intr();
			vm_exit_debug(vmx->vm, vcpu, rip);
			break;
		}

		
		if (tpr_shadowing && !virtual_interrupt_delivery) {
			if ((vmx->cap[vcpu].proc_ctls & PROCBASED_USE_TPR_SHADOW) != 0) {
				vmcs_write(VMCS_TPR_THRESHOLD, vlapic_get_cr8(vlapic));
			}
		}

		
		sgdt(&gdtr);
		sidt(&idtr);
		ldt_sel = sldt();

		
		vmx_msr_guest_enter_tsc_aux(vmx, vcpu);

		vmx_run_trace(vmx, vcpu);
		vmx_dr_enter_guest(vmxctx);
		rc = vmx_enter_guest(vmxctx, vmx, launched);
		vmx_dr_leave_guest(vmxctx);

		vmx_msr_guest_exit_tsc_aux(vmx, vcpu);

		bare_lgdt(&gdtr);
		lidt(&idtr);
		lldt(ldt_sel);

		
		vmexit->rip = rip = vmcs_guest_rip();
		vmexit->inst_length = vmexit_instruction_length();
		vmexit->u.vmx.exit_reason = exit_reason = vmcs_exit_reason();
		vmexit->u.vmx.exit_qualification = vmcs_exit_qualification();

		
		vmx->state[vcpu].nextrip = rip;

		if (rc == VMX_GUEST_VMEXIT) {
			vmx_exit_handle_nmi(vmx, vcpu, vmexit);
			enable_intr();
			handled = vmx_exit_process(vmx, vcpu, vmexit);
		} else {
			enable_intr();
			vmx_exit_inst_error(vmxctx, rc, vmexit);
		}
		launched = 1;
		vmx_exit_trace(vmx, vcpu, rip, exit_reason, handled);
		rip = vmexit->rip;
	} while (handled);

	
	if ((handled && vmexit->exitcode != VM_EXITCODE_BOGUS) || (!handled && vmexit->exitcode == VM_EXITCODE_BOGUS)) {
		panic("Mismatch between handled (%d) and exitcode (%d)", handled, vmexit->exitcode);
	}

	if (!handled)
		vmm_stat_incr(vm, vcpu, VMEXIT_USERSPACE, 1);

	VCPU_CTR1(vm, vcpu, "returning from vmx_run: exitcode %d", vmexit->exitcode);

	VMCLEAR(vmcs);
	vmx_msr_guest_exit(vmx, vcpu);

	return (0);
}

static void vmx_vmcleanup(void *arg)
{
	int i;
	struct vmx *vmx = arg;
	uint16_t maxcpus;

	if (apic_access_virtualization(vmx, 0))
		vm_unmap_mmio(vmx->vm, DEFAULT_APIC_BASE, PAGE_SIZE);

	maxcpus = vm_get_maxcpus(vmx->vm);
	for (i = 0; i < maxcpus; i++)
		vpid_free(vmx->state[i].vpid);

	free(vmx, M_VMX);

	return;
}

static register_t * vmxctx_regptr(struct vmxctx *vmxctx, int reg)
{

	switch (reg) {
	case VM_REG_GUEST_RAX:
		return (&vmxctx->guest_rax);
	case VM_REG_GUEST_RBX:
		return (&vmxctx->guest_rbx);
	case VM_REG_GUEST_RCX:
		return (&vmxctx->guest_rcx);
	case VM_REG_GUEST_RDX:
		return (&vmxctx->guest_rdx);
	case VM_REG_GUEST_RSI:
		return (&vmxctx->guest_rsi);
	case VM_REG_GUEST_RDI:
		return (&vmxctx->guest_rdi);
	case VM_REG_GUEST_RBP:
		return (&vmxctx->guest_rbp);
	case VM_REG_GUEST_R8:
		return (&vmxctx->guest_r8);
	case VM_REG_GUEST_R9:
		return (&vmxctx->guest_r9);
	case VM_REG_GUEST_R10:
		return (&vmxctx->guest_r10);
	case VM_REG_GUEST_R11:
		return (&vmxctx->guest_r11);
	case VM_REG_GUEST_R12:
		return (&vmxctx->guest_r12);
	case VM_REG_GUEST_R13:
		return (&vmxctx->guest_r13);
	case VM_REG_GUEST_R14:
		return (&vmxctx->guest_r14);
	case VM_REG_GUEST_R15:
		return (&vmxctx->guest_r15);
	case VM_REG_GUEST_CR2:
		return (&vmxctx->guest_cr2);
	case VM_REG_GUEST_DR0:
		return (&vmxctx->guest_dr0);
	case VM_REG_GUEST_DR1:
		return (&vmxctx->guest_dr1);
	case VM_REG_GUEST_DR2:
		return (&vmxctx->guest_dr2);
	case VM_REG_GUEST_DR3:
		return (&vmxctx->guest_dr3);
	case VM_REG_GUEST_DR6:
		return (&vmxctx->guest_dr6);
	default:
		break;
	}
	return (NULL);
}

static int vmxctx_getreg(struct vmxctx *vmxctx, int reg, uint64_t *retval)
{
	register_t *regp;

	if ((regp = vmxctx_regptr(vmxctx, reg)) != NULL) {
		*retval = *regp;
		return (0);
	} else return (EINVAL);
}

static int vmxctx_setreg(struct vmxctx *vmxctx, int reg, uint64_t val)
{
	register_t *regp;

	if ((regp = vmxctx_regptr(vmxctx, reg)) != NULL) {
		*regp = val;
		return (0);
	} else return (EINVAL);
}

static int vmx_get_intr_shadow(struct vmx *vmx, int vcpu, int running, uint64_t *retval)
{
	uint64_t gi;
	int error;

	error = vmcs_getreg(&vmx->vmcs[vcpu], running, VMCS_IDENT(VMCS_GUEST_INTERRUPTIBILITY), &gi);
	*retval = (gi & HWINTR_BLOCKING) ? 1 : 0;
	return (error);
}

static int vmx_modify_intr_shadow(struct vmx *vmx, int vcpu, int running, uint64_t val)
{
	struct vmcs *vmcs;
	uint64_t gi;
	int error, ident;

	
	if (val) {
		error = EINVAL;
		goto done;
	}

	vmcs = &vmx->vmcs[vcpu];
	ident = VMCS_IDENT(VMCS_GUEST_INTERRUPTIBILITY);
	error = vmcs_getreg(vmcs, running, ident, &gi);
	if (error == 0) {
		gi &= ~HWINTR_BLOCKING;
		error = vmcs_setreg(vmcs, running, ident, gi);
	}
done:
	VCPU_CTR2(vmx->vm, vcpu, "Setting intr_shadow to %#lx %s", val, error ? "failed" : "succeeded");
	return (error);
}

static int vmx_shadow_reg(int reg)
{
	int shreg;

	shreg = -1;

	switch (reg) {
	case VM_REG_GUEST_CR0:
		shreg = VMCS_CR0_SHADOW;
		break;
	case VM_REG_GUEST_CR4:
		shreg = VMCS_CR4_SHADOW;
		break;
	default:
		break;
	}

	return (shreg);
}

static int vmx_getreg(void *arg, int vcpu, int reg, uint64_t *retval)
{
	int running, hostcpu;
	struct vmx *vmx = arg;

	running = vcpu_is_running(vmx->vm, vcpu, &hostcpu);
	if (running && hostcpu != curcpu)
		panic("vmx_getreg: %s%d is running", vm_name(vmx->vm), vcpu);

	if (reg == VM_REG_GUEST_INTR_SHADOW)
		return (vmx_get_intr_shadow(vmx, vcpu, running, retval));

	if (vmxctx_getreg(&vmx->ctx[vcpu], reg, retval) == 0)
		return (0);

	return (vmcs_getreg(&vmx->vmcs[vcpu], running, reg, retval));
}

static int vmx_setreg(void *arg, int vcpu, int reg, uint64_t val)
{
	int error, hostcpu, running, shadow;
	uint64_t ctls;
	pmap_t pmap;
	struct vmx *vmx = arg;

	running = vcpu_is_running(vmx->vm, vcpu, &hostcpu);
	if (running && hostcpu != curcpu)
		panic("vmx_setreg: %s%d is running", vm_name(vmx->vm), vcpu);

	if (reg == VM_REG_GUEST_INTR_SHADOW)
		return (vmx_modify_intr_shadow(vmx, vcpu, running, val));

	if (vmxctx_setreg(&vmx->ctx[vcpu], reg, val) == 0)
		return (0);

	error = vmcs_setreg(&vmx->vmcs[vcpu], running, reg, val);

	if (error == 0) {
		
		if ((entry_ctls & VM_ENTRY_LOAD_EFER) != 0 && (reg == VM_REG_GUEST_EFER)) {
			vmcs_getreg(&vmx->vmcs[vcpu], running, VMCS_IDENT(VMCS_ENTRY_CTLS), &ctls);
			if (val & EFER_LMA)
				ctls |= VM_ENTRY_GUEST_LMA;
			else ctls &= ~VM_ENTRY_GUEST_LMA;
			vmcs_setreg(&vmx->vmcs[vcpu], running, VMCS_IDENT(VMCS_ENTRY_CTLS), ctls);
		}

		shadow = vmx_shadow_reg(reg);
		if (shadow > 0) {
			
			error = vmcs_setreg(&vmx->vmcs[vcpu], running, VMCS_IDENT(shadow), val);
		}

		if (reg == VM_REG_GUEST_CR3) {
			
			pmap = vmx->ctx[vcpu].pmap;
			vmx_invvpid(vmx, vcpu, pmap, running);
		}
	}

	return (error);
}

static int vmx_getdesc(void *arg, int vcpu, int reg, struct seg_desc *desc)
{
	int hostcpu, running;
	struct vmx *vmx = arg;

	running = vcpu_is_running(vmx->vm, vcpu, &hostcpu);
	if (running && hostcpu != curcpu)
		panic("vmx_getdesc: %s%d is running", vm_name(vmx->vm), vcpu);

	return (vmcs_getdesc(&vmx->vmcs[vcpu], running, reg, desc));
}

static int vmx_setdesc(void *arg, int vcpu, int reg, struct seg_desc *desc)
{
	int hostcpu, running;
	struct vmx *vmx = arg;

	running = vcpu_is_running(vmx->vm, vcpu, &hostcpu);
	if (running && hostcpu != curcpu)
		panic("vmx_setdesc: %s%d is running", vm_name(vmx->vm), vcpu);

	return (vmcs_setdesc(&vmx->vmcs[vcpu], running, reg, desc));
}

static int vmx_getcap(void *arg, int vcpu, int type, int *retval)
{
	struct vmx *vmx = arg;
	int vcap;
	int ret;

	ret = ENOENT;

	vcap = vmx->cap[vcpu].set;

	switch (type) {
	case VM_CAP_HALT_EXIT:
		if (cap_halt_exit)
			ret = 0;
		break;
	case VM_CAP_PAUSE_EXIT:
		if (cap_pause_exit)
			ret = 0;
		break;
	case VM_CAP_MTRAP_EXIT:
		if (cap_monitor_trap)
			ret = 0;
		break;
	case VM_CAP_RDPID:
		if (cap_rdpid)
			ret = 0;
		break;
	case VM_CAP_RDTSCP:
		if (cap_rdtscp)
			ret = 0;
		break;
	case VM_CAP_UNRESTRICTED_GUEST:
		if (cap_unrestricted_guest)
			ret = 0;
		break;
	case VM_CAP_ENABLE_INVPCID:
		if (cap_invpcid)
			ret = 0;
		break;
	case VM_CAP_BPT_EXIT:
		ret = 0;
		break;
	default:
		break;
	}

	if (ret == 0)
		*retval = (vcap & (1 << type)) ? 1 : 0;

	return (ret);
}

static int vmx_setcap(void *arg, int vcpu, int type, int val)
{
	struct vmx *vmx = arg;
	struct vmcs *vmcs = &vmx->vmcs[vcpu];
	uint32_t baseval;
	uint32_t *pptr;
	int error;
	int flag;
	int reg;
	int retval;

	retval = ENOENT;
	pptr = NULL;

	switch (type) {
	case VM_CAP_HALT_EXIT:
		if (cap_halt_exit) {
			retval = 0;
			pptr = &vmx->cap[vcpu].proc_ctls;
			baseval = *pptr;
			flag = PROCBASED_HLT_EXITING;
			reg = VMCS_PRI_PROC_BASED_CTLS;
		}
		break;
	case VM_CAP_MTRAP_EXIT:
		if (cap_monitor_trap) {
			retval = 0;
			pptr = &vmx->cap[vcpu].proc_ctls;
			baseval = *pptr;
			flag = PROCBASED_MTF;
			reg = VMCS_PRI_PROC_BASED_CTLS;
		}
		break;
	case VM_CAP_PAUSE_EXIT:
		if (cap_pause_exit) {
			retval = 0;
			pptr = &vmx->cap[vcpu].proc_ctls;
			baseval = *pptr;
			flag = PROCBASED_PAUSE_EXITING;
			reg = VMCS_PRI_PROC_BASED_CTLS;
		}
		break;
	case VM_CAP_RDPID:
	case VM_CAP_RDTSCP:
		if (cap_rdpid || cap_rdtscp)
			
			error = EOPNOTSUPP;
		break;
	case VM_CAP_UNRESTRICTED_GUEST:
		if (cap_unrestricted_guest) {
			retval = 0;
			pptr = &vmx->cap[vcpu].proc_ctls2;
			baseval = *pptr;
			flag = PROCBASED2_UNRESTRICTED_GUEST;
			reg = VMCS_SEC_PROC_BASED_CTLS;
		}
		break;
	case VM_CAP_ENABLE_INVPCID:
		if (cap_invpcid) {
			retval = 0;
			pptr = &vmx->cap[vcpu].proc_ctls2;
			baseval = *pptr;
			flag = PROCBASED2_ENABLE_INVPCID;
			reg = VMCS_SEC_PROC_BASED_CTLS;
		}
		break;
	case VM_CAP_BPT_EXIT:
		retval = 0;

		
		if (vmx->cap[vcpu].exc_bitmap != 0xffffffff) {
			pptr = &vmx->cap[vcpu].exc_bitmap;
			baseval = *pptr;
			flag = (1 << IDT_BP);
			reg = VMCS_EXCEPTION_BITMAP;
		}
		break;
	default:
		break;
	}

	if (retval)
		return (retval);

	if (pptr != NULL) {
		if (val) {
			baseval |= flag;
		} else {
			baseval &= ~flag;
		}
		VMPTRLD(vmcs);
		error = vmwrite(reg, baseval);
		VMCLEAR(vmcs);

		if (error)
			return (error);

		
		*pptr = baseval;
	}

	if (val) {
		vmx->cap[vcpu].set |= (1 << type);
	} else {
		vmx->cap[vcpu].set &= ~(1 << type);
	}

	return (0);
}

struct vlapic_vtx {
	struct vlapic	vlapic;
	struct pir_desc	*pir_desc;
	struct vmx	*vmx;
	u_int	pending_prio;
};














static int vmx_set_intr_ready(struct vlapic *vlapic, int vector, bool level)
{
	struct vlapic_vtx *vlapic_vtx;
	struct pir_desc *pir_desc;
	uint64_t mask;
	int idx, notify = 0;

	vlapic_vtx = (struct vlapic_vtx *)vlapic;
	pir_desc = vlapic_vtx->pir_desc;

	
	idx = vector / 64;
	mask = 1UL << (vector % 64);
	atomic_set_long(&pir_desc->pir[idx], mask);

	
	if (atomic_cmpset_long(&pir_desc->pending, 0, 1) != 0) {
		notify = 1;
		vlapic_vtx->pending_prio = 0;
	} else {
		const u_int old_prio = vlapic_vtx->pending_prio;
		const u_int prio_bit = VPR_PRIO_BIT(vector & APIC_TPR_INT);

		if ((old_prio & prio_bit) == 0 && prio_bit > old_prio) {
			atomic_set_int(&vlapic_vtx->pending_prio, prio_bit);
			notify = 1;
		}
	}

	VMX_CTR_PIR(vlapic->vm, vlapic->vcpuid, pir_desc, notify, vector, level, "vmx_set_intr_ready");
	return (notify);
}

static int vmx_pending_intr(struct vlapic *vlapic, int *vecptr)
{
	struct vlapic_vtx *vlapic_vtx;
	struct pir_desc *pir_desc;
	struct LAPIC *lapic;
	uint64_t pending, pirval;
	uint32_t ppr, vpr;
	int i;

	
	KASSERT(vecptr == NULL, ("vmx_pending_intr: vecptr must be NULL"));

	vlapic_vtx = (struct vlapic_vtx *)vlapic;
	pir_desc = vlapic_vtx->pir_desc;

	pending = atomic_load_acq_long(&pir_desc->pending);
	if (!pending) {
		
		struct vm_exit *vmexit;
		uint8_t rvi, ppr;

		vmexit = vm_exitinfo(vlapic->vm, vlapic->vcpuid);
		KASSERT(vmexit->exitcode == VM_EXITCODE_HLT, ("vmx_pending_intr: exitcode not 'HLT'"));
		rvi = vmexit->u.hlt.intr_status & APIC_TPR_INT;
		lapic = vlapic->apic_page;
		ppr = lapic->ppr & APIC_TPR_INT;
		if (rvi > ppr) {
			return (1);
		}

		return (0);
	}

	
	lapic = vlapic->apic_page;
	ppr = lapic->ppr & APIC_TPR_INT;
	if (ppr == 0)
		return (1);

	VCPU_CTR1(vlapic->vm, vlapic->vcpuid, "HLT with non-zero PPR %d", lapic->ppr);

	vpr = 0;
	for (i = 3; i >= 0; i--) {
		pirval = pir_desc->pir[i];
		if (pirval != 0) {
			vpr = (i * 64 + flsl(pirval) - 1) & APIC_TPR_INT;
			break;
		}
	}

	
	if (vpr <= ppr) {
		const u_int prio_bit = VPR_PRIO_BIT(vpr);
		const u_int old = vlapic_vtx->pending_prio;

		if (old > prio_bit && (old & prio_bit) == 0) {
			vlapic_vtx->pending_prio = prio_bit;
		}
		return (0);
	}
	return (1);
}

static void vmx_intr_accepted(struct vlapic *vlapic, int vector)
{

	panic("vmx_intr_accepted: not expected to be called");
}

static void vmx_set_tmr(struct vlapic *vlapic, int vector, bool level)
{
	struct vlapic_vtx *vlapic_vtx;
	struct vmx *vmx;
	struct vmcs *vmcs;
	uint64_t mask, val;

	KASSERT(vector >= 0 && vector <= 255, ("invalid vector %d", vector));
	KASSERT(!vcpu_is_running(vlapic->vm, vlapic->vcpuid, NULL), ("vmx_set_tmr: vcpu cannot be running"));

	vlapic_vtx = (struct vlapic_vtx *)vlapic;
	vmx = vlapic_vtx->vmx;
	vmcs = &vmx->vmcs[vlapic->vcpuid];
	mask = 1UL << (vector % 64);

	VMPTRLD(vmcs);
	val = vmcs_read(VMCS_EOI_EXIT(vector));
	if (level)
		val |= mask;
	else val &= ~mask;
	vmcs_write(VMCS_EOI_EXIT(vector), val);
	VMCLEAR(vmcs);
}

static void vmx_enable_x2apic_mode_ts(struct vlapic *vlapic)
{
	struct vmx *vmx;
	struct vmcs *vmcs;
	uint32_t proc_ctls;
	int vcpuid;

	vcpuid = vlapic->vcpuid;
	vmx = ((struct vlapic_vtx *)vlapic)->vmx;
	vmcs = &vmx->vmcs[vcpuid];

	proc_ctls = vmx->cap[vcpuid].proc_ctls;
	proc_ctls &= ~PROCBASED_USE_TPR_SHADOW;
	proc_ctls |= PROCBASED_CR8_LOAD_EXITING;
	proc_ctls |= PROCBASED_CR8_STORE_EXITING;
	vmx->cap[vcpuid].proc_ctls = proc_ctls;

	VMPTRLD(vmcs);
	vmcs_write(VMCS_PRI_PROC_BASED_CTLS, proc_ctls);
	VMCLEAR(vmcs);
}

static void vmx_enable_x2apic_mode_vid(struct vlapic *vlapic)
{
	struct vmx *vmx;
	struct vmcs *vmcs;
	uint32_t proc_ctls2;
	int vcpuid, error;

	vcpuid = vlapic->vcpuid;
	vmx = ((struct vlapic_vtx *)vlapic)->vmx;
	vmcs = &vmx->vmcs[vcpuid];

	proc_ctls2 = vmx->cap[vcpuid].proc_ctls2;
	KASSERT((proc_ctls2 & PROCBASED2_VIRTUALIZE_APIC_ACCESSES) != 0, ("%s: invalid proc_ctls2 %#x", __func__, proc_ctls2));

	proc_ctls2 &= ~PROCBASED2_VIRTUALIZE_APIC_ACCESSES;
	proc_ctls2 |= PROCBASED2_VIRTUALIZE_X2APIC_MODE;
	vmx->cap[vcpuid].proc_ctls2 = proc_ctls2;

	VMPTRLD(vmcs);
	vmcs_write(VMCS_SEC_PROC_BASED_CTLS, proc_ctls2);
	VMCLEAR(vmcs);

	if (vlapic->vcpuid == 0) {
		
		error = vm_unmap_mmio(vmx->vm, DEFAULT_APIC_BASE, PAGE_SIZE);
		KASSERT(error == 0, ("%s: vm_unmap_mmio error %d", __func__, error));

		
		error = vmx_allow_x2apic_msrs(vmx);
		KASSERT(error == 0, ("%s: vmx_allow_x2apic_msrs error %d", __func__, error));
	}
}

static void vmx_post_intr(struct vlapic *vlapic, int hostcpu)
{

	ipi_cpu(hostcpu, pirvec);
}


static void vmx_inject_pir(struct vlapic *vlapic)
{
	struct vlapic_vtx *vlapic_vtx;
	struct pir_desc *pir_desc;
	struct LAPIC *lapic;
	uint64_t val, pirval;
	int rvi, pirbase = -1;
	uint16_t intr_status_old, intr_status_new;

	vlapic_vtx = (struct vlapic_vtx *)vlapic;
	pir_desc = vlapic_vtx->pir_desc;
	if (atomic_cmpset_long(&pir_desc->pending, 1, 0) == 0) {
		VCPU_CTR0(vlapic->vm, vlapic->vcpuid, "vmx_inject_pir: " "no posted interrupt pending");
		return;
	}

	pirval = 0;
	pirbase = -1;
	lapic = vlapic->apic_page;

	val = atomic_readandclear_long(&pir_desc->pir[0]);
	if (val != 0) {
		lapic->irr0 |= val;
		lapic->irr1 |= val >> 32;
		pirbase = 0;
		pirval = val;
	}

	val = atomic_readandclear_long(&pir_desc->pir[1]);
	if (val != 0) {
		lapic->irr2 |= val;
		lapic->irr3 |= val >> 32;
		pirbase = 64;
		pirval = val;
	}

	val = atomic_readandclear_long(&pir_desc->pir[2]);
	if (val != 0) {
		lapic->irr4 |= val;
		lapic->irr5 |= val >> 32;
		pirbase = 128;
		pirval = val;
	}

	val = atomic_readandclear_long(&pir_desc->pir[3]);
	if (val != 0) {
		lapic->irr6 |= val;
		lapic->irr7 |= val >> 32;
		pirbase = 192;
		pirval = val;
	}

	VLAPIC_CTR_IRR(vlapic, "vmx_inject_pir");

	
	if (pirval != 0) {
		rvi = pirbase + flsl(pirval) - 1;
		intr_status_old = vmcs_read(VMCS_GUEST_INTR_STATUS);
		intr_status_new = (intr_status_old & 0xFF00) | rvi;
		if (intr_status_new > intr_status_old) {
			vmcs_write(VMCS_GUEST_INTR_STATUS, intr_status_new);
			VCPU_CTR2(vlapic->vm, vlapic->vcpuid, "vmx_inject_pir: " "guest_intr_status changed from 0x%04x to 0x%04x", intr_status_old, intr_status_new);

		}
	}
}

static struct vlapic * vmx_vlapic_init(void *arg, int vcpuid)
{
	struct vmx *vmx;
	struct vlapic *vlapic;
	struct vlapic_vtx *vlapic_vtx;

	vmx = arg;

	vlapic = malloc(sizeof(struct vlapic_vtx), M_VLAPIC, M_WAITOK | M_ZERO);
	vlapic->vm = vmx->vm;
	vlapic->vcpuid = vcpuid;
	vlapic->apic_page = (struct LAPIC *)&vmx->apic_page[vcpuid];

	vlapic_vtx = (struct vlapic_vtx *)vlapic;
	vlapic_vtx->pir_desc = &vmx->pir_desc[vcpuid];
	vlapic_vtx->vmx = vmx;

	if (tpr_shadowing) {
		vlapic->ops.enable_x2apic_mode = vmx_enable_x2apic_mode_ts;
	}

	if (virtual_interrupt_delivery) {
		vlapic->ops.set_intr_ready = vmx_set_intr_ready;
		vlapic->ops.pending_intr = vmx_pending_intr;
		vlapic->ops.intr_accepted = vmx_intr_accepted;
		vlapic->ops.set_tmr = vmx_set_tmr;
		vlapic->ops.enable_x2apic_mode = vmx_enable_x2apic_mode_vid;
	}

	if (posted_interrupts)
		vlapic->ops.post_intr = vmx_post_intr;

	vlapic_init(vlapic);

	return (vlapic);
}

static void vmx_vlapic_cleanup(void *arg, struct vlapic *vlapic)
{

	vlapic_cleanup(vlapic);
	free(vlapic, M_VLAPIC);
}


static int vmx_snapshot_vmi(void *arg, struct vm_snapshot_meta *meta)
{
	struct vmx *vmx;
	struct vmxctx *vmxctx;
	int i;
	int ret;

	vmx = arg;

	KASSERT(vmx != NULL, ("%s: arg was NULL", __func__));

	for (i = 0; i < VM_MAXCPU; i++) {
		SNAPSHOT_BUF_OR_LEAVE(vmx->guest_msrs[i], sizeof(vmx->guest_msrs[i]), meta, ret, done);

		vmxctx = &vmx->ctx[i];
		SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_rdi, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_rsi, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_rdx, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_rcx, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r8, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r9, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_rax, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_rbx, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_rbp, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r10, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r11, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r12, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r13, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r14, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_r15, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_cr2, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_dr0, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_dr1, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_dr2, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_dr3, meta, ret, done);
		SNAPSHOT_VAR_OR_LEAVE(vmxctx->guest_dr6, meta, ret, done);
	}

done:
	return (ret);
}

static int vmx_snapshot_vmcx(void *arg, struct vm_snapshot_meta *meta, int vcpu)
{
	struct vmcs *vmcs;
	struct vmx *vmx;
	int err, run, hostcpu;

	vmx = (struct vmx *)arg;
	err = 0;

	KASSERT(arg != NULL, ("%s: arg was NULL", __func__));
	vmcs = &vmx->vmcs[vcpu];

	run = vcpu_is_running(vmx->vm, vcpu, &hostcpu);
	if (run && hostcpu != curcpu) {
		printf("%s: %s%d is running", __func__, vm_name(vmx->vm), vcpu);
		return (EINVAL);
	}

	err += vmcs_snapshot_reg(vmcs, run, VM_REG_GUEST_CR0, meta);
	err += vmcs_snapshot_reg(vmcs, run, VM_REG_GUEST_CR3, meta);
	err += vmcs_snapshot_reg(vmcs, run, VM_REG_GUEST_CR4, meta);
	err += vmcs_snapshot_reg(vmcs, run, VM_REG_GUEST_DR7, meta);
	err += vmcs_snapshot_reg(vmcs, run, VM_REG_GUEST_RSP, meta);
	err += vmcs_snapshot_reg(vmcs, run, VM_REG_GUEST_RIP, meta);
	err += vmcs_snapshot_reg(vmcs, run, VM_REG_GUEST_RFLAGS, meta);

	
	err += vmcs_snapshot_reg(vmcs, run, VM_REG_GUEST_ES, meta);
	err += vmcs_snapshot_desc(vmcs, run, VM_REG_GUEST_ES, meta);

	err += vmcs_snapshot_reg(vmcs, run, VM_REG_GUEST_CS, meta);
	err += vmcs_snapshot_desc(vmcs, run, VM_REG_GUEST_CS, meta);

	err += vmcs_snapshot_reg(vmcs, run, VM_REG_GUEST_SS, meta);
	err += vmcs_snapshot_desc(vmcs, run, VM_REG_GUEST_SS, meta);

	err += vmcs_snapshot_reg(vmcs, run, VM_REG_GUEST_DS, meta);
	err += vmcs_snapshot_desc(vmcs, run, VM_REG_GUEST_DS, meta);

	err += vmcs_snapshot_reg(vmcs, run, VM_REG_GUEST_FS, meta);
	err += vmcs_snapshot_desc(vmcs, run, VM_REG_GUEST_FS, meta);

	err += vmcs_snapshot_reg(vmcs, run, VM_REG_GUEST_GS, meta);
	err += vmcs_snapshot_desc(vmcs, run, VM_REG_GUEST_GS, meta);

	err += vmcs_snapshot_reg(vmcs, run, VM_REG_GUEST_TR, meta);
	err += vmcs_snapshot_desc(vmcs, run, VM_REG_GUEST_TR, meta);

	err += vmcs_snapshot_reg(vmcs, run, VM_REG_GUEST_LDTR, meta);
	err += vmcs_snapshot_desc(vmcs, run, VM_REG_GUEST_LDTR, meta);

	err += vmcs_snapshot_reg(vmcs, run, VM_REG_GUEST_EFER, meta);

	err += vmcs_snapshot_desc(vmcs, run, VM_REG_GUEST_IDTR, meta);
	err += vmcs_snapshot_desc(vmcs, run, VM_REG_GUEST_GDTR, meta);

	
	err += vmcs_snapshot_reg(vmcs, run, VM_REG_GUEST_PDPTE0, meta);
	err += vmcs_snapshot_reg(vmcs, run, VM_REG_GUEST_PDPTE1, meta);
	err += vmcs_snapshot_reg(vmcs, run, VM_REG_GUEST_PDPTE2, meta);
	err += vmcs_snapshot_reg(vmcs, run, VM_REG_GUEST_PDPTE3, meta);

	
	err += vmcs_snapshot_any(vmcs, run, VMCS_GUEST_IA32_SYSENTER_CS, meta);
	err += vmcs_snapshot_any(vmcs, run, VMCS_GUEST_IA32_SYSENTER_ESP, meta);
	err += vmcs_snapshot_any(vmcs, run, VMCS_GUEST_IA32_SYSENTER_EIP, meta);
	err += vmcs_snapshot_any(vmcs, run, VMCS_GUEST_INTERRUPTIBILITY, meta);
	err += vmcs_snapshot_any(vmcs, run, VMCS_GUEST_ACTIVITY, meta);
	err += vmcs_snapshot_any(vmcs, run, VMCS_ENTRY_CTLS, meta);
	err += vmcs_snapshot_any(vmcs, run, VMCS_EXIT_CTLS, meta);

	return (err);
}

static int vmx_restore_tsc(void *arg, int vcpu, uint64_t offset)
{
	struct vmcs *vmcs;
	struct vmx *vmx = (struct vmx *)arg;
	int error, running, hostcpu;

	KASSERT(arg != NULL, ("%s: arg was NULL", __func__));
	vmcs = &vmx->vmcs[vcpu];

	running = vcpu_is_running(vmx->vm, vcpu, &hostcpu);
	if (running && hostcpu != curcpu) {
		printf("%s: %s%d is running", __func__, vm_name(vmx->vm), vcpu);
		return (EINVAL);
	}

	if (!running)
		VMPTRLD(vmcs);

	error = vmx_set_tsc_offset(vmx, vcpu, offset);

	if (!running)
		VMCLEAR(vmcs);
	return (error);
}


struct vmm_ops vmm_ops_intel = {
	.init		= vmx_init, .cleanup	= vmx_cleanup, .resume		= vmx_restore, .vminit		= vmx_vminit, .vmrun		= vmx_run, .vmcleanup	= vmx_vmcleanup, .vmgetreg	= vmx_getreg, .vmsetreg	= vmx_setreg, .vmgetdesc	= vmx_getdesc, .vmsetdesc	= vmx_setdesc, .vmgetcap	= vmx_getcap, .vmsetcap	= vmx_setcap, .vmspace_alloc	= ept_vmspace_alloc, .vmspace_free	= ept_vmspace_free, .vlapic_init	= vmx_vlapic_init, .vlapic_cleanup	= vmx_vlapic_cleanup,  .vmsnapshot	= vmx_snapshot_vmi, .vmcx_snapshot	= vmx_snapshot_vmcx, .vm_restore_tsc	= vmx_restore_tsc,  };




















