






























static void __init spectre_v1_select_mitigation(void);
static void __init spectre_v2_select_mitigation(void);
static void __init retbleed_select_mitigation(void);
static void __init spectre_v2_user_select_mitigation(void);
static void __init ssb_select_mitigation(void);
static void __init l1tf_select_mitigation(void);
static void __init mds_select_mitigation(void);
static void __init md_clear_update_mitigation(void);
static void __init md_clear_select_mitigation(void);
static void __init taa_select_mitigation(void);
static void __init mmio_select_mitigation(void);
static void __init srbds_select_mitigation(void);
static void __init l1d_flush_select_mitigation(void);


u64 x86_spec_ctrl_base;
EXPORT_SYMBOL_GPL(x86_spec_ctrl_base);


DEFINE_PER_CPU(u64, x86_spec_ctrl_current);
EXPORT_SYMBOL_GPL(x86_spec_ctrl_current);

static DEFINE_MUTEX(spec_ctrl_mutex);


static void update_spec_ctrl(u64 val)
{
	this_cpu_write(x86_spec_ctrl_current, val);
	wrmsrl(MSR_IA32_SPEC_CTRL, val);
}


void update_spec_ctrl_cond(u64 val)
{
	if (this_cpu_read(x86_spec_ctrl_current) == val)
		return;

	this_cpu_write(x86_spec_ctrl_current, val);

	
	if (!cpu_feature_enabled(X86_FEATURE_KERNEL_IBRS))
		wrmsrl(MSR_IA32_SPEC_CTRL, val);
}

noinstr u64 spec_ctrl_current(void)
{
	return this_cpu_read(x86_spec_ctrl_current);
}
EXPORT_SYMBOL_GPL(spec_ctrl_current);


u64 __ro_after_init x86_amd_ls_cfg_base;
u64 __ro_after_init x86_amd_ls_cfg_ssbd_mask;


DEFINE_STATIC_KEY_FALSE(switch_to_cond_stibp);

DEFINE_STATIC_KEY_FALSE(switch_mm_cond_ibpb);

DEFINE_STATIC_KEY_FALSE(switch_mm_always_ibpb);


DEFINE_STATIC_KEY_FALSE(mds_user_clear);
EXPORT_SYMBOL_GPL(mds_user_clear);

DEFINE_STATIC_KEY_FALSE(mds_idle_clear);
EXPORT_SYMBOL_GPL(mds_idle_clear);


DEFINE_STATIC_KEY_FALSE(switch_mm_cond_l1d_flush);


DEFINE_STATIC_KEY_FALSE(mmio_stale_data_clear);
EXPORT_SYMBOL_GPL(mmio_stale_data_clear);

void __init check_bugs(void)
{
	identify_boot_cpu();

	
	cpu_smt_check_topology();

	if (!IS_ENABLED(CONFIG_SMP)) {
		pr_info("CPU: ");
		print_cpu_info(&boot_cpu_data);
	}

	
	if (cpu_feature_enabled(X86_FEATURE_MSR_SPEC_CTRL)) {
		rdmsrl(MSR_IA32_SPEC_CTRL, x86_spec_ctrl_base);

		
		x86_spec_ctrl_base &= ~SPEC_CTRL_MITIGATIONS_MASK;
	}

	
	spectre_v1_select_mitigation();
	spectre_v2_select_mitigation();
	
	retbleed_select_mitigation();
	
	spectre_v2_user_select_mitigation();
	ssb_select_mitigation();
	l1tf_select_mitigation();
	md_clear_select_mitigation();
	srbds_select_mitigation();
	l1d_flush_select_mitigation();

	arch_smt_update();


	
	if (boot_cpu_data.x86 < 4)
		panic("Kernel requires i486+ for 'invlpg' and other features");

	init_utsname()->machine[1] = '0' + (boot_cpu_data.x86 > 6 ? 6 : boot_cpu_data.x86);
	alternative_instructions();

	fpu__init_check_bugs();

	alternative_instructions();

	
	if (!direct_gbpages)
		set_memory_4k((unsigned long)__va(0), 1);

}


void x86_virt_spec_ctrl(u64 guest_virt_spec_ctrl, bool setguest)
{
	u64 guestval, hostval;
	struct thread_info *ti = current_thread_info();

	
	if (!static_cpu_has(X86_FEATURE_LS_CFG_SSBD) && !static_cpu_has(X86_FEATURE_VIRT_SSBD))
		return;

	
	if (static_cpu_has(X86_FEATURE_SPEC_STORE_BYPASS_DISABLE))
		hostval = SPEC_CTRL_SSBD;
	else hostval = ssbd_tif_to_spec_ctrl(ti->flags);

	
	guestval = guest_virt_spec_ctrl & SPEC_CTRL_SSBD;

	if (hostval != guestval) {
		unsigned long tif;

		tif = setguest ? ssbd_spec_ctrl_to_tif(guestval) :
				 ssbd_spec_ctrl_to_tif(hostval);

		speculation_ctrl_update(tif);
	}
}
EXPORT_SYMBOL_GPL(x86_virt_spec_ctrl);

static void x86_amd_ssb_disable(void)
{
	u64 msrval = x86_amd_ls_cfg_base | x86_amd_ls_cfg_ssbd_mask;

	if (boot_cpu_has(X86_FEATURE_VIRT_SSBD))
		wrmsrl(MSR_AMD64_VIRT_SPEC_CTRL, SPEC_CTRL_SSBD);
	else if (boot_cpu_has(X86_FEATURE_LS_CFG_SSBD))
		wrmsrl(MSR_AMD64_LS_CFG, msrval);
}





static enum mds_mitigations mds_mitigation __ro_after_init = MDS_MITIGATION_FULL;
static bool mds_nosmt __ro_after_init = false;

static const char * const mds_strings[] = {
	[MDS_MITIGATION_OFF]	= "Vulnerable", [MDS_MITIGATION_FULL]	= "Mitigation: Clear CPU buffers", [MDS_MITIGATION_VMWERV]	= "Vulnerable: Clear CPU buffers attempted, no microcode", };



static void __init mds_select_mitigation(void)
{
	if (!boot_cpu_has_bug(X86_BUG_MDS) || cpu_mitigations_off()) {
		mds_mitigation = MDS_MITIGATION_OFF;
		return;
	}

	if (mds_mitigation == MDS_MITIGATION_FULL) {
		if (!boot_cpu_has(X86_FEATURE_MD_CLEAR))
			mds_mitigation = MDS_MITIGATION_VMWERV;

		static_branch_enable(&mds_user_clear);

		if (!boot_cpu_has(X86_BUG_MSBDS_ONLY) && (mds_nosmt || cpu_mitigations_auto_nosmt()))
			cpu_smt_disable(false);
	}
}

static int __init mds_cmdline(char *str)
{
	if (!boot_cpu_has_bug(X86_BUG_MDS))
		return 0;

	if (!str)
		return -EINVAL;

	if (!strcmp(str, "off"))
		mds_mitigation = MDS_MITIGATION_OFF;
	else if (!strcmp(str, "full"))
		mds_mitigation = MDS_MITIGATION_FULL;
	else if (!strcmp(str, "full,nosmt")) {
		mds_mitigation = MDS_MITIGATION_FULL;
		mds_nosmt = true;
	}

	return 0;
}
early_param("mds", mds_cmdline);




enum taa_mitigations {
	TAA_MITIGATION_OFF, TAA_MITIGATION_UCODE_NEEDED, TAA_MITIGATION_VERW, TAA_MITIGATION_TSX_DISABLED, };





static enum taa_mitigations taa_mitigation __ro_after_init = TAA_MITIGATION_VERW;
static bool taa_nosmt __ro_after_init;

static const char * const taa_strings[] = {
	[TAA_MITIGATION_OFF]		= "Vulnerable", [TAA_MITIGATION_UCODE_NEEDED]	= "Vulnerable: Clear CPU buffers attempted, no microcode", [TAA_MITIGATION_VERW]		= "Mitigation: Clear CPU buffers", [TAA_MITIGATION_TSX_DISABLED]	= "Mitigation: TSX disabled", };




static void __init taa_select_mitigation(void)
{
	u64 ia32_cap;

	if (!boot_cpu_has_bug(X86_BUG_TAA)) {
		taa_mitigation = TAA_MITIGATION_OFF;
		return;
	}

	
	if (!boot_cpu_has(X86_FEATURE_RTM)) {
		taa_mitigation = TAA_MITIGATION_TSX_DISABLED;
		return;
	}

	if (cpu_mitigations_off()) {
		taa_mitigation = TAA_MITIGATION_OFF;
		return;
	}

	
	if (taa_mitigation == TAA_MITIGATION_OFF && mds_mitigation == MDS_MITIGATION_OFF)
		return;

	if (boot_cpu_has(X86_FEATURE_MD_CLEAR))
		taa_mitigation = TAA_MITIGATION_VERW;
	else taa_mitigation = TAA_MITIGATION_UCODE_NEEDED;

	
	ia32_cap = x86_read_arch_cap_msr();
	if ( (ia32_cap & ARCH_CAP_MDS_NO) && !(ia32_cap & ARCH_CAP_TSX_CTRL_MSR))
		taa_mitigation = TAA_MITIGATION_UCODE_NEEDED;

	
	static_branch_enable(&mds_user_clear);

	if (taa_nosmt || cpu_mitigations_auto_nosmt())
		cpu_smt_disable(false);
}

static int __init tsx_async_abort_parse_cmdline(char *str)
{
	if (!boot_cpu_has_bug(X86_BUG_TAA))
		return 0;

	if (!str)
		return -EINVAL;

	if (!strcmp(str, "off")) {
		taa_mitigation = TAA_MITIGATION_OFF;
	} else if (!strcmp(str, "full")) {
		taa_mitigation = TAA_MITIGATION_VERW;
	} else if (!strcmp(str, "full,nosmt")) {
		taa_mitigation = TAA_MITIGATION_VERW;
		taa_nosmt = true;
	}

	return 0;
}
early_param("tsx_async_abort", tsx_async_abort_parse_cmdline);




enum mmio_mitigations {
	MMIO_MITIGATION_OFF, MMIO_MITIGATION_UCODE_NEEDED, MMIO_MITIGATION_VERW, };




static enum mmio_mitigations mmio_mitigation __ro_after_init = MMIO_MITIGATION_VERW;
static bool mmio_nosmt __ro_after_init = false;

static const char * const mmio_strings[] = {
	[MMIO_MITIGATION_OFF]		= "Vulnerable", [MMIO_MITIGATION_UCODE_NEEDED]	= "Vulnerable: Clear CPU buffers attempted, no microcode", [MMIO_MITIGATION_VERW]		= "Mitigation: Clear CPU buffers", };



static void __init mmio_select_mitigation(void)
{
	u64 ia32_cap;

	if (!boot_cpu_has_bug(X86_BUG_MMIO_STALE_DATA) || boot_cpu_has_bug(X86_BUG_MMIO_UNKNOWN) || cpu_mitigations_off()) {

		mmio_mitigation = MMIO_MITIGATION_OFF;
		return;
	}

	if (mmio_mitigation == MMIO_MITIGATION_OFF)
		return;

	ia32_cap = x86_read_arch_cap_msr();

	
	if (boot_cpu_has_bug(X86_BUG_MDS) || (boot_cpu_has_bug(X86_BUG_TAA) && boot_cpu_has(X86_FEATURE_RTM)))
		static_branch_enable(&mds_user_clear);
	else static_branch_enable(&mmio_stale_data_clear);

	
	if (!(ia32_cap & ARCH_CAP_FBSDP_NO))
		static_branch_enable(&mds_idle_clear);

	
	if ((ia32_cap & ARCH_CAP_FB_CLEAR) || (boot_cpu_has(X86_FEATURE_MD_CLEAR) && boot_cpu_has(X86_FEATURE_FLUSH_L1D) && !(ia32_cap & ARCH_CAP_MDS_NO)))


		mmio_mitigation = MMIO_MITIGATION_VERW;
	else mmio_mitigation = MMIO_MITIGATION_UCODE_NEEDED;

	if (mmio_nosmt || cpu_mitigations_auto_nosmt())
		cpu_smt_disable(false);
}

static int __init mmio_stale_data_parse_cmdline(char *str)
{
	if (!boot_cpu_has_bug(X86_BUG_MMIO_STALE_DATA))
		return 0;

	if (!str)
		return -EINVAL;

	if (!strcmp(str, "off")) {
		mmio_mitigation = MMIO_MITIGATION_OFF;
	} else if (!strcmp(str, "full")) {
		mmio_mitigation = MMIO_MITIGATION_VERW;
	} else if (!strcmp(str, "full,nosmt")) {
		mmio_mitigation = MMIO_MITIGATION_VERW;
		mmio_nosmt = true;
	}

	return 0;
}
early_param("mmio_stale_data", mmio_stale_data_parse_cmdline);




static void __init md_clear_update_mitigation(void)
{
	if (cpu_mitigations_off())
		return;

	if (!static_key_enabled(&mds_user_clear))
		goto out;

	
	if (mds_mitigation == MDS_MITIGATION_OFF && boot_cpu_has_bug(X86_BUG_MDS)) {
		mds_mitigation = MDS_MITIGATION_FULL;
		mds_select_mitigation();
	}
	if (taa_mitigation == TAA_MITIGATION_OFF && boot_cpu_has_bug(X86_BUG_TAA)) {
		taa_mitigation = TAA_MITIGATION_VERW;
		taa_select_mitigation();
	}
	if (mmio_mitigation == MMIO_MITIGATION_OFF && boot_cpu_has_bug(X86_BUG_MMIO_STALE_DATA)) {
		mmio_mitigation = MMIO_MITIGATION_VERW;
		mmio_select_mitigation();
	}
out:
	if (boot_cpu_has_bug(X86_BUG_MDS))
		pr_info("MDS: %s\n", mds_strings[mds_mitigation]);
	if (boot_cpu_has_bug(X86_BUG_TAA))
		pr_info("TAA: %s\n", taa_strings[taa_mitigation]);
	if (boot_cpu_has_bug(X86_BUG_MMIO_STALE_DATA))
		pr_info("MMIO Stale Data: %s\n", mmio_strings[mmio_mitigation]);
	else if (boot_cpu_has_bug(X86_BUG_MMIO_UNKNOWN))
		pr_info("MMIO Stale Data: Unknown: No mitigations\n");
}

static void __init md_clear_select_mitigation(void)
{
	mds_select_mitigation();
	taa_select_mitigation();
	mmio_select_mitigation();

	
	md_clear_update_mitigation();
}




enum srbds_mitigations {
	SRBDS_MITIGATION_OFF, SRBDS_MITIGATION_UCODE_NEEDED, SRBDS_MITIGATION_FULL, SRBDS_MITIGATION_TSX_OFF, SRBDS_MITIGATION_HYPERVISOR, };





static enum srbds_mitigations srbds_mitigation __ro_after_init = SRBDS_MITIGATION_FULL;

static const char * const srbds_strings[] = {
	[SRBDS_MITIGATION_OFF]		= "Vulnerable", [SRBDS_MITIGATION_UCODE_NEEDED]	= "Vulnerable: No microcode", [SRBDS_MITIGATION_FULL]		= "Mitigation: Microcode", [SRBDS_MITIGATION_TSX_OFF]	= "Mitigation: TSX disabled", [SRBDS_MITIGATION_HYPERVISOR]	= "Unknown: Dependent on hypervisor status", };





static bool srbds_off;

void update_srbds_msr(void)
{
	u64 mcu_ctrl;

	if (!boot_cpu_has_bug(X86_BUG_SRBDS))
		return;

	if (boot_cpu_has(X86_FEATURE_HYPERVISOR))
		return;

	if (srbds_mitigation == SRBDS_MITIGATION_UCODE_NEEDED)
		return;

	
	if (!boot_cpu_has(X86_FEATURE_SRBDS_CTRL))
		return;

	rdmsrl(MSR_IA32_MCU_OPT_CTRL, mcu_ctrl);

	switch (srbds_mitigation) {
	case SRBDS_MITIGATION_OFF:
	case SRBDS_MITIGATION_TSX_OFF:
		mcu_ctrl |= RNGDS_MITG_DIS;
		break;
	case SRBDS_MITIGATION_FULL:
		mcu_ctrl &= ~RNGDS_MITG_DIS;
		break;
	default:
		break;
	}

	wrmsrl(MSR_IA32_MCU_OPT_CTRL, mcu_ctrl);
}

static void __init srbds_select_mitigation(void)
{
	u64 ia32_cap;

	if (!boot_cpu_has_bug(X86_BUG_SRBDS))
		return;

	
	ia32_cap = x86_read_arch_cap_msr();
	if ((ia32_cap & ARCH_CAP_MDS_NO) && !boot_cpu_has(X86_FEATURE_RTM) && !boot_cpu_has_bug(X86_BUG_MMIO_STALE_DATA))
		srbds_mitigation = SRBDS_MITIGATION_TSX_OFF;
	else if (boot_cpu_has(X86_FEATURE_HYPERVISOR))
		srbds_mitigation = SRBDS_MITIGATION_HYPERVISOR;
	else if (!boot_cpu_has(X86_FEATURE_SRBDS_CTRL))
		srbds_mitigation = SRBDS_MITIGATION_UCODE_NEEDED;
	else if (cpu_mitigations_off() || srbds_off)
		srbds_mitigation = SRBDS_MITIGATION_OFF;

	update_srbds_msr();
	pr_info("%s\n", srbds_strings[srbds_mitigation]);
}

static int __init srbds_parse_cmdline(char *str)
{
	if (!str)
		return -EINVAL;

	if (!boot_cpu_has_bug(X86_BUG_SRBDS))
		return 0;

	srbds_off = !strcmp(str, "off");
	return 0;
}
early_param("srbds", srbds_parse_cmdline);




enum l1d_flush_mitigations {
	L1D_FLUSH_OFF = 0, L1D_FLUSH_ON, };


static enum l1d_flush_mitigations l1d_flush_mitigation __initdata = L1D_FLUSH_OFF;

static void __init l1d_flush_select_mitigation(void)
{
	if (!l1d_flush_mitigation || !boot_cpu_has(X86_FEATURE_FLUSH_L1D))
		return;

	static_branch_enable(&switch_mm_cond_l1d_flush);
	pr_info("Conditional flush on switch_mm() enabled\n");
}

static int __init l1d_flush_parse_cmdline(char *str)
{
	if (!strcmp(str, "on"))
		l1d_flush_mitigation = L1D_FLUSH_ON;

	return 0;
}
early_param("l1d_flush", l1d_flush_parse_cmdline);




enum spectre_v1_mitigation {
	SPECTRE_V1_MITIGATION_NONE, SPECTRE_V1_MITIGATION_AUTO, };


static enum spectre_v1_mitigation spectre_v1_mitigation __ro_after_init = SPECTRE_V1_MITIGATION_AUTO;

static const char * const spectre_v1_strings[] = {
	[SPECTRE_V1_MITIGATION_NONE] = "Vulnerable: __user pointer sanitization and usercopy barriers only; no swapgs barriers", [SPECTRE_V1_MITIGATION_AUTO] = "Mitigation: usercopy/swapgs barriers and __user pointer sanitization", };



static bool smap_works_speculatively(void)
{
	if (!boot_cpu_has(X86_FEATURE_SMAP))
		return false;

	
	if (boot_cpu_has(X86_BUG_CPU_MELTDOWN))
		return false;

	return true;
}

static void __init spectre_v1_select_mitigation(void)
{
	if (!boot_cpu_has_bug(X86_BUG_SPECTRE_V1) || cpu_mitigations_off()) {
		spectre_v1_mitigation = SPECTRE_V1_MITIGATION_NONE;
		return;
	}

	if (spectre_v1_mitigation == SPECTRE_V1_MITIGATION_AUTO) {
		
		if (boot_cpu_has(X86_FEATURE_FSGSBASE) || !smap_works_speculatively()) {
			
			if (boot_cpu_has_bug(X86_BUG_SWAPGS) && !boot_cpu_has(X86_FEATURE_PTI))
				setup_force_cpu_cap(X86_FEATURE_FENCE_SWAPGS_USER);

			
			setup_force_cpu_cap(X86_FEATURE_FENCE_SWAPGS_KERNEL);
		}
	}

	pr_info("%s\n", spectre_v1_strings[spectre_v1_mitigation]);
}

static int __init nospectre_v1_cmdline(char *str)
{
	spectre_v1_mitigation = SPECTRE_V1_MITIGATION_NONE;
	return 0;
}
early_param("nospectre_v1", nospectre_v1_cmdline);

static enum spectre_v2_mitigation spectre_v2_enabled __ro_after_init = SPECTRE_V2_NONE;




enum retbleed_mitigation {
	RETBLEED_MITIGATION_NONE, RETBLEED_MITIGATION_UNRET, RETBLEED_MITIGATION_IBPB, RETBLEED_MITIGATION_IBRS, RETBLEED_MITIGATION_EIBRS, RETBLEED_MITIGATION_STUFF, };






enum retbleed_mitigation_cmd {
	RETBLEED_CMD_OFF, RETBLEED_CMD_AUTO, RETBLEED_CMD_UNRET, RETBLEED_CMD_IBPB, RETBLEED_CMD_STUFF, };





static const char * const retbleed_strings[] = {
	[RETBLEED_MITIGATION_NONE]	= "Vulnerable", [RETBLEED_MITIGATION_UNRET]	= "Mitigation: untrained return thunk", [RETBLEED_MITIGATION_IBPB]	= "Mitigation: IBPB", [RETBLEED_MITIGATION_IBRS]	= "Mitigation: IBRS", [RETBLEED_MITIGATION_EIBRS]	= "Mitigation: Enhanced IBRS", [RETBLEED_MITIGATION_STUFF]	= "Mitigation: Stuffing", };






static enum retbleed_mitigation retbleed_mitigation __ro_after_init = RETBLEED_MITIGATION_NONE;
static enum retbleed_mitigation_cmd retbleed_cmd __ro_after_init = RETBLEED_CMD_AUTO;

static int __ro_after_init retbleed_nosmt = false;

static int __init retbleed_parse_cmdline(char *str)
{
	if (!str)
		return -EINVAL;

	while (str) {
		char *next = strchr(str, ',');
		if (next) {
			*next = 0;
			next++;
		}

		if (!strcmp(str, "off")) {
			retbleed_cmd = RETBLEED_CMD_OFF;
		} else if (!strcmp(str, "auto")) {
			retbleed_cmd = RETBLEED_CMD_AUTO;
		} else if (!strcmp(str, "unret")) {
			retbleed_cmd = RETBLEED_CMD_UNRET;
		} else if (!strcmp(str, "ibpb")) {
			retbleed_cmd = RETBLEED_CMD_IBPB;
		} else if (!strcmp(str, "stuff")) {
			retbleed_cmd = RETBLEED_CMD_STUFF;
		} else if (!strcmp(str, "nosmt")) {
			retbleed_nosmt = true;
		} else if (!strcmp(str, "force")) {
			setup_force_cpu_bug(X86_BUG_RETBLEED);
		} else {
			pr_err("Ignoring unknown retbleed option (%s).", str);
		}

		str = next;
	}

	return 0;
}
early_param("retbleed", retbleed_parse_cmdline);




static void __init retbleed_select_mitigation(void)
{
	bool mitigate_smt = false;

	if (!boot_cpu_has_bug(X86_BUG_RETBLEED) || cpu_mitigations_off())
		return;

	switch (retbleed_cmd) {
	case RETBLEED_CMD_OFF:
		return;

	case RETBLEED_CMD_UNRET:
		if (IS_ENABLED(CONFIG_CPU_UNRET_ENTRY)) {
			retbleed_mitigation = RETBLEED_MITIGATION_UNRET;
		} else {
			pr_err("WARNING: kernel not compiled with CPU_UNRET_ENTRY.\n");
			goto do_cmd_auto;
		}
		break;

	case RETBLEED_CMD_IBPB:
		if (!boot_cpu_has(X86_FEATURE_IBPB)) {
			pr_err("WARNING: CPU does not support IBPB.\n");
			goto do_cmd_auto;
		} else if (IS_ENABLED(CONFIG_CPU_IBPB_ENTRY)) {
			retbleed_mitigation = RETBLEED_MITIGATION_IBPB;
		} else {
			pr_err("WARNING: kernel not compiled with CPU_IBPB_ENTRY.\n");
			goto do_cmd_auto;
		}
		break;

	case RETBLEED_CMD_STUFF:
		if (IS_ENABLED(CONFIG_CALL_DEPTH_TRACKING) && spectre_v2_enabled == SPECTRE_V2_RETPOLINE) {
			retbleed_mitigation = RETBLEED_MITIGATION_STUFF;

		} else {
			if (IS_ENABLED(CONFIG_CALL_DEPTH_TRACKING))
				pr_err("WARNING: retbleed=stuff depends on spectre_v2=retpoline\n");
			else pr_err("WARNING: kernel not compiled with CALL_DEPTH_TRACKING.\n");

			goto do_cmd_auto;
		}
		break;

do_cmd_auto:
	case RETBLEED_CMD_AUTO:
	default:
		if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD || boot_cpu_data.x86_vendor == X86_VENDOR_HYGON) {
			if (IS_ENABLED(CONFIG_CPU_UNRET_ENTRY))
				retbleed_mitigation = RETBLEED_MITIGATION_UNRET;
			else if (IS_ENABLED(CONFIG_CPU_IBPB_ENTRY) && boot_cpu_has(X86_FEATURE_IBPB))
				retbleed_mitigation = RETBLEED_MITIGATION_IBPB;
		}

		

		break;
	}

	switch (retbleed_mitigation) {
	case RETBLEED_MITIGATION_UNRET:
		setup_force_cpu_cap(X86_FEATURE_RETHUNK);
		setup_force_cpu_cap(X86_FEATURE_UNRET);

		if (boot_cpu_data.x86_vendor != X86_VENDOR_AMD && boot_cpu_data.x86_vendor != X86_VENDOR_HYGON)
			pr_err(RETBLEED_UNTRAIN_MSG);

		mitigate_smt = true;
		break;

	case RETBLEED_MITIGATION_IBPB:
		setup_force_cpu_cap(X86_FEATURE_ENTRY_IBPB);
		mitigate_smt = true;
		break;

	case RETBLEED_MITIGATION_STUFF:
		setup_force_cpu_cap(X86_FEATURE_RETHUNK);
		setup_force_cpu_cap(X86_FEATURE_CALL_DEPTH);
		x86_set_skl_return_thunk();
		break;

	default:
		break;
	}

	if (mitigate_smt && !boot_cpu_has(X86_FEATURE_STIBP) && (retbleed_nosmt || cpu_mitigations_auto_nosmt()))
		cpu_smt_disable(false);

	
	if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL) {
		switch (spectre_v2_enabled) {
		case SPECTRE_V2_IBRS:
			retbleed_mitigation = RETBLEED_MITIGATION_IBRS;
			break;
		case SPECTRE_V2_EIBRS:
		case SPECTRE_V2_EIBRS_RETPOLINE:
		case SPECTRE_V2_EIBRS_LFENCE:
			retbleed_mitigation = RETBLEED_MITIGATION_EIBRS;
			break;
		default:
			if (retbleed_mitigation != RETBLEED_MITIGATION_STUFF)
				pr_err(RETBLEED_INTEL_MSG);
		}
	}

	pr_info("%s\n", retbleed_strings[retbleed_mitigation]);
}




static enum spectre_v2_user_mitigation spectre_v2_user_stibp __ro_after_init = SPECTRE_V2_USER_NONE;
static enum spectre_v2_user_mitigation spectre_v2_user_ibpb __ro_after_init = SPECTRE_V2_USER_NONE;


static bool spectre_v2_bad_module;

bool retpoline_module_ok(bool has_retpoline)
{
	if (spectre_v2_enabled == SPECTRE_V2_NONE || has_retpoline)
		return true;

	pr_err("System may be vulnerable to spectre v2\n");
	spectre_v2_bad_module = true;
	return false;
}

static inline const char *spectre_v2_module_string(void)
{
	return spectre_v2_bad_module ? " - vulnerable module loaded" : "";
}

static inline const char *spectre_v2_module_string(void) { return ""; }








void unpriv_ebpf_notify(int new_state)
{
	if (new_state)
		return;

	

	switch (spectre_v2_enabled) {
	case SPECTRE_V2_EIBRS:
		pr_err(SPECTRE_V2_EIBRS_EBPF_MSG);
		break;
	case SPECTRE_V2_EIBRS_LFENCE:
		if (sched_smt_active())
			pr_err(SPECTRE_V2_EIBRS_LFENCE_EBPF_SMT_MSG);
		break;
	default:
		break;
	}
}


static inline bool match_option(const char *arg, int arglen, const char *opt)
{
	int len = strlen(opt);

	return len == arglen && !strncmp(arg, opt, len);
}


enum spectre_v2_mitigation_cmd {
	SPECTRE_V2_CMD_NONE, SPECTRE_V2_CMD_AUTO, SPECTRE_V2_CMD_FORCE, SPECTRE_V2_CMD_RETPOLINE, SPECTRE_V2_CMD_RETPOLINE_GENERIC, SPECTRE_V2_CMD_RETPOLINE_LFENCE, SPECTRE_V2_CMD_EIBRS, SPECTRE_V2_CMD_EIBRS_RETPOLINE, SPECTRE_V2_CMD_EIBRS_LFENCE, SPECTRE_V2_CMD_IBRS, };










enum spectre_v2_user_cmd {
	SPECTRE_V2_USER_CMD_NONE, SPECTRE_V2_USER_CMD_AUTO, SPECTRE_V2_USER_CMD_FORCE, SPECTRE_V2_USER_CMD_PRCTL, SPECTRE_V2_USER_CMD_PRCTL_IBPB, SPECTRE_V2_USER_CMD_SECCOMP, SPECTRE_V2_USER_CMD_SECCOMP_IBPB, };







static const char * const spectre_v2_user_strings[] = {
	[SPECTRE_V2_USER_NONE]			= "User space: Vulnerable", [SPECTRE_V2_USER_STRICT]		= "User space: Mitigation: STIBP protection", [SPECTRE_V2_USER_STRICT_PREFERRED]	= "User space: Mitigation: STIBP always-on protection", [SPECTRE_V2_USER_PRCTL]			= "User space: Mitigation: STIBP via prctl", [SPECTRE_V2_USER_SECCOMP]		= "User space: Mitigation: STIBP via seccomp and prctl", };





static const struct {
	const char			*option;
	enum spectre_v2_user_cmd	cmd;
	bool				secure;
} v2_user_options[] __initconst = {
	{ "auto",		SPECTRE_V2_USER_CMD_AUTO,		false }, { "off",		SPECTRE_V2_USER_CMD_NONE,		false }, { "on",			SPECTRE_V2_USER_CMD_FORCE,		true  }, { "prctl",		SPECTRE_V2_USER_CMD_PRCTL,		false }, { "prctl,ibpb",		SPECTRE_V2_USER_CMD_PRCTL_IBPB,		false }, { "seccomp",		SPECTRE_V2_USER_CMD_SECCOMP,		false }, { "seccomp,ibpb",	SPECTRE_V2_USER_CMD_SECCOMP_IBPB,	false }, };







static void __init spec_v2_user_print_cond(const char *reason, bool secure)
{
	if (boot_cpu_has_bug(X86_BUG_SPECTRE_V2) != secure)
		pr_info("spectre_v2_user=%s forced on command line.\n", reason);
}

static __ro_after_init enum spectre_v2_mitigation_cmd spectre_v2_cmd;

static enum spectre_v2_user_cmd __init spectre_v2_parse_user_cmdline(void)
{
	char arg[20];
	int ret, i;

	switch (spectre_v2_cmd) {
	case SPECTRE_V2_CMD_NONE:
		return SPECTRE_V2_USER_CMD_NONE;
	case SPECTRE_V2_CMD_FORCE:
		return SPECTRE_V2_USER_CMD_FORCE;
	default:
		break;
	}

	ret = cmdline_find_option(boot_command_line, "spectre_v2_user", arg, sizeof(arg));
	if (ret < 0)
		return SPECTRE_V2_USER_CMD_AUTO;

	for (i = 0; i < ARRAY_SIZE(v2_user_options); i++) {
		if (match_option(arg, ret, v2_user_options[i].option)) {
			spec_v2_user_print_cond(v2_user_options[i].option, v2_user_options[i].secure);
			return v2_user_options[i].cmd;
		}
	}

	pr_err("Unknown user space protection option (%s). Switching to AUTO select\n", arg);
	return SPECTRE_V2_USER_CMD_AUTO;
}

static inline bool spectre_v2_in_ibrs_mode(enum spectre_v2_mitigation mode)
{
	return mode == SPECTRE_V2_IBRS || mode == SPECTRE_V2_EIBRS || mode == SPECTRE_V2_EIBRS_RETPOLINE || mode == SPECTRE_V2_EIBRS_LFENCE;


}

static void __init spectre_v2_user_select_mitigation(void)
{
	enum spectre_v2_user_mitigation mode = SPECTRE_V2_USER_NONE;
	bool smt_possible = IS_ENABLED(CONFIG_SMP);
	enum spectre_v2_user_cmd cmd;

	if (!boot_cpu_has(X86_FEATURE_IBPB) && !boot_cpu_has(X86_FEATURE_STIBP))
		return;

	if (cpu_smt_control == CPU_SMT_FORCE_DISABLED || cpu_smt_control == CPU_SMT_NOT_SUPPORTED)
		smt_possible = false;

	cmd = spectre_v2_parse_user_cmdline();
	switch (cmd) {
	case SPECTRE_V2_USER_CMD_NONE:
		goto set_mode;
	case SPECTRE_V2_USER_CMD_FORCE:
		mode = SPECTRE_V2_USER_STRICT;
		break;
	case SPECTRE_V2_USER_CMD_AUTO:
	case SPECTRE_V2_USER_CMD_PRCTL:
	case SPECTRE_V2_USER_CMD_PRCTL_IBPB:
		mode = SPECTRE_V2_USER_PRCTL;
		break;
	case SPECTRE_V2_USER_CMD_SECCOMP:
	case SPECTRE_V2_USER_CMD_SECCOMP_IBPB:
		if (IS_ENABLED(CONFIG_SECCOMP))
			mode = SPECTRE_V2_USER_SECCOMP;
		else mode = SPECTRE_V2_USER_PRCTL;
		break;
	}

	
	if (boot_cpu_has(X86_FEATURE_IBPB)) {
		setup_force_cpu_cap(X86_FEATURE_USE_IBPB);

		spectre_v2_user_ibpb = mode;
		switch (cmd) {
		case SPECTRE_V2_USER_CMD_FORCE:
		case SPECTRE_V2_USER_CMD_PRCTL_IBPB:
		case SPECTRE_V2_USER_CMD_SECCOMP_IBPB:
			static_branch_enable(&switch_mm_always_ibpb);
			spectre_v2_user_ibpb = SPECTRE_V2_USER_STRICT;
			break;
		case SPECTRE_V2_USER_CMD_PRCTL:
		case SPECTRE_V2_USER_CMD_AUTO:
		case SPECTRE_V2_USER_CMD_SECCOMP:
			static_branch_enable(&switch_mm_cond_ibpb);
			break;
		default:
			break;
		}

		pr_info("mitigation: Enabling %s Indirect Branch Prediction Barrier\n", static_key_enabled(&switch_mm_always_ibpb) ? "always-on" : "conditional");

	}

	
	if (!boot_cpu_has(X86_FEATURE_STIBP) || !smt_possible || spectre_v2_in_ibrs_mode(spectre_v2_enabled))

		return;

	
	if (mode != SPECTRE_V2_USER_STRICT && boot_cpu_has(X86_FEATURE_AMD_STIBP_ALWAYS_ON))
		mode = SPECTRE_V2_USER_STRICT_PREFERRED;

	if (retbleed_mitigation == RETBLEED_MITIGATION_UNRET || retbleed_mitigation == RETBLEED_MITIGATION_IBPB) {
		if (mode != SPECTRE_V2_USER_STRICT && mode != SPECTRE_V2_USER_STRICT_PREFERRED)
			pr_info("Selecting STIBP always-on mode to complement retbleed mitigation\n");
		mode = SPECTRE_V2_USER_STRICT_PREFERRED;
	}

	spectre_v2_user_stibp = mode;

set_mode:
	pr_info("%s\n", spectre_v2_user_strings[mode]);
}

static const char * const spectre_v2_strings[] = {
	[SPECTRE_V2_NONE]			= "Vulnerable", [SPECTRE_V2_RETPOLINE]			= "Mitigation: Retpolines", [SPECTRE_V2_LFENCE]			= "Mitigation: LFENCE", [SPECTRE_V2_EIBRS]			= "Mitigation: Enhanced / Automatic IBRS", [SPECTRE_V2_EIBRS_LFENCE]		= "Mitigation: Enhanced / Automatic IBRS + LFENCE", [SPECTRE_V2_EIBRS_RETPOLINE]		= "Mitigation: Enhanced / Automatic IBRS + Retpolines", [SPECTRE_V2_IBRS]			= "Mitigation: IBRS", };







static const struct {
	const char *option;
	enum spectre_v2_mitigation_cmd cmd;
	bool secure;
} mitigation_options[] __initconst = {
	{ "off",		SPECTRE_V2_CMD_NONE,		  false }, { "on",			SPECTRE_V2_CMD_FORCE,		  true  }, { "retpoline",		SPECTRE_V2_CMD_RETPOLINE,	  false }, { "retpoline,amd",	SPECTRE_V2_CMD_RETPOLINE_LFENCE,  false }, { "retpoline,lfence",	SPECTRE_V2_CMD_RETPOLINE_LFENCE,  false }, { "retpoline,generic",	SPECTRE_V2_CMD_RETPOLINE_GENERIC, false }, { "eibrs",		SPECTRE_V2_CMD_EIBRS,		  false }, { "eibrs,lfence",	SPECTRE_V2_CMD_EIBRS_LFENCE,	  false }, { "eibrs,retpoline",	SPECTRE_V2_CMD_EIBRS_RETPOLINE,	  false }, { "auto",		SPECTRE_V2_CMD_AUTO,		  false }, { "ibrs",		SPECTRE_V2_CMD_IBRS,              false }, };











static void __init spec_v2_print_cond(const char *reason, bool secure)
{
	if (boot_cpu_has_bug(X86_BUG_SPECTRE_V2) != secure)
		pr_info("%s selected on command line.\n", reason);
}

static enum spectre_v2_mitigation_cmd __init spectre_v2_parse_cmdline(void)
{
	enum spectre_v2_mitigation_cmd cmd = SPECTRE_V2_CMD_AUTO;
	char arg[20];
	int ret, i;

	if (cmdline_find_option_bool(boot_command_line, "nospectre_v2") || cpu_mitigations_off())
		return SPECTRE_V2_CMD_NONE;

	ret = cmdline_find_option(boot_command_line, "spectre_v2", arg, sizeof(arg));
	if (ret < 0)
		return SPECTRE_V2_CMD_AUTO;

	for (i = 0; i < ARRAY_SIZE(mitigation_options); i++) {
		if (!match_option(arg, ret, mitigation_options[i].option))
			continue;
		cmd = mitigation_options[i].cmd;
		break;
	}

	if (i >= ARRAY_SIZE(mitigation_options)) {
		pr_err("unknown option (%s). Switching to AUTO select\n", arg);
		return SPECTRE_V2_CMD_AUTO;
	}

	if ((cmd == SPECTRE_V2_CMD_RETPOLINE || cmd == SPECTRE_V2_CMD_RETPOLINE_LFENCE || cmd == SPECTRE_V2_CMD_RETPOLINE_GENERIC || cmd == SPECTRE_V2_CMD_EIBRS_LFENCE || cmd == SPECTRE_V2_CMD_EIBRS_RETPOLINE) && !IS_ENABLED(CONFIG_RETPOLINE)) {




		pr_err("%s selected but not compiled in. Switching to AUTO select\n", mitigation_options[i].option);
		return SPECTRE_V2_CMD_AUTO;
	}

	if ((cmd == SPECTRE_V2_CMD_EIBRS || cmd == SPECTRE_V2_CMD_EIBRS_LFENCE || cmd == SPECTRE_V2_CMD_EIBRS_RETPOLINE) && !boot_cpu_has(X86_FEATURE_IBRS_ENHANCED)) {


		pr_err("%s selected but CPU doesn't have Enhanced or Automatic IBRS. Switching to AUTO select\n", mitigation_options[i].option);
		return SPECTRE_V2_CMD_AUTO;
	}

	if ((cmd == SPECTRE_V2_CMD_RETPOLINE_LFENCE || cmd == SPECTRE_V2_CMD_EIBRS_LFENCE) && !boot_cpu_has(X86_FEATURE_LFENCE_RDTSC)) {

		pr_err("%s selected, but CPU doesn't have a serializing LFENCE. Switching to AUTO select\n", mitigation_options[i].option);
		return SPECTRE_V2_CMD_AUTO;
	}

	if (cmd == SPECTRE_V2_CMD_IBRS && !IS_ENABLED(CONFIG_CPU_IBRS_ENTRY)) {
		pr_err("%s selected but not compiled in. Switching to AUTO select\n", mitigation_options[i].option);
		return SPECTRE_V2_CMD_AUTO;
	}

	if (cmd == SPECTRE_V2_CMD_IBRS && boot_cpu_data.x86_vendor != X86_VENDOR_INTEL) {
		pr_err("%s selected but not Intel CPU. Switching to AUTO select\n", mitigation_options[i].option);
		return SPECTRE_V2_CMD_AUTO;
	}

	if (cmd == SPECTRE_V2_CMD_IBRS && !boot_cpu_has(X86_FEATURE_IBRS)) {
		pr_err("%s selected but CPU doesn't have IBRS. Switching to AUTO select\n", mitigation_options[i].option);
		return SPECTRE_V2_CMD_AUTO;
	}

	if (cmd == SPECTRE_V2_CMD_IBRS && cpu_feature_enabled(X86_FEATURE_XENPV)) {
		pr_err("%s selected but running as XenPV guest. Switching to AUTO select\n", mitigation_options[i].option);
		return SPECTRE_V2_CMD_AUTO;
	}

	spec_v2_print_cond(mitigation_options[i].option, mitigation_options[i].secure);
	return cmd;
}

static enum spectre_v2_mitigation __init spectre_v2_select_retpoline(void)
{
	if (!IS_ENABLED(CONFIG_RETPOLINE)) {
		pr_err("Kernel not compiled with retpoline; no mitigation available!");
		return SPECTRE_V2_NONE;
	}

	return SPECTRE_V2_RETPOLINE;
}


static void __init spec_ctrl_disable_kernel_rrsba(void)
{
	u64 ia32_cap;

	if (!boot_cpu_has(X86_FEATURE_RRSBA_CTRL))
		return;

	ia32_cap = x86_read_arch_cap_msr();

	if (ia32_cap & ARCH_CAP_RRSBA) {
		x86_spec_ctrl_base |= SPEC_CTRL_RRSBA_DIS_S;
		update_spec_ctrl(x86_spec_ctrl_base);
	}
}

static void __init spectre_v2_determine_rsb_fill_type_at_vmexit(enum spectre_v2_mitigation mode)
{
	
	switch (mode) {
	case SPECTRE_V2_NONE:
		return;

	case SPECTRE_V2_EIBRS_LFENCE:
	case SPECTRE_V2_EIBRS:
		if (boot_cpu_has_bug(X86_BUG_EIBRS_PBRSB)) {
			setup_force_cpu_cap(X86_FEATURE_RSB_VMEXIT_LITE);
			pr_info("Spectre v2 / PBRSB-eIBRS: Retire a single CALL on VMEXIT\n");
		}
		return;

	case SPECTRE_V2_EIBRS_RETPOLINE:
	case SPECTRE_V2_RETPOLINE:
	case SPECTRE_V2_LFENCE:
	case SPECTRE_V2_IBRS:
		setup_force_cpu_cap(X86_FEATURE_RSB_VMEXIT);
		pr_info("Spectre v2 / SpectreRSB : Filling RSB on VMEXIT\n");
		return;
	}

	pr_warn_once("Unknown Spectre v2 mode, disabling RSB mitigation at VM exit");
	dump_stack();
}

static void __init spectre_v2_select_mitigation(void)
{
	enum spectre_v2_mitigation_cmd cmd = spectre_v2_parse_cmdline();
	enum spectre_v2_mitigation mode = SPECTRE_V2_NONE;

	
	if (!boot_cpu_has_bug(X86_BUG_SPECTRE_V2) && (cmd == SPECTRE_V2_CMD_NONE || cmd == SPECTRE_V2_CMD_AUTO))
		return;

	switch (cmd) {
	case SPECTRE_V2_CMD_NONE:
		return;

	case SPECTRE_V2_CMD_FORCE:
	case SPECTRE_V2_CMD_AUTO:
		if (boot_cpu_has(X86_FEATURE_IBRS_ENHANCED)) {
			mode = SPECTRE_V2_EIBRS;
			break;
		}

		if (IS_ENABLED(CONFIG_CPU_IBRS_ENTRY) && boot_cpu_has_bug(X86_BUG_RETBLEED) && retbleed_cmd != RETBLEED_CMD_OFF && retbleed_cmd != RETBLEED_CMD_STUFF && boot_cpu_has(X86_FEATURE_IBRS) && boot_cpu_data.x86_vendor == X86_VENDOR_INTEL) {




			mode = SPECTRE_V2_IBRS;
			break;
		}

		mode = spectre_v2_select_retpoline();
		break;

	case SPECTRE_V2_CMD_RETPOLINE_LFENCE:
		pr_err(SPECTRE_V2_LFENCE_MSG);
		mode = SPECTRE_V2_LFENCE;
		break;

	case SPECTRE_V2_CMD_RETPOLINE_GENERIC:
		mode = SPECTRE_V2_RETPOLINE;
		break;

	case SPECTRE_V2_CMD_RETPOLINE:
		mode = spectre_v2_select_retpoline();
		break;

	case SPECTRE_V2_CMD_IBRS:
		mode = SPECTRE_V2_IBRS;
		break;

	case SPECTRE_V2_CMD_EIBRS:
		mode = SPECTRE_V2_EIBRS;
		break;

	case SPECTRE_V2_CMD_EIBRS_LFENCE:
		mode = SPECTRE_V2_EIBRS_LFENCE;
		break;

	case SPECTRE_V2_CMD_EIBRS_RETPOLINE:
		mode = SPECTRE_V2_EIBRS_RETPOLINE;
		break;
	}

	if (mode == SPECTRE_V2_EIBRS && unprivileged_ebpf_enabled())
		pr_err(SPECTRE_V2_EIBRS_EBPF_MSG);

	if (spectre_v2_in_ibrs_mode(mode)) {
		if (boot_cpu_has(X86_FEATURE_AUTOIBRS)) {
			msr_set_bit(MSR_EFER, _EFER_AUTOIBRS);
		} else {
			x86_spec_ctrl_base |= SPEC_CTRL_IBRS;
			update_spec_ctrl(x86_spec_ctrl_base);
		}
	}

	switch (mode) {
	case SPECTRE_V2_NONE:
	case SPECTRE_V2_EIBRS:
		break;

	case SPECTRE_V2_IBRS:
		setup_force_cpu_cap(X86_FEATURE_KERNEL_IBRS);
		if (boot_cpu_has(X86_FEATURE_IBRS_ENHANCED))
			pr_warn(SPECTRE_V2_IBRS_PERF_MSG);
		break;

	case SPECTRE_V2_LFENCE:
	case SPECTRE_V2_EIBRS_LFENCE:
		setup_force_cpu_cap(X86_FEATURE_RETPOLINE_LFENCE);
		fallthrough;

	case SPECTRE_V2_RETPOLINE:
	case SPECTRE_V2_EIBRS_RETPOLINE:
		setup_force_cpu_cap(X86_FEATURE_RETPOLINE);
		break;
	}

	
	if (mode == SPECTRE_V2_EIBRS_LFENCE || mode == SPECTRE_V2_EIBRS_RETPOLINE || mode == SPECTRE_V2_RETPOLINE)

		spec_ctrl_disable_kernel_rrsba();

	spectre_v2_enabled = mode;
	pr_info("%s\n", spectre_v2_strings[mode]);

	
	setup_force_cpu_cap(X86_FEATURE_RSB_CTXSW);
	pr_info("Spectre v2 / SpectreRSB mitigation: Filling RSB on context switch\n");

	spectre_v2_determine_rsb_fill_type_at_vmexit(mode);

	
	if (boot_cpu_has_bug(X86_BUG_RETBLEED) && boot_cpu_has(X86_FEATURE_IBPB) && (boot_cpu_data.x86_vendor == X86_VENDOR_AMD || boot_cpu_data.x86_vendor == X86_VENDOR_HYGON)) {



		if (retbleed_cmd != RETBLEED_CMD_IBPB) {
			setup_force_cpu_cap(X86_FEATURE_USE_IBPB_FW);
			pr_info("Enabling Speculation Barrier for firmware calls\n");
		}

	} else if (boot_cpu_has(X86_FEATURE_IBRS) && !spectre_v2_in_ibrs_mode(mode)) {
		setup_force_cpu_cap(X86_FEATURE_USE_IBRS_FW);
		pr_info("Enabling Restricted Speculation for firmware calls\n");
	}

	
	spectre_v2_cmd = cmd;
}

static void update_stibp_msr(void * __unused)
{
	u64 val = spec_ctrl_current() | (x86_spec_ctrl_base & SPEC_CTRL_STIBP);
	update_spec_ctrl(val);
}


static void update_stibp_strict(void)
{
	u64 mask = x86_spec_ctrl_base & ~SPEC_CTRL_STIBP;

	if (sched_smt_active())
		mask |= SPEC_CTRL_STIBP;

	if (mask == x86_spec_ctrl_base)
		return;

	pr_info("Update user space SMT mitigation: STIBP %s\n", mask & SPEC_CTRL_STIBP ? "always-on" : "off");
	x86_spec_ctrl_base = mask;
	on_each_cpu(update_stibp_msr, NULL, 1);
}


static void update_indir_branch_cond(void)
{
	if (sched_smt_active())
		static_branch_enable(&switch_to_cond_stibp);
	else static_branch_disable(&switch_to_cond_stibp);
}





static void update_mds_branch_idle(void)
{
	u64 ia32_cap = x86_read_arch_cap_msr();

	
	if (!boot_cpu_has_bug(X86_BUG_MSBDS_ONLY))
		return;

	if (sched_smt_active()) {
		static_branch_enable(&mds_idle_clear);
	} else if (mmio_mitigation == MMIO_MITIGATION_OFF || (ia32_cap & ARCH_CAP_FBSDP_NO)) {
		static_branch_disable(&mds_idle_clear);
	}
}





void cpu_bugs_smt_update(void)
{
	mutex_lock(&spec_ctrl_mutex);

	if (sched_smt_active() && unprivileged_ebpf_enabled() && spectre_v2_enabled == SPECTRE_V2_EIBRS_LFENCE)
		pr_warn_once(SPECTRE_V2_EIBRS_LFENCE_EBPF_SMT_MSG);

	switch (spectre_v2_user_stibp) {
	case SPECTRE_V2_USER_NONE:
		break;
	case SPECTRE_V2_USER_STRICT:
	case SPECTRE_V2_USER_STRICT_PREFERRED:
		update_stibp_strict();
		break;
	case SPECTRE_V2_USER_PRCTL:
	case SPECTRE_V2_USER_SECCOMP:
		update_indir_branch_cond();
		break;
	}

	switch (mds_mitigation) {
	case MDS_MITIGATION_FULL:
	case MDS_MITIGATION_VMWERV:
		if (sched_smt_active() && !boot_cpu_has(X86_BUG_MSBDS_ONLY))
			pr_warn_once(MDS_MSG_SMT);
		update_mds_branch_idle();
		break;
	case MDS_MITIGATION_OFF:
		break;
	}

	switch (taa_mitigation) {
	case TAA_MITIGATION_VERW:
	case TAA_MITIGATION_UCODE_NEEDED:
		if (sched_smt_active())
			pr_warn_once(TAA_MSG_SMT);
		break;
	case TAA_MITIGATION_TSX_DISABLED:
	case TAA_MITIGATION_OFF:
		break;
	}

	switch (mmio_mitigation) {
	case MMIO_MITIGATION_VERW:
	case MMIO_MITIGATION_UCODE_NEEDED:
		if (sched_smt_active())
			pr_warn_once(MMIO_MSG_SMT);
		break;
	case MMIO_MITIGATION_OFF:
		break;
	}

	mutex_unlock(&spec_ctrl_mutex);
}




static enum ssb_mitigation ssb_mode __ro_after_init = SPEC_STORE_BYPASS_NONE;


enum ssb_mitigation_cmd {
	SPEC_STORE_BYPASS_CMD_NONE, SPEC_STORE_BYPASS_CMD_AUTO, SPEC_STORE_BYPASS_CMD_ON, SPEC_STORE_BYPASS_CMD_PRCTL, SPEC_STORE_BYPASS_CMD_SECCOMP, };





static const char * const ssb_strings[] = {
	[SPEC_STORE_BYPASS_NONE]	= "Vulnerable", [SPEC_STORE_BYPASS_DISABLE]	= "Mitigation: Speculative Store Bypass disabled", [SPEC_STORE_BYPASS_PRCTL]	= "Mitigation: Speculative Store Bypass disabled via prctl", [SPEC_STORE_BYPASS_SECCOMP]	= "Mitigation: Speculative Store Bypass disabled via prctl and seccomp", };




static const struct {
	const char *option;
	enum ssb_mitigation_cmd cmd;
} ssb_mitigation_options[]  __initconst = {
	{ "auto",	SPEC_STORE_BYPASS_CMD_AUTO },     { "on",		SPEC_STORE_BYPASS_CMD_ON }, { "off",	SPEC_STORE_BYPASS_CMD_NONE }, { "prctl",	SPEC_STORE_BYPASS_CMD_PRCTL }, { "seccomp",	SPEC_STORE_BYPASS_CMD_SECCOMP }, };





static enum ssb_mitigation_cmd __init ssb_parse_cmdline(void)
{
	enum ssb_mitigation_cmd cmd = SPEC_STORE_BYPASS_CMD_AUTO;
	char arg[20];
	int ret, i;

	if (cmdline_find_option_bool(boot_command_line, "nospec_store_bypass_disable") || cpu_mitigations_off()) {
		return SPEC_STORE_BYPASS_CMD_NONE;
	} else {
		ret = cmdline_find_option(boot_command_line, "spec_store_bypass_disable", arg, sizeof(arg));
		if (ret < 0)
			return SPEC_STORE_BYPASS_CMD_AUTO;

		for (i = 0; i < ARRAY_SIZE(ssb_mitigation_options); i++) {
			if (!match_option(arg, ret, ssb_mitigation_options[i].option))
				continue;

			cmd = ssb_mitigation_options[i].cmd;
			break;
		}

		if (i >= ARRAY_SIZE(ssb_mitigation_options)) {
			pr_err("unknown option (%s). Switching to AUTO select\n", arg);
			return SPEC_STORE_BYPASS_CMD_AUTO;
		}
	}

	return cmd;
}

static enum ssb_mitigation __init __ssb_select_mitigation(void)
{
	enum ssb_mitigation mode = SPEC_STORE_BYPASS_NONE;
	enum ssb_mitigation_cmd cmd;

	if (!boot_cpu_has(X86_FEATURE_SSBD))
		return mode;

	cmd = ssb_parse_cmdline();
	if (!boot_cpu_has_bug(X86_BUG_SPEC_STORE_BYPASS) && (cmd == SPEC_STORE_BYPASS_CMD_NONE || cmd == SPEC_STORE_BYPASS_CMD_AUTO))

		return mode;

	switch (cmd) {
	case SPEC_STORE_BYPASS_CMD_SECCOMP:
		
		if (IS_ENABLED(CONFIG_SECCOMP))
			mode = SPEC_STORE_BYPASS_SECCOMP;
		else mode = SPEC_STORE_BYPASS_PRCTL;
		break;
	case SPEC_STORE_BYPASS_CMD_ON:
		mode = SPEC_STORE_BYPASS_DISABLE;
		break;
	case SPEC_STORE_BYPASS_CMD_AUTO:
	case SPEC_STORE_BYPASS_CMD_PRCTL:
		mode = SPEC_STORE_BYPASS_PRCTL;
		break;
	case SPEC_STORE_BYPASS_CMD_NONE:
		break;
	}

	
	if (mode == SPEC_STORE_BYPASS_DISABLE) {
		setup_force_cpu_cap(X86_FEATURE_SPEC_STORE_BYPASS_DISABLE);
		
		if (!static_cpu_has(X86_FEATURE_SPEC_CTRL_SSBD) && !static_cpu_has(X86_FEATURE_AMD_SSBD)) {
			x86_amd_ssb_disable();
		} else {
			x86_spec_ctrl_base |= SPEC_CTRL_SSBD;
			update_spec_ctrl(x86_spec_ctrl_base);
		}
	}

	return mode;
}

static void ssb_select_mitigation(void)
{
	ssb_mode = __ssb_select_mitigation();

	if (boot_cpu_has_bug(X86_BUG_SPEC_STORE_BYPASS))
		pr_info("%s\n", ssb_strings[ssb_mode]);
}




static void task_update_spec_tif(struct task_struct *tsk)
{
	
	set_tsk_thread_flag(tsk, TIF_SPEC_FORCE_UPDATE);

	
	if (tsk == current)
		speculation_ctrl_update_current();
}

static int l1d_flush_prctl_set(struct task_struct *task, unsigned long ctrl)
{

	if (!static_branch_unlikely(&switch_mm_cond_l1d_flush))
		return -EPERM;

	switch (ctrl) {
	case PR_SPEC_ENABLE:
		set_ti_thread_flag(&task->thread_info, TIF_SPEC_L1D_FLUSH);
		return 0;
	case PR_SPEC_DISABLE:
		clear_ti_thread_flag(&task->thread_info, TIF_SPEC_L1D_FLUSH);
		return 0;
	default:
		return -ERANGE;
	}
}

static int ssb_prctl_set(struct task_struct *task, unsigned long ctrl)
{
	if (ssb_mode != SPEC_STORE_BYPASS_PRCTL && ssb_mode != SPEC_STORE_BYPASS_SECCOMP)
		return -ENXIO;

	switch (ctrl) {
	case PR_SPEC_ENABLE:
		
		if (task_spec_ssb_force_disable(task))
			return -EPERM;
		task_clear_spec_ssb_disable(task);
		task_clear_spec_ssb_noexec(task);
		task_update_spec_tif(task);
		break;
	case PR_SPEC_DISABLE:
		task_set_spec_ssb_disable(task);
		task_clear_spec_ssb_noexec(task);
		task_update_spec_tif(task);
		break;
	case PR_SPEC_FORCE_DISABLE:
		task_set_spec_ssb_disable(task);
		task_set_spec_ssb_force_disable(task);
		task_clear_spec_ssb_noexec(task);
		task_update_spec_tif(task);
		break;
	case PR_SPEC_DISABLE_NOEXEC:
		if (task_spec_ssb_force_disable(task))
			return -EPERM;
		task_set_spec_ssb_disable(task);
		task_set_spec_ssb_noexec(task);
		task_update_spec_tif(task);
		break;
	default:
		return -ERANGE;
	}
	return 0;
}

static bool is_spec_ib_user_controlled(void)
{
	return spectre_v2_user_ibpb == SPECTRE_V2_USER_PRCTL || spectre_v2_user_ibpb == SPECTRE_V2_USER_SECCOMP || spectre_v2_user_stibp == SPECTRE_V2_USER_PRCTL || spectre_v2_user_stibp == SPECTRE_V2_USER_SECCOMP;


}

static int ib_prctl_set(struct task_struct *task, unsigned long ctrl)
{
	switch (ctrl) {
	case PR_SPEC_ENABLE:
		if (spectre_v2_user_ibpb == SPECTRE_V2_USER_NONE && spectre_v2_user_stibp == SPECTRE_V2_USER_NONE)
			return 0;

		
		if (!is_spec_ib_user_controlled() || task_spec_ib_force_disable(task))
			return -EPERM;

		task_clear_spec_ib_disable(task);
		task_update_spec_tif(task);
		break;
	case PR_SPEC_DISABLE:
	case PR_SPEC_FORCE_DISABLE:
		
		if (spectre_v2_user_ibpb == SPECTRE_V2_USER_NONE && spectre_v2_user_stibp == SPECTRE_V2_USER_NONE)
			return -EPERM;

		if (!is_spec_ib_user_controlled())
			return 0;

		task_set_spec_ib_disable(task);
		if (ctrl == PR_SPEC_FORCE_DISABLE)
			task_set_spec_ib_force_disable(task);
		task_update_spec_tif(task);
		if (task == current)
			indirect_branch_prediction_barrier();
		break;
	default:
		return -ERANGE;
	}
	return 0;
}

int arch_prctl_spec_ctrl_set(struct task_struct *task, unsigned long which, unsigned long ctrl)
{
	switch (which) {
	case PR_SPEC_STORE_BYPASS:
		return ssb_prctl_set(task, ctrl);
	case PR_SPEC_INDIRECT_BRANCH:
		return ib_prctl_set(task, ctrl);
	case PR_SPEC_L1D_FLUSH:
		return l1d_flush_prctl_set(task, ctrl);
	default:
		return -ENODEV;
	}
}


void arch_seccomp_spec_mitigate(struct task_struct *task)
{
	if (ssb_mode == SPEC_STORE_BYPASS_SECCOMP)
		ssb_prctl_set(task, PR_SPEC_FORCE_DISABLE);
	if (spectre_v2_user_ibpb == SPECTRE_V2_USER_SECCOMP || spectre_v2_user_stibp == SPECTRE_V2_USER_SECCOMP)
		ib_prctl_set(task, PR_SPEC_FORCE_DISABLE);
}


static int l1d_flush_prctl_get(struct task_struct *task)
{
	if (!static_branch_unlikely(&switch_mm_cond_l1d_flush))
		return PR_SPEC_FORCE_DISABLE;

	if (test_ti_thread_flag(&task->thread_info, TIF_SPEC_L1D_FLUSH))
		return PR_SPEC_PRCTL | PR_SPEC_ENABLE;
	else return PR_SPEC_PRCTL | PR_SPEC_DISABLE;
}

static int ssb_prctl_get(struct task_struct *task)
{
	switch (ssb_mode) {
	case SPEC_STORE_BYPASS_DISABLE:
		return PR_SPEC_DISABLE;
	case SPEC_STORE_BYPASS_SECCOMP:
	case SPEC_STORE_BYPASS_PRCTL:
		if (task_spec_ssb_force_disable(task))
			return PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE;
		if (task_spec_ssb_noexec(task))
			return PR_SPEC_PRCTL | PR_SPEC_DISABLE_NOEXEC;
		if (task_spec_ssb_disable(task))
			return PR_SPEC_PRCTL | PR_SPEC_DISABLE;
		return PR_SPEC_PRCTL | PR_SPEC_ENABLE;
	default:
		if (boot_cpu_has_bug(X86_BUG_SPEC_STORE_BYPASS))
			return PR_SPEC_ENABLE;
		return PR_SPEC_NOT_AFFECTED;
	}
}

static int ib_prctl_get(struct task_struct *task)
{
	if (!boot_cpu_has_bug(X86_BUG_SPECTRE_V2))
		return PR_SPEC_NOT_AFFECTED;

	if (spectre_v2_user_ibpb == SPECTRE_V2_USER_NONE && spectre_v2_user_stibp == SPECTRE_V2_USER_NONE)
		return PR_SPEC_ENABLE;
	else if (is_spec_ib_user_controlled()) {
		if (task_spec_ib_force_disable(task))
			return PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE;
		if (task_spec_ib_disable(task))
			return PR_SPEC_PRCTL | PR_SPEC_DISABLE;
		return PR_SPEC_PRCTL | PR_SPEC_ENABLE;
	} else if (spectre_v2_user_ibpb == SPECTRE_V2_USER_STRICT || spectre_v2_user_stibp == SPECTRE_V2_USER_STRICT || spectre_v2_user_stibp == SPECTRE_V2_USER_STRICT_PREFERRED)

		return PR_SPEC_DISABLE;
	else return PR_SPEC_NOT_AFFECTED;
}

int arch_prctl_spec_ctrl_get(struct task_struct *task, unsigned long which)
{
	switch (which) {
	case PR_SPEC_STORE_BYPASS:
		return ssb_prctl_get(task);
	case PR_SPEC_INDIRECT_BRANCH:
		return ib_prctl_get(task);
	case PR_SPEC_L1D_FLUSH:
		return l1d_flush_prctl_get(task);
	default:
		return -ENODEV;
	}
}

void x86_spec_ctrl_setup_ap(void)
{
	if (boot_cpu_has(X86_FEATURE_MSR_SPEC_CTRL))
		update_spec_ctrl(x86_spec_ctrl_base);

	if (ssb_mode == SPEC_STORE_BYPASS_DISABLE)
		x86_amd_ssb_disable();
}

bool itlb_multihit_kvm_mitigation;
EXPORT_SYMBOL_GPL(itlb_multihit_kvm_mitigation);





enum l1tf_mitigations l1tf_mitigation __ro_after_init = L1TF_MITIGATION_FLUSH;

EXPORT_SYMBOL_GPL(l1tf_mitigation);

enum vmx_l1d_flush_state l1tf_vmx_mitigation = VMENTER_L1D_FLUSH_AUTO;
EXPORT_SYMBOL_GPL(l1tf_vmx_mitigation);


static void override_cache_bits(struct cpuinfo_x86 *c)
{
	if (c->x86 != 6)
		return;

	switch (c->x86_model) {
	case INTEL_FAM6_NEHALEM:
	case INTEL_FAM6_WESTMERE:
	case INTEL_FAM6_SANDYBRIDGE:
	case INTEL_FAM6_IVYBRIDGE:
	case INTEL_FAM6_HASWELL:
	case INTEL_FAM6_HASWELL_L:
	case INTEL_FAM6_HASWELL_G:
	case INTEL_FAM6_BROADWELL:
	case INTEL_FAM6_BROADWELL_G:
	case INTEL_FAM6_SKYLAKE_L:
	case INTEL_FAM6_SKYLAKE:
	case INTEL_FAM6_KABYLAKE_L:
	case INTEL_FAM6_KABYLAKE:
		if (c->x86_cache_bits < 44)
			c->x86_cache_bits = 44;
		break;
	}
}

static void __init l1tf_select_mitigation(void)
{
	u64 half_pa;

	if (!boot_cpu_has_bug(X86_BUG_L1TF))
		return;

	if (cpu_mitigations_off())
		l1tf_mitigation = L1TF_MITIGATION_OFF;
	else if (cpu_mitigations_auto_nosmt())
		l1tf_mitigation = L1TF_MITIGATION_FLUSH_NOSMT;

	override_cache_bits(&boot_cpu_data);

	switch (l1tf_mitigation) {
	case L1TF_MITIGATION_OFF:
	case L1TF_MITIGATION_FLUSH_NOWARN:
	case L1TF_MITIGATION_FLUSH:
		break;
	case L1TF_MITIGATION_FLUSH_NOSMT:
	case L1TF_MITIGATION_FULL:
		cpu_smt_disable(false);
		break;
	case L1TF_MITIGATION_FULL_FORCE:
		cpu_smt_disable(true);
		break;
	}


	pr_warn("Kernel not compiled for PAE. No mitigation for L1TF\n");
	return;


	half_pa = (u64)l1tf_pfn_limit() << PAGE_SHIFT;
	if (l1tf_mitigation != L1TF_MITIGATION_OFF && e820__mapped_any(half_pa, ULLONG_MAX - half_pa, E820_TYPE_RAM)) {
		pr_warn("System has more than MAX_PA/2 memory. L1TF mitigation not effective.\n");
		pr_info("You may make it effective by booting the kernel with mem=%llu parameter.\n", half_pa);
		pr_info("However, doing so will make a part of your RAM unusable.\n");
		pr_info("Reading https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/l1tf.html might help you decide.\n");
		return;
	}

	setup_force_cpu_cap(X86_FEATURE_L1TF_PTEINV);
}

static int __init l1tf_cmdline(char *str)
{
	if (!boot_cpu_has_bug(X86_BUG_L1TF))
		return 0;

	if (!str)
		return -EINVAL;

	if (!strcmp(str, "off"))
		l1tf_mitigation = L1TF_MITIGATION_OFF;
	else if (!strcmp(str, "flush,nowarn"))
		l1tf_mitigation = L1TF_MITIGATION_FLUSH_NOWARN;
	else if (!strcmp(str, "flush"))
		l1tf_mitigation = L1TF_MITIGATION_FLUSH;
	else if (!strcmp(str, "flush,nosmt"))
		l1tf_mitigation = L1TF_MITIGATION_FLUSH_NOSMT;
	else if (!strcmp(str, "full"))
		l1tf_mitigation = L1TF_MITIGATION_FULL;
	else if (!strcmp(str, "full,force"))
		l1tf_mitigation = L1TF_MITIGATION_FULL_FORCE;

	return 0;
}
early_param("l1tf", l1tf_cmdline);









static const char * const l1tf_vmx_states[] = {
	[VMENTER_L1D_FLUSH_AUTO]		= "auto", [VMENTER_L1D_FLUSH_NEVER]		= "vulnerable", [VMENTER_L1D_FLUSH_COND]		= "conditional cache flushes", [VMENTER_L1D_FLUSH_ALWAYS]		= "cache flushes", [VMENTER_L1D_FLUSH_EPT_DISABLED]	= "EPT disabled", [VMENTER_L1D_FLUSH_NOT_REQUIRED]	= "flush not necessary" };






static ssize_t l1tf_show_state(char *buf)
{
	if (l1tf_vmx_mitigation == VMENTER_L1D_FLUSH_AUTO)
		return sysfs_emit(buf, "%s\n", L1TF_DEFAULT_MSG);

	if (l1tf_vmx_mitigation == VMENTER_L1D_FLUSH_EPT_DISABLED || (l1tf_vmx_mitigation == VMENTER_L1D_FLUSH_NEVER && sched_smt_active())) {

		return sysfs_emit(buf, "%s; VMX: %s\n", L1TF_DEFAULT_MSG, l1tf_vmx_states[l1tf_vmx_mitigation]);
	}

	return sysfs_emit(buf, "%s; VMX: %s, SMT %s\n", L1TF_DEFAULT_MSG, l1tf_vmx_states[l1tf_vmx_mitigation], sched_smt_active() ? "vulnerable" : "disabled");

}

static ssize_t itlb_multihit_show_state(char *buf)
{
	if (!boot_cpu_has(X86_FEATURE_MSR_IA32_FEAT_CTL) || !boot_cpu_has(X86_FEATURE_VMX))
		return sysfs_emit(buf, "KVM: Mitigation: VMX unsupported\n");
	else if (!(cr4_read_shadow() & X86_CR4_VMXE))
		return sysfs_emit(buf, "KVM: Mitigation: VMX disabled\n");
	else if (itlb_multihit_kvm_mitigation)
		return sysfs_emit(buf, "KVM: Mitigation: Split huge pages\n");
	else return sysfs_emit(buf, "KVM: Vulnerable\n");
}

static ssize_t l1tf_show_state(char *buf)
{
	return sysfs_emit(buf, "%s\n", L1TF_DEFAULT_MSG);
}

static ssize_t itlb_multihit_show_state(char *buf)
{
	return sysfs_emit(buf, "Processor vulnerable\n");
}


static ssize_t mds_show_state(char *buf)
{
	if (boot_cpu_has(X86_FEATURE_HYPERVISOR)) {
		return sysfs_emit(buf, "%s; SMT Host state unknown\n", mds_strings[mds_mitigation]);
	}

	if (boot_cpu_has(X86_BUG_MSBDS_ONLY)) {
		return sysfs_emit(buf, "%s; SMT %s\n", mds_strings[mds_mitigation], (mds_mitigation == MDS_MITIGATION_OFF ? "vulnerable" :
				   sched_smt_active() ? "mitigated" : "disabled"));
	}

	return sysfs_emit(buf, "%s; SMT %s\n", mds_strings[mds_mitigation], sched_smt_active() ? "vulnerable" : "disabled");
}

static ssize_t tsx_async_abort_show_state(char *buf)
{
	if ((taa_mitigation == TAA_MITIGATION_TSX_DISABLED) || (taa_mitigation == TAA_MITIGATION_OFF))
		return sysfs_emit(buf, "%s\n", taa_strings[taa_mitigation]);

	if (boot_cpu_has(X86_FEATURE_HYPERVISOR)) {
		return sysfs_emit(buf, "%s; SMT Host state unknown\n", taa_strings[taa_mitigation]);
	}

	return sysfs_emit(buf, "%s; SMT %s\n", taa_strings[taa_mitigation], sched_smt_active() ? "vulnerable" : "disabled");
}

static ssize_t mmio_stale_data_show_state(char *buf)
{
	if (boot_cpu_has_bug(X86_BUG_MMIO_UNKNOWN))
		return sysfs_emit(buf, "Unknown: No mitigations\n");

	if (mmio_mitigation == MMIO_MITIGATION_OFF)
		return sysfs_emit(buf, "%s\n", mmio_strings[mmio_mitigation]);

	if (boot_cpu_has(X86_FEATURE_HYPERVISOR)) {
		return sysfs_emit(buf, "%s; SMT Host state unknown\n", mmio_strings[mmio_mitigation]);
	}

	return sysfs_emit(buf, "%s; SMT %s\n", mmio_strings[mmio_mitigation], sched_smt_active() ? "vulnerable" : "disabled");
}

static char *stibp_state(void)
{
	if (spectre_v2_in_ibrs_mode(spectre_v2_enabled))
		return "";

	switch (spectre_v2_user_stibp) {
	case SPECTRE_V2_USER_NONE:
		return ", STIBP: disabled";
	case SPECTRE_V2_USER_STRICT:
		return ", STIBP: forced";
	case SPECTRE_V2_USER_STRICT_PREFERRED:
		return ", STIBP: always-on";
	case SPECTRE_V2_USER_PRCTL:
	case SPECTRE_V2_USER_SECCOMP:
		if (static_key_enabled(&switch_to_cond_stibp))
			return ", STIBP: conditional";
	}
	return "";
}

static char *ibpb_state(void)
{
	if (boot_cpu_has(X86_FEATURE_IBPB)) {
		if (static_key_enabled(&switch_mm_always_ibpb))
			return ", IBPB: always-on";
		if (static_key_enabled(&switch_mm_cond_ibpb))
			return ", IBPB: conditional";
		return ", IBPB: disabled";
	}
	return "";
}

static char *pbrsb_eibrs_state(void)
{
	if (boot_cpu_has_bug(X86_BUG_EIBRS_PBRSB)) {
		if (boot_cpu_has(X86_FEATURE_RSB_VMEXIT_LITE) || boot_cpu_has(X86_FEATURE_RSB_VMEXIT))
			return ", PBRSB-eIBRS: SW sequence";
		else return ", PBRSB-eIBRS: Vulnerable";
	} else {
		return ", PBRSB-eIBRS: Not affected";
	}
}

static ssize_t spectre_v2_show_state(char *buf)
{
	if (spectre_v2_enabled == SPECTRE_V2_LFENCE)
		return sysfs_emit(buf, "Vulnerable: LFENCE\n");

	if (spectre_v2_enabled == SPECTRE_V2_EIBRS && unprivileged_ebpf_enabled())
		return sysfs_emit(buf, "Vulnerable: eIBRS with unprivileged eBPF\n");

	if (sched_smt_active() && unprivileged_ebpf_enabled() && spectre_v2_enabled == SPECTRE_V2_EIBRS_LFENCE)
		return sysfs_emit(buf, "Vulnerable: eIBRS+LFENCE with unprivileged eBPF and SMT\n");

	return sysfs_emit(buf, "%s%s%s%s%s%s%s\n", spectre_v2_strings[spectre_v2_enabled], ibpb_state(), boot_cpu_has(X86_FEATURE_USE_IBRS_FW) ? ", IBRS_FW" : "", stibp_state(), boot_cpu_has(X86_FEATURE_RSB_CTXSW) ? ", RSB filling" : "", pbrsb_eibrs_state(), spectre_v2_module_string());






}

static ssize_t srbds_show_state(char *buf)
{
	return sysfs_emit(buf, "%s\n", srbds_strings[srbds_mitigation]);
}

static ssize_t retbleed_show_state(char *buf)
{
	if (retbleed_mitigation == RETBLEED_MITIGATION_UNRET || retbleed_mitigation == RETBLEED_MITIGATION_IBPB) {
		if (boot_cpu_data.x86_vendor != X86_VENDOR_AMD && boot_cpu_data.x86_vendor != X86_VENDOR_HYGON)
			return sysfs_emit(buf, "Vulnerable: untrained return thunk / IBPB on non-AMD based uarch\n");

		return sysfs_emit(buf, "%s; SMT %s\n", retbleed_strings[retbleed_mitigation], !sched_smt_active() ? "disabled" :
				  spectre_v2_user_stibp == SPECTRE_V2_USER_STRICT || spectre_v2_user_stibp == SPECTRE_V2_USER_STRICT_PREFERRED ? "enabled with STIBP protection" : "vulnerable");

	}

	return sysfs_emit(buf, "%s\n", retbleed_strings[retbleed_mitigation]);
}

static ssize_t cpu_show_common(struct device *dev, struct device_attribute *attr, char *buf, unsigned int bug)
{
	if (!boot_cpu_has_bug(bug))
		return sysfs_emit(buf, "Not affected\n");

	switch (bug) {
	case X86_BUG_CPU_MELTDOWN:
		if (boot_cpu_has(X86_FEATURE_PTI))
			return sysfs_emit(buf, "Mitigation: PTI\n");

		if (hypervisor_is_type(X86_HYPER_XEN_PV))
			return sysfs_emit(buf, "Unknown (XEN PV detected, hypervisor mitigation required)\n");

		break;

	case X86_BUG_SPECTRE_V1:
		return sysfs_emit(buf, "%s\n", spectre_v1_strings[spectre_v1_mitigation]);

	case X86_BUG_SPECTRE_V2:
		return spectre_v2_show_state(buf);

	case X86_BUG_SPEC_STORE_BYPASS:
		return sysfs_emit(buf, "%s\n", ssb_strings[ssb_mode]);

	case X86_BUG_L1TF:
		if (boot_cpu_has(X86_FEATURE_L1TF_PTEINV))
			return l1tf_show_state(buf);
		break;

	case X86_BUG_MDS:
		return mds_show_state(buf);

	case X86_BUG_TAA:
		return tsx_async_abort_show_state(buf);

	case X86_BUG_ITLB_MULTIHIT:
		return itlb_multihit_show_state(buf);

	case X86_BUG_SRBDS:
		return srbds_show_state(buf);

	case X86_BUG_MMIO_STALE_DATA:
	case X86_BUG_MMIO_UNKNOWN:
		return mmio_stale_data_show_state(buf);

	case X86_BUG_RETBLEED:
		return retbleed_show_state(buf);

	default:
		break;
	}

	return sysfs_emit(buf, "Vulnerable\n");
}

ssize_t cpu_show_meltdown(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_CPU_MELTDOWN);
}

ssize_t cpu_show_spectre_v1(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_SPECTRE_V1);
}

ssize_t cpu_show_spectre_v2(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_SPECTRE_V2);
}

ssize_t cpu_show_spec_store_bypass(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_SPEC_STORE_BYPASS);
}

ssize_t cpu_show_l1tf(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_L1TF);
}

ssize_t cpu_show_mds(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_MDS);
}

ssize_t cpu_show_tsx_async_abort(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_TAA);
}

ssize_t cpu_show_itlb_multihit(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_ITLB_MULTIHIT);
}

ssize_t cpu_show_srbds(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_SRBDS);
}

ssize_t cpu_show_mmio_stale_data(struct device *dev, struct device_attribute *attr, char *buf)
{
	if (boot_cpu_has_bug(X86_BUG_MMIO_UNKNOWN))
		return cpu_show_common(dev, attr, buf, X86_BUG_MMIO_UNKNOWN);
	else return cpu_show_common(dev, attr, buf, X86_BUG_MMIO_STALE_DATA);
}

ssize_t cpu_show_retbleed(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_RETBLEED);
}

