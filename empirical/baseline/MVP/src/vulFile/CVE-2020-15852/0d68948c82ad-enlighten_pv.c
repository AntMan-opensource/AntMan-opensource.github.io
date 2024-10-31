

















































































void *xen_initial_gdt;

static int xen_cpu_up_prepare_pv(unsigned int cpu);
static int xen_cpu_dead_pv(unsigned int cpu);

struct tls_descs {
	struct desc_struct desc[3];
};


static DEFINE_PER_CPU(struct tls_descs, shadow_tls_desc);

static void __init xen_banner(void)
{
	unsigned version = HYPERVISOR_xen_version(XENVER_version, NULL);
	struct xen_extraversion extra;
	HYPERVISOR_xen_version(XENVER_extraversion, &extra);

	pr_info("Booting paravirtualized kernel on %s\n", pv_info.name);
	printk(KERN_INFO "Xen version: %d.%d%s%s\n", version >> 16, version & 0xffff, extra.extraversion, xen_feature(XENFEAT_mmu_pt_update_preserve_ad) ? " (preserve-AD)" : "");



	pr_warn("WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING!\n" "Support for running as 32-bit PV-guest under Xen will soon be removed\n" "from the Linux kernel!\n" "Please use either a 64-bit kernel or switch to HVM or PVH mode!\n" "WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING!\n");




}

static void __init xen_pv_init_platform(void)
{
	populate_extra_pte(fix_to_virt(FIX_PARAVIRT_BOOTMAP));

	set_fixmap(FIX_PARAVIRT_BOOTMAP, xen_start_info->shared_info);
	HYPERVISOR_shared_info = (void *)fix_to_virt(FIX_PARAVIRT_BOOTMAP);

	
	xen_vcpu_info_reset(0);

	
	xen_init_time_ops();
}

static void __init xen_pv_guest_late_init(void)
{

	
	xen_setup_vcpu_info_placement();

}


bool xen_running_on_version_or_later(unsigned int major, unsigned int minor)
{
	unsigned int version;

	if (!xen_domain())
		return false;

	version = HYPERVISOR_xen_version(XENVER_version, NULL);
	if ((((version >> 16) == major) && ((version & 0xffff) >= minor)) || ((version >> 16) > major))
		return true;
	return false;
}

static __read_mostly unsigned int cpuid_leaf5_ecx_val;
static __read_mostly unsigned int cpuid_leaf5_edx_val;

static void xen_cpuid(unsigned int *ax, unsigned int *bx, unsigned int *cx, unsigned int *dx)
{
	unsigned maskebx = ~0;

	
	switch (*ax) {
	case CPUID_MWAIT_LEAF:
		
		*ax = 0;
		*bx = 0;
		*cx = cpuid_leaf5_ecx_val;
		*dx = cpuid_leaf5_edx_val;
		return;

	case 0xb:
		
		maskebx = 0;
		break;
	}

	asm(XEN_EMULATE_PREFIX "cpuid" : "=a" (*ax), "=b" (*bx), "=c" (*cx), "=d" (*dx)



		: "0" (*ax), "2" (*cx));

	*bx &= maskebx;
}
STACK_FRAME_NON_STANDARD(xen_cpuid); 

static bool __init xen_check_mwait(void)
{

	struct xen_platform_op op = {
		.cmd			= XENPF_set_processor_pminfo, .u.set_pminfo.id	= -1, .u.set_pminfo.type	= XEN_PM_PDC, };


	uint32_t buf[3];
	unsigned int ax, bx, cx, dx;
	unsigned int mwait_mask;

	
	if (!xen_initial_domain())
		return false;

	
	if (!xen_running_on_version_or_later(4, 2))
		return false;

	ax = 1;
	cx = 0;

	native_cpuid(&ax, &bx, &cx, &dx);

	mwait_mask = (1 << (X86_FEATURE_EST % 32)) | (1 << (X86_FEATURE_MWAIT % 32));

	if ((cx & mwait_mask) != mwait_mask)
		return false;

	

	ax = CPUID_MWAIT_LEAF;
	bx = 0;
	cx = 0;
	dx = 0;

	native_cpuid(&ax, &bx, &cx, &dx);

	
	buf[0] = ACPI_PDC_REVISION_ID;
	buf[1] = 1;
	buf[2] = (ACPI_PDC_C_CAPABILITY_SMP | ACPI_PDC_EST_CAPABILITY_SWSMP);

	set_xen_guest_handle(op.u.set_pminfo.pdc, buf);

	if ((HYPERVISOR_platform_op(&op) == 0) && (buf[2] & (ACPI_PDC_C_C1_FFH | ACPI_PDC_C_C2C3_FFH))) {
		cpuid_leaf5_ecx_val = cx;
		cpuid_leaf5_edx_val = dx;
	}
	return true;

	return false;

}

static bool __init xen_check_xsave(void)
{
	unsigned int cx, xsave_mask;

	cx = cpuid_ecx(1);

	xsave_mask = (1 << (X86_FEATURE_XSAVE % 32)) | (1 << (X86_FEATURE_OSXSAVE % 32));

	
	return (cx & xsave_mask) == xsave_mask;
}

static void __init xen_init_capabilities(void)
{
	setup_force_cpu_cap(X86_FEATURE_XENPV);
	setup_clear_cpu_cap(X86_FEATURE_DCA);
	setup_clear_cpu_cap(X86_FEATURE_APERFMPERF);
	setup_clear_cpu_cap(X86_FEATURE_MTRR);
	setup_clear_cpu_cap(X86_FEATURE_ACC);
	setup_clear_cpu_cap(X86_FEATURE_X2APIC);
	setup_clear_cpu_cap(X86_FEATURE_SME);

	
	setup_clear_cpu_cap(X86_FEATURE_PCID);

	if (!xen_initial_domain())
		setup_clear_cpu_cap(X86_FEATURE_ACPI);

	if (xen_check_mwait())
		setup_force_cpu_cap(X86_FEATURE_MWAIT);
	else setup_clear_cpu_cap(X86_FEATURE_MWAIT);

	if (!xen_check_xsave()) {
		setup_clear_cpu_cap(X86_FEATURE_XSAVE);
		setup_clear_cpu_cap(X86_FEATURE_OSXSAVE);
	}
}

static void xen_set_debugreg(int reg, unsigned long val)
{
	HYPERVISOR_set_debugreg(reg, val);
}

static unsigned long xen_get_debugreg(int reg)
{
	return HYPERVISOR_get_debugreg(reg);
}

static void xen_end_context_switch(struct task_struct *next)
{
	xen_mc_flush();
	paravirt_end_context_switch(next);
}

static unsigned long xen_store_tr(void)
{
	return 0;
}


static void set_aliased_prot(void *v, pgprot_t prot)
{
	int level;
	pte_t *ptep;
	pte_t pte;
	unsigned long pfn;
	struct page *page;
	unsigned char dummy;

	ptep = lookup_address((unsigned long)v, &level);
	BUG_ON(ptep == NULL);

	pfn = pte_pfn(*ptep);
	page = pfn_to_page(pfn);

	pte = pfn_pte(pfn, prot);

	

	preempt_disable();

	copy_from_kernel_nofault(&dummy, v, 1);

	if (HYPERVISOR_update_va_mapping((unsigned long)v, pte, 0))
		BUG();

	if (!PageHighMem(page)) {
		void *av = __va(PFN_PHYS(pfn));

		if (av != v)
			if (HYPERVISOR_update_va_mapping((unsigned long)av, pte, 0))
				BUG();
	} else kmap_flush_unused();

	preempt_enable();
}

static void xen_alloc_ldt(struct desc_struct *ldt, unsigned entries)
{
	const unsigned entries_per_page = PAGE_SIZE / LDT_ENTRY_SIZE;
	int i;

	

	for (i = 0; i < entries; i += entries_per_page)
		set_aliased_prot(ldt + i, PAGE_KERNEL_RO);
}

static void xen_free_ldt(struct desc_struct *ldt, unsigned entries)
{
	const unsigned entries_per_page = PAGE_SIZE / LDT_ENTRY_SIZE;
	int i;

	for (i = 0; i < entries; i += entries_per_page)
		set_aliased_prot(ldt + i, PAGE_KERNEL);
}

static void xen_set_ldt(const void *addr, unsigned entries)
{
	struct mmuext_op *op;
	struct multicall_space mcs = xen_mc_entry(sizeof(*op));

	trace_xen_cpu_set_ldt(addr, entries);

	op = mcs.args;
	op->cmd = MMUEXT_SET_LDT;
	op->arg1.linear_addr = (unsigned long)addr;
	op->arg2.nr_ents = entries;

	MULTI_mmuext_op(mcs.mc, op, 1, NULL, DOMID_SELF);

	xen_mc_issue(PARAVIRT_LAZY_CPU);
}

static void xen_load_gdt(const struct desc_ptr *dtr)
{
	unsigned long va = dtr->address;
	unsigned int size = dtr->size + 1;
	unsigned long pfn, mfn;
	int level;
	pte_t *ptep;
	void *virt;

	
	BUG_ON(size > PAGE_SIZE);
	BUG_ON(va & ~PAGE_MASK);

	
	ptep = lookup_address(va, &level);
	BUG_ON(ptep == NULL);

	pfn = pte_pfn(*ptep);
	mfn = pfn_to_mfn(pfn);
	virt = __va(PFN_PHYS(pfn));

	make_lowmem_page_readonly((void *)va);
	make_lowmem_page_readonly(virt);

	if (HYPERVISOR_set_gdt(&mfn, size / sizeof(struct desc_struct)))
		BUG();
}


static void __init xen_load_gdt_boot(const struct desc_ptr *dtr)
{
	unsigned long va = dtr->address;
	unsigned int size = dtr->size + 1;
	unsigned long pfn, mfn;
	pte_t pte;

	
	BUG_ON(size > PAGE_SIZE);
	BUG_ON(va & ~PAGE_MASK);

	pfn = virt_to_pfn(va);
	mfn = pfn_to_mfn(pfn);

	pte = pfn_pte(pfn, PAGE_KERNEL_RO);

	if (HYPERVISOR_update_va_mapping((unsigned long)va, pte, 0))
		BUG();

	if (HYPERVISOR_set_gdt(&mfn, size / sizeof(struct desc_struct)))
		BUG();
}

static inline bool desc_equal(const struct desc_struct *d1, const struct desc_struct *d2)
{
	return !memcmp(d1, d2, sizeof(*d1));
}

static void load_TLS_descriptor(struct thread_struct *t, unsigned int cpu, unsigned int i)
{
	struct desc_struct *shadow = &per_cpu(shadow_tls_desc, cpu).desc[i];
	struct desc_struct *gdt;
	xmaddr_t maddr;
	struct multicall_space mc;

	if (desc_equal(shadow, &t->tls_array[i]))
		return;

	*shadow = t->tls_array[i];

	gdt = get_cpu_gdt_rw(cpu);
	maddr = arbitrary_virt_to_machine(&gdt[GDT_ENTRY_TLS_MIN+i]);
	mc = __xen_mc_entry(0);

	MULTI_update_descriptor(mc.mc, maddr.maddr, t->tls_array[i]);
}

static void xen_load_tls(struct thread_struct *t, unsigned int cpu)
{
	
	if (paravirt_get_lazy_mode() == PARAVIRT_LAZY_CPU) {

		lazy_load_gs(0);

		loadsegment(fs, 0);

	}

	xen_mc_batch();

	load_TLS_descriptor(t, cpu, 0);
	load_TLS_descriptor(t, cpu, 1);
	load_TLS_descriptor(t, cpu, 2);

	xen_mc_issue(PARAVIRT_LAZY_CPU);
}


static void xen_load_gs_index(unsigned int idx)
{
	if (HYPERVISOR_set_segment_base(SEGBASE_GS_USER_SEL, idx))
		BUG();
}


static void xen_write_ldt_entry(struct desc_struct *dt, int entrynum, const void *ptr)
{
	xmaddr_t mach_lp = arbitrary_virt_to_machine(&dt[entrynum]);
	u64 entry = *(u64 *)ptr;

	trace_xen_cpu_write_ldt_entry(dt, entrynum, entry);

	preempt_disable();

	xen_mc_flush();
	if (HYPERVISOR_update_descriptor(mach_lp.maddr, entry))
		BUG();

	preempt_enable();
}


void noist_exc_debug(struct pt_regs *regs);

DEFINE_IDTENTRY_RAW(xenpv_exc_nmi)
{
	
	exc_nmi(regs);
}

DEFINE_IDTENTRY_RAW(xenpv_exc_debug)
{
	
	if (user_mode(regs))
		noist_exc_debug(regs);
	else exc_debug(regs);
}

struct trap_array_entry {
	void (*orig)(void);
	void (*xen)(void);
	bool ist_okay;
};









static struct trap_array_entry trap_array[] = {
	TRAP_ENTRY_REDIR(exc_debug,			true  ), TRAP_ENTRY(exc_double_fault,			true  ),  TRAP_ENTRY(exc_machine_check,			true  ),  TRAP_ENTRY_REDIR(exc_nmi,			true  ), TRAP_ENTRY(exc_int3,				false ), TRAP_ENTRY(exc_overflow,			false ),  { entry_INT80_compat,          xen_entry_INT80_compat,          false },  TRAP_ENTRY(exc_page_fault,			false ), TRAP_ENTRY(exc_divide_error,			false ), TRAP_ENTRY(exc_bounds,				false ), TRAP_ENTRY(exc_invalid_op,			false ), TRAP_ENTRY(exc_device_not_available,		false ), TRAP_ENTRY(exc_coproc_segment_overrun,		false ), TRAP_ENTRY(exc_invalid_tss,			false ), TRAP_ENTRY(exc_segment_not_present,		false ), TRAP_ENTRY(exc_stack_segment,			false ), TRAP_ENTRY(exc_general_protection,		false ), TRAP_ENTRY(exc_spurious_interrupt_bug,		false ), TRAP_ENTRY(exc_coprocessor_error,		false ), TRAP_ENTRY(exc_alignment_check,			false ), TRAP_ENTRY(exc_simd_coprocessor_error,		false ), };

























static bool __ref get_trap_addr(void **addr, unsigned int ist)
{
	unsigned int nr;
	bool ist_okay = false;

	
	for (nr = 0; nr < ARRAY_SIZE(trap_array); nr++) {
		struct trap_array_entry *entry = trap_array + nr;

		if (*addr == entry->orig) {
			*addr = entry->xen;
			ist_okay = entry->ist_okay;
			break;
		}
	}

	if (nr == ARRAY_SIZE(trap_array) && *addr >= (void *)early_idt_handler_array[0] && *addr < (void *)early_idt_handler_array[NUM_EXCEPTION_VECTORS]) {

		nr = (*addr - (void *)early_idt_handler_array[0]) / EARLY_IDT_HANDLER_SIZE;
		*addr = (void *)xen_early_idt_handler_array[nr];
	}

	if (WARN_ON(ist != 0 && !ist_okay))
		return false;

	return true;
}


static int cvt_gate_to_trap(int vector, const gate_desc *val, struct trap_info *info)
{
	unsigned long addr;

	if (val->bits.type != GATE_TRAP && val->bits.type != GATE_INTERRUPT)
		return 0;

	info->vector = vector;

	addr = gate_offset(val);

	if (!get_trap_addr((void **)&addr, val->bits.ist))
		return 0;

	info->address = addr;

	info->cs = gate_segment(val);
	info->flags = val->bits.dpl;
	
	if (val->bits.type == GATE_INTERRUPT)
		info->flags |= 1 << 2;

	return 1;
}


static DEFINE_PER_CPU(struct desc_ptr, idt_desc);


static void xen_write_idt_entry(gate_desc *dt, int entrynum, const gate_desc *g)
{
	unsigned long p = (unsigned long)&dt[entrynum];
	unsigned long start, end;

	trace_xen_cpu_write_idt_entry(dt, entrynum, g);

	preempt_disable();

	start = __this_cpu_read(idt_desc.address);
	end = start + __this_cpu_read(idt_desc.size) + 1;

	xen_mc_flush();

	native_write_idt_entry(dt, entrynum, g);

	if (p >= start && (p + 8) <= end) {
		struct trap_info info[2];

		info[1].address = 0;

		if (cvt_gate_to_trap(entrynum, g, &info[0]))
			if (HYPERVISOR_set_trap_table(info))
				BUG();
	}

	preempt_enable();
}

static void xen_convert_trap_info(const struct desc_ptr *desc, struct trap_info *traps)
{
	unsigned in, out, count;

	count = (desc->size+1) / sizeof(gate_desc);
	BUG_ON(count > 256);

	for (in = out = 0; in < count; in++) {
		gate_desc *entry = (gate_desc *)(desc->address) + in;

		if (cvt_gate_to_trap(in, entry, &traps[out]))
			out++;
	}
	traps[out].address = 0;
}

void xen_copy_trap_info(struct trap_info *traps)
{
	const struct desc_ptr *desc = this_cpu_ptr(&idt_desc);

	xen_convert_trap_info(desc, traps);
}


static void xen_load_idt(const struct desc_ptr *desc)
{
	static DEFINE_SPINLOCK(lock);
	static struct trap_info traps[257];

	trace_xen_cpu_load_idt(desc);

	spin_lock(&lock);

	memcpy(this_cpu_ptr(&idt_desc), desc, sizeof(idt_desc));

	xen_convert_trap_info(desc, traps);

	xen_mc_flush();
	if (HYPERVISOR_set_trap_table(traps))
		BUG();

	spin_unlock(&lock);
}


static void xen_write_gdt_entry(struct desc_struct *dt, int entry, const void *desc, int type)
{
	trace_xen_cpu_write_gdt_entry(dt, entry, desc, type);

	preempt_disable();

	switch (type) {
	case DESC_LDT:
	case DESC_TSS:
		
		break;

	default: {
		xmaddr_t maddr = arbitrary_virt_to_machine(&dt[entry]);

		xen_mc_flush();
		if (HYPERVISOR_update_descriptor(maddr.maddr, *(u64 *)desc))
			BUG();
	}

	}

	preempt_enable();
}


static void __init xen_write_gdt_entry_boot(struct desc_struct *dt, int entry, const void *desc, int type)
{
	trace_xen_cpu_write_gdt_entry(dt, entry, desc, type);

	switch (type) {
	case DESC_LDT:
	case DESC_TSS:
		
		break;

	default: {
		xmaddr_t maddr = virt_to_machine(&dt[entry]);

		if (HYPERVISOR_update_descriptor(maddr.maddr, *(u64 *)desc))
			dt[entry] = *(struct desc_struct *)desc;
	}

	}
}

static void xen_load_sp0(unsigned long sp0)
{
	struct multicall_space mcs;

	mcs = xen_mc_entry(0);
	MULTI_stack_switch(mcs.mc, __KERNEL_DS, sp0);
	xen_mc_issue(PARAVIRT_LAZY_CPU);
	this_cpu_write(cpu_tss_rw.x86_tss.sp0, sp0);
}


static void xen_update_io_bitmap(void)
{
	struct physdev_set_iobitmap iobitmap;
	struct tss_struct *tss = this_cpu_ptr(&cpu_tss_rw);

	native_tss_update_io_bitmap();

	iobitmap.bitmap = (uint8_t *)(&tss->x86_tss) + tss->x86_tss.io_bitmap_base;
	if (tss->x86_tss.io_bitmap_base == IO_BITMAP_OFFSET_INVALID)
		iobitmap.nr_ports = 0;
	else iobitmap.nr_ports = IO_BITMAP_BITS;

	HYPERVISOR_physdev_op(PHYSDEVOP_set_iobitmap, &iobitmap);
}


static void xen_io_delay(void)
{
}

static DEFINE_PER_CPU(unsigned long, xen_cr0_value);

static unsigned long xen_read_cr0(void)
{
	unsigned long cr0 = this_cpu_read(xen_cr0_value);

	if (unlikely(cr0 == 0)) {
		cr0 = native_read_cr0();
		this_cpu_write(xen_cr0_value, cr0);
	}

	return cr0;
}

static void xen_write_cr0(unsigned long cr0)
{
	struct multicall_space mcs;

	this_cpu_write(xen_cr0_value, cr0);

	
	mcs = xen_mc_entry(0);

	MULTI_fpu_taskswitch(mcs.mc, (cr0 & X86_CR0_TS) != 0);

	xen_mc_issue(PARAVIRT_LAZY_CPU);
}

static void xen_write_cr4(unsigned long cr4)
{
	cr4 &= ~(X86_CR4_PGE | X86_CR4_PSE | X86_CR4_PCE);

	native_write_cr4(cr4);
}

static u64 xen_read_msr_safe(unsigned int msr, int *err)
{
	u64 val;

	if (pmu_msr_read(msr, &val, err))
		return val;

	val = native_read_msr_safe(msr, err);
	switch (msr) {
	case MSR_IA32_APICBASE:
		val &= ~X2APIC_ENABLE;
		break;
	}
	return val;
}

static int xen_write_msr_safe(unsigned int msr, unsigned low, unsigned high)
{
	int ret;

	unsigned int which;
	u64 base;


	ret = 0;

	switch (msr) {

	case MSR_FS_BASE:		which = SEGBASE_FS; goto set;
	case MSR_KERNEL_GS_BASE:	which = SEGBASE_GS_USER; goto set;
	case MSR_GS_BASE:		which = SEGBASE_GS_KERNEL; goto set;

	set:
		base = ((u64)high << 32) | low;
		if (HYPERVISOR_set_segment_base(which, base) != 0)
			ret = -EIO;
		break;


	case MSR_STAR:
	case MSR_CSTAR:
	case MSR_LSTAR:
	case MSR_SYSCALL_MASK:
	case MSR_IA32_SYSENTER_CS:
	case MSR_IA32_SYSENTER_ESP:
	case MSR_IA32_SYSENTER_EIP:
		
		break;

	default:
		if (!pmu_msr_write(msr, low, high, &ret))
			ret = native_write_msr_safe(msr, low, high);
	}

	return ret;
}

static u64 xen_read_msr(unsigned int msr)
{
	
	int err;

	return xen_read_msr_safe(msr, &err);
}

static void xen_write_msr(unsigned int msr, unsigned low, unsigned high)
{
	
	xen_write_msr_safe(msr, low, high);
}


void __init xen_setup_vcpu_info_placement(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		
		per_cpu(xen_vcpu_id, cpu) = cpu;

		
		(void) xen_vcpu_setup(cpu);
	}

	
	if (xen_have_vcpu_info_placement) {
		pv_ops.irq.save_fl = __PV_IS_CALLEE_SAVE(xen_save_fl_direct);
		pv_ops.irq.restore_fl = __PV_IS_CALLEE_SAVE(xen_restore_fl_direct);
		pv_ops.irq.irq_disable = __PV_IS_CALLEE_SAVE(xen_irq_disable_direct);
		pv_ops.irq.irq_enable = __PV_IS_CALLEE_SAVE(xen_irq_enable_direct);
		pv_ops.mmu.read_cr2 = __PV_IS_CALLEE_SAVE(xen_read_cr2_direct);
	}
}

static const struct pv_info xen_info __initconst = {
	.shared_kernel_pmd = 0,   .extra_user_64bit_cs = FLAT_USER_CS64,  .name = "Xen", };






static const struct pv_cpu_ops xen_cpu_ops __initconst = {
	.cpuid = xen_cpuid,  .set_debugreg = xen_set_debugreg, .get_debugreg = xen_get_debugreg,  .read_cr0 = xen_read_cr0, .write_cr0 = xen_write_cr0,  .write_cr4 = xen_write_cr4,  .wbinvd = native_wbinvd,  .read_msr = xen_read_msr, .write_msr = xen_write_msr,  .read_msr_safe = xen_read_msr_safe, .write_msr_safe = xen_write_msr_safe,  .read_pmc = xen_read_pmc,  .iret = xen_iret,  .usergs_sysret64 = xen_sysret64,   .load_tr_desc = paravirt_nop, .set_ldt = xen_set_ldt, .load_gdt = xen_load_gdt, .load_idt = xen_load_idt, .load_tls = xen_load_tls,  .load_gs_index = xen_load_gs_index,   .alloc_ldt = xen_alloc_ldt, .free_ldt = xen_free_ldt,  .store_tr = xen_store_tr,  .write_ldt_entry = xen_write_ldt_entry, .write_gdt_entry = xen_write_gdt_entry, .write_idt_entry = xen_write_idt_entry, .load_sp0 = xen_load_sp0,   .update_io_bitmap = xen_update_io_bitmap,  .io_delay = xen_io_delay,   .swapgs = paravirt_nop,  .start_context_switch = paravirt_start_context_switch, .end_context_switch = xen_end_context_switch, };






















































static void xen_restart(char *msg)
{
	xen_reboot(SHUTDOWN_reboot);
}

static void xen_machine_halt(void)
{
	xen_reboot(SHUTDOWN_poweroff);
}

static void xen_machine_power_off(void)
{
	if (pm_power_off)
		pm_power_off();
	xen_reboot(SHUTDOWN_poweroff);
}

static void xen_crash_shutdown(struct pt_regs *regs)
{
	xen_reboot(SHUTDOWN_crash);
}

static const struct machine_ops xen_machine_ops __initconst = {
	.restart = xen_restart, .halt = xen_machine_halt, .power_off = xen_machine_power_off, .shutdown = xen_machine_halt, .crash_shutdown = xen_crash_shutdown, .emergency_restart = xen_emergency_restart, };






static unsigned char xen_get_nmi_reason(void)
{
	unsigned char reason = 0;

	
	if (test_bit(_XEN_NMIREASON_io_error, &HYPERVISOR_shared_info->arch.nmi_reason))
		reason |= NMI_REASON_IOCHK;
	if (test_bit(_XEN_NMIREASON_pci_serr, &HYPERVISOR_shared_info->arch.nmi_reason))
		reason |= NMI_REASON_SERR;

	return reason;
}

static void __init xen_boot_params_init_edd(void)
{

	struct xen_platform_op op;
	struct edd_info *edd_info;
	u32 *mbr_signature;
	unsigned nr;
	int ret;

	edd_info = boot_params.eddbuf;
	mbr_signature = boot_params.edd_mbr_sig_buffer;

	op.cmd = XENPF_firmware_info;

	op.u.firmware_info.type = XEN_FW_DISK_INFO;
	for (nr = 0; nr < EDDMAXNR; nr++) {
		struct edd_info *info = edd_info + nr;

		op.u.firmware_info.index = nr;
		info->params.length = sizeof(info->params);
		set_xen_guest_handle(op.u.firmware_info.u.disk_info.edd_params, &info->params);
		ret = HYPERVISOR_platform_op(&op);
		if (ret)
			break;


		C(device);
		C(version);
		C(interface_support);
		C(legacy_max_cylinder);
		C(legacy_max_head);
		C(legacy_sectors_per_track);

	}
	boot_params.eddbuf_entries = nr;

	op.u.firmware_info.type = XEN_FW_DISK_MBR_SIGNATURE;
	for (nr = 0; nr < EDD_MBR_SIG_MAX; nr++) {
		op.u.firmware_info.index = nr;
		ret = HYPERVISOR_platform_op(&op);
		if (ret)
			break;
		mbr_signature[nr] = op.u.firmware_info.u.disk_mbr_signature.mbr_signature;
	}
	boot_params.edd_mbr_sig_buf_entries = nr;

}


static void __init xen_setup_gdt(int cpu)
{
	pv_ops.cpu.write_gdt_entry = xen_write_gdt_entry_boot;
	pv_ops.cpu.load_gdt = xen_load_gdt_boot;

	setup_stack_canary_segment(cpu);
	switch_to_new_gdt(cpu);

	pv_ops.cpu.write_gdt_entry = xen_write_gdt_entry;
	pv_ops.cpu.load_gdt = xen_load_gdt;
}

static void __init xen_dom0_set_legacy_features(void)
{
	x86_platform.legacy.rtc = 1;
}


asmlinkage __visible void __init xen_start_kernel(void)
{
	struct physdev_set_iopl set_iopl;
	unsigned long initrd_start = 0;
	int rc;

	if (!xen_start_info)
		return;

	xen_domain_type = XEN_PV_DOMAIN;
	xen_start_flags = xen_start_info->flags;

	xen_setup_features();

	
	pv_info = xen_info;
	pv_ops.init.patch = paravirt_patch_default;
	pv_ops.cpu = xen_cpu_ops;
	xen_init_irq_ops();

	
	xen_vcpu_info_reset(0);

	x86_platform.get_nmi_reason = xen_get_nmi_reason;

	x86_init.resources.memory_setup = xen_memory_setup;
	x86_init.irqs.intr_mode_select	= x86_init_noop;
	x86_init.irqs.intr_mode_init	= x86_init_noop;
	x86_init.oem.arch_setup = xen_arch_setup;
	x86_init.oem.banner = xen_banner;
	x86_init.hyper.init_platform = xen_pv_init_platform;
	x86_init.hyper.guest_late_init = xen_pv_guest_late_init;

	

	xen_setup_machphys_mapping();
	xen_init_mmu_ops();

	
	__supported_pte_mask &= ~_PAGE_GLOBAL;
	__default_kernel_pte_mask &= ~_PAGE_GLOBAL;

	
	__userpte_alloc_gfp &= ~__GFP_HIGHMEM;

	
	xen_build_dynamic_phys_to_machine();

	
	xen_setup_gdt(0);

	
	get_cpu_cap(&boot_cpu_data);
	x86_configure_nx();

	
	get_cpu_address_sizes(&boot_cpu_data);

	
	per_cpu(xen_vcpu_id, 0) = 0;

	idt_setup_early_handler();

	xen_init_capabilities();


	
	xen_init_apic();


	if (xen_feature(XENFEAT_mmu_pt_update_preserve_ad)) {
		pv_ops.mmu.ptep_modify_prot_start = xen_ptep_modify_prot_start;
		pv_ops.mmu.ptep_modify_prot_commit = xen_ptep_modify_prot_commit;
	}

	machine_ops = xen_machine_ops;

	
	xen_initial_gdt = &per_cpu(gdt_page, 0);

	xen_smp_init();


	
	acpi_numa = -1;

	WARN_ON(xen_cpuhp_setup(xen_cpu_up_prepare_pv, xen_cpu_dead_pv));

	local_irq_disable();
	early_boot_irqs_disabled = true;

	xen_raw_console_write("mapping kernel into physical memory\n");
	xen_setup_kernel_pagetable((pgd_t *)xen_start_info->pt_base, xen_start_info->nr_pages);
	xen_reserve_special_pages();

	


	pv_info.kernel_rpl = 1;
	if (xen_feature(XENFEAT_supervisor_mode_kernel))
		pv_info.kernel_rpl = 0;

	pv_info.kernel_rpl = 0;

	
	xen_reserve_top();

	
	set_iopl.iopl = 1;
	rc = HYPERVISOR_physdev_op(PHYSDEVOP_set_iopl, &set_iopl);
	if (rc != 0)
		xen_raw_printk("physdev_op failed %d\n", rc);


	
	cpu_detect(&new_cpu_data);
	set_cpu_cap(&new_cpu_data, X86_FEATURE_FPU);
	new_cpu_data.x86_capability[CPUID_1_EDX] = cpuid_edx(1);


	if (xen_start_info->mod_start) {
	    if (xen_start_info->flags & SIF_MOD_START_PFN)
		initrd_start = PFN_PHYS(xen_start_info->mod_start);
	    else initrd_start = __pa(xen_start_info->mod_start);
	}

	
	boot_params.hdr.type_of_loader = (9 << 4) | 0;
	boot_params.hdr.ramdisk_image = initrd_start;
	boot_params.hdr.ramdisk_size = xen_start_info->mod_len;
	boot_params.hdr.cmd_line_ptr = __pa(xen_start_info->cmd_line);
	boot_params.hdr.hardware_subarch = X86_SUBARCH_XEN;

	if (!xen_initial_domain()) {
		add_preferred_console("xenboot", 0, NULL);
		if (pci_xen)
			x86_init.pci.arch_init = pci_xen_init;
	} else {
		const struct dom0_vga_console_info *info = (void *)((char *)xen_start_info + xen_start_info->console.dom0.info_off);

		struct xen_platform_op op = {
			.cmd = XENPF_firmware_info, .interface_version = XENPF_INTERFACE_VERSION, .u.firmware_info.type = XEN_FW_KBD_SHIFT_FLAGS, };



		x86_platform.set_legacy_features = xen_dom0_set_legacy_features;
		xen_init_vga(info, xen_start_info->console.dom0.info_size);
		xen_start_info->console.domU.mfn = 0;
		xen_start_info->console.domU.evtchn = 0;

		if (HYPERVISOR_platform_op(&op) == 0)
			boot_params.kbd_status = op.u.firmware_info.u.kbd_shift_flags;

		
		pci_request_acs();

		xen_acpi_sleep_register();

		
		x86_init.mpparse.find_smp_config = x86_init_noop;
		x86_init.mpparse.get_smp_config = x86_init_uint_noop;

		xen_boot_params_init_edd();
	}

	if (!boot_params.screen_info.orig_video_isVGA)
		add_preferred_console("tty", 0, NULL);
	add_preferred_console("hvc", 0, NULL);
	if (boot_params.screen_info.orig_video_isVGA)
		add_preferred_console("tty", 0, NULL);


	
	pci_probe &= ~PCI_PROBE_BIOS;

	xen_raw_console_write("about to get started...\n");

	
	xen_setup_runstate_info(0);

	xen_efi_init(&boot_params);

	

	i386_start_kernel();

	cr4_init_shadow(); 
	x86_64_start_reservations((char *)__pa_symbol(&boot_params));

}

static int xen_cpu_up_prepare_pv(unsigned int cpu)
{
	int rc;

	if (per_cpu(xen_vcpu, cpu) == NULL)
		return -ENODEV;

	xen_setup_timer(cpu);

	rc = xen_smp_intr_init(cpu);
	if (rc) {
		WARN(1, "xen_smp_intr_init() for CPU %d failed: %d\n", cpu, rc);
		return rc;
	}

	rc = xen_smp_intr_init_pv(cpu);
	if (rc) {
		WARN(1, "xen_smp_intr_init_pv() for CPU %d failed: %d\n", cpu, rc);
		return rc;
	}

	return 0;
}

static int xen_cpu_dead_pv(unsigned int cpu)
{
	xen_smp_intr_free(cpu);
	xen_smp_intr_free_pv(cpu);

	xen_teardown_timer(cpu);

	return 0;
}

static uint32_t __init xen_platform_pv(void)
{
	if (xen_pv_domain())
		return xen_cpuid_base();

	return 0;
}

const __initconst struct hypervisor_x86 x86_hyper_xen_pv = {
	.name                   = "Xen PV", .detect                 = xen_platform_pv, .type			= X86_HYPER_XEN_PV, .runtime.pin_vcpu       = xen_pin_vcpu, .ignore_nopv		= true, };




