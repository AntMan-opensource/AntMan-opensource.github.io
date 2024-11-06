













static struct acrn_vcpu *is_single_destination(struct acrn_vm *vm, const struct msi_info *info)
{
	uint64_t vdmask;
	uint16_t vid;
	struct acrn_vcpu *vcpu = NULL;

	vdmask = vlapic_calc_dest_noshort(vm, false, (uint32_t)(info->addr.bits.dest_field), (bool)(info->addr.bits.dest_mode == MSI_ADDR_DESTMODE_PHYS), (bool)(info->data.bits.delivery_mode == MSI_DATA_DELMODE_LOPRI));


	vid = ffs64(vdmask);

	
	if ((info->data.bits.delivery_mode == MSI_DATA_DELMODE_FIXED)
		|| (info->data.bits.delivery_mode == MSI_DATA_DELMODE_LOPRI)) {
		
		if (vdmask == (1UL << vid)) {
			vcpu = vcpu_from_vid(vm, vid);
		}
	}

	return vcpu;
}

static uint32_t calculate_logical_dest_mask(uint64_t pdmask)
{
	uint32_t dest_mask = 0UL;
	uint64_t pcpu_mask = pdmask;
	uint16_t pcpu_id;

	pcpu_id = ffs64(pcpu_mask);
	while (pcpu_id < MAX_PCPU_NUM) {
		bitmap_clear_nolock(pcpu_id, &pcpu_mask);
		dest_mask |= per_cpu(lapic_ldr, pcpu_id);
		pcpu_id = ffs64(pcpu_mask);
	}
	return dest_mask;
}


static void ptirq_free_irte(const struct ptirq_remapping_info *entry)
{
	struct intr_source intr_src;

	if (entry->irte_idx < CONFIG_MAX_IR_ENTRIES) {
		if (entry->intr_type == PTDEV_INTR_MSI) {
			intr_src.is_msi = true;
			intr_src.src.msi.value = entry->phys_sid.msi_id.bdf;
		} else {
			intr_src.is_msi = false;
			intr_src.src.ioapic_id = ioapic_irq_to_ioapic_id(entry->allocated_pirq);
		}
		dmar_free_irte(&intr_src, entry->irte_idx);
	}
}


static void ptirq_build_physical_msi(struct acrn_vm *vm, struct ptirq_remapping_info *entry, uint32_t vector, uint64_t pid_paddr, uint16_t irte_idx)
{
	uint64_t vdmask, pdmask;
	uint32_t dest, delmode, dest_mask;
	bool phys;
	union dmar_ir_entry irte;
	union irte_index ir_index;
	int32_t ret;
	struct intr_source intr_src;

	
	dest = entry->vmsi.addr.bits.dest_field;
	phys = (entry->vmsi.addr.bits.dest_mode == MSI_ADDR_DESTMODE_PHYS);

	vdmask = vlapic_calc_dest_noshort(vm, false, dest, phys, false);
	pdmask = vcpumask2pcpumask(vm, vdmask);

	
	delmode = entry->vmsi.data.bits.delivery_mode;
	if ((delmode != MSI_DATA_DELMODE_FIXED) && (delmode != MSI_DATA_DELMODE_LOPRI)) {
		delmode = MSI_DATA_DELMODE_LOPRI;
	}

	dest_mask = calculate_logical_dest_mask(pdmask);

	
	irte.value.lo_64 = 0UL;
	irte.value.hi_64 = 0UL;
	irte.bits.remap.vector = vector;
	irte.bits.remap.delivery_mode = delmode;
	irte.bits.remap.dest_mode = MSI_ADDR_DESTMODE_LOGICAL;
	irte.bits.remap.rh = MSI_ADDR_RH;
	irte.bits.remap.dest = dest_mask;

	intr_src.is_msi = true;
	intr_src.pid_paddr = pid_paddr;
	intr_src.src.msi.value = entry->phys_sid.msi_id.bdf;
	if (entry->irte_idx == INVALID_IRTE_ID) {
		entry->irte_idx = irte_idx;
	}
	ret = dmar_assign_irte(&intr_src, &irte, entry->irte_idx, &ir_index.index);

	if (ret == 0) {
		entry->pmsi.data.full = 0U;
		entry->pmsi.addr.full = 0UL;
		entry->irte_idx = ir_index.index;
		if (ir_index.index != INVALID_IRTE_ID) {
			
			entry->pmsi.addr.ir_bits.intr_index_high = ir_index.bits.index_high;
			entry->pmsi.addr.ir_bits.shv = 0U;
			entry->pmsi.addr.ir_bits.intr_format = 0x1U;
			entry->pmsi.addr.ir_bits.intr_index_low = ir_index.bits.index_low;
			entry->pmsi.addr.ir_bits.constant = 0xFEEU;
		}
	} else {
		
		entry->pmsi.data = entry->vmsi.data;
		entry->pmsi.data.bits.delivery_mode = delmode;
		entry->pmsi.data.bits.vector = vector;

		entry->pmsi.addr = entry->vmsi.addr;
		entry->pmsi.addr.bits.dest_field = dest_mask;
		entry->pmsi.addr.bits.rh = MSI_ADDR_RH;
		entry->pmsi.addr.bits.dest_mode = MSI_ADDR_DESTMODE_LOGICAL;
	}
	dev_dbg(DBG_LEVEL_IRQ, "MSI %s addr:data = 0x%lx:%x(V) -> 0x%lx:%x(P)", (entry->pmsi.addr.ir_bits.intr_format != 0U) ? " Remappable Format" : "Compatibility Format", entry->vmsi.addr.full, entry->vmsi.data.full, entry->pmsi.addr.full, entry->pmsi.data.full);


}

static union ioapic_rte ptirq_build_physical_rte(struct acrn_vm *vm, struct ptirq_remapping_info *entry)
{
	union ioapic_rte rte;
	uint32_t phys_irq = entry->allocated_pirq;
	union source_id *virt_sid = &entry->virt_sid;
	union irte_index ir_index;
	union dmar_ir_entry irte;
	struct intr_source intr_src;
	int32_t ret;

	if (virt_sid->intx_id.ctlr == INTX_CTLR_IOAPIC) {
		uint64_t vdmask, pdmask;
		uint32_t dest, delmode, dest_mask, vector;
		union ioapic_rte virt_rte;
		bool phys;

		vioapic_get_rte(vm, virt_sid->intx_id.gsi, &virt_rte);
		rte = virt_rte;

		
		if (rte.bits.intr_polarity == IOAPIC_RTE_INTPOL_ALO) {
			if (entry->polarity == 0U) {
				vioapic_set_irqline_nolock(vm, virt_sid->intx_id.gsi, GSI_SET_HIGH);
			}
			entry->polarity = 1U;
		} else {
			if (entry->polarity == 1U) {
				vioapic_set_irqline_nolock(vm, virt_sid->intx_id.gsi, GSI_SET_LOW);
			}
			entry->polarity = 0U;
		}

		
		phys = (virt_rte.bits.dest_mode == IOAPIC_RTE_DESTMODE_PHY);
		dest = (uint32_t)virt_rte.bits.dest_field;
		vdmask = vlapic_calc_dest_noshort(vm, false, dest, phys, false);
		pdmask = vcpumask2pcpumask(vm, vdmask);

		
		delmode = virt_rte.bits.delivery_mode;
		if ((delmode != IOAPIC_RTE_DELMODE_FIXED) && (delmode != IOAPIC_RTE_DELMODE_LOPRI)) {
			delmode = IOAPIC_RTE_DELMODE_LOPRI;
		}

		
		vector = irq_to_vector(phys_irq);
		dest_mask = calculate_logical_dest_mask(pdmask);

		irte.value.lo_64 = 0UL;
		irte.value.hi_64 = 0UL;
		irte.bits.remap.vector = vector;
		irte.bits.remap.delivery_mode = delmode;
		irte.bits.remap.dest_mode = IOAPIC_RTE_DESTMODE_LOGICAL;
		irte.bits.remap.dest = dest_mask;
		irte.bits.remap.trigger_mode = rte.bits.trigger_mode;

		intr_src.is_msi = false;
		intr_src.pid_paddr = 0UL;
		intr_src.src.ioapic_id = ioapic_irq_to_ioapic_id(phys_irq);
		ret = dmar_assign_irte(&intr_src, &irte, entry->irte_idx, &ir_index.index);

		if (ret == 0) {
			entry->irte_idx = ir_index.index;
			if (ir_index.index != INVALID_IRTE_ID) {
				rte.ir_bits.vector = vector;
				rte.ir_bits.constant = 0U;
				rte.ir_bits.intr_index_high = ir_index.bits.index_high;
				rte.ir_bits.intr_format = 1U;
				rte.ir_bits.intr_index_low = ir_index.bits.index_low;
			} else {
				rte.bits.intr_mask = 1;
			}
		} else {
			rte.bits.dest_mode = IOAPIC_RTE_DESTMODE_LOGICAL;
			rte.bits.delivery_mode = delmode;
			rte.bits.vector = vector;
			rte.bits.dest_field = dest_mask;
		}

		dev_dbg(DBG_LEVEL_IRQ, "IOAPIC RTE %s = 0x%x:%x(V) -> 0x%x:%x(P)", (rte.ir_bits.intr_format != 0U) ? "Remappable Format" : "Compatibility Format", virt_rte.u.hi_32, virt_rte.u.lo_32, rte.u.hi_32, rte.u.lo_32);


	} else {
		enum vpic_trigger trigger;
		union ioapic_rte phys_rte;

		
		ioapic_get_rte(phys_irq, &phys_rte);
		rte = phys_rte;
		rte.bits.trigger_mode = IOAPIC_RTE_TRGRMODE_EDGE;
		vpic_get_irqline_trigger_mode(vm_pic(vm), (uint32_t)virt_sid->intx_id.gsi, &trigger);
		if (trigger == LEVEL_TRIGGER) {
			rte.bits.trigger_mode = IOAPIC_RTE_TRGRMODE_LEVEL;
		}

		dev_dbg(DBG_LEVEL_IRQ, "IOAPIC RTE %s = 0x%x:%x(P) -> 0x%x:%x(P)", (rte.ir_bits.intr_format != 0U) ? "Remappable Format" : "Compatibility Format", phys_rte.u.hi_32, phys_rte.u.lo_32, rte.u.hi_32, rte.u.lo_32);


	}

	return rte;
}


static struct ptirq_remapping_info *add_msix_remapping(struct acrn_vm *vm, uint16_t virt_bdf, uint16_t phys_bdf, uint32_t entry_nr)
{
	struct ptirq_remapping_info *entry;
	DEFINE_MSI_SID(phys_sid, phys_bdf, entry_nr);
	DEFINE_MSI_SID(virt_sid, virt_bdf, entry_nr);

	entry = find_ptirq_entry(PTDEV_INTR_MSI, &phys_sid, NULL);
	if (entry == NULL) {
		entry = ptirq_alloc_entry(vm, PTDEV_INTR_MSI);
		if (entry != NULL) {
			entry->phys_sid.value = phys_sid.value;
			entry->virt_sid.value = virt_sid.value;
			entry->release_cb = ptirq_free_irte;

			
			if (ptirq_activate_entry(entry, IRQ_INVALID) < 0) {
				ptirq_release_entry(entry);
				entry = NULL;
			}
		}

		dev_dbg(DBG_LEVEL_IRQ, "VM%d MSIX add vector mapping vbdf%x:pbdf%x idx=%d", vm->vm_id, virt_bdf, phys_bdf, entry_nr);
	}

	return entry;
}


static void remove_msix_remapping(const struct acrn_vm *vm, uint16_t phys_bdf, uint32_t entry_nr)
{
	struct ptirq_remapping_info *entry;
	DEFINE_MSI_SID(phys_sid, phys_bdf, entry_nr);
	struct intr_source intr_src;

	entry = find_ptirq_entry(PTDEV_INTR_MSI, &phys_sid, NULL);
	if ((entry != NULL) && (entry->vm == vm)) {
		if (is_entry_active(entry)) {
			
			ptirq_deactivate_entry(entry);
		}

		intr_src.is_msi = true;
		intr_src.src.msi.value = entry->phys_sid.msi_id.bdf;
		dmar_free_irte(&intr_src, entry->irte_idx);

		dev_dbg(DBG_LEVEL_IRQ, "VM%d MSIX remove vector mapping vbdf-pbdf:0x%x-0x%x idx=%d", vm->vm_id, entry->virt_sid.msi_id.bdf, phys_bdf, entry_nr);

		ptirq_release_entry(entry);
	}

}


static struct ptirq_remapping_info *add_intx_remapping(struct acrn_vm *vm, uint32_t virt_gsi, uint32_t phys_gsi, enum intx_ctlr vgsi_ctlr)
{
	struct ptirq_remapping_info *entry = NULL;
	DEFINE_INTX_SID(phys_sid, phys_gsi, INTX_CTLR_IOAPIC);
	DEFINE_INTX_SID(virt_sid, virt_gsi, vgsi_ctlr);
	uint32_t phys_irq = ioapic_gsi_to_irq(phys_gsi);

	entry = find_ptirq_entry(PTDEV_INTR_INTX, &phys_sid, NULL);
	if (entry == NULL) {
		if (find_ptirq_entry(PTDEV_INTR_INTX, &virt_sid, vm) == NULL) {
			entry = ptirq_alloc_entry(vm, PTDEV_INTR_INTX);
			if (entry != NULL) {
				entry->phys_sid.value = phys_sid.value;
				entry->virt_sid.value = virt_sid.value;
				entry->release_cb = ptirq_free_irte;

				
				if (ptirq_activate_entry(entry, phys_irq) < 0) {
					ptirq_release_entry(entry);
					entry = NULL;
				}
			}
		} else {
			pr_err("INTX re-add vpin %d", virt_gsi);
		}
	} else if (entry->vm != vm) {
		if (is_sos_vm(entry->vm)) {
			entry->vm = vm;
			entry->virt_sid.value = virt_sid.value;
			entry->polarity = 0U;
		} else {
			pr_err("INTX gsi%d already in vm%d with vgsi%d, not able to add into vm%d with vgsi%d", phys_gsi, entry->vm->vm_id, entry->virt_sid.intx_id.gsi, vm->vm_id, virt_gsi);
			entry = NULL;
		}
	} else {
		
	}


	

	if (entry != NULL) {
		dev_dbg(DBG_LEVEL_IRQ, "VM%d INTX add pin mapping vgsi%d:pgsi%d", entry->vm->vm_id, virt_gsi, phys_gsi);
	}

	return entry;
}


static void remove_intx_remapping(const struct acrn_vm *vm, uint32_t virt_gsi, enum intx_ctlr vgsi_ctlr)
{
	uint32_t phys_irq;
	struct ptirq_remapping_info *entry;
	struct intr_source intr_src;
	DEFINE_INTX_SID(virt_sid, virt_gsi, vgsi_ctlr);

	entry = find_ptirq_entry(PTDEV_INTR_INTX, &virt_sid, vm);
	if (entry != NULL) {
		if (is_entry_active(entry)) {
			phys_irq = entry->allocated_pirq;
			
			ioapic_gsi_mask_irq(phys_irq);

			ptirq_deactivate_entry(entry);
			intr_src.is_msi = false;
			intr_src.src.ioapic_id = ioapic_irq_to_ioapic_id(phys_irq);

			dmar_free_irte(&intr_src, entry->irte_idx);
			dev_dbg(DBG_LEVEL_IRQ, "deactive %s intx entry:pgsi=%d, pirq=%d ", (vgsi_ctlr == INTX_CTLR_PIC) ? "vPIC" : "vIOAPIC", entry->phys_sid.intx_id.gsi, phys_irq);


			dev_dbg(DBG_LEVEL_IRQ, "from vm%d vgsi=%d\n", entry->vm->vm_id, virt_gsi);
		}

		ptirq_release_entry(entry);
	}
}

static void ptirq_handle_intx(struct acrn_vm *vm, const struct ptirq_remapping_info *entry)
{
	const union source_id *virt_sid = &entry->virt_sid;

	switch (virt_sid->intx_id.ctlr) {
	case INTX_CTLR_IOAPIC:
	{
		union ioapic_rte rte;
		bool trigger_lvl = false;

		
		vioapic_get_rte(vm, (uint32_t)virt_sid->intx_id.gsi, &rte);
		if (rte.bits.trigger_mode == IOAPIC_RTE_TRGRMODE_LEVEL) {
			trigger_lvl = true;
		}

		if (trigger_lvl) {
			if (entry->polarity != 0U) {
				vioapic_set_irqline_lock(vm, virt_sid->intx_id.gsi, GSI_SET_LOW);
			} else {
				vioapic_set_irqline_lock(vm, virt_sid->intx_id.gsi, GSI_SET_HIGH);
			}
		} else {
			if (entry->polarity != 0U) {
				vioapic_set_irqline_lock(vm, virt_sid->intx_id.gsi, GSI_FALLING_PULSE);
			} else {
				vioapic_set_irqline_lock(vm, virt_sid->intx_id.gsi, GSI_RAISING_PULSE);
			}
		}

		dev_dbg(DBG_LEVEL_PTIRQ, "dev-assign: irq=0x%x assert vr: 0x%x vRTE=0x%lx", entry->allocated_pirq, irq_to_vector(entry->allocated_pirq), rte.full);



		break;
	}
	case INTX_CTLR_PIC:
	{
		enum vpic_trigger trigger;

		
		vpic_get_irqline_trigger_mode(vm_pic(vm), virt_sid->intx_id.gsi, &trigger);
		if (trigger == LEVEL_TRIGGER) {
			vpic_set_irqline(vm_pic(vm), virt_sid->intx_id.gsi, GSI_SET_HIGH);
		} else {
			vpic_set_irqline(vm_pic(vm), virt_sid->intx_id.gsi, GSI_RAISING_PULSE);
		}
		break;
	}
	default:
		
		break;
	}
}

void ptirq_softirq(uint16_t pcpu_id)
{
	while (1) {
		struct ptirq_remapping_info *entry = ptirq_dequeue_softirq(pcpu_id);
		struct msi_info *vmsi;

		if (entry == NULL) {
			break;
		}

		vmsi = &entry->vmsi;

		
		if (!is_entry_active(entry)) {
			
			continue;
		}

		
		if (entry->intr_type == PTDEV_INTR_INTX) {
			ptirq_handle_intx(entry->vm, entry);
		} else {
			if (vmsi != NULL) {
				
				(void)vlapic_inject_msi(entry->vm, vmsi->addr.full, vmsi->data.full);
				dev_dbg(DBG_LEVEL_PTIRQ, "dev-assign: irq=0x%x MSI VR: 0x%x-0x%x", entry->allocated_pirq, vmsi->data.bits.vector, irq_to_vector(entry->allocated_pirq));

				dev_dbg(DBG_LEVEL_PTIRQ, " vmsi_addr: 0x%lx vmsi_data: 0x%x", vmsi->addr.full, vmsi->data.full);
			}
		}
	}
}

void ptirq_intx_ack(struct acrn_vm *vm, uint32_t virt_gsi, enum intx_ctlr vgsi_ctlr)
{
	uint32_t phys_irq;
	struct ptirq_remapping_info *entry;
	DEFINE_INTX_SID(virt_sid, virt_gsi, vgsi_ctlr);

	entry = find_ptirq_entry(PTDEV_INTR_INTX, &virt_sid, vm);
	if (entry != NULL) {
		phys_irq = entry->allocated_pirq;

		
		switch (vgsi_ctlr) {
		case INTX_CTLR_IOAPIC:
			if (entry->polarity != 0U) {
				vioapic_set_irqline_lock(vm, virt_gsi, GSI_SET_HIGH);
			} else {
				vioapic_set_irqline_lock(vm, virt_gsi, GSI_SET_LOW);
			}
			break;
		case INTX_CTLR_PIC:
			vpic_set_irqline(vm_pic(vm), virt_gsi, GSI_SET_LOW);
			break;
		default:
			
			break;
		}

		dev_dbg(DBG_LEVEL_PTIRQ, "dev-assign: irq=0x%x acked vr: 0x%x", phys_irq, irq_to_vector(phys_irq));
		ioapic_gsi_unmask_irq(phys_irq);
	}
}


int32_t ptirq_prepare_msix_remap(struct acrn_vm *vm, uint16_t virt_bdf, uint16_t phys_bdf, uint16_t entry_nr, struct msi_info *info, uint16_t irte_idx)
{
	struct ptirq_remapping_info *entry;
	int32_t ret = -ENODEV;
	union pci_bdf vbdf;

	
	spinlock_obtain(&ptdev_lock);
	entry = add_msix_remapping(vm, virt_bdf, phys_bdf, entry_nr);
	spinlock_release(&ptdev_lock);

	if (entry != NULL) {
		ret = 0;
		entry->vmsi = *info;

		
		if (is_lapic_pt_configured(vm)) {
			enum vm_vlapic_mode vlapic_mode = check_vm_vlapic_mode(vm);

			if (vlapic_mode == VM_VLAPIC_X2APIC) {
				
				ptirq_build_physical_msi(vm, entry, (uint32_t)info->data.bits.vector, 0UL, irte_idx);
			} else if (vlapic_mode == VM_VLAPIC_XAPIC) {
				
				ptirq_build_physical_msi(vm, entry, irq_to_vector(entry->allocated_pirq), 0UL, irte_idx);
			} else if (vlapic_mode == VM_VLAPIC_TRANSITION) {
				
				ret = -EFAULT;
			} else {
				
				ret = -EFAULT;
			}
		} else {
			struct acrn_vcpu *vcpu = is_single_destination(vm, info);

			if (is_pi_capable(vm) && (vcpu != NULL)) {
				ptirq_build_physical_msi(vm, entry, (uint32_t)info->data.bits.vector, hva2hpa(get_pi_desc(vcpu)), irte_idx);
			} else {
				
				ptirq_build_physical_msi(vm, entry, irq_to_vector(entry->allocated_pirq), 0UL, irte_idx);
			}
		}

		if (ret == 0) {
			*info = entry->pmsi;
			vbdf.value = virt_bdf;
			dev_dbg(DBG_LEVEL_IRQ, "PCI %x:%x.%x MSI VR[%d] 0x%x->0x%x assigned to vm%d", vbdf.bits.b, vbdf.bits.d, vbdf.bits.f, entry_nr, entry->vmsi.data.bits.vector, irq_to_vector(entry->allocated_pirq), entry->vm->vm_id);

		}
	}

	return ret;
}

static void activate_physical_ioapic(struct acrn_vm *vm, struct ptirq_remapping_info *entry)
{
	union ioapic_rte rte;
	uint32_t phys_irq = entry->allocated_pirq;
	uint64_t intr_mask;
	bool is_lvl_trigger = false;

	
	ioapic_gsi_mask_irq(phys_irq);

	
	rte = ptirq_build_physical_rte(vm, entry);
	intr_mask = rte.bits.intr_mask;

	
	if (rte.bits.trigger_mode == IOAPIC_RTE_TRGRMODE_LEVEL) {
		is_lvl_trigger = true;
	}
	set_irq_trigger_mode(phys_irq, is_lvl_trigger);

	
	rte.bits.intr_mask = IOAPIC_RTE_MASK_SET;
	ioapic_set_rte(phys_irq, rte);

	if (intr_mask == IOAPIC_RTE_MASK_CLR) {
		ioapic_gsi_unmask_irq(phys_irq);
	}
}


int32_t ptirq_intx_pin_remap(struct acrn_vm *vm, uint32_t virt_gsi, enum intx_ctlr vgsi_ctlr)
{
	int32_t status = 0;
	struct ptirq_remapping_info *entry = NULL;
	DEFINE_INTX_SID(virt_sid, virt_gsi, vgsi_ctlr);
	DEFINE_INTX_SID(alt_virt_sid, virt_gsi, vgsi_ctlr);

	

	
	if (!is_vuart_intx(vm, virt_sid.intx_id.gsi)) {
		
		spinlock_obtain(&ptdev_lock);
		entry = find_ptirq_entry(PTDEV_INTR_INTX, &virt_sid, vm);
		if (entry == NULL) {
			if (is_sos_vm(vm)) {

				
				if (virt_gsi < NR_LEGACY_PIN) {

					if (vgsi_ctlr == INTX_CTLR_PIC) {
						alt_virt_sid.intx_id.ctlr = INTX_CTLR_IOAPIC;
					} else {
						alt_virt_sid.intx_id.ctlr = INTX_CTLR_PIC;
					}

					entry = find_ptirq_entry(PTDEV_INTR_INTX, &alt_virt_sid, vm);
					if (entry != NULL) {
						uint32_t phys_gsi = virt_gsi;

						remove_intx_remapping(vm, alt_virt_sid.intx_id.gsi, alt_virt_sid.intx_id.ctlr);
						entry = add_intx_remapping(vm, virt_gsi, phys_gsi, vgsi_ctlr);
						if (entry == NULL) {
							pr_err("%s, add intx remapping failed", __func__);
							status = -ENODEV;
						} else {
							dev_dbg(DBG_LEVEL_IRQ, "IOAPIC gsi=%hhu pirq=%u vgsi=%d from %s to %s for vm%d", entry->phys_sid.intx_id.gsi, entry->allocated_pirq, entry->virt_sid.intx_id.gsi, (vgsi_ctlr == INTX_CTLR_IOAPIC) ? "vPIC" : "vIOAPIC", (vgsi_ctlr == INTX_CTLR_IOAPIC) ? "vIOPIC" : "vPIC", entry->vm->vm_id);





						}
					}
				}

				
				if (entry == NULL) {
					uint32_t phys_gsi = virt_gsi;

					entry = add_intx_remapping(vm, virt_gsi, phys_gsi, vgsi_ctlr);
					if (entry == NULL) {
						pr_err("%s, add intx remapping failed", __func__);
						status = -ENODEV;
					}
				}
			} else {
				
				status = -ENODEV;
			}
		}
		spinlock_release(&ptdev_lock);
	} else {
		status = -EINVAL;
	}

	if (status == 0) {
		activate_physical_ioapic(vm, entry);
	}

	return status;
}


int32_t ptirq_add_intx_remapping(struct acrn_vm *vm, uint32_t virt_gsi, uint32_t phys_gsi, bool pic_pin)
{
	struct ptirq_remapping_info *entry;
	enum intx_ctlr vgsi_ctlr = pic_pin ? INTX_CTLR_PIC : INTX_CTLR_IOAPIC;

	spinlock_obtain(&ptdev_lock);
	entry = add_intx_remapping(vm, virt_gsi, phys_gsi, vgsi_ctlr);
	spinlock_release(&ptdev_lock);

	return (entry != NULL) ? 0 : -ENODEV;
}


void ptirq_remove_intx_remapping(const struct acrn_vm *vm, uint32_t virt_gsi, bool pic_pin)
{
	enum intx_ctlr vgsi_ctlr = pic_pin ? INTX_CTLR_PIC : INTX_CTLR_IOAPIC;

	spinlock_obtain(&ptdev_lock);
	remove_intx_remapping(vm, virt_gsi, vgsi_ctlr);
	spinlock_release(&ptdev_lock);
}


void ptirq_remove_msix_remapping(const struct acrn_vm *vm, uint16_t phys_bdf, uint32_t vector_count)
{
	uint32_t i;

	for (i = 0U; i < vector_count; i++) {
		spinlock_obtain(&ptdev_lock);
		remove_msix_remapping(vm, phys_bdf, i);
		spinlock_release(&ptdev_lock);
	}
}


void ptirq_remove_configured_intx_remappings(const struct acrn_vm *vm)
{
	const struct acrn_vm_config *vm_config = get_vm_config(vm->vm_id);
	uint32_t i;

	for (i = 0; i < vm_config->pt_intx_num; i++) {
		ptirq_remove_intx_remapping(vm, vm_config->pt_intx[i].virt_gsi, false);
	}
}
