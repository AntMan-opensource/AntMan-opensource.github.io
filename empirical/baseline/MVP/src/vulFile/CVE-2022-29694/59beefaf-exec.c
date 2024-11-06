





























typedef struct PhysPageEntry PhysPageEntry;

struct PhysPageEntry {
    
    uint32_t skip : 6;
     
    uint32_t ptr : 26;
};











typedef PhysPageEntry Node[P_L2_SIZE];

typedef struct PhysPageMap {
    unsigned sections_nb;
    unsigned sections_nb_alloc;
    unsigned nodes_nb;
    unsigned nodes_nb_alloc;
    Node *nodes;
    MemoryRegionSection *sections;
} PhysPageMap;

struct AddressSpaceDispatch {
    MemoryRegionSection *mru_section;
    
    PhysPageEntry phys_map;
    PhysPageMap map;
    struct uc_struct *uc;
};


typedef struct subpage_t {
    MemoryRegion iomem;
    FlatView *fv;
    hwaddr base;
    uint16_t sub_section[];
} subpage_t;



static void tcg_commit(MemoryListener *listener);


struct CPUAddressSpace {
    CPUState *cpu;
    AddressSpace *as;
    struct AddressSpaceDispatch *memory_dispatch;
    MemoryListener tcg_as_listener;
};


static void phys_map_node_reserve(AddressSpaceDispatch *d, PhysPageMap *map, unsigned nodes)
{
    if (map->nodes_nb + nodes > map->nodes_nb_alloc) {
        map->nodes_nb_alloc = MAX(d->uc->alloc_hint, map->nodes_nb + nodes);
        map->nodes = g_renew(Node, map->nodes, map->nodes_nb_alloc);
        d->uc->alloc_hint = map->nodes_nb_alloc;
    }
}

static uint32_t phys_map_node_alloc(PhysPageMap *map, bool leaf)
{
    unsigned i;
    uint32_t ret;
    PhysPageEntry e;
    PhysPageEntry *p;

    ret = map->nodes_nb++;
    p = map->nodes[ret];
    assert(ret != PHYS_MAP_NODE_NIL);
    assert(ret != map->nodes_nb_alloc);

    e.skip = leaf ? 0 : 1;
    e.ptr = leaf ? PHYS_SECTION_UNASSIGNED : PHYS_MAP_NODE_NIL;
    for (i = 0; i < P_L2_SIZE; ++i) {
        memcpy(&p[i], &e, sizeof(e));
    }
    return ret;
}

static void phys_page_set_level(PhysPageMap *map, PhysPageEntry *lp, hwaddr *index, uint64_t *nb, uint16_t leaf, int level)

{
    PhysPageEntry *p;
    hwaddr step = (hwaddr)1 << (level * P_L2_BITS);

    if (lp->skip && lp->ptr == PHYS_MAP_NODE_NIL) {
        lp->ptr = phys_map_node_alloc(map, level == 0);
    }
    p = map->nodes[lp->ptr];
    lp = &p[(*index >> (level * P_L2_BITS)) & (P_L2_SIZE - 1)];

    while (*nb && lp < &p[P_L2_SIZE]) {
        if ((*index & (step - 1)) == 0 && *nb >= step) {
            lp->skip = 0;
            lp->ptr = leaf;
            *index += step;
            *nb -= step;
        } else {
            phys_page_set_level(map, lp, index, nb, leaf, level - 1);
        }
        ++lp;
    }
}

static void phys_page_set(AddressSpaceDispatch *d, hwaddr index, uint64_t nb, uint16_t leaf)

{

    struct uc_struct *uc = d->uc;

    
    phys_map_node_reserve(d, &d->map, 3 * P_L2_LEVELS);

    phys_page_set_level(&d->map, &d->phys_map, &index, &nb, leaf, P_L2_LEVELS - 1);
}


static void phys_page_compact(struct uc_struct *uc, PhysPageEntry *lp, Node *nodes)
{
    unsigned valid_ptr = P_L2_SIZE;
    int valid = 0;
    PhysPageEntry *p;
    int i;

    if (lp->ptr == PHYS_MAP_NODE_NIL) {
        return;
    }

    p = nodes[lp->ptr];
    for (i = 0; i < P_L2_SIZE; i++) {
        if (p[i].ptr == PHYS_MAP_NODE_NIL) {
            continue;
        }

        valid_ptr = i;
        valid++;
        if (p[i].skip) {
            phys_page_compact(uc, &p[i], nodes);
        }
    }

    
    if (valid != 1) {
        return;
    }

    assert(valid_ptr < P_L2_SIZE);

    
    if (P_L2_LEVELS >= (1 << 6) && lp->skip + p[valid_ptr].skip >= (1 << 6)) {
        return;
    }

    lp->ptr = p[valid_ptr].ptr;
    if (!p[valid_ptr].skip) {
        
        
        lp->skip = 0;
    } else {
        lp->skip += p[valid_ptr].skip;
    }
}

void address_space_dispatch_compact(AddressSpaceDispatch *d)
{
    if (d->phys_map.skip) {
        phys_page_compact(d->uc, &d->phys_map, d->map.nodes);
    }
}

static inline bool section_covers_addr(const MemoryRegionSection *section, hwaddr addr)
{
    
    return int128_gethi(section->size) || range_covers_byte(section->offset_within_address_space, int128_getlo(section->size), addr);

}

static MemoryRegionSection *phys_page_find(AddressSpaceDispatch *d, hwaddr addr)
{

    struct uc_struct *uc = d->uc;

    PhysPageEntry lp = d->phys_map, *p;
    Node *nodes = d->map.nodes;
    MemoryRegionSection *sections = d->map.sections;
    hwaddr index = addr >> TARGET_PAGE_BITS;
    int i;

    for (i = P_L2_LEVELS; lp.skip && (i -= lp.skip) >= 0;) {
        if (lp.ptr == PHYS_MAP_NODE_NIL) {
            return &sections[PHYS_SECTION_UNASSIGNED];
        }
        p = nodes[lp.ptr];
        lp = p[(index >> (i * P_L2_BITS)) & (P_L2_SIZE - 1)];
    }

    if (section_covers_addr(&sections[lp.ptr], addr)) {
        return &sections[lp.ptr];
    } else {
        return &sections[PHYS_SECTION_UNASSIGNED];
    }
}


static MemoryRegionSection *address_space_lookup_region(AddressSpaceDispatch *d, hwaddr addr, bool resolve_subpage)

{

    struct uc_struct *uc = d->uc;

    MemoryRegionSection *section = d->mru_section;
    subpage_t *subpage;

    if (!section || section == &d->map.sections[PHYS_SECTION_UNASSIGNED] || !section_covers_addr(section, addr)) {
        section = phys_page_find(d, addr);
        d->mru_section = section;
    }
    if (resolve_subpage && section->mr->subpage) {
        subpage = container_of(section->mr, subpage_t, iomem);
        section = &d->map.sections[subpage->sub_section[SUBPAGE_IDX(addr)]];
    }
    return section;
}


static MemoryRegionSection * address_space_translate_internal(AddressSpaceDispatch *d, hwaddr addr, hwaddr *xlat, hwaddr *plen, bool resolve_subpage)

{
    MemoryRegionSection *section;
    MemoryRegion *mr;
    Int128 diff;

    section = address_space_lookup_region(d, addr, resolve_subpage);
    
    addr -= section->offset_within_address_space;

    
    *xlat = addr + section->offset_within_region;

    mr = section->mr;

    
    if (memory_region_is_ram(mr)) {
        diff = int128_sub(section->size, int128_make64(addr));
        *plen = int128_get64(int128_min(diff, int128_make64(*plen)));
    }
    return section;
}


static MemoryRegionSection address_space_translate_iommu(IOMMUMemoryRegion *iommu_mr, hwaddr *xlat, hwaddr *plen_out, hwaddr *page_mask_out, bool is_write, bool is_mmio, AddressSpace **target_as, MemTxAttrs attrs)






{
    MemoryRegionSection *section;
    hwaddr page_mask = (hwaddr)-1;
    MemoryRegion *mr = MEMORY_REGION(iommu_mr);

    do {
        hwaddr addr = *xlat;
        IOMMUMemoryRegionClass *imrc = memory_region_get_iommu_class_nocheck(iommu_mr);
        int iommu_idx = 0;
        IOMMUTLBEntry iotlb;

        if (imrc->attrs_to_index) {
            iommu_idx = imrc->attrs_to_index(iommu_mr, attrs);
        }

        iotlb = imrc->translate(iommu_mr, addr, is_write ? IOMMU_WO : IOMMU_RO, iommu_idx);

        if (!(iotlb.perm & (1 << is_write))) {
            goto unassigned;
        }

        addr = ((iotlb.translated_addr & ~iotlb.addr_mask)
                | (addr & iotlb.addr_mask));
        page_mask &= iotlb.addr_mask;
        *plen_out = MIN(*plen_out, (addr | iotlb.addr_mask) - addr + 1);
        *target_as = iotlb.target_as;

        section = address_space_translate_internal( address_space_to_dispatch(iotlb.target_as), addr, xlat, plen_out, is_mmio);


        iommu_mr = memory_region_get_iommu(section->mr);
    } while (unlikely(iommu_mr));

    if (page_mask_out) {
        *page_mask_out = page_mask;
    }
    return *section;

unassigned:
    return (MemoryRegionSection) { .mr = &(mr->uc->io_mem_unassigned) };
}


static MemoryRegionSection flatview_do_translate(struct uc_struct *uc, FlatView *fv, hwaddr addr, hwaddr *xlat, hwaddr *plen_out, hwaddr *page_mask_out, bool is_write, bool is_mmio, AddressSpace **target_as, MemTxAttrs attrs)







{
    MemoryRegionSection *section;
    IOMMUMemoryRegion *iommu_mr;
    hwaddr plen = (hwaddr)(-1);

    if (!plen_out) {
        plen_out = &plen;
    }

    section = address_space_translate_internal( flatview_to_dispatch(fv), addr, xlat, plen_out, is_mmio);


    iommu_mr = memory_region_get_iommu(section->mr);
    if (unlikely(iommu_mr)) {
        return address_space_translate_iommu(iommu_mr, xlat, plen_out, page_mask_out, is_write, is_mmio, target_as, attrs);


    }
    if (page_mask_out) {
        
        *page_mask_out = ~TARGET_PAGE_MASK;
    }

    return *section;
}


MemoryRegion *flatview_translate(struct uc_struct *uc, FlatView *fv, hwaddr addr, hwaddr *xlat, hwaddr *plen, bool is_write, MemTxAttrs attrs)

{
    MemoryRegion *mr;
    MemoryRegionSection section;
    AddressSpace *as = NULL;

    
    section = flatview_do_translate(uc, fv, addr, xlat, plen, NULL, is_write, true, &as, attrs);
    mr = section.mr;

    return mr;
}


MemoryRegionSection * address_space_translate_for_iotlb(CPUState *cpu, int asidx, hwaddr addr, hwaddr *xlat, hwaddr *plen, MemTxAttrs attrs, int *prot)


{
    MemoryRegionSection *section;
    IOMMUMemoryRegion *iommu_mr;
    IOMMUMemoryRegionClass *imrc;
    IOMMUTLBEntry iotlb;
    int iommu_idx;
    AddressSpaceDispatch *d = cpu->cpu_ases[asidx].memory_dispatch;

    for (;;) {
        section = address_space_translate_internal(d, addr, &addr, plen, false);

        iommu_mr = memory_region_get_iommu(section->mr);
        if (!iommu_mr) {
            break;
        }

        imrc = memory_region_get_iommu_class_nocheck(iommu_mr);

        iommu_idx = imrc->attrs_to_index(iommu_mr, attrs);

        

        
        iotlb = imrc->translate(iommu_mr, addr, IOMMU_NONE, iommu_idx);
        addr = ((iotlb.translated_addr & ~iotlb.addr_mask)
                | (addr & iotlb.addr_mask));
        
        if (!(iotlb.perm & IOMMU_RO)) {
            *prot &= ~(PAGE_READ | PAGE_EXEC);
        }
        if (!(iotlb.perm & IOMMU_WO)) {
            *prot &= ~PAGE_WRITE;
        }

        if (!*prot) {
            goto translate_fail;
        }

        d = flatview_to_dispatch(address_space_to_flatview(iotlb.target_as));
    }

    assert(!(memory_region_get_iommu(section->mr) != NULL));
    *xlat = addr;
    
    
    
    
    
    
    
    if (!memory_region_is_ram(section->mr) && section == &d->map.sections[PHYS_SECTION_UNASSIGNED]) {
        *prot = 0;
    }
    return section;

translate_fail:
    return &d->map.sections[PHYS_SECTION_UNASSIGNED];
}

CPUState *qemu_get_cpu(struct uc_struct *uc, int index)
{
    CPUState *cpu = uc->cpu;
    if (cpu->cpu_index == index) {
        return cpu;
    }

    return NULL;
}

void cpu_address_space_init(CPUState *cpu, int asidx, MemoryRegion *mr)
{
    
    assert(asidx < cpu->num_ases);

    if (!cpu->cpu_ases) {
        cpu->cpu_ases = g_new0(CPUAddressSpace, cpu->num_ases);
        cpu->cpu_ases[0].cpu = cpu;
        cpu->cpu_ases[0].as = &(cpu->uc->address_space_memory);
        cpu->cpu_ases[0].tcg_as_listener.commit = tcg_commit;
        memory_listener_register(&(cpu->cpu_ases[0].tcg_as_listener), cpu->cpu_ases[0].as);
    }
    
    if (asidx > 0) {
        cpu->cpu_ases[asidx].cpu = cpu;
        cpu->cpu_ases[asidx].as = &(cpu->uc->address_space_memory);
        cpu->cpu_ases[asidx].tcg_as_listener.commit = tcg_commit;
        memory_listener_register(&(cpu->cpu_ases[asidx].tcg_as_listener), cpu->cpu_ases[asidx].as);
    }
}

AddressSpace *cpu_get_address_space(CPUState *cpu, int asidx)
{
    
    return cpu->cpu_ases[0].as;
}

void cpu_exec_unrealizefn(CPUState *cpu)
{
}

void cpu_exec_initfn(CPUState *cpu)
{
    cpu->num_ases = 1;
    cpu->as = &(cpu->uc->address_space_memory);
    cpu->memory = cpu->uc->system_memory;
}

void cpu_exec_realizefn(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);

    cc->tcg_initialize(cpu->uc);
    tlb_init(cpu);
}

void tb_invalidate_phys_addr(AddressSpace *as, hwaddr addr, MemTxAttrs attrs)
{
    ram_addr_t ram_addr;
    MemoryRegion *mr;
    hwaddr l = 1;

    mr = address_space_translate(as, addr, &addr, &l, false, attrs);
    if (!memory_region_is_ram(mr)) {
        return;
    }

    ram_addr = memory_region_get_ram_addr(mr) + addr;
    tb_invalidate_phys_page_range(as->uc, ram_addr, ram_addr + 1);
}

static void breakpoint_invalidate(CPUState *cpu, target_ulong pc)
{
    
    tb_flush(cpu);
}


int cpu_watchpoint_insert(CPUState *cpu, vaddr addr, vaddr len, int flags, CPUWatchpoint **watchpoint)
{

    CPUWatchpoint *wp;

    
    if (len == 0 || (addr + len - 1) < addr) {
        error_report("tried to set invalid watchpoint at %" VADDR_PRIx ", len=%" VADDR_PRIu, addr, len);
        return -EINVAL;
    }
    wp = g_malloc(sizeof(*wp));

    wp->vaddr = addr;
    wp->len = len;
    wp->flags = flags;

    
    if (flags & BP_GDB) {
        QTAILQ_INSERT_HEAD(&cpu->watchpoints, wp, entry);
    } else {
        QTAILQ_INSERT_TAIL(&cpu->watchpoints, wp, entry);
    }

    tlb_flush_page(cpu, addr);

    if (watchpoint)
        *watchpoint = wp;


    return 0;
}


void cpu_watchpoint_remove_by_ref(CPUState *cpu, CPUWatchpoint *watchpoint)
{

    QTAILQ_REMOVE(&cpu->watchpoints, watchpoint, entry);

    tlb_flush_page(cpu, watchpoint->vaddr);

    g_free(watchpoint);

}


void cpu_watchpoint_remove_all(CPUState *cpu, int mask)
{

    CPUWatchpoint *wp, *next;

    QTAILQ_FOREACH_SAFE(wp, &cpu->watchpoints, entry, next) {
        if (wp->flags & mask) {
            cpu_watchpoint_remove_by_ref(cpu, wp);
        }
    }

}


int cpu_watchpoint_address_matches(CPUState *cpu, vaddr addr, vaddr len)
{

    CPUWatchpoint *wp;
    int ret = 0;

    QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
        if (watchpoint_address_matches(wp, addr, TARGET_PAGE_SIZE)) {
            ret |= wp->flags;
        }
    }
    return ret;

    return 0;
}


int cpu_breakpoint_insert(CPUState *cpu, vaddr pc, int flags, CPUBreakpoint **breakpoint)
{
    CPUBreakpoint *bp;

    bp = g_malloc(sizeof(*bp));

    bp->pc = pc;
    bp->flags = flags;

    
    if (flags & BP_GDB) {
        QTAILQ_INSERT_HEAD(&cpu->breakpoints, bp, entry);
    } else {
        QTAILQ_INSERT_TAIL(&cpu->breakpoints, bp, entry);
    }

    breakpoint_invalidate(cpu, pc);

    if (breakpoint) {
        *breakpoint = bp;
    }
    return 0;
}


int cpu_breakpoint_remove(CPUState *cpu, vaddr pc, int flags)
{
    CPUBreakpoint *bp;

    QTAILQ_FOREACH(bp, &cpu->breakpoints, entry) {
        if (bp->pc == pc && bp->flags == flags) {
            cpu_breakpoint_remove_by_ref(cpu, bp);
            return 0;
        }
    }
    return -ENOENT;
}


void cpu_breakpoint_remove_by_ref(CPUState *cpu, CPUBreakpoint *breakpoint)
{
    QTAILQ_REMOVE(&cpu->breakpoints, breakpoint, entry);

    breakpoint_invalidate(cpu, breakpoint->pc);

    g_free(breakpoint);
}


void cpu_breakpoint_remove_all(CPUState *cpu, int mask)
{
    CPUBreakpoint *bp, *next;

    QTAILQ_FOREACH_SAFE(bp, &cpu->breakpoints, entry, next) {
        if (bp->flags & mask) {
            cpu_breakpoint_remove_by_ref(cpu, bp);
        }
    }
}

void cpu_abort(CPUState *cpu, const char *fmt, ...)
{
    abort();
}


static RAMBlock *qemu_get_ram_block(struct uc_struct *uc, ram_addr_t addr)
{
    RAMBlock *block;

    block = uc->ram_list.mru_block;
    if (block && addr - block->offset < block->max_length) {
        return block;
    }
    RAMBLOCK_FOREACH(block) {
        if (addr - block->offset < block->max_length) {
            goto found;
        }
    }

    fprintf(stderr, "Bad ram offset %" PRIx64 "\n", (uint64_t)addr);
    abort();

found:
    uc->ram_list.mru_block = block;
    return block;
}


bool cpu_physical_memory_test_and_clear_dirty(ram_addr_t start, ram_addr_t length, unsigned client)

{
    return false;
}


hwaddr memory_region_section_get_iotlb(CPUState *cpu, MemoryRegionSection *section)
{
    AddressSpaceDispatch *d = flatview_to_dispatch(section->fv);
    return section - d->map.sections;
}

static int subpage_register(struct uc_struct *uc, subpage_t *mmio, uint32_t start, uint32_t end, uint16_t section);
static subpage_t *subpage_init(struct uc_struct *, FlatView *fv, hwaddr base);

static void *(*phys_mem_alloc)(struct uc_struct *uc, size_t size, uint64_t *align) = qemu_anon_ram_alloc;

static uint16_t phys_section_add(struct uc_struct *uc, PhysPageMap *map, MemoryRegionSection *section)
{
    
    assert(map->sections_nb < TARGET_PAGE_SIZE);

    if (map->sections_nb == map->sections_nb_alloc) {
        map->sections_nb_alloc = MAX(map->sections_nb_alloc * 2, 16);
        map->sections = g_renew(MemoryRegionSection, map->sections, map->sections_nb_alloc);
    }
    map->sections[map->sections_nb] = *section;
    return map->sections_nb++;
}

static void phys_section_destroy(MemoryRegion *mr)
{
    bool have_sub_page = mr->subpage;

    if (have_sub_page) {
        subpage_t *subpage = container_of(mr, subpage_t, iomem);
        
        g_free(subpage);
    }
}

static void phys_sections_free(PhysPageMap *map)
{
    while (map->sections_nb > 0) {
        MemoryRegionSection *section = &map->sections[--map->sections_nb];
        phys_section_destroy(section->mr);
    }
    g_free(map->sections);
    g_free(map->nodes);
}

static void register_subpage(struct uc_struct *uc, FlatView *fv, MemoryRegionSection *section)
{
    AddressSpaceDispatch *d = flatview_to_dispatch(fv);
    subpage_t *subpage;
    hwaddr base = section->offset_within_address_space & TARGET_PAGE_MASK;
    MemoryRegionSection *existing = phys_page_find(d, base);
    MemoryRegionSection subsection = {
        .offset_within_address_space = base, .size = int128_make64(TARGET_PAGE_SIZE), };

    hwaddr start, end;

    assert(existing->mr->subpage || existing->mr == &(section->mr->uc->io_mem_unassigned));

    if (!(existing->mr->subpage)) {
        subpage = subpage_init(uc, fv, base);
        subsection.fv = fv;
        subsection.mr = &subpage->iomem;
        phys_page_set(d, base >> TARGET_PAGE_BITS, 1, phys_section_add(uc, &d->map, &subsection));
    } else {
        subpage = container_of(existing->mr, subpage_t, iomem);
    }
    start = section->offset_within_address_space & ~TARGET_PAGE_MASK;
    end = start + int128_get64(section->size) - 1;
    subpage_register(uc, subpage, start, end, phys_section_add(uc, &d->map, section));
}


static void register_multipage(struct uc_struct *uc, FlatView *fv, MemoryRegionSection *section)
{
    AddressSpaceDispatch *d = flatview_to_dispatch(fv);
    hwaddr start_addr = section->offset_within_address_space;
    uint16_t section_index = phys_section_add(uc, &d->map, section);
    uint64_t num_pages = int128_get64(int128_rshift(section->size, TARGET_PAGE_BITS));

    assert(num_pages);
    phys_page_set(d, start_addr >> TARGET_PAGE_BITS, num_pages, section_index);
}


void flatview_add_to_dispatch(struct uc_struct *uc, FlatView *fv, MemoryRegionSection *section)
{
    MemoryRegionSection remain = *section;
    Int128 page_size = int128_make64(TARGET_PAGE_SIZE);

    
    if (remain.offset_within_address_space & ~TARGET_PAGE_MASK) {
        uint64_t left = TARGET_PAGE_ALIGN(remain.offset_within_address_space)
                        - remain.offset_within_address_space;

        MemoryRegionSection now = remain;
        now.size = int128_min(int128_make64(left), now.size);
        register_subpage(uc, fv, &now);
        if (int128_eq(remain.size, now.size)) {
            return;
        }
        remain.size = int128_sub(remain.size, now.size);
        remain.offset_within_address_space += int128_get64(now.size);
        remain.offset_within_region += int128_get64(now.size);
    }

    
    if (int128_ge(remain.size, page_size)) {
        MemoryRegionSection now = remain;
        now.size = int128_and(now.size, int128_neg(page_size));
        register_multipage(uc, fv, &now);
        if (int128_eq(remain.size, now.size)) {
            return;
        }
        remain.size = int128_sub(remain.size, now.size);
        remain.offset_within_address_space += int128_get64(now.size);
        remain.offset_within_region += int128_get64(now.size);
    }

    
    register_subpage(uc, fv, &remain);
}


static ram_addr_t find_ram_offset(struct uc_struct *uc, ram_addr_t size)
{
    RAMBlock *block, *next_block;
    ram_addr_t offset = RAM_ADDR_MAX, mingap = RAM_ADDR_MAX;

    assert(size != 0); 

    if (QLIST_EMPTY(&uc->ram_list.blocks)) {
        return 0;
    }

    RAMBLOCK_FOREACH(block) {
        ram_addr_t candidate, next = RAM_ADDR_MAX;

        
        candidate = block->offset + block->max_length;
        candidate = ROUND_UP(candidate, BITS_PER_LONG << TARGET_PAGE_BITS);

        
        RAMBLOCK_FOREACH(next_block) {
            if (next_block->offset >= candidate) {
                next = MIN(next, next_block->offset);
            }
        }

        
        if (next - candidate >= size && next - candidate < mingap) {
            offset = candidate;
            mingap = next - candidate;
        }
    }

    if (offset == RAM_ADDR_MAX) {
        fprintf(stderr, "Failed to find gap of requested size: %" PRIu64 "\n", (uint64_t)size);
        abort();
    }

    return offset;
}

void *qemu_ram_get_host_addr(RAMBlock *rb)
{
    return rb->host;
}

ram_addr_t qemu_ram_get_offset(RAMBlock *rb)
{
    return rb->offset;
}

ram_addr_t qemu_ram_get_used_length(RAMBlock *rb)
{
    return rb->used_length;
}

bool qemu_ram_is_shared(RAMBlock *rb)
{
    return rb->flags & RAM_SHARED;
}

size_t qemu_ram_pagesize(RAMBlock *rb)
{
    return rb->page_size;
}

static void ram_block_add(struct uc_struct *uc, RAMBlock *new_block)
{
    RAMBlock *block;
    RAMBlock *last_block = NULL;

    new_block->offset = find_ram_offset(uc, new_block->max_length);

    if (!new_block->host) {
        new_block->host = phys_mem_alloc(uc, new_block->max_length, &new_block->mr->align);
        if (!new_block->host) {
            
            
            
            return;
        }
        
    }

    
    RAMBLOCK_FOREACH(block) {
        last_block = block;
        if (block->max_length < new_block->max_length) {
            break;
        }
    }
    if (block) {
        QLIST_INSERT_BEFORE(block, new_block, next);
    } else if (last_block) {
        QLIST_INSERT_AFTER(last_block, new_block, next);
    } else { 
        QLIST_INSERT_HEAD(&uc->ram_list.blocks, new_block, next);
    }
    uc->ram_list.mru_block = NULL;

    
    

    cpu_physical_memory_set_dirty_range(new_block->offset, new_block->used_length, DIRTY_CLIENTS_ALL);


}

RAMBlock *qemu_ram_alloc_from_ptr(struct uc_struct *uc, ram_addr_t size, void *host, MemoryRegion *mr)
{
    RAMBlock *new_block;
    ram_addr_t max_size = size;

    size = HOST_PAGE_ALIGN(uc, size);
    max_size = HOST_PAGE_ALIGN(uc, max_size);
    new_block = g_malloc0(sizeof(*new_block));
    if (new_block == NULL)
        return NULL;
    new_block->mr = mr;
    new_block->used_length = size;
    new_block->max_length = max_size;
    assert(max_size >= size);
    new_block->page_size = uc->qemu_real_host_page_size;
    new_block->host = host;
    if (host) {
        new_block->flags |= RAM_PREALLOC;
    }
    ram_block_add(mr->uc, new_block);

    return new_block;
}

RAMBlock *qemu_ram_alloc(struct uc_struct *uc, ram_addr_t size, MemoryRegion *mr)
{
    return qemu_ram_alloc_from_ptr(uc, size, NULL, mr);
}

static void reclaim_ramblock(struct uc_struct *uc, RAMBlock *block)
{
    if (block->flags & RAM_PREALLOC) {
        ;
    } else if (false) {
    } else {
        qemu_anon_ram_free(uc, block->host, block->max_length);
    }
    g_free(block);
}

void qemu_ram_free(struct uc_struct *uc, RAMBlock *block)
{
    if (!block) {
        return;
    }

    
    
    

    QLIST_REMOVE(block, next);
    uc->ram_list.mru_block = NULL;
    
    
    
    reclaim_ramblock(uc, block);
}


void *qemu_map_ram_ptr(struct uc_struct *uc, RAMBlock *ram_block, ram_addr_t addr)
{
    RAMBlock *block = ram_block;

    if (block == NULL) {
        block = qemu_get_ram_block(uc, addr);
        addr -= block->offset;
    }

    return ramblock_ptr(block, addr);
}


static void *qemu_ram_ptr_length(struct uc_struct *uc, RAMBlock *ram_block, ram_addr_t addr, hwaddr *size, bool lock)
{
    RAMBlock *block = ram_block;
    if (*size == 0) {
        return NULL;
    }

    if (block == NULL) {
        block = qemu_get_ram_block(uc, addr);
        addr -= block->offset;
    }
    *size = MIN(*size, block->max_length - addr);

    return ramblock_ptr(block, addr);
}


ram_addr_t qemu_ram_block_host_offset(RAMBlock *rb, void *host)
{
    ram_addr_t res = (uint8_t *)host - (uint8_t *)rb->host;
    assert((uintptr_t)host >= (uintptr_t)rb->host);
    assert(res < rb->max_length);

    return res;
}


RAMBlock *qemu_ram_block_from_host(struct uc_struct *uc, void *ptr, bool round_offset, ram_addr_t *offset)
{
    RAMBlock *block;
    uint8_t *host = ptr;

    block = uc->ram_list.mru_block;
    if (block && block->host && host - block->host < block->max_length) {
        goto found;
    }

    RAMBLOCK_FOREACH(block) {
        
        if (block->host == NULL) {
            continue;
        }
        if (host - block->host < block->max_length) {
            goto found;
        }
    }

    return NULL;

found:
    *offset = (host - block->host);
    if (round_offset) {
        *offset &= TARGET_PAGE_MASK;
    }
    return block;
}


ram_addr_t qemu_ram_addr_from_host(struct uc_struct *uc, void *ptr)
{
    RAMBlock *block;
    ram_addr_t offset;

    block = qemu_ram_block_from_host(uc, ptr, false, &offset);
    if (!block) {
        return RAM_ADDR_INVALID;
    }

    return block->offset + offset;
}


void cpu_check_watchpoint(CPUState *cpu, vaddr addr, vaddr len, MemTxAttrs attrs, int flags, uintptr_t ra)
{
}

static MemTxResult flatview_read(struct uc_struct *uc, FlatView *fv, hwaddr addr, MemTxAttrs attrs, void *buf, hwaddr len);
static MemTxResult flatview_write(struct uc_struct *, FlatView *fv, hwaddr addr, MemTxAttrs attrs, const void *buf, hwaddr len);
static bool flatview_access_valid(struct uc_struct *uc, FlatView *fv, hwaddr addr, hwaddr len, bool is_write, MemTxAttrs attrs);

static MemTxResult subpage_read(struct uc_struct *uc, void *opaque, hwaddr addr, uint64_t *data, unsigned len, MemTxAttrs attrs)
{
    subpage_t *subpage = opaque;
    uint8_t buf[8];
    MemTxResult res;


    printf("%s: subpage %p len %u addr " TARGET_FMT_plx "\n", __func__, subpage, len, addr);

    res = flatview_read(uc, subpage->fv, addr + subpage->base, attrs, buf, len);
    if (res) {
        return res;
    }
    *data = ldn_p(buf, len);
    return MEMTX_OK;
}

static MemTxResult subpage_write(struct uc_struct *uc, void *opaque, hwaddr addr, uint64_t value, unsigned len, MemTxAttrs attrs)
{
    subpage_t *subpage = opaque;
    uint8_t buf[8];


    printf("%s: subpage %p len %u addr " TARGET_FMT_plx " value %"PRIx64"\n", __func__, subpage, len, addr, value);


    stn_p(buf, len, value);
    return flatview_write(uc, subpage->fv, addr + subpage->base, attrs, buf, len);
}

static bool subpage_accepts(struct uc_struct *uc, void *opaque, hwaddr addr, unsigned len, bool is_write, MemTxAttrs attrs)

{
    subpage_t *subpage = opaque;

    printf("%s: subpage %p %c len %u addr " TARGET_FMT_plx "\n", __func__, subpage, is_write ? 'w' : 'r', len, addr);


    return flatview_access_valid(uc, subpage->fv, addr + subpage->base, len, is_write, attrs);
}

static const MemoryRegionOps subpage_ops = {
    .read_with_attrs = subpage_read, .write_with_attrs = subpage_write, .impl.min_access_size = 1, .impl.max_access_size = 8, .valid.min_access_size = 1, .valid.max_access_size = 8, .valid.accepts = subpage_accepts, .endianness = DEVICE_NATIVE_ENDIAN, };








static int subpage_register(struct uc_struct *uc, subpage_t *mmio, uint32_t start, uint32_t end, uint16_t section)
{
    int idx, eidx;

    if (start >= TARGET_PAGE_SIZE || end >= TARGET_PAGE_SIZE)
        return -1;
    idx = SUBPAGE_IDX(start);
    eidx = SUBPAGE_IDX(end);

    printf("%s: %p start %08x end %08x idx %08x eidx %08x section %d\n", __func__, mmio, start, end, idx, eidx, section);

    for (; idx <= eidx; idx++) {
        mmio->sub_section[idx] = section;
    }

    return 0;
}

static subpage_t *subpage_init(struct uc_struct *uc, FlatView *fv, hwaddr base)
{
    subpage_t *mmio;

    
    mmio = g_malloc0(sizeof(subpage_t) + TARGET_PAGE_SIZE * sizeof(uint16_t));
    mmio->fv = fv;
    mmio->base = base;
    memory_region_init_io(fv->root->uc, &mmio->iomem, &subpage_ops, mmio, TARGET_PAGE_SIZE);
    mmio->iomem.subpage = true;

    printf("%s: %p base " TARGET_FMT_plx " len %08x\n", __func__, mmio, base, TARGET_PAGE_SIZE);


    return mmio;
}

static uint16_t dummy_section(struct uc_struct *uc, PhysPageMap *map, FlatView *fv, MemoryRegion *mr)
{
    assert(fv);
    MemoryRegionSection section = {
        .fv = fv, .mr = mr, .offset_within_address_space = 0, .offset_within_region = 0, .size = int128_2_64(), };





    return phys_section_add(uc, map, &section);
}

MemoryRegionSection *iotlb_to_section(CPUState *cpu, hwaddr index, MemTxAttrs attrs)
{

    struct uc_struct *uc = cpu->uc;

    int asidx = cpu_asidx_from_attrs(cpu, attrs);
    CPUAddressSpace *cpuas = &cpu->cpu_ases[asidx];
    AddressSpaceDispatch *d = cpuas->memory_dispatch;
    MemoryRegionSection *sections = d->map.sections;

    return &sections[index & ~TARGET_PAGE_MASK];
}

static void io_mem_init(struct uc_struct *uc)
{
    memory_region_init_io(uc, &uc->io_mem_unassigned, &unassigned_mem_ops, NULL, UINT64_MAX);
}

AddressSpaceDispatch *address_space_dispatch_new(struct uc_struct *uc, FlatView *fv)
{
    AddressSpaceDispatch *d = g_new0(AddressSpaceDispatch, 1);

    uint16_t n;

    n = dummy_section(uc, &d->map, fv, &(uc->io_mem_unassigned));
    assert(n == PHYS_SECTION_UNASSIGNED);

    dummy_section(uc, &d->map, fv, &(uc->io_mem_unassigned));


    d->phys_map  = (PhysPageEntry) { .ptr = PHYS_MAP_NODE_NIL, .skip = 1 };
    d->uc = uc;

    return d;
}

void address_space_dispatch_free(AddressSpaceDispatch *d)
{
    phys_sections_free(&d->map);
    g_free(d);
}

static void tcg_commit(MemoryListener *listener)
{
    CPUAddressSpace *cpuas;
    AddressSpaceDispatch *d;

    
    cpuas = container_of(listener, CPUAddressSpace, tcg_as_listener);
    cpu_reloading_memory_map();
    
    d = address_space_to_dispatch(cpuas->as);
    cpuas->memory_dispatch = d;
    tlb_flush(cpuas->cpu);
}

static uint64_t unassigned_io_read(struct uc_struct *uc, void* opaque, hwaddr addr, unsigned size)
{

    return (uint64_t)0xffffffffffffffffULL;

    return (uint64_t)-1ULL;

}

static void unassigned_io_write(struct uc_struct *uc, void* opaque, hwaddr addr, uint64_t data, unsigned size)
{
}

static const MemoryRegionOps unassigned_io_ops = {
    .read = unassigned_io_read, .write = unassigned_io_write, .endianness = DEVICE_NATIVE_ENDIAN, };



static void memory_map_init(struct uc_struct *uc)
{
    uc->system_memory = g_malloc(sizeof(*(uc->system_memory)));
    memory_region_init(uc, uc->system_memory, UINT64_MAX);
    address_space_init(uc, &uc->address_space_memory, uc->system_memory);

    uc->system_io = g_malloc(sizeof(*(uc->system_io)));
    memory_region_init_io(uc, uc->system_io, &unassigned_io_ops, NULL, 65536);
    address_space_init(uc, &uc->address_space_io, uc->system_io);
}


static void invalidate_and_set_dirty(MemoryRegion *mr, hwaddr addr, hwaddr length)
{
}

static int memory_access_size(MemoryRegion *mr, unsigned l, hwaddr addr)
{
    unsigned access_size_max = mr->ops->valid.max_access_size;

    
    if (access_size_max == 0) {
        access_size_max = 4;
    }

    
    if (!mr->ops->impl.unaligned) {

        unsigned align_size_max = addr & (0ULL - addr);

        unsigned align_size_max = addr & -addr;

        if (align_size_max != 0 && align_size_max < access_size_max) {
            access_size_max = align_size_max;
        }
    }

    
    if (l > access_size_max) {
        l = access_size_max;
    }
    l = pow2floor(l);

    return l;
}

static bool prepare_mmio_access(MemoryRegion *mr)
{
    return true;
}


static MemTxResult flatview_write_continue(struct uc_struct *uc, FlatView *fv, hwaddr addr, MemTxAttrs attrs, const void *ptr, hwaddr len, hwaddr addr1, hwaddr l, MemoryRegion *mr)



{
    uint8_t *ram_ptr;
    uint64_t val;
    MemTxResult result = MEMTX_OK;
    bool release_lock = false;
    const uint8_t *buf = ptr;

    for (;;) {
        if (!memory_access_is_direct(mr, true)) {
            release_lock |= prepare_mmio_access(mr);
            l = memory_access_size(mr, l, addr1);
            
            val = ldn_he_p(buf, l);
            result |= memory_region_dispatch_write(uc, mr, addr1, val, size_memop(l), attrs);
        } else {
            
            ram_ptr = qemu_ram_ptr_length(fv->root->uc, mr->ram_block, addr1, &l, false);
            memcpy(ram_ptr, buf, l);
        }

        if (release_lock) {
            release_lock = false;
        }

        len -= l;
        buf += l;
        addr += l;

        if (!len) {
            break;
        }

        l = len;
        mr = flatview_translate(uc, fv, addr, &addr1, &l, true, attrs);
    }

    return result;
}


static MemTxResult flatview_write(struct uc_struct *uc, FlatView *fv, hwaddr addr, MemTxAttrs attrs, const void *buf, hwaddr len)
{
    hwaddr l;
    hwaddr addr1;
    MemoryRegion *mr;
    MemTxResult result = MEMTX_OK;

    l = len;
    mr = flatview_translate(uc, fv, addr, &addr1, &l, true, attrs);
    result = flatview_write_continue(uc, fv, addr, attrs, buf, len, addr1, l, mr);

    return result;
}


MemTxResult flatview_read_continue(struct uc_struct *uc, FlatView *fv, hwaddr addr, MemTxAttrs attrs, void *ptr, hwaddr len, hwaddr addr1, hwaddr l, MemoryRegion *mr)


{
    uint8_t *ram_ptr;
    uint64_t val;
    MemTxResult result = MEMTX_OK;
    bool release_lock = false;
    uint8_t *buf = ptr;

    for (;;) {
        if (!memory_access_is_direct(mr, false)) {
            
            release_lock |= prepare_mmio_access(mr);
            l = memory_access_size(mr, l, addr1);
            result |= memory_region_dispatch_read(uc, mr, addr1, &val, size_memop(l), attrs);
            stn_he_p(buf, l, val);
        } else {
            
            ram_ptr = qemu_ram_ptr_length(fv->root->uc, mr->ram_block, addr1, &l, false);
            memcpy(buf, ram_ptr, l);
        }

        if (release_lock) {
            release_lock = false;
        }

        len -= l;
        buf += l;
        addr += l;

        if (!len) {
            break;
        }

        l = len;
        mr = flatview_translate(uc, fv, addr, &addr1, &l, false, attrs);
    }

    return result;
}


static MemTxResult flatview_read(struct uc_struct *uc, FlatView *fv, hwaddr addr, MemTxAttrs attrs, void *buf, hwaddr len)
{
    hwaddr l;
    hwaddr addr1;
    MemoryRegion *mr;

    l = len;
    mr = flatview_translate(uc, fv, addr, &addr1, &l, false, attrs);
    return flatview_read_continue(uc, fv, addr, attrs, buf, len, addr1, l, mr);
}

MemTxResult address_space_read_full(AddressSpace *as, hwaddr addr, MemTxAttrs attrs, void *buf, hwaddr len)
{
    MemTxResult result = MEMTX_OK;
    FlatView *fv;

    if (len > 0) {
        fv = address_space_to_flatview(as);
        result = flatview_read(as->uc, fv, addr, attrs, buf, len);
    }

    return result;
}

MemTxResult address_space_write(AddressSpace *as, hwaddr addr, MemTxAttrs attrs, const void *buf, hwaddr len)

{
    MemTxResult result = MEMTX_OK;
    FlatView *fv;

    if (len > 0) {
        fv = address_space_to_flatview(as);
        result = flatview_write(as->uc, fv, addr, attrs, buf, len);
    }

    return result;
}

MemTxResult address_space_rw(AddressSpace *as, hwaddr addr, MemTxAttrs attrs, void *buf, hwaddr len, bool is_write)
{
    if (is_write) {
        return address_space_write(as, addr, attrs, buf, len);
    } else {
        return address_space_read_full(as, addr, attrs, buf, len);
    }
}

bool cpu_physical_memory_rw(AddressSpace *as, hwaddr addr, void *buf, hwaddr len, bool is_write)
{
    MemTxResult result = address_space_rw(as, addr, MEMTXATTRS_UNSPECIFIED, buf, len, is_write);
    if (result == MEMTX_OK) {
        return true;
    } else {
        return false;
    }
}

enum write_rom_type {
    WRITE_DATA, FLUSH_CACHE, };


static inline MemTxResult address_space_write_rom_internal(AddressSpace *as, hwaddr addr, MemTxAttrs attrs, const void *ptr, hwaddr len, enum write_rom_type type)




{
    hwaddr l;
    uint8_t *ram_ptr;
    hwaddr addr1;
    MemoryRegion *mr;
    const uint8_t *buf = ptr;

    while (len > 0) {
        l = len;
        mr = address_space_translate(as, addr, &addr1, &l, true, attrs);

        if (!memory_region_is_ram(mr)) {
            l = memory_access_size(mr, l, addr1);
        } else {
            
            ram_ptr = qemu_map_ram_ptr(as->uc, mr->ram_block, addr1);
            switch (type) {
            case WRITE_DATA:
                memcpy(ram_ptr, buf, l);
                break;
            case FLUSH_CACHE:
                flush_icache_range((uintptr_t)ram_ptr, (uintptr_t)ram_ptr + l);
                break;
            }
        }
        len -= l;
        buf += l;
        addr += l;
    }
    return MEMTX_OK;
}


MemTxResult address_space_write_rom(AddressSpace *as, hwaddr addr, MemTxAttrs attrs, const void *buf, hwaddr len)

{
    return address_space_write_rom_internal(as, addr, attrs, buf, len, WRITE_DATA);
}

void cpu_flush_icache_range(AddressSpace *as, hwaddr start, hwaddr len)
{
}

void cpu_exec_init_all(struct uc_struct *uc)
{
    
    finalize_target_page_bits(uc);
    memory_map_init(uc);
    io_mem_init(uc);
}

static bool flatview_access_valid(struct uc_struct *uc, FlatView *fv, hwaddr addr, hwaddr len, bool is_write, MemTxAttrs attrs)
{
    MemoryRegion *mr;
    hwaddr l, xlat;

    while (len > 0) {
        l = len;
        mr = flatview_translate(uc, fv, addr, &xlat, &l, is_write, attrs);
        if (!memory_access_is_direct(mr, is_write)) {
            l = memory_access_size(mr, l, addr);
            if (!memory_region_access_valid(uc, mr, xlat, l, is_write, attrs)) {
                return false;
            }
        }

        len -= l;
        addr += l;
    }
    return true;
}

bool address_space_access_valid(AddressSpace *as, hwaddr addr, hwaddr len, bool is_write, MemTxAttrs attrs)

{
    FlatView *fv;
    bool result;

    fv = address_space_to_flatview(as);
    result = flatview_access_valid(as->uc, fv, addr, len, is_write, attrs);
    return result;
}

static hwaddr flatview_extend_translation(struct uc_struct *uc, FlatView *fv, hwaddr addr, hwaddr target_len, MemoryRegion *mr, hwaddr base, hwaddr len, bool is_write, MemTxAttrs attrs)



{
    hwaddr done = 0;
    hwaddr xlat;
    MemoryRegion *this_mr;

    for (;;) {
        target_len -= len;
        addr += len;
        done += len;
        if (target_len == 0) {
            return done;
        }

        len = target_len;
        this_mr = flatview_translate(uc, fv, addr, &xlat, &len, is_write, attrs);
        if (this_mr != mr || xlat != base + done) {
            return done;
        }
    }
}


void *address_space_map(AddressSpace *as, hwaddr addr, hwaddr *plen, bool is_write, MemTxAttrs attrs)



{
    hwaddr len = *plen;
    hwaddr l, xlat;
    MemoryRegion *mr;
    void *ptr;
    FlatView *fv;
    struct uc_struct *uc = as->uc;

    if (len == 0) {
        return NULL;
    }

    l = len;
    fv = address_space_to_flatview(as);
    mr = flatview_translate(uc, fv, addr, &xlat, &l, is_write, attrs);

    if (!memory_access_is_direct(mr, is_write)) {
        
        l = MIN(l, TARGET_PAGE_SIZE);
        mr->uc->bounce.buffer = qemu_memalign(TARGET_PAGE_SIZE, l);
        mr->uc->bounce.addr = addr;
        mr->uc->bounce.len = l;

        mr->uc->bounce.mr = mr;
        if (!is_write) {
            flatview_read(as->uc, fv, addr, MEMTXATTRS_UNSPECIFIED, mr->uc->bounce.buffer, l);
        }

        *plen = l;
        return mr->uc->bounce.buffer;
    }


    *plen = flatview_extend_translation(as->uc, fv, addr, len, mr, xlat, l, is_write, attrs);
    ptr = qemu_ram_ptr_length(as->uc, mr->ram_block, xlat, plen, true);

    return ptr;
}


void address_space_unmap(AddressSpace *as, void *buffer, hwaddr len, bool is_write, hwaddr access_len)
{
    if (buffer != as->uc->bounce.buffer) {
        MemoryRegion *mr;
        ram_addr_t addr1;

        mr = memory_region_from_host(as->uc, buffer, &addr1);
        assert(mr != NULL);
        if (is_write) {
            invalidate_and_set_dirty(mr, addr1, access_len);
        }
        return;
    }
    if (is_write) {
        address_space_write(as, as->uc->bounce.addr, MEMTXATTRS_UNSPECIFIED, as->uc->bounce.buffer, access_len);
    }
    qemu_vfree(as->uc->bounce.buffer);
    as->uc->bounce.buffer = NULL;
}

void *cpu_physical_memory_map(AddressSpace *as, hwaddr addr, hwaddr *plen, bool is_write)

{
    return address_space_map(as, addr, plen, is_write, MEMTXATTRS_UNSPECIFIED);
}

void cpu_physical_memory_unmap(AddressSpace *as, void *buffer, hwaddr len, bool is_write, hwaddr access_len)
{
    address_space_unmap(as, buffer, len, is_write, access_len);
}












static inline MemoryRegion *address_space_translate_cached( MemoryRegionCache *cache, hwaddr addr, hwaddr *xlat, hwaddr *plen, bool is_write, MemTxAttrs attrs)

{
    MemoryRegionSection section;
    MemoryRegion *mr;
    IOMMUMemoryRegion *iommu_mr;
    AddressSpace *target_as;

    assert(!cache->ptr);
    *xlat = addr + cache->xlat;

    mr = cache->mrs.mr;
    iommu_mr = memory_region_get_iommu(mr);
    if (!iommu_mr) {
        
        return mr;
    }

    section = address_space_translate_iommu(iommu_mr, xlat, plen, NULL, is_write, true, &target_as, attrs);

    return section.mr;
}












int cpu_memory_rw_debug(CPUState *cpu, target_ulong addr, void *ptr, target_ulong len, bool is_write)
{

    struct uc_struct *uc = cpu->uc;

    hwaddr phys_addr;
    target_ulong l, page;
    uint8_t *buf = ptr;

    while (len > 0) {
        int asidx;
        MemTxAttrs attrs;

        page = addr & TARGET_PAGE_MASK;
        phys_addr = cpu_get_phys_page_attrs_debug(cpu, page, &attrs);
        asidx = cpu_asidx_from_attrs(cpu, attrs);
        
        if (phys_addr == -1)
            return -1;
        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len)
            l = len;
        phys_addr += (addr & ~TARGET_PAGE_MASK);
        if (is_write) {
            address_space_write_rom(cpu->cpu_ases[asidx].as, phys_addr, attrs, buf, l);
        } else {
            address_space_read(cpu->cpu_ases[asidx].as, phys_addr, attrs, buf, l);
        }
        len -= l;
        buf += l;
        addr += l;
    }
    return 0;
}


size_t qemu_target_page_size(struct uc_struct *uc)
{
    return TARGET_PAGE_SIZE;
}

int qemu_target_page_bits(struct uc_struct *uc)
{
    return TARGET_PAGE_BITS;
}

int qemu_target_page_bits_min(void)
{
    return TARGET_PAGE_BITS_MIN;
}

bool target_words_bigendian(void)
{

    return true;

    return false;

}

bool cpu_physical_memory_is_io(AddressSpace *as, hwaddr phys_addr)
{
    MemoryRegion*mr;
    hwaddr l = 1;
    bool res;

    mr = address_space_translate(as, phys_addr, &phys_addr, &l, false, MEMTXATTRS_UNSPECIFIED);


    res = !memory_region_is_ram(mr);
    return res;
}


int ram_block_discard_range(struct uc_struct *uc, RAMBlock *rb, uint64_t start, size_t length)
{
    int ret = -1;

    uint8_t *host_startaddr = rb->host + start;

    if (!QEMU_PTR_IS_ALIGNED(host_startaddr, rb->page_size)) {
        
        
        goto err;
    }

    if ((start + length) <= rb->used_length) {
        bool need_madvise;
        if (!QEMU_IS_ALIGNED(length, rb->page_size)) {
            
            
            goto err;
        }

        errno = ENOTSUP; 

        
        need_madvise = (rb->page_size == uc->qemu_host_page_size);
        if (need_madvise) {
            

            ret =  madvise(host_startaddr, length, MADV_DONTNEED);
            if (ret) {
                ret = -errno;
                
                
                
                goto err;
            }

            ret = -ENOSYS;
            
            
            
            goto err;

        }
    } else {
        
        
        
    }

err:
    return ret;
}

bool ramblock_is_pmem(RAMBlock *rb)
{
    return rb->flags & RAM_PMEM;
}

void page_size_init(struct uc_struct *uc)
{
    
    if (uc->qemu_host_page_size == 0) {
        uc->qemu_host_page_size = uc->qemu_real_host_page_size;
    }
    if (uc->qemu_host_page_size < TARGET_PAGE_SIZE) {
        uc->qemu_host_page_size = TARGET_PAGE_SIZE;
    }
}
