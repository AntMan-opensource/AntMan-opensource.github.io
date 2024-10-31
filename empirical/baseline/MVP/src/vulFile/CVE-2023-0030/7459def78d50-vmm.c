





static void nvkm_vmm_pt_del(struct nvkm_vmm_pt **ppgt)
{
	struct nvkm_vmm_pt *pgt = *ppgt;
	if (pgt) {
		kvfree(pgt->pde);
		kfree(pgt);
		*ppgt = NULL;
	}
}


static struct nvkm_vmm_pt * nvkm_vmm_pt_new(const struct nvkm_vmm_desc *desc, bool sparse, const struct nvkm_vmm_page *page)

{
	const u32 pten = 1 << desc->bits;
	struct nvkm_vmm_pt *pgt;
	u32 lpte = 0;

	if (desc->type > PGT) {
		if (desc->type == SPT) {
			const struct nvkm_vmm_desc *pair = page[-1].desc;
			lpte = pten >> (desc->bits - pair->bits);
		} else {
			lpte = pten;
		}
	}

	if (!(pgt = kzalloc(sizeof(*pgt) + lpte, GFP_KERNEL)))
		return NULL;
	pgt->page = page ? page->shift : 0;
	pgt->sparse = sparse;

	if (desc->type == PGD) {
		pgt->pde = kvcalloc(pten, sizeof(*pgt->pde), GFP_KERNEL);
		if (!pgt->pde) {
			kfree(pgt);
			return NULL;
		}
	}

	return pgt;
}

struct nvkm_vmm_iter {
	const struct nvkm_vmm_page *page;
	const struct nvkm_vmm_desc *desc;
	struct nvkm_vmm *vmm;
	u64 cnt;
	u16 max, lvl;
	u32 pte[NVKM_VMM_LEVELS_MAX];
	struct nvkm_vmm_pt *pt[NVKM_VMM_LEVELS_MAX];
	int flush;
};


static const char * nvkm_vmm_desc_type(const struct nvkm_vmm_desc *desc)
{
	switch (desc->type) {
	case PGD: return "PGD";
	case PGT: return "PGT";
	case SPT: return "SPT";
	case LPT: return "LPT";
	default:
		return "UNKNOWN";
	}
}

static void nvkm_vmm_trace(struct nvkm_vmm_iter *it, char *buf)
{
	int lvl;
	for (lvl = it->max; lvl >= 0; lvl--) {
		if (lvl >= it->lvl)
			buf += sprintf(buf,  "%05x:", it->pte[lvl]);
		else buf += sprintf(buf, "xxxxx:");
	}
}










static inline void nvkm_vmm_flush_mark(struct nvkm_vmm_iter *it)
{
	it->flush = min(it->flush, it->max - it->lvl);
}

static inline void nvkm_vmm_flush(struct nvkm_vmm_iter *it)
{
	if (it->flush != NVKM_VMM_LEVELS_MAX) {
		if (it->vmm->func->flush) {
			TRA(it, "flush: %d", it->flush);
			it->vmm->func->flush(it->vmm, it->flush);
		}
		it->flush = NVKM_VMM_LEVELS_MAX;
	}
}

static void nvkm_vmm_unref_pdes(struct nvkm_vmm_iter *it)
{
	const struct nvkm_vmm_desc *desc = it->desc;
	const int type = desc[it->lvl].type == SPT;
	struct nvkm_vmm_pt *pgd = it->pt[it->lvl + 1];
	struct nvkm_vmm_pt *pgt = it->pt[it->lvl];
	struct nvkm_mmu_pt *pt = pgt->pt[type];
	struct nvkm_vmm *vmm = it->vmm;
	u32 pdei = it->pte[it->lvl + 1];

	
	it->lvl++;
	if (--pgd->refs[0]) {
		const struct nvkm_vmm_desc_func *func = desc[it->lvl].func;
		
		TRA(it, "PDE unmap %s", nvkm_vmm_desc_type(&desc[it->lvl - 1]));
		pgt->pt[type] = NULL;
		if (!pgt->refs[!type]) {
			
			if (pgd->pt[0]) {
				if (pgt->sparse) {
					func->sparse(vmm, pgd->pt[0], pdei, 1);
					pgd->pde[pdei] = NVKM_VMM_PDE_SPARSE;
				} else {
					func->unmap(vmm, pgd->pt[0], pdei, 1);
					pgd->pde[pdei] = NULL;
				}
			} else {
				
				func->pde(vmm, pgd, pdei);
				pgd->pde[pdei] = NULL;
			}
		} else {
			
			func->pde(vmm, pgd, pdei);
		}

		
		nvkm_vmm_flush_mark(it);
		nvkm_vmm_flush(it);
	} else {
		
		nvkm_vmm_unref_pdes(it);
	}

	
	TRA(it, "PDE free %s", nvkm_vmm_desc_type(&desc[it->lvl - 1]));
	nvkm_mmu_ptc_put(vmm->mmu, vmm->bootstrapped, &pt);
	if (!pgt->refs[!type])
		nvkm_vmm_pt_del(&pgt);
	it->lvl--;
}

static void nvkm_vmm_unref_sptes(struct nvkm_vmm_iter *it, struct nvkm_vmm_pt *pgt, const struct nvkm_vmm_desc *desc, u32 ptei, u32 ptes)

{
	const struct nvkm_vmm_desc *pair = it->page[-1].desc;
	const u32 sptb = desc->bits - pair->bits;
	const u32 sptn = 1 << sptb;
	struct nvkm_vmm *vmm = it->vmm;
	u32 spti = ptei & (sptn - 1), lpti, pteb;

	
	for (lpti = ptei >> sptb; ptes; spti = 0, lpti++) {
		const u32 pten = min(sptn - spti, ptes);
		pgt->pte[lpti] -= pten;
		ptes -= pten;
	}

	
	if (!pgt->refs[0])
		return;

	for (ptei = pteb = ptei >> sptb; ptei < lpti; pteb = ptei) {
		
		if (pgt->pte[pteb] & NVKM_VMM_PTE_SPTES) {
			for (ptes = 1, ptei++; ptei < lpti; ptes++, ptei++) {
				if (!(pgt->pte[ptei] & NVKM_VMM_PTE_SPTES))
					break;
			}
			continue;
		}

		
		pgt->pte[ptei] &= ~NVKM_VMM_PTE_VALID;
		for (ptes = 1, ptei++; ptei < lpti; ptes++, ptei++) {
			if (pgt->pte[ptei] & NVKM_VMM_PTE_SPTES)
				break;
			pgt->pte[ptei] &= ~NVKM_VMM_PTE_VALID;
		}

		if (pgt->pte[pteb] & NVKM_VMM_PTE_SPARSE) {
			TRA(it, "LPTE %05x: U -> S %d PTEs", pteb, ptes);
			pair->func->sparse(vmm, pgt->pt[0], pteb, ptes);
		} else if (pair->func->invalid) {
			
			TRA(it, "LPTE %05x: U -> I %d PTEs", pteb, ptes);
			pair->func->invalid(vmm, pgt->pt[0], pteb, ptes);
		}
	}
}

static bool nvkm_vmm_unref_ptes(struct nvkm_vmm_iter *it, u32 ptei, u32 ptes)
{
	const struct nvkm_vmm_desc *desc = it->desc;
	const int type = desc->type == SPT;
	struct nvkm_vmm_pt *pgt = it->pt[0];

	
	pgt->refs[type] -= ptes;

	
	if (desc->type == SPT && (pgt->refs[0] || pgt->refs[1]))
		nvkm_vmm_unref_sptes(it, pgt, desc, ptei, ptes);

	
	if (!pgt->refs[type]) {
		it->lvl++;
		TRA(it, "%s empty", nvkm_vmm_desc_type(desc));
		it->lvl--;
		nvkm_vmm_unref_pdes(it);
		return false; 
	}

	return true;
}

static void nvkm_vmm_ref_sptes(struct nvkm_vmm_iter *it, struct nvkm_vmm_pt *pgt, const struct nvkm_vmm_desc *desc, u32 ptei, u32 ptes)

{
	const struct nvkm_vmm_desc *pair = it->page[-1].desc;
	const u32 sptb = desc->bits - pair->bits;
	const u32 sptn = 1 << sptb;
	struct nvkm_vmm *vmm = it->vmm;
	u32 spti = ptei & (sptn - 1), lpti, pteb;

	
	for (lpti = ptei >> sptb; ptes; spti = 0, lpti++) {
		const u32 pten = min(sptn - spti, ptes);
		pgt->pte[lpti] += pten;
		ptes -= pten;
	}

	
	if (!pgt->refs[0])
		return;

	for (ptei = pteb = ptei >> sptb; ptei < lpti; pteb = ptei) {
		
		if (pgt->pte[pteb] & NVKM_VMM_PTE_VALID) {
			for (ptes = 1, ptei++; ptei < lpti; ptes++, ptei++) {
				if (!(pgt->pte[ptei] & NVKM_VMM_PTE_VALID))
					break;
			}
			continue;
		}

		
		pgt->pte[ptei] |= NVKM_VMM_PTE_VALID;
		for (ptes = 1, ptei++; ptei < lpti; ptes++, ptei++) {
			if (pgt->pte[ptei] & NVKM_VMM_PTE_VALID)
				break;
			pgt->pte[ptei] |= NVKM_VMM_PTE_VALID;
		}

		if (pgt->pte[pteb] & NVKM_VMM_PTE_SPARSE) {
			const u32 spti = pteb * sptn;
			const u32 sptc = ptes * sptn;
			
			TRA(it, "SPTE %05x: U -> S %d PTEs", spti, sptc);
			desc->func->sparse(vmm, pgt->pt[1], spti, sptc);
			
			TRA(it, "LPTE %05x: S -> U %d PTEs", pteb, ptes);
			pair->func->unmap(vmm, pgt->pt[0], pteb, ptes);
		} else if (pair->func->invalid) {
			
			TRA(it, "LPTE %05x: I -> U %d PTEs", pteb, ptes);
			pair->func->unmap(vmm, pgt->pt[0], pteb, ptes);
		}
	}
}

static bool nvkm_vmm_ref_ptes(struct nvkm_vmm_iter *it, u32 ptei, u32 ptes)
{
	const struct nvkm_vmm_desc *desc = it->desc;
	const int type = desc->type == SPT;
	struct nvkm_vmm_pt *pgt = it->pt[0];

	
	pgt->refs[type] += ptes;

	
	if (desc->type == SPT)
		nvkm_vmm_ref_sptes(it, pgt, desc, ptei, ptes);

	return true;
}

static void nvkm_vmm_sparse_ptes(const struct nvkm_vmm_desc *desc, struct nvkm_vmm_pt *pgt, u32 ptei, u32 ptes)

{
	if (desc->type == PGD) {
		while (ptes--)
			pgt->pde[ptei++] = NVKM_VMM_PDE_SPARSE;
	} else if (desc->type == LPT) {
		memset(&pgt->pte[ptei], NVKM_VMM_PTE_SPARSE, ptes);
	}
}

static bool nvkm_vmm_sparse_unref_ptes(struct nvkm_vmm_iter *it, u32 ptei, u32 ptes)
{
	struct nvkm_vmm_pt *pt = it->pt[0];
	if (it->desc->type == PGD)
		memset(&pt->pde[ptei], 0x00, sizeof(pt->pde[0]) * ptes);
	else if (it->desc->type == LPT)
		memset(&pt->pte[ptei], 0x00, sizeof(pt->pte[0]) * ptes);
	return nvkm_vmm_unref_ptes(it, ptei, ptes);
}

static bool nvkm_vmm_sparse_ref_ptes(struct nvkm_vmm_iter *it, u32 ptei, u32 ptes)
{
	nvkm_vmm_sparse_ptes(it->desc, it->pt[0], ptei, ptes);
	return nvkm_vmm_ref_ptes(it, ptei, ptes);
}

static bool nvkm_vmm_ref_hwpt(struct nvkm_vmm_iter *it, struct nvkm_vmm_pt *pgd, u32 pdei)
{
	const struct nvkm_vmm_desc *desc = &it->desc[it->lvl - 1];
	const int type = desc->type == SPT;
	struct nvkm_vmm_pt *pgt = pgd->pde[pdei];
	const bool zero = !pgt->sparse && !desc->func->invalid;
	struct nvkm_vmm *vmm = it->vmm;
	struct nvkm_mmu *mmu = vmm->mmu;
	struct nvkm_mmu_pt *pt;
	u32 pten = 1 << desc->bits;
	u32 pteb, ptei, ptes;
	u32 size = desc->size * pten;

	pgd->refs[0]++;

	pgt->pt[type] = nvkm_mmu_ptc_get(mmu, size, desc->align, zero);
	if (!pgt->pt[type]) {
		it->lvl--;
		nvkm_vmm_unref_pdes(it);
		return false;
	}

	if (zero)
		goto done;

	pt = pgt->pt[type];

	if (desc->type == LPT && pgt->refs[1]) {
		
		for (ptei = pteb = 0; ptei < pten; pteb = ptei) {
			bool spte = pgt->pte[ptei] & NVKM_VMM_PTE_SPTES;
			for (ptes = 1, ptei++; ptei < pten; ptes++, ptei++) {
				bool next = pgt->pte[ptei] & NVKM_VMM_PTE_SPTES;
				if (spte != next)
					break;
			}

			if (!spte) {
				if (pgt->sparse)
					desc->func->sparse(vmm, pt, pteb, ptes);
				else desc->func->invalid(vmm, pt, pteb, ptes);
				memset(&pgt->pte[pteb], 0x00, ptes);
			} else {
				desc->func->unmap(vmm, pt, pteb, ptes);
				while (ptes--)
					pgt->pte[pteb++] |= NVKM_VMM_PTE_VALID;
			}
		}
	} else {
		if (pgt->sparse) {
			nvkm_vmm_sparse_ptes(desc, pgt, 0, pten);
			desc->func->sparse(vmm, pt, 0, pten);
		} else {
			desc->func->invalid(vmm, pt, 0, pten);
		}
	}

done:
	TRA(it, "PDE write %s", nvkm_vmm_desc_type(desc));
	it->desc[it->lvl].func->pde(it->vmm, pgd, pdei);
	nvkm_vmm_flush_mark(it);
	return true;
}

static bool nvkm_vmm_ref_swpt(struct nvkm_vmm_iter *it, struct nvkm_vmm_pt *pgd, u32 pdei)
{
	const struct nvkm_vmm_desc *desc = &it->desc[it->lvl - 1];
	struct nvkm_vmm_pt *pgt = pgd->pde[pdei];

	pgt = nvkm_vmm_pt_new(desc, NVKM_VMM_PDE_SPARSED(pgt), it->page);
	if (!pgt) {
		if (!pgd->refs[0])
			nvkm_vmm_unref_pdes(it);
		return false;
	}

	pgd->pde[pdei] = pgt;
	return true;
}

static inline u64 nvkm_vmm_iter(struct nvkm_vmm *vmm, const struct nvkm_vmm_page *page, u64 addr, u64 size, const char *name, bool ref, bool (*REF_PTES)(struct nvkm_vmm_iter *, u32, u32), nvkm_vmm_pte_func MAP_PTES, struct nvkm_vmm_map *map, nvkm_vmm_pxe_func CLR_PTES)




{
	const struct nvkm_vmm_desc *desc = page->desc;
	struct nvkm_vmm_iter it;
	u64 bits = addr >> page->shift;

	it.page = page;
	it.desc = desc;
	it.vmm = vmm;
	it.cnt = size >> page->shift;
	it.flush = NVKM_VMM_LEVELS_MAX;

	
	for (it.lvl = 0; desc[it.lvl].bits; it.lvl++) {
		it.pte[it.lvl] = bits & ((1 << desc[it.lvl].bits) - 1);
		bits >>= desc[it.lvl].bits;
	}
	it.max = --it.lvl;
	it.pt[it.max] = vmm->pd;

	it.lvl = 0;
	TRA(&it, "%s: %016llx %016llx %d %lld PTEs", name, addr, size, page->shift, it.cnt);
	it.lvl = it.max;

	
	while (it.cnt) {
		struct nvkm_vmm_pt *pgt = it.pt[it.lvl];
		const int type = desc->type == SPT;
		const u32 pten = 1 << desc->bits;
		const u32 ptei = it.pte[0];
		const u32 ptes = min_t(u64, it.cnt, pten - ptei);

		
		for (; it.lvl; it.lvl--) {
			const u32 pdei = it.pte[it.lvl];
			struct nvkm_vmm_pt *pgd = pgt;

			
			if (ref && NVKM_VMM_PDE_INVALID(pgd->pde[pdei])) {
				if (!nvkm_vmm_ref_swpt(&it, pgd, pdei))
					goto fail;
			}
			it.pt[it.lvl - 1] = pgt = pgd->pde[pdei];

			
			if (ref && !pgt->refs[desc[it.lvl - 1].type == SPT]) {
				if (!nvkm_vmm_ref_hwpt(&it, pgd, pdei))
					goto fail;
			}
		}

		
		if (!REF_PTES || REF_PTES(&it, ptei, ptes)) {
			struct nvkm_mmu_pt *pt = pgt->pt[type];
			if (MAP_PTES || CLR_PTES) {
				if (MAP_PTES)
					MAP_PTES(vmm, pt, ptei, ptes, map);
				else CLR_PTES(vmm, pt, ptei, ptes);
				nvkm_vmm_flush_mark(&it);
			}
		}

		
		it.pte[it.lvl] += ptes;
		it.cnt -= ptes;
		if (it.cnt) {
			while (it.pte[it.lvl] == (1 << desc[it.lvl].bits)) {
				it.pte[it.lvl++] = 0;
				it.pte[it.lvl]++;
			}
		}
	};

	nvkm_vmm_flush(&it);
	return ~0ULL;

fail:
	
	addr = it.pte[it.max--];
	do {
		addr  = addr << desc[it.max].bits;
		addr |= it.pte[it.max];
	} while (it.max--);

	return addr << page->shift;
}

static void nvkm_vmm_ptes_sparse_put(struct nvkm_vmm *vmm, const struct nvkm_vmm_page *page, u64 addr, u64 size)

{
	nvkm_vmm_iter(vmm, page, addr, size, "sparse unref", false, nvkm_vmm_sparse_unref_ptes, NULL, NULL, page->desc->func->invalid ? page->desc->func->invalid : page->desc->func->unmap);


}

static int nvkm_vmm_ptes_sparse_get(struct nvkm_vmm *vmm, const struct nvkm_vmm_page *page, u64 addr, u64 size)

{
	if ((page->type & NVKM_VMM_PAGE_SPARSE)) {
		u64 fail = nvkm_vmm_iter(vmm, page, addr, size, "sparse ref", true, nvkm_vmm_sparse_ref_ptes, NULL, NULL, page->desc->func->sparse);

		if (fail != ~0ULL) {
			if ((size = fail - addr))
				nvkm_vmm_ptes_sparse_put(vmm, page, addr, size);
			return -ENOMEM;
		}
		return 0;
	}
	return -EINVAL;
}

static int nvkm_vmm_ptes_sparse(struct nvkm_vmm *vmm, u64 addr, u64 size, bool ref)
{
	const struct nvkm_vmm_page *page = vmm->func->page;
	int m = 0, i;
	u64 start = addr;
	u64 block;

	while (size) {
		
		while (size < (1ULL << page[m].shift))
			m++;
		i = m;

		
		while (!IS_ALIGNED(addr, 1ULL << page[i].shift))
			i++;

		
		if (i != m) {
			
			u64 next = 1ULL << page[i - 1].shift;
			u64 part = ALIGN(addr, next) - addr;
			if (size - part >= next)
				block = (part >> page[i].shift) << page[i].shift;
			else block = (size >> page[i].shift) << page[i].shift;
		} else {
			block = (size >> page[i].shift) << page[i].shift;
		}

		
		if (ref) {
			int ret = nvkm_vmm_ptes_sparse_get(vmm, &page[i], addr, block);
			if (ret) {
				if ((size = addr - start))
					nvkm_vmm_ptes_sparse(vmm, start, size, false);
				return ret;
			}
		} else {
			nvkm_vmm_ptes_sparse_put(vmm, &page[i], addr, block);
		}

		size -= block;
		addr += block;
	}

	return 0;
}

static void nvkm_vmm_ptes_unmap_put(struct nvkm_vmm *vmm, const struct nvkm_vmm_page *page, u64 addr, u64 size, bool sparse)

{
	const struct nvkm_vmm_desc_func *func = page->desc->func;
	nvkm_vmm_iter(vmm, page, addr, size, "unmap + unref", false, nvkm_vmm_unref_ptes, NULL, NULL, sparse ? func->sparse : func->invalid ? func->invalid :

							      func->unmap);
}

static int nvkm_vmm_ptes_get_map(struct nvkm_vmm *vmm, const struct nvkm_vmm_page *page, u64 addr, u64 size, struct nvkm_vmm_map *map, nvkm_vmm_pte_func func)


{
	u64 fail = nvkm_vmm_iter(vmm, page, addr, size, "ref + map", true, nvkm_vmm_ref_ptes, func, map, NULL);
	if (fail != ~0ULL) {
		if ((size = fail - addr))
			nvkm_vmm_ptes_unmap_put(vmm, page, addr, size, false);
		return -ENOMEM;
	}
	return 0;
}

static void nvkm_vmm_ptes_unmap(struct nvkm_vmm *vmm, const struct nvkm_vmm_page *page, u64 addr, u64 size, bool sparse)

{
	const struct nvkm_vmm_desc_func *func = page->desc->func;
	nvkm_vmm_iter(vmm, page, addr, size, "unmap", false, NULL, NULL, NULL, sparse ? func->sparse : func->invalid ? func->invalid :
							      func->unmap);
}

static void nvkm_vmm_ptes_map(struct nvkm_vmm *vmm, const struct nvkm_vmm_page *page, u64 addr, u64 size, struct nvkm_vmm_map *map, nvkm_vmm_pte_func func)


{
	nvkm_vmm_iter(vmm, page, addr, size, "map", false, NULL, func, map, NULL);
}

static void nvkm_vmm_ptes_put(struct nvkm_vmm *vmm, const struct nvkm_vmm_page *page, u64 addr, u64 size)

{
	nvkm_vmm_iter(vmm, page, addr, size, "unref", false, nvkm_vmm_unref_ptes, NULL, NULL, NULL);
}

static int nvkm_vmm_ptes_get(struct nvkm_vmm *vmm, const struct nvkm_vmm_page *page, u64 addr, u64 size)

{
	u64 fail = nvkm_vmm_iter(vmm, page, addr, size, "ref", true, nvkm_vmm_ref_ptes, NULL, NULL, NULL);
	if (fail != ~0ULL) {
		if (fail != addr)
			nvkm_vmm_ptes_put(vmm, page, addr, fail - addr);
		return -ENOMEM;
	}
	return 0;
}

static inline struct nvkm_vma * nvkm_vma_new(u64 addr, u64 size)
{
	struct nvkm_vma *vma = kzalloc(sizeof(*vma), GFP_KERNEL);
	if (vma) {
		vma->addr = addr;
		vma->size = size;
		vma->page = NVKM_VMA_PAGE_NONE;
		vma->refd = NVKM_VMA_PAGE_NONE;
	}
	return vma;
}

struct nvkm_vma * nvkm_vma_tail(struct nvkm_vma *vma, u64 tail)
{
	struct nvkm_vma *new;

	BUG_ON(vma->size == tail);

	if (!(new = nvkm_vma_new(vma->addr + (vma->size - tail), tail)))
		return NULL;
	vma->size -= tail;

	new->mapref = vma->mapref;
	new->sparse = vma->sparse;
	new->page = vma->page;
	new->refd = vma->refd;
	new->used = vma->used;
	new->part = vma->part;
	new->user = vma->user;
	new->busy = vma->busy;
	list_add(&new->head, &vma->head);
	return new;
}

static void nvkm_vmm_free_insert(struct nvkm_vmm *vmm, struct nvkm_vma *vma)
{
	struct rb_node **ptr = &vmm->free.rb_node;
	struct rb_node *parent = NULL;

	while (*ptr) {
		struct nvkm_vma *this = rb_entry(*ptr, typeof(*this), tree);
		parent = *ptr;
		if (vma->size < this->size)
			ptr = &parent->rb_left;
		else if (vma->size > this->size)
			ptr = &parent->rb_right;
		else if (vma->addr < this->addr)
			ptr = &parent->rb_left;
		else if (vma->addr > this->addr)
			ptr = &parent->rb_right;
		else BUG();
	}

	rb_link_node(&vma->tree, parent, ptr);
	rb_insert_color(&vma->tree, &vmm->free);
}

void nvkm_vmm_node_insert(struct nvkm_vmm *vmm, struct nvkm_vma *vma)
{
	struct rb_node **ptr = &vmm->root.rb_node;
	struct rb_node *parent = NULL;

	while (*ptr) {
		struct nvkm_vma *this = rb_entry(*ptr, typeof(*this), tree);
		parent = *ptr;
		if (vma->addr < this->addr)
			ptr = &parent->rb_left;
		else if (vma->addr > this->addr)
			ptr = &parent->rb_right;
		else BUG();
	}

	rb_link_node(&vma->tree, parent, ptr);
	rb_insert_color(&vma->tree, &vmm->root);
}

struct nvkm_vma * nvkm_vmm_node_search(struct nvkm_vmm *vmm, u64 addr)
{
	struct rb_node *node = vmm->root.rb_node;
	while (node) {
		struct nvkm_vma *vma = rb_entry(node, typeof(*vma), tree);
		if (addr < vma->addr)
			node = node->rb_left;
		else if (addr >= vma->addr + vma->size)
			node = node->rb_right;
		else return vma;
	}
	return NULL;
}

static void nvkm_vmm_dtor(struct nvkm_vmm *vmm)
{
	struct nvkm_vma *vma;
	struct rb_node *node;

	while ((node = rb_first(&vmm->root))) {
		struct nvkm_vma *vma = rb_entry(node, typeof(*vma), tree);
		nvkm_vmm_put(vmm, &vma);
	}

	if (vmm->bootstrapped) {
		const struct nvkm_vmm_page *page = vmm->func->page;
		const u64 limit = vmm->limit - vmm->start;

		while (page[1].shift)
			page++;

		nvkm_mmu_ptc_dump(vmm->mmu);
		nvkm_vmm_ptes_put(vmm, page, vmm->start, limit);
	}

	vma = list_first_entry(&vmm->list, typeof(*vma), head);
	list_del(&vma->head);
	kfree(vma);
	WARN_ON(!list_empty(&vmm->list));

	if (vmm->nullp) {
		dma_free_coherent(vmm->mmu->subdev.device->dev, 16 * 1024, vmm->nullp, vmm->null);
	}

	if (vmm->pd) {
		nvkm_mmu_ptc_put(vmm->mmu, true, &vmm->pd->pt[0]);
		nvkm_vmm_pt_del(&vmm->pd);
	}
}

int nvkm_vmm_ctor(const struct nvkm_vmm_func *func, struct nvkm_mmu *mmu, u32 pd_header, u64 addr, u64 size, struct lock_class_key *key, const char *name, struct nvkm_vmm *vmm)


{
	static struct lock_class_key _key;
	const struct nvkm_vmm_page *page = func->page;
	const struct nvkm_vmm_desc *desc;
	struct nvkm_vma *vma;
	int levels, bits = 0;

	vmm->func = func;
	vmm->mmu = mmu;
	vmm->name = name;
	vmm->debug = mmu->subdev.debug;
	kref_init(&vmm->kref);

	__mutex_init(&vmm->mutex, "&vmm->mutex", key ? key : &_key);

	
	while (page[1].shift)
		page++;

	
	for (levels = 0, desc = page->desc; desc->bits; desc++, levels++)
		bits += desc->bits;
	bits += page->shift;
	desc--;

	if (WARN_ON(levels > NVKM_VMM_LEVELS_MAX))
		return -EINVAL;

	vmm->start = addr;
	vmm->limit = size ? (addr + size) : (1ULL << bits);
	if (vmm->start > vmm->limit || vmm->limit > (1ULL << bits))
		return -EINVAL;

	
	vmm->pd = nvkm_vmm_pt_new(desc, false, NULL);
	if (!vmm->pd)
		return -ENOMEM;
	vmm->pd->refs[0] = 1;
	INIT_LIST_HEAD(&vmm->join);

	
	if (desc->size) {
		const u32 size = pd_header + desc->size * (1 << desc->bits);
		vmm->pd->pt[0] = nvkm_mmu_ptc_get(mmu, size, desc->align, true);
		if (!vmm->pd->pt[0])
			return -ENOMEM;
	}

	
	INIT_LIST_HEAD(&vmm->list);
	vmm->free = RB_ROOT;
	vmm->root = RB_ROOT;

	if (!(vma = nvkm_vma_new(vmm->start, vmm->limit - vmm->start)))
		return -ENOMEM;

	nvkm_vmm_free_insert(vmm, vma);
	list_add(&vma->head, &vmm->list);
	return 0;
}

int nvkm_vmm_new_(const struct nvkm_vmm_func *func, struct nvkm_mmu *mmu, u32 hdr, u64 addr, u64 size, struct lock_class_key *key, const char *name, struct nvkm_vmm **pvmm)


{
	if (!(*pvmm = kzalloc(sizeof(**pvmm), GFP_KERNEL)))
		return -ENOMEM;
	return nvkm_vmm_ctor(func, mmu, hdr, addr, size, key, name, *pvmm);
}



void nvkm_vmm_unmap_region(struct nvkm_vmm *vmm, struct nvkm_vma *vma)
{
	struct nvkm_vma *next;

	nvkm_memory_tags_put(vma->memory, vmm->mmu->subdev.device, &vma->tags);
	nvkm_memory_unref(&vma->memory);

	if (vma->part) {
		struct nvkm_vma *prev = node(vma, prev);
		if (!prev->memory) {
			prev->size += vma->size;
			rb_erase(&vma->tree, &vmm->root);
			list_del(&vma->head);
			kfree(vma);
			vma = prev;
		}
	}

	next = node(vma, next);
	if (next && next->part) {
		if (!next->memory) {
			vma->size += next->size;
			rb_erase(&next->tree, &vmm->root);
			list_del(&next->head);
			kfree(next);
		}
	}
}

void nvkm_vmm_unmap_locked(struct nvkm_vmm *vmm, struct nvkm_vma *vma)
{
	const struct nvkm_vmm_page *page = &vmm->func->page[vma->refd];

	if (vma->mapref) {
		nvkm_vmm_ptes_unmap_put(vmm, page, vma->addr, vma->size, vma->sparse);
		vma->refd = NVKM_VMA_PAGE_NONE;
	} else {
		nvkm_vmm_ptes_unmap(vmm, page, vma->addr, vma->size, vma->sparse);
	}

	nvkm_vmm_unmap_region(vmm, vma);
}

void nvkm_vmm_unmap(struct nvkm_vmm *vmm, struct nvkm_vma *vma)
{
	if (vma->memory) {
		mutex_lock(&vmm->mutex);
		nvkm_vmm_unmap_locked(vmm, vma);
		mutex_unlock(&vmm->mutex);
	}
}

static int nvkm_vmm_map_valid(struct nvkm_vmm *vmm, struct nvkm_vma *vma, void *argv, u32 argc, struct nvkm_vmm_map *map)

{
	switch (nvkm_memory_target(map->memory)) {
	case NVKM_MEM_TARGET_VRAM:
		if (!(map->page->type & NVKM_VMM_PAGE_VRAM)) {
			VMM_DEBUG(vmm, "%d !VRAM", map->page->shift);
			return -EINVAL;
		}
		break;
	case NVKM_MEM_TARGET_HOST:
	case NVKM_MEM_TARGET_NCOH:
		if (!(map->page->type & NVKM_VMM_PAGE_HOST)) {
			VMM_DEBUG(vmm, "%d !HOST", map->page->shift);
			return -EINVAL;
		}
		break;
	default:
		WARN_ON(1);
		return -ENOSYS;
	}

	if (!IS_ALIGNED(     vma->addr, 1ULL << map->page->shift) || !IS_ALIGNED((u64)vma->size, 1ULL << map->page->shift) || !IS_ALIGNED(   map->offset, 1ULL << map->page->shift) || nvkm_memory_page(map->memory) < map->page->shift) {


		VMM_DEBUG(vmm, "alignment %016llx %016llx %016llx %d %d", vma->addr, (u64)vma->size, map->offset, map->page->shift, nvkm_memory_page(map->memory));

		return -EINVAL;
	}

	return vmm->func->valid(vmm, argv, argc, map);
}

static int nvkm_vmm_map_choose(struct nvkm_vmm *vmm, struct nvkm_vma *vma, void *argv, u32 argc, struct nvkm_vmm_map *map)

{
	for (map->page = vmm->func->page; map->page->shift; map->page++) {
		VMM_DEBUG(vmm, "trying %d", map->page->shift);
		if (!nvkm_vmm_map_valid(vmm, vma, argv, argc, map))
			return 0;
	}
	return -EINVAL;
}

static int nvkm_vmm_map_locked(struct nvkm_vmm *vmm, struct nvkm_vma *vma, void *argv, u32 argc, struct nvkm_vmm_map *map)

{
	nvkm_vmm_pte_func func;
	int ret;

	
	if (unlikely(nvkm_memory_size(map->memory) < map->offset + vma->size)) {
		VMM_DEBUG(vmm, "overrun %016llx %016llx %016llx", nvkm_memory_size(map->memory), map->offset, (u64)vma->size);

		return -EINVAL;
	}

	
	if (vma->page == NVKM_VMA_PAGE_NONE && vma->refd == NVKM_VMA_PAGE_NONE) {
		
		const u32 debug = vmm->debug;
		vmm->debug = 0;
		ret = nvkm_vmm_map_choose(vmm, vma, argv, argc, map);
		vmm->debug = debug;
		if (ret) {
			VMM_DEBUG(vmm, "invalid at any page size");
			nvkm_vmm_map_choose(vmm, vma, argv, argc, map);
			return -EINVAL;
		}
	} else {
		
		if (vma->refd != NVKM_VMA_PAGE_NONE)
			map->page = &vmm->func->page[vma->refd];
		else map->page = &vmm->func->page[vma->page];

		ret = nvkm_vmm_map_valid(vmm, vma, argv, argc, map);
		if (ret) {
			VMM_DEBUG(vmm, "invalid %d\n", ret);
			return ret;
		}
	}

	
	map->off = map->offset;
	if (map->mem) {
		for (; map->off; map->mem = map->mem->next) {
			u64 size = (u64)map->mem->length << NVKM_RAM_MM_SHIFT;
			if (size > map->off)
				break;
			map->off -= size;
		}
		func = map->page->desc->func->mem;
	} else if (map->sgl) {
		for (; map->off; map->sgl = sg_next(map->sgl)) {
			u64 size = sg_dma_len(map->sgl);
			if (size > map->off)
				break;
			map->off -= size;
		}
		func = map->page->desc->func->sgl;
	} else {
		map->dma += map->offset >> PAGE_SHIFT;
		map->off  = map->offset & PAGE_MASK;
		func = map->page->desc->func->dma;
	}

	
	if (vma->refd == NVKM_VMA_PAGE_NONE) {
		ret = nvkm_vmm_ptes_get_map(vmm, map->page, vma->addr, vma->size, map, func);
		if (ret)
			return ret;

		vma->refd = map->page - vmm->func->page;
	} else {
		nvkm_vmm_ptes_map(vmm, map->page, vma->addr, vma->size, map, func);
	}

	nvkm_memory_tags_put(vma->memory, vmm->mmu->subdev.device, &vma->tags);
	nvkm_memory_unref(&vma->memory);
	vma->memory = nvkm_memory_ref(map->memory);
	vma->tags = map->tags;
	return 0;
}

int nvkm_vmm_map(struct nvkm_vmm *vmm, struct nvkm_vma *vma, void *argv, u32 argc, struct nvkm_vmm_map *map)

{
	int ret;
	mutex_lock(&vmm->mutex);
	ret = nvkm_vmm_map_locked(vmm, vma, argv, argc, map);
	vma->busy = false;
	mutex_unlock(&vmm->mutex);
	return ret;
}

static void nvkm_vmm_put_region(struct nvkm_vmm *vmm, struct nvkm_vma *vma)
{
	struct nvkm_vma *prev, *next;

	if ((prev = node(vma, prev)) && !prev->used) {
		rb_erase(&prev->tree, &vmm->free);
		list_del(&prev->head);
		vma->addr  = prev->addr;
		vma->size += prev->size;
		kfree(prev);
	}

	if ((next = node(vma, next)) && !next->used) {
		rb_erase(&next->tree, &vmm->free);
		list_del(&next->head);
		vma->size += next->size;
		kfree(next);
	}

	nvkm_vmm_free_insert(vmm, vma);
}

void nvkm_vmm_put_locked(struct nvkm_vmm *vmm, struct nvkm_vma *vma)
{
	const struct nvkm_vmm_page *page = vmm->func->page;
	struct nvkm_vma *next = vma;

	BUG_ON(vma->part);

	if (vma->mapref || !vma->sparse) {
		do {
			const bool map = next->memory != NULL;
			const u8  refd = next->refd;
			const u64 addr = next->addr;
			u64 size = next->size;

			
			while ((next = node(next, next)) && next->part && (next->memory != NULL) == map && (next->refd == refd))

				size += next->size;

			if (map) {
				
				nvkm_vmm_ptes_unmap_put(vmm, &page[refd], addr, size, vma->sparse);
			} else if (refd != NVKM_VMA_PAGE_NONE) {
				
				nvkm_vmm_ptes_put(vmm, &page[refd], addr, size);
			}
		} while (next && next->part);
	}

	
	next = vma;
	do {
		if (next->memory)
			nvkm_vmm_unmap_region(vmm, next);
	} while ((next = node(vma, next)) && next->part);

	if (vma->sparse && !vma->mapref) {
		
		nvkm_vmm_ptes_sparse_put(vmm, &page[vma->refd], vma->addr, vma->size);
	} else if (vma->sparse) {
		
		nvkm_vmm_ptes_sparse(vmm, vma->addr, vma->size, false);
	}

	
	rb_erase(&vma->tree, &vmm->root);

	
	vma->page = NVKM_VMA_PAGE_NONE;
	vma->refd = NVKM_VMA_PAGE_NONE;
	vma->used = false;
	vma->user = false;
	nvkm_vmm_put_region(vmm, vma);
}

void nvkm_vmm_put(struct nvkm_vmm *vmm, struct nvkm_vma **pvma)
{
	struct nvkm_vma *vma = *pvma;
	if (vma) {
		mutex_lock(&vmm->mutex);
		nvkm_vmm_put_locked(vmm, vma);
		mutex_unlock(&vmm->mutex);
		*pvma = NULL;
	}
}

int nvkm_vmm_get_locked(struct nvkm_vmm *vmm, bool getref, bool mapref, bool sparse, u8 shift, u8 align, u64 size, struct nvkm_vma **pvma)

{
	const struct nvkm_vmm_page *page = &vmm->func->page[NVKM_VMA_PAGE_NONE];
	struct rb_node *node = NULL, *temp;
	struct nvkm_vma *vma = NULL, *tmp;
	u64 addr, tail;
	int ret;

	VMM_TRACE(vmm, "getref %d mapref %d sparse %d " "shift: %d align: %d size: %016llx", getref, mapref, sparse, shift, align, size);


	
	if (unlikely(!size || (!getref && !mapref && sparse))) {
		VMM_DEBUG(vmm, "args %016llx %d %d %d", size, getref, mapref, sparse);
		return -EINVAL;
	}

	
	if (unlikely((getref || vmm->func->page_block) && !shift)) {
		VMM_DEBUG(vmm, "page size required: %d %016llx", getref, vmm->func->page_block);
		return -EINVAL;
	}

	
	if (shift) {
		for (page = vmm->func->page; page->shift; page++) {
			if (shift == page->shift)
				break;
		}

		if (!page->shift || !IS_ALIGNED(size, 1ULL << page->shift)) {
			VMM_DEBUG(vmm, "page %d %016llx", shift, size);
			return -EINVAL;
		}
		align = max_t(u8, align, shift);
	} else {
		align = max_t(u8, align, 12);
	}

	
	temp = vmm->free.rb_node;
	while (temp) {
		struct nvkm_vma *this = rb_entry(temp, typeof(*this), tree);
		if (this->size < size) {
			temp = temp->rb_right;
		} else {
			node = temp;
			temp = temp->rb_left;
		}
	}

	if (unlikely(!node))
		return -ENOSPC;

	
	do {
		struct nvkm_vma *this = rb_entry(node, typeof(*this), tree);
		struct nvkm_vma *prev = node(this, prev);
		struct nvkm_vma *next = node(this, next);
		const int p = page - vmm->func->page;

		addr = this->addr;
		if (vmm->func->page_block && prev && prev->page != p)
			addr = ALIGN(addr, vmm->func->page_block);
		addr = ALIGN(addr, 1ULL << align);

		tail = this->addr + this->size;
		if (vmm->func->page_block && next && next->page != p)
			tail = ALIGN_DOWN(tail, vmm->func->page_block);

		if (addr <= tail && tail - addr >= size) {
			rb_erase(&this->tree, &vmm->free);
			vma = this;
			break;
		}
	} while ((node = rb_next(node)));

	if (unlikely(!vma))
		return -ENOSPC;

	
	if (addr != vma->addr) {
		if (!(tmp = nvkm_vma_tail(vma, vma->size + vma->addr - addr))) {
			nvkm_vmm_put_region(vmm, vma);
			return -ENOMEM;
		}
		nvkm_vmm_free_insert(vmm, vma);
		vma = tmp;
	}

	if (size != vma->size) {
		if (!(tmp = nvkm_vma_tail(vma, vma->size - size))) {
			nvkm_vmm_put_region(vmm, vma);
			return -ENOMEM;
		}
		nvkm_vmm_free_insert(vmm, tmp);
	}

	
	if (sparse && getref)
		ret = nvkm_vmm_ptes_sparse_get(vmm, page, vma->addr, vma->size);
	else if (sparse)
		ret = nvkm_vmm_ptes_sparse(vmm, vma->addr, vma->size, true);
	else if (getref)
		ret = nvkm_vmm_ptes_get(vmm, page, vma->addr, vma->size);
	else ret = 0;
	if (ret) {
		nvkm_vmm_put_region(vmm, vma);
		return ret;
	}

	vma->mapref = mapref && !getref;
	vma->sparse = sparse;
	vma->page = page - vmm->func->page;
	vma->refd = getref ? vma->page : NVKM_VMA_PAGE_NONE;
	vma->used = true;
	nvkm_vmm_node_insert(vmm, vma);
	*pvma = vma;
	return 0;
}

int nvkm_vmm_get(struct nvkm_vmm *vmm, u8 page, u64 size, struct nvkm_vma **pvma)
{
	int ret;
	mutex_lock(&vmm->mutex);
	ret = nvkm_vmm_get_locked(vmm, false, true, false, page, 0, size, pvma);
	mutex_unlock(&vmm->mutex);
	return ret;
}

void nvkm_vmm_part(struct nvkm_vmm *vmm, struct nvkm_memory *inst)
{
	if (inst && vmm->func->part) {
		mutex_lock(&vmm->mutex);
		vmm->func->part(vmm, inst);
		mutex_unlock(&vmm->mutex);
	}
}

int nvkm_vmm_join(struct nvkm_vmm *vmm, struct nvkm_memory *inst)
{
	int ret = 0;
	if (vmm->func->join) {
		mutex_lock(&vmm->mutex);
		ret = vmm->func->join(vmm, inst);
		mutex_unlock(&vmm->mutex);
	}
	return ret;
}

static bool nvkm_vmm_boot_ptes(struct nvkm_vmm_iter *it, u32 ptei, u32 ptes)
{
	const struct nvkm_vmm_desc *desc = it->desc;
	const int type = desc->type == SPT;
	nvkm_memory_boot(it->pt[0]->pt[type]->memory, it->vmm);
	return false;
}

int nvkm_vmm_boot(struct nvkm_vmm *vmm)
{
	const struct nvkm_vmm_page *page = vmm->func->page;
	const u64 limit = vmm->limit - vmm->start;
	int ret;

	while (page[1].shift)
		page++;

	ret = nvkm_vmm_ptes_get(vmm, page, vmm->start, limit);
	if (ret)
		return ret;

	nvkm_vmm_iter(vmm, page, vmm->start, limit, "bootstrap", false, nvkm_vmm_boot_ptes, NULL, NULL, NULL);
	vmm->bootstrapped = true;
	return 0;
}

static void nvkm_vmm_del(struct kref *kref)
{
	struct nvkm_vmm *vmm = container_of(kref, typeof(*vmm), kref);
	nvkm_vmm_dtor(vmm);
	kfree(vmm);
}

void nvkm_vmm_unref(struct nvkm_vmm **pvmm)
{
	struct nvkm_vmm *vmm = *pvmm;
	if (vmm) {
		kref_put(&vmm->kref, nvkm_vmm_del);
		*pvmm = NULL;
	}
}

struct nvkm_vmm * nvkm_vmm_ref(struct nvkm_vmm *vmm)
{
	if (vmm)
		kref_get(&vmm->kref);
	return vmm;
}

int nvkm_vmm_new(struct nvkm_device *device, u64 addr, u64 size, void *argv, u32 argc, struct lock_class_key *key, const char *name, struct nvkm_vmm **pvmm)


{
	struct nvkm_mmu *mmu = device->mmu;
	struct nvkm_vmm *vmm = NULL;
	int ret;
	ret = mmu->func->vmm.ctor(mmu, addr, size, argv, argc, key, name, &vmm);
	if (ret)
		nvkm_vmm_unref(&vmm);
	*pvmm = vmm;
	return ret;
}
