


































static struct kmem_cache *anon_vma_cachep;
static struct kmem_cache *anon_vma_chain_cachep;

static inline struct anon_vma *anon_vma_alloc(void)
{
	struct anon_vma *anon_vma;

	anon_vma = kmem_cache_alloc(anon_vma_cachep, GFP_KERNEL);
	if (anon_vma) {
		atomic_set(&anon_vma->refcount, 1);
		anon_vma->degree = 1;	
		anon_vma->parent = anon_vma;
		
		anon_vma->root = anon_vma;
	}

	return anon_vma;
}

static inline void anon_vma_free(struct anon_vma *anon_vma)
{
	VM_BUG_ON(atomic_read(&anon_vma->refcount));

	
	might_sleep();
	if (rwsem_is_locked(&anon_vma->root->rwsem)) {
		anon_vma_lock_write(anon_vma);
		anon_vma_unlock_write(anon_vma);
	}

	kmem_cache_free(anon_vma_cachep, anon_vma);
}

static inline struct anon_vma_chain *anon_vma_chain_alloc(gfp_t gfp)
{
	return kmem_cache_alloc(anon_vma_chain_cachep, gfp);
}

static void anon_vma_chain_free(struct anon_vma_chain *anon_vma_chain)
{
	kmem_cache_free(anon_vma_chain_cachep, anon_vma_chain);
}

static void anon_vma_chain_link(struct vm_area_struct *vma, struct anon_vma_chain *avc, struct anon_vma *anon_vma)

{
	avc->vma = vma;
	avc->anon_vma = anon_vma;
	list_add(&avc->same_vma, &vma->anon_vma_chain);
	anon_vma_interval_tree_insert(avc, &anon_vma->rb_root);
}


int __anon_vma_prepare(struct vm_area_struct *vma)
{
	struct mm_struct *mm = vma->vm_mm;
	struct anon_vma *anon_vma, *allocated;
	struct anon_vma_chain *avc;

	might_sleep();

	avc = anon_vma_chain_alloc(GFP_KERNEL);
	if (!avc)
		goto out_enomem;

	anon_vma = find_mergeable_anon_vma(vma);
	allocated = NULL;
	if (!anon_vma) {
		anon_vma = anon_vma_alloc();
		if (unlikely(!anon_vma))
			goto out_enomem_free_avc;
		allocated = anon_vma;
	}

	anon_vma_lock_write(anon_vma);
	
	spin_lock(&mm->page_table_lock);
	if (likely(!vma->anon_vma)) {
		vma->anon_vma = anon_vma;
		anon_vma_chain_link(vma, avc, anon_vma);
		
		anon_vma->degree++;
		allocated = NULL;
		avc = NULL;
	}
	spin_unlock(&mm->page_table_lock);
	anon_vma_unlock_write(anon_vma);

	if (unlikely(allocated))
		put_anon_vma(allocated);
	if (unlikely(avc))
		anon_vma_chain_free(avc);

	return 0;

 out_enomem_free_avc:
	anon_vma_chain_free(avc);
 out_enomem:
	return -ENOMEM;
}


static inline struct anon_vma *lock_anon_vma_root(struct anon_vma *root, struct anon_vma *anon_vma)
{
	struct anon_vma *new_root = anon_vma->root;
	if (new_root != root) {
		if (WARN_ON_ONCE(root))
			up_write(&root->rwsem);
		root = new_root;
		down_write(&root->rwsem);
	}
	return root;
}

static inline void unlock_anon_vma_root(struct anon_vma *root)
{
	if (root)
		up_write(&root->rwsem);
}


int anon_vma_clone(struct vm_area_struct *dst, struct vm_area_struct *src)
{
	struct anon_vma_chain *avc, *pavc;
	struct anon_vma *root = NULL;

	list_for_each_entry_reverse(pavc, &src->anon_vma_chain, same_vma) {
		struct anon_vma *anon_vma;

		avc = anon_vma_chain_alloc(GFP_NOWAIT | __GFP_NOWARN);
		if (unlikely(!avc)) {
			unlock_anon_vma_root(root);
			root = NULL;
			avc = anon_vma_chain_alloc(GFP_KERNEL);
			if (!avc)
				goto enomem_failure;
		}
		anon_vma = pavc->anon_vma;
		root = lock_anon_vma_root(root, anon_vma);
		anon_vma_chain_link(dst, avc, anon_vma);

		
		if (!dst->anon_vma && src->anon_vma && anon_vma != src->anon_vma && anon_vma->degree < 2)
			dst->anon_vma = anon_vma;
	}
	if (dst->anon_vma)
		dst->anon_vma->degree++;
	unlock_anon_vma_root(root);
	return 0;

 enomem_failure:
	
	dst->anon_vma = NULL;
	unlink_anon_vmas(dst);
	return -ENOMEM;
}


int anon_vma_fork(struct vm_area_struct *vma, struct vm_area_struct *pvma)
{
	struct anon_vma_chain *avc;
	struct anon_vma *anon_vma;
	int error;

	
	if (!pvma->anon_vma)
		return 0;

	
	vma->anon_vma = NULL;

	
	error = anon_vma_clone(vma, pvma);
	if (error)
		return error;

	
	if (vma->anon_vma)
		return 0;

	
	anon_vma = anon_vma_alloc();
	if (!anon_vma)
		goto out_error;
	avc = anon_vma_chain_alloc(GFP_KERNEL);
	if (!avc)
		goto out_error_free_anon_vma;

	
	anon_vma->root = pvma->anon_vma->root;
	anon_vma->parent = pvma->anon_vma;
	
	get_anon_vma(anon_vma->root);
	
	vma->anon_vma = anon_vma;
	anon_vma_lock_write(anon_vma);
	anon_vma_chain_link(vma, avc, anon_vma);
	anon_vma->parent->degree++;
	anon_vma_unlock_write(anon_vma);

	return 0;

 out_error_free_anon_vma:
	put_anon_vma(anon_vma);
 out_error:
	unlink_anon_vmas(vma);
	return -ENOMEM;
}

void unlink_anon_vmas(struct vm_area_struct *vma)
{
	struct anon_vma_chain *avc, *next;
	struct anon_vma *root = NULL;

	
	list_for_each_entry_safe(avc, next, &vma->anon_vma_chain, same_vma) {
		struct anon_vma *anon_vma = avc->anon_vma;

		root = lock_anon_vma_root(root, anon_vma);
		anon_vma_interval_tree_remove(avc, &anon_vma->rb_root);

		
		if (RB_EMPTY_ROOT(&anon_vma->rb_root.rb_root)) {
			anon_vma->parent->degree--;
			continue;
		}

		list_del(&avc->same_vma);
		anon_vma_chain_free(avc);
	}
	if (vma->anon_vma) {
		vma->anon_vma->degree--;

		
		vma->anon_vma = NULL;
	}
	unlock_anon_vma_root(root);

	
	list_for_each_entry_safe(avc, next, &vma->anon_vma_chain, same_vma) {
		struct anon_vma *anon_vma = avc->anon_vma;

		VM_WARN_ON(anon_vma->degree);
		put_anon_vma(anon_vma);

		list_del(&avc->same_vma);
		anon_vma_chain_free(avc);
	}
}

static void anon_vma_ctor(void *data)
{
	struct anon_vma *anon_vma = data;

	init_rwsem(&anon_vma->rwsem);
	atomic_set(&anon_vma->refcount, 0);
	anon_vma->rb_root = RB_ROOT_CACHED;
}

void __init anon_vma_init(void)
{
	anon_vma_cachep = kmem_cache_create("anon_vma", sizeof(struct anon_vma), 0, SLAB_TYPESAFE_BY_RCU|SLAB_PANIC|SLAB_ACCOUNT, anon_vma_ctor);

	anon_vma_chain_cachep = KMEM_CACHE(anon_vma_chain, SLAB_PANIC|SLAB_ACCOUNT);
}


struct anon_vma *page_get_anon_vma(struct page *page)
{
	struct anon_vma *anon_vma = NULL;
	unsigned long anon_mapping;

	rcu_read_lock();
	anon_mapping = (unsigned long)READ_ONCE(page->mapping);
	if ((anon_mapping & PAGE_MAPPING_FLAGS) != PAGE_MAPPING_ANON)
		goto out;
	if (!page_mapped(page))
		goto out;

	anon_vma = (struct anon_vma *) (anon_mapping - PAGE_MAPPING_ANON);
	if (!atomic_inc_not_zero(&anon_vma->refcount)) {
		anon_vma = NULL;
		goto out;
	}

	
	if (!page_mapped(page)) {
		rcu_read_unlock();
		put_anon_vma(anon_vma);
		return NULL;
	}
out:
	rcu_read_unlock();

	return anon_vma;
}


struct anon_vma *folio_lock_anon_vma_read(struct folio *folio, struct rmap_walk_control *rwc)
{
	struct anon_vma *anon_vma = NULL;
	struct anon_vma *root_anon_vma;
	unsigned long anon_mapping;

	rcu_read_lock();
	anon_mapping = (unsigned long)READ_ONCE(folio->mapping);
	if ((anon_mapping & PAGE_MAPPING_FLAGS) != PAGE_MAPPING_ANON)
		goto out;
	if (!folio_mapped(folio))
		goto out;

	anon_vma = (struct anon_vma *) (anon_mapping - PAGE_MAPPING_ANON);
	root_anon_vma = READ_ONCE(anon_vma->root);
	if (down_read_trylock(&root_anon_vma->rwsem)) {
		
		if (!folio_mapped(folio)) {
			up_read(&root_anon_vma->rwsem);
			anon_vma = NULL;
		}
		goto out;
	}

	if (rwc && rwc->try_lock) {
		anon_vma = NULL;
		rwc->contended = true;
		goto out;
	}

	
	if (!atomic_inc_not_zero(&anon_vma->refcount)) {
		anon_vma = NULL;
		goto out;
	}

	if (!folio_mapped(folio)) {
		rcu_read_unlock();
		put_anon_vma(anon_vma);
		return NULL;
	}

	
	rcu_read_unlock();
	anon_vma_lock_read(anon_vma);

	if (atomic_dec_and_test(&anon_vma->refcount)) {
		
		anon_vma_unlock_read(anon_vma);
		__put_anon_vma(anon_vma);
		anon_vma = NULL;
	}

	return anon_vma;

out:
	rcu_read_unlock();
	return anon_vma;
}

void page_unlock_anon_vma_read(struct anon_vma *anon_vma)
{
	anon_vma_unlock_read(anon_vma);
}



void try_to_unmap_flush(void)
{
	struct tlbflush_unmap_batch *tlb_ubc = &current->tlb_ubc;

	if (!tlb_ubc->flush_required)
		return;

	arch_tlbbatch_flush(&tlb_ubc->arch);
	tlb_ubc->flush_required = false;
	tlb_ubc->writable = false;
}


void try_to_unmap_flush_dirty(void)
{
	struct tlbflush_unmap_batch *tlb_ubc = &current->tlb_ubc;

	if (tlb_ubc->writable)
		try_to_unmap_flush();
}






static void set_tlb_ubc_flush_pending(struct mm_struct *mm, bool writable)
{
	struct tlbflush_unmap_batch *tlb_ubc = &current->tlb_ubc;
	int batch, nbatch;

	arch_tlbbatch_add_mm(&tlb_ubc->arch, mm);
	tlb_ubc->flush_required = true;

	
	barrier();
	batch = atomic_read(&mm->tlb_flush_batched);
retry:
	if ((batch & TLB_FLUSH_BATCH_PENDING_MASK) > TLB_FLUSH_BATCH_PENDING_LARGE) {
		
		nbatch = atomic_cmpxchg(&mm->tlb_flush_batched, batch, 1);
		if (nbatch != batch) {
			batch = nbatch;
			goto retry;
		}
	} else {
		atomic_inc(&mm->tlb_flush_batched);
	}

	
	if (writable)
		tlb_ubc->writable = true;
}


static bool should_defer_flush(struct mm_struct *mm, enum ttu_flags flags)
{
	bool should_defer = false;

	if (!(flags & TTU_BATCH_FLUSH))
		return false;

	
	if (cpumask_any_but(mm_cpumask(mm), get_cpu()) < nr_cpu_ids)
		should_defer = true;
	put_cpu();

	return should_defer;
}


void flush_tlb_batched_pending(struct mm_struct *mm)
{
	int batch = atomic_read(&mm->tlb_flush_batched);
	int pending = batch & TLB_FLUSH_BATCH_PENDING_MASK;
	int flushed = batch >> TLB_FLUSH_BATCH_FLUSHED_SHIFT;

	if (pending != flushed) {
		flush_tlb_mm(mm);
		
		atomic_cmpxchg(&mm->tlb_flush_batched, batch, pending | (pending << TLB_FLUSH_BATCH_FLUSHED_SHIFT));
	}
}

static void set_tlb_ubc_flush_pending(struct mm_struct *mm, bool writable)
{
}

static bool should_defer_flush(struct mm_struct *mm, enum ttu_flags flags)
{
	return false;
}



unsigned long page_address_in_vma(struct page *page, struct vm_area_struct *vma)
{
	struct folio *folio = page_folio(page);
	if (folio_test_anon(folio)) {
		struct anon_vma *page__anon_vma = folio_anon_vma(folio);
		
		if (!vma->anon_vma || !page__anon_vma || vma->anon_vma->root != page__anon_vma->root)
			return -EFAULT;
	} else if (!vma->vm_file) {
		return -EFAULT;
	} else if (vma->vm_file->f_mapping != folio->mapping) {
		return -EFAULT;
	}

	return vma_address(page, vma);
}

pmd_t *mm_find_pmd(struct mm_struct *mm, unsigned long address)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd = NULL;
	pmd_t pmde;

	pgd = pgd_offset(mm, address);
	if (!pgd_present(*pgd))
		goto out;

	p4d = p4d_offset(pgd, address);
	if (!p4d_present(*p4d))
		goto out;

	pud = pud_offset(p4d, address);
	if (!pud_present(*pud))
		goto out;

	pmd = pmd_offset(pud, address);
	
	pmde = *pmd;
	barrier();
	if (!pmd_present(pmde) || pmd_trans_huge(pmde))
		pmd = NULL;
out:
	return pmd;
}

struct folio_referenced_arg {
	int mapcount;
	int referenced;
	unsigned long vm_flags;
	struct mem_cgroup *memcg;
};

static bool folio_referenced_one(struct folio *folio, struct vm_area_struct *vma, unsigned long address, void *arg)
{
	struct folio_referenced_arg *pra = arg;
	DEFINE_FOLIO_VMA_WALK(pvmw, folio, vma, address, 0);
	int referenced = 0;

	while (page_vma_mapped_walk(&pvmw)) {
		address = pvmw.address;

		if ((vma->vm_flags & VM_LOCKED) && (!folio_test_large(folio) || !pvmw.pte)) {
			
			mlock_vma_folio(folio, vma, !pvmw.pte);
			page_vma_mapped_walk_done(&pvmw);
			pra->vm_flags |= VM_LOCKED;
			return false; 
		}

		if (pvmw.pte) {
			if (ptep_clear_flush_young_notify(vma, address, pvmw.pte)) {
				
				if (likely(!(vma->vm_flags & VM_SEQ_READ)))
					referenced++;
			}
		} else if (IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE)) {
			if (pmdp_clear_flush_young_notify(vma, address, pvmw.pmd))
				referenced++;
		} else {
			
			WARN_ON_ONCE(1);
		}

		pra->mapcount--;
	}

	if (referenced)
		folio_clear_idle(folio);
	if (folio_test_clear_young(folio))
		referenced++;

	if (referenced) {
		pra->referenced++;
		pra->vm_flags |= vma->vm_flags & ~VM_LOCKED;
	}

	if (!pra->mapcount)
		return false; 

	return true;
}

static bool invalid_folio_referenced_vma(struct vm_area_struct *vma, void *arg)
{
	struct folio_referenced_arg *pra = arg;
	struct mem_cgroup *memcg = pra->memcg;

	if (!mm_match_cgroup(vma->vm_mm, memcg))
		return true;

	return false;
}


int folio_referenced(struct folio *folio, int is_locked, struct mem_cgroup *memcg, unsigned long *vm_flags)
{
	int we_locked = 0;
	struct folio_referenced_arg pra = {
		.mapcount = folio_mapcount(folio), .memcg = memcg, };

	struct rmap_walk_control rwc = {
		.rmap_one = folio_referenced_one, .arg = (void *)&pra, .anon_lock = folio_lock_anon_vma_read, .try_lock = true, };




	*vm_flags = 0;
	if (!pra.mapcount)
		return 0;

	if (!folio_raw_mapping(folio))
		return 0;

	if (!is_locked && (!folio_test_anon(folio) || folio_test_ksm(folio))) {
		we_locked = folio_trylock(folio);
		if (!we_locked)
			return 1;
	}

	
	if (memcg) {
		rwc.invalid_vma = invalid_folio_referenced_vma;
	}

	rmap_walk(folio, &rwc);
	*vm_flags = pra.vm_flags;

	if (we_locked)
		folio_unlock(folio);

	return rwc.contended ? -1 : pra.referenced;
}

static int page_vma_mkclean_one(struct page_vma_mapped_walk *pvmw)
{
	int cleaned = 0;
	struct vm_area_struct *vma = pvmw->vma;
	struct mmu_notifier_range range;
	unsigned long address = pvmw->address;

	
	mmu_notifier_range_init(&range, MMU_NOTIFY_PROTECTION_PAGE, 0, vma, vma->vm_mm, address, vma_address_end(pvmw));

	mmu_notifier_invalidate_range_start(&range);

	while (page_vma_mapped_walk(pvmw)) {
		int ret = 0;

		address = pvmw->address;
		if (pvmw->pte) {
			pte_t entry;
			pte_t *pte = pvmw->pte;

			if (!pte_dirty(*pte) && !pte_write(*pte))
				continue;

			flush_cache_page(vma, address, pte_pfn(*pte));
			entry = ptep_clear_flush(vma, address, pte);
			entry = pte_wrprotect(entry);
			entry = pte_mkclean(entry);
			set_pte_at(vma->vm_mm, address, pte, entry);
			ret = 1;
		} else {

			pmd_t *pmd = pvmw->pmd;
			pmd_t entry;

			if (!pmd_dirty(*pmd) && !pmd_write(*pmd))
				continue;

			flush_cache_range(vma, address, address + HPAGE_PMD_SIZE);
			entry = pmdp_invalidate(vma, address, pmd);
			entry = pmd_wrprotect(entry);
			entry = pmd_mkclean(entry);
			set_pmd_at(vma->vm_mm, address, pmd, entry);
			ret = 1;

			
			WARN_ON_ONCE(1);

		}

		
		if (ret)
			cleaned++;
	}

	mmu_notifier_invalidate_range_end(&range);

	return cleaned;
}

static bool page_mkclean_one(struct folio *folio, struct vm_area_struct *vma, unsigned long address, void *arg)
{
	DEFINE_FOLIO_VMA_WALK(pvmw, folio, vma, address, PVMW_SYNC);
	int *cleaned = arg;

	*cleaned += page_vma_mkclean_one(&pvmw);

	return true;
}

static bool invalid_mkclean_vma(struct vm_area_struct *vma, void *arg)
{
	if (vma->vm_flags & VM_SHARED)
		return false;

	return true;
}

int folio_mkclean(struct folio *folio)
{
	int cleaned = 0;
	struct address_space *mapping;
	struct rmap_walk_control rwc = {
		.arg = (void *)&cleaned, .rmap_one = page_mkclean_one, .invalid_vma = invalid_mkclean_vma, };



	BUG_ON(!folio_test_locked(folio));

	if (!folio_mapped(folio))
		return 0;

	mapping = folio_mapping(folio);
	if (!mapping)
		return 0;

	rmap_walk(folio, &rwc);

	return cleaned;
}
EXPORT_SYMBOL_GPL(folio_mkclean);


int pfn_mkclean_range(unsigned long pfn, unsigned long nr_pages, pgoff_t pgoff, struct vm_area_struct *vma)
{
	struct page_vma_mapped_walk pvmw = {
		.pfn		= pfn, .nr_pages	= nr_pages, .pgoff		= pgoff, .vma		= vma, .flags		= PVMW_SYNC, };





	if (invalid_mkclean_vma(vma, NULL))
		return 0;

	pvmw.address = vma_pgoff_address(pgoff, nr_pages, vma);
	VM_BUG_ON_VMA(pvmw.address == -EFAULT, vma);

	return page_vma_mkclean_one(&pvmw);
}


void page_move_anon_rmap(struct page *page, struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;
	struct page *subpage = page;

	page = compound_head(page);

	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_VMA(!anon_vma, vma);

	anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
	
	WRITE_ONCE(page->mapping, (struct address_space *) anon_vma);
	SetPageAnonExclusive(subpage);
}


static void __page_set_anon_rmap(struct page *page, struct vm_area_struct *vma, unsigned long address, int exclusive)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	BUG_ON(!anon_vma);

	if (PageAnon(page))
		goto out;

	
	if (!exclusive)
		anon_vma = anon_vma->root;

	
	anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
	WRITE_ONCE(page->mapping, (struct address_space *) anon_vma);
	page->index = linear_page_index(vma, address);
out:
	if (exclusive)
		SetPageAnonExclusive(page);
}


static void __page_check_anon_rmap(struct page *page, struct vm_area_struct *vma, unsigned long address)
{
	struct folio *folio = page_folio(page);
	
	VM_BUG_ON_FOLIO(folio_anon_vma(folio)->root != vma->anon_vma->root, folio);
	VM_BUG_ON_PAGE(page_to_pgoff(page) != linear_page_index(vma, address), page);
}


void page_add_anon_rmap(struct page *page, struct vm_area_struct *vma, unsigned long address, rmap_t flags)
{
	bool compound = flags & RMAP_COMPOUND;
	bool first;

	if (unlikely(PageKsm(page)))
		lock_page_memcg(page);
	else VM_BUG_ON_PAGE(!PageLocked(page), page);

	if (compound) {
		atomic_t *mapcount;
		VM_BUG_ON_PAGE(!PageLocked(page), page);
		VM_BUG_ON_PAGE(!PageTransHuge(page), page);
		mapcount = compound_mapcount_ptr(page);
		first = atomic_inc_and_test(mapcount);
	} else {
		first = atomic_inc_and_test(&page->_mapcount);
	}
	VM_BUG_ON_PAGE(!first && (flags & RMAP_EXCLUSIVE), page);
	VM_BUG_ON_PAGE(!first && PageAnonExclusive(page), page);

	if (first) {
		int nr = compound ? thp_nr_pages(page) : 1;
		
		if (compound)
			__mod_lruvec_page_state(page, NR_ANON_THPS, nr);
		__mod_lruvec_page_state(page, NR_ANON_MAPPED, nr);
	}

	if (unlikely(PageKsm(page)))
		unlock_page_memcg(page);

	
	else if (first)
		__page_set_anon_rmap(page, vma, address, !!(flags & RMAP_EXCLUSIVE));
	else __page_check_anon_rmap(page, vma, address);

	mlock_vma_page(page, vma, compound);
}


void page_add_new_anon_rmap(struct page *page, struct vm_area_struct *vma, unsigned long address)
{
	const bool compound = PageCompound(page);
	int nr = compound ? thp_nr_pages(page) : 1;

	VM_BUG_ON_VMA(address < vma->vm_start || address >= vma->vm_end, vma);
	__SetPageSwapBacked(page);
	if (compound) {
		VM_BUG_ON_PAGE(!PageTransHuge(page), page);
		
		atomic_set(compound_mapcount_ptr(page), 0);
		atomic_set(compound_pincount_ptr(page), 0);

		__mod_lruvec_page_state(page, NR_ANON_THPS, nr);
	} else {
		
		atomic_set(&page->_mapcount, 0);
	}
	__mod_lruvec_page_state(page, NR_ANON_MAPPED, nr);
	__page_set_anon_rmap(page, vma, address, 1);
}


void page_add_file_rmap(struct page *page, struct vm_area_struct *vma, bool compound)
{
	int i, nr = 0;

	VM_BUG_ON_PAGE(compound && !PageTransHuge(page), page);
	lock_page_memcg(page);
	if (compound && PageTransHuge(page)) {
		int nr_pages = thp_nr_pages(page);

		for (i = 0; i < nr_pages; i++) {
			if (atomic_inc_and_test(&page[i]._mapcount))
				nr++;
		}
		if (!atomic_inc_and_test(compound_mapcount_ptr(page)))
			goto out;

		
		VM_WARN_ON_ONCE(!PageLocked(page));
		if (nr == nr_pages && PageDoubleMap(page))
			ClearPageDoubleMap(page);

		if (PageSwapBacked(page))
			__mod_lruvec_page_state(page, NR_SHMEM_PMDMAPPED, nr_pages);
		else __mod_lruvec_page_state(page, NR_FILE_PMDMAPPED, nr_pages);

	} else {
		if (PageTransCompound(page) && page_mapping(page)) {
			VM_WARN_ON_ONCE(!PageLocked(page));
			SetPageDoubleMap(compound_head(page));
		}
		if (atomic_inc_and_test(&page->_mapcount))
			nr++;
	}
out:
	if (nr)
		__mod_lruvec_page_state(page, NR_FILE_MAPPED, nr);
	unlock_page_memcg(page);

	mlock_vma_page(page, vma, compound);
}

static void page_remove_file_rmap(struct page *page, bool compound)
{
	int i, nr = 0;

	VM_BUG_ON_PAGE(compound && !PageHead(page), page);

	
	if (unlikely(PageHuge(page))) {
		
		atomic_dec(compound_mapcount_ptr(page));
		return;
	}

	
	if (compound && PageTransHuge(page)) {
		int nr_pages = thp_nr_pages(page);

		for (i = 0; i < nr_pages; i++) {
			if (atomic_add_negative(-1, &page[i]._mapcount))
				nr++;
		}
		if (!atomic_add_negative(-1, compound_mapcount_ptr(page)))
			goto out;
		if (PageSwapBacked(page))
			__mod_lruvec_page_state(page, NR_SHMEM_PMDMAPPED, -nr_pages);
		else __mod_lruvec_page_state(page, NR_FILE_PMDMAPPED, -nr_pages);

	} else {
		if (atomic_add_negative(-1, &page->_mapcount))
			nr++;
	}
out:
	if (nr)
		__mod_lruvec_page_state(page, NR_FILE_MAPPED, -nr);
}

static void page_remove_anon_compound_rmap(struct page *page)
{
	int i, nr;

	if (!atomic_add_negative(-1, compound_mapcount_ptr(page)))
		return;

	
	if (unlikely(PageHuge(page)))
		return;

	if (!IS_ENABLED(CONFIG_TRANSPARENT_HUGEPAGE))
		return;

	__mod_lruvec_page_state(page, NR_ANON_THPS, -thp_nr_pages(page));

	if (TestClearPageDoubleMap(page)) {
		
		for (i = 0, nr = 0; i < thp_nr_pages(page); i++) {
			if (atomic_add_negative(-1, &page[i]._mapcount))
				nr++;
		}

		
		if (nr && nr < thp_nr_pages(page))
			deferred_split_huge_page(page);
	} else {
		nr = thp_nr_pages(page);
	}

	if (nr)
		__mod_lruvec_page_state(page, NR_ANON_MAPPED, -nr);
}


void page_remove_rmap(struct page *page, struct vm_area_struct *vma, bool compound)
{
	lock_page_memcg(page);

	if (!PageAnon(page)) {
		page_remove_file_rmap(page, compound);
		goto out;
	}

	if (compound) {
		page_remove_anon_compound_rmap(page);
		goto out;
	}

	
	if (!atomic_add_negative(-1, &page->_mapcount))
		goto out;

	
	__dec_lruvec_page_state(page, NR_ANON_MAPPED);

	if (PageTransCompound(page))
		deferred_split_huge_page(compound_head(page));

	
out:
	unlock_page_memcg(page);

	munlock_vma_page(page, vma, compound);
}


static bool try_to_unmap_one(struct folio *folio, struct vm_area_struct *vma, unsigned long address, void *arg)
{
	struct mm_struct *mm = vma->vm_mm;
	DEFINE_FOLIO_VMA_WALK(pvmw, folio, vma, address, 0);
	pte_t pteval;
	struct page *subpage;
	bool anon_exclusive, ret = true;
	struct mmu_notifier_range range;
	enum ttu_flags flags = (enum ttu_flags)(long)arg;

	
	if (flags & TTU_SYNC)
		pvmw.flags = PVMW_SYNC;

	if (flags & TTU_SPLIT_HUGE_PMD)
		split_huge_pmd_address(vma, address, false, folio);

	
	range.end = vma_address_end(&pvmw);
	mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, vma, vma->vm_mm, address, range.end);
	if (folio_test_hugetlb(folio)) {
		
		adjust_range_if_pmd_sharing_possible(vma, &range.start, &range.end);
	}
	mmu_notifier_invalidate_range_start(&range);

	while (page_vma_mapped_walk(&pvmw)) {
		
		VM_BUG_ON_FOLIO(!pvmw.pte, folio);

		
		if (!(flags & TTU_IGNORE_MLOCK) && (vma->vm_flags & VM_LOCKED)) {
			
			mlock_vma_folio(folio, vma, false);
			page_vma_mapped_walk_done(&pvmw);
			ret = false;
			break;
		}

		subpage = folio_page(folio, pte_pfn(*pvmw.pte) - folio_pfn(folio));
		address = pvmw.address;
		anon_exclusive = folio_test_anon(folio) && PageAnonExclusive(subpage);

		if (folio_test_hugetlb(folio)) {
			bool anon = folio_test_anon(folio);

			
			VM_BUG_ON_PAGE(!PageHWPoison(subpage), subpage);
			
			flush_cache_range(vma, range.start, range.end);

			
			VM_BUG_ON(!anon && !(flags & TTU_RMAP_LOCKED));
			if (!anon && huge_pmd_unshare(mm, vma, address, pvmw.pte)) {
				flush_tlb_range(vma, range.start, range.end);
				mmu_notifier_invalidate_range(mm, range.start, range.end);

				
				page_vma_mapped_walk_done(&pvmw);
				break;
			}
			pteval = huge_ptep_clear_flush(vma, address, pvmw.pte);
		} else {
			flush_cache_page(vma, address, pte_pfn(*pvmw.pte));
			
			if (should_defer_flush(mm, flags) && !anon_exclusive) {
				
				pteval = ptep_get_and_clear(mm, address, pvmw.pte);

				set_tlb_ubc_flush_pending(mm, pte_dirty(pteval));
			} else {
				pteval = ptep_clear_flush(vma, address, pvmw.pte);
			}
		}

		
		pte_install_uffd_wp_if_needed(vma, address, pvmw.pte, pteval);

		
		if (pte_dirty(pteval))
			folio_mark_dirty(folio);

		
		update_hiwater_rss(mm);

		if (PageHWPoison(subpage) && !(flags & TTU_IGNORE_HWPOISON)) {
			pteval = swp_entry_to_pte(make_hwpoison_entry(subpage));
			if (folio_test_hugetlb(folio)) {
				hugetlb_count_sub(folio_nr_pages(folio), mm);
				set_huge_pte_at(mm, address, pvmw.pte, pteval);
			} else {
				dec_mm_counter(mm, mm_counter(&folio->page));
				set_pte_at(mm, address, pvmw.pte, pteval);
			}

		} else if (pte_unused(pteval) && !userfaultfd_armed(vma)) {
			
			dec_mm_counter(mm, mm_counter(&folio->page));
			
			mmu_notifier_invalidate_range(mm, address, address + PAGE_SIZE);
		} else if (folio_test_anon(folio)) {
			swp_entry_t entry = { .val = page_private(subpage) };
			pte_t swp_pte;
			
			if (unlikely(folio_test_swapbacked(folio) != folio_test_swapcache(folio))) {
				WARN_ON_ONCE(1);
				ret = false;
				
				mmu_notifier_invalidate_range(mm, address, address + PAGE_SIZE);
				page_vma_mapped_walk_done(&pvmw);
				break;
			}

			
			if (!folio_test_swapbacked(folio)) {
				int ref_count, map_count;

				
				smp_mb();

				ref_count = folio_ref_count(folio);
				map_count = folio_mapcount(folio);

				
				smp_rmb();

				
				if (ref_count == 1 + map_count && !folio_test_dirty(folio)) {
					
					mmu_notifier_invalidate_range(mm, address, address + PAGE_SIZE);
					dec_mm_counter(mm, MM_ANONPAGES);
					goto discard;
				}

				
				set_pte_at(mm, address, pvmw.pte, pteval);
				folio_set_swapbacked(folio);
				ret = false;
				page_vma_mapped_walk_done(&pvmw);
				break;
			}

			if (swap_duplicate(entry) < 0) {
				set_pte_at(mm, address, pvmw.pte, pteval);
				ret = false;
				page_vma_mapped_walk_done(&pvmw);
				break;
			}
			if (arch_unmap_one(mm, vma, address, pteval) < 0) {
				swap_free(entry);
				set_pte_at(mm, address, pvmw.pte, pteval);
				ret = false;
				page_vma_mapped_walk_done(&pvmw);
				break;
			}
			if (anon_exclusive && page_try_share_anon_rmap(subpage)) {
				swap_free(entry);
				set_pte_at(mm, address, pvmw.pte, pteval);
				ret = false;
				page_vma_mapped_walk_done(&pvmw);
				break;
			}
			
			if (list_empty(&mm->mmlist)) {
				spin_lock(&mmlist_lock);
				if (list_empty(&mm->mmlist))
					list_add(&mm->mmlist, &init_mm.mmlist);
				spin_unlock(&mmlist_lock);
			}
			dec_mm_counter(mm, MM_ANONPAGES);
			inc_mm_counter(mm, MM_SWAPENTS);
			swp_pte = swp_entry_to_pte(entry);
			if (anon_exclusive)
				swp_pte = pte_swp_mkexclusive(swp_pte);
			if (pte_soft_dirty(pteval))
				swp_pte = pte_swp_mksoft_dirty(swp_pte);
			if (pte_uffd_wp(pteval))
				swp_pte = pte_swp_mkuffd_wp(swp_pte);
			set_pte_at(mm, address, pvmw.pte, swp_pte);
			
			mmu_notifier_invalidate_range(mm, address, address + PAGE_SIZE);
		} else {
			
			dec_mm_counter(mm, mm_counter_file(&folio->page));
		}
discard:
		
		page_remove_rmap(subpage, vma, folio_test_hugetlb(folio));
		if (vma->vm_flags & VM_LOCKED)
			mlock_page_drain_local();
		folio_put(folio);
	}

	mmu_notifier_invalidate_range_end(&range);

	return ret;
}

static bool invalid_migration_vma(struct vm_area_struct *vma, void *arg)
{
	return vma_is_temporary_stack(vma);
}

static int page_not_mapped(struct folio *folio)
{
	return !folio_mapped(folio);
}


void try_to_unmap(struct folio *folio, enum ttu_flags flags)
{
	struct rmap_walk_control rwc = {
		.rmap_one = try_to_unmap_one, .arg = (void *)flags, .done = page_not_mapped, .anon_lock = folio_lock_anon_vma_read, };




	if (flags & TTU_RMAP_LOCKED)
		rmap_walk_locked(folio, &rwc);
	else rmap_walk(folio, &rwc);
}


static bool try_to_migrate_one(struct folio *folio, struct vm_area_struct *vma, unsigned long address, void *arg)
{
	struct mm_struct *mm = vma->vm_mm;
	DEFINE_FOLIO_VMA_WALK(pvmw, folio, vma, address, 0);
	pte_t pteval;
	struct page *subpage;
	bool anon_exclusive, ret = true;
	struct mmu_notifier_range range;
	enum ttu_flags flags = (enum ttu_flags)(long)arg;

	
	if (flags & TTU_SYNC)
		pvmw.flags = PVMW_SYNC;

	
	if (flags & TTU_SPLIT_HUGE_PMD)
		split_huge_pmd_address(vma, address, true, folio);

	
	range.end = vma_address_end(&pvmw);
	mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, vma, vma->vm_mm, address, range.end);
	if (folio_test_hugetlb(folio)) {
		
		adjust_range_if_pmd_sharing_possible(vma, &range.start, &range.end);
	}
	mmu_notifier_invalidate_range_start(&range);

	while (page_vma_mapped_walk(&pvmw)) {

		
		if (!pvmw.pte) {
			subpage = folio_page(folio, pmd_pfn(*pvmw.pmd) - folio_pfn(folio));
			VM_BUG_ON_FOLIO(folio_test_hugetlb(folio) || !folio_test_pmd_mappable(folio), folio);

			if (set_pmd_migration_entry(&pvmw, subpage)) {
				ret = false;
				page_vma_mapped_walk_done(&pvmw);
				break;
			}
			continue;
		}


		
		VM_BUG_ON_FOLIO(!pvmw.pte, folio);

		if (folio_is_zone_device(folio)) {
			
			VM_BUG_ON_FOLIO(folio_nr_pages(folio) > 1, folio);
			subpage = &folio->page;
		} else {
			subpage = folio_page(folio, pte_pfn(*pvmw.pte) - folio_pfn(folio));
		}
		address = pvmw.address;
		anon_exclusive = folio_test_anon(folio) && PageAnonExclusive(subpage);

		if (folio_test_hugetlb(folio)) {
			bool anon = folio_test_anon(folio);

			
			flush_cache_range(vma, range.start, range.end);

			
			VM_BUG_ON(!anon && !(flags & TTU_RMAP_LOCKED));
			if (!anon && huge_pmd_unshare(mm, vma, address, pvmw.pte)) {
				flush_tlb_range(vma, range.start, range.end);
				mmu_notifier_invalidate_range(mm, range.start, range.end);

				
				page_vma_mapped_walk_done(&pvmw);
				break;
			}

			
			pteval = huge_ptep_clear_flush(vma, address, pvmw.pte);
		} else {
			flush_cache_page(vma, address, pte_pfn(*pvmw.pte));
			
			pteval = ptep_clear_flush(vma, address, pvmw.pte);
		}

		
		if (pte_dirty(pteval))
			folio_mark_dirty(folio);

		
		update_hiwater_rss(mm);

		if (folio_is_device_private(folio)) {
			unsigned long pfn = folio_pfn(folio);
			swp_entry_t entry;
			pte_t swp_pte;

			if (anon_exclusive)
				BUG_ON(page_try_share_anon_rmap(subpage));

			
			entry = pte_to_swp_entry(pteval);
			if (is_writable_device_private_entry(entry))
				entry = make_writable_migration_entry(pfn);
			else if (anon_exclusive)
				entry = make_readable_exclusive_migration_entry(pfn);
			else entry = make_readable_migration_entry(pfn);
			swp_pte = swp_entry_to_pte(entry);

			
			if (pte_swp_soft_dirty(pteval))
				swp_pte = pte_swp_mksoft_dirty(swp_pte);
			if (pte_swp_uffd_wp(pteval))
				swp_pte = pte_swp_mkuffd_wp(swp_pte);
			set_pte_at(mm, pvmw.address, pvmw.pte, swp_pte);
			trace_set_migration_pte(pvmw.address, pte_val(swp_pte), compound_order(&folio->page));
			
		} else if (PageHWPoison(subpage)) {
			pteval = swp_entry_to_pte(make_hwpoison_entry(subpage));
			if (folio_test_hugetlb(folio)) {
				hugetlb_count_sub(folio_nr_pages(folio), mm);
				set_huge_pte_at(mm, address, pvmw.pte, pteval);
			} else {
				dec_mm_counter(mm, mm_counter(&folio->page));
				set_pte_at(mm, address, pvmw.pte, pteval);
			}

		} else if (pte_unused(pteval) && !userfaultfd_armed(vma)) {
			
			dec_mm_counter(mm, mm_counter(&folio->page));
			
			mmu_notifier_invalidate_range(mm, address, address + PAGE_SIZE);
		} else {
			swp_entry_t entry;
			pte_t swp_pte;

			if (arch_unmap_one(mm, vma, address, pteval) < 0) {
				if (folio_test_hugetlb(folio))
					set_huge_pte_at(mm, address, pvmw.pte, pteval);
				else set_pte_at(mm, address, pvmw.pte, pteval);
				ret = false;
				page_vma_mapped_walk_done(&pvmw);
				break;
			}
			VM_BUG_ON_PAGE(pte_write(pteval) && folio_test_anon(folio) && !anon_exclusive, subpage);
			if (anon_exclusive && page_try_share_anon_rmap(subpage)) {
				if (folio_test_hugetlb(folio))
					set_huge_pte_at(mm, address, pvmw.pte, pteval);
				else set_pte_at(mm, address, pvmw.pte, pteval);
				ret = false;
				page_vma_mapped_walk_done(&pvmw);
				break;
			}

			
			if (pte_write(pteval))
				entry = make_writable_migration_entry( page_to_pfn(subpage));
			else if (anon_exclusive)
				entry = make_readable_exclusive_migration_entry( page_to_pfn(subpage));
			else entry = make_readable_migration_entry( page_to_pfn(subpage));


			swp_pte = swp_entry_to_pte(entry);
			if (pte_soft_dirty(pteval))
				swp_pte = pte_swp_mksoft_dirty(swp_pte);
			if (pte_uffd_wp(pteval))
				swp_pte = pte_swp_mkuffd_wp(swp_pte);
			if (folio_test_hugetlb(folio))
				set_huge_pte_at(mm, address, pvmw.pte, swp_pte);
			else set_pte_at(mm, address, pvmw.pte, swp_pte);
			trace_set_migration_pte(address, pte_val(swp_pte), compound_order(&folio->page));
			
		}

		
		page_remove_rmap(subpage, vma, folio_test_hugetlb(folio));
		if (vma->vm_flags & VM_LOCKED)
			mlock_page_drain_local();
		folio_put(folio);
	}

	mmu_notifier_invalidate_range_end(&range);

	return ret;
}


void try_to_migrate(struct folio *folio, enum ttu_flags flags)
{
	struct rmap_walk_control rwc = {
		.rmap_one = try_to_migrate_one, .arg = (void *)flags, .done = page_not_mapped, .anon_lock = folio_lock_anon_vma_read, };




	
	if (WARN_ON_ONCE(flags & ~(TTU_RMAP_LOCKED | TTU_SPLIT_HUGE_PMD | TTU_SYNC)))
		return;

	if (folio_is_zone_device(folio) && (!folio_is_device_private(folio) && !folio_is_device_coherent(folio)))
		return;

	
	if (!folio_test_ksm(folio) && folio_test_anon(folio))
		rwc.invalid_vma = invalid_migration_vma;

	if (flags & TTU_RMAP_LOCKED)
		rmap_walk_locked(folio, &rwc);
	else rmap_walk(folio, &rwc);
}


struct make_exclusive_args {
	struct mm_struct *mm;
	unsigned long address;
	void *owner;
	bool valid;
};

static bool page_make_device_exclusive_one(struct folio *folio, struct vm_area_struct *vma, unsigned long address, void *priv)
{
	struct mm_struct *mm = vma->vm_mm;
	DEFINE_FOLIO_VMA_WALK(pvmw, folio, vma, address, 0);
	struct make_exclusive_args *args = priv;
	pte_t pteval;
	struct page *subpage;
	bool ret = true;
	struct mmu_notifier_range range;
	swp_entry_t entry;
	pte_t swp_pte;

	mmu_notifier_range_init_owner(&range, MMU_NOTIFY_EXCLUSIVE, 0, vma, vma->vm_mm, address, min(vma->vm_end, address + folio_size(folio)), args->owner);


	mmu_notifier_invalidate_range_start(&range);

	while (page_vma_mapped_walk(&pvmw)) {
		
		VM_BUG_ON_FOLIO(!pvmw.pte, folio);

		if (!pte_present(*pvmw.pte)) {
			ret = false;
			page_vma_mapped_walk_done(&pvmw);
			break;
		}

		subpage = folio_page(folio, pte_pfn(*pvmw.pte) - folio_pfn(folio));
		address = pvmw.address;

		
		flush_cache_page(vma, address, pte_pfn(*pvmw.pte));
		pteval = ptep_clear_flush(vma, address, pvmw.pte);

		
		if (pte_dirty(pteval))
			folio_mark_dirty(folio);

		
		if (args->mm == mm && args->address == address && pte_write(pteval))
			args->valid = true;

		
		if (pte_write(pteval))
			entry = make_writable_device_exclusive_entry( page_to_pfn(subpage));
		else entry = make_readable_device_exclusive_entry( page_to_pfn(subpage));

		swp_pte = swp_entry_to_pte(entry);
		if (pte_soft_dirty(pteval))
			swp_pte = pte_swp_mksoft_dirty(swp_pte);
		if (pte_uffd_wp(pteval))
			swp_pte = pte_swp_mkuffd_wp(swp_pte);

		set_pte_at(mm, address, pvmw.pte, swp_pte);

		
		page_remove_rmap(subpage, vma, false);
	}

	mmu_notifier_invalidate_range_end(&range);

	return ret;
}


static bool folio_make_device_exclusive(struct folio *folio, struct mm_struct *mm, unsigned long address, void *owner)
{
	struct make_exclusive_args args = {
		.mm = mm, .address = address, .owner = owner, .valid = false, };



	struct rmap_walk_control rwc = {
		.rmap_one = page_make_device_exclusive_one, .done = page_not_mapped, .anon_lock = folio_lock_anon_vma_read, .arg = &args, };




	
	if (!folio_test_anon(folio))
		return false;

	rmap_walk(folio, &rwc);

	return args.valid && !folio_mapcount(folio);
}


int make_device_exclusive_range(struct mm_struct *mm, unsigned long start, unsigned long end, struct page **pages, void *owner)

{
	long npages = (end - start) >> PAGE_SHIFT;
	long i;

	npages = get_user_pages_remote(mm, start, npages, FOLL_GET | FOLL_WRITE | FOLL_SPLIT_PMD, pages, NULL, NULL);

	if (npages < 0)
		return npages;

	for (i = 0; i < npages; i++, start += PAGE_SIZE) {
		struct folio *folio = page_folio(pages[i]);
		if (PageTail(pages[i]) || !folio_trylock(folio)) {
			folio_put(folio);
			pages[i] = NULL;
			continue;
		}

		if (!folio_make_device_exclusive(folio, mm, start, owner)) {
			folio_unlock(folio);
			folio_put(folio);
			pages[i] = NULL;
		}
	}

	return npages;
}
EXPORT_SYMBOL_GPL(make_device_exclusive_range);


void __put_anon_vma(struct anon_vma *anon_vma)
{
	struct anon_vma *root = anon_vma->root;

	anon_vma_free(anon_vma);
	if (root != anon_vma && atomic_dec_and_test(&root->refcount))
		anon_vma_free(root);
}

static struct anon_vma *rmap_walk_anon_lock(struct folio *folio, struct rmap_walk_control *rwc)
{
	struct anon_vma *anon_vma;

	if (rwc->anon_lock)
		return rwc->anon_lock(folio, rwc);

	
	anon_vma = folio_anon_vma(folio);
	if (!anon_vma)
		return NULL;

	if (anon_vma_trylock_read(anon_vma))
		goto out;

	if (rwc->try_lock) {
		anon_vma = NULL;
		rwc->contended = true;
		goto out;
	}

	anon_vma_lock_read(anon_vma);
out:
	return anon_vma;
}


static void rmap_walk_anon(struct folio *folio, struct rmap_walk_control *rwc, bool locked)
{
	struct anon_vma *anon_vma;
	pgoff_t pgoff_start, pgoff_end;
	struct anon_vma_chain *avc;

	if (locked) {
		anon_vma = folio_anon_vma(folio);
		
		VM_BUG_ON_FOLIO(!anon_vma, folio);
	} else {
		anon_vma = rmap_walk_anon_lock(folio, rwc);
	}
	if (!anon_vma)
		return;

	pgoff_start = folio_pgoff(folio);
	pgoff_end = pgoff_start + folio_nr_pages(folio) - 1;
	anon_vma_interval_tree_foreach(avc, &anon_vma->rb_root, pgoff_start, pgoff_end) {
		struct vm_area_struct *vma = avc->vma;
		unsigned long address = vma_address(&folio->page, vma);

		VM_BUG_ON_VMA(address == -EFAULT, vma);
		cond_resched();

		if (rwc->invalid_vma && rwc->invalid_vma(vma, rwc->arg))
			continue;

		if (!rwc->rmap_one(folio, vma, address, rwc->arg))
			break;
		if (rwc->done && rwc->done(folio))
			break;
	}

	if (!locked)
		anon_vma_unlock_read(anon_vma);
}


static void rmap_walk_file(struct folio *folio, struct rmap_walk_control *rwc, bool locked)
{
	struct address_space *mapping = folio_mapping(folio);
	pgoff_t pgoff_start, pgoff_end;
	struct vm_area_struct *vma;

	
	VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);

	if (!mapping)
		return;

	pgoff_start = folio_pgoff(folio);
	pgoff_end = pgoff_start + folio_nr_pages(folio) - 1;
	if (!locked) {
		if (i_mmap_trylock_read(mapping))
			goto lookup;

		if (rwc->try_lock) {
			rwc->contended = true;
			return;
		}

		i_mmap_lock_read(mapping);
	}
lookup:
	vma_interval_tree_foreach(vma, &mapping->i_mmap, pgoff_start, pgoff_end) {
		unsigned long address = vma_address(&folio->page, vma);

		VM_BUG_ON_VMA(address == -EFAULT, vma);
		cond_resched();

		if (rwc->invalid_vma && rwc->invalid_vma(vma, rwc->arg))
			continue;

		if (!rwc->rmap_one(folio, vma, address, rwc->arg))
			goto done;
		if (rwc->done && rwc->done(folio))
			goto done;
	}

done:
	if (!locked)
		i_mmap_unlock_read(mapping);
}

void rmap_walk(struct folio *folio, struct rmap_walk_control *rwc)
{
	if (unlikely(folio_test_ksm(folio)))
		rmap_walk_ksm(folio, rwc);
	else if (folio_test_anon(folio))
		rmap_walk_anon(folio, rwc, false);
	else rmap_walk_file(folio, rwc, false);
}


void rmap_walk_locked(struct folio *folio, struct rmap_walk_control *rwc)
{
	
	VM_BUG_ON_FOLIO(folio_test_ksm(folio), folio);
	if (folio_test_anon(folio))
		rmap_walk_anon(folio, rwc, true);
	else rmap_walk_file(folio, rwc, true);
}



void hugepage_add_anon_rmap(struct page *page, struct vm_area_struct *vma, unsigned long address, rmap_t flags)
{
	struct anon_vma *anon_vma = vma->anon_vma;
	int first;

	BUG_ON(!PageLocked(page));
	BUG_ON(!anon_vma);
	
	first = atomic_inc_and_test(compound_mapcount_ptr(page));
	VM_BUG_ON_PAGE(!first && (flags & RMAP_EXCLUSIVE), page);
	VM_BUG_ON_PAGE(!first && PageAnonExclusive(page), page);
	if (first)
		__page_set_anon_rmap(page, vma, address, !!(flags & RMAP_EXCLUSIVE));
}

void hugepage_add_new_anon_rmap(struct page *page, struct vm_area_struct *vma, unsigned long address)
{
	BUG_ON(address < vma->vm_start || address >= vma->vm_end);
	atomic_set(compound_mapcount_ptr(page), 0);
	atomic_set(compound_pincount_ptr(page), 0);

	__page_set_anon_rmap(page, vma, address, 1);
}

