

























static const unsigned int btrfs_blocked_trans_types[TRANS_STATE_MAX] = {
	[TRANS_STATE_RUNNING]		= 0U, [TRANS_STATE_COMMIT_START]	= (__TRANS_START | __TRANS_ATTACH), [TRANS_STATE_COMMIT_DOING]	= (__TRANS_START | __TRANS_ATTACH | __TRANS_JOIN | __TRANS_JOIN_NOSTART), [TRANS_STATE_UNBLOCKED]		= (__TRANS_START | __TRANS_ATTACH | __TRANS_JOIN | __TRANS_JOIN_NOLOCK | __TRANS_JOIN_NOSTART), [TRANS_STATE_SUPER_COMMITTED]	= (__TRANS_START | __TRANS_ATTACH | __TRANS_JOIN | __TRANS_JOIN_NOLOCK | __TRANS_JOIN_NOSTART), [TRANS_STATE_COMPLETED]		= (__TRANS_START | __TRANS_ATTACH | __TRANS_JOIN | __TRANS_JOIN_NOLOCK | __TRANS_JOIN_NOSTART), };





















void btrfs_put_transaction(struct btrfs_transaction *transaction)
{
	WARN_ON(refcount_read(&transaction->use_count) == 0);
	if (refcount_dec_and_test(&transaction->use_count)) {
		BUG_ON(!list_empty(&transaction->list));
		WARN_ON(!RB_EMPTY_ROOT( &transaction->delayed_refs.href_root.rb_root));
		WARN_ON(!RB_EMPTY_ROOT( &transaction->delayed_refs.dirty_extent_root));
		if (transaction->delayed_refs.pending_csums)
			btrfs_err(transaction->fs_info, "pending csums is %llu", transaction->delayed_refs.pending_csums);

		
		while (!list_empty(&transaction->deleted_bgs)) {
			struct btrfs_block_group *cache;

			cache = list_first_entry(&transaction->deleted_bgs, struct btrfs_block_group, bg_list);

			list_del_init(&cache->bg_list);
			btrfs_unfreeze_block_group(cache);
			btrfs_put_block_group(cache);
		}
		WARN_ON(!list_empty(&transaction->dev_update_list));
		kfree(transaction);
	}
}

static noinline void switch_commit_roots(struct btrfs_trans_handle *trans)
{
	struct btrfs_transaction *cur_trans = trans->transaction;
	struct btrfs_fs_info *fs_info = trans->fs_info;
	struct btrfs_root *root, *tmp;
	struct btrfs_caching_control *caching_ctl, *next;

	down_write(&fs_info->commit_root_sem);
	list_for_each_entry_safe(root, tmp, &cur_trans->switch_commits, dirty_list) {
		list_del_init(&root->dirty_list);
		free_extent_buffer(root->commit_root);
		root->commit_root = btrfs_root_node(root);
		extent_io_tree_release(&root->dirty_log_pages);
		btrfs_qgroup_clean_swapped_blocks(root);
	}

	
	spin_lock(&cur_trans->dropped_roots_lock);
	while (!list_empty(&cur_trans->dropped_roots)) {
		root = list_first_entry(&cur_trans->dropped_roots, struct btrfs_root, root_list);
		list_del_init(&root->root_list);
		spin_unlock(&cur_trans->dropped_roots_lock);
		btrfs_free_log(trans, root);
		btrfs_drop_and_free_fs_root(fs_info, root);
		spin_lock(&cur_trans->dropped_roots_lock);
	}
	spin_unlock(&cur_trans->dropped_roots_lock);

	
	spin_lock(&fs_info->block_group_cache_lock);
	list_for_each_entry_safe(caching_ctl, next, &fs_info->caching_block_groups, list) {
		struct btrfs_block_group *cache = caching_ctl->block_group;

		if (btrfs_block_group_done(cache)) {
			cache->last_byte_to_unpin = (u64)-1;
			list_del_init(&caching_ctl->list);
			btrfs_put_caching_control(caching_ctl);
		} else {
			cache->last_byte_to_unpin = caching_ctl->progress;
		}
	}
	spin_unlock(&fs_info->block_group_cache_lock);
	up_write(&fs_info->commit_root_sem);
}

static inline void extwriter_counter_inc(struct btrfs_transaction *trans, unsigned int type)
{
	if (type & TRANS_EXTWRITERS)
		atomic_inc(&trans->num_extwriters);
}

static inline void extwriter_counter_dec(struct btrfs_transaction *trans, unsigned int type)
{
	if (type & TRANS_EXTWRITERS)
		atomic_dec(&trans->num_extwriters);
}

static inline void extwriter_counter_init(struct btrfs_transaction *trans, unsigned int type)
{
	atomic_set(&trans->num_extwriters, ((type & TRANS_EXTWRITERS) ? 1 : 0));
}

static inline int extwriter_counter_read(struct btrfs_transaction *trans)
{
	return atomic_read(&trans->num_extwriters);
}


void btrfs_trans_release_chunk_metadata(struct btrfs_trans_handle *trans)
{
	struct btrfs_fs_info *fs_info = trans->fs_info;
	struct btrfs_transaction *cur_trans = trans->transaction;

	if (!trans->chunk_bytes_reserved)
		return;

	WARN_ON_ONCE(!list_empty(&trans->new_bgs));

	btrfs_block_rsv_release(fs_info, &fs_info->chunk_block_rsv, trans->chunk_bytes_reserved, NULL);
	atomic64_sub(trans->chunk_bytes_reserved, &cur_trans->chunk_bytes_reserved);
	cond_wake_up(&cur_trans->chunk_reserve_wait);
	trans->chunk_bytes_reserved = 0;
}


static noinline int join_transaction(struct btrfs_fs_info *fs_info, unsigned int type)
{
	struct btrfs_transaction *cur_trans;

	spin_lock(&fs_info->trans_lock);
loop:
	
	if (test_bit(BTRFS_FS_STATE_ERROR, &fs_info->fs_state)) {
		spin_unlock(&fs_info->trans_lock);
		return -EROFS;
	}

	cur_trans = fs_info->running_transaction;
	if (cur_trans) {
		if (TRANS_ABORTED(cur_trans)) {
			spin_unlock(&fs_info->trans_lock);
			return cur_trans->aborted;
		}
		if (btrfs_blocked_trans_types[cur_trans->state] & type) {
			spin_unlock(&fs_info->trans_lock);
			return -EBUSY;
		}
		refcount_inc(&cur_trans->use_count);
		atomic_inc(&cur_trans->num_writers);
		extwriter_counter_inc(cur_trans, type);
		spin_unlock(&fs_info->trans_lock);
		return 0;
	}
	spin_unlock(&fs_info->trans_lock);

	
	if (type == TRANS_ATTACH)
		return -ENOENT;

	
	BUG_ON(type == TRANS_JOIN_NOLOCK);

	cur_trans = kmalloc(sizeof(*cur_trans), GFP_NOFS);
	if (!cur_trans)
		return -ENOMEM;

	spin_lock(&fs_info->trans_lock);
	if (fs_info->running_transaction) {
		
		kfree(cur_trans);
		goto loop;
	} else if (test_bit(BTRFS_FS_STATE_ERROR, &fs_info->fs_state)) {
		spin_unlock(&fs_info->trans_lock);
		kfree(cur_trans);
		return -EROFS;
	}

	cur_trans->fs_info = fs_info;
	atomic_set(&cur_trans->pending_ordered, 0);
	init_waitqueue_head(&cur_trans->pending_wait);
	atomic_set(&cur_trans->num_writers, 1);
	extwriter_counter_init(cur_trans, type);
	init_waitqueue_head(&cur_trans->writer_wait);
	init_waitqueue_head(&cur_trans->commit_wait);
	cur_trans->state = TRANS_STATE_RUNNING;
	
	refcount_set(&cur_trans->use_count, 2);
	cur_trans->flags = 0;
	cur_trans->start_time = ktime_get_seconds();

	memset(&cur_trans->delayed_refs, 0, sizeof(cur_trans->delayed_refs));

	cur_trans->delayed_refs.href_root = RB_ROOT_CACHED;
	cur_trans->delayed_refs.dirty_extent_root = RB_ROOT;
	atomic_set(&cur_trans->delayed_refs.num_entries, 0);

	
	smp_mb();
	if (!list_empty(&fs_info->tree_mod_seq_list))
		WARN(1, KERN_ERR "BTRFS: tree_mod_seq_list not empty when creating a fresh transaction\n");
	if (!RB_EMPTY_ROOT(&fs_info->tree_mod_log))
		WARN(1, KERN_ERR "BTRFS: tree_mod_log rb tree not empty when creating a fresh transaction\n");
	atomic64_set(&fs_info->tree_mod_seq, 0);

	spin_lock_init(&cur_trans->delayed_refs.lock);

	INIT_LIST_HEAD(&cur_trans->pending_snapshots);
	INIT_LIST_HEAD(&cur_trans->dev_update_list);
	INIT_LIST_HEAD(&cur_trans->switch_commits);
	INIT_LIST_HEAD(&cur_trans->dirty_bgs);
	INIT_LIST_HEAD(&cur_trans->io_bgs);
	INIT_LIST_HEAD(&cur_trans->dropped_roots);
	mutex_init(&cur_trans->cache_write_mutex);
	spin_lock_init(&cur_trans->dirty_bgs_lock);
	INIT_LIST_HEAD(&cur_trans->deleted_bgs);
	spin_lock_init(&cur_trans->dropped_roots_lock);
	INIT_LIST_HEAD(&cur_trans->releasing_ebs);
	spin_lock_init(&cur_trans->releasing_ebs_lock);
	atomic64_set(&cur_trans->chunk_bytes_reserved, 0);
	init_waitqueue_head(&cur_trans->chunk_reserve_wait);
	list_add_tail(&cur_trans->list, &fs_info->trans_list);
	extent_io_tree_init(fs_info, &cur_trans->dirty_pages, IO_TREE_TRANS_DIRTY_PAGES, fs_info->btree_inode);
	extent_io_tree_init(fs_info, &cur_trans->pinned_extents, IO_TREE_FS_PINNED_EXTENTS, NULL);
	fs_info->generation++;
	cur_trans->transid = fs_info->generation;
	fs_info->running_transaction = cur_trans;
	cur_trans->aborted = 0;
	spin_unlock(&fs_info->trans_lock);

	return 0;
}


static int record_root_in_trans(struct btrfs_trans_handle *trans, struct btrfs_root *root, int force)

{
	struct btrfs_fs_info *fs_info = root->fs_info;
	int ret = 0;

	if ((test_bit(BTRFS_ROOT_SHAREABLE, &root->state) && root->last_trans < trans->transid) || force) {
		WARN_ON(root == fs_info->extent_root);
		WARN_ON(!force && root->commit_root != root->node);

		
		set_bit(BTRFS_ROOT_IN_TRANS_SETUP, &root->state);

		
		smp_wmb();

		spin_lock(&fs_info->fs_roots_radix_lock);
		if (root->last_trans == trans->transid && !force) {
			spin_unlock(&fs_info->fs_roots_radix_lock);
			return 0;
		}
		radix_tree_tag_set(&fs_info->fs_roots_radix, (unsigned long)root->root_key.objectid, BTRFS_ROOT_TRANS_TAG);

		spin_unlock(&fs_info->fs_roots_radix_lock);
		root->last_trans = trans->transid;

		
		ret = btrfs_init_reloc_root(trans, root);
		smp_mb__before_atomic();
		clear_bit(BTRFS_ROOT_IN_TRANS_SETUP, &root->state);
	}
	return ret;
}


void btrfs_add_dropped_root(struct btrfs_trans_handle *trans, struct btrfs_root *root)
{
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_transaction *cur_trans = trans->transaction;

	
	spin_lock(&cur_trans->dropped_roots_lock);
	list_add_tail(&root->root_list, &cur_trans->dropped_roots);
	spin_unlock(&cur_trans->dropped_roots_lock);

	
	spin_lock(&fs_info->fs_roots_radix_lock);
	radix_tree_tag_clear(&fs_info->fs_roots_radix, (unsigned long)root->root_key.objectid, BTRFS_ROOT_TRANS_TAG);

	spin_unlock(&fs_info->fs_roots_radix_lock);
}

int btrfs_record_root_in_trans(struct btrfs_trans_handle *trans, struct btrfs_root *root)
{
	struct btrfs_fs_info *fs_info = root->fs_info;
	int ret;

	if (!test_bit(BTRFS_ROOT_SHAREABLE, &root->state))
		return 0;

	
	smp_rmb();
	if (root->last_trans == trans->transid && !test_bit(BTRFS_ROOT_IN_TRANS_SETUP, &root->state))
		return 0;

	mutex_lock(&fs_info->reloc_mutex);
	ret = record_root_in_trans(trans, root, 0);
	mutex_unlock(&fs_info->reloc_mutex);

	return ret;
}

static inline int is_transaction_blocked(struct btrfs_transaction *trans)
{
	return (trans->state >= TRANS_STATE_COMMIT_START && trans->state < TRANS_STATE_UNBLOCKED && !TRANS_ABORTED(trans));

}


static void wait_current_trans(struct btrfs_fs_info *fs_info)
{
	struct btrfs_transaction *cur_trans;

	spin_lock(&fs_info->trans_lock);
	cur_trans = fs_info->running_transaction;
	if (cur_trans && is_transaction_blocked(cur_trans)) {
		refcount_inc(&cur_trans->use_count);
		spin_unlock(&fs_info->trans_lock);

		wait_event(fs_info->transaction_wait, cur_trans->state >= TRANS_STATE_UNBLOCKED || TRANS_ABORTED(cur_trans));

		btrfs_put_transaction(cur_trans);
	} else {
		spin_unlock(&fs_info->trans_lock);
	}
}

static int may_wait_transaction(struct btrfs_fs_info *fs_info, int type)
{
	if (test_bit(BTRFS_FS_LOG_RECOVERING, &fs_info->flags))
		return 0;

	if (type == TRANS_START)
		return 1;

	return 0;
}

static inline bool need_reserve_reloc_root(struct btrfs_root *root)
{
	struct btrfs_fs_info *fs_info = root->fs_info;

	if (!fs_info->reloc_ctl || !test_bit(BTRFS_ROOT_SHAREABLE, &root->state) || root->root_key.objectid == BTRFS_TREE_RELOC_OBJECTID || root->reloc_root)


		return false;

	return true;
}

static struct btrfs_trans_handle * start_transaction(struct btrfs_root *root, unsigned int num_items, unsigned int type, enum btrfs_reserve_flush_enum flush, bool enforce_qgroups)


{
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_block_rsv *delayed_refs_rsv = &fs_info->delayed_refs_rsv;
	struct btrfs_trans_handle *h;
	struct btrfs_transaction *cur_trans;
	u64 num_bytes = 0;
	u64 qgroup_reserved = 0;
	bool reloc_reserved = false;
	bool do_chunk_alloc = false;
	int ret;

	if (test_bit(BTRFS_FS_STATE_ERROR, &fs_info->fs_state))
		return ERR_PTR(-EROFS);

	if (current->journal_info) {
		WARN_ON(type & TRANS_EXTWRITERS);
		h = current->journal_info;
		refcount_inc(&h->use_count);
		WARN_ON(refcount_read(&h->use_count) > 2);
		h->orig_rsv = h->block_rsv;
		h->block_rsv = NULL;
		goto got_it;
	}

	
	if (num_items && root != fs_info->chunk_root) {
		struct btrfs_block_rsv *rsv = &fs_info->trans_block_rsv;
		u64 delayed_refs_bytes = 0;

		qgroup_reserved = num_items * fs_info->nodesize;
		ret = btrfs_qgroup_reserve_meta_pertrans(root, qgroup_reserved, enforce_qgroups);
		if (ret)
			return ERR_PTR(ret);

		
		num_bytes = btrfs_calc_insert_metadata_size(fs_info, num_items);
		if (flush == BTRFS_RESERVE_FLUSH_ALL && delayed_refs_rsv->full == 0) {
			delayed_refs_bytes = num_bytes;
			num_bytes <<= 1;
		}

		
		if (need_reserve_reloc_root(root)) {
			num_bytes += fs_info->nodesize;
			reloc_reserved = true;
		}

		ret = btrfs_block_rsv_add(root, rsv, num_bytes, flush);
		if (ret)
			goto reserve_fail;
		if (delayed_refs_bytes) {
			btrfs_migrate_to_delayed_refs_rsv(fs_info, rsv, delayed_refs_bytes);
			num_bytes -= delayed_refs_bytes;
		}

		if (rsv->space_info->force_alloc)
			do_chunk_alloc = true;
	} else if (num_items == 0 && flush == BTRFS_RESERVE_FLUSH_ALL && !delayed_refs_rsv->full) {
		
		ret = btrfs_delayed_refs_rsv_refill(fs_info, flush);
		if (ret)
			goto reserve_fail;
	}
again:
	h = kmem_cache_zalloc(btrfs_trans_handle_cachep, GFP_NOFS);
	if (!h) {
		ret = -ENOMEM;
		goto alloc_fail;
	}

	
	if (type & __TRANS_FREEZABLE)
		sb_start_intwrite(fs_info->sb);

	if (may_wait_transaction(fs_info, type))
		wait_current_trans(fs_info);

	do {
		ret = join_transaction(fs_info, type);
		if (ret == -EBUSY) {
			wait_current_trans(fs_info);
			if (unlikely(type == TRANS_ATTACH || type == TRANS_JOIN_NOSTART))
				ret = -ENOENT;
		}
	} while (ret == -EBUSY);

	if (ret < 0)
		goto join_fail;

	cur_trans = fs_info->running_transaction;

	h->transid = cur_trans->transid;
	h->transaction = cur_trans;
	h->root = root;
	refcount_set(&h->use_count, 1);
	h->fs_info = root->fs_info;

	h->type = type;
	h->can_flush_pending_bgs = true;
	INIT_LIST_HEAD(&h->new_bgs);

	smp_mb();
	if (cur_trans->state >= TRANS_STATE_COMMIT_START && may_wait_transaction(fs_info, type)) {
		current->journal_info = h;
		btrfs_commit_transaction(h);
		goto again;
	}

	if (num_bytes) {
		trace_btrfs_space_reservation(fs_info, "transaction", h->transid, num_bytes, 1);
		h->block_rsv = &fs_info->trans_block_rsv;
		h->bytes_reserved = num_bytes;
		h->reloc_reserved = reloc_reserved;
	}

got_it:
	if (!current->journal_info)
		current->journal_info = h;

	
	if (do_chunk_alloc && num_bytes) {
		u64 flags = h->block_rsv->space_info->flags;

		btrfs_chunk_alloc(h, btrfs_get_alloc_profile(fs_info, flags), CHUNK_ALLOC_NO_FORCE);
	}

	
	ret = btrfs_record_root_in_trans(h, root);
	if (ret) {
		
		btrfs_end_transaction(h);
		return ERR_PTR(ret);
	}

	return h;

join_fail:
	if (type & __TRANS_FREEZABLE)
		sb_end_intwrite(fs_info->sb);
	kmem_cache_free(btrfs_trans_handle_cachep, h);
alloc_fail:
	if (num_bytes)
		btrfs_block_rsv_release(fs_info, &fs_info->trans_block_rsv, num_bytes, NULL);
reserve_fail:
	btrfs_qgroup_free_meta_pertrans(root, qgroup_reserved);
	return ERR_PTR(ret);
}

struct btrfs_trans_handle *btrfs_start_transaction(struct btrfs_root *root, unsigned int num_items)
{
	return start_transaction(root, num_items, TRANS_START, BTRFS_RESERVE_FLUSH_ALL, true);
}

struct btrfs_trans_handle *btrfs_start_transaction_fallback_global_rsv( struct btrfs_root *root, unsigned int num_items)

{
	return start_transaction(root, num_items, TRANS_START, BTRFS_RESERVE_FLUSH_ALL_STEAL, false);
}

struct btrfs_trans_handle *btrfs_join_transaction(struct btrfs_root *root)
{
	return start_transaction(root, 0, TRANS_JOIN, BTRFS_RESERVE_NO_FLUSH, true);
}

struct btrfs_trans_handle *btrfs_join_transaction_spacecache(struct btrfs_root *root)
{
	return start_transaction(root, 0, TRANS_JOIN_NOLOCK, BTRFS_RESERVE_NO_FLUSH, true);
}


struct btrfs_trans_handle *btrfs_join_transaction_nostart(struct btrfs_root *root)
{
	return start_transaction(root, 0, TRANS_JOIN_NOSTART, BTRFS_RESERVE_NO_FLUSH, true);
}


struct btrfs_trans_handle *btrfs_attach_transaction(struct btrfs_root *root)
{
	return start_transaction(root, 0, TRANS_ATTACH, BTRFS_RESERVE_NO_FLUSH, true);
}


struct btrfs_trans_handle * btrfs_attach_transaction_barrier(struct btrfs_root *root)
{
	struct btrfs_trans_handle *trans;

	trans = start_transaction(root, 0, TRANS_ATTACH, BTRFS_RESERVE_NO_FLUSH, true);
	if (trans == ERR_PTR(-ENOENT))
		btrfs_wait_for_commit(root->fs_info, 0);

	return trans;
}


static noinline void wait_for_commit(struct btrfs_transaction *commit, const enum btrfs_trans_state min_state)
{
	wait_event(commit->commit_wait, commit->state >= min_state);
}

int btrfs_wait_for_commit(struct btrfs_fs_info *fs_info, u64 transid)
{
	struct btrfs_transaction *cur_trans = NULL, *t;
	int ret = 0;

	if (transid) {
		if (transid <= fs_info->last_trans_committed)
			goto out;

		
		spin_lock(&fs_info->trans_lock);
		list_for_each_entry(t, &fs_info->trans_list, list) {
			if (t->transid == transid) {
				cur_trans = t;
				refcount_inc(&cur_trans->use_count);
				ret = 0;
				break;
			}
			if (t->transid > transid) {
				ret = 0;
				break;
			}
		}
		spin_unlock(&fs_info->trans_lock);

		
		if (!cur_trans) {
			if (transid > fs_info->last_trans_committed)
				ret = -EINVAL;
			goto out;
		}
	} else {
		
		spin_lock(&fs_info->trans_lock);
		list_for_each_entry_reverse(t, &fs_info->trans_list, list) {
			if (t->state >= TRANS_STATE_COMMIT_START) {
				if (t->state == TRANS_STATE_COMPLETED)
					break;
				cur_trans = t;
				refcount_inc(&cur_trans->use_count);
				break;
			}
		}
		spin_unlock(&fs_info->trans_lock);
		if (!cur_trans)
			goto out;  
	}

	wait_for_commit(cur_trans, TRANS_STATE_COMPLETED);
	btrfs_put_transaction(cur_trans);
out:
	return ret;
}

void btrfs_throttle(struct btrfs_fs_info *fs_info)
{
	wait_current_trans(fs_info);
}

static bool should_end_transaction(struct btrfs_trans_handle *trans)
{
	struct btrfs_fs_info *fs_info = trans->fs_info;

	if (btrfs_check_space_for_delayed_refs(fs_info))
		return true;

	return !!btrfs_block_rsv_check(&fs_info->global_block_rsv, 5);
}

bool btrfs_should_end_transaction(struct btrfs_trans_handle *trans)
{
	struct btrfs_transaction *cur_trans = trans->transaction;

	if (cur_trans->state >= TRANS_STATE_COMMIT_START || test_bit(BTRFS_DELAYED_REFS_FLUSHING, &cur_trans->delayed_refs.flags))
		return true;

	return should_end_transaction(trans);
}

static void btrfs_trans_release_metadata(struct btrfs_trans_handle *trans)

{
	struct btrfs_fs_info *fs_info = trans->fs_info;

	if (!trans->block_rsv) {
		ASSERT(!trans->bytes_reserved);
		return;
	}

	if (!trans->bytes_reserved)
		return;

	ASSERT(trans->block_rsv == &fs_info->trans_block_rsv);
	trace_btrfs_space_reservation(fs_info, "transaction", trans->transid, trans->bytes_reserved, 0);
	btrfs_block_rsv_release(fs_info, trans->block_rsv, trans->bytes_reserved, NULL);
	trans->bytes_reserved = 0;
}

static int __btrfs_end_transaction(struct btrfs_trans_handle *trans, int throttle)
{
	struct btrfs_fs_info *info = trans->fs_info;
	struct btrfs_transaction *cur_trans = trans->transaction;
	int err = 0;

	if (refcount_read(&trans->use_count) > 1) {
		refcount_dec(&trans->use_count);
		trans->block_rsv = trans->orig_rsv;
		return 0;
	}

	btrfs_trans_release_metadata(trans);
	trans->block_rsv = NULL;

	btrfs_create_pending_block_groups(trans);

	btrfs_trans_release_chunk_metadata(trans);

	if (trans->type & __TRANS_FREEZABLE)
		sb_end_intwrite(info->sb);

	WARN_ON(cur_trans != info->running_transaction);
	WARN_ON(atomic_read(&cur_trans->num_writers) < 1);
	atomic_dec(&cur_trans->num_writers);
	extwriter_counter_dec(cur_trans, trans->type);

	cond_wake_up(&cur_trans->writer_wait);
	btrfs_put_transaction(cur_trans);

	if (current->journal_info == trans)
		current->journal_info = NULL;

	if (throttle)
		btrfs_run_delayed_iputs(info);

	if (TRANS_ABORTED(trans) || test_bit(BTRFS_FS_STATE_ERROR, &info->fs_state)) {
		wake_up_process(info->transaction_kthread);
		if (TRANS_ABORTED(trans))
			err = trans->aborted;
		else err = -EROFS;
	}

	kmem_cache_free(btrfs_trans_handle_cachep, trans);
	return err;
}

int btrfs_end_transaction(struct btrfs_trans_handle *trans)
{
	return __btrfs_end_transaction(trans, 0);
}

int btrfs_end_transaction_throttle(struct btrfs_trans_handle *trans)
{
	return __btrfs_end_transaction(trans, 1);
}


int btrfs_write_marked_extents(struct btrfs_fs_info *fs_info, struct extent_io_tree *dirty_pages, int mark)
{
	int err = 0;
	int werr = 0;
	struct address_space *mapping = fs_info->btree_inode->i_mapping;
	struct extent_state *cached_state = NULL;
	u64 start = 0;
	u64 end;

	atomic_inc(&BTRFS_I(fs_info->btree_inode)->sync_writers);
	while (!find_first_extent_bit(dirty_pages, start, &start, &end, mark, &cached_state)) {
		bool wait_writeback = false;

		err = convert_extent_bit(dirty_pages, start, end, EXTENT_NEED_WAIT, mark, &cached_state);

		
		if (err == -ENOMEM) {
			err = 0;
			wait_writeback = true;
		}
		if (!err)
			err = filemap_fdatawrite_range(mapping, start, end);
		if (err)
			werr = err;
		else if (wait_writeback)
			werr = filemap_fdatawait_range(mapping, start, end);
		free_extent_state(cached_state);
		cached_state = NULL;
		cond_resched();
		start = end + 1;
	}
	atomic_dec(&BTRFS_I(fs_info->btree_inode)->sync_writers);
	return werr;
}


static int __btrfs_wait_marked_extents(struct btrfs_fs_info *fs_info, struct extent_io_tree *dirty_pages)
{
	int err = 0;
	int werr = 0;
	struct address_space *mapping = fs_info->btree_inode->i_mapping;
	struct extent_state *cached_state = NULL;
	u64 start = 0;
	u64 end;

	while (!find_first_extent_bit(dirty_pages, start, &start, &end, EXTENT_NEED_WAIT, &cached_state)) {
		
		err = clear_extent_bit(dirty_pages, start, end, EXTENT_NEED_WAIT, 0, 0, &cached_state);
		if (err == -ENOMEM)
			err = 0;
		if (!err)
			err = filemap_fdatawait_range(mapping, start, end);
		if (err)
			werr = err;
		free_extent_state(cached_state);
		cached_state = NULL;
		cond_resched();
		start = end + 1;
	}
	if (err)
		werr = err;
	return werr;
}

static int btrfs_wait_extents(struct btrfs_fs_info *fs_info, struct extent_io_tree *dirty_pages)
{
	bool errors = false;
	int err;

	err = __btrfs_wait_marked_extents(fs_info, dirty_pages);
	if (test_and_clear_bit(BTRFS_FS_BTREE_ERR, &fs_info->flags))
		errors = true;

	if (errors && !err)
		err = -EIO;
	return err;
}

int btrfs_wait_tree_log_extents(struct btrfs_root *log_root, int mark)
{
	struct btrfs_fs_info *fs_info = log_root->fs_info;
	struct extent_io_tree *dirty_pages = &log_root->dirty_log_pages;
	bool errors = false;
	int err;

	ASSERT(log_root->root_key.objectid == BTRFS_TREE_LOG_OBJECTID);

	err = __btrfs_wait_marked_extents(fs_info, dirty_pages);
	if ((mark & EXTENT_DIRTY) && test_and_clear_bit(BTRFS_FS_LOG1_ERR, &fs_info->flags))
		errors = true;

	if ((mark & EXTENT_NEW) && test_and_clear_bit(BTRFS_FS_LOG2_ERR, &fs_info->flags))
		errors = true;

	if (errors && !err)
		err = -EIO;
	return err;
}


static int btrfs_write_and_wait_transaction(struct btrfs_trans_handle *trans)
{
	int ret;
	int ret2;
	struct extent_io_tree *dirty_pages = &trans->transaction->dirty_pages;
	struct btrfs_fs_info *fs_info = trans->fs_info;
	struct blk_plug plug;

	blk_start_plug(&plug);
	ret = btrfs_write_marked_extents(fs_info, dirty_pages, EXTENT_DIRTY);
	blk_finish_plug(&plug);
	ret2 = btrfs_wait_extents(fs_info, dirty_pages);

	extent_io_tree_release(&trans->transaction->dirty_pages);

	if (ret)
		return ret;
	else if (ret2)
		return ret2;
	else return 0;
}


static int update_cowonly_root(struct btrfs_trans_handle *trans, struct btrfs_root *root)
{
	int ret;
	u64 old_root_bytenr;
	u64 old_root_used;
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_root *tree_root = fs_info->tree_root;

	old_root_used = btrfs_root_used(&root->root_item);

	while (1) {
		old_root_bytenr = btrfs_root_bytenr(&root->root_item);
		if (old_root_bytenr == root->node->start && old_root_used == btrfs_root_used(&root->root_item))
			break;

		btrfs_set_root_node(&root->root_item, root->node);
		ret = btrfs_update_root(trans, tree_root, &root->root_key, &root->root_item);

		if (ret)
			return ret;

		old_root_used = btrfs_root_used(&root->root_item);
	}

	return 0;
}


static noinline int commit_cowonly_roots(struct btrfs_trans_handle *trans)
{
	struct btrfs_fs_info *fs_info = trans->fs_info;
	struct list_head *dirty_bgs = &trans->transaction->dirty_bgs;
	struct list_head *io_bgs = &trans->transaction->io_bgs;
	struct list_head *next;
	struct extent_buffer *eb;
	int ret;

	eb = btrfs_lock_root_node(fs_info->tree_root);
	ret = btrfs_cow_block(trans, fs_info->tree_root, eb, NULL, 0, &eb, BTRFS_NESTING_COW);
	btrfs_tree_unlock(eb);
	free_extent_buffer(eb);

	if (ret)
		return ret;

	ret = btrfs_run_dev_stats(trans);
	if (ret)
		return ret;
	ret = btrfs_run_dev_replace(trans);
	if (ret)
		return ret;
	ret = btrfs_run_qgroups(trans);
	if (ret)
		return ret;

	ret = btrfs_setup_space_cache(trans);
	if (ret)
		return ret;

again:
	while (!list_empty(&fs_info->dirty_cowonly_roots)) {
		struct btrfs_root *root;
		next = fs_info->dirty_cowonly_roots.next;
		list_del_init(next);
		root = list_entry(next, struct btrfs_root, dirty_list);
		clear_bit(BTRFS_ROOT_DIRTY, &root->state);

		if (root != fs_info->extent_root)
			list_add_tail(&root->dirty_list, &trans->transaction->switch_commits);
		ret = update_cowonly_root(trans, root);
		if (ret)
			return ret;
	}

	
	ret = btrfs_run_delayed_refs(trans, (unsigned long)-1);
	if (ret)
		return ret;

	while (!list_empty(dirty_bgs) || !list_empty(io_bgs)) {
		ret = btrfs_write_dirty_block_groups(trans);
		if (ret)
			return ret;

		
		ret = btrfs_run_delayed_refs(trans, (unsigned long)-1);
		if (ret)
			return ret;
	}

	if (!list_empty(&fs_info->dirty_cowonly_roots))
		goto again;

	list_add_tail(&fs_info->extent_root->dirty_list, &trans->transaction->switch_commits);

	
	fs_info->dev_replace.committed_cursor_left = fs_info->dev_replace.cursor_left_last_write_of_item;

	return 0;
}


void btrfs_add_dead_root(struct btrfs_root *root)
{
	struct btrfs_fs_info *fs_info = root->fs_info;

	spin_lock(&fs_info->trans_lock);
	if (list_empty(&root->root_list)) {
		btrfs_grab_root(root);
		list_add_tail(&root->root_list, &fs_info->dead_roots);
	}
	spin_unlock(&fs_info->trans_lock);
}


static noinline int commit_fs_roots(struct btrfs_trans_handle *trans)
{
	struct btrfs_fs_info *fs_info = trans->fs_info;
	struct btrfs_root *gang[8];
	int i;
	int ret;

	spin_lock(&fs_info->fs_roots_radix_lock);
	while (1) {
		ret = radix_tree_gang_lookup_tag(&fs_info->fs_roots_radix, (void **)gang, 0, ARRAY_SIZE(gang), BTRFS_ROOT_TRANS_TAG);


		if (ret == 0)
			break;
		for (i = 0; i < ret; i++) {
			struct btrfs_root *root = gang[i];
			int ret2;

			radix_tree_tag_clear(&fs_info->fs_roots_radix, (unsigned long)root->root_key.objectid, BTRFS_ROOT_TRANS_TAG);

			spin_unlock(&fs_info->fs_roots_radix_lock);

			btrfs_free_log(trans, root);
			ret2 = btrfs_update_reloc_root(trans, root);
			if (ret2)
				return ret2;

			
			clear_bit(BTRFS_ROOT_FORCE_COW, &root->state);
			smp_mb__after_atomic();

			if (root->commit_root != root->node) {
				list_add_tail(&root->dirty_list, &trans->transaction->switch_commits);
				btrfs_set_root_node(&root->root_item, root->node);
			}

			ret2 = btrfs_update_root(trans, fs_info->tree_root, &root->root_key, &root->root_item);

			if (ret2)
				return ret2;
			spin_lock(&fs_info->fs_roots_radix_lock);
			btrfs_qgroup_free_meta_all_pertrans(root);
		}
	}
	spin_unlock(&fs_info->fs_roots_radix_lock);
	return 0;
}


int btrfs_defrag_root(struct btrfs_root *root)
{
	struct btrfs_fs_info *info = root->fs_info;
	struct btrfs_trans_handle *trans;
	int ret;

	if (test_and_set_bit(BTRFS_ROOT_DEFRAG_RUNNING, &root->state))
		return 0;

	while (1) {
		trans = btrfs_start_transaction(root, 0);
		if (IS_ERR(trans)) {
			ret = PTR_ERR(trans);
			break;
		}

		ret = btrfs_defrag_leaves(trans, root);

		btrfs_end_transaction(trans);
		btrfs_btree_balance_dirty(info);
		cond_resched();

		if (btrfs_fs_closing(info) || ret != -EAGAIN)
			break;

		if (btrfs_defrag_cancelled(info)) {
			btrfs_debug(info, "defrag_root cancelled");
			ret = -EAGAIN;
			break;
		}
	}
	clear_bit(BTRFS_ROOT_DEFRAG_RUNNING, &root->state);
	return ret;
}


static int qgroup_account_snapshot(struct btrfs_trans_handle *trans, struct btrfs_root *src, struct btrfs_root *parent, struct btrfs_qgroup_inherit *inherit, u64 dst_objectid)



{
	struct btrfs_fs_info *fs_info = src->fs_info;
	int ret;

	
	if (!test_bit(BTRFS_FS_QUOTA_ENABLED, &fs_info->flags))
		return 0;

	
	ret = record_root_in_trans(trans, src, 1);
	if (ret)
		return ret;

	
	ret = btrfs_run_delayed_refs(trans, (unsigned long)-1);
	if (ret) {
		btrfs_abort_transaction(trans, ret);
		return ret;
	}

	
	mutex_lock(&fs_info->tree_log_mutex);

	ret = commit_fs_roots(trans);
	if (ret)
		goto out;
	ret = btrfs_qgroup_account_extents(trans);
	if (ret < 0)
		goto out;

	
	ret = btrfs_qgroup_inherit(trans, src->root_key.objectid, dst_objectid, inherit);
	if (ret < 0)
		goto out;

	
	ret = commit_cowonly_roots(trans);
	if (ret)
		goto out;
	switch_commit_roots(trans);
	ret = btrfs_write_and_wait_transaction(trans);
	if (ret)
		btrfs_handle_fs_error(fs_info, ret, "Error while writing out transaction for qgroup");

out:
	mutex_unlock(&fs_info->tree_log_mutex);

	
	if (!ret)
		ret = record_root_in_trans(trans, parent, 1);
	return ret;
}


static noinline int create_pending_snapshot(struct btrfs_trans_handle *trans, struct btrfs_pending_snapshot *pending)
{

	struct btrfs_fs_info *fs_info = trans->fs_info;
	struct btrfs_key key;
	struct btrfs_root_item *new_root_item;
	struct btrfs_root *tree_root = fs_info->tree_root;
	struct btrfs_root *root = pending->root;
	struct btrfs_root *parent_root;
	struct btrfs_block_rsv *rsv;
	struct inode *parent_inode;
	struct btrfs_path *path;
	struct btrfs_dir_item *dir_item;
	struct dentry *dentry;
	struct extent_buffer *tmp;
	struct extent_buffer *old;
	struct timespec64 cur_time;
	int ret = 0;
	u64 to_reserve = 0;
	u64 index = 0;
	u64 objectid;
	u64 root_flags;

	ASSERT(pending->path);
	path = pending->path;

	ASSERT(pending->root_item);
	new_root_item = pending->root_item;

	pending->error = btrfs_get_free_objectid(tree_root, &objectid);
	if (pending->error)
		goto no_free_objectid;

	
	btrfs_set_skip_qgroup(trans, objectid);

	btrfs_reloc_pre_snapshot(pending, &to_reserve);

	if (to_reserve > 0) {
		pending->error = btrfs_block_rsv_add(root, &pending->block_rsv, to_reserve, BTRFS_RESERVE_NO_FLUSH);


		if (pending->error)
			goto clear_skip_qgroup;
	}

	key.objectid = objectid;
	key.offset = (u64)-1;
	key.type = BTRFS_ROOT_ITEM_KEY;

	rsv = trans->block_rsv;
	trans->block_rsv = &pending->block_rsv;
	trans->bytes_reserved = trans->block_rsv->reserved;
	trace_btrfs_space_reservation(fs_info, "transaction", trans->transid, trans->bytes_reserved, 1);

	dentry = pending->dentry;
	parent_inode = pending->dir;
	parent_root = BTRFS_I(parent_inode)->root;
	ret = record_root_in_trans(trans, parent_root, 0);
	if (ret)
		goto fail;
	cur_time = current_time(parent_inode);

	
	ret = btrfs_set_inode_index(BTRFS_I(parent_inode), &index);
	BUG_ON(ret); 

	
	dir_item = btrfs_lookup_dir_item(NULL, parent_root, path, btrfs_ino(BTRFS_I(parent_inode)), dentry->d_name.name, dentry->d_name.len, 0);


	if (dir_item != NULL && !IS_ERR(dir_item)) {
		pending->error = -EEXIST;
		goto dir_item_existed;
	} else if (IS_ERR(dir_item)) {
		ret = PTR_ERR(dir_item);
		btrfs_abort_transaction(trans, ret);
		goto fail;
	}
	btrfs_release_path(path);

	
	ret = btrfs_run_delayed_items(trans);
	if (ret) {	
		btrfs_abort_transaction(trans, ret);
		goto fail;
	}

	ret = record_root_in_trans(trans, root, 0);
	if (ret) {
		btrfs_abort_transaction(trans, ret);
		goto fail;
	}
	btrfs_set_root_last_snapshot(&root->root_item, trans->transid);
	memcpy(new_root_item, &root->root_item, sizeof(*new_root_item));
	btrfs_check_and_init_root_item(new_root_item);

	root_flags = btrfs_root_flags(new_root_item);
	if (pending->readonly)
		root_flags |= BTRFS_ROOT_SUBVOL_RDONLY;
	else root_flags &= ~BTRFS_ROOT_SUBVOL_RDONLY;
	btrfs_set_root_flags(new_root_item, root_flags);

	btrfs_set_root_generation_v2(new_root_item, trans->transid);
	generate_random_guid(new_root_item->uuid);
	memcpy(new_root_item->parent_uuid, root->root_item.uuid, BTRFS_UUID_SIZE);
	if (!(root_flags & BTRFS_ROOT_SUBVOL_RDONLY)) {
		memset(new_root_item->received_uuid, 0, sizeof(new_root_item->received_uuid));
		memset(&new_root_item->stime, 0, sizeof(new_root_item->stime));
		memset(&new_root_item->rtime, 0, sizeof(new_root_item->rtime));
		btrfs_set_root_stransid(new_root_item, 0);
		btrfs_set_root_rtransid(new_root_item, 0);
	}
	btrfs_set_stack_timespec_sec(&new_root_item->otime, cur_time.tv_sec);
	btrfs_set_stack_timespec_nsec(&new_root_item->otime, cur_time.tv_nsec);
	btrfs_set_root_otransid(new_root_item, trans->transid);

	old = btrfs_lock_root_node(root);
	ret = btrfs_cow_block(trans, root, old, NULL, 0, &old, BTRFS_NESTING_COW);
	if (ret) {
		btrfs_tree_unlock(old);
		free_extent_buffer(old);
		btrfs_abort_transaction(trans, ret);
		goto fail;
	}

	ret = btrfs_copy_root(trans, root, old, &tmp, objectid);
	
	btrfs_tree_unlock(old);
	free_extent_buffer(old);
	if (ret) {
		btrfs_abort_transaction(trans, ret);
		goto fail;
	}
	
	set_bit(BTRFS_ROOT_FORCE_COW, &root->state);
	smp_wmb();

	btrfs_set_root_node(new_root_item, tmp);
	
	key.offset = trans->transid;
	ret = btrfs_insert_root(trans, tree_root, &key, new_root_item);
	btrfs_tree_unlock(tmp);
	free_extent_buffer(tmp);
	if (ret) {
		btrfs_abort_transaction(trans, ret);
		goto fail;
	}

	
	ret = btrfs_add_root_ref(trans, objectid, parent_root->root_key.objectid, btrfs_ino(BTRFS_I(parent_inode)), index, dentry->d_name.name, dentry->d_name.len);


	if (ret) {
		btrfs_abort_transaction(trans, ret);
		goto fail;
	}

	key.offset = (u64)-1;
	pending->snap = btrfs_get_new_fs_root(fs_info, objectid, pending->anon_dev);
	if (IS_ERR(pending->snap)) {
		ret = PTR_ERR(pending->snap);
		pending->snap = NULL;
		btrfs_abort_transaction(trans, ret);
		goto fail;
	}

	ret = btrfs_reloc_post_snapshot(trans, pending);
	if (ret) {
		btrfs_abort_transaction(trans, ret);
		goto fail;
	}

	
	ret = qgroup_account_snapshot(trans, root, parent_root, pending->inherit, objectid);
	if (ret < 0)
		goto fail;

	ret = btrfs_insert_dir_item(trans, dentry->d_name.name, dentry->d_name.len, BTRFS_I(parent_inode), &key, BTRFS_FT_DIR, index);

	
	BUG_ON(ret == -EEXIST || ret == -EOVERFLOW);
	if (ret) {
		btrfs_abort_transaction(trans, ret);
		goto fail;
	}

	btrfs_i_size_write(BTRFS_I(parent_inode), parent_inode->i_size + dentry->d_name.len * 2);
	parent_inode->i_mtime = parent_inode->i_ctime = current_time(parent_inode);
	ret = btrfs_update_inode_fallback(trans, parent_root, BTRFS_I(parent_inode));
	if (ret) {
		btrfs_abort_transaction(trans, ret);
		goto fail;
	}
	ret = btrfs_uuid_tree_add(trans, new_root_item->uuid, BTRFS_UUID_KEY_SUBVOL, objectid);

	if (ret) {
		btrfs_abort_transaction(trans, ret);
		goto fail;
	}
	if (!btrfs_is_empty_uuid(new_root_item->received_uuid)) {
		ret = btrfs_uuid_tree_add(trans, new_root_item->received_uuid, BTRFS_UUID_KEY_RECEIVED_SUBVOL, objectid);

		if (ret && ret != -EEXIST) {
			btrfs_abort_transaction(trans, ret);
			goto fail;
		}
	}

fail:
	pending->error = ret;
dir_item_existed:
	trans->block_rsv = rsv;
	trans->bytes_reserved = 0;
clear_skip_qgroup:
	btrfs_clear_skip_qgroup(trans);
no_free_objectid:
	kfree(new_root_item);
	pending->root_item = NULL;
	btrfs_free_path(path);
	pending->path = NULL;

	return ret;
}


static noinline int create_pending_snapshots(struct btrfs_trans_handle *trans)
{
	struct btrfs_pending_snapshot *pending, *next;
	struct list_head *head = &trans->transaction->pending_snapshots;
	int ret = 0;

	list_for_each_entry_safe(pending, next, head, list) {
		list_del(&pending->list);
		ret = create_pending_snapshot(trans, pending);
		if (ret)
			break;
	}
	return ret;
}

static void update_super_roots(struct btrfs_fs_info *fs_info)
{
	struct btrfs_root_item *root_item;
	struct btrfs_super_block *super;

	super = fs_info->super_copy;

	root_item = &fs_info->chunk_root->root_item;
	super->chunk_root = root_item->bytenr;
	super->chunk_root_generation = root_item->generation;
	super->chunk_root_level = root_item->level;

	root_item = &fs_info->tree_root->root_item;
	super->root = root_item->bytenr;
	super->generation = root_item->generation;
	super->root_level = root_item->level;
	if (btrfs_test_opt(fs_info, SPACE_CACHE))
		super->cache_generation = root_item->generation;
	else if (test_bit(BTRFS_FS_CLEANUP_SPACE_CACHE_V1, &fs_info->flags))
		super->cache_generation = 0;
	if (test_bit(BTRFS_FS_UPDATE_UUID_TREE_GEN, &fs_info->flags))
		super->uuid_tree_generation = root_item->generation;
}

int btrfs_transaction_in_commit(struct btrfs_fs_info *info)
{
	struct btrfs_transaction *trans;
	int ret = 0;

	spin_lock(&info->trans_lock);
	trans = info->running_transaction;
	if (trans)
		ret = (trans->state >= TRANS_STATE_COMMIT_START);
	spin_unlock(&info->trans_lock);
	return ret;
}

int btrfs_transaction_blocked(struct btrfs_fs_info *info)
{
	struct btrfs_transaction *trans;
	int ret = 0;

	spin_lock(&info->trans_lock);
	trans = info->running_transaction;
	if (trans)
		ret = is_transaction_blocked(trans);
	spin_unlock(&info->trans_lock);
	return ret;
}


struct btrfs_async_commit {
	struct btrfs_trans_handle *newtrans;
	struct work_struct work;
};

static void do_async_commit(struct work_struct *work)
{
	struct btrfs_async_commit *ac = container_of(work, struct btrfs_async_commit, work);

	
	if (ac->newtrans->type & __TRANS_FREEZABLE)
		__sb_writers_acquired(ac->newtrans->fs_info->sb, SB_FREEZE_FS);

	current->journal_info = ac->newtrans;

	btrfs_commit_transaction(ac->newtrans);
	kfree(ac);
}

int btrfs_commit_transaction_async(struct btrfs_trans_handle *trans)
{
	struct btrfs_fs_info *fs_info = trans->fs_info;
	struct btrfs_async_commit *ac;
	struct btrfs_transaction *cur_trans;

	ac = kmalloc(sizeof(*ac), GFP_NOFS);
	if (!ac)
		return -ENOMEM;

	INIT_WORK(&ac->work, do_async_commit);
	ac->newtrans = btrfs_join_transaction(trans->root);
	if (IS_ERR(ac->newtrans)) {
		int err = PTR_ERR(ac->newtrans);
		kfree(ac);
		return err;
	}

	
	cur_trans = trans->transaction;
	refcount_inc(&cur_trans->use_count);

	btrfs_end_transaction(trans);

	
	if (ac->newtrans->type & __TRANS_FREEZABLE)
		__sb_writers_release(fs_info->sb, SB_FREEZE_FS);

	schedule_work(&ac->work);
	
	wait_event(fs_info->transaction_blocked_wait, cur_trans->state >= TRANS_STATE_COMMIT_START || TRANS_ABORTED(cur_trans));

	if (current->journal_info == trans)
		current->journal_info = NULL;

	btrfs_put_transaction(cur_trans);
	return 0;
}


static void cleanup_transaction(struct btrfs_trans_handle *trans, int err)
{
	struct btrfs_fs_info *fs_info = trans->fs_info;
	struct btrfs_transaction *cur_trans = trans->transaction;

	WARN_ON(refcount_read(&trans->use_count) > 1);

	btrfs_abort_transaction(trans, err);

	spin_lock(&fs_info->trans_lock);

	
	BUG_ON(list_empty(&cur_trans->list));

	if (cur_trans == fs_info->running_transaction) {
		cur_trans->state = TRANS_STATE_COMMIT_DOING;
		spin_unlock(&fs_info->trans_lock);
		wait_event(cur_trans->writer_wait, atomic_read(&cur_trans->num_writers) == 1);

		spin_lock(&fs_info->trans_lock);
	}

	
	list_del_init(&cur_trans->list);

	spin_unlock(&fs_info->trans_lock);

	btrfs_cleanup_one_transaction(trans->transaction, fs_info);

	spin_lock(&fs_info->trans_lock);
	if (cur_trans == fs_info->running_transaction)
		fs_info->running_transaction = NULL;
	spin_unlock(&fs_info->trans_lock);

	if (trans->type & __TRANS_FREEZABLE)
		sb_end_intwrite(fs_info->sb);
	btrfs_put_transaction(cur_trans);
	btrfs_put_transaction(cur_trans);

	trace_btrfs_transaction_commit(trans->root);

	if (current->journal_info == trans)
		current->journal_info = NULL;
	btrfs_scrub_cancel(fs_info);

	kmem_cache_free(btrfs_trans_handle_cachep, trans);
}


static void btrfs_cleanup_pending_block_groups(struct btrfs_trans_handle *trans)
{
       struct btrfs_fs_info *fs_info = trans->fs_info;
       struct btrfs_block_group *block_group, *tmp;

       list_for_each_entry_safe(block_group, tmp, &trans->new_bgs, bg_list) {
               btrfs_delayed_refs_rsv_release(fs_info, 1);
               list_del_init(&block_group->bg_list);
       }
}

static inline int btrfs_start_delalloc_flush(struct btrfs_fs_info *fs_info)
{
	
	if (btrfs_test_opt(fs_info, FLUSHONCOMMIT))
		writeback_inodes_sb(fs_info->sb, WB_REASON_SYNC);
	return 0;
}

static inline void btrfs_wait_delalloc_flush(struct btrfs_fs_info *fs_info)
{
	if (btrfs_test_opt(fs_info, FLUSHONCOMMIT))
		btrfs_wait_ordered_roots(fs_info, U64_MAX, 0, (u64)-1);
}

int btrfs_commit_transaction(struct btrfs_trans_handle *trans)
{
	struct btrfs_fs_info *fs_info = trans->fs_info;
	struct btrfs_transaction *cur_trans = trans->transaction;
	struct btrfs_transaction *prev_trans = NULL;
	int ret;

	ASSERT(refcount_read(&trans->use_count) == 1);

	
	if (TRANS_ABORTED(cur_trans)) {
		ret = cur_trans->aborted;
		btrfs_end_transaction(trans);
		return ret;
	}

	btrfs_trans_release_metadata(trans);
	trans->block_rsv = NULL;

	
	if (!test_and_set_bit(BTRFS_DELAYED_REFS_FLUSHING, &cur_trans->delayed_refs.flags)) {
		
		ret = btrfs_run_delayed_refs(trans, 0);
		if (ret) {
			btrfs_end_transaction(trans);
			return ret;
		}
	}

	btrfs_create_pending_block_groups(trans);

	if (!test_bit(BTRFS_TRANS_DIRTY_BG_RUN, &cur_trans->flags)) {
		int run_it = 0;

		
		mutex_lock(&fs_info->ro_block_group_mutex);
		if (!test_and_set_bit(BTRFS_TRANS_DIRTY_BG_RUN, &cur_trans->flags))
			run_it = 1;
		mutex_unlock(&fs_info->ro_block_group_mutex);

		if (run_it) {
			ret = btrfs_start_dirty_block_groups(trans);
			if (ret) {
				btrfs_end_transaction(trans);
				return ret;
			}
		}
	}

	spin_lock(&fs_info->trans_lock);
	if (cur_trans->state >= TRANS_STATE_COMMIT_START) {
		enum btrfs_trans_state want_state = TRANS_STATE_COMPLETED;

		spin_unlock(&fs_info->trans_lock);
		refcount_inc(&cur_trans->use_count);

		if (trans->in_fsync)
			want_state = TRANS_STATE_SUPER_COMMITTED;
		ret = btrfs_end_transaction(trans);
		wait_for_commit(cur_trans, want_state);

		if (TRANS_ABORTED(cur_trans))
			ret = cur_trans->aborted;

		btrfs_put_transaction(cur_trans);

		return ret;
	}

	cur_trans->state = TRANS_STATE_COMMIT_START;
	wake_up(&fs_info->transaction_blocked_wait);

	if (cur_trans->list.prev != &fs_info->trans_list) {
		enum btrfs_trans_state want_state = TRANS_STATE_COMPLETED;

		if (trans->in_fsync)
			want_state = TRANS_STATE_SUPER_COMMITTED;

		prev_trans = list_entry(cur_trans->list.prev, struct btrfs_transaction, list);
		if (prev_trans->state < want_state) {
			refcount_inc(&prev_trans->use_count);
			spin_unlock(&fs_info->trans_lock);

			wait_for_commit(prev_trans, want_state);

			ret = READ_ONCE(prev_trans->aborted);

			btrfs_put_transaction(prev_trans);
			if (ret)
				goto cleanup_transaction;
		} else {
			spin_unlock(&fs_info->trans_lock);
		}
	} else {
		spin_unlock(&fs_info->trans_lock);
		
		if (test_bit(BTRFS_FS_STATE_TRANS_ABORTED, &fs_info->fs_state)) {
			ret = -EROFS;
			goto cleanup_transaction;
		}
	}

	extwriter_counter_dec(cur_trans, trans->type);

	ret = btrfs_start_delalloc_flush(fs_info);
	if (ret)
		goto cleanup_transaction;

	ret = btrfs_run_delayed_items(trans);
	if (ret)
		goto cleanup_transaction;

	wait_event(cur_trans->writer_wait, extwriter_counter_read(cur_trans) == 0);

	
	ret = btrfs_run_delayed_items(trans);
	if (ret)
		goto cleanup_transaction;

	btrfs_wait_delalloc_flush(fs_info);

	
	wait_event(cur_trans->pending_wait, atomic_read(&cur_trans->pending_ordered) == 0);

	btrfs_scrub_pause(fs_info);
	
	spin_lock(&fs_info->trans_lock);
	cur_trans->state = TRANS_STATE_COMMIT_DOING;
	spin_unlock(&fs_info->trans_lock);
	wait_event(cur_trans->writer_wait, atomic_read(&cur_trans->num_writers) == 1);

	if (TRANS_ABORTED(cur_trans)) {
		ret = cur_trans->aborted;
		goto scrub_continue;
	}
	
	mutex_lock(&fs_info->reloc_mutex);

	
	ret = create_pending_snapshots(trans);
	if (ret)
		goto unlock_reloc;

	
	ret = btrfs_run_delayed_items(trans);
	if (ret)
		goto unlock_reloc;

	ret = btrfs_run_delayed_refs(trans, (unsigned long)-1);
	if (ret)
		goto unlock_reloc;

	
	btrfs_assert_delayed_root_empty(fs_info);

	WARN_ON(cur_trans != trans->transaction);

	
	mutex_lock(&fs_info->tree_log_mutex);

	ret = commit_fs_roots(trans);
	if (ret)
		goto unlock_tree_log;

	
	btrfs_apply_pending_changes(fs_info);

	
	btrfs_free_log_root_tree(trans, fs_info);

	
	ret = btrfs_qgroup_account_extents(trans);
	if (ret < 0)
		goto unlock_tree_log;

	ret = commit_cowonly_roots(trans);
	if (ret)
		goto unlock_tree_log;

	
	if (TRANS_ABORTED(cur_trans)) {
		ret = cur_trans->aborted;
		goto unlock_tree_log;
	}

	cur_trans = fs_info->running_transaction;

	btrfs_set_root_node(&fs_info->tree_root->root_item, fs_info->tree_root->node);
	list_add_tail(&fs_info->tree_root->dirty_list, &cur_trans->switch_commits);

	btrfs_set_root_node(&fs_info->chunk_root->root_item, fs_info->chunk_root->node);
	list_add_tail(&fs_info->chunk_root->dirty_list, &cur_trans->switch_commits);

	switch_commit_roots(trans);

	ASSERT(list_empty(&cur_trans->dirty_bgs));
	ASSERT(list_empty(&cur_trans->io_bgs));
	update_super_roots(fs_info);

	btrfs_set_super_log_root(fs_info->super_copy, 0);
	btrfs_set_super_log_root_level(fs_info->super_copy, 0);
	memcpy(fs_info->super_for_commit, fs_info->super_copy, sizeof(*fs_info->super_copy));

	btrfs_commit_device_sizes(cur_trans);

	clear_bit(BTRFS_FS_LOG1_ERR, &fs_info->flags);
	clear_bit(BTRFS_FS_LOG2_ERR, &fs_info->flags);

	btrfs_trans_release_chunk_metadata(trans);

	spin_lock(&fs_info->trans_lock);
	cur_trans->state = TRANS_STATE_UNBLOCKED;
	fs_info->running_transaction = NULL;
	spin_unlock(&fs_info->trans_lock);
	mutex_unlock(&fs_info->reloc_mutex);

	wake_up(&fs_info->transaction_wait);

	ret = btrfs_write_and_wait_transaction(trans);
	if (ret) {
		btrfs_handle_fs_error(fs_info, ret, "Error while writing out transaction");
		
		mutex_unlock(&fs_info->tree_log_mutex);
		goto scrub_continue;
	}

	
	btrfs_free_redirty_list(cur_trans);

	ret = write_all_supers(fs_info, 0);
	
	mutex_unlock(&fs_info->tree_log_mutex);
	if (ret)
		goto scrub_continue;

	
	cur_trans->state = TRANS_STATE_SUPER_COMMITTED;
	wake_up(&cur_trans->commit_wait);

	btrfs_finish_extent_commit(trans);

	if (test_bit(BTRFS_TRANS_HAVE_FREE_BGS, &cur_trans->flags))
		btrfs_clear_space_info_full(fs_info);

	fs_info->last_trans_committed = cur_trans->transid;
	
	cur_trans->state = TRANS_STATE_COMPLETED;
	wake_up(&cur_trans->commit_wait);

	spin_lock(&fs_info->trans_lock);
	list_del_init(&cur_trans->list);
	spin_unlock(&fs_info->trans_lock);

	btrfs_put_transaction(cur_trans);
	btrfs_put_transaction(cur_trans);

	if (trans->type & __TRANS_FREEZABLE)
		sb_end_intwrite(fs_info->sb);

	trace_btrfs_transaction_commit(trans->root);

	btrfs_scrub_continue(fs_info);

	if (current->journal_info == trans)
		current->journal_info = NULL;

	kmem_cache_free(btrfs_trans_handle_cachep, trans);

	return ret;

unlock_tree_log:
	mutex_unlock(&fs_info->tree_log_mutex);
unlock_reloc:
	mutex_unlock(&fs_info->reloc_mutex);
scrub_continue:
	btrfs_scrub_continue(fs_info);
cleanup_transaction:
	btrfs_trans_release_metadata(trans);
	btrfs_cleanup_pending_block_groups(trans);
	btrfs_trans_release_chunk_metadata(trans);
	trans->block_rsv = NULL;
	btrfs_warn(fs_info, "Skipping commit of aborted transaction.");
	if (current->journal_info == trans)
		current->journal_info = NULL;
	cleanup_transaction(trans, ret);

	return ret;
}


int btrfs_clean_one_deleted_snapshot(struct btrfs_root *root)
{
	int ret;
	struct btrfs_fs_info *fs_info = root->fs_info;

	spin_lock(&fs_info->trans_lock);
	if (list_empty(&fs_info->dead_roots)) {
		spin_unlock(&fs_info->trans_lock);
		return 0;
	}
	root = list_first_entry(&fs_info->dead_roots, struct btrfs_root, root_list);
	list_del_init(&root->root_list);
	spin_unlock(&fs_info->trans_lock);

	btrfs_debug(fs_info, "cleaner removing %llu", root->root_key.objectid);

	btrfs_kill_all_delayed_nodes(root);

	if (btrfs_header_backref_rev(root->node) < BTRFS_MIXED_BACKREF_REV)
		ret = btrfs_drop_snapshot(root, 0, 0);
	else ret = btrfs_drop_snapshot(root, 1, 0);

	btrfs_put_root(root);
	return (ret < 0) ? 0 : 1;
}

void btrfs_apply_pending_changes(struct btrfs_fs_info *fs_info)
{
	unsigned long prev;
	unsigned long bit;

	prev = xchg(&fs_info->pending_changes, 0);
	if (!prev)
		return;

	bit = 1 << BTRFS_PENDING_COMMIT;
	if (prev & bit)
		btrfs_debug(fs_info, "pending commit done");
	prev &= ~bit;

	if (prev)
		btrfs_warn(fs_info, "unknown pending changes left 0x%lx, ignoring", prev);
}
