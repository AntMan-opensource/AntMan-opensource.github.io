


















static void __jbd2_journal_temp_unlink_buffer(struct journal_head *jh);
static void __jbd2_journal_unfile_buffer(struct journal_head *jh);

static struct kmem_cache *transaction_cache;
int __init jbd2_journal_init_transaction_cache(void)
{
	J_ASSERT(!transaction_cache);
	transaction_cache = kmem_cache_create("jbd2_transaction_s", sizeof(transaction_t), 0, SLAB_HWCACHE_ALIGN|SLAB_TEMPORARY, NULL);



	if (!transaction_cache) {
		pr_emerg("JBD2: failed to create transaction cache\n");
		return -ENOMEM;
	}
	return 0;
}

void jbd2_journal_destroy_transaction_cache(void)
{
	kmem_cache_destroy(transaction_cache);
	transaction_cache = NULL;
}

void jbd2_journal_free_transaction(transaction_t *transaction)
{
	if (unlikely(ZERO_OR_NULL_PTR(transaction)))
		return;
	kmem_cache_free(transaction_cache, transaction);
}


static int jbd2_descriptor_blocks_per_trans(journal_t *journal)
{
	int tag_space = journal->j_blocksize - sizeof(journal_header_t);
	int tags_per_block;

	
	tag_space -= 16;
	if (jbd2_journal_has_csum_v2or3(journal))
		tag_space -= sizeof(struct jbd2_journal_block_tail);
	
	tags_per_block = (tag_space - 16) / journal_tag_bytes(journal);
	
	return 1 + DIV_ROUND_UP(journal->j_max_transaction_buffers, tags_per_block);
}



static void jbd2_get_transaction(journal_t *journal, transaction_t *transaction)
{
	transaction->t_journal = journal;
	transaction->t_state = T_RUNNING;
	transaction->t_start_time = ktime_get();
	transaction->t_tid = journal->j_transaction_sequence++;
	transaction->t_expires = jiffies + journal->j_commit_interval;
	spin_lock_init(&transaction->t_handle_lock);
	atomic_set(&transaction->t_updates, 0);
	atomic_set(&transaction->t_outstanding_credits, jbd2_descriptor_blocks_per_trans(journal) + atomic_read(&journal->j_reserved_credits));

	atomic_set(&transaction->t_outstanding_revokes, 0);
	atomic_set(&transaction->t_handle_count, 0);
	INIT_LIST_HEAD(&transaction->t_inode_list);
	INIT_LIST_HEAD(&transaction->t_private_list);

	
	journal->j_commit_timer.expires = round_jiffies_up(transaction->t_expires);
	add_timer(&journal->j_commit_timer);

	J_ASSERT(journal->j_running_transaction == NULL);
	journal->j_running_transaction = transaction;
	transaction->t_max_wait = 0;
	transaction->t_start = jiffies;
	transaction->t_requested = 0;
}




static inline void update_t_max_wait(transaction_t *transaction, unsigned long ts)
{

	if (jbd2_journal_enable_debug && time_after(transaction->t_start, ts)) {
		ts = jbd2_time_diff(ts, transaction->t_start);
		spin_lock(&transaction->t_handle_lock);
		if (ts > transaction->t_max_wait)
			transaction->t_max_wait = ts;
		spin_unlock(&transaction->t_handle_lock);
	}

}


static void wait_transaction_locked(journal_t *journal)
	__releases(journal->j_state_lock)
{
	DEFINE_WAIT(wait);
	int need_to_start;
	tid_t tid = journal->j_running_transaction->t_tid;

	prepare_to_wait(&journal->j_wait_transaction_locked, &wait, TASK_UNINTERRUPTIBLE);
	need_to_start = !tid_geq(journal->j_commit_request, tid);
	read_unlock(&journal->j_state_lock);
	if (need_to_start)
		jbd2_log_start_commit(journal, tid);
	jbd2_might_wait_for_commit(journal);
	schedule();
	finish_wait(&journal->j_wait_transaction_locked, &wait);
}


static void wait_transaction_switching(journal_t *journal)
	__releases(journal->j_state_lock)
{
	DEFINE_WAIT(wait);

	if (WARN_ON(!journal->j_running_transaction || journal->j_running_transaction->t_state != T_SWITCH)) {
		read_unlock(&journal->j_state_lock);
		return;
	}
	prepare_to_wait(&journal->j_wait_transaction_locked, &wait, TASK_UNINTERRUPTIBLE);
	read_unlock(&journal->j_state_lock);
	
	schedule();
	finish_wait(&journal->j_wait_transaction_locked, &wait);
}

static void sub_reserved_credits(journal_t *journal, int blocks)
{
	atomic_sub(blocks, &journal->j_reserved_credits);
	wake_up(&journal->j_wait_reserved);
}


static int add_transaction_credits(journal_t *journal, int blocks, int rsv_blocks)
__must_hold(&journal->j_state_lock)
{
	transaction_t *t = journal->j_running_transaction;
	int needed;
	int total = blocks + rsv_blocks;

	
	if (t->t_state != T_RUNNING) {
		WARN_ON_ONCE(t->t_state >= T_FLUSH);
		wait_transaction_locked(journal);
		__acquire(&journal->j_state_lock); 
		return 1;
	}

	
	needed = atomic_add_return(total, &t->t_outstanding_credits);
	if (needed > journal->j_max_transaction_buffers) {
		
		atomic_sub(total, &t->t_outstanding_credits);

		
		if (atomic_read(&journal->j_reserved_credits) + total > journal->j_max_transaction_buffers) {
			read_unlock(&journal->j_state_lock);
			jbd2_might_wait_for_commit(journal);
			wait_event(journal->j_wait_reserved, atomic_read(&journal->j_reserved_credits) + total <= journal->j_max_transaction_buffers);

			__acquire(&journal->j_state_lock); 
			return 1;
		}

		wait_transaction_locked(journal);
		__acquire(&journal->j_state_lock); 
		return 1;
	}

	
	if (jbd2_log_space_left(journal) < journal->j_max_transaction_buffers) {
		atomic_sub(total, &t->t_outstanding_credits);
		read_unlock(&journal->j_state_lock);
		jbd2_might_wait_for_commit(journal);
		write_lock(&journal->j_state_lock);
		if (jbd2_log_space_left(journal) < journal->j_max_transaction_buffers)
			__jbd2_log_wait_for_space(journal);
		write_unlock(&journal->j_state_lock);
		__acquire(&journal->j_state_lock); 
		return 1;
	}

	
	if (!rsv_blocks)
		return 0;

	needed = atomic_add_return(rsv_blocks, &journal->j_reserved_credits);
	
	if (needed > journal->j_max_transaction_buffers / 2) {
		sub_reserved_credits(journal, rsv_blocks);
		atomic_sub(total, &t->t_outstanding_credits);
		read_unlock(&journal->j_state_lock);
		jbd2_might_wait_for_commit(journal);
		wait_event(journal->j_wait_reserved, atomic_read(&journal->j_reserved_credits) + rsv_blocks <= journal->j_max_transaction_buffers / 2);

		__acquire(&journal->j_state_lock); 
		return 1;
	}
	return 0;
}



static int start_this_handle(journal_t *journal, handle_t *handle, gfp_t gfp_mask)
{
	transaction_t	*transaction, *new_transaction = NULL;
	int		blocks = handle->h_total_credits;
	int		rsv_blocks = 0;
	unsigned long ts = jiffies;

	if (handle->h_rsv_handle)
		rsv_blocks = handle->h_rsv_handle->h_total_credits;

	
	if ((rsv_blocks > journal->j_max_transaction_buffers / 2) || (rsv_blocks + blocks > journal->j_max_transaction_buffers)) {
		printk(KERN_ERR "JBD2: %s wants too many credits " "credits:%d rsv_credits:%d max:%d\n", current->comm, blocks, rsv_blocks, journal->j_max_transaction_buffers);


		WARN_ON(1);
		return -ENOSPC;
	}

alloc_transaction:
	
	if (!data_race(journal->j_running_transaction)) {
		
		if ((gfp_mask & __GFP_FS) == 0)
			gfp_mask |= __GFP_NOFAIL;
		new_transaction = kmem_cache_zalloc(transaction_cache, gfp_mask);
		if (!new_transaction)
			return -ENOMEM;
	}

	jbd_debug(3, "New handle %p going live.\n", handle);

	
repeat:
	read_lock(&journal->j_state_lock);
	BUG_ON(journal->j_flags & JBD2_UNMOUNT);
	if (is_journal_aborted(journal) || (journal->j_errno != 0 && !(journal->j_flags & JBD2_ACK_ERR))) {
		read_unlock(&journal->j_state_lock);
		jbd2_journal_free_transaction(new_transaction);
		return -EROFS;
	}

	
	if (!handle->h_reserved && journal->j_barrier_count) {
		read_unlock(&journal->j_state_lock);
		wait_event(journal->j_wait_transaction_locked, journal->j_barrier_count == 0);
		goto repeat;
	}

	if (!journal->j_running_transaction) {
		read_unlock(&journal->j_state_lock);
		if (!new_transaction)
			goto alloc_transaction;
		write_lock(&journal->j_state_lock);
		if (!journal->j_running_transaction && (handle->h_reserved || !journal->j_barrier_count)) {
			jbd2_get_transaction(journal, new_transaction);
			new_transaction = NULL;
		}
		write_unlock(&journal->j_state_lock);
		goto repeat;
	}

	transaction = journal->j_running_transaction;

	if (!handle->h_reserved) {
		
		if (add_transaction_credits(journal, blocks, rsv_blocks)) {
			
			__release(&journal->j_state_lock);
			goto repeat;
		}
	} else {
		
		if (transaction->t_state == T_SWITCH) {
			wait_transaction_switching(journal);
			goto repeat;
		}
		sub_reserved_credits(journal, blocks);
		handle->h_reserved = 0;
	}

	
	update_t_max_wait(transaction, ts);
	handle->h_transaction = transaction;
	handle->h_requested_credits = blocks;
	handle->h_revoke_credits_requested = handle->h_revoke_credits;
	handle->h_start_jiffies = jiffies;
	atomic_inc(&transaction->t_updates);
	atomic_inc(&transaction->t_handle_count);
	jbd_debug(4, "Handle %p given %d credits (total %d, free %lu)\n", handle, blocks, atomic_read(&transaction->t_outstanding_credits), jbd2_log_space_left(journal));


	read_unlock(&journal->j_state_lock);
	current->journal_info = handle;

	rwsem_acquire_read(&journal->j_trans_commit_map, 0, 0, _THIS_IP_);
	jbd2_journal_free_transaction(new_transaction);
	
	handle->saved_alloc_context = memalloc_nofs_save();
	return 0;
}


static handle_t *new_handle(int nblocks)
{
	handle_t *handle = jbd2_alloc_handle(GFP_NOFS);
	if (!handle)
		return NULL;
	handle->h_total_credits = nblocks;
	handle->h_ref = 1;

	return handle;
}

handle_t *jbd2__journal_start(journal_t *journal, int nblocks, int rsv_blocks, int revoke_records, gfp_t gfp_mask, unsigned int type, unsigned int line_no)

{
	handle_t *handle = journal_current_handle();
	int err;

	if (!journal)
		return ERR_PTR(-EROFS);

	if (handle) {
		J_ASSERT(handle->h_transaction->t_journal == journal);
		handle->h_ref++;
		return handle;
	}

	nblocks += DIV_ROUND_UP(revoke_records, journal->j_revoke_records_per_block);
	handle = new_handle(nblocks);
	if (!handle)
		return ERR_PTR(-ENOMEM);
	if (rsv_blocks) {
		handle_t *rsv_handle;

		rsv_handle = new_handle(rsv_blocks);
		if (!rsv_handle) {
			jbd2_free_handle(handle);
			return ERR_PTR(-ENOMEM);
		}
		rsv_handle->h_reserved = 1;
		rsv_handle->h_journal = journal;
		handle->h_rsv_handle = rsv_handle;
	}
	handle->h_revoke_credits = revoke_records;

	err = start_this_handle(journal, handle, gfp_mask);
	if (err < 0) {
		if (handle->h_rsv_handle)
			jbd2_free_handle(handle->h_rsv_handle);
		jbd2_free_handle(handle);
		return ERR_PTR(err);
	}
	handle->h_type = type;
	handle->h_line_no = line_no;
	trace_jbd2_handle_start(journal->j_fs_dev->bd_dev, handle->h_transaction->t_tid, type, line_no, nblocks);


	return handle;
}
EXPORT_SYMBOL(jbd2__journal_start);



handle_t *jbd2_journal_start(journal_t *journal, int nblocks)
{
	return jbd2__journal_start(journal, nblocks, 0, 0, GFP_NOFS, 0, 0);
}
EXPORT_SYMBOL(jbd2_journal_start);

static void __jbd2_journal_unreserve_handle(handle_t *handle, transaction_t *t)
{
	journal_t *journal = handle->h_journal;

	WARN_ON(!handle->h_reserved);
	sub_reserved_credits(journal, handle->h_total_credits);
	if (t)
		atomic_sub(handle->h_total_credits, &t->t_outstanding_credits);
}

void jbd2_journal_free_reserved(handle_t *handle)
{
	journal_t *journal = handle->h_journal;

	
	read_lock(&journal->j_state_lock);
	__jbd2_journal_unreserve_handle(handle, journal->j_running_transaction);
	read_unlock(&journal->j_state_lock);
	jbd2_free_handle(handle);
}
EXPORT_SYMBOL(jbd2_journal_free_reserved);


int jbd2_journal_start_reserved(handle_t *handle, unsigned int type, unsigned int line_no)
{
	journal_t *journal = handle->h_journal;
	int ret = -EIO;

	if (WARN_ON(!handle->h_reserved)) {
		
		jbd2_journal_stop(handle);
		return ret;
	}
	
	if (WARN_ON(current->journal_info)) {
		jbd2_journal_free_reserved(handle);
		return ret;
	}

	handle->h_journal = NULL;
	
	ret = start_this_handle(journal, handle, GFP_NOFS);
	if (ret < 0) {
		handle->h_journal = journal;
		jbd2_journal_free_reserved(handle);
		return ret;
	}
	handle->h_type = type;
	handle->h_line_no = line_no;
	trace_jbd2_handle_start(journal->j_fs_dev->bd_dev, handle->h_transaction->t_tid, type, line_no, handle->h_total_credits);

	return 0;
}
EXPORT_SYMBOL(jbd2_journal_start_reserved);


int jbd2_journal_extend(handle_t *handle, int nblocks, int revoke_records)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	int result;
	int wanted;

	if (is_handle_aborted(handle))
		return -EROFS;
	journal = transaction->t_journal;

	result = 1;

	read_lock(&journal->j_state_lock);

	
	if (transaction->t_state != T_RUNNING) {
		jbd_debug(3, "denied handle %p %d blocks: " "transaction not running\n", handle, nblocks);
		goto error_out;
	}

	nblocks += DIV_ROUND_UP( handle->h_revoke_credits_requested + revoke_records, journal->j_revoke_records_per_block) - DIV_ROUND_UP( handle->h_revoke_credits_requested, journal->j_revoke_records_per_block);




	spin_lock(&transaction->t_handle_lock);
	wanted = atomic_add_return(nblocks, &transaction->t_outstanding_credits);

	if (wanted > journal->j_max_transaction_buffers) {
		jbd_debug(3, "denied handle %p %d blocks: " "transaction too large\n", handle, nblocks);
		atomic_sub(nblocks, &transaction->t_outstanding_credits);
		goto unlock;
	}

	trace_jbd2_handle_extend(journal->j_fs_dev->bd_dev, transaction->t_tid, handle->h_type, handle->h_line_no, handle->h_total_credits, nblocks);




	handle->h_total_credits += nblocks;
	handle->h_requested_credits += nblocks;
	handle->h_revoke_credits += revoke_records;
	handle->h_revoke_credits_requested += revoke_records;
	result = 0;

	jbd_debug(3, "extended handle %p by %d\n", handle, nblocks);
unlock:
	spin_unlock(&transaction->t_handle_lock);
error_out:
	read_unlock(&journal->j_state_lock);
	return result;
}

static void stop_this_handle(handle_t *handle)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal = transaction->t_journal;
	int revokes;

	J_ASSERT(journal_current_handle() == handle);
	J_ASSERT(atomic_read(&transaction->t_updates) > 0);
	current->journal_info = NULL;
	
	revokes = handle->h_revoke_credits_requested - handle->h_revoke_credits;
	if (revokes) {
		int t_revokes, revoke_descriptors;
		int rr_per_blk = journal->j_revoke_records_per_block;

		WARN_ON_ONCE(DIV_ROUND_UP(revokes, rr_per_blk)
				> handle->h_total_credits);
		t_revokes = atomic_add_return(revokes, &transaction->t_outstanding_revokes);
		revoke_descriptors = DIV_ROUND_UP(t_revokes, rr_per_blk) - DIV_ROUND_UP(t_revokes - revokes, rr_per_blk);

		handle->h_total_credits -= revoke_descriptors;
	}
	atomic_sub(handle->h_total_credits, &transaction->t_outstanding_credits);
	if (handle->h_rsv_handle)
		__jbd2_journal_unreserve_handle(handle->h_rsv_handle, transaction);
	if (atomic_dec_and_test(&transaction->t_updates))
		wake_up(&journal->j_wait_updates);

	rwsem_release(&journal->j_trans_commit_map, _THIS_IP_);
	
	memalloc_nofs_restore(handle->saved_alloc_context);
}


int jbd2__journal_restart(handle_t *handle, int nblocks, int revoke_records, gfp_t gfp_mask)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	tid_t		tid;
	int		need_to_start;
	int		ret;

	
	if (is_handle_aborted(handle))
		return 0;
	journal = transaction->t_journal;
	tid = transaction->t_tid;

	
	jbd_debug(2, "restarting handle %p\n", handle);
	stop_this_handle(handle);
	handle->h_transaction = NULL;

	
	read_lock(&journal->j_state_lock);
	need_to_start = !tid_geq(journal->j_commit_request, tid);
	read_unlock(&journal->j_state_lock);
	if (need_to_start)
		jbd2_log_start_commit(journal, tid);
	handle->h_total_credits = nblocks + DIV_ROUND_UP(revoke_records, journal->j_revoke_records_per_block);

	handle->h_revoke_credits = revoke_records;
	ret = start_this_handle(journal, handle, gfp_mask);
	trace_jbd2_handle_restart(journal->j_fs_dev->bd_dev, ret ? 0 : handle->h_transaction->t_tid, handle->h_type, handle->h_line_no, handle->h_total_credits);


	return ret;
}
EXPORT_SYMBOL(jbd2__journal_restart);


int jbd2_journal_restart(handle_t *handle, int nblocks)
{
	return jbd2__journal_restart(handle, nblocks, 0, GFP_NOFS);
}
EXPORT_SYMBOL(jbd2_journal_restart);


void jbd2_journal_wait_updates(journal_t *journal)
{
	transaction_t *commit_transaction = journal->j_running_transaction;

	if (!commit_transaction)
		return;

	spin_lock(&commit_transaction->t_handle_lock);
	while (atomic_read(&commit_transaction->t_updates)) {
		DEFINE_WAIT(wait);

		prepare_to_wait(&journal->j_wait_updates, &wait, TASK_UNINTERRUPTIBLE);
		if (atomic_read(&commit_transaction->t_updates)) {
			spin_unlock(&commit_transaction->t_handle_lock);
			write_unlock(&journal->j_state_lock);
			schedule();
			write_lock(&journal->j_state_lock);
			spin_lock(&commit_transaction->t_handle_lock);
		}
		finish_wait(&journal->j_wait_updates, &wait);
	}
	spin_unlock(&commit_transaction->t_handle_lock);
}


void jbd2_journal_lock_updates(journal_t *journal)
{
	DEFINE_WAIT(wait);

	jbd2_might_wait_for_commit(journal);

	write_lock(&journal->j_state_lock);
	++journal->j_barrier_count;

	
	if (atomic_read(&journal->j_reserved_credits)) {
		write_unlock(&journal->j_state_lock);
		wait_event(journal->j_wait_reserved, atomic_read(&journal->j_reserved_credits) == 0);
		write_lock(&journal->j_state_lock);
	}

	
	jbd2_journal_wait_updates(journal);

	write_unlock(&journal->j_state_lock);

	
	mutex_lock(&journal->j_barrier);
}


void jbd2_journal_unlock_updates (journal_t *journal)
{
	J_ASSERT(journal->j_barrier_count != 0);

	mutex_unlock(&journal->j_barrier);
	write_lock(&journal->j_state_lock);
	--journal->j_barrier_count;
	write_unlock(&journal->j_state_lock);
	wake_up(&journal->j_wait_transaction_locked);
}

static void warn_dirty_buffer(struct buffer_head *bh)
{
	printk(KERN_WARNING "JBD2: Spotted dirty metadata buffer (dev = %pg, blocknr = %llu). " "There's a risk of filesystem corruption in case of system " "crash.\n", bh->b_bdev, (unsigned long long)bh->b_blocknr);



}


static void jbd2_freeze_jh_data(struct journal_head *jh)
{
	struct page *page;
	int offset;
	char *source;
	struct buffer_head *bh = jh2bh(jh);

	J_EXPECT_JH(jh, buffer_uptodate(bh), "Possible IO failure.\n");
	page = bh->b_page;
	offset = offset_in_page(bh->b_data);
	source = kmap_atomic(page);
	
	jbd2_buffer_frozen_trigger(jh, source + offset, jh->b_triggers);
	memcpy(jh->b_frozen_data, source + offset, bh->b_size);
	kunmap_atomic(source);

	
	jh->b_frozen_triggers = jh->b_triggers;
}


static int do_get_write_access(handle_t *handle, struct journal_head *jh, int force_copy)

{
	struct buffer_head *bh;
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	int error;
	char *frozen_buffer = NULL;
	unsigned long start_lock, time_lock;

	journal = transaction->t_journal;

	jbd_debug(5, "journal_head %p, force_copy %d\n", jh, force_copy);

	JBUFFER_TRACE(jh, "entry");
repeat:
	bh = jh2bh(jh);

	

 	start_lock = jiffies;
	lock_buffer(bh);
	spin_lock(&jh->b_state_lock);

	
	time_lock = jbd2_time_diff(start_lock, jiffies);
	if (time_lock > HZ/10)
		trace_jbd2_lock_buffer_stall(bh->b_bdev->bd_dev, jiffies_to_msecs(time_lock));

	

	if (buffer_dirty(bh)) {
		
		if (jh->b_transaction) {
			J_ASSERT_JH(jh, jh->b_transaction == transaction || jh->b_transaction == journal->j_committing_transaction);


			if (jh->b_next_transaction)
				J_ASSERT_JH(jh, jh->b_next_transaction == transaction);
			warn_dirty_buffer(bh);
		}
		
		JBUFFER_TRACE(jh, "Journalling dirty buffer");
		clear_buffer_dirty(bh);
		set_buffer_jbddirty(bh);
	}

	unlock_buffer(bh);

	error = -EROFS;
	if (is_handle_aborted(handle)) {
		spin_unlock(&jh->b_state_lock);
		goto out;
	}
	error = 0;

	
	if (jh->b_transaction == transaction || jh->b_next_transaction == transaction)
		goto done;

	
	jh->b_modified = 0;

	
	if (!jh->b_transaction) {
		JBUFFER_TRACE(jh, "no transaction");
		J_ASSERT_JH(jh, !jh->b_next_transaction);
		JBUFFER_TRACE(jh, "file as BJ_Reserved");
		
		smp_wmb();
		spin_lock(&journal->j_list_lock);
		__jbd2_journal_file_buffer(jh, transaction, BJ_Reserved);
		spin_unlock(&journal->j_list_lock);
		goto done;
	}
	
	if (jh->b_frozen_data) {
		JBUFFER_TRACE(jh, "has frozen data");
		J_ASSERT_JH(jh, jh->b_next_transaction == NULL);
		goto attach_next;
	}

	JBUFFER_TRACE(jh, "owned by older transaction");
	J_ASSERT_JH(jh, jh->b_next_transaction == NULL);
	J_ASSERT_JH(jh, jh->b_transaction == journal->j_committing_transaction);

	
	if (buffer_shadow(bh)) {
		JBUFFER_TRACE(jh, "on shadow: sleep");
		spin_unlock(&jh->b_state_lock);
		wait_on_bit_io(&bh->b_state, BH_Shadow, TASK_UNINTERRUPTIBLE);
		goto repeat;
	}

	
	if (jh->b_jlist == BJ_Metadata || force_copy) {
		JBUFFER_TRACE(jh, "generate frozen data");
		if (!frozen_buffer) {
			JBUFFER_TRACE(jh, "allocate memory for buffer");
			spin_unlock(&jh->b_state_lock);
			frozen_buffer = jbd2_alloc(jh2bh(jh)->b_size, GFP_NOFS | __GFP_NOFAIL);
			goto repeat;
		}
		jh->b_frozen_data = frozen_buffer;
		frozen_buffer = NULL;
		jbd2_freeze_jh_data(jh);
	}
attach_next:
	
	smp_wmb();
	jh->b_next_transaction = transaction;

done:
	spin_unlock(&jh->b_state_lock);

	
	jbd2_journal_cancel_revoke(handle, jh);

out:
	if (unlikely(frozen_buffer))	
		jbd2_free(frozen_buffer, bh->b_size);

	JBUFFER_TRACE(jh, "exit");
	return error;
}


static bool jbd2_write_access_granted(handle_t *handle, struct buffer_head *bh, bool undo)
{
	struct journal_head *jh;
	bool ret = false;

	
	if (buffer_dirty(bh))
		return false;

	
	rcu_read_lock();
	if (!buffer_jbd(bh))
		goto out;
	
	jh = READ_ONCE(bh->b_private);
	if (!jh)
		goto out;
	
	if (undo && !jh->b_committed_data)
		goto out;
	if (READ_ONCE(jh->b_transaction) != handle->h_transaction && READ_ONCE(jh->b_next_transaction) != handle->h_transaction)
		goto out;
	
	smp_mb();
	if (unlikely(jh->b_bh != bh))
		goto out;
	ret = true;
out:
	rcu_read_unlock();
	return ret;
}



int jbd2_journal_get_write_access(handle_t *handle, struct buffer_head *bh)
{
	struct journal_head *jh;
	int rc;

	if (is_handle_aborted(handle))
		return -EROFS;

	if (jbd2_write_access_granted(handle, bh, false))
		return 0;

	jh = jbd2_journal_add_journal_head(bh);
	
	rc = do_get_write_access(handle, jh, 0);
	jbd2_journal_put_journal_head(jh);
	return rc;
}





int jbd2_journal_get_create_access(handle_t *handle, struct buffer_head *bh)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	struct journal_head *jh = jbd2_journal_add_journal_head(bh);
	int err;

	jbd_debug(5, "journal_head %p\n", jh);
	err = -EROFS;
	if (is_handle_aborted(handle))
		goto out;
	journal = transaction->t_journal;
	err = 0;

	JBUFFER_TRACE(jh, "entry");
	
	spin_lock(&jh->b_state_lock);
	J_ASSERT_JH(jh, (jh->b_transaction == transaction || jh->b_transaction == NULL || (jh->b_transaction == journal->j_committing_transaction && jh->b_jlist == BJ_Forget)));



	J_ASSERT_JH(jh, jh->b_next_transaction == NULL);
	J_ASSERT_JH(jh, buffer_locked(jh2bh(jh)));

	if (jh->b_transaction == NULL) {
		
		clear_buffer_dirty(jh2bh(jh));
		
		jh->b_modified = 0;

		JBUFFER_TRACE(jh, "file as BJ_Reserved");
		spin_lock(&journal->j_list_lock);
		__jbd2_journal_file_buffer(jh, transaction, BJ_Reserved);
		spin_unlock(&journal->j_list_lock);
	} else if (jh->b_transaction == journal->j_committing_transaction) {
		
		jh->b_modified = 0;

		JBUFFER_TRACE(jh, "set next transaction");
		spin_lock(&journal->j_list_lock);
		jh->b_next_transaction = transaction;
		spin_unlock(&journal->j_list_lock);
	}
	spin_unlock(&jh->b_state_lock);

	
	JBUFFER_TRACE(jh, "cancelling revoke");
	jbd2_journal_cancel_revoke(handle, jh);
out:
	jbd2_journal_put_journal_head(jh);
	return err;
}


int jbd2_journal_get_undo_access(handle_t *handle, struct buffer_head *bh)
{
	int err;
	struct journal_head *jh;
	char *committed_data = NULL;

	if (is_handle_aborted(handle))
		return -EROFS;

	if (jbd2_write_access_granted(handle, bh, true))
		return 0;

	jh = jbd2_journal_add_journal_head(bh);
	JBUFFER_TRACE(jh, "entry");

	
	err = do_get_write_access(handle, jh, 1);
	if (err)
		goto out;

repeat:
	if (!jh->b_committed_data)
		committed_data = jbd2_alloc(jh2bh(jh)->b_size, GFP_NOFS|__GFP_NOFAIL);

	spin_lock(&jh->b_state_lock);
	if (!jh->b_committed_data) {
		
		JBUFFER_TRACE(jh, "generate b_committed data");
		if (!committed_data) {
			spin_unlock(&jh->b_state_lock);
			goto repeat;
		}

		jh->b_committed_data = committed_data;
		committed_data = NULL;
		memcpy(jh->b_committed_data, bh->b_data, bh->b_size);
	}
	spin_unlock(&jh->b_state_lock);
out:
	jbd2_journal_put_journal_head(jh);
	if (unlikely(committed_data))
		jbd2_free(committed_data, bh->b_size);
	return err;
}


void jbd2_journal_set_triggers(struct buffer_head *bh, struct jbd2_buffer_trigger_type *type)
{
	struct journal_head *jh = jbd2_journal_grab_journal_head(bh);

	if (WARN_ON_ONCE(!jh))
		return;
	jh->b_triggers = type;
	jbd2_journal_put_journal_head(jh);
}

void jbd2_buffer_frozen_trigger(struct journal_head *jh, void *mapped_data, struct jbd2_buffer_trigger_type *triggers)
{
	struct buffer_head *bh = jh2bh(jh);

	if (!triggers || !triggers->t_frozen)
		return;

	triggers->t_frozen(triggers, bh, mapped_data, bh->b_size);
}

void jbd2_buffer_abort_trigger(struct journal_head *jh, struct jbd2_buffer_trigger_type *triggers)
{
	if (!triggers || !triggers->t_abort)
		return;

	triggers->t_abort(triggers, jh2bh(jh));
}


int jbd2_journal_dirty_metadata(handle_t *handle, struct buffer_head *bh)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	struct journal_head *jh;
	int ret = 0;

	if (is_handle_aborted(handle))
		return -EROFS;
	if (!buffer_jbd(bh))
		return -EUCLEAN;

	
	jh = bh2jh(bh);
	jbd_debug(5, "journal_head %p\n", jh);
	JBUFFER_TRACE(jh, "entry");

	
	if (data_race(jh->b_transaction != transaction && jh->b_next_transaction != transaction)) {
		spin_lock(&jh->b_state_lock);
		J_ASSERT_JH(jh, jh->b_transaction == transaction || jh->b_next_transaction == transaction);
		spin_unlock(&jh->b_state_lock);
	}
	if (jh->b_modified == 1) {
		
		if (data_race(jh->b_transaction == transaction && jh->b_jlist != BJ_Metadata)) {
			spin_lock(&jh->b_state_lock);
			if (jh->b_transaction == transaction && jh->b_jlist != BJ_Metadata)
				pr_err("JBD2: assertion failure: h_type=%u " "h_line_no=%u block_no=%llu jlist=%u\n", handle->h_type, handle->h_line_no, (unsigned long long) bh->b_blocknr, jh->b_jlist);



			J_ASSERT_JH(jh, jh->b_transaction != transaction || jh->b_jlist == BJ_Metadata);
			spin_unlock(&jh->b_state_lock);
		}
		goto out;
	}

	journal = transaction->t_journal;
	spin_lock(&jh->b_state_lock);

	if (jh->b_modified == 0) {
		
		if (WARN_ON_ONCE(jbd2_handle_buffer_credits(handle) <= 0)) {
			ret = -ENOSPC;
			goto out_unlock_bh;
		}
		jh->b_modified = 1;
		handle->h_total_credits--;
	}

	
	if (jh->b_transaction == transaction && jh->b_jlist == BJ_Metadata) {
		JBUFFER_TRACE(jh, "fastpath");
		if (unlikely(jh->b_transaction != journal->j_running_transaction)) {
			printk(KERN_ERR "JBD2: %s: " "jh->b_transaction (%llu, %p, %u) != " "journal->j_running_transaction (%p, %u)\n", journal->j_devname, (unsigned long long) bh->b_blocknr, jh->b_transaction, jh->b_transaction ? jh->b_transaction->t_tid : 0, journal->j_running_transaction, journal->j_running_transaction ? journal->j_running_transaction->t_tid : 0);








			ret = -EINVAL;
		}
		goto out_unlock_bh;
	}

	set_buffer_jbddirty(bh);

	
	if (jh->b_transaction != transaction) {
		JBUFFER_TRACE(jh, "already on other transaction");
		if (unlikely(((jh->b_transaction != journal->j_committing_transaction)) || (jh->b_next_transaction != transaction))) {

			printk(KERN_ERR "jbd2_journal_dirty_metadata: %s: " "bad jh for block %llu: " "transaction (%p, %u), " "jh->b_transaction (%p, %u), " "jh->b_next_transaction (%p, %u), jlist %u\n", journal->j_devname, (unsigned long long) bh->b_blocknr, transaction, transaction->t_tid, jh->b_transaction, jh->b_transaction ? jh->b_transaction->t_tid : 0, jh->b_next_transaction, jh->b_next_transaction ? jh->b_next_transaction->t_tid : 0, jh->b_jlist);













			WARN_ON(1);
			ret = -EINVAL;
		}
		
		goto out_unlock_bh;
	}

	
	J_ASSERT_JH(jh, jh->b_frozen_data == NULL);

	JBUFFER_TRACE(jh, "file as BJ_Metadata");
	spin_lock(&journal->j_list_lock);
	__jbd2_journal_file_buffer(jh, transaction, BJ_Metadata);
	spin_unlock(&journal->j_list_lock);
out_unlock_bh:
	spin_unlock(&jh->b_state_lock);
out:
	JBUFFER_TRACE(jh, "exit");
	return ret;
}


int jbd2_journal_forget(handle_t *handle, struct buffer_head *bh)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	struct journal_head *jh;
	int drop_reserve = 0;
	int err = 0;
	int was_modified = 0;

	if (is_handle_aborted(handle))
		return -EROFS;
	journal = transaction->t_journal;

	BUFFER_TRACE(bh, "entry");

	jh = jbd2_journal_grab_journal_head(bh);
	if (!jh) {
		__bforget(bh);
		return 0;
	}

	spin_lock(&jh->b_state_lock);

	
	if (!J_EXPECT_JH(jh, !jh->b_committed_data, "inconsistent data on disk")) {
		err = -EIO;
		goto drop;
	}

	
	was_modified = jh->b_modified;

	
	jh->b_modified = 0;

	if (jh->b_transaction == transaction) {
		J_ASSERT_JH(jh, !jh->b_frozen_data);

		
		clear_buffer_dirty(bh);
		clear_buffer_jbddirty(bh);

		JBUFFER_TRACE(jh, "belongs to current transaction: unfile");

		
		if (was_modified)
			drop_reserve = 1;

		

		spin_lock(&journal->j_list_lock);
		if (jh->b_cp_transaction) {
			__jbd2_journal_temp_unlink_buffer(jh);
			__jbd2_journal_file_buffer(jh, transaction, BJ_Forget);
		} else {
			__jbd2_journal_unfile_buffer(jh);
			jbd2_journal_put_journal_head(jh);
		}
		spin_unlock(&journal->j_list_lock);
	} else if (jh->b_transaction) {
		J_ASSERT_JH(jh, (jh->b_transaction == journal->j_committing_transaction));
		
		JBUFFER_TRACE(jh, "belongs to older transaction");
		

		set_buffer_freed(bh);

		if (!jh->b_next_transaction) {
			spin_lock(&journal->j_list_lock);
			jh->b_next_transaction = transaction;
			spin_unlock(&journal->j_list_lock);
		} else {
			J_ASSERT(jh->b_next_transaction == transaction);

			
			if (was_modified)
				drop_reserve = 1;
		}
	} else {
		
		spin_lock(&journal->j_list_lock);
		if (!jh->b_cp_transaction) {
			JBUFFER_TRACE(jh, "belongs to none transaction");
			spin_unlock(&journal->j_list_lock);
			goto drop;
		}

		
		if (!buffer_dirty(bh)) {
			__jbd2_journal_remove_checkpoint(jh);
			spin_unlock(&journal->j_list_lock);
			goto drop;
		}

		
		clear_buffer_dirty(bh);
		__jbd2_journal_file_buffer(jh, transaction, BJ_Forget);
		spin_unlock(&journal->j_list_lock);
	}
drop:
	__brelse(bh);
	spin_unlock(&jh->b_state_lock);
	jbd2_journal_put_journal_head(jh);
	if (drop_reserve) {
		
		handle->h_total_credits++;
	}
	return err;
}


int jbd2_journal_stop(handle_t *handle)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	int err = 0, wait_for_commit = 0;
	tid_t tid;
	pid_t pid;

	if (--handle->h_ref > 0) {
		jbd_debug(4, "h_ref %d -> %d\n", handle->h_ref + 1, handle->h_ref);
		if (is_handle_aborted(handle))
			return -EIO;
		return 0;
	}
	if (!transaction) {
		
		memalloc_nofs_restore(handle->saved_alloc_context);
		goto free_and_exit;
	}
	journal = transaction->t_journal;
	tid = transaction->t_tid;

	if (is_handle_aborted(handle))
		err = -EIO;

	jbd_debug(4, "Handle %p going down\n", handle);
	trace_jbd2_handle_stats(journal->j_fs_dev->bd_dev, tid, handle->h_type, handle->h_line_no, jiffies - handle->h_start_jiffies, handle->h_sync, handle->h_requested_credits, (handle->h_requested_credits - handle->h_total_credits));





	
	pid = current->pid;
	if (handle->h_sync && journal->j_last_sync_writer != pid && journal->j_max_batch_time) {
		u64 commit_time, trans_time;

		journal->j_last_sync_writer = pid;

		read_lock(&journal->j_state_lock);
		commit_time = journal->j_average_commit_time;
		read_unlock(&journal->j_state_lock);

		trans_time = ktime_to_ns(ktime_sub(ktime_get(), transaction->t_start_time));

		commit_time = max_t(u64, commit_time, 1000*journal->j_min_batch_time);
		commit_time = min_t(u64, commit_time, 1000*journal->j_max_batch_time);

		if (trans_time < commit_time) {
			ktime_t expires = ktime_add_ns(ktime_get(), commit_time);
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_hrtimeout(&expires, HRTIMER_MODE_ABS);
		}
	}

	if (handle->h_sync)
		transaction->t_synchronous_commit = 1;

	
	if (handle->h_sync || time_after_eq(jiffies, transaction->t_expires)) {
		

		jbd_debug(2, "transaction too old, requesting commit for " "handle %p\n", handle);
		
		jbd2_log_start_commit(journal, tid);

		
		if (handle->h_sync && !(current->flags & PF_MEMALLOC))
			wait_for_commit = 1;
	}

	
	stop_this_handle(handle);

	if (wait_for_commit)
		err = jbd2_log_wait_commit(journal, tid);

free_and_exit:
	if (handle->h_rsv_handle)
		jbd2_free_handle(handle->h_rsv_handle);
	jbd2_free_handle(handle);
	return err;
}





static inline void __blist_add_buffer(struct journal_head **list, struct journal_head *jh)
{
	if (!*list) {
		jh->b_tnext = jh->b_tprev = jh;
		*list = jh;
	} else {
		
		struct journal_head *first = *list, *last = first->b_tprev;
		jh->b_tprev = last;
		jh->b_tnext = first;
		last->b_tnext = first->b_tprev = jh;
	}
}



static inline void __blist_del_buffer(struct journal_head **list, struct journal_head *jh)
{
	if (*list == jh) {
		*list = jh->b_tnext;
		if (*list == jh)
			*list = NULL;
	}
	jh->b_tprev->b_tnext = jh->b_tnext;
	jh->b_tnext->b_tprev = jh->b_tprev;
}


static void __jbd2_journal_temp_unlink_buffer(struct journal_head *jh)
{
	struct journal_head **list = NULL;
	transaction_t *transaction;
	struct buffer_head *bh = jh2bh(jh);

	lockdep_assert_held(&jh->b_state_lock);
	transaction = jh->b_transaction;
	if (transaction)
		assert_spin_locked(&transaction->t_journal->j_list_lock);

	J_ASSERT_JH(jh, jh->b_jlist < BJ_Types);
	if (jh->b_jlist != BJ_None)
		J_ASSERT_JH(jh, transaction != NULL);

	switch (jh->b_jlist) {
	case BJ_None:
		return;
	case BJ_Metadata:
		transaction->t_nr_buffers--;
		J_ASSERT_JH(jh, transaction->t_nr_buffers >= 0);
		list = &transaction->t_buffers;
		break;
	case BJ_Forget:
		list = &transaction->t_forget;
		break;
	case BJ_Shadow:
		list = &transaction->t_shadow_list;
		break;
	case BJ_Reserved:
		list = &transaction->t_reserved_list;
		break;
	}

	__blist_del_buffer(list, jh);
	jh->b_jlist = BJ_None;
	if (transaction && is_journal_aborted(transaction->t_journal))
		clear_buffer_jbddirty(bh);
	else if (test_clear_buffer_jbddirty(bh))
		mark_buffer_dirty(bh);	
}


static void __jbd2_journal_unfile_buffer(struct journal_head *jh)
{
	J_ASSERT_JH(jh, jh->b_transaction != NULL);
	J_ASSERT_JH(jh, jh->b_next_transaction == NULL);

	__jbd2_journal_temp_unlink_buffer(jh);
	jh->b_transaction = NULL;
}

void jbd2_journal_unfile_buffer(journal_t *journal, struct journal_head *jh)
{
	struct buffer_head *bh = jh2bh(jh);

	
	get_bh(bh);
	spin_lock(&jh->b_state_lock);
	spin_lock(&journal->j_list_lock);
	__jbd2_journal_unfile_buffer(jh);
	spin_unlock(&journal->j_list_lock);
	spin_unlock(&jh->b_state_lock);
	jbd2_journal_put_journal_head(jh);
	__brelse(bh);
}


static void __journal_try_to_free_buffer(journal_t *journal, struct buffer_head *bh)
{
	struct journal_head *jh;

	jh = bh2jh(bh);

	if (buffer_locked(bh) || buffer_dirty(bh))
		goto out;

	if (jh->b_next_transaction != NULL || jh->b_transaction != NULL)
		goto out;

	spin_lock(&journal->j_list_lock);
	if (jh->b_cp_transaction != NULL) {
		
		JBUFFER_TRACE(jh, "remove from checkpoint list");
		__jbd2_journal_remove_checkpoint(jh);
	}
	spin_unlock(&journal->j_list_lock);
out:
	return;
}


int jbd2_journal_try_to_free_buffers(journal_t *journal, struct page *page)
{
	struct buffer_head *head;
	struct buffer_head *bh;
	int ret = 0;

	J_ASSERT(PageLocked(page));

	head = page_buffers(page);
	bh = head;
	do {
		struct journal_head *jh;

		
		jh = jbd2_journal_grab_journal_head(bh);
		if (!jh)
			continue;

		spin_lock(&jh->b_state_lock);
		__journal_try_to_free_buffer(journal, bh);
		spin_unlock(&jh->b_state_lock);
		jbd2_journal_put_journal_head(jh);
		if (buffer_jbd(bh))
			goto busy;
	} while ((bh = bh->b_this_page) != head);

	ret = try_to_free_buffers(page);
busy:
	return ret;
}


static int __dispose_buffer(struct journal_head *jh, transaction_t *transaction)
{
	int may_free = 1;
	struct buffer_head *bh = jh2bh(jh);

	if (jh->b_cp_transaction) {
		JBUFFER_TRACE(jh, "on running+cp transaction");
		__jbd2_journal_temp_unlink_buffer(jh);
		
		clear_buffer_dirty(bh);
		__jbd2_journal_file_buffer(jh, transaction, BJ_Forget);
		may_free = 0;
	} else {
		JBUFFER_TRACE(jh, "on running transaction");
		__jbd2_journal_unfile_buffer(jh);
		jbd2_journal_put_journal_head(jh);
	}
	return may_free;
}




static int journal_unmap_buffer(journal_t *journal, struct buffer_head *bh, int partial_page)
{
	transaction_t *transaction;
	struct journal_head *jh;
	int may_free = 1;

	BUFFER_TRACE(bh, "entry");

	

	jh = jbd2_journal_grab_journal_head(bh);
	if (!jh)
		goto zap_buffer_unlocked;

	
	write_lock(&journal->j_state_lock);
	spin_lock(&jh->b_state_lock);
	spin_lock(&journal->j_list_lock);

	
	transaction = jh->b_transaction;
	if (transaction == NULL) {
		
		if (!jh->b_cp_transaction) {
			JBUFFER_TRACE(jh, "not on any transaction: zap");
			goto zap_buffer;
		}

		if (!buffer_dirty(bh)) {
			
			__jbd2_journal_remove_checkpoint(jh);
			goto zap_buffer;
		}

		

		if (journal->j_running_transaction) {
			
			JBUFFER_TRACE(jh, "checkpointed: add to BJ_Forget");
			may_free = __dispose_buffer(jh, journal->j_running_transaction);
			goto zap_buffer;
		} else {
			
			if (journal->j_committing_transaction) {
				JBUFFER_TRACE(jh, "give to committing trans");
				may_free = __dispose_buffer(jh, journal->j_committing_transaction);
				goto zap_buffer;
			} else {
				
				clear_buffer_jbddirty(bh);
				__jbd2_journal_remove_checkpoint(jh);
				goto zap_buffer;
			}
		}
	} else if (transaction == journal->j_committing_transaction) {
		JBUFFER_TRACE(jh, "on committing transaction");
		
		if (partial_page) {
			spin_unlock(&journal->j_list_lock);
			spin_unlock(&jh->b_state_lock);
			write_unlock(&journal->j_state_lock);
			jbd2_journal_put_journal_head(jh);
			return -EBUSY;
		}
		
		set_buffer_freed(bh);
		if (journal->j_running_transaction && buffer_jbddirty(bh))
			jh->b_next_transaction = journal->j_running_transaction;
		jh->b_modified = 0;
		spin_unlock(&journal->j_list_lock);
		spin_unlock(&jh->b_state_lock);
		write_unlock(&journal->j_state_lock);
		jbd2_journal_put_journal_head(jh);
		return 0;
	} else {
		
		J_ASSERT_JH(jh, transaction == journal->j_running_transaction);
		JBUFFER_TRACE(jh, "on running transaction");
		may_free = __dispose_buffer(jh, transaction);
	}

zap_buffer:
	
	jh->b_modified = 0;
	spin_unlock(&journal->j_list_lock);
	spin_unlock(&jh->b_state_lock);
	write_unlock(&journal->j_state_lock);
	jbd2_journal_put_journal_head(jh);
zap_buffer_unlocked:
	clear_buffer_dirty(bh);
	J_ASSERT_BH(bh, !buffer_jbddirty(bh));
	clear_buffer_mapped(bh);
	clear_buffer_req(bh);
	clear_buffer_new(bh);
	clear_buffer_delay(bh);
	clear_buffer_unwritten(bh);
	bh->b_bdev = NULL;
	return may_free;
}


int jbd2_journal_invalidatepage(journal_t *journal, struct page *page, unsigned int offset, unsigned int length)


{
	struct buffer_head *head, *bh, *next;
	unsigned int stop = offset + length;
	unsigned int curr_off = 0;
	int partial_page = (offset || length < PAGE_SIZE);
	int may_free = 1;
	int ret = 0;

	if (!PageLocked(page))
		BUG();
	if (!page_has_buffers(page))
		return 0;

	BUG_ON(stop > PAGE_SIZE || stop < length);

	

	head = bh = page_buffers(page);
	do {
		unsigned int next_off = curr_off + bh->b_size;
		next = bh->b_this_page;

		if (next_off > stop)
			return 0;

		if (offset <= curr_off) {
			
			lock_buffer(bh);
			ret = journal_unmap_buffer(journal, bh, partial_page);
			unlock_buffer(bh);
			if (ret < 0)
				return ret;
			may_free &= ret;
		}
		curr_off = next_off;
		bh = next;

	} while (bh != head);

	if (!partial_page) {
		if (may_free && try_to_free_buffers(page))
			J_ASSERT(!page_has_buffers(page));
	}
	return 0;
}


void __jbd2_journal_file_buffer(struct journal_head *jh, transaction_t *transaction, int jlist)
{
	struct journal_head **list = NULL;
	int was_dirty = 0;
	struct buffer_head *bh = jh2bh(jh);

	lockdep_assert_held(&jh->b_state_lock);
	assert_spin_locked(&transaction->t_journal->j_list_lock);

	J_ASSERT_JH(jh, jh->b_jlist < BJ_Types);
	J_ASSERT_JH(jh, jh->b_transaction == transaction || jh->b_transaction == NULL);

	if (jh->b_transaction && jh->b_jlist == jlist)
		return;

	if (jlist == BJ_Metadata || jlist == BJ_Reserved || jlist == BJ_Shadow || jlist == BJ_Forget) {
		
		if (buffer_dirty(bh))
			warn_dirty_buffer(bh);
		if (test_clear_buffer_dirty(bh) || test_clear_buffer_jbddirty(bh))
			was_dirty = 1;
	}

	if (jh->b_transaction)
		__jbd2_journal_temp_unlink_buffer(jh);
	else jbd2_journal_grab_journal_head(bh);
	jh->b_transaction = transaction;

	switch (jlist) {
	case BJ_None:
		J_ASSERT_JH(jh, !jh->b_committed_data);
		J_ASSERT_JH(jh, !jh->b_frozen_data);
		return;
	case BJ_Metadata:
		transaction->t_nr_buffers++;
		list = &transaction->t_buffers;
		break;
	case BJ_Forget:
		list = &transaction->t_forget;
		break;
	case BJ_Shadow:
		list = &transaction->t_shadow_list;
		break;
	case BJ_Reserved:
		list = &transaction->t_reserved_list;
		break;
	}

	__blist_add_buffer(list, jh);
	jh->b_jlist = jlist;

	if (was_dirty)
		set_buffer_jbddirty(bh);
}

void jbd2_journal_file_buffer(struct journal_head *jh, transaction_t *transaction, int jlist)
{
	spin_lock(&jh->b_state_lock);
	spin_lock(&transaction->t_journal->j_list_lock);
	__jbd2_journal_file_buffer(jh, transaction, jlist);
	spin_unlock(&transaction->t_journal->j_list_lock);
	spin_unlock(&jh->b_state_lock);
}


bool __jbd2_journal_refile_buffer(struct journal_head *jh)
{
	int was_dirty, jlist;
	struct buffer_head *bh = jh2bh(jh);

	lockdep_assert_held(&jh->b_state_lock);
	if (jh->b_transaction)
		assert_spin_locked(&jh->b_transaction->t_journal->j_list_lock);

	
	if (jh->b_next_transaction == NULL) {
		__jbd2_journal_unfile_buffer(jh);
		return true;
	}

	

	was_dirty = test_clear_buffer_jbddirty(bh);
	__jbd2_journal_temp_unlink_buffer(jh);

	
	J_ASSERT_JH(jh, jh->b_transaction != NULL);

	
	WRITE_ONCE(jh->b_transaction, jh->b_next_transaction);
	WRITE_ONCE(jh->b_next_transaction, NULL);
	if (buffer_freed(bh))
		jlist = BJ_Forget;
	else if (jh->b_modified)
		jlist = BJ_Metadata;
	else jlist = BJ_Reserved;
	__jbd2_journal_file_buffer(jh, jh->b_transaction, jlist);
	J_ASSERT_JH(jh, jh->b_transaction->t_state == T_RUNNING);

	if (was_dirty)
		set_buffer_jbddirty(bh);
	return false;
}


void jbd2_journal_refile_buffer(journal_t *journal, struct journal_head *jh)
{
	bool drop;

	spin_lock(&jh->b_state_lock);
	spin_lock(&journal->j_list_lock);
	drop = __jbd2_journal_refile_buffer(jh);
	spin_unlock(&jh->b_state_lock);
	spin_unlock(&journal->j_list_lock);
	if (drop)
		jbd2_journal_put_journal_head(jh);
}


static int jbd2_journal_file_inode(handle_t *handle, struct jbd2_inode *jinode, unsigned long flags, loff_t start_byte, loff_t end_byte)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;

	if (is_handle_aborted(handle))
		return -EROFS;
	journal = transaction->t_journal;

	jbd_debug(4, "Adding inode %lu, tid:%d\n", jinode->i_vfs_inode->i_ino, transaction->t_tid);

	spin_lock(&journal->j_list_lock);
	jinode->i_flags |= flags;

	if (jinode->i_dirty_end) {
		jinode->i_dirty_start = min(jinode->i_dirty_start, start_byte);
		jinode->i_dirty_end = max(jinode->i_dirty_end, end_byte);
	} else {
		jinode->i_dirty_start = start_byte;
		jinode->i_dirty_end = end_byte;
	}

	
	if (jinode->i_transaction == transaction || jinode->i_next_transaction == transaction)
		goto done;

	
	if (!transaction->t_need_data_flush)
		transaction->t_need_data_flush = 1;
	
	if (jinode->i_transaction) {
		J_ASSERT(jinode->i_next_transaction == NULL);
		J_ASSERT(jinode->i_transaction == journal->j_committing_transaction);
		jinode->i_next_transaction = transaction;
		goto done;
	}
	
	J_ASSERT(!jinode->i_next_transaction);
	jinode->i_transaction = transaction;
	list_add(&jinode->i_list, &transaction->t_inode_list);
done:
	spin_unlock(&journal->j_list_lock);

	return 0;
}

int jbd2_journal_inode_ranged_write(handle_t *handle, struct jbd2_inode *jinode, loff_t start_byte, loff_t length)
{
	return jbd2_journal_file_inode(handle, jinode, JI_WRITE_DATA | JI_WAIT_DATA, start_byte, start_byte + length - 1);

}

int jbd2_journal_inode_ranged_wait(handle_t *handle, struct jbd2_inode *jinode, loff_t start_byte, loff_t length)
{
	return jbd2_journal_file_inode(handle, jinode, JI_WAIT_DATA, start_byte, start_byte + length - 1);
}


int jbd2_journal_begin_ordered_truncate(journal_t *journal, struct jbd2_inode *jinode, loff_t new_size)

{
	transaction_t *inode_trans, *commit_trans;
	int ret = 0;

	
	if (!jinode->i_transaction)
		goto out;
	
	read_lock(&journal->j_state_lock);
	commit_trans = journal->j_committing_transaction;
	read_unlock(&journal->j_state_lock);
	spin_lock(&journal->j_list_lock);
	inode_trans = jinode->i_transaction;
	spin_unlock(&journal->j_list_lock);
	if (inode_trans == commit_trans) {
		ret = filemap_fdatawrite_range(jinode->i_vfs_inode->i_mapping, new_size, LLONG_MAX);
		if (ret)
			jbd2_journal_abort(journal, ret);
	}
out:
	return ret;
}
