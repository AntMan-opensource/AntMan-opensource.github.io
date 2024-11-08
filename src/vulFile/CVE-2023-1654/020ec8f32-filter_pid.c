	





static void free_evt(GF_FilterEvent *evt);

static void pcki_del(GF_FilterPacketInstance *pcki)
{
	assert(pcki->pck->reference_count);
	if (safe_int_dec(&pcki->pck->reference_count) == 0) {
		gf_filter_packet_destroy(pcki->pck);
	}
	gf_free(pcki);
}

void gf_filter_pid_inst_reset(GF_FilterPidInst *pidinst)
{
	assert(pidinst);
	while (gf_fq_count(pidinst->packets)) {
		GF_FilterPacketInstance *pcki = gf_fq_pop(pidinst->packets);
		pcki_del(pcki);
	}

	while (gf_list_count(pidinst->pck_reassembly)) {
		GF_FilterPacketInstance *pcki = gf_list_pop_back(pidinst->pck_reassembly);
		pcki_del(pcki);
	}
}

void gf_filter_pid_inst_del(GF_FilterPidInst *pidinst)
{
	assert(pidinst);
	gf_filter_pid_inst_reset(pidinst);

 	gf_fq_del(pidinst->packets, (gf_destruct_fun) pcki_del);
	gf_mx_del(pidinst->pck_mx);
	gf_list_del(pidinst->pck_reassembly);
	if (pidinst->props) {
		assert(pidinst->props->reference_count);
		if (safe_int_dec(&pidinst->props->reference_count) == 0) {
			
			gf_mx_p(pidinst->pid->filter->tasks_mx);
			gf_list_del_item(pidinst->pid->properties, pidinst->props);
			gf_mx_v(pidinst->pid->filter->tasks_mx);
			gf_props_del(pidinst->props);
		}
	}
	gf_free(pidinst);
}

static GF_FilterPidInst *gf_filter_pid_inst_new(GF_Filter *filter, GF_FilterPid *pid)
{
	GF_FilterPidInst *pidinst;
	GF_SAFEALLOC(pidinst, GF_FilterPidInst);
	if (!pidinst) return NULL;
	pidinst->pid = pid;
	pidinst->filter = filter;

	if (filter->session->use_locks) {
		char szName[200];
		u32 pid_idx = 1 + gf_list_find(pid->filter->output_pids, pid);
		u32 dst_idx = 1 + pid->num_destinations;
		snprintf(szName, 200, "F%sPid%dDest%dPackets", filter->name, pid_idx, dst_idx);
		pidinst->pck_mx = gf_mx_new(szName);
	}

	pidinst->packets = gf_fq_new(pidinst->pck_mx);

	pidinst->pck_reassembly = gf_list_new();
	pidinst->last_block_ended = GF_TRUE;
	return pidinst;
}

static void gf_filter_pid_check_unblock(GF_FilterPid *pid)
{
	Bool unblock;

	if (pid->ignore_blocking) {
		return;
	}
	
	if (pid->has_seen_eos && !pid->nb_buffer_unit) {
		if (!pid->would_block) {
			safe_int_inc(&pid->would_block);
			safe_int_inc(&pid->filter->would_block);
			assert(pid->filter->would_block + pid->filter->num_out_pids_not_connected <= pid->filter->num_output_pids);
		}
		return;
	}

	unblock=GF_FALSE;

	assert(pid->playback_speed_scaler);

	
	
	if (pid->max_buffer_unit) {
		if (pid->nb_buffer_unit * GF_FILTER_SPEED_SCALER < pid->max_buffer_unit * pid->playback_speed_scaler) {
			unblock=GF_TRUE;
		}
	} else if (pid->buffer_duration * GF_FILTER_SPEED_SCALER < pid->max_buffer_time * pid->playback_speed_scaler) {
		unblock=GF_TRUE;
	}

	if (!unblock) {
		return;
	}
	gf_mx_p(pid->filter->tasks_mx);
	unblock = GF_FALSE;

	
	if (pid->would_block) {
		safe_int_dec(&pid->would_block);

		assert(pid->filter->would_block);
		safe_int_dec(&pid->filter->would_block);
		assert((s32)pid->filter->would_block>=0);
		assert(pid->filter->would_block + pid->filter->num_out_pids_not_connected <= pid->filter->num_output_pids);

		GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter %s PID %s unblocked (filter has %d blocking pids)\n", pid->pid->filter->name, pid->pid->name, pid->pid->filter->would_block));

		
		unblock = GF_TRUE;
	}
	
	else if (!pid->filter->process_task_queued) {
		unblock = GF_TRUE;
	}

	if (unblock && (pid->filter->would_block + pid->filter->num_out_pids_not_connected < pid->filter->num_output_pids)) {
		GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter %s has only %d / %d blocked pids, requesting process task (%d queued)\n", pid->filter->name, pid->filter->would_block + pid->filter->num_out_pids_not_connected, pid->filter->num_output_pids, pid->filter->process_task_queued));

		
		gf_filter_post_process_task(pid->filter);
	}

	gf_mx_v(pid->filter->tasks_mx);
}

static void gf_filter_pid_inst_check_dependencies(GF_FilterPidInst *pidi)
{
	const GF_PropertyValue *p;
	u32 i, dep_id = 0;
	GF_FilterPid *pid = pidi->pid;
	GF_Filter *filter = pid->filter;

	
	p = gf_filter_pid_get_property_first(pid, GF_PROP_PID_DEPENDENCY_ID);
	if (p) dep_id = p->value.uint;

	if (!dep_id) return;

	for (i=0; i<filter->num_output_pids; i++) {
		u32 j;
		GF_FilterPid *a_pid = gf_list_get(filter->output_pids, i);
		if (a_pid==pid) continue;
		p = gf_filter_pid_get_property_first(a_pid, GF_PROP_PID_ID);
		if (!p) p = gf_filter_pid_get_property_first(a_pid, GF_PROP_PID_ESID);
		if (!p || (p->value.uint != dep_id)) continue;

		for (j=0; j<a_pid->num_destinations; j++) {
			GF_FilterPidInst *a_pidi = gf_list_get(a_pid->destinations, j);
			if (a_pidi == pidi) continue;
			if (! a_pidi->is_decoder_input) continue;

			if (a_pidi->filter == pidi->filter) continue;

			GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("Filter %s PID %s connected to decoder %s, but dependent stream %s connected to %s - switching pid destination\n", a_pid->filter->name, a_pid->name, a_pidi->filter->name, pidi->pid->name, pidi->filter->name));

			
			gf_fs_post_task(filter->session, gf_filter_pid_disconnect_task, a_pidi->filter, a_pid, "pidinst_disconnect", NULL);

			
			safe_int_inc(&pid->filter->out_pid_connection_pending);
			gf_filter_pid_post_connect_task(pidi->filter, a_pid);

		}
	}
}

static void gf_filter_pid_update_caps(GF_FilterPid *pid)
{
	u32 mtype=0, codecid=0;
	u32 i;
	const GF_PropertyValue *p;

	pid->raw_media = GF_FALSE;
	p = gf_filter_pid_get_property_first(pid, GF_PROP_PID_CODECID);
	if (p) codecid = p->value.uint;

	p = gf_filter_pid_get_property_first(pid, GF_PROP_PID_STREAM_TYPE);
	if (p) mtype = p->value.uint;

	Bool was_sparse = pid->is_sparse;
	p = gf_filter_pid_get_property_first(pid, GF_PROP_PID_SPARSE);
	if (p) {
		pid->is_sparse = p->value.boolean;
	} else {
		u32 otype = mtype;
		p = gf_filter_pid_get_property_first(pid, GF_PROP_PID_ORIG_STREAM_TYPE);
		if (p) otype = p->value.uint;
		switch (otype) {
		case GF_STREAM_AUDIO:
		case GF_STREAM_VISUAL:
		case GF_STREAM_FILE:
			pid->is_sparse = GF_FALSE;
			break;
		default:
			pid->is_sparse = GF_TRUE;
			break;
		}
	}
	if (was_sparse && !pid->is_sparse)
		safe_int_dec(&pid->filter->nb_sparse_pids);
	else if (!was_sparse && pid->is_sparse)
		safe_int_inc(&pid->filter->nb_sparse_pids);


	pid->stream_type = mtype;
	pid->codecid = codecid;

	u32 buffer_us = pid->filter->pid_buffer_max_us ? pid->filter->pid_buffer_max_us : pid->filter->session->default_pid_buffer_max_us;
	if (pid->user_max_buffer_time) {
		pid->max_buffer_time = MAX(pid->user_max_buffer_time, buffer_us);
		pid->max_buffer_unit = 0;
	} else {
		pid->max_buffer_time = buffer_us;
		pid->max_buffer_unit = pid->filter->pid_buffer_max_units ? pid->filter->pid_buffer_max_units : pid->filter->session->default_pid_buffer_max_units;
	}
	pid->raw_media = GF_FALSE;

	if (codecid!=GF_CODECID_RAW) {
		gf_mx_p(pid->filter->tasks_mx);
		for (i=0; i<pid->filter->num_input_pids; i++) {
			u32 i_codecid=0, i_type=0;
			GF_FilterPidInst *pidi = gf_list_get(pid->filter->input_pids, i);
			if (!pidi->pid) continue;
			p = gf_filter_pid_get_property_first(pidi->pid, GF_PROP_PID_STREAM_TYPE);
			if (p) i_type = p->value.uint;

			p = gf_filter_pid_get_property_first(pidi->pid, GF_PROP_PID_CODECID);
			if (p) i_codecid = p->value.uint;
			
			if ((mtype==i_type) && (i_codecid==GF_CODECID_RAW)) {
				pidi->is_encoder_input = GF_TRUE;
			}
		}
		gf_mx_v(pid->filter->tasks_mx);
		return;
	}

	
	
	gf_mx_p(pid->filter->tasks_mx);
	for (i=0; i<pid->filter->num_input_pids; i++) {
		u32 i_codecid=0, i_type=0;
		GF_FilterPidInst *pidi = gf_list_get(pid->filter->input_pids, i);
		if (!pidi->pid) continue;

		p = gf_filter_pid_get_property_first(pidi->pid, GF_PROP_PID_STREAM_TYPE);
		if (p) i_type = p->value.uint;

		p = gf_filter_pid_get_property_first(pidi->pid, GF_PROP_PID_CODECID);
		if (p) i_codecid = p->value.uint;

		
		if ((mtype==i_type) && (codecid != i_codecid)) {

			buffer_us = pid->filter->pid_decode_buffer_max_us ? pid->filter->pid_decode_buffer_max_us : pid->filter->session->decoder_pid_buffer_max_us;
			
			pidi->pid->max_buffer_time = MAX(pidi->pid->user_max_buffer_time, buffer_us);
			pidi->pid->max_buffer_unit = 0;

			
			if (pid->filter->pid_buffer_max_units) {
				pid->max_buffer_unit = pid->filter->pid_buffer_max_units;
			} else if (mtype==GF_STREAM_VISUAL) {
				pid->max_buffer_unit = 4;
			} else if (mtype==GF_STREAM_AUDIO) {
				pid->max_buffer_unit = 20;
			}

			if (!pidi->is_decoder_input) {
				GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter %s pid instance %s marked as decoder input\n",  pidi->pid->filter->name, pidi->pid->name));
				pidi->is_decoder_input = GF_TRUE;
				safe_int_inc(&pidi->pid->nb_decoder_inputs);

				if ((i_type == GF_STREAM_AUDIO) || (i_type == GF_STREAM_VISUAL))
					gf_filter_pid_inst_check_dependencies(pidi);
			}
		}
		
		else if (mtype==i_type) {
			pid->raw_media = GF_TRUE;
			
			if (pid->filter->num_input_pids==1) {
				GF_FilterPidInst *pid_in = gf_list_get(pid->filter->input_pids, i);
				if ((pid_in->pid->max_buffer_unit>1) || pid_in->pid->max_buffer_time) {
					pid->max_buffer_unit = pid_in->pid->max_buffer_unit;
					pid->filter->pid_buffer_max_units = pid_in->pid->max_buffer_unit;
					pid->max_buffer_time = pid_in->pid->max_buffer_time;
					pid->filter->pid_buffer_max_us = (u32) pid_in->pid->max_buffer_time;
				}
				
				if (pid_in->pid->num_destinations==1) {
					pid_in->pid->max_buffer_unit = 1;
					pid_in->pid->max_buffer_time = 0;
				}
			}
		}
		
		else if ((i_type==GF_STREAM_FILE) && (mtype!=GF_STREAM_FILE) && (codecid==GF_CODECID_RAW) ) {
			pid->raw_media = GF_TRUE;
		}
	}
	
	if (!pid->filter->num_input_pids && pid->num_destinations) {
		pid->raw_media = GF_TRUE;
	}
	gf_mx_v(pid->filter->tasks_mx);
}




void gf_filter_pid_inst_delete_task(GF_FSTask *task)
{
	GF_FilterPid *pid = task->pid;
	GF_FilterPidInst *pidinst = task->udta;
	GF_Filter *filter = pid->filter;
	Bool pid_still_alive = GF_FALSE;

	assert(filter);
	
	if ((pidinst->filter && pidinst->discard_packets) || filter->stream_reset_pending || filter->abort_pending) {
		TASK_REQUEUE(task)
		return;
	}

	
	
	
	gf_filter_pid_inst_reset(pidinst);

	
	if (pidinst->pid->nb_shared_packets_out) {
		
		if (!pid->num_destinations || ((pid->num_destinations>=1) && (gf_list_find(pid->destinations, pidinst)>=0))) {
			TASK_REQUEUE(task)
			return;
		}
	}

	
	GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Filter %s pid instance %s destruction (%d fan-out)\n",  filter->name, pid->name, pid->num_destinations));
	gf_mx_p(filter->tasks_mx);
	gf_list_del_item(pid->destinations, pidinst);
	pid->num_destinations = gf_list_count(pid->destinations);
	if (pidinst->pid->num_pidinst_del_pending) {
		pidinst->pid->num_pidinst_del_pending--;
		if (pidinst->pid->num_pidinst_del_pending)
			pid_still_alive = GF_TRUE;
	}
	gf_mx_v(filter->tasks_mx);

	if (pidinst->is_decoder_input) {
		assert(pid->nb_decoder_inputs);
		safe_int_dec(&pid->nb_decoder_inputs);
	}
	gf_filter_pid_inst_del(pidinst);
	
	if (pid->num_destinations) {
		u32 i;
		u32 nb_pck = 0;
		s64 buf_dur = 0;
		for (i = 0; i < pid->num_destinations; i++) {
			GF_FilterPidInst *apidi = gf_list_get(pid->destinations, i);
			u32 npck = gf_fq_count(apidi->packets);
			if (npck > nb_pck) nb_pck = npck;
			if (apidi->buffer_duration > buf_dur) buf_dur = apidi->buffer_duration;
		}
		pid->nb_buffer_unit = nb_pck;
		pid->buffer_duration = buf_dur;
	} else {
		pid->nb_buffer_unit = 0;
		pid->buffer_duration = 0;
	}

	assert(pid->filter == filter);

	if (pid_still_alive)
		return;

	
	if (pid->num_destinations || pid->init_task_pending) {
		if (pid->would_block)
			gf_filter_pid_check_unblock(pid);
		else gf_filter_pid_would_block(pid);

		return;
	}
	gf_mx_p(filter->tasks_mx);
	
	if (gf_list_count(filter->input_pids)) {
		gf_mx_v(filter->tasks_mx);
		return;
	}
	
	if (pid->would_block) {
		assert(pid->filter->would_block);
		safe_int_dec(&pid->filter->would_block);
	}

	
	
	
	pid->removed = GF_TRUE;

	
	if (!gf_list_count(filter->input_pids) && !filter->finalized) {
		u32 i, nb_opid_rem=0;
		for (i=0; i<filter->num_output_pids; i++) {
			GF_FilterPid *apid = gf_list_get(filter->output_pids, i);
			if (apid->removed) nb_opid_rem++;
		}
		if (gf_list_count(filter->output_pids)==nb_opid_rem) {
			gf_filter_post_remove(filter);
		}
	}

	gf_mx_v(filter->tasks_mx);
}

static void gf_filter_pid_inst_swap_delete(GF_Filter *filter, GF_FilterPid *pid, GF_FilterPidInst *pidinst, GF_FilterPidInst *dst_swapinst)
{
	u32 i, j;

	
	
	
	gf_filter_pid_inst_reset(pidinst);

	GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Filter %s pid instance %s swap destruction\n",  filter->name, pidinst->pid ? pidinst->pid->name : pid->name));
	gf_mx_p(filter->tasks_mx);
	gf_list_del_item(filter->input_pids, pidinst);
	filter->num_input_pids = gf_list_count(filter->input_pids);
	if (!filter->num_input_pids)
		filter->single_source = NULL;
	gf_mx_v(filter->tasks_mx);

	gf_mx_p(pid->filter->tasks_mx);
	gf_list_del_item(pid->destinations, pidinst);
	pid->num_destinations = gf_list_count(pid->destinations);
	gf_mx_v(pid->filter->tasks_mx);


	if (pidinst->is_decoder_input) {
		assert(pid->nb_decoder_inputs);
		safe_int_dec(&pid->nb_decoder_inputs);
	}
	
	if (filter->detached_pid_inst && (gf_list_find(filter->detached_pid_inst, pidinst)>=0) )
		return;

	gf_filter_pid_inst_del(pidinst);

	if (filter->num_input_pids) return;
	
	if (filter->detached_pid_inst) return;

	
	for (i=0; i<filter->num_output_pids; i++) {
		GF_FilterPid *a_pid = gf_list_get(filter->output_pids, i);
		for (j=0; j<a_pid->num_destinations; j++) {
			GF_FilterPidInst *a_pidi = gf_list_get(a_pid->destinations, j);
			if (a_pidi == dst_swapinst) continue;

			gf_filter_pid_inst_swap_delete(a_pidi->filter, a_pid, a_pidi, dst_swapinst);
		}
	}
	filter->swap_pidinst_dst = NULL;
	filter->swap_pidinst_src = NULL;
	gf_filter_post_remove(filter);
}

static void gf_filter_pid_inst_swap_delete_task(GF_FSTask *task)
{
	GF_FilterPidInst *pidinst = task->udta;
	GF_Filter *filter = pidinst->filter;
	GF_FilterPid *pid = task->pid ? task->pid : pidinst->pid;
	GF_FilterPidInst *dst_swapinst = pidinst->filter->swap_pidinst_dst;

	
	if ((pidinst->filter && pidinst->discard_packets)
		|| filter->stream_reset_pending || filter->nb_shared_packets_out ) {

		TASK_REQUEUE(task)
		return;
	}
	if (pidinst->filter)
		pidinst->filter->swap_pidinst_dst = NULL;

	gf_filter_pid_inst_swap_delete(filter, pid, pidinst, dst_swapinst);
}

static void gf_filter_pid_inst_swap(GF_Filter *filter, GF_FilterPidInst *dst)
{
	GF_PropertyMap *prev_dst_props;
	u32 nb_pck_transfer=0;
	GF_FilterPidInst *src = filter->swap_pidinst_src;
	if (!src) src = filter->swap_pidinst_dst;
	
	if (src) {
		GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter %s swaping PID %s to PID %s\n", filter->name, src->pid->name, dst->pid->name));
	}

	
	if (filter->swap_needs_init) {
		
		assert(filter->swap_pidinst_dst && filter->swap_pidinst_dst->detach_pending);
		

		
	}
	
	else {
		gf_mx_p(dst->pid->filter->tasks_mx);
		if (src)
			gf_list_del_item(dst->pid->destinations, src);
		if (gf_list_find(dst->pid->destinations, dst)<0)
			gf_list_add(dst->pid->destinations, dst);
		dst->pid->num_destinations = gf_list_count(dst->pid->destinations);
		if (gf_list_find(dst->filter->input_pids, dst)<0) {
			gf_list_add(dst->filter->input_pids, dst);
			dst->filter->num_input_pids = gf_list_count(dst->filter->input_pids);

			if (dst->filter->num_input_pids==1) {
				dst->filter->single_source = dst->pid->filter;
			} else if (dst->filter->single_source != dst->pid->filter) {
				dst->filter->single_source = NULL;
			}
		}
		gf_mx_v(dst->pid->filter->tasks_mx);
	}

	if (src) {
		GF_FilterPacketInstance *pcki;
		while (1) {
			pcki = gf_fq_pop(src->packets);
			if (!pcki) break;
			assert(src->filter->pending_packets);
			safe_int_dec(&src->filter->pending_packets);

			if (pcki->pck->info.flags & GF_PCKF_FORCE_MAIN) {
				assert(src->filter->nb_main_thread_forced);
				safe_int_dec(&src->filter->nb_main_thread_forced);
				safe_int_inc(&dst->filter->nb_main_thread_forced);
			}
			pcki->pid = dst;
			gf_fq_add(dst->packets, pcki);
			safe_int_inc(&dst->filter->pending_packets);
			nb_pck_transfer++;
		}
		if (src->requires_full_data_block && gf_list_count(src->pck_reassembly)) {
			dst->requires_full_data_block = src->requires_full_data_block;
			dst->last_block_ended = src->last_block_ended;
			dst->first_block_started = src->first_block_started;
			if (!dst->pck_reassembly) dst->pck_reassembly = gf_list_new();
			while (gf_list_count(src->pck_reassembly)) {
				pcki = gf_list_pop_front(src->pck_reassembly);
				pcki->pid = dst;
				gf_list_add(dst->pck_reassembly, pcki);
			}
		}
		
		dst->is_end_of_stream = src->is_end_of_stream;
		dst->nb_eos_signaled = src->nb_eos_signaled;
		dst->buffer_duration = src->buffer_duration;
		dst->nb_clocks_signaled = src->nb_clocks_signaled;

		
		
		
		prev_dst_props = dst->props;
		dst->props = src->props;
		dst->force_reconfig = GF_TRUE;
		src->force_reconfig = GF_TRUE;
		src->props = NULL;
		if (prev_dst_props) {
			if (dst->props) {
				gf_props_merge_property(dst->props, prev_dst_props, NULL, NULL);
				assert(prev_dst_props->reference_count);
				if (safe_int_dec(&prev_dst_props->reference_count) == 0) {
					gf_props_del(prev_dst_props);
				}
			} else {
				dst->props = prev_dst_props;
			}
		}

		if (nb_pck_transfer && !dst->filter->process_task_queued) {
			gf_filter_post_process_task(dst->filter);
		}
	}


	src = filter->swap_pidinst_dst;
	if (src) {
		if (filter->swap_needs_init) {
			
			assert(src->filter->stream_reset_pending);
			safe_int_dec(&src->filter->stream_reset_pending);

			
			safe_int_inc(&src->pid->filter->detach_pid_tasks_pending);
			safe_int_inc(&filter->detach_pid_tasks_pending);
			gf_fs_post_task(filter->session, gf_filter_pid_detach_task, src->filter, src->pid, "pidinst_detach", filter);
		} else {
			GF_Filter *src_filter = src->filter;
			assert(!src->filter->sticky);
			assert(src->filter->num_input_pids==1);

			gf_mx_p(src_filter->tasks_mx);
			gf_list_del_item(src_filter->input_pids, src);
			src_filter->num_input_pids = gf_list_count(src_filter->input_pids);
			if (!src_filter->num_input_pids)
				src_filter->single_source = NULL;
			gf_mx_v(src_filter->tasks_mx);

			gf_list_del_item(src->pid->destinations, src);
			src->pid->num_destinations = gf_list_count(src->pid->destinations);
			gf_filter_pid_inst_del(src);

			filter->swap_pidinst_dst = NULL;
			filter->swap_pidinst_src = NULL;
			gf_filter_post_remove(src_filter);
		}
	}
	
	if (filter->swap_pidinst_src) {
		src = filter->swap_pidinst_src;
		assert(!src->filter->swap_pidinst_dst);
		src->filter->swap_pidinst_dst = filter->swap_pidinst_dst;
		src->filter->swap_pending = GF_TRUE;
		gf_fs_post_task(filter->session, gf_filter_pid_inst_swap_delete_task, src->filter, src->pid, "pid_inst_delete", src);
	}
}




void gf_filter_instance_detach_pid(GF_FilterPidInst *pidinst)
{
	u32 i, count;
	if (!pidinst->filter) return;

	count = gf_fq_count(pidinst->packets);
	for (i=0; i<count; i++) {
		GF_FilterPacketInstance *pcki = gf_fq_get(pidinst->packets, i);
		if (!pcki) break;
		if (pcki->pck->info.flags & GF_PCKF_FORCE_MAIN) {
			assert(pidinst->filter->nb_main_thread_forced);
			safe_int_dec(&pidinst->filter->nb_main_thread_forced);
		}
	}
	count = gf_list_count(pidinst->pck_reassembly);
	for (i=0; i<count; i++) {
		GF_FilterPacketInstance *pcki = gf_list_get(pidinst->pck_reassembly, i);
		if (!pcki) break;
		if (pcki->pck->info.flags & GF_PCKF_FORCE_MAIN) {
			assert(pidinst->filter->nb_main_thread_forced);
			safe_int_dec(&pidinst->filter->nb_main_thread_forced);
		}
	}
	pidinst->filter = NULL;
}

void task_canceled(GF_FSTask *task)
{
	if (task->class_type==TASK_TYPE_EVENT) {
		GF_FilterEvent *evt = task->udta;
		free_evt(evt);
	}
	else if (task->class_type==TASK_TYPE_SETUP) {
		gf_free(task->udta);
	}
	else if (task->class_type==TASK_TYPE_USER) {
		gf_free(task->udta);
		gf_free((char *)task->log_name);
		task->log_name = NULL;
	}
}


typedef enum {
	GF_PID_CONF_CONNECT, GF_PID_CONF_RECONFIG, GF_PID_CONF_REMOVE, } GF_PidConnectType;



static GF_Err gf_filter_pid_configure(GF_Filter *filter, GF_FilterPid *pid, GF_PidConnectType ctype)
{
	u32 i, count;
	GF_Err e;
	Bool refire_events=GF_FALSE;
	Bool new_pid_inst=GF_FALSE;
	Bool remove_filter=GF_FALSE;
	GF_FilterPidInst *pidinst=NULL;
	GF_Filter *alias_orig = NULL;

	if (filter->multi_sink_target) {
		alias_orig = filter;
		filter = filter->multi_sink_target;
	}

	assert(filter->freg->configure_pid);
	if (filter->finalized) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Trying to configure PID %s in finalized filter %s\n",  pid->name, filter->name));
		if (ctype==GF_PID_CONF_CONNECT) {
			assert(pid->filter->out_pid_connection_pending);
			safe_int_dec(&pid->filter->out_pid_connection_pending);
		}
		return GF_SERVICE_ERROR;
	}

	if (filter->detached_pid_inst) {
		count = gf_list_count(filter->detached_pid_inst);
		for (i=0; i<count; i++) {
			pidinst = gf_list_get(filter->detached_pid_inst, i);
			if (pidinst->filter==filter) {
				gf_list_rem(filter->detached_pid_inst, i);
				
				pidinst->filter = filter;
				pidinst->pid = pid;

				assert(!pidinst->props);

				
				if (ctype == GF_PID_CONF_CONNECT) {
					new_pid_inst=GF_TRUE;
					if (!pid->filter->nb_pids_playing && (pidinst->is_playing || pidinst->is_paused))
						refire_events = GF_TRUE;
				}
				assert(pidinst->detach_pending);
				safe_int_dec(&pidinst->detach_pending);
				
				if (filter->sticky == 2)
					filter->sticky = 0;
				break;
			}
			pidinst=NULL;
		}
		if (! gf_list_count(filter->detached_pid_inst)) {
			gf_list_del(filter->detached_pid_inst);
			filter->detached_pid_inst = NULL;
		}
	}
	if (!pidinst) {
		count = pid->num_destinations;
		for (i=0; i<count; i++) {
			pidinst = gf_list_get(pid->destinations, i);
			if (pidinst->filter==filter) {
				break;
			}
			pidinst=NULL;
		}
	}

	
	if (!pidinst) {
		if (ctype != GF_PID_CONF_CONNECT) {
			GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Trying to disconnect PID %s not present in filter %s inputs\n",  pid->name, filter->name));
			return GF_SERVICE_ERROR;
		}
		pidinst = gf_filter_pid_inst_new(filter, pid);
		new_pid_inst=GF_TRUE;
	}
	if (!pidinst->alias_orig)
		pidinst->alias_orig = alias_orig;

	
	if (new_pid_inst) {
		assert(pidinst);
		gf_mx_p(pid->filter->tasks_mx);

		GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Registering %s:%s as destination for %s:%s\n", pid->filter->name, pid->name, pidinst->filter->name, pidinst->pid->name));
		gf_list_add(pid->destinations, pidinst);
		pid->num_destinations = gf_list_count(pid->destinations);

		gf_mx_v(pid->filter->tasks_mx);

		gf_mx_p(filter->tasks_mx);
		if (!filter->input_pids) filter->input_pids = gf_list_new();
		gf_list_add(filter->input_pids, pidinst);
		filter->num_input_pids = gf_list_count(filter->input_pids);
		if (filter->num_input_pids==1) {
			filter->single_source = pidinst->pid->filter;
		} else if (filter->single_source != pidinst->pid->filter) {
			filter->single_source = NULL;
		}
		gf_mx_v(filter->tasks_mx);

		
		
		
		gf_filter_pid_update_caps(pid);
	}

	
	
	
	if (filter->swap_pending) {
		gf_filter_pid_inst_swap(filter, pidinst);
		filter->swap_pending = GF_FALSE;
	}

	filter->in_connect_err = GF_EOS;
	
	

	FSESS_CHECK_THREAD(filter)


	GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter %s PID %s reconfigure\n", pidinst->filter->name, pidinst->pid->name));
	e = filter->freg->configure_pid(filter, (GF_FilterPid*) pidinst, (ctype==GF_PID_CONF_REMOVE) ? GF_TRUE : GF_FALSE);


	if (filter->session->check_allocs) {
		if (filter->nb_consecutive_process >= filter->max_nb_consecutive_process) {
			filter->max_nb_consecutive_process = filter->nb_consecutive_process;
			filter->max_nb_process = filter->nb_process_since_reset;
			filter->max_stats_nb_alloc = filter->stats_nb_alloc;
			filter->max_stats_nb_calloc = filter->stats_nb_calloc;
			filter->max_stats_nb_realloc = filter->stats_nb_realloc;
			filter->max_stats_nb_free = filter->stats_nb_free;
		}
		filter->stats_mem_allocated = 0;
		filter->stats_nb_alloc = filter->stats_nb_realloc = filter->stats_nb_free = 0;
		filter->nb_process_since_reset = filter->nb_consecutive_process = 0;
	}

	if ((e==GF_OK) && (filter->in_connect_err<GF_OK))
		e = filter->in_connect_err;

	filter->in_connect_err = GF_OK;
	
	if (e==GF_OK) {
		
		if (new_pid_inst) {
			GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Filter %s (%p) PID %s (%p) (%d fan-out) connected to filter %s (%p)\n", pid->filter->name, pid->filter, pid->name, pid, pid->num_destinations, filter->name, filter));
		}
		
		
		gf_list_reset(pidinst->pid->filter->blacklisted);
	}
	
	else if ((ctype==GF_PID_CONF_RECONFIG) && (e != GF_FILTER_NOT_SUPPORTED)) {
		
		pidinst->is_end_of_stream = GF_TRUE;
		if (e==GF_BAD_PARAM) {
			GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Failed to reconfigure PID %s:%s in filter %s: %s\n", pid->filter->name, pid->name, filter->name, gf_error_to_string(e) ));

			filter->session->last_connect_error = e;
		} else {
			GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Failed to reconfigure PID %s:%s in filter %s: %s, reloading filter graph\n", pid->filter->name, pid->name, filter->name, gf_error_to_string(e) ));
			gf_list_add(pid->filter->blacklisted, (void *) filter->freg);
			gf_filter_relink_dst(pidinst, e);
		}
	} else {

		
		gf_mx_p(filter->tasks_mx);
		gf_list_del_item(filter->input_pids, pidinst);
		filter->num_input_pids = gf_list_count(filter->input_pids);
		if (!filter->num_input_pids)
			filter->single_source = NULL;
		filter->freg->configure_pid(filter, (GF_FilterPid *) pidinst, GF_TRUE);
		gf_mx_v(filter->tasks_mx);

		gf_mx_p(pidinst->pid->filter->tasks_mx);
		gf_list_del_item(pidinst->pid->destinations, pidinst);
		pidinst->pid->num_destinations = gf_list_count(pidinst->pid->destinations);
		
		gf_filter_instance_detach_pid(pidinst);
		gf_mx_v(pidinst->pid->filter->tasks_mx);

		
		if (new_pid_inst) {
			gf_mx_p(pid->filter->tasks_mx);
			gf_list_del_item(pid->destinations, pidinst);
			pid->num_destinations = gf_list_count(pid->destinations);

			
			gf_mx_p(pid->filter->tasks_mx);
			count = gf_fq_count(pid->filter->tasks);
			for (i=0; i<count; i++) {
				GF_FSTask *t = gf_fq_get(pid->filter->tasks, i);
				if (t->pid == (GF_FilterPid *) pidinst) {
					t->run_task = task_canceled;
				}
			}
			gf_mx_v(pid->filter->tasks_mx);

			
			gf_filter_pid_inst_del(pidinst);
			gf_mx_v(pid->filter->tasks_mx);
		}


		if (e==GF_REQUIRES_NEW_INSTANCE) {
			
			GF_Filter *new_filter = gf_filter_clone(filter, pid->filter);
			if (new_filter) {
				GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Clone filter %s, new instance for pid %s\n", filter->name, pid->name));
				gf_filter_pid_post_connect_task(new_filter, pid);
				return GF_OK;
			} else {
				GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Failed to clone filter %s\n", filter->name));
				e = GF_OUT_OF_MEM;
			}
		}
		if (e && (ctype==GF_PID_CONF_REMOVE)) {
			GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Failed to disconnect filter %s PID %s from filter %s: %s\n", pid->filter->name, pid->name, filter->name, gf_error_to_string(e) ));
		}
		else if (e) {
			if (e!= GF_EOS) {
				GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Failed to connect filter %s PID %s to filter %s: %s\n", pid->filter->name, pid->name, filter->name, gf_error_to_string(e) ));
			}

			if ((e==GF_BAD_PARAM)
				|| (e==GF_SERVICE_ERROR)
				|| (e==GF_REMOTE_SERVICE_ERROR)
				|| (e==GF_FILTER_NOT_SUPPORTED)
				|| (e==GF_EOS)
				|| (filter->session->flags & GF_FS_FLAG_NO_REASSIGN)
			) {
				if (filter->session->flags & GF_FS_FLAG_NO_REASSIGN) {
					GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Filter reassignment disabled, skippping chain reload for filter %s PID %s\n", pid->filter->name, pid->name ));
				}
				if (e!= GF_EOS) {
					filter->session->last_connect_error = e;
				}

				if (ctype==GF_PID_CONF_CONNECT) {
					GF_FilterEvent evt;
					GF_FEVT_INIT(evt, GF_FEVT_PLAY, pid);
					gf_filter_pid_send_event_internal(pid, &evt, GF_TRUE);

					GF_FEVT_INIT(evt, GF_FEVT_STOP, pid);
					gf_filter_pid_send_event_internal(pid, &evt, GF_TRUE);

					gf_filter_pid_set_eos(pid);

					if (pid->filter->freg->process_event) {
						GF_FEVT_INIT(evt, GF_FEVT_CONNECT_FAIL, pid);
						gf_filter_pid_send_event_internal(pid, &evt, GF_TRUE);
					}
					if (!filter->num_input_pids && !filter->num_output_pids) {
						remove_filter = GF_TRUE;
					}
				}
			} else if (filter->has_out_caps) {
				Bool unload_filter = GF_TRUE;
				GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("Blacklisting %s as output from %s and retrying connections\n", filter->name, pid->filter->name));
				
				
				gf_list_add(pid->filter->blacklisted, (void *) filter->freg);
				
				gf_mx_p(filter->tasks_mx);
				while (gf_list_count(filter->input_pids)) {
					GF_FilterPidInst *a_pidinst = gf_list_pop_back(filter->input_pids);
					FSESS_CHECK_THREAD(filter)
					filter->num_input_pids--;
					filter->freg->configure_pid(filter, (GF_FilterPid *) a_pidinst, GF_TRUE);

					gf_filter_pid_post_init_task(a_pidinst->pid->filter, a_pidinst->pid);
					gf_fs_post_task(filter->session, gf_filter_pid_inst_delete_task, a_pidinst->pid->filter, a_pidinst->pid, "pid_inst_delete", a_pidinst);

					unload_filter = GF_FALSE;
				}
				filter->num_input_pids = 0;
				filter->single_source = NULL;
				filter->removed = 1;
				filter->has_pending_pids = GF_FALSE;
				gf_mx_v(filter->tasks_mx);

				

				if (ctype==GF_PID_CONF_CONNECT) {
					assert(pid->filter->out_pid_connection_pending);
					safe_int_dec(&pid->filter->out_pid_connection_pending);
				}
				
				gf_filter_pid_post_init_task(pid->filter, pid);

				if (unload_filter) {
					assert(!gf_list_count(filter->input_pids));

					if (filter->num_output_pids) {
						for (i=0; i<filter->num_output_pids; i++) {
							u32 j;
							GF_FilterPid *opid = gf_list_get(filter->output_pids, i);
							for (j=0; j< opid->num_destinations; j++) {
								GF_FilterPidInst *a_pidi = gf_list_get(opid->destinations, j);
								a_pidi->pid = NULL;
							}
							gf_list_reset(opid->destinations);
							opid->num_destinations = 0;
							gf_filter_pid_remove(opid);
						}
					}
					filter->swap_pidinst_src = NULL;
					if (filter->swap_pidinst_dst) {
						GF_Filter *target = filter->swap_pidinst_dst->filter;
						assert(target);
						if (!target->detached_pid_inst) {
							target->detached_pid_inst = gf_list_new();
						}
						
						if (filter->swap_pidinst_dst->props) {
							filter->swap_pidinst_dst->props = NULL;
						}
						filter->swap_pidinst_dst->pid = NULL;
						if (gf_list_find(target->detached_pid_inst, filter->swap_pidinst_dst)<0)
							gf_list_add(target->detached_pid_inst, filter->swap_pidinst_dst);
					}
					filter->swap_pidinst_dst = NULL;
					if (filter->on_setup_error) {
						gf_filter_notification_failure(filter, e, GF_TRUE);
					} else {
						gf_filter_post_remove(filter);
					}
				}
				return e;
			} else {
				GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Failed to reconfigure input of sink %s, cannot rebuild graph\n", filter->name));
				if (pid->filter->freg->process_event) {
					GF_FilterEvent evt;
					GF_FEVT_INIT(evt, GF_FEVT_CONNECT_FAIL, pid);
					pid->filter->freg->process_event(pid->filter, &evt);
				}
				filter->session->last_connect_error = e;
			}
		} else {
			filter->session->last_connect_error = GF_OK;
		}

		
		if (filter->session->requires_solved_graph)
			return e;
	}

	
	if (filter->has_pending_pids) {
		filter->has_pending_pids = GF_FALSE;
		while (gf_fq_count(filter->pending_pids)) {
			GF_FilterPid *a_pid=gf_fq_pop(filter->pending_pids);
			
			
			if (pid->is_playing && filter->is_pid_adaptation_filter)
				a_pid->is_playing = GF_TRUE;

			gf_filter_pid_post_init_task(filter, a_pid);
		}
	}

	if (ctype==GF_PID_CONF_REMOVE) {
		gf_mx_p(filter->tasks_mx);
		gf_list_del_item(filter->input_pids, pidinst);
		filter->num_input_pids = gf_list_count(filter->input_pids);
		if (!filter->num_input_pids)
			filter->single_source = NULL;
		gf_mx_v(filter->tasks_mx);

		
		
		
		
		
		
		gf_mx_p(pidinst->pid->filter->tasks_mx);
		pidinst->pid->num_pidinst_del_pending ++;
		gf_list_del_item(pidinst->pid->destinations, pidinst);
		pidinst->pid->num_destinations = gf_list_count(pidinst->pid->destinations);
		gf_filter_instance_detach_pid(pidinst);
		gf_mx_v(pidinst->pid->filter->tasks_mx);

		
		if (!filter->num_input_pids && !filter->sticky) {
			gf_filter_reset_pending_packets(filter);
			filter->removed = 1;
		}
		
		gf_fs_post_task(filter->session, gf_filter_pid_inst_delete_task, pid->filter, pid, "pid_inst_delete", pidinst);

		return e;
	}

	if (ctype==GF_PID_CONF_CONNECT) {
		assert(pid->filter->out_pid_connection_pending);
		if (safe_int_dec(&pid->filter->out_pid_connection_pending) == 0) {

			
			
			if (refire_events) {
				GF_FilterEvent evt;
				if (pidinst->is_playing) {
					pidinst->is_playing = GF_FALSE;
					GF_FEVT_INIT(evt, GF_FEVT_PLAY, (GF_FilterPid*)pidinst);
					gf_filter_pid_send_event((GF_FilterPid *)pidinst, &evt);
				}
				if (pidinst->is_paused) {
					pidinst->is_paused = GF_FALSE;
					GF_FEVT_INIT(evt, GF_FEVT_PAUSE, (GF_FilterPid*)pidinst);
					gf_filter_pid_send_event((GF_FilterPid *)pidinst, &evt);
				}
			}

			if (e==GF_OK) {
				
				
				if (pid->filter->postponed_packets || pid->filter->pending_packets || pid->filter->nb_caps_renegociate) {
					gf_filter_post_process_task(pid->filter);
				}
			}
		}
		if (remove_filter && !filter->sticky)
			gf_filter_post_remove(filter);
	}
	
	gf_filter_pid_update_caps(pid);
	return e;
}

static void gf_filter_pid_connect_task(GF_FSTask *task)
{
	GF_Filter *filter = task->filter;
	GF_FilterSession *fsess = filter->session;
	GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter %s pid %s connecting to %s (%p)\n", task->pid->pid->filter->name, task->pid->pid->name, task->filter->name, filter));

	
	if (filter->num_input_pids && (filter->max_extra_pids <= filter->num_input_pids - 1)) {
		GF_Filter *new_filter = gf_filter_clone(filter, task->pid->pid->filter);
		if (new_filter) {
			filter = new_filter;
		} else {
			GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Failed to clone filter %s\n", filter->name));
			assert(filter->in_pid_connection_pending);
			safe_int_dec(&filter->in_pid_connection_pending);
			if (task->pid->pid) {
				gf_mx_p(filter->tasks_mx);
				gf_list_del_item(filter->temp_input_pids, task->pid->pid);
				gf_mx_v(filter->tasks_mx);
			}
			return;
		}
	}
	if (task->pid->pid) {
		gf_mx_p(filter->tasks_mx);
		gf_list_del_item(filter->temp_input_pids, task->pid->pid);
		gf_mx_v(filter->tasks_mx);
		gf_filter_pid_configure(filter, task->pid->pid, GF_PID_CONF_CONNECT);
		
		if (!task->pid->pid->nb_pck_sent) {
			task->pid->pid->request_property_map = GF_TRUE;
			task->pid->pid->pid_info_changed = GF_FALSE;
		}
	}
	
	
	assert(task->filter->in_pid_connection_pending);
	safe_int_dec(&task->filter->in_pid_connection_pending);

	gf_fs_cleanup_filters(fsess);

}

void gf_filter_pid_reconfigure_task(GF_FSTask *task)
{
	GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Filter %s pid %s reconfigure to %s\n", task->pid->pid->filter->name, task->pid->pid->name, task->filter->name));

	if (task->pid->pid) {
		gf_filter_pid_configure(task->filter, task->pid->pid, GF_PID_CONF_RECONFIG);
		
		if (!task->pid->pid->nb_pck_sent) {
			task->pid->pid->request_property_map = GF_TRUE;
			task->pid->pid->pid_info_changed = GF_FALSE;
		}
	}
}

void gf_filter_pid_reconfigure_task_discard(GF_FSTask *task)
{
	GF_FilterPidInst *pidi = (GF_FilterPidInst *) task->pid;
	GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Filter %s pid %s reconfigure to %s\n", task->pid->pid->filter->name, task->pid->pid->name, task->filter->name));

	if (!pidi->pid) return;
	gf_filter_pid_configure(task->filter, pidi->pid, GF_PID_CONF_RECONFIG);
	
	if (!task->pid->pid->nb_pck_sent) {
		task->pid->pid->request_property_map = GF_TRUE;
		task->pid->pid->pid_info_changed = GF_FALSE;
	}

	if (pidi->discard_inputs==2) {
		gf_filter_aggregate_packets(pidi);
		while (gf_filter_pid_get_packet((GF_FilterPid *) pidi)) {
			gf_filter_pid_drop_packet((GF_FilterPid *) pidi);
		}
		
		pidi->discard_inputs = 1;
	}
}
void gf_filter_pid_disconnect_task(GF_FSTask *task)
{
	GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Filter %s pid %s disconnect from %s\n", task->pid->pid->filter->name, task->pid->pid->name, task->filter->name));
	gf_filter_pid_configure(task->filter, task->pid->pid, GF_PID_CONF_REMOVE);

	gf_mx_p(task->filter->tasks_mx);
	
	if (task->filter->removed && !gf_list_count(task->filter->output_pids) && !gf_list_count(task->filter->input_pids)) {
		Bool direct_mode = task->filter->session->direct_mode;
		gf_filter_post_remove(task->filter);
		if (direct_mode) {
			gf_mx_v(task->filter->tasks_mx);
			task->filter = NULL;
			return;
		}
	}
	gf_mx_v(task->filter->tasks_mx);
}

void gf_filter_pid_detach_task(GF_FSTask *task)
{
	u32 i, count;
	GF_Filter *filter = task->filter;
	GF_FilterPid *pid = task->pid->pid;
	GF_FilterPidInst *pidinst=NULL;
	GF_Filter *new_chain_input = task->udta;

	
	
	if (pid->filter->stream_reset_pending) {
		TASK_REQUEUE(task)
		return;
	}
	if (new_chain_input->in_pid_connection_pending) {
		TASK_REQUEUE(task)
		return;
	}

	count = pid->num_destinations;
	for (i=0; i<count; i++) {
		pidinst = gf_list_get(pid->destinations, i);
		if (pidinst->filter==filter) {
			break;
		}
		pidinst=NULL;
	}
	
	if (pidinst && gf_fq_count(pidinst->packets)) {
		Bool in_process = filter->in_process;
		filter->in_process = GF_FALSE;
		
		filter->in_force_flush = GF_TRUE;
		pidinst->force_flush = GF_TRUE;
		gf_filter_process_inline(filter);
		pidinst->force_flush = GF_FALSE;
		filter->in_force_flush = GF_FALSE;
		filter->in_process = in_process;
		TASK_REQUEUE(task)
		return;
	}

	assert(filter->freg->configure_pid);
	GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Filter %s pid %s detach from %s\n", task->pid->pid->filter->name, task->pid->pid->name, task->filter->name));
	assert(pid->filter->detach_pid_tasks_pending);
	safe_int_dec(&pid->filter->detach_pid_tasks_pending);

	
	if (!pidinst) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Trying to detach PID %s not present in filter %s inputs\n",  pid->name, filter->name));
		
		assert(!new_chain_input->swap_pidinst_src);
		new_chain_input->swap_needs_init = GF_FALSE;
		return;
	}

	
	if (pidinst->props) {
		assert(pidinst->props->reference_count);
		if (safe_int_dec(& pidinst->props->reference_count) == 0) {
			
			gf_mx_p(pidinst->pid->filter->tasks_mx);
			gf_list_del_item(pidinst->pid->properties, pidinst->props);
			gf_mx_v(pidinst->pid->filter->tasks_mx);
			gf_props_del(pidinst->props);
		}
	}
	pidinst->props = NULL;

	gf_mx_p(filter->tasks_mx);
	
	count = gf_fq_count(pidinst->packets);
	assert(count <= filter->pending_packets);
	safe_int_sub(&filter->pending_packets, (s32) count);
	gf_filter_pid_inst_reset(pidinst);
	pidinst->pid = NULL;
	gf_list_del_item(pid->destinations, pidinst);
	pid->num_destinations = gf_list_count(pid->destinations);
	gf_list_del_item(filter->input_pids, pidinst);
	filter->num_input_pids = gf_list_count(filter->input_pids);
	if (!filter->num_input_pids)
		filter->single_source = NULL;
	gf_mx_v(filter->tasks_mx);

	if (!filter->detached_pid_inst) {
		filter->detached_pid_inst = gf_list_new();
	}
	if (gf_list_find(filter->detached_pid_inst, pidinst)<0)
		gf_list_add(filter->detached_pid_inst, pidinst);

	
	if (new_chain_input->swap_needs_init) {
		new_chain_input->swap_pidinst_dst = NULL;
		new_chain_input->swap_pidinst_src = NULL;
		new_chain_input->swap_needs_init = GF_FALSE;
	}
	assert(new_chain_input->detach_pid_tasks_pending);
	safe_int_dec(&new_chain_input->detach_pid_tasks_pending);
}

GF_EXPORT void gf_filter_pid_set_name(GF_FilterPid *pid, const char *name)
{
	if (PID_IS_INPUT(pid)) {
		GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("Attempt to assign name %s to input PID %s in filter %s - ignoring\n", name, pid->pid->name, pid->pid->filter->name));
	} else if (name) {
		if (pid->name && !strcmp(pid->name, name)) return;
		if (pid->name) gf_free(pid->name);
		pid->name = gf_strdup(name);
	}
}

GF_EXPORT const char *gf_filter_pid_get_name(GF_FilterPid *pid)
{
	return pid->pid->name;
}

GF_EXPORT const char *gf_filter_pid_get_filter_name(GF_FilterPid *pid)
{
	if (PID_IS_INPUT(pid)) {
		return pid->pid->filter->name;
	}
	return pid->filter->name;
}

GF_EXPORT const char *gf_filter_pid_orig_src_args(GF_FilterPid *pid, Bool for_unicity)
{
	u32 i;
	const char *args;
	
	pid = pid->pid;
	args = pid->filter->src_args;
	if (args && strstr(args, "src")) return args;
	gf_mx_p(pid->filter->tasks_mx);
	if (!pid->filter->num_input_pids) {
		gf_mx_v(pid->filter->tasks_mx);
		return args;
	}
	for (i=0; i<pid->filter->num_input_pids; i++) {
		GF_FilterPidInst *pidi = gf_list_get(pid->filter->input_pids, i);
		if (for_unicity && (pidi->pid->num_destinations>1)) {
			gf_mx_v(pid->filter->tasks_mx);
			return "__GPAC_SRC_FANOUT__";
		}
		const char *arg_src = gf_filter_pid_orig_src_args(pidi->pid, for_unicity);
		if (arg_src) {
			if (for_unicity && !strcmp(arg_src, "__GPAC_SRC_FANOUT__"))
				arg_src = pid->filter->orig_args ? pid->filter->orig_args : pid->filter->src_args;
			if (arg_src) {
				gf_mx_v(pid->filter->tasks_mx);
				return arg_src;
			}
		}
	}
	gf_mx_v(pid->filter->tasks_mx);
	return args;
}

GF_EXPORT const char *gf_filter_pid_get_source_filter_name(GF_FilterPid *pid)
{
	GF_Filter *filter  = pid->pid->filter;
	while (1) {
		GF_Filter *f;
		if (!filter) break;
		gf_mx_p(filter->tasks_mx);
		if (!filter->num_input_pids) {
			gf_mx_v(filter->tasks_mx);
			break;
		}
		GF_FilterPidInst *pidi = gf_list_get(filter->input_pids, 0);
		f = pidi->pid->filter;
		gf_mx_v(filter->tasks_mx);
		filter = f;
	}
	if (!filter) return NULL;
	return filter->name ? filter->name : filter->freg->name;
}

GF_EXPORT Bool gf_filter_pid_get_buffer_occupancy(GF_FilterPid *pid, u32 *max_slots, u32 *nb_pck, u32 *max_duration, u32 *duration)
{
	if (max_slots) *max_slots = pid->pid->max_buffer_unit;
	if (max_duration) *max_duration = (u32) pid->pid->max_buffer_time;

	if (pid->filter->session->in_final_flush) {
		if (duration) *duration =  (u32) pid->pid->max_buffer_time;
		if (nb_pck) *nb_pck = pid->pid->nb_buffer_unit;
		return GF_FALSE;
	}
	if (nb_pck) *nb_pck = pid->pid->nb_buffer_unit;
	if (duration) *duration = (u32) pid->pid->buffer_duration;
	return GF_TRUE;
}

GF_EXPORT void gf_filter_pid_set_udta(GF_FilterPid *pid, void *udta)
{
	if (PID_IS_INPUT(pid)) {
		((GF_FilterPidInst *)pid)->udta = udta;
	} else {
		pid->udta = udta;
	}
}

GF_EXPORT void *gf_filter_pid_get_udta(GF_FilterPid *pid)
{
	if (PID_IS_INPUT(pid)) {
		return ((GF_FilterPidInst *)pid)->udta;
	} else {
		return pid->udta;
	}
}

static Bool filter_pid_check_fragment(GF_FilterPid *src_pid, char *frag_name, Bool *pid_excluded, Bool *needs_resolve, Bool *prop_not_found, char prop_dump_buffer[GF_PROP_DUMP_ARG_SIZE])
{
	char *psep;
	u32 comp_type=0;
	Bool is_neg = GF_FALSE;
	const GF_PropertyEntry *pent;
	const GF_PropertyEntry *pent_val=NULL;
	*needs_resolve = GF_FALSE;
	*prop_not_found = GF_FALSE;

	if (frag_name[0] == src_pid->filter->session->sep_neg) {
		frag_name++;
		is_neg = GF_TRUE;
	}
	
	pent = gf_filter_pid_get_property_entry(src_pid, GF_PROP_PID_STREAM_TYPE);
	if (pent) {
		u32 matched=0;
		u32 type=0;
		u32 ptype = pent->prop.value.uint;

		if (!strnicmp(frag_name, "audio", 5)) {
			matched=5;
			type=GF_STREAM_AUDIO;
		} else if (!strnicmp(frag_name, "video", 5)) {
			matched=5;
			type=GF_STREAM_VISUAL;
		} else if (!strnicmp(frag_name, "scene", 5)) {
			matched=5;
			type=GF_STREAM_SCENE;
		} else if (!strnicmp(frag_name, "font", 4)) {
			matched=4;
			type=GF_STREAM_FONT;
		} else if (!strnicmp(frag_name, "text", 4)) {
			matched=4;
			type=GF_STREAM_TEXT;
		} else {
			
			
			if (strlen(frag_name)==4) {
				pent = gf_filter_pid_get_property_entry(src_pid, GF_PROP_PID_ISOM_HANDLER);
				if (pent && (pent->prop.value.uint == gf_4cc_parse(frag_name)) ) {
					matched=4;
					type = ptype;
				}
			}
		}
		
		if ((ptype == GF_STREAM_ENCRYPTED) && type && (type != GF_STREAM_ENCRYPTED) ) {
			pent = gf_filter_pid_get_property_entry(src_pid, GF_PROP_PID_ORIG_STREAM_TYPE);
			if (pent) ptype = pent->prop.value.uint;
		}

		if (matched && ( (!is_neg && (type != ptype)) || (is_neg && (type == ptype)) )
		) {
			
			
			if (ptype == GF_STREAM_FILE) {
				*prop_not_found = GF_TRUE;
				return GF_TRUE;
			}
			*pid_excluded = GF_TRUE;
			return GF_FALSE;
		}

		if (matched) {
			u32 idx=0;
			u32 k, count_pid;
			if (strlen(frag_name)==matched) return GF_TRUE;
			idx = atoi(frag_name+matched);
			count_pid = src_pid->filter->num_output_pids;
			for (k=0; k<count_pid; k++) {
				GF_FilterPid *p = gf_list_get(src_pid->filter->output_pids, k);
				pent = gf_filter_pid_get_property_entry(src_pid, GF_PROP_PID_STREAM_TYPE);
				if (pent && pent->prop.value.uint==type) {
					idx--;
					if (!idx     || ((count_pid==1) && !src_pid->filter->max_extra_pids)




					) {
						if (p==src_pid) return GF_TRUE;
						break;
					}
				}
			}
			*pid_excluded = GF_TRUE;
			return GF_FALSE;
		}
	}
	
	if (!strcmp(frag_name, "raw")) {
		pent = gf_filter_pid_get_property_entry(src_pid, GF_PROP_PID_CODECID);
		if (pent) {
			Bool is_eq = (pent->prop.value.uint==GF_CODECID_RAW) ? GF_TRUE : GF_FALSE;
			if (is_neg) is_eq = !is_eq;
			if (is_eq) return GF_TRUE;
			*pid_excluded = GF_TRUE;
			return GF_FALSE;
		}
		
		return GF_TRUE;
	}

	
	psep = strchr(frag_name, src_pid->filter->session->sep_name);
	if (!psep) {
		psep = strchr(frag_name, '-');
		if (psep) comp_type = 1;
		else {
			psep = strchr(frag_name, '+');
			if (psep) comp_type = 2;
		}
	}

	if (!psep) {
		*prop_not_found = GF_TRUE;
		GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("PID addressing %s not recognized, ignoring and assuming match\n", frag_name ));
		return GF_TRUE;
	}

	Bool is_equal = GF_FALSE;
	Bool use_not_equal = GF_FALSE;
	GF_PropertyValue prop_val;
	u32 p4cc = 0;
	char c=psep[0];
	psep[0] = 0;
	pent=NULL;

	
	if (!strcmp(frag_name, "TAG") || !strcmp(frag_name, "ITAG")) {
		psep[0] = c;
		if (src_pid->filter->tag) {
			Bool is_eq;
			
			if ( (psep[0]==src_pid->filter->session->sep_name) && (psep[1]==src_pid->filter->session->sep_neg) ) {
				psep++;
				use_not_equal = GF_TRUE;
			}

			is_eq = !strcmp(psep+1, src_pid->filter->tag);
			if (use_not_equal) is_eq = !is_eq;
			if (is_eq) return GF_TRUE;
			*pid_excluded = GF_TRUE;
			return GF_FALSE;
		}
		
		return GF_TRUE;
	}


	
	p4cc = gf_props_get_id(frag_name);
	if (!p4cc && !strcmp(frag_name, "PID") )
		p4cc = GF_PROP_PID_ID;

	if (!p4cc && (strlen(frag_name)==4))
		p4cc = GF_4CC(frag_name[0], frag_name[1], frag_name[2], frag_name[3]);

	if (p4cc) pent = gf_filter_pid_get_property_entry(src_pid, p4cc);
	
	if (!pent) {
		pent = gf_filter_pid_get_property_entry_str(src_pid, frag_name);
	}

	psep[0] = c;

	
	if (!pent) {
		*prop_not_found = GF_TRUE;
		return GF_TRUE;
	}
	
	if ( (psep[0]==src_pid->filter->session->sep_name) && ((psep[1]=='*') || (psep[1]=='\0') ) ) {
		*needs_resolve = GF_TRUE;
		gf_props_dump_val(&pent->prop, prop_dump_buffer, GF_PROP_DUMP_DATA_NONE, NULL);
		return GF_FALSE;
	}

	
	if ( (psep[0]==src_pid->filter->session->sep_name) && (psep[1]==src_pid->filter->session->sep_neg) ) {
		psep++;
		use_not_equal = GF_TRUE;
	}

	
	if (pent->p4cc==GF_PROP_PID_CODECID) {
		prop_val.type = GF_PROP_UINT;
		prop_val.value.uint = gf_codecid_parse(psep+1);
	}
	
	else if (pent->p4cc==GF_PROP_PID_STREAM_TYPE) {
		prop_val.type = GF_PROP_UINT;
		prop_val.value.uint = gf_stream_type_by_name(psep+1);
	} else {
		u32 val_is_prop = gf_props_get_id(psep+1);
		if (val_is_prop) {
			pent_val = gf_filter_pid_get_property_entry(src_pid, val_is_prop);
			if (pent_val) {
				prop_val = pent_val->prop;
			} else {
				*pid_excluded = GF_TRUE;
				return GF_FALSE;
			}
		} else {
			prop_val = gf_props_parse_value(pent->prop.type, frag_name, psep+1, NULL, src_pid->filter->session->sep_list);
		}
	}
	if (!comp_type) {
		is_equal = gf_props_equal(&pent->prop, &prop_val);
		if (use_not_equal) is_equal = !is_equal;
	} else {
		switch (prop_val.type) {
		case GF_PROP_SINT:
			if (pent->prop.value.sint<prop_val.value.sint) is_equal = GF_TRUE;
			if (comp_type==2) is_equal = !is_equal;
			break;
		case GF_PROP_UINT:
		case GF_PROP_4CC:
			if (pent->prop.value.uint<prop_val.value.uint) is_equal = GF_TRUE;
			if (comp_type==2) is_equal = !is_equal;
			break;
		case GF_PROP_LSINT:
			if (pent->prop.value.longsint<prop_val.value.longsint) is_equal = GF_TRUE;
			if (comp_type==2) is_equal = !is_equal;
			break;
		case GF_PROP_LUINT:
			if (pent->prop.value.longuint<prop_val.value.longuint) is_equal = GF_TRUE;
			if (comp_type==2) is_equal = !is_equal;
			break;
		case GF_PROP_FLOAT:
			if (pent->prop.value.fnumber<prop_val.value.fnumber) is_equal = GF_TRUE;
			if (comp_type==2) is_equal = !is_equal;
			break;
		case GF_PROP_DOUBLE:
			if (pent->prop.value.number<prop_val.value.number) is_equal = GF_TRUE;
			if (comp_type==2) is_equal = !is_equal;
			break;
		case GF_PROP_FRACTION:
			if (pent->prop.value.frac.num * prop_val.value.frac.den < pent->prop.value.frac.den * prop_val.value.frac.num) is_equal = GF_TRUE;
			if (comp_type == 2) is_equal = !is_equal;
			break;
		case GF_PROP_FRACTION64:
			if (pent->prop.value.lfrac.num * prop_val.value.lfrac.den < pent->prop.value.lfrac.den * prop_val.value.lfrac.num) is_equal = GF_TRUE;
			if (comp_type == 2) is_equal = !is_equal;
			break;
		default:
			GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("PID addressing uses \'%s\' comparison on property %s which is not a number, defaulting to equal=true\n", (comp_type==1) ? "less than" : "more than", gf_props_4cc_get_name(p4cc) ));
			is_equal = GF_TRUE;
			break;
		}
	}
	if (!pent_val)
		gf_props_reset_single(&prop_val);

	if (!is_equal) *pid_excluded = GF_TRUE;

	return is_equal;
}

static Bool filter_source_id_match(GF_FilterPid *src_pid, const char *id, GF_Filter *dst_filter, Bool *pid_excluded, Bool *needs_clone)
{
	const char *source_ids;
	char *resolved_source_ids = NULL;
	Bool result = GF_FALSE;
	Bool first_pass = GF_TRUE;
	Bool has_default_match;
	Bool is_pid_excluded;
	*pid_excluded = GF_FALSE;
	if (!dst_filter->source_ids)
		return GF_TRUE;
	if (!id)
		return GF_FALSE;

sourceid_reassign:
	source_ids = resolved_source_ids ? resolved_source_ids : dst_filter->source_ids;
	if (!first_pass) {
		assert(dst_filter->dynamic_source_ids);
		source_ids = dst_filter->dynamic_source_ids;
	}
	has_default_match = GF_FALSE;
	is_pid_excluded = GF_FALSE;

	while (source_ids) {
		Bool all_matched = GF_TRUE;
		Bool all_frags_not_found = GF_TRUE;
		u32 len, sublen;
		Bool last=GF_FALSE;
		char *frag_name, *frag_clone;
		char *sep;
		Bool use_neg = GF_FALSE;
		if (source_ids[0] == src_pid->filter->session->sep_neg) {
			source_ids++;
			use_neg = GF_TRUE;
		}

		sep = strchr(source_ids, src_pid->filter->session->sep_list);
		if (sep) {
			len = (u32) (sep - source_ids);
		} else {
			len = (u32) strlen(source_ids);
			last=GF_TRUE;
		}

		frag_name = strchr(source_ids, src_pid->filter->session->sep_frag);
		if (frag_name > source_ids + len) frag_name = NULL;
		sublen = frag_name ? (u32) (frag_name - source_ids) : len;
		
		if (frag_name) frag_name++;

		
		if (source_ids[0]=='*') { }
		
		else {
			Bool res = strncmp(id, source_ids, sublen) ? GF_FALSE : GF_TRUE;
			if (use_neg) res = !res;
			if (!res) {
				source_ids += len+1;
				if (last) break;
				continue;
			}
		}
		
		if (!frag_name || !strcmp(src_pid->name, frag_name)) {
			result = GF_TRUE;
			break;
		}
		frag_clone = NULL;
		if (!last) {
			frag_clone = gf_strdup(frag_name);
			char *nsep = strchr(frag_clone, src_pid->filter->session->sep_list);
			assert(nsep);
			nsep[0] = 0;
			frag_name = frag_clone;
		}

		
		while (frag_name && all_matched) {
			char prop_dump_buffer[GF_PROP_DUMP_ARG_SIZE];
			Bool needs_resolve = GF_FALSE;
			Bool prop_not_found = GF_FALSE;
			Bool local_pid_excluded = GF_FALSE;
			char *next_frag = strchr(frag_name, src_pid->filter->session->sep_frag);
			if (next_frag) next_frag[0] = 0;

			if (! filter_pid_check_fragment(src_pid, frag_name, &local_pid_excluded, &needs_resolve, &prop_not_found, prop_dump_buffer)) {
				if (needs_resolve) {
					if (first_pass) {
						char *sid = resolved_source_ids ? resolved_source_ids : dst_filter->source_ids;
						char *frag_sep = strchr(frag_name, dst_filter->session->sep_name);
						assert(frag_sep);
						if (next_frag) next_frag[0] = src_pid->filter->session->sep_frag;

						char *new_source_ids = gf_malloc(sizeof(char) * (strlen(sid) + strlen(prop_dump_buffer)+1));
						u32 clen = (u32) (1+frag_sep - sid);
						strncpy(new_source_ids, sid, clen);
						new_source_ids[clen]=0;
						strcat(new_source_ids, prop_dump_buffer);
						if (next_frag) strcat(new_source_ids, next_frag);

						if (resolved_source_ids) gf_free(resolved_source_ids);
						resolved_source_ids = new_source_ids;
						if (frag_clone) gf_free(frag_clone);
						goto sourceid_reassign;
					}
				}
				else {
					all_matched = GF_FALSE;
					
					if (local_pid_excluded)
						is_pid_excluded = GF_TRUE;
				}
			} else {
				
				if (!prop_not_found)
					all_frags_not_found = GF_FALSE;
			}

			if (!next_frag) break;

			next_frag[0] = src_pid->filter->session->sep_frag;
			frag_name = next_frag+1;
		}
		if (frag_clone) gf_free(frag_clone);
		if (all_matched) {
			
			if (!all_frags_not_found) {
				result = GF_TRUE;
				break;
			}
			
			has_default_match = GF_TRUE;
		}
		*needs_clone = GF_FALSE;
		if (!sep) break;
		source_ids = sep+1;
	}

	if (!result) {
		
		if (has_default_match && !is_pid_excluded)
			result = GF_TRUE;
	}

	if (!result) {
		if (resolved_source_ids) gf_free(resolved_source_ids);
		if (dst_filter->dynamic_source_ids && first_pass) {
			first_pass = GF_FALSE;
			goto sourceid_reassign;
		}
		*pid_excluded = is_pid_excluded;
		return GF_FALSE;
	}
	if (resolved_source_ids) {
		if (!dst_filter->dynamic_source_ids) {
			dst_filter->dynamic_source_ids = dst_filter->source_ids;
			dst_filter->source_ids = resolved_source_ids;
		} else {
			gf_free(dst_filter->source_ids);
			dst_filter->source_ids = resolved_source_ids;
		}
	}
	if (!first_pass) {
		*needs_clone = GF_TRUE;
	}
	return GF_TRUE;
}

GF_EXPORT Bool gf_filter_in_parent_chain(GF_Filter *parent, GF_Filter *filter)
{
	u32 i;
	if (parent == filter) return GF_TRUE;

	
	
	gf_mx_p(parent->tasks_mx);
	if (!parent->num_input_pids) {
		gf_mx_v(parent->tasks_mx);
		return GF_FALSE;
	}
	
	if (parent->single_source) {
		Bool res = gf_filter_in_parent_chain(parent->single_source, filter);
		gf_mx_v(parent->tasks_mx);
		return res;
	}
	for (i=0; i<parent->num_input_pids; i++) {
		GF_FilterPidInst *pidi = gf_list_get(parent->input_pids, i);
		if (gf_filter_in_parent_chain(pidi->pid->filter, filter)) {
			gf_mx_v(parent->tasks_mx);
			return GF_TRUE;
		}
	}
	for (i=0; i<gf_list_count(parent->temp_input_pids); i++) {
		GF_FilterPid *a_src_pid = gf_list_get(parent->temp_input_pids, i);
		if (gf_filter_in_parent_chain(a_src_pid->filter, filter)) {
			gf_mx_v(parent->tasks_mx);
			return GF_TRUE;
		}
	}
	gf_mx_v(parent->tasks_mx);
	return GF_FALSE;
}


static Bool cap_code_match(u32 c1, u32 c2)
{
	if (c1==c2) return GF_TRUE;
	
	if ((c1==GF_PROP_PID_FILE_EXT) && (c2==GF_PROP_PID_MIME)) return GF_TRUE;
	if ((c1==GF_PROP_PID_MIME) && (c2==GF_PROP_PID_FILE_EXT)) return GF_TRUE;
	return GF_FALSE;
}


Bool gf_filter_pid_caps_match(GF_FilterPid *src_pid_or_ipid, const GF_FilterRegister *freg, GF_Filter *filter_inst, u8 *priority, u32 *dst_bundle_idx, GF_Filter *dst_filter, s32 for_bundle_idx)
{
	u32 i=0;
	u32 cur_bundle_start = 0;
	u32 cap_bundle_idx = 0;
	u32 nb_subcaps=0;
	Bool skip_explicit_load = GF_FALSE;
	Bool all_caps_matched = GF_TRUE;
	Bool mime_matched = GF_FALSE;
	Bool has_file_ext_cap = GF_FALSE;
	Bool ext_not_trusted;
	GF_FilterPid *src_pid = src_pid_or_ipid->pid;
	const GF_FilterCapability *in_caps;
	u32 nb_in_caps;

	if (!freg) {
		assert(dst_filter);
		freg = dst_filter->freg;
		skip_explicit_load = GF_TRUE;
	}

	in_caps = freg->caps;
	nb_in_caps = freg->nb_caps;
	if (filter_inst && (filter_inst->freg==freg)) {
		skip_explicit_load = GF_TRUE;
		if (filter_inst->forced_caps) {
			in_caps = filter_inst->forced_caps;
			nb_in_caps = filter_inst->nb_forced_caps;
		}
	}
	ext_not_trusted = src_pid->ext_not_trusted;
	if (ext_not_trusted) {
		Bool has_mime_cap = GF_FALSE;

		for (i=0; i<nb_in_caps; i++) {
			const GF_FilterCapability *cap = &in_caps[i];
			if (! (cap->flags & GF_CAPFLAG_INPUT) ) continue;
			if (cap->code == GF_PROP_PID_MIME) {
				has_mime_cap = GF_TRUE;
				break;
			}
		}
		if (!has_mime_cap) ext_not_trusted = GF_FALSE;
	}

	if (filter_inst && filter_inst->encoder_stream_type) {
		const GF_PropertyValue *pid_st = gf_filter_pid_get_property_first(src_pid_or_ipid, GF_PROP_PID_STREAM_TYPE);
		if (pid_st && (pid_st->value.uint != filter_inst->encoder_stream_type))
			return GF_FALSE;
	}

	if (priority)
		(*priority) = freg->priority;

	if (dst_bundle_idx)
		(*dst_bundle_idx) = 0;

	
	if (!in_caps)
		return GF_TRUE;

	
	for (i=0; i<nb_in_caps; i++) {
		const GF_PropertyValue *pid_cap=NULL;
		const GF_FilterCapability *cap = &in_caps[i];

		
		if (i && !(cap->flags & GF_CAPFLAG_IN_BUNDLE) ) {
			if (has_file_ext_cap && ext_not_trusted && !mime_matched)
				all_caps_matched = GF_FALSE;

			if (all_caps_matched) {
				if (dst_bundle_idx)
					(*dst_bundle_idx) = cap_bundle_idx;
				return GF_TRUE;
			}
			all_caps_matched = GF_TRUE;
			mime_matched = GF_FALSE;
			has_file_ext_cap = GF_FALSE;
			nb_subcaps=0;
			cur_bundle_start = i;
			cap_bundle_idx++;
			if ((for_bundle_idx>=0) && (cap_bundle_idx > (u32) for_bundle_idx)) {
				break;
			}
			continue;
		}
		if ((for_bundle_idx>=0) && (cap_bundle_idx < (u32) for_bundle_idx)) {
			all_caps_matched = 0;
			continue;
		}

		
		if (! (cap->flags & GF_CAPFLAG_INPUT) ) {
			if (!skip_explicit_load && (cap->flags & GF_CAPFLAG_LOADED_FILTER) ) {
				all_caps_matched = 0;
			}
			continue;
		}

		nb_subcaps++;
		
		if (!all_caps_matched) continue;

		if (cap->code) {
			pid_cap = gf_filter_pid_get_property_first(src_pid_or_ipid, cap->code);

			
			
			if (pid_cap && (cap->code==GF_PROP_PID_FILE_EXT) ) {
				u32 j;
				for (j=0; j<src_pid->filter->freg->nb_caps; j++) {
					const GF_FilterCapability *out_cap = &src_pid->filter->freg->caps[j];
					if (!(out_cap->flags & GF_CAPFLAG_OUTPUT)) continue;
					if (out_cap->code != GF_PROP_PID_FILE_EXT) continue;
					if (! gf_props_equal(pid_cap, &out_cap->val)) continue;
					pid_cap = &out_cap->val;
					break;
				}
			}
			
			if (!pid_cap) {
				if (cap->code==GF_PROP_PID_FILE_EXT)
					pid_cap = gf_filter_pid_get_property_first(src_pid_or_ipid, GF_PROP_PID_MIME);
				else if (cap->code==GF_PROP_PID_MIME)
					pid_cap = gf_filter_pid_get_property_first(src_pid_or_ipid, GF_PROP_PID_FILE_EXT);
			}
		}

		
		if (!pid_cap && cap->name) pid_cap = gf_filter_pid_get_property_str_first(src_pid_or_ipid, cap->name);

		if (ext_not_trusted && (cap->code==GF_PROP_PID_FILE_EXT)) {
			has_file_ext_cap = GF_TRUE;
			continue;
		}

		
		if (cap->flags & GF_CAPFLAG_OPTIONAL) {
			if (pid_cap && priority && cap->priority && ((*priority) < cap->priority)) {
				(*priority) = cap->priority;
			}
			continue;
		}


		
		if (pid_cap) {
			u32 j;
			Bool prop_excluded = GF_FALSE;
			Bool prop_equal = GF_FALSE;

			
			for (j=0; j<nb_in_caps; j++) {
				const GF_FilterCapability *a_cap = &in_caps[j];

				if ((j>cur_bundle_start) && ! (a_cap->flags & GF_CAPFLAG_IN_BUNDLE) ) {
					break;
				}
				
				if (! (a_cap->flags & GF_CAPFLAG_INPUT) ) continue;
				
				if (! (a_cap->flags & GF_CAPFLAG_STATIC)) {
					if (j<cur_bundle_start)
						continue;
				}

				if (cap->code) {
					if (!cap_code_match(cap->code, a_cap->code) )
						continue;
				} else if (!cap->name || !a_cap->name || strcmp(cap->name, a_cap->name)) {
					continue;
				}
				if (!skip_explicit_load && (a_cap->flags & GF_CAPFLAG_LOADED_FILTER) ) {
					if (!dst_filter || (dst_filter != src_pid->filter->dst_filter)) {
						prop_equal = GF_FALSE;
						break;
					}
					if (dst_filter->freg != freg) {
						prop_equal = GF_FALSE;
						break;
					}
				}

				if (!prop_equal) {
					prop_equal = gf_props_equal(pid_cap, &a_cap->val);
					
					if (a_cap->flags & GF_CAPFLAG_EXCLUDED) {
						if (prop_equal) {
							prop_equal = GF_FALSE;
							prop_excluded = GF_FALSE;
							break;
						}
						prop_excluded = GF_TRUE;
					}
					if (prop_equal) {
						if (priority && a_cap->priority && ((*priority) < a_cap->priority)) {
							(*priority) = a_cap->priority;
						}
						break;
					}
				}
			}
			if (!prop_equal && !prop_excluded) {
				all_caps_matched=GF_FALSE;
			}
			if (ext_not_trusted && prop_equal && (cap->code==GF_PROP_PID_MIME))
				mime_matched = GF_TRUE;
		}
		else if (! (cap->flags & (GF_CAPFLAG_EXCLUDED | GF_CAPFLAG_OPTIONAL) ) ) {
			all_caps_matched=GF_FALSE;
		}
	}

	if (has_file_ext_cap && ext_not_trusted && !mime_matched)
		all_caps_matched = GF_FALSE;

	if (nb_subcaps && all_caps_matched) {
		if (dst_bundle_idx)
			(*dst_bundle_idx) = cap_bundle_idx;
		return GF_TRUE;
	}

	return GF_FALSE;
}

u32 gf_filter_caps_bundle_count(const GF_FilterCapability *caps, u32 nb_caps)
{
	u32 i, nb_bundles = 0, num_in_bundle=0;
	for (i=0; i<nb_caps; i++) {
		const GF_FilterCapability *cap = &caps[i];
		if (! (cap->flags & GF_CAPFLAG_IN_BUNDLE)) {
			if (num_in_bundle) nb_bundles++;
			num_in_bundle=0;
			continue;
		}
		num_in_bundle++;
	}
	if (num_in_bundle) nb_bundles++;
	return nb_bundles;
}

static Bool gf_filter_has_in_out_caps(const GF_FilterCapability *caps, u32 nb_caps, Bool check_in)
{
	u32 i;
	
	for (i=0; i<nb_caps; i++) {
		const GF_FilterCapability *a_cap = &caps[i];
		if (check_in) {
			if (a_cap->flags & GF_CAPFLAG_INPUT) {
				return GF_TRUE;
			}
		} else {
			if (a_cap->flags & GF_CAPFLAG_OUTPUT) {
				return GF_TRUE;
			}
		}
	}
	return GF_FALSE;

}
Bool gf_filter_has_out_caps(const GF_FilterCapability *caps, u32 nb_caps)
{
	return gf_filter_has_in_out_caps(caps, nb_caps, GF_FALSE);
}
Bool gf_filter_has_in_caps(const GF_FilterCapability *caps, u32 nb_caps)
{
	return gf_filter_has_in_out_caps(caps, nb_caps, GF_TRUE);
}

u32 gf_filter_caps_to_caps_match(const GF_FilterRegister *src, u32 src_bundle_idx, const GF_FilterRegister *dst_reg, GF_Filter *dst_filter, u32 *dst_bundle_idx, u32 for_dst_bundle, u32 *loaded_filter_flags, GF_CapsBundleStore *capstore)
{
	u32 i=0;
	s32 first_static_cap=-1;
	u32 cur_bundle_start = 0;
	u32 cur_bundle_idx = 0;
	u32 nb_matched=0;
	
	u32 nb_in_bundles=0;
	u32 bundle_score = 0;
	u32 *bundles_in_ok = NULL;
	u32 *bundles_cap_found = NULL;
	u32 *bundles_in_scores = NULL;
	
	Bool all_caps_matched = GF_TRUE;
	const GF_FilterCapability *dst_caps = dst_reg->caps;
	u32 nb_dst_caps = dst_reg->nb_caps;

	if (dst_filter && dst_filter->freg==dst_reg && dst_filter->forced_caps) {
		dst_caps = dst_filter->forced_caps;
		nb_dst_caps = dst_filter->nb_forced_caps;
	}

	
	if (! gf_filter_has_out_caps(src->caps, src->nb_caps)) {
		GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter %s has no output caps, cannot match filter %s inputs\n", src->name, dst_reg->name));
		return 0;
	}

	
	nb_in_bundles = gf_filter_caps_bundle_count(dst_caps, nb_dst_caps);
	if (!nb_in_bundles) {
		if (dst_reg->configure_pid) {
			GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter %s has no caps but pid configure possible, assuming possible connection\n", dst_reg->name));
			return 1;
		}
		GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter %s has no caps and no pid configure, no possible connection\n", dst_reg->name));
		return 0;
	}
	if (capstore->nb_allocs < nb_in_bundles) {
		capstore->nb_allocs = nb_in_bundles;
		capstore->bundles_in_ok = gf_realloc(capstore->bundles_in_ok, sizeof(u32) * nb_in_bundles);
		capstore->bundles_cap_found = gf_realloc(capstore->bundles_cap_found, sizeof(u32) * nb_in_bundles);
		capstore->bundles_in_scores = gf_realloc(capstore->bundles_in_scores,  sizeof(u32) * nb_in_bundles);
	}
	bundles_in_ok =	capstore->bundles_in_ok;
	bundles_cap_found = capstore->bundles_cap_found;
	bundles_in_scores = capstore->bundles_in_scores;

	for (i=0; i<nb_in_bundles; i++) {
		bundles_in_ok[i] = 1;
		bundles_cap_found[i] = 0;
		bundles_in_scores[i] = 0;
	}

	
	for (i=0; i<src->nb_caps; i++) {
		u32 j, k;
		Bool already_tested = GF_FALSE;
		const GF_FilterCapability *out_cap = &src->caps[i];

		if (i<cur_bundle_start) {
			if (!(out_cap->flags & GF_CAPFLAG_STATIC))
				continue;
		}

		if (!(out_cap->flags & GF_CAPFLAG_IN_BUNDLE) ) {
			all_caps_matched = GF_TRUE;
			cur_bundle_start = i+1;
			cur_bundle_idx++;
			if (src_bundle_idx < cur_bundle_idx)
				break;

			if (first_static_cap>=0)
				i = (u32) (first_static_cap-1);
			continue;
		}

		
		if ((src_bundle_idx != cur_bundle_idx) && ! (out_cap->flags & GF_CAPFLAG_STATIC) ) {
			continue;
		}

		
		if (!(out_cap->flags & GF_CAPFLAG_OUTPUT) ) continue;

		if ((first_static_cap==-1) && (out_cap->flags & GF_CAPFLAG_STATIC)) {
			first_static_cap = i;
		}


		
		if (!all_caps_matched) continue;

		
		for (k=cur_bundle_start; k<i; k++) {
			const GF_FilterCapability *an_out_cap = &src->caps[k];
			if (! (an_out_cap->flags & GF_CAPFLAG_IN_BUNDLE) ) {
				break;
			}
			if (! (an_out_cap->flags & GF_CAPFLAG_OUTPUT) ) {
				continue;
			}
			if (out_cap->code && (out_cap->code == an_out_cap->code) ) {
				already_tested = GF_TRUE;
				break;
			}
			if (out_cap->name && an_out_cap->name && !strcmp(out_cap->name, an_out_cap->name)) {
				already_tested = GF_TRUE;
				break;
			}
		}
		if (already_tested) {
			continue;
		}
		

		
		for (k=0; k<nb_in_bundles; k++) {
			bundles_cap_found[k] = 0;
		}

		
		if (first_static_cap>=0)
			k = first_static_cap-1;
		else k = cur_bundle_start;

		for (; k<src->nb_caps; k++) {
			u32 cur_dst_bundle=0;
			Bool static_matched = GF_FALSE;
			u32 nb_caps_tested = 0;
			u32 cap_loaded_filter_only = 0;
			Bool matched=GF_FALSE;
			Bool exclude=GF_FALSE;
			Bool prop_found=GF_FALSE;
			const GF_FilterCapability *an_out_cap = &src->caps[k];

			if (k<cur_bundle_start) {
				if (!(an_out_cap->flags & GF_CAPFLAG_STATIC))
					continue;
			}
			if (! (an_out_cap->flags & GF_CAPFLAG_IN_BUNDLE) ) {
				break;
			}
			if (! (an_out_cap->flags & GF_CAPFLAG_OUTPUT) ) {
				continue;
			}
			if (out_cap->code && !cap_code_match(out_cap->code, an_out_cap->code) )
				continue;

			if (out_cap->name && (!an_out_cap->name || strcmp(out_cap->name, an_out_cap->name)))
				continue;

			
			if ((src_bundle_idx != cur_bundle_idx) && ! (an_out_cap->flags & GF_CAPFLAG_STATIC) ) {
				continue;
			}

			nb_matched = 0;
			
			for (j=0; j<nb_dst_caps; j++) {
				Bool prop_equal;
				const GF_FilterCapability *in_cap = &dst_caps[j];

				if (! (in_cap->flags & GF_CAPFLAG_IN_BUNDLE)) {
					if (((cur_dst_bundle >= for_dst_bundle) || (in_cap->flags & GF_CAPFLAG_STATIC))) {
						if (!matched && !nb_caps_tested && (out_cap->flags & GF_CAPFLAG_EXCLUDED)) {
							matched = GF_TRUE;
						}
					}

					
					if (!matched && prop_found) matched = GF_TRUE;

					
					if (matched) {
						if (!bundles_cap_found[cur_dst_bundle])
							bundles_cap_found[cur_dst_bundle] = cap_loaded_filter_only ? 2 : 1;

						nb_matched++;
					}

					matched = static_matched ? GF_TRUE : GF_FALSE;
					if (exclude) {
						bundles_cap_found[cur_dst_bundle] = 0;
						exclude = GF_FALSE;
					}
					prop_found = GF_FALSE;
					nb_caps_tested = 0;
					cur_dst_bundle++;
					if (cur_dst_bundle > for_dst_bundle)
						break;

					continue;
				}
				
				if (!(in_cap->flags & GF_CAPFLAG_INPUT) )
					continue;

				
				if (in_cap->flags & GF_CAPFLAG_OPTIONAL)
					continue;

				if ((cur_dst_bundle < for_dst_bundle) && !(in_cap->flags & GF_CAPFLAG_STATIC))
					continue;

				
				if (exclude) continue;
				
				if (matched) continue;

				if (out_cap->code && !cap_code_match(out_cap->code, in_cap->code) )
					continue;

				if (out_cap->name && (!in_cap->name || strcmp(out_cap->name, in_cap->name)))
					continue;

				nb_caps_tested++;
				
				prop_equal = gf_props_equal(&in_cap->val, &an_out_cap->val);
				if ((in_cap->flags & GF_CAPFLAG_EXCLUDED) && !(an_out_cap->flags & GF_CAPFLAG_EXCLUDED) ) {
					
					
					
					
					if (an_out_cap->flags & (GF_CAPFLAG_OPTIONAL|GF_CAPFLAG_LOADED_FILTER))
						prop_equal = GF_FALSE;

					
					if (prop_equal) {
						matched = GF_FALSE;
						exclude = GF_TRUE;
						prop_found = GF_FALSE;
					} else {
						
						
						prop_found = GF_TRUE;
					}
				} else if (!(in_cap->flags & GF_CAPFLAG_EXCLUDED) && (an_out_cap->flags & GF_CAPFLAG_EXCLUDED) ) {
					
					if (prop_equal) {
						matched = GF_FALSE;
						exclude = GF_TRUE;
						prop_found = GF_FALSE;
					} else {
						
						
						prop_found = GF_TRUE;
					}
				} else if (prop_equal) {
					matched = GF_TRUE;


				} else if ((in_cap->flags & GF_CAPFLAG_EXCLUDED) && (an_out_cap->flags & GF_CAPFLAG_EXCLUDED) ) {
					
					prop_found = GF_TRUE;
				}

				if (prop_found && (in_cap->flags & GF_CAPFLAG_LOADED_FILTER))
					cap_loaded_filter_only = 1;
			}
			if (nb_caps_tested) {
				
				if (!matched && prop_found) matched = GF_TRUE;
				
				if (matched) {
					if (!bundles_cap_found[cur_dst_bundle])
						bundles_cap_found[cur_dst_bundle] = cap_loaded_filter_only ? 2 : 1;

					nb_matched++;
				}
				
				else if (exclude) {
					bundles_cap_found[cur_dst_bundle] = 0;
				}
			} else if (!nb_dst_caps) {
				if (!bundles_cap_found[cur_dst_bundle])
					bundles_cap_found[cur_dst_bundle] = cap_loaded_filter_only ? 2 : 1;

				nb_matched++;
			} else if (!nb_matched && !prop_found && (an_out_cap->flags & (GF_CAPFLAG_EXCLUDED|GF_CAPFLAG_OPTIONAL)) && (cur_dst_bundle<nb_in_bundles) ) {
				if (!bundles_cap_found[cur_dst_bundle])
					bundles_cap_found[cur_dst_bundle] = cap_loaded_filter_only ? 2 : 1;

				nb_matched++;
			}
		}
		
		nb_matched=0;
		for (k=0; k<nb_in_bundles; k++) {
			if (!bundles_cap_found[k])
				bundles_in_ok[k] = 0;
			else {
				nb_matched += 1;
				
				bundles_in_scores[k] ++;
				
				if (bundles_cap_found[k]==2)
				 	bundles_in_ok[k] |= 1<<1;
				
				if (out_cap->flags & GF_CAPFLAG_LOADED_FILTER)
					bundles_in_ok[k] |= 1<<2;
			}
		}

		
		if (!nb_matched && !(out_cap->flags & (GF_CAPFLAG_EXCLUDED|GF_CAPFLAG_OPTIONAL))) {
			all_caps_matched = GF_FALSE;
		}
	}

	
	bundle_score = 0;
	nb_matched = 0;

	for (i=0; i<nb_in_bundles; i++) {
		if (bundles_in_ok[i]) {
			nb_matched++;
			if (bundle_score < bundles_in_scores[i]) {
				*dst_bundle_idx = i;
				bundle_score = bundles_in_scores[i];
				if (loaded_filter_flags) {
					*loaded_filter_flags = (bundles_in_ok[i]>>1);
				}
			}
			if (for_dst_bundle==i) {
				*dst_bundle_idx = i;
				if (loaded_filter_flags) {
					*loaded_filter_flags = (bundles_in_ok[i]>>1);
				}
				return bundles_in_scores[i];
			}
		}
	}
	if (!bundle_score) {

	} else {

	}
	return bundle_score;
}

GF_EXPORT Bool gf_filter_pid_check_caps(GF_FilterPid *_pid)
{
	u8 priority;
	Bool res;
	GF_Filter *on_filter;
	if (PID_IS_OUTPUT(_pid)) return GF_FALSE;
	GF_FilterPidInst *pidi = (GF_FilterPidInst *)_pid;
	on_filter = pidi->alias_orig ? pidi->alias_orig : pidi->filter;
	pidi->pid->local_props = pidi->props;
	res = gf_filter_pid_caps_match(pidi->pid, NULL, on_filter, &priority, NULL, on_filter, -1);
	pidi->pid->local_props = NULL;
	return res;
}


static void concat_reg(GF_FilterSession *sess, char prefRegister[1001], const char *reg_key, const char *args)
{
	u32 len;
	char *forced_reg, *sep;
	if (!args) return;
	forced_reg = strstr(args, reg_key);
	if (!forced_reg) return;
	forced_reg += 6;
	sep = strchr(forced_reg, sess->sep_args);
	len = sep ? (u32) (sep-forced_reg) : (u32) strlen(forced_reg);
	if (len+2+strlen(prefRegister)>1000) {
		return;
	}
	if (prefRegister[0]) {
		char szSepChar[2];
		szSepChar[0] = sess->sep_args;
		szSepChar[1] = 0;
		strcat(prefRegister, szSepChar);
	}
	strncat(prefRegister, forced_reg, len);
}

static Bool gf_filter_out_caps_solved_by_connection(const GF_FilterRegister *freg, u32 bundle_idx)
{
	u32 i, k, cur_bundle_idx = 0;
    u32 nb_out_caps=0;
	for (i=0; i<freg->nb_caps; i++) {
		u32 nb_caps = 0;
        u32 cap_bundle_idx = 0;
		const GF_FilterCapability *cap = &freg->caps[i];
		if (!(cap->flags & GF_CAPFLAG_IN_BUNDLE)) {
			cur_bundle_idx++;
			if (cur_bundle_idx>bundle_idx) return GF_FALSE;
            continue;
		}
		if (!(cap->flags & GF_CAPFLAG_STATIC) && (bundle_idx>cur_bundle_idx)) continue;
		if (!(cap->flags & GF_CAPFLAG_OUTPUT)) continue;

		if (cap->flags & GF_CAPFLAG_OPTIONAL) continue;

		for (k=0; k<freg->nb_caps; k++) {
			const GF_FilterCapability *acap = &freg->caps[k];
            if (!(acap->flags & GF_CAPFLAG_IN_BUNDLE)) {
                cap_bundle_idx++;
                continue;
            }
			if (!(acap->flags & GF_CAPFLAG_OUTPUT)) continue;
			if (acap->flags & GF_CAPFLAG_OPTIONAL) continue;
			if (!(acap->flags & GF_CAPFLAG_STATIC) && (cap_bundle_idx!=bundle_idx) ) continue;

			if (cap->code && (acap->code==cap->code)) {
				nb_caps++;
			} else if (cap->name && acap->name && !strcmp(cap->name, acap->name)) {
				nb_caps++;
			}
			
			if (nb_caps>1)
				return GF_TRUE;
		}
        if (nb_caps && !(cap->flags & GF_CAPFLAG_EXCLUDED))
            nb_out_caps++;
	}
	if (!nb_out_caps)
		return GF_TRUE;
	return GF_FALSE;
}

static s32 gf_filter_reg_get_bundle_stream_type(const GF_FilterRegister *freg, u32 cap_idx, Bool for_output)
{
	u32 i, cur_bundle, stype=0, nb_stype=0;

	cur_bundle = 0;
	for (i=0; i<freg->nb_caps; i++) {
		u32 cap_stype=0;
		const GF_FilterCapability *cap = &freg->caps[i];
		if (!(cap->flags & GF_CAPFLAG_IN_BUNDLE)) {
			cur_bundle++;
			continue;
		}
		if (for_output) {
			if (!(cap->flags & GF_CAPFLAG_OUTPUT)) continue;
		} else {
			if (!(cap->flags & GF_CAPFLAG_INPUT)) continue;
		}
		if ((cur_bundle != cap_idx) && !(cap->flags & GF_CAPFLAG_STATIC) ) continue;
		
		if (cap->flags & GF_CAPFLAG_EXCLUDED) continue;

		if (cap->code == GF_PROP_PID_STREAM_TYPE)
			cap_stype = cap->val.value.uint;
		else if ((cap->code == GF_PROP_PID_MIME) || (cap->code == GF_PROP_PID_FILE_EXT) )
			cap_stype = GF_STREAM_FILE;

		if (!cap_stype) continue;

		if (stype != cap_stype) {
			stype = cap_stype;
			nb_stype++;
		}
	}
	if (nb_stype==1) return (s32) stype;
	if (nb_stype) return -1;
	return 0;
}


static u32 gf_filter_pid_enable_edges(GF_FilterSession *fsess, GF_FilterRegDesc *reg_desc, u32 src_cap_idx, const GF_FilterRegister *src_freg, u32 rlevel, s32 dst_stream_type, GF_FilterRegDesc *parent_desc, GF_FilterPid *pid, u32 pid_stream_type)
{
	u32 i=0;
	Bool enable_graph = GF_FALSE;
	Bool aborted_graph_too_deep = GF_FALSE;

	
	if (src_freg == reg_desc->freg) {
		return 1;
	}
	
	if (rlevel > fsess->max_resolve_chain_len) {
		return 2;
	}
	
	if (reg_desc->in_edges_enabling)
		return 0;

	
	if ((rlevel>1) && (dst_stream_type==GF_STREAM_FILE))
		return 0;

	reg_desc->in_edges_enabling = 1;

	for (i=0; i<reg_desc->nb_edges; i++) {
		u32 res;
		s32 source_stream_type;
		GF_FilterRegEdge *edge = &reg_desc->edges[i];
		
		if (edge->dst_cap_idx != src_cap_idx) continue;

		
		if (edge->status == EDGE_STATUS_DISABLED)
			continue;

		
		if (edge->loaded_filter_only && (edge->src_reg->freg != pid->filter->freg) ) {
			edge->status = EDGE_STATUS_DISABLED;
			edge->disabled_depth = rlevel+1;
			continue;
		}

		
		if (edge->status == EDGE_STATUS_ENABLED) {
			enable_graph = GF_TRUE;
			continue;
		}

		
		source_stream_type = edge->src_stream_type;

		if (pid->filter->freg == edge->src_reg->freg)
			source_stream_type = pid_stream_type;

		
		if (source_stream_type<0) {
			
			
			if ((dst_stream_type>0) && (dst_stream_type != GF_STREAM_FILE))
				source_stream_type = dst_stream_type;
		}
		
		if (!source_stream_type && dst_stream_type>0)
			source_stream_type = dst_stream_type;
		
		if ((source_stream_type==GF_STREAM_ENCRYPTED) && (dst_stream_type>0) && (dst_stream_type!=GF_STREAM_FILE))
			source_stream_type = dst_stream_type;
		
		if ((dst_stream_type==GF_STREAM_ENCRYPTED) && source_stream_type>0)
			dst_stream_type = source_stream_type;

		
		
		if ((dst_stream_type>0) && (source_stream_type>0) && (source_stream_type != GF_STREAM_FILE) && (dst_stream_type != GF_STREAM_FILE) && (source_stream_type != dst_stream_type)) {

			
			if (!(reg_desc->freg->flags & GF_FS_REG_EXPLICIT_ONLY) && (dst_stream_type==GF_STREAM_VISUAL)
				&& ((source_stream_type==GF_STREAM_TEXT) || (source_stream_type==GF_STREAM_SCENE) || (source_stream_type==GF_STREAM_OD) )
			) {

			} else {
				edge->status = EDGE_STATUS_DISABLED;
				edge->disabled_depth = rlevel+1;
				continue;
			}
		}

		res = gf_filter_pid_enable_edges(fsess, edge->src_reg, edge->src_cap_idx, src_freg, rlevel+1, source_stream_type, reg_desc, pid, pid_stream_type);
		
		if (res==1) {
			edge->status = EDGE_STATUS_ENABLED;
			enable_graph = GF_TRUE;
		}
		
		else if (res==2) {
			aborted_graph_too_deep = GF_TRUE;
		}
		
		else if (res==0) {
			edge->status = EDGE_STATUS_DISABLED;
			edge->disabled_depth = rlevel+1;
		}
	}
	reg_desc->in_edges_enabling = 0;
	
	if (enable_graph) return 1;
	
	if (aborted_graph_too_deep) return 2;
	
	return 0;
}

static void gf_filter_reg_build_graph_single(GF_FilterRegDesc *reg_desc, const GF_FilterRegister *freg, GF_FilterRegDesc *a_reg, Bool freg_has_output, u32 nb_dst_caps, GF_CapsBundleStore *capstore, GF_Filter *dst_filter)
{
	u32 nb_src_caps, k, l;
	u32 path_weight;

	
	nb_src_caps = gf_filter_caps_bundle_count(a_reg->freg->caps, a_reg->freg->nb_caps);
	for (k=0; k<nb_src_caps; k++) {
		for (l=0; l<nb_dst_caps; l++) {
			s32 bundle_idx;

			if (gf_filter_has_out_caps(a_reg->freg->caps, a_reg->freg->nb_caps)) {
				u32 loaded_filter_only_flags = 0;

				path_weight = gf_filter_caps_to_caps_match(a_reg->freg, k, (const GF_FilterRegister *) freg, dst_filter, &bundle_idx, l, &loaded_filter_only_flags, capstore);

				if (path_weight && (bundle_idx == l)) {
					GF_FilterRegEdge *edge;
					if (reg_desc->nb_edges==reg_desc->nb_alloc_edges) {
						reg_desc->nb_alloc_edges += 10;
						reg_desc->edges = gf_realloc(reg_desc->edges, sizeof(GF_FilterRegEdge) * reg_desc->nb_alloc_edges);
					}
					assert(path_weight<0xFF);
					assert(k<0xFFFF);
					assert(l<0xFFFF);
					edge = &reg_desc->edges[reg_desc->nb_edges];
					memset(edge, 0, sizeof(GF_FilterRegEdge));
					edge->src_reg = a_reg;
					edge->weight = (u8) path_weight;
					edge->src_cap_idx = (u16) k;
					edge->dst_cap_idx = (u16) l;

					
					if (loaded_filter_only_flags & EDGE_LOADED_SOURCE_ONLY)
						edge->loaded_filter_only |= EDGE_LOADED_DEST_ONLY;
					if (loaded_filter_only_flags & EDGE_LOADED_DEST_ONLY)
						edge->loaded_filter_only |= EDGE_LOADED_SOURCE_ONLY;
					edge->src_stream_type = gf_filter_reg_get_bundle_stream_type(edge->src_reg->freg, edge->src_cap_idx, GF_TRUE);
					reg_desc->nb_edges++;
				}
			}

			if ( freg_has_output ) {
				u32 loaded_filter_only_flags = 0;

				path_weight = gf_filter_caps_to_caps_match(freg, l, a_reg->freg, dst_filter, &bundle_idx, k, &loaded_filter_only_flags, capstore);

				if (path_weight && (bundle_idx == k)) {
					GF_FilterRegEdge *edge;
					if (a_reg->nb_edges==a_reg->nb_alloc_edges) {
						a_reg->nb_alloc_edges += 10;
						a_reg->edges = gf_realloc(a_reg->edges, sizeof(GF_FilterRegEdge) * a_reg->nb_alloc_edges);
					}
					edge = &a_reg->edges[a_reg->nb_edges];
					edge->src_reg = reg_desc;
					edge->weight = (u8) path_weight;
					edge->src_cap_idx = (u16) l;
					edge->dst_cap_idx = (u16) k;
					edge->priority = 0;
					edge->loaded_filter_only = loaded_filter_only_flags;
					edge->src_stream_type = gf_filter_reg_get_bundle_stream_type(edge->src_reg->freg, edge->src_cap_idx, GF_TRUE);
					a_reg->nb_edges++;
				}
			}
		}
	}
}

static GF_FilterRegDesc *gf_filter_reg_build_graph(GF_List *links, const GF_FilterRegister *freg, GF_CapsBundleStore *capstore, GF_FilterPid *src_pid, GF_Filter *dst_filter)
{
	u32 nb_dst_caps, nb_regs, i, nb_caps;
	Bool freg_has_output;

	GF_FilterRegDesc *reg_desc = NULL;
	const GF_FilterCapability *caps = freg->caps;
	nb_caps = freg->nb_caps;
	if (dst_filter && ((freg->flags & (GF_FS_REG_SCRIPT|GF_FS_REG_CUSTOM)) || (src_pid && dst_filter->forced_caps) ) ) {
		caps = dst_filter->forced_caps;
		nb_caps = dst_filter->nb_forced_caps;
	}

	freg_has_output = gf_filter_has_out_caps(caps, nb_caps);

	GF_SAFEALLOC(reg_desc, GF_FilterRegDesc);
	if (!reg_desc) return NULL;

	reg_desc->freg = freg;

	nb_dst_caps = gf_filter_caps_bundle_count(caps, nb_caps);


	
	if (src_pid || dst_filter) freg_has_output = GF_FALSE;

	
	nb_regs = gf_list_count(links);
	for (i=0; i<nb_regs; i++) {
		GF_FilterRegDesc *a_reg = gf_list_get(links, i);
		if (a_reg->freg == freg) continue;

		gf_filter_reg_build_graph_single(reg_desc, freg, a_reg, freg_has_output, nb_dst_caps, capstore, dst_filter);
	}

	if (!dst_filter && (freg->flags & GF_FS_REG_ALLOW_CYCLIC)) {
		gf_filter_reg_build_graph_single(reg_desc, freg, reg_desc, freg_has_output, nb_dst_caps, capstore, NULL);
	}
	return reg_desc;
}

void gf_filter_sess_build_graph(GF_FilterSession *fsess, const GF_FilterRegister *for_reg)
{
	u32 i, count;
	GF_CapsBundleStore capstore;
	memset(&capstore, 0, sizeof(GF_CapsBundleStore));

	if (!fsess->links) fsess->links = gf_list_new();

	if (for_reg) {
		GF_FilterRegDesc *freg_desc = gf_filter_reg_build_graph(fsess->links, for_reg, &capstore, NULL, NULL);
		if (!freg_desc) {
			GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Failed to build graph entry for filter %s\n", for_reg->name));
		} else {
			gf_list_add(fsess->links, freg_desc);
		}
	} else {

		u64 start_time = gf_sys_clock_high_res();

		count = gf_list_count(fsess->registry);
		for (i=0; i<count; i++) {
			const GF_FilterRegister *freg = gf_list_get(fsess->registry, i);
			GF_FilterRegDesc *freg_desc = gf_filter_reg_build_graph(fsess->links, freg, &capstore, NULL, NULL);
			if (!freg_desc) {
				GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Failed to build graph entry for filter %s\n", freg->name));
			} else {
				gf_list_add(fsess->links, freg_desc);
			}
		}
		GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Built filter graph in "LLU" us\n", gf_sys_clock_high_res() - start_time));

		if (fsess->flags & GF_FS_FLAG_PRINT_CONNECTIONS) {
			u32 j;
			count = gf_list_count(fsess->links);
			for (i=0; i<count; i++) {
				GF_FilterRegDesc *freg_desc = gf_list_get(fsess->links, i);
				GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter %s sources:", freg_desc->freg->name));
				for (j=0; j<freg_desc->nb_edges; j++ ) {
					GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, (" %s(%d,%d->%d)", freg_desc->edges[j].src_reg->freg->name, freg_desc->edges[j].weight, freg_desc->edges[j].src_cap_idx, freg_desc->edges[j].dst_cap_idx));
				}
				GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("\n"));
			}
		}
	}
	if (capstore.bundles_cap_found) gf_free(capstore.bundles_cap_found);
	if (capstore.bundles_in_ok) gf_free(capstore.bundles_in_ok);
	if (capstore.bundles_in_scores) gf_free(capstore.bundles_in_scores);
}

void gf_filter_sess_reset_graph(GF_FilterSession *fsess, const GF_FilterRegister *freg)
{
	gf_mx_p(fsess->links_mx);
	
	if (freg && fsess->filters) {
		s32 reg_idx=-1;
		u32 i, count = gf_list_count(fsess->links);
		for (i=0; i<count; i++) {
			u32 j;
			GF_FilterRegDesc *rdesc = gf_list_get(fsess->links, i);
			if (rdesc->freg == freg) {
				reg_idx = i;
				continue;
			}
			for (j=0; j<rdesc->nb_edges; j++) {
				if (rdesc->edges[j].src_reg->freg == freg) {
					if (rdesc->nb_edges > j + 1) {
						memmove(&rdesc->edges[j], &rdesc->edges[j+1], sizeof (GF_FilterRegEdge) * (rdesc->nb_edges - j - 1));
					}
					j--;
					rdesc->nb_edges--;
				}
			}
		}
		if (reg_idx>=0) {
			GF_FilterRegDesc *rdesc = gf_list_get(fsess->links, reg_idx);
			gf_list_rem(fsess->links, reg_idx);
			gf_free(rdesc->edges);
			gf_free(rdesc);
		}
	} else {
		while (gf_list_count(fsess->links)) {
			GF_FilterRegDesc *rdesc = gf_list_pop_back(fsess->links);
			gf_free(rdesc->edges);
			gf_free(rdesc);
		}
	}
	gf_mx_v(fsess->links_mx);
}


void dump_dijstra_edges(Bool is_before, GF_FilterRegDesc *reg_dst, GF_List *dijkstra_nodes)
{
	u32 i, count;
	if (! gf_log_tool_level_on(GF_LOG_FILTER, GF_LOG_DEBUG))
		return;

	GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Dijstra edges %s edge solving\n", is_before ? "before" : "after"));

	GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter %s sources: ", reg_dst->freg->name));
	for (i=0; i<reg_dst->nb_edges; i++) {
		GF_FilterRegEdge *edge = &reg_dst->edges[i];
		GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, (" %s(%d(%d),%d,%d->%d)", edge->src_reg->freg->name, edge->status, edge->disabled_depth, edge->weight, edge->src_cap_idx, edge->dst_cap_idx));
	}
	GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("\n"));

	count = gf_list_count(dijkstra_nodes);
	for (i=0; i<count; i++) {
		u32 j;
		GF_FilterRegDesc *rdesc = gf_list_get(dijkstra_nodes, i);
		GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter %s sources: ", rdesc->freg->name));
		for (j=0; j<rdesc->nb_edges; j++) {
			GF_FilterRegEdge *edge = &rdesc->edges[j];
			GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, (" %s(%d(%d),%d,%d->%d)", edge->src_reg->freg->name, edge->status, edge->disabled_depth, edge->weight, edge->src_cap_idx, edge->dst_cap_idx));
		}
		GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("\n"));
	}
}


static void gf_filter_pid_resolve_link_dijkstra(GF_FilterPid *pid, GF_Filter *dst, const char *prefRegister, Bool reconfigurable_only, GF_List *out_reg_chain)
{
	GF_FilterRegDesc *reg_dst, *result;
	GF_List *dijkstra_nodes;
	GF_FilterSession *fsess = pid->filter->session;
	
	u32 i, dijsktra_node_count, dijsktra_edge_count, count;
	GF_CapsBundleStore capstore;
	Bool first;
	Bool check_codec_id_raw = GF_FALSE;
	u32 path_weight, pid_stream_type, max_weight=0;
	u64 dijkstra_time_us, sort_time_us, start_time_us = gf_sys_clock_high_res();
	const GF_PropertyValue *p;
	if (!fsess->links || ! gf_list_count( fsess->links))
	 	gf_filter_sess_build_graph(fsess, NULL);

	dijkstra_nodes = gf_list_new();

	result = NULL;
	pid_stream_type = 0;
	p = gf_filter_pid_get_property(pid, GF_PROP_PID_STREAM_TYPE);
	if (p) pid_stream_type = p->value.uint;

	
	
	
	
	if (reconfigurable_only && pid->caps_negociate && (gf_list_count(pid->caps_negociate->properties)==1)

	) {
		const GF_PropertyValue *cid = gf_props_get_property(pid->caps_negociate, GF_PROP_PID_CODECID, NULL);
		
		if (cid && (cid->value.uint==GF_CODECID_RAW)) {
			check_codec_id_raw = cid->value.uint;
		}
	}

	
	count = gf_list_count(fsess->links);
	for (i=0; i<count; i++) {
		u32 j;
		Bool disable_filter = GF_FALSE;
		Bool reconf_only = reconfigurable_only;
		GF_FilterRegDesc *reg_desc = gf_list_get(fsess->links, i);
		const GF_FilterRegister *freg = reg_desc->freg;

		if (check_codec_id_raw) {
			Bool has_raw_out=GF_FALSE, has_non_raw_in=GF_FALSE;
			for (j=0; j<freg->nb_caps; j++) {
				if (!(freg->caps[j].flags & GF_CAPFLAG_IN_BUNDLE))
					continue;
				if (freg->caps[j].code!=GF_PROP_PID_CODECID) continue;

				if (freg->caps[j].val.value.uint == GF_CODECID_RAW) {
					if ((freg->caps[j].flags & GF_CAPFLAG_OUTPUT) && ! (freg->caps[j].flags & GF_CAPFLAG_EXCLUDED))
						has_raw_out = GF_TRUE;
					continue;
				}
				if ((freg->caps[j].flags & GF_CAPFLAG_INPUT) && ! (freg->caps[j].flags & GF_CAPFLAG_EXCLUDED))
					has_non_raw_in = GF_TRUE;
			}
			if (has_raw_out && has_non_raw_in)
				reconf_only = GF_FALSE;
		}
		
		reg_desc->destination = NULL;
		reg_desc->cap_idx = 0;
		reg_desc->in_edges_enabling = 0;
		
		reg_desc->dist = -1;
		reg_desc->priority = 0xFF;

		
		
		if (freg == pid->filter->freg)
			result = reg_desc;

		
		if (!freg->configure_pid && (freg!=pid->filter->freg)) {
			assert(freg != dst->freg);
			disable_filter = GF_TRUE;
		}
		
		else if ((freg->flags & (GF_FS_REG_EXPLICIT_ONLY|GF_FS_REG_SCRIPT|GF_FS_REG_CUSTOM)) && (freg != pid->filter->freg) && (freg != dst->freg) ) {
			assert(freg != dst->freg);
			disable_filter = GF_TRUE;
		}
		
		else if ((freg != dst->freg) && !gf_filter_has_out_caps(freg->caps, freg->nb_caps)) {
			disable_filter = GF_TRUE;
		}
		
		else if (reconf_only && !freg->reconfigure_output && (freg != dst->freg)) {
			assert(freg != dst->freg);
			disable_filter = GF_TRUE;
		}
		
		else if (gf_list_find(pid->filter->blacklisted, (void *) freg)>=0) {
			
			
			if (!reconfigurable_only) {
				assert(freg != pid->filter->freg);
			}
			disable_filter = GF_TRUE;
		}
		
		else if (pid->adapters_blacklist && (gf_list_find(pid->adapters_blacklist, (void *) freg)>=0)) {
			assert(freg != dst->freg);
			disable_filter = GF_TRUE;
		}

		
		for (j=0; j<reg_desc->nb_edges; j++) {
			GF_FilterRegEdge *edge = &reg_desc->edges[j];

			edge->disabled_depth = 0;
			if (disable_filter) {
				edge->status = EDGE_STATUS_DISABLED;
				continue;
			}
			edge->status = EDGE_STATUS_NONE;

			
			if (edge->src_reg->freg == pid->filter->freg) {
				u8 priority=0;
				u32 dst_bundle_idx;
				
				path_weight = gf_filter_pid_caps_match(pid, freg, NULL, &priority, &dst_bundle_idx, pid->filter->dst_filter, edge->dst_cap_idx);
				if (!path_weight) {
					edge->status = EDGE_STATUS_DISABLED;
					continue;
				}

				if (priority)
					path_weight *= priority;

			}

			
			if ((edge->loaded_filter_only & EDGE_LOADED_SOURCE_ONLY) && (edge->src_reg->freg != pid->filter->freg) ) {
				edge->status = EDGE_STATUS_DISABLED;
				continue;
			}

			if ((u32) edge->weight + 1 > max_weight)
				max_weight = (u32) edge->weight + 1;
		}
		
		if (disable_filter)
			continue;


		
		if (dst->freg == reg_desc->freg) {
			reg_desc->dist = 0;
			reg_desc->priority = 0;
		} else {
			gf_list_add(dijkstra_nodes, reg_desc);
		}
	}
	
	memset(&capstore, 0, sizeof(GF_CapsBundleStore));
	reg_dst = gf_filter_reg_build_graph(dijkstra_nodes, dst->freg, &capstore, pid, dst);
	reg_dst->dist = 0;
	reg_dst->priority = 0;
	reg_dst->in_edges_enabling = 0;

	
	for (i=0; i<reg_dst->nb_edges; i++) {
		GF_FilterRegEdge *edge = &reg_dst->edges[i];
		edge->status = EDGE_STATUS_NONE;

		
		if (edge->src_reg->freg == pid->filter->freg) {
			u8 priority=0;
			u32 dst_bundle_idx;
			path_weight = gf_filter_pid_caps_match(pid, dst->freg, dst, &priority, &dst_bundle_idx, pid->filter->dst_filter, -1);
			if (!path_weight) {
				edge->status = EDGE_STATUS_DISABLED;
				continue;
			}
			if (dst_bundle_idx != edge->dst_cap_idx) {
				edge->status = EDGE_STATUS_DISABLED;
				continue;
			}
		}
		
		if ( (edge->loaded_filter_only & EDGE_LOADED_SOURCE_ONLY) && (edge->src_reg->freg != pid->filter->freg) ) {
			edge->status = EDGE_STATUS_DISABLED;
			continue;
		}
		
		
		
		if ((dst->bundle_idx_at_resolution>=0)
			
			&& !dst->max_extra_pids && !(edge->loaded_filter_only & EDGE_LOADED_DEST_ONLY)
			&& (edge->dst_cap_idx !=dst->bundle_idx_at_resolution)
		) {
			edge->status = EDGE_STATUS_DISABLED;
			continue;
		}

		if ((u32) edge->weight + 1 > max_weight)
			max_weight = edge->weight + 1;
		
		edge->status = EDGE_STATUS_ENABLED;

		gf_filter_pid_enable_edges(fsess, edge->src_reg, edge->src_cap_idx, pid->filter->freg, 1, edge->src_stream_type, reg_dst, pid, pid_stream_type);
	}

	if (capstore.bundles_cap_found) gf_free(capstore.bundles_cap_found);
	if (capstore.bundles_in_ok) gf_free(capstore.bundles_in_ok);
	if (capstore.bundles_in_scores) gf_free(capstore.bundles_in_scores);


	if (fsess->flags & GF_FS_FLAG_PRINT_CONNECTIONS) {
		dump_dijstra_edges(GF_FALSE, reg_dst, dijkstra_nodes);
	}


	
	count = gf_list_count(dijkstra_nodes);
	for (i=0; i<count; i++) {
		u32 j, nb_edges;
		GF_FilterRegDesc *rdesc = gf_list_get(dijkstra_nodes, i);
		if (rdesc->freg == pid->filter->freg) continue;

		nb_edges = 0;
		for (j=0; j<rdesc->nb_edges; j++) {
			GF_FilterRegEdge *edge = &rdesc->edges[j];
			if (edge->status == EDGE_STATUS_ENABLED) {
				nb_edges++;
				break;
			}
		}

		if (!nb_edges) {
			gf_list_rem(dijkstra_nodes, i);
			i--;
			count--;
		}
	}

	if (fsess->flags & GF_FS_FLAG_PRINT_CONNECTIONS) {
		GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filters in dijkstra set:"));
		count = gf_list_count(dijkstra_nodes);
		for (i=0; i<count; i++) {
			GF_FilterRegDesc *rdesc = gf_list_get(dijkstra_nodes, i);
			GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, (" %s", rdesc->freg->name));
		}
		GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("\n"));
	}


	sort_time_us = gf_sys_clock_high_res();


	dijsktra_edge_count = 0;
	dijsktra_node_count = gf_list_count(dijkstra_nodes)+1;
	first = GF_TRUE;
	
	while (1) {
		GF_FilterRegDesc *current_node = NULL;
		u32 reg_idx = -1;
		u32 min_dist = -1;

		count = gf_list_count(dijkstra_nodes);
		if (!count) break;

		if (first) {
			current_node = reg_dst;
		} else {
			
			for (i=0; i<count; i++) {
				GF_FilterRegDesc *reg_desc = gf_list_get(dijkstra_nodes, i);
				if (reg_desc->dist < min_dist) {
					min_dist = reg_desc->dist;
					current_node = reg_desc;
					reg_idx = i;
				}
			}
			
			if (!current_node)
				break;
			gf_list_rem(dijkstra_nodes, reg_idx);
		}

		if (current_node->freg == pid->filter->freg) {
			result = current_node;
		}
		GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("[Filters] Dijkstra: testing filter %s\n", current_node->freg->name));

		
		for (i=0; i<current_node->nb_edges; i++) {
			u8 priority=0;
			GF_FilterRegEdge *redge = &current_node->edges[i];
			u32 dist;
			Bool do_switch = GF_FALSE;
			dijsktra_edge_count++;

			if (redge->status != EDGE_STATUS_ENABLED)
				continue;

			dist = current_node->dist + 1;
			if (current_node->freg->flags & GF_FS_REG_HIDE_WEIGHT) {
				dist = current_node->dist;
			}

			priority = redge->priority;
			if (redge->src_reg->freg == pid->filter->freg) {
				s32 dst_bundle_idx;
				if (gf_filter_pid_caps_match(pid, current_node->freg, NULL, &priority, &dst_bundle_idx, dst, redge->dst_cap_idx)) {

				} else {
					continue;
				}
			}

			if (dist < redge->src_reg->dist) do_switch = GF_TRUE;
			else if (dist == redge->src_reg->dist) {
				if (prefRegister[0] && (redge->src_reg->destination != current_node) && strstr(prefRegister, current_node->freg->name)) {
					do_switch = GF_TRUE;
					priority = 0;
				} else if ( (dist == redge->src_reg->dist) && (priority < redge->src_reg->priority) )
					do_switch = GF_TRUE;
			}

			if (do_switch) {
				GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("[Filters] Dijkstra: assign filter %s distance %d destination to %s in cap %d out cap %d priority %d (previous destination %s distance %d priority %d)\n", redge->src_reg->freg->name, dist, current_node->freg->name, redge->src_cap_idx, redge->dst_cap_idx, redge->priority, redge->src_reg->destination ? redge->src_reg->destination->freg->name : "none", redge->src_reg->dist, redge->src_reg->priority ));
				redge->src_reg->dist = dist;
				redge->src_reg->priority = priority;
				redge->src_reg->destination = current_node;
				redge->src_reg->cap_idx = redge->src_cap_idx;
			} else if (fsess->flags & GF_FS_FLAG_PRINT_CONNECTIONS) {
				GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("[Filters] Dijkstra: no shorter path from filter %s distance %d from destination %s priority %d (tested %s dist %d priority %d)\n", redge->src_reg->freg->name, redge->src_reg->dist, redge->src_reg->destination ? redge->src_reg->destination->freg->name : "none", redge->priority, current_node->freg->name, dist, redge->src_reg->priority));
			}
		}
		first = GF_FALSE;
	}

	sort_time_us -= start_time_us;
	dijkstra_time_us = gf_sys_clock_high_res() - start_time_us;
	GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("[Filters] Dijkstra: sorted filters in "LLU" us, Dijkstra done in "LLU" us on %d nodes %d edges\n", sort_time_us, dijkstra_time_us, dijsktra_node_count, dijsktra_edge_count));

	if (result && result->destination) {
		GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("[Filters] Dijkstra result: %s(%d)", result->freg->name, result->cap_idx));
		result = result->destination;
		while (result->destination) {
			GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, (" %s(%d)", result->freg->name, result->cap_idx ));
			gf_list_add(out_reg_chain, (void *) result->freg);
			gf_list_add(out_reg_chain, (void *) &result->freg->caps[result->cap_idx]);
			result = result->destination;
		}
		GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, (" %s\n", result->freg->name));
	} else {
		GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("[Filters] Dijkstra: no results found!\n"));
	}
	gf_list_del(dijkstra_nodes);

	gf_free(reg_dst->edges);
	gf_free(reg_dst);
}



static GF_Filter *gf_filter_pid_resolve_link_internal(GF_FilterPid *pid, GF_Filter *dst, Bool *filter_reassigned, u32 reconfigurable_only_type, u32 *min_chain_len, GF_List *skip_if_in_filter_list, Bool *skipped)
{
	GF_Filter *chain_input = NULL;
	GF_FilterSession *fsess = pid->filter->session;
	GF_List *filter_chain;
	u32 i, count;
	char *gfloc = NULL;
	char gfloc_c=0;
	char prefRegister[1001];
	char szForceReg[20];
	Bool reconfigurable_only;

	if (!fsess->max_resolve_chain_len) return NULL;

	filter_chain = gf_list_new();

	if (!dst) return NULL;

	reconfigurable_only = (reconfigurable_only_type==2) ? GF_TRUE : GF_FALSE;

	sprintf(szForceReg, "gfreg%c", pid->filter->session->sep_name);
	prefRegister[0]=0;
	
	concat_reg(pid->filter->session, prefRegister, szForceReg, pid->filter->orig_args ? pid->filter->orig_args : pid->filter->src_args);
	concat_reg(pid->filter->session, prefRegister, szForceReg, pid->filter->dst_args);
	concat_reg(pid->filter->session, prefRegister, szForceReg, dst->src_args);
	concat_reg(pid->filter->session, prefRegister, szForceReg, dst->dst_args);

	gf_mx_p(fsess->links_mx);
	gf_filter_pid_resolve_link_dijkstra(pid, dst, prefRegister, reconfigurable_only, filter_chain);
	gf_mx_v(fsess->links_mx);

	count = gf_list_count(filter_chain);
	if (min_chain_len) {
		*min_chain_len = count;
	} else if (count==0) {
		Bool can_reassign = GF_TRUE;

		
		if (pid->filter->num_input_pids) can_reassign = GF_FALSE;
		
		else if (pid->filter->sticky) can_reassign = GF_FALSE;
		
		else if (pid->filter->out_pid_connection_pending) can_reassign = GF_FALSE;
		
		else if (pid->filter->num_output_pids) {
			u32 k;
			for (k=0; k<pid->filter->num_output_pids; k++) {
				GF_FilterPid *apid = gf_list_get(pid->filter->output_pids, k);
				if (apid->num_destinations) can_reassign = GF_FALSE;
				else if ((apid==pid) && (apid->init_task_pending>1)) can_reassign = GF_FALSE;
				else if ((apid!=pid) && apid->init_task_pending) can_reassign = GF_FALSE;
				if (!can_reassign)
					break;
			}
		}
		
		if (filter_reassigned && can_reassign) {
			if (! *filter_reassigned) {
				if (! gf_filter_swap_source_register(pid->filter) ) {
					
					GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("No suitable filter chain found\n"));
				} else {
					GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Swap source demux to %s\n", pid->filter->freg->name));
				}
			}
			*filter_reassigned = GF_TRUE;
		} else if (!reconfigurable_only) {
			GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("No suitable filter found for pid %s from filter %s\n", pid->name, pid->filter->name));
			if (filter_reassigned)
				*filter_reassigned = GF_FALSE;
		}
	} else if (reconfigurable_only && (count>2)) {
		GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Cannot find filter chain with only one filter handling reconfigurable output for pid %s from filter %s - not supported\n", pid->name, pid->filter->name));
	} else {
		Bool dst_is_sink = gf_filter_is_sink(dst);
		const char *dst_args = NULL;
		const char *args = pid->filter->orig_args ? pid->filter->orig_args : pid->filter->src_args;
		GF_FilterPid *a_pid = pid;
		GF_Filter *prev_af;

		if (skip_if_in_filter_list) {
			assert(skipped);
			*skipped = GF_FALSE;
			u32 nb_skip = gf_list_count(skip_if_in_filter_list);
			const GF_FilterRegister *chain_start_freg = gf_list_get(filter_chain, 0);
			for (i=0; i<nb_skip; i++) {
				GF_Filter *f = gf_list_get(skip_if_in_filter_list, i);
				u32 j;
				GF_Filter *dest_f = NULL;
				Bool true_skip = GF_FALSE;

				for (j=0; j<gf_list_count(dst->destination_filters); j++) {
					dest_f = gf_list_get(dst->destination_filters, j);
					if ((gf_list_find(f->destination_filters, dest_f)>=0) || (gf_list_find(f->destination_links, dest_f)>=0)) {
						true_skip = GF_TRUE;
						break;
					}
					dest_f = NULL;
				}

				for (j=0; j<gf_list_count(dst->destination_links) && !true_skip; j++) {
					dest_f = gf_list_get(dst->destination_links, j);
					if ((gf_list_find(f->destination_filters, dest_f)>=0) || (gf_list_find(f->destination_links, dest_f)>=0)) {
						true_skip = GF_TRUE;
						break;
					}
					dest_f = NULL;
				}
				if (true_skip) {
					GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Skip link from %s:%s to %s because both filters share the same destination %s\n", pid->filter->name, pid->name, dst->name, dest_f->name));
					*skipped = GF_TRUE;
					gf_list_del(filter_chain);
					return NULL;
				}

				if (f->freg == chain_start_freg) {
					
					if (gf_list_find(f->destination_links, dst)<0)
						gf_list_add(f->destination_links, dst);

					GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Skip link from %s:%s to %s because already connected to filter %s which can handle the connection\n", pid->filter->name, pid->name, dst->name, f->name));

					*skipped = GF_TRUE;
					gf_list_del(filter_chain);
					return NULL;
				}
			}
		}

		dst_args = dst->src_args ? dst->src_args : dst->orig_args;

		while (a_pid) {
			GF_FilterPidInst *pidi;
			args = a_pid->filter->src_args;
			if (!args) args = a_pid->filter->orig_args;
			if (args) break;
			gf_mx_p(a_pid->filter->tasks_mx);
			pidi = gf_list_get(a_pid->filter->input_pids, 0);
			gf_mx_v(a_pid->filter->tasks_mx);
			if (!pidi) break;
			a_pid = pidi->pid;
		}


		if (gf_log_tool_level_on(GF_LOG_FILTER, GF_LOG_INFO)) {
			GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Solved %sfilter chain from filter %s PID %s to filter %s - dumping chain:\n", reconfigurable_only_type ? "adaptation " : "", pid->filter->name, pid->name, dst->freg->name));
		}

		char szLocSep[8];
		sprintf(szLocSep, "gfloc%c", fsess->sep_args);
		gfloc = strstr(args, "gfloc");
		if (gfloc) {
			if ((gfloc>args) && (gfloc[-1]==fsess->sep_args))
				gfloc --;

			gfloc_c = gfloc[0];
			gfloc[0] = 0;
		}
		prev_af = NULL;
		for (i=0; i<count; i++) {
			GF_Filter *af;
			Bool load_first_only = GF_FALSE;
			s32 cap_idx = -1;
			const GF_FilterRegister *freg;
			const GF_FilterCapability *cap = NULL;
			u32 k, cur_bundle, bundle_idx=0;
			if (i%2) continue;
			freg = gf_list_get(filter_chain, i);
			cap = gf_list_get(filter_chain, i + 1);
			
			
			for (k=0; k<freg->nb_caps; k++) {
				if (&freg->caps[k]==cap) {
					bundle_idx = k;
					break;
				}
			}
			cur_bundle = 0;
			for (k=0; k<freg->nb_caps; k++) {
				cap = &freg->caps[k];
				if (cur_bundle==bundle_idx) {
					cap_idx = k;
					break;
				}
				if (!(cap->flags & GF_CAPFLAG_IN_BUNDLE)) {
					cur_bundle++;
				}
			}
			
			
			if (!i && gf_filter_out_caps_solved_by_connection(freg, bundle_idx)) {
				load_first_only = GF_TRUE;
			} else if (i) {
				Bool break_chain = GF_FALSE;
				u32 j, nb_filters = gf_list_count(fsess->filters);
				for (j=0; j<nb_filters; j++) {
					GF_Filter *afilter = gf_list_get(fsess->filters, j);
					if (afilter->freg != freg) continue;
					if (!afilter->dynamic_filter) continue;
					if (gf_list_find(pid->filter->destination_links, dst)<0) continue;
					if (!afilter->max_extra_pids) continue;

					
					
					break_chain = GF_TRUE;
					if (prev_af) {
						
						if ( gf_list_find(pid->filter->destination_links, afilter)<0)
							gf_list_add(pid->filter->destination_links, afilter);

						
						prev_af->cap_dst_filter = dst;
					}
					break;
				}
				if (break_chain) {
					break;
				}
			}

			GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("\t%s\n", freg->name));

			af = gf_filter_new(fsess, freg, args, dst_args, pid->filter->no_dst_arg_inherit ? GF_FILTER_ARG_INHERIT_SOURCE_ONLY : GF_FILTER_ARG_INHERIT, NULL, NULL, GF_TRUE);
			if (!af) goto exit;
			af->subsession_id = dst->subsession_id;
			if (dst->itag) af->itag = gf_strdup(dst->itag);
			
			
			
			Bool af_is_mux = GF_FALSE;
			if (dst_is_sink) {
				for (u32 cidx=0; cidx<freg->nb_caps; cidx++) {
					const GF_FilterCapability *a_cap = &freg->caps[cidx];
					if (!(a_cap->flags & GF_CAPFLAG_IN_BUNDLE)) continue;
					if (!(a_cap->flags & GF_CAPFLAG_OUTPUT)) continue;
					if (a_cap->flags & GF_CAPFLAG_EXCLUDED) continue;
					if (a_cap->code!=GF_PROP_PID_STREAM_TYPE) continue;
					if (a_cap->val.value.uint!=GF_STREAM_FILE) break;
					af_is_mux = GF_TRUE;
				}
			}
			if (af_is_mux)
				af->subsource_id = 0;
			else if (pid->filter->subsource_id)
				af->subsource_id = pid->filter->subsource_id;
			
			else af->subsource_id = 1;

			if (!af->forced_caps) {
				
				af->bundle_idx_at_resolution = bundle_idx;
				
				af->cap_idx_at_resolution = cap_idx;
			}
			if (pid->require_source_id)
				af->require_source_id = GF_TRUE;
			
			
			
			
			
			
			if (!prev_af && pid->filter->restricted_source_id)
				af->source_ids = gf_strdup(pid->filter->restricted_source_id);
			else if (prev_af && prev_af->source_ids)
				af->source_ids = gf_strdup(prev_af->source_ids);
			else if (dst->source_ids)
				af->source_ids = gf_strdup(dst->source_ids);

			
			if (prev_af)
				gf_list_add(prev_af->destination_filters, af);

			
			if (i+2==count) {
				gf_list_add(af->destination_filters, dst);
			}
			
			
			else if (!load_first_only) {
				gf_list_add(af->destination_filters, dst);
			}

			
			af->target_filter = pid->filter->target_filter;

			prev_af = af;

			if (reconfigurable_only_type) af->is_pid_adaptation_filter = GF_TRUE;

			
			if (!i) chain_input = af;

			if (load_first_only) {
				GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter %s needs to be connected to decide its outputs, not loading end of the chain\n", freg->name));
				
				if ( gf_list_find(pid->filter->destination_links, dst)<0)
					gf_list_add(pid->filter->destination_links, dst);

				
				gf_list_del_item(af->destination_filters, dst);

				
				af->cap_dst_filter = dst;
				break;
			}
		}
	}

exit:
	if (gfloc) gfloc[0] = gfloc_c;

	gf_list_del(filter_chain);
	return chain_input;
}

GF_Filter *gf_filter_pid_resolve_link(GF_FilterPid *pid, GF_Filter *dst, Bool *filter_reassigned)
{
	return gf_filter_pid_resolve_link_internal(pid, dst, filter_reassigned, 0, NULL, NULL, NULL);
}

GF_Filter *gf_filter_pid_resolve_link_check_loaded(GF_FilterPid *pid, GF_Filter *dst, Bool *filter_reassigned, GF_List *skip_if_in_filter_list, Bool *skipped)
{
	return gf_filter_pid_resolve_link_internal(pid, dst, filter_reassigned, 0, NULL, skip_if_in_filter_list, skipped);
}

GF_Filter *gf_filter_pid_resolve_link_for_caps(GF_FilterPid *pid, GF_Filter *dst, Bool check_reconfig_only)
{
	return gf_filter_pid_resolve_link_internal(pid, dst, NULL, check_reconfig_only ? 2 : 1, NULL, NULL, NULL);
}

u32 gf_filter_pid_resolve_link_length(GF_FilterPid *pid, GF_Filter *dst)
{
	u32 chain_len=0;
	gf_filter_pid_resolve_link_internal(pid, dst, NULL, 0, &chain_len, NULL, NULL);
	return chain_len;
}


GF_List *gf_filter_pid_compute_link(GF_FilterPid *pid, GF_Filter *dst)
{
	GF_FilterSession *fsess = pid->filter->session;
	GF_List *filter_chain;
	char prefRegister[1001];
	char szForceReg[20];

	if (!fsess->max_resolve_chain_len) return NULL;
	if (!dst) return NULL;

	filter_chain = gf_list_new();

	s32 dst_bundle_idx=-1;
	if (gf_filter_pid_caps_match(pid, dst->freg, dst, NULL, &dst_bundle_idx, pid->filter->dst_filter, -1)) {
		gf_list_add(filter_chain, (void*)dst->freg);
		if ((dst_bundle_idx<0) || ((u32) dst_bundle_idx>=dst->freg->nb_caps))
			dst_bundle_idx=0;

		gf_list_add(filter_chain, (void*)&dst->freg->caps[dst_bundle_idx]);
		return filter_chain;
	}

	sprintf(szForceReg, "gfreg%c", pid->filter->session->sep_name);
	prefRegister[0]=0;
	
	concat_reg(pid->filter->session, prefRegister, szForceReg, pid->filter->orig_args ? pid->filter->orig_args : pid->filter->src_args);
	concat_reg(pid->filter->session, prefRegister, szForceReg, pid->filter->dst_args);
	concat_reg(pid->filter->session, prefRegister, szForceReg, dst->src_args);
	concat_reg(pid->filter->session, prefRegister, szForceReg, dst->dst_args);

	gf_mx_p(fsess->links_mx);
	gf_filter_pid_resolve_link_dijkstra(pid, dst, prefRegister, GF_FALSE, filter_chain);
	gf_mx_v(fsess->links_mx);
	if (!gf_list_count(filter_chain)) {
		gf_list_del(filter_chain);
		return NULL;
	}
	gf_list_add(filter_chain, (void *)dst->freg);
	if (dst->freg->nb_caps)
		gf_list_add(filter_chain, (void*)&dst->freg->caps[0]);
	return filter_chain;
}


static void gf_filter_pid_set_args_internal(GF_Filter *filter, GF_FilterPid *pid, char *args, Bool use_default_seps, u32 argfile_level)
{
	char sep_args, sep_frag, sep_name, sep_list;

	if (use_default_seps) {
		sep_args = ':';
		sep_frag = '#';
		sep_name = '=';
		sep_list = ',';
	} else {
		sep_args = filter->session->sep_args;
		sep_frag = filter->session->sep_frag;
		sep_name = filter->session->sep_name;
		sep_list = filter->session->sep_list;
	}

	
	while (args) {
		u32 p4cc=0;
		u32 prop_type=GF_PROP_FORBIDEN;
		Bool parse_prop = GF_TRUE;
		char *value_next_list = NULL;
		char *value_sep = NULL;
		char *value, *name, *sep;

		
		if (args[0] == sep_args) {
			char szEscape[3];
			szEscape[0] = szEscape[1] = sep_args;
			szEscape[2] = 0;
			args++;
			sep = strstr(args, szEscape);
		} else {
			if (sep_args == ':') {
				sep = (char *)gf_fs_path_escape_colon(filter->session, args);
			} else {
				sep = strchr(args, sep_args);
			}
		}
		if (sep) {
			char *xml_start = strchr(args, '<');
			if (xml_start && (xml_start<sep)) {
				char szEnd[3];
				szEnd[0] = '>';
				szEnd[1] = filter->session->sep_args;
				szEnd[2] = 0;
				char *xml_end = strstr(xml_start, szEnd);
				if (!xml_end) {
					sep = NULL;
				} else {
					sep = xml_end+1;
				}
			}
		}

		if (sep) sep[0]=0;

		if (args[0] != sep_frag) {
			
			if (strcmp(args, "gpac") && strcmp(args, "gfopt") && strcmp(args, "gfloc") && gf_file_exists(args)) {
				if (argfile_level<5) {
					char szLine[2001];
					FILE *arg_file = gf_fopen(args, "rt");
					szLine[2000]=0;
					while (!gf_feof(arg_file)) {
						u32 llen;
						char *subarg, *res;
						szLine[0] = 0;
						res = gf_fgets(szLine, 2000, arg_file);
						if (!res) break;
						llen = (u32) strlen(szLine);
						while (llen && strchr(" \n\r\t", szLine[llen-1])) {
							szLine[llen-1]=0;
							llen--;
						}
						if (!llen)
							continue;

						subarg = szLine;
						while (subarg[0] && strchr(" \n\r\t", subarg[0]))
							subarg++;
						if ((subarg[0] == '/') && (subarg[1] == '/'))
							continue;

						gf_filter_pid_set_args_internal(filter, pid, subarg, use_default_seps, argfile_level+1);
					}
					gf_fclose(arg_file);
				} else {
					GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Filter argument file has too many nested levels of sub-files, maximum allowed is 5\n"));
				}
			}
			goto skip_arg;
		}

		value = NULL;
		value_sep = strchr(args, sep_name);
		if (value_sep) {
			value_sep[0]=0;
			value = value_sep+1;
		}
		name = args+1;

		if (strlen(name)==4) {
			p4cc = GF_4CC(name[0], name[1], name[2], name[3]);
			if (p4cc) prop_type = gf_props_4cc_get_type(p4cc);
		}
		if (prop_type==GF_PROP_FORBIDEN) {
			p4cc = gf_props_get_id(name);
			if (p4cc) prop_type = gf_props_4cc_get_type(p4cc);
		}

		
		while (value && (value[0]=='(')) {
			Bool pid_excluded, needs_resolve, prop_not_found, prop_matched;
			char prop_dump_buffer[GF_PROP_DUMP_ARG_SIZE];

			char *next_val = NULL;
			char *closing = strchr(value, ')');
			if (!closing) break;

			if (!strncmp(value, "()", 2)) {
				value = closing+1;
				parse_prop = GF_TRUE;
				value_next_list = next_val;
				break;
			}

			parse_prop = GF_FALSE;

			next_val = strchr(closing, sep_list);
			if (next_val) next_val[0] = 0;

			while (closing) {
				char *next_closing;
				closing[0] = 0;
				prop_matched = filter_pid_check_fragment(pid, value+1, &pid_excluded, &needs_resolve, &prop_not_found, prop_dump_buffer);
				if (prop_not_found) prop_matched = GF_FALSE;
				closing[0] = ')';

				if (!prop_matched)
					break;
				if (strncmp(closing, ")(", 2)) break;
				next_closing = strchr(closing+2, ')');
				if (!next_closing) break;

				value = closing+1;
				closing = next_closing;
			}

			if (prop_matched) {
				value = closing+1;
				parse_prop = GF_TRUE;
				value_next_list = next_val;
				break;
			}
			if (!next_val) break;
			next_val[0] = sep_list;
			value = next_val+1;
		}

		if (!parse_prop)
			goto skip_arg;


		if (prop_type != GF_PROP_FORBIDEN) {
			GF_PropertyValue p;
			p.type = GF_PROP_FORBIDEN;

			
			if ((p4cc == GF_PROP_PID_CONTENT_LIGHT_LEVEL) && strchr(value, sep_list) ){
				GF_PropertyValue a_p = gf_props_parse_value(GF_PROP_UINT_LIST, name, value, NULL, sep_list);
				if ((a_p.type == GF_PROP_UINT_LIST) && (a_p.value.uint_list.nb_items==2))  {
					GF_BitStream *bs = gf_bs_new(NULL, 0, GF_BITSTREAM_WRITE);
					gf_bs_write_u16(bs, a_p.value.uint_list.vals[0]);
					gf_bs_write_u16(bs, a_p.value.uint_list.vals[1]);
					gf_bs_get_content(bs, &p.value.data.ptr, &p.value.data.size);
					p.type = GF_PROP_DATA;
					gf_bs_del(bs);
				}
				gf_props_reset_single(&a_p);
			}
			
			else if ((p4cc == GF_PROP_PID_MASTER_DISPLAY_COLOUR) && strchr(value, sep_list) ) {
				GF_PropertyValue a_p = gf_props_parse_value(GF_PROP_UINT_LIST, name, value, NULL, sep_list);
				if ((a_p.type == GF_PROP_UINT_LIST) && (a_p.value.uint_list.nb_items==10))  {
					GF_BitStream *bs = gf_bs_new(NULL, 0, GF_BITSTREAM_WRITE);
					gf_bs_write_u16(bs, a_p.value.uint_list.vals[0]);
					gf_bs_write_u16(bs, a_p.value.uint_list.vals[1]);
					gf_bs_write_u16(bs, a_p.value.uint_list.vals[2]);
					gf_bs_write_u16(bs, a_p.value.uint_list.vals[3]);
					gf_bs_write_u16(bs, a_p.value.uint_list.vals[4]);
					gf_bs_write_u16(bs, a_p.value.uint_list.vals[5]);
					gf_bs_write_u16(bs, a_p.value.uint_list.vals[6]);
					gf_bs_write_u16(bs, a_p.value.uint_list.vals[7]);
					gf_bs_write_u32(bs, a_p.value.uint_list.vals[8]);
					gf_bs_write_u32(bs, a_p.value.uint_list.vals[9]);
					gf_bs_get_content(bs, &p.value.data.ptr, &p.value.data.size);
					p.type = GF_PROP_DATA;
					gf_bs_del(bs);
				}
				gf_props_reset_single(&a_p);
			}
			
			else if (p4cc == GF_PROP_PID_CODECID) {
				
				if (filter->dynamic_filter) goto skip_arg;
				u32 cid = gf_codecid_parse(value);
				if (cid) {
					p.type = GF_PROP_UINT;
					p.value.uint = cid;
				}
			}
			
			else if (p4cc == GF_PROP_PID_STREAM_TYPE) {
				
				if (filter->dynamic_filter) goto skip_arg;
				u32 st = gf_stream_type_by_name(value);
				if (st!=GF_STREAM_UNKNOWN) {
					p.type = GF_PROP_UINT;
					p.value.uint = st;
				}
			}
			

			if (p.type == GF_PROP_FORBIDEN) {
				p = gf_props_parse_value(prop_type, name, value, NULL, sep_list);
			}

			if (p.type != GF_PROP_FORBIDEN) {
				if (prop_type==GF_PROP_NAME) {
					p.type = GF_PROP_STRING;
					gf_filter_pid_set_property(pid, p4cc, &p);
				} else {
					gf_filter_pid_set_property(pid, p4cc, &p);
				}
			}

			if ((p4cc==GF_PROP_PID_TEMPLATE) && p.value.string) {
				if (strstr(p.value.string, "$Bandwidth$")) {
					gf_opts_set_key("temp", "force_indexing", "true");
				}
			}

			if (prop_type==GF_PROP_STRING_LIST) {
				p.value.string_list.vals = NULL;
				p.value.string_list.nb_items = 0;
			}
			
			else if ((prop_type==GF_PROP_UINT_LIST) || (prop_type==GF_PROP_SINT_LIST) || (prop_type==GF_PROP_VEC2I_LIST) || (prop_type==GF_PROP_4CC_LIST)) {
				p.value.uint_list.vals = NULL;
			}
			gf_props_reset_single(&p);
		} else if (value) {
			Bool reset_prop=GF_FALSE;
			GF_PropertyValue p;
			if (!strncmp(value, "bxml@", 5)) {
				p = gf_props_parse_value(GF_PROP_DATA_NO_COPY, name, value, NULL, sep_list);
			} else if (!strncmp(value, "file@", 5)) {
				p = gf_props_parse_value(GF_PROP_STRING, name, value, NULL, sep_list);
				p.type = GF_PROP_STRING_NO_COPY;
			} else {
				u32 ptype = GF_PROP_FORBIDEN;
				char *type_sep = strchr(value, '@');
				if (type_sep) {
					type_sep[0] = 0;
					ptype = gf_props_parse_type(value);
					if (ptype==GF_PROP_FORBIDEN) {
						GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("Unrecognized property type %s, defaulting to string\n", value));
					} else {
						value = type_sep+1;
					}
					type_sep[0] = '@';
				}
				memset(&p, 0, sizeof(GF_PropertyValue));
				if (ptype == GF_PROP_FORBIDEN) {
					p.type = GF_PROP_STRING;
					p.value.string = value;
				} else {
					p = gf_props_parse_value(ptype, name, value, NULL, sep_list);
					reset_prop = GF_TRUE;
				}
			}
			gf_filter_pid_set_property_dyn(pid, name, &p);
			if (reset_prop) gf_props_reset_single(&p);
		}
		if (value_next_list)
			value_next_list[0] = sep_list;

skip_arg:
		if (value_sep)
			value_sep[0] = sep_name;

		if (sep) {
			sep[0] = sep_args;
			args=sep+1;
		} else {
			break;
		}
	}
}

GF_EXPORT GF_Err gf_filter_pid_push_properties(GF_FilterPid *pid, char *args, Bool direct_merge, Bool use_default_seps)
{
	if (!args) return GF_OK;
	if (PID_IS_INPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to write property on input PID in filter %s - ignoring\n", pid->filter->name ? pid->filter->name : pid->filter->freg->name));
		return GF_BAD_PARAM;
	}

	
	if (direct_merge) {
		Bool req_map_bck = pid->request_property_map;
		pid->request_property_map = GF_FALSE;
		gf_filter_pid_set_args_internal(pid->filter, pid, args, use_default_seps, 0);
		pid->request_property_map = req_map_bck;
	} else {
		gf_filter_pid_set_args_internal(pid->filter, pid, args, use_default_seps, 0);
	}
	return GF_OK;
}

void gf_filter_pid_set_args(GF_Filter *filter, GF_FilterPid *pid)
{
	Bool req_map_bck;
	char *args;
	if (!filter->src_args && !filter->orig_args) return;
	args = filter->orig_args ? filter->orig_args : filter->src_args;

	
	req_map_bck = pid->request_property_map;
	pid->request_property_map = GF_FALSE;
	gf_filter_pid_set_args_internal(filter, pid, args, GF_FALSE, 0);
	pid->request_property_map = req_map_bck;
}

static const char *gf_filter_last_id_in_chain(GF_Filter *filter, Bool ignore_first)
{
	u32 i;
	const char *id;
	if (!ignore_first) {
		if (filter->id) return filter->id;
		if (!filter->dynamic_filter) return NULL;
	}

	gf_mx_p(filter->tasks_mx);
	for (i=0; i<filter->num_input_pids; i++) {
		GF_FilterPidInst *pidi = gf_list_get(filter->input_pids, i);
		if (pidi->pid->filter->id) {
			gf_mx_v(filter->tasks_mx);
			return pidi->pid->filter->id;
		}
		
		if (!pidi->pid->filter->dynamic_filter) continue;
		id = gf_filter_last_id_in_chain(pidi->pid->filter, GF_FALSE);
		if (id) {
			gf_mx_v(filter->tasks_mx);
			return id;
		}
		
		if (pidi->pid->filter->single_source)
			break;
	}
	gf_mx_v(filter->tasks_mx);
	return NULL;
}

void gf_filter_pid_retry_caps_negotiate(GF_FilterPid *src_pid, GF_FilterPid *pid, GF_Filter *dst_filter)
{
	assert(dst_filter);
	src_pid->caps_negociate = pid->caps_negociate;
	pid->caps_negociate = NULL;
	src_pid->caps_dst_filter = dst_filter;
	
	if (!src_pid->adapters_blacklist) src_pid->adapters_blacklist = gf_list_new();
	gf_list_add(src_pid->adapters_blacklist, (void *) pid->filter->freg);
	
	safe_int_inc(& src_pid->filter->nb_caps_renegociate );

	
	gf_fs_post_task(src_pid->filter->session, gf_filter_pid_disconnect_task, pid->filter, src_pid, "pidinst_disconnect", NULL);
}


static Bool gf_filter_pid_needs_explicit_resolution(GF_FilterPid *pid, GF_Filter *dst)
{
	u32 i;
	const GF_FilterCapability *caps;
	u32 nb_caps;
	Bool dst_has_raw_cid_in = GF_FALSE;
	const GF_PropertyValue *stream_type = gf_filter_pid_get_property_first(pid, GF_PROP_PID_STREAM_TYPE);
	if (!stream_type) return GF_TRUE;

	if (stream_type->value.uint==GF_STREAM_FILE) return GF_FALSE;
	if (stream_type->value.uint==GF_STREAM_ENCRYPTED) {
		stream_type = gf_filter_pid_get_property_first(pid, GF_PROP_PID_ORIG_STREAM_TYPE);
		if (!stream_type) return GF_TRUE;
	}

	caps = dst->forced_caps ? dst->forced_caps : dst->freg->caps;
	nb_caps = dst->forced_caps ? dst->nb_forced_caps : dst->freg->nb_caps;

	for (i=0; i<nb_caps; i++) {
		const GF_FilterCapability *cap = &caps[i];
		if (!(cap->flags & GF_CAPFLAG_INPUT)) continue;

		if (cap->code != GF_PROP_PID_CODECID) continue;
		if (cap->val.value.uint==GF_CODECID_RAW)
			dst_has_raw_cid_in = GF_TRUE;
	}


	for (i=0; i<nb_caps; i++) {
		const GF_FilterCapability *cap = &caps[i];
		if (!(cap->flags & GF_CAPFLAG_INPUT)) continue;

		if (cap->code != GF_PROP_PID_STREAM_TYPE) continue;
		
		if ((cap->val.value.uint==GF_STREAM_FILE) || (cap->val.value.uint==stream_type->value.uint)) return GF_FALSE;
		
		if (dst_has_raw_cid_in  && (cap->val.value.uint==GF_STREAM_VISUAL)) {
			switch (stream_type->value.uint) {
			case GF_STREAM_TEXT:
			case GF_STREAM_SCENE:
			case GF_STREAM_OD:
				return GF_FALSE;
			default:
				break;
			}
		}
	}
	
	return GF_TRUE;
}

static void add_possible_link_destination(GF_List *possible_linked_resolutions, GF_Filter *filter_dst)
{
	u32 i;

	for (i=0; i<gf_list_count(possible_linked_resolutions); i++) {
		GF_Filter *parent = gf_list_get(possible_linked_resolutions, i);
		if (parent->max_extra_pids) continue;

		if ((gf_list_find(filter_dst->destination_links, parent)>=0) || (gf_list_find(filter_dst->destination_filters, parent)>=0)) {
			gf_list_rem(possible_linked_resolutions, i);
			gf_list_insert(possible_linked_resolutions, filter_dst, i);
			return;
		}
		if ((gf_list_find(parent->destination_links, filter_dst)>=0) || (gf_list_find(parent->destination_filters, filter_dst)>=0)) {
			return;
		}
	}
	gf_list_add(possible_linked_resolutions, filter_dst);
}


static void dump_pid_props(GF_FilterPid *pid)
{
	u32 idx = 0;
	char szDump[GF_PROP_DUMP_ARG_SIZE];
	const GF_PropertyEntry *p;
	GF_PropertyMap *pmap = gf_list_get(pid->properties, 0);
	while (pmap && (p = gf_list_enum(pmap->properties, &idx))) {
		GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Pid prop %s: %s\n", gf_props_4cc_get_name(p->p4cc), gf_props_dump(p->p4cc, &p->prop, szDump, GF_PROP_DUMP_DATA_NONE) ));
	}
}


static Bool gf_pid_in_parent_chain(GF_FilterPid *pid, GF_FilterPid *look_for_pid)
{
	u32 i, ret=GF_FALSE;
	if (pid == look_for_pid) return GF_TRUE;
	
	
	if (!pid->filter->dynamic_filter && pid->filter->id) return GF_FALSE;

	gf_mx_p(pid->filter->tasks_mx);
	for (i=0; i<pid->filter->num_input_pids; i++) {
		GF_FilterPidInst *pidi = gf_list_get(pid->filter->input_pids, i);
		if (gf_pid_in_parent_chain(pidi->pid, look_for_pid)) {
			ret = GF_TRUE;
			break;
		}
		
		if (pidi->pid->filter->single_source)
			break;
	}
	gf_mx_v(pid->filter->tasks_mx);
	return ret;
}

static Bool filter_match_target_dst(GF_List *flist, GF_Filter *dst)
{
	u32 i, count=gf_list_count(flist);
	for (i=0;i<count;i++) {
		GF_Filter *f = gf_list_get(flist, i);
		if (f==dst) return GF_TRUE;
		if (filter_match_target_dst(f->destination_filters, dst))
			return GF_TRUE;
		if (filter_match_target_dst(f->destination_links, dst))
			return GF_TRUE;
	}
	return GF_FALSE;
}

static Bool parent_chain_has_dyn_pids(GF_Filter *filter)
{
	u32 i;
	if (filter->freg->flags & GF_FS_REG_DYNAMIC_PIDS) return GF_TRUE;
	gf_mx_p(filter->tasks_mx);
	for (i=0; i<filter->num_input_pids; i++) {
		GF_FilterPidInst *pidi = gf_list_get(filter->input_pids, i);
		if (parent_chain_has_dyn_pids(pidi->pid->filter)) {
			gf_mx_v(filter->tasks_mx);
			return GF_TRUE;
		}
	}
	gf_mx_v(filter->tasks_mx);
	return GF_FALSE;
}

static void gf_filter_pid_init_task(GF_FSTask *task)
{
	u32 f_idx, count;
	Bool found_dest=GF_FALSE;
	Bool found_matching_sourceid;
	Bool can_reassign_filter = GF_FALSE;
	Bool can_try_link_resolution=GF_FALSE;
	Bool link_sinks_only = GF_FALSE;
	Bool implicit_link_found = GF_FALSE;
	u32 num_pass=0;
	GF_List *loaded_filters = NULL;
	GF_List *linked_dest_filters = NULL;
    GF_List *force_link_resolutions = NULL;
    GF_List *possible_linked_resolutions = NULL;
	GF_Filter *filter = task->filter;
	GF_FilterPid *pid = task->pid;
	GF_Filter *dynamic_filter_clone = NULL;
	Bool filter_found_but_pid_excluded = GF_FALSE;
	Bool possible_link_found_implicit_mode = GF_FALSE;
	u32 pid_is_file = 0;
	const char *filter_id;

	if (pid->destroyed || pid->removed) {
		assert(pid->init_task_pending);
		safe_int_dec(&pid->init_task_pending);
		return;
	}
	pid->props_changed_since_connect = GF_FALSE;

	
	if (filter->swap_pidinst_src || filter->swap_pidinst_dst) {
		task->requeue_request = GF_TRUE;
		task->can_swap = 1;
		return;
	}
	if (filter->caps_negociate) {
		if (! gf_filter_reconf_output(filter, pid))
			return;
	}

	gf_fs_check_graph_load(filter->session, GF_TRUE);

	if (filter->user_pid_props)
		gf_filter_pid_set_args(filter, pid);

	
	if (!pid->filter->dynamic_filter && !pid->filter->num_input_pids && (pid->filter->freg->flags & GF_FS_REG_FORCE_REMUX)

	) {
		const GF_PropertyValue *st = gf_filter_pid_get_property(pid, GF_PROP_PID_STREAM_TYPE);
		if (st && (st->value.uint==GF_STREAM_FILE))
			pid_is_file = 1;
	}

	
	
	if (filter->subsource_id) {
		filter_id = gf_filter_last_id_in_chain(filter, GF_FALSE);
		if (!filter_id && filter->cloned_from)
			filter_id = gf_filter_last_id_in_chain(filter->cloned_from, GF_FALSE);
	}
	
	else {
		
		filter_id = filter->cloned_from ? filter->cloned_from->id : filter->id;
	}

	
	
	
	
	
	
	
	gf_mx_p(filter->session->filters_mx);

	linked_dest_filters = gf_list_new();
	force_link_resolutions = gf_list_new();
    possible_linked_resolutions = gf_list_new();

	GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s:%s init\n", pid->filter->name, pid->name));

	
	
	
	
restart:

	if (num_pass) {

		
		
		
		
		
		
		
		
		

		loaded_filters = gf_list_clone(linked_dest_filters);
	}

	found_matching_sourceid = GF_FALSE;

	
	
	










	
	count = gf_list_count(filter->session->filters);
	for (f_idx=0; f_idx<count; f_idx++) {
		s32 f_dst_idx;
		Bool needs_clone;
		Bool cap_matched, in_parent_chain, is_sink;
		Bool ignore_source_ids;
		Bool use_explicit_link;
		GF_Filter *filter_dst;

single_retry:

		ignore_source_ids = GF_FALSE;
		use_explicit_link = GF_FALSE;
		filter_dst = gf_list_get(filter->session->filters, f_idx);
		
		if (!filter_dst)
			break;
		
		if (!filter_dst->freg->configure_pid) continue;
		if (filter_dst->finalized || filter_dst->removed || filter_dst->disabled || filter_dst->marked_for_removal || filter_dst->no_inputs) continue;
		if (filter_dst->target_filter == pid->filter) continue;

		
		if (pid->pid->filter->freg == filter_dst->freg) {
			
			if (  filter->dynamic_filter  || !(filter_dst->freg->flags & (GF_FS_REG_ALLOW_CYCLIC|GF_FS_REG_SCRIPT|GF_FS_REG_CUSTOM))



			) {
				continue;
			}
		}

		is_sink = GF_FALSE;
		if (filter->session->flags & GF_FS_FLAG_IMPLICIT_MODE) {
			if (filter_dst->dynamic_filter) {
				if (!filter_dst->subsource_id) {
					is_sink = GF_TRUE;
				}
			} else if (filter_dst->forced_caps) {
				is_sink = !gf_filter_has_out_caps(filter_dst->forced_caps, filter_dst->nb_forced_caps);
			} else {
				is_sink = !gf_filter_has_out_caps(filter_dst->freg->caps, filter_dst->freg->nb_caps);
			}
		}

		
		if (link_sinks_only && !is_sink) continue;
		
		if (implicit_link_found && !filter_dst->source_ids) {
			
			if (!is_sink) continue;
			
			
			
			
			
			if ((gf_list_find(filter->destination_filters, filter_dst)<0)
				&& (gf_list_find(filter->destination_links, filter_dst)<0)
			) {
				continue;
			}
		}

		
		if (pid->num_destinations) {
			u32 j;
			Bool already_linked = GF_FALSE;
			for (j=0; j<pid->num_destinations; j++) {
				GF_FilterPidInst *pidi = gf_list_get(pid->destinations, j);
				if (pidi->filter == filter_dst) {
					already_linked=GF_TRUE;
					break;
				}
			}
			if (already_linked) continue;
		}

		
		if (gf_list_find(linked_dest_filters, filter_dst)>=0) {
			GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s already linked to filter %s\n", pid->name, filter_dst->name));
			continue;
		}
		if (gf_list_count(pid->filter->destination_filters)) {
			s32 ours = gf_list_find(pid->filter->destination_filters, filter_dst);
			if (ours<0) {
				ours = num_pass ? gf_list_del_item(pid->filter->destination_links, filter_dst) : -1;
				if (!filter_dst->source_ids && (ours<0)) {
					GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s has destination filters, filter %s not one of them\n", pid->name, filter_dst->name));
					continue;
				}

				pid->filter->dst_filter = NULL;
			} else {
				filter_dst->in_link_resolution = 0;
				pid->filter->dst_filter = filter_dst;
				
				if (!num_pass && !filter->subsource_id)
					ignore_source_ids = GF_TRUE;
			}
		}

		if (num_pass && gf_list_count(filter->destination_links)) {
			s32 ours = gf_list_find(pid->filter->destination_links, filter_dst);
			if (ours<0) {
				ours = gf_list_find(possible_linked_resolutions, filter_dst);
				if (ours<0) {
					ours = gf_list_find(force_link_resolutions, filter_dst);
				}
				if (ours<0) {
					GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s has destination links, filter %s not one of them\n", pid->name, filter_dst->name));
					continue;
				}
			}
			pid->filter->dst_filter = NULL;
		}
		
		gf_mx_v(filter->session->filters_mx);
		gf_mx_p(filter_dst->tasks_mx);
		if (gf_list_count(filter_dst->source_filters)) {
			u32 j, count2 = gf_list_count(filter_dst->source_filters);
			for (j=0; j<count2; j++) {
				Bool in_par;
				GF_Filter *srcf = gf_list_get(filter_dst->source_filters, j);
				gf_mx_v(filter_dst->tasks_mx);
				in_par = gf_filter_in_parent_chain(pid->filter, srcf);
				gf_mx_p(filter_dst->tasks_mx);
				if (in_par) {
					ignore_source_ids = GF_TRUE;
					break;
				}
			}
		}
		gf_mx_v(filter_dst->tasks_mx);
		RELOCK_FILTER_LIST    if (!filter_dst->max_extra_pids && !filter_dst->dynamic_source_ids && (filter_dst->num_input_pids || filter_dst->in_pid_connection_pending || filter_dst->in_link_resolution)





		 	&& (!filter->swap_pidinst_dst || (filter->swap_pidinst_dst->filter != filter_dst))
		) {
			if ((filter_dst->clonable==GF_FILTER_CLONE_PROBE)
				&& !(filter->session->flags & GF_FS_FLAG_IMPLICIT_MODE)
				&& !filter->source_ids )
				filter_dst->clonable = GF_FILTER_NO_CLONE;

			
			if (filter_dst->clonable==GF_FILTER_NO_CLONE) {
				GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter %s not clonable\n", filter_dst->name));
				continue;
			}

			
			if (!gf_filter_pid_caps_match(pid, filter_dst->freg, filter_dst, NULL, NULL, pid->filter->dst_filter, -1)) {
				GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s caps does not match clonable filter %s\n", pid->name, filter_dst->name));
				continue;
			}
		}

		if (gf_list_find(pid->filter->blacklisted, (void *) filter_dst->freg)>=0) continue;

		
		if (filter_dst->dynamic_filter && (filter_dst != pid->filter->dst_filter)) {
			
			if (pid->filter->dst_filter) {
				GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s has explicit dest %s not %s\n", pid->name, pid->filter->dst_filter->name, filter_dst->name));
				continue;
			}
			
			
			if (!filter_dst->max_extra_pids) {
				GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s has explicit dest %s (%p) matching but no extra pid possible\n", pid->name, filter_dst->name, filter_dst));
				continue;
			}
		}
		
		
		if (!pid->filter->dst_filter && pid->filter->target_filter && (filter_dst != pid->filter->target_filter)) {
			if (filter_dst->target_filter != pid->filter->target_filter) {
				GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s has target filter %s not matching %s->%s\n", pid->name, pid->filter->target_filter->name, filter_dst->name, filter_dst->target_filter ? filter_dst->target_filter->name : "null"));
				continue;
			}
			
		}

		
		
		if (!filter_dst->source_ids && pid->filter->dynamic_filter && pid->filter->dst_filter && (filter_dst!=pid->filter->dst_filter)) {
			GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s has dest filter %s not matching %s\n", pid->name, pid->filter->dst_filter->name, filter_dst->name));
			continue;
		}
		
		
		
		gf_mx_v(filter->session->filters_mx);
		in_parent_chain = gf_filter_in_parent_chain(filter, filter_dst);

		RELOCK_FILTER_LIST  if (in_parent_chain) {

			GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s has filter %s in its parent chain\n", pid->name, filter_dst->name));
			continue;
		}

		
		
		
		
		
		
		
		
		
		if (filter->dynamic_filter)  {
			Bool cyclic_detected = GF_FALSE;
			u32 k;
			gf_mx_p(filter_dst->tasks_mx);
			
			for (k=0; k<gf_list_count(filter_dst->temp_input_pids); k++) {
				GF_FilterPid *a_src_pid = gf_list_get(filter_dst->temp_input_pids, k);
				if (a_src_pid == pid) continue;
				if (gf_pid_in_parent_chain(pid, a_src_pid))
					cyclic_detected = GF_TRUE;
			}
			gf_mx_v(filter_dst->tasks_mx);

			
			gf_mx_v(filter->session->filters_mx);
			gf_mx_p(filter_dst->tasks_mx);
			
			for (k=0; k<filter_dst->num_input_pids && !cyclic_detected; k++) {
				GF_FilterPidInst *pidi = gf_list_get(filter_dst->input_pids, k);
				if (pidi->pid == pid) continue;
				if (gf_pid_in_parent_chain(pid, pidi->pid))
					cyclic_detected = GF_TRUE;
			}
			gf_mx_v(filter_dst->tasks_mx);

			RELOCK_FILTER_LIST  if (cyclic_detected) {

				GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("PID %s:%s has one or more PID in input chain already connected to filter %s, breaking cycle\n", pid->name, pid->filter->name, filter_dst->name));
				gf_list_del_item(force_link_resolutions, filter_dst);
				for (k=0; k<gf_list_count(filter_dst->destination_links); k++) {
					GF_Filter *a_dst = gf_list_get(filter_dst->destination_links, k);
                   gf_list_del_item(force_link_resolutions, a_dst);
				}
				for (k=0; k<gf_list_count(filter_dst->destination_filters); k++) {
					GF_Filter *a_dst = gf_list_get(filter_dst->destination_filters, k);
                    gf_list_del_item(force_link_resolutions, a_dst);
				}
				continue;
			}
		}

		
		if (filter_dst->cloned_from) {
			if (gf_filter_in_parent_chain(filter, filter_dst->cloned_from) ) {
				GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s has the original of cloned filter %s in its parent chain\n", pid->name, filter_dst->name));
				continue;
			}
			if (gf_filter_in_parent_chain(filter_dst->cloned_from, filter) ) {
				GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s has the original of cloned filter %s in its output filter chain\n", pid->name, filter_dst->name));
				continue;
			}
		}

		
		if (filter->cloned_from) {
			if (gf_filter_in_parent_chain(filter->cloned_from, filter_dst) ) {
				GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s filter is cloned and has filter %s in its clone parent chain\n", pid->name, filter_dst->name));
				continue;
			}
		}

		
		needs_clone=GF_FALSE;
		if (filter_id) {
			if (filter_dst->source_ids) {
				Bool pid_excluded=GF_FALSE;
				if (!filter_source_id_match(pid, filter_id, filter_dst, &pid_excluded, &needs_clone)) {
					Bool not_ours=GF_TRUE;
					
					
					
					
					
					
					if (filter->dynamic_filter && filter->id) {
						const char *src_filter_id = gf_filter_last_id_in_chain(filter, GF_TRUE);
						if (filter_source_id_match(pid, src_filter_id, filter_dst, &pid_excluded, &needs_clone)) {
							not_ours = GF_FALSE;
						}
					}
					if (not_ours) {
						if (pid_excluded && !num_pass) filter_found_but_pid_excluded = GF_TRUE;

						GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s does not match source ID for filter %s\n", pid->name, filter_dst->name));
						continue;
					}
				}
				
				
				
				
				
				
				if (!filter->dynamic_filter || filter_dst->id || !(filter->session->flags & GF_FS_FLAG_IMPLICIT_MODE))
					use_explicit_link = GF_TRUE;
			}
			
			
			else if (pid->require_source_id) {
				GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s requires source ID, not set for filter %s\n", pid->name, filter_dst->name));
				continue;
			}
		}
		
		else if (filter_dst->source_ids && !ignore_source_ids) {
			Bool pid_excluded=GF_FALSE;
			if ( (filter_dst->source_ids[0]!='*')
				&& (filter_dst->source_ids[0]!=filter->session->sep_frag)
				&& (filter_dst->source_ids[0]!=filter->session->sep_neg)
				) {
				GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s does not match filter %s source ID\n", pid->name, filter_dst->name));
				continue;
			}
			if (!filter_source_id_match(pid, "*", filter_dst, &pid_excluded, &needs_clone)) {
				if (pid_excluded && !num_pass) filter_found_but_pid_excluded = GF_TRUE;
				GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s is excluded by filter %s source ID\n", pid->name, filter_dst->name));
				continue;
			}
			use_explicit_link = GF_TRUE;
		}
		else if (filter->subsession_id != filter_dst->subsession_id) {
			GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s and filter %s not in same subsession and no links directive\n", pid->name, filter_dst->name));
			continue;
		}
		
		
		else if (filter->subsource_id && filter_dst->subsource_id && (filter->subsource_id != filter_dst->subsource_id)) {
			GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s and filter %s do not have same source and no links directive\n", pid->name, filter_dst->name));
			continue;
		}
		if (needs_clone) {
			
			
			if (!num_pass && !dynamic_filter_clone && !found_matching_sourceid) {
				dynamic_filter_clone = filter_dst;
			}
			GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s needs cloning of filter %s\n", pid->name, filter_dst->name));
			continue;
		} else if (dynamic_filter_clone && dynamic_filter_clone->freg==filter_dst->freg) {
			dynamic_filter_clone = NULL;
		}
		
		found_matching_sourceid = GF_TRUE;

		
		cap_matched = gf_filter_pid_caps_match(pid, filter_dst->freg, filter_dst, NULL, NULL, pid->filter->dst_filter, -1);

		
		
		if (cap_matched && filter_dst->force_demux && pid_is_file) {
			if (pid_is_file==1)
				pid_is_file = 2;
			continue;
		}

		can_try_link_resolution = GF_TRUE;

		
		
		
		if (num_pass) {
			u32 k, alt_count = gf_list_count(possible_linked_resolutions);
			for (k=0; k<alt_count; k++) {
				GF_Filter *adest = gf_list_get(possible_linked_resolutions, k);
				
				
				
				
				
				if (! (adest->freg->flags & GF_FS_REG_DYNAMIC_REDIRECT))
					continue;
				if ((gf_list_find(adest->destination_filters, filter_dst)>=0) || (gf_list_find(adest->destination_links, filter_dst)>=0) ) {
					filter_dst = adest;
					gf_list_rem(possible_linked_resolutions, k);
					break;
				}
			}
		}

		
		
		if (!cap_matched && (filter_dst->clonable==GF_FILTER_CLONE) && pid->filter->num_input_pids) {
			cap_matched = gf_filter_pid_caps_match(pid, filter_dst->freg, NULL, NULL, NULL, pid->filter->dst_filter, -1);
		}

		if (!cap_matched) {
			Bool skipped = GF_FALSE;
			Bool reassigned=GF_FALSE;
			GF_Filter *new_f;

			
			
			if (gf_filter_pid_needs_explicit_resolution(pid, filter_dst)) {
				GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s needs explicit resolution for linking to filter %s\n", pid->name, filter_dst->name));
				continue;
			}

			
			if (pid->filter->dst_filter && (filter_dst == pid->filter->dst_filter)) {
				GF_Filter *old_dst = pid->filter->dst_filter;
				pid->filter->dst_filter = NULL;
				gf_list_del_item(pid->filter->destination_links, filter_dst);
				gf_list_del_item(pid->filter->destination_filters, filter_dst);
				
				if (old_dst->dynamic_filter && !old_dst->has_pending_pids && !old_dst->num_input_pids && !old_dst->num_output_pids && !old_dst->out_pid_connection_pending ) {




					Bool skip = ((old_dst==filter_dst) && (filter_dst->dynamic_filter!=2)) ? GF_TRUE : GF_FALSE;
					gf_filter_post_remove(old_dst);
					if (skip)
						continue;
				}
			}
			if (!num_pass) {
                
                
				if (filter_dst->source_ids || (is_sink && !implicit_link_found)) {
                    gf_list_add(force_link_resolutions, filter_dst);
                    
                    if (filter_dst->multi_sink_target) {
						gf_list_del_item(force_link_resolutions, filter_dst->multi_sink_target);
						gf_list_add(linked_dest_filters, filter_dst->multi_sink_target);
					}
				} else {
					
					
					if (!possible_link_found_implicit_mode)
						add_possible_link_destination(possible_linked_resolutions, filter_dst);

					
					
					
					
					
					
					if (!use_explicit_link && (filter->session->flags & GF_FS_FLAG_IMPLICIT_MODE) && !is_sink) {
						possible_link_found_implicit_mode = GF_TRUE;
					}
				}
				continue;
			}
			filter_found_but_pid_excluded = GF_FALSE;

			GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Attempting to solve link between PID %s:%s and filter %s\n", pid->filter->freg->name, pid->name, filter_dst->name));

			if (num_pass==1) reassigned = GF_TRUE;
			else reassigned = GF_FALSE;

			
			new_f = gf_filter_pid_resolve_link_check_loaded(pid, filter_dst, &reassigned, loaded_filters, &skipped);

			
			if (! new_f) {
				if (skipped) {
					continue;
				}
				if (pid->filter->session->run_status!=GF_OK) {
					GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("PID %s:%s init canceled (session abort)\n", pid->filter->name, pid->name));
					gf_mx_v(filter->session->filters_mx);
					assert(pid->init_task_pending);
					safe_int_dec(&pid->init_task_pending);
					if (loaded_filters) gf_list_del(loaded_filters);
					gf_list_del(linked_dest_filters);
                    gf_list_del(force_link_resolutions);
                    gf_list_del(possible_linked_resolutions);
					return;
				}

				
				if (reassigned) {
					if (num_pass==1) {
						can_reassign_filter = GF_TRUE;
						continue;
					}
					gf_mx_v(filter->session->filters_mx);
					assert(pid->init_task_pending);
					safe_int_dec(&pid->init_task_pending);
					if (loaded_filters) gf_list_del(loaded_filters);
					gf_list_del(linked_dest_filters);
                    gf_list_del(force_link_resolutions);
                    gf_list_del(possible_linked_resolutions);
					return;
				}
				
				if (filter_dst->dynamic_filter && filter_dst->dst_filter) {
					GF_Filter *new_dst = filter_dst;
					while (new_dst->dst_filter && new_dst->dynamic_filter) {
						GF_Filter *f = new_dst;
						new_dst = new_dst->dst_filter;
						if (!f->num_input_pids && !f->num_output_pids && !f->in_pid_connection_pending) {
							gf_filter_post_remove(f);
						}
					}
					
					pid->filter->dst_filter = NULL;
					new_f = gf_filter_pid_resolve_link(pid, new_dst, &reassigned);
					if (!new_f) {
						if (reassigned) {
							gf_mx_v(filter->session->filters_mx);
							assert(pid->init_task_pending);
							safe_int_dec(&pid->init_task_pending);
							if (loaded_filters) gf_list_del(loaded_filters);
							gf_list_del(linked_dest_filters);
                            gf_list_del(force_link_resolutions);
                            gf_list_del(possible_linked_resolutions);
							return;
						} else {
							continue;
						}
					}
					
				} else {
					continue;
				}
			}

			
			if ((filter->session->flags & GF_FS_FLAG_IMPLICIT_MODE)
				&& !gf_list_count(new_f->destination_filters)
				&& !gf_list_count(new_f->destination_links)
				&& !filter_dst->source_ids ) {
				gf_list_add(new_f->destination_links, filter_dst);
			}

			
			if ((filter_dst->clonable==GF_FILTER_CLONE_PROBE) && new_f->max_extra_pids)
				filter_dst->clonable = GF_FILTER_NO_CLONE;

			gf_list_del_item(filter->destination_filters, filter_dst);
			if (gf_list_find(new_f->destination_filters, filter_dst)>=0) {
				if (filter_dst->clonable==GF_FILTER_NO_CLONE)
					filter_dst->in_link_resolution = GF_TRUE;
			}

			filter_dst = new_f;
			gf_list_add(loaded_filters, new_f);
		}

		if (!(filter_dst->freg->flags & (GF_FS_REG_ALLOW_CYCLIC|GF_FS_REG_SCRIPT|GF_FS_REG_CUSTOM))) {
			assert(pid->pid->filter->freg != filter_dst->freg);
		}

		safe_int_inc(&pid->filter->out_pid_connection_pending);
		gf_mx_p(filter_dst->tasks_mx);
		gf_list_add(filter_dst->temp_input_pids, pid);
		if (pid->filter != filter_dst->single_source)
			filter_dst->single_source = NULL;
		gf_mx_v(filter_dst->tasks_mx);
		gf_filter_pid_post_connect_task(filter_dst, pid);

		found_dest = GF_TRUE;
		gf_list_add(linked_dest_filters, filter_dst);

		gf_list_del_item(filter->destination_links, filter_dst);
		
		if (filter_dst->max_extra_pids) {
			u32 k=0;
			for (k=0; k<gf_list_count(filter_dst->destination_filters); k++) {
				GF_Filter *dst_f = gf_list_get(filter_dst->destination_filters, k);
				gf_list_del_item(filter->destination_links, dst_f);
			}
		}

		
		if (!use_explicit_link && (filter->session->flags & GF_FS_FLAG_IMPLICIT_MODE)) {
			if (is_sink)
				link_sinks_only = GF_TRUE;
			else if (!implicit_link_found) {
				u32 k=0;
				for (k=0; k<gf_list_count(force_link_resolutions); k++) {
					GF_Filter *dst_f = gf_list_get(force_link_resolutions, k);
					if (!dst_f->source_ids) {
						gf_list_rem(force_link_resolutions, k);
						k--;
					}
				}
				implicit_link_found = GF_TRUE;
			}
		}
    }

	if (!num_pass) {
		u32 i, k;
		gf_mx_v(filter->session->filters_mx);
		
		
		for (i=0; i< gf_list_count(linked_dest_filters); i++) {
			GF_Filter *filter_dst = gf_list_get(linked_dest_filters, i);
			for (k=0; k<gf_list_count(force_link_resolutions); k++) {
				GF_Filter *dst_link = gf_list_get(force_link_resolutions, k);
				if ( gf_filter_in_parent_chain(filter_dst, dst_link)
					|| gf_filter_in_parent_chain(dst_link, filter_dst)
					
					
					
					
					|| filter_match_target_dst(filter_dst->destination_filters, dst_link)
					|| filter_match_target_dst(filter_dst->destination_links, dst_link)
					
					|| (dst_link->target_filter == filter_dst)
				) {
					gf_list_rem(force_link_resolutions, k);
					k--;
				}
			}
		}

		
		
		
		for (i=0; i<gf_list_count(force_link_resolutions); i++) {
			GF_Filter *forced_dst = gf_list_get(force_link_resolutions, i);
			for (k=i+1; k<gf_list_count(force_link_resolutions); k++) {
				GF_Filter *forced_inserted = gf_list_get(force_link_resolutions, k);

				if (gf_filter_in_parent_chain(forced_inserted, forced_dst)
					|| filter_match_target_dst(forced_inserted->destination_filters, forced_dst)
					|| filter_match_target_dst(forced_inserted->destination_links, forced_dst)
				) {
					gf_list_rem(force_link_resolutions, i);
					
					gf_list_add(linked_dest_filters, forced_dst);
					i--;
					break;
				}
			}
		}
		gf_mx_p(filter->session->filters_mx);
	}

	if (loaded_filters) {
		gf_list_del(loaded_filters);
		loaded_filters = NULL;
	}

	
	if (!num_pass && gf_list_count(filter->destination_links) && can_try_link_resolution && filter->session->max_resolve_chain_len) {
		num_pass = 1;
		goto restart;
	}
    
	if (!num_pass && gf_list_count(force_link_resolutions)) {
		num_pass = 1;
		goto restart;
	}

    
	if (found_dest) {
		assert(pid->init_task_pending);
		safe_int_dec(&pid->init_task_pending);
		gf_mx_v(filter->session->filters_mx);
		pid->filter->disabled = GF_FILTER_ENABLED;
		gf_list_del(linked_dest_filters);
        gf_list_del(force_link_resolutions);
        gf_list_del(possible_linked_resolutions);
		gf_fs_check_graph_load(filter->session, GF_FALSE);
		if (pid->not_connected) {
			pid->not_connected = 0;
			assert(pid->filter->num_out_pids_not_connected);
			pid->filter->num_out_pids_not_connected--;
		}
		return;
	}

	
	if (dynamic_filter_clone && !num_pass) {
		GF_Filter *clone = gf_filter_clone(dynamic_filter_clone, NULL);
		if (clone) {
			assert(dynamic_filter_clone->dynamic_source_ids);
			gf_free(clone->source_ids);
			clone->source_ids = gf_strdup(dynamic_filter_clone->dynamic_source_ids);
			clone->cloned_from = NULL;
			count = gf_list_count(filter->session->filters);
			gf_list_add(pid->filter->destination_links, clone);
			f_idx = count-1;
			num_pass = 1;
			goto single_retry;
		}
	}

	
	if (!num_pass && !can_try_link_resolution && (pid_is_file==2)) {
		GF_Err e;
		GF_Filter *f = gf_fs_load_filter(filter->session, "reframer", &e);
		if (!e) {
			GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Local file PID %s to local file detected, forcing remux\n", pid->name));
			f->dynamic_filter = 2;
			f->subsession_id = pid->filter->subsession_id;
			f->subsource_id = pid->filter->subsource_id;
			
			
			
			
			pid->filter->dst_filter = f;
			num_pass = 1;
			goto restart;
		}
	}

	
	if (!num_pass && can_try_link_resolution && filter->session->max_resolve_chain_len) {
		num_pass = 1;
		goto restart;
	}
	if ((num_pass==1) && can_reassign_filter) {
		if (filter->session->flags & GF_FS_FLAG_NO_REASSIGN) {
			GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("PID %s in filter %s not connected, source reassignment was possible but is disabled\n", pid->name, pid->filter->name));
		} else {
			num_pass = 2;
			GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("PID %s in filter %s not connected to any loaded filter, trying source reassignment\n", pid->name, pid->filter->name));
			goto restart;
		}
	}

	gf_fs_check_graph_load(filter->session, GF_FALSE);

	gf_list_del(linked_dest_filters);
    gf_list_del(force_link_resolutions);
    gf_list_del(possible_linked_resolutions);
	gf_mx_v(filter->session->filters_mx);

	if (pid->num_destinations && !pid->not_connected) {
		assert(pid->init_task_pending);
		safe_int_dec(&pid->init_task_pending);
		return;
	}
	filter->num_out_pids_not_connected ++;
	
	if (pid->is_sparse) {
		assert(filter->nb_sparse_pids);
		safe_int_dec(&filter->nb_sparse_pids);
		pid->is_sparse = 0;
	}

	GF_FilterEvent evt;
	if (filter_found_but_pid_excluded) {
		
		GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("PID %s in filter %s not connected to any loaded filter due to source directives\n", pid->name, pid->filter->name));
		pid->not_connected = 1;
	} else {
		
		if (!pid->not_connected_ok && (filter->session->flags & GF_FS_FLAG_FULL_LINK) ) {
			GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("No filter chain found for PID %s in filter %s to any loaded filters - ABORTING!\n", pid->name, pid->filter->name));
			filter->session->last_connect_error = GF_FILTER_NOT_FOUND;
			filter->session->run_status = GF_FILTER_NOT_FOUND;
			filter->session->in_final_flush = GF_TRUE;
			assert(pid->init_task_pending);
			safe_int_dec(&pid->init_task_pending);
			return;
		}

		GF_LOG(pid->not_connected_ok ? GF_LOG_DEBUG : GF_LOG_WARNING, GF_LOG_FILTER, ("No filter chain found for PID %s in filter %s to any loaded filters - NOT CONNECTED\n", pid->name, pid->filter->name));

		if (pid->filter->freg->process_event) {
			GF_FEVT_INIT(evt, GF_FEVT_CONNECT_FAIL, pid);
			pid->filter->freg->process_event(filter, &evt);
		}
		pid->not_connected = 1;
	}
	GF_FEVT_INIT(evt, GF_FEVT_PLAY, pid);
	evt.play.initial_broadcast_play = 2;
	gf_filter_pid_send_event_internal(pid, &evt, GF_TRUE);

	GF_FEVT_INIT(evt, GF_FEVT_STOP, pid);
	evt.play.initial_broadcast_play = 2;
	gf_filter_pid_send_event_internal(pid, &evt, GF_TRUE);

	gf_filter_pid_set_eos(pid);
	if (!pid->not_connected_ok && !parent_chain_has_dyn_pids(pid->filter)
		&& (pid->filter->num_out_pids_not_connected == pid->filter->num_output_pids)
	) {
		pid->filter->disabled = GF_FILTER_DISABLED;

		if (can_reassign_filter) {
			gf_filter_setup_failure(pid->filter, GF_FILTER_NOT_FOUND);
		}
	}

	if (!filter_found_but_pid_excluded && !pid->not_connected_ok && !filter->session->max_resolve_chain_len) {
		filter->session->last_connect_error = GF_FILTER_NOT_FOUND;
	}

	assert(pid->init_task_pending);
	safe_int_dec(&pid->init_task_pending);
	return;
}

void gf_filter_pid_post_connect_task(GF_Filter *filter, GF_FilterPid *pid)
{
	assert(pid->pid);
	assert(pid->filter != filter);
	if (!(filter->freg->flags & (GF_FS_REG_ALLOW_CYCLIC|GF_FS_REG_SCRIPT|GF_FS_REG_CUSTOM))) {
		assert(pid->filter->freg != filter->freg);
	}
	assert(filter->freg->configure_pid);
	safe_int_inc(&filter->session->pid_connect_tasks_pending);
	safe_int_inc(&filter->in_pid_connection_pending);
	gf_fs_post_task_ex(filter->session, gf_filter_pid_connect_task, filter, pid, "pid_connect", NULL, GF_TRUE, GF_FALSE, GF_FALSE, TASK_TYPE_NONE);
}


void gf_filter_pid_post_init_task(GF_Filter *filter, GF_FilterPid *pid)
{

	if (pid->init_task_pending) return;

	safe_int_inc(&pid->init_task_pending);

	
	
	Bool force_main_thread = GF_TRUE;

	gf_fs_post_task_ex(filter->session, gf_filter_pid_init_task, filter, pid, "pid_init", NULL, GF_FALSE, force_main_thread, GF_FALSE, TASK_TYPE_NONE);
}

GF_EXPORT GF_Err gf_filter_pid_set_framing_mode(GF_FilterPid *pid, Bool requires_full_blocks)
{
	GF_FilterPidInst *pidinst = (GF_FilterPidInst *)pid;

	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to set framing info on an output pid in filter %s\n", pid->filter->name));
		return GF_BAD_PARAM;
	}
	pidinst->requires_full_data_block = requires_full_blocks;
	return GF_OK;
}

GF_EXPORT GF_FilterPid *gf_filter_pid_new(GF_Filter *filter)
{
	char szName[30];
	GF_FilterPid *pid;
	GF_SAFEALLOC(pid, GF_FilterPid);
	if (!pid) return NULL;
	pid->filter = filter;
	pid->destinations = gf_list_new();
	pid->properties = gf_list_new();
	if (!filter->output_pids) filter->output_pids = gf_list_new();
	gf_mx_p(filter->tasks_mx);
	gf_list_add(filter->output_pids, pid);
	filter->num_output_pids = gf_list_count(filter->output_pids);
	gf_mx_v(filter->tasks_mx);
	pid->pid = pid;
	pid->playback_speed_scaler = GF_FILTER_SPEED_SCALER;
	pid->require_source_id = filter->require_source_id;

	sprintf(szName, "PID%d", filter->num_output_pids);
	pid->name = gf_strdup(szName);

	filter->has_pending_pids = GF_TRUE;
	gf_fq_add(filter->pending_pids, pid);

	gf_mx_p(filter->tasks_mx);
	
	if (filter->num_input_pids==1) {
		GF_FilterPid *pidi = gf_list_get(filter->input_pids, 0);
		gf_filter_pid_copy_properties(pid, pidi);
	}
	gf_mx_v(filter->tasks_mx);
	return pid;
}

void gf_filter_pid_del(GF_FilterPid *pid)
{
	GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Filter %s pid %s destruction (%p)\n", pid->filter->name, pid->name, pid));
	while (gf_list_count(pid->destinations)) {
		gf_filter_pid_inst_del(gf_list_pop_back(pid->destinations));
	}
	gf_list_del(pid->destinations);

	while (gf_list_count(pid->properties)) {
		GF_PropertyMap *prop = gf_list_pop_back(pid->properties);
		assert(prop->reference_count);
		if (safe_int_dec(&prop->reference_count) == 0) {
			gf_props_del(prop);
		}
	}
	gf_list_del(pid->properties);

	if(pid->caps_negociate) {
		assert(pid->caps_negociate->reference_count);
		if (safe_int_dec(&pid->caps_negociate->reference_count) == 0) {
			gf_props_del(pid->caps_negociate);
		}
	}

	if (pid->adapters_blacklist)
		gf_list_del(pid->adapters_blacklist);

	if (pid->infos) {
		assert(pid->infos->reference_count);
		if (safe_int_dec(&pid->infos->reference_count) == 0) {
			gf_props_del(pid->infos);
		}
	}
	if (pid->name) gf_free(pid->name);
	gf_free(pid);
}

void gf_filter_pid_del_task(GF_FSTask *task)
{
	gf_filter_pid_del(task->pid);
}

static GF_PropertyMap *check_new_pid_props(GF_FilterPid *pid, Bool merge_props)
{
	u32 i, nb_recf;
	GF_PropertyMap *old_map;
	GF_PropertyMap *map;

	
	gf_mx_p(pid->filter->tasks_mx);
	old_map = gf_list_last(pid->properties);
	gf_mx_v(pid->filter->tasks_mx);

	pid->props_changed_since_connect = GF_TRUE;
	if (old_map && !pid->request_property_map) {
		return old_map;
	}
	map = gf_props_new(pid->filter);
	if (!map)
		return NULL;
	
	gf_mx_p(pid->filter->tasks_mx);
	gf_list_add(pid->properties, map);
	gf_mx_v(pid->filter->tasks_mx);

	pid->request_property_map = GF_FALSE;
	pid->pid_info_changed = GF_FALSE;

	
	if (old_map) {
		if (merge_props)
			gf_props_merge_property(map, old_map, NULL, NULL);

		assert(old_map->reference_count);
		if (safe_int_dec(&old_map->reference_count) == 0) {
			
			gf_mx_p(pid->filter->tasks_mx);
			gf_list_del_item(pid->properties, old_map);
			gf_mx_v(pid->filter->tasks_mx);
			gf_props_del(old_map);
		}
	}

	
	
	nb_recf = 0;
	for (i=0; i<pid->num_destinations; i++) {
		GF_FilterPidInst *pidi = gf_list_get(pid->destinations, i);
		if (!pidi->filter->process_task_queued) {
			
			pidi->reconfig_pid_props = map;
			nb_recf++;
		}
	}
	if (nb_recf)
		pid->filter->reconfigure_outputs = GF_TRUE;
	return map;
}

static GF_Err gf_filter_pid_set_property_full(GF_FilterPid *pid, u32 prop_4cc, const char *prop_name, char *dyn_name, const GF_PropertyValue *value, Bool is_info)
{
	GF_PropertyMap *map;
	const GF_PropertyValue *oldp;
	if (PID_IS_INPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to write property on input PID in filter %s - ignoring\n", pid->filter->name ? pid->filter->name : pid->filter->freg->name));
		return GF_BAD_PARAM;
	}

	if (prop_4cc) {
		oldp = gf_filter_pid_get_property(pid, prop_4cc);
	} else {
		oldp = gf_filter_pid_get_property_str(pid, prop_name ? prop_name : dyn_name);
	}
	if (!oldp && !value)
		return GF_OK;
	if (oldp && value) {
		if (gf_props_equal_strict(oldp, value)) {
			if (value->type==GF_PROP_DATA_NO_COPY) gf_free(value->value.data.ptr);
			else if (value->type==GF_PROP_STRING_NO_COPY) gf_free(value->value.string);
			else if (value->type==GF_PROP_STRING_LIST) gf_props_reset_single((GF_PropertyValue *) value);
			return GF_OK;
		}
	}

	
	if (is_info) {
		map = pid->infos;
		if (!map) {
			map = pid->infos = gf_props_new(pid->filter);
		}
		pid->pid_info_changed = GF_TRUE;
	} else {
		
		map = check_new_pid_props(pid, GF_TRUE);
	}
	if (!map) {
		GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("No properties for destination pid in filter %s, ignoring reset\n", pid->filter->name));
		return GF_OUT_OF_MEM;
	}
	if (value && (prop_4cc==GF_PROP_PID_TIMESCALE))
		map->timescale = value->value.uint;

	
	if (oldp && value) {
		Bool reset=0;
		if (prop_4cc == GF_PROP_PID_CODECID) {
			reset = 2;
		} else if (prop_4cc == GF_PROP_PID_STREAM_TYPE) {
			if ((oldp->value.uint==GF_STREAM_ENCRYPTED) || (value->value.uint==GF_STREAM_ENCRYPTED))
				reset = 1;
		}
		if (reset) {
			gf_props_set_property(map, GF_PROP_PID_ISOM_STSD_ALL_TEMPLATES, NULL, NULL, NULL);
			if (reset==2) {
				gf_props_set_property(map, GF_PROP_PID_ISOM_STSD_TEMPLATE, NULL, NULL, NULL);
				gf_props_set_property(map, GF_PROP_PID_ISOM_SUBTYPE, NULL, NULL, NULL);
			}
		}
	}

	if (value && (prop_4cc == GF_PROP_PID_ID) && !pid->name) {
		char szName[100];
		sprintf(szName, "PID%d", value->value.uint);
		gf_filter_pid_set_name(pid, szName);
	}
	return gf_props_set_property(map, prop_4cc, prop_name, dyn_name, value);
}

GF_EXPORT GF_Err gf_filter_pid_set_property(GF_FilterPid *pid, u32 prop_4cc, const GF_PropertyValue *value)
{
	if (!prop_4cc) return GF_BAD_PARAM;
	return gf_filter_pid_set_property_full(pid, prop_4cc, NULL, NULL, value, GF_FALSE);
}

GF_EXPORT GF_Err gf_filter_pid_set_property_str(GF_FilterPid *pid, const char *name, const GF_PropertyValue *value)
{
	if (!name) return GF_BAD_PARAM;
	return gf_filter_pid_set_property_full(pid, 0, name, NULL, value, GF_FALSE);
}

GF_EXPORT GF_Err gf_filter_pid_set_property_dyn(GF_FilterPid *pid, char *name, const GF_PropertyValue *value)
{
	if (!name) return GF_BAD_PARAM;
	return gf_filter_pid_set_property_full(pid, 0, NULL, name, value, GF_FALSE);
}

GF_EXPORT GF_Err gf_filter_pid_set_info(GF_FilterPid *pid, u32 prop_4cc, const GF_PropertyValue *value)
{
	if (!prop_4cc) return GF_BAD_PARAM;
	return gf_filter_pid_set_property_full(pid, prop_4cc, NULL, NULL, value, GF_TRUE);
}

GF_EXPORT GF_Err gf_filter_pid_set_info_str(GF_FilterPid *pid, const char *name, const GF_PropertyValue *value)
{
	if (!name) return GF_BAD_PARAM;
	return gf_filter_pid_set_property_full(pid, 0, name, NULL, value, GF_TRUE);
}

GF_EXPORT GF_Err gf_filter_pid_set_info_dyn(GF_FilterPid *pid, char *name, const GF_PropertyValue *value)
{
	if (!name) return GF_BAD_PARAM;
	return gf_filter_pid_set_property_full(pid, 0, NULL, name, value, GF_TRUE);
}

static GF_Err gf_filter_pid_negociate_property_full(GF_FilterPid *pid, u32 prop_4cc, const char *prop_name, char *dyn_name, const GF_PropertyValue *value)
{
	GF_FilterPidInst *pidi = (GF_FilterPidInst *) pid;
	if (!prop_4cc) return GF_BAD_PARAM;

	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to negociate property on output PID in filter %s - ignoring\n", pid->filter->name));
		return GF_BAD_PARAM;
	}
	pid = pid->pid;
	if (!pid->caps_negociate) {
		assert(!pid->caps_negociate_pidi_list);
		pid->caps_negociate = gf_props_new(pid->filter);
		pid->caps_negociate_pidi_list = gf_list_new();
		pid->caps_negociate_direct = GF_TRUE;
		gf_list_add(pid->caps_negociate_pidi_list, pidi);
		
		if (pid->adapters_blacklist) {
			gf_list_del(pid->adapters_blacklist);
			pid->adapters_blacklist = NULL;
		}
		safe_int_inc(&pid->filter->nb_caps_renegociate);
	}
	else {
		const GF_PropertyValue *p;
		
		if (gf_list_find(pid->caps_negociate_pidi_list, pidi)<0) {
			gf_list_add(pid->caps_negociate_pidi_list, pidi);
		}

		
		p = gf_props_get_property(pid->caps_negociate, prop_4cc, prop_name);
		if (p) {
			if (gf_props_equal(p, value))
				return GF_OK;
			
			pid->caps_negociate_direct = GF_FALSE;
		}
	}

	if (gf_log_tool_level_on(GF_LOG_FILTER, GF_LOG_INFO)) {
		char p_dump[GF_PROP_DUMP_ARG_SIZE];
		GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("PID %s negociate property %s to %s\n", pid->filter->name, 	prop_name ? prop_name : gf_props_4cc_get_name(prop_4cc), gf_props_dump(prop_4cc, value, p_dump, GF_PROP_DUMP_DATA_NONE)

		));
	}


	
	if (pid->has_seen_eos || gf_fq_count(pidi->packets)) {
		gf_fs_post_task(pid->filter->session, gf_filter_renegociate_output_task, pid->filter, NULL, "filter renegociate", NULL);
	}
	return gf_props_set_property(pid->caps_negociate, prop_4cc, prop_name, dyn_name, value);
}

GF_EXPORT GF_Err gf_filter_pid_negociate_property(GF_FilterPid *pid, u32 prop_4cc, const GF_PropertyValue *value)
{
	if (!prop_4cc) return GF_BAD_PARAM;
	return gf_filter_pid_negociate_property_full(pid, prop_4cc, NULL, NULL, value);
}

GF_EXPORT GF_Err gf_filter_pid_negociate_property_str(GF_FilterPid *pid, const char *name, const GF_PropertyValue *value)
{
	if (!name) return GF_BAD_PARAM;
	return gf_filter_pid_negociate_property_full(pid, 0, name, NULL, value);
}

GF_EXPORT GF_Err gf_filter_pid_negociate_property_dyn(GF_FilterPid *pid, char *name, const GF_PropertyValue *value)
{
	if (!name) return GF_BAD_PARAM;
	return gf_filter_pid_negociate_property_full(pid, 0, NULL, name, value);
}


static GF_PropertyMap *filter_pid_get_prop_map(GF_FilterPid *pid, Bool first_prop_if_output)
{
	if (PID_IS_INPUT(pid)) {
		GF_FilterPidInst *pidi = (GF_FilterPidInst *) pid;
		
		if (!pidi->props) {
			
			gf_mx_p(pid->filter->tasks_mx);
			pidi->props = gf_list_get(pid->pid->properties, 0);
			gf_mx_v(pid->filter->tasks_mx);
			assert(pidi->props);
			safe_int_inc(&pidi->props->reference_count);
		}
		return pidi->props;
	} else {
		GF_PropertyMap *res_map = NULL;
		pid = pid->pid;
		if (pid->local_props) return pid->local_props;

		
		gf_mx_p(pid->filter->tasks_mx);
		if (first_prop_if_output)
			res_map = gf_list_get(pid->properties, 0);
		else res_map = gf_list_last(pid->properties);
		gf_mx_v(pid->filter->tasks_mx);
		return res_map;
	}
	return NULL;
}

GF_EXPORT const GF_PropertyValue *gf_filter_pid_get_property(GF_FilterPid *pid, u32 prop_4cc)
{
	GF_PropertyMap *map = filter_pid_get_prop_map(pid, GF_FALSE);
	if (!map)
		return NULL;
	return gf_props_get_property(map, prop_4cc, NULL);
}

const GF_PropertyValue *gf_filter_pid_get_property_first(GF_FilterPid *pid, u32 prop_4cc)
{
	GF_PropertyMap *map = filter_pid_get_prop_map(pid, GF_TRUE);
	if (!map)
		return NULL;
	return gf_props_get_property(map, prop_4cc, NULL);
}

GF_EXPORT const GF_PropertyValue *gf_filter_pid_get_property_str(GF_FilterPid *pid, const char *prop_name)
{
	GF_PropertyMap *map = filter_pid_get_prop_map(pid, GF_FALSE);
	if (!map)
		return NULL;
	return gf_props_get_property(map, 0, prop_name);
}

const GF_PropertyValue *gf_filter_pid_get_property_str_first(GF_FilterPid *pid, const char *prop_name)
{
	GF_PropertyMap *map = filter_pid_get_prop_map(pid, GF_TRUE);
	if (!map)
		return NULL;
	return gf_props_get_property(map, 0, prop_name);
}

const GF_PropertyEntry *gf_filter_pid_get_property_entry(GF_FilterPid *pid, u32 prop_4cc)
{
	GF_PropertyMap *map = filter_pid_get_prop_map(pid, GF_FALSE);
	if (!map)
		return NULL;
	return gf_props_get_property_entry(map, prop_4cc, NULL);
}

GF_EXPORT const GF_PropertyEntry *gf_filter_pid_get_property_entry_str(GF_FilterPid *pid, const char *prop_name)
{
	GF_PropertyMap *map = filter_pid_get_prop_map(pid, GF_FALSE);
	if (!map)
		return NULL;
	return gf_props_get_property_entry(map, 0, prop_name);
}

static const GF_PropertyValue *gf_filter_pid_get_info_internal(GF_FilterPid *pid, u32 prop_4cc, const char *prop_name, Bool first_call,  GF_PropertyEntry **propentry)
{
	u32 i;
	const GF_PropertyEntry *prop_ent = NULL;
	GF_PropertyMap *map;
	*propentry = NULL;
	
	if (first_call) {
		gf_mx_p(pid->filter->session->info_mx);
	}
	map = filter_pid_get_prop_map(pid, GF_FALSE);

	if (map) {
		prop_ent = gf_props_get_property_entry(map, prop_4cc, prop_name);
		if (prop_ent) goto exit;
	}
	if (pid->pid->infos) {
		prop_ent = gf_props_get_property_entry(pid->pid->infos, prop_4cc, prop_name);
		if (prop_ent) goto exit;
	}
	if (PID_IS_OUTPUT(pid)) {
		prop_ent = NULL;
		goto exit;
	}
	pid = pid->pid;
	if (pid->infos) {
		prop_ent = gf_props_get_property_entry(pid->infos, prop_4cc, prop_name);
		if (prop_ent) goto exit;
	}

	gf_mx_p(pid->filter->tasks_mx);
	for (i=0; i<pid->filter->num_input_pids; i++) {
		const GF_PropertyValue *prop;
		GF_FilterPid *pidinst = gf_list_get(pid->filter->input_pids, i);
		if (!pidinst->pid) continue;
		if (!pidinst->pid->filter) continue;
		if (pidinst->pid->filter->removed) continue;

		prop = gf_filter_pid_get_info_internal((GF_FilterPid *)pidinst, prop_4cc, prop_name, GF_FALSE, propentry);
		if (prop) {
			prop_ent = *propentry;
			gf_mx_v(pid->filter->tasks_mx);
			goto exit;
		}
	}
	gf_mx_v(pid->filter->tasks_mx);
	prop_ent = NULL;

exit:
	if (first_call) {
		gf_mx_v(pid->filter->session->info_mx);
	}
	if (!prop_ent) {
		*propentry = NULL;
		return NULL;
	}
	if (! (*propentry)) {
		*propentry = (GF_PropertyEntry *) prop_ent;
		safe_int_inc(&prop_ent->reference_count);
	}
	return &prop_ent->prop;
}

GF_EXPORT const GF_PropertyValue *gf_filter_pid_get_info(GF_FilterPid *pid, u32 prop_4cc, GF_PropertyEntry **propentry)
{
	if (!propentry) return NULL;
	if (*propentry) {
		gf_filter_release_property(*propentry);
		*propentry = NULL;
	}
	return gf_filter_pid_get_info_internal(pid, prop_4cc, NULL, GF_TRUE, propentry);
}

GF_EXPORT const GF_PropertyValue *gf_filter_pid_get_info_str(GF_FilterPid *pid, const char *prop_name, GF_PropertyEntry **propentry)
{
	if (!propentry) return NULL;
	if (*propentry) {
		gf_filter_release_property(*propentry);
		*propentry = NULL;
	}
	return gf_filter_pid_get_info_internal(pid, 0, prop_name, GF_TRUE, propentry);
}

GF_EXPORT const GF_PropertyValue *gf_filter_pid_enum_info(GF_FilterPid *pid, u32 *idx, u32 *prop_4cc, const char **prop_name)
{
	u32 i, cur_idx=0, nb_in_pid=0;

	if (PID_IS_OUTPUT(pid)) {
		return NULL;
	}
	pid = pid->pid;
	cur_idx = *idx;
	if (pid->infos) {
		cur_idx = *idx;
		const GF_PropertyValue *prop = gf_props_enum_property(pid->infos, &cur_idx, prop_4cc, prop_name);
		if (prop) {
			*idx = cur_idx;
			return prop;
		}
		nb_in_pid = cur_idx;
		cur_idx = *idx - nb_in_pid;
	}

	gf_mx_p(pid->filter->tasks_mx);
	for (i=0; i<pid->filter->num_input_pids; i++) {
		u32 sub_idx = cur_idx;
		const GF_PropertyValue * prop;
		GF_FilterPid *pidinst = gf_list_get(pid->filter->input_pids, i);
		prop = gf_filter_pid_enum_info((GF_FilterPid *)pidinst, &sub_idx, prop_4cc, prop_name);
		if (prop) {
			*idx = nb_in_pid + sub_idx;
			gf_mx_v(pid->filter->tasks_mx);
			return prop;
		}
		nb_in_pid += sub_idx;
		cur_idx = *idx - nb_in_pid;
	}
	gf_mx_v(pid->filter->tasks_mx);
	return NULL;
}


static const GF_PropertyValue *gf_filter_get_info_internal(GF_Filter *filter, u32 prop_4cc, const char *prop_name, GF_PropertyEntry **propentry)
{
	u32 i;
	const GF_PropertyValue *prop=NULL;

	gf_mx_p(filter->session->info_mx);
	gf_mx_p(filter->tasks_mx);

	
	for (i=0; i<filter->num_output_pids; i++) {
		GF_FilterPid *pid = gf_list_get(filter->output_pids, i);
		prop = gf_filter_pid_get_info_internal(pid, prop_4cc, prop_name, GF_FALSE, propentry);
		if (prop) {
			gf_mx_v(filter->tasks_mx);
			gf_mx_v(filter->session->info_mx);
			return prop;
		}
	}
	for (i=0; i<filter->num_input_pids; i++) {
		GF_FilterPidInst *pidinst = gf_list_get(filter->input_pids, i);
		prop = gf_filter_pid_get_info_internal(pidinst->pid, prop_4cc, prop_name, GF_FALSE, propentry);
		if (prop) {
			gf_mx_v(filter->tasks_mx);
			gf_mx_v(filter->session->info_mx);
			return prop;
		}
	}
	gf_mx_v(filter->tasks_mx);
	gf_mx_v(filter->session->info_mx);
	return NULL;
}

GF_EXPORT const GF_PropertyValue *gf_filter_get_info(GF_Filter *filter, u32 prop_4cc, GF_PropertyEntry **propentry)
{
	if (!propentry) return NULL;
	if (*propentry) {
		gf_filter_release_property(*propentry);
		*propentry = NULL;
	}
	return gf_filter_get_info_internal(filter, prop_4cc, NULL, propentry);
}

GF_EXPORT const GF_PropertyValue *gf_filter_get_info_str(GF_Filter *filter, const char *prop_name, GF_PropertyEntry **propentry)
{
	if (!propentry) return NULL;
	if (*propentry) {
		gf_filter_release_property(*propentry);
		*propentry = NULL;
	}
	return gf_filter_get_info_internal(filter, 0, prop_name, propentry);
}

GF_EXPORT void gf_filter_release_property(GF_PropertyEntry *propentry)
{
	if (propentry) {
		gf_props_del_property(propentry);
	}
}

GF_EXPORT GF_Err gf_filter_pid_reset_properties(GF_FilterPid *pid)
{
	GF_PropertyMap *map;

	if (PID_IS_INPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to reset all properties on input PID in filter %s - ignoring\n", pid->filter->name));
		return GF_BAD_PARAM;
	}
	
	map = check_new_pid_props(pid, GF_FALSE);

	if (!map) {
		GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("No properties for destination pid in filter %s, ignoring reset\n", pid->filter->name));
		return GF_OUT_OF_MEM;
	}
	gf_props_reset(map);
	return GF_OK;

}

static GF_Err gf_filter_pid_merge_properties_internal(GF_FilterPid *dst_pid, GF_FilterPid *src_pid, gf_filter_prop_filter filter_prop, void *cbk, Bool is_merge)
{
	GF_PropertyMap *dst_props, *src_props = NULL, *old_dst_props=NULL;
	if (PID_IS_INPUT(dst_pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to reset all properties on input PID in filter %s - ignoring\n", dst_pid->filter->name));
		return GF_BAD_PARAM;
	}
	if (is_merge) {
		gf_mx_p(src_pid->filter->tasks_mx);
		old_dst_props = gf_list_last(dst_pid->properties);
		gf_mx_v(src_pid->filter->tasks_mx);
	}

	
	dst_props = check_new_pid_props(dst_pid, GF_FALSE);

	if (!dst_props) {
		GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("No properties for destination pid in filter %s, ignoring reset\n", dst_pid->filter->name));
		return GF_OUT_OF_MEM;
	}
	
	if (PID_IS_INPUT(src_pid)) {
		GF_FilterPidInst *pidi = (GF_FilterPidInst *)src_pid;
		if (!pidi->props) {
			
			gf_mx_p(src_pid->filter->tasks_mx);
			pidi->props = gf_list_get(src_pid->pid->properties, 0);
			gf_mx_v(src_pid->filter->tasks_mx);
			assert(pidi->props);
			safe_int_inc(&pidi->props->reference_count);
		}
		src_props = pidi->props;
	}
	
	src_pid = src_pid->pid;
	
	if (!src_props) {
		
		
		gf_mx_p(src_pid->filter->tasks_mx);
		src_props = gf_list_last(src_pid->properties);
		gf_mx_v(src_pid->filter->tasks_mx);
		if (!src_props) {
			GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("No properties to copy from pid %s in filter %s, ignoring merge\n", src_pid->name, src_pid->filter->name));
			return GF_OK;
		}
	}
	if (src_pid->name && !old_dst_props)
		gf_filter_pid_set_name(dst_pid, src_pid->name);

	if (!is_merge) {
		gf_props_reset(dst_props);
	} else {
		
		if (old_dst_props && (old_dst_props!=dst_props)) {
			GF_Err e = gf_props_merge_property(dst_props, old_dst_props, NULL, NULL);
			if (e) return e;
		}
	}
	return gf_props_merge_property(dst_props, src_props, filter_prop, cbk);
}

GF_EXPORT GF_Err gf_filter_pid_merge_properties(GF_FilterPid *dst_pid, GF_FilterPid *src_pid, gf_filter_prop_filter filter_prop, void *cbk )
{
	return gf_filter_pid_merge_properties_internal(dst_pid, src_pid, filter_prop, cbk, GF_TRUE);
}
GF_EXPORT GF_Err gf_filter_pid_copy_properties(GF_FilterPid *dst_pid, GF_FilterPid *src_pid)
{
	return gf_filter_pid_merge_properties_internal(dst_pid, src_pid, NULL, NULL, GF_FALSE);
}

GF_EXPORT u32 gf_filter_pid_get_packet_count(GF_FilterPid *pid)
{
	GF_FilterPidInst *pidinst = (GF_FilterPidInst *)pid;
	if (PID_IS_OUTPUT(pid)) {
		pidinst = gf_list_get(pid->destinations, 0);
		if (! pidinst) return 0;
		return gf_fq_count(pidinst->packets) - pidinst->nb_eos_signaled - pidinst->nb_clocks_signaled;

	} else {
		if (pidinst->discard_packets) return 0;
		return gf_fq_count(pidinst->packets) - pidinst->nb_eos_signaled - pidinst->nb_clocks_signaled;
	}
}

static Bool gf_filter_pid_filter_internal_packet(GF_FilterPidInst *pidi, GF_FilterPacketInstance *pcki)
{
	Bool is_internal = GF_FALSE;
	u32 ctype = (pcki->pck->info.flags & GF_PCK_CMD_MASK);
	if (ctype == GF_PCK_CMD_PID_EOS ) {
		pcki->pid->is_end_of_stream = pcki->pid->pid->has_seen_eos ? GF_TRUE : GF_FALSE;
		GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Found EOS packet in PID %s in filter %s - eos %d\n", pidi->pid->name, pidi->filter->name, pcki->pid->pid->has_seen_eos));
		assert(pcki->pid->nb_eos_signaled);
		safe_int_dec(&pcki->pid->nb_eos_signaled);
		is_internal = GF_TRUE;
	} else if (ctype == GF_PCK_CMD_PID_REM) {
		gf_fs_post_task(pidi->filter->session, gf_filter_pid_disconnect_task, pidi->filter, pidi->pid, "pidinst_disconnect", NULL);

		is_internal = GF_TRUE;
	}
	ctype = (pcki->pck->info.flags & GF_PCK_CKTYPE_MASK) >> GF_PCK_CKTYPE_POS;

	if (ctype) {
		u32 timescale;
		if (pcki->pid->handles_clock_references) return GF_FALSE;
		assert(pcki->pid->nb_clocks_signaled);
		safe_int_dec(&pcki->pid->nb_clocks_signaled);
		
		assert(!pcki->pid->filter->next_clock_dispatch_type || !pcki->pid->filter->num_output_pids);

		timescale = pcki->pck->pid_props ? pcki->pck->pid_props->timescale : 0;
		pcki->pid->filter->next_clock_dispatch = pcki->pck->info.cts;
		pcki->pid->filter->next_clock_dispatch_timescale = timescale;
		pcki->pid->filter->next_clock_dispatch_type = ctype;

		
		pcki->pid->last_clock_value = pcki->pck->info.cts;
		pcki->pid->last_clock_timescale = timescale;
		if (pcki->pid->last_clock_type != GF_FILTER_CLOCK_PCR_DISC)
			pcki->pid->last_clock_type = ctype;

		if (ctype == GF_FILTER_CLOCK_PCR_DISC) {
			assert(pcki->pid->last_clock_type == GF_FILTER_CLOCK_PCR_DISC);
		}
		GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Internal clock reference packet filtered - PID %s clock ref "LLU"/%d - type %d\n", pcki->pid->pid->name, pcki->pid->last_clock_value, pcki->pid->last_clock_timescale, pcki->pid->last_clock_type));
		
		is_internal = GF_TRUE;
	}

	if (is_internal) gf_filter_pid_drop_packet((GF_FilterPid *)pidi);
	return is_internal;
}

static Bool filter_pck_check_prop_change(GF_FilterPidInst *pidinst, GF_FilterPacketInstance *pcki, Bool do_notif)
{
	if ( (pcki->pck->info.flags & GF_PCKF_PROPS_CHANGED) && !pcki->pid_props_change_done) {
		GF_Err e;
		Bool skip_props = GF_FALSE;

		pcki->pid_props_change_done = 1;

		
		
		
		if (pidinst->props) {
			if (pidinst->force_reconfig || (pidinst->props != pcki->pck->pid_props)) {
				
				
				assert(pidinst->props->reference_count);
				if (safe_int_dec(& pidinst->props->reference_count) == 0) {
					
					gf_mx_p(pidinst->pid->filter->tasks_mx);
					gf_list_del_item(pidinst->pid->properties, pidinst->props);
					gf_mx_v(pidinst->pid->filter->tasks_mx);
					gf_props_del(pidinst->props);
				}
				pidinst->force_reconfig = GF_FALSE;
				
				pidinst->props = pcki->pck->pid_props;
				safe_int_inc( & pidinst->props->reference_count );
			} else {
				
				
				skip_props = GF_TRUE;
				if (do_notif) {
					GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter %s PID %s was already configured with the last property set, ignoring reconfigure\n", pidinst->pid->filter->name, pidinst->pid->name));
				}
			}
		}
		if (!skip_props) {
			if (do_notif) {
				GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Filter %s PID %s property changed at this packet, triggering reconfigure\n", pidinst->pid->filter->name, pidinst->pid->name));

				assert(pidinst->filter->freg->configure_pid);
			}

			
			
			
			gf_list_reset(pidinst->filter->blacklisted);

			if (do_notif) {
				e = gf_filter_pid_configure(pidinst->filter, pidinst->pid, GF_PID_CONF_RECONFIG);
				if (e != GF_OK) return GF_TRUE;
				if (pidinst->pid->caps_negociate)
					return GF_TRUE;
			}
		}
	}
	return GF_FALSE;
}

GF_EXPORT GF_FilterPacket *gf_filter_pid_get_packet(GF_FilterPid *pid)
{
	GF_FilterPacketInstance *pcki;
	GF_FilterPidInst *pidinst = (GF_FilterPidInst *)pid;

	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to fetch a packet on an output PID in filter %s\n", pid->filter->name));
		return NULL;
	}
	if (pidinst->discard_packets || (!pidinst->force_flush && pidinst->detach_pending)) {
		pidinst->filter->nb_pck_io++;
		return NULL;
	}

restart:
	pcki = (GF_FilterPacketInstance *)gf_fq_head(pidinst->packets);
	
	if (!pcki) {
		if (!pidinst->pid || !pidinst->pid->filter || !pidinst->filter) return NULL;
		if (pidinst->pid->filter->disabled) {
			pidinst->is_end_of_stream = pidinst->pid->has_seen_eos = GF_TRUE;
		}
		if (!pidinst->is_end_of_stream && pidinst->pid->filter->would_block)
			gf_filter_pid_check_unblock(pidinst->pid);
		pidinst->filter->nb_pck_io++;
		return NULL;
	}
	assert(pcki->pck);

	if (gf_filter_pid_filter_internal_packet(pidinst, pcki)) {
		
		goto restart;
	}
	pcki->pid->is_end_of_stream = GF_FALSE;

	if (filter_pck_check_prop_change(pidinst, pcki, GF_TRUE))
		return NULL;

	if ( (pcki->pck->info.flags & GF_PCKF_INFO_CHANGED) && !pcki->pid_info_change_done) {
		Bool res=GF_FALSE;

		
		
		if (pidinst->filter->freg->process_event && pidinst->filter->process_th_id && (pidinst->filter->process_th_id != gf_th_id()) ) {
			return NULL;
		}
		pcki->pid_info_change_done = 1;

		if (pidinst->filter->freg->process_event) {
			GF_FilterEvent evt;
			GF_FEVT_INIT(evt, GF_FEVT_INFO_UPDATE, pid);

			
			
			res = pidinst->filter->freg->process_event(pidinst->filter, &evt);
		}
		
		if (!res) {
			pidinst->filter->pid_info_changed = GF_TRUE;
		}
	}
	pidinst->last_pck_fetch_time = gf_sys_clock_high_res();

	return (GF_FilterPacket *)pcki;
}

static GF_FilterPacketInstance *gf_filter_pid_probe_next_packet(GF_FilterPidInst *pidinst)
{
	u32 i=0;
	
	
	while (1) {
		GF_FilterPacketInstance *pcki = (GF_FilterPacketInstance *)gf_fq_get(pidinst->packets, i);
		if (!pcki) break;
		i++;

		u32 ctype = (pcki->pck->info.flags & GF_PCK_CMD_MASK);
		if (ctype == GF_PCK_CMD_PID_EOS ) {
			break;
		} else if (ctype == GF_PCK_CMD_PID_REM) {
			break;
		}
		ctype = (pcki->pck->info.flags & GF_PCK_CKTYPE_MASK) >> GF_PCK_CKTYPE_POS;

		if (ctype) {
			if (pcki->pid->handles_clock_references) return NULL;

			gf_filter_pid_filter_internal_packet(pidinst, pcki);
			return gf_filter_pid_probe_next_packet(pidinst);
		}
		return pcki;
	}
	return NULL;
}

GF_EXPORT Bool gf_filter_pid_get_first_packet_cts(GF_FilterPid *pid, u64 *cts)
{
	GF_FilterPacketInstance *pcki;
	GF_FilterPidInst *pidinst = (GF_FilterPidInst *)pid;
	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to read packet CTS on an output PID in filter %s\n", pid->filter->name));
		return GF_FALSE;
	}
	if (pidinst->discard_packets) return GF_FALSE;

	pcki = gf_filter_pid_probe_next_packet(pidinst);
	
	if (!pcki) {
		return GF_FALSE;
	}
	assert(pcki->pck);
	if (pidinst->requires_full_data_block && !(pcki->pck->info.flags & GF_PCKF_BLOCK_END))
		return GF_FALSE;

	GF_PropertyMap *map = gf_list_get(pidinst->pid->properties, 0);
	if (map)
		*cts = gf_timestamp_rescale(pcki->pck->info.cts, pcki->pck->pid_props->timescale, map->timescale);
	else *cts = pcki->pck->info.cts;
	return GF_TRUE;
}

GF_EXPORT Bool gf_filter_pid_first_packet_is_empty(GF_FilterPid *pid)
{
	GF_FilterPacketInstance *pcki;
	GF_FilterPidInst *pidinst = (GF_FilterPidInst *)pid;
	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to read packet CTS on an output PID in filter %s\n", pid->filter->name));
		return GF_TRUE;
	}
	if (pidinst->discard_packets) return GF_TRUE;

	pcki = gf_filter_pid_probe_next_packet(pidinst);
	
	if (!pcki) {
		return GF_TRUE;
	}
	assert(pcki->pck);

	if (pidinst->requires_full_data_block && !(pcki->pck->info.flags & GF_PCKF_BLOCK_END))
		return GF_TRUE;
	return (pcki->pck->data_length || pcki->pck->frame_ifce) ? GF_FALSE : GF_TRUE;
}

GF_EXPORT Bool gf_filter_pid_first_packet_is_blocking_ref(GF_FilterPid *pid)
{
	GF_FilterPacketInstance *pcki;
	GF_FilterPidInst *pidinst = (GF_FilterPidInst *)pid;
	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to read packet CTS on an output PID in filter %s\n", pid->filter->name));
		return GF_FALSE;
	}
	if (pidinst->discard_packets) return GF_FALSE;

	pcki = gf_filter_pid_probe_next_packet(pidinst);
	
	if (!pcki) {
		return GF_FALSE;
	}
	assert(pcki->pck);
	return gf_filter_pck_is_blocking_ref(pcki->pck);
}


static void gf_filter_pidinst_update_stats(GF_FilterPidInst *pidi, GF_FilterPacket *pck)
{
	u64 now = gf_sys_clock_high_res();
	u64 dec_time = now - pidi->last_pck_fetch_time;
	if (pck->info.flags & GF_PCK_CMD_MASK) return;
	if (!pidi->filter || pidi->pid->filter->removed) return;

	pidi->filter->nb_pck_processed++;
	pidi->filter->nb_bytes_processed += pck->data_length;

	pidi->total_process_time += dec_time;
	if (!pidi->nb_processed) {
		pidi->first_frame_time = pidi->last_pck_fetch_time;
	}

	pidi->nb_processed++;
	if (pck->info.flags & GF_PCK_SAP_MASK) {
		pidi->nb_sap_processed ++;
		if (dec_time > pidi->max_sap_process_time) pidi->max_sap_process_time = dec_time;
		pidi->total_sap_process_time += dec_time;
	}

	if (dec_time > pidi->max_process_time) pidi->max_process_time = dec_time;

	if (pck->data_length) {
		Bool has_ts = GF_TRUE;
		u64 ts = (pck->info.dts != GF_FILTER_NO_TS) ? pck->info.dts : pck->info.cts;
		if ((ts != GF_FILTER_NO_TS) && pck->pid_props && pck->pid_props->timescale) {
			ts = gf_timestamp_rescale(ts, pck->pid_props->timescale, 1000000);
		} else {
			has_ts = GF_FALSE;
		}
		
		if (!pidi->cur_bit_size) {
			pidi->stats_start_ts = ts;
			pidi->stats_start_us = now;
			pidi->cur_bit_size = 8*pck->data_length;
		} else {
			Bool flush_stats = GF_FALSE;
			pidi->cur_bit_size += 8*pck->data_length;

			if (has_ts) {
				if (pidi->stats_start_ts + 1000000 <= ts) flush_stats = GF_TRUE;
			} else {
				if (pidi->stats_start_us + 1000000 <= now) flush_stats = GF_TRUE;
			}

			if (flush_stats) {
				u64 rate;
				u64 diff_t;

				if (has_ts) {
					rate = pidi->cur_bit_size;
					rate *= 1000000;
					diff_t = ts - pidi->stats_start_ts;
					if (!diff_t) diff_t = 1;
 					rate /= diff_t;
					pidi->avg_bit_rate = (u32) rate;
					if (pidi->avg_bit_rate > pidi->max_bit_rate) pidi->max_bit_rate = pidi->avg_bit_rate;
				}

				rate = pidi->cur_bit_size;
				rate *= 1000000;
				diff_t = now - pidi->stats_start_us;
				if (!diff_t) diff_t = 1;
				rate /= diff_t;
				pidi->avg_process_rate = (u32) rate;
				if (pidi->avg_process_rate > pidi->max_process_rate) pidi->max_process_rate = pidi->avg_process_rate;

				
				pidi->cur_bit_size = 0;
			}
		}
	}
}

static void gf_filter_pidinst_reset_stats(GF_FilterPidInst *pidi)
{
	pidi->last_pck_fetch_time = 0;
	pidi->stats_start_ts = 0;
	pidi->stats_start_us = 0;
	pidi->cur_bit_size = 0;
	pidi->avg_bit_rate = 0;
	pidi->max_bit_rate = 0;
	pidi->avg_process_rate = 0;
	pidi->max_process_rate = 0;
	pidi->nb_processed = 0;
	pidi->nb_sap_processed = 0;
	pidi->total_process_time = 0;
	pidi->total_sap_process_time = 0;
	pidi->max_process_time = 0;
	pidi->max_sap_process_time = 0;
	pidi->first_frame_time = 0;
}

GF_EXPORT void gf_filter_pid_drop_packet(GF_FilterPid *pid)
{

	u32 prev_nb_allocs, prev_nb_reallocs, nb_allocs, nb_reallocs;

	u32 timescale = 0;
	u32 nb_pck=0;
	GF_FilterPacket *pck=NULL;
	GF_FilterPacketInstance *pcki;
	GF_FilterPidInst *pidinst = (GF_FilterPidInst *)pid;

	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to discard a packet on an output PID in filter %s\n", pid->filter->name));
		return;
	}
	if (pidinst->filter)
		pidinst->filter->nb_pck_io++;

	
	pcki = gf_fq_pop(pidinst->packets);

	if (!pcki) {
		if (pidinst->filter && !pidinst->filter->finalized && !pidinst->discard_packets) {
			GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("Attempt to discard a packet already discarded in filter %s\n", pid->filter->name));
		}
		return;
	}

	gf_rmt_begin(pck_drop, GF_RMT_AGGREGATE);
	pck = pcki->pck;
	
	pid = pid->pid;
	if (pck->pid_props)
		timescale = pck->pid_props->timescale;

	
	if (pidinst->filter && (pck->info.flags & GF_PCKF_FORCE_MAIN)) {
		assert(pidinst->filter->nb_main_thread_forced);
		safe_int_dec(&pidinst->filter->nb_main_thread_forced);
	}

	gf_filter_pidinst_update_stats(pidinst, pck);
	if (timescale && (pck->info.cts!=GF_FILTER_NO_TS)) {
		pidinst->last_ts_drop.num = pck->info.cts;
		pidinst->last_ts_drop.den = timescale;
	}


	
	
	gf_mx_p(pid->filter->tasks_mx);
	nb_pck = gf_fq_count(pidinst->packets);

	if (!nb_pck) {
		safe_int64_sub(&pidinst->buffer_duration, pidinst->buffer_duration);
	} else if (pck->info.duration && (pck->info.flags & GF_PCKF_BLOCK_START) && timescale) {
		s64 d = gf_timestamp_rescale(pck->info.duration, timescale, 1000000);
		if (d > pidinst->buffer_duration) {
			GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("Corrupted buffer level in PID instance %s (%s -> %s), dropping packet duration "LLD" us greater than buffer duration "LLU" us\n", pid->name, pid->filter->name, pidinst->filter ? pidinst->filter->name : "disconnected", d, pidinst->buffer_duration));
			d = pidinst->buffer_duration;
		}
		assert(d <= pidinst->buffer_duration);
		safe_int64_sub(&pidinst->buffer_duration, (s32) d);
	}

	if ( (pid->num_destinations==1) || (pid->filter->session->blocking_mode==GF_FS_NOBLOCK_FANOUT)) {
		if (nb_pck<pid->nb_buffer_unit) {
			pid->nb_buffer_unit = nb_pck;
		}
		if (!pid->buffer_duration || (pidinst->buffer_duration < (s64) pid->buffer_duration)) {
			pid->buffer_duration = pidinst->buffer_duration;
		}
	}
	
	
	else {
		u32 i;
		u32 min_pck = nb_pck;
		s64 min_dur = pidinst->buffer_duration;
		for (i=0; i<pid->num_destinations; i++) {
			GF_FilterPidInst *a_pidi = gf_list_get(pid->destinations, i);
			if (a_pidi==pidinst) continue;
			if (a_pidi->buffer_duration > min_dur)
				min_dur = a_pidi->buffer_duration;
			nb_pck = gf_fq_count(a_pidi->packets);
			if (nb_pck>min_pck)
				min_pck = nb_pck;
		}
		pid->buffer_duration = min_dur;
		pid->nb_buffer_unit = min_pck;
	}
	gf_filter_pid_check_unblock(pid);

	gf_mx_v(pid->filter->tasks_mx);


	if (gf_log_tool_level_on(GF_LOG_FILTER, GF_LOG_DEBUG)) {
		u8 sap_type = (pck->info.flags & GF_PCK_SAP_MASK) >> GF_PCK_SAP_POS;
		Bool seek_flag = (pck->info.flags & GF_PCKF_SEEK) ? 1 : 0;

		if ((pck->info.dts != GF_FILTER_NO_TS) && (pck->info.cts != GF_FILTER_NO_TS) ) {
			GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter %s PID %s (%s) drop packet DTS "LLU" CTS "LLU" SAP %d Seek %d - %d packets remaining buffer "LLU" us\n", pidinst->filter ? pidinst->filter->name : "disconnected", pid->name, pid->filter->name, pck->info.dts, pck->info.cts, sap_type, seek_flag, nb_pck, pidinst->buffer_duration));
		} else if ((pck->info.cts != GF_FILTER_NO_TS) ) {
			GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter %s PID %s (%s) drop packet CTS "LLU" SAP %d Seek %d - %d packets remaining buffer "LLU" us\n", pidinst->filter ? pidinst->filter->name : "disconnected", pid->name, pid->filter->name, pck->info.cts, sap_type, seek_flag, nb_pck, pidinst->buffer_duration));
		} else if ((pck->info.dts != GF_FILTER_NO_TS) ) {
			GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter %s PID %s (%s) drop packet DTS "LLU" SAP %d Seek %d - %d packets remaining buffer "LLU" us\n", pidinst->filter ? pidinst->filter->name : "disconnected", pid->name, pid->filter->name, pck->info.dts, sap_type, seek_flag, nb_pck, pidinst->buffer_duration));
		} else {
			GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter %s PID %s (%s) drop packet SAP %d Seek %d - %d packets remaining buffer "LLU" us\n", pidinst->filter ? pidinst->filter->name : "disconnected", pid->name, pid->filter->name, sap_type, seek_flag, nb_pck, pidinst->buffer_duration));
		}
	}


	
	pcki->pck = NULL;
	pcki->pid = NULL;


	if (pid->filter && pid->filter->session->check_allocs) {
		gf_mem_get_stats(&prev_nb_allocs, NULL, &prev_nb_reallocs, NULL);
	}


	if (pid->filter->pcks_inst_reservoir) {
		gf_fq_add(pid->filter->pcks_inst_reservoir, pcki);
	} else {
		gf_free(pcki);
	}
	
	assert(pck->reference_count);
	if (safe_int_dec(&pck->reference_count) == 0) {
		gf_filter_packet_destroy(pck);
	}


	if (pid->filter && pid->filter->session->check_allocs) {
		gf_mem_get_stats(&nb_allocs, NULL, &nb_reallocs, NULL);

		pid->filter->session->nb_alloc_pck += (nb_allocs - prev_nb_allocs);
		pid->filter->session->nb_realloc_pck += (nb_reallocs - prev_nb_reallocs);
	}


	
	if (pidinst->filter) {
		assert(pidinst->filter->pending_packets);
		safe_int_dec(&pidinst->filter->pending_packets);

		gf_filter_forward_clock(pidinst->filter);
	}

	gf_rmt_end();
}

GF_EXPORT Bool gf_filter_pid_is_eos(GF_FilterPid *pid)
{
	GF_FilterPacketInstance *pcki;
	GF_FilterPidInst *pidi = (GF_FilterPidInst *)pid;

	if (pidi->detach_pending)
		return GF_FALSE;
		
	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to query EOS on output PID %s in filter %s\n", pid->pid->name, pid->filter->name));
		return GF_FALSE;
	}
	if (!pid->pid) return GF_TRUE;
	if (!pid->pid->has_seen_eos && !pidi->discard_inputs && !pidi->discard_packets) {
		pidi->is_end_of_stream = GF_FALSE;
		return GF_FALSE;
	}
	
	pcki = (GF_FilterPacketInstance *)gf_fq_head(pidi->packets);
	if (pcki)
		gf_filter_pid_filter_internal_packet(pidi, pcki);

	if (pidi->discard_packets && !pid->pid->filter->session->in_final_flush) return GF_FALSE;
	if (!pidi->is_end_of_stream) return GF_FALSE;
	if (!pidi->filter->eos_probe_state)
		pidi->filter->eos_probe_state = 1;
	return GF_TRUE;
}

GF_EXPORT void gf_filter_pid_set_eos(GF_FilterPid *pid)
{
	GF_FilterPacket *pck;
	
	if (!pid) return;

	if (PID_IS_INPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to signal EOS on input PID %s in filter %s\n", pid->pid->name, pid->filter->name));
		return;
	}
	if (pid->has_seen_eos) return;

	GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("EOS signaled on PID %s in filter %s\n", pid->name, pid->filter->name));
	
	pck = gf_filter_pck_new_shared_internal(pid, NULL, 0, NULL, GF_TRUE);
	if (!pck) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Failed to allocate new packet for EOS on PID %s in filter %s\n", pid->name, pid->filter->name));
		return;
	}
	gf_filter_pck_set_framing(pck, GF_TRUE, GF_TRUE);
	pck->pck->info.flags |= GF_PCK_CMD_PID_EOS;
	gf_filter_pck_send(pck);
}

GF_EXPORT const GF_PropertyValue *gf_filter_pid_enum_properties(GF_FilterPid *pid, u32 *idx, u32 *prop_4cc, const char **prop_name)
{
	GF_PropertyMap *props;

	if (PID_IS_INPUT(pid)) {
		GF_FilterPidInst *pidi = (GF_FilterPidInst *)pid;
		gf_mx_p(pid->filter->tasks_mx);
		props = pidi->props;
		gf_mx_v(pid->filter->tasks_mx);
	} else {
		gf_mx_p(pid->filter->tasks_mx);
		props = gf_list_last(pid->properties);
		gf_mx_v(pid->filter->tasks_mx);
	}
	if (!props) {
		GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("No properties for pid in filter %s, ignoring enum\n", pid->filter->name));
		*idx = 0xFFFFFFFF;
		return NULL;
	}
	return gf_props_enum_property(props, idx, prop_4cc, prop_name);
}

GF_EXPORT Bool gf_filter_pid_would_block(GF_FilterPid *pid)
{
	Bool would_block=GF_FALSE;
	Bool result=GF_FALSE;

	Bool blockmode_broken=GF_FALSE;

	if (PID_IS_INPUT(pid)) {
		pid = pid->pid;
		if (pid->would_block) return GF_TRUE;
		return GF_FALSE;
	}

	if (pid->filter->session->blocking_mode==GF_FS_NOBLOCK)
		return GF_FALSE;
	
	if (pid->filter->in_force_flush)
		return GF_FALSE;

	gf_mx_p(pid->filter->tasks_mx);
	
	if (pid->max_buffer_unit) {
		if (pid->nb_buffer_unit * GF_FILTER_SPEED_SCALER >= pid->max_buffer_unit * pid->playback_speed_scaler) {
			would_block = GF_TRUE;
		}

		if ((pid->num_destinations==1) && !pid->filter->blockmode_broken && ( (pid->nb_buffer_unit * GF_FILTER_SPEED_SCALER > 100 * pid->max_buffer_unit * pid->playback_speed_scaler) ) ) {
			blockmode_broken = GF_TRUE;
		}

	} else if (pid->max_buffer_time) {
		if (pid->buffer_duration * GF_FILTER_SPEED_SCALER > pid->max_buffer_time * pid->playback_speed_scaler) {
			would_block = GF_TRUE;
		}

		if ((pid->num_destinations==1) && !pid->filter->blockmode_broken && (pid->buffer_duration * GF_FILTER_SPEED_SCALER > 100 * pid->max_buffer_time * pid->playback_speed_scaler) ) {
			blockmode_broken = GF_TRUE;
		}

	}


	if (blockmode_broken) {
		GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("Filter %s PID %s block mode not respected: %u units "LLU" us vs %u max units "LLU" max buffer\n", pid->pid->filter->name, pid->pid->name, pid->nb_buffer_unit, pid->buffer_duration, pid->max_buffer_unit, pid->max_buffer_time));

		pid->filter->blockmode_broken = GF_TRUE;
	}


	result = would_block;
	
	
	
	
	
	if (!pid->would_block && pid->is_sparse && !pid->not_connected && (pid->filter->num_output_pids > 1+pid->filter->num_out_pids_not_connected)
		
		&& (pid->filter->nb_sparse_pids + pid->filter->num_out_pids_not_connected < pid->filter->num_output_pids)
	)
		would_block = GF_TRUE;

	if (would_block && !pid->would_block) {
		safe_int_inc(&pid->would_block);
		safe_int_inc(&pid->filter->would_block);
		assert(pid->filter->would_block + pid->filter->num_out_pids_not_connected <= pid->filter->num_output_pids);


		if (gf_log_tool_level_on(GF_LOG_FILTER, GF_LOG_DEBUG)) {
			if (pid->max_buffer_unit) {
				GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter %s PID %s blocked (%d units vs %d max units) - %d filter PIDs blocked\n", pid->pid->filter->name, pid->pid->name, pid->nb_buffer_unit, pid->max_buffer_unit, pid->filter->would_block));
			} else {
				GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter %s PID %s blocked ("LLU" us vs "LLU" max buffer) - %d filter PIDs blocked\n", pid->pid->filter->name, pid->pid->name, pid->buffer_duration, pid->max_buffer_time, pid->filter->would_block));
			}
		}

	}
	assert(pid->filter->would_block <= pid->filter->num_output_pids);
	gf_mx_v(pid->filter->tasks_mx);
	return result;
}

GF_EXPORT Bool gf_filter_pid_is_sparse(GF_FilterPid *pid)
{
	if (!pid) return GF_FALSE;
	return pid->pid->is_sparse;
}

static u64 gf_filter_pid_query_buffer_duration_internal(GF_FilterPid *pid, Bool check_pid_full, Bool force_update)
{
	u32 count, i, j;
	u64 duration=0;
	if (!pid || pid->filter->session->in_final_flush)
		return GF_FILTER_NO_TS;

	if (PID_IS_INPUT(pid)) {
		GF_Filter *filter;
		GF_FilterPidInst *pidinst = (GF_FilterPidInst *)pid;
		if (!pidinst->pid) return 0;
		filter = pidinst->pid->filter;
		if (check_pid_full) {
			u32 buffer_full = GF_FALSE;
			Bool buffer_valid = GF_FALSE;

			if (pidinst->pid->max_buffer_unit) {
				buffer_valid = GF_TRUE;
				if (pidinst->pid->max_buffer_unit<=pidinst->pid->nb_buffer_unit)
					buffer_full = GF_TRUE;
			}
			if (pidinst->pid->max_buffer_time) {
				buffer_valid = GF_TRUE;
				if (pidinst->pid->max_buffer_time<=pidinst->pid->buffer_duration)
					buffer_full = GF_TRUE;
			}

			if (buffer_valid) {
				if (!buffer_full) {
					return 0;
				}
				if (pidinst->pid->max_buffer_unit<=pidinst->pid->nb_buffer_unit)
					return GF_FILTER_NO_TS;
			}
		}

		
		
		
		if (!force_update && (pidinst->filter->last_schedule_task_time - pidinst->last_buf_query_clock < 10000)) {
			return pidinst->last_buf_query_dur;
		}
		pidinst->last_buf_query_clock = pidinst->filter->last_schedule_task_time;
		force_update = GF_TRUE;

		gf_mx_p(filter->tasks_mx);
		count = filter->num_input_pids;
		for (i=0; i<count; i++) {
			u64 dur = gf_filter_pid_query_buffer_duration_internal( gf_list_get(filter->input_pids, i), GF_FALSE, force_update);
			if (dur > duration)
				duration = dur;

			
			
			if ((count>1) && (filter->num_output_pids==1))
				break;
		}
		gf_mx_v(filter->tasks_mx);
		duration += pidinst->buffer_duration;
		pidinst->last_buf_query_dur = duration;
		return duration;
	} else {
		u32 count2;
		u64 max_dur=0;

		if (check_pid_full) {
			if (pid->max_buffer_unit && (pid->max_buffer_unit>pid->nb_buffer_unit))
				return 0;
			if (pid->max_buffer_time && (pid->max_buffer_time>pid->buffer_duration))
				return 0;
		}

		count = pid->num_destinations;
		for (i=0; i<count; i++) {
			GF_FilterPidInst *pidinst = gf_list_get(pid->destinations, i);

			count2 = pidinst->filter->num_output_pids;
			for (j=0; j<count2; j++) {
				GF_FilterPid *pid_n = gf_list_get(pidinst->filter->output_pids, i);
				u64 dur = gf_filter_pid_query_buffer_duration_internal(pid_n, GF_FALSE, GF_FALSE);
				if (dur > max_dur ) max_dur = dur;
			}
		}
		duration += max_dur;
	}
	return duration;
}

GF_EXPORT u64 gf_filter_pid_query_buffer_duration(GF_FilterPid *pid, Bool check_pid_full)
{
	return gf_filter_pid_query_buffer_duration_internal(pid, check_pid_full, GF_FALSE);

}
GF_EXPORT Bool gf_filter_pid_has_seen_eos(GF_FilterPid *pid)
{
	u32 i;
	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to query EOS on output PID %s in filter %s\n", pid->pid->name, pid->filter->name));
		return GF_FALSE;
	}
	if (pid->pid->has_seen_eos) return GF_TRUE;
	if (pid->pid->filter->block_eos) return GF_FALSE;
	gf_mx_p(pid->pid->filter->tasks_mx);
	for (i=0; i<pid->pid->filter->num_input_pids; i++) {
		GF_FilterPidInst *pidi = gf_list_get(pid->pid->filter->input_pids, i);
		if (gf_filter_pid_has_seen_eos((GF_FilterPid *) pidi)) {
			gf_mx_v(pid->pid->filter->tasks_mx);
			return GF_TRUE;
		}
	}
	gf_mx_v(pid->pid->filter->tasks_mx);
	return GF_FALSE;
}

GF_EXPORT Bool gf_filter_pid_eos_received(GF_FilterPid *pid)
{
	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to query EOS on output PID %s in filter %s\n", pid->pid->name, pid->filter->name));
		return GF_FALSE;
	}
	if (pid->pid->has_seen_eos) return GF_TRUE;
	return GF_FALSE;
}


GF_EXPORT const char *gf_filter_event_name(GF_FEventType type)
{
	switch (type) {
	case GF_FEVT_PLAY: return "PLAY";
	case GF_FEVT_SET_SPEED: return "SET_SPEED";
	case GF_FEVT_STOP: return "STOP";
	case GF_FEVT_SOURCE_SEEK: return "SOURCE_SEEK";
	case GF_FEVT_SOURCE_SWITCH: return "SOURCE_SWITCH";
	case GF_FEVT_ATTACH_SCENE: return "ATTACH_SCENE";
	case GF_FEVT_RESET_SCENE: return "RESET_SCENE";
	case GF_FEVT_PAUSE: return "PAUSE";
	case GF_FEVT_RESUME: return "RESUME";
	case GF_FEVT_QUALITY_SWITCH: return "QUALITY_SWITCH";
	case GF_FEVT_VISIBILITY_HINT: return "VISIBILITY_HINT";
	case GF_FEVT_INFO_UPDATE: return "INFO_UPDATE";
	case GF_FEVT_BUFFER_REQ: return "BUFFER_REQ";
	case GF_FEVT_USER: return "USER";
	case GF_FEVT_SEGMENT_SIZE: return "SEGMENT_SIZE";
	case GF_FEVT_FRAGMENT_SIZE: return "FRAGMENT_SIZE";
	case GF_FEVT_CAPS_CHANGE: return "CAPS_CHANGED";
	case GF_FEVT_CONNECT_FAIL: return "CONNECT_FAIL";
	case GF_FEVT_FILE_DELETE: return "FILE_DELETE";
	case GF_FEVT_PLAY_HINT: return "PLAY_HINT";
	case GF_FEVT_ENCODE_HINTS: return "ENCODE_HINTS";
	case GF_FEVT_NTP_REF: return "NTP_REF";
	default:
		return "UNKNOWN";
	}
}

static void gf_filter_pid_reset_task_ex(GF_FSTask *task, Bool *had_eos)
{
	GF_FilterPidInst *pidi = (GF_FilterPidInst *)task->udta;
	GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Filter %s input PID %s (from %s) resetting buffer\n", task->filter->name, pidi->pid->name, pidi->pid->filter->name ));

	if (had_eos) *had_eos = GF_FALSE;

	
	gf_filter_aggregate_packets(pidi);

	
	while (gf_fq_count(pidi->packets)) {
		GF_FilterPacketInstance *pcki = gf_fq_head(pidi->packets);
		if ( (pcki->pck->info.flags & GF_PCK_CMD_MASK) == GF_PCK_CMD_PID_EOS) {
			if (had_eos)
				*had_eos = GF_TRUE;
		}
		
		filter_pck_check_prop_change(pidi, pcki, GF_FALSE);

		gf_filter_pid_drop_packet((GF_FilterPid *) pidi);
	}

	gf_filter_pidinst_reset_stats(pidi);

	assert(pidi->discard_packets);
	safe_int_dec(&pidi->discard_packets);

	pidi->last_block_ended = GF_TRUE;
	pidi->first_block_started = GF_FALSE;
	pidi->is_end_of_stream = GF_FALSE;
	pidi->buffer_duration = 0;
	pidi->nb_eos_signaled = 0;
	pidi->pid->has_seen_eos = GF_FALSE;
	pidi->last_clock_type = 0;

	assert(pidi->pid->filter->stream_reset_pending);
	safe_int_dec(& pidi->pid->filter->stream_reset_pending );

	pidi->pid->nb_buffer_unit = 0;
	pidi->pid->buffer_duration = 0;
	gf_filter_pid_check_unblock(pidi->pid);
}

static void gf_filter_pid_reset_task(GF_FSTask *task)
{
	gf_filter_pid_reset_task_ex(task, NULL);
}

static void gf_filter_pid_reset_stop_task(GF_FSTask *task)
{
	GF_FilterPidInst *pidi = (GF_FilterPidInst *)task->udta;
	Bool has_eos;
	gf_filter_pid_reset_task_ex(task, &has_eos);
	pidi->is_end_of_stream = has_eos;
	pidi->pid->has_seen_eos = has_eos;
}

typedef struct {
	u32 ref_count;
	char string[1];
} GF_RefString;



static GF_RefString *evt_get_refstr(GF_FilterEvent *evt)
{
	if (evt->base.type == GF_FEVT_FILE_DELETE) {
		return TO_REFSTRING(evt->file_del.url);
	}
	if (evt->base.type == GF_FEVT_SOURCE_SWITCH) {
		return TO_REFSTRING(evt->seek.source_switch);
	}
	if (evt->base.type == GF_FEVT_SEGMENT_SIZE) {
		return TO_REFSTRING(evt->seg_size.seg_url);
	}
	return NULL;
}
static GF_FilterEvent *dup_evt(GF_FilterEvent *evt)
{
	GF_FilterEvent *an_evt;
	GF_RefString *rstr = evt_get_refstr(evt);
	an_evt = gf_malloc(sizeof(GF_FilterEvent));
	memcpy(an_evt, evt, sizeof(GF_FilterEvent));
	if (rstr) {
		safe_int_inc(&rstr->ref_count);
	}
	return an_evt;
}

static void free_evt(GF_FilterEvent *evt)
{
	GF_RefString *rstr = evt_get_refstr(evt);
	if (rstr) {
		assert(rstr->ref_count);
		if (safe_int_dec(&rstr->ref_count) == 0) {
			gf_free(rstr);
		}
	}
	gf_free(evt);
}

static GF_FilterEvent *init_evt(GF_FilterEvent *evt)
{
	char **url_addr_src = NULL;
	char **url_addr_dst = NULL;
	GF_FilterEvent *an_evt = gf_malloc(sizeof(GF_FilterEvent));
	memcpy(an_evt, evt, sizeof(GF_FilterEvent));

	if (evt->base.type==GF_FEVT_FILE_DELETE) {
		url_addr_src = (char **) &evt->file_del.url;
		url_addr_dst = (char **) &an_evt->file_del.url;
	} else if (evt->base.type==GF_FEVT_SOURCE_SWITCH) {
		url_addr_src = (char **) &evt->seek.source_switch;
		url_addr_dst = (char **) &an_evt->seek.source_switch;
	} else if (evt->base.type==GF_FEVT_SEGMENT_SIZE) {
		url_addr_src = (char **) &evt->seg_size.seg_url;
		url_addr_dst = (char **) &an_evt->seg_size.seg_url;
	}
	if (url_addr_src) {
		char *url = *url_addr_src;
		if (!url) {
			*url_addr_dst = NULL;
		} else {
			u32 len = (u32) strlen(url);
			GF_RefString *rstr = gf_malloc(sizeof(GF_RefString) + sizeof(char)*len);
			rstr->ref_count=1;
			strcpy( (char *) &rstr->string[0], url);
			*url_addr_dst = (char *) &rstr->string[0];
		}
	}
	return an_evt;
}


static Bool filter_pid_is_raw_source(GF_FilterPid *pid)
{
	u32 i;
	Bool res = GF_TRUE;
	if (!pid->raw_media) {
		if (pid->stream_type!=GF_STREAM_FILE)
			return GF_FALSE;
	}

	gf_mx_p(pid->filter->tasks_mx);

	for (i=0; i<pid->filter->num_input_pids; i++) {
		GF_FilterPidInst *pidi = gf_list_get(pid->filter->input_pids, i);
		if (pidi->pid->nb_decoder_inputs) {
			res = GF_FALSE;
			break;
		}
		if (! filter_pid_is_raw_source(pidi->pid)) {
			res = GF_FALSE;
			break;
		}
	}
	gf_mx_v(pid->filter->tasks_mx);
	return res;
}

void gf_filter_pid_send_event_downstream(GF_FSTask *task)
{
	u32 i, count, nb_playing=0, nb_paused=0;
	Bool canceled = GF_FALSE;
	Bool forced_cancel = GF_FALSE;
	GF_FilterEvent *evt = task->udta;
	GF_Filter *f = task->filter;
	GF_List *dispatched_filters = NULL;
	GF_FilterPidInst *for_pidi = (GF_FilterPidInst *)task->pid;

	if (for_pidi && (for_pidi->pid == task->pid)) {
		for_pidi = NULL;
	}

	
	if (f->stream_reset_pending) {
		TASK_REQUEUE(task)
		return;
	}
	
	if (f->detached_pid_inst) {
		TASK_REQUEUE(task)
		task->can_swap = 1;
		return;
	}

	if (evt->base.on_pid) {
		assert(evt->base.on_pid->filter->num_events_queued);
		safe_int_dec(&evt->base.on_pid->filter->num_events_queued);
	}
	if (f->finalized) {
		free_evt(evt);
		return;
	}

	if (for_pidi) {
		
		switch (evt->base.type) {
		case GF_FEVT_PLAY:
		case GF_FEVT_SOURCE_SEEK:
			for_pidi->is_playing = GF_TRUE;
			for_pidi->play_queued = 0;
			break;
		case GF_FEVT_STOP:
			for_pidi->is_playing = GF_FALSE;
			for_pidi->stop_queued = 0;
			break;
		case GF_FEVT_PAUSE:
			for_pidi->is_paused = GF_TRUE;
			break;
		case GF_FEVT_RESUME:
			for_pidi->is_paused = GF_FALSE;
			break;
		default:
			break;
		}
	}
	if (evt->base.on_pid) {
		GF_FilterPid *pid = (GF_FilterPid *) evt->base.on_pid->pid;
		
		
		if (pid->num_destinations && !for_pidi && ((evt->base.type==GF_FEVT_PLAY) || (evt->base.type==GF_FEVT_STOP) || (evt->base.type==GF_FEVT_CONNECT_FAIL))
		) {
			
			
			if (evt->base.type==GF_FEVT_STOP) {
				for (i=0; i<pid->num_destinations; i++) {
					for_pidi = gf_list_get(pid->destinations, i);
					if (for_pidi->discard_packets)
						safe_int_dec(&for_pidi->discard_packets);
				}
			}
			free_evt(evt);
			return;
		}
		
		for (i=0; i<pid->num_destinations; i++) {
			GF_FilterPidInst *pidi = gf_list_get(pid->destinations, i);
			if (pidi->is_playing) nb_playing++;
			if (pidi->is_paused) nb_paused++;
		}
	}

	if (evt->base.type == GF_FEVT_BUFFER_REQ) {
		if (!evt->base.on_pid) {
			free_evt(evt);
			return;
		}
		
		if (  evt->base.on_pid->nb_decoder_inputs  || evt->buffer_req.pid_only  || filter_pid_is_raw_source(evt->base.on_pid)





		) {
			evt->base.on_pid->max_buffer_time = evt->base.on_pid->user_max_buffer_time = evt->buffer_req.max_buffer_us;
			evt->base.on_pid->user_max_playout_time = evt->buffer_req.max_playout_us;
			evt->base.on_pid->user_min_playout_time = evt->buffer_req.min_playout_us;
			evt->base.on_pid->max_buffer_unit = 0;
			evt->base.on_pid->user_buffer_forced = evt->buffer_req.pid_only;
			
			if (evt->base.on_pid->would_block)
				gf_filter_pid_check_unblock(evt->base.on_pid);
			else gf_filter_pid_would_block(evt->base.on_pid);
			canceled = GF_TRUE;
		} else {
			evt->base.on_pid->user_buffer_forced = GF_FALSE;
		}
	} else if (evt->base.on_pid && (evt->base.type == GF_FEVT_PLAY)
		&& (evt->base.on_pid->pid->is_playing || (((GF_FilterPid *) evt->base.on_pid->pid)->not_connected==2))
		) {
		if (evt->base.on_pid->pid->is_playing) {
			GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Filter %s PID %s event %s but PID is already playing, discarding\n", f->name, evt->base.on_pid->name, gf_filter_event_name(evt->base.type)));
		}
		free_evt(evt);
		return;
	} else if (evt->base.on_pid && (evt->base.type == GF_FEVT_STOP)
		&& (  !evt->base.on_pid->pid->is_playing  || nb_playing )




	) {
		GF_FilterPid *pid = (GF_FilterPid *) evt->base.on_pid->pid;

		if (!evt->base.on_pid->pid->is_playing) {
			GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Filter %s PID %s event %s but PID is not playing, discarding\n", f->name, evt->base.on_pid->name, gf_filter_event_name(evt->base.type)));
		} else {
			GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Filter %s PID %s event %s but PID has playing destinations, discarding\n", f->name, evt->base.on_pid->name, gf_filter_event_name(evt->base.type)));
		}

		gf_mx_p(f->tasks_mx);
		for (i=0; i<pid->num_destinations; i++) {
			GF_FilterPidInst *pidi = (GF_FilterPidInst *) gf_list_get(pid->destinations, i);
			
			
			if (pidi->discard_packets) {
				safe_int_dec(&pidi->discard_packets);
			}
		}
		if (!evt->base.on_pid->pid->is_playing) {
			if ((f->num_input_pids==f->num_output_pids) && (f->num_input_pids==1)) {
				gf_filter_pid_set_discard(gf_list_get(f->input_pids, 0), GF_TRUE);
			}
			if (pid->not_connected)
				pid->not_connected = 2;
		}
		gf_mx_v(f->tasks_mx);
		free_evt(evt);
		return;
	}
	
	else if ((nb_paused>1) && (evt->base.type == GF_FEVT_PAUSE) ) {
		GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Filter %s PID %s event %s but PID is already paused, discarding\n", f->name, evt->base.on_pid->name, gf_filter_event_name(evt->base.type)));
		free_evt(evt);
		return;
	}
	
	else if (nb_paused && (evt->base.type == GF_FEVT_RESUME) ) {
		GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Filter %s PID %s event %s but some PID instances are still paused, discarding\n", f->name, evt->base.on_pid->name, gf_filter_event_name(evt->base.type)));
		free_evt(evt);
		return;
	}
	
	else if ((evt->base.type==GF_FEVT_CONNECT_FAIL) && evt->base.on_pid->is_playing) {
		free_evt(evt);
		return;
	}
	
	else {
		
		if (evt->base.type==GF_FEVT_SOURCE_SWITCH) {
			
			if (f->session->in_final_flush) {
				free_evt(evt);
				return;
			}
			for (i=0; i<f->num_output_pids; i++) {
				GF_FilterPid *apid = gf_list_get(f->output_pids, i);
				apid->has_seen_eos = GF_FALSE;
				gf_filter_pid_check_unblock(apid);
			}
		}

		if (f->freg->process_event) {
			FSESS_CHECK_THREAD(f)
			canceled = f->freg->process_event(f, evt);
		}
		if (!canceled && (evt->base.type==GF_FEVT_STOP) && evt->play.forced_dash_segment_switch) {
			GF_FilterPidInst *pid_inst = gf_list_get(f->input_pids, 0);
			
			if (pid_inst && ((pid_inst->pid->filter->num_input_pids==0) || (pid_inst->pid->filter->freg->flags & GF_FS_REG_ACT_AS_SOURCE))) {
				canceled = GF_TRUE;
				forced_cancel = GF_TRUE;
			}
		}
	}

	GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Filter %s PID %s processed event %s - canceled %s\n", f->name, evt->base.on_pid ? evt->base.on_pid->name : "none", gf_filter_event_name(evt->base.type), canceled ? "yes" : "no" ));

	if (evt->base.on_pid && ((evt->base.type == GF_FEVT_STOP) || (evt->base.type==GF_FEVT_SOURCE_SEEK) || (evt->base.type==GF_FEVT_PLAY)) ) {
		Bool do_reset = GF_TRUE;
		GF_FilterPidInst *p = (GF_FilterPidInst *) evt->base.on_pid;
		GF_FilterPid *pid = p->pid;
		gf_mx_p(pid->filter->tasks_mx);
		
		
		if (evt->base.type==GF_FEVT_PLAY) {
			pid->is_playing = GF_TRUE;
			pid->filter->nb_pids_playing++;
			if (pid->initial_play_done) {
				do_reset = GF_FALSE;
			} else {
				pid->initial_play_done = GF_TRUE;
				if (evt->play.start_range < 0.1)
					do_reset = GF_FALSE;
			}
		} else if (evt->base.type==GF_FEVT_STOP) {
			pid->is_playing = GF_FALSE;
			pid->filter->nb_pids_playing--;

			if (pid->not_connected)
				pid->not_connected = 2;
		} else if (evt->base.type==GF_FEVT_SOURCE_SEEK) {
			pid->is_playing = GF_TRUE;
			pid->filter->nb_pids_playing++;
		}
		for (i=0; i<pid->num_destinations && do_reset; i++) {
			GF_FilterPidInst *pidi = gf_list_get(pid->destinations, i);
			pidi->last_clock_type = 0;

			if (!pidi->discard_packets) {
				safe_int_inc(&pidi->discard_packets);
			}

			safe_int_inc(& pid->filter->stream_reset_pending );

			gf_mx_v(pid->filter->tasks_mx);

			
			if (evt->base.type==GF_FEVT_STOP)
				gf_fs_post_task(pidi->filter->session, gf_filter_pid_reset_stop_task, pidi->filter, NULL, "reset_stop_pid", pidi);
			else gf_fs_post_task(pidi->filter->session, gf_filter_pid_reset_task, pidi->filter, NULL, "reset_pid", pidi);

			gf_mx_p(pid->filter->tasks_mx);
		}
		pid->nb_reaggregation_pending = 0;
		gf_mx_v(pid->filter->tasks_mx);
	}
	
	gf_mx_p(f->tasks_mx);

	
	if (!f->num_input_pids || f->pending_packets) {
		if ((evt->base.type==GF_FEVT_PLAY) || (evt->base.type==GF_FEVT_SOURCE_SEEK)) {
			gf_filter_post_process_task(f);
		}
	}

	
	
	
	
	
	if ((f->num_input_pids==f->num_output_pids) && (f->num_input_pids==1)) {
		GF_FilterPidInst *apidi = gf_list_get(f->input_pids, 0);
		if (apidi->pid) {
			
			gf_mx_v(f->tasks_mx);
			if (evt->base.type==GF_FEVT_STOP) {
				if (forced_cancel) {
					
					gf_filter_pid_set_discard((GF_FilterPid *)apidi, GF_TRUE);

				} else if (!canceled) {
					gf_filter_pid_set_discard((GF_FilterPid *)apidi, GF_TRUE);
				}
			} else if (evt->base.type==GF_FEVT_PLAY) {
				gf_filter_pid_set_discard((GF_FilterPid *)apidi, GF_FALSE);
			}
			gf_mx_p(f->tasks_mx);
		}
	}
	gf_mx_v(f->tasks_mx);

	if ((evt->base.type==GF_FEVT_PLAY) || (evt->base.type==GF_FEVT_SET_SPEED)) {
		if (evt->base.on_pid) {
			u32 scaler = (u32)  ( (evt->play.speed<0) ? -evt->play.speed : evt->play.speed ) * GF_FILTER_SPEED_SCALER;
			if (!scaler) scaler = GF_FILTER_SPEED_SCALER;
			if (scaler != evt->base.on_pid->playback_speed_scaler) {
				u32 prev_scaler = evt->base.on_pid->playback_speed_scaler;
				evt->base.on_pid->playback_speed_scaler = scaler;
				
				if (scaler<prev_scaler)
					gf_filter_pid_would_block(evt->base.on_pid);
				
				else gf_filter_pid_check_unblock(evt->base.on_pid);
			}
		}
	}

	
	gf_mx_p(f->tasks_mx);
	count = f->num_input_pids;
	if (count==0) canceled = GF_TRUE;

	if (canceled) {
		free_evt(evt);
		gf_mx_v(f->tasks_mx);
		return;
	}

	if (!task->pid) dispatched_filters = gf_list_new();

	
	for (i=0; i<count; i++) {
		GF_FilterEvent *an_evt;
		GF_FilterPidInst *pid_inst = gf_list_get(f->input_pids, i);
		GF_FilterPid *pid = pid_inst->pid;
		if (!pid) continue;

		if (dispatched_filters) {
			if (gf_list_find(dispatched_filters, pid_inst->pid->filter) >=0 )
				continue;

			gf_list_add(dispatched_filters, pid_inst->pid->filter);
		}

		
		if ((evt->base.type == GF_FEVT_STOP) || (evt->base.type==GF_FEVT_SOURCE_SEEK)) {
			safe_int_inc(&pid_inst->discard_packets);
		}

		an_evt = dup_evt(evt);
		an_evt->base.on_pid = task->pid ? pid : NULL;

		safe_int_inc(&pid->filter->num_events_queued);
		
		gf_fs_post_task_class(pid->filter->session, gf_filter_pid_send_event_downstream, pid->filter, task->pid ? (GF_FilterPid *) pid_inst : NULL, "downstream_event", an_evt, TASK_TYPE_EVENT);
	}
	gf_mx_v(f->tasks_mx);
	if (dispatched_filters) gf_list_del(dispatched_filters);
	free_evt(evt);
	return;
}

void gf_filter_pid_send_event_upstream(GF_FSTask *task)
{
	u32 i, j;
	Bool canceled = GF_FALSE;
	GF_FilterEvent *evt = task->udta;
	GF_Filter *f = task->filter;

	if (f->stream_reset_pending) {
		TASK_REQUEUE(task)
		return;
	}

	canceled = f->freg->process_event ? f->freg->process_event(f, evt) : GF_FALSE;
	if (!canceled) {
		for (i=0; i<f->num_output_pids; i++) {
			GF_FilterPid *apid = gf_list_get(f->output_pids, i);
			for (j=0; j<apid->num_destinations; j++) {
				GF_FilterEvent *an_evt;
				GF_FilterPidInst *pidi = gf_list_get(apid->destinations, j);

				an_evt = dup_evt(evt);
				an_evt->base.on_pid = (GF_FilterPid *)pidi;
				gf_fs_post_task_class(pidi->filter->session, gf_filter_pid_send_event_upstream, pidi->filter, NULL, "upstream_event", an_evt, TASK_TYPE_EVENT);
			}
		}
	}
	free_evt(evt);
}

void gf_filter_pid_send_event_internal(GF_FilterPid *pid, GF_FilterEvent *evt, Bool force_downstream)
{
	GF_FilterEvent *an_evt;
	GF_FilterPid *target_pid=NULL;
	Bool upstream=GF_FALSE;
	if (!pid) {
		pid = evt->base.on_pid;
		if (!pid) return;
	}
	
	if (pid->filter->finalized) return;

	if ((evt->base.type==GF_FEVT_FILE_DELETE) && !evt->file_del.url) return;

	if (!force_downstream && PID_IS_OUTPUT(pid)) {
		upstream = GF_TRUE;
	}

	GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Filter %s PID %s queuing %s event %s\n", pid->pid->filter->name, pid->pid->name, upstream ? "upstream" : "downstream", gf_filter_event_name(evt->base.type) ));

	if (upstream) {
		u32 i, j;

		an_evt = init_evt(evt);

		for (i=0; i<pid->filter->num_output_pids; i++) {
			GF_FilterPid *apid = gf_list_get(pid->filter->output_pids, i);
			if (evt->base.on_pid && (apid != evt->base.on_pid)) continue;
			for (j=0; j<apid->num_destinations; j++) {
				GF_FilterEvent *up_evt;
				GF_FilterPidInst *pidi = gf_list_get(apid->destinations, j);

				up_evt = dup_evt(an_evt);
				up_evt->base.on_pid = (GF_FilterPid *)pidi;
				gf_fs_post_task_class(pidi->filter->session, gf_filter_pid_send_event_upstream, pidi->filter, NULL, "upstream_event", up_evt, TASK_TYPE_EVENT);
			}
		}
		free_evt(an_evt);
		return;
	}


	if ((evt->base.type == GF_FEVT_STOP)
		|| (evt->base.type == GF_FEVT_PLAY)
		|| (evt->base.type==GF_FEVT_SOURCE_SEEK)
	) {
		u32 i, nb_playing=0;
		Bool do_reset = GF_TRUE;
		gf_mx_p(pid->pid->filter->tasks_mx);

		for (i=0; i<pid->pid->num_destinations; i++) {
			GF_FilterPidInst *pidi = gf_list_get(pid->pid->destinations, i);
			if (pidi->is_playing || pidi->play_queued) nb_playing++;
			if (pidi->stop_queued) nb_playing--;

			
			if (pidi == (GF_FilterPidInst *)evt->base.on_pid) {
				
				if ((evt->base.type == GF_FEVT_STOP) && !pidi->is_playing && !pidi->play_queued) {
					gf_mx_v(pid->pid->filter->tasks_mx);
					return;
				}
				
				else if ((evt->base.type == GF_FEVT_PLAY) && pidi->is_playing && !pidi->stop_queued) {
					gf_mx_v(pid->pid->filter->tasks_mx);
					return;
				}
			}
		}
		
		
		
		if (evt->base.type == GF_FEVT_STOP) {
			if (nb_playing>1)
				do_reset = GF_FALSE;

			if (PID_IS_INPUT(pid)) {
				((GF_FilterPidInst*)evt->base.on_pid)->stop_queued = 1;
			}
		} else {
			if (nb_playing)
				do_reset = GF_FALSE;
			if (PID_IS_INPUT(pid)) {
				((GF_FilterPidInst*)evt->base.on_pid)->play_queued = 1;
			}
		}

		for (i=0; i<pid->pid->num_destinations; i++) {
			GF_FilterPidInst *pidi = gf_list_get(pid->pid->destinations, i);

			if (!do_reset && (pidi != (GF_FilterPidInst*)evt->base.on_pid))
				continue;

			if (evt->base.type == GF_FEVT_PLAY) {
				pidi->is_end_of_stream = GF_FALSE;
			} else {
				
				safe_int_inc(&pidi->discard_packets);
			}
		}

		gf_mx_v(pid->pid->filter->tasks_mx);
	}

	an_evt = init_evt(evt);
	if (evt->base.on_pid) {
		target_pid = evt->base.on_pid;
		an_evt->base.on_pid = evt->base.on_pid->pid;
		safe_int_inc(&target_pid->pid->filter->num_events_queued);
	}
	gf_fs_post_task_class(pid->pid->filter->session, gf_filter_pid_send_event_downstream, pid->pid->filter, target_pid, "downstream_event", an_evt, TASK_TYPE_EVENT);
}

GF_EXPORT void gf_filter_pid_send_event(GF_FilterPid *pid, GF_FilterEvent *evt)
{
	if (!evt) return;
	if (evt->base.type==GF_FEVT_RESET_SCENE) return;
	if (evt->base.type==GF_FEVT_INFO_UPDATE) return;

	gf_filter_pid_send_event_internal(pid, evt, GF_FALSE);
}

GF_EXPORT void gf_filter_send_event(GF_Filter *filter, GF_FilterEvent *evt, Bool upstream)
{
	GF_FilterEvent *an_evt;
	if (!filter) return;
	if (filter->multi_sink_target)
		filter = filter->multi_sink_target;

	
	if (filter->finalized) return;
	if (!evt) return;
	if ((evt->base.type==GF_FEVT_FILE_DELETE) && !evt->file_del.url) return;

	if (evt->base.type==GF_FEVT_RESET_SCENE)
		return;

	if (evt->base.on_pid && PID_IS_OUTPUT(evt->base.on_pid)) {
		gf_filter_pid_send_event_internal(evt->base.on_pid, evt, GF_FALSE);
		return;
	}

	
	if ((evt->base.type==GF_FEVT_SOURCE_SWITCH) || (evt->base.type==GF_FEVT_SOURCE_SEEK)) {
		if (filter->num_input_pids && !(filter->freg->flags & GF_FS_REG_ACT_AS_SOURCE)) {
			GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Sending %s event on non source filter %s is not allowed, discarding)\n", gf_filter_event_name(evt->base.type), filter->name));
			return;
		}
	}

	an_evt = init_evt(evt);

	if (evt->base.on_pid) {
		safe_int_inc(&evt->base.on_pid->filter->num_events_queued);
	}
	if (upstream)
		gf_fs_post_task_class(filter->session, gf_filter_pid_send_event_upstream, filter, evt->base.on_pid, "upstream_event", an_evt, TASK_TYPE_EVENT);
	else gf_fs_post_task_class(filter->session, gf_filter_pid_send_event_downstream, filter, evt->base.on_pid, "downstream_event", an_evt, TASK_TYPE_EVENT);
}


GF_EXPORT void gf_filter_pid_exec_event(GF_FilterPid *pid, GF_FilterEvent *evt)
{
	
	if (pid->pid->filter->finalized) return;
	if (! (pid->pid->filter->freg->flags &	GF_FS_REG_MAIN_THREAD)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Executing event on PID %s created by filter %s not running on main thread, not allowed\n", pid->pid->name, pid->filter->name));
		return;
	}

	if (pid->pid->filter->freg->process_event) {
		if (evt->base.on_pid) evt->base.on_pid = evt->base.on_pid->pid;
		FSESS_CHECK_THREAD(pid->pid->filter)
		pid->pid->filter->freg->process_event(pid->pid->filter, evt);
	}
}


GF_EXPORT Bool gf_filter_pid_is_filter_in_parents(GF_FilterPid *pid, GF_Filter *filter)
{
	if (!pid || !filter) return GF_FALSE;
	pid = pid->pid;
	return gf_filter_in_parent_chain(pid->filter, filter);
}



GF_EXPORT Bool gf_filter_pid_share_origin(GF_FilterPid *pid, GF_FilterPid *other_pid)
{
    if (!pid || !other_pid) return GF_FALSE;
    pid = pid->pid;
    other_pid = other_pid->pid;
    if (gf_filter_in_parent_chain(pid->filter, other_pid->filter))
        return GF_TRUE;
    if (gf_filter_in_parent_chain(other_pid->filter, pid->filter))
        return GF_TRUE;
    return GF_FALSE;
}

static void filter_pid_inst_collect_stats(GF_FilterPidInst *pidi, GF_FilterPidStatistics *stats)
{
	if (!pidi->pid) return;

	stats->average_bitrate += pidi->avg_bit_rate;
	if (!stats->first_process_time || (stats->first_process_time > pidi->first_frame_time))
		stats->first_process_time = pidi->first_frame_time;
	if (stats->last_process_time < pidi->last_pck_fetch_time)
		stats->last_process_time = pidi->last_pck_fetch_time;

	stats->max_bitrate += pidi->max_bit_rate;

	if (stats->max_process_time < (u32) pidi->max_process_time)
		stats->max_process_time = (u32) pidi->max_process_time;
	if (stats->max_sap_process_time < (u32) pidi->max_sap_process_time)
		stats->max_sap_process_time = (u32) pidi->max_sap_process_time;
	if (!stats->min_frame_dur || (stats->min_frame_dur > pidi->pid->min_pck_duration))
		stats->min_frame_dur = pidi->pid->min_pck_duration;
	stats->nb_processed += pidi->nb_processed;
	stats->nb_saps += pidi->nb_sap_processed;
	stats->total_process_time += pidi->total_process_time;
	stats->total_sap_process_time += pidi->total_sap_process_time;
	stats->average_process_rate += pidi->avg_process_rate;
	stats->max_process_rate += pidi->max_process_rate;

	if (stats->nb_buffer_units < pidi->pid->nb_buffer_unit)
		stats->nb_buffer_units = pidi->pid->nb_buffer_unit;
	if (stats->max_buffer_time < pidi->pid->max_buffer_time)
		stats->max_buffer_time = pidi->pid->max_buffer_time;

	if (stats->max_playout_time < pidi->pid->user_max_playout_time)
		stats->max_playout_time = pidi->pid->user_max_playout_time;
	if (!stats->min_playout_time || (stats->min_playout_time > pidi->pid->user_min_playout_time))
		stats->min_playout_time = pidi->pid->user_min_playout_time;

	if (stats->buffer_time < pidi->pid->buffer_duration)
		stats->buffer_time = pidi->pid->buffer_duration;

	if (!stats->last_ts_drop.den || gf_timestamp_less(stats->last_ts_drop.num, stats->last_ts_drop.den, pidi->last_ts_drop.num, pidi->last_ts_drop.den)
	) {
		stats->last_ts_drop = pidi->last_ts_drop;
	}
	if (!stats->last_ts_sent.den || gf_timestamp_less(stats->last_ts_sent.num, stats->last_ts_sent.den, pidi->pid->last_ts_sent.num, pidi->pid->last_ts_sent.den)
	) {
		stats->last_ts_sent = pidi->pid->last_ts_sent;
	}

	if (pidi->last_rt_report) {
		stats->last_rt_report = pidi->last_rt_report;
		stats->rtt = pidi->rtt;
		stats->jitter = pidi->jitter;
		stats->loss_rate = pidi->loss_rate;
	}
}

static void filter_pid_collect_stats(GF_List *pidi_list, GF_FilterPidStatistics *stats)
{
	u32 i;
	for (i=0; i<gf_list_count(pidi_list); i++) {
		GF_FilterPidInst *pidi = (GF_FilterPidInst *) gf_list_get(pidi_list, i);
		if (!pidi->pid) continue;

		filter_pid_inst_collect_stats(pidi, stats);
	}
}


static GF_Filter *filter_locate_enc_dec_sink(GF_Filter *filter, Bool locate_decoder)
{
	u32 i, j;

	for (i=0; i<filter->num_output_pids; i++) {
		GF_FilterPid *pid = gf_list_get(filter->output_pids, i);
		for (j=0; j<pid->num_destinations; j++) {
			GF_Filter *res;
			GF_FilterPidInst *pidi = gf_list_get(pid->destinations, j);
			if (( (pidi->is_decoder_input || pid->user_buffer_forced) && locate_decoder)
				|| (pidi->is_encoder_input && !locate_decoder)
			)
				return pidi->filter;
			res = filter_locate_enc_dec_sink(pidi->filter, locate_decoder);
			if (res) return res;
		}
	}
	return NULL;
}

static GF_Filter *filter_locate_enc_dec_src(GF_Filter *filter, Bool locate_decoder)
{
	u32 i;

	gf_mx_p(filter->tasks_mx);
	for (i=0; i<filter->num_input_pids; i++) {
		GF_Filter *res;
		GF_FilterPidInst *pidi = gf_list_get(filter->input_pids, i);
		if ((pidi->is_decoder_input && locate_decoder)
			|| (pidi->is_encoder_input && !locate_decoder)
		) {
			gf_mx_v(filter->tasks_mx);
			return filter;
		}
		res = filter_locate_enc_dec_sink(pidi->pid->filter, locate_decoder);
		if (res) {
			gf_mx_v(filter->tasks_mx);
			return res;
		}
	}
	gf_mx_v(filter->tasks_mx);
	return NULL;
}

static GF_Filter *filter_locate_sink(GF_Filter *filter)
{
	u32 i, j;

	if (!filter->num_output_pids) {
		return filter;
	}
	for (i=0; i<filter->num_output_pids; i++) {
		GF_FilterPid *pid = gf_list_get(filter->output_pids, i);
		for (j=0; j<pid->num_destinations; j++) {
			GF_Filter *res;
			GF_FilterPidInst *pidi = gf_list_get(pid->destinations, j);
			res = filter_locate_sink(pidi->filter);
			if (res) return res;
		}
	}
	return NULL;
}
GF_EXPORT GF_Err gf_filter_pid_get_statistics(GF_FilterPid *pid, GF_FilterPidStatistics *stats, GF_FilterPidStatsLocation location)
{
	GF_FilterPidInst *pidi = (GF_FilterPidInst *)pid;
	GF_Filter *filter=NULL;
	Bool for_decoder=GF_TRUE;

	memset(stats, 0, sizeof(GF_FilterPidStatistics) );
	if (!pidi->pid) {
		stats->disconnected = GF_TRUE;
		return GF_OK;
	}

	switch (location) {
	case GF_STATS_LOCAL:
		if (PID_IS_OUTPUT(pid)) {
			filter_pid_collect_stats(pid->destinations, stats);
			return GF_OK;
		}
		filter_pid_inst_collect_stats(pidi, stats);
		return GF_OK;
	case GF_STATS_LOCAL_INPUTS:
		if (PID_IS_OUTPUT(pid)) {
			filter_pid_collect_stats(pid->destinations, stats);
			return GF_OK;
		}
		filter = pidi->pid->filter;
		break;
	case GF_STATS_ENCODER_SOURCE:
		for_decoder = GF_FALSE;
	case GF_STATS_DECODER_SOURCE:
		filter = filter_locate_enc_dec_src(pidi->pid->filter, for_decoder);
		break;
	case GF_STATS_ENCODER_SINK:
		for_decoder = GF_FALSE;
	case GF_STATS_DECODER_SINK:
		filter = filter_locate_enc_dec_sink(pidi->pid->filter, for_decoder);
		break;
	case GF_STATS_SINK:
		filter = filter_locate_sink(pidi->pid->filter);
		break;
	}
	if (!filter) {
		return GF_NOT_FOUND;
	}
	gf_mx_p(filter->tasks_mx);
	filter_pid_collect_stats(filter->input_pids, stats);
	gf_mx_v(filter->tasks_mx);
	return GF_OK;
}

GF_EXPORT void gf_filter_pid_remove(GF_FilterPid *pid)
{
	GF_FilterPacket *pck;
	if (PID_IS_INPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Removing PID input filter (%s:%s) not allowed\n", pid->filter->name, pid->pid->name));
	}
	GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Filter %s removed output PID %s\n", pid->filter->name, pid->pid->name));

	if (pid->filter->removed) {
		return;
	}
	if (pid->removed) {
		return;
	}
	pid->removed = GF_TRUE;
	if (pid->filter->marked_for_removal || (pid->has_seen_eos && !pid->nb_buffer_unit)) {
		u32 i;
		for (i=0; i<pid->num_destinations; i++) {
			GF_FilterPidInst *pidi = gf_list_get(pid->destinations, i);
			gf_fs_post_task(pidi->filter->session, gf_filter_pid_disconnect_task, pidi->filter, pidi->pid, "pidinst_disconnect", NULL);
		}
		return;
	}

	
	pck = gf_filter_pck_new_shared_internal(pid, NULL, 0, NULL, GF_TRUE);
	if (!pck) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Failed to allocate new packet for PID %s remove in filter %s\n", pid->name, pid->filter->name));
		return;
	}
	gf_filter_pck_set_framing(pck, GF_TRUE, GF_TRUE);
	pck->pck->info.flags |= GF_PCK_CMD_PID_REM;
	gf_filter_pck_send(pck);
}

GF_EXPORT void gf_filter_pid_try_pull(GF_FilterPid *pid)
{
	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to pull from output PID %s in filter %s\n", pid->pid->name, pid->filter->name));
		return;
	}
	pid = pid->pid;

	if (pid->filter->session->threads) {
		GF_LOG(GF_LOG_DEBUG, GF_LOG_FILTER, ("Filter pull in multithread mode not yet implementing - defaulting to 1 ms sleep\n", pid->pid->name, pid->filter->name));
		gf_sleep(1);
		return;
	}


	gf_filter_process_inline(pid->filter);
}


GF_EXPORT GF_FilterClockType gf_filter_pid_get_clock_info(GF_FilterPid *pid, u64 *clock_time, u32 *timescale)
{
	GF_FilterPidInst *pidi = (GF_FilterPidInst *)pid;
	GF_FilterClockType res;
	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Querying clock on output PID %s in filter %s\n", pid->pid->name, pid->filter->name));
		return GF_FILTER_CLOCK_NONE;
	}
	if (clock_time) *clock_time = pidi->last_clock_value;
	if (timescale) *timescale = pidi->last_clock_timescale;
	res = pidi->last_clock_type;
	pidi->last_clock_type = 0;
	return res;
}

GF_EXPORT u32 gf_filter_pid_get_timescale(GF_FilterPid *pid)
{
	GF_PropertyMap *map;
	if (!pid) return 0;
	
	if (PID_IS_INPUT(pid))
		map = gf_list_get(pid->pid->properties, 0);
	
	else map = gf_list_last(pid->pid->properties);
	return map ? map->timescale : 0;
}

GF_EXPORT void gf_filter_pid_clear_eos(GF_FilterPid *pid, Bool clear_all)
{
	u32 i, j;
	GF_FilterPidInst *pidi = (GF_FilterPidInst *)pid;
	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Clearing EOS on output PID %s in filter %s\n", pid->pid->name, pid->filter->name));
		return;
	}
	pid = pid->pid;
	for (i=0; i<pid->filter->num_output_pids; i++) {
		GF_FilterPid *apid = gf_list_get(pid->filter->output_pids, i);
		if (!clear_all && (pid != apid)) continue;

		for (j=0; j<apid->num_destinations; j++) {
			GF_FilterPidInst *apidi = gf_list_get(apid->destinations, j);
			if (apidi->filter != pidi->filter) continue;

			if (apidi->is_end_of_stream) {
				apidi->is_end_of_stream = GF_FALSE;
			}
			if (apid->has_seen_eos) {
				apid->has_seen_eos = GF_FALSE;
				gf_filter_pid_check_unblock(apid);
			}

			if (apidi->pid->filter->would_block && apidi->pid->filter->num_input_pids) {
				u32 k;
				gf_mx_p(apidi->pid->filter->tasks_mx);
				for (k=0; k<apidi->pid->filter->num_input_pids; k++) {
					GF_FilterPidInst *source_pid_inst = gf_list_get(apidi->pid->filter->input_pids, k);
					gf_filter_pid_clear_eos((GF_FilterPid *) source_pid_inst, clear_all);
				}
				gf_mx_v(apidi->pid->filter->tasks_mx);
			}
		}
	}

	
	if (clear_all && !pid->filter->would_block) {
		
		gf_mx_p(pid->filter->tasks_mx);
		for (i=0; i<pid->filter->num_input_pids; i++) {
			GF_FilterPidInst *apidi = gf_list_get(pid->filter->input_pids, i);
			gf_filter_pid_clear_eos((GF_FilterPid *) apidi, GF_TRUE);
		}
		gf_mx_v(pid->filter->tasks_mx);
	}
}

GF_EXPORT void gf_filter_pid_set_clock_mode(GF_FilterPid *pid, Bool filter_in_charge)
{
	GF_FilterPidInst *pidi = (GF_FilterPidInst *)pid;
	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Changing clock mode on output PID %s in filter %s\n", pid->pid->name, pid->filter->name));
		return;
	}
	pidi->handles_clock_references = filter_in_charge;
}

GF_EXPORT const char *gf_filter_pid_get_args(GF_FilterPid *pid)
{
	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Querying args on output PID %s in filter %s\n", pid->pid->name, pid->filter->name));
		return NULL;
	}
	if (pid->pid->filter->src_args) return pid->pid->filter->src_args;
	return pid->pid->filter->orig_args;
}

GF_EXPORT void gf_filter_pid_set_max_buffer(GF_FilterPid *pid, u32 total_duration_us)
{
	if (PID_IS_INPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Setting max buffer on input PID %s in filter %s not allowed\n", pid->pid->name, pid->filter->name));
		return;
	}
	pid->max_buffer_time = pid->user_max_buffer_time = total_duration_us;
}

GF_EXPORT u32 gf_filter_pid_get_max_buffer(GF_FilterPid *pid)
{
	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Querying max buffer on output PID %s in filter %s not allowed\n", pid->pid->name, pid->filter->name));
		return 0;
	}
	return pid->pid->user_max_buffer_time;
}


GF_EXPORT void gf_filter_pid_set_loose_connect(GF_FilterPid *pid)
{
	if (PID_IS_INPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Setting loose connect on input PID %s in filter %s not allowed\n", pid->pid->name, pid->filter->name));
		return;
	}
	pid->not_connected_ok = GF_TRUE;
}

GF_EXPORT const GF_PropertyValue *gf_filter_pid_caps_query(GF_FilterPid *pid, u32 prop_4cc)
{
	u32 i;
	GF_PropertyMap *map = pid->pid->caps_negociate;
	if (PID_IS_INPUT(pid)) {
		u32 k;
		GF_Filter *dst = pid->filter->cap_dst_filter;
		
		
		if (!dst) dst = gf_list_last(pid->filter->destination_filters);
		if (!dst) dst = gf_list_get(pid->filter->destination_links, 0);

		if (!dst || (dst->cap_idx_at_resolution<0) ) {
			GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Reconfig caps query on input PID %s in filter %s with no destination filter set\n", pid->pid->name, pid->filter->name));
			return NULL;
		}
		for (k=dst->cap_idx_at_resolution; k<dst->freg->nb_caps; k++) {
			const GF_FilterCapability *cap = &dst->freg->caps[k];
			if (!(cap->flags & GF_CAPFLAG_IN_BUNDLE)) return NULL;

			if (!(cap->flags & GF_CAPFLAG_INPUT)) continue;
			if (cap->flags & GF_CAPFLAG_OPTIONAL) continue;
			if (cap->code == prop_4cc) return &cap->val;
		}
		return NULL;
	}
	if (map) return gf_props_get_property(map, prop_4cc, NULL);
	for (i=0; i<pid->num_destinations; i++) {
		u32 j;
		GF_FilterPidInst *pidi = gf_list_get(pid->destinations, i);
		for (j=0; j<pidi->filter->nb_forced_caps; j++) {
			if (pidi->filter->forced_caps[j].code==prop_4cc)
				return &pidi->filter->forced_caps[j].val;
		}
		
		for (j=0; j<pidi->filter->num_output_pids; j++) {
			GF_FilterPid *apid = gf_list_get(pidi->filter->output_pids, j);
			if (apid) {
				const GF_PropertyValue *p = gf_filter_pid_caps_query(apid, prop_4cc);
				if (p) return p;
			}
		}

	}

	
	
	if (gf_list_count(pid->filter->destination_filters) ) {
		GF_Filter *a_filter = gf_list_get(pid->filter->destination_filters, 0);
		while (a_filter) {
			for (i=0; i<a_filter->nb_forced_caps; i++) {
				if (a_filter->forced_caps[i].code==prop_4cc)
					return &a_filter->forced_caps[i].val;
			}
			a_filter = gf_list_get(a_filter->destination_filters, 0);
		}
	}

	
	
	if (pid->filter->cap_dst_filter) {
		GF_Filter *a_filter = pid->filter->cap_dst_filter;
		for (i=0; i<a_filter->nb_forced_caps; i++) {
			if (a_filter->forced_caps[i].code==prop_4cc)
				return &a_filter->forced_caps[i].val;
		}
		
		
		
		a_filter = a_filter->dst_filter;
		while (a_filter) {
			for (i=0; i<a_filter->nb_forced_caps; i++) {
				if (a_filter->forced_caps[i].code==prop_4cc)
					return &a_filter->forced_caps[i].val;
			}
			a_filter = a_filter->dst_filter;
		}
	}

	return NULL;
}

GF_EXPORT const GF_PropertyValue *gf_filter_pid_caps_query_str(GF_FilterPid *pid, const char *prop_name)
{
	GF_PropertyMap *map;
	if (PID_IS_INPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Reconfig caps query on input PID %s in filter %s not allowed\n", pid->pid->name, pid->filter->name));
		return NULL;
	}
	map = pid->caps_negociate;
	return map ? gf_props_get_property(map, 0, prop_name) : NULL;
}


GF_EXPORT GF_Err gf_filter_pid_resolve_file_template_ex(GF_FilterPid *pid, char szTemplate[GF_MAX_PATH], char szFinalName[GF_MAX_PATH], u32 file_idx, const char *file_suffix, const char *filename)
{
	u32 k;
	GF_FilterPacket *pck;
	char szFormat[30], szTemplateVal[GF_MAX_PATH], szPropVal[GF_PROP_DUMP_ARG_SIZE];
	char *name = szTemplate;
	if (!strchr(szTemplate, '$')) {
		strcpy(szFinalName, szTemplate);
		return GF_OK;
	}
	pck = gf_filter_pid_get_packet(pid);
	
	k = 0;
	while (name[0]) {
		char *sep=NULL;
		char *fsep=NULL;
		const char *str_val = NULL;
		s64 value = 0;
		Bool is_ok = GF_TRUE;
		Bool do_skip = GF_FALSE;
		Bool has_val = GF_FALSE;
		Bool is_file_str = GF_FALSE;
		u32 prop_4cc = 0;
		GF_PropertyValue prop_val_patched;
		const GF_PropertyValue *prop_val = NULL;

		if (k+1==GF_MAX_PATH) {
			GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("[Filter] Not enough memory to solve file template %s\n", szTemplate));
			return GF_OUT_OF_MEM;
		}
		if (name[0] != '$') {
			szFinalName[k] = name[0];
			k++;
			name++;
			continue;
		}
		if (name[1]=='$') {
			szFinalName[k] = '$';
			name++;
			k++;
			continue;
		}
		sep = strchr(name+1, '$');
		if (!sep) {
			GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("[Filter] broken file template expecting $KEYWORD$, couldn't find second '$'\n", szTemplate));
			strcpy(szFinalName, szTemplate);
			return GF_BAD_PARAM;
		}
		szFormat[0] = '%';
		szFormat[1] = 'd';
		szFormat[2] = 0;

		szFinalName[k] = 0;
		name++;
		sep[0]=0;
		fsep = strchr(name, '%');
		if (fsep) {
			strcpy(szFormat, fsep);
			fsep[0]=0;
		}

		if (!strcmp(name, "num")) {
			name += 3;
			value = file_idx;
			has_val = GF_TRUE;
		} else if (!strcmp(name, "URL")) {
			if (!filename)
				prop_val = gf_filter_pid_get_property_first(pid, GF_PROP_PID_URL);
			is_file_str = GF_TRUE;
		} else if (!strcmp(name, "File")) {
			if (!filename) {
				prop_val = gf_filter_pid_get_property_first(pid, GF_PROP_PID_FILEPATH);
				
				if (prop_val && !strncmp(prop_val->value.string, "gmem://", 7))
					prop_val = NULL;

				if (!prop_val)
					prop_val = gf_filter_pid_get_property_first(pid, GF_PROP_PID_URL);

				if (!prop_val && pid->pid->name) {
					prop_val_patched.type = GF_PROP_STRING;
					prop_val_patched.value.string = pid->pid->name;
					prop_val = &prop_val_patched;
				}
			}
			is_file_str = GF_TRUE;
		} else if (!strcmp(name, "PID")) {
			prop_val = gf_filter_pid_get_property_first(pid, GF_PROP_PID_ID);
		} else if (!strcmp(name, "FS")) {
			str_val = file_suffix ? file_suffix : "";
			is_ok = GF_TRUE;
		} else if (!strcmp(name, "Type")) {
			prop_val = gf_filter_pid_get_property_first(pid, GF_PROP_PID_STREAM_TYPE);
			if (prop_val) {
				str_val = gf_stream_type_short_name(prop_val->value.uint);
				is_ok = GF_TRUE;
			}
			prop_val = NULL;
		} else if (!strncmp(name, "p4cc=", 5)) {
			if (strlen(name) != 9) {
				GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("[Filter] wrong length in 4CC template, expecting 4cc=ABCD\n", name));
				is_ok = GF_FALSE;
			} else {
				prop_4cc = GF_4CC(name[5],name[6],name[7],name[8]);
				prop_val = gf_filter_pid_get_property_first(pid, prop_4cc);
				if (!prop_val && pck) {
					prop_val = gf_filter_pck_get_property(pck, prop_4cc);
				}
				if (!prop_val) {
					GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("[Filter] no pid property of type %s\n", name+5));
					is_ok = GF_FALSE;
				}
			}
		} else if (!strncmp(name, "pname=", 6)) {
			prop_val = gf_filter_pid_get_property_str_first(pid, name+6);
			if (!prop_val && pck) {
				prop_val = gf_filter_pck_get_property_str(pck, name+6);
			}
			if (!prop_val) {
				GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("[Filter] no pid property named %s\n", name+6));
				is_ok = GF_FALSE;
			}
		}
		
		else if (!strcmp(name, "Number")) {
			do_skip = GF_TRUE;
		} else if (!strcmp(name, "Time")) {
			do_skip = GF_TRUE;
		} else if (!strcmp(name, "RepresentationID")) {
			do_skip = GF_TRUE;
		} else if (!strcmp(name, "Bandwidth")) {
			do_skip = GF_TRUE;
		} else if (!strcmp(name, "SubNumber")) {
			do_skip = GF_TRUE;
		} else if (!strncmp(name, "Init", 4) && (name[4]=='=')) {
			do_skip = GF_TRUE;
		} else if (!strncmp(name, "XInit", 5) && (name[5]=='=')) {
			do_skip = GF_TRUE;
		} else if (!strncmp(name, "Path", 4) && (name[4]=='=')) {
			do_skip = GF_TRUE;
		} else {
			char *next_eq = strchr(name, '=');
			char *next_sep = strchr(name, '$');
			if (!next_eq || (next_eq - name < next_sep - name)) {
				prop_4cc = gf_props_get_id(name);
				
				if (!prop_4cc) {
					prop_val = gf_filter_pid_get_property_str_first(pid, name);
					if (!prop_val && pck)
						prop_val = gf_filter_pck_get_property_str(pck, name);
				} else {
					prop_val = gf_filter_pid_get_property_first(pid, prop_4cc);
					if (!prop_val && pck)
						prop_val = gf_filter_pck_get_property(pck, prop_4cc);
				}

				if (!prop_val && pck) {
					if (!strcmp(name, "cts")) {
						prop_val_patched.type = GF_PROP_LUINT;
						prop_val_patched.value.longuint = gf_filter_pck_get_cts(pck);
						prop_val = &prop_val_patched;
					} else if (!strcmp(name, "dts")) {
						prop_val_patched.type = GF_PROP_LUINT;
						prop_val_patched.value.longuint = gf_filter_pck_get_dts(pck);
						prop_val = &prop_val_patched;
					} else if (!strcmp(name, "dur")) {
						prop_val_patched.type = GF_PROP_UINT;
						prop_val_patched.value.uint = gf_filter_pck_get_duration(pck);
						prop_val = &prop_val_patched;
					} else if (!strcmp(name, "sap")) {
						prop_val_patched.type = GF_PROP_UINT;
						prop_val_patched.value.uint = gf_filter_pck_get_sap(pck);
						prop_val = &prop_val_patched;
					}
				}

				if (!prop_val) {
					if (!prop_4cc) {
						GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("[Filter] Unrecognized template %s\n", name));
					}
					is_ok = GF_FALSE;
				}
			} else {
				u32 i, len = (u32) (next_sep ? 1+(next_sep - name) : strlen(name) );
				szFinalName[k]='$';
				k++;
				for (i=0; i<len; i++) {
					szFinalName[k] = name[0];
					k++;
					name++;
				}
				szFinalName[k]='$';
				k++;
				sep[0] = '$';
				name = sep+1;
				continue;
			}
		}
		if (fsep) fsep[0] = '%';
		if (do_skip) {
			sep[0] = '$';
			szFinalName[k] = '$';
			k++;
			while (name[0] && (name[0] != '$')) {
				szFinalName[k] = name[0];
				k++;
				name++;
			}
			szFinalName[k] = '$';
			k++;
			name++;


			continue;

		}


		if (!is_ok && !prop_val && prop_4cc) {
			if (prop_4cc==GF_PROP_PID_CROP_POS) {
				prop_val_patched.type = GF_PROP_VEC2I;
				prop_val_patched.value.vec2i.x = 0;
				prop_val_patched.value.vec2i.y = 0;
				prop_val = &prop_val_patched;
				is_ok=GF_TRUE;
			}
			else if (prop_4cc==GF_PROP_PID_ORIG_SIZE) {
				prop_val_patched.type = GF_PROP_VEC2I;
				prop_val = gf_filter_pid_get_property_first(pid, GF_PROP_PID_WIDTH);
				prop_val_patched.value.vec2i.x = prop_val ? prop_val->value.uint : 0;
				prop_val = gf_filter_pid_get_property_first(pid, GF_PROP_PID_HEIGHT);
				prop_val_patched.value.vec2i.y = prop_val ? prop_val->value.uint : 0;
				prop_val = &prop_val_patched;
				is_ok=GF_TRUE;
			} else {
				GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("[Filter] property %s not found for pid, cannot resolve template\n", name));
				return GF_BAD_PARAM;
			}
		}

		if (!is_ok) {
			if (sep) sep[0] = '$';
			return GF_BAD_PARAM;
		}
		if (prop_val) {
			if ((prop_val->type==GF_PROP_UINT) || (prop_val->type==GF_PROP_SINT)) {
				value = prop_val->value.uint;
				has_val = GF_TRUE;
			} else {
				str_val = gf_props_dump_val(prop_val, szPropVal, GF_PROP_DUMP_DATA_NONE, NULL);
			}
		} else if (is_file_str) {
			str_val = filename;
		}
		szTemplateVal[0]=0;
		if (has_val) {
			sprintf(szTemplateVal, szFormat, value);
		} else if (str_val) {
			if (is_file_str) {
				if (!strncmp(str_val, "gfio://", 7))
					str_val = gf_fileio_translate_url(str_val);

				if (filename) {
					strcpy(szTemplateVal, filename);
				} else {
					char *ext, *sname;
					ext = strstr(str_val, "://");
					sname = strrchr(ext ? ext+4 : str_val, '/');
					if (!sname) sname = strrchr(ext ? ext+4 : str_val, '\\');
					if (sname && ext)
						str_val = sname+1;

					if (!sname) sname = (char *) str_val;
					else sname++;

					ext = strrchr(str_val, '.');

					if (ext && (ext > sname) ) {
						u32 len = (u32) (ext - sname);
						strncpy(szTemplateVal, sname, ext - sname);
						szTemplateVal[len] = 0;
					} else {
						strcpy(szTemplateVal, sname);
					}
				}
			} else {
				strcpy(szTemplateVal, str_val);
			}
		} else {
			GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("[Filter] property %s not found for pid, cannot resolve template\n", name));
			return GF_BAD_PARAM;
		}
		if (k + strlen(szTemplateVal) > GF_MAX_PATH) {
			GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("[Filter] Not enough memory to solve file template %s\n", szTemplate));
			return GF_OUT_OF_MEM;
		}

		strcat(szFinalName, szTemplateVal);
		k = (u32) strlen(szFinalName);

		if (!sep) break;
		sep[0] = '$';
		name = sep+1;
	}
	szFinalName[k] = 0;
	return GF_OK;
}

GF_EXPORT GF_Err gf_filter_pid_resolve_file_template(GF_FilterPid *pid, char szTemplate[GF_MAX_PATH], char szFinalName[GF_MAX_PATH], u32 file_idx, const char *file_suffix)
{
	return gf_filter_pid_resolve_file_template_ex(pid, szTemplate, szFinalName, file_idx, file_suffix, NULL);
}


GF_EXPORT GF_Err gf_filter_pid_set_discard(GF_FilterPid *pid, Bool discard_on)
{
	GF_FilterPidInst *pidi = (GF_FilterPidInst *) pid;
	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt at discarding packets on output PID %s in filter %s not allowed\n", pid->pid->name, pid->filter->name));
		return GF_BAD_PARAM;
	}
	if (discard_on) {
		GF_LOG(GF_LOG_INFO, GF_LOG_FILTER, ("Discarding packets on PID %s (filter %s to %s)\n", pid->pid->name, pid->pid->filter->name, pid->filter->name));
		gf_filter_aggregate_packets(pidi);
		
		u32 pck_discard_bck = pidi->discard_packets;
		pidi->discard_packets = 0;
		while (gf_filter_pid_get_packet(pid)) {
			gf_filter_pid_drop_packet(pid);
		}
		pidi->discard_packets = pck_discard_bck;
		pidi->is_end_of_stream = GF_TRUE;
	} else {
		
		
		
		
		if (!gf_fq_count(pidi->packets) && !pid->pid->filter->postponed_packets)
			pidi->is_end_of_stream = pid->pid->has_seen_eos;
	}
	pidi->discard_inputs = discard_on ? 1 : 0;
	return GF_OK;
}

static char *gf_filter_pid_get_dst_string(GF_FilterSession *sess, const char *_args, Bool is_dst)
{
	char *target, *sep;
	char szKey[6];
	u32 len;
	if (!_args) return NULL;

	if (is_dst)
		sprintf(szKey, "dst%c", sess->sep_name);
	else sprintf(szKey, "src%c", sess->sep_name);

	target = strstr(_args, szKey);
	if (!target) return NULL;

	sep = (char *) gf_fs_path_escape_colon(sess, target + 4);
	target += 4;
	if (sep) len = (u32) (sep - target);
	else len = (u32) strlen(target);

	char *res = gf_malloc(sizeof(char)* (len+1));
	memcpy(res, target, sizeof(char)* len);
	res[len]=0;
	return res;
}


GF_EXPORT char *gf_filter_pid_get_destination(GF_FilterPid *pid)
{
	const char *dst_args;
	char *res;
	u32 i, j;
	if (PID_IS_INPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to query destination on input PID %s in filter %s not allowed\n", pid->pid->name, pid->filter->name));
		return NULL;
	}

	dst_args = pid->filter->dst_args;
	if (!dst_args) dst_args = pid->filter->src_args;
	res = gf_filter_pid_get_dst_string(pid->filter->session, dst_args, GF_TRUE);
	if (res) return res;

	
	for (i=0; i<pid->num_destinations; i++) {
		GF_FilterPidInst *pidi = gf_list_get(pid->destinations, i);

		dst_args = pidi->filter->dst_args;
		if (!dst_args) dst_args = pidi->filter->src_args;
		res = gf_filter_pid_get_dst_string(pid->filter->session, dst_args, GF_TRUE);
		if (res) return res;

		for (j=0; j<pidi->filter->num_output_pids; j++) {
			GF_FilterPid *a_pid = gf_list_get(pidi->filter->output_pids, j);
			char *dst = gf_filter_pid_get_destination(a_pid);
			if (dst) return dst;
		}
	}
	return NULL;
}

GF_EXPORT char *gf_filter_pid_get_source(GF_FilterPid *pid)
{
	const char *src_args;
	char *res;

	u32 i;
	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to query source on output PID %s in filter %s not allowed\n", pid->pid->name, pid->filter->name));
		return NULL;
	}
	pid = pid->pid;

	src_args = pid->filter->src_args;
	if (!src_args) src_args = pid->filter->dst_args;
	res = gf_filter_pid_get_dst_string(pid->filter->session, src_args, GF_FALSE);
	if (res) return res;

	
	gf_mx_p(pid->filter->tasks_mx);
	for (i=0; i<pid->filter->num_input_pids; i++) {
		GF_FilterPidInst *pidi = gf_list_get(pid->filter->input_pids, i);

		src_args = pidi->pid->filter->src_args;
		if (!src_args) src_args = pidi->pid->filter->dst_args;
		res = gf_filter_pid_get_dst_string(pid->filter->session, src_args, GF_FALSE);
		if (res) {
			gf_mx_v(pid->filter->tasks_mx);
			return res;
		}
	}
	gf_mx_v(pid->filter->tasks_mx);
	return NULL;
}

GF_FilterPid *gf_filter_pid_first_pid_for_source(GF_FilterPid *pid, GF_Filter *source)
{
	u32 i;
	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to locate PID on output PID %s in filter %s not allowed\n", pid->pid->name, pid->filter->name));
		return NULL;
	}
	pid = pid->pid;
	for (i=0; i<pid->filter->num_input_pids; i++) {
		GF_FilterPid *a_pid;
		GF_FilterPidInst *a_pidi = gf_list_get(pid->filter->input_pids, i);
		if (gf_filter_in_parent_chain(a_pidi->pid->filter, source))
			return (GF_FilterPid *) a_pidi;
		a_pid = gf_filter_pid_first_pid_for_source((GF_FilterPid *) a_pidi, source);
		if (a_pid) return a_pid;
	}
	return NULL;

}

GF_EXPORT void gf_filter_pid_discard_block(GF_FilterPid *pid)
{
	if (PID_IS_INPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to reset block mode on input PID %s in filter %s not allowed\n", pid->pid->name, pid->filter->name));
		return;
	}
	if (!pid->has_seen_eos) {
		GF_LOG(GF_LOG_WARNING, GF_LOG_FILTER, ("Attempt to reset block mode on PID %s in filter %s not in end of stream, ignoring\n", pid->pid->name, pid->filter->name));
		return;
	}
	gf_mx_p(pid->filter->tasks_mx);
	if (pid->would_block) {
		safe_int_dec(&pid->would_block);
		assert(pid->filter->would_block);
		safe_int_dec(&pid->filter->would_block);
	}
	gf_mx_v(pid->filter->tasks_mx);
}

GF_EXPORT GF_Err gf_filter_pid_require_source_id(GF_FilterPid *pid)
{
	if (PID_IS_INPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to set require_source_id input PID %s in filter %s not allowed\n", pid->pid->name, pid->filter->name));
		return GF_BAD_PARAM;
	}
	pid->require_source_id = GF_TRUE;
	return GF_OK;
}

GF_EXPORT u32 gf_filter_pid_get_min_pck_duration(GF_FilterPid *pid)
{
	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to query min_pck_duration on output pid PID %s in filter %s not allowed\n", pid->pid->name, pid->filter->name));
		return 0;
	}
	return pid->pid->min_pck_duration;
}

GF_EXPORT void gf_filter_pid_recompute_dts(GF_FilterPid *pid, Bool do_recompute)
{
	if (PID_IS_INPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to set recompute_dts on input pid %s in filter %s not allowed\n", pid->pid->name, pid->filter->name));
		return;
	}
	pid->recompute_dts = do_recompute;
}

GF_EXPORT Bool gf_filter_pid_is_playing(GF_FilterPid *pid)
{
	if (!pid) return GF_FALSE;
	return pid->pid->is_playing;

}

GF_EXPORT GF_Err gf_filter_pid_allow_direct_dispatch(GF_FilterPid *pid)
{
	if (PID_IS_INPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to set direct dispatch mode on input pid %s in filter %s not allowed\n", pid->pid->name, pid->filter->name));
		return GF_BAD_PARAM;
	}

	if (pid->filter->session->threads)
		return GF_OK;

	pid->direct_dispatch = GF_TRUE;
	return GF_OK;
}

GF_EXPORT void *gf_filter_pid_get_alias_udta(GF_FilterPid *_pid)
{
	GF_FilterPidInst *pidi;
	if (PID_IS_OUTPUT(_pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to query multi_sink original filter context on output pid %s in filter %s not allowed\n", _pid->pid->name, _pid->filter->name));
		return NULL;
	}
	pidi = (GF_FilterPidInst *) _pid;
	if (!pidi->alias_orig) return NULL;
	return pidi->alias_orig->filter_udta;
}

GF_EXPORT GF_Filter *gf_filter_pid_get_source_filter(GF_FilterPid *pid)
{
	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to query source filter on output pid %s in filter %s not allowed\n", pid->pid->name, pid->filter->name));
		return NULL;
	}
	return pid->pid->filter;
}

GF_EXPORT GF_Filter *gf_filter_pid_enum_destinations(GF_FilterPid *pid, u32 idx)
{
	GF_FilterPidInst *dst_pid;
	if (PID_IS_INPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to query destination filters on input pid %s in filter %s not allowed\n", pid->pid->name, pid->filter->name));
		return NULL;
	}
	if (idx>=pid->num_destinations) return NULL;
	dst_pid = gf_list_get(pid->destinations, idx);
	return dst_pid->filter;
}

GF_EXPORT GF_Err gf_filter_pid_ignore_blocking(GF_FilterPid *pid, Bool do_ignore)
{
	GF_FilterPidInst *pidi;
	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to set output pid  %s in filter %s to ignore block mode not allowed\n", pid->pid->name, pid->filter->name));
		return GF_BAD_PARAM;
	}
	pidi = (GF_FilterPidInst *) pid;
	pidi->pid->ignore_blocking = do_ignore;
	return GF_OK;
}

GF_EXPORT u64 gf_filter_pid_get_next_ts(GF_FilterPid *pid)
{
	if (!pid) return GF_FILTER_NO_TS;
	u64 dts = pid->pid->last_pck_dts;
	if (dts == GF_FILTER_NO_TS)
		dts = pid->pid->last_pck_cts;
	if (dts == GF_FILTER_NO_TS)
		return dts;
	dts += pid->pid->last_pck_dur;
	return dts;
}

GF_EXPORT u32 gf_filter_pid_get_udta_flags(GF_FilterPid *pid)
{
	if (!pid) return 0;
	if (PID_IS_OUTPUT(pid)) {
		return pid->udta_flags;
	}
	return ((GF_FilterPidInst *)pid)->udta_flags;
}

GF_EXPORT GF_Err gf_filter_pid_set_udta_flags(GF_FilterPid *pid, u32 flags)
{
	if (!pid) return GF_BAD_PARAM;
	if (PID_IS_OUTPUT(pid)) {
		pid->udta_flags = flags;
	} else {
		((GF_FilterPidInst *)pid)->udta_flags = flags;
	}
	return GF_OK;
}

GF_EXPORT Bool gf_filter_pid_has_decoder(GF_FilterPid *pid)
{
	u32 i;
	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to query decoder presence on output PID %s in filter %s\n", pid->pid->name, pid->filter->name));
		return GF_FALSE;
	}
	if (pid->pid->nb_decoder_inputs)
		return GF_TRUE;
	gf_mx_p(pid->pid->filter->tasks_mx);
	for (i=0; i<pid->pid->filter->num_input_pids; i++) {
		GF_FilterPidInst *pidi = gf_list_get(pid->pid->filter->input_pids, i);
		if (gf_filter_pid_has_decoder((GF_FilterPid *) pidi)) {
			gf_mx_v(pid->pid->filter->tasks_mx);
			return GF_TRUE;
		}
	}
	gf_mx_v(pid->pid->filter->tasks_mx);
	return GF_FALSE;
}

GF_EXPORT GF_Err gf_filter_pid_set_rt_stats(GF_FilterPid *pid, u32 rtt_ms, u32 jitter_us, u32 loss_rate)
{
	GF_FilterPidInst *pidi;
	if (PID_IS_OUTPUT(pid)) {
		GF_LOG(GF_LOG_ERROR, GF_LOG_FILTER, ("Attempt to set real-time stats on output PID %s in filter %s\n", pid->pid->name, pid->filter->name));
		return GF_BAD_PARAM;
	}
	pidi = (GF_FilterPidInst*)pid;
	pidi->last_rt_report = gf_sys_clock_high_res();
	pidi->rtt = rtt_ms;
	pidi->jitter = jitter_us;
	pidi->loss_rate = loss_rate;
	return GF_OK;
}



GF_Err rfc_6381_get_codec_aac(char *szCodec, u32 codec_id,  u8 *dsi, u32 dsi_size, Bool force_sbr);
GF_Err rfc_6381_get_codec_m4v(char *szCodec, u32 codec_id, u8 *dsi, u32 dsi_size);
GF_Err rfc_6381_get_codec_avc(char *szCodec, u32 subtype, GF_AVCConfig *avcc);
GF_Err rfc_6381_get_codec_hevc(char *szCodec, u32 subtype, GF_HEVCConfig *hvcc);
GF_Err rfc_6381_get_codec_av1(char *szCodec, u32 subtype, GF_AV1Config *av1c, COLR colr);
GF_Err rfc_6381_get_codec_vpx(char *szCodec, u32 subtype, GF_VPConfig *vpcc, COLR colr);
GF_Err rfc_6381_get_codec_dolby_vision(char *szCodec, u32 subtype, GF_DOVIDecoderConfigurationRecord *dovi);
GF_Err rfc_6381_get_codec_vvc(char *szCodec, u32 subtype, GF_VVCConfig *vvcc);
GF_Err rfc_6381_get_codec_mpegha(char *szCodec, u32 subtype, u8 *dsi, u32 dsi_size, s32 pl);
GF_Err rfc_6381_get_codec_uncv(char *szCodec, u32 subtype, u8 *dsi, u32 dsi_size);
GF_Err rfc6381_codec_name_default(char *szCodec, u32 subtype, u32 codec_id);


GF_Err gf_filter_pid_get_rfc_6381_codec_string(GF_FilterPid *pid, char *szCodec, Bool force_inband, Bool force_sbr, const GF_PropertyValue *tile_base_dcd, u32 *out_inband_forced)
{
	u32 subtype=0, subtype_src=0, codec_id, stream_type;
	s32 mha_pl=-1;
	Bool is_tile_base = GF_FALSE;
	const GF_PropertyValue *p, *dcd, *dcd_enh, *dovi, *codec;
	COLR colr;

	memset(&colr, 0, sizeof(colr));
	szCodec[0] = 0;
	if (!pid) return GF_BAD_PARAM;

	p = gf_filter_pid_get_property(pid, GF_PROP_PID_CODECID);
	if (!p) return GF_BAD_PARAM;
	codec_id = p->value.uint;

	p = gf_filter_pid_get_property(pid, GF_PROP_PID_STREAM_TYPE);
	if (!p) return GF_BAD_PARAM;
	stream_type = p->value.uint;

	p = gf_filter_pid_get_property(pid, GF_PROP_PID_ISOM_SUBTYPE);
	if (p) subtype_src = p->value.uint;

	dcd = gf_filter_pid_get_property(pid, GF_PROP_PID_DECODER_CONFIG);
	dcd_enh = gf_filter_pid_get_property(pid, GF_PROP_PID_DECODER_CONFIG_ENHANCEMENT);

	
	{
		const GF_PropertyValue *p1 = gf_filter_pid_get_property(pid, GF_PROP_PID_COLR_PRIMARIES), *p2 = gf_filter_pid_get_property(pid, GF_PROP_PID_COLR_TRANSFER), *p3 = gf_filter_pid_get_property(pid, GF_PROP_PID_COLR_MX), *p4 = gf_filter_pid_get_property(pid, GF_PROP_PID_COLR_RANGE);


		if (p1 && p2 && p3 && p4) {
			colr.override = GF_TRUE;
			colr.colour_primaries = p1->value.uint;
			colr.transfer_characteristics = p2->value.uint;
			colr.matrix_coefficients = p3->value.uint;
			colr.full_range = p4->value.boolean;
		} else if (!p1 && !p2 && !p3 && !p4) {
		} else {
			GF_LOG(GF_LOG_WARNING, GF_LOG_MEDIA, ("[RFC6381] Incomplete upstream-filter 'colr' information. Ignoring.\n"));
		}
	}

	if (!force_inband) {
		const GF_PropertyValue *p = gf_filter_pid_get_property(pid, GF_PROP_PID_ISOM_SUBTYPE);
		if (p) {
			
			switch (p->value.uint) {
			case GF_ISOM_SUBTYPE_AVC3_H264:
			case GF_ISOM_SUBTYPE_AVC4_H264:
			case GF_ISOM_SUBTYPE_LHE1:
			case GF_ISOM_SUBTYPE_HEV1:
			case GF_ISOM_SUBTYPE_VVI1:
			case GF_ISOM_SUBTYPE_DVAV:
			case GF_ISOM_SUBTYPE_DVHE:
				force_inband = GF_TRUE;
				if (out_inband_forced) *out_inband_forced = 1;
				break;
			}
		}
	}

	codec = gf_filter_pid_get_property(pid, GF_PROP_PID_CODEC);
	if (codec && (codec->type==GF_PROP_STRING) && codec->value.string) {
		const char *codec_str = codec->value.string;
		if (codec_str[0] != '.') {
			snprintf(szCodec, RFC6381_CODEC_NAME_SIZE_MAX, "%s", codec_str);
			return GF_OK;
		}
		if (!subtype_src)
			subtype_src = gf_codecid_4cc_type(codec_id);
		snprintf(szCodec, RFC6381_CODEC_NAME_SIZE_MAX, "%s%s", gf_4cc_to_str(subtype_src), codec_str);
		return GF_OK;
	}

	p = gf_filter_pid_get_property(pid, GF_PROP_PID_TILE_BASE);
	if (p && p->value.boolean) is_tile_base = GF_TRUE;


	dovi = gf_filter_pid_get_property(pid, GF_PROP_PID_DOLBY_VISION);
	if (dovi) {
		GF_Err e;
		GF_BitStream *bs = gf_bs_new(dovi->value.data.ptr, dovi->value.data.size, GF_BITSTREAM_READ);
		GF_DOVIDecoderConfigurationRecord *dvcc = gf_odf_dovi_cfg_read_bs(bs);
		gf_bs_del(bs);
		if (!dvcc) {
			GF_LOG(GF_LOG_DEBUG, GF_LOG_MEDIA, ("[RFC6381] No config found for Dolby Vision file (\"%s\")\n", gf_4cc_to_str(subtype)));
			return GF_BAD_PARAM;
		}

		switch (codec_id) {
		case GF_CODECID_HEVC:
			e = rfc_6381_get_codec_dolby_vision(szCodec, force_inband ? GF_ISOM_SUBTYPE_DVHE : GF_ISOM_SUBTYPE_DVH1, dvcc);
			break;
		case GF_CODECID_AVC:
			e = rfc_6381_get_codec_dolby_vision(szCodec, force_inband ? GF_ISOM_SUBTYPE_DVAV : GF_ISOM_SUBTYPE_DVA1, dvcc);
			break;
		case GF_CODECID_AV1:
			e = rfc_6381_get_codec_dolby_vision(szCodec, GF_ISOM_SUBTYPE_DAV1, dvcc);
			break;
		default:
			e = GF_NOT_SUPPORTED;
		}
		gf_odf_dovi_cfg_del(dvcc);
		return e;
	}

	switch (codec_id) {
	case GF_CODECID_AAC_MPEG4:
	case GF_CODECID_AAC_MPEG2_MP:
	case GF_CODECID_AAC_MPEG2_LCP:
	case GF_CODECID_AAC_MPEG2_SSRP:
	case GF_CODECID_USAC:
		return rfc_6381_get_codec_aac(szCodec, codec_id, dcd ? dcd->value.data.ptr : NULL, dcd ? dcd->value.data.size : 0, force_sbr);

	case GF_CODECID_MPEG4_PART2:
		return rfc_6381_get_codec_m4v(szCodec, codec_id, dcd ? dcd->value.data.ptr : NULL, dcd ? dcd->value.data.size : 0);
		break;
	case GF_CODECID_SVC:
	case GF_CODECID_MVC:
		if (dcd_enh) dcd = dcd_enh;
		subtype = (codec_id==GF_CODECID_SVC) ? GF_ISOM_SUBTYPE_SVC_H264 : GF_ISOM_SUBTYPE_MVC_H264;
	case GF_CODECID_AVC:
		if (!subtype) {
			if (force_inband) {
				subtype = dcd_enh ? GF_ISOM_SUBTYPE_AVC4_H264 : GF_ISOM_SUBTYPE_AVC3_H264;
			} else {
				subtype = dcd_enh ? GF_ISOM_SUBTYPE_AVC2_H264 : GF_ISOM_SUBTYPE_AVC_H264;
			}
		}
		if (dcd) {
			GF_AVCConfig *avcc = gf_odf_avc_cfg_read(dcd->value.data.ptr, dcd->value.data.size);
			if (avcc) {
				GF_Err e = rfc_6381_get_codec_avc(szCodec, subtype, avcc);
				gf_odf_avc_cfg_del(avcc);
				return e;
			}
		}
		snprintf(szCodec, RFC6381_CODEC_NAME_SIZE_MAX, "%s", gf_4cc_to_str(subtype));
		GF_LOG(GF_LOG_WARNING, GF_LOG_MEDIA, ("[RFC6381] Cannot find AVC config, using default %s\n", szCodec));
		return GF_OK;


	case GF_CODECID_LHVC:
		subtype = force_inband ? GF_ISOM_SUBTYPE_LHE1 : GF_ISOM_SUBTYPE_LHV1;
		
	case GF_CODECID_HEVC_TILES:
		if (!subtype) subtype = GF_ISOM_SUBTYPE_HVT1;
		if (!dcd && tile_base_dcd) dcd = tile_base_dcd;

		
	case GF_CODECID_HEVC:
		if (!subtype) {
			if (is_tile_base) {
				subtype = force_inband ? GF_ISOM_SUBTYPE_HEV2 : GF_ISOM_SUBTYPE_HVC2;
			} else if (dcd_enh) {
				if (dcd) {
					subtype = force_inband ? GF_ISOM_SUBTYPE_HEV2 : GF_ISOM_SUBTYPE_HVC2;
				} else {
					subtype = force_inband ? GF_ISOM_SUBTYPE_LHE1 : GF_ISOM_SUBTYPE_LHV1;
				}
			} else {
				subtype = force_inband ? GF_ISOM_SUBTYPE_HEV1 : GF_ISOM_SUBTYPE_HVC1;
			}
		}
		if (dcd || dcd_enh) {
			GF_HEVCConfig *hvcc = dcd ? gf_odf_hevc_cfg_read(dcd->value.data.ptr, dcd->value.data.size, GF_FALSE) : NULL;
			if (hvcc) {
				GF_Err e = rfc_6381_get_codec_hevc(szCodec, subtype, hvcc);
				gf_odf_hevc_cfg_del(hvcc);
				return e;
			}
			GF_LOG(GF_LOG_ERROR, GF_LOG_MEDIA, ("[RFC6381] HEVC config not compliant !\n"));
			return GF_NON_COMPLIANT_BITSTREAM;
		}

		snprintf(szCodec, RFC6381_CODEC_NAME_SIZE_MAX, "%s", gf_4cc_to_str(subtype));
		GF_LOG(GF_LOG_WARNING, GF_LOG_MEDIA, ("[RFC6381]  Cannot find HEVC config, using default %s\n", szCodec));
		return GF_OK;



	case GF_CODECID_AV1:
		if (!subtype) subtype = GF_ISOM_SUBTYPE_AV01;

		if (dcd) {
			GF_AV1Config *av1c = gf_odf_av1_cfg_read(dcd->value.data.ptr, dcd->value.data.size);
			if (av1c) {
				GF_Err e = rfc_6381_get_codec_av1(szCodec, subtype, av1c, colr);
				gf_odf_av1_cfg_del(av1c);
				return e;
			}
			GF_LOG(GF_LOG_ERROR, GF_LOG_MEDIA, ("[RFC6381] AV1 config not conformant\n"));
			return GF_NON_COMPLIANT_BITSTREAM;
		}
		snprintf(szCodec, RFC6381_CODEC_NAME_SIZE_MAX, "%s", gf_4cc_to_str(subtype));
		GF_LOG(GF_LOG_WARNING, GF_LOG_MEDIA, ("[RFC6381] Cannot find AV1 config, using default %s\n", szCodec));
		return GF_OK;



	case GF_CODECID_VP8:
		if (!subtype) subtype = GF_ISOM_SUBTYPE_VP08;
	case GF_CODECID_VP9:
		if (!subtype) subtype = GF_ISOM_SUBTYPE_VP09;

		if (dcd) {
			GF_VPConfig *vpcc = gf_odf_vp_cfg_read(dcd->value.data.ptr, dcd->value.data.size);

			if (vpcc) {
				GF_Err e = rfc_6381_get_codec_vpx(szCodec, subtype, vpcc, colr);
				gf_odf_vp_cfg_del(vpcc);
				return e;
			}
			GF_LOG(GF_LOG_DEBUG, GF_LOG_MEDIA, ("[RFC6381] No config found for VP file (\"%s\").\n", gf_4cc_to_str(subtype)));
			return GF_NON_COMPLIANT_BITSTREAM;
		}
		snprintf(szCodec, RFC6381_CODEC_NAME_SIZE_MAX, "%s", gf_4cc_to_str(subtype));
		GF_LOG(GF_LOG_WARNING, GF_LOG_MEDIA, ("[RFC6381] Cannot find VPX config, using default %s\n", szCodec));
		return GF_OK;

	case GF_CODECID_MHAS:
		subtype = subtype_src ? subtype_src : GF_ISOM_SUBTYPE_MH3D_MHM1;
		if (!dcd) {
			const GF_PropertyValue *pl = gf_filter_pid_get_property(pid, GF_PROP_PID_PROFILE_LEVEL);
			if (pl) mha_pl = (s32) pl->value.uint;
		}
		
	case GF_CODECID_MPHA:
		if (!subtype)
			subtype = subtype_src ? subtype_src : GF_ISOM_SUBTYPE_MH3D_MHA1;

		return rfc_6381_get_codec_mpegha(szCodec, subtype, dcd ? dcd->value.data.ptr : NULL, dcd ? dcd->value.data.size : 0, mha_pl);

	case GF_CODECID_VVC:
		if (!subtype) {
			subtype = force_inband ? GF_ISOM_SUBTYPE_VVI1 : GF_ISOM_SUBTYPE_VVC1;
		}
		if (dcd) {
			GF_VVCConfig *vvcc = gf_odf_vvc_cfg_read(dcd->value.data.ptr, dcd->value.data.size);

			snprintf(szCodec, RFC6381_CODEC_NAME_SIZE_MAX, "%s.", gf_4cc_to_str(subtype));
			if (vvcc) {
				GF_Err e = rfc_6381_get_codec_vvc(szCodec, subtype, vvcc);
				gf_odf_vvc_cfg_del(vvcc);
				return e;
			}
			GF_LOG(GF_LOG_DEBUG, GF_LOG_MEDIA, ("[RFC6381] No config found for VP file (\"%s\")\n", gf_4cc_to_str(subtype)));
			return GF_NON_COMPLIANT_BITSTREAM;
		}
		snprintf(szCodec, RFC6381_CODEC_NAME_SIZE_MAX, "%s", gf_4cc_to_str(subtype));
		GF_LOG(GF_LOG_WARNING, GF_LOG_MEDIA, ("[RFC6381] Cannot find VVC config, using default %s\n", szCodec));
		return GF_OK;

	case GF_CODECID_RAW_UNCV:
		return rfc_6381_get_codec_uncv(szCodec, subtype, dcd->value.data.ptr, dcd->value.data.size);
	default:
		subtype = gf_codecid_4cc_type(codec_id);
		if (!subtype) {
			const GF_PropertyValue *p = gf_filter_pid_get_property(pid, GF_PROP_PID_ISOM_SUBTYPE);
			if (p) subtype = p->value.uint;
		}
		if (!subtype && (codec_id==GF_CODECID_RAW)) {
			if (stream_type==GF_STREAM_VISUAL) {
				p = gf_filter_pid_get_property(pid, GF_PROP_PID_PIXFMT);
				if (p) subtype = gf_pixel_fmt_to_qt_type(p->value.uint);
			}
			else if (stream_type==GF_STREAM_AUDIO) {
				p = gf_filter_pid_get_property(pid, GF_PROP_PID_AUDIO_FORMAT);
				if (p) subtype = gf_audio_fmt_to_isobmf(p->value.uint);
			}
		}

		if (!subtype) {
			const char *mime = gf_codecid_mime(codec_id);
			if (mime) mime = strchr(mime, '/');
			if (mime) mime++;
			if (mime && mime[0] && strcmp(mime, "octet-string")) {
				GF_LOG(GF_LOG_INFO, GF_LOG_MEDIA, ("[RFC6381] Codec parameters not known, using mime type %s\n", mime));
				strcpy(szCodec, mime);
				return GF_OK;
			}
			GF_LOG(GF_LOG_INFO, GF_LOG_MEDIA, ("[RFC6381] Codec parameters not known, cannot set codec string\n" ));
			strcpy(szCodec, "unkn");
			return GF_OK;
		}

		return rfc6381_codec_name_default(szCodec, subtype, codec_id);
	}
	return GF_OK;
}
