









static void _progress_coll_tree(pmixp_coll_t *coll);
static void _reset_coll(pmixp_coll_t *coll);

static int _pack_coll_info(pmixp_coll_t *coll, Buf buf)
{
	pmixp_proc_t *procs = coll->pset.procs;
	size_t nprocs = coll->pset.nprocs;
	uint32_t size;
	int i;

	
	size = coll->type;
	pack32(size, buf);

	
	pack32(nprocs, buf);
	for (i = 0; i < (int)nprocs; i++) {
		
		packmem(procs->nspace, strlen(procs->nspace) + 1, buf);
		pack32(procs->rank, buf);
	}

	return SLURM_SUCCESS;
}

int pmixp_coll_tree_unpack(Buf buf, pmixp_coll_type_t *type, int *nodeid, pmixp_proc_t **r, size_t *nr)
{
	pmixp_proc_t *procs = NULL;
	uint32_t nprocs = 0;
	uint32_t tmp;
	int i, rc;

	
	if (SLURM_SUCCESS != (rc = unpack32(&tmp, buf))) {
		PMIXP_ERROR("Cannot unpack collective type");
		return rc;
	}
	*type = tmp;

	
	if (SLURM_SUCCESS != (rc = unpack32(&nprocs, buf))) {
		PMIXP_ERROR("Cannot unpack collective type");
		return rc;
	}
	*nr = nprocs;

	procs = xmalloc(sizeof(pmixp_proc_t) * nprocs);
	*r = procs;

	for (i = 0; i < (int)nprocs; i++) {
		
		rc = unpackmem(procs[i].nspace, &tmp, buf);
		if (SLURM_SUCCESS != rc) {
			PMIXP_ERROR("Cannot unpack namespace for process #%d", i);
			return rc;
		}
		procs[i].nspace[tmp] = '\0';

		unsigned int tmp;
		rc = unpack32(&tmp, buf);
		procs[i].rank = tmp;
		if (SLURM_SUCCESS != rc) {
			PMIXP_ERROR("Cannot unpack ranks for process #%d, nsp=%s", i, procs[i].nspace);
			return rc;
		}
	}
	return SLURM_SUCCESS;
}

static void _reset_coll_ufwd(pmixp_coll_t *coll)
{
	pmixp_coll_tree_t *tree = &coll->state.tree;

	
	tree->contrib_children = 0;
	tree->contrib_local = false;
	memset(tree->contrib_chld, 0, sizeof(tree->contrib_chld[0]) * tree->chldrn_cnt);
	tree->serv_offs = pmixp_server_buf_reset(tree->ufwd_buf);
	if (SLURM_SUCCESS != _pack_coll_info(coll, tree->ufwd_buf)) {
		PMIXP_ERROR("Cannot pack ranges to message header!");
	}
	tree->ufwd_offset = get_buf_offset(tree->ufwd_buf);
	tree->ufwd_status = PMIXP_COLL_TREE_SND_NONE;
}

static void _reset_coll_dfwd(pmixp_coll_t *coll)
{
	
	(void)pmixp_server_buf_reset(coll->state.tree.dfwd_buf);
	if (SLURM_SUCCESS != _pack_coll_info(coll, coll->state.tree.dfwd_buf)) {
		PMIXP_ERROR("Cannot pack ranges to message header!");
	}
	coll->state.tree.dfwd_cb_cnt = 0;
	coll->state.tree.dfwd_cb_wait = 0;
	coll->state.tree.dfwd_status = PMIXP_COLL_TREE_SND_NONE;
	coll->state.tree.contrib_prnt = false;
	
	coll->state.tree.dfwd_offset = get_buf_offset( coll->state.tree.dfwd_buf);
}

static void _reset_coll(pmixp_coll_t *coll)
{
	pmixp_coll_tree_t *tree = &coll->state.tree;

	switch (tree->state) {
	case PMIXP_COLL_TREE_SYNC:
		
		xassert(!tree->contrib_local && !tree->contrib_children && !tree->contrib_prnt);
		break;
	case PMIXP_COLL_TREE_COLLECT:
	case PMIXP_COLL_TREE_UPFWD:
	case PMIXP_COLL_TREE_UPFWD_WSC:
		coll->seq++;
		tree->state = PMIXP_COLL_TREE_SYNC;
		_reset_coll_ufwd(coll);
		_reset_coll_dfwd(coll);
		coll->cbdata = NULL;
		coll->cbfunc = NULL;
		break;
	case PMIXP_COLL_TREE_UPFWD_WPC:
		
	case PMIXP_COLL_TREE_DOWNFWD:
		
		coll->seq++;
		_reset_coll_dfwd(coll);
		if (tree->contrib_local || tree->contrib_children) {
			
			tree->state = PMIXP_COLL_TREE_COLLECT;
		} else {
			tree->state = PMIXP_COLL_TREE_SYNC;
		}
		break;
	default:
		PMIXP_ERROR("Bad collective state = %d", (int)tree->state);
		
		tree->state = PMIXP_COLL_TREE_SYNC;
		slurm_kill_job_step(pmixp_info_jobid(), pmixp_info_stepid(), SIGKILL);
	}
}


int pmixp_coll_tree_init(pmixp_coll_t *coll, hostlist_t *hl)
{
	int max_depth, width, depth, i;
	char *p;
	pmixp_coll_tree_t *tree = NULL;

	tree = &coll->state.tree;
	tree->state = PMIXP_COLL_TREE_SYNC;

	width = slurm_get_tree_width();
	reverse_tree_info(coll->my_peerid, coll->peers_cnt, width, &tree->prnt_peerid, &tree->chldrn_cnt, &depth, &max_depth);


	
	tree->contrib_children = 0;
	tree->contrib_local = false;
	tree->chldrn_ids = xmalloc(sizeof(int) * width);
	tree->contrib_chld = xmalloc(sizeof(int) * width);
	tree->chldrn_cnt = reverse_tree_direct_children(coll->my_peerid, coll->peers_cnt, width, depth, tree->chldrn_ids);


	if (tree->prnt_peerid == -1) {
		
		tree->prnt_host = NULL;
		tree->all_chldrn_hl = hostlist_copy(*hl);
		hostlist_delete_host(tree->all_chldrn_hl, pmixp_info_hostname());
		tree->chldrn_str = hostlist_ranged_string_xmalloc(tree->all_chldrn_hl);
	} else {
		

		
		p = hostlist_nth(*hl, tree->prnt_peerid);
		tree->prnt_host = xstrdup(p);
		free(p);
		
		tree->prnt_peerid = pmixp_info_job_hostid(tree->prnt_host);

		
		p = hostlist_nth(*hl, 0);
		tree->root_host = xstrdup(p);
		free(p);
		
		tree->root_peerid = pmixp_info_job_hostid(tree->root_host);

		
		tree->all_chldrn_hl = hostlist_create("");
		tree->chldrn_str = NULL;
	}

	
	for(i=0; i<tree->chldrn_cnt; i++){
		p = hostlist_nth(*hl, tree->chldrn_ids[i]);
		tree->chldrn_ids[i] = pmixp_info_job_hostid(p);
		free(p);
	}

	
	tree->ufwd_buf = pmixp_server_buf_new();
	tree->dfwd_buf = pmixp_server_buf_new();
	_reset_coll_ufwd(coll);
	_reset_coll_dfwd(coll);
	coll->cbdata = NULL;
	coll->cbfunc = NULL;

	
	slurm_mutex_init(&coll->lock);

	return SLURM_SUCCESS;
}

void pmixp_coll_tree_free(pmixp_coll_tree_t *tree)
{
	if (NULL != tree->prnt_host) {
		xfree(tree->prnt_host);
	}
	if (NULL != tree->root_host) {
		xfree(tree->root_host);
	}
	hostlist_destroy(tree->all_chldrn_hl);
	if (tree->chldrn_str) {
		xfree(tree->chldrn_str);
	}
	if (NULL != tree->contrib_chld) {
		xfree(tree->contrib_chld);
	}
	FREE_NULL_BUFFER(tree->ufwd_buf);
	FREE_NULL_BUFFER(tree->dfwd_buf);
}

typedef struct {
	pmixp_coll_t *coll;
	uint32_t seq;
	volatile uint32_t refcntr;
} pmixp_coll_cbdata_t;


pmixp_coll_t *pmixp_coll_tree_from_cbdata(void *cbdata)
{
	pmixp_coll_cbdata_t *ptr = (pmixp_coll_cbdata_t*)cbdata;
	pmixp_coll_sanity_check(ptr->coll);
	return ptr->coll;
}

static void _ufwd_sent_cb(int rc, pmixp_p2p_ctx_t ctx, void *_vcbdata)
{
	pmixp_coll_cbdata_t *cbdata = (pmixp_coll_cbdata_t*)_vcbdata;
	pmixp_coll_t *coll = cbdata->coll;
	pmixp_coll_tree_t *tree = &coll->state.tree;

	if( PMIXP_P2P_REGULAR == ctx ){
		
		slurm_mutex_lock(&coll->lock);
	}
	if (cbdata->seq != coll->seq) {
		
		PMIXP_DEBUG("Collective was reset!");
		goto exit;
	}

	xassert(PMIXP_COLL_TREE_UPFWD == tree->state || PMIXP_COLL_TREE_UPFWD_WSC == tree->state);


	
	if( SLURM_SUCCESS == rc ){
		tree->ufwd_status = PMIXP_COLL_TREE_SND_DONE;
	} else {
		tree->ufwd_status = PMIXP_COLL_TREE_SND_FAILED;
	}


	PMIXP_DEBUG("%p: state: %s, snd_status=%s", coll, pmixp_coll_tree_state2str(tree->state), pmixp_coll_tree_sndstatus2str(tree->ufwd_status));



exit:
	xassert(0 < cbdata->refcntr);
	cbdata->refcntr--;
	if (!cbdata->refcntr) {
		xfree(cbdata);
	}

	if( PMIXP_P2P_REGULAR == ctx ){
		
		_progress_coll_tree(coll);

		
		slurm_mutex_unlock(&coll->lock);
	}
}

static void _dfwd_sent_cb(int rc, pmixp_p2p_ctx_t ctx, void *_vcbdata)
{
	pmixp_coll_cbdata_t *cbdata = (pmixp_coll_cbdata_t*)_vcbdata;
	pmixp_coll_t *coll = cbdata->coll;
	pmixp_coll_tree_t *tree = &coll->state.tree;

	if( PMIXP_P2P_REGULAR == ctx ){
		
		slurm_mutex_lock(&coll->lock);
	}

	if (cbdata->seq != coll->seq) {
		
		PMIXP_DEBUG("Collective was reset!");
		goto exit;
	}

	xassert(PMIXP_COLL_TREE_DOWNFWD == tree->state);

	
	if( SLURM_SUCCESS == rc ){
		tree->dfwd_cb_cnt++;
	} else {
		tree->dfwd_status = PMIXP_COLL_TREE_SND_FAILED;
	}


	PMIXP_DEBUG("%p: state: %s, snd_status=%s, compl_cnt=%d/%d", coll, pmixp_coll_tree_state2str(tree->state), pmixp_coll_tree_sndstatus2str(tree->dfwd_status), tree->dfwd_cb_cnt, tree->dfwd_cb_wait);




exit:
	xassert(0 < cbdata->refcntr);
	cbdata->refcntr--;
	if (!cbdata->refcntr) {
		xfree(cbdata);
	}

	if( PMIXP_P2P_REGULAR == ctx ){
		
		_progress_coll_tree(coll);

		
		slurm_mutex_unlock(&coll->lock);
	}
}

static void _libpmix_cb(void *_vcbdata)
{
	pmixp_coll_cbdata_t *cbdata = (pmixp_coll_cbdata_t*)_vcbdata;
	pmixp_coll_t *coll = cbdata->coll;
	pmixp_coll_tree_t *tree = &coll->state.tree;

	
	slurm_mutex_lock(&coll->lock);

	if (cbdata->seq != coll->seq) {
		
		PMIXP_ERROR("%p: collective was reset: myseq=%u, curseq=%u", coll, cbdata->seq, coll->seq);
		goto exit;
	}

	xassert(PMIXP_COLL_TREE_DOWNFWD == tree->state);

	tree->dfwd_cb_cnt++;

	PMIXP_DEBUG("%p: state: %s, snd_status=%s, compl_cnt=%d/%d", coll, pmixp_coll_tree_state2str(tree->state), pmixp_coll_tree_sndstatus2str(tree->dfwd_status), tree->dfwd_cb_cnt, tree->dfwd_cb_wait);



	_progress_coll_tree(coll);

exit:
	xassert(0 < cbdata->refcntr);
	cbdata->refcntr--;
	if (!cbdata->refcntr) {
		xfree(cbdata);
	}

	
	slurm_mutex_unlock(&coll->lock);
}

static int _progress_collect(pmixp_coll_t *coll)
{
	pmixp_ep_t ep = {0};
	int rc;
	pmixp_coll_tree_t *tree = &coll->state.tree;

	xassert(PMIXP_COLL_TREE_COLLECT == tree->state);

	ep.type = PMIXP_EP_NONE;

	PMIXP_DEBUG("%p: state=%s, local=%d, child_cntr=%d", coll, pmixp_coll_tree_state2str(tree->state), (int)tree->contrib_local, tree->contrib_children);


	
	pmixp_coll_sanity_check(coll);

	if (PMIXP_COLL_TREE_COLLECT != tree->state) {
		
		return 0;
	}

	if (!tree->contrib_local || tree->contrib_children != tree->chldrn_cnt) {
		
		return 0;
	}

	if (pmixp_info_srv_direct_conn()) {
		
		tree->state = PMIXP_COLL_TREE_UPFWD;
	} else {
		
		if (0 > tree->prnt_peerid) {
			tree->state = PMIXP_COLL_TREE_UPFWD;
		} else {
			tree->state = PMIXP_COLL_TREE_UPFWD_WSC;
		}
	}

	
	if (NULL != tree->prnt_host) {
		ep.type = PMIXP_EP_NOIDEID;
		ep.ep.nodeid = tree->prnt_peerid;
		tree->ufwd_status = PMIXP_COLL_TREE_SND_ACTIVE;
		PMIXP_DEBUG("%p: send data to %s:%d", coll, tree->prnt_host, tree->prnt_peerid);
	} else {
		
		char *dst, *src = get_buf_data(tree->ufwd_buf) + tree->ufwd_offset;
		size_t size = get_buf_offset(tree->ufwd_buf) - tree->ufwd_offset;
		pmixp_server_buf_reserve(tree->dfwd_buf, size);
		dst = get_buf_data(tree->dfwd_buf) + tree->dfwd_offset;
		memcpy(dst, src, size);
		set_buf_offset(tree->dfwd_buf, tree->dfwd_offset + size);
		
		tree->ufwd_status = PMIXP_COLL_TREE_SND_DONE;
		
		tree->contrib_prnt = true;
	}

	if (PMIXP_EP_NONE != ep.type) {
		pmixp_coll_cbdata_t *cbdata;
		cbdata = xmalloc(sizeof(pmixp_coll_cbdata_t));
		cbdata->coll = coll;
		cbdata->seq = coll->seq;
		cbdata->refcntr = 1;
		char *nodename = tree->prnt_host;
		rc = pmixp_server_send_nb(&ep, PMIXP_MSG_FAN_IN, coll->seq, tree->ufwd_buf, _ufwd_sent_cb, cbdata);


		if (SLURM_SUCCESS != rc) {
			PMIXP_ERROR("Cannot send data (size = %u), to %s:%d", get_buf_offset(tree->ufwd_buf), nodename, ep.ep.nodeid);

			tree->ufwd_status = PMIXP_COLL_TREE_SND_FAILED;
		}

		PMIXP_DEBUG("%p: fwd to %s:%d, size = %u", coll, nodename, ep.ep.nodeid, get_buf_offset(tree->dfwd_buf));


	}

	
	return true;
}

static int _progress_ufwd(pmixp_coll_t *coll)
{
	pmixp_coll_tree_t *tree = &coll->state.tree;
	pmixp_ep_t ep[tree->chldrn_cnt];
	int ep_cnt = 0;
	int rc, i;
	char *nodename = NULL;
	pmixp_coll_cbdata_t *cbdata = NULL;

	xassert(PMIXP_COLL_TREE_UPFWD == tree->state);

	

	switch (tree->ufwd_status) {
	case PMIXP_COLL_TREE_SND_FAILED:
		

		
		pmixp_coll_localcb_nodata(coll, SLURM_ERROR);

		_reset_coll(coll);
		
		return false;
	case PMIXP_COLL_TREE_SND_ACTIVE:
		
		return false;
	case PMIXP_COLL_TREE_SND_DONE:
		if (tree->contrib_prnt) {
			
			break;
		}
		return false;
	default:
		
		PMIXP_ERROR("Bad collective ufwd state=%d", (int)tree->ufwd_status);
		
		tree->state = PMIXP_COLL_TREE_SYNC;
		slurm_kill_job_step(pmixp_info_jobid(), pmixp_info_stepid(), SIGKILL);
		return false;
	}

	
	_reset_coll_ufwd(coll);

	
	tree->state = PMIXP_COLL_TREE_DOWNFWD;
	tree->dfwd_status = PMIXP_COLL_TREE_SND_ACTIVE;
	if (!pmixp_info_srv_direct_conn()) {
		
		xassert(0 > tree->prnt_peerid);
		if (tree->chldrn_cnt) {
			
			ep[ep_cnt].type = PMIXP_EP_HLIST;
			ep[ep_cnt].ep.hostlist = tree->chldrn_str;
			ep_cnt++;
		}
	} else {
		for(i=0; i<tree->chldrn_cnt; i++){
			ep[i].type = PMIXP_EP_NOIDEID;
			ep[i].ep.nodeid = tree->chldrn_ids[i];
			ep_cnt++;
		}
	}

	
	tree->dfwd_cb_wait = ep_cnt;

	if (ep_cnt || coll->cbfunc) {
		
		cbdata = xmalloc(sizeof(pmixp_coll_cbdata_t));
		cbdata->coll = coll;
		cbdata->seq = coll->seq;
		cbdata->refcntr = ep_cnt;
		if (coll->cbfunc) {
			cbdata->refcntr++;
		}
	}

	for(i=0; i < ep_cnt; i++){
		rc = pmixp_server_send_nb(&ep[i], PMIXP_MSG_FAN_OUT, coll->seq, tree->dfwd_buf, _dfwd_sent_cb, cbdata);


		if (SLURM_SUCCESS != rc) {
			if (PMIXP_EP_NOIDEID == ep[i].type){
				nodename = pmixp_info_job_host(ep[i].ep.nodeid);
				PMIXP_ERROR("Cannot send data (size = %u), " "to %s:%d", get_buf_offset(tree->dfwd_buf), nodename, ep[i].ep.nodeid);


				xfree(nodename);
			} else {
				PMIXP_ERROR("Cannot send data (size = %u), " "to %s", get_buf_offset(tree->dfwd_buf), ep[i].ep.hostlist);


			}
			tree->dfwd_status = PMIXP_COLL_TREE_SND_FAILED;
		}

		if (PMIXP_EP_NOIDEID == ep[i].type) {
			nodename = pmixp_info_job_host(ep[i].ep.nodeid);
			PMIXP_DEBUG("%p: fwd to %s:%d, size = %u", coll, nodename, ep[i].ep.nodeid, get_buf_offset(tree->dfwd_buf));

			xfree(nodename);
		} else {
			PMIXP_DEBUG("%p: fwd to %s, size = %u", coll, ep[i].ep.hostlist, get_buf_offset(tree->dfwd_buf));

		}

	}

	if (coll->cbfunc) {
		char *data = get_buf_data(tree->dfwd_buf) + tree->dfwd_offset;
		size_t size = get_buf_offset(tree->dfwd_buf) - tree->dfwd_offset;
		tree->dfwd_cb_wait++;
		pmixp_lib_modex_invoke(coll->cbfunc, SLURM_SUCCESS, data, size, coll->cbdata, _libpmix_cb, (void*)cbdata);

		
		coll->cbfunc = NULL;
		coll->cbdata = NULL;

		PMIXP_DEBUG("%p: local delivery, size = %lu", coll, size);

	}

	
	return true;
}

static int _progress_ufwd_sc(pmixp_coll_t *coll)
{
	pmixp_coll_tree_t *tree = &coll->state.tree;

	xassert(PMIXP_COLL_TREE_UPFWD_WSC == tree->state);

	
	switch (tree->ufwd_status) {
	case PMIXP_COLL_TREE_SND_FAILED:
		

		
		pmixp_coll_localcb_nodata(coll, SLURM_ERROR);

		_reset_coll(coll);
		
		return false;
	case PMIXP_COLL_TREE_SND_ACTIVE:
		
		return false;
	case PMIXP_COLL_TREE_SND_DONE:
		
		break;
	default:
		
		PMIXP_ERROR("Bad collective ufwd state=%d", (int)tree->ufwd_status);
		
		tree->state = PMIXP_COLL_TREE_SYNC;
		slurm_kill_job_step(pmixp_info_jobid(), pmixp_info_stepid(), SIGKILL);
		return false;
	}

	
	_reset_coll_ufwd(coll);

	
	tree->state = PMIXP_COLL_TREE_UPFWD_WPC;
	return true;
}

static int _progress_ufwd_wpc(pmixp_coll_t *coll)
{
	pmixp_coll_tree_t *tree = &coll->state.tree;
	xassert(PMIXP_COLL_TREE_UPFWD_WPC == tree->state);

	if (!tree->contrib_prnt) {
		return false;
	}

	
	tree->dfwd_status = PMIXP_COLL_TREE_SND_ACTIVE;
	tree->dfwd_cb_wait = 0;


	
	tree->state = PMIXP_COLL_TREE_DOWNFWD;

	
	if (coll->cbfunc) {
		pmixp_coll_cbdata_t *cbdata;
		cbdata = xmalloc(sizeof(pmixp_coll_cbdata_t));
		cbdata->coll = coll;
		cbdata->seq = coll->seq;
		cbdata->refcntr = 1;

		char *data = get_buf_data(tree->dfwd_buf) + tree->dfwd_offset;
		size_t size = get_buf_offset(tree->dfwd_buf) - tree->dfwd_offset;
		pmixp_lib_modex_invoke(coll->cbfunc, SLURM_SUCCESS, data, size, coll->cbdata, _libpmix_cb, (void *)cbdata);

		tree->dfwd_cb_wait++;
		
		coll->cbfunc = NULL;
		coll->cbdata = NULL;

		PMIXP_DEBUG("%p: local delivery, size = %lu", coll, size);

	}

	
	return true;
}

static int _progress_dfwd(pmixp_coll_t *coll)
{
	pmixp_coll_tree_t *tree = &coll->state.tree;
	xassert(PMIXP_COLL_TREE_DOWNFWD == tree->state);

	
	if (tree->dfwd_cb_wait == tree->dfwd_cb_cnt) {
		tree->dfwd_status = PMIXP_COLL_TREE_SND_DONE;
	}

	switch (tree->dfwd_status) {
	case PMIXP_COLL_TREE_SND_ACTIVE:
		return false;
	case PMIXP_COLL_TREE_SND_FAILED:
		
		PMIXP_ERROR("%p: failed to send, abort collective", coll);


		
		pmixp_coll_localcb_nodata(coll, SLURM_ERROR);

		_reset_coll(coll);
		
		return false;
	case PMIXP_COLL_TREE_SND_DONE:
		break;
	default:
		
		PMIXP_ERROR("Bad collective dfwd state=%d", (int)tree->dfwd_status);
		
		tree->state = PMIXP_COLL_TREE_SYNC;
		slurm_kill_job_step(pmixp_info_jobid(), pmixp_info_stepid(), SIGKILL);
		return false;
	}

	PMIXP_DEBUG("%p: %s seq=%d is DONE", coll, pmixp_coll_type2str(coll->type), coll->seq);

	_reset_coll(coll);

	return true;
}

static void _progress_coll_tree(pmixp_coll_t *coll)
{
	pmixp_coll_tree_t *tree = &coll->state.tree;
	int ret = 0;

	do {
		switch (tree->state) {
		case PMIXP_COLL_TREE_SYNC:
			
			if (tree->contrib_local || tree->contrib_children) {
				tree->state = PMIXP_COLL_TREE_COLLECT;
				ret = true;
			} else {
				ret = false;
			}
			break;
		case PMIXP_COLL_TREE_COLLECT:
			ret = _progress_collect(coll);
			break;
		case PMIXP_COLL_TREE_UPFWD:
			ret = _progress_ufwd(coll);
			break;
		case PMIXP_COLL_TREE_UPFWD_WSC:
			ret = _progress_ufwd_sc(coll);
			break;
		case PMIXP_COLL_TREE_UPFWD_WPC:
			ret = _progress_ufwd_wpc(coll);
			break;
		case PMIXP_COLL_TREE_DOWNFWD:
			ret = _progress_dfwd(coll);
			break;
		default:
			PMIXP_ERROR("%p: unknown state = %d", coll, tree->state);
		}
	} while(ret);
}

int pmixp_coll_tree_local(pmixp_coll_t *coll, char *data, size_t size, void *cbfunc, void *cbdata)
{
	pmixp_coll_tree_t *tree = NULL;
	int ret = SLURM_SUCCESS;

	pmixp_debug_hang(0);

	
	pmixp_coll_sanity_check(coll);

	
	slurm_mutex_lock(&coll->lock);
	tree = &coll->state.tree;


	PMIXP_DEBUG("%p: contrib/loc: seqnum=%u, state=%s, size=%zu", coll, coll->seq, pmixp_coll_tree_state2str(tree->state), size);



	switch (tree->state) {
	case PMIXP_COLL_TREE_SYNC:
		
		coll->ts = time(NULL);
		
	case PMIXP_COLL_TREE_COLLECT:
		
		break;
	case PMIXP_COLL_TREE_DOWNFWD:
		

		PMIXP_DEBUG("%p: contrib/loc: next coll!", coll);

		break;
	case PMIXP_COLL_TREE_UPFWD:
	case PMIXP_COLL_TREE_UPFWD_WSC:
	case PMIXP_COLL_TREE_UPFWD_WPC:
		

		PMIXP_DEBUG("%p: contrib/loc: before prev coll is finished!", coll);

		ret = SLURM_ERROR;
		goto exit;
	default:
		
		PMIXP_ERROR("%p: local contrib while active collective, state = %s", coll, pmixp_coll_tree_state2str(tree->state));
		
		tree->state = PMIXP_COLL_TREE_SYNC;
		slurm_kill_job_step(pmixp_info_jobid(), pmixp_info_stepid(), SIGKILL);
		ret = SLURM_ERROR;
		goto exit;
	}

	if (tree->contrib_local) {
		
		ret = SLURM_ERROR;
		goto exit;
	}

	
	tree->contrib_local = true;
	pmixp_server_buf_reserve(tree->ufwd_buf, size);
	memcpy(get_buf_data(tree->ufwd_buf) + get_buf_offset(tree->ufwd_buf), data, size);
	set_buf_offset(tree->ufwd_buf, get_buf_offset(tree->ufwd_buf) + size);

	
	coll->cbfunc = cbfunc;
	coll->cbdata = cbdata;

	
	_progress_coll_tree(coll);


	PMIXP_DEBUG("%p: finish, state=%s", coll, pmixp_coll_tree_state2str(tree->state));


exit:
	
	slurm_mutex_unlock(&coll->lock);
	return ret;
}

static int _chld_id(pmixp_coll_tree_t *tree, uint32_t nodeid)
{
	int i;

	for (i=0; i<tree->chldrn_cnt; i++) {
		if (tree->chldrn_ids[i] == nodeid) {
			return i;
		}
	}
	return -1;
}

static char *_chld_ids_str(pmixp_coll_tree_t *tree)
{
	char *p = NULL;
	int i;

	for (i=0; i<tree->chldrn_cnt; i++) {
		if ((tree->chldrn_cnt-1) > i) {
			xstrfmtcat(p, "%d, ", tree->chldrn_ids[i]);
		} else {
			xstrfmtcat(p, "%d", tree->chldrn_ids[i]);
		}
	}
	return p;
}


int pmixp_coll_tree_child(pmixp_coll_t *coll, uint32_t peerid, uint32_t seq, Buf buf)
{
	char *data_src = NULL, *data_dst = NULL;
	uint32_t size;
	int chld_id;
	pmixp_coll_tree_t *tree = NULL;

	
	slurm_mutex_lock(&coll->lock);
	pmixp_coll_sanity_check(coll);
	tree = &coll->state.tree;

	if (0 > (chld_id = _chld_id(tree, peerid))) {
		char *nodename = pmixp_info_job_host(peerid);
		char *avail_ids = _chld_ids_str(tree);
		PMIXP_DEBUG("%p: contribution from the non-child node %s:%u, acceptable ids: %s", coll, nodename, peerid, avail_ids);
		xfree(nodename);
		xfree(avail_ids);
	}


	PMIXP_DEBUG("%p: contrib/rem from nodeid=%u, childid=%d, state=%s, size=%u", coll, peerid, chld_id, pmixp_coll_tree_state2str(tree->state), remaining_buf(buf));




	switch (tree->state) {
	case PMIXP_COLL_TREE_SYNC:
		
		coll->ts = time(NULL);
		
	case PMIXP_COLL_TREE_COLLECT:
		
		if (coll->seq != seq) {
			char *nodename = pmixp_info_job_host(peerid);
			
			PMIXP_ERROR("%p: unexpected contrib from %s:%d (child #%d) seq = %d, coll->seq = %d, state=%s", coll, nodename, peerid, chld_id, seq, coll->seq, pmixp_coll_tree_state2str(tree->state));


			xfree(nodename);
			goto error;
		}
		break;
	case PMIXP_COLL_TREE_UPFWD:
	case PMIXP_COLL_TREE_UPFWD_WSC:
	{
		char *nodename = pmixp_info_job_host(peerid);
		
		PMIXP_ERROR("%p: unexpected contrib from %s:%d, state = %s", coll, nodename, peerid, pmixp_coll_tree_state2str(tree->state));

		xfree(nodename);
		goto error;
	}
	case PMIXP_COLL_TREE_UPFWD_WPC:
	case PMIXP_COLL_TREE_DOWNFWD:

		
		PMIXP_DEBUG("%p: contrib for the next coll. nodeid=%u, child=%d seq=%u, coll->seq=%u, state=%s", coll, peerid, chld_id, seq, coll->seq, pmixp_coll_tree_state2str(tree->state));


		if ((coll->seq +1) != seq) {
			char *nodename = pmixp_info_job_host(peerid);
			
			PMIXP_ERROR("%p: unexpected contrib from %s:%d(x:%d) seq = %d, coll->seq = %d, state=%s", coll, nodename, peerid, chld_id, seq, coll->seq, pmixp_coll_tree_state2str(tree->state));


			xfree(nodename);
			goto error;
		}
		break;
	default:
		
		PMIXP_ERROR("%p: unknown collective state %s", coll, pmixp_coll_tree_state2str(tree->state));
		
		tree->state = PMIXP_COLL_TREE_SYNC;
		goto error2;
	}

	
	if (tree->contrib_chld[chld_id]) {
		char *nodename = pmixp_info_job_host(peerid);
		
		PMIXP_DEBUG("%p: multiple contribs from %s:%d(x:%d)", coll, nodename, peerid, chld_id);
		
		xfree(nodename);
		goto proceed;
	}

	data_src = get_buf_data(buf) + get_buf_offset(buf);
	size = remaining_buf(buf);
	pmixp_server_buf_reserve(tree->ufwd_buf, size);
	data_dst = get_buf_data(tree->ufwd_buf) + get_buf_offset(tree->ufwd_buf);
	memcpy(data_dst, data_src, size);
	set_buf_offset(tree->ufwd_buf, get_buf_offset(tree->ufwd_buf) + size);

	
	tree->contrib_chld[chld_id] = true;
	
	tree->contrib_children++;

proceed:
	_progress_coll_tree(coll);


	PMIXP_DEBUG("%p: finish nodeid=%u, child=%d, state=%s", coll, peerid, chld_id, pmixp_coll_tree_state2str(tree->state));


	
	slurm_mutex_unlock(&coll->lock);

	return SLURM_SUCCESS;
error:
	pmixp_coll_log(coll);
	_reset_coll(coll);
error2:
	slurm_kill_job_step(pmixp_info_jobid(), pmixp_info_stepid(), SIGKILL);
	
	slurm_mutex_unlock(&coll->lock);

	return SLURM_ERROR;
}

int pmixp_coll_tree_parent(pmixp_coll_t *coll, uint32_t peerid, uint32_t seq, Buf buf)
{
	pmixp_coll_tree_t *tree = NULL;
	char *data_src = NULL, *data_dst = NULL;
	uint32_t size;
	int expected_peerid;

	
	slurm_mutex_lock(&coll->lock);
	tree = &coll->state.tree;

	if (pmixp_info_srv_direct_conn()) {
		expected_peerid = tree->prnt_peerid;
	} else {
		expected_peerid = tree->root_peerid;
	}

	if (expected_peerid != peerid) {
		char *nodename = pmixp_info_job_host(peerid);
		
		PMIXP_ERROR("%p: parent contrib from bad nodeid=%s:%u, expect=%d", coll, nodename, peerid, expected_peerid);
		xfree(nodename);
		goto proceed;
	}


	PMIXP_DEBUG("%p: contrib/rem nodeid=%u: state=%s, size=%u", coll, peerid, pmixp_coll_tree_state2str(tree->state), remaining_buf(buf));



	switch (tree->state) {
	case PMIXP_COLL_TREE_SYNC:
	case PMIXP_COLL_TREE_COLLECT:
		

		PMIXP_DEBUG("%p: prev contrib nodeid=%u: seq=%u, cur_seq=%u, state=%s", coll, peerid, seq, coll->seq, pmixp_coll_tree_state2str(tree->state));


		
		if ((coll->seq - 1) != seq) {
			
			char *nodename = pmixp_info_job_host(peerid);
			PMIXP_ERROR("%p: unexpected from %s:%d: seq = %d, coll->seq = %d, state=%s", coll, nodename, peerid, seq, coll->seq, pmixp_coll_tree_state2str(tree->state));

			xfree(nodename);
			goto error;
		}
		goto proceed;
	case PMIXP_COLL_TREE_UPFWD_WSC:{
		
		
		char *nodename = pmixp_info_job_host(peerid);
		PMIXP_ERROR("%p: unexpected from %s:%d: seq = %d, coll->seq = %d, state=%s", coll, nodename, peerid, seq, coll->seq, pmixp_coll_tree_state2str(tree->state));

		xfree(nodename);
		goto error;
	}
	case PMIXP_COLL_TREE_UPFWD:
	case PMIXP_COLL_TREE_UPFWD_WPC:
		
		break;
	case PMIXP_COLL_TREE_DOWNFWD:
		

		PMIXP_DEBUG("%p: double contrib nodeid=%u seq=%u, cur_seq=%u, state=%s", coll, peerid, seq, coll->seq, pmixp_coll_tree_state2str(tree->state));


		
		if (coll->seq != seq) {
			char *nodename = pmixp_info_job_host(peerid);
			
			PMIXP_ERROR("%p: unexpected contrib from %s:%d: seq = %d, coll->seq = %d, state=%s", coll, nodename, peerid, seq, coll->seq, pmixp_coll_tree_state2str(tree->state));

			xfree(nodename);
			goto error;
		}
		goto proceed;
	default:
		
		PMIXP_ERROR("%p: unknown collective state %s", coll, pmixp_coll_tree_state2str(tree->state));
		
		tree->state = PMIXP_COLL_TREE_SYNC;
		goto error2;
	}

	
	if (tree->contrib_prnt) {
		char *nodename = pmixp_info_job_host(peerid);
		
		PMIXP_DEBUG("%p: multiple contributions from parent %s:%d", coll, nodename, peerid);
		xfree(nodename);
		
		goto proceed;
	}
	tree->contrib_prnt = true;

	data_src = get_buf_data(buf) + get_buf_offset(buf);
	size = remaining_buf(buf);
	pmixp_server_buf_reserve(tree->dfwd_buf, size);

	data_dst = get_buf_data(tree->dfwd_buf) + get_buf_offset(tree->dfwd_buf);
	memcpy(data_dst, data_src, size);
	set_buf_offset(tree->dfwd_buf, get_buf_offset(tree->dfwd_buf) + size);
proceed:
	_progress_coll_tree(coll);


	PMIXP_DEBUG("%p: finish: nodeid=%u, state=%s", coll, peerid, pmixp_coll_tree_state2str(tree->state));

	
	slurm_mutex_unlock(&coll->lock);

	return SLURM_SUCCESS;
error:
	pmixp_coll_log(coll);
	_reset_coll(coll);
error2:
	slurm_kill_job_step(pmixp_info_jobid(), pmixp_info_stepid(), SIGKILL);
	slurm_mutex_unlock(&coll->lock);

	return SLURM_ERROR;
}

void pmixp_coll_tree_reset_if_to(pmixp_coll_t *coll, time_t ts)
{
	pmixp_coll_tree_t *tree = NULL;

	
	slurm_mutex_lock(&coll->lock);
	tree = &coll->state.tree;

	if (PMIXP_COLL_TREE_SYNC == tree->state) {
		goto unlock;
	}

	if (ts - coll->ts > pmixp_info_timeout()) {
		
		pmixp_coll_localcb_nodata(coll, PMIXP_ERR_TIMEOUT);

		
		PMIXP_ERROR("%p: collective timeout seq=%d", coll, coll->seq);
		pmixp_coll_log(coll);
		
		_reset_coll(coll);
	}
unlock:
	
	slurm_mutex_unlock(&coll->lock);
}

void pmixp_coll_tree_log(pmixp_coll_t *coll)
{
	int i;
	pmixp_coll_tree_t *tree = &coll->state.tree;
	char *nodename;

	PMIXP_ERROR("%p: %s state seq=%d contribs: loc=%d/prnt=%d/child=%u", coll, pmixp_coll_type2str(coll->type), coll->seq, tree->contrib_local, tree->contrib_prnt, tree->contrib_children);


	nodename = pmixp_info_job_host(coll->my_peerid);
	PMIXP_ERROR("my peerid: %d:%s", coll->my_peerid, nodename);
	xfree(nodename);
	nodename = pmixp_info_job_host(tree->root_peerid);
	PMIXP_ERROR("root host: %d:%s", tree->root_peerid, nodename);
	xfree(nodename);
	if (tree->prnt_peerid >= 0) {
		PMIXP_ERROR("prnt host: %d:%s", tree->prnt_peerid, tree->prnt_host);
		PMIXP_ERROR("prnt contrib:");
		PMIXP_ERROR("\t [%d:%s] %s", tree->prnt_peerid, tree->prnt_host, tree->contrib_prnt ? "true" : "false");
	}
	if (tree->chldrn_cnt) {
		char *done_contrib = NULL, *wait_contrib = NULL;
		hostlist_t hl_done_contrib = NULL, hl_wait_contrib = NULL, *tmp_list;

		PMIXP_ERROR("child contribs [%d]:", tree->chldrn_cnt);
		for (i = 0; i < tree->chldrn_cnt; i++) {
			nodename = pmixp_info_job_host(tree->chldrn_ids[i]);
			tmp_list = tree->contrib_chld[i] ? &hl_done_contrib : &hl_wait_contrib;

			if (!*tmp_list)
				*tmp_list = hostlist_create(nodename);
			else hostlist_push_host(*tmp_list, nodename);

			xfree(nodename);
		}
		if (hl_done_contrib) {
			done_contrib = slurm_hostlist_ranged_string_xmalloc( hl_done_contrib);

			FREE_NULL_HOSTLIST(hl_done_contrib);
		}

		if (hl_wait_contrib) {
			wait_contrib = slurm_hostlist_ranged_string_xmalloc( hl_wait_contrib);

			FREE_NULL_HOSTLIST(hl_wait_contrib);
		}
		PMIXP_ERROR("\t done contrib: %s", done_contrib ? done_contrib : "-");
		PMIXP_ERROR("\t wait contrib: %s", wait_contrib ? wait_contrib : "-");
		xfree(done_contrib);
		xfree(wait_contrib);
	}
	PMIXP_ERROR("status: coll=%s upfw=%s dfwd=%s", pmixp_coll_tree_state2str(tree->state), pmixp_coll_tree_sndstatus2str(tree->ufwd_status), pmixp_coll_tree_sndstatus2str(tree->dfwd_status));


	PMIXP_ERROR("dfwd status: dfwd_cb_cnt=%u, dfwd_cb_wait=%u", tree->dfwd_cb_cnt, tree->dfwd_cb_wait);
	PMIXP_ERROR("bufs (offset/size): upfw %u/%u, dfwd %u/%u", get_buf_offset(tree->ufwd_buf), size_buf(tree->ufwd_buf), get_buf_offset(tree->dfwd_buf), size_buf(tree->dfwd_buf));

}
