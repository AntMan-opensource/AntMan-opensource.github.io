


















static pj_status_t mod_ua_load(pjsip_endpoint *endpt);
static pj_status_t mod_ua_unload(void);
static pj_bool_t   mod_ua_on_rx_request(pjsip_rx_data *rdata);
static pj_bool_t   mod_ua_on_rx_response(pjsip_rx_data *rdata);
static void	   mod_ua_on_tsx_state(pjsip_transaction*, pjsip_event*);


extern long pjsip_dlg_lock_tls_id;	


struct dlg_set_head {
    PJ_DECL_LIST_MEMBER(pjsip_dialog);
};


struct dlg_set {
    
    PJ_DECL_LIST_MEMBER(struct dlg_set);

    
    pj_hash_entry_buf ht_entry;

    
    struct dlg_set_head  dlg_list;
};



static struct user_agent {
    pjsip_module	 mod;
    pj_pool_t		*pool;
    pjsip_endpoint	*endpt;
    pj_mutex_t		*mutex;
    pj_hash_table_t	*dlg_table;
    pjsip_ua_init_param  param;
    struct dlg_set	 free_dlgset_nodes;

} mod_ua =  {
  {
    NULL, NULL,		     { "mod-ua", 6 }, -1, PJSIP_MOD_PRIORITY_UA_PROXY_LAYER, &mod_ua_load, NULL, NULL, &mod_ua_unload, &mod_ua_on_rx_request, &mod_ua_on_rx_response, NULL, NULL, &mod_ua_on_tsx_state, }












};


static pj_status_t mod_ua_load(pjsip_endpoint *endpt)
{
    pj_status_t status;

    
    mod_ua.endpt = endpt;
    mod_ua.pool = pjsip_endpt_create_pool( endpt, "ua%p", PJSIP_POOL_LEN_UA, PJSIP_POOL_INC_UA);
    if (mod_ua.pool == NULL)
	return PJ_ENOMEM;

    status = pj_mutex_create_recursive(mod_ua.pool, " ua%p", &mod_ua.mutex);
    if (status != PJ_SUCCESS)
	return status;

    mod_ua.dlg_table = pj_hash_create(mod_ua.pool, PJSIP_MAX_DIALOG_COUNT);
    if (mod_ua.dlg_table == NULL)
	return PJ_ENOMEM;

    pj_list_init(&mod_ua.free_dlgset_nodes);

    
    status = pj_thread_local_alloc(&pjsip_dlg_lock_tls_id);
    if (status != PJ_SUCCESS)
	return status;

    pj_thread_local_set(pjsip_dlg_lock_tls_id, NULL);

    return PJ_SUCCESS;

}


static pj_status_t mod_ua_unload(void)
{
    pj_thread_local_free(pjsip_dlg_lock_tls_id);
    pj_mutex_destroy(mod_ua.mutex);

    
    if (mod_ua.pool) {
	pjsip_endpt_release_pool( mod_ua.endpt, mod_ua.pool );
    }
    return PJ_SUCCESS;
}


static void mod_ua_on_tsx_state( pjsip_transaction *tsx, pjsip_event *e)
{
    pjsip_dialog *dlg;

    
    if (mod_ua.mod.id == -1)
	return;

    
    dlg = (pjsip_dialog*) tsx->mod_data[mod_ua.mod.id];
    
    
    if (dlg == NULL)
	return;

    
    pjsip_dlg_on_tsx_state(dlg, tsx, e);
}



PJ_DEF(pj_status_t) pjsip_ua_init_module( pjsip_endpoint *endpt, const pjsip_ua_init_param *prm)
{
    pj_status_t status;

    
    PJ_ASSERT_RETURN(mod_ua.mod.id == -1, PJ_EINVALIDOP);

    
    if (prm)
	pj_memcpy(&mod_ua.param, prm, sizeof(pjsip_ua_init_param));

    
    status = pjsip_endpt_register_module(endpt, &mod_ua.mod);

    return status;
}


PJ_DEF(pjsip_user_agent*) pjsip_ua_instance(void)
{
    return &mod_ua.mod;
}



PJ_DEF(pjsip_endpoint*) pjsip_ua_get_endpt(pjsip_user_agent *ua)
{
    PJ_UNUSED_ARG(ua);
    pj_assert(ua == &mod_ua.mod);
    return mod_ua.endpt;
}



PJ_DEF(pj_status_t) pjsip_ua_destroy(void)
{
    
    PJ_ASSERT_RETURN(mod_ua.mod.id != -1, PJ_EINVALIDOP);

    return pjsip_endpt_unregister_module(mod_ua.endpt, &mod_ua.mod);
}







static struct dlg_set *alloc_dlgset_node(void)
{
    struct dlg_set *set;

    if (!pj_list_empty(&mod_ua.free_dlgset_nodes)) {
	set = mod_ua.free_dlgset_nodes.next;
	pj_list_erase(set);
	return set;
    } else {
	set = PJ_POOL_ALLOC_T(mod_ua.pool, struct dlg_set);
	return set;
    }
}


PJ_DEF(pj_status_t) pjsip_ua_register_dlg( pjsip_user_agent *ua, pjsip_dialog *dlg )
{
    
    PJ_ASSERT_RETURN(ua && dlg, PJ_EINVAL);

    
    PJ_ASSERT_RETURN(dlg->local.info && dlg->local.info->tag.slen && dlg->local.tag_hval != 0, PJ_EBUG);

    
    
    
    

    
    pj_mutex_lock(mod_ua.mutex);

    
    if (dlg->role == PJSIP_ROLE_UAC) {
	struct dlg_set *dlg_set;

	dlg_set = (struct dlg_set*)
		  pj_hash_get_lower( mod_ua.dlg_table, dlg->local.info->tag.ptr, (unsigned)dlg->local.info->tag.slen, &dlg->local.tag_hval);



	if (dlg_set) {
	    
	    pj_assert(dlg_set->dlg_list.next != (void*)&dlg_set->dlg_list);
	    pj_list_push_back(&dlg_set->dlg_list, dlg);

	    dlg->dlg_set = dlg_set;

	} else {
	    
	    dlg_set = alloc_dlgset_node();
	    pj_list_init(&dlg_set->dlg_list);
	    pj_list_push_back(&dlg_set->dlg_list, dlg);

	    dlg->dlg_set = dlg_set;

	    
	    pj_hash_set_np_lower(mod_ua.dlg_table,  dlg->local.info->tag.ptr, (unsigned)dlg->local.info->tag.slen, dlg->local.tag_hval, dlg_set->ht_entry, dlg_set);



	}

    } else {
	
	struct dlg_set *dlg_set;

	dlg_set = alloc_dlgset_node();
	pj_list_init(&dlg_set->dlg_list);
	pj_list_push_back(&dlg_set->dlg_list, dlg);

	dlg->dlg_set = dlg_set;

	pj_hash_set_np_lower(mod_ua.dlg_table,  dlg->local.info->tag.ptr, (unsigned)dlg->local.info->tag.slen, dlg->local.tag_hval, dlg_set->ht_entry, dlg_set);


    }

    
    pj_mutex_unlock(mod_ua.mutex);

    
    return PJ_SUCCESS;
}


PJ_DEF(pj_status_t) pjsip_ua_unregister_dlg( pjsip_user_agent *ua, pjsip_dialog *dlg )
{
    struct dlg_set *dlg_set;
    pjsip_dialog *d;

    
    PJ_ASSERT_RETURN(ua && dlg, PJ_EINVAL);

    
    PJ_ASSERT_RETURN(dlg->dlg_set, PJ_EINVALIDOP);

    
    pj_mutex_lock(mod_ua.mutex);

    
    dlg_set = (struct dlg_set*) dlg->dlg_set;
    d = dlg_set->dlg_list.next;
    while (d != (pjsip_dialog*)&dlg_set->dlg_list && d != dlg) {
	d = d->next;
    }

    if (d != dlg) {
	pj_assert(!"Dialog is not registered!");
	pj_mutex_unlock(mod_ua.mutex);
	return PJ_EINVALIDOP;
    }

    
    pj_list_erase(dlg);

    
    if (pj_list_empty(&dlg_set->dlg_list)) {
	pj_hash_set_lower(NULL, mod_ua.dlg_table, dlg->local.info->tag.ptr, (unsigned)dlg->local.info->tag.slen, dlg->local.tag_hval, NULL);


	
	pj_list_push_back(&mod_ua.free_dlgset_nodes, dlg_set);
    }

    
    pj_mutex_unlock(mod_ua.mutex);

    
    return PJ_SUCCESS;
}


PJ_DEF(pjsip_dialog*) pjsip_rdata_get_dlg( pjsip_rx_data *rdata )
{
    return (pjsip_dialog*) rdata->endpt_info.mod_data[mod_ua.mod.id];
}

PJ_DEF(pjsip_dialog*) pjsip_tdata_get_dlg( pjsip_tx_data *tdata )
{
    return (pjsip_dialog*) tdata->mod_data[mod_ua.mod.id];
}

PJ_DEF(pjsip_dialog*) pjsip_tsx_get_dlg( pjsip_transaction *tsx )
{
    return (pjsip_dialog*) tsx->mod_data[mod_ua.mod.id];
}



PJ_DEF(unsigned) pjsip_ua_get_dlg_set_count(void)
{
    unsigned count;

    PJ_ASSERT_RETURN(mod_ua.endpt, 0);

    pj_mutex_lock(mod_ua.mutex);
    count = pj_hash_count(mod_ua.dlg_table);
    pj_mutex_unlock(mod_ua.mutex);

    return count;
}



PJ_DEF(pjsip_dialog*) pjsip_ua_find_dialog(const pj_str_t *call_id, const pj_str_t *local_tag, const pj_str_t *remote_tag, pj_bool_t lock_dialog)


{
    struct dlg_set *dlg_set;
    pjsip_dialog *dlg;

    PJ_ASSERT_RETURN(call_id && local_tag && remote_tag, NULL);

    
    pj_mutex_lock(mod_ua.mutex);

    
    dlg_set = (struct dlg_set*)
    	      pj_hash_get_lower(mod_ua.dlg_table, local_tag->ptr, (unsigned)local_tag->slen, NULL);
    if (dlg_set == NULL) {
	
	pj_mutex_unlock(mod_ua.mutex);
	return NULL;
    }

    
    dlg = dlg_set->dlg_list.next;
    while (dlg != (pjsip_dialog*)&dlg_set->dlg_list) {	
	if (pj_stricmp(&dlg->remote.info->tag, remote_tag) == 0)
	    break;
	dlg = dlg->next;
    }

    if (dlg == (pjsip_dialog*)&dlg_set->dlg_list) {
	
	pj_mutex_unlock(mod_ua.mutex);
	return NULL;
    }

    
    if (pj_strcmp(&dlg->call_id->id, call_id)!=0) {

	PJ_LOG(6, (THIS_FILE, "Dialog not found: local and remote tags " "matched but not call id"));

        pj_mutex_unlock(mod_ua.mutex);
        return NULL;
    }

    if (lock_dialog) {
	if (pjsip_dlg_try_inc_lock(dlg) != PJ_SUCCESS) {

	    

	    
	    pj_mutex_unlock(mod_ua.mutex);
	    
	    pjsip_dlg_inc_lock(dlg);

	} else {
	    
	    pj_mutex_unlock(mod_ua.mutex);
	}

    } else {
	
	pj_mutex_unlock(mod_ua.mutex);
    }

    return dlg;
}



static struct dlg_set *find_dlg_set_for_msg( pjsip_rx_data *rdata )
{
    
    if (rdata->msg_info.cseq->method.id == PJSIP_CANCEL_METHOD) {

	pjsip_dialog *dlg;

	
	pj_str_t key;
	pjsip_role_e role;
	pjsip_transaction *tsx;

	if (rdata->msg_info.msg->type == PJSIP_REQUEST_MSG)
	    role = PJSIP_ROLE_UAS;
	else role = PJSIP_ROLE_UAC;

	pjsip_tsx_create_key(rdata->tp_info.pool, &key, role,  pjsip_get_invite_method(), rdata);

	
	tsx = pjsip_tsx_layer_find_tsx2(&key, PJ_TRUE);

	
	if (tsx) {
	    dlg = (pjsip_dialog*) tsx->mod_data[mod_ua.mod.id];
	    pj_grp_lock_dec_ref(tsx->grp_lock);

	    
	    return dlg ? (struct dlg_set*) dlg->dlg_set : NULL;

	} else {
	    return NULL;
	}


    } else {
	pj_str_t *tag;
	struct dlg_set *dlg_set;

	if (rdata->msg_info.msg->type == PJSIP_REQUEST_MSG)
	    tag = &rdata->msg_info.to->tag;
	else tag = &rdata->msg_info.from->tag;

	
	dlg_set = (struct dlg_set*)
		  pj_hash_get_lower(mod_ua.dlg_table, tag->ptr,  (unsigned)tag->slen, NULL);
	return dlg_set;
    }
}


static pj_bool_t mod_ua_on_rx_request(pjsip_rx_data *rdata)
{
    struct dlg_set *dlg_set;
    pj_str_t *from_tag;
    pjsip_dialog *dlg;
    pj_status_t status;

    
    if (rdata->msg_info.to->tag.slen == 0 &&  rdata->msg_info.msg->line.req.method.id != PJSIP_CANCEL_METHOD)
    {
	return PJ_FALSE;
    }

    
    if (rdata->msg_info.msg->line.req.method.id == PJSIP_REGISTER_METHOD)
	return PJ_FALSE;

retry_on_deadlock:

    
    pj_mutex_lock(mod_ua.mutex);

    
    dlg_set = find_dlg_set_for_msg(rdata);

    
    if (dlg_set == NULL) {
	
	pj_mutex_unlock(mod_ua.mutex);

	if (rdata->msg_info.msg->line.req.method.id != PJSIP_ACK_METHOD) {
	    PJ_LOG(5,(THIS_FILE,  "Unable to find dialogset for %s, answering with 481", pjsip_rx_data_get_info(rdata)));


	    
	    pjsip_endpt_respond_stateless( mod_ua.endpt, rdata, 481, NULL,  NULL, NULL );
	}
	return PJ_TRUE;
    }

    
    from_tag = &rdata->msg_info.from->tag;
    dlg = dlg_set->dlg_list.next;
    while (dlg != (pjsip_dialog*)&dlg_set->dlg_list) {
	
	if (pj_stricmp(&dlg->remote.info->tag, from_tag) == 0)
	    break;

	dlg = dlg->next;
    }

    
    if (dlg == (pjsip_dialog*)&dlg_set->dlg_list) {

	pjsip_dialog *first_dlg = dlg_set->dlg_list.next;

	if (first_dlg->remote.info->tag.slen != 0) {
	    
	    pj_mutex_unlock(mod_ua.mutex);

	    if (rdata->msg_info.msg->line.req.method.id != PJSIP_ACK_METHOD) {
		PJ_LOG(5,(THIS_FILE,  "Unable to find dialog for %s, answering with 481", pjsip_rx_data_get_info(rdata)));


		pjsip_endpt_respond_stateless(mod_ua.endpt, rdata, PJSIP_SC_CALL_TSX_DOES_NOT_EXIST, NULL, NULL, NULL);

	    } else {
		PJ_LOG(5,(THIS_FILE,  "Unable to find dialog for %s", pjsip_rx_data_get_info(rdata)));

	    }
	    return PJ_TRUE;
	}

	dlg = first_dlg;
    }

    
    rdata->endpt_info.mod_data[mod_ua.mod.id] = dlg;

    
    PJ_LOG(6,(dlg->obj_name, "UA layer acquiring dialog lock for request"));
    status = pjsip_dlg_try_inc_lock(dlg);
    if (status != PJ_SUCCESS) {
	
	pj_mutex_unlock(mod_ua.mutex);
	pj_thread_sleep(0);
	goto retry_on_deadlock;
    }

    
    pj_mutex_unlock(mod_ua.mutex);

    
    pjsip_dlg_on_rx_request(dlg, rdata);

    
    pjsip_dlg_dec_lock(dlg);

    
    return PJ_TRUE;
}



static pj_bool_t mod_ua_on_rx_response(pjsip_rx_data *rdata)
{
    pjsip_transaction *tsx;
    struct dlg_set *dlg_set;
    pjsip_dialog *dlg;
    pj_status_t status;

    

retry_on_deadlock:

    dlg = NULL;

    
    pj_mutex_lock(mod_ua.mutex);

    
    tsx = pjsip_rdata_get_tsx(rdata);
    if (tsx) {
	
	dlg = pjsip_tsx_get_dlg(tsx);
	if (!dlg) {
	    
	    pj_mutex_unlock(mod_ua.mutex);
	    return PJ_FALSE;
	}

	
	dlg_set = (struct dlg_set*) dlg->dlg_set;

	

    } else {
	
	pjsip_cseq_hdr *cseq_hdr = rdata->msg_info.cseq;

	if (cseq_hdr->method.id != PJSIP_INVITE_METHOD || rdata->msg_info.msg->line.status.code / 100 != 2)
	{
	    
	    
	    pj_mutex_unlock(mod_ua.mutex);
	    return PJ_FALSE;
	}


	
	dlg_set = (struct dlg_set*)
		  pj_hash_get_lower(mod_ua.dlg_table,  rdata->msg_info.from->tag.ptr, (unsigned)rdata->msg_info.from->tag.slen, NULL);



	if (!dlg_set) {
	    
	    pj_mutex_unlock(mod_ua.mutex);

	    
	    PJ_LOG(4,(THIS_FILE,  "Received strayed 2xx response (no dialog is found)" " from %s:%d: %s", rdata->pkt_info.src_name, rdata->pkt_info.src_port, pjsip_rx_data_get_info(rdata)));




	    return PJ_TRUE;
	}
    }

    
    pj_assert(dlg_set && !pj_list_empty(&dlg_set->dlg_list));

    

    
    
    
    

    if (rdata->msg_info.cseq->method.id == PJSIP_INVITE_METHOD) {
	
	int st_code = rdata->msg_info.msg->line.status.code;
	pj_str_t *to_tag = &rdata->msg_info.to->tag;

	dlg = dlg_set->dlg_list.next;

	while (dlg != (pjsip_dialog*)&dlg_set->dlg_list) {

	    
	    if (dlg->remote.info->tag.slen == 0)
		break;

	    
	    if (pj_stricmp(to_tag, &dlg->remote.info->tag) == 0)
		break;

	    dlg = dlg->next;
	}

	
	if (dlg == (pjsip_dialog*)&dlg_set->dlg_list && ((st_code/100==1 && st_code!=100) || st_code/100==2))
	{

	    PJ_LOG(5,(THIS_FILE,  "Received forked %s for existing dialog %s", pjsip_rx_data_get_info(rdata), dlg_set->dlg_list.next->obj_name));



	    
	    if (mod_ua.param.on_dlg_forked) {
		dlg = (*mod_ua.param.on_dlg_forked)(dlg_set->dlg_list.next,  rdata);
		if (dlg == NULL) {
		    pj_mutex_unlock(mod_ua.mutex);
		    return PJ_TRUE;
		}
	    } else {
		dlg = dlg_set->dlg_list.next;

		PJ_LOG(4,(THIS_FILE,  "Unhandled forked %s from %s:%d, response will be " "handed over to the first dialog", pjsip_rx_data_get_info(rdata), rdata->pkt_info.src_name, rdata->pkt_info.src_port));



	    }

	} else if (dlg == (pjsip_dialog*)&dlg_set->dlg_list) {

	    

	    dlg = dlg_set->dlg_list.next;

	}

    } else {
	
	pj_assert(tsx != NULL);
	pj_assert(dlg != NULL);
    }

    
    pj_assert(dlg != NULL);

    
    rdata->endpt_info.mod_data[mod_ua.mod.id] = dlg;

    
    PJ_LOG(6,(dlg->obj_name, "UA layer acquiring dialog lock for response"));
    status = pjsip_dlg_try_inc_lock(dlg);
    if (status != PJ_SUCCESS) {
	
	pj_mutex_unlock(mod_ua.mutex);
	pj_thread_sleep(0);
	goto retry_on_deadlock;
    }

    
    pj_mutex_unlock(mod_ua.mutex);

    
    pjsip_dlg_on_rx_response(dlg, rdata);

    
    pjsip_dlg_dec_lock(dlg);

    
    return PJ_TRUE;
}



static void print_dialog( const char *title, pjsip_dialog *dlg, char *buf, pj_size_t size)
{
    int len;
    char userinfo[PJSIP_MAX_URL_SIZE];

    len = pjsip_hdr_print_on(dlg->remote.info, userinfo, sizeof(userinfo));
    if (len < 0)
	pj_ansi_strcpy(userinfo, "<--uri too long-->");
    else userinfo[len] = '\0';
    
    len = pj_ansi_snprintf(buf, size, "%s[%s]  %s", title, (dlg->state==PJSIP_DIALOG_STATE_NULL ? " - " :

							     "est"), userinfo);
    if (len < 1 || len >= (int)size) {
	pj_ansi_strcpy(buf, "<--uri too long-->");
    } else buf[len] = '\0';
}



PJ_DEF(void) pjsip_ua_dump(pj_bool_t detail)
{

    pj_hash_iterator_t itbuf, *it;
    char dlginfo[128];

    pj_mutex_lock(mod_ua.mutex);

    PJ_LOG(3, (THIS_FILE, "Number of dialog sets: %u",  pj_hash_count(mod_ua.dlg_table)));

    if (detail && pj_hash_count(mod_ua.dlg_table)) {
	PJ_LOG(3, (THIS_FILE, "Dumping dialog sets:"));
	it = pj_hash_first(mod_ua.dlg_table, &itbuf);
	for (; it != NULL; it = pj_hash_next(mod_ua.dlg_table, it))  {
	    struct dlg_set *dlg_set;
	    pjsip_dialog *dlg;
	    const char *title;

	    dlg_set = (struct dlg_set*) pj_hash_this(mod_ua.dlg_table, it);
	    if (!dlg_set || pj_list_empty(&dlg_set->dlg_list)) continue;

	    
	    dlg = dlg_set->dlg_list.next;
	    if (dlg->role == PJSIP_ROLE_UAC)
		title = "  [out] ";
	    else title = "  [in]  ";

	    print_dialog(title, dlg, dlginfo, sizeof(dlginfo));
	    PJ_LOG(3,(THIS_FILE, "%s", dlginfo));

	    
	    dlg = dlg->next;
	    while (dlg != (pjsip_dialog*) &dlg_set->dlg_list) {
		print_dialog("    [forked] ", dlg, dlginfo, sizeof(dlginfo));
		dlg = dlg->next;
	    }
	}
    }

    pj_mutex_unlock(mod_ua.mutex);

}

