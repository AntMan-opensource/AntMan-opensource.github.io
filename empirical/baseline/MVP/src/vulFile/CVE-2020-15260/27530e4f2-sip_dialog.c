






















long pjsip_dlg_lock_tls_id;


pj_bool_t pjsip_include_allow_hdr_in_dlg = PJSIP_INCLUDE_ALLOW_HDR_IN_DLG;


static const pj_str_t HCONTACT = { "Contact", 7 };


PJ_DEF(pj_bool_t) pjsip_method_creates_dialog(const pjsip_method *m)
{
    const pjsip_method subscribe = { PJSIP_OTHER_METHOD, {"SUBSCRIBE", 9}};
    const pjsip_method refer = { PJSIP_OTHER_METHOD, {"REFER", 5}};
    const pjsip_method notify = { PJSIP_OTHER_METHOD, {"NOTIFY", 6}};
    const pjsip_method update = { PJSIP_OTHER_METHOD, {"UPDATE", 6}};

    return m->id == PJSIP_INVITE_METHOD || (pjsip_method_cmp(m, &subscribe)==0) || (pjsip_method_cmp(m, &refer)==0) || (pjsip_method_cmp(m, &notify)==0) || (pjsip_method_cmp(m, &update)==0);



}

static void dlg_on_destroy( void *arg )
{
    pjsip_dialog *dlg = (pjsip_dialog *)arg;

    PJ_LOG(5,(dlg->obj_name, "Dialog destroyed!"));

    pjsip_endpt_release_pool(dlg->endpt, dlg->pool);
}

static pj_status_t create_dialog( pjsip_user_agent *ua, pj_grp_lock_t *grp_lock, pjsip_dialog **p_dlg)

{
    pjsip_endpoint *endpt;
    pj_pool_t *pool;
    pjsip_dialog *dlg;
    pj_status_t status;

    endpt = pjsip_ua_get_endpt(ua);
    if (!endpt)
	return PJ_EINVALIDOP;

    pool = pjsip_endpt_create_pool(endpt, "dlg%p", PJSIP_POOL_LEN_DIALOG, PJSIP_POOL_INC_DIALOG);

    if (!pool)
	return PJ_ENOMEM;

    dlg = PJ_POOL_ZALLOC_T(pool, pjsip_dialog);
    PJ_ASSERT_RETURN(dlg != NULL, PJ_ENOMEM);

    dlg->pool = pool;
    pj_ansi_snprintf(dlg->obj_name, sizeof(dlg->obj_name), "dlg%p", dlg);
    dlg->ua = ua;
    dlg->endpt = endpt;
    dlg->state = PJSIP_DIALOG_STATE_NULL;
    dlg->add_allow = pjsip_include_allow_hdr_in_dlg;

    pj_list_init(&dlg->inv_hdr);
    pj_list_init(&dlg->rem_cap_hdr);

    
    status = pjsip_auth_clt_init(&dlg->auth_sess, dlg->endpt, dlg->pool, 0);
    if (status != PJ_SUCCESS)
	goto on_error;

    if (grp_lock) {
	dlg->grp_lock_ = grp_lock;
    } else {
 	status = pj_grp_lock_create(pool, NULL, &dlg->grp_lock_);
 	if (status != PJ_SUCCESS) {
	    goto on_error;
 	}
    }

    pj_grp_lock_add_ref(dlg->grp_lock_);
    pj_grp_lock_add_handler(dlg->grp_lock_, pool, dlg, &dlg_on_destroy);

    pjsip_target_set_init(&dlg->target_set);

    *p_dlg = dlg;
    return PJ_SUCCESS;

on_error:
    pjsip_endpt_release_pool(endpt, pool);
    return status;
}

static void destroy_dialog( pjsip_dialog *dlg, pj_bool_t unlock_mutex )
{
    if (dlg->tp_sel.type != PJSIP_TPSELECTOR_NONE) {
	pjsip_tpselector_dec_ref(&dlg->tp_sel);
	pj_bzero(&dlg->tp_sel, sizeof(pjsip_tpselector));
    }
    pjsip_auth_clt_deinit(&dlg->auth_sess);

    pj_grp_lock_dec_ref(dlg->grp_lock_);

    if (unlock_mutex)
	pj_grp_lock_release(dlg->grp_lock_);
}


PJ_DEF(pj_status_t) pjsip_dlg_create_uac( pjsip_user_agent *ua, const pj_str_t *local_uri, const pj_str_t *local_contact, const pj_str_t *remote_uri, const pj_str_t *target, pjsip_dialog **p_dlg)




{
    pjsip_dlg_create_uac_param create_param;

    PJ_ASSERT_RETURN(ua && local_uri && remote_uri && p_dlg, PJ_EINVAL);

    pj_bzero(&create_param, sizeof(create_param));
    create_param.ua = ua;
    create_param.local_uri = *local_uri;
    create_param.remote_uri = *remote_uri;
    if (local_contact)
	create_param.local_contact = *local_contact;

    if (target)
	create_param.target = *target;

    return pjsip_dlg_create_uac2(&create_param, p_dlg);
}

PJ_DEF(pj_status_t) pjsip_dlg_create_uac2( const pjsip_dlg_create_uac_param *create_param, pjsip_dialog **p_dlg)

{
    pj_status_t status;
    pj_str_t tmp;
    pjsip_dialog *dlg;

    
    PJ_ASSERT_RETURN(create_param->ua && create_param->local_uri.slen && create_param->remote_uri.slen && p_dlg, PJ_EINVAL);

    
    status = create_dialog(create_param->ua, create_param->grp_lock, &dlg);
    if (status != PJ_SUCCESS)
	return status;

    
    pj_strdup_with_null(dlg->pool, &tmp, create_param->target.slen ? &create_param->target : &create_param->remote_uri);
    dlg->target = pjsip_parse_uri(dlg->pool, tmp.ptr, tmp.slen, 0);
    if (!dlg->target) {
	status = PJSIP_EINVALIDURI;
	goto on_error;
    }

    
    if (PJSIP_URI_SCHEME_IS_SIP(dlg->target) || PJSIP_URI_SCHEME_IS_SIPS(dlg->target))
    {
	pjsip_param *param;
	pjsip_sip_uri *uri = (pjsip_sip_uri*)pjsip_uri_get_uri(dlg->target);

	param = uri->header_param.next;
	while (param != &uri->header_param) {
	    if (param->value.ptr) {
		pjsip_hdr *hdr;
		int c;

		c = param->value.ptr[param->value.slen];
		param->value.ptr[param->value.slen] = '\0';

		hdr = (pjsip_hdr*)
		    pjsip_parse_hdr(dlg->pool, &param->name, param->value.ptr, param->value.slen, NULL);

		param->value.ptr[param->value.slen] = (char)c;

		if (hdr == NULL) {
		    status = PJSIP_EINVALIDURI;
		    goto on_error;
		}
		pj_list_push_back(&dlg->inv_hdr, hdr);
	    }

	    param = param->next;
	}

	
	pj_list_init(&uri->header_param);
    }

    
    pjsip_target_set_add_uri(&dlg->target_set, dlg->pool, dlg->target, 0);

    
    dlg->local.info = pjsip_from_hdr_create(dlg->pool);
    pj_strdup_with_null(dlg->pool, &dlg->local.info_str, &create_param->local_uri);
    dlg->local.info->uri = pjsip_parse_uri(dlg->pool, dlg->local.info_str.ptr, dlg->local.info_str.slen, 0);

    if (!dlg->local.info->uri) {
	status = PJSIP_EINVALIDURI;
	goto on_error;
    }

    
    pj_create_unique_string(dlg->pool, &dlg->local.info->tag);

    
    dlg->local.tag_hval = pj_hash_calc_tolower(0, NULL, &dlg->local.info->tag);

    
    dlg->local.first_cseq = pj_rand() & 0x7FFF;
    dlg->local.cseq = dlg->local.first_cseq;

    
    pj_strdup_with_null(dlg->pool, &tmp, create_param->local_contact.slen ? &create_param->local_contact : &create_param->local_uri);

    dlg->local.contact = (pjsip_contact_hdr*)
			 pjsip_parse_hdr(dlg->pool, &HCONTACT, tmp.ptr, tmp.slen, NULL);
    if (!dlg->local.contact) {
	status = PJSIP_EINVALIDURI;
	goto on_error;
    }

    
    dlg->remote.info = pjsip_to_hdr_create(dlg->pool);
    pj_strdup_with_null(dlg->pool, &dlg->remote.info_str, &create_param->remote_uri);
    dlg->remote.info->uri = pjsip_parse_uri(dlg->pool, dlg->remote.info_str.ptr, dlg->remote.info_str.slen, 0);

    if (!dlg->remote.info->uri) {
	status = PJSIP_EINVALIDURI;
	goto on_error;
    }

    
    if (PJSIP_URI_SCHEME_IS_SIP(dlg->remote.info->uri) || PJSIP_URI_SCHEME_IS_SIPS(dlg->remote.info->uri))
    {
	pjsip_sip_uri *sip_uri = (pjsip_sip_uri *)
				 pjsip_uri_get_uri(dlg->remote.info->uri);
	if (!pj_list_empty(&sip_uri->header_param)) {
	    pj_str_t tmp2;

	    
	    pj_list_init(&sip_uri->header_param);

	    
	    tmp2.ptr = (char*) pj_pool_alloc(dlg->pool, dlg->remote.info_str.slen);
	    tmp2.slen = pjsip_uri_print(PJSIP_URI_IN_FROMTO_HDR, sip_uri, tmp2.ptr, dlg->remote.info_str.slen);


	    if (tmp2.slen < 1) {
		status = PJSIP_EURITOOLONG;
		goto on_error;
	    }

	    
	    dlg->remote.info_str = tmp2;
	}
    }


    
    dlg->remote.cseq = dlg->remote.first_cseq = -1;

    
    dlg->role = PJSIP_ROLE_UAC;

    
    dlg->secure = PJSIP_URI_SCHEME_IS_SIPS(dlg->target);

    
    dlg->call_id = pjsip_cid_hdr_create(dlg->pool);
    pj_create_unique_string(dlg->pool, &dlg->call_id->id);

    
    pj_list_init(&dlg->route_set);

    
    status = pjsip_ua_register_dlg( create_param->ua, dlg );
    if (status != PJ_SUCCESS)
	goto on_error;

    
    *p_dlg = dlg;

    PJ_LOG(5,(dlg->obj_name, "UAC dialog created"));

    return PJ_SUCCESS;

on_error:
    destroy_dialog(dlg, PJ_FALSE);
    return status;
}



pj_status_t create_uas_dialog( pjsip_user_agent *ua, pjsip_rx_data *rdata, const pj_str_t *contact, pj_bool_t inc_lock, pjsip_dialog **p_dlg)



{
    pj_status_t status;
    pjsip_hdr *pos = NULL;
    pjsip_contact_hdr *contact_hdr;
    pjsip_rr_hdr *rr;
    pjsip_transaction *tsx = NULL;
    pj_str_t tmp;
    enum { TMP_LEN=PJSIP_MAX_URL_SIZE };
    pj_ssize_t len;
    pjsip_dialog *dlg;
    pj_bool_t lock_incremented = PJ_FALSE;

    
    PJ_ASSERT_RETURN(ua && rdata && p_dlg, PJ_EINVAL);

    
    PJ_ASSERT_RETURN(rdata->msg_info.msg->type == PJSIP_REQUEST_MSG, PJSIP_ENOTREQUESTMSG);

    
    PJ_ASSERT_RETURN(rdata->msg_info.to->tag.slen == 0, PJ_EINVALIDOP);

    
    PJ_ASSERT_RETURN( pjsip_method_creates_dialog(&rdata->msg_info.msg->line.req.method), PJ_EINVALIDOP);


    
    status = create_dialog(ua, NULL, &dlg);
    if (status != PJ_SUCCESS)
	return status;

    
    tmp.ptr = (char*) pj_pool_alloc(rdata->tp_info.pool, TMP_LEN);

    
    dlg->local.info = (pjsip_fromto_hdr*)
    		      pjsip_hdr_clone(dlg->pool, rdata->msg_info.to);
    pjsip_fromto_hdr_set_from(dlg->local.info);

    
    pj_create_unique_string(dlg->pool, &dlg->local.info->tag);


    
    len = pjsip_uri_print(PJSIP_URI_IN_FROMTO_HDR, dlg->local.info->uri, tmp.ptr, TMP_LEN);
    if (len < 1) {
	pj_ansi_strcpy(tmp.ptr, "<-error: uri too long->");
	tmp.slen = pj_ansi_strlen(tmp.ptr);
    } else tmp.slen = len;

    
    pj_strdup(dlg->pool, &dlg->local.info_str, &tmp);

    
    dlg->local.tag_hval = pj_hash_calc_tolower(0, NULL, &dlg->local.info->tag);


    
    dlg->local.first_cseq = pj_rand() & 0x7FFF;
    dlg->local.cseq = dlg->local.first_cseq;

    
    
    if (contact) {
	pj_str_t tmp2;

	pj_strdup_with_null(dlg->pool, &tmp2, contact);
	dlg->local.contact = (pjsip_contact_hdr*)
			     pjsip_parse_hdr(dlg->pool, &HCONTACT, tmp2.ptr, tmp2.slen, NULL);
	if (!dlg->local.contact) {
	    status = PJSIP_EINVALIDURI;
	    goto on_error;
	}

    } else {
	dlg->local.contact = pjsip_contact_hdr_create(dlg->pool);
	dlg->local.contact->uri = dlg->local.info->uri;
    }

    
    dlg->remote.info = (pjsip_fromto_hdr*)
    		       pjsip_hdr_clone(dlg->pool, rdata->msg_info.from);
    pjsip_fromto_hdr_set_to(dlg->remote.info);

    
    len = pjsip_uri_print(PJSIP_URI_IN_FROMTO_HDR, dlg->remote.info->uri, tmp.ptr, TMP_LEN);
    if (len < 1) {
	pj_ansi_strcpy(tmp.ptr, "<-error: uri too long->");
	tmp.slen = pj_ansi_strlen(tmp.ptr);
    } else tmp.slen = len;

    
    pj_strdup(dlg->pool, &dlg->remote.info_str, &tmp);


    
    do {
	contact_hdr = (pjsip_contact_hdr*)
		      pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_CONTACT, pos);
	if (contact_hdr) {
	    if (!contact_hdr->uri || (!PJSIP_URI_SCHEME_IS_SIP(contact_hdr->uri) && !PJSIP_URI_SCHEME_IS_SIPS(contact_hdr->uri)))

	    {
		pos = (pjsip_hdr*)contact_hdr->next;
		if (pos == &rdata->msg_info.msg->hdr)
		    contact_hdr = NULL;
	    } else {
		break;
	    }
	}
    } while (contact_hdr);

    if (!contact_hdr) {
	status = PJSIP_ERRNO_FROM_SIP_STATUS(PJSIP_SC_BAD_REQUEST);
	goto on_error;
    }

    dlg->remote.contact = (pjsip_contact_hdr*)
    			  pjsip_hdr_clone(dlg->pool, (pjsip_hdr*)contact_hdr);

    
    dlg->remote.cseq = dlg->remote.first_cseq = rdata->msg_info.cseq->cseq;

    
    dlg->target = dlg->remote.contact->uri;

    
    dlg->role = PJSIP_ROLE_UAS;

    
    dlg->secure = PJSIP_TRANSPORT_IS_SECURE(rdata->tp_info.transport) && PJSIP_URI_SCHEME_IS_SIPS(rdata->msg_info.msg->line.req.uri);

    
    dlg->call_id = (pjsip_cid_hdr*)
    		   pjsip_hdr_clone(dlg->pool, rdata->msg_info.cid);

    
    pj_list_init(&dlg->route_set);
    rr = rdata->msg_info.record_route;
    while (rr != NULL) {
	pjsip_route_hdr *route;

	
	route = (pjsip_route_hdr*) pjsip_hdr_clone(dlg->pool, rr);
	pjsip_routing_hdr_set_route(route);

	
	pj_list_push_back(&dlg->route_set, route);

	
	rr = rr->next;
	if (rr == (void*)&rdata->msg_info.msg->hdr)
	    break;
	rr = (pjsip_route_hdr*) pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_RECORD_ROUTE, rr);
    }
    dlg->route_set_frozen = PJ_TRUE;

    
    if (inc_lock) {
        pjsip_dlg_inc_lock(dlg);
        lock_incremented = PJ_TRUE;
    }

    
    status = pjsip_tsx_create_uas(dlg->ua, rdata, &tsx);
    if (status != PJ_SUCCESS)
	goto on_error;

    
    tsx->mod_data[dlg->ua->id] = dlg;

    
    ++dlg->tsx_count;

    
    dlg->remote.tag_hval = pj_hash_calc_tolower(0, NULL, &dlg->remote.info->tag);

    
    pjsip_dlg_update_remote_cap(dlg, rdata->msg_info.msg, PJ_TRUE);

    
    status = pjsip_ua_register_dlg( ua, dlg );
    if (status != PJ_SUCCESS)
	goto on_error;

    
    rdata->endpt_info.mod_data[ua->id] = dlg;

    PJ_TODO(DIALOG_APP_TIMER);

    
    pjsip_tsx_recv_msg(tsx, rdata);

    
    *p_dlg = dlg;
    PJ_LOG(5,(dlg->obj_name, "UAS dialog created"));
    return PJ_SUCCESS;

on_error:
    if (tsx) {
	pjsip_tsx_terminate(tsx, 500);
	pj_assert(dlg->tsx_count>0);
	--dlg->tsx_count;
    }

    if (lock_incremented) {
        pjsip_dlg_dec_lock(dlg);
    } else {
        destroy_dialog(dlg, PJ_FALSE);
    }

    return status;
}




PJ_DEF(pj_status_t) pjsip_dlg_create_uas(   pjsip_user_agent *ua, pjsip_rx_data *rdata, const pj_str_t *contact, pjsip_dialog **p_dlg)


{
    return create_uas_dialog(ua, rdata, contact, PJ_FALSE, p_dlg);
}




PJ_DEF(pj_status_t)
pjsip_dlg_create_uas_and_inc_lock(    pjsip_user_agent *ua, pjsip_rx_data *rdata, const pj_str_t *contact, pjsip_dialog **p_dlg)


{
    return create_uas_dialog(ua, rdata, contact, PJ_TRUE, p_dlg);
}



PJ_DEF(pj_status_t) pjsip_dlg_set_transport( pjsip_dialog *dlg, const pjsip_tpselector *sel)
{
    
    PJ_ASSERT_RETURN(dlg && sel, PJ_EINVAL);

    
    pjsip_dlg_inc_lock(dlg);

    
    pjsip_tpselector_dec_ref(&dlg->tp_sel);

    
    pj_memcpy(&dlg->tp_sel, sel, sizeof(*sel));

    
    pjsip_tpselector_add_ref(&dlg->tp_sel);

    
    pjsip_dlg_dec_lock(dlg);

    return PJ_SUCCESS;
}


PJ_DEF(pj_status_t) pjsip_dlg_set_via_sent_by( pjsip_dialog *dlg, pjsip_host_port *via_addr, pjsip_transport *via_tp)

{
    PJ_ASSERT_RETURN(dlg, PJ_EINVAL);

    if (!via_addr)
        pj_bzero(&dlg->via_addr, sizeof(dlg->via_addr));
    else {
        if (pj_strcmp(&dlg->via_addr.host, &via_addr->host))
            pj_strdup(dlg->pool, &dlg->via_addr.host, &via_addr->host);
        dlg->via_addr.port = via_addr->port;
    }
    dlg->via_tp = via_tp;

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjsip_dlg_fork( const pjsip_dialog *first_dlg, const pjsip_rx_data *rdata, pjsip_dialog **new_dlg )

{
    pjsip_dialog *dlg;
    const pjsip_msg *msg = rdata->msg_info.msg;
    const pjsip_hdr *end_hdr, *hdr;
    const pjsip_contact_hdr *contact;
    pj_status_t status;

    
    PJ_ASSERT_RETURN(first_dlg && rdata && new_dlg, PJ_EINVAL);

    
    PJ_ASSERT_RETURN(msg->type == PJSIP_RESPONSE_MSG, PJSIP_ENOTRESPONSEMSG);

    
    status = msg->line.status.code;
    PJ_ASSERT_RETURN( (status/100==1 && status!=100) || (status/100==2), PJ_EBUG);

    
    PJ_ASSERT_RETURN(rdata->msg_info.to->tag.slen != 0, PJSIP_EMISSINGTAG);

    
    contact = (const pjsip_contact_hdr*)
	      pjsip_msg_find_hdr(msg, PJSIP_H_CONTACT, NULL);
    if (contact == NULL || contact->uri == NULL)
	return PJSIP_EMISSINGHDR;

    
    status = create_dialog((pjsip_user_agent*)first_dlg->ua, NULL, &dlg);
    if (status != PJ_SUCCESS)
	return status;

    
    dlg->target = (pjsip_uri*) pjsip_uri_clone(dlg->pool, contact->uri);

    
    dlg->local.info = (pjsip_fromto_hdr*)
    		      pjsip_hdr_clone(dlg->pool, first_dlg->local.info);

    
    pj_strdup(dlg->pool, &dlg->local.info->tag, &first_dlg->local.info->tag);
    dlg->local.tag_hval = first_dlg->local.tag_hval;

    
    dlg->local.first_cseq = first_dlg->local.first_cseq;
    dlg->local.cseq = first_dlg->local.cseq;

    
    dlg->local.contact = (pjsip_contact_hdr*)
    			 pjsip_hdr_clone(dlg->pool, first_dlg->local.contact);

    
    dlg->remote.info = (pjsip_fromto_hdr*)
    		       pjsip_hdr_clone(dlg->pool, first_dlg->remote.info);

    
    pj_strdup(dlg->pool, &dlg->remote.info->tag, &rdata->msg_info.to->tag);

    
    dlg->remote.cseq = dlg->remote.first_cseq = -1;

    
    dlg->role = PJSIP_ROLE_UAC;

    
    status = msg->line.status.code/100;
    if (status == 1 || status == 2)
	dlg->state = PJSIP_DIALOG_STATE_ESTABLISHED;
    else {
	pj_assert(!"Invalid status code");
	dlg->state = PJSIP_DIALOG_STATE_NULL;
    }

    
    dlg->secure = PJSIP_URI_SCHEME_IS_SIPS(dlg->target);

    
    dlg->call_id = (pjsip_cid_hdr*)
    		   pjsip_hdr_clone(dlg->pool, first_dlg->call_id);

    
    pj_list_init(&dlg->route_set);
    end_hdr = &msg->hdr;
    for (hdr=msg->hdr.prev; hdr!=end_hdr; hdr=hdr->prev) {
	if (hdr->type == PJSIP_H_RECORD_ROUTE) {
	    pjsip_route_hdr *r;
	    r = (pjsip_route_hdr*) pjsip_hdr_clone(dlg->pool, hdr);
	    pjsip_routing_hdr_set_route(r);
	    pj_list_push_back(&dlg->route_set, r);
	}
    }

    

    
    status = pjsip_auth_clt_clone(dlg->pool, &dlg->auth_sess, &first_dlg->auth_sess);
    if (status != PJ_SUCCESS)
	goto on_error;

    
    status = pjsip_ua_register_dlg(dlg->ua, dlg );
    if (status != PJ_SUCCESS)
	goto on_error;


    
    *new_dlg = dlg;

    PJ_LOG(5,(dlg->obj_name, "Forked dialog created"));
    return PJ_SUCCESS;

on_error:
    destroy_dialog(dlg, PJ_FALSE);
    return status;
}



static pj_status_t unregister_and_destroy_dialog( pjsip_dialog *dlg, pj_bool_t unlock_mutex )
{
    pj_status_t status;

    

    
    
    PJ_ASSERT_RETURN(dlg->sess_count==0, PJ_EINVALIDOP);

    
    PJ_ASSERT_RETURN(dlg->tsx_count==0, PJ_EINVALIDOP);

    
    if (dlg->dlg_set) {
	status = pjsip_ua_unregister_dlg(dlg->ua, dlg);
	if (status != PJ_SUCCESS) {
	    pj_assert(!"Unexpected failed unregistration!");
	    return status;
	}
    }

    
    destroy_dialog(dlg, unlock_mutex);

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjsip_dlg_terminate( pjsip_dialog *dlg )
{
    
    PJ_ASSERT_RETURN(dlg->sess_count==0, PJ_EINVALIDOP);

    
    PJ_ASSERT_RETURN(dlg->tsx_count==0, PJ_EINVALIDOP);

    return unregister_and_destroy_dialog(dlg, PJ_FALSE);
}



PJ_DEF(pj_status_t) pjsip_dlg_set_route_set( pjsip_dialog *dlg, const pjsip_route_hdr *route_set )
{
    pjsip_route_hdr *r;

    PJ_ASSERT_RETURN(dlg, PJ_EINVAL);

    pjsip_dlg_inc_lock(dlg);

    
    pj_list_init(&dlg->route_set);

    if (!route_set) {
	pjsip_dlg_dec_lock(dlg);
	return PJ_SUCCESS;
    }

    r = route_set->next;
    while (r != route_set) {
	pjsip_route_hdr *new_r;

	new_r = (pjsip_route_hdr*) pjsip_hdr_clone(dlg->pool, r);
	pj_list_push_back(&dlg->route_set, new_r);

	r = r->next;
    }

    pjsip_dlg_dec_lock(dlg);
    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjsip_dlg_inc_session( pjsip_dialog *dlg, pjsip_module *mod )
{
    PJ_ASSERT_RETURN(dlg && mod, PJ_EINVAL);

    pj_log_push_indent();

    pjsip_dlg_inc_lock(dlg);
    ++dlg->sess_count;
    pjsip_dlg_dec_lock(dlg);

    PJ_LOG(5,(dlg->obj_name, "Session count inc to %d by %.*s", dlg->sess_count, (int)mod->name.slen, mod->name.ptr));

    pj_log_pop_indent();
    return PJ_SUCCESS;
}


PJ_DEF(void) pjsip_dlg_inc_lock(pjsip_dialog *dlg)
{
    PJ_LOG(6,(dlg->obj_name, "Entering pjsip_dlg_inc_lock(), sess_count=%d", dlg->sess_count));

    pj_grp_lock_acquire(dlg->grp_lock_);
    dlg->sess_count++;

    PJ_LOG(6,(dlg->obj_name, "Leaving pjsip_dlg_inc_lock(), sess_count=%d", dlg->sess_count));
}


PJ_DEF(pj_status_t) pjsip_dlg_try_inc_lock(pjsip_dialog *dlg)
{
    pj_status_t status;

    PJ_LOG(6,(dlg->obj_name,"Entering pjsip_dlg_try_inc_lock(), sess_count=%d", dlg->sess_count));

    status = pj_grp_lock_tryacquire(dlg->grp_lock_);
    if (status != PJ_SUCCESS) {
	PJ_LOG(6,(dlg->obj_name, "pjsip_dlg_try_inc_lock() failed"));
	return status;
    }

    dlg->sess_count++;

    PJ_LOG(6,(dlg->obj_name, "Leaving pjsip_dlg_try_inc_lock(), sess_count=%d", dlg->sess_count));

    return PJ_SUCCESS;
}



PJ_DEF(void) pjsip_dlg_dec_lock(pjsip_dialog *dlg)
{
    PJ_ASSERT_ON_FAIL(dlg!=NULL, return);

    PJ_LOG(6,(dlg->obj_name, "Entering pjsip_dlg_dec_lock(), sess_count=%d", dlg->sess_count));

    pj_assert(dlg->sess_count > 0);
    --dlg->sess_count;

    if (dlg->sess_count==0 && dlg->tsx_count==0) {
	pj_grp_lock_release(dlg->grp_lock_);
	pj_grp_lock_acquire(dlg->grp_lock_);
	
	unregister_and_destroy_dialog(dlg, PJ_TRUE);
    } else {
	pj_grp_lock_release(dlg->grp_lock_);
    }

    PJ_LOG(6,(THIS_FILE, "Leaving pjsip_dlg_dec_lock() (dlg=%p)", dlg));
}



PJ_DEF(pj_status_t) pjsip_dlg_dec_session( pjsip_dialog *dlg, pjsip_module *mod)
{
    PJ_ASSERT_RETURN(dlg, PJ_EINVAL);

    pj_log_push_indent();

    PJ_LOG(5,(dlg->obj_name, "Session count dec to %d by %.*s", dlg->sess_count-1, (int)mod->name.slen, mod->name.ptr));

    pjsip_dlg_inc_lock(dlg);
    --dlg->sess_count;
    pjsip_dlg_dec_lock(dlg);

    pj_log_pop_indent();
    return PJ_SUCCESS;
}

PJ_DEF(pj_grp_lock_t *) pjsip_dlg_get_lock(pjsip_dialog *dlg)
{
    PJ_ASSERT_RETURN(dlg, NULL);
    return dlg->grp_lock_;
}


PJ_DEF(pj_bool_t) pjsip_dlg_has_usage( pjsip_dialog *dlg, pjsip_module *mod)
{
    unsigned index;
    pj_bool_t found = PJ_FALSE;

    pjsip_dlg_inc_lock(dlg);
    for (index=0; index<dlg->usage_cnt; ++index) {
    	if (dlg->usage[index] == mod) {
    	    found = PJ_TRUE;
    	    break;
    	}
    }
    pjsip_dlg_dec_lock(dlg);

    return found;
}


PJ_DEF(pj_status_t) pjsip_dlg_add_usage( pjsip_dialog *dlg, pjsip_module *mod, void *mod_data )

{
    unsigned index;

    PJ_ASSERT_RETURN(dlg && mod, PJ_EINVAL);
    PJ_ASSERT_RETURN(mod->id >= 0 && mod->id < PJSIP_MAX_MODULE, PJ_EINVAL);
    PJ_ASSERT_RETURN(dlg->usage_cnt < PJSIP_MAX_MODULE, PJ_EBUG);

    PJ_LOG(5,(dlg->obj_name, "Module %.*s added as dialog usage, data=%p", (int)mod->name.slen, mod->name.ptr, mod_data));


    pjsip_dlg_inc_lock(dlg);

    
    for (index=0; index<dlg->usage_cnt; ++index) {
	if (dlg->usage[index] == mod) {
	    
	    PJ_LOG(4,(dlg->obj_name, "Module %.*s already registered as dialog usage, " "updating the data %p", (int)mod->name.slen, mod->name.ptr, mod_data));


	    dlg->mod_data[mod->id] = mod_data;

	    pjsip_dlg_dec_lock(dlg);
	    return PJ_SUCCESS;

	    
	    
	    
	}

	if (dlg->usage[index]->priority > mod->priority)
	    break;
    }

    
    pj_array_insert(dlg->usage, sizeof(dlg->usage[0]), dlg->usage_cnt, index, &mod);

    
    dlg->mod_data[mod->id] = mod_data;

    
    ++dlg->usage_cnt;

    pjsip_dlg_dec_lock(dlg);

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjsip_dlg_set_mod_data( pjsip_dialog *dlg, int mod_id, void *data )

{
    PJ_ASSERT_RETURN(dlg, PJ_EINVAL);
    PJ_ASSERT_RETURN(mod_id >= 0 && mod_id < PJSIP_MAX_MODULE, PJ_EINVAL);
    dlg->mod_data[mod_id] = data;
    return PJ_SUCCESS;
}


PJ_DEF(void*) pjsip_dlg_get_mod_data( pjsip_dialog *dlg, int mod_id)
{
    PJ_ASSERT_RETURN(dlg, NULL);
    PJ_ASSERT_RETURN(mod_id >= 0 && mod_id < PJSIP_MAX_MODULE, NULL);
    return dlg->mod_data[mod_id];
}



static pj_status_t dlg_create_request_throw( pjsip_dialog *dlg, const pjsip_method *method, int cseq, pjsip_tx_data **p_tdata )


{
    pjsip_tx_data *tdata;
    pjsip_contact_hdr *contact;
    pjsip_route_hdr *route, *end_list;
    pj_status_t status;

    
    if (pjsip_method_creates_dialog(method))
	contact = dlg->local.contact;
    else contact = NULL;

    
    status = pjsip_endpt_create_request_from_hdr(dlg->endpt, method, dlg->target, dlg->local.info, dlg->remote.info, contact, dlg->call_id, cseq, NULL, &tdata);








    if (status != PJ_SUCCESS)
	return status;

    
    tdata->mod_data[dlg->ua->id] = dlg;

    
    route = dlg->route_set.next;
    end_list = &dlg->route_set;
    for (; route != end_list; route = route->next ) {
	pjsip_route_hdr *r;
	r = (pjsip_route_hdr*) pjsip_hdr_shallow_clone( tdata->pool, route );
	pjsip_routing_hdr_set_route(r);
	pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)r);
    }

    
    if (method->id != PJSIP_ACK_METHOD && method->id != PJSIP_CANCEL_METHOD) {
	status = pjsip_auth_clt_init_req( &dlg->auth_sess, tdata );
	if (status != PJ_SUCCESS)
	    return status;
    }

    
    *p_tdata = tdata;

    return PJ_SUCCESS;
}




PJ_DEF(pj_status_t) pjsip_dlg_create_request( pjsip_dialog *dlg, const pjsip_method *method, int cseq, pjsip_tx_data **p_tdata)


{
    pj_status_t status;
    pjsip_tx_data *tdata = NULL;
    PJ_USE_EXCEPTION;

    PJ_ASSERT_RETURN(dlg && method && p_tdata, PJ_EINVAL);

    
    pjsip_dlg_inc_lock(dlg);

    
    if (cseq < 0)
	cseq = dlg->local.cseq + 1;

    
    status = PJ_EBUG;

    
    PJ_TRY {
	status = dlg_create_request_throw(dlg, method, cseq, &tdata);
    }
    PJ_CATCH_ANY {
	status = PJ_ENOMEM;
    }
    PJ_END;

    
    if (status != PJ_SUCCESS && tdata) {
	pjsip_tx_data_dec_ref( tdata );
	tdata = NULL;
    }

    
    pjsip_dlg_dec_lock(dlg);

    *p_tdata = tdata;

    return status;
}


static void send_ack_callback( pjsip_send_state *send_state, pj_ssize_t sent, pj_bool_t *cont )
{
    if (sent > 0)
	return;

    if (*cont) {
	PJ_PERROR(3,(THIS_FILE, (pj_status_t)-sent, "Temporary failure in sending %s, " "will try next server", pjsip_tx_data_get_info(send_state->tdata)));


    } else {
	PJ_PERROR(3,(THIS_FILE, (pj_status_t)-sent, "Failed to send %s!", pjsip_tx_data_get_info(send_state->tdata)));

    }
}


PJ_DEF(pj_status_t) pjsip_dlg_send_request( pjsip_dialog *dlg, pjsip_tx_data *tdata, int mod_data_id, void *mod_data)


{
    pjsip_transaction *tsx;
    pjsip_msg *msg = tdata->msg;
    pj_status_t status;

    
    PJ_ASSERT_RETURN(dlg && tdata && tdata->msg, PJ_EINVAL);
    PJ_ASSERT_RETURN(tdata->msg->type == PJSIP_REQUEST_MSG, PJSIP_ENOTREQUESTMSG);

    pj_log_push_indent();
    PJ_LOG(5,(dlg->obj_name, "Sending %s", pjsip_tx_data_get_info(tdata)));

    
    pjsip_dlg_inc_lock(dlg);

    
    tdata->mod_data[dlg->ua->id] = dlg;

    
    if (dlg->via_addr.host.slen > 0) {
        tdata->via_addr = dlg->via_addr;
        tdata->via_tp = dlg->via_tp;
    }

    
    if (msg->line.req.method.id != PJSIP_CANCEL_METHOD && msg->line.req.method.id != PJSIP_ACK_METHOD)
    {
	pjsip_cseq_hdr *ch;

	ch = PJSIP_MSG_CSEQ_HDR(msg);
	PJ_ASSERT_RETURN(ch!=NULL, PJ_EBUG);

	ch->cseq = dlg->local.cseq++;

	
	pjsip_tx_data_invalidate_msg( tdata );
    }

    
    if (msg->line.req.method.id != PJSIP_ACK_METHOD) {
	int tsx_count;

	status = pjsip_tsx_create_uac(dlg->ua, tdata, &tsx);
	if (status != PJ_SUCCESS)
	    goto on_error;

	
	status = pjsip_tsx_set_transport(tsx, &dlg->tp_sel);
	pj_assert(status == PJ_SUCCESS);

	
	tsx->mod_data[dlg->ua->id] = dlg;

	
	if (mod_data_id >= 0 && mod_data_id < PJSIP_MAX_MODULE)
	    tsx->mod_data[mod_data_id] = mod_data;

	
	tsx_count = ++dlg->tsx_count;

	
	status = pjsip_tsx_send_msg(tsx, tdata);
	if (status != PJ_SUCCESS) {
	    if (dlg->tsx_count == tsx_count)
		pjsip_tsx_terminate(tsx, tsx->status_code);
	    goto on_error;
	}

    } else {
	
	pjsip_tx_data_set_transport(tdata, &dlg->tp_sel);

	
	status = pjsip_endpt_send_request_stateless(dlg->endpt, tdata, NULL, &send_ack_callback);
	if (status != PJ_SUCCESS)
	    goto on_error;

    }

    
    pjsip_dlg_dec_lock(dlg);
    pj_log_pop_indent();
    return PJ_SUCCESS;

on_error:
    
    pjsip_dlg_dec_lock(dlg);

    
    pjsip_tx_data_dec_ref( tdata );
    pj_log_pop_indent();
    return status;
}


static void dlg_beautify_response(pjsip_dialog *dlg, pj_bool_t add_headers, int st_code, pjsip_tx_data *tdata)


{
    pjsip_cseq_hdr *cseq;
    int st_class;
    const pjsip_hdr *c_hdr;
    pjsip_hdr *hdr;

    cseq = PJSIP_MSG_CSEQ_HDR(tdata->msg);
    pj_assert(cseq != NULL);

    st_class = st_code / 100;

    
    if (add_headers && pjsip_method_creates_dialog(&cseq->method)) {
	
	if (st_class==2 || st_class==3 || (st_class==1 && st_code != 100) || st_code==485)
	{
	    
	    if (pjsip_msg_find_hdr(tdata->msg, PJSIP_H_CONTACT, NULL) == 0 && pjsip_msg_find_hdr_by_name(tdata->msg, &HCONTACT, NULL) == 0)
	    {
		hdr = (pjsip_hdr*) pjsip_hdr_clone(tdata->pool, dlg->local.contact);
		pjsip_msg_add_hdr(tdata->msg, hdr);
	    }
	}

	
	if ((((st_code/10==18 || st_class==2) && dlg->add_allow)
	     || st_code==405) && pjsip_msg_find_hdr(tdata->msg, PJSIP_H_ALLOW, NULL)==NULL)
	{
	    c_hdr = pjsip_endpt_get_capability(dlg->endpt, PJSIP_H_ALLOW, NULL);
	    if (c_hdr) {
		hdr = (pjsip_hdr*) pjsip_hdr_clone(tdata->pool, c_hdr);
		pjsip_msg_add_hdr(tdata->msg, hdr);
	    }
	}

	
	if (st_class==2 && pjsip_msg_find_hdr(tdata->msg, PJSIP_H_SUPPORTED, NULL)==NULL)
	{
	    c_hdr = pjsip_endpt_get_capability(dlg->endpt, PJSIP_H_SUPPORTED, NULL);
	    if (c_hdr) {
		hdr = (pjsip_hdr*) pjsip_hdr_clone(tdata->pool, c_hdr);
		pjsip_msg_add_hdr(tdata->msg, hdr);
	    }
	}

    }

    
    if (st_code != 100) {
	pjsip_to_hdr *to;

	to = PJSIP_MSG_TO_HDR(tdata->msg);
	pj_assert(to != NULL);

	to->tag = dlg->local.info->tag;

	if (dlg->state == PJSIP_DIALOG_STATE_NULL)
	    dlg->state = PJSIP_DIALOG_STATE_ESTABLISHED;
    }
}



PJ_DEF(pj_status_t) pjsip_dlg_create_response(	pjsip_dialog *dlg, pjsip_rx_data *rdata, int st_code, const pj_str_t *st_text, pjsip_tx_data **p_tdata)



{
    pj_status_t status;
    pjsip_tx_data *tdata;

    
    status = pjsip_endpt_create_response(dlg->endpt, rdata, st_code, st_text, &tdata);
    if (status != PJ_SUCCESS)
	return status;

    
    pjsip_dlg_inc_lock(dlg);

    
    tdata->mod_data[dlg->ua->id] = dlg;

    dlg_beautify_response(dlg, PJ_FALSE, st_code, tdata);

    
    pjsip_dlg_dec_lock(dlg);

    
    *p_tdata = tdata;
    return PJ_SUCCESS;
}


PJ_DEF(pj_status_t) pjsip_dlg_modify_response(	pjsip_dialog *dlg, pjsip_tx_data *tdata, int st_code, const pj_str_t *st_text)


{
    pjsip_hdr *hdr;

    PJ_ASSERT_RETURN(dlg && tdata && tdata->msg, PJ_EINVAL);
    PJ_ASSERT_RETURN(tdata->msg->type == PJSIP_RESPONSE_MSG, PJSIP_ENOTRESPONSEMSG);
    PJ_ASSERT_RETURN(st_code >= 100 && st_code <= 699, PJ_EINVAL);

    
    pjsip_dlg_inc_lock(dlg);

    
    tdata->msg->line.status.code = st_code;
    if (st_text) {
	pj_strdup(tdata->pool, &tdata->msg->line.status.reason, st_text);
    } else {
	tdata->msg->line.status.reason = *pjsip_get_status_text(st_code);
    }

    
    hdr = (pjsip_hdr*) pjsip_msg_find_hdr(tdata->msg, PJSIP_H_CONTACT, NULL);
    if (hdr)
	pj_list_erase(hdr);

    
    dlg_beautify_response(dlg, st_code/100 <= 2, st_code, tdata);


    
    pjsip_tx_data_add_ref(tdata);

    
    pjsip_tx_data_invalidate_msg(tdata);

    
    pjsip_dlg_dec_lock(dlg);

    return PJ_SUCCESS;
}


PJ_DEF(pj_status_t) pjsip_dlg_send_response( pjsip_dialog *dlg, pjsip_transaction *tsx, pjsip_tx_data *tdata)

{
    pj_status_t status;

    
    PJ_ASSERT_RETURN(dlg && tsx && tdata && tdata->msg, PJ_EINVAL);
    PJ_ASSERT_RETURN(tdata->msg->type == PJSIP_RESPONSE_MSG, PJSIP_ENOTRESPONSEMSG);

    
    PJ_ASSERT_RETURN(tsx->mod_data[dlg->ua->id] == dlg, PJ_EINVALIDOP);

    pj_log_push_indent();

    PJ_LOG(5,(dlg->obj_name, "Sending %s", pjsip_tx_data_get_info(tdata)));

    

    PJ_ASSERT_RETURN( PJSIP_MSG_CSEQ_HDR(tdata->msg)->cseq == tsx->cseq && pjsip_method_cmp(&PJSIP_MSG_CSEQ_HDR(tdata->msg)->method, &tsx->method)==0, PJ_EINVALIDOP);




    
    pjsip_dlg_inc_lock(dlg);

    
    dlg_beautify_response(dlg, PJ_TRUE, tdata->msg->line.status.code, tdata);

    
    if (dlg->tp_sel.type != tsx->tp_sel.type || dlg->tp_sel.u.ptr != tsx->tp_sel.u.ptr)
    {
	status = pjsip_tsx_set_transport(tsx, &dlg->tp_sel);
	pj_assert(status == PJ_SUCCESS);
    }

    
    status = pjsip_tsx_send_msg(tsx, tdata);

    
    if (status != PJ_SUCCESS) {
	pjsip_tx_data_dec_ref(tdata);
    }

    pjsip_dlg_dec_lock(dlg);
    pj_log_pop_indent();

    return status;
}



PJ_DEF(pj_status_t) pjsip_dlg_respond(  pjsip_dialog *dlg, pjsip_rx_data *rdata, int st_code, const pj_str_t *st_text, const pjsip_hdr *hdr_list, const pjsip_msg_body *body )




{
    pj_status_t status;
    pjsip_tx_data *tdata;

    
    PJ_ASSERT_RETURN(dlg && rdata && rdata->msg_info.msg, PJ_EINVAL);
    PJ_ASSERT_RETURN(rdata->msg_info.msg->type == PJSIP_REQUEST_MSG, PJSIP_ENOTREQUESTMSG);

    
    PJ_ASSERT_RETURN(pjsip_rdata_get_tsx(rdata) && pjsip_rdata_get_tsx(rdata)->mod_data[dlg->ua->id] == dlg, PJ_EINVALIDOP);


    
    status = pjsip_dlg_create_response(dlg, rdata, st_code, st_text, &tdata);
    if (status != PJ_SUCCESS)
	return status;

    
    if (hdr_list) {
	const pjsip_hdr *hdr;

	hdr = hdr_list->next;
	while (hdr != hdr_list) {
	    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)pjsip_hdr_clone(tdata->pool, hdr));
	    hdr = hdr->next;
	}
    }

    
    if (body) {
	tdata->msg->body = pjsip_msg_body_clone( tdata->pool, body);
    }

    
    return pjsip_dlg_send_response(dlg, pjsip_rdata_get_tsx(rdata), tdata);
}



void pjsip_dlg_on_rx_request( pjsip_dialog *dlg, pjsip_rx_data *rdata )
{
    pj_status_t status;
    pjsip_transaction *tsx = NULL;
    pj_bool_t processed = PJ_FALSE;
    unsigned i;

    PJ_LOG(5,(dlg->obj_name, "Received %s", pjsip_rx_data_get_info(rdata)));
    pj_log_push_indent();

    
    pjsip_dlg_inc_lock(dlg);

    
    if (rdata->msg_info.cseq->cseq <= dlg->remote.cseq && rdata->msg_info.msg->line.req.method.id != PJSIP_ACK_METHOD && rdata->msg_info.msg->line.req.method.id != PJSIP_CANCEL_METHOD)

    {
	
	pj_str_t warn_text;

	
	pjsip_dlg_dec_lock(dlg);

	pj_assert(pjsip_rdata_get_tsx(rdata) == NULL);
	warn_text = pj_str("Invalid CSeq");
	pjsip_endpt_respond_stateless(dlg->endpt, rdata, 500, &warn_text, NULL, NULL);
	pj_log_pop_indent();
	return;
    }

    
    dlg->remote.cseq = rdata->msg_info.cseq->cseq;

    
    if (dlg->remote.info->tag.slen == 0) {
	pj_strdup(dlg->pool, &dlg->remote.info->tag, &rdata->msg_info.from->tag);
    }

    
    if (pjsip_rdata_get_tsx(rdata) == NULL && rdata->msg_info.msg->line.req.method.id != PJSIP_ACK_METHOD)
    {
	status = pjsip_tsx_create_uas(dlg->ua, rdata, &tsx);
	if (status != PJ_SUCCESS) {
	    
	    char errmsg[PJ_ERR_MSG_SIZE];
	    pj_str_t reason;

	    reason = pj_strerror(status, errmsg, sizeof(errmsg));
	    pjsip_endpt_respond_stateless(dlg->endpt, rdata, 500, &reason, NULL, NULL);
	    goto on_return;
	}

	
	tsx->mod_data[dlg->ua->id] = dlg;

	
	++dlg->tsx_count;
    }

    
    if (pjsip_method_creates_dialog(&rdata->msg_info.cseq->method)) {
	pjsip_contact_hdr *contact;

	contact = (pjsip_contact_hdr*)
		  pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_CONTACT, NULL);
	if (contact && contact->uri && (dlg->remote.contact==NULL || pjsip_uri_cmp(PJSIP_URI_IN_REQ_URI, dlg->remote.contact->uri, contact->uri)))



	{
	    dlg->remote.contact = (pjsip_contact_hdr*)
	    			  pjsip_hdr_clone(dlg->pool, contact);
	    dlg->target = dlg->remote.contact->uri;
	}
    }

    
    for (i=0; i<dlg->usage_cnt; ++i) {

	if (!dlg->usage[i]->on_rx_request)
	    continue;

	processed = (*dlg->usage[i]->on_rx_request)(rdata);

	if (processed)
	    break;
    }

    
    if (tsx)
	pjsip_tsx_recv_msg(tsx, rdata);

    
    if (!processed && tsx && tsx->status_code < 200) {
	pjsip_tx_data *tdata;
	const pj_str_t reason = { "Unhandled by dialog usages", 26};

	PJ_LOG(4,(tsx->obj_name, "%s was unhandled by " "dialog usages, sending 500 response", pjsip_rx_data_get_info(rdata)));


	status = pjsip_dlg_create_response(dlg, rdata, 500, &reason, &tdata);
	if (status == PJ_SUCCESS) {
	    status = pjsip_dlg_send_response(dlg, tsx, tdata);
	}
    }

on_return:
    
    pjsip_dlg_dec_lock(dlg);
    pj_log_pop_indent();
}


static void dlg_update_routeset(pjsip_dialog *dlg, const pjsip_rx_data *rdata)
{
    const pjsip_hdr *hdr, *end_hdr;
    
    const pjsip_msg *msg;
    const pjsip_method update = { PJSIP_OTHER_METHOD, {"UPDATE", 6}};

    msg = rdata->msg_info.msg;
    

    
    if (dlg->route_set_frozen)
	return;

    
    if (pjsip_method_cmp(&rdata->msg_info.cseq->method, &update) == 0)
	return;

    
    if (dlg->role == PJSIP_ROLE_UAC) {

	
	if (msg->type != PJSIP_RESPONSE_MSG)
	    return;

	
	
	

    } else {

	
	pj_assert(!"Should not happen");

    }

    
    pj_assert(msg->type == PJSIP_RESPONSE_MSG);

    
    if (msg->line.status.code >= 300)
	return;

    
    pj_list_init(&dlg->route_set);

    
    end_hdr = &msg->hdr;
    for (hdr=msg->hdr.prev; hdr!=end_hdr; hdr=hdr->prev) {
	if (hdr->type == PJSIP_H_RECORD_ROUTE) {
	    pjsip_route_hdr *r;
	    r = (pjsip_route_hdr*) pjsip_hdr_clone(dlg->pool, hdr);
	    pjsip_routing_hdr_set_route(r);
	    pj_list_push_back(&dlg->route_set, r);
	}
    }

    PJ_LOG(5,(dlg->obj_name, "Route-set updated"));

    
    if (pjsip_method_creates_dialog(&rdata->msg_info.cseq->method) && PJSIP_IS_STATUS_IN_CLASS(msg->line.status.code, 200))
    {
	dlg->route_set_frozen = PJ_TRUE;
	PJ_LOG(5,(dlg->obj_name, "Route-set frozen"));
    }
}



void pjsip_dlg_on_rx_response( pjsip_dialog *dlg, pjsip_rx_data *rdata )
{
    unsigned i;
    int res_code;

    PJ_LOG(5,(dlg->obj_name, "Received %s", pjsip_rx_data_get_info(rdata)));
    pj_log_push_indent();

    
    pjsip_dlg_inc_lock(dlg);

    
    pj_assert(pjsip_rdata_get_dlg(rdata) == dlg);

    
    res_code = rdata->msg_info.msg->line.status.code;

    
    if ((dlg->state == PJSIP_DIALOG_STATE_NULL && pjsip_method_creates_dialog(&rdata->msg_info.cseq->method) && (res_code > 100 && res_code < 300) && rdata->msg_info.to->tag.slen)


	 || (dlg->role==PJSIP_ROLE_UAC && !dlg->uac_has_2xx && res_code > 100 && res_code/100 <= 2 && pjsip_method_creates_dialog(&rdata->msg_info.cseq->method) && pj_stricmp(&dlg->remote.info->tag, &rdata->msg_info.to->tag)))





    {
	pjsip_contact_hdr *contact;

	
	pjsip_dlg_update_remote_cap(dlg, rdata->msg_info.msg, pj_stricmp(&dlg->remote.info->tag, &rdata->msg_info.to->tag));


	
	pj_strdup(dlg->pool, &dlg->remote.info->tag, &rdata->msg_info.to->tag);
	

	
	dlg_update_routeset(dlg, rdata);

	
	contact = (pjsip_contact_hdr*)
		  pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_CONTACT, NULL);
	if (contact && contact->uri && (dlg->remote.contact==NULL || pjsip_uri_cmp(PJSIP_URI_IN_REQ_URI, dlg->remote.contact->uri, contact->uri)))



	{
	    dlg->remote.contact = (pjsip_contact_hdr*)
	    			  pjsip_hdr_clone(dlg->pool, contact);
	    dlg->target = dlg->remote.contact->uri;
	}

	dlg->state = PJSIP_DIALOG_STATE_ESTABLISHED;

	
	if (dlg->role==PJSIP_ROLE_UAC && !dlg->uac_has_2xx && res_code/100==2)
	{
	    dlg->uac_has_2xx = PJ_TRUE;
	}
    }

    
    if (pjsip_method_creates_dialog(&rdata->msg_info.cseq->method) && res_code/100 == 2)
    {
	pjsip_contact_hdr *contact;

	contact = (pjsip_contact_hdr*) pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_CONTACT, NULL);

	if (contact && contact->uri && (dlg->remote.contact==NULL || pjsip_uri_cmp(PJSIP_URI_IN_REQ_URI, dlg->remote.contact->uri, contact->uri)))



	{
	    dlg->remote.contact = (pjsip_contact_hdr*)
	    			  pjsip_hdr_clone(dlg->pool, contact);
	    dlg->target = dlg->remote.contact->uri;
	}

	dlg_update_routeset(dlg, rdata);

	
	if (dlg->role==PJSIP_ROLE_UAC && !dlg->uac_has_2xx) {
	    pjsip_dlg_update_remote_cap(dlg, rdata->msg_info.msg, PJ_FALSE);
	    dlg->uac_has_2xx = PJ_TRUE;
	}
    }

    
    for (i=0; i<dlg->usage_cnt; ++i) {
	pj_bool_t processed;

	if (!dlg->usage[i]->on_rx_response)
	    continue;

	processed = (*dlg->usage[i]->on_rx_response)(rdata);

	if (processed)
	    break;
    }

    
    if (dlg->usage_cnt==0) {
	pj_status_t status;

	if (rdata->msg_info.cseq->method.id==PJSIP_INVITE_METHOD && rdata->msg_info.msg->line.status.code/100 == 2)
	{
	    pjsip_tx_data *ack;

	    status = pjsip_dlg_create_request(dlg, &pjsip_ack_method, rdata->msg_info.cseq->cseq, &ack);

	    if (status == PJ_SUCCESS)
		status = pjsip_dlg_send_request(dlg, ack, -1, NULL);
	} else if (rdata->msg_info.msg->line.status.code==401 || rdata->msg_info.msg->line.status.code==407)
	{
	    pjsip_transaction *tsx = pjsip_rdata_get_tsx(rdata);
	    pjsip_tx_data *tdata;

	    status = pjsip_auth_clt_reinit_req( &dlg->auth_sess, rdata, tsx->last_tx, &tdata);


	    if (status == PJ_SUCCESS) {
		
		status = pjsip_dlg_send_request(dlg, tdata, -1, NULL);
	    }
	}
    }

    

    
    pjsip_dlg_dec_lock(dlg);

    pj_log_pop_indent();
}


void pjsip_dlg_on_tsx_state( pjsip_dialog *dlg, pjsip_transaction *tsx, pjsip_event *e )

{
    unsigned i;

    PJ_LOG(5,(dlg->obj_name, "Transaction %s state changed to %s", tsx->obj_name, pjsip_tsx_state_str(tsx->state)));
    pj_log_push_indent();

    
    pjsip_dlg_inc_lock(dlg);

    
    for (i=0; i<dlg->usage_cnt; ++i) {

	if (!dlg->usage[i]->on_tsx_state)
	    continue;

	(*dlg->usage[i]->on_tsx_state)(tsx, e);
    }


    
    if (tsx->state == PJSIP_TSX_STATE_TERMINATED && tsx->mod_data[dlg->ua->id] == dlg)
    {
	pj_assert(dlg->tsx_count>0);
	--dlg->tsx_count;
	tsx->mod_data[dlg->ua->id] = NULL;
    }

    
    pjsip_dlg_dec_lock(dlg);
    pj_log_pop_indent();
}



PJ_DEF(pjsip_dialog_cap_status) pjsip_dlg_remote_has_cap( pjsip_dialog *dlg, int htype, const pj_str_t *hname, const pj_str_t *token)



{
    const pjsip_generic_array_hdr *hdr;
    pjsip_dialog_cap_status cap_status = PJSIP_DIALOG_CAP_UNSUPPORTED;
    unsigned i;

    PJ_ASSERT_RETURN(dlg && token, PJSIP_DIALOG_CAP_UNKNOWN);

    pjsip_dlg_inc_lock(dlg);

    hdr = (const pjsip_generic_array_hdr*)
	   pjsip_dlg_get_remote_cap_hdr(dlg, htype, hname);
    if (!hdr) {
	cap_status = PJSIP_DIALOG_CAP_UNKNOWN;
    } else {
	for (i=0; i<hdr->count; ++i) {
	    if (!pj_stricmp(&hdr->values[i], token)) {
		cap_status = PJSIP_DIALOG_CAP_SUPPORTED;
		break;
	    }
	}
    }

    pjsip_dlg_dec_lock(dlg);

    return cap_status;
}



PJ_DEF(pj_status_t) pjsip_dlg_update_remote_cap(pjsip_dialog *dlg, const pjsip_msg *msg, pj_bool_t strict)

{
    pjsip_hdr_e htypes[] = { PJSIP_H_ACCEPT, PJSIP_H_ALLOW, PJSIP_H_SUPPORTED };
    unsigned i;

    PJ_ASSERT_RETURN(dlg && msg, PJ_EINVAL);

    pjsip_dlg_inc_lock(dlg);

    
    for (i = 0; i < PJ_ARRAY_SIZE(htypes); ++i) {
	const pjsip_generic_array_hdr *hdr;
	pj_status_t status;

	
	hdr = (const pjsip_generic_array_hdr*)
	      pjsip_msg_find_hdr(msg, htypes[i], NULL);
	if (!hdr) {
	    
	    if (strict)
		pjsip_dlg_remove_remote_cap_hdr(dlg, htypes[i], NULL);
	} else {
	    
	    pjsip_generic_array_hdr tmp_hdr;

	    
	    pjsip_generic_array_hdr_init(dlg->pool, &tmp_hdr, NULL);
	    pj_memcpy(&tmp_hdr, hdr, sizeof(pjsip_hdr));

	    while (hdr) {
		unsigned j;

		
		for(j=0; j<hdr->count && tmp_hdr.count<PJSIP_GENERIC_ARRAY_MAX_COUNT; ++j)
		{
		    tmp_hdr.values[tmp_hdr.count++] = hdr->values[j];
		}

		
		hdr = (const pjsip_generic_array_hdr*)
		      pjsip_msg_find_hdr(msg, htypes[i], hdr->next);
	    }

	    
	    status = pjsip_dlg_set_remote_cap_hdr(dlg, &tmp_hdr);
	    if (status != PJ_SUCCESS) {
		pjsip_dlg_dec_lock(dlg);
		return status;
	    }
	}
    }

    pjsip_dlg_dec_lock(dlg);

    return PJ_SUCCESS;
}



PJ_DEF(const pjsip_hdr*) pjsip_dlg_get_remote_cap_hdr(pjsip_dialog *dlg, int htype, const pj_str_t *hname)

{
    pjsip_hdr *hdr;

    
    PJ_ASSERT_RETURN(dlg, NULL);
    PJ_ASSERT_RETURN((htype != PJSIP_H_OTHER) || (hname && hname->slen), NULL);

    pjsip_dlg_inc_lock(dlg);

    hdr = dlg->rem_cap_hdr.next;
    while (hdr != &dlg->rem_cap_hdr) {
	if ((htype != PJSIP_H_OTHER && htype == hdr->type) || (htype == PJSIP_H_OTHER && pj_stricmp(&hdr->name, hname) == 0))
	{
	    pjsip_dlg_dec_lock(dlg);
	    return hdr;
	}
	hdr = hdr->next;
    }

    pjsip_dlg_dec_lock(dlg);

    return NULL;
}



PJ_DEF(pj_status_t) pjsip_dlg_set_remote_cap_hdr( pjsip_dialog *dlg, const pjsip_generic_array_hdr *cap_hdr)

{
    pjsip_generic_array_hdr *hdr;

    
    PJ_ASSERT_RETURN(dlg && cap_hdr, PJ_EINVAL);

    pjsip_dlg_inc_lock(dlg);

    
    hdr = (pjsip_generic_array_hdr*)
	  pjsip_dlg_get_remote_cap_hdr(dlg, cap_hdr->type, &cap_hdr->name);

    
    if (hdr && hdr->count == cap_hdr->count) {
	unsigned i;
	pj_bool_t uptodate = PJ_TRUE;

	for (i=0; i<hdr->count; ++i) {
	    if (pj_stricmp(&hdr->values[i], &cap_hdr->values[i]))
		uptodate = PJ_FALSE;
	}

	
	if (uptodate) {
	    pjsip_dlg_dec_lock(dlg);
	    return PJ_SUCCESS;
	}
    }

    
    if (hdr)
	pj_list_erase(hdr);

    
    hdr = (pjsip_generic_array_hdr*) pjsip_hdr_clone(dlg->pool, cap_hdr);
    hdr->type = cap_hdr->type;
    pj_strdup(dlg->pool, &hdr->name, &cap_hdr->name);
    pj_list_push_back(&dlg->rem_cap_hdr, hdr);

    pjsip_dlg_dec_lock(dlg);

    
    return PJ_SUCCESS;
}


PJ_DEF(pj_status_t) pjsip_dlg_remove_remote_cap_hdr(pjsip_dialog *dlg, int htype, const pj_str_t *hname)

{
    pjsip_generic_array_hdr *hdr;

    
    PJ_ASSERT_RETURN(dlg, PJ_EINVAL);
    PJ_ASSERT_RETURN((htype != PJSIP_H_OTHER) || (hname && hname->slen), PJ_EINVAL);

    pjsip_dlg_inc_lock(dlg);

    hdr = (pjsip_generic_array_hdr*)
	  pjsip_dlg_get_remote_cap_hdr(dlg, htype, hname);
    if (!hdr) {
	pjsip_dlg_dec_lock(dlg);
	return PJ_ENOTFOUND;
    }

    pj_list_erase(hdr);

    pjsip_dlg_dec_lock(dlg);

    return PJ_SUCCESS;
}
