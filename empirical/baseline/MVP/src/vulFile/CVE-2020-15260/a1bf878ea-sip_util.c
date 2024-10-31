




















static const char *event_str[] =  {
    "UNIDENTIFIED", "TIMER", "TX_MSG", "RX_MSG", "TRANSPORT_ERROR", "TSX_STATE", "USER", };







static pj_str_t str_TEXT = { "text", 4}, str_PLAIN = { "plain", 5 };


PJ_DEF(pj_status_t) pjsip_target_set_add_uri( pjsip_target_set *tset, pj_pool_t *pool, const pjsip_uri *uri, int q1000)


{
    pjsip_target *t, *pos = NULL;

    PJ_ASSERT_RETURN(tset && pool && uri, PJ_EINVAL);

    
    if (q1000 <= 0)
	q1000 = 1000;

    
    t = tset->head.next;
    while (t != &tset->head) {
	if (pjsip_uri_cmp(PJSIP_URI_IN_REQ_URI, t->uri, uri)==PJ_SUCCESS)
	    return PJ_EEXISTS;
	if (pos==NULL && t->q1000 < q1000)
	    pos = t;
	t = t->next;
    }

    
    t = PJ_POOL_ZALLOC_T(pool, pjsip_target);
    t->uri = (pjsip_uri*)pjsip_uri_clone(pool, uri);
    t->q1000 = q1000;

    
    if (pos == NULL)
	pj_list_push_back(&tset->head, t);
    else pj_list_insert_before(pos, t);

    
    if (tset->current == NULL)
	tset->current = t;

    return PJ_SUCCESS;
}


PJ_DEF(pj_status_t) pjsip_target_set_add_from_msg( pjsip_target_set *tset, pj_pool_t *pool, const pjsip_msg *msg)

{
    const pjsip_hdr *hdr;
    unsigned added = 0;

    PJ_ASSERT_RETURN(tset && pool && msg, PJ_EINVAL);

    
    hdr = msg->hdr.next;
    while (hdr != &msg->hdr) {
	if (hdr->type == PJSIP_H_CONTACT) {
	    const pjsip_contact_hdr *cn_hdr = (const pjsip_contact_hdr*)hdr;

	    if (!cn_hdr->star) {
		pj_status_t rc;
		rc = pjsip_target_set_add_uri(tset, pool, cn_hdr->uri,  cn_hdr->q1000);
		if (rc == PJ_SUCCESS)
		    ++added;
	    }
	}
	hdr = hdr->next;
    }

    return added ? PJ_SUCCESS : PJ_EEXISTS;
}



PJ_DEF(pjsip_target*) pjsip_target_set_get_next(const pjsip_target_set *tset)
{
    const pjsip_target *t, *next = NULL;

    t = tset->head.next;
    while (t != &tset->head) {
	if (PJSIP_IS_STATUS_IN_CLASS(t->code, 200)) {
	    
	    return NULL;
	}
	if (PJSIP_IS_STATUS_IN_CLASS(t->code, 600)) {
	    
	    return NULL;
	}
	if (t->code==0 && next==NULL) {
	    
	    next = t;
	}
	t = t->next;
    }

    return (pjsip_target*)next;
}



PJ_DEF(pj_status_t) pjsip_target_set_set_current( pjsip_target_set *tset, pjsip_target *target)
{
    PJ_ASSERT_RETURN(tset && target, PJ_EINVAL);
    PJ_ASSERT_RETURN(pj_list_find_node(tset, target) != NULL, PJ_ENOTFOUND);

    tset->current = target;

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjsip_target_assign_status( pjsip_target *target, pj_pool_t *pool, int status_code, const pj_str_t *reason)


{
    PJ_ASSERT_RETURN(target && pool && status_code && reason, PJ_EINVAL);

    target->code = (pjsip_status_code)status_code;
    pj_strdup(pool, &target->reason, reason);

    return PJ_SUCCESS;
}




static void init_request_throw( pjsip_endpoint *endpt, pjsip_tx_data *tdata, pjsip_method *method, pjsip_uri *param_target, pjsip_from_hdr *param_from, pjsip_to_hdr *param_to, pjsip_contact_hdr *param_contact, pjsip_cid_hdr *param_call_id, pjsip_cseq_hdr *param_cseq, const pj_str_t *param_text)








{
    pjsip_msg *msg;
    pjsip_msg_body *body;
    pjsip_via_hdr *via;
    const pjsip_hdr *endpt_hdr;

    
    msg = tdata->msg = pjsip_msg_create(tdata->pool, PJSIP_REQUEST_MSG);

    
    pj_memcpy(&msg->line.req.method, method, sizeof(*method));
    msg->line.req.uri = param_target;

    
    endpt_hdr = pjsip_endpt_get_request_headers(endpt)->next;
    while (endpt_hdr != pjsip_endpt_get_request_headers(endpt)) {
	pjsip_hdr *hdr = (pjsip_hdr*) 
			 pjsip_hdr_shallow_clone(tdata->pool, endpt_hdr);
	pjsip_msg_add_hdr( tdata->msg, hdr );
	endpt_hdr = endpt_hdr->next;
    }

    
    if (param_from->tag.slen == 0)
	pj_create_unique_string(tdata->pool, &param_from->tag);
    pjsip_msg_add_hdr(msg, (pjsip_hdr*)param_from);

    
    pjsip_msg_add_hdr(msg, (pjsip_hdr*)param_to);

    
    if (param_contact) {
	pjsip_msg_add_hdr(msg, (pjsip_hdr*)param_contact);
    }

    
    pjsip_msg_add_hdr(msg, (pjsip_hdr*)param_call_id);

    
    pjsip_msg_add_hdr(msg, (pjsip_hdr*)param_cseq);

    
    via = pjsip_via_hdr_create(tdata->pool);
    via->rport_param = pjsip_cfg()->endpt.disable_rport ? -1 : 0;
    pjsip_msg_insert_first_hdr(msg, (pjsip_hdr*)via);

    
    if (PJSIP_URI_SCHEME_IS_SIP(param_target) ||  PJSIP_URI_SCHEME_IS_SIPS(param_target))
    {
	pjsip_sip_uri *uri = (pjsip_sip_uri*) pjsip_uri_get_uri(param_target);
	pjsip_param *hparam;

	hparam = uri->header_param.next;
	while (hparam != &uri->header_param) {
	    pjsip_generic_string_hdr *hdr;

	    hdr = pjsip_generic_string_hdr_create(tdata->pool,  &hparam->name, &hparam->value);

	    pjsip_msg_add_hdr(msg, (pjsip_hdr*)hdr);
	    hparam = hparam->next;
	}
    }

    
    if (param_text) {
	body = PJ_POOL_ZALLOC_T(tdata->pool, pjsip_msg_body);
	body->content_type.type = str_TEXT;
	body->content_type.subtype = str_PLAIN;
	body->data = pj_pool_alloc(tdata->pool, param_text->slen );
	pj_memcpy(body->data, param_text->ptr, param_text->slen);
	body->len = (unsigned)param_text->slen;
	body->print_body = &pjsip_print_text_body;
	msg->body = body;
    }

    PJ_LOG(5,(THIS_FILE, "%s created.",  pjsip_tx_data_get_info(tdata)));

}


PJ_DEF(pj_status_t) pjsip_endpt_create_request(  pjsip_endpoint *endpt,  const pjsip_method *method, const pj_str_t *param_target, const pj_str_t *param_from, const pj_str_t *param_to, const pj_str_t *param_contact, const pj_str_t *param_call_id, int param_cseq, const pj_str_t *param_text, pjsip_tx_data **p_tdata)








{
    pjsip_uri *target;
    pjsip_tx_data *tdata;
    pjsip_from_hdr *from;
    pjsip_to_hdr *to;
    pjsip_contact_hdr *contact;
    pjsip_cseq_hdr *cseq = NULL;    
    pjsip_cid_hdr *call_id;
    pj_str_t tmp;
    pj_status_t status;
    const pj_str_t STR_CONTACT = { "Contact", 7 };
    PJ_USE_EXCEPTION;

    status = pjsip_endpt_create_tdata(endpt, &tdata);
    if (status != PJ_SUCCESS)
	return status;

    
    pjsip_tx_data_add_ref(tdata);

    PJ_TRY {
	
	pj_strdup_with_null(tdata->pool, &tmp, param_target);
	target = pjsip_parse_uri( tdata->pool, tmp.ptr, tmp.slen, 0);
	if (target == NULL) {
	    status = PJSIP_EINVALIDREQURI;
	    goto on_error;
	}

	
	from = pjsip_from_hdr_create(tdata->pool);
	pj_strdup_with_null(tdata->pool, &tmp, param_from);
	from->uri = pjsip_parse_uri( tdata->pool, tmp.ptr, tmp.slen,  PJSIP_PARSE_URI_AS_NAMEADDR);
	if (from->uri == NULL) {
	    status = PJSIP_EINVALIDHDR;
	    goto on_error;
	}
	pj_create_unique_string(tdata->pool, &from->tag);

	
	to = pjsip_to_hdr_create(tdata->pool);
	pj_strdup_with_null(tdata->pool, &tmp, param_to);
	to->uri = pjsip_parse_uri( tdata->pool, tmp.ptr, tmp.slen,  PJSIP_PARSE_URI_AS_NAMEADDR);
	if (to->uri == NULL) {
	    status = PJSIP_EINVALIDHDR;
	    goto on_error;
	}

	
	if (param_contact) {
	    pj_strdup_with_null(tdata->pool, &tmp, param_contact);
	    contact = (pjsip_contact_hdr*)
		      pjsip_parse_hdr(tdata->pool, &STR_CONTACT, tmp.ptr,  tmp.slen, NULL);
	    if (contact == NULL) {
		status = PJSIP_EINVALIDHDR;
		goto on_error;
	    }
	} else {
	    contact = NULL;
	}

	
	call_id = pjsip_cid_hdr_create(tdata->pool);
	if (param_call_id != NULL && param_call_id->slen)
	    pj_strdup(tdata->pool, &call_id->id, param_call_id);
	else pj_create_unique_string(tdata->pool, &call_id->id);

	
	cseq = pjsip_cseq_hdr_create(tdata->pool);
	if (param_cseq >= 0)
	    cseq->cseq = param_cseq;
	else cseq->cseq = pj_rand() & 0xFFFF;

	
	pjsip_method_copy(tdata->pool, &cseq->method, method);

	
	init_request_throw( endpt, tdata, &cseq->method, target, from, to,  contact, call_id, cseq, param_text);
    }
    PJ_CATCH_ANY {
	status = PJ_ENOMEM;
	goto on_error;
    }
    PJ_END  *p_tdata = tdata;

    return PJ_SUCCESS;

on_error:
    pjsip_tx_data_dec_ref(tdata);
    return status;
}

PJ_DEF(pj_status_t) pjsip_endpt_create_request_from_hdr( pjsip_endpoint *endpt, const pjsip_method *method, const pjsip_uri *param_target, const pjsip_from_hdr *param_from, const pjsip_to_hdr *param_to, const pjsip_contact_hdr *param_contact, const pjsip_cid_hdr *param_call_id, int param_cseq, const pj_str_t *param_text, pjsip_tx_data **p_tdata)








{
    pjsip_uri *target;
    pjsip_tx_data *tdata;
    pjsip_from_hdr *from;
    pjsip_to_hdr *to;
    pjsip_contact_hdr *contact;
    pjsip_cid_hdr *call_id;
    pjsip_cseq_hdr *cseq = NULL; 
    pj_status_t status;
    PJ_USE_EXCEPTION;

    
    PJ_ASSERT_RETURN(endpt && method && param_target && param_from && param_to && p_tdata, PJ_EINVAL);

    
    status = pjsip_endpt_create_tdata(endpt, &tdata);
    if (status != PJ_SUCCESS)
	return status;

    
    pjsip_tx_data_add_ref(tdata);

    PJ_TRY {
	
	target = (pjsip_uri*) pjsip_uri_clone(tdata->pool, param_target);
	from = (pjsip_from_hdr*) pjsip_hdr_clone(tdata->pool, param_from);
	pjsip_fromto_hdr_set_from(from);
	to = (pjsip_to_hdr*) pjsip_hdr_clone(tdata->pool, param_to);
	pjsip_fromto_hdr_set_to(to);
	if (param_contact) {
	    contact = (pjsip_contact_hdr*) 
	    	      pjsip_hdr_clone(tdata->pool, param_contact);
	} else {
	    contact = NULL;
	}
	call_id = pjsip_cid_hdr_create(tdata->pool);
	if (param_call_id != NULL && param_call_id->id.slen)
	    pj_strdup(tdata->pool, &call_id->id, &param_call_id->id);
	else pj_create_unique_string(tdata->pool, &call_id->id);

	cseq = pjsip_cseq_hdr_create(tdata->pool);
	if (param_cseq >= 0)
	    cseq->cseq = param_cseq;
	else cseq->cseq = pj_rand() % 0xFFFF;
	pjsip_method_copy(tdata->pool, &cseq->method, method);

	
	init_request_throw(endpt, tdata, &cseq->method, target, from, to,  contact, call_id, cseq, param_text);
    }
    PJ_CATCH_ANY {
	status = PJ_ENOMEM;
	goto on_error;
    }
    PJ_END;

    *p_tdata = tdata;
    return PJ_SUCCESS;

on_error:
    pjsip_tx_data_dec_ref(tdata);
    return status;
}


PJ_DEF(pj_status_t) pjsip_endpt_create_response( pjsip_endpoint *endpt, const pjsip_rx_data *rdata, int st_code, const pj_str_t *st_text, pjsip_tx_data **p_tdata)



{
    pjsip_tx_data *tdata;
    pjsip_msg *msg, *req_msg;
    pjsip_hdr *hdr;
    pjsip_to_hdr *to_hdr;
    pjsip_via_hdr *top_via = NULL, *via;
    pjsip_rr_hdr *rr;
    pj_status_t status;

    
    PJ_ASSERT_RETURN(endpt && rdata && p_tdata, PJ_EINVAL);

    
    PJ_ASSERT_RETURN(st_code >= 100 && st_code <= 699, PJ_EINVAL);

    
    req_msg = rdata->msg_info.msg;
    pj_assert(req_msg->type == PJSIP_REQUEST_MSG);

    
    PJ_ASSERT_RETURN(req_msg->line.req.method.id != PJSIP_ACK_METHOD, PJ_EINVALIDOP);

    
    status = pjsip_endpt_create_tdata( endpt, &tdata);
    if (status != PJ_SUCCESS)
	return status;

    
    pjsip_tx_data_add_ref(tdata);

    
    tdata->msg = msg = pjsip_msg_create(tdata->pool, PJSIP_RESPONSE_MSG);

    
    msg->line.status.code = st_code;
    if (st_text)
	pj_strdup(tdata->pool, &msg->line.status.reason, st_text);
    else msg->line.status.reason = *pjsip_get_status_text(st_code);

    
    tdata->rx_timestamp = rdata->pkt_info.timestamp;

    
    via = rdata->msg_info.via;
    while (via) {
	pjsip_via_hdr *new_via;

	new_via = (pjsip_via_hdr*)pjsip_hdr_clone(tdata->pool, via);
	if (top_via == NULL)
	    top_via = new_via;

	pjsip_msg_add_hdr( msg, (pjsip_hdr*)new_via);
	via = via->next;
	if (via != (void*)&req_msg->hdr)
	    via = (pjsip_via_hdr*) 
	    	  pjsip_msg_find_hdr(req_msg, PJSIP_H_VIA, via);
	else break;
    }

    
    rr = (pjsip_rr_hdr*) 
    	 pjsip_msg_find_hdr(req_msg, PJSIP_H_RECORD_ROUTE, NULL);
    while (rr) {
	pjsip_msg_add_hdr(msg, (pjsip_hdr*) pjsip_hdr_clone(tdata->pool, rr));
	rr = rr->next;
	if (rr != (void*)&req_msg->hdr)
	    rr = (pjsip_rr_hdr*) pjsip_msg_find_hdr(req_msg,  PJSIP_H_RECORD_ROUTE, rr);
	else break;
    }

    
    hdr = (pjsip_hdr*) pjsip_msg_find_hdr( req_msg, PJSIP_H_CALL_ID, NULL);
    pjsip_msg_add_hdr(msg, (pjsip_hdr*) pjsip_hdr_clone(tdata->pool, hdr));

    
    hdr = (pjsip_hdr*) pjsip_hdr_clone(tdata->pool, rdata->msg_info.from);
    pjsip_msg_add_hdr( msg, hdr);

    
    to_hdr = (pjsip_to_hdr*) pjsip_hdr_clone(tdata->pool, rdata->msg_info.to);
    pjsip_msg_add_hdr( msg, (pjsip_hdr*)to_hdr);

    
    if (to_hdr->tag.slen==0 && st_code > 100 && top_via) {
	to_hdr->tag = top_via->branch_param;
    }

    
    hdr = (pjsip_hdr*) pjsip_hdr_clone(tdata->pool, rdata->msg_info.cseq);
    pjsip_msg_add_hdr( msg, hdr);

    
    *p_tdata = tdata;

    PJ_LOG(5,(THIS_FILE, "%s created", pjsip_tx_data_get_info(tdata)));
    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjsip_endpt_create_ack( pjsip_endpoint *endpt, const pjsip_tx_data *tdata, const pjsip_rx_data *rdata, pjsip_tx_data **ack_tdata)


{
    pjsip_tx_data *ack = NULL;
    const pjsip_msg *invite_msg;
    const pjsip_from_hdr *from_hdr;
    const pjsip_to_hdr *to_hdr;
    const pjsip_cid_hdr *cid_hdr;
    const pjsip_cseq_hdr *cseq_hdr;
    const pjsip_hdr *hdr;
    pjsip_hdr *via;
    pjsip_to_hdr *to;
    pj_status_t status;

    
    pj_assert(rdata->msg_info.msg->type==PJSIP_RESPONSE_MSG && rdata->msg_info.msg->line.status.code >= 300);

    
    *ack_tdata = NULL;

    
    invite_msg = tdata->msg;

    


    from_hdr = (const pjsip_from_hdr*) FIND_HDR(invite_msg, FROM);
    PJ_ASSERT_ON_FAIL(from_hdr != NULL, goto on_missing_hdr);

    to_hdr = (const pjsip_to_hdr*) FIND_HDR(invite_msg, TO);
    PJ_ASSERT_ON_FAIL(to_hdr != NULL, goto on_missing_hdr);

    cid_hdr = (const pjsip_cid_hdr*) FIND_HDR(invite_msg, CALL_ID);
    PJ_ASSERT_ON_FAIL(to_hdr != NULL, goto on_missing_hdr);

    cseq_hdr = (const pjsip_cseq_hdr*) FIND_HDR(invite_msg, CSEQ);
    PJ_ASSERT_ON_FAIL(to_hdr != NULL, goto on_missing_hdr);



    
    status = pjsip_endpt_create_request_from_hdr(endpt,  pjsip_get_ack_method(), tdata->msg->line.req.uri, from_hdr, to_hdr, NULL, cid_hdr, cseq_hdr->cseq, NULL, &ack);






    if (status != PJ_SUCCESS)
	return status;

    
    to = (pjsip_to_hdr*) pjsip_msg_find_hdr(ack->msg, PJSIP_H_TO, NULL);
    pj_strdup(ack->pool, &to->tag, &rdata->msg_info.to->tag);


    
    while ((via=(pjsip_hdr*)pjsip_msg_find_hdr(ack->msg, PJSIP_H_VIA, NULL)) != NULL)
	pj_list_erase(via);

    
    hdr = (pjsip_hdr*) pjsip_msg_find_hdr( invite_msg, PJSIP_H_VIA, NULL);
    pjsip_msg_insert_first_hdr( ack->msg,  (pjsip_hdr*) pjsip_hdr_clone(ack->pool,hdr) );

    
    hdr = (pjsip_hdr*) pjsip_msg_find_hdr( invite_msg, PJSIP_H_ROUTE, NULL);
    while (hdr != NULL) {
	pjsip_msg_add_hdr( ack->msg,  (pjsip_hdr*) pjsip_hdr_clone(ack->pool, hdr) );
	hdr = hdr->next;
	if (hdr == &invite_msg->hdr)
	    break;
	hdr = (pjsip_hdr*) pjsip_msg_find_hdr( invite_msg, PJSIP_H_ROUTE, hdr);
    }

    
    *ack_tdata = ack;
    return PJ_SUCCESS;

on_missing_hdr:
    if (ack)
	pjsip_tx_data_dec_ref(ack);
    return PJSIP_EMISSINGHDR;
}



PJ_DEF(pj_status_t) pjsip_endpt_create_cancel( pjsip_endpoint *endpt, const pjsip_tx_data *req_tdata, pjsip_tx_data **p_tdata)

{
    pjsip_tx_data *cancel_tdata = NULL;
    const pjsip_from_hdr *from_hdr;
    const pjsip_to_hdr *to_hdr;
    const pjsip_cid_hdr *cid_hdr;
    const pjsip_cseq_hdr *cseq_hdr;
    const pjsip_hdr *hdr;
    pjsip_hdr *via;
    pj_status_t status;

    
    PJ_ASSERT_RETURN(req_tdata->msg->type == PJSIP_REQUEST_MSG && req_tdata->msg->line.req.method.id == PJSIP_INVITE_METHOD, PJ_EINVAL);


    


    from_hdr = (const pjsip_from_hdr*) FIND_HDR(req_tdata->msg, FROM);
    PJ_ASSERT_ON_FAIL(from_hdr != NULL, goto on_missing_hdr);

    to_hdr = (const pjsip_to_hdr*) FIND_HDR(req_tdata->msg, TO);
    PJ_ASSERT_ON_FAIL(to_hdr != NULL, goto on_missing_hdr);

    cid_hdr = (const pjsip_cid_hdr*) FIND_HDR(req_tdata->msg, CALL_ID);
    PJ_ASSERT_ON_FAIL(to_hdr != NULL, goto on_missing_hdr);

    cseq_hdr = (const pjsip_cseq_hdr*) FIND_HDR(req_tdata->msg, CSEQ);
    PJ_ASSERT_ON_FAIL(to_hdr != NULL, goto on_missing_hdr);



    
    status = pjsip_endpt_create_request_from_hdr(endpt,  pjsip_get_cancel_method(), req_tdata->msg->line.req.uri, from_hdr, to_hdr, NULL, cid_hdr, cseq_hdr->cseq, NULL, &cancel_tdata);






    if (status != PJ_SUCCESS)
	return status;

    
    while ((via=(pjsip_hdr*)pjsip_msg_find_hdr(cancel_tdata->msg, PJSIP_H_VIA, NULL)) != NULL)
	pj_list_erase(via);


    
    hdr = (pjsip_hdr*) pjsip_msg_find_hdr(req_tdata->msg, PJSIP_H_VIA, NULL);
    if (hdr) {
	pjsip_msg_insert_first_hdr(cancel_tdata->msg,  (pjsip_hdr*)pjsip_hdr_clone(cancel_tdata->pool, hdr));
    }

    
    hdr = (pjsip_hdr*) pjsip_msg_find_hdr(req_tdata->msg, PJSIP_H_ROUTE, NULL);
    while (hdr != NULL) {
	pjsip_msg_add_hdr(cancel_tdata->msg,  (pjsip_hdr*) pjsip_hdr_clone(cancel_tdata->pool, hdr));
	hdr = hdr->next;
	if (hdr != &req_tdata->msg->hdr)
	    hdr = (pjsip_hdr*) pjsip_msg_find_hdr(req_tdata->msg,  PJSIP_H_ROUTE, hdr);
	else break;
    }

    
    if (req_tdata->saved_strict_route) {
	cancel_tdata->saved_strict_route = (pjsip_route_hdr*)
	    pjsip_hdr_clone(cancel_tdata->pool, req_tdata->saved_strict_route);
    }

    
    pj_memcpy(&cancel_tdata->dest_info, &req_tdata->dest_info, sizeof(req_tdata->dest_info));

    
    pj_strdup(cancel_tdata->pool, &cancel_tdata->dest_info.name, &req_tdata->dest_info.name);

    
    *p_tdata = cancel_tdata;
    return PJ_SUCCESS;

on_missing_hdr:
    if (cancel_tdata)
	pjsip_tx_data_dec_ref(cancel_tdata);
    return PJSIP_EMISSINGHDR;
}



PJ_DEF(pj_status_t) pjsip_get_dest_info(const pjsip_uri *target_uri, const pjsip_uri *request_uri, pj_pool_t *pool, pjsip_host_info *dest_info)


{
    
    pj_bzero(dest_info, sizeof(*dest_info));

    
    if (PJSIP_URI_SCHEME_IS_SIPS(target_uri) ||  (pjsip_cfg()->endpt.disable_tls_switch == 0 && request_uri && PJSIP_URI_SCHEME_IS_SIPS(request_uri)))

    {
	pjsip_uri *uri = (pjsip_uri*) target_uri;
	const pjsip_sip_uri *url=(const pjsip_sip_uri*)pjsip_uri_get_uri(uri);
	unsigned flag;

	if (!PJSIP_URI_SCHEME_IS_SIPS(target_uri)) {
	    PJ_LOG(4,(THIS_FILE, "Automatic switch to TLS transport as " "request-URI uses ""sips"" scheme."));
	}

	dest_info->flag |= (PJSIP_TRANSPORT_SECURE | PJSIP_TRANSPORT_RELIABLE);
	if (url->maddr_param.slen)
	    pj_strdup(pool, &dest_info->addr.host, &url->maddr_param);
	else pj_strdup(pool, &dest_info->addr.host, &url->host);
        dest_info->addr.port = url->port;
	dest_info->type =  pjsip_transport_get_type_from_name(&url->transport_param);
	
	flag = pjsip_transport_get_flag_from_type(dest_info->type);
	if ((flag & dest_info->flag) != dest_info->flag) {
	    pjsip_transport_type_e t;

	    t = pjsip_transport_get_type_from_flag(dest_info->flag);
	    if (t != PJSIP_TRANSPORT_UNSPECIFIED)
		dest_info->type = t;
	}

    } else if (PJSIP_URI_SCHEME_IS_SIP(target_uri)) {
	pjsip_uri *uri = (pjsip_uri*) target_uri;
	const pjsip_sip_uri *url=(const pjsip_sip_uri*)pjsip_uri_get_uri(uri);
	if (url->maddr_param.slen)
	    pj_strdup(pool, &dest_info->addr.host, &url->maddr_param);
	else pj_strdup(pool, &dest_info->addr.host, &url->host);
	dest_info->addr.port = url->port;
	dest_info->type =  pjsip_transport_get_type_from_name(&url->transport_param);
	dest_info->flag =  pjsip_transport_get_flag_from_type(dest_info->type);
    } else {
	
	PJ_TODO(SUPPORT_REQUEST_ADDR_RESOLUTION_FOR_TEL_URI);
	return PJSIP_ENOROUTESET;
    }

    
    if (dest_info->type != PJSIP_TRANSPORT_UNSPECIFIED &&  pj_strchr(&dest_info->addr.host, ':'))
    {
	dest_info->type = (pjsip_transport_type_e)
			  ((int)dest_info->type | PJSIP_TRANSPORT_IPV6);
    }

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjsip_get_request_dest(const pjsip_tx_data *tdata, pjsip_host_info *dest_info )
{
    const pjsip_uri *target_uri;
    const pjsip_route_hdr *first_route_hdr;
    
    PJ_ASSERT_RETURN(tdata->msg->type == PJSIP_REQUEST_MSG,  PJSIP_ENOTREQUESTMSG);
    PJ_ASSERT_RETURN(dest_info != NULL, PJ_EINVAL);

    
    first_route_hdr = (const pjsip_route_hdr*) 
    		      pjsip_msg_find_hdr(tdata->msg, PJSIP_H_ROUTE, NULL);
    if (first_route_hdr) {
	target_uri = first_route_hdr->name_addr.uri;
    } else {
	target_uri = tdata->msg->line.req.uri;
    }

    return pjsip_get_dest_info(target_uri, tdata->msg->line.req.uri, (pj_pool_t*)tdata->pool, dest_info);
}



PJ_DEF(pj_status_t) pjsip_process_route_set(pjsip_tx_data *tdata, pjsip_host_info *dest_info )
{
    const pjsip_uri *new_request_uri, *target_uri;
    const pjsip_name_addr *topmost_route_uri;
    pjsip_route_hdr *first_route_hdr, *last_route_hdr;
    pj_status_t status;
    
    PJ_ASSERT_RETURN(tdata->msg->type == PJSIP_REQUEST_MSG,  PJSIP_ENOTREQUESTMSG);
    PJ_ASSERT_RETURN(dest_info != NULL, PJ_EINVAL);

    
    if (tdata->saved_strict_route != NULL) {
	pjsip_restore_strict_route_set(tdata);
    }
    PJ_ASSERT_RETURN(tdata->saved_strict_route==NULL, PJ_EBUG);

    
    last_route_hdr = first_route_hdr = (pjsip_route_hdr*)
	pjsip_msg_find_hdr(tdata->msg, PJSIP_H_ROUTE, NULL);
    if (first_route_hdr) {
	topmost_route_uri = &first_route_hdr->name_addr;
	while (last_route_hdr->next != (void*)&tdata->msg->hdr) {
	    pjsip_route_hdr *hdr;
	    hdr = (pjsip_route_hdr*)
	    	  pjsip_msg_find_hdr(tdata->msg, PJSIP_H_ROUTE,  last_route_hdr->next);
	    if (!hdr)
		break;
	    last_route_hdr = hdr;
	}
    } else {
	topmost_route_uri = NULL;
    }

    
    if (topmost_route_uri) {
	pj_bool_t has_lr_param;

	if (PJSIP_URI_SCHEME_IS_SIP(topmost_route_uri) || PJSIP_URI_SCHEME_IS_SIPS(topmost_route_uri))
	{
	    const pjsip_sip_uri *url = (const pjsip_sip_uri*)
		pjsip_uri_get_uri((const void*)topmost_route_uri);
	    has_lr_param = url->lr_param;
	} else {
	    has_lr_param = 0;
	}

	if (has_lr_param) {
	    new_request_uri = tdata->msg->line.req.uri;
	    
	    
	} else {
	    new_request_uri = (const pjsip_uri*) 
	    		      pjsip_uri_get_uri((pjsip_uri*)topmost_route_uri);
	    pj_list_erase(first_route_hdr);
	    tdata->saved_strict_route = first_route_hdr;
	    if (first_route_hdr == last_route_hdr)
		first_route_hdr = last_route_hdr = NULL;
	}

	target_uri = (pjsip_uri*)topmost_route_uri;

    } else {
	target_uri = new_request_uri = tdata->msg->line.req.uri;
    }

    
    status = pjsip_get_dest_info(target_uri, new_request_uri, tdata->pool, dest_info);
    if (status != PJ_SUCCESS)
	return status;

    
    if (tdata->tp_sel.type != PJSIP_TPSELECTOR_NONE && tdata->tp_sel.u.ptr) {
	if (tdata->tp_sel.type == PJSIP_TPSELECTOR_TRANSPORT)
	    dest_info->type = tdata->tp_sel.u.transport->key.type;
	else if (tdata->tp_sel.type == PJSIP_TPSELECTOR_LISTENER)
	    dest_info->type = tdata->tp_sel.u.listener->type;
    }

    
    if (new_request_uri && new_request_uri!=tdata->msg->line.req.uri) {
	pjsip_route_hdr *route = pjsip_route_hdr_create(tdata->pool);
	route->name_addr.uri = (pjsip_uri*) 
			       pjsip_uri_get_uri(tdata->msg->line.req.uri);
	if (last_route_hdr)
	    pj_list_insert_after(last_route_hdr, route);
	else pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)route);
	tdata->msg->line.req.uri = (pjsip_uri*)new_request_uri;
    }

    
    return PJ_SUCCESS;  
}



PJ_DEF(void) pjsip_restore_strict_route_set(pjsip_tx_data *tdata)
{
    pjsip_route_hdr *first_route_hdr, *last_route_hdr;

    
    if (tdata->saved_strict_route == NULL) {
	
	return;
    }

    
    first_route_hdr = (pjsip_route_hdr*)
		      pjsip_msg_find_hdr(tdata->msg, PJSIP_H_ROUTE, NULL);

    if (first_route_hdr == NULL) {
	
	pj_assert(!"Message route was modified?");
	tdata->saved_strict_route = NULL;
	return;
    }

    
    last_route_hdr = first_route_hdr;
    while (last_route_hdr->next != (void*)&tdata->msg->hdr) {
	pjsip_route_hdr *hdr;
	hdr = (pjsip_route_hdr*)
	      pjsip_msg_find_hdr(tdata->msg, PJSIP_H_ROUTE,  last_route_hdr->next);
	if (!hdr)
	    break;
	last_route_hdr = hdr;
    }

    
    tdata->msg->line.req.uri = last_route_hdr->name_addr.uri;
    pj_list_insert_before(first_route_hdr, tdata->saved_strict_route);
    pj_list_erase(last_route_hdr);

    
    tdata->saved_strict_route = NULL;
}



static void stateless_send_transport_cb( void *token, pjsip_tx_data *tdata, pj_ssize_t sent )

{
    pjsip_send_state *stateless_data = (pjsip_send_state*) token;
    pj_status_t need_update_via = PJ_TRUE;

    PJ_UNUSED_ARG(tdata);
    pj_assert(tdata == stateless_data->tdata);

    for (;;) {
	pj_status_t status;
	pj_bool_t cont;

	pj_sockaddr_t *cur_addr;
	pjsip_transport_type_e cur_addr_type;
	int cur_addr_len;

	pjsip_via_hdr *via;

	if (sent == -PJ_EPENDING) {
	    
	    cont = PJ_TRUE;
	} else {
	    
	    cont = (sent > 0) ? PJ_FALSE :
		   (tdata->dest_info.cur_addr<tdata->dest_info.addr.count-1);
	    if (stateless_data->app_cb) {
		(*stateless_data->app_cb)(stateless_data, sent, &cont);
	    } else {
		
		cont = PJ_FALSE;
	    }
	}

	
	if (stateless_data->cur_transport) {
	    pjsip_transport_dec_ref(stateless_data->cur_transport);
	    stateless_data->cur_transport = NULL;
	}

	
	if (sent > 0 || !cont) {
	    pjsip_tx_data_dec_ref(tdata);
	    return;
	}

	
	if (sent != -PJ_EPENDING) {
	    tdata->dest_info.cur_addr++;
	}

	
	if (tdata->dest_info.cur_addr >= tdata->dest_info.addr.count) {
	    
	    pjsip_tx_data_dec_ref(tdata);
	    return;
	}

	
	cur_addr = &tdata->dest_info.addr.entry[tdata->dest_info.cur_addr].addr;
	cur_addr_type = tdata->dest_info.addr.entry[tdata->dest_info.cur_addr].type;
	cur_addr_len = tdata->dest_info.addr.entry[tdata->dest_info.cur_addr].addr_len;

	
	status = pjsip_endpt_acquire_transport2(stateless_data->endpt, cur_addr_type, cur_addr, cur_addr_len, &tdata->tp_sel, tdata, &stateless_data->cur_transport);





	if (status != PJ_SUCCESS) {
	    sent = -status;
	    continue;
	}

	
	via = (pjsip_via_hdr*) pjsip_msg_find_hdr( tdata->msg, PJSIP_H_VIA, NULL);
	if (!via) {
	    
	    pj_assert(!"Via header not found!");
	    via = pjsip_via_hdr_create(tdata->pool);
	    pjsip_msg_insert_first_hdr(tdata->msg, (pjsip_hdr*)via);
	}

	if (tdata->msg->line.req.method.id == PJSIP_CANCEL_METHOD) {
	    if (via->sent_by.host.slen > 0) {
		
		need_update_via = PJ_FALSE;
	    }
	}

	if (via->branch_param.slen == 0) {
	    pj_str_t tmp;
	    via->branch_param.ptr = (char*)pj_pool_alloc(tdata->pool, PJSIP_MAX_BRANCH_LEN);
	    via->branch_param.slen = PJSIP_MAX_BRANCH_LEN;
	    pj_memcpy(via->branch_param.ptr, PJSIP_RFC3261_BRANCH_ID, PJSIP_RFC3261_BRANCH_LEN);
	    tmp.ptr = via->branch_param.ptr + PJSIP_RFC3261_BRANCH_LEN + 2;
	    *(tmp.ptr-2) = 80; *(tmp.ptr-1) = 106;
	    pj_generate_unique_string(&tmp);
	}

	if (need_update_via) {
	    via->transport = pj_str(stateless_data->cur_transport->type_name);

	    if (tdata->via_addr.host.slen > 0 && (!tdata->via_tp || tdata->via_tp == (void *)stateless_data->cur_transport))

	    {
		via->sent_by = tdata->via_addr;

		
		tdata->via_tp = stateless_data->cur_transport;
	    } else {
		via->sent_by = stateless_data->cur_transport->local_name;

		
		tdata->via_tp = stateless_data->cur_transport;
		tdata->via_addr = via->sent_by;
	    }
	    
	    via->rport_param = pjsip_cfg()->endpt.disable_rport ? -1 : 0;

	    
	    if (pjsip_cfg()->endpt.req_has_via_alias && tdata->msg->type == PJSIP_REQUEST_MSG)
	    {
		const pj_str_t ALIAS_STR = {"alias", 5};
		pjsip_param *alias_param;
		pj_bool_t is_datagram;

		alias_param = pjsip_param_find(&via->other_param, &ALIAS_STR);
		is_datagram = (stateless_data->cur_transport->flag &  PJSIP_TRANSPORT_DATAGRAM);
		if (!is_datagram && !alias_param) {
		    alias_param = PJ_POOL_ZALLOC_T(tdata->pool, pjsip_param);
		    alias_param->name = ALIAS_STR;
		    pj_list_push_back(&via->other_param, alias_param);
		} else if (is_datagram && alias_param) {
		    pj_list_erase(alias_param);
		}
	    }
	}

	pjsip_tx_data_invalidate_msg(tdata);

	
	status = pjsip_transport_send( stateless_data->cur_transport, tdata, cur_addr, cur_addr_len, stateless_data, &stateless_send_transport_cb);




	if (status == PJ_SUCCESS) {
	    
	    sent = tdata->buf.cur - tdata->buf.start;
	    stateless_send_transport_cb( stateless_data, tdata, sent );
	    return;
	} else if (status == PJ_EPENDING) {
	    
	    return;
	} else {
	    
	    sent = -status;
	    stateless_send_transport_cb( stateless_data, tdata, sent );
	    return;
	}
    }

}


static void  stateless_send_resolver_callback( pj_status_t status, void *token, const struct pjsip_server_addresses *addr)


{
    pjsip_send_state *stateless_data = (pjsip_send_state*) token;
    pjsip_tx_data *tdata = stateless_data->tdata;

    
    if (status != PJ_SUCCESS) {
	if (stateless_data->app_cb) {
	    pj_bool_t cont = PJ_FALSE;
	    (*stateless_data->app_cb)(stateless_data, -status, &cont);
	}
	pjsip_tx_data_dec_ref(tdata);
	return;
    }

    
    if (addr && addr != &tdata->dest_info.addr) {
	pj_memcpy( &tdata->dest_info.addr, addr,  sizeof(pjsip_server_addresses));
    }
    pj_assert(tdata->dest_info.addr.count != 0);

    
    if (pjsip_cfg()->endpt.disable_tcp_switch==0 && tdata->msg->type == PJSIP_REQUEST_MSG && tdata->dest_info.addr.count > 0 && tdata->dest_info.addr.entry[0].type == PJSIP_TRANSPORT_UDP)


    {
	int len;

	
	status = pjsip_tx_data_encode(tdata);
	if (status != PJ_SUCCESS) {
	    if (stateless_data->app_cb) {
		pj_bool_t cont = PJ_FALSE;
		(*stateless_data->app_cb)(stateless_data, -status, &cont);
	    }
	    pjsip_tx_data_dec_ref(tdata);
	    return;
	}

	
	len = (int)(tdata->buf.cur - tdata->buf.start);
	if (len >= PJSIP_UDP_SIZE_THRESHOLD) {
	    int i;
	    int count = tdata->dest_info.addr.count;

	    PJ_LOG(5,(THIS_FILE, "%s exceeds UDP size threshold (%u), " "sending with TCP", pjsip_tx_data_get_info(tdata), PJSIP_UDP_SIZE_THRESHOLD));



	    
	    if (count * 2 > PJSIP_MAX_RESOLVED_ADDRESSES)
		count = PJSIP_MAX_RESOLVED_ADDRESSES / 2;
	    for (i = 0; i < count; ++i) {
		pj_memcpy(&tdata->dest_info.addr.entry[i+count], &tdata->dest_info.addr.entry[i], sizeof(tdata->dest_info.addr.entry[0]));

		tdata->dest_info.addr.entry[i].type = PJSIP_TRANSPORT_TCP;
	    }
	    tdata->dest_info.addr.count = count * 2;
	}
    }

    
    stateless_send_transport_cb( stateless_data, tdata, -PJ_EPENDING);
}


PJ_DEF(pj_status_t) pjsip_endpt_send_request_stateless(pjsip_endpoint *endpt,  pjsip_tx_data *tdata, void *token, pjsip_send_callback cb)


{
    pjsip_host_info dest_info;
    pjsip_send_state *stateless_data;
    pj_status_t status;

    PJ_ASSERT_RETURN(endpt && tdata, PJ_EINVAL);

    
    status = pjsip_process_route_set(tdata, &dest_info);
    if (status != PJ_SUCCESS)
	return status;

    
    stateless_data = PJ_POOL_ZALLOC_T(tdata->pool, pjsip_send_state);
    stateless_data->token = token;
    stateless_data->endpt = endpt;
    stateless_data->tdata = tdata;
    stateless_data->app_cb = cb;

    
    if (tdata->dest_info.addr.count == 0) {
	
	pj_strdup(tdata->pool, &tdata->dest_info.name, &dest_info.addr.host);

	pjsip_endpt_resolve( endpt, tdata->pool, &dest_info, stateless_data, &stateless_send_resolver_callback);
    } else {
	PJ_LOG(5,(THIS_FILE, "%s: skipping target resolution because " "address is already set", pjsip_tx_data_get_info(tdata)));

	stateless_send_resolver_callback(PJ_SUCCESS, stateless_data, &tdata->dest_info.addr);
    }
    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjsip_endpt_send_raw( pjsip_endpoint *endpt, pjsip_transport_type_e tp_type, const pjsip_tpselector *sel, const void *raw_data, pj_size_t data_len, const pj_sockaddr_t *addr, int addr_len, void *token, pjsip_tp_send_callback cb)







{
    return pjsip_tpmgr_send_raw(pjsip_endpt_get_tpmgr(endpt), tp_type, sel, NULL, raw_data, data_len, addr, addr_len, token, cb);

}



struct send_raw_data {
    pjsip_endpoint	    *endpt;
    pjsip_tx_data	    *tdata;
    pjsip_tpselector	    *sel;
    void		    *app_token;
    pjsip_tp_send_callback   app_cb;
};



static void send_raw_resolver_callback( pj_status_t status, void *token, const pjsip_server_addresses *addr)

{
    struct send_raw_data *sraw_data = (struct send_raw_data*) token;

    if (status != PJ_SUCCESS) {
	if (sraw_data->app_cb) {
	    (*sraw_data->app_cb)(sraw_data->app_token, sraw_data->tdata, -status);
	}
    } else {
	pj_size_t data_len;

	pj_assert(addr->count != 0);

	
	pjsip_tx_data_add_ref(sraw_data->tdata);

	data_len = sraw_data->tdata->buf.cur - sraw_data->tdata->buf.start;
	status = pjsip_tpmgr_send_raw(pjsip_endpt_get_tpmgr(sraw_data->endpt), addr->entry[0].type, sraw_data->sel, sraw_data->tdata, sraw_data->tdata->buf.start, data_len, &addr->entry[0].addr, addr->entry[0].addr_len, sraw_data->app_token, sraw_data->app_cb);






	if (status == PJ_SUCCESS) {
	    (*sraw_data->app_cb)(sraw_data->app_token, sraw_data->tdata, data_len);
	} else if (status != PJ_EPENDING) {
	    (*sraw_data->app_cb)(sraw_data->app_token, sraw_data->tdata, -status);
	}
    }

    if (sraw_data->sel) {
	pjsip_tpselector_dec_ref(sraw_data->sel);
    }
    pjsip_tx_data_dec_ref(sraw_data->tdata);
}



PJ_DEF(pj_status_t) pjsip_endpt_send_raw_to_uri(pjsip_endpoint *endpt, const pj_str_t *p_dst_uri, const pjsip_tpselector *sel, const void *raw_data, pj_size_t data_len, void *token, pjsip_tp_send_callback cb)





{
    pjsip_tx_data *tdata;
    struct send_raw_data *sraw_data;
    pj_str_t dst_uri;
    pjsip_uri *uri;
    pjsip_host_info dest_info;
    pj_status_t status;

    
    status = pjsip_endpt_create_tdata(endpt, &tdata);
    if (status != PJ_SUCCESS)
	return status;

    pjsip_tx_data_add_ref(tdata);

    
    pj_strdup_with_null(tdata->pool, &dst_uri, p_dst_uri);

    
    uri = pjsip_parse_uri(tdata->pool, dst_uri.ptr, dst_uri.slen, 0);
    if (uri == NULL) {
	pjsip_tx_data_dec_ref(tdata);
	return PJSIP_EINVALIDURI;
    }

    
    status = pjsip_get_dest_info(uri, NULL, tdata->pool, &dest_info);
    if (status != PJ_SUCCESS) {
	pjsip_tx_data_dec_ref(tdata);
	return status;
    }

    
    tdata->buf.start = (char*) pj_pool_alloc(tdata->pool, data_len+1);
    tdata->buf.end = tdata->buf.start + data_len + 1;
    if (data_len)
	pj_memcpy(tdata->buf.start, raw_data, data_len);
    tdata->buf.cur = tdata->buf.start + data_len;

    
    sraw_data = PJ_POOL_ZALLOC_T(tdata->pool, struct send_raw_data);
    sraw_data->endpt = endpt;
    sraw_data->tdata = tdata;
    sraw_data->app_token = token;
    sraw_data->app_cb = cb;

    if (sel) {
	sraw_data->sel = PJ_POOL_ALLOC_T(tdata->pool, pjsip_tpselector);
	pj_memcpy(sraw_data->sel, sel, sizeof(pjsip_tpselector));
	pjsip_tpselector_add_ref(sraw_data->sel);
    }

    
    pj_strdup(tdata->pool, &tdata->dest_info.name, &dest_info.addr.host);

    
    pjsip_endpt_resolve( endpt, tdata->pool, &dest_info, sraw_data, &send_raw_resolver_callback);
    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjsip_get_response_addr( pj_pool_t *pool, pjsip_rx_data *rdata, pjsip_response_addr *res_addr )

{
    pjsip_transport *src_transport = rdata->tp_info.transport;

    
    PJ_ASSERT_RETURN(pool && rdata && res_addr, PJ_EINVAL);

    
    PJ_ASSERT_RETURN(rdata->msg_info.msg->type == PJSIP_REQUEST_MSG, PJ_EINVAL);

    
    pj_assert(rdata->msg_info.via->recvd_param.slen != 0);

    

    if (PJSIP_TRANSPORT_IS_RELIABLE(src_transport)) {
	
	res_addr->transport = rdata->tp_info.transport;
	pj_memcpy(&res_addr->addr, &rdata->pkt_info.src_addr, rdata->pkt_info.src_addr_len);
	res_addr->addr_len = rdata->pkt_info.src_addr_len;
	res_addr->dst_host.type=(pjsip_transport_type_e)src_transport->key.type;
	res_addr->dst_host.flag = src_transport->flag;
	pj_strdup( pool, &res_addr->dst_host.addr.host,  &rdata->msg_info.via->recvd_param);
	res_addr->dst_host.addr.port = rdata->msg_info.via->sent_by.port;
	if (res_addr->dst_host.addr.port == 0) {
	    res_addr->dst_host.addr.port =  pjsip_transport_get_default_port_for_type(res_addr->dst_host.type);
	}

    } else if (rdata->msg_info.via->maddr_param.slen) {
	
	res_addr->transport = NULL;
	res_addr->dst_host.type=(pjsip_transport_type_e)src_transport->key.type;
	res_addr->dst_host.flag = src_transport->flag;
	pj_strdup( pool, &res_addr->dst_host.addr.host,  &rdata->msg_info.via->maddr_param);
	res_addr->dst_host.addr.port = rdata->msg_info.via->sent_by.port;
	if (res_addr->dst_host.addr.port == 0)
	    res_addr->dst_host.addr.port = 5060;

    } else if (rdata->msg_info.via->rport_param >= 0) {
	
	res_addr->transport = rdata->tp_info.transport;
	pj_memcpy(&res_addr->addr, &rdata->pkt_info.src_addr, rdata->pkt_info.src_addr_len);
	res_addr->addr_len = rdata->pkt_info.src_addr_len;
	res_addr->dst_host.type=(pjsip_transport_type_e)src_transport->key.type;
	res_addr->dst_host.flag = src_transport->flag;
	pj_strdup( pool, &res_addr->dst_host.addr.host,  &rdata->msg_info.via->recvd_param);
	res_addr->dst_host.addr.port = rdata->msg_info.via->sent_by.port;
	if (res_addr->dst_host.addr.port == 0) {
	    res_addr->dst_host.addr.port =  pjsip_transport_get_default_port_for_type(res_addr->dst_host.type);
	}

    } else {
	res_addr->transport = NULL;
	res_addr->dst_host.type=(pjsip_transport_type_e)src_transport->key.type;
	res_addr->dst_host.flag = src_transport->flag;
	pj_strdup( pool, &res_addr->dst_host.addr.host,  &rdata->msg_info.via->recvd_param);
	res_addr->dst_host.addr.port = rdata->msg_info.via->sent_by.port;
	if (res_addr->dst_host.addr.port == 0) {
	    res_addr->dst_host.addr.port =  pjsip_transport_get_default_port_for_type(res_addr->dst_host.type);
	}
    }

    return PJ_SUCCESS;
}


static void send_response_transport_cb(void *token, pjsip_tx_data *tdata, pj_ssize_t sent)
{
    pjsip_send_state *send_state = (pjsip_send_state*) token;
    pj_bool_t cont = PJ_FALSE;

    
    if (send_state->app_cb)
	(*send_state->app_cb)(send_state, sent, &cont);

    
    pjsip_transport_dec_ref(send_state->cur_transport);

    
    pjsip_tx_data_dec_ref(tdata);
}


static void send_response_resolver_cb( pj_status_t status, void *token, const pjsip_server_addresses *addr )
{
    pjsip_send_state *send_state = (pjsip_send_state*) token;

    if (status != PJ_SUCCESS) {
	if (send_state->app_cb) {
	    pj_bool_t cont = PJ_FALSE;
	    (*send_state->app_cb)(send_state, -status, &cont);
	}
	pjsip_tx_data_dec_ref(send_state->tdata);
	return;
    }

    

    
    status = pjsip_endpt_acquire_transport2(send_state->endpt,  addr->entry[0].type, &addr->entry[0].addr, addr->entry[0].addr_len, &send_state->tdata->tp_sel, send_state->tdata, &send_state->cur_transport);





    if (status != PJ_SUCCESS) {
	if (send_state->app_cb) {
	    pj_bool_t cont = PJ_FALSE;
	    (*send_state->app_cb)(send_state, -status, &cont);
	}
	pjsip_tx_data_dec_ref(send_state->tdata);
	return;
    }

    
    pj_memcpy(&send_state->tdata->dest_info.addr, addr, sizeof(*addr));

    
    status = pjsip_transport_send( send_state->cur_transport,  send_state->tdata, &addr->entry[0].addr, addr->entry[0].addr_len, send_state, &send_response_transport_cb);




    if (status == PJ_SUCCESS) {
	pj_ssize_t sent = send_state->tdata->buf.cur -  send_state->tdata->buf.start;
	send_response_transport_cb(send_state, send_state->tdata, sent);

    } else if (status == PJ_EPENDING) {
	
    } else {
	send_response_transport_cb(send_state, send_state->tdata, -status);
    }
}


PJ_DEF(pj_status_t) pjsip_endpt_send_response( pjsip_endpoint *endpt, pjsip_response_addr *res_addr, pjsip_tx_data *tdata, void *token, pjsip_send_callback cb)



{
    
    pjsip_send_state *send_state;
    pj_status_t status;

    
    send_state = PJ_POOL_ZALLOC_T(tdata->pool, pjsip_send_state);
    send_state->endpt = endpt;
    send_state->tdata = tdata;
    send_state->token = token;
    send_state->app_cb = cb;

    if (res_addr->transport != NULL) {
	send_state->cur_transport = res_addr->transport;
	pjsip_transport_add_ref(send_state->cur_transport);

	status = pjsip_transport_send( send_state->cur_transport, tdata,  &res_addr->addr, res_addr->addr_len, send_state, &send_response_transport_cb );



	if (status == PJ_SUCCESS) {
	    pj_ssize_t sent = tdata->buf.cur - tdata->buf.start;
	    send_response_transport_cb(send_state, tdata, sent);
	    return PJ_SUCCESS;
	} else if (status == PJ_EPENDING) {
	    
	    return PJ_SUCCESS;
	} else {
	    pjsip_transport_dec_ref(send_state->cur_transport);
	    return status;
	}
    } else {
	
	pj_strdup(tdata->pool, &tdata->dest_info.name,  &res_addr->dst_host.addr.host);

	pjsip_endpt_resolve(endpt, tdata->pool, &res_addr->dst_host,  send_state, &send_response_resolver_cb);
	return PJ_SUCCESS;
    }
}


PJ_DEF(pj_status_t) pjsip_endpt_send_response2( pjsip_endpoint *endpt, pjsip_rx_data *rdata, pjsip_tx_data *tdata, void *token, pjsip_send_callback cb)



{
    pjsip_response_addr res_addr;
    pj_status_t status;

    status = pjsip_get_response_addr(tdata->pool, rdata, &res_addr);
    if (status != PJ_SUCCESS) {
	pjsip_tx_data_dec_ref(tdata);
	return PJ_SUCCESS;
    }

    status = pjsip_endpt_send_response(endpt, &res_addr, tdata, token, cb);
    return status;
}



PJ_DEF(pj_status_t) pjsip_endpt_respond_stateless( pjsip_endpoint *endpt, pjsip_rx_data *rdata, int st_code, const pj_str_t *st_text, const pjsip_hdr *hdr_list, const pjsip_msg_body *body)




{
    pj_status_t status;
    pjsip_response_addr res_addr;
    pjsip_tx_data *tdata;

    
    PJ_ASSERT_RETURN(endpt && rdata, PJ_EINVAL);
    PJ_ASSERT_RETURN(rdata->msg_info.msg->type == PJSIP_REQUEST_MSG, PJSIP_ENOTREQUESTMSG);

    
    PJ_ASSERT_RETURN(pjsip_rdata_get_tsx(rdata)==NULL, PJ_EINVALIDOP);

    
    status = pjsip_endpt_create_response( endpt, rdata, st_code, st_text,  &tdata);
    if (status != PJ_SUCCESS)
	return status;

    
    if (hdr_list) {
	const pjsip_hdr *hdr = hdr_list->next;
	while (hdr != hdr_list) {
	    pjsip_msg_add_hdr(tdata->msg,  (pjsip_hdr*) pjsip_hdr_clone(tdata->pool, hdr) );
	    hdr = hdr->next;
	}
    }

    
    if (body) {
	tdata->msg->body = pjsip_msg_body_clone( tdata->pool, body );
	if (tdata->msg->body == NULL) {
	    pjsip_tx_data_dec_ref(tdata);
	    return status;
	}
    }

    
    status = pjsip_get_response_addr( tdata->pool, rdata, &res_addr );
    if (status != PJ_SUCCESS) {
	pjsip_tx_data_dec_ref(tdata);
	return status;
    }

    
    status = pjsip_endpt_send_response( endpt, &res_addr, tdata, NULL, NULL );
    if (status != PJ_SUCCESS) {
	pjsip_tx_data_dec_ref(tdata);
	return status;
    }

    return PJ_SUCCESS;
}



PJ_DEF(const char *) pjsip_event_str(pjsip_event_id_e e)
{
    return event_str[e];
}

