


























static const char *addr_string(const pj_sockaddr_t *addr)
{
    static char str[PJ_INET6_ADDRSTRLEN];
    pj_inet_ntop(((const pj_sockaddr*)addr)->addr.sa_family,  pj_sockaddr_get_addr(addr), str, sizeof(str));

    return str;
}
static const char* print_tpsel_info(const pjsip_tpselector *sel)
{
    static char tpsel_info_buf[80];
    if (!sel) return "(null)";
    if (sel->type==PJSIP_TPSELECTOR_LISTENER)
	pj_ansi_snprintf(tpsel_info_buf, sizeof(tpsel_info_buf), "listener[%s], reuse=%d", sel->u.listener->obj_name, !sel->disable_connection_reuse);

    else if (sel->type==PJSIP_TPSELECTOR_TRANSPORT)
	pj_ansi_snprintf(tpsel_info_buf, sizeof(tpsel_info_buf), "transport[%s], reuse=%d", sel->u.transport->info, !sel->disable_connection_reuse);

    else pj_ansi_snprintf(tpsel_info_buf, sizeof(tpsel_info_buf), "unknown[%p], reuse=%d", sel->u.ptr, !sel->disable_connection_reuse);


    return tpsel_info_buf;
}











    #define TPMGR_POOL_INC_SIZE	64








static pj_status_t mod_on_tx_msg(pjsip_tx_data *tdata);


static pjsip_module mod_msg_print =  {
    NULL, NULL,				 { "mod-msg-print", 13}, -1, PJSIP_MOD_PRIORITY_TRANSPORT_LAYER, NULL, NULL, NULL, NULL, NULL, NULL, &mod_on_tx_msg, &mod_on_tx_msg, NULL, };














typedef struct transport {
    PJ_DECL_LIST_MEMBER(struct transport);
    pj_hash_entry_buf tp_buf;
    pjsip_transport *tp;
} transport;


struct pjsip_tpmgr  {
    pj_hash_table_t *table;
    pj_lock_t	    *lock;
    pjsip_endpoint  *endpt;
    pjsip_tpfactory  factory_list;
    pj_pool_t	    *pool;

    pj_atomic_t	    *tdata_counter;

    void           (*on_rx_msg)(pjsip_endpoint*, pj_status_t, pjsip_rx_data*);
    pj_status_t	   (*on_tx_msg)(pjsip_endpoint*, pjsip_tx_data*);
    pjsip_tp_state_callback tp_state_cb;
    pjsip_tp_on_rx_dropped_cb tp_drop_data_cb;

    
    pjsip_tx_data    tdata_list;

    
    transport	     tp_entry_freelist;
};



typedef struct tp_state_listener {
    PJ_DECL_LIST_MEMBER(struct tp_state_listener);

    pjsip_tp_state_callback  cb;
    void *user_data;
} tp_state_listener;



typedef struct transport_data {
    
    tp_state_listener	    st_listeners;
    tp_state_listener	    st_listeners_empty;
} transport_data;





static struct transport_names_t {
    pjsip_transport_type_e type;	    
    pj_uint16_t		   port;	    
    pj_str_t		   name;	    
    const char		  *description;	    
    unsigned		   flag;	    
    char		   name_buf[16];    
} transport_names[16] =  {
    { 
	PJSIP_TRANSPORT_UNSPECIFIED,  0, {"Unspecified", 11}, "Unspecified", 0 }, {





	PJSIP_TRANSPORT_UDP,  5060, {"UDP", 3}, "UDP transport", PJSIP_TRANSPORT_DATAGRAM }, {





	PJSIP_TRANSPORT_TCP,  5060, {"TCP", 3}, "TCP transport", PJSIP_TRANSPORT_RELIABLE }, {





	PJSIP_TRANSPORT_TLS,  5061, {"TLS", 3}, "TLS transport", PJSIP_TRANSPORT_RELIABLE | PJSIP_TRANSPORT_SECURE }, {





	PJSIP_TRANSPORT_DTLS, 5061, {"DTLS", 4}, "DTLS transport", PJSIP_TRANSPORT_SECURE }, {





	PJSIP_TRANSPORT_SCTP,  5060, {"SCTP", 4}, "SCTP transport", PJSIP_TRANSPORT_RELIABLE }, {





	PJSIP_TRANSPORT_LOOP,  15060, {"LOOP", 4}, "Loopback transport", PJSIP_TRANSPORT_RELIABLE }, {





	PJSIP_TRANSPORT_LOOP_DGRAM,  15060, {"LOOP-DGRAM", 10}, "Loopback datagram transport", PJSIP_TRANSPORT_DATAGRAM }, {





	PJSIP_TRANSPORT_UDP6,  5060, {"UDP", 3}, "UDP IPv6 transport", PJSIP_TRANSPORT_DATAGRAM }, {





	PJSIP_TRANSPORT_TCP6,  5060, {"TCP", 3}, "TCP IPv6 transport", PJSIP_TRANSPORT_RELIABLE }, {





	PJSIP_TRANSPORT_TLS6, 5061, {"TLS", 3}, "TLS IPv6 transport", PJSIP_TRANSPORT_RELIABLE | PJSIP_TRANSPORT_SECURE }, {





	PJSIP_TRANSPORT_DTLS6, 5061, {"DTLS", 4}, "DTLS IPv6 transport", PJSIP_TRANSPORT_SECURE }, };






static void tp_state_callback(pjsip_transport *tp, pjsip_transport_state state, const pjsip_transport_state_info *info);



static struct transport_names_t *get_tpname(pjsip_transport_type_e type)
{
    unsigned i;
    for (i=0; i<PJ_ARRAY_SIZE(transport_names); ++i) {
	if (transport_names[i].type == type)
	    return &transport_names[i];
    }
    pj_assert(!"Invalid transport type!");
    return NULL;
}




PJ_DEF(pj_status_t) pjsip_transport_register_type( unsigned tp_flag, const char *tp_name, int def_port, int *p_tp_type)


{
    unsigned i;
    pjsip_transport_type_e parent = 0;

    PJ_ASSERT_RETURN(tp_flag && tp_name && def_port, PJ_EINVAL);
    PJ_ASSERT_RETURN(pj_ansi_strlen(tp_name) <  PJ_ARRAY_SIZE(transport_names[0].name_buf), PJ_ENAMETOOLONG);


    for (i=1; i<PJ_ARRAY_SIZE(transport_names); ++i) {
        if (tp_flag & PJSIP_TRANSPORT_IPV6 &&  pj_stricmp2(&transport_names[i].name, tp_name) == 0)
        {
	    parent = transport_names[i].type;
        }
	if (transport_names[i].type == 0)
	    break;
    }

    if (i == PJ_ARRAY_SIZE(transport_names))
	return PJ_ETOOMANY;

    if (tp_flag & PJSIP_TRANSPORT_IPV6 && parent) {
        transport_names[i].type = parent | PJSIP_TRANSPORT_IPV6;
    } else {
        transport_names[i].type = (pjsip_transport_type_e)i;
    }

    transport_names[i].port = (pj_uint16_t)def_port;
    pj_ansi_strcpy(transport_names[i].name_buf, tp_name);
    transport_names[i].name = pj_str(transport_names[i].name_buf);
    transport_names[i].flag = tp_flag;

    if (p_tp_type)
	*p_tp_type = transport_names[i].type;

    return PJ_SUCCESS;
}



PJ_DEF(pjsip_transport_type_e) pjsip_transport_get_type_from_name(const pj_str_t *name)
{
    unsigned i;

    if (name->slen == 0)
	return PJSIP_TRANSPORT_UNSPECIFIED;

    
    for (i=0; i<PJ_ARRAY_SIZE(transport_names); ++i) {
	if (pj_stricmp(name, &transport_names[i].name) == 0) {
	    return transport_names[i].type;
	}
    }

    pj_assert(!"Invalid transport name");
    return PJSIP_TRANSPORT_UNSPECIFIED;
}



PJ_DEF(pjsip_transport_type_e) pjsip_transport_get_type_from_flag(unsigned flag)
{
    unsigned i;

    
    for (i=0; i<PJ_ARRAY_SIZE(transport_names); ++i) {
	if (transport_names[i].flag == flag) {
	    return transport_names[i].type;
	}
    }

    pj_assert(!"Invalid transport type");
    return PJSIP_TRANSPORT_UNSPECIFIED;
}


PJ_DEF(int) pjsip_transport_type_get_af(pjsip_transport_type_e type)
{
    if (type & PJSIP_TRANSPORT_IPV6)
	return pj_AF_INET6();
    else return pj_AF_INET();
}

PJ_DEF(unsigned) pjsip_transport_get_flag_from_type(pjsip_transport_type_e type)
{
    
    return get_tpname(type)->flag;
}


PJ_DEF(int) pjsip_transport_get_default_port_for_type(pjsip_transport_type_e type)
{
    
    return get_tpname(type)->port;
}


PJ_DEF(const char*) pjsip_transport_get_type_name(pjsip_transport_type_e type)
{
    
    return get_tpname(type)->name.ptr;
}


PJ_DEF(const char*) pjsip_transport_get_type_desc(pjsip_transport_type_e type)
{
    
    return get_tpname(type)->description;
}





PJ_DEF(void) pjsip_tpselector_add_ref(pjsip_tpselector *sel)
{
    if (sel->type == PJSIP_TPSELECTOR_TRANSPORT && sel->u.transport != NULL)
	pjsip_transport_add_ref(sel->u.transport);
    else if (sel->type == PJSIP_TPSELECTOR_LISTENER && sel->u.listener != NULL)
	; 
}



PJ_DEF(void) pjsip_tpselector_dec_ref(pjsip_tpselector *sel)
{
    if (sel->type == PJSIP_TPSELECTOR_TRANSPORT && sel->u.transport != NULL)
	pjsip_transport_dec_ref(sel->u.transport);
    else if (sel->type == PJSIP_TPSELECTOR_LISTENER && sel->u.listener != NULL)
	; 
}





PJ_DEF(pj_status_t) pjsip_tx_data_create( pjsip_tpmgr *mgr, pjsip_tx_data **p_tdata )
{
    pj_pool_t *pool;
    pjsip_tx_data *tdata;
    pj_status_t status;

    PJ_ASSERT_RETURN(mgr && p_tdata, PJ_EINVAL);

    pool = pjsip_endpt_create_pool( mgr->endpt, "tdta%p", PJSIP_POOL_LEN_TDATA, PJSIP_POOL_INC_TDATA );

    if (!pool)
	return PJ_ENOMEM;

    tdata = PJ_POOL_ZALLOC_T(pool, pjsip_tx_data);
    tdata->pool = pool;
    tdata->mgr = mgr;
    pj_ansi_snprintf(tdata->obj_name, sizeof(tdata->obj_name), "tdta%p", tdata);
    pj_memcpy(pool->obj_name, tdata->obj_name, sizeof(pool->obj_name));

    status = pj_atomic_create(tdata->pool, 0, &tdata->ref_cnt);
    if (status != PJ_SUCCESS) {
	pjsip_endpt_release_pool( mgr->endpt, tdata->pool );
	return status;
    }
    
    
    status = pj_lock_create_null_mutex(pool, "tdta%p", &tdata->lock);
    if (status != PJ_SUCCESS) {
	pjsip_endpt_release_pool( mgr->endpt, tdata->pool );
	return status;
    }

    pj_ioqueue_op_key_init(&tdata->op_key.key, sizeof(tdata->op_key.key));
    pj_list_init(tdata);


    
    pj_lock_acquire(mgr->lock);
    pj_list_push_back(&mgr->tdata_list, tdata);
    pj_lock_release(mgr->lock);



    pj_atomic_inc( tdata->mgr->tdata_counter );


    *p_tdata = tdata;
    return PJ_SUCCESS;
}



PJ_DEF(void) pjsip_tx_data_add_ref( pjsip_tx_data *tdata )
{
    pj_atomic_inc(tdata->ref_cnt);
}

static void tx_data_destroy(pjsip_tx_data *tdata)
{
    PJ_LOG(5,(tdata->obj_name, "Destroying txdata %s", pjsip_tx_data_get_info(tdata)));
    pjsip_tpselector_dec_ref(&tdata->tp_sel);

    pj_atomic_dec( tdata->mgr->tdata_counter );



    
    pj_lock_acquire(tdata->mgr->lock);
    pj_list_erase(tdata);
    pj_lock_release(tdata->mgr->lock);


    pj_atomic_destroy( tdata->ref_cnt );
    pj_lock_destroy( tdata->lock );
    pjsip_endpt_release_pool( tdata->mgr->endpt, tdata->pool );
}


PJ_DEF(pj_status_t) pjsip_tx_data_dec_ref( pjsip_tx_data *tdata )
{
    pj_atomic_value_t ref_cnt;
    
    PJ_ASSERT_RETURN(tdata && tdata->ref_cnt, PJ_EINVAL);

    ref_cnt = pj_atomic_dec_and_get(tdata->ref_cnt);
    pj_assert( ref_cnt >= 0);
    if (ref_cnt == 0) {
	tx_data_destroy(tdata);
	return PJSIP_EBUFDESTROYED;
    } else {
	return PJ_SUCCESS;
    }
}


PJ_DEF(void) pjsip_tx_data_invalidate_msg( pjsip_tx_data *tdata )
{
    tdata->buf.cur = tdata->buf.start;
    tdata->info = NULL;
}


PJ_DEF(pj_status_t) pjsip_tx_data_encode(pjsip_tx_data *tdata)
{
    
    if (tdata->buf.start == NULL) {
	PJ_USE_EXCEPTION;

	PJ_TRY {
	    tdata->buf.start = (char*) 
			       pj_pool_alloc(tdata->pool, PJSIP_MAX_PKT_LEN);
	}
	PJ_CATCH_ANY {
	    return PJ_ENOMEM;
	}
	PJ_END  tdata->buf.cur = tdata->buf.start;

	tdata->buf.end = tdata->buf.start + PJSIP_MAX_PKT_LEN;
    }

    
    if (!pjsip_tx_data_is_valid(tdata)) {
	pj_ssize_t size;

	size = pjsip_msg_print( tdata->msg, tdata->buf.start,  tdata->buf.end - tdata->buf.start);
	if (size < 0) {
	    return PJSIP_EMSGTOOLONG;
	}
	pj_assert(size != 0);
	tdata->buf.cur[size] = '\0';
	tdata->buf.cur += size;
    }

    return PJ_SUCCESS;
}

PJ_DEF(pj_bool_t) pjsip_tx_data_is_valid( pjsip_tx_data *tdata )
{
    return tdata->buf.cur != tdata->buf.start;
}

static char *get_msg_info(pj_pool_t *pool, const char *obj_name, const pjsip_msg *msg)
{
    char info_buf[128], *info;
    const pjsip_cseq_hdr *cseq;
    int len;

    cseq = (const pjsip_cseq_hdr*) pjsip_msg_find_hdr(msg, PJSIP_H_CSEQ, NULL);
    PJ_ASSERT_RETURN(cseq != NULL, "INVALID MSG");

    if (msg->type == PJSIP_REQUEST_MSG) {
	len = pj_ansi_snprintf(info_buf, sizeof(info_buf),  "Request msg %.*s/cseq=%d (%s)", (int)msg->line.req.method.name.slen, msg->line.req.method.name.ptr, cseq->cseq, obj_name);



    } else {
	len = pj_ansi_snprintf(info_buf, sizeof(info_buf), "Response msg %d/%.*s/cseq=%d (%s)", msg->line.status.code, (int)cseq->method.name.slen, cseq->method.name.ptr, cseq->cseq, obj_name);




    }

    if (len < 1 || len >= (int)sizeof(info_buf)) {
	return (char*)obj_name;
    }

    info = (char*) pj_pool_alloc(pool, len+1);
    pj_memcpy(info, info_buf, len+1);

    return info;
}

PJ_DEF(char*) pjsip_tx_data_get_info( pjsip_tx_data *tdata )
{
    PJ_ASSERT_RETURN(tdata, "NULL");

    
    if (tdata->info)
	return tdata->info;

    if (tdata->msg==NULL)
	return "NULL";

    pj_lock_acquire(tdata->lock);
    tdata->info = get_msg_info(tdata->pool, tdata->obj_name, tdata->msg);
    pj_lock_release(tdata->lock);

    return tdata->info;
}

PJ_DEF(pj_status_t) pjsip_tx_data_set_transport(pjsip_tx_data *tdata, const pjsip_tpselector *sel)
{
    PJ_ASSERT_RETURN(tdata && sel, PJ_EINVAL);

    pj_lock_acquire(tdata->lock);

    pjsip_tpselector_dec_ref(&tdata->tp_sel);

    pj_memcpy(&tdata->tp_sel, sel, sizeof(*sel));
    pjsip_tpselector_add_ref(&tdata->tp_sel);

    pj_lock_release(tdata->lock);

    return PJ_SUCCESS;
}


PJ_DEF(pj_status_t) pjsip_tx_data_clone(const pjsip_tx_data *src, unsigned flags, pjsip_tx_data ** p_tdata)

{
    pjsip_tx_data *dst;
    const pjsip_hdr *hsrc;
    pjsip_msg *msg;
    pj_status_t status;

    PJ_UNUSED_ARG(flags);

    status = pjsip_tx_data_create(src->mgr, p_tdata);
    if (status != PJ_SUCCESS)
	return status;

    dst = *p_tdata;

    msg = pjsip_msg_create(dst->pool, PJSIP_RESPONSE_MSG);
    dst->msg = msg;
    pjsip_tx_data_add_ref(dst);

    
    msg->line.status.code = src->msg->line.status.code;
    pj_strdup(dst->pool, &msg->line.status.reason, &src->msg->line.status.reason);

    
    hsrc = src->msg->hdr.next;
    while (hsrc != &src->msg->hdr) {
	pjsip_hdr *h = (pjsip_hdr*) pjsip_hdr_clone(dst->pool, hsrc);
	pjsip_msg_add_hdr(msg, h);
	hsrc = hsrc->next;
    }

    
    if (src->msg->body)
	msg->body = pjsip_msg_body_clone(dst->pool, src->msg->body);

    
    

    PJ_LOG(5,(THIS_FILE, "Tx data %s cloned", pjsip_tx_data_get_info(dst)));


    return PJ_SUCCESS;
}

PJ_DEF(char*) pjsip_rx_data_get_info(pjsip_rx_data *rdata)
{
    char obj_name[PJ_MAX_OBJ_NAME];

    PJ_ASSERT_RETURN(rdata->msg_info.msg, "INVALID MSG");

    if (rdata->msg_info.info)
	return rdata->msg_info.info;

    pj_ansi_strcpy(obj_name, "rdata");
    pj_ansi_snprintf(obj_name+5, sizeof(obj_name)-5, "%p", rdata);

    rdata->msg_info.info = get_msg_info(rdata->tp_info.pool, obj_name, rdata->msg_info.msg);
    return rdata->msg_info.info;
}


PJ_DEF(pj_status_t) pjsip_rx_data_clone( const pjsip_rx_data *src, unsigned flags, pjsip_rx_data **p_rdata)

{
    pj_pool_t *pool;
    pjsip_rx_data *dst;
    pjsip_hdr *hdr;

    PJ_ASSERT_RETURN(src && flags==0 && p_rdata, PJ_EINVAL);

    pool = pj_pool_create(src->tp_info.pool->factory, "rtd%p", PJSIP_POOL_RDATA_LEN, PJSIP_POOL_RDATA_INC, NULL);



    if (!pool)
	return PJ_ENOMEM;

    dst = PJ_POOL_ZALLOC_T(pool, pjsip_rx_data);

    
    dst->tp_info.pool = pool;
    dst->tp_info.transport = (pjsip_transport*)src->tp_info.transport;

    
    pj_memcpy(&dst->pkt_info, &src->pkt_info, sizeof(src->pkt_info));

    
    dst->msg_info.msg_buf = dst->pkt_info.packet + (src->msg_info.msg_buf - src->pkt_info.packet);
    dst->msg_info.len = src->msg_info.len;
    dst->msg_info.msg = pjsip_msg_clone(pool, src->msg_info.msg);
    pj_list_init(&dst->msg_info.parse_err);








    hdr = dst->msg_info.msg->hdr.next;
    while (hdr != &dst->msg_info.msg->hdr) {
	switch (hdr->type) {
	GET_MSG_HDR(CALL_ID, cid);
	GET_MSG_HDR(FROM, from);
	GET_MSG_HDR(TO, to);
	GET_MSG_HDR(VIA, via);
	GET_MSG_HDR(CSEQ, cseq);
	GET_MSG_HDR(MAX_FORWARDS, max_fwd);
	GET_MSG_HDR(ROUTE, route);
	GET_MSG_HDR2(RECORD_ROUTE, rr, record_route);
	GET_MSG_HDR(CONTENT_TYPE, ctype);
	GET_MSG_HDR(CONTENT_LENGTH, clen);
	GET_MSG_HDR(REQUIRE, require);
	GET_MSG_HDR(SUPPORTED, supported);
	default:
	    break;
	}
	hdr = hdr->next;
    }




    *p_rdata = dst;

    
    return pjsip_transport_add_ref(dst->tp_info.transport);
}


PJ_DEF(pj_status_t) pjsip_rx_data_free_cloned(pjsip_rx_data *rdata)
{
    PJ_ASSERT_RETURN(rdata, PJ_EINVAL);

    pjsip_transport_dec_ref(rdata->tp_info.transport);
    pj_pool_release(rdata->tp_info.pool);

    return PJ_SUCCESS;
}






static void transport_send_callback(pjsip_transport *transport, void *token, pj_ssize_t size)

{
    pjsip_tx_data *tdata = (pjsip_tx_data*) token;

    PJ_UNUSED_ARG(transport);

    
    tdata->is_pending = 0;

    
    if (tdata->cb) {
	(*tdata->cb)(tdata->token, tdata, size);
    }

    
    pjsip_tx_data_dec_ref(tdata);
}


static pj_status_t mod_on_tx_msg(pjsip_tx_data *tdata)
{
    return pjsip_tx_data_encode(tdata);
}


PJ_DEF(pj_status_t) pjsip_transport_send(  pjsip_transport *tr,  pjsip_tx_data *tdata, const pj_sockaddr_t *addr, int addr_len, void *token, pjsip_tp_send_callback cb)




{
    pj_status_t status;

    PJ_ASSERT_RETURN(tr && tdata && addr, PJ_EINVAL);

    
    if (tdata->is_pending) {
	pj_assert(!"Invalid operation step!");
	PJ_LOG(2,(THIS_FILE, "Unable to send %s: message is pending",  pjsip_tx_data_get_info(tdata)));
	return PJSIP_EPENDINGTX;
    }

    
    pjsip_transport_add_ref(tr);

    
    tdata->tp_info.transport = tr;
    pj_memcpy(&tdata->tp_info.dst_addr, addr, addr_len);
    tdata->tp_info.dst_addr_len = addr_len;

    pj_inet_ntop(((pj_sockaddr*)addr)->addr.sa_family, pj_sockaddr_get_addr(addr), tdata->tp_info.dst_name, sizeof(tdata->tp_info.dst_name));


    tdata->tp_info.dst_port = pj_sockaddr_get_port(addr);

    
    if (tr->tpmgr->on_tx_msg) {
	status = (*tr->tpmgr->on_tx_msg)(tr->endpt, tdata);
	if (status != PJ_SUCCESS) {
	    pjsip_transport_dec_ref(tr);
	    return status;
	}
    }

    
    tdata->token = token;
    tdata->cb = cb;

    
    pjsip_tx_data_add_ref(tdata);

    
    tdata->is_pending = 1;

    
    status = (*tr->send_msg)(tr, tdata,  addr, addr_len, (void*)tdata,  &transport_send_callback);

    if (status != PJ_EPENDING) {
	tdata->is_pending = 0;
	pjsip_tx_data_dec_ref(tdata);
    }

    pjsip_transport_dec_ref(tr);
    return status;
}



static void send_raw_callback(pjsip_transport *transport, void *token, pj_ssize_t size)

{
    pjsip_tx_data *tdata = (pjsip_tx_data*) token;

    
    tdata->is_pending = 0;

    
    if (tdata->cb) {
	(*tdata->cb)(tdata->token, tdata, size);
    }

    
    pjsip_tx_data_dec_ref(tdata);

    
    pjsip_transport_dec_ref(transport);
}



PJ_DEF(pj_status_t) pjsip_tpmgr_send_raw(pjsip_tpmgr *mgr, pjsip_transport_type_e tp_type, const pjsip_tpselector *sel, pjsip_tx_data *tdata, const void *raw_data, pj_size_t data_len, const pj_sockaddr_t *addr, int addr_len, void *token, pjsip_tp_send_callback cb)








{
    pjsip_transport *tr;
    pj_status_t status;
 
    
    status = pjsip_tpmgr_acquire_transport(mgr, tp_type, addr, addr_len, sel, &tr);
    if (status != PJ_SUCCESS)
	return status;

    
    if (tdata == NULL) {
	status = pjsip_endpt_create_tdata(tr->endpt, &tdata);
	if (status != PJ_SUCCESS) {
	    pjsip_transport_dec_ref(tr);
	    return status;
	}

	tdata->info = "raw";

	
	pjsip_tx_data_add_ref(tdata);
    }

    
    if (tdata->buf.start == NULL || (tdata->buf.end - tdata->buf.start) < (int)data_len)
    {
	
	tdata->buf.start = (char*) pj_pool_alloc(tdata->pool, data_len+1);
	tdata->buf.end = tdata->buf.start + data_len + 1;
    }
 
    
    if (data_len) {
	pj_memcpy(tdata->buf.start, raw_data, data_len);
    }
    tdata->buf.cur = tdata->buf.start + data_len;
 
    
    tdata->token = token;
    tdata->cb = cb;

    
    tdata->is_pending = 1;

    
    status = tr->send_msg(tr, tdata, addr, addr_len, tdata, &send_raw_callback);
 
    if (status != PJ_EPENDING) {
	
	pjsip_tx_data_dec_ref(tdata);
	pjsip_transport_dec_ref(tr);
    }

    return status;
}


static void transport_idle_callback(pj_timer_heap_t *timer_heap, struct pj_timer_entry *entry)
{
    pjsip_transport *tp = (pjsip_transport*) entry->user_data;
    pj_assert(tp != NULL);

    PJ_UNUSED_ARG(timer_heap);

    if (entry->id == PJ_FALSE)
	return;

    entry->id = PJ_FALSE;

    
    pj_lock_acquire(tp->tpmgr->lock);
    if (pj_atomic_get(tp->ref_cnt) == 0) {
	tp->is_destroying = PJ_TRUE;
    } else {
	pj_lock_release(tp->tpmgr->lock);
	return;
    }
    pj_lock_release(tp->tpmgr->lock);

    pjsip_transport_destroy(tp);
}


static pj_bool_t is_transport_valid(pjsip_transport *tp, pjsip_tpmgr *tpmgr, const pjsip_transport_key *key, int key_len)

{
    transport *tp_entry;

    tp_entry = (transport *)pj_hash_get(tpmgr->table, key, key_len, NULL);
    if (tp_entry != NULL) {

	transport *tp_iter = tp_entry;
	do {
	    if (tp_iter->tp == tp) {
		return PJ_TRUE;
	    }
	    tp_iter = tp_iter->next;
	} while (tp_iter != tp_entry);
    }

    return PJ_FALSE;
}


PJ_DEF(pj_status_t) pjsip_transport_add_ref( pjsip_transport *tp )
{
    pjsip_tpmgr *tpmgr;
    pjsip_transport_key key;
    int key_len;

    PJ_ASSERT_RETURN(tp != NULL, PJ_EINVAL);

    
    if (tp->grp_lock)
	pj_grp_lock_add_ref(tp->grp_lock);

    
    tpmgr = tp->tpmgr;
    key_len = sizeof(tp->key.type) + tp->addr_len;
    pj_memcpy(&key, &tp->key, key_len);

    if (pj_atomic_inc_and_get(tp->ref_cnt) == 1) {
	pj_lock_acquire(tpmgr->lock);
	
	if (is_transport_valid(tp, tpmgr, &key, key_len) && pj_atomic_get(tp->ref_cnt) == 1)
	{
	    if (tp->idle_timer.id != PJ_FALSE) {
		tp->idle_timer.id = PJ_FALSE;
		pjsip_endpt_cancel_timer(tp->tpmgr->endpt, &tp->idle_timer);
	    }
	}
	pj_lock_release(tpmgr->lock);
    }

    return PJ_SUCCESS;
}


PJ_DEF(pj_status_t) pjsip_transport_dec_ref( pjsip_transport *tp )
{
    pjsip_tpmgr *tpmgr;
    pjsip_transport_key key;
    int key_len;

    PJ_ASSERT_RETURN(tp != NULL, PJ_EINVAL);
    pj_assert(pj_atomic_get(tp->ref_cnt) > 0);

    
    tpmgr = tp->tpmgr;
    key_len = sizeof(tp->key.type) + tp->addr_len;
    pj_memcpy(&key, &tp->key, key_len);

    if (pj_atomic_dec_and_get(tp->ref_cnt) == 0) {
	pj_lock_acquire(tpmgr->lock);
	
	if (is_transport_valid(tp, tpmgr, &key, key_len) && !tp->is_destroying && pj_atomic_get(tp->ref_cnt) == 0)
	{
	    pj_time_val delay;
	    
	    
	    if (tp->is_shutdown) {
		delay.sec = delay.msec = 0;
	    } else {
		delay.sec = (tp->dir==PJSIP_TP_DIR_OUTGOING) ? PJSIP_TRANSPORT_IDLE_TIME :
				PJSIP_TRANSPORT_SERVER_IDLE_TIME;
		delay.msec = 0;
	    }

	    
	    if (pj_timer_entry_running(&tp->idle_timer))
		pjsip_endpt_cancel_timer(tp->tpmgr->endpt, &tp->idle_timer);

	    pjsip_endpt_schedule_timer_w_grp_lock(tp->tpmgr->endpt, &tp->idle_timer, &delay, PJ_TRUE, tp->grp_lock);



	}
	pj_lock_release(tpmgr->lock);
    }

    
    if (tp->grp_lock) {
	pj_grp_lock_dec_ref(tp->grp_lock);
    }

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjsip_transport_register( pjsip_tpmgr *mgr, pjsip_transport *tp )
{
    int key_len;
    pj_uint32_t hval;
    transport *tp_ref = NULL;
    transport *tp_add = NULL;

    
    tp->tpmgr = mgr;
    pj_bzero(&tp->idle_timer, sizeof(tp->idle_timer));
    tp->idle_timer.user_data = tp;
    tp->idle_timer.cb = &transport_idle_callback;

    
    key_len = sizeof(tp->key.type) + tp->addr_len;
    pj_lock_acquire(mgr->lock);

    hval = 0;
    tp_ref = (transport *)pj_hash_get(mgr->table, &tp->key, key_len, &hval);

    
    if (pj_list_empty(&mgr->tp_entry_freelist)) {
	unsigned i = 0;

	TRACE_((THIS_FILE, "Transport list is full, allocate new entry"));
	
	for (; i < PJSIP_TRANSPORT_ENTRY_ALLOC_CNT; ++i) {
	    tp_add = PJ_POOL_ZALLOC_T(mgr->pool, transport);
	    if (!tp_add)
		return PJ_ENOMEM;
	    pj_list_init(tp_add);
	    pj_list_push_back(&mgr->tp_entry_freelist, tp_add);
	}
    }
    tp_add = mgr->tp_entry_freelist.next;
    tp_add->tp = tp;
    pj_list_erase(tp_add);

    if (tp_ref) {
	
	pj_list_push_back(tp_ref, tp_add);
	TRACE_((THIS_FILE, "Remote address already registered, " "appended the transport to the list"));
    } else {
	
	pj_hash_set_np(mgr->table, &tp->key, key_len, hval, tp_add->tp_buf, tp_add);
	TRACE_((THIS_FILE, "Remote address not registered, " "added the transport to the hash"));
    }

    
    if (tp->grp_lock)
	pj_grp_lock_add_ref(tp->grp_lock);

    pj_lock_release(mgr->lock);

    TRACE_((THIS_FILE, "Transport %s registered: type=%s, remote=%s:%d", tp->obj_name, pjsip_transport_get_type_name(tp->key.type), pj_sockaddr_has_addr(&tp->key.rem_addr)? addr_string(&tp->key.rem_addr):"", pj_sockaddr_has_addr(&tp->key.rem_addr)? pj_sockaddr_get_port(&tp->key.rem_addr):0));






    return PJ_SUCCESS;
}


static pj_status_t destroy_transport( pjsip_tpmgr *mgr, pjsip_transport *tp )
{
    int key_len;
    pj_uint32_t hval;
    void *entry;

    tp->is_destroying = PJ_TRUE;

    TRACE_((THIS_FILE, "Transport %s is being destroyed", tp->obj_name));

    pj_lock_acquire(tp->lock);
    pj_lock_acquire(mgr->lock);

    
    
    if (tp->idle_timer.id != PJ_FALSE) {
	tp->idle_timer.id = PJ_FALSE;
	pjsip_endpt_cancel_timer(mgr->endpt, &tp->idle_timer);
    }

    
    key_len = sizeof(tp->key.type) + tp->addr_len;
    hval = 0;
    entry = pj_hash_get(mgr->table, &tp->key, key_len, &hval);
    if (entry) {
	transport *tp_ref = (transport *)entry;
	transport *tp_iter = tp_ref;
	
	do {
	    if (tp_iter->tp == tp) {
		transport *tp_next = tp_iter->next;

		
		if (tp_iter == tp_ref) {
		    pj_hash_set(NULL, mgr->table, &tp->key, key_len, hval, NULL);

		    if (tp_ref->next != tp_ref) {
			
			pj_hash_set_np(mgr->table, &tp_next->tp->key, key_len, hval, tp_next->tp_buf, tp_next);
			TRACE_((THIS_FILE, "Hash entry updated after " "transport %d being destroyed", tp->obj_name));

		    } else {
			TRACE_((THIS_FILE, "Hash entry deleted after " "transport %d being destroyed", tp->obj_name));

		    }
		}

		pj_list_erase(tp_iter);
		
		pj_list_push_back(&mgr->tp_entry_freelist, tp_iter);

		break;
	    }
	    tp_iter = tp_iter->next;
	} while (tp_iter != tp_ref);

	if (tp_iter->tp != tp) {
	    PJ_LOG(3, (THIS_FILE, "Warning: transport %s being destroyed is " "not registered", tp->obj_name));
	}
    } else {
	PJ_LOG(3, (THIS_FILE, "Warning: transport %s being destroyed is " "not found in the hash table", tp->obj_name));
    }

    pj_lock_release(mgr->lock);
    pj_lock_release(tp->lock);

    
    if (tp->grp_lock) {
	pj_grp_lock_dec_ref(tp->grp_lock);
    }

    
    return tp->destroy(tp);
}



PJ_DEF(pj_status_t) pjsip_transport_shutdown(pjsip_transport *tp)
{
    return pjsip_transport_shutdown2(tp, PJ_FALSE);
}



PJ_DEF(pj_status_t) pjsip_transport_shutdown2(pjsip_transport *tp, pj_bool_t force)
{
    pjsip_tpmgr *mgr;
    pj_status_t status;
    pjsip_tp_state_callback state_cb;

    PJ_LOG(4, (THIS_FILE, "Transport %s shutting down, force=%d", tp->obj_name, force));

    pj_lock_acquire(tp->lock);

    mgr = tp->tpmgr;
    pj_lock_acquire(mgr->lock);

    
    if (tp->is_shutdown || tp->is_destroying) {
	pj_lock_release(mgr->lock);
	pj_lock_release(tp->lock);
	return PJ_SUCCESS;
    }

    status = PJ_SUCCESS;

    
    if (tp->do_shutdown)
	status = tp->do_shutdown(tp);

    if (status == PJ_SUCCESS)
	tp->is_shutdown = PJ_TRUE;

    
    state_cb = pjsip_tpmgr_get_state_cb(tp->tpmgr);
    if (state_cb) {
	pjsip_transport_state_info state_info;

	pj_bzero(&state_info, sizeof(state_info));
	state_info.status = PJ_ECANCELLED;
	(*state_cb)(tp, (force? PJSIP_TP_STATE_DISCONNECTED:
		    PJSIP_TP_STATE_SHUTDOWN), &state_info);
    }

    
    if (pj_atomic_get(tp->ref_cnt) == 0) {
	pjsip_transport_add_ref(tp);
	pjsip_transport_dec_ref(tp);
    }

    pj_lock_release(mgr->lock);
    pj_lock_release(tp->lock);

    return status;
}



PJ_DEF(pj_status_t) pjsip_transport_destroy( pjsip_transport *tp)
{
    pjsip_tp_state_callback state_cb;

    
    PJ_ASSERT_RETURN(pj_atomic_get(tp->ref_cnt) == 0, PJSIP_EBUSY);

    
    state_cb = pjsip_tpmgr_get_state_cb(tp->tpmgr);
    if (state_cb) {
	pjsip_transport_state_info state_info;

	pj_bzero(&state_info, sizeof(state_info));
        (*state_cb)(tp, PJSIP_TP_STATE_DESTROY, &state_info);
    }

    
    return destroy_transport(tp->tpmgr, tp);
}






PJ_DEF(pj_status_t) pjsip_tpmgr_register_tpfactory( pjsip_tpmgr *mgr, pjsip_tpfactory *tpf)
{
    pjsip_tpfactory *p;
    pj_status_t status;

    pj_lock_acquire(mgr->lock);

    
    status = PJ_SUCCESS;
    for (p=mgr->factory_list.next; p!=&mgr->factory_list; p=p->next) {
	if (p == tpf) {
	    status = PJ_EEXISTS;
	    break;
	}
    }

    if (status != PJ_SUCCESS) {
	pj_lock_release(mgr->lock);
	return status;
    }

    pj_list_insert_before(&mgr->factory_list, tpf);

    pj_lock_release(mgr->lock);

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjsip_tpmgr_unregister_tpfactory( pjsip_tpmgr *mgr, pjsip_tpfactory *tpf)
{
    pj_lock_acquire(mgr->lock);

    pj_assert(pj_list_find_node(&mgr->factory_list, tpf) == tpf);
    pj_list_erase(tpf);

    pj_lock_release(mgr->lock);

    return PJ_SUCCESS;
}

PJ_DECL(void) pjsip_tpmgr_fla2_param_default(pjsip_tpmgr_fla2_param *prm)
{
    pj_bzero(prm, sizeof(*prm));
}

static pj_bool_t pjsip_tpmgr_is_tpfactory_valid(pjsip_tpmgr *mgr, pjsip_tpfactory *tpf)
{
    pjsip_tpfactory *p;

    pj_lock_acquire(mgr->lock);
    for (p=mgr->factory_list.next; p!=&mgr->factory_list; p=p->next) {
	if (p == tpf) {
	    pj_lock_release(mgr->lock);
	    return PJ_TRUE;
	}
    }
    pj_lock_release(mgr->lock);

    return PJ_FALSE;
}




PJ_DEF(pj_status_t) pjsip_tpmgr_create( pj_pool_t *pool, pjsip_endpoint *endpt, pjsip_rx_callback rx_cb, pjsip_tx_callback tx_cb, pjsip_tpmgr **p_mgr)



{
    pjsip_tpmgr *mgr;
    pj_status_t status;
    unsigned i = 0;
    pj_pool_t *mgr_pool;

    PJ_ASSERT_RETURN(pool && endpt && rx_cb && p_mgr, PJ_EINVAL);

    
    status = pjsip_endpt_register_module(endpt, &mod_msg_print);
    if (status != PJ_SUCCESS)
	return status;

    
    mgr_pool = pjsip_endpt_create_pool(endpt, "tpmgr", TPMGR_POOL_INIT_SIZE, TPMGR_POOL_INC_SIZE);

    mgr = PJ_POOL_ZALLOC_T(mgr_pool, pjsip_tpmgr);
    mgr->endpt = endpt;
    mgr->on_rx_msg = rx_cb;
    mgr->on_tx_msg = tx_cb;
    mgr->pool = mgr_pool;

    if (!mgr->pool)
	return PJ_ENOMEM;

    pj_list_init(&mgr->factory_list);
    pj_list_init(&mgr->tdata_list);
    pj_list_init(&mgr->tp_entry_freelist);

    mgr->table = pj_hash_create(mgr->pool, PJSIP_TPMGR_HTABLE_SIZE);
    if (!mgr->table)
	return PJ_ENOMEM;

    status = pj_lock_create_recursive_mutex(mgr->pool, "tmgr%p", &mgr->lock);
    if (status != PJ_SUCCESS)
	return status;

    for (; i < PJSIP_TRANSPORT_ENTRY_ALLOC_CNT; ++i) {
	transport *tp_add = NULL;

	tp_add = PJ_POOL_ZALLOC_T(mgr->pool, transport);
	if (!tp_add)
	    return PJ_ENOMEM;
	pj_list_init(tp_add);
	pj_list_push_back(&mgr->tp_entry_freelist, tp_add);
    }


    status = pj_atomic_create(mgr->pool, 0, &mgr->tdata_counter);
    if (status != PJ_SUCCESS) {
    	pj_lock_destroy(mgr->lock);
    	return status;
    }


    
    pjsip_tpmgr_set_state_cb(mgr, &tp_state_callback);

    PJ_LOG(5, (THIS_FILE, "Transport manager created."));

    *p_mgr = mgr;
    return PJ_SUCCESS;
}


static pj_status_t get_net_interface(pjsip_transport_type_e tp_type, const pj_str_t *dst, pj_str_t *itf_str_addr)

{
    int af;
    pj_sockaddr itf_addr;
    pj_status_t status = -1;

    af = (tp_type & PJSIP_TRANSPORT_IPV6)? pj_AF_INET6() : pj_AF_INET();

    if (pjsip_cfg()->endpt.resolve_hostname_to_get_interface) {
	status = pj_getipinterface(af, dst, &itf_addr, PJ_TRUE, NULL);
    }

    if (status != PJ_SUCCESS) { 
	status = pj_getipinterface(af, dst, &itf_addr, PJ_FALSE, NULL);
	if (status != PJ_SUCCESS) {
	    
	    PJ_PERROR(5,(THIS_FILE, status, "Warning: unable to determine local interface, " "fallback to default interface!"));

	    status = pj_gethostip(af, &itf_addr);
	    if (status != PJ_SUCCESS)
		return status;
	}
    }

    
    pj_sockaddr_print(&itf_addr, itf_str_addr->ptr, PJ_INET6_ADDRSTRLEN, 0);
    itf_str_addr->slen = pj_ansi_strlen(itf_str_addr->ptr);

    return PJ_SUCCESS;
}


PJ_DEF(pj_status_t) pjsip_tpmgr_find_local_addr2(pjsip_tpmgr *tpmgr, pj_pool_t *pool, pjsip_tpmgr_fla2_param *prm)

{
    char tmp_buf[PJ_INET6_ADDRSTRLEN+10];
    pj_str_t tmp_str;
    pj_status_t status = PJSIP_EUNSUPTRANSPORT;
    unsigned flag;

    
    PJ_ASSERT_RETURN(tpmgr && pool && prm, PJ_EINVAL);

    pj_strset(&tmp_str, tmp_buf, 0);
    prm->ret_addr.slen = 0;
    prm->ret_port = 0;
    prm->ret_tp = NULL;

    flag = pjsip_transport_get_flag_from_type(prm->tp_type);

    if (prm->tp_sel && prm->tp_sel->type == PJSIP_TPSELECTOR_TRANSPORT && prm->tp_sel->u.transport)
    {
	const pjsip_transport *tp = prm->tp_sel->u.transport;
	if (prm->local_if) {
	    status = get_net_interface((pjsip_transport_type_e)tp->key.type, &prm->dst_host, &tmp_str);
	    if (status != PJ_SUCCESS)
		goto on_return;
	    pj_strdup(pool, &prm->ret_addr, &tmp_str);
	    prm->ret_port = pj_sockaddr_get_port(&tp->local_addr);
	    prm->ret_tp = tp;
	} else {
	    pj_strdup(pool, &prm->ret_addr, &tp->local_name.host);
	    prm->ret_port = (pj_uint16_t)tp->local_name.port;
	}
	status = PJ_SUCCESS;

    } else if (prm->tp_sel && prm->tp_sel->type == PJSIP_TPSELECTOR_LISTENER && prm->tp_sel->u.listener)
    {
	if (prm->local_if) {
	    status = get_net_interface(prm->tp_sel->u.listener->type, &prm->dst_host, &tmp_str);
	    if (status != PJ_SUCCESS)
		goto on_return;
	    pj_strdup(pool, &prm->ret_addr, &tmp_str);
	} else {
	    pj_strdup(pool, &prm->ret_addr, &prm->tp_sel->u.listener->addr_name.host);
	}
	prm->ret_port = (pj_uint16_t)prm->tp_sel->u.listener->addr_name.port;
	status = PJ_SUCCESS;

    } else if ((flag & PJSIP_TRANSPORT_DATAGRAM) != 0) {
	pj_sockaddr remote;
	int addr_len;
	pjsip_transport *tp;

	pj_bzero(&remote, sizeof(remote));
	if (prm->tp_type & PJSIP_TRANSPORT_IPV6) {
	    addr_len = sizeof(pj_sockaddr_in6);
	    remote.addr.sa_family = pj_AF_INET6();
	} else {
	    addr_len = sizeof(pj_sockaddr_in);
	    remote.addr.sa_family = pj_AF_INET();
	}

	status = pjsip_tpmgr_acquire_transport(tpmgr, prm->tp_type, &remote, addr_len, NULL, &tp);

	if (status == PJ_SUCCESS) {
	    if (prm->local_if) {
		status = get_net_interface((pjsip_transport_type_e)
					   tp->key.type, &prm->dst_host, &tmp_str);
		if (status != PJ_SUCCESS)
		    goto on_return;
		pj_strdup(pool, &prm->ret_addr, &tmp_str);
		prm->ret_port = pj_sockaddr_get_port(&tp->local_addr);
		prm->ret_tp = tp;
	    } else {
		pj_strdup(pool, &prm->ret_addr, &tp->local_name.host);
		prm->ret_port = (pj_uint16_t)tp->local_name.port;
	    }

	    pjsip_transport_dec_ref(tp);
	}

    } else {
	
	pjsip_tpfactory *f;

	pj_lock_acquire(tpmgr->lock);

	f = tpmgr->factory_list.next;
	while (f != &tpmgr->factory_list) {
	    if (f->type == prm->tp_type)
		break;
	    f = f->next;
	}

	if (f != &tpmgr->factory_list) {
	    if (prm->local_if) {
		status = get_net_interface(f->type, &prm->dst_host, &tmp_str);
		if (status == PJ_SUCCESS) {
		    pj_strdup(pool, &prm->ret_addr, &tmp_str);
		} else {
		    
		    PJ_PERROR(5,(THIS_FILE, status, "Warning: unable to " "determine local interface"));
		    pj_strdup(pool, &prm->ret_addr, &f->addr_name.host);
		    status = PJ_SUCCESS;
		}
	    } else {
		pj_strdup(pool, &prm->ret_addr, &f->addr_name.host);
	    }
	    prm->ret_port = (pj_uint16_t)f->addr_name.port;
	    status = PJ_SUCCESS;
	}
	pj_lock_release(tpmgr->lock);
    }

on_return:
    return status;
}

PJ_DEF(pj_status_t) pjsip_tpmgr_find_local_addr( pjsip_tpmgr *tpmgr, pj_pool_t *pool, pjsip_transport_type_e type, const pjsip_tpselector *sel, pj_str_t *ip_addr, int *port)




{
    pjsip_tpmgr_fla2_param prm;
    pj_status_t status;

    pjsip_tpmgr_fla2_param_default(&prm);
    prm.tp_type = type;
    prm.tp_sel = sel;

    status = pjsip_tpmgr_find_local_addr2(tpmgr, pool, &prm);
    if (status != PJ_SUCCESS)
	return status;

    *ip_addr = prm.ret_addr;
    *port = prm.ret_port;

    return PJ_SUCCESS;
}


PJ_DEF(unsigned) pjsip_tpmgr_get_transport_count(pjsip_tpmgr *mgr)
{
    pj_hash_iterator_t itr_val;
    pj_hash_iterator_t *itr;
    int nr_of_transports = 0;

    pj_lock_acquire(mgr->lock);

    itr = pj_hash_first(mgr->table, &itr_val);
    while (itr) {
	transport *tp_entry = (transport *)pj_hash_this(mgr->table, itr);
	nr_of_transports += pj_list_size(tp_entry);
	itr = pj_hash_next(mgr->table, itr);
    }

    pj_lock_release(mgr->lock);

    return nr_of_transports;
}


PJ_DEF(pj_status_t) pjsip_tpmgr_destroy( pjsip_tpmgr *mgr )
{
    pj_hash_iterator_t itr_val;
    pj_hash_iterator_t *itr;
    pjsip_tpfactory *factory;
    pjsip_endpoint *endpt = mgr->endpt;

    PJ_LOG(5, (THIS_FILE, "Destroying transport manager"));

    pj_lock_acquire(mgr->lock);

    
    for (itr = pj_hash_first(mgr->table, &itr_val); itr;
	 itr = pj_hash_first(mgr->table, &itr_val))
    {
	transport *tp_ref;
	tp_ref = pj_hash_this(mgr->table, itr);
	destroy_transport(mgr, tp_ref->tp);
    }

    
    factory = mgr->factory_list.next;
    while (factory != &mgr->factory_list) {
	pjsip_tpfactory *next = factory->next;

	factory->destroy(factory);

	factory = next;
    }

    pj_lock_release(mgr->lock);


    
    
    if (pj_atomic_get(mgr->tdata_counter) != 0) {
	PJ_LOG(3,(THIS_FILE, "Warning: %d transmit buffer(s) not freed!", pj_atomic_get(mgr->tdata_counter)));
    }


    
    if (!pj_list_empty(&mgr->tdata_list)) {
	pjsip_tx_data *tdata = mgr->tdata_list.next;
	while (tdata != &mgr->tdata_list) {
	    pjsip_tx_data *next = tdata->next;
	    tx_data_destroy(tdata);
	    tdata = next;
	}
	PJ_LOG(3,(THIS_FILE, "Cleaned up dangling transmit buffer(s)."));
    }


    pj_atomic_destroy(mgr->tdata_counter);


    pj_lock_destroy(mgr->lock);

    
    if (mod_msg_print.id != -1) {
	pjsip_endpt_unregister_module(endpt, &mod_msg_print);
    }

    if (mgr->pool) {
	pjsip_endpt_release_pool( mgr->endpt, mgr->pool );
    }

    return PJ_SUCCESS;
}



PJ_DEF(pj_ssize_t) pjsip_tpmgr_receive_packet( pjsip_tpmgr *mgr, pjsip_rx_data *rdata)
{
    pjsip_transport *tr = rdata->tp_info.transport;

    char *current_pkt;
    pj_size_t remaining_len;
    pj_size_t total_processed = 0;

    
    pj_assert(rdata->pkt_info.len > 0);
    if (rdata->pkt_info.len <= 0)
	return -1;

    current_pkt = rdata->pkt_info.packet;
    remaining_len = rdata->pkt_info.len;

    tr->last_recv_len = rdata->pkt_info.len;
    pj_get_timestamp(&tr->last_recv_ts);
    
    
    current_pkt[remaining_len] = '\0';

    
    while (remaining_len > 0) {

	pjsip_msg *msg;
	char *p, *end;
	char saved;
	pj_size_t msg_fragment_size;

	
	for (p=current_pkt, end=p+remaining_len; p!=end; ++p) {
	    if (*p != '\r' && *p != '\n')
		break;
	}
	if (p!=current_pkt) {
	    remaining_len -= (p - current_pkt);
	    total_processed += (p - current_pkt);

	    
	    if (mgr->tp_drop_data_cb) {
		pjsip_tp_dropped_data dd;
		pj_bzero(&dd, sizeof(dd));
		dd.tp = tr;
		dd.data = current_pkt;
		dd.len = p - current_pkt;
		dd.status = PJ_EIGNORED;
		(*mgr->tp_drop_data_cb)(&dd);
	    }

	    current_pkt = p;
	    if (remaining_len == 0) {
		return total_processed;
	    }
	}

	
	msg_fragment_size = remaining_len;

	
	pj_bzero(&rdata->msg_info, sizeof(rdata->msg_info));
	pj_list_init(&rdata->msg_info.parse_err);
	rdata->msg_info.msg_buf = current_pkt;
	rdata->msg_info.len = (int)remaining_len;

	
	if ((tr->flag & PJSIP_TRANSPORT_DATAGRAM) == 0) {
	    pj_status_t msg_status;
	    msg_status = pjsip_find_msg(current_pkt, remaining_len, PJ_FALSE,  &msg_fragment_size);
	    if (msg_status != PJ_SUCCESS) {
		if (remaining_len == PJSIP_MAX_PKT_LEN) {
		    mgr->on_rx_msg(mgr->endpt, PJSIP_ERXOVERFLOW, rdata);
		    
		    
	    	    if (mgr->tp_drop_data_cb) {
			pjsip_tp_dropped_data dd;
			pj_bzero(&dd, sizeof(dd));
			dd.tp = tr;
			dd.data = current_pkt;
			dd.len = msg_fragment_size;
			dd.status = PJSIP_ERXOVERFLOW;
			(*mgr->tp_drop_data_cb)(&dd);
	    	    }
		    
		    
		    return rdata->pkt_info.len;
		} else {
		    
		    return total_processed;
		}
	    }
	}

	
	rdata->msg_info.len = (int)msg_fragment_size;

	
	saved = current_pkt[msg_fragment_size];
	current_pkt[msg_fragment_size] = '\0';

	
	rdata->msg_info.msg = msg =  pjsip_parse_rdata( current_pkt, msg_fragment_size, rdata);

	
	current_pkt[msg_fragment_size] = saved;

	
	if (msg==NULL || !pj_list_empty(&rdata->msg_info.parse_err)) {
	    pjsip_parser_err_report *err;
	    char buf[256];
	    pj_str_t tmp;

	    
	    tmp.ptr = buf; tmp.slen = 0;
	    err = rdata->msg_info.parse_err.next;
	    while (err != &rdata->msg_info.parse_err) {
		int len;
		len = pj_ansi_snprintf(tmp.ptr+tmp.slen, sizeof(buf)-tmp.slen, ": %s exception when parsing '%.*s' " "header on line %d col %d", pj_exception_id_name(err->except_code), (int)err->hname.slen, err->hname.ptr, err->line, err->col);




		if (len >= (int)sizeof(buf)-tmp.slen) {
		    len = (int)sizeof(buf)-tmp.slen;
		}
		if (len > 0) {
		    tmp.slen += len;
		}
		err = err->next;
	    }

	    
	    if (tmp.slen) {
		PJ_LOG(1, (THIS_FILE,  "Error processing %d bytes packet from %s %s:%d %.*s:\n" "%.*s\n" "-- end of packet.", msg_fragment_size, rdata->tp_info.transport->type_name, rdata->pkt_info.src_name, rdata->pkt_info.src_port, (int)tmp.slen, tmp.ptr, (int)msg_fragment_size, rdata->msg_info.msg_buf));









	    }

	    
	    if (tmp.slen && mgr->tp_drop_data_cb) {
		pjsip_tp_dropped_data dd;
		pj_bzero(&dd, sizeof(dd));
		dd.tp = tr;
		dd.data = current_pkt;
		dd.len = msg_fragment_size;
		dd.status = PJSIP_EINVALIDMSG;
		(*mgr->tp_drop_data_cb)(&dd);
		
		if (dd.len > 0 && dd.len < msg_fragment_size)
		    msg_fragment_size = dd.len;
	    }

	    goto finish_process_fragment;
	}

	
	if (rdata->msg_info.cid == NULL || rdata->msg_info.cid->id.slen == 0 || rdata->msg_info.from == NULL || rdata->msg_info.to == NULL || rdata->msg_info.via == NULL || rdata->msg_info.cseq == NULL)




	{
	    mgr->on_rx_msg(mgr->endpt, PJSIP_EMISSINGHDR, rdata);

	    
	    if (mgr->tp_drop_data_cb) {
		pjsip_tp_dropped_data dd;
		pj_bzero(&dd, sizeof(dd));
		dd.tp = tr;
		dd.data = current_pkt;
		dd.len = msg_fragment_size;
		dd.status = PJSIP_EMISSINGHDR;
		(*mgr->tp_drop_data_cb)(&dd);	    
	    }
	    goto finish_process_fragment;
	}

	
	if (rdata->msg_info.msg->type == PJSIP_REQUEST_MSG) {
	    
	    pj_strdup2(rdata->tp_info.pool,  &rdata->msg_info.via->recvd_param, rdata->pkt_info.src_name);


	    
	    if (rdata->msg_info.via->rport_param == 0) {
		rdata->msg_info.via->rport_param = rdata->pkt_info.src_port;
	    }
	} else {
	    
	    if (rdata->msg_info.msg->line.status.code < 100 || rdata->msg_info.msg->line.status.code >= 700)
	    {
		mgr->on_rx_msg(mgr->endpt, PJSIP_EINVALIDSTATUS, rdata);

		
		if (mgr->tp_drop_data_cb) {
		    pjsip_tp_dropped_data dd;
		    pj_bzero(&dd, sizeof(dd));
		    dd.tp = tr;
		    dd.data = current_pkt;
		    dd.len = msg_fragment_size;
		    dd.status = PJSIP_EINVALIDSTATUS;
		    (*mgr->tp_drop_data_cb)(&dd);	    
		}
		goto finish_process_fragment;
	    }
	}

	
	

	
	mgr->on_rx_msg(mgr->endpt, PJ_SUCCESS, rdata);


finish_process_fragment:
	total_processed += msg_fragment_size;
	current_pkt += msg_fragment_size;
	remaining_len -= msg_fragment_size;

    }	


    return total_processed;
}



PJ_DEF(pj_status_t) pjsip_tpmgr_acquire_transport(pjsip_tpmgr *mgr, pjsip_transport_type_e type, const pj_sockaddr_t *remote, int addr_len, const pjsip_tpselector *sel, pjsip_transport **tp)




{
    return pjsip_tpmgr_acquire_transport2(mgr, type, remote, addr_len, sel, NULL, tp);
}



PJ_DEF(pj_status_t) pjsip_tpmgr_acquire_transport2(pjsip_tpmgr *mgr, pjsip_transport_type_e type, const pj_sockaddr_t *remote, int addr_len, const pjsip_tpselector *sel, pjsip_tx_data *tdata, pjsip_transport **tp)





{
    pjsip_tpfactory *factory;
    pj_status_t status;

    TRACE_((THIS_FILE,"Acquiring transport type=%s, sel=%s remote=%s:%d", pjsip_transport_get_type_name(type), print_tpsel_info(sel), addr_string(remote), pj_sockaddr_get_port(remote)));




    pj_lock_acquire(mgr->lock);

    
    if (sel && sel->type == PJSIP_TPSELECTOR_TRANSPORT && sel->u.transport)
    {
	pjsip_transport *seltp = sel->u.transport;

	
	if (seltp->key.type != type) {
	    pj_lock_release(mgr->lock);
	    TRACE_((THIS_FILE, "Transport type in tpsel not matched"));
	    return PJSIP_ETPNOTSUITABLE;
	}

	
	if (seltp->is_destroying) {
	    pj_lock_release(mgr->lock);
	    TRACE_((THIS_FILE,"Transport to be acquired is being destroyed"));
	    return PJ_ENOTFOUND;
	}

	

	
	pjsip_transport_add_ref(seltp);
	pj_lock_release(mgr->lock);
	*tp = seltp;

	TRACE_((THIS_FILE, "Transport %s acquired", seltp->obj_name));
	return PJ_SUCCESS;

    } else {

	
	pjsip_transport_key key;
	int key_len;
	pjsip_transport *tp_ref = NULL;
	transport *tp_entry = NULL;


	
	if (sel && sel->type == PJSIP_TPSELECTOR_LISTENER && sel->u.listener)
	{
	    if (sel->u.listener->type != type) {
		pj_lock_release(mgr->lock);
		TRACE_((THIS_FILE, "Listener type in tpsel not matched"));
		return PJSIP_ETPNOTSUITABLE;
	    }
	}

	if (!sel || sel->disable_connection_reuse == PJ_FALSE) {
	    pj_bzero(&key, sizeof(key));
	    key_len = sizeof(key.type) + addr_len;

	    
	    key.type = type;
	    pj_memcpy(&key.rem_addr, remote, addr_len);

	    tp_entry = (transport *)pj_hash_get(mgr->table, &key, key_len, NULL);
	    if (tp_entry) {
		transport *tp_iter = tp_entry;
		do {
		    
		    if (!tp_iter->tp->is_shutdown && !tp_iter->tp->is_destroying)
		    {
			if (sel && sel->type == PJSIP_TPSELECTOR_LISTENER && sel->u.listener)
			{
			    
			    if (tp_iter->tp->factory == sel->u.listener) {
				tp_ref = tp_iter->tp;
				break;
			    }
			} else {
			    tp_ref = tp_iter->tp;
			    break;
			}
		    }
		    tp_iter = tp_iter->next;
		} while (tp_iter != tp_entry);
	    }
	}

	if (tp_ref == NULL && (!sel || sel->disable_connection_reuse == PJ_FALSE))
	{
	    unsigned flag = pjsip_transport_get_flag_from_type(type);
	    const pj_sockaddr *remote_addr = (const pj_sockaddr*)remote;


	    
	    if (type == PJSIP_TRANSPORT_LOOP || type == PJSIP_TRANSPORT_LOOP_DGRAM)
	    {
		pj_sockaddr *addr = &key.rem_addr;

		pj_bzero(addr, addr_len);
		key_len = sizeof(key.type) + addr_len;
		tp_entry = (transport *) pj_hash_get(mgr->table, &key, key_len, NULL);
		if (tp_entry) {
		    tp_ref = tp_entry->tp;
		}
	    }
	    
	    else if (flag & PJSIP_TRANSPORT_DATAGRAM)
	    {
		pj_sockaddr *addr = &key.rem_addr;

		pj_bzero(addr, addr_len);
		addr->addr.sa_family = remote_addr->addr.sa_family;

		key_len = sizeof(key.type) + addr_len;
		tp_entry = (transport *) pj_hash_get(mgr->table, &key, key_len, NULL);
		if (tp_entry) {
		    tp_ref = tp_entry->tp;
		}
	    }
	}

	
	else if (sel && sel->type == PJSIP_TPSELECTOR_LISTENER && sel->u.listener && tp_ref->factory != sel->u.listener)
	{
	    tp_ref = NULL;
	    
	    TRACE_((THIS_FILE, "Transport found but from different listener"));
	}

	if (tp_ref!=NULL && !tp_ref->is_shutdown && !tp_ref->is_destroying) {
	    
	    pjsip_transport_add_ref(tp_ref);
	    pj_lock_release(mgr->lock);
	    *tp = tp_ref;

	    TRACE_((THIS_FILE, "Transport %s acquired", tp_ref->obj_name));
	    return PJ_SUCCESS;
	}


	
	if (sel && sel->type == PJSIP_TPSELECTOR_LISTENER && sel->u.listener)
	{
	    

	    
	    
	    

	    
	    factory = sel->u.listener;

	    
	    if (!pjsip_tpmgr_is_tpfactory_valid(mgr, factory)) {
		pj_lock_release(mgr->lock);
		PJ_LOG(3,(THIS_FILE, "Specified factory for creating " "transport is not found"));
		return PJ_ENOTFOUND;
	    }

	} else {

	    
	    factory = mgr->factory_list.next;
	    while (factory != &mgr->factory_list) {
		if (factory->type == type)
		    break;
		factory = factory->next;
	    }

	    if (factory == &mgr->factory_list) {
		
		pj_lock_release(mgr->lock);
		TRACE_((THIS_FILE, "No suitable factory was found either"));
		return PJSIP_EUNSUPTRANSPORT;
	    }
	}
    }

    TRACE_((THIS_FILE, "Creating new transport from factory"));

    
    if (factory->create_transport2) {
	status = factory->create_transport2(factory, mgr, mgr->endpt, (const pj_sockaddr*) remote, addr_len, tdata, tp);

    } else {
	status = factory->create_transport(factory, mgr, mgr->endpt, (const pj_sockaddr*) remote, addr_len, tp);

    }
    if (status == PJ_SUCCESS) {
	PJ_ASSERT_ON_FAIL(tp!=NULL, {pj_lock_release(mgr->lock); return PJ_EBUG;});
	pjsip_transport_add_ref(*tp);
	(*tp)->factory = factory;
    }
    pj_lock_release(mgr->lock);
    return status;
}


PJ_DEF(void) pjsip_tpmgr_dump_transports(pjsip_tpmgr *mgr)
{

    pj_hash_iterator_t itr_val;
    pj_hash_iterator_t *itr;
    pjsip_tpfactory *factory;

    pj_lock_acquire(mgr->lock);


    PJ_LOG(3,(THIS_FILE, " Outstanding transmit buffers: %d", pj_atomic_get(mgr->tdata_counter)));


    PJ_LOG(3, (THIS_FILE, " Dumping listeners:"));
    factory = mgr->factory_list.next;
    while (factory != &mgr->factory_list) {
	PJ_LOG(3, (THIS_FILE, "  %s %s:%.*s:%d",  factory->obj_name, factory->type_name, (int)factory->addr_name.host.slen, factory->addr_name.host.ptr, (int)factory->addr_name.port));




	factory = factory->next;
    }

    itr = pj_hash_first(mgr->table, &itr_val);
    if (itr) {
	PJ_LOG(3, (THIS_FILE, " Dumping transports:"));

	do {
	    transport *tp_entry = (transport *) pj_hash_this(mgr->table, itr);
	    if (tp_entry) {
		transport *tp_iter = tp_entry;

		do {
		    pjsip_transport *tp_ref = tp_iter->tp;

		    PJ_LOG(3, (THIS_FILE, "  %s %s%s%s%s(refcnt=%d%s)", tp_ref->obj_name, tp_ref->info, (tp_ref->factory)?" listener[":"", (tp_ref->factory)?tp_ref->factory->obj_name:"", (tp_ref->factory)?"]":"", pj_atomic_get(tp_ref->ref_cnt), (tp_ref->idle_timer.id ? " [idle]" : "")));







		    tp_iter = tp_iter->next;
		} while (tp_iter != tp_entry);
	    }
	    itr = pj_hash_next(mgr->table, itr);
	} while (itr);
    }

    pj_lock_release(mgr->lock);

    PJ_UNUSED_ARG(mgr);

}


PJ_DEF(pj_status_t) pjsip_tpmgr_set_state_cb(pjsip_tpmgr *mgr, pjsip_tp_state_callback cb)
{
    PJ_ASSERT_RETURN(mgr, PJ_EINVAL);

    mgr->tp_state_cb = cb;

    return PJ_SUCCESS;
}


PJ_DEF(pjsip_tp_state_callback) pjsip_tpmgr_get_state_cb( const pjsip_tpmgr *mgr)
{
    PJ_ASSERT_RETURN(mgr, NULL);

    return mgr->tp_state_cb;
}



static void init_tp_data(pjsip_transport *tp)
{
    transport_data *tp_data;

    pj_assert(tp && !tp->data);

    tp_data = PJ_POOL_ZALLOC_T(tp->pool, transport_data);
    pj_list_init(&tp_data->st_listeners);
    pj_list_init(&tp_data->st_listeners_empty);
    tp->data = tp_data;
}


static void tp_state_callback(pjsip_transport *tp, pjsip_transport_state state, const pjsip_transport_state_info *info)

{
    transport_data *tp_data;

    pj_lock_acquire(tp->lock);

    tp_data = (transport_data*)tp->data;

    
    if (!tp_data || pj_list_empty(&tp_data->st_listeners)) {
	goto on_return;
    } else {
	pjsip_transport_state_info st_info;
	tp_state_listener *st_listener = tp_data->st_listeners.next;

	
	pj_memcpy(&st_info, info, sizeof(st_info));
	while (st_listener != &tp_data->st_listeners) {
	    st_info.user_data = st_listener->user_data;
	    (*st_listener->cb)(tp, state, &st_info);

	    st_listener = st_listener->next;
	}
    }

on_return:
    pj_lock_release(tp->lock);
}



PJ_DEF(pj_status_t) pjsip_transport_add_state_listener ( pjsip_transport *tp, pjsip_tp_state_callback cb, void *user_data, pjsip_tp_state_listener_key **key)



{
    transport_data *tp_data;
    tp_state_listener *entry;

    PJ_ASSERT_RETURN(tp && cb && key, PJ_EINVAL);

    if (tp->is_shutdown || tp->is_destroying) {
	*key = NULL;
	return PJ_EINVALIDOP;
    }

    pj_lock_acquire(tp->lock);

    
    if (!tp->data)
	init_tp_data(tp);

    tp_data = (transport_data*)tp->data;

    
    if (!pj_list_empty(&tp_data->st_listeners_empty)) {
	entry = tp_data->st_listeners_empty.next;
	pj_list_erase(entry);
    } else {
	entry = PJ_POOL_ZALLOC_T(tp->pool, tp_state_listener);
    }
    entry->cb = cb;
    entry->user_data = user_data;

    
    pj_list_push_back(&tp_data->st_listeners, entry);

    *key = entry;

    pj_lock_release(tp->lock);

    return PJ_SUCCESS;
}


PJ_DEF(pj_status_t) pjsip_transport_remove_state_listener ( pjsip_transport *tp, pjsip_tp_state_listener_key *key, const void *user_data)


{
    transport_data *tp_data;
    tp_state_listener *entry;

    PJ_ASSERT_RETURN(tp && key, PJ_EINVAL);

    pj_lock_acquire(tp->lock);

    tp_data = (transport_data*)tp->data;

    
    if (!tp_data || pj_list_empty(&tp_data->st_listeners)) {
	pj_lock_release(tp->lock);
	return PJ_ENOTFOUND;
    }

    entry = (tp_state_listener*)key;

    
    if (entry->user_data != user_data) {
	pj_assert(!"Invalid transport state listener key");
	pj_lock_release(tp->lock);
	return PJ_EBUG;
    }

    
    entry->cb = NULL;
    entry->user_data = NULL;
    pj_list_erase(entry);
    pj_list_push_back(&tp_data->st_listeners_empty, entry);

    pj_lock_release(tp->lock);

    return PJ_SUCCESS;
}


PJ_DEF(pj_status_t) pjsip_tpmgr_set_drop_data_cb(pjsip_tpmgr *mgr, pjsip_tp_on_rx_dropped_cb cb)
{
    PJ_ASSERT_RETURN(mgr, PJ_EINVAL);

    mgr->tp_drop_data_cb = cb;

    return PJ_SUCCESS;
}
