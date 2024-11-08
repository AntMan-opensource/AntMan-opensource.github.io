












PJ_DEF(pj_status_t) pjsip_auth_srv_init(  pj_pool_t *pool, pjsip_auth_srv *auth_srv, const pj_str_t *realm, pjsip_auth_lookup_cred *lookup, unsigned options )



{
    PJ_ASSERT_RETURN(pool && auth_srv && realm && lookup, PJ_EINVAL);

    pj_bzero(auth_srv, sizeof(*auth_srv));
    pj_strdup( pool, &auth_srv->realm, realm);
    auth_srv->lookup = lookup;
    auth_srv->is_proxy = (options & PJSIP_AUTH_SRV_IS_PROXY);

    return PJ_SUCCESS;
}


PJ_DEF(pj_status_t) pjsip_auth_srv_init2( pj_pool_t *pool, pjsip_auth_srv *auth_srv, const pjsip_auth_srv_init_param *param)


{
    PJ_ASSERT_RETURN(pool && auth_srv && param, PJ_EINVAL);

    pj_bzero(auth_srv, sizeof(*auth_srv));
    pj_strdup( pool, &auth_srv->realm, param->realm);
    auth_srv->lookup2 = param->lookup2;
    auth_srv->is_proxy = (param->options & PJSIP_AUTH_SRV_IS_PROXY);

    return PJ_SUCCESS;
}



static pj_status_t pjsip_auth_verify( const pjsip_authorization_hdr *hdr, const pj_str_t *method, const pjsip_cred_info *cred_info )

{
    if (pj_stricmp(&hdr->scheme, &pjsip_DIGEST_STR) == 0) {
	char digest_buf[PJSIP_MD5STRLEN];
	pj_str_t digest;
	const pjsip_digest_credential *dig = &hdr->credential.digest;

	
	PJ_ASSERT_RETURN(pj_strcmp(&dig->username, &cred_info->username) == 0, PJ_EINVALIDOP);
	PJ_ASSERT_RETURN(pj_strcmp(&dig->realm, &cred_info->realm) == 0, PJ_EINVALIDOP);

	
	digest.ptr = digest_buf;
	digest.slen = PJSIP_MD5STRLEN;

	
	pjsip_auth_create_digest(&digest,  &hdr->credential.digest.nonce, &hdr->credential.digest.nc, &hdr->credential.digest.cnonce, &hdr->credential.digest.qop, &hdr->credential.digest.uri, &cred_info->realm, cred_info, method );








	
	return (pj_stricmp(&digest, &hdr->credential.digest.response) == 0) ? PJ_SUCCESS : PJSIP_EAUTHINVALIDDIGEST;

    } else {
	pj_assert(!"Unsupported authentication scheme");
	return PJSIP_EINVALIDAUTHSCHEME;
    }
}



PJ_DEF(pj_status_t) pjsip_auth_srv_verify( pjsip_auth_srv *auth_srv, pjsip_rx_data *rdata, int *status_code)

{
    pjsip_authorization_hdr *h_auth;
    pjsip_msg *msg = rdata->msg_info.msg;
    pjsip_hdr_e htype;
    pj_str_t acc_name;
    pjsip_cred_info cred_info;
    pj_status_t status;

    PJ_ASSERT_RETURN(auth_srv && rdata, PJ_EINVAL);
    PJ_ASSERT_RETURN(msg->type == PJSIP_REQUEST_MSG, PJSIP_ENOTREQUESTMSG);

    htype = auth_srv->is_proxy ? PJSIP_H_PROXY_AUTHORIZATION : 
				 PJSIP_H_AUTHORIZATION;

    
    *status_code = 200;

    
    h_auth = (pjsip_authorization_hdr*) pjsip_msg_find_hdr(msg, htype, NULL);
    while (h_auth) {
	if (!pj_stricmp(&h_auth->credential.common.realm, &auth_srv->realm))
	    break;

	h_auth = h_auth->next;
	if (h_auth == (void*) &msg->hdr) {
	    h_auth = NULL;
	    break;
	}

	h_auth=(pjsip_authorization_hdr*)pjsip_msg_find_hdr(msg,htype,h_auth);
    }

    if (!h_auth) {
	*status_code = auth_srv->is_proxy ? 407 : 401;
	return PJSIP_EAUTHNOAUTH;
    }

    
    if (pj_stricmp(&h_auth->scheme, &pjsip_DIGEST_STR) == 0)
	acc_name = h_auth->credential.digest.username;
    else {
	*status_code = auth_srv->is_proxy ? 407 : 401;
	return PJSIP_EINVALIDAUTHSCHEME;
    }

    
    if (auth_srv->lookup2) {
	pjsip_auth_lookup_cred_param param;

	pj_bzero(&param, sizeof(param));
	param.realm = auth_srv->realm;
	param.acc_name = acc_name;
	param.rdata = rdata;
	status = (*auth_srv->lookup2)(rdata->tp_info.pool, &param, &cred_info);
	if (status != PJ_SUCCESS) {
	    *status_code = PJSIP_SC_FORBIDDEN;
	    return status;
	}
    } else {
	status = (*auth_srv->lookup)(rdata->tp_info.pool, &auth_srv->realm, &acc_name, &cred_info);
	if (status != PJ_SUCCESS) {
	    *status_code = PJSIP_SC_FORBIDDEN;
	    return status;
	}
    }

    
    status = pjsip_auth_verify(h_auth, &msg->line.req.method.name,  &cred_info);
    if (status != PJ_SUCCESS) {
	*status_code = PJSIP_SC_FORBIDDEN;
    }
    return status;
}



PJ_DEF(pj_status_t) pjsip_auth_srv_challenge(  pjsip_auth_srv *auth_srv, const pj_str_t *qop, const pj_str_t *nonce, const pj_str_t *opaque, pj_bool_t stale, pjsip_tx_data *tdata)




{
    pjsip_www_authenticate_hdr *hdr;
    char nonce_buf[16];
    pj_str_t random;

    PJ_ASSERT_RETURN( auth_srv && tdata, PJ_EINVAL );

    random.ptr = nonce_buf;
    random.slen = sizeof(nonce_buf);

    
    if (auth_srv->is_proxy)
	hdr = pjsip_proxy_authenticate_hdr_create(tdata->pool);
    else hdr = pjsip_www_authenticate_hdr_create(tdata->pool);

    
    hdr->scheme = pjsip_DIGEST_STR;
    hdr->challenge.digest.algorithm = pjsip_MD5_STR;
    if (nonce) {
	pj_strdup(tdata->pool, &hdr->challenge.digest.nonce, nonce);
    } else {
	pj_create_random_string(nonce_buf, sizeof(nonce_buf));
	pj_strdup(tdata->pool, &hdr->challenge.digest.nonce, &random);
    }
    if (opaque) {
	pj_strdup(tdata->pool, &hdr->challenge.digest.opaque, opaque);
    } else {
	pj_create_random_string(nonce_buf, sizeof(nonce_buf));
	pj_strdup(tdata->pool, &hdr->challenge.digest.opaque, &random);
    }
    if (qop) {
	pj_strdup(tdata->pool, &hdr->challenge.digest.qop, qop);
    } else {
	hdr->challenge.digest.qop.slen = 0;
    }
    pj_strdup(tdata->pool, &hdr->challenge.digest.realm, &auth_srv->realm);
    hdr->challenge.digest.stale = stale;

    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)hdr);

    return PJ_SUCCESS;
}

