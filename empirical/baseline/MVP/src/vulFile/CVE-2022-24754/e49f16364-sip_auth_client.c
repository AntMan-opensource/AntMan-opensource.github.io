























































static void dup_bin(pj_pool_t *pool, pj_str_t *dst, const pj_str_t *src)
{
    dst->slen = src->slen;

    if (dst->slen) {
	dst->ptr = (char*) pj_pool_alloc(pool, src->slen);
	pj_memcpy(dst->ptr, src->ptr, src->slen);
    } else {
	dst->ptr = NULL;
    }
}

PJ_DEF(void) pjsip_cred_info_dup(pj_pool_t *pool, pjsip_cred_info *dst, const pjsip_cred_info *src)

{
    pj_memcpy(dst, src, sizeof(pjsip_cred_info));

    pj_strdup_with_null(pool, &dst->realm, &src->realm);
    pj_strdup_with_null(pool, &dst->scheme, &src->scheme);
    pj_strdup_with_null(pool, &dst->username, &src->username);
    pj_strdup_with_null(pool, &dst->data, &src->data);

    if ((dst->data_type & EXT_MASK) == PJSIP_CRED_DATA_EXT_AKA) {
	dup_bin(pool, &dst->ext.aka.k, &src->ext.aka.k);
	dup_bin(pool, &dst->ext.aka.op, &src->ext.aka.op);
	dup_bin(pool, &dst->ext.aka.amf, &src->ext.aka.amf);
    }
}


PJ_DEF(int) pjsip_cred_info_cmp(const pjsip_cred_info *cred1, const pjsip_cred_info *cred2)
{
    int result;

    result = pj_strcmp(&cred1->realm, &cred2->realm);
    if (result) goto on_return;
    result = pj_strcmp(&cred1->scheme, &cred2->scheme);
    if (result) goto on_return;
    result = pj_strcmp(&cred1->username, &cred2->username);
    if (result) goto on_return;
    result = pj_strcmp(&cred1->data, &cred2->data);
    if (result) goto on_return;
    result = (cred1->data_type != cred2->data_type);
    if (result) goto on_return;

    if ((cred1->data_type & EXT_MASK) == PJSIP_CRED_DATA_EXT_AKA) {
	result = pj_strcmp(&cred1->ext.aka.k, &cred2->ext.aka.k);
	if (result) goto on_return;
	result = pj_strcmp(&cred1->ext.aka.op, &cred2->ext.aka.op);
	if (result) goto on_return;
	result = pj_strcmp(&cred1->ext.aka.amf, &cred2->ext.aka.amf);
	if (result) goto on_return;
    }

on_return:
    return result;
}

PJ_DEF(void) pjsip_auth_clt_pref_dup( pj_pool_t *pool, pjsip_auth_clt_pref *dst, const pjsip_auth_clt_pref *src)

{
    pj_memcpy(dst, src, sizeof(pjsip_auth_clt_pref));
    pj_strdup_with_null(pool, &dst->algorithm, &src->algorithm);
}



static void digestNtoStr(const unsigned char digest[], int n, char *output)
{
    int i;
    for (i = 0; i<n; ++i) {
        pj_val_to_hex_digit(digest[i], output);
        output += 2;
    }
}



PJ_DEF(void) pjsip_auth_create_digest( pj_str_t *result, const pj_str_t *nonce, const pj_str_t *nc, const pj_str_t *cnonce, const pj_str_t *qop, const pj_str_t *uri, const pj_str_t *realm, const pjsip_cred_info *cred_info, const pj_str_t *method)







{
    char ha1[PJSIP_MD5STRLEN];
    char ha2[PJSIP_MD5STRLEN];
    unsigned char digest[16];
    pj_md5_context pms;

    pj_assert(result->slen >= PJSIP_MD5STRLEN);

    AUTH_TRACE_((THIS_FILE, "Begin creating digest"));

    if ((cred_info->data_type & PASSWD_MASK) == PJSIP_CRED_DATA_PLAIN_PASSWD) {
	
	pj_md5_init(&pms);
	MD5_APPEND( &pms, cred_info->username.ptr, cred_info->username.slen);
	MD5_APPEND( &pms, ":", 1);
	MD5_APPEND( &pms, realm->ptr, realm->slen);
	MD5_APPEND( &pms, ":", 1);
	MD5_APPEND( &pms, cred_info->data.ptr, cred_info->data.slen);
	pj_md5_final(&pms, digest);

	digestNtoStr(digest, 16, ha1);

    } else if ((cred_info->data_type & PASSWD_MASK) == PJSIP_CRED_DATA_DIGEST) {
	pj_assert(cred_info->data.slen == 32);
	pj_memcpy( ha1, cred_info->data.ptr, cred_info->data.slen );
    } else {
	pj_assert(!"Invalid data_type");
    }

    AUTH_TRACE_((THIS_FILE, "  ha1=%.32s", ha1));

    
    pj_md5_init(&pms);
    MD5_APPEND( &pms, method->ptr, method->slen);
    MD5_APPEND( &pms, ":", 1);
    MD5_APPEND( &pms, uri->ptr, uri->slen);
    pj_md5_final(&pms, digest);
    digestNtoStr(digest, 16, ha2);

    AUTH_TRACE_((THIS_FILE, "  ha2=%.32s", ha2));

    
    pj_md5_init(&pms);
    MD5_APPEND( &pms, ha1, PJSIP_MD5STRLEN);
    MD5_APPEND( &pms, ":", 1);
    MD5_APPEND( &pms, nonce->ptr, nonce->slen);
    if (qop && qop->slen != 0) {
	MD5_APPEND( &pms, ":", 1);
	MD5_APPEND( &pms, nc->ptr, nc->slen);
	MD5_APPEND( &pms, ":", 1);
	MD5_APPEND( &pms, cnonce->ptr, cnonce->slen);
	MD5_APPEND( &pms, ":", 1);
	MD5_APPEND( &pms, qop->ptr, qop->slen);
    }
    MD5_APPEND( &pms, ":", 1);
    MD5_APPEND( &pms, ha2, PJSIP_MD5STRLEN);

    
    pj_md5_final(&pms, digest);

    
    result->slen = PJSIP_MD5STRLEN;
    digestNtoStr(digest, 16, result->ptr);

    AUTH_TRACE_((THIS_FILE, "  digest=%.32s", result->ptr));
    AUTH_TRACE_((THIS_FILE, "Digest created"));
}



PJ_DEF(void) pjsip_auth_create_digestSHA256(pj_str_t *result, const pj_str_t *nonce, const pj_str_t *nc, const pj_str_t *cnonce, const pj_str_t *qop, const pj_str_t *uri, const pj_str_t *realm, const pjsip_cred_info *cred_info, const pj_str_t *method)







{


    char ha1[PJSIP_SHA256STRLEN];
    char ha2[PJSIP_SHA256STRLEN];
    unsigned char digest[32];
    SHA256_CTX pms;

    pj_assert(result->slen >= PJSIP_SHA256STRLEN);

    AUTH_TRACE_((THIS_FILE, "Begin creating digest"));

    if ((cred_info->data_type & PASSWD_MASK) == PJSIP_CRED_DATA_PLAIN_PASSWD)
    {
	
	SHA256_Init(&pms);
	SHA256_Update( &pms, cred_info->username.ptr, cred_info->username.slen);
	SHA256_Update( &pms, ":", 1);
	SHA256_Update( &pms, realm->ptr, realm->slen);
	SHA256_Update( &pms, ":", 1);
	SHA256_Update( &pms, cred_info->data.ptr, cred_info->data.slen);
	SHA256_Final(digest, &pms);

	digestNtoStr(digest, 32, ha1);

    } else if ((cred_info->data_type & PASSWD_MASK) == PJSIP_CRED_DATA_DIGEST)
    {
	pj_assert(cred_info->data.slen == 32);
	pj_memcpy( ha1, cred_info->data.ptr, cred_info->data.slen );
    } else {
	pj_assert(!"Invalid data_type");
    }

    AUTH_TRACE_((THIS_FILE, " ha1=%.64s", ha1));

    
    SHA256_Init(&pms);
    SHA256_Update( &pms, method->ptr, method->slen);
    SHA256_Update( &pms, ":", 1);
    SHA256_Update( &pms, uri->ptr, uri->slen);
    SHA256_Final( digest, &pms);
    digestNtoStr(digest, 32, ha2);

    AUTH_TRACE_((THIS_FILE, " ha2=%.64s", ha2));

    
    SHA256_Init(&pms);
    SHA256_Update( &pms, ha1, PJSIP_SHA256STRLEN);
    SHA256_Update( &pms, ":", 1);
    SHA256_Update( &pms, nonce->ptr, nonce->slen);
    if (qop && qop->slen != 0) {
	SHA256_Update( &pms, ":", 1);
	SHA256_Update( &pms, nc->ptr, nc->slen);
	SHA256_Update( &pms, ":", 1);
	SHA256_Update( &pms, cnonce->ptr, cnonce->slen);
	SHA256_Update( &pms, ":", 1);
	SHA256_Update( &pms, qop->ptr, qop->slen);
    }
    SHA256_Update( &pms, ":", 1);
    SHA256_Update( &pms, ha2, PJSIP_SHA256STRLEN);

    
    SHA256_Final(digest, &pms);

    
    result->slen = PJSIP_SHA256STRLEN;
    digestNtoStr(digest, 32, result->ptr);

    AUTH_TRACE_((THIS_FILE, " digest=%.64s", result->ptr));
    AUTH_TRACE_((THIS_FILE, "Digest created"));


    PJ_UNUSED_ARG(result);
    PJ_UNUSED_ARG(nonce);
    PJ_UNUSED_ARG(nc);
    PJ_UNUSED_ARG(cnonce);
    PJ_UNUSED_ARG(qop);
    PJ_UNUSED_ARG(uri);
    PJ_UNUSED_ARG(realm);
    PJ_UNUSED_ARG(cred_info);
    PJ_UNUSED_ARG(method);

}



static pj_bool_t has_auth_qop( pj_pool_t *pool, const pj_str_t *qop_offer)
{
    pj_str_t qop;
    char *p;

    pj_strdup_with_null( pool, &qop, qop_offer);
    p = qop.ptr;
    while (*p) {
	*p = (char)pj_tolower(*p);
	++p;
    }

    p = qop.ptr;
    while (*p) {
	if (*p=='a' && *(p+1)=='u' && *(p+2)=='t' && *(p+3)=='h') {
	    int e = *(p+4);
	    if (e=='"' || e==',' || e==0)
		return PJ_TRUE;
	    else p += 4;
	} else {
	    ++p;
	}
    }

    return PJ_FALSE;
}


static pj_status_t respond_digest( pj_pool_t *pool, pjsip_digest_credential *cred, const pjsip_digest_challenge *chal, const pj_str_t *uri, const pjsip_cred_info *cred_info, const pj_str_t *cnonce, pj_uint32_t nc, const pj_str_t *method)






{
    const pj_str_t pjsip_AKAv1_MD5_STR = { "AKAv1-MD5", 9 };
    pj_bool_t algo_sha256 = PJ_FALSE;

    

    algo_sha256 = (pj_stricmp(&chal->algorithm, &pjsip_SHA256_STR)==0);


    
    if (chal->algorithm.slen==0 || (algo_sha256 || pj_stricmp(&chal->algorithm, &pjsip_MD5_STR)==0 || pj_stricmp(&chal->algorithm, &pjsip_AKAv1_MD5_STR)==0))


    {
	PJ_LOG(4,(THIS_FILE, "Digest algorithm is \"%.*s\"", chal->algorithm.slen, chal->algorithm.ptr));
    }
    else {
	PJ_LOG(4,(THIS_FILE, "Unsupported digest algorithm \"%.*s\"", chal->algorithm.slen, chal->algorithm.ptr));
	return PJSIP_EINVALIDALGORITHM;
    }

    
    pj_strdup(pool, &cred->username, &cred_info->username);
    pj_strdup(pool, &cred->realm, &chal->realm);
    pj_strdup(pool, &cred->nonce, &chal->nonce);
    pj_strdup(pool, &cred->uri, uri);
    pj_strdup(pool, &cred->algorithm, &chal->algorithm);
    pj_strdup(pool, &cred->opaque, &chal->opaque);

    
    cred->response.slen = algo_sha256? PJSIP_SHA256STRLEN : PJSIP_MD5STRLEN;
    cred->response.ptr = (char*) pj_pool_alloc(pool, cred->response.slen);

    if (chal->qop.slen == 0) {
	

	if ((cred_info->data_type & EXT_MASK) == PJSIP_CRED_DATA_EXT_AKA) {
	    
	    return (*cred_info->ext.aka.cb)(pool, chal, cred_info, method, cred);
	}
	else {
	    
	    if (algo_sha256) {
		pjsip_auth_create_digestSHA256( &cred->response, &cred->nonce, NULL, NULL,  NULL, uri, &chal->realm, cred_info, method);


	    } else {
		pjsip_auth_create_digest( &cred->response, &cred->nonce, NULL, NULL,  NULL, uri, &chal->realm, cred_info, method);

	    }
	}

    } else if (has_auth_qop(pool, &chal->qop)) {
	
	cred->qop = pjsip_AUTH_STR;
	cred->nc.ptr = (char*) pj_pool_alloc(pool, 16);
	cred->nc.slen = pj_ansi_snprintf(cred->nc.ptr, 16, "%08u", nc);

	if (cnonce && cnonce->slen) {
	    pj_strdup(pool, &cred->cnonce, cnonce);
	} else {
	    pj_str_t dummy_cnonce = { "b39971", 6};
	    pj_strdup(pool, &cred->cnonce, &dummy_cnonce);
	}

	if ((cred_info->data_type & EXT_MASK) == PJSIP_CRED_DATA_EXT_AKA) {
	    
	    return (*cred_info->ext.aka.cb)(pool, chal, cred_info, method, cred);
	}
	else {
	    
	    if (algo_sha256) {
		pjsip_auth_create_digestSHA256( &cred->response, &cred->nonce, &cred->nc, &cred->cnonce, &pjsip_AUTH_STR, uri, &chal->realm, cred_info, method);




	    } else {
		pjsip_auth_create_digest( &cred->response, &cred->nonce, &cred->nc, &cred->cnonce, &pjsip_AUTH_STR, uri, &chal->realm, cred_info, method);



	    }
	}

    } else {
	
	PJ_LOG(4,(THIS_FILE, "Unsupported qop offer %.*s", chal->qop.slen, chal->qop.ptr));
	return PJSIP_EINVALIDQOP;
    }

    return PJ_SUCCESS;
}



static void update_digest_session( pjsip_cached_auth *cached_auth, const pjsip_www_authenticate_hdr *hdr )
{
    if (hdr->challenge.digest.qop.slen == 0) {

	if (!cached_auth->last_chal || pj_stricmp2(&hdr->scheme, "digest")) {
	    cached_auth->last_chal = (pjsip_www_authenticate_hdr*)
				     pjsip_hdr_clone(cached_auth->pool, hdr);
	} else {
	    
	    const pjsip_digest_challenge *d1 = &cached_auth->last_chal->challenge.digest;
	    const pjsip_digest_challenge *d2 = &hdr->challenge.digest;

	    if (pj_strcmp(&d1->domain, &d2->domain) || pj_strcmp(&d1->realm, &d2->realm) || pj_strcmp(&d1->nonce, &d2->nonce) || pj_strcmp(&d1->opaque, &d2->opaque) || pj_strcmp(&d1->algorithm, &d2->algorithm) || pj_strcmp(&d1->qop, &d2->qop))




	    {
		cached_auth->last_chal = (pjsip_www_authenticate_hdr*)
				       pjsip_hdr_clone(cached_auth->pool, hdr);
	    }
	}

	return;
    }

    
    if (cached_auth->cnonce.slen == 0) {
	
	cached_auth->last_chal = (pjsip_www_authenticate_hdr*)
				 pjsip_hdr_clone(cached_auth->pool, hdr);

	
	pj_create_unique_string( cached_auth->pool, &cached_auth->cnonce );

	if (pj_strchr(&cached_auth->cnonce, '-')) {
	    
	    pj_size_t w, r, len = pj_strlen(&cached_auth->cnonce);
	    char *s = cached_auth->cnonce.ptr;

	    w = r = 0;
	    for (; r < len; r++) {
		if (s[r] != '-')
		    s[w++] = s[r];
	    }
	    s[w] = '\0';
	    cached_auth->cnonce.slen = w;
	}


	
	cached_auth->nc = 1;

	
	
	if (cached_auth->realm.slen == 0) {
	    pj_strdup(cached_auth->pool, &cached_auth->realm, &hdr->challenge.digest.realm);
	}

    } else {
	
	if (!pj_strcmp(&hdr->challenge.digest.nonce, &cached_auth->last_chal->challenge.digest.nonce))
	{
	    
	    ++cached_auth->nc;
	} else {
	    
	    pj_strdup(cached_auth->pool,  &cached_auth->last_chal->challenge.digest.nonce, &hdr->challenge.digest.nonce);

	    
	    if (pj_strcmp(&cached_auth->last_chal->challenge.digest.opaque, &hdr->challenge.digest.opaque))
	    {
		pj_strdup(cached_auth->pool, &cached_auth->last_chal->challenge.digest.opaque, &hdr->challenge.digest.opaque);

	    }
	    cached_auth->nc = 1;
	}
    }
}




static pjsip_cached_auth *find_cached_auth( pjsip_auth_clt_sess *sess, const pj_str_t *realm )
{
    pjsip_cached_auth *auth = sess->cached_auth.next;
    while (auth != &sess->cached_auth) {
	if (pj_stricmp(&auth->realm, realm) == 0)
	    return auth;
	auth = auth->next;
    }

    return NULL;
}


static const pjsip_cred_info* auth_find_cred( const pjsip_auth_clt_sess *sess, const pj_str_t *realm, const pj_str_t *auth_scheme)

{
    unsigned i;
    int wildcard = -1;

    PJ_UNUSED_ARG(auth_scheme);

    for (i=0; i<sess->cred_cnt; ++i) {
	if (pj_stricmp(&sess->cred_info[i].realm, realm) == 0)
	    return &sess->cred_info[i];
	else if (sess->cred_info[i].realm.slen == 1 && sess->cred_info[i].realm.ptr[0] == '*')
	{
	    wildcard = i;
	}
    }

    
    if (wildcard != -1)
	return &sess->cred_info[wildcard];

    
    return NULL;
}



PJ_DEF(pj_status_t) pjsip_auth_clt_init(  pjsip_auth_clt_sess *sess, pjsip_endpoint *endpt, pj_pool_t *pool, unsigned options)


{
    PJ_ASSERT_RETURN(sess && endpt && pool && (options==0), PJ_EINVAL);

    sess->pool = pool;
    sess->endpt = endpt;
    sess->cred_cnt = 0;
    sess->cred_info = NULL;
    pj_list_init(&sess->cached_auth);

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjsip_auth_clt_deinit(pjsip_auth_clt_sess *sess)
{
    pjsip_cached_auth *auth;
    
    PJ_ASSERT_RETURN(sess && sess->endpt, PJ_EINVAL);
    
    auth = sess->cached_auth.next;
    while (auth != &sess->cached_auth) {
	pjsip_endpt_release_pool(sess->endpt, auth->pool);
	auth = auth->next;
    }

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjsip_auth_clt_clone( pj_pool_t *pool, pjsip_auth_clt_sess *sess, const pjsip_auth_clt_sess *rhs )

{
    unsigned i;

    PJ_ASSERT_RETURN(pool && sess && rhs, PJ_EINVAL);

    pjsip_auth_clt_init(sess, (pjsip_endpoint*)rhs->endpt, pool, 0);

    sess->cred_cnt = rhs->cred_cnt;
    sess->cred_info = (pjsip_cred_info*)
    		      pj_pool_alloc(pool, sess->cred_cnt*sizeof(pjsip_cred_info));
    for (i=0; i<rhs->cred_cnt; ++i) {
	pj_strdup(pool, &sess->cred_info[i].realm, &rhs->cred_info[i].realm);
	pj_strdup(pool, &sess->cred_info[i].scheme, &rhs->cred_info[i].scheme);
	pj_strdup(pool, &sess->cred_info[i].username, &rhs->cred_info[i].username);
	sess->cred_info[i].data_type = rhs->cred_info[i].data_type;
	pj_strdup(pool, &sess->cred_info[i].data, &rhs->cred_info[i].data);
    }

    
    PJ_TODO(FULL_CLONE_OF_AUTH_CLIENT_SESSION);

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjsip_auth_clt_set_credentials( pjsip_auth_clt_sess *sess, int cred_cnt, const pjsip_cred_info *c)

{
    PJ_ASSERT_RETURN(sess && c, PJ_EINVAL);

    if (cred_cnt == 0) {
	sess->cred_cnt = 0;
    } else {
	int i;
	sess->cred_info = (pjsip_cred_info*)
			  pj_pool_alloc(sess->pool, cred_cnt * sizeof(*c));
	for (i=0; i<cred_cnt; ++i) {
	    sess->cred_info[i].data_type = c[i].data_type;

	    
	    if ((c[i].data_type & EXT_MASK) == PJSIP_CRED_DATA_EXT_AKA) {


		if (!PJSIP_HAS_DIGEST_AKA_AUTH) {
		    pj_assert(!"PJSIP_HAS_DIGEST_AKA_AUTH is not enabled");
		    return PJSIP_EAUTHINAKACRED;
		}


		
		PJ_ASSERT_RETURN(c[i].ext.aka.cb != NULL, PJ_EINVAL);

		
		PJ_ASSERT_RETURN(c[i].ext.aka.k.slen <= PJSIP_AKA_KLEN, PJSIP_EAUTHINAKACRED);

		
		PJ_ASSERT_RETURN(c[i].ext.aka.op.slen <= PJSIP_AKA_OPLEN, PJSIP_EAUTHINAKACRED);

		
		PJ_ASSERT_RETURN(c[i].ext.aka.amf.slen <= PJSIP_AKA_AMFLEN, PJSIP_EAUTHINAKACRED);

		sess->cred_info[i].ext.aka.cb = c[i].ext.aka.cb;
		pj_strdup(sess->pool, &sess->cred_info[i].ext.aka.k, &c[i].ext.aka.k);
		pj_strdup(sess->pool, &sess->cred_info[i].ext.aka.op, &c[i].ext.aka.op);
		pj_strdup(sess->pool, &sess->cred_info[i].ext.aka.amf, &c[i].ext.aka.amf);
	    }

	    pj_strdup(sess->pool, &sess->cred_info[i].scheme, &c[i].scheme);
	    pj_strdup(sess->pool, &sess->cred_info[i].realm, &c[i].realm);
	    pj_strdup(sess->pool, &sess->cred_info[i].username, &c[i].username);
	    pj_strdup(sess->pool, &sess->cred_info[i].data, &c[i].data);
	}
	sess->cred_cnt = cred_cnt;
    }

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjsip_auth_clt_set_prefs(pjsip_auth_clt_sess *sess, const pjsip_auth_clt_pref *p)
{
    PJ_ASSERT_RETURN(sess && p, PJ_EINVAL);

    pj_memcpy(&sess->pref, p, sizeof(*p));
    pj_strdup(sess->pool, &sess->pref.algorithm, &p->algorithm);
    
    

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjsip_auth_clt_get_prefs(pjsip_auth_clt_sess *sess, pjsip_auth_clt_pref *p)
{
    PJ_ASSERT_RETURN(sess && p, PJ_EINVAL);

    pj_memcpy(p, &sess->pref, sizeof(pjsip_auth_clt_pref));
    return PJ_SUCCESS;
}



static pj_status_t auth_respond( pj_pool_t *req_pool, const pjsip_www_authenticate_hdr *hdr, const pjsip_uri *uri, const pjsip_cred_info *cred_info, const pjsip_method *method, pj_pool_t *sess_pool, pjsip_cached_auth *cached_auth, pjsip_authorization_hdr **p_h_auth)






{
    pjsip_authorization_hdr *hauth;
    char tmp[PJSIP_MAX_URL_SIZE];
    pj_str_t uri_str;
    pj_pool_t *pool;
    pj_status_t status;

    
    PJ_ASSERT_RETURN(req_pool && hdr && uri && cred_info && method && sess_pool && cached_auth && p_h_auth, PJ_EINVAL);

    
    uri_str.ptr = tmp;
    uri_str.slen = pjsip_uri_print(PJSIP_URI_IN_REQ_URI, uri, tmp,sizeof(tmp));
    if (uri_str.slen < 1) {
	return PJSIP_EURITOOLONG;
    }


    {
	pool = sess_pool;
	PJ_UNUSED_ARG(req_pool);
    }

    {
	pool = req_pool;
	PJ_UNUSED_ARG(sess_pool);
    }


    if (hdr->type == PJSIP_H_WWW_AUTHENTICATE)
	hauth = pjsip_authorization_hdr_create(pool);
    else if (hdr->type == PJSIP_H_PROXY_AUTHENTICATE)
	hauth = pjsip_proxy_authorization_hdr_create(pool);
    else {
	return PJSIP_EINVALIDHDR;
    }

    
    if (!pj_stricmp(&hdr->scheme, &pjsip_DIGEST_STR)) {
	pj_str_t *cnonce = NULL;
	pj_uint32_t nc = 1;

	

	{
	    if (cached_auth) {
		update_digest_session( cached_auth, hdr );

		cnonce = &cached_auth->cnonce;
		nc = cached_auth->nc;
	    }
	}


	hauth->scheme = pjsip_DIGEST_STR;
	status = respond_digest( pool, &hauth->credential.digest, &hdr->challenge.digest, &uri_str, cred_info, cnonce, nc, &method->name);

	if (status != PJ_SUCCESS)
	    return status;

	
	if (hdr->challenge.digest.qop.slen != 0 && cached_auth) {
	    if (cached_auth->qop_value == PJSIP_AUTH_QOP_NONE) {
		pj_str_t *qop_val = &hauth->credential.digest.qop;
		if (!pj_strcmp(qop_val, &pjsip_AUTH_STR)) {
		    cached_auth->qop_value = PJSIP_AUTH_QOP_AUTH;
		} else {
		    cached_auth->qop_value = PJSIP_AUTH_QOP_UNKNOWN;
		}
	    }
	}
    } else {
	return PJSIP_EINVALIDAUTHSCHEME;
    }

    

    {
	if (hauth && cached_auth && cached_auth->qop_value == PJSIP_AUTH_QOP_NONE) {
	    pjsip_cached_auth_hdr *cached_hdr;

	    
	    cached_hdr = cached_auth->cached_hdr.next;
	    while (cached_hdr != &cached_auth->cached_hdr) {
		if (pjsip_method_cmp(method, &cached_hdr->method)==0)
		    break;
		cached_hdr = cached_hdr->next;
	    }

	    
	    if (cached_hdr != &cached_auth->cached_hdr) {
		cached_hdr->hdr = hauth;
	    } else {
		cached_hdr = pj_pool_alloc(pool, sizeof(*cached_hdr));
		pjsip_method_copy( pool, &cached_hdr->method, method);
		cached_hdr->hdr = hauth;
		pj_list_insert_before( &cached_auth->cached_hdr, cached_hdr );
	    }
	}


	    if (hdr != cached_auth->last_chal) {
		cached_auth->last_chal = pjsip_hdr_clone(sess_pool, hdr);
	    }

    }


    *p_h_auth = hauth;
    return PJ_SUCCESS;

}



static pj_status_t new_auth_for_req( pjsip_tx_data *tdata, pjsip_auth_clt_sess *sess, pjsip_cached_auth *auth, pjsip_authorization_hdr **p_h_auth)


{
    const pjsip_cred_info *cred;
    pjsip_authorization_hdr *hauth;
    pj_status_t status;

    PJ_ASSERT_RETURN(tdata && sess && auth, PJ_EINVAL);
    PJ_ASSERT_RETURN(auth->last_chal != NULL, PJSIP_EAUTHNOPREVCHAL);

    cred = auth_find_cred( sess, &auth->realm, &auth->last_chal->scheme );
    if (!cred)
	return PJSIP_ENOCREDENTIAL;

    status = auth_respond( tdata->pool, auth->last_chal, tdata->msg->line.req.uri, cred, &tdata->msg->line.req.method, sess->pool, auth, &hauth);


    if (status != PJ_SUCCESS)
	return status;

    pjsip_msg_add_hdr( tdata->msg, (pjsip_hdr*)hauth);

    if (p_h_auth)
	*p_h_auth = hauth;

    return PJ_SUCCESS;
}




static pjsip_authorization_hdr* get_header_for_realm(const pjsip_hdr *hdr_list, const pj_str_t *realm)
{
    pjsip_authorization_hdr *h;

    h = (pjsip_authorization_hdr*)hdr_list->next;
    while (h != (pjsip_authorization_hdr*)hdr_list) {
	if (pj_stricmp(&h->credential.digest.realm, realm)==0)
	    return h;
	h = h->next;
    }

    return NULL;
}



PJ_DEF(pj_status_t) pjsip_auth_clt_init_req( pjsip_auth_clt_sess *sess, pjsip_tx_data *tdata )
{
    const pjsip_method *method;
    pjsip_cached_auth *auth;
    pjsip_hdr added;

    PJ_ASSERT_RETURN(sess && tdata, PJ_EINVAL);
    PJ_ASSERT_RETURN(sess->pool, PJSIP_ENOTINITIALIZED);
    PJ_ASSERT_RETURN(tdata->msg->type==PJSIP_REQUEST_MSG, PJSIP_ENOTREQUESTMSG);

    
    pj_list_init(&added);

    
    method = &tdata->msg->line.req.method;
    PJ_UNUSED_ARG(method); 

    auth = sess->cached_auth.next;
    while (auth != &sess->cached_auth) {
	
	auth->stale_cnt = 0;

	if (auth->qop_value == PJSIP_AUTH_QOP_NONE) {

	    {
		pjsip_cached_auth_hdr *entry = auth->cached_hdr.next;
		while (entry != &auth->cached_hdr) {
		    if (pjsip_method_cmp(&entry->method, method)==0) {
			pjsip_authorization_hdr *hauth;
			hauth = pjsip_hdr_shallow_clone(tdata->pool, entry->hdr);
			
			pj_list_push_back(&added, hauth);
			break;
		    }
		    entry = entry->next;
		}


		{
		    if (entry == &auth->cached_hdr)
			new_auth_for_req( tdata, sess, auth, NULL);
		}


	    }

	    {
		new_auth_for_req( tdata, sess, auth, NULL);
	    }


	}


	else if (auth->qop_value == PJSIP_AUTH_QOP_AUTH) {
	    
	    const pjsip_cred_info *cred;
	    pjsip_authorization_hdr *hauth;
	    pj_status_t status;

	    cred = auth_find_cred(sess, &auth->realm, &auth->last_chal->scheme);
	    if (!cred) {
		auth = auth->next;
		continue;
	    }

	    status = auth_respond( tdata->pool, auth->last_chal, tdata->msg->line.req.uri, cred, &tdata->msg->line.req.method, sess->pool, auth, &hauth);



	    if (status != PJ_SUCCESS)
		return status;

	    
	    pj_list_push_back(&added, hauth);
	}


	auth = auth->next;
    }

    if (sess->pref.initial_auth == PJ_FALSE) {
	pjsip_hdr *h;

	

	h = added.next;
	while (h != &added) {
	    pjsip_hdr *next = h->next;
	    pjsip_msg_add_hdr(tdata->msg, h);
	    h = next;
	}
    } else {
	
	unsigned i;
	pj_str_t uri;

	uri.ptr = (char*)pj_pool_alloc(tdata->pool, PJSIP_MAX_URL_SIZE);
	uri.slen = pjsip_uri_print(PJSIP_URI_IN_REQ_URI, tdata->msg->line.req.uri, uri.ptr, PJSIP_MAX_URL_SIZE);

	if (uri.slen < 1 || uri.slen >= PJSIP_MAX_URL_SIZE)
	    return PJSIP_EURITOOLONG;

	for (i=0; i<sess->cred_cnt; ++i) {
	    pjsip_cred_info *c = &sess->cred_info[i];
	    pjsip_authorization_hdr *h;

	    h = get_header_for_realm(&added, &c->realm);
	    if (h) {
		pj_list_erase(h);
		pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)h);
	    } else {
		pjsip_authorization_hdr *hs;

		hs = pjsip_authorization_hdr_create(tdata->pool);
		pj_strdup(tdata->pool, &hs->scheme, &c->scheme);
		if (pj_stricmp(&c->scheme, &pjsip_BEARER_STR)==0) {
			pj_strdup(tdata->pool, &hs->credential.oauth.username, &c->username);
                        pj_strdup(tdata->pool, &hs->credential.oauth.realm, &c->realm);
                        pj_strdup(tdata->pool, &hs->credential.oauth.token, &c->data);
		} else { 
			pj_strdup(tdata->pool, &hs->credential.digest.username, &c->username);
			pj_strdup(tdata->pool, &hs->credential.digest.realm, &c->realm);
			pj_strdup(tdata->pool,&hs->credential.digest.uri, &uri);
			pj_strdup(tdata->pool, &hs->credential.digest.algorithm, &sess->pref.algorithm);
		}

		pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)hs);
	    }
	}
    }

    return PJ_SUCCESS;
}


static void recreate_cached_auth_pool( pjsip_endpoint *endpt,  pjsip_cached_auth *auth )
{
    pj_pool_t *auth_pool = pjsip_endpt_create_pool(endpt, "auth_cli%p", 1024,  1024);

    if (auth->realm.slen) {
        pj_str_t realm;
        pj_strdup(auth_pool, &realm, &auth->realm);
        pj_strassign(&auth->realm, &realm);
    }

    if (auth->cnonce.slen) {
        pj_str_t cnonce;
        pj_strdup(auth_pool, &cnonce, &auth->cnonce);
        pj_strassign(&auth->cnonce, &cnonce);
    }

    if (auth->last_chal) {
        auth->last_chal = (pjsip_www_authenticate_hdr*)
			  pjsip_hdr_clone(auth_pool, auth->last_chal);
    }

    pjsip_endpt_release_pool(endpt, auth->pool);
    auth->pool = auth_pool;
}


static pj_status_t process_auth( pj_pool_t *req_pool, const pjsip_www_authenticate_hdr *hchal, const pjsip_uri *uri, pjsip_tx_data *tdata, pjsip_auth_clt_sess *sess, pjsip_cached_auth *cached_auth, pjsip_authorization_hdr **h_auth)





{
    const pjsip_cred_info *cred;
    pjsip_authorization_hdr *sent_auth = NULL;
    pjsip_hdr *hdr;
    pj_status_t status;

    
    hdr = tdata->msg->hdr.next;
    while (hdr != &tdata->msg->hdr) {
	if ((hchal->type == PJSIP_H_WWW_AUTHENTICATE && hdr->type == PJSIP_H_AUTHORIZATION) || (hchal->type == PJSIP_H_PROXY_AUTHENTICATE && hdr->type == PJSIP_H_PROXY_AUTHORIZATION))


	{
	    sent_auth = (pjsip_authorization_hdr*) hdr;
	    if (pj_stricmp(&hchal->challenge.common.realm, &sent_auth->credential.common.realm)==0 && pj_stricmp(&hchal->scheme, &sent_auth->scheme)==0)

	    {
		
		if (pj_stricmp(&sent_auth->scheme, &pjsip_DIGEST_STR)==0 && sent_auth->credential.digest.response.slen == 0)
		{
		    
		    hdr = hdr->next;
		    pj_list_erase(sent_auth);
		    continue;
		} else if (pj_stricmp(&sent_auth->scheme, &pjsip_DIGEST_STR)==0 && pj_stricmp(&sent_auth->credential.digest.algorithm, &hchal->challenge.digest.algorithm)!=0)


		{
		    
		    hdr = hdr->next;
		    continue;
		} else {
		    
		    break;
		}
	    }
	}
	hdr = hdr->next;
    }

    
    if (hdr != &tdata->msg->hdr) {
	pj_bool_t stale;

	
	stale = hchal->challenge.digest.stale;
	if (!stale) {
	    
	    stale = pj_strcmp(&hchal->challenge.digest.nonce, &sent_auth->credential.digest.nonce);
	}

	if (stale == PJ_FALSE) {
	    
	    PJ_LOG(4, (THIS_FILE, "Authorization failed for %.*s@%.*s: " "server rejected with stale=false", sent_auth->credential.digest.username.slen, sent_auth->credential.digest.username.ptr, sent_auth->credential.digest.realm.slen, sent_auth->credential.digest.realm.ptr));




	    return PJSIP_EFAILEDCREDENTIAL;
	}

	cached_auth->stale_cnt++;
	if (cached_auth->stale_cnt >= PJSIP_MAX_STALE_COUNT) {
	    
	    PJ_LOG(4, (THIS_FILE, "Authorization failed for %.*s@%.*s: " "maximum number of stale retries exceeded", sent_auth->credential.digest.username.slen, sent_auth->credential.digest.username.ptr, sent_auth->credential.digest.realm.slen, sent_auth->credential.digest.realm.ptr));




	    return PJSIP_EAUTHSTALECOUNT;
	}

	
	pj_list_erase(sent_auth);
    }

    
    cred = auth_find_cred( sess, &hchal->challenge.common.realm, &hchal->scheme);
    if (!cred) {
	const pj_str_t *realm = &hchal->challenge.common.realm;
	PJ_LOG(4,(THIS_FILE, "Unable to set auth for %s: can not find credential for %.*s/%.*s", tdata->obj_name, realm->slen, realm->ptr, hchal->scheme.slen, hchal->scheme.ptr));



	return PJSIP_ENOCREDENTIAL;
    }

    
    status = auth_respond( req_pool, hchal, uri, cred, &tdata->msg->line.req.method, sess->pool, cached_auth, h_auth);

    return status;
}



PJ_DEF(pj_status_t) pjsip_auth_clt_reinit_req(	pjsip_auth_clt_sess *sess, const pjsip_rx_data *rdata, pjsip_tx_data *old_request, pjsip_tx_data **new_request )


{
    pjsip_tx_data *tdata;
    const pjsip_hdr *hdr;
    unsigned chal_cnt, auth_cnt;
    pjsip_via_hdr *via;
    pj_status_t status;
    pj_status_t last_auth_err;

    PJ_ASSERT_RETURN(sess && rdata && old_request && new_request, PJ_EINVAL);
    PJ_ASSERT_RETURN(sess->pool, PJSIP_ENOTINITIALIZED);
    PJ_ASSERT_RETURN(rdata->msg_info.msg->type == PJSIP_RESPONSE_MSG, PJSIP_ENOTRESPONSEMSG);
    PJ_ASSERT_RETURN(old_request->msg->type == PJSIP_REQUEST_MSG, PJSIP_ENOTREQUESTMSG);
    PJ_ASSERT_RETURN(rdata->msg_info.msg->line.status.code == 401 || rdata->msg_info.msg->line.status.code == 407, PJSIP_EINVALIDSTATUS);


    tdata = old_request;
    tdata->auth_retry = PJ_FALSE;

    
    hdr = rdata->msg_info.msg->hdr.next;
    chal_cnt = 0;
    auth_cnt = 0;
    last_auth_err = PJSIP_EAUTHNOAUTH;
    while (hdr != &rdata->msg_info.msg->hdr && auth_cnt == 0) {
	pjsip_cached_auth *cached_auth;
	const pjsip_www_authenticate_hdr *hchal;
	pjsip_authorization_hdr *hauth;

	
	while (hdr != &rdata->msg_info.msg->hdr && hdr->type != PJSIP_H_WWW_AUTHENTICATE && hdr->type != PJSIP_H_PROXY_AUTHENTICATE)

	{
	    hdr = hdr->next;
	}
	if (hdr == &rdata->msg_info.msg->hdr)
	    break;

	hchal = (const pjsip_www_authenticate_hdr*)hdr;
	++chal_cnt;

	
	cached_auth = find_cached_auth(sess, &hchal->challenge.common.realm);
	if (!cached_auth) {
	    cached_auth = PJ_POOL_ZALLOC_T(sess->pool, pjsip_cached_auth);
	    cached_auth->pool = pjsip_endpt_create_pool(sess->endpt, "auth_cli%p", 1024, 1024);


	    pj_strdup(cached_auth->pool, &cached_auth->realm, &hchal->challenge.common.realm);
	    cached_auth->is_proxy = (hchal->type == PJSIP_H_PROXY_AUTHENTICATE);

	    {
		pj_list_init(&cached_auth->cached_hdr);
	    }

	    pj_list_insert_before(&sess->cached_auth, cached_auth);
	}

	
	status = process_auth(tdata->pool, hchal, tdata->msg->line.req.uri, tdata, sess, cached_auth, &hauth);
	if (status != PJ_SUCCESS) {
	    last_auth_err = status;

	    
	    hdr = hdr->next;
	    continue;
	}

	if (pj_pool_get_used_size(cached_auth->pool) > PJSIP_AUTH_CACHED_POOL_MAX_SIZE)
	{
	    recreate_cached_auth_pool(sess->endpt, cached_auth);
	}	

	
	pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr*)hauth);

	
	hdr = hdr->next;
	auth_cnt++;
    }

    
    if (chal_cnt == 0)
	return PJSIP_EAUTHNOCHAL;

    
    if (auth_cnt == 0)
	return last_auth_err;

    
    via = (pjsip_via_hdr*) pjsip_msg_find_hdr(tdata->msg, PJSIP_H_VIA, NULL);
    via->branch_param.slen = 0;

    
    pjsip_restore_strict_route_set(tdata);

    
    pjsip_tx_data_invalidate_msg(tdata);

    
    tdata->auth_retry = PJ_TRUE;

    
    pjsip_tx_data_add_ref(tdata);

    
    *new_request = tdata;
    return PJ_SUCCESS;

}

