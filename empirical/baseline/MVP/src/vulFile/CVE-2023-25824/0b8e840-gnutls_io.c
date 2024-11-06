






APLOG_USE_MODULE(gnutls);
















static inline void gnutls_io_filter_eos(ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_bucket *bucket = apr_bucket_eos_create(f->c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, bucket);
}



static int char_buffer_read(mgs_char_buffer_t * buffer, char *in, int inl) {
    if (!buffer->length) {
        return 0;
    }

    if (buffer->length > inl) {
        
        memmove(in, buffer->value, inl);
        buffer->value += inl;
        buffer->length -= inl;
    } else {
        
        memmove(in, buffer->value, buffer->length);
        inl = buffer->length;
        buffer->value = NULL;
        buffer->length = 0;
    }

    return inl;
}

static int char_buffer_write(mgs_char_buffer_t * buffer, char *in, int inl) {
    buffer->value = in;
    buffer->length = inl;
    return inl;
}


static apr_status_t brigade_consume(apr_bucket_brigade * bb, apr_read_type_e block, char *c, apr_size_t * len) {

    apr_size_t actual = 0;
    apr_status_t status = APR_SUCCESS;

    while (!APR_BRIGADE_EMPTY(bb)) {
        apr_bucket *b = APR_BRIGADE_FIRST(bb);
        const char *str;
        apr_size_t str_len;

        
        if (APR_BUCKET_IS_EOS(b)) {
            status = APR_EOF;
            break;
        }

        
        status = apr_bucket_read(b, &str, &str_len, block);

        if (status != APR_SUCCESS) {
            if (APR_STATUS_IS_EOF(status)) {
                
                apr_bucket_delete(b);
                continue;
            }
            break;
        }

        if (str_len > 0) {
            
            block = APR_NONBLOCK_READ;

            
            apr_size_t consume = (str_len + actual > *len) ? *len - actual : str_len;

            memcpy(c, str, consume);

            c += consume;
            actual += consume;

            if (consume >= b->length) {
                
                apr_bucket_delete(b);
            } else {
                
                b->start += consume;
                b->length -= consume;
            }
        } else if (b->length == 0) {
            apr_bucket_delete(b);
        }

        
        if (actual >= *len) {
            break;
        }
    }

    *len = actual;
    return status;
}

static apr_status_t gnutls_io_input_read(mgs_handle_t * ctxt, char *buf, apr_size_t * len)
{
    apr_size_t wanted = *len;
    apr_size_t bytes = 0;

    *len = 0;

    
    if ((bytes = char_buffer_read(&ctxt->input_cbuf, buf, wanted))) {
        *len = bytes;
        if (ctxt->input_mode == AP_MODE_SPECULATIVE) {
            
            if (ctxt->input_cbuf.length > 0) {
                ctxt->input_cbuf.value -= bytes;
                ctxt->input_cbuf.length += bytes;
            } else {
                char_buffer_write(&ctxt->input_cbuf, buf, (int) bytes);
            }
            return APR_SUCCESS;
        }
        
        if (*len >= wanted) {
            return APR_SUCCESS;
        }
        if (ctxt->input_mode == AP_MODE_GETLINE) {
            if (memchr(buf, APR_ASCII_LF, *len)) {
                return APR_SUCCESS;
            }
        } else {
            
            ctxt->input_block = APR_NONBLOCK_READ;
        }
    }

    if (ctxt->session == NULL) {
        ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, ctxt->c, "%s: GnuTLS session is NULL!", __func__);
        return APR_EGENERAL;
    }

    while (1)
    {
        
        int rc = gnutls_record_recv(ctxt->session, buf + bytes, wanted - bytes);

        if (rc > 0) {
            *len += rc;
            if (ctxt->input_mode == AP_MODE_SPECULATIVE) {
                
                char_buffer_write(&ctxt->input_cbuf, buf, *len);
            }
            return ctxt->input_rc;
        } else if (rc == 0) {
            
            if (*len > 0) {
                ctxt->input_rc = APR_SUCCESS;
            } else {
                ctxt->input_rc = APR_EOF;
            }
            break;
        } else { 

            if (rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN)
            {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE2, ctxt->input_rc, ctxt->c, "%s: looping recv after '%s' (%d)", __func__, gnutls_strerror(rc), rc);

                
                if (ctxt->input_block != APR_NONBLOCK_READ)
                    continue;
                else ctxt->input_rc = (rc == GNUTLS_E_AGAIN ? APR_EAGAIN : APR_EINTR);

            } else if (rc == GNUTLS_E_REHANDSHAKE) {
                
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, ctxt->input_rc, ctxt->c, "GnuTLS: Error reading data. Client Requested a New Handshake." " (%d) '%s'", rc, gnutls_strerror(rc));




            } else if (rc == GNUTLS_E_WARNING_ALERT_RECEIVED) {
                rc = gnutls_alert_get(ctxt->session);
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, ctxt->input_rc, ctxt->c, "GnuTLS: Warning Alert From Client: " " (%d) '%s'", rc, gnutls_alert_get_name(rc));




            } else if (rc == GNUTLS_E_FATAL_ALERT_RECEIVED) {
                rc = gnutls_alert_get(ctxt->session);
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, ctxt->input_rc, ctxt->c, "GnuTLS: Fatal Alert From Client: " "(%d) '%s'", rc, gnutls_alert_get_name(rc));




                ctxt->input_rc = APR_EGENERAL;
                break;
            } else {
                
                if (gnutls_error_is_fatal(rc)) {
                    ap_log_cerror( APLOG_MARK, APLOG_DEBUG, ctxt->input_rc, ctxt->c, "GnuTLS: Error reading data. (%d) '%s'", rc, gnutls_strerror(rc));




                } else if (*len > 0) {
                    ctxt->input_rc = APR_SUCCESS;
                    break;
                }
            }

            if (ctxt->input_rc == APR_SUCCESS) {
                ap_log_cerror(APLOG_MARK, APLOG_INFO, ctxt->input_rc, ctxt->c, "%s: GnuTLS error: %s (%d)", __func__, gnutls_strerror(rc), rc);

                ctxt->input_rc = APR_EGENERAL;
            }
            break;
        }
    }
    return ctxt->input_rc;
}

static apr_status_t gnutls_io_input_getline(mgs_handle_t * ctxt, char *buf, apr_size_t * len) {
    const char *pos = NULL;
    apr_size_t tmplen = *len, buflen = *len, offset = 0;

    *len = 0;

    while (tmplen > 0)
    {
        apr_status_t status = gnutls_io_input_read(ctxt, buf + offset, &tmplen);

        if (status != APR_SUCCESS) {
            return status;
        }

        *len += tmplen;

        if ((pos = memchr(buf, APR_ASCII_LF, *len))) {
            break;
        }

        offset += tmplen;
        tmplen = buflen - offset;
    }

    if (pos) {
        char *value;
        int length;
        apr_size_t bytes = pos - buf;

        bytes += 1;
        value = buf + bytes;
        length = *len - bytes;

        char_buffer_write(&ctxt->input_cbuf, value, length);

        *len = bytes;
    }

    return APR_SUCCESS;
}



static int gnutls_do_handshake(mgs_handle_t * ctxt) {
    int ret;
    int errcode;
    int maxtries = HANDSHAKE_MAX_TRIES;

    if (ctxt->status != 0 || ctxt->session == NULL) {
        return -1;
    }

    
    if (ctxt->is_proxy == GNUTLS_ENABLED_TRUE)
        mgs_set_proxy_handshake_ext(ctxt);

tryagain:
    do {
        ret = gnutls_handshake(ctxt->session);
        maxtries--;
    } while ((ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN)
            && maxtries > 0);

    if (maxtries < 1) {
        ctxt->status = -1;
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, ctxt->c, "GnuTLS: Handshake Failed. Hit Maximum Attempts");
        if (ctxt->session) {
            gnutls_alert_send(ctxt->session, GNUTLS_AL_FATAL, gnutls_error_to_alert (GNUTLS_E_INTERNAL_ERROR, NULL));

            gnutls_deinit(ctxt->session);
        }
        ctxt->session = NULL;
        return -1;
    }

    if (ret < 0) {
        if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED || ret == GNUTLS_E_FATAL_ALERT_RECEIVED) {
            errcode = gnutls_alert_get(ctxt->session);
            ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, ctxt->c, "GnuTLS: Handshake Alert (%d) '%s'.", errcode, gnutls_alert_get_name(errcode));

        }

        if (!gnutls_error_is_fatal(ret)) {
            ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, ctxt->c, "GnuTLS: Non-Fatal Handshake Error: (%d) '%s'", ret, gnutls_strerror(ret));

            goto tryagain;
        }
        ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, ctxt->c, "GnuTLS: Handshake Failed (%d) '%s'", ret, gnutls_strerror(ret));

        ctxt->status = -1;
        if (ctxt->session) {
            gnutls_alert_send(ctxt->session, GNUTLS_AL_FATAL, gnutls_error_to_alert(ret, NULL));

            gnutls_deinit(ctxt->session);
        }
        ctxt->session = NULL;
        return ret;
    } else {
        
        ctxt->status = 1;
        if (gnutls_session_is_resumed(ctxt->session))
        {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, ctxt->c, "%s: TLS session resumed.", __func__);
        }
        return GNUTLS_E_SUCCESS;
    }
}



int mgs_reauth(mgs_handle_t *ctxt, request_rec *r)
{
    if (ctxt->session == NULL)
        return GNUTLS_E_INVALID_REQUEST;

    
    int rv = GNUTLS_E_INTERNAL_ERROR;
    int tries = 0;

    do {
        rv = gnutls_reauth(ctxt->session, 0);
        tries++;

        
        if (rv == GNUTLS_E_GOT_APPLICATION_DATA)
        {
            
            apr_size_t len = sizeof(ctxt->input_buffer);
            ctxt->input_mode = AP_MODE_SPECULATIVE;
            apr_status_t status = gnutls_io_input_read(ctxt, ctxt->input_buffer, &len);
            if (status == APR_SUCCESS)
            {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r, "%s: cached %" APR_SIZE_T_FMT " bytes.", __func__, len);

                
                rv = gnutls_reauth(ctxt->session, 0);
            }
            else ap_log_rerror(APLOG_MARK, APLOG_INFO, status, r, "%s: buffering request data failed!", __func__);


        }
        
    } while (tries < HANDSHAKE_MAX_TRIES && (rv == GNUTLS_E_INTERRUPTED || rv == GNUTLS_E_AGAIN));

    if (rv != GNUTLS_E_SUCCESS)
    {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "%s: post-handshake authentication failed: %s (%d)", __func__, gnutls_strerror(rv), rv);

        return rv;
    }

    return GNUTLS_E_SUCCESS;
}




static int mgs_bye(mgs_handle_t* ctxt)
{
    int ret = GNUTLS_E_SUCCESS;
    
    if (ctxt->session != NULL)
    {
        
        do {
            ret = gnutls_bye(ctxt->session, GNUTLS_SHUT_WR);
        } while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);
        if (ret != GNUTLS_E_SUCCESS)
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_EGENERAL, ctxt->c, "%s: Error while closing TLS %sconnection: " "'%s' (%d)", __func__, IS_PROXY_STR(ctxt), gnutls_strerror(ret), (int) ret);



        else ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, ctxt->c, "%s: TLS %sconnection closed.", __func__, IS_PROXY_STR(ctxt));


        
        gnutls_deinit(ctxt->session);
        ctxt->session = NULL;
    }
    return ret;
}



apr_status_t mgs_filter_input(ap_filter_t * f, apr_bucket_brigade * bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)


{
    apr_status_t status = APR_SUCCESS;
    mgs_handle_t *ctxt = (mgs_handle_t *) f->ctx;
    apr_size_t len = sizeof (ctxt->input_buffer);

    if (f->c->aborted) {
        gnutls_io_filter_eos(f, bb);
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, ctxt->c, "%s: %sconnection aborted", __func__, IS_PROXY_STR(ctxt));

        return APR_ECONNABORTED;
    }

    if (ctxt->status == 0) {
        int ret = gnutls_do_handshake(ctxt);
        if (ret == GNUTLS_E_SUCCESS)
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, ctxt->c, "%s: TLS %sconnection opened.", __func__, IS_PROXY_STR(ctxt));

    }

    if (ctxt->status < 0)
    {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, ctxt->c, "%s: %sconnection failed, cannot provide data!", __func__, IS_PROXY_STR(ctxt));

        gnutls_io_filter_eos(f, bb);
        return APR_ECONNABORTED;
    }

    
    if (mode != AP_MODE_READBYTES && mode != AP_MODE_GETLINE && mode != AP_MODE_SPECULATIVE && mode != AP_MODE_INIT) {
        return APR_ENOTIMPL;
    }

    ctxt->input_mode = mode;
    ctxt->input_block = block;

    if (ctxt->input_mode == AP_MODE_READBYTES || ctxt->input_mode == AP_MODE_SPECULATIVE) {
        if (readbytes < 0) {
            
            return APR_ENOTIMPL;
        }
        

        if ((apr_size_t) readbytes < len)
        {
            
            if (__builtin_expect(imaxabs(readbytes) > SIZE_MAX, 0))
            {
                ap_log_cerror(APLOG_MARK, APLOG_CRIT, APR_EINVAL, ctxt->c, "%s: prevented buffer length overflow", __func__);

                return APR_EINVAL;
            }
            len = (apr_size_t) readbytes;
        }

        if ((apr_size_t) readbytes < len && __builtin_add_overflow(readbytes, 0, &len))
        {
            ap_log_cerror(APLOG_MARK, APLOG_CRIT, APR_EINVAL, ctxt->c, "%s: prevented buffer length overflow", __func__);

            return APR_EINVAL;
        }

        status = gnutls_io_input_read(ctxt, ctxt->input_buffer, &len);
    } else if (ctxt->input_mode == AP_MODE_GETLINE) {
        status = gnutls_io_input_getline(ctxt, ctxt->input_buffer, &len);

    } else {
        
        return APR_ENOTIMPL;
    }

    if (status != APR_SUCCESS)
    {
        
        if ((block == APR_NONBLOCK_READ) && APR_STATUS_IS_EINTR(status))
            return APR_EAGAIN;

        
        if (APR_STATUS_IS_EOF(status))
            mgs_bye(ctxt);

        gnutls_io_filter_eos(f, bb);
        return status;
    }

    
    if (len > 0) {
        apr_bucket *bucket = apr_bucket_transient_create(ctxt->input_buffer, len, f->c->bucket_alloc);

        APR_BRIGADE_INSERT_TAIL(bb, bucket);
    }

    return status;
}


static ssize_t write_flush(mgs_handle_t * ctxt) {
    apr_bucket *e;

    if (!(ctxt->output_blen || ctxt->output_length)) {
        ctxt->output_rc = APR_SUCCESS;
        return 1;
    }

    if (ctxt->output_blen) {
        e = apr_bucket_transient_create(ctxt->output_buffer, ctxt->output_blen, ctxt->output_bb-> bucket_alloc);


        
        APR_BRIGADE_INSERT_HEAD(ctxt->output_bb, e);
        ctxt->output_blen = 0;
    }

    ctxt->output_length = 0;
    e = apr_bucket_flush_create(ctxt->output_bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(ctxt->output_bb, e);

    ctxt->output_rc = ap_pass_brigade(ctxt->output_filter->next, ctxt->output_bb);
    
    apr_brigade_cleanup(ctxt->output_bb);

    return (ctxt->output_rc == APR_SUCCESS) ? 1 : -1;
}

apr_status_t mgs_filter_output(ap_filter_t * f, apr_bucket_brigade * bb) {
    int ret;
    mgs_handle_t *ctxt = (mgs_handle_t *) f->ctx;
    apr_status_t status = APR_SUCCESS;
    apr_read_type_e rblock = APR_NONBLOCK_READ;

    if (f->c->aborted) {
        apr_brigade_cleanup(bb);
        return APR_ECONNABORTED;
    }

    if (ctxt->status == 0) {
        ret = gnutls_do_handshake(ctxt);
        if (ret == GNUTLS_E_SUCCESS)
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, ctxt->c, "%s: TLS %sconnection opened.", __func__, IS_PROXY_STR(ctxt));

        else if (ctxt->is_proxy)
        {
            
            gnutls_io_filter_eos(f, bb);
            return APR_SUCCESS;
        }
        
    }

    if (ctxt->status < 0)
    {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, ctxt->c, "%s: %sconnection failed, refusing to send.", __func__, IS_PROXY_STR(ctxt));

        return APR_ECONNABORTED;
    }

    while (!APR_BRIGADE_EMPTY(bb)) {
        apr_bucket *bucket = APR_BRIGADE_FIRST(bb);

        if (APR_BUCKET_IS_EOS(bucket)) {
            return ap_pass_brigade(f->next, bb);
        } else if (APR_BUCKET_IS_FLUSH(bucket)) {
            
            if (write_flush(ctxt) < 0) {
                
                return ctxt->output_rc;
            }
            
            apr_bucket_delete(bucket);
        } else if (AP_BUCKET_IS_EOC(bucket)) {
            
            mgs_bye(ctxt);
            
            apr_bucket_delete(bucket);
            
            return ap_pass_brigade(f->next, bb);
        } else {
            
            const char *data;
            apr_size_t len;

            status = apr_bucket_read(bucket, &data, &len, rblock);

            if (APR_STATUS_IS_EAGAIN(status)) {
                
                if (write_flush(ctxt) < 0) {
                    return ctxt->output_rc;
                }
                
                rblock = APR_BLOCK_READ;
                continue;
            }

            rblock = APR_NONBLOCK_READ;

            if (!APR_STATUS_IS_EOF(status)
                    && (status != APR_SUCCESS)) {
                return status;
            }

            if (len > 0) {

                if (ctxt->session == NULL) {
                    ret = GNUTLS_E_INVALID_REQUEST;
                } else {
                    do {
                        ret = gnutls_record_send (ctxt->session, data, len);


                    } while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);
                }

                if (ret < 0) {
                    
                    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, ctxt->output_rc, ctxt->c, "GnuTLS: Error writing data. (%d) '%s'", ret, gnutls_strerror(ret));


                    if (ctxt->output_rc == APR_SUCCESS) {
                        ctxt->output_rc = APR_EGENERAL;
                        return ctxt->output_rc;
                    }
                } else if ((apr_size_t)(ret) != len) {
                    
                    
                    apr_bucket_split(bucket, ret);
                }
            }

            apr_bucket_delete(bucket);
        }
    }

    return status;
}

int mgs_transport_read_ready(gnutls_transport_ptr_t ptr, unsigned int ms)
{
    mgs_handle_t *ctxt = ptr;
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, APR_SUCCESS, ctxt->c, "%s: called with %u ms wait", __func__, ms);

    apr_pool_t *tmp = NULL;
    apr_status_t rv = apr_pool_create(&tmp, ctxt->c->pool);
    if (rv != APR_SUCCESS)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_ENOMEM, ctxt->c, "could not create temporary pool for %s", __func__);

        return -1;
    }

    apr_bucket_brigade *bb = apr_brigade_create(tmp, ctxt->c->bucket_alloc);

    
    rv = ap_get_brigade(ctxt->input_filter->next, bb, AP_MODE_SPECULATIVE, APR_NONBLOCK_READ, 1);

    int result;
    if (rv == APR_SUCCESS && !APR_BRIGADE_EMPTY(bb))
        result = 1;
    else result = 0;

    apr_brigade_destroy(bb);

    
    if (ms == 0 || result == 1)
    {
        apr_pool_destroy(tmp);
        return result;
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, APR_SUCCESS, ctxt->c, "%s: waiting for data", __func__);

    
    apr_socket_t *sock = ap_get_conn_socket(ctxt->c);
    apr_interval_time_t timeout = -1;
    apr_interval_time_t original_timeout;
    rv = apr_socket_timeout_get(sock, &original_timeout);
    if (rv != APR_SUCCESS)
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, ctxt->c, "%s: could not get socket timeout", __func__);

        apr_pool_destroy(tmp);
        return -1;
    }

    
    if (ms != GNUTLS_INDEFINITE_TIMEOUT)
    {
        
        if (__builtin_mul_overflow(ms, 1000, &timeout))
        {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_ENOMEM, ctxt->c, "%s: overflow while calculating timeout!", __func__);

            apr_pool_destroy(tmp);
            return -1;
        }
        rv = apr_socket_timeout_set(sock, timeout);
        if (rv != APR_SUCCESS)
        {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, ctxt->c, "%s: could not set socket timeout", __func__);

            apr_pool_destroy(tmp);
            return -1;
        }
    }


    apr_pollfd_t pollset;
    apr_int32_t nsds;
    pollset.p = tmp;
    pollset.desc_type = APR_POLL_SOCKET;
    pollset.reqevents = APR_POLLIN | APR_POLLHUP;
    pollset.desc.s = sock;
    rv = apr_poll(&pollset, 1, &nsds, timeout);

    rv = apr_socket_wait(sock, APR_WAIT_READ);

    apr_pool_destroy(tmp);

    if (ms != GNUTLS_INDEFINITE_TIMEOUT)
    {
        
        apr_status_t rc = apr_socket_timeout_set(sock, original_timeout);
        if (rc != APR_SUCCESS)
        {
            ap_log_cerror(APLOG_MARK, APLOG_CRIT, rc, ctxt->c, "%s: could not restore socket timeout", __func__);

            return -1;
        }
    }

    if (rv == APR_SUCCESS)
        return 1;
    else if (APR_STATUS_IS_TIMEUP(rv))
        return 0;
    else {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, ctxt->c, "%s: waiting for data on connection socket failed", __func__);

        return -1;
    }
}


ssize_t mgs_transport_read(gnutls_transport_ptr_t ptr, void *buffer, size_t len)
{
    mgs_handle_t *ctxt = ptr;
    apr_size_t in = len;
    apr_read_type_e block = ctxt->input_block;

    ctxt->input_rc = APR_SUCCESS;

    
    if (!len || buffer == NULL)
    {
        return 0;
    }
    
    if (!ctxt->input_bb)
    {
        ctxt->input_rc = APR_EOF;
        gnutls_transport_set_errno(ctxt->session, ECONNABORTED);
        return -1;
    }

    if (APR_BRIGADE_EMPTY(ctxt->input_bb))
    {
        apr_status_t rc = ap_get_brigade(ctxt->input_filter->next, ctxt->input_bb, AP_MODE_READBYTES, ctxt->input_block, in);


        
        if (APR_STATUS_IS_EAGAIN(rc) || APR_STATUS_IS_EINTR(rc)
            || (rc == APR_SUCCESS && APR_BRIGADE_EMPTY(ctxt->input_bb)))
        {
            
            ctxt->input_rc = (rc != APR_SUCCESS ? rc : APR_EINTR);
            gnutls_transport_set_errno(ctxt->session, EAI_APR_TO_RAW(ctxt->input_rc));
            return -1;
        }

        
        if (ctxt->input_block == APR_BLOCK_READ && APR_STATUS_IS_TIMEUP(rc)
            && APR_BRIGADE_EMPTY(ctxt->input_bb))
        {
            ctxt->input_rc = rc;
            gnutls_transport_set_errno(ctxt->session, EAGAIN);
            return -1;
        }

        if (rc != APR_SUCCESS)
        {
            
            ap_log_cerror(APLOG_MARK, APLOG_INFO, rc, ctxt->c, "%s: Unexpected error!", __func__);
            apr_brigade_cleanup(ctxt->input_bb);
            ctxt->input_bb = NULL;
            gnutls_transport_set_errno(ctxt->session, EIO);
            return -1;
        }
    }

    ctxt->input_rc = brigade_consume(ctxt->input_bb, block, buffer, &len);

    if (ctxt->input_rc == APR_SUCCESS)
    {
        return (ssize_t) len;
    }

    if (APR_STATUS_IS_EAGAIN(ctxt->input_rc)
        || APR_STATUS_IS_EINTR(ctxt->input_rc))
    {
        if (len == 0)
        {
            gnutls_transport_set_errno(ctxt->session, EAI_APR_TO_RAW(ctxt->input_rc));
            return -1;
        }

        return (ssize_t) len;
    }

    
    apr_brigade_cleanup(ctxt->input_bb);
    ctxt->input_bb = NULL;

    if (APR_STATUS_IS_EOF(ctxt->input_rc) && len)
    {
        
        return (ssize_t) len;
    }

    gnutls_transport_set_errno(ctxt->session, EIO);
    return -1;
}


ssize_t mgs_transport_write(gnutls_transport_ptr_t ptr, const void *buffer, size_t len)
{
    mgs_handle_t *ctxt = ptr;

    
    apr_bucket *bucket = apr_bucket_transient_create(buffer, len, ctxt->output_bb-> bucket_alloc);

    ctxt->output_length += len;
    APR_BRIGADE_INSERT_TAIL(ctxt->output_bb, bucket);

    if (write_flush(ctxt) < 0)
    {
        
        int err = EIO;
        if (APR_STATUS_IS_EAGAIN(ctxt->output_rc)
            || APR_STATUS_IS_EINTR(ctxt->output_rc))
            err = EAI_APR_TO_RAW(ctxt->output_rc);

        gnutls_transport_set_errno(ctxt->session, err);
        return -1;
    }
    return len;
}
