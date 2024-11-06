









int ldbm_back_bind(Slapi_PBlock *pb)
{
    backend *be;
    ldbm_instance *inst;
    ber_tag_t method;
    struct berval *cred;
    struct ldbminfo *li;
    struct backentry *e;
    Slapi_Attr *attr;
    Slapi_Value **bvals;
    entry_address *addr;
    back_txn txn = {NULL};
    int rc = SLAPI_BIND_SUCCESS;
    int result_sent = 0;

    
    slapi_pblock_get(pb, SLAPI_BACKEND, &be);
    slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &li);
    slapi_pblock_get(pb, SLAPI_TARGET_ADDRESS, &addr);
    slapi_pblock_get(pb, SLAPI_BIND_METHOD, &method);
    slapi_pblock_get(pb, SLAPI_BIND_CREDENTIALS, &cred);
    slapi_pblock_get(pb, SLAPI_TXN, &txn.back_txn_txn);

    if (!txn.back_txn_txn) {
        dblayer_txn_init(li, &txn);
        slapi_pblock_set(pb, SLAPI_TXN, txn.back_txn_txn);
    }

    inst = (ldbm_instance *)be->be_instance_info;
    if (inst->inst_ref_count) {
        slapi_counter_increment(inst->inst_ref_count);
    } else {
        slapi_log_err(SLAPI_LOG_ERR, "ldbm_back_bind", "instance %s does not exist.\n", inst->inst_name);
        return (SLAPI_BIND_FAIL);
    }

    
    if (method == LDAP_AUTH_SIMPLE && cred->bv_len == 0) {
        rc = SLAPI_BIND_ANONYMOUS;
        goto bail;
    }

    
    if ((e = find_entry(pb, be, addr, &txn, &result_sent)) == NULL) {
        rc = SLAPI_BIND_FAIL;
        
        if (!result_sent) {
            slapi_send_ldap_result(pb, LDAP_INAPPROPRIATE_AUTH, NULL, NULL, 0, NULL);
        }
        goto bail;
    }

    switch (method) {
    case LDAP_AUTH_SIMPLE: {
        Slapi_Value cv;
        if (slapi_entry_attr_find(e->ep_entry, "userpassword", &attr) != 0) {
            slapi_send_ldap_result(pb, LDAP_INAPPROPRIATE_AUTH, NULL, NULL, 0, NULL);
            CACHE_RETURN(&inst->inst_cache, &e);
            rc = SLAPI_BIND_FAIL;
            goto bail;
        }
        bvals = attr_get_present_values(attr);
        slapi_value_init_berval(&cv, cred);
        if (slapi_pw_find_sv(bvals, &cv) != 0) {
            slapi_pblock_set(pb, SLAPI_PB_RESULT_TEXT, "Invalid credentials");
            slapi_send_ldap_result(pb, LDAP_INVALID_CREDENTIALS, NULL, NULL, 0, NULL);
            CACHE_RETURN(&inst->inst_cache, &e);
            value_done(&cv);
            rc = SLAPI_BIND_FAIL;
            goto bail;
        }
        value_done(&cv);
    } break;

    default:
        slapi_send_ldap_result(pb, LDAP_STRONG_AUTH_NOT_SUPPORTED, NULL, "auth method not supported", 0, NULL);
        CACHE_RETURN(&inst->inst_cache, &e);
        rc = SLAPI_BIND_FAIL;
        goto bail;
    }

    CACHE_RETURN(&inst->inst_cache, &e);
bail:
    if (inst->inst_ref_count) {
        slapi_counter_decrement(inst->inst_ref_count);
    }
    
    return rc;
}
