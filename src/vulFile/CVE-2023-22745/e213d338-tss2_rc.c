




















static void clearbuf(char *buffer)
{
    buffer[0] = '\0';
}


static void COMPILER_ATTR(format (printf, 3, 4))
_catbuf(char *buf, size_t len, const char *fmt, ...)
{
    va_list argptr;
    va_start(argptr, fmt);
    size_t offset = strlen(buf);
    vsnprintf(&buf[offset], len - offset, fmt, argptr);
    va_end(argptr);
}








static inline UINT16 tpm2_error_get(TSS2_RC rc)
{
    return ((rc & TPM2_ERROR_TSS2_RC_ERROR_MASK));
}


static inline UINT8 tss2_rc_layer_number_get(TSS2_RC rc)
{
    return ((rc & TSS2_RC_LAYER_MASK) >> TSS2_RC_LAYER_SHIFT);
}


static inline UINT8 tpm2_rc_fmt1_N_get(TPM2_RC rc)
{
    return ((rc & (0xF << 8)) >> 8);
}


static inline UINT8 tpm2_rc_fmt1_N_index_get(TPM2_RC rc)
{
    return (tpm2_rc_fmt1_N_get(rc) & 0x7);
}


static inline bool tpm2_rc_fmt1_N_is_handle(TPM2_RC rc)
{
    return ((tpm2_rc_fmt1_N_get(rc) & 0x8) == 0);
}

static inline UINT8 tpm2_rc_fmt1_P_get(TPM2_RC rc)
{
    return ((rc & (1 << 6)) >> 6);
}

static inline UINT8 tpm2_rc_fmt1_error_get(TPM2_RC rc)
{
    return (rc & 0x3F);
}

static inline UINT8 tpm2_rc_fmt0_error_get(TPM2_RC rc)
{
    return (rc & 0x7F);
}

static inline UINT8 tpm2_rc_tpm_fmt0_V_get(TPM2_RC rc)
{
    return ((rc & (1 << 8)) >> 8);
}

static inline UINT8 tpm2_rc_fmt0_T_get(TPM2_RC rc)
{
    return ((rc & (1 << 10)) >> 8);
}

static inline UINT8 tpm2_rc_fmt0_S_get(TSS2_RC rc)
{
    return ((rc & (1 << 11)) >> 8);
}







const char * tss2_fmt1_err_strs_get(TSS2_RC error)
{
    
    static const char *fmt1_err_strs[] = {
        
        NULL,  "asymmetric algorithm not supported or not correct",  "inconsistent attributes",  "hash algorithm not supported or not appropriate",  "value is out of range or is not correct for the context",  "hierarchy is not enabled or is not correct for the use",  NULL,  "key size is not supported",  "mask generation function not supported",  "mode of operation not supported",  "the type of the value is not appropriate for the use",  "the handle is not correct for the use",  "unsupported key derivation function or function not appropriate for " "use",  "value was out of allowed range",  "the authorization HMAC check failed and DA counter incremented",  "invalid nonce size or nonce value mismatch",  "authorization requires assertion of PP",  NULL,  "unsupported or incompatible scheme",  NULL,  NULL,  "structure is the wrong size",  "unsupported symmetric algorithm or key size or not appropriate for" " instance",  "incorrect structure tag",  "union selector is incorrect",  NULL,  "the TPM was unable to unmarshal a value because there were not enough" " octets in the input buffer",  "the signature is not valid",  "key fields are not compatible with the selected use",  "a policy check failed",  NULL,  "integrity check failed",  "invalid ticket",  "reserved bits not set to zero as required",  "authorization failure without DA implications",  "the policy has expired",  "the commandCode in the policy is not the commandCode of the command" " or the command code in a policy command references a command that" " is not implemented",  "public and sensitive portions of an object are not cryptographically bound",  "curve not supported",  "point is not on the required curve", };




















































































    if (error < ARRAY_LEN(fmt1_err_strs)) {
        return fmt1_err_strs[error];
    }

    return NULL;
}

const char * tss2_fmt0_err_strs_get(TSS2_RC rc)
{
    
    static const char *fmt0_warn_strs[] = {
            
            NULL,  "gap for context ID is too large",  "out of memory for object contexts",  "out of memory for session contexts",  "out of shared objectsession memory or need space for internal" " operations",  "out of session handles",  "out of object handles",  "bad locality",  "the TPM has suspended operation on the command forward progress" " was made and the command may be retried",  "the command was canceled",  "TPM is performing selftests",  NULL,  NULL,  NULL,  NULL,  NULL,  "the 1st handle in the handle area references a transient object" " or session that is not loaded",  "the 2nd handle in the handle area references a transient object" " or session that is not loaded",  "the 3rd handle in the handle area references a transient object" " or session that is not loaded",  "the 4th handle in the handle area references a transient object" " or session that is not loaded",  "the 5th handle in the handle area references a transient object" " or session that is not loaded",  "the 6th handle in the handle area references a transient object" " or session that is not loaded",  "the 7th handle in the handle area references a transient object" " or session that is not loaded",  NULL,  "the 1st authorization session handle references a session that" " is not loaded",  "the 2nd authorization session handle references a session that" " is not loaded",  "the 3rd authorization session handle references a session that" " is not loaded",  "the 4th authorization session handle references a session that" " is not loaded",  "the 5th session handle references a session that" " is not loaded",  "the 6th session handle references a session that" " is not loaded",  "the 7th authorization session handle references a session that" " is not loaded",  NULL,  "the TPM is rate limiting accesses to prevent wearout of NV",  "authorizations for objects subject to DA protection are not" " allowed at this time because the TPM is in DA lockout mode",  "the TPM was not able to start the command",  "the command may require writing of NV and NV is not current" " accessible", };

























































































    
    static const char *fmt0_err_strs[] = {
        
        "TPM not initialized by TPM2_Startup or already initialized",  "commands not being accepted because of a TPM failure",  NULL,  "improper use of a sequence handle",  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  "not currently used",  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  "not currently used",  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  "the command is disabled",  "command failed because audit sequence required exclusivity",  NULL,  NULL,  "authorization handle is not correct for command",  "command requires an authorization session for handle and it is" " not present",  "policy failure in math operation or an invalid authPolicy value",  "PCR check fail",  "PCR have changed since checked",  NULL,  NULL,  NULL,  NULL,  "For all commands, other than TPM2_FieldUpgradeData, " "this code indicates that the TPM is in field upgrade mode. " "For TPM2_FieldUpgradeData, this code indicates that the TPM " "is not in field upgrade mode",  "context ID counter is at maximum",  "authValue or authPolicy is not available for selected entity",  "a _TPM_Init and StartupCLEAR is required before the TPM can" " resume operation",  "the protection algorithms hash and symmetric are not reasonably" " balanced. The digest size of the hash must be larger than the key" " size of the symmetric algorithm.",  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  NULL,  "command commandSize value is inconsistent with contents of the" " command buffer. Either the size is not the same as the octets" " loaded by the hardware interface layer or the value is not large" " enough to hold a command header",  "command code not supported",  "the value of authorizationSize is out of range or the number of" " octets in the Authorization Area is greater than required",  "use of an authorization session with a context command or another" " command that cannot have an authorization session",  "NV offset+size is out of range",  "Requested allocation size is larger than allowed",  "NV access locked",  "NV access authorization fails in command actions",  "an NV Index is used before being initialized or the state saved" " by TPM2_ShutdownSTATE could not be restored",  "insufficient space for NV allocation",  "NV Index or persistent object already defined",  NULL,  NULL,  NULL,  "context in TPM2_ContextLoad is not valid",  "cpHash value already set or not correct for use",  "handle for parent is not a valid parent",  "some function needs testing",  "returned when an internal function cannot process a request due to" " an unspecified problem. This code is usually related to invalid" " parameters that are not properly filtered by the input" " unmarshaling code",  "the sensitive area did not unmarshal correctly after decryption", };



























































































































































































    UINT8 errnum = tpm2_rc_fmt0_error_get(rc);
    
    size_t len = tpm2_rc_fmt0_S_get(rc) ? ARRAY_LEN(fmt0_warn_strs) : ARRAY_LEN(fmt0_err_strs);
    const char **selection = tpm2_rc_fmt0_S_get(rc) ? fmt0_warn_strs : fmt0_err_strs;
    if (errnum >= len) {
        return NULL;
    }

    return selection[errnum];
}

static const char * tpm2_err_handler_fmt1(TPM2_RC rc)
{
    static __thread char buf[TSS2_ERR_LAYER_ERROR_STR_MAX + 1];

    clearbuf(buf);

    
    UINT8 index = tpm2_rc_fmt1_N_index_get(rc);

    bool is_handle = tpm2_rc_fmt1_N_is_handle(rc);
    const char *m = tpm2_rc_fmt1_P_get(rc) ? "parameter" :
                    is_handle ? "handle" : "session";
    catbuf(buf, "%s", m);

    if (index) {
        catbuf(buf, "(%u):", index);
    } else {
        catbuf(buf, "%s", "(unk):");
    }

    UINT8 errnum = tpm2_rc_fmt1_error_get(rc);
    m = tss2_fmt1_err_strs_get(errnum);
    if (m) {
        catbuf(buf, "%s", m);
    } else {
        catbuf(buf, "unknown error num: 0x%X", errnum);
    }

    return buf;
}

static const char * tpm2_err_handler_fmt0(TSS2_RC rc)
{
    static __thread char buf[TSS2_ERR_LAYER_ERROR_STR_MAX + 1];

    clearbuf(buf);

    char *e = tpm2_rc_fmt0_S_get(rc) ? "warn" : "error";
    char *v = tpm2_rc_tpm_fmt0_V_get(rc) ? "2.0" : "1.2";
    catbuf(buf, "%s(%s): ", e, v);

    UINT8 errnum = tpm2_rc_fmt0_error_get(rc);
    
    if (tpm2_rc_tpm_fmt0_V_get(rc)) {
        
        if (tpm2_rc_fmt0_T_get(rc)) {
            catbuf(buf, "Vendor specific error: 0x%X", errnum);
            return buf;
        }

        const char *m = tss2_fmt0_err_strs_get(rc);
        if (!m) {
            return NULL;
        }

        catbuf(buf, "%s", m);
        return buf;
    }

    catbuf(buf, "%s", "unknown version 1.2 error code");

    return buf;
}


static inline UINT8 tss2_rc_layer_format_get(TSS2_RC rc)
{
    return ((rc & (1 << 7)) >> 7);
}


static const char * tpm2_ehandler(TSS2_RC rc)
{
    bool is_fmt_1 = tss2_rc_layer_format_get(rc);

    return is_fmt_1 ? tpm2_err_handler_fmt1(rc) : tpm2_err_handler_fmt0(rc);
}


static const char * tss_err_handler (TSS2_RC rc)
{
    
    static const char *errors[] =   {
        
        "Catch all for all errors not otherwise specified",  "If called functionality isn't implemented",  "A context structure is bad",  "Passed in ABI version doesn't match called module's ABI version",  "A pointer is NULL that isn't allowed to be NULL.",  "A buffer isn't large enough",  "Function called in the wrong order",  "Fails to connect to next lower layer",  "Operation timed out; function must be called again to be completed",  "IO failure",  "A parameter has a bad value",  "Operation not permitted.",  "Session structures were sent, but command doesn't use them or doesn't" " use the specified number of them",  "If function called that uses decrypt parameter, but command doesn't" " support decrypt parameter.",  "If function called that uses encrypt parameter, but command doesn't" " support decrypt parameter.",  "If size of a parameter is incorrect",  "Response is malformed",  "Context not large enough",  "Response is not long enough",  "Unknown or unusable TCTI version",  "Functionality not supported",  "TCTI context is bad",  "Failed to allocate memory",  "The ESYS_TR resource object is bad",  "Multiple sessions were marked with attribute decrypt",  "Multiple sessions were marked with attribute encrypt",  "Authorizing the TPM response failed",  "No config is available",  "The provided path is bad",  "The object is not deletable",  "The provided path already exists",  "The key was not found",  "Signature verification failed",  "Hashes mismatch",  "Key is not duplicatable",  "The path was not found",  "No certificate",  "No PCR",  "PCR not resettable",  "The template is bad",  "Authorization failed",  "Authorization is unknown",  "NV is not readable",  "NV is too small",  "NV is not writable",  "The policy is unknown",  "The NV type is wrong",  "The name already exists",  "No TPM available",  "The key is bad",  "No handle provided",  "Provisioning was not executed.",  "Already provisioned" };












































































































    return (rc - 1u < ARRAY_LEN(errors)) ? errors[rc - 1u] : NULL;
}


static struct {
    char name[TSS2_ERR_LAYER_NAME_MAX];
    TSS2_RC_HANDLER handler;
} layer_handler[TPM2_ERROR_TSS2_RC_LAYER_COUNT] = {
    ADD_HANDLER("tpm" , tpm2_ehandler), ADD_NULL_HANDLER, ADD_NULL_HANDLER, ADD_NULL_HANDLER, ADD_NULL_HANDLER, ADD_NULL_HANDLER, ADD_HANDLER("fapi", tss_err_handler), ADD_HANDLER("esapi", tss_err_handler), ADD_HANDLER("sys", tss_err_handler), ADD_HANDLER("mu",  tss_err_handler),  ADD_HANDLER("tcti", tss_err_handler),  ADD_HANDLER("rmt", tpm2_ehandler),   ADD_HANDLER("rm", NULL), ADD_HANDLER("policy", tss_err_handler), };



















static const char * unknown_layer_handler(TSS2_RC rc)
{
    static __thread char buf[32];

    clearbuf(buf);
    catbuf(buf, "0x%X", tpm2_error_get(rc));

    return buf;
}


TSS2_RC_HANDLER Tss2_RC_SetHandler(UINT8 layer, const char *name, TSS2_RC_HANDLER handler)

{
    TSS2_RC_HANDLER old = layer_handler[layer].handler;

    layer_handler[layer].handler = handler;

    if (handler && name) {
        snprintf(layer_handler[layer].name, sizeof(layer_handler[layer].name), "%s", name);
    } else {
        memset(layer_handler[layer].name, 0, sizeof(layer_handler[layer].name));
    }

    return old;
}


const char * Tss2_RC_Decode(TSS2_RC rc)
{
    static __thread char buf[TSS2_ERR_LAYER_NAME_MAX + TSS2_ERR_LAYER_ERROR_STR_MAX + 1];

    clearbuf(buf);

    UINT8 layer = tss2_rc_layer_number_get(rc);

    TSS2_RC_HANDLER handler = layer_handler[layer].handler;
    const char *lname = layer_handler[layer].name;

    if (lname[0]) {
        catbuf(buf, "%s:", lname);
    } else {
        catbuf(buf, "%u:", layer);
    }

    handler = !handler ? unknown_layer_handler : handler;

    
    UINT16 err_bits = tpm2_error_get(rc);
    const char *e = err_bits ? handler(err_bits) : "success";
    if (e) {
        catbuf(buf, "%s", e);
    } else {
        catbuf(buf, "0x%X", err_bits);
    }

    return buf;
}


TSS2_RC Tss2_RC_DecodeInfo(TSS2_RC rc, TSS2_RC_INFO *info)
{
    UINT8 n;

    if (!info) {
        return TSS2_BASE_RC_BAD_REFERENCE;
    }

    memset(info, 0, sizeof(TSS2_RC_INFO));

    info->layer = tss2_rc_layer_number_get(rc);
    info->format = tss2_rc_layer_format_get(rc);

    if (info->format) {
        info->error = tpm2_rc_fmt1_error_get(rc) | TPM2_RC_FMT1;
        n = tpm2_rc_fmt1_N_index_get(rc);
        if (tpm2_rc_fmt1_P_get(rc)) {
	    info->parameter = n;
        } else if (tpm2_rc_fmt1_N_is_handle(rc)) {
            info->handle = n;
        } else {
          info->session = n;
        }
    } else {
        info->error = tpm2_error_get(rc);
    }

    return TSS2_RC_SUCCESS;
}


const char * Tss2_RC_DecodeInfoError(TSS2_RC_INFO *info)
{
    static __thread char buf[TSS2_ERR_LAYER_ERROR_STR_MAX + 1];
    const char *m = NULL;

    if (!info) {
        return NULL;
    }
    clearbuf(buf);

    if (info->format) {
        m = tss2_fmt1_err_strs_get(info->error ^ TPM2_RC_FMT1);
    } else {
        m = tss2_fmt0_err_strs_get(info->error ^ TPM2_RC_VER1);
    }

    if (m) {
        catbuf(buf, "%s", m);
    } else {
        catbuf(buf, "0x%X", info->error);
    }

    return buf;
}
