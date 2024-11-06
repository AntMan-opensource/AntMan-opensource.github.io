



















typedef struct pkgdata_s *pkgdatap;

typedef void (*hdrvsmsg)(struct rpmsinfo_s *sinfo, pkgdatap pkgdata, const char *msg);

struct pkgdata_s {
    hdrvsmsg msgfunc;
    const char *fn;
    char *msg;
    rpmRC rc;
};


static void headerMergeLegacySigs(Header h, Header sigh)
{
    HeaderIterator hi;
    struct rpmtd_s td;

    hi = headerInitIterator(sigh);
    for (; headerNext(hi, &td); rpmtdFreeData(&td))
    {
	switch (td.tag) {
	
	case RPMSIGTAG_SIZE:
	    td.tag = RPMTAG_SIGSIZE;
	    break;
	case RPMSIGTAG_PGP:
	    td.tag = RPMTAG_SIGPGP;
	    break;
	case RPMSIGTAG_MD5:
	    td.tag = RPMTAG_SIGMD5;
	    break;
	case RPMSIGTAG_GPG:
	    td.tag = RPMTAG_SIGGPG;
	    break;
	case RPMSIGTAG_PGP5:
	    td.tag = RPMTAG_SIGPGP5;
	    break;
	case RPMSIGTAG_PAYLOADSIZE:
	    td.tag = RPMTAG_ARCHIVESIZE;
	    break;
	case RPMSIGTAG_FILESIGNATURES:
	    td.tag = RPMTAG_FILESIGNATURES;
	    break;
	case RPMSIGTAG_FILESIGNATURELENGTH:
	    td.tag = RPMTAG_FILESIGNATURELENGTH;
	    break;
	case RPMSIGTAG_VERITYSIGNATURES:
	case RPMSIGTAG_VERITYSIGNATUREALGO:
	case RPMSIGTAG_SHA1:
	case RPMSIGTAG_SHA256:
	case RPMSIGTAG_DSA:
	case RPMSIGTAG_RSA:
	default:
	    if (!(td.tag >= HEADER_SIGBASE && td.tag < HEADER_TAGBASE))
		continue;
	    break;
	}
	if (!headerIsEntry(h, td.tag)) {
	    switch (td.type) {
	    case RPM_NULL_TYPE:
		continue;
		break;
	    case RPM_CHAR_TYPE:
	    case RPM_INT8_TYPE:
	    case RPM_INT16_TYPE:
	    case RPM_INT32_TYPE:
	    case RPM_INT64_TYPE:
		if (td.count != 1)
		    continue;
		break;
	    case RPM_STRING_TYPE:
	    case RPM_STRING_ARRAY_TYPE:
	    case RPM_BIN_TYPE:
		if (td.count >= 16*1024)
		    continue;
		break;
	    case RPM_I18NSTRING_TYPE:
		continue;
		break;
	    }
	    (void) headerPut(h, &td, HEADERPUT_DEFAULT);
	}
    }
    headerFreeIterator(hi);
}


static int stashKeyid(unsigned int keyid)
{
    static pthread_mutex_t keyid_lock = PTHREAD_MUTEX_INITIALIZER;
    static const unsigned int nkeyids_max = 256;
    static unsigned int nkeyids = 0;
    static unsigned int nextkeyid  = 0;
    static unsigned int * keyids;

    int i;
    int seen = 0;

    if (keyid == 0)
	return 0;

    
    if (pthread_mutex_lock(&keyid_lock))
	return 0;

    if (keyids != NULL)
    for (i = 0; i < nkeyids; i++) {
	if (keyid == keyids[i]) {
	    seen = 1;
	    goto exit;
        }
    }

    if (nkeyids < nkeyids_max) {
	nkeyids++;
	keyids = xrealloc(keyids, nkeyids * sizeof(*keyids));
    }
    if (keyids)		
	keyids[nextkeyid] = keyid;
    nextkeyid++;
    nextkeyid %= nkeyids_max;

exit:
    pthread_mutex_unlock(&keyid_lock);
    return seen;
}

static int handleHdrVS(struct rpmsinfo_s *sinfo, void *cbdata)
{
    struct pkgdata_s *pkgdata = cbdata;

    if (pkgdata->msgfunc) {
	char *vsmsg = rpmsinfoMsg(sinfo);
	pkgdata->msgfunc(sinfo, pkgdata, vsmsg);
	free(vsmsg);
    }

    
    if (sinfo->rc && pkgdata->rc != RPMRC_FAIL)
	pkgdata->rc = sinfo->rc;

    
    if (sinfo->rc != RPMRC_FAIL)
	sinfo->rc = RPMRC_OK;

    return 1;
}


static void appendhdrmsg(struct rpmsinfo_s *sinfo, struct pkgdata_s *pkgdata, const char *msg)
{
    pkgdata->msg = rstrscat(&pkgdata->msg, "\n", msg, NULL);
}

static void updateHdrDigests(rpmDigestBundle bundle, struct hdrblob_s *blob)
{
    int32_t ildl[2] = { htonl(blob->ril), htonl(blob->rdl) };

    rpmDigestBundleUpdate(bundle, rpm_header_magic, sizeof(rpm_header_magic));
    rpmDigestBundleUpdate(bundle, ildl, sizeof(ildl));
    rpmDigestBundleUpdate(bundle, blob->pe, (blob->ril * sizeof(*blob->pe)));
    rpmDigestBundleUpdate(bundle, blob->dataStart, blob->rdl);
}

rpmRC headerCheck(rpmts ts, const void * uh, size_t uc, char ** msg)
{
    rpmRC rc = RPMRC_FAIL;
    rpmVSFlags vsflags = rpmtsVSFlags(ts) | RPMVSF_NEEDPAYLOAD;
    rpmKeyring keyring = rpmtsGetKeyring(ts, 1);
    struct hdrblob_s blob;
    struct pkgdata_s pkgdata = {
	.msgfunc = appendhdrmsg, .fn = NULL, .msg = NULL, .rc = RPMRC_OK, };




    if (hdrblobInit(uh, uc, 0, 0, &blob, msg) == RPMRC_OK) {
	struct rpmvs_s *vs = rpmvsCreate(0, vsflags, keyring);
	rpmDigestBundle bundle = rpmDigestBundleNew();

	rpmswEnter(rpmtsOp(ts, RPMTS_OP_DIGEST), 0);

	rpmvsInit(vs, &blob, bundle);
	rpmvsInitRange(vs, RPMSIG_HEADER);
	updateHdrDigests(bundle, &blob);
	rpmvsFiniRange(vs, RPMSIG_HEADER);

	rpmvsVerify(vs, RPMSIG_VERIFIABLE_TYPE, handleHdrVS, &pkgdata);

	rpmswExit(rpmtsOp(ts, RPMTS_OP_DIGEST), uc);

	rc = pkgdata.rc;

	if (rc == RPMRC_OK && pkgdata.msg == NULL)
	    pkgdata.msg = xstrdup("Header sanity check: OK");

	if (msg)
	    *msg = pkgdata.msg;
	else free(pkgdata.msg);

	rpmDigestBundleFree(bundle);
	rpmvsFree(vs);
    }

    rpmKeyringFree(keyring);

    return rc;
}

rpmRC rpmReadHeader(rpmts ts, FD_t fd, Header *hdrp, char ** msg)
{
    char *buf = NULL;
    struct hdrblob_s blob;
    Header h = NULL;
    rpmRC rc = RPMRC_FAIL;		

    if (hdrp)
	*hdrp = NULL;
    if (msg)
	*msg = NULL;

    if (hdrblobRead(fd, 1, 1, RPMTAG_HEADERIMMUTABLE, &blob, &buf) != RPMRC_OK)
	goto exit;

    
    rc = hdrblobImport(&blob, 0, &h, &buf);
    
exit:
    if (hdrp && h && rc == RPMRC_OK)
	*hdrp = headerLink(h);
    headerFree(h);

    if (msg != NULL && *msg == NULL && buf != NULL) {
	*msg = buf;
    } else {
	free(buf);
    }

    return rc;
}

static void applyRetrofits(Header h)
{
    int v3 = 0;
    
    if (!headerIsEntry(h, RPMTAG_SOURCERPM) && !headerIsEntry(h, RPMTAG_SOURCEPACKAGE)) {
	
	if (headerIsEntry(h, RPMTAG_OLDFILENAMES))
	    headerConvert(h, HEADERCONV_COMPRESSFILELIST);
	if (headerIsSourceHeuristic(h)) {
	    
	    uint32_t one = 1;
	    headerPutUint32(h, RPMTAG_SOURCEPACKAGE, &one, 1);
	} else {
	    
	    headerPutString(h, RPMTAG_SOURCERPM, "(none)");
	}
    }

    
    if (!headerIsEntry(h, RPMTAG_HEADERIMMUTABLE)) {
	v3 = 1;
	headerConvert(h, HEADERCONV_RETROFIT_V3);
    } else if (headerIsEntry(h, RPMTAG_OLDFILENAMES)) {
	headerConvert(h, HEADERCONV_COMPRESSFILELIST);
	v3 = 1;
    }
    if (v3) {
	char *s = headerGetAsString(h, RPMTAG_NEVRA);
	rpmlog(RPMLOG_WARNING, _("RPM v3 packages are deprecated: %s\n"), s);
	free(s);
    }
}

static void loghdrmsg(struct rpmsinfo_s *sinfo, struct pkgdata_s *pkgdata, const char *msg)
{
    int lvl = RPMLOG_DEBUG;
    switch (sinfo->rc) {
    case RPMRC_OK:		
	break;
    case RPMRC_NOTTRUSTED:	
    case RPMRC_NOKEY:		
	
	if (stashKeyid(sinfo->keyid) == 0)
	    lvl = RPMLOG_WARNING;
	break;
    case RPMRC_NOTFOUND:	
	lvl = RPMLOG_WARNING;
	break;
    default:
    case RPMRC_FAIL:		
	lvl = RPMLOG_ERR;
	break;
    }

    rpmlog(lvl, "%s: %s\n", pkgdata->fn, msg);
}

rpmRC rpmReadPackageFile(rpmts ts, FD_t fd, const char * fn, Header * hdrp)
{
    char *msg = NULL;
    Header h = NULL;
    Header sigh = NULL;
    hdrblob blob = NULL;
    hdrblob sigblob = NULL;
    rpmVSFlags vsflags = rpmtsVSFlags(ts) | RPMVSF_NEEDPAYLOAD;
    rpmKeyring keyring = rpmtsGetKeyring(ts, 1);
    struct rpmvs_s *vs = rpmvsCreate(0, vsflags, keyring);
    struct pkgdata_s pkgdata = {
	.msgfunc = loghdrmsg, .fn = fn ? fn : Fdescr(fd), .msg = NULL, .rc = RPMRC_OK, };




    
    if (hdrp)
	*hdrp = NULL;

    rpmRC rc = rpmpkgRead(vs, fd, &sigblob, &blob, &msg);
    if (rc)
	goto exit;

    
    rc = RPMRC_FAIL;
    if (!rpmvsVerify(vs, RPMSIG_VERIFIABLE_TYPE, handleHdrVS, &pkgdata)) {
	
	if (hdrp) {
	    if (hdrblobImport(sigblob, 0, &sigh, &msg))
		goto exit;
	    if (hdrblobImport(blob, 0, &h, &msg))
		goto exit;

	    
	    headerMergeLegacySigs(h, sigh);
	    applyRetrofits(h);

	    
	    *hdrp = headerLink(h);
	}
	rc = RPMRC_OK;
    }

    
    if (rc == RPMRC_OK && pkgdata.rc)
	rc = pkgdata.rc;

exit:
    if (rc && msg)
	rpmlog(RPMLOG_ERR, "%s: %s\n", Fdescr(fd), msg);
    hdrblobFree(sigblob);
    hdrblobFree(blob);
    headerFree(sigh);
    headerFree(h);
    rpmKeyringFree(keyring);
    rpmvsFree(vs);
    free(msg);

    return rc;
}



