


































static AUTHSSTATS authenticateDigestStats;

helper *digestauthenticators = NULL;

static hash_table *digest_nonce_cache;

static int authdigest_initialised = 0;
static MemAllocator *digest_nonce_pool = NULL;

enum http_digest_attr_type {
    DIGEST_USERNAME, DIGEST_REALM, DIGEST_QOP, DIGEST_ALGORITHM, DIGEST_URI, DIGEST_NONCE, DIGEST_NC, DIGEST_CNONCE, DIGEST_RESPONSE, DIGEST_INVALID_ATTR };










static const LookupTable<http_digest_attr_type>::Record DigestAttrs[] = {
    {"username", DIGEST_USERNAME}, {"realm", DIGEST_REALM}, {"qop", DIGEST_QOP}, {"algorithm", DIGEST_ALGORITHM}, {"uri", DIGEST_URI}, {"nonce", DIGEST_NONCE}, {"nc", DIGEST_NC}, {"cnonce", DIGEST_CNONCE}, {"response", DIGEST_RESPONSE}, {nullptr, DIGEST_INVALID_ATTR}








};

LookupTable<http_digest_attr_type> DigestFieldsLookupTable(DIGEST_INVALID_ATTR, DigestAttrs);



static void authenticateDigestNonceCacheCleanup(void *data);
static digest_nonce_h *authenticateDigestNonceFindNonce(const char *noncehex);
static void authenticateDigestNonceDelete(digest_nonce_h * nonce);
static void authenticateDigestNonceSetup(void);
static void authDigestNonceEncode(digest_nonce_h * nonce);
static void authDigestNonceLink(digest_nonce_h * nonce);

static int authDigestNonceLinks(digest_nonce_h * nonce);

static void authDigestNonceUserUnlink(digest_nonce_h * nonce);

static void authDigestNonceEncode(digest_nonce_h * nonce)
{
    if (!nonce)
        return;

    if (nonce->key)
        xfree(nonce->key);

    SquidMD5_CTX Md5Ctx;
    HASH H;
    SquidMD5Init(&Md5Ctx);
    SquidMD5Update(&Md5Ctx, reinterpret_cast<const uint8_t *>(&nonce->noncedata), sizeof(nonce->noncedata));
    SquidMD5Final(reinterpret_cast<uint8_t *>(H), &Md5Ctx);

    nonce->key = xcalloc(sizeof(HASHHEX), 1);
    CvtHex(H, static_cast<char *>(nonce->key));
}

digest_nonce_h * authenticateDigestNonceNew(void)
{
    digest_nonce_h *newnonce = static_cast < digest_nonce_h * >(digest_nonce_pool->alloc());

    
    
    
    static std::mt19937 mt(static_cast<uint32_t>(getCurrentTime() & 0xFFFFFFFF));
    static xuniform_int_distribution<uint32_t> newRandomData;

    
    newnonce->nc = 0;
    newnonce->flags.valid = true;
    newnonce->noncedata.creationtime = current_time.tv_sec;
    newnonce->noncedata.randomdata = newRandomData(mt);

    authDigestNonceEncode(newnonce);

    
    while (authenticateDigestNonceFindNonce((char const *) (newnonce->key))) {
        
        newnonce->noncedata.randomdata = newRandomData(mt);
        authDigestNonceEncode(newnonce);
    }

    hash_join(digest_nonce_cache, newnonce);
    
    authDigestNonceLink(newnonce);
    newnonce->flags.incache = true;
    debugs(29, 5, "created nonce " << newnonce << " at " << newnonce->noncedata.creationtime);
    return newnonce;
}

static void authenticateDigestNonceDelete(digest_nonce_h * nonce)
{
    if (nonce) {
        assert(nonce->references == 0);


        if (nonce->flags.incache)
            hash_remove_link(digest_nonce_cache, nonce);



        assert(!nonce->flags.incache);

        safe_free(nonce->key);

        digest_nonce_pool->freeOne(nonce);
    }
}

static void authenticateDigestNonceSetup(void)
{
    if (!digest_nonce_pool)
        digest_nonce_pool = memPoolCreate("Digest Scheme nonce's", sizeof(digest_nonce_h));

    if (!digest_nonce_cache) {
        digest_nonce_cache = hash_create((HASHCMP *) strcmp, 7921, hash_string);
        assert(digest_nonce_cache);
        eventAdd("Digest nonce cache maintenance", authenticateDigestNonceCacheCleanup, NULL, static_cast<Auth::Digest::Config*>(Auth::Config::Find("digest"))->nonceGCInterval, 1);
    }
}

void authenticateDigestNonceShutdown(void)
{
    
    digest_nonce_h *nonce;

    if (digest_nonce_cache) {
        debugs(29, 2, "Shutting down nonce cache");
        hash_first(digest_nonce_cache);

        while ((nonce = ((digest_nonce_h *) hash_next(digest_nonce_cache)))) {
            assert(nonce->flags.incache);
            authDigestNoncePurge(nonce);
        }
    }


    if (digest_nonce_pool) {
        delete digest_nonce_pool;
        digest_nonce_pool = NULL;
    }


    debugs(29, 2, "Nonce cache shutdown");
}

static void authenticateDigestNonceCacheCleanup(void *)
{
    
    digest_nonce_h *nonce;
    debugs(29, 3, "Cleaning the nonce cache now");
    debugs(29, 3, "Current time: " << current_time.tv_sec);
    hash_first(digest_nonce_cache);

    while ((nonce = ((digest_nonce_h *) hash_next(digest_nonce_cache)))) {
        debugs(29, 3, "nonce entry  : " << nonce << " '" << (char *) nonce->key << "'");
        debugs(29, 4, "Creation time: " << nonce->noncedata.creationtime);

        if (authDigestNonceIsStale(nonce)) {
            debugs(29, 4, "Removing nonce " << (char *) nonce->key << " from cache due to timeout.");
            assert(nonce->flags.incache);
            
            nonce->flags.valid = false;
            
            authDigestNonceUserUnlink(nonce);
            authDigestNoncePurge(nonce);
        }
    }

    debugs(29, 3, "Finished cleaning the nonce cache.");

    if (static_cast<Auth::Digest::Config*>(Auth::Config::Find("digest"))->active())
        eventAdd("Digest nonce cache maintenance", authenticateDigestNonceCacheCleanup, NULL, static_cast<Auth::Digest::Config*>(Auth::Config::Find("digest"))->nonceGCInterval, 1);
}

static void authDigestNonceLink(digest_nonce_h * nonce)
{
    assert(nonce != NULL);
    ++nonce->references;
    debugs(29, 9, "nonce '" << nonce << "' now at '" << nonce->references << "'.");
}


static int authDigestNonceLinks(digest_nonce_h * nonce)
{
    if (!nonce)
        return -1;

    return nonce->references;
}



void authDigestNonceUnlink(digest_nonce_h * nonce)
{
    assert(nonce != NULL);

    if (nonce->references > 0) {
        -- nonce->references;
    } else {
        debugs(29, DBG_IMPORTANT, "Attempt to lower nonce " << nonce << " refcount below 0!");
    }

    debugs(29, 9, "nonce '" << nonce << "' now at '" << nonce->references << "'.");

    if (nonce->references == 0)
        authenticateDigestNonceDelete(nonce);
}

const char * authenticateDigestNonceNonceHex(const digest_nonce_h * nonce)
{
    if (!nonce)
        return NULL;

    return (char const *) nonce->key;
}

static digest_nonce_h * authenticateDigestNonceFindNonce(const char *noncehex)
{
    digest_nonce_h *nonce = NULL;

    if (noncehex == NULL)
        return NULL;

    debugs(29, 9, "looking for noncehex '" << noncehex << "' in the nonce cache.");

    nonce = static_cast < digest_nonce_h * >(hash_lookup(digest_nonce_cache, noncehex));

    if ((nonce == NULL) || (strcmp(authenticateDigestNonceNonceHex(nonce), noncehex)))
        return NULL;

    debugs(29, 9, "Found nonce '" << nonce << "'");

    return nonce;
}

int authDigestNonceIsValid(digest_nonce_h * nonce, char nc[9])
{
    unsigned long intnc;
    

    if (!nonce)
        return 0;

    intnc = strtol(nc, NULL, 16);

    
    if (!nonce->flags.valid) {
        debugs(29, 4, "Nonce already invalidated");
        return 0;
    }

    
    if (!static_cast<Auth::Digest::Config*>(Auth::Config::Find("digest"))->CheckNonceCount) {
        
        intnc = nonce->nc + 1;
    }

    if ((static_cast<Auth::Digest::Config*>(Auth::Config::Find("digest"))->NonceStrictness && intnc != nonce->nc + 1) || intnc < nonce->nc + 1) {
        debugs(29, 4, "Nonce count doesn't match");
        nonce->flags.valid = false;
        return 0;
    }

    
    nonce->nc = intnc;

    return !authDigestNonceIsStale(nonce);
}

int authDigestNonceIsStale(digest_nonce_h * nonce)
{
    

    if (!nonce)
        return -1;

    
    if (!nonce->flags.valid)
        return -1;

    
    if (nonce->noncedata.creationtime + static_cast<Auth::Digest::Config*>(Auth::Config::Find("digest"))->noncemaxduration < current_time.tv_sec) {
        debugs(29, 4, "Nonce is too old. " << nonce->noncedata.creationtime << " " << static_cast<Auth::Digest::Config*>(Auth::Config::Find("digest"))->noncemaxduration << " " << current_time.tv_sec);



        nonce->flags.valid = false;
        return -1;
    }

    if (nonce->nc > 99999998) {
        debugs(29, 4, "Nonce count overflow");
        nonce->flags.valid = false;
        return -1;
    }

    if (nonce->nc > static_cast<Auth::Digest::Config*>(Auth::Config::Find("digest"))->noncemaxuses) {
        debugs(29, 4, "Nonce count over user limit");
        nonce->flags.valid = false;
        return -1;
    }

    
    return 0;
}


int authDigestNonceLastRequest(digest_nonce_h * nonce)
{
    if (!nonce)
        return -1;

    if (nonce->nc == 99999997) {
        debugs(29, 4, "Nonce count about to overflow");
        return -1;
    }

    if (nonce->nc >= static_cast<Auth::Digest::Config*>(Auth::Config::Find("digest"))->noncemaxuses - 1) {
        debugs(29, 4, "Nonce count about to hit user limit");
        return -1;
    }

    
    return 0;
}

void authDigestNoncePurge(digest_nonce_h * nonce)
{
    if (!nonce)
        return;

    if (!nonce->flags.incache)
        return;

    hash_remove_link(digest_nonce_cache, nonce);

    nonce->flags.incache = false;

    
    authDigestNonceUnlink(nonce);
}

void Auth::Digest::Config::rotateHelpers()
{
    
    if (digestauthenticators) {
        helperShutdown(digestauthenticators);
    }

    
}

bool Auth::Digest::Config::dump(StoreEntry * entry, const char *name, Auth::Config * scheme) const {

    if (!Auth::Config::dump(entry, name, scheme))
        return false;

    storeAppendPrintf(entry, "%s %s nonce_max_count %d\n%s %s nonce_max_duration %d seconds\n%s %s nonce_garbage_interval %d seconds\n", name, "digest", noncemaxuses, name, "digest", (int) noncemaxduration, name, "digest", (int) nonceGCInterval);


    storeAppendPrintf(entry, "%s digest utf8 %s\n", name, utf8 ? "on" : "off");
    return true;
}

bool Auth::Digest::Config::active() const {

    return authdigest_initialised == 1;
}

bool Auth::Digest::Config::configured() const {

    if ((authenticateProgram != NULL) && (authenticateChildren.n_max != 0) && !realm.isEmpty() && (noncemaxduration > -1))

        return true;

    return false;
}


void Auth::Digest::Config::fixHeader(Auth::UserRequest::Pointer auth_user_request, HttpReply *rep, Http::HdrType hdrType, HttpRequest *)
{
    if (!authenticateProgram)
        return;

    bool stale = false;
    digest_nonce_h *nonce = NULL;

    
    if (auth_user_request != NULL) {
        Auth::Digest::User *digest_user = dynamic_cast<Auth::Digest::User *>(auth_user_request->user().getRaw());

        if (digest_user) {
            stale = digest_user->credentials() == Auth::Handshake;
            if (stale) {
                nonce = digest_user->currentNonce();
            }
        }
    }
    if (!nonce) {
        nonce = authenticateDigestNonceNew();
    }

    debugs(29, 9, "Sending type:" << hdrType << " header: 'Digest realm=\"" << realm << "\", nonce=\"" << authenticateDigestNonceNonceHex(nonce) << "\", qop=\"" << QOP_AUTH << "\", stale=" << (stale ? "true" : "false"));



    
    httpHeaderPutStrf(&rep->header, hdrType, "Digest realm=\"" SQUIDSBUFPH "\", nonce=\"%s\", qop=\"%s\", stale=%s", SQUIDSBUFPRINT(realm), authenticateDigestNonceNonceHex(nonce), QOP_AUTH, stale ? "true" : "false");
}


void Auth::Digest::Config::init(Auth::Config *)
{
    if (authenticateProgram) {
        authenticateDigestNonceSetup();
        authdigest_initialised = 1;

        if (digestauthenticators == NULL)
            digestauthenticators = new helper("digestauthenticator");

        digestauthenticators->cmdline = authenticateProgram;

        digestauthenticators->childs.updateLimits(authenticateChildren);

        digestauthenticators->ipc_type = IPC_STREAM;

        helperOpenServers(digestauthenticators);
    }
}

void Auth::Digest::Config::registerWithCacheManager(void)
{
    Mgr::RegisterAction("digestauthenticator", "Digest User Authenticator Stats", authenticateDigestStats, 0, 1);

}


void Auth::Digest::Config::done()
{
    Auth::Config::done();

    authdigest_initialised = 0;

    if (digestauthenticators)
        helperShutdown(digestauthenticators);

    if (!shutting_down)
        return;

    delete digestauthenticators;
    digestauthenticators = NULL;

    if (authenticateProgram)
        wordlistDestroy(&authenticateProgram);
}

Auth::Digest::Config::Config() :
    nonceGCInterval(5*60), noncemaxduration(30*60), noncemaxuses(50), NonceStrictness(0), CheckNonceCount(1), PostWorkaround(0), utf8(0)





{}

void Auth::Digest::Config::parse(Auth::Config * scheme, int n_configured, char *param_str)
{
    if (strcmp(param_str, "program") == 0) {
        if (authenticateProgram)
            wordlistDestroy(&authenticateProgram);

        parse_wordlist(&authenticateProgram);

        requirePathnameExists("auth_param digest program", authenticateProgram->key);
    } else if (strcmp(param_str, "nonce_garbage_interval") == 0) {
        parse_time_t(&nonceGCInterval);
    } else if (strcmp(param_str, "nonce_max_duration") == 0) {
        parse_time_t(&noncemaxduration);
    } else if (strcmp(param_str, "nonce_max_count") == 0) {
        parse_int((int *) &noncemaxuses);
    } else if (strcmp(param_str, "nonce_strictness") == 0) {
        parse_onoff(&NonceStrictness);
    } else if (strcmp(param_str, "check_nonce_count") == 0) {
        parse_onoff(&CheckNonceCount);
    } else if (strcmp(param_str, "post_workaround") == 0) {
        parse_onoff(&PostWorkaround);
    } else if (strcmp(param_str, "utf8") == 0) {
        parse_onoff(&utf8);
    } else Auth::Config::parse(scheme, n_configured, param_str);
}

const char * Auth::Digest::Config::type() const {

    return Auth::Digest::Scheme::GetInstance()->type();
}

static void authenticateDigestStats(StoreEntry * sentry)
{
    if (digestauthenticators)
        digestauthenticators->packStatsInto(sentry, "Digest Authenticator Statistics");
}



static void authDigestNonceUserUnlink(digest_nonce_h * nonce)
{
    Auth::Digest::User *digest_user;
    dlink_node *link, *tmplink;

    if (!nonce)
        return;

    if (!nonce->user)
        return;

    digest_user = nonce->user;

    
    link = digest_user->nonces.head;

    while (link) {
        tmplink = link;
        link = link->next;

        if (tmplink->data == nonce) {
            dlinkDelete(tmplink, &digest_user->nonces);
            authDigestNonceUnlink(static_cast < digest_nonce_h * >(tmplink->data));
            delete tmplink;
            link = NULL;
        }
    }

    
    nonce->user = NULL;
}


void authDigestUserLinkNonce(Auth::Digest::User * user, digest_nonce_h * nonce)
{
    dlink_node *node;

    if (!user || !nonce || !nonce->user)
        return;

    Auth::Digest::User *digest_user = user;

    node = digest_user->nonces.head;

    while (node && (node->data != nonce))
        node = node->next;

    if (node)
        return;

    node = new dlink_node;

    dlinkAddTail(nonce, node, &digest_user->nonces);

    authDigestNonceLink(nonce);

    
    assert((nonce->user == NULL) || (nonce->user == user));

    
    nonce->user = user;
}


static Auth::UserRequest::Pointer authDigestLogUsername(char *username, Auth::UserRequest::Pointer auth_user_request, const char *requestRealm)
{
    assert(auth_user_request != NULL);

    
    debugs(29, 9, "Creating new user for logging '" << (username?username:"[no username]") << "'");
    Auth::User::Pointer digest_user = new Auth::Digest::User(static_cast<Auth::Digest::Config*>(Auth::Config::Find("digest")), requestRealm);
    
    digest_user->username(username);
    
    digest_user->auth_type = Auth::AUTH_BROKEN;
    
    auth_user_request->user(digest_user);
    return auth_user_request;
}


Auth::UserRequest::Pointer Auth::Digest::Config::decode(char const *proxy_auth, const char *aRequestRealm)
{
    const char *item;
    const char *p;
    const char *pos = NULL;
    char *username = NULL;
    digest_nonce_h *nonce;
    int ilen;

    debugs(29, 9, "beginning");

    Auth::Digest::UserRequest *digest_request = new Auth::Digest::UserRequest();

    

    while (xisgraph(*proxy_auth))
        ++proxy_auth;

    
    while (xisspace(*proxy_auth))
        ++proxy_auth;

    String temp(proxy_auth);

    while (strListGetItem(&temp, ',', &item, &ilen, &pos)) {
        
        size_t nlen;
        size_t vlen;
        if ((p = (const char *)memchr(item, '=', ilen)) && (p - item < ilen)) {
            nlen = p - item;
            ++p;
            vlen = ilen - (p - item);
        } else {
            nlen = ilen;
            vlen = 0;
        }

        SBuf keyName(item, nlen);
        String value;

        if (vlen > 0) {
            

            if (keyName == SBuf("domain",6) || keyName == SBuf("uri",3)) {
                
                
                if (vlen > 1 && *p == '"' && *(p + vlen -1) == '"') {
                    value.limitInit(p+1, vlen-2);
                }
            } else if (keyName == SBuf("qop",3)) {
                
                
                
                if (vlen > 1 && *p == '"' && *(p + vlen -1) == '"') {
                    value.limitInit(p+1, vlen-2);
                } else {
                    value.limitInit(p, vlen);
                }
            } else if (*p == '"') {
                if (!httpHeaderParseQuotedString(p, vlen, &value)) {
                    debugs(29, 9, "Failed to parse attribute '" << item << "' in '" << temp << "'");
                    continue;
                }
            } else {
                value.limitInit(p, vlen);
            }
        } else {
            debugs(29, 9, "Failed to parse attribute '" << item << "' in '" << temp << "'");
            continue;
        }

        
        const http_digest_attr_type t = DigestFieldsLookupTable.lookup(keyName);

        switch (t) {
        case DIGEST_USERNAME:
            safe_free(username);
            if (value.size() != 0)
                username = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "Found Username '" << username << "'");
            break;

        case DIGEST_REALM:
            safe_free(digest_request->realm);
            if (value.size() != 0)
                digest_request->realm = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "Found realm '" << digest_request->realm << "'");
            break;

        case DIGEST_QOP:
            safe_free(digest_request->qop);
            if (value.size() != 0)
                digest_request->qop = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "Found qop '" << digest_request->qop << "'");
            break;

        case DIGEST_ALGORITHM:
            safe_free(digest_request->algorithm);
            if (value.size() != 0)
                digest_request->algorithm = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "Found algorithm '" << digest_request->algorithm << "'");
            break;

        case DIGEST_URI:
            safe_free(digest_request->uri);
            if (value.size() != 0)
                digest_request->uri = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "Found uri '" << digest_request->uri << "'");
            break;

        case DIGEST_NONCE:
            safe_free(digest_request->noncehex);
            if (value.size() != 0)
                digest_request->noncehex = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "Found nonce '" << digest_request->noncehex << "'");
            break;

        case DIGEST_NC:
            if (value.size() != 8) {
                debugs(29, 9, "Invalid nc '" << value << "' in '" << temp << "'");
            }
            xstrncpy(digest_request->nc, value.rawBuf(), value.size() + 1);
            debugs(29, 9, "Found noncecount '" << digest_request->nc << "'");
            break;

        case DIGEST_CNONCE:
            safe_free(digest_request->cnonce);
            if (value.size() != 0)
                digest_request->cnonce = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "Found cnonce '" << digest_request->cnonce << "'");
            break;

        case DIGEST_RESPONSE:
            safe_free(digest_request->response);
            if (value.size() != 0)
                digest_request->response = xstrndup(value.rawBuf(), value.size() + 1);
            debugs(29, 9, "Found response '" << digest_request->response << "'");
            break;

        default:
            debugs(29, 3, "Unknown attribute '" << item << "' in '" << temp << "'");
            break;
        }
    }

    temp.clean();

    

    

    

    
    Auth::UserRequest::Pointer rv;
    
    if (!username || username[0] == '\0') {
        debugs(29, 2, "Empty or not present username");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    
    if (strchr(username, '"')) {
        debugs(29, 2, "Unacceptable username '" << username << "'");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    
    if (!digest_request->realm || digest_request->realm[0] == '\0') {
        debugs(29, 2, "Empty or not present realm");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    
    if (!digest_request->noncehex || digest_request->noncehex[0] == '\0') {
        debugs(29, 2, "Empty or not present nonce");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    
    if (!digest_request->uri || digest_request->uri[0] == '\0') {
        debugs(29, 2, "Missing URI field");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    
    if (!digest_request->response || strlen(digest_request->response) != 32) {
        debugs(29, 2, "Response length invalid");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    
    if (!digest_request->algorithm)
        digest_request->algorithm = xstrndup("MD5", 4);
    else if (strcmp(digest_request->algorithm, "MD5")
             && strcmp(digest_request->algorithm, "MD5-sess")) {
        debugs(29, 2, "invalid algorithm specified!");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    
    if (digest_request->qop) {

        
        if (strcmp(digest_request->qop, QOP_AUTH) != 0) {
            
            debugs(29, 2, "Invalid qop option received");
            rv = authDigestLogUsername(username, digest_request, aRequestRealm);
            safe_free(username);
            return rv;
        }

        
        if (!digest_request->cnonce || digest_request->cnonce[0] == '\0') {
            debugs(29, 2, "Missing cnonce field");
            rv = authDigestLogUsername(username, digest_request, aRequestRealm);
            safe_free(username);
            return rv;
        }

        
        if (strlen(digest_request->nc) != 8 || strspn(digest_request->nc, "0123456789abcdefABCDEF") != 8) {
            debugs(29, 2, "invalid nonce count");
            rv = authDigestLogUsername(username, digest_request, aRequestRealm);
            safe_free(username);
            return rv;
        }
    } else {
        
        if (digest_request->cnonce || digest_request->nc[0] != '\0') {
            debugs(29, 2, "missing qop!");
            rv = authDigestLogUsername(username, digest_request, aRequestRealm);
            safe_free(username);
            return rv;
        }
    }

    

    
    nonce = authenticateDigestNonceFindNonce(digest_request->noncehex);
    
    if (nonce && nonce->user && strcmp(username, nonce->user->username())) {
        debugs(29, 2, "Username for the nonce does not equal the username for the request");
        nonce = NULL;
    }

    if (!nonce) {
        
        debugs(29, 2, "Unexpected or invalid nonce received from " << username);
        Auth::UserRequest::Pointer auth_request = authDigestLogUsername(username, digest_request, aRequestRealm);
        auth_request->user()->credentials(Auth::Handshake);
        safe_free(username);
        return auth_request;
    }

    digest_request->nonce = nonce;
    authDigestNonceLink(nonce);

    
    if (nonce->user && strcmp(username, nonce->user->username())) {
        debugs(29, 2, "Username for the nonce does not equal the username for the request");
        rv = authDigestLogUsername(username, digest_request, aRequestRealm);
        safe_free(username);
        return rv;
    }

    

    

    
    Auth::Digest::User *digest_user;

    Auth::User::Pointer auth_user;

    SBuf key = Auth::User::BuildUserKey(username, aRequestRealm);
    if (key.isEmpty() || !(auth_user = Auth::Digest::User::Cache()->lookup(key))) {
        
        debugs(29, 9, "Creating new digest user '" << username << "'");
        digest_user = new Auth::Digest::User(this, aRequestRealm);
        
        auth_user = digest_user;
        
        digest_user->username(username);
        
        digest_user->auth_type = Auth::AUTH_DIGEST;
        
        
        digest_user->addToNameCache();

        
        authDigestUserLinkNonce(digest_user, nonce);

        
        auth_user->expiretime = current_time.tv_sec;
    } else {
        debugs(29, 9, "Found user '" << username << "' in the user cache as '" << auth_user << "'");
        digest_user = static_cast<Auth::Digest::User *>(auth_user.getRaw());
        digest_user->credentials(Auth::Unchecked);
        xfree(username);
    }

    
    assert(digest_request != NULL);

    digest_request->user(digest_user);
    debugs(29, 9, "username = '" << digest_user->username() << "'\nrealm = '" << digest_request->realm << "'\nqop = '" << digest_request->qop << "'\nalgorithm = '" << digest_request->algorithm << "'\nuri = '" << digest_request->uri << "'\nnonce = '" << digest_request->noncehex << "'\nnc = '" << digest_request->nc << "'\ncnonce = '" << digest_request->cnonce << "'\nresponse = '" << digest_request->response << "'\ndigestnonce = '" << nonce << "'");






    return digest_request;
}

