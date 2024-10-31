









static void setProtocolError(const char *errstr, client *c);
int postponeClientRead(client *c);
int ProcessingEventsWhileBlocked = 0; 


size_t sdsZmallocSize(sds s) {
    void *sh = sdsAllocPtr(s);
    return zmalloc_size(sh);
}


size_t getStringObjectSdsUsedMemory(robj *o) {
    serverAssertWithInfo(NULL,o,o->type == OBJ_STRING);
    switch(o->encoding) {
    case OBJ_ENCODING_RAW: return sdsZmallocSize(o->ptr);
    case OBJ_ENCODING_EMBSTR: return zmalloc_size(o)-sizeof(robj);
    default: return 0; 
    }
}


size_t getStringObjectLen(robj *o) {
    serverAssertWithInfo(NULL,o,o->type == OBJ_STRING);
    switch(o->encoding) {
    case OBJ_ENCODING_RAW: return sdslen(o->ptr);
    case OBJ_ENCODING_EMBSTR: return sdslen(o->ptr);
    default: return 0; 
    }
}


void *dupClientReplyValue(void *o) {
    clientReplyBlock *old = o;
    clientReplyBlock *buf = zmalloc(sizeof(clientReplyBlock) + old->size);
    memcpy(buf, o, sizeof(clientReplyBlock) + old->size);
    return buf;
}

void freeClientReplyValue(void *o) {
    zfree(o);
}

int listMatchObjects(void *a, void *b) {
    return equalStringObjects(a,b);
}


void linkClient(client *c) {
    listAddNodeTail(server.clients,c);
    
    c->client_list_node = listLast(server.clients);
    uint64_t id = htonu64(c->id);
    raxInsert(server.clients_index,(unsigned char*)&id,sizeof(id),c,NULL);
}

client *createClient(connection *conn) {
    client *c = zmalloc(sizeof(client));

    
    if (conn) {
        connNonBlock(conn);
        connEnableTcpNoDelay(conn);
        if (server.tcpkeepalive)
            connKeepAlive(conn,server.tcpkeepalive);
        connSetReadHandler(conn, readQueryFromClient);
        connSetPrivateData(conn, c);
    }

    selectDb(c,0);
    uint64_t client_id = ++server.next_client_id;
    c->id = client_id;
    c->resp = 2;
    c->conn = conn;
    c->name = NULL;
    c->bufpos = 0;
    c->qb_pos = 0;
    c->querybuf = sdsempty();
    c->pending_querybuf = sdsempty();
    c->querybuf_peak = 0;
    c->reqtype = 0;
    c->argc = 0;
    c->argv = NULL;
    c->argv_len_sum = 0;
    c->cmd = c->lastcmd = NULL;
    c->user = DefaultUser;
    c->multibulklen = 0;
    c->bulklen = -1;
    c->sentlen = 0;
    c->flags = 0;
    c->ctime = c->lastinteraction = server.unixtime;
    
    c->authenticated = (c->user->flags & USER_FLAG_NOPASS) && !(c->user->flags & USER_FLAG_DISABLED);
    c->replstate = REPL_STATE_NONE;
    c->repl_put_online_on_ack = 0;
    c->reploff = 0;
    c->read_reploff = 0;
    c->repl_ack_off = 0;
    c->repl_ack_time = 0;
    c->repl_last_partial_write = 0;
    c->slave_listening_port = 0;
    c->slave_ip[0] = '\0';
    c->slave_capa = SLAVE_CAPA_NONE;
    c->reply = listCreate();
    c->reply_bytes = 0;
    c->obuf_soft_limit_reached_time = 0;
    listSetFreeMethod(c->reply,freeClientReplyValue);
    listSetDupMethod(c->reply,dupClientReplyValue);
    c->btype = BLOCKED_NONE;
    c->bpop.timeout = 0;
    c->bpop.keys = dictCreate(&objectKeyHeapPointerValueDictType,NULL);
    c->bpop.target = NULL;
    c->bpop.xread_group = NULL;
    c->bpop.xread_consumer = NULL;
    c->bpop.xread_group_noack = 0;
    c->bpop.numreplicas = 0;
    c->bpop.reploffset = 0;
    c->woff = 0;
    c->watched_keys = listCreate();
    c->pubsub_channels = dictCreate(&objectKeyPointerValueDictType,NULL);
    c->pubsub_patterns = listCreate();
    c->peerid = NULL;
    c->client_list_node = NULL;
    c->client_tracking_redirection = 0;
    c->client_tracking_prefixes = NULL;
    c->client_cron_last_memory_usage = 0;
    c->client_cron_last_memory_type = CLIENT_TYPE_NORMAL;
    c->auth_callback = NULL;
    c->auth_callback_privdata = NULL;
    c->auth_module = NULL;
    listSetFreeMethod(c->pubsub_patterns,decrRefCountVoid);
    listSetMatchMethod(c->pubsub_patterns,listMatchObjects);
    if (conn) linkClient(c);
    initClientMultiState(c);
    return c;
}


void clientInstallWriteHandler(client *c) {
    
    if (!(c->flags & CLIENT_PENDING_WRITE) && (c->replstate == REPL_STATE_NONE || (c->replstate == SLAVE_STATE_ONLINE && !c->repl_put_online_on_ack)))

    {
        
        c->flags |= CLIENT_PENDING_WRITE;
        listAddNodeHead(server.clients_pending_write,c);
    }
}


int prepareClientToWrite(client *c) {
    
    if (c->flags & (CLIENT_LUA|CLIENT_MODULE)) return C_OK;

    
    if (c->flags & CLIENT_CLOSE_ASAP) return C_ERR;

    
    if (c->flags & (CLIENT_REPLY_OFF|CLIENT_REPLY_SKIP)) return C_ERR;

    
    if ((c->flags & CLIENT_MASTER) && !(c->flags & CLIENT_MASTER_FORCE_REPLY)) return C_ERR;

    if (!c->conn) return C_ERR; 

    
    if (!clientHasPendingReplies(c) && !(c->flags & CLIENT_PENDING_READ))
            clientInstallWriteHandler(c);

    
    return C_OK;
}




int _addReplyToBuffer(client *c, const char *s, size_t len) {
    size_t available = sizeof(c->buf)-c->bufpos;

    if (c->flags & CLIENT_CLOSE_AFTER_REPLY) return C_OK;

    
    if (listLength(c->reply) > 0) return C_ERR;

    
    if (len > available) return C_ERR;

    memcpy(c->buf+c->bufpos,s,len);
    c->bufpos+=len;
    return C_OK;
}


void _addReplyProtoToList(client *c, const char *s, size_t len) {
    if (c->flags & CLIENT_CLOSE_AFTER_REPLY) return;

    listNode *ln = listLast(c->reply);
    clientReplyBlock *tail = ln? listNodeValue(ln): NULL;

    

    
    if (tail) {
        
        size_t avail = tail->size - tail->used;
        size_t copy = avail >= len? len: avail;
        memcpy(tail->buf + tail->used, s, copy);
        tail->used += copy;
        s += copy;
        len -= copy;
    }
    if (len) {
        
        size_t size = len < PROTO_REPLY_CHUNK_BYTES? PROTO_REPLY_CHUNK_BYTES: len;
        tail = zmalloc(size + sizeof(clientReplyBlock));
        
        tail->size = zmalloc_usable(tail) - sizeof(clientReplyBlock);
        tail->used = len;
        memcpy(tail->buf, s, len);
        listAddNodeTail(c->reply, tail);
        c->reply_bytes += tail->size;
    }
    asyncCloseClientOnOutputBufferLimitReached(c);
}




void addReply(client *c, robj *obj) {
    if (prepareClientToWrite(c) != C_OK) return;

    if (sdsEncodedObject(obj)) {
        if (_addReplyToBuffer(c,obj->ptr,sdslen(obj->ptr)) != C_OK)
            _addReplyProtoToList(c,obj->ptr,sdslen(obj->ptr));
    } else if (obj->encoding == OBJ_ENCODING_INT) {
        
        char buf[32];
        size_t len = ll2string(buf,sizeof(buf),(long)obj->ptr);
        if (_addReplyToBuffer(c,buf,len) != C_OK)
            _addReplyProtoToList(c,buf,len);
    } else {
        serverPanic("Wrong obj->encoding in addReply()");
    }
}


void addReplySds(client *c, sds s) {
    if (prepareClientToWrite(c) != C_OK) {
        
        sdsfree(s);
        return;
    }
    if (_addReplyToBuffer(c,s,sdslen(s)) != C_OK)
        _addReplyProtoToList(c,s,sdslen(s));
    sdsfree(s);
}


void addReplyProto(client *c, const char *s, size_t len) {
    if (prepareClientToWrite(c) != C_OK) return;
    if (_addReplyToBuffer(c,s,len) != C_OK)
        _addReplyProtoToList(c,s,len);
}


void addReplyErrorLength(client *c, const char *s, size_t len) {
    
    if (!len || s[0] != '-') addReplyProto(c,"-ERR ",5);
    addReplyProto(c,s,len);
    addReplyProto(c,"\r\n",2);
}


void afterErrorReply(client *c, const char *s, size_t len) {
    
    int ctype = getClientType(c);
    if (ctype == CLIENT_TYPE_MASTER || ctype == CLIENT_TYPE_SLAVE || c->id == CLIENT_ID_AOF) {
        char *to, *from;

        if (c->id == CLIENT_ID_AOF) {
            to = "AOF-loading-client";
            from = "server";
        } else if (ctype == CLIENT_TYPE_MASTER) {
            to = "master";
            from = "replica";
        } else {
            to = "replica";
            from = "master";
        }

        if (len > 4096) len = 4096;
        char *cmdname = c->lastcmd ? c->lastcmd->name : "<unknown>";
        serverLog(LL_WARNING,"== CRITICAL == This %s is sending an error " "to its %s: '%.*s' after processing the command " "'%s'", from, to, (int)len, s, cmdname);

        if (ctype == CLIENT_TYPE_MASTER && server.repl_backlog && server.repl_backlog_histlen > 0)
        {
            showLatestBacklog();
        }
        server.stat_unexpected_error_replies++;
    }
}


void addReplyErrorObject(client *c, robj *err) {
    addReply(c, err);
    afterErrorReply(c, err->ptr, sdslen(err->ptr)-2); 
}


void addReplyError(client *c, const char *err) {
    addReplyErrorLength(c,err,strlen(err));
    afterErrorReply(c,err,strlen(err));
}


void addReplyErrorSds(client *c, sds err) {
    addReplyErrorLength(c,err,sdslen(err));
    afterErrorReply(c,err,sdslen(err));
}


void addReplyErrorFormat(client *c, const char *fmt, ...) {
    va_list ap;
    va_start(ap,fmt);
    sds s = sdscatvprintf(sdsempty(),fmt,ap);
    va_end(ap);
    
    s = sdstrim(s, "\r\n");
    
    s = sdsmapchars(s, "\r\n", "  ",  2);
    addReplyErrorLength(c,s,sdslen(s));
    afterErrorReply(c,s,sdslen(s));
    sdsfree(s);
}

void addReplyStatusLength(client *c, const char *s, size_t len) {
    addReplyProto(c,"+",1);
    addReplyProto(c,s,len);
    addReplyProto(c,"\r\n",2);
}

void addReplyStatus(client *c, const char *status) {
    addReplyStatusLength(c,status,strlen(status));
}

void addReplyStatusFormat(client *c, const char *fmt, ...) {
    va_list ap;
    va_start(ap,fmt);
    sds s = sdscatvprintf(sdsempty(),fmt,ap);
    va_end(ap);
    addReplyStatusLength(c,s,sdslen(s));
    sdsfree(s);
}


void trimReplyUnusedTailSpace(client *c) {
    listNode *ln = listLast(c->reply);
    clientReplyBlock *tail = ln? listNodeValue(ln): NULL;

    
    if (!tail) return;

    
    if (tail->size - tail->used > tail->size / 4 && tail->used < PROTO_REPLY_CHUNK_BYTES)
    {
        size_t old_size = tail->size;
        tail = zrealloc(tail, tail->used + sizeof(clientReplyBlock));
        
        tail->size = zmalloc_usable(tail) - sizeof(clientReplyBlock);
        c->reply_bytes = c->reply_bytes + tail->size - old_size;
        listNodeValue(ln) = tail;
    }
}


void *addReplyDeferredLen(client *c) {
    
    if (prepareClientToWrite(c) != C_OK) return NULL;
    trimReplyUnusedTailSpace(c);
    listAddNodeTail(c->reply,NULL); 
    return listLast(c->reply);
}


void setDeferredAggregateLen(client *c, void *node, long length, char prefix) {
    serverAssert(length >= 0);
    listNode *ln = (listNode*)node;
    clientReplyBlock *next;
    char lenstr[128];
    size_t lenstr_len = sprintf(lenstr, "%c%ld\r\n", prefix, length);

    
    if (node == NULL) return;
    serverAssert(!listNodeValue(ln));

    
    if (ln->next != NULL && (next = listNodeValue(ln->next)) && next->size - next->used >= lenstr_len && next->used < PROTO_REPLY_CHUNK_BYTES * 4) {

        memmove(next->buf + lenstr_len, next->buf, next->used);
        memcpy(next->buf, lenstr, lenstr_len);
        next->used += lenstr_len;
        listDelNode(c->reply,ln);
    } else {
        
        clientReplyBlock *buf = zmalloc(lenstr_len + sizeof(clientReplyBlock));
        
        buf->size = zmalloc_usable(buf) - sizeof(clientReplyBlock);
        buf->used = lenstr_len;
        memcpy(buf->buf, lenstr, lenstr_len);
        listNodeValue(ln) = buf;
        c->reply_bytes += buf->size;
    }
    asyncCloseClientOnOutputBufferLimitReached(c);
}

void setDeferredArrayLen(client *c, void *node, long length) {
    setDeferredAggregateLen(c,node,length,'*');
}

void setDeferredMapLen(client *c, void *node, long length) {
    int prefix = c->resp == 2 ? '*' : '%';
    if (c->resp == 2) length *= 2;
    setDeferredAggregateLen(c,node,length,prefix);
}

void setDeferredSetLen(client *c, void *node, long length) {
    int prefix = c->resp == 2 ? '*' : '~';
    setDeferredAggregateLen(c,node,length,prefix);
}

void setDeferredAttributeLen(client *c, void *node, long length) {
    serverAssert(c->resp >= 3);
    setDeferredAggregateLen(c,node,length,'|');
}

void setDeferredPushLen(client *c, void *node, long length) {
    serverAssert(c->resp >= 3);
    setDeferredAggregateLen(c,node,length,'>');
}


void addReplyDouble(client *c, double d) {
    if (isinf(d)) {
        
        if (c->resp == 2) {
            addReplyBulkCString(c, d > 0 ? "inf" : "-inf");
        } else {
            addReplyProto(c, d > 0 ? ",inf\r\n" : ",-inf\r\n", d > 0 ? 6 : 7);
        }
    } else {
        char dbuf[MAX_LONG_DOUBLE_CHARS+3], sbuf[MAX_LONG_DOUBLE_CHARS+32];
        int dlen, slen;
        if (c->resp == 2) {
            dlen = snprintf(dbuf,sizeof(dbuf),"%.17g",d);
            slen = snprintf(sbuf,sizeof(sbuf),"$%d\r\n%s\r\n",dlen,dbuf);
            addReplyProto(c,sbuf,slen);
        } else {
            dlen = snprintf(dbuf,sizeof(dbuf),",%.17g\r\n",d);
            addReplyProto(c,dbuf,dlen);
        }
    }
}

void addReplyBigNum(client *c, const char* num, size_t len) {
    if (c->resp == 2) {
        addReplyBulkCBuffer(c, num, len);
    } else {
        addReplyProto(c,"(",1);
        addReplyProto(c,num,len);
        addReply(c,shared.crlf);
    }
}


void addReplyHumanLongDouble(client *c, long double d) {
    if (c->resp == 2) {
        robj *o = createStringObjectFromLongDouble(d,1);
        addReplyBulk(c,o);
        decrRefCount(o);
    } else {
        char buf[MAX_LONG_DOUBLE_CHARS];
        int len = ld2string(buf,sizeof(buf),d,LD_STR_HUMAN);
        addReplyProto(c,",",1);
        addReplyProto(c,buf,len);
        addReplyProto(c,"\r\n",2);
    }
}


void addReplyLongLongWithPrefix(client *c, long long ll, char prefix) {
    char buf[128];
    int len;

    
    if (prefix == '*' && ll < OBJ_SHARED_BULKHDR_LEN && ll >= 0) {
        addReply(c,shared.mbulkhdr[ll]);
        return;
    } else if (prefix == '$' && ll < OBJ_SHARED_BULKHDR_LEN && ll >= 0) {
        addReply(c,shared.bulkhdr[ll]);
        return;
    }

    buf[0] = prefix;
    len = ll2string(buf+1,sizeof(buf)-1,ll);
    buf[len+1] = '\r';
    buf[len+2] = '\n';
    addReplyProto(c,buf,len+3);
}

void addReplyLongLong(client *c, long long ll) {
    if (ll == 0)
        addReply(c,shared.czero);
    else if (ll == 1)
        addReply(c,shared.cone);
    else addReplyLongLongWithPrefix(c,ll,':');
}

void addReplyAggregateLen(client *c, long length, int prefix) {
    if (prefix == '*' && length < OBJ_SHARED_BULKHDR_LEN)
        addReply(c,shared.mbulkhdr[length]);
    else addReplyLongLongWithPrefix(c,length,prefix);
}

void addReplyArrayLen(client *c, long length) {
    addReplyAggregateLen(c,length,'*');
}

void addReplyMapLen(client *c, long length) {
    int prefix = c->resp == 2 ? '*' : '%';
    if (c->resp == 2) length *= 2;
    addReplyAggregateLen(c,length,prefix);
}

void addReplySetLen(client *c, long length) {
    int prefix = c->resp == 2 ? '*' : '~';
    addReplyAggregateLen(c,length,prefix);
}

void addReplyAttributeLen(client *c, long length) {
    serverAssert(c->resp >= 3);
    addReplyAggregateLen(c,length,'|');
}

void addReplyPushLen(client *c, long length) {
    serverAssert(c->resp >= 3);
    addReplyAggregateLen(c,length,'>');
}

void addReplyNull(client *c) {
    if (c->resp == 2) {
        addReplyProto(c,"$-1\r\n",5);
    } else {
        addReplyProto(c,"_\r\n",3);
    }
}

void addReplyBool(client *c, int b) {
    if (c->resp == 2) {
        addReply(c, b ? shared.cone : shared.czero);
    } else {
        addReplyProto(c, b ? "#t\r\n" : "#f\r\n",4);
    }
}


void addReplyNullArray(client *c) {
    if (c->resp == 2) {
        addReplyProto(c,"*-1\r\n",5);
    } else {
        addReplyProto(c,"_\r\n",3);
    }
}


void addReplyBulkLen(client *c, robj *obj) {
    size_t len = stringObjectLen(obj);

    if (len < OBJ_SHARED_BULKHDR_LEN)
        addReply(c,shared.bulkhdr[len]);
    else addReplyLongLongWithPrefix(c,len,'$');
}


void addReplyBulk(client *c, robj *obj) {
    addReplyBulkLen(c,obj);
    addReply(c,obj);
    addReply(c,shared.crlf);
}


void addReplyBulkCBuffer(client *c, const void *p, size_t len) {
    addReplyLongLongWithPrefix(c,len,'$');
    addReplyProto(c,p,len);
    addReply(c,shared.crlf);
}


void addReplyBulkSds(client *c, sds s)  {
    addReplyLongLongWithPrefix(c,sdslen(s),'$');
    addReplySds(c,s);
    addReply(c,shared.crlf);
}


void addReplyBulkCString(client *c, const char *s) {
    if (s == NULL) {
        addReplyNull(c);
    } else {
        addReplyBulkCBuffer(c,s,strlen(s));
    }
}


void addReplyBulkLongLong(client *c, long long ll) {
    char buf[64];
    int len;

    len = ll2string(buf,64,ll);
    addReplyBulkCBuffer(c,buf,len);
}


void addReplyVerbatim(client *c, const char *s, size_t len, const char *ext) {
    if (c->resp == 2) {
        addReplyBulkCBuffer(c,s,len);
    } else {
        char buf[32];
        size_t preflen = snprintf(buf,sizeof(buf),"=%zu\r\nxxx:",len+4);
        char *p = buf+preflen-4;
        for (int i = 0; i < 3; i++) {
            if (*ext == '\0') {
                p[i] = ' ';
            } else {
                p[i] = *ext++;
            }
        }
        addReplyProto(c,buf,preflen);
        addReplyProto(c,s,len);
        addReplyProto(c,"\r\n",2);
    }
}


void addReplyHelp(client *c, const char **help) {
    sds cmd = sdsnew((char*) c->argv[0]->ptr);
    void *blenp = addReplyDeferredLen(c);
    int blen = 0;

    sdstoupper(cmd);
    addReplyStatusFormat(c, "%s <subcommand> arg arg ... arg. Subcommands are:",cmd);
    sdsfree(cmd);

    while (help[blen]) addReplyStatus(c,help[blen++]);

    blen++;  
    setDeferredArrayLen(c,blenp,blen);
}


void addReplySubcommandSyntaxError(client *c) {
    sds cmd = sdsnew((char*) c->argv[0]->ptr);
    sdstoupper(cmd);
    addReplyErrorFormat(c, "Unknown subcommand or wrong number of arguments for '%s'. Try %s HELP.", (char*)c->argv[1]->ptr,cmd);

    sdsfree(cmd);
}


void AddReplyFromClient(client *dst, client *src) {
    
    if (src->flags & CLIENT_CLOSE_ASAP) {
        sds client = catClientInfoString(sdsempty(),dst);
        freeClientAsync(dst);
        serverLog(LL_WARNING,"Client %s scheduled to be closed ASAP for overcoming of output buffer limits.", client);
        sdsfree(client);
        return;
    }

    
    addReplyProto(dst,src->buf, src->bufpos);

    
    if (prepareClientToWrite(dst) != C_OK)
        return;

    
    if (dst->flags & CLIENT_CLOSE_AFTER_REPLY) return;

    
    if (listLength(src->reply))
        listJoin(dst->reply,src->reply);
    dst->reply_bytes += src->reply_bytes;
    src->reply_bytes = 0;
    src->bufpos = 0;

    
    asyncCloseClientOnOutputBufferLimitReached(dst);
}


void copyClientOutputBuffer(client *dst, client *src) {
    listRelease(dst->reply);
    dst->sentlen = 0;
    dst->reply = listDup(src->reply);
    memcpy(dst->buf,src->buf,src->bufpos);
    dst->bufpos = src->bufpos;
    dst->reply_bytes = src->reply_bytes;
}


int clientHasPendingReplies(client *c) {
    return c->bufpos || listLength(c->reply);
}

void clientAcceptHandler(connection *conn) {
    client *c = connGetPrivateData(conn);

    if (connGetState(conn) != CONN_STATE_CONNECTED) {
        serverLog(LL_WARNING, "Error accepting a client connection: %s", connGetLastError(conn));

        freeClientAsync(c);
        return;
    }

    
    if (server.protected_mode && server.bindaddr_count == 0 && DefaultUser->flags & USER_FLAG_NOPASS && !(c->flags & CLIENT_UNIX_SOCKET))


    {
        char cip[NET_IP_STR_LEN+1] = { 0 };
        connPeerToString(conn, cip, sizeof(cip)-1, NULL);

        if (strcmp(cip,"127.0.0.1") && strcmp(cip,"::1")) {
            char *err = "-DENIED Redis is running in protected mode because protected " "mode is enabled, no bind address was specified, no " "authentication password is requested to clients. In this mode " "connections are only accepted from the loopback interface. " "If you want to connect from external computers to Redis you " "may adopt one of the following solutions: " "1) Just disable protected mode sending the command " "'CONFIG SET protected-mode no' from the loopback interface " "by connecting to Redis from the same host the server is " "running, however MAKE SURE Redis is not publicly accessible " "from internet if you do so. Use CONFIG REWRITE to make this " "change permanent. " "2) Alternatively you can just disable the protected mode by " "editing the Redis configuration file, and setting the protected " "mode option to 'no', and then restarting the server. " "3) If you started the server manually just for testing, restart " "it with the '--protected-mode no' option. " "4) Setup a bind address or an authentication password. " "NOTE: You only need to do one of the above things in order for " "the server to start accepting connections from the outside.\r\n";



















            if (connWrite(c->conn,err,strlen(err)) == -1) {
                
            }
            server.stat_rejected_conn++;
            freeClientAsync(c);
            return;
        }
    }

    server.stat_numconnections++;
    moduleFireServerEvent(REDISMODULE_EVENT_CLIENT_CHANGE, REDISMODULE_SUBEVENT_CLIENT_CHANGE_CONNECTED, c);

}


static void acceptCommonHandler(connection *conn, int flags, char *ip) {
    client *c;
    char conninfo[100];
    UNUSED(ip);

    if (connGetState(conn) != CONN_STATE_ACCEPTING) {
        serverLog(LL_VERBOSE, "Accepted client connection in error state: %s (conn: %s)", connGetLastError(conn), connGetInfo(conn, conninfo, sizeof(conninfo)));


        connClose(conn);
        return;
    }

    
    if (listLength(server.clients) + getClusterConnectionsCount()
        >= server.maxclients)
    {
        char *err;
        if (server.cluster_enabled)
            err = "-ERR max number of clients + cluster " "connections reached\r\n";
        else err = "-ERR max number of clients reached\r\n";

        
        if (connWrite(conn,err,strlen(err)) == -1) {
            
        }
        server.stat_rejected_conn++;
        connClose(conn);
        return;
    }

    
    if ((c = createClient(conn)) == NULL) {
        serverLog(LL_WARNING, "Error registering fd event for the new client: %s (conn: %s)", connGetLastError(conn), connGetInfo(conn, conninfo, sizeof(conninfo)));


        connClose(conn); 
        return;
    }

    
    c->flags |= flags;

    
    if (connAccept(conn, clientAcceptHandler) == C_ERR) {
        char conninfo[100];
        if (connGetState(conn) == CONN_STATE_ERROR)
            serverLog(LL_WARNING, "Error accepting a client connection: %s (conn: %s)", connGetLastError(conn), connGetInfo(conn, conninfo, sizeof(conninfo)));

        freeClient(connGetPrivateData(conn));
        return;
    }
}

void acceptTcpHandler(aeEventLoop *el, int fd, void *privdata, int mask) {
    int cport, cfd, max = MAX_ACCEPTS_PER_CALL;
    char cip[NET_IP_STR_LEN];
    UNUSED(el);
    UNUSED(mask);
    UNUSED(privdata);

    while(max--) {
        cfd = anetTcpAccept(server.neterr, fd, cip, sizeof(cip), &cport);
        if (cfd == ANET_ERR) {
            if (errno != EWOULDBLOCK)
                serverLog(LL_WARNING, "Accepting client connection: %s", server.neterr);
            return;
        }
        serverLog(LL_VERBOSE,"Accepted %s:%d", cip, cport);
        acceptCommonHandler(connCreateAcceptedSocket(cfd),0,cip);
    }
}

void acceptTLSHandler(aeEventLoop *el, int fd, void *privdata, int mask) {
    int cport, cfd, max = MAX_ACCEPTS_PER_CALL;
    char cip[NET_IP_STR_LEN];
    UNUSED(el);
    UNUSED(mask);
    UNUSED(privdata);

    while(max--) {
        cfd = anetTcpAccept(server.neterr, fd, cip, sizeof(cip), &cport);
        if (cfd == ANET_ERR) {
            if (errno != EWOULDBLOCK)
                serverLog(LL_WARNING, "Accepting client connection: %s", server.neterr);
            return;
        }
        serverLog(LL_VERBOSE,"Accepted %s:%d", cip, cport);
        acceptCommonHandler(connCreateAcceptedTLS(cfd, server.tls_auth_clients),0,cip);
    }
}

void acceptUnixHandler(aeEventLoop *el, int fd, void *privdata, int mask) {
    int cfd, max = MAX_ACCEPTS_PER_CALL;
    UNUSED(el);
    UNUSED(mask);
    UNUSED(privdata);

    while(max--) {
        cfd = anetUnixAccept(server.neterr, fd);
        if (cfd == ANET_ERR) {
            if (errno != EWOULDBLOCK)
                serverLog(LL_WARNING, "Accepting client connection: %s", server.neterr);
            return;
        }
        serverLog(LL_VERBOSE,"Accepted connection to %s", server.unixsocket);
        acceptCommonHandler(connCreateAcceptedSocket(cfd),CLIENT_UNIX_SOCKET,NULL);
    }
}

static void freeClientArgv(client *c) {
    int j;
    for (j = 0; j < c->argc; j++)
        decrRefCount(c->argv[j]);
    c->argc = 0;
    c->cmd = NULL;
    c->argv_len_sum = 0;
}


void disconnectSlaves(void) {
    listIter li;
    listNode *ln;
    listRewind(server.slaves,&li);
    while((ln = listNext(&li))) {
        freeClient((client*)ln->value);
    }
}


void unlinkClient(client *c) {
    listNode *ln;

    
    if (server.current_client == c) server.current_client = NULL;

    
    if (c->conn) {
        
        if (c->client_list_node) {
            uint64_t id = htonu64(c->id);
            raxRemove(server.clients_index,(unsigned char*)&id,sizeof(id),NULL);
            listDelNode(server.clients,c->client_list_node);
            c->client_list_node = NULL;
        }

        
        if (c->flags & CLIENT_SLAVE && c->replstate == SLAVE_STATE_WAIT_BGSAVE_END && server.rdb_pipe_conns)

        {
            int i;
            for (i=0; i < server.rdb_pipe_numconns; i++) {
                if (server.rdb_pipe_conns[i] == c->conn) {
                    rdbPipeWriteHandlerConnRemoved(c->conn);
                    server.rdb_pipe_conns[i] = NULL;
                    break;
                }
            }
        }
        connClose(c->conn);
        c->conn = NULL;
    }

    
    if (c->flags & CLIENT_PENDING_WRITE) {
        ln = listSearchKey(server.clients_pending_write,c);
        serverAssert(ln != NULL);
        listDelNode(server.clients_pending_write,ln);
        c->flags &= ~CLIENT_PENDING_WRITE;
    }

    
    if (c->flags & CLIENT_PENDING_READ) {
        ln = listSearchKey(server.clients_pending_read,c);
        serverAssert(ln != NULL);
        listDelNode(server.clients_pending_read,ln);
        c->flags &= ~CLIENT_PENDING_READ;
    }

    
    if (c->flags & CLIENT_UNBLOCKED) {
        ln = listSearchKey(server.unblocked_clients,c);
        serverAssert(ln != NULL);
        listDelNode(server.unblocked_clients,ln);
        c->flags &= ~CLIENT_UNBLOCKED;
    }

    
    if (c->flags & CLIENT_TRACKING) disableTracking(c);
}

void freeClient(client *c) {
    listNode *ln;

    
    if (c->flags & CLIENT_PROTECTED) {
        freeClientAsync(c);
        return;
    }

    
    if (c->conn) {
        moduleFireServerEvent(REDISMODULE_EVENT_CLIENT_CHANGE, REDISMODULE_SUBEVENT_CLIENT_CHANGE_DISCONNECTED, c);

    }

    
    moduleNotifyUserChanged(c);

    
    if (c->flags & CLIENT_CLOSE_ASAP) {
        ln = listSearchKey(server.clients_to_close,c);
        serverAssert(ln != NULL);
        listDelNode(server.clients_to_close,ln);
    }

    
    if (server.master && c->flags & CLIENT_MASTER) {
        serverLog(LL_WARNING,"Connection with master lost.");
        if (!(c->flags & (CLIENT_PROTOCOL_ERROR|CLIENT_BLOCKED))) {
            c->flags &= ~(CLIENT_CLOSE_ASAP|CLIENT_CLOSE_AFTER_REPLY);
            replicationCacheMaster(c);
            return;
        }
    }

    
    if (getClientType(c) == CLIENT_TYPE_SLAVE) {
        serverLog(LL_WARNING,"Connection with replica %s lost.", replicationGetSlaveName(c));
    }

    
    sdsfree(c->querybuf);
    sdsfree(c->pending_querybuf);
    c->querybuf = NULL;

    
    if (c->flags & CLIENT_BLOCKED) unblockClient(c);
    dictRelease(c->bpop.keys);

    
    unwatchAllKeys(c);
    listRelease(c->watched_keys);

    
    pubsubUnsubscribeAllChannels(c,0);
    pubsubUnsubscribeAllPatterns(c,0);
    dictRelease(c->pubsub_channels);
    listRelease(c->pubsub_patterns);

    
    listRelease(c->reply);
    freeClientArgv(c);

    
    unlinkClient(c);

    
    if (c->flags & CLIENT_SLAVE) {
        if (c->replstate == SLAVE_STATE_SEND_BULK) {
            if (c->repldbfd != -1) close(c->repldbfd);
            if (c->replpreamble) sdsfree(c->replpreamble);
        }
        list *l = (c->flags & CLIENT_MONITOR) ? server.monitors : server.slaves;
        ln = listSearchKey(l,c);
        serverAssert(ln != NULL);
        listDelNode(l,ln);
        
        if (getClientType(c) == CLIENT_TYPE_SLAVE && listLength(server.slaves) == 0)
            server.repl_no_slaves_since = server.unixtime;
        refreshGoodSlavesCount();
        
        if (c->replstate == SLAVE_STATE_ONLINE)
            moduleFireServerEvent(REDISMODULE_EVENT_REPLICA_CHANGE, REDISMODULE_SUBEVENT_REPLICA_CHANGE_OFFLINE, NULL);

    }

    
    if (c->flags & CLIENT_MASTER) replicationHandleMasterDisconnection();

   
    server.stat_clients_type_memory[c->client_cron_last_memory_type] -= c->client_cron_last_memory_usage;

    
    if (c->name) decrRefCount(c->name);
    zfree(c->argv);
    c->argv_len_sum = 0;
    freeClientMultiState(c);
    sdsfree(c->peerid);
    zfree(c);
}


void freeClientAsync(client *c) {
    
    if (c->flags & CLIENT_CLOSE_ASAP || c->flags & CLIENT_LUA) return;
    c->flags |= CLIENT_CLOSE_ASAP;
    if (server.io_threads_num == 1) {
        
        listAddNodeTail(server.clients_to_close,c);
        return;
    }
    static pthread_mutex_t async_free_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&async_free_queue_mutex);
    listAddNodeTail(server.clients_to_close,c);
    pthread_mutex_unlock(&async_free_queue_mutex);
}


int freeClientsInAsyncFreeQueue(void) {
    int freed = 0;
    listIter li;
    listNode *ln;

    listRewind(server.clients_to_close,&li);
    while ((ln = listNext(&li)) != NULL) {
        client *c = listNodeValue(ln);

        if (c->flags & CLIENT_PROTECTED) continue;

        c->flags &= ~CLIENT_CLOSE_ASAP;
        freeClient(c);
        listDelNode(server.clients_to_close,ln);
        freed++;
    }
    return freed;
}


client *lookupClientByID(uint64_t id) {
    id = htonu64(id);
    client *c = raxFind(server.clients_index,(unsigned char*)&id,sizeof(id));
    return (c == raxNotFound) ? NULL : c;
}


int writeToClient(client *c, int handler_installed) {
    
    server.stat_total_writes_processed++;

    ssize_t nwritten = 0, totwritten = 0;
    size_t objlen;
    clientReplyBlock *o;

    while(clientHasPendingReplies(c)) {
        if (c->bufpos > 0) {
            nwritten = connWrite(c->conn,c->buf+c->sentlen,c->bufpos-c->sentlen);
            if (nwritten <= 0) break;
            c->sentlen += nwritten;
            totwritten += nwritten;

            
            if ((int)c->sentlen == c->bufpos) {
                c->bufpos = 0;
                c->sentlen = 0;
            }
        } else {
            o = listNodeValue(listFirst(c->reply));
            objlen = o->used;

            if (objlen == 0) {
                c->reply_bytes -= o->size;
                listDelNode(c->reply,listFirst(c->reply));
                continue;
            }

            nwritten = connWrite(c->conn, o->buf + c->sentlen, objlen - c->sentlen);
            if (nwritten <= 0) break;
            c->sentlen += nwritten;
            totwritten += nwritten;

            
            if (c->sentlen == objlen) {
                c->reply_bytes -= o->size;
                listDelNode(c->reply,listFirst(c->reply));
                c->sentlen = 0;
                
                if (listLength(c->reply) == 0)
                    serverAssert(c->reply_bytes == 0);
            }
        }
        
        if (totwritten > NET_MAX_WRITES_PER_EVENT && (server.maxmemory == 0 || zmalloc_used_memory() < server.maxmemory) && !(c->flags & CLIENT_SLAVE)) break;


    }
    server.stat_net_output_bytes += totwritten;
    if (nwritten == -1) {
        if (connGetState(c->conn) == CONN_STATE_CONNECTED) {
            nwritten = 0;
        } else {
            serverLog(LL_VERBOSE, "Error writing to client: %s", connGetLastError(c->conn));
            freeClientAsync(c);
            return C_ERR;
        }
    }
    if (totwritten > 0) {
        
        if (!(c->flags & CLIENT_MASTER)) c->lastinteraction = server.unixtime;
    }
    if (!clientHasPendingReplies(c)) {
        c->sentlen = 0;
        
        if (handler_installed) connSetWriteHandler(c->conn, NULL);

        
        if (c->flags & CLIENT_CLOSE_AFTER_REPLY) {
            freeClientAsync(c);
            return C_ERR;
        }
    }
    return C_OK;
}


void sendReplyToClient(connection *conn) {
    client *c = connGetPrivateData(conn);
    writeToClient(c,1);
}


int handleClientsWithPendingWrites(void) {
    listIter li;
    listNode *ln;
    int processed = listLength(server.clients_pending_write);

    listRewind(server.clients_pending_write,&li);
    while((ln = listNext(&li))) {
        client *c = listNodeValue(ln);
        c->flags &= ~CLIENT_PENDING_WRITE;
        listDelNode(server.clients_pending_write,ln);

        
        if (c->flags & CLIENT_PROTECTED) continue;

        
        if (c->flags & CLIENT_CLOSE_ASAP) continue;

        
        if (writeToClient(c,0) == C_ERR) continue;

        
        if (clientHasPendingReplies(c)) {
            int ae_barrier = 0;
            
            if (server.aof_state == AOF_ON && server.aof_fsync == AOF_FSYNC_ALWAYS)
            {
                ae_barrier = 1;
            }
            if (connSetWriteHandlerWithBarrier(c->conn, sendReplyToClient, ae_barrier) == C_ERR) {
                freeClientAsync(c);
            }
        }
    }
    return processed;
}


void resetClient(client *c) {
    redisCommandProc *prevcmd = c->cmd ? c->cmd->proc : NULL;

    freeClientArgv(c);
    c->reqtype = 0;
    c->multibulklen = 0;
    c->bulklen = -1;

    
    if (!(c->flags & CLIENT_MULTI) && prevcmd != askingCommand)
        c->flags &= ~CLIENT_ASKING;

    
    if (!(c->flags & CLIENT_MULTI) && prevcmd != clientCommand)
        c->flags &= ~CLIENT_TRACKING_CACHING;

    
    c->flags &= ~CLIENT_REPLY_SKIP;
    if (c->flags & CLIENT_REPLY_SKIP_NEXT) {
        c->flags |= CLIENT_REPLY_SKIP;
        c->flags &= ~CLIENT_REPLY_SKIP_NEXT;
    }
}


void protectClient(client *c) {
    c->flags |= CLIENT_PROTECTED;
    if (c->conn) {
        connSetReadHandler(c->conn,NULL);
        connSetWriteHandler(c->conn,NULL);
    }
}


void unprotectClient(client *c) {
    if (c->flags & CLIENT_PROTECTED) {
        c->flags &= ~CLIENT_PROTECTED;
        if (c->conn) {
            connSetReadHandler(c->conn,readQueryFromClient);
            if (clientHasPendingReplies(c)) clientInstallWriteHandler(c);
        }
    }
}


int processInlineBuffer(client *c) {
    char *newline;
    int argc, j, linefeed_chars = 1;
    sds *argv, aux;
    size_t querylen;

    
    newline = strchr(c->querybuf+c->qb_pos,'\n');

    
    if (newline == NULL) {
        if (sdslen(c->querybuf)-c->qb_pos > PROTO_INLINE_MAX_SIZE) {
            addReplyError(c,"Protocol error: too big inline request");
            setProtocolError("too big inline request",c);
        }
        return C_ERR;
    }

    
    if (newline && newline != c->querybuf+c->qb_pos && *(newline-1) == '\r')
        newline--, linefeed_chars++;

    
    querylen = newline-(c->querybuf+c->qb_pos);
    aux = sdsnewlen(c->querybuf+c->qb_pos,querylen);
    argv = sdssplitargs(aux,&argc);
    sdsfree(aux);
    if (argv == NULL) {
        addReplyError(c,"Protocol error: unbalanced quotes in request");
        setProtocolError("unbalanced quotes in inline request",c);
        return C_ERR;
    }

    
    if (querylen == 0 && getClientType(c) == CLIENT_TYPE_SLAVE)
        c->repl_ack_time = server.unixtime;

    
    if (querylen != 0 && c->flags & CLIENT_MASTER) {
        sdsfreesplitres(argv,argc);
        serverLog(LL_WARNING,"WARNING: Receiving inline protocol from master, master stream corruption? Closing the master connection and discarding the cached master.");
        setProtocolError("Master using the inline protocol. Desync?",c);
        return C_ERR;
    }

    
    c->qb_pos += querylen+linefeed_chars;

    
    if (argc) {
        if (c->argv) zfree(c->argv);
        c->argv = zmalloc(sizeof(robj*)*argc);
        c->argv_len_sum = 0;
    }

    
    for (c->argc = 0, j = 0; j < argc; j++) {
        c->argv[c->argc] = createObject(OBJ_STRING,argv[j]);
        c->argc++;
        c->argv_len_sum += sdslen(argv[j]);
    }
    zfree(argv);
    return C_OK;
}



static void setProtocolError(const char *errstr, client *c) {
    if (server.verbosity <= LL_VERBOSE || c->flags & CLIENT_MASTER) {
        sds client = catClientInfoString(sdsempty(),c);

        
        char buf[256];
        if (sdslen(c->querybuf)-c->qb_pos < PROTO_DUMP_LEN) {
            snprintf(buf,sizeof(buf),"Query buffer during protocol error: '%s'", c->querybuf+c->qb_pos);
        } else {
            snprintf(buf,sizeof(buf),"Query buffer during protocol error: '%.*s' (... more %zu bytes ...) '%.*s'", PROTO_DUMP_LEN/2, c->querybuf+c->qb_pos, sdslen(c->querybuf)-c->qb_pos-PROTO_DUMP_LEN, PROTO_DUMP_LEN/2, c->querybuf+sdslen(c->querybuf)-PROTO_DUMP_LEN/2);
        }

        
        char *p = buf;
        while (*p != '\0') {
            if (!isprint(*p)) *p = '.';
            p++;
        }

        
        int loglevel = (c->flags & CLIENT_MASTER) ? LL_WARNING :
                                                    LL_VERBOSE;
        serverLog(loglevel, "Protocol error (%s) from client: %s. %s", errstr, client, buf);
        sdsfree(client);
    }
    c->flags |= (CLIENT_CLOSE_AFTER_REPLY|CLIENT_PROTOCOL_ERROR);
}


int processMultibulkBuffer(client *c) {
    char *newline = NULL;
    int ok;
    long long ll;

    if (c->multibulklen == 0) {
        
        serverAssertWithInfo(c,NULL,c->argc == 0);

        
        newline = strchr(c->querybuf+c->qb_pos,'\r');
        if (newline == NULL) {
            if (sdslen(c->querybuf)-c->qb_pos > PROTO_INLINE_MAX_SIZE) {
                addReplyError(c,"Protocol error: too big mbulk count string");
                setProtocolError("too big mbulk count string",c);
            }
            return C_ERR;
        }

        
        if (newline-(c->querybuf+c->qb_pos) > (ssize_t)(sdslen(c->querybuf)-c->qb_pos-2))
            return C_ERR;

        
        serverAssertWithInfo(c,NULL,c->querybuf[c->qb_pos] == '*');
        ok = string2ll(c->querybuf+1+c->qb_pos,newline-(c->querybuf+1+c->qb_pos),&ll);
        if (!ok || ll > 1024*1024) {
            addReplyError(c,"Protocol error: invalid multibulk length");
            setProtocolError("invalid mbulk count",c);
            return C_ERR;
        }

        c->qb_pos = (newline-c->querybuf)+2;

        if (ll <= 0) return C_OK;

        c->multibulklen = ll;

        
        if (c->argv) zfree(c->argv);
        c->argv = zmalloc(sizeof(robj*)*c->multibulklen);
        c->argv_len_sum = 0;
    }

    serverAssertWithInfo(c,NULL,c->multibulklen > 0);
    while(c->multibulklen) {
        
        if (c->bulklen == -1) {
            newline = strchr(c->querybuf+c->qb_pos,'\r');
            if (newline == NULL) {
                if (sdslen(c->querybuf)-c->qb_pos > PROTO_INLINE_MAX_SIZE) {
                    addReplyError(c, "Protocol error: too big bulk count string");
                    setProtocolError("too big bulk count string",c);
                    return C_ERR;
                }
                break;
            }

            
            if (newline-(c->querybuf+c->qb_pos) > (ssize_t)(sdslen(c->querybuf)-c->qb_pos-2))
                break;

            if (c->querybuf[c->qb_pos] != '$') {
                addReplyErrorFormat(c, "Protocol error: expected '$', got '%c'", c->querybuf[c->qb_pos]);

                setProtocolError("expected $ but got something else",c);
                return C_ERR;
            }

            ok = string2ll(c->querybuf+c->qb_pos+1,newline-(c->querybuf+c->qb_pos+1),&ll);
            if (!ok || ll < 0 || (!(c->flags & CLIENT_MASTER) && ll > server.proto_max_bulk_len)) {
                addReplyError(c,"Protocol error: invalid bulk length");
                setProtocolError("invalid bulk length",c);
                return C_ERR;
            }

            c->qb_pos = newline-c->querybuf+2;
            if (ll >= PROTO_MBULK_BIG_ARG) {
                
                if (sdslen(c->querybuf)-c->qb_pos <= (size_t)ll+2) {
                    sdsrange(c->querybuf,c->qb_pos,-1);
                    c->qb_pos = 0;
                    
                    c->querybuf = sdsMakeRoomFor(c->querybuf,ll+2-sdslen(c->querybuf));
                }
            }
            c->bulklen = ll;
        }

        
        if (sdslen(c->querybuf)-c->qb_pos < (size_t)(c->bulklen+2)) {
            
            break;
        } else {
            
            if (c->qb_pos == 0 && c->bulklen >= PROTO_MBULK_BIG_ARG && sdslen(c->querybuf) == (size_t)(c->bulklen+2))

            {
                c->argv[c->argc++] = createObject(OBJ_STRING,c->querybuf);
                c->argv_len_sum += c->bulklen;
                sdsIncrLen(c->querybuf,-2); 
                
                c->querybuf = sdsnewlen(SDS_NOINIT,c->bulklen+2);
                sdsclear(c->querybuf);
            } else {
                c->argv[c->argc++] = createStringObject(c->querybuf+c->qb_pos,c->bulklen);
                c->argv_len_sum += c->bulklen;
                c->qb_pos += c->bulklen+2;
            }
            c->bulklen = -1;
            c->multibulklen--;
        }
    }

    
    if (c->multibulklen == 0) return C_OK;

    
    return C_ERR;
}


void commandProcessed(client *c) {
    long long prev_offset = c->reploff;
    if (c->flags & CLIENT_MASTER && !(c->flags & CLIENT_MULTI)) {
        
        c->reploff = c->read_reploff - sdslen(c->querybuf) + c->qb_pos;
    }

    
    if (!(c->flags & CLIENT_BLOCKED) || c->btype != BLOCKED_MODULE)
    {
        resetClient(c);
    }

    
    if (c->flags & CLIENT_MASTER) {
        long long applied = c->reploff - prev_offset;
        if (applied) {
            replicationFeedSlavesFromMasterStream(server.slaves, c->pending_querybuf, applied);
            sdsrange(c->pending_querybuf,applied,-1);
        }
    }
}


int processCommandAndResetClient(client *c) {
    int deadclient = 0;
    server.current_client = c;
    if (processCommand(c) == C_OK) {
        commandProcessed(c);
    }
    if (server.current_client == NULL) deadclient = 1;
    server.current_client = NULL;
    
    return deadclient ? C_ERR : C_OK;
}


int processPendingCommandsAndResetClient(client *c) {
    if (c->flags & CLIENT_PENDING_COMMAND) {
        c->flags &= ~CLIENT_PENDING_COMMAND;
        if (processCommandAndResetClient(c) == C_ERR) {
            return C_ERR;
        }
    }
    return C_OK;
}


void processInputBuffer(client *c) {
    
    while(c->qb_pos < sdslen(c->querybuf)) {
        
        if (!(c->flags & CLIENT_SLAVE) &&  !(c->flags & CLIENT_PENDING_READ) && clientsArePaused()) break;


        
        if (c->flags & CLIENT_BLOCKED) break;

        
        if (c->flags & CLIENT_PENDING_COMMAND) break;

        
        if (server.lua_timedout && c->flags & CLIENT_MASTER) break;

        
        if (c->flags & (CLIENT_CLOSE_AFTER_REPLY|CLIENT_CLOSE_ASAP)) break;

        
        if (!c->reqtype) {
            if (c->querybuf[c->qb_pos] == '*') {
                c->reqtype = PROTO_REQ_MULTIBULK;
            } else {
                c->reqtype = PROTO_REQ_INLINE;
            }
        }

        if (c->reqtype == PROTO_REQ_INLINE) {
            if (processInlineBuffer(c) != C_OK) break;
            
            if (server.gopher_enabled && !server.io_threads_do_reads && ((c->argc == 1 && ((char*)(c->argv[0]->ptr))[0] == '/') || c->argc == 0))

            {
                processGopherRequest(c);
                resetClient(c);
                c->flags |= CLIENT_CLOSE_AFTER_REPLY;
                break;
            }
        } else if (c->reqtype == PROTO_REQ_MULTIBULK) {
            if (processMultibulkBuffer(c) != C_OK) break;
        } else {
            serverPanic("Unknown request type");
        }

        
        if (c->argc == 0) {
            resetClient(c);
        } else {
            
            if (c->flags & CLIENT_PENDING_READ) {
                c->flags |= CLIENT_PENDING_COMMAND;
                break;
            }

            
            if (processCommandAndResetClient(c) == C_ERR) {
                
                return;
            }
        }
    }

    
    if (c->qb_pos) {
        sdsrange(c->querybuf,c->qb_pos,-1);
        c->qb_pos = 0;
    }
}

void readQueryFromClient(connection *conn) {
    client *c = connGetPrivateData(conn);
    int nread, readlen;
    size_t qblen;

    
    if (postponeClientRead(c)) return;

    
    server.stat_total_reads_processed++;

    readlen = PROTO_IOBUF_LEN;
    
    if (c->reqtype == PROTO_REQ_MULTIBULK && c->multibulklen && c->bulklen != -1 && c->bulklen >= PROTO_MBULK_BIG_ARG)
    {
        ssize_t remaining = (size_t)(c->bulklen+2)-sdslen(c->querybuf);

        
        if (remaining > 0 && remaining < readlen) readlen = remaining;
    }

    qblen = sdslen(c->querybuf);
    if (c->querybuf_peak < qblen) c->querybuf_peak = qblen;
    c->querybuf = sdsMakeRoomFor(c->querybuf, readlen);
    nread = connRead(c->conn, c->querybuf+qblen, readlen);
    if (nread == -1) {
        if (connGetState(conn) == CONN_STATE_CONNECTED) {
            return;
        } else {
            serverLog(LL_VERBOSE, "Reading from client: %s",connGetLastError(c->conn));
            freeClientAsync(c);
            return;
        }
    } else if (nread == 0) {
        serverLog(LL_VERBOSE, "Client closed connection");
        freeClientAsync(c);
        return;
    } else if (c->flags & CLIENT_MASTER) {
        
        c->pending_querybuf = sdscatlen(c->pending_querybuf, c->querybuf+qblen,nread);
    }

    sdsIncrLen(c->querybuf,nread);
    c->lastinteraction = server.unixtime;
    if (c->flags & CLIENT_MASTER) c->read_reploff += nread;
    server.stat_net_input_bytes += nread;
    if (sdslen(c->querybuf) > server.client_max_querybuf_len) {
        sds ci = catClientInfoString(sdsempty(),c), bytes = sdsempty();

        bytes = sdscatrepr(bytes,c->querybuf,64);
        serverLog(LL_WARNING,"Closing client that reached max query buffer length: %s (qbuf initial bytes: %s)", ci, bytes);
        sdsfree(ci);
        sdsfree(bytes);
        freeClientAsync(c);
        return;
    }

    
     processInputBuffer(c);
}

void getClientsMaxBuffers(unsigned long *longest_output_list, unsigned long *biggest_input_buffer) {
    client *c;
    listNode *ln;
    listIter li;
    unsigned long lol = 0, bib = 0;

    listRewind(server.clients,&li);
    while ((ln = listNext(&li)) != NULL) {
        c = listNodeValue(ln);

        if (listLength(c->reply) > lol) lol = listLength(c->reply);
        if (sdslen(c->querybuf) > bib) bib = sdslen(c->querybuf);
    }
    *longest_output_list = lol;
    *biggest_input_buffer = bib;
}


void genClientPeerId(client *client, char *peerid, size_t peerid_len) {
    if (client->flags & CLIENT_UNIX_SOCKET) {
        
        snprintf(peerid,peerid_len,"%s:0",server.unixsocket);
    } else {
        
        connFormatPeer(client->conn,peerid,peerid_len);
    }
}


char *getClientPeerId(client *c) {
    char peerid[NET_PEER_ID_LEN];

    if (c->peerid == NULL) {
        genClientPeerId(c,peerid,sizeof(peerid));
        c->peerid = sdsnew(peerid);
    }
    return c->peerid;
}


sds catClientInfoString(sds s, client *client) {
    char flags[16], events[3], conninfo[CONN_INFO_LEN], *p;

    p = flags;
    if (client->flags & CLIENT_SLAVE) {
        if (client->flags & CLIENT_MONITOR)
            *p++ = 'O';
        else *p++ = 'S';
    }
    if (client->flags & CLIENT_MASTER) *p++ = 'M';
    if (client->flags & CLIENT_PUBSUB) *p++ = 'P';
    if (client->flags & CLIENT_MULTI) *p++ = 'x';
    if (client->flags & CLIENT_BLOCKED) *p++ = 'b';
    if (client->flags & CLIENT_TRACKING) *p++ = 't';
    if (client->flags & CLIENT_TRACKING_BROKEN_REDIR) *p++ = 'R';
    if (client->flags & CLIENT_DIRTY_CAS) *p++ = 'd';
    if (client->flags & CLIENT_CLOSE_AFTER_REPLY) *p++ = 'c';
    if (client->flags & CLIENT_UNBLOCKED) *p++ = 'u';
    if (client->flags & CLIENT_CLOSE_ASAP) *p++ = 'A';
    if (client->flags & CLIENT_UNIX_SOCKET) *p++ = 'U';
    if (client->flags & CLIENT_READONLY) *p++ = 'r';
    if (p == flags) *p++ = 'N';
    *p++ = '\0';

    p = events;
    if (client->conn) {
        if (connHasReadHandler(client->conn)) *p++ = 'r';
        if (connHasWriteHandler(client->conn)) *p++ = 'w';
    }
    *p = '\0';

    
    size_t obufmem = getClientOutputBufferMemoryUsage(client);
    size_t total_mem = obufmem;
    total_mem += zmalloc_size(client); 
    total_mem += sdsZmallocSize(client->querybuf);
    
    total_mem += client->argv_len_sum;
    if (client->argv)
        total_mem += zmalloc_size(client->argv);

    return sdscatfmt(s, "id=%U addr=%s %s name=%s age=%I idle=%I flags=%s db=%i sub=%i psub=%i multi=%i qbuf=%U qbuf-free=%U argv-mem=%U obl=%U oll=%U omem=%U tot-mem=%U events=%s cmd=%s user=%s", (unsigned long long) client->id, getClientPeerId(client), connGetInfo(client->conn, conninfo, sizeof(conninfo)), client->name ? (char*)client->name->ptr : "", (long long)(server.unixtime - client->ctime), (long long)(server.unixtime - client->lastinteraction), flags, client->db->id, (int) dictSize(client->pubsub_channels), (int) listLength(client->pubsub_patterns), (client->flags & CLIENT_MULTI) ? client->mstate.count : -1, (unsigned long long) sdslen(client->querybuf), (unsigned long long) sdsavail(client->querybuf), (unsigned long long) client->argv_len_sum, (unsigned long long) client->bufpos, (unsigned long long) listLength(client->reply), (unsigned long long) obufmem, (unsigned long long) total_mem, events, client->lastcmd ? client->lastcmd->name : "NULL", client->user ? client->user->name : "(superuser)");





















}

sds getAllClientsInfoString(int type) {
    listNode *ln;
    listIter li;
    client *client;
    sds o = sdsnewlen(SDS_NOINIT,200*listLength(server.clients));
    sdsclear(o);
    listRewind(server.clients,&li);
    while ((ln = listNext(&li)) != NULL) {
        client = listNodeValue(ln);
        if (type != -1 && getClientType(client) != type) continue;
        o = catClientInfoString(o,client);
        o = sdscatlen(o,"\n",1);
    }
    return o;
}


int clientSetNameOrReply(client *c, robj *name) {
    int len = sdslen(name->ptr);
    char *p = name->ptr;

    
    if (len == 0) {
        if (c->name) decrRefCount(c->name);
        c->name = NULL;
        return C_OK;
    }

    
    for (int j = 0; j < len; j++) {
        if (p[j] < '!' || p[j] > '~') { 
            addReplyError(c, "Client names cannot contain spaces, " "newlines or special characters.");

            return C_ERR;
        }
    }
    if (c->name) decrRefCount(c->name);
    c->name = name;
    incrRefCount(name);
    return C_OK;
}

void clientCommand(client *c) {
    listNode *ln;
    listIter li;

    if (c->argc == 2 && !strcasecmp(c->argv[1]->ptr,"help")) {
        const char *help[] = {
"ID                     -- Return the ID of the current connection.", "GETNAME                -- Return the name of the current connection.", "KILL <ip:port>         -- Kill connection made from <ip:port>.", "KILL <option> <value> [option value ...] -- Kill connections. Options are:", "     ADDR <ip:port>                      -- Kill connection made from <ip:port>", "     TYPE (normal|master|replica|pubsub) -- Kill connections by type.", "     USER <username>   -- Kill connections authenticated with such user.", "     SKIPME (yes|no)   -- Skip killing current connection (default: yes).", "LIST [options ...]     -- Return information about client connections. Options:", "     TYPE (normal|master|replica|pubsub) -- Return clients of specified type.", "PAUSE <timeout>        -- Suspend all Redis clients for <timout> milliseconds.", "REPLY (on|off|skip)    -- Control the replies sent to the current connection.", "SETNAME <name>         -- Assign the name <name> to the current connection.", "UNBLOCK <clientid> [TIMEOUT|ERROR] -- Unblock the specified blocked client.", "TRACKING (on|off) [REDIRECT <id>] [BCAST] [PREFIX first] [PREFIX second] [OPTIN] [OPTOUT]... -- Enable client keys tracking for client side caching.", "CACHING  (yes|no)      -- Enable/Disable tracking of the keys for next command in OPTIN/OPTOUT mode.", "GETREDIR               -- Return the client ID we are redirecting to when tracking is enabled.", NULL };

















        addReplyHelp(c, help);
    } else if (!strcasecmp(c->argv[1]->ptr,"id") && c->argc == 2) {
        
        addReplyLongLong(c,c->id);
    } else if (!strcasecmp(c->argv[1]->ptr,"list")) {
        
        int type = -1;
        if (c->argc == 4 && !strcasecmp(c->argv[2]->ptr,"type")) {
            type = getClientTypeByName(c->argv[3]->ptr);
            if (type == -1) {
                addReplyErrorFormat(c,"Unknown client type '%s'", (char*) c->argv[3]->ptr);
                return;
             }
        } else if (c->argc != 2) {
            addReply(c,shared.syntaxerr);
            return;
        }
        sds o = getAllClientsInfoString(type);
        addReplyVerbatim(c,o,sdslen(o),"txt");
        sdsfree(o);
    } else if (!strcasecmp(c->argv[1]->ptr,"reply") && c->argc == 3) {
        
        if (!strcasecmp(c->argv[2]->ptr,"on")) {
            c->flags &= ~(CLIENT_REPLY_SKIP|CLIENT_REPLY_OFF);
            addReply(c,shared.ok);
        } else if (!strcasecmp(c->argv[2]->ptr,"off")) {
            c->flags |= CLIENT_REPLY_OFF;
        } else if (!strcasecmp(c->argv[2]->ptr,"skip")) {
            if (!(c->flags & CLIENT_REPLY_OFF))
                c->flags |= CLIENT_REPLY_SKIP_NEXT;
        } else {
            addReply(c,shared.syntaxerr);
            return;
        }
    } else if (!strcasecmp(c->argv[1]->ptr,"kill")) {
        
        char *addr = NULL;
        user *user = NULL;
        int type = -1;
        uint64_t id = 0;
        int skipme = 1;
        int killed = 0, close_this_client = 0;

        if (c->argc == 3) {
            
            addr = c->argv[2]->ptr;
            skipme = 0; 
        } else if (c->argc > 3) {
            int i = 2; 

            
            while(i < c->argc) {
                int moreargs = c->argc > i+1;

                if (!strcasecmp(c->argv[i]->ptr,"id") && moreargs) {
                    long long tmp;

                    if (getLongLongFromObjectOrReply(c,c->argv[i+1],&tmp,NULL)
                        != C_OK) return;
                    id = tmp;
                } else if (!strcasecmp(c->argv[i]->ptr,"type") && moreargs) {
                    type = getClientTypeByName(c->argv[i+1]->ptr);
                    if (type == -1) {
                        addReplyErrorFormat(c,"Unknown client type '%s'", (char*) c->argv[i+1]->ptr);
                        return;
                    }
                } else if (!strcasecmp(c->argv[i]->ptr,"addr") && moreargs) {
                    addr = c->argv[i+1]->ptr;
                } else if (!strcasecmp(c->argv[i]->ptr,"user") && moreargs) {
                    user = ACLGetUserByName(c->argv[i+1]->ptr, sdslen(c->argv[i+1]->ptr));
                    if (user == NULL) {
                        addReplyErrorFormat(c,"No such user '%s'", (char*) c->argv[i+1]->ptr);
                        return;
                    }
                } else if (!strcasecmp(c->argv[i]->ptr,"skipme") && moreargs) {
                    if (!strcasecmp(c->argv[i+1]->ptr,"yes")) {
                        skipme = 1;
                    } else if (!strcasecmp(c->argv[i+1]->ptr,"no")) {
                        skipme = 0;
                    } else {
                        addReply(c,shared.syntaxerr);
                        return;
                    }
                } else {
                    addReply(c,shared.syntaxerr);
                    return;
                }
                i += 2;
            }
        } else {
            addReply(c,shared.syntaxerr);
            return;
        }

        
        listRewind(server.clients,&li);
        while ((ln = listNext(&li)) != NULL) {
            client *client = listNodeValue(ln);
            if (addr && strcmp(getClientPeerId(client),addr) != 0) continue;
            if (type != -1 && getClientType(client) != type) continue;
            if (id != 0 && client->id != id) continue;
            if (user && client->user != user) continue;
            if (c == client && skipme) continue;

            
            if (c == client) {
                close_this_client = 1;
            } else {
                freeClient(client);
            }
            killed++;
        }

        
        if (c->argc == 3) {
            if (killed == 0)
                addReplyError(c,"No such client");
            else addReply(c,shared.ok);
        } else {
            addReplyLongLong(c,killed);
        }

        
        if (close_this_client) c->flags |= CLIENT_CLOSE_AFTER_REPLY;
    } else if (!strcasecmp(c->argv[1]->ptr,"unblock") && (c->argc == 3 || c->argc == 4))
    {
        
        long long id;
        int unblock_error = 0;

        if (c->argc == 4) {
            if (!strcasecmp(c->argv[3]->ptr,"timeout")) {
                unblock_error = 0;
            } else if (!strcasecmp(c->argv[3]->ptr,"error")) {
                unblock_error = 1;
            } else {
                addReplyError(c, "CLIENT UNBLOCK reason should be TIMEOUT or ERROR");
                return;
            }
        }
        if (getLongLongFromObjectOrReply(c,c->argv[2],&id,NULL)
            != C_OK) return;
        struct client *target = lookupClientByID(id);
        if (target && target->flags & CLIENT_BLOCKED) {
            if (unblock_error)
                addReplyError(target, "-UNBLOCKED client unblocked via CLIENT UNBLOCK");
            else replyToBlockedClientTimedOut(target);
            unblockClient(target);
            addReply(c,shared.cone);
        } else {
            addReply(c,shared.czero);
        }
    } else if (!strcasecmp(c->argv[1]->ptr,"setname") && c->argc == 3) {
        
        if (clientSetNameOrReply(c,c->argv[2]) == C_OK)
            addReply(c,shared.ok);
    } else if (!strcasecmp(c->argv[1]->ptr,"getname") && c->argc == 2) {
        
        if (c->name)
            addReplyBulk(c,c->name);
        else addReplyNull(c);
    } else if (!strcasecmp(c->argv[1]->ptr,"pause") && c->argc == 3) {
        
        long long duration;

        if (getTimeoutFromObjectOrReply(c,c->argv[2],&duration, UNIT_MILLISECONDS) != C_OK) return;
        pauseClients(duration);
        addReply(c,shared.ok);
    } else if (!strcasecmp(c->argv[1]->ptr,"tracking") && c->argc >= 3) {
        
        long long redir = 0;
        uint64_t options = 0;
        robj **prefix = NULL;
        size_t numprefix = 0;

        
        for (int j = 3; j < c->argc; j++) {
            int moreargs = (c->argc-1) - j;

            if (!strcasecmp(c->argv[j]->ptr,"redirect") && moreargs) {
                j++;
                if (redir != 0) {
                    addReplyError(c,"A client can only redirect to a single " "other client");
                    zfree(prefix);
                    return;
                }

                if (getLongLongFromObjectOrReply(c,c->argv[j],&redir,NULL) != C_OK)
                {
                    zfree(prefix);
                    return;
                }
                
                if (lookupClientByID(redir) == NULL) {
                    addReplyError(c,"The client ID you want redirect to " "does not exist");
                    zfree(prefix);
                    return;
                }
            } else if (!strcasecmp(c->argv[j]->ptr,"bcast")) {
                options |= CLIENT_TRACKING_BCAST;
            } else if (!strcasecmp(c->argv[j]->ptr,"optin")) {
                options |= CLIENT_TRACKING_OPTIN;
            } else if (!strcasecmp(c->argv[j]->ptr,"optout")) {
                options |= CLIENT_TRACKING_OPTOUT;
            } else if (!strcasecmp(c->argv[j]->ptr,"noloop")) {
                options |= CLIENT_TRACKING_NOLOOP;
            } else if (!strcasecmp(c->argv[j]->ptr,"prefix") && moreargs) {
                j++;
                prefix = zrealloc(prefix,sizeof(robj*)*(numprefix+1));
                prefix[numprefix++] = c->argv[j];
            } else {
                zfree(prefix);
                addReply(c,shared.syntaxerr);
                return;
            }
        }

        
        if (!strcasecmp(c->argv[2]->ptr,"on")) {
            
            if (!(options & CLIENT_TRACKING_BCAST) && numprefix) {
                addReplyError(c, "PREFIX option requires BCAST mode to be enabled");
                zfree(prefix);
                return;
            }

            if (c->flags & CLIENT_TRACKING) {
                int oldbcast = !!(c->flags & CLIENT_TRACKING_BCAST);
                int newbcast = !!(options & CLIENT_TRACKING_BCAST);
                if (oldbcast != newbcast) {
                    addReplyError(c, "You can't switch BCAST mode on/off before disabling " "tracking for this client, and then re-enabling it with " "a different mode.");


                    zfree(prefix);
                    return;
                }
            }

            if (options & CLIENT_TRACKING_BCAST && options & (CLIENT_TRACKING_OPTIN|CLIENT_TRACKING_OPTOUT))
            {
                addReplyError(c, "OPTIN and OPTOUT are not compatible with BCAST");
                zfree(prefix);
                return;
            }

            if (options & CLIENT_TRACKING_OPTIN && options & CLIENT_TRACKING_OPTOUT)
            {
                addReplyError(c, "You can't specify both OPTIN mode and OPTOUT mode");
                zfree(prefix);
                return;
            }

            if ((options & CLIENT_TRACKING_OPTIN && c->flags & CLIENT_TRACKING_OPTOUT) || (options & CLIENT_TRACKING_OPTOUT && c->flags & CLIENT_TRACKING_OPTIN))
            {
                addReplyError(c, "You can't switch OPTIN/OPTOUT mode before disabling " "tracking for this client, and then re-enabling it with " "a different mode.");


                zfree(prefix);
                return;
            }

            enableTracking(c,redir,options,prefix,numprefix);
        } else if (!strcasecmp(c->argv[2]->ptr,"off")) {
            disableTracking(c);
        } else {
            zfree(prefix);
            addReply(c,shared.syntaxerr);
            return;
        }
        zfree(prefix);
        addReply(c,shared.ok);
    } else if (!strcasecmp(c->argv[1]->ptr,"caching") && c->argc >= 3) {
        if (!(c->flags & CLIENT_TRACKING)) {
            addReplyError(c,"CLIENT CACHING can be called only when the " "client is in tracking mode with OPTIN or " "OPTOUT mode enabled");

            return;
        }

        char *opt = c->argv[2]->ptr;
        if (!strcasecmp(opt,"yes")) {
            if (c->flags & CLIENT_TRACKING_OPTIN) {
                c->flags |= CLIENT_TRACKING_CACHING;
            } else {
                addReplyError(c,"CLIENT CACHING YES is only valid when tracking is enabled in OPTIN mode.");
                return;
            }
        } else if (!strcasecmp(opt,"no")) {
            if (c->flags & CLIENT_TRACKING_OPTOUT) {
                c->flags |= CLIENT_TRACKING_CACHING;
            } else {
                addReplyError(c,"CLIENT CACHING NO is only valid when tracking is enabled in OPTOUT mode.");
                return;
            }
        } else {
            addReply(c,shared.syntaxerr);
            return;
        }

        
        addReply(c,shared.ok);
    } else if (!strcasecmp(c->argv[1]->ptr,"getredir") && c->argc == 2) {
        
        if (c->flags & CLIENT_TRACKING) {
            addReplyLongLong(c,c->client_tracking_redirection);
        } else {
            addReplyLongLong(c,-1);
        }
    } else {
        addReplyErrorFormat(c, "Unknown subcommand or wrong number of arguments for '%s'. Try CLIENT HELP", (char*)c->argv[1]->ptr);
    }
}


void helloCommand(client *c) {
    long long ver;

    if (getLongLongFromObject(c->argv[1],&ver) != C_OK || ver < 2 || ver > 3)
    {
        addReplyError(c,"-NOPROTO unsupported protocol version");
        return;
    }

    for (int j = 2; j < c->argc; j++) {
        int moreargs = (c->argc-1) - j;
        const char *opt = c->argv[j]->ptr;
        if (!strcasecmp(opt,"AUTH") && moreargs >= 2) {
            if (ACLAuthenticateUser(c, c->argv[j+1], c->argv[j+2]) == C_ERR) {
                addReplyError(c,"-WRONGPASS invalid username-password pair");
                return;
            }
            j += 2;
        } else if (!strcasecmp(opt,"SETNAME") && moreargs) {
            if (clientSetNameOrReply(c, c->argv[j+1]) == C_ERR) return;
            j++;
        } else {
            addReplyErrorFormat(c,"Syntax error in HELLO option '%s'",opt);
            return;
        }
    }

    
    if (!c->authenticated) {
        addReplyError(c,"-NOAUTH HELLO must be called with the client already " "authenticated, otherwise the HELLO AUTH <user> <pass> " "option can be used to authenticate the client and " "select the RESP protocol version at the same time");


        return;
    }

    
    c->resp = ver;
    addReplyMapLen(c,6 + !server.sentinel_mode);

    addReplyBulkCString(c,"server");
    addReplyBulkCString(c,"redis");

    addReplyBulkCString(c,"version");
    addReplyBulkCString(c,REDIS_VERSION);

    addReplyBulkCString(c,"proto");
    addReplyLongLong(c,ver);

    addReplyBulkCString(c,"id");
    addReplyLongLong(c,c->id);

    addReplyBulkCString(c,"mode");
    if (server.sentinel_mode) addReplyBulkCString(c,"sentinel");
    else if (server.cluster_enabled) addReplyBulkCString(c,"cluster");
    else addReplyBulkCString(c,"standalone");

    if (!server.sentinel_mode) {
        addReplyBulkCString(c,"role");
        addReplyBulkCString(c,server.masterhost ? "replica" : "master");
    }

    addReplyBulkCString(c,"modules");
    addReplyLoadedModules(c);
}


void securityWarningCommand(client *c) {
    static time_t logged_time;
    time_t now = time(NULL);

    if (labs(now-logged_time) > 60) {
        serverLog(LL_WARNING,"Possible SECURITY ATTACK detected. It looks like somebody is sending POST or Host: commands to Redis. This is likely due to an attacker attempting to use Cross Protocol Scripting to compromise your Redis instance. Connection aborted.");
        logged_time = now;
    }
    freeClientAsync(c);
}


void rewriteClientCommandVector(client *c, int argc, ...) {
    va_list ap;
    int j;
    robj **argv; 

    argv = zmalloc(sizeof(robj*)*argc);
    va_start(ap,argc);
    for (j = 0; j < argc; j++) {
        robj *a;

        a = va_arg(ap, robj*);
        argv[j] = a;
        incrRefCount(a);
    }
    
    for (j = 0; j < c->argc; j++) decrRefCount(c->argv[j]);
    zfree(c->argv);
    
    c->argv = argv;
    c->argc = argc;
    c->argv_len_sum = 0;
    for (j = 0; j < c->argc; j++)
        if (c->argv[j])
            c->argv_len_sum += getStringObjectLen(c->argv[j]);
    c->cmd = lookupCommandOrOriginal(c->argv[0]->ptr);
    serverAssertWithInfo(c,NULL,c->cmd != NULL);
    va_end(ap);
}


void replaceClientCommandVector(client *c, int argc, robj **argv) {
    int j;
    freeClientArgv(c);
    zfree(c->argv);
    c->argv = argv;
    c->argc = argc;
    c->argv_len_sum = 0;
    for (j = 0; j < c->argc; j++)
        if (c->argv[j])
            c->argv_len_sum += getStringObjectLen(c->argv[j]);
    c->cmd = lookupCommandOrOriginal(c->argv[0]->ptr);
    serverAssertWithInfo(c,NULL,c->cmd != NULL);
}


void rewriteClientCommandArgument(client *c, int i, robj *newval) {
    robj *oldval;

    if (i >= c->argc) {
        c->argv = zrealloc(c->argv,sizeof(robj*)*(i+1));
        c->argc = i+1;
        c->argv[i] = NULL;
    }
    oldval = c->argv[i];
    if (oldval) c->argv_len_sum -= getStringObjectLen(oldval);
    if (newval) c->argv_len_sum += getStringObjectLen(newval);
    c->argv[i] = newval;
    incrRefCount(newval);
    if (oldval) decrRefCount(oldval);

    
    if (i == 0) {
        c->cmd = lookupCommandOrOriginal(c->argv[0]->ptr);
        serverAssertWithInfo(c,NULL,c->cmd != NULL);
    }
}


unsigned long getClientOutputBufferMemoryUsage(client *c) {
    unsigned long list_item_size = sizeof(listNode) + sizeof(clientReplyBlock);
    return c->reply_bytes + (list_item_size*listLength(c->reply));
}


int getClientType(client *c) {
    if (c->flags & CLIENT_MASTER) return CLIENT_TYPE_MASTER;
    
    if ((c->flags & CLIENT_SLAVE) && !(c->flags & CLIENT_MONITOR))
        return CLIENT_TYPE_SLAVE;
    if (c->flags & CLIENT_PUBSUB) return CLIENT_TYPE_PUBSUB;
    return CLIENT_TYPE_NORMAL;
}

int getClientTypeByName(char *name) {
    if (!strcasecmp(name,"normal")) return CLIENT_TYPE_NORMAL;
    else if (!strcasecmp(name,"slave")) return CLIENT_TYPE_SLAVE;
    else if (!strcasecmp(name,"replica")) return CLIENT_TYPE_SLAVE;
    else if (!strcasecmp(name,"pubsub")) return CLIENT_TYPE_PUBSUB;
    else if (!strcasecmp(name,"master")) return CLIENT_TYPE_MASTER;
    else return -1;
}

char *getClientTypeName(int class) {
    switch(class) {
    case CLIENT_TYPE_NORMAL: return "normal";
    case CLIENT_TYPE_SLAVE:  return "slave";
    case CLIENT_TYPE_PUBSUB: return "pubsub";
    case CLIENT_TYPE_MASTER: return "master";
    default:                       return NULL;
    }
}


int checkClientOutputBufferLimits(client *c) {
    int soft = 0, hard = 0, class;
    unsigned long used_mem = getClientOutputBufferMemoryUsage(c);

    class = getClientType(c);
    
    if (class == CLIENT_TYPE_MASTER) class = CLIENT_TYPE_NORMAL;

    if (server.client_obuf_limits[class].hard_limit_bytes && used_mem >= server.client_obuf_limits[class].hard_limit_bytes)
        hard = 1;
    if (server.client_obuf_limits[class].soft_limit_bytes && used_mem >= server.client_obuf_limits[class].soft_limit_bytes)
        soft = 1;

    
    if (soft) {
        if (c->obuf_soft_limit_reached_time == 0) {
            c->obuf_soft_limit_reached_time = server.unixtime;
            soft = 0; 
        } else {
            time_t elapsed = server.unixtime - c->obuf_soft_limit_reached_time;

            if (elapsed <= server.client_obuf_limits[class].soft_limit_seconds) {
                soft = 0; 
            }
        }
    } else {
        c->obuf_soft_limit_reached_time = 0;
    }
    return soft || hard;
}


void asyncCloseClientOnOutputBufferLimitReached(client *c) {
    if (!c->conn) return; 
    serverAssert(c->reply_bytes < SIZE_MAX-(1024*64));
    if (c->reply_bytes == 0 || c->flags & CLIENT_CLOSE_ASAP) return;
    if (checkClientOutputBufferLimits(c)) {
        sds client = catClientInfoString(sdsempty(),c);

        freeClientAsync(c);
        serverLog(LL_WARNING,"Client %s scheduled to be closed ASAP for overcoming of output buffer limits.", client);
        sdsfree(client);
    }
}


void flushSlavesOutputBuffers(void) {
    listIter li;
    listNode *ln;

    listRewind(server.slaves,&li);
    while((ln = listNext(&li))) {
        client *slave = listNodeValue(ln);
        int can_receive_writes = connHasWriteHandler(slave->conn) || (slave->flags & CLIENT_PENDING_WRITE);

        
        if (slave->replstate == SLAVE_STATE_ONLINE && can_receive_writes && !slave->repl_put_online_on_ack && clientHasPendingReplies(slave))


        {
            writeToClient(slave,0);
        }
    }
}


void pauseClients(mstime_t end) {
    if (!server.clients_paused || end > server.clients_pause_end_time)
        server.clients_pause_end_time = end;
    server.clients_paused = 1;
}


int clientsArePaused(void) {
    if (server.clients_paused && server.clients_pause_end_time < server.mstime)
    {
        listNode *ln;
        listIter li;
        client *c;

        server.clients_paused = 0;

        
        listRewind(server.clients,&li);
        while ((ln = listNext(&li)) != NULL) {
            c = listNodeValue(ln);

            
            if (c->flags & (CLIENT_SLAVE|CLIENT_BLOCKED)) continue;
            queueClientForReprocessing(c);
        }
    }
    return server.clients_paused;
}


void processEventsWhileBlocked(void) {
    int iterations = 4; 

    
    ProcessingEventsWhileBlocked = 1;
    while (iterations--) {
        long long startval = server.events_processed_while_blocked;
        long long ae_events = aeProcessEvents(server.el, AE_FILE_EVENTS|AE_DONT_WAIT| AE_CALL_BEFORE_SLEEP|AE_CALL_AFTER_SLEEP);

        
        server.events_processed_while_blocked += ae_events;
        long long events = server.events_processed_while_blocked - startval;
        if (!events) break;
    }
    ProcessingEventsWhileBlocked = 0;
}



int tio_debug = 0;





pthread_t io_threads[IO_THREADS_MAX_NUM];
pthread_mutex_t io_threads_mutex[IO_THREADS_MAX_NUM];
_Atomic unsigned long io_threads_pending[IO_THREADS_MAX_NUM];
int io_threads_op;      


list *io_threads_list[IO_THREADS_MAX_NUM];

void *IOThreadMain(void *myid) {
    
    long id = (unsigned long)myid;
    char thdname[16];

    snprintf(thdname, sizeof(thdname), "io_thd_%ld", id);
    redis_set_thread_title(thdname);
    redisSetCpuAffinity(server.server_cpulist);
    makeThreadKillable();

    while(1) {
        
        for (int j = 0; j < 1000000; j++) {
            if (io_threads_pending[id] != 0) break;
        }

        
        if (io_threads_pending[id] == 0) {
            pthread_mutex_lock(&io_threads_mutex[id]);
            pthread_mutex_unlock(&io_threads_mutex[id]);
            continue;
        }

        serverAssert(io_threads_pending[id] != 0);

        if (tio_debug) printf("[%ld] %d to handle\n", id, (int)listLength(io_threads_list[id]));

        
        listIter li;
        listNode *ln;
        listRewind(io_threads_list[id],&li);
        while((ln = listNext(&li))) {
            client *c = listNodeValue(ln);
            if (io_threads_op == IO_THREADS_OP_WRITE) {
                writeToClient(c,0);
            } else if (io_threads_op == IO_THREADS_OP_READ) {
                readQueryFromClient(c->conn);
            } else {
                serverPanic("io_threads_op value is unknown");
            }
        }
        listEmpty(io_threads_list[id]);
        io_threads_pending[id] = 0;

        if (tio_debug) printf("[%ld] Done\n", id);
    }
}


void initThreadedIO(void) {
    server.io_threads_active = 0; 

    
    if (server.io_threads_num == 1) return;

    if (server.io_threads_num > IO_THREADS_MAX_NUM) {
        serverLog(LL_WARNING,"Fatal: too many I/O threads configured. " "The maximum number is %d.", IO_THREADS_MAX_NUM);
        exit(1);
    }

    
    for (int i = 0; i < server.io_threads_num; i++) {
        
        io_threads_list[i] = listCreate();
        if (i == 0) continue; 

        
        pthread_t tid;
        pthread_mutex_init(&io_threads_mutex[i],NULL);
        io_threads_pending[i] = 0;
        pthread_mutex_lock(&io_threads_mutex[i]); 
        if (pthread_create(&tid,NULL,IOThreadMain,(void*)(long)i) != 0) {
            serverLog(LL_WARNING,"Fatal: Can't initialize IO thread.");
            exit(1);
        }
        io_threads[i] = tid;
    }
}

void killIOThreads(void) {
    int err, j;
    for (j = 0; j < server.io_threads_num; j++) {
        if (io_threads[j] == pthread_self()) continue;
        if (io_threads[j] && pthread_cancel(io_threads[j]) == 0) {
            if ((err = pthread_join(io_threads[j],NULL)) != 0) {
                serverLog(LL_WARNING, "IO thread(tid:%lu) can not be joined: %s", (unsigned long)io_threads[j], strerror(err));

            } else {
                serverLog(LL_WARNING, "IO thread(tid:%lu) terminated",(unsigned long)io_threads[j]);
            }
        }
    }
}

void startThreadedIO(void) {
    if (tio_debug) { printf("S"); fflush(stdout); }
    if (tio_debug) printf("--- STARTING THREADED IO ---\n");
    serverAssert(server.io_threads_active == 0);
    for (int j = 1; j < server.io_threads_num; j++)
        pthread_mutex_unlock(&io_threads_mutex[j]);
    server.io_threads_active = 1;
}

void stopThreadedIO(void) {
    
    handleClientsWithPendingReadsUsingThreads();
    if (tio_debug) { printf("E"); fflush(stdout); }
    if (tio_debug) printf("--- STOPPING THREADED IO [R%d] [W%d] ---\n", (int) listLength(server.clients_pending_read), (int) listLength(server.clients_pending_write));

    serverAssert(server.io_threads_active == 1);
    for (int j = 1; j < server.io_threads_num; j++)
        pthread_mutex_lock(&io_threads_mutex[j]);
    server.io_threads_active = 0;
}


int stopThreadedIOIfNeeded(void) {
    int pending = listLength(server.clients_pending_write);

    
    if (server.io_threads_num == 1) return 1;

    if (pending < (server.io_threads_num*2)) {
        if (server.io_threads_active) stopThreadedIO();
        return 1;
    } else {
        return 0;
    }
}

int handleClientsWithPendingWritesUsingThreads(void) {
    int processed = listLength(server.clients_pending_write);
    if (processed == 0) return 0; 

    
    if (server.io_threads_num == 1 || stopThreadedIOIfNeeded()) {
        return handleClientsWithPendingWrites();
    }

    
    if (!server.io_threads_active) startThreadedIO();

    if (tio_debug) printf("%d TOTAL WRITE pending clients\n", processed);

    
    listIter li;
    listNode *ln;
    listRewind(server.clients_pending_write,&li);
    int item_id = 0;
    while((ln = listNext(&li))) {
        client *c = listNodeValue(ln);
        c->flags &= ~CLIENT_PENDING_WRITE;

        
        if (c->flags & CLIENT_CLOSE_ASAP) {
            listDelNode(server.clients_pending_write, ln);
            continue;
        }

        int target_id = item_id % server.io_threads_num;
        listAddNodeTail(io_threads_list[target_id],c);
        item_id++;
    }

    
    io_threads_op = IO_THREADS_OP_WRITE;
    for (int j = 1; j < server.io_threads_num; j++) {
        int count = listLength(io_threads_list[j]);
        io_threads_pending[j] = count;
    }

    
    listRewind(io_threads_list[0],&li);
    while((ln = listNext(&li))) {
        client *c = listNodeValue(ln);
        writeToClient(c,0);
    }
    listEmpty(io_threads_list[0]);

    
    while(1) {
        unsigned long pending = 0;
        for (int j = 1; j < server.io_threads_num; j++)
            pending += io_threads_pending[j];
        if (pending == 0) break;
    }
    if (tio_debug) printf("I/O WRITE All threads finshed\n");

    
    listRewind(server.clients_pending_write,&li);
    while((ln = listNext(&li))) {
        client *c = listNodeValue(ln);

        
        if (clientHasPendingReplies(c) && connSetWriteHandler(c->conn, sendReplyToClient) == AE_ERR)
        {
            freeClientAsync(c);
        }
    }
    listEmpty(server.clients_pending_write);

    
    server.stat_io_writes_processed += processed;

    return processed;
}


int postponeClientRead(client *c) {
    if (server.io_threads_active && server.io_threads_do_reads && !clientsArePaused() && !ProcessingEventsWhileBlocked && !(c->flags & (CLIENT_MASTER|CLIENT_SLAVE|CLIENT_PENDING_READ)))



    {
        c->flags |= CLIENT_PENDING_READ;
        listAddNodeHead(server.clients_pending_read,c);
        return 1;
    } else {
        return 0;
    }
}


int handleClientsWithPendingReadsUsingThreads(void) {
    if (!server.io_threads_active || !server.io_threads_do_reads) return 0;
    int processed = listLength(server.clients_pending_read);
    if (processed == 0) return 0;

    if (tio_debug) printf("%d TOTAL READ pending clients\n", processed);

    
    listIter li;
    listNode *ln;
    listRewind(server.clients_pending_read,&li);
    int item_id = 0;
    while((ln = listNext(&li))) {
        client *c = listNodeValue(ln);
        int target_id = item_id % server.io_threads_num;
        listAddNodeTail(io_threads_list[target_id],c);
        item_id++;
    }

    
    io_threads_op = IO_THREADS_OP_READ;
    for (int j = 1; j < server.io_threads_num; j++) {
        int count = listLength(io_threads_list[j]);
        io_threads_pending[j] = count;
    }

    
    listRewind(io_threads_list[0],&li);
    while((ln = listNext(&li))) {
        client *c = listNodeValue(ln);
        readQueryFromClient(c->conn);
    }
    listEmpty(io_threads_list[0]);

    
    while(1) {
        unsigned long pending = 0;
        for (int j = 1; j < server.io_threads_num; j++)
            pending += io_threads_pending[j];
        if (pending == 0) break;
    }
    if (tio_debug) printf("I/O READ All threads finshed\n");

    
    while(listLength(server.clients_pending_read)) {
        ln = listFirst(server.clients_pending_read);
        client *c = listNodeValue(ln);
        c->flags &= ~CLIENT_PENDING_READ;
        listDelNode(server.clients_pending_read,ln);
        
        if (clientsArePaused()) continue;

        if (processPendingCommandsAndResetClient(c) == C_ERR) {
            
            continue;
        }
        processInputBuffer(c);

        
        if (!(c->flags & CLIENT_PENDING_WRITE) && clientHasPendingReplies(c))
            clientInstallWriteHandler(c);
    }

    
    server.stat_io_reads_processed += processed;

    return processed;
}
