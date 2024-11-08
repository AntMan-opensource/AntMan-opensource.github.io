












char *redisProtocolToLuaType_Int(lua_State *lua, char *reply);
char *redisProtocolToLuaType_Bulk(lua_State *lua, char *reply);
char *redisProtocolToLuaType_Status(lua_State *lua, char *reply);
char *redisProtocolToLuaType_Error(lua_State *lua, char *reply);
char *redisProtocolToLuaType_Aggregate(lua_State *lua, char *reply, int atype);
char *redisProtocolToLuaType_Null(lua_State *lua, char *reply);
char *redisProtocolToLuaType_Bool(lua_State *lua, char *reply, int tf);
char *redisProtocolToLuaType_Double(lua_State *lua, char *reply);
int redis_math_random (lua_State *L);
int redis_math_randomseed (lua_State *L);
void ldbInit(void);
void ldbDisable(client *c);
void ldbEnable(client *c);
void evalGenericCommandWithDebugging(client *c, int evalsha);
void luaLdbLineHook(lua_State *lua, lua_Debug *ar);
void ldbLog(sds entry);
void ldbLogRedisReply(char *reply);
sds ldbCatStackValue(sds s, lua_State *lua, int idx);




struct ldbState {
    connection *conn; 
    int active; 
    int forked; 
    list *logs; 
    list *traces; 
    list *children; 
    int bp[LDB_BREAKPOINTS_MAX]; 
    int bpcount; 
    int step;   
    int luabp;  
    sds *src;   
    int lines;  
    int currentline;    
    sds cbuf;   
    size_t maxlen;  
    int maxlen_hint_sent; 
} ldb;




void sha1hex(char *digest, char *script, size_t len) {
    SHA1_CTX ctx;
    unsigned char hash[20];
    char *cset = "0123456789abcdef";
    int j;

    SHA1Init(&ctx);
    SHA1Update(&ctx,(unsigned char*)script,len);
    SHA1Final(hash,&ctx);

    for (j = 0; j < 20; j++) {
        digest[j*2] = cset[((hash[j]&0xF0)>>4)];
        digest[j*2+1] = cset[(hash[j]&0xF)];
    }
    digest[40] = '\0';
}





char *redisProtocolToLuaType(lua_State *lua, char* reply) {
    char *p = reply;

    switch(*p) {
    case ':': p = redisProtocolToLuaType_Int(lua,reply); break;
    case '$': p = redisProtocolToLuaType_Bulk(lua,reply); break;
    case '+': p = redisProtocolToLuaType_Status(lua,reply); break;
    case '-': p = redisProtocolToLuaType_Error(lua,reply); break;
    case '*': p = redisProtocolToLuaType_Aggregate(lua,reply,*p); break;
    case '%': p = redisProtocolToLuaType_Aggregate(lua,reply,*p); break;
    case '~': p = redisProtocolToLuaType_Aggregate(lua,reply,*p); break;
    case '_': p = redisProtocolToLuaType_Null(lua,reply); break;
    case '#': p = redisProtocolToLuaType_Bool(lua,reply,p[1]); break;
    case ',': p = redisProtocolToLuaType_Double(lua,reply); break;
    }
    return p;
}

char *redisProtocolToLuaType_Int(lua_State *lua, char *reply) {
    char *p = strchr(reply+1,'\r');
    long long value;

    string2ll(reply+1,p-reply-1,&value);
    lua_pushnumber(lua,(lua_Number)value);
    return p+2;
}

char *redisProtocolToLuaType_Bulk(lua_State *lua, char *reply) {
    char *p = strchr(reply+1,'\r');
    long long bulklen;

    string2ll(reply+1,p-reply-1,&bulklen);
    if (bulklen == -1) {
        lua_pushboolean(lua,0);
        return p+2;
    } else {
        lua_pushlstring(lua,p+2,bulklen);
        return p+2+bulklen+2;
    }
}

char *redisProtocolToLuaType_Status(lua_State *lua, char *reply) {
    char *p = strchr(reply+1,'\r');

    lua_newtable(lua);
    lua_pushstring(lua,"ok");
    lua_pushlstring(lua,reply+1,p-reply-1);
    lua_settable(lua,-3);
    return p+2;
}

char *redisProtocolToLuaType_Error(lua_State *lua, char *reply) {
    char *p = strchr(reply+1,'\r');

    lua_newtable(lua);
    lua_pushstring(lua,"err");
    lua_pushlstring(lua,reply+1,p-reply-1);
    lua_settable(lua,-3);
    return p+2;
}

char *redisProtocolToLuaType_Aggregate(lua_State *lua, char *reply, int atype) {
    char *p = strchr(reply+1,'\r');
    long long mbulklen;
    int j = 0;

    string2ll(reply+1,p-reply-1,&mbulklen);
    if (server.lua_client->resp == 2 || atype == '*') {
        p += 2;
        if (mbulklen == -1) {
            lua_pushboolean(lua,0);
            return p;
        }
        lua_newtable(lua);
        for (j = 0; j < mbulklen; j++) {
            lua_pushnumber(lua,j+1);
            p = redisProtocolToLuaType(lua,p);
            lua_settable(lua,-3);
        }
    } else if (server.lua_client->resp == 3) {
        
        p += 2;
        lua_newtable(lua);
        lua_pushstring(lua,atype == '%' ? "map" : "set");
        lua_newtable(lua);
        for (j = 0; j < mbulklen; j++) {
            p = redisProtocolToLuaType(lua,p);
            if (atype == '%') {
                p = redisProtocolToLuaType(lua,p);
            } else {
                lua_pushboolean(lua,1);
            }
            lua_settable(lua,-3);
        }
        lua_settable(lua,-3);
    }
    return p;
}

char *redisProtocolToLuaType_Null(lua_State *lua, char *reply) {
    char *p = strchr(reply+1,'\r');
    lua_pushnil(lua);
    return p+2;
}

char *redisProtocolToLuaType_Bool(lua_State *lua, char *reply, int tf) {
    char *p = strchr(reply+1,'\r');
    lua_pushboolean(lua,tf == 't');
    return p+2;
}

char *redisProtocolToLuaType_Double(lua_State *lua, char *reply) {
    char *p = strchr(reply+1,'\r');
    char buf[MAX_LONG_DOUBLE_CHARS+1];
    size_t len = p-reply-1;
    double d;

    if (len <= MAX_LONG_DOUBLE_CHARS) {
        memcpy(buf,reply+1,len);
        buf[len] = '\0';
        d = strtod(buf,NULL); 
    } else {
        d = 0;
    }

    lua_newtable(lua);
    lua_pushstring(lua,"double");
    lua_pushnumber(lua,d);
    lua_settable(lua,-3);
    return p+2;
}


void luaPushError(lua_State *lua, char *error) {
    lua_Debug dbg;

    
    if (ldb.active && ldb.step) {
        ldbLog(sdscatprintf(sdsempty(),"<error> %s",error));
    }

    lua_newtable(lua);
    lua_pushstring(lua,"err");

    
    if(lua_getstack(lua, 1, &dbg) && lua_getinfo(lua, "nSl", &dbg)) {
        sds msg = sdscatprintf(sdsempty(), "%s: %d: %s", dbg.source, dbg.currentline, error);
        lua_pushstring(lua, msg);
        sdsfree(msg);
    } else {
        lua_pushstring(lua, error);
    }
    lua_settable(lua,-3);
}


int luaRaiseError(lua_State *lua) {
    lua_pushstring(lua,"err");
    lua_gettable(lua,-2);
    return lua_error(lua);
}


void luaSortArray(lua_State *lua) {
    
    lua_getglobal(lua,"table");
    lua_pushstring(lua,"sort");
    lua_gettable(lua,-2);       
    lua_pushvalue(lua,-3);      
    if (lua_pcall(lua,1,0,0)) {
        

        
        lua_pop(lua,1);             
        lua_pushstring(lua,"sort"); 
        lua_gettable(lua,-2);       
        lua_pushvalue(lua,-3);      
        lua_getglobal(lua,"__redis__compare_helper");
        
        lua_call(lua,2,0);
    }
    
    lua_pop(lua,1);             
}




void luaReplyToRedisReply(client *c, lua_State *lua) {
    int t = lua_type(lua,-1);

    switch(t) {
    case LUA_TSTRING:
        addReplyBulkCBuffer(c,(char*)lua_tostring(lua,-1),lua_strlen(lua,-1));
        break;
    case LUA_TBOOLEAN:
        if (server.lua_client->resp == 2)
            addReply(c,lua_toboolean(lua,-1) ? shared.cone :
                                               shared.null[c->resp]);
        else addReplyBool(c,lua_toboolean(lua,-1));
        break;
    case LUA_TNUMBER:
        addReplyLongLong(c,(long long)lua_tonumber(lua,-1));
        break;
    case LUA_TTABLE:
        

        
        lua_pushstring(lua,"err");
        lua_gettable(lua,-2);
        t = lua_type(lua,-1);
        if (t == LUA_TSTRING) {
            sds err = sdsnew(lua_tostring(lua,-1));
            sdsmapchars(err,"\r\n","  ",2);
            addReplySds(c,sdscatprintf(sdsempty(),"-%s\r\n",err));
            sdsfree(err);
            lua_pop(lua,2);
            return;
        }
        lua_pop(lua,1); 

        
        lua_pushstring(lua,"ok");
        lua_gettable(lua,-2);
        t = lua_type(lua,-1);
        if (t == LUA_TSTRING) {
            sds ok = sdsnew(lua_tostring(lua,-1));
            sdsmapchars(ok,"\r\n","  ",2);
            addReplySds(c,sdscatprintf(sdsempty(),"+%s\r\n",ok));
            sdsfree(ok);
            lua_pop(lua,2);
            return;
        }
        lua_pop(lua,1); 

        
        lua_pushstring(lua,"double");
        lua_gettable(lua,-2);
        t = lua_type(lua,-1);
        if (t == LUA_TNUMBER) {
            addReplyDouble(c,lua_tonumber(lua,-1));
            lua_pop(lua,2);
            return;
        }
        lua_pop(lua,1); 

        
        lua_pushstring(lua,"map");
        lua_gettable(lua,-2);
        t = lua_type(lua,-1);
        if (t == LUA_TTABLE) {
            int maplen = 0;
            void *replylen = addReplyDeferredLen(c);
            lua_pushnil(lua); 
            while (lua_next(lua,-2)) {
                
                lua_pushvalue(lua,-2);        
                luaReplyToRedisReply(c, lua); 
                luaReplyToRedisReply(c, lua); 
                
                maplen++;
            }
            setDeferredMapLen(c,replylen,maplen);
            lua_pop(lua,2);
            return;
        }
        lua_pop(lua,1); 

        
        lua_pushstring(lua,"set");
        lua_gettable(lua,-2);
        t = lua_type(lua,-1);
        if (t == LUA_TTABLE) {
            int setlen = 0;
            void *replylen = addReplyDeferredLen(c);
            lua_pushnil(lua); 
            while (lua_next(lua,-2)) {
                
                lua_pop(lua,1);               
                lua_pushvalue(lua,-1);        
                luaReplyToRedisReply(c, lua); 
                
                setlen++;
            }
            setDeferredSetLen(c,replylen,setlen);
            lua_pop(lua,2);
            return;
        }
        lua_pop(lua,1); 

        
        void *replylen = addReplyDeferredLen(c);
        int j = 1, mbulklen = 0;
        while(1) {
            lua_pushnumber(lua,j++);
            lua_gettable(lua,-2);
            t = lua_type(lua,-1);
            if (t == LUA_TNIL) {
                lua_pop(lua,1);
                break;
            }
            luaReplyToRedisReply(c, lua);
            mbulklen++;
        }
        setDeferredArrayLen(c,replylen,mbulklen);
        break;
    default:
        addReplyNull(c);
    }
    lua_pop(lua,1);
}





int luaRedisGenericCommand(lua_State *lua, int raise_error) {
    int j, argc = lua_gettop(lua);
    struct redisCommand *cmd;
    client *c = server.lua_client;
    sds reply;

    
    static robj **argv = NULL;
    static int argv_size = 0;
    static robj *cached_objects[LUA_CMD_OBJCACHE_SIZE];
    static size_t cached_objects_len[LUA_CMD_OBJCACHE_SIZE];
    static int inuse = 0;   

    
    if (inuse) {
        char *recursion_warning = "luaRedisGenericCommand() recursive call detected. " "Are you doing funny stuff with Lua debug hooks?";

        serverLog(LL_WARNING,"%s",recursion_warning);
        luaPushError(lua,recursion_warning);
        return 1;
    }
    inuse++;

    
    if (argc == 0) {
        luaPushError(lua, "Please specify at least one argument for redis.call()");
        inuse--;
        return raise_error ? luaRaiseError(lua) : 1;
    }

    
    if (argv_size < argc) {
        argv = zrealloc(argv,sizeof(robj*)*argc);
        argv_size = argc;
    }

    for (j = 0; j < argc; j++) {
        char *obj_s;
        size_t obj_len;
        char dbuf[64];

        if (lua_type(lua,j+1) == LUA_TNUMBER) {
            
            lua_Number num = lua_tonumber(lua,j+1);

            obj_len = snprintf(dbuf,sizeof(dbuf),"%.17g",(double)num);
            obj_s = dbuf;
        } else {
            obj_s = (char*)lua_tolstring(lua,j+1,&obj_len);
            if (obj_s == NULL) break; 
        }

        
        if (j < LUA_CMD_OBJCACHE_SIZE && cached_objects[j] && cached_objects_len[j] >= obj_len)
        {
            sds s = cached_objects[j]->ptr;
            argv[j] = cached_objects[j];
            cached_objects[j] = NULL;
            memcpy(s,obj_s,obj_len+1);
            sdssetlen(s, obj_len);
        } else {
            argv[j] = createStringObject(obj_s, obj_len);
        }
    }

    
    if (j != argc) {
        j--;
        while (j >= 0) {
            decrRefCount(argv[j]);
            j--;
        }
        luaPushError(lua, "Lua redis() command arguments must be strings or integers");
        inuse--;
        return raise_error ? luaRaiseError(lua) : 1;
    }

    
    c->argv = argv;
    c->argc = argc;
    c->user = server.lua_caller->user;

    
    moduleCallCommandFilters(c);
    argv = c->argv;
    argc = c->argc;

    
    if (ldb.active && ldb.step) {
        sds cmdlog = sdsnew("<redis>");
        for (j = 0; j < c->argc; j++) {
            if (j == 10) {
                cmdlog = sdscatprintf(cmdlog," ... (%d more)", c->argc-j-1);
                break;
            } else {
                cmdlog = sdscatlen(cmdlog," ",1);
                cmdlog = sdscatsds(cmdlog,c->argv[j]->ptr);
            }
        }
        ldbLog(cmdlog);
    }

    
    cmd = lookupCommand(argv[0]->ptr);
    if (!cmd || ((cmd->arity > 0 && cmd->arity != argc) || (argc < -cmd->arity)))
    {
        if (cmd)
            luaPushError(lua, "Wrong number of args calling Redis command From Lua script");
        else luaPushError(lua,"Unknown Redis command called from Lua script");
        goto cleanup;
    }
    c->cmd = c->lastcmd = cmd;

    
    if (cmd->flags & CMD_NOSCRIPT) {
        luaPushError(lua, "This Redis command is not allowed from scripts");
        goto cleanup;
    }

    
    int acl_keypos;
    int acl_retval = ACLCheckCommandPerm(c,&acl_keypos);
    if (acl_retval != ACL_OK) {
        addACLLogEntry(c,acl_retval,acl_keypos,NULL);
        if (acl_retval == ACL_DENIED_CMD)
            luaPushError(lua, "The user executing the script can't run this " "command or subcommand");
        else luaPushError(lua, "The user executing the script can't access " "at least one of the keys mentioned in the " "command arguments");


        goto cleanup;
    }

    
    if (cmd->flags & CMD_WRITE) {
        int deny_write_type = writeCommandsDeniedByDiskError();
        if (server.lua_random_dirty && !server.lua_replicate_commands) {
            luaPushError(lua, "Write commands not allowed after non deterministic commands. Call redis.replicate_commands() at the start of your script in order to switch to single commands replication mode.");
            goto cleanup;
        } else if (server.masterhost && server.repl_slave_ro && !server.loading && !(server.lua_caller->flags & CLIENT_MASTER))

        {
            luaPushError(lua, shared.roslaveerr->ptr);
            goto cleanup;
        } else if (deny_write_type != DISK_ERROR_TYPE_NONE) {
            if (deny_write_type == DISK_ERROR_TYPE_RDB) {
                luaPushError(lua, shared.bgsaveerr->ptr);
            } else {
                sds aof_write_err = sdscatfmt(sdsempty(), "-MISCONF Errors writing to the AOF file: %s\r\n", strerror(server.aof_last_write_errno));

                luaPushError(lua, aof_write_err);
                sdsfree(aof_write_err);
            }
            goto cleanup;
        }
    }

    
    if (server.maxmemory &&              !server.loading && !server.masterhost && server.lua_write_dirty == 0 && server.lua_oom && (cmd->flags & CMD_DENYOOM))




    {
        luaPushError(lua, shared.oomerr->ptr);
        goto cleanup;
    }

    if (cmd->flags & CMD_RANDOM) server.lua_random_dirty = 1;
    if (cmd->flags & CMD_WRITE) server.lua_write_dirty = 1;

    
    if (server.cluster_enabled && !server.loading && !(server.lua_caller->flags & CLIENT_MASTER))
    {
        int error_code;
        
        c->flags &= ~(CLIENT_READONLY|CLIENT_ASKING);
        c->flags |= server.lua_caller->flags & (CLIENT_READONLY|CLIENT_ASKING);
        if (getNodeByQuery(c,c->cmd,c->argv,c->argc,NULL,&error_code) != server.cluster->myself)
        {
            if (error_code == CLUSTER_REDIR_DOWN_RO_STATE) { 
                luaPushError(lua, "Lua script attempted to execute a write command while the " "cluster is down and readonly");

            } else if (error_code == CLUSTER_REDIR_DOWN_STATE) { 
                luaPushError(lua, "Lua script attempted to execute a command while the " "cluster is down");

            } else {
                luaPushError(lua, "Lua script attempted to access a non local key in a " "cluster node");

            }

            goto cleanup;
        }
    }

    
    if (server.lua_replicate_commands && !server.lua_multi_emitted && !(server.lua_caller->flags & CLIENT_MULTI) && server.lua_write_dirty && server.lua_repl != PROPAGATE_NONE)



    {
        execCommandPropagateMulti(server.lua_caller);
        server.lua_multi_emitted = 1;
        
        c->flags |= CLIENT_MULTI;
    }

    
    int call_flags = CMD_CALL_SLOWLOG | CMD_CALL_STATS;
    if (server.lua_replicate_commands) {
        
        if (server.lua_repl & PROPAGATE_AOF)
            call_flags |= CMD_CALL_PROPAGATE_AOF;
        if (server.lua_repl & PROPAGATE_REPL)
            call_flags |= CMD_CALL_PROPAGATE_REPL;
    }
    call(c,call_flags);

    
    if (listLength(c->reply) == 0 && c->bufpos < PROTO_REPLY_CHUNK_BYTES) {
        
        c->buf[c->bufpos] = '\0';
        reply = c->buf;
        c->bufpos = 0;
    } else {
        reply = sdsnewlen(c->buf,c->bufpos);
        c->bufpos = 0;
        while(listLength(c->reply)) {
            clientReplyBlock *o = listNodeValue(listFirst(c->reply));

            reply = sdscatlen(reply,o->buf,o->used);
            listDelNode(c->reply,listFirst(c->reply));
        }
    }
    if (raise_error && reply[0] != '-') raise_error = 0;
    redisProtocolToLuaType(lua,reply);

    
    if (ldb.active && ldb.step)
        ldbLogRedisReply(reply);

    
    if ((cmd->flags & CMD_SORT_FOR_SCRIPT) && (server.lua_replicate_commands == 0) && (reply[0] == '*' && reply[1] != '-')) {

            luaSortArray(lua);
    }
    if (reply != c->buf) sdsfree(reply);
    c->reply_bytes = 0;

cleanup:
    
    for (j = 0; j < c->argc; j++) {
        robj *o = c->argv[j];

        
        if (j < LUA_CMD_OBJCACHE_SIZE && o->refcount == 1 && (o->encoding == OBJ_ENCODING_RAW || o->encoding == OBJ_ENCODING_EMBSTR) && sdslen(o->ptr) <= LUA_CMD_OBJCACHE_MAX_LEN)



        {
            sds s = o->ptr;
            if (cached_objects[j]) decrRefCount(cached_objects[j]);
            cached_objects[j] = o;
            cached_objects_len[j] = sdsalloc(s);
        } else {
            decrRefCount(o);
        }
    }

    if (c->argv != argv) {
        zfree(c->argv);
        argv = NULL;
        argv_size = 0;
    }

    c->user = NULL;

    if (raise_error) {
        
        inuse--;
        return luaRaiseError(lua);
    }
    inuse--;
    return 1;
}


int luaRedisCallCommand(lua_State *lua) {
    return luaRedisGenericCommand(lua,1);
}


int luaRedisPCallCommand(lua_State *lua) {
    return luaRedisGenericCommand(lua,0);
}


int luaRedisSha1hexCommand(lua_State *lua) {
    int argc = lua_gettop(lua);
    char digest[41];
    size_t len;
    char *s;

    if (argc != 1) {
        lua_pushstring(lua, "wrong number of arguments");
        return lua_error(lua);
    }

    s = (char*)lua_tolstring(lua,1,&len);
    sha1hex(digest,s,len);
    lua_pushstring(lua,digest);
    return 1;
}


int luaRedisReturnSingleFieldTable(lua_State *lua, char *field) {
    if (lua_gettop(lua) != 1 || lua_type(lua,-1) != LUA_TSTRING) {
        luaPushError(lua, "wrong number or type of arguments");
        return 1;
    }

    lua_newtable(lua);
    lua_pushstring(lua, field);
    lua_pushvalue(lua, -3);
    lua_settable(lua, -3);
    return 1;
}


int luaRedisErrorReplyCommand(lua_State *lua) {
    return luaRedisReturnSingleFieldTable(lua,"err");
}


int luaRedisStatusReplyCommand(lua_State *lua) {
    return luaRedisReturnSingleFieldTable(lua,"ok");
}


int luaRedisReplicateCommandsCommand(lua_State *lua) {
    if (server.lua_write_dirty) {
        lua_pushboolean(lua,0);
    } else {
        server.lua_replicate_commands = 1;
        
        redisSrand48(rand());
        lua_pushboolean(lua,1);
    }
    return 1;
}


int luaRedisBreakpointCommand(lua_State *lua) {
    if (ldb.active) {
        ldb.luabp = 1;
        lua_pushboolean(lua,1);
    } else {
        lua_pushboolean(lua,0);
    }
    return 1;
}


int luaRedisDebugCommand(lua_State *lua) {
    if (!ldb.active) return 0;
    int argc = lua_gettop(lua);
    sds log = sdscatprintf(sdsempty(),"<debug> line %d: ", ldb.currentline);
    while(argc--) {
        log = ldbCatStackValue(log,lua,-1 - argc);
        if (argc != 0) log = sdscatlen(log,", ",2);
    }
    ldbLog(log);
    return 0;
}


int luaRedisSetReplCommand(lua_State *lua) {
    int argc = lua_gettop(lua);
    int flags;

    if (server.lua_replicate_commands == 0) {
        lua_pushstring(lua, "You can set the replication behavior only after turning on single commands replication with redis.replicate_commands().");
        return lua_error(lua);
    } else if (argc != 1) {
        lua_pushstring(lua, "redis.set_repl() requires two arguments.");
        return lua_error(lua);
    }

    flags = lua_tonumber(lua,-1);
    if ((flags & ~(PROPAGATE_AOF|PROPAGATE_REPL)) != 0) {
        lua_pushstring(lua, "Invalid replication flags. Use REPL_AOF, REPL_REPLICA, REPL_ALL or REPL_NONE.");
        return lua_error(lua);
    }
    server.lua_repl = flags;
    return 0;
}


int luaLogCommand(lua_State *lua) {
    int j, argc = lua_gettop(lua);
    int level;
    sds log;

    if (argc < 2) {
        lua_pushstring(lua, "redis.log() requires two arguments or more.");
        return lua_error(lua);
    } else if (!lua_isnumber(lua,-argc)) {
        lua_pushstring(lua, "First argument must be a number (log level).");
        return lua_error(lua);
    }
    level = lua_tonumber(lua,-argc);
    if (level < LL_DEBUG || level > LL_WARNING) {
        lua_pushstring(lua, "Invalid debug level.");
        return lua_error(lua);
    }
    if (level < server.verbosity) return 0;

    
    log = sdsempty();
    for (j = 1; j < argc; j++) {
        size_t len;
        char *s;

        s = (char*)lua_tolstring(lua,(-argc)+j,&len);
        if (s) {
            if (j != 1) log = sdscatlen(log," ",1);
            log = sdscatlen(log,s,len);
        }
    }
    serverLogRaw(level,log);
    sdsfree(log);
    return 0;
}


int luaSetResp(lua_State *lua) {
    int argc = lua_gettop(lua);

    if (argc != 1) {
        lua_pushstring(lua, "redis.setresp() requires one argument.");
        return lua_error(lua);
    }

    int resp = lua_tonumber(lua,-argc);
    if (resp != 2 && resp != 3) {
        lua_pushstring(lua, "RESP version must be 2 or 3.");
        return lua_error(lua);
    }

    server.lua_client->resp = resp;
    return 0;
}



void luaLoadLib(lua_State *lua, const char *libname, lua_CFunction luafunc) {
  lua_pushcfunction(lua, luafunc);
  lua_pushstring(lua, libname);
  lua_call(lua, 1, 0);
}

LUALIB_API int (luaopen_cjson) (lua_State *L);
LUALIB_API int (luaopen_struct) (lua_State *L);
LUALIB_API int (luaopen_cmsgpack) (lua_State *L);
LUALIB_API int (luaopen_bit) (lua_State *L);

void luaLoadLibraries(lua_State *lua) {
    luaLoadLib(lua, "", luaopen_base);
    luaLoadLib(lua, LUA_TABLIBNAME, luaopen_table);
    luaLoadLib(lua, LUA_STRLIBNAME, luaopen_string);
    luaLoadLib(lua, LUA_MATHLIBNAME, luaopen_math);
    luaLoadLib(lua, LUA_DBLIBNAME, luaopen_debug);
    luaLoadLib(lua, "cjson", luaopen_cjson);
    luaLoadLib(lua, "struct", luaopen_struct);
    luaLoadLib(lua, "cmsgpack", luaopen_cmsgpack);
    luaLoadLib(lua, "bit", luaopen_bit);


    luaLoadLib(lua, LUA_LOADLIBNAME, luaopen_package);
    luaLoadLib(lua, LUA_OSLIBNAME, luaopen_os);

}


void luaRemoveUnsupportedFunctions(lua_State *lua) {
    lua_pushnil(lua);
    lua_setglobal(lua,"loadfile");
    lua_pushnil(lua);
    lua_setglobal(lua,"dofile");
}


void scriptingEnableGlobalsProtection(lua_State *lua) {
    char *s[32];
    sds code = sdsempty();
    int j = 0;

    
    s[j++]="local dbg=debug\n";
    s[j++]="local mt = {}\n";
    s[j++]="setmetatable(_G, mt)\n";
    s[j++]="mt.__newindex = function (t, n, v)\n";
    s[j++]="  if dbg.getinfo(2) then\n";
    s[j++]="    local w = dbg.getinfo(2, \"S\").what\n";
    s[j++]="    if w ~= \"main\" and w ~= \"C\" then\n";
    s[j++]="      error(\"Script attempted to create global variable '\"..tostring(n)..\"'\", 2)\n";
    s[j++]="    end\n";
    s[j++]="  end\n";
    s[j++]="  rawset(t, n, v)\n";
    s[j++]="end\n";
    s[j++]="mt.__index = function (t, n)\n";
    s[j++]="  if dbg.getinfo(2) and dbg.getinfo(2, \"S\").what ~= \"C\" then\n";
    s[j++]="    error(\"Script attempted to access nonexistent global variable '\"..tostring(n)..\"'\", 2)\n";
    s[j++]="  end\n";
    s[j++]="  return rawget(t, n)\n";
    s[j++]="end\n";
    s[j++]="debug = nil\n";
    s[j++]=NULL;

    for (j = 0; s[j] != NULL; j++) code = sdscatlen(code,s[j],strlen(s[j]));
    luaL_loadbuffer(lua,code,sdslen(code),"@enable_strict_lua");
    lua_pcall(lua,0,0,0);
    sdsfree(code);
}


void scriptingInit(int setup) {
    lua_State *lua = lua_open();

    if (setup) {
        server.lua_client = NULL;
        server.lua_caller = NULL;
        server.lua_cur_script = NULL;
        server.lua_timedout = 0;
        ldbInit();
    }

    luaLoadLibraries(lua);
    luaRemoveUnsupportedFunctions(lua);

    
    server.lua_scripts = dictCreate(&shaScriptObjectDictType,NULL);
    server.lua_scripts_mem = 0;

    
    lua_newtable(lua);

    
    lua_pushstring(lua,"call");
    lua_pushcfunction(lua,luaRedisCallCommand);
    lua_settable(lua,-3);

    
    lua_pushstring(lua,"pcall");
    lua_pushcfunction(lua,luaRedisPCallCommand);
    lua_settable(lua,-3);

    
    lua_pushstring(lua,"log");
    lua_pushcfunction(lua,luaLogCommand);
    lua_settable(lua,-3);

    
    lua_pushstring(lua,"setresp");
    lua_pushcfunction(lua,luaSetResp);
    lua_settable(lua,-3);

    lua_pushstring(lua,"LOG_DEBUG");
    lua_pushnumber(lua,LL_DEBUG);
    lua_settable(lua,-3);

    lua_pushstring(lua,"LOG_VERBOSE");
    lua_pushnumber(lua,LL_VERBOSE);
    lua_settable(lua,-3);

    lua_pushstring(lua,"LOG_NOTICE");
    lua_pushnumber(lua,LL_NOTICE);
    lua_settable(lua,-3);

    lua_pushstring(lua,"LOG_WARNING");
    lua_pushnumber(lua,LL_WARNING);
    lua_settable(lua,-3);

    
    lua_pushstring(lua, "sha1hex");
    lua_pushcfunction(lua, luaRedisSha1hexCommand);
    lua_settable(lua, -3);

    
    lua_pushstring(lua, "error_reply");
    lua_pushcfunction(lua, luaRedisErrorReplyCommand);
    lua_settable(lua, -3);
    lua_pushstring(lua, "status_reply");
    lua_pushcfunction(lua, luaRedisStatusReplyCommand);
    lua_settable(lua, -3);

    
    lua_pushstring(lua, "replicate_commands");
    lua_pushcfunction(lua, luaRedisReplicateCommandsCommand);
    lua_settable(lua, -3);

    
    lua_pushstring(lua,"set_repl");
    lua_pushcfunction(lua,luaRedisSetReplCommand);
    lua_settable(lua,-3);

    lua_pushstring(lua,"REPL_NONE");
    lua_pushnumber(lua,PROPAGATE_NONE);
    lua_settable(lua,-3);

    lua_pushstring(lua,"REPL_AOF");
    lua_pushnumber(lua,PROPAGATE_AOF);
    lua_settable(lua,-3);

    lua_pushstring(lua,"REPL_SLAVE");
    lua_pushnumber(lua,PROPAGATE_REPL);
    lua_settable(lua,-3);

    lua_pushstring(lua,"REPL_REPLICA");
    lua_pushnumber(lua,PROPAGATE_REPL);
    lua_settable(lua,-3);

    lua_pushstring(lua,"REPL_ALL");
    lua_pushnumber(lua,PROPAGATE_AOF|PROPAGATE_REPL);
    lua_settable(lua,-3);

    
    lua_pushstring(lua,"breakpoint");
    lua_pushcfunction(lua,luaRedisBreakpointCommand);
    lua_settable(lua,-3);

    
    lua_pushstring(lua,"debug");
    lua_pushcfunction(lua,luaRedisDebugCommand);
    lua_settable(lua,-3);

    
    lua_setglobal(lua,"redis");

    
    lua_getglobal(lua,"math");

    lua_pushstring(lua,"random");
    lua_pushcfunction(lua,redis_math_random);
    lua_settable(lua,-3);

    lua_pushstring(lua,"randomseed");
    lua_pushcfunction(lua,redis_math_randomseed);
    lua_settable(lua,-3);

    lua_setglobal(lua,"math");

    
    {
        char *compare_func =    "function __redis__compare_helper(a,b)\n" "  if a == false then a = '' end\n" "  if b == false then b = '' end\n" "  return a<b\n" "end\n";



        luaL_loadbuffer(lua,compare_func,strlen(compare_func),"@cmp_func_def");
        lua_pcall(lua,0,0,0);
    }

    
    {
        char *errh_func =       "local dbg = debug\n" "function __redis__err__handler(err)\n" "  local i = dbg.getinfo(2,'nSl')\n" "  if i and i.what == 'C' then\n" "    i = dbg.getinfo(3,'nSl')\n" "  end\n" "  if i then\n" "    return i.source .. ':' .. i.currentline .. ': ' .. err\n" "  else\n" "    return err\n" "  end\n" "end\n";










        luaL_loadbuffer(lua,errh_func,strlen(errh_func),"@err_handler_def");
        lua_pcall(lua,0,0,0);
    }

    
    if (server.lua_client == NULL) {
        server.lua_client = createClient(NULL);
        server.lua_client->flags |= CLIENT_LUA;
    }

    
    scriptingEnableGlobalsProtection(lua);

    server.lua = lua;
}


void scriptingRelease(void) {
    dictRelease(server.lua_scripts);
    server.lua_scripts_mem = 0;
    lua_close(server.lua);
}

void scriptingReset(void) {
    scriptingRelease();
    scriptingInit(0);
}


void luaSetGlobalArray(lua_State *lua, char *var, robj **elev, int elec) {
    int j;

    lua_newtable(lua);
    for (j = 0; j < elec; j++) {
        lua_pushlstring(lua,(char*)elev[j]->ptr,sdslen(elev[j]->ptr));
        lua_rawseti(lua,-2,j+1);
    }
    lua_setglobal(lua,var);
}






int redis_math_random (lua_State *L) {
  
  lua_Number r = (lua_Number)(redisLrand48()%REDIS_LRAND48_MAX) / (lua_Number)REDIS_LRAND48_MAX;
  switch (lua_gettop(L)) {  
    case 0: {  
      lua_pushnumber(L, r);  
      break;
    }
    case 1: {  
      int u = luaL_checkint(L, 1);
      luaL_argcheck(L, 1<=u, 1, "interval is empty");
      lua_pushnumber(L, floor(r*u)+1);  
      break;
    }
    case 2: {  
      int l = luaL_checkint(L, 1);
      int u = luaL_checkint(L, 2);
      luaL_argcheck(L, l<=u, 2, "interval is empty");
      lua_pushnumber(L, floor(r*(u-l+1))+l);  
      break;
    }
    default: return luaL_error(L, "wrong number of arguments");
  }
  return 1;
}

int redis_math_randomseed (lua_State *L) {
  redisSrand48(luaL_checkint(L, 1));
  return 0;
}




sds luaCreateFunction(client *c, lua_State *lua, robj *body) {
    char funcname[43];
    dictEntry *de;

    funcname[0] = 'f';
    funcname[1] = '_';
    sha1hex(funcname+2,body->ptr,sdslen(body->ptr));

    sds sha = sdsnewlen(funcname+2,40);
    if ((de = dictFind(server.lua_scripts,sha)) != NULL) {
        sdsfree(sha);
        return dictGetKey(de);
    }

    sds funcdef = sdsempty();
    funcdef = sdscat(funcdef,"function ");
    funcdef = sdscatlen(funcdef,funcname,42);
    funcdef = sdscatlen(funcdef,"() ",3);
    funcdef = sdscatlen(funcdef,body->ptr,sdslen(body->ptr));
    funcdef = sdscatlen(funcdef,"\nend",4);

    if (luaL_loadbuffer(lua,funcdef,sdslen(funcdef),"@user_script")) {
        if (c != NULL) {
            addReplyErrorFormat(c, "Error compiling script (new function): %s\n", lua_tostring(lua,-1));

        }
        lua_pop(lua,1);
        sdsfree(sha);
        sdsfree(funcdef);
        return NULL;
    }
    sdsfree(funcdef);

    if (lua_pcall(lua,0,0,0)) {
        if (c != NULL) {
            addReplyErrorFormat(c,"Error running script (new function): %s\n", lua_tostring(lua,-1));
        }
        lua_pop(lua,1);
        sdsfree(sha);
        return NULL;
    }

    
    int retval = dictAdd(server.lua_scripts,sha,body);
    serverAssertWithInfo(c ? c : server.lua_client,NULL,retval == DICT_OK);
    server.lua_scripts_mem += sdsZmallocSize(sha) + getStringObjectSdsUsedMemory(body);
    incrRefCount(body);
    return sha;
}


void luaMaskCountHook(lua_State *lua, lua_Debug *ar) {
    long long elapsed = mstime() - server.lua_time_start;
    UNUSED(ar);
    UNUSED(lua);

    
    if (elapsed >= server.lua_time_limit && server.lua_timedout == 0) {
        serverLog(LL_WARNING, "Lua slow script detected: still in execution after %lld milliseconds. " "You can try killing the script using the SCRIPT KILL command. " "Script SHA1 is: %s", elapsed, server.lua_cur_script);



        server.lua_timedout = 1;
        
        protectClient(server.lua_caller);
    }
    if (server.lua_timedout) processEventsWhileBlocked();
    if (server.lua_kill) {
        serverLog(LL_WARNING,"Lua script killed by user with SCRIPT KILL.");
        lua_pushstring(lua,"Script killed by user with SCRIPT KILL...");
        lua_error(lua);
    }
}

void prepareLuaClient(void) {
    
    selectDb(server.lua_client,server.lua_caller->db->id);
    server.lua_client->resp = 2; 

    
    if (server.lua_caller->flags & CLIENT_MULTI) {
        server.lua_client->flags |= CLIENT_MULTI;
    }
}

void resetLuaClient(void) {
    
    server.lua_client->flags &= ~CLIENT_MULTI;
}

void evalGenericCommand(client *c, int evalsha) {
    lua_State *lua = server.lua;
    char funcname[43];
    long long numkeys;
    long long initial_server_dirty = server.dirty;
    int delhook = 0, err;

    
    redisSrand48(0);

    
    server.lua_random_dirty = 0;
    server.lua_write_dirty = 0;
    server.lua_replicate_commands = server.lua_always_replicate_commands;
    server.lua_multi_emitted = 0;
    server.lua_repl = PROPAGATE_AOF|PROPAGATE_REPL;

    
    if (getLongLongFromObjectOrReply(c,c->argv[2],&numkeys,NULL) != C_OK)
        return;
    if (numkeys > (c->argc - 3)) {
        addReplyError(c,"Number of keys can't be greater than number of args");
        return;
    } else if (numkeys < 0) {
        addReplyError(c,"Number of keys can't be negative");
        return;
    }

    
    funcname[0] = 'f';
    funcname[1] = '_';
    if (!evalsha) {
        
        sha1hex(funcname+2,c->argv[1]->ptr,sdslen(c->argv[1]->ptr));
    } else {
        
        int j;
        char *sha = c->argv[1]->ptr;

        
        for (j = 0; j < 40; j++)
            funcname[j+2] = (sha[j] >= 'A' && sha[j] <= 'Z') ? sha[j]+('a'-'A') : sha[j];
        funcname[42] = '\0';
    }

    
    lua_getglobal(lua, "__redis__err__handler");

    
    lua_getglobal(lua, funcname);
    if (lua_isnil(lua,-1)) {
        lua_pop(lua,1); 
        
        if (evalsha) {
            lua_pop(lua,1); 
            addReply(c, shared.noscripterr);
            return;
        }
        if (luaCreateFunction(c,lua,c->argv[1]) == NULL) {
            lua_pop(lua,1); 
            
            return;
        }
        
        lua_getglobal(lua, funcname);
        serverAssert(!lua_isnil(lua,-1));
    }

    
    luaSetGlobalArray(lua,"KEYS",c->argv+3,numkeys);
    luaSetGlobalArray(lua,"ARGV",c->argv+3+numkeys,c->argc-3-numkeys);

    
    server.lua_caller = c;
    server.lua_cur_script = funcname + 2;
    server.lua_time_start = mstime();
    server.lua_kill = 0;
    if (server.lua_time_limit > 0 && ldb.active == 0) {
        lua_sethook(lua,luaMaskCountHook,LUA_MASKCOUNT,100000);
        delhook = 1;
    } else if (ldb.active) {
        lua_sethook(server.lua,luaLdbLineHook,LUA_MASKLINE|LUA_MASKCOUNT,100000);
        delhook = 1;
    }

    prepareLuaClient();

    
    err = lua_pcall(lua,0,1,-2);

    resetLuaClient();

    
    if (delhook) lua_sethook(lua,NULL,0,0); 
    if (server.lua_timedout) {
        server.lua_timedout = 0;
        
        unprotectClient(c);
        if (server.masterhost && server.master)
            queueClientForReprocessing(server.master);
    }
    server.lua_caller = NULL;
    server.lua_cur_script = NULL;

    
    #define LUA_GC_CYCLE_PERIOD 50
    {
        static long gc_count = 0;

        gc_count++;
        if (gc_count == LUA_GC_CYCLE_PERIOD) {
            lua_gc(lua,LUA_GCSTEP,LUA_GC_CYCLE_PERIOD);
            gc_count = 0;
        }
    }

    if (err) {
        addReplyErrorFormat(c,"Error running script (call to %s): %s\n", funcname, lua_tostring(lua,-1));
        lua_pop(lua,2); 
    } else {
        
        luaReplyToRedisReply(c,lua); 
        lua_pop(lua,1); 
    }

    
    if (server.lua_replicate_commands) {
        preventCommandPropagation(c);
        if (server.lua_multi_emitted) {
            execCommandPropagateExec(c);
        }
    }

    
    if (evalsha && !server.lua_replicate_commands) {
        if (!replicationScriptCacheExists(c->argv[1]->ptr)) {
            
            robj *script = dictFetchValue(server.lua_scripts,c->argv[1]->ptr);

            replicationScriptCacheAdd(c->argv[1]->ptr);
            serverAssertWithInfo(c,NULL,script != NULL);

            
            if (server.dirty == initial_server_dirty) {
                rewriteClientCommandVector(c,3, resetRefCount(createStringObject("SCRIPT",6)), resetRefCount(createStringObject("LOAD",4)), script);


            } else {
                rewriteClientCommandArgument(c,0, resetRefCount(createStringObject("EVAL",4)));
                rewriteClientCommandArgument(c,1,script);
            }
            forceCommandPropagation(c,PROPAGATE_REPL|PROPAGATE_AOF);
        }
    }
}

void evalCommand(client *c) {
    if (!(c->flags & CLIENT_LUA_DEBUG))
        evalGenericCommand(c,0);
    else evalGenericCommandWithDebugging(c,0);
}

void evalShaCommand(client *c) {
    if (sdslen(c->argv[1]->ptr) != 40) {
        
        addReply(c, shared.noscripterr);
        return;
    }
    if (!(c->flags & CLIENT_LUA_DEBUG))
        evalGenericCommand(c,1);
    else {
        addReplyError(c,"Please use EVAL instead of EVALSHA for debugging");
        return;
    }
}

void scriptCommand(client *c) {
    if (c->argc == 2 && !strcasecmp(c->argv[1]->ptr,"help")) {
        const char *help[] = {
"DEBUG (yes|sync|no) -- Set the debug mode for subsequent scripts executed.", "EXISTS <sha1> [<sha1> ...] -- Return information about the existence of the scripts in the script cache.", "FLUSH -- Flush the Lua scripts cache. Very dangerous on replicas.", "KILL -- Kill the currently executing Lua script.", "LOAD <script> -- Load a script into the scripts cache, without executing it.", NULL };





        addReplyHelp(c, help);
    } else if (c->argc == 2 && !strcasecmp(c->argv[1]->ptr,"flush")) {
        scriptingReset();
        addReply(c,shared.ok);
        replicationScriptCacheFlush();
        server.dirty++; 
    } else if (c->argc >= 2 && !strcasecmp(c->argv[1]->ptr,"exists")) {
        int j;

        addReplyArrayLen(c, c->argc-2);
        for (j = 2; j < c->argc; j++) {
            if (dictFind(server.lua_scripts,c->argv[j]->ptr))
                addReply(c,shared.cone);
            else addReply(c,shared.czero);
        }
    } else if (c->argc == 3 && !strcasecmp(c->argv[1]->ptr,"load")) {
        sds sha = luaCreateFunction(c,server.lua,c->argv[2]);
        if (sha == NULL) return; 
        addReplyBulkCBuffer(c,sha,40);
        forceCommandPropagation(c,PROPAGATE_REPL|PROPAGATE_AOF);
    } else if (c->argc == 2 && !strcasecmp(c->argv[1]->ptr,"kill")) {
        if (server.lua_caller == NULL) {
            addReplySds(c,sdsnew("-NOTBUSY No scripts in execution right now.\r\n"));
        } else if (server.lua_caller->flags & CLIENT_MASTER) {
            addReplySds(c,sdsnew("-UNKILLABLE The busy script was sent by a master instance in the context of replication and cannot be killed.\r\n"));
        } else if (server.lua_write_dirty) {
            addReplySds(c,sdsnew("-UNKILLABLE Sorry the script already executed write commands against the dataset. You can either wait the script termination or kill the server in a hard way using the SHUTDOWN NOSAVE command.\r\n"));
        } else {
            server.lua_kill = 1;
            addReply(c,shared.ok);
        }
    } else if (c->argc == 3 && !strcasecmp(c->argv[1]->ptr,"debug")) {
        if (clientHasPendingReplies(c)) {
            addReplyError(c,"SCRIPT DEBUG must be called outside a pipeline");
            return;
        }
        if (!strcasecmp(c->argv[2]->ptr,"no")) {
            ldbDisable(c);
            addReply(c,shared.ok);
        } else if (!strcasecmp(c->argv[2]->ptr,"yes")) {
            ldbEnable(c);
            addReply(c,shared.ok);
        } else if (!strcasecmp(c->argv[2]->ptr,"sync")) {
            ldbEnable(c);
            addReply(c,shared.ok);
            c->flags |= CLIENT_LUA_DEBUG_SYNC;
        } else {
            addReplyError(c,"Use SCRIPT DEBUG yes/sync/no");
            return;
        }
    } else {
        addReplySubcommandSyntaxError(c);
    }
}




void ldbInit(void) {
    ldb.conn = NULL;
    ldb.active = 0;
    ldb.logs = listCreate();
    listSetFreeMethod(ldb.logs,(void (*)(void*))sdsfree);
    ldb.children = listCreate();
    ldb.src = NULL;
    ldb.lines = 0;
    ldb.cbuf = sdsempty();
}


void ldbFlushLog(list *log) {
    listNode *ln;

    while((ln = listFirst(log)) != NULL)
        listDelNode(log,ln);
}


void ldbEnable(client *c) {
    c->flags |= CLIENT_LUA_DEBUG;
    ldbFlushLog(ldb.logs);
    ldb.conn = c->conn;
    ldb.step = 1;
    ldb.bpcount = 0;
    ldb.luabp = 0;
    sdsfree(ldb.cbuf);
    ldb.cbuf = sdsempty();
    ldb.maxlen = LDB_MAX_LEN_DEFAULT;
    ldb.maxlen_hint_sent = 0;
}


void ldbDisable(client *c) {
    c->flags &= ~(CLIENT_LUA_DEBUG|CLIENT_LUA_DEBUG_SYNC);
}


void ldbLog(sds entry) {
    listAddNodeTail(ldb.logs,entry);
}


void ldbLogWithMaxLen(sds entry) {
    int trimmed = 0;
    if (ldb.maxlen && sdslen(entry) > ldb.maxlen) {
        sdsrange(entry,0,ldb.maxlen-1);
        entry = sdscatlen(entry," ...",4);
        trimmed = 1;
    }
    ldbLog(entry);
    if (trimmed && ldb.maxlen_hint_sent == 0) {
        ldb.maxlen_hint_sent = 1;
        ldbLog(sdsnew( "<hint> The above reply was trimmed. Use 'maxlen 0' to disable trimming."));
    }
}


void ldbSendLogs(void) {
    sds proto = sdsempty();
    proto = sdscatfmt(proto,"*%i\r\n", (int)listLength(ldb.logs));
    while(listLength(ldb.logs)) {
        listNode *ln = listFirst(ldb.logs);
        proto = sdscatlen(proto,"+",1);
        sdsmapchars(ln->value,"\r\n","  ",2);
        proto = sdscatsds(proto,ln->value);
        proto = sdscatlen(proto,"\r\n",2);
        listDelNode(ldb.logs,ln);
    }
    if (connWrite(ldb.conn,proto,sdslen(proto)) == -1) {
        
    }
    sdsfree(proto);
}


int ldbStartSession(client *c) {
    ldb.forked = (c->flags & CLIENT_LUA_DEBUG_SYNC) == 0;
    if (ldb.forked) {
        pid_t cp = redisFork(CHILD_TYPE_LDB);
        if (cp == -1) {
            addReplyError(c,"Fork() failed: can't run EVAL in debugging mode.");
            return 0;
        } else if (cp == 0) {
            
            struct sigaction act;
            sigemptyset(&act.sa_mask);
            act.sa_flags = 0;
            act.sa_handler = SIG_IGN;
            sigaction(SIGTERM, &act, NULL);
            sigaction(SIGINT, &act, NULL);

            
            serverLog(LL_WARNING,"Redis forked for debugging eval");
        } else {
            
            listAddNodeTail(ldb.children,(void*)(unsigned long)cp);
            freeClientAsync(c); 
            return 0;
        }
    } else {
        serverLog(LL_WARNING, "Redis synchronous debugging eval session started");
    }

    
    connBlock(ldb.conn);
    connSendTimeout(ldb.conn,5000);
    ldb.active = 1;

    
    sds srcstring = sdsdup(c->argv[1]->ptr);
    size_t srclen = sdslen(srcstring);
    while(srclen && (srcstring[srclen-1] == '\n' || srcstring[srclen-1] == '\r'))
    {
        srcstring[--srclen] = '\0';
    }
    sdssetlen(srcstring,srclen);
    ldb.src = sdssplitlen(srcstring,sdslen(srcstring),"\n",1,&ldb.lines);
    sdsfree(srcstring);
    return 1;
}


void ldbEndSession(client *c) {
    
    ldbLog(sdsnew("<endsession>"));
    ldbSendLogs();

    
    if (ldb.forked) {
        writeToClient(c,0);
        serverLog(LL_WARNING,"Lua debugging session child exiting");
        exitFromChild(0);
    } else {
        serverLog(LL_WARNING, "Redis synchronous debugging eval session ended");
    }

    
    connNonBlock(ldb.conn);
    connSendTimeout(ldb.conn,0);

    
    c->flags |= CLIENT_CLOSE_AFTER_REPLY;

    
    sdsfreesplitres(ldb.src,ldb.lines);
    ldb.lines = 0;
    ldb.active = 0;
}


int ldbRemoveChild(pid_t pid) {
    listNode *ln = listSearchKey(ldb.children,(void*)(unsigned long)pid);
    if (ln) {
        listDelNode(ldb.children,ln);
        return 1;
    }
    return 0;
}


int ldbPendingChildren(void) {
    return listLength(ldb.children);
}


void ldbKillForkedSessions(void) {
    listIter li;
    listNode *ln;

    listRewind(ldb.children,&li);
    while((ln = listNext(&li))) {
        pid_t pid = (unsigned long) ln->value;
        serverLog(LL_WARNING,"Killing debugging session %ld",(long)pid);
        kill(pid,SIGKILL);
    }
    listRelease(ldb.children);
    ldb.children = listCreate();
}


void evalGenericCommandWithDebugging(client *c, int evalsha) {
    if (ldbStartSession(c)) {
        evalGenericCommand(c,evalsha);
        ldbEndSession(c);
    } else {
        ldbDisable(c);
    }
}


char *ldbGetSourceLine(int line) {
    int idx = line-1;
    if (idx < 0 || idx >= ldb.lines) return "<out of range source code line>";
    return ldb.src[idx];
}


int ldbIsBreakpoint(int line) {
    int j;

    for (j = 0; j < ldb.bpcount; j++)
        if (ldb.bp[j] == line) return 1;
    return 0;
}


int ldbAddBreakpoint(int line) {
    if (line <= 0 || line > ldb.lines) return 0;
    if (!ldbIsBreakpoint(line) && ldb.bpcount != LDB_BREAKPOINTS_MAX) {
        ldb.bp[ldb.bpcount++] = line;
        return 1;
    }
    return 0;
}


int ldbDelBreakpoint(int line) {
    int j;

    for (j = 0; j < ldb.bpcount; j++) {
        if (ldb.bp[j] == line) {
            ldb.bpcount--;
            memmove(ldb.bp+j,ldb.bp+j+1,ldb.bpcount-j);
            return 1;
        }
    }
    return 0;
}


sds *ldbReplParseCommand(int *argcp) {
    sds *argv = NULL;
    int argc = 0;
    if (sdslen(ldb.cbuf) == 0) return NULL;

    
    sds copy = sdsdup(ldb.cbuf);
    char *p = copy;

    

    
    p = strchr(p,'*'); if (!p) goto protoerr;
    char *plen = p+1; 
    p = strstr(p,"\r\n"); if (!p) goto protoerr;
    *p = '\0'; p += 2;
    *argcp = atoi(plen);
    if (*argcp <= 0 || *argcp > 1024) goto protoerr;

    
    argv = zmalloc(sizeof(sds)*(*argcp));
    argc = 0;
    while(argc < *argcp) {
        if (*p != '$') goto protoerr;
        plen = p+1; 
        p = strstr(p,"\r\n"); if (!p) goto protoerr;
        *p = '\0'; p += 2;
        int slen = atoi(plen); 
        if (slen <= 0 || slen > 1024) goto protoerr;
        argv[argc++] = sdsnewlen(p,slen);
        p += slen; 
        if (p[0] != '\r' || p[1] != '\n') goto protoerr;
        p += 2; 
    }
    sdsfree(copy);
    return argv;

protoerr:
    sdsfreesplitres(argv,argc);
    sdsfree(copy);
    return NULL;
}


void ldbLogSourceLine(int lnum) {
    char *line = ldbGetSourceLine(lnum);
    char *prefix;
    int bp = ldbIsBreakpoint(lnum);
    int current = ldb.currentline == lnum;

    if (current && bp)
        prefix = "->#";
    else if (current)
        prefix = "-> ";
    else if (bp)
        prefix = "  #";
    else prefix = "   ";
    sds thisline = sdscatprintf(sdsempty(),"%s%-3d %s", prefix, lnum, line);
    ldbLog(thisline);
}


void ldbList(int around, int context) {
    int j;

    for (j = 1; j <= ldb.lines; j++) {
        if (around != 0 && abs(around-j) > context) continue;
        ldbLogSourceLine(j);
    }
}



sds ldbCatStackValueRec(sds s, lua_State *lua, int idx, int level) {
    int t = lua_type(lua,idx);

    if (level++ == LDB_MAX_VALUES_DEPTH)
        return sdscat(s,"<max recursion level reached! Nested table?>");

    switch(t) {
    case LUA_TSTRING:
        {
        size_t strl;
        char *strp = (char*)lua_tolstring(lua,idx,&strl);
        s = sdscatrepr(s,strp,strl);
        }
        break;
    case LUA_TBOOLEAN:
        s = sdscat(s,lua_toboolean(lua,idx) ? "true" : "false");
        break;
    case LUA_TNUMBER:
        s = sdscatprintf(s,"%g",(double)lua_tonumber(lua,idx));
        break;
    case LUA_TNIL:
        s = sdscatlen(s,"nil",3);
        break;
    case LUA_TTABLE:
        {
        int expected_index = 1; 
        int is_array = 1; 
        
        sds repr1 = sdsempty();
        sds repr2 = sdsempty();
        lua_pushnil(lua); 
        while (lua_next(lua,idx-1)) {
            
            if (is_array && (lua_type(lua,-2) != LUA_TNUMBER || lua_tonumber(lua,-2) != expected_index)) is_array = 0;

            
            
            repr1 = ldbCatStackValueRec(repr1,lua,-1,level);
            repr1 = sdscatlen(repr1,"; ",2);
            
            repr2 = sdscatlen(repr2,"[",1);
            repr2 = ldbCatStackValueRec(repr2,lua,-2,level);
            repr2 = sdscatlen(repr2,"]=",2);
            repr2 = ldbCatStackValueRec(repr2,lua,-1,level);
            repr2 = sdscatlen(repr2,"; ",2);
            lua_pop(lua,1); 
            expected_index++;
        }
        
        if (sdslen(repr1)) sdsrange(repr1,0,-3);
        if (sdslen(repr2)) sdsrange(repr2,0,-3);
        
        s = sdscatlen(s,"{",1);
        s = sdscatsds(s,is_array ? repr1 : repr2);
        s = sdscatlen(s,"}",1);
        sdsfree(repr1);
        sdsfree(repr2);
        }
        break;
    case LUA_TFUNCTION:
    case LUA_TUSERDATA:
    case LUA_TTHREAD:
    case LUA_TLIGHTUSERDATA:
        {
        const void *p = lua_topointer(lua,idx);
        char *typename = "unknown";
        if (t == LUA_TFUNCTION) typename = "function";
        else if (t == LUA_TUSERDATA) typename = "userdata";
        else if (t == LUA_TTHREAD) typename = "thread";
        else if (t == LUA_TLIGHTUSERDATA) typename = "light-userdata";
        s = sdscatprintf(s,"\"%s@%p\"",typename,p);
        }
        break;
    default:
        s = sdscat(s,"\"<unknown-lua-type>\"");
        break;
    }
    return s;
}


sds ldbCatStackValue(sds s, lua_State *lua, int idx) {
    return ldbCatStackValueRec(s,lua,idx,0);
}


void ldbLogStackValue(lua_State *lua, char *prefix) {
    sds s = sdsnew(prefix);
    s = ldbCatStackValue(s,lua,-1);
    ldbLogWithMaxLen(s);
}

char *ldbRedisProtocolToHuman_Int(sds *o, char *reply);
char *ldbRedisProtocolToHuman_Bulk(sds *o, char *reply);
char *ldbRedisProtocolToHuman_Status(sds *o, char *reply);
char *ldbRedisProtocolToHuman_MultiBulk(sds *o, char *reply);
char *ldbRedisProtocolToHuman_Set(sds *o, char *reply);
char *ldbRedisProtocolToHuman_Map(sds *o, char *reply);
char *ldbRedisProtocolToHuman_Null(sds *o, char *reply);
char *ldbRedisProtocolToHuman_Bool(sds *o, char *reply);
char *ldbRedisProtocolToHuman_Double(sds *o, char *reply);


char *ldbRedisProtocolToHuman(sds *o, char *reply) {
    char *p = reply;
    switch(*p) {
    case ':': p = ldbRedisProtocolToHuman_Int(o,reply); break;
    case '$': p = ldbRedisProtocolToHuman_Bulk(o,reply); break;
    case '+': p = ldbRedisProtocolToHuman_Status(o,reply); break;
    case '-': p = ldbRedisProtocolToHuman_Status(o,reply); break;
    case '*': p = ldbRedisProtocolToHuman_MultiBulk(o,reply); break;
    case '~': p = ldbRedisProtocolToHuman_Set(o,reply); break;
    case '%': p = ldbRedisProtocolToHuman_Map(o,reply); break;
    case '_': p = ldbRedisProtocolToHuman_Null(o,reply); break;
    case '#': p = ldbRedisProtocolToHuman_Bool(o,reply); break;
    case ',': p = ldbRedisProtocolToHuman_Double(o,reply); break;
    }
    return p;
}



char *ldbRedisProtocolToHuman_Int(sds *o, char *reply) {
    char *p = strchr(reply+1,'\r');
    *o = sdscatlen(*o,reply+1,p-reply-1);
    return p+2;
}

char *ldbRedisProtocolToHuman_Bulk(sds *o, char *reply) {
    char *p = strchr(reply+1,'\r');
    long long bulklen;

    string2ll(reply+1,p-reply-1,&bulklen);
    if (bulklen == -1) {
        *o = sdscatlen(*o,"NULL",4);
        return p+2;
    } else {
        *o = sdscatrepr(*o,p+2,bulklen);
        return p+2+bulklen+2;
    }
}

char *ldbRedisProtocolToHuman_Status(sds *o, char *reply) {
    char *p = strchr(reply+1,'\r');

    *o = sdscatrepr(*o,reply,p-reply);
    return p+2;
}

char *ldbRedisProtocolToHuman_MultiBulk(sds *o, char *reply) {
    char *p = strchr(reply+1,'\r');
    long long mbulklen;
    int j = 0;

    string2ll(reply+1,p-reply-1,&mbulklen);
    p += 2;
    if (mbulklen == -1) {
        *o = sdscatlen(*o,"NULL",4);
        return p;
    }
    *o = sdscatlen(*o,"[",1);
    for (j = 0; j < mbulklen; j++) {
        p = ldbRedisProtocolToHuman(o,p);
        if (j != mbulklen-1) *o = sdscatlen(*o,",",1);
    }
    *o = sdscatlen(*o,"]",1);
    return p;
}

char *ldbRedisProtocolToHuman_Set(sds *o, char *reply) {
    char *p = strchr(reply+1,'\r');
    long long mbulklen;
    int j = 0;

    string2ll(reply+1,p-reply-1,&mbulklen);
    p += 2;
    *o = sdscatlen(*o,"~(",2);
    for (j = 0; j < mbulklen; j++) {
        p = ldbRedisProtocolToHuman(o,p);
        if (j != mbulklen-1) *o = sdscatlen(*o,",",1);
    }
    *o = sdscatlen(*o,")",1);
    return p;
}

char *ldbRedisProtocolToHuman_Map(sds *o, char *reply) {
    char *p = strchr(reply+1,'\r');
    long long mbulklen;
    int j = 0;

    string2ll(reply+1,p-reply-1,&mbulklen);
    p += 2;
    *o = sdscatlen(*o,"{",1);
    for (j = 0; j < mbulklen; j++) {
        p = ldbRedisProtocolToHuman(o,p);
        *o = sdscatlen(*o," => ",4);
        p = ldbRedisProtocolToHuman(o,p);
        if (j != mbulklen-1) *o = sdscatlen(*o,",",1);
    }
    *o = sdscatlen(*o,"}",1);
    return p;
}

char *ldbRedisProtocolToHuman_Null(sds *o, char *reply) {
    char *p = strchr(reply+1,'\r');
    *o = sdscatlen(*o,"(null)",6);
    return p+2;
}

char *ldbRedisProtocolToHuman_Bool(sds *o, char *reply) {
    char *p = strchr(reply+1,'\r');
    if (reply[1] == 't')
        *o = sdscatlen(*o,"#true",5);
    else *o = sdscatlen(*o,"#false",6);
    return p+2;
}

char *ldbRedisProtocolToHuman_Double(sds *o, char *reply) {
    char *p = strchr(reply+1,'\r');
    *o = sdscatlen(*o,"(double) ",9);
    *o = sdscatlen(*o,reply+1,p-reply-1);
    return p+2;
}


void ldbLogRedisReply(char *reply) {
    sds log = sdsnew("<reply> ");
    ldbRedisProtocolToHuman(&log,reply);
    ldbLogWithMaxLen(log);
}


void ldbPrint(lua_State *lua, char *varname) {
    lua_Debug ar;

    int l = 0; 
    while (lua_getstack(lua,l,&ar) != 0) {
        l++;
        const char *name;
        int i = 1; 
        while((name = lua_getlocal(lua,&ar,i)) != NULL) {
            i++;
            if (strcmp(varname,name) == 0) {
                ldbLogStackValue(lua,"<value> ");
                lua_pop(lua,1);
                return;
            } else {
                lua_pop(lua,1); 
            }
        }
    }

    
    if (!strcmp(varname,"ARGV") || !strcmp(varname,"KEYS")) {
        lua_getglobal(lua, varname);
        ldbLogStackValue(lua,"<value> ");
        lua_pop(lua,1);
    } else {
        ldbLog(sdsnew("No such variable."));
    }
}


void ldbPrintAll(lua_State *lua) {
    lua_Debug ar;
    int vars = 0;

    if (lua_getstack(lua,0,&ar) != 0) {
        const char *name;
        int i = 1; 
        while((name = lua_getlocal(lua,&ar,i)) != NULL) {
            i++;
            if (!strstr(name,"(*temporary)")) {
                sds prefix = sdscatprintf(sdsempty(),"<value> %s = ",name);
                ldbLogStackValue(lua,prefix);
                sdsfree(prefix);
                vars++;
            }
            lua_pop(lua,1);
        }
    }

    if (vars == 0) {
        ldbLog(sdsnew("No local variables in the current context."));
    }
}


void ldbBreak(sds *argv, int argc) {
    if (argc == 1) {
        if (ldb.bpcount == 0) {
            ldbLog(sdsnew("No breakpoints set. Use 'b <line>' to add one."));
            return;
        } else {
            ldbLog(sdscatfmt(sdsempty(),"%i breakpoints set:",ldb.bpcount));
            int j;
            for (j = 0; j < ldb.bpcount; j++)
                ldbLogSourceLine(ldb.bp[j]);
        }
    } else {
        int j;
        for (j = 1; j < argc; j++) {
            char *arg = argv[j];
            long line;
            if (!string2l(arg,sdslen(arg),&line)) {
                ldbLog(sdscatfmt(sdsempty(),"Invalid argument:'%s'",arg));
            } else {
                if (line == 0) {
                    ldb.bpcount = 0;
                    ldbLog(sdsnew("All breakpoints removed."));
                } else if (line > 0) {
                    if (ldb.bpcount == LDB_BREAKPOINTS_MAX) {
                        ldbLog(sdsnew("Too many breakpoints set."));
                    } else if (ldbAddBreakpoint(line)) {
                        ldbList(line,1);
                    } else {
                        ldbLog(sdsnew("Wrong line number."));
                    }
                } else if (line < 0) {
                    if (ldbDelBreakpoint(-line))
                        ldbLog(sdsnew("Breakpoint removed."));
                    else ldbLog(sdsnew("No breakpoint in the specified line."));
                }
            }
        }
    }
}


void ldbEval(lua_State *lua, sds *argv, int argc) {
    
    sds code = sdsjoinsds(argv+1,argc-1," ",1);
    sds expr = sdscatsds(sdsnew("return "),code);

    
    if (luaL_loadbuffer(lua,expr,sdslen(expr),"@ldb_eval")) {
        lua_pop(lua,1);
        
        if (luaL_loadbuffer(lua,code,sdslen(code),"@ldb_eval")) {
            ldbLog(sdscatfmt(sdsempty(),"<error> %s",lua_tostring(lua,-1)));
            lua_pop(lua,1);
            sdsfree(code);
            sdsfree(expr);
            return;
        }
    }

    
    sdsfree(code);
    sdsfree(expr);
    if (lua_pcall(lua,0,1,0)) {
        ldbLog(sdscatfmt(sdsempty(),"<error> %s",lua_tostring(lua,-1)));
        lua_pop(lua,1);
        return;
    }
    ldbLogStackValue(lua,"<retval> ");
    lua_pop(lua,1);
}


void ldbRedis(lua_State *lua, sds *argv, int argc) {
    int j, saved_rc = server.lua_replicate_commands;

    lua_getglobal(lua,"redis");
    lua_pushstring(lua,"call");
    lua_gettable(lua,-2);       
    for (j = 1; j < argc; j++)
        lua_pushlstring(lua,argv[j],sdslen(argv[j]));
    ldb.step = 1;               
    server.lua_replicate_commands = 1;
    lua_pcall(lua,argc-1,1,0);  
    ldb.step = 0;               
    server.lua_replicate_commands = saved_rc;
    lua_pop(lua,2);             
}


void ldbTrace(lua_State *lua) {
    lua_Debug ar;
    int level = 0;

    while(lua_getstack(lua,level,&ar)) {
        lua_getinfo(lua,"Snl",&ar);
        if(strstr(ar.short_src,"user_script") != NULL) {
            ldbLog(sdscatprintf(sdsempty(),"%s %s:", (level == 0) ? "In" : "From", ar.name ? ar.name : "top level"));

            ldbLogSourceLine(ar.currentline);
        }
        level++;
    }
    if (level == 0) {
        ldbLog(sdsnew("<error> Can't retrieve Lua stack."));
    }
}


void ldbMaxlen(sds *argv, int argc) {
    if (argc == 2) {
        int newval = atoi(argv[1]);
        ldb.maxlen_hint_sent = 1; 
        if (newval != 0 && newval <= 60) newval = 60;
        ldb.maxlen = newval;
    }
    if (ldb.maxlen) {
        ldbLog(sdscatprintf(sdsempty(),"<value> replies are truncated at %d bytes.",(int)ldb.maxlen));
    } else {
        ldbLog(sdscatprintf(sdsempty(),"<value> replies are unlimited."));
    }
}


int ldbRepl(lua_State *lua) {
    sds *argv;
    int argc;

    
    while(1) {
        while((argv = ldbReplParseCommand(&argc)) == NULL) {
            char buf[1024];
            int nread = connRead(ldb.conn,buf,sizeof(buf));
            if (nread <= 0) {
                
                ldb.step = 0;
                ldb.bpcount = 0;
                return C_ERR;
            }
            ldb.cbuf = sdscatlen(ldb.cbuf,buf,nread);
        }

        
        sdsfree(ldb.cbuf);
        ldb.cbuf = sdsempty();

        
        if (!strcasecmp(argv[0],"h") || !strcasecmp(argv[0],"help")) {
ldbLog(sdsnew("Redis Lua debugger help:"));
ldbLog(sdsnew("[h]elp               Show this help."));
ldbLog(sdsnew("[s]tep               Run current line and stop again."));
ldbLog(sdsnew("[n]ext               Alias for step."));
ldbLog(sdsnew("[c]continue          Run till next breakpoint."));
ldbLog(sdsnew("[l]list              List source code around current line."));
ldbLog(sdsnew("[l]list [line]       List source code around [line]."));
ldbLog(sdsnew("                     line = 0 means: current position."));
ldbLog(sdsnew("[l]list [line] [ctx] In this form [ctx] specifies how many lines"));
ldbLog(sdsnew("                     to show before/after [line]."));
ldbLog(sdsnew("[w]hole              List all source code. Alias for 'list 1 1000000'."));
ldbLog(sdsnew("[p]rint              Show all the local variables."));
ldbLog(sdsnew("[p]rint <var>        Show the value of the specified variable."));
ldbLog(sdsnew("                     Can also show global vars KEYS and ARGV."));
ldbLog(sdsnew("[b]reak              Show all breakpoints."));
ldbLog(sdsnew("[b]reak <line>       Add a breakpoint to the specified line."));
ldbLog(sdsnew("[b]reak -<line>      Remove breakpoint from the specified line."));
ldbLog(sdsnew("[b]reak 0            Remove all breakpoints."));
ldbLog(sdsnew("[t]race              Show a backtrace."));
ldbLog(sdsnew("[e]eval <code>       Execute some Lua code (in a different callframe)."));
ldbLog(sdsnew("[r]edis <cmd>        Execute a Redis command."));
ldbLog(sdsnew("[m]axlen [len]       Trim logged Redis replies and Lua var dumps to len."));
ldbLog(sdsnew("                     Specifying zero as <len> means unlimited."));
ldbLog(sdsnew("[a]bort              Stop the execution of the script. In sync"));
ldbLog(sdsnew("                     mode dataset changes will be retained."));
ldbLog(sdsnew(""));
ldbLog(sdsnew("Debugger functions you can call from Lua scripts:"));
ldbLog(sdsnew("redis.debug()        Produce logs in the debugger console."));
ldbLog(sdsnew("redis.breakpoint()   Stop execution like if there was a breakpoint in the"));
ldbLog(sdsnew("                     next line of code."));
            ldbSendLogs();
        } else if (!strcasecmp(argv[0],"s") || !strcasecmp(argv[0],"step") || !strcasecmp(argv[0],"n") || !strcasecmp(argv[0],"next")) {
            ldb.step = 1;
            break;
        } else if (!strcasecmp(argv[0],"c") || !strcasecmp(argv[0],"continue")){
            break;
        } else if (!strcasecmp(argv[0],"t") || !strcasecmp(argv[0],"trace")) {
            ldbTrace(lua);
            ldbSendLogs();
        } else if (!strcasecmp(argv[0],"m") || !strcasecmp(argv[0],"maxlen")) {
            ldbMaxlen(argv,argc);
            ldbSendLogs();
        } else if (!strcasecmp(argv[0],"b") || !strcasecmp(argv[0],"break")) {
            ldbBreak(argv,argc);
            ldbSendLogs();
        } else if (!strcasecmp(argv[0],"e") || !strcasecmp(argv[0],"eval")) {
            ldbEval(lua,argv,argc);
            ldbSendLogs();
        } else if (!strcasecmp(argv[0],"a") || !strcasecmp(argv[0],"abort")) {
            lua_pushstring(lua, "script aborted for user request");
            lua_error(lua);
        } else if (argc > 1 && (!strcasecmp(argv[0],"r") || !strcasecmp(argv[0],"redis"))) {
            ldbRedis(lua,argv,argc);
            ldbSendLogs();
        } else if ((!strcasecmp(argv[0],"p") || !strcasecmp(argv[0],"print"))) {
            if (argc == 2)
                ldbPrint(lua,argv[1]);
            else ldbPrintAll(lua);
            ldbSendLogs();
        } else if (!strcasecmp(argv[0],"l") || !strcasecmp(argv[0],"list")){
            int around = ldb.currentline, ctx = 5;
            if (argc > 1) {
                int num = atoi(argv[1]);
                if (num > 0) around = num;
            }
            if (argc > 2) ctx = atoi(argv[2]);
            ldbList(around,ctx);
            ldbSendLogs();
        } else if (!strcasecmp(argv[0],"w") || !strcasecmp(argv[0],"whole")){
            ldbList(1,1000000);
            ldbSendLogs();
        } else {
            ldbLog(sdsnew("<error> Unknown Redis Lua debugger command or " "wrong number of arguments."));
            ldbSendLogs();
        }

        
        sdsfreesplitres(argv,argc);
    }

    
    sdsfreesplitres(argv,argc);
    return C_OK;
}


void luaLdbLineHook(lua_State *lua, lua_Debug *ar) {
    lua_getstack(lua,0,ar);
    lua_getinfo(lua,"Sl",ar);
    ldb.currentline = ar->currentline;

    int bp = ldbIsBreakpoint(ldb.currentline) || ldb.luabp;
    int timeout = 0;

    
    if(strstr(ar->short_src,"user_script") == NULL) return;

    
    if (ar->event == LUA_HOOKCOUNT && ldb.step == 0 && bp == 0) {
        mstime_t elapsed = mstime() - server.lua_time_start;
        mstime_t timelimit = server.lua_time_limit ? server.lua_time_limit : 5000;
        if (elapsed >= timelimit) {
            timeout = 1;
            ldb.step = 1;
        } else {
            return; 
        }
    }

    if (ldb.step || bp) {
        char *reason = "step over";
        if (bp) reason = ldb.luabp ? "redis.breakpoint() called" :
                                     "break point";
        else if (timeout) reason = "timeout reached, infinite loop?";
        ldb.step = 0;
        ldb.luabp = 0;
        ldbLog(sdscatprintf(sdsempty(), "* Stopped at %d, stop reason = %s", ldb.currentline, reason));

        ldbLogSourceLine(ldb.currentline);
        ldbSendLogs();
        if (ldbRepl(lua) == C_ERR && timeout) {
            
            lua_pushstring(lua, "timeout during Lua debugging with client closing connection");
            lua_error(lua);
        }
        server.lua_time_start = mstime();
    }
}

