









typedef struct configEnum {
    const char *name;
    const int val;
} configEnum;

configEnum maxmemory_policy_enum[] = {
    {"volatile-lru", MAXMEMORY_VOLATILE_LRU}, {"volatile-lfu", MAXMEMORY_VOLATILE_LFU}, {"volatile-random",MAXMEMORY_VOLATILE_RANDOM}, {"volatile-ttl",MAXMEMORY_VOLATILE_TTL}, {"allkeys-lru",MAXMEMORY_ALLKEYS_LRU}, {"allkeys-lfu",MAXMEMORY_ALLKEYS_LFU}, {"allkeys-random",MAXMEMORY_ALLKEYS_RANDOM}, {"noeviction",MAXMEMORY_NO_EVICTION}, {NULL, 0}







};

configEnum syslog_facility_enum[] = {
    {"user",    LOG_USER}, {"local0",  LOG_LOCAL0}, {"local1",  LOG_LOCAL1}, {"local2",  LOG_LOCAL2}, {"local3",  LOG_LOCAL3}, {"local4",  LOG_LOCAL4}, {"local5",  LOG_LOCAL5}, {"local6",  LOG_LOCAL6}, {"local7",  LOG_LOCAL7}, {NULL, 0}








};

configEnum loglevel_enum[] = {
    {"debug", LL_DEBUG}, {"verbose", LL_VERBOSE}, {"notice", LL_NOTICE}, {"warning", LL_WARNING}, {NULL,0}



};

configEnum supervised_mode_enum[] = {
    {"upstart", SUPERVISED_UPSTART}, {"systemd", SUPERVISED_SYSTEMD}, {"auto", SUPERVISED_AUTODETECT}, {"no", SUPERVISED_NONE}, {NULL, 0}



};

configEnum aof_fsync_enum[] = {
    {"everysec", AOF_FSYNC_EVERYSEC}, {"always", AOF_FSYNC_ALWAYS}, {"no", AOF_FSYNC_NO}, {NULL, 0}


};

configEnum repl_diskless_load_enum[] = {
    {"disabled", REPL_DISKLESS_LOAD_DISABLED}, {"on-empty-db", REPL_DISKLESS_LOAD_WHEN_DB_EMPTY}, {"swapdb", REPL_DISKLESS_LOAD_SWAPDB}, {NULL, 0}


};

configEnum tls_auth_clients_enum[] = {
    {"no", TLS_CLIENT_AUTH_NO}, {"yes", TLS_CLIENT_AUTH_YES}, {"optional", TLS_CLIENT_AUTH_OPTIONAL}, {NULL, 0}


};

configEnum oom_score_adj_enum[] = {
    {"no", OOM_SCORE_ADJ_NO}, {"yes", OOM_SCORE_RELATIVE}, {"relative", OOM_SCORE_RELATIVE}, {"absolute", OOM_SCORE_ADJ_ABSOLUTE}, {NULL, 0}



};


clientBufferLimitsConfig clientBufferLimitsDefaults[CLIENT_TYPE_OBUF_COUNT] = {
    {0, 0, 0},  {1024*1024*256, 1024*1024*64, 60}, {1024*1024*32, 1024*1024*8, 60}

};


int configOOMScoreAdjValuesDefaults[CONFIG_OOM_COUNT] = { 0, 200, 800 };




typedef struct boolConfigData {
    int *config; 
    const int default_value; 
    int (*is_valid_fn)(int val, char **err); 
    int (*update_fn)(int val, int prev, char **err); 
} boolConfigData;

typedef struct stringConfigData {
    char **config; 
    const char *default_value; 
    int (*is_valid_fn)(char* val, char **err); 
    int (*update_fn)(char* val, char* prev, char **err); 
    int convert_empty_to_null; 
} stringConfigData;

typedef struct enumConfigData {
    int *config; 
    configEnum *enum_value; 
    const int default_value; 
    int (*is_valid_fn)(int val, char **err); 
    int (*update_fn)(int val, int prev, char **err); 
} enumConfigData;

typedef enum numericType {
    NUMERIC_TYPE_INT, NUMERIC_TYPE_UINT, NUMERIC_TYPE_LONG, NUMERIC_TYPE_ULONG, NUMERIC_TYPE_LONG_LONG, NUMERIC_TYPE_ULONG_LONG, NUMERIC_TYPE_SIZE_T, NUMERIC_TYPE_SSIZE_T, NUMERIC_TYPE_OFF_T, NUMERIC_TYPE_TIME_T, } numericType;










typedef struct numericConfigData {
    union {
        int *i;
        unsigned int *ui;
        long *l;
        unsigned long *ul;
        long long *ll;
        unsigned long long *ull;
        size_t *st;
        ssize_t *sst;
        off_t *ot;
        time_t *tt;
    } config; 
    int is_memory; 
    numericType numeric_type; 
    long long lower_bound; 
    long long upper_bound; 
    const long long default_value; 
    int (*is_valid_fn)(long long val, char **err); 
    int (*update_fn)(long long val, long long prev, char **err); 
} numericConfigData;

typedef union typeData {
    boolConfigData yesno;
    stringConfigData string;
    enumConfigData enumd;
    numericConfigData numeric;
} typeData;

typedef struct typeInterface {
    
    void (*init)(typeData data);
    
    int (*load)(typeData data, sds *argc, int argv, char **err);
    
    int (*set)(typeData data, sds value, int update, char **err);
    
    void (*get)(client *c, typeData data);
    
    void (*rewrite)(typeData data, const char *name, struct rewriteConfigState *state);
} typeInterface;

typedef struct standardConfig {
    const char *name; 
    const char *alias; 
    const int modifiable; 
    typeInterface interface; 
    typeData data; 
} standardConfig;

standardConfig configs[];




int configEnumGetValue(configEnum *ce, char *name) {
    while(ce->name != NULL) {
        if (!strcasecmp(ce->name,name)) return ce->val;
        ce++;
    }
    return INT_MIN;
}


const char *configEnumGetName(configEnum *ce, int val) {
    while(ce->name != NULL) {
        if (ce->val == val) return ce->name;
        ce++;
    }
    return NULL;
}


const char *configEnumGetNameOrUnknown(configEnum *ce, int val) {
    const char *name = configEnumGetName(ce,val);
    return name ? name : "unknown";
}


const char *evictPolicyToString(void) {
    return configEnumGetNameOrUnknown(maxmemory_policy_enum,server.maxmemory_policy);
}



int yesnotoi(char *s) {
    if (!strcasecmp(s,"yes")) return 1;
    else if (!strcasecmp(s,"no")) return 0;
    else return -1;
}

void appendServerSaveParams(time_t seconds, int changes) {
    server.saveparams = zrealloc(server.saveparams,sizeof(struct saveparam)*(server.saveparamslen+1));
    server.saveparams[server.saveparamslen].seconds = seconds;
    server.saveparams[server.saveparamslen].changes = changes;
    server.saveparamslen++;
}

void resetServerSaveParams(void) {
    zfree(server.saveparams);
    server.saveparams = NULL;
    server.saveparamslen = 0;
}

void queueLoadModule(sds path, sds *argv, int argc) {
    int i;
    struct moduleLoadQueueEntry *loadmod;

    loadmod = zmalloc(sizeof(struct moduleLoadQueueEntry));
    loadmod->argv = zmalloc(sizeof(robj*)*argc);
    loadmod->path = sdsnew(path);
    loadmod->argc = argc;
    for (i = 0; i < argc; i++) {
        loadmod->argv[i] = createRawStringObject(argv[i],sdslen(argv[i]));
    }
    listAddNodeTail(server.loadmodule_queue,loadmod);
}



static int updateOOMScoreAdjValues(sds *args, char **err, int apply) {
    int i;
    int values[CONFIG_OOM_COUNT];

    for (i = 0; i < CONFIG_OOM_COUNT; i++) {
        char *eptr;
        long long val = strtoll(args[i], &eptr, 10);

        if (*eptr != '\0' || val < -2000 || val > 2000) {
            if (err) *err = "Invalid oom-score-adj-values, elements must be between -2000 and 2000.";
            return C_ERR;
        }

        values[i] = val;
    }

    

    if (values[CONFIG_OOM_REPLICA] < values[CONFIG_OOM_MASTER] || values[CONFIG_OOM_BGCHILD] < values[CONFIG_OOM_REPLICA]) {
            serverLog(LOG_WARNING, "The oom-score-adj-values configuration may not work for non-privileged processes! " "Please consult the documentation.");

    }

    
    int old_values[CONFIG_OOM_COUNT];
    for (i = 0; i < CONFIG_OOM_COUNT; i++) {
        old_values[i] = server.oom_score_adj_values[i];
        server.oom_score_adj_values[i] = values[i];
    }
    
    
    if (!apply)
        return C_OK;

    
    if (setOOMScoreAdj(-1) == C_ERR) {
        
        for (i = 0; i < CONFIG_OOM_COUNT; i++)
            server.oom_score_adj_values[i] = old_values[i];

        if (err)
            *err = "Failed to apply oom-score-adj-values configuration, check server logs.";

        return C_ERR;
    }

    return C_OK;
}

void initConfigValues() {
    for (standardConfig *config = configs; config->name != NULL; config++) {
        config->interface.init(config->data);
    }
}

void loadServerConfigFromString(char *config) {
    char *err = NULL;
    int linenum = 0, totlines, i;
    int slaveof_linenum = 0;
    sds *lines;

    lines = sdssplitlen(config,strlen(config),"\n",1,&totlines);

    for (i = 0; i < totlines; i++) {
        sds *argv;
        int argc;

        linenum = i+1;
        lines[i] = sdstrim(lines[i]," \t\r\n");

        
        if (lines[i][0] == '#' || lines[i][0] == '\0') continue;

        
        argv = sdssplitargs(lines[i],&argc);
        if (argv == NULL) {
            err = "Unbalanced quotes in configuration line";
            goto loaderr;
        }

        
        if (argc == 0) {
            sdsfreesplitres(argv,argc);
            continue;
        }
        sdstolower(argv[0]);

        
        int match = 0;
        for (standardConfig *config = configs; config->name != NULL; config++) {
            if ((!strcasecmp(argv[0],config->name) || (config->alias && !strcasecmp(argv[0],config->alias))))
            {
                if (argc != 2) {
                    err = "wrong number of arguments";
                    goto loaderr;
                }
                if (!config->interface.set(config->data, argv[1], 0, &err)) {
                    goto loaderr;
                }

                match = 1;
                break;
            }
        }

        if (match) {
            sdsfreesplitres(argv,argc);
            continue;
        }

        
        if (!strcasecmp(argv[0],"bind") && argc >= 2) {
            int j, addresses = argc-1;

            if (addresses > CONFIG_BINDADDR_MAX) {
                err = "Too many bind addresses specified"; goto loaderr;
            }
            
            for (j = 0; j < server.bindaddr_count; j++) {
                zfree(server.bindaddr[j]);
            }
            for (j = 0; j < addresses; j++)
                server.bindaddr[j] = zstrdup(argv[j+1]);
            server.bindaddr_count = addresses;
        } else if (!strcasecmp(argv[0],"unixsocketperm") && argc == 2) {
            errno = 0;
            server.unixsocketperm = (mode_t)strtol(argv[1], NULL, 8);
            if (errno || server.unixsocketperm > 0777) {
                err = "Invalid socket file permissions"; goto loaderr;
            }
        } else if (!strcasecmp(argv[0],"save")) {
            if (argc == 3) {
                int seconds = atoi(argv[1]);
                int changes = atoi(argv[2]);
                if (seconds < 1 || changes < 0) {
                    err = "Invalid save parameters"; goto loaderr;
                }
                appendServerSaveParams(seconds,changes);
            } else if (argc == 2 && !strcasecmp(argv[1],"")) {
                resetServerSaveParams();
            }
        } else if (!strcasecmp(argv[0],"dir") && argc == 2) {
            if (chdir(argv[1]) == -1) {
                serverLog(LL_WARNING,"Can't chdir to '%s': %s", argv[1], strerror(errno));
                exit(1);
            }
        } else if (!strcasecmp(argv[0],"logfile") && argc == 2) {
            FILE *logfp;

            zfree(server.logfile);
            server.logfile = zstrdup(argv[1]);
            if (server.logfile[0] != '\0') {
                
                logfp = fopen(server.logfile,"a");
                if (logfp == NULL) {
                    err = sdscatprintf(sdsempty(), "Can't open the log file: %s", strerror(errno));
                    goto loaderr;
                }
                fclose(logfp);
            }
        } else if (!strcasecmp(argv[0],"include") && argc == 2) {
            loadServerConfig(argv[1],NULL);
        } else if ((!strcasecmp(argv[0],"client-query-buffer-limit")) && argc == 2) {
             server.client_max_querybuf_len = memtoll(argv[1],NULL);
        } else if ((!strcasecmp(argv[0],"slaveof") || !strcasecmp(argv[0],"replicaof")) && argc == 3) {
            slaveof_linenum = linenum;
            sdsfree(server.masterhost);
            if (!strcasecmp(argv[1], "no") && !strcasecmp(argv[2], "one")) {
                server.masterhost = NULL;
                continue;
            }
            server.masterhost = sdsnew(argv[1]);
            char *ptr;
            server.masterport = strtol(argv[2], &ptr, 10);
            if (server.masterport < 0 || server.masterport > 65535 || *ptr != '\0') {
                err = "Invalid master port"; goto loaderr;
            }
            server.repl_state = REPL_STATE_CONNECT;
        } else if (!strcasecmp(argv[0],"requirepass") && argc == 2) {
            if (strlen(argv[1]) > CONFIG_AUTHPASS_MAX_LEN) {
                err = "Password is longer than CONFIG_AUTHPASS_MAX_LEN";
                goto loaderr;
            }
            
            ACLSetUser(DefaultUser,"resetpass",-1);
            sdsfree(server.requirepass);
            server.requirepass = NULL;
            if (sdslen(argv[1])) {
                sds aclop = sdscatprintf(sdsempty(),">%s",argv[1]);
                ACLSetUser(DefaultUser,aclop,sdslen(aclop));
                sdsfree(aclop);
                server.requirepass = sdsnew(argv[1]);
            } else {
                ACLSetUser(DefaultUser,"nopass",-1);
            }
        } else if (!strcasecmp(argv[0],"list-max-ziplist-entries") && argc == 2){
            
        } else if (!strcasecmp(argv[0],"list-max-ziplist-value") && argc == 2) {
            
        } else if (!strcasecmp(argv[0],"rename-command") && argc == 3) {
            struct redisCommand *cmd = lookupCommand(argv[1]);
            int retval;

            if (!cmd) {
                err = "No such command in rename-command";
                goto loaderr;
            }

            
            retval = dictDelete(server.commands, argv[1]);
            serverAssert(retval == DICT_OK);

            
            if (sdslen(argv[2]) != 0) {
                sds copy = sdsdup(argv[2]);

                retval = dictAdd(server.commands, copy, cmd);
                if (retval != DICT_OK) {
                    sdsfree(copy);
                    err = "Target command name already exists"; goto loaderr;
                }
            }
        } else if (!strcasecmp(argv[0],"cluster-config-file") && argc == 2) {
            zfree(server.cluster_configfile);
            server.cluster_configfile = zstrdup(argv[1]);
        } else if (!strcasecmp(argv[0],"client-output-buffer-limit") && argc == 5)
        {
            int class = getClientTypeByName(argv[1]);
            unsigned long long hard, soft;
            int soft_seconds;

            if (class == -1 || class == CLIENT_TYPE_MASTER) {
                err = "Unrecognized client limit class: the user specified " "an invalid one, or 'master' which has no buffer limits.";
                goto loaderr;
            }
            hard = memtoll(argv[2],NULL);
            soft = memtoll(argv[3],NULL);
            soft_seconds = atoi(argv[4]);
            if (soft_seconds < 0) {
                err = "Negative number of seconds in soft limit is invalid";
                goto loaderr;
            }
            server.client_obuf_limits[class].hard_limit_bytes = hard;
            server.client_obuf_limits[class].soft_limit_bytes = soft;
            server.client_obuf_limits[class].soft_limit_seconds = soft_seconds;
        } else if (!strcasecmp(argv[0],"oom-score-adj-values") && argc == 1 + CONFIG_OOM_COUNT) {
            if (updateOOMScoreAdjValues(&argv[1], &err, 0) == C_ERR) goto loaderr;
        } else if (!strcasecmp(argv[0],"notify-keyspace-events") && argc == 2) {
            int flags = keyspaceEventsStringToFlags(argv[1]);

            if (flags == -1) {
                err = "Invalid event class character. Use 'g$lshzxeA'.";
                goto loaderr;
            }
            server.notify_keyspace_events = flags;
        } else if (!strcasecmp(argv[0],"user") && argc >= 2) {
            int argc_err;
            if (ACLAppendUserForLoading(argv,argc,&argc_err) == C_ERR) {
                char buf[1024];
                char *errmsg = ACLSetUserStringError();
                snprintf(buf,sizeof(buf),"Error in user declaration '%s': %s", argv[argc_err],errmsg);
                err = buf;
                goto loaderr;
            }
        } else if (!strcasecmp(argv[0],"loadmodule") && argc >= 2) {
            queueLoadModule(argv[1],&argv[2],argc-2);
        } else if (!strcasecmp(argv[0],"sentinel")) {
            
            if (argc != 1) {
                if (!server.sentinel_mode) {
                    err = "sentinel directive while not in sentinel mode";
                    goto loaderr;
                }
                err = sentinelHandleConfiguration(argv+1,argc-1);
                if (err) goto loaderr;
            }
        } else {
            err = "Bad directive or wrong number of arguments"; goto loaderr;
        }
        sdsfreesplitres(argv,argc);
    }

    
    if (server.cluster_enabled && server.masterhost) {
        linenum = slaveof_linenum;
        i = linenum-1;
        err = "replicaof directive not allowed in cluster mode";
        goto loaderr;
    }

    sdsfreesplitres(lines,totlines);
    return;

loaderr:
    fprintf(stderr, "\n*** FATAL CONFIG FILE ERROR (Redis %s) ***\n", REDIS_VERSION);
    fprintf(stderr, "Reading the configuration file, at line %d\n", linenum);
    fprintf(stderr, ">>> '%s'\n", lines[i]);
    fprintf(stderr, "%s\n", err);
    exit(1);
}


void loadServerConfig(char *filename, char *options) {
    sds config = sdsempty();
    char buf[CONFIG_MAX_LINE+1];

    
    if (filename) {
        FILE *fp;

        if (filename[0] == '-' && filename[1] == '\0') {
            fp = stdin;
        } else {
            if ((fp = fopen(filename,"r")) == NULL) {
                serverLog(LL_WARNING, "Fatal error, can't open config file '%s': %s", filename, strerror(errno));

                exit(1);
            }
        }
        while(fgets(buf,CONFIG_MAX_LINE+1,fp) != NULL)
            config = sdscat(config,buf);
        if (fp != stdin) fclose(fp);
    }
    
    if (options) {
        config = sdscat(config,"\n");
        config = sdscat(config,options);
    }
    loadServerConfigFromString(config);
    sdsfree(config);
}


























void configSetCommand(client *c) {
    robj *o;
    long long ll;
    int err;
    char *errstr = NULL;
    serverAssertWithInfo(c,c->argv[2],sdsEncodedObject(c->argv[2]));
    serverAssertWithInfo(c,c->argv[3],sdsEncodedObject(c->argv[3]));
    o = c->argv[3];

    
    for (standardConfig *config = configs; config->name != NULL; config++) {
        if(config->modifiable && (!strcasecmp(c->argv[2]->ptr,config->name) || (config->alias && !strcasecmp(c->argv[2]->ptr,config->alias))))
        {
            if (!config->interface.set(config->data,o->ptr,1,&errstr)) {
                goto badfmt;
            }
            addReply(c,shared.ok);
            return;
        }
    }

    if (0) { 

    
    config_set_special_field("requirepass") {
        if (sdslen(o->ptr) > CONFIG_AUTHPASS_MAX_LEN) goto badfmt;
        
        ACLSetUser(DefaultUser,"resetpass",-1);
        sdsfree(server.requirepass);
        server.requirepass = NULL;
        if (sdslen(o->ptr)) {
            sds aclop = sdscatprintf(sdsempty(),">%s",(char*)o->ptr);
            ACLSetUser(DefaultUser,aclop,sdslen(aclop));
            sdsfree(aclop);
            server.requirepass = sdsnew(o->ptr);
        } else {
            ACLSetUser(DefaultUser,"nopass",-1);
        }
    } config_set_special_field("save") {
        int vlen, j;
        sds *v = sdssplitlen(o->ptr,sdslen(o->ptr)," ",1,&vlen);

        
        if (vlen & 1) {
            sdsfreesplitres(v,vlen);
            goto badfmt;
        }
        for (j = 0; j < vlen; j++) {
            char *eptr;
            long val;

            val = strtoll(v[j], &eptr, 10);
            if (eptr[0] != '\0' || ((j & 1) == 0 && val < 1) || ((j & 1) == 1 && val < 0)) {

                sdsfreesplitres(v,vlen);
                goto badfmt;
            }
        }
        
        resetServerSaveParams();
        for (j = 0; j < vlen; j += 2) {
            time_t seconds;
            int changes;

            seconds = strtoll(v[j],NULL,10);
            changes = strtoll(v[j+1],NULL,10);
            appendServerSaveParams(seconds, changes);
        }
        sdsfreesplitres(v,vlen);
    } config_set_special_field("dir") {
        if (chdir((char*)o->ptr) == -1) {
            addReplyErrorFormat(c,"Changing directory: %s", strerror(errno));
            return;
        }
    } config_set_special_field("client-output-buffer-limit") {
        int vlen, j;
        sds *v = sdssplitlen(o->ptr,sdslen(o->ptr)," ",1,&vlen);

        
        if (vlen % 4) {
            sdsfreesplitres(v,vlen);
            goto badfmt;
        }

        
        for (j = 0; j < vlen; j++) {
            long val;

            if ((j % 4) == 0) {
                int class = getClientTypeByName(v[j]);
                if (class == -1 || class == CLIENT_TYPE_MASTER) {
                    sdsfreesplitres(v,vlen);
                    goto badfmt;
                }
            } else {
                val = memtoll(v[j], &err);
                if (err || val < 0) {
                    sdsfreesplitres(v,vlen);
                    goto badfmt;
                }
            }
        }
        
        for (j = 0; j < vlen; j += 4) {
            int class;
            unsigned long long hard, soft;
            int soft_seconds;

            class = getClientTypeByName(v[j]);
            hard = memtoll(v[j+1],NULL);
            soft = memtoll(v[j+2],NULL);
            soft_seconds = strtoll(v[j+3],NULL,10);

            server.client_obuf_limits[class].hard_limit_bytes = hard;
            server.client_obuf_limits[class].soft_limit_bytes = soft;
            server.client_obuf_limits[class].soft_limit_seconds = soft_seconds;
        }
        sdsfreesplitres(v,vlen);
    } config_set_special_field("oom-score-adj-values") {
        int vlen;
        int success = 1;

        sds *v = sdssplitlen(o->ptr, sdslen(o->ptr), " ", 1, &vlen);
        if (vlen != CONFIG_OOM_COUNT || updateOOMScoreAdjValues(v, &errstr, 1) == C_ERR)
            success = 0;

        sdsfreesplitres(v, vlen);
        if (!success)
            goto badfmt;
    } config_set_special_field("notify-keyspace-events") {
        int flags = keyspaceEventsStringToFlags(o->ptr);

        if (flags == -1) goto badfmt;
        server.notify_keyspace_events = flags;
    
    } config_set_numerical_field( "watchdog-period",ll,0,INT_MAX) {
        if (ll)
            enableWatchdog(ll);
        else disableWatchdog();
    
    } config_set_memory_field( "client-query-buffer-limit",server.client_max_querybuf_len) {
    
    } config_set_else {
        addReplyErrorFormat(c,"Unsupported CONFIG parameter: %s", (char*)c->argv[2]->ptr);
        return;
    }

    
    addReply(c,shared.ok);
    return;

badfmt: 
    if (errstr) {
        addReplyErrorFormat(c,"Invalid argument '%s' for CONFIG SET '%s' - %s", (char*)o->ptr, (char*)c->argv[2]->ptr, errstr);


    } else {
        addReplyErrorFormat(c,"Invalid argument '%s' for CONFIG SET '%s'", (char*)o->ptr, (char*)c->argv[2]->ptr);

    }
}


























void configGetCommand(client *c) {
    robj *o = c->argv[2];
    void *replylen = addReplyDeferredLen(c);
    char *pattern = o->ptr;
    char buf[128];
    int matches = 0;
    serverAssertWithInfo(c,o,sdsEncodedObject(o));

    
    for (standardConfig *config = configs; config->name != NULL; config++) {
        if (stringmatch(pattern,config->name,1)) {
            addReplyBulkCString(c,config->name);
            config->interface.get(c,config->data);
            matches++;
        }
        if (config->alias && stringmatch(pattern,config->alias,1)) {
            addReplyBulkCString(c,config->alias);
            config->interface.get(c,config->data);
            matches++;
        }
    }

    
    config_get_string_field("logfile",server.logfile);

    
    config_get_numerical_field("client-query-buffer-limit",server.client_max_querybuf_len);
    config_get_numerical_field("watchdog-period",server.watchdog_period);

    

    if (stringmatch(pattern,"dir",1)) {
        char buf[1024];

        if (getcwd(buf,sizeof(buf)) == NULL)
            buf[0] = '\0';

        addReplyBulkCString(c,"dir");
        addReplyBulkCString(c,buf);
        matches++;
    }
    if (stringmatch(pattern,"save",1)) {
        sds buf = sdsempty();
        int j;

        for (j = 0; j < server.saveparamslen; j++) {
            buf = sdscatprintf(buf,"%jd %d", (intmax_t)server.saveparams[j].seconds, server.saveparams[j].changes);

            if (j != server.saveparamslen-1)
                buf = sdscatlen(buf," ",1);
        }
        addReplyBulkCString(c,"save");
        addReplyBulkCString(c,buf);
        sdsfree(buf);
        matches++;
    }
    if (stringmatch(pattern,"client-output-buffer-limit",1)) {
        sds buf = sdsempty();
        int j;

        for (j = 0; j < CLIENT_TYPE_OBUF_COUNT; j++) {
            buf = sdscatprintf(buf,"%s %llu %llu %ld", getClientTypeName(j), server.client_obuf_limits[j].hard_limit_bytes, server.client_obuf_limits[j].soft_limit_bytes, (long) server.client_obuf_limits[j].soft_limit_seconds);



            if (j != CLIENT_TYPE_OBUF_COUNT-1)
                buf = sdscatlen(buf," ",1);
        }
        addReplyBulkCString(c,"client-output-buffer-limit");
        addReplyBulkCString(c,buf);
        sdsfree(buf);
        matches++;
    }
    if (stringmatch(pattern,"unixsocketperm",1)) {
        char buf[32];
        snprintf(buf,sizeof(buf),"%o",server.unixsocketperm);
        addReplyBulkCString(c,"unixsocketperm");
        addReplyBulkCString(c,buf);
        matches++;
    }
    if (stringmatch(pattern,"slaveof",1) || stringmatch(pattern,"replicaof",1))
    {
        char *optname = stringmatch(pattern,"slaveof",1) ? "slaveof" : "replicaof";
        char buf[256];

        addReplyBulkCString(c,optname);
        if (server.masterhost)
            snprintf(buf,sizeof(buf),"%s %d", server.masterhost, server.masterport);
        else buf[0] = '\0';
        addReplyBulkCString(c,buf);
        matches++;
    }
    if (stringmatch(pattern,"notify-keyspace-events",1)) {
        sds flags = keyspaceEventsFlagsToString(server.notify_keyspace_events);

        addReplyBulkCString(c,"notify-keyspace-events");
        addReplyBulkSds(c,flags);
        matches++;
    }
    if (stringmatch(pattern,"bind",1)) {
        sds aux = sdsjoin(server.bindaddr,server.bindaddr_count," ");

        addReplyBulkCString(c,"bind");
        addReplyBulkCString(c,aux);
        sdsfree(aux);
        matches++;
    }
    if (stringmatch(pattern,"requirepass",1)) {
        addReplyBulkCString(c,"requirepass");
        sds password = server.requirepass;
        if (password) {
            addReplyBulkCBuffer(c,password,sdslen(password));
        } else {
            addReplyBulkCString(c,"");
        }
        matches++;
    }

    if (stringmatch(pattern,"oom-score-adj-values",0)) {
        sds buf = sdsempty();
        int j;

        for (j = 0; j < CONFIG_OOM_COUNT; j++) {
            buf = sdscatprintf(buf,"%d", server.oom_score_adj_values[j]);
            if (j != CONFIG_OOM_COUNT-1)
                buf = sdscatlen(buf," ",1);
        }

        addReplyBulkCString(c,"oom-score-adj-values");
        addReplyBulkCString(c,buf);
        sdsfree(buf);
        matches++;
    }

    setDeferredMapLen(c,replylen,matches);
}






uint64_t dictSdsCaseHash(const void *key);
int dictSdsKeyCaseCompare(void *privdata, const void *key1, const void *key2);
void dictSdsDestructor(void *privdata, void *val);
void dictListDestructor(void *privdata, void *val);


void rewriteConfigSentinelOption(struct rewriteConfigState *state);

dictType optionToLineDictType = {
    dictSdsCaseHash,             NULL, NULL, dictSdsKeyCaseCompare, dictSdsDestructor, dictListDestructor };






dictType optionSetDictType = {
    dictSdsCaseHash,             NULL, NULL, dictSdsKeyCaseCompare, dictSdsDestructor, NULL };







struct rewriteConfigState {
    dict *option_to_line; 
    dict *rewritten;      
    int numlines;         
    sds *lines;           
    int has_tail;         
    int force_all;        
};


void rewriteConfigAppendLine(struct rewriteConfigState *state, sds line) {
    state->lines = zrealloc(state->lines, sizeof(char*) * (state->numlines+1));
    state->lines[state->numlines++] = line;
}


void rewriteConfigAddLineNumberToOption(struct rewriteConfigState *state, sds option, int linenum) {
    list *l = dictFetchValue(state->option_to_line,option);

    if (l == NULL) {
        l = listCreate();
        dictAdd(state->option_to_line,sdsdup(option),l);
    }
    listAddNodeTail(l,(void*)(long)linenum);
}


void rewriteConfigMarkAsProcessed(struct rewriteConfigState *state, const char *option) {
    sds opt = sdsnew(option);

    if (dictAdd(state->rewritten,opt,NULL) != DICT_OK) sdsfree(opt);
}


struct rewriteConfigState *rewriteConfigReadOldFile(char *path) {
    FILE *fp = fopen(path,"r");
    if (fp == NULL && errno != ENOENT) return NULL;

    char buf[CONFIG_MAX_LINE+1];
    int linenum = -1;
    struct rewriteConfigState *state = zmalloc(sizeof(*state));
    state->option_to_line = dictCreate(&optionToLineDictType,NULL);
    state->rewritten = dictCreate(&optionSetDictType,NULL);
    state->numlines = 0;
    state->lines = NULL;
    state->has_tail = 0;
    state->force_all = 0;
    if (fp == NULL) return state;

    
    while(fgets(buf,CONFIG_MAX_LINE+1,fp) != NULL) {
        int argc;
        sds *argv;
        sds line = sdstrim(sdsnew(buf),"\r\n\t ");

        linenum++; 

        
        if (line[0] == '#' || line[0] == '\0') {
            if (!state->has_tail && !strcmp(line,REDIS_CONFIG_REWRITE_SIGNATURE))
                state->has_tail = 1;
            rewriteConfigAppendLine(state,line);
            continue;
        }

        
        argv = sdssplitargs(line,&argc);
        if (argv == NULL) {
            
            sds aux = sdsnew("# ??? ");
            aux = sdscatsds(aux,line);
            sdsfree(line);
            rewriteConfigAppendLine(state,aux);
            continue;
        }

        sdstolower(argv[0]); 

        
        rewriteConfigAppendLine(state,line);

        
        char *p = strstr(argv[0],"slave");
        if (p) {
            sds alt = sdsempty();
            alt = sdscatlen(alt,argv[0],p-argv[0]);;
            alt = sdscatlen(alt,"replica",7);
            alt = sdscatlen(alt,p+5,strlen(p+5));
            sdsfree(argv[0]);
            argv[0] = alt;
        }
        rewriteConfigAddLineNumberToOption(state,argv[0],linenum);
        sdsfreesplitres(argv,argc);
    }
    fclose(fp);
    return state;
}


void rewriteConfigRewriteLine(struct rewriteConfigState *state, const char *option, sds line, int force) {
    sds o = sdsnew(option);
    list *l = dictFetchValue(state->option_to_line,o);

    rewriteConfigMarkAsProcessed(state,option);

    if (!l && !force && !state->force_all) {
        
        sdsfree(line);
        sdsfree(o);
        return;
    }

    if (l) {
        listNode *ln = listFirst(l);
        int linenum = (long) ln->value;

        
        listDelNode(l,ln);
        if (listLength(l) == 0) dictDelete(state->option_to_line,o);
        sdsfree(state->lines[linenum]);
        state->lines[linenum] = line;
    } else {
        
        if (!state->has_tail) {
            rewriteConfigAppendLine(state, sdsnew(REDIS_CONFIG_REWRITE_SIGNATURE));
            state->has_tail = 1;
        }
        rewriteConfigAppendLine(state,line);
    }
    sdsfree(o);
}


int rewriteConfigFormatMemory(char *buf, size_t len, long long bytes) {
    int gb = 1024*1024*1024;
    int mb = 1024*1024;
    int kb = 1024;

    if (bytes && (bytes % gb) == 0) {
        return snprintf(buf,len,"%lldgb",bytes/gb);
    } else if (bytes && (bytes % mb) == 0) {
        return snprintf(buf,len,"%lldmb",bytes/mb);
    } else if (bytes && (bytes % kb) == 0) {
        return snprintf(buf,len,"%lldkb",bytes/kb);
    } else {
        return snprintf(buf,len,"%lld",bytes);
    }
}


void rewriteConfigBytesOption(struct rewriteConfigState *state, const char *option, long long value, long long defvalue) {
    char buf[64];
    int force = value != defvalue;
    sds line;

    rewriteConfigFormatMemory(buf,sizeof(buf),value);
    line = sdscatprintf(sdsempty(),"%s %s",option,buf);
    rewriteConfigRewriteLine(state,option,line,force);
}


void rewriteConfigYesNoOption(struct rewriteConfigState *state, const char *option, int value, int defvalue) {
    int force = value != defvalue;
    sds line = sdscatprintf(sdsempty(),"%s %s",option, value ? "yes" : "no");

    rewriteConfigRewriteLine(state,option,line,force);
}


void rewriteConfigStringOption(struct rewriteConfigState *state, const char *option, char *value, const char *defvalue) {
    int force = 1;
    sds line;

    
    if (value == NULL) {
        rewriteConfigMarkAsProcessed(state,option);
        return;
    }

    
    if (defvalue && strcmp(value,defvalue) == 0) force = 0;

    line = sdsnew(option);
    line = sdscatlen(line, " ", 1);
    line = sdscatrepr(line, value, strlen(value));

    rewriteConfigRewriteLine(state,option,line,force);
}


void rewriteConfigNumericalOption(struct rewriteConfigState *state, const char *option, long long value, long long defvalue) {
    int force = value != defvalue;
    sds line = sdscatprintf(sdsempty(),"%s %lld",option,value);

    rewriteConfigRewriteLine(state,option,line,force);
}


void rewriteConfigOctalOption(struct rewriteConfigState *state, char *option, int value, int defvalue) {
    int force = value != defvalue;
    sds line = sdscatprintf(sdsempty(),"%s %o",option,value);

    rewriteConfigRewriteLine(state,option,line,force);
}


void rewriteConfigEnumOption(struct rewriteConfigState *state, const char *option, int value, configEnum *ce, int defval) {
    sds line;
    const char *name = configEnumGetNameOrUnknown(ce,value);
    int force = value != defval;

    line = sdscatprintf(sdsempty(),"%s %s",option,name);
    rewriteConfigRewriteLine(state,option,line,force);
}


void rewriteConfigSaveOption(struct rewriteConfigState *state) {
    int j;
    sds line;

    
    if (server.sentinel_mode) {
        rewriteConfigMarkAsProcessed(state,"save");
        return;
    }

    
    for (j = 0; j < server.saveparamslen; j++) {
        line = sdscatprintf(sdsempty(),"save %ld %d", (long) server.saveparams[j].seconds, server.saveparams[j].changes);
        rewriteConfigRewriteLine(state,"save",line,1);
    }
    
    rewriteConfigMarkAsProcessed(state,"save");
}


void rewriteConfigUserOption(struct rewriteConfigState *state) {
    
    if (server.acl_filename[0] != '\0') {
        rewriteConfigMarkAsProcessed(state,"user");
        return;
    }

    
    raxIterator ri;
    raxStart(&ri,Users);
    raxSeek(&ri,"^",NULL,0);
    while(raxNext(&ri)) {
        user *u = ri.data;
        sds line = sdsnew("user ");
        line = sdscatsds(line,u->name);
        line = sdscatlen(line," ",1);
        sds descr = ACLDescribeUser(u);
        line = sdscatsds(line,descr);
        sdsfree(descr);
        rewriteConfigRewriteLine(state,"user",line,1);
    }
    raxStop(&ri);

    
    rewriteConfigMarkAsProcessed(state,"user");
}


void rewriteConfigDirOption(struct rewriteConfigState *state) {
    char cwd[1024];

    if (getcwd(cwd,sizeof(cwd)) == NULL) {
        rewriteConfigMarkAsProcessed(state,"dir");
        return; 
    }
    rewriteConfigStringOption(state,"dir",cwd,NULL);
}


void rewriteConfigSlaveofOption(struct rewriteConfigState *state, char *option) {
    sds line;

    
    if (server.cluster_enabled || server.masterhost == NULL) {
        rewriteConfigMarkAsProcessed(state,option);
        return;
    }
    line = sdscatprintf(sdsempty(),"%s %s %d", option, server.masterhost, server.masterport);
    rewriteConfigRewriteLine(state,option,line,1);
}


void rewriteConfigNotifykeyspaceeventsOption(struct rewriteConfigState *state) {
    int force = server.notify_keyspace_events != 0;
    char *option = "notify-keyspace-events";
    sds line, flags;

    flags = keyspaceEventsFlagsToString(server.notify_keyspace_events);
    line = sdsnew(option);
    line = sdscatlen(line, " ", 1);
    line = sdscatrepr(line, flags, sdslen(flags));
    sdsfree(flags);
    rewriteConfigRewriteLine(state,option,line,force);
}


void rewriteConfigClientoutputbufferlimitOption(struct rewriteConfigState *state) {
    int j;
    char *option = "client-output-buffer-limit";

    for (j = 0; j < CLIENT_TYPE_OBUF_COUNT; j++) {
        int force = (server.client_obuf_limits[j].hard_limit_bytes != clientBufferLimitsDefaults[j].hard_limit_bytes) || (server.client_obuf_limits[j].soft_limit_bytes != clientBufferLimitsDefaults[j].soft_limit_bytes) || (server.client_obuf_limits[j].soft_limit_seconds != clientBufferLimitsDefaults[j].soft_limit_seconds);




        sds line;
        char hard[64], soft[64];

        rewriteConfigFormatMemory(hard,sizeof(hard), server.client_obuf_limits[j].hard_limit_bytes);
        rewriteConfigFormatMemory(soft,sizeof(soft), server.client_obuf_limits[j].soft_limit_bytes);

        char *typename = getClientTypeName(j);
        if (!strcmp(typename,"slave")) typename = "replica";
        line = sdscatprintf(sdsempty(),"%s %s %s %s %ld", option, typename, hard, soft, (long) server.client_obuf_limits[j].soft_limit_seconds);

        rewriteConfigRewriteLine(state,option,line,force);
    }
}


void rewriteConfigOOMScoreAdjValuesOption(struct rewriteConfigState *state) {
    int force = 0;
    int j;
    char *option = "oom-score-adj-values";
    sds line;

    line = sdsnew(option);
    line = sdscatlen(line, " ", 1);
    for (j = 0; j < CONFIG_OOM_COUNT; j++) {
        if (server.oom_score_adj_values[j] != configOOMScoreAdjValuesDefaults[j])
            force = 1;

        line = sdscatprintf(line, "%d", server.oom_score_adj_values[j]);
        if (j+1 != CONFIG_OOM_COUNT)
            line = sdscatlen(line, " ", 1);
    }
    rewriteConfigRewriteLine(state,option,line,force);
}


void rewriteConfigBindOption(struct rewriteConfigState *state) {
    int force = 1;
    sds line, addresses;
    char *option = "bind";

    
    if (server.bindaddr_count == 0) {
        rewriteConfigMarkAsProcessed(state,option);
        return;
    }

    
    addresses = sdsjoin(server.bindaddr,server.bindaddr_count," ");
    line = sdsnew(option);
    line = sdscatlen(line, " ", 1);
    line = sdscatsds(line, addresses);
    sdsfree(addresses);

    rewriteConfigRewriteLine(state,option,line,force);
}


void rewriteConfigRequirepassOption(struct rewriteConfigState *state, char *option) {
    int force = 1;
    sds line;
    sds password = server.requirepass;

    
    if (password == NULL) {
        rewriteConfigMarkAsProcessed(state,option);
        return;
    }

    line = sdsnew(option);
    line = sdscatlen(line, " ", 1);
    line = sdscatsds(line, password);

    rewriteConfigRewriteLine(state,option,line,force);
}


sds rewriteConfigGetContentFromState(struct rewriteConfigState *state) {
    sds content = sdsempty();
    int j, was_empty = 0;

    for (j = 0; j < state->numlines; j++) {
        
        if (sdslen(state->lines[j]) == 0) {
            if (was_empty) continue;
            was_empty = 1;
        } else {
            was_empty = 0;
        }
        content = sdscatsds(content,state->lines[j]);
        content = sdscatlen(content,"\n",1);
    }
    return content;
}


void rewriteConfigReleaseState(struct rewriteConfigState *state) {
    sdsfreesplitres(state->lines,state->numlines);
    dictRelease(state->option_to_line);
    dictRelease(state->rewritten);
    zfree(state);
}


void rewriteConfigRemoveOrphaned(struct rewriteConfigState *state) {
    dictIterator *di = dictGetIterator(state->option_to_line);
    dictEntry *de;

    while((de = dictNext(di)) != NULL) {
        list *l = dictGetVal(de);
        sds option = dictGetKey(de);

        
        if (dictFind(state->rewritten,option) == NULL) {
            serverLog(LL_DEBUG,"Not rewritten option: %s", option);
            continue;
        }

        while(listLength(l)) {
            listNode *ln = listFirst(l);
            int linenum = (long) ln->value;

            sdsfree(state->lines[linenum]);
            state->lines[linenum] = sdsempty();
            listDelNode(l,ln);
        }
    }
    dictReleaseIterator(di);
}


int rewriteConfigOverwriteFile(char *configfile, sds content) {
    int fd = -1;
    int retval = -1;
    char tmp_conffile[PATH_MAX];
    const char *tmp_suffix = ".XXXXXX";
    size_t offset = 0;
    ssize_t written_bytes = 0;

    int tmp_path_len = snprintf(tmp_conffile, sizeof(tmp_conffile), "%s%s", configfile, tmp_suffix);
    if (tmp_path_len <= 0 || (unsigned int)tmp_path_len >= sizeof(tmp_conffile)) {
        serverLog(LL_WARNING, "Config file full path is too long");
        errno = ENAMETOOLONG;
        return retval;
    }


    fd = mkostemp(tmp_conffile, O_CLOEXEC);

    
    fd = mkstemp(tmp_conffile);


    if (fd == -1) {
        serverLog(LL_WARNING, "Could not create tmp config file (%s)", strerror(errno));
        return retval;
    }

    while (offset < sdslen(content)) {
         written_bytes = write(fd, content + offset, sdslen(content) - offset);
         if (written_bytes <= 0) {
             if (errno == EINTR) continue; 
             serverLog(LL_WARNING, "Failed after writing (%zd) bytes to tmp config file (%s)", offset, strerror(errno));
             goto cleanup;
         }
         offset+=written_bytes;
    }

    if (fsync(fd))
        serverLog(LL_WARNING, "Could not sync tmp config file to disk (%s)", strerror(errno));
    else if (fchmod(fd, 0644 & ~server.umask) == -1)
        serverLog(LL_WARNING, "Could not chmod config file (%s)", strerror(errno));
    else if (rename(tmp_conffile, configfile) == -1)
        serverLog(LL_WARNING, "Could not rename tmp config file (%s)", strerror(errno));
    else {
        retval = 0;
        serverLog(LL_DEBUG, "Rewritten config file (%s) successfully", configfile);
    }

cleanup:
    close(fd);
    if (retval) unlink(tmp_conffile);
    return retval;
}


int rewriteConfig(char *path, int force_all) {
    struct rewriteConfigState *state;
    sds newcontent;
    int retval;

    
    if ((state = rewriteConfigReadOldFile(path)) == NULL) return -1;
    if (force_all) state->force_all = 1;

    

    
    for (standardConfig *config = configs; config->name != NULL; config++) {
        config->interface.rewrite(config->data, config->name, state);
    }

    rewriteConfigBindOption(state);
    rewriteConfigOctalOption(state,"unixsocketperm",server.unixsocketperm,CONFIG_DEFAULT_UNIX_SOCKET_PERM);
    rewriteConfigStringOption(state,"logfile",server.logfile,CONFIG_DEFAULT_LOGFILE);
    rewriteConfigSaveOption(state);
    rewriteConfigUserOption(state);
    rewriteConfigDirOption(state);
    rewriteConfigSlaveofOption(state,"replicaof");
    rewriteConfigRequirepassOption(state,"requirepass");
    rewriteConfigBytesOption(state,"client-query-buffer-limit",server.client_max_querybuf_len,PROTO_MAX_QUERYBUF_LEN);
    rewriteConfigStringOption(state,"cluster-config-file",server.cluster_configfile,CONFIG_DEFAULT_CLUSTER_CONFIG_FILE);
    rewriteConfigNotifykeyspaceeventsOption(state);
    rewriteConfigClientoutputbufferlimitOption(state);
    rewriteConfigOOMScoreAdjValuesOption(state);

    
    if (server.sentinel_mode) rewriteConfigSentinelOption(state);

    
    rewriteConfigRemoveOrphaned(state);

    
    newcontent = rewriteConfigGetContentFromState(state);
    retval = rewriteConfigOverwriteFile(server.configfile,newcontent);

    sdsfree(newcontent);
    rewriteConfigReleaseState(state);
    return retval;
}



static char loadbuf[LOADBUF_SIZE];

















static void boolConfigInit(typeData data) {
    *data.yesno.config = data.yesno.default_value;
}

static int boolConfigSet(typeData data, sds value, int update, char **err) {
    int yn = yesnotoi(value);
    if (yn == -1) {
        *err = "argument must be 'yes' or 'no'";
        return 0;
    }
    if (data.yesno.is_valid_fn && !data.yesno.is_valid_fn(yn, err))
        return 0;
    int prev = *(data.yesno.config);
    *(data.yesno.config) = yn;
    if (update && data.yesno.update_fn && !data.yesno.update_fn(yn, prev, err)) {
        *(data.yesno.config) = prev;
        return 0;
    }
    return 1;
}

static void boolConfigGet(client *c, typeData data) {
    addReplyBulkCString(c, *data.yesno.config ? "yes" : "no");
}

static void boolConfigRewrite(typeData data, const char *name, struct rewriteConfigState *state) {
    rewriteConfigYesNoOption(state, name,*(data.yesno.config), data.yesno.default_value);
}












static void stringConfigInit(typeData data) {
    if (data.string.convert_empty_to_null) {
        *data.string.config = data.string.default_value ? zstrdup(data.string.default_value) : NULL;
    } else {
        *data.string.config = zstrdup(data.string.default_value);
    }
}

static int stringConfigSet(typeData data, sds value, int update, char **err) {
    if (data.string.is_valid_fn && !data.string.is_valid_fn(value, err))
        return 0;
    char *prev = *data.string.config;
    if (data.string.convert_empty_to_null) {
        *data.string.config = value[0] ? zstrdup(value) : NULL;
    } else {
        *data.string.config = zstrdup(value);
    }
    if (update && data.string.update_fn && !data.string.update_fn(*data.string.config, prev, err)) {
        zfree(*data.string.config);
        *data.string.config = prev;
        return 0;
    }
    zfree(prev);
    return 1;
}

static void stringConfigGet(client *c, typeData data) {
    addReplyBulkCString(c, *data.string.config ? *data.string.config : "");
}

static void stringConfigRewrite(typeData data, const char *name, struct rewriteConfigState *state) {
    rewriteConfigStringOption(state, name,*(data.string.config), data.string.default_value);
}
















static void enumConfigInit(typeData data) {
    *data.enumd.config = data.enumd.default_value;
}

static int enumConfigSet(typeData data, sds value, int update, char **err) {
    int enumval = configEnumGetValue(data.enumd.enum_value, value);
    if (enumval == INT_MIN) {
        sds enumerr = sdsnew("argument must be one of the following: ");
        configEnum *enumNode = data.enumd.enum_value;
        while(enumNode->name != NULL) {
            enumerr = sdscatlen(enumerr, enumNode->name, strlen(enumNode->name));
            enumerr = sdscatlen(enumerr, ", ", 2);
            enumNode++;
        }
        sdsrange(enumerr,0,-3); 

        strncpy(loadbuf, enumerr, LOADBUF_SIZE);
        loadbuf[LOADBUF_SIZE - 1] = '\0';

        sdsfree(enumerr);
        *err = loadbuf;
        return 0;
    }
    if (data.enumd.is_valid_fn && !data.enumd.is_valid_fn(enumval, err))
        return 0;
    int prev = *(data.enumd.config);
    *(data.enumd.config) = enumval;
    if (update && data.enumd.update_fn && !data.enumd.update_fn(enumval, prev, err)) {
        *(data.enumd.config) = prev;
        return 0;
    }
    return 1;
}

static void enumConfigGet(client *c, typeData data) {
    addReplyBulkCString(c, configEnumGetNameOrUnknown(data.enumd.enum_value,*data.enumd.config));
}

static void enumConfigRewrite(typeData data, const char *name, struct rewriteConfigState *state) {
    rewriteConfigEnumOption(state, name,*(data.enumd.config), data.enumd.enum_value, data.enumd.default_value);
}



























































static void numericConfigInit(typeData data) {
    SET_NUMERIC_TYPE(data.numeric.default_value)
}

static int numericBoundaryCheck(typeData data, long long ll, char **err) {
    if (data.numeric.numeric_type == NUMERIC_TYPE_ULONG_LONG || data.numeric.numeric_type == NUMERIC_TYPE_UINT || data.numeric.numeric_type == NUMERIC_TYPE_SIZE_T) {

        
        unsigned long long ull = ll;
        unsigned long long upper_bound = data.numeric.upper_bound;
        unsigned long long lower_bound = data.numeric.lower_bound;
        if (ull > upper_bound || ull < lower_bound) {
            snprintf(loadbuf, LOADBUF_SIZE, "argument must be between %llu and %llu inclusive", lower_bound, upper_bound);


            *err = loadbuf;
            return 0;
        }
    } else {
        
        if (ll > data.numeric.upper_bound || ll < data.numeric.lower_bound) {
            snprintf(loadbuf, LOADBUF_SIZE, "argument must be between %lld and %lld inclusive", data.numeric.lower_bound, data.numeric.upper_bound);


            *err = loadbuf;
            return 0;
        }
    }
    return 1;
}

static int numericConfigSet(typeData data, sds value, int update, char **err) {
    long long ll, prev = 0;
    if (data.numeric.is_memory) {
        int memerr;
        ll = memtoll(value, &memerr);
        if (memerr || ll < 0) {
            *err = "argument must be a memory value";
            return 0;
        }
    } else {
        if (!string2ll(value, sdslen(value),&ll)) {
            *err = "argument couldn't be parsed into an integer" ;
            return 0;
        }
    }

    if (!numericBoundaryCheck(data, ll, err))
        return 0;

    if (data.numeric.is_valid_fn && !data.numeric.is_valid_fn(ll, err))
        return 0;

    GET_NUMERIC_TYPE(prev)
    SET_NUMERIC_TYPE(ll)

    if (update && data.numeric.update_fn && !data.numeric.update_fn(ll, prev, err)) {
        SET_NUMERIC_TYPE(prev)
        return 0;
    }
    return 1;
}

static void numericConfigGet(client *c, typeData data) {
    char buf[128];
    long long value = 0;

    GET_NUMERIC_TYPE(value)

    ll2string(buf, sizeof(buf), value);
    addReplyBulkCString(c, buf);
}

static void numericConfigRewrite(typeData data, const char *name, struct rewriteConfigState *state) {
    long long value = 0;

    GET_NUMERIC_TYPE(value)

    if (data.numeric.is_memory) {
        rewriteConfigBytesOption(state, name, value, data.numeric.default_value);
    } else {
        rewriteConfigNumericalOption(state, name, value, data.numeric.default_value);
    }
}










































































static int isValidActiveDefrag(int val, char **err) {

    if (val) {
        *err = "Active defragmentation cannot be enabled: it " "requires a Redis server compiled with a modified Jemalloc " "like the one shipped by default with the Redis source " "distribution";


        return 0;
    }

    UNUSED(val);
    UNUSED(err);

    return 1;
}

static int isValidDBfilename(char *val, char **err) {
    if (!pathIsBaseName(val)) {
        *err = "dbfilename can't be a path, just a filename";
        return 0;
    }
    return 1;
}

static int isValidAOFfilename(char *val, char **err) {
    if (!pathIsBaseName(val)) {
        *err = "appendfilename can't be a path, just a filename";
        return 0;
    }
    return 1;
}

static int updateHZ(long long val, long long prev, char **err) {
    UNUSED(prev);
    UNUSED(err);
    
    server.config_hz = val;
    if (server.config_hz < CONFIG_MIN_HZ) server.config_hz = CONFIG_MIN_HZ;
    if (server.config_hz > CONFIG_MAX_HZ) server.config_hz = CONFIG_MAX_HZ;
    server.hz = server.config_hz;
    return 1;
}

static int updateJemallocBgThread(int val, int prev, char **err) {
    UNUSED(prev);
    UNUSED(err);
    set_jemalloc_bg_thread(val);
    return 1;
}

static int updateReplBacklogSize(long long val, long long prev, char **err) {
    
    UNUSED(err);
    server.repl_backlog_size = prev;
    resizeReplicationBacklog(val);
    return 1;
}

static int updateMaxmemory(long long val, long long prev, char **err) {
    UNUSED(prev);
    UNUSED(err);
    if (val) {
        size_t used = zmalloc_used_memory()-freeMemoryGetNotCountedMemory();
        if ((unsigned long long)val < used) {
            serverLog(LL_WARNING,"WARNING: the new maxmemory value set via CONFIG SET (%llu) is smaller than the current memory usage (%zu). This will result in key eviction and/or the inability to accept new write commands depending on the maxmemory-policy.", server.maxmemory, used);
        }
        freeMemoryIfNeededAndSafe();
    }
    return 1;
}

static int updateGoodSlaves(long long val, long long prev, char **err) {
    UNUSED(val);
    UNUSED(prev);
    UNUSED(err);
    refreshGoodSlavesCount();
    return 1;
}

static int updateAppendonly(int val, int prev, char **err) {
    UNUSED(prev);
    if (val == 0 && server.aof_state != AOF_OFF) {
        stopAppendOnly();
    } else if (val && server.aof_state == AOF_OFF) {
        if (startAppendOnly() == C_ERR) {
            *err = "Unable to turn on AOF. Check server logs.";
            return 0;
        }
    }
    return 1;
}

static int updateMaxclients(long long val, long long prev, char **err) {
    
    if (val > prev) {
        adjustOpenFilesLimit();
        if (server.maxclients != val) {
            static char msg[128];
            sprintf(msg, "The operating system is not able to handle the specified number of clients, try with %d", server.maxclients);
            *err = msg;
            if (server.maxclients > prev) {
                server.maxclients = prev;
                adjustOpenFilesLimit();
            }
            return 0;
        }
        if ((unsigned int) aeGetSetSize(server.el) < server.maxclients + CONFIG_FDSET_INCR)
        {
            if (aeResizeSetSize(server.el, server.maxclients + CONFIG_FDSET_INCR) == AE_ERR)
            {
                *err = "The event loop API used by Redis is not able to handle the specified number of clients";
                return 0;
            }
        }
    }
    return 1;
}

static int updateOOMScoreAdj(int val, int prev, char **err) {
    UNUSED(prev);

    if (val) {
        if (setOOMScoreAdj(-1) == C_ERR) {
            *err = "Failed to set current oom_score_adj. Check server logs.";
            return 0;
        }
    }

    return 1;
}


static int updateTlsCfg(char *val, char *prev, char **err) {
    UNUSED(val);
    UNUSED(prev);
    UNUSED(err);

    
    if ((server.tls_port || server.tls_replication || server.tls_cluster)
            && tlsConfigure(&server.tls_ctx_config) == C_ERR) {
        *err = "Unable to update TLS configuration. Check server logs.";
        return 0;
    }
    return 1;
}
static int updateTlsCfgBool(int val, int prev, char **err) {
    UNUSED(val);
    UNUSED(prev);
    return updateTlsCfg(NULL, NULL, err);
}

static int updateTlsCfgInt(long long val, long long prev, char **err) {
    UNUSED(val);
    UNUSED(prev);
    return updateTlsCfg(NULL, NULL, err);
}


standardConfig configs[] = {
    
    createBoolConfig("rdbchecksum", NULL, IMMUTABLE_CONFIG, server.rdb_checksum, 1, NULL, NULL), createBoolConfig("daemonize", NULL, IMMUTABLE_CONFIG, server.daemonize, 0, NULL, NULL), createBoolConfig("io-threads-do-reads", NULL, IMMUTABLE_CONFIG, server.io_threads_do_reads, 0,NULL, NULL), createBoolConfig("lua-replicate-commands", NULL, MODIFIABLE_CONFIG, server.lua_always_replicate_commands, 1, NULL, NULL), createBoolConfig("always-show-logo", NULL, IMMUTABLE_CONFIG, server.always_show_logo, 0, NULL, NULL), createBoolConfig("protected-mode", NULL, MODIFIABLE_CONFIG, server.protected_mode, 1, NULL, NULL), createBoolConfig("rdbcompression", NULL, MODIFIABLE_CONFIG, server.rdb_compression, 1, NULL, NULL), createBoolConfig("rdb-del-sync-files", NULL, MODIFIABLE_CONFIG, server.rdb_del_sync_files, 0, NULL, NULL), createBoolConfig("activerehashing", NULL, MODIFIABLE_CONFIG, server.activerehashing, 1, NULL, NULL), createBoolConfig("stop-writes-on-bgsave-error", NULL, MODIFIABLE_CONFIG, server.stop_writes_on_bgsave_err, 1, NULL, NULL), createBoolConfig("dynamic-hz", NULL, MODIFIABLE_CONFIG, server.dynamic_hz, 1, NULL, NULL), createBoolConfig("lazyfree-lazy-eviction", NULL, MODIFIABLE_CONFIG, server.lazyfree_lazy_eviction, 0, NULL, NULL), createBoolConfig("lazyfree-lazy-expire", NULL, MODIFIABLE_CONFIG, server.lazyfree_lazy_expire, 0, NULL, NULL), createBoolConfig("lazyfree-lazy-server-del", NULL, MODIFIABLE_CONFIG, server.lazyfree_lazy_server_del, 0, NULL, NULL), createBoolConfig("lazyfree-lazy-user-del", NULL, MODIFIABLE_CONFIG, server.lazyfree_lazy_user_del , 0, NULL, NULL), createBoolConfig("repl-disable-tcp-nodelay", NULL, MODIFIABLE_CONFIG, server.repl_disable_tcp_nodelay, 0, NULL, NULL), createBoolConfig("repl-diskless-sync", NULL, MODIFIABLE_CONFIG, server.repl_diskless_sync, 0, NULL, NULL), createBoolConfig("gopher-enabled", NULL, MODIFIABLE_CONFIG, server.gopher_enabled, 0, NULL, NULL), createBoolConfig("aof-rewrite-incremental-fsync", NULL, MODIFIABLE_CONFIG, server.aof_rewrite_incremental_fsync, 1, NULL, NULL), createBoolConfig("no-appendfsync-on-rewrite", NULL, MODIFIABLE_CONFIG, server.aof_no_fsync_on_rewrite, 0, NULL, NULL), createBoolConfig("cluster-require-full-coverage", NULL, MODIFIABLE_CONFIG, server.cluster_require_full_coverage, 1, NULL, NULL), createBoolConfig("rdb-save-incremental-fsync", NULL, MODIFIABLE_CONFIG, server.rdb_save_incremental_fsync, 1, NULL, NULL), createBoolConfig("aof-load-truncated", NULL, MODIFIABLE_CONFIG, server.aof_load_truncated, 1, NULL, NULL), createBoolConfig("aof-use-rdb-preamble", NULL, MODIFIABLE_CONFIG, server.aof_use_rdb_preamble, 1, NULL, NULL), createBoolConfig("cluster-replica-no-failover", "cluster-slave-no-failover", MODIFIABLE_CONFIG, server.cluster_slave_no_failover, 0, NULL, NULL), createBoolConfig("replica-lazy-flush", "slave-lazy-flush", MODIFIABLE_CONFIG, server.repl_slave_lazy_flush, 0, NULL, NULL), createBoolConfig("replica-serve-stale-data", "slave-serve-stale-data", MODIFIABLE_CONFIG, server.repl_serve_stale_data, 1, NULL, NULL), createBoolConfig("replica-read-only", "slave-read-only", MODIFIABLE_CONFIG, server.repl_slave_ro, 1, NULL, NULL), createBoolConfig("replica-ignore-maxmemory", "slave-ignore-maxmemory", MODIFIABLE_CONFIG, server.repl_slave_ignore_maxmemory, 1, NULL, NULL), createBoolConfig("jemalloc-bg-thread", NULL, MODIFIABLE_CONFIG, server.jemalloc_bg_thread, 1, NULL, updateJemallocBgThread), createBoolConfig("activedefrag", NULL, MODIFIABLE_CONFIG, server.active_defrag_enabled, 0, isValidActiveDefrag, NULL), createBoolConfig("syslog-enabled", NULL, IMMUTABLE_CONFIG, server.syslog_enabled, 0, NULL, NULL), createBoolConfig("cluster-enabled", NULL, IMMUTABLE_CONFIG, server.cluster_enabled, 0, NULL, NULL), createBoolConfig("appendonly", NULL, MODIFIABLE_CONFIG, server.aof_enabled, 0, NULL, updateAppendonly), createBoolConfig("cluster-allow-reads-when-down", NULL, MODIFIABLE_CONFIG, server.cluster_allow_reads_when_down, 0, NULL, NULL),   createStringConfig("aclfile", NULL, IMMUTABLE_CONFIG, ALLOW_EMPTY_STRING, server.acl_filename, "", NULL, NULL), createStringConfig("unixsocket", NULL, IMMUTABLE_CONFIG, EMPTY_STRING_IS_NULL, server.unixsocket, NULL, NULL, NULL), createStringConfig("pidfile", NULL, IMMUTABLE_CONFIG, EMPTY_STRING_IS_NULL, server.pidfile, NULL, NULL, NULL), createStringConfig("replica-announce-ip", "slave-announce-ip", MODIFIABLE_CONFIG, EMPTY_STRING_IS_NULL, server.slave_announce_ip, NULL, NULL, NULL), createStringConfig("masteruser", NULL, MODIFIABLE_CONFIG, EMPTY_STRING_IS_NULL, server.masteruser, NULL, NULL, NULL), createStringConfig("masterauth", NULL, MODIFIABLE_CONFIG, EMPTY_STRING_IS_NULL, server.masterauth, NULL, NULL, NULL), createStringConfig("cluster-announce-ip", NULL, MODIFIABLE_CONFIG, EMPTY_STRING_IS_NULL, server.cluster_announce_ip, NULL, NULL, NULL), createStringConfig("syslog-ident", NULL, IMMUTABLE_CONFIG, ALLOW_EMPTY_STRING, server.syslog_ident, "redis", NULL, NULL), createStringConfig("dbfilename", NULL, MODIFIABLE_CONFIG, ALLOW_EMPTY_STRING, server.rdb_filename, "dump.rdb", isValidDBfilename, NULL), createStringConfig("appendfilename", NULL, IMMUTABLE_CONFIG, ALLOW_EMPTY_STRING, server.aof_filename, "appendonly.aof", isValidAOFfilename, NULL), createStringConfig("server_cpulist", NULL, IMMUTABLE_CONFIG, EMPTY_STRING_IS_NULL, server.server_cpulist, NULL, NULL, NULL), createStringConfig("bio_cpulist", NULL, IMMUTABLE_CONFIG, EMPTY_STRING_IS_NULL, server.bio_cpulist, NULL, NULL, NULL), createStringConfig("aof_rewrite_cpulist", NULL, IMMUTABLE_CONFIG, EMPTY_STRING_IS_NULL, server.aof_rewrite_cpulist, NULL, NULL, NULL), createStringConfig("bgsave_cpulist", NULL, IMMUTABLE_CONFIG, EMPTY_STRING_IS_NULL, server.bgsave_cpulist, NULL, NULL, NULL), createStringConfig("ignore-warnings", NULL, MODIFIABLE_CONFIG, ALLOW_EMPTY_STRING, server.ignore_warnings, "ARM64-COW-BUG", NULL, NULL),   createEnumConfig("supervised", NULL, IMMUTABLE_CONFIG, supervised_mode_enum, server.supervised_mode, SUPERVISED_NONE, NULL, NULL), createEnumConfig("syslog-facility", NULL, IMMUTABLE_CONFIG, syslog_facility_enum, server.syslog_facility, LOG_LOCAL0, NULL, NULL), createEnumConfig("repl-diskless-load", NULL, MODIFIABLE_CONFIG, repl_diskless_load_enum, server.repl_diskless_load, REPL_DISKLESS_LOAD_DISABLED, NULL, NULL), createEnumConfig("loglevel", NULL, MODIFIABLE_CONFIG, loglevel_enum, server.verbosity, LL_NOTICE, NULL, NULL), createEnumConfig("maxmemory-policy", NULL, MODIFIABLE_CONFIG, maxmemory_policy_enum, server.maxmemory_policy, MAXMEMORY_NO_EVICTION, NULL, NULL), createEnumConfig("appendfsync", NULL, MODIFIABLE_CONFIG, aof_fsync_enum, server.aof_fsync, AOF_FSYNC_EVERYSEC, NULL, NULL), createEnumConfig("oom-score-adj", NULL, MODIFIABLE_CONFIG, oom_score_adj_enum, server.oom_score_adj, OOM_SCORE_ADJ_NO, NULL, updateOOMScoreAdj),   createIntConfig("databases", NULL, IMMUTABLE_CONFIG, 1, INT_MAX, server.dbnum, 16, INTEGER_CONFIG, NULL, NULL), createIntConfig("port", NULL, IMMUTABLE_CONFIG, 0, 65535, server.port, 6379, INTEGER_CONFIG, NULL, NULL), createIntConfig("io-threads", NULL, IMMUTABLE_CONFIG, 1, 128, server.io_threads_num, 1, INTEGER_CONFIG, NULL, NULL), createIntConfig("auto-aof-rewrite-percentage", NULL, MODIFIABLE_CONFIG, 0, INT_MAX, server.aof_rewrite_perc, 100, INTEGER_CONFIG, NULL, NULL), createIntConfig("cluster-replica-validity-factor", "cluster-slave-validity-factor", MODIFIABLE_CONFIG, 0, INT_MAX, server.cluster_slave_validity_factor, 10, INTEGER_CONFIG, NULL, NULL), createIntConfig("list-max-ziplist-size", NULL, MODIFIABLE_CONFIG, INT_MIN, INT_MAX, server.list_max_ziplist_size, -2, INTEGER_CONFIG, NULL, NULL), createIntConfig("tcp-keepalive", NULL, MODIFIABLE_CONFIG, 0, INT_MAX, server.tcpkeepalive, 300, INTEGER_CONFIG, NULL, NULL), createIntConfig("cluster-migration-barrier", NULL, MODIFIABLE_CONFIG, 0, INT_MAX, server.cluster_migration_barrier, 1, INTEGER_CONFIG, NULL, NULL), createIntConfig("active-defrag-cycle-min", NULL, MODIFIABLE_CONFIG, 1, 99, server.active_defrag_cycle_min, 1, INTEGER_CONFIG, NULL, NULL), createIntConfig("active-defrag-cycle-max", NULL, MODIFIABLE_CONFIG, 1, 99, server.active_defrag_cycle_max, 25, INTEGER_CONFIG, NULL, NULL), createIntConfig("active-defrag-threshold-lower", NULL, MODIFIABLE_CONFIG, 0, 1000, server.active_defrag_threshold_lower, 10, INTEGER_CONFIG, NULL, NULL), createIntConfig("active-defrag-threshold-upper", NULL, MODIFIABLE_CONFIG, 0, 1000, server.active_defrag_threshold_upper, 100, INTEGER_CONFIG, NULL, NULL), createIntConfig("lfu-log-factor", NULL, MODIFIABLE_CONFIG, 0, INT_MAX, server.lfu_log_factor, 10, INTEGER_CONFIG, NULL, NULL), createIntConfig("lfu-decay-time", NULL, MODIFIABLE_CONFIG, 0, INT_MAX, server.lfu_decay_time, 1, INTEGER_CONFIG, NULL, NULL), createIntConfig("replica-priority", "slave-priority", MODIFIABLE_CONFIG, 0, INT_MAX, server.slave_priority, 100, INTEGER_CONFIG, NULL, NULL), createIntConfig("repl-diskless-sync-delay", NULL, MODIFIABLE_CONFIG, 0, INT_MAX, server.repl_diskless_sync_delay, 5, INTEGER_CONFIG, NULL, NULL), createIntConfig("maxmemory-samples", NULL, MODIFIABLE_CONFIG, 1, INT_MAX, server.maxmemory_samples, 5, INTEGER_CONFIG, NULL, NULL), createIntConfig("timeout", NULL, MODIFIABLE_CONFIG, 0, INT_MAX, server.maxidletime, 0, INTEGER_CONFIG, NULL, NULL), createIntConfig("replica-announce-port", "slave-announce-port", MODIFIABLE_CONFIG, 0, 65535, server.slave_announce_port, 0, INTEGER_CONFIG, NULL, NULL), createIntConfig("tcp-backlog", NULL, IMMUTABLE_CONFIG, 0, INT_MAX, server.tcp_backlog, 511, INTEGER_CONFIG, NULL, NULL), createIntConfig("cluster-announce-bus-port", NULL, MODIFIABLE_CONFIG, 0, 65535, server.cluster_announce_bus_port, 0, INTEGER_CONFIG, NULL, NULL), createIntConfig("cluster-announce-port", NULL, MODIFIABLE_CONFIG, 0, 65535, server.cluster_announce_port, 0, INTEGER_CONFIG, NULL, NULL), createIntConfig("repl-timeout", NULL, MODIFIABLE_CONFIG, 1, INT_MAX, server.repl_timeout, 60, INTEGER_CONFIG, NULL, NULL), createIntConfig("repl-ping-replica-period", "repl-ping-slave-period", MODIFIABLE_CONFIG, 1, INT_MAX, server.repl_ping_slave_period, 10, INTEGER_CONFIG, NULL, NULL), createIntConfig("list-compress-depth", NULL, MODIFIABLE_CONFIG, 0, INT_MAX, server.list_compress_depth, 0, INTEGER_CONFIG, NULL, NULL), createIntConfig("rdb-key-save-delay", NULL, MODIFIABLE_CONFIG, 0, INT_MAX, server.rdb_key_save_delay, 0, INTEGER_CONFIG, NULL, NULL), createIntConfig("key-load-delay", NULL, MODIFIABLE_CONFIG, 0, INT_MAX, server.key_load_delay, 0, INTEGER_CONFIG, NULL, NULL), createIntConfig("active-expire-effort", NULL, MODIFIABLE_CONFIG, 1, 10, server.active_expire_effort, 1, INTEGER_CONFIG, NULL, NULL), createIntConfig("hz", NULL, MODIFIABLE_CONFIG, 0, INT_MAX, server.config_hz, CONFIG_DEFAULT_HZ, INTEGER_CONFIG, NULL, updateHZ), createIntConfig("min-replicas-to-write", "min-slaves-to-write", MODIFIABLE_CONFIG, 0, INT_MAX, server.repl_min_slaves_to_write, 0, INTEGER_CONFIG, NULL, updateGoodSlaves), createIntConfig("min-replicas-max-lag", "min-slaves-max-lag", MODIFIABLE_CONFIG, 0, INT_MAX, server.repl_min_slaves_max_lag, 10, INTEGER_CONFIG, NULL, updateGoodSlaves),   createUIntConfig("maxclients", NULL, MODIFIABLE_CONFIG, 1, UINT_MAX, server.maxclients, 10000, INTEGER_CONFIG, NULL, updateMaxclients),   createULongConfig("active-defrag-max-scan-fields", NULL, MODIFIABLE_CONFIG, 1, LONG_MAX, server.active_defrag_max_scan_fields, 1000, INTEGER_CONFIG, NULL, NULL), createULongConfig("slowlog-max-len", NULL, MODIFIABLE_CONFIG, 0, LONG_MAX, server.slowlog_max_len, 128, INTEGER_CONFIG, NULL, NULL), createULongConfig("acllog-max-len", NULL, MODIFIABLE_CONFIG, 0, LONG_MAX, server.acllog_max_len, 128, INTEGER_CONFIG, NULL, NULL),   createLongLongConfig("lua-time-limit", NULL, MODIFIABLE_CONFIG, 0, LONG_MAX, server.lua_time_limit, 5000, INTEGER_CONFIG, NULL, NULL), createLongLongConfig("cluster-node-timeout", NULL, MODIFIABLE_CONFIG, 0, LLONG_MAX, server.cluster_node_timeout, 15000, INTEGER_CONFIG, NULL, NULL), createLongLongConfig("slowlog-log-slower-than", NULL, MODIFIABLE_CONFIG, -1, LLONG_MAX, server.slowlog_log_slower_than, 10000, INTEGER_CONFIG, NULL, NULL), createLongLongConfig("latency-monitor-threshold", NULL, MODIFIABLE_CONFIG, 0, LLONG_MAX, server.latency_monitor_threshold, 0, INTEGER_CONFIG, NULL, NULL), createLongLongConfig("proto-max-bulk-len", NULL, MODIFIABLE_CONFIG, 1024*1024, LLONG_MAX, server.proto_max_bulk_len, 512ll*1024*1024, MEMORY_CONFIG, NULL, NULL), createLongLongConfig("stream-node-max-entries", NULL, MODIFIABLE_CONFIG, 0, LLONG_MAX, server.stream_node_max_entries, 100, INTEGER_CONFIG, NULL, NULL), createLongLongConfig("repl-backlog-size", NULL, MODIFIABLE_CONFIG, 1, LLONG_MAX, server.repl_backlog_size, 1024*1024, MEMORY_CONFIG, NULL, updateReplBacklogSize),   createULongLongConfig("maxmemory", NULL, MODIFIABLE_CONFIG, 0, ULLONG_MAX, server.maxmemory, 0, MEMORY_CONFIG, NULL, updateMaxmemory),   createSizeTConfig("hash-max-ziplist-entries", NULL, MODIFIABLE_CONFIG, 0, LONG_MAX, server.hash_max_ziplist_entries, 512, INTEGER_CONFIG, NULL, NULL), createSizeTConfig("set-max-intset-entries", NULL, MODIFIABLE_CONFIG, 0, LONG_MAX, server.set_max_intset_entries, 512, INTEGER_CONFIG, NULL, NULL), createSizeTConfig("zset-max-ziplist-entries", NULL, MODIFIABLE_CONFIG, 0, LONG_MAX, server.zset_max_ziplist_entries, 128, INTEGER_CONFIG, NULL, NULL), createSizeTConfig("active-defrag-ignore-bytes", NULL, MODIFIABLE_CONFIG, 1, LLONG_MAX, server.active_defrag_ignore_bytes, 100<<20, MEMORY_CONFIG, NULL, NULL), createSizeTConfig("hash-max-ziplist-value", NULL, MODIFIABLE_CONFIG, 0, LONG_MAX, server.hash_max_ziplist_value, 64, MEMORY_CONFIG, NULL, NULL), createSizeTConfig("stream-node-max-bytes", NULL, MODIFIABLE_CONFIG, 0, LONG_MAX, server.stream_node_max_bytes, 4096, MEMORY_CONFIG, NULL, NULL), createSizeTConfig("zset-max-ziplist-value", NULL, MODIFIABLE_CONFIG, 0, LONG_MAX, server.zset_max_ziplist_value, 64, MEMORY_CONFIG, NULL, NULL), createSizeTConfig("hll-sparse-max-bytes", NULL, MODIFIABLE_CONFIG, 0, LONG_MAX, server.hll_sparse_max_bytes, 3000, MEMORY_CONFIG, NULL, NULL), createSizeTConfig("tracking-table-max-keys", NULL, MODIFIABLE_CONFIG, 0, LONG_MAX, server.tracking_table_max_keys, 1000000, INTEGER_CONFIG, NULL, NULL),   createTimeTConfig("repl-backlog-ttl", NULL, MODIFIABLE_CONFIG, 0, LONG_MAX, server.repl_backlog_time_limit, 60*60, INTEGER_CONFIG, NULL, NULL), createOffTConfig("auto-aof-rewrite-min-size", NULL, MODIFIABLE_CONFIG, 0, LLONG_MAX, server.aof_rewrite_min_size, 64*1024*1024, MEMORY_CONFIG, NULL, NULL),   createIntConfig("tls-port", NULL, IMMUTABLE_CONFIG, 0, 65535, server.tls_port, 0, INTEGER_CONFIG, NULL, updateTlsCfgInt), createIntConfig("tls-session-cache-size", NULL, MODIFIABLE_CONFIG, 0, INT_MAX, server.tls_ctx_config.session_cache_size, 20*1024, INTEGER_CONFIG, NULL, updateTlsCfgInt), createIntConfig("tls-session-cache-timeout", NULL, MODIFIABLE_CONFIG, 0, INT_MAX, server.tls_ctx_config.session_cache_timeout, 300, INTEGER_CONFIG, NULL, updateTlsCfgInt), createBoolConfig("tls-cluster", NULL, MODIFIABLE_CONFIG, server.tls_cluster, 0, NULL, updateTlsCfgBool), createBoolConfig("tls-replication", NULL, MODIFIABLE_CONFIG, server.tls_replication, 0, NULL, updateTlsCfgBool), createEnumConfig("tls-auth-clients", NULL, MODIFIABLE_CONFIG, tls_auth_clients_enum, server.tls_auth_clients, TLS_CLIENT_AUTH_YES, NULL, NULL), createBoolConfig("tls-prefer-server-ciphers", NULL, MODIFIABLE_CONFIG, server.tls_ctx_config.prefer_server_ciphers, 0, NULL, updateTlsCfgBool), createBoolConfig("tls-session-caching", NULL, MODIFIABLE_CONFIG, server.tls_ctx_config.session_caching, 1, NULL, updateTlsCfgBool), createStringConfig("tls-cert-file", NULL, MODIFIABLE_CONFIG, EMPTY_STRING_IS_NULL, server.tls_ctx_config.cert_file, NULL, NULL, updateTlsCfg), createStringConfig("tls-key-file", NULL, MODIFIABLE_CONFIG, EMPTY_STRING_IS_NULL, server.tls_ctx_config.key_file, NULL, NULL, updateTlsCfg), createStringConfig("tls-dh-params-file", NULL, MODIFIABLE_CONFIG, EMPTY_STRING_IS_NULL, server.tls_ctx_config.dh_params_file, NULL, NULL, updateTlsCfg), createStringConfig("tls-ca-cert-file", NULL, MODIFIABLE_CONFIG, EMPTY_STRING_IS_NULL, server.tls_ctx_config.ca_cert_file, NULL, NULL, updateTlsCfg), createStringConfig("tls-ca-cert-dir", NULL, MODIFIABLE_CONFIG, EMPTY_STRING_IS_NULL, server.tls_ctx_config.ca_cert_dir, NULL, NULL, updateTlsCfg), createStringConfig("tls-protocols", NULL, MODIFIABLE_CONFIG, EMPTY_STRING_IS_NULL, server.tls_ctx_config.protocols, NULL, NULL, updateTlsCfg), createStringConfig("tls-ciphers", NULL, MODIFIABLE_CONFIG, EMPTY_STRING_IS_NULL, server.tls_ctx_config.ciphers, NULL, NULL, updateTlsCfg), createStringConfig("tls-ciphersuites", NULL, MODIFIABLE_CONFIG, EMPTY_STRING_IS_NULL, server.tls_ctx_config.ciphersuites, NULL, NULL, updateTlsCfg),    {NULL}





















































































































































};



void configCommand(client *c) {
    
    if (server.loading && strcasecmp(c->argv[1]->ptr,"get")) {
        addReplyError(c,"Only CONFIG GET is allowed during loading");
        return;
    }

    if (c->argc == 2 && !strcasecmp(c->argv[1]->ptr,"help")) {
        const char *help[] = {
"GET <pattern> -- Return parameters matching the glob-like <pattern> and their values.", "SET <parameter> <value> -- Set parameter to value.", "RESETSTAT -- Reset statistics reported by INFO.", "REWRITE -- Rewrite the configuration file.", NULL };




        addReplyHelp(c, help);
    } else if (!strcasecmp(c->argv[1]->ptr,"set") && c->argc == 4) {
        configSetCommand(c);
    } else if (!strcasecmp(c->argv[1]->ptr,"get") && c->argc == 3) {
        configGetCommand(c);
    } else if (!strcasecmp(c->argv[1]->ptr,"resetstat") && c->argc == 2) {
        resetServerStats();
        resetCommandTableStats();
        addReply(c,shared.ok);
    } else if (!strcasecmp(c->argv[1]->ptr,"rewrite") && c->argc == 2) {
        if (server.configfile == NULL) {
            addReplyError(c,"The server is running without a config file");
            return;
        }
        if (rewriteConfig(server.configfile, 0) == -1) {
            serverLog(LL_WARNING,"CONFIG REWRITE failed: %s", strerror(errno));
            addReplyErrorFormat(c,"Rewriting config file: %s", strerror(errno));
        } else {
            serverLog(LL_WARNING,"CONFIG REWRITE executed with success.");
            addReply(c,shared.ok);
        }
    } else {
        addReplySubcommandSyntaxError(c);
        return;
    }
}
