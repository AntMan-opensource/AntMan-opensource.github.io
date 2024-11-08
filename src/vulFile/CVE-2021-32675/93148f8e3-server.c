





































struct sharedObjectsStruct shared;



double R_Zero, R_PosInf, R_NegInf, R_Nan;




struct redisServer server; 



struct redisCommand redisCommandTable[] = {
    {"module",moduleCommand,-2, "admin no-script", 0,NULL,0,0,0,0,0,0},  {"get",getCommand,2, "read-only fast @string", 0,NULL,1,1,1,0,0,0},   {"set",setCommand,-3, "write use-memory @string", 0,NULL,1,1,1,0,0,0},  {"setnx",setnxCommand,3, "write use-memory fast @string", 0,NULL,1,1,1,0,0,0},  {"setex",setexCommand,4, "write use-memory @string", 0,NULL,1,1,1,0,0,0},  {"psetex",psetexCommand,4, "write use-memory @string", 0,NULL,1,1,1,0,0,0},  {"append",appendCommand,3, "write use-memory fast @string", 0,NULL,1,1,1,0,0,0},  {"strlen",strlenCommand,2, "read-only fast @string", 0,NULL,1,1,1,0,0,0},  {"del",delCommand,-2, "write @keyspace", 0,NULL,1,-1,1,0,0,0},  {"unlink",unlinkCommand,-2, "write fast @keyspace", 0,NULL,1,-1,1,0,0,0},  {"exists",existsCommand,-2, "read-only fast @keyspace", 0,NULL,1,-1,1,0,0,0},  {"setbit",setbitCommand,4, "write use-memory @bitmap", 0,NULL,1,1,1,0,0,0},  {"getbit",getbitCommand,3, "read-only fast @bitmap", 0,NULL,1,1,1,0,0,0},  {"bitfield",bitfieldCommand,-2, "write use-memory @bitmap", 0,NULL,1,1,1,0,0,0},  {"bitfield_ro",bitfieldroCommand,-2, "read-only fast @bitmap", 0,NULL,1,1,1,0,0,0},  {"setrange",setrangeCommand,4, "write use-memory @string", 0,NULL,1,1,1,0,0,0},  {"getrange",getrangeCommand,4, "read-only @string", 0,NULL,1,1,1,0,0,0},  {"substr",getrangeCommand,4, "read-only @string", 0,NULL,1,1,1,0,0,0},  {"incr",incrCommand,2, "write use-memory fast @string", 0,NULL,1,1,1,0,0,0},  {"decr",decrCommand,2, "write use-memory fast @string", 0,NULL,1,1,1,0,0,0},  {"mget",mgetCommand,-2, "read-only fast @string", 0,NULL,1,-1,1,0,0,0},  {"rpush",rpushCommand,-3, "write use-memory fast @list", 0,NULL,1,1,1,0,0,0},  {"lpush",lpushCommand,-3, "write use-memory fast @list", 0,NULL,1,1,1,0,0,0},  {"rpushx",rpushxCommand,-3, "write use-memory fast @list", 0,NULL,1,1,1,0,0,0},  {"lpushx",lpushxCommand,-3, "write use-memory fast @list", 0,NULL,1,1,1,0,0,0},  {"linsert",linsertCommand,5, "write use-memory @list", 0,NULL,1,1,1,0,0,0},  {"rpop",rpopCommand,2, "write fast @list", 0,NULL,1,1,1,0,0,0},  {"lpop",lpopCommand,2, "write fast @list", 0,NULL,1,1,1,0,0,0},  {"brpop",brpopCommand,-3, "write no-script @list @blocking", 0,NULL,1,-2,1,0,0,0},  {"brpoplpush",brpoplpushCommand,4, "write use-memory no-script @list @blocking", 0,NULL,1,2,1,0,0,0},  {"blpop",blpopCommand,-3, "write no-script @list @blocking", 0,NULL,1,-2,1,0,0,0},  {"llen",llenCommand,2, "read-only fast @list", 0,NULL,1,1,1,0,0,0},  {"lindex",lindexCommand,3, "read-only @list", 0,NULL,1,1,1,0,0,0},  {"lset",lsetCommand,4, "write use-memory @list", 0,NULL,1,1,1,0,0,0},  {"lrange",lrangeCommand,4, "read-only @list", 0,NULL,1,1,1,0,0,0},  {"ltrim",ltrimCommand,4, "write @list", 0,NULL,1,1,1,0,0,0},  {"lpos",lposCommand,-3, "read-only @list", 0,NULL,1,1,1,0,0,0},  {"lrem",lremCommand,4, "write @list", 0,NULL,1,1,1,0,0,0},  {"rpoplpush",rpoplpushCommand,3, "write use-memory @list", 0,NULL,1,2,1,0,0,0},  {"sadd",saddCommand,-3, "write use-memory fast @set", 0,NULL,1,1,1,0,0,0},  {"srem",sremCommand,-3, "write fast @set", 0,NULL,1,1,1,0,0,0},  {"smove",smoveCommand,4, "write fast @set", 0,NULL,1,2,1,0,0,0},  {"sismember",sismemberCommand,3, "read-only fast @set", 0,NULL,1,1,1,0,0,0},  {"scard",scardCommand,2, "read-only fast @set", 0,NULL,1,1,1,0,0,0},  {"spop",spopCommand,-2, "write random fast @set", 0,NULL,1,1,1,0,0,0},  {"srandmember",srandmemberCommand,-2, "read-only random @set", 0,NULL,1,1,1,0,0,0},  {"sinter",sinterCommand,-2, "read-only to-sort @set", 0,NULL,1,-1,1,0,0,0},  {"sinterstore",sinterstoreCommand,-3, "write use-memory @set", 0,NULL,1,-1,1,0,0,0},  {"sunion",sunionCommand,-2, "read-only to-sort @set", 0,NULL,1,-1,1,0,0,0},  {"sunionstore",sunionstoreCommand,-3, "write use-memory @set", 0,NULL,1,-1,1,0,0,0},  {"sdiff",sdiffCommand,-2, "read-only to-sort @set", 0,NULL,1,-1,1,0,0,0},  {"sdiffstore",sdiffstoreCommand,-3, "write use-memory @set", 0,NULL,1,-1,1,0,0,0},  {"smembers",sinterCommand,2, "read-only to-sort @set", 0,NULL,1,1,1,0,0,0},  {"sscan",sscanCommand,-3, "read-only random @set", 0,NULL,1,1,1,0,0,0},  {"zadd",zaddCommand,-4, "write use-memory fast @sortedset", 0,NULL,1,1,1,0,0,0},  {"zincrby",zincrbyCommand,4, "write use-memory fast @sortedset", 0,NULL,1,1,1,0,0,0},  {"zrem",zremCommand,-3, "write fast @sortedset", 0,NULL,1,1,1,0,0,0},  {"zremrangebyscore",zremrangebyscoreCommand,4, "write @sortedset", 0,NULL,1,1,1,0,0,0},  {"zremrangebyrank",zremrangebyrankCommand,4, "write @sortedset", 0,NULL,1,1,1,0,0,0},  {"zremrangebylex",zremrangebylexCommand,4, "write @sortedset", 0,NULL,1,1,1,0,0,0},  {"zunionstore",zunionstoreCommand,-4, "write use-memory @sortedset", 0,zunionInterGetKeys,1,1,1,0,0,0},  {"zinterstore",zinterstoreCommand,-4, "write use-memory @sortedset", 0,zunionInterGetKeys,1,1,1,0,0,0},  {"zrange",zrangeCommand,-4, "read-only @sortedset", 0,NULL,1,1,1,0,0,0},  {"zrangebyscore",zrangebyscoreCommand,-4, "read-only @sortedset", 0,NULL,1,1,1,0,0,0},  {"zrevrangebyscore",zrevrangebyscoreCommand,-4, "read-only @sortedset", 0,NULL,1,1,1,0,0,0},  {"zrangebylex",zrangebylexCommand,-4, "read-only @sortedset", 0,NULL,1,1,1,0,0,0},  {"zrevrangebylex",zrevrangebylexCommand,-4, "read-only @sortedset", 0,NULL,1,1,1,0,0,0},  {"zcount",zcountCommand,4, "read-only fast @sortedset", 0,NULL,1,1,1,0,0,0},  {"zlexcount",zlexcountCommand,4, "read-only fast @sortedset", 0,NULL,1,1,1,0,0,0},  {"zrevrange",zrevrangeCommand,-4, "read-only @sortedset", 0,NULL,1,1,1,0,0,0},  {"zcard",zcardCommand,2, "read-only fast @sortedset", 0,NULL,1,1,1,0,0,0},  {"zscore",zscoreCommand,3, "read-only fast @sortedset", 0,NULL,1,1,1,0,0,0},  {"zrank",zrankCommand,3, "read-only fast @sortedset", 0,NULL,1,1,1,0,0,0},  {"zrevrank",zrevrankCommand,3, "read-only fast @sortedset", 0,NULL,1,1,1,0,0,0},  {"zscan",zscanCommand,-3, "read-only random @sortedset", 0,NULL,1,1,1,0,0,0},  {"zpopmin",zpopminCommand,-2, "write fast @sortedset", 0,NULL,1,1,1,0,0,0},  {"zpopmax",zpopmaxCommand,-2, "write fast @sortedset", 0,NULL,1,1,1,0,0,0},  {"bzpopmin",bzpopminCommand,-3, "write no-script fast @sortedset @blocking", 0,NULL,1,-2,1,0,0,0},  {"bzpopmax",bzpopmaxCommand,-3, "write no-script fast @sortedset @blocking", 0,NULL,1,-2,1,0,0,0},  {"hset",hsetCommand,-4, "write use-memory fast @hash", 0,NULL,1,1,1,0,0,0},  {"hsetnx",hsetnxCommand,4, "write use-memory fast @hash", 0,NULL,1,1,1,0,0,0},  {"hget",hgetCommand,3, "read-only fast @hash", 0,NULL,1,1,1,0,0,0},  {"hmset",hsetCommand,-4, "write use-memory fast @hash", 0,NULL,1,1,1,0,0,0},  {"hmget",hmgetCommand,-3, "read-only fast @hash", 0,NULL,1,1,1,0,0,0},  {"hincrby",hincrbyCommand,4, "write use-memory fast @hash", 0,NULL,1,1,1,0,0,0},  {"hincrbyfloat",hincrbyfloatCommand,4, "write use-memory fast @hash", 0,NULL,1,1,1,0,0,0},  {"hdel",hdelCommand,-3, "write fast @hash", 0,NULL,1,1,1,0,0,0},  {"hlen",hlenCommand,2, "read-only fast @hash", 0,NULL,1,1,1,0,0,0},  {"hstrlen",hstrlenCommand,3, "read-only fast @hash", 0,NULL,1,1,1,0,0,0},  {"hkeys",hkeysCommand,2, "read-only to-sort @hash", 0,NULL,1,1,1,0,0,0},  {"hvals",hvalsCommand,2, "read-only to-sort @hash", 0,NULL,1,1,1,0,0,0},  {"hgetall",hgetallCommand,2, "read-only random @hash", 0,NULL,1,1,1,0,0,0},  {"hexists",hexistsCommand,3, "read-only fast @hash", 0,NULL,1,1,1,0,0,0},  {"hscan",hscanCommand,-3, "read-only random @hash", 0,NULL,1,1,1,0,0,0},  {"incrby",incrbyCommand,3, "write use-memory fast @string", 0,NULL,1,1,1,0,0,0},  {"decrby",decrbyCommand,3, "write use-memory fast @string", 0,NULL,1,1,1,0,0,0},  {"incrbyfloat",incrbyfloatCommand,3, "write use-memory fast @string", 0,NULL,1,1,1,0,0,0},  {"getset",getsetCommand,3, "write use-memory fast @string", 0,NULL,1,1,1,0,0,0},  {"mset",msetCommand,-3, "write use-memory @string", 0,NULL,1,-1,2,0,0,0},  {"msetnx",msetnxCommand,-3, "write use-memory @string", 0,NULL,1,-1,2,0,0,0},  {"randomkey",randomkeyCommand,1, "read-only random @keyspace", 0,NULL,0,0,0,0,0,0},  {"select",selectCommand,2, "ok-loading fast ok-stale @keyspace", 0,NULL,0,0,0,0,0,0},  {"swapdb",swapdbCommand,3, "write fast @keyspace @dangerous", 0,NULL,0,0,0,0,0,0},  {"move",moveCommand,3, "write fast @keyspace", 0,NULL,1,1,1,0,0,0},   {"rename",renameCommand,3, "write @keyspace", 0,NULL,1,2,1,0,0,0},  {"renamenx",renamenxCommand,3, "write fast @keyspace", 0,NULL,1,2,1,0,0,0},  {"expire",expireCommand,3, "write fast @keyspace", 0,NULL,1,1,1,0,0,0},  {"expireat",expireatCommand,3, "write fast @keyspace", 0,NULL,1,1,1,0,0,0},  {"pexpire",pexpireCommand,3, "write fast @keyspace", 0,NULL,1,1,1,0,0,0},  {"pexpireat",pexpireatCommand,3, "write fast @keyspace", 0,NULL,1,1,1,0,0,0},  {"keys",keysCommand,2, "read-only to-sort @keyspace @dangerous", 0,NULL,0,0,0,0,0,0},  {"scan",scanCommand,-2, "read-only random @keyspace", 0,NULL,0,0,0,0,0,0},  {"dbsize",dbsizeCommand,1, "read-only fast @keyspace", 0,NULL,0,0,0,0,0,0},  {"auth",authCommand,-2, "no-auth no-script ok-loading ok-stale fast no-monitor no-slowlog @connection", 0,NULL,0,0,0,0,0,0},   {"ping",pingCommand,-1, "ok-stale fast @connection", 0,NULL,0,0,0,0,0,0},  {"echo",echoCommand,2, "read-only fast @connection", 0,NULL,0,0,0,0,0,0},  {"save",saveCommand,1, "admin no-script", 0,NULL,0,0,0,0,0,0},  {"bgsave",bgsaveCommand,-1, "admin no-script", 0,NULL,0,0,0,0,0,0},  {"bgrewriteaof",bgrewriteaofCommand,1, "admin no-script", 0,NULL,0,0,0,0,0,0},  {"shutdown",shutdownCommand,-1, "admin no-script ok-loading ok-stale", 0,NULL,0,0,0,0,0,0},  {"lastsave",lastsaveCommand,1, "read-only random fast ok-loading ok-stale @admin @dangerous", 0,NULL,0,0,0,0,0,0},  {"type",typeCommand,2, "read-only fast @keyspace", 0,NULL,1,1,1,0,0,0},  {"multi",multiCommand,1, "no-script fast ok-loading ok-stale @transaction", 0,NULL,0,0,0,0,0,0},  {"exec",execCommand,1, "no-script no-monitor no-slowlog ok-loading ok-stale @transaction", 0,NULL,0,0,0,0,0,0},  {"discard",discardCommand,1, "no-script fast ok-loading ok-stale @transaction", 0,NULL,0,0,0,0,0,0},  {"sync",syncCommand,1, "admin no-script", 0,NULL,0,0,0,0,0,0},  {"psync",syncCommand,3, "admin no-script", 0,NULL,0,0,0,0,0,0},  {"replconf",replconfCommand,-1, "admin no-script ok-loading ok-stale", 0,NULL,0,0,0,0,0,0},  {"flushdb",flushdbCommand,-1, "write @keyspace @dangerous", 0,NULL,0,0,0,0,0,0},  {"flushall",flushallCommand,-1, "write @keyspace @dangerous", 0,NULL,0,0,0,0,0,0},  {"sort",sortCommand,-2, "write use-memory @list @set @sortedset @dangerous", 0,sortGetKeys,1,1,1,0,0,0},  {"info",infoCommand,-1, "ok-loading ok-stale random @dangerous", 0,NULL,0,0,0,0,0,0},  {"monitor",monitorCommand,1, "admin no-script ok-loading ok-stale", 0,NULL,0,0,0,0,0,0},  {"ttl",ttlCommand,2, "read-only fast random @keyspace", 0,NULL,1,1,1,0,0,0},  {"touch",touchCommand,-2, "read-only fast @keyspace", 0,NULL,1,-1,1,0,0,0},  {"pttl",pttlCommand,2, "read-only fast random @keyspace", 0,NULL,1,1,1,0,0,0},  {"persist",persistCommand,2, "write fast @keyspace", 0,NULL,1,1,1,0,0,0},  {"slaveof",replicaofCommand,3, "admin no-script ok-stale", 0,NULL,0,0,0,0,0,0},  {"replicaof",replicaofCommand,3, "admin no-script ok-stale", 0,NULL,0,0,0,0,0,0},  {"role",roleCommand,1, "ok-loading ok-stale no-script fast read-only @dangerous", 0,NULL,0,0,0,0,0,0},  {"debug",debugCommand,-2, "admin no-script ok-loading ok-stale", 0,NULL,0,0,0,0,0,0},  {"config",configCommand,-2, "admin ok-loading ok-stale no-script", 0,NULL,0,0,0,0,0,0},  {"subscribe",subscribeCommand,-2, "pub-sub no-script ok-loading ok-stale", 0,NULL,0,0,0,0,0,0},  {"unsubscribe",unsubscribeCommand,-1, "pub-sub no-script ok-loading ok-stale", 0,NULL,0,0,0,0,0,0},  {"psubscribe",psubscribeCommand,-2, "pub-sub no-script ok-loading ok-stale", 0,NULL,0,0,0,0,0,0},  {"punsubscribe",punsubscribeCommand,-1, "pub-sub no-script ok-loading ok-stale", 0,NULL,0,0,0,0,0,0},  {"publish",publishCommand,3, "pub-sub ok-loading ok-stale fast", 0,NULL,0,0,0,0,0,0},  {"pubsub",pubsubCommand,-2, "pub-sub ok-loading ok-stale random", 0,NULL,0,0,0,0,0,0},  {"watch",watchCommand,-2, "no-script fast ok-loading ok-stale @transaction", 0,NULL,1,-1,1,0,0,0},  {"unwatch",unwatchCommand,1, "no-script fast ok-loading ok-stale @transaction", 0,NULL,0,0,0,0,0,0},  {"cluster",clusterCommand,-2, "admin ok-stale random", 0,NULL,0,0,0,0,0,0},  {"restore",restoreCommand,-4, "write use-memory @keyspace @dangerous", 0,NULL,1,1,1,0,0,0},  {"restore-asking",restoreCommand,-4, "write use-memory cluster-asking @keyspace @dangerous", 0,NULL,1,1,1,0,0,0},  {"migrate",migrateCommand,-6, "write random @keyspace @dangerous", 0,migrateGetKeys,0,0,0,0,0,0},  {"asking",askingCommand,1, "fast @keyspace", 0,NULL,0,0,0,0,0,0},  {"readonly",readonlyCommand,1, "fast @keyspace", 0,NULL,0,0,0,0,0,0},  {"readwrite",readwriteCommand,1, "fast @keyspace", 0,NULL,0,0,0,0,0,0},  {"dump",dumpCommand,2, "read-only random @keyspace", 0,NULL,1,1,1,0,0,0},  {"object",objectCommand,-2, "read-only random @keyspace", 0,NULL,2,2,1,0,0,0},  {"memory",memoryCommand,-2, "random read-only", 0,memoryGetKeys,0,0,0,0,0,0},  {"client",clientCommand,-2, "admin no-script random ok-loading ok-stale @connection", 0,NULL,0,0,0,0,0,0},  {"hello",helloCommand,-2, "no-auth no-script fast no-monitor ok-loading ok-stale no-slowlog @connection", 0,NULL,0,0,0,0,0,0},   {"eval",evalCommand,-3, "no-script @scripting", 0,evalGetKeys,0,0,0,0,0,0},  {"evalsha",evalShaCommand,-3, "no-script @scripting", 0,evalGetKeys,0,0,0,0,0,0},  {"slowlog",slowlogCommand,-2, "admin random ok-loading ok-stale", 0,NULL,0,0,0,0,0,0},  {"script",scriptCommand,-2, "no-script @scripting", 0,NULL,0,0,0,0,0,0},  {"time",timeCommand,1, "read-only random fast ok-loading ok-stale", 0,NULL,0,0,0,0,0,0},  {"bitop",bitopCommand,-4, "write use-memory @bitmap", 0,NULL,2,-1,1,0,0,0},  {"bitcount",bitcountCommand,-2, "read-only @bitmap", 0,NULL,1,1,1,0,0,0},  {"bitpos",bitposCommand,-3, "read-only @bitmap", 0,NULL,1,1,1,0,0,0},  {"wait",waitCommand,3, "no-script @keyspace", 0,NULL,0,0,0,0,0,0},  {"command",commandCommand,-1, "ok-loading ok-stale random @connection", 0,NULL,0,0,0,0,0,0},  {"geoadd",geoaddCommand,-5, "write use-memory @geo", 0,NULL,1,1,1,0,0,0},   {"georadius",georadiusCommand,-6, "write use-memory @geo", 0,georadiusGetKeys,1,1,1,0,0,0},  {"georadius_ro",georadiusroCommand,-6, "read-only @geo", 0,NULL,1,1,1,0,0,0},  {"georadiusbymember",georadiusbymemberCommand,-5, "write use-memory @geo", 0,georadiusGetKeys,1,1,1,0,0,0},  {"georadiusbymember_ro",georadiusbymemberroCommand,-5, "read-only @geo", 0,NULL,1,1,1,0,0,0},  {"geohash",geohashCommand,-2, "read-only @geo", 0,NULL,1,1,1,0,0,0},  {"geopos",geoposCommand,-2, "read-only @geo", 0,NULL,1,1,1,0,0,0},  {"geodist",geodistCommand,-4, "read-only @geo", 0,NULL,1,1,1,0,0,0},  {"pfselftest",pfselftestCommand,1, "admin @hyperloglog", 0,NULL,0,0,0,0,0,0},  {"pfadd",pfaddCommand,-2, "write use-memory fast @hyperloglog", 0,NULL,1,1,1,0,0,0},   {"pfcount",pfcountCommand,-2, "read-only @hyperloglog", 0,NULL,1,-1,1,0,0,0},  {"pfmerge",pfmergeCommand,-2, "write use-memory @hyperloglog", 0,NULL,1,-1,1,0,0,0},  {"pfdebug",pfdebugCommand,-3, "admin write", 0,NULL,0,0,0,0,0,0},  {"xadd",xaddCommand,-5, "write use-memory fast random @stream", 0,NULL,1,1,1,0,0,0},  {"xrange",xrangeCommand,-4, "read-only @stream", 0,NULL,1,1,1,0,0,0},  {"xrevrange",xrevrangeCommand,-4, "read-only @stream", 0,NULL,1,1,1,0,0,0},  {"xlen",xlenCommand,2, "read-only fast @stream", 0,NULL,1,1,1,0,0,0},  {"xread",xreadCommand,-4, "read-only @stream @blocking", 0,xreadGetKeys,0,0,0,0,0,0},  {"xreadgroup",xreadCommand,-7, "write @stream @blocking", 0,xreadGetKeys,0,0,0,0,0,0},  {"xgroup",xgroupCommand,-2, "write use-memory @stream", 0,NULL,2,2,1,0,0,0},  {"xsetid",xsetidCommand,3, "write use-memory fast @stream", 0,NULL,1,1,1,0,0,0},  {"xack",xackCommand,-4, "write fast random @stream", 0,NULL,1,1,1,0,0,0},  {"xpending",xpendingCommand,-3, "read-only random @stream", 0,NULL,1,1,1,0,0,0},  {"xclaim",xclaimCommand,-6, "write random fast @stream", 0,NULL,1,1,1,0,0,0},  {"xinfo",xinfoCommand,-2, "read-only random @stream", 0,NULL,2,2,1,0,0,0},  {"xdel",xdelCommand,-3, "write fast @stream", 0,NULL,1,1,1,0,0,0},  {"xtrim",xtrimCommand,-2, "write random @stream", 0,NULL,1,1,1,0,0,0},  {"post",securityWarningCommand,-1, "ok-loading ok-stale read-only", 0,NULL,0,0,0,0,0,0},  {"host:",securityWarningCommand,-1, "ok-loading ok-stale read-only", 0,NULL,0,0,0,0,0,0},  {"latency",latencyCommand,-2, "admin no-script ok-loading ok-stale", 0,NULL,0,0,0,0,0,0},  {"lolwut",lolwutCommand,-1, "read-only fast", 0,NULL,0,0,0,0,0,0},  {"acl",aclCommand,-2, "admin no-script no-slowlog ok-loading ok-stale", 0,NULL,0,0,0,0,0,0},  {"stralgo",stralgoCommand,-2, "read-only @string", 0,lcsGetKeys,0,0,0,0,0,0}























































































































































































































































































































































































































































































































































































































































































































































































































































};




void nolocks_localtime(struct tm *tmp, time_t t, time_t tz, int dst);


void serverLogRaw(int level, const char *msg) {
    const int syslogLevelMap[] = { LOG_DEBUG, LOG_INFO, LOG_NOTICE, LOG_WARNING };
    const char *c = ".-*#";
    FILE *fp;
    char buf[64];
    int rawmode = (level & LL_RAW);
    int log_to_stdout = server.logfile[0] == '\0';

    level &= 0xff; 
    if (level < server.verbosity) return;

    fp = log_to_stdout ? stdout : fopen(server.logfile,"a");
    if (!fp) return;

    if (rawmode) {
        fprintf(fp,"%s",msg);
    } else {
        int off;
        struct timeval tv;
        int role_char;
        pid_t pid = getpid();

        gettimeofday(&tv,NULL);
        struct tm tm;
        nolocks_localtime(&tm,tv.tv_sec,server.timezone,server.daylight_active);
        off = strftime(buf,sizeof(buf),"%d %b %Y %H:%M:%S.",&tm);
        snprintf(buf+off,sizeof(buf)-off,"%03d",(int)tv.tv_usec/1000);
        if (server.sentinel_mode) {
            role_char = 'X'; 
        } else if (pid != server.pid) {
            role_char = 'C'; 
        } else {
            role_char = (server.masterhost ? 'S':'M'); 
        }
        fprintf(fp,"%d:%c %s %c %s\n", (int)getpid(),role_char, buf,c[level],msg);
    }
    fflush(fp);

    if (!log_to_stdout) fclose(fp);
    if (server.syslog_enabled) syslog(syslogLevelMap[level], "%s", msg);
}


void serverLog(int level, const char *fmt, ...) {
    va_list ap;
    char msg[LOG_MAX_LEN];

    if ((level&0xff) < server.verbosity) return;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    serverLogRaw(level,msg);
}


void serverLogFromHandler(int level, const char *msg) {
    int fd;
    int log_to_stdout = server.logfile[0] == '\0';
    char buf[64];

    if ((level&0xff) < server.verbosity || (log_to_stdout && server.daemonize))
        return;
    fd = log_to_stdout ? STDOUT_FILENO :
                         open(server.logfile, O_APPEND|O_CREAT|O_WRONLY, 0644);
    if (fd == -1) return;
    ll2string(buf,sizeof(buf),getpid());
    if (write(fd,buf,strlen(buf)) == -1) goto err;
    if (write(fd,":signal-handler (",17) == -1) goto err;
    ll2string(buf,sizeof(buf),time(NULL));
    if (write(fd,buf,strlen(buf)) == -1) goto err;
    if (write(fd,") ",2) == -1) goto err;
    if (write(fd,msg,strlen(msg)) == -1) goto err;
    if (write(fd,"\n",1) == -1) goto err;
err:
    if (!log_to_stdout) close(fd);
}


long long ustime(void) {
    struct timeval tv;
    long long ust;

    gettimeofday(&tv, NULL);
    ust = ((long long)tv.tv_sec)*1000000;
    ust += tv.tv_usec;
    return ust;
}


mstime_t mstime(void) {
    return ustime()/1000;
}


void exitFromChild(int retcode) {

    exit(retcode);

    _exit(retcode);

}





void dictVanillaFree(void *privdata, void *val)
{
    DICT_NOTUSED(privdata);
    zfree(val);
}

void dictListDestructor(void *privdata, void *val)
{
    DICT_NOTUSED(privdata);
    listRelease((list*)val);
}

int dictSdsKeyCompare(void *privdata, const void *key1, const void *key2)
{
    int l1,l2;
    DICT_NOTUSED(privdata);

    l1 = sdslen((sds)key1);
    l2 = sdslen((sds)key2);
    if (l1 != l2) return 0;
    return memcmp(key1, key2, l1) == 0;
}


int dictSdsKeyCaseCompare(void *privdata, const void *key1, const void *key2)
{
    DICT_NOTUSED(privdata);

    return strcasecmp(key1, key2) == 0;
}

void dictObjectDestructor(void *privdata, void *val)
{
    DICT_NOTUSED(privdata);

    if (val == NULL) return; 
    decrRefCount(val);
}

void dictSdsDestructor(void *privdata, void *val)
{
    DICT_NOTUSED(privdata);

    sdsfree(val);
}

int dictObjKeyCompare(void *privdata, const void *key1, const void *key2)
{
    const robj *o1 = key1, *o2 = key2;
    return dictSdsKeyCompare(privdata,o1->ptr,o2->ptr);
}

uint64_t dictObjHash(const void *key) {
    const robj *o = key;
    return dictGenHashFunction(o->ptr, sdslen((sds)o->ptr));
}

uint64_t dictSdsHash(const void *key) {
    return dictGenHashFunction((unsigned char*)key, sdslen((char*)key));
}

uint64_t dictSdsCaseHash(const void *key) {
    return dictGenCaseHashFunction((unsigned char*)key, sdslen((char*)key));
}

int dictEncObjKeyCompare(void *privdata, const void *key1, const void *key2)
{
    robj *o1 = (robj*) key1, *o2 = (robj*) key2;
    int cmp;

    if (o1->encoding == OBJ_ENCODING_INT && o2->encoding == OBJ_ENCODING_INT)
            return o1->ptr == o2->ptr;

    
    if (o1->refcount != OBJ_STATIC_REFCOUNT) o1 = getDecodedObject(o1);
    if (o2->refcount != OBJ_STATIC_REFCOUNT) o2 = getDecodedObject(o2);
    cmp = dictSdsKeyCompare(privdata,o1->ptr,o2->ptr);
    if (o1->refcount != OBJ_STATIC_REFCOUNT) decrRefCount(o1);
    if (o2->refcount != OBJ_STATIC_REFCOUNT) decrRefCount(o2);
    return cmp;
}

uint64_t dictEncObjHash(const void *key) {
    robj *o = (robj*) key;

    if (sdsEncodedObject(o)) {
        return dictGenHashFunction(o->ptr, sdslen((sds)o->ptr));
    } else {
        if (o->encoding == OBJ_ENCODING_INT) {
            char buf[32];
            int len;

            len = ll2string(buf,32,(long)o->ptr);
            return dictGenHashFunction((unsigned char*)buf, len);
        } else {
            uint64_t hash;

            o = getDecodedObject(o);
            hash = dictGenHashFunction(o->ptr, sdslen((sds)o->ptr));
            decrRefCount(o);
            return hash;
        }
    }
}


dictType objectKeyPointerValueDictType = {
    dictEncObjHash,             NULL, NULL, dictEncObjKeyCompare, dictObjectDestructor, NULL };







dictType objectKeyHeapPointerValueDictType = {
    dictEncObjHash,             NULL, NULL, dictEncObjKeyCompare, dictObjectDestructor, dictVanillaFree };







dictType setDictType = {
    dictSdsHash,                NULL, NULL, dictSdsKeyCompare, dictSdsDestructor, NULL };







dictType zsetDictType = {
    dictSdsHash,                NULL, NULL, dictSdsKeyCompare, NULL, NULL };







dictType dbDictType = {
    dictSdsHash,                 NULL, NULL, dictSdsKeyCompare, dictSdsDestructor, dictObjectDestructor };







dictType shaScriptObjectDictType = {
    dictSdsCaseHash,             NULL, NULL, dictSdsKeyCaseCompare, dictSdsDestructor, dictObjectDestructor };







dictType keyptrDictType = {
    dictSdsHash,                 NULL, NULL, dictSdsKeyCompare, NULL, NULL };







dictType commandTableDictType = {
    dictSdsCaseHash,             NULL, NULL, dictSdsKeyCaseCompare, dictSdsDestructor, NULL };







dictType hashDictType = {
    dictSdsHash,                 NULL, NULL, dictSdsKeyCompare, dictSdsDestructor, dictSdsDestructor };







dictType keylistDictType = {
    dictObjHash,                 NULL, NULL, dictObjKeyCompare, dictObjectDestructor, dictListDestructor };







dictType clusterNodesDictType = {
    dictSdsHash,                 NULL, NULL, dictSdsKeyCompare, dictSdsDestructor, NULL };







dictType clusterNodesBlackListDictType = {
    dictSdsCaseHash,             NULL, NULL, dictSdsKeyCaseCompare, dictSdsDestructor, NULL };







dictType modulesDictType = {
    dictSdsCaseHash,             NULL, NULL, dictSdsKeyCaseCompare, dictSdsDestructor, NULL };







dictType migrateCacheDictType = {
    dictSdsHash,                 NULL, NULL, dictSdsKeyCompare, dictSdsDestructor, NULL };







dictType replScriptCacheDictType = {
    dictSdsCaseHash,             NULL, NULL, dictSdsKeyCaseCompare, dictSdsDestructor, NULL };






int htNeedsResize(dict *dict) {
    long long size, used;

    size = dictSlots(dict);
    used = dictSize(dict);
    return (size > DICT_HT_INITIAL_SIZE && (used*100/size < HASHTABLE_MIN_FILL));
}


void tryResizeHashTables(int dbid) {
    if (htNeedsResize(server.db[dbid].dict))
        dictResize(server.db[dbid].dict);
    if (htNeedsResize(server.db[dbid].expires))
        dictResize(server.db[dbid].expires);
}


int incrementallyRehash(int dbid) {
    
    if (dictIsRehashing(server.db[dbid].dict)) {
        dictRehashMilliseconds(server.db[dbid].dict,1);
        return 1; 
    }
    
    if (dictIsRehashing(server.db[dbid].expires)) {
        dictRehashMilliseconds(server.db[dbid].expires,1);
        return 1; 
    }
    return 0;
}


void updateDictResizePolicy(void) {
    if (!hasActiveChildProcess())
        dictEnableResize();
    else dictDisableResize();
}


int hasActiveChildProcess() {
    return server.rdb_child_pid != -1 || server.aof_child_pid != -1 || server.module_child_pid != -1;

}


int allPersistenceDisabled(void) {
    return server.saveparamslen == 0 && server.aof_state == AOF_OFF;
}




void trackInstantaneousMetric(int metric, long long current_reading) {
    long long t = mstime() - server.inst_metric[metric].last_sample_time;
    long long ops = current_reading - server.inst_metric[metric].last_sample_count;
    long long ops_sec;

    ops_sec = t > 0 ? (ops*1000/t) : 0;

    server.inst_metric[metric].samples[server.inst_metric[metric].idx] = ops_sec;
    server.inst_metric[metric].idx++;
    server.inst_metric[metric].idx %= STATS_METRIC_SAMPLES;
    server.inst_metric[metric].last_sample_time = mstime();
    server.inst_metric[metric].last_sample_count = current_reading;
}


long long getInstantaneousMetric(int metric) {
    int j;
    long long sum = 0;

    for (j = 0; j < STATS_METRIC_SAMPLES; j++)
        sum += server.inst_metric[metric].samples[j];
    return sum / STATS_METRIC_SAMPLES;
}


int clientsCronResizeQueryBuffer(client *c) {
    size_t querybuf_size = sdsAllocSize(c->querybuf);
    time_t idletime = server.unixtime - c->lastinteraction;

    
    if (querybuf_size > PROTO_MBULK_BIG_ARG && ((querybuf_size/(c->querybuf_peak+1)) > 2 || idletime > 2))

    {
        
        if (sdsavail(c->querybuf) > 1024*4) {
            c->querybuf = sdsRemoveFreeSpace(c->querybuf);
        }
    }
    
    c->querybuf_peak = 0;

    
    if (c->flags & CLIENT_MASTER) {
        
        size_t pending_querybuf_size = sdsAllocSize(c->pending_querybuf);
        if(pending_querybuf_size > LIMIT_PENDING_QUERYBUF && sdslen(c->pending_querybuf) < (pending_querybuf_size/2))
        {
            c->pending_querybuf = sdsRemoveFreeSpace(c->pending_querybuf);
        }
    }
    return 0;
}



size_t ClientsPeakMemInput[CLIENTS_PEAK_MEM_USAGE_SLOTS];
size_t ClientsPeakMemOutput[CLIENTS_PEAK_MEM_USAGE_SLOTS];

int clientsCronTrackExpansiveClients(client *c) {
    size_t in_usage = sdsZmallocSize(c->querybuf) + c->argv_len_sum;
    size_t out_usage = getClientOutputBufferMemoryUsage(c);
    int i = server.unixtime % CLIENTS_PEAK_MEM_USAGE_SLOTS;
    int zeroidx = (i+1) % CLIENTS_PEAK_MEM_USAGE_SLOTS;

    
    ClientsPeakMemInput[zeroidx] = 0;
    ClientsPeakMemOutput[zeroidx] = 0;

    
    if (in_usage > ClientsPeakMemInput[i]) ClientsPeakMemInput[i] = in_usage;
    if (out_usage > ClientsPeakMemOutput[i]) ClientsPeakMemOutput[i] = out_usage;

    return 0; 
}


int clientsCronTrackClientsMemUsage(client *c) {
    size_t mem = 0;
    int type = getClientType(c);
    mem += getClientOutputBufferMemoryUsage(c);
    mem += sdsZmallocSize(c->querybuf);
    mem += zmalloc_size(c);
    mem += c->argv_len_sum;
    if (c->argv) mem += zmalloc_size(c->argv);
    
    server.stat_clients_type_memory[c->client_cron_last_memory_type] -= c->client_cron_last_memory_usage;
    server.stat_clients_type_memory[type] += mem;
    
    c->client_cron_last_memory_usage = mem;
    c->client_cron_last_memory_type = type;
    return 0;
}


void getExpansiveClientsInfo(size_t *in_usage, size_t *out_usage) {
    size_t i = 0, o = 0;
    for (int j = 0; j < CLIENTS_PEAK_MEM_USAGE_SLOTS; j++) {
        if (ClientsPeakMemInput[j] > i) i = ClientsPeakMemInput[j];
        if (ClientsPeakMemOutput[j] > o) o = ClientsPeakMemOutput[j];
    }
    *in_usage = i;
    *out_usage = o;
}



void clientsCron(void) {
    
    int numclients = listLength(server.clients);
    int iterations = numclients/server.hz;
    mstime_t now = mstime();

    
    if (iterations < CLIENTS_CRON_MIN_ITERATIONS)
        iterations = (numclients < CLIENTS_CRON_MIN_ITERATIONS) ? numclients : CLIENTS_CRON_MIN_ITERATIONS;

    while(listLength(server.clients) && iterations--) {
        client *c;
        listNode *head;

        
        listRotateTailToHead(server.clients);
        head = listFirst(server.clients);
        c = listNodeValue(head);
        
        if (clientsCronHandleTimeout(c,now)) continue;
        if (clientsCronResizeQueryBuffer(c)) continue;
        if (clientsCronTrackExpansiveClients(c)) continue;
        if (clientsCronTrackClientsMemUsage(c)) continue;
    }
}


void databasesCron(void) {
    
    if (server.active_expire_enabled) {
        if (iAmMaster()) {
            activeExpireCycle(ACTIVE_EXPIRE_CYCLE_SLOW);
        } else {
            expireSlaveKeys();
        }
    }

    
    activeDefragCycle();

    
    if (!hasActiveChildProcess()) {
        
        static unsigned int resize_db = 0;
        static unsigned int rehash_db = 0;
        int dbs_per_call = CRON_DBS_PER_CALL;
        int j;

        
        if (dbs_per_call > server.dbnum) dbs_per_call = server.dbnum;

        
        for (j = 0; j < dbs_per_call; j++) {
            tryResizeHashTables(resize_db % server.dbnum);
            resize_db++;
        }

        
        if (server.activerehashing) {
            for (j = 0; j < dbs_per_call; j++) {
                int work_done = incrementallyRehash(rehash_db);
                if (work_done) {
                    
                    break;
                } else {
                    
                    rehash_db++;
                    rehash_db %= server.dbnum;
                }
            }
        }
    }
}


void updateCachedTime(int update_daylight_info) {
    server.ustime = ustime();
    server.mstime = server.ustime / 1000;
    server.unixtime = server.mstime / 1000;

    
    if (update_daylight_info) {
        struct tm tm;
        time_t ut = server.unixtime;
        localtime_r(&ut,&tm);
        server.daylight_active = tm.tm_isdst;
    }
}

void checkChildrenDone(void) {
    int statloc;
    pid_t pid;

    if ((pid = wait3(&statloc,WNOHANG,NULL)) != 0) {
        int exitcode = WEXITSTATUS(statloc);
        int bysignal = 0;

        if (WIFSIGNALED(statloc)) bysignal = WTERMSIG(statloc);

        
        if (exitcode == SERVER_CHILD_NOERROR_RETVAL) {
            bysignal = SIGUSR1;
            exitcode = 1;
        }

        if (pid == -1) {
            serverLog(LL_WARNING,"wait3() returned an error: %s. " "rdb_child_pid = %d, aof_child_pid = %d, module_child_pid = %d", strerror(errno), (int) server.rdb_child_pid, (int) server.aof_child_pid, (int) server.module_child_pid);




        } else if (pid == server.rdb_child_pid) {
            backgroundSaveDoneHandler(exitcode,bysignal);
            if (!bysignal && exitcode == 0) receiveChildInfo();
        } else if (pid == server.aof_child_pid) {
            backgroundRewriteDoneHandler(exitcode,bysignal);
            if (!bysignal && exitcode == 0) receiveChildInfo();
        } else if (pid == server.module_child_pid) {
            ModuleForkDoneHandler(exitcode,bysignal);
            if (!bysignal && exitcode == 0) receiveChildInfo();
        } else {
            if (!ldbRemoveChild(pid)) {
                serverLog(LL_WARNING, "Warning, detected child with unmatched pid: %ld", (long)pid);

            }
        }
        updateDictResizePolicy();
        closeChildInfoPipe();
    }
}



int serverCron(struct aeEventLoop *eventLoop, long long id, void *clientData) {
    int j;
    UNUSED(eventLoop);
    UNUSED(id);
    UNUSED(clientData);

    
    if (server.watchdog_period) watchdogScheduleSignal(server.watchdog_period);

    
    updateCachedTime(1);

    server.hz = server.config_hz;
    
    if (server.dynamic_hz) {
        while (listLength(server.clients) / server.hz > MAX_CLIENTS_PER_CLOCK_TICK)
        {
            server.hz *= 2;
            if (server.hz > CONFIG_MAX_HZ) {
                server.hz = CONFIG_MAX_HZ;
                break;
            }
        }
    }

    run_with_period(100) {
        trackInstantaneousMetric(STATS_METRIC_COMMAND,server.stat_numcommands);
        trackInstantaneousMetric(STATS_METRIC_NET_INPUT, server.stat_net_input_bytes);
        trackInstantaneousMetric(STATS_METRIC_NET_OUTPUT, server.stat_net_output_bytes);
    }

    
    server.lruclock = getLRUClock();

    
    if (zmalloc_used_memory() > server.stat_peak_memory)
        server.stat_peak_memory = zmalloc_used_memory();

    run_with_period(100) {
        
        server.cron_malloc_stats.process_rss = zmalloc_get_rss();
        server.cron_malloc_stats.zmalloc_used = zmalloc_used_memory();
        
        zmalloc_get_allocator_info(&server.cron_malloc_stats.allocator_allocated, &server.cron_malloc_stats.allocator_active, &server.cron_malloc_stats.allocator_resident);

        
        if (!server.cron_malloc_stats.allocator_resident) {
            
            size_t lua_memory = lua_gc(server.lua,LUA_GCCOUNT,0)*1024LL;
            server.cron_malloc_stats.allocator_resident = server.cron_malloc_stats.process_rss - lua_memory;
        }
        if (!server.cron_malloc_stats.allocator_active)
            server.cron_malloc_stats.allocator_active = server.cron_malloc_stats.allocator_resident;
        if (!server.cron_malloc_stats.allocator_allocated)
            server.cron_malloc_stats.allocator_allocated = server.cron_malloc_stats.zmalloc_used;
    }

    
    if (server.shutdown_asap) {
        if (prepareForShutdown(SHUTDOWN_NOFLAGS) == C_OK) exit(0);
        serverLog(LL_WARNING,"SIGTERM received but errors trying to shut down the server, check the logs for more information");
        server.shutdown_asap = 0;
    }

    
    run_with_period(5000) {
        for (j = 0; j < server.dbnum; j++) {
            long long size, used, vkeys;

            size = dictSlots(server.db[j].dict);
            used = dictSize(server.db[j].dict);
            vkeys = dictSize(server.db[j].expires);
            if (used || vkeys) {
                serverLog(LL_VERBOSE,"DB %d: %lld keys (%lld volatile) in %lld slots HT.",j,used,vkeys,size);
                
            }
        }
    }

    
    if (!server.sentinel_mode) {
        run_with_period(5000) {
            serverLog(LL_DEBUG, "%lu clients connected (%lu replicas), %zu bytes in use", listLength(server.clients)-listLength(server.slaves), listLength(server.slaves), zmalloc_used_memory());



        }
    }

    
    clientsCron();

    
    databasesCron();

    
    if (!hasActiveChildProcess() && server.aof_rewrite_scheduled)
    {
        rewriteAppendOnlyFileBackground();
    }

    
    if (hasActiveChildProcess() || ldbPendingChildren())
    {
        checkChildrenDone();
    } else {
        
        for (j = 0; j < server.saveparamslen; j++) {
            struct saveparam *sp = server.saveparams+j;

            
            if (server.dirty >= sp->changes && server.unixtime-server.lastsave > sp->seconds && (server.unixtime-server.lastbgsave_try > CONFIG_BGSAVE_RETRY_DELAY || server.lastbgsave_status == C_OK))



            {
                serverLog(LL_NOTICE,"%d changes in %d seconds. Saving...", sp->changes, (int)sp->seconds);
                rdbSaveInfo rsi, *rsiptr;
                rsiptr = rdbPopulateSaveInfo(&rsi);
                rdbSaveBackground(server.rdb_filename,rsiptr);
                break;
            }
        }

        
        if (server.aof_state == AOF_ON && !hasActiveChildProcess() && server.aof_rewrite_perc && server.aof_current_size > server.aof_rewrite_min_size)


        {
            long long base = server.aof_rewrite_base_size ? server.aof_rewrite_base_size : 1;
            long long growth = (server.aof_current_size*100/base) - 100;
            if (growth >= server.aof_rewrite_perc) {
                serverLog(LL_NOTICE,"Starting automatic rewriting of AOF on %lld%% growth",growth);
                rewriteAppendOnlyFileBackground();
            }
        }
    }
    
    updateDictResizePolicy();


    
    if (server.aof_flush_postponed_start) flushAppendOnlyFile(0);

    
    run_with_period(1000) {
        if (server.aof_last_write_status == C_ERR)
            flushAppendOnlyFile(0);
    }

    
    clientsArePaused(); 

    
    run_with_period(1000) replicationCron();

    
    run_with_period(100) {
        if (server.cluster_enabled) clusterCron();
    }

    
    if (server.sentinel_mode) sentinelTimer();

    
    run_with_period(1000) {
        migrateCloseTimedoutSockets();
    }

    
    stopThreadedIOIfNeeded();

    
    if (server.tracking_clients) trackingLimitUsedSlots();

    
    if (!hasActiveChildProcess() && server.rdb_bgsave_scheduled && (server.unixtime-server.lastbgsave_try > CONFIG_BGSAVE_RETRY_DELAY || server.lastbgsave_status == C_OK))


    {
        rdbSaveInfo rsi, *rsiptr;
        rsiptr = rdbPopulateSaveInfo(&rsi);
        if (rdbSaveBackground(server.rdb_filename,rsiptr) == C_OK)
            server.rdb_bgsave_scheduled = 0;
    }

    
    RedisModuleCronLoopV1 ei = {REDISMODULE_CRON_LOOP_VERSION,server.hz};
    moduleFireServerEvent(REDISMODULE_EVENT_CRON_LOOP, 0, &ei);


    server.cronloops++;
    return 1000/server.hz;
}

extern int ProcessingEventsWhileBlocked;


void beforeSleep(struct aeEventLoop *eventLoop) {
    UNUSED(eventLoop);

    size_t zmalloc_used = zmalloc_used_memory();
    if (zmalloc_used > server.stat_peak_memory)
        server.stat_peak_memory = zmalloc_used;

    
    if (ProcessingEventsWhileBlocked) {
        uint64_t processed = 0;
        processed += handleClientsWithPendingReadsUsingThreads();
        processed += tlsProcessPendingData();
        processed += handleClientsWithPendingWrites();
        processed += freeClientsInAsyncFreeQueue();
        server.events_processed_while_blocked += processed;
        return;
    }

    
    handleBlockedClientsTimeout();

    
    handleClientsWithPendingReadsUsingThreads();

    
    tlsProcessPendingData();

    
    aeSetDontWait(server.el, tlsHasPendingData());

    
    if (server.cluster_enabled) clusterBeforeSleep();

    
    if (server.active_expire_enabled && server.masterhost == NULL)
        activeExpireCycle(ACTIVE_EXPIRE_CYCLE_FAST);

    
    if (listLength(server.clients_waiting_acks))
        processClientsWaitingReplicas();

    
    if (moduleCount()) moduleHandleBlockedClients();

    
    if (listLength(server.unblocked_clients))
        processUnblockedClients();

    
    if (server.get_ack_from_slaves) {
        robj *argv[3];

        argv[0] = createStringObject("REPLCONF",8);
        argv[1] = createStringObject("GETACK",6);
        argv[2] = createStringObject("*",1); 
        replicationFeedSlaves(server.slaves, server.slaveseldb, argv, 3);
        decrRefCount(argv[0]);
        decrRefCount(argv[1]);
        decrRefCount(argv[2]);
        server.get_ack_from_slaves = 0;
    }

    
    trackingBroadcastInvalidationMessages();

    
    flushAppendOnlyFile(0);

    
    handleClientsWithPendingWritesUsingThreads();

    
    freeClientsInAsyncFreeQueue();

    
    handleClientsBlockedOnKeys();

    
    if (moduleCount()) moduleReleaseGIL();

    
}


void afterSleep(struct aeEventLoop *eventLoop) {
    UNUSED(eventLoop);

    

    
    if (!ProcessingEventsWhileBlocked) {
        if (moduleCount()) moduleAcquireGIL();
    }
}



void createSharedObjects(void) {
    int j;

    shared.crlf = createObject(OBJ_STRING,sdsnew("\r\n"));
    shared.ok = createObject(OBJ_STRING,sdsnew("+OK\r\n"));
    shared.err = createObject(OBJ_STRING,sdsnew("-ERR\r\n"));
    shared.emptybulk = createObject(OBJ_STRING,sdsnew("$0\r\n\r\n"));
    shared.czero = createObject(OBJ_STRING,sdsnew(":0\r\n"));
    shared.cone = createObject(OBJ_STRING,sdsnew(":1\r\n"));
    shared.emptyarray = createObject(OBJ_STRING,sdsnew("*0\r\n"));
    shared.pong = createObject(OBJ_STRING,sdsnew("+PONG\r\n"));
    shared.queued = createObject(OBJ_STRING,sdsnew("+QUEUED\r\n"));
    shared.emptyscan = createObject(OBJ_STRING,sdsnew("*2\r\n$1\r\n0\r\n*0\r\n"));
    shared.wrongtypeerr = createObject(OBJ_STRING,sdsnew( "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n"));
    shared.nokeyerr = createObject(OBJ_STRING,sdsnew( "-ERR no such key\r\n"));
    shared.syntaxerr = createObject(OBJ_STRING,sdsnew( "-ERR syntax error\r\n"));
    shared.sameobjecterr = createObject(OBJ_STRING,sdsnew( "-ERR source and destination objects are the same\r\n"));
    shared.outofrangeerr = createObject(OBJ_STRING,sdsnew( "-ERR index out of range\r\n"));
    shared.noscripterr = createObject(OBJ_STRING,sdsnew( "-NOSCRIPT No matching script. Please use EVAL.\r\n"));
    shared.loadingerr = createObject(OBJ_STRING,sdsnew( "-LOADING Redis is loading the dataset in memory\r\n"));
    shared.slowscripterr = createObject(OBJ_STRING,sdsnew( "-BUSY Redis is busy running a script. You can only call SCRIPT KILL or SHUTDOWN NOSAVE.\r\n"));
    shared.masterdownerr = createObject(OBJ_STRING,sdsnew( "-MASTERDOWN Link with MASTER is down and replica-serve-stale-data is set to 'no'.\r\n"));
    shared.bgsaveerr = createObject(OBJ_STRING,sdsnew( "-MISCONF Redis is configured to save RDB snapshots, but it is currently not able to persist on disk. Commands that may modify the data set are disabled, because this instance is configured to report errors during writes if RDB snapshotting fails (stop-writes-on-bgsave-error option). Please check the Redis logs for details about the RDB error.\r\n"));
    shared.roslaveerr = createObject(OBJ_STRING,sdsnew( "-READONLY You can't write against a read only replica.\r\n"));
    shared.noautherr = createObject(OBJ_STRING,sdsnew( "-NOAUTH Authentication required.\r\n"));
    shared.oomerr = createObject(OBJ_STRING,sdsnew( "-OOM command not allowed when used memory > 'maxmemory'.\r\n"));
    shared.execaborterr = createObject(OBJ_STRING,sdsnew( "-EXECABORT Transaction discarded because of previous errors.\r\n"));
    shared.noreplicaserr = createObject(OBJ_STRING,sdsnew( "-NOREPLICAS Not enough good replicas to write.\r\n"));
    shared.busykeyerr = createObject(OBJ_STRING,sdsnew( "-BUSYKEY Target key name already exists.\r\n"));
    shared.space = createObject(OBJ_STRING,sdsnew(" "));
    shared.colon = createObject(OBJ_STRING,sdsnew(":"));
    shared.plus = createObject(OBJ_STRING,sdsnew("+"));

    
    shared.null[0] = NULL;
    shared.null[1] = NULL;
    shared.null[2] = createObject(OBJ_STRING,sdsnew("$-1\r\n"));
    shared.null[3] = createObject(OBJ_STRING,sdsnew("_\r\n"));

    shared.nullarray[0] = NULL;
    shared.nullarray[1] = NULL;
    shared.nullarray[2] = createObject(OBJ_STRING,sdsnew("*-1\r\n"));
    shared.nullarray[3] = createObject(OBJ_STRING,sdsnew("_\r\n"));

    shared.emptymap[0] = NULL;
    shared.emptymap[1] = NULL;
    shared.emptymap[2] = createObject(OBJ_STRING,sdsnew("*0\r\n"));
    shared.emptymap[3] = createObject(OBJ_STRING,sdsnew("%0\r\n"));

    shared.emptyset[0] = NULL;
    shared.emptyset[1] = NULL;
    shared.emptyset[2] = createObject(OBJ_STRING,sdsnew("*0\r\n"));
    shared.emptyset[3] = createObject(OBJ_STRING,sdsnew("~0\r\n"));

    for (j = 0; j < PROTO_SHARED_SELECT_CMDS; j++) {
        char dictid_str[64];
        int dictid_len;

        dictid_len = ll2string(dictid_str,sizeof(dictid_str),j);
        shared.select[j] = createObject(OBJ_STRING, sdscatprintf(sdsempty(), "*2\r\n$6\r\nSELECT\r\n$%d\r\n%s\r\n", dictid_len, dictid_str));


    }
    shared.messagebulk = createStringObject("$7\r\nmessage\r\n",13);
    shared.pmessagebulk = createStringObject("$8\r\npmessage\r\n",14);
    shared.subscribebulk = createStringObject("$9\r\nsubscribe\r\n",15);
    shared.unsubscribebulk = createStringObject("$11\r\nunsubscribe\r\n",18);
    shared.psubscribebulk = createStringObject("$10\r\npsubscribe\r\n",17);
    shared.punsubscribebulk = createStringObject("$12\r\npunsubscribe\r\n",19);
    shared.del = createStringObject("DEL",3);
    shared.unlink = createStringObject("UNLINK",6);
    shared.rpop = createStringObject("RPOP",4);
    shared.lpop = createStringObject("LPOP",4);
    shared.lpush = createStringObject("LPUSH",5);
    shared.rpoplpush = createStringObject("RPOPLPUSH",9);
    shared.zpopmin = createStringObject("ZPOPMIN",7);
    shared.zpopmax = createStringObject("ZPOPMAX",7);
    shared.multi = createStringObject("MULTI",5);
    shared.exec = createStringObject("EXEC",4);
    for (j = 0; j < OBJ_SHARED_INTEGERS; j++) {
        shared.integers[j] = makeObjectShared(createObject(OBJ_STRING,(void*)(long)j));
        shared.integers[j]->encoding = OBJ_ENCODING_INT;
    }
    for (j = 0; j < OBJ_SHARED_BULKHDR_LEN; j++) {
        shared.mbulkhdr[j] = createObject(OBJ_STRING, sdscatprintf(sdsempty(),"*%d\r\n",j));
        shared.bulkhdr[j] = createObject(OBJ_STRING, sdscatprintf(sdsempty(),"$%d\r\n",j));
    }
    
    shared.minstring = sdsnew("minstring");
    shared.maxstring = sdsnew("maxstring");
}

void initServerConfig(void) {
    int j;

    updateCachedTime(1);
    getRandomHexChars(server.runid,CONFIG_RUN_ID_SIZE);
    server.runid[CONFIG_RUN_ID_SIZE] = '\0';
    changeReplicationId();
    clearReplicationId2();
    server.hz = CONFIG_DEFAULT_HZ; 
    server.timezone = getTimeZone(); 
    server.configfile = NULL;
    server.executable = NULL;
    server.arch_bits = (sizeof(long) == 8) ? 64 : 32;
    server.bindaddr_count = 0;
    server.unixsocketperm = CONFIG_DEFAULT_UNIX_SOCKET_PERM;
    server.ipfd_count = 0;
    server.tlsfd_count = 0;
    server.sofd = -1;
    server.active_expire_enabled = 1;
    server.client_max_querybuf_len = PROTO_MAX_QUERYBUF_LEN;
    server.saveparams = NULL;
    server.loading = 0;
    server.logfile = zstrdup(CONFIG_DEFAULT_LOGFILE);
    server.aof_state = AOF_OFF;
    server.aof_rewrite_base_size = 0;
    server.aof_rewrite_scheduled = 0;
    server.aof_flush_sleep = 0;
    server.aof_last_fsync = time(NULL);
    server.aof_rewrite_time_last = -1;
    server.aof_rewrite_time_start = -1;
    server.aof_lastbgrewrite_status = C_OK;
    server.aof_delayed_fsync = 0;
    server.aof_fd = -1;
    server.aof_selected_db = -1; 
    server.aof_flush_postponed_start = 0;
    server.pidfile = NULL;
    server.active_defrag_running = 0;
    server.notify_keyspace_events = 0;
    server.blocked_clients = 0;
    memset(server.blocked_clients_by_type,0, sizeof(server.blocked_clients_by_type));
    server.shutdown_asap = 0;
    server.cluster_configfile = zstrdup(CONFIG_DEFAULT_CLUSTER_CONFIG_FILE);
    server.cluster_module_flags = CLUSTER_MODULE_FLAG_NONE;
    server.migrate_cached_sockets = dictCreate(&migrateCacheDictType,NULL);
    server.next_client_id = 1; 
    server.loading_process_events_interval_bytes = (1024*1024*2);

    server.lruclock = getLRUClock();
    resetServerSaveParams();

    appendServerSaveParams(60*60,1);  
    appendServerSaveParams(300,100);  
    appendServerSaveParams(60,10000); 

    
    server.masterauth = NULL;
    server.masterhost = NULL;
    server.masterport = 6379;
    server.master = NULL;
    server.cached_master = NULL;
    server.master_initial_offset = -1;
    server.repl_state = REPL_STATE_NONE;
    server.repl_transfer_tmpfile = NULL;
    server.repl_transfer_fd = -1;
    server.repl_transfer_s = NULL;
    server.repl_syncio_timeout = CONFIG_REPL_SYNCIO_TIMEOUT;
    server.repl_down_since = 0; 
    server.master_repl_offset = 0;

    
    server.repl_backlog = NULL;
    server.repl_backlog_histlen = 0;
    server.repl_backlog_idx = 0;
    server.repl_backlog_off = 0;
    server.repl_no_slaves_since = time(NULL);

    
    for (j = 0; j < CLIENT_TYPE_OBUF_COUNT; j++)
        server.client_obuf_limits[j] = clientBufferLimitsDefaults[j];

    
    for (j = 0; j < CONFIG_OOM_COUNT; j++)
        server.oom_score_adj_values[j] = configOOMScoreAdjValuesDefaults[j];

    
    R_Zero = 0.0;
    R_PosInf = 1.0/R_Zero;
    R_NegInf = -1.0/R_Zero;
    R_Nan = R_Zero/R_Zero;

    
    server.commands = dictCreate(&commandTableDictType,NULL);
    server.orig_commands = dictCreate(&commandTableDictType,NULL);
    populateCommandTable();
    server.delCommand = lookupCommandByCString("del");
    server.multiCommand = lookupCommandByCString("multi");
    server.lpushCommand = lookupCommandByCString("lpush");
    server.lpopCommand = lookupCommandByCString("lpop");
    server.rpopCommand = lookupCommandByCString("rpop");
    server.zpopminCommand = lookupCommandByCString("zpopmin");
    server.zpopmaxCommand = lookupCommandByCString("zpopmax");
    server.sremCommand = lookupCommandByCString("srem");
    server.execCommand = lookupCommandByCString("exec");
    server.expireCommand = lookupCommandByCString("expire");
    server.pexpireCommand = lookupCommandByCString("pexpire");
    server.xclaimCommand = lookupCommandByCString("xclaim");
    server.xgroupCommand = lookupCommandByCString("xgroup");
    server.rpoplpushCommand = lookupCommandByCString("rpoplpush");

    
    server.assert_failed = "<no assertion failed>";
    server.assert_file = "<no file>";
    server.assert_line = 0;
    server.bug_report_start = 0;
    server.watchdog_period = 0;

    
    server.lua_always_replicate_commands = 1;

    initConfigValues();
}

extern char **environ;


int restartServer(int flags, mstime_t delay) {
    int j;

    
    if (access(server.executable,X_OK) == -1) {
        serverLog(LL_WARNING,"Can't restart: this process has no " "permissions to execute %s", server.executable);
        return C_ERR;
    }

    
    if (flags & RESTART_SERVER_CONFIG_REWRITE && server.configfile && rewriteConfig(server.configfile, 0) == -1)

    {
        serverLog(LL_WARNING,"Can't restart: configuration rewrite process " "failed");
        return C_ERR;
    }

    
    if (flags & RESTART_SERVER_GRACEFULLY && prepareForShutdown(SHUTDOWN_NOFLAGS) != C_OK)
    {
        serverLog(LL_WARNING,"Can't restart: error preparing for shutdown");
        return C_ERR;
    }

    
    for (j = 3; j < (int)server.maxclients + 1024; j++) {
        
        if (fcntl(j,F_GETFD) != -1) close(j);
    }

    
    if (delay) usleep(delay*1000);
    zfree(server.exec_argv[0]);
    server.exec_argv[0] = zstrdup(server.executable);
    execve(server.executable,server.exec_argv,environ);

    
    _exit(1);

    return C_ERR; 
}

static void readOOMScoreAdj(void) {

    char buf[64];
    int fd = open("/proc/self/oom_score_adj", O_RDONLY);

    if (fd < 0) return;
    if (read(fd, buf, sizeof(buf)) > 0)
        server.oom_score_adj_base = atoi(buf);
    close(fd);

}


int setOOMScoreAdj(int process_class) {

    if (server.oom_score_adj == OOM_SCORE_ADJ_NO) return C_OK;
    if (process_class == -1)
        process_class = (server.masterhost ? CONFIG_OOM_REPLICA : CONFIG_OOM_MASTER);

    serverAssert(process_class >= 0 && process_class < CONFIG_OOM_COUNT);


    int fd;
    int val;
    char buf[64];

    val = server.oom_score_adj_values[process_class];
    if (server.oom_score_adj == OOM_SCORE_RELATIVE)
        val += server.oom_score_adj_base;
    if (val > 1000) val = 1000;
    if (val < -1000) val = -1000;

    snprintf(buf, sizeof(buf) - 1, "%d\n", val);

    fd = open("/proc/self/oom_score_adj", O_WRONLY);
    if (fd < 0 || write(fd, buf, strlen(buf)) < 0) {
        serverLog(LOG_WARNING, "Unable to write oom_score_adj: %s", strerror(errno));
        if (fd != -1) close(fd);
        return C_ERR;
    }

    close(fd);
    return C_OK;

    
    return C_ERR;

}


void adjustOpenFilesLimit(void) {
    rlim_t maxfiles = server.maxclients+CONFIG_MIN_RESERVED_FDS;
    struct rlimit limit;

    if (getrlimit(RLIMIT_NOFILE,&limit) == -1) {
        serverLog(LL_WARNING,"Unable to obtain the current NOFILE limit (%s), assuming 1024 and setting the max clients configuration accordingly.", strerror(errno));
        server.maxclients = 1024-CONFIG_MIN_RESERVED_FDS;
    } else {
        rlim_t oldlimit = limit.rlim_cur;

        
        if (oldlimit < maxfiles) {
            rlim_t bestlimit;
            int setrlimit_error = 0;

            
            bestlimit = maxfiles;
            while(bestlimit > oldlimit) {
                rlim_t decr_step = 16;

                limit.rlim_cur = bestlimit;
                limit.rlim_max = bestlimit;
                if (setrlimit(RLIMIT_NOFILE,&limit) != -1) break;
                setrlimit_error = errno;

                
                if (bestlimit < decr_step) break;
                bestlimit -= decr_step;
            }

            
            if (bestlimit < oldlimit) bestlimit = oldlimit;

            if (bestlimit < maxfiles) {
                unsigned int old_maxclients = server.maxclients;
                server.maxclients = bestlimit-CONFIG_MIN_RESERVED_FDS;
                
                if (bestlimit <= CONFIG_MIN_RESERVED_FDS) {
                    serverLog(LL_WARNING,"Your current 'ulimit -n' " "of %llu is not enough for the server to start. " "Please increase your open file limit to at least " "%llu. Exiting.", (unsigned long long) oldlimit, (unsigned long long) maxfiles);




                    exit(1);
                }
                serverLog(LL_WARNING,"You requested maxclients of %d " "requiring at least %llu max file descriptors.", old_maxclients, (unsigned long long) maxfiles);


                serverLog(LL_WARNING,"Server can't set maximum open files " "to %llu because of OS error: %s.", (unsigned long long) maxfiles, strerror(setrlimit_error));

                serverLog(LL_WARNING,"Current maximum open files is %llu. " "maxclients has been reduced to %d to compensate for " "low ulimit. " "If you need higher maxclients increase 'ulimit -n'.", (unsigned long long) bestlimit, server.maxclients);



            } else {
                serverLog(LL_NOTICE,"Increased maximum number of open files " "to %llu (it was originally set to %llu).", (unsigned long long) maxfiles, (unsigned long long) oldlimit);


            }
        }
    }
}


void checkTcpBacklogSettings(void) {

    FILE *fp = fopen("/proc/sys/net/core/somaxconn","r");
    char buf[1024];
    if (!fp) return;
    if (fgets(buf,sizeof(buf),fp) != NULL) {
        int somaxconn = atoi(buf);
        if (somaxconn > 0 && somaxconn < server.tcp_backlog) {
            serverLog(LL_WARNING,"WARNING: The TCP backlog setting of %d cannot be enforced because /proc/sys/net/core/somaxconn is set to the lower value of %d.", server.tcp_backlog, somaxconn);
        }
    }
    fclose(fp);

}


int listenToPort(int port, int *fds, int *count) {
    int j;

    
    if (server.bindaddr_count == 0) server.bindaddr[0] = NULL;
    for (j = 0; j < server.bindaddr_count || j == 0; j++) {
        if (server.bindaddr[j] == NULL) {
            int unsupported = 0;
            
            fds[*count] = anetTcp6Server(server.neterr,port,NULL, server.tcp_backlog);
            if (fds[*count] != ANET_ERR) {
                anetNonBlock(NULL,fds[*count]);
                (*count)++;
            } else if (errno == EAFNOSUPPORT) {
                unsupported++;
                serverLog(LL_WARNING,"Not listening to IPv6: unsupported");
            }

            if (*count == 1 || unsupported) {
                
                fds[*count] = anetTcpServer(server.neterr,port,NULL, server.tcp_backlog);
                if (fds[*count] != ANET_ERR) {
                    anetNonBlock(NULL,fds[*count]);
                    (*count)++;
                } else if (errno == EAFNOSUPPORT) {
                    unsupported++;
                    serverLog(LL_WARNING,"Not listening to IPv4: unsupported");
                }
            }
            
            if (*count + unsupported == 2) break;
        } else if (strchr(server.bindaddr[j],':')) {
            
            fds[*count] = anetTcp6Server(server.neterr,port,server.bindaddr[j], server.tcp_backlog);
        } else {
            
            fds[*count] = anetTcpServer(server.neterr,port,server.bindaddr[j], server.tcp_backlog);
        }
        if (fds[*count] == ANET_ERR) {
            int net_errno = errno;
            serverLog(LL_WARNING, "Could not create server TCP listening socket %s:%d: %s", server.bindaddr[j] ? server.bindaddr[j] : "*", port, server.neterr);


                if (net_errno == ENOPROTOOPT     || net_errno == EPROTONOSUPPORT || net_errno == ESOCKTNOSUPPORT || net_errno == EPFNOSUPPORT || net_errno == EAFNOSUPPORT    || net_errno == EADDRNOTAVAIL)

                    continue;
            return C_ERR;
        }
        anetNonBlock(NULL,fds[*count]);
        (*count)++;
    }
    return C_OK;
}


void resetServerStats(void) {
    int j;

    server.stat_numcommands = 0;
    server.stat_numconnections = 0;
    server.stat_expiredkeys = 0;
    server.stat_expired_stale_perc = 0;
    server.stat_expired_time_cap_reached_count = 0;
    server.stat_expire_cycle_time_used = 0;
    server.stat_evictedkeys = 0;
    server.stat_keyspace_misses = 0;
    server.stat_keyspace_hits = 0;
    server.stat_active_defrag_hits = 0;
    server.stat_active_defrag_misses = 0;
    server.stat_active_defrag_key_hits = 0;
    server.stat_active_defrag_key_misses = 0;
    server.stat_active_defrag_scanned = 0;
    server.stat_fork_time = 0;
    server.stat_fork_rate = 0;
    server.stat_rejected_conn = 0;
    server.stat_sync_full = 0;
    server.stat_sync_partial_ok = 0;
    server.stat_sync_partial_err = 0;
    server.stat_io_reads_processed = 0;
    server.stat_total_reads_processed = 0;
    server.stat_io_writes_processed = 0;
    server.stat_total_writes_processed = 0;
    for (j = 0; j < STATS_METRIC_COUNT; j++) {
        server.inst_metric[j].idx = 0;
        server.inst_metric[j].last_sample_time = mstime();
        server.inst_metric[j].last_sample_count = 0;
        memset(server.inst_metric[j].samples,0, sizeof(server.inst_metric[j].samples));
    }
    server.stat_net_input_bytes = 0;
    server.stat_net_output_bytes = 0;
    server.stat_unexpected_error_replies = 0;
    server.aof_delayed_fsync = 0;
}


void makeThreadKillable(void) {
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
}

void initServer(void) {
    int j;

    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    setupSignalHandlers();
    makeThreadKillable();

    if (server.syslog_enabled) {
        openlog(server.syslog_ident, LOG_PID | LOG_NDELAY | LOG_NOWAIT, server.syslog_facility);
    }

    
    server.aof_state = server.aof_enabled ? AOF_ON : AOF_OFF;
    server.hz = server.config_hz;
    server.pid = getpid();
    server.in_fork_child = CHILD_TYPE_NONE;
    server.main_thread_id = pthread_self();
    server.current_client = NULL;
    server.fixed_time_expire = 0;
    server.clients = listCreate();
    server.clients_index = raxNew();
    server.clients_to_close = listCreate();
    server.slaves = listCreate();
    server.monitors = listCreate();
    server.clients_pending_write = listCreate();
    server.clients_pending_read = listCreate();
    server.clients_timeout_table = raxNew();
    server.slaveseldb = -1; 
    server.unblocked_clients = listCreate();
    server.ready_keys = listCreate();
    server.clients_waiting_acks = listCreate();
    server.get_ack_from_slaves = 0;
    server.clients_paused = 0;
    server.events_processed_while_blocked = 0;
    server.system_memory_size = zmalloc_get_memory_size();

    if ((server.tls_port || server.tls_replication || server.tls_cluster)
                && tlsConfigure(&server.tls_ctx_config) == C_ERR) {
        serverLog(LL_WARNING, "Failed to configure TLS. Check logs for more info.");
        exit(1);
    }

    createSharedObjects();
    adjustOpenFilesLimit();
    server.el = aeCreateEventLoop(server.maxclients+CONFIG_FDSET_INCR);
    if (server.el == NULL) {
        serverLog(LL_WARNING, "Failed creating the event loop. Error message: '%s'", strerror(errno));

        exit(1);
    }
    server.db = zmalloc(sizeof(redisDb)*server.dbnum);

    
    if (server.port != 0 && listenToPort(server.port,server.ipfd,&server.ipfd_count) == C_ERR)
        exit(1);
    if (server.tls_port != 0 && listenToPort(server.tls_port,server.tlsfd,&server.tlsfd_count) == C_ERR)
        exit(1);

    
    if (server.unixsocket != NULL) {
        unlink(server.unixsocket); 
        server.sofd = anetUnixServer(server.neterr,server.unixsocket, server.unixsocketperm, server.tcp_backlog);
        if (server.sofd == ANET_ERR) {
            serverLog(LL_WARNING, "Opening Unix socket: %s", server.neterr);
            exit(1);
        }
        anetNonBlock(NULL,server.sofd);
    }

    
    if (server.ipfd_count == 0 && server.tlsfd_count == 0 && server.sofd < 0) {
        serverLog(LL_WARNING, "Configured to not listen anywhere, exiting.");
        exit(1);
    }

    
    for (j = 0; j < server.dbnum; j++) {
        server.db[j].dict = dictCreate(&dbDictType,NULL);
        server.db[j].expires = dictCreate(&keyptrDictType,NULL);
        server.db[j].expires_cursor = 0;
        server.db[j].blocking_keys = dictCreate(&keylistDictType,NULL);
        server.db[j].ready_keys = dictCreate(&objectKeyPointerValueDictType,NULL);
        server.db[j].watched_keys = dictCreate(&keylistDictType,NULL);
        server.db[j].id = j;
        server.db[j].avg_ttl = 0;
        server.db[j].defrag_later = listCreate();
        listSetFreeMethod(server.db[j].defrag_later,(void (*)(void*))sdsfree);
    }
    evictionPoolAlloc(); 
    server.pubsub_channels = dictCreate(&keylistDictType,NULL);
    server.pubsub_patterns = listCreate();
    server.pubsub_patterns_dict = dictCreate(&keylistDictType,NULL);
    listSetFreeMethod(server.pubsub_patterns,freePubsubPattern);
    listSetMatchMethod(server.pubsub_patterns,listMatchPubsubPattern);
    server.cronloops = 0;
    server.rdb_child_pid = -1;
    server.aof_child_pid = -1;
    server.module_child_pid = -1;
    server.rdb_child_type = RDB_CHILD_TYPE_NONE;
    server.rdb_pipe_conns = NULL;
    server.rdb_pipe_numconns = 0;
    server.rdb_pipe_numconns_writing = 0;
    server.rdb_pipe_buff = NULL;
    server.rdb_pipe_bufflen = 0;
    server.rdb_bgsave_scheduled = 0;
    server.child_info_pipe[0] = -1;
    server.child_info_pipe[1] = -1;
    server.child_info_data.magic = 0;
    aofRewriteBufferReset();
    server.aof_buf = sdsempty();
    server.lastsave = time(NULL); 
    server.lastbgsave_try = 0;    
    server.rdb_save_time_last = -1;
    server.rdb_save_time_start = -1;
    server.dirty = 0;
    resetServerStats();
    
    server.stat_starttime = time(NULL);
    server.stat_peak_memory = 0;
    server.stat_rdb_cow_bytes = 0;
    server.stat_aof_cow_bytes = 0;
    server.stat_module_cow_bytes = 0;
    for (int j = 0; j < CLIENT_TYPE_COUNT; j++)
        server.stat_clients_type_memory[j] = 0;
    server.cron_malloc_stats.zmalloc_used = 0;
    server.cron_malloc_stats.process_rss = 0;
    server.cron_malloc_stats.allocator_allocated = 0;
    server.cron_malloc_stats.allocator_active = 0;
    server.cron_malloc_stats.allocator_resident = 0;
    server.lastbgsave_status = C_OK;
    server.aof_last_write_status = C_OK;
    server.aof_last_write_errno = 0;
    server.repl_good_slaves_count = 0;

    
    if (aeCreateTimeEvent(server.el, 1, serverCron, NULL, NULL) == AE_ERR) {
        serverPanic("Can't create event loop timers.");
        exit(1);
    }

    
    for (j = 0; j < server.ipfd_count; j++) {
        if (aeCreateFileEvent(server.el, server.ipfd[j], AE_READABLE, acceptTcpHandler,NULL) == AE_ERR)
            {
                serverPanic( "Unrecoverable error creating server.ipfd file event.");
            }
    }
    for (j = 0; j < server.tlsfd_count; j++) {
        if (aeCreateFileEvent(server.el, server.tlsfd[j], AE_READABLE, acceptTLSHandler,NULL) == AE_ERR)
            {
                serverPanic( "Unrecoverable error creating server.tlsfd file event.");
            }
    }
    if (server.sofd > 0 && aeCreateFileEvent(server.el,server.sofd,AE_READABLE, acceptUnixHandler,NULL) == AE_ERR) serverPanic("Unrecoverable error creating server.sofd file event.");


    
    if (aeCreateFileEvent(server.el, server.module_blocked_pipe[0], AE_READABLE, moduleBlockedClientPipeReadable,NULL) == AE_ERR) {
            serverPanic( "Error registering the readable event for the module " "blocked clients subsystem.");

    }

    
    aeSetBeforeSleepProc(server.el,beforeSleep);
    aeSetAfterSleepProc(server.el,afterSleep);

    
    if (server.aof_state == AOF_ON) {
        server.aof_fd = open(server.aof_filename, O_WRONLY|O_APPEND|O_CREAT,0644);
        if (server.aof_fd == -1) {
            serverLog(LL_WARNING, "Can't open the append-only file: %s", strerror(errno));
            exit(1);
        }
    }

    
    if (server.arch_bits == 32 && server.maxmemory == 0) {
        serverLog(LL_WARNING,"Warning: 32 bit instance detected but no memory limit set. Setting 3 GB maxmemory limit with 'noeviction' policy now.");
        server.maxmemory = 3072LL*(1024*1024); 
        server.maxmemory_policy = MAXMEMORY_NO_EVICTION;
    }

    if (server.cluster_enabled) clusterInit();
    replicationScriptCacheInit();
    scriptingInit(1);
    slowlogInit();
    latencyMonitorInit();
}


void InitServerLast() {
    bioInit();
    initThreadedIO();
    set_jemalloc_bg_thread(server.jemalloc_bg_thread);
    server.initial_memory_usage = zmalloc_used_memory();
}


int populateCommandTableParseFlags(struct redisCommand *c, char *strflags) {
    int argc;
    sds *argv;

    
    argv = sdssplitargs(strflags,&argc);
    if (argv == NULL) return C_ERR;

    for (int j = 0; j < argc; j++) {
        char *flag = argv[j];
        if (!strcasecmp(flag,"write")) {
            c->flags |= CMD_WRITE|CMD_CATEGORY_WRITE;
        } else if (!strcasecmp(flag,"read-only")) {
            c->flags |= CMD_READONLY|CMD_CATEGORY_READ;
        } else if (!strcasecmp(flag,"use-memory")) {
            c->flags |= CMD_DENYOOM;
        } else if (!strcasecmp(flag,"admin")) {
            c->flags |= CMD_ADMIN|CMD_CATEGORY_ADMIN|CMD_CATEGORY_DANGEROUS;
        } else if (!strcasecmp(flag,"pub-sub")) {
            c->flags |= CMD_PUBSUB|CMD_CATEGORY_PUBSUB;
        } else if (!strcasecmp(flag,"no-script")) {
            c->flags |= CMD_NOSCRIPT;
        } else if (!strcasecmp(flag,"random")) {
            c->flags |= CMD_RANDOM;
        } else if (!strcasecmp(flag,"to-sort")) {
            c->flags |= CMD_SORT_FOR_SCRIPT;
        } else if (!strcasecmp(flag,"ok-loading")) {
            c->flags |= CMD_LOADING;
        } else if (!strcasecmp(flag,"ok-stale")) {
            c->flags |= CMD_STALE;
        } else if (!strcasecmp(flag,"no-monitor")) {
            c->flags |= CMD_SKIP_MONITOR;
        } else if (!strcasecmp(flag,"no-slowlog")) {
            c->flags |= CMD_SKIP_SLOWLOG;
        } else if (!strcasecmp(flag,"cluster-asking")) {
            c->flags |= CMD_ASKING;
        } else if (!strcasecmp(flag,"fast")) {
            c->flags |= CMD_FAST | CMD_CATEGORY_FAST;
        } else if (!strcasecmp(flag,"no-auth")) {
            c->flags |= CMD_NO_AUTH;
        } else {
            
            uint64_t catflag;
            if (flag[0] == '@' && (catflag = ACLGetCommandCategoryFlagByName(flag+1)) != 0)
            {
                c->flags |= catflag;
            } else {
                sdsfreesplitres(argv,argc);
                return C_ERR;
            }
        }
    }
    
    if (!(c->flags & CMD_CATEGORY_FAST)) c->flags |= CMD_CATEGORY_SLOW;

    sdsfreesplitres(argv,argc);
    return C_OK;
}


void populateCommandTable(void) {
    int j;
    int numcommands = sizeof(redisCommandTable)/sizeof(struct redisCommand);

    for (j = 0; j < numcommands; j++) {
        struct redisCommand *c = redisCommandTable+j;
        int retval1, retval2;

        
        if (populateCommandTableParseFlags(c,c->sflags) == C_ERR)
            serverPanic("Unsupported command flag");

        c->id = ACLGetCommandID(c->name); 
        retval1 = dictAdd(server.commands, sdsnew(c->name), c);
        
        retval2 = dictAdd(server.orig_commands, sdsnew(c->name), c);
        serverAssert(retval1 == DICT_OK && retval2 == DICT_OK);
    }
}

void resetCommandTableStats(void) {
    struct redisCommand *c;
    dictEntry *de;
    dictIterator *di;

    di = dictGetSafeIterator(server.commands);
    while((de = dictNext(di)) != NULL) {
        c = (struct redisCommand *) dictGetVal(de);
        c->microseconds = 0;
        c->calls = 0;
    }
    dictReleaseIterator(di);

}



void redisOpArrayInit(redisOpArray *oa) {
    oa->ops = NULL;
    oa->numops = 0;
}

int redisOpArrayAppend(redisOpArray *oa, struct redisCommand *cmd, int dbid, robj **argv, int argc, int target)
{
    redisOp *op;

    oa->ops = zrealloc(oa->ops,sizeof(redisOp)*(oa->numops+1));
    op = oa->ops+oa->numops;
    op->cmd = cmd;
    op->dbid = dbid;
    op->argv = argv;
    op->argc = argc;
    op->target = target;
    oa->numops++;
    return oa->numops;
}

void redisOpArrayFree(redisOpArray *oa) {
    while(oa->numops) {
        int j;
        redisOp *op;

        oa->numops--;
        op = oa->ops+oa->numops;
        for (j = 0; j < op->argc; j++)
            decrRefCount(op->argv[j]);
        zfree(op->argv);
    }
    zfree(oa->ops);
}



struct redisCommand *lookupCommand(sds name) {
    return dictFetchValue(server.commands, name);
}

struct redisCommand *lookupCommandByCString(const char *s) {
    struct redisCommand *cmd;
    sds name = sdsnew(s);

    cmd = dictFetchValue(server.commands, name);
    sdsfree(name);
    return cmd;
}


struct redisCommand *lookupCommandOrOriginal(sds name) {
    struct redisCommand *cmd = dictFetchValue(server.commands, name);

    if (!cmd) cmd = dictFetchValue(server.orig_commands,name);
    return cmd;
}


void propagate(struct redisCommand *cmd, int dbid, robj **argv, int argc, int flags)
{
    if (server.aof_state != AOF_OFF && flags & PROPAGATE_AOF)
        feedAppendOnlyFile(cmd,dbid,argv,argc);
    if (flags & PROPAGATE_REPL)
        replicationFeedSlaves(server.slaves,dbid,argv,argc);
}


void alsoPropagate(struct redisCommand *cmd, int dbid, robj **argv, int argc, int target)
{
    robj **argvcopy;
    int j;

    if (server.loading) return; 

    argvcopy = zmalloc(sizeof(robj*)*argc);
    for (j = 0; j < argc; j++) {
        argvcopy[j] = argv[j];
        incrRefCount(argv[j]);
    }
    redisOpArrayAppend(&server.also_propagate,cmd,dbid,argvcopy,argc,target);
}


void forceCommandPropagation(client *c, int flags) {
    if (flags & PROPAGATE_REPL) c->flags |= CLIENT_FORCE_REPL;
    if (flags & PROPAGATE_AOF) c->flags |= CLIENT_FORCE_AOF;
}


void preventCommandPropagation(client *c) {
    c->flags |= CLIENT_PREVENT_PROP;
}


void preventCommandAOF(client *c) {
    c->flags |= CLIENT_PREVENT_AOF_PROP;
}


void preventCommandReplication(client *c) {
    c->flags |= CLIENT_PREVENT_REPL_PROP;
}


void call(client *c, int flags) {
    long long dirty;
    ustime_t start, duration;
    int client_old_flags = c->flags;
    struct redisCommand *real_cmd = c->cmd;

    
    if (listLength(server.monitors) && !server.loading && !(c->cmd->flags & (CMD_SKIP_MONITOR|CMD_ADMIN)))

    {
        replicationFeedMonitors(c,server.monitors,c->db->id,c->argv,c->argc);
    }

    
    c->flags &= ~(CLIENT_FORCE_AOF|CLIENT_FORCE_REPL|CLIENT_PREVENT_PROP);
    redisOpArray prev_also_propagate = server.also_propagate;
    redisOpArrayInit(&server.also_propagate);

    
    dirty = server.dirty;

    
    if (server.fixed_time_expire++ == 0) {
        updateCachedTime(0);
    }

    start = server.ustime;
    c->cmd->proc(c);
    duration = ustime()-start;
    dirty = server.dirty-dirty;
    if (dirty < 0) dirty = 0;

    
    if (c->flags & CLIENT_CLOSE_AFTER_COMMAND) {
        c->flags &= ~CLIENT_CLOSE_AFTER_COMMAND;
        c->flags |= CLIENT_CLOSE_AFTER_REPLY;
    }

    
    if (server.loading && c->flags & CLIENT_LUA)
        flags &= ~(CMD_CALL_SLOWLOG | CMD_CALL_STATS);

    
    if (c->flags & CLIENT_LUA && server.lua_caller) {
        if (c->flags & CLIENT_FORCE_REPL)
            server.lua_caller->flags |= CLIENT_FORCE_REPL;
        if (c->flags & CLIENT_FORCE_AOF)
            server.lua_caller->flags |= CLIENT_FORCE_AOF;
    }

    
    if (flags & CMD_CALL_SLOWLOG && !(c->cmd->flags & CMD_SKIP_SLOWLOG)) {
        char *latency_event = (c->cmd->flags & CMD_FAST) ? "fast-command" : "command";
        latencyAddSampleIfNeeded(latency_event,duration/1000);
        slowlogPushEntryIfNeeded(c,c->argv,c->argc,duration);
    }

    if (flags & CMD_CALL_STATS) {
        
        real_cmd->microseconds += duration;
        real_cmd->calls++;
    }

    
    if (flags & CMD_CALL_PROPAGATE && (c->flags & CLIENT_PREVENT_PROP) != CLIENT_PREVENT_PROP)
    {
        int propagate_flags = PROPAGATE_NONE;

        
        if (dirty) propagate_flags |= (PROPAGATE_AOF|PROPAGATE_REPL);

        
        if (c->flags & CLIENT_FORCE_REPL) propagate_flags |= PROPAGATE_REPL;
        if (c->flags & CLIENT_FORCE_AOF) propagate_flags |= PROPAGATE_AOF;

        
        if (c->flags & CLIENT_PREVENT_REPL_PROP || !(flags & CMD_CALL_PROPAGATE_REPL))
                propagate_flags &= ~PROPAGATE_REPL;
        if (c->flags & CLIENT_PREVENT_AOF_PROP || !(flags & CMD_CALL_PROPAGATE_AOF))
                propagate_flags &= ~PROPAGATE_AOF;

        
        if (propagate_flags != PROPAGATE_NONE && !(c->cmd->flags & CMD_MODULE))
            propagate(c->cmd,c->db->id,c->argv,c->argc,propagate_flags);
    }

    
    c->flags &= ~(CLIENT_FORCE_AOF|CLIENT_FORCE_REPL|CLIENT_PREVENT_PROP);
    c->flags |= client_old_flags & (CLIENT_FORCE_AOF|CLIENT_FORCE_REPL|CLIENT_PREVENT_PROP);

    
    if (server.also_propagate.numops) {
        int j;
        redisOp *rop;

        if (flags & CMD_CALL_PROPAGATE) {
            int multi_emitted = 0;
            
            if (server.also_propagate.numops > 1 && !(c->cmd->flags & CMD_MODULE) && !(c->flags & CLIENT_MULTI) && !(flags & CMD_CALL_NOWRAP))


            {
                execCommandPropagateMulti(c);
                multi_emitted = 1;
            }

            for (j = 0; j < server.also_propagate.numops; j++) {
                rop = &server.also_propagate.ops[j];
                int target = rop->target;
                
                if (!(flags&CMD_CALL_PROPAGATE_AOF)) target &= ~PROPAGATE_AOF;
                if (!(flags&CMD_CALL_PROPAGATE_REPL)) target &= ~PROPAGATE_REPL;
                if (target)
                    propagate(rop->cmd,rop->dbid,rop->argv,rop->argc,target);
            }

            if (multi_emitted) {
                execCommandPropagateExec(c);
            }
        }
        redisOpArrayFree(&server.also_propagate);
    }
    server.also_propagate = prev_also_propagate;

    
    if (c->cmd->flags & CMD_READONLY) {
        client *caller = (c->flags & CLIENT_LUA && server.lua_caller) ? server.lua_caller : c;
        if (caller->flags & CLIENT_TRACKING && !(caller->flags & CLIENT_TRACKING_BCAST))
        {
            trackingRememberKeys(caller);
        }
    }

    server.fixed_time_expire--;
    server.stat_numcommands++;

    
    size_t zmalloc_used = zmalloc_used_memory();
    if (zmalloc_used > server.stat_peak_memory)
        server.stat_peak_memory = zmalloc_used;
}


void rejectCommand(client *c, robj *reply) {
    flagTransaction(c);
    if (c->cmd && c->cmd->proc == execCommand) {
        execCommandAbort(c, reply->ptr);
    } else {
        
        addReplyErrorObject(c, reply);
    }
}

void rejectCommandFormat(client *c, const char *fmt, ...) {
    flagTransaction(c);
    va_list ap;
    va_start(ap,fmt);
    sds s = sdscatvprintf(sdsempty(),fmt,ap);
    va_end(ap);
    
    sdsmapchars(s, "\r\n", "  ",  2);
    if (c->cmd && c->cmd->proc == execCommand) {
        execCommandAbort(c, s);
    } else {
        addReplyErrorSds(c, s);
    }
    sdsfree(s);
}


int processCommand(client *c) {
    moduleCallCommandFilters(c);

    
    if (!strcasecmp(c->argv[0]->ptr,"quit")) {
        addReply(c,shared.ok);
        c->flags |= CLIENT_CLOSE_AFTER_REPLY;
        return C_ERR;
    }

    
    c->cmd = c->lastcmd = lookupCommand(c->argv[0]->ptr);
    if (!c->cmd) {
        sds args = sdsempty();
        int i;
        for (i=1; i < c->argc && sdslen(args) < 128; i++)
            args = sdscatprintf(args, "`%.*s`, ", 128-(int)sdslen(args), (char*)c->argv[i]->ptr);
        rejectCommandFormat(c,"unknown command `%s`, with args beginning with: %s", (char*)c->argv[0]->ptr, args);
        sdsfree(args);
        return C_OK;
    } else if ((c->cmd->arity > 0 && c->cmd->arity != c->argc) || (c->argc < -c->cmd->arity)) {
        rejectCommandFormat(c,"wrong number of arguments for '%s' command", c->cmd->name);
        return C_OK;
    }

    int is_write_command = (c->cmd->flags & CMD_WRITE) || (c->cmd->proc == execCommand && (c->mstate.cmd_flags & CMD_WRITE));
    int is_denyoom_command = (c->cmd->flags & CMD_DENYOOM) || (c->cmd->proc == execCommand && (c->mstate.cmd_flags & CMD_DENYOOM));
    int is_denystale_command = !(c->cmd->flags & CMD_STALE) || (c->cmd->proc == execCommand && (c->mstate.cmd_inv_flags & CMD_STALE));
    int is_denyloading_command = !(c->cmd->flags & CMD_LOADING) || (c->cmd->proc == execCommand && (c->mstate.cmd_inv_flags & CMD_LOADING));

    
    int auth_required = (!(DefaultUser->flags & USER_FLAG_NOPASS) || (DefaultUser->flags & USER_FLAG_DISABLED)) && !c->authenticated;

    if (auth_required) {
        
        if (!(c->cmd->flags & CMD_NO_AUTH)) {
            rejectCommand(c,shared.noautherr);
            return C_OK;
        }
    }

    
    int acl_keypos;
    int acl_retval = ACLCheckCommandPerm(c,&acl_keypos);
    if (acl_retval != ACL_OK) {
        addACLLogEntry(c,acl_retval,acl_keypos,NULL);
        if (acl_retval == ACL_DENIED_CMD)
            rejectCommandFormat(c, "-NOPERM this user has no permissions to run " "the '%s' command or its subcommand", c->cmd->name);

        else rejectCommandFormat(c, "-NOPERM this user has no permissions to access " "one of the keys used as arguments");


        return C_OK;
    }

    
    if (server.cluster_enabled && !(c->flags & CLIENT_MASTER) && !(c->flags & CLIENT_LUA && server.lua_caller->flags & CLIENT_MASTER) && !(c->cmd->getkeys_proc == NULL && c->cmd->firstkey == 0 && c->cmd->proc != execCommand))




    {
        int hashslot;
        int error_code;
        clusterNode *n = getNodeByQuery(c,c->cmd,c->argv,c->argc, &hashslot,&error_code);
        if (n == NULL || n != server.cluster->myself) {
            if (c->cmd->proc == execCommand) {
                discardTransaction(c);
            } else {
                flagTransaction(c);
            }
            clusterRedirectClient(c,n,hashslot,error_code);
            return C_OK;
        }
    }

    
    if (server.maxmemory && !server.lua_timedout) {
        int out_of_memory = freeMemoryIfNeededAndSafe() == C_ERR;
        
        if (server.current_client == NULL) return C_ERR;

        int reject_cmd_on_oom = is_denyoom_command;
        
        if (c->flags & CLIENT_MULTI && c->cmd->proc != execCommand && c->cmd->proc != discardCommand) {

            reject_cmd_on_oom = 1;
        }

        if (out_of_memory && reject_cmd_on_oom) {
            rejectCommand(c, shared.oomerr);
            return C_OK;
        }

        
        if (c->cmd->proc == evalCommand || c->cmd->proc == evalShaCommand) {
            server.lua_oom = out_of_memory;
        }
    }

    
    if (server.tracking_clients) trackingLimitUsedSlots();

    
    int deny_write_type = writeCommandsDeniedByDiskError();
    if (deny_write_type != DISK_ERROR_TYPE_NONE && server.masterhost == NULL && (is_write_command ||c->cmd->proc == pingCommand))

    {
        if (deny_write_type == DISK_ERROR_TYPE_RDB)
            rejectCommand(c, shared.bgsaveerr);
        else rejectCommandFormat(c, "-MISCONF Errors writing to the AOF file: %s", strerror(server.aof_last_write_errno));


        return C_OK;
    }

    
    if (server.masterhost == NULL && server.repl_min_slaves_to_write && server.repl_min_slaves_max_lag && is_write_command && server.repl_good_slaves_count < server.repl_min_slaves_to_write)



    {
        rejectCommand(c, shared.noreplicaserr);
        return C_OK;
    }

    
    if (server.masterhost && server.repl_slave_ro && !(c->flags & CLIENT_MASTER) && is_write_command)

    {
        rejectCommand(c, shared.roslaveerr);
        return C_OK;
    }

    
    if ((c->flags & CLIENT_PUBSUB && c->resp == 2) && c->cmd->proc != pingCommand && c->cmd->proc != subscribeCommand && c->cmd->proc != unsubscribeCommand && c->cmd->proc != psubscribeCommand && c->cmd->proc != punsubscribeCommand) {




        rejectCommandFormat(c, "Can't execute '%s': only (P)SUBSCRIBE / " "(P)UNSUBSCRIBE / PING / QUIT are allowed in this context", c->cmd->name);


        return C_OK;
    }

    
    if (server.masterhost && server.repl_state != REPL_STATE_CONNECTED && server.repl_serve_stale_data == 0 && is_denystale_command)

    {
        rejectCommand(c, shared.masterdownerr);
        return C_OK;
    }

    
    if (server.loading && is_denyloading_command) {
        rejectCommand(c, shared.loadingerr);
        return C_OK;
    }

    
    if (server.lua_timedout && c->cmd->proc != authCommand && c->cmd->proc != helloCommand && c->cmd->proc != replconfCommand && c->cmd->proc != multiCommand && c->cmd->proc != discardCommand && c->cmd->proc != watchCommand && c->cmd->proc != unwatchCommand && !(c->cmd->proc == shutdownCommand && c->argc == 2 && tolower(((char*)c->argv[1]->ptr)[0]) == 'n') && !(c->cmd->proc == scriptCommand && c->argc == 2 && tolower(((char*)c->argv[1]->ptr)[0]) == 'k'))












    {
        rejectCommand(c, shared.slowscripterr);
        return C_OK;
    }

    
    if (c->flags & CLIENT_MULTI && c->cmd->proc != execCommand && c->cmd->proc != discardCommand && c->cmd->proc != multiCommand && c->cmd->proc != watchCommand)

    {
        queueMultiCommand(c);
        addReply(c,shared.queued);
    } else {
        call(c,CMD_CALL_FULL);
        c->woff = server.master_repl_offset;
        if (listLength(server.ready_keys))
            handleClientsBlockedOnKeys();
    }
    return C_OK;
}




void closeListeningSockets(int unlink_unix_socket) {
    int j;

    for (j = 0; j < server.ipfd_count; j++) close(server.ipfd[j]);
    for (j = 0; j < server.tlsfd_count; j++) close(server.tlsfd[j]);
    if (server.sofd != -1) close(server.sofd);
    if (server.cluster_enabled)
        for (j = 0; j < server.cfd_count; j++) close(server.cfd[j]);
    if (unlink_unix_socket && server.unixsocket) {
        serverLog(LL_NOTICE,"Removing the unix socket file.");
        unlink(server.unixsocket); 
    }
}

int prepareForShutdown(int flags) {
    
    if (server.loading || server.sentinel_mode)
        flags = (flags & ~SHUTDOWN_SAVE) | SHUTDOWN_NOSAVE;

    int save = flags & SHUTDOWN_SAVE;
    int nosave = flags & SHUTDOWN_NOSAVE;

    serverLog(LL_WARNING,"User requested shutdown...");
    if (server.supervised_mode == SUPERVISED_SYSTEMD)
        redisCommunicateSystemd("STOPPING=1\n");

    
    ldbKillForkedSessions();

    
    if (server.rdb_child_pid != -1) {
        serverLog(LL_WARNING,"There is a child saving an .rdb. Killing it!");
        
        killRDBChild();
    }

    
    if (server.module_child_pid != -1) {
        serverLog(LL_WARNING,"There is a module fork child. Killing it!");
        TerminateModuleForkChild(server.module_child_pid,0);
    }

    if (server.aof_state != AOF_OFF) {
        
        if (server.aof_child_pid != -1) {
            
            if (server.aof_state == AOF_WAIT_REWRITE) {
                serverLog(LL_WARNING, "Writing initial AOF, can't exit.");
                return C_ERR;
            }
            serverLog(LL_WARNING, "There is a child rewriting the AOF. Killing it!");
            killAppendOnlyChild();
        }
        
        serverLog(LL_NOTICE,"Calling fsync() on the AOF file.");
        flushAppendOnlyFile(1);
        redis_fsync(server.aof_fd);
    }

    
    if ((server.saveparamslen > 0 && !nosave) || save) {
        serverLog(LL_NOTICE,"Saving the final RDB snapshot before exiting.");
        if (server.supervised_mode == SUPERVISED_SYSTEMD)
            redisCommunicateSystemd("STATUS=Saving the final RDB snapshot\n");
        
        rdbSaveInfo rsi, *rsiptr;
        rsiptr = rdbPopulateSaveInfo(&rsi);
        if (rdbSave(server.rdb_filename,rsiptr) != C_OK) {
            
            serverLog(LL_WARNING,"Error trying to save the DB, can't exit.");
            if (server.supervised_mode == SUPERVISED_SYSTEMD)
                redisCommunicateSystemd("STATUS=Error trying to save the DB, can't exit.\n");
            return C_ERR;
        }
    }

    
    moduleFireServerEvent(REDISMODULE_EVENT_SHUTDOWN,0,NULL);

    
    if (server.daemonize || server.pidfile) {
        serverLog(LL_NOTICE,"Removing the pid file.");
        unlink(server.pidfile);
    }

    
    flushSlavesOutputBuffers();

    
    closeListeningSockets(1);
    serverLog(LL_WARNING,"%s is now ready to exit, bye bye...", server.sentinel_mode ? "Sentinel" : "Redis");
    return C_OK;
}




int writeCommandsDeniedByDiskError(void) {
    if (server.stop_writes_on_bgsave_err && server.saveparamslen > 0 && server.lastbgsave_status == C_ERR)

    {
        return DISK_ERROR_TYPE_RDB;
    } else if (server.aof_state != AOF_OFF && server.aof_last_write_status == C_ERR)
    {
        return DISK_ERROR_TYPE_AOF;
    } else {
        return DISK_ERROR_TYPE_NONE;
    }
}


void pingCommand(client *c) {
    
    if (c->argc > 2) {
        addReplyErrorFormat(c,"wrong number of arguments for '%s' command", c->cmd->name);
        return;
    }

    if (c->flags & CLIENT_PUBSUB && c->resp == 2) {
        addReply(c,shared.mbulkhdr[2]);
        addReplyBulkCBuffer(c,"pong",4);
        if (c->argc == 1)
            addReplyBulkCBuffer(c,"",0);
        else addReplyBulk(c,c->argv[1]);
    } else {
        if (c->argc == 1)
            addReply(c,shared.pong);
        else addReplyBulk(c,c->argv[1]);
    }
}

void echoCommand(client *c) {
    addReplyBulk(c,c->argv[1]);
}

void timeCommand(client *c) {
    struct timeval tv;

    
    gettimeofday(&tv,NULL);
    addReplyArrayLen(c,2);
    addReplyBulkLongLong(c,tv.tv_sec);
    addReplyBulkLongLong(c,tv.tv_usec);
}


int addReplyCommandFlag(client *c, struct redisCommand *cmd, int f, char *reply) {
    if (cmd->flags & f) {
        addReplyStatus(c, reply);
        return 1;
    }
    return 0;
}


void addReplyCommand(client *c, struct redisCommand *cmd) {
    if (!cmd) {
        addReplyNull(c);
    } else {
        
        addReplyArrayLen(c, 7);
        addReplyBulkCString(c, cmd->name);
        addReplyLongLong(c, cmd->arity);

        int flagcount = 0;
        void *flaglen = addReplyDeferredLen(c);
        flagcount += addReplyCommandFlag(c,cmd,CMD_WRITE, "write");
        flagcount += addReplyCommandFlag(c,cmd,CMD_READONLY, "readonly");
        flagcount += addReplyCommandFlag(c,cmd,CMD_DENYOOM, "denyoom");
        flagcount += addReplyCommandFlag(c,cmd,CMD_ADMIN, "admin");
        flagcount += addReplyCommandFlag(c,cmd,CMD_PUBSUB, "pubsub");
        flagcount += addReplyCommandFlag(c,cmd,CMD_NOSCRIPT, "noscript");
        flagcount += addReplyCommandFlag(c,cmd,CMD_RANDOM, "random");
        flagcount += addReplyCommandFlag(c,cmd,CMD_SORT_FOR_SCRIPT,"sort_for_script");
        flagcount += addReplyCommandFlag(c,cmd,CMD_LOADING, "loading");
        flagcount += addReplyCommandFlag(c,cmd,CMD_STALE, "stale");
        flagcount += addReplyCommandFlag(c,cmd,CMD_SKIP_MONITOR, "skip_monitor");
        flagcount += addReplyCommandFlag(c,cmd,CMD_SKIP_SLOWLOG, "skip_slowlog");
        flagcount += addReplyCommandFlag(c,cmd,CMD_ASKING, "asking");
        flagcount += addReplyCommandFlag(c,cmd,CMD_FAST, "fast");
        flagcount += addReplyCommandFlag(c,cmd,CMD_NO_AUTH, "no_auth");
        if ((cmd->getkeys_proc && !(cmd->flags & CMD_MODULE)) || cmd->flags & CMD_MODULE_GETKEYS)
        {
            addReplyStatus(c, "movablekeys");
            flagcount += 1;
        }
        setDeferredSetLen(c, flaglen, flagcount);

        addReplyLongLong(c, cmd->firstkey);
        addReplyLongLong(c, cmd->lastkey);
        addReplyLongLong(c, cmd->keystep);

        addReplyCommandCategories(c,cmd);
    }
}


void commandCommand(client *c) {
    dictIterator *di;
    dictEntry *de;

    if (c->argc == 2 && !strcasecmp(c->argv[1]->ptr,"help")) {
        const char *help[] = {
"(no subcommand) -- Return details about all Redis commands.", "COUNT -- Return the total number of commands in this Redis server.", "GETKEYS <full-command> -- Return the keys from a full Redis command.", "INFO [command-name ...] -- Return details about multiple Redis commands.", NULL };




        addReplyHelp(c, help);
    } else if (c->argc == 1) {
        addReplyArrayLen(c, dictSize(server.commands));
        di = dictGetIterator(server.commands);
        while ((de = dictNext(di)) != NULL) {
            addReplyCommand(c, dictGetVal(de));
        }
        dictReleaseIterator(di);
    } else if (!strcasecmp(c->argv[1]->ptr, "info")) {
        int i;
        addReplyArrayLen(c, c->argc-2);
        for (i = 2; i < c->argc; i++) {
            addReplyCommand(c, dictFetchValue(server.commands, c->argv[i]->ptr));
        }
    } else if (!strcasecmp(c->argv[1]->ptr, "count") && c->argc == 2) {
        addReplyLongLong(c, dictSize(server.commands));
    } else if (!strcasecmp(c->argv[1]->ptr,"getkeys") && c->argc >= 3) {
        struct redisCommand *cmd = lookupCommand(c->argv[2]->ptr);
        getKeysResult result = GETKEYS_RESULT_INIT;
        int j;

        if (!cmd) {
            addReplyError(c,"Invalid command specified");
            return;
        } else if (cmd->getkeys_proc == NULL && cmd->firstkey == 0) {
            addReplyError(c,"The command has no key arguments");
            return;
        } else if ((cmd->arity > 0 && cmd->arity != c->argc-2) || ((c->argc-2) < -cmd->arity))
        {
            addReplyError(c,"Invalid number of arguments specified for command");
            return;
        }

        if (!getKeysFromCommand(cmd,c->argv+2,c->argc-2,&result)) {
            addReplyError(c,"Invalid arguments specified for command");
        } else {
            addReplyArrayLen(c,result.numkeys);
            for (j = 0; j < result.numkeys; j++) addReplyBulk(c,c->argv[result.keys[j]+2]);
        }
        getKeysFreeResult(&result);
    } else {
        addReplySubcommandSyntaxError(c);
    }
}


void bytesToHuman(char *s, unsigned long long n) {
    double d;

    if (n < 1024) {
        
        sprintf(s,"%lluB",n);
    } else if (n < (1024*1024)) {
        d = (double)n/(1024);
        sprintf(s,"%.2fK",d);
    } else if (n < (1024LL*1024*1024)) {
        d = (double)n/(1024*1024);
        sprintf(s,"%.2fM",d);
    } else if (n < (1024LL*1024*1024*1024)) {
        d = (double)n/(1024LL*1024*1024);
        sprintf(s,"%.2fG",d);
    } else if (n < (1024LL*1024*1024*1024*1024)) {
        d = (double)n/(1024LL*1024*1024*1024);
        sprintf(s,"%.2fT",d);
    } else if (n < (1024LL*1024*1024*1024*1024*1024)) {
        d = (double)n/(1024LL*1024*1024*1024*1024);
        sprintf(s,"%.2fP",d);
    } else {
        
        sprintf(s,"%lluB",n);
    }
}


sds genRedisInfoString(const char *section) {
    sds info = sdsempty();
    time_t uptime = server.unixtime-server.stat_starttime;
    int j;
    struct rusage self_ru, c_ru;
    int allsections = 0, defsections = 0, everything = 0, modules = 0;
    int sections = 0;

    if (section == NULL) section = "default";
    allsections = strcasecmp(section,"all") == 0;
    defsections = strcasecmp(section,"default") == 0;
    everything = strcasecmp(section,"everything") == 0;
    modules = strcasecmp(section,"modules") == 0;
    if (everything) allsections = 1;

    getrusage(RUSAGE_SELF, &self_ru);
    getrusage(RUSAGE_CHILDREN, &c_ru);

    
    if (allsections || defsections || !strcasecmp(section,"server")) {
        static int call_uname = 1;
        static struct utsname name;
        char *mode;

        if (server.cluster_enabled) mode = "cluster";
        else if (server.sentinel_mode) mode = "sentinel";
        else mode = "standalone";

        if (sections++) info = sdscat(info,"\r\n");

        if (call_uname) {
            
            uname(&name);
            call_uname = 0;
        }

        info = sdscatfmt(info, "# Server\r\n" "redis_version:%s\r\n" "redis_git_sha1:%s\r\n" "redis_git_dirty:%i\r\n" "redis_build_id:%s\r\n" "redis_mode:%s\r\n" "os:%s %s %s\r\n" "arch_bits:%i\r\n" "multiplexing_api:%s\r\n" "atomicvar_api:%s\r\n" "gcc_version:%i.%i.%i\r\n" "process_id:%I\r\n" "run_id:%s\r\n" "tcp_port:%i\r\n" "uptime_in_seconds:%I\r\n" "uptime_in_days:%I\r\n" "hz:%i\r\n" "configured_hz:%i\r\n" "lru_clock:%u\r\n" "executable:%s\r\n" "config_file:%s\r\n" "io_threads_active:%i\r\n", REDIS_VERSION, redisGitSHA1(), strtol(redisGitDirty(),NULL,10) > 0, redisBuildIdString(), mode, name.sysname, name.release, name.machine, server.arch_bits, aeGetApiName(), REDIS_ATOMIC_API,  __GNUC__,__GNUC_MINOR__,__GNUC_PATCHLEVEL__,  0,0,0,  (int64_t) getpid(), server.runid, server.port ? server.port : server.tls_port, (int64_t)uptime, (int64_t)(uptime/(3600*24)), server.hz, server.config_hz, server.lruclock, server.executable ? server.executable : "", server.configfile ? server.configfile : "", server.io_threads_active);














































    }

    
    if (allsections || defsections || !strcasecmp(section,"clients")) {
        size_t maxin, maxout;
        getExpansiveClientsInfo(&maxin,&maxout);
        if (sections++) info = sdscat(info,"\r\n");
        info = sdscatprintf(info, "# Clients\r\n" "connected_clients:%lu\r\n" "client_recent_max_input_buffer:%zu\r\n" "client_recent_max_output_buffer:%zu\r\n" "blocked_clients:%d\r\n" "tracking_clients:%d\r\n" "clients_in_timeout_table:%llu\r\n", listLength(server.clients)-listLength(server.slaves), maxin, maxout, server.blocked_clients, server.tracking_clients, (unsigned long long) raxSize(server.clients_timeout_table));











    }

    
    if (allsections || defsections || !strcasecmp(section,"memory")) {
        char hmem[64];
        char peak_hmem[64];
        char total_system_hmem[64];
        char used_memory_lua_hmem[64];
        char used_memory_scripts_hmem[64];
        char used_memory_rss_hmem[64];
        char maxmemory_hmem[64];
        size_t zmalloc_used = zmalloc_used_memory();
        size_t total_system_mem = server.system_memory_size;
        const char *evict_policy = evictPolicyToString();
        long long memory_lua = server.lua ? (long long)lua_gc(server.lua,LUA_GCCOUNT,0)*1024 : 0;
        struct redisMemOverhead *mh = getMemoryOverheadData();

        
        if (zmalloc_used > server.stat_peak_memory)
            server.stat_peak_memory = zmalloc_used;

        bytesToHuman(hmem,zmalloc_used);
        bytesToHuman(peak_hmem,server.stat_peak_memory);
        bytesToHuman(total_system_hmem,total_system_mem);
        bytesToHuman(used_memory_lua_hmem,memory_lua);
        bytesToHuman(used_memory_scripts_hmem,mh->lua_caches);
        bytesToHuman(used_memory_rss_hmem,server.cron_malloc_stats.process_rss);
        bytesToHuman(maxmemory_hmem,server.maxmemory);

        if (sections++) info = sdscat(info,"\r\n");
        info = sdscatprintf(info, "# Memory\r\n" "used_memory:%zu\r\n" "used_memory_human:%s\r\n" "used_memory_rss:%zu\r\n" "used_memory_rss_human:%s\r\n" "used_memory_peak:%zu\r\n" "used_memory_peak_human:%s\r\n" "used_memory_peak_perc:%.2f%%\r\n" "used_memory_overhead:%zu\r\n" "used_memory_startup:%zu\r\n" "used_memory_dataset:%zu\r\n" "used_memory_dataset_perc:%.2f%%\r\n" "allocator_allocated:%zu\r\n" "allocator_active:%zu\r\n" "allocator_resident:%zu\r\n" "total_system_memory:%lu\r\n" "total_system_memory_human:%s\r\n" "used_memory_lua:%lld\r\n" "used_memory_lua_human:%s\r\n" "used_memory_scripts:%lld\r\n" "used_memory_scripts_human:%s\r\n" "number_of_cached_scripts:%lu\r\n" "maxmemory:%lld\r\n" "maxmemory_human:%s\r\n" "maxmemory_policy:%s\r\n" "allocator_frag_ratio:%.2f\r\n" "allocator_frag_bytes:%zu\r\n" "allocator_rss_ratio:%.2f\r\n" "allocator_rss_bytes:%zd\r\n" "rss_overhead_ratio:%.2f\r\n" "rss_overhead_bytes:%zd\r\n" "mem_fragmentation_ratio:%.2f\r\n" "mem_fragmentation_bytes:%zd\r\n" "mem_not_counted_for_evict:%zu\r\n" "mem_replication_backlog:%zu\r\n" "mem_clients_slaves:%zu\r\n" "mem_clients_normal:%zu\r\n" "mem_aof_buffer:%zu\r\n" "mem_allocator:%s\r\n" "active_defrag_running:%d\r\n" "lazyfree_pending_objects:%zu\r\n", zmalloc_used, hmem, server.cron_malloc_stats.process_rss, used_memory_rss_hmem, server.stat_peak_memory, peak_hmem, mh->peak_perc, mh->overhead_total, mh->startup_allocated, mh->dataset, mh->dataset_perc, server.cron_malloc_stats.allocator_allocated, server.cron_malloc_stats.allocator_active, server.cron_malloc_stats.allocator_resident, (unsigned long)total_system_mem, total_system_hmem, memory_lua, used_memory_lua_hmem, (long long) mh->lua_caches, used_memory_scripts_hmem, dictSize(server.lua_scripts), server.maxmemory, maxmemory_hmem, evict_policy, mh->allocator_frag, mh->allocator_frag_bytes, mh->allocator_rss, mh->allocator_rss_bytes, mh->rss_extra, mh->rss_extra_bytes, mh->total_frag, mh->total_frag_bytes, freeMemoryGetNotCountedMemory(), mh->repl_backlog, mh->clients_slaves, mh->clients_normal, mh->aof_buffer, ZMALLOC_LIB, server.active_defrag_running, lazyfreeGetPendingObjectsCount()
















































































        );
        freeMemoryOverheadData(mh);
    }

    
    if (allsections || defsections || !strcasecmp(section,"persistence")) {
        if (sections++) info = sdscat(info,"\r\n");
        info = sdscatprintf(info, "# Persistence\r\n" "loading:%d\r\n" "rdb_changes_since_last_save:%lld\r\n" "rdb_bgsave_in_progress:%d\r\n" "rdb_last_save_time:%jd\r\n" "rdb_last_bgsave_status:%s\r\n" "rdb_last_bgsave_time_sec:%jd\r\n" "rdb_current_bgsave_time_sec:%jd\r\n" "rdb_last_cow_size:%zu\r\n" "aof_enabled:%d\r\n" "aof_rewrite_in_progress:%d\r\n" "aof_rewrite_scheduled:%d\r\n" "aof_last_rewrite_time_sec:%jd\r\n" "aof_current_rewrite_time_sec:%jd\r\n" "aof_last_bgrewrite_status:%s\r\n" "aof_last_write_status:%s\r\n" "aof_last_cow_size:%zu\r\n" "module_fork_in_progress:%d\r\n" "module_fork_last_cow_size:%zu\r\n", server.loading, server.dirty, server.rdb_child_pid != -1, (intmax_t)server.lastsave, (server.lastbgsave_status == C_OK) ? "ok" : "err", (intmax_t)server.rdb_save_time_last, (intmax_t)((server.rdb_child_pid == -1) ? -1 : time(NULL)-server.rdb_save_time_start), server.stat_rdb_cow_bytes, server.aof_state != AOF_OFF, server.aof_child_pid != -1, server.aof_rewrite_scheduled, (intmax_t)server.aof_rewrite_time_last, (intmax_t)((server.aof_child_pid == -1) ? -1 : time(NULL)-server.aof_rewrite_time_start), (server.aof_lastbgrewrite_status == C_OK) ? "ok" : "err", (server.aof_last_write_status == C_OK) ? "ok" : "err", server.stat_aof_cow_bytes, server.module_child_pid != -1, server.stat_module_cow_bytes);







































        if (server.aof_enabled) {
            info = sdscatprintf(info, "aof_current_size:%lld\r\n" "aof_base_size:%lld\r\n" "aof_pending_rewrite:%d\r\n" "aof_buffer_length:%zu\r\n" "aof_rewrite_buffer_length:%lu\r\n" "aof_pending_bio_fsync:%llu\r\n" "aof_delayed_fsync:%lu\r\n", (long long) server.aof_current_size, (long long) server.aof_rewrite_base_size, server.aof_rewrite_scheduled, sdslen(server.aof_buf), aofRewriteBufferSize(), bioPendingJobsOfType(BIO_AOF_FSYNC), server.aof_delayed_fsync);













        }

        if (server.loading) {
            double perc;
            time_t eta, elapsed;
            off_t remaining_bytes = server.loading_total_bytes- server.loading_loaded_bytes;

            perc = ((double)server.loading_loaded_bytes / (server.loading_total_bytes+1)) * 100;

            elapsed = time(NULL)-server.loading_start_time;
            if (elapsed == 0) {
                eta = 1; 
            } else {
                eta = (elapsed*remaining_bytes)/(server.loading_loaded_bytes+1);
            }

            info = sdscatprintf(info, "loading_start_time:%jd\r\n" "loading_total_bytes:%llu\r\n" "loading_loaded_bytes:%llu\r\n" "loading_loaded_perc:%.2f\r\n" "loading_eta_seconds:%jd\r\n", (intmax_t) server.loading_start_time, (unsigned long long) server.loading_total_bytes, (unsigned long long) server.loading_loaded_bytes, perc, (intmax_t)eta );










        }
    }

    
    if (allsections || defsections || !strcasecmp(section,"stats")) {
        if (sections++) info = sdscat(info,"\r\n");
        info = sdscatprintf(info, "# Stats\r\n" "total_connections_received:%lld\r\n" "total_commands_processed:%lld\r\n" "instantaneous_ops_per_sec:%lld\r\n" "total_net_input_bytes:%lld\r\n" "total_net_output_bytes:%lld\r\n" "instantaneous_input_kbps:%.2f\r\n" "instantaneous_output_kbps:%.2f\r\n" "rejected_connections:%lld\r\n" "sync_full:%lld\r\n" "sync_partial_ok:%lld\r\n" "sync_partial_err:%lld\r\n" "expired_keys:%lld\r\n" "expired_stale_perc:%.2f\r\n" "expired_time_cap_reached_count:%lld\r\n" "expire_cycle_cpu_milliseconds:%lld\r\n" "evicted_keys:%lld\r\n" "keyspace_hits:%lld\r\n" "keyspace_misses:%lld\r\n" "pubsub_channels:%ld\r\n" "pubsub_patterns:%lu\r\n" "latest_fork_usec:%lld\r\n" "migrate_cached_sockets:%ld\r\n" "slave_expires_tracked_keys:%zu\r\n" "active_defrag_hits:%lld\r\n" "active_defrag_misses:%lld\r\n" "active_defrag_key_hits:%lld\r\n" "active_defrag_key_misses:%lld\r\n" "tracking_total_keys:%lld\r\n" "tracking_total_items:%lld\r\n" "tracking_total_prefixes:%lld\r\n" "unexpected_error_replies:%lld\r\n" "total_reads_processed:%lld\r\n" "total_writes_processed:%lld\r\n" "io_threaded_reads_processed:%lld\r\n" "io_threaded_writes_processed:%lld\r\n", server.stat_numconnections, server.stat_numcommands, getInstantaneousMetric(STATS_METRIC_COMMAND), server.stat_net_input_bytes, server.stat_net_output_bytes, (float)getInstantaneousMetric(STATS_METRIC_NET_INPUT)/1024, (float)getInstantaneousMetric(STATS_METRIC_NET_OUTPUT)/1024, server.stat_rejected_conn, server.stat_sync_full, server.stat_sync_partial_ok, server.stat_sync_partial_err, server.stat_expiredkeys, server.stat_expired_stale_perc*100, server.stat_expired_time_cap_reached_count, server.stat_expire_cycle_time_used/1000, server.stat_evictedkeys, server.stat_keyspace_hits, server.stat_keyspace_misses, dictSize(server.pubsub_channels), listLength(server.pubsub_patterns), server.stat_fork_time, dictSize(server.migrate_cached_sockets), getSlaveKeyWithExpireCount(), server.stat_active_defrag_hits, server.stat_active_defrag_misses, server.stat_active_defrag_key_hits, server.stat_active_defrag_key_misses, (unsigned long long) trackingGetTotalKeys(), (unsigned long long) trackingGetTotalItems(), (unsigned long long) trackingGetTotalPrefixes(), server.stat_unexpected_error_replies, server.stat_total_reads_processed, server.stat_total_writes_processed, server.stat_io_reads_processed, server.stat_io_writes_processed);






































































    }

    
    if (allsections || defsections || !strcasecmp(section,"replication")) {
        if (sections++) info = sdscat(info,"\r\n");
        info = sdscatprintf(info, "# Replication\r\n" "role:%s\r\n", server.masterhost == NULL ? "master" : "slave");


        if (server.masterhost) {
            long long slave_repl_offset = 1;

            if (server.master)
                slave_repl_offset = server.master->reploff;
            else if (server.cached_master)
                slave_repl_offset = server.cached_master->reploff;

            info = sdscatprintf(info, "master_host:%s\r\n" "master_port:%d\r\n" "master_link_status:%s\r\n" "master_last_io_seconds_ago:%d\r\n" "master_sync_in_progress:%d\r\n" "slave_repl_offset:%lld\r\n" ,server.masterhost, server.masterport, (server.repl_state == REPL_STATE_CONNECTED) ? "up" : "down", server.master ? ((int)(server.unixtime-server.master->lastinteraction)) : -1, server.repl_state == REPL_STATE_TRANSFER, slave_repl_offset );















            if (server.repl_state == REPL_STATE_TRANSFER) {
                info = sdscatprintf(info, "master_sync_left_bytes:%lld\r\n" "master_sync_last_io_seconds_ago:%d\r\n" , (long long)


                        (server.repl_transfer_size - server.repl_transfer_read), (int)(server.unixtime-server.repl_transfer_lastio)
                );
            }

            if (server.repl_state != REPL_STATE_CONNECTED) {
                info = sdscatprintf(info, "master_link_down_since_seconds:%jd\r\n", (intmax_t)(server.unixtime-server.repl_down_since));

            }
            info = sdscatprintf(info, "slave_priority:%d\r\n" "slave_read_only:%d\r\n", server.slave_priority, server.repl_slave_ro);



        }

        info = sdscatprintf(info, "connected_slaves:%lu\r\n", listLength(server.slaves));


        
        if (server.repl_min_slaves_to_write && server.repl_min_slaves_max_lag) {
            info = sdscatprintf(info, "min_slaves_good_slaves:%d\r\n", server.repl_good_slaves_count);

        }

        if (listLength(server.slaves)) {
            int slaveid = 0;
            listNode *ln;
            listIter li;

            listRewind(server.slaves,&li);
            while((ln = listNext(&li))) {
                client *slave = listNodeValue(ln);
                char *state = NULL;
                char ip[NET_IP_STR_LEN], *slaveip = slave->slave_ip;
                int port;
                long lag = 0;

                if (slaveip[0] == '\0') {
                    if (connPeerToString(slave->conn,ip,sizeof(ip),&port) == -1)
                        continue;
                    slaveip = ip;
                }
                switch(slave->replstate) {
                case SLAVE_STATE_WAIT_BGSAVE_START:
                case SLAVE_STATE_WAIT_BGSAVE_END:
                    state = "wait_bgsave";
                    break;
                case SLAVE_STATE_SEND_BULK:
                    state = "send_bulk";
                    break;
                case SLAVE_STATE_ONLINE:
                    state = "online";
                    break;
                }
                if (state == NULL) continue;
                if (slave->replstate == SLAVE_STATE_ONLINE)
                    lag = time(NULL) - slave->repl_ack_time;

                info = sdscatprintf(info, "slave%d:ip=%s,port=%d,state=%s," "offset=%lld,lag=%ld\r\n", slaveid,slaveip,slave->slave_listening_port,state, slave->repl_ack_off, lag);



                slaveid++;
            }
        }
        info = sdscatprintf(info, "master_replid:%s\r\n" "master_replid2:%s\r\n" "master_repl_offset:%lld\r\n" "second_repl_offset:%lld\r\n" "repl_backlog_active:%d\r\n" "repl_backlog_size:%lld\r\n" "repl_backlog_first_byte_offset:%lld\r\n" "repl_backlog_histlen:%lld\r\n", server.replid, server.replid2, server.master_repl_offset, server.second_replid_offset, server.repl_backlog != NULL, server.repl_backlog_size, server.repl_backlog_off, server.repl_backlog_histlen);















    }

    
    if (allsections || defsections || !strcasecmp(section,"cpu")) {
        if (sections++) info = sdscat(info,"\r\n");
        info = sdscatprintf(info, "# CPU\r\n" "used_cpu_sys:%ld.%06ld\r\n" "used_cpu_user:%ld.%06ld\r\n" "used_cpu_sys_children:%ld.%06ld\r\n" "used_cpu_user_children:%ld.%06ld\r\n", (long)self_ru.ru_stime.tv_sec, (long)self_ru.ru_stime.tv_usec, (long)self_ru.ru_utime.tv_sec, (long)self_ru.ru_utime.tv_usec, (long)c_ru.ru_stime.tv_sec, (long)c_ru.ru_stime.tv_usec, (long)c_ru.ru_utime.tv_sec, (long)c_ru.ru_utime.tv_usec);








    }

    
    if (allsections || defsections || !strcasecmp(section,"modules")) {
        if (sections++) info = sdscat(info,"\r\n");
        info = sdscatprintf(info,"# Modules\r\n");
        info = genModulesInfoString(info);
    }

    
    if (allsections || !strcasecmp(section,"commandstats")) {
        if (sections++) info = sdscat(info,"\r\n");
        info = sdscatprintf(info, "# Commandstats\r\n");

        struct redisCommand *c;
        dictEntry *de;
        dictIterator *di;
        di = dictGetSafeIterator(server.commands);
        while((de = dictNext(di)) != NULL) {
            c = (struct redisCommand *) dictGetVal(de);
            if (!c->calls) continue;
            info = sdscatprintf(info, "cmdstat_%s:calls=%lld,usec=%lld,usec_per_call=%.2f\r\n", c->name, c->calls, c->microseconds, (c->calls == 0) ? 0 : ((float)c->microseconds/c->calls));


        }
        dictReleaseIterator(di);
    }

    
    if (allsections || defsections || !strcasecmp(section,"cluster")) {
        if (sections++) info = sdscat(info,"\r\n");
        info = sdscatprintf(info, "# Cluster\r\n" "cluster_enabled:%d\r\n", server.cluster_enabled);


    }

    
    if (allsections || defsections || !strcasecmp(section,"keyspace")) {
        if (sections++) info = sdscat(info,"\r\n");
        info = sdscatprintf(info, "# Keyspace\r\n");
        for (j = 0; j < server.dbnum; j++) {
            long long keys, vkeys;

            keys = dictSize(server.db[j].dict);
            vkeys = dictSize(server.db[j].expires);
            if (keys || vkeys) {
                info = sdscatprintf(info, "db%d:keys=%lld,expires=%lld,avg_ttl=%lld\r\n", j, keys, vkeys, server.db[j].avg_ttl);

            }
        }
    }

    
    if (everything || modules || (!allsections && !defsections && sections==0)) {
        info = modulesCollectInfo(info, everything || modules ? NULL: section, 0, sections);


    }
    return info;
}

void infoCommand(client *c) {
    char *section = c->argc == 2 ? c->argv[1]->ptr : "default";

    if (c->argc > 2) {
        addReply(c,shared.syntaxerr);
        return;
    }
    sds info = genRedisInfoString(section);
    addReplyVerbatim(c,info,sdslen(info),"txt");
    sdsfree(info);
}

void monitorCommand(client *c) {
    
    if (c->flags & CLIENT_SLAVE) return;

    c->flags |= (CLIENT_SLAVE|CLIENT_MONITOR);
    listAddNodeTail(server.monitors,c);
    addReply(c,shared.ok);
}



int checkIgnoreWarning(const char *warning) {
    int argc, j;
    sds *argv = sdssplitargs(server.ignore_warnings, &argc);
    if (argv == NULL)
        return 0;

    for (j = 0; j < argc; j++) {
        char *flag = argv[j];
        if (!strcasecmp(flag, warning))
            break;
    }
    sdsfreesplitres(argv,argc);
    return j < argc;
}


int linuxOvercommitMemoryValue(void) {
    FILE *fp = fopen("/proc/sys/vm/overcommit_memory","r");
    char buf[64];

    if (!fp) return -1;
    if (fgets(buf,64,fp) == NULL) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    return atoi(buf);
}

void linuxMemoryWarnings(void) {
    if (linuxOvercommitMemoryValue() == 0) {
        serverLog(LL_WARNING,"WARNING overcommit_memory is set to 0! Background save may fail under low memory condition. To fix this issue add 'vm.overcommit_memory = 1' to /etc/sysctl.conf and then reboot or run the command 'sysctl vm.overcommit_memory=1' for this to take effect.");
    }
    if (THPIsEnabled()) {
        serverLog(LL_WARNING,"WARNING you have Transparent Huge Pages (THP) support enabled in your kernel. This will create latency and memory usage issues with Redis. To fix this issue run the command 'echo madvise > /sys/kernel/mm/transparent_hugepage/enabled' as root, and add it to your /etc/rc.local in order to retain the setting after a reboot. Redis must be restarted after THP is disabled (set to 'madvise' or 'never').");
    }
}




static int smapsGetSharedDirty(unsigned long addr) {
    int ret, in_mapping = 0, val = -1;
    unsigned long from, to;
    char buf[64];
    FILE *f;

    f = fopen("/proc/self/smaps", "r");
    if (!f) return -1;

    while (1) {
        if (!fgets(buf, sizeof(buf), f))
            break;

        ret = sscanf(buf, "%lx-%lx", &from, &to);
        if (ret == 2)
            in_mapping = from <= addr && addr < to;

        if (in_mapping && !memcmp(buf, "Shared_Dirty:", 13)) {
            sscanf(buf, "%*s %d", &val);
            
            break;
        }
    }

    fclose(f);
    return val;
}


int linuxMadvFreeForkBugCheck(void) {
    int ret, pipefd[2] = { -1, -1 };
    pid_t pid;
    char *p = NULL, *q;
    int bug_found = 0;
    long page_size = sysconf(_SC_PAGESIZE);
    long map_size = 3 * page_size;

    
    p = mmap(NULL, map_size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) {
        serverLog(LL_WARNING, "Failed to mmap(): %s", strerror(errno));
        return -1;
    }

    q = p + page_size;

    
    ret = mprotect(q, page_size, PROT_READ | PROT_WRITE);
    if (ret < 0) {
        serverLog(LL_WARNING, "Failed to mprotect(): %s", strerror(errno));
        bug_found = -1;
        goto exit;
    }

    
    *(volatile char*)q = 0;

    



    ret = madvise(q, page_size, MADV_FREE);
    if (ret < 0) {
        
        if (errno == EINVAL) goto exit;

        serverLog(LL_WARNING, "Failed to madvise(): %s", strerror(errno));
        bug_found = -1;
        goto exit;
    }

    
    *(volatile char*)q = 0;

    
    ret = pipe(pipefd);
    if (ret < 0) {
        serverLog(LL_WARNING, "Failed to create pipe: %s", strerror(errno));
        bug_found = -1;
        goto exit;
    }

    
    pid = fork();
    if (pid < 0) {
        serverLog(LL_WARNING, "Failed to fork: %s", strerror(errno));
        bug_found = -1;
        goto exit;
    } else if (!pid) {
        
        ret = smapsGetSharedDirty((unsigned long) q);
        if (!ret)
            bug_found = 1;
        else if (ret == -1)     
            bug_found = -1;

        if (write(pipefd[1], &bug_found, sizeof(bug_found)) < 0)
            serverLog(LL_WARNING, "Failed to write to parent: %s", strerror(errno));
        exit(0);
    } else {
        
        ret = read(pipefd[0], &bug_found, sizeof(bug_found));
        if (ret < 0) {
            serverLog(LL_WARNING, "Failed to read from child: %s", strerror(errno));
            bug_found = -1;
        }

        
        waitpid(pid, NULL, 0);
    }

exit:
    
    if (pipefd[0] != -1) close(pipefd[0]);
    if (pipefd[1] != -1) close(pipefd[1]);
    if (p != NULL) munmap(p, map_size);

    return bug_found;
}



void createPidFile(void) {
    
    if (!server.pidfile) server.pidfile = zstrdup(CONFIG_DEFAULT_PID_FILE);

    
    FILE *fp = fopen(server.pidfile,"w");
    if (fp) {
        fprintf(fp,"%d\n",(int)getpid());
        fclose(fp);
    }
}

void daemonize(void) {
    int fd;

    if (fork() != 0) exit(0); 
    setsid(); 

    
    if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) close(fd);
    }
}

void version(void) {
    printf("Redis server v=%s sha=%s:%d malloc=%s bits=%d build=%llx\n", REDIS_VERSION, redisGitSHA1(), atoi(redisGitDirty()) > 0, ZMALLOC_LIB, sizeof(long) == 4 ? 32 : 64, (unsigned long long) redisBuildId());





    exit(0);
}

void usage(void) {
    fprintf(stderr,"Usage: ./redis-server [/path/to/redis.conf] [options]\n");
    fprintf(stderr,"       ./redis-server - (read config from stdin)\n");
    fprintf(stderr,"       ./redis-server -v or --version\n");
    fprintf(stderr,"       ./redis-server -h or --help\n");
    fprintf(stderr,"       ./redis-server --test-memory <megabytes>\n\n");
    fprintf(stderr,"Examples:\n");
    fprintf(stderr,"       ./redis-server (run the server with default conf)\n");
    fprintf(stderr,"       ./redis-server /etc/redis/6379.conf\n");
    fprintf(stderr,"       ./redis-server --port 7777\n");
    fprintf(stderr,"       ./redis-server --port 7777 --replicaof 127.0.0.1 8888\n");
    fprintf(stderr,"       ./redis-server /etc/myredis.conf --loglevel verbose\n\n");
    fprintf(stderr,"Sentinel mode:\n");
    fprintf(stderr,"       ./redis-server /etc/sentinel.conf --sentinel\n");
    exit(1);
}

void redisAsciiArt(void) {

    char *buf = zmalloc(1024*16);
    char *mode;

    if (server.cluster_enabled) mode = "cluster";
    else if (server.sentinel_mode) mode = "sentinel";
    else mode = "standalone";

    
    int show_logo = ((!server.syslog_enabled && server.logfile[0] == '\0' && isatty(fileno(stdout))) || server.always_show_logo);



    if (!show_logo) {
        serverLog(LL_NOTICE, "Running mode=%s, port=%d.", mode, server.port ? server.port : server.tls_port );


    } else {
        snprintf(buf,1024*16,ascii_logo, REDIS_VERSION, redisGitSHA1(), strtol(redisGitDirty(),NULL,10) > 0, (sizeof(long) == 8) ? "64" : "32", mode, server.port ? server.port : server.tls_port, (long) getpid()





        );
        serverLogRaw(LL_NOTICE|LL_RAW,buf);
    }
    zfree(buf);
}

static void sigShutdownHandler(int sig) {
    char *msg;

    switch (sig) {
    case SIGINT:
        msg = "Received SIGINT scheduling shutdown...";
        break;
    case SIGTERM:
        msg = "Received SIGTERM scheduling shutdown...";
        break;
    default:
        msg = "Received shutdown signal, scheduling shutdown...";
    };

    
    if (server.shutdown_asap && sig == SIGINT) {
        serverLogFromHandler(LL_WARNING, "You insist... exiting now.");
        rdbRemoveTempFile(getpid(), 1);
        exit(1); 
    } else if (server.loading) {
        serverLogFromHandler(LL_WARNING, "Received shutdown signal during loading, exiting now.");
        exit(0);
    }

    serverLogFromHandler(LL_WARNING, msg);
    server.shutdown_asap = 1;
}

void setupSignalHandlers(void) {
    struct sigaction act;

    
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = sigShutdownHandler;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);


    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_NODEFER | SA_RESETHAND | SA_SIGINFO;
    act.sa_sigaction = sigsegvHandler;
    sigaction(SIGSEGV, &act, NULL);
    sigaction(SIGBUS, &act, NULL);
    sigaction(SIGFPE, &act, NULL);
    sigaction(SIGILL, &act, NULL);

    return;
}


static void sigKillChildHandler(int sig) {
    UNUSED(sig);
    int level = server.in_fork_child == CHILD_TYPE_MODULE? LL_VERBOSE: LL_WARNING;
    serverLogFromHandler(level, "Received SIGUSR1 in child, exiting now.");
    exitFromChild(SERVER_CHILD_NOERROR_RETVAL);
}

void setupChildSignalHandlers(void) {
    struct sigaction act;

    
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = sigKillChildHandler;
    sigaction(SIGUSR1, &act, NULL);
    return;
}


void closeClildUnusedResourceAfterFork() {
    closeListeningSockets(0);
    if (server.cluster_enabled && server.cluster_config_file_lock_fd != -1)
        close(server.cluster_config_file_lock_fd);  

    
    zfree(server.pidfile);
    server.pidfile = NULL;
}


int redisFork(int purpose) {
    int childpid;
    long long start = ustime();
    if ((childpid = fork()) == 0) {
        
        server.in_fork_child = purpose;
        setOOMScoreAdj(CONFIG_OOM_BGCHILD);
        setupChildSignalHandlers();
        closeClildUnusedResourceAfterFork();
    } else {
        
        server.stat_fork_time = ustime()-start;
        server.stat_fork_rate = (double) zmalloc_used_memory() * 1000000 / server.stat_fork_time / (1024*1024*1024); 
        latencyAddSampleIfNeeded("fork",server.stat_fork_time/1000);
        if (childpid == -1) {
            return -1;
        }
    }
    return childpid;
}

void sendChildCOWInfo(int ptype, char *pname) {
    size_t private_dirty = zmalloc_get_private_dirty(-1);

    if (private_dirty) {
        serverLog(LL_NOTICE, "%s: %zu MB of memory used by copy-on-write", pname, private_dirty/(1024*1024));

    }

    server.child_info_data.cow_size = private_dirty;
    sendChildInfo(ptype);
}

void memtest(size_t megabytes, int passes);


int checkForSentinelMode(int argc, char **argv) {
    int j;

    if (strstr(argv[0],"redis-sentinel") != NULL) return 1;
    for (j = 1; j < argc; j++)
        if (!strcmp(argv[j],"--sentinel")) return 1;
    return 0;
}


void loadDataFromDisk(void) {
    long long start = ustime();
    if (server.aof_state == AOF_ON) {
        if (loadAppendOnlyFile(server.aof_filename) == C_OK)
            serverLog(LL_NOTICE,"DB loaded from append only file: %.3f seconds",(float)(ustime()-start)/1000000);
    } else {
        rdbSaveInfo rsi = RDB_SAVE_INFO_INIT;
        errno = 0; 
        if (rdbLoad(server.rdb_filename,&rsi,RDBFLAGS_NONE) == C_OK) {
            serverLog(LL_NOTICE,"DB loaded from disk: %.3f seconds", (float)(ustime()-start)/1000000);

            
            if ((server.masterhost || (server.cluster_enabled && nodeIsSlave(server.cluster->myself))) && rsi.repl_id_is_set && rsi.repl_offset != -1 &&  rsi.repl_stream_db != -1)





            {
                memcpy(server.replid,rsi.repl_id,sizeof(server.replid));
                server.master_repl_offset = rsi.repl_offset;
                
                replicationCacheMasterUsingMyself();
                selectDb(server.cached_master,rsi.repl_stream_db);
            }
        } else if (errno != ENOENT) {
            serverLog(LL_WARNING,"Fatal error loading the DB: %s. Exiting.",strerror(errno));
            exit(1);
        }
    }
}

void redisOutOfMemoryHandler(size_t allocation_size) {
    serverLog(LL_WARNING,"Out Of Memory allocating %zu bytes!", allocation_size);
    serverPanic("Redis aborting for OUT OF MEMORY. Allocating %zu bytes!",  allocation_size);
}

void redisSetProcTitle(char *title) {

    char *server_mode = "";
    if (server.cluster_enabled) server_mode = " [cluster]";
    else if (server.sentinel_mode) server_mode = " [sentinel]";

    setproctitle("%s %s:%d%s", title, server.bindaddr_count ? server.bindaddr[0] : "*", server.port ? server.port : server.tls_port, server_mode);




    UNUSED(title);

}

void redisSetCpuAffinity(const char *cpulist) {

    setcpuaffinity(cpulist);

    UNUSED(cpulist);

}



int redisSupervisedUpstart(void) {
    const char *upstart_job = getenv("UPSTART_JOB");

    if (!upstart_job) {
        serverLog(LL_WARNING, "upstart supervision requested, but UPSTART_JOB not found");
        return 0;
    }

    serverLog(LL_NOTICE, "supervised by upstart, will stop to signal readiness");
    raise(SIGSTOP);
    unsetenv("UPSTART_JOB");
    return 1;
}

int redisCommunicateSystemd(const char *sd_notify_msg) {
    const char *notify_socket = getenv("NOTIFY_SOCKET");
    if (!notify_socket) {
        serverLog(LL_WARNING, "systemd supervision requested, but NOTIFY_SOCKET not found");
    }

    #ifdef HAVE_LIBSYSTEMD
    (void) sd_notify(0, sd_notify_msg);
    #else
    UNUSED(sd_notify_msg);
    #endif
    return 0;
}

int redisIsSupervised(int mode) {
    if (mode == SUPERVISED_AUTODETECT) {
        const char *upstart_job = getenv("UPSTART_JOB");
        const char *notify_socket = getenv("NOTIFY_SOCKET");

        if (upstart_job) {
            redisSupervisedUpstart();
        } else if (notify_socket) {
            server.supervised_mode = SUPERVISED_SYSTEMD;
            serverLog(LL_WARNING, "WARNING auto-supervised by systemd - you MUST set appropriate values for TimeoutStartSec and TimeoutStopSec in your service unit.");
            return redisCommunicateSystemd("STATUS=Redis is loading...\n");
        }
    } else if (mode == SUPERVISED_UPSTART) {
        return redisSupervisedUpstart();
    } else if (mode == SUPERVISED_SYSTEMD) {
        serverLog(LL_WARNING, "WARNING supervised by systemd - you MUST set appropriate values for TimeoutStartSec and TimeoutStopSec in your service unit.");
        return redisCommunicateSystemd("STATUS=Redis is loading...\n");
    }

    return 0;
}

int iAmMaster(void) {
    return ((!server.cluster_enabled && server.masterhost == NULL) || (server.cluster_enabled && nodeIsMaster(server.cluster->myself)));
}

int main(int argc, char **argv) {
    struct timeval tv;
    int j;


    if (argc == 3 && !strcasecmp(argv[1], "test")) {
        if (!strcasecmp(argv[2], "ziplist")) {
            return ziplistTest(argc, argv);
        } else if (!strcasecmp(argv[2], "quicklist")) {
            quicklistTest(argc, argv);
        } else if (!strcasecmp(argv[2], "intset")) {
            return intsetTest(argc, argv);
        } else if (!strcasecmp(argv[2], "zipmap")) {
            return zipmapTest(argc, argv);
        } else if (!strcasecmp(argv[2], "sha1test")) {
            return sha1Test(argc, argv);
        } else if (!strcasecmp(argv[2], "util")) {
            return utilTest(argc, argv);
        } else if (!strcasecmp(argv[2], "endianconv")) {
            return endianconvTest(argc, argv);
        } else if (!strcasecmp(argv[2], "crc64")) {
            return crc64Test(argc, argv);
        } else if (!strcasecmp(argv[2], "zmalloc")) {
            return zmalloc_test(argc, argv);
        }

        return -1; 
    }


    

    spt_init(argc, argv);

    setlocale(LC_COLLATE,"");
    tzset(); 
    zmalloc_set_oom_handler(redisOutOfMemoryHandler);
    srand(time(NULL)^getpid());
    gettimeofday(&tv,NULL);
    init_genrand64(((long long) tv.tv_sec * 1000000 + tv.tv_usec) ^ getpid());
    crc64_init();

    
    umask(server.umask = umask(0777));

    uint8_t hashseed[16];
    getRandomBytes(hashseed,sizeof(hashseed));
    dictSetHashFunctionSeed(hashseed);
    server.sentinel_mode = checkForSentinelMode(argc,argv);
    initServerConfig();
    ACLInit(); 
    moduleInitModulesSystem();
    tlsInit();

    
    server.executable = getAbsolutePath(argv[0]);
    server.exec_argv = zmalloc(sizeof(char*)*(argc+1));
    server.exec_argv[argc] = NULL;
    for (j = 0; j < argc; j++) server.exec_argv[j] = zstrdup(argv[j]);

    
    if (server.sentinel_mode) {
        initSentinelConfig();
        initSentinel();
    }

    
    if (strstr(argv[0],"redis-check-rdb") != NULL)
        redis_check_rdb_main(argc,argv,NULL);
    else if (strstr(argv[0],"redis-check-aof") != NULL)
        redis_check_aof_main(argc,argv);

    if (argc >= 2) {
        j = 1; 
        sds options = sdsempty();
        char *configfile = NULL;

        
        if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) version();
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) usage();
        if (strcmp(argv[1], "--test-memory") == 0) {
            if (argc == 3) {
                memtest(atoi(argv[2]),50);
                exit(0);
            } else {
                fprintf(stderr,"Please specify the amount of memory to test in megabytes.\n");
                fprintf(stderr,"Example: ./redis-server --test-memory 4096\n\n");
                exit(1);
            }
        }

        
        if (argv[j][0] != '-' || argv[j][1] != '-') {
            configfile = argv[j];
            server.configfile = getAbsolutePath(configfile);
            
            zfree(server.exec_argv[j]);
            server.exec_argv[j] = zstrdup(server.configfile);
            j++;
        }

        
        while(j != argc) {
            if (argv[j][0] == '-' && argv[j][1] == '-') {
                
                if (!strcmp(argv[j], "--check-rdb")) {
                    
                    j++;
                    continue;
                }
                if (sdslen(options)) options = sdscat(options,"\n");
                options = sdscat(options,argv[j]+2);
                options = sdscat(options," ");
            } else {
                
                options = sdscatrepr(options,argv[j],strlen(argv[j]));
                options = sdscat(options," ");
            }
            j++;
        }
        if (server.sentinel_mode && configfile && *configfile == '-') {
            serverLog(LL_WARNING, "Sentinel config from STDIN not allowed.");
            serverLog(LL_WARNING, "Sentinel needs config file on disk to save state.  Exiting...");
            exit(1);
        }
        resetServerSaveParams();
        loadServerConfig(configfile,options);
        sdsfree(options);
    }

    server.supervised = redisIsSupervised(server.supervised_mode);
    int background = server.daemonize && !server.supervised;
    if (background) daemonize();

    serverLog(LL_WARNING, "oO0OoO0OoO0Oo Redis is starting oO0OoO0OoO0Oo");
    serverLog(LL_WARNING, "Redis version=%s, bits=%d, commit=%s, modified=%d, pid=%d, just started", REDIS_VERSION, (sizeof(long) == 8) ? 64 : 32, redisGitSHA1(), strtol(redisGitDirty(),NULL,10) > 0, (int)getpid());






    if (argc == 1) {
        serverLog(LL_WARNING, "Warning: no config file specified, using the default config. In order to specify a config file use %s /path/to/%s.conf", argv[0], server.sentinel_mode ? "sentinel" : "redis");
    } else {
        serverLog(LL_WARNING, "Configuration loaded");
    }

    readOOMScoreAdj();
    initServer();
    if (background || server.pidfile) createPidFile();
    redisSetProcTitle(argv[0]);
    redisAsciiArt();
    checkTcpBacklogSettings();

    if (!server.sentinel_mode) {
        
        serverLog(LL_WARNING,"Server initialized");
    #ifdef __linux__
        linuxMemoryWarnings();
    #if defined (__arm64__)
        int ret;
        if ((ret = linuxMadvFreeForkBugCheck())) {
            if (ret == 1)
                serverLog(LL_WARNING,"WARNING Your kernel has a bug that could lead to data corruption during background save. " "Please upgrade to the latest stable kernel.");
            else serverLog(LL_WARNING, "Failed to test the kernel for a bug that could lead to data corruption during background save. " "Your system could be affected, please report this error.");

            if (!checkIgnoreWarning("ARM64-COW-BUG")) {
                serverLog(LL_WARNING,"Redis will now exit to prevent data corruption. " "Note that it is possible to suppress this warning by setting the following config: ignore-warnings ARM64-COW-BUG");
                exit(1);
            }
        }
    #endif 
    #endif 
        moduleLoadFromQueue();
        ACLLoadUsersAtStartup();
        InitServerLast();
        loadDataFromDisk();
        if (server.cluster_enabled) {
            if (verifyClusterConfigWithData() == C_ERR) {
                serverLog(LL_WARNING, "You can't have keys in a DB different than DB 0 when in " "Cluster mode. Exiting.");

                exit(1);
            }
        }
        if (server.ipfd_count > 0 || server.tlsfd_count > 0)
            serverLog(LL_NOTICE,"Ready to accept connections");
        if (server.sofd > 0)
            serverLog(LL_NOTICE,"The server is now ready to accept connections at %s", server.unixsocket);
        if (server.supervised_mode == SUPERVISED_SYSTEMD) {
            if (!server.masterhost) {
                redisCommunicateSystemd("STATUS=Ready to accept connections\n");
                redisCommunicateSystemd("READY=1\n");
            } else {
                redisCommunicateSystemd("STATUS=Waiting for MASTER <-> REPLICA sync\n");
            }
        }
    } else {
        InitServerLast();
        sentinelIsRunning();
        if (server.supervised_mode == SUPERVISED_SYSTEMD) {
            redisCommunicateSystemd("STATUS=Ready to accept connections\n");
            redisCommunicateSystemd("READY=1\n");
        }
    }

    
    if (server.maxmemory > 0 && server.maxmemory < 1024*1024) {
        serverLog(LL_WARNING,"WARNING: You specified a maxmemory value that is less than 1MB (current value is %llu bytes). Are you sure this is what you really want?", server.maxmemory);
    }

    redisSetCpuAffinity(server.server_cpulist);
    setOOMScoreAdj(-1);

    aeMain(server.el);
    aeDeleteEventLoop(server.el);
    return 0;
}


