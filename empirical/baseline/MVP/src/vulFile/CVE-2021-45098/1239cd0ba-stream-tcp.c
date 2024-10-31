







































































static int StreamTcpHandleFin(ThreadVars *tv, StreamTcpThread *, TcpSession *, Packet *, PacketQueueNoLock *);
void StreamTcpReturnStreamSegments (TcpStream *);
void StreamTcpInitConfig(bool);
int StreamTcpGetFlowState(void *);
void StreamTcpSetOSPolicy(TcpStream*, Packet*);

static int StreamTcpValidateTimestamp(TcpSession * , Packet *);
static int StreamTcpHandleTimestamp(TcpSession * , Packet *);
static int StreamTcpValidateRst(TcpSession * , Packet *);
static inline int StreamTcpValidateAck(TcpSession *ssn, TcpStream *, Packet *);
static int StreamTcpStateDispatch(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq, uint8_t state);


extern int g_detect_disabled;

static PoolThread *ssn_pool = NULL;
static SCMutex ssn_pool_mutex = SCMUTEX_INITIALIZER; 

static uint64_t ssn_pool_cnt = 0; 


TcpStreamCnf stream_config;
uint64_t StreamTcpReassembleMemuseGlobalCounter(void);
SC_ATOMIC_DECLARE(uint64_t, st_memuse);

void StreamTcpInitMemuse(void)
{
    SC_ATOMIC_INIT(st_memuse);
}

void StreamTcpIncrMemuse(uint64_t size)
{
    (void) SC_ATOMIC_ADD(st_memuse, size);
    SCLogDebug("STREAM %"PRIu64", incr %"PRIu64, StreamTcpMemuseCounter(), size);
    return;
}

void StreamTcpDecrMemuse(uint64_t size)
{

    uint64_t presize = SC_ATOMIC_GET(st_memuse);
    if (RunmodeIsUnittests()) {
        BUG_ON(presize > UINT_MAX);
    }


    (void) SC_ATOMIC_SUB(st_memuse, size);


    if (RunmodeIsUnittests()) {
        uint64_t postsize = SC_ATOMIC_GET(st_memuse);
        BUG_ON(postsize > presize);
    }

    SCLogDebug("STREAM %"PRIu64", decr %"PRIu64, StreamTcpMemuseCounter(), size);
    return;
}

uint64_t StreamTcpMemuseCounter(void)
{
    uint64_t memusecopy = SC_ATOMIC_GET(st_memuse);
    return memusecopy;
}


int StreamTcpCheckMemcap(uint64_t size)
{
    uint64_t memcapcopy = SC_ATOMIC_GET(stream_config.memcap);
    if (memcapcopy == 0 || size + SC_ATOMIC_GET(st_memuse) <= memcapcopy)
        return 1;
    return 0;
}


int StreamTcpSetMemcap(uint64_t size)
{
    if (size == 0 || (uint64_t)SC_ATOMIC_GET(st_memuse) < size) {
        SC_ATOMIC_SET(stream_config.memcap, size);
        return 1;
    }

    return 0;
}


uint64_t StreamTcpGetMemcap(void)
{
    uint64_t memcapcopy = SC_ATOMIC_GET(stream_config.memcap);
    return memcapcopy;
}

void StreamTcpStreamCleanup(TcpStream *stream)
{
    if (stream != NULL) {
        StreamTcpSackFreeList(stream);
        StreamTcpReturnStreamSegments(stream);
        StreamingBufferClear(&stream->sb);
    }
}


void StreamTcpSessionCleanup(TcpSession *ssn)
{
    SCEnter();
    TcpStateQueue *q, *q_next;

    if (ssn == NULL)
        return;

    StreamTcpStreamCleanup(&ssn->client);
    StreamTcpStreamCleanup(&ssn->server);

    q = ssn->queue;
    while (q != NULL) {
        q_next = q->next;
        SCFree(q);
        q = q_next;
        StreamTcpDecrMemuse((uint64_t)sizeof(TcpStateQueue));
    }
    ssn->queue = NULL;
    ssn->queue_len = 0;

    SCReturn;
}


void StreamTcpSessionClear(void *ssnptr)
{
    SCEnter();
    TcpSession *ssn = (TcpSession *)ssnptr;
    if (ssn == NULL)
        return;

    StreamTcpSessionCleanup(ssn);

    
    PoolThreadReserved a = ssn->res;
    memset(ssn, 0, sizeof(TcpSession));
    ssn->res = a;

    PoolThreadReturn(ssn_pool, ssn);

    SCMutexLock(&ssn_pool_mutex);
    ssn_pool_cnt--;
    SCMutexUnlock(&ssn_pool_mutex);


    SCReturn;
}


void StreamTcpSessionPktFree (Packet *p)
{
    SCEnter();

    TcpSession *ssn = (TcpSession *)p->flow->protoctx;
    if (ssn == NULL)
        SCReturn;

    StreamTcpReturnStreamSegments(&ssn->client);
    StreamTcpReturnStreamSegments(&ssn->server);

    SCReturn;
}


static void *StreamTcpSessionPoolAlloc(void)
{
    void *ptr = NULL;

    if (StreamTcpCheckMemcap((uint32_t)sizeof(TcpSession)) == 0)
        return NULL;

    ptr = SCMalloc(sizeof(TcpSession));
    if (unlikely(ptr == NULL))
        return NULL;

    return ptr;
}

static int StreamTcpSessionPoolInit(void *data, void* initdata)
{
    memset(data, 0, sizeof(TcpSession));
    StreamTcpIncrMemuse((uint64_t)sizeof(TcpSession));

    return 1;
}


static void StreamTcpSessionPoolCleanup(void *s)
{
    if (s != NULL) {
        StreamTcpSessionCleanup(s);
        
        StreamTcpDecrMemuse((uint64_t)sizeof(TcpSession));
    }
}


int StreamTcpInlineDropInvalid(void)
{
    return ((stream_config.flags & STREAMTCP_INIT_FLAG_INLINE)
            && (stream_config.flags & STREAMTCP_INIT_FLAG_DROP_INVALID));
}


static int RandomGetWrap(void)
{
    unsigned long r;

    do {
        r = RandomGet();
    } while(r >= ULONG_MAX - (ULONG_MAX % RAND_MAX));

    return r % RAND_MAX;
}



void StreamTcpInitConfig(bool quiet)
{
    intmax_t value = 0;
    uint16_t rdrange = 10;

    SCLogDebug("Initializing Stream");

    memset(&stream_config,  0, sizeof(stream_config));

    SC_ATOMIC_INIT(stream_config.memcap);
    SC_ATOMIC_INIT(stream_config.reassembly_memcap);

    if ((ConfGetInt("stream.max-sessions", &value)) == 1) {
        SCLogWarning(SC_WARN_OPTION_OBSOLETE, "max-sessions is obsolete. " "Number of concurrent sessions is now only limited by Flow and " "TCP stream engine memcaps.");

    }

    if ((ConfGetInt("stream.prealloc-sessions", &value)) == 1) {
        stream_config.prealloc_sessions = (uint32_t)value;
    } else {
        if (RunmodeIsUnittests()) {
            stream_config.prealloc_sessions = 128;
        } else {
            stream_config.prealloc_sessions = STREAMTCP_DEFAULT_PREALLOC;
            if (ConfGetNode("stream.prealloc-sessions") != NULL) {
                WarnInvalidConfEntry("stream.prealloc_sessions", "%"PRIu32, stream_config.prealloc_sessions);

            }
        }
    }
    if (!quiet) {
        SCLogConfig("stream \"prealloc-sessions\": %"PRIu32" (per thread)", stream_config.prealloc_sessions);
    }

    const char *temp_stream_memcap_str;
    if (ConfGetValue("stream.memcap", &temp_stream_memcap_str) == 1) {
        uint64_t stream_memcap_copy;
        if (ParseSizeStringU64(temp_stream_memcap_str, &stream_memcap_copy) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing stream.memcap " "from conf file - %s.  Killing engine", temp_stream_memcap_str);

            exit(EXIT_FAILURE);
        } else {
            SC_ATOMIC_SET(stream_config.memcap, stream_memcap_copy);
        }
    } else {
        SC_ATOMIC_SET(stream_config.memcap, STREAMTCP_DEFAULT_MEMCAP);
    }

    if (!quiet) {
        SCLogConfig("stream \"memcap\": %"PRIu64, SC_ATOMIC_GET(stream_config.memcap));
    }

    int imidstream;
    (void)ConfGetBool("stream.midstream", &imidstream);
    stream_config.midstream = imidstream != 0;

    if (!quiet) {
        SCLogConfig("stream \"midstream\" session pickups: %s", stream_config.midstream ? "enabled" : "disabled");
    }

    (void)ConfGetBool("stream.async-oneside", &stream_config.async_oneside);

    if (!quiet) {
        SCLogConfig("stream \"async-oneside\": %s", stream_config.async_oneside ? "enabled" : "disabled");
    }

    int csum = 0;

    if ((ConfGetBool("stream.checksum-validation", &csum)) == 1) {
        if (csum == 1) {
            stream_config.flags |= STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION;
        }
    
    } else {
        stream_config.flags |= STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION;
    }

    if (!quiet) {
        SCLogConfig("stream \"checksum-validation\": %s", stream_config.flags & STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION ? "enabled" : "disabled");

    }

    const char *temp_stream_inline_str;
    if (ConfGetValue("stream.inline", &temp_stream_inline_str) == 1) {
        int inl = 0;

        
        if (strcmp(temp_stream_inline_str, "auto") == 0) {
            if (EngineModeIsIPS()) {
                stream_config.flags |= STREAMTCP_INIT_FLAG_INLINE;
            }
        } else if (ConfGetBool("stream.inline", &inl) == 1) {
            if (inl) {
                stream_config.flags |= STREAMTCP_INIT_FLAG_INLINE;
            }
        }
    } else {
        
        if (EngineModeIsIPS()) {
            stream_config.flags |= STREAMTCP_INIT_FLAG_INLINE;
        }
    }

    if (!quiet) {
        SCLogConfig("stream.\"inline\": %s", stream_config.flags & STREAMTCP_INIT_FLAG_INLINE ? "enabled" : "disabled");

    }

    int bypass = 0;
    if ((ConfGetBool("stream.bypass", &bypass)) == 1) {
        if (bypass == 1) {
            stream_config.flags |= STREAMTCP_INIT_FLAG_BYPASS;
        }
    }

    if (!quiet) {
        SCLogConfig("stream \"bypass\": %s", (stream_config.flags & STREAMTCP_INIT_FLAG_BYPASS)
                    ? "enabled" : "disabled");
    }

    int drop_invalid = 0;
    if ((ConfGetBool("stream.drop-invalid", &drop_invalid)) == 1) {
        if (drop_invalid == 1) {
            stream_config.flags |= STREAMTCP_INIT_FLAG_DROP_INVALID;
        }
    } else {
        stream_config.flags |= STREAMTCP_INIT_FLAG_DROP_INVALID;
    }

    if ((ConfGetInt("stream.max-synack-queued", &value)) == 1) {
        if (value >= 0 && value <= 255) {
            stream_config.max_synack_queued = (uint8_t)value;
        } else {
            stream_config.max_synack_queued = (uint8_t)STREAMTCP_DEFAULT_MAX_SYNACK_QUEUED;
        }
    } else {
        stream_config.max_synack_queued = (uint8_t)STREAMTCP_DEFAULT_MAX_SYNACK_QUEUED;
    }
    if (!quiet) {
        SCLogConfig("stream \"max-synack-queued\": %"PRIu8, stream_config.max_synack_queued);
    }

    const char *temp_stream_reassembly_memcap_str;
    if (ConfGetValue("stream.reassembly.memcap", &temp_stream_reassembly_memcap_str) == 1) {
        uint64_t stream_reassembly_memcap_copy;
        if (ParseSizeStringU64(temp_stream_reassembly_memcap_str, &stream_reassembly_memcap_copy) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing " "stream.reassembly.memcap " "from conf file - %s.  Killing engine", temp_stream_reassembly_memcap_str);


            exit(EXIT_FAILURE);
        } else {
            SC_ATOMIC_SET(stream_config.reassembly_memcap, stream_reassembly_memcap_copy);
        }
    } else {
        SC_ATOMIC_SET(stream_config.reassembly_memcap , STREAMTCP_DEFAULT_REASSEMBLY_MEMCAP);
    }

    if (!quiet) {
        SCLogConfig("stream.reassembly \"memcap\": %"PRIu64"", SC_ATOMIC_GET(stream_config.reassembly_memcap));
    }

    const char *temp_stream_reassembly_depth_str;
    if (ConfGetValue("stream.reassembly.depth", &temp_stream_reassembly_depth_str) == 1) {
        if (ParseSizeStringU32(temp_stream_reassembly_depth_str, &stream_config.reassembly_depth) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing " "stream.reassembly.depth " "from conf file - %s.  Killing engine", temp_stream_reassembly_depth_str);


            exit(EXIT_FAILURE);
        }
    } else {
        stream_config.reassembly_depth = 0;
    }

    if (!quiet) {
        SCLogConfig("stream.reassembly \"depth\": %"PRIu32"", stream_config.reassembly_depth);
    }

    int randomize = 0;
    if ((ConfGetBool("stream.reassembly.randomize-chunk-size", &randomize)) == 0) {
        
        if (!(RunmodeIsUnittests()))
            randomize = 1;
    }

    if (randomize) {
        const char *temp_rdrange;
        if (ConfGetValue("stream.reassembly.randomize-chunk-range", &temp_rdrange) == 1) {
            if (ParseSizeStringU16(temp_rdrange, &rdrange) < 0) {
                SCLogError(SC_ERR_SIZE_PARSE, "Error parsing " "stream.reassembly.randomize-chunk-range " "from conf file - %s.  Killing engine", temp_rdrange);


                exit(EXIT_FAILURE);
            } else if (rdrange >= 100) {
                           FatalError(SC_ERR_FATAL, "stream.reassembly.randomize-chunk-range " "must be lower than 100");

            }
        }
    }

    const char *temp_stream_reassembly_toserver_chunk_size_str;
    if (ConfGetValue("stream.reassembly.toserver-chunk-size", &temp_stream_reassembly_toserver_chunk_size_str) == 1) {
        if (ParseSizeStringU16(temp_stream_reassembly_toserver_chunk_size_str, &stream_config.reassembly_toserver_chunk_size) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing " "stream.reassembly.toserver-chunk-size " "from conf file - %s.  Killing engine", temp_stream_reassembly_toserver_chunk_size_str);


            exit(EXIT_FAILURE);
        }
    } else {
        stream_config.reassembly_toserver_chunk_size = STREAMTCP_DEFAULT_TOSERVER_CHUNK_SIZE;
    }

    if (randomize) {
        long int r = RandomGetWrap();
        stream_config.reassembly_toserver_chunk_size += (int) (stream_config.reassembly_toserver_chunk_size * (r * 1.0 / RAND_MAX - 0.5) * rdrange / 100);

    }
    const char *temp_stream_reassembly_toclient_chunk_size_str;
    if (ConfGetValue("stream.reassembly.toclient-chunk-size", &temp_stream_reassembly_toclient_chunk_size_str) == 1) {
        if (ParseSizeStringU16(temp_stream_reassembly_toclient_chunk_size_str, &stream_config.reassembly_toclient_chunk_size) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing " "stream.reassembly.toclient-chunk-size " "from conf file - %s.  Killing engine", temp_stream_reassembly_toclient_chunk_size_str);


            exit(EXIT_FAILURE);
        }
    } else {
        stream_config.reassembly_toclient_chunk_size = STREAMTCP_DEFAULT_TOCLIENT_CHUNK_SIZE;
    }

    if (randomize) {
        long int r = RandomGetWrap();
        stream_config.reassembly_toclient_chunk_size += (int) (stream_config.reassembly_toclient_chunk_size * (r * 1.0 / RAND_MAX - 0.5) * rdrange / 100);

    }
    if (!quiet) {
        SCLogConfig("stream.reassembly \"toserver-chunk-size\": %"PRIu16, stream_config.reassembly_toserver_chunk_size);
        SCLogConfig("stream.reassembly \"toclient-chunk-size\": %"PRIu16, stream_config.reassembly_toclient_chunk_size);
    }

    int enable_raw = 1;
    if (ConfGetBool("stream.reassembly.raw", &enable_raw) == 1) {
        if (!enable_raw) {
            stream_config.stream_init_flags = STREAMTCP_STREAM_FLAG_DISABLE_RAW;
        }
    } else {
        enable_raw = 1;
    }
    if (!quiet)
        SCLogConfig("stream.reassembly.raw: %s", enable_raw ? "enabled" : "disabled");

    
    StreamTcpInitMemuse();
    StatsRegisterGlobalCounter("tcp.memuse", StreamTcpMemuseCounter);

    StreamTcpReassembleInit(quiet);

    
    FlowSetProtoFreeFunc(IPPROTO_TCP, StreamTcpSessionClear);


    if (RunmodeIsUnittests()) {
        SCMutexLock(&ssn_pool_mutex);
        if (ssn_pool == NULL) {
            ssn_pool = PoolThreadInit(1,  0, stream_config.prealloc_sessions, sizeof(TcpSession), StreamTcpSessionPoolAlloc, StreamTcpSessionPoolInit, NULL, StreamTcpSessionPoolCleanup, NULL);





        }
        SCMutexUnlock(&ssn_pool_mutex);
    }

}

void StreamTcpFreeConfig(bool quiet)
{
    StreamTcpReassembleFree(quiet);

    SCMutexLock(&ssn_pool_mutex);
    if (ssn_pool != NULL) {
        PoolThreadFree(ssn_pool);
        ssn_pool = NULL;
    }
    SCMutexUnlock(&ssn_pool_mutex);
    SCMutexDestroy(&ssn_pool_mutex);

    SCLogDebug("ssn_pool_cnt %"PRIu64"", ssn_pool_cnt);
}


static TcpSession *StreamTcpNewSession (Packet *p, int id)
{
    TcpSession *ssn = (TcpSession *)p->flow->protoctx;

    if (ssn == NULL) {
        p->flow->protoctx = PoolThreadGetById(ssn_pool, id);

        SCMutexLock(&ssn_pool_mutex);
        if (p->flow->protoctx != NULL)
            ssn_pool_cnt++;
        SCMutexUnlock(&ssn_pool_mutex);


        ssn = (TcpSession *)p->flow->protoctx;
        if (ssn == NULL) {
            SCLogDebug("ssn_pool is empty");
            return NULL;
        }

        ssn->state = TCP_NONE;
        ssn->reassembly_depth = stream_config.reassembly_depth;
        ssn->tcp_packet_flags = p->tcph ? p->tcph->th_flags : 0;
        ssn->server.flags = stream_config.stream_init_flags;
        ssn->client.flags = stream_config.stream_init_flags;

        StreamingBuffer x = STREAMING_BUFFER_INITIALIZER(&stream_config.sbcnf);
        ssn->client.sb = x;
        ssn->server.sb = x;

        if (PKT_IS_TOSERVER(p)) {
            ssn->client.tcp_flags = p->tcph ? p->tcph->th_flags : 0;
            ssn->server.tcp_flags = 0;
        } else if (PKT_IS_TOCLIENT(p)) {
            ssn->server.tcp_flags = p->tcph ? p->tcph->th_flags : 0;
            ssn->client.tcp_flags = 0;
        }
    }

    return ssn;
}

static void StreamTcpPacketSetState(Packet *p, TcpSession *ssn, uint8_t state)
{
    if (state == ssn->state || PKT_IS_PSEUDOPKT(p))
        return;

    ssn->pstate = ssn->state;
    ssn->state = state;

    
    switch(ssn->state) {
        case TCP_ESTABLISHED:
        case TCP_FIN_WAIT1:
        case TCP_FIN_WAIT2:
        case TCP_CLOSING:
        case TCP_CLOSE_WAIT:
            FlowUpdateState(p->flow, FLOW_STATE_ESTABLISHED);
            break;
        case TCP_LAST_ACK:
        case TCP_TIME_WAIT:
        case TCP_CLOSED:
            FlowUpdateState(p->flow, FLOW_STATE_CLOSED);
            break;
    }
}


void StreamTcpSetOSPolicy(TcpStream *stream, Packet *p)
{
    int ret = 0;

    if (PKT_IS_IPV4(p)) {
        
        ret = SCHInfoGetIPv4HostOSFlavour((uint8_t *)GET_IPV4_DST_ADDR_PTR(p));
        if (ret > 0)
            stream->os_policy = ret;
        else stream->os_policy = OS_POLICY_DEFAULT;

    } else if (PKT_IS_IPV6(p)) {
        
        ret = SCHInfoGetIPv6HostOSFlavour((uint8_t *)GET_IPV6_DST_ADDR(p));
        if (ret > 0)
            stream->os_policy = ret;
        else stream->os_policy = OS_POLICY_DEFAULT;
    }

    if (stream->os_policy == OS_POLICY_BSD_RIGHT)
        stream->os_policy = OS_POLICY_BSD;
    else if (stream->os_policy == OS_POLICY_OLD_SOLARIS)
        stream->os_policy = OS_POLICY_SOLARIS;

    SCLogDebug("Policy is %"PRIu8"", stream->os_policy);

}









































static inline void StreamTcpCloseSsnWithReset(Packet *p, TcpSession *ssn)
{
    ssn->flags |= STREAMTCP_FLAG_CLOSED_BY_RST;
    StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
    SCLogDebug("ssn %p: (state: %s) Reset received and state changed to " "TCP_CLOSED", ssn, StreamTcpStateAsString(ssn->state));
}

static int StreamTcpPacketIsRetransmission(TcpStream *stream, Packet *p)
{
    if (p->payload_len == 0)
        SCReturnInt(0);

    
    if (SEQ_LT(TCP_GET_SEQ(p), stream->last_ack) && SEQ_GT((TCP_GET_SEQ(p) + p->payload_len), stream->last_ack))
    {
        StreamTcpSetEvent(p, STREAM_PKT_RETRANSMISSION);
        SCReturnInt(1);
    }

    
    if (SEQ_LEQ((TCP_GET_SEQ(p) + p->payload_len), stream->last_ack)) {
        StreamTcpSetEvent(p, STREAM_PKT_RETRANSMISSION);
        SCReturnInt(1);
    }

    
    if (SEQ_LEQ((TCP_GET_SEQ(p) + p->payload_len), stream->next_seq)) {
        StreamTcpSetEvent(p, STREAM_PKT_RETRANSMISSION);
        SCReturnInt(2);
    }

    SCLogDebug("seq %u payload_len %u => %u, last_ack %u, next_seq %u", TCP_GET_SEQ(p), p->payload_len, (TCP_GET_SEQ(p) + p->payload_len), stream->last_ack, stream->next_seq);
    SCReturnInt(0);
}


static int StreamTcpPacketStateNone(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq)

{
    if (p->tcph->th_flags & TH_RST) {
        StreamTcpSetEvent(p, STREAM_RST_BUT_NO_SESSION);
        SCLogDebug("RST packet received, no session setup");
        return -1;

    } else if (p->tcph->th_flags & TH_FIN) {
        StreamTcpSetEvent(p, STREAM_FIN_BUT_NO_SESSION);
        SCLogDebug("FIN packet received, no session setup");
        return -1;

    
    } else if ((p->tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
        if (!stream_config.midstream && stream_config.async_oneside == FALSE)
            return 0;

        if (ssn == NULL) {
            ssn = StreamTcpNewSession(p, stt->ssn_pool_id);
            if (ssn == NULL) {
                StatsIncr(tv, stt->counter_tcp_ssn_memcap);
                return -1;
            }
            StatsIncr(tv, stt->counter_tcp_sessions);
            StatsIncr(tv, stt->counter_tcp_midstream_pickups);
        }

        
        SCLogDebug("reversing flow and packet");
        PacketSwap(p);
        FlowSwap(p->flow);

        
        StreamTcpPacketSetState(p, ssn, TCP_SYN_RECV);
        SCLogDebug("ssn %p: =~ midstream picked ssn state is now " "TCP_SYN_RECV", ssn);
        ssn->flags |= STREAMTCP_FLAG_MIDSTREAM;
        
        ssn->flags |= STREAMTCP_FLAG_MIDSTREAM_SYNACK;
        if (stream_config.async_oneside) {
            SCLogDebug("ssn %p: =~ ASYNC", ssn);
            ssn->flags |= STREAMTCP_FLAG_ASYNC;
        }

        
        ssn->server.isn = TCP_GET_SEQ(p);
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
        ssn->server.next_seq = ssn->server.isn + 1;
        ssn->server.window = TCP_GET_WINDOW(p);
        SCLogDebug("ssn %p: server window %u", ssn, ssn->server.window);

        ssn->client.isn = TCP_GET_ACK(p) - 1;
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn);
        ssn->client.next_seq = ssn->client.isn + 1;

        ssn->client.last_ack = TCP_GET_ACK(p);
        ssn->server.last_ack = TCP_GET_SEQ(p);

        ssn->server.next_win = ssn->server.last_ack + ssn->server.window;

        
        if (TCP_HAS_WSCALE(p)) {
            ssn->client.wscale = TCP_GET_WSCALE(p);
            ssn->server.wscale = TCP_WSCALE_MAX;
            SCLogDebug("ssn %p: wscale enabled. client %u server %u", ssn, ssn->client.wscale, ssn->server.wscale);
        }

        SCLogDebug("ssn %p: ssn->client.isn %"PRIu32", ssn->client.next_seq" " %"PRIu32", ssn->client.last_ack %"PRIu32"", ssn, ssn->client.isn, ssn->client.next_seq, ssn->client.last_ack);


        SCLogDebug("ssn %p: ssn->server.isn %"PRIu32", ssn->server.next_seq" " %"PRIu32", ssn->server.last_ack %"PRIu32"", ssn, ssn->server.isn, ssn->server.next_seq, ssn->server.last_ack);



        
        if (TCP_HAS_TS(p)) {
            ssn->server.last_ts = TCP_GET_TSVAL(p);
            ssn->client.last_ts = TCP_GET_TSECR(p);
            SCLogDebug("ssn %p: ssn->server.last_ts %" PRIu32" " "ssn->client.last_ts %" PRIu32"", ssn, ssn->server.last_ts, ssn->client.last_ts);


            ssn->flags |= STREAMTCP_FLAG_TIMESTAMP;

            ssn->server.last_pkt_ts = p->ts.tv_sec;
            if (ssn->server.last_ts == 0)
                ssn->server.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
            if (ssn->client.last_ts == 0)
                ssn->client.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;

        } else {
            ssn->server.last_ts = 0;
            ssn->client.last_ts = 0;
        }

        if (TCP_GET_SACKOK(p) == 1) {
            ssn->flags |= STREAMTCP_FLAG_SACKOK;
            SCLogDebug("ssn %p: SYN/ACK with SACK permitted, assuming " "SACK permitted for both sides", ssn);
        }
        return 0;

    } else if (p->tcph->th_flags & TH_SYN) {
        if (ssn == NULL) {
            ssn = StreamTcpNewSession(p, stt->ssn_pool_id);
            if (ssn == NULL) {
                StatsIncr(tv, stt->counter_tcp_ssn_memcap);
                return -1;
            }

            StatsIncr(tv, stt->counter_tcp_sessions);
        }

        
        StreamTcpPacketSetState(p, ssn, TCP_SYN_SENT);
        SCLogDebug("ssn %p: =~ ssn state is now TCP_SYN_SENT", ssn);

        if (stream_config.async_oneside) {
            SCLogDebug("ssn %p: =~ ASYNC", ssn);
            ssn->flags |= STREAMTCP_FLAG_ASYNC;
        }

        
        ssn->client.isn = TCP_GET_SEQ(p);
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn);
        ssn->client.next_seq = ssn->client.isn + 1;

        
        if (TCP_HAS_TS(p)) {
            ssn->client.last_ts = TCP_GET_TSVAL(p);
            SCLogDebug("ssn %p: %02x", ssn, ssn->client.last_ts);

            if (ssn->client.last_ts == 0)
                ssn->client.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;

            ssn->client.last_pkt_ts = p->ts.tv_sec;
            ssn->client.flags |= STREAMTCP_STREAM_FLAG_TIMESTAMP;
        }

        ssn->server.window = TCP_GET_WINDOW(p);
        if (TCP_HAS_WSCALE(p)) {
            ssn->flags |= STREAMTCP_FLAG_SERVER_WSCALE;
            ssn->server.wscale = TCP_GET_WSCALE(p);
        }

        if (TCP_GET_SACKOK(p) == 1) {
            ssn->flags |= STREAMTCP_FLAG_CLIENT_SACKOK;
            SCLogDebug("ssn %p: SACK permitted on SYN packet", ssn);
        }

        if (TCP_HAS_TFO(p)) {
            ssn->flags |= STREAMTCP_FLAG_TCP_FAST_OPEN;
            if (p->payload_len) {
                StreamTcpUpdateNextSeq(ssn, &ssn->client, (ssn->client.next_seq + p->payload_len));
                SCLogDebug("ssn: %p (TFO) [len: %d] isn %u base_seq %u next_seq %u payload len %u", ssn, p->tcpvars.tfo.len, ssn->client.isn, ssn->client.base_seq, ssn->client.next_seq, p->payload_len);
                StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);
            }
        }

        SCLogDebug("ssn %p: ssn->client.isn %" PRIu32 ", " "ssn->client.next_seq %" PRIu32 ", ssn->client.last_ack " "%"PRIu32"", ssn, ssn->client.isn, ssn->client.next_seq, ssn->client.last_ack);



    } else if (p->tcph->th_flags & TH_ACK) {
        if (!stream_config.midstream)
            return 0;

        if (ssn == NULL) {
            ssn = StreamTcpNewSession(p, stt->ssn_pool_id);
            if (ssn == NULL) {
                StatsIncr(tv, stt->counter_tcp_ssn_memcap);
                return -1;
            }
            StatsIncr(tv, stt->counter_tcp_sessions);
            StatsIncr(tv, stt->counter_tcp_midstream_pickups);
        }
        
        StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
        SCLogDebug("ssn %p: =~ midstream picked ssn state is now " "TCP_ESTABLISHED", ssn);

        ssn->flags = STREAMTCP_FLAG_MIDSTREAM;
        ssn->flags |= STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED;
        if (stream_config.async_oneside) {
            SCLogDebug("ssn %p: =~ ASYNC", ssn);
            ssn->flags |= STREAMTCP_FLAG_ASYNC;
        }

        
        ssn->client.wscale = TCP_WSCALE_MAX;
        ssn->server.wscale = TCP_WSCALE_MAX;

        
        ssn->client.isn = TCP_GET_SEQ(p) - 1;
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn);
        ssn->client.next_seq = TCP_GET_SEQ(p) + p->payload_len;
        ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
        ssn->client.last_ack = TCP_GET_SEQ(p);
        ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
        SCLogDebug("ssn %p: ssn->client.isn %u, ssn->client.next_seq %u", ssn, ssn->client.isn, ssn->client.next_seq);

        ssn->server.isn = TCP_GET_ACK(p) - 1;
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
        ssn->server.next_seq = ssn->server.isn + 1;
        ssn->server.last_ack = TCP_GET_ACK(p);
        ssn->server.next_win = ssn->server.last_ack;

        SCLogDebug("ssn %p: ssn->client.next_win %"PRIu32", " "ssn->server.next_win %"PRIu32"", ssn, ssn->client.next_win, ssn->server.next_win);

        SCLogDebug("ssn %p: ssn->client.last_ack %"PRIu32", " "ssn->server.last_ack %"PRIu32"", ssn, ssn->client.last_ack, ssn->server.last_ack);


        
        if (TCP_HAS_TS(p)) {
            ssn->client.last_ts = TCP_GET_TSVAL(p);
            ssn->server.last_ts = TCP_GET_TSECR(p);
            SCLogDebug("ssn %p: ssn->server.last_ts %" PRIu32" " "ssn->client.last_ts %" PRIu32"", ssn, ssn->server.last_ts, ssn->client.last_ts);


            ssn->flags |= STREAMTCP_FLAG_TIMESTAMP;

            ssn->client.last_pkt_ts = p->ts.tv_sec;
            if (ssn->server.last_ts == 0)
                ssn->server.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
            if (ssn->client.last_ts == 0)
                ssn->client.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;

        } else {
            ssn->server.last_ts = 0;
            ssn->client.last_ts = 0;
        }

        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);

        ssn->flags |= STREAMTCP_FLAG_SACKOK;
        SCLogDebug("ssn %p: assuming SACK permitted for both sides", ssn);

    } else {
        SCLogDebug("default case");
    }

    return 0;
}


static inline void StreamTcp3whsSynAckToStateQueue(Packet *p, TcpStateQueue *q)
{
    q->flags = 0;
    q->wscale = 0;
    q->ts = 0;
    q->win = TCP_GET_WINDOW(p);
    q->seq = TCP_GET_SEQ(p);
    q->ack = TCP_GET_ACK(p);
    q->pkt_ts = p->ts.tv_sec;

    if (TCP_GET_SACKOK(p) == 1)
        q->flags |= STREAMTCP_QUEUE_FLAG_SACK;

    if (TCP_HAS_WSCALE(p)) {
        q->flags |= STREAMTCP_QUEUE_FLAG_WS;
        q->wscale = TCP_GET_WSCALE(p);
    }
    if (TCP_HAS_TS(p)) {
        q->flags |= STREAMTCP_QUEUE_FLAG_TS;
        q->ts = TCP_GET_TSVAL(p);
    }
}


static TcpStateQueue *StreamTcp3whsFindSynAckBySynAck(TcpSession *ssn, Packet *p)
{
    TcpStateQueue *q = ssn->queue;
    TcpStateQueue search;

    StreamTcp3whsSynAckToStateQueue(p, &search);

    while (q != NULL) {
        if (search.flags == q->flags && search.wscale == q->wscale && search.win == q->win && search.seq == q->seq && search.ack == q->ack && search.ts == q->ts) {




            return q;
        }

        q = q->next;
    }

    return q;
}

static int StreamTcp3whsQueueSynAck(TcpSession *ssn, Packet *p)
{
    
    if (StreamTcp3whsFindSynAckBySynAck(ssn, p) != NULL)
        return 0;

    if (ssn->queue_len == stream_config.max_synack_queued) {
        SCLogDebug("ssn %p: =~ SYN/ACK queue limit reached", ssn);
        StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_FLOOD);
        return -1;
    }

    if (StreamTcpCheckMemcap((uint32_t)sizeof(TcpStateQueue)) == 0) {
        SCLogDebug("ssn %p: =~ SYN/ACK queue failed: stream memcap reached", ssn);
        return -1;
    }

    TcpStateQueue *q = SCMalloc(sizeof(*q));
    if (unlikely(q == NULL)) {
        SCLogDebug("ssn %p: =~ SYN/ACK queue failed: alloc failed", ssn);
        return -1;
    }
    memset(q, 0x00, sizeof(*q));
    StreamTcpIncrMemuse((uint64_t)sizeof(TcpStateQueue));

    StreamTcp3whsSynAckToStateQueue(p, q);

    
    q->next = ssn->queue;
    ssn->queue = q;
    ssn->queue_len++;
    return 0;
}


static TcpStateQueue *StreamTcp3whsFindSynAckByAck(TcpSession *ssn, Packet *p)
{
    uint32_t ack = TCP_GET_SEQ(p);
    uint32_t seq = TCP_GET_ACK(p) - 1;
    TcpStateQueue *q = ssn->queue;

    while (q != NULL) {
        if (seq == q->seq && ack == q->ack) {
            return q;
        }

        q = q->next;
    }

    return NULL;
}


static void StreamTcp3whsSynAckUpdate(TcpSession *ssn, Packet *p, TcpStateQueue *q)
{
    TcpStateQueue update;
    if (likely(q == NULL)) {
        StreamTcp3whsSynAckToStateQueue(p, &update);
        q = &update;
    }

    if (ssn->state != TCP_SYN_RECV) {
        
        StreamTcpPacketSetState(p, ssn, TCP_SYN_RECV);
        SCLogDebug("ssn %p: =~ ssn state is now TCP_SYN_RECV", ssn);
    }
    
    ssn->server.isn = q->seq;
    STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
    ssn->server.next_seq = ssn->server.isn + 1;

    ssn->client.window = q->win;
    SCLogDebug("ssn %p: window %" PRIu32 "", ssn, ssn->server.window);

    
    if ((q->flags & STREAMTCP_QUEUE_FLAG_TS) && (ssn->client.flags & STREAMTCP_STREAM_FLAG_TIMESTAMP))
    {
        ssn->server.last_ts = q->ts;
        SCLogDebug("ssn %p: ssn->server.last_ts %" PRIu32" " "ssn->client.last_ts %" PRIu32"", ssn, ssn->server.last_ts, ssn->client.last_ts);

        ssn->flags |= STREAMTCP_FLAG_TIMESTAMP;
        ssn->server.last_pkt_ts = q->pkt_ts;
        if (ssn->server.last_ts == 0)
            ssn->server.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
    } else {
        ssn->client.last_ts = 0;
        ssn->server.last_ts = 0;
        ssn->client.flags &= ~STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
    }

    ssn->client.last_ack = q->ack;
    ssn->server.last_ack = ssn->server.isn + 1;

    
    if ((ssn->flags & STREAMTCP_FLAG_SERVER_WSCALE) && (q->flags & STREAMTCP_QUEUE_FLAG_WS))
    {
        ssn->client.wscale = q->wscale;
    } else {
        ssn->client.wscale = 0;
    }

    if ((ssn->flags & STREAMTCP_FLAG_CLIENT_SACKOK) && (q->flags & STREAMTCP_QUEUE_FLAG_SACK)) {
        ssn->flags |= STREAMTCP_FLAG_SACKOK;
        SCLogDebug("ssn %p: SACK permitted for session", ssn);
    } else {
        ssn->flags &= ~STREAMTCP_FLAG_SACKOK;
    }

    ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
    ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
    SCLogDebug("ssn %p: ssn->server.next_win %" PRIu32 "", ssn, ssn->server.next_win);
    SCLogDebug("ssn %p: ssn->client.next_win %" PRIu32 "", ssn, ssn->client.next_win);
    SCLogDebug("ssn %p: ssn->server.isn %" PRIu32 ", " "ssn->server.next_seq %" PRIu32 ", " "ssn->server.last_ack %" PRIu32 " " "(ssn->client.last_ack %" PRIu32 ")", ssn, ssn->server.isn, ssn->server.next_seq, ssn->server.last_ack, ssn->client.last_ack);





    
    if (ssn->flags & STREAMTCP_FLAG_4WHS)
        SCLogDebug("ssn %p: STREAMTCP_FLAG_4WHS unset, normal SYN/ACK" " so considering 3WHS", ssn);

    ssn->flags &=~ STREAMTCP_FLAG_4WHS;
}


static inline bool StateSynSentValidateTimestamp(TcpSession *ssn, Packet *p)
{
    
    if (PKT_IS_TOSERVER(p) || !(TCP_HAS_TS(p))) {
        return true;
    }

    TcpStream *receiver_stream = &ssn->client;
    uint32_t ts_echo = TCP_GET_TSECR(p);
    if ((receiver_stream->flags & STREAMTCP_STREAM_FLAG_TIMESTAMP) != 0) {
        if (receiver_stream->last_ts != 0 && ts_echo != 0 && ts_echo != receiver_stream->last_ts)
        {
            SCLogDebug("ssn %p: BAD TSECR echo %u recv %u", ssn, ts_echo, receiver_stream->last_ts);
            return false;
        }
    } else {
        if (receiver_stream->last_ts == 0 && ts_echo != 0) {
            SCLogDebug("ssn %p: BAD TSECR echo %u recv %u", ssn, ts_echo, receiver_stream->last_ts);
            return false;
        }
    }
    return true;
}



static int StreamTcpPacketStateSynSent(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq)

{
    if (ssn == NULL)
        return -1;

    SCLogDebug("ssn %p: pkt received: %s", ssn, PKT_IS_TOCLIENT(p) ? "toclient":"toserver");

    
    if (StateSynSentValidateTimestamp(ssn, p) == false)
        return -1;

    
    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        if (PKT_IS_TOSERVER(p)) {
            if (SEQ_EQ(TCP_GET_SEQ(p), ssn->client.isn) && SEQ_EQ(TCP_GET_WINDOW(p), 0) && SEQ_EQ(TCP_GET_ACK(p), (ssn->client.isn + 1)))

            {
                SCLogDebug("ssn->server.flags |= STREAMTCP_STREAM_FLAG_RST_RECV");
                ssn->server.flags |= STREAMTCP_STREAM_FLAG_RST_RECV;
                StreamTcpCloseSsnWithReset(p, ssn);
            }
        } else {
            ssn->client.flags |= STREAMTCP_STREAM_FLAG_RST_RECV;
            SCLogDebug("ssn->client.flags |= STREAMTCP_STREAM_FLAG_RST_RECV");
            StreamTcpCloseSsnWithReset(p, ssn);
        }

    
    } else if (p->tcph->th_flags & TH_FIN) {
        

    
    } else if ((p->tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
        if ((ssn->flags & STREAMTCP_FLAG_4WHS) && PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: SYN/ACK received on 4WHS session", ssn);

            
            if (!(SEQ_EQ(TCP_GET_ACK(p), ssn->server.isn + 1))) {
                StreamTcpSetEvent(p, STREAM_4WHS_SYNACK_WITH_WRONG_ACK);

                SCLogDebug("ssn %p: 4WHS ACK mismatch, packet ACK %"PRIu32"" " != %" PRIu32 " from stream", ssn, TCP_GET_ACK(p), ssn->server.isn + 1);

                return -1;
            }

            
            if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.isn))) {
                StreamTcpSetEvent(p, STREAM_4WHS_SYNACK_WITH_WRONG_SYN);

                SCLogDebug("ssn %p: 4WHS SEQ mismatch, packet SEQ %"PRIu32"" " != %" PRIu32 " from *first* SYN pkt", ssn, TCP_GET_SEQ(p), ssn->client.isn);

                return -1;
            }


            
            StreamTcpPacketSetState(p, ssn, TCP_SYN_RECV);
            SCLogDebug("ssn %p: =~ 4WHS ssn state is now TCP_SYN_RECV", ssn);

            
            ssn->client.isn = TCP_GET_SEQ(p);
            STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn);
            ssn->client.next_seq = ssn->client.isn + 1;

            ssn->server.window = TCP_GET_WINDOW(p);
            SCLogDebug("ssn %p: 4WHS window %" PRIu32 "", ssn, ssn->client.window);

            
            if ((TCP_HAS_TS(p)) && (ssn->server.flags & STREAMTCP_STREAM_FLAG_TIMESTAMP))
            {
                ssn->client.last_ts = TCP_GET_TSVAL(p);
                SCLogDebug("ssn %p: 4WHS ssn->client.last_ts %" PRIu32" " "ssn->server.last_ts %" PRIu32"", ssn, ssn->client.last_ts, ssn->server.last_ts);

                ssn->flags |= STREAMTCP_FLAG_TIMESTAMP;
                ssn->client.last_pkt_ts = p->ts.tv_sec;
                if (ssn->client.last_ts == 0)
                    ssn->client.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
            } else {
                ssn->server.last_ts = 0;
                ssn->client.last_ts = 0;
                ssn->server.flags &= ~STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
            }

            ssn->server.last_ack = TCP_GET_ACK(p);
            ssn->client.last_ack = ssn->client.isn + 1;

            
            if ((ssn->flags & STREAMTCP_FLAG_SERVER_WSCALE) && (TCP_HAS_WSCALE(p)))
            {
                ssn->server.wscale = TCP_GET_WSCALE(p);
            } else {
                ssn->server.wscale = 0;
            }

            if ((ssn->flags & STREAMTCP_FLAG_CLIENT_SACKOK) && TCP_GET_SACKOK(p) == 1) {
                ssn->flags |= STREAMTCP_FLAG_SACKOK;
                SCLogDebug("ssn %p: SACK permitted for 4WHS session", ssn);
            }

            ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
            SCLogDebug("ssn %p: 4WHS ssn->client.next_win %" PRIu32 "", ssn, ssn->client.next_win);
            SCLogDebug("ssn %p: 4WHS ssn->server.next_win %" PRIu32 "", ssn, ssn->server.next_win);
            SCLogDebug("ssn %p: 4WHS ssn->client.isn %" PRIu32 ", " "ssn->client.next_seq %" PRIu32 ", " "ssn->client.last_ack %" PRIu32 " " "(ssn->server.last_ack %" PRIu32 ")", ssn, ssn->client.isn, ssn->client.next_seq, ssn->client.last_ack, ssn->server.last_ack);





            
            return 0;
        }

        if (PKT_IS_TOSERVER(p)) {
            StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_IN_WRONG_DIRECTION);
            SCLogDebug("ssn %p: SYN/ACK received in the wrong direction", ssn);
            return -1;
        }

        if (!(TCP_HAS_TFO(p) || (ssn->flags & STREAMTCP_FLAG_TCP_FAST_OPEN))) {
            
            if (!(SEQ_EQ(TCP_GET_ACK(p), ssn->client.isn + 1))) {
                StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_WITH_WRONG_ACK);
                SCLogDebug("ssn %p: ACK mismatch, packet ACK %" PRIu32 " != " "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p), ssn->client.isn + 1);

                return -1;
            }
        } else {
            if (!(SEQ_EQ(TCP_GET_ACK(p), ssn->client.next_seq))) {
                StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_WITH_WRONG_ACK);
                SCLogDebug("ssn %p: (TFO) ACK mismatch, packet ACK %" PRIu32 " != " "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p), ssn->client.next_seq);

                return -1;
            }
            SCLogDebug("ssn %p: (TFO) ACK match, packet ACK %" PRIu32 " == " "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p), ssn->client.next_seq);


            ssn->flags |= STREAMTCP_FLAG_TCP_FAST_OPEN;
            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
        }
        StreamTcp3whsSynAckUpdate(ssn, p, NULL);

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn %p: SYN packet on state SYN_SENT... resent", ssn);
        if (ssn->flags & STREAMTCP_FLAG_4WHS) {
            SCLogDebug("ssn %p: SYN packet on state SYN_SENT... resent of " "4WHS SYN", ssn);
        }

        if (PKT_IS_TOCLIENT(p)) {
            

            
            ssn->flags |= STREAMTCP_FLAG_4WHS;
            SCLogDebug("ssn %p: STREAMTCP_FLAG_4WHS flag set", ssn);

            
            ssn->server.isn = TCP_GET_SEQ(p);
            STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
            ssn->server.next_seq = ssn->server.isn + 1;

            
            if (TCP_HAS_TS(p)) {
                ssn->server.last_ts = TCP_GET_TSVAL(p);
                SCLogDebug("ssn %p: %02x", ssn, ssn->server.last_ts);

                if (ssn->server.last_ts == 0)
                    ssn->server.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
                ssn->server.last_pkt_ts = p->ts.tv_sec;
                ssn->server.flags |= STREAMTCP_STREAM_FLAG_TIMESTAMP;
            }

            ssn->server.window = TCP_GET_WINDOW(p);
            if (TCP_HAS_WSCALE(p)) {
                ssn->flags |= STREAMTCP_FLAG_SERVER_WSCALE;
                ssn->server.wscale = TCP_GET_WSCALE(p);
            } else {
                ssn->flags &= ~STREAMTCP_FLAG_SERVER_WSCALE;
                ssn->server.wscale = 0;
            }

            if (TCP_GET_SACKOK(p) == 1) {
                ssn->flags |= STREAMTCP_FLAG_CLIENT_SACKOK;
            } else {
                ssn->flags &= ~STREAMTCP_FLAG_CLIENT_SACKOK;
            }

            SCLogDebug("ssn %p: 4WHS ssn->server.isn %" PRIu32 ", " "ssn->server.next_seq %" PRIu32 ", " "ssn->server.last_ack %"PRIu32"", ssn, ssn->server.isn, ssn->server.next_seq, ssn->server.last_ack);



            SCLogDebug("ssn %p: 4WHS ssn->client.isn %" PRIu32 ", " "ssn->client.next_seq %" PRIu32 ", " "ssn->client.last_ack %"PRIu32"", ssn, ssn->client.isn, ssn->client.next_seq, ssn->client.last_ack);



        }

        

    } else if (p->tcph->th_flags & TH_ACK) {
        
        if (stream_config.async_oneside == FALSE)
            return 0;

        

        
        if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq))) {
            StreamTcpSetEvent(p, STREAM_3WHS_ASYNC_WRONG_SEQ);

            SCLogDebug("ssn %p: SEQ mismatch, packet SEQ %" PRIu32 " != " "%" PRIu32 " from stream",ssn, TCP_GET_SEQ(p), ssn->client.next_seq);

            return -1;
        }

        ssn->flags |= STREAMTCP_FLAG_ASYNC;
        StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
        SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

        ssn->client.window = TCP_GET_WINDOW(p);
        ssn->client.last_ack = TCP_GET_SEQ(p);
        ssn->client.next_win = ssn->client.last_ack + ssn->client.window;

        
        ssn->server.isn = TCP_GET_ACK(p) - 1;
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
        ssn->server.next_seq = ssn->server.isn + 1;
        ssn->server.last_ack = ssn->server.next_seq;
        ssn->server.next_win = ssn->server.last_ack;

        SCLogDebug("ssn %p: synsent => Asynchronous stream, packet SEQ" " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), " "ssn->client.next_seq %" PRIu32 "" ,ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p)


                + p->payload_len, ssn->client.next_seq);

        
        if (ssn->flags & STREAMTCP_FLAG_SERVER_WSCALE) {
            ssn->client.wscale = TCP_WSCALE_MAX;
        }

        
        if (TCP_HAS_TS(p) && (ssn->client.flags & STREAMTCP_STREAM_FLAG_TIMESTAMP))
        {
            ssn->flags |= STREAMTCP_FLAG_TIMESTAMP;
            ssn->client.flags &= ~STREAMTCP_STREAM_FLAG_TIMESTAMP;
            ssn->client.last_pkt_ts = p->ts.tv_sec;
        } else {
            ssn->client.last_ts = 0;
            ssn->client.flags &= ~STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
        }

        if (ssn->flags & STREAMTCP_FLAG_CLIENT_SACKOK) {
            ssn->flags |= STREAMTCP_FLAG_SACKOK;
        }

        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);

    } else {
        SCLogDebug("ssn %p: default case", ssn);
    }

    return 0;
}



static int StreamTcpPacketStateSynRecv(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq)

{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        bool reset = true;
        
        if (ssn->flags & STREAMTCP_FLAG_DETECTION_EVASION_ATTEMPT) {
            if (PKT_IS_TOSERVER(p)) {
                if ((ssn->server.os_policy == OS_POLICY_LINUX) || (ssn->server.os_policy == OS_POLICY_OLD_LINUX) || (ssn->server.os_policy == OS_POLICY_SOLARIS))

                {
                    reset = false;
                    SCLogDebug("Detection evasion has been attempted, so" " not resetting the connection !!");
                }
            } else {
                if ((ssn->client.os_policy == OS_POLICY_LINUX) || (ssn->client.os_policy == OS_POLICY_OLD_LINUX) || (ssn->client.os_policy == OS_POLICY_SOLARIS))

                {
                    reset = false;
                    SCLogDebug("Detection evasion has been attempted, so" " not resetting the connection !!");
                }
            }
        }

        if (reset) {
            StreamTcpCloseSsnWithReset(p, ssn);

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }
        }

    } else if (p->tcph->th_flags & TH_FIN) {
        ;
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if ((StreamTcpHandleFin(tv, stt, ssn, p, pq)) == -1)
            return -1;

    
    } else if ((p->tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
        SCLogDebug("ssn %p: SYN/ACK packet on state SYN_RECV. resent", ssn);

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: SYN/ACK-pkt to server in SYN_RECV state", ssn);

            StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_TOSERVER_ON_SYN_RECV);
            return -1;
        }

        
        if (!(SEQ_EQ(TCP_GET_ACK(p), ssn->client.last_ack))) {
            SCLogDebug("ssn %p: ACK mismatch, packet ACK %" PRIu32 " != " "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p), ssn->client.isn + 1);


            StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_RESEND_WITH_DIFFERENT_ACK);
            return -1;
        }

        
        if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->server.isn))) {
            SCLogDebug("ssn %p: SEQ mismatch, packet SEQ %" PRIu32 " != " "%" PRIu32 " from stream", ssn, TCP_GET_SEQ(p), ssn->client.isn);


            if (StreamTcp3whsQueueSynAck(ssn, p) == -1)
                return -1;
            SCLogDebug("ssn %p: queued different SYN/ACK", ssn);
        }

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn %p: SYN packet on state SYN_RECV... resent", ssn);

        if (PKT_IS_TOCLIENT(p)) {
            SCLogDebug("ssn %p: SYN-pkt to client in SYN_RECV state", ssn);

            StreamTcpSetEvent(p, STREAM_3WHS_SYN_TOCLIENT_ON_SYN_RECV);
            return -1;
        }

        if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.isn))) {
            SCLogDebug("ssn %p: SYN with different SEQ on SYN_RECV state", ssn);

            StreamTcpSetEvent(p, STREAM_3WHS_SYN_RESEND_DIFF_SEQ_ON_SYN_RECV);
            return -1;
        }

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->queue_len) {
            SCLogDebug("ssn %p: checking ACK against queued SYN/ACKs", ssn);
            TcpStateQueue *q = StreamTcp3whsFindSynAckByAck(ssn, p);
            if (q != NULL) {
                SCLogDebug("ssn %p: here we update state against queued SYN/ACK", ssn);
                StreamTcp3whsSynAckUpdate(ssn, p, q);
            } else {
                SCLogDebug("ssn %p: none found, now checking ACK against original SYN/ACK (state)", ssn);
            }
        }


        
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!(StreamTcpValidateTimestamp(ssn, p))) {
                return -1;
            }
        }

        if ((ssn->flags & STREAMTCP_FLAG_4WHS) && PKT_IS_TOCLIENT(p)) {
            SCLogDebug("ssn %p: ACK received on 4WHS session",ssn);

            if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq))) {
                SCLogDebug("ssn %p: 4WHS wrong seq nr on packet", ssn);
                StreamTcpSetEvent(p, STREAM_4WHS_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: 4WHS invalid ack nr on packet", ssn);
                StreamTcpSetEvent(p, STREAM_4WHS_INVALID_ACK);
                return -1;
            }

            SCLogDebug("4WHS normal pkt");
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));


            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));
            StreamTcpUpdateNextSeq(ssn, &ssn->server, (ssn->server.next_seq + p->payload_len));
            ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            ssn->client.next_win = ssn->client.last_ack + ssn->client.window;

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);

            SCLogDebug("ssn %p: ssn->client.next_win %" PRIu32 ", " "ssn->client.last_ack %"PRIu32"", ssn, ssn->client.next_win, ssn->client.last_ack);

            return 0;
        }

        bool ack_indicates_missed_3whs_ack_packet = false;
        
        if (PKT_IS_TOCLIENT(p)) {
            
            if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM_SYNACK) {
                SCLogDebug("ssn %p: ACK received on midstream SYN/ACK " "pickup session",ssn);
                
            } else if (ssn->flags & STREAMTCP_FLAG_TCP_FAST_OPEN) {
                SCLogDebug("ssn %p: ACK received on TFO session",ssn);
                

            } else {
                
                if (StreamTcpInlineMode()) {
                    if (p->payload_len > 0 && SEQ_EQ(TCP_GET_ACK(p), ssn->client.last_ack) && SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq)) {

                        
                        SCLogDebug("ssn %p: possible data injection", ssn);
                        StreamTcpSetEvent(p, STREAM_3WHS_ACK_DATA_INJECT);
                        return -1;
                    }

                    SCLogDebug("ssn %p: ACK received in the wrong direction", ssn);
                    StreamTcpSetEvent(p, STREAM_3WHS_ACK_IN_WRONG_DIR);
                    return -1;
                }
                ack_indicates_missed_3whs_ack_packet = true;
            }
        }

        SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 "" ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));


        
        if ((SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq)) && SEQ_EQ(TCP_GET_ACK(p), ssn->server.next_seq)) {
            SCLogDebug("normal pkt");

            

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));
            StreamTcpUpdateNextSeq(ssn, &ssn->client, (ssn->client.next_seq + p->payload_len));
            ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;

            if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) {
                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
                ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
                ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
                if (!(ssn->flags & STREAMTCP_FLAG_MIDSTREAM_SYNACK)) {
                    
                    ssn->server.wscale = TCP_WSCALE_MAX;
                    ssn->client.wscale = TCP_WSCALE_MAX;
                    ssn->flags |= STREAMTCP_FLAG_SACKOK;
                }
            }

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);

            
        } else if (stream_config.async_oneside == TRUE && (SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq)))
        {
            
            ssn->flags |= STREAMTCP_FLAG_ASYNC;
            ssn->server.next_seq += p->payload_len;
            ssn->server.last_ack = TCP_GET_SEQ(p);

            ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            ssn->client.last_ack = TCP_GET_ACK(p);

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) {
                ssn->server.window = TCP_GET_WINDOW(p);
                ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
                
                ssn->server.wscale = TCP_WSCALE_MAX;
                ssn->client.wscale = TCP_WSCALE_MAX;
                ssn->flags |= STREAMTCP_FLAG_SACKOK;
            }

            SCLogDebug("ssn %p: synrecv => Asynchronous stream, packet SEQ" " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), " "ssn->server.next_seq %" PRIu32 , ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p)


                    + p->payload_len, ssn->server.next_seq);

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);
            
        } else if (SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq)){
            ssn->flags |= STREAMTCP_FLAG_DETECTION_EVASION_ATTEMPT;
            SCLogDebug("ssn %p: wrong ack nr on packet, possible evasion!!", ssn);

            StreamTcpSetEvent(p, STREAM_3WHS_RIGHT_SEQ_WRONG_ACK_EVASION);
            return -1;

            
        } else if (PKT_IS_TOCLIENT(p) && !StreamTcpInlineMode() && SEQ_GT(TCP_GET_SEQ(p), ssn->client.next_seq) && SEQ_GT(TCP_GET_ACK(p), ssn->client.last_ack)) {

            SCLogDebug("ssn %p: ACK for missing data", ssn);

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len;
            SCLogDebug("ssn %p: ACK for missing data: ssn->server.next_seq %u", ssn, ssn->server.next_seq);
            ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

            ssn->client.next_win = ssn->client.last_ack + ssn->client.window;

            ssn->client.window = TCP_GET_WINDOW(p);
            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);

            
        } else if (SEQ_GT(TCP_GET_SEQ(p), ssn->client.next_seq) && SEQ_LEQ(TCP_GET_SEQ(p), ssn->client.next_win) && SEQ_EQ(TCP_GET_ACK(p), ssn->server.next_seq)) {

            SCLogDebug("ssn %p: ACK for missing data", ssn);

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            ssn->client.next_seq = TCP_GET_SEQ(p) + p->payload_len;
            SCLogDebug("ssn %p: ACK for missing data: ssn->client.next_seq %u", ssn, ssn->client.next_seq);
            ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;

            if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) {
                ssn->client.window = TCP_GET_WINDOW(p);
                ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
                
                ssn->server.wscale = TCP_WSCALE_MAX;
                ssn->client.wscale = TCP_WSCALE_MAX;
                ssn->flags |= STREAMTCP_FLAG_SACKOK;
            }

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);

        
        } else if ((ack_indicates_missed_3whs_ack_packet || (ssn->flags & STREAMTCP_FLAG_TCP_FAST_OPEN)) && SEQ_EQ(TCP_GET_ACK(p), ssn->client.last_ack) && SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq)) {


            if (ack_indicates_missed_3whs_ack_packet) {
                SCLogDebug("ssn %p: packet fits perfectly after a missed 3whs-ACK", ssn);
            } else {
                SCLogDebug("ssn %p: (TFO) expected packet fits perfectly after SYN/ACK", ssn);
            }

            StreamTcpUpdateNextSeq(ssn, &ssn->server, (TCP_GET_SEQ(p) + p->payload_len));

            ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);

        } else {
            SCLogDebug("ssn %p: wrong seq nr on packet", ssn);

            StreamTcpSetEvent(p, STREAM_3WHS_WRONG_SEQ_WRONG_ACK);
            return -1;
        }

        SCLogDebug("ssn %p: ssn->server.next_win %" PRIu32 ", " "ssn->server.last_ack %"PRIu32"", ssn, ssn->server.next_win, ssn->server.last_ack);

    } else {
        SCLogDebug("ssn %p: default case", ssn);
    }

    return 0;
}


static int HandleEstablishedPacketToServer(ThreadVars *tv, TcpSession *ssn, Packet *p, StreamTcpThread *stt, PacketQueueNoLock *pq)
{
    SCLogDebug("ssn %p: =+ pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 "," "ACK %" PRIu32 ", WIN %"PRIu16"", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p), TCP_GET_WINDOW(p));


    if (StreamTcpValidateAck(ssn, &(ssn->server), p) == -1) {
        SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
        StreamTcpSetEvent(p, STREAM_EST_INVALID_ACK);
        return -1;
    }

    
    if ((p->payload_len == 0 || p->payload_len == 1) && (TCP_GET_SEQ(p) == (ssn->client.next_seq - 1))) {
        SCLogDebug("ssn %p: pkt is keep alive", ssn);

    
    } else if (!(SEQ_GEQ((TCP_GET_SEQ(p)+p->payload_len), ssn->client.last_ack))) {
        if (ssn->flags & STREAMTCP_FLAG_ASYNC) {
            SCLogDebug("ssn %p: server => Asynchrouns stream, packet SEQ" " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 ")," " ssn->client.last_ack %" PRIu32 ", ssn->client.next_win" "%" PRIu32"(%"PRIu32")", ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p) + p->payload_len, ssn->client.last_ack, ssn->client.next_win, TCP_GET_SEQ(p) + p->payload_len - ssn->client.next_win);






            
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_SEQ(p));

        } else if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p)) && (stream_config.async_oneside == TRUE) && (ssn->flags & STREAMTCP_FLAG_MIDSTREAM)) {

            SCLogDebug("ssn %p: server => Asynchronous stream, packet SEQ." " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), " "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win " "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p) + p->payload_len, ssn->client.last_ack, ssn->client.next_win, TCP_GET_SEQ(p) + p->payload_len - ssn->client.next_win);






            
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_SEQ(p));
            ssn->flags |= STREAMTCP_FLAG_ASYNC;

        } else if (SEQ_EQ(ssn->client.last_ack, (ssn->client.isn + 1)) && (stream_config.async_oneside == TRUE) && (ssn->flags & STREAMTCP_FLAG_MIDSTREAM)) {

            SCLogDebug("ssn %p: server => Asynchronous stream, packet SEQ" " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), " "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win " "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p) + p->payload_len, ssn->client.last_ack, ssn->client.next_win, TCP_GET_SEQ(p) + p->payload_len - ssn->client.next_win);






            
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_SEQ(p));
            ssn->flags |= STREAMTCP_FLAG_ASYNC;

        
        } else if (SEQ_GT(ssn->client.last_ack, ssn->client.next_seq) && SEQ_GT((TCP_GET_SEQ(p)+p->payload_len),ssn->client.next_seq))
        {
            SCLogDebug("ssn %p: PKT SEQ %"PRIu32" payload_len %"PRIu16 " before last_ack %"PRIu32", after next_seq %"PRIu32":" " acked data that we haven't seen before", ssn, TCP_GET_SEQ(p), p->payload_len, ssn->client.last_ack, ssn->client.next_seq);


            if (SEQ_EQ(TCP_GET_SEQ(p),ssn->client.next_seq)) {
                StreamTcpUpdateNextSeq(ssn, &ssn->client, (ssn->client.next_seq + p->payload_len));
            }
        } else {
            SCLogDebug("ssn %p: server => SEQ before last_ack, packet SEQ" " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), " "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win " "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p) + p->payload_len, ssn->client.last_ack, ssn->client.next_win, TCP_GET_SEQ(p) + p->payload_len - ssn->client.next_win);






            SCLogDebug("ssn %p: rejecting because pkt before last_ack", ssn);
            StreamTcpSetEvent(p, STREAM_EST_PKT_BEFORE_LAST_ACK);
            return -1;
        }
    }

    int zerowindowprobe = 0;
    
    if (p->payload_len == 1 && TCP_GET_SEQ(p) == ssn->client.next_seq && ssn->client.window == 0) {
        SCLogDebug("ssn %p: zero window probe", ssn);
        zerowindowprobe = 1;

    
    } else if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
        StreamTcpUpdateNextSeq(ssn, &ssn->client, (ssn->client.next_seq + p->payload_len));

    
    } else if (SEQ_LT(TCP_GET_SEQ(p),ssn->client.next_seq) && SEQ_GT((TCP_GET_SEQ(p)+p->payload_len), ssn->client.next_seq))
    {
        StreamTcpUpdateNextSeq(ssn, &ssn->client, (TCP_GET_SEQ(p) + p->payload_len));
        SCLogDebug("ssn %p: ssn->client.next_seq %"PRIu32 " (started before next_seq, ended after)", ssn, ssn->client.next_seq);


    
    } else if (SEQ_LT(ssn->client.next_seq, ssn->client.last_ack)) {
        StreamTcpUpdateNextSeq(ssn, &ssn->client, (TCP_GET_SEQ(p) + p->payload_len));
        SCLogDebug("ssn %p: ssn->client.next_seq %"PRIu32 " (next_seq had fallen behind last_ack)", ssn, ssn->client.next_seq);


    } else {
        SCLogDebug("ssn %p: no update to ssn->client.next_seq %"PRIu32 " SEQ %u SEQ+ %u last_ack %u", ssn, ssn->client.next_seq, TCP_GET_SEQ(p), TCP_GET_SEQ(p)+p->payload_len, ssn->client.last_ack);


    }

    
    if (zerowindowprobe) {
        SCLogDebug("ssn %p: zero window probe, skipping oow check", ssn);
    } else if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->client.next_win) || (ssn->flags & (STREAMTCP_FLAG_MIDSTREAM|STREAMTCP_FLAG_ASYNC)))
    {
        SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->client.next_win " "%" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->client.next_win);

        ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
        SCLogDebug("ssn %p: ssn->server.window %"PRIu32"", ssn, ssn->server.window);

        
        if (p->tcph->th_flags & TH_ACK)
            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));
        SCLogDebug("ack %u last_ack %u next_seq %u", TCP_GET_ACK(p), ssn->server.last_ack, ssn->server.next_seq);

        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            StreamTcpHandleTimestamp(ssn, p);
        }

        StreamTcpSackUpdatePacket(&ssn->server, p);

        
        StreamTcpUpdateNextWin(ssn, &ssn->server, (ssn->server.last_ack + ssn->server.window));

        
        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);

    } else {
        SCLogDebug("ssn %p: toserver => SEQ out of window, packet SEQ " "%" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 ")," "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win " "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p) + p->payload_len, ssn->client.last_ack, ssn->client.next_win, (TCP_GET_SEQ(p) + p->payload_len) - ssn->client.next_win);





        SCLogDebug("ssn %p: window %u sacked %u", ssn, ssn->client.window, StreamTcpSackedSize(&ssn->client));
        StreamTcpSetEvent(p, STREAM_EST_PACKET_OUT_OF_WINDOW);
        return -1;
    }
    return 0;
}


static int HandleEstablishedPacketToClient(ThreadVars *tv, TcpSession *ssn, Packet *p, StreamTcpThread *stt, PacketQueueNoLock *pq)
{
    SCLogDebug("ssn %p: =+ pkt (%" PRIu32 ") is to client: SEQ %" PRIu32 "," " ACK %" PRIu32 ", WIN %"PRIu16"", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p), TCP_GET_WINDOW(p));


    if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
        SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
        StreamTcpSetEvent(p, STREAM_EST_INVALID_ACK);
        return -1;
    }

    
    if ((ssn->flags & STREAMTCP_FLAG_MIDSTREAM) && (ssn->flags & STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED))
    {
        ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
        ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
        ssn->flags &= ~STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED;
        SCLogDebug("ssn %p: adjusted midstream ssn->server.next_win to " "%" PRIu32 "", ssn, ssn->server.next_win);
    }

    
    if ((p->payload_len == 0 || p->payload_len == 1) && (TCP_GET_SEQ(p) == (ssn->server.next_seq - 1))) {
        SCLogDebug("ssn %p: pkt is keep alive", ssn);

    
    } else if (!(SEQ_GEQ((TCP_GET_SEQ(p)+p->payload_len), ssn->server.last_ack))) {
        if (ssn->flags & STREAMTCP_FLAG_ASYNC) {

            SCLogDebug("ssn %p: client => Asynchrouns stream, packet SEQ" " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 ")," " ssn->client.last_ack %" PRIu32 ", ssn->client.next_win" " %"PRIu32"(%"PRIu32")", ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p) + p->payload_len, ssn->server.last_ack, ssn->server.next_win, TCP_GET_SEQ(p) + p->payload_len - ssn->server.next_win);






            ssn->server.last_ack = TCP_GET_SEQ(p);

        
        } else if (SEQ_GT(ssn->server.last_ack, ssn->server.next_seq) && SEQ_GT((TCP_GET_SEQ(p)+p->payload_len),ssn->server.next_seq))
        {
            SCLogDebug("ssn %p: PKT SEQ %"PRIu32" payload_len %"PRIu16 " before last_ack %"PRIu32", after next_seq %"PRIu32":" " acked data that we haven't seen before", ssn, TCP_GET_SEQ(p), p->payload_len, ssn->server.last_ack, ssn->server.next_seq);


            if (SEQ_EQ(TCP_GET_SEQ(p),ssn->server.next_seq)) {
                StreamTcpUpdateNextSeq(ssn, &ssn->server, (ssn->server.next_seq + p->payload_len));
            }
        } else {
            SCLogDebug("ssn %p: PKT SEQ %"PRIu32" payload_len %"PRIu16 " before last_ack %"PRIu32". next_seq %"PRIu32, ssn, TCP_GET_SEQ(p), p->payload_len, ssn->server.last_ack, ssn->server.next_seq);

            StreamTcpSetEvent(p, STREAM_EST_PKT_BEFORE_LAST_ACK);
            return -1;
        }
    }

    int zerowindowprobe = 0;
    
    if (p->payload_len == 1 && TCP_GET_SEQ(p) == ssn->server.next_seq && ssn->server.window == 0) {
        SCLogDebug("ssn %p: zero window probe", ssn);
        zerowindowprobe = 1;

    
    } else if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(p))) {
        StreamTcpUpdateNextSeq(ssn, &ssn->server, (ssn->server.next_seq + p->payload_len));

    
    } else if (SEQ_LT(TCP_GET_SEQ(p),ssn->server.next_seq) && SEQ_GT((TCP_GET_SEQ(p)+p->payload_len), ssn->server.next_seq))
    {
        StreamTcpUpdateNextSeq(ssn, &ssn->server, (TCP_GET_SEQ(p) + p->payload_len));
        SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 " (started before next_seq, ended after)", ssn, ssn->server.next_seq);


    
    } else if (SEQ_LT(ssn->server.next_seq, ssn->server.last_ack)) {
        StreamTcpUpdateNextSeq(ssn, &ssn->server, (TCP_GET_SEQ(p) + p->payload_len));
        SCLogDebug("ssn %p: ssn->server.next_seq %"PRIu32 " (next_seq had fallen behind last_ack)", ssn, ssn->server.next_seq);


    } else {
        SCLogDebug("ssn %p: no update to ssn->server.next_seq %"PRIu32 " SEQ %u SEQ+ %u last_ack %u", ssn, ssn->server.next_seq, TCP_GET_SEQ(p), TCP_GET_SEQ(p)+p->payload_len, ssn->server.last_ack);


    }

    if (zerowindowprobe) {
        SCLogDebug("ssn %p: zero window probe, skipping oow check", ssn);
    } else if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->server.next_win) || (ssn->flags & (STREAMTCP_FLAG_MIDSTREAM|STREAMTCP_FLAG_ASYNC)))
    {
        SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->server.next_win " "%" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->server.next_win);
        ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
        SCLogDebug("ssn %p: ssn->client.window %"PRIu32"", ssn, ssn->client.window);

        if (p->tcph->th_flags & TH_ACK)
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            StreamTcpHandleTimestamp(ssn, p);
        }

        StreamTcpSackUpdatePacket(&ssn->client, p);

        StreamTcpUpdateNextWin(ssn, &ssn->client, (ssn->client.last_ack + ssn->client.window));

        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);
    } else {
        SCLogDebug("ssn %p: client => SEQ out of window, packet SEQ" "%" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 ")," " ssn->server.last_ack %" PRIu32 ", ssn->server.next_win " "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p) + p->payload_len, ssn->server.last_ack, ssn->server.next_win, TCP_GET_SEQ(p) + p->payload_len - ssn->server.next_win);





        StreamTcpSetEvent(p, STREAM_EST_PACKET_OUT_OF_WINDOW);
        return -1;
    }
    return 0;
}


static inline uint32_t StreamTcpResetGetMaxAck(TcpStream *stream, uint32_t seq)
{
    uint32_t ack = seq;

    if (STREAM_HAS_SEEN_DATA(stream)) {
        const uint32_t tail_seq = STREAM_SEQ_RIGHT_EDGE(stream);
        if (SEQ_GT(tail_seq, ack)) {
            ack = tail_seq;
        }
    }

    SCReturnUInt(ack);
}


static bool StreamTcpPacketIsOutdatedAck(TcpSession *ssn, Packet *p)
{
    if (ssn->state < TCP_ESTABLISHED)
        return false;
    if (p->payload_len != 0)
        return false;
    if ((p->tcph->th_flags & (TH_ACK | TH_SYN | TH_FIN | TH_RST)) != TH_ACK)
        return false;

    
    if (PKT_IS_TOSERVER(p)) {
        if (SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq) && SEQ_LT(TCP_GET_ACK(p), ssn->server.last_ack)) {
            if (!TCP_HAS_SACK(p)) {
                SCLogDebug("outdated ACK (no SACK, SEQ %u vs next_seq %u)", TCP_GET_SEQ(p), ssn->client.next_seq);
                return true;
            }

            if (StreamTcpSackPacketIsOutdated(&ssn->server, p)) {
                SCLogDebug("outdated ACK (have SACK, SEQ %u vs next_seq %u)", TCP_GET_SEQ(p), ssn->client.next_seq);
                return true;
            }
        }
    } else {
        if (SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq) && SEQ_LT(TCP_GET_ACK(p), ssn->client.last_ack)) {
            if (!TCP_HAS_SACK(p)) {
                SCLogDebug("outdated ACK (no SACK, SEQ %u vs next_seq %u)", TCP_GET_SEQ(p), ssn->client.next_seq);
                return true;
            }

            if (StreamTcpSackPacketIsOutdated(&ssn->client, p)) {
                SCLogDebug("outdated ACK (have SACK, SEQ %u vs next_seq %u)", TCP_GET_SEQ(p), ssn->client.next_seq);
                return true;
            }
        }
    }
    return false;
}



static int StreamTcpPacketStateEstablished(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        if (PKT_IS_TOSERVER(p)) {
            StreamTcpCloseSsnWithReset(p, ssn);

            ssn->server.next_seq = TCP_GET_ACK(p);
            ssn->client.next_seq = TCP_GET_SEQ(p) + p->payload_len;
            SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "", ssn, ssn->server.next_seq);
            ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->server, StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client, StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK " "%" PRIu32 "", ssn, ssn->client.next_seq, ssn->server.last_ack);


            
        } else {
            StreamTcpCloseSsnWithReset(p, ssn);

            ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len + 1;
            ssn->client.next_seq = TCP_GET_ACK(p);

            SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "", ssn, ssn->server.next_seq);
            ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->client, StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server, StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK " "%" PRIu32 "", ssn, ssn->server.next_seq, ssn->client.last_ack);


            
        }

    } else if (p->tcph->th_flags & TH_FIN) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        SCLogDebug("ssn (%p: FIN received SEQ" " %" PRIu32 ", last ACK %" PRIu32 ", next win %"PRIu32"," " win %" PRIu32 "", ssn, ssn->server.next_seq, ssn->client.last_ack, ssn->server.next_win, ssn->server.window);




        if ((StreamTcpHandleFin(tv, stt, ssn, p, pq)) == -1)
            return -1;

    
    } else if ((p->tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
        SCLogDebug("ssn %p: SYN/ACK packet on state ESTABLISHED... resent", ssn);

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: SYN/ACK-pkt to server in ESTABLISHED state", ssn);

            StreamTcpSetEvent(p, STREAM_EST_SYNACK_TOSERVER);
            return -1;
        }

        
        if (!(SEQ_EQ(TCP_GET_ACK(p), ssn->client.last_ack))) {
            SCLogDebug("ssn %p: ACK mismatch, packet ACK %" PRIu32 " != " "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p), ssn->client.isn + 1);


            StreamTcpSetEvent(p, STREAM_EST_SYNACK_RESEND_WITH_DIFFERENT_ACK);
            return -1;
        }

        
        if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->server.isn))) {
            SCLogDebug("ssn %p: SEQ mismatch, packet SEQ %" PRIu32 " != " "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p), ssn->client.isn + 1);


            StreamTcpSetEvent(p, STREAM_EST_SYNACK_RESEND_WITH_DIFF_SEQ);
            return -1;
        }

        if (ssn->flags & STREAMTCP_FLAG_3WHS_CONFIRMED) {
            
            StreamTcpSetEvent(p, STREAM_EST_SYNACK_RESEND);
            return -1;
        }

        SCLogDebug("ssn %p: SYN/ACK packet on state ESTABLISHED... resent. " "Likely due server not receiving final ACK in 3whs", ssn);
        return 0;

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn %p: SYN packet on state ESTABLISHED... resent", ssn);
        if (PKT_IS_TOCLIENT(p)) {
            SCLogDebug("ssn %p: SYN-pkt to client in EST state", ssn);

            StreamTcpSetEvent(p, STREAM_EST_SYN_TOCLIENT);
            return -1;
        }

        if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.isn))) {
            SCLogDebug("ssn %p: SYN with different SEQ on SYN_RECV state", ssn);

            StreamTcpSetEvent(p, STREAM_EST_SYN_RESEND_DIFF_SEQ);
            return -1;
        }

        
        StreamTcpSetEvent(p, STREAM_EST_SYN_RESEND);
        return -1;

    } else if (p->tcph->th_flags & TH_ACK) {
        

        
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            
            HandleEstablishedPacketToServer(tv, ssn, p, stt, pq);

            SCLogDebug("ssn %p: next SEQ %" PRIu32 ", last ACK %" PRIu32 "," " next win %" PRIu32 ", win %" PRIu32 "", ssn, ssn->client.next_seq, ssn->server.last_ack ,ssn->client.next_win, ssn->client.window);



        } else { 
            if (!(ssn->flags & STREAMTCP_FLAG_3WHS_CONFIRMED)) {
                ssn->flags |= STREAMTCP_FLAG_3WHS_CONFIRMED;
                SCLogDebug("3whs is now confirmed by server");
            }

            
            HandleEstablishedPacketToClient(tv, ssn, p, stt, pq);

            SCLogDebug("ssn %p: next SEQ %" PRIu32 ", last ACK %" PRIu32 "," " next win %" PRIu32 ", win %" PRIu32 "", ssn, ssn->server.next_seq, ssn->client.last_ack, ssn->server.next_win, ssn->server.window);


        }
    } else {
        SCLogDebug("ssn %p: default case", ssn);
    }

    return 0;
}



static int StreamTcpHandleFin(ThreadVars *tv, StreamTcpThread *stt, TcpSession *ssn, Packet *p, PacketQueueNoLock *pq)
{
    if (PKT_IS_TOSERVER(p)) {
        SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 "," " ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));


        if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
            SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
            StreamTcpSetEvent(p, STREAM_FIN_INVALID_ACK);
            return -1;
        }

        if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq) || SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window)))
        {
            SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != " "%" PRIu32 " from stream", ssn, TCP_GET_SEQ(p), ssn->client.next_seq);


            StreamTcpSetEvent(p, STREAM_FIN_OUT_OF_WINDOW);
            return -1;
        }

        StreamTcpPacketSetState(p, ssn, TCP_CLOSE_WAIT);
        SCLogDebug("ssn %p: state changed to TCP_CLOSE_WAIT", ssn);

        if (SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq))
            ssn->client.next_seq = TCP_GET_SEQ(p) + p->payload_len;

        SCLogDebug("ssn %p: ssn->client.next_seq %" PRIu32 "", ssn, ssn->client.next_seq);
        ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

        if (p->tcph->th_flags & TH_ACK)
            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            StreamTcpHandleTimestamp(ssn, p);
        }

        
        if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
            ssn->server.next_seq = TCP_GET_ACK(p);

        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);

        SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "", ssn, ssn->client.next_seq, ssn->server.last_ack);
    } else { 
        SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ %" PRIu32 ", " "ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));


        if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
            SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
            StreamTcpSetEvent(p, STREAM_FIN_INVALID_ACK);
            return -1;
        }

        if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) || SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window)))
        {
            SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != " "%" PRIu32 " from stream (last_ack %u win %u = %u)", ssn, TCP_GET_SEQ(p), ssn->server.next_seq, ssn->server.last_ack, ssn->server.window, (ssn->server.last_ack + ssn->server.window));


            StreamTcpSetEvent(p, STREAM_FIN_OUT_OF_WINDOW);
            return -1;
        }

        StreamTcpPacketSetState(p, ssn, TCP_FIN_WAIT1);
        SCLogDebug("ssn %p: state changed to TCP_FIN_WAIT1", ssn);

        if (SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq))
            ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len;

        SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "", ssn, ssn->server.next_seq);
        ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

        if (p->tcph->th_flags & TH_ACK)
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            StreamTcpHandleTimestamp(ssn, p);
        }

        
        if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
            ssn->client.next_seq = TCP_GET_ACK(p);

        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);

        SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "", ssn, ssn->server.next_seq, ssn->client.last_ack);
    }

    return 0;
}



static int StreamTcpPacketStateFinWait1(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        StreamTcpCloseSsnWithReset(p, ssn);

        if (PKT_IS_TOSERVER(p)) {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->server, StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client, StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);
        } else {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->client, StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server, StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);
        }

    } else if ((p->tcph->th_flags & (TH_FIN|TH_ACK)) == (TH_FIN|TH_ACK)) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq) || SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window)))
            {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 "" " != %" PRIu32 " from stream", ssn, TCP_GET_SEQ(p), ssn->client.next_seq);

                StreamTcpSetEvent(p, STREAM_FIN1_FIN_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN1_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
                StreamTcpUpdateNextSeq(ssn, &ssn->client, (ssn->client.next_seq + p->payload_len));
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK " "%" PRIu32 "", ssn, ssn->client.next_seq, ssn->server.last_ack);

        } else { 
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            } else if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(p)) && SEQ_EQ(ssn->client.last_ack, TCP_GET_ACK(p))) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) || SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window))) {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 "" " != %" PRIu32 " from stream", ssn, TCP_GET_SEQ(p), ssn->server.next_seq);

                StreamTcpSetEvent(p, STREAM_FIN1_FIN_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN1_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(p))) {
                StreamTcpUpdateNextSeq(ssn, &ssn->server, (ssn->server.next_seq + p->payload_len));
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK " "%" PRIu32 "", ssn, ssn->server.next_seq, ssn->client.last_ack);

        }

    } else if (p->tcph->th_flags & TH_FIN) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq) || SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window)))
            {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 "" " != %" PRIu32 " from stream", ssn, TCP_GET_SEQ(p), ssn->client.next_seq);

                StreamTcpSetEvent(p, STREAM_FIN1_FIN_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN1_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_CLOSING);
                SCLogDebug("ssn %p: state changed to TCP_CLOSING", ssn);

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            if (p->tcph->th_flags & TH_ACK)
                StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
                StreamTcpUpdateNextSeq(ssn, &ssn->client, (ssn->client.next_seq + p->payload_len));
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK " "%" PRIu32 "", ssn, ssn->client.next_seq, ssn->server.last_ack);

        } else { 
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));


            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) || SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window)))
            {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 "" " != %" PRIu32 " from stream", ssn, TCP_GET_SEQ(p), ssn->server.next_seq);

                StreamTcpSetEvent(p, STREAM_FIN1_FIN_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN1_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_CLOSING);
                SCLogDebug("ssn %p: state changed to TCP_CLOSING", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            if (p->tcph->th_flags & TH_ACK)
                StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(p))) {
                StreamTcpUpdateNextSeq(ssn, &ssn->server, (ssn->server.next_seq + p->payload_len));
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK " "%" PRIu32 "", ssn, ssn->server.next_seq, ssn->client.last_ack);

        }
    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn (%p): SYN pkt on FinWait1", ssn);
        StreamTcpSetEvent(p, STREAM_SHUTDOWN_SYN_RESEND);
        return -1;

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN1_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->client.next_win) || (ssn->flags & (STREAMTCP_FLAG_MIDSTREAM|STREAMTCP_FLAG_ASYNC)))
                {
                    SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->client.next_win " "%" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->client.next_win);

                    if (TCP_GET_SEQ(p) == ssn->client.next_seq) {
                        StreamTcpPacketSetState(p, ssn, TCP_FIN_WAIT2);
                        SCLogDebug("ssn %p: state changed to TCP_FIN_WAIT2", ssn);
                    }
                } else {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 "" " != %" PRIu32 " from stream", ssn, TCP_GET_SEQ(p), ssn->client.next_seq);


                    StreamTcpSetEvent(p, STREAM_FIN1_ACK_WRONG_SEQ);
                    return -1;
                }

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
                StreamTcpUpdateNextSeq(ssn, &ssn->client, (ssn->client.next_seq + p->payload_len));
            }

            StreamTcpSackUpdatePacket(&ssn->server, p);

            
            StreamTcpUpdateNextWin(ssn, &ssn->server, (ssn->server.last_ack + ssn->server.window));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK " "%" PRIu32 "", ssn, ssn->client.next_seq, ssn->server.last_ack);


        } else { 

            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));


            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN1_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->server.next_win) || (ssn->flags & (STREAMTCP_FLAG_MIDSTREAM|STREAMTCP_FLAG_ASYNC)))
                {
                    SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->server.next_win " "%" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->server.next_win);

                    if (TCP_GET_SEQ(p) == ssn->server.next_seq) {
                        StreamTcpPacketSetState(p, ssn, TCP_FIN_WAIT2);
                        SCLogDebug("ssn %p: state changed to TCP_FIN_WAIT2", ssn);
                    }
                } else {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 "" " != %" PRIu32 " from stream", ssn, TCP_GET_SEQ(p), ssn->server.next_seq);

                    StreamTcpSetEvent(p, STREAM_FIN1_ACK_WRONG_SEQ);
                    return -1;
                }

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(p))) {
                StreamTcpUpdateNextSeq(ssn, &ssn->server, (ssn->server.next_seq + p->payload_len));
            }

            StreamTcpSackUpdatePacket(&ssn->client, p);

            
            StreamTcpUpdateNextWin(ssn, &ssn->client, (ssn->client.last_ack + ssn->client.window));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK " "%" PRIu32 "", ssn, ssn->server.next_seq, ssn->client.last_ack);

        }
    } else {
        SCLogDebug("ssn (%p): default case", ssn);
    }

    return 0;
}



static int StreamTcpPacketStateFinWait2(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        StreamTcpCloseSsnWithReset(p, ssn);

        if (PKT_IS_TOSERVER(p)) {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->server, StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client, StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);
        } else {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->client, StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server, StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);
        }

    } else if (p->tcph->th_flags & TH_FIN) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;

            if (SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq - 1) && SEQ_EQ(TCP_GET_ACK(p), ssn->server.last_ack)) {
                SCLogDebug("ssn %p: retransmission", ssn);
                retransmission = 1;
            } else if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq) || SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window)))
            {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ " "%" PRIu32 " != %" PRIu32 " from stream", ssn, TCP_GET_SEQ(p), ssn->client.next_seq);

                StreamTcpSetEvent(p, STREAM_FIN2_FIN_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN2_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
                    StreamTcpUpdateNextSeq( ssn, &ssn->client, (ssn->client.next_seq + p->payload_len));
                }
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            if (p->tcph->th_flags & TH_ACK)
                StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK " "%" PRIu32 "", ssn, ssn->client.next_seq, ssn->server.last_ack);

        } else { 
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;

            if (SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq - 1) && SEQ_EQ(TCP_GET_ACK(p), ssn->client.last_ack)) {
                SCLogDebug("ssn %p: retransmission", ssn);
                retransmission = 1;
            } else if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) || SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window)))
            {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ " "%" PRIu32 " != %" PRIu32 " from stream", ssn, TCP_GET_SEQ(p), ssn->server.next_seq);

                StreamTcpSetEvent(p, STREAM_FIN2_FIN_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN2_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            if (p->tcph->th_flags & TH_ACK)
                StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK " "%" PRIu32 "", ssn, ssn->server.next_seq, ssn->client.last_ack);

        }

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn (%p): SYN pkt on FinWait2", ssn);
        StreamTcpSetEvent(p, STREAM_SHUTDOWN_SYN_RESEND);
        return -1;

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN2_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->client.next_win) || (ssn->flags & (STREAMTCP_FLAG_MIDSTREAM|STREAMTCP_FLAG_ASYNC)))
                {
                    SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->client.next_win " "%" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->client.next_win);

                } else {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 "" " != %" PRIu32 " from stream", ssn, TCP_GET_SEQ(p), ssn->client.next_seq);

                    StreamTcpSetEvent(p, STREAM_FIN2_ACK_WRONG_SEQ);
                    return -1;
                }

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
                StreamTcpUpdateNextSeq(ssn, &ssn->client, (ssn->client.next_seq + p->payload_len));
            }

            StreamTcpSackUpdatePacket(&ssn->server, p);

            
            StreamTcpUpdateNextWin(ssn, &ssn->server, (ssn->server.last_ack + ssn->server.window));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK " "%" PRIu32 "", ssn, ssn->client.next_seq, ssn->server.last_ack);

        } else { 
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN2_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->server.next_win) || (ssn->flags & (STREAMTCP_FLAG_MIDSTREAM|STREAMTCP_FLAG_ASYNC)))
                {
                    SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->server.next_win " "%" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->server.next_win);
                } else {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 "" " != %" PRIu32 " from stream", ssn, TCP_GET_SEQ(p), ssn->server.next_seq);

                    StreamTcpSetEvent(p, STREAM_FIN2_ACK_WRONG_SEQ);
                    return -1;
                }

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(p))) {
                StreamTcpUpdateNextSeq(ssn, &ssn->server, (ssn->server.next_seq + p->payload_len));
            }

            StreamTcpSackUpdatePacket(&ssn->client, p);

            
            StreamTcpUpdateNextWin(ssn, &ssn->client, (ssn->client.last_ack + ssn->client.window));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK " "%" PRIu32 "", ssn, ssn->server.next_seq, ssn->client.last_ack);

        }
    } else {
        SCLogDebug("ssn %p: default case", ssn);
    }

    return 0;
}



static int StreamTcpPacketStateClosing(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        StreamTcpCloseSsnWithReset(p, ssn);

        if (PKT_IS_TOSERVER(p)) {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->server, StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client, StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);
        } else {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->client, StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server, StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);
        }

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn (%p): SYN pkt on Closing", ssn);
        StreamTcpSetEvent(p, STREAM_SHUTDOWN_SYN_RESEND);
        return -1;

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (TCP_GET_SEQ(p) != ssn->client.next_seq) {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 "" " != %" PRIu32 " from stream", ssn, TCP_GET_SEQ(p), ssn->client.next_seq);

                StreamTcpSetEvent(p, STREAM_CLOSING_ACK_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSING_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }
            
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK " "%" PRIu32 "", ssn, ssn->client.next_seq, ssn->server.last_ack);

        } else { 
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (TCP_GET_SEQ(p) != ssn->server.next_seq) {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 "" " != %" PRIu32 " from stream", ssn, TCP_GET_SEQ(p), ssn->server.next_seq);

                StreamTcpSetEvent(p, STREAM_CLOSING_ACK_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSING_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);
            SCLogDebug("StreamTcpPacketStateClosing (%p): =+ next SEQ " "%" PRIu32 ", last ACK %" PRIu32 "", ssn, ssn->server.next_seq, ssn->client.last_ack);

        }
    } else {
        SCLogDebug("ssn %p: default case", ssn);
    }

    return 0;
}



static int StreamTcpPacketStateCloseWait(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq)
{
    SCEnter();

    if (ssn == NULL) {
        SCReturnInt(-1);
    }

    if (PKT_IS_TOCLIENT(p)) {
        SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

    } else {
        SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

    }

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        StreamTcpCloseSsnWithReset(p, ssn);

        if (PKT_IS_TOSERVER(p)) {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->server, StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client, StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);
        } else {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->client, StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server, StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);
        }

    } else if (p->tcph->th_flags & TH_FIN) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                SCReturnInt(-1);
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));


            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (!retransmission) {
                if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq) || SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window)))
                {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 "" " != %" PRIu32 " from stream", ssn, TCP_GET_SEQ(p), ssn->client.next_seq);

                    StreamTcpSetEvent(p, STREAM_CLOSEWAIT_FIN_OUT_OF_WINDOW);
                    SCReturnInt(-1);
                }
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_INVALID_ACK);
                SCReturnInt(-1);
            }

            

            if (!retransmission)
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

            if (p->tcph->th_flags & TH_ACK)
                StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK " "%" PRIu32 "", ssn, ssn->client.next_seq, ssn->server.last_ack);

        } else {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));


            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (!retransmission) {
                if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) || SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window)))
                {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 "" " != %" PRIu32 " from stream", ssn, TCP_GET_SEQ(p), ssn->server.next_seq);

                    StreamTcpSetEvent(p, STREAM_CLOSEWAIT_FIN_OUT_OF_WINDOW);
                    SCReturnInt(-1);
                }
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_INVALID_ACK);
                SCReturnInt(-1);
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_LAST_ACK);
                SCLogDebug("ssn %p: state changed to TCP_LAST_ACK", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            if (p->tcph->th_flags & TH_ACK)
                StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK " "%" PRIu32 "", ssn, ssn->server.next_seq, ssn->client.last_ack);

        }

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn (%p): SYN pkt on CloseWait", ssn);
        StreamTcpSetEvent(p, STREAM_SHUTDOWN_SYN_RESEND);
        SCReturnInt(-1);

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                SCReturnInt(-1);
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));


            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (p->payload_len > 0 && (SEQ_LEQ((TCP_GET_SEQ(p) + p->payload_len), ssn->client.last_ack))) {
                SCLogDebug("ssn %p: -> retransmission", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_PKT_BEFORE_LAST_ACK);
                SCReturnInt(-1);

            } else if (SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window)))
            {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 "" " != %" PRIu32 " from stream", ssn, TCP_GET_SEQ(p), ssn->client.next_seq);

                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_ACK_OUT_OF_WINDOW);
                SCReturnInt(-1);
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_INVALID_ACK);
                SCReturnInt(-1);
            }

            if (!retransmission) {
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(TCP_GET_SEQ(p),ssn->client.next_seq))
                StreamTcpUpdateNextSeq(ssn, &ssn->client, (ssn->client.next_seq + p->payload_len));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK " "%" PRIu32 "", ssn, ssn->client.next_seq, ssn->server.last_ack);

        } else {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (p->payload_len > 0 && (SEQ_LEQ((TCP_GET_SEQ(p) + p->payload_len), ssn->server.last_ack))) {
                SCLogDebug("ssn %p: -> retransmission", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_PKT_BEFORE_LAST_ACK);
                SCReturnInt(-1);

            } else if (SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window)))
            {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 "" " != %" PRIu32 " from stream", ssn, TCP_GET_SEQ(p), ssn->server.next_seq);

                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_ACK_OUT_OF_WINDOW);
                SCReturnInt(-1);
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_INVALID_ACK);
                SCReturnInt(-1);
            }

            if (!retransmission) {
                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(TCP_GET_SEQ(p),ssn->server.next_seq))
                StreamTcpUpdateNextSeq(ssn, &ssn->server, (ssn->server.next_seq + p->payload_len));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK " "%" PRIu32 "", ssn, ssn->server.next_seq, ssn->client.last_ack);

        }

    } else {
        SCLogDebug("ssn %p: default case", ssn);
    }
    SCReturnInt(0);
}



static int StreamTcpPacketStateLastAck(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        StreamTcpCloseSsnWithReset(p, ssn);

        if (PKT_IS_TOSERVER(p)) {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->server, StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client, StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);
        } else {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->client, StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server, StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);
        }

    } else if (p->tcph->th_flags & TH_FIN) {
        
        SCLogDebug("ssn (%p): FIN pkt on LastAck", ssn);

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn (%p): SYN pkt on LastAck", ssn);
        StreamTcpSetEvent(p, STREAM_SHUTDOWN_SYN_RESEND);
        return -1;

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));


            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_LASTACK_INVALID_ACK);
                SCReturnInt(-1);
            }

            if (!retransmission) {
                if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq)) {
                    SCLogDebug("ssn %p: not updating state as packet is before next_seq", ssn);
                } else if (TCP_GET_SEQ(p) != ssn->client.next_seq && TCP_GET_SEQ(p) != ssn->client.next_seq + 1) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 "" " != %" PRIu32 " from stream", ssn, TCP_GET_SEQ(p), ssn->client.next_seq);

                    StreamTcpSetEvent(p, STREAM_LASTACK_ACK_WRONG_SEQ);
                    return -1;
                } else {
                    StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                    SCLogDebug("ssn %p: state changed to TCP_CLOSED", ssn);

                }
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK " "%" PRIu32 "", ssn, ssn->client.next_seq, ssn->server.last_ack);

        }
    } else {
        SCLogDebug("ssn %p: default case", ssn);
    }

    return 0;
}



static int StreamTcpPacketStateTimeWait(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        StreamTcpCloseSsnWithReset(p, ssn);

        if (PKT_IS_TOSERVER(p)) {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->server, StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client, StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);
        } else {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->client, StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server, StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);
        }

    } else if (p->tcph->th_flags & TH_FIN) {
        

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn (%p): SYN pkt on TimeWait", ssn);
        StreamTcpSetEvent(p, STREAM_SHUTDOWN_SYN_RESEND);
        return -1;

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (TCP_GET_SEQ(p) != ssn->client.next_seq && TCP_GET_SEQ(p) != ssn->client.next_seq+1) {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 "" " != %" PRIu32 " from stream", ssn, TCP_GET_SEQ(p), ssn->client.next_seq);

                StreamTcpSetEvent(p, STREAM_TIMEWAIT_ACK_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_TIMEWAIT_INVALID_ACK);
                SCReturnInt(-1);
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                SCLogDebug("ssn %p: state changed to TCP_CLOSED", ssn);

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK " "%" PRIu32 "", ssn, ssn->client.next_seq, ssn->server.last_ack);

        } else {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ " "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            } else if (TCP_GET_SEQ(p) != ssn->server.next_seq && TCP_GET_SEQ(p) != ssn->server.next_seq+1) {
                if (p->payload_len > 0 && TCP_GET_SEQ(p) == ssn->server.last_ack) {
                    SCLogDebug("ssn %p: -> retransmission", ssn);
                    SCReturnInt(0);
                } else {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 "" " != %" PRIu32 " from stream", ssn, TCP_GET_SEQ(p), ssn->server.next_seq);

                    StreamTcpSetEvent(p, STREAM_TIMEWAIT_ACK_WRONG_SEQ);
                    return -1;
                }
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_TIMEWAIT_INVALID_ACK);
                SCReturnInt(-1);
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                SCLogDebug("ssn %p: state changed to TCP_CLOSED", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK " "%" PRIu32 "", ssn, ssn->server.next_seq, ssn->client.last_ack);

        }

    } else {
        SCLogDebug("ssn %p: default case", ssn);
    }

    return 0;
}

static int StreamTcpPacketStateClosed(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        SCLogDebug("RST on closed state");
        return 0;
    }

    TcpStream *stream = NULL, *ostream = NULL;
    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
        ostream = &ssn->server;
    } else {
        stream = &ssn->server;
        ostream = &ssn->client;
    }

    SCLogDebug("stream %s ostream %s", stream->flags & STREAMTCP_STREAM_FLAG_RST_RECV?"true":"false", ostream->flags & STREAMTCP_STREAM_FLAG_RST_RECV ? "true":"false");


    
    if ((stream->flags & STREAMTCP_STREAM_FLAG_RST_RECV) == 0) {
        if (ostream->flags & STREAMTCP_STREAM_FLAG_RST_RECV) {
            if (StreamTcpStateDispatch(tv, p, stt, ssn, &stt->pseudo_queue, ssn->pstate) < 0)
                return -1;
        }
    }
    return 0;
}

static void StreamTcpPacketCheckPostRst(TcpSession *ssn, Packet *p)
{
    if (p->flags & PKT_PSEUDO_STREAM_END) {
        return;
    }
    
    if ((p->tcph->th_flags & (TH_RST)) != 0) {
        return;
    }

    TcpStream *ostream = NULL;
    if (PKT_IS_TOSERVER(p)) {
        ostream = &ssn->server;
    } else {
        ostream = &ssn->client;
    }

    if (ostream->flags & STREAMTCP_STREAM_FLAG_RST_RECV) {
        SCLogDebug("regular packet %"PRIu64" from same sender as " "the previous RST. Looks like it injected!", p->pcap_cnt);
        ostream->flags &= ~STREAMTCP_STREAM_FLAG_RST_RECV;
        ssn->flags &= ~STREAMTCP_FLAG_CLOSED_BY_RST;
        StreamTcpSetEvent(p, STREAM_SUSPECTED_RST_INJECT);
        return;
    }
    return;
}


static int StreamTcpPacketIsKeepAlive(TcpSession *ssn, Packet *p)
{
    TcpStream *stream = NULL, *ostream = NULL;
    uint32_t seq;
    uint32_t ack;

    if (p->flags & PKT_PSEUDO_STREAM_END)
        return 0;

    
    if (p->payload_len > 1)
        return 0;

    if ((p->tcph->th_flags & (TH_SYN|TH_FIN|TH_RST)) != 0) {
        return 0;
    }

    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
        ostream = &ssn->server;
    } else {
        stream = &ssn->server;
        ostream = &ssn->client;
    }

    seq = TCP_GET_SEQ(p);
    ack = TCP_GET_ACK(p);

    if (ack == ostream->last_ack && seq == (stream->next_seq - 1)) {
        SCLogDebug("packet is TCP keep-alive: %"PRIu64, p->pcap_cnt);
        stream->flags |= STREAMTCP_STREAM_FLAG_KEEPALIVE;
        return 1;
    }
    SCLogDebug("seq %u (%u), ack %u (%u)", seq,  (stream->next_seq - 1), ack, ostream->last_ack);
    return 0;
}


static int StreamTcpPacketIsKeepAliveACK(TcpSession *ssn, Packet *p)
{
    TcpStream *stream = NULL, *ostream = NULL;
    uint32_t seq;
    uint32_t ack;
    uint32_t pkt_win;

    if (p->flags & PKT_PSEUDO_STREAM_END)
        return 0;
    
    if (p->payload_len > 0)
        return 0;

    if ((p->tcph->th_flags & (TH_SYN|TH_FIN|TH_RST)) != 0)
        return 0;

    if (TCP_GET_WINDOW(p) == 0)
        return 0;

    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
        ostream = &ssn->server;
    } else {
        stream = &ssn->server;
        ostream = &ssn->client;
    }

    seq = TCP_GET_SEQ(p);
    ack = TCP_GET_ACK(p);

    pkt_win = TCP_GET_WINDOW(p) << ostream->wscale;
    if (pkt_win != ostream->window)
        return 0;

    if ((ostream->flags & STREAMTCP_STREAM_FLAG_KEEPALIVE) && ack == ostream->last_ack && seq == stream->next_seq) {
        SCLogDebug("packet is TCP keep-aliveACK: %"PRIu64, p->pcap_cnt);
        ostream->flags &= ~STREAMTCP_STREAM_FLAG_KEEPALIVE;
        return 1;
    }
    SCLogDebug("seq %u (%u), ack %u (%u) FLAG_KEEPALIVE: %s", seq, stream->next_seq, ack, ostream->last_ack, ostream->flags & STREAMTCP_STREAM_FLAG_KEEPALIVE ? "set" : "not set");
    return 0;
}

static void StreamTcpClearKeepAliveFlag(TcpSession *ssn, Packet *p)
{
    TcpStream *stream = NULL;

    if (p->flags & PKT_PSEUDO_STREAM_END)
        return;

    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
    } else {
        stream = &ssn->server;
    }

    if (stream->flags & STREAMTCP_STREAM_FLAG_KEEPALIVE) {
        stream->flags &= ~STREAMTCP_STREAM_FLAG_KEEPALIVE;
        SCLogDebug("FLAG_KEEPALIVE cleared");
    }
}


static int StreamTcpPacketIsWindowUpdate(TcpSession *ssn, Packet *p)
{
    TcpStream *stream = NULL, *ostream = NULL;
    uint32_t seq;
    uint32_t ack;
    uint32_t pkt_win;

    if (p->flags & PKT_PSEUDO_STREAM_END)
        return 0;

    if (ssn->state < TCP_ESTABLISHED)
        return 0;

    if (p->payload_len > 0)
        return 0;

    if ((p->tcph->th_flags & (TH_SYN|TH_FIN|TH_RST)) != 0)
        return 0;

    if (TCP_GET_WINDOW(p) == 0)
        return 0;

    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
        ostream = &ssn->server;
    } else {
        stream = &ssn->server;
        ostream = &ssn->client;
    }

    seq = TCP_GET_SEQ(p);
    ack = TCP_GET_ACK(p);

    pkt_win = TCP_GET_WINDOW(p) << ostream->wscale;
    if (pkt_win == ostream->window)
        return 0;

    if (ack == ostream->last_ack && seq == stream->next_seq) {
        SCLogDebug("packet is TCP window update: %"PRIu64, p->pcap_cnt);
        return 1;
    }
    SCLogDebug("seq %u (%u), ack %u (%u)", seq, stream->next_seq, ack, ostream->last_ack);
    return 0;
}


static int StreamTcpPacketIsFinShutdownAck(TcpSession *ssn, Packet *p)
{
    TcpStream *stream = NULL, *ostream = NULL;
    uint32_t seq;
    uint32_t ack;

    if (p->flags & PKT_PSEUDO_STREAM_END)
        return 0;
    if (!(ssn->state == TCP_TIME_WAIT || ssn->state == TCP_CLOSE_WAIT || ssn->state == TCP_LAST_ACK))
        return 0;
    if (p->tcph->th_flags != TH_ACK)
        return 0;
    if (p->payload_len != 0)
        return 0;

    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
        ostream = &ssn->server;
    } else {
        stream = &ssn->server;
        ostream = &ssn->client;
    }

    seq = TCP_GET_SEQ(p);
    ack = TCP_GET_ACK(p);

    SCLogDebug("%"PRIu64", seq %u ack %u stream->next_seq %u ostream->next_seq %u", p->pcap_cnt, seq, ack, stream->next_seq, ostream->next_seq);

    if (SEQ_EQ(stream->next_seq + 1, seq) && SEQ_EQ(ack, ostream->next_seq + 1)) {
        return 1;
    }
    return 0;
}


static int StreamTcpPacketIsBadWindowUpdate(TcpSession *ssn, Packet *p)
{
    TcpStream *stream = NULL, *ostream = NULL;
    uint32_t seq;
    uint32_t ack;
    uint32_t pkt_win;

    if (p->flags & PKT_PSEUDO_STREAM_END)
        return 0;

    if (ssn->state < TCP_ESTABLISHED || ssn->state == TCP_CLOSED)
        return 0;

    if ((p->tcph->th_flags & (TH_SYN|TH_FIN|TH_RST)) != 0)
        return 0;

    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
        ostream = &ssn->server;
    } else {
        stream = &ssn->server;
        ostream = &ssn->client;
    }

    seq = TCP_GET_SEQ(p);
    ack = TCP_GET_ACK(p);

    pkt_win = TCP_GET_WINDOW(p) << ostream->wscale;

    if (pkt_win < ostream->window) {
        uint32_t diff = ostream->window - pkt_win;
        if (diff > p->payload_len && SEQ_GT(ack, ostream->next_seq) && SEQ_GT(seq, stream->next_seq))

        {
            SCLogDebug("%"PRIu64", pkt_win %u, stream win %u, diff %u, dsize %u", p->pcap_cnt, pkt_win, ostream->window, diff, p->payload_len);
            SCLogDebug("%"PRIu64", pkt_win %u, stream win %u", p->pcap_cnt, pkt_win, ostream->window);
            SCLogDebug("%"PRIu64", seq %u ack %u ostream->next_seq %u ostream->last_ack %u, ostream->next_win %u, diff %u (%u)", p->pcap_cnt, seq, ack, ostream->next_seq, ostream->last_ack, ostream->next_win, ostream->next_seq - ostream->last_ack, stream->next_seq - stream->last_ack);


            
            uint32_t adiff = ack - ostream->last_ack;
            if (((pkt_win > 1024) && (diff > (adiff + 32))) || ((pkt_win <= 1024) && (diff > adiff)))
            {
                SCLogDebug("pkt ACK %u is %u bytes beyond last_ack %u, shrinks window by %u " "(allowing 32 bytes extra): pkt WIN %u", ack, adiff, ostream->last_ack, diff, pkt_win);
                SCLogDebug("%u - %u = %u (state %u)", diff, adiff, diff - adiff, ssn->state);
                StreamTcpSetEvent(p, STREAM_PKT_BAD_WINDOW_UPDATE);
                return 1;
            }
        }

    }
    SCLogDebug("seq %u (%u), ack %u (%u)", seq, stream->next_seq, ack, ostream->last_ack);
    return 0;
}


static inline int StreamTcpStateDispatch(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq, const uint8_t state)

{
    SCLogDebug("ssn: %p", ssn);
    switch (state) {
        case TCP_SYN_SENT:
            SCLogDebug("packet received on TCP_SYN_SENT state");
            if (StreamTcpPacketStateSynSent(tv, p, stt, ssn, pq)) {
                return -1;
            }
            break;
        case TCP_SYN_RECV:
            SCLogDebug("packet received on TCP_SYN_RECV state");
            if (StreamTcpPacketStateSynRecv(tv, p, stt, ssn, pq)) {
                return -1;
            }
            break;
        case TCP_ESTABLISHED:
            SCLogDebug("packet received on TCP_ESTABLISHED state");
            if (StreamTcpPacketStateEstablished(tv, p, stt, ssn, pq)) {
                return -1;
            }
            break;
        case TCP_FIN_WAIT1:
            SCLogDebug("packet received on TCP_FIN_WAIT1 state");
            if (StreamTcpPacketStateFinWait1(tv, p, stt, ssn, pq)) {
                return -1;
            }
            break;
        case TCP_FIN_WAIT2:
            SCLogDebug("packet received on TCP_FIN_WAIT2 state");
            if (StreamTcpPacketStateFinWait2(tv, p, stt, ssn, pq)) {
                return -1;
            }
            break;
        case TCP_CLOSING:
            SCLogDebug("packet received on TCP_CLOSING state");
            if (StreamTcpPacketStateClosing(tv, p, stt, ssn, pq)) {
                return -1;
            }
            break;
        case TCP_CLOSE_WAIT:
            SCLogDebug("packet received on TCP_CLOSE_WAIT state");
            if (StreamTcpPacketStateCloseWait(tv, p, stt, ssn, pq)) {
                return -1;
            }
            break;
        case TCP_LAST_ACK:
            SCLogDebug("packet received on TCP_LAST_ACK state");
            if (StreamTcpPacketStateLastAck(tv, p, stt, ssn, pq)) {
                return -1;
            }
            break;
        case TCP_TIME_WAIT:
            SCLogDebug("packet received on TCP_TIME_WAIT state");
            if (StreamTcpPacketStateTimeWait(tv, p, stt, ssn, pq)) {
                return -1;
            }
            break;
        case TCP_CLOSED:
            
            SCLogDebug("packet received on closed state");

            if (StreamTcpPacketStateClosed(tv, p, stt, ssn, pq)) {
                return -1;
            }

            break;
        default:
            SCLogDebug("packet received on default state");
            break;
    }
    return 0;
}

static inline void HandleThreadId(ThreadVars *tv, Packet *p, StreamTcpThread *stt)
{
    const int idx = (!(PKT_IS_TOSERVER(p)));

    
    if (unlikely(p->flow->thread_id[idx] == 0)) {
        p->flow->thread_id[idx] = (FlowThreadId)tv->id;
    } else if (unlikely((FlowThreadId)tv->id != p->flow->thread_id[idx])) {
        SCLogDebug("wrong thread: flow has %u, we are %d", p->flow->thread_id[idx], tv->id);
        if (p->pkt_src == PKT_SRC_WIRE) {
            StatsIncr(tv, stt->counter_tcp_wrong_thread);
            if ((p->flow->flags & FLOW_WRONG_THREAD) == 0) {
                p->flow->flags |= FLOW_WRONG_THREAD;
                StreamTcpSetEvent(p, STREAM_WRONG_THREAD);
            }
        }
    }
}


int StreamTcpPacket (ThreadVars *tv, Packet *p, StreamTcpThread *stt, PacketQueueNoLock *pq)
{
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(p->flow);

    SCLogDebug("p->pcap_cnt %"PRIu64, p->pcap_cnt);

    HandleThreadId(tv, p, stt);

    TcpSession *ssn = (TcpSession *)p->flow->protoctx;

    
    if (ssn != NULL) {
        ssn->tcp_packet_flags |= p->tcph->th_flags;
        if (PKT_IS_TOSERVER(p))
            ssn->client.tcp_flags |= p->tcph->th_flags;
        else if (PKT_IS_TOCLIENT(p))
            ssn->server.tcp_flags |= p->tcph->th_flags;

        
        if (ssn->flags & STREAMTCP_FLAG_ASYNC && ssn->client.tcp_flags != 0 && ssn->server.tcp_flags != 0)

        {
            SCLogDebug("ssn %p: removing ASYNC flag as we have packets on both sides", ssn);
            ssn->flags &= ~STREAMTCP_FLAG_ASYNC;
        }
    }

    
    if ((p->tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
        StatsIncr(tv, stt->counter_tcp_synack);
    } else if (p->tcph->th_flags & (TH_SYN)) {
        StatsIncr(tv, stt->counter_tcp_syn);
    }
    if (p->tcph->th_flags & (TH_RST)) {
        StatsIncr(tv, stt->counter_tcp_rst);
    }

    
    if (!(p->tcph->th_flags & TH_ACK) && TCP_GET_ACK(p) != 0) {
        StreamTcpSetEvent(p, STREAM_PKT_BROKEN_ACK);
    }

    
    if (StreamTcpCheckFlowDrops(p) == 1) {
        SCLogDebug("This flow/stream triggered a drop rule");
        FlowSetNoPacketInspectionFlag(p->flow);
        DecodeSetNoPacketInspectionFlag(p);
        StreamTcpDisableAppLayer(p->flow);
        PACKET_DROP(p);
        
        StreamTcpSessionPktFree(p);
        SCReturnInt(0);
    }

    if (ssn == NULL || ssn->state == TCP_NONE) {
        if (StreamTcpPacketStateNone(tv, p, stt, ssn, &stt->pseudo_queue) == -1) {
            goto error;
        }

        if (ssn != NULL)
            SCLogDebug("ssn->alproto %"PRIu16"", p->flow->alproto);
    } else {
        
        if (p->flags & PKT_PSEUDO_STREAM_END) {
            if (PKT_IS_TOCLIENT(p)) {
                ssn->client.last_ack = TCP_GET_ACK(p);
                StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);
            } else {
                ssn->server.last_ack = TCP_GET_ACK(p);
                StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);
            }
            
            goto skip;
        }

        if (p->flow->flags & FLOW_WRONG_THREAD) {
            
            p->flags |= PKT_STREAM_NO_EVENTS;
        }

        if (StreamTcpPacketIsKeepAlive(ssn, p) == 1) {
            goto skip;
        }
        if (StreamTcpPacketIsKeepAliveACK(ssn, p) == 1) {
            StreamTcpClearKeepAliveFlag(ssn, p);
            goto skip;
        }
        StreamTcpClearKeepAliveFlag(ssn, p);

        
        if (StreamTcpPacketIsFinShutdownAck(ssn, p) == 0) {
            if (StreamTcpPacketIsWindowUpdate(ssn, p) == 0) {
                if (StreamTcpPacketIsBadWindowUpdate(ssn,p))
                    goto skip;
                if (StreamTcpPacketIsOutdatedAck(ssn, p))
                    goto skip;
            }
        }

        
        if (StreamTcpStateDispatch(tv, p, stt, ssn, &stt->pseudo_queue, ssn->state) < 0)
            goto error;

    skip:
        StreamTcpPacketCheckPostRst(ssn, p);

        if (ssn->state >= TCP_ESTABLISHED) {
            p->flags |= PKT_STREAM_EST;
        }
    }

    
    if (ssn != NULL) {
        while (stt->pseudo_queue.len > 0) {
            SCLogDebug("processing pseudo packet / stream end");
            Packet *np = PacketDequeueNoLock(&stt->pseudo_queue);
            if (np != NULL) {
                
                if (PKT_IS_TOSERVER(np)) {
                    SCLogDebug("pseudo packet is to server");
                    StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, np, NULL);
                } else {
                    SCLogDebug("pseudo packet is to client");
                    StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, np, NULL);
                }

                
                PacketEnqueueNoLock(pq, np);
            }
            SCLogDebug("processing pseudo packet / stream end done");
        }

        
        if (p->flags & PKT_STREAM_MODIFIED) {
            ReCalculateChecksum(p);
        }
        

        
        if ((ssn->client.flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) || (ssn->server.flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED))
        {
            
            if (StreamTcpBypassEnabled()) {
                PacketBypassCallback(p);
            }
        }

        if ((ssn->client.flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) || (ssn->server.flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED))
        {
            p->flags |= PKT_STREAM_NOPCAPLOG;
        }

        
        if ((PKT_IS_TOSERVER(p) && (ssn->client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) || (PKT_IS_TOCLIENT(p) && (ssn->server.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)))
        {
            p->flags |= PKT_STREAM_NOPCAPLOG;
        }

        if (ssn->flags & STREAMTCP_FLAG_BYPASS) {
            
            if (StreamTcpBypassEnabled()) {
                PacketBypassCallback(p);
            }

        
        } else if (g_detect_disabled && (ssn->client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) && (ssn->server.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) && StreamTcpBypassEnabled())


        {
            SCLogDebug("bypass as stream is dead and we have no rules");
            PacketBypassCallback(p);
        }
    }

    SCReturnInt(0);

error:
    
    while (stt->pseudo_queue.len > 0) {
        Packet *np = PacketDequeueNoLock(&stt->pseudo_queue);
        if (np != NULL) {
            PacketEnqueueNoLock(pq, np);
        }
    }

    
    if (p->flags & PKT_STREAM_MODIFIED) {
        ReCalculateChecksum(p);
    }

    if (StreamTcpInlineDropInvalid()) {
        
        DecodeSetNoPayloadInspectionFlag(p);
        PACKET_DROP(p);
    }
    SCReturnInt(-1);
}


static inline int StreamTcpValidateChecksum(Packet *p)
{
    int ret = 1;

    if (p->flags & PKT_IGNORE_CHECKSUM)
        return ret;

    if (p->level4_comp_csum == -1) {
        if (PKT_IS_IPV4(p)) {
            p->level4_comp_csum = TCPChecksum(p->ip4h->s_ip_addrs, (uint16_t *)p->tcph, (p->payload_len + TCP_GET_HLEN(p)), p->tcph->th_sum);



        } else if (PKT_IS_IPV6(p)) {
            p->level4_comp_csum = TCPV6Checksum(p->ip6h->s_ip6_addrs, (uint16_t *)p->tcph, (p->payload_len + TCP_GET_HLEN(p)), p->tcph->th_sum);



        }
    }

    if (p->level4_comp_csum != 0) {
        ret = 0;
        if (p->livedev) {
            (void) SC_ATOMIC_ADD(p->livedev->invalid_checksums, 1);
        } else if (p->pcap_cnt) {
            PcapIncreaseInvalidChecksum();
        }
    }

    return ret;
}


static int TcpSessionPacketIsStreamStarter(const Packet *p)
{
    if (p->tcph->th_flags == TH_SYN) {
        SCLogDebug("packet %"PRIu64" is a stream starter: %02x", p->pcap_cnt, p->tcph->th_flags);
        return 1;
    }

    if (stream_config.midstream || stream_config.async_oneside == TRUE) {
        if (p->tcph->th_flags == (TH_SYN|TH_ACK)) {
            SCLogDebug("packet %"PRIu64" is a midstream stream starter: %02x", p->pcap_cnt, p->tcph->th_flags);
            return 1;
        }
    }
    return 0;
}


static int TcpSessionReuseDoneEnoughSyn(const Packet *p, const Flow *f, const TcpSession *ssn)
{
    if (FlowGetPacketDirection(f, p) == TOSERVER) {
        if (ssn == NULL) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p null. No reuse.", p->pcap_cnt, ssn);
            return 0;
        }
        if (SEQ_EQ(ssn->client.isn, TCP_GET_SEQ(p))) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p. Packet SEQ == Stream ISN. Retransmission. Don't reuse.", p->pcap_cnt, ssn);
            return 0;
        }
        if (ssn->state >= TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state >= TCP_LAST_ACK (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state == TCP_NONE) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state == TCP_NONE (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state < TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state < TCP_LAST_ACK (%u). Don't reuse.", p->pcap_cnt, ssn, ssn->state);
            return 0;
        }

    } else {
        if (ssn == NULL) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p null. Reuse.", p->pcap_cnt, ssn);
            return 1;
        }
        if (ssn->state >= TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state >= TCP_LAST_ACK (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state == TCP_NONE) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state == TCP_NONE (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state < TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state < TCP_LAST_ACK (%u). Don't reuse.", p->pcap_cnt, ssn, ssn->state);
            return 0;
        }
    }

    SCLogDebug("default: how did we get here?");
    return 0;
}


static int TcpSessionReuseDoneEnoughSynAck(const Packet *p, const Flow *f, const TcpSession *ssn)
{
    if (FlowGetPacketDirection(f, p) == TOCLIENT) {
        if (ssn == NULL) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p null. No reuse.", p->pcap_cnt, ssn);
            return 0;
        }
        if (SEQ_EQ(ssn->server.isn, TCP_GET_SEQ(p))) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p. Packet SEQ == Stream ISN. Retransmission. Don't reuse.", p->pcap_cnt, ssn);
            return 0;
        }
        if (ssn->state >= TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state >= TCP_LAST_ACK (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state == TCP_NONE) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state == TCP_NONE (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state < TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state < TCP_LAST_ACK (%u). Don't reuse.", p->pcap_cnt, ssn, ssn->state);
            return 0;
        }

    } else {
        if (ssn == NULL) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p null. Reuse.", p->pcap_cnt, ssn);
            return 1;
        }
        if (ssn->state >= TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state >= TCP_LAST_ACK (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state == TCP_NONE) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state == TCP_NONE (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state < TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state < TCP_LAST_ACK (%u). Don't reuse.", p->pcap_cnt, ssn, ssn->state);
            return 0;
        }
    }

    SCLogDebug("default: how did we get here?");
    return 0;
}


static int TcpSessionReuseDoneEnough(const Packet *p, const Flow *f, const TcpSession *ssn)
{
    if (p->tcph->th_flags == TH_SYN) {
        return TcpSessionReuseDoneEnoughSyn(p, f, ssn);
    }

    if (stream_config.midstream || stream_config.async_oneside == TRUE) {
        if (p->tcph->th_flags == (TH_SYN|TH_ACK)) {
            return TcpSessionReuseDoneEnoughSynAck(p, f, ssn);
        }
    }

    return 0;
}

int TcpSessionPacketSsnReuse(const Packet *p, const Flow *f, const void *tcp_ssn)
{
    if (p->proto == IPPROTO_TCP && p->tcph != NULL) {
        if (TcpSessionPacketIsStreamStarter(p) == 1) {
            if (TcpSessionReuseDoneEnough(p, f, tcp_ssn) == 1) {
                return 1;
            }
        }
    }
    return 0;
}

TmEcode StreamTcp (ThreadVars *tv, Packet *p, void *data, PacketQueueNoLock *pq)
{
    StreamTcpThread *stt = (StreamTcpThread *)data;

    SCLogDebug("p->pcap_cnt %" PRIu64 " direction %s", p->pcap_cnt, p->flow ? (FlowGetPacketDirection(p->flow, p) == TOSERVER ? "toserver" : "toclient")
                    : "noflow");

    if (!(PKT_IS_TCP(p))) {
        return TM_ECODE_OK;
    }

    if (p->flow == NULL) {
        StatsIncr(tv, stt->counter_tcp_no_flow);
        return TM_ECODE_OK;
    }

    

    if (!(p->flags & PKT_PSEUDO_STREAM_END)) {
        if (stream_config.flags & STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION) {
            if (StreamTcpValidateChecksum(p) == 0) {
                StatsIncr(tv, stt->counter_tcp_invalid_checksum);
                return TM_ECODE_OK;
            }
        } else {
            p->flags |= PKT_IGNORE_CHECKSUM;
        }
    } else {
        p->flags |= PKT_IGNORE_CHECKSUM; 
    }
    AppLayerProfilingReset(stt->ra_ctx->app_tctx);

    (void)StreamTcpPacket(tv, p, stt, pq);

    return TM_ECODE_OK;
}

TmEcode StreamTcpThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    StreamTcpThread *stt = SCMalloc(sizeof(StreamTcpThread));
    if (unlikely(stt == NULL))
        SCReturnInt(TM_ECODE_FAILED);
    memset(stt, 0, sizeof(StreamTcpThread));
    stt->ssn_pool_id = -1;

    *data = (void *)stt;

    stt->counter_tcp_sessions = StatsRegisterCounter("tcp.sessions", tv);
    stt->counter_tcp_ssn_memcap = StatsRegisterCounter("tcp.ssn_memcap_drop", tv);
    stt->counter_tcp_pseudo = StatsRegisterCounter("tcp.pseudo", tv);
    stt->counter_tcp_pseudo_failed = StatsRegisterCounter("tcp.pseudo_failed", tv);
    stt->counter_tcp_invalid_checksum = StatsRegisterCounter("tcp.invalid_checksum", tv);
    stt->counter_tcp_no_flow = StatsRegisterCounter("tcp.no_flow", tv);
    stt->counter_tcp_syn = StatsRegisterCounter("tcp.syn", tv);
    stt->counter_tcp_synack = StatsRegisterCounter("tcp.synack", tv);
    stt->counter_tcp_rst = StatsRegisterCounter("tcp.rst", tv);
    stt->counter_tcp_midstream_pickups = StatsRegisterCounter("tcp.midstream_pickups", tv);
    stt->counter_tcp_wrong_thread = StatsRegisterCounter("tcp.pkt_on_wrong_thread", tv);

    
    stt->ra_ctx = StreamTcpReassembleInitThreadCtx(tv);
    if (stt->ra_ctx == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    stt->ra_ctx->counter_tcp_segment_memcap = StatsRegisterCounter("tcp.segment_memcap_drop", tv);
    stt->ra_ctx->counter_tcp_stream_depth = StatsRegisterCounter("tcp.stream_depth_reached", tv);
    stt->ra_ctx->counter_tcp_reass_gap = StatsRegisterCounter("tcp.reassembly_gap", tv);
    stt->ra_ctx->counter_tcp_reass_overlap = StatsRegisterCounter("tcp.overlap", tv);
    stt->ra_ctx->counter_tcp_reass_overlap_diff_data = StatsRegisterCounter("tcp.overlap_diff_data", tv);

    stt->ra_ctx->counter_tcp_reass_data_normal_fail = StatsRegisterCounter("tcp.insert_data_normal_fail", tv);
    stt->ra_ctx->counter_tcp_reass_data_overlap_fail = StatsRegisterCounter("tcp.insert_data_overlap_fail", tv);
    stt->ra_ctx->counter_tcp_reass_list_fail = StatsRegisterCounter("tcp.insert_list_fail", tv);


    SCLogDebug("StreamTcp thread specific ctx online at %p, reassembly ctx %p", stt, stt->ra_ctx);

    SCMutexLock(&ssn_pool_mutex);
    if (ssn_pool == NULL) {
        ssn_pool = PoolThreadInit(1,  0, stream_config.prealloc_sessions, sizeof(TcpSession), StreamTcpSessionPoolAlloc, StreamTcpSessionPoolInit, NULL, StreamTcpSessionPoolCleanup, NULL);





        stt->ssn_pool_id = 0;
        SCLogDebug("pool size %d, thread ssn_pool_id %d", PoolThreadSize(ssn_pool), stt->ssn_pool_id);
    } else {
        
        stt->ssn_pool_id = PoolThreadExpand(ssn_pool);
        SCLogDebug("pool size %d, thread ssn_pool_id %d", PoolThreadSize(ssn_pool), stt->ssn_pool_id);
    }
    SCMutexUnlock(&ssn_pool_mutex);
    if (stt->ssn_pool_id < 0 || ssn_pool == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "failed to setup/expand stream session pool. Expand stream.memcap?");
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode StreamTcpThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();
    StreamTcpThread *stt = (StreamTcpThread *)data;
    if (stt == NULL) {
        return TM_ECODE_OK;
    }

    

    
    StreamTcpReassembleFreeThreadCtx(stt->ra_ctx);

    
    memset(stt, 0, sizeof(StreamTcpThread));

    SCFree(stt);
    SCReturnInt(TM_ECODE_OK);
}



static int StreamTcpValidateRst(TcpSession *ssn, Packet *p)
{

    uint8_t os_policy;

    if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
        if (!StreamTcpValidateTimestamp(ssn, p)) {
            SCReturnInt(0);
        }
    }

    
    if (PKT_IS_TOSERVER(p)) {
        if (ssn->server.os_policy == 0)
            StreamTcpSetOSPolicy(&ssn->server, p);

        os_policy = ssn->server.os_policy;

        if (p->tcph->th_flags & TH_ACK && TCP_GET_ACK(p) && StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
            SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
            StreamTcpSetEvent(p, STREAM_RST_INVALID_ACK);
            SCReturnInt(0);
        }

    } else {
        if (ssn->client.os_policy == 0)
            StreamTcpSetOSPolicy(&ssn->client, p);

        os_policy = ssn->client.os_policy;

        if (p->tcph->th_flags & TH_ACK && TCP_GET_ACK(p) && StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
            SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
            StreamTcpSetEvent(p, STREAM_RST_INVALID_ACK);
            SCReturnInt(0);
        }
    }

    if (ssn->flags & STREAMTCP_FLAG_ASYNC) {
        if (PKT_IS_TOSERVER(p)) {
            if (SEQ_GEQ(TCP_GET_SEQ(p), ssn->client.next_seq)) {
                SCLogDebug("ssn %p: ASYNC accept RST", ssn);
                return 1;
            }
        } else {
            if (SEQ_GEQ(TCP_GET_SEQ(p), ssn->server.next_seq)) {
                SCLogDebug("ssn %p: ASYNC accept RST", ssn);
                return 1;
            }
        }
        SCLogDebug("ssn %p: ASYNC reject RST", ssn);
        return 0;
    }

    switch (os_policy) {
        case OS_POLICY_HPUX11:
            if(PKT_IS_TOSERVER(p)){
                if(SEQ_GEQ(TCP_GET_SEQ(p), ssn->client.next_seq)) {
                    SCLogDebug("reset is Valid! Packet SEQ: %" PRIu32 "", TCP_GET_SEQ(p));
                    return 1;
                } else {
                    SCLogDebug("reset is not Valid! Packet SEQ: %" PRIu32 " " "and server SEQ: %" PRIu32 "", TCP_GET_SEQ(p), ssn->client.next_seq);

                    return 0;
                }
            } else { 
                if(SEQ_GEQ(TCP_GET_SEQ(p), ssn->server.next_seq)) {
                    SCLogDebug("reset is valid! Packet SEQ: %" PRIu32 "", TCP_GET_SEQ(p));
                    return 1;
                } else {
                    SCLogDebug("reset is not valid! Packet SEQ: %" PRIu32 " " "and client SEQ: %" PRIu32 "", TCP_GET_SEQ(p), ssn->server.next_seq);

                    return 0;
                }
            }
            break;
        case OS_POLICY_OLD_LINUX:
        case OS_POLICY_LINUX:
        case OS_POLICY_SOLARIS:
            if(PKT_IS_TOSERVER(p)){
                if(SEQ_GEQ((TCP_GET_SEQ(p)+p->payload_len), ssn->client.last_ack))
                { 
                    if(SEQ_LT(TCP_GET_SEQ(p), (ssn->client.next_seq + ssn->client.window)))
                    {
                        SCLogDebug("reset is Valid! Packet SEQ: %" PRIu32 "", TCP_GET_SEQ(p));
                        return 1;
                    }
                } else {
                    SCLogDebug("reset is not valid! Packet SEQ: %" PRIu32 " and" " server SEQ: %" PRIu32 "", TCP_GET_SEQ(p), ssn->client.next_seq);

                    return 0;
                }
            } else { 
                if(SEQ_GEQ((TCP_GET_SEQ(p) + p->payload_len), ssn->server.last_ack))
                { 
                    if(SEQ_LT(TCP_GET_SEQ(p), (ssn->server.next_seq + ssn->server.window)))
                    {
                        SCLogDebug("reset is Valid! Packet SEQ: %" PRIu32 "", TCP_GET_SEQ(p));
                        return 1;
                    }
                } else {
                    SCLogDebug("reset is not valid! Packet SEQ: %" PRIu32 " and" " client SEQ: %" PRIu32 "", TCP_GET_SEQ(p), ssn->server.next_seq);

                    return 0;
                }
            }
            break;
        default:
        case OS_POLICY_BSD:
        case OS_POLICY_FIRST:
        case OS_POLICY_HPUX10:
        case OS_POLICY_IRIX:
        case OS_POLICY_MACOS:
        case OS_POLICY_LAST:
        case OS_POLICY_WINDOWS:
        case OS_POLICY_WINDOWS2K3:
        case OS_POLICY_VISTA:
            if(PKT_IS_TOSERVER(p)) {
                if(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq)) {
                    SCLogDebug("reset is valid! Packet SEQ: %" PRIu32 "", TCP_GET_SEQ(p));
                    return 1;
                } else {
                    SCLogDebug("reset is not valid! Packet SEQ: %" PRIu32 " " "and server SEQ: %" PRIu32 "", TCP_GET_SEQ(p), ssn->client.next_seq);

                    return 0;
                }
            } else { 
                if (SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq)) {
                    SCLogDebug("reset is valid! Packet SEQ: %" PRIu32 " Stream %u", TCP_GET_SEQ(p), ssn->server.next_seq);
                    return 1;
                } else {
                    SCLogDebug("reset is not valid! Packet SEQ: %" PRIu32 " and" " client SEQ: %" PRIu32 "", TCP_GET_SEQ(p), ssn->server.next_seq);

                    return 0;
                }
            }
            break;
    }
    return 0;
}


static int StreamTcpValidateTimestamp (TcpSession *ssn, Packet *p)
{
    SCEnter();

    TcpStream *sender_stream;
    TcpStream *receiver_stream;
    uint8_t ret = 1;
    uint8_t check_ts = 1;

    if (PKT_IS_TOSERVER(p)) {
        sender_stream = &ssn->client;
        receiver_stream = &ssn->server;
    } else {
        sender_stream = &ssn->server;
        receiver_stream = &ssn->client;
    }

    
    if (receiver_stream->os_policy == 0) {
        StreamTcpSetOSPolicy(receiver_stream, p);
    }

    if (TCP_HAS_TS(p)) {
        uint32_t ts = TCP_GET_TSVAL(p);
        uint32_t last_pkt_ts = sender_stream->last_pkt_ts;
        uint32_t last_ts = sender_stream->last_ts;

        if (sender_stream->flags & STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP) {
            
            switch (receiver_stream->os_policy) {
                case OS_POLICY_LINUX:
                case OS_POLICY_WINDOWS2K3:
                    
                    check_ts = 0;
                    break;

                case OS_POLICY_OLD_LINUX:
                case OS_POLICY_WINDOWS:
                case OS_POLICY_VISTA:
                    if (SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p))) {
                        last_ts = ts;
                        check_ts = 0; 
                    }
                    break;
            }
        }

        if (receiver_stream->os_policy == OS_POLICY_HPUX11) {
            
            if (!SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p)))
                check_ts = 0;
        }

        if (ts == 0) {
            switch (receiver_stream->os_policy) {
                case OS_POLICY_OLD_LINUX:
                case OS_POLICY_WINDOWS:
                case OS_POLICY_WINDOWS2K3:
                case OS_POLICY_VISTA:
                case OS_POLICY_SOLARIS:
                    
                    break;
                default:
                    
                    goto invalid;
            }
        }

        if (check_ts) {
            int32_t result = 0;

            SCLogDebug("ts %"PRIu32", last_ts %"PRIu32"", ts, last_ts);

            if (receiver_stream->os_policy == OS_POLICY_LINUX) {
                
                result = (int32_t) ((ts - last_ts) + 1);
            } else {
                result = (int32_t) (ts - last_ts);
            }

            SCLogDebug("result %"PRIi32", p->ts.tv_sec %"PRIuMAX"", result, (uintmax_t)p->ts.tv_sec);

            if (last_pkt_ts == 0 && (ssn->flags & STREAMTCP_FLAG_MIDSTREAM))
            {
                last_pkt_ts = p->ts.tv_sec;
            }

            if (result < 0) {
                SCLogDebug("timestamp is not valid last_ts " "%" PRIu32 " p->tcpvars->ts %" PRIu32 " result " "%" PRId32 "", last_ts, ts, result);

                
                ret = 0;
            } else if ((sender_stream->last_ts != 0) && (((uint32_t) p->ts.tv_sec) > last_pkt_ts + PAWS_24DAYS))

            {
                SCLogDebug("packet is not valid last_pkt_ts " "%" PRIu32 " p->ts.tv_sec %" PRIu32 "", last_pkt_ts, (uint32_t) p->ts.tv_sec);

                
                ret = 0;
            }

            if (ret == 0) {
                
                if ((SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p))) && (((uint32_t) p->ts.tv_sec > (last_pkt_ts + PAWS_24DAYS))))
                {
                    SCLogDebug("timestamp considered valid anyway");
                } else {
                    goto invalid;
                }
            }
        }
    }

    SCReturnInt(1);

invalid:
    StreamTcpSetEvent(p, STREAM_PKT_INVALID_TIMESTAMP);
    SCReturnInt(0);
}


static int StreamTcpHandleTimestamp (TcpSession *ssn, Packet *p)
{
    SCEnter();

    TcpStream *sender_stream;
    TcpStream *receiver_stream;
    uint8_t ret = 1;
    uint8_t check_ts = 1;

    if (PKT_IS_TOSERVER(p)) {
        sender_stream = &ssn->client;
        receiver_stream = &ssn->server;
    } else {
        sender_stream = &ssn->server;
        receiver_stream = &ssn->client;
    }

    
    if (receiver_stream->os_policy == 0) {
        StreamTcpSetOSPolicy(receiver_stream, p);
    }

    if (TCP_HAS_TS(p)) {
        uint32_t ts = TCP_GET_TSVAL(p);

        if (sender_stream->flags & STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP) {
            
            switch (receiver_stream->os_policy) {
                case OS_POLICY_LINUX:
                case OS_POLICY_WINDOWS2K3:
                    
                    ssn->flags &= ~STREAMTCP_FLAG_TIMESTAMP;
                    check_ts = 0;
                    break;

                case OS_POLICY_OLD_LINUX:
                case OS_POLICY_WINDOWS:
                case OS_POLICY_VISTA:
                    sender_stream->flags &= ~STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
                    if (SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p))) {
                        sender_stream->last_ts = ts;
                        check_ts = 0; 
                    }
                    break;
                default:
                    break;
            }
        }

        if (receiver_stream->os_policy == OS_POLICY_HPUX11) {
            
            if (!SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p)))
                check_ts = 0;
        }

        if (ts == 0) {
            switch (receiver_stream->os_policy) {
                case OS_POLICY_OLD_LINUX:
                case OS_POLICY_WINDOWS:
                case OS_POLICY_WINDOWS2K3:
                case OS_POLICY_VISTA:
                case OS_POLICY_SOLARIS:
                    
                    break;
                default:
                    
                    goto invalid;
            }
        }

        if (check_ts) {
            int32_t result = 0;

            SCLogDebug("ts %"PRIu32", last_ts %"PRIu32"", ts, sender_stream->last_ts);

            if (receiver_stream->os_policy == OS_POLICY_LINUX) {
                
                result = (int32_t) ((ts - sender_stream->last_ts) + 1);
            } else {
                result = (int32_t) (ts - sender_stream->last_ts);
            }

            SCLogDebug("result %"PRIi32", p->ts.tv_sec %"PRIuMAX"", result, (uintmax_t)p->ts.tv_sec);

            if (sender_stream->last_pkt_ts == 0 && (ssn->flags & STREAMTCP_FLAG_MIDSTREAM))
            {
                sender_stream->last_pkt_ts = p->ts.tv_sec;
            }

            if (result < 0) {
                SCLogDebug("timestamp is not valid sender_stream->last_ts " "%" PRIu32 " p->tcpvars->ts %" PRIu32 " result " "%" PRId32 "", sender_stream->last_ts, ts, result);

                
                ret = 0;
            } else if ((sender_stream->last_ts != 0) && (((uint32_t) p->ts.tv_sec) > sender_stream->last_pkt_ts + PAWS_24DAYS))

            {
                SCLogDebug("packet is not valid sender_stream->last_pkt_ts " "%" PRIu32 " p->ts.tv_sec %" PRIu32 "", sender_stream->last_pkt_ts, (uint32_t) p->ts.tv_sec);

                
                ret = 0;
            }

            if (ret == 1) {
                
                if (SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p)))
                    sender_stream->last_ts = ts;

                sender_stream->last_pkt_ts = p->ts.tv_sec;

            } else if (ret == 0) {
                
                if ((SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p))) && (((uint32_t) p->ts.tv_sec > (sender_stream->last_pkt_ts + PAWS_24DAYS))))
                {
                    sender_stream->last_ts = ts;
                    sender_stream->last_pkt_ts = p->ts.tv_sec;

                    SCLogDebug("timestamp considered valid anyway");
                } else {
                    goto invalid;
                }
            }
        }
    } else {
        
        if (receiver_stream->os_policy == OS_POLICY_SOLARIS)
            ssn->flags &= ~STREAMTCP_FLAG_TIMESTAMP;
    }

    SCReturnInt(1);

invalid:
    StreamTcpSetEvent(p, STREAM_PKT_INVALID_TIMESTAMP);
    SCReturnInt(0);
}


static inline int StreamTcpValidateAck(TcpSession *ssn, TcpStream *stream, Packet *p)
{
    SCEnter();

    if (!(p->tcph->th_flags & TH_ACK))
        SCReturnInt(0);

    uint32_t ack = TCP_GET_ACK(p);

    
    if (SEQ_GT(ack, stream->last_ack) && SEQ_LEQ(ack, stream->next_win))
    {
        SCLogDebug("ACK in bounds");
        SCReturnInt(0);
    }
    
    else if (SEQ_EQ(ack, stream->last_ack)) {
        SCLogDebug("pkt ACK %"PRIu32" == stream last ACK %"PRIu32, TCP_GET_ACK(p), stream->last_ack);
        SCReturnInt(0);
    }

    
    if (SEQ_LT(ack, stream->last_ack)) {
        SCLogDebug("pkt ACK %"PRIu32" < stream last ACK %"PRIu32, TCP_GET_ACK(p), stream->last_ack);

        

        if (stream->window != 0 && SEQ_LT(ack, (stream->last_ack - stream->window))) {
            SCLogDebug("ACK %"PRIu32" is before last_ack %"PRIu32" - window " "%"PRIu32" = %"PRIu32, ack, stream->last_ack, stream->window, stream->last_ack - stream->window);

            goto invalid;
        }

        SCReturnInt(0);
    }

    
    if ((ssn->flags & STREAMTCP_FLAG_ASYNC) != 0) {
        SCReturnInt(0);
    }

    if (ssn->state > TCP_SYN_SENT && SEQ_GT(ack, stream->next_win)) {
        SCLogDebug("ACK %"PRIu32" is after next_win %"PRIu32, ack, stream->next_win);
        goto invalid;
    
    } else if (ssn->state == TCP_SYN_SENT && PKT_IS_TOCLIENT(p) && p->tcph->th_flags & TH_RST && SEQ_EQ(ack, stream->isn + 1)) {

        SCReturnInt(0);
    }

    SCLogDebug("default path leading to invalid: ACK %"PRIu32", last_ack %"PRIu32 " next_win %"PRIu32, ack, stream->last_ack, stream->next_win);
invalid:
    StreamTcpSetEvent(p, STREAM_PKT_INVALID_ACK);
    SCReturnInt(-1);
}


void StreamTcpUpdateAppLayerProgress(TcpSession *ssn, char direction, const uint32_t progress)
{
    if (direction) {
        ssn->server.app_progress_rel += progress;
    } else {
        ssn->client.app_progress_rel += progress;
    }
}


void StreamTcpSetSessionNoReassemblyFlag(TcpSession *ssn, char direction)
{
    ssn->flags |= STREAMTCP_FLAG_APP_LAYER_DISABLED;
    if (direction) {
        ssn->server.flags |= STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED;
    } else {
        ssn->client.flags |= STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED;
    }
}


void StreamTcpSetDisableRawReassemblyFlag(TcpSession *ssn, char direction)
{
    direction ? (ssn->server.flags |= STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED) :
                (ssn->client.flags |= STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED);
}


void StreamTcpSetSessionBypassFlag(TcpSession *ssn)
{
    ssn->flags |= STREAMTCP_FLAG_BYPASS;
}




























Packet *StreamTcpPseudoSetup(Packet *parent, uint8_t *pkt, uint32_t len)
{
    SCEnter();

    if (len == 0) {
        SCReturnPtr(NULL, "Packet");
    }

    Packet *p = PacketGetFromQueueOrAlloc();
    if (p == NULL) {
        SCReturnPtr(NULL, "Packet");
    }

    
    if (parent->root != NULL)
        p->root = parent->root;
    else p->root = parent;

    
    p->proto = parent->proto;
    p->datalink = parent->datalink;

    PacketCopyData(p, pkt, len);
    p->recursion_level = parent->recursion_level + 1;
    p->ts.tv_sec = parent->ts.tv_sec;
    p->ts.tv_usec = parent->ts.tv_usec;

    FlowReference(&p->flow, parent->flow);
    

    
    SET_TUNNEL_PKT(p);
    
    SET_TUNNEL_PKT(parent);

    
    TUNNEL_INCR_PKT_TPR(p);

    return p;
}


static void StreamTcpPseudoPacketCreateDetectLogFlush(ThreadVars *tv, StreamTcpThread *stt, Packet *parent, TcpSession *ssn, PacketQueueNoLock *pq, int dir)

{
    SCEnter();
    Flow *f = parent->flow;

    if (parent->flags & PKT_PSEUDO_DETECTLOG_FLUSH) {
        SCReturn;
    }

    Packet *np = PacketPoolGetPacket();
    if (np == NULL) {
        SCReturn;
    }
    PKT_SET_SRC(np, PKT_SRC_STREAM_TCP_DETECTLOG_FLUSH);

    np->tenant_id = f->tenant_id;
    np->datalink = DLT_RAW;
    np->proto = IPPROTO_TCP;
    FlowReference(&np->flow, f);
    np->flags |= PKT_STREAM_EST;
    np->flags |= PKT_HAS_FLOW;
    np->flags |= PKT_IGNORE_CHECKSUM;
    np->flags |= PKT_PSEUDO_DETECTLOG_FLUSH;
    np->vlan_id[0] = f->vlan_id[0];
    np->vlan_id[1] = f->vlan_id[1];
    np->vlan_idx = f->vlan_idx;
    np->livedev = (struct LiveDevice_ *)f->livedev;

    if (f->flags & FLOW_NOPACKET_INSPECTION) {
        DecodeSetNoPacketInspectionFlag(np);
    }
    if (f->flags & FLOW_NOPAYLOAD_INSPECTION) {
        DecodeSetNoPayloadInspectionFlag(np);
    }

    if (dir == 0) {
        SCLogDebug("pseudo is to_server");
        np->flowflags |= FLOW_PKT_TOSERVER;
    } else {
        SCLogDebug("pseudo is to_client");
        np->flowflags |= FLOW_PKT_TOCLIENT;
    }
    np->flowflags |= FLOW_PKT_ESTABLISHED;
    np->payload = NULL;
    np->payload_len = 0;

    if (FLOW_IS_IPV4(f)) {
        if (dir == 0) {
            FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->src, &np->src);
            FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->dst, &np->dst);
            np->sp = f->sp;
            np->dp = f->dp;
        } else {
            FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->src, &np->dst);
            FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->dst, &np->src);
            np->sp = f->dp;
            np->dp = f->sp;
        }

        
        if (GET_PKT_DIRECT_MAX_SIZE(np) <  40) {
            if (PacketCallocExtPkt(np, 40) == -1) {
                goto error;
            }
        }
        
        np->ip4h = (IPV4Hdr *)GET_PKT_DATA(np);
        
        np->ip4h->ip_verhl = 0x45;
        np->ip4h->ip_tos = 0;
        np->ip4h->ip_len = htons(40);
        np->ip4h->ip_id = 0;
        np->ip4h->ip_off = 0;
        np->ip4h->ip_ttl = 64;
        np->ip4h->ip_proto = IPPROTO_TCP;
        if (dir == 0) {
            np->ip4h->s_ip_src.s_addr = f->src.addr_data32[0];
            np->ip4h->s_ip_dst.s_addr = f->dst.addr_data32[0];
        } else {
            np->ip4h->s_ip_src.s_addr = f->dst.addr_data32[0];
            np->ip4h->s_ip_dst.s_addr = f->src.addr_data32[0];
        }

        
        np->tcph = (TCPHdr *)((uint8_t *)GET_PKT_DATA(np) + 20);

        SET_PKT_LEN(np, 40); 

    } else if (FLOW_IS_IPV6(f)) {
        if (dir == 0) {
            FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->src, &np->src);
            FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->dst, &np->dst);
            np->sp = f->sp;
            np->dp = f->dp;
        } else {
            FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->src, &np->dst);
            FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->dst, &np->src);
            np->sp = f->dp;
            np->dp = f->sp;
        }

        
        if (GET_PKT_DIRECT_MAX_SIZE(np) <  60) {
            if (PacketCallocExtPkt(np, 60) == -1) {
                goto error;
            }
        }
        
        np->ip6h = (IPV6Hdr *)GET_PKT_DATA(np);
        
        np->ip6h->s_ip6_vfc = 0x60;
        np->ip6h->s_ip6_flow = 0;
        np->ip6h->s_ip6_nxt = IPPROTO_TCP;
        np->ip6h->s_ip6_plen = htons(20);
        np->ip6h->s_ip6_hlim = 64;
        if (dir == 0) {
            np->ip6h->s_ip6_src[0] = f->src.addr_data32[0];
            np->ip6h->s_ip6_src[1] = f->src.addr_data32[1];
            np->ip6h->s_ip6_src[2] = f->src.addr_data32[2];
            np->ip6h->s_ip6_src[3] = f->src.addr_data32[3];
            np->ip6h->s_ip6_dst[0] = f->dst.addr_data32[0];
            np->ip6h->s_ip6_dst[1] = f->dst.addr_data32[1];
            np->ip6h->s_ip6_dst[2] = f->dst.addr_data32[2];
            np->ip6h->s_ip6_dst[3] = f->dst.addr_data32[3];
        } else {
            np->ip6h->s_ip6_src[0] = f->dst.addr_data32[0];
            np->ip6h->s_ip6_src[1] = f->dst.addr_data32[1];
            np->ip6h->s_ip6_src[2] = f->dst.addr_data32[2];
            np->ip6h->s_ip6_src[3] = f->dst.addr_data32[3];
            np->ip6h->s_ip6_dst[0] = f->src.addr_data32[0];
            np->ip6h->s_ip6_dst[1] = f->src.addr_data32[1];
            np->ip6h->s_ip6_dst[2] = f->src.addr_data32[2];
            np->ip6h->s_ip6_dst[3] = f->src.addr_data32[3];
        }

        
        np->tcph = (TCPHdr *)((uint8_t *)GET_PKT_DATA(np) + 40);

        SET_PKT_LEN(np, 60); 
    }

    np->tcph->th_offx2 = 0x50;
    np->tcph->th_flags |= TH_ACK;
    np->tcph->th_win = 10;
    np->tcph->th_urp = 0;

    
    if (dir == 0) {
        np->tcph->th_sport = htons(f->sp);
        np->tcph->th_dport = htons(f->dp);

        np->tcph->th_seq = htonl(ssn->client.next_seq);
        np->tcph->th_ack = htonl(ssn->server.last_ack);

    
    } else {
        np->tcph->th_sport = htons(f->dp);
        np->tcph->th_dport = htons(f->sp);

        np->tcph->th_seq = htonl(ssn->server.next_seq);
        np->tcph->th_ack = htonl(ssn->client.last_ack);
    }

    
    memcpy(&np->ts, &parent->ts, sizeof(struct timeval));

    SCLogDebug("np %p", np);
    PacketEnqueueNoLock(pq, np);

    StatsIncr(tv, stt->counter_tcp_pseudo);
    SCReturn;
error:
    FlowDeReference(&np->flow);
    SCReturn;
}


void StreamTcpDetectLogFlush(ThreadVars *tv, StreamTcpThread *stt, Flow *f, Packet *p, PacketQueueNoLock *pq)
{
    TcpSession *ssn = f->protoctx;
    ssn->client.flags |= STREAMTCP_STREAM_FLAG_TRIGGER_RAW;
    ssn->server.flags |= STREAMTCP_STREAM_FLAG_TRIGGER_RAW;
    bool ts = PKT_IS_TOSERVER(p) ? true : false;
    ts ^= StreamTcpInlineMode();
    StreamTcpPseudoPacketCreateDetectLogFlush(tv, stt, p, ssn, pq, ts^0);
    StreamTcpPseudoPacketCreateDetectLogFlush(tv, stt, p, ssn, pq, ts^1);
}


int StreamTcpSegmentForEach(const Packet *p, uint8_t flag, StreamSegmentCallback CallbackFunc, void *data)
{
    TcpSession *ssn = NULL;
    TcpStream *stream = NULL;
    int ret = 0;
    int cnt = 0;

    if (p->flow == NULL)
        return 0;

    ssn = (TcpSession *)p->flow->protoctx;

    if (ssn == NULL) {
        return 0;
    }

    if (flag & FLOW_PKT_TOSERVER) {
        stream = &(ssn->server);
    } else {
        stream = &(ssn->client);
    }

    
    TcpSegment *seg;
    RB_FOREACH(seg, TCPSEG, &stream->seg_tree) {
        if (!((stream_config.flags & STREAMTCP_INIT_FLAG_INLINE)
                    || SEQ_LT(seg->seq, stream->last_ack)))
            break;

        const uint8_t *seg_data;
        uint32_t seg_datalen;
        StreamingBufferSegmentGetData(&stream->sb, &seg->sbseg, &seg_data, &seg_datalen);

        ret = CallbackFunc(p, data, seg_data, seg_datalen);
        if (ret != 1) {
            SCLogDebug("Callback function has failed");
            return -1;
        }

        cnt++;
    }
    return cnt;
}

int StreamTcpBypassEnabled(void)
{
    return (stream_config.flags & STREAMTCP_INIT_FLAG_BYPASS);
}


int StreamTcpInlineMode(void)
{
    return (stream_config.flags & STREAMTCP_INIT_FLAG_INLINE) ? 1 : 0;
}


void TcpSessionSetReassemblyDepth(TcpSession *ssn, uint32_t size)
{
    if (size > ssn->reassembly_depth || size == 0) {
        ssn->reassembly_depth = size;
    }

    return;
}

const char *StreamTcpStateAsString(const enum TcpState state)
{
    const char *tcp_state = NULL;
    switch (state) {
        case TCP_NONE:
            tcp_state = "none";
            break;
        case TCP_LISTEN:
            tcp_state = "listen";
            break;
        case TCP_SYN_SENT:
            tcp_state = "syn_sent";
            break;
        case TCP_SYN_RECV:
            tcp_state = "syn_recv";
            break;
        case TCP_ESTABLISHED:
            tcp_state = "established";
            break;
        case TCP_FIN_WAIT1:
            tcp_state = "fin_wait1";
            break;
        case TCP_FIN_WAIT2:
            tcp_state = "fin_wait2";
            break;
        case TCP_TIME_WAIT:
            tcp_state = "time_wait";
            break;
        case TCP_LAST_ACK:
            tcp_state = "last_ack";
            break;
        case TCP_CLOSE_WAIT:
            tcp_state = "close_wait";
            break;
        case TCP_CLOSING:
            tcp_state = "closing";
            break;
        case TCP_CLOSED:
            tcp_state = "closed";
            break;
    }
    return tcp_state;
}

const char *StreamTcpSsnStateAsString(const TcpSession *ssn)
{
    if (ssn == NULL)
        return NULL;
    return StreamTcpStateAsString(ssn->state);
}




