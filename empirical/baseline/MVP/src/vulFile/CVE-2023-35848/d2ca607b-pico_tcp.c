


































































static void *Mutex = NULL;





struct tcp_input_segment {
    uint32_t seq;
    
    unsigned char *payload;
    uint16_t payload_len;
};


static int input_segment_compare(void *ka, void *kb)
{
    struct tcp_input_segment *a = ka, *b = kb;
    return pico_seq_compare(a->seq, b->seq);
}

static struct tcp_input_segment *segment_from_frame(struct pico_frame *f)
{
    struct tcp_input_segment *seg;

    if (!f->payload_len)
        return NULL;

    seg = PICO_ZALLOC(sizeof(struct tcp_input_segment));
    if (!seg)
        return NULL;

    seg->payload = PICO_ZALLOC(f->payload_len);
    if(!seg->payload)
    {
        PICO_FREE(seg);
        return NULL;
    }

    seg->seq = SEQN(f);
    seg->payload_len = f->payload_len;
    memcpy(seg->payload, f->payload, seg->payload_len);
    return seg;
}

static int segment_compare(void *ka, void *kb)
{
    struct pico_frame *a = ka, *b = kb;
    return pico_seq_compare(SEQN(a), SEQN(b));
}

struct pico_tcp_queue {
    struct pico_tree pool;
    uint32_t max_size;
    uint32_t size;
    uint32_t frames;
};

static void tcp_discard_all_segments(struct pico_tcp_queue *tq);
static void *peek_segment(struct pico_tcp_queue *tq, uint32_t seq)
{
    if(!IS_INPUT_QUEUE(tq))
    {
        struct pico_tcp_hdr H;
        struct pico_frame f = {
            0 };
        f.transport_hdr = (uint8_t *) (&H);
        H.seq = long_be(seq);

        return pico_tree_findKey(&tq->pool, &f);
    }
    else {
        struct tcp_input_segment dummy = {
            0 };
        dummy.seq = seq;

        return pico_tree_findKey(&tq->pool, &dummy);
    }

}

static void *first_segment(struct pico_tcp_queue *tq)
{
    return pico_tree_first(&tq->pool);
}

static void *next_segment(struct pico_tcp_queue *tq, void *cur)
{
    if (!cur)
        return NULL;

    if(IS_INPUT_QUEUE(tq))
    {
        return peek_segment(tq, ((struct tcp_input_segment *)cur)->seq + ((struct tcp_input_segment *)cur)->payload_len);
    }
    else {
        return peek_segment(tq, SEQN((struct pico_frame *)cur) + ((struct pico_frame *)cur)->payload_len);
    }
}

static uint16_t enqueue_segment_len(struct pico_tcp_queue *tq, void *f)
{
    if (IS_INPUT_QUEUE(tq)) {
        return ((struct tcp_input_segment *)f)->payload_len;
    } else {
        return (uint16_t)(((struct pico_frame *)f)->buffer_len);
    }
}


static int32_t do_enqueue_segment(struct pico_tcp_queue *tq, void *f, uint16_t payload_len)
{
    int32_t ret = -1;
    PICOTCP_MUTEX_LOCK(Mutex);
    if ((tq->size + payload_len) > tq->max_size)
    {
        ret = 0;
        goto out;
    }

    if (pico_tree_insert(&tq->pool, f) != 0)
    {
        ret = 0;
        goto out;
    }

    tq->size += (uint16_t)payload_len;
    if (payload_len > 0)
        tq->frames++;

    ret = (int32_t)payload_len;

out:
    PICOTCP_MUTEX_UNLOCK(Mutex);
    return ret;
}

static int32_t pico_enqueue_segment(struct pico_tcp_queue *tq, void *f)
{
    uint16_t payload_len;

    if (!f)
        return -1;

    payload_len = enqueue_segment_len(tq, f);


    if (payload_len == 0) {
        tcp_dbg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! TRIED TO ENQUEUE INVALID SEGMENT!\n");
        return -1;
    }

    return do_enqueue_segment(tq, f, payload_len);
}

static void pico_discard_segment(struct pico_tcp_queue *tq, void *f)
{
    void *f1;
    uint16_t payload_len = (uint16_t)((IS_INPUT_QUEUE(tq)) ? (((struct tcp_input_segment *)f)->payload_len) :
                                      (((struct pico_frame *)f)->buffer_len));
    PICOTCP_MUTEX_LOCK(Mutex);
    f1 = pico_tree_delete(&tq->pool, f);
    if (f1) {
        tq->size -= (uint16_t)payload_len;
        if (payload_len > 0)
            tq->frames--;
    }

    if(f1 && IS_INPUT_QUEUE(tq))
    {
        struct tcp_input_segment *inp = f1;
        PICO_FREE(inp->payload);
        PICO_FREE(inp);
    }
    else pico_frame_discard(f);

    PICOTCP_MUTEX_UNLOCK(Mutex);
}


struct tcp_sack_block {
    uint32_t left;
    uint32_t right;
    struct tcp_sack_block *next;
};

struct pico_socket_tcp {
    struct pico_socket sock;

    
    struct pico_tcp_queue tcpq_in;  
    struct pico_tcp_queue tcpq_out;
    struct pico_tcp_queue tcpq_hold; 

    
    uint32_t snd_nxt;
    uint32_t snd_last;
    uint32_t snd_old_ack;
    uint32_t snd_retry;
    uint32_t snd_last_out;

    
    uint32_t avg_rtt;
    uint32_t rttvar;
    uint32_t rto;
    uint32_t in_flight;
    uint32_t retrans_tmr;
    pico_time retrans_tmr_due;
    uint16_t cwnd_counter;
    uint16_t cwnd;
    uint16_t ssthresh;
    uint16_t recv_wnd;
    uint16_t recv_wnd_scale;

    
    uint32_t rcv_nxt;
    uint32_t rcv_ackd;
    uint32_t rcv_processed;
    uint16_t wnd;
    uint16_t wnd_scale;
    uint16_t remote_closed;

    
    uint32_t ts_nxt;
    uint16_t mss;
    uint8_t sack_ok;
    uint8_t ts_ok;
    uint8_t mss_ok;
    uint8_t scale_ok;
    struct tcp_sack_block *sacks;
    uint32_t linger_timeout;

    
    uint8_t x_mode;
    uint8_t dupacks;
    uint8_t backoff;
    uint8_t localZeroWindow;

    
    uint32_t keepalive_tmr;
    pico_time ack_timestamp;
    uint32_t ka_time;
    uint32_t ka_intvl;
    uint32_t ka_probes;
    uint32_t ka_retries_count;

    
    uint32_t fin_tmr;
};


static struct pico_frame *pico_hold_segment_make(struct pico_socket_tcp *t);


int pico_tcp_queue_in_is_empty(struct pico_socket *s)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *) s;

    if (t->tcpq_in.frames == 0)
        return 1;
    else return 0;
}


int pico_tcp_queue_in_size(struct pico_socket *s)
{
    struct tcp_input_segment *f;
    struct pico_socket_tcp *t = (struct pico_socket_tcp *) s;
    if (!t)
        return -1;
    f = first_segment(&t->tcpq_in);
    if (!f)
        return 0;
    return f->payload_len;
}


static int release_until(struct pico_tcp_queue *q, uint32_t seq)
{
    void *head = first_segment(q);
    int ret = 0;
    int32_t seq_result = 0;

    if (!head)
        return ret;

    do {
        void *cur = head;

        if (IS_INPUT_QUEUE(q))
            seq_result = pico_seq_compare(((struct tcp_input_segment *)head)->seq + ((struct tcp_input_segment *)head)->payload_len, seq);
        else seq_result = pico_seq_compare(SEQN((struct pico_frame *)head) + ((struct pico_frame *)head)->payload_len, seq);

        if (seq_result <= 0)
        {
            head = next_segment(q, cur);
            
            pico_discard_segment(q, cur);
            ret++;
        } else {
            break;
        }
    } while (head);

    return ret;
}

static int release_all_until(struct pico_tcp_queue *q, uint32_t seq, pico_time *timestamp)
{
    void *f = NULL;
    struct pico_tree_node *idx, *temp;
    int seq_result;
    int ret = 0;
    *timestamp = 0;

    pico_tree_foreach_safe(idx, &q->pool, temp)
    {
        f = idx->keyValue;

        if (IS_INPUT_QUEUE(q))
            seq_result = pico_seq_compare(((struct tcp_input_segment *)f)->seq + ((struct tcp_input_segment *)f)->payload_len, seq);
        else seq_result = pico_seq_compare(SEQN((struct pico_frame *)f) + ((struct pico_frame *)f)->payload_len, seq);

        if (seq_result <= 0) {
            tcp_dbg("Releasing %p\n", f);
            if ((seq_result == 0) && !IS_INPUT_QUEUE(q))
                *timestamp = ((struct pico_frame *)f)->timestamp;

            pico_discard_segment(q, f);
            ret++;
        } else {
            return ret;
        }
    }
    return ret;
}




uint16_t pico_tcp_checksum_ipv4(struct pico_frame *f)
{
    struct pico_ipv4_hdr *hdr = (struct pico_ipv4_hdr *) f->net_hdr;
    struct pico_tcp_hdr *tcp_hdr = (struct pico_tcp_hdr *) f->transport_hdr;
    struct pico_socket *s = f->sock;
    struct pico_ipv4_pseudo_hdr pseudo;

    if (s) {
        
        
        pseudo.src.addr = s->local_addr.ip4.addr;
        pseudo.dst.addr = s->remote_addr.ip4.addr;
    } else {
        
        
        pseudo.src.addr = hdr->src.addr;
        pseudo.dst.addr = hdr->dst.addr;
    }

    pseudo.zeros = 0;
    pseudo.proto = PICO_PROTO_TCP;
    pseudo.len = (uint16_t)short_be(f->transport_len);

    return pico_dualbuffer_checksum(&pseudo, sizeof(struct pico_ipv4_pseudo_hdr), tcp_hdr, f->transport_len);
}


uint16_t pico_tcp_checksum_ipv6(struct pico_frame *f)
{
    struct pico_ipv6_hdr *ipv6_hdr = (struct pico_ipv6_hdr *)f->net_hdr;
    struct pico_tcp_hdr *tcp_hdr = (struct pico_tcp_hdr *)f->transport_hdr;
    struct pico_ipv6_pseudo_hdr pseudo;
    struct pico_socket *s = f->sock;

    
    if (s) {
        
        pseudo.src = s->local_addr.ip6;
        pseudo.dst = s->remote_addr.ip6;
    } else {
        
        pseudo.src = ipv6_hdr->src;
        pseudo.dst = ipv6_hdr->dst;
    }

    pseudo.zero[0] = 0;
    pseudo.zero[1] = 0;
    pseudo.zero[2] = 0;
    pseudo.len = long_be(f->transport_len);
    pseudo.nxthdr = PICO_PROTO_TCP;

    return pico_dualbuffer_checksum(&pseudo, sizeof(struct pico_ipv6_pseudo_hdr), tcp_hdr, f->transport_len);
}



static inline int checksum_is_ipv4(struct pico_frame *f)
{
    return (IS_IPV4(f) || (f->sock && (f->sock->net == &pico_proto_ipv4)));
}



static inline int checksum_is_ipv6(struct pico_frame *f)
{
    return ((IS_IPV6(f)) || (f->sock && (f->sock->net == &pico_proto_ipv6)));
}


uint16_t pico_tcp_checksum(struct pico_frame *f)
{
    (void)f;

    #ifdef PICO_SUPPORT_IPV4
    if (checksum_is_ipv4(f))
        return pico_tcp_checksum_ipv4(f);

    #endif

    #ifdef PICO_SUPPORT_IPV6
    if (checksum_is_ipv6(f))
        return pico_tcp_checksum_ipv6(f);

    #endif
    return 0xffff;
}

static void tcp_send_fin(struct pico_socket_tcp *t);
static int pico_tcp_process_out(struct pico_stack *S, struct pico_protocol *self, struct pico_frame *f)
{
    struct pico_tcp_hdr *hdr;
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)f->sock;
    IGNORE_PARAMETER(S);
    IGNORE_PARAMETER(self);
    hdr = (struct pico_tcp_hdr *)f->transport_hdr;
    f->sock->timestamp = TCP_TIME;
    if (f->payload_len > 0) {
        tcp_dbg("Process out: sending %p (%d bytes)\n", f, f->payload_len);
    } else {
        tcp_dbg("Sending empty packet\n");
    }

    if (f->payload_len > 0) {
        if (pico_seq_compare(SEQN(f) + f->payload_len, t->snd_nxt) > 0) {
            t->snd_nxt = SEQN(f) + f->payload_len;
            tcp_dbg("%s: snd_nxt is now %08x\n", __FUNCTION__, t->snd_nxt);
        }
    } else if (hdr->flags == PICO_TCP_ACK) { 
        
    } else {
        tcp_dbg("%s: non-pure ACK with len=0, fl:%04x\n", __FUNCTION__, hdr->flags);
    }

    pico_network_send(f);
    return 0;
}

int pico_tcp_push(struct pico_stack *S, struct pico_protocol *self, struct pico_frame *data);


struct pico_protocol pico_proto_tcp = {
    .name = "tcp", .proto_number = PICO_PROTO_TCP, .layer = PICO_LAYER_TRANSPORT, .process_in = pico_transport_process_in, .process_out = pico_tcp_process_out, .push = pico_tcp_push, };






static uint32_t pico_paws(void)
{
    static uint32_t _paws = 0;
    _paws = pico_rand();
    return long_be(_paws);
}

static inline void tcp_add_sack_option(struct pico_socket_tcp *ts, struct pico_frame *f, uint16_t flags, uint32_t *ii)
{
    if (flags & PICO_TCP_ACK) {
        struct tcp_sack_block *sb;
        uint32_t len_off;

        if (ts->sack_ok && ts->sacks) {
            f->start[(*ii)++] = PICO_TCP_OPTION_SACK;
            len_off = *ii;
            f->start[(*ii)++] = PICO_TCPOPTLEN_SACK;
            while(ts->sacks) {
                sb = ts->sacks;
                ts->sacks = sb->next;
                memcpy(f->start + *ii, sb, 2 * sizeof(uint32_t));
                *ii += (2 * (uint32_t)sizeof(uint32_t));
                f->start[len_off] = (uint8_t)(f->start[len_off] + (2 * sizeof(uint32_t)));
                PICO_FREE(sb);
            }
        }
    }
}

static void tcp_add_options(struct pico_socket_tcp *ts, struct pico_frame *f, uint16_t flags, uint16_t optsiz)
{
    uint32_t tsval = long_be((uint32_t)TCP_TIME);
    uint32_t tsecr = long_be(ts->ts_nxt);
    uint32_t i = 0;
    f->start = f->transport_hdr + PICO_SIZE_TCPHDR;

    memset(f->start, PICO_TCP_OPTION_NOOP, optsiz); 

    if (flags & PICO_TCP_SYN) {
        f->start[i++] = PICO_TCP_OPTION_MSS;
        f->start[i++] = PICO_TCPOPTLEN_MSS;
        f->start[i++] = (uint8_t)((ts->mss >> 8) & 0xFF);
        f->start[i++] = (uint8_t)(ts->mss & 0xFF);
        f->start[i++] = PICO_TCP_OPTION_SACK_OK;
        f->start[i++] = PICO_TCPOPTLEN_SACK_OK;
    }

    f->start[i++] = PICO_TCP_OPTION_WS;
    f->start[i++] = PICO_TCPOPTLEN_WS;
    f->start[i++] = (uint8_t)(ts->wnd_scale);

    if ((flags & PICO_TCP_SYN) || ts->ts_ok) {
        f->start[i++] = PICO_TCP_OPTION_TIMESTAMP;
        f->start[i++] = PICO_TCPOPTLEN_TIMESTAMP;
        memcpy(f->start + i, &tsval, 4);
        i += 4;
        memcpy(f->start + i, &tsecr, 4);
        i += 4;
    }

    tcp_add_sack_option(ts, f, flags, &i);

    if (i < optsiz)
        f->start[ optsiz - 1 ] = PICO_TCP_OPTION_END;
}

static uint16_t tcp_options_size_frame(struct pico_frame *f)
{
    uint16_t size = 0;

    
    size = (uint16_t)(size + PICO_TCPOPTLEN_WS);
    if (f->transport_flags_saved)
        size = (uint16_t)(size + PICO_TCPOPTLEN_TIMESTAMP);

    size = (uint16_t)(size + PICO_TCPOPTLEN_END);
    size = (uint16_t)(((uint16_t)(size + 3u) >> 2u) << 2u);
    return size;
}

static void tcp_add_options_frame(struct pico_socket_tcp *ts, struct pico_frame *f)
{
    uint32_t tsval = long_be((uint32_t)TCP_TIME);
    uint32_t tsecr = long_be(ts->ts_nxt);
    uint32_t i = 0;
    uint16_t optsiz = tcp_options_size_frame(f);

    f->start = f->transport_hdr + PICO_SIZE_TCPHDR;

    memset(f->start, PICO_TCP_OPTION_NOOP, optsiz); 


    f->start[i++] = PICO_TCP_OPTION_WS;
    f->start[i++] = PICO_TCPOPTLEN_WS;
    f->start[i++] = (uint8_t)(ts->wnd_scale);

    if (f->transport_flags_saved) {
        f->start[i++] = PICO_TCP_OPTION_TIMESTAMP;
        f->start[i++] = PICO_TCPOPTLEN_TIMESTAMP;
        memcpy(f->start + i, &tsval, 4);
        i += 4;
        memcpy(f->start + i, &tsecr, 4);
        i += 4;
    }

    if (i < optsiz)
        f->start[ optsiz - 1 ] = PICO_TCP_OPTION_END;
}

static void tcp_send_ack(struct pico_socket_tcp *t);


static inline void tcp_set_space_check_winupdate(struct pico_socket_tcp *t, int32_t space, uint32_t shift)
{
    if (((uint32_t)space != t->wnd) || (shift != t->wnd_scale) || ((space - t->wnd) > (int32_t)((uint32_t)space >> 2u))) {
        t->wnd = (uint16_t)space;
        t->wnd_scale = (uint16_t)shift;

        if(t->wnd == 0) 
            t->localZeroWindow = 1u;
        else if(t->localZeroWindow)
        {
            t->localZeroWindow = 0u;
            tcp_send_windowUpdate(t);
        }
    }
}

static void tcp_set_space(struct pico_socket_tcp *t)
{
    int32_t space;
    uint32_t shift = 0;

    if (t->tcpq_in.max_size == 0) {
        space = ONE_GIGABYTE;
    } else {
        space = (int32_t)(t->tcpq_in.max_size - t->tcpq_in.size);
    }

    if (space < 0)
        space = 0;

    while(space > 0xFFFF) {
        space = (int32_t)(((uint32_t)space >> 1u));
        shift++;
    }
    tcp_set_space_check_winupdate(t, space, shift);
}


static uint16_t tcp_options_size(struct pico_socket_tcp *t, uint16_t flags)
{
    uint16_t size = 0;
    struct tcp_sack_block *sb = t->sacks;

    if (flags & PICO_TCP_SYN) { 
        size = PICO_TCPOPTLEN_MSS + PICO_TCP_OPTION_SACK_OK + PICO_TCPOPTLEN_WS + PICO_TCPOPTLEN_TIMESTAMP;
    } else {

        
        size = (uint16_t)(size + PICO_TCPOPTLEN_WS);

        if (t->ts_ok)
            size = (uint16_t)(size + PICO_TCPOPTLEN_TIMESTAMP);

        size = (uint16_t)(size + PICO_TCPOPTLEN_END);
    }

    if ((flags & PICO_TCP_ACK) && (t->sack_ok && sb)) {
        size = (uint16_t)(size + 2);
        while(sb) {
            size = (uint16_t)(size + (2 * sizeof(uint32_t)));
            sb = sb->next;
        }
    }

    size = (uint16_t)(((size + 3u) >> 2u) << 2u);
    return size;
}

uint16_t pico_tcp_overhead(struct pico_socket *s)
{
    if (!s)
        return 0;

    return (uint16_t)(PICO_SIZE_TCPHDR + tcp_options_size((struct pico_socket_tcp *)s, (uint16_t)0)); 

}

static inline int tcp_sack_marker(struct pico_frame *f, uint32_t start, uint32_t end, uint16_t *count)
{
    int cmp;
    cmp = pico_seq_compare(SEQN(f), start);
    if (cmp > 0)
        return 0;

    if (cmp == 0) {
        cmp = pico_seq_compare(SEQN(f) + f->payload_len, end);
        if (cmp > 0) {
            tcp_dbg("Invalid SACK: ignoring.\n");
        }

        tcp_dbg("Marking (by SACK) segment %08x BLK:[%08x::%08x]\n", SEQN(f), start, end);
        f->flags |= PICO_FRAME_FLAG_SACKED;
        (*count)++;
    }

    return cmp;
}

static void tcp_process_sack(struct pico_socket_tcp *t, uint32_t start, uint32_t end)
{
    struct pico_frame *f;
    struct pico_tree_node *index, *temp;
    uint16_t count = 0;

    pico_tree_foreach_safe(index, &t->tcpq_out.pool, temp){
        f = index->keyValue;
        if (tcp_sack_marker(f, start, end, &count) == 0)
            goto done;
    }

done:
    if (t->x_mode > PICO_TCP_LOOKAHEAD) {
        if (t->in_flight > (count))
            t->in_flight -= (count);
        else t->in_flight = 0;
    }
}

inline static void tcp_add_header(struct pico_socket_tcp *t, struct pico_frame *f)
{
    struct pico_tcp_hdr *hdr = (struct pico_tcp_hdr *)f->transport_hdr;
    f->timestamp = TCP_TIME;
    tcp_add_options(t, f, 0, (uint16_t)(f->transport_len - f->payload_len - (uint16_t)PICO_SIZE_TCPHDR));
    hdr->rwnd = short_be(t->wnd);
    hdr->flags |= PICO_TCP_PSH | PICO_TCP_ACK;
    hdr->ack = long_be(t->rcv_nxt);
    hdr->crc = 0;
    hdr->crc = short_be(pico_tcp_checksum(f));
}

static void tcp_rcv_sack(struct pico_socket_tcp *t, uint8_t *opt, int len)
{
    uint32_t start, end;
    int i = 0;
    if (len % 8) {
        tcp_dbg("SACK: Invalid len.\n");
        return;
    }

    while (i < len) {
        start = long_from(opt + i);
        i += 4;
        end = long_from(opt + i);
        i += 4;
        tcp_process_sack(t, long_be(start), long_be(end));
    }
}

static int tcpopt_len_check(uint32_t *idx, uint8_t len, uint8_t expected)
{
    if (len != expected) {
        if (len < 2)
            return -1;
        *idx = *idx + len - 2;
        return -1;
    }

    return 0;
}

static inline void tcp_parse_option_ws(struct pico_socket_tcp *t, uint8_t len, uint8_t *opt, uint32_t *idx)
{
    if (tcpopt_len_check(idx, len, PICO_TCPOPTLEN_WS) < 0)
        return;

    t->recv_wnd_scale = opt[(*idx)++];
    tcp_dbg_options("TCP Window scale: received %d\n", t->recv_wnd_scale);

}

static inline void tcp_parse_option_sack_ok(struct pico_socket_tcp *t, struct pico_frame *f, uint8_t len, uint32_t *idx)
{
    if (tcpopt_len_check(idx, len, PICO_TCPOPTLEN_SACK_OK) < 0)
        return;

    if(((struct pico_tcp_hdr *)(f->transport_hdr))->flags & PICO_TCP_SYN )
        t->sack_ok = 1;
}

static inline void tcp_parse_option_mss(struct pico_socket_tcp *t, uint8_t len, uint8_t *opt, uint32_t *idx)
{
    uint16_t mss;
    if (tcpopt_len_check(idx, len, PICO_TCPOPTLEN_MSS) < 0)
        return;

    t->mss_ok = 1;
    mss = short_from(opt + *idx);
    *idx += (uint32_t)sizeof(uint16_t);
    if (t->mss > short_be(mss))
        t->mss = short_be(mss);
}

static inline void tcp_parse_option_timestamp(struct pico_socket_tcp *t, struct pico_frame *f, uint8_t len, uint8_t *opt, uint32_t *idx)
{
    uint32_t tsval, tsecr;
    if (tcpopt_len_check(idx, len, PICO_TCPOPTLEN_TIMESTAMP) < 0)
        return;

    t->ts_ok = 1;
    tsval = long_from(opt + *idx);
    *idx += (uint32_t)sizeof(uint32_t);
    tsecr = long_from(opt + *idx);
    f->timestamp = long_be(tsecr);
    *idx += (uint32_t)sizeof(uint32_t);
    t->ts_nxt = long_be(tsval);
}

static int tcp_parse_options(struct pico_frame *f)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)f->sock;
    uint8_t *opt = f->transport_hdr + PICO_SIZE_TCPHDR;
    uint32_t i = 0;
    f->timestamp = 0;
    while (i < (f->transport_len - PICO_SIZE_TCPHDR)) {
        uint8_t type =  opt[i++];
        uint8_t len;
        if(i < (f->transport_len - PICO_SIZE_TCPHDR) && (type > 1))
            len =  opt[i++];
        else len = 1;

        if (f->payload && ((opt + i) > f->payload))
            break;

        if (len == 0) {
            return -1;
        }

        tcp_dbg_options("Received option '%d', len = %d \n", type, len);
        switch (type) {
        case PICO_TCP_OPTION_NOOP:
        case PICO_TCP_OPTION_END:
            break;
        case PICO_TCP_OPTION_WS:
            tcp_parse_option_ws(t, len, opt, &i);
            break;
        case PICO_TCP_OPTION_SACK_OK:
            tcp_parse_option_sack_ok(t, f, len, &i);
            break;
        case PICO_TCP_OPTION_MSS:
            tcp_parse_option_mss(t, len, opt, &i);
            break;
        case PICO_TCP_OPTION_TIMESTAMP:
            tcp_parse_option_timestamp(t, f, len, opt, &i);
            break;

        case PICO_TCP_OPTION_SACK:
            tcp_rcv_sack(t, opt + i, len - 2);
            i = i + len - 2;
            break;
        default:
            tcp_dbg_options("TCP: received unsupported option %u\n", type);
            i = i + len - 2;
        }
    }
    return 0;
}

static inline void tcp_send_add_tcpflags(struct pico_socket_tcp *ts, struct pico_frame *f)
{
    struct pico_tcp_hdr *hdr = (struct pico_tcp_hdr *) f->transport_hdr;
    if (ts->rcv_nxt != 0) {
        if ((ts->rcv_ackd == 0) || (pico_seq_compare(ts->rcv_ackd, ts->rcv_nxt) != 0) || (hdr->flags & PICO_TCP_ACK)) {
            hdr->flags |= PICO_TCP_ACK;
            hdr->ack = long_be(ts->rcv_nxt);
            ts->rcv_ackd = ts->rcv_nxt;
        }
    }

    if (hdr->flags & PICO_TCP_SYN) {
        ts->snd_nxt++;
    }

    if (f->payload_len > 0) {
        hdr->flags |= PICO_TCP_PSH | PICO_TCP_ACK;
        hdr->ack = long_be(ts->rcv_nxt);
        ts->rcv_ackd = ts->rcv_nxt;
    }
}

static inline int tcp_send_try_enqueue(struct pico_socket_tcp *ts, struct pico_frame *f)
{
    struct pico_tcp_hdr *hdr = (struct pico_tcp_hdr *) f->transport_hdr;
    struct pico_frame *cpy;
    (void)hdr;

    
    cpy = pico_frame_copy(f);
    if (!cpy) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    if ((pico_enqueue(&ts->sock.stack->q_tcp.out, cpy) > 0)) {
        if (f->payload_len > 0) {
            ts->in_flight++;
            ts->snd_nxt += f->payload_len; 
        }

        tcp_dbg("DBG> [tcp output] state: %02x --> local port:%u remote port: %u seq: %08x ack: %08x flags: %02x = t_len: %u, hdr: %u payload: %d\n", TCPSTATE(&ts->sock) >> 8, short_be(hdr->trans.sport), short_be(hdr->trans.dport), SEQN(f), ACKN(f), hdr->flags, f->transport_len, (hdr->len & 0xf0) >> 2, f->payload_len );
    } else {
        pico_frame_discard(cpy);
    }

    return 0;

}

static int tcp_send(struct pico_socket_tcp *ts, struct pico_frame *f)
{
    struct pico_tcp_hdr *hdr = (struct pico_tcp_hdr *) f->transport_hdr;
    hdr->trans.sport = ts->sock.local_port;
    hdr->trans.dport = ts->sock.remote_port;
    if (!hdr->seq)
        hdr->seq = long_be(ts->snd_nxt);

    tcp_send_add_tcpflags(ts, f);

    f->start = f->transport_hdr + PICO_SIZE_TCPHDR;
    hdr->rwnd = short_be(ts->wnd);
    hdr->crc = 0;
    hdr->crc = short_be(pico_tcp_checksum(f));

    return tcp_send_try_enqueue(ts, f);

}




static void sock_stats(uint32_t when, void *arg)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)arg;
    tcp_dbg("STATISTIC> [%lu] socket state: %02x --> local port:%d remote port: %d queue size: %d snd_una: %08x snd_nxt: %08x cwnd: %d\n", when, t->sock.state, short_be(t->sock.local_port), short_be(t->sock.remote_port), t->tcpq_out.size, SEQN((struct pico_frame *)first_segment(&t->tcpq_out)), t->snd_nxt, t->cwnd);
    if (!pico_timer_add(t->sock.stack, 2000, sock_stats, t)) {
        tcp_dbg("TCP: Failed to start socket statistics timer\n");
    }
}


static void tcp_send_probe(struct pico_socket_tcp *t);

static void pico_tcp_keepalive(pico_time now, void *arg)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)arg;
    if (((t->sock.state & PICO_SOCKET_STATE_TCP) == PICO_SOCKET_STATE_TCP_ESTABLISHED)  && (t->ka_time > 0)) {
        if (t->ka_time < (now - t->ack_timestamp)) {
            if (t->ka_retries_count == 0) {
                
                tcp_send_probe(t);
                t->ka_retries_count++;
            }

            if (t->ka_retries_count > t->ka_probes) {
                if (t->sock.wakeup)
                {
                    pico_err = PICO_ERR_ECONNRESET;
                    t->sock.wakeup(PICO_SOCK_EV_ERR, &t->sock);
                }
            }

            if (((t->ka_retries_count * (pico_time)t->ka_intvl) + t->ka_time) < (now - t->ack_timestamp)) {
                
                tcp_send_probe(t);
                t->ka_retries_count++;
            }
        } else {
            t->ka_retries_count = 0;
        }
    }

    t->keepalive_tmr = pico_timer_add(t->sock.stack, 1000, pico_tcp_keepalive, t);
    if (!t->keepalive_tmr) {
        tcp_dbg("TCP: Failed to start keepalive timer\n");
        if (t->sock.wakeup)
            t->sock.wakeup(PICO_SOCK_EV_ERR, &t->sock);
    }
}

static inline void rto_set(struct pico_socket_tcp *t, uint32_t rto)
{
    if (rto < PICO_TCP_RTO_MIN)
        rto = PICO_TCP_RTO_MIN;

    if (rto > PICO_TCP_RTO_MAX)
        rto = PICO_TCP_RTO_MAX;

    t->rto = rto;
}


struct pico_socket *pico_tcp_open(struct pico_stack *S, uint16_t family)
{
    struct pico_socket_tcp *t = PICO_ZALLOC(sizeof(struct pico_socket_tcp));
    if (!t)
        return NULL;

    t->sock.stack = S;
    t->sock.timestamp = TCP_TIME;
    pico_socket_set_family(&t->sock, family);
    t->mss = (uint16_t)(pico_socket_get_mss(&t->sock) - PICO_SIZE_TCPHDR);
    t->tcpq_in.pool.root = t->tcpq_hold.pool.root = t->tcpq_out.pool.root = &LEAF;
    t->tcpq_hold.pool.compare = t->tcpq_out.pool.compare = segment_compare;
    t->tcpq_in.pool.compare = input_segment_compare;
    t->tcpq_in.max_size = PICO_DEFAULT_SOCKETQ;
    t->tcpq_out.max_size = PICO_DEFAULT_SOCKETQ;
    t->tcpq_hold.max_size = 2u * t->mss;
    rto_set(t, PICO_TCP_RTO_MIN);

    
    t->sock.opt_flags |= (1 << PICO_SOCKET_OPT_TCPNODELAY);

    
    

    
    t->linger_timeout = PICO_SOCKET_LINGER_TIMEOUT;



    if (!pico_timer_add(t->sock.stack, 2000, sock_stats, t)) {
        tcp_dbg("TCP: Failed to start socket statistics timer\n");
        PICO_FREE(t);
        return NULL;
    }


    t->keepalive_tmr = pico_timer_add(t->sock.stack, 1000, pico_tcp_keepalive, t);
    if (!t->keepalive_tmr) {
        tcp_dbg("TCP: Failed to start keepalive timer\n");
        PICO_FREE(t);
        return NULL;
    }
    tcp_set_space(t);
    return &t->sock;
}

static uint32_t tcp_read_finish(struct pico_socket *s, uint32_t tot_rd_len)
{
    struct pico_socket_tcp *t = TCP_SOCK(s);
    tcp_set_space(t);
    if (t->tcpq_in.size == 0) {
        s->ev_pending &= (uint16_t)(~PICO_SOCK_EV_RD);
    }

    if (t->remote_closed) {
        s->ev_pending |= (uint16_t)(PICO_SOCK_EV_CLOSE);
        s->state &= 0x00FFU;
        s->state |= PICO_SOCKET_STATE_TCP_CLOSE_WAIT;
        
        s->state |= PICO_SOCKET_STATE_SHUT_REMOTE;
        if (s->wakeup) {
            s->wakeup(PICO_SOCK_EV_CLOSE, s);
        }
    }

    return tot_rd_len;
}

static inline uint32_t tcp_read_in_frame_len(struct tcp_input_segment *f, int32_t in_frame_off, uint32_t tot_rd_len, uint32_t read_op_len)
{
    uint32_t in_frame_len = 0;
    if (in_frame_off > 0)
    {
        if ((uint32_t)in_frame_off > f->payload_len) {
            tcp_dbg("FATAL TCP ERR: in_frame_off > f->payload_len\n");
        }

        in_frame_len = f->payload_len - (uint32_t)in_frame_off;
    } else { 
        in_frame_len = f->payload_len;
    }

    if ((in_frame_len + tot_rd_len) > (uint32_t)read_op_len) {
        in_frame_len = read_op_len - tot_rd_len;
    }

    return in_frame_len;

}

static inline void tcp_read_check_segment_done(struct pico_socket_tcp *t, struct tcp_input_segment *f, uint32_t in_frame_len)
{
    if ((in_frame_len == 0u) || (in_frame_len == (uint32_t)f->payload_len)) {
        pico_discard_segment(&t->tcpq_in, f);
    }
}

uint32_t pico_tcp_read(struct pico_socket *s, void *buf, uint32_t len)
{
    struct pico_socket_tcp *t = TCP_SOCK(s);
    struct tcp_input_segment *f;
    int32_t in_frame_off;
    uint32_t in_frame_len;
    uint32_t tot_rd_len = 0;

    while (tot_rd_len < len) {
        
        release_until(&t->tcpq_in, t->rcv_processed);
        f = first_segment(&t->tcpq_in);
        if (!f)
            return tcp_read_finish(s, tot_rd_len);

        in_frame_off = pico_seq_compare(t->rcv_processed, f->seq);
        
        if (in_frame_off < 0) {
            tcp_dbg("TCP> read hole beginning of data, %08x - %08x. rcv_nxt is %08x\n", t->rcv_processed, f->seq, t->rcv_nxt);
            return tcp_read_finish(s, tot_rd_len);
        }

        in_frame_len = tcp_read_in_frame_len(f, in_frame_off, tot_rd_len, len);


        memcpy((uint8_t *)buf + tot_rd_len, f->payload + in_frame_off, in_frame_len);
        tot_rd_len += in_frame_len;
        t->rcv_processed += in_frame_len;

        tcp_read_check_segment_done(t, f, in_frame_len);

    }
    return tcp_read_finish(s, tot_rd_len);
}

int pico_tcp_initconn(struct pico_socket *s);
static void initconn_retry(pico_time when, void *arg)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)arg;
    IGNORE_PARAMETER(when);
    if (TCPSTATE(&t->sock) != PICO_SOCKET_STATE_TCP_ESTABLISHED)
    {
        if (t->backoff > PICO_TCP_MAX_CONNECT_RETRIES) {
            tcp_dbg("TCP> Connection timeout. \n");
            if (t->sock.wakeup)
            {
                pico_err = PICO_ERR_ECONNREFUSED;
                t->sock.wakeup(PICO_SOCK_EV_ERR, &t->sock);
            }

            pico_socket_del(&t->sock);
            return;
        }

        tcp_dbg("TCP> SYN retry %d...\n", t->backoff);
        t->backoff++;
        pico_tcp_initconn(&t->sock);
    } else {
        tcp_dbg("TCP> Connection is already established: no retry needed. good.\n");
    }
}

int pico_tcp_initconn(struct pico_socket *s)
{
    struct pico_socket_tcp *ts = TCP_SOCK(s);
    struct pico_frame *syn;
    struct pico_tcp_hdr *hdr;
    uint16_t mtu, opt_len = tcp_options_size(ts, PICO_TCP_SYN);

    syn = s->net->alloc(s->stack, s->net, NULL, (uint16_t)(PICO_SIZE_TCPHDR + opt_len));
    if (!syn)
        return -1;

    hdr = (struct pico_tcp_hdr *) syn->transport_hdr;

    if (!ts->snd_nxt)
        ts->snd_nxt = long_be(pico_paws());

    ts->snd_last = ts->snd_nxt;
    ts->cwnd = PICO_TCP_IW;
    mtu = (uint16_t)pico_socket_get_mss(s);
    ts->mss = (uint16_t)(mtu - PICO_SIZE_TCPHDR);
    ts->ssthresh = (uint16_t)((uint16_t)(PICO_DEFAULT_SOCKETQ / ts->mss) -  (((uint16_t)(PICO_DEFAULT_SOCKETQ / ts->mss)) >> 3u));
    syn->sock = s;
    hdr->seq = long_be(ts->snd_nxt);
    hdr->len = (uint8_t)((PICO_SIZE_TCPHDR + opt_len) << 2);
    hdr->flags = PICO_TCP_SYN;
    tcp_set_space(ts);
    hdr->rwnd = short_be(ts->wnd);
    tcp_add_options(ts, syn, PICO_TCP_SYN, opt_len);
    hdr->trans.sport = ts->sock.local_port;
    hdr->trans.dport = ts->sock.remote_port;

    hdr->crc = 0;
    hdr->crc = short_be(pico_tcp_checksum(syn));

    
    tcp_dbg("Sending SYN... (ports: %d - %d) size: %d\n", short_be(ts->sock.local_port), short_be(ts->sock.remote_port), syn->buffer_len);
    ts->retrans_tmr = pico_timer_add(s->stack, PICO_TCP_SYN_TO << ts->backoff, initconn_retry, ts);
    if (!ts->retrans_tmr) {
        tcp_dbg("TCP: Failed to start initconn_retry timer\n");
        PICO_FREE(syn);
        return -1;
    }
    pico_enqueue(&s->stack->q_tcp.out, syn);
    return 0;
}

static int tcp_send_synack(struct pico_socket *s)
{
    struct pico_socket_tcp *ts = TCP_SOCK(s);
    struct pico_frame *synack;
    struct pico_tcp_hdr *hdr;
    uint16_t opt_len = tcp_options_size(ts, PICO_TCP_SYN | PICO_TCP_ACK);

    synack = s->net->alloc(s->stack, s->net, NULL, (uint16_t)(PICO_SIZE_TCPHDR + opt_len));
    if (!synack)
        return -1;

    hdr = (struct pico_tcp_hdr *) synack->transport_hdr;

    synack->sock = s;
    hdr->len = (uint8_t)((PICO_SIZE_TCPHDR + opt_len) << 2);
    hdr->flags = PICO_TCP_SYN | PICO_TCP_ACK;
    hdr->rwnd = short_be(ts->wnd);
    hdr->seq = long_be(ts->snd_nxt);
    ts->rcv_processed = long_be(hdr->seq);
    ts->snd_last = ts->snd_nxt;
    tcp_set_space(ts);
    tcp_add_options(ts, synack, hdr->flags, opt_len);
    synack->payload_len = 0;
    synack->timestamp = TCP_TIME;
    tcp_send(ts, synack);
    pico_frame_discard(synack);
    return 0;
}

static void tcp_send_empty(struct pico_socket_tcp *t, uint16_t flags, int is_keepalive)
{
    struct pico_frame *f;
    struct pico_tcp_hdr *hdr;
    uint16_t opt_len = tcp_options_size(t, flags);
    f = t->sock.net->alloc(t->sock.stack, t->sock.net, NULL, (uint16_t)(PICO_SIZE_TCPHDR + opt_len));
    if (!f) {
        return;
    }

    f->sock = &t->sock;
    hdr = (struct pico_tcp_hdr *) f->transport_hdr;
    hdr->len = (uint8_t)((PICO_SIZE_TCPHDR + opt_len) << 2);
    hdr->flags = (uint8_t)flags;
    hdr->rwnd = short_be(t->wnd);
    tcp_set_space(t);
    tcp_add_options(t, f, flags, opt_len);
    hdr->trans.sport = t->sock.local_port;
    hdr->trans.dport = t->sock.remote_port;
    hdr->seq = long_be(t->snd_nxt);
    if ((flags & PICO_TCP_ACK) != 0) {
        hdr->ack = long_be(t->rcv_nxt);
    }

    if (is_keepalive)
        hdr->seq = long_be(t->snd_nxt - 1);

    t->rcv_ackd = t->rcv_nxt;

    f->start = f->transport_hdr + PICO_SIZE_TCPHDR;
    hdr->rwnd = short_be(t->wnd);
    hdr->crc = 0;
    hdr->crc = short_be(pico_tcp_checksum(f));

    
    pico_enqueue(&t->sock.stack->q_tcp.out, f);
}

static void tcp_send_ack(struct pico_socket_tcp *t)
{
    tcp_send_empty(t, PICO_TCP_ACK, 0);
}

static void tcp_send_probe(struct pico_socket_tcp *t)
{
    
    tcp_send_empty(t, PICO_TCP_PSHACK, 1);
}

static int tcp_do_send_rst(struct pico_socket *s, uint32_t seq)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *) s;
    uint16_t opt_len = tcp_options_size(t, PICO_TCP_RST);
    struct pico_frame *f;
    struct pico_tcp_hdr *hdr;
    f = t->sock.net->alloc(s->stack, t->sock.net, NULL, (uint16_t)(PICO_SIZE_TCPHDR + opt_len));
    if (!f) {
        return -1;
    }

    f->sock = &t->sock;
    tcp_dbg("TCP SEND_RST >>>>>>>>>>>>>>> START\n");

    hdr = (struct pico_tcp_hdr *) f->transport_hdr;
    hdr->len = (uint8_t)((PICO_SIZE_TCPHDR + opt_len) << 2);
    hdr->flags = PICO_TCP_RST;
    hdr->rwnd = short_be(t->wnd);
    tcp_set_space(t);
    tcp_add_options(t, f, PICO_TCP_RST, opt_len);
    hdr->trans.sport = t->sock.local_port;
    hdr->trans.dport = t->sock.remote_port;
    hdr->seq = seq;
    hdr->ack = long_be(t->rcv_nxt);
    t->rcv_ackd = t->rcv_nxt;
    f->start = f->transport_hdr + PICO_SIZE_TCPHDR;
    hdr->rwnd = short_be(t->wnd);
    hdr->crc = 0;
    hdr->crc = short_be(pico_tcp_checksum(f));

    
    pico_enqueue(&t->sock.stack->q_tcp.out, f);
    tcp_dbg("TCP SEND_RST >>>>>>>>>>>>>>> DONE\n");
    return 0;
}

static int tcp_send_rst(struct pico_socket *s, struct pico_frame *fr)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *) s;
    struct pico_tcp_hdr *hdr_rcv;
    int ret;

    if (fr && ((s->state & PICO_SOCKET_STATE_TCP) > PICO_SOCKET_STATE_TCP_SYN_RECV)) {
        
        hdr_rcv = (struct pico_tcp_hdr *) fr->transport_hdr;
        ret = tcp_do_send_rst(s, hdr_rcv->ack);
    } else {
        
        
        (t->sock).state &= 0x00FFU;
        (t->sock).state |= PICO_SOCKET_STATE_TCP_CLOSED;
        ret = tcp_do_send_rst(s, long_be(t->snd_nxt));

        
        (t->sock).state &= 0xFF00U;
        (t->sock).state |= PICO_SOCKET_STATE_CLOSED;

        
        if ((t->sock).wakeup)
            (t->sock).wakeup(PICO_SOCK_EV_FIN, &(t->sock));

        
        pico_socket_del(&t->sock);
    }

    return ret;
}

static inline void tcp_fill_rst_payload(struct pico_frame *fr, struct pico_frame *f)
{
    
    if (IS_IPV4(fr)) {
        memcpy(f->net_hdr, fr->net_hdr, sizeof(struct pico_ipv4_hdr));
        ((struct pico_ipv4_hdr *)(f->net_hdr))->dst.addr = ((struct pico_ipv4_hdr *)(fr->net_hdr))->src.addr;
        ((struct pico_ipv4_hdr *)(f->net_hdr))->src.addr = ((struct pico_ipv4_hdr *)(fr->net_hdr))->dst.addr;
        tcp_dbg("Making IPv4 reset frame...\n");

    } else {
        memcpy(f->net_hdr, fr->net_hdr, sizeof(struct pico_ipv6_hdr));
        ((struct pico_ipv6_hdr *)(f->net_hdr))->dst = ((struct pico_ipv6_hdr *)(fr->net_hdr))->src;
        ((struct pico_ipv6_hdr *)(f->net_hdr))->src = ((struct pico_ipv6_hdr *)(fr->net_hdr))->dst;
    }

    
    ((struct pico_tcp_hdr *)(f->transport_hdr))->trans.dport = ((struct pico_tcp_hdr *)(fr->transport_hdr))->trans.sport;
    ((struct pico_tcp_hdr *)(f->transport_hdr))->trans.sport = ((struct pico_tcp_hdr *)(fr->transport_hdr))->trans.dport;

}


static inline void tcp_fill_rst_header(struct pico_frame *fr, struct pico_tcp_hdr *hdr1, struct pico_frame *f, struct pico_tcp_hdr *hdr)
{
    if(!(hdr1->flags & PICO_TCP_ACK))
        hdr->flags |= PICO_TCP_ACK;

    hdr->rwnd  = 0;
    if (((struct pico_tcp_hdr *)(fr->transport_hdr))->flags & PICO_TCP_ACK) {
        hdr->seq = ((struct pico_tcp_hdr *)(fr->transport_hdr))->ack;
    } else {
        hdr->seq = 0U;
    }

    hdr->ack = 0;
    if(!(hdr1->flags & PICO_TCP_ACK))
        hdr->ack = long_be(long_be(((struct pico_tcp_hdr *)(fr->transport_hdr))->seq) + fr->payload_len);

    hdr->crc = short_be(pico_tcp_checksum(f));
}

int pico_tcp_reply_rst(struct pico_stack *S, struct pico_frame *fr)
{
    struct pico_tcp_hdr *hdr, *hdr1;
    struct pico_frame *f;
    uint16_t size = PICO_SIZE_TCPHDR;


    hdr1 = (struct pico_tcp_hdr *) (fr->transport_hdr);
    if ((hdr1->flags & PICO_TCP_RST) != 0)
        return -1;

    tcp_dbg("TCP> sending RST ... \n");

    f = fr->sock->net->alloc(fr->sock->stack, fr->sock->net, NULL, size);
    if (!f) {
        pico_err = PICO_ERR_ENOMEM;
        return -1;
    }

    tcp_fill_rst_payload(fr, f);

    hdr = (struct pico_tcp_hdr *) f->transport_hdr;
    hdr->len   = (uint8_t)(size << 2);
    hdr->flags = PICO_TCP_RST;

    tcp_fill_rst_header(fr, hdr1, f, hdr);

    if (0) {

    } else if (IS_IPV4(f)) {
        tcp_dbg("Pushing IPv4 reset frame...\n");
        pico_ipv4_frame_push(S, f, &(((struct pico_ipv4_hdr *)(f->net_hdr))->dst), PICO_PROTO_TCP);


    } else {
        pico_ipv6_frame_push(S, f, NULL, &(((struct pico_ipv6_hdr *)(f->net_hdr))->dst), PICO_PROTO_TCP, 0);

    }


    return 0;
}

static int tcp_nosync_rst(struct pico_socket *s, struct pico_frame *fr)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *) s;
    struct pico_frame *f;
    struct pico_tcp_hdr *hdr, *hdr_rcv;
    uint16_t opt_len = tcp_options_size(t, PICO_TCP_RST | PICO_TCP_ACK);
    hdr_rcv = (struct pico_tcp_hdr *) fr->transport_hdr;

    tcp_dbg("TCP SEND RST (NON-SYNC) >>>>>>>>>>>>>>>>>> state %x\n", (s->state & PICO_SOCKET_STATE_TCP));
    if (((s->state & PICO_SOCKET_STATE_TCP) ==  PICO_SOCKET_STATE_TCP_LISTEN)) {
        if ((fr->flags & PICO_TCP_RST) != 0)
            return 0;

        return pico_tcp_reply_rst(s->stack, fr);
    }

    
    
    f = t->sock.net->alloc(t->sock.stack, t->sock.net, NULL, (uint16_t)(PICO_SIZE_TCPHDR + opt_len));

    if (!f) {
        return -1;
    }


    f->sock = &t->sock;
    hdr = (struct pico_tcp_hdr *) f->transport_hdr;
    hdr->len = (uint8_t)((PICO_SIZE_TCPHDR + opt_len) << 2);
    hdr->flags = PICO_TCP_RST | PICO_TCP_ACK;
    hdr->rwnd = short_be(t->wnd);
    tcp_set_space(t);
    tcp_add_options(t, f, PICO_TCP_RST | PICO_TCP_ACK, opt_len);
    hdr->trans.sport = t->sock.local_port;
    hdr->trans.dport = t->sock.remote_port;

    
    if (hdr_rcv->flags & PICO_TCP_ACK) {
        hdr->seq = hdr_rcv->ack;
    } else {
        hdr->seq = 0U;
    }

    hdr->ack = long_be(SEQN(fr) + fr->payload_len);

    t->rcv_ackd = t->rcv_nxt;
    f->start = f->transport_hdr + PICO_SIZE_TCPHDR;
    hdr->rwnd = short_be(t->wnd);
    hdr->crc = 0;
    hdr->crc = short_be(pico_tcp_checksum(f));

    
    pico_enqueue(&t->sock.stack->q_tcp.out, f);

    

    tcp_dbg("TCP SEND_RST (NON_SYNC) >>>>>>>>>>>>>>> DONE, ...\n");

    return 0;
}

static void tcp_deltcb(pico_time when, void *arg);

static void tcp_linger(struct pico_socket_tcp *t)
{
    pico_timer_cancel(t->sock.stack, t->fin_tmr);
    t->fin_tmr = pico_timer_add(t->sock.stack, t->linger_timeout, tcp_deltcb, t);
    if (!t->fin_tmr) {
        tcp_dbg("TCP: failed to start delete callback timer, deleting socket now\n");
        tcp_deltcb((pico_time)0, t);
    }
}

static void tcp_send_fin(struct pico_socket_tcp *t)
{
    struct pico_frame *f;
    struct pico_tcp_hdr *hdr;
    uint16_t opt_len = tcp_options_size(t, PICO_TCP_FIN);
    f = t->sock.net->alloc(t->sock.stack, t->sock.net, NULL, (uint16_t)(PICO_SIZE_TCPHDR + opt_len));
    if (!f) {
        return;
    }

    f->sock = &t->sock;
    hdr = (struct pico_tcp_hdr *) f->transport_hdr;
    hdr->len = (uint8_t)((PICO_SIZE_TCPHDR + opt_len) << 2);
    hdr->flags = PICO_TCP_FIN | PICO_TCP_ACK;
    hdr->ack = long_be(t->rcv_nxt);
    t->rcv_ackd = t->rcv_nxt;
    hdr->rwnd = short_be(t->wnd);
    tcp_set_space(t);
    tcp_add_options(t, f, PICO_TCP_FIN, opt_len);
    hdr->trans.sport = t->sock.local_port;
    hdr->trans.dport = t->sock.remote_port;
    hdr->seq = long_be(t->snd_nxt);

    f->start = f->transport_hdr + PICO_SIZE_TCPHDR;
    hdr->rwnd = short_be(t->wnd);
    hdr->crc = 0;
    hdr->crc = short_be(pico_tcp_checksum(f));
    
    if (t->linger_timeout > 0) {
        pico_enqueue(&t->sock.stack->q_tcp.out, f);
        t->snd_nxt++;
    } else {
        pico_frame_discard(f);
    }

    tcp_linger(t);
}

static void tcp_sack_prepare(struct pico_socket_tcp *t)
{
    struct tcp_input_segment *pkt;
    uint32_t left = 0, right = 0;
    struct tcp_sack_block *sb;
    int n = 0;
    if (t->sacks) 
        return;

    pkt = first_segment(&t->tcpq_in);
    while(n < 3) {
        if (!pkt) {
            if(left) {
                sb = PICO_ZALLOC(sizeof(struct tcp_sack_block));
                if (!sb)
                    break;

                sb->left = long_be(left);
                sb->right = long_be(right);
                n++;
                sb->next = t->sacks;
                t->sacks = sb;
                left = 0;
                right = 0;
            }

            break;
        }

        if (pkt->seq < t->rcv_nxt) {
            pkt = next_segment(&t->tcpq_in, pkt);
            continue;
        }

        if (!left) {
            left = pkt->seq;
            right = pkt->seq + pkt->payload_len;
            pkt = next_segment(&t->tcpq_in, pkt);
            continue;
        }

        if(pkt->seq == right) {
            right += pkt->payload_len;
            pkt = next_segment(&t->tcpq_in, pkt);
            continue;
        } else {
            sb = PICO_ZALLOC(sizeof(struct tcp_sack_block));
            if (!sb)
                break;

            sb->left = long_be(left);
            sb->right = long_be(right);
            n++;
            sb->next = t->sacks;
            t->sacks = sb;
            left = 0;
            right = 0;
            pkt = next_segment(&t->tcpq_in, pkt);
        }
    }
}

void pico_tcp_out_all(struct pico_stack *S, void *arg);
static inline int tcp_data_in_expected(struct pico_socket_tcp *t, struct pico_frame *f)
{
    struct tcp_input_segment *nxt;
    if (pico_seq_compare(SEQN(f), t->rcv_nxt) == 0) { 
        
        struct tcp_input_segment *input = segment_from_frame(f);
        if (!input) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        if(pico_enqueue_segment(&t->tcpq_in, input) <= 0)
        {
            
            PICO_FREE(input->payload);
            PICO_FREE(input);
            return -1;
        } else {
            t->rcv_nxt = SEQN(f) + f->payload_len;
            nxt = peek_segment(&t->tcpq_in, t->rcv_nxt);
            while(nxt) {
                tcp_dbg("scrolling rcv_nxt...%08x\n", t->rcv_nxt);
                t->rcv_nxt += nxt->payload_len;
                nxt = peek_segment(&t->tcpq_in, t->rcv_nxt);
            }
            t->sock.ev_pending |= PICO_SOCK_EV_RD;
            pico_schedule_job(t->sock.stack, pico_tcp_out_all, t);
        }
    } else {
        tcp_dbg("TCP> lo segment. Uninteresting retransmission. (exp: %x got: %x)\n", t->rcv_nxt, SEQN(f));
    }

    return 0;
}

static inline int tcp_data_in_high_segment(struct pico_socket_tcp *t, struct pico_frame *f)
{
    tcp_dbg("TCP> hi segment. Possible packet loss. I'll dupack this. (exp: %x got: %x)\n", t->rcv_nxt, SEQN(f));
    if (t->sack_ok) {
        struct tcp_input_segment *input = segment_from_frame(f);
        if (!input) {
            pico_err = PICO_ERR_ENOMEM;
            return -1;
        }

        if(pico_enqueue_segment(&t->tcpq_in, input) <= 0) {
            
            PICO_FREE(input->payload);
            PICO_FREE(input);
            return -1;
        }

        tcp_sack_prepare(t);
    }

    return 0;
}

static inline void tcp_data_in_send_ack(struct pico_socket_tcp *t, struct pico_frame *f)
{
    struct pico_tcp_hdr *hdr = (struct pico_tcp_hdr *) f->transport_hdr;
    
    if (((t->sock.state & PICO_SOCKET_STATE_TCP) != PICO_SOCKET_STATE_TCP_CLOSE_WAIT) && ((t->sock.state & PICO_SOCKET_STATE_TCP) != PICO_SOCKET_STATE_TCP_SYN_SENT) && ((t->sock.state & PICO_SOCKET_STATE_TCP) != PICO_SOCKET_STATE_TCP_SYN_RECV) && ((hdr->flags & PICO_TCP_RST) == 0))


        tcp_send_ack(t);
}

static int tcp_data_in(struct pico_socket *s, struct pico_frame *f)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    struct pico_tcp_hdr *hdr = (struct pico_tcp_hdr *) f->transport_hdr;
    uint16_t payload_len = (uint16_t)(f->transport_len - ((hdr->len & 0xf0u) >> 2u));
    int ret = 0;
    (void)hdr;

    if (((hdr->len & 0xf0u) >> 2u) <= f->transport_len) {
        if (tcp_parse_options(f) < 0)
            return -1;
        f->payload = f->transport_hdr + ((hdr->len & 0xf0u) >> 2u);
        f->payload_len = payload_len;
        tcp_dbg("TCP> Received segment. (exp: %x got: %x)\n", t->rcv_nxt, SEQN(f));

        if (pico_seq_compare(SEQN(f), t->rcv_nxt) <= 0) {
            ret = tcp_data_in_expected(t, f);
        } else {
            ret = tcp_data_in_high_segment(t, f);
        }

        tcp_data_in_send_ack(t, f);
        return ret;
    } else {
        tcp_dbg("TCP: invalid data in pkt len, exp: %d, got %d\n", (hdr->len & 0xf0) >> 2, f->transport_len);
        return -1;
    }
}

static int tcp_ack_advance_una(struct pico_socket_tcp *t, struct pico_frame *f, pico_time *timestamp)
{
    int ret =  release_all_until(&t->tcpq_out, ACKN(f), timestamp);
    if (ret > 0) {
        t->sock.ev_pending |= PICO_SOCK_EV_WR;
    }
    pico_schedule_job(t->sock.stack, pico_tcp_out_all, t);

    return ret;
}

static uint16_t time_diff(pico_time a, pico_time b)
{
    if (a >= b)
        return (uint16_t)(a - b);
    else return (uint16_t)(b - a);
}

static void tcp_rtt(struct pico_socket_tcp *t, uint32_t rtt)
{

    uint32_t avg = t->avg_rtt;
    uint32_t rvar = t->rttvar;
    if (!avg) {
        
        t->avg_rtt = rtt;
        t->rttvar = rtt >> 1;
        rto_set(t, t->avg_rtt + (t->rttvar << 2));
    } else {
        int32_t var = (int32_t)t->avg_rtt - (int32_t)rtt;
        if (var < 0)
            var = 0 - var;

        

        
        t->rttvar <<= 2;
        t->rttvar -= rvar;
        t->rttvar += (uint32_t)var;
        t->rttvar >>= 2;

        
        t->avg_rtt <<= 3;
        t->avg_rtt -= avg;
        t->avg_rtt += rtt;
        t->avg_rtt >>= 3;

        
        rto_set(t, t->avg_rtt + (t->rttvar << 2));
    }

    tcp_dbg(" -----=============== RTT CUR: %u AVG: %u RTTVAR: %u RTO: %u ======================----\n", rtt, t->avg_rtt, t->rttvar, t->rto);
}

static void tcp_congestion_control(struct pico_socket_tcp *t)
{
    if (t->x_mode > PICO_TCP_LOOKAHEAD)
        return;

    tcp_dbg("Doing congestion control\n");
    if (t->cwnd < t->ssthresh) {
        t->cwnd++;
    } else {
        t->cwnd_counter++;
        if (t->cwnd_counter >= t->cwnd) {
            t->cwnd++;
            t->cwnd_counter = 0;
        }
    }

    tcp_dbg("TCP_CWND, %lu, %u, %u, %u\n", TCP_TIME, t->cwnd, t->ssthresh, t->in_flight);
}

static void add_retransmission_timer(struct pico_socket_tcp *t, pico_time next_ts);




static void tcp_first_timeout(struct pico_socket_tcp *t)
{
    t->x_mode = PICO_TCP_BLACKOUT;
    t->cwnd = PICO_TCP_IW;
    t->in_flight = 0;
}

static int tcp_rto_xmit(struct pico_socket_tcp *t, struct pico_frame *f)
{
    struct pico_frame *cpy;
    
    cpy = pico_frame_copy(f);
    if (!cpy) {
        add_retransmission_timer(t, (t->rto << t->backoff) + TCP_TIME);
        return -1;
    }

    if (pico_enqueue(&t->sock.stack->q_tcp.out, cpy) > 0) {
        t->snd_last_out = SEQN(cpy);
        add_retransmission_timer(t, (t->rto << (++t->backoff)) + TCP_TIME);
        tcp_dbg("TCP_CWND, %lu, %u, %u, %u\n", TCP_TIME, t->cwnd, t->ssthresh, t->in_flight);
        tcp_dbg("Sending RTO!\n");
        return 1;
    } else {
        tcp_dbg("RTO fail, retry!\n");
        add_retransmission_timer(t, (t->rto << t->backoff) + TCP_TIME);
        pico_frame_discard(cpy);
        return 0;
    }
}

static void tcp_next_zerowindow_probe(struct pico_socket_tcp *t)
{
    tcp_dbg("Sending probe!\n");
    tcp_send_probe(t);
    add_retransmission_timer(t, (t->rto << ++t->backoff) + TCP_TIME);
}

static int tcp_is_allowed_to_send(struct pico_socket_tcp *t)
{
    return t->sock.net && ( ((t->sock.state & 0xFF00) == PICO_SOCKET_STATE_TCP_ESTABLISHED) || ((t->sock.state & 0xFF00) == PICO_SOCKET_STATE_TCP_CLOSE_WAIT)


           ) && ((t->backoff < PICO_TCP_MAX_RETRANS));
}

static inline int tcp_retrans_timeout_check_queue(struct pico_socket_tcp *t)
{
    struct pico_frame *f = NULL;
    f = first_segment(&t->tcpq_out);
    while (f) {
        tcp_dbg("Checking frame in queue \n");
        if (t->x_mode == PICO_TCP_WINDOW_FULL) {
            tcp_dbg("TCP BLACKOUT> TIMED OUT (output) frame %08x, len= %d rto=%d Win full: %d frame flags: %04x\n", SEQN(f), f->payload_len, t->rto, t->x_mode == PICO_TCP_WINDOW_FULL, f->flags);
            tcp_next_zerowindow_probe(t);
            return -1;
        }

        if (t->x_mode != PICO_TCP_BLACKOUT)
            tcp_first_timeout(t);

        tcp_add_header(t, f);
        if (tcp_rto_xmit(t, f) > 0) 
            return -1;

        f = next_segment(&t->tcpq_out, f);
    }
    if (t->tcpq_out.size < t->tcpq_out.max_size)
        t->sock.ev_pending |= PICO_SOCK_EV_WR;
    pico_schedule_job(t->sock.stack, pico_tcp_out_all, t);

    return 0;



}

static void tcp_retrans_timeout(pico_time val, void *sock)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *) sock;

    t->retrans_tmr = 0;

    if (t->retrans_tmr_due == 0ull) {
        return;
    }

    if (t->retrans_tmr_due > val) {
        
        add_retransmission_timer(t, t->retrans_tmr_due);
        return;
    }

    pico_schedule_job(t->sock.stack, pico_tcp_out_all, t);

    tcp_dbg("TIMEOUT! backoff = %d, rto: %d\n", t->backoff, t->rto);
    t->retrans_tmr_due = 0ull;

    if (tcp_is_allowed_to_send(t)) {
        if (tcp_retrans_timeout_check_queue(t) < 0)
            return;
    }
    else if(t->backoff >= PICO_TCP_MAX_RETRANS && ((t->sock.state & PICO_SOCKET_STATE_TCP) == PICO_SOCKET_STATE_TCP_ESTABLISHED || (t->sock.state & PICO_SOCKET_STATE_TCP) == PICO_SOCKET_STATE_TCP_FIN_WAIT1 || (t->sock.state & PICO_SOCKET_STATE_TCP) == PICO_SOCKET_STATE_TCP_FIN_WAIT2 || (t->sock.state & PICO_SOCKET_STATE_TCP) == PICO_SOCKET_STATE_TCP_TIME_WAIT || (t->sock.state & PICO_SOCKET_STATE_TCP) == PICO_SOCKET_STATE_TCP_CLOSE_WAIT || (t->sock.state & PICO_SOCKET_STATE_TCP) == PICO_SOCKET_STATE_TCP_LAST_ACK || (t->sock.state & PICO_SOCKET_STATE_TCP) == PICO_SOCKET_STATE_TCP_CLOSING))






    {
        tcp_dbg("Connection timeout!\n");
        
        tcp_discard_all_segments(&t->tcpq_out);
        if(t->sock.wakeup)
            t->sock.wakeup(PICO_SOCK_EV_FIN, &t->sock);

        
        pico_socket_del(&t->sock);
        return;
    } else {
        tcp_dbg("Retransmission not allowed, rescheduling\n");
    }
}

static void add_retransmission_timer(struct pico_socket_tcp *t, pico_time next_ts)
{
    struct pico_tree_node *index;
    pico_time now = TCP_TIME;
    pico_time val = 0;


    if (next_ts == 0) {
        struct pico_frame *f;

        pico_tree_foreach(index, &t->tcpq_out.pool){
            f = index->keyValue;
            if ((next_ts == 0) || ((f->timestamp < next_ts) && (f->timestamp > 0))) {
                next_ts = f->timestamp;
                val = next_ts + (t->rto << t->backoff);
            }
        }
    } else {
        val = next_ts;
    }

    if ((val > 0) || (val > now)) {
        t->retrans_tmr_due = val;
    } else {
        t->retrans_tmr_due = now + 1;
    }

    if (!t->retrans_tmr) {
        t->retrans_tmr = pico_timer_add(t->sock.stack, t->retrans_tmr_due - now, tcp_retrans_timeout, t);
        if(!t->retrans_tmr) {
            tcp_dbg("TCP: Failed to start retransmission timer\n");
            
        } else {
            tcp_dbg("Next timeout in %u msec\n", (uint32_t) (t->retrans_tmr_due - now));
        }
    }
}

static int tcp_retrans(struct pico_socket_tcp *t, struct pico_frame *f)
{
    struct pico_frame *cpy;
    if (f) {
        tcp_dbg("TCP> RETRANS (by dupack) frame %08x, len= %d\n", SEQN(f), f->payload_len);
        tcp_add_header(t, f);
        
        cpy = pico_frame_copy(f);
        if (!cpy) {
            return -1;
        }

        if (pico_enqueue(&t->sock.stack->q_tcp.out, cpy) > 0) {
            t->in_flight++;
            t->snd_last_out = SEQN(cpy);
        } else {
            pico_frame_discard(cpy);
        }

        add_retransmission_timer(t, TCP_TIME + t->rto);
        return(f->payload_len);
    }

    return 0;
}


static void tcp_ack_dbg(struct pico_socket *s, struct pico_frame *f)
{
    uint32_t una, nxt, ack, cur;
    struct pico_frame *una_f = NULL, *cur_f;
    struct pico_tree_node *idx;
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    char info[64];
    char tmp[64];
    ack = ACKN(f);
    nxt = t->snd_nxt;
    tcp_dbg("===================================\n");
    tcp_dbg("Queue out (%d/%d). ACKED=%08x\n", t->tcpq_out.size, t->tcpq_out.max_size, ack);

    pico_tree_foreach(idx, &t->tcpq_out.pool) {
        info[0] = 0;
        cur_f = idx->keyValue;
        cur = SEQN(cur_f);
        if (!una_f) {
            una_f = cur_f;
            una = SEQN(una_f);
        }

        if (cur == nxt) {
            strncpy(tmp, info, strlen(info));
            snprintf(info, 64, "%s SND_NXT", tmp);
        }

        if (cur == ack) {
            strncpy(tmp, info, strlen(info));
            snprintf(info, 64, "%s ACK", tmp);
        }

        if (cur == una) {
            strncpy(tmp, info, strlen(info));
            snprintf(info, 64, "%s SND_UNA", tmp);
        }

        if (cur == t->snd_last) {
            strncpy(tmp, info, strlen(info));
            snprintf(info, 64, "%s SND_LAST", tmp);
        }

        tcp_dbg("%08x %d%s\n", cur, cur_f->payload_len, info);

    }
    tcp_dbg("SND_NXT is %08x, snd_LAST is %08x\n", nxt, t->snd_last);
    tcp_dbg("===================================\n");
    tcp_dbg("\n\n");
}


static int tcp_ack(struct pico_socket *s, struct pico_frame *f)
{
    struct pico_frame *f_new;              
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    struct pico_tcp_hdr *hdr;
    uint32_t rtt = 0;
    uint16_t acked = 0;
    pico_time acked_timestamp = 0;
    struct pico_frame *una = NULL;

    if (!f || !s) {
        pico_err = PICO_ERR_EINVAL;
        return -1;
    }

    hdr = (struct pico_tcp_hdr *) f->transport_hdr;

    if ((hdr->flags & PICO_TCP_ACK) == 0)
        return -1;


    tcp_ack_dbg(s, f);


    if (tcp_parse_options(f) < 0)
        return -1;
    t->recv_wnd = short_be(hdr->rwnd);

    acked = (uint16_t)tcp_ack_advance_una(t, f, &acked_timestamp);
    una = first_segment(&t->tcpq_out);
    t->ack_timestamp = TCP_TIME;

    if ((t->x_mode == PICO_TCP_BLACKOUT) || ((t->x_mode == PICO_TCP_WINDOW_FULL) && ((t->recv_wnd << t->recv_wnd_scale) > t->mss))) {
        int prev_mode = t->x_mode;
        tcp_dbg("Re-entering look-ahead...\n\n\n");
        t->x_mode = PICO_TCP_LOOKAHEAD;
        t->backoff = 0;

        if((prev_mode == PICO_TCP_BLACKOUT) && (acked > 0) && una)
        {
            t->snd_nxt = SEQN(una);
            
            if (t->retrans_tmr) {
                t->retrans_tmr_due = 0ull;
            }
        }
    }

    
    if ((acked == 0) && (f->payload_len  == 0) && (t->in_flight > 0))
        t->in_flight--;

    if (!una || acked > 0) {
        t->x_mode = PICO_TCP_LOOKAHEAD;
        tcp_dbg("Mode: Look-ahead. In flight: %d/%d buf: %d\n", t->in_flight, t->cwnd, t->tcpq_out.frames);
        t->backoff = 0;

        
        
        if(f->timestamp != 0) {
            rtt = time_diff(TCP_TIME, f->timestamp);
            if (rtt)
                tcp_rtt(t, rtt);
        } else if(acked_timestamp) {
            
            rtt = time_diff(TCP_TIME, acked_timestamp);
            if (rtt)
                tcp_rtt(t, rtt);
        }

        tcp_dbg("TCP ACK> FRESH ACK %08x (acked %d) Queue size: %u/%u frames: %u cwnd: %u in_flight: %u snd_una: %u\n", ACKN(f), acked, t->tcpq_out.size, t->tcpq_out.max_size, t->tcpq_out.frames, t->cwnd, t->in_flight, SEQN(una));
        if (acked > t->in_flight) {
            tcp_dbg("WARNING: in flight < 0\n");
            t->in_flight = 0;
        } else t->in_flight -= (acked);

    } else if ((t->snd_old_ack == ACKN(f)) &&               ((0 == (hdr->flags & (PICO_TCP_PSH | PICO_TCP_SYN))) && (f->payload_len == 0)) && (ACKN(f) != t->snd_nxt))


    {
        
        if (t->x_mode < PICO_TCP_RECOVER) {
            t->x_mode++;
            tcp_dbg("Mode: DUPACK %d, due to PURE ACK %0x, len = %d\n", t->x_mode, SEQN(f), f->payload_len);
            
            if (t->x_mode == PICO_TCP_RECOVER) {              
                if (t->in_flight > PICO_TCP_IW)
                    t->cwnd = (uint16_t)t->in_flight;
                else t->cwnd = PICO_TCP_IW;

                t->snd_retry = SEQN((struct pico_frame *)first_segment(&t->tcpq_out));
                if (t->ssthresh > t->cwnd)
                    t->ssthresh >>= 2;
                else t->ssthresh = (t->cwnd >> 1);

                if (t->ssthresh < 2)
                    t->ssthresh = 2;
            }
        } else if (t->x_mode == PICO_TCP_RECOVER) {
            
            if (t->in_flight <= t->cwnd) {
                struct pico_frame *nxt = peek_segment(&t->tcpq_out, t->snd_retry);
                if (!nxt)
                    nxt = first_segment(&t->tcpq_out);

                while (nxt && (nxt->flags & PICO_FRAME_FLAG_SACKED) && (nxt != first_segment(&t->tcpq_out))) {
                    tcp_dbg("Skipping %08x because it is sacked.\n", SEQN(nxt));
                    nxt = next_segment(&t->tcpq_out, nxt);
                }
                if (nxt && (pico_seq_compare(SEQN(nxt), t->snd_nxt)) > 0)
                    nxt = NULL;

                if (nxt && (pico_seq_compare(SEQN(nxt), SEQN((struct pico_frame *)first_segment(&t->tcpq_out))) > (int)(t->recv_wnd << t->recv_wnd_scale)))
                    nxt = NULL;

                if(!nxt)
                    nxt = first_segment(&t->tcpq_out);

                if (nxt) {
                    tcp_retrans(t, peek_segment(&t->tcpq_out, t->snd_retry));
                    t->snd_retry = SEQN(nxt);
                }
            }

            if (++t->cwnd_counter > 1) {
                t->cwnd--;
                if (t->cwnd < 2)
                    t->cwnd = 2;

                t->cwnd_counter = 0;
            }
        } else {
            tcp_dbg("DUPACK in mode %d \n", t->x_mode);

        }
    }              

    
    if ((0 == (hdr->flags & (PICO_TCP_PSH | PICO_TCP_SYN))) &&  (ACKN(f) == t->snd_nxt) && (pico_seq_compare(SEQN(f), t->rcv_nxt) < 0))

    {
        tcp_send_ack(t);
    }


    
    tcp_congestion_control(t);
    if ((acked > 0) && t->sock.wakeup) {
        if (t->tcpq_out.size < t->tcpq_out.max_size)
            t->sock.wakeup(PICO_SOCK_EV_WR, &(t->sock));

        
        pico_schedule_job(t->sock.stack, pico_tcp_out_all, t);
    }

    
    if (IS_NAGLE_ENABLED((&(t->sock)))) {
        while (!IS_TCP_HOLDQ_EMPTY(t) && ((t->tcpq_out.max_size - t->tcpq_out.size) >= t->mss)) {
            tcp_dbg_nagle("TCP_ACK - NAGLE add new segment\n");
            f_new = pico_hold_segment_make(t);
            if (f_new == NULL)
                break;              

            if (pico_enqueue_segment(&t->tcpq_out, f_new) <= 0)
                
                tcp_dbg_nagle("TCP_ACK - NAGLE FAILED to enqueue in out\n");
        }
    }

    
    tcp_dbg("TCP_CWND, %lu, %u, %u, %u\n", TCP_TIME, t->cwnd, t->ssthresh, t->in_flight);
    if (t->x_mode ==  PICO_TCP_LOOKAHEAD) {
        if ((t->cwnd >= t->in_flight) && (t->snd_nxt > t->snd_last_out)) {
            pico_tcp_output(&t->sock, (int)t->cwnd - (int)t->in_flight);
        }
    }

    add_retransmission_timer(t, 0);
    t->snd_old_ack = ACKN(f);
    return 0;
}

static int tcp_finwaitack(struct pico_socket *s, struct pico_frame *f)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    tcp_dbg("RECEIVED ACK IN FIN_WAIT1\n");

    
    tcp_ack(s, f);


    tcp_dbg("FIN_WAIT1: ack is %08x - snd_nxt is %08x\n", ACKN(f), t->snd_nxt);
    if (ACKN(f) == (t->snd_nxt - 1u)) {
        
        s->state &= 0x00FFU;
        s->state |= PICO_SOCKET_STATE_TCP_FIN_WAIT2;
        tcp_dbg("TCP> IN STATE FIN_WAIT2\n");
    }

    return 0;
}

static void tcp_deltcb(pico_time when, void *arg)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)arg;
    IGNORE_PARAMETER(when);

    
    if ((((t->sock).state & PICO_SOCKET_STATE_TCP) != PICO_SOCKET_STATE_TCP_TIME_WAIT)
        && (((t->sock).state & PICO_SOCKET_STATE_TCP) != PICO_SOCKET_STATE_TCP_CLOSING)) {
        tcp_dbg("Called deltcb in state = %04x (sending reset!)\n", (t->sock).state);
        tcp_do_send_rst(&t->sock, long_be(t->snd_nxt));
    } else {
        tcp_dbg("Called deltcb in state = %04x\n", (t->sock).state);
    }

    
    (t->sock).state &= 0x00FFU;
    (t->sock).state |= PICO_SOCKET_STATE_TCP_CLOSED;
    (t->sock).state &= 0xFF00U;
    (t->sock).state |= PICO_SOCKET_STATE_CLOSED;
    
    if (t->sock.wakeup) {
        (t->sock).wakeup(PICO_SOCK_EV_FIN, &(t->sock));
    }

    
    pico_socket_del(&t->sock);
}

static int tcp_finwaitfin(struct pico_socket *s, struct pico_frame *f)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    struct pico_tcp_hdr *hdr  = (struct pico_tcp_hdr *) (f->transport_hdr);
    tcp_dbg("TCP> received fin in FIN_WAIT2\n");
    
    t->rcv_nxt = long_be(hdr->seq) + 1;
    s->state &= 0x00FFU;
    s->state |= PICO_SOCKET_STATE_TCP_TIME_WAIT;
    
    s->state |= PICO_SOCKET_STATE_SHUT_REMOTE;
    if (s->wakeup)
        s->wakeup(PICO_SOCK_EV_CLOSE, s);

    if (f->payload_len > 0)              
        tcp_data_in(s, f);

    
    tcp_send_ack(t);
    
    tcp_linger(t);
    return 0;
}

static int tcp_closing_ack(struct pico_socket *s, struct pico_frame *f)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    tcp_dbg("TCP> received ack in CLOSING\n");
    
    tcp_ack(s, f);

    
    tcp_dbg("CLOSING: ack is %08x - snd_nxt is %08x\n", ACKN(f), t->snd_nxt);
    if (ACKN(f) == t->snd_nxt) {
        s->state &= 0x00FFU;
        s->state |= PICO_SOCKET_STATE_TCP_TIME_WAIT;
        
        tcp_linger(t);
    }

    return 0;
}

static int tcp_lastackwait(struct pico_socket *s, struct pico_frame *f)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    tcp_dbg("LAST_ACK: ack is %08x - snd_nxt is %08x\n", ACKN(f), t->snd_nxt);
    if (ACKN(f) == t->snd_nxt) {
        s->state &= 0x00FFU;
        s->state |= PICO_SOCKET_STATE_TCP_CLOSED;
        s->state &= 0xFF00U;
        s->state |= PICO_SOCKET_STATE_CLOSED;
        
        if (s->wakeup)
            s->wakeup(PICO_SOCK_EV_FIN, s);

        
        pico_socket_del(s);
    }

    return 0;
}

static int tcp_syn(struct pico_socket *s, struct pico_frame *f)
{
    struct pico_socket_tcp *new = NULL;
    struct pico_tcp_hdr *hdr = NULL;
    uint16_t mtu;
    if(s->number_of_pending_conn >= s->max_backlog)
        return -1;

    new = (struct pico_socket_tcp *)pico_socket_clone(s);
    hdr = (struct pico_tcp_hdr *)f->transport_hdr;
    if (!new)
        return -1;


    if (!pico_timer_add(t->sock.stack, 2000, sock_stats, s)) {
        tcp_dbg("TCP: Failed to start socket statistics timer\n");
        return -1;
    }


    new->sock.remote_port = ((struct pico_trans *)f->transport_hdr)->sport;

    if (IS_IPV4(f)) {
        new->sock.remote_addr.ip4.addr = ((struct pico_ipv4_hdr *)(f->net_hdr))->src.addr;
        new->sock.local_addr.ip4.addr = ((struct pico_ipv4_hdr *)(f->net_hdr))->dst.addr;
    }



    if (IS_IPV6(f)) {
        new->sock.remote_addr.ip6 = ((struct pico_ipv6_hdr *)(f->net_hdr))->src;
        new->sock.local_addr.ip6 = ((struct pico_ipv6_hdr *)(f->net_hdr))->dst;
    }


    f->sock = &new->sock;
    mtu = (uint16_t)pico_socket_get_mss(&new->sock);
    new->mss = (uint16_t)(mtu - PICO_SIZE_TCPHDR);
    if (tcp_parse_options(f) < 0)
        return -1;
    new->sock.stack = s->stack;
    new->tcpq_in.max_size = PICO_DEFAULT_SOCKETQ;
    new->tcpq_out.max_size = PICO_DEFAULT_SOCKETQ;
    new->tcpq_hold.max_size = 2u * mtu;
    new->rcv_nxt = long_be(hdr->seq) + 1;
    new->snd_nxt = long_be(pico_paws());
    new->snd_last = new->snd_nxt;
    new->cwnd = PICO_TCP_IW;
    new->ssthresh = (uint16_t)((uint16_t)(PICO_DEFAULT_SOCKETQ / new->mss) -  (((uint16_t)(PICO_DEFAULT_SOCKETQ / new->mss)) >> 3u));
    new->recv_wnd = short_be(hdr->rwnd);
    new->linger_timeout = PICO_SOCKET_LINGER_TIMEOUT;
    s->number_of_pending_conn++;
    new->sock.parent = s;
    new->sock.wakeup = s->wakeup;
    rto_set(new, PICO_TCP_RTO_MIN);
    
    new->sock.state = PICO_SOCKET_STATE_BOUND | PICO_SOCKET_STATE_CONNECTED | PICO_SOCKET_STATE_TCP_SYN_RECV;
    pico_socket_add(&new->sock);
    tcp_send_synack(&new->sock);
    tcp_dbg("SYNACK sent, socket added. snd_nxt is %08x\n", new->snd_nxt);
    return 0;
}

static int tcp_synrecv_syn(struct pico_socket *s, struct pico_frame *f)
{
    struct pico_tcp_hdr *hdr = NULL;
    struct pico_socket_tcp *t = TCP_SOCK(s);
    hdr = (struct pico_tcp_hdr *)f->transport_hdr;
    if (t->rcv_nxt == long_be(hdr->seq) + 1u) {
        
        t->snd_nxt--;
        tcp_send_synack(s);
    } else {
        tcp_send_rst(s, f);
        return -1;
    }

    return 0;
}

static void tcp_set_init_point(struct pico_socket *s)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    t->rcv_processed = t->rcv_nxt;
}


uint16_t pico_tcp_get_socket_mss(struct pico_socket *s)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *) s;
    if (t->mss > 0)
        return (uint16_t)(t->mss + PICO_SIZE_TCPHDR);
    else return (uint16_t)pico_socket_get_mss(s);
}

static int tcp_synack(struct pico_socket *s, struct pico_frame *f)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *) s;
    struct pico_tcp_hdr *hdr  = (struct pico_tcp_hdr *)f->transport_hdr;

    if (ACKN(f) ==  (1u + t->snd_nxt)) {
        
        pico_timer_cancel(t->sock.stack, t->retrans_tmr);
        t->retrans_tmr = 0;

        t->rcv_nxt = long_be(hdr->seq);
        t->rcv_processed = t->rcv_nxt + 1;
        tcp_ack(s, f);

        s->state &= 0x00FFU;
        s->state |= PICO_SOCKET_STATE_TCP_ESTABLISHED;
        tcp_dbg("TCP> Established. State: %x\n", s->state);

        if (s->wakeup)
            s->wakeup(PICO_SOCK_EV_CONN, s);

        s->ev_pending |= PICO_SOCK_EV_WR;
        pico_schedule_job(t->sock.stack, pico_tcp_out_all, t);

        t->rcv_nxt++;
        t->snd_nxt++;
        tcp_send_ack(t);              

        return 0;

    } else if ((hdr->flags & PICO_TCP_RST) == 0) {
        tcp_dbg("TCP> Not established, RST sent.\n");
        tcp_nosync_rst(s, f);
        return 0;
    } else {
        
        return 0;
    }
}

static int tcp_first_ack(struct pico_socket *s, struct pico_frame *f)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    struct pico_tcp_hdr *hdr  = (struct pico_tcp_hdr *)f->transport_hdr;
    tcp_dbg("ACK in SYN_RECV: expecting %08x got %08x\n", t->snd_nxt, ACKN(f));
    if (t->snd_nxt == ACKN(f)) {
        tcp_set_init_point(s);
        tcp_ack(s, f);
        s->state &= 0x00FFU;
        s->state |= PICO_SOCKET_STATE_TCP_ESTABLISHED;
        tcp_dbg("TCP: Established. State now: %04x\n", s->state);
        if( !s->parent && s->wakeup) {              
            tcp_dbg("FIRST ACK - No parent found -> sending socket\n");
            s->wakeup(PICO_SOCK_EV_CONN,  s);
        }

        if (s->parent && s->parent->wakeup) {
            tcp_dbg("FIRST ACK - Parent found -> listening socket\n");
            s->wakeup = s->parent->wakeup;
            s->parent->wakeup(PICO_SOCK_EV_CONN, s->parent);
        }

        s->ev_pending |= PICO_SOCK_EV_WR;
        pico_schedule_job(t->sock.stack, pico_tcp_out_all, t);
        tcp_dbg("%s: snd_nxt is now %08x\n", __FUNCTION__, t->snd_nxt);
        return 0;
    } else if ((hdr->flags & PICO_TCP_RST) == 0) {
        tcp_nosync_rst(s, f);
        return 0;
    } else {
        
        return 0;
    }
}

static void tcp_attempt_closewait(struct pico_socket *s, struct pico_frame *f)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    struct pico_tcp_hdr *hdr  = (struct pico_tcp_hdr *) (f->transport_hdr);
    if (pico_seq_compare(SEQN(f), t->rcv_nxt) == 0) {
        
        t->rcv_nxt = long_be(hdr->seq) + 1;
        if (pico_seq_compare(SEQN(f), t->rcv_processed) == 0) {
            if ((s->state & PICO_SOCKET_STATE_TCP) == PICO_SOCKET_STATE_TCP_ESTABLISHED) {
                tcp_dbg("Changing state to CLOSE_WAIT\n");
                s->state &= 0x00FFU;
                s->state |= PICO_SOCKET_STATE_TCP_CLOSE_WAIT;
            }

            
            s->state |= PICO_SOCKET_STATE_SHUT_REMOTE;
            tcp_dbg("TCP> Close-wait\n");
            if (s->wakeup) {
                s->wakeup(PICO_SOCK_EV_CLOSE, s);
            }
        } else {
            t->remote_closed = 1;
        }
    }


}

static int tcp_closewait(struct pico_socket *s, struct pico_frame *f)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    struct pico_tcp_hdr *hdr = (struct pico_tcp_hdr *) (f->transport_hdr);

    if (f->payload_len > 0)
        tcp_data_in(s, f);

    if (hdr->flags & PICO_TCP_ACK)
        tcp_ack(s, f);

    tcp_dbg("called close_wait (%p), in state %08x, f->flags: 0x%02x, hdr->flags: 0x%02x\n", tcp_closewait, s->state, f->flags, hdr->flags);
    tcp_attempt_closewait(s, f);

    
    if (((s->state & PICO_SOCKET_STATE_TCP) == PICO_SOCKET_STATE_TCP_CLOSE_WAIT) || ((s->state & PICO_SOCKET_STATE_TCP) == PICO_SOCKET_STATE_TCP_ESTABLISHED))
    {
        tcp_dbg("In closewait: Sending ack! (state is %08x)\n", s->state);
        tcp_send_ack(t);
    }

    return 0;
}

static int tcp_rcvfin(struct pico_socket *s, struct pico_frame *f)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    IGNORE_PARAMETER(f);
    tcp_dbg("TCP> Received FIN in FIN_WAIT1\n");
    s->state &= 0x00FFU;
    s->state |= PICO_SOCKET_STATE_TCP_CLOSING;
    t->rcv_processed = t->rcv_nxt + 1;
    t->rcv_nxt++;
    
    tcp_send_ack(t);
    return 0;
}

static int tcp_finack(struct pico_socket *s, struct pico_frame *f)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    IGNORE_PARAMETER(f);

    tcp_dbg("TCP> ENTERED finack\n");
    t->rcv_nxt++;
    
    tcp_send_ack(t);

    
    if (s->wakeup)
        s->wakeup(PICO_SOCK_EV_FIN, s);

    s->state &= 0x00FFU;
    s->state |= PICO_SOCKET_STATE_TCP_TIME_WAIT;
    
    s->state |= PICO_SOCKET_STATE_SHUT_REMOTE;

    tcp_linger(t);

    return 0;
}

static void tcp_force_closed(struct pico_socket *s)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *) s;
    
    (t->sock).state &= 0x00FFU;
    (t->sock).state |= PICO_SOCKET_STATE_TCP_CLOSED;
    (t->sock).state &= 0xFF00U;
    (t->sock).state |= PICO_SOCKET_STATE_CLOSED;
    
    if (((s->state & PICO_SOCKET_STATE_TCP) == PICO_SOCKET_STATE_TCP_ESTABLISHED)) {
        if ((t->sock).wakeup)
            (t->sock).wakeup(PICO_SOCK_EV_FIN, &(t->sock));
    } else {
        pico_err = PICO_ERR_ECONNRESET;
        if ((t->sock).wakeup)
            (t->sock).wakeup(PICO_SOCK_EV_FIN, &(t->sock));

        
        pico_socket_del(&t->sock);
    }
}

static void tcp_wakeup_pending(struct pico_socket *s, uint16_t ev)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *) s;
    if ((t->sock).wakeup)
        (t->sock).wakeup(ev, &(t->sock));
}

static int tcp_rst(struct pico_socket *s, struct pico_frame *f)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *) s;
    struct pico_tcp_hdr *hdr = (struct pico_tcp_hdr *) (f->transport_hdr);

    tcp_dbg("TCP >>>>>>>>>>>>>> received RST <<<<<<<<<<<<<<<<<<<<\n");
    if ((s->state & PICO_SOCKET_STATE_TCP) == PICO_SOCKET_STATE_TCP_SYN_SENT) {
        
        if ((t->snd_nxt + 1u) == ACKN(f)) {              
            tcp_force_closed(s);
        } else {                  
            tcp_dbg("TCP RST> IGNORE\n");
            return 0;
        }
    } else {              
        
        uint32_t this_seq = long_be(hdr->seq);
        if ((this_seq >= t->rcv_ackd) && (this_seq <= ((uint32_t)(short_be(hdr->rwnd) << (t->wnd_scale)) + t->rcv_ackd))) {
            tcp_force_closed(s);
        } else {                  
            tcp_dbg("TCP RST> IGNORE\n");
            return 0;
        }
    }

    return 0;
}
static int tcp_halfopencon(struct pico_socket *s, struct pico_frame *fr)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *) s;
    IGNORE_PARAMETER(fr);
    tcp_send_ack(t);
    return 0;
}

static int tcp_closeconn(struct pico_socket *s, struct pico_frame *fr)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *) s;
    struct pico_tcp_hdr *hdr  = (struct pico_tcp_hdr *) (fr->transport_hdr);

    pico_schedule_job(t->sock.stack, pico_tcp_out_all, t);
    if (pico_seq_compare(SEQN(fr), t->rcv_nxt) == 0) {
        
        t->rcv_nxt = long_be(hdr->seq) + 1;
        s->state &= 0x00FFU;
        s->state |= PICO_SOCKET_STATE_TCP_CLOSE_WAIT;
        
        s->state |= PICO_SOCKET_STATE_SHUT_LOCAL;
        pico_socket_close(s);
        return 1;
    }

    return 0;
}

struct tcp_action_entry {
    uint16_t tcpstate;
    int (*syn)(struct pico_socket *s, struct pico_frame *f);
    int (*synack)(struct pico_socket *s, struct pico_frame *f);
    int (*ack)(struct pico_socket *s, struct pico_frame *f);
    int (*data)(struct pico_socket *s, struct pico_frame *f);
    int (*fin)(struct pico_socket *s, struct pico_frame *f);
    int (*finack)(struct pico_socket *s, struct pico_frame *f);
    int (*rst)(struct pico_socket *s, struct pico_frame *f);
};

static const struct tcp_action_entry tcp_fsm[] = {
    
    { PICO_SOCKET_STATE_TCP_UNDEF,        NULL,            NULL,              NULL,              NULL,            NULL,            NULL,            NULL     }, { PICO_SOCKET_STATE_TCP_CLOSED,       NULL,            NULL,              NULL,              NULL,            NULL,            NULL,            NULL     }, { PICO_SOCKET_STATE_TCP_LISTEN,       &tcp_syn,        NULL,              NULL,              NULL,            NULL,            NULL,            NULL     }, { PICO_SOCKET_STATE_TCP_SYN_SENT,     NULL,            &tcp_synack,       NULL,              NULL,            NULL,            NULL,            &tcp_rst }, { PICO_SOCKET_STATE_TCP_SYN_RECV,     &tcp_synrecv_syn, NULL,              &tcp_first_ack,    &tcp_data_in,    NULL,            &tcp_closeconn,  &tcp_rst }, { PICO_SOCKET_STATE_TCP_ESTABLISHED,  &tcp_halfopencon, &tcp_ack,         &tcp_ack,          &tcp_data_in,    &tcp_closewait,  &tcp_closewait,  &tcp_rst }, { PICO_SOCKET_STATE_TCP_CLOSE_WAIT,   NULL,            &tcp_ack,          &tcp_ack,          &tcp_send_rst,   &tcp_closewait,  &tcp_closewait,  &tcp_rst }, { PICO_SOCKET_STATE_TCP_LAST_ACK,     NULL,            &tcp_ack,          &tcp_lastackwait,  &tcp_send_rst,   &tcp_send_rst,   &tcp_send_rst,   &tcp_rst }, { PICO_SOCKET_STATE_TCP_FIN_WAIT1,    NULL,            &tcp_ack,          &tcp_finwaitack,   &tcp_data_in,    &tcp_rcvfin,     &tcp_finack,     &tcp_rst }, { PICO_SOCKET_STATE_TCP_FIN_WAIT2,    NULL,            &tcp_ack,          &tcp_ack,          &tcp_data_in,    &tcp_finwaitfin, &tcp_finack,     &tcp_rst }, { PICO_SOCKET_STATE_TCP_CLOSING,      NULL,            &tcp_ack,          &tcp_closing_ack, &tcp_send_rst,   &tcp_send_rst,   &tcp_send_rst,   &tcp_rst }, { PICO_SOCKET_STATE_TCP_TIME_WAIT,    NULL,            NULL,          NULL,     &tcp_send_rst,   NULL, NULL, NULL}










};


static uint8_t invalid_flags(struct pico_socket *s, uint8_t flags)
{
    uint8_t i;
    static const uint8_t valid_flags[PICO_SOCKET_STATE_TCP_ARRAYSIZ][MAX_VALID_FLAGS] = {
        {  0, }, {  0, }, {  PICO_TCP_SYN }, {  PICO_TCP_SYNACK, PICO_TCP_RST, PICO_TCP_RSTACK}, {  PICO_TCP_SYN, PICO_TCP_ACK, PICO_TCP_PSH, PICO_TCP_PSHACK, PICO_TCP_FINACK, PICO_TCP_FINPSHACK, PICO_TCP_RST}, {  PICO_TCP_SYN, PICO_TCP_SYNACK, PICO_TCP_ACK, PICO_TCP_PSH, PICO_TCP_PSHACK, PICO_TCP_FIN, PICO_TCP_FINACK, PICO_TCP_FINPSHACK, PICO_TCP_RST, PICO_TCP_RSTACK}, {  PICO_TCP_SYNACK, PICO_TCP_ACK, PICO_TCP_PSH, PICO_TCP_PSHACK, PICO_TCP_FIN, PICO_TCP_FINACK, PICO_TCP_FINPSHACK, PICO_TCP_RST}, {  PICO_TCP_SYNACK, PICO_TCP_ACK, PICO_TCP_PSH, PICO_TCP_PSHACK, PICO_TCP_FIN, PICO_TCP_FINACK, PICO_TCP_FINPSHACK, PICO_TCP_RST}, {  PICO_TCP_SYNACK, PICO_TCP_ACK, PICO_TCP_PSH, PICO_TCP_PSHACK, PICO_TCP_FIN, PICO_TCP_FINACK, PICO_TCP_FINPSHACK, PICO_TCP_RST}, {  PICO_TCP_SYNACK, PICO_TCP_ACK, PICO_TCP_PSH, PICO_TCP_PSHACK, PICO_TCP_FIN, PICO_TCP_FINACK, PICO_TCP_FINPSHACK, PICO_TCP_RST}, {  PICO_TCP_SYNACK, PICO_TCP_ACK, PICO_TCP_PSH, PICO_TCP_PSHACK, PICO_TCP_FIN, PICO_TCP_FINACK, PICO_TCP_FINPSHACK, PICO_TCP_RST}, {  PICO_TCP_SYNACK, PICO_TCP_ACK, PICO_TCP_PSH, PICO_TCP_PSHACK, PICO_TCP_FIN, PICO_TCP_FINACK, PICO_TCP_FINPSHACK, PICO_TCP_RST}, };











    if(!flags)
        return 1;

    for(i = 0; i < MAX_VALID_FLAGS; i++) {
        if(valid_flags[s->state >> 8u][i] == flags)
            return 0;
    }
    return 1;
}

static void tcp_action_call(int (*call)(struct pico_socket *s, struct pico_frame *f), struct pico_socket *s, struct pico_frame *f )
{
    if (call)
        call(s, f);
}

static int tcp_action_by_flags(const struct tcp_action_entry *action, struct pico_socket *s, struct pico_frame *f, uint8_t flags)
{
    int ret = 0;

    if ((flags == PICO_TCP_ACK) || (flags == (PICO_TCP_ACK | PICO_TCP_PSH))) {
        tcp_action_call(action->ack, s, f);
    }

    if ((f->payload_len > 0 || (flags & PICO_TCP_PSH)) && !(s->state & PICO_SOCKET_STATE_CLOSED) && !TCP_IS_STATE(s, PICO_SOCKET_STATE_TCP_LISTEN))
    {
        ret = f->payload_len;
        tcp_action_call(action->data, s, f);
    }

    if (flags == PICO_TCP_FIN) {
        tcp_action_call(action->fin, s, f);
    }

    if ((flags == (PICO_TCP_FIN | PICO_TCP_ACK)) || (flags == (PICO_TCP_FIN | PICO_TCP_ACK | PICO_TCP_PSH))) {
        tcp_action_call(action->finack, s, f);
    }

    if (flags & PICO_TCP_RST) {
        tcp_action_call(action->rst, s, f);
    }

    return ret;
}

int pico_tcp_input(struct pico_socket *s, struct pico_frame *f)
{
    struct pico_tcp_hdr *hdr = (struct pico_tcp_hdr *) (f->transport_hdr);
    int ret = 0;
    uint8_t flags = hdr->flags;
    const struct tcp_action_entry *action = &tcp_fsm[s->state >> 8];

    f->payload = (f->transport_hdr + ((hdr->len & 0xf0u) >> 2u));
    f->payload_len = (uint16_t)(f->transport_len - ((hdr->len & 0xf0u) >> 2u));

    tcp_dbg("[sam] TCP> [tcp input] t_len: %u\n", f->transport_len);
    tcp_dbg("[sam] TCP> flags = 0x%02x\n", hdr->flags);
    tcp_dbg("[sam] TCP> s->state >> 8 = %u\n", s->state >> 8);
    tcp_dbg("[sam] TCP> [tcp input] socket: %p state: %d <-- local port:%u remote port: %u seq: 0x%08x ack: 0x%08x flags: 0x%02x t_len: %u, hdr: %u payload: %d\n", s, s->state >> 8, short_be(hdr->trans.dport), short_be(hdr->trans.sport), SEQN(f), ACKN(f), hdr->flags, f->transport_len, (hdr->len & 0xf0) >> 2, f->payload_len );

    if ((f->payload + f->payload_len) > (f->buffer + f->buffer_len)) {
        tcp_dbg("TCP> Invalid payload len %04x\n", f->payload_len);
        pico_frame_discard(f);
        return -1;
    }

    
    f->sock = s;
    s->timestamp = TCP_TIME;
    
    
    if(invalid_flags(s, flags)) {
        pico_tcp_reply_rst(s->stack, f);
    }
    else if (flags == PICO_TCP_SYN) {
        tcp_action_call(action->syn, s, f);
    } else if (flags == (PICO_TCP_SYN | PICO_TCP_ACK)) {
        tcp_action_call(action->synack, s, f);
    } else {
        ret = tcp_action_by_flags(action, s, f, flags);
    }

    if (s->ev_pending)
        tcp_wakeup_pending(s, s->ev_pending);


    pico_frame_discard(f);
    return ret;
}


inline static int checkLocalClosing(struct pico_socket *s);
inline static int checkRemoteClosing(struct pico_socket *s);

static struct pico_frame *tcp_split_segment(struct pico_socket_tcp *t, struct pico_frame *f, uint16_t size)
{
    struct pico_frame *f1, *f2;
    uint16_t size1, size2, size_f;
    uint16_t overhead;
    struct pico_tcp_hdr *hdr1, *hdr2, *hdr = (struct pico_tcp_hdr *)f->transport_hdr;
    overhead = pico_tcp_overhead(&t->sock);
    size_f = f->payload_len;


    if (size >= size_f)
        return f; 

    size1 = size;
    size2 = (uint16_t)(size_f - size);

    f1 = pico_socket_frame_alloc(&t->sock, get_sock_dev(&t->sock), (uint16_t) (size1 + overhead));
    f2 = pico_socket_frame_alloc(&t->sock, get_sock_dev(&t->sock), (uint16_t) (size2 + overhead));

    if (!f1 || !f2) {
        pico_err = PICO_ERR_ENOMEM;
        return NULL;
    }

    
    f1->payload += overhead;
    f1->payload_len = (uint16_t)(f1->payload_len - overhead);
    f2->payload += overhead;
    f2->payload_len = (uint16_t)(f2->payload_len - overhead);

    hdr1 = (struct pico_tcp_hdr *)f1->transport_hdr;
    hdr2 = (struct pico_tcp_hdr *)f2->transport_hdr;

    
    memcpy(f1->payload, f->payload, size1);
    memcpy(f2->payload, f->payload + size1, size2);

    
    memcpy(hdr1, hdr, sizeof(struct pico_tcp_hdr));
    memcpy(hdr2, hdr, sizeof(struct pico_tcp_hdr));

    
    hdr2->seq = long_be(SEQN(f) + size1);

    
    pico_tcp_flags_update(f1, &t->sock);
    pico_tcp_flags_update(f2, &t->sock);
    tcp_add_options_frame(t, f1);
    tcp_add_options_frame(t, f2);

    
    pico_discard_segment(&t->tcpq_out, f);

    
    if (pico_enqueue_segment(&t->tcpq_out, f2) < 0) {
        tcp_dbg("Discarding invalid segment\n");
        pico_frame_discard(f2);
    }

    
    return f1;
}


int pico_tcp_output(struct pico_socket *s, int loop_score)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    struct pico_frame *f, *una;
    int sent = 0;
    int data_sent = 0;
    int32_t seq_diff = 0;

    una = first_segment(&t->tcpq_out);
    f = peek_segment(&t->tcpq_out, t->snd_nxt);

    while((f) && (t->cwnd >= t->in_flight)) {
        f->timestamp = TCP_TIME;
        add_retransmission_timer(t, t->rto + TCP_TIME);
        tcp_add_options_frame(t, f);
        seq_diff = pico_seq_compare(SEQN(f), SEQN(una));
        if (seq_diff < 0) {
            tcp_dbg(">>> FATAL: seq diff is negative!\n");
            break;
        }

        
        if ((uint32_t)seq_diff >= (uint32_t)(t->recv_wnd << t->recv_wnd_scale)) {
            if (t->x_mode != PICO_TCP_WINDOW_FULL) {
                tcp_dbg("TCP> RIGHT SIZING (rwnd: %d, frame len: %d\n", t->recv_wnd << t->recv_wnd_scale, f->payload_len);
                tcp_dbg("In window full...\n");
                t->snd_nxt = SEQN(una);
                t->snd_retry = SEQN(una);
                t->x_mode = PICO_TCP_WINDOW_FULL;
            }

            break;
        }

        
        if ((uint32_t)(seq_diff + f->payload_len) > (uint32_t)(t->recv_wnd << t->recv_wnd_scale)) {
            f = tcp_split_segment(t, f, (uint16_t)(t->recv_wnd << t->recv_wnd_scale));
            if (!f)
                break;

            
            t->cwnd = (uint16_t)t->in_flight;
            if (t->cwnd < 1)
                t->cwnd = 1;
        }

        tcp_dbg("TCP> DEQUEUED (for output) frame %08x, acks %08x len= %d, remaining frames %d\n", SEQN(f), ACKN(f), f->payload_len, t->tcpq_out.frames);
        tcp_send(t, f);
        sent++;
        loop_score--;
        t->snd_last_out = SEQN(f);
        if (loop_score < 1)
            break;

        if (f->payload_len > 0) {
            data_sent++;
            f = next_segment(&t->tcpq_out, f);
        } else {
            f = NULL;
        }
    }
    if ((sent > 0 && data_sent > 0)) {
        rto_set(t, t->rto);
    } else {
        
    }

    if ((t->tcpq_out.frames == 0) && (s->state & PICO_SOCKET_STATE_SHUT_LOCAL)) {              
        if(!checkLocalClosing(&t->sock))              
        {
            checkRemoteClosing(&t->sock);              
        }
    }

    return loop_score;
}

int pico_tcp_output(struct pico_socket *s, int loop_score);
void pico_tcp_out_all(struct pico_stack *S, void *arg)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)arg;
    (void)S;
    if (t) {
        struct pico_socket *s = &t->sock;
        pico_tcp_output(&t->sock, (int)t->tcpq_out.frames);
        if ((s->ev_pending) && s->wakeup) {
            s->wakeup(s->ev_pending, s);
            if(!s->parent)
                s->ev_pending = 0;
        }

        if(pico_socket_sanity_check(s) < 0)
        {
            pico_socket_del(s);
        }
    }
}


static struct pico_frame *pico_hold_segment_make(struct pico_socket_tcp *t)
{
    struct pico_frame *f_temp, *f_new;
    struct pico_socket *s = (struct pico_socket *) &t->sock;
    struct pico_tcp_hdr *hdr;
    uint16_t total_len = 0, total_payload_len = 0;
    uint16_t off = 0, test = 0;

    off = pico_tcp_overhead(s);

    
    f_temp = first_segment(&t->tcpq_hold);
    total_len = f_temp->payload_len;
    f_temp = next_segment(&t->tcpq_hold, f_temp);

    
    while ((f_temp != NULL) && ((total_len + f_temp->payload_len) <= t->mss)) {
        total_len = (uint16_t)(total_len + f_temp->payload_len);
        f_temp = next_segment(&t->tcpq_hold, f_temp);
        if (f_temp == NULL)
            break;
    }
    
    f_new = pico_socket_frame_alloc(s, get_sock_dev(s), (uint16_t)(off + total_len));
    if (!f_new) {
        pico_err = PICO_ERR_ENOMEM;
        return f_new;
    }

    pico_tcp_flags_update(f_new, &t->sock);
    hdr = (struct pico_tcp_hdr *) f_new->transport_hdr;
    
    f_new->payload += off;
    f_new->payload_len = (uint16_t)(f_new->payload_len - off);
    f_new->sock = s;

    f_temp = first_segment(&t->tcpq_hold);
    hdr->seq = ((struct pico_tcp_hdr *)(f_temp->transport_hdr))->seq;              
    hdr->trans.sport = t->sock.local_port;
    hdr->trans.dport = t->sock.remote_port;

    
    while ((f_temp != NULL) && ((total_payload_len + f_temp->payload_len) <= t->mss)) {
        
        test++;
        memcpy(f_new->payload + total_payload_len, f_temp->payload, f_temp->payload_len);
        total_payload_len = (uint16_t)(total_payload_len + f_temp->payload_len);
        pico_discard_segment(&t->tcpq_hold, f_temp);
        f_temp = first_segment(&t->tcpq_hold);
    }
    hdr->len = (uint8_t)((f_new->payload - f_new->transport_hdr) << 2u);

    tcp_dbg_nagle("NAGLE make - joined %d segments, len %d bytes\n", test, total_payload_len);
    tcp_add_options_frame(t, f_new);

    return f_new;
}



static int pico_tcp_push_nagle_enqueue(struct pico_socket_tcp *t, struct pico_frame *f)
{
    if (pico_enqueue_segment(&t->tcpq_out, f) > 0) {
        tcp_dbg_nagle("TCP_PUSH - NAGLE - Pushing segment %08x, len %08x to socket %p\n", t->snd_last + 1, f->payload_len, t);
        t->snd_last += f->payload_len;
        pico_schedule_job(t->sock.stack, pico_tcp_out_all, t);
        return f->payload_len;
    } else {
        tcp_dbg("Enqueue failed.\n");
        return 0;
    }
}

static int pico_tcp_push_nagle_hold(struct pico_socket_tcp *t, struct pico_frame *f)
{
    struct pico_frame *f_new;
    uint32_t total_len = 0;
    pico_schedule_job(t->sock.stack, pico_tcp_out_all, t);
    total_len = f->payload_len + t->tcpq_hold.size;
    if ((total_len >= t->mss) && ((t->tcpq_out.max_size - t->tcpq_out.size) >= t->mss)) {
        
        
        if (pico_enqueue_segment(&t->tcpq_hold, f) > 0 ) {
            tcp_dbg_nagle("TCP_PUSH - NAGLE - Pushed into hold, make new (enqueued frames out %d)\n", t->tcpq_out.frames);
            t->snd_last += f->payload_len;              
            f_new = pico_hold_segment_make(t);
        } else {
            tcp_dbg_nagle("TCP_PUSH - NAGLE - enqueue hold failed 1\n");
            return 0;
        }

        
        if ((f_new != NULL) && (pico_enqueue_segment(&t->tcpq_out, f_new) > 0)) {
            return f_new->payload_len;
        } else {
            tcp_dbg_nagle("TCP_PUSH - NAGLE - enqueue out failed, f_new = %p\n", f_new);
            return -1;              
        }
    } else {
        
        if (pico_enqueue_segment(&t->tcpq_hold, f) > 0) {
            tcp_dbg_nagle("TCP_PUSH - NAGLE - Pushed into hold (enqueued frames out %d)\n", t->tcpq_out.frames);
            t->snd_last += f->payload_len;              
            return f->payload_len;
        } else {
            pico_err = PICO_ERR_EAGAIN;
            tcp_dbg_nagle("TCP_PUSH - NAGLE - enqueue hold failed 2\n");
        }
    }

    return 0;
}


static int pico_tcp_push_nagle_on(struct pico_socket_tcp *t, struct pico_frame *f)
{
    
    if (IS_TCP_IDLE(t) && IS_TCP_HOLDQ_EMPTY(t))
        return pico_tcp_push_nagle_enqueue(t, f);

    return pico_tcp_push_nagle_hold(t, f);
}




int pico_tcp_push(struct pico_stack *S, struct pico_protocol *self, struct pico_frame *f)
{
    struct pico_tcp_hdr *hdr = (struct pico_tcp_hdr *)f->transport_hdr;
    struct pico_socket_tcp *t = (struct pico_socket_tcp *) f->sock;
    (void)S;
    IGNORE_PARAMETER(self);
    pico_err = PICO_ERR_NOERR;
    hdr->trans.sport = t->sock.local_port;
    hdr->trans.dport = t->sock.remote_port;
    hdr->seq = long_be(t->snd_last + 1);
    hdr->len = (uint8_t)((f->payload - f->transport_hdr) << 2u);

    if ((uint32_t)f->payload_len > (uint32_t)(t->tcpq_out.max_size - t->tcpq_out.size))
        t->sock.ev_pending &= (uint16_t)(~PICO_SOCK_EV_WR);

    

    if (!IS_NAGLE_ENABLED((&(t->sock)))) {
        
        if (pico_enqueue_segment(&t->tcpq_out, f) > 0) {
            pico_schedule_job(t->sock.stack, pico_tcp_out_all, t);
            tcp_dbg_nagle("TCP_PUSH - NO NAGLE - Pushing segment %08x, len %08x to socket %p\n", t->snd_last + 1, f->payload_len, t);
            t->snd_last += f->payload_len;
            return f->payload_len;
        } else {
            tcp_dbg("Enqueue failed.\n");
            return 0;
        }
    } else {
        return pico_tcp_push_nagle_on(t, f);
    }

}

static void tcp_discard_all_segments(struct pico_tcp_queue *tq)
{
    struct pico_tree_node *index = NULL, *index_safe = NULL;
    PICOTCP_MUTEX_LOCK(Mutex);
    pico_tree_foreach_safe(index, &tq->pool, index_safe)
    {
        void *f = index->keyValue;
        if(!f)
            break;

        pico_tree_delete(&tq->pool, f);
        if(IS_INPUT_QUEUE(tq))
        {
            struct tcp_input_segment *inp = (struct tcp_input_segment *)f;
            PICO_FREE(inp->payload);
            PICO_FREE(inp);
        }
        else pico_frame_discard(f);
    }
    tq->frames = 0;
    tq->size = 0;
    PICOTCP_MUTEX_UNLOCK(Mutex);
}

void pico_tcp_cleanup_queues(struct pico_socket *sck)
{
    struct pico_socket_tcp *tcp = (struct pico_socket_tcp *)sck;
    pico_timer_cancel(tcp->sock.stack, tcp->retrans_tmr);
    pico_timer_cancel(tcp->sock.stack, tcp->keepalive_tmr);
    pico_timer_cancel(tcp->sock.stack, tcp->fin_tmr);

    tcp->retrans_tmr = 0;
    tcp->keepalive_tmr = 0;
    tcp->fin_tmr = 0;

    tcp_discard_all_segments(&tcp->tcpq_in);
    tcp_discard_all_segments(&tcp->tcpq_out);
    tcp_discard_all_segments(&tcp->tcpq_hold);
}

static int checkLocalClosing(struct pico_socket *s)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    if ((s->state & PICO_SOCKET_STATE_TCP) == PICO_SOCKET_STATE_TCP_ESTABLISHED) {
        tcp_dbg("TCP> buffer empty, shutdown established ...\n");
        
        tcp_send_fin(t);
        
        s->state &= 0x00FFU;
        s->state |= PICO_SOCKET_STATE_TCP_FIN_WAIT1;
        return 1;
    }

    return 0;
}

static int checkRemoteClosing(struct pico_socket *s)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    if ((s->state & PICO_SOCKET_STATE_TCP) == PICO_SOCKET_STATE_TCP_CLOSE_WAIT) {
        
        tcp_send_fin(t);
        
        s->state &= 0x00FFU;
        s->state |= PICO_SOCKET_STATE_TCP_LAST_ACK;
        tcp_dbg("TCP> STATE: LAST_ACK.\n");
        return 1;
    }

    return 0;
}

void pico_tcp_notify_closing(struct pico_socket *sck)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)sck;
    if(t->tcpq_out.frames == 0)
    {
        if(!checkLocalClosing(sck))
            checkRemoteClosing(sck);
    }
}


int pico_tcp_check_listen_close(struct pico_socket *s)
{
    if (TCP_IS_STATE(s, PICO_SOCKET_STATE_TCP_LISTEN)) {
        pico_socket_del(s);
        return 0;
    }

    return -1;
}

void pico_tcp_flags_update(struct pico_frame *f, struct pico_socket *s)
{
    f->transport_flags_saved = ((struct pico_socket_tcp *)s)->ts_ok;
}

int pico_tcp_set_bufsize_in(struct pico_socket *s, uint32_t value)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    t->tcpq_in.max_size = value;
    return 0;
}

int pico_tcp_set_bufsize_out(struct pico_socket *s, uint32_t value)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    t->tcpq_out.max_size = value;
    return 0;
}

int pico_tcp_get_bufsize_in(struct pico_socket *s, uint32_t *value)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    *value = t->tcpq_in.max_size;
    return 0;
}

int pico_tcp_get_bufsize_out(struct pico_socket *s, uint32_t *value)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    *value = t->tcpq_out.max_size;
    return 0;
}

int pico_tcp_set_keepalive_probes(struct pico_socket *s, uint32_t value)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    t->ka_probes = value;
    return 0;
}

int pico_tcp_set_keepalive_intvl(struct pico_socket *s, uint32_t value)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    t->ka_intvl = value;
    return 0;
}

int pico_tcp_set_keepalive_time(struct pico_socket *s, uint32_t value)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    t->ka_time = value;
    return 0;
}

int pico_tcp_set_linger(struct pico_socket *s, uint32_t value)
{
    struct pico_socket_tcp *t = (struct pico_socket_tcp *)s;
    t->linger_timeout = value;
    return 0;
}


