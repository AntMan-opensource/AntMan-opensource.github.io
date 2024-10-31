









struct st_h2o_http3_req_scheduler_t {
    struct {
        struct {
            h2o_linklist_t high;
            h2o_linklist_t low;
        } urgencies[H2O_ABSPRIO_NUM_URGENCY_LEVELS];
        size_t smallest_urgency;
    } active;
    h2o_linklist_t conn_blocked;
};


struct st_h2o_http3_req_scheduler_node_t {
    h2o_linklist_t link;
    h2o_absprio_t priority;
    uint64_t call_cnt;
};


typedef int (*h2o_http3_req_scheduler_compare_cb)(struct st_h2o_http3_req_scheduler_t *sched, const struct st_h2o_http3_req_scheduler_node_t *x, const struct st_h2o_http3_req_scheduler_node_t *y);





enum h2o_http3_server_stream_state {
    
    H2O_HTTP3_SERVER_STREAM_STATE_RECV_HEADERS,  H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_BEFORE_BLOCK,  H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_BLOCKED,  H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_UNBLOCKED,  H2O_HTTP3_SERVER_STREAM_STATE_REQ_PENDING,  H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS,  H2O_HTTP3_SERVER_STREAM_STATE_SEND_BODY,  H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT };















struct st_h2o_http3_server_conn_t {
    h2o_conn_t super;
    h2o_http3_conn_t h3;
    ptls_handshake_properties_t handshake_properties;
    h2o_linklist_t _conns; 
    
    struct {
        
        h2o_linklist_t recv_body_blocked;
        
        h2o_linklist_t req_streaming;
        
        h2o_linklist_t pending;
    } delayed_streams;
    
    h2o_timer_t timeout;
    
    union {
        struct {
            uint32_t recv_headers;
            uint32_t recv_body_before_block;
            uint32_t recv_body_blocked;
            uint32_t recv_body_unblocked;
            uint32_t req_pending;
            uint32_t send_headers;
            uint32_t send_body;
            uint32_t close_wait;
        };
        uint32_t counters[1];
    } num_streams;
    
    uint32_t num_streams_req_streaming;
    
    struct {
        
        struct st_h2o_http3_req_scheduler_t reqs;
        
        struct {
            uint16_t active;
            uint16_t conn_blocked;
        } uni;
    } scheduler;
};


struct st_h2o_http3_server_sendvec_t {
    h2o_sendvec_t vec;
    
    uint64_t entity_offset;
};

struct st_h2o_http3_server_stream_t {
    quicly_stream_t *quic;
    struct {
        h2o_buffer_t *buf;
        int (*handle_input)(struct st_h2o_http3_server_stream_t *stream, const uint8_t **src, const uint8_t *src_end, const char **err_desc);
        uint64_t bytes_left_in_data_frame;
    } recvbuf;
    struct {
        H2O_VECTOR(struct st_h2o_http3_server_sendvec_t) vecs;
        size_t off_within_first_vec;
        size_t min_index_to_addref;
        uint64_t final_size, final_body_size;
        uint8_t data_frame_header_buf[9];
    } sendbuf;
    enum h2o_http3_server_stream_state state;
    h2o_linklist_t link;
    h2o_ostream_t ostr_final;
    struct st_h2o_http3_req_scheduler_node_t scheduler;
    
    uint8_t read_blocked : 1;
    
    uint8_t proceed_requested : 1;
    
    uint8_t proceed_while_sending : 1;
    
    uint8_t received_priority_update : 1;
    
    uint8_t req_disposed : 1;
    
    h2o_buffer_t *req_body;
    
    struct st_h2o_http3_server_tunnel_t {
        
        h2o_tunnel_t *tunnel;
        struct st_h2o_http3_server_stream_t *stream;
        struct {
            h2o_timer_t delayed_write;
            char bytes_inflight[16384];
            unsigned is_inflight : 1;
        } up;
    } * tunnel;
    
    h2o_req_t req;
};

static void on_stream_destroy(quicly_stream_t *qs, int err);
static int retain_sendvecs(struct st_h2o_http3_server_stream_t *stream);
static int handle_input_post_trailers(struct st_h2o_http3_server_stream_t *stream, const uint8_t **src, const uint8_t *src_end, const char **err_desc);
static int handle_input_expect_data(struct st_h2o_http3_server_stream_t *stream, const uint8_t **src, const uint8_t *src_end, const char **err_desc);
static void tunnel_write(struct st_h2o_http3_server_stream_t *stream);
static void tunnel_write_delayed(h2o_timer_t *timer);

static void req_scheduler_init(struct st_h2o_http3_req_scheduler_t *sched)
{
    size_t i;

    for (i = 0; i < H2O_ABSPRIO_NUM_URGENCY_LEVELS; ++i) {
        h2o_linklist_init_anchor(&sched->active.urgencies[i].high);
        h2o_linklist_init_anchor(&sched->active.urgencies[i].low);
    }
    sched->active.smallest_urgency = i;
    h2o_linklist_init_anchor(&sched->conn_blocked);
}

static void req_scheduler_activate(struct st_h2o_http3_req_scheduler_t *sched, struct st_h2o_http3_req_scheduler_node_t *node, h2o_http3_req_scheduler_compare_cb comp)
{
    
    if (h2o_linklist_is_linked(&node->link))
        h2o_linklist_unlink(&node->link);

    if (!node->priority.incremental || node->call_cnt == 0) {
        
        h2o_linklist_t *anchor = &sched->active.urgencies[node->priority.urgency].high, *pos;
        for (pos = anchor->prev; pos != anchor; pos = pos->prev) {
            struct st_h2o_http3_req_scheduler_node_t *node_at_pos = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_req_scheduler_node_t, link, pos);
            if (comp(sched, node_at_pos, node) < 0)
                break;
        }
        h2o_linklist_insert(pos->next, &node->link);
    } else {
        
        h2o_linklist_insert(&sched->active.urgencies[node->priority.urgency].low, &node->link);
    }

    
    if (node->priority.urgency < sched->active.smallest_urgency)
        sched->active.smallest_urgency = node->priority.urgency;
}

static void req_scheduler_update_smallest_urgency_post_removal(struct st_h2o_http3_req_scheduler_t *sched, size_t changed)
{
    if (sched->active.smallest_urgency < changed)
        return;

    
    sched->active.smallest_urgency = changed;
    while (h2o_linklist_is_empty(&sched->active.urgencies[sched->active.smallest_urgency].high) && h2o_linklist_is_empty(&sched->active.urgencies[sched->active.smallest_urgency].low)) {
        ++sched->active.smallest_urgency;
        if (sched->active.smallest_urgency >= H2O_ABSPRIO_NUM_URGENCY_LEVELS)
            break;
    }
}

static void req_scheduler_deactivate(struct st_h2o_http3_req_scheduler_t *sched, struct st_h2o_http3_req_scheduler_node_t *node)
{
    if (h2o_linklist_is_linked(&node->link))
        h2o_linklist_unlink(&node->link);

    req_scheduler_update_smallest_urgency_post_removal(sched, node->priority.urgency);
}

static void req_scheduler_setup_for_next(struct st_h2o_http3_req_scheduler_t *sched, struct st_h2o_http3_req_scheduler_node_t *node, h2o_http3_req_scheduler_compare_cb comp)
{
    assert(h2o_linklist_is_linked(&node->link));

    
    if (node->priority.incremental)
        req_scheduler_activate(sched, node, comp);
}

static void req_scheduler_conn_blocked(struct st_h2o_http3_req_scheduler_t *sched, struct st_h2o_http3_req_scheduler_node_t *node)
{
    if (h2o_linklist_is_linked(&node->link))
        h2o_linklist_unlink(&node->link);

    h2o_linklist_insert(&sched->conn_blocked, &node->link);

    req_scheduler_update_smallest_urgency_post_removal(sched, node->priority.urgency);
}

static void req_scheduler_unblock_conn_blocked(struct st_h2o_http3_req_scheduler_t *sched, h2o_http3_req_scheduler_compare_cb comp)
{
    while (!h2o_linklist_is_empty(&sched->conn_blocked)) {
        struct st_h2o_http3_req_scheduler_node_t *node = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_req_scheduler_node_t, link, sched->conn_blocked.next);
        req_scheduler_activate(sched, node, comp);
    }
}

static int req_scheduler_compare_stream_id(struct st_h2o_http3_req_scheduler_t *sched, const struct st_h2o_http3_req_scheduler_node_t *x, const struct st_h2o_http3_req_scheduler_node_t *y)

{
    struct st_h2o_http3_server_stream_t *sx = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, scheduler, x), *sy = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, scheduler, y);
    if (sx->quic->stream_id < sy->quic->stream_id) {
        return -1;
    } else if (sx->quic->stream_id > sy->quic->stream_id) {
        return 1;
    } else {
        return 0;
    }
}

static struct st_h2o_http3_server_conn_t *get_conn(struct st_h2o_http3_server_stream_t *stream)
{
    return (void *)stream->req.conn;
}

static uint32_t *get_state_counter(struct st_h2o_http3_server_conn_t *conn, enum h2o_http3_server_stream_state state)
{
    return conn->num_streams.counters + (size_t)state;
}

static void request_run_delayed(struct st_h2o_http3_server_conn_t *conn)
{
    if (!h2o_timer_is_linked(&conn->timeout))
        h2o_timer_link(conn->super.ctx->loop, 0, &conn->timeout);
}

static void check_run_blocked(struct st_h2o_http3_server_conn_t *conn)
{
    if (conn->num_streams.recv_body_unblocked + conn->num_streams_req_streaming == 0 && !h2o_linklist_is_empty(&conn->delayed_streams.recv_body_blocked))
        request_run_delayed(conn);
}

static void pre_dispose_request(struct st_h2o_http3_server_stream_t *stream)
{
    size_t i;

    
    for (i = 0; i != stream->sendbuf.vecs.size; ++i) {
        struct st_h2o_http3_server_sendvec_t *vec = stream->sendbuf.vecs.entries + i;
        if (vec->vec.callbacks->update_refcnt != NULL)
            vec->vec.callbacks->update_refcnt(&vec->vec, &stream->req, 0);
    }

    
    if (stream->req_body != NULL)
        h2o_buffer_dispose(&stream->req_body);

    
    if (stream->req.write_req.cb != NULL) {
        struct st_h2o_http3_server_conn_t *conn = get_conn(stream);
        assert(conn->num_streams_req_streaming != 0);
        --conn->num_streams_req_streaming;
        check_run_blocked(conn);
    }

    
    if (stream->tunnel != NULL) {
        if (stream->tunnel->tunnel != NULL) {
            retain_sendvecs(stream);
            stream->tunnel->tunnel->destroy(stream->tunnel->tunnel);
            stream->tunnel->tunnel = NULL;
        }
        if (h2o_timer_is_linked(&stream->tunnel->up.delayed_write))
            h2o_timer_unlink(&stream->tunnel->up.delayed_write);
        free(stream->tunnel);
        stream->tunnel = NULL;
    }
}

static void set_state(struct st_h2o_http3_server_stream_t *stream, enum h2o_http3_server_stream_state state, int in_generator)
{
    struct st_h2o_http3_server_conn_t *conn = get_conn(stream);
    enum h2o_http3_server_stream_state old_state = stream->state;

    H2O_PROBE_CONN(H3S_STREAM_SET_STATE, &conn->super, stream->quic->stream_id, (unsigned)state);

    --*get_state_counter(conn, old_state);
    stream->state = state;
    ++*get_state_counter(conn, stream->state);

    switch (state) {
    case H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_BLOCKED:
        assert(conn->delayed_streams.recv_body_blocked.prev == &stream->link || !"stream is not registered to the recv_body list?");
        break;
    case H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT: {
        if (h2o_linklist_is_linked(&stream->link))
            h2o_linklist_unlink(&stream->link);
        pre_dispose_request(stream);
        if (!in_generator) {
            h2o_dispose_request(&stream->req);
            stream->req_disposed = 1;
        }
        static const quicly_stream_callbacks_t close_wait_callbacks = {on_stream_destroy, quicly_stream_noop_on_send_shift, quicly_stream_noop_on_send_emit, quicly_stream_noop_on_send_stop, quicly_stream_noop_on_receive, quicly_stream_noop_on_receive_reset};




        stream->quic->callbacks = &close_wait_callbacks;
    } break;
    default:
        break;
    }
}


static void shutdown_stream(struct st_h2o_http3_server_stream_t *stream, int stop_sending_code, int reset_code, int in_generator)
{
    assert(stream->state < H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT);
    if (quicly_stream_has_receive_side(0, stream->quic->stream_id)) {
        quicly_request_stop(stream->quic, stop_sending_code);
        h2o_buffer_consume(&stream->recvbuf.buf, stream->recvbuf.buf->size);
    }
    if (quicly_stream_has_send_side(0, stream->quic->stream_id) && !quicly_sendstate_transfer_complete(&stream->quic->sendstate))
        quicly_reset_stream(stream->quic, reset_code);
    set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT, in_generator);
}

static socklen_t get_sockname(h2o_conn_t *_conn, struct sockaddr *sa)
{
    struct st_h2o_http3_server_conn_t *conn = (void *)_conn;
    struct sockaddr *src = quicly_get_sockname(conn->h3.super.quic);
    socklen_t len = src->sa_family == AF_UNSPEC ? sizeof(struct sockaddr) : quicly_get_socklen(src);
    memcpy(sa, src, len);
    return len;
}

static socklen_t get_peername(h2o_conn_t *_conn, struct sockaddr *sa)
{
    struct st_h2o_http3_server_conn_t *conn = (void *)_conn;
    struct sockaddr *src = quicly_get_peername(conn->h3.super.quic);
    socklen_t len = quicly_get_socklen(src);
    memcpy(sa, src, len);
    return len;
}

static ptls_t *get_ptls(h2o_conn_t *_conn)
{
    struct st_h2o_http3_server_conn_t *conn = (void *)_conn;
    return quicly_get_tls(conn->h3.super.quic);
}

static int get_skip_tracing(h2o_conn_t *conn)
{
    ptls_t *ptls = get_ptls(conn);
    return ptls_skip_tracing(ptls);
}

static uint32_t num_reqs_inflight(h2o_conn_t *_conn)
{
    struct st_h2o_http3_server_conn_t *conn = (void *)_conn;
    return quicly_num_streams_by_group(conn->h3.super.quic, 0, 0);
}

static quicly_tracer_t *get_tracer(h2o_conn_t *_conn)
{
    struct st_h2o_http3_server_conn_t *conn = (void *)_conn;
    return quicly_get_tracer(conn->h3.super.quic);
}

static h2o_iovec_t log_cc_name(h2o_req_t *req)
{
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    quicly_stats_t stats;

    if (quicly_get_stats(conn->h3.super.quic, &stats) == 0)
        return h2o_iovec_init(stats.cc.type->name, strlen(stats.cc.type->name));
    return h2o_iovec_init(NULL, 0);
}

static h2o_iovec_t log_delivery_rate(h2o_req_t *req)
{
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    quicly_rate_t rate;

    if (quicly_get_delivery_rate(conn->h3.super.quic, &rate) == 0 && rate.latest != 0) {
        char *buf = h2o_mem_alloc_pool(&req->pool, char, sizeof(H2O_UINT64_LONGEST_STR));
        size_t len = sprintf(buf, "%" PRIu64, rate.latest);
        return h2o_iovec_init(buf, len);
    }

    return h2o_iovec_init(NULL, 0);
}

static h2o_iovec_t log_tls_protocol_version(h2o_req_t *_req)
{
    return h2o_iovec_init(H2O_STRLIT("TLSv1.3"));
}

static h2o_iovec_t log_session_reused(h2o_req_t *req)
{
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    ptls_t *tls = quicly_get_tls(conn->h3.super.quic);
    return ptls_is_psk_handshake(tls) ? h2o_iovec_init(H2O_STRLIT("1")) : h2o_iovec_init(H2O_STRLIT("0"));
}

static h2o_iovec_t log_cipher(h2o_req_t *req)
{
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    ptls_t *tls = quicly_get_tls(conn->h3.super.quic);
    ptls_cipher_suite_t *cipher = ptls_get_cipher(tls);
    return cipher != NULL ? h2o_iovec_init(cipher->aead->name, strlen(cipher->aead->name)) : h2o_iovec_init(NULL, 0);
}

static h2o_iovec_t log_cipher_bits(h2o_req_t *req)
{
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    ptls_t *tls = quicly_get_tls(conn->h3.super.quic);
    ptls_cipher_suite_t *cipher = ptls_get_cipher(tls);
    if (cipher == NULL)
        return h2o_iovec_init(NULL, 0);

    char *buf = h2o_mem_alloc_pool(&req->pool, char, sizeof(H2O_UINT16_LONGEST_STR));
    return h2o_iovec_init(buf, sprintf(buf, "%" PRIu16, (uint16_t)(cipher->aead->key_size * 8)));
}

static h2o_iovec_t log_session_id(h2o_req_t *_req)
{
    
    return h2o_iovec_init(NULL, 0);
}

static h2o_iovec_t log_server_name(h2o_req_t *req)
{
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    ptls_t *tls = quicly_get_tls(conn->h3.super.quic);
    const char *server_name = ptls_get_server_name(tls);
    return server_name != NULL ? h2o_iovec_init(server_name, strlen(server_name)) : h2o_iovec_init(NULL, 0);
}

static h2o_iovec_t log_negotiated_protocol(h2o_req_t *req)
{
    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    ptls_t *tls = quicly_get_tls(conn->h3.super.quic);
    const char *proto = ptls_get_negotiated_protocol(tls);
    return proto != NULL ? h2o_iovec_init(proto, strlen(proto)) : h2o_iovec_init(NULL, 0);
}

static h2o_iovec_t log_stream_id(h2o_req_t *_req)
{
    struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, req, _req);
    char *buf = h2o_mem_alloc_pool(&stream->req.pool, char, sizeof(H2O_UINT64_LONGEST_STR));
    return h2o_iovec_init(buf, sprintf(buf, "%" PRIu64, stream->quic->stream_id));
}

static h2o_iovec_t log_quic_stats(h2o_req_t *req)
{








    struct st_h2o_http3_server_conn_t *conn = (struct st_h2o_http3_server_conn_t *)req->conn;
    quicly_stats_t stats;

    if (quicly_get_stats(conn->h3.super.quic, &stats) != 0)
        return h2o_iovec_init(H2O_STRLIT("-"));

    char *buf;
    size_t len, bufsize = 1400;
Redo:
    buf = h2o_mem_alloc_pool(&req->pool, char, bufsize);
    len = snprintf( buf, bufsize, "packets-received=%" PRIu64 ",packets-decryption-failed=%" PRIu64 ",packets-sent=%" PRIu64 ",packets-lost=%" PRIu64 ",packets-lost-time-threshold=%" PRIu64 ",packets-ack-received=%" PRIu64 ",late-acked=%" PRIu64 ",bytes-received=%" PRIu64 ",bytes-sent=%" PRIu64 ",bytes-lost=%" PRIu64 ",bytes-ack-received=%" PRIu64 ",bytes-stream-data-sent=%" PRIu64 ",bytes-stream-data-resent=%" PRIu64 ",rtt-minimum=%" PRIu32 ",rtt-smoothed=%" PRIu32 ",rtt-variance=%" PRIu32 ",rtt-latest=%" PRIu32 ",cwnd=%" PRIu32 ",ssthresh=%" PRIu32 ",cwnd-initial=%" PRIu32 ",cwnd-exiting-slow-start=%" PRIu32 ",cwnd-minimum=%" PRIu32 ",cwnd-maximum=%" PRIu32 ",num-loss-episodes=%" PRIu32 ",num-ptos=%" PRIu64 ",delivery-rate-latest=%" PRIu64 ",delivery-rate-smoothed=%" PRIu64 ",delivery-rate-stdev=%" PRIu64 APPLY_NUM_FRAMES(FORMAT_OF_NUM_FRAMES, received)








            APPLY_NUM_FRAMES(FORMAT_OF_NUM_FRAMES, sent), stats.num_packets.received, stats.num_packets.decryption_failed, stats.num_packets.sent, stats.num_packets.lost, stats.num_packets.lost_time_threshold, stats.num_packets.ack_received, stats.num_packets.late_acked, stats.num_bytes.received, stats.num_bytes.sent, stats.num_bytes.lost, stats.num_bytes.ack_received, stats.num_bytes.stream_data_sent, stats.num_bytes.stream_data_resent, stats.rtt.minimum, stats.rtt.smoothed, stats.rtt.variance, stats.rtt.latest, stats.cc.cwnd, stats.cc.ssthresh, stats.cc.cwnd_initial, stats.cc.cwnd_exiting_slow_start, stats.cc.cwnd_minimum, stats.cc.cwnd_maximum, stats.cc.num_loss_episodes, stats.num_ptos, stats.delivery_rate.latest, stats.delivery_rate.smoothed, stats.delivery_rate.stdev APPLY_NUM_FRAMES(VALUE_OF_NUM_FRAMES, received) APPLY_NUM_FRAMES(VALUE_OF_NUM_FRAMES, sent));







    if (len + 1 > bufsize) {
        bufsize = len + 1;
        goto Redo;
    }

    return h2o_iovec_init(buf, len);




}

static h2o_iovec_t log_quic_version(h2o_req_t *_req)
{
    struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, req, _req);
    char *buf = h2o_mem_alloc_pool(&stream->req.pool, char, sizeof(H2O_UINT32_LONGEST_STR));
    return h2o_iovec_init(buf, sprintf(buf, "%" PRIu32, quicly_get_protocol_version(stream->quic->conn)));
}

void on_stream_destroy(quicly_stream_t *qs, int err)
{
    struct st_h2o_http3_server_stream_t *stream = qs->data;
    struct st_h2o_http3_server_conn_t *conn = get_conn(stream);

    --*get_state_counter(conn, stream->state);

    req_scheduler_deactivate(&conn->scheduler.reqs, &stream->scheduler);

    if (h2o_linklist_is_linked(&stream->link))
        h2o_linklist_unlink(&stream->link);
    if (stream->state != H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT)
        pre_dispose_request(stream);
    if (!stream->req_disposed)
        h2o_dispose_request(&stream->req);
    
    h2o_buffer_dispose(&stream->recvbuf.buf);

    free(stream);
}

static void allocated_vec_update_refcnt(h2o_sendvec_t *vec, h2o_req_t *req, int is_incr)
{
    assert(!is_incr);
    free(vec->raw);
}

int retain_sendvecs(struct st_h2o_http3_server_stream_t *stream)
{
    for (; stream->sendbuf.min_index_to_addref != stream->sendbuf.vecs.size; ++stream->sendbuf.min_index_to_addref) {
        struct st_h2o_http3_server_sendvec_t *vec = stream->sendbuf.vecs.entries + stream->sendbuf.min_index_to_addref;
        
        if (vec->vec.callbacks->update_refcnt == NULL) {
            static const h2o_sendvec_callbacks_t vec_callbacks = {h2o_sendvec_flatten_raw, allocated_vec_update_refcnt};
            size_t off_within_vec = stream->sendbuf.min_index_to_addref == 0 ? stream->sendbuf.off_within_first_vec : 0;
            h2o_iovec_t copy = h2o_iovec_init(h2o_mem_alloc(vec->vec.len - off_within_vec), vec->vec.len - off_within_vec);
            if (!(*vec->vec.callbacks->flatten)(&vec->vec, &stream->req, copy, off_within_vec)) {
                free(copy.base);
                return 0;
            }
            vec->vec = (h2o_sendvec_t){&vec_callbacks, copy.len, {copy.base}};
            if (stream->sendbuf.min_index_to_addref == 0)
                stream->sendbuf.off_within_first_vec = 0;
        }
    }

    return 1;
}

static void on_send_shift(quicly_stream_t *qs, size_t delta)
{
    struct st_h2o_http3_server_stream_t *stream = qs->data;
    size_t i;

    assert(stream->state == H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS || stream->state == H2O_HTTP3_SERVER_STREAM_STATE_SEND_BODY);
    assert(delta != 0);
    assert(stream->sendbuf.vecs.size != 0);

    size_t bytes_avail_in_first_vec = stream->sendbuf.vecs.entries[0].vec.len - stream->sendbuf.off_within_first_vec;
    if (delta < bytes_avail_in_first_vec) {
        stream->sendbuf.off_within_first_vec += delta;
        return;
    }
    delta -= bytes_avail_in_first_vec;
    stream->sendbuf.off_within_first_vec = 0;
    if (stream->sendbuf.vecs.entries[0].vec.callbacks->update_refcnt != NULL)
        stream->sendbuf.vecs.entries[0].vec.callbacks->update_refcnt(&stream->sendbuf.vecs.entries[0].vec, &stream->req, 0);

    for (i = 1; delta != 0; ++i) {
        assert(i < stream->sendbuf.vecs.size);
        if (delta < stream->sendbuf.vecs.entries[i].vec.len) {
            stream->sendbuf.off_within_first_vec = delta;
            break;
        }
        delta -= stream->sendbuf.vecs.entries[i].vec.len;
        if (stream->sendbuf.vecs.entries[i].vec.callbacks->update_refcnt != NULL)
            stream->sendbuf.vecs.entries[i].vec.callbacks->update_refcnt(&stream->sendbuf.vecs.entries[i].vec, &stream->req, 0);
    }
    memmove(stream->sendbuf.vecs.entries, stream->sendbuf.vecs.entries + i, (stream->sendbuf.vecs.size - i) * sizeof(stream->sendbuf.vecs.entries[0]));
    stream->sendbuf.vecs.size -= i;
    if (stream->sendbuf.min_index_to_addref <= i) {
        stream->sendbuf.min_index_to_addref = 0;
    } else {
        stream->sendbuf.min_index_to_addref -= i;
    }

    if (stream->sendbuf.vecs.size == 0) {
        if (quicly_sendstate_is_open(&stream->quic->sendstate)) {
            assert(stream->state == H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS || stream->proceed_requested);
        } else {
            set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT, 0);
        }
    }
}

static void on_send_emit(quicly_stream_t *qs, size_t off, void *_dst, size_t *len, int *wrote_all)
{
    struct st_h2o_http3_server_stream_t *stream = qs->data;

    assert(stream->state == H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS || stream->state == H2O_HTTP3_SERVER_STREAM_STATE_SEND_BODY);

    uint8_t *dst = _dst, *dst_end = dst + *len;
    size_t vec_index = 0;

    
    off += stream->sendbuf.off_within_first_vec;
    while (off != 0) {
        assert(vec_index < stream->sendbuf.vecs.size);
        if (off < stream->sendbuf.vecs.entries[vec_index].vec.len)
            break;
        off -= stream->sendbuf.vecs.entries[vec_index].vec.len;
        ++vec_index;
    }
    assert(vec_index < stream->sendbuf.vecs.size);

    
    *wrote_all = 0;
    do {
        struct st_h2o_http3_server_sendvec_t *this_vec = stream->sendbuf.vecs.entries + vec_index;
        size_t sz = this_vec->vec.len - off;
        if (dst_end - dst < sz)
            sz = dst_end - dst;
        if (!(this_vec->vec.callbacks->flatten)(&this_vec->vec, &stream->req, h2o_iovec_init(dst, sz), off))
            goto Error;
        if (this_vec->entity_offset != UINT64_MAX && stream->req.bytes_sent < this_vec->entity_offset + off + sz)
            stream->req.bytes_sent = this_vec->entity_offset + off + sz;
        dst += sz;
        off += sz;
        
        if (off == this_vec->vec.len) {
            off = 0;
            ++vec_index;
            if (vec_index == stream->sendbuf.vecs.size) {
                *wrote_all = 1;
                break;
            }
        }
    } while (dst != dst_end);

    *len = dst - (uint8_t *)_dst;

    
    if (stream->state == H2O_HTTP3_SERVER_STREAM_STATE_SEND_BODY && *wrote_all && quicly_sendstate_is_open(&stream->quic->sendstate) && !stream->proceed_requested) {
        if (!retain_sendvecs(stream))
            goto Error;
        stream->proceed_requested = 1;
        stream->proceed_while_sending = 1;
    }

    return;
Error:
    *len = 0;
    *wrote_all = 1;
    shutdown_stream(stream, H2O_HTTP3_ERROR_EARLY_RESPONSE, H2O_HTTP3_ERROR_INTERNAL, 0);
}

static void on_send_stop(quicly_stream_t *qs, int err)
{
    struct st_h2o_http3_server_stream_t *stream = qs->data;

    shutdown_stream(stream, H2O_HTTP3_ERROR_REQUEST_CANCELLED, err, 0);
}

static void handle_buffered_input(struct st_h2o_http3_server_stream_t *stream, int in_generator)
{
    struct st_h2o_http3_server_conn_t *conn = get_conn(stream);

    if (stream->state >= H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT)
        return;

    { 
        size_t bytes_available = quicly_recvstate_bytes_available(&stream->quic->recvstate);
        assert(bytes_available <= stream->recvbuf.buf->size);
        const uint8_t *src = (const uint8_t *)stream->recvbuf.buf->bytes, *src_end = src + bytes_available;
        while (src != src_end) {
            int err;
            const char *err_desc = NULL;
            if ((err = stream->recvbuf.handle_input(stream, &src, src_end, &err_desc)) != 0) {
                if (err == H2O_HTTP3_ERROR_INCOMPLETE) {
                    if (!quicly_recvstate_transfer_complete(&stream->quic->recvstate))
                        break;
                    err = H2O_HTTP3_ERROR_GENERAL_PROTOCOL;
                    err_desc = "incomplete frame";
                }
                h2o_quic_close_connection(&conn->h3.super, err, err_desc);
                return;
            }
        }
        size_t bytes_consumed = src - (const uint8_t *)stream->recvbuf.buf->bytes;
        h2o_buffer_consume(&stream->recvbuf.buf, bytes_consumed);
        quicly_stream_sync_recvbuf(stream->quic, bytes_consumed);
    }

    if (stream->tunnel != NULL) {
        if (stream->tunnel->tunnel != NULL && !stream->tunnel->up.is_inflight)
            tunnel_write(stream);
        return;
    }

    if (quicly_recvstate_transfer_complete(&stream->quic->recvstate)) {
        if (stream->recvbuf.buf->size == 0 && (stream->recvbuf.handle_input == handle_input_expect_data || stream->recvbuf.handle_input == handle_input_post_trailers)) {
            
            if (stream->req.content_length != SIZE_MAX && stream->req.content_length != stream->req.req_body_bytes_received) {
                
                shutdown_stream(stream, H2O_HTTP3_ERROR_NONE , stream->req.req_body_bytes_received < stream->req.content_length ? H2O_HTTP3_ERROR_REQUEST_INCOMPLETE : H2O_HTTP3_ERROR_GENERAL_PROTOCOL, in_generator);



            } else {
                if (stream->req.write_req.cb != NULL) {
                    if (!h2o_linklist_is_linked(&stream->link))
                        h2o_linklist_insert(&conn->delayed_streams.req_streaming, &stream->link);
                    request_run_delayed(conn);
                } else if (!stream->req.process_called && stream->state < H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS) {
                    
                    switch (stream->state) {
                    case H2O_HTTP3_SERVER_STREAM_STATE_RECV_HEADERS:
                    case H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_BEFORE_BLOCK:
                    case H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_UNBLOCKED:
                        break;
                    default:
                        assert(!"unexpected state");
                        break;
                    }
                    set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_REQ_PENDING, in_generator);
                    h2o_linklist_insert(&conn->delayed_streams.pending, &stream->link);
                    request_run_delayed(conn);
                }
            }
        } else {
            shutdown_stream(stream, H2O_HTTP3_ERROR_NONE , H2O_HTTP3_ERROR_REQUEST_INCOMPLETE, in_generator);
        }
    } else {
        if (stream->state == H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_BEFORE_BLOCK && stream->req_body != NULL && stream->req_body->size >= H2O_HTTP3_REQUEST_BODY_MIN_BYTES_TO_BLOCK) {
            
            stream->read_blocked = 1;
            h2o_linklist_insert(&conn->delayed_streams.recv_body_blocked, &stream->link);
            set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_BLOCKED, in_generator);
            check_run_blocked(conn);
        } else if (stream->req.write_req.cb != NULL && stream->req_body->size != 0) {
            
            if (!h2o_linklist_is_linked(&stream->link))
                h2o_linklist_insert(&conn->delayed_streams.req_streaming, &stream->link);
            request_run_delayed(conn);
        }
    }
}

static void on_receive(quicly_stream_t *qs, size_t off, const void *input, size_t len)
{
    struct st_h2o_http3_server_stream_t *stream = qs->data;

    
    h2o_http3_update_recvbuf(&stream->recvbuf.buf, off, input, len);

    if (stream->read_blocked)
        return;

    
    handle_buffered_input(stream, 0);
}

static void on_receive_reset(quicly_stream_t *qs, int err)
{
    struct st_h2o_http3_server_stream_t *stream = qs->data;

    shutdown_stream(stream, H2O_HTTP3_ERROR_NONE , stream->state == H2O_HTTP3_SERVER_STREAM_STATE_RECV_HEADERS ? H2O_HTTP3_ERROR_REQUEST_REJECTED : H2O_HTTP3_ERROR_REQUEST_CANCELLED, 0);


}

static void proceed_request_streaming(h2o_req_t *_req, size_t bytes_written, h2o_send_state_t state)
{
    struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, req, _req);
    struct st_h2o_http3_server_conn_t *conn = get_conn(stream);

    assert(stream->req_body != NULL);
    assert(!h2o_linklist_is_linked(&stream->link));
    assert(conn->num_streams_req_streaming != 0);

    if (state != H2O_SEND_STATE_IN_PROGRESS) {
        
        stream->req.write_req.cb = NULL;
        stream->req.write_req.ctx = NULL;
        stream->req.proceed_req = NULL;
        --conn->num_streams_req_streaming;
        check_run_blocked(conn);
        
        if (state == H2O_SEND_STATE_ERROR) {
            shutdown_stream(stream, H2O_HTTP3_ERROR_INTERNAL, H2O_HTTP3_ERROR_INTERNAL, 1);
            return;
        }
    }

    
    assert(stream->req_body->size == bytes_written);
    h2o_buffer_consume(&stream->req_body, bytes_written);
    stream->req.entity = h2o_iovec_init(NULL, 0);

    
    stream->read_blocked = 0;

    
    handle_buffered_input(stream, 1);
}

static void run_delayed(h2o_timer_t *timer)
{
    struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, timeout, timer);
    int made_progress;

    do {
        made_progress = 0;

        
        if (conn->num_streams.recv_body_unblocked + conn->num_streams_req_streaming == 0 && !h2o_linklist_is_empty(&conn->delayed_streams.recv_body_blocked)) {
            struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, link, conn->delayed_streams.recv_body_blocked.next);
            assert(stream->state == H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_BLOCKED);
            assert(stream->read_blocked);
            h2o_linklist_unlink(&stream->link);
            made_progress = 1;
            quicly_stream_set_receive_window(stream->quic, conn->super.ctx->globalconf->http3.active_stream_window_size);
            if (h2o_req_can_stream_request(&stream->req)) {
                
                ++conn->num_streams_req_streaming;
                stream->req.proceed_req = proceed_request_streaming;
                set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS, 0);
                h2o_process_request(&stream->req);
            } else {
                
                stream->read_blocked = 0;
                set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_UNBLOCKED, 0);
                handle_buffered_input(stream, 0);
                if (quicly_get_state(conn->h3.super.quic) >= QUICLY_STATE_CLOSING)
                    return;
            }
        }

        
        while (!h2o_linklist_is_empty(&conn->delayed_streams.req_streaming)) {
            struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, link, conn->delayed_streams.req_streaming.next);
            int is_end_stream = quicly_recvstate_transfer_complete(&stream->quic->recvstate);
            assert(stream->req.process_called);
            assert(stream->req.write_req.cb != NULL);
            assert(stream->req_body != NULL);
            assert(stream->req_body->size != 0 || is_end_stream);
            assert(!stream->read_blocked);
            h2o_linklist_unlink(&stream->link);
            stream->read_blocked = 1;
            made_progress = 1;
            if (stream->req.write_req.cb(stream->req.write_req.ctx, h2o_iovec_init(stream->req_body->bytes, stream->req_body->size), is_end_stream) != 0)
                shutdown_stream(stream, H2O_HTTP3_ERROR_INTERNAL, H2O_HTTP3_ERROR_INTERNAL, 0);
        }

        
        while (!h2o_linklist_is_empty(&conn->delayed_streams.pending)) {
            struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, link, conn->delayed_streams.pending.next);
            assert(stream->state == H2O_HTTP3_SERVER_STREAM_STATE_REQ_PENDING);
            assert(!stream->req.process_called);
            assert(!stream->read_blocked);
            h2o_linklist_unlink(&stream->link);
            made_progress = 1;
            set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS, 0);
            h2o_process_request(&stream->req);
        }

    } while (made_progress);
}

int handle_input_post_trailers(struct st_h2o_http3_server_stream_t *stream, const uint8_t **src, const uint8_t *src_end, const char **err_desc)
{
    h2o_http3_read_frame_t frame;
    int ret;

    
    if ((ret = h2o_http3_read_frame(&frame, 0, H2O_HTTP3_STREAM_TYPE_REQUEST, src, src_end, err_desc)) != 0)
        return ret;
    switch (frame.type) {
    case H2O_HTTP3_FRAME_TYPE_HEADERS:
    case H2O_HTTP3_FRAME_TYPE_DATA:
        return H2O_HTTP3_ERROR_FRAME_UNEXPECTED;
    default:
        break;
    }

    return 0;
}

static int handle_input_expect_data_payload(struct st_h2o_http3_server_stream_t *stream, const uint8_t **src, const uint8_t *src_end, const char **err_desc)
{
    size_t bytes_avail = src_end - *src;

    
    if (bytes_avail > stream->recvbuf.bytes_left_in_data_frame)
        bytes_avail = stream->recvbuf.bytes_left_in_data_frame;
    if (stream->req_body == NULL)
        h2o_buffer_init(&stream->req_body, &h2o_socket_buffer_prototype);
    if (!h2o_buffer_try_append(&stream->req_body, *src, bytes_avail))
        return H2O_HTTP3_ERROR_INTERNAL;
    stream->req.entity = h2o_iovec_init(stream->req_body->bytes, stream->req_body->size);
    stream->req.req_body_bytes_received += bytes_avail;
    stream->recvbuf.bytes_left_in_data_frame -= bytes_avail;
    *src += bytes_avail;

    if (stream->recvbuf.bytes_left_in_data_frame == 0)
        stream->recvbuf.handle_input = handle_input_expect_data;

    return 0;
}

int handle_input_expect_data(struct st_h2o_http3_server_stream_t *stream, const uint8_t **src, const uint8_t *src_end, const char **err_desc)
{
    h2o_http3_read_frame_t frame;
    int ret;

    
    if ((ret = h2o_http3_read_frame(&frame, 0, H2O_HTTP3_STREAM_TYPE_REQUEST, src, src_end, err_desc)) != 0)
        return ret;
    switch (frame.type) {
    case H2O_HTTP3_FRAME_TYPE_HEADERS:
        
        if (stream->tunnel != NULL) {
            *err_desc = "unexpected frame type";
            return H2O_HTTP3_ERROR_FRAME_UNEXPECTED;
        }
        
        stream->recvbuf.handle_input = handle_input_post_trailers;
        return 0;
    case H2O_HTTP3_FRAME_TYPE_DATA:
        if (stream->req.content_length != SIZE_MAX && stream->req.content_length - stream->req.req_body_bytes_received < frame.length) {
            
            shutdown_stream(stream, H2O_HTTP3_ERROR_EARLY_RESPONSE, H2O_HTTP3_ERROR_GENERAL_PROTOCOL, 0);
            return 0;
        }
        break;
    default:
        return 0;
    }

    
    if (frame.length != 0) {
        stream->recvbuf.handle_input = handle_input_expect_data_payload;
        stream->recvbuf.bytes_left_in_data_frame = frame.length;
    }

    return 0;
}

static int handle_input_expect_headers_send_http_error(struct st_h2o_http3_server_stream_t *stream, void (*sendfn)(h2o_req_t *, const char *, const char *, int), const char *reason, const char *body, const char **err_desc)

{
    if (!quicly_recvstate_transfer_complete(&stream->quic->recvstate))
        quicly_request_stop(stream->quic, H2O_HTTP3_ERROR_EARLY_RESPONSE);

    set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS, 0);
    sendfn(&stream->req, reason, body, 0);
    *err_desc = NULL;

    return 0;
}

static int handle_input_expect_headers(struct st_h2o_http3_server_stream_t *stream, const uint8_t **src, const uint8_t *src_end, const char **err_desc)
{
    struct st_h2o_http3_server_conn_t *conn = get_conn(stream);
    h2o_http3_read_frame_t frame;
    int header_exists_map = 0, ret;
    uint8_t header_ack[H2O_HPACK_ENCODE_INT_MAX_LENGTH];
    size_t header_ack_len;

    
    if ((ret = h2o_http3_read_frame(&frame, 0, H2O_HTTP3_STREAM_TYPE_REQUEST, src, src_end, err_desc)) != 0)
        return ret;
    if (frame.type != H2O_HTTP3_FRAME_TYPE_HEADERS) {
        switch (frame.type) {
        case H2O_HTTP3_FRAME_TYPE_DATA:
            return H2O_HTTP3_ERROR_FRAME_UNEXPECTED;
        default:
            break;
        }
        return 0;
    }
    stream->recvbuf.handle_input = handle_input_expect_data;

    
    if ((ret = h2o_qpack_parse_request(&stream->req.pool, get_conn(stream)->h3.qpack.dec, stream->quic->stream_id, &stream->req.input.method, &stream->req.input.scheme, &stream->req.input.authority, &stream->req.input.path, &stream->req.headers, &header_exists_map, &stream->req.content_length, NULL , header_ack, &header_ack_len, frame.payload, frame.length, err_desc)) != 0 && ret != H2O_HTTP2_ERROR_INVALID_HEADER_CHAR)




        return ret;
    if (header_ack_len != 0)
        h2o_http3_send_qpack_header_ack(&conn->h3, header_ack, header_ack_len);

    if (stream->req.input.scheme == NULL)
        stream->req.input.scheme = &H2O_URL_SCHEME_HTTPS;

    h2o_probe_log_request(&stream->req, stream->quic->stream_id);

    int is_connect = h2o_memis(stream->req.input.method.base, stream->req.input.method.len, H2O_STRLIT("CONNECT"));

    
    int expected_map = H2O_HPACK_PARSE_HEADERS_METHOD_EXISTS | H2O_HPACK_PARSE_HEADERS_AUTHORITY_EXISTS;
    if (!is_connect)
        expected_map |= H2O_HPACK_PARSE_HEADERS_SCHEME_EXISTS | H2O_HPACK_PARSE_HEADERS_PATH_EXISTS;
    if (header_exists_map != expected_map) {
        shutdown_stream(stream, H2O_HTTP3_ERROR_GENERAL_PROTOCOL, H2O_HTTP3_ERROR_GENERAL_PROTOCOL, 0);
        return 0;
    }

    
    if (ret == H2O_HTTP2_ERROR_INVALID_HEADER_CHAR)
        return handle_input_expect_headers_send_http_error(stream, h2o_send_error_400, "Invalid Request", *err_desc, err_desc);

    
    if (stream->req.content_length != SIZE_MAX && stream->req.content_length > conn->super.ctx->globalconf->max_request_entity_size)
        return handle_input_expect_headers_send_http_error(stream, h2o_send_error_413, "Request Entity Too Large", "request entity is too large", err_desc);

    
    assert(!h2o_linklist_is_linked(&stream->scheduler.link));
    if (!stream->received_priority_update) {
        ssize_t index;
        if ((index = h2o_find_header(&stream->req.headers, H2O_TOKEN_PRIORITY, -1)) != -1) {
            h2o_iovec_t *value = &stream->req.headers.entries[index].value;
            h2o_absprio_parse_priority(value->base, value->len, &stream->scheduler.priority);
        }
    }

    
    if (is_connect) {
        if (stream->req.content_length != SIZE_MAX)
            return handle_input_expect_headers_send_http_error(stream, h2o_send_error_400, "Invalid Request", "CONNECT request cannot have request body", err_desc);
        set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS, 0);
        stream->tunnel = h2o_mem_alloc(sizeof(*stream->tunnel));
        stream->tunnel->tunnel = NULL;
        stream->tunnel->stream = stream;
        stream->tunnel->up.is_inflight = 0;
        stream->tunnel->up.delayed_write = (h2o_timer_t){.cb = tunnel_write_delayed};
        h2o_process_request(&stream->req);
        return 0;
    }

    
    set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_RECV_BODY_BEFORE_BLOCK, 0);

    return 0;
}

static void write_response(struct st_h2o_http3_server_stream_t *stream)
{
    h2o_iovec_t frame = h2o_qpack_flatten_response(get_conn(stream)->h3.qpack.enc, &stream->req.pool, stream->quic->stream_id, NULL, stream->req.res.status, stream->req.res.headers.entries, stream->req.res.headers.size, &get_conn(stream)->super.ctx->globalconf->server_name, stream->req.res.content_length);



    h2o_vector_reserve(&stream->req.pool, &stream->sendbuf.vecs, stream->sendbuf.vecs.size + 1);
    struct st_h2o_http3_server_sendvec_t *vec = stream->sendbuf.vecs.entries + stream->sendbuf.vecs.size++;
    h2o_sendvec_init_immutable(&vec->vec, frame.base, frame.len);
    vec->entity_offset = UINT64_MAX;
    stream->sendbuf.final_size += frame.len;
}

static size_t flatten_data_frame_header(struct st_h2o_http3_server_stream_t *stream, struct st_h2o_http3_server_sendvec_t *dst, size_t payload_size)
{
    size_t header_size = 0;

    
    stream->sendbuf.data_frame_header_buf[header_size++] = H2O_HTTP3_FRAME_TYPE_DATA;
    header_size = quicly_encodev(stream->sendbuf.data_frame_header_buf + header_size, payload_size) - stream->sendbuf.data_frame_header_buf;

    
    h2o_sendvec_init_raw(&dst->vec, stream->sendbuf.data_frame_header_buf, header_size);
    dst->entity_offset = UINT64_MAX;

    return header_size;
}

static void shutdown_by_generator(struct st_h2o_http3_server_stream_t *stream)
{
    quicly_sendstate_shutdown(&stream->quic->sendstate, stream->sendbuf.final_size);
    if (stream->sendbuf.vecs.size == 0)
        set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT, 1);
}

static void finalize_do_send(struct st_h2o_http3_server_stream_t *stream)
{
    quicly_stream_sync_sendbuf(stream->quic, 1);
    if (!stream->proceed_while_sending)
        h2o_quic_schedule_timer(&get_conn(stream)->h3.super);
}

static void do_send(h2o_ostream_t *_ostr, h2o_req_t *_req, h2o_sendvec_t *bufs, size_t bufcnt, h2o_send_state_t send_state)
{
    struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, ostr_final, _ostr);

    assert(&stream->req == _req);

    stream->proceed_requested = 0;

    if (stream->state == H2O_HTTP3_SERVER_STREAM_STATE_SEND_HEADERS) {
        write_response(stream);
        h2o_probe_log_response(&stream->req, stream->quic->stream_id, NULL);
        set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_SEND_BODY, 1);
    } else {
        assert(stream->state == H2O_HTTP3_SERVER_STREAM_STATE_SEND_BODY);
        assert(quicly_sendstate_is_open(&stream->quic->sendstate));
    }

    
    if (bufcnt != 0) {
        h2o_vector_reserve(&stream->req.pool, &stream->sendbuf.vecs, stream->sendbuf.vecs.size + 1 + bufcnt);
        uint64_t prev_body_size = stream->sendbuf.final_body_size;
        for (size_t i = 0; i != bufcnt; ++i) {
            
            struct st_h2o_http3_server_sendvec_t *dst = stream->sendbuf.vecs.entries + stream->sendbuf.vecs.size + i + 1;
            dst->vec = bufs[i];
            dst->entity_offset = stream->sendbuf.final_body_size;
            stream->sendbuf.final_body_size += bufs[i].len;
            
            if (bufs[i].callbacks->update_refcnt != NULL)
                bufs[i].callbacks->update_refcnt(bufs + i, &stream->req, 1);
        }
        uint64_t payload_size = stream->sendbuf.final_body_size - prev_body_size;
        
        size_t header_size = flatten_data_frame_header(stream, stream->sendbuf.vecs.entries + stream->sendbuf.vecs.size, payload_size);
        
        stream->sendbuf.vecs.size += 1 + bufcnt;
        stream->sendbuf.final_size += header_size + payload_size;
    }

    switch (send_state) {
    case H2O_SEND_STATE_IN_PROGRESS:
        break;
    case H2O_SEND_STATE_FINAL:
    case H2O_SEND_STATE_ERROR:
        
        shutdown_by_generator(stream);
        break;
    }

    finalize_do_send(stream);
}

static void do_send_informational(h2o_ostream_t *_ostr, h2o_req_t *_req)
{
    struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, ostr_final, _ostr);
    assert(&stream->req == _req);

    write_response(stream);

    finalize_do_send(stream);
}

static void tunnel_on_read(h2o_tunnel_t *_tunnel, const char *err, const void *bytes, size_t len)
{
    struct st_h2o_http3_server_stream_t *stream = _tunnel->data;

    stream->proceed_requested = 0;

    
    if (len != 0) {
        h2o_vector_reserve(&stream->req.pool, &stream->sendbuf.vecs, stream->sendbuf.vecs.size + 2);
        
        size_t header_size = flatten_data_frame_header(stream, stream->sendbuf.vecs.entries + stream->sendbuf.vecs.size++, len);
        
        struct st_h2o_http3_server_sendvec_t *vec = stream->sendbuf.vecs.entries + stream->sendbuf.vecs.size++;
        h2o_sendvec_init_raw(&vec->vec, bytes, len);
        vec->entity_offset = stream->sendbuf.final_body_size;
        stream->sendbuf.final_body_size += len;
        
        stream->sendbuf.final_size += header_size + len;
    }

    
    if (err != NULL) {
        retain_sendvecs(stream);
        stream->tunnel->tunnel->destroy(stream->tunnel->tunnel);
        stream->tunnel->tunnel = NULL;
        shutdown_by_generator(stream);
    }

    finalize_do_send(stream);
}

void tunnel_write(struct st_h2o_http3_server_stream_t *stream)
{
    size_t bytes_to_send;

    assert(!stream->tunnel->up.is_inflight);

    if ((bytes_to_send = stream->req_body->size) == 0)
        return;

    
    if (bytes_to_send > sizeof(stream->tunnel->up.bytes_inflight))
        bytes_to_send = sizeof(stream->tunnel->up.bytes_inflight);
    memcpy(stream->tunnel->up.bytes_inflight, stream->req_body->bytes, bytes_to_send);
    stream->tunnel->up.is_inflight = 1;
    h2o_buffer_consume(&stream->req_body, bytes_to_send);

    
    stream->tunnel->tunnel->write_(stream->tunnel->tunnel, stream->tunnel->up.bytes_inflight, bytes_to_send);
}

void tunnel_write_delayed(h2o_timer_t *timer)
{
    struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_tunnel_t, up.delayed_write, timer)->stream;
    tunnel_write(stream);
}

static void tunnel_on_write_complete(h2o_tunnel_t *tunnel, const char *err)
{
    struct st_h2o_http3_server_stream_t *stream = tunnel->data;

    assert(stream->tunnel->up.is_inflight);
    stream->tunnel->up.is_inflight = 0;

    if (err != NULL) {
        retain_sendvecs(stream);
        stream->tunnel->tunnel->destroy(stream->tunnel->tunnel);
        stream->tunnel->tunnel = NULL;
        shutdown_by_generator(stream);
        return;
    }

    tunnel_write(stream);
}

static void establish_tunnel(h2o_req_t *req, h2o_tunnel_t *tunnel, uint64_t idle_timeout)
{
    struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, req, req);

    if (stream->tunnel == NULL) {
        
        return;
    }
    stream->tunnel->tunnel = tunnel;
    tunnel->data = stream;
    tunnel->on_write_complete = tunnel_on_write_complete;
    tunnel->on_read = tunnel_on_read;

    write_response(stream);
    h2o_probe_log_response(&stream->req, stream->quic->stream_id, stream->tunnel->tunnel);
    set_state(stream, H2O_HTTP3_SERVER_STREAM_STATE_SEND_BODY, 1);

    finalize_do_send(stream);
    assert(!stream->proceed_while_sending);
    stream->proceed_requested = 1; 

    if (stream->req_body != NULL)
        tunnel_write(stream);
}

static int handle_priority_update_frame(struct st_h2o_http3_server_conn_t *conn, const h2o_http3_priority_update_frame_t *frame)
{
    if (frame->element_is_push)
        return H2O_HTTP3_ERROR_GENERAL_PROTOCOL;

    
    quicly_stream_t *qs;
    if (quicly_get_or_open_stream(conn->h3.super.quic, frame->element, &qs) != 0)
        return H2O_HTTP3_ERROR_ID;
    if (qs == NULL)
        return 0;

    
    struct st_h2o_http3_server_stream_t *stream = qs->data;
    assert(stream != NULL);
    stream->received_priority_update = 1;
    if (h2o_linklist_is_linked(&stream->scheduler.link)) {
        req_scheduler_deactivate(&conn->scheduler.reqs, &stream->scheduler);
        stream->scheduler.priority = frame->priority; 
        req_scheduler_activate(&conn->scheduler.reqs, &stream->scheduler, req_scheduler_compare_stream_id);
    } else {
        stream->scheduler.priority = frame->priority; 
    }

    return 0;
}

static void handle_control_stream_frame(h2o_http3_conn_t *_conn, uint8_t type, const uint8_t *payload, size_t len)
{
    struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, _conn);
    int err;
    const char *err_desc = NULL;

    if (!h2o_http3_has_received_settings(&conn->h3)) {
        if (type != H2O_HTTP3_FRAME_TYPE_SETTINGS) {
            err = H2O_HTTP3_ERROR_MISSING_SETTINGS;
            goto Fail;
        }
        if ((err = h2o_http3_handle_settings_frame(&conn->h3, payload, len, &err_desc)) != 0)
            goto Fail;
        assert(h2o_http3_has_received_settings(&conn->h3));
    } else {
        switch (type) {
        case H2O_HTTP3_FRAME_TYPE_SETTINGS:
            err = H2O_HTTP3_ERROR_FRAME_UNEXPECTED;
            err_desc = "unexpected SETTINGS frame";
            goto Fail;
        case H2O_HTTP3_FRAME_TYPE_PRIORITY_UPDATE: {
            h2o_http3_priority_update_frame_t frame;
            if ((err = h2o_http3_decode_priority_update_frame(&frame, payload, len, &err_desc)) != 0)
                goto Fail;
            if ((err = handle_priority_update_frame(conn, &frame)) != 0) {
                err_desc = "invalid PRIORITY_UPDATE frame";
                goto Fail;
            }
        } break;
        default:
            break;
        }
    }

    return;
Fail:
    h2o_quic_close_connection(&conn->h3.super, err, err_desc);
}

static int stream_open_cb(quicly_stream_open_t *self, quicly_stream_t *qs)
{
    static const quicly_stream_callbacks_t callbacks = {on_stream_destroy, on_send_shift, on_send_emit, on_send_stop,      on_receive,    on_receive_reset};

    
    if (quicly_stream_is_unidirectional(qs->stream_id)) {
        h2o_http3_on_create_unidirectional_stream(qs);
        return 0;
    }

    assert(quicly_stream_is_client_initiated(qs->stream_id));

    struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, *quicly_get_data(qs->conn));

    
    struct st_h2o_http3_server_stream_t *stream = h2o_mem_alloc(sizeof(*stream));
    stream->quic = qs;
    h2o_buffer_init(&stream->recvbuf.buf, &h2o_socket_buffer_prototype);
    stream->recvbuf.handle_input = handle_input_expect_headers;
    memset(&stream->sendbuf, 0, sizeof(stream->sendbuf));
    stream->state = H2O_HTTP3_SERVER_STREAM_STATE_RECV_HEADERS;
    stream->link = (h2o_linklist_t){NULL};
    stream->ostr_final = (h2o_ostream_t){NULL, do_send, NULL, do_send_informational};
    stream->scheduler.link = (h2o_linklist_t){NULL};
    stream->scheduler.priority = h2o_absprio_default;
    stream->scheduler.call_cnt = 0;

    stream->read_blocked = 0;
    stream->proceed_requested = 0;
    stream->proceed_while_sending = 0;
    stream->received_priority_update = 0;
    stream->req_disposed = 0;
    stream->req_body = NULL;

    stream->tunnel = NULL;

    h2o_init_request(&stream->req, &conn->super, NULL);
    stream->req.version = 0x0300;
    stream->req._ostr_top = &stream->ostr_final;
    stream->req.establish_tunnel = establish_tunnel;

    stream->quic->data = stream;
    stream->quic->callbacks = &callbacks;

    ++*get_state_counter(get_conn(stream), stream->state);
    return 0;
}

static quicly_stream_open_t on_stream_open = {stream_open_cb};

static void unblock_conn_blocked_streams(struct st_h2o_http3_server_conn_t *conn)
{
    conn->scheduler.uni.active |= conn->scheduler.uni.conn_blocked;
    conn->scheduler.uni.conn_blocked = 0;
    req_scheduler_unblock_conn_blocked(&conn->scheduler.reqs, req_scheduler_compare_stream_id);
}

static int scheduler_can_send(quicly_stream_scheduler_t *sched, quicly_conn_t *qc, int conn_is_saturated)
{
    struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, *quicly_get_data(qc));

    if (!conn_is_saturated) {
        
        unblock_conn_blocked_streams(conn);
    } else {
        
    }

    if (conn->scheduler.uni.active != 0)
        return 1;
    if (conn->scheduler.reqs.active.smallest_urgency < H2O_ABSPRIO_NUM_URGENCY_LEVELS)
        return 1;

    return 0;
}

static int scheduler_do_send(quicly_stream_scheduler_t *sched, quicly_conn_t *qc, quicly_send_context_t *s)
{
    struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, *quicly_get_data(qc));
    int ret = 0;

    while (quicly_can_send_data(conn->h3.super.quic, s)) {
        
        if (conn->scheduler.uni.active != 0) {
            static const ptrdiff_t stream_offsets[] = {
                offsetof(struct st_h2o_http3_server_conn_t, h3._control_streams.egress.control), offsetof(struct st_h2o_http3_server_conn_t, h3._control_streams.egress.qpack_encoder), offsetof(struct st_h2o_http3_server_conn_t, h3._control_streams.egress.qpack_decoder)};

            
            struct st_h2o_http3_egress_unistream_t *stream = NULL;
            size_t i;
            for (i = 0; i != sizeof(stream_offsets) / sizeof(stream_offsets[0]); ++i) {
                stream = *(void **)((char *)conn + stream_offsets[i]);
                if ((conn->scheduler.uni.active & (1 << stream->quic->stream_id)) != 0)
                    break;
            }
            assert(i != sizeof(stream_offsets) / sizeof(stream_offsets[0]) && "we should have found one stream");
            
            if (quicly_is_blocked(conn->h3.super.quic) && !quicly_stream_can_send(stream->quic, 0)) {
                conn->scheduler.uni.active &= ~(1 << stream->quic->stream_id);
                conn->scheduler.uni.conn_blocked |= 1 << stream->quic->stream_id;
                continue;
            }
            
            if ((ret = quicly_send_stream(stream->quic, s)) != 0)
                goto Exit;
            
            conn->scheduler.uni.active &= ~(1 << stream->quic->stream_id);
            if (quicly_stream_can_send(stream->quic, 1)) {
                uint16_t *slot = &conn->scheduler.uni.active;
                if (quicly_is_blocked(conn->h3.super.quic) && !quicly_stream_can_send(stream->quic, 0))
                    slot = &conn->scheduler.uni.conn_blocked;
                *slot |= 1 << stream->quic->stream_id;
            }
        } else if (conn->scheduler.reqs.active.smallest_urgency < H2O_ABSPRIO_NUM_URGENCY_LEVELS) {
            
            h2o_linklist_t *anchor = &conn->scheduler.reqs.active.urgencies[conn->scheduler.reqs.active.smallest_urgency].high;
            if (h2o_linklist_is_empty(anchor)) {
                anchor = &conn->scheduler.reqs.active.urgencies[conn->scheduler.reqs.active.smallest_urgency].low;
                assert(!h2o_linklist_is_empty(anchor));
            }
            struct st_h2o_http3_server_stream_t *stream = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_stream_t, scheduler.link, anchor->next);
            
            if (quicly_is_blocked(conn->h3.super.quic) && !quicly_stream_can_send(stream->quic, 0)) {
                req_scheduler_conn_blocked(&conn->scheduler.reqs, &stream->scheduler);
                continue;
            }
            
            if ((ret = quicly_send_stream(stream->quic, s)) != 0)
                goto Exit;
            ++stream->scheduler.call_cnt;
            
            if (stream->proceed_while_sending) {
                assert(stream->proceed_requested);
                if (stream->tunnel != NULL) {
                    if (quicly_sendstate_is_open(&stream->quic->sendstate)) {
                        stream->tunnel->tunnel->proceed_read(stream->tunnel->tunnel);
                    } else {
                        assert(stream->tunnel->tunnel == NULL);
                    }
                } else {
                    h2o_proceed_response(&stream->req);
                }
                stream->proceed_while_sending = 0;
            }
            
            if (quicly_stream_can_send(stream->quic, 1)) {
                if (quicly_is_blocked(conn->h3.super.quic) && !quicly_stream_can_send(stream->quic, 0)) {
                    
                    req_scheduler_conn_blocked(&conn->scheduler.reqs, &stream->scheduler);
                } else {
                    
                    req_scheduler_setup_for_next(&conn->scheduler.reqs, &stream->scheduler, req_scheduler_compare_stream_id);
                }
            } else {
                
                req_scheduler_deactivate(&conn->scheduler.reqs, &stream->scheduler);
            }
        } else {
            break;
        }
    }

Exit:
    return ret;
}

static int scheduler_update_state(struct st_quicly_stream_scheduler_t *sched, quicly_stream_t *qs)
{
    struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, *quicly_get_data(qs->conn));
    enum { DEACTIVATE, ACTIVATE, CONN_BLOCKED } new_state;

    if (quicly_stream_can_send(qs, 1)) {
        if (quicly_is_blocked(conn->h3.super.quic) && !quicly_stream_can_send(qs, 0)) {
            new_state = CONN_BLOCKED;
        } else {
            new_state = ACTIVATE;
        }
    } else {
        new_state = DEACTIVATE;
    }

    if (quicly_stream_is_unidirectional(qs->stream_id)) {
        assert(qs->stream_id < sizeof(uint16_t) * 8);
        uint16_t mask = (uint16_t)1 << qs->stream_id;
        switch (new_state) {
        case DEACTIVATE:
            conn->scheduler.uni.active &= ~mask;
            conn->scheduler.uni.conn_blocked &= ~mask;
            break;
        case ACTIVATE:
            conn->scheduler.uni.active |= mask;
            conn->scheduler.uni.conn_blocked &= ~mask;
            break;
        case CONN_BLOCKED:
            conn->scheduler.uni.active &= ~mask;
            conn->scheduler.uni.conn_blocked |= mask;
            break;
        }
    } else {
        struct st_h2o_http3_server_stream_t *stream = qs->data;
        if (stream->proceed_while_sending)
            return 0;
        switch (new_state) {
        case DEACTIVATE:
            req_scheduler_deactivate(&conn->scheduler.reqs, &stream->scheduler);
            break;
        case ACTIVATE:
            req_scheduler_activate(&conn->scheduler.reqs, &stream->scheduler, req_scheduler_compare_stream_id);
            break;
        case CONN_BLOCKED:
            req_scheduler_conn_blocked(&conn->scheduler.reqs, &stream->scheduler);
            break;
        }
    }

    return 0;
}

static quicly_stream_scheduler_t scheduler = {scheduler_can_send, scheduler_do_send, scheduler_update_state};

static void on_h3_destroy(h2o_quic_conn_t *h3_)
{
    h2o_http3_conn_t *h3 = (h2o_http3_conn_t *)h3_;
    struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, h3, h3);
    quicly_stats_t stats;

    H2O_PROBE_CONN0(H3S_DESTROY, &conn->super);

    if (quicly_get_stats(h3_->quic, &stats) == 0) {

        H2O_QUIC_AGGREGATED_STATS_APPLY(ACC);

    }

    
    h2o_linklist_unlink(&conn->_conns);
    if (h2o_timer_is_linked(&conn->timeout))
        h2o_timer_unlink(&conn->timeout);
    h2o_http3_dispose_conn(&conn->h3);

    
    assert(conn->num_streams.recv_headers == 0);
    assert(conn->num_streams.req_pending == 0);
    assert(conn->num_streams.send_headers == 0);
    assert(conn->num_streams.send_body == 0);
    assert(conn->num_streams.close_wait == 0);
    assert(conn->num_streams_req_streaming == 0);
    assert(h2o_linklist_is_empty(&conn->delayed_streams.recv_body_blocked));
    assert(h2o_linklist_is_empty(&conn->delayed_streams.req_streaming));
    assert(h2o_linklist_is_empty(&conn->delayed_streams.pending));
    assert(conn->scheduler.reqs.active.smallest_urgency >= H2O_ABSPRIO_NUM_URGENCY_LEVELS);
    assert(h2o_linklist_is_empty(&conn->scheduler.reqs.conn_blocked));

    
    free(conn);
}

h2o_http3_conn_t *h2o_http3_server_accept(h2o_http3_server_ctx_t *ctx, quicly_address_t *destaddr, quicly_address_t *srcaddr, quicly_decoded_packet_t *packet, quicly_address_token_plaintext_t *address_token, int skip_tracing, const h2o_http3_conn_callbacks_t *h3_callbacks)

{
    static const h2o_conn_callbacks_t conn_callbacks = {
        .get_sockname = get_sockname, .get_peername = get_peername, .get_ptls = get_ptls, .skip_tracing = get_skip_tracing, .num_reqs_inflight = num_reqs_inflight, .get_tracer = get_tracer, .log_ = {{





            .transport = {
                    .cc_name = log_cc_name, .delivery_rate = log_delivery_rate, }, .ssl = {



                    .protocol_version = log_tls_protocol_version, .session_reused = log_session_reused, .cipher = log_cipher, .cipher_bits = log_cipher_bits, .session_id = log_session_id, .server_name = log_server_name, .negotiated_protocol = log_negotiated_protocol, }, .http3 = {








                    .stream_id = log_stream_id, .quic_stats = log_quic_stats, .quic_version = log_quic_version, }, }}, };





    
    struct st_h2o_http3_server_conn_t *conn = (void *)h2o_create_connection( sizeof(*conn), ctx->accept_ctx->ctx, ctx->accept_ctx->hosts, h2o_gettimeofday(ctx->accept_ctx->ctx->loop), &conn_callbacks);
    h2o_http3_init_conn(&conn->h3, &ctx->super, h3_callbacks, &ctx->qpack);
    conn->handshake_properties = (ptls_handshake_properties_t){{{{NULL}}}};
    h2o_linklist_init_anchor(&conn->delayed_streams.recv_body_blocked);
    h2o_linklist_init_anchor(&conn->delayed_streams.req_streaming);
    h2o_linklist_init_anchor(&conn->delayed_streams.pending);
    h2o_timer_init(&conn->timeout, run_delayed);
    memset(&conn->num_streams, 0, sizeof(conn->num_streams));
    conn->num_streams_req_streaming = 0;
    req_scheduler_init(&conn->scheduler.reqs);
    conn->scheduler.uni.active = 0;
    conn->scheduler.uni.conn_blocked = 0;
    memset(&conn->_conns, 0, sizeof(conn->_conns));

    

    unsigned orig_skip_tracing = ptls_default_skip_tracing;
    ptls_default_skip_tracing = skip_tracing;

    quicly_conn_t *qconn;
    int accept_ret = quicly_accept(&qconn, ctx->super.quic, &destaddr->sa, &srcaddr->sa, packet, address_token, &ctx->super.next_cid, &conn->handshake_properties);

    ptls_default_skip_tracing = orig_skip_tracing;

    if (accept_ret != 0) {
        h2o_http3_conn_t *ret = NULL;
        if (accept_ret == QUICLY_ERROR_DECRYPTION_FAILED)
            ret = (h2o_http3_conn_t *)H2O_QUIC_ACCEPT_CONN_DECRYPTION_FAILED;
        h2o_http3_dispose_conn(&conn->h3);
        free(conn);
        return ret;
    }
    ++ctx->super.next_cid.master_id; 
    h2o_linklist_insert(&ctx->accept_ctx->ctx->http3._conns, &conn->_conns);
    h2o_http3_setup(&conn->h3, qconn);

    H2O_PROBE_CONN(H3S_ACCEPT, &conn->super, &conn->super, conn->h3.super.quic, h2o_conn_get_uuid(&conn->super));

    h2o_quic_send(&conn->h3.super);

    return &conn->h3;
}

void h2o_http3_server_amend_quicly_context(h2o_globalconf_t *conf, quicly_context_t *quic)
{
    quic->transport_params.max_data = conf->http3.active_stream_window_size;
    quic->transport_params.max_streams_uni = 10;
    quic->transport_params.max_stream_data.bidi_remote = H2O_HTTP3_INITIAL_REQUEST_STREAM_WINDOW_SIZE;
    quic->transport_params.max_idle_timeout = conf->http3.idle_timeout;
    quic->transport_params.min_ack_delay_usec = conf->http3.allow_delayed_ack ? 0 : UINT64_MAX;
    quic->ack_frequency = conf->http3.ack_frequency;
    quic->stream_open = &on_stream_open;
    quic->stream_scheduler = &scheduler;
}

static void graceful_shutdown_close_stragglers(h2o_timer_t *entry)
{
    h2o_context_t *ctx = H2O_STRUCT_FROM_MEMBER(h2o_context_t, http3._graceful_shutdown_timeout, entry);
    h2o_linklist_t *node, *next;

    
    for (node = ctx->http3._conns.next; node != &ctx->http3._conns; node = next) {
        struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, _conns, node);
        next = node->next;
        h2o_quic_close_connection(&conn->h3.super, 0, "shutting down");
    }

    ctx->http3._graceful_shutdown_timeout.cb = NULL;
}

static void graceful_shutdown_resend_goaway(h2o_timer_t *entry)
{
    h2o_context_t *ctx = H2O_STRUCT_FROM_MEMBER(h2o_context_t, http3._graceful_shutdown_timeout, entry);
    h2o_linklist_t *node;
    int do_close_stragglers = 0;

    
    for (node = ctx->http3._conns.next; node != &ctx->http3._conns; node = node->next) {
        struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, _conns, node);
        if (conn->h3.state < H2O_HTTP3_CONN_STATE_HALF_CLOSED && quicly_get_state(conn->h3.super.quic) == QUICLY_STATE_CONNECTED) {
            quicly_stream_id_t next_stream_id = quicly_get_remote_next_stream_id(conn->h3.super.quic, 0 );
            
            quicly_stream_id_t max_stream_id = next_stream_id < 4 ? 0  : next_stream_id - 4;
            h2o_http3_send_goaway_frame(&conn->h3, max_stream_id);
            conn->h3.state = H2O_HTTP3_CONN_STATE_HALF_CLOSED;
            do_close_stragglers = 1;
        }
    }

    
    if (do_close_stragglers && ctx->globalconf->http3.graceful_shutdown_timeout > 0) {
        ctx->http3._graceful_shutdown_timeout.cb = graceful_shutdown_close_stragglers;
        h2o_timer_link(ctx->loop, ctx->globalconf->http3.graceful_shutdown_timeout, &ctx->http3._graceful_shutdown_timeout);
    } else {
        ctx->http3._graceful_shutdown_timeout.cb = NULL;
    }
}

static void initiate_graceful_shutdown(h2o_context_t *ctx)
{
    h2o_linklist_t *node;

    
    if (ctx->http3._graceful_shutdown_timeout.cb != NULL)
        return;
    ctx->http3._graceful_shutdown_timeout.cb = graceful_shutdown_resend_goaway;

    for (node = ctx->http3._conns.next; node != &ctx->http3._conns; node = node->next) {
        struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, _conns, node);
        
        if (conn->h3.state < H2O_HTTP3_CONN_STATE_HALF_CLOSED && quicly_get_state(conn->h3.super.quic) == QUICLY_STATE_CONNECTED) {
            
            h2o_http3_send_goaway_frame(&conn->h3, (UINT64_C(1) << 62) - 4);
        }
    }
    h2o_timer_link(ctx->loop, 1000, &ctx->http3._graceful_shutdown_timeout);
}

struct foreach_request_ctx {
    int (*cb)(h2o_req_t *req, void *cbdata);
    void *cbdata;
};

static int foreach_request_per_conn(void *_ctx, quicly_stream_t *qs)
{
    struct foreach_request_ctx *ctx = _ctx;

    
    if (!(quicly_stream_is_client_initiated(qs->stream_id) && !quicly_stream_is_unidirectional(qs->stream_id)))
        return 0;

    struct st_h2o_http3_server_stream_t *stream = qs->data;
    assert(stream->quic == qs);

    if (stream->state == H2O_HTTP3_SERVER_STREAM_STATE_CLOSE_WAIT)
        return 0;
    return ctx->cb(&stream->req, ctx->cbdata);
}

static int foreach_request(h2o_context_t *ctx, int (*cb)(h2o_req_t *req, void *cbdata), void *cbdata)
{
    struct foreach_request_ctx foreach_ctx = {.cb = cb, .cbdata = cbdata};

    for (h2o_linklist_t *node = ctx->http3._conns.next; node != &ctx->http3._conns; node = node->next) {
        struct st_h2o_http3_server_conn_t *conn = H2O_STRUCT_FROM_MEMBER(struct st_h2o_http3_server_conn_t, _conns, node);
        quicly_foreach_stream(conn->h3.super.quic, &foreach_ctx, foreach_request_per_conn);
    }

    return 0;
}

const h2o_protocol_callbacks_t H2O_HTTP3_SERVER_CALLBACKS = {initiate_graceful_shutdown, foreach_request};
const h2o_http3_conn_callbacks_t H2O_HTTP3_CONN_CALLBACKS = {{on_h3_destroy}, handle_control_stream_frame};
