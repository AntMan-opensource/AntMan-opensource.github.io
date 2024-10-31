

























typedef struct tlstran_pipe tlstran_pipe;
typedef struct tlstran_ep   tlstran_ep;

static inline void tlstran_pipe_send_start_v4(tlstran_pipe *p, nni_msg *msg, nni_aio *aio);
static inline void tlstran_pipe_send_start_v5(tlstran_pipe *p, nni_msg *msg, nni_aio *aio);


struct tlstran_pipe {
	nng_stream *conn;
	nni_pipe   *npipe; 
	conf       *conf;
	
	
	size_t          rcvmax;
	size_t          gotrxhead;
	size_t          wantrxhead;
	bool            closed;
	bool            busy; 
	uint8_t         txlen[NANO_MIN_PACKET_LEN];
	uint8_t         rxlen[NNI_NANO_MAX_HEADER_SIZE];
	uint8_t        *conn_buf;
	uint8_t        *qos_buf;
	nni_aio        *txaio;
	nni_aio        *rxaio;
	nni_aio        *qsaio;
	nni_aio        *rpaio;
	nni_aio        *negoaio;
	nni_lmq         rslmq;
	nni_msg        *rxmsg, *cnmsg;
	nni_mtx         mtx;
	conn_param     *tcp_cparam;
	nni_list        recvq;
	nni_list        sendq;
	nni_list_node   node;
	tlstran_ep     *ep;
	nni_atomic_flag reaped;
	nni_reap_node   reap;
	
	
	
	uint16_t qrecv_quota;
	uint32_t qsend_quota;
};

struct tlstran_ep {
	nni_mtx mtx;
	
	size_t               rcvmax;
	conf *               conf;
	bool                 fini;
	bool                 started;
	bool                 closed;
	nng_url *            url;
	nng_sockaddr         src;
	nng_sockaddr         sa;
	int                  refcnt; 
	int                  authmode;
	nni_aio *            useraio;
	nni_aio *            connaio;
	nni_aio *            timeaio;
	nni_list             busypipes; 
	nni_list             waitpipes; 
	nni_list             negopipes; 
	nni_reap_node        reap;
	nng_stream_listener *listener;

	nni_stat_item st_rcv_max;

};

static void tlstran_pipe_send_start(tlstran_pipe *);
static void tlstran_pipe_recv_start(tlstran_pipe *);
static void tlstran_pipe_qos_send_cb(void *);
static void tlstran_pipe_send_cb(void *);
static void tlstran_pipe_recv_cb(void *);
static void tlstran_pipe_nego_cb(void *);
static void tlstran_ep_fini(void *);
static void tlstran_pipe_fini(void *);

static inline void tlstran_pipe_send_start_v5(tlstran_pipe *p, nni_msg *msg, nni_aio *aio);

static nni_reap_list tlstran_ep_reap_list = {
	.rl_offset = offsetof(tlstran_ep, reap), .rl_func   = tlstran_ep_fini, };


static nni_reap_list tlstran_pipe_reap_list = {
	.rl_offset = offsetof(tlstran_pipe, reap), .rl_func   = tlstran_pipe_fini, };


static void tlstran_init(void)
{
}

static void tlstran_fini(void)
{
}

static void tlstran_pipe_close(void *arg)
{
	tlstran_pipe *p = arg;
	

	nni_mtx_lock(&p->mtx);
	p->closed = true;
	log_trace(" ###### tlstran_pipe_close ###### ");
	

	nni_lmq_flush(&p->rslmq);
	nni_mtx_unlock(&p->mtx);

	nni_aio_close(p->rxaio);
	nni_aio_close(p->rpaio);
	nni_aio_close(p->txaio);
	nni_aio_close(p->qsaio);
	nni_aio_close(p->negoaio);

	nng_stream_close(p->conn);
}

static void tlstran_pipe_stop(void *arg)
{
	tlstran_pipe *p = arg;
	log_trace(" ###### tlstran_pipe_stop ###### ");
	p->tcp_cparam = NULL;
	nni_aio_stop(p->qsaio);
	nni_aio_stop(p->rpaio);
	nni_aio_stop(p->rxaio);
	nni_aio_stop(p->txaio);
	nni_aio_stop(p->negoaio);
}

static int tlstran_pipe_init(void *arg, nni_pipe *npipe)
{
	log_trace("************tlstran_pipe_init************");
	tlstran_pipe *p = arg;

	nni_pipe_set_conn_param(npipe, p->tcp_cparam);
	p->npipe    = npipe;

	if (!p->conf->sqlite.enable) {
		nni_qos_db_init_id_hash(npipe->nano_qos_db);
	}

	p->conn_buf = NULL;
	p->busy     = false;

	nni_lmq_init(&p->rslmq, 16);
	p->qos_buf = nng_zalloc(16 + NNI_NANO_MAX_PACKET_SIZE);
	return (0);
}

static void tlstran_pipe_fini(void *arg)
{
	tlstran_pipe *p = arg;
	tlstran_ep *  ep;

	tlstran_pipe_stop(p);
	if ((ep = p->ep) != NULL) {
		nni_mtx_lock(&ep->mtx);
		nni_list_node_remove(&p->node);
		ep->refcnt--;
		if (ep->fini && (ep->refcnt == 0)) {
			nni_reap(&tlstran_ep_reap_list, ep);
		}
		nni_mtx_unlock(&ep->mtx);
	}

	nng_free(p->qos_buf, 16 + NNI_NANO_MAX_PACKET_SIZE);
	nni_aio_free(p->qsaio);
	nni_aio_free(p->rpaio);
	nni_aio_free(p->rxaio);
	nni_aio_free(p->txaio);
	nni_aio_free(p->negoaio);
	nng_stream_free(p->conn);
	if (p->rxmsg != NULL)
		nni_msg_free(p->rxmsg);
	nni_lmq_fini(&p->rslmq);
	
	NNI_FREE_STRUCT(p);
}

static void tlstran_pipe_reap(tlstran_pipe *p)
{
	if (!nni_atomic_flag_test_and_set(&p->reaped)) {
		if (p->conn != NULL) {
			nng_stream_close(p->conn);
		}
		nni_reap(&tlstran_pipe_reap_list, p);
	}
}

static int tlstran_pipe_alloc(tlstran_pipe **pipep)
{
	tlstran_pipe *p;
	int           rv;

	if ((p = NNI_ALLOC_STRUCT(p)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&p->mtx);
	if (((rv = nni_aio_alloc(&p->txaio, tlstran_pipe_send_cb, p)) != 0) || ((rv = nni_aio_alloc(&p->qsaio, tlstran_pipe_qos_send_cb, p)) != 0) || ((rv = nni_aio_alloc(&p->rpaio, NULL, p)) != 0) || ((rv = nni_aio_alloc(&p->rxaio, tlstran_pipe_recv_cb, p)) != 0) || ((rv = nni_aio_alloc(&p->negoaio, tlstran_pipe_nego_cb, p)) != 0)) {




		tlstran_pipe_fini(p);
		return (rv);
	}
	nni_aio_list_init(&p->recvq);
	nni_aio_list_init(&p->sendq);
	nni_atomic_flag_reset(&p->reaped);

	*pipep = p;

	return (0);
}

static void tlstran_ep_match(tlstran_ep *ep)
{
	nni_aio *     aio;
	tlstran_pipe *p;

	if (((aio = ep->useraio) == NULL) || ((p = nni_list_first(&ep->waitpipes)) == NULL)) {
		return;
	}
	nni_list_remove(&ep->waitpipes, p);
	nni_list_append(&ep->busypipes, p);
	ep->useraio = NULL;
	p->rcvmax   = ep->rcvmax;
	p->conf     = ep->conf;
	nni_aio_set_output(aio, 0, p);
	nni_aio_finish(aio, 0, 0);
}


static void tlstran_pipe_nego_cb(void *arg)
{
	tlstran_pipe *p   = arg;
	tlstran_ep *  ep  = p->ep;
	nni_aio *     aio = p->negoaio;
	nni_aio *     uaio;
	nni_iov       iov;
	uint32_t      len;
	int           rv, len_of_varint = 0;

	log_trace("start tlstran_pipe_nego_cb max len %ld pipe_addr %p\n", NANO_CONNECT_PACKET_LEN, p);
	nni_mtx_lock(&ep->mtx);

	if ((rv = nni_aio_result(aio)) != 0) {
		log_warn(" nego aio error %s", nng_strerror(rv));
		goto error;
	}

	
	if (p->gotrxhead < p->wantrxhead) {
		p->gotrxhead += nni_aio_count(aio);
	}

	
	if (p->gotrxhead < NNI_NANO_MAX_HEADER_SIZE) {
		nni_iov iov;
		iov.iov_len = NNI_NANO_MAX_HEADER_SIZE - p->gotrxhead;
		iov.iov_buf = &p->rxlen[p->gotrxhead];
		nni_aio_set_iov(aio, 1, &iov);
		nng_stream_recv(p->conn, aio);
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	if (p->gotrxhead == NNI_NANO_MAX_HEADER_SIZE) {
		if (p->rxlen[0] != CMD_CONNECT) {
			log_warn("CMD TYPE %x", p->rxlen[0]);
			rv = NNG_EPROTO;
			goto error;
		}
		len = get_var_integer(p->rxlen + 1, (uint32_t *) &len_of_varint);
		p->wantrxhead = len + 1 + len_of_varint;
		rv            = (p->wantrxhead >= NANO_CONNECT_PACKET_LEN) ? 0 : NNG_EPROTO;
		if (rv != 0) {
			goto error;
		}
	}

	
	if (p->gotrxhead < p->wantrxhead) {
		nni_iov iov;
		iov.iov_len = p->wantrxhead - p->gotrxhead;
		if (p->conn_buf == NULL) {
			p->conn_buf = nng_alloc(p->wantrxhead);
			memcpy(p->conn_buf, p->rxlen, p->gotrxhead);
		}
		iov.iov_buf = &p->conn_buf[p->gotrxhead];
		nni_aio_set_iov(aio, 1, &iov);
		nng_stream_recv(p->conn, aio);
		nni_mtx_unlock(&ep->mtx);
		return;
	}

	
	

	if (p->gotrxhead >= p->wantrxhead) {
		if (p->tcp_cparam == NULL) {
			conn_param_alloc(&p->tcp_cparam);
		}
		if (conn_handler(p->conn_buf, p->tcp_cparam, p->wantrxhead) == 0) {
			nng_free(p->conn_buf, p->wantrxhead);
			p->conn_buf = NULL;
			
			
			

			
			if (p->tcp_cparam->pro_ver == 5) {
				p->qsend_quota = p->tcp_cparam->rx_max;
			}
			nni_list_remove(&ep->negopipes, p);
			nni_list_append(&ep->waitpipes, p);
			tlstran_ep_match(ep);
			if (p->tcp_cparam->max_packet_size == 0) {
				
				p->tcp_cparam->max_packet_size = p->conf == NULL? NANO_MAX_RECV_PACKET_SIZE : p->conf->client_max_packet_size;
			}
			nni_mtx_unlock(&ep->mtx);
			return;
		} else {
			nng_free(p->conn_buf, p->wantrxhead);
			if (p->tcp_cparam->pro_ver == 5) {
				goto close;
			} else {
				goto error;
			}
		}
	}

	nni_mtx_unlock(&ep->mtx);
	log_trace("^^^^^^^^^^end of tlstran_pipe_nego_cb^^^^^^^^^^\n");
	return;

close:
	
	
	
	p->txlen[0] = CMD_CONNACK;
	p->txlen[1] = 0x03;
	p->txlen[2] = 0x00;
	p->txlen[3] = rv;
	p->txlen[4] = 0x00;
	iov.iov_len = 5;
	iov.iov_buf = &p->txlen;
	
	nni_aio_set_iov(p->rpaio, 1, &iov);
	nng_stream_send(p->conn, p->rpaio);
	nng_aio_wait(p->rpaio);
error:
	
	
	
	
	conn_param_free(p->tcp_cparam);
	if (rv == NNG_ECLOSED) {
		rv = NNG_ECONNSHUT;
	}
	nng_stream_close(p->conn);

	if ((uaio = ep->useraio) != NULL) {
		ep->useraio = NULL;
		nni_aio_finish_error(uaio, rv);
	}
	nni_mtx_unlock(&ep->mtx);
	tlstran_pipe_reap(p);
	log_error("connect nego error rv: %s(%d)", nng_strerror(rv), rv);
}

static void tlstran_pipe_qos_send_cb(void *arg)
{
	tlstran_pipe *p = arg;
	nni_msg      *msg;
	nni_aio      *qsaio = p->qsaio;
	uint8_t       type;
	size_t        n;

	if (nni_aio_result(qsaio) != 0) {
		nni_msg_free(nni_aio_get_msg(qsaio));
		nni_aio_set_msg(qsaio, NULL);
		tlstran_pipe_close(p);
		return;
	}
	nni_mtx_lock(&p->mtx);
	n = nni_aio_count(qsaio);
	nni_aio_iov_advance(qsaio, n);
	if (nni_aio_iov_count(qsaio) > 0) {
		nng_stream_send(p->conn, qsaio);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	msg  = nni_aio_get_msg(p->qsaio);
	type = nni_msg_cmd_type(msg);

	if (p->tcp_cparam->pro_ver == 5) {
		(type == CMD_PUBCOMP || type == PUBACK) ? p->qrecv_quota++ : p->qrecv_quota;
	}
	nni_msg_free(msg);
	if (nni_lmq_get(&p->rslmq, &msg) == 0) {
		nni_iov iov;
		nni_msg_insert( msg, nni_msg_header(msg), nni_msg_header_len(msg));
		iov.iov_len = nni_msg_len(msg);
		iov.iov_buf = nni_msg_body(msg);
		nni_aio_set_msg(p->qsaio, msg);
		
		nni_aio_set_iov(p->qsaio, 1, &iov);
		nng_stream_send(p->conn, p->qsaio);
		p->busy = true;
		nni_mtx_unlock(&p->mtx);
		nni_aio_set_msg(qsaio, NULL);
		return;
	}
	p->busy = false;
	nni_mtx_unlock(&p->mtx);
	nni_aio_set_msg(qsaio, NULL);
	return;
}

static void tlstran_pipe_send_cb(void *arg)
{
	tlstran_pipe *p = arg;
	int           rv;
	nni_aio *     aio;
	uint8_t *     header;
	uint8_t       flag = 0, cmd;
	size_t        n;
	nni_msg *     msg;
	nni_aio *     txaio = p->txaio;

	nni_mtx_lock(&p->mtx);
	aio = nni_list_first(&p->sendq);

	log_trace("############### tlstran_pipe_send_cb ################");

	if ((rv = nni_aio_result(txaio)) != 0) {
		log_warn(" send aio error %s", nng_strerror(rv));
		nni_pipe_bump_error(p->npipe, rv);
		nni_aio_list_remove(aio);
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	n = nni_aio_count(txaio);
	nni_aio_iov_advance(txaio, n);
	log_trace("tls over tcp socket sent %ld bytes iov %ld", n, nni_aio_iov_count(txaio));

	if (nni_aio_iov_count(txaio) > 0) {
		nng_stream_send(p->conn, txaio);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	msg = nni_aio_get_msg(txaio);
	nni_aio_set_msg(txaio, NULL);
	if (msg != NULL) {
		nni_msg_free(msg);
	}
	msg = nni_aio_get_msg(aio);

	if (nni_aio_get_prov_data(txaio) != NULL) {
		
		if (p->tcp_cparam->pro_ver == 4)
			tlstran_pipe_send_start_v4(p, msg, txaio);
		else if (p->tcp_cparam->pro_ver == 5)
			tlstran_pipe_send_start_v5(p, msg, txaio);
		nni_mtx_unlock(&p->mtx);
		return;
	}

	nni_aio_list_remove(aio);
	tlstran_pipe_send_start(p);

	if (msg == NULL) {
		nni_mtx_unlock(&p->mtx);
		
		nni_aio_set_msg(aio, NULL);
		nni_aio_finish_sync(aio, 0, 0);
		return;
	}

	n   = nni_msg_len(msg);
	cmd = nni_msg_cmd_type(msg);
	if (cmd == CMD_CONNACK) {
		header = nni_msg_header(msg);
		
		flag = header[3];
	}
	
	nni_mtx_unlock(&p->mtx);

	nni_aio_set_msg(aio, NULL);
	nni_msg_free(msg);
	if (cmd == CMD_CONNACK && flag != 0x00) {
		nni_aio_finish_error(aio, flag);
	} else if (cmd == CMD_DISCONNECT) {
		nni_aio_finish_error(aio, NNG_ECLOSED);
	} else {
		nni_aio_finish_sync(aio, 0, n);
	}
}


static void tlstran_pipe_recv_cb(void *arg)
{
	nni_aio *     aio;
	nni_iov       iov[2];
	uint8_t       type;
	uint8_t       rv;
	uint32_t      pos = 1;
	uint64_t      len = 0;
	size_t        n;
	nni_msg      *msg, *qmsg;
	tlstran_pipe *p     = arg;
	nni_aio *     rxaio = p->rxaio;
	conn_param *  cparam;
	bool          ack   = false;

	log_trace("tlstran_pipe_recv_cb %p\n", p);
	nni_mtx_lock(&p->mtx);

	aio = nni_list_first(&p->recvq);

	if ((rv = nni_aio_result(rxaio)) != 0) {
		log_warn(" recv aio error %s", nng_strerror(rv));
		rv = NMQ_SERVER_BUSY;
		goto recv_error;
	}

	n = nni_aio_count(rxaio);
	p->gotrxhead += n;

	nni_aio_iov_advance(rxaio, n);
	
	len = get_var_integer(p->rxlen, &pos);
	log_trace("new %ld recevied %ld header %x %d pos: %d len : %d", n, p->gotrxhead, p->rxlen[0], p->rxlen[1], pos, len);
	log_trace("still need byte count:%ld > 0\n", nni_aio_iov_count(rxaio));

	if (nni_aio_iov_count(rxaio) > 0) {
		log_trace("got: %x %x, %ld!!\n", p->rxlen[0], p->rxlen[1], strlen((char *) p->rxlen));
		nng_stream_recv(p->conn, rxaio);
		nni_mtx_unlock(&p->mtx);
		return;
	} else if (p->gotrxhead <= NNI_NANO_MAX_HEADER_SIZE && p->rxlen[p->gotrxhead - 1] > 0x7f) {
		
		if (p->gotrxhead == NNI_NANO_MAX_HEADER_SIZE) {
			rv = NNG_EMSGSIZE;
			goto recv_error;
		}
		
		iov[0].iov_buf = &p->rxlen[p->gotrxhead];
		iov[0].iov_len = 1;
		nni_aio_set_iov(rxaio, 1, iov);
		nng_stream_recv(p->conn, rxaio);
		nni_mtx_unlock(&p->mtx);
		return;
	} else if (len == 0 && n == 2) {
		if ((p->rxlen[0] & 0XFF) == CMD_PINGREQ) {
			nng_aio_wait(p->rpaio);
			p->txlen[0] = CMD_PINGRESP;
			p->txlen[1] = 0x00;
			iov[0].iov_len = 2;
			iov[0].iov_buf = &p->txlen;
			
			nni_aio_set_iov(p->rpaio, 1, iov);
			nng_stream_send(p->conn, p->rpaio);
			goto notify;
		}
	}

	
	p->wantrxhead = len + p->gotrxhead;
	cparam        = p->tcp_cparam;

	if (p->rxmsg == NULL) {
		
		
		log_trace("pipe %p header got: %x %x %x %x %x, %ld!!\n", p, p->rxlen[0], p->rxlen[1], p->rxlen[2], p->rxlen[3], p->rxlen[4], p->wantrxhead);

		
		
		if (len > p->conf->max_packet_size) {
			log_error("size error 0x95\n");
			rv = NMQ_PACKET_TOO_LARGE;
			goto recv_error;
		}

		if ((rv = nni_msg_alloc(&p->rxmsg, (size_t) len)) != 0) {
			log_error("mem error %ld\n", (size_t) len);
			rv = NMQ_SERVER_UNAVAILABLE;
			goto recv_error;
		}

		
		
		
		if (len != 0) {
			iov[0].iov_buf = nni_msg_body(p->rxmsg);
			iov[0].iov_len = (size_t) len;

			nni_aio_set_iov(rxaio, 1, iov);
			
			nng_stream_recv(p->conn, rxaio);
			nni_mtx_unlock(&p->mtx);
			return;
		}
	}

	
	
	nni_aio_list_remove(aio);
	msg      = p->rxmsg;
	p->rxmsg = NULL;
	n        = nni_msg_len(msg);
	type     = p->rxlen[0] & 0xf0;

	fixed_header_adaptor(p->rxlen, msg);
	nni_msg_set_conn_param(msg, cparam);
	
	nni_msg_set_remaining_len(msg, len);
	nni_msg_set_cmd_type(msg, type);
	log_trace("remain_len %d cparam %p clientid %s username %s proto %d\n", len, cparam, cparam->clientid.body, cparam->username.body, cparam->pro_ver);


	
	log_trace("The type of msg is %x", type);
	uint16_t  packet_id   = 0;
	uint8_t   reason_code = 0;
	property *prop        = NULL;
	uint8_t   ack_cmd     = 0;
	if (type == CMD_PUBLISH) {
		nni_msg_set_timestamp(msg, nng_clock());
		uint8_t qos_pac = nni_msg_get_pub_qos(msg);
		if (qos_pac > 0) {
			
			
			if (p->tcp_cparam->pro_ver == 5) {
				if (p->qrecv_quota > 0) {
					p->qrecv_quota--;
				} else {
					rv = NMQ_RECEIVE_MAXIMUM_EXCEEDED;
					goto recv_error;
				}
			}
			if (qos_pac == 1) {
				ack_cmd = CMD_PUBACK;
			} else if (qos_pac == 2) {
				ack_cmd = CMD_PUBREC;
			}
			packet_id = nni_msg_get_pub_pid(msg);
			ack       = true;
		}
	} else if (type == CMD_PUBREC) {
		if (nni_mqtt_pubres_decode(msg, &packet_id, &reason_code, &prop, cparam->pro_ver) != 0) {
			log_error("decode PUBREC variable header failed!");
		}
		ack_cmd = CMD_PUBREL;
		ack     = true;
	} else if (type == CMD_PUBREL) {
		if (nni_mqtt_pubres_decode(msg, &packet_id, &reason_code, &prop, cparam->pro_ver) != 0) {
			log_error("decode PUBREL variable header failed!");
		}
		ack_cmd = CMD_PUBCOMP;
		ack     = true;
	} else if (type == CMD_PUBACK || type == CMD_PUBCOMP) {
		if (nni_mqtt_pubres_decode(msg, &packet_id, &reason_code, &prop, cparam->pro_ver) != 0) {
			log_error("decode PUBACK or PUBCOMP variable header " "failed!");
		}
		
		if (p->tcp_cparam->pro_ver == 5) {
			property_free(prop);
			p->qsend_quota++;
		}
	}
	if (ack == true) {
		
		
		if ((rv = nni_msg_alloc(&qmsg, 0)) != 0) {
			ack = false;
			rv  = NMQ_SERVER_BUSY;
			goto recv_error;
		}
		

		nni_msg_set_cmd_type(qmsg, ack_cmd);
		nni_mqtt_msgack_encode( qmsg, packet_id, reason_code, prop, cparam->pro_ver);
		nni_mqtt_pubres_header_encode(qmsg, ack_cmd);
		
		
		
		
		if (p->busy == false) {
			
			
			if (nni_aio_begin(aio) != 0) {
				log_error("ACK aio error!!");
			}
			nni_msg_insert(qmsg, nni_msg_header(qmsg), nni_msg_header_len(qmsg));
			iov[0].iov_len = nni_msg_len(qmsg);
			iov[0].iov_buf = nni_msg_body(qmsg);
			p->busy        = true;
			nni_aio_set_msg(p->qsaio, qmsg);
			
			nni_aio_set_iov(p->qsaio, 1, iov);
			nng_stream_send(p->conn, p->qsaio);
			log_trace("QoS ACK msg sent!");
		} else {
			if (nni_lmq_full(&p->rslmq)) {
				
				
				if (nni_lmq_cap(&p->rslmq) <= NANO_MAX_QOS_PACKET) {
					if ((rv = nni_lmq_resize(&p->rslmq, nni_lmq_cap(&p->rslmq) * 2)) == 0) {

						nni_lmq_put(&p->rslmq, qmsg);
					} else {
						
						nni_msg_free(qmsg);
					}
				} else {
					nni_msg *old;
					(void) nni_lmq_get(&p->rslmq, &old);
					nni_msg_free(old);
					nni_lmq_put(&p->rslmq, qmsg);
				}
			} else {
				nni_lmq_put(&p->rslmq, qmsg);
			}
		}
		ack = false;
	}

	
	
	if (!nni_list_empty(&p->recvq)) {
		tlstran_pipe_recv_start(p);
	}
	nni_pipe_bump_rx(p->npipe, n);
	nni_mtx_unlock(&p->mtx);

	nni_aio_set_msg(aio, msg);
	nni_aio_finish_sync(aio, 0, n);
	log_trace("end of tlstran_pipe_recv_cb: synch! %p\n", p);
	return;

recv_error:
	nni_aio_list_remove(aio);
	msg      = p->rxmsg;
	p->rxmsg = NULL;
	nni_pipe_bump_error(p->npipe, rv);
	nni_mtx_unlock(&p->mtx);

	nni_msg_free(msg);
	nni_aio_finish_error(aio, rv);
	log_trace("tlstran_pipe_recv_cb: recv error rv: %d\n", rv);
	return;
notify:
	
	nni_aio_list_remove(aio);
	
	nni_mtx_unlock(&p->mtx);
	nni_aio_set_msg(aio, NULL);
	nni_aio_finish(aio, 0, 0);
	return;
}

static void tlstran_pipe_send_cancel(nni_aio *aio, void *arg, int rv)
{
	tlstran_pipe *p = arg;

	nni_mtx_lock(&p->mtx);
	if (!nni_aio_list_active(aio)) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	
	
	
	if (nni_list_first(&p->sendq) == aio) {
		nni_aio_abort(p->txaio, rv);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	nni_aio_list_remove(aio);
	nni_mtx_unlock(&p->mtx);

	nni_aio_finish_error(aio, rv);
}


static inline void tlstran_pipe_send_start_v4(tlstran_pipe *p, nni_msg *msg, nni_aio *aio)
{
	nni_aio *txaio;
	nni_iov  iov[8];
	int      niov = 0;
	nni_msg  *tmsg;
	
	uint8_t  qos = 0;

	if (nni_msg_header_len(msg) <= 0 || nni_msg_get_type(msg) != CMD_PUBLISH) {
		goto send;
	}

	bool      is_sqlite = p->conf->sqlite.enable;
	int       qlen = 0, topic_len = 0;
	subinfo * tinfo = NULL, *info = NULL;
	nni_list *subinfol = p->npipe->subinfol;
	char *    topic    = nni_msg_get_pub_topic(msg, &topic_len);

	txaio = p->txaio;
	tinfo = nni_aio_get_prov_data(txaio);
	nni_aio_set_prov_data(txaio, NULL);

	
	
	NNI_LIST_FOREACH(subinfol, info) {
		if (tinfo != NULL && info != tinfo)
			continue;

		tinfo = NULL;

		char *sub_topic = info->topic;
		if (sub_topic[0] == '$') {
			if (0 == strncmp(sub_topic, "$share/", strlen("$share/"))) {
				sub_topic = strchr(sub_topic, '/');
				sub_topic++;
				sub_topic = strchr(sub_topic, '/');
				sub_topic++;
			}
		}
		if (false == topic_filtern(sub_topic, topic, topic_len))
			continue;
		if (niov > 4) {
			
			nni_aio_set_prov_data(txaio, info);
			break;
		}

		uint8_t * body, *header, qos_pac;
		uint8_t   var_extra[2], fixheader, tmp[4] = { 0 };
		int       len_offset = 0;
		uint32_t  pos        = 1;
		nni_pipe *pipe;
		uint16_t  pid;
		uint32_t  property_bytes = 0, property_len = 0;
		size_t    tlen, rlen, mlen, plength;

		pipe    = p->npipe;
		body    = nni_msg_body(msg);
		header  = nni_msg_header(msg);

		plength = 0;
		mlen    = nni_msg_len(msg);
		qos_pac = nni_msg_get_pub_qos(msg);
		NNI_GET16(body, tlen);

		if (nni_msg_cmd_type(msg) == CMD_PUBLISH_V5) {
			
			
			
			if (qos_pac > 0) {
				property_len = get_var_integer( body + 4 + tlen, &property_bytes);

			} else {
				property_len = get_var_integer( body + 2 + tlen, &property_bytes);
			}
			
			

			plength = property_len + property_bytes;
		} else if (nni_msg_cmd_type(msg) == CMD_PUBLISH) {

			if (qos_pac == 0) {
				if (nni_msg_header_len(msg) > 0) {
					iov[niov].iov_buf = nni_msg_header(msg);
					iov[niov].iov_len = nni_msg_header_len(msg);
					niov++;
				}
				if (nni_msg_len(msg) > 0) {
					iov[niov].iov_buf = nni_msg_body(msg);
					iov[niov].iov_len = nni_msg_len(msg);
					niov++;
				}
				
				continue;
			}
		}

		qos = info->qos;
		log_trace("qos_pac %d sub %d\n", qos_pac, qos);
		fixheader = *header;
		
		qos = qos_pac > qos ? qos : qos_pac;

		
		if (qos_pac > qos) {
			if (qos == 1) {
				
				fixheader = fixheader & 0xF9;
				fixheader = fixheader | 0x02;
			} else {
				
				fixheader = fixheader & 0xF9;
				len_offset   = len_offset - 2;
			}
		}
		
		rlen = put_var_integer( tmp, get_var_integer(header, &pos) + len_offset - plength);
		*(p->qos_buf + qlen) = fixheader;
		
		memcpy(p->qos_buf+1+qlen, tmp, rlen);

		
		len_offset = 0;      
		
		if (qos > 0) {
			
			len_offset = 2;
			nni_msg *old;
			
			pid = (uint16_t)(size_t) nni_aio_get_prov_data(aio);
			if (pid == 0) {
				
				pid = nni_pipe_inc_packetid(pipe);
				
				nni_msg_clone(msg);
				if ((old = nni_qos_db_get(is_sqlite, pipe->nano_qos_db, pipe->p_id, pid)) != NULL) {

					
					
					
					log_error("packet id duplicates in " "nano_qos_db");

					nni_qos_db_remove_msg(is_sqlite, pipe->nano_qos_db, old);
				}
				old = msg;
				nni_qos_db_set(is_sqlite, pipe->nano_qos_db, pipe->p_id, pid, old);
				nni_qos_db_remove_oldest(is_sqlite, pipe->nano_qos_db, p->conf->sqlite.disk_cache_size);

			}
			NNI_PUT16(var_extra, pid);
		} else if (qos_pac > 0) {
			len_offset += 2;
		}
		
		iov[niov].iov_buf = p->qos_buf+qlen;
		iov[niov].iov_len = 1+rlen;
		niov++;
		qlen += rlen + 1;
		
		iov[niov].iov_buf = body;
		iov[niov].iov_len = 2+tlen;
		niov++;
		
		if (qos > 0) {
			
			memcpy(p->qos_buf + 5 + qlen, var_extra, 2);
			iov[niov].iov_buf = p->qos_buf + 5 + qlen;
			iov[niov].iov_len = 2;
			niov++;
			qlen += 2;
		}
		
		if (mlen > 0) {
			
			iov[niov].iov_buf = body + 2 + tlen + len_offset + plength;
			iov[niov].iov_len = mlen - 2 - len_offset - tlen - plength;
			niov++;
		}
	}

	nni_msg_alloc(&tmsg, 0);
	
	for (int i = 0; i < niov; i++) {
		nni_msg_append(tmsg, iov[i].iov_buf, iov[i].iov_len);
	}
	
	
	iov[0].iov_buf = nni_msg_body(tmsg);
	iov[0].iov_len = nni_msg_len(tmsg);
	nni_aio_set_msg(txaio, tmsg);
	nni_aio_set_iov(txaio, 1, iov);

	nng_stream_send(p->conn, txaio);
	return;

send:
	
	nni_msg_alloc(&tmsg, 0);
	txaio = p->txaio;
	niov  = 0;

	if (nni_msg_header_len(msg) > 0) {
		nni_msg_append( tmsg, nni_msg_header(msg), nni_msg_header_len(msg));
	}
	if (nni_msg_len(msg) > 0) {
		nni_msg_append(tmsg, nni_msg_body(msg), nni_msg_len(msg));
	}
	iov[0].iov_buf = nni_msg_body(tmsg);
	iov[0].iov_len = nni_msg_len(tmsg);
	nni_aio_set_msg(txaio, tmsg);
	nni_aio_set_iov(txaio, 1, iov);
	nng_stream_send(p->conn, txaio);
}


static inline void tlstran_pipe_send_start_v5(tlstran_pipe *p, nni_msg *msg, nni_aio *aio)
{
	nni_aio  *txaio;
	nni_pipe *pipe = p->npipe;
	int       niov;
	nni_iov   iov[8];
	nni_msg  *tmsg;

	if (nni_msg_get_type(msg) != CMD_PUBLISH)
		goto send;
	

	uint8_t *     body, *header, qos_pac;
	target_prover target_prover;
	int           len_offset = 0, sub_id = 0, qos = 0;
	uint16_t      pid;
	uint32_t tprop_bytes, prop_bytes = 0, id_bytes = 0, property_len = 0;
	size_t   tlen, rlen, mlen, hlen, qlength, plength;

	bool is_sqlite = p->conf->sqlite.enable;

	txaio   = p->txaio;
	body    = nni_msg_body(msg);
	header  = nni_msg_header(msg);
	niov    = 0;
	qlength = 0;
	plength = 0;
	mlen    = nni_msg_len(msg);
	hlen    = nni_msg_header_len(msg);
	qos_pac = nni_msg_get_pub_qos(msg);
	NNI_GET16(body, tlen);

	
	uint32_t total_len = mlen + hlen;
	if (total_len > p->tcp_cparam->max_packet_size) {
		
		
		log_warn("msg dropped due to overceed max packet size!");
		nni_msg_free(msg);
		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, 0);
		return;
	}
	if (nni_msg_cmd_type(msg) == CMD_PUBLISH_V5) {
		if (qos_pac > 0) {
			property_len = get_var_integer(body + 4 + tlen, &prop_bytes);
		} else {
			property_len = get_var_integer(body + 2 + tlen, &prop_bytes);
		}
		target_prover = MQTTV5;
		tprop_bytes = prop_bytes;
	}
	
	subinfo *info, *tinfo;
	tinfo = nni_aio_get_prov_data(txaio);
	nni_aio_set_prov_data(txaio, NULL);
	NNI_LIST_FOREACH (p->npipe->subinfol, info) {
		if (tinfo != NULL && info != tinfo ) {
			continue;
		}
		if (info->no_local == 1 && p->npipe->p_id == nni_msg_get_pipe(msg)) {
			continue;
		}
		tinfo = NULL;
		len_offset=0;
		char *sub_topic = info->topic;
		if (sub_topic[0] == '$') {
			if (0 == strncmp(sub_topic, "$share/", strlen("$share/"))) {
				sub_topic = strchr(sub_topic, '/');
				sub_topic++;
				sub_topic = strchr(sub_topic, '/');
				sub_topic++;
			}
		}
		if (topic_filtern(sub_topic, (char*)(body + 2), tlen)) {
			if (niov >= 8) {
				
				nni_aio_set_prov_data(txaio, info);
				break;
			}
			uint8_t  var_extra[2], fixheader, tmp[4] = { 0 };
			uint8_t  proplen[4] = { 0 }, var_subid[5] = { 0 };
			uint32_t pos = 1;
			sub_id       = info->subid;
			qos          = info->qos;

			fixheader = *header;
			if (nni_msg_cmd_type(msg) == CMD_PUBLISH) {
				
				target_prover = MQTTV4_V5;
				prop_bytes    = 1;
				tprop_bytes   = 1;
				len_offset    = 1;
			}
			if (info->rap == 0) {
				fixheader = fixheader & 0xFE;
			}
			if (sub_id != 0) {
				var_subid[0] = 0x0B;
				id_bytes = put_var_integer(var_subid+1, sub_id);
				tprop_bytes = put_var_integer(proplen, property_len+1+id_bytes);
				len_offset += (tprop_bytes - prop_bytes + 1 + id_bytes);
			}
			
			qos = qos_pac > qos ? qos : qos_pac;

			
			if (qos_pac > qos) {
				if (qos == 1) {
					
					fixheader = fixheader & 0xF9;
					fixheader = fixheader | 0x02;
				} else {
					
					fixheader = fixheader & 0xF9;
					len_offset   = len_offset - 2;
				}
			}
			
			pos=1;
			rlen = put_var_integer( tmp, get_var_integer(header, &pos) + len_offset);
			
			*(p->qos_buf + qlength) = fixheader;
			memcpy(p->qos_buf + qlength + 1, tmp, rlen);
			iov[niov].iov_buf = p->qos_buf + qlength;
			iov[niov].iov_len = rlen + 1;
			niov++;
			qlength += rlen + 1;
			
			iov[niov].iov_buf = body;
			iov[niov].iov_len = tlen+2;
			niov++;
			
			len_offset = 0;
			plength = 0;
			if (qos > 0) {
				
				len_offset = 2;
				nni_msg *old;
				
				
				pid = (uint16_t)(size_t) nni_aio_get_prov_data(aio);
				if (pid == 0) {
					
					pid = nni_pipe_inc_packetid(pipe);
					
					nni_msg_clone(msg);
					if ((old = nni_qos_db_get(is_sqlite, pipe->nano_qos_db, pipe->p_id, pid)) != NULL) {

						
						
						
						
						nni_println("ERROR: packet id " "duplicates in " "nano_qos_db");


						nni_qos_db_remove_msg( is_sqlite, pipe->nano_qos_db, old);

					}
					old = msg;
					nni_qos_db_set(is_sqlite, pipe->nano_qos_db, pipe->p_id, pid, old);

					nni_qos_db_remove_oldest(is_sqlite, pipe->nano_qos_db, p->conf->sqlite.disk_cache_size);

				}
				NNI_PUT16(var_extra, pid);
				
				memcpy(p->qos_buf + qlength, var_extra, 2);
				qlength += 2;
				plength += 2;
			} else if (qos_pac > 0) {
				
				len_offset += 2;
			}
			
			if (sub_id != 0) {
				memcpy(p->qos_buf + qlength, proplen, tprop_bytes);
				qlength += tprop_bytes;
				plength += tprop_bytes;
				memcpy(p->qos_buf + qlength, var_subid, id_bytes + 1);
				qlength += id_bytes + 1;
				plength += id_bytes + 1;
				if (target_prover == MQTTV5)
					len_offset += prop_bytes;
			} else {
				
				if (target_prover == MQTTV4_V5) {
					
					memcpy(p->qos_buf + qlength, proplen, tprop_bytes);
					qlength += tprop_bytes;
					plength += tprop_bytes;
				}
			}
			
			iov[niov].iov_buf = p->qos_buf+qlength-plength;
			iov[niov].iov_len = plength;
			niov++;
			
			iov[niov].iov_buf = body + 2 + tlen + len_offset;
			iov[niov].iov_len = mlen - 2 - len_offset - tlen;
			niov++;
		}
	}

	
	if (qos > 0) {
		if (p->qsend_quota > 0) {
			p->qsend_quota--;
		} else {
			
			
			
			
			nni_msg_free(msg);
			nni_aio_set_prov_data(txaio, NULL);
			nni_list_remove(&p->sendq, aio);
			nni_aio_set_msg(aio, NULL);
			nni_aio_finish(aio, 0, 0);
			return;
		}
	}
	if (niov == 0) {
		
		nni_msg_free(msg);
		nni_aio_set_prov_data(txaio, NULL);
		nni_list_remove(&p->sendq, aio);
		nni_aio_set_msg(aio, NULL);
		nni_aio_finish(aio, 0, 0);
		return;
	}
	nni_msg_alloc(&tmsg, 0);
	
	for (int i = 0; i < niov; i++) {
		nni_msg_append(tmsg, iov[i].iov_buf, iov[i].iov_len);
	}
	
	
	iov[0].iov_buf = nni_msg_body(tmsg);
	iov[0].iov_len = nni_msg_len(tmsg);
	nni_aio_set_msg(txaio, tmsg);
	nni_aio_set_iov(txaio, 1, iov);

	nng_stream_send(p->conn, txaio);
	return;

send:
	
	nni_msg_alloc(&tmsg, 0);
	txaio = p->txaio;
	niov  = 0;

	if (nni_msg_header_len(msg) > 0) {
		nni_msg_append( tmsg, nni_msg_header(msg), nni_msg_header_len(msg));
	}
	if (nni_msg_len(msg) > 0) {
		nni_msg_append(tmsg, nni_msg_body(msg), nni_msg_len(msg));
	}
	iov[0].iov_buf = nni_msg_body(tmsg);
	iov[0].iov_len = nni_msg_len(tmsg);
	nni_aio_set_msg(txaio, tmsg);
	nni_aio_set_iov(txaio, 1, iov);
	nng_stream_send(p->conn, txaio);
}


static void tlstran_pipe_send_start(tlstran_pipe *p)
{
	nni_aio *aio;
	nni_msg *msg;

	log_trace("########### tlstran_pipe_send_start ###########");
	if (p->closed) {
		while ((aio = nni_list_first(&p->sendq)) != NULL) {
			nni_list_remove(&p->sendq, aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
		return;
	}

	if ((aio = nni_list_first(&p->sendq)) == NULL) {
		log_trace("aio not functioning");
		return;
	}

	
	msg = nni_aio_get_msg(aio);
	if (msg == NULL || p->tcp_cparam == NULL) {
		
		nni_println("ERROR: sending NULL msg or pipe is invalid!");
		nni_aio_finish(aio, NNG_ECANCELED, 0);
		return;
	}
	if (p->tcp_cparam->pro_ver == 4) {
		tlstran_pipe_send_start_v4(p, msg, aio);
	} else if (p->tcp_cparam->pro_ver == 5) {
		tlstran_pipe_send_start_v5(p, msg, aio);
	}
	return;
}

static void tlstran_pipe_send(void *arg, nni_aio *aio)
{
	tlstran_pipe *p = arg;
	int           rv;

	log_trace("####################tlstran_pipe_send###########");
	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, tlstran_pipe_send_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_list_append(&p->sendq, aio);
	if (nni_list_first(&p->sendq) == aio) {
		
		tlstran_pipe_send_start(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static void tlstran_pipe_recv_cancel(nni_aio *aio, void *arg, int rv)
{
	tlstran_pipe *p = arg;

	nni_mtx_lock(&p->mtx);
	if (!nni_aio_list_active(aio)) {
		nni_mtx_unlock(&p->mtx);
		return;
	}
	
	
	
	if (nni_list_first(&p->recvq) == aio) {
		nni_aio_abort(p->rxaio, rv);
		nni_mtx_unlock(&p->mtx);
		return;
	}
	nni_aio_list_remove(aio);
	nni_mtx_unlock(&p->mtx);
	nni_aio_finish_error(aio, rv);
}

static void tlstran_pipe_recv(void *arg, nni_aio *aio)
{
	tlstran_pipe *p = arg;
	int           rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&p->mtx);
	if ((rv = nni_aio_schedule(aio, tlstran_pipe_recv_cancel, p)) != 0) {
		nni_mtx_unlock(&p->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}

	
	nni_list_append(&p->recvq, aio);
	

	if (nni_list_first(&p->recvq) == aio) {
		tlstran_pipe_recv_start(p);
	}
	nni_mtx_unlock(&p->mtx);
}

static int tlstran_pipe_getopt( void *arg, const char *name, void *buf, size_t *szp, nni_type t)

{
	tlstran_pipe *p = arg;
	return (nni_stream_get(p->conn, name, buf, szp, t));
}

static void tlstran_pipe_recv_start(tlstran_pipe *p)
{
	nni_aio *rxaio;
	nni_iov  iov;
	log_trace("*** tlstran_pipe_recv_start ***\n");

	if (p->closed) {
		nni_aio *aio;
		while ((aio = nni_list_first(&p->recvq)) != NULL) {
			nni_list_remove(&p->recvq, aio);
			nni_aio_finish_error(aio, NNG_ECLOSED);
		}
		return;
	}
	if (nni_list_empty(&p->recvq)) {
		return;
	}

	
	rxaio         = p->rxaio;
	p->gotrxhead  = 0;
	p->wantrxhead = NANO_MIN_FIXED_HEADER_LEN;
	iov.iov_buf   = p->rxlen;
	iov.iov_len   = NANO_MIN_FIXED_HEADER_LEN;
	nni_aio_set_iov(rxaio, 1, &iov);
	nng_stream_recv(p->conn, rxaio);
}


static void tlstran_pipe_start(tlstran_pipe *p, nng_stream *conn, tlstran_ep *ep)
{
	nni_iov iov;
	

	ep->refcnt++;

	p->conn = conn;
	p->ep   = ep;
	p->conf = ep->conf;
	

	log_trace("tlstran_pipe_start!");
	p->qrecv_quota = NANO_MAX_QOS_PACKET;
	p->gotrxhead  = 0;
	p->wantrxhead = NANO_CONNECT_PACKET_LEN; 
	                                         
	                                         
	iov.iov_len = NNI_NANO_MAX_HEADER_SIZE;  
	iov.iov_buf = p->rxlen;

	nni_aio_set_iov(p->negoaio, 1, &iov);
	nni_list_append(&ep->negopipes, p);

	nni_aio_set_timeout(p->negoaio, 15 * 1000);
	nng_stream_recv(p->conn, p->negoaio);
}

static void tlstran_ep_fini(void *arg)
{
	tlstran_ep *ep = arg;

	nni_mtx_lock(&ep->mtx);
	ep->fini = true;
	if (ep->refcnt != 0) {
		nni_mtx_unlock(&ep->mtx);
		return;
	}
	nni_mtx_unlock(&ep->mtx);
	nni_aio_stop(ep->timeaio);
	nni_aio_stop(ep->connaio);
	nng_stream_listener_free(ep->listener);
	nni_aio_free(ep->timeaio);
	nni_aio_free(ep->connaio);

	nni_mtx_fini(&ep->mtx);
	NNI_FREE_STRUCT(ep);
}

static void tlstran_ep_close(void *arg)
{
	tlstran_ep *  ep = arg;
	tlstran_pipe *p;

	nni_mtx_lock(&ep->mtx);

	log_trace("tlstran_ep_close");
	ep->closed = true;
	nni_aio_close(ep->timeaio);
	if (ep->listener != NULL) {
		nng_stream_listener_close(ep->listener);
	}
	NNI_LIST_FOREACH (&ep->negopipes, p) {
		tlstran_pipe_close(p);
	}
	NNI_LIST_FOREACH (&ep->waitpipes, p) {
		tlstran_pipe_close(p);
	}
	NNI_LIST_FOREACH (&ep->busypipes, p) {
		tlstran_pipe_close(p);
	}
	if (ep->useraio != NULL) {
		nni_aio_finish_error(ep->useraio, NNG_ECLOSED);
		ep->useraio = NULL;
	}

	nni_mtx_unlock(&ep->mtx);
}




int tlstran_url_parse_source(nng_url *url, nng_sockaddr *sa, const nng_url *surl)
{
	int      af;
	char *   semi;
	char *   src;
	size_t   len;
	int      rv;
	nni_aio *aio;

	
	

	url->u_scheme   = surl->u_scheme;
	url->u_port     = surl->u_port;
	url->u_hostname = surl->u_hostname;

	if ((semi = strchr(url->u_hostname, ';')) == NULL) {
		memset(sa, 0, sizeof(*sa));
		return (0);
	}

	len             = (size_t)(semi - url->u_hostname);
	url->u_hostname = semi + 1;

	if (strcmp(surl->u_scheme, "tls+tcp") == 0) {
		af = NNG_AF_UNSPEC;
	} else if (strcmp(surl->u_scheme, "tls+tcp4") == 0) {
		af = NNG_AF_INET;
	} else if (strcmp(surl->u_scheme, "tls+tcp6") == 0) {
		af = NNG_AF_INET6;
	} else {
		return (NNG_EADDRINVAL);
	}

	if ((src = nni_alloc(len + 1)) == NULL) {
		return (NNG_ENOMEM);
	}
	memcpy(src, surl->u_hostname, len);
	src[len] = '\0';

	if ((rv = nni_aio_alloc(&aio, NULL, NULL)) != 0) {
		nni_free(src, len + 1);
		return (rv);
	}

	nni_resolv_ip(src, "0", af, true, sa, aio);
	nni_aio_wait(aio);
	rv = nni_aio_result(aio);
	nni_aio_free(aio);
	nni_free(src, len + 1);
	return (rv);
}

static void tlstran_timer_cb(void *arg)
{
	tlstran_ep *ep = arg;
	if (nni_aio_result(ep->timeaio) == 0) {
		nng_stream_listener_accept(ep->listener, ep->connaio);
	}
}


static void tlstran_accept_cb(void *arg)
{
	tlstran_ep *  ep  = arg;
	nni_aio *     aio = ep->connaio;
	tlstran_pipe *p;
	int           rv;
	nng_stream *  conn;

	nni_mtx_lock(&ep->mtx);

	if ((rv = nni_aio_result(aio)) != 0) {
		log_warn(" send aio error %s", nng_strerror(rv));
		goto error;
	}

	conn = nni_aio_get_output(aio, 0);
	if ((rv = tlstran_pipe_alloc(&p)) != 0) {
		nng_stream_free(conn);
		goto error;
	}

	if (ep->closed) {
		tlstran_pipe_fini(p);
		nng_stream_free(conn);
		rv = NNG_ECLOSED;
		goto error;
	}
	tlstran_pipe_start(p, conn, ep);
	nng_stream_listener_accept(ep->listener, ep->connaio);
	nni_mtx_unlock(&ep->mtx);
	return;

error:
	
	
	if ((aio = ep->useraio) != NULL) {
		ep->useraio = NULL;
		nni_aio_finish_error(aio, rv);
	}
	switch (rv) {

	case NNG_ENOMEM:
	case NNG_ENOFILES:
		nng_sleep_aio(10, ep->timeaio);
		break;

	default:
		if (!ep->closed) {
			nng_stream_listener_accept(ep->listener, ep->connaio);
		}
		break;
	}
	nni_mtx_unlock(&ep->mtx);
}

static int tlstran_ep_init(tlstran_ep **epp, nng_url *url, nni_sock *sock)
{
	tlstran_ep *ep;
	NNI_ARG_UNUSED(sock);

	if ((ep = NNI_ALLOC_STRUCT(ep)) == NULL) {
		return (NNG_ENOMEM);
	}
	nni_mtx_init(&ep->mtx);
	NNI_LIST_INIT(&ep->busypipes, tlstran_pipe, node);
	NNI_LIST_INIT(&ep->waitpipes, tlstran_pipe, node);
	NNI_LIST_INIT(&ep->negopipes, tlstran_pipe, node);

	
	ep->url = url;

	static const nni_stat_info rcv_max_info = {
		.si_name   = "rcv_max", .si_desc   = "maximum receive size", .si_type   = NNG_STAT_LEVEL, .si_unit   = NNG_UNIT_BYTES, .si_atomic = true, };




	nni_stat_init(&ep->st_rcv_max, &rcv_max_info);


	*epp = ep;
	return (0);
}

static int tlstran_ep_init_listener(void **lp, nng_url *url, nni_listener *nlistener)
{
	tlstran_ep *ep;
	uint16_t    af;
	char *      host = url->u_hostname;
	nni_aio *   aio;
	int         rv;
	nni_sock *  sock = nni_listener_sock(nlistener);

	if (strcmp(url->u_scheme, "tls+nmq-tcp") == 0) {
		af = NNG_AF_UNSPEC;
	} else if (strcmp(url->u_scheme, "tls+nmq-tcp4") == 0) {
		af = NNG_AF_INET;
	} else if (strcmp(url->u_scheme, "tls+nmq-tcp6") == 0) {
		af = NNG_AF_INET6;
	} else {
		return (NNG_EADDRINVAL);
	}
	
	if ((strlen(url->u_path) != 0) && (strcmp(url->u_path, "/") != 0)) {
		return (NNG_EADDRINVAL);
	}
	if ((url->u_fragment != NULL) || (url->u_userinfo != NULL) || (url->u_query != NULL)) {
		return (NNG_EADDRINVAL);
	}

	if (((rv = tlstran_ep_init(&ep, url, sock)) != 0) || ((rv = nni_aio_alloc(&ep->connaio, tlstran_accept_cb, ep)) != 0) || ((rv = nni_aio_alloc(&ep->timeaio, tlstran_timer_cb, ep)) != 0)) {

		return (rv);
	}

	ep->authmode = NNG_TLS_AUTH_MODE_NONE;

	if (strlen(host) == 0) {
		host = NULL;
	}

	
	
	
	
	
	

	if ((rv = nni_aio_alloc(&aio, NULL, NULL)) != 0) {
		tlstran_ep_fini(ep);
		return (rv);
	}
	nni_resolv_ip(host, url->u_port, af, true, &ep->sa, aio);
	nni_aio_wait(aio);
	rv = nni_aio_result(aio);
	nni_aio_free(aio);

	if ((rv != 0) || ((rv = nng_stream_listener_alloc_url(&ep->listener, url)) != 0) || ((rv = nni_stream_listener_set(ep->listener, NNG_OPT_TLS_AUTH_MODE, &ep->authmode, sizeof(ep->authmode), NNI_TYPE_INT32)) != 0)) {



		tlstran_ep_fini(ep);
		return (rv);
	}


	nni_listener_add_stat(nlistener, &ep->st_rcv_max);

	*lp = ep;
	return (0);
}

static void tlstran_ep_cancel(nni_aio *aio, void *arg, int rv)
{
	tlstran_ep *ep = arg;
	nni_mtx_lock(&ep->mtx);
	if (ep->useraio == aio) {
		ep->useraio = NULL;
		nni_aio_finish_error(aio, rv);
	}
	nni_mtx_unlock(&ep->mtx);
}


static int tlstran_ep_get_url(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tlstran_ep *ep = arg;
	char *      s;
	int         rv;
	int         port = 0;

	if (ep->listener != NULL) {
		(void) nng_stream_listener_get_int( ep->listener, NNG_OPT_TCP_BOUND_PORT, &port);
	}

	if ((rv = nni_url_asprintf_port(&s, ep->url, port)) == 0) {
		rv = nni_copyout_str(s, v, szp, t);
		nni_strfree(s);
	}
	return (rv);
}

static int tlstran_ep_set_conf(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tlstran_ep *ep = arg;
	NNI_ARG_UNUSED(sz);
	NNI_ARG_UNUSED(t);
	nni_mtx_lock(&ep->mtx);
	ep->conf = (conf *) v;
	nni_mtx_unlock(&ep->mtx);
	return 0;
}

static int tlstran_ep_get_recvmaxsz(void *arg, void *v, size_t *szp, nni_opt_type t)
{
	tlstran_ep *ep = arg;
	int         rv;

	nni_mtx_lock(&ep->mtx);
	rv = nni_copyout_size(ep->rcvmax, v, szp, t);
	nni_mtx_unlock(&ep->mtx);
	return (rv);
}

static int tlstran_ep_set_recvmaxsz(void *arg, const void *v, size_t sz, nni_opt_type t)
{
	tlstran_ep *ep = arg;
	size_t      val;
	int         rv;
	if ((rv = nni_copyin_size(&val, v, sz, 0, NNI_MAXSZ, t)) == 0) {
		tlstran_pipe *p;
		nni_mtx_lock(&ep->mtx);
		ep->rcvmax = val;
		NNI_LIST_FOREACH (&ep->waitpipes, p) {
			p->rcvmax = val;
		}
		NNI_LIST_FOREACH (&ep->negopipes, p) {
			p->rcvmax = val;
		}
		NNI_LIST_FOREACH (&ep->busypipes, p) {
			p->rcvmax = val;
		}
		nni_mtx_unlock(&ep->mtx);

		nni_stat_set_value(&ep->st_rcv_max, val);

	}
	return (rv);
}

static int tlstran_ep_bind(void *arg)
{
	tlstran_ep *ep = arg;
	int         rv;

	nni_mtx_lock(&ep->mtx);
	rv = nng_stream_listener_listen(ep->listener);
	nni_mtx_unlock(&ep->mtx);

	return (rv);
}

static void tlstran_ep_accept(void *arg, nni_aio *aio)
{
	tlstran_ep *ep = arg;
	int         rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&ep->mtx);
	if (ep->closed) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, NNG_ECLOSED);
		return;
	}
	if (ep->useraio != NULL) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, NNG_EBUSY);
		return;
	}
	if ((rv = nni_aio_schedule(aio, tlstran_ep_cancel, ep)) != 0) {
		nni_mtx_unlock(&ep->mtx);
		nni_aio_finish_error(aio, rv);
		return;
	}
	ep->useraio = aio;
	if (!ep->started) {
		ep->started = true;
		nng_stream_listener_accept(ep->listener, ep->connaio);
	} else {
		tlstran_ep_match(ep);
	}
	nni_mtx_unlock(&ep->mtx);
}


static nni_sp_pipe_ops tlstran_pipe_ops = {
	.p_init  = tlstran_pipe_init, .p_fini  = tlstran_pipe_fini, .p_stop  = tlstran_pipe_stop, .p_send  = tlstran_pipe_send, .p_recv  = tlstran_pipe_recv, .p_close = tlstran_pipe_close,  .p_getopt = tlstran_pipe_getopt, };








static const nni_option tlstran_ep_opts[] = {
	{
	    .o_name = NNG_OPT_RECVMAXSZ, .o_get  = tlstran_ep_get_recvmaxsz, .o_set  = tlstran_ep_set_recvmaxsz, }, {



	    .o_name = NNG_OPT_URL, .o_get  = tlstran_ep_get_url, }, {


	    .o_name = NANO_CONF, .o_set  = tlstran_ep_set_conf, },  {



	    .o_name = NULL, }, };


static int tlstran_listener_get( void *arg, const char *name, void *buf, size_t *szp, nni_type t)

{
	tlstran_ep *ep = arg;
	int         rv;

	rv = nni_stream_listener_get(ep->listener, name, buf, szp, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_getopt(tlstran_ep_opts, name, ep, buf, szp, t);
	}
	return (rv);
}

static int tlstran_listener_set( void *arg, const char *name, const void *buf, size_t sz, nni_type t)

{
	tlstran_ep *ep = arg;
	int         rv;

	rv = nni_stream_listener_set( ep != NULL ? ep->listener : NULL, name, buf, sz, t);
	if (rv == NNG_ENOTSUP) {
		rv = nni_setopt(tlstran_ep_opts, name, ep, buf, sz, t);
	}
	return (rv);
}

static nni_sp_listener_ops tlstran_listener_ops = {
	.l_init   = tlstran_ep_init_listener, .l_fini   = tlstran_ep_fini, .l_bind   = tlstran_ep_bind, .l_accept = tlstran_ep_accept, .l_close  = tlstran_ep_close, .l_getopt = tlstran_listener_get, .l_setopt = tlstran_listener_set, };







static nni_sp_tran tlstran_mqtt = {
	.tran_scheme   = "tls+nmq-tcp", .tran_listener = &tlstran_listener_ops, .tran_pipe     = &tlstran_pipe_ops, .tran_init     = tlstran_init, .tran_fini     = tlstran_fini, };





static nni_sp_tran tls_tcp4_tran_mqtt = {
	.tran_scheme   = "tls+nmq-tcp4", .tran_listener = &tlstran_listener_ops, .tran_pipe     = &tlstran_pipe_ops, .tran_init     = tlstran_init, .tran_fini     = tlstran_fini, };





static nni_sp_tran tls_tcp6_tran_mqtt = {
	.tran_scheme   = "tls+nmq-tcp6", .tran_listener = &tlstran_listener_ops, .tran_pipe     = &tlstran_pipe_ops, .tran_init     = tlstran_init, .tran_fini     = tlstran_fini, };






int nmq_mqtt_tls_register(void)
{
	return (nni_init());
}


void nni_nmq_broker_tls_register(void)
{
	nni_sp_tran_register(&tlstran_mqtt);
	nni_sp_tran_register(&tls_tcp4_tran_mqtt);
	nni_sp_tran_register(&tls_tcp6_tran_mqtt);
}
