



















static void pjmedia_rtp_seq_restart(pjmedia_rtp_seq_session *seq_ctrl,  pj_uint16_t seq);


PJ_DEF(pj_status_t) pjmedia_rtp_session_init( pjmedia_rtp_session *ses, int default_pt, pj_uint32_t sender_ssrc )

{
    PJ_LOG(5, (THIS_FILE,  "pjmedia_rtp_session_init: ses=%p, default_pt=%d, ssrc=0x%x", ses, default_pt, sender_ssrc));


    
    if (sizeof(struct pjmedia_rtp_hdr) != 12) {
	pj_assert(!"Wrong RTP header packing!");
	return PJMEDIA_RTP_EINPACK;
    }

    
    if (sender_ssrc == 0 || sender_ssrc == (pj_uint32_t)-1) {
	sender_ssrc = pj_htonl(pj_rand());
    } else {
	sender_ssrc = pj_htonl(sender_ssrc);
    }

    
    pj_bzero(ses, sizeof(*ses));

    
    
    ses->out_extseq = pj_rand() & 0x7FFF;
    ses->peer_ssrc = 0;
    
    
    ses->out_hdr.v = RTP_VERSION;
    ses->out_hdr.p = 0;
    ses->out_hdr.x = 0;
    ses->out_hdr.cc = 0;
    ses->out_hdr.m = 0;
    ses->out_hdr.pt = (pj_uint8_t) default_pt;
    ses->out_hdr.seq = (pj_uint16_t) pj_htons( (pj_uint16_t)ses->out_extseq );
    ses->out_hdr.ts = 0;
    ses->out_hdr.ssrc = sender_ssrc;

    
    ses->out_pt = (pj_uint16_t) default_pt;

    return PJ_SUCCESS;
}

PJ_DEF(pj_status_t) pjmedia_rtp_session_init2(  pjmedia_rtp_session *ses, pjmedia_rtp_session_setting settings)

{
    pj_status_t status;
    int		 pt = 0;
    pj_uint32_t	 sender_ssrc = 0;

    if (settings.flags & 1)
	pt = settings.default_pt;
    if (settings.flags & 2)
	sender_ssrc = settings.sender_ssrc;

    status = pjmedia_rtp_session_init(ses, pt, sender_ssrc);
    if (status != PJ_SUCCESS)
	return status;

    if (settings.flags & 4) {
	ses->out_extseq = settings.seq;
	ses->out_hdr.seq = pj_htons((pj_uint16_t)ses->out_extseq);
    }
    if (settings.flags & 8)
	ses->out_hdr.ts = pj_htonl(settings.ts);
    if (settings.flags & 16) {
        ses->has_peer_ssrc = PJ_TRUE;
	ses->peer_ssrc = settings.peer_ssrc;
    }

    PJ_LOG(5, (THIS_FILE, "pjmedia_rtp_session_init2: ses=%p, seq=%d, ts=%d, peer_ssrc=%d", ses, pj_ntohs(ses->out_hdr.seq), pj_ntohl(ses->out_hdr.ts), ses->has_peer_ssrc? ses->peer_ssrc : 0));



    return PJ_SUCCESS;
}


PJ_DEF(pj_status_t) pjmedia_rtp_encode_rtp( pjmedia_rtp_session *ses,  int pt, int m, int payload_len, int ts_len, const void **rtphdr, int *hdrlen )


{
    
    ses->out_hdr.ts = pj_htonl(pj_ntohl(ses->out_hdr.ts)+ts_len);

    
    if (payload_len == 0)
	return PJ_SUCCESS;

    
    ses->out_extseq++;

    
    ses->out_hdr.pt = (pj_uint8_t) ((pt == -1) ? ses->out_pt : pt);
    ses->out_hdr.m = (pj_uint16_t) m;
    ses->out_hdr.seq = pj_htons( (pj_uint16_t) ses->out_extseq);

    
    *rtphdr = &ses->out_hdr;
    *hdrlen = sizeof(pjmedia_rtp_hdr);

    return PJ_SUCCESS;
}


PJ_DEF(pj_status_t) pjmedia_rtp_decode_rtp( pjmedia_rtp_session *ses,  const void *pkt, int pkt_len, const pjmedia_rtp_hdr **hdr, const void **payload, unsigned *payloadlen)



{
    pjmedia_rtp_dec_hdr dec_hdr;

    return pjmedia_rtp_decode_rtp2(ses, pkt, pkt_len, hdr, &dec_hdr,  payload, payloadlen);
}


PJ_DEF(pj_status_t) pjmedia_rtp_decode_rtp2( pjmedia_rtp_session *ses, const void *pkt, int pkt_len, const pjmedia_rtp_hdr **hdr, pjmedia_rtp_dec_hdr *dec_hdr, const void **payload, unsigned *payloadlen)





{
    int offset;

    PJ_UNUSED_ARG(ses);

    
    *hdr = (pjmedia_rtp_hdr*)pkt;

    
    if ((*hdr)->v != RTP_VERSION) {
	return PJMEDIA_RTP_EINVER;
    }

    
    offset = sizeof(pjmedia_rtp_hdr) + ((*hdr)->cc * sizeof(pj_uint32_t));

    
    if ((*hdr)->x) {
        dec_hdr->ext_hdr = (pjmedia_rtp_ext_hdr*)(((pj_uint8_t*)pkt) + offset);
        dec_hdr->ext = (pj_uint32_t*)(dec_hdr->ext_hdr + 1);
        dec_hdr->ext_len = pj_ntohs((dec_hdr->ext_hdr)->length);
        offset += ((dec_hdr->ext_len + 1) * sizeof(pj_uint32_t));
    } else {
	dec_hdr->ext_hdr = NULL;
	dec_hdr->ext = NULL;
	dec_hdr->ext_len = 0;
    }

    
    if (offset > pkt_len)
	return PJMEDIA_RTP_EINLEN;

    
    *payload = ((pj_uint8_t*)pkt) + offset;
    *payloadlen = pkt_len - offset;
 
    
    if ((*hdr)->p && *payloadlen > 0) {
	pj_uint8_t pad_len;

	pad_len = ((pj_uint8_t*)(*payload))[*payloadlen - 1];
	if (pad_len <= *payloadlen)
	    *payloadlen -= pad_len;
    }

    return PJ_SUCCESS;
}


PJ_DEF(void) pjmedia_rtp_session_update( pjmedia_rtp_session *ses,  const pjmedia_rtp_hdr *hdr, pjmedia_rtp_status *p_seq_st)

{
    pjmedia_rtp_session_update2(ses, hdr, p_seq_st, PJ_TRUE);
}

PJ_DEF(void) pjmedia_rtp_session_update2( pjmedia_rtp_session *ses,  const pjmedia_rtp_hdr *hdr, pjmedia_rtp_status *p_seq_st, pj_bool_t check_pt)


{
    pjmedia_rtp_status seq_st;

    
    pj_assert(check_pt==PJ_TRUE || check_pt==PJ_FALSE);

    
    seq_st.status.value = 0;
    seq_st.diff = 0;

    
    if (!ses->has_peer_ssrc && ses->peer_ssrc == 0)
        ses->peer_ssrc = pj_ntohl(hdr->ssrc);

    if (pj_ntohl(hdr->ssrc) != ses->peer_ssrc) {
	seq_st.status.flag.badssrc = 1;
	if (!ses->has_peer_ssrc)
	    ses->peer_ssrc = pj_ntohl(hdr->ssrc);
    }

    
    if (check_pt && hdr->pt != ses->out_pt) {
	if (p_seq_st) {
	    p_seq_st->status.value = seq_st.status.value;
	    p_seq_st->status.flag.bad = 1;
	    p_seq_st->status.flag.badpt = 1;
	}
	return;
    }

    
    if (ses->received == 0)
	pjmedia_rtp_seq_init( &ses->seq_ctrl, pj_ntohs(hdr->seq) );

    
    pjmedia_rtp_seq_update( &ses->seq_ctrl, pj_ntohs(hdr->seq), &seq_st);
    if (seq_st.status.flag.restart) {
	++ses->received;

    } else if (!seq_st.status.flag.bad) {
	++ses->received;
    }

    if (p_seq_st) {
	p_seq_st->status.value = seq_st.status.value;
	p_seq_st->diff = seq_st.diff;
    }
}



void pjmedia_rtp_seq_restart(pjmedia_rtp_seq_session *sess, pj_uint16_t seq)
{
    sess->base_seq = seq;
    sess->max_seq = seq;
    sess->bad_seq = RTP_SEQ_MOD + 1;
    sess->cycles = 0;
}


void pjmedia_rtp_seq_init(pjmedia_rtp_seq_session *sess, pj_uint16_t seq)
{
    pjmedia_rtp_seq_restart(sess, seq);

    sess->max_seq = (pj_uint16_t) (seq - 1);
    sess->probation = MIN_SEQUENTIAL;
}


void pjmedia_rtp_seq_update( pjmedia_rtp_seq_session *sess,  pj_uint16_t seq, pjmedia_rtp_status *seq_status)

{
    pj_uint16_t udelta = (pj_uint16_t) (seq - sess->max_seq);
    pjmedia_rtp_status st;
    
    
    st.status.value = 0;
    st.diff = 0;

    
    if (sess->probation) {

	st.status.flag.probation = 1;
	
        if (seq == sess->max_seq+ 1) {
	    
	    st.diff = 1;
	    sess->probation--;
            sess->max_seq = seq;
            if (sess->probation == 0) {
		st.status.flag.probation = 0;
            }
	} else {

	    st.diff = 0;

	    st.status.flag.bad = 1;
	    if (seq == sess->max_seq)
		st.status.flag.dup = 1;
	    else st.status.flag.outorder = 1;

	    sess->probation = MIN_SEQUENTIAL - 1;
	    sess->max_seq = seq;
        }


    } else if (udelta == 0) {

	st.status.flag.dup = 1;

    } else if (udelta < MAX_DROPOUT) {
	
	if (seq < sess->max_seq) {
	    
	    sess->cycles += RTP_SEQ_MOD;
        }
        sess->max_seq = seq;

	st.diff = udelta;

    } else if (udelta <= (RTP_SEQ_MOD - MAX_MISORDER)) {
	
        if (seq == sess->bad_seq) {
	    
	    pjmedia_rtp_seq_restart(sess, seq);
	    st.status.flag.restart = 1;
	    st.status.flag.probation = 1;
	    st.diff = 1;
	}
        else {
	    sess->bad_seq = (seq + 1) & (RTP_SEQ_MOD-1);
            st.status.flag.bad = 1;
	    st.status.flag.outorder = 1;
        }
    } else {
	
	st.status.flag.outorder = 1;
    }
    

    if (seq_status) {
	seq_status->diff = st.diff;
	seq_status->status.value = st.status.value;
    }
}


