




























static pj_status_t ipp_test_alloc( pjmedia_codec_factory *factory,  const pjmedia_codec_info *id );
static pj_status_t ipp_default_attr( pjmedia_codec_factory *factory,  const pjmedia_codec_info *id, pjmedia_codec_param *attr );

static pj_status_t ipp_enum_codecs( pjmedia_codec_factory *factory,  unsigned *count, pjmedia_codec_info codecs[]);

static pj_status_t ipp_alloc_codec( pjmedia_codec_factory *factory,  const pjmedia_codec_info *id, pjmedia_codec **p_codec);

static pj_status_t ipp_dealloc_codec( pjmedia_codec_factory *factory,  pjmedia_codec *codec );


static pj_status_t  ipp_codec_init( pjmedia_codec *codec,  pj_pool_t *pool );
static pj_status_t  ipp_codec_open( pjmedia_codec *codec,  pjmedia_codec_param *attr );
static pj_status_t  ipp_codec_close( pjmedia_codec *codec );
static pj_status_t  ipp_codec_modify(pjmedia_codec *codec,  const pjmedia_codec_param *attr );
static pj_status_t  ipp_codec_parse( pjmedia_codec *codec, void *pkt, pj_size_t pkt_size, const pj_timestamp *ts, unsigned *frame_cnt, pjmedia_frame frames[]);




static pj_status_t  ipp_codec_encode( pjmedia_codec *codec,  const struct pjmedia_frame *input, unsigned output_buf_len, struct pjmedia_frame *output);


static pj_status_t  ipp_codec_decode( pjmedia_codec *codec,  const struct pjmedia_frame *input, unsigned output_buf_len, struct pjmedia_frame *output);


static pj_status_t  ipp_codec_recover(pjmedia_codec *codec,  unsigned output_buf_len, struct pjmedia_frame *output);



static pjmedia_codec_op ipp_op =  {
    &ipp_codec_init, &ipp_codec_open, &ipp_codec_close, &ipp_codec_modify, &ipp_codec_parse, &ipp_codec_encode, &ipp_codec_decode, &ipp_codec_recover };









static pjmedia_codec_factory_op ipp_factory_op = {
    &ipp_test_alloc, &ipp_default_attr, &ipp_enum_codecs, &ipp_alloc_codec, &ipp_dealloc_codec, &pjmedia_codec_ipp_deinit };







static struct ipp_factory {
    pjmedia_codec_factory    base;
    pjmedia_endpt	    *endpt;
    pj_pool_t		    *pool;
    pj_mutex_t		    *mutex;
    unsigned		     g7221_pcm_shift;
} ipp_factory;


typedef struct ipp_private {
    int			 codec_idx;	    
    void		*codec_setting;	    
    pj_pool_t		*pool;		    

    USC_Handle		 enc;		    
    USC_Handle		 dec;		    
    USC_CodecInfo	*info;		    
    pj_uint16_t		 frame_size;	    

    pj_bool_t		 plc_enabled;	    
    pjmedia_plc		*plc;		    

    pj_bool_t		 vad_enabled;	    
    pjmedia_silence_det	*vad;		    
    pj_timestamp	 last_tx;	    

    unsigned		 g7221_pcm_shift;   
} ipp_private_t;



extern USC_Fxns USC_G729AFP_Fxns;
extern USC_Fxns USC_G729I_Fxns;
extern USC_Fxns USC_G723_Fxns;
extern USC_Fxns USC_G726_Fxns;
extern USC_Fxns USC_G728_Fxns;
extern USC_Fxns USC_G722_Fxns;
extern USC_Fxns USC_GSMAMR_Fxns;
extern USC_Fxns USC_AMRWB_Fxns;
extern USC_Fxns USC_AMRWBE_Fxns;





typedef void (*predecode_cb)(ipp_private_t *codec_data, const pjmedia_frame *rtp_frame, USC_Bitstream *usc_frame);



typedef pj_status_t (*parse_cb)(ipp_private_t *codec_data, void *pkt,  pj_size_t pkt_size, const pj_timestamp *ts, unsigned *frame_cnt, pjmedia_frame frames[]);



typedef pj_status_t (*pack_cb)(ipp_private_t *codec_data, void *pkt,  pj_size_t *pkt_size, pj_size_t max_pkt_size);




static    void predecode_g723( ipp_private_t *codec_data, const pjmedia_frame *rtp_frame, USC_Bitstream *usc_frame);

static pj_status_t parse_g723( ipp_private_t *codec_data, void *pkt,  pj_size_t pkt_size, const pj_timestamp *ts, unsigned *frame_cnt, pjmedia_frame frames[]);


static void predecode_g729( ipp_private_t *codec_data, const pjmedia_frame *rtp_frame, USC_Bitstream *usc_frame);


static    void predecode_amr( ipp_private_t *codec_data, const pjmedia_frame *rtp_frame, USC_Bitstream *usc_frame);

static pj_status_t parse_amr( ipp_private_t *codec_data, void *pkt,  pj_size_t pkt_size, const pj_timestamp *ts, unsigned *frame_cnt, pjmedia_frame frames[]);

static  pj_status_t pack_amr( ipp_private_t *codec_data, void *pkt,  pj_size_t *pkt_size, pj_size_t max_pkt_size);

static    void predecode_g7221( ipp_private_t *codec_data, const pjmedia_frame *rtp_frame, USC_Bitstream *usc_frame);

static  pj_status_t pack_g7221( ipp_private_t *codec_data, void *pkt,  pj_size_t *pkt_size, pj_size_t max_pkt_size);


static struct ipp_codec {
    int		     enabled;		
    const char	    *name;		
    pj_uint8_t	     pt;		
    USC_Fxns	    *fxns;		
    unsigned	     clock_rate;	
    unsigned	     channel_count;	
    unsigned	     samples_per_frame;	

    unsigned	     def_bitrate;	
    unsigned	     max_bitrate;	
    pj_uint8_t	     frm_per_pkt;	
    int		     has_native_vad;	
    int		     has_native_plc;	

    predecode_cb     predecode;		
    parse_cb	     parse;		
    pack_cb	     pack;		

    pjmedia_codec_fmtp dec_fmtp;	
}

ipp_codec[] =  {

    {1, "AMR",	    PJMEDIA_RTP_PT_AMR,       &USC_GSMAMR_Fxns,  8000, 1, 160,  7400, 12200, 2, 1, 1, &predecode_amr, &parse_amr, &pack_amr, {1, {{{"octet-align", 11}, {"1", 1}}} }


    },    {1, "AMR-WB",   PJMEDIA_RTP_PT_AMRWB,     &USC_AMRWB_Fxns,  16000, 1, 320, 15850, 23850, 2, 1, 1, &predecode_amr, &parse_amr, &pack_amr, {1, {{{"octet-align", 11}, {"1", 1}}} }






    },     {1, "G729",	    PJMEDIA_RTP_PT_G729,      &USC_G729AFP_Fxns, 8000, 1,  80, 8000, 11800, 2, 1, 1, &predecode_g729, NULL, NULL },  {1, "G729",	    PJMEDIA_RTP_PT_G729,      &USC_G729I_Fxns,	 8000, 1,  80, 8000, 11800, 2, 1, 1, &predecode_g729, NULL, NULL },      {1, "G723",	    PJMEDIA_RTP_PT_G723,      &USC_G723_Fxns,	 8000, 1, 240, 6300,  6300, 1, 1, 1, &predecode_g723, &parse_g723, NULL },    {0, "G726-16",  PJMEDIA_RTP_PT_G726_16,   &USC_G726_Fxns,	 8000, 1,  80, 16000, 16000, 2, 0, 0, NULL, NULL, NULL }, {0, "G726-24",  PJMEDIA_RTP_PT_G726_24,   &USC_G726_Fxns,	 8000, 1,  80, 24000, 24000, 2, 0, 0, NULL, NULL, NULL }, {1, "G726-32",  PJMEDIA_RTP_PT_G726_32,   &USC_G726_Fxns,	 8000, 1,  80, 32000, 32000, 2, 0, 0, NULL, NULL, NULL }, {0, "G726-40",  PJMEDIA_RTP_PT_G726_40,   &USC_G726_Fxns,	 8000, 1,  80, 40000, 40000, 2, 0, 0, NULL, NULL, NULL },  {1, "G721",	    PJMEDIA_RTP_PT_G721,      &USC_G726_Fxns,	 8000, 1,  80, 32000, 32000, 2, 0, 0, NULL, NULL, NULL },    {1, "G728",	    PJMEDIA_RTP_PT_G728,      &USC_G728_Fxns,	 8000, 1,  80, 16000, 16000, 2, 0, 1, NULL, NULL, NULL },    {0, "G7221",    PJMEDIA_RTP_PT_G722_1_16, &USC_G722_Fxns,	16000, 1, 320, 16000, 16000, 1, 0, 1, predecode_g7221, NULL, pack_g7221, {1, {{{"bitrate", 7}, {"16000", 5}}} }



























































    }, {1, "G7221",    PJMEDIA_RTP_PT_G722_1_24, &USC_G722_Fxns,	16000, 1, 320, 24000, 24000, 1, 0, 1, predecode_g7221, NULL, pack_g7221, {1, {{{"bitrate", 7}, {"24000", 5}}} }



    }, {1, "G7221",    PJMEDIA_RTP_PT_G722_1_32, &USC_G722_Fxns,	16000, 1, 320, 32000, 32000, 1, 0, 1, predecode_g7221, NULL, pack_g7221, {1, {{{"bitrate", 7}, {"32000", 5}}} }



    },  };





static void predecode_g729( ipp_private_t *codec_data, const pjmedia_frame *rtp_frame, USC_Bitstream *usc_frame)

{
    switch (rtp_frame->size) {
    case 2:
	
	usc_frame->frametype = 1;
	usc_frame->bitrate = codec_data->info->params.modes.bitrate;
	break;
    case 8:  
	
	usc_frame->frametype = 2;
	usc_frame->bitrate = 6400;
	break;
    case 10: 
	
	usc_frame->frametype = 3;
	usc_frame->bitrate = 8000;
	break;
    case 15: 
	
	usc_frame->frametype = 4;
	usc_frame->bitrate = 11800;
	break;
    default: 
	usc_frame->frametype = 0;
	usc_frame->bitrate = 0;
	break;
    }

    usc_frame->pBuffer = rtp_frame->buf;
    usc_frame->nbytes = rtp_frame->size;
}






static    void predecode_g723( ipp_private_t *codec_data, const pjmedia_frame *rtp_frame, USC_Bitstream *usc_frame)

{
    int i, HDR = 0;
    pj_uint8_t *f = (pj_uint8_t*)rtp_frame->buf;

    PJ_UNUSED_ARG(codec_data);

    for (i = 0; i < 2; ++i){
	int tmp;
	tmp = (f[0] >> (i & 0x7)) & 1;
	HDR +=  tmp << i ;
    }

    usc_frame->pBuffer = rtp_frame->buf;
    usc_frame->nbytes = rtp_frame->size;
    usc_frame->bitrate = HDR == 0? 6300 : 5300;
    usc_frame->frametype = 0;
}

static pj_status_t parse_g723(ipp_private_t *codec_data, void *pkt,  pj_size_t pkt_size, const pj_timestamp *ts, unsigned *frame_cnt, pjmedia_frame frames[])

{
    unsigned count = 0;
    pj_uint8_t *f = (pj_uint8_t*)pkt;

    while (pkt_size && count < *frame_cnt) {
	int framesize, i, j;
	int HDR = 0;

	for (i = 0; i < 2; ++i){
	    j = (f[0] >> (i & 0x7)) & 1;
	    HDR +=  j << i ;
	}

	if (HDR == 0)
	    framesize = 24;
	else if (HDR == 1)
	    framesize = 20;
	else if (HDR == 2)
	    framesize = 4;
	else if (HDR == 3)
	    framesize = 1;
	else {
	    pj_assert(!"Unknown G723.1 frametype, packet may be corrupted!");
	    return PJMEDIA_CODEC_EINMODE;
	}

	frames[count].type = PJMEDIA_FRAME_TYPE_AUDIO;
	frames[count].buf = f;
	frames[count].size = framesize;
	frames[count].timestamp.u64 = ts->u64 + count *  ipp_codec[codec_data->codec_idx].samples_per_frame;

	f += framesize;
	pkt_size -= framesize;

	++count;
    }

    *frame_cnt = count;
    return PJ_SUCCESS;
}








typedef struct amr_settings_t {
    pjmedia_codec_amr_pack_setting enc_setting;
    pjmedia_codec_amr_pack_setting dec_setting;
    pj_int8_t enc_mode;
} amr_settings_t;



static void predecode_amr( ipp_private_t *codec_data, const pjmedia_frame *rtp_frame, USC_Bitstream *usc_frame)

{
    pjmedia_frame frame;
    pjmedia_codec_amr_bit_info *info;
    pjmedia_codec_amr_pack_setting *setting;

    setting = &((amr_settings_t*)codec_data->codec_setting)->dec_setting;

    frame = *rtp_frame;
    pjmedia_codec_amr_predecode(rtp_frame, setting, &frame);
    info = (pjmedia_codec_amr_bit_info*) &frame.bit_info;

    usc_frame->pBuffer = frame.buf;
    usc_frame->nbytes = frame.size;
    if (info->mode != -1) {
	usc_frame->bitrate = setting->amr_nb?  pjmedia_codec_amrnb_bitrates[info->mode]:
			     pjmedia_codec_amrwb_bitrates[info->mode];
    } else {
	usc_frame->bitrate = 0;
    }

    if (frame.size > 5) {
	
	if (info->good_quality)
	    usc_frame->frametype = 0;
	else usc_frame->frametype = setting->amr_nb ? 5 : 6;
    } else if (frame.size == 5) {
	
	if (info->good_quality) {
	    usc_frame->frametype = info->STI? 2 : 1;
	} else {
	    usc_frame->frametype = setting->amr_nb ? 6 : 7;
	}
    } else {
	
	usc_frame->frametype = 3;
    }
}


static pj_status_t pack_amr(ipp_private_t *codec_data, void *pkt,  pj_size_t *pkt_size, pj_size_t max_pkt_size)
{
    enum {MAX_FRAMES_PER_PACKET = PJMEDIA_MAX_FRAME_DURATION_MS / 20};

    pjmedia_frame frames[MAX_FRAMES_PER_PACKET];
    unsigned nframes = 0;
    pjmedia_codec_amr_bit_info *info;
    pj_uint8_t *r; 
    pj_uint8_t SID_FT;
    pjmedia_codec_amr_pack_setting *setting;
    const pj_uint8_t *framelen_tbl;

    setting = &((amr_settings_t*)codec_data->codec_setting)->enc_setting;
    framelen_tbl = setting->amr_nb? pjmedia_codec_amrnb_framelen:
				    pjmedia_codec_amrwb_framelen;

    SID_FT = (pj_uint8_t)(setting->amr_nb? 8 : 9);

    
    r = (pj_uint8_t*)pkt + max_pkt_size - *pkt_size;
    pj_memmove(r, pkt, *pkt_size);

    
    for (;;) {
	pj_bool_t eof;
	pj_uint16_t info_;

	info_ = *((pj_uint16_t*)r);
	eof = ((info_ & 0x40) != 0);

	info = (pjmedia_codec_amr_bit_info*) &frames[nframes].bit_info;
	pj_bzero(info, sizeof(*info));
	info->frame_type = (pj_uint8_t)(info_ & 0x0F);
	info->good_quality = (pj_uint8_t)((info_ & 0x80) == 0);
	info->mode = (pj_int8_t) ((info_ >> 8) & 0x0F);
	info->STI = (pj_uint8_t)((info_ >> 5) & 1);

	frames[nframes].buf = r + 2;
	frames[nframes].size = info->frame_type <= SID_FT ? framelen_tbl[info->frame_type] : 0;

	r += frames[nframes].size + 2;

	
	if (++nframes >= MAX_FRAMES_PER_PACKET || eof)
	    break;
    }

    
    *pkt_size = max_pkt_size;
    return pjmedia_codec_amr_pack(frames, nframes, setting, pkt, pkt_size);
}



static pj_status_t parse_amr(ipp_private_t *codec_data, void *pkt,  pj_size_t pkt_size, const pj_timestamp *ts, unsigned *frame_cnt, pjmedia_frame frames[])

{
    amr_settings_t* s = (amr_settings_t*)codec_data->codec_setting;
    pjmedia_codec_amr_pack_setting *setting;
    pj_status_t status;
    pj_uint8_t cmr;

    setting = &s->dec_setting;

    status = pjmedia_codec_amr_parse(pkt, pkt_size, ts, setting, frames,  frame_cnt, &cmr);
    if (status != PJ_SUCCESS)
	return status;

    
    if (((setting->amr_nb && cmr <= 7) || (!setting->amr_nb && cmr <= 8)) && s->enc_mode != cmr)
    {
	struct ipp_codec *ippc = &ipp_codec[codec_data->codec_idx];

	s->enc_mode = cmr;
	codec_data->info->params.modes.bitrate = s->enc_setting.amr_nb? pjmedia_codec_amrnb_bitrates[s->enc_mode] :
				pjmedia_codec_amrwb_bitrates[s->enc_mode];
	ippc->fxns->std.Control(&codec_data->info->params.modes,  codec_data->enc);

	PJ_LOG(4,(THIS_FILE, "AMR%s switched encoding mode to: %d (%dbps)", (s->enc_setting.amr_nb?"":"-WB"), s->enc_mode, codec_data->info->params.modes.bitrate));


    }

    return PJ_SUCCESS;
}






static void predecode_g7221( ipp_private_t *codec_data, const pjmedia_frame *rtp_frame, USC_Bitstream *usc_frame)

{
    usc_frame->pBuffer = (char*)rtp_frame->buf;
    usc_frame->nbytes = rtp_frame->size;
    usc_frame->frametype = 0;
    usc_frame->bitrate = codec_data->info->params.modes.bitrate;


    {
	pj_uint16_t *p, *p_end;

	p = (pj_uint16_t*)rtp_frame->buf;
	p_end = p + rtp_frame->size/2;
	while (p < p_end) {
	    *p = pj_ntohs(*p);
	    ++p;
	}
    }

}

static pj_status_t pack_g7221( ipp_private_t *codec_data, void *pkt,  pj_size_t *pkt_size, pj_size_t max_pkt_size)
{
    PJ_UNUSED_ARG(codec_data);
    PJ_UNUSED_ARG(max_pkt_size);


    {
	pj_uint16_t *p, *p_end;

	p = (pj_uint16_t*)pkt;
	p_end = p + *pkt_size/2;
	while (p < p_end) {
	    *p = pj_htons(*p);
	    ++p;
	}
    }

    PJ_UNUSED_ARG(pkt);
    PJ_UNUSED_ARG(pkt_size);


    return PJ_SUCCESS;
}





PJ_DEF(pj_status_t) pjmedia_codec_g7221_set_pcm_shift(int val)
{
    PJ_ASSERT_RETURN(val >= 0, PJ_EINVAL);

    ipp_factory.g7221_pcm_shift = val;
    return PJ_SUCCESS;
}





PJ_DEF(pj_status_t) pjmedia_codec_ipp_init( pjmedia_endpt *endpt )
{
    pjmedia_codec_mgr *codec_mgr;
    pj_str_t codec_name;
    pj_status_t status;

    if (ipp_factory.pool != NULL) {
	
	return PJ_SUCCESS;
    }

    
    ipp_factory.base.op = &ipp_factory_op;
    ipp_factory.base.factory_data = NULL;
    ipp_factory.endpt = endpt;
    ipp_factory.g7221_pcm_shift = PJMEDIA_G7221_DEFAULT_PCM_SHIFT;

    ipp_factory.pool = pjmedia_endpt_create_pool(endpt, "IPP codecs", 4000, 4000);
    if (!ipp_factory.pool)
	return PJ_ENOMEM;

    
    status = pj_mutex_create_simple(ipp_factory.pool, "IPP codecs",  &ipp_factory.mutex);
    if (status != PJ_SUCCESS)
	goto on_error;

    
    codec_mgr = pjmedia_endpt_get_codec_mgr(endpt);
    if (!codec_mgr) {
	status = PJ_EINVALIDOP;
	goto on_error;
    }

    

    pj_cstr(&codec_name, "G7221");
    status = pjmedia_sdp_neg_register_fmt_match_cb( &codec_name, &pjmedia_codec_g7221_match_sdp);

    if (status != PJ_SUCCESS)
	goto on_error;



    pj_cstr(&codec_name, "AMR");
    status = pjmedia_sdp_neg_register_fmt_match_cb( &codec_name, &pjmedia_codec_amr_match_sdp);

    if (status != PJ_SUCCESS)
	goto on_error;



    pj_cstr(&codec_name, "AMR-WB");
    status = pjmedia_sdp_neg_register_fmt_match_cb( &codec_name, &pjmedia_codec_amr_match_sdp);

    if (status != PJ_SUCCESS)
	goto on_error;


    
    PJ_UNUSED_ARG(codec_name);

    
    status = pjmedia_codec_mgr_register_factory(codec_mgr,  &ipp_factory.base);
    if (status != PJ_SUCCESS)
	goto on_error;

    
    return PJ_SUCCESS;

on_error:
    pj_pool_release(ipp_factory.pool);
    ipp_factory.pool = NULL;
    return status;
}


PJ_DEF(pj_status_t) pjmedia_codec_ipp_deinit(void)
{
    pjmedia_codec_mgr *codec_mgr;
    pj_status_t status;

    if (ipp_factory.pool == NULL) {
	
	return PJ_SUCCESS;
    }

    pj_mutex_lock(ipp_factory.mutex);

    
    codec_mgr = pjmedia_endpt_get_codec_mgr(ipp_factory.endpt);
    if (!codec_mgr) {
	pj_pool_release(ipp_factory.pool);
	ipp_factory.pool = NULL;
	pj_mutex_unlock(ipp_factory.mutex);
	return PJ_EINVALIDOP;
    }

    
    status = pjmedia_codec_mgr_unregister_factory(codec_mgr, &ipp_factory.base);
    
    
    pj_mutex_unlock(ipp_factory.mutex);
    pj_mutex_destroy(ipp_factory.mutex);
    ipp_factory.mutex = NULL;

    
    pj_pool_release(ipp_factory.pool);
    ipp_factory.pool = NULL;

    return status;
}



static pj_status_t ipp_test_alloc( pjmedia_codec_factory *factory,  const pjmedia_codec_info *info )
{
    unsigned i;

    PJ_UNUSED_ARG(factory);

    
    if (info->type != PJMEDIA_TYPE_AUDIO)
	return PJMEDIA_CODEC_EUNSUP;

    for (i = 0; i < PJ_ARRAY_SIZE(ipp_codec); ++i) {
	pj_str_t name = pj_str((char*)ipp_codec[i].name);
	if ((pj_stricmp(&info->encoding_name, &name) == 0) && (info->clock_rate == (unsigned)ipp_codec[i].clock_rate) && (info->channel_cnt == (unsigned)ipp_codec[i].channel_count) && (ipp_codec[i].enabled))


	{
	    return PJ_SUCCESS;
	}
    }
    
    
    return PJMEDIA_CODEC_EUNSUP;
}


static pj_status_t ipp_default_attr (pjmedia_codec_factory *factory,  const pjmedia_codec_info *id, pjmedia_codec_param *attr )

{
    unsigned i;

    PJ_ASSERT_RETURN(factory==&ipp_factory.base, PJ_EINVAL);

    pj_bzero(attr, sizeof(pjmedia_codec_param));

    for (i = 0; i < PJ_ARRAY_SIZE(ipp_codec); ++i) {
	pj_str_t name = pj_str((char*)ipp_codec[i].name);
	if ((pj_stricmp(&id->encoding_name, &name) == 0) && (id->clock_rate == (unsigned)ipp_codec[i].clock_rate) && (id->channel_cnt == (unsigned)ipp_codec[i].channel_count) && (id->pt == (unsigned)ipp_codec[i].pt))


	{
	    attr->info.pt = (pj_uint8_t)id->pt;
	    attr->info.channel_cnt = ipp_codec[i].channel_count;
	    attr->info.clock_rate = ipp_codec[i].clock_rate;
	    attr->info.avg_bps = ipp_codec[i].def_bitrate;
	    attr->info.max_bps = ipp_codec[i].max_bitrate;
	    attr->info.pcm_bits_per_sample = 16;
	    attr->info.frm_ptime =  (pj_uint16_t)
				    (ipp_codec[i].samples_per_frame * 1000 /  ipp_codec[i].channel_count / ipp_codec[i].clock_rate);

	    attr->setting.frm_per_pkt = ipp_codec[i].frm_per_pkt;

	    
	    attr->setting.plc = 1;
	    attr->setting.penh= 0;
	    attr->setting.vad = 1;
	    attr->setting.cng = attr->setting.vad;
	    attr->setting.dec_fmtp = ipp_codec[i].dec_fmtp;

	    if (attr->setting.vad == 0) {

		if (id->pt == PJMEDIA_RTP_PT_G729) {
		    
		    attr->setting.dec_fmtp.cnt = 1;
		    pj_strset2(&attr->setting.dec_fmtp.param[0].name, "annexb");
		    pj_strset2(&attr->setting.dec_fmtp.param[0].val, "no");
		}

	    }

	    return PJ_SUCCESS;
	}
    }

    return PJMEDIA_CODEC_EUNSUP;
}


static pj_status_t ipp_enum_codecs(pjmedia_codec_factory *factory,  unsigned *count, pjmedia_codec_info codecs[])

{
    unsigned max;
    unsigned i;

    PJ_UNUSED_ARG(factory);
    PJ_ASSERT_RETURN(codecs && *count > 0, PJ_EINVAL);

    max = *count;
    
    for (i = 0, *count = 0; i < PJ_ARRAY_SIZE(ipp_codec) && *count < max; ++i) 
    {
	if (!ipp_codec[i].enabled)
	    continue;

	pj_bzero(&codecs[*count], sizeof(pjmedia_codec_info));
	codecs[*count].encoding_name = pj_str((char*)ipp_codec[i].name);
	codecs[*count].pt = ipp_codec[i].pt;
	codecs[*count].type = PJMEDIA_TYPE_AUDIO;
	codecs[*count].clock_rate = ipp_codec[i].clock_rate;
	codecs[*count].channel_cnt = ipp_codec[i].channel_count;

	++*count;
    }

    return PJ_SUCCESS;
}


static pj_status_t ipp_alloc_codec( pjmedia_codec_factory *factory,  const pjmedia_codec_info *id, pjmedia_codec **p_codec)

{
    ipp_private_t *codec_data;
    pjmedia_codec *codec;
    int idx;
    pj_pool_t *pool;
    unsigned i;

    PJ_ASSERT_RETURN(factory && id && p_codec, PJ_EINVAL);
    PJ_ASSERT_RETURN(factory == &ipp_factory.base, PJ_EINVAL);

    pj_mutex_lock(ipp_factory.mutex);

    
    idx = -1;
    for (i = 0; i < PJ_ARRAY_SIZE(ipp_codec); ++i) {
	pj_str_t name = pj_str((char*)ipp_codec[i].name);
	if ((pj_stricmp(&id->encoding_name, &name) == 0) && (id->clock_rate == (unsigned)ipp_codec[i].clock_rate) && (id->channel_cnt == (unsigned)ipp_codec[i].channel_count) && (ipp_codec[i].enabled))


	{
	    idx = i;
	    break;
	}
    }
    if (idx == -1) {
	*p_codec = NULL;
	return PJMEDIA_CODEC_EFAILED;
    }

    
    pool = pjmedia_endpt_create_pool(ipp_factory.endpt, "IPPcodec", 512, 512);
    codec = PJ_POOL_ZALLOC_T(pool, pjmedia_codec);
    PJ_ASSERT_RETURN(codec != NULL, PJ_ENOMEM);
    codec->op = &ipp_op;
    codec->factory = factory;
    codec->codec_data = PJ_POOL_ZALLOC_T(pool, ipp_private_t);
    codec_data = (ipp_private_t*) codec->codec_data;

    
    if (!ipp_codec[idx].has_native_plc) {
	pj_status_t status;
	status = pjmedia_plc_create(pool, ipp_codec[idx].clock_rate,  ipp_codec[idx].samples_per_frame, 0, &codec_data->plc);

	if (status != PJ_SUCCESS) {
	    pj_pool_release(pool);
	    pj_mutex_unlock(ipp_factory.mutex);
	    return status;
	}
    }

    
    if (!ipp_codec[idx].has_native_vad) {
	pj_status_t status;
	status = pjmedia_silence_det_create(pool, ipp_codec[idx].clock_rate, ipp_codec[idx].samples_per_frame, &codec_data->vad);


	if (status != PJ_SUCCESS) {
	    pj_pool_release(pool);
	    pj_mutex_unlock(ipp_factory.mutex);
	    return status;
	}
    }

    codec_data->pool = pool;
    codec_data->codec_idx = idx;

    pj_mutex_unlock(ipp_factory.mutex);

    *p_codec = codec;
    return PJ_SUCCESS;
}


static pj_status_t ipp_dealloc_codec( pjmedia_codec_factory *factory,  pjmedia_codec *codec )
{
    ipp_private_t *codec_data;

    PJ_ASSERT_RETURN(factory && codec, PJ_EINVAL);
    PJ_ASSERT_RETURN(factory == &ipp_factory.base, PJ_EINVAL);

    
    codec_data = (ipp_private_t*) codec->codec_data;
    if (codec_data->enc != NULL || codec_data->dec != NULL) {
	ipp_codec_close(codec);
    }

    pj_pool_release(codec_data->pool);

    return PJ_SUCCESS;
}


static pj_status_t ipp_codec_init( pjmedia_codec *codec,  pj_pool_t *pool )
{
    PJ_UNUSED_ARG(codec);
    PJ_UNUSED_ARG(pool);
    return PJ_SUCCESS;
}


static pj_status_t ipp_codec_open( pjmedia_codec *codec,  pjmedia_codec_param *attr )
{
    ipp_private_t *codec_data = (ipp_private_t*) codec->codec_data;
    struct ipp_codec *ippc = &ipp_codec[codec_data->codec_idx];
    int info_size;
    pj_pool_t *pool;
    int i, j;
    USC_MemBank *membanks;
    int nb_membanks;

    pool = codec_data->pool;

    
    if (USC_NoError != ippc->fxns->std.GetInfoSize(&info_size)) {
	PJ_LOG(1,(THIS_FILE, "Error getting codec info size"));
	goto on_error;
    }
    
    codec_data->info = pj_pool_zalloc(pool, info_size);
    if (USC_NoError != ippc->fxns->std.GetInfo((USC_Handle)NULL,  codec_data->info))
    {
	PJ_LOG(1,(THIS_FILE, "Error getting codec info"));
	goto on_error;
    }

    

    
    codec_data->info->params.direction = USC_ENCODE;
    codec_data->info->params.modes.vad = attr->setting.vad &&  ippc->has_native_vad;
    codec_data->info->params.modes.bitrate = attr->info.avg_bps;
    codec_data->info->params.law = 0; 


    if (ippc->pt == PJMEDIA_RTP_PT_G729) {
	
	for (i = 0; i < attr->setting.enc_fmtp.cnt; ++i) {
	    if (pj_stricmp2(&attr->setting.enc_fmtp.param[i].name, "annexb")==0)
	    {
		if (pj_stricmp2(&attr->setting.enc_fmtp.param[i].val, "no")==0)
		{
		    attr->setting.vad = 0;
		    codec_data->info->params.modes.vad = 0;
		}
		break;
	    }
	}
    }


    
    if (USC_NoError != ippc->fxns->std.NumAlloc(&codec_data->info->params, &nb_membanks))
    {
	PJ_LOG(1,(THIS_FILE, "Error getting no of memory blocks of encoder"));
	goto on_error;
    }

    
    membanks = (USC_MemBank*) pj_pool_zalloc(pool,  sizeof(USC_MemBank) * nb_membanks);
    
    if (USC_NoError != ippc->fxns->std.MemAlloc(&codec_data->info->params,  membanks))
    {
	PJ_LOG(1,(THIS_FILE, "Error getting memory blocks size of encoder"));
	goto on_error;
    }

    
    for (i = 0; i < nb_membanks; i++) {
	membanks[i].pMem = (char*) pj_pool_zalloc(pool, membanks[i].nbytes);
    }

    
    if (USC_NoError != ippc->fxns->std.Init(&codec_data->info->params, membanks, &codec_data->enc))

    {
	PJ_LOG(1,(THIS_FILE, "Error initializing encoder"));
	goto on_error;
    }

    

    
    codec_data->info->params.direction = USC_DECODE;

    
    

    
    if (USC_NoError != ippc->fxns->std.NumAlloc(&codec_data->info->params,  &nb_membanks))
    {
	PJ_LOG(1,(THIS_FILE, "Error getting no of memory blocks of decoder"));
	goto on_error;
    }

    
    membanks = (USC_MemBank*) pj_pool_zalloc(pool,  sizeof(USC_MemBank) * nb_membanks);
    
    if (USC_NoError != ippc->fxns->std.MemAlloc(&codec_data->info->params,  membanks))
    {
	PJ_LOG(1,(THIS_FILE, "Error getting memory blocks size of decoder"));
	goto on_error;
    }

    
    for (i = 0; i < nb_membanks; i++) {
	membanks[i].pMem = (char*) pj_pool_zalloc(pool, membanks[i].nbytes);
    }

    
    if (USC_NoError != ippc->fxns->std.Init(&codec_data->info->params,  membanks, &codec_data->dec))
    {
	PJ_LOG(1,(THIS_FILE, "Error initializing decoder"));
	goto on_error;
    }

    
    ippc->fxns->std.GetInfo((USC_Handle)codec_data->enc, codec_data->info);

    
    i = codec_data->info->params.modes.bitrate * ippc->samples_per_frame;
    j = ippc->clock_rate << 3;
    codec_data->frame_size = (pj_uint16_t)(i / j);
    if (i % j) ++codec_data->frame_size;

    codec_data->vad_enabled = (attr->setting.vad != 0);
    codec_data->plc_enabled = (attr->setting.plc != 0);


    
    if (ippc->pt == PJMEDIA_RTP_PT_AMR || ippc->pt == PJMEDIA_RTP_PT_AMRWB) {
	amr_settings_t *s;
	pj_uint8_t octet_align = 0;
	pj_int8_t enc_mode;

	enc_mode = pjmedia_codec_amr_get_mode( codec_data->info->params.modes.bitrate);
	pj_assert(enc_mode >= 0 && enc_mode <= 8);

	

	for (i = 0; i < attr->setting.dec_fmtp.cnt; ++i) {
	    
	    const pj_str_t STR_FMTP_OCTET_ALIGN = {"octet-align", 11};
	    
	    if (pj_stricmp(&attr->setting.dec_fmtp.param[i].name,  &STR_FMTP_OCTET_ALIGN) == 0)
	    {
		octet_align=(pj_uint8_t)
			    pj_strtoul(&attr->setting.dec_fmtp.param[i].val);
		break;
	    }
	}

	for (i = 0; i < attr->setting.enc_fmtp.cnt; ++i) {
	    
	    const pj_str_t STR_FMTP_MODE_SET = {"mode-set", 8};
	    
	    if (pj_stricmp(&attr->setting.enc_fmtp.param[i].name,  &STR_FMTP_MODE_SET) == 0)
	    {
		const char *p;
		pj_size_t l;
		pj_int8_t diff = 99;
		
		p = pj_strbuf(&attr->setting.enc_fmtp.param[i].val);
		l = pj_strlen(&attr->setting.enc_fmtp.param[i].val);

		while (l--) {
		    if ((ippc->pt==PJMEDIA_RTP_PT_AMR && *p>='0' && *p<='7') || (ippc->pt==PJMEDIA_RTP_PT_AMRWB && *p>='0' && *p<='8'))
		    {
			pj_int8_t tmp = (pj_int8_t)(*p - '0' - enc_mode);

			if (PJ_ABS(diff) > PJ_ABS(tmp) ||  (PJ_ABS(diff) == PJ_ABS(tmp) && tmp > diff))
			{
			    diff = tmp;
			    if (diff == 0) break;
			}
		    }
		    ++p;
		}

		if (diff == 99)
		    goto on_error;

		enc_mode = (pj_int8_t)(enc_mode + diff);

		break;
	    }
	}

	
	s = PJ_POOL_ZALLOC_T(pool, amr_settings_t);
	codec_data->codec_setting = s;

	s->enc_setting.amr_nb = (pj_uint8_t)(ippc->pt == PJMEDIA_RTP_PT_AMR);
	s->enc_setting.octet_aligned = octet_align;
	s->enc_setting.reorder = PJ_TRUE;
	s->enc_setting.cmr = 15;

	s->dec_setting.amr_nb = (pj_uint8_t)(ippc->pt == PJMEDIA_RTP_PT_AMR);
	s->dec_setting.octet_aligned = octet_align;
	s->dec_setting.reorder = PJ_TRUE;

	
	s->enc_mode = enc_mode;
	codec_data->info->params.modes.bitrate = s->enc_setting.amr_nb? pjmedia_codec_amrnb_bitrates[s->enc_mode]:
				pjmedia_codec_amrwb_bitrates[s->enc_mode];
	ippc->fxns->std.Control(&codec_data->info->params.modes,  codec_data->enc);

	PJ_LOG(4,(THIS_FILE, "AMR%s encoding mode: %d (%dbps)",  (s->enc_setting.amr_nb?"":"-WB"), s->enc_mode, codec_data->info->params.modes.bitrate));



	
	attr->info.avg_bps = codec_data->info->params.modes.bitrate;
    }



    if (ippc->pt >= PJMEDIA_RTP_PT_G722_1_16 &&  ippc->pt <= PJMEDIA_RTP_PT_G7221_RSV2)
    {
	codec_data->g7221_pcm_shift = ipp_factory.g7221_pcm_shift;
    }


    return PJ_SUCCESS;

on_error:
    return PJMEDIA_CODEC_EFAILED;
}


static pj_status_t ipp_codec_close( pjmedia_codec *codec )
{
    PJ_UNUSED_ARG(codec);

    return PJ_SUCCESS;
}



static pj_status_t  ipp_codec_modify(pjmedia_codec *codec,  const pjmedia_codec_param *attr )
{
    ipp_private_t *codec_data = (ipp_private_t*) codec->codec_data;
    struct ipp_codec *ippc = &ipp_codec[codec_data->codec_idx];

    codec_data->vad_enabled = (attr->setting.vad != 0);
    codec_data->plc_enabled = (attr->setting.plc != 0);

    if (ippc->has_native_vad) {
	USC_Modes modes;

	modes = codec_data->info->params.modes;
	modes.vad = codec_data->vad_enabled;
	ippc->fxns->std.Control(&modes, codec_data->enc);
    }

    return PJ_SUCCESS;
}


static pj_status_t  ipp_codec_parse( pjmedia_codec *codec, void *pkt, pj_size_t pkt_size, const pj_timestamp *ts, unsigned *frame_cnt, pjmedia_frame frames[])




{
    ipp_private_t *codec_data = (ipp_private_t*) codec->codec_data;
    struct ipp_codec *ippc = &ipp_codec[codec_data->codec_idx];
    unsigned count = 0;

    PJ_ASSERT_RETURN(frame_cnt, PJ_EINVAL);

    if (ippc->parse != NULL) {
	return ippc->parse(codec_data, pkt,  pkt_size, ts, frame_cnt, frames);
    }

    while (pkt_size >= codec_data->frame_size && count < *frame_cnt) {
	frames[count].type = PJMEDIA_FRAME_TYPE_AUDIO;
	frames[count].buf = pkt;
	frames[count].size = codec_data->frame_size;
	frames[count].timestamp.u64 = ts->u64 + count*ippc->samples_per_frame;

	pkt = ((char*)pkt) + codec_data->frame_size;
	pkt_size -= codec_data->frame_size;

	++count;
    }

    if (pkt_size && count < *frame_cnt) {
	frames[count].type = PJMEDIA_FRAME_TYPE_AUDIO;
	frames[count].buf = pkt;
	frames[count].size = pkt_size;
	frames[count].timestamp.u64 = ts->u64 + count*ippc->samples_per_frame;
	++count;
    }

    *frame_cnt = count;
    return PJ_SUCCESS;
}


static pj_status_t ipp_codec_encode( pjmedia_codec *codec,  const struct pjmedia_frame *input, unsigned output_buf_len, struct pjmedia_frame *output)


{
    ipp_private_t *codec_data = (ipp_private_t*) codec->codec_data;
    struct ipp_codec *ippc = &ipp_codec[codec_data->codec_idx];
    unsigned samples_per_frame;
    unsigned nsamples;
    pj_size_t tx = 0;
    pj_int16_t *pcm_in   = (pj_int16_t*)input->buf;
    pj_uint8_t  *bits_out = (pj_uint8_t*) output->buf;
    pj_uint8_t pt;

    
    if (codec_data->vad && codec_data->vad_enabled) {
	pj_bool_t is_silence;
	pj_int32_t silence_duration;

	silence_duration = pj_timestamp_diff32(&codec_data->last_tx,  &input->timestamp);

	is_silence = pjmedia_silence_det_detect(codec_data->vad,  (const pj_int16_t*) input->buf, (input->size >> 1), NULL);


	if (is_silence && (PJMEDIA_CODEC_MAX_SILENCE_PERIOD == -1 || silence_duration < (PJMEDIA_CODEC_MAX_SILENCE_PERIOD * (int)ippc->clock_rate / 1000)))


	{
	    output->type = PJMEDIA_FRAME_TYPE_NONE;
	    output->buf = NULL;
	    output->size = 0;
	    output->timestamp = input->timestamp;
	    return PJ_SUCCESS;
	} else {
	    codec_data->last_tx = input->timestamp;
	}
    }

    nsamples = input->size >> 1;
    samples_per_frame = ippc->samples_per_frame;
    pt = ippc->pt;

    PJ_ASSERT_RETURN(nsamples % samples_per_frame == 0,  PJMEDIA_CODEC_EPCMFRMINLEN);

    
    while (nsamples >= samples_per_frame) {
	USC_PCMStream in;
	USC_Bitstream out;

	in.bitrate = codec_data->info->params.modes.bitrate;
	in.nbytes = samples_per_frame << 1;
	in.pBuffer = (char*)pcm_in;
	in.pcmType.bitPerSample = codec_data->info->params.pcmType.bitPerSample;
	in.pcmType.nChannels = codec_data->info->params.pcmType.nChannels;
	in.pcmType.sample_frequency = codec_data->info->params.pcmType.sample_frequency;

	out.pBuffer = (char*)bits_out;


	
	if (pt == PJMEDIA_RTP_PT_AMR || pt == PJMEDIA_RTP_PT_AMRWB) {
	    out.pBuffer += 2;
	}



	
	if (pt >= PJMEDIA_RTP_PT_G722_1_16 &&  pt <= PJMEDIA_RTP_PT_G7221_RSV2 && codec_data->g7221_pcm_shift)

	{
	    unsigned i;
	    for (i = 0; i < samples_per_frame; ++i)
		pcm_in[i] >>= codec_data->g7221_pcm_shift;
	}


	if (USC_NoError != ippc->fxns->Encode(codec_data->enc, &in, &out)) {
	    break;
	}


	
	if (pt == PJMEDIA_RTP_PT_AMR || pt == PJMEDIA_RTP_PT_AMRWB) {
	    pj_uint16_t *info = (pj_uint16_t*)bits_out;

	    
	    out.nbytes += 2;
	    if (out.frametype == 0 || out.frametype == 4 ||  (pt == PJMEDIA_RTP_PT_AMR && out.frametype == 5) || (pt == PJMEDIA_RTP_PT_AMRWB && out.frametype == 6))

	    {
		
		*info = (char)pjmedia_codec_amr_get_mode(out.bitrate);
		
		if (out.frametype == 5 || out.frametype == 6)
		    *info |= 0x80;
	    } else if (out.frametype == 1 || out.frametype == 2 ||  (pt == PJMEDIA_RTP_PT_AMR && out.frametype == 6) || (pt == PJMEDIA_RTP_PT_AMRWB && out.frametype == 7))

	    {
		
		*info = (pj_uint8_t)(pt == PJMEDIA_RTP_PT_AMRWB? 9 : 8);
		
		if (out.frametype == 6 || out.frametype == 7)
		    *info |= 0x80;
		
		if (out.frametype != 1)
		    *info |= 0x20;
	    } else {
		
		*info = 15;
		out.nbytes = 2;
	    }

	    
	    *info |= (char)pjmedia_codec_amr_get_mode(out.bitrate) << 8;

	    
	    if (nsamples == samples_per_frame)
		*info |= 0x40;
	}


	pcm_in += samples_per_frame;
	nsamples -= samples_per_frame;
	tx += out.nbytes;
	bits_out += out.nbytes;


	if (pt == PJMEDIA_RTP_PT_G729) {
	    if (out.frametype == 1) {
		
		break;
	    } else if (out.frametype == 0) {
		
		tx -= out.nbytes;
		break;
	    }
	}


    }

    if (ippc->pack != NULL) {
	ippc->pack(codec_data, output->buf, &tx, output_buf_len);
    }

    
    if (tx == 0) {
	output->buf = NULL;
	output->size = 0;
	output->timestamp.u64 = input->timestamp.u64;
	output->type = PJMEDIA_FRAME_TYPE_NONE;
	return PJ_SUCCESS;
    }

    output->size = tx;
    output->type = PJMEDIA_FRAME_TYPE_AUDIO;
    output->timestamp = input->timestamp;

    return PJ_SUCCESS;
}


static pj_status_t ipp_codec_decode( pjmedia_codec *codec,  const struct pjmedia_frame *input, unsigned output_buf_len, struct pjmedia_frame *output)


{
    ipp_private_t *codec_data = (ipp_private_t*) codec->codec_data;
    struct ipp_codec *ippc = &ipp_codec[codec_data->codec_idx];
    unsigned samples_per_frame;
    USC_PCMStream out;
    USC_Bitstream in;
    pj_uint8_t pt;

    pt = ippc->pt; 
    samples_per_frame = ippc->samples_per_frame;

    PJ_ASSERT_RETURN(output_buf_len >= samples_per_frame << 1, PJMEDIA_CODEC_EPCMTOOSHORT);

    if (input->type == PJMEDIA_FRAME_TYPE_AUDIO) {
	if (ippc->predecode) {
	    ippc->predecode(codec_data, input, &in);
	} else {
	    
	    in.pBuffer = (char*)input->buf;
	    in.nbytes = input->size;
	    in.frametype = 0;
	    in.bitrate = codec_data->info->params.modes.bitrate;
	}

	out.pBuffer = output->buf;
    }

    if (input->type != PJMEDIA_FRAME_TYPE_AUDIO || USC_NoError != ippc->fxns->Decode(codec_data->dec, &in, &out))
    {
	pjmedia_zero_samples((pj_int16_t*)output->buf, samples_per_frame);
	output->size = samples_per_frame << 1;
	output->timestamp.u64 = input->timestamp.u64;
	output->type = PJMEDIA_FRAME_TYPE_AUDIO;
	return PJ_SUCCESS;
    }


    
    if (pt == PJMEDIA_RTP_PT_G726_16 || pt == PJMEDIA_RTP_PT_G726_24 || pt == PJMEDIA_RTP_PT_G726_32 || pt == PJMEDIA_RTP_PT_G726_40 || pt == PJMEDIA_RTP_PT_G721)

    {
	unsigned i;
	pj_int16_t *s = (pj_int16_t*)output->buf;

	for (i = 0; i < samples_per_frame; ++i)
	    s[i] <<= 2;
    }



    
    if (pt >= PJMEDIA_RTP_PT_G722_1_16 &&  pt <= PJMEDIA_RTP_PT_G7221_RSV2 && codec_data->g7221_pcm_shift)

    {
	unsigned i;
	pj_int16_t *s = (pj_int16_t*)output->buf;

	for (i = 0; i < samples_per_frame; ++i)
	    s[i] <<= codec_data->g7221_pcm_shift;
    }


    output->type = PJMEDIA_FRAME_TYPE_AUDIO;
    output->size = samples_per_frame << 1;
    output->timestamp.u64 = input->timestamp.u64;

    
    if (codec_data->plc && codec_data->plc_enabled)
	pjmedia_plc_save(codec_data->plc, (pj_int16_t*)output->buf);

    return PJ_SUCCESS;
}


static pj_status_t  ipp_codec_recover(pjmedia_codec *codec,  unsigned output_buf_len, struct pjmedia_frame *output)

{
    ipp_private_t *codec_data = (ipp_private_t*) codec->codec_data;
    struct ipp_codec *ippc = &ipp_codec[codec_data->codec_idx];
    unsigned samples_per_frame;

    PJ_UNUSED_ARG(output_buf_len);

    samples_per_frame = ippc->samples_per_frame;

    output->type = PJMEDIA_FRAME_TYPE_AUDIO;
    output->size = samples_per_frame << 1;

    if (codec_data->plc_enabled) {
	if (codec_data->plc) {
	    pjmedia_plc_generate(codec_data->plc, (pj_int16_t*)output->buf);
	} else {
	    USC_PCMStream out;
	    out.pBuffer = output->buf;
	    ippc->fxns->Decode(codec_data->dec, NULL, &out);
	}
    } else {
	pjmedia_zero_samples((pj_int16_t*)output->buf, samples_per_frame);
    }

    return PJ_SUCCESS;
}


























