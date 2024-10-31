










































    static void data_to_host(void *data, pj_uint8_t bits, unsigned count)
    {
	unsigned i;

        count /= (bits == 32? 4 : 2);

	if (bits == 32) {
	    pj_int32_t *data32 = (pj_int32_t *)data;
	    for (i=0; i<count; ++i)
		data32[i] = pj_swap32(data32[i]);
	} else {
	    pj_int16_t *data16 = (pj_int16_t *)data;
	    for (i=0; i<count; ++i)
		data16[i] = pj_swap16(data16[i]);
	}

    }
    static void data_to_host2(void *data, pj_uint8_t nsizes, pj_uint8_t *sizes)
    {
	unsigned i;
        pj_int8_t *datap = (pj_int8_t *)data;
        for (i = 0; i < nsizes; i++) {
            data_to_host(datap, 32, sizes[i]);
            datap += sizes[i++];
            if (i >= nsizes)
                break;
            data_to_host(datap, 16, sizes[i]);
            datap += sizes[i];
	}
    }





typedef struct avi_fmt_info {
    pjmedia_format_id   fmt_id;
    pjmedia_format_id   eff_fmt_id;
} avi_fmt_info;

static avi_fmt_info avi_fmts[] = {
    {PJMEDIA_FORMAT_MJPEG}, {PJMEDIA_FORMAT_H264}, {PJMEDIA_FORMAT_UYVY}, {PJMEDIA_FORMAT_YUY2}, {PJMEDIA_FORMAT_IYUV}, {PJMEDIA_FORMAT_I420}, {PJMEDIA_FORMAT_DIB}, {PJMEDIA_FORMAT_RGB24}, {PJMEDIA_FORMAT_RGB32}, {PJMEDIA_FORMAT_PACK('X','V','I','D'), PJMEDIA_FORMAT_MPEG4}, {PJMEDIA_FORMAT_PACK('x','v','i','d'), PJMEDIA_FORMAT_MPEG4}, {PJMEDIA_FORMAT_PACK('D','I','V','X'), PJMEDIA_FORMAT_MPEG4}, {PJMEDIA_FORMAT_PACK('F','M','P','4'), PJMEDIA_FORMAT_MPEG4}, {PJMEDIA_FORMAT_PACK('D','X','5','0'), PJMEDIA_FORMAT_MPEG4}








};

struct pjmedia_avi_streams {
    unsigned        num_streams;
    pjmedia_port  **streams;
};

struct avi_reader_port {
    pjmedia_port     base;
    unsigned         stream_id;
    unsigned	     options;
    pjmedia_format_id fmt_id;
    unsigned         usec_per_frame;
    pj_uint16_t	     bits_per_sample;
    pj_bool_t	     eof;
    pj_off_t	     fsize;
    pj_off_t	     start_data;
    pj_uint8_t       pad;
    pj_oshandle_t    fd;
    pj_ssize_t       size_left;
    pj_timestamp     next_ts;

    pj_status_t	   (*cb)(pjmedia_port*, void*);
    pj_bool_t	     subscribed;
    void	   (*cb2)(pjmedia_port*, void*);
};


static pj_status_t avi_get_frame(pjmedia_port *this_port,  pjmedia_frame *frame);
static pj_status_t avi_on_destroy(pjmedia_port *this_port);

static struct avi_reader_port *create_avi_port(pj_pool_t *pool)
{
    const pj_str_t name = pj_str("file");
    struct avi_reader_port *port;

    port = PJ_POOL_ZALLOC_T(pool, struct avi_reader_port);
    if (!port)
	return NULL;

    
    pjmedia_port_info_init(&port->base.info, &name, SIGNATURE,  8000, 1, 16, 80);

    port->fd = (pj_oshandle_t)(pj_ssize_t)-1;
    port->base.get_frame = &avi_get_frame;
    port->base.on_destroy = &avi_on_destroy;

    return port;
}




static pj_status_t file_read3(pj_oshandle_t fd, void *data, pj_ssize_t size, pj_uint16_t bits, pj_ssize_t *psz_read)
{
    pj_ssize_t size_read = size, size_to_read = size;
    pj_status_t status = pj_file_read(fd, data, &size_read);
    if (status != PJ_SUCCESS)
        return status;

    
    if (bits > 0)
        data_to_host(data, bits, size_read);

    if (size_read != size_to_read) {
        if (psz_read)
            *psz_read = size_read;
        return AVI_EOF;
    }

    return status;
}


PJ_DEF(pj_status_t)
pjmedia_avi_player_create_streams(pj_pool_t *pool, const char *filename, unsigned options, pjmedia_avi_streams **p_streams)


{
    pjmedia_avi_hdr avi_hdr;
    struct avi_reader_port *fport[PJMEDIA_AVI_MAX_NUM_STREAMS];
    pj_off_t pos;
    unsigned i, nstr = 0;
    pj_status_t status = PJ_SUCCESS;

    
    PJ_ASSERT_RETURN(pool && filename && p_streams, PJ_EINVAL);

    
    if (!pj_file_exists(filename)) {
	return PJ_ENOTFOUND;
    }

    
    fport[0] = create_avi_port(pool);
    if (!fport[0]) {
	return PJ_ENOMEM;
    }

    
    fport[0]->fsize = pj_file_size(filename);

    
    if (fport[0]->fsize <= sizeof(riff_hdr_t) + sizeof(avih_hdr_t) +  sizeof(strl_hdr_t))
    {
	return PJMEDIA_EINVALIMEDIATYPE;
    }

    
    status = pj_file_open(pool, filename, PJ_O_RDONLY, &fport[0]->fd);
    if (status != PJ_SUCCESS)
	return status;

    
    status = file_read(fport[0]->fd, &avi_hdr, sizeof(riff_hdr_t) + sizeof(avih_hdr_t));
    if (status != PJ_SUCCESS)
        goto on_error;

    
    if (!COMPARE_TAG(avi_hdr.riff_hdr.riff, PJMEDIA_AVI_RIFF_TAG) || !COMPARE_TAG(avi_hdr.riff_hdr.avi, PJMEDIA_AVI_AVI_TAG) || !COMPARE_TAG(avi_hdr.avih_hdr.list_tag, PJMEDIA_AVI_LIST_TAG) || !COMPARE_TAG(avi_hdr.avih_hdr.hdrl_tag, PJMEDIA_AVI_HDRL_TAG) || !COMPARE_TAG(avi_hdr.avih_hdr.avih, PJMEDIA_AVI_AVIH_TAG))



    {
	status = PJMEDIA_EINVALIMEDIATYPE;
        goto on_error;
    }

    PJ_LOG(5, (THIS_FILE, "The AVI file has %d streams.", avi_hdr.avih_hdr.num_streams));

    
    if (avi_hdr.avih_hdr.num_streams > PJMEDIA_AVI_MAX_NUM_STREAMS) {
        status = PJMEDIA_EAVIUNSUPP;
        goto on_error;
    }

    
    if (avi_hdr.avih_hdr.flags & AVIF_MUSTUSEINDEX || avi_hdr.avih_hdr.pad > 1)
    {
        PJ_LOG(3, (THIS_FILE, "Warning!!! Possibly unsupported AVI format: " "flags:%d, pad:%d", avi_hdr.avih_hdr.flags, avi_hdr.avih_hdr.pad));

    }

    
    for (i = 0; i < avi_hdr.avih_hdr.num_streams; i++) {
        pj_size_t elem = 0;
        pj_ssize_t size_to_read;

        
        status = file_read(fport[0]->fd, &avi_hdr.strl_hdr[i], sizeof(strl_hdr_t));
        if (status != PJ_SUCCESS)
            goto on_error;
        
        elem = COMPARE_TAG(avi_hdr.strl_hdr[i].data_type,  PJMEDIA_AVI_VIDS_TAG) ? sizeof(strf_video_hdr_t) :

               COMPARE_TAG(avi_hdr.strl_hdr[i].data_type,  PJMEDIA_AVI_AUDS_TAG) ? sizeof(strf_audio_hdr_t) : 0;


        
        status = file_read2(fport[0]->fd, &avi_hdr.strf_hdr[i], elem, 0);
        if (status != PJ_SUCCESS)
            goto on_error;

        
        if (elem == sizeof(strf_video_hdr_t))
            data_to_host2(&avi_hdr.strf_hdr[i], sizeof(strf_video_hdr_sizes)/ sizeof(strf_video_hdr_sizes[0]), strf_video_hdr_sizes);


        else if (elem == sizeof(strf_audio_hdr_t))
            data_to_host2(&avi_hdr.strf_hdr[i], sizeof(strf_audio_hdr_sizes)/ sizeof(strf_audio_hdr_sizes[0]), strf_audio_hdr_sizes);



        
        size_to_read = avi_hdr.strl_hdr[i].list_sz - (sizeof(strl_hdr_t) - 8) - elem;
	status = pj_file_setpos(fport[0]->fd, size_to_read, PJ_SEEK_CUR);
	if (status != PJ_SUCCESS) {
            goto on_error;
	}
    }

    
    status = pj_file_setpos(fport[0]->fd, avi_hdr.avih_hdr.list_sz + sizeof(riff_hdr_t) + 8, PJ_SEEK_SET);
    if (status != PJ_SUCCESS) {
        goto on_error;
    }

    
    do {
        pjmedia_avi_subchunk ch;
        int read = 0;

        status = file_read(fport[0]->fd, &ch, sizeof(pjmedia_avi_subchunk));
        if (status != PJ_SUCCESS) {
            goto on_error;
        }

        if (COMPARE_TAG(ch.id, PJMEDIA_AVI_LIST_TAG))
        {
            read = 4;
            status = file_read(fport[0]->fd, &ch, read);
            if (COMPARE_TAG(ch.id, PJMEDIA_AVI_MOVI_TAG))
                break;
        }

        status = pj_file_setpos(fport[0]->fd, ch.len-read, PJ_SEEK_CUR);
        if (status != PJ_SUCCESS) {
            goto on_error;
        }
    } while(1);

    status = pj_file_getpos(fport[0]->fd, &pos);
    if (status != PJ_SUCCESS)
        goto on_error;

    for (i = 0, nstr = 0; i < avi_hdr.avih_hdr.num_streams; i++) {
	pjmedia_format_id fmt_id;

        
        if ((!COMPARE_TAG(avi_hdr.strl_hdr[i].data_type,  PJMEDIA_AVI_VIDS_TAG) && !COMPARE_TAG(avi_hdr.strl_hdr[i].data_type, PJMEDIA_AVI_AUDS_TAG)) || avi_hdr.strl_hdr[i].flags & AVISF_DISABLED)



        {
            continue;
        }

        if (COMPARE_TAG(avi_hdr.strl_hdr[i].data_type,  PJMEDIA_AVI_VIDS_TAG))
        {
            int j;

            if (avi_hdr.strl_hdr[i].flags & AVISF_VIDEO_PALCHANGES) {
                PJ_LOG(4, (THIS_FILE, "Unsupported video stream"));
                continue;
            }

            fmt_id = avi_hdr.strl_hdr[i].codec;
            for (j = sizeof(avi_fmts)/sizeof(avi_fmts[0])-1; j >= 0; j--) {
                
                if (fmt_id == avi_fmts[j].fmt_id) {
                    if (avi_fmts[j].eff_fmt_id)
                        fmt_id = avi_fmts[j].eff_fmt_id;
                    break;
                }
            }
            
            if (j < 0) {
                PJ_LOG(4, (THIS_FILE, "Unsupported video stream"));
                continue;
            }
        } else {
            
	    strf_audio_hdr_t *hdr = (strf_audio_hdr_t*)
				    &avi_hdr.strf_hdr[i].strf_audio_hdr;
            if (hdr->fmt_tag == PJMEDIA_WAVE_FMT_TAG_PCM && hdr->bits_per_sample == 16)
	    {
		fmt_id = PJMEDIA_FORMAT_PCM;
	    }
	    else if (hdr->fmt_tag == PJMEDIA_WAVE_FMT_TAG_ALAW)
	    {
		fmt_id = PJMEDIA_FORMAT_PCMA;
	    }
	    else if (hdr->fmt_tag == PJMEDIA_WAVE_FMT_TAG_ULAW)
	    {
		fmt_id = PJMEDIA_FORMAT_PCMU;
	    }
	    else {
                PJ_LOG(4, (THIS_FILE, "Unsupported audio stream"));
                continue;
            }
        }

        if (nstr > 0) {
            
            fport[nstr] = create_avi_port(pool);
            if (!fport[nstr]) {
	        status = PJ_ENOMEM;
                goto on_error;
            }

            
            status = pj_file_open(pool, filename, PJ_O_RDONLY, &fport[nstr]->fd);
            if (status != PJ_SUCCESS)
                goto on_error;

            
            status = pj_file_setpos(fport[nstr]->fd, pos, PJ_SEEK_SET);
            if (status != PJ_SUCCESS) {
                goto on_error;
            }
        }

        fport[nstr]->stream_id = i;
        fport[nstr]->fmt_id = fmt_id;

        nstr++;
    }

    if (nstr == 0) {
        status = PJMEDIA_EAVIUNSUPP;
        goto on_error;
    }

    for (i = 0; i < nstr; i++) {
        strl_hdr_t *strl_hdr = &avi_hdr.strl_hdr[fport[i]->stream_id];

        
        fport[i]->options = options;
        fport[i]->fsize = fport[0]->fsize;
        
        fport[i]->start_data = pos;
        
        if (COMPARE_TAG(strl_hdr->data_type, PJMEDIA_AVI_VIDS_TAG)) {
            strf_video_hdr_t *strf_hdr = &avi_hdr.strf_hdr[fport[i]->stream_id].strf_video_hdr;
            const pjmedia_video_format_info *vfi;

            vfi = pjmedia_get_video_format_info( pjmedia_video_format_mgr_instance(), strl_hdr->codec);


            fport[i]->bits_per_sample = (vfi ? vfi->bpp : 0);
            fport[i]->usec_per_frame = avi_hdr.avih_hdr.usec_per_frame;
            pjmedia_format_init_video(&fport[i]->base.info.fmt, fport[i]->fmt_id, strf_hdr->biWidth, strf_hdr->biHeight, strl_hdr->rate, strl_hdr->scale);





            
            bps = strf_hdr->biSizeImage * 8 * strl_hdr->rate / strl_hdr->scale;
            if (bps==0) {
        	
        	bps = strf_hdr->biWidth * strf_hdr->biHeight * strf_hdr->biBitCount * strl_hdr->rate / strl_hdr->scale;

            }
            fport[i]->base.info.fmt.det.vid.avg_bps = bps;
            fport[i]->base.info.fmt.det.vid.max_bps = bps;

        } else {
            strf_audio_hdr_t *strf_hdr = &avi_hdr.strf_hdr[fport[i]->stream_id].strf_audio_hdr;

            fport[i]->bits_per_sample = strf_hdr->bits_per_sample;
            fport[i]->usec_per_frame = avi_hdr.avih_hdr.usec_per_frame;
            pjmedia_format_init_audio(&fport[i]->base.info.fmt, fport[i]->fmt_id, strf_hdr->sample_rate, strf_hdr->nchannels, strf_hdr->bits_per_sample, 20000 , strf_hdr->bytes_per_sec * 8, strf_hdr->bytes_per_sec * 8);







	    
	    if (fport[i]->fmt_id == PJMEDIA_FORMAT_PCMA || fport[i]->fmt_id == PJMEDIA_FORMAT_PCMU)
	    {
		fport[i]->base.info.fmt.id = PJMEDIA_FORMAT_PCM;
		fport[i]->base.info.fmt.det.aud.bits_per_sample = 16;
	    }
	}

        pj_strdup2(pool, &fport[i]->base.info.name, filename);
    }

    
    *p_streams = pj_pool_alloc(pool, sizeof(pjmedia_avi_streams));
    (*p_streams)->num_streams = nstr;
    (*p_streams)->streams = pj_pool_calloc(pool, (*p_streams)->num_streams, sizeof(pjmedia_port *));
    for (i = 0; i < nstr; i++)
        (*p_streams)->streams[i] = &fport[i]->base;

    PJ_LOG(4,(THIS_FILE,  "AVI file player '%.*s' created with " "%d media ports", (int)fport[0]->base.info.name.slen, fport[0]->base.info.name.ptr, (*p_streams)->num_streams));





    return PJ_SUCCESS;

on_error:
    fport[0]->base.on_destroy(&fport[0]->base);
    for (i = 1; i < nstr; i++)
        fport[i]->base.on_destroy(&fport[i]->base);
    if (status == AVI_EOF)
        return PJMEDIA_EINVALIMEDIATYPE;
    return status;
}

PJ_DEF(unsigned)
pjmedia_avi_streams_get_num_streams(pjmedia_avi_streams *streams)
{
    pj_assert(streams);
    return streams->num_streams;
}

PJ_DEF(pjmedia_avi_stream *)
pjmedia_avi_streams_get_stream(pjmedia_avi_streams *streams, unsigned idx)
{
    pj_assert(streams);
    return (idx < streams->num_streams ? streams->streams[idx] : NULL);
}

PJ_DEF(pjmedia_avi_stream *)
pjmedia_avi_streams_get_stream_by_media(pjmedia_avi_streams *streams, unsigned start_idx, pjmedia_type media_type)

{
    unsigned i;

    pj_assert(streams);
    for (i = start_idx; i < streams->num_streams; i++)
        if (streams->streams[i]->info.fmt.type == media_type)
            return streams->streams[i];
    return NULL;
}



PJ_DEF(pj_ssize_t) pjmedia_avi_stream_get_len(pjmedia_avi_stream *stream)
{
    struct avi_reader_port *fport;

    
    PJ_ASSERT_RETURN(stream, -PJ_EINVAL);

    
    PJ_ASSERT_RETURN(stream->info.signature == SIGNATURE, -PJ_EINVALIDOP);

    fport = (struct avi_reader_port*) stream;

    return (pj_ssize_t)(fport->fsize - fport->start_data);
}




PJ_DEF(pj_status_t)
pjmedia_avi_stream_set_eof_cb( pjmedia_avi_stream *stream, void *user_data, pj_status_t (*cb)(pjmedia_avi_stream *stream, void *usr_data))


{
    struct avi_reader_port *fport;

    
    PJ_ASSERT_RETURN(stream, -PJ_EINVAL);

    
    PJ_ASSERT_RETURN(stream->info.signature == SIGNATURE, -PJ_EINVALIDOP);

    PJ_LOG(1, (THIS_FILE, "pjmedia_avi_stream_set_eof_cb() is deprecated. " "Use pjmedia_avi_stream_set_eof_cb2() instead."));

    fport = (struct avi_reader_port*) stream;

    fport->base.port_data.pdata = user_data;
    fport->cb = cb;

    return PJ_SUCCESS;
}




PJ_DEF(pj_status_t)
pjmedia_avi_stream_set_eof_cb2(pjmedia_avi_stream *stream, void *user_data, void (*cb)(pjmedia_avi_stream *stream, void *usr_data))


{
    struct avi_reader_port *fport;

    
    PJ_ASSERT_RETURN(stream, -PJ_EINVAL);

    
    PJ_ASSERT_RETURN(stream->info.signature == SIGNATURE, -PJ_EINVALIDOP);

    fport = (struct avi_reader_port*) stream;

    fport->base.port_data.pdata = user_data;
    fport->cb2 = cb;

    return PJ_SUCCESS;
}


static pj_status_t file_on_event(pjmedia_event *event, void *user_data)
{
    struct avi_reader_port *fport = (struct avi_reader_port*)user_data;

    if (event->type == PJMEDIA_EVENT_CALLBACK) {
	if (fport->cb2)
	    (*fport->cb2)(&fport->base, fport->base.port_data.pdata);
    }
    
    return PJ_SUCCESS;
}



static pj_status_t avi_get_frame(pjmedia_port *this_port,  pjmedia_frame *frame)
{
    struct avi_reader_port *fport = (struct avi_reader_port*)this_port;
    pj_status_t status = PJ_SUCCESS;
    pj_ssize_t size_read = 0, size_to_read = 0;

    pj_assert(fport->base.info.signature == SIGNATURE);

    
    if (fport->eof) {
	PJ_LOG(5,(THIS_FILE, "File port %.*s EOF", (int)fport->base.info.name.slen, fport->base.info.name.ptr));


	
	if (fport->cb2) {
	    pj_bool_t no_loop = (fport->options & PJMEDIA_AVI_FILE_NO_LOOP);

	    if (!fport->subscribed) {
	    	status = pjmedia_event_subscribe(NULL, &file_on_event, fport, fport);
	    	fport->subscribed = (status == PJ_SUCCESS)? PJ_TRUE:
	    			    PJ_FALSE;
	    }

	    if (fport->subscribed && fport->eof != 2) {
	    	pjmedia_event event;

	    	if (no_loop) {
	    	    
	    	    fport->eof = 2;
	    	} else {
	    	    fport->eof = PJ_FALSE;
        	    pj_file_setpos(fport->fd, fport->start_data, PJ_SEEK_SET);
	    	}

	    	pjmedia_event_init(&event, PJMEDIA_EVENT_CALLBACK, NULL, fport);
	    	pjmedia_event_publish(NULL, fport, &event, PJMEDIA_EVENT_PUBLISH_POST_EVENT);
	    }
	    
	    
	    frame->type = PJMEDIA_FRAME_TYPE_NONE;
	    frame->size = 0;
	    
	    return (no_loop? PJ_EEOF: PJ_SUCCESS);

	} else if (fport->cb) {
	    status = (*fport->cb)(this_port, fport->base.port_data.pdata);
	}

	
	if ((status != PJ_SUCCESS) || (fport->options & PJMEDIA_AVI_FILE_NO_LOOP))
        {
	    frame->type = PJMEDIA_FRAME_TYPE_NONE;
	    frame->size = 0;
	    return PJ_EEOF;
	}

        
	PJ_LOG(5,(THIS_FILE, "File port %.*s rewinding..", (int)fport->base.info.name.slen, fport->base.info.name.ptr));

	fport->eof = PJ_FALSE;
        pj_file_setpos(fport->fd, fport->start_data, PJ_SEEK_SET);
    }

    
    if (fport->base.info.fmt.type == PJMEDIA_TYPE_AUDIO && (fport->fmt_id == PJMEDIA_FORMAT_PCMA || fport->fmt_id == PJMEDIA_FORMAT_PCMU))

    {
	frame->size >>= 1;
    }

    
    size_to_read = frame->size;
    do {
        pjmedia_avi_subchunk ch = {0, 0};
        char *cid;
        unsigned stream_id;

        
        if (fport->size_left > 0 && fport->size_left < size_to_read) {
            status = file_read3(fport->fd, frame->buf, fport->size_left, fport->bits_per_sample, &size_read);
            if (status != PJ_SUCCESS)
                goto on_error2;
            size_to_read -= fport->size_left;
            fport->size_left = 0;
        }

        
        if (fport->size_left == 0) {
            pj_off_t pos;
            pj_file_getpos(fport->fd, &pos);

            
            if (fport->pad) {
                status = pj_file_setpos(fport->fd, fport->pad, PJ_SEEK_CUR);
                fport->pad = 0;
            }

            status = file_read(fport->fd, &ch, sizeof(pjmedia_avi_subchunk));
            if (status != PJ_SUCCESS) {
                size_read = 0;
                goto on_error2;
            }

            cid = (char *)&ch.id;
            if (cid[0] >= '0' && cid[0] <= '9' && cid[1] >= '0' && cid[1] <= '9')
            {
                stream_id = (cid[0] - '0') * 10 + (cid[1] - '0');
            } else stream_id = 100;
            fport->pad = (pj_uint8_t)ch.len & 1;

            TRACE_((THIS_FILE, "Reading movi data at pos %u (%x), id: %.*s, " "length: %u", (unsigned long)pos, (unsigned long)pos, 4, cid, ch.len));


            
            if (stream_id != fport->stream_id) {
                if (COMPARE_TAG(ch.id, PJMEDIA_AVI_LIST_TAG))
                    PJ_LOG(5, (THIS_FILE, "Unsupported LIST tag found in " "the movi data."));
                else if (COMPARE_TAG(ch.id, PJMEDIA_AVI_RIFF_TAG)) {
                    PJ_LOG(3, (THIS_FILE, "Unsupported format: multiple " "AVIs in a single file."));
                    status = AVI_EOF;
                    goto on_error2;
                }

                status = pj_file_setpos(fport->fd, ch.len, PJ_SEEK_CUR);
                continue;
            }
            fport->size_left = ch.len;
        }

        frame->type = (fport->base.info.fmt.type == PJMEDIA_TYPE_VIDEO ? PJMEDIA_FRAME_TYPE_VIDEO : PJMEDIA_FRAME_TYPE_AUDIO);

        if (frame->type == PJMEDIA_FRAME_TYPE_AUDIO) {
            if (size_to_read > fport->size_left)
                size_to_read = fport->size_left;
            status = file_read3(fport->fd, (char *)frame->buf + frame->size - size_to_read, size_to_read, fport->bits_per_sample, &size_read);

            if (status != PJ_SUCCESS)
                goto on_error2;
            fport->size_left -= size_to_read;
        } else {
            pj_assert(frame->size >= ch.len);
            status = file_read3(fport->fd, frame->buf, ch.len, 0, &size_read);
            if (status != PJ_SUCCESS)
                goto on_error2;
            frame->size = ch.len;
            fport->size_left = 0;
        }

        break;

    } while(1);
    frame->timestamp.u64 = fport->next_ts.u64;
    if (frame->type == PJMEDIA_FRAME_TYPE_AUDIO) {

	
	if (fport->fmt_id == PJMEDIA_FORMAT_PCMA || fport->fmt_id == PJMEDIA_FORMAT_PCMU)
	{
	    unsigned i;
	    pj_uint16_t *dst;
	    pj_uint8_t *src;

	    dst = (pj_uint16_t*)frame->buf + frame->size - 1;
	    src = (pj_uint8_t*)frame->buf + frame->size - 1;

	    if (fport->fmt_id == PJMEDIA_FORMAT_PCMU) {
		for (i = 0; i < frame->size; ++i) {
		    *dst-- = (pj_uint16_t) pjmedia_ulaw2linear(*src--);
		}
	    } else {
		for (i = 0; i < frame->size; ++i) {
		    *dst-- = (pj_uint16_t) pjmedia_alaw2linear(*src--);
		}
	    }

	    
	    frame->size <<= 1;
	}

	if (fport->usec_per_frame) {
	    fport->next_ts.u64 += (fport->usec_per_frame * fport->base.info.fmt.det.aud.clock_rate / 1000000);

	} else {
	    fport->next_ts.u64 += (frame->size * fport->base.info.fmt.det.aud.clock_rate / (fport->base.info.fmt.det.aud.avg_bps / 8));

	}
    } else {
	if (fport->usec_per_frame) {
	    fport->next_ts.u64 += (fport->usec_per_frame * VIDEO_CLOCK_RATE / 1000000);
	} else {
	    fport->next_ts.u64 += (frame->size * VIDEO_CLOCK_RATE / (fport->base.info.fmt.det.vid.avg_bps / 8));
	}
    }

    return PJ_SUCCESS;

on_error2:
    if (status == AVI_EOF) {
        fport->eof = PJ_TRUE;

        size_to_read -= size_read;
        if (size_to_read == (pj_ssize_t)frame->size) {
            
 	    frame->type = PJMEDIA_FRAME_TYPE_NONE;
	    frame->size = 0;
	    return PJ_EEOF;           
        }
        pj_bzero((char *)frame->buf + frame->size - size_to_read, size_to_read);

        return PJ_SUCCESS;
    }

    return status;
}


static pj_status_t avi_on_destroy(pjmedia_port *this_port)
{
    struct avi_reader_port *fport = (struct avi_reader_port*) this_port;

    pj_assert(this_port->info.signature == SIGNATURE);

    if (fport->subscribed) {
    	pjmedia_event_unsubscribe(NULL, &file_on_event, fport, fport);
    	fport->subscribed = PJ_FALSE;
    }

    if (fport->fd != (pj_oshandle_t) (pj_ssize_t)-1)
        pj_file_close(fport->fd);
    return PJ_SUCCESS;
}



