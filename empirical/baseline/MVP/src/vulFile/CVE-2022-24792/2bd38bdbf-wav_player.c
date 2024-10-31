


























    static void samples_to_host(pj_int16_t *samples, unsigned count)
    {
	unsigned i;
	for (i=0; i<count; ++i) {
	    samples[i] = pj_swap16(samples[i]);
	}
    }




struct file_reader_port {
    pjmedia_port     base;
    unsigned	     options;
    pjmedia_wave_fmt_tag fmt_tag;
    pj_uint16_t	     bytes_per_sample;
    pj_bool_t	     eof;
    pj_uint32_t	     bufsize;
    char	    *buf;
    char	    *readpos;
    char	    *eofpos;

    pj_off_t	     fsize;
    unsigned	     start_data;
    unsigned         data_len;
    unsigned         data_left;
    pj_off_t	     fpos;
    pj_oshandle_t    fd;

    pj_status_t	   (*cb)(pjmedia_port*, void*);
    pj_bool_t	     subscribed;
    void	   (*cb2)(pjmedia_port*, void*);
};


static pj_status_t file_get_frame(pjmedia_port *this_port,  pjmedia_frame *frame);
static pj_status_t file_on_destroy(pjmedia_port *this_port);

static struct file_reader_port *create_file_port(pj_pool_t *pool)
{
    const pj_str_t name = pj_str("file");
    struct file_reader_port *port;

    port = PJ_POOL_ZALLOC_T(pool, struct file_reader_port);
    if (!port)
	return NULL;

    
    pjmedia_port_info_init(&port->base.info, &name, SIGNATURE,  8000, 1, 16, 80);

    port->base.get_frame = &file_get_frame;
    port->base.on_destroy = &file_on_destroy;


    return port;
}


static pj_status_t fill_buffer(struct file_reader_port *fport)
{
    pj_uint32_t size_left = fport->bufsize;
    unsigned size_to_read;
    pj_ssize_t size;
    pj_status_t status;

    fport->eofpos = NULL;
    
    while (size_left > 0) {

	
	size = size_to_read = size_left;
	status = pj_file_read(fport->fd,  &fport->buf[fport->bufsize-size_left], &size);

	if (status != PJ_SUCCESS)
	    return status;
	if (size < 0) {
	    
	    return PJ_ECANCELLED;
	}

        if (size > (pj_ssize_t)fport->data_left) {
            
            size = (pj_ssize_t)fport->data_left;
        }

	size_left -= (pj_uint32_t)size;
        fport->data_left -= (pj_uint32_t)size;
	fport->fpos += size;

	
        if (size < (pj_ssize_t)size_to_read) {
            fport->eof = PJ_TRUE;
            fport->eofpos = fport->buf + fport->bufsize - size_left;

            if (fport->options & PJMEDIA_FILE_NO_LOOP) {
                
                if (fport->fmt_tag == PJMEDIA_WAVE_FMT_TAG_PCM) {
                    pj_bzero(fport->eofpos, size_left);
                } else if (fport->fmt_tag == PJMEDIA_WAVE_FMT_TAG_ULAW) {
                    int val = pjmedia_linear2ulaw(0);
                    pj_memset(fport->eofpos, val, size_left);
                } else if (fport->fmt_tag == PJMEDIA_WAVE_FMT_TAG_ALAW) {
                    int val = pjmedia_linear2alaw(0);
                    pj_memset(fport->eofpos, val, size_left);
                }
		size_left = 0;
            }

	    
	    fport->fpos = fport->start_data;
	    pj_file_setpos( fport->fd, fport->fpos, PJ_SEEK_SET);
            fport->data_left = fport->data_len;
	}
    }

    
    samples_to_host((pj_int16_t*)fport->buf,  fport->bufsize/fport->bytes_per_sample);

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjmedia_wav_player_port_create( pj_pool_t *pool, const char *filename, unsigned ptime, unsigned options, pj_ssize_t buff_size, pjmedia_port **p_port )




{
    pjmedia_wave_hdr wave_hdr;
    pj_ssize_t size_to_read, size_read;
    struct file_reader_port *fport;
    pjmedia_audio_format_detail *ad;
    pj_off_t pos;
    pj_str_t name;
    unsigned samples_per_frame;
    pj_status_t status = PJ_SUCCESS;


    
    PJ_ASSERT_RETURN(pool && filename && p_port, PJ_EINVAL);

    
    if (!pj_file_exists(filename)) {
	return PJ_ENOTFOUND;
    }

    
    if (ptime == 0)
	ptime = 20;

    
    if (buff_size < 1) buff_size = PJMEDIA_FILE_PORT_BUFSIZE;


    
    fport = create_file_port(pool);
    if (!fport) {
	return PJ_ENOMEM;
    }


    
    fport->fsize = pj_file_size(filename);

    
    if (fport->fsize <= sizeof(pjmedia_wave_hdr)) {
	return PJMEDIA_ENOTVALIDWAVE;
    }

    
    status = pj_file_open( pool, filename, PJ_O_RDONLY, &fport->fd);
    if (status != PJ_SUCCESS)
	return status;

    
    size_read = size_to_read = sizeof(wave_hdr) - 8;
    status = pj_file_read( fport->fd, &wave_hdr, &size_read);
    if (status != PJ_SUCCESS) {
	pj_file_close(fport->fd);
	return status;
    }
    if (size_read != size_to_read) {
	pj_file_close(fport->fd);
	return PJMEDIA_ENOTVALIDWAVE;
    }

    
    pjmedia_wave_hdr_file_to_host(&wave_hdr);
    
    
    if (wave_hdr.riff_hdr.riff != PJMEDIA_RIFF_TAG || wave_hdr.riff_hdr.wave != PJMEDIA_WAVE_TAG || wave_hdr.fmt_hdr.fmt != PJMEDIA_FMT_TAG)

    {
	pj_file_close(fport->fd);
	TRACE_((THIS_FILE,  "actual value|expected riff=%x|%x, wave=%x|%x fmt=%x|%x", wave_hdr.riff_hdr.riff, PJMEDIA_RIFF_TAG, wave_hdr.riff_hdr.wave, PJMEDIA_WAVE_TAG, wave_hdr.fmt_hdr.fmt, PJMEDIA_FMT_TAG));



	return PJMEDIA_ENOTVALIDWAVE;
    }

    
    switch (wave_hdr.fmt_hdr.fmt_tag) {
    case PJMEDIA_WAVE_FMT_TAG_PCM:
	if (wave_hdr.fmt_hdr.bits_per_sample != 16 ||  wave_hdr.fmt_hdr.block_align != 2 * wave_hdr.fmt_hdr.nchan)
	    status = PJMEDIA_EWAVEUNSUPP;
	break;

    case PJMEDIA_WAVE_FMT_TAG_ALAW:
    case PJMEDIA_WAVE_FMT_TAG_ULAW:
	if (wave_hdr.fmt_hdr.bits_per_sample != 8 || wave_hdr.fmt_hdr.block_align != wave_hdr.fmt_hdr.nchan)
	    status = PJMEDIA_ENOTVALIDWAVE;
	break;

    default:
	status = PJMEDIA_EWAVEUNSUPP;
	break;
    }

    if (status != PJ_SUCCESS) {
	pj_file_close(fport->fd);
	return status;
    }

    fport->fmt_tag = (pjmedia_wave_fmt_tag)wave_hdr.fmt_hdr.fmt_tag;
    fport->bytes_per_sample = (pj_uint16_t) 
			      (wave_hdr.fmt_hdr.bits_per_sample / 8);

    
    if (wave_hdr.fmt_hdr.len > 16) {
	size_to_read = wave_hdr.fmt_hdr.len - 16;
	status = pj_file_setpos(fport->fd, size_to_read, PJ_SEEK_CUR);
	if (status != PJ_SUCCESS) {
	    pj_file_close(fport->fd);
	    return status;
	}
    }

    
    for (;;) {
	pjmedia_wave_subchunk subchunk;
	size_read = 8;
	status = pj_file_read(fport->fd, &subchunk, &size_read);
	if (status != PJ_SUCCESS || size_read != 8) {
	    pj_file_close(fport->fd);
	    return PJMEDIA_EWAVETOOSHORT;
	}

	
	PJMEDIA_WAVE_NORMALIZE_SUBCHUNK(&subchunk);

	
	if (subchunk.id == PJMEDIA_DATA_TAG) {
	    wave_hdr.data_hdr.data = PJMEDIA_DATA_TAG;
	    wave_hdr.data_hdr.len = subchunk.len;
	    break;
	}

	
	size_to_read = subchunk.len;
	status = pj_file_setpos(fport->fd, size_to_read, PJ_SEEK_CUR);
	if (status != PJ_SUCCESS) {
	    pj_file_close(fport->fd);
	    return status;
	}
    }

    
    status = pj_file_getpos(fport->fd, &pos);
    fport->start_data = (unsigned)pos;
    fport->data_len = wave_hdr.data_hdr.len;
    fport->data_left = wave_hdr.data_hdr.len;

    
    if (wave_hdr.data_hdr.len > fport->fsize - fport->start_data) {
    	
    	wave_hdr.data_hdr.len = (pj_uint32_t)fport->fsize - fport->start_data;
	
	
    }
    if (wave_hdr.data_hdr.len < ptime * wave_hdr.fmt_hdr.sample_rate * wave_hdr.fmt_hdr.nchan / 1000)
    {
	pj_file_close(fport->fd);
	return PJMEDIA_EWAVETOOSHORT;
    }

    

    
    fport->options = options;

    
    ad = pjmedia_format_get_audio_format_detail(&fport->base.info.fmt, 1);
    pj_strdup2(pool, &name, filename);
    samples_per_frame = ptime * wave_hdr.fmt_hdr.sample_rate * wave_hdr.fmt_hdr.nchan / 1000;
    pjmedia_port_info_init(&fport->base.info, &name, SIGNATURE, wave_hdr.fmt_hdr.sample_rate, wave_hdr.fmt_hdr.nchan, BITS_PER_SAMPLE, samples_per_frame);




    
    if (wave_hdr.data_hdr.len < (unsigned)buff_size)
	buff_size = wave_hdr.data_hdr.len;

    
    fport->bufsize = (pj_uint32_t)buff_size;


    
    if (samples_per_frame * fport->bytes_per_sample >= fport->bufsize) {
	pj_file_close(fport->fd);
	return PJ_EINVAL;
    }

    
    fport->buf = (char*) pj_pool_alloc(pool, fport->bufsize);
    if (!fport->buf) {
	pj_file_close(fport->fd);
	return PJ_ENOMEM;
    }
 
    fport->readpos = fport->buf;

    
    fport->fpos = fport->start_data;

    
    status = fill_buffer(fport);
    if (status != PJ_SUCCESS) {
	pj_file_close(fport->fd);
	return status;
    }

    

    *p_port = &fport->base;


    PJ_LOG(4,(THIS_FILE,  "File player '%.*s' created: samp.rate=%d, ch=%d, bufsize=%uKB, " "filesize=%luKB", (int)fport->base.info.name.slen, fport->base.info.name.ptr, ad->clock_rate, ad->channel_count, fport->bufsize / 1000, (unsigned long)(fport->fsize / 1000)));








    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjmedia_wav_player_get_info( pjmedia_port *port, pjmedia_wav_player_info *info)

{
    struct file_reader_port *fport;
    PJ_ASSERT_RETURN(port && info, PJ_EINVAL);

    pj_bzero(info, sizeof(*info));

    
    PJ_ASSERT_RETURN(port->info.signature == SIGNATURE, PJ_EINVALIDOP);

    fport = (struct file_reader_port*) port;

    if (fport->fmt_tag == PJMEDIA_WAVE_FMT_TAG_PCM) {
	info->fmt_id = PJMEDIA_FORMAT_PCM;
	info->payload_bits_per_sample = 16;
    } else if (fport->fmt_tag == PJMEDIA_WAVE_FMT_TAG_ULAW) {
	info->fmt_id = PJMEDIA_FORMAT_ULAW;
	info->payload_bits_per_sample = 8;
    } else if (fport->fmt_tag == PJMEDIA_WAVE_FMT_TAG_ALAW) {
	info->fmt_id = PJMEDIA_FORMAT_ALAW;
	info->payload_bits_per_sample = 8;
    } else {
	pj_assert(!"Unsupported format");
	return PJ_ENOTSUP;
    }

    info->size_bytes = (pj_uint32_t)pjmedia_wav_player_get_len(port);
    info->size_samples = info->size_bytes / (info->payload_bits_per_sample / 8);

    return PJ_SUCCESS;
}


PJ_DEF(pj_ssize_t) pjmedia_wav_player_get_len(pjmedia_port *port)
{
    struct file_reader_port *fport;
    pj_ssize_t size;

    
    PJ_ASSERT_RETURN(port, -PJ_EINVAL);

    
    PJ_ASSERT_RETURN(port->info.signature == SIGNATURE, -PJ_EINVALIDOP);

    fport = (struct file_reader_port*) port;

    size = (pj_ssize_t) fport->fsize;
    return size - fport->start_data;
}



PJ_DEF(pj_status_t) pjmedia_wav_player_port_set_pos(pjmedia_port *port, pj_uint32_t bytes )
{
    struct file_reader_port *fport;
    pj_status_t status;

    
    PJ_ASSERT_RETURN(port, PJ_EINVAL);

    
    PJ_ASSERT_RETURN(port->info.signature == SIGNATURE, PJ_EINVALIDOP);


    fport = (struct file_reader_port*) port;

    
    PJ_ASSERT_RETURN(bytes < fport->data_len, PJ_EINVAL);

    fport->fpos = fport->start_data + bytes;
    fport->data_left = fport->data_len - bytes;
    pj_file_setpos( fport->fd, fport->fpos, PJ_SEEK_SET);

    fport->eof = PJ_FALSE;
    status = fill_buffer(fport);
    if (status != PJ_SUCCESS)
	return status;

    fport->readpos = fport->buf;

    return PJ_SUCCESS;
}



PJ_DEF(pj_ssize_t) pjmedia_wav_player_port_get_pos( pjmedia_port *port )
{
    struct file_reader_port *fport;
    pj_size_t payload_pos;

    
    PJ_ASSERT_RETURN(port, -PJ_EINVAL);

    
    PJ_ASSERT_RETURN(port->info.signature == SIGNATURE, -PJ_EINVALIDOP);

    fport = (struct file_reader_port*) port;

    payload_pos = (pj_size_t)(fport->fpos - fport->start_data);
    if (payload_pos == 0)
	return 0;
    else if (payload_pos >= fport->bufsize)
	return payload_pos - fport->bufsize + (fport->readpos - fport->buf);
    else return (fport->readpos - fport->buf) % payload_pos;
}




PJ_DEF(pj_status_t) pjmedia_wav_player_set_eof_cb( pjmedia_port *port, void *user_data, pj_status_t (*cb)(pjmedia_port *port, void *usr_data))


{
    struct file_reader_port *fport;

    
    PJ_ASSERT_RETURN(port, -PJ_EINVAL);

    
    PJ_ASSERT_RETURN(port->info.signature == SIGNATURE, -PJ_EINVALIDOP);

    PJ_LOG(1, (THIS_FILE, "pjmedia_wav_player_set_eof_cb() is deprecated. " "Use pjmedia_wav_player_set_eof_cb2() instead."));

    fport = (struct file_reader_port*) port;

    fport->base.port_data.pdata = user_data;
    fport->cb = cb;

    return PJ_SUCCESS;
}




PJ_DEF(pj_status_t) pjmedia_wav_player_set_eof_cb2(pjmedia_port *port, void *user_data, void (*cb)(pjmedia_port *port, void *usr_data))


{
    struct file_reader_port *fport;

    
    PJ_ASSERT_RETURN(port, -PJ_EINVAL);

    
    PJ_ASSERT_RETURN(port->info.signature == SIGNATURE, -PJ_EINVALIDOP);

    fport = (struct file_reader_port*) port;

    fport->base.port_data.pdata = user_data;
    fport->cb2 = cb;

    return PJ_SUCCESS;
}


static pj_status_t file_on_event(pjmedia_event *event, void *user_data)
{
    struct file_reader_port *fport = (struct file_reader_port*)user_data;

    if (event->type == PJMEDIA_EVENT_CALLBACK) {
	if (fport->cb2)
	    (*fport->cb2)(&fport->base, fport->base.port_data.pdata);
    }
    
    return PJ_SUCCESS;
}



static pj_status_t file_get_frame(pjmedia_port *this_port,  pjmedia_frame *frame)
{
    struct file_reader_port *fport = (struct file_reader_port*)this_port;
    pj_size_t frame_size;
    pj_status_t status = PJ_SUCCESS;

    pj_assert(fport->base.info.signature == SIGNATURE);
    pj_assert(frame->size <= fport->bufsize);

    
    if (fport->eof && fport->readpos >= fport->eofpos) {
	PJ_LOG(5,(THIS_FILE, "File port %.*s EOF", (int)fport->base.info.name.slen, fport->base.info.name.ptr));


	
	if (fport->cb2) {
	    pj_bool_t no_loop = (fport->options & PJMEDIA_FILE_NO_LOOP);

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

	
	if ((status != PJ_SUCCESS) || (fport->options & PJMEDIA_FILE_NO_LOOP))
	{
	    frame->type = PJMEDIA_FRAME_TYPE_NONE;
	    frame->size = 0;
	    return PJ_EEOF;
	}

        
	PJ_LOG(5,(THIS_FILE, "File port %.*s rewinding..", (int)fport->base.info.name.slen, fport->base.info.name.ptr));

	fport->eof = PJ_FALSE;
    }

    
    if (fport->fmt_tag == PJMEDIA_WAVE_FMT_TAG_PCM) {
	frame_size = frame->size;
	
    } else {
	
	pj_assert(fport->fmt_tag == PJMEDIA_WAVE_FMT_TAG_ULAW ||  fport->fmt_tag == PJMEDIA_WAVE_FMT_TAG_ALAW);

	frame_size = frame->size >> 1;
	frame->size = frame_size << 1;
    }

    
    frame->type = PJMEDIA_FRAME_TYPE_AUDIO;
    frame->timestamp.u64 = 0;

    if ((fport->readpos + frame_size) <= (fport->buf + fport->bufsize))
    {
	
	pj_memcpy(frame->buf, fport->readpos, frame_size);

	
	fport->readpos += frame_size;
	if (fport->readpos == fport->buf + fport->bufsize) {
	    fport->readpos = fport->buf;

	    status = fill_buffer(fport);
	    if (status != PJ_SUCCESS) {
		frame->type = PJMEDIA_FRAME_TYPE_NONE;
		frame->size = 0;
		fport->readpos = fport->buf + fport->bufsize;
		return status;
	    }
	}
    } else {
	unsigned endread;

	
	endread = (unsigned)((fport->buf+fport->bufsize) - fport->readpos);
	pj_memcpy(frame->buf, fport->readpos, endread);

	
	if (fport->eof && (fport->options & PJMEDIA_FILE_NO_LOOP)) {
	    fport->readpos += endread;

            if (fport->fmt_tag == PJMEDIA_WAVE_FMT_TAG_PCM) {
                pj_bzero((char*)frame->buf + endread, frame_size - endread);
            } else if (fport->fmt_tag == PJMEDIA_WAVE_FMT_TAG_ULAW) {
                int val = pjmedia_linear2ulaw(0);
                pj_memset((char*)frame->buf + endread, val, frame_size - endread);
            } else if (fport->fmt_tag == PJMEDIA_WAVE_FMT_TAG_ALAW) {
                int val = pjmedia_linear2alaw(0);
                pj_memset((char*)frame->buf + endread, val, frame_size - endread);
            }

	    return PJ_SUCCESS;
	}

	
	status = fill_buffer(fport);
	if (status != PJ_SUCCESS) {
	    frame->type = PJMEDIA_FRAME_TYPE_NONE;
	    frame->size = 0;
	    fport->readpos = fport->buf + fport->bufsize;
	    return status;
	}

	pj_memcpy(((char*)frame->buf)+endread, fport->buf, frame_size-endread);
	fport->readpos = fport->buf + (frame_size - endread);
    }

    if (fport->fmt_tag == PJMEDIA_WAVE_FMT_TAG_ULAW || fport->fmt_tag == PJMEDIA_WAVE_FMT_TAG_ALAW)
    {
	unsigned i;
	pj_uint16_t *dst;
	pj_uint8_t *src;

	dst = (pj_uint16_t*)frame->buf + frame_size - 1;
	src = (pj_uint8_t*)frame->buf + frame_size - 1;

	if (fport->fmt_tag == PJMEDIA_WAVE_FMT_TAG_ULAW) {
	    for (i = 0; i < frame_size; ++i) {
		*dst-- = (pj_uint16_t) pjmedia_ulaw2linear(*src--);
	    }
	} else {
	    for (i = 0; i < frame_size; ++i) {
		*dst-- = (pj_uint16_t) pjmedia_alaw2linear(*src--);
	    }
	}
    }

    return PJ_SUCCESS;
}


static pj_status_t file_on_destroy(pjmedia_port *this_port)
{
    struct file_reader_port *fport = (struct file_reader_port*) this_port;

    pj_assert(this_port->info.signature == SIGNATURE);

    pj_file_close(fport->fd);

    if (fport->subscribed) {
    	pjmedia_event_unsubscribe(NULL, &file_on_event, fport, fport);
    	fport->subscribed = PJ_FALSE;
    }

    return PJ_SUCCESS;
}

