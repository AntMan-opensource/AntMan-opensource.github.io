
























    static void samples_to_host(pj_int16_t *samples, unsigned count)
    {
	unsigned i;
	for (i=0; i<count; ++i) {
	    samples[i] = pj_swap16(samples[i]);
	}
    }





struct playlist_port {
    pjmedia_port     base;
    unsigned	     options;
    pj_bool_t	     eof;
    pj_uint32_t	     bufsize;
    char	    *buf;
    char	    *readpos;

    pj_off_t        *fsize_list;
    unsigned        *start_data_list;
    unsigned        *data_len_list;
    unsigned        *data_left_list;
    pj_off_t        *fpos_list;
    pj_oshandle_t   *fd_list;	    
    int              current_file;  
    int              max_file;	    

    pj_status_t	   (*cb)(pjmedia_port*, void*);
    pj_bool_t	     subscribed;
    void	   (*cb2)(pjmedia_port*, void*);
};


static pj_status_t file_list_get_frame(pjmedia_port *this_port, pjmedia_frame *frame);
static pj_status_t file_list_on_destroy(pjmedia_port *this_port);


static struct playlist_port *create_file_list_port(pj_pool_t *pool, const pj_str_t *name)
{
    struct playlist_port *port;

    port = PJ_POOL_ZALLOC_T(pool, struct playlist_port);
    if (!port)
	return NULL;

    
    pjmedia_port_info_init(&port->base.info, name, SIGNATURE, 8000, 1, 16, 80);

    port->base.get_frame = &file_list_get_frame;
    port->base.on_destroy = &file_list_on_destroy;

    return port;
}


static pj_status_t file_on_event(pjmedia_event *event, void *user_data)
{
    struct playlist_port *fport = (struct playlist_port*)user_data;

    if (event->type == PJMEDIA_EVENT_CALLBACK) {
	if (fport->cb2)
	    (*fport->cb2)(&fport->base, fport->base.port_data.pdata);
    }
    
    return PJ_SUCCESS;
}



static pj_status_t file_fill_buffer(struct playlist_port *fport)
{
    pj_uint32_t size_left = fport->bufsize;
    pj_uint32_t size_to_read;
    pj_ssize_t size;
    pj_status_t status;
    int current_file = fport->current_file;

    
    if (fport->eof)
	return PJ_EEOF;

    while (size_left > 0)
    {
	
	size = size_to_read = size_left;
	status = pj_file_read(fport->fd_list[current_file], &fport->buf[fport->bufsize-size_left], &size);

	if (status != PJ_SUCCESS)
	    return status;
	
	if (size < 0)
	{
	    
	    return PJ_ECANCELLED;
	}

        if (size > (pj_ssize_t)fport->data_left_list[current_file]) {
            
            size = (pj_ssize_t)fport->data_left_list[current_file];
        }
	
	size_left -= (pj_uint32_t)size;
	fport->data_left_list[current_file] -= (pj_uint32_t)size;
	fport->fpos_list[current_file] += size;	
	
	
	if (size < (pj_ssize_t)size_to_read)
	{
	    
	    fport->fpos_list[current_file] =  fport->start_data_list[current_file];
	    pj_file_setpos(fport->fd_list[current_file],  fport->fpos_list[current_file], PJ_SEEK_SET);
	    fport->data_left_list[current_file] =  fport->data_len_list[current_file];

	    
	    current_file++;
	    fport->current_file = current_file;

	    if (fport->current_file == fport->max_file)
	    {
		
		if (size_left > 0) {
		    pj_bzero(&fport->buf[fport->bufsize-size_left],  size_left);
		}

		
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
		    	    
		    	    fport->current_file = current_file = 0;
		    	    fport->fpos_list[0] = fport->start_data_list[0];
		    	    pj_file_setpos(fport->fd_list[0], fport->fpos_list[0], PJ_SEEK_SET);
		    	    fport->data_left_list[0] = fport->data_len_list[0];
	    		}

	    	    	pjmedia_event_init(&event, PJMEDIA_EVENT_CALLBACK, NULL, fport);
	    	    	pjmedia_event_publish(NULL, fport, &event, PJMEDIA_EVENT_PUBLISH_POST_EVENT);
	            }

	    	    
	    	    return (no_loop? PJ_EEOF: PJ_SUCCESS);

	    	} else if (fport->cb) {
		    PJ_LOG(5,(THIS_FILE, "File port %.*s EOF, calling callback", (int)fport->base.info.name.slen, fport->base.info.name.ptr));


		    
		    fport->eof = PJ_TRUE;

		    status = (*fport->cb)(&fport->base, fport->base.port_data.pdata);

		    if (status != PJ_SUCCESS)
		    {
			
			return status;
		    }

		    fport->eof = PJ_FALSE;
		}


		if (fport->options & PJMEDIA_FILE_NO_LOOP)
		{
		    PJ_LOG(5,(THIS_FILE, "File port %.*s EOF, stopping..", (int)fport->base.info.name.slen, fport->base.info.name.ptr));

		    fport->eof = PJ_TRUE;
		    return PJ_EEOF;
		}
		else {
		    PJ_LOG(5,(THIS_FILE, "File port %.*s EOF, rewinding..", (int)fport->base.info.name.slen, fport->base.info.name.ptr));

		    
		    
		    fport->current_file = current_file = 0;
		    fport->fpos_list[0] = fport->start_data_list[0];
		    pj_file_setpos(fport->fd_list[0], fport->fpos_list[0], PJ_SEEK_SET);
		    fport->data_left_list[0] = fport->data_len_list[0];
		}		
		
	    } 

	} 

    } 
    
    
    samples_to_host((pj_int16_t*)fport->buf, fport->bufsize/BYTES_PER_SAMPLE);
    
    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjmedia_wav_playlist_create(pj_pool_t *pool, const pj_str_t *port_label, const pj_str_t file_list[], int file_count, unsigned ptime, unsigned options, pj_ssize_t buff_size, pjmedia_port **p_port)






{
    struct playlist_port *fport;
    pjmedia_audio_format_detail *afd;
    pj_off_t pos;
    pj_status_t status;
    int index;
    pj_bool_t has_wave_info = PJ_FALSE;
    pj_str_t tmp_port_label;
    char filename[PJ_MAXPATH];	


    
    PJ_ASSERT_RETURN(pool && file_list && file_count && p_port, PJ_EINVAL);

    
    if (port_label == NULL || port_label->slen == 0) {
	tmp_port_label = pj_str("WAV playlist");
	port_label = &tmp_port_label;
    }

    
    for (index=0; index<file_count; index++) {

	PJ_ASSERT_RETURN(file_list[index].slen >= 0, PJ_ETOOSMALL);
	if (file_list[index].slen >= PJ_MAXPATH)
	    return PJ_ENAMETOOLONG;

	pj_memcpy(filename, file_list[index].ptr, file_list[index].slen);
	filename[file_list[index].slen] = '\0';

    	
    	if (!pj_file_exists(filename)) {
	    PJ_LOG(4,(THIS_FILE, "WAV playlist error: file '%s' not found", filename));

	    return PJ_ENOTFOUND;
    	}
    }

    
    if (ptime == 0)
	ptime = 20;

    
    fport = create_file_list_port(pool, port_label);
    if (!fport) {
	return PJ_ENOMEM;
    }

    afd = pjmedia_format_get_audio_format_detail(&fport->base.info.fmt, 1);

    
    fport->current_file = 0;
    fport->max_file = file_count;

    
    fport->fd_list = (pj_oshandle_t*)
		     pj_pool_zalloc(pool, sizeof(pj_oshandle_t)*file_count);
    if (!fport->fd_list) {
	return PJ_ENOMEM;
    }

    
    fport->fsize_list = (pj_off_t*)
			pj_pool_alloc(pool, sizeof(pj_off_t)*file_count);
    if (!fport->fsize_list) {
	return PJ_ENOMEM;
    }

    
    fport->start_data_list = (unsigned*)
			     pj_pool_alloc(pool, sizeof(unsigned)*file_count);
    if (!fport->start_data_list) {
	return PJ_ENOMEM;
    }

    
    fport->data_len_list = (unsigned*)
			     pj_pool_alloc(pool, sizeof(unsigned)*file_count);
    if (!fport->data_len_list) {
	return PJ_ENOMEM;
    }

    
    fport->data_left_list = (unsigned*)
			     pj_pool_alloc(pool, sizeof(unsigned)*file_count);
    if (!fport->data_left_list) {
	return PJ_ENOMEM;
    }

    
    fport->fpos_list = (pj_off_t*)
		       pj_pool_alloc(pool, sizeof(pj_off_t)*file_count);
    if (!fport->fpos_list) {
	return PJ_ENOMEM;
    }

    
    if (buff_size < 1) buff_size = PJMEDIA_FILE_PORT_BUFSIZE;
    fport->bufsize = (pj_uint32_t)buff_size;


    
    fport->buf = (char*) pj_pool_alloc(pool, fport->bufsize);
    if (!fport->buf) {
	return PJ_ENOMEM;
    }

    
    fport->options = options;
    fport->readpos = fport->buf;


    
    for (index=file_count-1; index>=0; index--) {

	pjmedia_wave_hdr wavehdr;
	pj_ssize_t size_to_read, size_read;

	
	pj_memcpy(filename, file_list[index].ptr, file_list[index].slen);
	filename[file_list[index].slen] = '\0';

	
	fport->current_file = index;
	fport->fsize_list[index] = pj_file_size(filename);
	
	
	if (fport->fsize_list[index] <= sizeof(pjmedia_wave_hdr)) {
	    status = PJMEDIA_ENOTVALIDWAVE;
	    goto on_error;
	}
	
	
	status = pj_file_open( pool, filename, PJ_O_RDONLY,  &fport->fd_list[index]);
	if (status != PJ_SUCCESS)
	    goto on_error;
	
	
	size_read = size_to_read = sizeof(wavehdr) - 8;
	status = pj_file_read( fport->fd_list[index], &wavehdr, &size_read);
	if (status != PJ_SUCCESS) {
	    goto on_error;
	}

	if (size_read != size_to_read) {
	    status = PJMEDIA_ENOTVALIDWAVE;
	    goto on_error;
	}
	
	
	pjmedia_wave_hdr_file_to_host(&wavehdr);
	
	
	if (wavehdr.riff_hdr.riff != PJMEDIA_RIFF_TAG || wavehdr.riff_hdr.wave != PJMEDIA_WAVE_TAG || wavehdr.fmt_hdr.fmt != PJMEDIA_FMT_TAG)

	{
	    TRACE_((THIS_FILE, "actual value|expected riff=%x|%x, wave=%x|%x fmt=%x|%x", wavehdr.riff_hdr.riff, PJMEDIA_RIFF_TAG, wavehdr.riff_hdr.wave, PJMEDIA_WAVE_TAG, wavehdr.fmt_hdr.fmt, PJMEDIA_FMT_TAG));



	    status = PJMEDIA_ENOTVALIDWAVE;
	    goto on_error;
	}
	
	
	if (wavehdr.fmt_hdr.fmt_tag != 1 || wavehdr.fmt_hdr.bits_per_sample != 16)
	{
	    status = PJMEDIA_EWAVEUNSUPP;
	    goto on_error;
	}
	
	
	if (wavehdr.fmt_hdr.block_align !=  wavehdr.fmt_hdr.nchan * BYTES_PER_SAMPLE)
	{
	    status = PJMEDIA_EWAVEUNSUPP;
	    goto on_error;
	}
	
	
	if (wavehdr.fmt_hdr.len > 16) {
	    size_to_read = wavehdr.fmt_hdr.len - 16;
	    status = pj_file_setpos(fport->fd_list[index], size_to_read,  PJ_SEEK_CUR);
	    if (status != PJ_SUCCESS) {
		goto on_error;
	    }
	}
	
	
	for (;;) {
	    pjmedia_wave_subchunk subchunk;
	    size_read = 8;
	    status = pj_file_read(fport->fd_list[index], &subchunk,  &size_read);
	    if (status != PJ_SUCCESS || size_read != 8) {
		status = PJMEDIA_EWAVETOOSHORT;
		goto on_error;
	    }
	    
	    
	    PJMEDIA_WAVE_NORMALIZE_SUBCHUNK(&subchunk);
	    
	    
	    if (subchunk.id == PJMEDIA_DATA_TAG) {
		wavehdr.data_hdr.data = PJMEDIA_DATA_TAG;
		wavehdr.data_hdr.len = subchunk.len;
		break;
	    }
	    
	    
	    size_to_read = subchunk.len;
	    status = pj_file_setpos(fport->fd_list[index], size_to_read,  PJ_SEEK_CUR);
	    if (status != PJ_SUCCESS) {
		goto on_error;
	    }
	}
	
	
	status = pj_file_getpos(fport->fd_list[index], &pos);
	fport->start_data_list[index] = (unsigned)pos;
	fport->data_len_list[index] = wavehdr.data_hdr.len;
	fport->data_left_list[index] = wavehdr.data_hdr.len;
	
	
	if (wavehdr.data_hdr.len > fport->fsize_list[index] -  fport->start_data_list[index])
	{
	    status = PJMEDIA_EWAVEUNSUPP;
	    goto on_error;
	}
	if (wavehdr.data_hdr.len < ptime * wavehdr.fmt_hdr.sample_rate * wavehdr.fmt_hdr.nchan / 1000)
	{
	    status = PJMEDIA_EWAVETOOSHORT;
	    goto on_error;
	}
	
	
	
	
	if (!has_wave_info) {
	    afd->channel_count = wavehdr.fmt_hdr.nchan;
	    afd->clock_rate = wavehdr.fmt_hdr.sample_rate;
	    afd->bits_per_sample = wavehdr.fmt_hdr.bits_per_sample;
	    afd->frame_time_usec = ptime * 1000;
	    afd->avg_bps = afd->max_bps = afd->clock_rate * afd->channel_count * afd->bits_per_sample;


	    has_wave_info = PJ_TRUE;

	} else {

	    
	    if (wavehdr.fmt_hdr.nchan != afd->channel_count || wavehdr.fmt_hdr.sample_rate != afd->clock_rate || wavehdr.fmt_hdr.bits_per_sample != afd->bits_per_sample)

	    {
		
		PJ_LOG(4,(THIS_FILE, "WAV playlist error: file '%s' has differrent number" " of channels, sample rate, or bits per sample", filename));


		status = PJMEDIA_EWAVEUNSUPP;
		goto on_error;
	    }

	}

	
	if (wavehdr.data_hdr.len < (unsigned)buff_size)
	    buff_size = wavehdr.data_hdr.len;

	
	fport->bufsize = (pj_uint32_t)buff_size;	
	
	
	fport->fpos_list[index] = fport->start_data_list[index];
    }

    
    status = file_fill_buffer(fport);
    if (status != PJ_SUCCESS) {
	goto on_error;
    }
    
    
    
    *p_port = &fport->base;
    
    PJ_LOG(4,(THIS_FILE, "WAV playlist '%.*s' created: samp.rate=%d, ch=%d, bufsize=%uKB", (int)port_label->slen, port_label->ptr, afd->clock_rate, afd->channel_count, fport->bufsize / 1000));





    
    return PJ_SUCCESS;

on_error:
    for (index=0; index<file_count; ++index) {
	if (fport->fd_list[index] != 0)
	    pj_file_close(fport->fd_list[index]);
    }

    return status;
}




PJ_DEF(pj_status_t) pjmedia_wav_playlist_set_eof_cb(pjmedia_port *port, void *user_data, pj_status_t (*cb)(pjmedia_port *port, void *usr_data))


{
    struct playlist_port *fport;

    
    PJ_ASSERT_RETURN(port, PJ_EINVAL);

    
    PJ_ASSERT_RETURN(port->info.signature == SIGNATURE, PJ_EINVALIDOP);

    PJ_LOG(1, (THIS_FILE, "pjmedia_wav_playlist_set_eof_cb() is deprecated. " "Use pjmedia_wav_playlist_set_eof_cb2() instead."));

    fport = (struct playlist_port*) port;

    fport->base.port_data.pdata = user_data;
    fport->cb = cb;

    return PJ_SUCCESS;
}




PJ_DEF(pj_status_t) pjmedia_wav_playlist_set_eof_cb2(pjmedia_port *port, void *user_data, void (*cb)(pjmedia_port *port, void *usr_data))


{
    struct playlist_port *fport;

    
    PJ_ASSERT_RETURN(port, PJ_EINVAL);

    
    PJ_ASSERT_RETURN(port->info.signature == SIGNATURE, PJ_EINVALIDOP);

    fport = (struct playlist_port*) port;

    fport->base.port_data.pdata = user_data;
    fport->cb2 = cb;

    return PJ_SUCCESS;
}



static pj_status_t file_list_get_frame(pjmedia_port *this_port, pjmedia_frame *frame)
{
    struct playlist_port *fport = (struct playlist_port*)this_port;
    pj_size_t frame_size;
    pj_status_t status;

    pj_assert(fport->base.info.signature == SIGNATURE);

    
    
    frame_size = frame->size;

    
    frame->type = PJMEDIA_FRAME_TYPE_AUDIO;
    frame->size = frame_size;
    frame->timestamp.u64 = 0;

    if (fport->readpos + frame_size <= fport->buf + fport->bufsize) {

	
	pj_memcpy(frame->buf, fport->readpos, frame_size);

	
	fport->readpos += frame_size;
	if (fport->readpos == fport->buf + fport->bufsize) {
	    fport->readpos = fport->buf;

	    status = file_fill_buffer(fport);
	    if (status != PJ_SUCCESS) {
		frame->type = PJMEDIA_FRAME_TYPE_NONE;
		frame->size = 0;
		return status;
	    }
	}
    } else {
	unsigned endread;

	
	endread = (unsigned)((fport->buf+fport->bufsize) - fport->readpos);
	pj_memcpy(frame->buf, fport->readpos, endread);

	
	status = file_fill_buffer(fport);
	if (status != PJ_SUCCESS) {
	    pj_bzero(((char*)frame->buf)+endread, frame_size-endread);
	    return status;
	}

	pj_memcpy(((char*)frame->buf)+endread, fport->buf, frame_size-endread);
	fport->readpos = fport->buf + (frame_size - endread);
    }

    return PJ_SUCCESS;
}



static pj_status_t file_list_on_destroy(pjmedia_port *this_port)
{
    struct playlist_port *fport = (struct playlist_port*) this_port;
    int index;

    pj_assert(this_port->info.signature == SIGNATURE);

    if (fport->subscribed) {
    	pjmedia_event_unsubscribe(NULL, &file_on_event, fport, fport);
    	fport->subscribed = PJ_FALSE;
    }

    for (index=0; index<fport->max_file; index++)
	pj_file_close(fport->fd_list[index]);

    return PJ_SUCCESS;
}

