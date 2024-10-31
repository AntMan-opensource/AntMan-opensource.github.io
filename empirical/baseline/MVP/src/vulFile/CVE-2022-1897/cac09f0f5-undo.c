
















typedef struct {
    buf_T	*bi_buf;
    FILE	*bi_fp;

    cryptstate_T *bi_state;
    char_u	*bi_buffer; 
    size_t	bi_used;    
    size_t	bi_avail;   

} bufinfo_T;


static void u_unch_branch(u_header_T *uhp);
static u_entry_T *u_get_headentry(void);
static void u_getbot(void);
static void u_doit(int count);
static void u_undoredo(int undo);
static void u_undo_end(int did_undo, int absolute);
static void u_freeheader(buf_T *buf, u_header_T *uhp, u_header_T **uhpp);
static void u_freebranch(buf_T *buf, u_header_T *uhp, u_header_T **uhpp);
static void u_freeentries(buf_T *buf, u_header_T *uhp, u_header_T **uhpp);
static void u_freeentry(u_entry_T *, long);


static int undo_flush(bufinfo_T *bi);

static int undo_read(bufinfo_T *bi, char_u *buffer, size_t size);
static int serialize_uep(bufinfo_T *bi, u_entry_T *uep);
static u_entry_T *unserialize_uep(bufinfo_T *bi, int *error, char_u *file_name);
static void serialize_pos(bufinfo_T *bi, pos_T pos);
static void unserialize_pos(bufinfo_T *bi, pos_T *pos);
static void serialize_visualinfo(bufinfo_T *bi, visualinfo_T *info);
static void unserialize_visualinfo(bufinfo_T *bi, visualinfo_T *info);

static void u_saveline(linenr_T lnum);




static long	u_newcount, u_oldcount;


static int	undo_undoes = FALSE;

static int	lastmark = 0;



static int seen_b_u_curhead;
static int seen_b_u_newhead;
static int header_count;

    static void u_check_tree(u_header_T *uhp, u_header_T *exp_uh_next, u_header_T *exp_uh_alt_prev)


{
    u_entry_T *uep;

    if (uhp == NULL)
	return;
    ++header_count;
    if (uhp == curbuf->b_u_curhead && ++seen_b_u_curhead > 1)
    {
	emsg("b_u_curhead found twice (looping?)");
	return;
    }
    if (uhp == curbuf->b_u_newhead && ++seen_b_u_newhead > 1)
    {
	emsg("b_u_newhead found twice (looping?)");
	return;
    }

    if (uhp->uh_magic != UH_MAGIC)
	emsg("uh_magic wrong (may be using freed memory)");
    else {
	
	if (uhp->uh_next.ptr != exp_uh_next)
	{
	    emsg("uh_next wrong");
	    smsg("expected: 0x%x, actual: 0x%x", exp_uh_next, uhp->uh_next.ptr);
	}
	if (uhp->uh_alt_prev.ptr != exp_uh_alt_prev)
	{
	    emsg("uh_alt_prev wrong");
	    smsg("expected: 0x%x, actual: 0x%x", exp_uh_alt_prev, uhp->uh_alt_prev.ptr);
	}

	
	for (uep = uhp->uh_entry; uep != NULL; uep = uep->ue_next)
	{
	    if (uep->ue_magic != UE_MAGIC)
	    {
		emsg("ue_magic wrong (may be using freed memory)");
		break;
	    }
	}

	
	u_check_tree(uhp->uh_alt_next.ptr, uhp->uh_next.ptr, uhp);

	
	u_check_tree(uhp->uh_prev.ptr, uhp, NULL);
    }
}

    static void u_check(int newhead_may_be_NULL)
{
    seen_b_u_newhead = 0;
    seen_b_u_curhead = 0;
    header_count = 0;

    u_check_tree(curbuf->b_u_oldhead, NULL, NULL);

    if (seen_b_u_newhead == 0 && curbuf->b_u_oldhead != NULL && !(newhead_may_be_NULL && curbuf->b_u_newhead == NULL))
	semsg("b_u_newhead invalid: 0x%x", curbuf->b_u_newhead);
    if (curbuf->b_u_curhead != NULL && seen_b_u_curhead == 0)
	semsg("b_u_curhead invalid: 0x%x", curbuf->b_u_curhead);
    if (header_count != curbuf->b_u_numhead)
    {
	emsg("b_u_numhead invalid");
	smsg("expected: %ld, actual: %ld", (long)header_count, (long)curbuf->b_u_numhead);
    }
}



    int u_save_cursor(void)
{
    return (u_save((linenr_T)(curwin->w_cursor.lnum - 1), (linenr_T)(curwin->w_cursor.lnum + 1)));
}


    int u_save(linenr_T top, linenr_T bot)
{
    if (undo_off)
	return OK;

    if (top >= bot || bot > curbuf->b_ml.ml_line_count + 1)
	return FAIL;	

    if (top + 2 == bot)
	u_saveline((linenr_T)(top + 1));

    return (u_savecommon(top, bot, (linenr_T)0, FALSE));
}


    int u_savesub(linenr_T lnum)
{
    if (undo_off)
	return OK;

    return (u_savecommon(lnum - 1, lnum + 1, lnum + 1, FALSE));
}


    int u_inssub(linenr_T lnum)
{
    if (undo_off)
	return OK;

    return (u_savecommon(lnum - 1, lnum, lnum + 1, FALSE));
}


    int u_savedel(linenr_T lnum, long nlines)
{
    if (undo_off)
	return OK;

    return (u_savecommon(lnum - 1, lnum + nlines, nlines == curbuf->b_ml.ml_line_count ? 2 : lnum, FALSE));
}


    int undo_allowed(void)
{
    
    if (!curbuf->b_p_ma)
    {
	emsg(_(e_cannot_make_changes_modifiable_is_off));
	return FALSE;
    }


    
    if (sandbox != 0)
    {
	emsg(_(e_not_allowed_in_sandbox));
	return FALSE;
    }


    
    
    if (textwinlock != 0 || textlock != 0)
    {
	emsg(_(e_not_allowed_to_change_text_here));
	return FALSE;
    }

    return TRUE;
}


    static long get_undolevel(void)
{
    if (curbuf->b_p_ul == NO_LOCAL_UNDOLEVEL)
	return p_ul;
    return curbuf->b_p_ul;
}


    static int u_save_line(undoline_T *ul, linenr_T lnum)
{
    char_u *line = ml_get(lnum);

    if (curbuf->b_ml.ml_line_len == 0)
    {
	ul->ul_len = 1;
	ul->ul_line = vim_strsave((char_u *)"");
    }
    else {
	
	
	ul->ul_len = curbuf->b_ml.ml_line_len;
	ul->ul_line = vim_memsave(line, ul->ul_len);
    }
    return ul->ul_line == NULL ? FAIL : OK;
}



    static int has_prop_w_flags(linenr_T lnum, int flags)
{
    char_u  *props;
    int	    i;
    int	    proplen = get_text_props(curbuf, lnum, &props, FALSE);

    for (i = 0; i < proplen; ++i)
    {
	textprop_T prop;

	mch_memmove(&prop, props + i * sizeof prop, sizeof prop);
	if (prop.tp_flags & flags)
	    return TRUE;
    }
    return FALSE;
}



    int u_savecommon( linenr_T	top, linenr_T	bot, linenr_T	newbot, int		reload)




{
    linenr_T	lnum;
    long	i;
    u_header_T	*uhp;
    u_header_T	*old_curhead;
    u_entry_T	*uep;
    u_entry_T	*prev_uep;
    long	size;

    if (!reload)
    {
	
	
	if (!undo_allowed())
	    return FAIL;


	
	if (netbeans_active())
	{
	    if (netbeans_is_guarded(top, bot))
	    {
		emsg(_(e_region_is_guarded_cannot_modify));
		return FAIL;
	    }
	    if (curbuf->b_p_ro)
	    {
		emsg(_(e_netbeans_does_not_allow_changes_in_read_only_files));
		return FAIL;
	    }
	}


	
	term_change_in_curbuf();


	
	change_warning(0);
	if (bot > curbuf->b_ml.ml_line_count + 1)
	{
	    
	    
	    emsg(_(e_line_count_changed_unexpectedly));
	    return FAIL;
	}
    }


    u_check(FALSE);



    
    
    if (bot - top > 1)
    {
	if (top > 0 && has_prop_w_flags(top + 1, TP_FLAG_CONT_PREV))
	    --top;
	if (bot <= curbuf->b_ml.ml_line_count && has_prop_w_flags(bot - 1, TP_FLAG_CONT_NEXT))
	{
	    ++bot;
	    if (newbot != 0)
		++newbot;
	}
    }


    size = bot - top - 1;

    
    if (curbuf->b_u_synced)
    {
	
	curbuf->b_new_change = TRUE;

	if (get_undolevel() >= 0)
	{
	    
	    uhp = U_ALLOC_LINE(sizeof(u_header_T));
	    if (uhp == NULL)
		goto nomem;

	    uhp->uh_magic = UH_MAGIC;

	}
	else uhp = NULL;

	
	old_curhead = curbuf->b_u_curhead;
	if (old_curhead != NULL)
	{
	    curbuf->b_u_newhead = old_curhead->uh_next.ptr;
	    curbuf->b_u_curhead = NULL;
	}

	
	while (curbuf->b_u_numhead > get_undolevel()
					       && curbuf->b_u_oldhead != NULL)
	{
	    u_header_T	    *uhfree = curbuf->b_u_oldhead;

	    if (uhfree == old_curhead)
		
		u_freebranch(curbuf, uhfree, &old_curhead);
	    else if (uhfree->uh_alt_next.ptr == NULL)
		
		u_freeheader(curbuf, uhfree, &old_curhead);
	    else {
		
		while (uhfree->uh_alt_next.ptr != NULL)
		    uhfree = uhfree->uh_alt_next.ptr;
		u_freebranch(curbuf, uhfree, &old_curhead);
	    }

	    u_check(TRUE);

	}

	if (uhp == NULL)		
	{
	    if (old_curhead != NULL)
		u_freebranch(curbuf, old_curhead, NULL);
	    curbuf->b_u_synced = FALSE;
	    return OK;
	}

	uhp->uh_prev.ptr = NULL;
	uhp->uh_next.ptr = curbuf->b_u_newhead;
	uhp->uh_alt_next.ptr = old_curhead;
	if (old_curhead != NULL)
	{
	    uhp->uh_alt_prev.ptr = old_curhead->uh_alt_prev.ptr;
	    if (uhp->uh_alt_prev.ptr != NULL)
		uhp->uh_alt_prev.ptr->uh_alt_next.ptr = uhp;
	    old_curhead->uh_alt_prev.ptr = uhp;
	    if (curbuf->b_u_oldhead == old_curhead)
		curbuf->b_u_oldhead = uhp;
	}
	else uhp->uh_alt_prev.ptr = NULL;
	if (curbuf->b_u_newhead != NULL)
	    curbuf->b_u_newhead->uh_prev.ptr = uhp;

	uhp->uh_seq = ++curbuf->b_u_seq_last;
	curbuf->b_u_seq_cur = uhp->uh_seq;
	uhp->uh_time = vim_time();
	uhp->uh_save_nr = 0;
	curbuf->b_u_time_cur = uhp->uh_time + 1;

	uhp->uh_walk = 0;
	uhp->uh_entry = NULL;
	uhp->uh_getbot_entry = NULL;
	uhp->uh_cursor = curwin->w_cursor;	
	if (virtual_active() && curwin->w_cursor.coladd > 0)
	    uhp->uh_cursor_vcol = getviscol();
	else uhp->uh_cursor_vcol = -1;

	
	uhp->uh_flags = (curbuf->b_changed ? UH_CHANGED : 0) + ((curbuf->b_ml.ml_flags & ML_EMPTY) ? UH_EMPTYBUF : 0);

	
	mch_memmove(uhp->uh_namedm, curbuf->b_namedm, sizeof(pos_T) * NMARKS);
	uhp->uh_visual = curbuf->b_visual;

	curbuf->b_u_newhead = uhp;
	if (curbuf->b_u_oldhead == NULL)
	    curbuf->b_u_oldhead = uhp;
	++curbuf->b_u_numhead;
    }
    else {
	if (get_undolevel() < 0)	
	    return OK;

	
	if (size == 1)
	{
	    uep = u_get_headentry();
	    prev_uep = NULL;
	    for (i = 0; i < 10; ++i)
	    {
		if (uep == NULL)
		    break;

		
		
		if ((curbuf->b_u_newhead->uh_getbot_entry != uep ? (uep->ue_top + uep->ue_size + 1 != (uep->ue_bot == 0 ? curbuf->b_ml.ml_line_count + 1 : uep->ue_bot))



			    : uep->ue_lcount != curbuf->b_ml.ml_line_count)
			|| (uep->ue_size > 1 && top >= uep->ue_top && top + 2 <= uep->ue_top + uep->ue_size + 1))

		    break;

		
		if (uep->ue_size == 1 && uep->ue_top == top)
		{
		    if (i > 0)
		    {
			
			
			
			u_getbot();
			curbuf->b_u_synced = FALSE;

			
			
			
			
			
			
			prev_uep->ue_next = uep->ue_next;
			uep->ue_next = curbuf->b_u_newhead->uh_entry;
			curbuf->b_u_newhead->uh_entry = uep;
		    }

		    
		    if (newbot != 0)
			uep->ue_bot = newbot;
		    else if (bot > curbuf->b_ml.ml_line_count)
			uep->ue_bot = 0;
		    else {
			uep->ue_lcount = curbuf->b_ml.ml_line_count;
			curbuf->b_u_newhead->uh_getbot_entry = uep;
		    }
		    return OK;
		}
		prev_uep = uep;
		uep = uep->ue_next;
	    }
	}

	
	u_getbot();
    }


	
    if (size >= 8000)
	goto nomem;


    
    uep = U_ALLOC_LINE(sizeof(u_entry_T));
    if (uep == NULL)
	goto nomem;
    CLEAR_POINTER(uep);

    uep->ue_magic = UE_MAGIC;


    uep->ue_size = size;
    uep->ue_top = top;
    if (newbot != 0)
	uep->ue_bot = newbot;
    
    else if (bot > curbuf->b_ml.ml_line_count)
	uep->ue_bot = 0;
    else {
	uep->ue_lcount = curbuf->b_ml.ml_line_count;
	curbuf->b_u_newhead->uh_getbot_entry = uep;
    }

    if (size > 0)
    {
	if ((uep->ue_array = U_ALLOC_LINE(sizeof(undoline_T) * size)) == NULL)
	{
	    u_freeentry(uep, 0L);
	    goto nomem;
	}
	for (i = 0, lnum = top + 1; i < size; ++i)
	{
	    fast_breakcheck();
	    if (got_int)
	    {
		u_freeentry(uep, i);
		return FAIL;
	    }
	    if (u_save_line(&uep->ue_array[i], lnum++) == FAIL)
	    {
		u_freeentry(uep, i);
		goto nomem;
	    }
	}
    }
    else uep->ue_array = NULL;
    uep->ue_next = curbuf->b_u_newhead->uh_entry;
    curbuf->b_u_newhead->uh_entry = uep;
    curbuf->b_u_synced = FALSE;
    undo_undoes = FALSE;


    u_check(FALSE);

    return OK;

nomem:
    msg_silent = 0;	
    if (ask_yesno((char_u *)_("No undo possible; continue anyway"), TRUE)
								       == 'y')
    {
	undo_off = TRUE;	    
	return OK;
    }
    do_outofmem_msg((long_u)0);
    return FAIL;
}



















    void u_compute_hash(char_u *hash)
{
    context_sha256_T	ctx;
    linenr_T		lnum;
    char_u		*p;

    sha256_start(&ctx);
    for (lnum = 1; lnum <= curbuf->b_ml.ml_line_count; ++lnum)
    {
	p = ml_get(lnum);
	sha256_update(&ctx, p, (UINT32_T)(STRLEN(p) + 1));
    }
    sha256_finish(&ctx, hash);
}


    static char_u * u_get_undo_file_name(char_u *buf_ffname, int reading)
{
    char_u	*dirp;
    char_u	dir_name[IOSIZE + 1];
    char_u	*munged_name = NULL;
    char_u	*undo_file_name = NULL;
    int		dir_len;
    char_u	*p;
    stat_T	st;
    char_u	*ffname = buf_ffname;

    char_u	fname_buf[MAXPATHL];


    if (ffname == NULL)
	return NULL;


    
    
    if (resolve_symlink(ffname, fname_buf) == OK)
	ffname = fname_buf;


    
    
    dirp = p_udir;
    while (*dirp != NUL)
    {
	dir_len = copy_option_part(&dirp, dir_name, IOSIZE, ",");
	if (dir_len == 1 && dir_name[0] == '.')
	{
	    
	    
	    undo_file_name = vim_strnsave(ffname, STRLEN(ffname) + 5);
	    if (undo_file_name == NULL)
		break;
	    p = gettail(undo_file_name);

	    
	    
	    
	    mch_memmove(p + 4,  p, STRLEN(p) + 1);
	    mch_memmove(p, "_un_", 4);


	    
	    
	    mch_memmove(p + 1, p, STRLEN(p) + 1);
	    *p = '.';
	    STRCAT(p, ".un~");

	}
	else {
	    dir_name[dir_len] = NUL;
	    if (mch_isdir(dir_name))
	    {
		if (munged_name == NULL)
		{
		    munged_name = vim_strsave(ffname);
		    if (munged_name == NULL)
			return NULL;
		    for (p = munged_name; *p != NUL; MB_PTR_ADV(p))
			if (vim_ispathsep(*p))
			    *p = '%';
		}
		undo_file_name = concat_fnames(dir_name, munged_name, TRUE);
	    }
	}

	
	if (undo_file_name != NULL && (!reading || mch_stat((char *)undo_file_name, &st) >= 0))
	    break;
	VIM_CLEAR(undo_file_name);
    }

    vim_free(munged_name);
    return undo_file_name;
}

    static void corruption_error(char *mesg, char_u *file_name)
{
    semsg(_(e_corrupted_undo_file_str_str), mesg, file_name);
}

    static void u_free_uhp(u_header_T *uhp)
{
    u_entry_T	*nuep;
    u_entry_T	*uep;

    uep = uhp->uh_entry;
    while (uep != NULL)
    {
	nuep = uep->ue_next;
	u_freeentry(uep, uep->ue_size);
	uep = nuep;
    }
    vim_free(uhp);
}


    static int undo_write(bufinfo_T *bi, char_u *ptr, size_t len)
{

    if (bi->bi_buffer != NULL)
    {
	size_t	len_todo = len;
	char_u  *p = ptr;

	while (bi->bi_used + len_todo >= CRYPT_BUF_SIZE)
	{
	    size_t	n = CRYPT_BUF_SIZE - bi->bi_used;

	    mch_memmove(bi->bi_buffer + bi->bi_used, p, n);
	    len_todo -= n;
	    p += n;
	    bi->bi_used = CRYPT_BUF_SIZE;
	    if (undo_flush(bi) == FAIL)
		return FAIL;
	}
	if (len_todo > 0)
	{
	    mch_memmove(bi->bi_buffer + bi->bi_used, p, len_todo);
	    bi->bi_used += len_todo;
	}
	return OK;
    }

    if (fwrite(ptr, len, (size_t)1, bi->bi_fp) != 1)
	return FAIL;
    return OK;
}


    static int undo_flush(bufinfo_T *bi)
{
    if (bi->bi_buffer != NULL && bi->bi_state != NULL && bi->bi_used > 0)
    {
	
	
	crypt_encode_inplace(bi->bi_state, bi->bi_buffer, bi->bi_used, FALSE);
	if (fwrite(bi->bi_buffer, bi->bi_used, (size_t)1, bi->bi_fp) != 1)
	    return FAIL;
	bi->bi_used = 0;
    }
    return OK;
}



    static int fwrite_crypt(bufinfo_T *bi, char_u *ptr, size_t len)
{

    char_u  *copy;
    char_u  small_buf[100];
    size_t  i;

    if (bi->bi_state != NULL && bi->bi_buffer == NULL)
    {
	
	if (len < 100)
	    copy = small_buf;  
	else {
	    copy = lalloc(len, FALSE);
	    if (copy == NULL)
		return 0;
	}
	
	
	crypt_encode(bi->bi_state, ptr, len, copy, TRUE);
	i = fwrite(copy, len, (size_t)1, bi->bi_fp);
	if (copy != small_buf)
	    vim_free(copy);
	return i == 1 ? OK : FAIL;
    }

    return undo_write(bi, ptr, len);
}


    static int undo_write_bytes(bufinfo_T *bi, long_u nr, int len)
{
    char_u  buf[8];
    int	    i;
    int	    bufi = 0;

    for (i = len - 1; i >= 0; --i)
	buf[bufi++] = (char_u)(nr >> (i * 8));
    return undo_write(bi, buf, (size_t)len);
}


    static void put_header_ptr(bufinfo_T *bi, u_header_T *uhp)
{
    undo_write_bytes(bi, (long_u)(uhp != NULL ? uhp->uh_seq : 0), 4);
}

    static int undo_read_4c(bufinfo_T *bi)
{

    if (bi->bi_buffer != NULL)
    {
	char_u  buf[4];
	int	n;

	undo_read(bi, buf, (size_t)4);
	n = ((unsigned)buf[0] << 24) + (buf[1] << 16) + (buf[2] << 8) + buf[3];
	return n;
    }

    return get4c(bi->bi_fp);
}

    static int undo_read_2c(bufinfo_T *bi)
{

    if (bi->bi_buffer != NULL)
    {
	char_u  buf[2];
	int	n;

	undo_read(bi, buf, (size_t)2);
	n = (buf[0] << 8) + buf[1];
	return n;
    }

    return get2c(bi->bi_fp);
}

    static int undo_read_byte(bufinfo_T *bi)
{

    if (bi->bi_buffer != NULL)
    {
	char_u  buf[1];

	undo_read(bi, buf, (size_t)1);
	return buf[0];
    }

    return getc(bi->bi_fp);
}

    static time_t undo_read_time(bufinfo_T *bi)
{

    if (bi->bi_buffer != NULL)
    {
	char_u  buf[8];
	time_t	n = 0;
	int	i;

	undo_read(bi, buf, (size_t)8);
	for (i = 0; i < 8; ++i)
	    n = (n << 8) + buf[i];
	return n;
    }

    return get8ctime(bi->bi_fp);
}


    static int undo_read(bufinfo_T *bi, char_u *buffer, size_t size)
{
    int retval = OK;


    if (bi->bi_buffer != NULL)
    {
	int	size_todo = (int)size;
	char_u	*p = buffer;

	while (size_todo > 0)
	{
	    size_t n;

	    if (bi->bi_used >= bi->bi_avail)
	    {
		n = fread(bi->bi_buffer, 1, (size_t)CRYPT_BUF_SIZE, bi->bi_fp);
		if (n == 0)
		{
		    retval = FAIL;
		    break;
		}
		bi->bi_avail = n;
		bi->bi_used = 0;
		crypt_decode_inplace(bi->bi_state, bi->bi_buffer, bi->bi_avail, FALSE);
	    }
	    n = size_todo;
	    if (n > bi->bi_avail - bi->bi_used)
		n = bi->bi_avail - bi->bi_used;
	    mch_memmove(p, bi->bi_buffer + bi->bi_used, n);
	    bi->bi_used += n;
	    size_todo -= (int)n;
	    p += n;
	}
    }
    else  if (fread(buffer, size, 1, bi->bi_fp) != 1)

	retval = FAIL;

    if (retval == FAIL)
	
	
	vim_memset(buffer, 0, size);
    return retval;
}


    static char_u * read_string_decrypt(bufinfo_T *bi, int len)
{
    char_u  *ptr = alloc(len + 1);

    if (ptr != NULL)
    {
	if (len > 0 && undo_read(bi, ptr, len) == FAIL)
	{
	    vim_free(ptr);
	    return NULL;
	}
	
	
	ptr[len] = NUL;

	if (bi->bi_state != NULL && bi->bi_buffer == NULL)
	    crypt_decode_inplace(bi->bi_state, ptr, len, FALSE);

    }
    return ptr;
}


    static int serialize_header(bufinfo_T *bi, char_u *hash)
{
    long	len;
    buf_T	*buf = bi->bi_buf;
    FILE	*fp = bi->bi_fp;
    char_u	time_buf[8];

    
    if (fwrite(UF_START_MAGIC, (size_t)UF_START_MAGIC_LEN, (size_t)1, fp) != 1)
	return FAIL;

    
    

    if (*buf->b_p_key != NUL)
    {
	char_u *header;
	int    header_len;

	undo_write_bytes(bi, (long_u)UF_VERSION_CRYPT, 2);
	bi->bi_state = crypt_create_for_writing(crypt_get_method_nr(buf), buf->b_p_key, &header, &header_len);
	if (bi->bi_state == NULL)
	    return FAIL;
	len = (long)fwrite(header, (size_t)header_len, (size_t)1, fp);
	vim_free(header);
	if (len != 1)
	{
	    crypt_free_state(bi->bi_state);
	    bi->bi_state = NULL;
	    return FAIL;
	}

	if (crypt_whole_undofile(crypt_get_method_nr(buf)))
	{
	    bi->bi_buffer = alloc(CRYPT_BUF_SIZE);
	    if (bi->bi_buffer == NULL)
	    {
		crypt_free_state(bi->bi_state);
		bi->bi_state = NULL;
		return FAIL;
	    }
	    bi->bi_used = 0;
	}
    }
    else  undo_write_bytes(bi, (long_u)UF_VERSION, 2);



    
    
    if (undo_write(bi, hash, (size_t)UNDO_HASH_SIZE) == FAIL)
	return FAIL;

    
    undo_write_bytes(bi, (long_u)buf->b_ml.ml_line_count, 4);
    len = buf->b_u_line_ptr.ul_line == NULL ? 0L : (long)STRLEN(buf->b_u_line_ptr.ul_line);
    undo_write_bytes(bi, (long_u)len, 4);
    if (len > 0 && fwrite_crypt(bi, buf->b_u_line_ptr.ul_line, (size_t)len)
								       == FAIL)
	return FAIL;
    undo_write_bytes(bi, (long_u)buf->b_u_line_lnum, 4);
    undo_write_bytes(bi, (long_u)buf->b_u_line_colnr, 4);

    
    put_header_ptr(bi, buf->b_u_oldhead);
    put_header_ptr(bi, buf->b_u_newhead);
    put_header_ptr(bi, buf->b_u_curhead);

    undo_write_bytes(bi, (long_u)buf->b_u_numhead, 4);
    undo_write_bytes(bi, (long_u)buf->b_u_seq_last, 4);
    undo_write_bytes(bi, (long_u)buf->b_u_seq_cur, 4);
    time_to_bytes(buf->b_u_time_cur, time_buf);
    undo_write(bi, time_buf, 8);

    
    undo_write_bytes(bi, 4, 1);
    undo_write_bytes(bi, UF_LAST_SAVE_NR, 1);
    undo_write_bytes(bi, (long_u)buf->b_u_save_nr_last, 4);

    undo_write_bytes(bi, 0, 1);  

    return OK;
}

    static int serialize_uhp(bufinfo_T *bi, u_header_T *uhp)
{
    int		i;
    u_entry_T	*uep;
    char_u	time_buf[8];

    if (undo_write_bytes(bi, (long_u)UF_HEADER_MAGIC, 2) == FAIL)
	return FAIL;

    put_header_ptr(bi, uhp->uh_next.ptr);
    put_header_ptr(bi, uhp->uh_prev.ptr);
    put_header_ptr(bi, uhp->uh_alt_next.ptr);
    put_header_ptr(bi, uhp->uh_alt_prev.ptr);
    undo_write_bytes(bi, uhp->uh_seq, 4);
    serialize_pos(bi, uhp->uh_cursor);
    undo_write_bytes(bi, (long_u)uhp->uh_cursor_vcol, 4);
    undo_write_bytes(bi, (long_u)uhp->uh_flags, 2);
    
    for (i = 0; i < NMARKS; ++i)
	serialize_pos(bi, uhp->uh_namedm[i]);
    serialize_visualinfo(bi, &uhp->uh_visual);
    time_to_bytes(uhp->uh_time, time_buf);
    undo_write(bi, time_buf, 8);

    
    undo_write_bytes(bi, 4, 1);
    undo_write_bytes(bi, UHP_SAVE_NR, 1);
    undo_write_bytes(bi, (long_u)uhp->uh_save_nr, 4);

    undo_write_bytes(bi, 0, 1);  

    
    for (uep = uhp->uh_entry; uep != NULL; uep = uep->ue_next)
    {
	undo_write_bytes(bi, (long_u)UF_ENTRY_MAGIC, 2);
	if (serialize_uep(bi, uep) == FAIL)
	    return FAIL;
    }
    undo_write_bytes(bi, (long_u)UF_ENTRY_END_MAGIC, 2);
    return OK;
}

    static u_header_T * unserialize_uhp(bufinfo_T *bi, char_u *file_name)
{
    u_header_T	*uhp;
    int		i;
    u_entry_T	*uep, *last_uep;
    int		c;
    int		error;

    uhp = U_ALLOC_LINE(sizeof(u_header_T));
    if (uhp == NULL)
	return NULL;
    CLEAR_POINTER(uhp);

    uhp->uh_magic = UH_MAGIC;

    uhp->uh_next.seq = undo_read_4c(bi);
    uhp->uh_prev.seq = undo_read_4c(bi);
    uhp->uh_alt_next.seq = undo_read_4c(bi);
    uhp->uh_alt_prev.seq = undo_read_4c(bi);
    uhp->uh_seq = undo_read_4c(bi);
    if (uhp->uh_seq <= 0)
    {
	corruption_error("uh_seq", file_name);
	vim_free(uhp);
	return NULL;
    }
    unserialize_pos(bi, &uhp->uh_cursor);
    uhp->uh_cursor_vcol = undo_read_4c(bi);
    uhp->uh_flags = undo_read_2c(bi);
    for (i = 0; i < NMARKS; ++i)
	unserialize_pos(bi, &uhp->uh_namedm[i]);
    unserialize_visualinfo(bi, &uhp->uh_visual);
    uhp->uh_time = undo_read_time(bi);

    
    for (;;)
    {
	int len = undo_read_byte(bi);
	int what;

	if (len == EOF)
	{
	    corruption_error("truncated", file_name);
	    u_free_uhp(uhp);
	    return NULL;
	}
	if (len == 0)
	    break;
	what = undo_read_byte(bi);
	switch (what)
	{
	    case UHP_SAVE_NR:
		uhp->uh_save_nr = undo_read_4c(bi);
		break;
	    default:
		
		while (--len >= 0)
		    (void)undo_read_byte(bi);
	}
    }

    
    last_uep = NULL;
    while ((c = undo_read_2c(bi)) == UF_ENTRY_MAGIC)
    {
	error = FALSE;
	uep = unserialize_uep(bi, &error, file_name);
	if (last_uep == NULL)
	    uhp->uh_entry = uep;
	else last_uep->ue_next = uep;
	last_uep = uep;
	if (uep == NULL || error)
	{
	    u_free_uhp(uhp);
	    return NULL;
	}
    }
    if (c != UF_ENTRY_END_MAGIC)
    {
	corruption_error("entry end", file_name);
	u_free_uhp(uhp);
	return NULL;
    }

    return uhp;
}


    static int serialize_uep( bufinfo_T	*bi, u_entry_T	*uep)


{
    int		i;
    size_t	len;

    undo_write_bytes(bi, (long_u)uep->ue_top, 4);
    undo_write_bytes(bi, (long_u)uep->ue_bot, 4);
    undo_write_bytes(bi, (long_u)uep->ue_lcount, 4);
    undo_write_bytes(bi, (long_u)uep->ue_size, 4);
    for (i = 0; i < uep->ue_size; ++i)
    {
	
	
	len = STRLEN(uep->ue_array[i].ul_line);
	if (undo_write_bytes(bi, (long_u)len, 4) == FAIL)
	    return FAIL;
	if (len > 0 && fwrite_crypt(bi, uep->ue_array[i].ul_line, len) == FAIL)
	    return FAIL;
    }
    return OK;
}

    static u_entry_T * unserialize_uep(bufinfo_T *bi, int *error, char_u *file_name)
{
    int		i;
    u_entry_T	*uep;
    undoline_T	*array = NULL;
    char_u	*line;
    int		line_len;

    uep = U_ALLOC_LINE(sizeof(u_entry_T));
    if (uep == NULL)
	return NULL;
    CLEAR_POINTER(uep);

    uep->ue_magic = UE_MAGIC;

    uep->ue_top = undo_read_4c(bi);
    uep->ue_bot = undo_read_4c(bi);
    uep->ue_lcount = undo_read_4c(bi);
    uep->ue_size = undo_read_4c(bi);
    if (uep->ue_size > 0)
    {
	if (uep->ue_size < LONG_MAX / (int)sizeof(char_u *))
	    array = U_ALLOC_LINE(sizeof(undoline_T) * uep->ue_size);
	if (array == NULL)
	{
	    *error = TRUE;
	    return uep;
	}
	vim_memset(array, 0, sizeof(undoline_T) * uep->ue_size);
    }
    uep->ue_array = array;

    for (i = 0; i < uep->ue_size; ++i)
    {
	line_len = undo_read_4c(bi);
	if (line_len >= 0)
	    line = read_string_decrypt(bi, line_len);
	else {
	    line = NULL;
	    corruption_error("line length", file_name);
	}
	if (line == NULL)
	{
	    *error = TRUE;
	    return uep;
	}
	array[i].ul_line = line;
	array[i].ul_len = line_len + 1;
    }
    return uep;
}


    static void serialize_pos(bufinfo_T *bi, pos_T pos)
{
    undo_write_bytes(bi, (long_u)pos.lnum, 4);
    undo_write_bytes(bi, (long_u)pos.col, 4);
    undo_write_bytes(bi, (long_u)pos.coladd, 4);
}


    static void unserialize_pos(bufinfo_T *bi, pos_T *pos)
{
    pos->lnum = undo_read_4c(bi);
    if (pos->lnum < 0)
	pos->lnum = 0;
    pos->col = undo_read_4c(bi);
    if (pos->col < 0)
	pos->col = 0;
    pos->coladd = undo_read_4c(bi);
    if (pos->coladd < 0)
	pos->coladd = 0;
}


    static void serialize_visualinfo(bufinfo_T *bi, visualinfo_T *info)
{
    serialize_pos(bi, info->vi_start);
    serialize_pos(bi, info->vi_end);
    undo_write_bytes(bi, (long_u)info->vi_mode, 4);
    undo_write_bytes(bi, (long_u)info->vi_curswant, 4);
}


    static void unserialize_visualinfo(bufinfo_T *bi, visualinfo_T *info)
{
    unserialize_pos(bi, &info->vi_start);
    unserialize_pos(bi, &info->vi_end);
    info->vi_mode = undo_read_4c(bi);
    info->vi_curswant = undo_read_4c(bi);
}


    void u_write_undo( char_u	*name, int		forceit, buf_T	*buf, char_u	*hash)




{
    u_header_T	*uhp;
    char_u	*file_name;
    int		mark;

    int		headers_written = 0;

    int		fd;
    FILE	*fp = NULL;
    int		perm;
    int		write_ok = FALSE;

    int		st_old_valid = FALSE;
    stat_T	st_old;
    stat_T	st_new;

    bufinfo_T	bi;

    CLEAR_FIELD(bi);

    if (name == NULL)
    {
	file_name = u_get_undo_file_name(buf->b_ffname, FALSE);
	if (file_name == NULL)
	{
	    if (p_verbose > 0)
	    {
		verbose_enter();
		smsg( _("Cannot write undo file in any directory in 'undodir'"));
		verbose_leave();
	    }
	    return;
	}
    }
    else file_name = name;

    
    perm = 0600;
    if (buf->b_ffname != NULL)
    {

	if (mch_stat((char *)buf->b_ffname, &st_old) >= 0)
	{
	    perm = st_old.st_mode;
	    st_old_valid = TRUE;
	}

	perm = mch_getperm(buf->b_ffname);
	if (perm < 0)
	    perm = 0600;

    }

    
    perm = perm & 0666;

    
    
    if (mch_getperm(file_name) >= 0)
    {
	if (name == NULL || !forceit)
	{
	    
	    fd = mch_open((char *)file_name, O_RDONLY|O_EXTRA, 0);
	    if (fd < 0)
	    {
		if (name != NULL || p_verbose > 0)
		{
		    if (name == NULL)
			verbose_enter();
		    smsg( _("Will not overwrite with undo file, cannot read: %s"), file_name);

		    if (name == NULL)
			verbose_leave();
		}
		goto theend;
	    }
	    else {
		char_u	mbuf[UF_START_MAGIC_LEN];
		int	len;

		len = read_eintr(fd, mbuf, UF_START_MAGIC_LEN);
		close(fd);
		if (len < UF_START_MAGIC_LEN || memcmp(mbuf, UF_START_MAGIC, UF_START_MAGIC_LEN) != 0)
		{
		    if (name != NULL || p_verbose > 0)
		    {
			if (name == NULL)
			    verbose_enter();
			smsg( _("Will not overwrite, this is not an undo file: %s"), file_name);

			if (name == NULL)
			    verbose_leave();
		    }
		    goto theend;
		}
	    }
	}
	mch_remove(file_name);
    }

    
    
    if (buf->b_u_numhead == 0 && buf->b_u_line_ptr.ul_line == NULL)
    {
	if (p_verbose > 0)
	    verb_msg(_("Skipping undo file write, nothing to undo"));
	goto theend;
    }

    fd = mch_open((char *)file_name, O_CREAT|O_EXTRA|O_WRONLY|O_EXCL|O_NOFOLLOW, perm);
    if (fd < 0)
    {
	semsg(_(e_cannot_open_undo_file_for_writing_str), file_name);
	goto theend;
    }
    (void)mch_setperm(file_name, perm);
    if (p_verbose > 0)
    {
	verbose_enter();
	smsg(_("Writing undo file: %s"), file_name);
	verbose_leave();
    }


    
    u_check(FALSE);



    
    if (st_old_valid && mch_stat((char *)file_name, &st_new) >= 0 && st_new.st_gid != st_old.st_gid  && fchown(fd, (uid_t)-1, st_old.st_gid) != 0  )





	mch_setperm(file_name, (perm & 0707) | ((perm & 07) << 3));

    if (buf->b_ffname != NULL)
	mch_copy_sec(buf->b_ffname, file_name);



    fp = fdopen(fd, "w");
    if (fp == NULL)
    {
	semsg(_(e_cannot_open_undo_file_for_writing_str), file_name);
	close(fd);
	mch_remove(file_name);
	goto theend;
    }

    
    u_sync(TRUE);

    
    bi.bi_buf = buf;
    bi.bi_fp = fp;
    if (serialize_header(&bi, hash) == FAIL)
	goto write_error;

    
    mark = ++lastmark;
    uhp = buf->b_u_oldhead;
    while (uhp != NULL)
    {
	
	if (uhp->uh_walk != mark)
	{
	    uhp->uh_walk = mark;

	    ++headers_written;

	    if (serialize_uhp(&bi, uhp) == FAIL)
		goto write_error;
	}

	
	if (uhp->uh_prev.ptr != NULL && uhp->uh_prev.ptr->uh_walk != mark)
	    uhp = uhp->uh_prev.ptr;
	else if (uhp->uh_alt_next.ptr != NULL && uhp->uh_alt_next.ptr->uh_walk != mark)
	    uhp = uhp->uh_alt_next.ptr;
	else if (uhp->uh_next.ptr != NULL && uhp->uh_alt_prev.ptr == NULL && uhp->uh_next.ptr->uh_walk != mark)
	    uhp = uhp->uh_next.ptr;
	else if (uhp->uh_alt_prev.ptr != NULL)
	    uhp = uhp->uh_alt_prev.ptr;
	else uhp = uhp->uh_next.ptr;
    }

    if (undo_write_bytes(&bi, (long_u)UF_HEADER_END_MAGIC, 2) == OK)
	write_ok = TRUE;

    if (headers_written != buf->b_u_numhead)
    {
	semsg("Written %ld headers, ...", headers_written);
	semsg("... but numhead is %ld", buf->b_u_numhead);
    }



    if (bi.bi_state != NULL && undo_flush(&bi) == FAIL)
	write_ok = FALSE;



    if (p_fs && fflush(fp) == 0 && vim_fsync(fd) != 0)
	write_ok = FALSE;


write_error:
    fclose(fp);
    if (!write_ok)
	semsg(_(e_write_error_in_undo_file_str), file_name);


    
    
    if (buf->b_ffname != NULL)
	(void)mch_copy_file_attribute(buf->b_ffname, file_name);


    if (buf->b_ffname != NULL)
    {
	vim_acl_T	    acl;

	
	acl = mch_get_acl(buf->b_ffname);
	mch_set_acl(file_name, acl);
	mch_free_acl(acl);
    }


theend:

    if (bi.bi_state != NULL)
	crypt_free_state(bi.bi_state);
    vim_free(bi.bi_buffer);

    if (file_name != name)
	vim_free(file_name);
}


    void u_read_undo(char_u *name, char_u *hash, char_u *orig_name UNUSED)
{
    char_u	*file_name;
    FILE	*fp;
    long	version, str_len;
    undoline_T	line_ptr;
    linenr_T	line_lnum;
    colnr_T	line_colnr;
    linenr_T	line_count;
    long	num_head = 0;
    long	old_header_seq, new_header_seq, cur_header_seq;
    long	seq_last, seq_cur;
    long	last_save_nr = 0;
    short	old_idx = -1, new_idx = -1, cur_idx = -1;
    long	num_read_uhps = 0;
    time_t	seq_time;
    int		i, j;
    int		c;
    u_header_T	*uhp;
    u_header_T	**uhp_table = NULL;
    char_u	read_hash[UNDO_HASH_SIZE];
    char_u	magic_buf[UF_START_MAGIC_LEN];

    int		*uhp_table_used;


    stat_T	st_orig;
    stat_T	st_undo;

    bufinfo_T	bi;

    CLEAR_FIELD(bi);
    line_ptr.ul_len = 0;
    line_ptr.ul_line = NULL;

    if (name == NULL)
    {
	file_name = u_get_undo_file_name(curbuf->b_ffname, TRUE);
	if (file_name == NULL)
	    return;


	
	
	if (mch_stat((char *)orig_name, &st_orig) >= 0 && mch_stat((char *)file_name, &st_undo) >= 0 && st_orig.st_uid != st_undo.st_uid && st_undo.st_uid != getuid())


	{
	    if (p_verbose > 0)
	    {
		verbose_enter();
		smsg(_("Not reading undo file, owner differs: %s"), file_name);
		verbose_leave();
	    }
	    return;
	}

    }
    else file_name = name;

    if (p_verbose > 0)
    {
	verbose_enter();
	smsg(_("Reading undo file: %s"), file_name);
	verbose_leave();
    }

    fp = mch_fopen((char *)file_name, "r");
    if (fp == NULL)
    {
	if (name != NULL || p_verbose > 0)
	    semsg(_(e_cannot_open_undo_file_for_reading_str), file_name);
	goto error;
    }
    bi.bi_buf = curbuf;
    bi.bi_fp = fp;

    
    if (fread(magic_buf, UF_START_MAGIC_LEN, 1, fp) != 1 || memcmp(magic_buf, UF_START_MAGIC, UF_START_MAGIC_LEN) != 0)
    {
	semsg(_(e_not_an_undo_file_str), file_name);
	goto error;
    }
    version = get2c(fp);
    if (version == UF_VERSION_CRYPT)
    {

	if (*curbuf->b_p_key == NUL)
	{
	    semsg(_(e_non_encrypted_file_has_encrypted_undo_file), file_name);
	    goto error;
	}
	bi.bi_state = crypt_create_from_file(fp, curbuf->b_p_key);
	if (bi.bi_state == NULL)
	{
	    semsg(_(e_undo_file_decryption_failed), file_name);
	    goto error;
	}
	if (crypt_whole_undofile(bi.bi_state->method_nr))
	{
	    bi.bi_buffer = alloc(CRYPT_BUF_SIZE);
	    if (bi.bi_buffer == NULL)
	    {
		crypt_free_state(bi.bi_state);
		bi.bi_state = NULL;
		goto error;
	    }
	    bi.bi_avail = 0;
	    bi.bi_used = 0;
	}

	semsg(_(e_undo_file_is_encrypted_str), file_name);
	goto error;

    }
    else if (version != UF_VERSION)
    {
	semsg(_(e_incompatible_undo_file_str), file_name);
	goto error;
    }

    if (undo_read(&bi, read_hash, (size_t)UNDO_HASH_SIZE) == FAIL)
    {
	corruption_error("hash", file_name);
	goto error;
    }
    line_count = (linenr_T)undo_read_4c(&bi);
    if (memcmp(hash, read_hash, UNDO_HASH_SIZE) != 0 || line_count != curbuf->b_ml.ml_line_count)
    {
	if (p_verbose > 0 || name != NULL)
	{
	    if (name == NULL)
		verbose_enter();
	    give_warning((char_u *)
		      _("File contents changed, cannot use undo info"), TRUE);
	    if (name == NULL)
		verbose_leave();
	}
	goto error;
    }

    
    str_len = undo_read_4c(&bi);
    if (str_len < 0)
	goto error;
    if (str_len > 0)
    {
	line_ptr.ul_line = read_string_decrypt(&bi, str_len);
	line_ptr.ul_len = str_len + 1;
    }
    line_lnum = (linenr_T)undo_read_4c(&bi);
    line_colnr = (colnr_T)undo_read_4c(&bi);
    if (line_lnum < 0 || line_colnr < 0)
    {
	corruption_error("line lnum/col", file_name);
	goto error;
    }

    
    old_header_seq = undo_read_4c(&bi);
    new_header_seq = undo_read_4c(&bi);
    cur_header_seq = undo_read_4c(&bi);
    num_head = undo_read_4c(&bi);
    seq_last = undo_read_4c(&bi);
    seq_cur = undo_read_4c(&bi);
    seq_time = undo_read_time(&bi);

    
    for (;;)
    {
	int len = undo_read_byte(&bi);
	int what;

	if (len == 0 || len == EOF)
	    break;
	what = undo_read_byte(&bi);
	switch (what)
	{
	    case UF_LAST_SAVE_NR:
		last_save_nr = undo_read_4c(&bi);
		break;
	    default:
		
		while (--len >= 0)
		    (void)undo_read_byte(&bi);
	}
    }

    
    
    
    
    if (num_head > 0)
    {
	if (num_head < LONG_MAX / (long)sizeof(u_header_T *))
	    uhp_table = U_ALLOC_LINE(num_head * sizeof(u_header_T *));
	if (uhp_table == NULL)
	    goto error;
    }

    while ((c = undo_read_2c(&bi)) == UF_HEADER_MAGIC)
    {
	if (num_read_uhps >= num_head)
	{
	    corruption_error("num_head too small", file_name);
	    goto error;
	}

	uhp = unserialize_uhp(&bi, file_name);
	if (uhp == NULL)
	    goto error;
	uhp_table[num_read_uhps++] = uhp;
    }

    if (num_read_uhps != num_head)
    {
	corruption_error("num_head", file_name);
	goto error;
    }
    if (c != UF_HEADER_END_MAGIC)
    {
	corruption_error("end marker", file_name);
	goto error;
    }


    uhp_table_used = alloc_clear(sizeof(int) * num_head + 1);





    
    
    
    for (i = 0; i < num_head; i++)
    {
	uhp = uhp_table[i];
	if (uhp == NULL)
	    continue;
	for (j = 0; j < num_head; j++)
	    if (uhp_table[j] != NULL && i != j && uhp_table[i]->uh_seq == uhp_table[j]->uh_seq)
	    {
		corruption_error("duplicate uh_seq", file_name);
		goto error;
	    }
	for (j = 0; j < num_head; j++)
	    if (uhp_table[j] != NULL && uhp_table[j]->uh_seq == uhp->uh_next.seq)
	    {
		uhp->uh_next.ptr = uhp_table[j];
		SET_FLAG(j);
		break;
	    }
	for (j = 0; j < num_head; j++)
	    if (uhp_table[j] != NULL && uhp_table[j]->uh_seq == uhp->uh_prev.seq)
	    {
		uhp->uh_prev.ptr = uhp_table[j];
		SET_FLAG(j);
		break;
	    }
	for (j = 0; j < num_head; j++)
	    if (uhp_table[j] != NULL && uhp_table[j]->uh_seq == uhp->uh_alt_next.seq)
	    {
		uhp->uh_alt_next.ptr = uhp_table[j];
		SET_FLAG(j);
		break;
	    }
	for (j = 0; j < num_head; j++)
	    if (uhp_table[j] != NULL && uhp_table[j]->uh_seq == uhp->uh_alt_prev.seq)
	    {
		uhp->uh_alt_prev.ptr = uhp_table[j];
		SET_FLAG(j);
		break;
	    }
	if (old_header_seq > 0 && old_idx < 0 && uhp->uh_seq == old_header_seq)
	{
	    old_idx = i;
	    SET_FLAG(i);
	}
	if (new_header_seq > 0 && new_idx < 0 && uhp->uh_seq == new_header_seq)
	{
	    new_idx = i;
	    SET_FLAG(i);
	}
	if (cur_header_seq > 0 && cur_idx < 0 && uhp->uh_seq == cur_header_seq)
	{
	    cur_idx = i;
	    SET_FLAG(i);
	}
    }

    
    
    u_blockfree(curbuf);
    curbuf->b_u_oldhead = old_idx < 0 ? NULL : uhp_table[old_idx];
    curbuf->b_u_newhead = new_idx < 0 ? NULL : uhp_table[new_idx];
    curbuf->b_u_curhead = cur_idx < 0 ? NULL : uhp_table[cur_idx];
    curbuf->b_u_line_ptr = line_ptr;
    curbuf->b_u_line_lnum = line_lnum;
    curbuf->b_u_line_colnr = line_colnr;
    curbuf->b_u_numhead = num_head;
    curbuf->b_u_seq_last = seq_last;
    curbuf->b_u_seq_cur = seq_cur;
    curbuf->b_u_time_cur = seq_time;
    curbuf->b_u_save_nr_last = last_save_nr;
    curbuf->b_u_save_nr_cur = last_save_nr;

    curbuf->b_u_synced = TRUE;
    vim_free(uhp_table);


    for (i = 0; i < num_head; ++i)
	if (uhp_table_used[i] == 0)
	    semsg("uhp_table entry %ld not used, leaking memory", i);
    vim_free(uhp_table_used);
    u_check(TRUE);


    if (name != NULL)
	smsg(_("Finished reading undo file %s"), file_name);
    goto theend;

error:
    vim_free(line_ptr.ul_line);
    if (uhp_table != NULL)
    {
	for (i = 0; i < num_read_uhps; i++)
	    if (uhp_table[i] != NULL)
		u_free_uhp(uhp_table[i]);
	vim_free(uhp_table);
    }

theend:

    if (bi.bi_state != NULL)
	crypt_free_state(bi.bi_state);
    vim_free(bi.bi_buffer);

    if (fp != NULL)
	fclose(fp);
    if (file_name != name)
	vim_free(file_name);
    return;
}





    void u_undo(int count)
{
    
    if (curbuf->b_u_synced == FALSE)
    {
	u_sync(TRUE);
	count = 1;
    }

    if (vim_strchr(p_cpo, CPO_UNDO) == NULL)
	undo_undoes = TRUE;
    else undo_undoes = !undo_undoes;
    u_doit(count);
}


    void u_redo(int count)
{
    if (vim_strchr(p_cpo, CPO_UNDO) == NULL)
	undo_undoes = FALSE;
    u_doit(count);
}


    static void u_doit(int startcount)
{
    int count = startcount;

    if (!undo_allowed())
	return;

    u_newcount = 0;
    u_oldcount = 0;
    if (curbuf->b_ml.ml_flags & ML_EMPTY)
	u_oldcount = -1;
    while (count--)
    {
	
	
	
	
	change_warning(0);

	if (undo_undoes)
	{
	    if (curbuf->b_u_curhead == NULL)		
		curbuf->b_u_curhead = curbuf->b_u_newhead;
	    else if (get_undolevel() > 0)		
		
		curbuf->b_u_curhead = curbuf->b_u_curhead->uh_next.ptr;
	    
	    if (curbuf->b_u_numhead == 0 || curbuf->b_u_curhead == NULL)
	    {
		
		curbuf->b_u_curhead = curbuf->b_u_oldhead;
		beep_flush();
		if (count == startcount - 1)
		{
		    msg(_("Already at oldest change"));
		    return;
		}
		break;
	    }

	    u_undoredo(TRUE);
	}
	else {
	    if (curbuf->b_u_curhead == NULL || get_undolevel() <= 0)
	    {
		beep_flush();	
		if (count == startcount - 1)
		{
		    msg(_("Already at newest change"));
		    return;
		}
		break;
	    }

	    u_undoredo(FALSE);

	    
	    
	    if (curbuf->b_u_curhead->uh_prev.ptr == NULL)
		curbuf->b_u_newhead = curbuf->b_u_curhead;
	    curbuf->b_u_curhead = curbuf->b_u_curhead->uh_prev.ptr;
	}
    }
    u_undo_end(undo_undoes, FALSE);
}


    void undo_time( long	step, int		sec, int		file, int		absolute)




{
    long	    target;
    long	    closest;
    long	    closest_start;
    long	    closest_seq = 0;
    long	    val;
    u_header_T	    *uhp = NULL;
    u_header_T	    *last;
    int		    mark;
    int		    nomark = 0;  
    int		    round;
    int		    dosec = sec;
    int		    dofile = file;
    int		    above = FALSE;
    int		    did_undo = TRUE;

    
    if (curbuf->b_u_synced == FALSE)
	u_sync(TRUE);

    u_newcount = 0;
    u_oldcount = 0;
    if (curbuf->b_ml.ml_flags & ML_EMPTY)
	u_oldcount = -1;

    
    
    if (absolute)
    {
	target = step;
	closest = -1;
    }
    else {
	if (dosec)
	    target = (long)(curbuf->b_u_time_cur) + step;
	else if (dofile)
	{
	    if (step < 0)
	    {
		
		
		
		uhp = curbuf->b_u_curhead;
		if (uhp != NULL)
		    uhp = uhp->uh_next.ptr;
		else uhp = curbuf->b_u_newhead;
		if (uhp != NULL && uhp->uh_save_nr != 0)
		    
		    
		    target = curbuf->b_u_save_nr_cur + step;
		else  target = curbuf->b_u_save_nr_cur + step + 1;

		if (target <= 0)
		    
		    
		    dofile = FALSE;
	    }
	    else {
		
		target = curbuf->b_u_save_nr_cur + step;
		if (target > curbuf->b_u_save_nr_last)
		{
		    
		    
		    target = curbuf->b_u_seq_last + 1;
		    dofile = FALSE;
		}
	    }
	}
	else target = curbuf->b_u_seq_cur + step;
	if (step < 0)
	{
	    if (target < 0)
		target = 0;
	    closest = -1;
	}
	else {
	    if (dosec)
		closest = (long)(vim_time() + 1);
	    else if (dofile)
		closest = curbuf->b_u_save_nr_last + 2;
	    else closest = curbuf->b_u_seq_last + 2;
	    if (target >= closest)
		target = closest - 1;
	}
    }
    closest_start = closest;
    closest_seq = curbuf->b_u_seq_cur;

    
    if (target == 0)
    {
	mark = lastmark;  
	goto target_zero;
    }

    
    for (round = 1; round <= 2; ++round)
    {
	
	
	
	
	mark = ++lastmark;
	nomark = ++lastmark;

	if (curbuf->b_u_curhead == NULL)	
	    uhp = curbuf->b_u_newhead;
	else uhp = curbuf->b_u_curhead;

	while (uhp != NULL)
	{
	    uhp->uh_walk = mark;
	    if (dosec)
		val = (long)(uhp->uh_time);
	    else if (dofile)
		val = uhp->uh_save_nr;
	    else val = uhp->uh_seq;

	    if (round == 1 && !(dofile && val == 0))
	    {
		
		
		
		
		if ((step < 0 ? uhp->uh_seq <= curbuf->b_u_seq_cur : uhp->uh_seq > curbuf->b_u_seq_cur)
			&& ((dosec && val == closest)
			    ? (step < 0 ? uhp->uh_seq < closest_seq : uhp->uh_seq > closest_seq)

			    : closest == closest_start || (val > target ? (closest > target ? val - target <= closest - target : val - target <= target - closest)



				    : (closest > target ? target - val <= closest - target : target - val <= target - closest))))

		{
		    closest = val;
		    closest_seq = uhp->uh_seq;
		}
	    }

	    
	    
	    if (target == val && !dosec)
	    {
		target = uhp->uh_seq;
		break;
	    }

	    
	    if (uhp->uh_prev.ptr != NULL && uhp->uh_prev.ptr->uh_walk != nomark && uhp->uh_prev.ptr->uh_walk != mark)
		uhp = uhp->uh_prev.ptr;

	    
	    else if (uhp->uh_alt_next.ptr != NULL && uhp->uh_alt_next.ptr->uh_walk != nomark && uhp->uh_alt_next.ptr->uh_walk != mark)

		uhp = uhp->uh_alt_next.ptr;

	    
	    
	    else if (uhp->uh_next.ptr != NULL && uhp->uh_alt_prev.ptr == NULL && uhp->uh_next.ptr->uh_walk != nomark && uhp->uh_next.ptr->uh_walk != mark)

	    {
		
		if (uhp == curbuf->b_u_curhead)
		    uhp->uh_walk = nomark;
		uhp = uhp->uh_next.ptr;
	    }

	    else {
		
		uhp->uh_walk = nomark;
		if (uhp->uh_alt_prev.ptr != NULL)
		    uhp = uhp->uh_alt_prev.ptr;
		else uhp = uhp->uh_next.ptr;
	    }
	}

	if (uhp != NULL)    
	    break;

	if (absolute)
	{
	    semsg(_(e_undo_number_nr_not_found), step);
	    return;
	}

	if (closest == closest_start)
	{
	    if (step < 0)
		msg(_("Already at oldest change"));
	    else msg(_("Already at newest change"));
	    return;
	}

	target = closest_seq;
	dosec = FALSE;
	dofile = FALSE;
	if (step < 0)
	    above = TRUE;	
    }

target_zero:
    
    if (uhp != NULL || target == 0)
    {
	
	while (!got_int)
	{
	    
	    change_warning(0);

	    uhp = curbuf->b_u_curhead;
	    if (uhp == NULL)
		uhp = curbuf->b_u_newhead;
	    else uhp = uhp->uh_next.ptr;
	    if (uhp == NULL || (target > 0 && uhp->uh_walk != mark)
					 || (uhp->uh_seq == target && !above))
		break;
	    curbuf->b_u_curhead = uhp;
	    u_undoredo(TRUE);
	    if (target > 0)
		uhp->uh_walk = nomark;	
	}

	
	if (target > 0)
	{
	    
	    while (!got_int)
	    {
		
		change_warning(0);

		uhp = curbuf->b_u_curhead;
		if (uhp == NULL)
		    break;

		
		while (uhp->uh_alt_prev.ptr != NULL && uhp->uh_alt_prev.ptr->uh_walk == mark)
		    uhp = uhp->uh_alt_prev.ptr;

		
		last = uhp;
		while (last->uh_alt_next.ptr != NULL && last->uh_alt_next.ptr->uh_walk == mark)
		    last = last->uh_alt_next.ptr;
		if (last != uhp)
		{
		    
		    
		    while (uhp->uh_alt_prev.ptr != NULL)
			uhp = uhp->uh_alt_prev.ptr;
		    if (last->uh_alt_next.ptr != NULL)
			last->uh_alt_next.ptr->uh_alt_prev.ptr = last->uh_alt_prev.ptr;
		    last->uh_alt_prev.ptr->uh_alt_next.ptr = last->uh_alt_next.ptr;
		    last->uh_alt_prev.ptr = NULL;
		    last->uh_alt_next.ptr = uhp;
		    uhp->uh_alt_prev.ptr = last;

		    if (curbuf->b_u_oldhead == uhp)
			curbuf->b_u_oldhead = last;
		    uhp = last;
		    if (uhp->uh_next.ptr != NULL)
			uhp->uh_next.ptr->uh_prev.ptr = uhp;
		}
		curbuf->b_u_curhead = uhp;

		if (uhp->uh_walk != mark)
		    break;	    

		
		
		if (uhp->uh_seq == target && above)
		{
		    curbuf->b_u_seq_cur = target - 1;
		    break;
		}

		u_undoredo(FALSE);

		
		
		if (uhp->uh_prev.ptr == NULL)
		    curbuf->b_u_newhead = uhp;
		curbuf->b_u_curhead = uhp->uh_prev.ptr;
		did_undo = FALSE;

		if (uhp->uh_seq == target)	
		    break;

		uhp = uhp->uh_prev.ptr;
		if (uhp == NULL || uhp->uh_walk != mark)
		{
		    
		    internal_error("undo_time()");
		    break;
		}
	    }
	}
    }
    u_undo_end(did_undo, absolute);
}


    static void u_undoredo(int undo)
{
    undoline_T	*newarray = NULL;
    linenr_T	oldsize;
    linenr_T	newsize;
    linenr_T	top, bot;
    linenr_T	lnum;
    linenr_T	newlnum = MAXLNUM;
    pos_T	new_curpos = curwin->w_cursor;
    long	i;
    u_entry_T	*uep, *nuep;
    u_entry_T	*newlist = NULL;
    int		old_flags;
    int		new_flags;
    pos_T	namedm[NMARKS];
    visualinfo_T visualinfo;
    int		empty_buffer;		    
    u_header_T	*curhead = curbuf->b_u_curhead;

    
    
    block_autocmds();


    u_check(FALSE);

    old_flags = curhead->uh_flags;
    new_flags = (curbuf->b_changed ? UH_CHANGED : 0) + ((curbuf->b_ml.ml_flags & ML_EMPTY) ? UH_EMPTYBUF : 0);
    setpcmark();

    
    mch_memmove(namedm, curbuf->b_namedm, sizeof(pos_T) * NMARKS);
    visualinfo = curbuf->b_visual;
    curbuf->b_op_start.lnum = curbuf->b_ml.ml_line_count;
    curbuf->b_op_start.col = 0;
    curbuf->b_op_end.lnum = 0;
    curbuf->b_op_end.col = 0;

    for (uep = curhead->uh_entry; uep != NULL; uep = nuep)
    {
	top = uep->ue_top;
	bot = uep->ue_bot;
	if (bot == 0)
	    bot = curbuf->b_ml.ml_line_count + 1;
	if (top > curbuf->b_ml.ml_line_count || top >= bot || bot > curbuf->b_ml.ml_line_count + 1)
	{
	    unblock_autocmds();
	    iemsg(_(e_u_undo_line_numbers_wrong));
	    changed();		
	    return;
	}

	oldsize = bot - top - 1;    
	newsize = uep->ue_size;	    

	
	
	if (top < newlnum)
	{
	    
	    
	    
	    lnum = curhead->uh_cursor.lnum;
	    if (lnum >= top && lnum <= top + newsize + 1)
	    {
		new_curpos = curhead->uh_cursor;
		newlnum = new_curpos.lnum - 1;
	    }
	    else {
		
		
		
		for (i = 0; i < newsize && i < oldsize; ++i)
		{
		    char_u *p = ml_get(top + 1 + i);

		    if (curbuf->b_ml.ml_line_len != uep->ue_array[i].ul_len || memcmp(uep->ue_array[i].ul_line, p, curbuf->b_ml.ml_line_len) != 0)

			break;
		}
		if (i == newsize && newlnum == MAXLNUM && uep->ue_next == NULL)
		{
		    newlnum = top;
		    new_curpos.lnum = newlnum + 1;
		}
		else if (i < newsize)
		{
		    newlnum = top + i;
		    new_curpos.lnum = newlnum + 1;
		}
	    }
	}

	empty_buffer = FALSE;

	
	if (oldsize > 0)
	{
	    if ((newarray = U_ALLOC_LINE(sizeof(undoline_T) * oldsize)) == NULL)
	    {
		do_outofmem_msg((long_u)(sizeof(undoline_T) * oldsize));

		
		
		while (uep != NULL)
		{
		    nuep = uep->ue_next;
		    u_freeentry(uep, uep->ue_size);
		    uep = nuep;
		}
		break;
	    }
	    
	    for (lnum = bot - 1, i = oldsize; --i >= 0; --lnum)
	    {
		
		if (u_save_line(&newarray[i], lnum) == FAIL)
		    do_outofmem_msg((long_u)0);
		
		
		if (curbuf->b_ml.ml_line_count == 1)
		    empty_buffer = TRUE;
		ml_delete_flags(lnum, ML_DEL_UNDO);
	    }
	}
	else newarray = NULL;

	
	check_cursor_lnum();

	
	if (newsize)
	{
	    for (lnum = top, i = 0; i < newsize; ++i, ++lnum)
	    {
		
		
		if (empty_buffer && lnum == 0)
		    ml_replace_len((linenr_T)1, uep->ue_array[i].ul_line, uep->ue_array[i].ul_len, TRUE, TRUE);
		else ml_append_flags(lnum, uep->ue_array[i].ul_line, (colnr_T)uep->ue_array[i].ul_len, ML_APPEND_UNDO);

		vim_free(uep->ue_array[i].ul_line);
	    }
	    vim_free((char_u *)uep->ue_array);
	}

	
	if (oldsize != newsize)
	{
	    mark_adjust(top + 1, top + oldsize, (long)MAXLNUM, (long)newsize - (long)oldsize);
	    if (curbuf->b_op_start.lnum > top + oldsize)
		curbuf->b_op_start.lnum += newsize - oldsize;
	    if (curbuf->b_op_end.lnum > top + oldsize)
		curbuf->b_op_end.lnum += newsize - oldsize;
	}
	if (oldsize > 0 || newsize > 0)
	    changed_lines(top + 1, 0, bot, newsize - oldsize);

	
	if (top + 1 < curbuf->b_op_start.lnum)
	    curbuf->b_op_start.lnum = top + 1;
	
	if (newsize == 0 && top + 1 > curbuf->b_op_end.lnum)
	    curbuf->b_op_end.lnum = top + 1;
	else if (top + newsize > curbuf->b_op_end.lnum)
	    curbuf->b_op_end.lnum = top + newsize;

	u_newcount += newsize;
	u_oldcount += oldsize;
	uep->ue_size = oldsize;
	uep->ue_array = newarray;
	uep->ue_bot = top + newsize + 1;

	
	nuep = uep->ue_next;
	uep->ue_next = newlist;
	newlist = uep;
    }

    
    if (curbuf->b_op_start.lnum > curbuf->b_ml.ml_line_count)
	 curbuf->b_op_start.lnum = curbuf->b_ml.ml_line_count;
    if (curbuf->b_op_end.lnum > curbuf->b_ml.ml_line_count)
	 curbuf->b_op_end.lnum = curbuf->b_ml.ml_line_count;

    
    curwin->w_cursor = new_curpos;
    check_cursor_lnum();

    curhead->uh_entry = newlist;
    curhead->uh_flags = new_flags;
    if ((old_flags & UH_EMPTYBUF) && BUFEMPTY())
	curbuf->b_ml.ml_flags |= ML_EMPTY;
    if (old_flags & UH_CHANGED)
	changed();
    else   if (!isNetbeansModified(curbuf))



	unchanged(curbuf, FALSE, TRUE);

    
    for (i = 0; i < NMARKS; ++i)
    {
	if (curhead->uh_namedm[i].lnum != 0)
	    curbuf->b_namedm[i] = curhead->uh_namedm[i];
	if (namedm[i].lnum != 0)
	    curhead->uh_namedm[i] = namedm[i];
	else curhead->uh_namedm[i].lnum = 0;
    }
    if (curhead->uh_visual.vi_start.lnum != 0)
    {
	curbuf->b_visual = curhead->uh_visual;
	curhead->uh_visual = visualinfo;
    }

    
    if (curhead->uh_cursor.lnum + 1 == curwin->w_cursor.lnum && curwin->w_cursor.lnum > 1)
	--curwin->w_cursor.lnum;
    if (curwin->w_cursor.lnum <= curbuf->b_ml.ml_line_count)
    {
	if (curhead->uh_cursor.lnum == curwin->w_cursor.lnum)
	{
	    curwin->w_cursor.col = curhead->uh_cursor.col;
	    if (virtual_active() && curhead->uh_cursor_vcol >= 0)
		coladvance((colnr_T)curhead->uh_cursor_vcol);
	    else curwin->w_cursor.coladd = 0;
	}
	else beginline(BL_SOL | BL_FIX);
    }
    else {
	
	
	
	
	curwin->w_cursor.col = 0;
	curwin->w_cursor.coladd = 0;
    }

    
    check_cursor();

    
    curbuf->b_u_seq_cur = curhead->uh_seq;
    if (undo)
    {
	
	
	if (curhead->uh_next.ptr != NULL)
	    curbuf->b_u_seq_cur = curhead->uh_next.ptr->uh_seq;
	else curbuf->b_u_seq_cur = 0;
    }

    
    if (curhead->uh_save_nr != 0)
    {
	if (undo)
	    curbuf->b_u_save_nr_cur = curhead->uh_save_nr - 1;
	else curbuf->b_u_save_nr_cur = curhead->uh_save_nr;
    }

    
    
    curbuf->b_u_time_cur = curhead->uh_time;

    unblock_autocmds();

    u_check(FALSE);

}


    static void u_undo_end( int		did_undo, int		absolute)


{
    char	*msgstr;
    u_header_T	*uhp;
    char_u	msgbuf[80];


    if ((fdo_flags & FDO_UNDO) && KeyTyped)
	foldOpenCursor();


    if (global_busy	     || !messaging())
	return;

    if (curbuf->b_ml.ml_flags & ML_EMPTY)
	--u_newcount;

    u_oldcount -= u_newcount;
    if (u_oldcount == -1)
	msgstr = N_("more line");
    else if (u_oldcount < 0)
	msgstr = N_("more lines");
    else if (u_oldcount == 1)
	msgstr = N_("line less");
    else if (u_oldcount > 1)
	msgstr = N_("fewer lines");
    else {
	u_oldcount = u_newcount;
	if (u_newcount == 1)
	    msgstr = N_("change");
	else msgstr = N_("changes");
    }

    if (curbuf->b_u_curhead != NULL)
    {
	
	if (absolute && curbuf->b_u_curhead->uh_next.ptr != NULL)
	{
	    uhp = curbuf->b_u_curhead->uh_next.ptr;
	    did_undo = FALSE;
	}
	else if (did_undo)
	    uhp = curbuf->b_u_curhead;
	else uhp = curbuf->b_u_curhead->uh_next.ptr;
    }
    else uhp = curbuf->b_u_newhead;

    if (uhp == NULL)
	*msgbuf = NUL;
    else add_time(msgbuf, sizeof(msgbuf), uhp->uh_time);


    {
	win_T	*wp;

	FOR_ALL_WINDOWS(wp)
	{
	    if (wp->w_buffer == curbuf && wp->w_p_cole > 0)
		redraw_win_later(wp, NOT_VALID);
	}
    }

    if (VIsual_active)
	check_pos(curbuf, &VIsual);

    smsg_attr_keep(0, _("%ld %s; %s #%ld  %s"), u_oldcount < 0 ? -u_oldcount : u_oldcount, _(msgstr), did_undo ? _("before") : _("after"), uhp == NULL ? 0L : uhp->uh_seq, msgbuf);




}


    void u_sync( int	    force)

{
    
    if (curbuf->b_u_synced || (!force && no_u_sync > 0))
	return;

    if (p_imst == IM_ON_THE_SPOT && im_is_preediting())
	return;		    

    if (get_undolevel() < 0)
	curbuf->b_u_synced = TRUE;  
    else {
	u_getbot();		    
	curbuf->b_u_curhead = NULL;
    }
}


    void ex_undolist(exarg_T *eap UNUSED)
{
    garray_T	ga;
    u_header_T	*uhp;
    int		mark;
    int		nomark;
    int		changes = 1;
    int		i;

    
    mark = ++lastmark;
    nomark = ++lastmark;
    ga_init2(&ga, sizeof(char *), 20);

    uhp = curbuf->b_u_oldhead;
    while (uhp != NULL)
    {
	if (uhp->uh_prev.ptr == NULL && uhp->uh_walk != nomark && uhp->uh_walk != mark)
	{
	    if (ga_grow(&ga, 1) == FAIL)
		break;
	    vim_snprintf((char *)IObuff, IOSIZE, "%6ld %7d  ", uhp->uh_seq, changes);
	    add_time(IObuff + STRLEN(IObuff), IOSIZE - STRLEN(IObuff), uhp->uh_time);
	    if (uhp->uh_save_nr > 0)
	    {
		while (STRLEN(IObuff) < 33)
		    STRCAT(IObuff, " ");
		vim_snprintf_add((char *)IObuff, IOSIZE, "  %3ld", uhp->uh_save_nr);
	    }
	    ((char_u **)(ga.ga_data))[ga.ga_len++] = vim_strsave(IObuff);
	}

	uhp->uh_walk = mark;

	
	if (uhp->uh_prev.ptr != NULL && uhp->uh_prev.ptr->uh_walk != nomark && uhp->uh_prev.ptr->uh_walk != mark)
	{
	    uhp = uhp->uh_prev.ptr;
	    ++changes;
	}

	
	else if (uhp->uh_alt_next.ptr != NULL && uhp->uh_alt_next.ptr->uh_walk != nomark && uhp->uh_alt_next.ptr->uh_walk != mark)

	    uhp = uhp->uh_alt_next.ptr;

	
	
	else if (uhp->uh_next.ptr != NULL && uhp->uh_alt_prev.ptr == NULL && uhp->uh_next.ptr->uh_walk != nomark && uhp->uh_next.ptr->uh_walk != mark)

	{
	    uhp = uhp->uh_next.ptr;
	    --changes;
	}

	else {
	    
	    uhp->uh_walk = nomark;
	    if (uhp->uh_alt_prev.ptr != NULL)
		uhp = uhp->uh_alt_prev.ptr;
	    else {
		uhp = uhp->uh_next.ptr;
		--changes;
	    }
	}
    }

    if (ga.ga_len == 0)
	msg(_("Nothing to undo"));
    else {
	sort_strings((char_u **)ga.ga_data, ga.ga_len);

	msg_start();
	msg_puts_attr(_("number changes  when               saved"), HL_ATTR(HLF_T));
	for (i = 0; i < ga.ga_len && !got_int; ++i)
	{
	    msg_putchar('\n');
	    if (got_int)
		break;
	    msg_puts(((char **)ga.ga_data)[i]);
	}
	msg_end();

	ga_clear_strings(&ga);
    }
}


    void ex_undojoin(exarg_T *eap UNUSED)
{
    if (curbuf->b_u_newhead == NULL)
	return;		    
    if (curbuf->b_u_curhead != NULL)
    {
	emsg(_(e_undojoin_is_not_allowed_after_undo));
	return;
    }
    if (!curbuf->b_u_synced)
	return;		    
    if (get_undolevel() < 0)
	return;		    
    else  curbuf->b_u_synced = FALSE;

}


    void u_unchanged(buf_T *buf)
{
    u_unch_branch(buf->b_u_oldhead);
    buf->b_did_warn = FALSE;
}


    void u_find_first_changed(void)
{
    u_header_T	*uhp = curbuf->b_u_newhead;
    u_entry_T   *uep;
    linenr_T	lnum;

    if (curbuf->b_u_curhead != NULL || uhp == NULL)
	return;  

    
    uep = uhp->uh_entry;
    if (uep->ue_top != 0 || uep->ue_bot != 0)
	return;

    for (lnum = 1; lnum < curbuf->b_ml.ml_line_count && lnum <= uep->ue_size; ++lnum)
    {
	char_u *p = ml_get_buf(curbuf, lnum, FALSE);

	if (uep->ue_array[lnum - 1].ul_len != curbuf->b_ml.ml_line_len || memcmp(p, uep->ue_array[lnum - 1].ul_line, uep->ue_array[lnum - 1].ul_len) != 0)
	{
	    CLEAR_POS(&(uhp->uh_cursor));
	    uhp->uh_cursor.lnum = lnum;
	    return;
	}
    }
    if (curbuf->b_ml.ml_line_count != uep->ue_size)
    {
	
	CLEAR_POS(&(uhp->uh_cursor));
	uhp->uh_cursor.lnum = lnum;
    }
}


    void u_update_save_nr(buf_T *buf)
{
    u_header_T	*uhp;

    ++buf->b_u_save_nr_last;
    buf->b_u_save_nr_cur = buf->b_u_save_nr_last;
    uhp = buf->b_u_curhead;
    if (uhp != NULL)
	uhp = uhp->uh_next.ptr;
    else uhp = buf->b_u_newhead;
    if (uhp != NULL)
	uhp->uh_save_nr = buf->b_u_save_nr_last;
}

    static void u_unch_branch(u_header_T *uhp)
{
    u_header_T	*uh;

    for (uh = uhp; uh != NULL; uh = uh->uh_prev.ptr)
    {
	uh->uh_flags |= UH_CHANGED;
	if (uh->uh_alt_next.ptr != NULL)
	    u_unch_branch(uh->uh_alt_next.ptr);	    
    }
}


    static u_entry_T * u_get_headentry(void)
{
    if (curbuf->b_u_newhead == NULL || curbuf->b_u_newhead->uh_entry == NULL)
    {
	iemsg(_(e_undo_list_corrupt));
	return NULL;
    }
    return curbuf->b_u_newhead->uh_entry;
}


    static void u_getbot(void)
{
    u_entry_T	*uep;
    linenr_T	extra;

    uep = u_get_headentry();	
    if (uep == NULL)
	return;

    uep = curbuf->b_u_newhead->uh_getbot_entry;
    if (uep != NULL)
    {
	
	extra = curbuf->b_ml.ml_line_count - uep->ue_lcount;
	uep->ue_bot = uep->ue_top + uep->ue_size + 1 + extra;
	if (uep->ue_bot < 1 || uep->ue_bot > curbuf->b_ml.ml_line_count)
	{
	    iemsg(_(e_undo_line_missing));
	    uep->ue_bot = uep->ue_top + 1;  
					    
					    
					    
	}

	curbuf->b_u_newhead->uh_getbot_entry = NULL;
    }

    curbuf->b_u_synced = TRUE;
}


    static void u_freeheader( buf_T	    *buf, u_header_T	    *uhp, u_header_T	    **uhpp)



{
    u_header_T	    *uhap;

    
    
    if (uhp->uh_alt_next.ptr != NULL)
	u_freebranch(buf, uhp->uh_alt_next.ptr, uhpp);

    if (uhp->uh_alt_prev.ptr != NULL)
	uhp->uh_alt_prev.ptr->uh_alt_next.ptr = NULL;

    
    if (uhp->uh_next.ptr == NULL)
	buf->b_u_oldhead = uhp->uh_prev.ptr;
    else uhp->uh_next.ptr->uh_prev.ptr = uhp->uh_prev.ptr;

    if (uhp->uh_prev.ptr == NULL)
	buf->b_u_newhead = uhp->uh_next.ptr;
    else for (uhap = uhp->uh_prev.ptr; uhap != NULL;
						 uhap = uhap->uh_alt_next.ptr)
	    uhap->uh_next.ptr = uhp->uh_next.ptr;

    u_freeentries(buf, uhp, uhpp);
}


    static void u_freebranch( buf_T	    *buf, u_header_T	    *uhp, u_header_T	    **uhpp)



{
    u_header_T	    *tofree, *next;

    
    
    if (uhp == buf->b_u_oldhead)
    {
	while (buf->b_u_oldhead != NULL)
	    u_freeheader(buf, buf->b_u_oldhead, uhpp);
	return;
    }

    if (uhp->uh_alt_prev.ptr != NULL)
	uhp->uh_alt_prev.ptr->uh_alt_next.ptr = NULL;

    next = uhp;
    while (next != NULL)
    {
	tofree = next;
	if (tofree->uh_alt_next.ptr != NULL)
	    u_freebranch(buf, tofree->uh_alt_next.ptr, uhpp);   
	next = tofree->uh_prev.ptr;
	u_freeentries(buf, tofree, uhpp);
    }
}


    static void u_freeentries( buf_T	    *buf, u_header_T	    *uhp, u_header_T	    **uhpp)



{
    u_entry_T	    *uep, *nuep;

    
    if (buf->b_u_curhead == uhp)
	buf->b_u_curhead = NULL;
    if (buf->b_u_newhead == uhp)
	buf->b_u_newhead = NULL;  
    if (uhpp != NULL && uhp == *uhpp)
	*uhpp = NULL;

    for (uep = uhp->uh_entry; uep != NULL; uep = nuep)
    {
	nuep = uep->ue_next;
	u_freeentry(uep, uep->ue_size);
    }


    uhp->uh_magic = 0;

    vim_free((char_u *)uhp);
    --buf->b_u_numhead;
}


    static void u_freeentry(u_entry_T *uep, long n)
{
    while (n > 0)
	vim_free(uep->ue_array[--n].ul_line);
    vim_free((char_u *)uep->ue_array);

    uep->ue_magic = 0;

    vim_free((char_u *)uep);
}


    void u_clearall(buf_T *buf)
{
    buf->b_u_newhead = buf->b_u_oldhead = buf->b_u_curhead = NULL;
    buf->b_u_synced = TRUE;
    buf->b_u_numhead = 0;
    buf->b_u_line_ptr.ul_line = NULL;
    buf->b_u_line_ptr.ul_len = 0;
    buf->b_u_line_lnum = 0;
}


    static void u_saveline(linenr_T lnum)
{
    if (lnum == curbuf->b_u_line_lnum)	    
	return;
    if (lnum < 1 || lnum > curbuf->b_ml.ml_line_count) 
	return;
    u_clearline();
    curbuf->b_u_line_lnum = lnum;
    if (curwin->w_cursor.lnum == lnum)
	curbuf->b_u_line_colnr = curwin->w_cursor.col;
    else curbuf->b_u_line_colnr = 0;
    if (u_save_line(&curbuf->b_u_line_ptr, lnum) == FAIL)
	do_outofmem_msg((long_u)0);
}


    void u_clearline(void)
{
    if (curbuf->b_u_line_ptr.ul_line != NULL)
    {
	VIM_CLEAR(curbuf->b_u_line_ptr.ul_line);
	curbuf->b_u_line_ptr.ul_len = 0;
	curbuf->b_u_line_lnum = 0;
    }
}


    void u_undoline(void)
{
    colnr_T	t;
    undoline_T  oldp;

    if (undo_off)
	return;

    if (curbuf->b_u_line_ptr.ul_line == NULL || curbuf->b_u_line_lnum > curbuf->b_ml.ml_line_count)
    {
	beep_flush();
	return;
    }

    
    if (u_savecommon(curbuf->b_u_line_lnum - 1, curbuf->b_u_line_lnum + 1, (linenr_T)0, FALSE) == FAIL)
	return;
    if (u_save_line(&oldp, curbuf->b_u_line_lnum) == FAIL)
    {
	do_outofmem_msg((long_u)0);
	return;
    }
    ml_replace_len(curbuf->b_u_line_lnum, curbuf->b_u_line_ptr.ul_line, curbuf->b_u_line_ptr.ul_len, TRUE, FALSE);
    changed_bytes(curbuf->b_u_line_lnum, 0);
    curbuf->b_u_line_ptr = oldp;

    t = curbuf->b_u_line_colnr;
    if (curwin->w_cursor.lnum == curbuf->b_u_line_lnum)
	curbuf->b_u_line_colnr = curwin->w_cursor.col;
    curwin->w_cursor.col = t;
    curwin->w_cursor.lnum = curbuf->b_u_line_lnum;
    check_cursor_col();
}


    void u_blockfree(buf_T *buf)
{
    while (buf->b_u_oldhead != NULL)
	u_freeheader(buf, buf->b_u_oldhead, NULL);
    vim_free(buf->b_u_line_ptr.ul_line);
}


    int bufIsChanged(buf_T *buf)
{

    if (term_job_running(buf->b_term))
	return TRUE;

    return bufIsChangedNotTerm(buf);
}


    int anyBufIsChanged(void)
{
    buf_T *buf;

    FOR_ALL_BUFFERS(buf)
	if (bufIsChanged(buf))
	    return TRUE;
    return FALSE;
}


    int bufIsChangedNotTerm(buf_T *buf)
{
    
    
    return (!bt_dontwrite(buf) || bt_prompt(buf))
	&& (buf->b_changed || file_ff_differs(buf, TRUE));
}

    int curbufIsChanged(void)
{
    return bufIsChanged(curbuf);
}




    static void u_eval_tree(u_header_T *first_uhp, list_T *list)
{
    u_header_T  *uhp = first_uhp;
    dict_T	*dict;

    while (uhp != NULL)
    {
	dict = dict_alloc();
	if (dict == NULL)
	    return;
	dict_add_number(dict, "seq", uhp->uh_seq);
	dict_add_number(dict, "time", (long)uhp->uh_time);
	if (uhp == curbuf->b_u_newhead)
	    dict_add_number(dict, "newhead", 1);
	if (uhp == curbuf->b_u_curhead)
	    dict_add_number(dict, "curhead", 1);
	if (uhp->uh_save_nr > 0)
	    dict_add_number(dict, "save", uhp->uh_save_nr);

	if (uhp->uh_alt_next.ptr != NULL)
	{
	    list_T	*alt_list = list_alloc();

	    if (alt_list != NULL)
	    {
		
		u_eval_tree(uhp->uh_alt_next.ptr, alt_list);
		dict_add_list(dict, "alt", alt_list);
	    }
	}

	list_append_dict(list, dict);
	uhp = uhp->uh_prev.ptr;
    }
}


    void f_undofile(typval_T *argvars UNUSED, typval_T *rettv)
{
    if (in_vim9script() && check_for_string_arg(argvars, 0) == FAIL)
	return;

    rettv->v_type = VAR_STRING;

    {
	char_u *fname = tv_get_string(&argvars[0]);

	if (*fname == NUL)
	{
	    
	    rettv->vval.v_string = NULL;
	}
	else {
	    char_u *ffname = FullName_save(fname, TRUE);

	    if (ffname != NULL)
		rettv->vval.v_string = u_get_undo_file_name(ffname, FALSE);
	    vim_free(ffname);
	}
    }

    rettv->vval.v_string = NULL;

}


    void u_undofile_reset_and_delete(buf_T *buf)
{
    char_u *file_name;

    if (!buf->b_p_udf)
	return;

    file_name = u_get_undo_file_name(buf->b_ffname, TRUE);
    if (file_name != NULL)
    {
	mch_remove(file_name);
	vim_free(file_name);
    }

    set_option_value_give_err((char_u *)"undofile", 0L, NULL, OPT_LOCAL);
}
 #endif


    void f_undotree(typval_T *argvars UNUSED, typval_T *rettv)
{
    if (rettv_dict_alloc(rettv) == OK)
    {
	dict_T *dict = rettv->vval.v_dict;
	list_T *list;

	dict_add_number(dict, "synced", (long)curbuf->b_u_synced);
	dict_add_number(dict, "seq_last", curbuf->b_u_seq_last);
	dict_add_number(dict, "save_last", curbuf->b_u_save_nr_last);
	dict_add_number(dict, "seq_cur", curbuf->b_u_seq_cur);
	dict_add_number(dict, "time_cur", (long)curbuf->b_u_time_cur);
	dict_add_number(dict, "save_cur", curbuf->b_u_save_nr_cur);

	list = list_alloc();
	if (list != NULL)
	{
	    u_eval_tree(curbuf->b_u_oldhead, list);
	    dict_add_list(dict, "entries", list);
	}
    }
}


