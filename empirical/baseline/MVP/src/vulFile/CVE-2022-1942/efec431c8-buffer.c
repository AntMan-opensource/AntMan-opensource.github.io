













static void	enter_buffer(buf_T *buf);
static void	buflist_getfpos(void);
static char_u	*buflist_match(regmatch_T *rmp, buf_T *buf, int ignore_case);
static char_u	*fname_match(regmatch_T *rmp, char_u *name, int ignore_case);

static buf_T	*buflist_findname_stat(char_u *ffname, stat_T *st);
static int	otherfile_buf(buf_T *buf, char_u *ffname, stat_T *stp);
static int	buf_same_ino(buf_T *buf, stat_T *stp);

static int	otherfile_buf(buf_T *buf, char_u *ffname);

static int	value_changed(char_u *str, char_u **last);
static int	append_arg_number(win_T *wp, char_u *buf, int buflen, int add_file);
static void	free_buffer(buf_T *);
static void	free_buffer_stuff(buf_T *buf, int free_options);
static void	clear_wininfo(buf_T *buf);










static char *msg_loclist = N_("[Location List]");
static char *msg_qflist = N_("[Quickfix List]");



static int	buf_free_count = 0;

static int	top_file_num = 1;	
static garray_T buf_reuse = GA_EMPTY;	


    int get_highest_fnum(void)
{
    return top_file_num - 1;
}


    static int read_buffer( int		read_stdin, exarg_T	*eap, int		flags)



{
    int		retval = OK;
    linenr_T	line_count;

    
    
    
    line_count = curbuf->b_ml.ml_line_count;
    retval = readfile( read_stdin ? NULL : curbuf->b_ffname, read_stdin ? NULL : curbuf->b_fname, line_count, (linenr_T)0, (linenr_T)MAXLNUM, eap, flags | READ_BUFFER);



    if (retval == OK)
    {
	
	while (--line_count >= 0)
	    ml_delete((linenr_T)1);
    }
    else {
	
	while (curbuf->b_ml.ml_line_count > line_count)
	    ml_delete(line_count);
    }
    
    curwin->w_cursor.lnum = 1;
    curwin->w_cursor.col = 0;

    if (read_stdin)
    {
	
	
	if (!readonlymode && !BUFEMPTY())
	    changed();
	else if (retval == OK)
	    unchanged(curbuf, FALSE, TRUE);

	if (retval == OK)
	{

	    apply_autocmds_retval(EVENT_STDINREADPOST, NULL, NULL, FALSE, curbuf, &retval);

	    apply_autocmds(EVENT_STDINREADPOST, NULL, NULL, FALSE, curbuf);

	}
    }
    return retval;
}



    void buffer_ensure_loaded(buf_T *buf)
{
    if (buf->b_ml.ml_mfp == NULL)
    {
	aco_save_T	aco;

	aucmd_prepbuf(&aco, buf);
	if (swap_exists_action != SEA_READONLY)
	    swap_exists_action = SEA_NONE;
	open_buffer(FALSE, NULL, 0);
	aucmd_restbuf(&aco);
    }
}



    int open_buffer( int		read_stdin, exarg_T	*eap, int		flags)



{
    int		retval = OK;
    bufref_T	old_curbuf;

    long	old_tw = curbuf->b_p_tw;

    int		read_fifo = FALSE;

    
    
    
    if (readonlymode && curbuf->b_ffname != NULL && (curbuf->b_flags & BF_NEVERLOADED))
	curbuf->b_p_ro = TRUE;

    if (ml_open(curbuf) == FAIL)
    {
	
	
	close_buffer(NULL, curbuf, 0, FALSE, FALSE);
	FOR_ALL_BUFFERS(curbuf)
	    if (curbuf->b_ml.ml_mfp != NULL)
		break;
	
	
	if (curbuf == NULL)
	{
	    emsg(_(e_cannot_allocate_any_buffer_exiting));

	    
	    
	    v_dying = 2;
	    getout(2);
	}

	emsg(_(e_cannot_allocate_buffer_using_other_one));
	enter_buffer(curbuf);

	if (old_tw != curbuf->b_p_tw)
	    check_colorcolumn(curwin);

	return FAIL;
    }

    
    
    set_bufref(&old_curbuf, curbuf);
    modified_was_set = FALSE;

    
    curwin->w_valid = 0;

    if (curbuf->b_ffname != NULL  && netbeansReadFile  )



    {
	int old_msg_silent = msg_silent;

	int save_bin = curbuf->b_p_bin;
	int perm;


	int oldFire = netbeansFireChanges;

	netbeansFireChanges = 0;


	perm = mch_getperm(curbuf->b_ffname);
	if (perm >= 0 && (S_ISFIFO(perm)
		      || S_ISSOCK(perm)

		      || (S_ISCHR(perm) && is_dev_fd_file(curbuf->b_ffname))

		    ))
		read_fifo = TRUE;
	if (read_fifo)
	    curbuf->b_p_bin = TRUE;

	if (shortmess(SHM_FILEINFO))
	    msg_silent = 1;
	retval = readfile(curbuf->b_ffname, curbuf->b_fname, (linenr_T)0, (linenr_T)0, (linenr_T)MAXLNUM, eap, flags | READ_NEW | (read_fifo ? READ_FIFO : 0));


	if (read_fifo)
	{
	    curbuf->b_p_bin = save_bin;
	    if (retval == OK)
		retval = read_buffer(FALSE, eap, flags);
	}

	msg_silent = old_msg_silent;

	netbeansFireChanges = oldFire;

	
	if (bt_help(curbuf))
	    fix_help_buffer();
    }
    else if (read_stdin)
    {
	int	save_bin = curbuf->b_p_bin;

	
	
	
	
	curbuf->b_p_bin = TRUE;
	retval = readfile(NULL, NULL, (linenr_T)0, (linenr_T)0, (linenr_T)MAXLNUM, NULL, flags | (READ_NEW + READ_STDIN));

	curbuf->b_p_bin = save_bin;
	if (retval == OK)
	    retval = read_buffer(TRUE, eap, flags);
    }

    
    if (curbuf->b_flags & BF_NEVERLOADED)
    {
	(void)buf_init_chartab(curbuf, FALSE);
	parse_cino(curbuf);
    }

    
    
    
    
    
    
    
    if ((got_int && vim_strchr(p_cpo, CPO_INTMOD) != NULL)
		|| modified_was_set	  || (aborting() && vim_strchr(p_cpo, CPO_INTMOD) != NULL)


       )
	changed();
    else if (retval == OK && !read_stdin && !read_fifo)
	unchanged(curbuf, FALSE, TRUE);
    save_file_ff(curbuf);		

    
    
    curbuf->b_last_changedtick = CHANGEDTICK(curbuf);
    curbuf->b_last_changedtick_i = CHANGEDTICK(curbuf);
    curbuf->b_last_changedtick_pum = CHANGEDTICK(curbuf);

    

    if (aborting())

    if (got_int)

	curbuf->b_flags |= BF_READERR;


    
    
    foldUpdateAll(curwin);


    
    if (!(curwin->w_valid & VALID_TOPLINE))
    {
	curwin->w_topline = 1;

	curwin->w_topfill = 0;

    }

    apply_autocmds_retval(EVENT_BUFENTER, NULL, NULL, FALSE, curbuf, &retval);

    apply_autocmds(EVENT_BUFENTER, NULL, NULL, FALSE, curbuf);


    if (retval == OK)
    {
	
	
	if (bufref_valid(&old_curbuf) && old_curbuf.br_buf->b_ml.ml_mfp != NULL)
	{
	    aco_save_T	aco;

	    
	    aucmd_prepbuf(&aco, old_curbuf.br_buf);
	    do_modelines(0);
	    curbuf->b_flags &= ~(BF_CHECK_RO | BF_NEVERLOADED);

	    if ((flags & READ_NOWINENTER) == 0)

		apply_autocmds_retval(EVENT_BUFWINENTER, NULL, NULL, FALSE, curbuf, &retval);

		apply_autocmds(EVENT_BUFWINENTER, NULL, NULL, FALSE, curbuf);


	    
	    aucmd_restbuf(&aco);
	}
    }

    return retval;
}


    void set_bufref(bufref_T *bufref, buf_T *buf)
{
    bufref->br_buf = buf;
    bufref->br_fnum = buf == NULL ? 0 : buf->b_fnum;
    bufref->br_buf_free_count = buf_free_count;
}


    int bufref_valid(bufref_T *bufref)
{
    return bufref->br_buf_free_count == buf_free_count ? TRUE : buf_valid(bufref->br_buf)
				  && bufref->br_fnum == bufref->br_buf->b_fnum;
}


    int buf_valid(buf_T *buf)
{
    buf_T	*bp;

    
    
    FOR_ALL_BUFS_FROM_LAST(bp)
	if (bp == buf)
	    return TRUE;
    return FALSE;
}


static hashtab_T buf_hashtab;

    static void buf_hashtab_add(buf_T *buf)
{
    sprintf((char *)buf->b_key, "%x", buf->b_fnum);
    if (hash_add(&buf_hashtab, buf->b_key) == FAIL)
	emsg(_(e_buffer_cannot_be_registered));
}

    static void buf_hashtab_remove(buf_T *buf)
{
    hashitem_T *hi = hash_find(&buf_hashtab, buf->b_key);

    if (!HASHITEM_EMPTY(hi))
	hash_remove(&buf_hashtab, hi);
}


    static int can_unload_buffer(buf_T *buf)
{
    int	    can_unload = !buf->b_locked;

    if (can_unload && updating_screen)
    {
	win_T	*wp;

	FOR_ALL_WINDOWS(wp)
	    if (wp->w_buffer == buf)
	    {
		can_unload = FALSE;
		break;
	    }
    }
    if (!can_unload)
	semsg(_(e_attempt_to_delete_buffer_that_is_in_use_str), buf->b_fname);
    return can_unload;
}


    int close_buffer( win_T	*win, buf_T	*buf, int		action, int		abort_if_last, int		ignore_abort)





{
    int		is_curbuf;
    int		nwindows;
    bufref_T	bufref;
    int		is_curwin = (curwin != NULL && curwin->w_buffer == buf);
    win_T	*the_curwin = curwin;
    tabpage_T	*the_curtab = curtab;
    int		unload_buf = (action != 0);
    int		wipe_buf = (action == DOBUF_WIPE || action == DOBUF_WIPE_REUSE);
    int		del_buf = (action == DOBUF_DEL || wipe_buf);

    CHECK_CURBUF;

    
    
    
    if (buf->b_p_bh[0] == 'd')		
    {
	del_buf = TRUE;
	unload_buf = TRUE;
    }
    else if (buf->b_p_bh[0] == 'w')	
    {
	del_buf = TRUE;
	unload_buf = TRUE;
	wipe_buf = TRUE;
    }
    else if (buf->b_p_bh[0] == 'u')	
	unload_buf = TRUE;


    if (bt_terminal(buf) && (buf->b_nwindows == 1 || del_buf))
    {
	CHECK_CURBUF;
	if (term_job_running(buf->b_term))
	{
	    if (wipe_buf || unload_buf)
	    {
		if (!can_unload_buffer(buf))
		    return FALSE;

		
		free_terminal(buf);
	    }
	    else {
		
		del_buf = FALSE;
		unload_buf = FALSE;
	    }
	}
	else if (buf->b_p_bh[0] == 'h' && !del_buf)
	{
	    
	    unload_buf = FALSE;
	}
	else {
	    
	    del_buf = TRUE;
	    unload_buf = TRUE;
	    wipe_buf = TRUE;
	}
	CHECK_CURBUF;
    }


    
    
    if ((del_buf || wipe_buf) && !can_unload_buffer(buf))
	return FALSE;

    
    if (win != NULL && win_valid_any_tab(win))
    {
	
	
	
	
	if (buf->b_nwindows == 1)
	    set_last_cursor(win);
	buflist_setfpos(buf, win, win->w_cursor.lnum == 1 ? 0 : win->w_cursor.lnum, win->w_cursor.col, TRUE);

    }

    set_bufref(&bufref, buf);

    
    if (buf->b_nwindows == 1)
    {
	++buf->b_locked;
	++buf->b_locked_split;
	if (apply_autocmds(EVENT_BUFWINLEAVE, buf->b_fname, buf->b_fname, FALSE, buf)
		&& !bufref_valid(&bufref))
	{
	    
aucmd_abort:
	    emsg(_(e_autocommands_caused_command_to_abort));
	    return FALSE;
	}
	--buf->b_locked;
	--buf->b_locked_split;
	if (abort_if_last && one_window())
	    
	    goto aucmd_abort;

	
	
	if (!unload_buf)
	{
	    ++buf->b_locked;
	    ++buf->b_locked_split;
	    if (apply_autocmds(EVENT_BUFHIDDEN, buf->b_fname, buf->b_fname, FALSE, buf)
		    && !bufref_valid(&bufref))
		
		goto aucmd_abort;
	    --buf->b_locked;
	    --buf->b_locked_split;
	    if (abort_if_last && one_window())
		
		goto aucmd_abort;
	}

	
	if (!ignore_abort && aborting())
	    return FALSE;

    }

    
    
    
    if (is_curwin && curwin != the_curwin &&  win_valid_any_tab(the_curwin))
    {
	block_autocmds();
	goto_tabpage_win(the_curtab, the_curwin);
	unblock_autocmds();
    }

    nwindows = buf->b_nwindows;

    
    if (buf->b_nwindows > 0)
	--buf->b_nwindows;


    if (diffopt_hiddenoff() && !unload_buf && buf->b_nwindows == 0)
	diff_buf_delete(buf);	


    
    
    if (buf->b_nwindows > 0 || !unload_buf)
	return FALSE;

    
    if (buf->b_ffname == NULL)
	del_buf = TRUE;

    
    
    if (buf == curbuf && VIsual_active  && !entered_free_all_mem  )



	end_visual_mode();

    
    
    
    
    
    is_curbuf = (buf == curbuf);
    buf->b_nwindows = nwindows;

    buf_freeall(buf, (del_buf ? BFA_DEL : 0)
		   + (wipe_buf ? BFA_WIPE : 0)
		   + (ignore_abort ? BFA_IGNORE_ABORT : 0));

    
    if (!bufref_valid(&bufref))
	return FALSE;

    
    if (!ignore_abort && aborting())
	return FALSE;


    
    
    
    
    
    if (buf == curbuf && !is_curbuf)
	return FALSE;

    if (win_valid_any_tab(win) && win->w_buffer == buf)
	win->w_buffer = NULL;  

    
    
    if (buf->b_nwindows > 0)
	--buf->b_nwindows;

    
    if (wipe_buf)
    {
	
	if (buf->b_nwindows > 0)
	    return FALSE;

	if (action == DOBUF_WIPE_REUSE)
	{
	    
	    if (buf_reuse.ga_itemsize == 0)
		ga_init2(&buf_reuse, sizeof(int), 50);
	    if (ga_grow(&buf_reuse, 1) == OK)
		((int *)buf_reuse.ga_data)[buf_reuse.ga_len++] = buf->b_fnum;
	}
	if (buf->b_sfname != buf->b_ffname)
	    VIM_CLEAR(buf->b_sfname);
	else buf->b_sfname = NULL;
	VIM_CLEAR(buf->b_ffname);
	if (buf->b_prev == NULL)
	    firstbuf = buf->b_next;
	else buf->b_prev->b_next = buf->b_next;
	if (buf->b_next == NULL)
	    lastbuf = buf->b_prev;
	else buf->b_next->b_prev = buf->b_prev;
	free_buffer(buf);
    }
    else {
	if (del_buf)
	{
	    
	    
	    free_buffer_stuff(buf, TRUE);

	    
	    buf->b_flags = BF_CHECK_RO | BF_NEVERLOADED;

	    
	    buf->b_p_initialized = FALSE;
	}
	buf_clear_file(buf);
	if (del_buf)
	    buf->b_p_bl = FALSE;
    }
    
    return TRUE;
}


    void buf_clear_file(buf_T *buf)
{
    buf->b_ml.ml_line_count = 1;
    unchanged(buf, TRUE, TRUE);
    buf->b_shortname = FALSE;
    buf->b_p_eol = TRUE;
    buf->b_start_eol = TRUE;
    buf->b_p_bomb = FALSE;
    buf->b_start_bomb = FALSE;
    buf->b_ml.ml_mfp = NULL;
    buf->b_ml.ml_flags = ML_EMPTY;		

    netbeans_deleted_all_lines(buf);

}


    void buf_freeall(buf_T *buf, int flags)
{
    int		is_curbuf = (buf == curbuf);
    bufref_T	bufref;
    int		is_curwin = (curwin != NULL && curwin->w_buffer == buf);
    win_T	*the_curwin = curwin;
    tabpage_T	*the_curtab = curtab;

    
    ++buf->b_locked;
    ++buf->b_locked_split;
    set_bufref(&bufref, buf);
    if (buf->b_ml.ml_mfp != NULL)
    {
	if (apply_autocmds(EVENT_BUFUNLOAD, buf->b_fname, buf->b_fname, FALSE, buf)
		&& !bufref_valid(&bufref))
	    
	    return;
    }
    if ((flags & BFA_DEL) && buf->b_p_bl)
    {
	if (apply_autocmds(EVENT_BUFDELETE, buf->b_fname, buf->b_fname, FALSE, buf)
		&& !bufref_valid(&bufref))
	    
	    return;
    }
    if (flags & BFA_WIPE)
    {
	if (apply_autocmds(EVENT_BUFWIPEOUT, buf->b_fname, buf->b_fname, FALSE, buf)
		&& !bufref_valid(&bufref))
	    
	    return;
    }
    --buf->b_locked;
    --buf->b_locked_split;

    
    
    
    if (is_curwin && curwin != the_curwin &&  win_valid_any_tab(the_curwin))
    {
	block_autocmds();
	goto_tabpage_win(the_curtab, the_curwin);
	unblock_autocmds();
    }


    
    if ((flags & BFA_IGNORE_ABORT) == 0 && aborting())
	return;


    
    
    
    
    if (buf == curbuf && !is_curbuf)
	return;

    diff_buf_delete(buf);	    


    
    if (curwin != NULL && curwin->w_buffer == buf)
	reset_synblock(curwin);



    
    {
	win_T		*win;
	tabpage_T	*tp;

	FOR_ALL_TAB_WINDOWS(tp, win)
	    if (win->w_buffer == buf)
		clearFolding(win);
    }



    tcl_buffer_free(buf);

    ml_close(buf, TRUE);	    
    buf->b_ml.ml_line_count = 0;    
    if ((flags & BFA_KEEP_UNDO) == 0)
    {
	u_blockfree(buf);	    
	u_clearall(buf);	    
    }

    syntax_clear(&buf->b_s);	    


    clear_buf_prop_types(buf);

    buf->b_flags &= ~BF_READERR;    
}


    static void free_buffer(buf_T *buf)
{
    ++buf_free_count;
    free_buffer_stuff(buf, TRUE);

    
    dictitem_remove(buf->b_vars, (dictitem_T *)&buf->b_ct_di);
    unref_var_dict(buf->b_vars);
    remove_listeners(buf);


    lua_buffer_free(buf);


    mzscheme_buffer_free(buf);


    perl_buf_free(buf);


    python_buffer_free(buf);


    python3_buffer_free(buf);


    ruby_buffer_free(buf);


    channel_buffer_free(buf);


    free_terminal(buf);


    vim_free(buf->b_prompt_text);
    free_callback(&buf->b_prompt_callback);
    free_callback(&buf->b_prompt_interrupt);


    buf_hashtab_remove(buf);

    aubuflocal_remove(buf);

    if (autocmd_busy)
    {
	
	
	buf->b_next = au_pending_free_buf;
	au_pending_free_buf = buf;
    }
    else {
	vim_free(buf);
	if (curbuf == buf)
	    curbuf = NULL;  
    }
}


    static void init_changedtick(buf_T *buf)
{
    dictitem_T *di = (dictitem_T *)&buf->b_ct_di;

    di->di_flags = DI_FLAGS_FIX | DI_FLAGS_RO;
    di->di_tv.v_type = VAR_NUMBER;
    di->di_tv.v_lock = VAR_FIXED;
    di->di_tv.vval.v_number = 0;


    STRCPY(buf->b_ct_di.di_key, "changedtick");
    (void)dict_add(buf->b_vars, di);

}


    static void free_buffer_stuff( buf_T	*buf, int		free_options)


{
    if (free_options)
    {
	clear_wininfo(buf);		
	free_buf_options(buf, TRUE);

	ga_clear(&buf->b_s.b_langp);

    }

    {
	varnumber_T tick = CHANGEDTICK(buf);

	vars_clear(&buf->b_vars->dv_hashtab); 
	hash_init(&buf->b_vars->dv_hashtab);
	init_changedtick(buf);
	CHANGEDTICK(buf) = tick;
	remove_listeners(buf);
    }

    uc_clear(&buf->b_ucmds);		

    buf_delete_signs(buf, (char_u *)"*");	


    netbeans_file_killed(buf);

    map_clear_int(buf, MAP_ALL_MODES, TRUE, FALSE);  
    map_clear_int(buf, MAP_ALL_MODES, TRUE, TRUE);   
    VIM_CLEAR(buf->b_start_fenc);
}


    void free_wininfo(wininfo_T *wip)
{
    if (wip->wi_optset)
    {
	clear_winopt(&wip->wi_opt);

	deleteFoldRecurse(&wip->wi_folds);

    }
    vim_free(wip);
}


    static void clear_wininfo(buf_T *buf)
{
    wininfo_T	*wip;

    while (buf->b_wininfo != NULL)
    {
	wip = buf->b_wininfo;
	buf->b_wininfo = wip->wi_next;
	free_wininfo(wip);
    }
}


    void goto_buffer( exarg_T	*eap, int		start, int		dir, int		count)




{
    bufref_T	old_curbuf;
    int		save_sea = swap_exists_action;

    set_bufref(&old_curbuf, curbuf);

    if (swap_exists_action == SEA_NONE)
	swap_exists_action = SEA_DIALOG;
    (void)do_buffer(*eap->cmd == 's' ? DOBUF_SPLIT : DOBUF_GOTO, start, dir, count, eap->forceit);
    if (swap_exists_action == SEA_QUIT && *eap->cmd == 's')
    {

	cleanup_T   cs;

	
	
	enter_cleanup(&cs);


	
	win_close(curwin, TRUE);
	swap_exists_action = save_sea;
	swap_exists_did_quit = TRUE;


	
	
	leave_cleanup(&cs);

    }
    else handle_swap_exists(&old_curbuf);
}


    void handle_swap_exists(bufref_T *old_curbuf)
{

    cleanup_T	cs;


    long	old_tw = curbuf->b_p_tw;

    buf_T	*buf;

    if (swap_exists_action == SEA_QUIT)
    {

	
	
	enter_cleanup(&cs);


	
	
	
	swap_exists_action = SEA_NONE;	
	swap_exists_did_quit = TRUE;
	close_buffer(curwin, curbuf, DOBUF_UNLOAD, FALSE, FALSE);
	if (old_curbuf == NULL || !bufref_valid(old_curbuf)
					      || old_curbuf->br_buf == curbuf)
	{
	    
	    block_autocmds();
	    buf = buflist_new(NULL, NULL, 1L, BLN_CURBUF | BLN_LISTED);
	    unblock_autocmds();
	}
	else buf = old_curbuf->br_buf;
	if (buf != NULL)
	{
	    int old_msg_silent = msg_silent;

	    if (shortmess(SHM_FILEINFO))
		msg_silent = 1;  
	    enter_buffer(buf);
	    
	    msg_silent = old_msg_silent;


	    if (old_tw != curbuf->b_p_tw)
		check_colorcolumn(curwin);

	}
	


	
	
	leave_cleanup(&cs);

    }
    else if (swap_exists_action == SEA_RECOVER)
    {

	
	
	enter_cleanup(&cs);


	
	msg_scroll = TRUE;
	ml_recover(FALSE);
	msg_puts("\n");	
	cmdline_row = msg_row;
	do_modelines(0);


	
	
	leave_cleanup(&cs);

    }
    swap_exists_action = SEA_NONE;
}


    static int empty_curbuf( int close_others, int forceit, int action)



{
    int	    retval;
    buf_T   *buf = curbuf;
    bufref_T bufref;

    if (action == DOBUF_UNLOAD)
    {
	emsg(_(e_cannot_unload_last_buffer));
	return FAIL;
    }

    set_bufref(&bufref, buf);
    if (close_others)
	
	close_windows(buf, TRUE);

    setpcmark();
    retval = do_ecmd(0, NULL, NULL, NULL, ECMD_ONE, forceit ? ECMD_FORCEIT : 0, curwin);

    
    
    
    if (buf != curbuf && bufref_valid(&bufref) && buf->b_nwindows == 0)
	close_buffer(NULL, buf, action, FALSE, FALSE);
    if (!close_others)
	need_fileinfo = FALSE;
    return retval;
}


    static int do_buffer_ext( int		action, int		start, int		dir, int		count, int		flags)





{
    buf_T	*buf;
    buf_T	*bp;
    int		unload = (action == DOBUF_UNLOAD || action == DOBUF_DEL || action == DOBUF_WIPE || action == DOBUF_WIPE_REUSE);

    switch (start)
    {
	case DOBUF_FIRST:   buf = firstbuf; break;
	case DOBUF_LAST:    buf = lastbuf;  break;
	default:	    buf = curbuf;   break;
    }
    if (start == DOBUF_MOD)	    
    {
	while (count-- > 0)
	{
	    do {
		buf = buf->b_next;
		if (buf == NULL)
		    buf = firstbuf;
	    }
	    while (buf != curbuf && !bufIsChanged(buf));
	}
	if (!bufIsChanged(buf))
	{
	    emsg(_(e_no_modified_buffer_found));
	    return FAIL;
	}
    }
    else if (start == DOBUF_FIRST && count) 
    {
	while (buf != NULL && buf->b_fnum != count)
	    buf = buf->b_next;
    }
    else {
	bp = NULL;
	while (count > 0 || (!unload && !buf->b_p_bl && bp != buf))
	{
	    
	    
	    if (bp == NULL)
		bp = buf;
	    if (dir == FORWARD)
	    {
		buf = buf->b_next;
		if (buf == NULL)
		    buf = firstbuf;
	    }
	    else {
		buf = buf->b_prev;
		if (buf == NULL)
		    buf = lastbuf;
	    }
	    
	    if (unload || buf->b_p_bl)
	    {
		 --count;
		 bp = NULL;	
	    }
	    if (bp == buf)
	    {
		
		emsg(_(e_there_is_no_listed_buffer));
		return FAIL;
	    }
	}
    }

    if (buf == NULL)	    
    {
	if (start == DOBUF_FIRST)
	{
	    
	    if (!unload)
		semsg(_(e_buffer_nr_does_not_exist), count);
	}
	else if (dir == FORWARD)
	    emsg(_(e_cannot_go_beyond_last_buffer));
	else emsg(_(e_cannot_go_before_first_buffer));
	return FAIL;
    }

    if ((flags & DOBUF_NOPOPUP) && bt_popup(buf)

				&& !bt_terminal(buf)

       )
	return OK;



    need_mouse_correct = TRUE;


    
    if (unload)
    {
	int	forward;
	bufref_T bufref;

	if (!can_unload_buffer(buf))
	    return FAIL;

	set_bufref(&bufref, buf);

	
	
	if (action != DOBUF_WIPE && action != DOBUF_WIPE_REUSE && buf->b_ml.ml_mfp == NULL && !buf->b_p_bl)
	    return FAIL;

	if ((flags & DOBUF_FORCEIT) == 0 && bufIsChanged(buf))
	{

	    if ((p_confirm || (cmdmod.cmod_flags & CMOD_CONFIRM)) && p_write)
	    {
		dialog_changed(buf, FALSE);
		if (!bufref_valid(&bufref))
		    
		    
		    return FAIL;
		
		
		if (bufIsChanged(buf))
		    return FAIL;
	    }
	    else  {

		semsg(_(e_no_write_since_last_change_for_buffer_nr_add_bang_to_override), buf->b_fnum);
		return FAIL;
	    }
	}

	
	if (buf == curbuf && VIsual_active)
	    end_visual_mode();

	
	
	FOR_ALL_BUFFERS(bp)
	    if (bp->b_p_bl && bp != buf)
		break;
	if (bp == NULL && buf == curbuf)
	    return empty_curbuf(TRUE, (flags & DOBUF_FORCEIT), action);

	
	
	
	while (buf == curbuf && !(curwin->w_closing || curwin->w_buffer->b_locked > 0)
		   && (!ONE_WINDOW || first_tabpage->tp_next != NULL))
	{
	    if (win_close(curwin, FALSE) == FAIL)
		break;
	}

	
	if (buf != curbuf)
	{
	    close_windows(buf, FALSE);
	    if (buf != curbuf && bufref_valid(&bufref) && buf->b_nwindows <= 0)
		    close_buffer(NULL, buf, action, FALSE, FALSE);
	    return OK;
	}

	
	buf = NULL;	
	bp = NULL;	
	if (au_new_curbuf.br_buf != NULL && bufref_valid(&au_new_curbuf))
	    buf = au_new_curbuf.br_buf;
	else if (curwin->w_jumplistlen > 0)
	{
	    int     jumpidx;

	    jumpidx = curwin->w_jumplistidx - 1;
	    if (jumpidx < 0)
		jumpidx = curwin->w_jumplistlen - 1;

	    forward = jumpidx;
	    while (jumpidx != curwin->w_jumplistidx)
	    {
		buf = buflist_findnr(curwin->w_jumplist[jumpidx].fmark.fnum);
		if (buf != NULL)
		{
		    
		    
		    if (buf == curbuf || !buf->b_p_bl  || bt_quickfix(buf)


			    )
			buf = NULL;
		    else if (buf->b_ml.ml_mfp == NULL)
		    {
			
			if (bp == NULL)
			    bp = buf;
			buf = NULL;
		    }
		}
		if (buf != NULL)   
		    break;
		
		if (!jumpidx && curwin->w_jumplistidx == curwin->w_jumplistlen)
		    break;
		if (--jumpidx < 0)
		    jumpidx = curwin->w_jumplistlen - 1;
		if (jumpidx == forward)		
		    break;
	    }
	}

	if (buf == NULL)	
	{
	    forward = TRUE;
	    buf = curbuf->b_next;
	    for (;;)
	    {
		if (buf == NULL)
		{
		    if (!forward)	
			break;
		    buf = curbuf->b_prev;
		    forward = FALSE;
		    continue;
		}
		
		if (buf->b_help == curbuf->b_help && buf->b_p_bl  && !bt_quickfix(buf)


			   )
		{
		    if (buf->b_ml.ml_mfp != NULL)   
			break;
		    if (bp == NULL)	
			bp = buf;
		}
		if (forward)
		    buf = buf->b_next;
		else buf = buf->b_prev;
	    }
	}
	if (buf == NULL)	
	    buf = bp;
	if (buf == NULL)	
	{
	    FOR_ALL_BUFFERS(buf)
		if (buf->b_p_bl && buf != curbuf  && !bt_quickfix(buf)


		       )
		    break;
	}
	if (buf == NULL)	
	{
	    if (curbuf->b_next != NULL)
		buf = curbuf->b_next;
	    else buf = curbuf->b_prev;

	    if (bt_quickfix(buf))
		buf = NULL;

	}
    }

    if (buf == NULL)
    {
	
	
	return empty_curbuf(FALSE, (flags & DOBUF_FORCEIT), action);
    }

    
    if (action == DOBUF_SPLIT)	    
    {
	
	
	if ((swb_flags & SWB_USEOPEN) && buf_jump_open_win(buf))
	    return OK;
	
	
	if ((swb_flags & SWB_USETAB) && buf_jump_open_tab(buf))
	    return OK;
	if (win_split(0, 0) == FAIL)
	    return FAIL;
    }

    
    if (buf == curbuf)
	return OK;

    
    if (action == DOBUF_GOTO && !can_abandon(curbuf, (flags & DOBUF_FORCEIT)))
    {

	if ((p_confirm || (cmdmod.cmod_flags & CMOD_CONFIRM)) && p_write)
	{
	    bufref_T bufref;

	    set_bufref(&bufref, buf);
	    dialog_changed(curbuf, FALSE);
	    if (!bufref_valid(&bufref))
		
		return FAIL;
	}
	if (bufIsChanged(curbuf))

	{
	    no_write_message();
	    return FAIL;
	}
    }

    
    set_curbuf(buf, action);

    if (action == DOBUF_SPLIT)
	RESET_BINDING(curwin);	


    if (aborting())	    
	return FAIL;


    return OK;
}

    int do_buffer( int		action, int		start, int		dir, int		count, int		forceit)





{
    return do_buffer_ext(action, start, dir, count, forceit ? DOBUF_FORCEIT : 0);
}


    char * do_bufdel( int		command, char_u	*arg, int		addr_count, int		start_bnr, int		end_bnr, int		forceit)






{
    int		do_current = 0;	
    int		deleted = 0;	
    char	*errormsg = NULL; 
    int		bnr;		
    char_u	*p;

    if (addr_count == 0)
    {
	(void)do_buffer(command, DOBUF_CURRENT, FORWARD, 0, forceit);
    }
    else {
	if (addr_count == 2)
	{
	    if (*arg)		
		return ex_errmsg(e_trailing_characters_str, arg);
	    bnr = start_bnr;
	}
	else	 bnr = end_bnr;

	for ( ;!got_int; ui_breakcheck())
	{
	    
	    
	    
	    
	    if (bnr == curbuf->b_fnum)
		do_current = bnr;
	    else if (do_buffer_ext(command, DOBUF_FIRST, FORWARD, bnr, DOBUF_NOPOPUP | (forceit ? DOBUF_FORCEIT : 0)) == OK)
		++deleted;

	    
	    if (addr_count == 2)
	    {
		if (++bnr > end_bnr)
		    break;
	    }
	    else     {
		arg = skipwhite(arg);
		if (*arg == NUL)
		    break;
		if (!VIM_ISDIGIT(*arg))
		{
		    p = skiptowhite_esc(arg);
		    bnr = buflist_findpat(arg, p, command == DOBUF_WIPE || command == DOBUF_WIPE_REUSE, FALSE, FALSE);

		    if (bnr < 0)	    
			break;
		    arg = p;
		}
		else bnr = getdigits(&arg);
	    }
	}
	if (!got_int && do_current && do_buffer(command, DOBUF_FIRST, FORWARD, do_current, forceit) == OK)
	    ++deleted;

	if (deleted == 0)
	{
	    if (command == DOBUF_UNLOAD)
		STRCPY(IObuff, _(e_no_buffers_were_unloaded));
	    else if (command == DOBUF_DEL)
		STRCPY(IObuff, _(e_no_buffers_were_deleted));
	    else STRCPY(IObuff, _(e_no_buffers_were_wiped_out));
	    errormsg = (char *)IObuff;
	}
	else if (deleted >= p_report)
	{
	    if (command == DOBUF_UNLOAD)
		smsg(NGETTEXT("%d buffer unloaded", "%d buffers unloaded", deleted), deleted);
	    else if (command == DOBUF_DEL)
		smsg(NGETTEXT("%d buffer deleted", "%d buffers deleted", deleted), deleted);
	    else smsg(NGETTEXT("%d buffer wiped out", "%d buffers wiped out", deleted), deleted);

	}
    }


    return errormsg;
}


    void set_curbuf(buf_T *buf, int action)
{
    buf_T	*prevbuf;
    int		unload = (action == DOBUF_UNLOAD || action == DOBUF_DEL || action == DOBUF_WIPE || action == DOBUF_WIPE_REUSE);

    long	old_tw = curbuf->b_p_tw;

    bufref_T	newbufref;
    bufref_T	prevbufref;
    int		valid;

    setpcmark();
    if ((cmdmod.cmod_flags & CMOD_KEEPALT) == 0)
	curwin->w_alt_fnum = curbuf->b_fnum; 
    buflist_altfpos(curwin);			 

    
    VIsual_reselect = FALSE;

    
    prevbuf = curbuf;
    set_bufref(&prevbufref, prevbuf);
    set_bufref(&newbufref, buf);

    
    
    if (!apply_autocmds(EVENT_BUFLEAVE, NULL, NULL, FALSE, curbuf)
	    || (bufref_valid(&prevbufref)
		&& bufref_valid(&newbufref)

		&& !aborting()

	       ))
    {

	if (prevbuf == curwin->w_buffer)
	    reset_synblock(curwin);

	if (unload)
	    close_windows(prevbuf, FALSE);

	if (bufref_valid(&prevbufref) && !aborting())

	if (bufref_valid(&prevbufref))

	{
	    win_T  *previouswin = curwin;

	    
	    
	    
	    if (prevbuf == curbuf && ((State & MODE_INSERT) == 0 || curbuf->b_nwindows <= 1))
		u_sync(FALSE);
	    close_buffer(prevbuf == curwin->w_buffer ? curwin : NULL, prevbuf, unload ? action : (action == DOBUF_GOTO && !buf_hide(prevbuf)

			&& !bufIsChanged(prevbuf)) ? DOBUF_UNLOAD : 0, FALSE, FALSE);
	    if (curwin != previouswin && win_valid(previouswin))
	      
	      curwin = previouswin;
	}
    }
    
    
    
    valid = buf_valid(buf);
    if ((valid && buf != curbuf  && !aborting()


	) || curwin->w_buffer == NULL)
    {
	
	
	if (!valid)
	    enter_buffer(lastbuf);
	else enter_buffer(buf);

	if (old_tw != curbuf->b_p_tw)
	    check_colorcolumn(curwin);

    }
}


    static void enter_buffer(buf_T *buf)
{
    
    curwin->w_buffer = buf;
    curbuf = buf;
    ++curbuf->b_nwindows;

    
    buf_copy_options(buf, BCO_ENTER | BCO_NOHELP);
    if (!buf->b_help)
	get_winopts(buf);

    else  clearFolding(curwin);

    foldUpdateAll(curwin);	



    if (curwin->w_p_diff)
	diff_buf_add(curbuf);



    curwin->w_s = &(curbuf->b_s);


    
    curwin->w_cursor.lnum = 1;
    curwin->w_cursor.col = 0;
    curwin->w_cursor.coladd = 0;
    curwin->w_set_curswant = TRUE;
    curwin->w_topline_was_set = FALSE;

    
    curwin->w_valid = 0;

    buflist_setfpos(curbuf, curwin, curbuf->b_last_cursor.lnum, curbuf->b_last_cursor.col, TRUE);

    
    if (curbuf->b_ml.ml_mfp == NULL)	
    {
	
	
	
	if (*curbuf->b_p_ft == NUL)
	    did_filetype = FALSE;

	open_buffer(FALSE, NULL, 0);
    }
    else {
	if (!msg_silent && !shortmess(SHM_FILEINFO))
	    need_fileinfo = TRUE;	

	
	(void)buf_check_timestamp(curbuf, FALSE);

	curwin->w_topline = 1;

	curwin->w_topfill = 0;

	apply_autocmds(EVENT_BUFENTER, NULL, NULL, FALSE, curbuf);
	apply_autocmds(EVENT_BUFWINENTER, NULL, NULL, FALSE, curbuf);
    }

    
    
    if (curwin->w_cursor.lnum == 1 && inindent(0))
	buflist_getfpos();

    check_arg_idx(curwin);		
    maketitle();
	
    if (curwin->w_topline == 1 && !curwin->w_topline_was_set)
	scroll_cursor_halfway(FALSE);	


    
    netbeans_file_activated(curbuf);


    
    DO_AUTOCHDIR;


    if (curbuf->b_kmap_state & KEYMAP_INIT)
	(void)keymap_init();


    
    
    if (!curbuf->b_help && curwin->w_p_spell && *curwin->w_s->b_p_spl != NUL)
	(void)did_set_spelllang(curwin);


    curbuf->b_last_used = vim_time();


    redraw_later(NOT_VALID);
}



    void do_autochdir(void)
{
    if ((starting == 0 || test_autochdir)
	    && curbuf->b_ffname != NULL && vim_chdirfile(curbuf->b_ffname, "auto") == OK)
    {
	shorten_fnames(TRUE);
	last_chdir_reason = "autochdir";
    }
}


    void no_write_message(void)
{

    if (term_job_running(curbuf->b_term))
	emsg(_(e_job_still_running_add_bang_to_end_the_job));
    else  emsg(_(e_no_write_since_last_change_add_bang_to_override));

}

    void no_write_message_nobang(buf_T *buf UNUSED)
{

    if (term_job_running(buf->b_term))
	emsg(_(e_job_still_running));
    else  emsg(_(e_no_write_since_last_change));

}




    int curbuf_reusable(void)
{
    return (curbuf != NULL && curbuf->b_ffname == NULL && curbuf->b_nwindows <= 1 && (curbuf->b_ml.ml_mfp == NULL || BUFEMPTY())



	&& !bt_quickfix(curbuf)

	&& !curbufIsChanged());
}


    buf_T * buflist_new( char_u	*ffname_arg, char_u	*sfname_arg, linenr_T	lnum, int		flags)




{
    char_u	*ffname = ffname_arg;
    char_u	*sfname = sfname_arg;
    buf_T	*buf;

    stat_T	st;


    if (top_file_num == 1)
	hash_init(&buf_hashtab);

    fname_expand(curbuf, &ffname, &sfname);	

    

    
    
    if (sfname == NULL || mch_stat((char *)sfname, &st) < 0)
	st.st_dev = (dev_T)-1;

    if (ffname != NULL && !(flags & (BLN_DUMMY | BLN_NEW)) && (buf =  buflist_findname_stat(ffname, &st)


		buflist_findname(ffname)

		) != NULL)
    {
	vim_free(ffname);
	if (lnum != 0)
	    buflist_setfpos(buf, (flags & BLN_NOCURWIN) ? NULL : curwin, lnum, (colnr_T)0, FALSE);

	if ((flags & BLN_NOOPT) == 0)
	    
	    
	    buf_copy_options(buf, 0);

	if ((flags & BLN_LISTED) && !buf->b_p_bl)
	{
	    bufref_T bufref;

	    buf->b_p_bl = TRUE;
	    set_bufref(&bufref, buf);
	    if (!(flags & BLN_DUMMY))
	    {
		if (apply_autocmds(EVENT_BUFADD, NULL, NULL, FALSE, buf)
			&& !bufref_valid(&bufref))
		    return NULL;
	    }
	}
	return buf;
    }

    
    buf = NULL;
    if ((flags & BLN_CURBUF) && curbuf_reusable())
    {
	buf = curbuf;
	
	
	buf_freeall(buf, BFA_WIPE | BFA_DEL);
	if (buf != curbuf)   
	    return NULL;

	if (aborting())		
	{
	    vim_free(ffname);
	    return NULL;
	}

    }
    if (buf != curbuf || curbuf == NULL)
    {
	buf = ALLOC_CLEAR_ONE(buf_T);
	if (buf == NULL)
	{
	    vim_free(ffname);
	    return NULL;
	}

	
	buf->b_vars = dict_alloc_id(aid_newbuf_bvars);
	if (buf->b_vars == NULL)
	{
	    vim_free(ffname);
	    vim_free(buf);
	    return NULL;
	}
	init_var_dict(buf->b_vars, &buf->b_bufvar, VAR_SCOPE);

	init_changedtick(buf);
    }

    if (ffname != NULL)
    {
	buf->b_ffname = ffname;
	buf->b_sfname = vim_strsave(sfname);
    }

    clear_wininfo(buf);
    buf->b_wininfo = ALLOC_CLEAR_ONE(wininfo_T);

    if ((ffname != NULL && (buf->b_ffname == NULL || buf->b_sfname == NULL))
	    || buf->b_wininfo == NULL)
    {
	if (buf->b_sfname != buf->b_ffname)
	    VIM_CLEAR(buf->b_sfname);
	else buf->b_sfname = NULL;
	VIM_CLEAR(buf->b_ffname);
	if (buf != curbuf)
	    free_buffer(buf);
	return NULL;
    }

    if (buf == curbuf)
    {
	free_buffer_stuff(buf, FALSE);	

	
	buf->b_p_initialized = FALSE;
	buf_copy_options(buf, BCO_ENTER);


	
	curbuf->b_kmap_state |= KEYMAP_INIT;

    }
    else {
	
	buf->b_next = NULL;
	if (firstbuf == NULL)		
	{
	    buf->b_prev = NULL;
	    firstbuf = buf;
	}
	else				 {
	    lastbuf->b_next = buf;
	    buf->b_prev = lastbuf;
	}
	lastbuf = buf;

	if ((flags & BLN_REUSE) && buf_reuse.ga_len > 0)
	{
	    
	    
	    
	    --buf_reuse.ga_len;
	    buf->b_fnum = ((int *)buf_reuse.ga_data)[buf_reuse.ga_len];

	    
	    while (buf->b_prev != NULL && buf->b_fnum < buf->b_prev->b_fnum)
	    {
		buf_T	*prev = buf->b_prev;

		prev->b_next = buf->b_next;
		if (prev->b_next != NULL)
		    prev->b_next->b_prev = prev;
		buf->b_next = prev;
		buf->b_prev = prev->b_prev;
		if (buf->b_prev != NULL)
		    buf->b_prev->b_next = buf;
		prev->b_prev = buf;
		if (lastbuf == buf)
		    lastbuf = prev;
		if (firstbuf == prev)
		    firstbuf = buf;
	    }
	}
	else buf->b_fnum = top_file_num++;
	if (top_file_num < 0)		
	{
	    emsg(_("W14: Warning: List of file names overflow"));
	    if (emsg_silent == 0 && !in_assert_fails)
	    {
		out_flush();
		ui_delay(3001L, TRUE);	
	    }
	    top_file_num = 1;
	}
	buf_hashtab_add(buf);

	
	buf_copy_options(buf, BCO_ALWAYS);
    }

    buf->b_wininfo->wi_fpos.lnum = lnum;
    buf->b_wininfo->wi_win = curwin;


    hash_init(&buf->b_s.b_keywtab);
    hash_init(&buf->b_s.b_keywtab_ic);


    buf->b_fname = buf->b_sfname;

    if (st.st_dev == (dev_T)-1)
	buf->b_dev_valid = FALSE;
    else {
	buf->b_dev_valid = TRUE;
	buf->b_dev = st.st_dev;
	buf->b_ino = st.st_ino;
    }

    buf->b_u_synced = TRUE;
    buf->b_flags = BF_CHECK_RO | BF_NEVERLOADED;
    if (flags & BLN_DUMMY)
	buf->b_flags |= BF_DUMMY;
    buf_clear_file(buf);
    clrallmarks(buf);			
    fmarks_check_names(buf);		
    buf->b_p_bl = (flags & BLN_LISTED) ? TRUE : FALSE;	
    if (!(flags & BLN_DUMMY))
    {
	bufref_T bufref;

	
	
	
	set_bufref(&bufref, buf);
	if (apply_autocmds(EVENT_BUFNEW, NULL, NULL, FALSE, buf)
		&& !bufref_valid(&bufref))
	    return NULL;
	if (flags & BLN_LISTED)
	{
	    if (apply_autocmds(EVENT_BUFADD, NULL, NULL, FALSE, buf)
		    && !bufref_valid(&bufref))
		return NULL;
	}

	if (aborting())		
	    return NULL;

    }

    return buf;
}


    void free_buf_options( buf_T	*buf, int		free_p_ff)


{
    if (free_p_ff)
    {
	clear_string_option(&buf->b_p_fenc);
	clear_string_option(&buf->b_p_ff);
	clear_string_option(&buf->b_p_bh);
	clear_string_option(&buf->b_p_bt);
    }

    clear_string_option(&buf->b_p_def);
    clear_string_option(&buf->b_p_inc);

    clear_string_option(&buf->b_p_inex);



    clear_string_option(&buf->b_p_inde);
    clear_string_option(&buf->b_p_indk);


    clear_string_option(&buf->b_p_bexpr);


    clear_string_option(&buf->b_p_cm);

    clear_string_option(&buf->b_p_fp);

    clear_string_option(&buf->b_p_fex);



    if ((buf->b_p_key != NULL) && (*buf->b_p_key != NUL) && (crypt_get_method_nr(buf) == CRYPT_M_SOD))
	crypt_sodium_munlock(buf->b_p_key, STRLEN(buf->b_p_key));

    clear_string_option(&buf->b_p_key);

    clear_string_option(&buf->b_p_kp);
    clear_string_option(&buf->b_p_mps);
    clear_string_option(&buf->b_p_fo);
    clear_string_option(&buf->b_p_flp);
    clear_string_option(&buf->b_p_isk);

    clear_string_option(&buf->b_p_vsts);
    vim_free(buf->b_p_vsts_nopaste);
    buf->b_p_vsts_nopaste = NULL;
    VIM_CLEAR(buf->b_p_vsts_array);
    clear_string_option(&buf->b_p_vts);
    VIM_CLEAR(buf->b_p_vts_array);


    clear_string_option(&buf->b_p_keymap);
    keymap_clear(&buf->b_kmap_ga);
    ga_clear(&buf->b_kmap_ga);

    clear_string_option(&buf->b_p_com);

    clear_string_option(&buf->b_p_cms);

    clear_string_option(&buf->b_p_nf);

    clear_string_option(&buf->b_p_syn);
    clear_string_option(&buf->b_s.b_syn_isk);


    clear_string_option(&buf->b_s.b_p_spc);
    clear_string_option(&buf->b_s.b_p_spf);
    vim_regfree(buf->b_s.b_cap_prog);
    buf->b_s.b_cap_prog = NULL;
    clear_string_option(&buf->b_s.b_p_spl);
    clear_string_option(&buf->b_s.b_p_spo);


    clear_string_option(&buf->b_p_sua);

    clear_string_option(&buf->b_p_ft);
    clear_string_option(&buf->b_p_cink);
    clear_string_option(&buf->b_p_cino);
    clear_string_option(&buf->b_p_cinsd);
    clear_string_option(&buf->b_p_cinw);
    clear_string_option(&buf->b_p_cpt);

    clear_string_option(&buf->b_p_cfu);
    free_callback(&buf->b_cfu_cb);
    clear_string_option(&buf->b_p_ofu);
    free_callback(&buf->b_ofu_cb);
    clear_string_option(&buf->b_p_tsrfu);
    free_callback(&buf->b_tsrfu_cb);


    clear_string_option(&buf->b_p_gp);
    clear_string_option(&buf->b_p_mp);
    clear_string_option(&buf->b_p_efm);

    clear_string_option(&buf->b_p_ep);
    clear_string_option(&buf->b_p_path);
    clear_string_option(&buf->b_p_tags);
    clear_string_option(&buf->b_p_tc);

    clear_string_option(&buf->b_p_tfu);
    free_callback(&buf->b_tfu_cb);

    clear_string_option(&buf->b_p_dict);
    clear_string_option(&buf->b_p_tsr);

    clear_string_option(&buf->b_p_qe);

    buf->b_p_ar = -1;
    buf->b_p_ul = NO_LOCAL_UNDOLEVEL;
    clear_string_option(&buf->b_p_lw);
    clear_string_option(&buf->b_p_bkc);
    clear_string_option(&buf->b_p_menc);
}


    int buflist_getfile( int		n, linenr_T	lnum, int		options, int		forceit)




{
    buf_T	*buf;
    win_T	*wp = NULL;
    pos_T	*fpos;
    colnr_T	col;

    buf = buflist_findnr(n);
    if (buf == NULL)
    {
	if ((options & GETF_ALT) && n == 0)
	    emsg(_(e_no_alternate_file));
	else semsg(_(e_buffer_nr_not_found), n);
	return FAIL;
    }

    
    if (buf == curbuf)
	return OK;

    if (text_locked())
    {
	text_locked_msg();
	return FAIL;
    }
    if (curbuf_locked())
	return FAIL;

    
    if (lnum == 0)
    {
	fpos = buflist_findfpos(buf);
	lnum = fpos->lnum;
	col = fpos->col;
    }
    else col = 0;

    if (options & GETF_SWITCH)
    {
	
	
	if (swb_flags & SWB_USEOPEN)
	    wp = buf_jump_open_win(buf);

	
	
	if (wp == NULL && (swb_flags & SWB_USETAB))
	    wp = buf_jump_open_tab(buf);

	
	
	if (wp == NULL && (swb_flags & (SWB_VSPLIT | SWB_SPLIT | SWB_NEWTAB))
							       && !BUFEMPTY())
	{
	    if (swb_flags & SWB_NEWTAB)
		tabpage_new();
	    else if (win_split(0, (swb_flags & SWB_VSPLIT) ? WSP_VERT : 0)
								      == FAIL)
		return FAIL;
	    RESET_BINDING(curwin);
	}
    }

    ++RedrawingDisabled;
    if (GETFILE_SUCCESS(getfile(buf->b_fnum, NULL, NULL, (options & GETF_SETMARK), lnum, forceit)))
    {
	--RedrawingDisabled;

	
	if (!p_sol && col != 0)
	{
	    curwin->w_cursor.col = col;
	    check_cursor_col();
	    curwin->w_cursor.coladd = 0;
	    curwin->w_set_curswant = TRUE;
	}
	return OK;
    }
    --RedrawingDisabled;
    return FAIL;
}


    static void buflist_getfpos(void)
{
    pos_T	*fpos;

    fpos = buflist_findfpos(curbuf);

    curwin->w_cursor.lnum = fpos->lnum;
    check_cursor_lnum();

    if (p_sol)
	curwin->w_cursor.col = 0;
    else {
	curwin->w_cursor.col = fpos->col;
	check_cursor_col();
	curwin->w_cursor.coladd = 0;
	curwin->w_set_curswant = TRUE;
    }
}



    buf_T * buflist_findname_exp(char_u *fname)
{
    char_u	*ffname;
    buf_T	*buf = NULL;

    
    ffname = FullName_save(fname,  TRUE  FALSE  );





    if (ffname != NULL)
    {
	buf = buflist_findname(ffname);
	vim_free(ffname);
    }
    return buf;
}



    buf_T * buflist_findname(char_u *ffname)
{

    stat_T	st;

    if (mch_stat((char *)ffname, &st) < 0)
	st.st_dev = (dev_T)-1;
    return buflist_findname_stat(ffname, &st);
}


    static buf_T * buflist_findname_stat( char_u	*ffname, stat_T	*stp)


{

    buf_T	*buf;

    
    FOR_ALL_BUFS_FROM_LAST(buf)
	if ((buf->b_flags & BF_DUMMY) == 0 && !otherfile_buf(buf, ffname  , stp  ))



	    return buf;
    return NULL;
}


    int buflist_findpat( char_u	*pattern, char_u	*pattern_end, int		unlisted, int		diffmode UNUSED, int		curtab_only)





{
    buf_T	*buf;
    int		match = -1;
    int		find_listed;
    char_u	*pat;
    char_u	*patend;
    int		attempt;
    char_u	*p;
    int		toggledollar;

    
    if ((pattern_end == pattern + 1 && (*pattern == '%' || *pattern == '#'))
	    || (in_vim9script() && pattern_end == pattern + 2 && pattern[0] == '%' && pattern[1] == '%'))
    {
	if (*pattern == '#' || pattern_end == pattern + 2)
	    match = curwin->w_alt_fnum;
	else match = curbuf->b_fnum;

	if (diffmode && !diff_mode_buf(buflist_findnr(match)))
	    match = -1;

    }

    
    else {
	pat = file_pat_to_reg_pat(pattern, pattern_end, NULL, FALSE);
	if (pat == NULL)
	    return -1;
	patend = pat + STRLEN(pat) - 1;
	toggledollar = (patend > pat && *patend == '$');

	
	
	find_listed = TRUE;
	for (;;)
	{
	    for (attempt = 0; attempt <= 3; ++attempt)
	    {
		regmatch_T	regmatch;

		
		if (toggledollar)
		    *patend = (attempt < 2) ? NUL : '$'; 
		p = pat;
		if (*p == '^' && !(attempt & 1))	 
		    ++p;
		regmatch.regprog = vim_regcomp(p, magic_isset() ? RE_MAGIC : 0);

		FOR_ALL_BUFS_FROM_LAST(buf)
		{
		    if (regmatch.regprog == NULL)
		    {
			
			vim_free(pat);
			return -1;
		    }
		    if (buf->b_p_bl == find_listed  && (!diffmode || diff_mode_buf(buf))


			    && buflist_match(&regmatch, buf, FALSE) != NULL)
		    {
			if (curtab_only)
			{
			    
			    
			    win_T	*wp;

			    FOR_ALL_WINDOWS(wp)
				if (wp->w_buffer == buf)
				    break;
			    if (wp == NULL)
				continue;
			}
			if (match >= 0)		
			{
			    match = -2;
			    break;
			}
			match = buf->b_fnum;	
		    }
		}

		vim_regfree(regmatch.regprog);
		if (match >= 0)			
		    break;
	    }

	    
	    
	    if (!unlisted || !find_listed || match != -1)
		break;
	    find_listed = FALSE;
	}

	vim_free(pat);
    }

    if (match == -2)
	semsg(_(e_more_than_one_match_for_str), pattern);
    else if (match < 0)
	semsg(_(e_no_matching_buffer_for_str), pattern);
    return match;
}


typedef struct {
    buf_T   *buf;
    char_u  *match;
} bufmatch_T;



    int ExpandBufnames( char_u	*pat, int		*num_file, char_u	***file, int		options)




{
    int		count = 0;
    buf_T	*buf;
    int		round;
    char_u	*p;
    int		attempt;
    char_u	*patc = NULL;

    bufmatch_T	*matches = NULL;

    int		fuzzy;
    fuzmatch_str_T  *fuzmatch = NULL;

    *num_file = 0;		    
    *file = NULL;


    if ((options & BUF_DIFF_FILTER) && !curwin->w_p_diff)
	return FAIL;


    fuzzy = cmdline_fuzzy_complete(pat);

    
    
    if (!fuzzy)
    {
	if (*pat == '^')
	{
	    patc = alloc(STRLEN(pat) + 11);
	    if (patc == NULL)
		return FAIL;
	    STRCPY(patc, "\\(^\\|[\\/]\\)");
	    STRCPY(patc + 11, pat + 1);
	}
	else patc = pat;
    }

    
    
    for (attempt = 0; attempt <= (fuzzy ? 0 : 1); ++attempt)
    {
	regmatch_T	regmatch;
	int		score = 0;

	if (!fuzzy)
	{
	    if (attempt > 0 && patc == pat)
		break;	
	    regmatch.regprog = vim_regcomp(patc + attempt * 11, RE_MAGIC);
	}

	
	
	for (round = 1; round <= 2; ++round)
	{
	    count = 0;
	    FOR_ALL_BUFFERS(buf)
	    {
		if (!buf->b_p_bl)	
		    continue;

		if (options & BUF_DIFF_FILTER)
		    
		    
		    if (buf == curbuf || !diff_mode_buf(buf))
			continue;


		if (!fuzzy)
		{
		    if (regmatch.regprog == NULL)
		    {
			
			if (patc != pat)
			    vim_free(patc);
			return FAIL;
		    }
		    p = buflist_match(&regmatch, buf, p_wic);
		}
		else {
		    p = NULL;
		    
		    if ((score = fuzzy_match_str(buf->b_sfname, pat)) != 0)
			p = buf->b_sfname;
		    if (p == NULL)
		    {
			
			if ((score = fuzzy_match_str(buf->b_ffname, pat)) != 0)
			    p = buf->b_ffname;
		    }
		}

		if (p == NULL)
		    continue;

		if (round == 1)
		{
		    ++count;
		    continue;
		}

		if (options & WILD_HOME_REPLACE)
		    p = home_replace_save(buf, p);
		else p = vim_strsave(p);

		if (!fuzzy)
		{

		    if (matches != NULL)
		    {
			matches[count].buf = buf;
			matches[count].match = p;
			count++;
		    }
		    else  (*file)[count++] = p;

		}
		else {
		    fuzmatch[count].idx = count;
		    fuzmatch[count].str = p;
		    fuzmatch[count].score = score;
		    count++;
		}
	    }
	    if (count == 0)	
		break;
	    if (round == 1)
	    {
		if (!fuzzy)
		{
		    *file = ALLOC_MULT(char_u *, count);
		    if (*file == NULL)
		    {
			vim_regfree(regmatch.regprog);
			if (patc != pat)
			    vim_free(patc);
			return FAIL;
		    }

		    if (options & WILD_BUFLASTUSED)
			matches = ALLOC_MULT(bufmatch_T, count);

		}
		else {
		    fuzmatch = ALLOC_MULT(fuzmatch_str_T, count);
		    if (fuzmatch == NULL)
		    {
			*num_file = 0;
			*file = NULL;
			return FAIL;
		    }
		}
	    }
	}

	if (!fuzzy)
	{
	    vim_regfree(regmatch.regprog);
	    if (count)		
		break;
	}
    }

    if (!fuzzy && patc != pat)
	vim_free(patc);


    if (!fuzzy)
    {
	if (matches != NULL)
	{
	    int i;
	    if (count > 1)
		qsort(matches, count, sizeof(bufmatch_T), buf_compare);
	    
	    if (matches[0].buf == curbuf)
	    {
		for (i = 1; i < count; i++)
		    (*file)[i-1] = matches[i].match;
		(*file)[count-1] = matches[0].match;
	    }
	    else {
		for (i = 0; i < count; i++)
		    (*file)[i] = matches[i].match;
	    }
	    vim_free(matches);
	}
    }
    else {
	if (fuzzymatches_to_strmatches(fuzmatch, file, count, FALSE) == FAIL)
	    return FAIL;
    }


    *num_file = count;
    return (count == 0 ? FAIL : OK);
}


    static char_u * buflist_match( regmatch_T	*rmp, buf_T	*buf, int		ignore_case)



{
    char_u	*match;

    
    match = fname_match(rmp, buf->b_sfname, ignore_case);
    if (match == NULL && rmp->regprog != NULL)
	match = fname_match(rmp, buf->b_ffname, ignore_case);

    return match;
}


    static char_u * fname_match( regmatch_T	*rmp, char_u	*name, int		ignore_case)



{
    char_u	*match = NULL;
    char_u	*p;

    
    if (name != NULL && rmp->regprog != NULL)
    {
	
	rmp->rm_ic = p_fic || ignore_case;
	if (vim_regexec(rmp, name, (colnr_T)0))
	    match = name;
	else if (rmp->regprog != NULL)
	{
	    
	    p = home_replace_save(NULL, name);
	    if (p != NULL && vim_regexec(rmp, p, (colnr_T)0))
		match = name;
	    vim_free(p);
	}
    }

    return match;
}


    buf_T * buflist_findnr(int nr)
{
    char_u	key[VIM_SIZEOF_INT * 2 + 1];
    hashitem_T	*hi;

    if (nr == 0)
	nr = curwin->w_alt_fnum;
    sprintf((char *)key, "%x", nr);
    hi = hash_find(&buf_hashtab, key);

    if (!HASHITEM_EMPTY(hi))
	return (buf_T *)(hi->hi_key - ((unsigned)(curbuf->b_key - (char_u *)curbuf)));
    return NULL;
}


    char_u * buflist_nr2name( int		n, int		fullname, int		helptail)



{
    buf_T	*buf;

    buf = buflist_findnr(n);
    if (buf == NULL)
	return NULL;
    return home_replace_save(helptail ? buf : NULL, fullname ? buf->b_ffname : buf->b_fname);
}


    void buflist_setfpos( buf_T	*buf, win_T	*win, linenr_T	lnum, colnr_T	col, int		copy_options)





{
    wininfo_T	*wip;

    FOR_ALL_BUF_WININFO(buf, wip)
	if (wip->wi_win == win)
	    break;
    if (wip == NULL)
    {
	
	wip = ALLOC_CLEAR_ONE(wininfo_T);
	if (wip == NULL)
	    return;
	wip->wi_win = win;
	if (lnum == 0)		
	    lnum = 1;
    }
    else {
	
	if (wip->wi_prev)
	    wip->wi_prev->wi_next = wip->wi_next;
	else buf->b_wininfo = wip->wi_next;
	if (wip->wi_next)
	    wip->wi_next->wi_prev = wip->wi_prev;
	if (copy_options && wip->wi_optset)
	{
	    clear_winopt(&wip->wi_opt);

	    deleteFoldRecurse(&wip->wi_folds);

	}
    }
    if (lnum != 0)
    {
	wip->wi_fpos.lnum = lnum;
	wip->wi_fpos.col = col;
    }
    if (win != NULL)
	wip->wi_changelistidx = win->w_changelistidx;
    if (copy_options && win != NULL)
    {
	
	copy_winopt(&win->w_onebuf_opt, &wip->wi_opt);

	wip->wi_fold_manual = win->w_fold_manual;
	cloneFoldGrowArray(&win->w_folds, &wip->wi_folds);

	wip->wi_optset = TRUE;
    }

    
    wip->wi_next = buf->b_wininfo;
    buf->b_wininfo = wip;
    wip->wi_prev = NULL;
    if (wip->wi_next)
	wip->wi_next->wi_prev = wip;
}



    static int wininfo_other_tab_diff(wininfo_T *wip)
{
    win_T	*wp;

    if (wip->wi_opt.wo_diff)
    {
	FOR_ALL_WINDOWS(wp)
	    
	    
	    if (wip->wi_win == wp)
		return FALSE;
	return TRUE;
    }
    return FALSE;
}



    static wininfo_T * find_wininfo( buf_T	*buf, int		need_options, int		skip_diff_buffer UNUSED)



{
    wininfo_T	*wip;

    FOR_ALL_BUF_WININFO(buf, wip)
	if (wip->wi_win == curwin  && (!skip_diff_buffer || !wininfo_other_tab_diff(wip))



		&& (!need_options || wip->wi_optset))
	    break;

    
    
    
    
    
    if (wip == NULL)
    {

	if (skip_diff_buffer)
	{
	    FOR_ALL_BUF_WININFO(buf, wip)
		if (!wininfo_other_tab_diff(wip)
			&& (!need_options || wip->wi_optset || (wip->wi_win != NULL && wip->wi_win->w_buffer == buf)))

		    break;
	}
	else  wip = buf->b_wininfo;

    }
    return wip;
}


    void get_winopts(buf_T *buf)
{
    wininfo_T	*wip;

    clear_winopt(&curwin->w_onebuf_opt);

    clearFolding(curwin);


    wip = find_wininfo(buf, TRUE, TRUE);
    if (wip != NULL && wip->wi_win != NULL && wip->wi_win != curwin && wip->wi_win->w_buffer == buf)
    {
	
	
	win_T *wp = wip->wi_win;

	copy_winopt(&wp->w_onebuf_opt, &curwin->w_onebuf_opt);

	curwin->w_fold_manual = wp->w_fold_manual;
	curwin->w_foldinvalid = TRUE;
	cloneFoldGrowArray(&wp->w_folds, &curwin->w_folds);

    }
    else if (wip != NULL && wip->wi_optset)
    {
	
	copy_winopt(&wip->wi_opt, &curwin->w_onebuf_opt);

	curwin->w_fold_manual = wip->wi_fold_manual;
	curwin->w_foldinvalid = TRUE;
	cloneFoldGrowArray(&wip->wi_folds, &curwin->w_folds);

    }
    else copy_winopt(&curwin->w_allbuf_opt, &curwin->w_onebuf_opt);
    if (wip != NULL)
	curwin->w_changelistidx = wip->wi_changelistidx;


    
    if (p_fdls >= 0)
	curwin->w_p_fdl = p_fdls;

    after_copy_winopt(curwin);
}


    pos_T * buflist_findfpos(buf_T *buf)
{
    wininfo_T	*wip;
    static pos_T no_position = {1, 0, 0};

    wip = find_wininfo(buf, FALSE, FALSE);
    if (wip != NULL)
	return &(wip->wi_fpos);
    else return &no_position;
}


    linenr_T buflist_findlnum(buf_T *buf)
{
    return buflist_findfpos(buf)->lnum;
}


    void buflist_list(exarg_T *eap)
{
    buf_T	*buf = firstbuf;
    int		len;
    int		i;
    int		ro_char;
    int		changed_char;

    int		job_running;
    int		job_none_open;



    garray_T	buflist;
    buf_T	**buflist_data = NULL, **p;

    if (vim_strchr(eap->arg, 't'))
    {
	ga_init2(&buflist, sizeof(buf_T *), 50);
	FOR_ALL_BUFFERS(buf)
	{
	    if (ga_grow(&buflist, 1) == OK)
		((buf_T **)buflist.ga_data)[buflist.ga_len++] = buf;
	}

	qsort(buflist.ga_data, (size_t)buflist.ga_len, sizeof(buf_T *), buf_compare);

	buflist_data = (buf_T **)buflist.ga_data;
	buf = *buflist_data;
    }
    p = buflist_data;

    for (; buf != NULL && !got_int; buf = buflist_data != NULL ? (++p < buflist_data + buflist.ga_len ? *p : NULL)
	    : buf->b_next)

    for (buf = firstbuf; buf != NULL && !got_int; buf = buf->b_next)

    {

	job_running = term_job_running(buf->b_term);
	job_none_open = term_none_open(buf->b_term);

	
	if ((!buf->b_p_bl && !eap->forceit && !vim_strchr(eap->arg, 'u'))
		|| (vim_strchr(eap->arg, 'u') && buf->b_p_bl)
		|| (vim_strchr(eap->arg, '+')
			&& ((buf->b_flags & BF_READERR) || !bufIsChanged(buf)))
		|| (vim_strchr(eap->arg, 'a')
			&& (buf->b_ml.ml_mfp == NULL || buf->b_nwindows == 0))
		|| (vim_strchr(eap->arg, 'h')
			&& (buf->b_ml.ml_mfp == NULL || buf->b_nwindows != 0))

		|| (vim_strchr(eap->arg, 'R')
			&& (!job_running || (job_running && job_none_open)))
		|| (vim_strchr(eap->arg, '?')
			&& (!job_running || (job_running && !job_none_open)))
		|| (vim_strchr(eap->arg, 'F')
			&& (job_running || buf->b_term == NULL))

		|| (vim_strchr(eap->arg, '-') && buf->b_p_ma)
		|| (vim_strchr(eap->arg, '=') && !buf->b_p_ro)
		|| (vim_strchr(eap->arg, 'x') && !(buf->b_flags & BF_READERR))
		|| (vim_strchr(eap->arg, '%') && buf != curbuf)
		|| (vim_strchr(eap->arg, '#')
		      && (buf == curbuf || curwin->w_alt_fnum != buf->b_fnum)))
	    continue;
	if (buf_spname(buf) != NULL)
	    vim_strncpy(NameBuff, buf_spname(buf), MAXPATHL - 1);
	else home_replace(buf, buf->b_fname, NameBuff, MAXPATHL, TRUE);
	if (message_filtered(NameBuff))
	    continue;

	changed_char = (buf->b_flags & BF_READERR) ? 'x' : (bufIsChanged(buf) ? '+' : ' ');

	if (job_running)
	{
	    if (job_none_open)
		ro_char = '?';
	    else ro_char = 'R';
	    changed_char = ' ';  
				 
	}
	else if (buf->b_term != NULL)
	    ro_char = 'F';
	else  ro_char = !buf->b_p_ma ? '-' : (buf->b_p_ro ? '=' : ' ');


	msg_putchar('\n');
	len = vim_snprintf((char *)IObuff, IOSIZE - 20, "%3d%c%c%c%c%c \"%s\"", buf->b_fnum, buf->b_p_bl ? ' ' : 'u', buf == curbuf ? '%' :


			(curwin->w_alt_fnum == buf->b_fnum ? '#' : ' '), buf->b_ml.ml_mfp == NULL ? ' ' :
			(buf->b_nwindows == 0 ? 'h' : 'a'), ro_char, changed_char, NameBuff);


	if (len > IOSIZE - 20)
	    len = IOSIZE - 20;

	
	i = 40 - vim_strsize(IObuff);
	do IObuff[len++] = ' ';
	while (--i > 0 && len < IOSIZE - 18);

	if (vim_strchr(eap->arg, 't') && buf->b_last_used)
	    add_time(IObuff + len, (size_t)(IOSIZE - len), buf->b_last_used);
	else  vim_snprintf((char *)IObuff + len, (size_t)(IOSIZE - len), _("line %ld"), buf == curbuf ? curwin->w_cursor.lnum : (long)buflist_findlnum(buf));



	msg_outtrans(IObuff);
	out_flush();	    
	ui_breakcheck();
    }


    if (buflist_data)
	ga_clear(&buflist);

}


    int buflist_name_nr( int		fnum, char_u	**fname, linenr_T	*lnum)



{
    buf_T	*buf;

    buf = buflist_findnr(fnum);
    if (buf == NULL || buf->b_fname == NULL)
	return FAIL;

    *fname = buf->b_fname;
    *lnum = buflist_findlnum(buf);

    return OK;
}


    int setfname( buf_T	*buf, char_u	*ffname_arg, char_u	*sfname_arg, int		message)




{
    char_u	*ffname = ffname_arg;
    char_u	*sfname = sfname_arg;
    buf_T	*obuf = NULL;

    stat_T	st;


    if (ffname == NULL || *ffname == NUL)
    {
	
	if (buf->b_sfname != buf->b_ffname)
	    VIM_CLEAR(buf->b_sfname);
	else buf->b_sfname = NULL;
	VIM_CLEAR(buf->b_ffname);

	st.st_dev = (dev_T)-1;

    }
    else {
	fname_expand(buf, &ffname, &sfname); 
	if (ffname == NULL)		    
	    return FAIL;

	

	if (mch_stat((char *)ffname, &st) < 0)
	    st.st_dev = (dev_T)-1;

	if (!(buf->b_flags & BF_DUMMY))

	    obuf = buflist_findname_stat(ffname, &st);

	    obuf = buflist_findname(ffname);

	if (obuf != NULL && obuf != buf)
	{
	    win_T	*win;
	    tabpage_T   *tab;
	    int		in_use = FALSE;

	    
	    FOR_ALL_TAB_WINDOWS(tab, win)
		if (win->w_buffer == obuf)
		    in_use = TRUE;

	    
	    if (obuf->b_ml.ml_mfp != NULL || in_use)
	    {
		if (message)
		    emsg(_(e_buffer_with_this_name_already_exists));
		vim_free(ffname);
		return FAIL;
	    }
	    
	    close_buffer(NULL, obuf, DOBUF_WIPE, FALSE, FALSE);
	}
	sfname = vim_strsave(sfname);
	if (ffname == NULL || sfname == NULL)
	{
	    vim_free(sfname);
	    vim_free(ffname);
	    return FAIL;
	}

	fname_case(sfname, 0);    

	if (buf->b_sfname != buf->b_ffname)
	    vim_free(buf->b_sfname);
	vim_free(buf->b_ffname);
	buf->b_ffname = ffname;
	buf->b_sfname = sfname;
    }
    buf->b_fname = buf->b_sfname;

    if (st.st_dev == (dev_T)-1)
	buf->b_dev_valid = FALSE;
    else {
	buf->b_dev_valid = TRUE;
	buf->b_dev = st.st_dev;
	buf->b_ino = st.st_ino;
    }


    buf->b_shortname = FALSE;

    buf_name_changed(buf);
    return OK;
}


    void buf_set_name(int fnum, char_u *name)
{
    buf_T	*buf;

    buf = buflist_findnr(fnum);
    if (buf != NULL)
    {
	if (buf->b_sfname != buf->b_ffname)
	    vim_free(buf->b_sfname);
	vim_free(buf->b_ffname);
	buf->b_ffname = vim_strsave(name);
	buf->b_sfname = NULL;
	
	
	fname_expand(buf, &buf->b_ffname, &buf->b_sfname);
	buf->b_fname = buf->b_sfname;
    }
}


    void buf_name_changed(buf_T *buf)
{
    
    if (buf->b_ml.ml_mfp != NULL)
	ml_setname(buf);


    if (buf->b_term != NULL)
	term_clear_status_text(buf->b_term);


    if (curwin->w_buffer == buf)
	check_arg_idx(curwin);	
    maketitle();		
    status_redraw_all();	
    fmarks_check_names(buf);	
    ml_timestamp(buf);		
}


    buf_T * setaltfname( char_u	*ffname, char_u	*sfname, linenr_T	lnum)



{
    buf_T	*buf;

    
    buf = buflist_new(ffname, sfname, lnum, 0);
    if (buf != NULL && (cmdmod.cmod_flags & CMOD_KEEPALT) == 0)
	curwin->w_alt_fnum = buf->b_fnum;
    return buf;
}


    char_u  * getaltfname( int		errmsg)

{
    char_u	*fname;
    linenr_T	dummy;

    if (buflist_name_nr(0, &fname, &dummy) == FAIL)
    {
	if (errmsg)
	    emsg(_(e_no_alternate_file));
	return NULL;
    }
    return fname;
}


    int buflist_add(char_u *fname, int flags)
{
    buf_T	*buf;

    buf = buflist_new(fname, NULL, (linenr_T)0, flags);
    if (buf != NULL)
	return buf->b_fnum;
    return 0;
}



    void buflist_slash_adjust(void)
{
    buf_T	*bp;

    FOR_ALL_BUFFERS(bp)
    {
	if (bp->b_ffname != NULL)
	    slash_adjust(bp->b_ffname);
	if (bp->b_sfname != NULL)
	    slash_adjust(bp->b_sfname);
    }
}



    void buflist_altfpos(win_T *win)
{
    buflist_setfpos(curbuf, win, win->w_cursor.lnum, win->w_cursor.col, TRUE);
}


    int otherfile(char_u *ffname)
{
    return otherfile_buf(curbuf, ffname  , NULL  );



}

    static int otherfile_buf( buf_T		*buf, char_u		*ffname  , stat_T		*stp  )






{
    
    if (ffname == NULL || *ffname == NUL || buf->b_ffname == NULL)
	return TRUE;
    if (fnamecmp(ffname, buf->b_ffname) == 0)
	return FALSE;

    {
	stat_T	    st;

	
	if (stp == NULL)
	{
	    if (!buf->b_dev_valid || mch_stat((char *)ffname, &st) < 0)
		st.st_dev = (dev_T)-1;
	    stp = &st;
	}
	
	
	
	
	
	
	
	
	
	if (buf_same_ino(buf, stp))
	{
	    buf_setino(buf);
	    if (buf_same_ino(buf, stp))
		return FALSE;
	}
    }

    return TRUE;
}



    void buf_setino(buf_T *buf)
{
    stat_T	st;

    if (buf->b_fname != NULL && mch_stat((char *)buf->b_fname, &st) >= 0)
    {
	buf->b_dev_valid = TRUE;
	buf->b_dev = st.st_dev;
	buf->b_ino = st.st_ino;
    }
    else buf->b_dev_valid = FALSE;
}


    static int buf_same_ino( buf_T	*buf, stat_T	*stp)


{
    return (buf->b_dev_valid && stp->st_dev == buf->b_dev && stp->st_ino == buf->b_ino);

}



    void fileinfo( int fullname, int shorthelp, int	dont_truncate)



{
    char_u	*name;
    int		n;
    char	*p;
    char	*buffer;
    size_t	len;

    buffer = alloc(IOSIZE);
    if (buffer == NULL)
	return;

    if (fullname > 1)	    
    {
	vim_snprintf(buffer, IOSIZE, "buf %d: ", curbuf->b_fnum);
	p = buffer + STRLEN(buffer);
    }
    else p = buffer;

    *p++ = '"';
    if (buf_spname(curbuf) != NULL)
	vim_strncpy((char_u *)p, buf_spname(curbuf), IOSIZE - (p - buffer) - 1);
    else {
	if (!fullname && curbuf->b_fname != NULL)
	    name = curbuf->b_fname;
	else name = curbuf->b_ffname;
	home_replace(shorthelp ? curbuf : NULL, name, (char_u *)p, (int)(IOSIZE - (p - buffer)), TRUE);
    }

    vim_snprintf_add(buffer, IOSIZE, "\"%s%s%s%s%s%s", curbufIsChanged() ? (shortmess(SHM_MOD)
					  ?  " [+]" : _(" [Modified]")) : " ", (curbuf->b_flags & BF_NOTEDITED)

		    && !bt_dontwrite(curbuf)

					? _("[Not edited]") : "", (curbuf->b_flags & BF_NEW)

		    && !bt_dontwrite(curbuf)

					   ? new_file_message() : "", (curbuf->b_flags & BF_READERR) ? _("[Read errors]") : "", curbuf->b_p_ro ? (shortmess(SHM_RO) ? _("[RO]")

						      : _("[readonly]")) : "", (curbufIsChanged() || (curbuf->b_flags & BF_WRITE_MASK)
							  || curbuf->b_p_ro) ? " " : "");
    
    
    if (curwin->w_cursor.lnum > 1000000L)
	n = (int)(((long)curwin->w_cursor.lnum) / ((long)curbuf->b_ml.ml_line_count / 100L));
    else n = (int)(((long)curwin->w_cursor.lnum * 100L) / (long)curbuf->b_ml.ml_line_count);

    if (curbuf->b_ml.ml_flags & ML_EMPTY)
	vim_snprintf_add(buffer, IOSIZE, "%s", _(no_lines_msg));

    else if (p_ru)
	
	vim_snprintf_add(buffer, IOSIZE, NGETTEXT("%ld line --%d%%--", "%ld lines --%d%%--", curbuf->b_ml.ml_line_count), (long)curbuf->b_ml.ml_line_count, n);



    else {
	vim_snprintf_add(buffer, IOSIZE, _("line %ld of %ld --%d%%-- col "), (long)curwin->w_cursor.lnum, (long)curbuf->b_ml.ml_line_count, n);



	validate_virtcol();
	len = STRLEN(buffer);
	col_print((char_u *)buffer + len, IOSIZE - len, (int)curwin->w_cursor.col + 1, (int)curwin->w_virtcol + 1);
    }

    (void)append_arg_number(curwin, (char_u *)buffer, IOSIZE, !shortmess(SHM_FILE));

    if (dont_truncate)
    {
	
	
	msg_start();
	n = msg_scroll;
	msg_scroll = TRUE;
	msg(buffer);
	msg_scroll = n;
    }
    else {
	p = msg_trunc_attr(buffer, FALSE, 0);
	if (restart_edit != 0 || (msg_scrolled && !need_wait_return))
	    
	    
	    
	    
	    
	    set_keep_msg((char_u *)p, 0);
    }

    vim_free(buffer);
}

    void col_print( char_u  *buf, size_t  buflen, int	    col, int	    vcol)




{
    if (col == vcol)
	vim_snprintf((char *)buf, buflen, "%d", col);
    else vim_snprintf((char *)buf, buflen, "%d-%d", col, vcol);
}

static char_u *lasttitle = NULL;
static char_u *lasticon = NULL;


    void maketitle(void)
{
    char_u	*p;
    char_u	*title_str = NULL;
    char_u	*icon_str = NULL;
    int		maxlen = 0;
    int		len;
    int		mustset;
    char_u	buf[IOSIZE];
    int		off;

    if (!redrawing())
    {
	
	need_maketitle = TRUE;
	return;
    }

    need_maketitle = FALSE;
    if (!p_title && !p_icon && lasttitle == NULL && lasticon == NULL)
	return;  

    if (p_title)
    {
	if (p_titlelen > 0)
	{
	    maxlen = p_titlelen * Columns / 100;
	    if (maxlen < 10)
		maxlen = 10;
	}

	title_str = buf;
	if (*p_titlestring != NUL)
	{

	    if (stl_syntax & STL_IN_TITLE)
	    {
		int	use_sandbox = FALSE;
		int	called_emsg_before = called_emsg;


		use_sandbox = was_set_insecurely((char_u *)"titlestring", 0);

		build_stl_str_hl(curwin, title_str, sizeof(buf), p_titlestring, use_sandbox, 0, maxlen, NULL, NULL);

		if (called_emsg > called_emsg_before)
		    set_string_option_direct((char_u *)"titlestring", -1, (char_u *)"", OPT_FREE, SID_ERROR);
	    }
	    else  title_str = p_titlestring;

	}
	else {
	    




	    if (curbuf->b_fname == NULL)
		vim_strncpy(buf, (char_u *)_("[No Name]"), SPACE_FOR_FNAME);

	    else if (curbuf->b_term != NULL)
	    {
		vim_strncpy(buf, term_get_status_text(curbuf->b_term), SPACE_FOR_FNAME);
	    }

	    else {
		p = transstr(gettail(curbuf->b_fname));
		vim_strncpy(buf, p, SPACE_FOR_FNAME);
		vim_free(p);
	    }


	    if (curbuf->b_term == NULL)

		switch (bufIsChanged(curbuf)
			+ (curbuf->b_p_ro * 2)
			+ (!curbuf->b_p_ma * 4))
		{
		    case 1: STRCAT(buf, " +"); break;
		    case 2: STRCAT(buf, " ="); break;
		    case 3: STRCAT(buf, " =+"); break;
		    case 4:
		    case 6: STRCAT(buf, " -"); break;
		    case 5:
		    case 7: STRCAT(buf, " -+"); break;
		}

	    if (curbuf->b_fname != NULL  && curbuf->b_term == NULL  )



	    {
		
		off = (int)STRLEN(buf);
		buf[off++] = ' ';
		buf[off++] = '(';
		home_replace(curbuf, curbuf->b_ffname, buf + off, SPACE_FOR_DIR - off, TRUE);

		
		if (isalpha(buf[off]) && buf[off + 1] == ':')
		    off += 2;

		
		p = gettail_sep(buf + off);
		if (p == buf + off)
		{
		    
		    vim_strncpy(buf + off, (char_u *)_("help"), (size_t)(SPACE_FOR_DIR - off - 1));
		}
		else *p = NUL;

		
		
		
		if (off < SPACE_FOR_DIR)
		{
		    p = transstr(buf + off);
		    vim_strncpy(buf + off, p, (size_t)(SPACE_FOR_DIR - off));
		    vim_free(p);
		}
		else {
		    vim_strncpy(buf + off, (char_u *)"...", (size_t)(SPACE_FOR_ARGNR - off));
		}
		STRCAT(buf, ")");
	    }

	    append_arg_number(curwin, buf, SPACE_FOR_ARGNR, FALSE);


	    if (serverName != NULL)
	    {
		STRCAT(buf, " - ");
		vim_strcat(buf, serverName, IOSIZE);
	    }
	    else  STRCAT(buf, " - VIM");


	    if (maxlen > 0)
	    {
		
		if (vim_strsize(buf) > maxlen)
		    trunc_string(buf, buf, maxlen, IOSIZE);
	    }
	}
    }
    mustset = value_changed(title_str, &lasttitle);

    if (p_icon)
    {
	icon_str = buf;
	if (*p_iconstring != NUL)
	{

	    if (stl_syntax & STL_IN_ICON)
	    {
		int	use_sandbox = FALSE;
		int	called_emsg_before = called_emsg;


		use_sandbox = was_set_insecurely((char_u *)"iconstring", 0);

		build_stl_str_hl(curwin, icon_str, sizeof(buf), p_iconstring, use_sandbox, 0, 0, NULL, NULL);

		if (called_emsg > called_emsg_before)
		    set_string_option_direct((char_u *)"iconstring", -1, (char_u *)"", OPT_FREE, SID_ERROR);
	    }
	    else  icon_str = p_iconstring;

	}
	else {
	    if (buf_spname(curbuf) != NULL)
		p = buf_spname(curbuf);
	    else		     p = gettail(curbuf->b_ffname);
	    *icon_str = NUL;
	    
	    len = (int)STRLEN(p);
	    if (len > 100)
	    {
		len -= 100;
		if (has_mbyte)
		    len += (*mb_tail_off)(p, p + len) + 1;
		p += len;
	    }
	    STRCPY(icon_str, p);
	    trans_characters(icon_str, IOSIZE);
	}
    }

    mustset |= value_changed(icon_str, &lasticon);

    if (mustset)
	resettitle();
}


    static int value_changed(char_u *str, char_u **last)
{
    if ((str == NULL) != (*last == NULL)
	    || (str != NULL && *last != NULL && STRCMP(str, *last) != 0))
    {
	vim_free(*last);
	if (str == NULL)
	{
	    *last = NULL;
	    mch_restore_title( last == &lasttitle ? SAVE_RESTORE_TITLE : SAVE_RESTORE_ICON);
	}
	else {
	    *last = vim_strsave(str);
	    return TRUE;
	}
    }
    return FALSE;
}


    void resettitle(void)
{
    mch_settitle(lasttitle, lasticon);
}


    void free_titles(void)
{
    vim_free(lasttitle);
    vim_free(lasticon);
}






typedef struct {
    char_u	*stl_start;
    int		stl_minwid;
    int		stl_maxwid;
    enum {
	Normal, Empty, Group, Middle, Highlight, TabPage, Trunc }		stl_type;






} stl_item_T;

static size_t		stl_items_len = 20; 
static stl_item_T      *stl_items = NULL;
static int	       *stl_groupitem = NULL;
static stl_hlrec_T     *stl_hltab = NULL;
static stl_hlrec_T     *stl_tabtab = NULL;


    int build_stl_str_hl( win_T	*wp, char_u	*out, size_t	outlen, char_u	*fmt, int		use_sandbox UNUSED, int		fillchar, int		maxwidth, stl_hlrec_T **hltab, stl_hlrec_T **tabtab)









{
    linenr_T	lnum;
    size_t	len;
    char_u	*p;
    char_u	*s;
    char_u	*t;
    int		byteval;

    win_T	*save_curwin;
    buf_T	*save_curbuf;
    int		save_VIsual_active;

    int		empty_line;
    colnr_T	virtcol;
    long	l;
    long	n;
    int		prevchar_isflag;
    int		prevchar_isitem;
    int		itemisflag;
    int		fillable;
    char_u	*str;
    long	num;
    int		width;
    int		itemcnt;
    int		curitem;
    int		group_end_userhl;
    int		group_start_userhl;
    int		groupdepth;

    int		evaldepth;

    int		minwid;
    int		maxwid;
    int		zeropad;
    char_u	base;
    char_u	opt;

    char_u	buf_tmp[TMPLEN];
    char_u	win_tmp[TMPLEN];
    char_u	*usefmt = fmt;
    stl_hlrec_T *sp;
    int		save_must_redraw = must_redraw;
    int		save_redr_type = curwin->w_redr_type;
    int		save_KeyTyped = KeyTyped;

    if (stl_items == NULL)
    {
	stl_items = ALLOC_MULT(stl_item_T, stl_items_len);
	stl_groupitem = ALLOC_MULT(int, stl_items_len);

	
	
	stl_hltab  = ALLOC_MULT(stl_hlrec_T, stl_items_len + 1);
	stl_tabtab = ALLOC_MULT(stl_hlrec_T, stl_items_len + 1);
    }


    
    if (fmt[0] == '%' && fmt[1] == '!')
    {
	typval_T	tv;

	tv.v_type = VAR_NUMBER;
	tv.vval.v_number = wp->w_id;
	set_var((char_u *)"g:statusline_winid", &tv, FALSE);

	usefmt = eval_to_string_safe(fmt + 2, use_sandbox, FALSE);
	if (usefmt == NULL)
	    usefmt = fmt;

	do_unlet((char_u *)"g:statusline_winid", TRUE);
    }


    if (fillchar == 0)
	fillchar = ' ';

    
    
    lnum = wp->w_cursor.lnum;
    if (lnum > wp->w_buffer->b_ml.ml_line_count)
    {
	lnum = wp->w_buffer->b_ml.ml_line_count;
	wp->w_cursor.lnum = lnum;
    }

    
    
    p = ml_get_buf(wp->w_buffer, lnum, FALSE);
    empty_line = (*p == NUL);

    
    
    len = STRLEN(p);
    if (wp->w_cursor.col > (colnr_T)len)
    {
	
	
	wp->w_cursor.col = (colnr_T)len;
	wp->w_cursor.coladd = 0;
	byteval = 0;
    }
    else byteval = (*mb_ptr2char)(p + wp->w_cursor.col);

    groupdepth = 0;

    evaldepth = 0;

    p = out;
    curitem = 0;
    prevchar_isflag = TRUE;
    prevchar_isitem = FALSE;
    for (s = usefmt; *s; )
    {
	if (curitem == (int)stl_items_len)
	{
	    size_t	new_len = stl_items_len * 3 / 2;
	    stl_item_T	*new_items;
	    int		*new_groupitem;
	    stl_hlrec_T	*new_hlrec;

	    new_items = vim_realloc(stl_items, sizeof(stl_item_T) * new_len);
	    if (new_items == NULL)
		break;
	    stl_items = new_items;
	    new_groupitem = vim_realloc(stl_groupitem, sizeof(int) * new_len);
	    if (new_groupitem == NULL)
		break;
	    stl_groupitem = new_groupitem;
	    new_hlrec = vim_realloc(stl_hltab, sizeof(stl_hlrec_T) * (new_len + 1));
	    if (new_hlrec == NULL)
		break;
	    stl_hltab = new_hlrec;
	    new_hlrec = vim_realloc(stl_tabtab, sizeof(stl_hlrec_T) * (new_len + 1));
	    if (new_hlrec == NULL)
		break;
	    stl_tabtab = new_hlrec;
	    stl_items_len = new_len;
	}

	if (*s != NUL && *s != '%')
	    prevchar_isflag = prevchar_isitem = FALSE;

	
	while (*s != NUL && *s != '%' && p + 1 < out + outlen)
	    *p++ = *s++;
	if (*s == NUL || p + 1 >= out + outlen)
	    break;

	
	s++;
	if (*s == NUL)  
	    break;
	if (*s == '%')
	{
	    if (p + 1 >= out + outlen)
		break;
	    *p++ = *s++;
	    prevchar_isflag = prevchar_isitem = FALSE;
	    continue;
	}
	if (*s == STL_MIDDLEMARK)
	{
	    s++;
	    if (groupdepth > 0)
		continue;
	    stl_items[curitem].stl_type = Middle;
	    stl_items[curitem++].stl_start = p;
	    continue;
	}
	if (*s == STL_TRUNCMARK)
	{
	    s++;
	    stl_items[curitem].stl_type = Trunc;
	    stl_items[curitem++].stl_start = p;
	    continue;
	}
	if (*s == ')')
	{
	    s++;
	    if (groupdepth < 1)
		continue;
	    groupdepth--;

	    t = stl_items[stl_groupitem[groupdepth]].stl_start;
	    *p = NUL;
	    l = vim_strsize(t);
	    if (curitem > stl_groupitem[groupdepth] + 1 && stl_items[stl_groupitem[groupdepth]].stl_minwid == 0)
	    {
		
		
		group_start_userhl = group_end_userhl = 0;
		for (n = stl_groupitem[groupdepth] - 1; n >= 0; n--)
		{
		    if (stl_items[n].stl_type == Highlight)
		    {
			group_start_userhl = group_end_userhl = stl_items[n].stl_minwid;
			break;
		    }
		}
		for (n = stl_groupitem[groupdepth] + 1; n < curitem; n++)
		{
		    if (stl_items[n].stl_type == Normal)
			break;
		    if (stl_items[n].stl_type == Highlight)
			group_end_userhl = stl_items[n].stl_minwid;
		}
		if (n == curitem && group_start_userhl == group_end_userhl)
		{
		    
		    p = t;
		    l = 0;
		    for (n = stl_groupitem[groupdepth] + 1; n < curitem; n++)
		    {
			
			if (stl_items[n].stl_type == Highlight)
			    stl_items[n].stl_type = Empty;
			
			
			if (stl_items[n].stl_type == TabPage)
			    stl_items[n].stl_start = p;
		    }
		}
	    }
	    if (l > stl_items[stl_groupitem[groupdepth]].stl_maxwid)
	    {
		
		if (has_mbyte)
		{
		    
		    n = 0;
		    while (l >= stl_items[stl_groupitem[groupdepth]].stl_maxwid)
		    {
			l -= ptr2cells(t + n);
			n += (*mb_ptr2len)(t + n);
		    }
		}
		else n = (long)(p - t) - stl_items[stl_groupitem[groupdepth]] .stl_maxwid + 1;


		*t = '<';
		mch_memmove(t + 1, t + n, (size_t)(p - (t + n)));
		p = p - n + 1;

		
		while (++l < stl_items[stl_groupitem[groupdepth]].stl_minwid)
		    MB_CHAR2BYTES(fillchar, p);

		
		for (l = stl_groupitem[groupdepth] + 1; l < curitem; l++)
		{
		    
		    stl_items[l].stl_start -= n - 1;
		    if (stl_items[l].stl_start < t)
			stl_items[l].stl_start = t;
		}
	    }
	    else if (abs(stl_items[stl_groupitem[groupdepth]].stl_minwid) > l)
	    {
		
		n = stl_items[stl_groupitem[groupdepth]].stl_minwid;
		if (n < 0)
		{
		    
		    n = 0 - n;
		    while (l++ < n && p + 1 < out + outlen)
			MB_CHAR2BYTES(fillchar, p);
		}
		else {
		    
		    l = (n - l) * MB_CHAR2LEN(fillchar);
		    mch_memmove(t + l, t, (size_t)(p - t));
		    if (p + l >= out + outlen)
			l = (long)((out + outlen) - p - 1);
		    p += l;
		    for (n = stl_groupitem[groupdepth] + 1; n < curitem; n++)
			stl_items[n].stl_start += l;
		    for ( ; l > 0; l--)
			MB_CHAR2BYTES(fillchar, t);
		}
	    }
	    continue;
	}
	minwid = 0;
	maxwid = 9999;
	zeropad = FALSE;
	l = 1;
	if (*s == '0')
	{
	    s++;
	    zeropad = TRUE;
	}
	if (*s == '-')
	{
	    s++;
	    l = -1;
	}
	if (VIM_ISDIGIT(*s))
	{
	    minwid = (int)getdigits(&s);
	    if (minwid < 0)	
		minwid = 0;
	}
	if (*s == STL_USER_HL)
	{
	    stl_items[curitem].stl_type = Highlight;
	    stl_items[curitem].stl_start = p;
	    stl_items[curitem].stl_minwid = minwid > 9 ? 1 : minwid;
	    s++;
	    curitem++;
	    continue;
	}
	if (*s == STL_TABPAGENR || *s == STL_TABCLOSENR)
	{
	    if (*s == STL_TABCLOSENR)
	    {
		if (minwid == 0)
		{
		    
		    
		    for (n = curitem - 1; n >= 0; --n)
			if (stl_items[n].stl_type == TabPage && stl_items[n].stl_minwid >= 0)
			{
			    minwid = stl_items[n].stl_minwid;
			    break;
			}
		}
		else  minwid = - minwid;

	    }
	    stl_items[curitem].stl_type = TabPage;
	    stl_items[curitem].stl_start = p;
	    stl_items[curitem].stl_minwid = minwid;
	    s++;
	    curitem++;
	    continue;
	}
	if (*s == '.')
	{
	    s++;
	    if (VIM_ISDIGIT(*s))
	    {
		maxwid = (int)getdigits(&s);
		if (maxwid <= 0)	
		    maxwid = 50;
	    }
	}
	minwid = (minwid > 50 ? 50 : minwid) * l;
	if (*s == '(')
	{
	    stl_groupitem[groupdepth++] = curitem;
	    stl_items[curitem].stl_type = Group;
	    stl_items[curitem].stl_start = p;
	    stl_items[curitem].stl_minwid = minwid;
	    stl_items[curitem].stl_maxwid = maxwid;
	    s++;
	    curitem++;
	    continue;
	}

	
	if (*s == '}' && evaldepth > 0)
	{
	    s++;
	    evaldepth--;
	    continue;
	}

	if (vim_strchr(STL_ALL, *s) == NULL)
	{
	    s++;
	    continue;
	}
	opt = *s++;

	
	base = 'D';
	itemisflag = FALSE;
	fillable = TRUE;
	num = -1;
	str = NULL;
	switch (opt)
	{
	case STL_FILEPATH:
	case STL_FULLPATH:
	case STL_FILENAME:
	    fillable = FALSE;	
	    if (buf_spname(wp->w_buffer) != NULL)
		vim_strncpy(NameBuff, buf_spname(wp->w_buffer), MAXPATHL - 1);
	    else {
		t = (opt == STL_FULLPATH) ? wp->w_buffer->b_ffname : wp->w_buffer->b_fname;
		home_replace(wp->w_buffer, t, NameBuff, MAXPATHL, TRUE);
	    }
	    trans_characters(NameBuff, MAXPATHL);
	    if (opt != STL_FILENAME)
		str = NameBuff;
	    else str = gettail(NameBuff);
	    break;

	case STL_VIM_EXPR: 
	{

	    char_u *block_start = s - 1;

	    int reevaluate = (*s == '%');

	    if (reevaluate)
		s++;
	    itemisflag = TRUE;
	    t = p;
	    while ((*s != '}' || (reevaluate && s[-1] != '%'))
					  && *s != NUL && p + 1 < out + outlen)
		*p++ = *s++;
	    if (*s != '}')	
		break;
	    s++;
	    if (reevaluate)
		p[-1] = 0; 
	    else *p = 0;
	    p = t;

	    vim_snprintf((char *)buf_tmp, sizeof(buf_tmp), "%d", curbuf->b_fnum);
	    set_internal_string_var((char_u *)"g:actual_curbuf", buf_tmp);
	    vim_snprintf((char *)win_tmp, sizeof(win_tmp), "%d", curwin->w_id);
	    set_internal_string_var((char_u *)"g:actual_curwin", win_tmp);

	    save_curbuf = curbuf;
	    save_curwin = curwin;
	    save_VIsual_active = VIsual_active;
	    curwin = wp;
	    curbuf = wp->w_buffer;
	    
	    if (curwin != save_curwin)
		VIsual_active = FALSE;

	    str = eval_to_string_safe(p, use_sandbox, FALSE);

	    curwin = save_curwin;
	    curbuf = save_curbuf;
	    VIsual_active = save_VIsual_active;
	    do_unlet((char_u *)"g:actual_curbuf", TRUE);
	    do_unlet((char_u *)"g:actual_curwin", TRUE);

	    if (str != NULL && *str != 0)
	    {
		if (*skipdigits(str) == NUL)
		{
		    num = atoi((char *)str);
		    VIM_CLEAR(str);
		    itemisflag = FALSE;
		}
	    }

	    
	    
	    if (reevaluate && str != NULL && *str != 0 && strchr((const char *)str, '%') != NULL && evaldepth < MAX_STL_EVAL_DEPTH)

	    {
		size_t parsed_usefmt = (size_t)(block_start - usefmt);
		size_t str_length = strlen((const char *)str);
		size_t fmt_length = strlen((const char *)s);
		size_t new_fmt_len = parsed_usefmt + str_length + fmt_length + 3;
		char_u *new_fmt = (char_u *)alloc(new_fmt_len * sizeof(char_u));
		char_u *new_fmt_p = new_fmt;

		new_fmt_p = (char_u *)memcpy(new_fmt_p, usefmt, parsed_usefmt)
							       + parsed_usefmt;
		new_fmt_p = (char_u *)memcpy(new_fmt_p , str, str_length)
								  + str_length;
		new_fmt_p = (char_u *)memcpy(new_fmt_p, "%}", 2) + 2;
		new_fmt_p = (char_u *)memcpy(new_fmt_p , s, fmt_length)
								  + fmt_length;
		*new_fmt_p = 0;
		new_fmt_p = NULL;

		if (usefmt != fmt)
		    vim_free(usefmt);
		VIM_CLEAR(str);
		usefmt = new_fmt;
		s = usefmt + parsed_usefmt;
		evaldepth++;
		continue;
	    }

	    break;
	}
	case STL_LINE:
	    num = (wp->w_buffer->b_ml.ml_flags & ML_EMPTY)
		  ? 0L : (long)(wp->w_cursor.lnum);
	    break;

	case STL_NUMLINES:
	    num = wp->w_buffer->b_ml.ml_line_count;
	    break;

	case STL_COLUMN:
	    num = (State & MODE_INSERT) == 0 && empty_line ? 0 : (int)wp->w_cursor.col + 1;
	    break;

	case STL_VIRTCOL:
	case STL_VIRTCOL_ALT:
	    virtcol = wp->w_virtcol + 1;
	    
	    if (opt == STL_VIRTCOL_ALT && (virtcol == (colnr_T)((State & MODE_INSERT) == 0 && empty_line ? 0 : (int)wp->w_cursor.col + 1)))

		break;
	    num = (long)virtcol;
	    break;

	case STL_PERCENTAGE:
	    num = (int)(((long)wp->w_cursor.lnum * 100L) / (long)wp->w_buffer->b_ml.ml_line_count);
	    break;

	case STL_ALTPERCENT:
	    str = buf_tmp;
	    get_rel_pos(wp, str, TMPLEN);
	    break;

	case STL_ARGLISTSTAT:
	    fillable = FALSE;
	    buf_tmp[0] = 0;
	    if (append_arg_number(wp, buf_tmp, (int)sizeof(buf_tmp), FALSE))
		str = buf_tmp;
	    break;

	case STL_KEYMAP:
	    fillable = FALSE;
	    if (get_keymap_str(wp, (char_u *)"<%s>", buf_tmp, TMPLEN))
		str = buf_tmp;
	    break;
	case STL_PAGENUM:

	    num = printer_page_num;

	    num = 0;

	    break;

	case STL_BUFNO:
	    num = wp->w_buffer->b_fnum;
	    break;

	case STL_OFFSET_X:
	    base = 'X';
	    
	case STL_OFFSET:

	    l = ml_find_line_or_offset(wp->w_buffer, wp->w_cursor.lnum, NULL);
	    num = (wp->w_buffer->b_ml.ml_flags & ML_EMPTY) || l < 0 ? 0L : l + 1 + ((State & MODE_INSERT) == 0 && empty_line ? 0 : (int)wp->w_cursor.col);


	    break;

	case STL_BYTEVAL_X:
	    base = 'X';
	    
	case STL_BYTEVAL:
	    num = byteval;
	    if (num == NL)
		num = 0;
	    else if (num == CAR && get_fileformat(wp->w_buffer) == EOL_MAC)
		num = NL;
	    break;

	case STL_ROFLAG:
	case STL_ROFLAG_ALT:
	    itemisflag = TRUE;
	    if (wp->w_buffer->b_p_ro)
		str = (char_u *)((opt == STL_ROFLAG_ALT) ? ",RO" : _("[RO]"));
	    break;

	case STL_HELPFLAG:
	case STL_HELPFLAG_ALT:
	    itemisflag = TRUE;
	    if (wp->w_buffer->b_help)
		str = (char_u *)((opt == STL_HELPFLAG_ALT) ? ",HLP" : _("[Help]"));
	    break;

	case STL_FILETYPE:
	    if (*wp->w_buffer->b_p_ft != NUL && STRLEN(wp->w_buffer->b_p_ft) < TMPLEN - 3)
	    {
		vim_snprintf((char *)buf_tmp, sizeof(buf_tmp), "[%s]", wp->w_buffer->b_p_ft);
		str = buf_tmp;
	    }
	    break;

	case STL_FILETYPE_ALT:
	    itemisflag = TRUE;
	    if (*wp->w_buffer->b_p_ft != NUL && STRLEN(wp->w_buffer->b_p_ft) < TMPLEN - 2)
	    {
		vim_snprintf((char *)buf_tmp, sizeof(buf_tmp), ",%s", wp->w_buffer->b_p_ft);
		for (t = buf_tmp; *t != 0; t++)
		    *t = TOUPPER_LOC(*t);
		str = buf_tmp;
	    }
	    break;


	case STL_PREVIEWFLAG:
	case STL_PREVIEWFLAG_ALT:
	    itemisflag = TRUE;
	    if (wp->w_p_pvw)
		str = (char_u *)((opt == STL_PREVIEWFLAG_ALT) ? ",PRV" : _("[Preview]"));
	    break;

	case STL_QUICKFIX:
	    if (bt_quickfix(wp->w_buffer))
		str = (char_u *)(wp->w_llist_ref ? _(msg_loclist)
			    : _(msg_qflist));
	    break;


	case STL_MODIFIED:
	case STL_MODIFIED_ALT:
	    itemisflag = TRUE;
	    switch ((opt == STL_MODIFIED_ALT)
		    + bufIsChanged(wp->w_buffer) * 2 + (!wp->w_buffer->b_p_ma) * 4)
	    {
		case 2: str = (char_u *)"[+]"; break;
		case 3: str = (char_u *)",+"; break;
		case 4: str = (char_u *)"[-]"; break;
		case 5: str = (char_u *)",-"; break;
		case 6: str = (char_u *)"[+-]"; break;
		case 7: str = (char_u *)",+-"; break;
	    }
	    break;

	case STL_HIGHLIGHT:
	    t = s;
	    while (*s != '#' && *s != NUL)
		++s;
	    if (*s == '#')
	    {
		stl_items[curitem].stl_type = Highlight;
		stl_items[curitem].stl_start = p;
		stl_items[curitem].stl_minwid = -syn_namen2id(t, (int)(s - t));
		curitem++;
	    }
	    if (*s != NUL)
		++s;
	    continue;
	}

	stl_items[curitem].stl_start = p;
	stl_items[curitem].stl_type = Normal;
	if (str != NULL && *str)
	{
	    t = str;
	    if (itemisflag)
	    {
		if ((t[0] && t[1])
			&& ((!prevchar_isitem && *t == ',')
			      || (prevchar_isflag && *t == ' ')))
		    t++;
		prevchar_isflag = TRUE;
	    }
	    l = vim_strsize(t);
	    if (l > 0)
		prevchar_isitem = TRUE;
	    if (l > maxwid)
	    {
		while (l >= maxwid)
		    if (has_mbyte)
		    {
			l -= ptr2cells(t);
			t += (*mb_ptr2len)(t);
		    }
		    else l -= byte2cells(*t++);
		if (p + 1 >= out + outlen)
		    break;
		*p++ = '<';
	    }
	    if (minwid > 0)
	    {
		for (; l < minwid && p + 1 < out + outlen; l++)
		{
		    
		    if (l + 1 == minwid && fillchar == '-' && VIM_ISDIGIT(*t))
			*p++ = ' ';
		    else MB_CHAR2BYTES(fillchar, p);
		}
		minwid = 0;
	    }
	    else minwid *= -1;
	    for (; *t && p + 1 < out + outlen; t++)
	    {
		
		
		if (fillable && *t == ' ' && (!VIM_ISDIGIT(*(t + 1)) || fillchar != '-'))
		    MB_CHAR2BYTES(fillchar, p);
		else *p++ = *t;
	    }
	    for (; l < minwid && p + 1 < out + outlen; l++)
		MB_CHAR2BYTES(fillchar, p);
	}
	else if (num >= 0)
	{
	    int nbase = (base == 'D' ? 10 : (base == 'O' ? 8 : 16));
	    char_u nstr[20];

	    if (p + 20 >= out + outlen)
		break;		
	    prevchar_isitem = TRUE;
	    t = nstr;
	    if (opt == STL_VIRTCOL_ALT)
	    {
		*t++ = '-';
		minwid--;
	    }
	    *t++ = '%';
	    if (zeropad)
		*t++ = '0';
	    *t++ = '*';
	    *t++ = nbase == 16 ? base : (char_u)(nbase == 8 ? 'o' : 'd');
	    *t = 0;

	    for (n = num, l = 1; n >= nbase; n /= nbase)
		l++;
	    if (opt == STL_VIRTCOL_ALT)
		l++;
	    if (l > maxwid)
	    {
		l += 2;
		n = l - maxwid;
		while (l-- > maxwid)
		    num /= nbase;
		*t++ = '>';
		*t++ = '%';
		*t = t[-3];
		*++t = 0;
		vim_snprintf((char *)p, outlen - (p - out), (char *)nstr, 0, num, n);
	    }
	    else vim_snprintf((char *)p, outlen - (p - out), (char *)nstr, minwid, num);

	    p += STRLEN(p);
	}
	else stl_items[curitem].stl_type = Empty;

	if (opt == STL_VIM_EXPR)
	    vim_free(str);

	if (num >= 0 || (!itemisflag && str && *str))
	    prevchar_isflag = FALSE;	    
	curitem++;
    }
    *p = NUL;
    itemcnt = curitem;


    if (usefmt != fmt)
	vim_free(usefmt);


    width = vim_strsize(out);
    if (maxwidth > 0 && width > maxwidth)
    {
	
	l = 0;
	if (itemcnt == 0)
	    s = out;
	else {
	    for ( ; l < itemcnt; l++)
		if (stl_items[l].stl_type == Trunc)
		{
		    
		    s = stl_items[l].stl_start;
		    break;
		}
	    if (l == itemcnt)
	    {
		
		s = stl_items[0].stl_start;
		l = 0;
	    }
	}

	if (width - vim_strsize(s) >= maxwidth)
	{
	    
	    if (has_mbyte)
	    {
		s = out;
		width = 0;
		for (;;)
		{
		    width += ptr2cells(s);
		    if (width >= maxwidth)
			break;
		    s += (*mb_ptr2len)(s);
		}
		
		while (++width < maxwidth)
		    MB_CHAR2BYTES(fillchar, s);
	    }
	    else s = out + maxwidth - 1;
	    for (l = 0; l < itemcnt; l++)
		if (stl_items[l].stl_start > s)
		    break;
	    itemcnt = l;
	    *s++ = '>';
	    *s = 0;
	}
	else {
	    if (has_mbyte)
	    {
		n = 0;
		while (width >= maxwidth)
		{
		    width -= ptr2cells(s + n);
		    n += (*mb_ptr2len)(s + n);
		}
	    }
	    else n = width - maxwidth + 1;
	    p = s + n;
	    STRMOVE(s + 1, p);
	    *s = '<';

	    
	    while (++width < maxwidth)
	    {
		s = s + STRLEN(s);
		MB_CHAR2BYTES(fillchar, s);
		*s = NUL;
	    }

	    --n;	
	    for (; l < itemcnt; l++)
	    {
		if (stl_items[l].stl_start - n >= s)
		    stl_items[l].stl_start -= n;
		else stl_items[l].stl_start = s;
	    }
	}
	width = maxwidth;
    }
    else if (width < maxwidth && STRLEN(out) + maxwidth - width + 1 < outlen)
    {
	
	for (l = 0; l < itemcnt; l++)
	    if (stl_items[l].stl_type == Middle)
		break;
	if (l < itemcnt)
	{
	    int middlelength = (maxwidth - width) * MB_CHAR2LEN(fillchar);
	    p = stl_items[l].stl_start + middlelength;
	    STRMOVE(p, stl_items[l].stl_start);
	    for (s = stl_items[l].stl_start; s < p;)
		MB_CHAR2BYTES(fillchar, s);
	    for (l++; l < itemcnt; l++)
		stl_items[l].stl_start += middlelength;
	    width = maxwidth;
	}
    }

    
    if (hltab != NULL)
    {
	*hltab = stl_hltab;
	sp = stl_hltab;
	for (l = 0; l < itemcnt; l++)
	{
	    if (stl_items[l].stl_type == Highlight)
	    {
		sp->start = stl_items[l].stl_start;
		sp->userhl = stl_items[l].stl_minwid;
		sp++;
	    }
	}
	sp->start = NULL;
	sp->userhl = 0;
    }

    
    if (tabtab != NULL)
    {
	*tabtab = stl_tabtab;
	sp = stl_tabtab;
	for (l = 0; l < itemcnt; l++)
	{
	    if (stl_items[l].stl_type == TabPage)
	    {
		sp->start = stl_items[l].stl_start;
		sp->userhl = stl_items[l].stl_minwid;
		sp++;
	    }
	}
	sp->start = NULL;
	sp->userhl = 0;
    }

    
    
    if (updating_screen)
    {
	must_redraw = save_must_redraw;
	curwin->w_redr_type = save_redr_type;
    }

    
    KeyTyped = save_KeyTyped;

    return width;
}




    void get_rel_pos( win_T	*wp, char_u	*buf, int		buflen)



{
    long	above; 
    long	below; 

    if (buflen < 3) 
	return;
    above = wp->w_topline - 1;

    above += diff_check_fill(wp, wp->w_topline) - wp->w_topfill;
    if (wp->w_topline == 1 && wp->w_topfill >= 1)
	above = 0;  
		    
		    

    below = wp->w_buffer->b_ml.ml_line_count - wp->w_botline + 1;
    if (below <= 0)
	vim_strncpy(buf, (char_u *)(above == 0 ? _("All") : _("Bot")), (size_t)(buflen - 1));
    else if (above <= 0)
	vim_strncpy(buf, (char_u *)_("Top"), (size_t)(buflen - 1));
    else vim_snprintf((char *)buf, (size_t)buflen, "%2d%%", above > 1000000L ? (int)(above / ((above + below) / 100L))

				    : (int)(above * 100L / (above + below)));
}



    static int append_arg_number( win_T	*wp, char_u	*buf, int		buflen, int		add_file)




{
    char_u	*p;

    if (ARGCOUNT <= 1)		
	return FALSE;

    p = buf + STRLEN(buf);	
    if (p - buf + 35 >= buflen)	
	return FALSE;
    *p++ = ' ';
    *p++ = '(';
    if (add_file)
    {
	STRCPY(p, "file ");
	p += 5;
    }
    vim_snprintf((char *)p, (size_t)(buflen - (p - buf)), wp->w_arg_idx_invalid ? "(%d) of %d)" : "%d of %d)", wp->w_arg_idx + 1, ARGCOUNT);

    return TRUE;
}


    char_u  * fix_fname(char_u  *fname)
{
    

    return FullName_save(fname, TRUE);

    if (!vim_isAbsName(fname)
	    || strstr((char *)fname, "..") != NULL || strstr((char *)fname, "//") != NULL  || strstr((char *)fname, "\\\\") != NULL   || vim_strchr(fname, '~') != NULL  )







	return FullName_save(fname, FALSE);

    fname = vim_strsave(fname);


    if (fname != NULL)
	fname_case(fname, 0);	


    return fname;

}


    void fname_expand( buf_T	*buf UNUSED, char_u	**ffname, char_u	**sfname)



{
    if (*ffname == NULL)	    
	return;
    if (*sfname == NULL)	    
	*sfname = *ffname;
    *ffname = fix_fname(*ffname);   


    if (!buf->b_p_bin)
    {
	char_u  *rfname;

	
	rfname = mch_resolve_path(*ffname, FALSE);
	if (rfname != NULL)
	{
	    vim_free(*ffname);
	    *ffname = rfname;
	    *sfname = rfname;
	}
    }

}


    void ex_buffer_all(exarg_T *eap)
{
    buf_T	*buf;
    win_T	*wp, *wpnext;
    int		split_ret = OK;
    int		p_ea_save;
    int		open_wins = 0;
    int		r;
    int		count;		
    int		all;		
    int		had_tab = cmdmod.cmod_tab;
    tabpage_T	*tpnext;

    if (eap->addr_count == 0)	
	count = 9999;
    else count = eap->line2;
    if (eap->cmdidx == CMD_unhide || eap->cmdidx == CMD_sunhide)
	all = FALSE;
    else all = TRUE;

    setpcmark();


    need_mouse_correct = TRUE;


    
    if (had_tab > 0)
	goto_tabpage_tp(first_tabpage, TRUE, TRUE);
    for (;;)
    {
	tpnext = curtab->tp_next;
	for (wp = firstwin; wp != NULL; wp = wpnext)
	{
	    wpnext = wp->w_next;
	    if ((wp->w_buffer->b_nwindows > 1 || ((cmdmod.cmod_split & WSP_VERT)
			    ? wp->w_height + wp->w_status_height < Rows - p_ch - tabline_height()
			    : wp->w_width != Columns)
			|| (had_tab > 0 && wp != firstwin))
		    && !ONE_WINDOW && !(wp->w_closing || wp->w_buffer->b_locked > 0)
		    && !win_unlisted(wp))
	    {
		if (win_close(wp, FALSE) == FAIL)
		    break;
		
		
		wpnext = firstwin;
		tpnext = first_tabpage;
		open_wins = 0;
	    }
	    else ++open_wins;
	}

	
	if (had_tab == 0 || tpnext == NULL)
	    break;
	goto_tabpage_tp(tpnext, TRUE, TRUE);
    }

    
    
    ++autocmd_no_enter;
    win_enter(lastwin, FALSE);
    ++autocmd_no_leave;
    for (buf = firstbuf; buf != NULL && open_wins < count; buf = buf->b_next)
    {
	
	if ((!all && buf->b_ml.ml_mfp == NULL) || !buf->b_p_bl)
	    continue;

	if (had_tab != 0)
	{
	    
	    if (buf->b_nwindows > 0)
		wp = lastwin;	    
	    else wp = NULL;
	}
	else {
	    
	    FOR_ALL_WINDOWS(wp)
		if (wp->w_buffer == buf)
		    break;
	    
	    if (wp != NULL)
		win_move_after(wp, curwin);
	}

	if (wp == NULL && split_ret == OK)
	{
	    bufref_T	bufref;

	    set_bufref(&bufref, buf);

	    
	    p_ea_save = p_ea;
	    p_ea = TRUE;		
	    split_ret = win_split(0, WSP_ROOM | WSP_BELOW);
	    ++open_wins;
	    p_ea = p_ea_save;
	    if (split_ret == FAIL)
		continue;

	    
	    swap_exists_action = SEA_DIALOG;
	    set_curbuf(buf, DOBUF_GOTO);
	    if (!bufref_valid(&bufref))
	    {
		
		swap_exists_action = SEA_NONE;
		break;
	    }
	    if (swap_exists_action == SEA_QUIT)
	    {

		cleanup_T   cs;

		
		
		enter_cleanup(&cs);


		
		win_close(curwin, TRUE);
		--open_wins;
		swap_exists_action = SEA_NONE;
		swap_exists_did_quit = TRUE;


		
		
		
		leave_cleanup(&cs);

	    }
	    else handle_swap_exists(NULL);
	}

	ui_breakcheck();
	if (got_int)
	{
	    (void)vgetc();	
	    break;
	}

	
	if (aborting())
	    break;

	
	if (had_tab > 0 && tabpage_index(NULL) <= p_tpm)
	    cmdmod.cmod_tab = 9999;
    }
    --autocmd_no_enter;
    win_enter(firstwin, FALSE);		
    --autocmd_no_leave;

    
    for (wp = lastwin; open_wins > count; )
    {
	r = (buf_hide(wp->w_buffer) || !bufIsChanged(wp->w_buffer)
				     || autowrite(wp->w_buffer, FALSE) == OK);
	if (!win_valid(wp))
	{
	    
	    wp = lastwin;
	}
	else if (r)
	{
	    win_close(wp, !buf_hide(wp->w_buffer));
	    --open_wins;
	    wp = lastwin;
	}
	else {
	    wp = wp->w_prev;
	    if (wp == NULL)
		break;
	}
    }
}


static int  chk_modeline(linenr_T, int);


    void do_modelines(int flags)
{
    linenr_T	lnum;
    int		nmlines;
    static int	entered = 0;

    if (!curbuf->b_p_ml || (nmlines = (int)p_mls) == 0)
	return;

    
    
    if (entered)
	return;

    ++entered;
    for (lnum = 1; curbuf->b_p_ml && lnum <= curbuf->b_ml.ml_line_count && lnum <= nmlines;
								       ++lnum)
	if (chk_modeline(lnum, flags) == FAIL)
	    nmlines = 0;

    for (lnum = curbuf->b_ml.ml_line_count; curbuf->b_p_ml && lnum > 0 && lnum > nmlines && lnum > curbuf->b_ml.ml_line_count - nmlines; --lnum)
	if (chk_modeline(lnum, flags) == FAIL)
	    nmlines = 0;
    --entered;
}




    static int chk_modeline( linenr_T	lnum, int		flags)


{
    char_u	*s;
    char_u	*e;
    char_u	*linecopy;		
    int		prev;
    int		vers;
    int		end;
    int		retval = OK;
    sctx_T	save_current_sctx;

    ESTACK_CHECK_DECLARATION  prev = -1;

    for (s = ml_get(lnum); *s != NUL; ++s)
    {
	if (prev == -1 || vim_isspace(prev))
	{
	    if ((prev != -1 && STRNCMP(s, "ex:", (size_t)3) == 0)
		    || STRNCMP(s, "vi:", (size_t)3) == 0)
		break;
	    
	    if ((s[0] == 'v' || s[0] == 'V') && s[1] == 'i' && s[2] == 'm')
	    {
		if (s[3] == '<' || s[3] == '=' || s[3] == '>')
		    e = s + 4;
		else e = s + 3;
		vers = getdigits(&e);
		if (*e == ':' && (s[0] != 'V' || STRNCMP(skipwhite(e + 1), "set", 3) == 0)

			&& (s[3] == ':' || (VIM_VERSION_100 >= vers && isdigit(s[3]))
			    || (VIM_VERSION_100 < vers && s[3] == '<')
			    || (VIM_VERSION_100 > vers && s[3] == '>')
			    || (VIM_VERSION_100 == vers && s[3] == '=')))
		    break;
	    }
	}
	prev = *s;
    }

    if (*s)
    {
	do				 ++s;
	while (s[-1] != ':');

	s = linecopy = vim_strsave(s);	
	if (linecopy == NULL)
	    return FAIL;

	
	estack_push(ETYPE_MODELINE, (char_u *)"modelines", lnum);
	ESTACK_CHECK_SETUP  end = FALSE;

	while (end == FALSE)
	{
	    s = skipwhite(s);
	    if (*s == NUL)
		break;

	    
	    for (e = s; *e != ':' && *e != NUL; ++e)
		if (e[0] == '\\' && e[1] == ':')
		    STRMOVE(e, e + 1);
	    if (*e == NUL)
		end = TRUE;

	    
	    if (STRNCMP(s, "set ", (size_t)4) == 0 || STRNCMP(s, "se ", (size_t)3) == 0)
	    {
		if (*e != ':')		
		    break;
		end = TRUE;
		s = vim_strchr(s, ' ') + 1;
	    }
	    *e = NUL;			

	    if (*s != NUL)		
	    {
		int secure_save = secure;

		save_current_sctx = current_sctx;
		current_sctx.sc_version = 1;

		current_sctx.sc_sid = SID_MODELINE;
		current_sctx.sc_seq = 0;
		current_sctx.sc_lnum = lnum;


		
		secure = 1;

		retval = do_set(s, OPT_MODELINE | OPT_LOCAL | flags);

		secure = secure_save;
		current_sctx = save_current_sctx;
		if (retval == FAIL)		
		    break;
	    }
	    s = e + 1;			
	}

	ESTACK_CHECK_NOW estack_pop();
	vim_free(linecopy);
    }
    return retval;
}


    int bt_normal(buf_T *buf)
{
    return buf != NULL && buf->b_p_bt[0] == NUL;
}



    int bt_quickfix(buf_T *buf)
{
    return buf != NULL && buf->b_p_bt[0] == 'q';
}




    int bt_terminal(buf_T *buf)
{
    return buf != NULL && buf->b_p_bt[0] == 't';
}



    int bt_help(buf_T *buf)
{
    return buf != NULL && buf->b_help;
}


    int bt_prompt(buf_T *buf)
{
    return buf != NULL && buf->b_p_bt[0] == 'p' && buf->b_p_bt[1] == 'r';
}



    int bt_popup(buf_T *buf)
{
    return buf != NULL && buf->b_p_bt != NULL && buf->b_p_bt[0] == 'p' && buf->b_p_bt[1] == 'o';
}



    int bt_nofilename(buf_T *buf)
{
    return buf != NULL && ((buf->b_p_bt[0] == 'n' && buf->b_p_bt[2] == 'f')
	    || buf->b_p_bt[0] == 'a' || buf->b_p_bt[0] == 't' || buf->b_p_bt[0] == 'p');

}



    int bt_nofile(buf_T *buf)
{
    return buf != NULL && buf->b_p_bt[0] == 'n' && buf->b_p_bt[2] == 'f';
}



    int bt_dontwrite(buf_T *buf)
{
    return buf != NULL && (buf->b_p_bt[0] == 'n' || buf->b_p_bt[0] == 't' || buf->b_p_bt[0] == 'p');

}


    int bt_dontwrite_msg(buf_T *buf)
{
    if (bt_dontwrite(buf))
    {
	emsg(_(e_cannot_write_buftype_option_is_set));
	return TRUE;
    }
    return FALSE;
}



    int buf_hide(buf_T *buf)
{
    
    switch (buf->b_p_bh[0])
    {
	case 'u':		    
	case 'w':		    
	case 'd': return FALSE;	    
	case 'h': return TRUE;	    
    }
    return (p_hid || (cmdmod.cmod_flags & CMOD_HIDE));
}


    char_u * buf_spname(buf_T *buf)
{

    if (bt_quickfix(buf))
    {
	
	if (buf->b_fnum == qf_stack_get_bufnr())
	    return (char_u *)_(msg_qflist);
	else return (char_u *)_(msg_loclist);
    }


    
    
    if (bt_nofilename(buf))
    {

	if (buf->b_term != NULL)
	    return term_get_status_text(buf->b_term);

	if (buf->b_fname != NULL)
	    return buf->b_fname;

	if (bt_prompt(buf))
	    return (char_u *)_("[Prompt]");


	if (bt_popup(buf))
	    return (char_u *)_("[Popup]");

	return (char_u *)_("[Scratch]");
    }

    if (buf->b_fname == NULL)
	return buf_get_fname(buf);
    return NULL;
}


    char_u * buf_get_fname(buf_T *buf)
{
    if (buf->b_fname == NULL)
	return (char_u *)_("[No Name]");
    return buf->b_fname;
}


    void set_buflisted(int on)
{
    if (on != curbuf->b_p_bl)
    {
	curbuf->b_p_bl = on;
	if (on)
	    apply_autocmds(EVENT_BUFADD, NULL, NULL, FALSE, curbuf);
	else apply_autocmds(EVENT_BUFDELETE, NULL, NULL, FALSE, curbuf);
    }
}


    int buf_contents_changed(buf_T *buf)
{
    buf_T	*newbuf;
    int		differ = TRUE;
    linenr_T	lnum;
    aco_save_T	aco;
    exarg_T	ea;

    
    newbuf = buflist_new(NULL, NULL, (linenr_T)1, BLN_DUMMY);
    if (newbuf == NULL)
	return TRUE;

    
    if (prep_exarg(&ea, buf) == FAIL)
    {
	wipe_buffer(newbuf, FALSE);
	return TRUE;
    }

    
    aucmd_prepbuf(&aco, newbuf);

    if (ml_open(curbuf) == OK && readfile(buf->b_ffname, buf->b_fname, (linenr_T)0, (linenr_T)0, (linenr_T)MAXLNUM, &ea, READ_NEW | READ_DUMMY) == OK)


    {
	
	if (buf->b_ml.ml_line_count == curbuf->b_ml.ml_line_count)
	{
	    differ = FALSE;
	    for (lnum = 1; lnum <= curbuf->b_ml.ml_line_count; ++lnum)
		if (STRCMP(ml_get_buf(buf, lnum, FALSE), ml_get(lnum)) != 0)
		{
		    differ = TRUE;
		    break;
		}
	}
    }
    vim_free(ea.cmd);

    
    aucmd_restbuf(&aco);

    if (curbuf != newbuf)	
	wipe_buffer(newbuf, FALSE);

    return differ;
}


    void wipe_buffer( buf_T	*buf, int		aucmd)


{
    if (buf->b_fnum == top_file_num - 1)
	--top_file_num;

    if (!aucmd)		    
	block_autocmds();

    close_buffer(NULL, buf, DOBUF_WIPE, FALSE, TRUE);

    if (!aucmd)
	unblock_autocmds();
}
