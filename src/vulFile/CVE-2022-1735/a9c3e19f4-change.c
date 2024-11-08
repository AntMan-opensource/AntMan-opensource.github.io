






    void change_warning(int col)
{
    static char *w_readonly = N_("W10: Warning: Changing a readonly file");

    if (curbuf->b_did_warn == FALSE && curbufIsChanged() == 0 && !autocmd_busy && curbuf->b_p_ro)


    {
	++curbuf_lock;
	apply_autocmds(EVENT_FILECHANGEDRO, NULL, NULL, FALSE, curbuf);
	--curbuf_lock;
	if (!curbuf->b_p_ro)
	    return;

	
	
	msg_start();
	if (msg_row == Rows - 1)
	    msg_col = col;
	msg_source(HL_ATTR(HLF_W));
	msg_puts_attr(_(w_readonly), HL_ATTR(HLF_W) | MSG_HIST);

	set_vim_var_string(VV_WARNINGMSG, (char_u *)_(w_readonly), -1);

	msg_clr_eos();
	(void)msg_end();
	if (msg_silent == 0 && !silent_mode  && time_for_testing != 1  )



	{
	    out_flush();
	    ui_delay(1002L, TRUE); 
	}
	curbuf->b_did_warn = TRUE;
	redraw_cmdline = FALSE;	
	if (msg_row < Rows - 1)
	    showmode();
    }
}


    void changed(void)
{

    if (p_imst == IM_ON_THE_SPOT)
    {
	
	
	
	if (im_is_preediting() && !xim_changed_while_preediting)
	    return;
	xim_changed_while_preediting = FALSE;
    }


    if (!curbuf->b_changed)
    {
	int	save_msg_scroll = msg_scroll;

	
	
	change_warning(0);

	
	
	if (curbuf->b_may_swap  && !bt_dontwrite(curbuf)


		)
	{
	    int save_need_wait_return = need_wait_return;

	    need_wait_return = FALSE;
	    ml_open_file(curbuf);

	    
	    
	    
	    
	    if (need_wait_return && emsg_silent == 0 && !in_assert_fails)
	    {
		out_flush();
		ui_delay(2002L, TRUE);
		wait_return(TRUE);
		msg_scroll = save_msg_scroll;
	    }
	    else need_wait_return = save_need_wait_return;
	}
	changed_internal();
    }
    ++CHANGEDTICK(curbuf);


    
    highlight_match = FALSE;

}


    void changed_internal(void)
{
    curbuf->b_changed = TRUE;
    ml_setflags(curbuf);
    check_status(curbuf);
    redraw_tabline = TRUE;
    need_maketitle = TRUE;	    
}


static long next_listener_id = 0;


    static void check_recorded_changes( buf_T		*buf, linenr_T	lnum, linenr_T	lnume, long		xtra)




{
    if (buf->b_recorded_changes != NULL && xtra != 0)
    {
	listitem_T *li;
	linenr_T    prev_lnum;
	linenr_T    prev_lnume;

	FOR_ALL_LIST_ITEMS(buf->b_recorded_changes, li)
	{
	    prev_lnum = (linenr_T)dict_get_number( li->li_tv.vval.v_dict, (char_u *)"lnum");
	    prev_lnume = (linenr_T)dict_get_number( li->li_tv.vval.v_dict, (char_u *)"end");
	    if (prev_lnum >= lnum || prev_lnum > lnume || prev_lnume >= lnum)
	    {
		
		
		invoke_listeners(curbuf);
		break;
	    }
	}
    }
}


    static void may_record_change( linenr_T	lnum, colnr_T	col, linenr_T	lnume, long	xtra)




{
    dict_T	*dict;

    if (curbuf->b_listener == NULL)
	return;

    
    
    check_recorded_changes(curbuf, lnum, lnume, xtra);

    if (curbuf->b_recorded_changes == NULL)
    {
	curbuf->b_recorded_changes = list_alloc();
	if (curbuf->b_recorded_changes == NULL)  
	    return;
	++curbuf->b_recorded_changes->lv_refcount;
	curbuf->b_recorded_changes->lv_lock = VAR_FIXED;
    }

    dict = dict_alloc();
    if (dict == NULL)
	return;
    dict_add_number(dict, "lnum", (varnumber_T)lnum);
    dict_add_number(dict, "end", (varnumber_T)lnume);
    dict_add_number(dict, "added", (varnumber_T)xtra);
    dict_add_number(dict, "col", (varnumber_T)col + 1);

    list_append_dict(curbuf->b_recorded_changes, dict);
}


    void f_listener_add(typval_T *argvars, typval_T *rettv)
{
    callback_T	callback;
    listener_T	*lnr;
    buf_T	*buf = curbuf;

    if (in_vim9script() && check_for_opt_buffer_arg(argvars, 1) == FAIL)
	return;

    callback = get_callback(&argvars[0]);
    if (callback.cb_name == NULL)
	return;

    if (argvars[1].v_type != VAR_UNKNOWN)
    {
	buf = get_buf_arg(&argvars[1]);
	if (buf == NULL)
	{
	    free_callback(&callback);
	    return;
	}
    }

    lnr = ALLOC_CLEAR_ONE(listener_T);
    if (lnr == NULL)
    {
	free_callback(&callback);
	return;
    }
    lnr->lr_next = buf->b_listener;
    buf->b_listener = lnr;

    set_callback(&lnr->lr_callback, &callback);

    lnr->lr_id = ++next_listener_id;
    rettv->vval.v_number = lnr->lr_id;
}


    void f_listener_flush(typval_T *argvars, typval_T *rettv UNUSED)
{
    buf_T	*buf = curbuf;

    if (in_vim9script() && check_for_opt_buffer_arg(argvars, 0) == FAIL)
	return;

    if (argvars[0].v_type != VAR_UNKNOWN)
    {
	buf = get_buf_arg(&argvars[0]);
	if (buf == NULL)
	    return;
    }
    invoke_listeners(buf);
}


    static void remove_listener(buf_T *buf, listener_T *lnr, listener_T *prev)
{
    if (prev != NULL)
	prev->lr_next = lnr->lr_next;
    else buf->b_listener = lnr->lr_next;
    free_callback(&lnr->lr_callback);
    vim_free(lnr);
}


    void f_listener_remove(typval_T *argvars, typval_T *rettv)
{
    listener_T	*lnr;
    listener_T	*next;
    listener_T	*prev;
    int		id;
    buf_T	*buf;

    if (in_vim9script() && check_for_number_arg(argvars, 0) == FAIL)
	return;

    id = tv_get_number(argvars);
    FOR_ALL_BUFFERS(buf)
    {
	prev = NULL;
	for (lnr = buf->b_listener; lnr != NULL; lnr = next)
	{
	    next = lnr->lr_next;
	    if (lnr->lr_id == id)
	    {
		if (textwinlock > 0)
		{
		    
		    lnr->lr_id = 0;
		    return;
		}
		remove_listener(buf, lnr, prev);
		rettv->vval.v_number = 1;
		return;
	    }
	    prev = lnr;
	}
    }
}


    void may_invoke_listeners(buf_T *buf, linenr_T lnum, linenr_T lnume, int added)
{
    check_recorded_changes(buf, lnum, lnume, added);
}


    void invoke_listeners(buf_T *buf)
{
    listener_T	*lnr;
    typval_T	rettv;
    typval_T	argv[6];
    listitem_T	*li;
    linenr_T	start = MAXLNUM;
    linenr_T	end = 0;
    linenr_T	added = 0;
    int		save_updating_screen = updating_screen;
    static int	recursive = FALSE;
    listener_T	*next;

    if (buf->b_recorded_changes == NULL   || buf->b_listener == NULL || recursive)

	return;
    recursive = TRUE;

    
    
    ++updating_screen;

    argv[0].v_type = VAR_NUMBER;
    argv[0].vval.v_number = buf->b_fnum; 

    FOR_ALL_LIST_ITEMS(buf->b_recorded_changes, li)
    {
	varnumber_T lnum;

	lnum = dict_get_number(li->li_tv.vval.v_dict, (char_u *)"lnum");
	if (start > lnum)
	    start = lnum;
	lnum = dict_get_number(li->li_tv.vval.v_dict, (char_u *)"end");
	if (end < lnum)
	    end = lnum;
	added += dict_get_number(li->li_tv.vval.v_dict, (char_u *)"added");
    }
    argv[1].v_type = VAR_NUMBER;
    argv[1].vval.v_number = start;
    argv[2].v_type = VAR_NUMBER;
    argv[2].vval.v_number = end;
    argv[3].v_type = VAR_NUMBER;
    argv[3].vval.v_number = added;

    argv[4].v_type = VAR_LIST;
    argv[4].vval.v_list = buf->b_recorded_changes;
    ++textwinlock;

    for (lnr = buf->b_listener; lnr != NULL; lnr = lnr->lr_next)
    {
	call_callback(&lnr->lr_callback, -1, &rettv, 5, argv);
	clear_tv(&rettv);
    }

    
    for (lnr = buf->b_listener; lnr != NULL; lnr = next)
    {
	listener_T	*prev = NULL;

	next = lnr->lr_next;
	if (lnr->lr_id == 0)
	    remove_listener(buf, lnr, prev);
	else prev = lnr;
    }

    --textwinlock;
    list_unref(buf->b_recorded_changes);
    buf->b_recorded_changes = NULL;

    if (save_updating_screen)
	updating_screen = TRUE;
    else after_updating_screen(TRUE);
    recursive = FALSE;
}


    void remove_listeners(buf_T *buf)
{
    listener_T	*lnr;
    listener_T	*next;

    for (lnr = buf->b_listener; lnr != NULL; lnr = next)
    {
	next = lnr->lr_next;
	free_callback(&lnr->lr_callback);
	vim_free(lnr);
    }
    buf->b_listener = NULL;
}



    static void changed_common( linenr_T	lnum, colnr_T	col, linenr_T	lnume, long	xtra)




{
    win_T	*wp;
    tabpage_T	*tp;
    int		i;
    int		cols;
    pos_T	*p;
    int		add;

    
    changed();


    may_record_change(lnum, col, lnume, xtra);


    if (curwin->w_p_diff && diff_internal())
	curtab->tp_diff_update = TRUE;


    
    if ((cmdmod.cmod_flags & CMOD_KEEPJUMPS) == 0)
    {
	curbuf->b_last_change.lnum = lnum;
	curbuf->b_last_change.col = col;

	
	
	if (curbuf->b_new_change || curbuf->b_changelistlen == 0)
	{
	    if (curbuf->b_changelistlen == 0)
		add = TRUE;
	    else {
		
		
		
		p = &curbuf->b_changelist[curbuf->b_changelistlen - 1];
		if (p->lnum != lnum)
		    add = TRUE;
		else {
		    cols = comp_textwidth(FALSE);
		    if (cols == 0)
			cols = 79;
		    add = (p->col + cols < col || col + cols < p->col);
		}
	    }
	    if (add)
	    {
		
		
		
		curbuf->b_new_change = FALSE;

		if (curbuf->b_changelistlen == JUMPLISTSIZE)
		{
		    
		    curbuf->b_changelistlen = JUMPLISTSIZE - 1;
		    mch_memmove(curbuf->b_changelist, curbuf->b_changelist + 1, sizeof(pos_T) * (JUMPLISTSIZE - 1));
		    FOR_ALL_TAB_WINDOWS(tp, wp)
		    {
			
			
			if (wp->w_buffer == curbuf && wp->w_changelistidx > 0)
			    --wp->w_changelistidx;
		    }
		}
		FOR_ALL_TAB_WINDOWS(tp, wp)
		{
		    
		    
		    if (wp->w_buffer == curbuf && wp->w_changelistidx == curbuf->b_changelistlen)
			++wp->w_changelistidx;
		}
		++curbuf->b_changelistlen;
	    }
	}
	curbuf->b_changelist[curbuf->b_changelistlen - 1] = curbuf->b_last_change;
	
	
	curwin->w_changelistidx = curbuf->b_changelistlen;
    }

    FOR_ALL_TAB_WINDOWS(tp, wp)
    {
	if (wp->w_buffer == curbuf)
	{

	    linenr_T last = lnume + xtra - 1;  

	    
	    if (wp->w_redr_type < VALID)
		wp->w_redr_type = VALID;

	    
	    

	    
	    
	    foldUpdate(wp, lnum, last);

	    
	    
	    
	    
	    
	    i = hasFoldingWin(wp, lnum, &lnum, NULL, FALSE, NULL);
	    if (wp->w_cursor.lnum == lnum)
		wp->w_cline_folded = i;
	    i = hasFoldingWin(wp, last, NULL, &last, FALSE, NULL);
	    if (wp->w_cursor.lnum == last)
		wp->w_cline_folded = i;

	    
	    
	    if (wp->w_cursor.lnum <= lnum)
	    {
		i = find_wl_entry(wp, lnum);
		if (i >= 0 && wp->w_cursor.lnum > wp->w_lines[i].wl_lnum)
		    changed_line_abv_curs_win(wp);
	    }

	    if (wp->w_cursor.lnum > lnum)
		changed_line_abv_curs_win(wp);
	    else if (wp->w_cursor.lnum == lnum && wp->w_cursor.col >= col)
		changed_cline_bef_curs_win(wp);
	    if (wp->w_botline >= lnum)
	    {
		if (xtra < 0)
		    invalidate_botline_win(wp);
		else   approximate_botline_win(wp);


	    }

	    
	    
	    
	    
	    for (i = 0; i < wp->w_lines_valid; ++i)
		if (wp->w_lines[i].wl_valid)
		{
		    if (wp->w_lines[i].wl_lnum >= lnum)
		    {
			if (wp->w_lines[i].wl_lnum < lnume)
			{
			    
			    wp->w_lines[i].wl_valid = FALSE;
			}
			else if (xtra != 0)
			{
			    
			    wp->w_lines[i].wl_lnum += xtra;

			    wp->w_lines[i].wl_lastlnum += xtra;

			}
		    }

		    else if (wp->w_lines[i].wl_lastlnum >= lnum)
		    {
			
			
			wp->w_lines[i].wl_valid = FALSE;
		    }

		}


	    
	    
	    if (hasAnyFolding(wp))
		set_topline(wp, wp->w_topline);

	    
	    
	    if (wp->w_p_rnu && xtra != 0)
	    {
		wp->w_last_cursor_lnum_rnu = 0;
		redraw_win_later(wp, VALID);
	    }

	    
	    
	    
	    if (wp->w_p_cul)
	    {
		if (xtra == 0)
		    redraw_win_later(wp, VALID);
		else if (lnum <= wp->w_last_cursorline)
		    redraw_win_later(wp, SOME_VALID);
	    }

	}
    }

    
    
    if (must_redraw < VALID)
	must_redraw = VALID;

    
    if (lnum <= curwin->w_cursor.lnum && lnume + (xtra < 0 ? -xtra : xtra) > curwin->w_cursor.lnum)
	last_cursormoved.lnum = 0;
}

    static void changedOneline(buf_T *buf, linenr_T lnum)
{
    if (buf->b_mod_set)
    {
	
	if (lnum < buf->b_mod_top)
	    buf->b_mod_top = lnum;
	else if (lnum >= buf->b_mod_bot)
	    buf->b_mod_bot = lnum + 1;
    }
    else {
	
	buf->b_mod_set = TRUE;
	buf->b_mod_top = lnum;
	buf->b_mod_bot = lnum + 1;
	buf->b_mod_xlines = 0;
    }
}


    void changed_bytes(linenr_T lnum, colnr_T col)
{
    changedOneline(curbuf, lnum);
    changed_common(lnum, col, lnum + 1, 0L);


    
    if (curwin->w_p_diff)
    {
	win_T	    *wp;
	linenr_T    wlnum;

	FOR_ALL_WINDOWS(wp)
	    if (wp->w_p_diff && wp != curwin)
	    {
		redraw_win_later(wp, VALID);
		wlnum = diff_lnum_win(lnum, wp);
		if (wlnum > 0)
		    changedOneline(wp->w_buffer, wlnum);
	    }
    }

}


    void inserted_bytes(linenr_T lnum, colnr_T col, int added UNUSED)
{

    if (curbuf->b_has_textprop && added != 0)
	adjust_prop_columns(lnum, col, added, 0);


    changed_bytes(lnum, col);
}


    void appended_lines(linenr_T lnum, long count)
{
    changed_lines(lnum + 1, 0, lnum + 1, count);
}


    void appended_lines_mark(linenr_T lnum, long count)
{
    
    
    if (lnum + count < curbuf->b_ml.ml_line_count  || curwin->w_p_diff  )



	mark_adjust(lnum + 1, (linenr_T)MAXLNUM, count, 0L);
    changed_lines(lnum + 1, 0, lnum + 1, count);
}


    void deleted_lines(linenr_T lnum, long count)
{
    changed_lines(lnum, 0, lnum + count, -count);
}


    void deleted_lines_mark(linenr_T lnum, long count)
{
    mark_adjust(lnum, (linenr_T)(lnum + count - 1), (long)MAXLNUM, -count);
    changed_lines(lnum, 0, lnum + count, -count);
}


    void changed_lines_buf( buf_T	*buf, linenr_T	lnum, linenr_T	lnume, long	xtra)




{
    if (buf->b_mod_set)
    {
	
	if (lnum < buf->b_mod_top)
	    buf->b_mod_top = lnum;
	if (lnum < buf->b_mod_bot)
	{
	    
	    buf->b_mod_bot += xtra;
	    if (buf->b_mod_bot < lnum)
		buf->b_mod_bot = lnum;
	}
	if (lnume + xtra > buf->b_mod_bot)
	    buf->b_mod_bot = lnume + xtra;
	buf->b_mod_xlines += xtra;
    }
    else {
	
	buf->b_mod_set = TRUE;
	buf->b_mod_top = lnum;
	buf->b_mod_bot = lnume + xtra;
	buf->b_mod_xlines = xtra;
    }
}


    void changed_lines( linenr_T	lnum, colnr_T	col, linenr_T	lnume, long	xtra)




{
    changed_lines_buf(curbuf, lnum, lnume, xtra);


    if (xtra == 0 && curwin->w_p_diff && !diff_internal())
    {
	
	
	
	win_T	    *wp;
	linenr_T    wlnum;

	FOR_ALL_WINDOWS(wp)
	    if (wp->w_p_diff && wp != curwin)
	    {
		redraw_win_later(wp, VALID);
		wlnum = diff_lnum_win(lnum, wp);
		if (wlnum > 0)
		    changed_lines_buf(wp->w_buffer, wlnum, lnume - lnum + wlnum, 0L);
	    }
    }


    changed_common(lnum, col, lnume, xtra);
}


    void unchanged(buf_T *buf, int ff, int always_inc_changedtick)
{
    if (buf->b_changed || (ff && file_ff_differs(buf, FALSE)))
    {
	buf->b_changed = 0;
	ml_setflags(buf);
	if (ff)
	    save_file_ff(buf);
	check_status(buf);
	redraw_tabline = TRUE;
	need_maketitle = TRUE;	    
	++CHANGEDTICK(buf);
    }
    else if (always_inc_changedtick)
	++CHANGEDTICK(buf);

    netbeans_unmodified(buf);

}


    void save_file_ff(buf_T *buf)
{
    buf->b_start_ffc = *buf->b_p_ff;
    buf->b_start_eol = buf->b_p_eol;
    buf->b_start_bomb = buf->b_p_bomb;

    
    if (buf->b_start_fenc == NULL || STRCMP(buf->b_start_fenc, buf->b_p_fenc) != 0)
    {
	vim_free(buf->b_start_fenc);
	buf->b_start_fenc = vim_strsave(buf->b_p_fenc);
    }
}


    int file_ff_differs(buf_T *buf, int ignore_empty)
{
    
    if (buf->b_flags & BF_NEVERLOADED)
	return FALSE;
    if (ignore_empty && (buf->b_flags & BF_NEW)
	    && buf->b_ml.ml_line_count == 1 && *ml_get_buf(buf, (linenr_T)1, FALSE) == NUL)
	return FALSE;
    if (buf->b_start_ffc != *buf->b_p_ff)
	return TRUE;
    if ((buf->b_p_bin || !buf->b_p_fixeol) && buf->b_start_eol != buf->b_p_eol)
	return TRUE;
    if (!buf->b_p_bin && buf->b_start_bomb != buf->b_p_bomb)
	return TRUE;
    if (buf->b_start_fenc == NULL)
	return (*buf->b_p_fenc != NUL);
    return (STRCMP(buf->b_start_fenc, buf->b_p_fenc) != 0);
}


    void ins_bytes(char_u *p)
{
    ins_bytes_len(p, (int)STRLEN(p));
}


    void ins_bytes_len(char_u *p, int len)
{
    int		i;
    int		n;

    if (has_mbyte)
	for (i = 0; i < len; i += n)
	{
	    if (enc_utf8)
		
		n = utfc_ptr2len_len(p + i, len - i);
	    else n = (*mb_ptr2len)(p + i);
	    ins_char_bytes(p + i, n);
	}
    else for (i = 0; i < len; ++i)
	    ins_char(p[i]);
}


    void ins_char(int c)
{
    char_u	buf[MB_MAXBYTES + 1];
    int		n = (*mb_char2bytes)(c, buf);

    
    
    if (buf[0] == 0)
	buf[0] = '\n';

    ins_char_bytes(buf, n);
}

    void ins_char_bytes(char_u *buf, int charlen)
{
    int		c = buf[0];
    int		newlen;		
    int		oldlen;		
    char_u	*p;
    char_u	*newp;
    char_u	*oldp;
    int		linelen;	
    colnr_T	col;
    linenr_T	lnum = curwin->w_cursor.lnum;
    int		i;

    
    if (virtual_active() && curwin->w_cursor.coladd > 0)
	coladvance_force(getviscol());

    col = curwin->w_cursor.col;
    oldp = ml_get(lnum);
    linelen = (int)STRLEN(oldp) + 1;

    
    oldlen = 0;
    newlen = charlen;

    if (State & REPLACE_FLAG)
    {
	if (State & VREPLACE_FLAG)
	{
	    colnr_T	new_vcol = 0;   
	    colnr_T	vcol;
	    int		old_list;

	    
	    
	    
	    old_list = curwin->w_p_list;
	    if (old_list && vim_strchr(p_cpo, CPO_LISTWM) == NULL)
		curwin->w_p_list = FALSE;

	    
	    
	    
	    
	    getvcol(curwin, &curwin->w_cursor, NULL, &vcol, NULL);
	    new_vcol = vcol + chartabsize(buf, vcol);
	    while (oldp[col + oldlen] != NUL && vcol < new_vcol)
	    {
		vcol += chartabsize(oldp + col + oldlen, vcol);
		
		
		if (vcol > new_vcol && oldp[col + oldlen] == TAB)
		    break;
		oldlen += (*mb_ptr2len)(oldp + col + oldlen);
		
		if (vcol > new_vcol)
		    newlen += vcol - new_vcol;
	    }
	    curwin->w_p_list = old_list;
	}
	else if (oldp[col] != NUL)
	{
	    
	    oldlen = (*mb_ptr2len)(oldp + col);
	}


	
	
	
	
	replace_push(NUL);
	for (i = 0; i < oldlen; ++i)
	{
	    if (has_mbyte)
		i += replace_push_mb(oldp + col + i) - 1;
	    else replace_push(oldp[col + i]);
	}
    }

    newp = alloc(linelen + newlen - oldlen);
    if (newp == NULL)
	return;

    
    if (col > 0)
	mch_memmove(newp, oldp, (size_t)col);

    
    p = newp + col;
    if (linelen > col + oldlen)
	mch_memmove(p + newlen, oldp + col + oldlen, (size_t)(linelen - col - oldlen));

    
    mch_memmove(p, buf, charlen);
    i = charlen;

    
    while (i < newlen)
	p[i++] = ' ';

    
    ml_replace(lnum, newp, FALSE);

    
    inserted_bytes(lnum, col, newlen - oldlen);

    
    
    if (p_sm && (State & MODE_INSERT)
	    && msg_silent == 0 && !ins_compl_active())
    {
	if (has_mbyte)
	    showmatch(mb_ptr2char(buf));
	else showmatch(c);
    }


    if (!p_ri || (State & REPLACE_FLAG))

    {
	
	curwin->w_cursor.col += charlen;
    }

    
}


    void ins_str(char_u *s)
{
    char_u	*oldp, *newp;
    int		newlen = (int)STRLEN(s);
    int		oldlen;
    colnr_T	col;
    linenr_T	lnum = curwin->w_cursor.lnum;

    if (virtual_active() && curwin->w_cursor.coladd > 0)
	coladvance_force(getviscol());

    col = curwin->w_cursor.col;
    oldp = ml_get(lnum);
    oldlen = (int)STRLEN(oldp);

    newp = alloc(oldlen + newlen + 1);
    if (newp == NULL)
	return;
    if (col > 0)
	mch_memmove(newp, oldp, (size_t)col);
    mch_memmove(newp + col, s, (size_t)newlen);
    mch_memmove(newp + col + newlen, oldp + col, (size_t)(oldlen - col + 1));
    ml_replace(lnum, newp, FALSE);
    inserted_bytes(lnum, col, newlen);
    curwin->w_cursor.col += newlen;
}


    int del_char(int fixpos)
{
    if (has_mbyte)
    {
	
	mb_adjust_cursor();
	if (*ml_get_cursor() == NUL)
	    return FAIL;
	return del_chars(1L, fixpos);
    }
    return del_bytes(1L, fixpos, TRUE);
}


    int del_chars(long count, int fixpos)
{
    long	bytes = 0;
    long	i;
    char_u	*p;
    int		l;

    p = ml_get_cursor();
    for (i = 0; i < count && *p != NUL; ++i)
    {
	l = (*mb_ptr2len)(p);
	bytes += l;
	p += l;
    }
    return del_bytes(bytes, fixpos, TRUE);
}


    int del_bytes( long	count, int		fixpos_arg, int		use_delcombine UNUSED)



{
    char_u	*oldp, *newp;
    colnr_T	oldlen;
    colnr_T	newlen;
    linenr_T	lnum = curwin->w_cursor.lnum;
    colnr_T	col = curwin->w_cursor.col;
    int		alloc_newp;
    long	movelen;
    int		fixpos = fixpos_arg;

    oldp = ml_get(lnum);
    oldlen = (int)STRLEN(oldp);

    
    if (col >= oldlen)
	return FAIL;

    
    if (count == 0)
	return OK;

    
    if (count < 1)
    {
	siemsg(e_invalid_count_for_del_bytes_nr, count);
	return FAIL;
    }

    
    
    if (p_deco && use_delcombine && enc_utf8 && utfc_ptr2len(oldp + col) >= count)
    {
	int	cc[MAX_MCO];
	int	n;

	(void)utfc_ptr2char(oldp + col, cc);
	if (cc[0] != NUL)
	{
	    
	    n = col;
	    do {
		col = n;
		count = utf_ptr2len(oldp + n);
		n += count;
	    } while (UTF_COMPOSINGLIKE(oldp + col, oldp + n));
	    fixpos = 0;
	}
    }

    
    movelen = (long)oldlen - (long)col - count + 1; 
    if (movelen <= 1)
    {
	
	
	
	if (col > 0 && fixpos && restart_edit == 0 && (get_ve_flags() & VE_ONEMORE) == 0)
	{
	    --curwin->w_cursor.col;
	    curwin->w_cursor.coladd = 0;
	    if (has_mbyte)
		curwin->w_cursor.col -= (*mb_head_off)(oldp, oldp + curwin->w_cursor.col);
	}
	count = oldlen - col;
	movelen = 1;
    }
    newlen = oldlen - count;

    
    
    
    
    

    if (netbeans_active())
	alloc_newp = TRUE;
    else  alloc_newp = !ml_line_alloced();

    if (!alloc_newp)
	newp = oldp;			    
    else {
	newp = alloc(newlen + 1);
	if (newp == NULL)
	    return FAIL;
	mch_memmove(newp, oldp, (size_t)col);
    }
    mch_memmove(newp + col, oldp + col + count, (size_t)movelen);
    if (alloc_newp)
	ml_replace(lnum, newp, FALSE);

    else {
	
	if (oldlen + 1 < curbuf->b_ml.ml_line_len)
	    mch_memmove(newp + newlen + 1, oldp + oldlen + 1, (size_t)curbuf->b_ml.ml_line_len - oldlen - 1);
	curbuf->b_ml.ml_line_len -= count;
    }


    
    inserted_bytes(lnum, col, -count);

    return OK;
}


    int open_line( int		dir, int		flags, int		second_line_indent, int		*did_do_comment UNUSED)




{
    char_u	*saved_line;		
    char_u	*next_line = NULL;	
    char_u	*p_extra = NULL;	
    int		less_cols = 0;		
    int		less_cols_off = 0;	
					
    pos_T	old_cursor;		
    int		newcol = 0;		
    int		newindent = 0;		
    int		n;
    int		trunc_line = FALSE;	
    int		retval = FAIL;		
    int		extra_len = 0;		
    int		lead_len;		
    int		comment_start = 0;	
    char_u	*lead_flags;	
    char_u	*leader = NULL;		
    char_u	*allocated = NULL;	
    char_u	*p;
    int		saved_char = NUL;	
    pos_T	*pos;

    int		do_cindent;


    int		do_si = may_do_si();
    int		no_si = FALSE;		
    int		first_char = NUL;	


    int		vreplace_mode;

    int		did_append;		
    int		saved_pi = curbuf->b_p_pi; 

    
    saved_line = vim_strsave(ml_get_curline());
    if (saved_line == NULL)	    
	return FALSE;

    if (State & VREPLACE_FLAG)
    {
	
	
	
	
	
	
	
	if (curwin->w_cursor.lnum < orig_line_count)
	    next_line = vim_strsave(ml_get(curwin->w_cursor.lnum + 1));
	else next_line = vim_strsave((char_u *)"");
	if (next_line == NULL)	    
	    goto theend;

	
	
	
	
	
	replace_push(NUL);  
	replace_push(NUL);
	p = saved_line + curwin->w_cursor.col;
	while (*p != NUL)
	{
	    if (has_mbyte)
		p += replace_push_mb(p);
	    else replace_push(*p++);
	}
	saved_line[curwin->w_cursor.col] = NUL;
    }

    if ((State & MODE_INSERT) && (State & VREPLACE_FLAG) == 0)
    {
	p_extra = saved_line + curwin->w_cursor.col;

	if (do_si)		
	{
	    p = skipwhite(p_extra);
	    first_char = *p;
	}

	extra_len = (int)STRLEN(p_extra);
	saved_char = *p_extra;
	*p_extra = NUL;
    }

    u_clearline();		

    did_si = FALSE;

    ai_col = 0;

    
    
    
    if (dir == FORWARD && did_ai)
	trunc_line = TRUE;

    
    
    if (curbuf->b_p_ai  || do_si  )



    {
	

	newindent = get_indent_str_vtab(saved_line, curbuf->b_p_ts, curbuf->b_p_vts_array, FALSE);

	newindent = get_indent_str(saved_line, (int)curbuf->b_p_ts, FALSE);

	if (newindent == 0 && !(flags & OPENLINE_COM_LIST))
	    newindent = second_line_indent; 


	
	
	
	
	
	if (!trunc_line && do_si && *saved_line != NUL && (p_extra == NULL || first_char != '{'))
	{
	    char_u  *ptr;
	    char_u  last_char;

	    old_cursor = curwin->w_cursor;
	    ptr = saved_line;
	    if (flags & OPENLINE_DO_COM)
		lead_len = get_leader_len(ptr, NULL, FALSE, TRUE);
	    else lead_len = 0;
	    if (dir == FORWARD)
	    {
		
		
		if ( lead_len == 0 && ptr[0] == '#')
		{
		    while (ptr[0] == '#' && curwin->w_cursor.lnum > 1)
			ptr = ml_get(--curwin->w_cursor.lnum);
		    newindent = get_indent();
		}
		if (flags & OPENLINE_DO_COM)
		    lead_len = get_leader_len(ptr, NULL, FALSE, TRUE);
		else lead_len = 0;
		if (lead_len > 0)
		{
		    
		    
		    
		    
		    
		    
		    p = skipwhite(ptr);
		    if (p[0] == '/' && p[1] == '*')
			p++;
		    if (p[0] == '*')
		    {
			for (p++; *p; p++)
			{
			    if (p[0] == '/' && p[-1] == '*')
			    {
				
				
				
				curwin->w_cursor.col = (colnr_T)(p - ptr);
				if ((pos = findmatch(NULL, NUL)) != NULL)
				{
				    curwin->w_cursor.lnum = pos->lnum;
				    newindent = get_indent();
				}
			    }
			}
		    }
		}
		else	 {
		    
		    p = ptr + STRLEN(ptr) - 1;
		    while (p > ptr && VIM_ISWHITE(*p))
			--p;
		    last_char = *p;

		    
		    if (last_char == '{' || last_char == ';')
		    {
			if (p > ptr)
			    --p;
			while (p > ptr && VIM_ISWHITE(*p))
			    --p;
		    }
		    
		    
		    
		    
		    
		    
		    if (*p == ')')
		    {
			curwin->w_cursor.col = (colnr_T)(p - ptr);
			if ((pos = findmatch(NULL, '(')) != NULL)
			{
			    curwin->w_cursor.lnum = pos->lnum;
			    newindent = get_indent();
			    ptr = ml_get_curline();
			}
		    }
		    
		    
		    if (last_char == '{')
		    {
			did_si = TRUE;	
			no_si = TRUE;	
		    }
		    
		    
		    
		    else if (last_char != ';' && last_char != '}' && cin_is_cinword(ptr))
			did_si = TRUE;
		}
	    }
	    else  {
		
		
		if (lead_len == 0 && ptr[0] == '#')
		{
		    int was_backslashed = FALSE;

		    while ((ptr[0] == '#' || was_backslashed) && curwin->w_cursor.lnum < curbuf->b_ml.ml_line_count)
		    {
			if (*ptr && ptr[STRLEN(ptr) - 1] == '\\')
			    was_backslashed = TRUE;
			else was_backslashed = FALSE;
			ptr = ml_get(++curwin->w_cursor.lnum);
		    }
		    if (was_backslashed)
			newindent = 0;	    
		    else newindent = get_indent();
		}
		p = skipwhite(ptr);
		if (*p == '}')	    
		    did_si = TRUE;
		else		     can_si_back = TRUE;
	    }
	    curwin->w_cursor = old_cursor;
	}
	if (do_si)
	    can_si = TRUE;


	did_ai = TRUE;
    }


    
    do_cindent = !p_paste && (curbuf->b_p_cin  || *curbuf->b_p_inde != NUL  )



	    && in_cinkeys(dir == FORWARD ? KEY_OPEN_FORW : KEY_OPEN_BACK, ' ', linewhite(curwin->w_cursor.lnum));



    
    
    end_comment_pending = NUL;
    if (flags & OPENLINE_DO_COM)
    {
	lead_len = get_leader_len(saved_line, &lead_flags, dir == BACKWARD, TRUE);

	if (lead_len == 0 && curbuf->b_p_cin && do_cindent && dir == FORWARD && !has_format_option(FO_NO_OPEN_COMS))
	{
	    
	    comment_start = check_linecomment(saved_line);
	    if (comment_start != MAXCOL)
	    {
		lead_len = get_leader_len(saved_line + comment_start, &lead_flags, FALSE, TRUE);
		if (lead_len != 0)
		{
		    lead_len += comment_start;
		    if (did_do_comment != NULL)
			*did_do_comment = TRUE;
		}
	    }
	}

    }
    else lead_len = 0;
    if (lead_len > 0)
    {
	char_u	*lead_repl = NULL;	    
	int	lead_repl_len = 0;	    
	char_u	lead_middle[COM_MAX_LEN];   
	char_u	lead_end[COM_MAX_LEN];	    
	char_u	*comment_end = NULL;	    
	int	extra_space = FALSE;	    
	int	current_flag;
	int	require_blank = FALSE;	    
	char_u	*p2;

	
	
	for (p = lead_flags; *p && *p != ':'; ++p)
	{
	    if (*p == COM_BLANK)
	    {
		require_blank = TRUE;
		continue;
	    }
	    if (*p == COM_START || *p == COM_MIDDLE)
	    {
		current_flag = *p;
		if (*p == COM_START)
		{
		    
		    if (dir == BACKWARD)
		    {
			lead_len = 0;
			break;
		    }

		    
		    (void)copy_option_part(&p, lead_middle, COM_MAX_LEN, ",");
		    require_blank = FALSE;
		}

		
		while (*p && p[-1] != ':')	
		{
		    if (*p == COM_BLANK)
			require_blank = TRUE;
		    ++p;
		}
		(void)copy_option_part(&p, lead_middle, COM_MAX_LEN, ",");

		while (*p && p[-1] != ':')	
		{
		    
		    if (*p == COM_AUTO_END)
			end_comment_pending = -1; 
		    ++p;
		}
		n = copy_option_part(&p, lead_end, COM_MAX_LEN, ",");

		if (end_comment_pending == -1)	
		    end_comment_pending = lead_end[n - 1];

		
		
		if (dir == FORWARD)
		{
		    for (p = saved_line + lead_len; *p; ++p)
			if (STRNCMP(p, lead_end, n) == 0)
			{
			    comment_end = p;
			    lead_len = 0;
			    break;
			}
		}

		
		if (lead_len > 0)
		{
		    if (current_flag == COM_START)
		    {
			lead_repl = lead_middle;
			lead_repl_len = (int)STRLEN(lead_middle);
		    }

		    
		    
		    
		    if (!VIM_ISWHITE(saved_line[lead_len - 1])
			    && ((p_extra != NULL && (int)curwin->w_cursor.col == lead_len)
				|| (p_extra == NULL && saved_line[lead_len] == NUL)
				|| require_blank))
			extra_space = TRUE;
		}
		break;
	    }
	    if (*p == COM_END)
	    {
		
		
		
		if (dir == FORWARD)
		{
		    comment_end = skipwhite(saved_line);
		    lead_len = 0;
		    break;
		}

		
		
		while (p > curbuf->b_p_com && *p != ',')
		    --p;
		for (lead_repl = p; lead_repl > curbuf->b_p_com && lead_repl[-1] != ':'; --lead_repl)
		    ;
		lead_repl_len = (int)(p - lead_repl);

		
		
		extra_space = TRUE;

		
		for (p2 = p; *p2 && *p2 != ':'; p2++)
		{
		    if (*p2 == COM_AUTO_END)
			end_comment_pending = -1; 
		}
		if (end_comment_pending == -1)
		{
		    
		    while (*p2 && *p2 != ',')
			p2++;
		    end_comment_pending = p2[-1];
		}
		break;
	    }
	    if (*p == COM_FIRST)
	    {
		
		
		if (dir == BACKWARD)
		    lead_len = 0;
		else {
		    lead_repl = (char_u *)"";
		    lead_repl_len = 0;
		}
		break;
	    }
	}
	if (lead_len)
	{
	    
	    leader = alloc(lead_len + lead_repl_len + extra_space + extra_len + (second_line_indent > 0 ? second_line_indent : 0) + 1);
	    allocated = leader;		    

	    if (leader == NULL)
		lead_len = 0;
	    else {
		int li;

		vim_strncpy(leader, saved_line, lead_len);

		
		for (li = 0; li < comment_start; ++li)
		    if (!VIM_ISWHITE(leader[li]))
			leader[li] = ' ';

		
		if (lead_repl != NULL)
		{
		    int		c = 0;
		    int		off = 0;

		    for (p = lead_flags; *p != NUL && *p != ':'; )
		    {
			if (*p == COM_RIGHT || *p == COM_LEFT)
			    c = *p++;
			else if (VIM_ISDIGIT(*p) || *p == '-')
			    off = getdigits(&p);
			else ++p;
		    }
		    if (c == COM_RIGHT)    
		    {
			
			for (p = leader + lead_len - 1; p > leader && VIM_ISWHITE(*p); --p)
			    ;
			++p;

			
			
			{
			    int	    repl_size = vim_strnsize(lead_repl, lead_repl_len);
			    int	    old_size = 0;
			    char_u  *endp = p;
			    int	    l;

			    while (old_size < repl_size && p > leader)
			    {
				MB_PTR_BACK(leader, p);
				old_size += ptr2cells(p);
			    }
			    l = lead_repl_len - (int)(endp - p);
			    if (l != 0)
				mch_memmove(endp + l, endp, (size_t)((leader + lead_len) - endp));
			    lead_len += l;
			}
			mch_memmove(p, lead_repl, (size_t)lead_repl_len);
			if (p + lead_repl_len > leader + lead_len)
			    p[lead_repl_len] = NUL;

			
			while (--p >= leader)
			{
			    int l = mb_head_off(leader, p);

			    if (l > 1)
			    {
				p -= l;
				if (ptr2cells(p) > 1)
				{
				    p[1] = ' ';
				    --l;
				}
				mch_memmove(p + 1, p + l + 1, (size_t)((leader + lead_len) - (p + l + 1)));
				lead_len -= l;
				*p = ' ';
			    }
			    else if (!VIM_ISWHITE(*p))
				*p = ' ';
			}
		    }
		    else	 {
			p = skipwhite(leader);

			
			
			
			{
			    int	    repl_size = vim_strnsize(lead_repl, lead_repl_len);
			    int	    i;
			    int	    l;

			    for (i = 0; i < lead_len && p[i] != NUL; i += l)
			    {
				l = (*mb_ptr2len)(p + i);
				if (vim_strnsize(p, i + l) > repl_size)
				    break;
			    }
			    if (i != lead_repl_len)
			    {
				mch_memmove(p + lead_repl_len, p + i, (size_t)(lead_len - i - (p - leader)));
				lead_len += lead_repl_len - i;
			    }
			}
			mch_memmove(p, lead_repl, (size_t)lead_repl_len);

			
			
			
			for (p += lead_repl_len; p < leader + lead_len; ++p)
			    if (!VIM_ISWHITE(*p))
			    {
				
				if (p + 1 < leader + lead_len && p[1] == TAB)
				{
				    --lead_len;
				    mch_memmove(p, p + 1, (leader + lead_len) - p);
				}
				else {
				    int	    l = (*mb_ptr2len)(p);

				    if (l > 1)
				    {
					if (ptr2cells(p) > 1)
					{
					    
					    
					    --l;
					    *p++ = ' ';
					}
					mch_memmove(p + 1, p + l, (leader + lead_len) - p);
					lead_len -= l - 1;
				    }
				    *p = ' ';
				}
			    }
			*p = NUL;
		    }

		    
		    if (curbuf->b_p_ai  || do_si  )




			newindent = get_indent_str_vtab(leader, curbuf->b_p_ts, curbuf->b_p_vts_array, FALSE);

			newindent = get_indent_str(leader, (int)curbuf->b_p_ts, FALSE);


		    
		    if (newindent + off < 0)
		    {
			off = -newindent;
			newindent = 0;
		    }
		    else newindent += off;

		    
		    
		    while (off > 0 && lead_len > 0 && leader[lead_len - 1] == ' ')
		    {
			
			if (vim_strchr(skipwhite(leader), '\t') != NULL)
			    break;
			--lead_len;
			--off;
		    }

		    
		    
		    if (lead_len > 0 && VIM_ISWHITE(leader[lead_len - 1]))
			extra_space = FALSE;
		    leader[lead_len] = NUL;
		}

		if (extra_space)
		{
		    leader[lead_len++] = ' ';
		    leader[lead_len] = NUL;
		}

		newcol = lead_len;

		
		
		if (newindent  || did_si  )



		{
		    while (lead_len && VIM_ISWHITE(*leader))
		    {
			--lead_len;
			--newcol;
			++leader;
		    }
		}

	    }

	    did_si = can_si = FALSE;

	}
	else if (comment_end != NULL)
	{
	    
	    
	    
	    
	    if (comment_end[0] == '*' && comment_end[1] == '/' && (curbuf->b_p_ai  || do_si  ))




	    {
		old_cursor = curwin->w_cursor;
		curwin->w_cursor.col = (colnr_T)(comment_end - saved_line);
		if ((pos = findmatch(NULL, NUL)) != NULL)
		{
		    curwin->w_cursor.lnum = pos->lnum;
		    newindent = get_indent();
		}
		curwin->w_cursor = old_cursor;
	    }
	}
    }

    
    if (p_extra != NULL)
    {
	*p_extra = saved_char;		

	
	
	
	
	
	
	if (REPLACE_NORMAL(State))
	    replace_push(NUL);	    
	if (curbuf->b_p_ai || (flags & OPENLINE_DELSPACES))
	{
	    while ((*p_extra == ' ' || *p_extra == '\t')
		    && (!enc_utf8 || !utf_iscomposing(utf_ptr2char(p_extra + 1))))
	    {
		if (REPLACE_NORMAL(State))
		    replace_push(*p_extra);
		++p_extra;
		++less_cols_off;
	    }
	}

	
	less_cols = (int)(p_extra - saved_line);
    }

    if (p_extra == NULL)
	p_extra = (char_u *)"";		    

    
    if (lead_len)
    {
	if (flags & OPENLINE_COM_LIST && second_line_indent > 0)
	{
	    int i;
	    int padding = second_line_indent - (newindent + (int)STRLEN(leader));

	    
	    
	    
	    for (i = 0; i < padding; i++)
	    {
		STRCAT(leader, " ");
		less_cols--;
		newcol++;
	    }
	}
	STRCAT(leader, p_extra);
	p_extra = leader;
	did_ai = TRUE;	    
	less_cols -= lead_len;
    }
    else end_comment_pending = NUL;

    old_cursor = curwin->w_cursor;
    if (dir == BACKWARD)
	--curwin->w_cursor.lnum;
    if (!(State & VREPLACE_FLAG) || old_cursor.lnum >= orig_line_count)
    {
	if (ml_append(curwin->w_cursor.lnum, p_extra, (colnr_T)0, FALSE)
								      == FAIL)
	    goto theend;
	
	
	
	
	if (curwin->w_cursor.lnum + 1 < curbuf->b_ml.ml_line_count  || curwin->w_p_diff  )



	    mark_adjust(curwin->w_cursor.lnum + 1, (linenr_T)MAXLNUM, 1L, 0L);
	did_append = TRUE;

	if ((State & MODE_INSERT) && (State & VREPLACE_FLAG) == 0)
	    
	    adjust_props_for_split(curwin->w_cursor.lnum, curwin->w_cursor.lnum, curwin->w_cursor.col + 1, 0);

    }
    else {
	
	curwin->w_cursor.lnum++;
	if (curwin->w_cursor.lnum >= Insstart.lnum + vr_lines_changed)
	{
	    
	    
	    (void)u_save_cursor();		    
	    vr_lines_changed++;
	}
	ml_replace(curwin->w_cursor.lnum, p_extra, TRUE);
	changed_bytes(curwin->w_cursor.lnum, 0);
	curwin->w_cursor.lnum--;
	did_append = FALSE;
    }

    if (newindent  || did_si  )



    {
	++curwin->w_cursor.lnum;

	if (did_si)
	{
	    int sw = (int)get_sw_value(curbuf);

	    if (p_sr)
		newindent -= newindent % sw;
	    newindent += sw;
	}

	
	if (curbuf->b_p_ci)
	{
	    (void)copy_indent(newindent, saved_line);

	    
	    
	    
	    curbuf->b_p_pi = TRUE;
	}
	else (void)set_indent(newindent, SIN_INSERT);
	less_cols -= curwin->w_cursor.col;

	ai_col = curwin->w_cursor.col;

	
	
	if (REPLACE_NORMAL(State))
	    for (n = 0; n < (int)curwin->w_cursor.col; ++n)
		replace_push(NUL);
	newcol += curwin->w_cursor.col;

	if (no_si)
	    did_si = FALSE;

    }

    
    
    if (REPLACE_NORMAL(State))
	while (lead_len-- > 0)
	    replace_push(NUL);

    curwin->w_cursor = old_cursor;

    if (dir == FORWARD)
    {
	if (trunc_line || (State & MODE_INSERT))
	{
	    
	    saved_line[curwin->w_cursor.col] = NUL;
	    
	    if (trunc_line && !(flags & OPENLINE_KEEPTRAIL))
		truncate_spaces(saved_line);
	    ml_replace(curwin->w_cursor.lnum, saved_line, FALSE);
	    saved_line = NULL;
	    if (did_append)
	    {
		changed_lines(curwin->w_cursor.lnum, curwin->w_cursor.col, curwin->w_cursor.lnum + 1, 1L);
		did_append = FALSE;

		
		if (flags & OPENLINE_MARKFIX)
		    mark_col_adjust(curwin->w_cursor.lnum, curwin->w_cursor.col + less_cols_off, 1L, (long)-less_cols, 0);


		
		if (curbuf->b_has_textprop && less_cols_off != 0)
		    adjust_prop_columns(curwin->w_cursor.lnum + 1, 0, -less_cols_off, 0);

	    }
	    else changed_bytes(curwin->w_cursor.lnum, curwin->w_cursor.col);
	}

	
	
	curwin->w_cursor.lnum = old_cursor.lnum + 1;
    }
    if (did_append)
	changed_lines(curwin->w_cursor.lnum, 0, curwin->w_cursor.lnum, 1L);

    curwin->w_cursor.col = newcol;
    curwin->w_cursor.coladd = 0;


    
    
    
    if (State & VREPLACE_FLAG)
    {
	vreplace_mode = State;	
	State = MODE_INSERT;
    }
    else vreplace_mode = 0;


    
    if (!p_paste && leader == NULL && curbuf->b_p_lisp && curbuf->b_p_ai)


    {
	fixthisline(get_lisp_indent);
	ai_col = (colnr_T)getwhitecols_curline();
    }


    
    if (do_cindent)
    {
	do_c_expr_indent();
	ai_col = (colnr_T)getwhitecols_curline();
    }


    if (vreplace_mode != 0)
	State = vreplace_mode;


    
    
    
    if (State & VREPLACE_FLAG)
    {
	
	p_extra = vim_strsave(ml_get_curline());
	if (p_extra == NULL)
	    goto theend;

	
	ml_replace(curwin->w_cursor.lnum, next_line, FALSE);

	
	curwin->w_cursor.col = 0;
	curwin->w_cursor.coladd = 0;
	ins_bytes(p_extra);	
	vim_free(p_extra);
	next_line = NULL;
    }

    retval = OK;		
theend:
    curbuf->b_p_pi = saved_pi;
    vim_free(saved_line);
    vim_free(next_line);
    vim_free(allocated);
    return retval;
}


    int truncate_line(int fixpos)
{
    char_u	*newp;
    linenr_T	lnum = curwin->w_cursor.lnum;
    colnr_T	col = curwin->w_cursor.col;
    char_u	*old_line;
    int		deleted;

    old_line = ml_get(lnum);
    if (col == 0)
	newp = vim_strsave((char_u *)"");
    else newp = vim_strnsave(old_line, col);
    deleted = (int)STRLEN(old_line) - col;

    if (newp == NULL)
	return FAIL;

    ml_replace(lnum, newp, FALSE);

    
    inserted_bytes(lnum, curwin->w_cursor.col, -deleted);

    
    if (fixpos && curwin->w_cursor.col > 0)
	--curwin->w_cursor.col;

    return OK;
}


    void del_lines(long nlines,	int undo)
{
    long	n;
    linenr_T	first = curwin->w_cursor.lnum;

    if (nlines <= 0)
	return;

    
    if (undo && u_savedel(first, nlines) == FAIL)
	return;

    for (n = 0; n < nlines; )
    {
	if (curbuf->b_ml.ml_flags & ML_EMPTY)	    
	    break;

	ml_delete_flags(first, ML_DEL_MESSAGE);
	++n;

	
	if (first > curbuf->b_ml.ml_line_count)
	    break;
    }

    
    
    curwin->w_cursor.col = 0;
    check_cursor_lnum();

    
    deleted_lines_mark(first, n);
}
