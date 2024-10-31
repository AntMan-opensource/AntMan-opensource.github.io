



static void cmd_with_count(char *cmd, char_u *bufp, size_t bufsize, long Prenum);
static void win_init(win_T *newp, win_T *oldp, int flags);
static void win_init_some(win_T *newp, win_T *oldp);
static void frame_comp_pos(frame_T *topfrp, int *row, int *col);
static void frame_setheight(frame_T *curfrp, int height);
static void frame_setwidth(frame_T *curfrp, int width);
static void win_exchange(long);
static void win_rotate(int, int);
static void win_totop(int size, int flags);
static void win_equal_rec(win_T *next_curwin, int current, frame_T *topfr, int dir, int col, int row, int width, int height);
static void trigger_winclosed(win_T *win);
static win_T *win_free_mem(win_T *win, int *dirp, tabpage_T *tp);
static frame_T *win_altframe(win_T *win, tabpage_T *tp);
static tabpage_T *alt_tabpage(void);
static win_T *frame2win(frame_T *frp);
static int frame_has_win(frame_T *frp, win_T *wp);
static void win_fix_scroll(int resize);
static void win_fix_cursor(int normal);
static void frame_new_height(frame_T *topfrp, int height, int topfirst, int wfh);
static int frame_fixed_height(frame_T *frp);
static int frame_fixed_width(frame_T *frp);
static void frame_add_statusline(frame_T *frp);
static void frame_new_width(frame_T *topfrp, int width, int leftfirst, int wfw);
static void frame_add_vsep(frame_T *frp);
static int frame_minwidth(frame_T *topfrp, win_T *next_curwin);
static void frame_fix_width(win_T *wp);
static int win_alloc_firstwin(win_T *oldwin);
static void new_frame(win_T *wp);
static tabpage_T *alloc_tabpage(void);
static int leave_tabpage(buf_T *new_curbuf, int trigger_leave_autocmds);
static void enter_tabpage(tabpage_T *tp, buf_T *old_curbuf, int trigger_enter_autocmds, int trigger_leave_autocmds);
static void frame_fix_height(win_T *wp);
static int frame_minheight(frame_T *topfrp, win_T *next_curwin);
static int may_open_tabpage(void);
static int win_enter_ext(win_T *wp, int flags);
static void win_free(win_T *wp, tabpage_T *tp);
static void win_append(win_T *after, win_T *wp);
static void frame_append(frame_T *after, frame_T *frp);
static void frame_insert(frame_T *before, frame_T *frp);
static void frame_remove(frame_T *frp);
static void win_goto_ver(int up, long count);
static void win_goto_hor(int left, long count);
static void frame_add_height(frame_T *frp, int n);
static void last_status_rec(frame_T *fr, int statusline);

static void make_snapshot_rec(frame_T *fr, frame_T **frp);
static void clear_snapshot(tabpage_T *tp, int idx);
static void clear_snapshot_rec(frame_T *fr);
static int check_snapshot_rec(frame_T *sn, frame_T *fr);
static win_T *restore_snapshot_rec(frame_T *sn, frame_T *fr);
static win_T *get_snapshot_curwin(int idx);

static int frame_check_height(frame_T *topfrp, int height);
static int frame_check_width(frame_T *topfrp, int width);

static win_T *win_alloc(win_T *after, int hidden);













static char *m_onlyone = N_("Already only one window");



static int split_disallowed = 0;



static int close_disallowed = 0;


    static void window_layout_lock(void)
{
    ++split_disallowed;
    ++close_disallowed;
}

    static void window_layout_unlock(void)
{
    --split_disallowed;
    --close_disallowed;
}


    int window_layout_locked(enum CMD_index cmd)
{
    if (split_disallowed > 0 || close_disallowed > 0)
    {
	if (close_disallowed == 0 && cmd == CMD_tabnew)
	    emsg(_(e_cannot_split_window_when_closing_buffer));
	else emsg(_(e_not_allowed_to_change_window_layout_in_this_autocmd));
	return TRUE;
    }
    return FALSE;
}




    static void log_frame_layout(frame_T *frame)
{
    ch_log(NULL, "layout %s, wi: %d, he: %d, wwi: %d, whe: %d, id: %d", frame->fr_layout == FR_LEAF ? "LEAF" : frame->fr_layout == FR_ROW ? "ROW" : "COL", frame->fr_width, frame->fr_height, frame->fr_win == NULL ? -1 : frame->fr_win->w_width, frame->fr_win == NULL ? -1 : frame->fr_win->w_height, frame->fr_win == NULL ? -1 : frame->fr_win->w_id);






    if (frame->fr_child != NULL)
    {
	ch_log(NULL, "children");
	log_frame_layout(frame->fr_child);
	if (frame->fr_next != NULL)
	    ch_log(NULL, "END of children");
    }
    if (frame->fr_next != NULL)
	log_frame_layout(frame->fr_next);
}



    win_T * prevwin_curwin(void)
{
    
    return is_in_cmdwin() && prevwin != NULL ? prevwin : curwin;
}


    void do_window( int		nchar, long	Prenum, int		xchar)



{
    long	Prenum1;
    win_T	*wp;
    char_u	*ptr;
    linenr_T    lnum = -1;

    int		type = FIND_DEFINE;
    int		len;

    char_u	cbuf[40];

    if (ERROR_IF_ANY_POPUP_WINDOW)
	return;









    Prenum1 = Prenum == 0 ? 1 : Prenum;

    switch (nchar)
    {

    case 'S':
    case Ctrl_S:
    case 's':
		CHECK_CMDWIN;
		reset_VIsual_and_resel();	
		
		
		if (bt_quickfix(curbuf))
		    goto newwindow;

		need_mouse_correct = TRUE;

		(void)win_split((int)Prenum, 0);
		break;


    case Ctrl_V:
    case 'v':
		CHECK_CMDWIN;
		reset_VIsual_and_resel();	
		
		
		if (bt_quickfix(curbuf))
		    goto newwindow;

		need_mouse_correct = TRUE;

		(void)win_split((int)Prenum, WSP_VERT);
		break;


    case Ctrl_HAT:
    case '^':
		CHECK_CMDWIN;
		reset_VIsual_and_resel();	

		if (buflist_findnr(Prenum == 0 ? curwin->w_alt_fnum : Prenum) == NULL)
		{
		    if (Prenum == 0)
			emsg(_(e_no_alternate_file));
		    else semsg(_(e_buffer_nr_not_found), Prenum);
		    break;
		}

		if (!curbuf_locked() && win_split(0, 0) == OK)
		    (void)buflist_getfile( Prenum == 0 ? curwin->w_alt_fnum : Prenum, (linenr_T)0, GETF_ALT, FALSE);

		break;


    case Ctrl_N:
    case 'n':
		CHECK_CMDWIN;
		reset_VIsual_and_resel();	
newwindow:
		if (Prenum)
		    
		    vim_snprintf((char *)cbuf, sizeof(cbuf) - 5, "%ld", Prenum);
		else cbuf[0] = NUL;

		if (nchar == 'v' || nchar == Ctrl_V)
		    STRCAT(cbuf, "v");

		STRCAT(cbuf, "new");
		do_cmdline_cmd(cbuf);
		break;


    case Ctrl_Q:
    case 'q':
		reset_VIsual_and_resel();	
		cmd_with_count("quit", cbuf, sizeof(cbuf), Prenum);
		do_cmdline_cmd(cbuf);
		break;


    case Ctrl_C:
    case 'c':
		reset_VIsual_and_resel();	
		cmd_with_count("close", cbuf, sizeof(cbuf), Prenum);
		do_cmdline_cmd(cbuf);
		break;



    case Ctrl_Z:
    case 'z':
		CHECK_CMDWIN;
		reset_VIsual_and_resel();	
		do_cmdline_cmd((char_u *)"pclose");
		break;


    case 'P':
		FOR_ALL_WINDOWS(wp)
		    if (wp->w_p_pvw)
			break;
		if (wp == NULL)
		    emsg(_(e_there_is_no_preview_window));
		else win_goto(wp);
		break;



    case Ctrl_O:
    case 'o':
		CHECK_CMDWIN;
		reset_VIsual_and_resel();	
		cmd_with_count("only", cbuf, sizeof(cbuf), Prenum);
		do_cmdline_cmd(cbuf);
		break;


    case Ctrl_W:
    case 'w':

    case 'W':
		CHECK_CMDWIN;
		if (ONE_WINDOW && Prenum != 1)	
		    beep_flush();
		else {
		    if (Prenum)			
		    {
			for (wp = firstwin; --Prenum > 0; )
			{
			    if (wp->w_next == NULL)
				break;
			    else wp = wp->w_next;
			}
		    }
		    else {
			if (nchar == 'W')	    
			{
			    wp = curwin->w_prev;
			    if (wp == NULL)
				wp = lastwin;	    
			}
			else			     {
			    wp = curwin->w_next;
			    if (wp == NULL)
				wp = firstwin;	    
			}
		    }
		    win_goto(wp);
		}
		break;


    case 'j':
    case K_DOWN:
    case Ctrl_J:
		CHECK_CMDWIN;
		win_goto_ver(FALSE, Prenum1);
		break;


    case 'k':
    case K_UP:
    case Ctrl_K:
		CHECK_CMDWIN;
		win_goto_ver(TRUE, Prenum1);
		break;


    case 'h':
    case K_LEFT:
    case Ctrl_H:
    case K_BS:
		CHECK_CMDWIN;
		win_goto_hor(TRUE, Prenum1);
		break;


    case 'l':
    case K_RIGHT:
    case Ctrl_L:
		CHECK_CMDWIN;
		win_goto_hor(FALSE, Prenum1);
		break;


    case 'T':
		CHECK_CMDWIN;
		if (one_window())
		    msg(_(m_onlyone));
		else {
		    tabpage_T	*oldtab = curtab;
		    tabpage_T	*newtab;

		    
		    
		    wp = curwin;
		    if (win_new_tabpage((int)Prenum) == OK && valid_tabpage(oldtab))
		    {
			newtab = curtab;
			goto_tabpage_tp(oldtab, TRUE, TRUE);
			if (curwin == wp)
			    win_close(curwin, FALSE);
			if (valid_tabpage(newtab))
			    goto_tabpage_tp(newtab, TRUE, TRUE);
		    }
		}
		break;


    case 't':
    case Ctrl_T:
		win_goto(firstwin);
		break;


    case 'b':
    case Ctrl_B:
		win_goto(lastwin);
		break;


    case 'p':
    case Ctrl_P:
		if (!win_valid(prevwin))
		    beep_flush();
		else win_goto(prevwin);
		break;


    case 'x':
    case Ctrl_X:
		CHECK_CMDWIN;
		win_exchange(Prenum);
		break;


    case Ctrl_R:
    case 'r':
		CHECK_CMDWIN;
		reset_VIsual_and_resel();	
		win_rotate(FALSE, (int)Prenum1);    
		break;


    case 'R':
		CHECK_CMDWIN;
		reset_VIsual_and_resel();	
		win_rotate(TRUE, (int)Prenum1);	    
		break;


    case 'K':
    case 'J':
    case 'H':
    case 'L':
		CHECK_CMDWIN;
		win_totop((int)Prenum, ((nchar == 'H' || nchar == 'L') ? WSP_VERT : 0)
			| ((nchar == 'H' || nchar == 'K') ? WSP_TOP : WSP_BOT));
		break;


    case '=':
		{
		    int mod = cmdmod.cmod_split & (WSP_VERT | WSP_HOR);

		    need_mouse_correct = TRUE;

		    win_equal(NULL, FALSE, mod == WSP_VERT ? 'v' : mod == WSP_HOR ? 'h' : 'b');
		}
		break;


    case '+':

		need_mouse_correct = TRUE;

		win_setheight(curwin->w_height + (int)Prenum1);
		break;


    case '-':

		need_mouse_correct = TRUE;

		win_setheight(curwin->w_height - (int)Prenum1);
		break;


    case Ctrl__:
    case '_':

		need_mouse_correct = TRUE;

		win_setheight(Prenum ? (int)Prenum : 9999);
		break;


    case '>':

		need_mouse_correct = TRUE;

		win_setwidth(curwin->w_width + (int)Prenum1);
		break;


    case '<':

		need_mouse_correct = TRUE;

		win_setwidth(curwin->w_width - (int)Prenum1);
		break;


    case '|':

		need_mouse_correct = TRUE;

		win_setwidth(Prenum != 0 ? (int)Prenum : 9999);
		break;



    case '}':
		CHECK_CMDWIN;
		if (Prenum)
		    g_do_tagpreview = Prenum;
		else g_do_tagpreview = p_pvh;

		
    case ']':
    case Ctrl_RSB:
		CHECK_CMDWIN;
		
		if (Prenum)
		    postponed_split = Prenum;
		else postponed_split = -1;

		if (nchar != '}')
		    g_do_tagpreview = 0;


		
		
		do_nv_ident(Ctrl_RSB, NUL);
		break;


    case 'f':
    case 'F':
    case Ctrl_F:
wingotofile:
		CHECK_CMDWIN;

		ptr = grab_file_name(Prenum1, &lnum);
		if (ptr != NULL)
		{
		    tabpage_T	*oldtab = curtab;
		    win_T	*oldwin = curwin;

		    need_mouse_correct = TRUE;

		    setpcmark();
		    if (win_split(0, 0) == OK)
		    {
			RESET_BINDING(curwin);
			if (do_ecmd(0, ptr, NULL, NULL, ECMD_LASTL, ECMD_HIDE, NULL) == FAIL)
			{
			    
			    
			    win_close(curwin, FALSE);
			    goto_tabpage_win(oldtab, oldwin);
			}
			else if (nchar == 'F' && lnum >= 0)
			{
			    curwin->w_cursor.lnum = lnum;
			    check_cursor_lnum();
			    beginline(BL_SOL | BL_FIX);
			}
		    }
		    vim_free(ptr);
		}
		break;




    case 'i':			    
    case Ctrl_I:
		type = FIND_ANY;
		
    case 'd':			    
    case Ctrl_D:
		CHECK_CMDWIN;
		if ((len = find_ident_under_cursor(&ptr, FIND_IDENT)) == 0)
		    break;

		
		ptr = vim_strnsave(ptr, len);
		if (ptr == NULL)
		    break;

		find_pattern_in_path(ptr, 0, len, TRUE, Prenum == 0 ? TRUE : FALSE, type, Prenum1, ACTION_SPLIT, (linenr_T)1, (linenr_T)MAXLNUM);

		vim_free(ptr);
		curwin->w_set_curswant = TRUE;
		break;




    case K_KENTER:
    case CAR:
		if (bt_quickfix(curbuf))
		    qf_view_result(TRUE);
		break;



    case 'g':
    case Ctrl_G:
		CHECK_CMDWIN;

		dont_scroll = TRUE;		

		++no_mapping;
		++allow_keys;   
		if (xchar == NUL)
		    xchar = plain_vgetc();
		LANGMAP_ADJUST(xchar, TRUE);
		--no_mapping;
		--allow_keys;
		(void)add_to_showcmd(xchar);

		switch (xchar)
		{

		    case '}':
			xchar = Ctrl_RSB;
			if (Prenum)
			    g_do_tagpreview = Prenum;
			else g_do_tagpreview = p_pvh;

			
		    case ']':
		    case Ctrl_RSB:
			
			if (Prenum)
			    postponed_split = Prenum;
			else postponed_split = -1;

			
			
			do_nv_ident('g', xchar);
			break;

		    case 'f':	    
		    case 'F':	    
			cmdmod.cmod_tab = tabpage_index(curtab) + 1;
			nchar = xchar;
			goto wingotofile;

		    case 't':	    
			goto_tabpage((int)Prenum);
			break;

		    case 'T':	    
			goto_tabpage(-(int)Prenum1);
			break;

		    case TAB:	    
			if (goto_tabpage_lastused() == FAIL)
			    beep_flush();
			break;

		    default:
			beep_flush();
			break;
		}
		break;

    default:	beep_flush();
		break;
    }
}


    void get_wincmd_addr_type(char_u *arg, exarg_T *eap)
{
    switch (*arg)
    {
    case 'S':
    case Ctrl_S:
    case 's':
    case Ctrl_N:
    case 'n':
    case 'j':
    case Ctrl_J:
    case 'k':
    case Ctrl_K:
    case 'T':
    case Ctrl_R:
    case 'r':
    case 'R':
    case 'K':
    case 'J':
    case '+':
    case '-':
    case Ctrl__:
    case '_':
    case '|':
    case ']':
    case Ctrl_RSB:
    case 'g':
    case Ctrl_G:
    case Ctrl_V:
    case 'v':
    case 'h':
    case Ctrl_H:
    case 'l':
    case Ctrl_L:
    case 'H':
    case 'L':
    case '>':
    case '<':

    case '}':

    case 'f':
    case 'F':
    case Ctrl_F:

    case 'i':
    case Ctrl_I:
    case 'd':
    case Ctrl_D:

		
		eap->addr_type = ADDR_OTHER;
		break;

    case Ctrl_HAT:
    case '^':
		
		eap->addr_type = ADDR_BUFFERS;
		break;

    case Ctrl_Q:
    case 'q':
    case Ctrl_C:
    case 'c':
    case Ctrl_O:
    case 'o':
    case Ctrl_W:
    case 'w':
    case 'W':
    case 'x':
    case Ctrl_X:
		
		eap->addr_type = ADDR_WINDOWS;
		break;


    case Ctrl_Z:
    case 'z':
    case 'P':

    case 't':
    case Ctrl_T:
    case 'b':
    case Ctrl_B:
    case 'p':
    case Ctrl_P:
    case '=':
    case CAR:
		
		eap->addr_type = ADDR_NONE;
		break;
    }
}

    static void cmd_with_count( char	*cmd, char_u	*bufp, size_t	bufsize, long	Prenum)




{
    if (Prenum > 0)
	vim_snprintf((char *)bufp, bufsize, "%s %ld", cmd, Prenum);
    else STRCPY(bufp, cmd);
}


    static int check_split_disallowed()
{
    if (split_disallowed > 0)
    {
	emsg(_(e_cant_split_window_while_closing_another));
	return FAIL;
    }
    if (curwin->w_buffer->b_locked_split)
    {
	emsg(_(e_cannot_split_window_when_closing_buffer));
	return FAIL;
    }
    return OK;
}


    int win_split(int size, int flags)
{
    if (ERROR_IF_ANY_POPUP_WINDOW)
	return FAIL;

    if (check_split_disallowed() == FAIL)
	return FAIL;

    
    if (may_open_tabpage() == OK)
	return OK;

    
    flags |= cmdmod.cmod_split;
    if ((flags & WSP_TOP) && (flags & WSP_BOT))
    {
	emsg(_(e_cant_split_topleft_and_botright_at_the_same_time));
	return FAIL;
    }

    
    
    if (flags & WSP_HELP)
	make_snapshot(SNAP_HELP_IDX);
    else clear_snapshot(curtab, SNAP_HELP_IDX);

    return win_split_ins(size, flags, NULL, 0);
}


    int win_split_ins( int		size, int		flags, win_T	*new_wp, int		dir)




{
    win_T	*wp = new_wp;
    win_T	*oldwin;
    int		new_size = size;
    int		i;
    int		need_status = 0;
    int		do_equal = FALSE;
    int		needed;
    int		available;
    int		oldwin_height = 0;
    int		layout;
    frame_T	*frp, *curfrp, *frp2, *prevfrp;
    int		before;
    int		minheight;
    int		wmh1;
    int		did_set_fraction = FALSE;

    if (flags & WSP_TOP)
	oldwin = firstwin;
    else if (flags & WSP_BOT)
	oldwin = lastwin;
    else oldwin = curwin;

    
    if (ONE_WINDOW && p_ls == 1 && oldwin->w_status_height == 0)
    {
	if (VISIBLE_HEIGHT(oldwin) <= p_wmh && new_wp == NULL)
	{
	    emsg(_(e_not_enough_room));
	    return FAIL;
	}
	need_status = STATUS_HEIGHT;
    }


    
    if (gui.in_use)
	out_flush();


    if (flags & WSP_VERT)
    {
	int	wmw1;
	int	minwidth;

	layout = FR_ROW;

	
	
	wmw1 = (p_wmw == 0 ? 1 : p_wmw);
	needed = wmw1 + 1;
	if (flags & WSP_ROOM)
	    needed += p_wiw - wmw1;
	if (flags & (WSP_BOT | WSP_TOP))
	{
	    minwidth = frame_minwidth(topframe, NOWIN);
	    available = topframe->fr_width;
	    needed += minwidth;
	}
	else if (p_ea)
	{
	    minwidth = frame_minwidth(oldwin->w_frame, NOWIN);
	    prevfrp = oldwin->w_frame;
	    for (frp = oldwin->w_frame->fr_parent; frp != NULL;
							frp = frp->fr_parent)
	    {
		if (frp->fr_layout == FR_ROW)
		    FOR_ALL_FRAMES(frp2, frp->fr_child)
			if (frp2 != prevfrp)
			    minwidth += frame_minwidth(frp2, NOWIN);
		prevfrp = frp;
	    }
	    available = topframe->fr_width;
	    needed += minwidth;
	}
	else {
	    minwidth = frame_minwidth(oldwin->w_frame, NOWIN);
	    available = oldwin->w_frame->fr_width;
	    needed += minwidth;
	}
	if (available < needed && new_wp == NULL)
	{
	    emsg(_(e_not_enough_room));
	    return FAIL;
	}
	if (new_size == 0)
	    new_size = oldwin->w_width / 2;
	if (new_size > available - minwidth - 1)
	    new_size = available - minwidth - 1;
	if (new_size < wmw1)
	    new_size = wmw1;

	
	if (oldwin->w_width - new_size - 1 < p_wmw)
	    do_equal = TRUE;

	
	
	
	if (oldwin->w_p_wfw)
	    win_setwidth_win(oldwin->w_width + new_size + 1, oldwin);

	
	
	if (!do_equal && p_ea && size == 0 && *p_ead != 'v' && oldwin->w_frame->fr_parent != NULL)
	{
	    frp = oldwin->w_frame->fr_parent->fr_child;
	    while (frp != NULL)
	    {
		if (frp->fr_win != oldwin && frp->fr_win != NULL && (frp->fr_win->w_width > new_size || frp->fr_win->w_width > oldwin->w_width - new_size - 1))


		{
		    do_equal = TRUE;
		    break;
		}
		frp = frp->fr_next;
	    }
	}
    }
    else {
	layout = FR_COL;

	
	
	wmh1 = (p_wmh == 0 ? 1 : p_wmh) + WINBAR_HEIGHT(curwin);
	needed = wmh1 + STATUS_HEIGHT;
	if (flags & WSP_ROOM)
	    needed += p_wh - wmh1;
	if (flags & (WSP_BOT | WSP_TOP))
	{
	    minheight = frame_minheight(topframe, NOWIN) + need_status;
	    available = topframe->fr_height;
	    needed += minheight;
	}
	else if (p_ea)
	{
	    minheight = frame_minheight(oldwin->w_frame, NOWIN) + need_status;
	    prevfrp = oldwin->w_frame;
	    for (frp = oldwin->w_frame->fr_parent; frp != NULL;
							frp = frp->fr_parent)
	    {
		if (frp->fr_layout == FR_COL)
		    FOR_ALL_FRAMES(frp2, frp->fr_child)
			if (frp2 != prevfrp)
			    minheight += frame_minheight(frp2, NOWIN);
		prevfrp = frp;
	    }
	    available = topframe->fr_height;
	    needed += minheight;
	}
	else {
	    minheight = frame_minheight(oldwin->w_frame, NOWIN) + need_status;
	    available = oldwin->w_frame->fr_height;
	    needed += minheight;
	}
	if (available < needed && new_wp == NULL)
	{
	    emsg(_(e_not_enough_room));
	    return FAIL;
	}
	oldwin_height = oldwin->w_height;
	if (need_status)
	{
	    oldwin->w_status_height = STATUS_HEIGHT;
	    oldwin_height -= STATUS_HEIGHT;
	}
	if (new_size == 0)
	    new_size = oldwin_height / 2;
	if (new_size > available - minheight - STATUS_HEIGHT)
	    new_size = available - minheight - STATUS_HEIGHT;
	if (new_size < wmh1)
	    new_size = wmh1;

	
	if (oldwin_height - new_size - STATUS_HEIGHT < p_wmh)
	    do_equal = TRUE;

	
	
	
	if (oldwin->w_p_wfh)
	{
	    
	    
	    set_fraction(oldwin);
	    did_set_fraction = TRUE;

	    win_setheight_win(oldwin->w_height + new_size + STATUS_HEIGHT, oldwin);
	    oldwin_height = oldwin->w_height;
	    if (need_status)
		oldwin_height -= STATUS_HEIGHT;
	}

	
	
	if (!do_equal && p_ea && size == 0 && *p_ead != 'h' && oldwin->w_frame->fr_parent != NULL)
	{
	    frp = oldwin->w_frame->fr_parent->fr_child;
	    while (frp != NULL)
	    {
		if (frp->fr_win != oldwin && frp->fr_win != NULL && (frp->fr_win->w_height > new_size || frp->fr_win->w_height > oldwin_height - new_size - STATUS_HEIGHT))


		{
		    do_equal = TRUE;
		    break;
		}
		frp = frp->fr_next;
	    }
	}
    }

    
    if ((flags & WSP_TOP) == 0 && ((flags & WSP_BOT)
		|| (flags & WSP_BELOW)
		|| (!(flags & WSP_ABOVE)
		    && ( (flags & WSP_VERT) ? p_spr : p_sb))))
    {
	
	if (new_wp == NULL)
	    wp = win_alloc(oldwin, FALSE);
	else win_append(oldwin, wp);
    }
    else {
	if (new_wp == NULL)
	    wp = win_alloc(oldwin->w_prev, FALSE);
	else win_append(oldwin->w_prev, wp);
    }

    if (new_wp == NULL)
    {
	if (wp == NULL)
	    return FAIL;

	new_frame(wp);
	if (wp->w_frame == NULL)
	{
	    win_free(wp, NULL);
	    return FAIL;
	}

	
	win_init(wp, curwin, flags);
    }

    
    if (flags & (WSP_TOP | WSP_BOT))
    {
	if ((topframe->fr_layout == FR_COL && (flags & WSP_VERT) == 0)
	    || (topframe->fr_layout == FR_ROW && (flags & WSP_VERT) != 0))
	{
	    curfrp = topframe->fr_child;
	    if (flags & WSP_BOT)
		while (curfrp->fr_next != NULL)
		    curfrp = curfrp->fr_next;
	}
	else curfrp = topframe;
	before = (flags & WSP_TOP);
    }
    else {
	curfrp = oldwin->w_frame;
	if (flags & WSP_BELOW)
	    before = FALSE;
	else if (flags & WSP_ABOVE)
	    before = TRUE;
	else if (flags & WSP_VERT)
	    before = !p_spr;
	else before = !p_sb;
    }
    if (curfrp->fr_parent == NULL || curfrp->fr_parent->fr_layout != layout)
    {
	
	frp = ALLOC_CLEAR_ONE(frame_T);
	*frp = *curfrp;
	curfrp->fr_layout = layout;
	frp->fr_parent = curfrp;
	frp->fr_next = NULL;
	frp->fr_prev = NULL;
	curfrp->fr_child = frp;
	curfrp->fr_win = NULL;
	curfrp = frp;
	if (frp->fr_win != NULL)
	    oldwin->w_frame = frp;
	else FOR_ALL_FRAMES(frp, frp->fr_child)
		frp->fr_parent = curfrp;
    }

    if (new_wp == NULL)
	frp = wp->w_frame;
    else frp = new_wp->w_frame;
    frp->fr_parent = curfrp->fr_parent;

    
    if (before)
	frame_insert(curfrp, frp);
    else frame_append(curfrp, frp);

    
    
    if (!did_set_fraction)
	set_fraction(oldwin);
    wp->w_fraction = oldwin->w_fraction;

    if (flags & WSP_VERT)
    {
	wp->w_p_scr = curwin->w_p_scr;

	if (need_status)
	{
	    win_new_height(oldwin, oldwin->w_height - 1);
	    oldwin->w_status_height = need_status;
	}
	if (flags & (WSP_TOP | WSP_BOT))
	{
	    
	    wp->w_winrow = tabline_height();
	    win_new_height(wp, curfrp->fr_height - (p_ls > 0)
							  - WINBAR_HEIGHT(wp));
	    wp->w_status_height = (p_ls > 0);
	}
	else {
	    
	    wp->w_winrow = oldwin->w_winrow;
	    win_new_height(wp, VISIBLE_HEIGHT(oldwin));
	    wp->w_status_height = oldwin->w_status_height;
	}
	frp->fr_height = curfrp->fr_height;

	
	
	win_new_width(wp, new_size);
	if (before)
	    wp->w_vsep_width = 1;
	else {
	    wp->w_vsep_width = oldwin->w_vsep_width;
	    oldwin->w_vsep_width = 1;
	}
	if (flags & (WSP_TOP | WSP_BOT))
	{
	    if (flags & WSP_BOT)
		frame_add_vsep(curfrp);
	    
	    frame_new_width(curfrp, curfrp->fr_width - (new_size + ((flags & WSP_TOP) != 0)), flags & WSP_TOP, FALSE);

	}
	else win_new_width(oldwin, oldwin->w_width - (new_size + 1));
	if (before)	
	{
	    wp->w_wincol = oldwin->w_wincol;
	    oldwin->w_wincol += new_size + 1;
	}
	else		 wp->w_wincol = oldwin->w_wincol + oldwin->w_width + 1;
	frame_fix_width(oldwin);
	frame_fix_width(wp);
    }
    else {
	
	if (flags & (WSP_TOP | WSP_BOT))
	{
	    wp->w_wincol = 0;
	    win_new_width(wp, Columns);
	    wp->w_vsep_width = 0;
	}
	else {
	    wp->w_wincol = oldwin->w_wincol;
	    win_new_width(wp, oldwin->w_width);
	    wp->w_vsep_width = oldwin->w_vsep_width;
	}
	frp->fr_width = curfrp->fr_width;

	
	
	win_new_height(wp, new_size);
	if (flags & (WSP_TOP | WSP_BOT))
	{
	    int new_fr_height = curfrp->fr_height - new_size + WINBAR_HEIGHT(wp) ;

	    if (!((flags & WSP_BOT) && p_ls == 0))
		new_fr_height -= STATUS_HEIGHT;
	    frame_new_height(curfrp, new_fr_height, flags & WSP_TOP, FALSE);
	}
	else win_new_height(oldwin, oldwin_height - (new_size + STATUS_HEIGHT));
	if (before)	
	{
	    wp->w_winrow = oldwin->w_winrow;
	    wp->w_status_height = STATUS_HEIGHT;
	    oldwin->w_winrow += wp->w_height + STATUS_HEIGHT;
	}
	else		 {
	    wp->w_winrow = oldwin->w_winrow + VISIBLE_HEIGHT(oldwin)
							       + STATUS_HEIGHT;
	    wp->w_status_height = oldwin->w_status_height;
	    if (!(flags & WSP_BOT))
		oldwin->w_status_height = STATUS_HEIGHT;
	}
	if (flags & WSP_BOT)
	    frame_add_statusline(curfrp);
	frame_fix_height(wp);
	frame_fix_height(oldwin);
    }

    if (flags & (WSP_TOP | WSP_BOT))
	(void)win_comp_pos();

     
     
    redraw_win_later(wp, UPD_NOT_VALID);
    redraw_win_later(oldwin, UPD_NOT_VALID);
    status_redraw_all();

    if (need_status)
    {
	msg_row = Rows - 1;
	msg_col = sc_col;
	msg_clr_eos_force();	
	comp_col();
	msg_row = Rows - 1;
	msg_col = 0;	
    }

    
    if (do_equal || dir != 0)
	win_equal(wp, TRUE, (flags & WSP_VERT) ? (dir == 'v' ? 'b' : 'h')
		: dir == 'h' ? 'b' : 'v');
    else if (*p_spk != 'c' && wp != aucmd_win)
	win_fix_scroll(FALSE);

    
    
    if (flags & WSP_VERT)
    {
	i = p_wiw;
	if (size != 0)
	    p_wiw = size;


	
	if (gui.in_use)
	    gui_init_which_components(NULL);

    }
    else {
	i = p_wh;
	if (size != 0)
	    p_wh = size;
    }

    
    (void)win_enter_ext(wp, WEE_TRIGGER_NEW_AUTOCMDS | WEE_TRIGGER_ENTER_AUTOCMDS | WEE_TRIGGER_LEAVE_AUTOCMDS);
    if (flags & WSP_VERT)
	p_wiw = i;
    else p_wh = i;

    return OK;
}



    static void win_init(win_T *newp, win_T *oldp, int flags UNUSED)
{
    int		i;

    newp->w_buffer = oldp->w_buffer;

    newp->w_s = &(oldp->w_buffer->b_s);

    oldp->w_buffer->b_nwindows++;
    newp->w_cursor = oldp->w_cursor;
    newp->w_valid = 0;
    newp->w_curswant = oldp->w_curswant;
    newp->w_set_curswant = oldp->w_set_curswant;
    newp->w_topline = oldp->w_topline;

    newp->w_topfill = oldp->w_topfill;

    newp->w_leftcol = oldp->w_leftcol;
    newp->w_pcmark = oldp->w_pcmark;
    newp->w_prev_pcmark = oldp->w_prev_pcmark;
    newp->w_alt_fnum = oldp->w_alt_fnum;
    newp->w_wrow = oldp->w_wrow;
    newp->w_fraction = oldp->w_fraction;
    newp->w_prev_fraction_row = oldp->w_prev_fraction_row;
    copy_jumplist(oldp, newp);

    if (flags & WSP_NEWLOC)
    {
	
	newp->w_llist = NULL;
	newp->w_llist_ref = NULL;
    }
    else copy_loclist_stack(oldp, newp);

    newp->w_localdir = (oldp->w_localdir == NULL)
				    ? NULL : vim_strsave(oldp->w_localdir);
    newp->w_prevdir = (oldp->w_prevdir == NULL)
				    ? NULL : vim_strsave(oldp->w_prevdir);

    if (*p_spk != 'c')
    {
	newp->w_botline = oldp->w_botline;
	newp->w_prev_height = oldp->w_height - WINBAR_HEIGHT(oldp);
	newp->w_prev_winrow = oldp->w_winrow + 2 * WINBAR_HEIGHT(oldp);
    }

    
    for (i = 0; i < oldp->w_tagstacklen; i++)
    {
	taggy_T	*tag = &newp->w_tagstack[i];
	*tag = oldp->w_tagstack[i];
	if (tag->tagname != NULL)
	    tag->tagname = vim_strsave(tag->tagname);
	if (tag->user_data != NULL)
	    tag->user_data = vim_strsave(tag->user_data);
    }
    newp->w_tagstackidx = oldp->w_tagstackidx;
    newp->w_tagstacklen = oldp->w_tagstacklen;

    
    newp->w_changelistidx = oldp->w_changelistidx;


    copyFoldingState(oldp, newp);


    win_init_some(newp, oldp);

    term_update_wincolor(newp);

}


    static void win_init_some(win_T *newp, win_T *oldp)
{
    
    newp->w_alist = oldp->w_alist;
    ++newp->w_alist->al_refcount;
    newp->w_arg_idx = oldp->w_arg_idx;

    
    win_copy_options(oldp, newp);
}


    int win_valid_popup(win_T *win UNUSED)
{

    win_T	*wp;

    FOR_ALL_POPUPWINS(wp)
	if (wp == win)
	    return TRUE;
    FOR_ALL_POPUPWINS_IN_TAB(curtab, wp)
	if (wp == win)
	    return TRUE;

    return FALSE;
}


    int win_valid(win_T *win)
{
    win_T	*wp;

    if (win == NULL)
	return FALSE;
    FOR_ALL_WINDOWS(wp)
	if (wp == win)
	    return TRUE;
    return win_valid_popup(win);
}


    win_T * win_find_by_id(int id)
{
    win_T   *wp;

    FOR_ALL_WINDOWS(wp)
	if (wp->w_id == id)
	    return wp;

    FOR_ALL_POPUPWINS(wp)
	if (wp->w_id == id)
	    return wp;
    FOR_ALL_POPUPWINS_IN_TAB(curtab, wp)
	if (wp->w_id == id)
	    return wp;

    return NULL;
}


    int win_valid_any_tab(win_T *win)
{
    win_T	*wp;
    tabpage_T	*tp;

    if (win == NULL)
	return FALSE;
    FOR_ALL_TABPAGES(tp)
    {
	FOR_ALL_WINDOWS_IN_TAB(tp, wp)
	{
	    if (wp == win)
		return TRUE;
	}

	FOR_ALL_POPUPWINS_IN_TAB(tp, wp)
	    if (wp == win)
		return TRUE;

    }
    return win_valid_popup(win);
}


    int win_count(void)
{
    win_T	*wp;
    int		count = 0;

    FOR_ALL_WINDOWS(wp)
	++count;
    return count;
}


    int make_windows( int		count, int		vertical UNUSED)


{
    int		maxcount;
    int		todo;

    if (vertical)
    {
	
	
	maxcount = (curwin->w_width + curwin->w_vsep_width - (p_wiw - p_wmw)) / (p_wmw + 1);
    }
    else {
	
	maxcount = (VISIBLE_HEIGHT(curwin) + curwin->w_status_height - (p_wh - p_wmh)) / (p_wmh + STATUS_HEIGHT);
    }

    if (maxcount < 2)
	maxcount = 2;
    if (count > maxcount)
	count = maxcount;

    
    if (count > 1)
	last_status(TRUE);

    
    block_autocmds();

    
    for (todo = count - 1; todo > 0; --todo)
	if (vertical)
	{
	    if (win_split(curwin->w_width - (curwin->w_width - todo)
			/ (todo + 1) - 1, WSP_VERT | WSP_ABOVE) == FAIL)
		break;
	}
	else {
	    if (win_split(curwin->w_height - (curwin->w_height - todo * STATUS_HEIGHT) / (todo + 1)
			- STATUS_HEIGHT, WSP_ABOVE) == FAIL)
		break;
	}

    unblock_autocmds();

    
    return (count - todo);
}


    static void win_exchange(long Prenum)
{
    frame_T	*frp;
    frame_T	*frp2;
    win_T	*wp;
    win_T	*wp2;
    int		temp;

    if (ERROR_IF_ANY_POPUP_WINDOW)
	return;
    if (ONE_WINDOW)	    
    {
	beep_flush();
	return;
    }


    need_mouse_correct = TRUE;


    
    if (Prenum)
    {
	frp = curwin->w_frame->fr_parent->fr_child;
	while (frp != NULL && --Prenum > 0)
	    frp = frp->fr_next;
    }
    else if (curwin->w_frame->fr_next != NULL)	
	frp = curwin->w_frame->fr_next;
    else     frp = curwin->w_frame->fr_prev;

    
    
    if (frp == NULL || frp->fr_win == NULL || frp->fr_win == curwin)
	return;
    wp = frp->fr_win;


    wp2 = curwin->w_prev;
    frp2 = curwin->w_frame->fr_prev;
    if (wp->w_prev != curwin)
    {
	win_remove(curwin, NULL);
	frame_remove(curwin->w_frame);
	win_append(wp->w_prev, curwin);
	frame_insert(frp, curwin->w_frame);
    }
    if (wp != wp2)
    {
	win_remove(wp, NULL);
	frame_remove(wp->w_frame);
	win_append(wp2, wp);
	if (frp2 == NULL)
	    frame_insert(wp->w_frame->fr_parent->fr_child, wp->w_frame);
	else frame_append(frp2, wp->w_frame);
    }
    temp = curwin->w_status_height;
    curwin->w_status_height = wp->w_status_height;
    wp->w_status_height = temp;
    temp = curwin->w_vsep_width;
    curwin->w_vsep_width = wp->w_vsep_width;
    wp->w_vsep_width = temp;

    frame_fix_height(curwin);
    frame_fix_height(wp);
    frame_fix_width(curwin);
    frame_fix_width(wp);

    (void)win_comp_pos();		

    if (wp->w_buffer != curbuf)
	reset_VIsual_and_resel();
    else if (VIsual_active)
	wp->w_cursor = curwin->w_cursor;

    win_enter(wp, TRUE);
    redraw_all_later(UPD_NOT_VALID);
}


    static void win_rotate(int upwards, int count)
{
    win_T	*wp1;
    win_T	*wp2;
    frame_T	*frp;
    int		n;

    if (ONE_WINDOW)		
    {
	beep_flush();
	return;
    }


    need_mouse_correct = TRUE;


    
    FOR_ALL_FRAMES(frp, curwin->w_frame->fr_parent->fr_child)
	if (frp->fr_win == NULL)
	{
	    emsg(_(e_cannot_rotate_when_another_window_is_split));
	    return;
	}

    while (count--)
    {
	if (upwards)		
	{
	    
	    frp = curwin->w_frame->fr_parent->fr_child;
	    wp1 = frp->fr_win;
	    win_remove(wp1, NULL);
	    frame_remove(frp);

	    
	    for ( ; frp->fr_next != NULL; frp = frp->fr_next)
		;
	    win_append(frp->fr_win, wp1);
	    frame_append(frp, wp1->w_frame);

	    wp2 = frp->fr_win;		
	}
	else			 {
	    
	    for (frp = curwin->w_frame; frp->fr_next != NULL;
							   frp = frp->fr_next)
		;
	    wp1 = frp->fr_win;
	    wp2 = wp1->w_prev;		    
	    win_remove(wp1, NULL);
	    frame_remove(frp);

	    
	    win_append(frp->fr_parent->fr_child->fr_win->w_prev, wp1);
	    frame_insert(frp->fr_parent->fr_child, frp);
	}

	
	n = wp2->w_status_height;
	wp2->w_status_height = wp1->w_status_height;
	wp1->w_status_height = n;
	frame_fix_height(wp1);
	frame_fix_height(wp2);
	n = wp2->w_vsep_width;
	wp2->w_vsep_width = wp1->w_vsep_width;
	wp1->w_vsep_width = n;
	frame_fix_width(wp1);
	frame_fix_width(wp2);

	
	(void)win_comp_pos();
    }

    redraw_all_later(UPD_NOT_VALID);
}


    static void win_totop(int size, int flags)
{
    int		dir;
    int		height = curwin->w_height;

    if (ONE_WINDOW)
    {
	beep_flush();
	return;
    }
    if (check_split_disallowed() == FAIL)
	return;

    
    (void)winframe_remove(curwin, &dir, NULL);
    win_remove(curwin, NULL);
    last_status(FALSE);	    
    (void)win_comp_pos();   

    
    (void)win_split_ins(size, flags, curwin, dir);
    if (!(flags & WSP_VERT))
    {
	win_setheight(height);
	if (p_ea)
	    win_equal(curwin, TRUE, 'v');
    }


    
    
    gui_may_update_scrollbars();

}


    void win_move_after(win_T *win1, win_T *win2)
{
    int		height;

    
    if (win1 == win2)
	return;

    
    if (win2->w_next != win1)
    {
	if (win1->w_frame->fr_parent != win2->w_frame->fr_parent)
	{
	    iemsg("INTERNAL: trying to move a window into another frame");
	    return;
	}

	
	
	if (win1 == lastwin)
	{
	    height = win1->w_prev->w_status_height;
	    win1->w_prev->w_status_height = win1->w_status_height;
	    win1->w_status_height = height;
	    if (win1->w_prev->w_vsep_width == 1)
	    {
		
		
		win1->w_prev->w_vsep_width = 0;
		win1->w_prev->w_frame->fr_width -= 1;
		win1->w_vsep_width = 1;
		win1->w_frame->fr_width += 1;
	    }
	}
	else if (win2 == lastwin)
	{
	    height = win1->w_status_height;
	    win1->w_status_height = win2->w_status_height;
	    win2->w_status_height = height;
	    if (win1->w_vsep_width == 1)
	    {
		
		
		win2->w_vsep_width = 1;
		win2->w_frame->fr_width += 1;
		win1->w_vsep_width = 0;
		win1->w_frame->fr_width -= 1;
	    }
	}
	win_remove(win1, NULL);
	frame_remove(win1->w_frame);
	win_append(win2, win1);
	frame_append(win2->w_frame, win1->w_frame);

	(void)win_comp_pos();	
	redraw_later(UPD_NOT_VALID);
    }
    win_enter(win1, FALSE);
}


    void win_equal( win_T	*next_curwin, int		current, int		dir)



				
{
    if (dir == 0)
	dir = *p_ead;
    win_equal_rec(next_curwin == NULL ? curwin : next_curwin, current, topframe, dir, 0, tabline_height(), (int)Columns, topframe->fr_height);

    if (*p_spk != 'c' && next_curwin != aucmd_win)
	win_fix_scroll(TRUE);
}


    static void win_equal_rec( win_T	*next_curwin, int		current, frame_T	*topfr, int		dir, int		col, int		row, int		width, int		height)








{
    int		n, m;
    int		extra_sep = 0;
    int		wincount, totwincount = 0;
    frame_T	*fr;
    int		next_curwin_size = 0;
    int		room = 0;
    int		new_size;
    int		has_next_curwin = 0;
    int		hnc;

    if (topfr->fr_layout == FR_LEAF)
    {
	
	
	if (topfr->fr_height != height || topfr->fr_win->w_winrow != row || topfr->fr_width != width || topfr->fr_win->w_wincol != col )

	{
	    topfr->fr_win->w_winrow = row;
	    frame_new_height(topfr, height, FALSE, FALSE);
	    topfr->fr_win->w_wincol = col;
	    frame_new_width(topfr, width, FALSE, FALSE);
	    redraw_all_later(UPD_NOT_VALID);
	}
    }
    else if (topfr->fr_layout == FR_ROW)
    {
	topfr->fr_width = width;
	topfr->fr_height = height;

	if (dir != 'v')			
	{
	    
	    
	    n = frame_minwidth(topfr, NOWIN);
	    
	    if (col + width == Columns)
		extra_sep = 1;
	    else extra_sep = 0;
	    totwincount = (n + extra_sep) / (p_wmw + 1);
	    has_next_curwin = frame_has_win(topfr, next_curwin);

	    
	    m = frame_minwidth(topfr, next_curwin);
	    room = width - m;
	    if (room < 0)
	    {
		next_curwin_size = p_wiw + room;
		room = 0;
	    }
	    else {
		next_curwin_size = -1;
		FOR_ALL_FRAMES(fr, topfr->fr_child)
		{
		    if (!frame_fixed_width(fr))
			continue;
		    
		    
		    n = frame_minwidth(fr, NOWIN);
		    new_size = fr->fr_width;
		    if (frame_has_win(fr, next_curwin))
		    {
			room += p_wiw - p_wmw;
			next_curwin_size = 0;
			if (new_size < p_wiw)
			    new_size = p_wiw;
		    }
		    else  totwincount -= (n + (fr->fr_next == NULL ? extra_sep : 0)) / (p_wmw + 1);


		    room -= new_size - n;
		    if (room < 0)
		    {
			new_size += room;
			room = 0;
		    }
		    fr->fr_newwidth = new_size;
		}
		if (next_curwin_size == -1)
		{
		    if (!has_next_curwin)
			next_curwin_size = 0;
		    else if (totwincount > 1 && (room + (totwincount - 2))
						  / (totwincount - 1) > p_wiw)
		    {
			
			
			next_curwin_size = (room + p_wiw + (totwincount - 1) * p_wmw + (totwincount - 1)) / totwincount;

			room -= next_curwin_size - p_wiw;
		    }
		    else next_curwin_size = p_wiw;
		}
	    }

	    if (has_next_curwin)
		--totwincount;		
	}

	FOR_ALL_FRAMES(fr, topfr->fr_child)
	{
	    wincount = 1;
	    if (fr->fr_next == NULL)
		
		new_size = width;
	    else if (dir == 'v')
		new_size = fr->fr_width;
	    else if (frame_fixed_width(fr))
	    {
		new_size = fr->fr_newwidth;
		wincount = 0;	    
	    }
	    else {
		
		n = frame_minwidth(fr, NOWIN);
		wincount = (n + (fr->fr_next == NULL ? extra_sep : 0))
								/ (p_wmw + 1);
		m = frame_minwidth(fr, next_curwin);
		if (has_next_curwin)
		    hnc = frame_has_win(fr, next_curwin);
		else hnc = FALSE;
		if (hnc)	    
		    --wincount;
		if (totwincount == 0)
		    new_size = room;
		else new_size = (wincount * room + ((unsigned)totwincount >> 1))
								/ totwincount;
		if (hnc)	    
		{
		    next_curwin_size -= p_wiw - (m - n);
		    if (next_curwin_size < 0)
			next_curwin_size = 0;
		    new_size += next_curwin_size;
		    room -= new_size - next_curwin_size;
		}
		else room -= new_size;
		new_size += n;
	    }

	    
	    
	    if (!current || dir != 'v' || topfr->fr_parent != NULL || (new_size != fr->fr_width)
		    || frame_has_win(fr, next_curwin))
		win_equal_rec(next_curwin, current, fr, dir, col, row, new_size, height);
	    col += new_size;
	    width -= new_size;
	    totwincount -= wincount;
	}
    }
    else  {
	topfr->fr_width = width;
	topfr->fr_height = height;

	if (dir != 'h')			
	{
	    
	    n = frame_minheight(topfr, NOWIN);
	    
	    if (row + height == cmdline_row && p_ls == 0)
		extra_sep = 1;
	    else extra_sep = 0;
	    totwincount = (n + extra_sep) / (p_wmh + 1);
	    has_next_curwin = frame_has_win(topfr, next_curwin);

	    
	    m = frame_minheight(topfr, next_curwin);
	    room = height - m;
	    if (room < 0)
	    {
		
		
		next_curwin_size = p_wh + room;
		room = 0;
	    }
	    else {
		next_curwin_size = -1;
		FOR_ALL_FRAMES(fr, topfr->fr_child)
		{
		    if (!frame_fixed_height(fr))
			continue;
		    
		    
		    
		    n = frame_minheight(fr, NOWIN);
		    new_size = fr->fr_height;
		    if (frame_has_win(fr, next_curwin))
		    {
			room += p_wh - p_wmh;
			next_curwin_size = 0;
			if (new_size < p_wh)
			    new_size = p_wh;
		    }
		    else  totwincount -= (n + (fr->fr_next == NULL ? extra_sep : 0)) / (p_wmh + 1);


		    room -= new_size - n;
		    if (room < 0)
		    {
			new_size += room;
			room = 0;
		    }
		    fr->fr_newheight = new_size;
		}
		if (next_curwin_size == -1)
		{
		    if (!has_next_curwin)
			next_curwin_size = 0;
		    else if (totwincount > 1 && (room + (totwincount - 2))
						   / (totwincount - 1) > p_wh)
		    {
			
			
			next_curwin_size = (room + p_wh + (totwincount - 1) * p_wmh + (totwincount - 1)) / totwincount;

			room -= next_curwin_size - p_wh;
		    }
		    else next_curwin_size = p_wh;
		}
	    }

	    if (has_next_curwin)
		--totwincount;		
	}

	FOR_ALL_FRAMES(fr, topfr->fr_child)
	{
	    wincount = 1;
	    if (fr->fr_next == NULL)
		
		new_size = height;
	    else if (dir == 'h')
		new_size = fr->fr_height;
	    else if (frame_fixed_height(fr))
	    {
		new_size = fr->fr_newheight;
		wincount = 0;	    
	    }
	    else {
		
		n = frame_minheight(fr, NOWIN);
		wincount = (n + (fr->fr_next == NULL ? extra_sep : 0))
								/ (p_wmh + 1);
		m = frame_minheight(fr, next_curwin);
		if (has_next_curwin)
		    hnc = frame_has_win(fr, next_curwin);
		else hnc = FALSE;
		if (hnc)	    
		    --wincount;
		if (totwincount == 0)
		    new_size = room;
		else new_size = (wincount * room + ((unsigned)totwincount >> 1))
								/ totwincount;
		if (hnc)	    
		{
		    next_curwin_size -= p_wh - (m - n);
		    new_size += next_curwin_size;
		    room -= new_size - next_curwin_size;
		}
		else room -= new_size;
		new_size += n;
	    }
	    
	    
	    if (!current || dir != 'h' || topfr->fr_parent != NULL || (new_size != fr->fr_height)
		    || frame_has_win(fr, next_curwin))
		win_equal_rec(next_curwin, current, fr, dir, col, row, width, new_size);
	    row += new_size;
	    height -= new_size;
	    totwincount -= wincount;
	}
    }
}


    static void leaving_window(win_T *win)
{
    
    if (!bt_prompt(win->w_buffer))
	return;

    
    
    win->w_buffer->b_prompt_insert = restart_edit;
    if (restart_edit != 0 && mode_displayed)
	clear_cmdline = TRUE;		
    restart_edit = NUL;

    
    
    
    if (State & MODE_INSERT)
    {
	stop_insert_mode = TRUE;
	if (win->w_buffer->b_prompt_insert == NUL)
	    win->w_buffer->b_prompt_insert = 'A';
    }
}

    void entering_window(win_T *win)
{
    
    if (!bt_prompt(win->w_buffer))
	return;

    
    
    if (win->w_buffer->b_prompt_insert != NUL)
	stop_insert_mode = FALSE;

    
    
    if ((State & MODE_INSERT) == 0)
	restart_edit = win->w_buffer->b_prompt_insert;
}


    static void win_init_empty(win_T *wp)
{
    redraw_win_later(wp, UPD_NOT_VALID);
    wp->w_lines_valid = 0;
    wp->w_cursor.lnum = 1;
    wp->w_curswant = wp->w_cursor.col = 0;
    wp->w_cursor.coladd = 0;
    wp->w_pcmark.lnum = 1;	
    wp->w_pcmark.col = 0;
    wp->w_prev_pcmark.lnum = 0;
    wp->w_prev_pcmark.col = 0;
    wp->w_topline = 1;

    wp->w_topfill = 0;

    wp->w_botline = 2;

    wp->w_s = &wp->w_buffer->b_s;


    term_reset_wincolor(wp);

}


    void curwin_init(void)
{
    win_init_empty(curwin);
}


    void close_windows( buf_T	*buf, int		keep_curwin)


{
    win_T	*wp;
    tabpage_T   *tp, *nexttp;
    int		count = tabpage_index(NULL);

    ++RedrawingDisabled;

    for (wp = firstwin; wp != NULL && !ONE_WINDOW; )
    {
	if (wp->w_buffer == buf && (!keep_curwin || wp != curwin)
		&& !(wp->w_closing || wp->w_buffer->b_locked > 0))
	{
	    if (win_close(wp, FALSE) == FAIL)
		
		
		break;

	    
	    wp = firstwin;
	}
	else wp = wp->w_next;
    }

    
    for (tp = first_tabpage; tp != NULL; tp = nexttp)
    {
	nexttp = tp->tp_next;
	if (tp != curtab)
	    FOR_ALL_WINDOWS_IN_TAB(tp, wp)
		if (wp->w_buffer == buf && !(wp->w_closing || wp->w_buffer->b_locked > 0))
		{
		    win_close_othertab(wp, FALSE, tp);

		    
		    
		    nexttp = first_tabpage;
		    break;
		}
    }

    --RedrawingDisabled;

    if (count != tabpage_index(NULL))
	apply_autocmds(EVENT_TABCLOSED, NULL, NULL, FALSE, curbuf);
}


    static int last_window(void)
{
    return (one_window() && first_tabpage->tp_next == NULL);
}


    int one_window(void)
{
    win_T	*wp;
    int		seen_one = FALSE;

    FOR_ALL_WINDOWS(wp)
    {
	if (wp != aucmd_win)
	{
	    if (seen_one)
		return FALSE;
	    seen_one = TRUE;
	}
    }
    return TRUE;
}


    static int close_last_window_tabpage( win_T	*win, int		free_buf, tabpage_T   *prev_curtab)



{
    if (ONE_WINDOW)
    {
	buf_T	*old_curbuf = curbuf;

	
	goto_tabpage_tp(alt_tabpage(), FALSE, TRUE);

	
	
	if (valid_tabpage(prev_curtab) && prev_curtab->tp_firstwin == win)
	    win_close_othertab(win, free_buf, prev_curtab);

	entering_window(curwin);

	
	
	apply_autocmds(EVENT_TABCLOSED, NULL, NULL, FALSE, curbuf);
	apply_autocmds(EVENT_WINENTER, NULL, NULL, FALSE, curbuf);
	apply_autocmds(EVENT_TABENTER, NULL, NULL, FALSE, curbuf);
	if (old_curbuf != curbuf)
	    apply_autocmds(EVENT_BUFENTER, NULL, NULL, FALSE, curbuf);
	return TRUE;
    }
    return FALSE;
}


    static void win_close_buffer(win_T *win, int action, int abort_if_last)
{

    
    if (win->w_buffer != NULL)
	reset_synblock(win);



    
    
    if (win->w_buffer != NULL && bt_quickfix(win->w_buffer)
					&& win->w_buffer->b_nwindows == 1)
	win->w_buffer->b_p_bl = FALSE;


    
    if (win->w_buffer != NULL)
    {
	bufref_T    bufref;

	set_bufref(&bufref, curbuf);
	win->w_closing = TRUE;
	close_buffer(win, win->w_buffer, action, abort_if_last, TRUE);
	if (win_valid_any_tab(win))
	    win->w_closing = FALSE;
	
	
	if (!bufref_valid(&bufref))
	    curbuf = firstbuf;
    }
}


    int win_close(win_T *win, int free_buf)
{
    win_T	*wp;
    int		other_buffer = FALSE;
    int		close_curwin = FALSE;
    int		dir;
    int		help_window = FALSE;
    tabpage_T   *prev_curtab = curtab;
    frame_T	*win_frame = win->w_frame->fr_parent;

    int		had_diffmode = win->w_p_diff;


    int		did_decrement = FALSE;



    
    if (may_close_term_popup() == OK)
	return OK;

    if (ERROR_IF_ANY_POPUP_WINDOW)
	return FAIL;

    if (last_window())
    {
	emsg(_(e_cannot_close_last_window));
	return FAIL;
    }
    if (window_layout_locked(CMD_close))
	return FAIL;

    if (win->w_closing || (win->w_buffer != NULL && win->w_buffer->b_locked > 0))
	return FAIL; 
    if (win_unlisted(win))
    {
	emsg(_(e_cannot_close_autocmd_or_popup_window));
	return FAIL;
    }
    if ((firstwin == aucmd_win || lastwin == aucmd_win) && one_window())
    {
	emsg(_(e_cannot_close_window_only_autocmd_window_would_remain));
	return FAIL;
    }

    
    
    
    if (close_last_window_tabpage(win, free_buf, prev_curtab))
      return FAIL;

    
    
    if (bt_help(win->w_buffer))
	help_window = TRUE;
    else clear_snapshot(curtab, SNAP_HELP_IDX);

    if (win == curwin)
    {

	leaving_window(curwin);

	
	wp = frame2win(win_altframe(win, NULL));

	
	if (wp->w_buffer != curbuf)
	{
	    reset_VIsual_and_resel();	

	    other_buffer = TRUE;
	    win->w_closing = TRUE;
	    apply_autocmds(EVENT_BUFLEAVE, NULL, NULL, FALSE, curbuf);
	    if (!win_valid(win))
		return FAIL;
	    win->w_closing = FALSE;
	    if (last_window())
		return FAIL;
	}
	win->w_closing = TRUE;
	apply_autocmds(EVENT_WINLEAVE, NULL, NULL, FALSE, curbuf);
	if (!win_valid(win))
	    return FAIL;
	win->w_closing = FALSE;
	if (last_window())
	    return FAIL;

	
	if (aborting())
	    return FAIL;

    }


    
    
    if (gui.in_use)
	out_flush();



    if (popup_win_closed(win) && !win_valid(win))
	return FAIL;


    
    trigger_winclosed(win);
    
    if (!win_valid_any_tab(win))
	return OK;

    win_close_buffer(win, free_buf ? DOBUF_UNLOAD : 0, TRUE);

    if (only_one_window() && win_valid(win) && win->w_buffer == NULL && (last_window() || curtab != prev_curtab || close_last_window_tabpage(win, free_buf, prev_curtab)))

    {
	
	
	if (curwin->w_buffer == NULL)
	    curwin->w_buffer = curbuf;
	getout(0);
    }

    
    if (curtab != prev_curtab && win_valid_any_tab(win)
						      && win->w_buffer == NULL)
    {
	
	
	block_autocmds();
	win_close_othertab(win, FALSE, prev_curtab);
	unblock_autocmds();
	return FAIL;
    }

    
    
    if (!win_valid(win) || last_window()
	    || close_last_window_tabpage(win, free_buf, prev_curtab))
	return FAIL;

    
    
    
    
    ++split_disallowed;

    ++dont_parse_messages;


    
    
    wp = win_free_mem(win, &dir, NULL);

    if (help_window)
    {
	
	
	win_T *prev_win = get_snapshot_curwin(SNAP_HELP_IDX);

	if (win_valid(prev_win))
	    wp = prev_win;
    }

    
    
    
    if (win == curwin)
    {
	curwin = wp;

	if (wp->w_p_pvw || bt_quickfix(wp->w_buffer))
	{
	    
	    for (;;)
	    {
		if (wp->w_next == NULL)
		    wp = firstwin;
		else wp = wp->w_next;
		if (wp == curwin)
		    break;
		if (!wp->w_p_pvw && !bt_quickfix(wp->w_buffer))
		{
		    curwin = wp;
		    break;
		}
	    }
	}

	curbuf = curwin->w_buffer;
	close_curwin = TRUE;

	
	
	check_cursor();
    }

    
    last_status(FALSE);

    if (p_ea && (*p_ead == 'b' || *p_ead == dir))
	
	
	win_equal(curwin, curwin->w_frame->fr_parent == win_frame, dir);
    else {
	win_comp_pos();
	if (*p_spk != 'c')
	    win_fix_scroll(FALSE);
    }
    if (close_curwin)
    {
	
	

	did_decrement =  (void)


	    win_enter_ext(wp, WEE_CURWIN_INVALID | WEE_TRIGGER_ENTER_AUTOCMDS | WEE_TRIGGER_LEAVE_AUTOCMDS | WEE_ALLOW_PARSE_MESSAGES);

	if (other_buffer)
	    
	    apply_autocmds(EVENT_BUFENTER, NULL, NULL, FALSE, curbuf);
    }

    --split_disallowed;

    if (!did_decrement)
	--dont_parse_messages;


    
    
    if (help_window)
	restore_snapshot(SNAP_HELP_IDX, close_curwin);


    
    
    
    if (diffopt_closeoff() && had_diffmode && curtab == prev_curtab)
    {
	int	diffcount = 0;
	win_T	*dwin;

	FOR_ALL_WINDOWS(dwin)
	    if (dwin->w_p_diff)
		++diffcount;
	if (diffcount == 1)
	    do_cmdline_cmd((char_u *)"diffoff!");
    }



    
    if (gui.in_use && !win_hasvertsplit())
	gui_init_which_components(NULL);


    redraw_all_later(UPD_NOT_VALID);
    return OK;
}

    static void trigger_winclosed(win_T *win)
{
    static int	recursive = FALSE;
    char_u	winid[NUMBUFLEN];

    if (recursive)
	return;
    recursive = TRUE;
    vim_snprintf((char *)winid, sizeof(winid), "%d", win->w_id);
    apply_autocmds(EVENT_WINCLOSED, winid, winid, FALSE, win->w_buffer);
    recursive = FALSE;
}


    void snapshot_windows_scroll_size(void)
{
    win_T *wp;
    FOR_ALL_WINDOWS(wp)
    {
	wp->w_last_topline = wp->w_topline;
	wp->w_last_leftcol = wp->w_leftcol;
	wp->w_last_skipcol = wp->w_skipcol;
	wp->w_last_width = wp->w_width;
	wp->w_last_height = wp->w_height;
    }
}

static int did_initial_scroll_size_snapshot = FALSE;

    void may_make_initial_scroll_size_snapshot(void)
{
    if (!did_initial_scroll_size_snapshot)
    {
	did_initial_scroll_size_snapshot = TRUE;
	snapshot_windows_scroll_size();
    }
}



    static dict_T * make_win_info_dict( int width, int height, int topline, int leftcol, int skipcol)





{
    dict_T *d = dict_alloc();
    if (d == NULL)
	return NULL;
    d->dv_refcount = 1;

    
    while (1)
    {
	typval_T tv;
	tv.v_lock = 0;
	tv.v_type = VAR_NUMBER;

	tv.vval.v_number = width;
	if (dict_add_tv(d, "width", &tv) == FAIL)
	    break;
	tv.vval.v_number = height;
	if (dict_add_tv(d, "height", &tv) == FAIL)
	    break;
	tv.vval.v_number = topline;
	if (dict_add_tv(d, "topline", &tv) == FAIL)
	    break;
	tv.vval.v_number = leftcol;
	if (dict_add_tv(d, "leftcol", &tv) == FAIL)
	    break;
	tv.vval.v_number = skipcol;
	if (dict_add_tv(d, "skipcol", &tv) == FAIL)
	    break;
	return d;
    }
    dict_unref(d);
    return NULL;
}







    static int check_window_scroll_resize( int	*size_count, win_T	**first_scroll_win, win_T	**first_size_win, list_T	*winlist UNUSED, dict_T	*v_event UNUSED)





{
    int result = 0;

    int listidx = 0;
    int tot_width = 0;
    int tot_height = 0;
    int tot_topline = 0;
    int tot_leftcol = 0;
    int tot_skipcol = 0;


    win_T *wp;
    FOR_ALL_WINDOWS(wp)
    {
	int size_changed = wp->w_last_width != wp->w_width || wp->w_last_height != wp->w_height;
	if (size_changed)
	{
	    result |= CWSR_RESIZED;

	    if (winlist != NULL)
	    {
		
		typval_T tv;
		tv.v_lock = 0;
		tv.v_type = VAR_NUMBER;
		tv.vval.v_number = wp->w_id;
		list_set_item(winlist, listidx++, &tv);
	    }
	    else  if (size_count != NULL)

	    {
		++*size_count;
		if (*first_size_win == NULL)
		    *first_size_win = wp;
		
		
		if (*first_scroll_win == NULL)
		    *first_scroll_win = wp;
	    }
	}

	int scroll_changed = wp->w_last_topline != wp->w_topline || wp->w_last_leftcol != wp->w_leftcol || wp->w_last_skipcol != wp->w_skipcol;

	if (scroll_changed)
	{
	    result |= CWSR_SCROLLED;
	    if (first_scroll_win != NULL && *first_scroll_win == NULL)
		*first_scroll_win = wp;
	}


	if ((size_changed || scroll_changed) && v_event != NULL)
	{
	    
	    int width = wp->w_width - wp->w_last_width;
	    int height = wp->w_height - wp->w_last_height;
	    int topline = wp->w_topline - wp->w_last_topline;
	    int leftcol = wp->w_leftcol - wp->w_last_leftcol;
	    int skipcol = wp->w_skipcol - wp->w_last_skipcol;
	    dict_T *d = make_win_info_dict(width, height, topline, leftcol, skipcol);
	    if (d == NULL)
		break;
	    char winid[NUMBUFLEN];
	    vim_snprintf(winid, sizeof(winid), "%d", wp->w_id);
	    if (dict_add_dict(v_event, winid, d) == FAIL)
	    {
		dict_unref(d);
		break;
	    }
	    --d->dv_refcount;

	    tot_width += abs(width);
	    tot_height += abs(height);
	    tot_topline += abs(topline);
	    tot_leftcol += abs(leftcol);
	    tot_skipcol += abs(skipcol);
	}

    }


    if (v_event != NULL)
    {
	dict_T *alldict = make_win_info_dict(tot_width, tot_height, tot_topline, tot_leftcol, tot_skipcol);
	if (alldict != NULL)
	{
	    if (dict_add_dict(v_event, "all", alldict) == FAIL)
		dict_unref(alldict);
	    else --alldict->dv_refcount;
	}
    }


    return result;
}


    void may_trigger_win_scrolled_resized(void)
{
    static int	    recursive = FALSE;
    int		    do_resize = has_winresized();
    int		    do_scroll = has_winscrolled();

    
    
    if (recursive || !(do_scroll || do_resize)
	    || !did_initial_scroll_size_snapshot)
	return;

    int size_count = 0;
    win_T *first_scroll_win = NULL, *first_size_win = NULL;
    int cwsr = check_window_scroll_resize(&size_count, &first_scroll_win, &first_size_win, NULL, NULL);

    int trigger_resize = do_resize && size_count > 0;
    int trigger_scroll = do_scroll && cwsr != 0;
    if (!trigger_resize && !trigger_scroll)
	return;  

    list_T *windows_list = NULL;
    if (trigger_resize)
    {
	
	windows_list = list_alloc_with_items(size_count);
	(void)check_window_scroll_resize(NULL, NULL, NULL, windows_list, NULL);
    }

    dict_T *scroll_dict = NULL;
    if (trigger_scroll)
    {
	
	scroll_dict = dict_alloc();
	if (scroll_dict != NULL)
	{
	    scroll_dict->dv_refcount = 1;
	    (void)check_window_scroll_resize(NULL, NULL, NULL, NULL, scroll_dict);
	}
    }


    
    
    
    
    snapshot_windows_scroll_size();

    
    
    window_layout_lock();
    recursive = TRUE;

    
    if (trigger_resize)
    {

	save_v_event_T  save_v_event;
	dict_T		*v_event = get_v_event(&save_v_event);

	if (dict_add_list(v_event, "windows", windows_list) == OK)
	{
	    dict_set_items_ro(v_event);

	    char_u winid[NUMBUFLEN];
	    vim_snprintf((char *)winid, sizeof(winid), "%d", first_size_win->w_id);
	    apply_autocmds(EVENT_WINRESIZED, winid, winid, FALSE, first_size_win->w_buffer);

	}
	restore_v_event(v_event, &save_v_event);

    }

    if (trigger_scroll  && scroll_dict != NULL  )



    {

	save_v_event_T  save_v_event;
	dict_T		*v_event = get_v_event(&save_v_event);

	
	dict_extend(v_event, scroll_dict, (char_u *)"move", NULL);
	dict_set_items_ro(v_event);
	dict_unref(scroll_dict);

	char_u winid[NUMBUFLEN];
	vim_snprintf((char *)winid, sizeof(winid), "%d", first_scroll_win->w_id);
	apply_autocmds(EVENT_WINSCROLLED, winid, winid, FALSE, first_scroll_win->w_buffer);

	restore_v_event(v_event, &save_v_event);

    }

    recursive = FALSE;
    window_layout_unlock();
}


    void win_close_othertab(win_T *win, int free_buf, tabpage_T *tp)
{
    win_T	*wp;
    int		dir;
    tabpage_T   *ptp = NULL;
    int		free_tp = FALSE;

    
    
    if (win->w_closing || (win->w_buffer != NULL && win->w_buffer->b_locked > 0))
	return; 

    
    trigger_winclosed(win);
    
    if (!win_valid_any_tab(win))
	return;

    if (win->w_buffer != NULL)
	
	close_buffer(win, win->w_buffer, free_buf ? DOBUF_UNLOAD : 0, FALSE, TRUE);

    
    
    for (ptp = first_tabpage; ptp != NULL && ptp != tp; ptp = ptp->tp_next)
	;
    if (ptp == NULL || tp == curtab)
    {
	
	
	if (win_valid_any_tab(win) && win->w_buffer == NULL)
	{
	    win->w_buffer = firstbuf;
	    ++firstbuf->b_nwindows;
	    win_init_empty(win);
	}
	return;
    }

    
    for (wp = tp->tp_firstwin; wp != NULL && wp != win; wp = wp->w_next)
	;
    if (wp == NULL)
	return;

    
    if (tp->tp_firstwin == tp->tp_lastwin)
    {
	int	h = tabline_height();

	if (tp == first_tabpage)
	    first_tabpage = tp->tp_next;
	else {
	    for (ptp = first_tabpage; ptp != NULL && ptp->tp_next != tp;
							   ptp = ptp->tp_next)
		;
	    if (ptp == NULL)
	    {
		internal_error("win_close_othertab()");
		return;
	    }
	    ptp->tp_next = tp->tp_next;
	}
	free_tp = TRUE;
	redraw_tabline = TRUE;
	if (h != tabline_height())
	    shell_new_rows();
    }

    
    win_free_mem(win, &dir, tp);

    if (free_tp)
	free_tabpage(tp);
}


    static win_T * win_free_mem( win_T	*win, int		*dirp, tabpage_T	*tp)



{
    frame_T	*frp;
    win_T	*wp;
    tabpage_T	*win_tp = tp == NULL ? curtab : tp;

    
    frp = win->w_frame;
    wp = winframe_remove(win, dirp, tp);
    vim_free(frp);
    win_free(win, tp);

    
    
    if (win == win_tp->tp_curwin)
	win_tp->tp_curwin = wp;

    return wp;
}


    void win_free_all(void)
{
    int		dummy;

    
    cmdwin_type = 0;

    while (first_tabpage->tp_next != NULL)
	tabpage_close(TRUE);

    if (aucmd_win != NULL)
    {
	(void)win_free_mem(aucmd_win, &dummy, NULL);
	aucmd_win = NULL;
    }

    while (firstwin != NULL)
	(void)win_free_mem(firstwin, &dummy, NULL);

    
    
    curwin = NULL;
}



    win_T * winframe_remove( win_T	*win, int		*dirp UNUSED, tabpage_T	*tp)



{
    frame_T	*frp, *frp2, *frp3;
    frame_T	*frp_close = win->w_frame;
    win_T	*wp;

    
    if (tp == NULL ? ONE_WINDOW : tp->tp_firstwin == tp->tp_lastwin)
	return NULL;

    
    frp2 = win_altframe(win, tp);
    wp = frame2win(frp2);

    
    frame_remove(frp_close);

    if (frp_close->fr_parent->fr_layout == FR_COL)
    {
	
	
	
	if (frp2->fr_win != NULL && frp2->fr_win->w_p_wfh)
	{
	    frp = frp_close->fr_prev;
	    frp3 = frp_close->fr_next;
	    while (frp != NULL || frp3 != NULL)
	    {
		if (frp != NULL)
		{
		    if (!frame_fixed_height(frp))
		    {
			frp2 = frp;
			wp = frame2win(frp2);
			break;
		    }
		    frp = frp->fr_prev;
		}
		if (frp3 != NULL)
		{
		    if (frp3->fr_win != NULL && !frp3->fr_win->w_p_wfh)
		    {
			frp2 = frp3;
			wp = frp3->fr_win;
			break;
		    }
		    frp3 = frp3->fr_next;
		}
	    }
	}
	frame_new_height(frp2, frp2->fr_height + frp_close->fr_height, frp2 == frp_close->fr_next ? TRUE : FALSE, FALSE);
	*dirp = 'v';
    }
    else {
	
	
	
	if (frp2->fr_win != NULL && frp2->fr_win->w_p_wfw)
	{
	    frp = frp_close->fr_prev;
	    frp3 = frp_close->fr_next;
	    while (frp != NULL || frp3 != NULL)
	    {
		if (frp != NULL)
		{
		    if (!frame_fixed_width(frp))
		    {
			frp2 = frp;
			wp = frame2win(frp2);
			break;
		    }
		    frp = frp->fr_prev;
		}
		if (frp3 != NULL)
		{
		    if (frp3->fr_win != NULL && !frp3->fr_win->w_p_wfw)
		    {
			frp2 = frp3;
			wp = frp3->fr_win;
			break;
		    }
		    frp3 = frp3->fr_next;
		}
	    }
	}
	frame_new_width(frp2, frp2->fr_width + frp_close->fr_width, frp2 == frp_close->fr_next ? TRUE : FALSE, FALSE);
	*dirp = 'h';
    }

    
    
    if (frp2 == frp_close->fr_next)
    {
	int row = win->w_winrow;
	int col = win->w_wincol;

	frame_comp_pos(frp2, &row, &col);
    }

    if (frp2->fr_next == NULL && frp2->fr_prev == NULL)
    {
	
	
	frp2->fr_parent->fr_layout = frp2->fr_layout;
	frp2->fr_parent->fr_child = frp2->fr_child;
	FOR_ALL_FRAMES(frp, frp2->fr_child)
	    frp->fr_parent = frp2->fr_parent;
	frp2->fr_parent->fr_win = frp2->fr_win;
	if (frp2->fr_win != NULL)
	    frp2->fr_win->w_frame = frp2->fr_parent;
	frp = frp2->fr_parent;
	if (topframe->fr_child == frp2)
	    topframe->fr_child = frp;
	vim_free(frp2);

	frp2 = frp->fr_parent;
	if (frp2 != NULL && frp2->fr_layout == frp->fr_layout)
	{
	    
	    
	    if (frp2->fr_child == frp)
		frp2->fr_child = frp->fr_child;
	    frp->fr_child->fr_prev = frp->fr_prev;
	    if (frp->fr_prev != NULL)
		frp->fr_prev->fr_next = frp->fr_child;
	    for (frp3 = frp->fr_child; ; frp3 = frp3->fr_next)
	    {
		frp3->fr_parent = frp2;
		if (frp3->fr_next == NULL)
		{
		    frp3->fr_next = frp->fr_next;
		    if (frp->fr_next != NULL)
			frp->fr_next->fr_prev = frp3;
		    break;
		}
	    }
	    if (topframe->fr_child == frp)
		topframe->fr_child = frp2;
	    vim_free(frp);
	}
    }

    return wp;
}


    static frame_T * win_altframe( win_T	*win, tabpage_T	*tp)


{
    frame_T	*frp;
    frame_T	*other_fr, *target_fr;

    if (tp == NULL ? ONE_WINDOW : tp->tp_firstwin == tp->tp_lastwin)
	return alt_tabpage()->tp_curwin->w_frame;

    frp = win->w_frame;

    if (frp->fr_prev == NULL)
	return frp->fr_next;
    if (frp->fr_next == NULL)
	return frp->fr_prev;

    
    
    target_fr = frp->fr_next;
    other_fr  = frp->fr_prev;

    
    
    if (frp->fr_parent != NULL && frp->fr_parent->fr_layout == FR_COL && p_sb)
    {
	target_fr = frp->fr_prev;
	other_fr  = frp->fr_next;
    }

    
    
    if (frp->fr_parent != NULL && frp->fr_parent->fr_layout == FR_ROW && p_spr)
    {
	target_fr = frp->fr_prev;
	other_fr  = frp->fr_next;
    }

    
    
    if (frp->fr_parent != NULL && frp->fr_parent->fr_layout == FR_ROW)
    {
	if (frame_fixed_width(target_fr) && !frame_fixed_width(other_fr))
	    target_fr = other_fr;
    }
    else {
	if (frame_fixed_height(target_fr) && !frame_fixed_height(other_fr))
	    target_fr = other_fr;
    }

    return target_fr;
}


    static tabpage_T * alt_tabpage(void)
{
    tabpage_T	*tp;

    
    if (curtab->tp_next != NULL)
	return curtab->tp_next;

    
    for (tp = first_tabpage; tp->tp_next != curtab; tp = tp->tp_next)
	;
    return tp;
}


    static win_T * frame2win(frame_T *frp)
{
    while (frp->fr_win == NULL)
	frp = frp->fr_child;
    return frp->fr_win;
}


    static int frame_has_win(frame_T *frp, win_T *wp)
{
    frame_T	*p;

    if (frp->fr_layout == FR_LEAF)
	return frp->fr_win == wp;

    FOR_ALL_FRAMES(p, frp->fr_child)
	if (frame_has_win(p, wp))
	    return TRUE;
    return FALSE;
}


    static void frame_new_height( frame_T	*topfrp, int		height, int		topfirst, int		wfh)




				
{
    frame_T	*frp;
    int		extra_lines;
    int		h;

    if (topfrp->fr_win != NULL)
    {
	
	win_new_height(topfrp->fr_win, height - topfrp->fr_win->w_status_height - WINBAR_HEIGHT(topfrp->fr_win));

    }
    else if (topfrp->fr_layout == FR_ROW)
    {
	do {
	    
	    FOR_ALL_FRAMES(frp, topfrp->fr_child)
	    {
		frame_new_height(frp, height, topfirst, wfh);
		if (frp->fr_height > height)
		{
		    
		    height = frp->fr_height;
		    break;
		}
	    }
	}
	while (frp != NULL);
    }
    else     {
	
	

	frp = topfrp->fr_child;
	if (wfh)
	    
	    while (frame_fixed_height(frp))
	    {
		frp = frp->fr_next;
		if (frp == NULL)
		    return;	    
	    }
	if (!topfirst)
	{
	    
	    while (frp->fr_next != NULL)
		frp = frp->fr_next;
	    if (wfh)
		
		while (frame_fixed_height(frp))
		    frp = frp->fr_prev;
	}

	extra_lines = height - topfrp->fr_height;
	if (extra_lines < 0)
	{
	    
	    while (frp != NULL)
	    {
		h = frame_minheight(frp, NULL);
		if (frp->fr_height + extra_lines < h)
		{
		    extra_lines += frp->fr_height - h;
		    frame_new_height(frp, h, topfirst, wfh);
		}
		else {
		    frame_new_height(frp, frp->fr_height + extra_lines, topfirst, wfh);
		    break;
		}
		if (topfirst)
		{
		    do frp = frp->fr_next;
		    while (wfh && frp != NULL && frame_fixed_height(frp));
		}
		else {
		    do frp = frp->fr_prev;
		    while (wfh && frp != NULL && frame_fixed_height(frp));
		}
		
		if (frp == NULL)
		    height -= extra_lines;
	    }
	}
	else if (extra_lines > 0)
	{
	    
	    frame_new_height(frp, frp->fr_height + extra_lines, topfirst, wfh);
	}
    }
    topfrp->fr_height = height;
}


    static int frame_fixed_height(frame_T *frp)
{
    
    if (frp->fr_win != NULL)
	return frp->fr_win->w_p_wfh;

    if (frp->fr_layout == FR_ROW)
    {
	
	
	FOR_ALL_FRAMES(frp, frp->fr_child)
	    if (frame_fixed_height(frp))
		return TRUE;
	return FALSE;
    }

    
    
    FOR_ALL_FRAMES(frp, frp->fr_child)
	if (!frame_fixed_height(frp))
	    return FALSE;
    return TRUE;
}


    static int frame_fixed_width(frame_T *frp)
{
    
    if (frp->fr_win != NULL)
	return frp->fr_win->w_p_wfw;

    if (frp->fr_layout == FR_COL)
    {
	
	
	FOR_ALL_FRAMES(frp, frp->fr_child)
	    if (frame_fixed_width(frp))
		return TRUE;
	return FALSE;
    }

    
    
    FOR_ALL_FRAMES(frp, frp->fr_child)
	if (!frame_fixed_width(frp))
	    return FALSE;
    return TRUE;
}


    static void frame_add_statusline(frame_T *frp)
{
    win_T	*wp;

    if (frp->fr_layout == FR_LEAF)
    {
	wp = frp->fr_win;
	if (wp->w_status_height == 0)
	{
	    if (wp->w_height > 0)	
		--wp->w_height;
	    wp->w_status_height = STATUS_HEIGHT;
	}
    }
    else if (frp->fr_layout == FR_ROW)
    {
	
	FOR_ALL_FRAMES(frp, frp->fr_child)
	    frame_add_statusline(frp);
    }
    else  {
	
	for (frp = frp->fr_child; frp->fr_next != NULL; frp = frp->fr_next)
	    ;
	frame_add_statusline(frp);
    }
}


    static void frame_new_width( frame_T	*topfrp, int		width, int		leftfirst, int		wfw)




				
{
    frame_T	*frp;
    int		extra_cols;
    int		w;
    win_T	*wp;

    if (topfrp->fr_layout == FR_LEAF)
    {
	
	wp = topfrp->fr_win;
	
	for (frp = topfrp; frp->fr_parent != NULL; frp = frp->fr_parent)
	    if (frp->fr_parent->fr_layout == FR_ROW && frp->fr_next != NULL)
		break;
	if (frp->fr_parent == NULL)
	    wp->w_vsep_width = 0;
	win_new_width(wp, width - wp->w_vsep_width);
    }
    else if (topfrp->fr_layout == FR_COL)
    {
	do {
	    
	    FOR_ALL_FRAMES(frp, topfrp->fr_child)
	    {
		frame_new_width(frp, width, leftfirst, wfw);
		if (frp->fr_width > width)
		{
		    
		    width = frp->fr_width;
		    break;
		}
	    }
	} while (frp != NULL);
    }
    else     {
	
	

	frp = topfrp->fr_child;
	if (wfw)
	    
	    while (frame_fixed_width(frp))
	    {
		frp = frp->fr_next;
		if (frp == NULL)
		    return;	    
	    }
	if (!leftfirst)
	{
	    
	    while (frp->fr_next != NULL)
		frp = frp->fr_next;
	    if (wfw)
		
		while (frame_fixed_width(frp))
		    frp = frp->fr_prev;
	}

	extra_cols = width - topfrp->fr_width;
	if (extra_cols < 0)
	{
	    
	    while (frp != NULL)
	    {
		w = frame_minwidth(frp, NULL);
		if (frp->fr_width + extra_cols < w)
		{
		    extra_cols += frp->fr_width - w;
		    frame_new_width(frp, w, leftfirst, wfw);
		}
		else {
		    frame_new_width(frp, frp->fr_width + extra_cols, leftfirst, wfw);
		    break;
		}
		if (leftfirst)
		{
		    do frp = frp->fr_next;
		    while (wfw && frp != NULL && frame_fixed_width(frp));
		}
		else {
		    do frp = frp->fr_prev;
		    while (wfw && frp != NULL && frame_fixed_width(frp));
		}
		
		if (frp == NULL)
		    width -= extra_cols;
	    }
	}
	else if (extra_cols > 0)
	{
	    
	    frame_new_width(frp, frp->fr_width + extra_cols, leftfirst, wfw);
	}
    }
    topfrp->fr_width = width;
}


    static void frame_add_vsep(frame_T *frp)
{
    win_T	*wp;

    if (frp->fr_layout == FR_LEAF)
    {
	wp = frp->fr_win;
	if (wp->w_vsep_width == 0)
	{
	    if (wp->w_width > 0)	
		--wp->w_width;
	    wp->w_vsep_width = 1;
	}
    }
    else if (frp->fr_layout == FR_COL)
    {
	
	FOR_ALL_FRAMES(frp, frp->fr_child)
	    frame_add_vsep(frp);
    }
    else  {
	
	frp = frp->fr_child;
	while (frp->fr_next != NULL)
	    frp = frp->fr_next;
	frame_add_vsep(frp);
    }
}


    static void frame_fix_width(win_T *wp)
{
    wp->w_frame->fr_width = wp->w_width + wp->w_vsep_width;
}


    static void frame_fix_height(win_T *wp)
{
    wp->w_frame->fr_height = VISIBLE_HEIGHT(wp) + wp->w_status_height;
}


    static int frame_minheight(frame_T *topfrp, win_T *next_curwin)
{
    frame_T	*frp;
    int		m;
    int		n;

    if (topfrp->fr_win != NULL)
    {
	if (topfrp->fr_win == next_curwin)
	    m = p_wh + topfrp->fr_win->w_status_height;
	else {
	    
	    m = p_wmh + topfrp->fr_win->w_status_height;
	    if (topfrp->fr_win == curwin && next_curwin == NULL)
	    {
		
		
		if (p_wmh == 0)
		    ++m;
		m += WINBAR_HEIGHT(curwin);
	    }
	}
    }
    else if (topfrp->fr_layout == FR_ROW)
    {
	
	m = 0;
	FOR_ALL_FRAMES(frp, topfrp->fr_child)
	{
	    n = frame_minheight(frp, next_curwin);
	    if (n > m)
		m = n;
	}
    }
    else {
	
	m = 0;
	FOR_ALL_FRAMES(frp, topfrp->fr_child)
	    m += frame_minheight(frp, next_curwin);
    }

    return m;
}


    static int frame_minwidth( frame_T	*topfrp, win_T	*next_curwin)


{
    frame_T	*frp;
    int		m, n;

    if (topfrp->fr_win != NULL)
    {
	if (topfrp->fr_win == next_curwin)
	    m = p_wiw + topfrp->fr_win->w_vsep_width;
	else {
	    
	    m = p_wmw + topfrp->fr_win->w_vsep_width;
	    
	    if (p_wmw == 0 && topfrp->fr_win == curwin && next_curwin == NULL)
		++m;
	}
    }
    else if (topfrp->fr_layout == FR_COL)
    {
	
	m = 0;
	FOR_ALL_FRAMES(frp, topfrp->fr_child)
	{
	    n = frame_minwidth(frp, next_curwin);
	    if (n > m)
		m = n;
	}
    }
    else {
	
	m = 0;
	FOR_ALL_FRAMES(frp, topfrp->fr_child)
	    m += frame_minwidth(frp, next_curwin);
    }

    return m;
}



    void close_others( int		message, int		forceit)


{
    win_T	*wp;
    win_T	*nextwp;
    int		r;

    if (one_window())
    {
	if (message && !autocmd_busy)
	    msg(_(m_onlyone));
	return;
    }

    
    for (wp = firstwin; win_valid(wp); wp = nextwp)
    {
	nextwp = wp->w_next;
	if (wp == curwin)		
	    continue;

	
	r = can_abandon(wp->w_buffer, forceit);
	if (!win_valid(wp))		
	{
	    nextwp = firstwin;
	    continue;
	}
	if (!r)
	{

	    if (message && (p_confirm || (cmdmod.cmod_flags & CMOD_CONFIRM)) && p_write)
	    {
		dialog_changed(wp->w_buffer, FALSE);
		if (!win_valid(wp))		
		{
		    nextwp = firstwin;
		    continue;
		}
	    }
	    if (bufIsChanged(wp->w_buffer))

		continue;
	}
	win_close(wp, !buf_hide(wp->w_buffer) && !bufIsChanged(wp->w_buffer));
    }

    if (message && !ONE_WINDOW)
	emsg(_(e_other_window_contains_changes));
}


    void unuse_tabpage(tabpage_T *tp)
{
    tp->tp_topframe = topframe;
    tp->tp_firstwin = firstwin;
    tp->tp_lastwin = lastwin;
    tp->tp_curwin = curwin;
}


    void use_tabpage(tabpage_T *tp)
{
    curtab = tp;
    topframe = curtab->tp_topframe;
    firstwin = curtab->tp_firstwin;
    lastwin = curtab->tp_lastwin;
    curwin = curtab->tp_curwin;
}


    int win_alloc_first(void)
{
    if (win_alloc_firstwin(NULL) == FAIL)
	return FAIL;

    first_tabpage = alloc_tabpage();
    if (first_tabpage == NULL)
	return FAIL;
    curtab = first_tabpage;
    unuse_tabpage(first_tabpage);

    return OK;
}


    win_T * win_alloc_popup_win(void)
{
    win_T *wp;

    wp = win_alloc(NULL, TRUE);
    if (wp != NULL)
    {
	
	
	win_init_some(wp, curwin);

	RESET_BINDING(wp);
	new_frame(wp);
    }
    return wp;
}


    void win_init_popup_win(win_T *wp, buf_T *buf)
{
    wp->w_buffer = buf;
    ++buf->b_nwindows;
    win_init_empty(wp); 

    
    
    VIM_CLEAR(wp->w_localdir);
}


    static int win_alloc_firstwin(win_T *oldwin)
{
    curwin = win_alloc(NULL, FALSE);
    if (curwin == NULL)
	return FAIL;
    if (oldwin == NULL)
    {
	
	
	curbuf = buflist_new(NULL, NULL, 1L, BLN_LISTED);
	if (curwin == NULL || curbuf == NULL)
	    return FAIL;
	curwin->w_buffer = curbuf;

	curwin->w_s = &(curbuf->b_s);

	curbuf->b_nwindows = 1;	
	curwin->w_alist = &global_alist;
	curwin_init();		
    }
    else {
	
	win_init(curwin, oldwin, 0);

	
	RESET_BINDING(curwin);
    }

    new_frame(curwin);
    if (curwin->w_frame == NULL)
	return FAIL;
    topframe = curwin->w_frame;
    topframe->fr_width = Columns;
    topframe->fr_height = Rows - p_ch;

    return OK;
}


    static void new_frame(win_T *wp)
{
    frame_T *frp = ALLOC_CLEAR_ONE(frame_T);

    wp->w_frame = frp;
    if (frp != NULL)
    {
	frp->fr_layout = FR_LEAF;
	frp->fr_win = wp;
    }
}


    void win_init_size(void)
{
    firstwin->w_height = ROWS_AVAIL;
    firstwin->w_prev_height = ROWS_AVAIL;
    topframe->fr_height = ROWS_AVAIL;
    firstwin->w_width = Columns;
    topframe->fr_width = Columns;
}


    static tabpage_T * alloc_tabpage(void)
{
    tabpage_T	*tp;

    int		i;



    tp = ALLOC_CLEAR_ONE(tabpage_T);
    if (tp == NULL)
	return NULL;


    
    tp->tp_vars = dict_alloc_id(aid_newtabpage_tvars);
    if (tp->tp_vars == NULL)
    {
	vim_free(tp);
	return NULL;
    }
    init_var_dict(tp->tp_vars, &tp->tp_winvar, VAR_SCOPE);



    for (i = 0; i < 3; i++)
	tp->tp_prev_which_scrollbars[i] = -1;


    tp->tp_diff_invalid = TRUE;

    tp->tp_ch_used = p_ch;

    return tp;
}

    void free_tabpage(tabpage_T *tp)
{
    int idx;


    diff_clear(tp);


    while (tp->tp_first_popupwin != NULL)
	popup_close_tabpage(tp, tp->tp_first_popupwin->w_id, TRUE);

    for (idx = 0; idx < SNAP_COUNT; ++idx)
	clear_snapshot(tp, idx);

    vars_clear(&tp->tp_vars->dv_hashtab);	
    hash_init(&tp->tp_vars->dv_hashtab);
    unref_var_dict(tp->tp_vars);


    if (tp == lastused_tabpage)
	lastused_tabpage = NULL;

    vim_free(tp->tp_localdir);
    vim_free(tp->tp_prevdir);


    python_tabpage_free(tp);



    python3_tabpage_free(tp);


    vim_free(tp);
}


    int win_new_tabpage(int after)
{
    tabpage_T	*tp = curtab;
    tabpage_T	*prev_tp = curtab;
    tabpage_T	*newtp;
    int		n;

    if (cmdwin_type != 0)
    {
	emsg(_(e_invalid_in_cmdline_window));
	return FAIL;
    }
    if (window_layout_locked(CMD_tabnew))
	return FAIL;

    newtp = alloc_tabpage();
    if (newtp == NULL)
	return FAIL;

    
    if (leave_tabpage(curbuf, TRUE) == FAIL)
    {
	vim_free(newtp);
	return FAIL;
    }
    curtab = newtp;

    newtp->tp_localdir = (tp->tp_localdir == NULL)
				    ? NULL : vim_strsave(tp->tp_localdir);
    
    if (win_alloc_firstwin(tp->tp_curwin) == OK)
    {
	
	if (after == 1)
	{
	    
	    newtp->tp_next = first_tabpage;
	    first_tabpage = newtp;
	}
	else {
	    if (after > 0)
	    {
		
		n = 2;
		for (tp = first_tabpage; tp->tp_next != NULL && n < after; tp = tp->tp_next)
		    ++n;
	    }
	    newtp->tp_next = tp->tp_next;
	    tp->tp_next = newtp;
	}
	newtp->tp_firstwin = newtp->tp_lastwin = newtp->tp_curwin = curwin;

	win_init_size();
	firstwin->w_winrow = tabline_height();
	firstwin->w_prev_winrow = firstwin->w_winrow;
	win_comp_scroll(curwin);

	newtp->tp_topframe = topframe;
	last_status(FALSE);

	lastused_tabpage = prev_tp;


	
	
	gui_may_update_scrollbars();


	entering_window(curwin);


	redraw_all_later(UPD_NOT_VALID);
	apply_autocmds(EVENT_WINNEW, NULL, NULL, FALSE, curbuf);
	apply_autocmds(EVENT_WINENTER, NULL, NULL, FALSE, curbuf);
	apply_autocmds(EVENT_TABNEW, NULL, NULL, FALSE, curbuf);
	apply_autocmds(EVENT_TABENTER, NULL, NULL, FALSE, curbuf);
	return OK;
    }

    
    enter_tabpage(curtab, curbuf, TRUE, TRUE);
    return FAIL;
}


    static int may_open_tabpage(void)
{
    int		n = (cmdmod.cmod_tab == 0)
				       ? postponed_split_tab : cmdmod.cmod_tab;

    if (n != 0)
    {
	cmdmod.cmod_tab = 0;	    
	postponed_split_tab = 0;
	return win_new_tabpage(n);
    }
    return FAIL;
}


    int make_tabpages(int maxcount)
{
    int		count = maxcount;
    int		todo;

    
    if (count > p_tpm)
	count = p_tpm;

    
    block_autocmds();

    for (todo = count - 1; todo > 0; --todo)
	if (win_new_tabpage(0) == FAIL)
	    break;

    unblock_autocmds();

    
    return (count - todo);
}


    int valid_tabpage(tabpage_T *tpc)
{
    tabpage_T	*tp;

    FOR_ALL_TABPAGES(tp)
	if (tp == tpc)
	    return TRUE;
    return FALSE;
}


    int valid_tabpage_win(tabpage_T *tpc)
{
    tabpage_T	*tp;
    win_T	*wp;

    FOR_ALL_TABPAGES(tp)
    {
	if (tp == tpc)
	{
	    FOR_ALL_WINDOWS_IN_TAB(tp, wp)
	    {
		if (win_valid_any_tab(wp))
		    return TRUE;
	    }
	    return FALSE;
	}
    }
    
    return FALSE;
}


    void close_tabpage(tabpage_T *tab)
{
    tabpage_T	*ptp;

    if (tab == first_tabpage)
    {
	first_tabpage = tab->tp_next;
	ptp = first_tabpage;
    }
    else {
	for (ptp = first_tabpage; ptp != NULL && ptp->tp_next != tab;
							    ptp = ptp->tp_next)
	    ;
	assert(ptp != NULL);
	ptp->tp_next = tab->tp_next;
    }

    goto_tabpage_tp(ptp, FALSE, FALSE);
    free_tabpage(tab);
}


    tabpage_T * find_tabpage(int n)
{
    tabpage_T	*tp;
    int		i = 1;

    if (n == 0)
	return curtab;

    for (tp = first_tabpage; tp != NULL && i != n; tp = tp->tp_next)
	++i;
    return tp;
}


    int tabpage_index(tabpage_T *ftp)
{
    int		i = 1;
    tabpage_T	*tp;

    for (tp = first_tabpage; tp != NULL && tp != ftp; tp = tp->tp_next)
	++i;
    return i;
}


    static int leave_tabpage( buf_T	*new_curbuf UNUSED,  int		trigger_leave_autocmds UNUSED)



{
    tabpage_T	*tp = curtab;


    leaving_window(curwin);

    reset_VIsual_and_resel();	
    if (trigger_leave_autocmds)
    {
	if (new_curbuf != curbuf)
	{
	    apply_autocmds(EVENT_BUFLEAVE, NULL, NULL, FALSE, curbuf);
	    if (curtab != tp)
		return FAIL;
	}
	apply_autocmds(EVENT_WINLEAVE, NULL, NULL, FALSE, curbuf);
	if (curtab != tp)
	    return FAIL;
	apply_autocmds(EVENT_TABLEAVE, NULL, NULL, FALSE, curbuf);
	if (curtab != tp)
	    return FAIL;
    }

    reset_dragwin();

    
    if (gui.in_use)
	gui_remove_scrollbars();

    tp->tp_curwin = curwin;
    tp->tp_prevwin = prevwin;
    tp->tp_firstwin = firstwin;
    tp->tp_lastwin = lastwin;
    tp->tp_old_Rows = Rows;
    if (tp->tp_old_Columns != -1)
	tp->tp_old_Columns = Columns;
    firstwin = NULL;
    lastwin = NULL;
    return OK;
}


    static void enter_tabpage( tabpage_T	*tp, buf_T	*old_curbuf UNUSED, int		trigger_enter_autocmds, int		trigger_leave_autocmds)




{
    int		row;
    int		old_off = tp->tp_firstwin->w_winrow;
    win_T	*next_prevwin = tp->tp_prevwin;
    tabpage_T	*last_tab = curtab;

    use_tabpage(tp);

    
    
    
    (void)win_enter_ext(tp->tp_curwin, WEE_CURWIN_INVALID | (trigger_enter_autocmds ? WEE_TRIGGER_ENTER_AUTOCMDS : 0)
		  | (trigger_leave_autocmds ? WEE_TRIGGER_LEAVE_AUTOCMDS : 0));
    prevwin = next_prevwin;

    last_status(FALSE);		
    row = win_comp_pos();	

    diff_need_scrollbind = TRUE;


    
    
    if (p_ch != curtab->tp_ch_used)
	clear_cmdline = TRUE;
    p_ch = curtab->tp_ch_used;

    
    
    
    if (row < cmdline_row && cmdline_row <= Rows - p_ch)
	clear_cmdline = TRUE;

    
    
    reset_dragwin();

    
    
    
    if (curtab->tp_old_Rows != Rows || (old_off != firstwin->w_winrow  && !gui_use_tabline()


		))
	shell_new_rows();
    if (curtab->tp_old_Columns != Columns)
    {
	if (starting == 0)
	{
	    shell_new_columns();	
	    curtab->tp_old_Columns = Columns;
	}
	else curtab->tp_old_Columns = -1;
    }

    lastused_tabpage = last_tab;


    
    
    gui_may_update_scrollbars();


    
    
    if (trigger_enter_autocmds)
    {
	apply_autocmds(EVENT_TABENTER, NULL, NULL, FALSE, curbuf);
	if (old_curbuf != curbuf)
	    apply_autocmds(EVENT_BUFENTER, NULL, NULL, FALSE, curbuf);
    }

    redraw_all_later(UPD_NOT_VALID);
}


    void goto_tabpage(int n)
{
    tabpage_T	*tp = NULL;  
    tabpage_T	*ttp;
    int		i;

    if (text_locked())
    {
	
	text_locked_msg();
	return;
    }

    
    if (first_tabpage->tp_next == NULL)
    {
	if (n > 1)
	    beep_flush();
	return;
    }

    if (n == 0)
    {
	
	if (curtab->tp_next == NULL)
	    tp = first_tabpage;
	else tp = curtab->tp_next;
    }
    else if (n < 0)
    {
	
	
	ttp = curtab;
	for (i = n; i < 0; ++i)
	{
	    for (tp = first_tabpage; tp->tp_next != ttp && tp->tp_next != NULL;
		    tp = tp->tp_next)
		;
	    ttp = tp;
	}
    }
    else if (n == 9999)
    {
	
	for (tp = first_tabpage; tp->tp_next != NULL; tp = tp->tp_next)
	    ;
    }
    else {
	
	tp = find_tabpage(n);
	if (tp == NULL)
	{
	    beep_flush();
	    return;
	}
    }

    goto_tabpage_tp(tp, TRUE, TRUE);


    if (gui_use_tabline())
	gui_mch_set_curtab(tabpage_index(curtab));

}


    void goto_tabpage_tp( tabpage_T	*tp, int		trigger_enter_autocmds, int		trigger_leave_autocmds)



{
    if (trigger_enter_autocmds || trigger_leave_autocmds)
	CHECK_CMDWIN;

    
    set_keep_msg(NULL, 0);

    skip_win_fix_scroll = TRUE;
    if (tp != curtab && leave_tabpage(tp->tp_curwin->w_buffer, trigger_leave_autocmds) == OK)
    {
	if (valid_tabpage(tp))
	    enter_tabpage(tp, curbuf, trigger_enter_autocmds, trigger_leave_autocmds);
	else enter_tabpage(curtab, curbuf, trigger_enter_autocmds, trigger_leave_autocmds);

    }
    skip_win_fix_scroll = FALSE;
}


    int goto_tabpage_lastused(void)
{
    if (valid_tabpage(lastused_tabpage))
    {
	goto_tabpage_tp(lastused_tabpage, TRUE, TRUE);
	return OK;
    }
    return FAIL;
}


    void goto_tabpage_win(tabpage_T *tp, win_T *wp)
{
    goto_tabpage_tp(tp, TRUE, TRUE);
    if (curtab == tp && win_valid(wp))
    {
	win_enter(wp, TRUE);

	if (gui_use_tabline())
	    gui_mch_set_curtab(tabpage_index(curtab));

    }
}


    void tabpage_move(int nr)
{
    int		n = 1;
    tabpage_T	*tp, *tp_dst;

    if (first_tabpage->tp_next == NULL)
	return;

    for (tp = first_tabpage; tp->tp_next != NULL && n < nr; tp = tp->tp_next)
	++n;

    if (tp == curtab || (nr > 0 && tp->tp_next != NULL && tp->tp_next == curtab))
	return;

    tp_dst = tp;

    
    if (curtab == first_tabpage)
	first_tabpage = curtab->tp_next;
    else {
	FOR_ALL_TABPAGES(tp)
	    if (tp->tp_next == curtab)
		break;
	if (tp == NULL)	
	    return;
	tp->tp_next = curtab->tp_next;
    }

    
    if (nr <= 0)
    {
	curtab->tp_next = first_tabpage;
	first_tabpage = curtab;
    }
    else {
	curtab->tp_next = tp_dst->tp_next;
	tp_dst->tp_next = curtab;
    }

    
    redraw_tabline = TRUE;
}



    void win_goto(win_T *wp)
{

    win_T	*owp = curwin;



    if (ERROR_IF_ANY_POPUP_WINDOW)
	return;
    if (popup_is_popup(wp))
    {
	emsg(_(e_not_allowed_to_enter_popup_window));
	return;
    }

    if (text_or_buf_locked())
    {
	beep_flush();
	return;
    }

    if (wp->w_buffer != curbuf)
	reset_VIsual_and_resel();
    else if (VIsual_active)
	wp->w_cursor = curwin->w_cursor;


    need_mouse_correct = TRUE;

    win_enter(wp, TRUE);


    
    if (win_valid(owp) && owp->w_p_cole > 0 && !msg_scrolled)
	redrawWinline(owp, owp->w_cursor.lnum);
    if (curwin->w_p_cole > 0 && !msg_scrolled)
	need_cursor_line_redraw = TRUE;

}



    win_T * win_find_nr(int winnr)
{
    win_T	*wp;

    FOR_ALL_WINDOWS(wp)
	if (--winnr == 0)
	    break;
    return wp;
}




    tabpage_T * win_find_tabpage(win_T *win)
{
    win_T	*wp;
    tabpage_T	*tp;

    FOR_ALL_TAB_WINDOWS(tp, wp)
	    if (wp == win)
		return tp;
    return NULL;
}



    win_T * win_vert_neighbor(tabpage_T *tp, win_T *wp, int up, long count)
{
    frame_T	*fr;
    frame_T	*nfr;
    frame_T	*foundfr;


    if (popup_is_popup(wp))
	
	return NULL;

    foundfr = wp->w_frame;
    while (count--)
    {
	
	fr = foundfr;
	for (;;)
	{
	    if (fr == tp->tp_topframe)
		goto end;
	    if (up)
		nfr = fr->fr_prev;
	    else nfr = fr->fr_next;
	    if (fr->fr_parent->fr_layout == FR_COL && nfr != NULL)
		break;
	    fr = fr->fr_parent;
	}

	
	for (;;)
	{
	    if (nfr->fr_layout == FR_LEAF)
	    {
		foundfr = nfr;
		break;
	    }
	    fr = nfr->fr_child;
	    if (nfr->fr_layout == FR_ROW)
	    {
		
		while (fr->fr_next != NULL && frame2win(fr)->w_wincol + fr->fr_width <= wp->w_wincol + wp->w_wcol)

		    fr = fr->fr_next;
	    }
	    if (nfr->fr_layout == FR_COL && up)
		while (fr->fr_next != NULL)
		    fr = fr->fr_next;
	    nfr = fr;
	}
    }
end:
    return foundfr != NULL ? foundfr->fr_win : NULL;
}


    static void win_goto_ver( int		up, long	count)


{
    win_T	*win;


    if (ERROR_IF_TERM_POPUP_WINDOW)
	return;

    win = win_vert_neighbor(curtab, curwin, up, count);
    if (win != NULL)
	win_goto(win);
}


    win_T * win_horz_neighbor(tabpage_T *tp, win_T *wp, int left, long count)
{
    frame_T	*fr;
    frame_T	*nfr;
    frame_T	*foundfr;


    if (popup_is_popup(wp))
	
	return NULL;

    foundfr = wp->w_frame;
    while (count--)
    {
	
	fr = foundfr;
	for (;;)
	{
	    if (fr == tp->tp_topframe)
		goto end;
	    if (left)
		nfr = fr->fr_prev;
	    else nfr = fr->fr_next;
	    if (fr->fr_parent->fr_layout == FR_ROW && nfr != NULL)
		break;
	    fr = fr->fr_parent;
	}

	
	for (;;)
	{
	    if (nfr->fr_layout == FR_LEAF)
	    {
		foundfr = nfr;
		break;
	    }
	    fr = nfr->fr_child;
	    if (nfr->fr_layout == FR_COL)
	    {
		
		while (fr->fr_next != NULL && frame2win(fr)->w_winrow + fr->fr_height <= wp->w_winrow + wp->w_wrow)

		    fr = fr->fr_next;
	    }
	    if (nfr->fr_layout == FR_ROW && left)
		while (fr->fr_next != NULL)
		    fr = fr->fr_next;
	    nfr = fr;
	}
    }
end:
    return foundfr != NULL ? foundfr->fr_win : NULL;
}


    static void win_goto_hor( int		left, long	count)


{
    win_T	*win;


    if (ERROR_IF_TERM_POPUP_WINDOW)
	return;

    win = win_horz_neighbor(curtab, curwin, left, count);
    if (win != NULL)
	win_goto(win);
}


    void win_enter(win_T *wp, int undo_sync)
{
    (void)win_enter_ext(wp, (undo_sync ? WEE_UNDO_SYNC : 0)
		    | WEE_TRIGGER_ENTER_AUTOCMDS | WEE_TRIGGER_LEAVE_AUTOCMDS);
}


    static void fix_current_dir(void)
{
    if (curwin->w_localdir != NULL || curtab->tp_localdir != NULL)
    {
	char_u	*dirname;

	
	
	
	if (globaldir == NULL)
	{
	    char_u	cwd[MAXPATHL];

	    if (mch_dirname(cwd, MAXPATHL) == OK)
		globaldir = vim_strsave(cwd);
	}
	if (curwin->w_localdir != NULL)
	    dirname = curwin->w_localdir;
	else dirname = curtab->tp_localdir;

	if (mch_chdir((char *)dirname) == 0)
	{
	    last_chdir_reason = NULL;
	    shorten_fnames(TRUE);
	}
    }
    else if (globaldir != NULL)
    {
	
	
	vim_ignored = mch_chdir((char *)globaldir);
	VIM_CLEAR(globaldir);
	last_chdir_reason = NULL;
	shorten_fnames(TRUE);
    }
}


    static int win_enter_ext(win_T *wp, int flags)
{
    int		other_buffer = FALSE;
    int		curwin_invalid = (flags & WEE_CURWIN_INVALID);
    int		did_decrement = FALSE;

    if (wp == curwin && !curwin_invalid)	
	return FALSE;


    if (!curwin_invalid)
	leaving_window(curwin);


    if (!curwin_invalid && (flags & WEE_TRIGGER_LEAVE_AUTOCMDS))
    {
	
	if (wp->w_buffer != curbuf)
	{
	    apply_autocmds(EVENT_BUFLEAVE, NULL, NULL, FALSE, curbuf);
	    other_buffer = TRUE;
	    if (!win_valid(wp))
		return FALSE;
	}
	apply_autocmds(EVENT_WINLEAVE, NULL, NULL, FALSE, curbuf);
	if (!win_valid(wp))
	    return FALSE;

	
	if (aborting())
	    return FALSE;

    }

    
    if ((flags & WEE_UNDO_SYNC) && curbuf != wp->w_buffer)
	u_sync(FALSE);

    
    
    if (*p_spk == 'c')
	update_topline();

    
    if (wp->w_buffer != curbuf)
	buf_copy_options(wp->w_buffer, BCO_ENTER | BCO_NOHELP);
    if (!curwin_invalid)
    {
	prevwin = curwin;	
	curwin->w_redr_status = TRUE;
    }
    curwin = wp;
    curbuf = wp->w_buffer;
    check_cursor();
    if (!virtual_active())
	curwin->w_cursor.coladd = 0;
    if (*p_spk == 'c')		
	changed_line_abv_curs();
    else win_fix_cursor(TRUE);

    
    

    if (flags & WEE_ALLOW_PARSE_MESSAGES)
    {
	--dont_parse_messages;
	did_decrement = TRUE;
    }


    fix_current_dir();


    entering_window(curwin);

    
    if (flags & WEE_TRIGGER_NEW_AUTOCMDS)
	apply_autocmds(EVENT_WINNEW, NULL, NULL, FALSE, curbuf);
    if (flags & WEE_TRIGGER_ENTER_AUTOCMDS)
    {
	apply_autocmds(EVENT_WINENTER, NULL, NULL, FALSE, curbuf);
	if (other_buffer)
	    apply_autocmds(EVENT_BUFENTER, NULL, NULL, FALSE, curbuf);
    }

    maketitle();
    curwin->w_redr_status = TRUE;

    if (bt_terminal(curwin->w_buffer))
	
	redraw_mode = TRUE;

    redraw_tabline = TRUE;
    if (restart_edit)
	redraw_later(UPD_VALID);	

    
    if (curwin->w_height < p_wh && !curwin->w_p_wfh  && !popup_is_popup(curwin)


	    )
	win_setheight((int)p_wh);
    else if (curwin->w_height == 0)
	win_setheight(1);

    
    if (curwin->w_width < p_wiw && !curwin->w_p_wfw)
	win_setwidth((int)p_wiw);

    setmouse();			

    
    DO_AUTOCHDIR;

    return did_decrement;
}


    win_T * buf_jump_open_win(buf_T *buf)
{
    win_T	*wp = NULL;

    if (curwin->w_buffer == buf)
	wp = curwin;
    else FOR_ALL_WINDOWS(wp)
	    if (wp->w_buffer == buf)
		break;
    if (wp != NULL)
	win_enter(wp, FALSE);
    return wp;
}


    win_T * buf_jump_open_tab(buf_T *buf)
{
    win_T	*wp = buf_jump_open_win(buf);
    tabpage_T	*tp;

    if (wp != NULL)
	return wp;

    FOR_ALL_TABPAGES(tp)
	if (tp != curtab)
	{
	    FOR_ALL_WINDOWS_IN_TAB(tp, wp)
		if (wp->w_buffer == buf)
		    break;
	    if (wp != NULL)
	    {
		goto_tabpage_win(tp, wp);
		if (curwin != wp)
		    wp = NULL;	
		break;
	    }
	}
    return wp;
}

static int last_win_id = LOWEST_WIN_ID - 1;


    static win_T * win_alloc(win_T *after, int hidden)
{
    win_T	*new_wp;

    
    new_wp = ALLOC_CLEAR_ONE(win_T);
    if (new_wp == NULL)
	return NULL;

    if (win_alloc_lines(new_wp) == FAIL)
    {
	vim_free(new_wp);
	return NULL;
    }

    new_wp->w_id = ++last_win_id;


    
    new_wp->w_vars = dict_alloc_id(aid_newwin_wvars);
    if (new_wp->w_vars == NULL)
    {
	win_free_lsize(new_wp);
	vim_free(new_wp);
	return NULL;
    }
    init_var_dict(new_wp->w_vars, &new_wp->w_winvar, VAR_SCOPE);


    
    
    
    block_autocmds();

    
    if (!hidden)
	win_append(after, new_wp);
    new_wp->w_wincol = 0;
    new_wp->w_width = Columns;

    
    new_wp->w_topline = 1;

    new_wp->w_topfill = 0;

    new_wp->w_botline = 2;
    new_wp->w_cursor.lnum = 1;
    new_wp->w_scbind_pos = 1;

    
    new_wp->w_p_so = -1;
    new_wp->w_p_siso = -1;

    
    new_wp->w_fraction = 0;
    new_wp->w_prev_fraction_row = -1;


    if (gui.in_use)
    {
	gui_create_scrollbar(&new_wp->w_scrollbars[SBAR_LEFT], SBAR_LEFT, new_wp);
	gui_create_scrollbar(&new_wp->w_scrollbars[SBAR_RIGHT], SBAR_RIGHT, new_wp);
    }


    foldInitWin(new_wp);

    unblock_autocmds();

    new_wp->w_next_match_id = 1000;  

    return new_wp;
}


    static void win_free( win_T	*wp, tabpage_T	*tp)


{
    int		i;
    buf_T	*buf;
    wininfo_T	*wip;


    clearFolding(wp);


    
    alist_unlink(wp->w_alist);

    
    
    block_autocmds();


    lua_window_free(wp);



    mzscheme_window_free(wp);



    perl_win_free(wp);



    python_window_free(wp);



    python3_window_free(wp);



    tcl_window_free(wp);



    ruby_window_free(wp);


    clear_winopt(&wp->w_onebuf_opt);
    clear_winopt(&wp->w_allbuf_opt);

    vim_free(wp->w_lcs_chars.multispace);
    vim_free(wp->w_lcs_chars.leadmultispace);


    vars_clear(&wp->w_vars->dv_hashtab);	
    hash_init(&wp->w_vars->dv_hashtab);
    unref_var_dict(wp->w_vars);


    {
	tabpage_T	*ttp;

	if (prevwin == wp)
	    prevwin = NULL;
	FOR_ALL_TABPAGES(ttp)
	    if (ttp->tp_prevwin == wp)
		ttp->tp_prevwin = NULL;
    }
    win_free_lsize(wp);

    for (i = 0; i < wp->w_tagstacklen; ++i)
    {
	vim_free(wp->w_tagstack[i].tagname);
	vim_free(wp->w_tagstack[i].user_data);
    }
    vim_free(wp->w_localdir);
    vim_free(wp->w_prevdir);

    
    
    FOR_ALL_BUFFERS(buf)
	FOR_ALL_BUF_WININFO(buf, wip)
	    if (wip->wi_win == wp)
	    {
		wininfo_T	*wip2;

		
		
		
		for (wip2 = buf->b_wininfo; wip2 != NULL; wip2 = wip2->wi_next)
		    if (wip2 != wip && wip2->wi_win == NULL)
		    {
			if (wip2->wi_next != NULL)
			    wip2->wi_next->wi_prev = wip2->wi_prev;
			if (wip2->wi_prev == NULL)
			    buf->b_wininfo = wip2->wi_next;
			else wip2->wi_prev->wi_next = wip2->wi_next;
			free_wininfo(wip2);
			break;
		    }

		wip->wi_win = NULL;
	    }


    clear_matches(wp);


    free_jumplist(wp);


    qf_free_all(wp);



    if (gui.in_use)
    {
	gui_mch_destroy_scrollbar(&wp->w_scrollbars[SBAR_LEFT]);
	gui_mch_destroy_scrollbar(&wp->w_scrollbars[SBAR_RIGHT]);
    }



    remove_winbar(wp);


    free_callback(&wp->w_close_cb);
    free_callback(&wp->w_filter_cb);
    for (i = 0; i < 4; ++i)
	VIM_CLEAR(wp->w_border_highlight[i]);
    vim_free(wp->w_scrollbar_highlight);
    vim_free(wp->w_thumb_highlight);
    vim_free(wp->w_popup_title);
    list_unref(wp->w_popup_mask);
    vim_free(wp->w_popup_mask_cells);



    vim_free(wp->w_p_cc_cols);


    if (win_valid_any_tab(wp))
	win_remove(wp, tp);
    if (autocmd_busy)
    {
	wp->w_next = au_pending_free_win;
	au_pending_free_win = wp;
    }
    else vim_free(wp);

    unblock_autocmds();
}


    int win_unlisted(win_T *wp)
{
    return wp == aucmd_win || WIN_IS_POPUP(wp);
}



    void win_free_popup(win_T *win)
{
    if (win->w_buffer != NULL)
    {
	if (bt_popup(win->w_buffer))
	    win_close_buffer(win, DOBUF_WIPE_REUSE, FALSE);
	else close_buffer(win, win->w_buffer, 0, FALSE, FALSE);
    }

    
    if (timer_valid(win->w_popup_timer))
	stop_timer(win->w_popup_timer);

    vim_free(win->w_frame);
    win_free(win, NULL);
}



    static void win_append(win_T *after, win_T *wp)
{
    win_T	*before;

    if (after == NULL)	    
	before = firstwin;
    else before = after->w_next;

    wp->w_next = before;
    wp->w_prev = after;
    if (after == NULL)
	firstwin = wp;
    else after->w_next = wp;
    if (before == NULL)
	lastwin = wp;
    else before->w_prev = wp;
}


    void win_remove( win_T	*wp, tabpage_T	*tp)


{
    if (wp->w_prev != NULL)
	wp->w_prev->w_next = wp->w_next;
    else if (tp == NULL)
	firstwin = curtab->tp_firstwin = wp->w_next;
    else tp->tp_firstwin = wp->w_next;

    if (wp->w_next != NULL)
	wp->w_next->w_prev = wp->w_prev;
    else if (tp == NULL)
	lastwin = curtab->tp_lastwin = wp->w_prev;
    else tp->tp_lastwin = wp->w_prev;
}


    static void frame_append(frame_T *after, frame_T *frp)
{
    frp->fr_next = after->fr_next;
    after->fr_next = frp;
    if (frp->fr_next != NULL)
	frp->fr_next->fr_prev = frp;
    frp->fr_prev = after;
}


    static void frame_insert(frame_T *before, frame_T *frp)
{
    frp->fr_next = before;
    frp->fr_prev = before->fr_prev;
    before->fr_prev = frp;
    if (frp->fr_prev != NULL)
	frp->fr_prev->fr_next = frp;
    else frp->fr_parent->fr_child = frp;
}


    static void frame_remove(frame_T *frp)
{
    if (frp->fr_prev != NULL)
	frp->fr_prev->fr_next = frp->fr_next;
    else frp->fr_parent->fr_child = frp->fr_next;
    if (frp->fr_next != NULL)
	frp->fr_next->fr_prev = frp->fr_prev;
}


    int win_alloc_lines(win_T *wp)
{
    wp->w_lines_valid = 0;
    wp->w_lines = ALLOC_CLEAR_MULT(wline_T, Rows);
    if (wp->w_lines == NULL)
	return FAIL;
    return OK;
}


    void win_free_lsize(win_T *wp)
{
    
    if (wp != NULL)
	VIM_CLEAR(wp->w_lines);
}


    void shell_new_rows(void)
{
    int		h = (int)ROWS_AVAIL;

    if (firstwin == NULL)	
	return;
    if (h < frame_minheight(topframe, NULL))
	h = frame_minheight(topframe, NULL);

    
    
    frame_new_height(topframe, h, FALSE, TRUE);
    if (!frame_check_height(topframe, h))
	frame_new_height(topframe, h, FALSE, FALSE);

    (void)win_comp_pos();		
    compute_cmdrow();
    curtab->tp_ch_used = p_ch;

    if (*p_spk != 'c' && !skip_win_fix_scroll)
	win_fix_scroll(TRUE);


    
    if (p_ea)
	win_equal(curwin, FALSE, 'v');

}


    void shell_new_columns(void)
{
    if (firstwin == NULL)	
	return;

    
    
    frame_new_width(topframe, (int)Columns, FALSE, TRUE);
    if (!frame_check_width(topframe, Columns))
	frame_new_width(topframe, (int)Columns, FALSE, FALSE);

    (void)win_comp_pos();		

    
    if (p_ea)
	win_equal(curwin, FALSE, 'h');

}


    void win_size_save(garray_T *gap)

{
    win_T	*wp;

    ga_init2(gap, sizeof(int), 1);
    if (ga_grow(gap, win_count() * 2 + 1) == OK)
    {
	
	((int *)gap->ga_data)[gap->ga_len++] = Rows;

	FOR_ALL_WINDOWS(wp)
	{
	    ((int *)gap->ga_data)[gap->ga_len++] = wp->w_width + wp->w_vsep_width;
	    ((int *)gap->ga_data)[gap->ga_len++] = wp->w_height;
	}
    }
}


    void win_size_restore(garray_T *gap)
{
    win_T	*wp;
    int		i, j;

    if (win_count() * 2 + 1 == gap->ga_len && ((int *)gap->ga_data)[0] == Rows)
    {
	
	
	for (j = 0; j < 2; ++j)
	{
	    i = 1;
	    FOR_ALL_WINDOWS(wp)
	    {
		frame_setwidth(wp->w_frame, ((int *)gap->ga_data)[i++]);
		win_setheight_win(((int *)gap->ga_data)[i++], wp);
	    }
	}
	
	(void)win_comp_pos();
    }
}


    int win_comp_pos(void)
{
    int		row = tabline_height();
    int		col = 0;

    frame_comp_pos(topframe, &row, &col);
    return row;
}


    static void frame_comp_pos(frame_T *topfrp, int *row, int *col)
{
    win_T	*wp;
    frame_T	*frp;
    int		startcol;
    int		startrow;
    int		h;

    wp = topfrp->fr_win;
    if (wp != NULL)
    {
	if (wp->w_winrow != *row || wp->w_wincol != *col)
	{
	    
	    wp->w_winrow = *row;
	    wp->w_wincol = *col;
	    redraw_win_later(wp, UPD_NOT_VALID);
	    wp->w_redr_status = TRUE;
	}
	
	h = VISIBLE_HEIGHT(wp) + wp->w_status_height;
	*row += h > topfrp->fr_height ? topfrp->fr_height : h;
	*col += wp->w_width + wp->w_vsep_width;
    }
    else {
	startrow = *row;
	startcol = *col;
	FOR_ALL_FRAMES(frp, topfrp->fr_child)
	{
	    if (topfrp->fr_layout == FR_ROW)
		*row = startrow;	
	    else *col = startcol;
	    frame_comp_pos(frp, row, col);
	}
    }
}


    void win_ensure_size()
{
    if (curwin->w_height == 0)
	win_setheight(1);
    if (curwin->w_width == 0)
	win_setwidth(1);
}


    void win_setheight(int height)
{
    win_setheight_win(height, curwin);
}


    void win_setheight_win(int height, win_T *win)
{
    int		row;

    if (win == curwin)
    {
	
	
	if (height < p_wmh)
	    height = p_wmh;
	if (height == 0)
	    height = 1;
	height += WINBAR_HEIGHT(curwin);
    }

    frame_setheight(win->w_frame, height + win->w_status_height);

    
    row = win_comp_pos();

    
    if (full_screen && msg_scrolled == 0 && row < cmdline_row)
	screen_fill(row, cmdline_row, 0, (int)Columns, ' ', ' ', 0);
    cmdline_row = row;
    msg_row = row;
    msg_col = 0;

    if (*p_spk != 'c')
	win_fix_scroll(TRUE);

    redraw_all_later(UPD_NOT_VALID);
}


    static void frame_setheight(frame_T *curfrp, int height)
{
    int		room;		
    int		take;		
    int		room_cmdline;	
    int		run;
    frame_T	*frp;
    int		h;
    int		room_reserved;

    
    if (curfrp->fr_height == height)
	return;

    if (curfrp->fr_parent == NULL)
    {
	
	if (height > ROWS_AVAIL)
	    height = ROWS_AVAIL;
	if (height > 0)
	    frame_new_height(curfrp, height, FALSE, FALSE);
    }
    else if (curfrp->fr_parent->fr_layout == FR_ROW)
    {
	
	
	h = frame_minheight(curfrp->fr_parent, NULL);
	if (height < h)
	    height = h;
	frame_setheight(curfrp->fr_parent, height);
    }
    else {
	
	
	for (run = 1; run <= 2; ++run)
	{
	    room = 0;
	    room_reserved = 0;
	    FOR_ALL_FRAMES(frp, curfrp->fr_parent->fr_child)
	    {
		if (frp != curfrp && frp->fr_win != NULL && frp->fr_win->w_p_wfh)

		    room_reserved += frp->fr_height;
		room += frp->fr_height;
		if (frp != curfrp)
		    room -= frame_minheight(frp, NULL);
	    }
	    if (curfrp->fr_width != Columns)
		room_cmdline = 0;
	    else {
		room_cmdline = Rows - p_ch - (lastwin->w_winrow + VISIBLE_HEIGHT(lastwin)
						+ lastwin->w_status_height);
		if (room_cmdline < 0)
		    room_cmdline = 0;
	    }

	    if (height <= room + room_cmdline)
		break;
	    if (run == 2 || curfrp->fr_width == Columns)
	    {
		height = room + room_cmdline;
		break;
	    }
	    frame_setheight(curfrp->fr_parent, height + frame_minheight(curfrp->fr_parent, NOWIN) - (int)p_wmh - 1);
	}

	
	take = height - curfrp->fr_height;

	
	
	if (height > room + room_cmdline - room_reserved)
	    room_reserved = room + room_cmdline - height;
	
	
	if (take < 0 && room - curfrp->fr_height < room_reserved)
	    room_reserved = 0;

	if (take > 0 && room_cmdline > 0)
	{
	    
	    if (take < room_cmdline)
		room_cmdline = take;
	    take -= room_cmdline;
	    topframe->fr_height += room_cmdline;
	}

	
	frame_new_height(curfrp, height, FALSE, FALSE);

	
	for (run = 0; run < 2; ++run)
	{
	    if (run == 0)
		frp = curfrp->fr_next;	
	    else frp = curfrp->fr_prev;
	    while (frp != NULL && take != 0)
	    {
		h = frame_minheight(frp, NULL);
		if (room_reserved > 0 && frp->fr_win != NULL && frp->fr_win->w_p_wfh)

		{
		    if (room_reserved >= frp->fr_height)
			room_reserved -= frp->fr_height;
		    else {
			if (frp->fr_height - room_reserved > take)
			    room_reserved = frp->fr_height - take;
			take -= frp->fr_height - room_reserved;
			frame_new_height(frp, room_reserved, FALSE, FALSE);
			room_reserved = 0;
		    }
		}
		else {
		    if (frp->fr_height - take < h)
		    {
			take -= frp->fr_height - h;
			frame_new_height(frp, h, FALSE, FALSE);
		    }
		    else {
			frame_new_height(frp, frp->fr_height - take, FALSE, FALSE);
			take = 0;
		    }
		}
		if (run == 0)
		    frp = frp->fr_next;
		else frp = frp->fr_prev;
	    }
	}
    }
}


    void win_setwidth(int width)
{
    win_setwidth_win(width, curwin);
}

    void win_setwidth_win(int width, win_T *wp)
{
    
    
    if (wp == curwin)
    {
	if (width < p_wmw)
	    width = p_wmw;
	if (width == 0)
	    width = 1;
    }
    else if (width < 0)
	width = 0;

    frame_setwidth(wp->w_frame, width + wp->w_vsep_width);

    
    (void)win_comp_pos();

    redraw_all_later(UPD_NOT_VALID);
}


    static void frame_setwidth(frame_T *curfrp, int width)
{
    int		room;		
    int		take;		
    int		run;
    frame_T	*frp;
    int		w;
    int		room_reserved;

    
    if (curfrp->fr_width == width)
	return;

    if (curfrp->fr_parent == NULL)
	
	return;

    if (curfrp->fr_parent->fr_layout == FR_COL)
    {
	
	
	w = frame_minwidth(curfrp->fr_parent, NULL);
	if (width < w)
	    width = w;
	frame_setwidth(curfrp->fr_parent, width);
    }
    else {
	
	for (run = 1; run <= 2; ++run)
	{
	    room = 0;
	    room_reserved = 0;
	    FOR_ALL_FRAMES(frp, curfrp->fr_parent->fr_child)
	    {
		if (frp != curfrp && frp->fr_win != NULL && frp->fr_win->w_p_wfw)

		    room_reserved += frp->fr_width;
		room += frp->fr_width;
		if (frp != curfrp)
		    room -= frame_minwidth(frp, NULL);
	    }

	    if (width <= room)
		break;
	    if (run == 2 || curfrp->fr_height >= ROWS_AVAIL)
	    {
		width = room;
		break;
	    }
	    frame_setwidth(curfrp->fr_parent, width + frame_minwidth(curfrp->fr_parent, NOWIN) - (int)p_wmw - 1);
	}

	
	take = width - curfrp->fr_width;

	
	
	if (width > room - room_reserved)
	    room_reserved = room - width;
	
	
	if (take < 0 && room - curfrp->fr_width < room_reserved)
	    room_reserved = 0;

	
	frame_new_width(curfrp, width, FALSE, FALSE);

	
	for (run = 0; run < 2; ++run)
	{
	    if (run == 0)
		frp = curfrp->fr_next;	
	    else frp = curfrp->fr_prev;
	    while (frp != NULL && take != 0)
	    {
		w = frame_minwidth(frp, NULL);
		if (room_reserved > 0 && frp->fr_win != NULL && frp->fr_win->w_p_wfw)

		{
		    if (room_reserved >= frp->fr_width)
			room_reserved -= frp->fr_width;
		    else {
			if (frp->fr_width - room_reserved > take)
			    room_reserved = frp->fr_width - take;
			take -= frp->fr_width - room_reserved;
			frame_new_width(frp, room_reserved, FALSE, FALSE);
			room_reserved = 0;
		    }
		}
		else {
		    if (frp->fr_width - take < w)
		    {
			take -= frp->fr_width - w;
			frame_new_width(frp, w, FALSE, FALSE);
		    }
		    else {
			frame_new_width(frp, frp->fr_width - take, FALSE, FALSE);
			take = 0;
		    }
		}
		if (run == 0)
		    frp = frp->fr_next;
		else frp = frp->fr_prev;
	    }
	}
    }
}


    void win_setminheight(void)
{
    int		room;
    int		needed;
    int		first = TRUE;

    
    while (p_wmh > 0)
    {
	room = Rows - p_ch;
	needed = min_rows() - 1;  
	if (room >= needed)
	    break;
	--p_wmh;
	if (first)
	{
	    emsg(_(e_not_enough_room));
	    first = FALSE;
	}
    }
}


    void win_setminwidth(void)
{
    int		room;
    int		needed;
    int		first = TRUE;

    
    while (p_wmw > 0)
    {
	room = Columns;
	needed = frame_minwidth(topframe, NULL);
	if (room >= needed)
	    break;
	--p_wmw;
	if (first)
	{
	    emsg(_(e_not_enough_room));
	    first = FALSE;
	}
    }
}


    void win_drag_status_line(win_T *dragwin, int offset)
{
    frame_T	*curfr;
    frame_T	*fr;
    int		room;
    int		row;
    int		up;	
    int		n;

    fr = dragwin->w_frame;
    curfr = fr;
    if (fr != topframe)		
    {
	fr = fr->fr_parent;
	
	
	if (fr->fr_layout != FR_COL)
	{
	    curfr = fr;
	    if (fr != topframe)	
		fr = fr->fr_parent;
	}
    }

    
    
    while (curfr != topframe && curfr->fr_next == NULL)
    {
	if (fr != topframe)
	    fr = fr->fr_parent;
	curfr = fr;
	if (fr != topframe)
	    fr = fr->fr_parent;
    }

    if (offset < 0) 
    {
	up = TRUE;
	offset = -offset;
	
	if (fr == curfr)
	{
	    
	    room = fr->fr_height - frame_minheight(fr, NULL);
	}
	else {
	    room = 0;
	    for (fr = fr->fr_child; ; fr = fr->fr_next)
	    {
		room += fr->fr_height - frame_minheight(fr, NULL);
		if (fr == curfr)
		    break;
	    }
	}
	fr = curfr->fr_next;		
    }
    else     {
	up = FALSE;
	
	room = Rows - cmdline_row;
	if (curfr->fr_next == NULL)
	    --room;
	else room -= p_ch;
	if (room < 0)
	    room = 0;
	
	FOR_ALL_FRAMES(fr, curfr->fr_next)
	    room += fr->fr_height - frame_minheight(fr, NULL);
	fr = curfr;			
    }

    if (room < offset)		
	offset = room;		
    if (offset <= 0)
	return;

    
    if (fr != NULL)
	frame_new_height(fr, fr->fr_height + offset, up, FALSE);

    if (up)
	fr = curfr;		
    else fr = curfr->fr_next;

    
    while (fr != NULL && offset > 0)
    {
	n = frame_minheight(fr, NULL);
	if (fr->fr_height - offset <= n)
	{
	    offset -= fr->fr_height - n;
	    frame_new_height(fr, n, !up, FALSE);
	}
	else {
	    frame_new_height(fr, fr->fr_height - offset, !up, FALSE);
	    break;
	}
	if (up)
	    fr = fr->fr_prev;
	else fr = fr->fr_next;
    }
    row = win_comp_pos();
    screen_fill(row, cmdline_row, 0, (int)Columns, ' ', ' ', 0);
    cmdline_row = row;
    p_ch = MAX(Rows - cmdline_row, 1);
    curtab->tp_ch_used = p_ch;

    if (*p_spk != 'c')
	win_fix_scroll(TRUE);

    redraw_all_later(UPD_SOME_VALID);
    showmode();
}


    void win_drag_vsep_line(win_T *dragwin, int offset)
{
    frame_T	*curfr;
    frame_T	*fr;
    int		room;
    int		left;	
    int		n;

    fr = dragwin->w_frame;
    if (fr == topframe)		
	return;
    curfr = fr;
    fr = fr->fr_parent;
    
    if (fr->fr_layout != FR_ROW)
    {
	if (fr == topframe)	
	    return;
	curfr = fr;
	fr = fr->fr_parent;
    }

    
    
    while (curfr->fr_next == NULL)
    {
	if (fr == topframe)
	    break;
	curfr = fr;
	fr = fr->fr_parent;
	if (fr != topframe)
	{
	    curfr = fr;
	    fr = fr->fr_parent;
	}
    }

    if (offset < 0) 
    {
	left = TRUE;
	offset = -offset;
	
	room = 0;
	for (fr = fr->fr_child; ; fr = fr->fr_next)
	{
	    room += fr->fr_width - frame_minwidth(fr, NULL);
	    if (fr == curfr)
		break;
	}
	fr = curfr->fr_next;		
    }
    else     {
	left = FALSE;
	
	room = 0;
	FOR_ALL_FRAMES(fr, curfr->fr_next)
	    room += fr->fr_width - frame_minwidth(fr, NULL);
	fr = curfr;			
    }

    if (room < offset)		
	offset = room;		
    if (offset <= 0)		
	return;
    if (fr == NULL)
	
	
	return;

    
    frame_new_width(fr, fr->fr_width + offset, left, FALSE);

    
    if (left)
	fr = curfr;		
    else fr = curfr->fr_next;

    while (fr != NULL && offset > 0)
    {
	n = frame_minwidth(fr, NULL);
	if (fr->fr_width - offset <= n)
	{
	    offset -= fr->fr_width - n;
	    frame_new_width(fr, n, !left, FALSE);
	}
	else {
	    frame_new_width(fr, fr->fr_width - offset, !left, FALSE);
	    break;
	}
	if (left)
	    fr = fr->fr_prev;
	else fr = fr->fr_next;
    }
    (void)win_comp_pos();
    redraw_all_later(UPD_NOT_VALID);
}




    void set_fraction(win_T *wp)
{
    if (wp->w_height > 1)
	
	
	
	wp->w_fraction = ((long)wp->w_wrow * FRACTION_MULT + FRACTION_MULT / 2) / (long)wp->w_height;
}


    static void win_fix_scroll(int resize)
{
    int		diff;
    win_T	*wp;
    linenr_T	lnum;

    skip_update_topline = TRUE;
    FOR_ALL_WINDOWS(wp)
    {
	
	if (wp->w_height != wp->w_prev_height)
	{
	    
	    if (*p_spk == 's' && wp->w_winrow != wp->w_prev_winrow && wp->w_botline - 1 <= wp->w_buffer->b_ml.ml_line_count)
	    {
		lnum = wp->w_cursor.lnum;
		diff = (wp->w_winrow - wp->w_prev_winrow)
		     + (wp->w_height - wp->w_prev_height);
		wp->w_cursor.lnum = wp->w_botline - 1;
		
		if (diff > 0)
		    cursor_down_inner(wp, diff);
		else cursor_up_inner(wp, -diff);
		
		wp->w_fraction = FRACTION_MULT;
		scroll_to_fraction(wp, wp->w_prev_height);
		wp->w_cursor.lnum = lnum;
	    }
	    else if (wp == curwin)
		wp->w_valid &= ~VALID_CROW;
	    invalidate_botline_win(wp);
	    validate_botline_win(wp);
	}
	wp->w_prev_height = wp->w_height;
	wp->w_prev_winrow = wp->w_winrow;
    }
    skip_update_topline = FALSE;
    
    if (!(get_real_state() & (MODE_NORMAL|MODE_CMDLINE|MODE_TERMINAL)))
	win_fix_cursor(FALSE);
    else if (resize)
	win_fix_cursor(TRUE);
}


    static void win_fix_cursor(int normal)
{
    long	so = get_scrolloff_value();
    win_T	*wp = curwin;
    linenr_T	nlnum = 0;
    linenr_T	lnum = wp->w_cursor.lnum;
    linenr_T	bot;
    linenr_T	top;

    if (wp->w_buffer->b_ml.ml_line_count < wp->w_height)
	return;
    if (skip_win_fix_cursor)
	return;

    
    so = MIN(wp->w_height / 2, so);
    wp->w_cursor.lnum = wp->w_topline;
    top = cursor_down_inner(wp, so);
    wp->w_cursor.lnum = wp->w_botline - 1;
    bot = cursor_up_inner(wp, so);
    wp->w_cursor.lnum = lnum;
    
    if (lnum > bot && (wp->w_botline - wp->w_buffer->b_ml.ml_line_count) != 1)
	nlnum = bot;
    else if (lnum < top && wp->w_topline != 1)
	nlnum = (so == wp->w_height / 2) ? bot : top;

    if (nlnum)  
    {
	if (normal)  
	{
	    setmark('\'');
	    wp->w_cursor.lnum = nlnum;
	}
	else   {
	    wp->w_fraction = (nlnum == bot) ? FRACTION_MULT : 0;
	    scroll_to_fraction(wp, wp->w_prev_height);
	    validate_botline_win(curwin);
	}
    }
}


    void win_new_height(win_T *wp, int height)
{
    int		prev_height = wp->w_height;

    
    
    if (height < 0)
	height = 0;
    if (wp->w_height == height)
	return;	    

    if (wp->w_height > 0)
    {
	if (wp == curwin && *p_spk == 'c')
	    
	    
	    validate_cursor();
	if (wp->w_height != prev_height)
	    return;  
		     
	if (wp->w_wrow != wp->w_prev_fraction_row)
	    set_fraction(wp);
    }

    wp->w_height = height;
    wp->w_skipcol = 0;
    win_comp_scroll(wp);

    
    
    if (!exiting && *p_spk == 'c')
	scroll_to_fraction(wp, prev_height);
}

    void scroll_to_fraction(win_T *wp, int prev_height)
{
    linenr_T	lnum;
    int		sline, line_size;
    int		height = wp->w_height;

    
    
    
    
    
    if (height > 0 && (!wp->w_p_scb || wp == curwin)
	   && (height < wp->w_buffer->b_ml.ml_line_count || wp->w_topline > 1))
    {
	
	lnum = wp->w_cursor.lnum;
	if (lnum < 1)		
	    lnum = 1;
	wp->w_wrow = ((long)wp->w_fraction * (long)height - 1L)
							       / FRACTION_MULT;
	line_size = plines_win_col(wp, lnum, (long)(wp->w_cursor.col)) - 1;
	sline = wp->w_wrow - line_size;

	if (sline >= 0)
	{
	    
	    int rows = plines_win(wp, lnum, FALSE);

	    if (sline > wp->w_height - rows)
	    {
		sline = wp->w_height - rows;
		wp->w_wrow -= rows - line_size;
	    }
	}

	if (sline < 0)
	{
	    
	    wp->w_wrow = line_size;
	    if (wp->w_wrow >= wp->w_height && (wp->w_width - win_col_off(wp)) > 0)
	    {
		wp->w_skipcol += wp->w_width - win_col_off(wp);
		--wp->w_wrow;
		while (wp->w_wrow >= wp->w_height)
		{
		    wp->w_skipcol += wp->w_width - win_col_off(wp)
							   + win_col_off2(wp);
		    --wp->w_wrow;
		}
	    }
	}
	else if (sline > 0)
	{
	    while (sline > 0 && lnum > 1)
	    {

		hasFoldingWin(wp, lnum, &lnum, NULL, TRUE, NULL);
		if (lnum == 1)
		{
		    
		    line_size = 1;
		    --sline;
		    break;
		}

		--lnum;

		if (lnum == wp->w_topline)
		    line_size = plines_win_nofill(wp, lnum, TRUE)
							      + wp->w_topfill;
		else  line_size = plines_win(wp, lnum, TRUE);

		sline -= line_size;
	    }

	    if (sline < 0)
	    {
		

		hasFoldingWin(wp, lnum, NULL, &lnum, TRUE, NULL);

		lnum++;
		wp->w_wrow -= line_size + sline;
	    }
	    else if (sline > 0)
	    {
		
		lnum = 1;
		wp->w_wrow -= sline;
	    }
	}
	set_topline(wp, lnum);
    }

    if (wp == curwin)
    {
	if (get_scrolloff_value())
	    update_topline();
	curs_columns(FALSE);	
    }
    if (prev_height > 0)
	wp->w_prev_fraction_row = wp->w_wrow;

    redraw_win_later(wp, UPD_SOME_VALID);
    wp->w_redr_status = TRUE;
    invalidate_botline_win(wp);
}


    void win_new_width(win_T *wp, int width)
{
    
    wp->w_width = width < 0 ? 0 : width;
    wp->w_lines_valid = 0;
    changed_line_abv_curs_win(wp);
    invalidate_botline_win(wp);
    if (wp == curwin)
    {
	skip_update_topline = (*p_spk != 'c');
	update_topline();
	curs_columns(TRUE);	
	skip_update_topline = FALSE;
    }
    redraw_win_later(wp, UPD_NOT_VALID);
    wp->w_redr_status = TRUE;
}

    void win_comp_scroll(win_T *wp)
{

    int old_w_p_scr = wp->w_p_scr;


    wp->w_p_scr = ((unsigned)wp->w_height >> 1);
    if (wp->w_p_scr == 0)
	wp->w_p_scr = 1;

    if (wp->w_p_scr != old_w_p_scr)
    {
	
	wp->w_p_script_ctx[WV_SCROLL].sc_sid = SID_WINLAYOUT;
	wp->w_p_script_ctx[WV_SCROLL].sc_lnum = 0;
    }

}


    void command_height(void)
{
    int		h;
    frame_T	*frp;
    int		old_p_ch = curtab->tp_ch_used;

    
    
    
    curtab->tp_ch_used = p_ch;

    
    
    if (p_ch > old_p_ch && cmdline_row <= Rows - p_ch)
	return;

    
    cmdline_row = topframe->fr_height + tabline_height();

    
    
    
    if (cmdline_row < Rows - p_ch)
	old_p_ch = Rows - cmdline_row;

    
    frp = lastwin->w_frame;
    while (frp->fr_width != Columns && frp->fr_parent != NULL)
	frp = frp->fr_parent;

    
    while (frp->fr_prev != NULL && frp->fr_layout == FR_LEAF && frp->fr_win->w_p_wfh)
	frp = frp->fr_prev;

    if (starting != NO_SCREEN)
    {
	cmdline_row = Rows - p_ch;

	if (p_ch > old_p_ch)		    
	{
	    while (p_ch > old_p_ch)
	    {
		if (frp == NULL)
		{
		    emsg(_(e_not_enough_room));
		    p_ch = old_p_ch;
		    curtab->tp_ch_used = p_ch;
		    cmdline_row = Rows - p_ch;
		    break;
		}
		h = frp->fr_height - frame_minheight(frp, NULL);
		if (h > p_ch - old_p_ch)
		    h = p_ch - old_p_ch;
		old_p_ch += h;
		frame_add_height(frp, -h);
		frp = frp->fr_prev;
	    }

	    
	    (void)win_comp_pos();

	    
	    if (full_screen)
		screen_fill(cmdline_row, (int)Rows, 0, (int)Columns, ' ', ' ', 0);
	    msg_row = cmdline_row;
	    redraw_cmdline = TRUE;
	    return;
	}

	if (msg_row < cmdline_row)
	    msg_row = cmdline_row;
	redraw_cmdline = TRUE;
    }
    frame_add_height(frp, (int)(old_p_ch - p_ch));

    
    if (frp != lastwin->w_frame)
	(void)win_comp_pos();
}


    static void frame_add_height(frame_T *frp, int n)
{
    frame_new_height(frp, frp->fr_height + n, FALSE, FALSE);
    for (;;)
    {
	frp = frp->fr_parent;
	if (frp == NULL)
	    break;
	frp->fr_height += n;
    }
}


    void last_status( int		morewin)

{
    
    last_status_rec(topframe, (p_ls == 2 || (p_ls == 1 && (morewin || !ONE_WINDOW))));
}

    static void last_status_rec(frame_T *fr, int statusline)
{
    frame_T	*fp;
    win_T	*wp;

    if (fr->fr_layout == FR_LEAF)
    {
	wp = fr->fr_win;
	if (wp->w_status_height != 0 && !statusline)
	{
	    
	    win_new_height(wp, wp->w_height + 1);
	    wp->w_status_height = 0;
	    comp_col();
	}
	else if (wp->w_status_height == 0 && statusline)
	{
	    
	    fp = fr;
	    while (fp->fr_height <= frame_minheight(fp, NULL))
	    {
		if (fp == topframe)
		{
		    emsg(_(e_not_enough_room));
		    return;
		}
		
		
		if (fp->fr_parent->fr_layout == FR_COL && fp->fr_prev != NULL)
		    fp = fp->fr_prev;
		else fp = fp->fr_parent;
	    }
	    wp->w_status_height = 1;
	    if (fp != fr)
	    {
		frame_new_height(fp, fp->fr_height - 1, FALSE, FALSE);
		frame_fix_height(wp);
		(void)win_comp_pos();
	    }
	    else win_new_height(wp, wp->w_height - 1);
	    comp_col();
	    redraw_all_later(UPD_SOME_VALID);
	}
	
	if (abs(wp->w_height - wp->w_prev_height) == 1)
	    wp->w_prev_height = wp->w_height;
    }
    else if (fr->fr_layout == FR_ROW)
    {
	
	FOR_ALL_FRAMES(fp, fr->fr_child)
	    last_status_rec(fp, statusline);
    }
    else {
	
	for (fp = fr->fr_child; fp->fr_next != NULL; fp = fp->fr_next)
	    ;
	last_status_rec(fp, statusline);
    }
}


    int tabline_height(void)
{

    
    if (gui_use_tabline())
	return 0;

    switch (p_stal)
    {
	case 0: return 0;
	case 1: return (first_tabpage->tp_next == NULL) ? 0 : 1;
    }
    return 1;
}


    int min_rows(void)
{
    int		total;
    tabpage_T	*tp;
    int		n;

    if (firstwin == NULL)	
	return MIN_LINES;

    total = 0;
    FOR_ALL_TABPAGES(tp)
    {
	n = frame_minheight(tp->tp_topframe, NULL);
	if (total < n)
	    total = n;
    }
    total += tabline_height();
    total += 1;		
    return total;
}


    int only_one_window(void)
{
    int		count = 0;
    win_T	*wp;


    
    if (popup_is_popup(curwin))
	return FALSE;


    
    if (first_tabpage->tp_next != NULL)
	return FALSE;

    FOR_ALL_WINDOWS(wp)
	if (wp->w_buffer != NULL && (!((bt_help(wp->w_buffer) && !bt_help(curbuf))

		    || wp->w_p_pvw  ) || wp == curwin) && wp != aucmd_win)

	    ++count;
    return (count <= 1);
}


    static void check_lnums_both(int do_curwin, int nested)
{
    win_T	*wp;
    tabpage_T	*tp;

    FOR_ALL_TAB_WINDOWS(tp, wp)
	if ((do_curwin || wp != curwin) && wp->w_buffer == curbuf)
	{
	    int need_adjust;

	    if (!nested)
	    {
		
		wp->w_save_cursor.w_cursor_save = wp->w_cursor;
		wp->w_save_cursor.w_topline_save = wp->w_topline;
	    }

	    need_adjust = wp->w_cursor.lnum > curbuf->b_ml.ml_line_count;
	    if (need_adjust)
		wp->w_cursor.lnum = curbuf->b_ml.ml_line_count;
	    if (need_adjust || !nested)
		
		wp->w_save_cursor.w_cursor_corr = wp->w_cursor;

	    need_adjust = wp->w_topline > curbuf->b_ml.ml_line_count;
	    if (need_adjust)
		wp->w_topline = curbuf->b_ml.ml_line_count;
	    if (need_adjust || !nested)
		
		wp->w_save_cursor.w_topline_corr = wp->w_topline;
	}
}


    void check_lnums(int do_curwin)
{
    check_lnums_both(do_curwin, FALSE);
}


    void check_lnums_nested(int do_curwin)
{
    check_lnums_both(do_curwin, TRUE);
}


    void reset_lnums()
{
    win_T	*wp;
    tabpage_T	*tp;

    FOR_ALL_TAB_WINDOWS(tp, wp)
	if (wp->w_buffer == curbuf)
	{
	    
	    
	    if (EQUAL_POS(wp->w_save_cursor.w_cursor_corr, wp->w_cursor)
				  && wp->w_save_cursor.w_cursor_save.lnum != 0)
		wp->w_cursor = wp->w_save_cursor.w_cursor_save;
	    if (wp->w_save_cursor.w_topline_corr == wp->w_topline && wp->w_save_cursor.w_topline_save != 0)
		wp->w_topline = wp->w_save_cursor.w_topline_save;
	}
}




    void make_snapshot(int idx)
{
    clear_snapshot(curtab, idx);
    make_snapshot_rec(topframe, &curtab->tp_snapshot[idx]);
}

    static void make_snapshot_rec(frame_T *fr, frame_T **frp)
{
    *frp = ALLOC_CLEAR_ONE(frame_T);
    if (*frp == NULL)
	return;
    (*frp)->fr_layout = fr->fr_layout;
    (*frp)->fr_width = fr->fr_width;
    (*frp)->fr_height = fr->fr_height;
    if (fr->fr_next != NULL)
	make_snapshot_rec(fr->fr_next, &((*frp)->fr_next));
    if (fr->fr_child != NULL)
	make_snapshot_rec(fr->fr_child, &((*frp)->fr_child));
    if (fr->fr_layout == FR_LEAF && fr->fr_win == curwin)
	(*frp)->fr_win = curwin;
}


    static void clear_snapshot(tabpage_T *tp, int idx)
{
    clear_snapshot_rec(tp->tp_snapshot[idx]);
    tp->tp_snapshot[idx] = NULL;
}

    static void clear_snapshot_rec(frame_T *fr)
{
    if (fr != NULL)
    {
	clear_snapshot_rec(fr->fr_next);
	clear_snapshot_rec(fr->fr_child);
	vim_free(fr);
    }
}


    static win_T * get_snapshot_curwin_rec(frame_T *ft)
{
    win_T	*wp;

    if (ft->fr_next != NULL)
    {
	if ((wp = get_snapshot_curwin_rec(ft->fr_next)) != NULL)
	    return wp;
    }
    if (ft->fr_child != NULL)
    {
	if ((wp = get_snapshot_curwin_rec(ft->fr_child)) != NULL)
	    return wp;
    }

    return ft->fr_win;
}


    static win_T * get_snapshot_curwin(int idx)
{
    if (curtab->tp_snapshot[idx] == NULL)
	return NULL;

    return get_snapshot_curwin_rec(curtab->tp_snapshot[idx]);
}


    void restore_snapshot( int		idx, int		close_curwin)


{
    win_T	*wp;

    if (curtab->tp_snapshot[idx] != NULL && curtab->tp_snapshot[idx]->fr_width == topframe->fr_width && curtab->tp_snapshot[idx]->fr_height == topframe->fr_height && check_snapshot_rec(curtab->tp_snapshot[idx], topframe) == OK)


    {
	wp = restore_snapshot_rec(curtab->tp_snapshot[idx], topframe);
	win_comp_pos();
	if (wp != NULL && close_curwin)
	    win_goto(wp);
	redraw_all_later(UPD_NOT_VALID);
    }
    clear_snapshot(curtab, idx);
}


    static int check_snapshot_rec(frame_T *sn, frame_T *fr)
{
    if (sn->fr_layout != fr->fr_layout || (sn->fr_next == NULL) != (fr->fr_next == NULL)
	    || (sn->fr_child == NULL) != (fr->fr_child == NULL)
	    || (sn->fr_next != NULL && check_snapshot_rec(sn->fr_next, fr->fr_next) == FAIL)
	    || (sn->fr_child != NULL && check_snapshot_rec(sn->fr_child, fr->fr_child) == FAIL)
	    || (sn->fr_win != NULL && !win_valid(sn->fr_win)))
	return FAIL;
    return OK;
}


    static win_T * restore_snapshot_rec(frame_T *sn, frame_T *fr)
{
    win_T	*wp = NULL;
    win_T	*wp2;

    fr->fr_height = sn->fr_height;
    fr->fr_width = sn->fr_width;
    if (fr->fr_layout == FR_LEAF)
    {
	frame_new_height(fr, fr->fr_height, FALSE, FALSE);
	frame_new_width(fr, fr->fr_width, FALSE, FALSE);
	wp = sn->fr_win;
    }
    if (sn->fr_next != NULL)
    {
	wp2 = restore_snapshot_rec(sn->fr_next, fr->fr_next);
	if (wp2 != NULL)
	    wp = wp2;
    }
    if (sn->fr_child != NULL)
    {
	wp2 = restore_snapshot_rec(sn->fr_child, fr->fr_child);
	if (wp2 != NULL)
	    wp = wp2;
    }
    return wp;
}



    int win_hasvertsplit(void)
{
    frame_T	*fr;

    if (topframe->fr_layout == FR_ROW)
	return TRUE;

    if (topframe->fr_layout == FR_COL)
	FOR_ALL_FRAMES(fr, topframe->fr_child)
	    if (fr->fr_layout == FR_ROW)
		return TRUE;

    return FALSE;
}



    int get_win_number(win_T *wp, win_T *first_win)
{
    int		i = 1;
    win_T	*w;

    for (w = first_win; w != NULL && w != wp; w = W_NEXT(w))
	++i;

    if (w == NULL)
	return 0;
    else return i;
}

    int get_tab_number(tabpage_T *tp UNUSED)
{
    int		i = 1;
    tabpage_T	*t;

    for (t = first_tabpage; t != NULL && t != tp; t = t->tp_next)
	++i;

    if (t == NULL)
	return 0;
    else return i;
}



    static int frame_check_height(frame_T *topfrp, int height)
{
    frame_T *frp;

    if (topfrp->fr_height != height)
	return FALSE;

    if (topfrp->fr_layout == FR_ROW)
	FOR_ALL_FRAMES(frp, topfrp->fr_child)
	    if (frp->fr_height != height)
		return FALSE;

    return TRUE;
}


    static int frame_check_width(frame_T *topfrp, int width)
{
    frame_T *frp;

    if (topfrp->fr_width != width)
	return FALSE;

    if (topfrp->fr_layout == FR_COL)
	FOR_ALL_FRAMES(frp, topfrp->fr_child)
	    if (frp->fr_width != width)
		return FALSE;

    return TRUE;
}



    static int int_cmp(const void *a, const void *b)
{
    return *(const int *)a - *(const int *)b;
}


    char * check_colorcolumn(win_T *wp)
{
    char_u	*s;
    int		col;
    int		count = 0;
    int		color_cols[256];
    int		i;
    int		j = 0;

    if (wp->w_buffer == NULL)
	return NULL;  

    for (s = wp->w_p_cc; *s != NUL && count < 255;)
    {
	if (*s == '-' || *s == '+')
	{
	    
	    col = (*s == '-') ? -1 : 1;
	    ++s;
	    if (!VIM_ISDIGIT(*s))
		return e_invalid_argument;
	    col = col * getdigits(&s);
	    if (wp->w_buffer->b_p_tw == 0)
		goto skip;  
	    col += wp->w_buffer->b_p_tw;
	    if (col < 0)
		goto skip;
	}
	else if (VIM_ISDIGIT(*s))
	    col = getdigits(&s);
	else return e_invalid_argument;
	color_cols[count++] = col - 1;  
skip:
	if (*s == NUL)
	    break;
	if (*s != ',')
	    return e_invalid_argument;
	if (*++s == NUL)
	    return e_invalid_argument;  
    }

    vim_free(wp->w_p_cc_cols);
    if (count == 0)
	wp->w_p_cc_cols = NULL;
    else {
	wp->w_p_cc_cols = ALLOC_MULT(int, count + 1);
	if (wp->w_p_cc_cols != NULL)
	{
	    
	    
	    qsort(color_cols, count, sizeof(int), int_cmp);

	    for (i = 0; i < count; ++i)
		
		if (j == 0 || wp->w_p_cc_cols[j - 1] != color_cols[i])
		    wp->w_p_cc_cols[j++] = color_cols[i];
	    wp->w_p_cc_cols[j] = -1;  
	}
    }

    return NULL;  
}

