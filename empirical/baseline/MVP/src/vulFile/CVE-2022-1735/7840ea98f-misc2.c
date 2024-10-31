




static char_u	*username = NULL; 

static int coladvance2(pos_T *pos, int addspaces, int finetune, colnr_T wcol);


    int virtual_active(void)
{
    unsigned int cur_ve_flags = get_ve_flags();

    
    
    
    if (virtual_op != MAYBE)
	return virtual_op;
    return (cur_ve_flags == VE_ALL || ((cur_ve_flags & VE_BLOCK) && VIsual_active && VIsual_mode == Ctrl_V)

	    || ((cur_ve_flags & VE_INSERT) && (State & MODE_INSERT)));
}


    int getviscol(void)
{
    colnr_T	x;

    getvvcol(curwin, &curwin->w_cursor, &x, NULL, NULL);
    return (int)x;
}


    int coladvance_force(colnr_T wcol)
{
    int rc = coladvance2(&curwin->w_cursor, TRUE, FALSE, wcol);

    if (wcol == MAXCOL)
	curwin->w_valid &= ~VALID_VIRTCOL;
    else {
	
	curwin->w_valid |= VALID_VIRTCOL;
	curwin->w_virtcol = wcol;
    }
    return rc;
}


    int getviscol2(colnr_T col, colnr_T coladd UNUSED)
{
    colnr_T	x;
    pos_T	pos;

    pos.lnum = curwin->w_cursor.lnum;
    pos.col = col;
    pos.coladd = coladd;
    getvvcol(curwin, &pos, &x, NULL, NULL);
    return (int)x;
}


    int coladvance(colnr_T wcol)
{
    int rc = getvpos(&curwin->w_cursor, wcol);

    if (wcol == MAXCOL || rc == FAIL)
	curwin->w_valid &= ~VALID_VIRTCOL;
    else if (*ml_get_cursor() != TAB)
    {
	
	curwin->w_valid |= VALID_VIRTCOL;
	curwin->w_virtcol = wcol;
    }
    return rc;
}


    int getvpos(pos_T *pos, colnr_T wcol)
{
    return coladvance2(pos, FALSE, virtual_active(), wcol);
}

    static int coladvance2( pos_T	*pos, int		addspaces, int		finetune, colnr_T	wcol_arg)




{
    colnr_T	wcol = wcol_arg;
    int		idx;
    char_u	*ptr;
    char_u	*line;
    colnr_T	col = 0;
    int		csize = 0;
    int		one_more;

    int		head = 0;


    one_more = (State & MODE_INSERT)
		    || restart_edit != NUL || (VIsual_active && *p_sel != 'o')
		    || ((get_ve_flags() & VE_ONEMORE) && wcol < MAXCOL);
    line = ml_get_buf(curbuf, pos->lnum, FALSE);

    if (wcol >= MAXCOL)
    {
	    idx = (int)STRLEN(line) - 1 + one_more;
	    col = wcol;

	    if ((addspaces || finetune) && !VIsual_active)
	    {
		curwin->w_curswant = linetabsize(line) + one_more;
		if (curwin->w_curswant > 0)
		    --curwin->w_curswant;
	    }
    }
    else {
	int width = curwin->w_width - win_col_off(curwin);

	if (finetune && curwin->w_p_wrap && curwin->w_width != 0 && wcol >= (colnr_T)width && width > 0)



	{
	    csize = linetabsize(line);
	    if (csize > 0)
		csize--;

	    if (wcol / width > (colnr_T)csize / width && ((State & MODE_INSERT) == 0 || (int)wcol > csize + 1))
	    {
		
		
		
		
		wcol = (csize / width + 1) * width - 1;
	    }
	}

	ptr = line;
	while (col <= wcol && *ptr != NUL)
	{
	    

	    csize = win_lbr_chartabsize(curwin, line, ptr, col, &head);
	    MB_PTR_ADV(ptr);

	    csize = lbr_chartabsize_adv(line, &ptr, col);

	    col += csize;
	}
	idx = (int)(ptr - line);
	
	if (col > wcol || (!virtual_active() && one_more == 0))
	{
	    idx -= 1;

	    
	    csize -= head;

	    col -= csize;
	}

	if (virtual_active()
		&& addspaces && wcol >= 0 && ((col != wcol && col != wcol + 1) || csize > 1))

	{
	    
	    

	    if (line[idx] == NUL)
	    {
		
		int	correct = wcol - col;
		char_u	*newline = alloc(idx + correct + 1);
		int	t;

		if (newline == NULL)
		    return FAIL;

		for (t = 0; t < idx; ++t)
		    newline[t] = line[t];

		for (t = 0; t < correct; ++t)
		    newline[t + idx] = ' ';

		newline[idx + correct] = NUL;

		ml_replace(pos->lnum, newline, FALSE);
		changed_bytes(pos->lnum, (colnr_T)idx);
		idx += correct;
		col = wcol;
	    }
	    else {
		
		int	linelen = (int)STRLEN(line);
		int	correct = wcol - col - csize + 1; 
		char_u	*newline;
		int	t, s = 0;
		int	v;

		if (-correct > csize)
		    return FAIL;

		newline = alloc(linelen + csize);
		if (newline == NULL)
		    return FAIL;

		for (t = 0; t < linelen; t++)
		{
		    if (t != idx)
			newline[s++] = line[t];
		    else for (v = 0; v < csize; v++)
			    newline[s++] = ' ';
		}

		newline[linelen + csize - 1] = NUL;

		ml_replace(pos->lnum, newline, FALSE);
		changed_bytes(pos->lnum, idx);
		idx += (csize - 1 + correct);
		col += correct;
	    }
	}
    }

    if (idx < 0)
	pos->col = 0;
    else pos->col = idx;

    pos->coladd = 0;

    if (finetune)
    {
	if (wcol == MAXCOL)
	{
	    
	    if (!one_more)
	    {
		colnr_T	    scol, ecol;

		getvcol(curwin, pos, &scol, NULL, &ecol);
		pos->coladd = ecol - scol;
	    }
	}
	else {
	    int b = (int)wcol - (int)col;

	    
	    if (b > 0 && b < (MAXCOL - 2 * curwin->w_width))
		pos->coladd = b;

	    col += b;
	}
    }

    
    if (has_mbyte)
	mb_adjustpos(curbuf, pos);

    if (wcol < 0 || col < wcol)
	return FAIL;
    return OK;
}


    int inc_cursor(void)
{
    return inc(&curwin->w_cursor);
}


    int inc(pos_T *lp)
{
    char_u  *p;

    
    if (lp->col != MAXCOL)
    {
	p = ml_get_pos(lp);
	if (*p != NUL)	
	{
	    if (has_mbyte)
	    {
		int l = (*mb_ptr2len)(p);

		lp->col += l;
		return ((p[l] != NUL) ? 0 : 2);
	    }
	    lp->col++;
	    lp->coladd = 0;
	    return ((p[1] != NUL) ? 0 : 2);
	}
    }
    if (lp->lnum != curbuf->b_ml.ml_line_count)     
    {
	lp->col = 0;
	lp->lnum++;
	lp->coladd = 0;
	return 1;
    }
    return -1;
}


    int incl(pos_T *lp)
{
    int	    r;

    if ((r = inc(lp)) >= 1 && lp->col)
	r = inc(lp);
    return r;
}


    int dec_cursor(void)
{
    return dec(&curwin->w_cursor);
}

    int dec(pos_T *lp)
{
    char_u	*p;

    lp->coladd = 0;
    if (lp->col == MAXCOL)
    {
	
	p = ml_get(lp->lnum);
	lp->col = (colnr_T)STRLEN(p);
	if (has_mbyte)
	    lp->col -= (*mb_head_off)(p, p + lp->col);
	return 0;
    }

    if (lp->col > 0)
    {
	
	lp->col--;
	if (has_mbyte)
	{
	    p = ml_get(lp->lnum);
	    lp->col -= (*mb_head_off)(p, p + lp->col);
	}
	return 0;
    }

    if (lp->lnum > 1)
    {
	
	lp->lnum--;
	p = ml_get(lp->lnum);
	lp->col = (colnr_T)STRLEN(p);
	if (has_mbyte)
	    lp->col -= (*mb_head_off)(p, p + lp->col);
	return 1;
    }

    
    return -1;
}


    int decl(pos_T *lp)
{
    int	    r;

    if ((r = dec(lp)) == 1 && lp->col)
	r = dec(lp);
    return r;
}


    linenr_T get_cursor_rel_lnum( win_T	*wp, linenr_T	lnum)


{
    linenr_T	cursor = wp->w_cursor.lnum;
    linenr_T	retval = 0;


    if (hasAnyFolding(wp))
    {
	if (lnum > cursor)
	{
	    while (lnum > cursor)
	    {
		(void)hasFoldingWin(wp, lnum, &lnum, NULL, TRUE, NULL);
		
		
		if (lnum > cursor)
		    retval++;
		lnum--;
	    }
	}
	else if (lnum < cursor)
	{
	    while (lnum < cursor)
	    {
		(void)hasFoldingWin(wp, lnum, NULL, &lnum, TRUE, NULL);
		
		
		if (lnum < cursor)
		    retval--;
		lnum++;
	    }
	}
	
	
    }
    else  retval = lnum - cursor;


    return retval;
}


    void check_pos(buf_T *buf, pos_T *pos)
{
    char_u *line;
    colnr_T len;

    if (pos->lnum > buf->b_ml.ml_line_count)
	pos->lnum = buf->b_ml.ml_line_count;

    if (pos->col > 0)
    {
	line = ml_get_buf(buf, pos->lnum, FALSE);
	len = (colnr_T)STRLEN(line);
	if (pos->col > len)
	    pos->col = len;
    }
}


    void check_cursor_lnum(void)
{
    if (curwin->w_cursor.lnum > curbuf->b_ml.ml_line_count)
    {

	
	
	if (!hasFolding(curbuf->b_ml.ml_line_count, &curwin->w_cursor.lnum, NULL))

	    curwin->w_cursor.lnum = curbuf->b_ml.ml_line_count;
    }
    if (curwin->w_cursor.lnum <= 0)
	curwin->w_cursor.lnum = 1;
}


    void check_cursor_col(void)
{
    check_cursor_col_win(curwin);
}


    void check_cursor_col_win(win_T *win)
{
    colnr_T      len;
    colnr_T      oldcol = win->w_cursor.col;
    colnr_T      oldcoladd = win->w_cursor.col + win->w_cursor.coladd;
    unsigned int cur_ve_flags = get_ve_flags();

    len = (colnr_T)STRLEN(ml_get_buf(win->w_buffer, win->w_cursor.lnum, FALSE));
    if (len == 0)
	win->w_cursor.col = 0;
    else if (win->w_cursor.col >= len)
    {
	
	
	
	
	if ((State & MODE_INSERT) || restart_edit || (VIsual_active && *p_sel != 'o')
		|| (cur_ve_flags & VE_ONEMORE)
		|| virtual_active())
	    win->w_cursor.col = len;
	else {
	    win->w_cursor.col = len - 1;
	    
	    if (has_mbyte)
		mb_adjustpos(win->w_buffer, &win->w_cursor);
	}
    }
    else if (win->w_cursor.col < 0)
	win->w_cursor.col = 0;

    
    
    
    if (oldcol == MAXCOL)
	win->w_cursor.coladd = 0;
    else if (cur_ve_flags == VE_ALL)
    {
	if (oldcoladd > win->w_cursor.col)
	{
	    win->w_cursor.coladd = oldcoladd - win->w_cursor.col;

	    
	    
	    
	    if (win->w_cursor.col + 1 < len)
	    {
		int cs, ce;

		getvcol(win, &win->w_cursor, &cs, NULL, &ce);
		if (win->w_cursor.coladd > ce - cs)
		    win->w_cursor.coladd = ce - cs;
	    }
	}
	else  win->w_cursor.coladd = 0;

    }
}


    void check_cursor(void)
{
    check_cursor_lnum();
    check_cursor_col();
}



    void adjust_cursor_col(void)
{
    if (curwin->w_cursor.col > 0 && (!VIsual_active || *p_sel == 'o')
	    && gchar_cursor() == NUL)
	--curwin->w_cursor.col;
}



    int leftcol_changed(void)
{
    long	lastcol;
    colnr_T	s, e;
    int		retval = FALSE;
    long	siso = get_sidescrolloff_value();

    changed_cline_bef_curs();
    lastcol = curwin->w_leftcol + curwin->w_width - curwin_col_off() - 1;
    validate_virtcol();

    
    if (curwin->w_virtcol > (colnr_T)(lastcol - siso))
    {
	retval = TRUE;
	coladvance((colnr_T)(lastcol - siso));
    }
    else if (curwin->w_virtcol < curwin->w_leftcol + siso)
    {
	retval = TRUE;
	(void)coladvance((colnr_T)(curwin->w_leftcol + siso));
    }

    
    getvvcol(curwin, &curwin->w_cursor, &s, NULL, &e);
    if (e > (colnr_T)lastcol)
    {
	retval = TRUE;
	coladvance(s - 1);
    }
    else if (s < curwin->w_leftcol)
    {
	retval = TRUE;
	if (coladvance(e + 1) == FAIL)	
	{
	    curwin->w_leftcol = s;	
	    changed_cline_bef_curs();
	}
    }

    if (retval)
	curwin->w_set_curswant = TRUE;
    redraw_later(NOT_VALID);
    return retval;
}


    int copy_option_part( char_u	**option, char_u	*buf, int		maxlen, char	*sep_chars)




{
    int	    len = 0;
    char_u  *p = *option;

    
    if (*p == '.')
	buf[len++] = *p++;
    while (*p != NUL && vim_strchr((char_u *)sep_chars, *p) == NULL)
    {
	
	if (p[0] == '\\' && vim_strchr((char_u *)sep_chars, p[1]) != NULL)
	    ++p;
	if (len < maxlen - 1)
	    buf[len++] = *p;
	++p;
    }
    buf[len] = NUL;

    if (*p != NUL && *p != ',')	
	++p;
    p = skip_to_option_part(p);	

    *option = p;
    return len;
}


    void * vim_memset(void *ptr, int c, size_t size)
{
    char *p = ptr;

    while (size-- > 0)
	*p++ = c;
    return ptr;
}



    int vim_isspace(int x)
{
    return ((x >= 9 && x <= 13) || x == ' ');
}





static struct modmasktable {
    short	mod_mask;	
    short	mod_flag;	
    char_u	name;		
} mod_mask_table[] = {
    {MOD_MASK_ALT,		MOD_MASK_ALT,		(char_u)'M', {MOD_MASK_META,		MOD_MASK_META,		(char_u)'T', {MOD_MASK_CTRL,		MOD_MASK_CTRL,		(char_u)'C', {MOD_MASK_SHIFT,		MOD_MASK_SHIFT,		(char_u)'S', {MOD_MASK_MULTI_CLICK,	MOD_MASK_2CLICK,	(char_u)'2', {MOD_MASK_MULTI_CLICK,	MOD_MASK_3CLICK,	(char_u)'3', {MOD_MASK_MULTI_CLICK,	MOD_MASK_4CLICK,	(char_u)'4',  {MOD_MASK_CMD,		MOD_MASK_CMD,		(char_u)'D',   {MOD_MASK_ALT,		MOD_MASK_ALT,		(char_u)'A', {0, 0, NUL}











    
};




static char_u modifier_keys_table[] = {

    MOD_MASK_SHIFT, '&', '9',			'@', '1',	 MOD_MASK_SHIFT, '&', '0',			'@', '2', MOD_MASK_SHIFT, '*', '1',			'@', '4', MOD_MASK_SHIFT, '*', '2',			'@', '5', MOD_MASK_SHIFT, '*', '3',			'@', '6', MOD_MASK_SHIFT, '*', '4',			'k', 'D', MOD_MASK_SHIFT, '*', '5',			'k', 'L', MOD_MASK_SHIFT, '*', '7',			'@', '7', MOD_MASK_CTRL,  KS_EXTRA, (int)KE_C_END,	'@', '7', MOD_MASK_SHIFT, '*', '9',			'@', '9', MOD_MASK_SHIFT, '*', '0',			'@', '0', MOD_MASK_SHIFT, '#', '1',			'%', '1', MOD_MASK_SHIFT, '#', '2',			'k', 'h', MOD_MASK_CTRL,  KS_EXTRA, (int)KE_C_HOME,	'k', 'h', MOD_MASK_SHIFT, '#', '3',			'k', 'I', MOD_MASK_SHIFT, '#', '4',			'k', 'l', MOD_MASK_CTRL,  KS_EXTRA, (int)KE_C_LEFT,	'k', 'l', MOD_MASK_SHIFT, '%', 'a',			'%', '3', MOD_MASK_SHIFT, '%', 'b',			'%', '4', MOD_MASK_SHIFT, '%', 'c',			'%', '5', MOD_MASK_SHIFT, '%', 'd',			'%', '7', MOD_MASK_SHIFT, '%', 'e',			'%', '8', MOD_MASK_SHIFT, '%', 'f',			'%', '9', MOD_MASK_SHIFT, '%', 'g',			'%', '0', MOD_MASK_SHIFT, '%', 'h',			'&', '3', MOD_MASK_SHIFT, '%', 'i',			'k', 'r', MOD_MASK_CTRL,  KS_EXTRA, (int)KE_C_RIGHT,	'k', 'r', MOD_MASK_SHIFT, '%', 'j',			'&', '5', MOD_MASK_SHIFT, '!', '1',			'&', '6', MOD_MASK_SHIFT, '!', '2',			'&', '7', MOD_MASK_SHIFT, '!', '3',			'&', '8', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_UP,	'k', 'u', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_DOWN,	'k', 'd',   MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_XF1,	KS_EXTRA, (int)KE_XF1, MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_XF2,	KS_EXTRA, (int)KE_XF2, MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_XF3,	KS_EXTRA, (int)KE_XF3, MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_XF4,	KS_EXTRA, (int)KE_XF4,  MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F1,	'k', '1', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F2,	'k', '2', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F3,	'k', '3', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F4,	'k', '4', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F5,	'k', '5', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F6,	'k', '6', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F7,	'k', '7', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F8,	'k', '8', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F9,	'k', '9', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F10,	'k', ';',  MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F11,	'F', '1', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F12,	'F', '2', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F13,	'F', '3', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F14,	'F', '4', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F15,	'F', '5', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F16,	'F', '6', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F17,	'F', '7', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F18,	'F', '8', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F19,	'F', '9', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F20,	'F', 'A',  MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F21,	'F', 'B', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F22,	'F', 'C', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F23,	'F', 'D', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F24,	'F', 'E', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F25,	'F', 'F', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F26,	'F', 'G', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F27,	'F', 'H', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F28,	'F', 'I', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F29,	'F', 'J', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F30,	'F', 'K',  MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F31,	'F', 'L', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F32,	'F', 'M', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F33,	'F', 'N', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F34,	'F', 'O', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F35,	'F', 'P', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F36,	'F', 'Q', MOD_MASK_SHIFT, KS_EXTRA, (int)KE_S_F37,	'F', 'R',   MOD_MASK_SHIFT, 'k', 'B',			KS_EXTRA, (int)KE_TAB,  NUL };





















































































static struct key_name_entry {
    int	    key;	
    char_u  *name;	
} key_names_table[] = {
    {' ',		(char_u *)"Space", {TAB,		(char_u *)"Tab", {K_TAB,		(char_u *)"Tab", {NL,		(char_u *)"NL", {NL,		(char_u *)"NewLine", {NL,		(char_u *)"LineFeed", {NL,		(char_u *)"LF", {CAR,		(char_u *)"CR", {CAR,		(char_u *)"Return", {CAR,		(char_u *)"Enter", {K_BS,		(char_u *)"BS", {K_BS,		(char_u *)"BackSpace", {ESC,		(char_u *)"Esc", {CSI,		(char_u *)"CSI", {K_CSI,		(char_u *)"xCSI", {'|',		(char_u *)"Bar", {'\\',		(char_u *)"Bslash", {K_DEL,		(char_u *)"Del", {K_DEL,		(char_u *)"Delete", {K_KDEL,		(char_u *)"kDel", {K_UP,		(char_u *)"Up", {K_DOWN,		(char_u *)"Down", {K_LEFT,		(char_u *)"Left", {K_RIGHT,		(char_u *)"Right", {K_XUP,		(char_u *)"xUp", {K_XDOWN,		(char_u *)"xDown", {K_XLEFT,		(char_u *)"xLeft", {K_XRIGHT,		(char_u *)"xRight", {K_PS,		(char_u *)"PasteStart", {K_PE,		(char_u *)"PasteEnd",  {K_F1,		(char_u *)"F1", {K_F2,		(char_u *)"F2", {K_F3,		(char_u *)"F3", {K_F4,		(char_u *)"F4", {K_F5,		(char_u *)"F5", {K_F6,		(char_u *)"F6", {K_F7,		(char_u *)"F7", {K_F8,		(char_u *)"F8", {K_F9,		(char_u *)"F9", {K_F10,		(char_u *)"F10",  {K_F11,		(char_u *)"F11", {K_F12,		(char_u *)"F12", {K_F13,		(char_u *)"F13", {K_F14,		(char_u *)"F14", {K_F15,		(char_u *)"F15", {K_F16,		(char_u *)"F16", {K_F17,		(char_u *)"F17", {K_F18,		(char_u *)"F18", {K_F19,		(char_u *)"F19", {K_F20,		(char_u *)"F20",  {K_F21,		(char_u *)"F21", {K_F22,		(char_u *)"F22", {K_F23,		(char_u *)"F23", {K_F24,		(char_u *)"F24", {K_F25,		(char_u *)"F25", {K_F26,		(char_u *)"F26", {K_F27,		(char_u *)"F27", {K_F28,		(char_u *)"F28", {K_F29,		(char_u *)"F29", {K_F30,		(char_u *)"F30",  {K_F31,		(char_u *)"F31", {K_F32,		(char_u *)"F32", {K_F33,		(char_u *)"F33", {K_F34,		(char_u *)"F34", {K_F35,		(char_u *)"F35", {K_F36,		(char_u *)"F36", {K_F37,		(char_u *)"F37",  {K_XF1,		(char_u *)"xF1", {K_XF2,		(char_u *)"xF2", {K_XF3,		(char_u *)"xF3", {K_XF4,		(char_u *)"xF4",  {K_HELP,		(char_u *)"Help", {K_UNDO,		(char_u *)"Undo", {K_INS,		(char_u *)"Insert", {K_INS,		(char_u *)"Ins", {K_KINS,		(char_u *)"kInsert", {K_HOME,		(char_u *)"Home", {K_KHOME,		(char_u *)"kHome", {K_XHOME,		(char_u *)"xHome", {K_ZHOME,		(char_u *)"zHome", {K_END,		(char_u *)"End", {K_KEND,		(char_u *)"kEnd", {K_XEND,		(char_u *)"xEnd", {K_ZEND,		(char_u *)"zEnd", {K_PAGEUP,		(char_u *)"PageUp", {K_PAGEDOWN,	(char_u *)"PageDown", {K_KPAGEUP,		(char_u *)"kPageUp", {K_KPAGEDOWN,	(char_u *)"kPageDown",  {K_KPLUS,		(char_u *)"kPlus", {K_KMINUS,		(char_u *)"kMinus", {K_KDIVIDE,		(char_u *)"kDivide", {K_KMULTIPLY,	(char_u *)"kMultiply", {K_KENTER,		(char_u *)"kEnter", {K_KPOINT,		(char_u *)"kPoint",  {K_K0,		(char_u *)"k0", {K_K1,		(char_u *)"k1", {K_K2,		(char_u *)"k2", {K_K3,		(char_u *)"k3", {K_K4,		(char_u *)"k4", {K_K5,		(char_u *)"k5", {K_K6,		(char_u *)"k6", {K_K7,		(char_u *)"k7", {K_K8,		(char_u *)"k8", {K_K9,		(char_u *)"k9",  {'<',		(char_u *)"lt",  {K_MOUSE,		(char_u *)"Mouse",  {K_NETTERM_MOUSE,	(char_u *)"NetMouse",   {K_DEC_MOUSE,	(char_u *)"DecMouse",   {K_JSBTERM_MOUSE,	(char_u *)"JsbMouse",   {K_PTERM_MOUSE,	(char_u *)"PtermMouse",   {K_URXVT_MOUSE,	(char_u *)"UrxvtMouse",  {K_SGR_MOUSE,	(char_u *)"SgrMouse", {K_SGR_MOUSERELEASE, (char_u *)"SgrMouseRelease", {K_LEFTMOUSE,	(char_u *)"LeftMouse", {K_LEFTMOUSE_NM,	(char_u *)"LeftMouseNM", {K_LEFTDRAG,	(char_u *)"LeftDrag", {K_LEFTRELEASE,	(char_u *)"LeftRelease", {K_LEFTRELEASE_NM,	(char_u *)"LeftReleaseNM", {K_MOUSEMOVE,	(char_u *)"MouseMove", {K_MIDDLEMOUSE,	(char_u *)"MiddleMouse", {K_MIDDLEDRAG,	(char_u *)"MiddleDrag", {K_MIDDLERELEASE,	(char_u *)"MiddleRelease", {K_RIGHTMOUSE,	(char_u *)"RightMouse", {K_RIGHTDRAG,	(char_u *)"RightDrag", {K_RIGHTRELEASE,	(char_u *)"RightRelease", {K_MOUSEDOWN,	(char_u *)"ScrollWheelUp", {K_MOUSEUP,		(char_u *)"ScrollWheelDown", {K_MOUSELEFT,	(char_u *)"ScrollWheelRight", {K_MOUSERIGHT,	(char_u *)"ScrollWheelLeft", {K_MOUSEDOWN,	(char_u *)"MouseDown", {K_MOUSEUP,		(char_u *)"MouseUp", {K_X1MOUSE,		(char_u *)"X1Mouse", {K_X1DRAG,		(char_u *)"X1Drag", {K_X1RELEASE,		(char_u *)"X1Release", {K_X2MOUSE,		(char_u *)"X2Mouse", {K_X2DRAG,		(char_u *)"X2Drag", {K_X2RELEASE,		(char_u *)"X2Release", {K_DROP,		(char_u *)"Drop", {K_ZERO,		(char_u *)"Nul",  {K_SNR,		(char_u *)"SNR",  {K_PLUG,		(char_u *)"Plug", {K_CURSORHOLD,	(char_u *)"CursorHold", {K_IGNORE,		(char_u *)"Ignore", {K_COMMAND,		(char_u *)"Cmd", {K_SCRIPT_COMMAND,	(char_u *)"ScriptCmd", {K_FOCUSGAINED,	(char_u *)"FocusGained", {K_FOCUSLOST,	(char_u *)"FocusLost", {0,			NULL}








































































































































































    
};




    static int name_to_mod_mask(int c)
{
    int	    i;

    c = TOUPPER_ASC(c);
    for (i = 0; mod_mask_table[i].mod_mask != 0; i++)
	if (c == mod_mask_table[i].name)
	    return mod_mask_table[i].mod_flag;
    return 0;
}


    int simplify_key(int key, int *modifiers)
{
    int	    i;
    int	    key0;
    int	    key1;

    if (*modifiers & (MOD_MASK_SHIFT | MOD_MASK_CTRL | MOD_MASK_ALT))
    {
	
	if (key == TAB && (*modifiers & MOD_MASK_SHIFT))
	{
	    *modifiers &= ~MOD_MASK_SHIFT;
	    return K_S_TAB;
	}
	key0 = KEY2TERMCAP0(key);
	key1 = KEY2TERMCAP1(key);
	for (i = 0; modifier_keys_table[i] != NUL; i += MOD_KEYS_ENTRY_SIZE)
	    if (key0 == modifier_keys_table[i + 3] && key1 == modifier_keys_table[i + 4] && (*modifiers & modifier_keys_table[i]))

	    {
		*modifiers &= ~modifier_keys_table[i];
		return TERMCAP2KEY(modifier_keys_table[i + 1], modifier_keys_table[i + 2]);
	    }
    }
    return key;
}


    int handle_x_keys(int key)
{
    switch (key)
    {
	case K_XUP:	return K_UP;
	case K_XDOWN:	return K_DOWN;
	case K_XLEFT:	return K_LEFT;
	case K_XRIGHT:	return K_RIGHT;
	case K_XHOME:	return K_HOME;
	case K_ZHOME:	return K_HOME;
	case K_XEND:	return K_END;
	case K_ZEND:	return K_END;
	case K_XF1:	return K_F1;
	case K_XF2:	return K_F2;
	case K_XF3:	return K_F3;
	case K_XF4:	return K_F4;
	case K_S_XF1:	return K_S_F1;
	case K_S_XF2:	return K_S_F2;
	case K_S_XF3:	return K_S_F3;
	case K_S_XF4:	return K_S_F4;
    }
    return key;
}


    char_u * get_special_key_name(int c, int modifiers)
{
    static char_u string[MAX_KEY_NAME_LEN + 1];

    int	    i, idx;
    int	    table_idx;
    char_u  *s;

    string[0] = '<';
    idx = 1;

    
    if (IS_SPECIAL(c) && KEY2TERMCAP0(c) == KS_KEY)
	c = KEY2TERMCAP1(c);

    
    if (IS_SPECIAL(c))
    {
	for (i = 0; modifier_keys_table[i] != 0; i += MOD_KEYS_ENTRY_SIZE)
	    if (       KEY2TERMCAP0(c) == (int)modifier_keys_table[i + 1] && (int)KEY2TERMCAP1(c) == (int)modifier_keys_table[i + 2])
	    {
		modifiers |= modifier_keys_table[i];
		c = TERMCAP2KEY(modifier_keys_table[i + 3], modifier_keys_table[i + 4]);
		break;
	    }
    }

    
    table_idx = find_special_key_in_table(c);

    
    if (c > 0 && (*mb_char2len)(c) == 1)
    {
	if (table_idx < 0 && (!vim_isprintc(c) || (c & 0x7f) == ' ')
		&& (c & 0x80))
	{
	    c &= 0x7f;
	    modifiers |= MOD_MASK_ALT;
	    
	    table_idx = find_special_key_in_table(c);
	}
	if (table_idx < 0 && !vim_isprintc(c) && c < ' ')
	{
	    c += '@';
	    modifiers |= MOD_MASK_CTRL;
	}
    }

    
    for (i = 0; mod_mask_table[i].name != 'A'; i++)
	if ((modifiers & mod_mask_table[i].mod_mask)
						== mod_mask_table[i].mod_flag)
	{
	    string[idx++] = mod_mask_table[i].name;
	    string[idx++] = (char_u)'-';
	}

    if (table_idx < 0)		
    {
	if (IS_SPECIAL(c))
	{
	    string[idx++] = 't';
	    string[idx++] = '_';
	    string[idx++] = KEY2TERMCAP0(c);
	    string[idx++] = KEY2TERMCAP1(c);
	}
	
	else {
	    if (has_mbyte && (*mb_char2len)(c) > 1)
		idx += (*mb_char2bytes)(c, string + idx);
	    else if (vim_isprintc(c))
		string[idx++] = c;
	    else {
		s = transchar(c);
		while (*s)
		    string[idx++] = *s++;
	    }
	}
    }
    else		 {
	size_t len = STRLEN(key_names_table[table_idx].name);

	if (len + idx + 2 <= MAX_KEY_NAME_LEN)
	{
	    STRCPY(string + idx, key_names_table[table_idx].name);
	    idx += (int)len;
	}
    }
    string[idx++] = '>';
    string[idx] = NUL;
    return string;
}


    int trans_special( char_u	**srcp, char_u	*dst, int		flags, int		escape_ks, int		*did_simplify)





{
    int		modifiers = 0;
    int		key;

    key = find_special_key(srcp, &modifiers, flags, did_simplify);
    if (key == 0)
	return 0;

    return special_to_buf(key, modifiers, escape_ks, dst);
}


    int special_to_buf(int key, int modifiers, int escape_ks, char_u *dst)
{
    int		dlen = 0;

    
    if (modifiers != 0)
    {
	dst[dlen++] = K_SPECIAL;
	dst[dlen++] = KS_MODIFIER;
	dst[dlen++] = modifiers;
    }

    if (IS_SPECIAL(key))
    {
	dst[dlen++] = K_SPECIAL;
	dst[dlen++] = KEY2TERMCAP0(key);
	dst[dlen++] = KEY2TERMCAP1(key);
    }
    else if (escape_ks)
	dlen = (int)(add_char2buf(key, dst + dlen) - dst);
    else if (has_mbyte)
	dlen += (*mb_char2bytes)(key, dst + dlen);
    else dst[dlen++] = key;

    return dlen;
}


    int find_special_key( char_u	**srcp, int		*modp, int		flags, int		*did_simplify)




{
    char_u	*last_dash;
    char_u	*end_of_name;
    char_u	*src;
    char_u	*bp;
    int		in_string = flags & FSK_IN_STRING;
    int		modifiers;
    int		bit;
    int		key;
    uvarnumber_T	n;
    int		l;

    src = *srcp;
    if (src[0] != '<')
	return 0;
    if (src[1] == '*')	    
	++src;

    
    last_dash = src;
    for (bp = src + 1; *bp == '-' || vim_isNormalIDc(*bp); bp++)
    {
	if (*bp == '-')
	{
	    last_dash = bp;
	    if (bp[1] != NUL)
	    {
		if (has_mbyte)
		    l = mb_ptr2len(bp + 1);
		else l = 1;
		
		
		
		if (!(in_string && bp[1] == '"') && bp[l + 1] == '>')
		    bp += l;
		else if (in_string && bp[1] == '\\' && bp[2] == '"' && bp[3] == '>')
		    bp += 2;
	    }
	}
	if (bp[0] == 't' && bp[1] == '_' && bp[2] && bp[3])
	    bp += 3;	
	else if (STRNICMP(bp, "char-", 5) == 0)
	{
	    vim_str2nr(bp + 5, NULL, &l, STR2NR_ALL, NULL, NULL, 0, TRUE);
	    if (l == 0)
	    {
		emsg(_(e_invalid_argument));
		return 0;
	    }
	    bp += l + 5;
	    break;
	}
    }

    if (*bp == '>')	
    {
	end_of_name = bp + 1;

	
	modifiers = 0x0;
	for (bp = src + 1; bp < last_dash; bp++)
	{
	    if (*bp != '-')
	    {
		bit = name_to_mod_mask(*bp);
		if (bit == 0x0)
		    break;	
		modifiers |= bit;
	    }
	}

	
	if (bp >= last_dash)
	{
	    if (STRNICMP(last_dash + 1, "char-", 5) == 0 && VIM_ISDIGIT(last_dash[6]))
	    {
		
		vim_str2nr(last_dash + 6, NULL, &l, STR2NR_ALL, NULL, &n, 0, TRUE);
		if (l == 0)
		{
		    emsg(_(e_invalid_argument));
		    return 0;
		}
		key = (int)n;
	    }
	    else {
		int off = 1;

		
		if (in_string && last_dash[1] == '\\' && last_dash[2] == '"')
		    off = 2;
		if (has_mbyte)
		    l = mb_ptr2len(last_dash + off);
		else l = 1;
		if (modifiers != 0 && last_dash[l + off] == '>')
		    key = PTR2CHAR(last_dash + off);
		else {
		    key = get_special_key_code(last_dash + off);
		    if (!(flags & FSK_KEEP_X_KEY))
			key = handle_x_keys(key);
		}
	    }

	    
	    if (key != NUL)
	    {
		
		key = simplify_key(key, &modifiers);

		if (!(flags & FSK_KEYCODE))
		{
		    
		    if (key == K_BS)
			key = BS;
		    else if (key == K_DEL || key == K_KDEL)
			key = DEL;
		}

		
		if (!IS_SPECIAL(key))
		    key = extract_modifiers(key, &modifiers, flags & FSK_SIMPLIFY, did_simplify);

		*modp = modifiers;
		*srcp = end_of_name;
		return key;
	    }
	}
    }
    return 0;
}



    int may_adjust_key_for_ctrl(int modifiers, int key)
{
    if (modifiers & MOD_MASK_CTRL)
    {
	if (ASCII_ISALPHA(key))
	    return TOUPPER_ASC(key);
	if (key == '2')
	    return '@';
	if (key == '6')
	    return '^';
	if (key == '-')
	    return '_';
    }
    return key;
}


    int may_remove_shift_modifier(int modifiers, int key)
{
    if ((modifiers == MOD_MASK_SHIFT || modifiers == (MOD_MASK_SHIFT | MOD_MASK_ALT)
		|| modifiers == (MOD_MASK_SHIFT | MOD_MASK_META))
	    && ((key >= '!' && key <= '/')
		|| (key >= ':' && key <= 'Z')
		|| (key >= '[' && key <= '`')
		|| (key >= '{' && key <= '~')))
	return modifiers & ~MOD_MASK_SHIFT;

    if (modifiers == (MOD_MASK_SHIFT | MOD_MASK_CTRL)
		&& (key == '{' || key == '}' || key == '|'))
	return modifiers & ~MOD_MASK_SHIFT;

    return modifiers;
}


    int extract_modifiers(int key, int *modp, int simplify, int *did_simplify)
{
    int	modifiers = *modp;


    
    if (!(modifiers & MOD_MASK_CMD))

    if ((modifiers & MOD_MASK_SHIFT) && ASCII_ISALPHA(key))
    {
	key = TOUPPER_ASC(key);
	
	
	if (simplify || modifiers == MOD_MASK_SHIFT || modifiers == (MOD_MASK_SHIFT | MOD_MASK_ALT)
		|| modifiers == (MOD_MASK_SHIFT | MOD_MASK_META))
	    modifiers &= ~MOD_MASK_SHIFT;
    }

    
    if ((modifiers & MOD_MASK_CTRL) && ASCII_ISALPHA(key))
	key = TOUPPER_ASC(key);

    if (simplify && (modifiers & MOD_MASK_CTRL)
	    && ((key >= '?' && key <= '_') || ASCII_ISALPHA(key)))
    {
	key = Ctrl_chr(key);
	modifiers &= ~MOD_MASK_CTRL;
	
	if (key == NUL)
	    key = K_ZERO;
	if (did_simplify != NULL)
	    *did_simplify = TRUE;
    }


    
    if (!(modifiers & MOD_MASK_CMD))

    if (simplify && (modifiers & MOD_MASK_ALT) && key < 0x80 && !enc_dbcs)
    {
	key |= 0x80;
	modifiers &= ~MOD_MASK_ALT;	
	if (did_simplify != NULL)
	    *did_simplify = TRUE;
    }

    *modp = modifiers;
    return key;
}


    int find_special_key_in_table(int c)
{
    int	    i;

    for (i = 0; key_names_table[i].name != NULL; i++)
	if (c == key_names_table[i].key)
	    break;
    if (key_names_table[i].name == NULL)
	i = -1;
    return i;
}


    int get_special_key_code(char_u *name)
{
    char_u  *table_name;
    char_u  string[3];
    int	    i, j;

    
    if (name[0] == 't' && name[1] == '_' && name[2] != NUL && name[3] != NUL)
    {
	string[0] = name[2];
	string[1] = name[3];
	string[2] = NUL;
	if (add_termcap_entry(string, FALSE) == OK)
	    return TERMCAP2KEY(name[2], name[3]);
    }
    else for (i = 0; key_names_table[i].name != NULL; i++)
	{
	    table_name = key_names_table[i].name;
	    for (j = 0; vim_isNormalIDc(name[j]) && table_name[j] != NUL; j++)
		if (TOLOWER_ASC(table_name[j]) != TOLOWER_ASC(name[j]))
		    break;
	    if (!vim_isNormalIDc(name[j]) && table_name[j] == NUL)
		return key_names_table[i].key;
	}
    return 0;
}

    char_u * get_key_name(int i)
{
    if (i >= (int)KEY_NAMES_TABLE_LEN)
	return NULL;
    return  key_names_table[i].name;
}


    int get_fileformat(buf_T *buf)
{
    int		c = *buf->b_p_ff;

    if (buf->b_p_bin || c == 'u')
	return EOL_UNIX;
    if (c == 'm')
	return EOL_MAC;
    return EOL_DOS;
}


    int get_fileformat_force( buf_T	*buf, exarg_T	*eap)


{
    int		c;

    if (eap != NULL && eap->force_ff != 0)
	c = eap->force_ff;
    else {
	if ((eap != NULL && eap->force_bin != 0)
			       ? (eap->force_bin == FORCE_BIN) : buf->b_p_bin)
	    return EOL_UNIX;
	c = *buf->b_p_ff;
    }
    if (c == 'u')
	return EOL_UNIX;
    if (c == 'm')
	return EOL_MAC;
    return EOL_DOS;
}


    void set_fileformat( int		t, int		opt_flags)


{
    char	*p = NULL;

    switch (t)
    {
    case EOL_DOS:
	p = FF_DOS;
	curbuf->b_p_tx = TRUE;
	break;
    case EOL_UNIX:
	p = FF_UNIX;
	curbuf->b_p_tx = FALSE;
	break;
    case EOL_MAC:
	p = FF_MAC;
	curbuf->b_p_tx = FALSE;
	break;
    }
    if (p != NULL)
	set_string_option_direct((char_u *)"ff", -1, (char_u *)p, OPT_FREE | opt_flags, 0);

    
    check_status(curbuf);
    redraw_tabline = TRUE;
    need_maketitle = TRUE;	    
}


    int default_fileformat(void)
{
    switch (*p_ffs)
    {
	case 'm':   return EOL_MAC;
	case 'd':   return EOL_DOS;
    }
    return EOL_UNIX;
}


    int call_shell(char_u *cmd, int opt)
{
    char_u	*ncmd;
    int		retval;

    proftime_T	wait_time;


    if (p_verbose > 3)
    {
	verbose_enter();
	smsg(_("Calling shell to execute: \"%s\""), cmd == NULL ? p_sh : cmd);
	out_char('\n');
	cursor_on();
	verbose_leave();
    }


    if (do_profiling == PROF_YES)
	prof_child_enter(&wait_time);


    if (*p_sh == NUL)
    {
	emsg(_(e_shell_option_is_empty));
	retval = -1;
    }
    else {

	
	gui_mch_mousehide(FALSE);


	++hold_gui_events;

	
	tag_freematch();

	if (cmd == NULL || *p_sxq == NUL)
	    retval = mch_call_shell(cmd, opt);
	else {
	    char_u *ecmd = cmd;

	    if (*p_sxe != NUL && *p_sxq == '(')
	    {
		ecmd = vim_strsave_escaped_ext(cmd, p_sxe, '^', FALSE);
		if (ecmd == NULL)
		    ecmd = cmd;
	    }
	    ncmd = alloc(STRLEN(ecmd) + STRLEN(p_sxq) * 2 + 1);
	    if (ncmd != NULL)
	    {
		STRCPY(ncmd, p_sxq);
		STRCAT(ncmd, ecmd);
		
		
		STRCAT(ncmd, *p_sxq == '(' ? (char_u *)")" : *p_sxq == '"' && *(p_sxq+1) == '(' ? (char_u *)")\"" : p_sxq);

		retval = mch_call_shell(ncmd, opt);
		vim_free(ncmd);
	    }
	    else retval = -1;
	    if (ecmd != cmd)
		vim_free(ecmd);
	}

	--hold_gui_events;

	
	shell_resized_check();
    }


    set_vim_var_nr(VV_SHELL_ERROR, (long)retval);

    if (do_profiling == PROF_YES)
	prof_child_exit(&wait_time);



    return retval;
}


    int get_real_state(void)
{
    if (State & MODE_NORMAL)
    {
	if (VIsual_active)
	{
	    if (VIsual_select)
		return MODE_SELECT;
	    return MODE_VISUAL;
	}
	else if (finish_op)
	    return MODE_OP_PENDING;
    }
    return State;
}


    int after_pathsep(char_u *b, char_u *p)
{
    return p > b && vim_ispathsep(p[-1])
			     && (!has_mbyte || (*mb_head_off)(b, p - 1) == 0);
}


    int same_directory(char_u *f1, char_u *f2)
{
    char_u	ffname[MAXPATHL];
    char_u	*t1;
    char_u	*t2;

    
    if (f1 == NULL || f2 == NULL)
	return FALSE;

    (void)vim_FullName(f1, ffname, MAXPATHL, FALSE);
    t1 = gettail_sep(ffname);
    t2 = gettail_sep(f2);
    return (t1 - ffname == t2 - f2 && pathcmp((char *)ffname, (char *)f2, (int)(t1 - ffname)) == 0);
}





    int vim_chdirfile(char_u *fname, char *trigger_autocmd)
{
    char_u	old_dir[MAXPATHL];
    char_u	new_dir[MAXPATHL];

    if (mch_dirname(old_dir, MAXPATHL) != OK)
	*old_dir = NUL;

    vim_strncpy(new_dir, fname, MAXPATHL - 1);
    *gettail_sep(new_dir) = NUL;

    if (pathcmp((char *)old_dir, (char *)new_dir, -1) == 0)
	
	return OK;

    if (trigger_autocmd != NULL)
	trigger_DirChangedPre((char_u *)trigger_autocmd, new_dir);

    if (mch_chdir((char *)new_dir) != 0)
	return FAIL;

    if (trigger_autocmd != NULL)
	apply_autocmds(EVENT_DIRCHANGED, (char_u *)trigger_autocmd, new_dir, FALSE, curbuf);
    return OK;
}




    static int illegal_slash(const char *name)
{
    if (name[0] == NUL)
	return FALSE;	    
    if (name[strlen(name) - 1] != '/')
	return FALSE;	    
    if (mch_isdir((char_u *)name))
	return FALSE;	    
    return TRUE;
}


    int vim_stat(const char *name, stat_T *stp)
{
    
    
    return illegal_slash(name) ? -1 : stat(name, stp);
}






cursorentry_T shape_table[SHAPE_IDX_COUNT] = {
    
    
    
    {0,	0, 0, 700L, 400L, 250L, 0, 0, "n", SHAPE_CURSOR+SHAPE_MOUSE}, {0,	0, 0, 700L, 400L, 250L, 0, 0, "v", SHAPE_CURSOR+SHAPE_MOUSE}, {0,	0, 0, 700L, 400L, 250L, 0, 0, "i", SHAPE_CURSOR+SHAPE_MOUSE}, {0,	0, 0, 700L, 400L, 250L, 0, 0, "r", SHAPE_CURSOR+SHAPE_MOUSE}, {0,	0, 0, 700L, 400L, 250L, 0, 0, "c", SHAPE_CURSOR+SHAPE_MOUSE}, {0,	0, 0, 700L, 400L, 250L, 0, 0, "ci", SHAPE_CURSOR+SHAPE_MOUSE}, {0,	0, 0, 700L, 400L, 250L, 0, 0, "cr", SHAPE_CURSOR+SHAPE_MOUSE}, {0,	0, 0, 700L, 400L, 250L, 0, 0, "o", SHAPE_CURSOR+SHAPE_MOUSE}, {0,	0, 0, 700L, 400L, 250L, 0, 0, "ve", SHAPE_CURSOR+SHAPE_MOUSE}, {0,	0, 0,   0L,   0L,   0L, 0, 0, "e", SHAPE_MOUSE}, {0,	0, 0,   0L,   0L,   0L, 0, 0, "s", SHAPE_MOUSE}, {0,	0, 0,   0L,   0L,   0L, 0, 0, "sd", SHAPE_MOUSE}, {0,	0, 0,   0L,   0L,   0L, 0, 0, "vs", SHAPE_MOUSE}, {0,	0, 0,   0L,   0L,   0L, 0, 0, "vd", SHAPE_MOUSE}, {0,	0, 0,   0L,   0L,   0L, 0, 0, "m", SHAPE_MOUSE}, {0,	0, 0,   0L,   0L,   0L, 0, 0, "ml", SHAPE_MOUSE}, {0,	0, 0, 100L, 100L, 100L, 0, 0, "sm", SHAPE_CURSOR}, };



















static char * mshape_names[] = {
    "arrow",	 "blank", "beam", "updown", "udsizing", "leftright", "lrsizing", "busy", "no", "crosshair", "hand1", "hand2", "pencil", "question", "rightup-arrow", "up-arrow", NULL };



















    char * parse_shape_opt(int what)
{
    char_u	*modep;
    char_u	*colonp;
    char_u	*commap;
    char_u	*slashp;
    char_u	*p, *endp;
    int		idx = 0;		
    int		all_idx;
    int		len;
    int		i;
    long	n;
    int		found_ve = FALSE;	
    int		round;

    
    for (round = 1; round <= 2; ++round)
    {
	

	if (what == SHAPE_MOUSE)
	    modep = p_mouseshape;
	else  modep = p_guicursor;

	while (*modep != NUL)
	{
	    colonp = vim_strchr(modep, ':');
	    commap = vim_strchr(modep, ',');

	    if (colonp == NULL || (commap != NULL && commap < colonp))
		return e_missing_colon_2;
	    if (colonp == modep)
		return e_illegal_mode;

	    
	    all_idx = -1;
	    while (modep < colonp || all_idx >= 0)
	    {
		if (all_idx < 0)
		{
		    
		    if (modep[1] == '-' || modep[1] == ':')
			len = 1;
		    else len = 2;
		    if (len == 1 && TOLOWER_ASC(modep[0]) == 'a')
			all_idx = SHAPE_IDX_COUNT - 1;
		    else {
			for (idx = 0; idx < SHAPE_IDX_COUNT; ++idx)
			    if (STRNICMP(modep, shape_table[idx].name, len)
									 == 0)
				break;
			if (idx == SHAPE_IDX_COUNT || (shape_table[idx].used_for & what) == 0)
			    return e_illegal_mode;
			if (len == 2 && modep[0] == 'v' && modep[1] == 'e')
			    found_ve = TRUE;
		    }
		    modep += len + 1;
		}

		if (all_idx >= 0)
		    idx = all_idx--;
		else if (round == 2)
		{

		    if (what == SHAPE_MOUSE)
		    {
			
			shape_table[idx].mshape = 0;
		    }
		    else  {

			
			shape_table[idx].shape = SHAPE_BLOCK;
			shape_table[idx].blinkwait = 700L;
			shape_table[idx].blinkon = 400L;
			shape_table[idx].blinkoff = 250L;
		    }
		}

		
		for (p = colonp + 1; *p && *p != ','; )
		{

		    if (what == SHAPE_MOUSE)
		    {
			for (i = 0; ; ++i)
			{
			    if (mshape_names[i] == NULL)
			    {
				if (!VIM_ISDIGIT(*p))
				    return e_illegal_mouseshape;
				if (round == 2)
				    shape_table[idx].mshape = getdigits(&p) + MSHAPE_NUMBERED;
				else (void)getdigits(&p);
				break;
			    }
			    len = (int)STRLEN(mshape_names[i]);
			    if (STRNICMP(p, mshape_names[i], len) == 0)
			    {
				if (round == 2)
				    shape_table[idx].mshape = i;
				p += len;
				break;
			    }
			}
		    }
		    else   {

			
			i = *p;
			len = 0;
			if (STRNICMP(p, "ver", 3) == 0)
			    len = 3;
			else if (STRNICMP(p, "hor", 3) == 0)
			    len = 3;
			else if (STRNICMP(p, "blinkwait", 9) == 0)
			    len = 9;
			else if (STRNICMP(p, "blinkon", 7) == 0)
			    len = 7;
			else if (STRNICMP(p, "blinkoff", 8) == 0)
			    len = 8;
			if (len != 0)
			{
			    p += len;
			    if (!VIM_ISDIGIT(*p))
				return e_digit_expected;
			    n = getdigits(&p);
			    if (len == 3)   
			    {
				if (n == 0)
				    return e_illegal_percentage;
				if (round == 2)
				{
				    if (TOLOWER_ASC(i) == 'v')
					shape_table[idx].shape = SHAPE_VER;
				    else shape_table[idx].shape = SHAPE_HOR;
				    shape_table[idx].percentage = n;
				}
			    }
			    else if (round == 2)
			    {
				if (len == 9)
				    shape_table[idx].blinkwait = n;
				else if (len == 7)
				    shape_table[idx].blinkon = n;
				else shape_table[idx].blinkoff = n;
			    }
			}
			else if (STRNICMP(p, "block", 5) == 0)
			{
			    if (round == 2)
				shape_table[idx].shape = SHAPE_BLOCK;
			    p += 5;
			}
			else	 {
			    endp = vim_strchr(p, '-');
			    if (commap == NULL)		    
			    {
				if (endp == NULL)
				    endp = p + STRLEN(p);   
			    }
			    else if (endp > commap || endp == NULL)
				endp = commap;
			    slashp = vim_strchr(p, '/');
			    if (slashp != NULL && slashp < endp)
			    {
				
				i = syn_check_group(p, (int)(slashp - p));
				p = slashp + 1;
			    }
			    if (round == 2)
			    {
				shape_table[idx].id = syn_check_group(p, (int)(endp - p));
				shape_table[idx].id_lm = shape_table[idx].id;
				if (slashp != NULL && slashp < endp)
				    shape_table[idx].id = i;
			    }
			    p = endp;
			}
		    } 

		    if (*p == '-')
			++p;
		}
	    }
	    modep = p;
	    if (*modep == ',')
		++modep;
	}
    }

    
    if (!found_ve)
    {

	if (what == SHAPE_MOUSE)
	{
	    shape_table[SHAPE_IDX_VE].mshape = shape_table[SHAPE_IDX_V].mshape;
	}
	else  {

	    shape_table[SHAPE_IDX_VE].shape = shape_table[SHAPE_IDX_V].shape;
	    shape_table[SHAPE_IDX_VE].percentage = shape_table[SHAPE_IDX_V].percentage;
	    shape_table[SHAPE_IDX_VE].blinkwait = shape_table[SHAPE_IDX_V].blinkwait;
	    shape_table[SHAPE_IDX_VE].blinkon = shape_table[SHAPE_IDX_V].blinkon;
	    shape_table[SHAPE_IDX_VE].blinkoff = shape_table[SHAPE_IDX_V].blinkoff;
	    shape_table[SHAPE_IDX_VE].id = shape_table[SHAPE_IDX_V].id;
	    shape_table[SHAPE_IDX_VE].id_lm = shape_table[SHAPE_IDX_V].id_lm;
	}
    }

    return NULL;
}



    int get_shape_idx(int mouse)
{

    if (mouse && (State == MODE_HITRETURN || State == MODE_ASKMORE))
    {

	int x, y;
	gui_mch_getmouse(&x, &y);
	if (Y_2_ROW(y) == Rows - 1)
	    return SHAPE_IDX_MOREL;

	return SHAPE_IDX_MORE;
    }
    if (mouse && drag_status_line)
	return SHAPE_IDX_SDRAG;
    if (mouse && drag_sep_line)
	return SHAPE_IDX_VDRAG;

    if (!mouse && State == MODE_SHOWMATCH)
	return SHAPE_IDX_SM;
    if (State & VREPLACE_FLAG)
	return SHAPE_IDX_R;
    if (State & REPLACE_FLAG)
	return SHAPE_IDX_R;
    if (State & MODE_INSERT)
	return SHAPE_IDX_I;
    if (State & MODE_CMDLINE)
    {
	if (cmdline_at_end())
	    return SHAPE_IDX_C;
	if (cmdline_overstrike())
	    return SHAPE_IDX_CR;
	return SHAPE_IDX_CI;
    }
    if (finish_op)
	return SHAPE_IDX_O;
    if (VIsual_active)
    {
	if (*p_sel == 'e')
	    return SHAPE_IDX_VE;
	else return SHAPE_IDX_V;
    }
    return SHAPE_IDX_N;
}



static int old_mouse_shape = 0;


    void update_mouseshape(int shape_idx)
{
    int new_mouse_shape;

    
    if (!gui.in_use || gui.starting)
	return;

    
    
    if (shape_idx == -1 && char_avail())
    {
	postponed_mouseshape = TRUE;
	return;
    }

    
    if (*p_mouse == NUL && (shape_idx == SHAPE_IDX_CLINE || shape_idx == SHAPE_IDX_STATUS || shape_idx == SHAPE_IDX_VSEP))


	shape_idx = -2;

    if (shape_idx == -2 && old_mouse_shape != shape_table[SHAPE_IDX_CLINE].mshape && old_mouse_shape != shape_table[SHAPE_IDX_STATUS].mshape && old_mouse_shape != shape_table[SHAPE_IDX_VSEP].mshape)


	return;
    if (shape_idx < 0)
	new_mouse_shape = shape_table[get_shape_idx(TRUE)].mshape;
    else new_mouse_shape = shape_table[shape_idx].mshape;
    if (new_mouse_shape != old_mouse_shape)
    {
	mch_set_mouse_shape(new_mouse_shape);
	old_mouse_shape = new_mouse_shape;
    }
    postponed_mouseshape = FALSE;
}






    int vim_chdir(char_u *new_dir)
{

    return mch_chdir((char *)new_dir);

    char_u	*dir_name;
    int		r;

    dir_name = find_directory_in_path(new_dir, (int)STRLEN(new_dir), FNAME_MESS, curbuf->b_ffname);
    if (dir_name == NULL)
	return -1;
    r = mch_chdir((char *)dir_name);
    vim_free(dir_name);
    return r;

}


    int get_user_name(char_u *buf, int len)
{
    if (username == NULL)
    {
	if (mch_get_user_name(buf, len) == FAIL)
	    return FAIL;
	username = vim_strsave(buf);
    }
    else vim_strncpy(buf, username, len - 1);
    return OK;
}



    void free_username(void)
{
    vim_free(username);
}




    void qsort( void	*base, size_t	elm_count, size_t	elm_size, int (*cmp)(const void *, const void *))




{
    char_u	*buf;
    char_u	*p1;
    char_u	*p2;
    int		i, j;
    int		gap;

    buf = alloc(elm_size);
    if (buf == NULL)
	return;

    for (gap = elm_count / 2; gap > 0; gap /= 2)
	for (i = gap; i < elm_count; ++i)
	    for (j = i - gap; j >= 0; j -= gap)
	    {
		
		p1 = (char_u *)base + j * elm_size;
		p2 = (char_u *)base + (j + gap) * elm_size;
		if ((*cmp)((void *)p1, (void *)p2) <= 0)
		    break;
		
		mch_memmove(buf, p1, elm_size);
		mch_memmove(p1, p2, elm_size);
		mch_memmove(p2, buf, elm_size);
	    }

    vim_free(buf);
}










static int  envsize = -1;	
extern char **environ;		

static int  findenv(char *name); 
static int  newenv(void);	
static int  moreenv(void);	

    int putenv(const char *string)
{
    int	    i;
    char    *p;

    if (envsize < 0)
    {				
	if (newenv() < 0)	
	    return -1;
    }

    i = findenv((char *)string); 

    if (i < 0)
    {				
	for (i = 0; environ[i]; i++);
	if (i >= (envsize - 1))
	{			
	    if (moreenv() < 0)
		return -1;
	}
	p = alloc(strlen(string) + 1);
	if (p == NULL)		
	    return -1;
	environ[i + 1] = 0;	
    }
    else {
	p = vim_realloc(environ[i], strlen(string) + 1);
	if (p == NULL)
	    return -1;
    }
    sprintf(p, "%s", string);	
    environ[i] = p;

    return 0;
}

    static int findenv(char *name)
{
    char    *namechar, *envchar;
    int	    i, found;

    found = 0;
    for (i = 0; environ[i] && !found; i++)
    {
	envchar = environ[i];
	namechar = name;
	while (*namechar && *namechar != '=' && (*namechar == *envchar))
	{
	    namechar++;
	    envchar++;
	}
	found = ((*namechar == '\0' || *namechar == '=') && *envchar == '=');
    }
    return found ? i - 1 : -1;
}

    static int newenv(void)
{
    char    **env, *elem;
    int	    i, esize;

    for (i = 0; environ[i]; i++)
	;

    esize = i + EXTRASIZE + 1;
    env = ALLOC_MULT(char *, esize);
    if (env == NULL)
	return -1;

    for (i = 0; environ[i]; i++)
    {
	elem = alloc(strlen(environ[i]) + 1);
	if (elem == NULL)
	    return -1;
	env[i] = elem;
	strcpy(elem, environ[i]);
    }

    env[i] = 0;
    environ = env;
    envsize = esize;
    return 0;
}

    static int moreenv(void)
{
    int	    esize;
    char    **env;

    esize = envsize + EXTRASIZE;
    env = vim_realloc((char *)environ, esize * sizeof (*env));
    if (env == 0)
	return -1;
    environ = env;
    envsize = esize;
    return 0;
}



    char_u * vimpty_getenv(const char_u *string)
{
    int i;
    char_u *p;

    if (envsize < 0)
	return NULL;

    i = findenv((char *)string);

    if (i < 0)
	return NULL;

    p = vim_strchr((char_u *)environ[i], '=');
    return (p + 1);
}






    int filewritable(char_u *fname)
{
    int		retval = 0;

    int		perm = 0;



    perm = mch_getperm(fname);

    if (  mch_writable(fname) &&   (perm & 0222) &&   mch_access((char *)fname, W_OK) == 0 )








    {
	++retval;
	if (mch_isdir(fname))
	    ++retval;
    }
    return retval;
}




    int get2c(FILE *fd)
{
    int		c, n;

    n = getc(fd);
    if (n == EOF) return -1;
    c = getc(fd);
    if (c == EOF) return -1;
    return (n << 8) + c;
}


    int get3c(FILE *fd)
{
    int		c, n;

    n = getc(fd);
    if (n == EOF) return -1;
    c = getc(fd);
    if (c == EOF) return -1;
    n = (n << 8) + c;
    c = getc(fd);
    if (c == EOF) return -1;
    return (n << 8) + c;
}


    int get4c(FILE *fd)
{
    int		c;
    
    
    unsigned	n;

    c = getc(fd);
    if (c == EOF) return -1;
    n = (unsigned)c;
    c = getc(fd);
    if (c == EOF) return -1;
    n = (n << 8) + (unsigned)c;
    c = getc(fd);
    if (c == EOF) return -1;
    n = (n << 8) + (unsigned)c;
    c = getc(fd);
    if (c == EOF) return -1;
    n = (n << 8) + (unsigned)c;
    return (int)n;
}


    char_u * read_string(FILE *fd, int cnt)
{
    char_u	*str;
    int		i;
    int		c;

    
    str = alloc(cnt + 1);
    if (str != NULL)
    {
	
	for (i = 0; i < cnt; ++i)
	{
	    c = getc(fd);
	    if (c == EOF)
	    {
		vim_free(str);
		return NULL;
	    }
	    str[i] = c;
	}
	str[i] = NUL;
    }
    return str;
}


    int put_bytes(FILE *fd, long_u nr, int len)
{
    int	    i;

    for (i = len - 1; i >= 0; --i)
	if (putc((int)(nr >> (i * 8)), fd) == EOF)
	    return FAIL;
    return OK;
}






    long elapsed(struct timeval *start_tv)
{
    struct timeval  now_tv;

    gettimeofday(&now_tv, NULL);
    return (now_tv.tv_sec - start_tv->tv_sec) * 1000L + (now_tv.tv_usec - start_tv->tv_usec) / 1000L;
}




    long elapsed(DWORD start_tick)
{
    DWORD	now = GetTickCount();

    return (long)now - (long)start_tick;
}







    int mch_parse_cmd(char_u *cmd, int use_shcf, char ***argv, int *argc)
{
    int		i;
    char_u	*p, *d;
    int		inquote;

    
    for (i = 1; i <= 2; ++i)
    {
	p = skipwhite(cmd);
	inquote = FALSE;
	*argc = 0;
	while (*p != NUL)
	{
	    if (i == 2)
		(*argv)[*argc] = (char *)p;
	    ++*argc;
	    d = p;
	    while (*p != NUL && (inquote || (*p != ' ' && *p != TAB)))
	    {
		if (p[0] == '"')
		    
		    inquote = !inquote;
		else {
		    if (rem_backslash(p))
		    {
			
			
			++p;
		    }
		    if (i == 2)
			*d++ = *p;
		}
		++p;
	    }
	    if (*p == NUL)
	    {
		if (i == 2)
		    *d++ = NUL;
		break;
	    }
	    if (i == 2)
		*d++ = NUL;
	    p = skipwhite(p + 1);
	}
	if (*argv == NULL)
	{
	    if (use_shcf)
	    {
		
		p = p_shcf;
		for (;;)
		{
		    p = skiptowhite(p);
		    if (*p == NUL)
			break;
		    ++*argc;
		    p = skipwhite(p);
		}
	    }

	    *argv = ALLOC_MULT(char *, *argc + 4);
	    if (*argv == NULL)	    
		return FAIL;
	}
    }
    return OK;
}


    int build_argv_from_string(char_u *cmd, char ***argv, int *argc)
{
    char_u	*cmd_copy;
    int		i;

    
    cmd_copy = vim_strsave(cmd);
    if (cmd_copy == NULL || mch_parse_cmd(cmd_copy, FALSE, argv, argc) == FAIL)
    {
	vim_free(cmd_copy);
	return FAIL;
    }
    for (i = 0; i < *argc; i++)
	(*argv)[i] = (char *)vim_strsave((char_u *)(*argv)[i]);
    (*argv)[*argc] = NULL;
    vim_free(cmd_copy);
    return OK;
}



    int build_argv_from_list(list_T *l, char ***argv, int *argc)
{
    listitem_T  *li;
    char_u	*s;

    
    *argv = ALLOC_MULT(char *, l->lv_len + 1);
    if (*argv == NULL)
	return FAIL;
    *argc = 0;
    FOR_ALL_LIST_ITEMS(l, li)
    {
	s = tv_get_string_chk(&li->li_tv);
	if (s == NULL)
	{
	    int i;

	    for (i = 0; i < *argc; ++i)
		VIM_CLEAR((*argv)[i]);
	    (*argv)[0] = NULL;
	    return FAIL;
	}
	(*argv)[*argc] = (char *)vim_strsave(s);
	*argc += 1;
    }
    (*argv)[*argc] = NULL;
    return OK;
}




    int get_special_pty_type(void)
{

    return get_conpty_type();

    return 0;

}
