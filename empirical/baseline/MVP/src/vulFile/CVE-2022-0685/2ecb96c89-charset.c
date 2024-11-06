






static int win_nolbr_chartabsize(win_T *wp, char_u *s, colnr_T col, int *headp);

static unsigned nr2hex(unsigned c);

static int    chartab_initialized = FALSE;








static char_u	g_chartab[256];







static int in_win_border(win_T *wp, colnr_T vcol);


    int init_chartab(void)
{
    return buf_init_chartab(curbuf, TRUE);
}

    int buf_init_chartab( buf_T	*buf, int		global)


{
    int		c;
    int		c2;
    char_u	*p;
    int		i;
    int		tilde;
    int		do_isalpha;

    if (global)
    {
	
	c = 0;
	while (c < ' ')
	    g_chartab[c++] = (dy_flags & DY_UHEX) ? 4 : 2;
	while (c <= '~')
	    g_chartab[c++] = 1 + CT_PRINT_CHAR;
	while (c < 256)
	{
	    
	    if (enc_utf8 && c >= 0xa0)
		g_chartab[c++] = CT_PRINT_CHAR + 1;
	    
	    else if (enc_dbcs == DBCS_JPNU && c == 0x8e)
		g_chartab[c++] = CT_PRINT_CHAR + 1;
	    
	    else if (enc_dbcs != 0 && MB_BYTE2LEN(c) == 2)
		g_chartab[c++] = CT_PRINT_CHAR + 2;
	    else  g_chartab[c++] = (dy_flags & DY_UHEX) ? 4 : 2;

	}

	
	for (c = 1; c < 256; ++c)
	    if ((enc_dbcs != 0 && MB_BYTE2LEN(c) > 1)
		    || (enc_dbcs == DBCS_JPNU && c == 0x8e)
		    || (enc_utf8 && c >= 0xa0))
		g_chartab[c] |= CT_FNAME_CHAR;
    }

    
    CLEAR_FIELD(buf->b_chartab);
    if (enc_dbcs != 0)
	for (c = 0; c < 256; ++c)
	{
	    
	    if (MB_BYTE2LEN(c) == 2)
		SET_CHARTAB(buf, c);
	}


    
    if (buf->b_p_lisp)
	SET_CHARTAB(buf, '-');


    
    
    
    for (i = global ? 0 : 3; i <= 3; ++i)
    {
	if (i == 0)
	    p = p_isi;		
	else if (i == 1)
	    p = p_isp;		
	else if (i == 2)
	    p = p_isf;		
	else	 p = buf->b_p_isk;

	while (*p)
	{
	    tilde = FALSE;
	    do_isalpha = FALSE;
	    if (*p == '^' && p[1] != NUL)
	    {
		tilde = TRUE;
		++p;
	    }
	    if (VIM_ISDIGIT(*p))
		c = getdigits(&p);
	    else if (has_mbyte)
		c = mb_ptr2char_adv(&p);
	    else c = *p++;
	    c2 = -1;
	    if (*p == '-' && p[1] != NUL)
	    {
		++p;
		if (VIM_ISDIGIT(*p))
		    c2 = getdigits(&p);
		else if (has_mbyte)
		    c2 = mb_ptr2char_adv(&p);
		else c2 = *p++;
	    }
	    if (c <= 0 || c >= 256 || (c2 < c && c2 != -1) || c2 >= 256 || !(*p == NUL || *p == ','))
		return FAIL;

	    if (c2 == -1)	
	    {
		
		if (c == '@')
		{
		    do_isalpha = TRUE;
		    c = 1;
		    c2 = 255;
		}
		else c2 = c;
	    }
	    while (c <= c2)
	    {
		
		
		
		if (!do_isalpha || MB_ISLOWER(c) || MB_ISUPPER(c))
		{
		    if (i == 0)			
		    {
			if (tilde)
			    g_chartab[c] &= ~CT_ID_CHAR;
			else g_chartab[c] |= CT_ID_CHAR;
		    }
		    else if (i == 1)		
		    {
			if ((c < ' ' || c > '~'   ) && !(enc_dbcs && MB_BYTE2LEN(c) == 2))


			{
			    if (tilde)
			    {
				g_chartab[c] = (g_chartab[c] & ~CT_CELL_MASK)
					     + ((dy_flags & DY_UHEX) ? 4 : 2);
				g_chartab[c] &= ~CT_PRINT_CHAR;
			    }
			    else {
				g_chartab[c] = (g_chartab[c] & ~CT_CELL_MASK) + 1;
				g_chartab[c] |= CT_PRINT_CHAR;
			    }
			}
		    }
		    else if (i == 2)		
		    {
			if (tilde)
			    g_chartab[c] &= ~CT_FNAME_CHAR;
			else g_chartab[c] |= CT_FNAME_CHAR;
		    }
		    else  {
			if (tilde)
			    RESET_CHARTAB(buf, c);
			else SET_CHARTAB(buf, c);
		    }
		}
		++c;
	    }

	    c = *p;
	    p = skip_to_option_part(p);
	    if (c == ',' && *p == NUL)
		
		return FAIL;
	}
    }
    chartab_initialized = TRUE;
    return OK;
}


    void trans_characters( char_u	*buf, int		bufsize)


{
    int		len;		
    int		room;		
    char_u	*trs;		
    int		trs_len;	

    len = (int)STRLEN(buf);
    room = bufsize - len;
    while (*buf != 0)
    {
	
	if (has_mbyte && (trs_len = (*mb_ptr2len)(buf)) > 1)
	    len -= trs_len;
	else {
	    trs = transchar_byte(*buf);
	    trs_len = (int)STRLEN(trs);
	    if (trs_len > 1)
	    {
		room -= trs_len - 1;
		if (room <= 0)
		    return;
		mch_memmove(buf + trs_len, buf + 1, (size_t)len);
	    }
	    mch_memmove(buf, trs, (size_t)trs_len);
	    --len;
	}
	buf += trs_len;
    }
}


    char_u * transstr(char_u *s)
{
    char_u	*res;
    char_u	*p;
    int		l, len, c;
    char_u	hexbuf[11];

    if (has_mbyte)
    {
	
	
	len = 0;
	p = s;
	while (*p != NUL)
	{
	    if ((l = (*mb_ptr2len)(p)) > 1)
	    {
		c = (*mb_ptr2char)(p);
		p += l;
		if (vim_isprintc(c))
		    len += l;
		else {
		    transchar_hex(hexbuf, c);
		    len += (int)STRLEN(hexbuf);
		}
	    }
	    else {
		l = byte2cells(*p++);
		if (l > 0)
		    len += l;
		else len += 4;
	    }
	}
	res = alloc(len + 1);
    }
    else res = alloc(vim_strsize(s) + 1);
    if (res != NULL)
    {
	*res = NUL;
	p = s;
	while (*p != NUL)
	{
	    if (has_mbyte && (l = (*mb_ptr2len)(p)) > 1)
	    {
		c = (*mb_ptr2char)(p);
		if (vim_isprintc(c))
		    STRNCAT(res, p, l);	
		else transchar_hex(res + STRLEN(res), c);
		p += l;
	    }
	    else STRCAT(res, transchar_byte(*p++));
	}
    }
    return res;
}


    char_u * str_foldcase( char_u	*str, int		orglen, char_u	*buf, int		buflen)




{
    garray_T	ga;
    int		i;
    int		len = orglen;






    
    if (buf == NULL)
    {
	ga_init2(&ga, 1, 10);
	if (ga_grow(&ga, len + 1) == FAIL)
	    return NULL;
	mch_memmove(ga.ga_data, str, (size_t)len);
	ga.ga_len = len;
    }
    else {
	if (len >= buflen)	    
	    len = buflen - 1;
	mch_memmove(buf, str, (size_t)len);
    }
    if (buf == NULL)
	GA_CHAR(len) = NUL;
    else buf[len] = NUL;

    
    i = 0;
    while (STR_CHAR(i) != NUL)
    {
	if (enc_utf8 || (has_mbyte && MB_BYTE2LEN(STR_CHAR(i)) > 1))
	{
	    if (enc_utf8)
	    {
		int	c = utf_ptr2char(STR_PTR(i));
		int	olen = utf_ptr2len(STR_PTR(i));
		int	lc = utf_tolower(c);

		
		
		
		if ((c < 0x80 || olen > 1) && c != lc)
		{
		    int	    nlen = utf_char2len(lc);

		    
		    
		    if (olen != nlen)
		    {
			if (nlen > olen)
			{
			    if (buf == NULL ? ga_grow(&ga, nlen - olen + 1) == FAIL : len + nlen - olen >= buflen)

			    {
				
				lc = c;
				nlen = olen;
			    }
			}
			if (olen != nlen)
			{
			    if (buf == NULL)
			    {
				STRMOVE(GA_PTR(i) + nlen, GA_PTR(i) + olen);
				ga.ga_len += nlen - olen;
			    }
			    else {
				STRMOVE(buf + i + nlen, buf + i + olen);
				len += nlen - olen;
			    }
			}
		    }
		    (void)utf_char2bytes(lc, STR_PTR(i));
		}
	    }
	    
	    i += (*mb_ptr2len)(STR_PTR(i));
	}
	else {
	    if (buf == NULL)
		GA_CHAR(i) = TOLOWER_LOC(GA_CHAR(i));
	    else buf[i] = TOLOWER_LOC(buf[i]);
	    ++i;
	}
    }

    if (buf == NULL)
	return (char_u *)ga.ga_data;
    return buf;
}


static char_u	transchar_charbuf[7];

    char_u * transchar(int c)
{
    return transchar_buf(curbuf, c);
}

    char_u * transchar_buf(buf_T *buf, int c)
{
    int			i;

    i = 0;
    if (IS_SPECIAL(c))	    
    {
	transchar_charbuf[0] = '~';
	transchar_charbuf[1] = '@';
	i = 2;
	c = K_SECOND(c);
    }

    if ((!chartab_initialized && ((c >= ' ' && c <= '~')))
					|| (c < 256 && vim_isprintc_strict(c)))
    {
	
	transchar_charbuf[i] = c;
	transchar_charbuf[i + 1] = NUL;
    }
    else transchar_nonprint(buf, transchar_charbuf + i, c);
    return transchar_charbuf;
}


    char_u * transchar_byte(int c)
{
    if (enc_utf8 && c >= 0x80)
    {
	transchar_nonprint(curbuf, transchar_charbuf, c);
	return transchar_charbuf;
    }
    return transchar(c);
}


    void transchar_nonprint(buf_T *buf, char_u *charbuf, int c)
{
    if (c == NL)
	c = NUL;		
    else if (c == CAR && get_fileformat(buf) == EOL_MAC)
	c = NL;			

    if (dy_flags & DY_UHEX)		
	transchar_hex(charbuf, c);

    else if (c <= 0x7f)			
    {
	charbuf[0] = '^';
	charbuf[1] = c ^ 0x40;		
	charbuf[2] = NUL;
    }
    else if (enc_utf8 && c >= 0x80)
    {
	transchar_hex(charbuf, c);
    }
    else if (c >= ' ' + 0x80 && c <= '~' + 0x80)    
    {
	charbuf[0] = '|';
	charbuf[1] = c - 0x80;
	charbuf[2] = NUL;
    }
    else					     {
	charbuf[0] = '~';
	charbuf[1] = (c - 0x80) ^ 0x40;	
	charbuf[2] = NUL;
    }
}

    void transchar_hex(char_u *buf, int c)
{
    int		i = 0;

    buf[0] = '<';
    if (c > 255)
    {
	buf[++i] = nr2hex((unsigned)c >> 12);
	buf[++i] = nr2hex((unsigned)c >> 8);
    }
    buf[++i] = nr2hex((unsigned)c >> 4);
    buf[++i] = nr2hex((unsigned)c);
    buf[++i] = '>';
    buf[++i] = NUL;
}


    static unsigned nr2hex(unsigned c)
{
    if ((c & 0xf) <= 9)
	return (c & 0xf) + '0';
    return (c & 0xf) - 10 + 'a';
}


    int byte2cells(int b)
{
    if (enc_utf8 && b >= 0x80)
	return 0;
    return (g_chartab[b] & CT_CELL_MASK);
}


    int char2cells(int c)
{
    if (IS_SPECIAL(c))
	return char2cells(K_SECOND(c)) + 2;
    if (c >= 0x80)
    {
	
	if (enc_utf8)
	    return utf_char2cells(c);
	
	
	if (enc_dbcs != 0 && c >= 0x100)
	{
	    if (enc_dbcs == DBCS_JPNU && ((unsigned)c >> 8) == 0x8e)
		return 1;
	    return 2;
	}
    }
    return (g_chartab[c & 0xff] & CT_CELL_MASK);
}


    int ptr2cells(char_u *p)
{
    
    if (enc_utf8 && *p >= 0x80)
	return utf_ptr2cells(p);
    
    return (g_chartab[*p] & CT_CELL_MASK);
}


    int vim_strsize(char_u *s)
{
    return vim_strnsize(s, (int)MAXCOL);
}


    int vim_strnsize(char_u *s, int len)
{
    int		size = 0;

    while (*s != NUL && --len >= 0)
	if (has_mbyte)
	{
	    int	    l = (*mb_ptr2len)(s);

	    size += ptr2cells(s);
	    s += l;
	    len -= l - 1;
	}
	else size += byte2cells(*s++);

    return size;
}





















    int chartabsize(char_u *p, colnr_T col)
{
    RET_WIN_BUF_CHARTABSIZE(curwin, curbuf, p, col)
}


    static int win_chartabsize(win_T *wp, char_u *p, colnr_T col)
{
    RET_WIN_BUF_CHARTABSIZE(wp, wp->w_buffer, p, col)
}



    int linetabsize(char_u *s)
{
    return linetabsize_col(0, s);
}


    int linetabsize_col(int startcol, char_u *s)
{
    colnr_T	col = startcol;
    char_u	*line = s; 

    while (*s != NUL)
	col += lbr_chartabsize_adv(line, &s, col);
    return (int)col;
}


    int win_linetabsize(win_T *wp, char_u *line, colnr_T len)
{
    colnr_T	col = 0;
    char_u	*s;

    for (s = line; *s != NUL && (len == MAXCOL || s < line + len);
								MB_PTR_ADV(s))
	col += win_lbr_chartabsize(wp, line, s, col, NULL);
    return (int)col;
}


    int vim_isIDc(int c)
{
    return (c > 0 && c < 0x100 && (g_chartab[c] & CT_ID_CHAR));
}


    int vim_isNormalIDc(int c)
{
    return ASCII_ISALNUM(c) || c == '_';
}


    int vim_iswordc(int c)
{
    return vim_iswordc_buf(c, curbuf);
}

    int vim_iswordc_buf(int c, buf_T *buf)
{
    if (c >= 0x100)
    {
	if (enc_dbcs != 0)
	    return dbcs_class((unsigned)c >> 8, (unsigned)(c & 0xff)) >= 2;
	if (enc_utf8)
	    return utf_class_buf(c, buf) >= 2;
	return FALSE;
    }
    return (c > 0 && GET_CHARTAB(buf, c) != 0);
}


    int vim_iswordp(char_u *p)
{
    return vim_iswordp_buf(p, curbuf);
}

    int vim_iswordp_buf(char_u *p, buf_T *buf)
{
    int	c = *p;

    if (has_mbyte && MB_BYTE2LEN(c) > 1)
	c = (*mb_ptr2char)(p);
    return vim_iswordc_buf(c, buf);
}


    int vim_isfilec(int c)
{
    return (c >= 0x100 || (c > 0 && (g_chartab[c] & CT_FNAME_CHAR)));
}


    int vim_isfilec_or_wc(int c)
{
    char_u buf[2];

    buf[0] = (char_u)c;
    buf[1] = NUL;
    return vim_isfilec(c) || c == ']' || mch_has_wildcard(buf);
}


    int vim_isprintc(int c)
{
    if (enc_utf8 && c >= 0x100)
	return utf_printable(c);
    return (c >= 0x100 || (c > 0 && (g_chartab[c] & CT_PRINT_CHAR)));
}


    int vim_isprintc_strict(int c)
{
    if (enc_dbcs != 0 && c < 0x100 && MB_BYTE2LEN(c) > 1)
	return FALSE;
    if (enc_utf8 && c >= 0x100)
	return utf_printable(c);
    return (c >= 0x100 || (c > 0 && (g_chartab[c] & CT_PRINT_CHAR)));
}


    int lbr_chartabsize( char_u		*line UNUSED, unsigned char	*s, colnr_T		col)



{

    if (!curwin->w_p_lbr && *get_showbreak_value(curwin) == NUL && !curwin->w_p_bri)
    {

	if (curwin->w_p_wrap)
	    return win_nolbr_chartabsize(curwin, s, col, NULL);
	RET_WIN_BUF_CHARTABSIZE(curwin, curbuf, s, col)

    }
    return win_lbr_chartabsize(curwin, line == NULL ? s : line, s, col, NULL);

}


    int lbr_chartabsize_adv( char_u	*line, char_u	**s, colnr_T	col)



{
    int		retval;

    retval = lbr_chartabsize(line, *s, col);
    MB_PTR_ADV(*s);
    return retval;
}


    int win_lbr_chartabsize( win_T	*wp, char_u	*line UNUSED, char_u	*s, colnr_T	col, int		*headp UNUSED)





{

    int		c;
    int		size;
    colnr_T	col2;
    colnr_T	col_adj = 0; 
    colnr_T	colmax;
    int		added;
    int		mb_added = 0;
    int		numberextra;
    char_u	*ps;
    int		tab_corr = (*s == TAB);
    int		n;
    char_u	*sbr;

    
    if (!wp->w_p_lbr && !wp->w_p_bri && *get_showbreak_value(wp) == NUL)

    {
	if (wp->w_p_wrap)
	    return win_nolbr_chartabsize(wp, s, col, headp);
	RET_WIN_BUF_CHARTABSIZE(wp, wp->w_buffer, s, col)
    }


    
    size = win_chartabsize(wp, s, col);
    c = *s;
    if (tab_corr)
	col_adj = size - 1;

    
    if (wp->w_p_lbr && VIM_ISBREAK(c)
	    && !VIM_ISBREAK((int)s[1])
	    && wp->w_p_wrap && wp->w_width != 0)
    {
	
	numberextra = win_col_off(wp);
	col2 = col;
	colmax = (colnr_T)(wp->w_width - numberextra - col_adj);
	if (col >= colmax)
	{
	    colmax += col_adj;
	    n = colmax +  win_col_off2(wp);
	    if (n > 0)
		colmax += (((col - colmax) / n) + 1) * n - col_adj;
	}

	for (;;)
	{
	    ps = s;
	    MB_PTR_ADV(s);
	    c = *s;
	    if (!(c != NUL && (VIM_ISBREAK(c)
			|| (!VIM_ISBREAK(c)
			    && (col2 == col || !VIM_ISBREAK((int)*ps))))))
		break;

	    col2 += win_chartabsize(wp, s, col2);
	    if (col2 >= colmax)		
	    {
		size = colmax - col + col_adj;
		break;
	    }
	}
    }
    else if (has_mbyte && size == 2 && MB_BYTE2LEN(*s) > 1 && wp->w_p_wrap && in_win_border(wp, col))
    {
	++size;		
	mb_added = 1;
    }

    
    added = 0;
    sbr = get_showbreak_value(wp);
    if ((*sbr != NUL || wp->w_p_bri) && wp->w_p_wrap && col != 0)
    {
	colnr_T sbrlen = 0;
	int	numberwidth = win_col_off(wp);

	numberextra = numberwidth;
	col += numberextra + mb_added;
	if (col >= (colnr_T)wp->w_width)
	{
	    col -= wp->w_width;
	    numberextra = wp->w_width - (numberextra - win_col_off2(wp));
	    if (col >= numberextra && numberextra > 0)
		col %= numberextra;
	    if (*sbr != NUL)
	    {
		sbrlen = (colnr_T)MB_CHARLEN(sbr);
		if (col >= sbrlen)
		    col -= sbrlen;
	    }
	    if (col >= numberextra && numberextra > 0)
		col = col % numberextra;
	    else if (col > 0 && numberextra > 0)
		col += numberwidth - win_col_off2(wp);

	    numberwidth -= win_col_off2(wp);
	}
	if (col == 0 || col + size + sbrlen > (colnr_T)wp->w_width)
	{
	    added = 0;
	    if (*sbr != NUL)
	    {
		if (size + sbrlen + numberwidth > (colnr_T)wp->w_width)
		{
		    
		    int width = (colnr_T)wp->w_width - sbrlen - numberwidth;
		    int prev_width = col ? ((colnr_T)wp->w_width - (sbrlen + col)) : 0;

		    if (width <= 0)
			width = (colnr_T)1;
		    added += ((size - prev_width) / width) * vim_strsize(sbr);
		    if ((size - prev_width) % width)
			
			added += vim_strsize(sbr);
		}
		else added += vim_strsize(sbr);
	    }
	    if (wp->w_p_bri)
		added += get_breakindent_win(wp, line);

	    size += added;
	    if (col != 0)
		added = 0;
	}
    }
    if (headp != NULL)
	*headp = added + mb_added;
    return size;

}


    static int win_nolbr_chartabsize( win_T	*wp, char_u	*s, colnr_T	col, int		*headp)




{
    int		n;

    if (*s == TAB && (!wp->w_p_list || wp->w_lcs_chars.tab1))
    {

	return tabstop_padding(col, wp->w_buffer->b_p_ts, wp->w_buffer->b_p_vts_array);

	n = wp->w_buffer->b_p_ts;
	return (int)(n - (col % n));

    }
    n = ptr2cells(s);
    
    
    if (n == 2 && MB_BYTE2LEN(*s) > 1 && in_win_border(wp, col))
    {
	if (headp != NULL)
	    *headp = 1;
	return 3;
    }
    return n;
}


    static int in_win_border(win_T *wp, colnr_T vcol)
{
    int		width1;		
    int		width2;		

    if (wp->w_width == 0)	
	return FALSE;
    width1 = wp->w_width - win_col_off(wp);
    if ((int)vcol < width1 - 1)
	return FALSE;
    if ((int)vcol == width1 - 1)
	return TRUE;
    width2 = width1 + win_col_off2(wp);
    if (width2 <= 0)
	return FALSE;
    return ((vcol - width1) % width2 == width2 - 1);
}


    void getvcol( win_T	*wp, pos_T	*pos, colnr_T	*start, colnr_T	*cursor, colnr_T	*end)





{
    colnr_T	vcol;
    char_u	*ptr;		
    char_u	*posptr;	
    char_u	*line;		
    int		incr;
    int		head;

    int		*vts = wp->w_buffer->b_p_vts_array;

    int		ts = wp->w_buffer->b_p_ts;
    int		c;

    vcol = 0;
    line = ptr = ml_get_buf(wp->w_buffer, pos->lnum, FALSE);
    if (pos->col == MAXCOL)
	posptr = NULL;  
    else {
	colnr_T i;

	
	for (i = 0; i < pos->col; ++i)
	    if (ptr[i] == NUL)
	    {
		pos->col = i;
		break;
	    }
	posptr = ptr + pos->col;
	if (has_mbyte)
	    
	    posptr -= (*mb_head_off)(line, posptr);
    }

    
    if ((!wp->w_p_list || wp->w_lcs_chars.tab1 != NUL)

	    && !wp->w_p_lbr && *get_showbreak_value(wp) == NUL && !wp->w_p_bri  )

    {
	for (;;)
	{
	    head = 0;
	    c = *ptr;
	    
	    if (c == NUL)
	    {
		incr = 1;	
		break;
	    }
	    
	    if (c == TAB)

		incr = tabstop_padding(vcol, ts, vts);

		incr = ts - (vcol % ts);

	    else {
		if (has_mbyte)
		{
		    
		    
		    if (enc_utf8 && c >= 0x80)
			incr = utf_ptr2cells(ptr);
		    else incr = g_chartab[c] & CT_CELL_MASK;

		    
		    
		    
		    if (incr == 2 && wp->w_p_wrap && MB_BYTE2LEN(*ptr) > 1 && in_win_border(wp, vcol))
		    {
			++incr;
			head = 1;
		    }
		}
		else incr = g_chartab[c] & CT_CELL_MASK;
	    }

	    if (posptr != NULL && ptr >= posptr) 
		break;

	    vcol += incr;
	    MB_PTR_ADV(ptr);
	}
    }
    else {
	for (;;)
	{
	    
	    head = 0;
	    incr = win_lbr_chartabsize(wp, line, ptr, vcol, &head);
	    
	    if (*ptr == NUL)
	    {
		incr = 1;	
		break;
	    }

	    if (posptr != NULL && ptr >= posptr) 
		break;

	    vcol += incr;
	    MB_PTR_ADV(ptr);
	}
    }
    if (start != NULL)
	*start = vcol + head;
    if (end != NULL)
	*end = vcol + incr - 1;
    if (cursor != NULL)
    {
	if (*ptr == TAB && (State & NORMAL)
		&& !wp->w_p_list && !virtual_active()
		&& !(VIsual_active && (*p_sel == 'e' || LTOREQ_POS(*pos, VIsual)))
		)
	    *cursor = vcol + incr - 1;	    
	else *cursor = vcol + head;
    }
}


    colnr_T getvcol_nolist(pos_T *posp)
{
    int		list_save = curwin->w_p_list;
    colnr_T	vcol;

    curwin->w_p_list = FALSE;
    if (posp->coladd)
	getvvcol(curwin, posp, NULL, &vcol, NULL);
    else getvcol(curwin, posp, NULL, &vcol, NULL);
    curwin->w_p_list = list_save;
    return vcol;
}


    void getvvcol( win_T	*wp, pos_T	*pos, colnr_T	*start, colnr_T	*cursor, colnr_T	*end)





{
    colnr_T	col;
    colnr_T	coladd;
    colnr_T	endadd;
    char_u	*ptr;

    if (virtual_active())
    {
	
	getvcol(wp, pos, &col, NULL, NULL);

	coladd = pos->coladd;
	endadd = 0;
	
	ptr = ml_get_buf(wp->w_buffer, pos->lnum, FALSE);
	if (pos->col < (colnr_T)STRLEN(ptr))
	{
	    int c = (*mb_ptr2char)(ptr + pos->col);

	    if (c != TAB && vim_isprintc(c))
	    {
		endadd = (colnr_T)(char2cells(c) - 1);
		if (coladd > endadd)	
		    endadd = 0;
		else coladd = 0;
	    }
	}
	col += coladd;
	if (start != NULL)
	    *start = col;
	if (cursor != NULL)
	    *cursor = col;
	if (end != NULL)
	    *end = col + endadd;
    }
    else getvcol(wp, pos, start, cursor, end);
}


    void getvcols( win_T	*wp, pos_T	*pos1, pos_T	*pos2, colnr_T	*left, colnr_T	*right)





{
    colnr_T	from1, from2, to1, to2;

    if (LT_POSP(pos1, pos2))
    {
	getvvcol(wp, pos1, &from1, NULL, &to1);
	getvvcol(wp, pos2, &from2, NULL, &to2);
    }
    else {
	getvvcol(wp, pos2, &from1, NULL, &to1);
	getvvcol(wp, pos1, &from2, NULL, &to2);
    }
    if (from2 < from1)
	*left = from2;
    else *left = from1;
    if (to2 > to1)
    {
	if (*p_sel == 'e' && from2 - 1 >= to1)
	    *right = from2 - 1;
	else *right = to2;
    }
    else *right = to1;
}


    char_u * skipwhite(char_u *q)
{
    char_u	*p = q;

    while (VIM_ISWHITE(*p))
	++p;
    return p;
}



    char_u * skipwhite_and_nl(char_u *q)
{
    char_u	*p = q;

    while (VIM_ISWHITE(*p) || *p == NL)
	++p;
    return p;
}



    int getwhitecols_curline()
{
    return getwhitecols(ml_get_curline());
}

    int getwhitecols(char_u *p)
{
    return skipwhite(p) - p;
}


    char_u * skipdigits(char_u *q)
{
    char_u	*p = q;

    while (VIM_ISDIGIT(*p))	
	++p;
    return p;
}



    char_u * skipbin(char_u *q)
{
    char_u	*p = q;

    while (vim_isbdigit(*p))	
	++p;
    return p;
}


    char_u * skiphex(char_u *q)
{
    char_u	*p = q;

    while (vim_isxdigit(*p))	
	++p;
    return p;
}



    char_u * skiptobin(char_u *q)
{
    char_u	*p = q;

    while (*p != NUL && !vim_isbdigit(*p))	
	++p;
    return p;
}


    char_u * skiptodigit(char_u *q)
{
    char_u	*p = q;

    while (*p != NUL && !VIM_ISDIGIT(*p))	
	++p;
    return p;
}


    char_u * skiptohex(char_u *q)
{
    char_u	*p = q;

    while (*p != NUL && !vim_isxdigit(*p))	
	++p;
    return p;
}


    int vim_isdigit(int c)
{
    return (c >= '0' && c <= '9');
}


    int vim_isxdigit(int c)
{
    return (c >= '0' && c <= '9')
	|| (c >= 'a' && c <= 'f')
	|| (c >= 'A' && c <= 'F');
}


    int vim_isbdigit(int c)
{
    return (c == '0' || c == '1');
}

    static int vim_isodigit(int c)
{
    return (c >= '0' && c <= '7');
}





static char_u latin1flags[257] = "                                                                 UUUUUUUUUUUUUUUUUUUUUUUUUU      llllllllllllllllllllllllll                                                                     UUUUUUUUUUUUUUUUUUUUUUU UUUUUUUllllllllllllllllllllllll llllllll";
static char_u latin1upper[257] = "                                 !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`ABCDEFGHIJKLMNOPQRSTUVWXYZ{|}~\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xf7\xd8\xd9\xda\xdb\xdc\xdd\xde\xff";
static char_u latin1lower[257] = "                                 !\"#$%&'()*+,-./0123456789:;<=>?@abcdefghijklmnopqrstuvwxyz[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xd7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";

    int vim_islower(int c)
{
    if (c <= '@')
	return FALSE;
    if (c >= 0x80)
    {
	if (enc_utf8)
	    return utf_islower(c);
	if (c >= 0x100)
	{

	    if (has_mbyte)
		return iswlower(c);

	    
	    return FALSE;
	}
	if (enc_latin1like)
	    return (latin1flags[c] & LATIN1LOWER) == LATIN1LOWER;
    }
    return islower(c);
}

    int vim_isupper(int c)
{
    if (c <= '@')
	return FALSE;
    if (c >= 0x80)
    {
	if (enc_utf8)
	    return utf_isupper(c);
	if (c >= 0x100)
	{

	    if (has_mbyte)
		return iswupper(c);

	    
	    return FALSE;
	}
	if (enc_latin1like)
	    return (latin1flags[c] & LATIN1UPPER) == LATIN1UPPER;
    }
    return isupper(c);
}

    int vim_toupper(int c)
{
    if (c <= '@')
	return c;
    if (c >= 0x80 || !(cmp_flags & CMP_KEEPASCII))
    {
	if (enc_utf8)
	    return utf_toupper(c);
	if (c >= 0x100)
	{

	    if (has_mbyte)
		return towupper(c);

	    
	    return c;
	}
	if (enc_latin1like)
	    return latin1upper[c];
    }
    if (c < 0x80 && (cmp_flags & CMP_KEEPASCII))
	return TOUPPER_ASC(c);
    return TOUPPER_LOC(c);
}

    int vim_tolower(int c)
{
    if (c <= '@')
	return c;
    if (c >= 0x80 || !(cmp_flags & CMP_KEEPASCII))
    {
	if (enc_utf8)
	    return utf_tolower(c);
	if (c >= 0x100)
	{

	    if (has_mbyte)
		return towlower(c);

	    
	    return c;
	}
	if (enc_latin1like)
	    return latin1lower[c];
    }
    if (c < 0x80 && (cmp_flags & CMP_KEEPASCII))
	return TOLOWER_ASC(c);
    return TOLOWER_LOC(c);
}


    char_u * skiptowhite(char_u *p)
{
    while (*p != ' ' && *p != '\t' && *p != NUL)
	++p;
    return p;
}


    char_u * skiptowhite_esc(char_u *p)
{
    while (*p != ' ' && *p != '\t' && *p != NUL)
    {
	if ((*p == '\\' || *p == Ctrl_V) && *(p + 1) != NUL)
	    ++p;
	++p;
    }
    return p;
}


    long getdigits(char_u **pp)
{
    char_u	*p;
    long	retval;

    p = *pp;
    retval = atol((char *)p);
    if (*p == '-')		
	++p;
    p = skipdigits(p);		
    *pp = p;
    return retval;
}


    long getdigits_quoted(char_u **pp)
{
    char_u	*p = *pp;
    long	retval = 0;

    if (*p == '-')
	++p;
    while (VIM_ISDIGIT(*p))
    {
	if (retval >= LONG_MAX / 10 - 10)
	    retval = LONG_MAX;
	else retval = retval * 10 - '0' + *p;
	++p;
	if (in_vim9script() && *p == '\'' && VIM_ISDIGIT(p[1]))
	    ++p;
    }
    if (**pp == '-')
    {
	if (retval == LONG_MAX)
	    retval = LONG_MIN;
	else retval = -retval;
    }
    *pp = p;
    return retval;
}


    int vim_isblankline(char_u *lbuf)
{
    char_u	*p;

    p = skipwhite(lbuf);
    return (*p == NUL || *p == '\r' || *p == '\n');
}


    void vim_str2nr( char_u		*start, int			*prep,   int			*len, int			what, varnumber_T		*nptr, uvarnumber_T	*unptr, int			maxlen, int			strict)










{
    char_u	    *ptr = start;
    int		    pre = 0;		
    int		    negative = FALSE;
    uvarnumber_T    un = 0;
    int		    n;

    if (len != NULL)
	*len = 0;

    if (ptr[0] == '-')
    {
	negative = TRUE;
	++ptr;
    }

    
    if (ptr[0] == '0' && ptr[1] != '8' && ptr[1] != '9' && (maxlen == 0 || maxlen > 1))
    {
	pre = ptr[1];
	if ((what & STR2NR_HEX)
		&& (pre == 'X' || pre == 'x') && vim_isxdigit(ptr[2])
		&& (maxlen == 0 || maxlen > 2))
	    
	    ptr += 2;
	else if ((what & STR2NR_BIN)
		&& (pre == 'B' || pre == 'b') && vim_isbdigit(ptr[2])
		&& (maxlen == 0 || maxlen > 2))
	    
	    ptr += 2;
	else if ((what & STR2NR_OOCT)
		&& (pre == 'O' || pre == 'o') && vim_isodigit(ptr[2])
		&& (maxlen == 0 || maxlen > 2))
	    
	    ptr += 2;
	else {
	    
	    pre = 0;
	    if (what & STR2NR_OCT)
	    {
		
		for (n = 1; n != maxlen && VIM_ISDIGIT(ptr[n]); ++n)
		{
		    if (ptr[n] > '7')
		    {
			pre = 0;	
			break;
		    }
		    pre = '0';	
		}
	    }
	}
    }

    
    n = 1;
    if (pre == 'B' || pre == 'b' || ((what & STR2NR_BIN) && (what & STR2NR_FORCE)))
    {
	
	if (pre != 0)
	    n += 2;	    
	while ('0' <= *ptr && *ptr <= '1')
	{
	    
	    if (un <= UVARNUM_MAX / 2)
		un = 2 * un + (uvarnumber_T)(*ptr - '0');
	    else un = UVARNUM_MAX;
	    ++ptr;
	    if (n++ == maxlen)
		break;
	    if ((what & STR2NR_QUOTE) && *ptr == '\'' && '0' <= ptr[1] && ptr[1] <= '1')
	    {
		++ptr;
		if (n++ == maxlen)
		    break;
	    }
	}
    }
    else if (pre == 'O' || pre == 'o' || pre == '0' || ((what & STR2NR_OCT) && (what & STR2NR_FORCE)))
    {
	
	if (pre != 0 && pre != '0')
	    n += 2;	    
	while ('0' <= *ptr && *ptr <= '7')
	{
	    
	    if (un <= UVARNUM_MAX / 8)
		un = 8 * un + (uvarnumber_T)(*ptr - '0');
	    else un = UVARNUM_MAX;
	    ++ptr;
	    if (n++ == maxlen)
		break;
	    if ((what & STR2NR_QUOTE) && *ptr == '\'' && '0' <= ptr[1] && ptr[1] <= '7')
	    {
		++ptr;
		if (n++ == maxlen)
		    break;
	    }
	}
    }
    else if (pre != 0 || ((what & STR2NR_HEX) && (what & STR2NR_FORCE)))
    {
	
	if (pre != 0)
	    n += 2;	    
	while (vim_isxdigit(*ptr))
	{
	    
	    if (un <= UVARNUM_MAX / 16)
		un = 16 * un + (uvarnumber_T)hex2nr(*ptr);
	    else un = UVARNUM_MAX;
	    ++ptr;
	    if (n++ == maxlen)
		break;
	    if ((what & STR2NR_QUOTE) && *ptr == '\'' && vim_isxdigit(ptr[1]))
	    {
		++ptr;
		if (n++ == maxlen)
		    break;
	    }
	}
    }
    else {
	
	while (VIM_ISDIGIT(*ptr))
	{
	    uvarnumber_T    digit = (uvarnumber_T)(*ptr - '0');

	    
	    if (un < UVARNUM_MAX / 10 || (un == UVARNUM_MAX / 10 && digit <= UVARNUM_MAX % 10))
		un = 10 * un + digit;
	    else un = UVARNUM_MAX;
	    ++ptr;
	    if (n++ == maxlen)
		break;
	    if ((what & STR2NR_QUOTE) && *ptr == '\'' && VIM_ISDIGIT(ptr[1]))
	    {
		++ptr;
		if (n++ == maxlen)
		    break;
	    }
	}
    }

    
    
    if (strict && n - 1 != maxlen && ASCII_ISALNUM(*ptr))
	return;

    if (prep != NULL)
	*prep = pre;
    if (len != NULL)
	*len = (int)(ptr - start);
    if (nptr != NULL)
    {
	if (negative)   
	{
	    
	    if (un > VARNUM_MAX)
		*nptr = VARNUM_MIN;
	    else *nptr = -(varnumber_T)un;
	}
	else {
	    if (un > VARNUM_MAX)
		un = VARNUM_MAX;
	    *nptr = (varnumber_T)un;
	}
    }
    if (unptr != NULL)
	*unptr = un;
}


    int hex2nr(int c)
{
    if (c >= 'a' && c <= 'f')
	return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
	return c - 'A' + 10;
    return c - '0';
}


    int hexhex2nr(char_u *p)
{
    if (!vim_isxdigit(p[0]) || !vim_isxdigit(p[1]))
	return -1;
    return (hex2nr(p[0]) << 4) + hex2nr(p[1]);
}


    int rem_backslash(char_u *str)
{

    return (str[0] == '\\' && str[1] < 0x80 && (str[1] == ' ' || (str[1] != NUL && str[1] != '*' && str[1] != '?' && !vim_isfilec(str[1]))));






    return (str[0] == '\\' && str[1] != NUL);

}


    void backslash_halve(char_u *p)
{
    for ( ; *p; ++p)
	if (rem_backslash(p))
	    STRMOVE(p, p + 1);
}


    char_u * backslash_halve_save(char_u *p)
{
    char_u	*res;

    res = vim_strsave(p);
    if (res == NULL)
	return p;
    backslash_halve(res);
    return res;
}
