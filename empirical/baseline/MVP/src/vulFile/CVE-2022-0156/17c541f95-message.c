







static void add_msg_hist(char_u *s, int len, int attr);
static void hit_return_msg(void);
static void msg_home_replace_attr(char_u *fname, int attr);
static void msg_puts_attr_len(char *str, int maxlen, int attr);
static void msg_puts_display(char_u *str, int maxlen, int attr, int recurse);
static void msg_scroll_up(void);
static void inc_msg_scrolled(void);
static void store_sb_text(char_u **sb_str, char_u *s, int attr, int *sb_col, int finish);
static void t_puts(int *t_col, char_u *t_s, char_u *s, int attr);
static void msg_puts_printf(char_u *str, int maxlen);
static int do_more_prompt(int typed_char);
static void msg_screen_putchar(int c, int attr);
static void msg_moremsg(int full);
static int  msg_check_screen(void);
static void redir_write(char_u *s, int maxlen);

static char_u *msg_show_console_dialog(char_u *message, char_u *buttons, int dfltbutton);
static int	confirm_msg_used = FALSE;	
static char_u	*confirm_msg = NULL;		
static char_u	*confirm_msg_tail;		
static void display_confirm_msg(void);


static int emsg_to_channel_log = FALSE;


struct msg_hist {
    struct msg_hist	*next;
    char_u		*msg;
    int			attr;
};

static struct msg_hist *first_msg_hist = NULL;
static struct msg_hist *last_msg_hist = NULL;
static int msg_hist_len = 0;

static FILE *verbose_fd = NULL;
static int  verbose_did_open = FALSE;




    int msg(char *s)
{
    return msg_attr_keep(s, 0, FALSE);
}


    int verb_msg(char *s)
{
    int		n;

    verbose_enter();
    n = msg_attr_keep(s, 0, FALSE);
    verbose_leave();

    return n;
}

    int msg_attr(char *s, int attr)
{
    return msg_attr_keep(s, attr, FALSE);
}

    int msg_attr_keep( char	*s, int		attr, int		keep)



{
    static int	entered = 0;
    int		retval;
    char_u	*buf = NULL;

    
    
    if (!emsg_on_display && message_filtered((char_u *)s))
	return TRUE;


    if (attr == 0)
	set_vim_var_string(VV_STATUSMSG, (char_u *)s, -1);


    
    if (entered >= 3)
	return TRUE;
    ++entered;

    
    
    if ((char_u *)s != keep_msg || (*s != '<' && last_msg_hist != NULL && last_msg_hist->msg != NULL && STRCMP(s, last_msg_hist->msg)))



	add_msg_hist((char_u *)s, -1, attr);


    if (emsg_to_channel_log)
	
	ch_log(NULL, "ERROR: %s", (char *)s);


    
    msg_start();
    buf = msg_strtrunc((char_u *)s, FALSE);
    if (buf != NULL)
	s = (char *)buf;

    msg_outtrans_attr((char_u *)s, attr);
    msg_clr_eos();
    retval = msg_end();

    if (keep && retval && vim_strsize((char_u *)s)
			    < (int)(Rows - cmdline_row - 1) * Columns + sc_col)
	set_keep_msg((char_u *)s, 0);

    vim_free(buf);
    --entered;
    return retval;
}


    char_u * msg_strtrunc( char_u	*s, int		force)


{
    char_u	*buf = NULL;
    int		len;
    int		room;

    
    if ((!msg_scroll && !need_wait_return && shortmess(SHM_TRUNCALL)
			       && !exmode_active && msg_silent == 0) || force)
    {
	len = vim_strsize(s);
	if (msg_scrolled != 0)
	    
	    room = (int)(Rows - msg_row) * Columns - 1;
	else  room = (int)(Rows - msg_row - 1) * Columns + sc_col - 1;

	if (len > room && room > 0)
	{
	    if (enc_utf8)
		
		
		len = (room + 2) * 18;
	    else if (enc_dbcs == DBCS_JPNU)
		
		len = (room + 2) * 2;
	    else len = room + 2;
	    buf = alloc(len);
	    if (buf != NULL)
		trunc_string(s, buf, room, len);
	}
    }
    return buf;
}


    void trunc_string( char_u	*s, char_u	*buf, int		room_in, int		buflen)




{
    size_t	room = room_in - 3; 
    size_t	half;
    size_t	len = 0;
    int		e;
    int		i;
    int		n;

    if (*s == NUL)
    {
	if (buflen > 0)
	    *buf = NUL;
	return;
    }

    if (room_in < 3)
	room = 0;
    half = room / 2;

    
    for (e = 0; len < half && e < buflen; ++e)
    {
	if (s[e] == NUL)
	{
	    
	    buf[e] = NUL;
	    return;
	}
	n = ptr2cells(s + e);
	if (len + n > half)
	    break;
	len += n;
	buf[e] = s[e];
	if (has_mbyte)
	    for (n = (*mb_ptr2len)(s + e); --n > 0; )
	    {
		if (++e == buflen)
		    break;
		buf[e] = s[e];
	    }
    }

    
    i = e;
    if (enc_dbcs != 0)
    {
	
	
	
	n = vim_strsize(s + i);
	while (len + n > room)
	{
	    n -= ptr2cells(s + i);
	    i += (*mb_ptr2len)(s + i);
	}
    }
    else if (enc_utf8)
    {
	
	half = i = (int)STRLEN(s);
	for (;;)
	{
	    do half = half - utf_head_off(s, s + half - 1) - 1;
	    while (half > 0 && utf_iscomposing(utf_ptr2char(s + half)));
	    n = ptr2cells(s + half);
	    if (len + n > room || half == 0)
		break;
	    len += n;
	    i = (int)half;
	}
    }
    else {
	for (i = (int)STRLEN(s);
		   i - 1 >= 0 && len + (n = ptr2cells(s + i - 1)) <= room; --i)
	    len += n;
    }


    if (i <= e + 3)
    {
	
	if (s != buf)
	{
	    len = STRLEN(s);
	    if (len >= (size_t)buflen)
		len = buflen - 1;
	    len = len - e + 1;
	    if (len < 1)
		buf[e - 1] = NUL;
	    else mch_memmove(buf + e, s + e, len);
	}
    }
    else if (e + 3 < buflen)
    {
	
	mch_memmove(buf + e, "...", (size_t)3);
	len = STRLEN(s + i) + 1;
	if (len >= (size_t)buflen - e - 3)
	    len = buflen - e - 3 - 1;
	mch_memmove(buf + e + 3, s + i, len);
	buf[e + 3 + len - 1] = NUL;
    }
    else {
	
	buf[e - 1] = NUL;
    }
}




int vim_snprintf(char *str, size_t str_m, const char *fmt, ...);

    int smsg(const char *s, ...)
{
    if (IObuff == NULL)
    {
	
	
	return msg((char *)s);
    }
    else {
	va_list arglist;

	va_start(arglist, s);
	vim_vsnprintf((char *)IObuff, IOSIZE, s, arglist);
	va_end(arglist);
	return msg((char *)IObuff);
    }
}

    int smsg_attr(int attr, const char *s, ...)
{
    if (IObuff == NULL)
    {
	
	
	return msg_attr((char *)s, attr);
    }
    else {
	va_list arglist;

	va_start(arglist, s);
	vim_vsnprintf((char *)IObuff, IOSIZE, s, arglist);
	va_end(arglist);
	return msg_attr((char *)IObuff, attr);
    }
}

    int smsg_attr_keep(int attr, const char *s, ...)
{
    if (IObuff == NULL)
    {
	
	
	return msg_attr_keep((char *)s, attr, TRUE);
    }
    else {
	va_list arglist;

	va_start(arglist, s);
	vim_vsnprintf((char *)IObuff, IOSIZE, s, arglist);
	va_end(arglist);
	return msg_attr_keep((char *)IObuff, attr, TRUE);
    }
}




static int	last_sourcing_lnum = 0;
static char_u   *last_sourcing_name = NULL;


    void reset_last_sourcing(void)
{
    VIM_CLEAR(last_sourcing_name);
    last_sourcing_lnum = 0;
}


    static int other_sourcing_name(void)
{
    if (HAVE_SOURCING_INFO && SOURCING_NAME != NULL)
    {
	if (last_sourcing_name != NULL)
	    return STRCMP(SOURCING_NAME, last_sourcing_name) != 0;
	return TRUE;
    }
    return FALSE;
}


    static char_u * get_emsg_source(void)
{
    char_u	*Buf, *p;

    if (HAVE_SOURCING_INFO && SOURCING_NAME != NULL && other_sourcing_name())
    {
	char_u	    *sname = estack_sfile(ESTACK_NONE);
	char_u	    *tofree = sname;

	if (sname == NULL)
	    sname = SOURCING_NAME;


	if (estack_compiling)
	    p = (char_u *)_("Error detected while compiling %s:");
	else  p = (char_u *)_("Error detected while processing %s:");

	Buf = alloc(STRLEN(sname) + STRLEN(p));
	if (Buf != NULL)
	    sprintf((char *)Buf, (char *)p, sname);
	vim_free(tofree);
	return Buf;
    }
    return NULL;
}


    static char_u * get_emsg_lnum(void)
{
    char_u	*Buf, *p;

    
    
    if (SOURCING_NAME != NULL && (other_sourcing_name() || SOURCING_LNUM != last_sourcing_lnum)
	    && SOURCING_LNUM != 0)
    {
	p = (char_u *)_("line %4ld:");
	Buf = alloc(STRLEN(p) + 20);
	if (Buf != NULL)
	    sprintf((char *)Buf, (char *)p, (long)SOURCING_LNUM);
	return Buf;
    }
    return NULL;
}


    void msg_source(int attr)
{
    char_u	*p;
    static int	recursive = FALSE;

    
    if (recursive)
	return;
    recursive = TRUE;

    ++no_wait_return;
    p = get_emsg_source();
    if (p != NULL)
    {
	msg_attr((char *)p, attr);
	vim_free(p);
    }
    p = get_emsg_lnum();
    if (p != NULL)
    {
	msg_attr((char *)p, HL_ATTR(HLF_N));
	vim_free(p);
	last_sourcing_lnum = SOURCING_LNUM;  
    }

    
    if (SOURCING_NAME == NULL || other_sourcing_name())
    {
	VIM_CLEAR(last_sourcing_name);
	if (SOURCING_NAME != NULL)
	    last_sourcing_name = vim_strsave(SOURCING_NAME);
    }
    --no_wait_return;

    recursive = FALSE;
}


    static int emsg_not_now(void)
{
    if ((emsg_off > 0 && vim_strchr(p_debug, 'm') == NULL && vim_strchr(p_debug, 't') == NULL)

	    || emsg_skip > 0  )

	return TRUE;
    return FALSE;
}


static garray_T ignore_error_list = GA_EMPTY;

    void ignore_error_for_testing(char_u *error)
{
    if (ignore_error_list.ga_itemsize == 0)
	ga_init2(&ignore_error_list, sizeof(char_u *), 1);

    if (STRCMP("RESET", error) == 0)
	ga_clear_strings(&ignore_error_list);
    else ga_add_string(&ignore_error_list, error);
}

    static int ignore_error(char_u *msg)
{
    int i;

    for (i = 0; i < ignore_error_list.ga_len; ++i)
	if (strstr((char *)msg, (char *)((char_u **)(ignore_error_list.ga_data))[i]) != NULL)
	    return TRUE;
    return FALSE;
}




    void do_perror(char *msg)
{
    perror(msg);
    ++emsg_silent;
    emsg(msg);
    --emsg_silent;
}



    static int emsg_core(char_u *s)
{
    int		attr;
    char_u	*p;
    int		r;

    int		ignore = FALSE;
    int		severe;



    
    if (ignore_error(s))
	
	return msg_use_printf() ? FALSE : msg((char *)s);


    ++called_emsg;


    
    
    severe = emsg_severe;
    emsg_severe = FALSE;


    if (!emsg_off || vim_strchr(p_debug, 't') != NULL)
    {

	
	if (cause_errthrow(s, severe, &ignore) == TRUE)
	{
	    if (!ignore)
		++did_emsg;
	    return TRUE;
	}

	if (in_assert_fails && emsg_assert_fails_msg == NULL)
	{
	    emsg_assert_fails_msg = vim_strsave(s);
	    emsg_assert_fails_lnum = SOURCING_LNUM;
	    vim_free(emsg_assert_fails_context);
	    emsg_assert_fails_context = vim_strsave( SOURCING_NAME == NULL ? (char_u *)"" : SOURCING_NAME);
	}

	
	set_vim_var_string(VV_ERRMSG, s, -1);


	
	if (emsg_silent != 0)
	{

	    ++did_emsg_silent;

	    if (emsg_noredir == 0)
	    {
		msg_start();
		p = get_emsg_source();
		if (p != NULL)
		{
		    STRCAT(p, "\n");
		    redir_write(p, -1);
		    vim_free(p);
		}
		p = get_emsg_lnum();
		if (p != NULL)
		{
		    STRCAT(p, "\n");
		    redir_write(p, -1);
		    vim_free(p);
		}
		redir_write(s, -1);
	    }

	    
	    
	    if (emsg_silent == emsg_silent_def)
		++did_emsg_def;


	    ch_log(NULL, "ERROR silent: %s", (char *)s);

	    return TRUE;
	}

	ex_exitval = 1;

	
	msg_silent = 0;
	cmd_silent = FALSE;

	if (global_busy)		
	    ++global_busy;

	if (p_eb)
	    beep_flush();		
	else flush_buffers(FLUSH_MINIMAL);
	++did_emsg;			   

	++uncaught_emsg;

    }

    emsg_on_display = TRUE;	
    ++msg_scroll;		
    attr = HL_ATTR(HLF_E);	
    if (msg_scrolled != 0)
	need_wait_return = TRUE;    
				    
				    
				    


    emsg_to_channel_log = TRUE;

    
    msg_source(attr);

    
    msg_nowait = FALSE;			
    r = msg_attr((char *)s, attr);


    emsg_to_channel_log = FALSE;

    return r;
}


    int emsg(char *s)
{
    
    if (!emsg_not_now())
	return emsg_core((char_u *)s);
    return TRUE;		
}



    int semsg(const char *s, ...)
{
    
    if (!emsg_not_now())
    {
	if (IObuff == NULL)
	{
	    
	    
	    return emsg_core((char_u *)s);
	}
	else {
	    va_list ap;

	    va_start(ap, s);
	    vim_vsnprintf((char *)IObuff, IOSIZE, s, ap);
	    va_end(ap);
	    return emsg_core(IObuff);
	}
    }
    return TRUE;		
}



    void iemsg(char *s)
{
    if (!emsg_not_now())
    {
	emsg_core((char_u *)s);

	set_vim_var_string(VV_ERRMSG, (char_u *)s, -1);
	abort();

    }
}



    void siemsg(const char *s, ...)
{
    if (!emsg_not_now())
    {
	if (IObuff == NULL)
	{
	    
	    
	    emsg_core((char_u *)s);
	}
	else {
	    va_list ap;

	    va_start(ap, s);
	    vim_vsnprintf((char *)IObuff, IOSIZE, s, ap);
	    va_end(ap);
	    emsg_core(IObuff);
	}
    }

    abort();

}



    void internal_error(char *where)
{
    siemsg(_(e_internal_error_str), where);
}



    void internal_error_no_abort(char *where)
{
     semsg(_(e_internal_error_str), where);
}




    void emsg_invreg(int name)
{
    semsg(_(e_invalid_register_name_str), transchar(name));
}



    void emsg_namelen(char *msg, char_u *name, int len)
{
    char_u *copy = vim_strnsave((char_u *)name, len);

    semsg(msg, copy == NULL ? "NULL" : (char *)copy);
    vim_free(copy);
}



    char * msg_trunc_attr(char *s, int force, int attr)
{
    int		n;
    char	*ts;

    
    add_msg_hist((char_u *)s, -1, attr);

    ts = (char *)msg_may_trunc(force, (char_u *)s);

    msg_hist_off = TRUE;
    n = msg_attr(ts, attr);
    msg_hist_off = FALSE;

    if (n)
	return ts;
    return NULL;
}


    char_u * msg_may_trunc(int force, char_u *s)
{
    int		n;
    int		room;

    room = (int)(Rows - cmdline_row - 1) * Columns + sc_col - 1;
    if ((force || (shortmess(SHM_TRUNC) && !exmode_active))
	    && (n = (int)STRLEN(s) - room) > 0)
    {
	if (has_mbyte)
	{
	    int	size = vim_strsize(s);

	    
	    if (size <= room)
		return s;

	    for (n = 0; size >= room; )
	    {
		size -= (*mb_ptr2cells)(s + n);
		n += (*mb_ptr2len)(s + n);
	    }
	    --n;
	}
	s += n;
	*s = '<';
    }
    return s;
}

    static void add_msg_hist( char_u	*s, int		len, int		attr)



{
    struct msg_hist *p;

    if (msg_hist_off || msg_silent != 0)
	return;

    
    while (msg_hist_len > MAX_MSG_HIST_LEN)
	(void)delete_first_msg();

    
    p = ALLOC_ONE(struct msg_hist);
    if (p != NULL)
    {
	if (len < 0)
	    len = (int)STRLEN(s);
	
	while (len > 0 && *s == '\n')
	{
	    ++s;
	    --len;
	}
	while (len > 0 && s[len - 1] == '\n')
	    --len;
	p->msg = vim_strnsave(s, len);
	p->next = NULL;
	p->attr = attr;
	if (last_msg_hist != NULL)
	    last_msg_hist->next = p;
	last_msg_hist = p;
	if (first_msg_hist == NULL)
	    first_msg_hist = last_msg_hist;
	++msg_hist_len;
    }
}


    int delete_first_msg(void)
{
    struct msg_hist *p;

    if (msg_hist_len <= 0)
	return FAIL;
    p = first_msg_hist;
    first_msg_hist = p->next;
    if (first_msg_hist == NULL)
	last_msg_hist = NULL;  
    vim_free(p->msg);
    vim_free(p);
    --msg_hist_len;
    return OK;
}


    void ex_messages(exarg_T *eap)
{
    struct msg_hist *p;
    char_u	    *s;
    int		    c = 0;

    if (STRCMP(eap->arg, "clear") == 0)
    {
	int keep = eap->addr_count == 0 ? 0 : eap->line2;

	while (msg_hist_len > keep)
	    (void)delete_first_msg();
	return;
    }

    if (*eap->arg != NUL)
    {
	emsg(_(e_invalid_argument));
	return;
    }

    msg_hist_off = TRUE;

    p = first_msg_hist;
    if (eap->addr_count != 0)
    {
	
	for (; p != NULL && !got_int; p = p->next)
	    c++;

	c -= eap->line2;

	
	for (p = first_msg_hist; p != NULL && !got_int && c > 0;
						    p = p->next, c--);
    }

    if (p == first_msg_hist)
    {

	s = get_mess_lang();

	s = mch_getenv((char_u *)"LANG");

	if (s != NULL && *s != NUL)
	    
	    
	    msg_attr(   _("Messages maintainer: Bram Moolenaar <Bram@vim.org>"), HL_ATTR(HLF_T));



    }

    
    for (; p != NULL && !got_int; p = p->next)
	if (p->msg != NULL)
	    msg_attr((char *)p->msg, p->attr);

    msg_hist_off = FALSE;
}



    void msg_end_prompt(void)
{
    need_wait_return = FALSE;
    emsg_on_display = FALSE;
    cmdline_row = msg_row;
    msg_col = 0;
    msg_clr_eos();
    lines_left = -1;
}



    void wait_return(int redraw)
{
    int		c;
    int		oldState;
    int		tmpState;
    int		had_got_int;
    int		save_reg_recording;
    FILE	*save_scriptout;

    if (redraw == TRUE)
	must_redraw = CLEAR;

    
    
    if (msg_silent != 0)
	return;

    
    if (vgetc_busy > 0)
	return;
    need_wait_return = TRUE;
    if (no_wait_return)
    {
	if (!exmode_active)
	    cmdline_row = msg_row;
	return;
    }

    redir_off = TRUE;		
    oldState = State;
    if (quit_more)
    {
	c = CAR;		
	quit_more = FALSE;
	got_int = FALSE;
    }
    else if (exmode_active)
    {
	msg_puts(" ");		
	c = CAR;		
	got_int = FALSE;
    }
    else {
	
	
	screenalloc(FALSE);

	State = HITRETURN;
	setmouse();

	dont_scroll = TRUE;		

	cmdline_row = msg_row;

	
	
	
	if (need_check_timestamps)
	    check_timestamps(FALSE);

	hit_return_msg();

	do {
	    
	    
	    had_got_int = got_int;

	    
	    
	    ++no_mapping;
	    ++allow_keys;

	    
	    
	    
	    save_reg_recording = reg_recording;
	    save_scriptout = scriptout;
	    reg_recording = 0;
	    scriptout = NULL;
	    c = safe_vgetc();
	    if (had_got_int && !global_busy)
		got_int = FALSE;
	    --no_mapping;
	    --allow_keys;
	    reg_recording = save_reg_recording;
	    scriptout = save_scriptout;


	    
	    
	    
	    if (c == Ctrl_Y && clip_star.state == SELECT_DONE)
	    {
		clip_copy_modeless_selection(TRUE);
		c = K_IGNORE;
	    }


	    
	    if (p_more && !p_cp)
	    {
		if (c == 'b' || c == 'k' || c == 'u' || c == 'g' || c == K_UP || c == K_PAGEUP)
		{
		    if (msg_scrolled > Rows)
			
			do_more_prompt(c);
		    else {
			msg_didout = FALSE;
			c = K_IGNORE;
			msg_col =  cmdmsg_rl ? Columns - 1 :


			    0;
		    }
		    if (quit_more)
		    {
			c = CAR;		
			quit_more = FALSE;
			got_int = FALSE;
		    }
		    else if (c != K_IGNORE)
		    {
			c = K_IGNORE;
			hit_return_msg();
		    }
		}
		else if (msg_scrolled > Rows - 2 && (c == 'j' || c == 'd' || c == 'f' || c == K_DOWN || c == K_PAGEDOWN))

		    c = K_IGNORE;
	    }
	} while ((had_got_int && c == Ctrl_C)
				|| c == K_IGNORE  || c == K_VER_SCROLLBAR || c == K_HOR_SCROLLBAR  || c == K_LEFTDRAG   || c == K_LEFTRELEASE || c == K_MIDDLEDRAG || c == K_MIDDLERELEASE || c == K_RIGHTDRAG  || c == K_RIGHTRELEASE || c == K_MOUSELEFT  || c == K_MOUSERIGHT || c == K_MOUSEDOWN  || c == K_MOUSEUP || c == K_MOUSEMOVE || (!mouse_has(MOUSE_RETURN)









				    && mouse_row < msg_row && (c == K_LEFTMOUSE || c == K_MIDDLEMOUSE || c == K_RIGHTMOUSE || c == K_X1MOUSE || c == K_X2MOUSE))




				);
	ui_breakcheck();
	
	if (c == K_LEFTMOUSE || c == K_MIDDLEMOUSE || c == K_RIGHTMOUSE || c == K_X1MOUSE || c == K_X2MOUSE)
	    (void)jump_to_mouse(MOUSE_SETPOS, NULL, 0);
	else if (vim_strchr((char_u *)"\r\n ", c) == NULL && c != Ctrl_C)
	{
	    
	    
	    ins_char_typebuf(vgetc_char, vgetc_mod_mask);
	    do_redraw = TRUE;	    
				    
	}
    }
    redir_off = FALSE;

    
    if (c == ':' || c == '?' || c == '/')
    {
	if (!exmode_active)
	    cmdline_row = msg_row;
	skip_redraw = TRUE;	    
	do_redraw = FALSE;

	skip_term_loop = TRUE;

    }

    
    tmpState = State;
    State = oldState;		    
    setmouse();
    msg_check();


    
    if (swapping_screen() && !termcap_active)
	newline_on_exit = TRUE;


    need_wait_return = FALSE;
    did_wait_return = TRUE;
    emsg_on_display = FALSE;	
    lines_left = -1;		
    reset_last_sourcing();
    if (keep_msg != NULL && vim_strsize(keep_msg) >= (Rows - cmdline_row - 1) * Columns + sc_col)
	VIM_CLEAR(keep_msg);	    

    if (tmpState == SETWSIZE)	    
    {
	starttermcap();		    
	shell_resized();
    }
    else if (!skip_redraw && (redraw == TRUE || (msg_scrolled != 0 && redraw != -1)))
    {
	starttermcap();		    
	redraw_later(VALID);
    }
}


    static void hit_return_msg(void)
{
    int		save_p_more = p_more;

    p_more = FALSE;	
    if (msg_didout)	
	msg_putchar('\n');
    if (got_int)
	msg_puts(_("Interrupt: "));

    msg_puts_attr(_("Press ENTER or type command to continue"), HL_ATTR(HLF_R));
    if (!msg_use_printf())
	msg_clr_eos();
    p_more = save_p_more;
}


    void set_keep_msg(char_u *s, int attr)
{
    vim_free(keep_msg);
    if (s != NULL && msg_silent == 0)
	keep_msg = vim_strsave(s);
    else keep_msg = NULL;
    keep_msg_more = FALSE;
    keep_msg_attr = attr;
}



    void set_keep_msg_from_hist(void)
{
    if (keep_msg == NULL && last_msg_hist != NULL && msg_scrolled == 0 && (State & NORMAL))
	set_keep_msg(last_msg_hist->msg, last_msg_hist->attr);
}



    void msg_start(void)
{
    int		did_return = FALSE;

    if (!msg_silent)
	VIM_CLEAR(keep_msg);


    if (need_clr_eos)
    {
	
	
	need_clr_eos = FALSE;
	msg_clr_eos();
    }


    if (!msg_scroll && full_screen)	
    {
	msg_row = cmdline_row;
	msg_col =  cmdmsg_rl ? Columns - 1 :


	    0;
    }
    else if (msg_didout)		    
    {
	msg_putchar('\n');
	did_return = TRUE;
	if (exmode_active != EXMODE_NORMAL)
	    cmdline_row = msg_row;
    }
    if (!msg_didany || lines_left < 0)
	msg_starthere();
    if (msg_silent == 0)
    {
	msg_didout = FALSE;		    
	cursor_off();
    }

    
    if (!did_return)
	redir_write((char_u *)"\n", -1);
}


    void msg_starthere(void)
{
    lines_left = cmdline_row;
    msg_didany = FALSE;
}

    void msg_putchar(int c)
{
    msg_putchar_attr(c, 0);
}

    void msg_putchar_attr(int c, int attr)
{
    char_u	buf[MB_MAXBYTES + 1];

    if (IS_SPECIAL(c))
    {
	buf[0] = K_SPECIAL;
	buf[1] = K_SECOND(c);
	buf[2] = K_THIRD(c);
	buf[3] = NUL;
    }
    else buf[(*mb_char2bytes)(c, buf)] = NUL;
    msg_puts_attr((char *)buf, attr);
}

    void msg_outnum(long n)
{
    char	buf[20];

    sprintf(buf, "%ld", n);
    msg_puts(buf);
}

    void msg_home_replace(char_u *fname)
{
    msg_home_replace_attr(fname, 0);
}


    void msg_home_replace_hl(char_u *fname)
{
    msg_home_replace_attr(fname, HL_ATTR(HLF_D));
}


    static void msg_home_replace_attr(char_u *fname, int attr)
{
    char_u	*name;

    name = home_replace_save(NULL, fname);
    if (name != NULL)
	msg_outtrans_attr(name, attr);
    vim_free(name);
}


    int msg_outtrans(char_u *str)
{
    return msg_outtrans_attr(str, 0);
}

    int msg_outtrans_attr(char_u *str, int attr)
{
    return msg_outtrans_len_attr(str, (int)STRLEN(str), attr);
}

    int msg_outtrans_len(char_u *str, int len)
{
    return msg_outtrans_len_attr(str, len, 0);
}


    char_u * msg_outtrans_one(char_u *p, int attr)
{
    int		l;

    if (has_mbyte && (l = (*mb_ptr2len)(p)) > 1)
    {
	msg_outtrans_len_attr(p, l, attr);
	return p + l;
    }
    msg_puts_attr((char *)transchar_byte(*p), attr);
    return p + 1;
}

    int msg_outtrans_len_attr(char_u *msgstr, int len, int attr)
{
    int		retval = 0;
    char_u	*str = msgstr;
    char_u	*plain_start = msgstr;
    char_u	*s;
    int		mb_l;
    int		c;
    int		save_got_int = got_int;

    
    got_int = FALSE;

    
    if (attr & MSG_HIST)
    {
	add_msg_hist(str, len, attr);
	attr &= ~MSG_HIST;
    }

    
    
    if (enc_utf8 && utf_iscomposing(utf_ptr2char(msgstr)))
	msg_puts_attr(" ", attr);

    
    while (--len >= 0 && !got_int)
    {
	if (enc_utf8)
	    
	    mb_l = utfc_ptr2len_len(str, len + 1);
	else if (has_mbyte)
	    mb_l = (*mb_ptr2len)(str);
	else mb_l = 1;
	if (has_mbyte && mb_l > 1)
	{
	    c = (*mb_ptr2char)(str);
	    if (vim_isprintc(c))
		
		retval += (*mb_ptr2cells)(str);
	    else {
		
		
		if (str > plain_start)
		    msg_puts_attr_len((char *)plain_start, (int)(str - plain_start), attr);
		plain_start = str + mb_l;
		msg_puts_attr((char *)transchar(c), attr == 0 ? HL_ATTR(HLF_8) : attr);
		retval += char2cells(c);
	    }
	    len -= mb_l - 1;
	    str += mb_l;
	}
	else {
	    s = transchar_byte(*str);
	    if (s[1] != NUL)
	    {
		
		
		if (str > plain_start)
		    msg_puts_attr_len((char *)plain_start, (int)(str - plain_start), attr);
		plain_start = str + 1;
		msg_puts_attr((char *)s, attr == 0 ? HL_ATTR(HLF_8) : attr);
		retval += (int)STRLEN(s);
	    }
	    else ++retval;
	    ++str;
	}
    }

    if (str > plain_start && !got_int)
	
	msg_puts_attr_len((char *)plain_start, (int)(str - plain_start), attr);

    got_int |= save_got_int;

    return retval;
}


    void msg_make(char_u *arg)
{
    int	    i;
    static char_u *str = (char_u *)"eeffoc", *rs = (char_u *)"Plon#dqg#vxjduB";

    arg = skipwhite(arg);
    for (i = 5; *arg && i >= 0; --i)
	if (*arg++ != str[i])
	    break;
    if (i < 0)
    {
	msg_putchar('\n');
	for (i = 0; rs[i]; ++i)
	    msg_putchar(rs[i] - 3);
    }
}



    int msg_outtrans_special( char_u	*strstart, int		from, int		maxlen)



{
    char_u	*str = strstart;
    int		retval = 0;
    char	*text;
    int		attr;
    int		len;

    attr = HL_ATTR(HLF_8);
    while (*str != NUL)
    {
	
	if ((str == strstart || str[1] == NUL) && *str == ' ')
	{
	    text = "<Space>";
	    ++str;
	}
	else text = (char *)str2special(&str, from);
	len = vim_strsize((char_u *)text);
	if (maxlen > 0 && retval + len >= maxlen)
	    break;
	
	msg_puts_attr(text, len > 1 && (*mb_ptr2len)((char_u *)text) <= 1 ? attr : 0);
	retval += len;
    }
    return retval;
}



    char_u * str2special_save( char_u  *str, int	    is_lhs)


{
    garray_T	ga;
    char_u	*p = str;

    ga_init2(&ga, 1, 40);
    while (*p != NUL)
	ga_concat(&ga, str2special(&p, is_lhs));
    ga_append(&ga, NUL);
    return (char_u *)ga.ga_data;
}



    char_u * str2special( char_u	**sp, int		from)


{
    int			c;
    static char_u	buf[7];
    char_u		*str = *sp;
    int			modifiers = 0;
    int			special = FALSE;

    if (has_mbyte)
    {
	char_u	*p;

	
	
	p = mb_unescape(sp);
	if (p != NULL)
	    return p;
    }

    c = *str;
    if (c == K_SPECIAL && str[1] != NUL && str[2] != NUL)
    {
	if (str[1] == KS_MODIFIER)
	{
	    modifiers = str[2];
	    str += 3;
	    c = *str;
	}
	if (c == K_SPECIAL && str[1] != NUL && str[2] != NUL)
	{
	    c = TO_SPECIAL(str[1], str[2]);
	    str += 2;
	}
	if (IS_SPECIAL(c) || modifiers)	
	    special = TRUE;
    }

    if (has_mbyte && !IS_SPECIAL(c))
    {
	int len = (*mb_ptr2len)(str);

	
	if (has_mbyte && MB_BYTE2LEN(*str) > len)
	{
	    transchar_nonprint(curbuf, buf, c);
	    *sp = str + 1;
	    return buf;
	}
	
	
	c = (*mb_ptr2char)(str);
	*sp = str + len;
    }
    else *sp = str + 1;

    
    
    if (special || char2cells(c) > 1 || (from && c == ' '))
	return get_special_key_name(c, modifiers);
    buf[0] = c;
    buf[1] = NUL;
    return buf;
}


    void str2specialbuf(char_u *sp, char_u *buf, int len)
{
    char_u	*s;

    *buf = NUL;
    while (*sp)
    {
	s = str2special(&sp, FALSE);
	if ((int)(STRLEN(s) + STRLEN(buf)) < len)
	    STRCAT(buf, s);
    }
}


    void msg_prt_line(char_u *s, int list)
{
    int		c;
    int		col = 0;
    int		n_extra = 0;
    int		c_extra = 0;
    int		c_final = 0;
    char_u	*p_extra = NULL;	    
    int		n;
    int		attr = 0;
    char_u	*trail = NULL;
    char_u	*lead = NULL;
    int		in_multispace = FALSE;
    int		multispace_pos = 0;
    int		l;
    char_u	buf[MB_MAXBYTES + 1];

    if (curwin->w_p_list)
	list = TRUE;

    if (list)
    {
	
	if (curwin->w_lcs_chars.trail)
	{
	    trail = s + STRLEN(s);
	    while (trail > s && VIM_ISWHITE(trail[-1]))
		--trail;
	}
	
	if (curwin->w_lcs_chars.lead)
	{
	    lead = s;
	    while (VIM_ISWHITE(lead[0]))
		lead++;
	    
	    if (*lead == NUL)
		lead = NULL;
	}
    }

    
    
    if (*s == NUL && !(list && curwin->w_lcs_chars.eol != NUL))
	msg_putchar(' ');

    while (!got_int)
    {
	if (n_extra > 0)
	{
	    --n_extra;
	    if (n_extra == 0 && c_final)
		c = c_final;
	    else if (c_extra)
		c = c_extra;
	    else c = *p_extra++;
	}
	else if (has_mbyte && (l = (*mb_ptr2len)(s)) > 1)
	{
	    col += (*mb_ptr2cells)(s);
	    if (l >= MB_MAXBYTES)
	    {
		STRCPY(buf, "?");
	    }
	    else if (curwin->w_lcs_chars.nbsp != NUL && list && (mb_ptr2char(s) == 160 || mb_ptr2char(s) == 0x202f))

	    {
		mb_char2bytes(curwin->w_lcs_chars.nbsp, buf);
		buf[(*mb_ptr2len)(buf)] = NUL;
	    }
	    else {
		mch_memmove(buf, s, (size_t)l);
		buf[l] = NUL;
	    }
	    msg_puts((char *)buf);
	    s += l;
	    continue;
	}
	else {
	    attr = 0;
	    c = *s++;
	    in_multispace = c == ' ' && ((col > 0 && s[-2] == ' ') || *s == ' ');
	    if (!in_multispace)
		multispace_pos = 0;
	    if (c == TAB && (!list || curwin->w_lcs_chars.tab1))
	    {
		

		n_extra = tabstop_padding(col, curbuf->b_p_ts, curbuf->b_p_vts_array) - 1;

		n_extra = curbuf->b_p_ts - col % curbuf->b_p_ts - 1;

		if (!list)
		{
		    c = ' ';
		    c_extra = ' ';
		    c_final = NUL;
		}
		else {
		    c = (n_extra == 0 && curwin->w_lcs_chars.tab3)
						? curwin->w_lcs_chars.tab3 : curwin->w_lcs_chars.tab1;
		    c_extra = curwin->w_lcs_chars.tab2;
		    c_final = curwin->w_lcs_chars.tab3;
		    attr = HL_ATTR(HLF_8);
		}
	    }
	    else if (c == 160 && list && curwin->w_lcs_chars.nbsp != NUL)
	    {
		c = curwin->w_lcs_chars.nbsp;
		attr = HL_ATTR(HLF_8);
	    }
	    else if (c == NUL && list && curwin->w_lcs_chars.eol != NUL)
	    {
		p_extra = (char_u *)"";
		c_extra = NUL;
		c_final = NUL;
		n_extra = 1;
		c = curwin->w_lcs_chars.eol;
		attr = HL_ATTR(HLF_AT);
		--s;
	    }
	    else if (c != NUL && (n = byte2cells(c)) > 1)
	    {
		n_extra = n - 1;
		p_extra = transchar_byte(c);
		c_extra = NUL;
		c_final = NUL;
		c = *p_extra++;
		
		
		attr = HL_ATTR(HLF_8);
	    }
	    else if (c == ' ')
	    {
		if (lead != NULL && s <= lead)
		{
		    c = curwin->w_lcs_chars.lead;
		    attr = HL_ATTR(HLF_8);
		}
		else if (trail != NULL && s > trail)
		{
		    c = curwin->w_lcs_chars.trail;
		    attr = HL_ATTR(HLF_8);
		}
		else if (list && in_multispace && curwin->w_lcs_chars.multispace != NULL)
		{
		    c = curwin->w_lcs_chars.multispace[multispace_pos++];
		    if (curwin->w_lcs_chars.multispace[multispace_pos] == NUL)
			multispace_pos = 0;
		    attr = HL_ATTR(HLF_8);
		}
		else if (list && curwin->w_lcs_chars.space != NUL)
		{
		    c = curwin->w_lcs_chars.space;
		    attr = HL_ATTR(HLF_8);
		}
	    }
	}

	if (c == NUL)
	    break;

	msg_putchar_attr(c, attr);
	col++;
    }
    msg_clr_eos();
}


    static char_u * screen_puts_mbyte(char_u *s, int l, int attr)
{
    int		cw;

    msg_didout = TRUE;		
    cw = (*mb_ptr2cells)(s);
    if (cw > 1 && (  cmdmsg_rl ? msg_col <= 1 :


		msg_col == Columns - 1))
    {
	
	msg_screen_putchar('>', HL_ATTR(HLF_AT));
	return s;
    }

    screen_puts_len(s, l, msg_row, msg_col, attr);

    if (cmdmsg_rl)
    {
	msg_col -= cw;
	if (msg_col == 0)
	{
	    msg_col = Columns;
	    ++msg_row;
	}
    }
    else  {

	msg_col += cw;
	if (msg_col >= Columns)
	{
	    msg_col = 0;
	    ++msg_row;
	}
    }
    return s + l;
}


    void msg_puts(char *s)
{
    msg_puts_attr(s, 0);
}

    void msg_puts_title(char *s)
{
    msg_puts_attr(s, HL_ATTR(HLF_T));
}


    static void msg_outtrans_long_len_attr(char_u *longstr, int len, int attr)
{
    int		slen = len;
    int		room;

    room = Columns - msg_col;
    if (len > room && room >= 20)
    {
	slen = (room - 3) / 2;
	msg_outtrans_len_attr(longstr, slen, attr);
	msg_puts_attr("...", HL_ATTR(HLF_8));
    }
    msg_outtrans_len_attr(longstr + len - slen, slen, attr);
}

    void msg_outtrans_long_attr(char_u *longstr, int attr)
{
    msg_outtrans_long_len_attr(longstr, (int)STRLEN(longstr), attr);
}


    void msg_puts_attr(char *s, int attr)
{
    msg_puts_attr_len(s, -1, attr);
}


    static void msg_puts_attr_len(char *str, int maxlen, int attr)
{
    
    redir_write((char_u *)str, maxlen);

    
    if (msg_silent != 0)
	return;

    
    if ((attr & MSG_HIST) && maxlen < 0)
    {
	add_msg_hist((char_u *)str, -1, attr);
	attr &= ~MSG_HIST;
    }

    
    
    
    
    
    if (msg_scrolled != 0 && !msg_scrolled_ign && STRCMP(str, "\r") != 0)
	need_wait_return = TRUE;
    msg_didany = TRUE;		

    
    if (msg_use_printf())
	msg_puts_printf((char_u *)str, maxlen);
    else msg_puts_display((char_u *)str, maxlen, attr, FALSE);
}


    static void msg_puts_display( char_u	*str, int		maxlen, int		attr, int		recurse)




{
    char_u	*s = str;
    char_u	*t_s = str;	
    int		t_col = 0;	
    int		l;
    int		cw;
    char_u	*sb_str = str;
    int		sb_col = msg_col;
    int		wrap;
    int		did_last_char;

    did_wait_return = FALSE;
    while ((maxlen < 0 || (int)(s - str) < maxlen) && *s != NUL)
    {
	
	if (!recurse && msg_row >= Rows - 1 && (*s == '\n' || (  cmdmsg_rl ? ( msg_col <= 1 || (*s == TAB && msg_col <= 7)




		      || (has_mbyte && (*mb_ptr2cells)(s) > 1 && msg_col <= 2))
		    :

		      ((*s != '\r' && msg_col + t_col >= Columns - 1)
		       || (*s == TAB && msg_col + t_col >= ((Columns - 1) & ~7))
		       || (has_mbyte && (*mb_ptr2cells)(s) > 1 && msg_col + t_col >= Columns - 2)))))
	{
	    
	    if (t_col > 0)
		
		t_puts(&t_col, t_s, s, attr);

	    
	    if (msg_no_more && lines_left == 0)
		break;

	    
	    msg_scroll_up();

	    msg_row = Rows - 2;
	    if (msg_col >= Columns)	
		msg_col = Columns - 1;

	    
	    if (*s >= ' '  && !cmdmsg_rl  )



	    {
		if (has_mbyte)
		{
		    if (enc_utf8 && maxlen >= 0)
			
			l = utfc_ptr2len_len(s, (int)((str + maxlen) - s));
		    else l = (*mb_ptr2len)(s);
		    s = screen_puts_mbyte(s, l, attr);
		}
		else msg_screen_putchar(*s++, attr);
		did_last_char = TRUE;
	    }
	    else did_last_char = FALSE;

	    if (p_more)
		
		store_sb_text(&sb_str, s, attr, &sb_col, TRUE);

	    inc_msg_scrolled();
	    need_wait_return = TRUE; 
	    redraw_cmdline = TRUE;
	    if (cmdline_row > 0 && !exmode_active)
		--cmdline_row;

	    
	    if (lines_left > 0)
		--lines_left;
	    if (p_more && lines_left == 0 && State != HITRETURN && !msg_no_more && !exmode_active)
	    {

		if (do_more_prompt(NUL))
		    s = confirm_msg_tail;

		(void)do_more_prompt(NUL);

		if (quit_more)
		    return;
	    }

	    
	    
	    if (did_last_char)
		continue;
	}

	wrap = *s == '\n' || msg_col + t_col >= Columns || (has_mbyte && (*mb_ptr2cells)(s) > 1 && msg_col + t_col >= Columns - 1);


	if (t_col > 0 && (wrap || *s == '\r' || *s == '\b' || *s == '\t' || *s == BELL))
	    
	    t_puts(&t_col, t_s, s, attr);

	if (wrap && p_more && !recurse)
	    
	    store_sb_text(&sb_str, s, attr, &sb_col, TRUE);

	if (*s == '\n')		    
	{
	    msg_didout = FALSE;	    

	    if (cmdmsg_rl)
		msg_col = Columns - 1;
	    else  msg_col = 0;

	    if (++msg_row >= Rows)  
		msg_row = Rows - 1;
	}
	else if (*s == '\r')	    
	{
	    msg_col = 0;
	}
	else if (*s == '\b')	    
	{
	    if (msg_col)
		--msg_col;
	}
	else if (*s == TAB)	    
	{
	    do msg_screen_putchar(' ', attr);
	    while (msg_col & 7);
	}
	else if (*s == BELL)		
	    vim_beep(BO_SH);
	else {
	    if (has_mbyte)
	    {
		cw = (*mb_ptr2cells)(s);
		if (enc_utf8 && maxlen >= 0)
		    
		    l = utfc_ptr2len_len(s, (int)((str + maxlen) - s));
		else l = (*mb_ptr2len)(s);
	    }
	    else {
		cw = 1;
		l = 1;
	    }

	    
	    
	    
	    if (  cmdmsg_rl ||  (cw > 1 && msg_col + t_col >= Columns - 1))



	    {
		if (l > 1)
		    s = screen_puts_mbyte(s, l, attr) - 1;
		else msg_screen_putchar(*s, attr);
	    }
	    else {
		
		if (t_col == 0)
		    t_s = s;
		t_col += cw;
		s += l - 1;
	    }
	}
	++s;
    }

    
    if (t_col > 0)
	t_puts(&t_col, t_s, s, attr);
    if (p_more && !recurse)
	store_sb_text(&sb_str, s, attr, &sb_col, FALSE);

    msg_check();
}


    int message_filtered(char_u *msg)
{
    int match;

    if (cmdmod.cmod_filter_regmatch.regprog == NULL)
	return FALSE;
    match = vim_regexec(&cmdmod.cmod_filter_regmatch, msg, (colnr_T)0);
    return cmdmod.cmod_filter_force ? match : !match;
}


    static void msg_scroll_up(void)
{

    
    
    if (gui.in_use)
	gui_undraw_cursor();

    
    mch_disable_flush();
    screen_del_lines(0, 0, 1, (int)Rows, TRUE, 0, NULL);
    mch_enable_flush();

    if (!can_clear((char_u *)" "))
    {
	
	
	
	screen_fill((int)Rows - 1, (int)Rows, 0, (int)Columns, ' ', ' ', 0);

	
	
	if (ScreenAttrs[LineOffset[Rows - 2] + Columns - 1] == (sattr_T)-1)
	    screen_fill((int)Rows - 2, (int)Rows - 1, (int)Columns - 1, (int)Columns, ' ', ' ', 0);
    }
}


    static void inc_msg_scrolled(void)
{

    if (*get_vim_var_str(VV_SCROLLSTART) == NUL)
    {
	char_u	    *p = SOURCING_NAME;
	char_u	    *tofree = NULL;
	int	    len;

	
	
	if (p == NULL)
	    p = (char_u *)_("Unknown");
	else {
	    len = (int)STRLEN(p) + 40;
	    tofree = alloc(len);
	    if (tofree != NULL)
	    {
		vim_snprintf((char *)tofree, len, _("%s line %ld"), p, (long)SOURCING_LNUM);
		p = tofree;
	    }
	}
	set_vim_var_string(VV_SCROLLSTART, p, -1);
	vim_free(tofree);
    }

    ++msg_scrolled;
    if (must_redraw < VALID)
	must_redraw = VALID;
}


typedef struct msgchunk_S msgchunk_T;
struct msgchunk_S {
    msgchunk_T	*sb_next;
    msgchunk_T	*sb_prev;
    char	sb_eol;		
    int		sb_msg_col;	
    int		sb_attr;	
    char_u	sb_text[1];	
};

static msgchunk_T *last_msgchunk = NULL; 

static msgchunk_T *msg_sb_start(msgchunk_T *mps);

typedef enum {
    SB_CLEAR_NONE = 0, SB_CLEAR_ALL, SB_CLEAR_CMDLINE_BUSY, SB_CLEAR_CMDLINE_DONE } sb_clear_T;





static sb_clear_T do_clear_sb_text = SB_CLEAR_NONE;


    static void store_sb_text( char_u	**sb_str, char_u	*s, int		attr, int		*sb_col, int		finish)





{
    msgchunk_T	*mp;

    if (do_clear_sb_text == SB_CLEAR_ALL || do_clear_sb_text == SB_CLEAR_CMDLINE_DONE)
    {
	clear_sb_text(do_clear_sb_text == SB_CLEAR_ALL);
	do_clear_sb_text = SB_CLEAR_NONE;
    }

    if (s > *sb_str)
    {
	mp = alloc(sizeof(msgchunk_T) + (s - *sb_str));
	if (mp != NULL)
	{
	    mp->sb_eol = finish;
	    mp->sb_msg_col = *sb_col;
	    mp->sb_attr = attr;
	    vim_strncpy(mp->sb_text, *sb_str, s - *sb_str);

	    if (last_msgchunk == NULL)
	    {
		last_msgchunk = mp;
		mp->sb_prev = NULL;
	    }
	    else {
		mp->sb_prev = last_msgchunk;
		last_msgchunk->sb_next = mp;
		last_msgchunk = mp;
	    }
	    mp->sb_next = NULL;
	}
    }
    else if (finish && last_msgchunk != NULL)
	last_msgchunk->sb_eol = TRUE;

    *sb_str = s;
    *sb_col = 0;
}


    void may_clear_sb_text(void)
{
    do_clear_sb_text = SB_CLEAR_ALL;
}


    void sb_text_start_cmdline(void)
{
    do_clear_sb_text = SB_CLEAR_CMDLINE_BUSY;
    msg_sb_eol();
}


    void sb_text_end_cmdline(void)
{
    do_clear_sb_text = SB_CLEAR_CMDLINE_DONE;
}


    void clear_sb_text(int all)
{
    msgchunk_T	*mp;
    msgchunk_T	**lastp;

    if (all)
	lastp = &last_msgchunk;
    else {
	if (last_msgchunk == NULL)
	    return;
	lastp = &last_msgchunk->sb_prev;
    }

    while (*lastp != NULL)
    {
	mp = (*lastp)->sb_prev;
	vim_free(*lastp);
	*lastp = mp;
    }
}


    void show_sb_text(void)
{
    msgchunk_T	*mp;

    
    
    mp = msg_sb_start(last_msgchunk);
    if (mp == NULL || mp->sb_prev == NULL)
	vim_beep(BO_MESS);
    else {
	do_more_prompt('G');
	wait_return(FALSE);
    }
}


    static msgchunk_T * msg_sb_start(msgchunk_T *mps)
{
    msgchunk_T *mp = mps;

    while (mp != NULL && mp->sb_prev != NULL && !mp->sb_prev->sb_eol)
	mp = mp->sb_prev;
    return mp;
}


    void msg_sb_eol(void)
{
    if (last_msgchunk != NULL)
	last_msgchunk->sb_eol = TRUE;
}


    static msgchunk_T * disp_sb_line(int row, msgchunk_T *smp)
{
    msgchunk_T	*mp = smp;
    char_u	*p;

    for (;;)
    {
	msg_row = row;
	msg_col = mp->sb_msg_col;
	p = mp->sb_text;
	if (*p == '\n')	    
	    ++p;
	msg_puts_display(p, -1, mp->sb_attr, TRUE);
	if (mp->sb_eol || mp->sb_next == NULL)
	    break;
	mp = mp->sb_next;
    }
    return mp->sb_next;
}


    static void t_puts( int		*t_col, char_u	*t_s, char_u	*s, int		attr)




{
    
    msg_didout = TRUE;		
    screen_puts_len(t_s, (int)(s - t_s), msg_row, msg_col, attr);
    msg_col += *t_col;
    *t_col = 0;
    
    
    if (enc_utf8 && utf_iscomposing(utf_ptr2char(t_s)))
	--msg_col;
    if (msg_col >= Columns)
    {
	msg_col = 0;
	++msg_row;
    }
}


    int msg_use_printf(void)
{
    return (!msg_check_screen()


	    || (!gui.in_use && !termcap_active)

	    || !termcap_active   || (swapping_screen() && !termcap_active)


	       );
}


    static void msg_puts_printf(char_u *str, int maxlen)
{
    char_u	*s = str;
    char_u	*buf = NULL;
    char_u	*p = s;


    if (!(silent_mode && p_verbose == 0))
	mch_settmode(TMODE_COOK);	

    while ((maxlen < 0 || (int)(s - str) < maxlen) && *s != NUL)
    {
	if (!(silent_mode && p_verbose == 0))
	{
	    
	    if (*s == NL)
	    {
		int n = (int)(s - p);

		buf = alloc(n + 3);
		if (buf != NULL)
		{
		    memcpy(buf, p, n);
		    if (!info_message)
			buf[n++] = CAR;
		    buf[n++] = NL;
		    buf[n++] = NUL;
		    if (info_message)   
			mch_msg((char *)buf);
		    else mch_errmsg((char *)buf);
		    vim_free(buf);
		}
		p = s + 1;
	    }
	}

	

	if (cmdmsg_rl)
	{
	    if (*s == CAR || *s == NL)
		msg_col = Columns - 1;
	    else --msg_col;
	}
	else  {

	    if (*s == CAR || *s == NL)
		msg_col = 0;
	    else ++msg_col;
	}
	++s;
    }

    if (*p != NUL && !(silent_mode && p_verbose == 0))
    {
	char_u *tofree = NULL;

	if (maxlen > 0 && STRLEN(p) > (size_t)maxlen)
	{
	    tofree = vim_strnsave(p, (size_t)maxlen);
	    p = tofree;
	}
	if (p != NULL)
	{
	    if (info_message)
		mch_msg((char *)p);
	    else mch_errmsg((char *)p);
	    vim_free(tofree);
	}
    }

    msg_didout = TRUE;	    


    if (!(silent_mode && p_verbose == 0))
	mch_settmode(TMODE_RAW);

}


    static int do_more_prompt(int typed_char)
{
    static int	entered = FALSE;
    int		used_typed_char = typed_char;
    int		oldState = State;
    int		c;

    int		retval = FALSE;

    int		toscroll;
    msgchunk_T	*mp_last = NULL;
    msgchunk_T	*mp;
    int		i;

    
    
    
    if (entered || (State == HITRETURN && typed_char == 0))
	return FALSE;
    entered = TRUE;

    if (typed_char == 'G')
    {
	
	mp_last = msg_sb_start(last_msgchunk);
	for (i = 0; i < Rows - 2 && mp_last != NULL && mp_last->sb_prev != NULL; ++i)
	    mp_last = msg_sb_start(mp_last->sb_prev);
    }

    State = ASKMORE;
    setmouse();
    if (typed_char == NUL)
	msg_moremsg(FALSE);
    for (;;)
    {
	
	if (used_typed_char != NUL)
	{
	    c = used_typed_char;	
	    used_typed_char = NUL;
	}
	else c = get_keystroke();


	if (c == K_MENU)
	{
	    int idx = get_menu_index(current_menu, ASKMORE);

	    
	    
	    
	    if (idx == MENU_INDEX_INVALID)
		continue;
	    c = *current_menu->strings[idx];
	    if (c != NUL && current_menu->strings[idx][1] != NUL)
		ins_typebuf(current_menu->strings[idx] + 1, current_menu->noremap[idx], 0, TRUE, current_menu->silent[idx]);

	}


	toscroll = 0;
	switch (c)
	{
	case BS:		
	case K_BS:
	case 'k':
	case K_UP:
	    toscroll = -1;
	    break;

	case CAR:		
	case NL:
	case 'j':
	case K_DOWN:
	    toscroll = 1;
	    break;

	case 'u':		
	    toscroll = -(Rows / 2);
	    break;

	case 'd':		
	    toscroll = Rows / 2;
	    break;

	case 'b':		
	case K_PAGEUP:
	    toscroll = -(Rows - 1);
	    break;

	case ' ':		
	case 'f':
	case K_PAGEDOWN:
	case K_LEFTMOUSE:
	    toscroll = Rows - 1;
	    break;

	case 'g':		
	    toscroll = -999999;
	    break;

	case 'G':		
	    toscroll = 999999;
	    lines_left = 999999;
	    break;

	case ':':		

	    if (!confirm_msg_used)

	    {
		
		
		typeahead_noflush(':');

		skip_term_loop = TRUE;

		cmdline_row = Rows - 1;		
		skip_redraw = TRUE;		
		need_wait_return = FALSE;	
	    }
	    
	case 'q':		
	case Ctrl_C:
	case ESC:

	    if (confirm_msg_used)
	    {
		
		retval = TRUE;
	    }
	    else  {

		got_int = TRUE;
		quit_more = TRUE;
	    }
	    
	    
	    lines_left = Rows - 1;
	    break;


	case Ctrl_Y:
	    
	    
	    
	    
	    
	    if (clip_star.state == SELECT_DONE)
		clip_copy_modeless_selection(TRUE);
	    continue;

	default:		
	    msg_moremsg(TRUE);
	    continue;
	}

	if (toscroll != 0)
	{
	    if (toscroll < 0)
	    {
		
		if (mp_last == NULL)
		    mp = msg_sb_start(last_msgchunk);
		else if (mp_last->sb_prev != NULL)
		    mp = msg_sb_start(mp_last->sb_prev);
		else mp = NULL;

		
		for (i = 0; i < Rows - 2 && mp != NULL && mp->sb_prev != NULL;
									  ++i)
		    mp = msg_sb_start(mp->sb_prev);

		if (mp != NULL && mp->sb_prev != NULL)
		{
		    
		    for (i = 0; i > toscroll; --i)
		    {
			if (mp == NULL || mp->sb_prev == NULL)
			    break;
			mp = msg_sb_start(mp->sb_prev);
			if (mp_last == NULL)
			    mp_last = msg_sb_start(last_msgchunk);
			else mp_last = msg_sb_start(mp_last->sb_prev);
		    }

		    if (toscroll == -1 && screen_ins_lines(0, 0, 1, (int)Rows, 0, NULL) == OK)
		    {
			
			(void)disp_sb_line(0, mp);
		    }
		    else {
			
			screenclear();
			for (i = 0; mp != NULL && i < Rows - 1; ++i)
			{
			    mp = disp_sb_line(i, mp);
			    ++msg_scrolled;
			}
		    }
		    toscroll = 0;
		}
	    }
	    else {
		
		while (toscroll > 0 && mp_last != NULL)
		{
		    
		    msg_scroll_up();
		    inc_msg_scrolled();
		    screen_fill((int)Rows - 2, (int)Rows - 1, 0, (int)Columns, ' ', ' ', 0);
		    mp_last = disp_sb_line((int)Rows - 2, mp_last);
		    --toscroll;
		}
	    }

	    if (toscroll <= 0)
	    {
		
		screen_fill((int)Rows - 1, (int)Rows, 0, (int)Columns, ' ', ' ', 0);
		msg_moremsg(FALSE);
		continue;
	    }

	    
	    lines_left = toscroll;
	}

	break;
    }

    
    screen_fill((int)Rows - 1, (int)Rows, 0, (int)Columns, ' ', ' ', 0);
    State = oldState;
    setmouse();
    if (quit_more)
    {
	msg_row = Rows - 1;
	msg_col = 0;
    }

    else if (cmdmsg_rl)
	msg_col = Columns - 1;


    entered = FALSE;

    return retval;

    return FALSE;

}











    static void mch_errmsg_c(char *str)
{
    int	    len = (int)STRLEN(str);
    DWORD   nwrite = 0;
    DWORD   mode = 0;
    HANDLE  h = GetStdHandle(STD_ERROR_HANDLE);

    if (GetConsoleMode(h, &mode) && enc_codepage >= 0 && (int)GetConsoleCP() != enc_codepage)
    {
	WCHAR	*w = enc_to_utf16((char_u *)str, &len);

	WriteConsoleW(h, w, len, &nwrite, NULL);
	vim_free(w);
    }
    else {
	fprintf(stderr, "%s", str);
    }
}



    void mch_errmsg(char *str)
{

    int		len;



    
    
    
    if (   (isatty(2) && strcmp("/dev/console", ttyname(2)) != 0)



	    isatty(2)


	    ||    !(gui.in_use || gui.starting)




	    )
    {
	fprintf(stderr, "%s", str);
	return;
    }




    if (!(gui.in_use || gui.starting))

    {
	mch_errmsg_c(str);
	return;
    }



    
    emsg_on_display = FALSE;

    len = (int)STRLEN(str) + 1;
    if (error_ga.ga_growsize == 0)
    {
	error_ga.ga_growsize = 80;
	error_ga.ga_itemsize = 1;
    }
    if (ga_grow(&error_ga, len) == OK)
    {
	mch_memmove((char_u *)error_ga.ga_data + error_ga.ga_len, (char_u *)str, len);

	
	{
	    char_u	*p;

	    p = (char_u *)error_ga.ga_data + error_ga.ga_len;
	    for (;;)
	    {
		p = vim_strchr(p, '\r');
		if (p == NULL)
		    break;
		*p = ' ';
	    }
	}

	--len;		
	error_ga.ga_len += len;
    }

}


    static void mch_msg_c(char *str)
{
    int	    len = (int)STRLEN(str);
    DWORD   nwrite = 0;
    DWORD   mode;
    HANDLE  h = GetStdHandle(STD_OUTPUT_HANDLE);


    if (GetConsoleMode(h, &mode) && enc_codepage >= 0 && (int)GetConsoleCP() != enc_codepage)
    {
	WCHAR	*w = enc_to_utf16((char_u *)str, &len);

	WriteConsoleW(h, w, len, &nwrite, NULL);
	vim_free(w);
    }
    else {
	printf("%s", str);
    }
}



    void mch_msg(char *str)
{

    
    
    
    
    if (   (isatty(2) && strcmp("/dev/console", ttyname(2)) != 0)



	    isatty(2)


	    ||    !(gui.in_use || gui.starting)




	    )
    {
	printf("%s", str);
	return;
    }




    if (!(gui.in_use || gui.starting))

    {
	mch_msg_c(str);
	return;
    }


    mch_errmsg(str);

}



    static void msg_screen_putchar(int c, int attr)
{
    msg_didout = TRUE;		
    screen_putchar(c, msg_row, msg_col, attr);

    if (cmdmsg_rl)
    {
	if (--msg_col == 0)
	{
	    msg_col = Columns;
	    ++msg_row;
	}
    }
    else  {

	if (++msg_col >= Columns)
	{
	    msg_col = 0;
	    ++msg_row;
	}
    }
}

    static void msg_moremsg(int full)
{
    int		attr;
    char_u	*s = (char_u *)_("-- More --");

    attr = HL_ATTR(HLF_M);
    screen_puts(s, (int)Rows - 1, 0, attr);
    if (full)
	screen_puts((char_u *)
		_(" SPACE/d/j: screen/page/line down, b/u/k: up, q: quit "), (int)Rows - 1, vim_strsize(s), attr);
}


    void repeat_message(void)
{
    if (State == ASKMORE)
    {
	msg_moremsg(TRUE);	
	msg_row = Rows - 1;
    }

    else if (State == CONFIRM)
    {
	display_confirm_msg();	
	msg_row = Rows - 1;
    }

    else if (State == EXTERNCMD)
    {
	windgoto(msg_row, msg_col); 
    }
    else if (State == HITRETURN || State == SETWSIZE)
    {
	if (msg_row == Rows - 1)
	{
	    
	    
	    
	    msg_didout = FALSE;
	    msg_col = 0;
	    msg_clr_eos();
	}
	hit_return_msg();
	msg_row = Rows - 1;
    }
}


    static int msg_check_screen(void)
{
    if (!full_screen || !screen_valid(FALSE))
	return FALSE;

    if (msg_row >= Rows)
	msg_row = Rows - 1;
    if (msg_col >= Columns)
	msg_col = Columns - 1;
    return TRUE;
}


    void msg_clr_eos(void)
{
    if (msg_silent == 0)
	msg_clr_eos_force();
}


    void msg_clr_eos_force(void)
{
    if (msg_use_printf())
    {
	if (full_screen)	
	{
	    if (*T_CD)
		out_str(T_CD);	
	    else if (*T_CE)
		out_str(T_CE);	
	}
    }
    else {

	if (cmdmsg_rl)
	{
	    screen_fill(msg_row, msg_row + 1, 0, msg_col + 1, ' ', ' ', 0);
	    screen_fill(msg_row + 1, (int)Rows, 0, (int)Columns, ' ', ' ', 0);
	}
	else  {

	    screen_fill(msg_row, msg_row + 1, msg_col, (int)Columns, ' ', ' ', 0);
	    screen_fill(msg_row + 1, (int)Rows, 0, (int)Columns, ' ', ' ', 0);
	}
    }
}


    void msg_clr_cmdline(void)
{
    msg_row = cmdline_row;
    msg_col = 0;
    msg_clr_eos_force();
}


    int msg_end(void)
{
    
    if (!exiting && need_wait_return && !(State & CMDLINE))
    {
	wait_return(FALSE);
	return FALSE;
    }
    out_flush();
    return TRUE;
}


    void msg_check(void)
{
    if (msg_row == Rows - 1 && msg_col >= sc_col)
    {
	need_wait_return = TRUE;
	redraw_cmdline = TRUE;
    }
}


    static void redir_write(char_u *str, int maxlen)
{
    char_u	*s = str;
    static int	cur_col = 0;

    
    if (redir_off)
	return;

    
    if (*p_vfile != NUL && verbose_fd == NULL)
	verbose_open();

    if (redirecting())
    {
	
	if (*s != '\n' && *s != '\r')
	{
	    while (cur_col < msg_col)
	    {

		if (redir_execute)
		    execute_redir_str((char_u *)" ", -1);
		else if (redir_reg)
		    write_reg_contents(redir_reg, (char_u *)" ", -1, TRUE);
		else if (redir_vname)
		    var_redir_str((char_u *)" ", -1);
		else  if (redir_fd != NULL)

		    fputs(" ", redir_fd);
		if (verbose_fd != NULL)
		    fputs(" ", verbose_fd);
		++cur_col;
	    }
	}


	if (redir_execute)
	    execute_redir_str(s, maxlen);
	else if (redir_reg)
	    write_reg_contents(redir_reg, s, maxlen, TRUE);
	else if (redir_vname)
	    var_redir_str(s, maxlen);


	
	while (*s != NUL && (maxlen < 0 || (int)(s - str) < maxlen))
	{

	    if (!redir_reg && !redir_vname && !redir_execute)

		if (redir_fd != NULL)
		    putc(*s, redir_fd);
	    if (verbose_fd != NULL)
		putc(*s, verbose_fd);
	    if (*s == '\r' || *s == '\n')
		cur_col = 0;
	    else if (*s == '\t')
		cur_col += (8 - cur_col % 8);
	    else ++cur_col;
	    ++s;
	}

	if (msg_silent != 0)	
	    msg_col = cur_col;
    }
}

    int redirecting(void)
{
    return redir_fd != NULL || *p_vfile != NUL  || redir_reg || redir_vname || redir_execute  ;



}


    void verbose_enter(void)
{
    if (*p_vfile != NUL)
	++msg_silent;
}


    void verbose_leave(void)
{
    if (*p_vfile != NUL)
	if (--msg_silent < 0)
	    msg_silent = 0;
}


    void verbose_enter_scroll(void)
{
    if (*p_vfile != NUL)
	++msg_silent;
    else  msg_scroll = TRUE;

}


    void verbose_leave_scroll(void)
{
    if (*p_vfile != NUL)
    {
	if (--msg_silent < 0)
	    msg_silent = 0;
    }
    else cmdline_row = msg_row;
}


    void verbose_stop(void)
{
    if (verbose_fd != NULL)
    {
	fclose(verbose_fd);
	verbose_fd = NULL;
    }
    verbose_did_open = FALSE;
}


    int verbose_open(void)
{
    if (verbose_fd == NULL && !verbose_did_open)
    {
	
	verbose_did_open = TRUE;

	verbose_fd = mch_fopen((char *)p_vfile, "a");
	if (verbose_fd == NULL)
	{
	    semsg(_(e_cant_open_file_str), p_vfile);
	    return FAIL;
	}
    }
    return OK;
}


    void give_warning(char_u *message, int hl)
{
    give_warning_with_source(message, hl, FALSE);
}

    void give_warning_with_source(char_u *message, int hl, int with_source)
{
    
    if (msg_silent != 0)
	return;

    
    ++no_wait_return;


    set_vim_var_string(VV_WARNINGMSG, message, -1);

    VIM_CLEAR(keep_msg);
    if (hl)
	keep_msg_attr = HL_ATTR(HLF_W);
    else keep_msg_attr = 0;

    if (with_source)
    {
	
	
	msg_start();
	msg_source(HL_ATTR(HLF_W));
	msg_puts(" ");
	msg_puts_attr((char *)message, HL_ATTR(HLF_W) | MSG_HIST);
	msg_clr_eos();
	(void)msg_end();
    }
    else if (msg_attr((char *)message, keep_msg_attr) && msg_scrolled == 0)
	set_keep_msg(message, keep_msg_attr);

    msg_didout = FALSE;	    
    msg_nowait = TRUE;	    
    msg_col = 0;

    --no_wait_return;
}


    void give_warning2(char_u *message, char_u *a1, int hl)
{
    if (IObuff == NULL)
    {
	
	
	give_warning((char_u *)message, hl);
    }
    else {
	vim_snprintf((char *)IObuff, IOSIZE, (char *)message, a1);
	give_warning(IObuff, hl);
    }
}



    void msg_advance(int col)
{
    if (msg_silent != 0)	
    {
	msg_col = col;		
	return;
    }
    if (col >= Columns)		
	col = Columns - 1;

    if (cmdmsg_rl)
	while (msg_col > Columns - col)
	    msg_putchar(' ');
    else  while (msg_col < col)

	    msg_putchar(' ');
}



    int do_dialog( int		type UNUSED, char_u	*title UNUSED, char_u	*message, char_u	*buttons, int		dfltbutton, char_u	*textfield UNUSED,  int		ex_cmd)








			    
{
    int		oldState;
    int		retval = 0;
    char_u	*hotkeys;
    int		c;
    int		i;
    tmode_T	save_tmode;


    
    if (silent_mode)
	return dfltbutton;   



    
    if (gui.in_use && vim_strchr(p_go, GO_CONDIALOG) == NULL)
    {
	c = gui_mch_dialog(type, title, message, buttons, dfltbutton, textfield, ex_cmd);
	
	need_wait_return = FALSE;
	emsg_on_display = FALSE;
	cmdline_row = msg_row;

	
	
	out_flush();
	gui_mch_update();

	return c;
    }


    oldState = State;
    State = CONFIRM;
    setmouse();

    
    save_tmode = cur_tmode;
    settmode(TMODE_RAW);

    
    ++no_wait_return;
    hotkeys = msg_show_console_dialog(message, buttons, dfltbutton);

    if (hotkeys != NULL)
    {
	for (;;)
	{
	    
	    c = get_keystroke();
	    switch (c)
	    {
	    case CAR:		
	    case NL:
		retval = dfltbutton;
		break;
	    case Ctrl_C:	
	    case ESC:
		retval = 0;
		break;
	    default:		
		if (c < 0)	
		    continue;
		if (c == ':' && ex_cmd)
		{
		    retval = dfltbutton;
		    ins_char_typebuf(':', 0);
		    break;
		}

		
		c = MB_TOLOWER(c);
		retval = 1;
		for (i = 0; hotkeys[i]; ++i)
		{
		    if (has_mbyte)
		    {
			if ((*mb_ptr2char)(hotkeys + i) == c)
			    break;
			i += (*mb_ptr2len)(hotkeys + i) - 1;
		    }
		    else if (hotkeys[i] == c)
			    break;
		    ++retval;
		}
		if (hotkeys[i])
		    break;
		
		continue;
	    }
	    break;
	}

	vim_free(hotkeys);
    }

    settmode(save_tmode);
    State = oldState;
    setmouse();
    --no_wait_return;
    msg_end_prompt();

    return retval;
}


    static int copy_char( char_u	*from, char_u	*to, int		lowercase)



{
    int		len;
    int		c;

    if (has_mbyte)
    {
	if (lowercase)
	{
	    c = MB_TOLOWER((*mb_ptr2char)(from));
	    return (*mb_char2bytes)(c, to);
	}
	else {
	    len = (*mb_ptr2len)(from);
	    mch_memmove(to, from, (size_t)len);
	    return len;
	}
    }
    else {
	if (lowercase)
	    *to = (char_u)TOLOWER_LOC(*from);
	else *to = *from;
	return 1;
    }
}


    static char_u * msg_show_console_dialog( char_u	*message, char_u	*buttons, int		dfltbutton)



{
    int		len = 0;

    int		lenhotkey = HOTK_LEN;	
    char_u	*hotk = NULL;
    char_u	*msgp = NULL;
    char_u	*hotkp = NULL;
    char_u	*r;
    int		copy;

    char_u	has_hotkey[HAS_HOTKEY_LEN];
    int		first_hotkey = FALSE;	
    int		idx;

    has_hotkey[0] = FALSE;

    
    for (copy = 0; copy <= 1; ++copy)
    {
	r = buttons;
	idx = 0;
	while (*r)
	{
	    if (*r == DLG_BUTTON_SEP)
	    {
		if (copy)
		{
		    *msgp++ = ',';
		    *msgp++ = ' ';	    

		    
		    if (has_mbyte)
			hotkp += STRLEN(hotkp);
		    else ++hotkp;
		    hotkp[copy_char(r + 1, hotkp, TRUE)] = NUL;
		    if (dfltbutton)
			--dfltbutton;

		    
		    if (idx < HAS_HOTKEY_LEN - 1 && !has_hotkey[++idx])
			first_hotkey = TRUE;
		}
		else {
		    len += 3;		    
		    lenhotkey += HOTK_LEN;  
		    if (idx < HAS_HOTKEY_LEN - 1)
			has_hotkey[++idx] = FALSE;
		}
	    }
	    else if (*r == DLG_HOTKEY_CHAR || first_hotkey)
	    {
		if (*r == DLG_HOTKEY_CHAR)
		    ++r;
		first_hotkey = FALSE;
		if (copy)
		{
		    if (*r == DLG_HOTKEY_CHAR)		
			*msgp++ = *r;
		    else {
			
			*msgp++ = (dfltbutton == 1) ? '[' : '(';
			msgp += copy_char(r, msgp, FALSE);
			*msgp++ = (dfltbutton == 1) ? ']' : ')';

			
			hotkp[copy_char(r, hotkp, TRUE)] = NUL;
		    }
		}
		else {
		    ++len;	    
		    if (idx < HAS_HOTKEY_LEN - 1)
			has_hotkey[idx] = TRUE;
		}
	    }
	    else {
		
		if (copy)
		    msgp += copy_char(r, msgp, FALSE);
	    }

	    
	    MB_PTR_ADV(r);
	}

	if (copy)
	{
	    *msgp++ = ':';
	    *msgp++ = ' ';
	    *msgp = NUL;
	}
	else {
	    len += (int)(STRLEN(message)
			+ 2			 + STRLEN(buttons)
			+ 3);			
	    lenhotkey++;			

	    
	    if (!has_hotkey[0])
	    {
		first_hotkey = TRUE;
		len += 2;		
	    }

	    
	    vim_free(confirm_msg);
	    confirm_msg = alloc(len);
	    if (confirm_msg == NULL)
		return NULL;
	    *confirm_msg = NUL;
	    hotk = alloc(lenhotkey);
	    if (hotk == NULL)
		return NULL;

	    *confirm_msg = '\n';
	    STRCPY(confirm_msg + 1, message);

	    msgp = confirm_msg + 1 + STRLEN(message);
	    hotkp = hotk;

	    
	    
	    hotkp[copy_char(buttons, hotkp, TRUE)] = NUL;

	    
	    
	    confirm_msg_tail = msgp;
	    *msgp++ = '\n';
	}
    }

    display_confirm_msg();
    return hotk;
}


    static void display_confirm_msg(void)
{
    
    ++confirm_msg_used;
    if (confirm_msg != NULL)
	msg_puts_attr((char *)confirm_msg, HL_ATTR(HLF_M));
    --confirm_msg_used;
}





    int vim_dialog_yesno( int		type, char_u	*title, char_u	*message, int		dflt)




{
    if (do_dialog(type, title == NULL ? (char_u *)_("Question") : title, message, (char_u *)_("&Yes\n&No"), dflt, NULL, FALSE) == 1)


	return VIM_YES;
    return VIM_NO;
}

    int vim_dialog_yesnocancel( int		type, char_u	*title, char_u	*message, int		dflt)




{
    switch (do_dialog(type, title == NULL ? (char_u *)_("Question") : title, message, (char_u *)_("&Yes\n&No\n&Cancel"), dflt, NULL, FALSE))


    {
	case 1: return VIM_YES;
	case 2: return VIM_NO;
    }
    return VIM_CANCEL;
}

    int vim_dialog_yesnoallcancel( int		type, char_u	*title, char_u	*message, int		dflt)




{
    switch (do_dialog(type, title == NULL ? (char_u *)"Question" : title, message, (char_u *)_("&Yes\n&No\nSave &All\n&Discard All\n&Cancel"), dflt, NULL, FALSE))



    {
	case 1: return VIM_YES;
	case 2: return VIM_NO;
	case 3: return VIM_ALL;
	case 4: return VIM_DISCARDALL;
    }
    return VIM_CANCEL;
}


