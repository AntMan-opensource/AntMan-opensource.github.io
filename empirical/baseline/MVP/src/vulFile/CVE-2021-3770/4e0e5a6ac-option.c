







static void set_options_default(int opt_flags);
static void set_string_default_esc(char *name, char_u *val, int escape);
static char_u *find_dup_item(char_u *origval, char_u *newval, long_u flags);
static char_u *option_expand(int opt_idx, char_u *val);
static void didset_options(void);
static void didset_options2(void);

static long_u *insecure_flag(int opt_idx, int opt_flags);



static char *set_bool_option(int opt_idx, char_u *varp, int value, int opt_flags);
static char *set_num_option(int opt_idx, char_u *varp, long value, char *errbuf, size_t errbuflen, int opt_flags);
static int find_key_option(char_u *arg_arg, int has_lt);
static void showoptions(int all, int opt_flags);
static int optval_default(struct vimoption *, char_u *varp, int compatible);
static void showoneopt(struct vimoption *, int opt_flags);
static int put_setstring(FILE *fd, char *cmd, char *name, char_u **valuep, long_u flags);
static int put_setnum(FILE *fd, char *cmd, char *name, long *valuep);
static int put_setbool(FILE *fd, char *cmd, char *name, int value);
static int istermoption(struct vimoption *p);
static char_u *get_varp_scope(struct vimoption *p, int opt_flags);
static char_u *get_varp(struct vimoption *);
static void check_win_options(win_T *win);
static void option_value2string(struct vimoption *, int opt_flags);
static void check_winopt(winopt_T *wop);
static int wc_use_keyname(char_u *varp, long *wcp);
static void paste_option_changed(void);
static void compatible_set(void);


    void set_init_1(int clean_arg)
{
    char_u	*p;
    int		opt_idx;
    long_u	n;


    langmap_init();


    
    p_cp = TRUE;

    
    if (mch_getenv((char_u *)"VIM_POSIX") != NULL)
    {
	set_string_default("cpo", (char_u *)CPO_ALL);
	set_string_default("shm", (char_u *)SHM_POSIX);
    }

    
    if (((p = mch_getenv((char_u *)"SHELL")) != NULL && *p != NUL)

	    || ((p = mch_getenv((char_u *)"COMSPEC")) != NULL && *p != NUL)
	    || ((p = (char_u *)default_shell()) != NULL && *p != NUL)

	    )

    {
	
	char_u	    *cmd;
	size_t	    len;

	if (vim_strchr(p, ' ') != NULL)
	{
	    len = STRLEN(p) + 3;  
	    cmd = alloc(len);
	    if (cmd != NULL)
	    {
		vim_snprintf((char *)cmd, len, "\"%s\"", p);
		set_string_default("sh", cmd);
		vim_free(cmd);
	    }
	}
	else set_string_default("sh", p);
    }

	set_string_default_esc("sh", p, TRUE);



    
    {

	static char	*(names[4]) = {"", "TMPDIR", "TEMP", "TMP";

	static char	*(names[3]) = {"TMPDIR", "TEMP", "TMP";

	int		len;
	garray_T	ga;
	int		mustfree;
	char_u		*item;

	opt_idx = findoption((char_u *)"backupskip");

	ga_init2(&ga, 1, 100);
	for (n = 0; n < (long)ARRAY_LENGTH(names); ++n)
	{
	    mustfree = FALSE;

	    if (*names[n] == NUL)

		p = (char_u *)"/private/tmp";

		p = (char_u *)"/tmp";

	    else  p = vim_getenv((char_u *)names[n], &mustfree);

	    if (p != NULL && *p != NUL)
	    {
		
		len = (int)STRLEN(p) + 3;
		item = alloc(len);
		STRCPY(item, p);
		add_pathsep(item);
		STRCAT(item, "*");
		if (find_dup_item(ga.ga_data, item, options[opt_idx].flags)
									== NULL && ga_grow(&ga, len) == OK)
		{
		    if (ga.ga_len > 0)
			STRCAT(ga.ga_data, ",");
		    STRCAT(ga.ga_data, item);
		    ga.ga_len += len;
		}
		vim_free(item);
	    }
	    if (mustfree)
		vim_free(p);
	}
	if (ga.ga_data != NULL)
	{
	    set_string_default("bsk", ga.ga_data);
	    vim_free(ga.ga_data);
	}
    }


    
    opt_idx = findoption((char_u *)"maxmemtot");
    if (opt_idx >= 0)
    {

	if (options[opt_idx].def_val[VI_DEFAULT] == (char_u *)0L)

	{

	    
	    n = (mch_avail_mem(FALSE) >> 1);


	    
	    n = (mch_total_mem(FALSE) >> 1);

	    n = (0x7fffffff >> 11);


	    options[opt_idx].def_val[VI_DEFAULT] = (char_u *)n;
	    opt_idx = findoption((char_u *)"maxmem");
	    if (opt_idx >= 0)
	    {

		if ((long)(long_i)options[opt_idx].def_val[VI_DEFAULT] > (long)n || (long)(long_i)options[opt_idx].def_val[VI_DEFAULT] == 0L)

		    options[opt_idx].def_val[VI_DEFAULT] = (char_u *)n;
	    }
	}
    }


    {
	char_u	*cdpath;
	char_u	*buf;
	int	i;
	int	j;
	int	mustfree = FALSE;

	
	cdpath = vim_getenv((char_u *)"CDPATH", &mustfree);
	if (cdpath != NULL)
	{
	    buf = alloc((STRLEN(cdpath) << 1) + 2);
	    if (buf != NULL)
	    {
		buf[0] = ',';	    
		j = 1;
		for (i = 0; cdpath[i] != NUL; ++i)
		{
		    if (vim_ispathlistsep(cdpath[i]))
			buf[j++] = ',';
		    else {
			if (cdpath[i] == ' ' || cdpath[i] == ',')
			    buf[j++] = '\\';
			buf[j++] = cdpath[i];
		    }
		}
		buf[j] = NUL;
		opt_idx = findoption((char_u *)"cdpath");
		if (opt_idx >= 0)
		{
		    options[opt_idx].def_val[VI_DEFAULT] = buf;
		    options[opt_idx].flags |= P_DEF_ALLOCED;
		}
		else vim_free(buf);
	    }
	    if (mustfree)
		vim_free(cdpath);
	}
    }



    
    set_string_default("penc",  (char_u *)"cp1252"   (char_u *)"dec-mcs"   (char_u *)"ebcdic-uk"   (char_u *)"mac-roman"  (char_u *)"hp-roman8"     );




















    
    set_string_default("pexpr",  (char_u *)"system('copy' . ' ' . v:fname_in . (&printdevice == '' ? ' LPT1:' : (' \"' . &printdevice . '\"'))) . delete(v:fname_in)"   (char_u *)"system('print/delete' . (&printdevice == '' ? '' : ' /queue=' . &printdevice) . ' ' . v:fname_in)"   (char_u *)"system('lpr' . (&printdevice == '' ? '' : ' -P' . &printdevice) . ' ' . v:fname_in) . delete(v:fname_in) + v:shell_error"   );












    
    set_options_default(0);


    if (clean_arg)
    {
	opt_idx = findoption((char_u *)"runtimepath");
	if (opt_idx >= 0)
	{
	    options[opt_idx].def_val[VI_DEFAULT] = (char_u *)CLEAN_RUNTIMEPATH;
	    p_rtp = (char_u *)CLEAN_RUNTIMEPATH;
	}
	opt_idx = findoption((char_u *)"packpath");
	if (opt_idx >= 0)
	{
	    options[opt_idx].def_val[VI_DEFAULT] = (char_u *)CLEAN_RUNTIMEPATH;
	    p_pp = (char_u *)CLEAN_RUNTIMEPATH;
	}
    }



    if (found_reverse_arg)
	set_option_value((char_u *)"bg", 0L, (char_u *)"dark", 0);


    curbuf->b_p_initialized = TRUE;
    curbuf->b_p_ar = -1;	
    curbuf->b_p_ul = NO_LOCAL_UNDOLEVEL;
    check_buf_options(curbuf);
    check_win_options(curwin);
    check_options();

    
    didset_options();


    
    
    init_spell_chartab();


    
    for (opt_idx = 0; !istermoption_idx(opt_idx); opt_idx++)
    {
	if ((options[opt_idx].flags & P_GETTEXT)
					      && options[opt_idx].var != NULL)
	    p = (char_u *)_(*(char **)options[opt_idx].var);
	else p = option_expand(opt_idx, NULL);
	if (p != NULL && (p = vim_strsave(p)) != NULL)
	{
	    *(char_u **)options[opt_idx].var = p;
	    
	    
	    
	    
	    if (options[opt_idx].flags & P_DEF_ALLOCED)
		vim_free(options[opt_idx].def_val[VI_DEFAULT]);
	    options[opt_idx].def_val[VI_DEFAULT] = p;
	    options[opt_idx].flags |= P_DEF_ALLOCED;
	}
    }

    save_file_ff(curbuf);	


    
    
    
    
    
    if (mch_getenv((char_u *)"MLTERM") != NULL)
	set_option_value((char_u *)"tbidi", 1L, NULL, 0);


    didset_options2();


    
    if (mch_getenv((char_u *)"LANG") == NULL)
    {
	char	buf[20];

	
	
	
	n = GetLocaleInfo(LOCALE_USER_DEFAULT, LOCALE_SABBREVLANGNAME, (LPTSTR)buf, 20);
	if (n >= 2 && STRNICMP(buf, "en", 2) != 0)
	{
	    
	    if (STRNICMP(buf, "cht", 3) == 0 || STRNICMP(buf, "zht", 3) == 0)
		STRCPY(buf, "zh_TW");
	    else if (STRNICMP(buf, "chs", 3) == 0 || STRNICMP(buf, "zhc", 3) == 0)
		STRCPY(buf, "zh_CN");
	    else if (STRNICMP(buf, "jp", 2) == 0)
		STRCPY(buf, "ja");
	    else buf[2] = NUL;
	    vim_setenv((char_u *)"LANG", (char_u *)buf);
	}
    }


    
    mac_lang_init();




    
    
    p = vim_strsave((char_u *)ENC_DFLT);

    
    
    p = enc_locale();

    if (p != NULL)
    {
	char_u *save_enc;

	
	
	save_enc = p_enc;
	p_enc = p;
	if (STRCMP(p_enc, "gb18030") == 0)
	{
	    
	    
	    
	    p_enc = vim_strsave((char_u *)"cp936");
	    vim_free(p);
	}
	if (mb_init() == NULL)
	{
	    opt_idx = findoption((char_u *)"encoding");
	    if (opt_idx >= 0)
	    {
		options[opt_idx].def_val[VI_DEFAULT] = p_enc;
		options[opt_idx].flags |= P_DEF_ALLOCED;
	    }


	    if (STRCMP(p_enc, "latin1") == 0 || enc_utf8)
	    {
		
		
		
		set_string_option_direct((char_u *)"isp", -1, ISP_LATIN1, OPT_FREE, SID_NONE);
		set_string_option_direct((char_u *)"isk", -1, ISK_LATIN1, OPT_FREE, SID_NONE);
		opt_idx = findoption((char_u *)"isp");
		if (opt_idx >= 0)
		    options[opt_idx].def_val[VIM_DEFAULT] = ISP_LATIN1;
		opt_idx = findoption((char_u *)"isk");
		if (opt_idx >= 0)
		    options[opt_idx].def_val[VIM_DEFAULT] = ISK_LATIN1;
		(void)init_chartab();
	    }



	    
	    
	    if (  (!gui.in_use && !gui.starting) &&  GetACP() != GetConsoleCP())



	    {
		char	buf[50];

		
		
		if (GetConsoleCP() == 0)
		    sprintf(buf, "cp%ld", (long)GetACP());
		else sprintf(buf, "cp%ld", (long)GetConsoleCP());
		p_tenc = vim_strsave((char_u *)buf);
		if (p_tenc != NULL)
		{
		    opt_idx = findoption((char_u *)"termencoding");
		    if (opt_idx >= 0)
		    {
			options[opt_idx].def_val[VI_DEFAULT] = p_tenc;
			options[opt_idx].flags |= P_DEF_ALLOCED;
		    }
		    convert_setup(&input_conv, p_tenc, p_enc);
		    convert_setup(&output_conv, p_enc, p_tenc);
		}
		else p_tenc = empty_option;
	    }


	    
	    init_homedir();

	}
	else {
	    vim_free(p_enc);
	    p_enc = save_enc;
	}
    }


    
    set_helplang_default(get_mess_lang());

}

static char_u *fencs_utf8_default = (char_u *)"ucs-bom,utf-8,default,latin1";


    void set_fencs_unicode()
{
    set_string_option_direct((char_u *)"fencs", -1, fencs_utf8_default, OPT_FREE, 0);
}


    static void set_option_default( int		opt_idx, int		opt_flags, int		compatible)



{
    char_u	*varp;		
    int		dvi;		
    long_u	flags;
    long_u	*flagsp;
    int		both = (opt_flags & (OPT_LOCAL | OPT_GLOBAL)) == 0;

    varp = get_varp_scope(&(options[opt_idx]), both ? OPT_LOCAL : opt_flags);
    flags = options[opt_idx].flags;
    if (varp != NULL)	    
    {
	dvi = ((flags & P_VI_DEF) || compatible) ? VI_DEFAULT : VIM_DEFAULT;
	if (flags & P_STRING)
	{
	    
	    if (options[opt_idx].var == (char_u *)&p_fencs && enc_utf8)
		set_fencs_unicode();
	    
	    
	    else if (options[opt_idx].indir != PV_NONE)
		set_string_option_direct(NULL, opt_idx, options[opt_idx].def_val[dvi], opt_flags, 0);
	    else {
		if ((opt_flags & OPT_FREE) && (flags & P_ALLOCED))
		    free_string_option(*(char_u **)(varp));
		*(char_u **)varp = options[opt_idx].def_val[dvi];
		options[opt_idx].flags &= ~P_ALLOCED;
	    }
	}
	else if (flags & P_NUM)
	{
	    if (options[opt_idx].indir == PV_SCROLL)
		win_comp_scroll(curwin);
	    else {
		long def_val = (long)(long_i)options[opt_idx].def_val[dvi];

		if ((long *)varp == &curwin->w_p_so || (long *)varp == &curwin->w_p_siso)
		    
		    
		    *(long *)varp = -1;
		else *(long *)varp = def_val;
		
		if (both)
		    *(long *)get_varp_scope(&(options[opt_idx]), OPT_GLOBAL) = def_val;
	    }
	}
	else	 {
	    
	    
	    *(int *)varp = (int)(long)(long_i)options[opt_idx].def_val[dvi];

	    
	    if (options[opt_idx].indir == PV_ML && getuid() == ROOT_UID)
		*(int *)varp = FALSE;

	    
	    if (both)
		*(int *)get_varp_scope(&(options[opt_idx]), OPT_GLOBAL) = *(int *)varp;
	}

	
	flagsp = insecure_flag(opt_idx, opt_flags);
	*flagsp = *flagsp & ~P_INSECURE;
    }


    set_option_sctx_idx(opt_idx, opt_flags, current_sctx);

}


    static void set_options_default( int		opt_flags)

{
    int		i;
    win_T	*wp;
    tabpage_T	*tp;

    for (i = 0; !istermoption_idx(i); i++)
	if (!(options[i].flags & P_NODEFAULT)
		&& (opt_flags == 0 || (options[i].var != (char_u *)&p_enc  && options[i].var != (char_u *)&p_cm && options[i].var != (char_u *)&p_key  )))





	    set_option_default(i, opt_flags, p_cp);

    
    FOR_ALL_TAB_WINDOWS(tp, wp)
	win_comp_scroll(wp);

    parse_cino(curbuf);

}


    static void set_string_default_esc(char *name, char_u *val, int escape)
{
    char_u	*p;
    int		opt_idx;

    if (escape && vim_strchr(val, ' ') != NULL)
	p = vim_strsave_escaped(val, (char_u *)" ");
    else p = vim_strsave(val);
    if (p != NULL)		
    {
	opt_idx = findoption((char_u *)name);
	if (opt_idx >= 0)
	{
	    if (options[opt_idx].flags & P_DEF_ALLOCED)
		vim_free(options[opt_idx].def_val[VI_DEFAULT]);
	    options[opt_idx].def_val[VI_DEFAULT] = p;
	    options[opt_idx].flags |= P_DEF_ALLOCED;
	}
    }
}

    void set_string_default(char *name, char_u *val)
{
    set_string_default_esc(name, val, FALSE);
}


    static char_u * find_dup_item(char_u *origval, char_u *newval, long_u flags)
{
    int	    bs = 0;
    size_t  newlen;
    char_u  *s;

    if (origval == NULL)
	return NULL;

    newlen = STRLEN(newval);
    for (s = origval; *s != NUL; ++s)
    {
	if ((!(flags & P_COMMA)
		    || s == origval || (s[-1] == ',' && !(bs & 1)))
		&& STRNCMP(s, newval, newlen) == 0 && (!(flags & P_COMMA)
		    || s[newlen] == ',' || s[newlen] == NUL))
	    return s;
	
	
	
	if ((s > origval + 1 && s[-1] == '\\' && s[-2] != ',')

		|| (s == origval + 1 && s[-1] == '\\'))
	    ++bs;
	else bs = 0;
    }
    return NULL;
}


    void set_number_default(char *name, long val)
{
    int		opt_idx;

    opt_idx = findoption((char_u *)name);
    if (opt_idx >= 0)
	options[opt_idx].def_val[VI_DEFAULT] = (char_u *)(long_i)val;
}


    void set_local_options_default(win_T *wp, int do_buffer)
{
    win_T	*save_curwin = curwin;
    int		i;

    curwin = wp;
    curbuf = curwin->w_buffer;
    block_autocmds();

    for (i = 0; !istermoption_idx(i); i++)
    {
	struct vimoption    *p = &(options[i]);
	char_u		    *varp = get_varp_scope(p, OPT_LOCAL);

	if (p->indir != PV_NONE && (do_buffer || (p->indir & PV_BUF) == 0)
		&& !(options[i].flags & P_NODEFAULT)
		&& !optval_default(p, varp, FALSE))
	    set_option_default(i, OPT_FREE|OPT_LOCAL, FALSE);
    }

    unblock_autocmds();
    curwin = save_curwin;
    curbuf = curwin->w_buffer;
}



    void free_all_options(void)
{
    int		i;

    for (i = 0; !istermoption_idx(i); i++)
    {
	if (options[i].indir == PV_NONE)
	{
	    
	    if ((options[i].flags & P_ALLOCED) && options[i].var != NULL)
		free_string_option(*(char_u **)options[i].var);
	    if (options[i].flags & P_DEF_ALLOCED)
		free_string_option(options[i].def_val[VI_DEFAULT]);
	}
	else if (options[i].var != VAR_WIN && (options[i].flags & P_STRING))
	    
	    clear_string_option((char_u **)options[i].var);
    }
}




    void set_init_2(void)
{
    int		idx;

    
    idx = findoption((char_u *)"scroll");
    if (idx >= 0 && !(options[idx].flags & P_WAS_SET))
	set_option_default(idx, OPT_LOCAL, p_cp);
    comp_col();

    
    if (!option_was_set((char_u *)"window"))
	p_window = Rows - 1;
    set_number_default("window", Rows - 1);

    

    
    idx = findoption((char_u *)"bg");
    if (idx >= 0 && !(options[idx].flags & P_WAS_SET)
						 && *term_bg_default() == 'd')
    {
	set_string_option_direct(NULL, idx, (char_u *)"dark", OPT_FREE, 0);
	
	
	options[idx].flags &= ~P_WAS_SET;
    }



    parse_shape_opt(SHAPE_CURSOR); 


    parse_shape_opt(SHAPE_MOUSE);  


    (void)parse_printoptions();	    

}


    void set_init_3(void)
{


    char_u  *p;
    int	    idx_srr;
    int	    do_srr;

    int	    idx_sp;
    int	    do_sp;


    idx_srr = findoption((char_u *)"srr");
    if (idx_srr < 0)
	do_srr = FALSE;
    else do_srr = !(options[idx_srr].flags & P_WAS_SET);

    idx_sp = findoption((char_u *)"sp");
    if (idx_sp < 0)
	do_sp = FALSE;
    else do_sp = !(options[idx_sp].flags & P_WAS_SET);

    p = get_isolated_shell_name();
    if (p != NULL)
    {
	
	if (	   fnamecmp(p, "csh") == 0 || fnamecmp(p, "tcsh") == 0  || fnamecmp(p, "csh.exe") == 0 || fnamecmp(p, "tcsh.exe") == 0  )





	{

	    if (do_sp)
	    {

		p_sp = (char_u *)">&";

		p_sp = (char_u *)"|& tee";

		options[idx_sp].def_val[VI_DEFAULT] = p_sp;
	    }

	    if (do_srr)
	    {
		p_srr = (char_u *)">&";
		options[idx_srr].def_val[VI_DEFAULT] = p_srr;
	    }
	}

	
	
	else if (   fnamecmp(p, "powershell") == 0 || fnamecmp(p, "powershell.exe") == 0 )

	{

		if (do_sp)
		{
		    p_sp = (char_u *)"2>&1 | Out-File -Encoding default";
		    options[idx_sp].def_val[VI_DEFAULT] = p_sp;
		}

		if (do_srr)
		{
		    p_srr = (char_u *)"2>&1 | Out-File -Encoding default";
		    options[idx_srr].def_val[VI_DEFAULT] = p_srr;
		}
	}

	else  if (       fnamecmp(p, "sh") == 0 || fnamecmp(p, "ksh") == 0 || fnamecmp(p, "mksh") == 0 || fnamecmp(p, "pdksh") == 0 || fnamecmp(p, "zsh") == 0 || fnamecmp(p, "zsh-beta") == 0 || fnamecmp(p, "bash") == 0 || fnamecmp(p, "fish") == 0 || fnamecmp(p, "ash") == 0 || fnamecmp(p, "dash") == 0 || fnamecmp(p, "pwsh") == 0  || fnamecmp(p, "cmd") == 0 || fnamecmp(p, "sh.exe") == 0 || fnamecmp(p, "ksh.exe") == 0 || fnamecmp(p, "mksh.exe") == 0 || fnamecmp(p, "pdksh.exe") == 0 || fnamecmp(p, "zsh.exe") == 0 || fnamecmp(p, "zsh-beta.exe") == 0 || fnamecmp(p, "bash.exe") == 0 || fnamecmp(p, "cmd.exe") == 0 || fnamecmp(p, "dash.exe") == 0 || fnamecmp(p, "pwsh.exe") == 0  )

























	    {

		if (do_sp)
		{

		    p_sp = (char_u *)">%s 2>&1";

		    if (fnamecmp(p, "pwsh") == 0)
			p_sp = (char_u *)">%s 2>&1";
		    else p_sp = (char_u *)"2>&1| tee";

		    options[idx_sp].def_val[VI_DEFAULT] = p_sp;
		}

		if (do_srr)
		{
		    p_srr = (char_u *)">%s 2>&1";
		    options[idx_srr].def_val[VI_DEFAULT] = p_srr;
		}
	    }
	vim_free(p);
    }



    
    if (strstr((char *)gettail(p_sh), "powershell") != NULL)
    {
	int	idx_opt;

	idx_opt = findoption((char_u *)"shcf");
	if (idx_opt >= 0 && !(options[idx_opt].flags & P_WAS_SET))
	{
	    p_shcf = (char_u*)"-Command";
	    options[idx_opt].def_val[VI_DEFAULT] = p_shcf;
	}

	idx_opt = findoption((char_u *)"sxq");
	if (idx_opt >= 0 && !(options[idx_opt].flags & P_WAS_SET))
	{
	    p_sxq = (char_u*)"\"";
	    options[idx_opt].def_val[VI_DEFAULT] = p_sxq;
	}
    }
    else if (strstr((char *)gettail(p_sh), "sh") != NULL)
    {
	int	idx3;

	idx3 = findoption((char_u *)"shcf");
	if (idx3 >= 0 && !(options[idx3].flags & P_WAS_SET))
	{
	    p_shcf = (char_u *)"-c";
	    options[idx3].def_val[VI_DEFAULT] = p_shcf;
	}

	
	idx3 = findoption((char_u *)"sxq");
	if (idx3 >= 0 && !(options[idx3].flags & P_WAS_SET))
	{
	    p_sxq = (char_u *)"\"";
	    options[idx3].def_val[VI_DEFAULT] = p_sxq;
	}
    }
    else if (strstr((char *)gettail(p_sh), "cmd.exe") != NULL)
    {
	int	idx3;

	
	idx3 = findoption((char_u *)"sxq");
	if (idx3 >= 0 && !(options[idx3].flags & P_WAS_SET))
	{
	    p_sxq = (char_u *)"(";
	    options[idx3].def_val[VI_DEFAULT] = p_sxq;
	}

	idx3 = findoption((char_u *)"shcf");
	if (idx3 >= 0 && !(options[idx3].flags & P_WAS_SET))
	{
	    p_shcf = (char_u *)"/c";
	    options[idx3].def_val[VI_DEFAULT] = p_shcf;
	}
    }


    if (BUFEMPTY())
    {
	int idx_ffs = findoption((char_u *)"ffs");

	
	if (idx_ffs >= 0 && (options[idx_ffs].flags & P_WAS_SET))
	    set_fileformat(default_fileformat(), OPT_LOCAL);
    }


    set_title_defaults();

}



    void set_helplang_default(char_u *lang)
{
    int		idx;

    if (lang == NULL || STRLEN(lang) < 2)	
	return;
    idx = findoption((char_u *)"hlg");
    if (idx >= 0 && !(options[idx].flags & P_WAS_SET))
    {
	if (options[idx].flags & P_ALLOCED)
	    free_string_option(p_hlg);
	p_hlg = vim_strsave(lang);
	if (p_hlg == NULL)
	    p_hlg = empty_option;
	else {
	    
	    if (STRNICMP(p_hlg, "zh_", 3) == 0 && STRLEN(p_hlg) >= 5)
	    {
		p_hlg[0] = TOLOWER_ASC(p_hlg[3]);
		p_hlg[1] = TOLOWER_ASC(p_hlg[4]);
	    }
	    
	    else if (STRLEN(p_hlg) >= 1 && *p_hlg == 'C')
	    {
		p_hlg[0] = 'e';
		p_hlg[1] = 'n';
	    }
	    p_hlg[2] = NUL;
	}
	options[idx].flags |= P_ALLOCED;
    }
}




    void set_title_defaults(void)
{
    int	    idx1;
    long    val;

    
    idx1 = findoption((char_u *)"title");
    if (idx1 >= 0 && !(options[idx1].flags & P_WAS_SET))
    {

	if (gui.starting || gui.in_use)
	    val = TRUE;
	else  val = mch_can_restore_title();

	options[idx1].def_val[VI_DEFAULT] = (char_u *)(long_i)val;
	p_title = val;
    }
    idx1 = findoption((char_u *)"icon");
    if (idx1 >= 0 && !(options[idx1].flags & P_WAS_SET))
    {

	if (gui.starting || gui.in_use)
	    val = TRUE;
	else  val = mch_can_restore_icon();

	options[idx1].def_val[VI_DEFAULT] = (char_u *)(long_i)val;
	p_icon = val;
    }
}


    void ex_set(exarg_T *eap)
{
    int		flags = 0;

    if (eap->cmdidx == CMD_setlocal)
	flags = OPT_LOCAL;
    else if (eap->cmdidx == CMD_setglobal)
	flags = OPT_GLOBAL;

    if ((cmdmod.cmod_flags & CMOD_BROWSE) && flags == 0)
	ex_options(eap);
    else  {

	if (eap->forceit)
	    flags |= OPT_ONECOLUMN;
	(void)do_set(eap->arg, flags);
    }
}


    int do_set( char_u	*arg_start, int		opt_flags)


{
    char_u	*arg = arg_start;
    int		opt_idx;
    char	*errmsg;
    char	errbuf[80];
    char_u	*startarg;
    int		prefix;	
    int		nextchar;	    
    int		afterchar;	    
    int		len;
    int		i;
    varnumber_T	value;
    int		key;
    long_u	flags;		    
    char_u	*varp = NULL;	    
    int		did_show = FALSE;   
    int		adding;		    
    int		prepending;	    
    int		removing;	    
    int		cp_val = 0;
    char_u	key_name[2];

    if (*arg == NUL)
    {
	showoptions(0, opt_flags);
	did_show = TRUE;
	goto theend;
    }

    while (*arg != NUL)		
    {
	errmsg = NULL;
	startarg = arg;		

	if (STRNCMP(arg, "all", 3) == 0 && !isalpha(arg[3])
						&& !(opt_flags & OPT_MODELINE))
	{
	    
	    arg += 3;
	    if (*arg == '&')
	    {
		++arg;
		
		set_options_default(OPT_FREE | opt_flags);
		didset_options();
		didset_options2();
		redraw_all_later(CLEAR);
	    }
	    else {
		showoptions(1, opt_flags);
		did_show = TRUE;
	    }
	}
	else if (STRNCMP(arg, "termcap", 7) == 0 && !(opt_flags & OPT_MODELINE))
	{
	    showoptions(2, opt_flags);
	    show_termcodes();
	    did_show = TRUE;
	    arg += 7;
	}
	else {
	    prefix = 1;
	    if (STRNCMP(arg, "no", 2) == 0 && STRNCMP(arg, "novice", 6) != 0)
	    {
		prefix = 0;
		arg += 2;
	    }
	    else if (STRNCMP(arg, "inv", 3) == 0)
	    {
		prefix = 2;
		arg += 3;
	    }

	    
	    key = 0;
	    if (*arg == '<')
	    {
		opt_idx = -1;
		
		if (arg[1] == 't' && arg[2] == '_' && arg[3] && arg[4])
		    len = 5;
		else {
		    len = 1;
		    while (arg[len] != NUL && arg[len] != '>')
			++len;
		}
		if (arg[len] != '>')
		{
		    errmsg = e_invarg;
		    goto skip;
		}
		arg[len] = NUL;			    
		if (arg[1] == 't' && arg[2] == '_') 
		    opt_idx = findoption(arg + 1);
		arg[len++] = '>';		    
		if (opt_idx == -1)
		    key = find_key_option(arg + 1, TRUE);
	    }
	    else {
		len = 0;
		
		if (arg[0] == 't' && arg[1] == '_' && arg[2] && arg[3])
		    len = 4;
		else while (ASCII_ISALNUM(arg[len]) || arg[len] == '_')
			++len;
		nextchar = arg[len];
		arg[len] = NUL;			    
		opt_idx = findoption(arg);
		arg[len] = nextchar;		    
		if (opt_idx == -1)
		    key = find_key_option(arg, FALSE);
	    }

	    
	    afterchar = arg[len];

	    if (in_vim9script())
	    {
		char_u *p = skipwhite(arg + len);

		
		if (p > arg + len && (p[0] == '=' || (vim_strchr((char_u *)"+-^", p[0]) != NULL && p[1] == '=')))

		{
		    errmsg = e_no_white_space_allowed_between_option_and;
		    arg = p;
		    startarg = p;
		    goto skip;
		}
	    }
	    else  while (VIM_ISWHITE(arg[len]))

		    ++len;

	    adding = FALSE;
	    prepending = FALSE;
	    removing = FALSE;
	    if (arg[len] != NUL && arg[len + 1] == '=')
	    {
		if (arg[len] == '+')
		{
		    adding = TRUE;		
		    ++len;
		}
		else if (arg[len] == '^')
		{
		    prepending = TRUE;		
		    ++len;
		}
		else if (arg[len] == '-')
		{
		    removing = TRUE;		
		    ++len;
		}
	    }
	    nextchar = arg[len];

	    if (opt_idx == -1 && key == 0)	
	    {
		if (in_vim9script() && arg > arg_start && vim_strchr((char_u *)"!&<", *arg) != NULL)
		    errmsg = e_no_white_space_allowed_between_option_and;
		else errmsg = N_("E518: Unknown option");
		goto skip;
	    }

	    if (opt_idx >= 0)
	    {
		if (options[opt_idx].var == NULL)   
		{
		    
		    
		    if (vim_strchr((char_u *)"=:!&<", nextchar) == NULL && (!(options[opt_idx].flags & P_BOOL)
				|| nextchar == '?'))
			errmsg = N_("E519: Option not supported");
		    goto skip;
		}

		flags = options[opt_idx].flags;
		varp = get_varp_scope(&(options[opt_idx]), opt_flags);
	    }
	    else {
		flags = P_STRING;
		if (key < 0)
		{
		    key_name[0] = KEY2TERMCAP0(key);
		    key_name[1] = KEY2TERMCAP1(key);
		}
		else {
		    key_name[0] = KS_KEY;
		    key_name[1] = (key & 0xff);
		}
	    }

	    
	    
	    if ((opt_flags & OPT_WINONLY)
			  && (opt_idx < 0 || options[opt_idx].var != VAR_WIN))
		goto skip;

	    
	    if ((opt_flags & OPT_NOWIN) && opt_idx >= 0 && options[opt_idx].var == VAR_WIN)
		goto skip;

	    
	    if (opt_flags & OPT_MODELINE)
	    {
		if (flags & (P_SECURE | P_NO_ML))
		{
		    errmsg = N_("E520: Not allowed in a modeline");
		    goto skip;
		}
		if ((flags & P_MLE) && !p_mle)
		{
		    errmsg = N_("E992: Not allowed in a modeline when 'modelineexpr' is off");
		    goto skip;
		}

		
		
		
		if (curwin->w_p_diff && opt_idx >= 0 && (  options[opt_idx].indir == PV_FDM ||  options[opt_idx].indir == PV_WRAP))





		    goto skip;

	    }


	    
	    if (sandbox != 0 && (flags & P_SECURE))
	    {
		errmsg = e_not_allowed_in_sandbox;
		goto skip;
	    }


	    if (vim_strchr((char_u *)"?=:!&<", nextchar) != NULL)
	    {
		arg += len;
		cp_val = p_cp;
		if (nextchar == '&' && arg[1] == 'v' && arg[2] == 'i')
		{
		    if (arg[3] == 'm')	
		    {
			cp_val = FALSE;
			arg += 3;
		    }
		    else		 {
			cp_val = TRUE;
			arg += 2;
		    }
		}
		if (vim_strchr((char_u *)"?!&<", nextchar) != NULL && arg[1] != NUL && !VIM_ISWHITE(arg[1]))
		{
		    errmsg = e_trailing;
		    goto skip;
		}
	    }

	    
	    if (nextchar == '?' || (prefix == 1 && vim_strchr((char_u *)"=:&<", nextchar) == NULL && !(flags & P_BOOL)))


	    {
		
		if (did_show)
		    msg_putchar('\n');	    
		else {
		    gotocmdline(TRUE);	    
		    did_show = TRUE;	    
		}
		if (opt_idx >= 0)
		{
		    showoneopt(&options[opt_idx], opt_flags);

		    if (p_verbose > 0)
		    {
			
			if (varp == options[opt_idx].var)
			    last_set_msg(options[opt_idx].script_ctx);
			else if ((int)options[opt_idx].indir & PV_WIN)
			    last_set_msg(curwin->w_p_script_ctx[ (int)options[opt_idx].indir & PV_MASK]);
			else if ((int)options[opt_idx].indir & PV_BUF)
			    last_set_msg(curbuf->b_p_script_ctx[ (int)options[opt_idx].indir & PV_MASK]);
		    }

		}
		else {
		    char_u	    *p;

		    p = find_termcode(key_name);
		    if (p == NULL)
		    {
			errmsg = N_("E846: Key code not set");
			goto skip;
		    }
		    else (void)show_one_termcode(key_name, p, TRUE);
		}
		if (nextchar != '?' && nextchar != NUL && !VIM_ISWHITE(afterchar))
		    errmsg = e_trailing;
	    }
	    else {
		int value_is_replaced = !prepending && !adding && !removing;
		int value_checked = FALSE;

		if (flags & P_BOOL)		    
		{
		    if (nextchar == '=' || nextchar == ':')
		    {
			errmsg = e_invarg;
			goto skip;
		    }

		    
		    if (nextchar == '!')
			value = *(int *)(varp) ^ 1;
		    else if (nextchar == '&')
			value = (int)(long)(long_i)options[opt_idx].def_val[ ((flags & P_VI_DEF) || cp_val)
						 ?  VI_DEFAULT : VIM_DEFAULT];
		    else if (nextchar == '<')
		    {
			
			if ((int *)varp == &curbuf->b_p_ar && opt_flags == OPT_LOCAL)
			    value = -1;
			else value = *(int *)get_varp_scope(&(options[opt_idx]), OPT_GLOBAL);

		    }
		    else {
			
			if (nextchar != NUL && !VIM_ISWHITE(afterchar))
			{
			    errmsg = e_trailing;
			    goto skip;
			}
			if (prefix == 2)	
			    value = *(int *)(varp) ^ 1;
			else value = prefix;
		    }

		    errmsg = set_bool_option(opt_idx, varp, (int)value, opt_flags);
		}
		else				     {
		    if (vim_strchr((char_u *)"=:&<", nextchar) == NULL || prefix != 1)
		    {
			errmsg = e_invarg;
			goto skip;
		    }

		    if (flags & P_NUM)		    
		    {
			
			++arg;
			if (nextchar == '&')
			    value = (long)(long_i)options[opt_idx].def_val[ ((flags & P_VI_DEF) || cp_val)
						 ?  VI_DEFAULT : VIM_DEFAULT];
			else if (nextchar == '<')
			{
			    
			    
			    if ((long *)varp == &curbuf->b_p_ul && opt_flags == OPT_LOCAL)
				value = NO_LOCAL_UNDOLEVEL;
			    else value = *(long *)get_varp_scope( &(options[opt_idx]), OPT_GLOBAL);

			}
			else if (((long *)varp == &p_wc || (long *)varp == &p_wcm)
				&& (*arg == '<' || *arg == '^' || (*arg != NUL && (!arg[1] || VIM_ISWHITE(arg[1]))


					&& !VIM_ISDIGIT(*arg))))
			{
			    value = string_to_key(arg, FALSE);
			    if (value == 0 && (long *)varp != &p_wcm)
			    {
				errmsg = e_invarg;
				goto skip;
			    }
			}
			else if (*arg == '-' || VIM_ISDIGIT(*arg))
			{
			    
			    
			    vim_str2nr(arg, NULL, &i, STR2NR_ALL, &value, NULL, 0, TRUE);
			    if (i == 0 || (arg[i] != NUL && !VIM_ISWHITE(arg[i])))
			    {
				errmsg = N_("E521: Number required after =");
				goto skip;
			    }
			}
			else {
			    errmsg = N_("E521: Number required after =");
			    goto skip;
			}

			if (adding)
			    value = *(long *)varp + value;
			if (prepending)
			    value = *(long *)varp * value;
			if (removing)
			    value = *(long *)varp - value;
			errmsg = set_num_option(opt_idx, varp, value, errbuf, sizeof(errbuf), opt_flags);
		    }
		    else if (opt_idx >= 0)		    
		    {
			char_u	  *save_arg = NULL;
			char_u	  *s = NULL;
			char_u	  *oldval = NULL; 
			char_u	  *newval;
			char_u	  *origval = NULL;
			char_u	  *origval_l = NULL;
			char_u	  *origval_g = NULL;

			char_u	  *saved_origval = NULL;
			char_u	  *saved_origval_l = NULL;
			char_u	  *saved_origval_g = NULL;
			char_u	  *saved_newval = NULL;

			unsigned  newlen;
			int	  comma;
			int	  new_value_alloced;	
							

			
			
			
			if ((opt_flags & (OPT_LOCAL | OPT_GLOBAL)) == 0 && ((int)options[opt_idx].indir & PV_BOTH))
			    varp = options[opt_idx].var;

			
			
			oldval = *(char_u **)varp;

			if ((opt_flags & (OPT_LOCAL | OPT_GLOBAL)) == 0)
			{
			    origval_l = *(char_u **)get_varp_scope( &(options[opt_idx]), OPT_LOCAL);
			    origval_g = *(char_u **)get_varp_scope( &(options[opt_idx]), OPT_GLOBAL);

			    
			    
			    
			    if (((int)options[opt_idx].indir & PV_BOTH)
						  && origval_l == empty_option)
				origval_l = origval_g;
			}

			
			
			if (((int)options[opt_idx].indir & PV_BOTH)
					       && (opt_flags & OPT_LOCAL))
			    origval = *(char_u **)get_varp( &options[opt_idx]);
			else origval = oldval;

			if (nextchar == '&')	
			{
			    newval = options[opt_idx].def_val[ ((flags & P_VI_DEF) || cp_val)
						 ?  VI_DEFAULT : VIM_DEFAULT];
			    if ((char_u **)varp == &p_bg)
			    {
				

				if (gui.in_use)
				    newval = gui_bg_default();
				else  newval = term_bg_default();

			    }
			    else if ((char_u **)varp == &p_fencs && enc_utf8)
				newval = fencs_utf8_default;

			    
			    
			    
			    
			    if (newval == NULL)
				newval = empty_option;
			    else {
				s = option_expand(opt_idx, newval);
				if (s == NULL)
				    s = newval;
				newval = vim_strsave(s);
			    }
			    new_value_alloced = TRUE;
			}
			else if (nextchar == '<')	
			{
			    newval = vim_strsave(*(char_u **)get_varp_scope( &(options[opt_idx]), OPT_GLOBAL));
			    new_value_alloced = TRUE;
			}
			else {
			    ++arg;	

			    
			    if (varp == (char_u *)&p_kp && (*arg == NUL || *arg == ' '))
			    {
				STRCPY(errbuf, ":help");
				save_arg = arg;
				arg = (char_u *)errbuf;
			    }
			    
			    else if (varp == (char_u *)&p_bs && VIM_ISDIGIT(**(char_u **)varp))
			    {
				i = getdigits((char_u **)varp);
				switch (i)
				{
				    case 0:
					*(char_u **)varp = empty_option;
					break;
				    case 1:
					*(char_u **)varp = vim_strsave( (char_u *)"indent,eol");
					break;
				    case 2:
					*(char_u **)varp = vim_strsave( (char_u *)"indent,eol,start");
					break;
				    case 3:
					*(char_u **)varp = vim_strsave( (char_u *)"indent,eol,nostop");
					break;
				}
				vim_free(oldval);
				if (origval == oldval)
				    origval = *(char_u **)varp;
				if (origval_l == oldval)
				    origval_l = *(char_u **)varp;
				if (origval_g == oldval)
				    origval_g = *(char_u **)varp;
				oldval = *(char_u **)varp;
			    }
			    
			    else if (varp == (char_u *)&p_ww && VIM_ISDIGIT(*arg))
			    {
				*errbuf = NUL;
				i = getdigits(&arg);
				if (i & 1)
				    STRCAT(errbuf, "b,");
				if (i & 2)
				    STRCAT(errbuf, "s,");
				if (i & 4)
				    STRCAT(errbuf, "h,l,");
				if (i & 8)
				    STRCAT(errbuf, "<,>,");
				if (i & 16)
				    STRCAT(errbuf, "[,],");
				if (*errbuf != NUL)	
				    errbuf[STRLEN(errbuf) - 1] = NUL;
				save_arg = arg;
				arg = (char_u *)errbuf;
			    }
			    
			    else if (  *arg == '>' && (varp == (char_u *)&p_dir || varp == (char_u *)&p_bdir))

			    {
				++arg;
			    }

			    
			    
			    newlen = (unsigned)STRLEN(arg) + 1;
			    if (adding || prepending || removing)
				newlen += (unsigned)STRLEN(origval) + 1;
			    newval = alloc(newlen);
			    if (newval == NULL)  
				break;
			    s = newval;

			    
			    while (*arg && !VIM_ISWHITE(*arg))
			    {
				if (*arg == '\\' && arg[1] != NUL  && !((flags & P_EXPAND)

						&& vim_isfilec(arg[1])
						&& !VIM_ISWHITE(arg[1])
						&& (arg[1] != '\\' || (s == newval && arg[2] != '\\')))


								    )
				    ++arg;	
				if (has_mbyte && (i = (*mb_ptr2len)(arg)) > 1)
				{
				    
				    mch_memmove(s, arg, (size_t)i);
				    arg += i;
				    s += i;
				}
				else *s++ = *arg++;
			    }
			    *s = NUL;

			    
			    if (!(adding || prepending || removing)
							 || (flags & P_COMMA))
			    {
				s = option_expand(opt_idx, newval);
				if (s != NULL)
				{
				    vim_free(newval);
				    newlen = (unsigned)STRLEN(s) + 1;
				    if (adding || prepending || removing)
					newlen += (unsigned)STRLEN(origval) + 1;
				    newval = alloc(newlen);
				    if (newval == NULL)
					break;
				    STRCPY(newval, s);
				}
			    }

			    
			    
			    i = 0;	
			    if (removing || (flags & P_NODUP))
			    {
				i = (int)STRLEN(newval);
				s = find_dup_item(origval, newval, flags);

				
				if ((adding || prepending) && s != NULL)
				{
				    prepending = FALSE;
				    adding = FALSE;
				    STRCPY(newval, origval);
				}

				
				
				if (s == NULL)
				    s = origval + (int)STRLEN(origval);
			    }

			    
			    
			    if (adding || prepending)
			    {
				comma = ((flags & P_COMMA) && *origval != NUL && *newval != NUL);
				if (adding)
				{
				    i = (int)STRLEN(origval);
				    
				    if (comma && i > 1 && (flags & P_ONECOMMA) == P_ONECOMMA && origval[i - 1] == ',' && origval[i - 2] != '\\')


					i--;
				    mch_memmove(newval + i + comma, newval, STRLEN(newval) + 1);
				    mch_memmove(newval, origval, (size_t)i);
				}
				else {
				    i = (int)STRLEN(newval);
				    STRMOVE(newval + i + comma, origval);
				}
				if (comma)
				    newval[i] = ',';
			    }

			    
			    
			    if (removing)
			    {
				STRCPY(newval, origval);
				if (*s)
				{
				    
				    if (flags & P_COMMA)
				    {
					if (s == origval)
					{
					    
					    if (s[i] == ',')
						++i;
					}
					else {
					    
					    --s;
					    ++i;
					}
				    }
				    STRMOVE(newval + (s - origval), s + i);
				}
			    }

			    if (flags & P_FLAGLIST)
			    {
				
				for (s = newval; *s;)
				{
				    
				    
				    if (flags & P_ONECOMMA)
				    {
					if (*s != ',' && *(s + 1) == ',' && vim_strchr(s + 2, *s) != NULL)
					{
					    
					    
					    STRMOVE(s, s + 2);
					    continue;
					}
				    }
				    else {
					if ((!(flags & P_COMMA) || *s != ',')
					      && vim_strchr(s + 1, *s) != NULL)
					{
					    STRMOVE(s, s + 1);
					    continue;
					}
				    }
				    ++s;
				}
			    }

			    if (save_arg != NULL)   
				arg = save_arg;
			    new_value_alloced = TRUE;
			}

			
			*(char_u **)(varp) = newval;


			if (!starting  && options[opt_idx].indir != PV_KEY  && origval != NULL && newval != NULL)



			{
			    
			    
			    saved_origval = vim_strsave(origval);
			    
			    
			    saved_newval = vim_strsave(newval);
			    if (origval_l != NULL)
				saved_origval_l = vim_strsave(origval_l);
			    if (origval_g != NULL)
				saved_origval_g = vim_strsave(origval_g);
			}


			{
			    long_u *p = insecure_flag(opt_idx, opt_flags);
			    int	    secure_saved = secure;

			    
			    
			    
			    
			    
			    if ((opt_flags & OPT_MODELINE)

				  || sandbox != 0  || (!value_is_replaced && (*p & P_INSECURE)))

				secure = 1;

			    
			    
			    
			    
			    errmsg = did_set_string_option( opt_idx, (char_u **)varp, new_value_alloced, oldval, errbuf, opt_flags, &value_checked);



			    secure = secure_saved;
			}


			if (errmsg == NULL)
			    trigger_optionsset_string( opt_idx, opt_flags, saved_origval, saved_origval_l, saved_origval_g, saved_newval);


			vim_free(saved_origval);
			vim_free(saved_origval_l);
			vim_free(saved_origval_g);
			vim_free(saved_newval);

			
			if (errmsg != NULL)
			    goto skip;
		    }
		    else	     {
			char_u	    *p;

			if (nextchar == '&')
			{
			    if (add_termcap_entry(key_name, TRUE) == FAIL)
				errmsg = N_("E522: Not found in termcap");
			}
			else {
			    ++arg; 
			    for (p = arg; *p && !VIM_ISWHITE(*p); ++p)
				if (*p == '\\' && p[1] != NUL)
				    ++p;
			    nextchar = *p;
			    *p = NUL;
			    add_termcode(key_name, arg, FALSE);
			    *p = nextchar;
			}
			if (full_screen)
			    ttest(FALSE);
			redraw_all_later(CLEAR);
		    }
		}

		if (opt_idx >= 0)
		    did_set_option( opt_idx, opt_flags, value_is_replaced, value_checked);
	    }

skip:
	    
	    for (i = 0; i < 2 ; ++i)
	    {
		while (*arg != NUL && !VIM_ISWHITE(*arg))
		    if (*arg++ == '\\' && *arg != NUL)
			++arg;
		arg = skipwhite(arg);
		if (*arg != '=')
		    break;
	    }
	}

	if (errmsg != NULL)
	{
	    vim_strncpy(IObuff, (char_u *)_(errmsg), IOSIZE - 1);
	    i = (int)STRLEN(IObuff) + 2;
	    if (i + (arg - startarg) < IOSIZE)
	    {
		
		STRCAT(IObuff, ": ");
		mch_memmove(IObuff + i, startarg, (arg - startarg));
		IObuff[i + (arg - startarg)] = NUL;
	    }
	    
	    trans_characters(IObuff, IOSIZE);

	    ++no_wait_return;		
	    emsg((char *)IObuff);	
	    --no_wait_return;

	    return FAIL;
	}

	arg = skipwhite(arg);
    }

theend:
    if (silent_mode && did_show)
    {
	
	silent_mode = FALSE;
	info_message = TRUE;	
	msg_putchar('\n');
	cursor_on();		
	out_flush();
	silent_mode = TRUE;
	info_message = FALSE;	
    }

    return OK;
}


    void did_set_option( int	    opt_idx, int	    opt_flags, int	    new_value, int	    value_checked)




			    
{
    long_u	*p;

    options[opt_idx].flags |= P_WAS_SET;

    
    
    
    p = insecure_flag(opt_idx, opt_flags);
    if (!value_checked && (secure  || sandbox != 0  || (opt_flags & OPT_MODELINE)))



	*p = *p | P_INSECURE;
    else if (new_value)
	*p = *p & ~P_INSECURE;
}


    int string_to_key(char_u *arg, int multi_byte)
{
    if (*arg == '<')
	return find_key_option(arg + 1, TRUE);
    if (*arg == '^')
	return Ctrl_chr(arg[1]);
    if (multi_byte)
	return PTR2CHAR(arg);
    return *arg;
}



    void did_set_title(void)
{
    if (starting != NO_SCREEN  && !gui.starting  )



	maketitle();
}



    void set_options_bin( int		oldval, int		newval, int		opt_flags)



{
    
    if (newval)
    {
	if (!oldval)		
	{
	    if (!(opt_flags & OPT_GLOBAL))
	    {
		curbuf->b_p_tw_nobin = curbuf->b_p_tw;
		curbuf->b_p_wm_nobin = curbuf->b_p_wm;
		curbuf->b_p_ml_nobin = curbuf->b_p_ml;
		curbuf->b_p_et_nobin = curbuf->b_p_et;
	    }
	    if (!(opt_flags & OPT_LOCAL))
	    {
		p_tw_nobin = p_tw;
		p_wm_nobin = p_wm;
		p_ml_nobin = p_ml;
		p_et_nobin = p_et;
	    }
	}

	if (!(opt_flags & OPT_GLOBAL))
	{
	    curbuf->b_p_tw = 0;	
	    curbuf->b_p_wm = 0;	
	    curbuf->b_p_ml = 0;	
	    curbuf->b_p_et = 0;	
	}
	if (!(opt_flags & OPT_LOCAL))
	{
	    p_tw = 0;
	    p_wm = 0;
	    p_ml = FALSE;
	    p_et = FALSE;
	    p_bin = TRUE;	
	}
    }
    else if (oldval)		
    {
	if (!(opt_flags & OPT_GLOBAL))
	{
	    curbuf->b_p_tw = curbuf->b_p_tw_nobin;
	    curbuf->b_p_wm = curbuf->b_p_wm_nobin;
	    curbuf->b_p_ml = curbuf->b_p_ml_nobin;
	    curbuf->b_p_et = curbuf->b_p_et_nobin;
	}
	if (!(opt_flags & OPT_LOCAL))
	{
	    p_tw = p_tw_nobin;
	    p_wm = p_wm_nobin;
	    p_ml = p_ml_nobin;
	    p_et = p_et_nobin;
	}
    }
}


    static char_u * option_expand(int opt_idx, char_u *val)
{
    
    if (!(options[opt_idx].flags & P_EXPAND) || options[opt_idx].var == NULL)
	return NULL;

    
    
    if (val != NULL && STRLEN(val) > MAXPATHL)
	return NULL;

    if (val == NULL)
	val = *(char_u **)options[opt_idx].var;

    
    expand_env_esc(val, NameBuff, MAXPATHL, (char_u **)options[opt_idx].var == &p_tags, FALSE,  (char_u **)options[opt_idx].var == &p_sps ? (char_u *)"file:" :



				  NULL);
    if (STRCMP(NameBuff, val) == 0)   
	return NULL;

    return NameBuff;
}


    static void didset_options(void)
{
    
    (void)init_chartab();

    didset_string_options();


    (void)spell_check_msm();
    (void)spell_check_sps();
    (void)compile_cap_prog(curwin->w_s);
    (void)did_set_spell_option(TRUE);


    
    (void)check_cedit();


    
    fill_breakat_flags();

    after_copy_winopt(curwin);
}


    static void didset_options2(void)
{
    
    (void)highlight_changed();

    
    check_opt_wim();

    
    (void)set_chars_option(curwin, &curwin->w_p_lcs);

    
    (void)set_chars_option(curwin, &p_fcs);


    
    (void)check_clipboard_option();


    vim_free(curbuf->b_p_vsts_array);
    tabstop_set(curbuf->b_p_vsts, &curbuf->b_p_vsts_array);
    vim_free(curbuf->b_p_vts_array);
    tabstop_set(curbuf->b_p_vts,  &curbuf->b_p_vts_array);

}


    void check_options(void)
{
    int		opt_idx;

    for (opt_idx = 0; options[opt_idx].fullname != NULL; opt_idx++)
	if ((options[opt_idx].flags & P_STRING) && options[opt_idx].var != NULL)
	    check_string_option((char_u **)get_varp(&(options[opt_idx])));
}


    int get_term_opt_idx(char_u **p)
{
    int opt_idx;

    for (opt_idx = 1; options[opt_idx].fullname != NULL; opt_idx++)
	if (options[opt_idx].var == (char_u *)p)
	    return opt_idx;
    return -1; 
}


    int set_term_option_alloced(char_u **p)
{
    int		opt_idx = get_term_opt_idx(p);

    if (opt_idx >= 0)
	options[opt_idx].flags |= P_ALLOCED;
    return opt_idx;
}



    int was_set_insecurely(char_u *opt, int opt_flags)
{
    int	    idx = findoption(opt);
    long_u  *flagp;

    if (idx >= 0)
    {
	flagp = insecure_flag(idx, opt_flags);
	return (*flagp & P_INSECURE) != 0;
    }
    internal_error("was_set_insecurely()");
    return -1;
}


    static long_u * insecure_flag(int opt_idx, int opt_flags)
{
    if (opt_flags & OPT_LOCAL)
	switch ((int)options[opt_idx].indir)
	{

	    case PV_STL:	return &curwin->w_p_stl_flags;



	    case PV_FDE:	return &curwin->w_p_fde_flags;
	    case PV_FDT:	return &curwin->w_p_fdt_flags;


	    case PV_BEXPR:	return &curbuf->b_p_bexpr_flags;


	    case PV_INDE:	return &curbuf->b_p_inde_flags;

	    case PV_FEX:	return &curbuf->b_p_fex_flags;

	    case PV_INEX:	return &curbuf->b_p_inex_flags;


	}

    
    return &options[opt_idx].flags;
}




void redraw_titles(void)
{
    need_maketitle = TRUE;
    redraw_tabline = TRUE;
}



    int valid_name(char_u *val, char *allowed)
{
    char_u *s;

    for (s = val; *s != NUL; ++s)
	if (!ASCII_ISALNUM(*s) && vim_strchr((char_u *)allowed, *s) == NULL)
	    return FALSE;
    return TRUE;
}



    void set_option_sctx_idx(int opt_idx, int opt_flags, sctx_T script_ctx)
{
    int		both = (opt_flags & (OPT_LOCAL | OPT_GLOBAL)) == 0;
    int		indir = (int)options[opt_idx].indir;
    sctx_T	new_script_ctx = script_ctx;

    
    if (!(opt_flags & OPT_MODELINE))
	new_script_ctx.sc_lnum += SOURCING_LNUM;

    
    
    if (both || (opt_flags & OPT_GLOBAL) || (indir & (PV_BUF|PV_WIN)) == 0)
	options[opt_idx].script_ctx = new_script_ctx;
    if (both || (opt_flags & OPT_LOCAL))
    {
	if (indir & PV_BUF)
	    curbuf->b_p_script_ctx[indir & PV_MASK] = new_script_ctx;
	else if (indir & PV_WIN)
	    curwin->w_p_script_ctx[indir & PV_MASK] = new_script_ctx;
    }
}


    void set_term_option_sctx_idx(char *name, int opt_idx)
{
    char_u  buf[5];
    int	    idx;

    if (name == NULL)
	idx = opt_idx;
    else {
	buf[0] = 't';
	buf[1] = '_';
	buf[2] = name[0];
	buf[3] = name[1];
	buf[4] = 0;
	idx = findoption(buf);
    }
    if (idx >= 0)
	set_option_sctx_idx(idx, OPT_GLOBAL, current_sctx);
}




    static void apply_optionset_autocmd( int	opt_idx, long	opt_flags, long	oldval, long	oldval_g, long	newval, char	*errmsg)






{
    char_u buf_old[12], buf_old_global[12], buf_new[12], buf_type[12];

    
    if (starting || errmsg != NULL || *get_vim_var_str(VV_OPTION_TYPE) != NUL)
	return;

    vim_snprintf((char *)buf_old, sizeof(buf_old), "%ld", oldval);
    vim_snprintf((char *)buf_old_global, sizeof(buf_old_global), "%ld", oldval_g);
    vim_snprintf((char *)buf_new, sizeof(buf_new), "%ld", newval);
    vim_snprintf((char *)buf_type, sizeof(buf_type), "%s", (opt_flags & OPT_LOCAL) ? "local" : "global");
    set_vim_var_string(VV_OPTION_NEW, buf_new, -1);
    set_vim_var_string(VV_OPTION_OLD, buf_old, -1);
    set_vim_var_string(VV_OPTION_TYPE, buf_type, -1);
    if (opt_flags & OPT_LOCAL)
    {
	set_vim_var_string(VV_OPTION_COMMAND, (char_u *)"setlocal", -1);
	set_vim_var_string(VV_OPTION_OLDLOCAL, buf_old, -1);
    }
    if (opt_flags & OPT_GLOBAL)
    {
	set_vim_var_string(VV_OPTION_COMMAND, (char_u *)"setglobal", -1);
	set_vim_var_string(VV_OPTION_OLDGLOBAL, buf_old, -1);
    }
    if ((opt_flags & (OPT_LOCAL | OPT_GLOBAL)) == 0)
    {
	set_vim_var_string(VV_OPTION_COMMAND, (char_u *)"set", -1);
	set_vim_var_string(VV_OPTION_OLDLOCAL, buf_old, -1);
	set_vim_var_string(VV_OPTION_OLDGLOBAL, buf_old_global, -1);
    }
    if (opt_flags & OPT_MODELINE)
    {
	set_vim_var_string(VV_OPTION_COMMAND, (char_u *)"modeline", -1);
	set_vim_var_string(VV_OPTION_OLDLOCAL, buf_old, -1);
    }
    apply_autocmds(EVENT_OPTIONSET, (char_u *)options[opt_idx].fullname, NULL, FALSE, NULL);
    reset_v_option_vars();
}



    static char * set_bool_option( int		opt_idx, char_u	*varp, int		value, int		opt_flags)




{
    int		old_value = *(int *)varp;

    int		old_global_value = 0;


    
    if ((secure  || sandbox != 0  ) && (options[opt_idx].flags & P_SECURE))



	return e_secure;


    
    
    
    if ((opt_flags & (OPT_LOCAL | OPT_GLOBAL)) == 0)
	old_global_value = *(int *)get_varp_scope(&(options[opt_idx]), OPT_GLOBAL);


    *(int *)varp = value;	    

    
    set_option_sctx_idx(opt_idx, opt_flags, current_sctx);



    need_mouse_correct = TRUE;


    
    if ((opt_flags & (OPT_LOCAL | OPT_GLOBAL)) == 0)
	*(int *)get_varp_scope(&(options[opt_idx]), OPT_GLOBAL) = value;

    

    
    if ((int *)varp == &p_cp)
	compatible_set();


    if ((int *)varp == &p_lrm)
	
	p_lnr = !p_lrm;
    else if ((int *)varp == &p_lnr)
	
	p_lrm = !p_lnr;



    else if ((int *)varp == &curwin->w_p_cul && !value && old_value)
	reset_cursorline();



    
    else if ((int *)varp == &curbuf->b_p_udf || (int *)varp == &p_udf)
    {
	
	
	
	if (curbuf->b_p_udf || p_udf)
	{
	    char_u	hash[UNDO_HASH_SIZE];
	    buf_T	*save_curbuf = curbuf;

	    FOR_ALL_BUFFERS(curbuf)
	    {
		
		
		
		
		if ((curbuf == save_curbuf || (opt_flags & OPT_GLOBAL) || opt_flags == 0)
			&& !curbufIsChanged() && curbuf->b_ml.ml_mfp != NULL)
		{

		    if (crypt_get_method_nr(curbuf) == CRYPT_M_SOD)
			continue;

		    u_compute_hash(hash);
		    u_read_undo(NULL, hash, curbuf->b_fname);
		}
	    }
	    curbuf = save_curbuf;
	}
    }


    else if ((int *)varp == &curbuf->b_p_ro)
    {
	
	if (!curbuf->b_p_ro && (opt_flags & OPT_LOCAL) == 0)
	    readonlymode = FALSE;

	
	if (curbuf->b_p_ro)
	    curbuf->b_did_warn = FALSE;


	redraw_titles();

    }


    else if ((int *)varp == &p_mh)
    {
	if (!p_mh)
	    gui_mch_mousehide(FALSE);
    }


    
    else if ((int *)varp == &curbuf->b_p_ma)
    {

	
	if (curbuf->b_p_ma && (term_in_normal_mode() || (bt_terminal(curbuf)
		      && curbuf->b_term != NULL && !term_is_finished(curbuf))))
	{
	    curbuf->b_p_ma = FALSE;
	    return N_("E946: Cannot make a terminal with running job modifiable");
	}


	redraw_titles();

    }

    
    else if ((int *)varp == &curbuf->b_p_eol)
    {
	redraw_titles();
    }
    
    else if ((int *)varp == &curbuf->b_p_fixeol)
    {
	redraw_titles();
    }
    
    else if ((int *)varp == &curbuf->b_p_bomb)
    {
	redraw_titles();
    }


    
    else if ((int *)varp == &curbuf->b_p_bin)
    {
	set_options_bin(old_value, curbuf->b_p_bin, opt_flags);

	redraw_titles();

    }

    
    else if ((int *)varp == &curbuf->b_p_bl && old_value != curbuf->b_p_bl)
    {
	apply_autocmds(curbuf->b_p_bl ? EVENT_BUFADD : EVENT_BUFDELETE, NULL, NULL, TRUE, curbuf);
    }

    
    else if ((int *)varp == &curbuf->b_p_swf)
    {
	if (curbuf->b_p_swf && p_uc)
	    ml_open_file(curbuf);		
	else   mf_close_file(curbuf, TRUE);


    }

    
    else if ((int *)varp == &p_terse)
    {
	char_u	*p;

	p = vim_strchr(p_shm, SHM_SEARCH);

	
	if (p_terse && p == NULL)
	{
	    STRCPY(IObuff, p_shm);
	    STRCAT(IObuff, "s");
	    set_string_option_direct((char_u *)"shm", -1, IObuff, OPT_FREE, 0);
	}
	
	else if (!p_terse && p != NULL)
	    STRMOVE(p, p + 1);
    }

    
    else if ((int *)varp == &p_paste)
    {
	paste_option_changed();
    }

    
    else if ((int *)varp == &p_im)
    {
	if (p_im)
	{
	    if ((State & INSERT) == 0)
		need_start_insertmode = TRUE;
	    stop_insert_mode = FALSE;
	}
	
	else if (old_value)
	{
	    need_start_insertmode = FALSE;
	    stop_insert_mode = TRUE;
	    if (restart_edit != 0 && mode_displayed)
		clear_cmdline = TRUE;	
	    restart_edit = 0;
	}
    }

    
    else if ((int *)varp == &p_ic && p_hls)
    {
	redraw_all_later(SOME_VALID);
    }


    
    else if ((int *)varp == &p_hls)
    {
	set_no_hlsearch(FALSE);
    }


    
    
    else if ((int *)varp == &curwin->w_p_scb)
    {
	if (curwin->w_p_scb)
	{
	    do_check_scrollbind(FALSE);
	    curwin->w_scbind_pos = curwin->w_topline;
	}
    }


    
    else if ((int *)varp == &curwin->w_p_pvw)
    {
	if (curwin->w_p_pvw)
	{
	    win_T	*win;

	    FOR_ALL_WINDOWS(win)
		if (win->w_p_pvw && win != curwin)
		{
		    curwin->w_p_pvw = FALSE;
		    return N_("E590: A preview window already exists");
		}
	}
    }


    
    else if ((int *)varp == &curbuf->b_p_tx)
    {
	set_fileformat(curbuf->b_p_tx ? EOL_DOS : EOL_UNIX, opt_flags);
    }

    
    else if ((int *)varp == &p_ta)
    {
	set_string_option_direct((char_u *)"ffs", -1, p_ta ? (char_u *)DFLT_FFS_VIM : (char_u *)"", OPT_FREE | opt_flags, 0);

    }

    

    else if (varp == (char_u *)&(curbuf->b_p_lisp))
    {
	(void)buf_init_chartab(curbuf, FALSE);	    
    }



    
    else if ((int *)varp == &p_title || (int *)varp == &p_icon)
    {
	did_set_title();
    }


    else if ((int *)varp == &curbuf->b_changed)
    {
	if (!value)
	    save_file_ff(curbuf);	

	redraw_titles();

	modified_was_set = value;
    }


    else if ((int *)varp == &p_ssl)
    {
	if (p_ssl)
	{
	    psepc = '/';
	    psepcN = '\\';
	    pseps[0] = '/';
	}
	else {
	    psepc = '\\';
	    psepcN = '/';
	    pseps[0] = '\\';
	}

	
	buflist_slash_adjust();
	alist_slash_adjust();

	scriptnames_slash_adjust();

    }


    
    else if ((int *)varp == &curwin->w_p_wrap)
    {
	if (curwin->w_p_wrap)
	    curwin->w_leftcol = 0;
    }

    else if ((int *)varp == &p_ea)
    {
	if (p_ea && !old_value)
	    win_equal(curwin, FALSE, 0);
    }

    else if ((int *)varp == &p_wiv)
    {
	
	if (p_wiv && !old_value)
	    T_XS = (char_u *)"y";
	else if (!p_wiv && old_value)
	    T_XS = empty_option;
	p_wiv = (*T_XS != NUL);
    }


    else if ((int *)varp == &p_beval)
    {
	if (!balloonEvalForTerm)
	{
	    if (p_beval && !old_value)
		gui_mch_enable_beval_area(balloonEval);
	    else if (!p_beval && old_value)
		gui_mch_disable_beval_area(balloonEval);
	}
    }


    else if ((int *)varp == &p_bevalterm)
    {
	mch_bevalterm_changed();
    }



    else if ((int *)varp == &p_acd)
    {
	
	DO_AUTOCHDIR;
    }



    
    else if ((int *)varp == &curwin->w_p_diff)
    {
	
	diff_buf_adjust(curwin);

	if (foldmethodIsDiff(curwin))
	    foldUpdateAll(curwin);

    }



    
    else if ((int *)varp == &p_imdisable)
    {
	
	if (p_imdisable)
	    im_set_active(FALSE);
	else if (State & INSERT)
	    
	    
	    im_set_active(curbuf->b_p_iminsert == B_IMODE_IM);
    }



    
    else if ((int *)varp == &curwin->w_p_spell)
    {
	if (curwin->w_p_spell)
	{
	    char	*errmsg = did_set_spelllang(curwin);

	    if (errmsg != NULL)
		emsg(_(errmsg));
	}
    }



    if ((int *)varp == &curwin->w_p_arab)
    {
	if (curwin->w_p_arab)
	{
	    
	    if (!p_tbidi)
	    {
		
		if (!curwin->w_p_rl)
		{
		    curwin->w_p_rl = TRUE;
		    changed_window_setting();
		}

		
		if (!p_arshape)
		{
		    p_arshape = TRUE;
		    redraw_later_clear();
		}
	    }

	    
	    
	    if (STRCMP(p_enc, "utf-8") != 0)
	    {
		static char *w_arabic = N_("W17: Arabic requires UTF-8, do ':set encoding=utf-8'");

		msg_source(HL_ATTR(HLF_W));
		msg_attr(_(w_arabic), HL_ATTR(HLF_W));

		set_vim_var_string(VV_WARNINGMSG, (char_u *)_(w_arabic), -1);

	    }

	    
	    p_deco = TRUE;


	    
	    set_option_value((char_u *)"keymap", 0L, (char_u *)"arabic", OPT_LOCAL);

	}
	else {
	    
	    if (!p_tbidi)
	    {
		
		if (curwin->w_p_rl)
		{
		    curwin->w_p_rl = FALSE;
		    changed_window_setting();
		}

		
		
	    }

	    
	    


	    
	    curbuf->b_p_iminsert = B_IMODE_NONE;
	    curbuf->b_p_imsearch = B_IMODE_USE_INSERT;

	}
    }




    else if (((int *)varp == &curwin->w_p_nu || (int *)varp == &curwin->w_p_rnu)
	    && gui.in_use && (*curwin->w_p_scl == 'n' && *(curwin->w_p_scl + 1) == 'u')
	    && curbuf->b_signlist != NULL)
    {
	
	
	
	
	
	
	if (!(curwin->w_p_nu && ((int *)varp == &curwin->w_p_rnu)))
	    redraw_all_later(CLEAR);
    }



    
    else if ((int *)varp == &p_tgc)
    {

	
	if (  !gui.in_use && !gui.starting &&  !has_vtp_working())



	{
	    p_tgc = 0;
	    return N_("E954: 24-bit colors are not supported on this environment");
	}
	if (is_term_win32())
	    swap_tcap();


	if (!gui.in_use && !gui.starting)

	    highlight_gui_started();

	
	if (is_term_win32())
	{
	    control_console_color_rgb();
	    set_termname(T_NAME);
	    init_highlight(TRUE, FALSE);
	}

    }


    

    

    options[opt_idx].flags |= P_WAS_SET;


    apply_optionset_autocmd(opt_idx, opt_flags, (long)(old_value ? TRUE : FALSE), (long)(old_global_value ? TRUE : FALSE), (long)(value ? TRUE : FALSE), NULL);




    comp_col();			    
    if (curwin->w_curswant != MAXCOL && (options[opt_idx].flags & (P_CURSWANT | P_RALL)) != 0)
	curwin->w_set_curswant = TRUE;

    if ((opt_flags & OPT_NO_REDRAW) == 0)
	check_redraw(options[opt_idx].flags);

    return NULL;
}


    static char * set_num_option( int		opt_idx, char_u	*varp, long	value, char	*errbuf, size_t	errbuflen, int		opt_flags)






					
{
    char	*errmsg = NULL;
    long	old_value = *(long *)varp;

    long	old_global_value = 0;	
					

    long	old_Rows = Rows;	
    long	old_Columns = Columns;	
    long	*pp = (long *)varp;

    
    if ((secure  || sandbox != 0  ) && (options[opt_idx].flags & P_SECURE))



	return e_secure;


    
    
    
    if ((opt_flags & (OPT_LOCAL | OPT_GLOBAL)) == 0)
	old_global_value = *(long *)get_varp_scope(&(options[opt_idx]), OPT_GLOBAL);


    *pp = value;

    
    set_option_sctx_idx(opt_idx, opt_flags, current_sctx);


    need_mouse_correct = TRUE;


    if (curbuf->b_p_sw < 0)
    {
	errmsg = e_positive;

	
	curbuf->b_p_sw = tabstop_count(curbuf->b_p_vts_array) > 0 ? tabstop_first(curbuf->b_p_vts_array)
		       : curbuf->b_p_ts;

	curbuf->b_p_sw = curbuf->b_p_ts;

    }

    
    if (pp == &p_wh || pp == &p_hh)
    {
	
	if (p_wh < 1)
	{
	    errmsg = e_positive;
	    p_wh = 1;
	}
	if (p_wmh > p_wh)
	{
	    errmsg = e_winheight;
	    p_wh = p_wmh;
	}
	if (p_hh < 0)
	{
	    errmsg = e_positive;
	    p_hh = 0;
	}

	
	if (!ONE_WINDOW)
	{
	    if (pp == &p_wh && curwin->w_height < p_wh)
		win_setheight((int)p_wh);
	    if (pp == &p_hh && curbuf->b_help && curwin->w_height < p_hh)
		win_setheight((int)p_hh);
	}
    }
    else if (pp == &p_wmh)
    {
	
	if (p_wmh < 0)
	{
	    errmsg = e_positive;
	    p_wmh = 0;
	}
	if (p_wmh > p_wh)
	{
	    errmsg = e_winheight;
	    p_wmh = p_wh;
	}
	win_setminheight();
    }
    else if (pp == &p_wiw)
    {
	
	if (p_wiw < 1)
	{
	    errmsg = e_positive;
	    p_wiw = 1;
	}
	if (p_wmw > p_wiw)
	{
	    errmsg = e_winwidth;
	    p_wiw = p_wmw;
	}

	
	if (!ONE_WINDOW && curwin->w_width < p_wiw)
	    win_setwidth((int)p_wiw);
    }
    else if (pp == &p_wmw)
    {
	
	if (p_wmw < 0)
	{
	    errmsg = e_positive;
	    p_wmw = 0;
	}
	if (p_wmw > p_wiw)
	{
	    errmsg = e_winwidth;
	    p_wmw = p_wiw;
	}
	win_setminwidth();
    }

    
    else if (pp == &p_ls)
    {
	last_status(FALSE);
    }

    
    else if (pp == &p_stal)
    {
	shell_new_rows();	
    }


    else if (pp == &p_linespace)
    {
	
	
	if (gui.in_use && gui_mch_adjust_charheight() == OK)
	    gui_set_shellsize(FALSE, FALSE, RESIZE_VERT);
    }



    
    else if (pp == &curwin->w_p_fdl)
    {
	if (curwin->w_p_fdl < 0)
	    curwin->w_p_fdl = 0;
	newFoldLevel();
    }

    
    else if (pp == &curwin->w_p_fml)
    {
	foldUpdateAll(curwin);
    }

    
    else if (pp == &curwin->w_p_fdn)
    {
	if (foldmethodIsSyntax(curwin) || foldmethodIsIndent(curwin))
	    foldUpdateAll(curwin);
    }

    
    else if (pp == &curwin->w_p_fdc)
    {
	if (curwin->w_p_fdc < 0)
	{
	    errmsg = e_positive;
	    curwin->w_p_fdc = 0;
	}
	else if (curwin->w_p_fdc > 12)
	{
	    errmsg = e_invarg;
	    curwin->w_p_fdc = 12;
	}
    }



    
    else if (pp == &curbuf->b_p_sw || pp == &curbuf->b_p_ts)
    {

	if (foldmethodIsIndent(curwin))
	    foldUpdateAll(curwin);


	
	
	if (pp == &curbuf->b_p_sw || curbuf->b_p_sw == 0)
	    parse_cino(curbuf);

    }


    
    else if (pp == &p_mco)
    {
	if (p_mco > MAX_MCO)
	    p_mco = MAX_MCO;
	else if (p_mco < 0)
	    p_mco = 0;
	screenclear();	    
    }

    else if (pp == &curbuf->b_p_iminsert)
    {
	if (curbuf->b_p_iminsert < 0 || curbuf->b_p_iminsert > B_IMODE_LAST)
	{
	    errmsg = e_invarg;
	    curbuf->b_p_iminsert = B_IMODE_NONE;
	}
	p_iminsert = curbuf->b_p_iminsert;
	if (termcap_active)	
	    showmode();

	
	status_redraw_curbuf();

    }


    
    else if (pp == &p_imst)
    {
	if (p_imst != IM_ON_THE_SPOT && p_imst != IM_OVER_THE_SPOT)
	    errmsg = e_invarg;
    }


    else if (pp == &p_window)
    {
	if (p_window < 1)
	    p_window = 1;
	else if (p_window >= Rows)
	    p_window = Rows - 1;
    }

    else if (pp == &curbuf->b_p_imsearch)
    {
	if (curbuf->b_p_imsearch < -1 || curbuf->b_p_imsearch > B_IMODE_LAST)
	{
	    errmsg = e_invarg;
	    curbuf->b_p_imsearch = B_IMODE_NONE;
	}
	p_imsearch = curbuf->b_p_imsearch;
    }


    
    else if (pp == &p_titlelen)
    {
	if (p_titlelen < 0)
	{
	    errmsg = e_positive;
	    p_titlelen = 85;
	}
	if (starting != NO_SCREEN && old_value != p_titlelen)
	    need_maketitle = TRUE;
    }


    
    else if (pp == &p_ch)
    {
	if (p_ch < 1)
	{
	    errmsg = e_positive;
	    p_ch = 1;
	}
	if (p_ch > Rows - min_rows() + 1)
	    p_ch = Rows - min_rows() + 1;

	
	
	if (p_ch != old_value && full_screen  && !gui.starting  )



	    command_height();
    }

    
    else if (pp == &p_uc)
    {
	if (p_uc < 0)
	{
	    errmsg = e_positive;
	    p_uc = 100;
	}
	if (p_uc && !old_value)
	    ml_open_files();
    }

    else if (pp == &curwin->w_p_cole)
    {
	if (curwin->w_p_cole < 0)
	{
	    errmsg = e_positive;
	    curwin->w_p_cole = 0;
	}
	else if (curwin->w_p_cole > 3)
	{
	    errmsg = e_invarg;
	    curwin->w_p_cole = 3;
	}
    }


    else if (pp == &p_mzq)
	mzvim_reset_timer();



    
    else if (pp == &p_pyx)
    {
	if (p_pyx != 0 && p_pyx != 2 && p_pyx != 3)
	    errmsg = e_invarg;
    }


    
    else if (pp == &p_ul)
    {
	
	p_ul = old_value;
	u_sync(TRUE);
	p_ul = value;
    }
    else if (pp == &curbuf->b_p_ul)
    {
	
	curbuf->b_p_ul = old_value;
	u_sync(TRUE);
	curbuf->b_p_ul = value;
    }


    
    else if (pp == &curwin->w_p_nuw)
    {
	if (curwin->w_p_nuw < 1)
	{
	    errmsg = e_positive;
	    curwin->w_p_nuw = 1;
	}
	if (curwin->w_p_nuw > 20)
	{
	    errmsg = e_invarg;
	    curwin->w_p_nuw = 20;
	}
	curwin->w_nrwidth_line_count = 0; 
    }


    else if (pp == &curbuf->b_p_tw)
    {
	if (curbuf->b_p_tw < 0)
	{
	    errmsg = e_positive;
	    curbuf->b_p_tw = 0;
	}

	{
	    win_T	*wp;
	    tabpage_T	*tp;

	    FOR_ALL_TAB_WINDOWS(tp, wp)
		check_colorcolumn(wp);
	}

    }

    
    if (Rows < min_rows() && full_screen)
    {
	if (errbuf != NULL)
	{
	    vim_snprintf((char *)errbuf, errbuflen, _("E593: Need at least %d lines"), min_rows());
	    errmsg = errbuf;
	}
	Rows = min_rows();
    }
    if (Columns < MIN_COLUMNS && full_screen)
    {
	if (errbuf != NULL)
	{
	    vim_snprintf((char *)errbuf, errbuflen, _("E594: Need at least %d columns"), MIN_COLUMNS);
	    errmsg = errbuf;
	}
	Columns = MIN_COLUMNS;
    }
    limit_screen_size();

    
    if (old_Rows != Rows || old_Columns != Columns)
    {
	
	if (updating_screen)
	    *pp = old_value;
	else if (full_screen  && !gui.starting  )



	    set_shellsize((int)Columns, (int)Rows, TRUE);
	else {
	    
	    
	    check_shellsize();
	    if (cmdline_row > Rows - p_ch && Rows > p_ch)
		cmdline_row = Rows - p_ch;
	}
	if (p_window >= Rows || !option_was_set((char_u *)"window"))
	    p_window = Rows - 1;
    }

    if (curbuf->b_p_ts <= 0)
    {
	errmsg = e_positive;
	curbuf->b_p_ts = 8;
    }
    if (p_tm < 0)
    {
	errmsg = e_positive;
	p_tm = 0;
    }
    if ((curwin->w_p_scr <= 0 || (curwin->w_p_scr > curwin->w_height && curwin->w_height > 0))

	    && full_screen)
    {
	if (pp == &(curwin->w_p_scr))
	{
	    if (curwin->w_p_scr != 0)
		errmsg = e_invalid_scroll_size;
	    win_comp_scroll(curwin);
	}
	
	
	else if (curwin->w_p_scr <= 0)
	    curwin->w_p_scr = 1;
	else  curwin->w_p_scr = curwin->w_height;
    }
    if (p_hi < 0)
    {
	errmsg = e_positive;
	p_hi = 0;
    }
    else if (p_hi > 10000)
    {
	errmsg = e_invarg;
	p_hi = 10000;
    }
    if (p_re < 0 || p_re > 2)
    {
	errmsg = e_invarg;
	p_re = 0;
    }
    if (p_report < 0)
    {
	errmsg = e_positive;
	p_report = 1;
    }
    if ((p_sj < -100 || p_sj >= Rows) && full_screen)
    {
	if (Rows != old_Rows)	
	    p_sj = Rows / 2;
	else {
	    errmsg = e_invalid_scroll_size;
	    p_sj = 1;
	}
    }
    if (p_so < 0 && full_screen)
    {
	errmsg = e_positive;
	p_so = 0;
    }
    if (p_siso < 0 && full_screen)
    {
	errmsg = e_positive;
	p_siso = 0;
    }

    if (p_cwh < 1)
    {
	errmsg = e_positive;
	p_cwh = 1;
    }

    if (p_ut < 0)
    {
	errmsg = e_positive;
	p_ut = 2000;
    }
    if (p_ss < 0)
    {
	errmsg = e_positive;
	p_ss = 0;
    }

    
    if ((opt_flags & (OPT_LOCAL | OPT_GLOBAL)) == 0)
	*(long *)get_varp_scope(&(options[opt_idx]), OPT_GLOBAL) = *pp;

    options[opt_idx].flags |= P_WAS_SET;


    apply_optionset_autocmd(opt_idx, opt_flags, old_value, old_global_value, value, errmsg);


    comp_col();			    
    if (curwin->w_curswant != MAXCOL && (options[opt_idx].flags & (P_CURSWANT | P_RALL)) != 0)
	curwin->w_set_curswant = TRUE;
    if ((opt_flags & OPT_NO_REDRAW) == 0)
	check_redraw(options[opt_idx].flags);

    return errmsg;
}


    void check_redraw(long_u flags)
{
    
    int		doclear = (flags & P_RCLR) == P_RCLR;
    int		all = ((flags & P_RALL) == P_RALL || doclear);

    if ((flags & P_RSTAT) || all)	
	status_redraw_all();

    if ((flags & P_RBUF) || (flags & P_RWIN) || all)
	changed_window_setting();
    if (flags & P_RBUF)
	redraw_curbuf_later(NOT_VALID);
    if (flags & P_RWINONLY)
	redraw_later(NOT_VALID);
    if (doclear)
	redraw_all_later(CLEAR);
    else if (all)
	redraw_all_later(NOT_VALID);
}


    int findoption(char_u *arg)
{
    int		    opt_idx;
    char	    *s, *p;
    static short    quick_tab[27] = {0, 0};	
    int		    is_term_opt;

    
    if (quick_tab[1] == 0)
    {
	p = options[0].fullname;
	for (opt_idx = 1; (s = options[opt_idx].fullname) != NULL; opt_idx++)
	{
	    if (s[0] != p[0])
	    {
		if (s[0] == 't' && s[1] == '_')
		    quick_tab[26] = opt_idx;
		else quick_tab[CharOrdLow(s[0])] = opt_idx;
	    }
	    p = s;
	}
    }

    

    if (!islower(arg[0]))

    if (arg[0] < 'a' || arg[0] > 'z')

	return -1;

    is_term_opt = (arg[0] == 't' && arg[1] == '_');
    if (is_term_opt)
	opt_idx = quick_tab[26];
    else opt_idx = quick_tab[CharOrdLow(arg[0])];
    for ( ; (s = options[opt_idx].fullname) != NULL; opt_idx++)
    {
	if (STRCMP(arg, s) == 0)		    
	    break;
    }
    if (s == NULL && !is_term_opt)
    {
	opt_idx = quick_tab[CharOrdLow(arg[0])];
	for ( ; options[opt_idx].fullname != NULL; opt_idx++)
	{
	    s = options[opt_idx].shortname;
	    if (s != NULL && STRCMP(arg, s) == 0)   
		break;
	    s = NULL;
	}
    }
    if (s == NULL)
	opt_idx = -1;
    return opt_idx;
}



    getoption_T get_option_value( char_u	*name, long	*numval, char_u	**stringval, int		opt_flags)




{
    int		opt_idx;
    char_u	*varp;

    opt_idx = findoption(name);
    if (opt_idx < 0)		    
    {
	int key;

	if (STRLEN(name) == 4 && name[0] == 't' && name[1] == '_' && (key = find_key_option(name, FALSE)) != 0)
	{
	    char_u key_name[2];
	    char_u *p;

	    
	    if (key < 0)
	    {
		key_name[0] = KEY2TERMCAP0(key);
		key_name[1] = KEY2TERMCAP1(key);
	    }
	    else {
		key_name[0] = KS_KEY;
		key_name[1] = (key & 0xff);
	    }
	    p = find_termcode(key_name);
	    if (p != NULL)
	    {
		if (stringval != NULL)
		    *stringval = vim_strsave(p);
		return gov_string;
	    }
	}
	return gov_unknown;
    }

    varp = get_varp_scope(&(options[opt_idx]), opt_flags);

    if (options[opt_idx].flags & P_STRING)
    {
	if (varp == NULL)		    
	    return gov_hidden_string;
	if (stringval != NULL)
	{

	    
	    if ((char_u **)varp == &curbuf->b_p_key && **(char_u **)(varp) != NUL)
		*stringval = vim_strsave((char_u *)"*****");
	    else  *stringval = vim_strsave(*(char_u **)(varp));

	}
	return gov_string;
    }

    if (varp == NULL)		    
	return (options[opt_idx].flags & P_NUM)
					 ? gov_hidden_number : gov_hidden_bool;
    if (options[opt_idx].flags & P_NUM)
	*numval = *(long *)varp;
    else {
	
	
	if ((int *)varp == &curbuf->b_changed)
	    *numval = curbufIsChanged();
	else *numval = (long) *(int *)varp;
    }
    return (options[opt_idx].flags & P_NUM) ? gov_number : gov_bool;
}




    int get_option_value_strict( char_u	*name, long	*numval, char_u	**stringval, int		opt_type, void	*from)





{
    int		opt_idx;
    char_u	*varp = NULL;
    struct vimoption *p;
    int		r = 0;

    opt_idx = findoption(name);
    if (opt_idx < 0)
	return 0;

    p = &(options[opt_idx]);

    
    if (p->var == NULL)
	return 0;

    if (p->flags & P_BOOL)
	r |= SOPT_BOOL;
    else if (p->flags & P_NUM)
	r |= SOPT_NUM;
    else if (p->flags & P_STRING)
	r |= SOPT_STRING;

    if (p->indir == PV_NONE)
    {
	if (opt_type == SREQ_GLOBAL)
	    r |= SOPT_GLOBAL;
	else return 0;
    }
    else {
	if (p->indir & PV_BOTH)
	    r |= SOPT_GLOBAL;
	else if (opt_type == SREQ_GLOBAL)
	    return 0; 

	if (p->indir & PV_WIN)
	{
	    if (opt_type == SREQ_BUF)
		return 0; 
	    else r |= SOPT_WIN;
	}
	else if (p->indir & PV_BUF)
	{
	    if (opt_type == SREQ_WIN)
		return 0; 
	    else r |= SOPT_BUF;
	}
    }

    if (stringval == NULL)
	return r;

    if (opt_type == SREQ_GLOBAL)
	varp = p->var;
    else {
	if (opt_type == SREQ_BUF)
	{
	    
	    
	    if (p->indir == PV_MOD)
	    {
		*numval = bufIsChanged((buf_T *)from);
		varp = NULL;
	    }

	    else if (p->indir == PV_KEY)
	    {
		
		*stringval = NULL;
		varp = NULL;
	    }

	    else {
		buf_T *save_curbuf = curbuf;

		
		curbuf = (buf_T *)from;
		curwin->w_buffer = curbuf;
		varp = get_varp(p);
		curbuf = save_curbuf;
		curwin->w_buffer = curbuf;
	    }
	}
	else if (opt_type == SREQ_WIN)
	{
	    win_T	*save_curwin = curwin;

	    curwin = (win_T *)from;
	    curbuf = curwin->w_buffer;
	    varp = get_varp(p);
	    curwin = save_curwin;
	    curbuf = curwin->w_buffer;
	}
	if (varp == p->var)
	    return (r | SOPT_UNSET);
    }

    if (varp != NULL)
    {
	if (p->flags & P_STRING)
	    *stringval = vim_strsave(*(char_u **)(varp));
	else if (p->flags & P_NUM)
	    *numval = *(long *) varp;
	else *numval = *(int *)varp;
    }

    return r;
}


    char_u * option_iter_next(void **option, int opt_type)
{
    struct vimoption	*ret = NULL;
    do {
	if (*option == NULL)
	    *option = (void *) options;
	else if (((struct vimoption *) (*option))->fullname == NULL)
	{
	    *option = NULL;
	    return NULL;
	}
	else *option = (void *) (((struct vimoption *) (*option)) + 1);

	ret = ((struct vimoption *) (*option));

	
	if (ret->var == NULL)
	{
	    ret = NULL;
	    continue;
	}

	switch (opt_type)
	{
	    case SREQ_GLOBAL:
		if (!(ret->indir == PV_NONE || ret->indir & PV_BOTH))
		    ret = NULL;
		break;
	    case SREQ_BUF:
		if (!(ret->indir & PV_BUF))
		    ret = NULL;
		break;
	    case SREQ_WIN:
		if (!(ret->indir & PV_WIN))
		    ret = NULL;
		break;
	    default:
		internal_error("option_iter_next()");
		return NULL;
	}
    }
    while (ret == NULL);

    return (char_u *)ret->fullname;
}



    long_u get_option_flags(int opt_idx)
{
    return options[opt_idx].flags;
}


    void set_option_flag(int opt_idx, long_u flag)
{
    options[opt_idx].flags |= flag;
}


    void clear_option_flag(int opt_idx, long_u flag)
{
    options[opt_idx].flags &= ~flag;
}


    int is_global_option(int opt_idx)
{
    return options[opt_idx].indir == PV_NONE;
}


    int is_global_local_option(int opt_idx)
{
    return options[opt_idx].indir & PV_BOTH;
}


    int is_window_local_option(int opt_idx)
{
    return options[opt_idx].var == VAR_WIN;
}


    int is_hidden_option(int opt_idx)
{
    return options[opt_idx].var == NULL;
}



    int is_crypt_key_option(int opt_idx)
{
    return options[opt_idx].indir == PV_KEY;
}



    char * set_option_value( char_u	*name, long	number, char_u	*string, int		opt_flags)




{
    int		opt_idx;
    char_u	*varp;
    long_u	flags;

    opt_idx = findoption(name);
    if (opt_idx < 0)
    {
	int key;

	if (STRLEN(name) == 4 && name[0] == 't' && name[1] == '_' && (key = find_key_option(name, FALSE)) != 0)
	{
	    char_u key_name[2];

	    if (key < 0)
	    {
		key_name[0] = KEY2TERMCAP0(key);
		key_name[1] = KEY2TERMCAP1(key);
	    }
	    else {
		key_name[0] = KS_KEY;
		key_name[1] = (key & 0xff);
	    }
	    add_termcode(key_name, string, FALSE);
	    if (full_screen)
		ttest(FALSE);
	    redraw_all_later(CLEAR);
	    return NULL;
	}

	semsg(_("E355: Unknown option: %s"), name);
    }
    else {
	flags = options[opt_idx].flags;

	
	if (sandbox > 0 && (flags & P_SECURE))
	{
	    emsg(_(e_not_allowed_in_sandbox));
	    return NULL;
	}

	if (flags & P_STRING)
	    return set_string_option(opt_idx, string, opt_flags);
	else {
	    varp = get_varp_scope(&(options[opt_idx]), opt_flags);
	    if (varp != NULL)	
	    {
		if (number == 0 && string != NULL)
		{
		    int idx;

		    
		    
		    for (idx = 0; string[idx] == '0'; ++idx)
			;
		    if (string[idx] != NUL || idx == 0)
		    {
			
			
			
			semsg(_("E521: Number required: &%s = '%s'"), name, string);
			return NULL;     

		    }
		}
		if (flags & P_NUM)
		    return set_num_option(opt_idx, varp, number, NULL, 0, opt_flags);
		else return set_bool_option(opt_idx, varp, (int)number, opt_flags);

	    }
	}
    }
    return NULL;
}


    char_u * get_term_code(char_u *tname)
{
    int	    opt_idx;
    char_u  *varp;

    if (tname[0] != 't' || tname[1] != '_' || tname[2] == NUL || tname[3] == NUL)
	return NULL;
    if ((opt_idx = findoption(tname)) >= 0)
    {
	varp = get_varp(&(options[opt_idx]));
	if (varp != NULL)
	    varp = *(char_u **)(varp);
	return varp;
    }
    return find_termcode(tname + 2);
}

    char_u * get_highlight_default(void)
{
    int i;

    i = findoption((char_u *)"hl");
    if (i >= 0)
	return options[i].def_val[VI_DEFAULT];
    return (char_u *)NULL;
}

    char_u * get_encoding_default(void)
{
    int i;

    i = findoption((char_u *)"enc");
    if (i >= 0)
	return options[i].def_val[VI_DEFAULT];
    return (char_u *)NULL;
}


    static int find_key_option(char_u *arg_arg, int has_lt)
{
    int		key = 0;
    int		modifiers;
    char_u	*arg = arg_arg;

    
    if (arg[0] == 't' && arg[1] == '_' && arg[2] && arg[3])
	key = TERMCAP2KEY(arg[2], arg[3]);
    else if (has_lt)
    {
	--arg;			    
	modifiers = 0;
	key = find_special_key(&arg, &modifiers, FSK_KEYCODE | FSK_KEEP_X_KEY | FSK_SIMPLIFY, NULL);
	if (modifiers)		    
	    key = 0;
    }
    return key;
}


    static void showoptions( int		all, int		opt_flags)


{
    struct vimoption	*p;
    int			col;
    int			isterm;
    char_u		*varp;
    struct vimoption	**items;
    int			item_count;
    int			run;
    int			row, rows;
    int			cols;
    int			i;
    int			len;




    items = ALLOC_MULT(struct vimoption *, OPTION_COUNT);
    if (items == NULL)
	return;

    
    if (all == 2)
	msg_puts_title(_("\n--- Terminal codes ---"));
    else if (opt_flags & OPT_GLOBAL)
	msg_puts_title(_("\n--- Global option values ---"));
    else if (opt_flags & OPT_LOCAL)
	msg_puts_title(_("\n--- Local option values ---"));
    else msg_puts_title(_("\n--- Options ---"));

    
    for (run = 1; run <= 2 && !got_int; ++run)
    {
	
	item_count = 0;
	for (p = &options[0]; p->fullname != NULL; p++)
	{
	    
	    if (message_filtered((char_u *)p->fullname))
		continue;

	    varp = NULL;
	    isterm = istermoption(p);
	    if ((opt_flags & (OPT_LOCAL | OPT_GLOBAL)) != 0)
	    {
		if (p->indir != PV_NONE && !isterm)
		    varp = get_varp_scope(p, opt_flags);
	    }
	    else varp = get_varp(p);
	    if (varp != NULL && ((all == 2 && isterm)
			|| (all == 1 && !isterm)
			|| (all == 0 && !optval_default(p, varp, p_cp))))
	    {
		if (opt_flags & OPT_ONECOLUMN)
		    len = Columns;
		else if (p->flags & P_BOOL)
		    len = 1;		
		else {
		    option_value2string(p, opt_flags);
		    len = (int)STRLEN(p->fullname) + vim_strsize(NameBuff) + 1;
		}
		if ((len <= INC - GAP && run == 1) || (len > INC - GAP && run == 2))
		    items[item_count++] = p;
	    }
	}

	
	if (run == 1)
	{
	    cols = (Columns + GAP - 3) / INC;
	    if (cols == 0)
		cols = 1;
	    rows = (item_count + cols - 1) / cols;
	}
	else	 rows = item_count;
	for (row = 0; row < rows && !got_int; ++row)
	{
	    msg_putchar('\n');			
	    if (got_int)			
		break;
	    col = 0;
	    for (i = row; i < item_count; i += rows)
	    {
		msg_col = col;			
		showoneopt(items[i], opt_flags);
		col += INC;
	    }
	    out_flush();
	    ui_breakcheck();
	}
    }
    vim_free(items);
}


    static int optval_default(struct vimoption *p, char_u *varp, int compatible)
{
    int		dvi;

    if (varp == NULL)
	return TRUE;	    
    dvi = ((p->flags & P_VI_DEF) || compatible) ? VI_DEFAULT : VIM_DEFAULT;
    if (p->flags & P_NUM)
	return (*(long *)varp == (long)(long_i)p->def_val[dvi]);
    if (p->flags & P_BOOL)
			
			
	return (*(int *)varp == (int)(long)(long_i)p->def_val[dvi]);
    
    return (STRCMP(*(char_u **)varp, p->def_val[dvi]) == 0);
}


    static void showoneopt( struct vimoption	*p, int			opt_flags)


{
    char_u	*varp;
    int		save_silent = silent_mode;

    silent_mode = FALSE;
    info_message = TRUE;	

    varp = get_varp_scope(p, opt_flags);

    
    if ((p->flags & P_BOOL) && ((int *)varp == &curbuf->b_changed ? !curbufIsChanged() : !*(int *)varp))
	msg_puts("no");
    else if ((p->flags & P_BOOL) && *(int *)varp < 0)
	msg_puts("--");
    else msg_puts("  ");
    msg_puts(p->fullname);
    if (!(p->flags & P_BOOL))
    {
	msg_putchar('=');
	
	option_value2string(p, opt_flags);
	msg_outtrans(NameBuff);
    }

    silent_mode = save_silent;
    info_message = FALSE;
}


    int makeset(FILE *fd, int opt_flags, int local_only)
{
    struct vimoption	*p;
    char_u		*varp;			
    char_u		*varp_fresh;		
    char_u		*varp_local = NULL;	
    char		*cmd;
    int			round;
    int			pri;

    
    for (pri = 1; pri >= 0; --pri)
    {
      for (p = &options[0]; !istermoption(p); p++)
	if (!(p->flags & P_NO_MKRC)
		&& !istermoption(p)
		&& ((pri == 1) == ((p->flags & P_PRI_MKRC) != 0)))
	{
	    
	    if (p->indir == PV_NONE && !(opt_flags & OPT_GLOBAL))
		continue;

	    
	    
	    if ((opt_flags & OPT_GLOBAL) && (p->flags & P_NOGLOB))
		continue;

	    
	    varp = get_varp_scope(p, opt_flags);
	    if ((opt_flags & OPT_GLOBAL) && optval_default(p, varp, p_cp))
		continue;

	    if ((opt_flags & OPT_SKIPRTP) && (p->var == (char_u *)&p_rtp || p->var == (char_u *)&p_pp))
		continue;

	    round = 2;
	    if (p->indir != PV_NONE)
	    {
		if (p->var == VAR_WIN)
		{
		    
		    if (!(opt_flags & OPT_LOCAL))
			continue;
		    
		    
		    if (!(opt_flags & OPT_GLOBAL) && !local_only)
		    {
			varp_fresh = get_varp_scope(p, OPT_GLOBAL);
			if (!optval_default(p, varp_fresh, p_cp))
			{
			    round = 1;
			    varp_local = varp;
			    varp = varp_fresh;
			}
		    }
		}
	    }

	    
	    
	    for ( ; round <= 2; varp = varp_local, ++round)
	    {
		if (round == 1 || (opt_flags & OPT_GLOBAL))
		    cmd = "set";
		else cmd = "setlocal";

		if (p->flags & P_BOOL)
		{
		    if (put_setbool(fd, cmd, p->fullname, *(int *)varp) == FAIL)
			return FAIL;
		}
		else if (p->flags & P_NUM)
		{
		    if (put_setnum(fd, cmd, p->fullname, (long *)varp) == FAIL)
			return FAIL;
		}
		else     {
		    int		do_endif = FALSE;

		    
		    
		    if (  p->indir == PV_SYN ||  p->indir == PV_FT)



		    {
			if (fprintf(fd, "if &%s != '%s'", p->fullname, *(char_u **)(varp)) < 0 || put_eol(fd) < 0)

			    return FAIL;
			do_endif = TRUE;
		    }
		    if (put_setstring(fd, cmd, p->fullname, (char_u **)varp, p->flags) == FAIL)
			return FAIL;
		    if (do_endif)
		    {
			if (put_line(fd, "endif") == FAIL)
			    return FAIL;
		    }
		}
	    }
	}
    }
    return OK;
}



    int makefoldset(FILE *fd)
{
    if (put_setstring(fd, "setlocal", "fdm", &curwin->w_p_fdm, 0) == FAIL  || put_setstring(fd, "setlocal", "fde", &curwin->w_p_fde, 0)

								       == FAIL  || put_setstring(fd, "setlocal", "fmr", &curwin->w_p_fmr, 0)

								       == FAIL || put_setstring(fd, "setlocal", "fdi", &curwin->w_p_fdi, 0)
								       == FAIL || put_setnum(fd, "setlocal", "fdl", &curwin->w_p_fdl) == FAIL || put_setnum(fd, "setlocal", "fml", &curwin->w_p_fml) == FAIL || put_setnum(fd, "setlocal", "fdn", &curwin->w_p_fdn) == FAIL || put_setbool(fd, "setlocal", "fen", curwin->w_p_fen) == FAIL )




	return FAIL;

    return OK;
}


    static int put_setstring( FILE	*fd, char	*cmd, char	*name, char_u	**valuep, long_u	flags)





{
    char_u	*s;
    char_u	*buf = NULL;
    char_u	*part = NULL;
    char_u	*p;

    if (fprintf(fd, "%s %s=", cmd, name) < 0)
	return FAIL;
    if (*valuep != NULL)
    {
	
	
	
	if (valuep == &p_pt)
	{
	    s = *valuep;
	    while (*s != NUL)
		if (put_escstr(fd, str2special(&s, FALSE), 2) == FAIL)
		    return FAIL;
	}
	
	else if ((flags & P_EXPAND) != 0)
	{
	    int  size = (int)STRLEN(*valuep) + 1;

	    
	    buf = alloc(size);
	    if (buf == NULL)
		goto fail;
	    home_replace(NULL, *valuep, buf, size, FALSE);

	    
	    
	    
	    if (size >= MAXPATHL && (flags & P_COMMA) != 0 && vim_strchr(*valuep, ',') != NULL)
	    {
		part = alloc(size);
		if (part == NULL)
		    goto fail;

		
		if (put_eol(fd) == FAIL)
		    goto fail;

		p = buf;
		while (*p != NUL)
		{
		    
		    
		    if (fprintf(fd, "%s %s+=", cmd, name) < 0)
			goto fail;
		    (void)copy_option_part(&p, part, size,  ",");
		    if (put_escstr(fd, part, 2) == FAIL || put_eol(fd) == FAIL)
			goto fail;
		}
		vim_free(buf);
		vim_free(part);
		return OK;
	    }
	    if (put_escstr(fd, buf, 2) == FAIL)
	    {
		vim_free(buf);
		return FAIL;
	    }
	    vim_free(buf);
	}
	else if (put_escstr(fd, *valuep, 2) == FAIL)
	    return FAIL;
    }
    if (put_eol(fd) < 0)
	return FAIL;
    return OK;
fail:
    vim_free(buf);
    vim_free(part);
    return FAIL;
}

    static int put_setnum( FILE	*fd, char	*cmd, char	*name, long	*valuep)




{
    long	wc;

    if (fprintf(fd, "%s %s=", cmd, name) < 0)
	return FAIL;
    if (wc_use_keyname((char_u *)valuep, &wc))
    {
	
	if (fputs((char *)get_special_key_name((int)wc, 0), fd) < 0)
	    return FAIL;
    }
    else if (fprintf(fd, "%ld", *valuep) < 0)
	return FAIL;
    if (put_eol(fd) < 0)
	return FAIL;
    return OK;
}

    static int put_setbool( FILE	*fd, char	*cmd, char	*name, int		value)




{
    if (value < 0)	
	return OK;
    if (fprintf(fd, "%s %s%s", cmd, value ? "" : "no", name) < 0 || put_eol(fd) < 0)
	return FAIL;
    return OK;
}


    void clear_termoptions(void)
{
    
    mch_setmouse(FALSE);	    

    mch_restore_title(SAVE_RESTORE_BOTH);    


    
    
    if (gui.starting)
	clear_xterm_clip();

    stoptermcap();			

    free_termoptions();
}

    void free_termoptions(void)
{
    struct vimoption   *p;

    for (p = options; p->fullname != NULL; p++)
	if (istermoption(p))
	{
	    if (p->flags & P_ALLOCED)
		free_string_option(*(char_u **)(p->var));
	    if (p->flags & P_DEF_ALLOCED)
		free_string_option(p->def_val[VI_DEFAULT]);
	    *(char_u **)(p->var) = empty_option;
	    p->def_val[VI_DEFAULT] = empty_option;
	    p->flags &= ~(P_ALLOCED|P_DEF_ALLOCED);

	    
	    set_option_sctx_idx((int)(p - options), OPT_GLOBAL, current_sctx);

	}
    clear_termcodes();
}


    void free_one_termoption(char_u *var)
{
    struct vimoption   *p;

    for (p = &options[0]; p->fullname != NULL; p++)
	if (p->var == var)
	{
	    if (p->flags & P_ALLOCED)
		free_string_option(*(char_u **)(p->var));
	    *(char_u **)(p->var) = empty_option;
	    p->flags &= ~P_ALLOCED;
	    break;
	}
}


    void set_term_defaults(void)
{
    struct vimoption   *p;

    for (p = &options[0]; p->fullname != NULL; p++)
    {
	if (istermoption(p) && p->def_val[VI_DEFAULT] != *(char_u **)(p->var))
	{
	    if (p->flags & P_DEF_ALLOCED)
	    {
		free_string_option(p->def_val[VI_DEFAULT]);
		p->flags &= ~P_DEF_ALLOCED;
	    }
	    p->def_val[VI_DEFAULT] = *(char_u **)(p->var);
	    if (p->flags & P_ALLOCED)
	    {
		p->flags |= P_DEF_ALLOCED;
		p->flags &= ~P_ALLOCED;	 
	    }
	}
    }
}


    static int istermoption(struct vimoption *p)
{
    return (p->fullname[0] == 't' && p->fullname[1] == '_');
}


    int istermoption_idx(int opt_idx)
{
    return istermoption(&options[opt_idx]);
}



    void unset_global_local_option(char_u *name, void *from)
{
    struct vimoption *p;
    int		opt_idx;
    buf_T	*buf = (buf_T *)from;

    opt_idx = findoption(name);
    if (opt_idx < 0)
	return;
    p = &(options[opt_idx]);

    switch ((int)p->indir)
    {
	
	case PV_EP:
	    clear_string_option(&buf->b_p_ep);
	    break;
	case PV_KP:
	    clear_string_option(&buf->b_p_kp);
	    break;
	case PV_PATH:
	    clear_string_option(&buf->b_p_path);
	    break;
	case PV_AR:
	    buf->b_p_ar = -1;
	    break;
	case PV_BKC:
	    clear_string_option(&buf->b_p_bkc);
	    buf->b_bkc_flags = 0;
	    break;
	case PV_TAGS:
	    clear_string_option(&buf->b_p_tags);
	    break;
	case PV_TC:
	    clear_string_option(&buf->b_p_tc);
	    buf->b_tc_flags = 0;
	    break;
        case PV_SISO:
            curwin->w_p_siso = -1;
            break;
        case PV_SO:
            curwin->w_p_so = -1;
            break;

	case PV_DEF:
	    clear_string_option(&buf->b_p_def);
	    break;
	case PV_INC:
	    clear_string_option(&buf->b_p_inc);
	    break;

	case PV_DICT:
	    clear_string_option(&buf->b_p_dict);
	    break;
	case PV_TSR:
	    clear_string_option(&buf->b_p_tsr);
	    break;
	case PV_FP:
	    clear_string_option(&buf->b_p_fp);
	    break;

	case PV_EFM:
	    clear_string_option(&buf->b_p_efm);
	    break;
	case PV_GP:
	    clear_string_option(&buf->b_p_gp);
	    break;
	case PV_MP:
	    clear_string_option(&buf->b_p_mp);
	    break;


	case PV_BEXPR:
	    clear_string_option(&buf->b_p_bexpr);
	    break;


	case PV_CM:
	    clear_string_option(&buf->b_p_cm);
	    break;


	case PV_SBR:
	    clear_string_option(&((win_T *)from)->w_p_sbr);
	    break;


	case PV_STL:
	    clear_string_option(&((win_T *)from)->w_p_stl);
	    break;

	case PV_UL:
	    buf->b_p_ul = NO_LOCAL_UNDOLEVEL;
	    break;

	case PV_LW:
	    clear_string_option(&buf->b_p_lw);
	    break;

	case PV_MENC:
	    clear_string_option(&buf->b_p_menc);
	    break;
	case PV_LCS:
	    clear_string_option(&((win_T *)from)->w_p_lcs);
	    set_chars_option((win_T *)from, &((win_T *)from)->w_p_lcs);
	    redraw_later(NOT_VALID);
	    break;
	case PV_VE:
	    clear_string_option(&((win_T *)from)->w_p_ve);
	    ((win_T *)from)->w_ve_flags = 0;
	    break;
    }
}



    static char_u * get_varp_scope(struct vimoption *p, int opt_flags)
{
    if ((opt_flags & OPT_GLOBAL) && p->indir != PV_NONE)
    {
	if (p->var == VAR_WIN)
	    return (char_u *)GLOBAL_WO(get_varp(p));
	return p->var;
    }
    if ((opt_flags & OPT_LOCAL) && ((int)p->indir & PV_BOTH))
    {
	switch ((int)p->indir)
	{
	    case PV_FP:   return (char_u *)&(curbuf->b_p_fp);

	    case PV_EFM:  return (char_u *)&(curbuf->b_p_efm);
	    case PV_GP:   return (char_u *)&(curbuf->b_p_gp);
	    case PV_MP:   return (char_u *)&(curbuf->b_p_mp);

	    case PV_EP:   return (char_u *)&(curbuf->b_p_ep);
	    case PV_KP:   return (char_u *)&(curbuf->b_p_kp);
	    case PV_PATH: return (char_u *)&(curbuf->b_p_path);
	    case PV_AR:   return (char_u *)&(curbuf->b_p_ar);
	    case PV_TAGS: return (char_u *)&(curbuf->b_p_tags);
	    case PV_TC:   return (char_u *)&(curbuf->b_p_tc);
            case PV_SISO: return (char_u *)&(curwin->w_p_siso);
            case PV_SO:   return (char_u *)&(curwin->w_p_so);

	    case PV_DEF:  return (char_u *)&(curbuf->b_p_def);
	    case PV_INC:  return (char_u *)&(curbuf->b_p_inc);

	    case PV_DICT: return (char_u *)&(curbuf->b_p_dict);
	    case PV_TSR:  return (char_u *)&(curbuf->b_p_tsr);

	    case PV_BEXPR: return (char_u *)&(curbuf->b_p_bexpr);


	    case PV_CM:	  return (char_u *)&(curbuf->b_p_cm);


	    case PV_SBR:  return (char_u *)&(curwin->w_p_sbr);


	    case PV_STL:  return (char_u *)&(curwin->w_p_stl);

	    case PV_UL:   return (char_u *)&(curbuf->b_p_ul);

	    case PV_LW:   return (char_u *)&(curbuf->b_p_lw);

	    case PV_BKC:  return (char_u *)&(curbuf->b_p_bkc);
	    case PV_MENC: return (char_u *)&(curbuf->b_p_menc);
	    case PV_LCS:  return (char_u *)&(curwin->w_p_lcs);
	    case PV_VE:	  return (char_u *)&(curwin->w_p_ve);

	}
	return NULL; 
    }
    return get_varp(p);
}


    char_u * get_option_varp_scope(int opt_idx, int opt_flags)
{
    return get_varp_scope(&(options[opt_idx]), opt_flags);
}


    static char_u * get_varp(struct vimoption *p)
{
    
    if (p->var == NULL)
	return NULL;

    switch ((int)p->indir)
    {
	case PV_NONE:	return p->var;

	
	case PV_EP:	return *curbuf->b_p_ep != NUL ? (char_u *)&curbuf->b_p_ep : p->var;
	case PV_KP:	return *curbuf->b_p_kp != NUL ? (char_u *)&curbuf->b_p_kp : p->var;
	case PV_PATH:	return *curbuf->b_p_path != NUL ? (char_u *)&(curbuf->b_p_path) : p->var;
	case PV_AR:	return curbuf->b_p_ar >= 0 ? (char_u *)&(curbuf->b_p_ar) : p->var;
	case PV_TAGS:	return *curbuf->b_p_tags != NUL ? (char_u *)&(curbuf->b_p_tags) : p->var;
	case PV_TC:	return *curbuf->b_p_tc != NUL ? (char_u *)&(curbuf->b_p_tc) : p->var;
	case PV_BKC:	return *curbuf->b_p_bkc != NUL ? (char_u *)&(curbuf->b_p_bkc) : p->var;
	case PV_SISO:	return curwin->w_p_siso >= 0 ? (char_u *)&(curwin->w_p_siso) : p->var;
	case PV_SO:	return curwin->w_p_so >= 0 ? (char_u *)&(curwin->w_p_so) : p->var;

	case PV_DEF:	return *curbuf->b_p_def != NUL ? (char_u *)&(curbuf->b_p_def) : p->var;
	case PV_INC:	return *curbuf->b_p_inc != NUL ? (char_u *)&(curbuf->b_p_inc) : p->var;

	case PV_DICT:	return *curbuf->b_p_dict != NUL ? (char_u *)&(curbuf->b_p_dict) : p->var;
	case PV_TSR:	return *curbuf->b_p_tsr != NUL ? (char_u *)&(curbuf->b_p_tsr) : p->var;
	case PV_FP:	return *curbuf->b_p_fp != NUL ? (char_u *)&(curbuf->b_p_fp) : p->var;

	case PV_EFM:	return *curbuf->b_p_efm != NUL ? (char_u *)&(curbuf->b_p_efm) : p->var;
	case PV_GP:	return *curbuf->b_p_gp != NUL ? (char_u *)&(curbuf->b_p_gp) : p->var;
	case PV_MP:	return *curbuf->b_p_mp != NUL ? (char_u *)&(curbuf->b_p_mp) : p->var;


	case PV_BEXPR:	return *curbuf->b_p_bexpr != NUL ? (char_u *)&(curbuf->b_p_bexpr) : p->var;


	case PV_CM:	return *curbuf->b_p_cm != NUL ? (char_u *)&(curbuf->b_p_cm) : p->var;


	case PV_SBR:	return *curwin->w_p_sbr != NUL ? (char_u *)&(curwin->w_p_sbr) : p->var;


	case PV_STL:	return *curwin->w_p_stl != NUL ? (char_u *)&(curwin->w_p_stl) : p->var;

	case PV_UL:	return curbuf->b_p_ul != NO_LOCAL_UNDOLEVEL ? (char_u *)&(curbuf->b_p_ul) : p->var;

	case PV_LW:	return *curbuf->b_p_lw != NUL ? (char_u *)&(curbuf->b_p_lw) : p->var;

	case PV_MENC:	return *curbuf->b_p_menc != NUL ? (char_u *)&(curbuf->b_p_menc) : p->var;

	case PV_ARAB:	return (char_u *)&(curwin->w_p_arab);

	case PV_LIST:	return (char_u *)&(curwin->w_p_list);
	case PV_LCS:	return *curwin->w_p_lcs != NUL ? (char_u *)&(curwin->w_p_lcs) : p->var;
	case PV_VE:	return *curwin->w_p_ve != NUL ? (char_u *)&(curwin->w_p_ve) : p->var;

	case PV_SPELL:	return (char_u *)&(curwin->w_p_spell);


	case PV_CUC:	return (char_u *)&(curwin->w_p_cuc);
	case PV_CUL:	return (char_u *)&(curwin->w_p_cul);
	case PV_CULOPT:	return (char_u *)&(curwin->w_p_culopt);
	case PV_CC:	return (char_u *)&(curwin->w_p_cc);


	case PV_DIFF:	return (char_u *)&(curwin->w_p_diff);


	case PV_FDC:	return (char_u *)&(curwin->w_p_fdc);
	case PV_FEN:	return (char_u *)&(curwin->w_p_fen);
	case PV_FDI:	return (char_u *)&(curwin->w_p_fdi);
	case PV_FDL:	return (char_u *)&(curwin->w_p_fdl);
	case PV_FDM:	return (char_u *)&(curwin->w_p_fdm);
	case PV_FML:	return (char_u *)&(curwin->w_p_fml);
	case PV_FDN:	return (char_u *)&(curwin->w_p_fdn);

	case PV_FDE:	return (char_u *)&(curwin->w_p_fde);
	case PV_FDT:	return (char_u *)&(curwin->w_p_fdt);

	case PV_FMR:	return (char_u *)&(curwin->w_p_fmr);

	case PV_NU:	return (char_u *)&(curwin->w_p_nu);
	case PV_RNU:	return (char_u *)&(curwin->w_p_rnu);

	case PV_NUW:	return (char_u *)&(curwin->w_p_nuw);

	case PV_WFH:	return (char_u *)&(curwin->w_p_wfh);
	case PV_WFW:	return (char_u *)&(curwin->w_p_wfw);

	case PV_PVW:	return (char_u *)&(curwin->w_p_pvw);


	case PV_RL:	return (char_u *)&(curwin->w_p_rl);
	case PV_RLC:	return (char_u *)&(curwin->w_p_rlc);

	case PV_SCROLL:	return (char_u *)&(curwin->w_p_scr);
	case PV_WRAP:	return (char_u *)&(curwin->w_p_wrap);

	case PV_LBR:	return (char_u *)&(curwin->w_p_lbr);
	case PV_BRI:	return (char_u *)&(curwin->w_p_bri);
	case PV_BRIOPT: return (char_u *)&(curwin->w_p_briopt);

	case PV_WCR:	return (char_u *)&(curwin->w_p_wcr);
	case PV_SCBIND: return (char_u *)&(curwin->w_p_scb);
	case PV_CRBIND: return (char_u *)&(curwin->w_p_crb);

	case PV_COCU:   return (char_u *)&(curwin->w_p_cocu);
	case PV_COLE:   return (char_u *)&(curwin->w_p_cole);


	case PV_TWK:    return (char_u *)&(curwin->w_p_twk);
	case PV_TWS:    return (char_u *)&(curwin->w_p_tws);
	case PV_TWSL:	return (char_u *)&(curbuf->b_p_twsl);


	case PV_AI:	return (char_u *)&(curbuf->b_p_ai);
	case PV_BIN:	return (char_u *)&(curbuf->b_p_bin);
	case PV_BOMB:	return (char_u *)&(curbuf->b_p_bomb);
	case PV_BH:	return (char_u *)&(curbuf->b_p_bh);
	case PV_BT:	return (char_u *)&(curbuf->b_p_bt);
	case PV_BL:	return (char_u *)&(curbuf->b_p_bl);
	case PV_CI:	return (char_u *)&(curbuf->b_p_ci);

	case PV_CIN:	return (char_u *)&(curbuf->b_p_cin);
	case PV_CINK:	return (char_u *)&(curbuf->b_p_cink);
	case PV_CINO:	return (char_u *)&(curbuf->b_p_cino);


	case PV_CINW:	return (char_u *)&(curbuf->b_p_cinw);

	case PV_COM:	return (char_u *)&(curbuf->b_p_com);

	case PV_CMS:	return (char_u *)&(curbuf->b_p_cms);

	case PV_CPT:	return (char_u *)&(curbuf->b_p_cpt);

	case PV_CSL:	return (char_u *)&(curbuf->b_p_csl);


	case PV_CFU:	return (char_u *)&(curbuf->b_p_cfu);
	case PV_OFU:	return (char_u *)&(curbuf->b_p_ofu);


	case PV_TFU:	return (char_u *)&(curbuf->b_p_tfu);

	case PV_EOL:	return (char_u *)&(curbuf->b_p_eol);
	case PV_FIXEOL:	return (char_u *)&(curbuf->b_p_fixeol);
	case PV_ET:	return (char_u *)&(curbuf->b_p_et);
	case PV_FENC:	return (char_u *)&(curbuf->b_p_fenc);
	case PV_FF:	return (char_u *)&(curbuf->b_p_ff);
	case PV_FT:	return (char_u *)&(curbuf->b_p_ft);
	case PV_FO:	return (char_u *)&(curbuf->b_p_fo);
	case PV_FLP:	return (char_u *)&(curbuf->b_p_flp);
	case PV_IMI:	return (char_u *)&(curbuf->b_p_iminsert);
	case PV_IMS:	return (char_u *)&(curbuf->b_p_imsearch);
	case PV_INF:	return (char_u *)&(curbuf->b_p_inf);
	case PV_ISK:	return (char_u *)&(curbuf->b_p_isk);


	case PV_INEX:	return (char_u *)&(curbuf->b_p_inex);



	case PV_INDE:	return (char_u *)&(curbuf->b_p_inde);
	case PV_INDK:	return (char_u *)&(curbuf->b_p_indk);


	case PV_FEX:	return (char_u *)&(curbuf->b_p_fex);


	case PV_KEY:	return (char_u *)&(curbuf->b_p_key);


	case PV_LISP:	return (char_u *)&(curbuf->b_p_lisp);

	case PV_ML:	return (char_u *)&(curbuf->b_p_ml);
	case PV_MPS:	return (char_u *)&(curbuf->b_p_mps);
	case PV_MA:	return (char_u *)&(curbuf->b_p_ma);
	case PV_MOD:	return (char_u *)&(curbuf->b_changed);
	case PV_NF:	return (char_u *)&(curbuf->b_p_nf);
	case PV_PI:	return (char_u *)&(curbuf->b_p_pi);

	case PV_QE:	return (char_u *)&(curbuf->b_p_qe);

	case PV_RO:	return (char_u *)&(curbuf->b_p_ro);

	case PV_SI:	return (char_u *)&(curbuf->b_p_si);

	case PV_SN:	return (char_u *)&(curbuf->b_p_sn);
	case PV_STS:	return (char_u *)&(curbuf->b_p_sts);

	case PV_SUA:	return (char_u *)&(curbuf->b_p_sua);

	case PV_SWF:	return (char_u *)&(curbuf->b_p_swf);

	case PV_SMC:	return (char_u *)&(curbuf->b_p_smc);
	case PV_SYN:	return (char_u *)&(curbuf->b_p_syn);


	case PV_SPC:	return (char_u *)&(curwin->w_s->b_p_spc);
	case PV_SPF:	return (char_u *)&(curwin->w_s->b_p_spf);
	case PV_SPL:	return (char_u *)&(curwin->w_s->b_p_spl);
	case PV_SPO:	return (char_u *)&(curwin->w_s->b_p_spo);

	case PV_SW:	return (char_u *)&(curbuf->b_p_sw);
	case PV_TS:	return (char_u *)&(curbuf->b_p_ts);
	case PV_TW:	return (char_u *)&(curbuf->b_p_tw);
	case PV_TX:	return (char_u *)&(curbuf->b_p_tx);

	case PV_UDF:	return (char_u *)&(curbuf->b_p_udf);

	case PV_WM:	return (char_u *)&(curbuf->b_p_wm);

	case PV_KMAP:	return (char_u *)&(curbuf->b_p_keymap);


	case PV_SCL:	return (char_u *)&(curwin->w_p_scl);


	case PV_VSTS:	return (char_u *)&(curbuf->b_p_vsts);
	case PV_VTS:	return (char_u *)&(curbuf->b_p_vts);

	default:	iemsg(_("E356: get_varp ERROR"));
    }
    
    return (char_u *)&(curbuf->b_p_wm);
}


    char_u * get_option_var(int opt_idx)
{
    return options[opt_idx].var;
}


    char_u * get_option_fullname(int opt_idx)
{
    return (char_u *)options[opt_idx].fullname;
}


    char_u * get_equalprg(void)
{
    if (*curbuf->b_p_ep == NUL)
	return p_ep;
    return curbuf->b_p_ep;
}


    void win_copy_options(win_T *wp_from, win_T *wp_to)
{
    copy_winopt(&wp_from->w_onebuf_opt, &wp_to->w_onebuf_opt);
    copy_winopt(&wp_from->w_allbuf_opt, &wp_to->w_allbuf_opt);
    after_copy_winopt(wp_to);
}


    void after_copy_winopt(win_T *wp UNUSED)
{

    briopt_check(wp);


    fill_culopt_flags(NULL, wp);
    check_colorcolumn(wp);

    set_chars_option(wp, &wp->w_p_lcs);
}


    void copy_winopt(winopt_T *from, winopt_T *to)
{

    to->wo_arab = from->wo_arab;

    to->wo_list = from->wo_list;
    to->wo_lcs = vim_strsave(from->wo_lcs);
    to->wo_nu = from->wo_nu;
    to->wo_rnu = from->wo_rnu;
    to->wo_ve = vim_strsave(from->wo_ve);
    to->wo_ve_flags = from->wo_ve_flags;

    to->wo_nuw = from->wo_nuw;


    to->wo_rl  = from->wo_rl;
    to->wo_rlc = vim_strsave(from->wo_rlc);


    to->wo_sbr = vim_strsave(from->wo_sbr);


    to->wo_stl = vim_strsave(from->wo_stl);

    to->wo_wrap = from->wo_wrap;

    to->wo_wrap_save = from->wo_wrap_save;


    to->wo_lbr = from->wo_lbr;
    to->wo_bri = from->wo_bri;
    to->wo_briopt = vim_strsave(from->wo_briopt);

    to->wo_wcr = vim_strsave(from->wo_wcr);
    to->wo_scb = from->wo_scb;
    to->wo_scb_save = from->wo_scb_save;
    to->wo_crb = from->wo_crb;
    to->wo_crb_save = from->wo_crb_save;

    to->wo_spell = from->wo_spell;


    to->wo_cuc = from->wo_cuc;
    to->wo_cul = from->wo_cul;
    to->wo_culopt = vim_strsave(from->wo_culopt);
    to->wo_cc = vim_strsave(from->wo_cc);


    to->wo_diff = from->wo_diff;
    to->wo_diff_saved = from->wo_diff_saved;


    to->wo_cocu = vim_strsave(from->wo_cocu);
    to->wo_cole = from->wo_cole;


    to->wo_twk = vim_strsave(from->wo_twk);
    to->wo_tws = vim_strsave(from->wo_tws);


    to->wo_fdc = from->wo_fdc;
    to->wo_fdc_save = from->wo_fdc_save;
    to->wo_fen = from->wo_fen;
    to->wo_fen_save = from->wo_fen_save;
    to->wo_fdi = vim_strsave(from->wo_fdi);
    to->wo_fml = from->wo_fml;
    to->wo_fdl = from->wo_fdl;
    to->wo_fdl_save = from->wo_fdl_save;
    to->wo_fdm = vim_strsave(from->wo_fdm);
    to->wo_fdm_save = from->wo_diff_saved ? vim_strsave(from->wo_fdm_save) : empty_option;
    to->wo_fdn = from->wo_fdn;

    to->wo_fde = vim_strsave(from->wo_fde);
    to->wo_fdt = vim_strsave(from->wo_fdt);

    to->wo_fmr = vim_strsave(from->wo_fmr);


    to->wo_scl = vim_strsave(from->wo_scl);



    
    mch_memmove(to->wo_script_ctx, from->wo_script_ctx, sizeof(to->wo_script_ctx));

    check_winopt(to);		
}


    static void check_win_options(win_T *win)
{
    check_winopt(&win->w_onebuf_opt);
    check_winopt(&win->w_allbuf_opt);
}


    static void check_winopt(winopt_T *wop UNUSED)
{

    check_string_option(&wop->wo_fdi);
    check_string_option(&wop->wo_fdm);
    check_string_option(&wop->wo_fdm_save);

    check_string_option(&wop->wo_fde);
    check_string_option(&wop->wo_fdt);

    check_string_option(&wop->wo_fmr);


    check_string_option(&wop->wo_scl);


    check_string_option(&wop->wo_rlc);


    check_string_option(&wop->wo_sbr);


    check_string_option(&wop->wo_stl);


    check_string_option(&wop->wo_culopt);
    check_string_option(&wop->wo_cc);


    check_string_option(&wop->wo_cocu);


    check_string_option(&wop->wo_twk);
    check_string_option(&wop->wo_tws);


    check_string_option(&wop->wo_briopt);

    check_string_option(&wop->wo_wcr);
    check_string_option(&wop->wo_lcs);
    check_string_option(&wop->wo_ve);
}


    void clear_winopt(winopt_T *wop UNUSED)
{

    clear_string_option(&wop->wo_fdi);
    clear_string_option(&wop->wo_fdm);
    clear_string_option(&wop->wo_fdm_save);

    clear_string_option(&wop->wo_fde);
    clear_string_option(&wop->wo_fdt);

    clear_string_option(&wop->wo_fmr);


    clear_string_option(&wop->wo_scl);


    clear_string_option(&wop->wo_briopt);

    clear_string_option(&wop->wo_wcr);

    clear_string_option(&wop->wo_rlc);


    clear_string_option(&wop->wo_sbr);


    clear_string_option(&wop->wo_stl);


    clear_string_option(&wop->wo_culopt);
    clear_string_option(&wop->wo_cc);


    clear_string_option(&wop->wo_cocu);


    clear_string_option(&wop->wo_twk);
    clear_string_option(&wop->wo_tws);

    clear_string_option(&wop->wo_lcs);
    clear_string_option(&wop->wo_ve);
}



static int buf_opt_idx[BV_COUNT];



    static void init_buf_opt_idx(void)
{
    static int did_init_buf_opt_idx = FALSE;
    int i;

    if (did_init_buf_opt_idx)
	return;
    did_init_buf_opt_idx = TRUE;
    for (i = 0; !istermoption_idx(i); i++)
	if (options[i].indir & PV_BUF)
	    buf_opt_idx[options[i].indir & PV_MASK] = i;
}





    void buf_copy_options(buf_T *buf, int flags)
{
    int		should_copy = TRUE;
    char_u	*save_p_isk = NULL;	    
    int		dont_do_help;
    int		did_isk = FALSE;

    
    if (p_cpo != NULL)
    {
	
	if ((vim_strchr(p_cpo, CPO_BUFOPTGLOB) == NULL || !(flags & BCO_ENTER))
		&& (buf->b_p_initialized || (!(flags & BCO_ENTER)
			&& vim_strchr(p_cpo, CPO_BUFOPT) != NULL)))
	    should_copy = FALSE;

	if (should_copy || (flags & BCO_ALWAYS))
	{

	    CLEAR_FIELD(buf->b_p_script_ctx);
	    init_buf_opt_idx();

	    
	    
	    
	    dont_do_help = ((flags & BCO_NOHELP) && buf->b_help)
						       || buf->b_p_initialized;
	    if (dont_do_help)		
	    {
		save_p_isk = buf->b_p_isk;
		buf->b_p_isk = NULL;
	    }
	    
	    if (!buf->b_p_initialized)
	    {
		free_buf_options(buf, TRUE);
		buf->b_p_ro = FALSE;		
		buf->b_p_tx = p_tx;
		buf->b_p_fenc = vim_strsave(p_fenc);
		switch (*p_ffs)
		{
		    case 'm':
			buf->b_p_ff = vim_strsave((char_u *)FF_MAC); break;
		    case 'd':
			buf->b_p_ff = vim_strsave((char_u *)FF_DOS); break;
		    case 'u':
			buf->b_p_ff = vim_strsave((char_u *)FF_UNIX); break;
		    default:
			buf->b_p_ff = vim_strsave(p_ff);
		}
		if (buf->b_p_ff != NULL)
		    buf->b_start_ffc = *buf->b_p_ff;
		buf->b_p_bh = empty_option;
		buf->b_p_bt = empty_option;
	    }
	    else free_buf_options(buf, FALSE);

	    buf->b_p_ai = p_ai;
	    COPY_OPT_SCTX(buf, BV_AI);
	    buf->b_p_ai_nopaste = p_ai_nopaste;
	    buf->b_p_sw = p_sw;
	    COPY_OPT_SCTX(buf, BV_SW);
	    buf->b_p_tw = p_tw;
	    COPY_OPT_SCTX(buf, BV_TW);
	    buf->b_p_tw_nopaste = p_tw_nopaste;
	    buf->b_p_tw_nobin = p_tw_nobin;
	    buf->b_p_wm = p_wm;
	    COPY_OPT_SCTX(buf, BV_WM);
	    buf->b_p_wm_nopaste = p_wm_nopaste;
	    buf->b_p_wm_nobin = p_wm_nobin;
	    buf->b_p_bin = p_bin;
	    COPY_OPT_SCTX(buf, BV_BIN);
	    buf->b_p_bomb = p_bomb;
	    COPY_OPT_SCTX(buf, BV_BOMB);
	    buf->b_p_fixeol = p_fixeol;
	    COPY_OPT_SCTX(buf, BV_FIXEOL);
	    buf->b_p_et = p_et;
	    COPY_OPT_SCTX(buf, BV_ET);
	    buf->b_p_et_nobin = p_et_nobin;
	    buf->b_p_et_nopaste = p_et_nopaste;
	    buf->b_p_ml = p_ml;
	    COPY_OPT_SCTX(buf, BV_ML);
	    buf->b_p_ml_nobin = p_ml_nobin;
	    buf->b_p_inf = p_inf;
	    COPY_OPT_SCTX(buf, BV_INF);
	    if (cmdmod.cmod_flags & CMOD_NOSWAPFILE)
		buf->b_p_swf = FALSE;
	    else {
		buf->b_p_swf = p_swf;
		COPY_OPT_SCTX(buf, BV_INF);
	    }
	    buf->b_p_cpt = vim_strsave(p_cpt);
	    COPY_OPT_SCTX(buf, BV_CPT);

	    buf->b_p_csl = vim_strsave(p_csl);
	    COPY_OPT_SCTX(buf, BV_CSL);


	    buf->b_p_cfu = vim_strsave(p_cfu);
	    COPY_OPT_SCTX(buf, BV_CFU);
	    buf->b_p_ofu = vim_strsave(p_ofu);
	    COPY_OPT_SCTX(buf, BV_OFU);


	    buf->b_p_tfu = vim_strsave(p_tfu);
	    COPY_OPT_SCTX(buf, BV_TFU);

	    buf->b_p_sts = p_sts;
	    COPY_OPT_SCTX(buf, BV_STS);
	    buf->b_p_sts_nopaste = p_sts_nopaste;

	    buf->b_p_vsts = vim_strsave(p_vsts);
	    COPY_OPT_SCTX(buf, BV_VSTS);
	    if (p_vsts && p_vsts != empty_option)
		tabstop_set(p_vsts, &buf->b_p_vsts_array);
	    else buf->b_p_vsts_array = 0;
	    buf->b_p_vsts_nopaste = p_vsts_nopaste ? vim_strsave(p_vsts_nopaste) : NULL;

	    buf->b_p_sn = p_sn;
	    COPY_OPT_SCTX(buf, BV_SN);
	    buf->b_p_com = vim_strsave(p_com);
	    COPY_OPT_SCTX(buf, BV_COM);

	    buf->b_p_cms = vim_strsave(p_cms);
	    COPY_OPT_SCTX(buf, BV_CMS);

	    buf->b_p_fo = vim_strsave(p_fo);
	    COPY_OPT_SCTX(buf, BV_FO);
	    buf->b_p_flp = vim_strsave(p_flp);
	    COPY_OPT_SCTX(buf, BV_FLP);
	    
	    
	    buf->b_p_nf = vim_strsave(p_nf);
	    COPY_OPT_SCTX(buf, BV_NF);
	    buf->b_p_mps = vim_strsave(p_mps);
	    COPY_OPT_SCTX(buf, BV_MPS);

	    buf->b_p_si = p_si;
	    COPY_OPT_SCTX(buf, BV_SI);

	    buf->b_p_ci = p_ci;
	    COPY_OPT_SCTX(buf, BV_CI);

	    buf->b_p_cin = p_cin;
	    COPY_OPT_SCTX(buf, BV_CIN);
	    buf->b_p_cink = vim_strsave(p_cink);
	    COPY_OPT_SCTX(buf, BV_CINK);
	    buf->b_p_cino = vim_strsave(p_cino);
	    COPY_OPT_SCTX(buf, BV_CINO);

	    
	    buf->b_p_ft = empty_option;
	    buf->b_p_pi = p_pi;
	    COPY_OPT_SCTX(buf, BV_PI);

	    buf->b_p_cinw = vim_strsave(p_cinw);
	    COPY_OPT_SCTX(buf, BV_CINW);


	    buf->b_p_lisp = p_lisp;
	    COPY_OPT_SCTX(buf, BV_LISP);


	    
	    buf->b_p_syn = empty_option;
	    buf->b_p_smc = p_smc;
	    COPY_OPT_SCTX(buf, BV_SMC);
	    buf->b_s.b_syn_isk = empty_option;


	    buf->b_s.b_p_spc = vim_strsave(p_spc);
	    COPY_OPT_SCTX(buf, BV_SPC);
	    (void)compile_cap_prog(&buf->b_s);
	    buf->b_s.b_p_spf = vim_strsave(p_spf);
	    COPY_OPT_SCTX(buf, BV_SPF);
	    buf->b_s.b_p_spl = vim_strsave(p_spl);
	    COPY_OPT_SCTX(buf, BV_SPL);
	    buf->b_s.b_p_spo = vim_strsave(p_spo);
	    COPY_OPT_SCTX(buf, BV_SPO);


	    buf->b_p_inde = vim_strsave(p_inde);
	    COPY_OPT_SCTX(buf, BV_INDE);
	    buf->b_p_indk = vim_strsave(p_indk);
	    COPY_OPT_SCTX(buf, BV_INDK);

	    buf->b_p_fp = empty_option;

	    buf->b_p_fex = vim_strsave(p_fex);
	    COPY_OPT_SCTX(buf, BV_FEX);


	    buf->b_p_key = vim_strsave(p_key);
	    COPY_OPT_SCTX(buf, BV_KEY);


	    buf->b_p_sua = vim_strsave(p_sua);
	    COPY_OPT_SCTX(buf, BV_SUA);


	    buf->b_p_keymap = vim_strsave(p_keymap);
	    COPY_OPT_SCTX(buf, BV_KMAP);
	    buf->b_kmap_state |= KEYMAP_INIT;


	    buf->b_p_twsl = p_twsl;
	    COPY_OPT_SCTX(buf, BV_TWSL);

	    
	    
	    buf->b_p_iminsert = p_iminsert;
	    COPY_OPT_SCTX(buf, BV_IMI);
	    buf->b_p_imsearch = p_imsearch;
	    COPY_OPT_SCTX(buf, BV_IMS);

	    
	    
	    buf->b_p_ar = -1;
	    buf->b_p_ul = NO_LOCAL_UNDOLEVEL;
	    buf->b_p_bkc = empty_option;
	    buf->b_bkc_flags = 0;

	    buf->b_p_gp = empty_option;
	    buf->b_p_mp = empty_option;
	    buf->b_p_efm = empty_option;

	    buf->b_p_ep = empty_option;
	    buf->b_p_kp = empty_option;
	    buf->b_p_path = empty_option;
	    buf->b_p_tags = empty_option;
	    buf->b_p_tc = empty_option;
	    buf->b_tc_flags = 0;

	    buf->b_p_def = empty_option;
	    buf->b_p_inc = empty_option;

	    buf->b_p_inex = vim_strsave(p_inex);
	    COPY_OPT_SCTX(buf, BV_INEX);


	    buf->b_p_dict = empty_option;
	    buf->b_p_tsr = empty_option;

	    buf->b_p_qe = vim_strsave(p_qe);
	    COPY_OPT_SCTX(buf, BV_QE);


	    buf->b_p_bexpr = empty_option;


	    buf->b_p_cm = empty_option;


	    buf->b_p_udf = p_udf;
	    COPY_OPT_SCTX(buf, BV_UDF);


	    buf->b_p_lw = empty_option;

	    buf->b_p_menc = empty_option;

	    
	    if (dont_do_help)
	    {
		buf->b_p_isk = save_p_isk;

		if (p_vts && p_vts != empty_option && !buf->b_p_vts_array)
		    tabstop_set(p_vts, &buf->b_p_vts_array);
		else buf->b_p_vts_array = NULL;

	    }
	    else {
		buf->b_p_isk = vim_strsave(p_isk);
		COPY_OPT_SCTX(buf, BV_ISK);
		did_isk = TRUE;
		buf->b_p_ts = p_ts;

		buf->b_p_vts = vim_strsave(p_vts);
		COPY_OPT_SCTX(buf, BV_VTS);
		if (p_vts && p_vts != empty_option && !buf->b_p_vts_array)
		    tabstop_set(p_vts, &buf->b_p_vts_array);
		else buf->b_p_vts_array = NULL;

		buf->b_help = FALSE;
		if (buf->b_p_bt[0] == 'h')
		    clear_string_option(&buf->b_p_bt);
		buf->b_p_ma = p_ma;
		COPY_OPT_SCTX(buf, BV_MA);
	    }
	}

	
	if (should_copy)
	    buf->b_p_initialized = TRUE;
    }

    check_buf_options(buf);	    
    if (did_isk)
	(void)buf_init_chartab(buf, FALSE);
}


    void reset_modifiable(void)
{
    int		opt_idx;

    curbuf->b_p_ma = FALSE;
    p_ma = FALSE;
    opt_idx = findoption((char_u *)"ma");
    if (opt_idx >= 0)
	options[opt_idx].def_val[VI_DEFAULT] = FALSE;
}


    void set_iminsert_global(void)
{
    p_iminsert = curbuf->b_p_iminsert;
}


    void set_imsearch_global(void)
{
    p_imsearch = curbuf->b_p_imsearch;
}

static int expand_option_idx = -1;
static char_u expand_option_name[5] = {'t', '_', NUL, NUL, NUL};
static int expand_option_flags = 0;

    void set_context_in_set_cmd( expand_T	*xp, char_u	*arg, int		opt_flags)



{
    int		nextchar;
    long_u	flags = 0;	
    int		opt_idx = 0;	
    char_u	*p;
    char_u	*s;
    int		is_term_option = FALSE;
    int		key;

    expand_option_flags = opt_flags;

    xp->xp_context = EXPAND_SETTINGS;
    if (*arg == NUL)
    {
	xp->xp_pattern = arg;
	return;
    }
    p = arg + STRLEN(arg) - 1;
    if (*p == ' ' && *(p - 1) != '\\')
    {
	xp->xp_pattern = p + 1;
	return;
    }
    while (p > arg)
    {
	s = p;
	
	if (*p == ' ' || *p == ',')
	{
	    while (s > arg && *(s - 1) == '\\')
		--s;
	}
	
	if (*p == ' ' && ((p - s) & 1) == 0)
	{
	    ++p;
	    break;
	}
	--p;
    }
    if (STRNCMP(p, "no", 2) == 0 && STRNCMP(p, "novice", 6) != 0)
    {
	xp->xp_context = EXPAND_BOOL_SETTINGS;
	p += 2;
    }
    if (STRNCMP(p, "inv", 3) == 0)
    {
	xp->xp_context = EXPAND_BOOL_SETTINGS;
	p += 3;
    }
    xp->xp_pattern = arg = p;
    if (*arg == '<')
    {
	while (*p != '>')
	    if (*p++ == NUL)	    
		return;
	key = get_special_key_code(arg + 1);
	if (key == 0)		    
	{
	    xp->xp_context = EXPAND_NOTHING;
	    return;
	}
	nextchar = *++p;
	is_term_option = TRUE;
	expand_option_name[2] = KEY2TERMCAP0(key);
	expand_option_name[3] = KEY2TERMCAP1(key);
    }
    else {
	if (p[0] == 't' && p[1] == '_')
	{
	    p += 2;
	    if (*p != NUL)
		++p;
	    if (*p == NUL)
		return;		
	    nextchar = *++p;
	    is_term_option = TRUE;
	    expand_option_name[2] = p[-2];
	    expand_option_name[3] = p[-1];
	}
	else {
	    
	    while (ASCII_ISALNUM(*p) || *p == '_' || *p == '*')
		p++;
	    if (*p == NUL)
		return;
	    nextchar = *p;
	    *p = NUL;
	    opt_idx = findoption(arg);
	    *p = nextchar;
	    if (opt_idx == -1 || options[opt_idx].var == NULL)
	    {
		xp->xp_context = EXPAND_NOTHING;
		return;
	    }
	    flags = options[opt_idx].flags;
	    if (flags & P_BOOL)
	    {
		xp->xp_context = EXPAND_NOTHING;
		return;
	    }
	}
    }
    
    if ((nextchar == '-' || nextchar == '+' || nextchar == '^') && p[1] == '=')
    {
	++p;
	nextchar = '=';
    }
    if ((nextchar != '=' && nextchar != ':')
				    || xp->xp_context == EXPAND_BOOL_SETTINGS)
    {
	xp->xp_context = EXPAND_UNSUCCESSFUL;
	return;
    }
    if (xp->xp_context != EXPAND_BOOL_SETTINGS && p[1] == NUL)
    {
	xp->xp_context = EXPAND_OLD_SETTING;
	if (is_term_option)
	    expand_option_idx = -1;
	else expand_option_idx = opt_idx;
	xp->xp_pattern = p + 1;
	return;
    }
    xp->xp_context = EXPAND_NOTHING;
    if (is_term_option || (flags & P_NUM))
	return;

    xp->xp_pattern = p + 1;

    if (flags & P_EXPAND)
    {
	p = options[opt_idx].var;
	if (p == (char_u *)&p_bdir || p == (char_u *)&p_dir || p == (char_u *)&p_path || p == (char_u *)&p_pp || p == (char_u *)&p_rtp  || p == (char_u *)&p_cdpath   || p == (char_u *)&p_vdir  )










	{
	    xp->xp_context = EXPAND_DIRECTORIES;
	    if (p == (char_u *)&p_path  || p == (char_u *)&p_cdpath  )



		xp->xp_backslash = XP_BS_THREE;
	    else xp->xp_backslash = XP_BS_ONE;
	}
	else if (p == (char_u *)&p_ft)
	{
	    xp->xp_context = EXPAND_FILETYPE;
	}
	else {
	    xp->xp_context = EXPAND_FILES;
	    
	    if (p == (char_u *)&p_tags)
		xp->xp_backslash = XP_BS_THREE;
	    else xp->xp_backslash = XP_BS_ONE;
	}
    }

    
    
    for (p = arg + STRLEN(arg) - 1; p > xp->xp_pattern; --p)
    {
	
	if (*p == ' ' || *p == ',')
	{
	    s = p;
	    while (s > xp->xp_pattern && *(s - 1) == '\\')
		--s;
	    if ((*p == ' ' && (xp->xp_backslash == XP_BS_THREE && (p - s) < 3))
		    || (*p == ',' && (flags & P_COMMA) && ((p - s) & 1) == 0))
	    {
		xp->xp_pattern = p + 1;
		break;
	    }
	}


	
	if (options[opt_idx].var == (char_u *)&p_sps && STRNCMP(p, "file:", 5) == 0)
	{
	    xp->xp_pattern = p + 5;
	    break;
	}

    }

    return;
}

    int ExpandSettings( expand_T	*xp, regmatch_T	*regmatch, int		*num_file, char_u	***file)




{
    int		num_normal = 0;	    
    int		num_term = 0;	    
    int		opt_idx;
    int		match;
    int		count = 0;
    char_u	*str;
    int		loop;
    int		is_term_opt;
    char_u	name_buf[MAX_KEY_NAME_LEN];
    static char *(names[]) = {"all", "termcap";
    int		ic = regmatch->rm_ic;	

    
    
    
    for (loop = 0; loop <= 1; ++loop)
    {
	regmatch->rm_ic = ic;
	if (xp->xp_context != EXPAND_BOOL_SETTINGS)
	{
	    for (match = 0; match < (int)ARRAY_LENGTH(names); ++match)
		if (vim_regexec(regmatch, (char_u *)names[match], (colnr_T)0))
		{
		    if (loop == 0)
			num_normal++;
		    else (*file)[count++] = vim_strsave((char_u *)names[match]);
		}
	}
	for (opt_idx = 0; (str = (char_u *)options[opt_idx].fullname) != NULL;
								    opt_idx++)
	{
	    if (options[opt_idx].var == NULL)
		continue;
	    if (xp->xp_context == EXPAND_BOOL_SETTINGS && !(options[opt_idx].flags & P_BOOL))
		continue;
	    is_term_opt = istermoption_idx(opt_idx);
	    if (is_term_opt && num_normal > 0)
		continue;
	    match = FALSE;
	    if (vim_regexec(regmatch, str, (colnr_T)0)
		    || (options[opt_idx].shortname != NULL && vim_regexec(regmatch, (char_u *)options[opt_idx].shortname, (colnr_T)0)))

		match = TRUE;
	    else if (is_term_opt)
	    {
		name_buf[0] = '<';
		name_buf[1] = 't';
		name_buf[2] = '_';
		name_buf[3] = str[2];
		name_buf[4] = str[3];
		name_buf[5] = '>';
		name_buf[6] = NUL;
		if (vim_regexec(regmatch, name_buf, (colnr_T)0))
		{
		    match = TRUE;
		    str = name_buf;
		}
	    }
	    if (match)
	    {
		if (loop == 0)
		{
		    if (is_term_opt)
			num_term++;
		    else num_normal++;
		}
		else (*file)[count++] = vim_strsave(str);
	    }
	}
	
	if (xp->xp_context != EXPAND_BOOL_SETTINGS  && num_normal == 0)
	{
	    for (opt_idx = 0; (str = get_termcode(opt_idx)) != NULL; opt_idx++)
	    {
		if (!isprint(str[0]) || !isprint(str[1]))
		    continue;

		name_buf[0] = 't';
		name_buf[1] = '_';
		name_buf[2] = str[0];
		name_buf[3] = str[1];
		name_buf[4] = NUL;

		match = FALSE;
		if (vim_regexec(regmatch, name_buf, (colnr_T)0))
		    match = TRUE;
		else {
		    name_buf[0] = '<';
		    name_buf[1] = 't';
		    name_buf[2] = '_';
		    name_buf[3] = str[0];
		    name_buf[4] = str[1];
		    name_buf[5] = '>';
		    name_buf[6] = NUL;

		    if (vim_regexec(regmatch, name_buf, (colnr_T)0))
			match = TRUE;
		}
		if (match)
		{
		    if (loop == 0)
			num_term++;
		    else (*file)[count++] = vim_strsave(name_buf);
		}
	    }

	    
	    regmatch->rm_ic = TRUE;		
	    for (opt_idx = 0; (str = get_key_name(opt_idx)) != NULL; opt_idx++)
	    {
		name_buf[0] = '<';
		STRCPY(name_buf + 1, str);
		STRCAT(name_buf, ">");

		if (vim_regexec(regmatch, name_buf, (colnr_T)0))
		{
		    if (loop == 0)
			num_term++;
		    else (*file)[count++] = vim_strsave(name_buf);
		}
	    }
	}
	if (loop == 0)
	{
	    if (num_normal > 0)
		*num_file = num_normal;
	    else if (num_term > 0)
		*num_file = num_term;
	    else return OK;
	    *file = ALLOC_MULT(char_u *, *num_file);
	    if (*file == NULL)
	    {
		*file = (char_u **)"";
		return FAIL;
	    }
	}
    }
    return OK;
}

    int ExpandOldSetting(int *num_file, char_u ***file)
{
    char_u  *var = NULL;	
    char_u  *buf;

    *num_file = 0;
    *file = ALLOC_ONE(char_u *);
    if (*file == NULL)
	return FAIL;

    
    if (expand_option_idx < 0)
    {
	var = find_termcode(expand_option_name + 2);
	if (var == NULL)
	    expand_option_idx = findoption(expand_option_name);
    }

    if (expand_option_idx >= 0)
    {
	
	option_value2string(&options[expand_option_idx], expand_option_flags);
	var = NameBuff;
    }
    else if (var == NULL)
	var = (char_u *)"";

    
    
    buf = vim_strsave_escaped(var, escape_chars);

    if (buf == NULL)
    {
	VIM_CLEAR(*file);
	return FAIL;
    }


    
    
    for (var = buf; *var != NUL; MB_PTR_ADV(var))
	if (var[0] == '\\' && var[1] == '\\' && expand_option_idx >= 0 && (options[expand_option_idx].flags & P_EXPAND)

		&& vim_isfilec(var[2])
		&& (var[2] != '\\' || (var == buf && var[4] != '\\')))
	    STRMOVE(var, var + 1);


    *file[0] = buf;
    *num_file = 1;
    return OK;
}


    static void option_value2string( struct vimoption	*opp, int			opt_flags)


{
    char_u	*varp;

    varp = get_varp_scope(opp, opt_flags);

    if (opp->flags & P_NUM)
    {
	long wc = 0;

	if (wc_use_keyname(varp, &wc))
	    STRCPY(NameBuff, get_special_key_name((int)wc, 0));
	else if (wc != 0)
	    STRCPY(NameBuff, transchar((int)wc));
	else sprintf((char *)NameBuff, "%ld", *(long *)varp);
    }
    else     {
	varp = *(char_u **)(varp);
	if (varp == NULL)		    
	    NameBuff[0] = NUL;

	
	else if (opp->var == (char_u *)&p_key && *varp)
	    STRCPY(NameBuff, "*****");

	else if (opp->flags & P_EXPAND)
	    home_replace(NULL, varp, NameBuff, MAXPATHL, FALSE);
	
	else if ((char_u **)opp->var == &p_pt)
	    str2specialbuf(p_pt, NameBuff, MAXPATHL);
	else vim_strncpy(NameBuff, varp, MAXPATHL - 1);
    }
}


    static int wc_use_keyname(char_u *varp, long *wcp)
{
    if (((long *)varp == &p_wc) || ((long *)varp == &p_wcm))
    {
	*wcp = *(long *)varp;
	if (IS_SPECIAL(*wcp) || find_special_key_in_table((int)*wcp) >= 0)
	    return TRUE;
    }
    return FALSE;
}


    int shortmess(int x)
{
    return p_shm != NULL && (   vim_strchr(p_shm, x) != NULL || (vim_strchr(p_shm, 'a') != NULL && vim_strchr((char_u *)SHM_A, x) != NULL));


}


    static void paste_option_changed(void)
{
    static int	old_p_paste = FALSE;
    static int	save_sm = 0;
    static int	save_sta = 0;

    static int	save_ru = 0;


    static int	save_ri = 0;
    static int	save_hkmap = 0;

    buf_T	*buf;

    if (p_paste)
    {
	
	if (!old_p_paste)
	{
	    
	    FOR_ALL_BUFFERS(buf)
	    {
		buf->b_p_tw_nopaste = buf->b_p_tw;
		buf->b_p_wm_nopaste = buf->b_p_wm;
		buf->b_p_sts_nopaste = buf->b_p_sts;
		buf->b_p_ai_nopaste = buf->b_p_ai;
		buf->b_p_et_nopaste = buf->b_p_et;

		if (buf->b_p_vsts_nopaste)
		    vim_free(buf->b_p_vsts_nopaste);
		buf->b_p_vsts_nopaste = buf->b_p_vsts && buf->b_p_vsts != empty_option ? vim_strsave(buf->b_p_vsts) : NULL;

	    }

	    
	    save_sm = p_sm;
	    save_sta = p_sta;

	    save_ru = p_ru;


	    save_ri = p_ri;
	    save_hkmap = p_hkmap;

	    
	    p_ai_nopaste = p_ai;
	    p_et_nopaste = p_et;
	    p_sts_nopaste = p_sts;
	    p_tw_nopaste = p_tw;
	    p_wm_nopaste = p_wm;

	    if (p_vsts_nopaste)
		vim_free(p_vsts_nopaste);
	    p_vsts_nopaste = p_vsts && p_vsts != empty_option ? vim_strsave(p_vsts) : NULL;

	}

	
	
	FOR_ALL_BUFFERS(buf)
	{
	    buf->b_p_tw = 0;	    
	    buf->b_p_wm = 0;	    
	    buf->b_p_sts = 0;	    
	    buf->b_p_ai = 0;	    
	    buf->b_p_et = 0;	    

	    if (buf->b_p_vsts)
		free_string_option(buf->b_p_vsts);
	    buf->b_p_vsts = empty_option;
	    if (buf->b_p_vsts_array)
		vim_free(buf->b_p_vsts_array);
	    buf->b_p_vsts_array = 0;

	}

	
	p_sm = 0;		    
	p_sta = 0;		    

	if (p_ru)
	    status_redraw_all();    
	p_ru = 0;		    


	p_ri = 0;		    
	p_hkmap = 0;		    

	
	p_tw = 0;
	p_wm = 0;
	p_sts = 0;
	p_ai = 0;

	if (p_vsts)
	    free_string_option(p_vsts);
	p_vsts = empty_option;

    }

    
    else if (old_p_paste)
    {
	
	FOR_ALL_BUFFERS(buf)
	{
	    buf->b_p_tw = buf->b_p_tw_nopaste;
	    buf->b_p_wm = buf->b_p_wm_nopaste;
	    buf->b_p_sts = buf->b_p_sts_nopaste;
	    buf->b_p_ai = buf->b_p_ai_nopaste;
	    buf->b_p_et = buf->b_p_et_nopaste;

	    if (buf->b_p_vsts)
		free_string_option(buf->b_p_vsts);
	    buf->b_p_vsts = buf->b_p_vsts_nopaste ? vim_strsave(buf->b_p_vsts_nopaste) : empty_option;
	    if (buf->b_p_vsts_array)
		vim_free(buf->b_p_vsts_array);
	    if (buf->b_p_vsts && buf->b_p_vsts != empty_option)
		tabstop_set(buf->b_p_vsts, &buf->b_p_vsts_array);
	    else buf->b_p_vsts_array = 0;

	}

	
	p_sm = save_sm;
	p_sta = save_sta;

	if (p_ru != save_ru)
	    status_redraw_all();    
	p_ru = save_ru;


	p_ri = save_ri;
	p_hkmap = save_hkmap;

	
	p_ai = p_ai_nopaste;
	p_et = p_et_nopaste;
	p_sts = p_sts_nopaste;
	p_tw = p_tw_nopaste;
	p_wm = p_wm_nopaste;

	if (p_vsts)
	    free_string_option(p_vsts);
	p_vsts = p_vsts_nopaste ? vim_strsave(p_vsts_nopaste) : empty_option;

    }

    old_p_paste = p_paste;
}


    void vimrc_found(char_u *fname, char_u *envname)
{
    int		opt_idx;
    int		dofree = FALSE;
    char_u	*p;

    if (!option_was_set((char_u *)"cp"))
    {
	p_cp = FALSE;
	for (opt_idx = 0; !istermoption_idx(opt_idx); opt_idx++)
	    if (!(options[opt_idx].flags & (P_WAS_SET|P_VI_DEF)))
		set_option_default(opt_idx, OPT_FREE, FALSE);
	didset_options();
	didset_options2();
    }

    if (fname != NULL)
    {
	p = vim_getenv(envname, &dofree);
	if (p == NULL)
	{
	    
	    p = FullName_save(fname, FALSE);
	    if (p != NULL)
	    {
		vim_setenv(envname, p);
		vim_free(p);
	    }
	}
	else if (dofree)
	    vim_free(p);
    }
}


    void change_compatible(int on)
{
    int	    opt_idx;

    if (p_cp != on)
    {
	p_cp = on;
	compatible_set();
    }
    opt_idx = findoption((char_u *)"cp");
    if (opt_idx >= 0)
	options[opt_idx].flags |= P_WAS_SET;
}


    int option_was_set(char_u *name)
{
    int idx;

    idx = findoption(name);
    if (idx < 0)	
	return FALSE;
    if (options[idx].flags & P_WAS_SET)
	return TRUE;
    return FALSE;
}


    int reset_option_was_set(char_u *name)
{
    int idx = findoption(name);

    if (idx >= 0)
    {
	options[idx].flags &= ~P_WAS_SET;
	return OK;
    }
    return FAIL;
}


    static void compatible_set(void)
{
    int	    opt_idx;

    for (opt_idx = 0; !istermoption_idx(opt_idx); opt_idx++)
	if (	   ((options[opt_idx].flags & P_VIM) && p_cp)
		|| (!(options[opt_idx].flags & P_VI_DEF) && !p_cp))
	    set_option_default(opt_idx, OPT_FREE, p_cp);
    didset_options();
    didset_options2();
}




    void fill_breakat_flags(void)
{
    char_u	*p;
    int		i;

    for (i = 0; i < 256; i++)
	breakat_flags[i] = FALSE;

    if (p_breakat != NULL)
	for (p = p_breakat; *p; p++)
	    breakat_flags[*p] = TRUE;
}



    int can_bs( int		what)

{

    if (what == BS_START && bt_prompt(curbuf))
	return FALSE;

    switch (*p_bs)
    {
	case '3':       return TRUE;
	case '2':	return (what != BS_NOSTOP);
	case '1':	return (what != BS_START);
	case '0':	return FALSE;
    }
    return vim_strchr(p_bs, what) != NULL;
}


    long get_scrolloff_value(void)
{
    return curwin->w_p_so < 0 ? p_so : curwin->w_p_so;
}


    long get_sidescrolloff_value(void)
{
    return curwin->w_p_siso < 0 ? p_siso : curwin->w_p_siso;
}


    unsigned int get_bkc_value(buf_T *buf)
{
    return buf->b_bkc_flags ? buf->b_bkc_flags : bkc_flags;
}


    unsigned int get_ve_flags(void)
{
    return (curwin->w_ve_flags ? curwin->w_ve_flags : ve_flags)
	    & ~(VE_NONE | VE_NONEU);
}



    char_u * get_showbreak_value(win_T *win)
{
    if (win->w_p_sbr == NULL || *win->w_p_sbr == NUL)
	return p_sbr;
    if (STRCMP(win->w_p_sbr, "NONE") == 0)
	return empty_option;
    return win->w_p_sbr;
}




    dict_T * get_winbuf_options(int bufopt)
{
    dict_T	*d;
    int		opt_idx;

    d = dict_alloc();
    if (d == NULL)
	return NULL;

    for (opt_idx = 0; !istermoption_idx(opt_idx); opt_idx++)
    {
	struct vimoption *opt = &options[opt_idx];

	if ((bufopt && (opt->indir & PV_BUF))
					 || (!bufopt && (opt->indir & PV_WIN)))
	{
	    char_u *varp = get_varp(opt);

	    if (varp != NULL)
	    {
		if (opt->flags & P_STRING)
		    dict_add_string(d, opt->fullname, *(char_u **)varp);
		else if (opt->flags & P_NUM)
		    dict_add_number(d, opt->fullname, *(long *)varp);
		else dict_add_number(d, opt->fullname, *(int *)varp);
	    }
	}
    }

    return d;
}




    int fill_culopt_flags(char_u *val, win_T *wp)
{
    char_u	*p;
    char_u	culopt_flags_new = 0;

    if (val == NULL)
	p = wp->w_p_culopt;
    else p = val;
    while (*p != NUL)
    {
	if (STRNCMP(p, "line", 4) == 0)
	{
	    p += 4;
	    culopt_flags_new |= CULOPT_LINE;
	}
	else if (STRNCMP(p, "both", 4) == 0)
	{
	    p += 4;
	    culopt_flags_new |= CULOPT_LINE | CULOPT_NBR;
	}
	else if (STRNCMP(p, "number", 6) == 0)
	{
	    p += 6;
	    culopt_flags_new |= CULOPT_NBR;
	}
	else if (STRNCMP(p, "screenline", 10) == 0)
	{
	    p += 10;
	    culopt_flags_new |= CULOPT_SCRLINE;
	}

	if (*p != ',' && *p != NUL)
	    return FAIL;
	if (*p == ',')
	    ++p;
    }

    
    if ((culopt_flags_new & CULOPT_LINE) && (culopt_flags_new & CULOPT_SCRLINE))
	return FAIL;
    wp->w_p_culopt_flags = culopt_flags_new;

    return OK;
}



    int magic_isset(void)
{
    switch (magic_overruled)
    {
	case OPTION_MAGIC_ON:      return TRUE;
	case OPTION_MAGIC_OFF:     return FALSE;
	case OPTION_MAGIC_NOT_SET: break;
    }

    if (in_vim9script())
	return TRUE;

    return p_magic;
}
