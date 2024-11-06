







char		*Version = VIM_VERSION_SHORT;
static char	*mediumVersion = VIM_VERSION_MEDIUM;



char	longVersion[sizeof(VIM_VERSION_LONG_DATE) + sizeof(__DATE__)
						      + sizeof(__TIME__) + 3];

    void init_longVersion(void)
{
    
    strcpy(longVersion, VIM_VERSION_LONG_DATE);

    strcat(longVersion, BUILD_DATE);

    strcat(longVersion, __DATE__);
    strcat(longVersion, " ");
    strcat(longVersion, __TIME__);

    strcat(longVersion, ")");
}


char	*longVersion = NULL;

    void init_longVersion(void)
{
    if (longVersion == NULL)
    {

	char *date_time = BUILD_DATE;

	char *date_time = __DATE__ " " __TIME__;

	char *msg = _("%s (%s, compiled %s)");
	size_t len = strlen(msg)
		    + strlen(VIM_VERSION_LONG_ONLY)
		    + strlen(VIM_VERSION_DATE_ONLY)
		    + strlen(date_time);

	longVersion = alloc(len);
	if (longVersion == NULL)
	    longVersion = VIM_VERSION_LONG;
	else vim_snprintf(longVersion, len, msg, VIM_VERSION_LONG_ONLY, VIM_VERSION_DATE_ONLY, date_time);

    }
}


char	*longVersion = VIM_VERSION_LONG;

    void init_longVersion(void)
{
    
}


static char *(features[]) = {

	"+acl",  "-acl",    "+ARP",  "-ARP",    "+arabic",  "-arabic",  "+autocmd",  "+autochdir",  "-autochdir",   "+autoservername",  "-autoservername",   "+balloon_eval",  "-balloon_eval",   "+balloon_eval_term",  "-balloon_eval_term",   "+browse",  "-browse",   "-builtin_terms",   "+builtin_terms",   "++builtin_terms",   "+byte_offset",  "-byte_offset",   "+channel",  "-channel",  "+cindent",  "+clientserver",  "-clientserver",   "+clipboard",  "-clipboard",  "+cmdline_compl", "+cmdline_hist",  "+cmdline_info",  "-cmdline_info",  "+comments",  "+conceal",  "-conceal",   "+cryptv",  "-cryptv",   "+cscope",  "-cscope",  "+cursorbind",  "+cursorshape",  "-cursorshape",   "+dialog_con_gui",   "+dialog_con",   "+dialog_gui",  "-dialog",     "+diff",  "-diff",   "+digraphs",  "-digraphs",    "+directx",  "-directx",    "+dnd",  "-dnd",  "-ebcdic",  "+emacs_tags",  "-emacs_tags",   "+eval",  "-eval",  "+ex_extra",  "+extra_search",  "-extra_search",  "-farsi",  "+file_in_path",  "-file_in_path",   "+find_in_path",  "-find_in_path",   "+float",  "-float",   "+folding",  "-folding",   "+footer",  "-footer",    "+fork()",    "+gettext/dyn",  "+gettext",   "-gettext",  "-hangul_input",   "+iconv/dyn",  "+iconv",   "-iconv",  "+insert_expand",  "+ipv6",  "-ipv6",   "+job",  "-job",  "+jumplist",  "+keymap",  "-keymap",   "+lambda",  "-lambda",   "+langmap",  "-langmap",   "+libcall",  "-libcall",   "+linebreak",  "-linebreak",  "+lispindent", "+listcmds", "+localmap",   "+lua/dyn",  "+lua",   "-lua",   "+menu",  "-menu",   "+mksession",  "-mksession",  "+modify_fname", "+mouse",  "+mouseshape",  "-mouseshape",     "+mouse_dec",  "-mouse_dec",    "+mouse_gpm/dyn",  "+mouse_gpm",   "-mouse_gpm",   "+mouse_jsbterm",  "-mouse_jsbterm",   "+mouse_netterm",  "-mouse_netterm",      "+mouse_pterm",  "-mouse_pterm",     "+mouse_sgr",  "+mouse_sysmouse",  "-mouse_sysmouse",   "+mouse_urxvt",  "-mouse_urxvt",  "+mouse_xterm",     "+multi_byte_ime/dyn",  "+multi_byte_ime",   "+multi_byte",   "+multi_lang",  "-multi_lang",    "+mzscheme/dyn",  "+mzscheme",   "-mzscheme",   "+netbeans_intg",  "-netbeans_intg",  "+num64",   "+ole",  "-ole",    "+packages",  "-packages",   "+path_extra",  "-path_extra",    "+perl/dyn",  "+perl",   "-perl",   "+persistent_undo",  "-persistent_undo",   "+popupwin",  "-popupwin",    "+postscript",  "-postscript",  "+printer",  "-printer",   "+profile",  "-profile",    "+python/dyn",  "+python",   "-python",    "+python3/dyn",  "+python3",   "-python3",   "+quickfix",  "-quickfix",   "+reltime",  "-reltime",   "+rightleft",  "-rightleft",    "+ruby/dyn",  "+ruby",   "-ruby",  "+scrollbind",  "+signs",  "-signs",  "+smartindent",   "+sodium/dyn",  "+sodium",   "-sodium",   "+sound",  "-sound",   "+spell",  "-spell",   "+startuptime",  "-startuptime",   "+statusline",  "-statusline",  "-sun_workshop",  "+syntax",  "-syntax",    "+system()",  "+tag_binary", "-tag_old_static", "-tag_any_white",   "+tcl/dyn",  "+tcl",   "-tcl",   "+termguicolors",  "-termguicolors",   "+terminal",  "-terminal",     "+terminfo",  "-terminfo",    "+termresponse",  "-termresponse",   "+textobjects",  "-textobjects",   "+textprop",  "-textprop",     "+tgetent",  "-tgetent",    "+timers",  "-timers",  "+title",  "+toolbar",  "-toolbar",  "+user_commands",  "+vartabs",  "-vartabs",  "+vertsplit", "+vim9script",  "+viminfo",  "-viminfo",  "+virtualedit", "+visual", "+visualextra", "+vreplace",   "+vtp",  "-vtp",    "+wildignore",  "-wildignore",   "+wildmenu",  "-wildmenu",  "+windows",  "+writebackup",  "-writebackup",    "+X11",  "-X11",    "+xfontset",  "-xfontset",   "+xim",  "-xim",    "+xpm_w32",  "-xpm_w32",   "+xpm",  "-xpm",    "+xsmp_interact",  "+xsmp",  "-xsmp",   "+xterm_clipboard",  "-xterm_clipboard",    "+xterm_save",  "-xterm_save",  NULL };































































































































































































































































































































































































































































































































































































































































static int included_patches[] = {

    219,  218,  217,  216,  215,  214,  213,  212,  211,  210,  209,  208,  207,  206,  205,  204,  203,  202,  201,  200,  199,  198,  197,  196,  195,  194,  193,  192,  191,  190,  189,  188,  187,  186,  185,  184,  183,  182,  181,  180,  179,  178,  177,  176,  175,  174,  173,  172,  171,  170,  169,  168,  167,  166,  165,  164,  163,  162,  161,  160,  159,  158,  157,  156,  155,  154,  153,  152,  151,  150,  149,  148,  147,  146,  145,  144,  143,  142,  141,  140,  139,  138,  137,  136,  135,  134,  133,  132,  131,  130,  129,  128,  127,  126,  125,  124,  123,  122,  121,  120,  119,  118,  117,  116,  115,  114,  113,  112,  111,  110,  109,  108,  107,  106,  105,  104,  103,  102,  101,  100,  99,  98,  97,  96,  95,  94,  93,  92,  91,  90,  89,  88,  87,  86,  85,  84,  83,  82,  81,  80,  79,  78,  77,  76,  75,  74,  73,  72,  71,  70,  69,  68,  67,  66,  65,  64,  63,  62,  61,  60,  59,  58,  57,  56,  55,  54,  53,  52,  51,  50,  49,  48,  47,  46,  45,  44,  43,  42,  41,  40,  39,  38,  37,  36,  35,  34,  33,  32,  31,  30,  29,  28,  27,  26,  25,  24,  23,  22,  21,  20,  19,  18,  17,  16,  15,  14,  13,  12,  11,  10,  9,  8,  7,  6,  5,  4,  3,  2,  1,  0 };
























































































































































































































































































































































































































































static char *(extra_patches[]) = {

    NULL };

    int highest_patch(void)
{
    
    return included_patches[0];
}



    int has_patch(int n)
{
    int		h, m, l;

    
    l = 0;
    h = (int)ARRAY_LENGTH(included_patches) - 1;
    for (;;)
    {
	m = (l + h) / 2;
	if (included_patches[m] == n)
	    return TRUE;
	if (l == h)
	    break;
	if (included_patches[m] < n)
	    h = m;
	else l = m + 1;
    }
    return FALSE;
}


    void ex_version(exarg_T *eap)
{
    
    if (*eap->arg == NUL)
    {
	msg_putchar('\n');
	list_version();
    }
}


    static void version_msg_wrap(char_u *s, int wrap)
{
    int		len = vim_strsize(s) + (wrap ? 2 : 0);

    if (!got_int && len < (int)Columns && msg_col + len >= (int)Columns && *s != '\n')
	msg_putchar('\n');
    if (!got_int)
    {
	if (wrap)
	    msg_puts("[");
	msg_puts((char *)s);
	if (wrap)
	    msg_puts("]");
    }
}

    static void version_msg(char *s)
{
    version_msg_wrap((char_u *)s, FALSE);
}


    static void list_features(void)
{
    list_in_columns((char_u **)features, -1, -1);
}


    void list_in_columns(char_u **items, int size, int current)
{
    int		i;
    int		ncol;
    int		nrow;
    int		cur_row = 1;
    int		item_count = 0;
    int		width = 0;

    int		use_highlight = (items == (char_u **)features);


    
    
    for (i = 0; size < 0 ? items[i] != NULL : i < size; ++i)
    {
	int l = vim_strsize(items[i]) + (i == current ? 2 : 0);

	if (l > width)
	    width = l;
	++item_count;
    }
    width += 1;

    if (Columns < width)
    {
	
	for (i = 0; i < item_count; ++i)
	{
	    version_msg_wrap(items[i], i == current);
	    if (msg_col > 0 && i < item_count - 1)
		msg_putchar('\n');
	}
	return;
    }

    
    
    ncol = (int) (Columns + 1) / width;
    nrow = item_count / ncol + ((item_count % ncol) ? 1 : 0);

    
    for (i = 0; !got_int && i < nrow * ncol; ++i)
    {
	int idx = (i / ncol) + (i % ncol) * nrow;

	if (idx < item_count)
	{
	    int last_col = (i + 1) % ncol == 0;

	    if (idx == current)
		msg_putchar('[');

	    if (use_highlight && items[idx][0] == '-')
		msg_puts_attr((char *)items[idx], HL_ATTR(HLF_W));
	    else  msg_puts((char *)items[idx]);

	    if (idx == current)
		msg_putchar(']');
	    if (last_col)
	    {
		if (msg_col > 0 && cur_row < nrow)
		    msg_putchar('\n');
		++cur_row;
	    }
	    else {
		while (msg_col % width)
		    msg_putchar(' ');
	    }
	}
	else {
	    
	    if (msg_col > 0)
	    {
		if (cur_row < nrow)
		    msg_putchar('\n');
		++cur_row;
	    }
	}
    }
}

    void list_version(void)
{
    int		i;
    int		first;
    char	*s = "";

    
    init_longVersion();
    msg(longVersion);




    msg_puts(_("\nMS-Windows 64-bit GUI/console version"));

    msg_puts(_("\nMS-Windows 32-bit GUI/console version"));



    msg_puts(_("\nMS-Windows 64-bit GUI version"));

    msg_puts(_("\nMS-Windows 32-bit GUI version"));



    msg_puts(_(" with OLE support"));



    msg_puts(_("\nMS-Windows 64-bit console version"));

    msg_puts(_("\nMS-Windows 32-bit console version"));





    msg_puts(_("\nmacOS version"));

    msg_puts(_("\nmacOS version w/o darwin feat."));


    msg_puts(" - arm64");

    msg_puts(" - x86_64");




    msg_puts(_("\nOpenVMS version"));

    if (*compiled_arch != NUL)
    {
	msg_puts(" - ");
	msg_puts((char *)compiled_arch);
    }




    
    
    if (included_patches[0] != 0)
    {
	msg_puts(_("\nIncluded patches: "));
	first = -1;
	i = (int)ARRAY_LENGTH(included_patches) - 1;
	while (--i >= 0)
	{
	    if (first < 0)
		first = included_patches[i];
	    if (i == 0 || included_patches[i - 1] != included_patches[i] + 1)
	    {
		msg_puts(s);
		s = ", ";
		msg_outnum((long)first);
		if (first != included_patches[i])
		{
		    msg_puts("-");
		    msg_outnum((long)included_patches[i]);
		}
		first = -1;
	    }
	}
    }

    
    if (extra_patches[0] != NULL)
    {
	msg_puts(_("\nExtra patches: "));
	s = "";
	for (i = 0; extra_patches[i] != NULL; ++i)
	{
	    msg_puts(s);
	    s = ", ";
	    msg_puts(extra_patches[i]);
	}
    }


    msg_puts("\n");
    msg_puts(_("Modified by "));
    msg_puts(MODIFIED_BY);



    if (*compiled_user != NUL || *compiled_sys != NUL)
    {
	msg_puts(_("\nCompiled "));
	if (*compiled_user != NUL)
	{
	    msg_puts(_("by "));
	    msg_puts((char *)compiled_user);
	}
	if (*compiled_sys != NUL)
	{
	    msg_puts("@");
	    msg_puts((char *)compiled_sys);
	}
    }



    msg_puts(_("\nHuge version "));

    msg_puts(_("\nBig version "));

    msg_puts(_("\nNormal version "));

    msg_puts(_("\nSmall version "));

    msg_puts(_("\nTiny version "));


    msg_puts(_("without GUI."));


    msg_puts(_("with GTK3 GUI."));

     msg_puts(_("with GTK2-GNOME GUI."));

     msg_puts(_("with GTK2 GUI."));


    msg_puts(_("with X11-Motif GUI."));

    msg_puts(_("with Haiku GUI."));

    msg_puts(_("with Photon GUI."));

    msg_puts(_("with GUI."));

    version_msg(_("  Features included (+) or not (-):\n"));

    list_features();
    if (msg_col > 0)
	msg_putchar('\n');


    version_msg(_("   system vimrc file: \""));
    version_msg(SYS_VIMRC_FILE);
    version_msg("\"\n");


    version_msg(_("     user vimrc file: \""));
    version_msg(USR_VIMRC_FILE);
    version_msg("\"\n");


    version_msg(_(" 2nd user vimrc file: \""));
    version_msg(USR_VIMRC_FILE2);
    version_msg("\"\n");


    version_msg(_(" 3rd user vimrc file: \""));
    version_msg(USR_VIMRC_FILE3);
    version_msg("\"\n");


    version_msg(_("      user exrc file: \""));
    version_msg(USR_EXRC_FILE);
    version_msg("\"\n");


    version_msg(_("  2nd user exrc file: \""));
    version_msg(USR_EXRC_FILE2);
    version_msg("\"\n");



    version_msg(_("  system gvimrc file: \""));
    version_msg(SYS_GVIMRC_FILE);
    version_msg("\"\n");

    version_msg(_("    user gvimrc file: \""));
    version_msg(USR_GVIMRC_FILE);
    version_msg("\"\n");

    version_msg(_("2nd user gvimrc file: \""));
    version_msg(USR_GVIMRC_FILE2);
    version_msg("\"\n");


    version_msg(_("3rd user gvimrc file: \""));
    version_msg(USR_GVIMRC_FILE3);
    version_msg("\"\n");


    version_msg(_("       defaults file: \""));
    version_msg(VIM_DEFAULTS_FILE);
    version_msg("\"\n");


    version_msg(_("    system menu file: \""));
    version_msg(SYS_MENU_FILE);
    version_msg("\"\n");



    if (*default_vim_dir != NUL)
    {
	version_msg(_("  fall-back for $VIM: \""));
	version_msg((char *)default_vim_dir);
	version_msg("\"\n");
    }
    if (*default_vimruntime_dir != NUL)
    {
	version_msg(_(" f-b for $VIMRUNTIME: \""));
	version_msg((char *)default_vimruntime_dir);
	version_msg("\"\n");
    }
    version_msg(_("Compilation: "));
    version_msg((char *)all_cflags);
    version_msg("\n");

    if (*compiler_version != NUL)
    {
	version_msg(_("Compiler: "));
	version_msg((char *)compiler_version);
	version_msg("\n");
    }

    version_msg(_("Linking: "));
    version_msg((char *)all_lflags);


    version_msg("\n");
    version_msg(_("  DEBUG BUILD"));

}

static void do_intro_line(int row, char_u *mesg, int add_version, int attr);
static void intro_message(int colon);


    void maybe_intro_message(void)
{
    if (BUFEMPTY()
	    && curbuf->b_fname == NULL && firstwin->w_next == NULL && vim_strchr(p_shm, SHM_INTRO) == NULL)

	intro_message(FALSE);
}


    static void intro_message( int		colon)

{
    int		i;
    int		row;
    int		blanklines;
    int		sponsor;
    char	*p;
    static char	*(lines[]) = {
	N_("VIM - Vi IMproved"), "", N_("version "), N_("by Bram Moolenaar et al."),  " ",  N_("Vim is open source and freely distributable"), "", N_("Help poor children in Uganda!"), N_("type  :help iccf<Enter>       for information "), "", N_("type  :q<Enter>               to exit         "), N_("type  :help<Enter>  or  <F1>  for on-line help"), N_("type  :help version9<Enter>   for version info"), NULL, "", N_("Running in Vi compatible mode"), N_("type  :set nocp<Enter>        for Vim defaults"), N_("type  :help cp-default<Enter> for info on this"), };




















    static char	*(gui_lines[]) = {
	NULL, NULL, NULL, NULL,  NULL,  NULL, NULL, NULL, N_("menu  Help->Orphans           for information    "), NULL, N_("Running modeless, typed text is inserted"), N_("menu  Edit->Global Settings->Toggle Insert Mode  "), N_("                              for two modes      "), NULL, NULL, NULL, N_("menu  Edit->Global Settings->Toggle Vi Compatible"), N_("                              for Vim defaults   "), };





















    
    blanklines = (int)Rows - (ARRAY_LENGTH(lines) - 1);
    if (!p_cp)
	blanklines += 4;  

    
    if (p_ls > 1)
	blanklines -= Rows - topframe->fr_height;
    if (blanklines < 0)
	blanklines = 0;

    
    
    sponsor = (int)time(NULL);
    sponsor = ((sponsor & 2) == 0) - ((sponsor & 4) == 0);

    
    row = blanklines / 2;
    if ((row >= 2 && Columns >= 50) || colon)
    {
	for (i = 0; i < (int)ARRAY_LENGTH(lines); ++i)
	{
	    p = lines[i];

	    if (p_im && gui.in_use && gui_lines[i] != NULL)
		p = gui_lines[i];

	    if (p == NULL)
	    {
		if (!p_cp)
		    break;
		continue;
	    }
	    if (sponsor != 0)
	    {
		if (strstr(p, "children") != NULL)
		    p = sponsor < 0 ? N_("Sponsor Vim development!")
			: N_("Become a registered Vim user!");
		else if (strstr(p, "iccf") != NULL)
		    p = sponsor < 0 ? N_("type  :help sponsor<Enter>    for information ")
			: N_("type  :help register<Enter>   for information ");
		else if (strstr(p, "Orphans") != NULL)
		    p = N_("menu  Help->Sponsor/Register  for information    ");
	    }
	    if (*p != NUL)
		do_intro_line(row, (char_u *)_(p), i == 2, 0);
	    ++row;
	}
    }

    
    if (colon)
	msg_row = row;
}

    static void do_intro_line( int		row, char_u	*mesg, int		add_version, int		attr)




{
    char_u	vers[20];
    int		col;
    char_u	*p;
    int		l;
    int		clen;


    char_u	modby[MODBY_LEN];

    if (*mesg == ' ')
    {
	vim_strncpy(modby, (char_u *)_("Modified by "), MODBY_LEN - 1);
	l = (int)STRLEN(modby);
	vim_strncpy(modby + l, (char_u *)MODIFIED_BY, MODBY_LEN - l - 1);
	mesg = modby;
    }


    
    col = vim_strsize(mesg);
    if (add_version)
    {
	STRCPY(vers, mediumVersion);
	if (highest_patch())
	{
	    
	    if (isalpha((int)vers[3]))
	    {
		int len = (isalpha((int)vers[4])) ? 5 : 4;
		sprintf((char *)vers + len, ".%d%s", highest_patch(), mediumVersion + len);
	    }
	    else sprintf((char *)vers + 3, ".%d", highest_patch());
	}
	col += (int)STRLEN(vers);
    }
    col = (Columns - col) / 2;
    if (col < 0)
	col = 0;

    
    for (p = mesg; *p != NUL; p += l)
    {
	clen = 0;
	for (l = 0; p[l] != NUL && (l == 0 || (p[l] != '<' && p[l - 1] != '>')); ++l)
	{
	    if (has_mbyte)
	    {
		clen += ptr2cells(p + l);
		l += (*mb_ptr2len)(p + l) - 1;
	    }
	    else clen += byte2cells(p[l]);
	}
	screen_puts_len(p, l, row, col, *p == '<' ? HL_ATTR(HLF_8) : attr);
	col += clen;
    }

    
    if (add_version)
	screen_puts(vers, row, col, 0);
}


    void ex_intro(exarg_T *eap UNUSED)
{
    screenclear();
    intro_message(TRUE);
    wait_return(TRUE);
}
