






























static char *ctrl_x_msgs[] = {
    N_(" Keyword completion (^N^P)"),  N_(" ^X mode (^]^D^E^F^I^K^L^N^O^Ps^U^V^Y)"), NULL, N_(" Whole line completion (^L^N^P)"), N_(" File name completion (^F^N^P)"), N_(" Tag completion (^]^N^P)"), N_(" Path pattern completion (^N^P)"), N_(" Definition completion (^D^N^P)"), NULL, N_(" Dictionary completion (^K^N^P)"), N_(" Thesaurus completion (^T^N^P)"), N_(" Command-line completion (^V^N^P)"), N_(" User defined completion (^U^N^P)"), N_(" Omni completion (^O^N^P)"), N_(" Spelling suggestion (s^N^P)"), N_(" Keyword Local completion (^N^P)"), NULL, N_(" Command-line completion (^V^N^P)"), };



















static char *ctrl_x_mode_names[] = {
	"keyword", "ctrl_x", "scroll", "whole_line", "files", "tags", "path_patterns", "path_defines", "unknown", "dictionary", "thesaurus", "cmdline", "function", "omni", "spell", NULL, "eval", "cmdline", };



























typedef struct compl_S compl_T;
struct compl_S {
    compl_T	*cp_next;
    compl_T	*cp_prev;
    char_u	*cp_str;	
    char_u	*(cp_text[CPT_COUNT]);	

    typval_T	cp_user_data;

    char_u	*cp_fname;	
				
    int		cp_flags;	
    int		cp_number;	
};









static char e_hitend[] = N_("Hit end of paragraph");


static compl_T    *compl_first_match = NULL;
static compl_T    *compl_curr_match = NULL;
static compl_T    *compl_shown_match = NULL;
static compl_T    *compl_old_match = NULL;



static int	  compl_enter_selects = FALSE;



static char_u	  *compl_leader = NULL;

static int	  compl_get_longest = FALSE;	
						

static int	  compl_no_insert = FALSE;	
						
static int	  compl_no_select = FALSE;	
						
static int	  compl_longest = FALSE;	
						



static int	  compl_used_match;


static int	  compl_was_interrupted = FALSE;



static int	  compl_interrupted = FALSE;

static int	  compl_restarting = FALSE;	



static int	  compl_started = FALSE;


static int	  ctrl_x_mode = CTRL_X_NORMAL;

static int	  compl_matches = 0;	    
static char_u	  *compl_pattern = NULL;
static int	  compl_direction = FORWARD;
static int	  compl_shows_dir = FORWARD;
static int	  compl_pending = 0;	    
static pos_T	  compl_startpos;


static int	  compl_length = 0;
static colnr_T	  compl_col = 0;	    
					    
static char_u	  *compl_orig_text = NULL;  
					    
static int	  compl_cont_mode = 0;
static expand_T	  compl_xp;


static int	  compl_cont_status = 0;


				


				

				

				

static int	  compl_opt_refresh_always = FALSE;
static int	  compl_opt_suppress_empty = FALSE;

static int ins_compl_add(char_u *str, int len, char_u *fname, char_u **cptext, typval_T *user_data, int cdir, int flags, int adup);
static void ins_compl_longest_match(compl_T *match);
static void ins_compl_del_pum(void);
static void ins_compl_files(int count, char_u **files, int thesaurus, int flags, regmatch_T *regmatch, char_u *buf, int *dir);
static char_u *find_line_end(char_u *ptr);
static void ins_compl_free(void);
static int  ins_compl_need_restart(void);
static void ins_compl_new_leader(void);
static int  get_compl_len(void);
static void ins_compl_restart(void);
static void ins_compl_set_original_text(char_u *str);
static void ins_compl_fixRedoBufForLeader(char_u *ptr_arg);

static void ins_compl_add_list(list_T *list);
static void ins_compl_add_dict(dict_T *dict);

static int  ins_compl_key2dir(int c);
static int  ins_compl_pum_key(int c);
static int  ins_compl_key2count(int c);
static void show_pum(int prev_w_wrow, int prev_w_leftcol);
static unsigned  quote_meta(char_u *dest, char_u *str, int len);


static void spell_back_to_badword(void);
static int  spell_bad_len = 0;	



    void ins_ctrl_x(void)
{
    if (!ctrl_x_mode_cmdline())
    {
	
	if (compl_cont_status & CONT_N_ADDS)
	    compl_cont_status |= CONT_INTRPT;
	else compl_cont_status = 0;
	
	ctrl_x_mode = CTRL_X_NOT_DEFINED_YET;
	edit_submode = (char_u *)_(CTRL_X_MSG(ctrl_x_mode));
	edit_submode_pre = NULL;
	showmode();
    }
    else   ctrl_x_mode = CTRL_X_CMDLINE_CTRL_X;



    may_trigger_modechanged();
}


int ctrl_x_mode_none(void) { return ctrl_x_mode == 0; }
int ctrl_x_mode_normal(void) { return ctrl_x_mode == CTRL_X_NORMAL; }
int ctrl_x_mode_scroll(void) { return ctrl_x_mode == CTRL_X_SCROLL; }
int ctrl_x_mode_whole_line(void) { return ctrl_x_mode == CTRL_X_WHOLE_LINE; }
int ctrl_x_mode_files(void) { return ctrl_x_mode == CTRL_X_FILES; }
int ctrl_x_mode_tags(void) { return ctrl_x_mode == CTRL_X_TAGS; }
int ctrl_x_mode_path_patterns(void) {
				  return ctrl_x_mode == CTRL_X_PATH_PATTERNS; }
int ctrl_x_mode_path_defines(void) {
				   return ctrl_x_mode == CTRL_X_PATH_DEFINES; }
int ctrl_x_mode_dictionary(void) { return ctrl_x_mode == CTRL_X_DICTIONARY; }
int ctrl_x_mode_thesaurus(void) { return ctrl_x_mode == CTRL_X_THESAURUS; }
int ctrl_x_mode_cmdline(void) {
	return ctrl_x_mode == CTRL_X_CMDLINE || ctrl_x_mode == CTRL_X_CMDLINE_CTRL_X; }
int ctrl_x_mode_function(void) { return ctrl_x_mode == CTRL_X_FUNCTION; }
int ctrl_x_mode_omni(void) { return ctrl_x_mode == CTRL_X_OMNI; }
int ctrl_x_mode_spell(void) { return ctrl_x_mode == CTRL_X_SPELL; }
static int ctrl_x_mode_eval(void) { return ctrl_x_mode == CTRL_X_EVAL; }
int ctrl_x_mode_line_or_eval(void) {
       return ctrl_x_mode == CTRL_X_WHOLE_LINE || ctrl_x_mode == CTRL_X_EVAL; }


    int ctrl_x_mode_not_default(void)
{
    return ctrl_x_mode != CTRL_X_NORMAL;
}


    int ctrl_x_mode_not_defined_yet(void)
{
    return ctrl_x_mode == CTRL_X_NOT_DEFINED_YET;
}


    int compl_status_adding(void)
{
    return compl_cont_status & CONT_ADDING;
}


    int compl_status_sol(void)
{
    return compl_cont_status & CONT_SOL;
}


    int compl_status_local(void)
{
    return compl_cont_status & CONT_LOCAL;
}


    void compl_status_clear(void)
{
    compl_cont_status = 0;
}


    static int compl_dir_forward(void)
{
    return compl_direction == FORWARD;
}


    static int compl_shows_dir_forward(void)
{
    return compl_shows_dir == FORWARD;
}


    static int compl_shows_dir_backward(void)
{
    return compl_shows_dir == BACKWARD;
}


    int has_compl_option(int dict_opt)
{
    if (dict_opt ? (*curbuf->b_p_dict == NUL && *p_dict == NUL  && !curwin->w_p_spell  )



		 : (*curbuf->b_p_tsr == NUL && *p_tsr == NUL  && *curbuf->b_p_tsrfu == NUL && *p_tsrfu == NUL  ))



    {
	ctrl_x_mode = CTRL_X_NORMAL;
	edit_submode = NULL;
	msg_attr(dict_opt ? _("'dictionary' option is empty")
			  : _("'thesaurus' option is empty"), HL_ATTR(HLF_E));
	if (emsg_silent == 0 && !in_assert_fails)
	{
	    vim_beep(BO_COMPL);
	    setcursor();
	    out_flush();

	    if (!get_vim_var_nr(VV_TESTING))

		ui_delay(2004L, FALSE);
	}
	return FALSE;
    }
    return TRUE;
}


    int vim_is_ctrl_x_key(int c)
{
    
    if (c == Ctrl_R)
	return TRUE;

    
    if (ins_compl_pum_key(c))
	return TRUE;

    switch (ctrl_x_mode)
    {
	case 0:		    
	    return (c == Ctrl_N || c == Ctrl_P || c == Ctrl_X);
	case CTRL_X_NOT_DEFINED_YET:
	case CTRL_X_CMDLINE_CTRL_X:
	    return (   c == Ctrl_X || c == Ctrl_Y || c == Ctrl_E || c == Ctrl_L || c == Ctrl_F || c == Ctrl_RSB || c == Ctrl_I || c == Ctrl_D || c == Ctrl_P || c == Ctrl_N || c == Ctrl_T || c == Ctrl_V || c == Ctrl_Q || c == Ctrl_U || c == Ctrl_O || c == Ctrl_S || c == Ctrl_K || c == 's' || c == Ctrl_Z);





	case CTRL_X_SCROLL:
	    return (c == Ctrl_Y || c == Ctrl_E);
	case CTRL_X_WHOLE_LINE:
	    return (c == Ctrl_L || c == Ctrl_P || c == Ctrl_N);
	case CTRL_X_FILES:
	    return (c == Ctrl_F || c == Ctrl_P || c == Ctrl_N);
	case CTRL_X_DICTIONARY:
	    return (c == Ctrl_K || c == Ctrl_P || c == Ctrl_N);
	case CTRL_X_THESAURUS:
	    return (c == Ctrl_T || c == Ctrl_P || c == Ctrl_N);
	case CTRL_X_TAGS:
	    return (c == Ctrl_RSB || c == Ctrl_P || c == Ctrl_N);

	case CTRL_X_PATH_PATTERNS:
	    return (c == Ctrl_P || c == Ctrl_N);
	case CTRL_X_PATH_DEFINES:
	    return (c == Ctrl_D || c == Ctrl_P || c == Ctrl_N);

	case CTRL_X_CMDLINE:
	    return (c == Ctrl_V || c == Ctrl_Q || c == Ctrl_P || c == Ctrl_N || c == Ctrl_X);

	case CTRL_X_FUNCTION:
	    return (c == Ctrl_U || c == Ctrl_P || c == Ctrl_N);
	case CTRL_X_OMNI:
	    return (c == Ctrl_O || c == Ctrl_P || c == Ctrl_N);

	case CTRL_X_SPELL:
	    return (c == Ctrl_S || c == Ctrl_P || c == Ctrl_N);
	case CTRL_X_EVAL:
	    return (c == Ctrl_P || c == Ctrl_N);
    }
    internal_error("vim_is_ctrl_x_key()");
    return FALSE;
}


    static int match_at_original_text(compl_T *match)
{
    return match->cp_flags & CP_ORIGINAL_TEXT;
}


    static int is_first_match(compl_T *match)
{
    return match == compl_first_match;
}


    int ins_compl_accept_char(int c)
{
    if (ctrl_x_mode & CTRL_X_WANT_IDENT)
	
	return vim_isIDc(c);

    switch (ctrl_x_mode)
    {
	case CTRL_X_FILES:
	    
	    
	    
	    return vim_isfilec(c) && !vim_ispathsep(c);

	case CTRL_X_CMDLINE:
	case CTRL_X_CMDLINE_CTRL_X:
	case CTRL_X_OMNI:
	    
	    
	    return vim_isprintc(c) && !VIM_ISWHITE(c);

	case CTRL_X_WHOLE_LINE:
	    
	    return vim_isprintc(c);
    }
    return vim_iswordc(c);
}


    static char_u * ins_compl_infercase_gettext( char_u	*str, int	char_len, int	compl_char_len, int	min_len, char_u  **tofree)





{
    int		*wca;			
    char_u	*p;
    int		i, c;
    int		has_lower = FALSE;
    int		was_letter = FALSE;
    garray_T	gap;

    IObuff[0] = NUL;

    
    wca = ALLOC_MULT(int, char_len);
    if (wca == NULL)
	return IObuff;

    p = str;
    for (i = 0; i < char_len; ++i)
	if (has_mbyte)
	    wca[i] = mb_ptr2char_adv(&p);
	else wca[i] = *(p++);

    
    p = compl_orig_text;
    for (i = 0; i < min_len; ++i)
    {
	if (has_mbyte)
	    c = mb_ptr2char_adv(&p);
	else c = *(p++);
	if (MB_ISLOWER(c))
	{
	    has_lower = TRUE;
	    if (MB_ISUPPER(wca[i]))
	    {
		
		for (i = compl_char_len; i < char_len; ++i)
		    wca[i] = MB_TOLOWER(wca[i]);
		break;
	    }
	}
    }

    
    
    if (!has_lower)
    {
	p = compl_orig_text;
	for (i = 0; i < min_len; ++i)
	{
	    if (has_mbyte)
		c = mb_ptr2char_adv(&p);
	    else c = *(p++);
	    if (was_letter && MB_ISUPPER(c) && MB_ISLOWER(wca[i]))
	    {
		
		for (i = compl_char_len; i < char_len; ++i)
		    wca[i] = MB_TOUPPER(wca[i]);
		break;
	    }
	    was_letter = MB_ISLOWER(c) || MB_ISUPPER(c);
	}
    }

    
    p = compl_orig_text;
    for (i = 0; i < min_len; ++i)
    {
	if (has_mbyte)
	    c = mb_ptr2char_adv(&p);
	else c = *(p++);
	if (MB_ISLOWER(c))
	    wca[i] = MB_TOLOWER(wca[i]);
	else if (MB_ISUPPER(c))
	    wca[i] = MB_TOUPPER(wca[i]);
    }

    
    p = IObuff;
    i = 0;
    ga_init2(&gap, 1, 500);
    while (i < char_len)
    {
	if (gap.ga_data != NULL)
	{
	    if (ga_grow(&gap, 10) == FAIL)
	    {
		ga_clear(&gap);
		return (char_u *)"[failed]";
	    }
	    p = (char_u *)gap.ga_data + gap.ga_len;
	    if (has_mbyte)
		gap.ga_len += (*mb_char2bytes)(wca[i++], p);
	    else {
		*p = wca[i++];
		++gap.ga_len;
	    }
	}
	else if ((p - IObuff) + 6 >= IOSIZE)
	{
	    
	    
	    
	    
	    if (ga_grow(&gap, IOSIZE) == FAIL)
		return (char_u *)"[failed]";
	    *p = NUL;
	    STRCPY(gap.ga_data, IObuff);
	    gap.ga_len = (int)STRLEN(IObuff);
	}
	else if (has_mbyte)
	    p += (*mb_char2bytes)(wca[i++], p);
	else *(p++) = wca[i++];
    }
    vim_free(wca);

    if (gap.ga_data != NULL)
    {
	*tofree = gap.ga_data;
	return gap.ga_data;
    }

    *p = NUL;
    return IObuff;
}


    int ins_compl_add_infercase( char_u	*str_arg, int		len, int		icase, char_u	*fname, int		dir, int		cont_s_ipos)






{
    char_u	*str = str_arg;
    char_u	*p;
    int		char_len;		
    int		compl_char_len;
    int		min_len;
    int		flags = 0;
    int		res;
    char_u	*tofree = NULL;

    if (p_ic && curbuf->b_p_inf && len > 0)
    {
	

	
	if (has_mbyte)
	{
	    p = str;
	    char_len = 0;
	    while (*p != NUL)
	    {
		MB_PTR_ADV(p);
		++char_len;
	    }
	}
	else char_len = len;

	
	if (has_mbyte)
	{
	    p = compl_orig_text;
	    compl_char_len = 0;
	    while (*p != NUL)
	    {
		MB_PTR_ADV(p);
		++compl_char_len;
	    }
	}
	else compl_char_len = compl_length;

	
	
	min_len = char_len < compl_char_len ? char_len : compl_char_len;

	str = ins_compl_infercase_gettext(str, char_len, compl_char_len, min_len, &tofree);
    }
    if (cont_s_ipos)
	flags |= CP_CONT_S_IPOS;
    if (icase)
	flags |= CP_ICASE;

    res = ins_compl_add(str, len, fname, NULL, NULL, dir, flags, FALSE);
    vim_free(tofree);
    return res;
}


    static int ins_compl_add( char_u	*str, int		len, char_u	*fname, char_u	**cptext, typval_T	*user_data UNUSED, int		cdir, int		flags_arg, int		adup)








{
    compl_T	*match;
    int		dir = (cdir == 0 ? compl_direction : cdir);
    int		flags = flags_arg;

    if (flags & CP_FAST)
	fast_breakcheck();
    else ui_breakcheck();
    if (got_int)
	return FAIL;
    if (len < 0)
	len = (int)STRLEN(str);

    
    if (compl_first_match != NULL && !adup)
    {
	match = compl_first_match;
	do {
	    if (!match_at_original_text(match)
		    && STRNCMP(match->cp_str, str, len) == 0 && ((int)STRLEN(match->cp_str) <= len || match->cp_str[len] == NUL))

		return NOTDONE;
	    match = match->cp_next;
	} while (match != NULL && !is_first_match(match));
    }

    
    ins_compl_del_pum();

    
    
    match = ALLOC_CLEAR_ONE(compl_T);
    if (match == NULL)
	return FAIL;
    match->cp_number = -1;
    if (flags & CP_ORIGINAL_TEXT)
	match->cp_number = 0;
    if ((match->cp_str = vim_strnsave(str, len)) == NULL)
    {
	vim_free(match);
	return FAIL;
    }

    
    
    
    
    if (fname != NULL && compl_curr_match != NULL && compl_curr_match->cp_fname != NULL && STRCMP(fname, compl_curr_match->cp_fname) == 0)


	match->cp_fname = compl_curr_match->cp_fname;
    else if (fname != NULL)
    {
	match->cp_fname = vim_strsave(fname);
	flags |= CP_FREE_FNAME;
    }
    else match->cp_fname = NULL;
    match->cp_flags = flags;

    if (cptext != NULL)
    {
	int i;

	for (i = 0; i < CPT_COUNT; ++i)
	    if (cptext[i] != NULL && *cptext[i] != NUL)
		match->cp_text[i] = vim_strsave(cptext[i]);
    }

    if (user_data != NULL)
	match->cp_user_data = *user_data;


    
    
    if (compl_first_match == NULL)
	match->cp_next = match->cp_prev = NULL;
    else if (dir == FORWARD)
    {
	match->cp_next = compl_curr_match->cp_next;
	match->cp_prev = compl_curr_match;
    }
    else	 {
	match->cp_next = compl_curr_match;
	match->cp_prev = compl_curr_match->cp_prev;
    }
    if (match->cp_next)
	match->cp_next->cp_prev = match;
    if (match->cp_prev)
	match->cp_prev->cp_next = match;
    else	 compl_first_match = match;
    compl_curr_match = match;

    
    if (compl_get_longest && (flags & CP_ORIGINAL_TEXT) == 0)
	ins_compl_longest_match(match);

    return OK;
}


    static int ins_compl_equal(compl_T *match, char_u *str, int len)
{
    if (match->cp_flags & CP_EQUAL)
	return TRUE;
    if (match->cp_flags & CP_ICASE)
	return STRNICMP(match->cp_str, str, (size_t)len) == 0;
    return STRNCMP(match->cp_str, str, (size_t)len) == 0;
}


    static void ins_compl_longest_match(compl_T *match)
{
    char_u	*p, *s;
    int		c1, c2;
    int		had_match;

    if (compl_leader == NULL)
    {
	
	compl_leader = vim_strsave(match->cp_str);
	if (compl_leader == NULL)
	    return;

	had_match = (curwin->w_cursor.col > compl_col);
	ins_compl_delete();
	ins_bytes(compl_leader + get_compl_len());
	ins_redraw(FALSE);

	
	
	if (!had_match)
	    ins_compl_delete();
	compl_used_match = FALSE;

	return;
    }

    
    p = compl_leader;
    s = match->cp_str;
    while (*p != NUL)
    {
	if (has_mbyte)
	{
	    c1 = mb_ptr2char(p);
	    c2 = mb_ptr2char(s);
	}
	else {
	    c1 = *p;
	    c2 = *s;
	}
	if ((match->cp_flags & CP_ICASE)
		? (MB_TOLOWER(c1) != MB_TOLOWER(c2)) : (c1 != c2))
	    break;
	if (has_mbyte)
	{
	    MB_PTR_ADV(p);
	    MB_PTR_ADV(s);
	}
	else {
	    ++p;
	    ++s;
	}
    }

    if (*p != NUL)
    {
	
	*p = NUL;
	had_match = (curwin->w_cursor.col > compl_col);
	ins_compl_delete();
	ins_bytes(compl_leader + get_compl_len());
	ins_redraw(FALSE);

	
	
	if (!had_match)
	    ins_compl_delete();
    }

    compl_used_match = FALSE;
}


    static void ins_compl_add_matches( int		num_matches, char_u	**matches, int		icase)



{
    int		i;
    int		add_r = OK;
    int		dir = compl_direction;

    for (i = 0; i < num_matches && add_r != FAIL; i++)
	if ((add_r = ins_compl_add(matches[i], -1, NULL, NULL, NULL, dir, CP_FAST | (icase ? CP_ICASE : 0), FALSE)) == OK)
	    
	    dir = FORWARD;
    FreeWild(num_matches, matches);
}


    static int ins_compl_make_cyclic(void)
{
    compl_T *match;
    int	    count = 0;

    if (compl_first_match == NULL)
	return 0;

    
    match = compl_first_match;
    
    while (match->cp_next != NULL && !is_first_match(match->cp_next))
    {
	match = match->cp_next;
	++count;
    }
    match->cp_next = compl_first_match;
    compl_first_match->cp_prev = match;

    return count;
}


    int ins_compl_has_shown_match(void)
{
    return compl_shown_match == NULL || compl_shown_match != compl_shown_match->cp_next;
}


    int ins_compl_long_shown_match(void)
{
    return (int)STRLEN(compl_shown_match->cp_str)
					    > curwin->w_cursor.col - compl_col;
}


    void completeopt_was_set(void)
{
    compl_no_insert = FALSE;
    compl_no_select = FALSE;
    compl_longest = FALSE;
    if (strstr((char *)p_cot, "noselect") != NULL)
	compl_no_select = TRUE;
    if (strstr((char *)p_cot, "noinsert") != NULL)
	compl_no_insert = TRUE;
    if (strstr((char *)p_cot, "longest") != NULL)
	compl_longest = TRUE;
}




static pumitem_T *compl_match_array = NULL;
static int compl_match_arraysize;


    static void ins_compl_upd_pum(void)
{
    int		h;

    if (compl_match_array == NULL)
	return;

    h = curwin->w_cline_height;
    
    pum_call_update_screen();
    if (h != curwin->w_cline_height)
	ins_compl_del_pum();
}


    static void ins_compl_del_pum(void)
{
    if (compl_match_array == NULL)
	return;

    pum_undisplay();
    VIM_CLEAR(compl_match_array);
}


    int pum_wanted(void)
{
    
    if (vim_strchr(p_cot, 'm') == NULL)
	return FALSE;

    
    if (t_colors < 8  && !gui.in_use  )



	return FALSE;
    return TRUE;
}


    static int pum_enough_matches(void)
{
    compl_T     *compl;
    int		i;

    
    
    compl = compl_first_match;
    i = 0;
    do {
	if (compl == NULL || (!match_at_original_text(compl) && ++i == 2))
	    break;
	compl = compl->cp_next;
    } while (!is_first_match(compl));

    if (strstr((char *)p_cot, "menuone") != NULL)
	return (i >= 1);
    return (i >= 2);
}



    static dict_T * ins_compl_dict_alloc(compl_T *match)
{
    dict_T *dict = dict_alloc_lock(VAR_FIXED);

    if (dict == NULL)
	return NULL;

    dict_add_string(dict, "word", match->cp_str);
    dict_add_string(dict, "abbr", match->cp_text[CPT_ABBR]);
    dict_add_string(dict, "menu", match->cp_text[CPT_MENU]);
    dict_add_string(dict, "kind", match->cp_text[CPT_KIND]);
    dict_add_string(dict, "info", match->cp_text[CPT_INFO]);
    if (match->cp_user_data.v_type == VAR_UNKNOWN)
	dict_add_string(dict, "user_data", (char_u *)"");
    else dict_add_tv(dict, "user_data", &match->cp_user_data);

    return dict;
}


    static void trigger_complete_changed_event(int cur)
{
    dict_T	    *v_event;
    dict_T	    *item;
    static int	    recursive = FALSE;
    save_v_event_T  save_v_event;

    if (recursive)
	return;

    if (cur < 0)
	item = dict_alloc();
    else item = ins_compl_dict_alloc(compl_curr_match);
    if (item == NULL)
	return;
    v_event = get_v_event(&save_v_event);
    dict_add_dict(v_event, "completed_item", item);
    pum_set_event_info(v_event);
    dict_set_items_ro(v_event);

    recursive = TRUE;
    textlock++;
    apply_autocmds(EVENT_COMPLETECHANGED, NULL, NULL, FALSE, curbuf);
    textlock--;
    recursive = FALSE;

    restore_v_event(v_event, &save_v_event);
}



    static int ins_compl_build_pum(void)
{
    compl_T     *compl;
    compl_T     *shown_compl = NULL;
    int		did_find_shown_match = FALSE;
    int		shown_match_ok = FALSE;
    int		i;
    int		cur = -1;
    int		lead_len = 0;

    
    compl_match_arraysize = 0;
    compl = compl_first_match;
    if (compl_leader != NULL)
	lead_len = (int)STRLEN(compl_leader);

    do {
	if (!match_at_original_text(compl)
		&& (compl_leader == NULL || ins_compl_equal(compl, compl_leader, lead_len)))
	    ++compl_match_arraysize;
	compl = compl->cp_next;
    } while (compl != NULL && !is_first_match(compl));

    if (compl_match_arraysize == 0)
	return -1;

    compl_match_array = ALLOC_CLEAR_MULT(pumitem_T, compl_match_arraysize);
    if (compl_match_array == NULL)
	return -1;

    
    
    if (match_at_original_text(compl_shown_match))
	shown_match_ok = TRUE;

    i = 0;
    compl = compl_first_match;
    do {
	if (!match_at_original_text(compl)
		&& (compl_leader == NULL || ins_compl_equal(compl, compl_leader, lead_len)))
	{
	    if (!shown_match_ok)
	    {
		if (compl == compl_shown_match || did_find_shown_match)
		{
		    
		    
		    compl_shown_match = compl;
		    did_find_shown_match = TRUE;
		    shown_match_ok = TRUE;
		}
		else   shown_compl = compl;


		cur = i;
	    }

	    if (compl->cp_text[CPT_ABBR] != NULL)
		compl_match_array[i].pum_text = compl->cp_text[CPT_ABBR];
	    else compl_match_array[i].pum_text = compl->cp_str;
	    compl_match_array[i].pum_kind = compl->cp_text[CPT_KIND];
	    compl_match_array[i].pum_info = compl->cp_text[CPT_INFO];
	    if (compl->cp_text[CPT_MENU] != NULL)
		compl_match_array[i++].pum_extra = compl->cp_text[CPT_MENU];
	    else compl_match_array[i++].pum_extra = compl->cp_fname;
	}

	if (compl == compl_shown_match)
	{
	    did_find_shown_match = TRUE;

	    
	    
	    if (match_at_original_text(compl))
		shown_match_ok = TRUE;

	    if (!shown_match_ok && shown_compl != NULL)
	    {
		
		
		compl_shown_match = shown_compl;
		shown_match_ok = TRUE;
	    }
	}
	compl = compl->cp_next;
    } while (compl != NULL && !is_first_match(compl));

    if (!shown_match_ok)    
	cur = -1;

    return cur;
}


    void ins_compl_show_pum(void)
{
    int		i;
    int		cur = -1;
    colnr_T	col;

    if (!pum_wanted() || !pum_enough_matches())
	return;


    
    do_cmdline_cmd((char_u *)"if exists('g:loaded_matchparen')|:3match none|endif");


    
    pum_call_update_screen();

    if (compl_match_array == NULL)
	
	cur = ins_compl_build_pum();
    else {
	
	for (i = 0; i < compl_match_arraysize; ++i)
	    if (compl_match_array[i].pum_text == compl_shown_match->cp_str || compl_match_array[i].pum_text == compl_shown_match->cp_text[CPT_ABBR])

	    {
		cur = i;
		break;
	    }
    }

    if (compl_match_array == NULL)
	return;

    
    
    dollar_vcol = -1;

    
    
    col = curwin->w_cursor.col;
    curwin->w_cursor.col = compl_col;
    pum_display(compl_match_array, compl_match_arraysize, cur);
    curwin->w_cursor.col = col;


    if (has_completechanged())
	trigger_complete_changed_event(cur);

}





    static void ins_compl_dictionaries( char_u	*dict_start, char_u	*pat, int		flags, int		thesaurus)




{
    char_u	*dict = dict_start;
    char_u	*ptr;
    char_u	*buf;
    regmatch_T	regmatch;
    char_u	**files;
    int		count;
    int		save_p_scs;
    int		dir = compl_direction;

    if (*dict == NUL)
    {

	
	
	if (!thesaurus && curwin->w_p_spell)
	    dict = (char_u *)"spell";
	else  return;

    }

    buf = alloc(LSIZE);
    if (buf == NULL)
	return;
    regmatch.regprog = NULL;	

    
    save_p_scs = p_scs;
    if (curbuf->b_p_inf)
	p_scs = FALSE;

    
    
    
    if (ctrl_x_mode_line_or_eval())
    {
	char_u *pat_esc = vim_strsave_escaped(pat, (char_u *)"\\");
	size_t len;

	if (pat_esc == NULL)
	    goto theend;
	len = STRLEN(pat_esc) + 10;
	ptr = alloc(len);
	if (ptr == NULL)
	{
	    vim_free(pat_esc);
	    goto theend;
	}
	vim_snprintf((char *)ptr, len, "^\\s*\\zs\\V%s", pat_esc);
	regmatch.regprog = vim_regcomp(ptr, RE_MAGIC);
	vim_free(pat_esc);
	vim_free(ptr);
    }
    else {
	regmatch.regprog = vim_regcomp(pat, magic_isset() ? RE_MAGIC : 0);
	if (regmatch.regprog == NULL)
	    goto theend;
    }

    
    regmatch.rm_ic = ignorecase(pat);
    while (*dict != NUL && !got_int && !compl_interrupted)
    {
	
	if (flags == DICT_EXACT)
	{
	    count = 1;
	    files = &dict;
	}
	else {
	    
	    
	    
	    copy_option_part(&dict, buf, LSIZE, ",");

	    if (!thesaurus && STRCMP(buf, "spell") == 0)
		count = -1;
	    else  if (vim_strchr(buf, '`') != NULL || expand_wildcards(1, &buf, &count, &files, EW_FILE|EW_SILENT) != OK)



		count = 0;
	}


	if (count == -1)
	{
	    
	    
	    if (pat[0] == '\\' && pat[1] == '<')
		ptr = pat + 2;
	    else ptr = pat;
	    spell_dump_compl(ptr, regmatch.rm_ic, &dir, 0);
	}
	else  if (count > 0)

	{
	    ins_compl_files(count, files, thesaurus, flags, &regmatch, buf, &dir);
	    if (flags != DICT_EXACT)
		FreeWild(count, files);
	}
	if (flags != 0)
	    break;
    }

theend:
    p_scs = save_p_scs;
    vim_regfree(regmatch.regprog);
    vim_free(buf);
}


    static int thesaurus_add_words_in_line( char_u	*fname, char_u	**buf_arg, int	dir, char_u	*skip_word)




{
    int		status = OK;
    char_u	*ptr;
    char_u	*wstart;

    
    ptr = *buf_arg;
    while (!got_int)
    {
	
	
	ptr = find_word_start(ptr);
	if (*ptr == NUL || *ptr == NL)
	    break;
	wstart = ptr;

	
	if (has_mbyte)
	    
	    
	    
	    while (*ptr != NUL)
	    {
		int l = (*mb_ptr2len)(ptr);

		if (l < 2 && !vim_iswordc(*ptr))
		    break;
		ptr += l;
	    }
	else ptr = find_word_end(ptr);

	
	if (wstart != skip_word)
	{
	    status = ins_compl_add_infercase(wstart, (int)(ptr - wstart), p_ic, fname, dir, FALSE);
	    if (status == FAIL)
		break;
	}
    }

    *buf_arg = ptr;
    return status;
}


    static void ins_compl_files( int		count, char_u	**files, int		thesaurus, int		flags, regmatch_T	*regmatch, char_u	*buf, int		*dir)







{
    char_u	*ptr;
    int		i;
    FILE	*fp;
    int		add_r;

    for (i = 0; i < count && !got_int && !compl_interrupted; i++)
    {
	fp = mch_fopen((char *)files[i], "r");  
	if (flags != DICT_EXACT)
	{
	    msg_hist_off = TRUE;	
	    vim_snprintf((char *)IObuff, IOSIZE, _("Scanning dictionary: %s"), (char *)files[i]);
	    (void)msg_trunc_attr((char *)IObuff, TRUE, HL_ATTR(HLF_R));
	}

	if (fp == NULL)
	    continue;

	
	
	while (!got_int && !compl_interrupted && !vim_fgets(buf, LSIZE, fp))
	{
	    ptr = buf;
	    while (vim_regexec(regmatch, buf, (colnr_T)(ptr - buf)))
	    {
		ptr = regmatch->startp[0];
		if (ctrl_x_mode_line_or_eval())
		    ptr = find_line_end(ptr);
		else ptr = find_word_end(ptr);
		add_r = ins_compl_add_infercase(regmatch->startp[0], (int)(ptr - regmatch->startp[0]), p_ic, files[i], *dir, FALSE);

		if (thesaurus)
		{
		    
		    ptr = buf;
		    add_r = thesaurus_add_words_in_line(files[i], &ptr, *dir, regmatch->startp[0]);
		}
		if (add_r == OK)
		    
		    *dir = FORWARD;
		else if (add_r == FAIL)
		    break;
		
		
		if (*ptr == '\n' || got_int)
		    break;
	    }
	    line_breakcheck();
	    ins_compl_check_keys(50, FALSE);
	}
	fclose(fp);
    }
}


    char_u * find_word_start(char_u *ptr)
{
    if (has_mbyte)
	while (*ptr != NUL && *ptr != '\n' && mb_get_class(ptr) <= 1)
	    ptr += (*mb_ptr2len)(ptr);
    else while (*ptr != NUL && *ptr != '\n' && !vim_iswordc(*ptr))
	    ++ptr;
    return ptr;
}


    char_u * find_word_end(char_u *ptr)
{
    int		start_class;

    if (has_mbyte)
    {
	start_class = mb_get_class(ptr);
	if (start_class > 1)
	    while (*ptr != NUL)
	    {
		ptr += (*mb_ptr2len)(ptr);
		if (mb_get_class(ptr) != start_class)
		    break;
	    }
    }
    else while (vim_iswordc(*ptr))
	    ++ptr;
    return ptr;
}


    static char_u * find_line_end(char_u *ptr)
{
    char_u	*s;

    s = ptr + STRLEN(ptr);
    while (s > ptr && (s[-1] == CAR || s[-1] == NL))
	--s;
    return s;
}


    static void ins_compl_free(void)
{
    compl_T *match;
    int	    i;

    VIM_CLEAR(compl_pattern);
    VIM_CLEAR(compl_leader);

    if (compl_first_match == NULL)
	return;

    ins_compl_del_pum();
    pum_clear();

    compl_curr_match = compl_first_match;
    do {
	match = compl_curr_match;
	compl_curr_match = compl_curr_match->cp_next;
	vim_free(match->cp_str);
	
	if (match->cp_flags & CP_FREE_FNAME)
	    vim_free(match->cp_fname);
	for (i = 0; i < CPT_COUNT; ++i)
	    vim_free(match->cp_text[i]);

	clear_tv(&match->cp_user_data);

	vim_free(match);
    } while (compl_curr_match != NULL && !is_first_match(compl_curr_match));
    compl_first_match = compl_curr_match = NULL;
    compl_shown_match = NULL;
    compl_old_match = NULL;
}


    void ins_compl_clear(void)
{
    compl_cont_status = 0;
    compl_started = FALSE;
    compl_matches = 0;
    VIM_CLEAR(compl_pattern);
    VIM_CLEAR(compl_leader);
    edit_submode_extra = NULL;
    VIM_CLEAR(compl_orig_text);
    compl_enter_selects = FALSE;

    
    set_vim_var_dict(VV_COMPLETED_ITEM, dict_alloc_lock(VAR_FIXED));

}


    int ins_compl_active(void)
{
    return compl_started;
}


    int ins_compl_used_match(void)
{
    return compl_used_match;
}


    void ins_compl_init_get_longest(void)
{
    compl_get_longest = FALSE;
}


    int ins_compl_interrupted(void)
{
    return compl_interrupted;
}


    int ins_compl_enter_selects(void)
{
    return compl_enter_selects;
}


    colnr_T ins_compl_col(void)
{
    return compl_col;
}


    int ins_compl_len(void)
{
    return compl_length;
}


    int ins_compl_bs(void)
{
    char_u	*line;
    char_u	*p;

    line = ml_get_curline();
    p = line + curwin->w_cursor.col;
    MB_PTR_BACK(line, p);

    
    
    
    if ((int)(p - line) - (int)compl_col < 0 || ((int)(p - line) - (int)compl_col == 0 && !ctrl_x_mode_omni())
	    || ctrl_x_mode_eval()
	    || (!can_bs(BS_START) && (int)(p - line) - (int)compl_col - compl_length < 0))
	return K_BS;

    
    
    if (curwin->w_cursor.col <= compl_col + compl_length || ins_compl_need_restart())
	ins_compl_restart();

    vim_free(compl_leader);
    compl_leader = vim_strnsave(line + compl_col, (p - line) - compl_col);
    if (compl_leader == NULL)
	return K_BS;

    ins_compl_new_leader();
    if (compl_shown_match != NULL)
	
	compl_curr_match = compl_shown_match;
    return NUL;
}


    static int ins_compl_need_restart(void)
{
    
    
    return compl_was_interrupted || ((ctrl_x_mode_function() || ctrl_x_mode_omni())
						  && compl_opt_refresh_always);
}


    static void ins_compl_new_leader(void)
{
    ins_compl_del_pum();
    ins_compl_delete();
    ins_bytes(compl_leader + get_compl_len());
    compl_used_match = FALSE;

    if (compl_started)
	ins_compl_set_original_text(compl_leader);
    else {

	spell_bad_len = 0;	

	
	
	
	pum_call_update_screen();

	if (gui.in_use)
	{
	    
	    setcursor();
	    out_flush_cursor(FALSE, FALSE);
	}

	compl_restarting = TRUE;
	if (ins_complete(Ctrl_N, TRUE) == FAIL)
	    compl_cont_status = 0;
	compl_restarting = FALSE;
    }

    compl_enter_selects = !compl_used_match;

    
    ins_compl_show_pum();

    
    if (compl_match_array == NULL)
	compl_enter_selects = FALSE;
}


    static int get_compl_len(void)
{
    int off = (int)curwin->w_cursor.col - (int)compl_col;

    if (off < 0)
	return 0;
    return off;
}


    void ins_compl_addleader(int c)
{
    int		cc;

    if (stop_arrow() == FAIL)
	return;
    if (has_mbyte && (cc = (*mb_char2len)(c)) > 1)
    {
	char_u	buf[MB_MAXBYTES + 1];

	(*mb_char2bytes)(c, buf);
	buf[cc] = NUL;
	ins_char_bytes(buf, cc);
	if (compl_opt_refresh_always)
	    AppendToRedobuff(buf);
    }
    else {
	ins_char(c);
	if (compl_opt_refresh_always)
	    AppendCharToRedobuff(c);
    }

    
    if (ins_compl_need_restart())
	ins_compl_restart();

    
    
    
    if (!compl_opt_refresh_always)
    {
	vim_free(compl_leader);
	compl_leader = vim_strnsave(ml_get_curline() + compl_col, curwin->w_cursor.col - compl_col);
	if (compl_leader != NULL)
	    ins_compl_new_leader();
    }
}


    static void ins_compl_restart(void)
{
    ins_compl_free();
    compl_started = FALSE;
    compl_matches = 0;
    compl_cont_status = 0;
    compl_cont_mode = 0;
}


    static void ins_compl_set_original_text(char_u *str)
{
    char_u	*p;

    
    
    
    if (match_at_original_text(compl_first_match))	
    {
	p = vim_strsave(str);
	if (p != NULL)
	{
	    vim_free(compl_first_match->cp_str);
	    compl_first_match->cp_str = p;
	}
    }
    else if (compl_first_match->cp_prev != NULL && match_at_original_text(compl_first_match->cp_prev))
    {
       p = vim_strsave(str);
       if (p != NULL)
       {
	   vim_free(compl_first_match->cp_prev->cp_str);
	   compl_first_match->cp_prev->cp_str = p;
       }
    }
}


    void ins_compl_addfrommatch(void)
{
    char_u	*p;
    int		len = (int)curwin->w_cursor.col - (int)compl_col;
    int		c;
    compl_T	*cp;

    p = compl_shown_match->cp_str;
    if ((int)STRLEN(p) <= len)   
    {
	
	
	if (!match_at_original_text(compl_shown_match))
	    return;

	p = NULL;
	for (cp = compl_shown_match->cp_next; cp != NULL && !is_first_match(cp); cp = cp->cp_next)
	{
	    if (compl_leader == NULL || ins_compl_equal(cp, compl_leader, (int)STRLEN(compl_leader)))

	    {
		p = cp->cp_str;
		break;
	    }
	}
	if (p == NULL || (int)STRLEN(p) <= len)
	    return;
    }
    p += len;
    c = PTR2CHAR(p);
    ins_compl_addleader(c);
}


    static int set_ctrl_x_mode(int c)
{
    int retval = FALSE;

    switch (c)
    {
	case Ctrl_E:
	case Ctrl_Y:
	    
	    ctrl_x_mode = CTRL_X_SCROLL;
	    if (!(State & REPLACE_FLAG))
		edit_submode = (char_u *)_(" (insert) Scroll (^E/^Y)");
	    else edit_submode = (char_u *)_(" (replace) Scroll (^E/^Y)");
	    edit_submode_pre = NULL;
	    showmode();
	    break;
	case Ctrl_L:
	    
	    ctrl_x_mode = CTRL_X_WHOLE_LINE;
	    break;
	case Ctrl_F:
	    
	    ctrl_x_mode = CTRL_X_FILES;
	    break;
	case Ctrl_K:
	    
	    ctrl_x_mode = CTRL_X_DICTIONARY;
	    break;
	case Ctrl_R:
	    
	    
	    break;
	case Ctrl_T:
	    
	    ctrl_x_mode = CTRL_X_THESAURUS;
	    break;

	case Ctrl_U:
	    
	    ctrl_x_mode = CTRL_X_FUNCTION;
	    break;
	case Ctrl_O:
	    
	    ctrl_x_mode = CTRL_X_OMNI;
	    break;

	case 's':
	case Ctrl_S:
	    
	    ctrl_x_mode = CTRL_X_SPELL;

	    ++emsg_off;	
	    spell_back_to_badword();
	    --emsg_off;

	    break;
	case Ctrl_RSB:
	    
	    ctrl_x_mode = CTRL_X_TAGS;
	    break;

	case Ctrl_I:
	case K_S_TAB:
	    
	    ctrl_x_mode = CTRL_X_PATH_PATTERNS;
	    break;
	case Ctrl_D:
	    
	    ctrl_x_mode = CTRL_X_PATH_DEFINES;
	    break;

	case Ctrl_V:
	case Ctrl_Q:
	    
	    ctrl_x_mode = CTRL_X_CMDLINE;
	    break;
	case Ctrl_Z:
	    
	    ctrl_x_mode = CTRL_X_NORMAL;
	    edit_submode = NULL;
	    showmode();
	    retval = TRUE;
	    break;
	case Ctrl_P:
	case Ctrl_N:
	    
	    
	    
	    
	    
	    
	    
	    if (!(compl_cont_status & CONT_INTRPT))
		compl_cont_status |= CONT_LOCAL;
	    else if (compl_cont_mode != 0)
		compl_cont_status &= ~CONT_LOCAL;
	    
	default:
	    
	    
	    
	    
	    
	    
	    
	    
	    
	    
	    if (c == Ctrl_X)
	    {
		if (compl_cont_mode != 0)
		    compl_cont_status = 0;
		else compl_cont_mode = CTRL_X_NOT_DEFINED_YET;
	    }
	    ctrl_x_mode = CTRL_X_NORMAL;
	    edit_submode = NULL;
	    showmode();
	    break;
    }

    return retval;
}


    static int ins_compl_stop(int c, int prev_mode, int retval)
{
    char_u	*ptr;
    int		want_cindent;

    
    
    
    if (compl_curr_match != NULL || compl_leader != NULL || c == Ctrl_E)
    {
	
	
	
	
	
	
	if (compl_curr_match != NULL && compl_used_match && c != Ctrl_E)
	    ptr = compl_curr_match->cp_str;
	else ptr = NULL;
	ins_compl_fixRedoBufForLeader(ptr);
    }

    want_cindent = (get_can_cindent() && cindent_on());

    
    
    if (compl_cont_mode == CTRL_X_WHOLE_LINE)
    {
	
	if (want_cindent)
	{
	    do_c_expr_indent();
	    want_cindent = FALSE;	
	}
    }
    else {
	int prev_col = curwin->w_cursor.col;

	
	if (prev_col > 0)
	    dec_cursor();
	
	if (!arrow_used && !ins_need_undo_get() && c != Ctrl_E)
	    insertchar(NUL, 0, -1);
	if (prev_col > 0 && ml_get_curline()[curwin->w_cursor.col] != NUL)
	    inc_cursor();
    }

    
    
    
    if ((c == Ctrl_Y || (compl_enter_selects && (c == CAR || c == K_KENTER || c == NL)))
	    && pum_visible())
	retval = TRUE;

    
    
    if (c == Ctrl_E)
    {
	char_u *p = NULL;

	ins_compl_delete();
	if (compl_leader != NULL)
	    p = compl_leader;
	else if (compl_first_match != NULL)
	    p = compl_orig_text;
	if (p != NULL)
	{
	    int	    compl_len = get_compl_len();
	    int	    len = (int)STRLEN(p);

	    if (len > compl_len)
		ins_bytes_len(p + compl_len, len - compl_len);
	}
	retval = TRUE;
    }

    auto_format(FALSE, TRUE);

    
    
    
    ctrl_x_mode = prev_mode;
    ins_apply_autocmds(EVENT_COMPLETEDONEPRE);

    ins_compl_free();
    compl_started = FALSE;
    compl_matches = 0;
    if (!shortmess(SHM_COMPLETIONMENU))
	msg_clr_cmdline();	
    ctrl_x_mode = CTRL_X_NORMAL;
    compl_enter_selects = FALSE;
    if (edit_submode != NULL)
    {
	edit_submode = NULL;
	showmode();
    }


    if (c == Ctrl_C && cmdwin_type != 0)
	
	
	update_screen(0);

    
    if (want_cindent && in_cinkeys(KEY_COMPLETE, ' ', inindent(0)))
	do_c_expr_indent();
    
    
    ins_apply_autocmds(EVENT_COMPLETEDONE);

    return retval;
}


    int ins_compl_prep(int c)
{
    int		retval = FALSE;
    int		prev_mode = ctrl_x_mode;

    
    
    if (c != Ctrl_R && vim_is_ctrl_x_key(c))
	edit_submode_extra = NULL;

    
    if (c == K_SELECT || c == K_MOUSEDOWN || c == K_MOUSEUP || c == K_MOUSELEFT || c == K_MOUSERIGHT || c == K_COMMAND || c == K_SCRIPT_COMMAND)

	return retval;


    
    if (is_mouse_key(c))
    {
	
	
	if (c == K_LEFTRELEASE || c == K_LEFTRELEASE_NM || c == K_MIDDLERELEASE || c == K_RIGHTRELEASE || c == K_X1RELEASE || c == K_X2RELEASE || c == K_LEFTDRAG || c == K_MIDDLEDRAG || c == K_RIGHTDRAG || c == K_X1DRAG || c == K_X2DRAG)









	    return retval;
	if (popup_visible)
	{
	    int	    row = mouse_row;
	    int	    col = mouse_col;
	    win_T   *wp = mouse_find_win(&row, &col, FIND_POPUP);

	    if (wp != NULL && WIN_IS_POPUP(wp))
		return retval;
	}
    }


    if (ctrl_x_mode == CTRL_X_CMDLINE_CTRL_X && c != Ctrl_X)
    {
	if (c == Ctrl_V || c == Ctrl_Q || c == Ctrl_Z || ins_compl_pum_key(c)
		|| !vim_is_ctrl_x_key(c))
	{
	    
	    ctrl_x_mode = CTRL_X_CMDLINE;

	    
	    if (c == Ctrl_Z)
		retval = TRUE;
	}
	else {
	    ctrl_x_mode = CTRL_X_CMDLINE;

	    
	    
	    ins_compl_prep(' ');
	    ctrl_x_mode = CTRL_X_NOT_DEFINED_YET;
	}
    }

    
    if (ctrl_x_mode_not_defined_yet()
			   || (ctrl_x_mode_normal() && !compl_started))
    {
	compl_get_longest = compl_longest;
	compl_used_match = TRUE;

    }

    if (ctrl_x_mode_not_defined_yet())
	
	
	retval = set_ctrl_x_mode(c);
    else if (ctrl_x_mode_not_default())
    {
	
	if (!vim_is_ctrl_x_key(c))
	{
	    if (ctrl_x_mode_scroll())
		ctrl_x_mode = CTRL_X_NORMAL;
	    else ctrl_x_mode = CTRL_X_FINISHED;
	    edit_submode = NULL;
	}
	showmode();
    }

    if (compl_started || ctrl_x_mode == CTRL_X_FINISHED)
    {
	
	
	
	showmode();
	if ((ctrl_x_mode_normal() && c != Ctrl_N && c != Ctrl_P && c != Ctrl_R && !ins_compl_pum_key(c))
		|| ctrl_x_mode == CTRL_X_FINISHED)
	    retval = ins_compl_stop(c, prev_mode, retval);
    }
    else if (ctrl_x_mode == CTRL_X_LOCAL_MSG)
	
	
	ins_apply_autocmds(EVENT_COMPLETEDONE);

    may_trigger_modechanged();

    
    
    if (!vim_is_ctrl_x_key(c))
    {
	compl_cont_status = 0;
	compl_cont_mode = 0;
    }

    return retval;
}


    static void ins_compl_fixRedoBufForLeader(char_u *ptr_arg)
{
    int	    len;
    char_u  *p;
    char_u  *ptr = ptr_arg;

    if (ptr == NULL)
    {
	if (compl_leader != NULL)
	    ptr = compl_leader;
	else return;
    }
    if (compl_orig_text != NULL)
    {
	p = compl_orig_text;
	for (len = 0; p[len] != NUL && p[len] == ptr[len]; ++len)
	    ;
	if (len > 0)
	    len -= (*mb_head_off)(p, p + len);
	for (p += len; *p != NUL; MB_PTR_ADV(p))
	    AppendCharToRedobuff(K_BS);
    }
    else len = 0;
    if (ptr != NULL)
	AppendToRedobuffLit(ptr + len, -1);
}


    static buf_T * ins_compl_next_buf(buf_T *buf, int flag)
{
    static win_T *wp = NULL;

    if (flag == 'w')		
    {
	if (buf == curbuf || wp == NULL)  
	    wp = curwin;
	while ((wp = (wp->w_next != NULL ? wp->w_next : firstwin)) != curwin && wp->w_buffer->b_scanned)
	    ;
	buf = wp->w_buffer;
    }
    else    while ((buf = (buf->b_next != NULL ? buf->b_next : firstbuf)) != curbuf && ((flag == 'U' ? buf->b_p_bl : (!buf->b_p_bl || (buf->b_ml.ml_mfp == NULL) != (flag == 'u')))







		    || buf->b_scanned))
	    ;
    return buf;
}




static callback_T cfu_cb;	    
static callback_T ofu_cb;	    
static callback_T tsrfu_cb;	    



    static void copy_global_to_buflocal_cb(callback_T *globcb, callback_T *bufcb)
{
    free_callback(bufcb);
    if (globcb->cb_name != NULL && *globcb->cb_name != NUL)
	copy_callback(bufcb, globcb);
}


    int set_completefunc_option(void)
{
    int	retval;

    retval = option_set_callback_func(curbuf->b_p_cfu, &cfu_cb);
    if (retval == OK)
	set_buflocal_cfu_callback(curbuf);

    return retval;
}


    void set_buflocal_cfu_callback(buf_T *buf UNUSED)
{

    copy_global_to_buflocal_cb(&cfu_cb, &buf->b_cfu_cb);

}


    int set_omnifunc_option(void)
{
    int	retval;

    retval = option_set_callback_func(curbuf->b_p_ofu, &ofu_cb);
    if (retval == OK)
	set_buflocal_ofu_callback(curbuf);

    return retval;
}


    void set_buflocal_ofu_callback(buf_T *buf UNUSED)
{

    copy_global_to_buflocal_cb(&ofu_cb, &buf->b_ofu_cb);

}


    int set_thesaurusfunc_option(void)
{
    int	retval;

    if (*curbuf->b_p_tsrfu != NUL)
    {
	
	retval = option_set_callback_func(curbuf->b_p_tsrfu, &curbuf->b_tsrfu_cb);
    }
    else {
	
	retval = option_set_callback_func(p_tsrfu, &tsrfu_cb);
    }

    return retval;
}


    int set_ref_in_insexpand_funcs(int copyID)
{
    int abort = FALSE;

    abort = set_ref_in_callback(&cfu_cb, copyID);
    abort = abort || set_ref_in_callback(&ofu_cb, copyID);
    abort = abort || set_ref_in_callback(&tsrfu_cb, copyID);

    return abort;
}


    static char_u * get_complete_funcname(int type)
{
    switch (type)
    {
	case CTRL_X_FUNCTION:
	    return curbuf->b_p_cfu;
	case CTRL_X_OMNI:
	    return curbuf->b_p_ofu;
	case CTRL_X_THESAURUS:
	    return *curbuf->b_p_tsrfu == NUL ? p_tsrfu : curbuf->b_p_tsrfu;
	default:
	    return (char_u *)"";
    }
}


    static callback_T * get_insert_callback(int type)
{
    if (type == CTRL_X_FUNCTION)
	return &curbuf->b_cfu_cb;
    if (type == CTRL_X_OMNI)
	return &curbuf->b_ofu_cb;
    
    return (*curbuf->b_p_tsrfu != NUL) ? &curbuf->b_tsrfu_cb : &tsrfu_cb;
}


    static void expand_by_function(int type, char_u *base)
{
    list_T      *matchlist = NULL;
    dict_T	*matchdict = NULL;
    typval_T	args[3];
    char_u	*funcname;
    pos_T	pos;
    callback_T	*cb;
    typval_T	rettv;
    int		save_State = State;
    int		retval;

    funcname = get_complete_funcname(type);
    if (*funcname == NUL)
	return;

    
    args[0].v_type = VAR_NUMBER;
    args[0].vval.v_number = 0;
    args[1].v_type = VAR_STRING;
    args[1].vval.v_string = base != NULL ? base : (char_u *)"";
    args[2].v_type = VAR_UNKNOWN;

    pos = curwin->w_cursor;
    
    
    
    ++textlock;

    cb = get_insert_callback(type);
    retval = call_callback(cb, 0, &rettv, 2, args);

    
    if (retval == OK)
    {
	switch (rettv.v_type)
	{
	    case VAR_LIST:
		matchlist = rettv.vval.v_list;
		break;
	    case VAR_DICT:
		matchdict = rettv.vval.v_dict;
		break;
	    case VAR_SPECIAL:
		if (rettv.vval.v_number == VVAL_NONE)
		    compl_opt_suppress_empty = TRUE;
		
	    default:
		
		clear_tv(&rettv);
		break;
	}
    }
    --textlock;

    curwin->w_cursor = pos;	
    validate_cursor();
    if (!EQUAL_POS(curwin->w_cursor, pos))
    {
	emsg(_(e_complete_function_deleted_text));
	goto theend;
    }

    if (matchlist != NULL)
	ins_compl_add_list(matchlist);
    else if (matchdict != NULL)
	ins_compl_add_dict(matchdict);

theend:
    
    State = save_State;

    if (matchdict != NULL)
	dict_unref(matchdict);
    if (matchlist != NULL)
	list_unref(matchlist);
}




    static int ins_compl_add_tv(typval_T *tv, int dir, int fast)
{
    char_u	*word;
    int		dup = FALSE;
    int		empty = FALSE;
    int		flags = fast ? CP_FAST : 0;
    char_u	*(cptext[CPT_COUNT]);
    typval_T	user_data;
    int		status;

    user_data.v_type = VAR_UNKNOWN;
    if (tv->v_type == VAR_DICT && tv->vval.v_dict != NULL)
    {
	word = dict_get_string(tv->vval.v_dict, "word", FALSE);
	cptext[CPT_ABBR] = dict_get_string(tv->vval.v_dict, "abbr", FALSE);
	cptext[CPT_MENU] = dict_get_string(tv->vval.v_dict, "menu", FALSE);
	cptext[CPT_KIND] = dict_get_string(tv->vval.v_dict, "kind", FALSE);
	cptext[CPT_INFO] = dict_get_string(tv->vval.v_dict, "info", FALSE);
	dict_get_tv(tv->vval.v_dict, "user_data", &user_data);
	if (dict_get_string(tv->vval.v_dict, "icase", FALSE) != NULL && dict_get_number(tv->vval.v_dict, "icase"))
	    flags |= CP_ICASE;
	if (dict_get_string(tv->vval.v_dict, "dup", FALSE) != NULL)
	    dup = dict_get_number(tv->vval.v_dict, "dup");
	if (dict_get_string(tv->vval.v_dict, "empty", FALSE) != NULL)
	    empty = dict_get_number(tv->vval.v_dict, "empty");
	if (dict_get_string(tv->vval.v_dict, "equal", FALSE) != NULL && dict_get_number(tv->vval.v_dict, "equal"))
	    flags |= CP_EQUAL;
    }
    else {
	word = tv_get_string_chk(tv);
	CLEAR_FIELD(cptext);
    }
    if (word == NULL || (!empty && *word == NUL))
    {
	clear_tv(&user_data);
	return FAIL;
    }
    status = ins_compl_add(word, -1, NULL, cptext, &user_data, dir, flags, dup);
    if (status != OK)
	clear_tv(&user_data);
    return status;
}


    static void ins_compl_add_list(list_T *list)
{
    listitem_T	*li;
    int		dir = compl_direction;

    
    CHECK_LIST_MATERIALIZE(list);
    FOR_ALL_LIST_ITEMS(list, li)
    {
	if (ins_compl_add_tv(&li->li_tv, dir, TRUE) == OK)
	    
	    dir = FORWARD;
	else if (did_emsg)
	    break;
    }
}


    static void ins_compl_add_dict(dict_T *dict)
{
    dictitem_T	*di_refresh;
    dictitem_T	*di_words;

    
    compl_opt_refresh_always = FALSE;
    di_refresh = dict_find(dict, (char_u *)"refresh", 7);
    if (di_refresh != NULL && di_refresh->di_tv.v_type == VAR_STRING)
    {
	char_u	*v = di_refresh->di_tv.vval.v_string;

	if (v != NULL && STRCMP(v, (char_u *)"always") == 0)
	    compl_opt_refresh_always = TRUE;
    }

    
    di_words = dict_find(dict, (char_u *)"words", 5);
    if (di_words != NULL && di_words->di_tv.v_type == VAR_LIST)
	ins_compl_add_list(di_words->di_tv.vval.v_list);
}


    static void set_completion(colnr_T startcol, list_T *list)
{
    int save_w_wrow = curwin->w_wrow;
    int save_w_leftcol = curwin->w_leftcol;
    int flags = CP_ORIGINAL_TEXT;

    
    if (ctrl_x_mode_not_default())
	ins_compl_prep(' ');
    ins_compl_clear();
    ins_compl_free();
    compl_get_longest = compl_longest;

    compl_direction = FORWARD;
    if (startcol > curwin->w_cursor.col)
	startcol = curwin->w_cursor.col;
    compl_col = startcol;
    compl_length = (int)curwin->w_cursor.col - (int)startcol;
    
    compl_orig_text = vim_strnsave(ml_get_curline() + compl_col, compl_length);
    if (p_ic)
	flags |= CP_ICASE;
    if (compl_orig_text == NULL || ins_compl_add(compl_orig_text, -1, NULL, NULL, NULL, 0, flags | CP_FAST, FALSE) != OK)

	return;

    ctrl_x_mode = CTRL_X_EVAL;

    ins_compl_add_list(list);
    compl_matches = ins_compl_make_cyclic();
    compl_started = TRUE;
    compl_used_match = TRUE;
    compl_cont_status = 0;

    compl_curr_match = compl_first_match;
    int no_select = compl_no_select || compl_longest;
    if (compl_no_insert || no_select)
    {
	ins_complete(K_DOWN, FALSE);
	if (no_select)
	    
	    ins_complete(K_UP, FALSE);
    }
    else ins_complete(Ctrl_N, FALSE);
    compl_enter_selects = compl_no_insert;

    
    if (!compl_interrupted)
	show_pum(save_w_wrow, save_w_leftcol);
    may_trigger_modechanged();
    out_flush();
}


    void f_complete(typval_T *argvars, typval_T *rettv UNUSED)
{
    int	    startcol;

    if (in_vim9script()
	    && (check_for_number_arg(argvars, 0) == FAIL || check_for_list_arg(argvars, 1) == FAIL))
	return;

    if ((State & MODE_INSERT) == 0)
    {
	emsg(_(e_complete_can_only_be_used_in_insert_mode));
	return;
    }

    
    
    if (!undo_allowed())
	return;

    if (check_for_nonnull_list_arg(argvars, 1) != FAIL)
    {
	startcol = (int)tv_get_number_chk(&argvars[0], NULL);
	if (startcol > 0)
	    set_completion(startcol - 1, argvars[1].vval.v_list);
    }
}


    void f_complete_add(typval_T *argvars, typval_T *rettv)
{
    if (in_vim9script() && check_for_string_or_dict_arg(argvars, 0) == FAIL)
	return;

    rettv->vval.v_number = ins_compl_add_tv(&argvars[0], 0, FALSE);
}


    void f_complete_check(typval_T *argvars UNUSED, typval_T *rettv)
{
    int		saved = RedrawingDisabled;

    RedrawingDisabled = 0;
    ins_compl_check_keys(0, TRUE);
    rettv->vval.v_number = ins_compl_interrupted();
    RedrawingDisabled = saved;
}


    static char_u * ins_compl_mode(void)
{
    if (ctrl_x_mode_not_defined_yet() || ctrl_x_mode_scroll() || compl_started)
	return (char_u *)ctrl_x_mode_names[ctrl_x_mode & ~CTRL_X_WANT_IDENT];

    return (char_u *)"";
}


    static void ins_compl_update_sequence_numbers()
{
    int		number = 0;
    compl_T	*match;

    if (compl_dir_forward())
    {
	
	
	
	for (match = compl_curr_match->cp_prev; match != NULL && !is_first_match(match); match = match->cp_prev)
	    if (match->cp_number != -1)
	    {
		number = match->cp_number;
		break;
	    }
	if (match != NULL)
	    
	    
	    for (match = match->cp_next;
		    match != NULL && match->cp_number == -1;
					   match = match->cp_next)
		match->cp_number = ++number;
    }
    else  {
	
	
	
	for (match = compl_curr_match->cp_next; match != NULL && !is_first_match(match); match = match->cp_next)
	    if (match->cp_number != -1)
	    {
		number = match->cp_number;
		break;
	    }
	if (match != NULL)
	    
	    
	    for (match = match->cp_prev; match && match->cp_number == -1;
					   match = match->cp_prev)
		match->cp_number = ++number;
    }
}


    static void get_complete_info(list_T *what_list, dict_T *retdict)
{
    int		ret = OK;
    listitem_T	*item;






    int		what_flag;

    if (what_list == NULL)
	what_flag = CI_WHAT_ALL;
    else {
	what_flag = 0;
	CHECK_LIST_MATERIALIZE(what_list);
	FOR_ALL_LIST_ITEMS(what_list, item)
	{
	    char_u *what = tv_get_string(&item->li_tv);

	    if (STRCMP(what, "mode") == 0)
		what_flag |= CI_WHAT_MODE;
	    else if (STRCMP(what, "pum_visible") == 0)
		what_flag |= CI_WHAT_PUM_VISIBLE;
	    else if (STRCMP(what, "items") == 0)
		what_flag |= CI_WHAT_ITEMS;
	    else if (STRCMP(what, "selected") == 0)
		what_flag |= CI_WHAT_SELECTED;
	    else if (STRCMP(what, "inserted") == 0)
		what_flag |= CI_WHAT_INSERTED;
	}
    }

    if (ret == OK && (what_flag & CI_WHAT_MODE))
	ret = dict_add_string(retdict, "mode", ins_compl_mode());

    if (ret == OK && (what_flag & CI_WHAT_PUM_VISIBLE))
	ret = dict_add_number(retdict, "pum_visible", pum_visible());

    if (ret == OK && (what_flag & CI_WHAT_ITEMS))
    {
	list_T	    *li;
	dict_T	    *di;
	compl_T     *match;

	li = list_alloc();
	if (li == NULL)
	    return;
	ret = dict_add_list(retdict, "items", li);
	if (ret == OK && compl_first_match != NULL)
	{
	    match = compl_first_match;
	    do {
		if (!match_at_original_text(match))
		{
		    di = dict_alloc();
		    if (di == NULL)
			return;
		    ret = list_append_dict(li, di);
		    if (ret != OK)
			return;
		    dict_add_string(di, "word", match->cp_str);
		    dict_add_string(di, "abbr", match->cp_text[CPT_ABBR]);
		    dict_add_string(di, "menu", match->cp_text[CPT_MENU]);
		    dict_add_string(di, "kind", match->cp_text[CPT_KIND]);
		    dict_add_string(di, "info", match->cp_text[CPT_INFO]);
		    if (match->cp_user_data.v_type == VAR_UNKNOWN)
			
			dict_add_string(di, "user_data", (char_u *)"");
		    else dict_add_tv(di, "user_data", &match->cp_user_data);
		}
		match = match->cp_next;
	    }
	    while (match != NULL && !is_first_match(match));
	}
    }

    if (ret == OK && (what_flag & CI_WHAT_SELECTED))
    {
	if (compl_curr_match != NULL && compl_curr_match->cp_number == -1)
	    ins_compl_update_sequence_numbers();
	ret = dict_add_number(retdict, "selected", compl_curr_match != NULL ? compl_curr_match->cp_number - 1 : -1);
    }

    if (ret == OK && (what_flag & CI_WHAT_INSERTED))
    {
	
    }
}


    void f_complete_info(typval_T *argvars, typval_T *rettv)
{
    list_T	*what_list = NULL;

    if (rettv_dict_alloc(rettv) == FAIL)
	return;

    if (in_vim9script() && check_for_opt_list_arg(argvars, 0) == FAIL)
	return;

    if (argvars[0].v_type != VAR_UNKNOWN)
    {
	if (check_for_list_arg(argvars, 0) == FAIL)
	    return;
	what_list = argvars[0].vval.v_list;
    }
    get_complete_info(what_list, rettv->vval.v_dict);
}



    static int thesaurus_func_complete(int type UNUSED)
{

    return type == CTRL_X_THESAURUS && (*curbuf->b_p_tsrfu != NUL || *p_tsrfu != NUL);

    return FALSE;

}


enum {
    INS_COMPL_CPT_OK = 1, INS_COMPL_CPT_CONT, INS_COMPL_CPT_END };




typedef struct {
    char_u	*e_cpt;			
    buf_T	*ins_buf;		
    pos_T	*cur_match_pos;			
    pos_T	prev_match_pos;		
    int		set_match_pos;		
    pos_T	first_match_pos;	
    pos_T	last_match_pos;		
    int		found_all;		
    char_u	*dict;			
    int		dict_f;			
} ins_compl_next_state_T;


    static int process_next_cpt_value( ins_compl_next_state_T *st, int		*compl_type_arg, pos_T		*start_match_pos)



{
    int	    compl_type = -1;
    int	    status = INS_COMPL_CPT_OK;

    st->found_all = FALSE;

    while (*st->e_cpt == ',' || *st->e_cpt == ' ')
	st->e_cpt++;

    if (*st->e_cpt == '.' && !curbuf->b_scanned)
    {
	st->ins_buf = curbuf;
	st->first_match_pos = *start_match_pos;
	
	
	if (ctrl_x_mode_normal() && dec(&st->first_match_pos) < 0)
	{
	    
	    
	    
	    st->first_match_pos.lnum = st->ins_buf->b_ml.ml_line_count;
	    st->first_match_pos.col = (colnr_T)STRLEN(ml_get(st->first_match_pos.lnum));
	}
	st->last_match_pos = st->first_match_pos;
	compl_type = 0;

	
	
	st->set_match_pos = TRUE;
    }
    else if (vim_strchr((char_u *)"buwU", *st->e_cpt) != NULL && (st->ins_buf = ins_compl_next_buf(st->ins_buf, *st->e_cpt)) != curbuf)
    {
	
	if (st->ins_buf->b_ml.ml_mfp != NULL)   
	{
	    compl_started = TRUE;
	    st->first_match_pos.col = st->last_match_pos.col = 0;
	    st->first_match_pos.lnum = st->ins_buf->b_ml.ml_line_count + 1;
	    st->last_match_pos.lnum = 0;
	    compl_type = 0;
	}
	else	 {
	    st->found_all = TRUE;
	    if (st->ins_buf->b_fname == NULL)
	    {
		status = INS_COMPL_CPT_CONT;
		goto done;
	    }
	    compl_type = CTRL_X_DICTIONARY;
	    st->dict = st->ins_buf->b_fname;
	    st->dict_f = DICT_EXACT;
	}
	msg_hist_off = TRUE;	
	vim_snprintf((char *)IObuff, IOSIZE, _("Scanning: %s"), st->ins_buf->b_fname == NULL ? buf_spname(st->ins_buf)

		    : st->ins_buf->b_sfname == NULL ? st->ins_buf->b_fname : st->ins_buf->b_sfname);

	(void)msg_trunc_attr((char *)IObuff, TRUE, HL_ATTR(HLF_R));
    }
    else if (*st->e_cpt == NUL)
	status = INS_COMPL_CPT_END;
    else {
	if (ctrl_x_mode_line_or_eval())
	    compl_type = -1;
	else if (*st->e_cpt == 'k' || *st->e_cpt == 's')
	{
	    if (*st->e_cpt == 'k')
		compl_type = CTRL_X_DICTIONARY;
	    else compl_type = CTRL_X_THESAURUS;
	    if (*++st->e_cpt != ',' && *st->e_cpt != NUL)
	    {
		st->dict = st->e_cpt;
		st->dict_f = DICT_FIRST;
	    }
	}

	else if (*st->e_cpt == 'i')
	    compl_type = CTRL_X_PATH_PATTERNS;
	else if (*st->e_cpt == 'd')
	    compl_type = CTRL_X_PATH_DEFINES;

	else if (*st->e_cpt == ']' || *st->e_cpt == 't')
	{
	    msg_hist_off = TRUE;	
	    compl_type = CTRL_X_TAGS;
	    vim_snprintf((char *)IObuff, IOSIZE, _("Scanning tags."));
	    (void)msg_trunc_attr((char *)IObuff, TRUE, HL_ATTR(HLF_R));
	}
	else compl_type = -1;

	
	(void)copy_option_part(&st->e_cpt, IObuff, IOSIZE, ",");

	st->found_all = TRUE;
	if (compl_type == -1)
	    status = INS_COMPL_CPT_CONT;
    }

done:
    *compl_type_arg = compl_type;
    return status;
}



    static void get_next_include_file_completion(int compl_type)
{
    find_pattern_in_path(compl_pattern, compl_direction, (int)STRLEN(compl_pattern), FALSE, FALSE, (compl_type == CTRL_X_PATH_DEFINES && !(compl_cont_status & CONT_SOL))


	    ? FIND_DEFINE : FIND_ANY, 1L, ACTION_EXPAND, (linenr_T)1, (linenr_T)MAXLNUM);
}



    static void get_next_dict_tsr_completion(int compl_type, char_u *dict, int dict_f)
{

    if (thesaurus_func_complete(compl_type))
	expand_by_function(compl_type, compl_pattern);
    else  ins_compl_dictionaries( dict != NULL ? dict : (compl_type == CTRL_X_THESAURUS ? (*curbuf->b_p_tsr == NUL ? p_tsr : curbuf->b_p_tsr)




		    : (*curbuf->b_p_dict == NUL ? p_dict : curbuf->b_p_dict)), compl_pattern, dict != NULL ? dict_f : 0, compl_type == CTRL_X_THESAURUS);


}


    static void get_next_tag_completion(void)
{
    int		save_p_ic;
    char_u	**matches;
    int		num_matches;

    
    save_p_ic = p_ic;
    p_ic = ignorecase(compl_pattern);

    
    
    g_tag_at_cursor = TRUE;
    if (find_tags(compl_pattern, &num_matches, &matches, TAG_REGEXP | TAG_NAMES | TAG_NOIC | TAG_INS_COMP | (ctrl_x_mode_not_default() ? TAG_VERBOSE : 0), TAG_MANY, curbuf->b_ffname) == OK && num_matches > 0)


	ins_compl_add_matches(num_matches, matches, p_ic);
    g_tag_at_cursor = FALSE;
    p_ic = save_p_ic;
}


    static void get_next_filename_completion(void)
{
    char_u	**matches;
    int		num_matches;

    if (expand_wildcards(1, &compl_pattern, &num_matches, &matches, EW_FILE|EW_DIR|EW_ADDSLASH|EW_SILENT) != OK)
	return;

    
    tilde_replace(compl_pattern, num_matches, matches);

    if (curbuf->b_p_csl[0] != NUL)
    {
	int	    i;

	for (i = 0; i < num_matches; ++i)
	{
	    char_u	*ptr = matches[i];

	    while (*ptr != NUL)
	    {
		if (curbuf->b_p_csl[0] == 's' && *ptr == '\\')
		    *ptr = '/';
		else if (curbuf->b_p_csl[0] == 'b' && *ptr == '/')
		    *ptr = '\\';
		ptr += (*mb_ptr2len)(ptr);
	    }
	}
    }

    ins_compl_add_matches(num_matches, matches, p_fic || p_wic);
}


    static void get_next_cmdline_completion()
{
    char_u	**matches;
    int		num_matches;

    if (expand_cmdline(&compl_xp, compl_pattern, (int)STRLEN(compl_pattern), &num_matches, &matches) == EXPAND_OK)

	ins_compl_add_matches(num_matches, matches, FALSE);
}


    static void get_next_spell_completion(linenr_T lnum UNUSED)
{

    char_u	**matches;
    int		num_matches;

    num_matches = expand_spelling(lnum, compl_pattern, &matches);
    if (num_matches > 0)
	ins_compl_add_matches(num_matches, matches, p_ic);
    else vim_free(matches);

}


    static char_u * ins_comp_get_next_word_or_line( buf_T	*ins_buf, pos_T	*cur_match_pos, int	*match_len, int	*cont_s_ipos)




{
    char_u	*ptr;
    int		len;

    *match_len = 0;
    ptr = ml_get_buf(ins_buf, cur_match_pos->lnum, FALSE) + cur_match_pos->col;
    if (ctrl_x_mode_line_or_eval())
    {
	if (compl_status_adding())
	{
	    if (cur_match_pos->lnum >= ins_buf->b_ml.ml_line_count)
		return NULL;
	    ptr = ml_get_buf(ins_buf, cur_match_pos->lnum + 1, FALSE);
	    if (!p_paste)
		ptr = skipwhite(ptr);
	}
	len = (int)STRLEN(ptr);
    }
    else {
	char_u	*tmp_ptr = ptr;

	if (compl_status_adding() && compl_length <= (int)STRLEN(tmp_ptr))
	{
	    tmp_ptr += compl_length;
	    
	    if (vim_iswordp(tmp_ptr))
		return NULL;
	    
	    tmp_ptr = find_word_start(tmp_ptr);
	}
	
	tmp_ptr = find_word_end(tmp_ptr);
	len = (int)(tmp_ptr - ptr);

	if (compl_status_adding() && len == compl_length)
	{
	    if (cur_match_pos->lnum < ins_buf->b_ml.ml_line_count)
	    {
		
		
		
		
		
		STRNCPY(IObuff, ptr, len);
		ptr = ml_get_buf(ins_buf, cur_match_pos->lnum + 1, FALSE);
		tmp_ptr = ptr = skipwhite(ptr);
		
		tmp_ptr = find_word_start(tmp_ptr);
		
		tmp_ptr = find_word_end(tmp_ptr);
		if (tmp_ptr > ptr)
		{
		    if (*ptr != ')' && IObuff[len - 1] != TAB)
		    {
			if (IObuff[len - 1] != ' ')
			    IObuff[len++] = ' ';
			
			if (p_js && (IObuff[len - 2] == '.' || (vim_strchr(p_cpo, CPO_JOINSP)

					== NULL && (IObuff[len - 2] == '?' || IObuff[len - 2] == '!'))))

			    IObuff[len++] = ' ';
		    }
		    
		    if (tmp_ptr - ptr >= IOSIZE - len)
			tmp_ptr = ptr + IOSIZE - len - 1;
		    STRNCPY(IObuff + len, ptr, tmp_ptr - ptr);
		    len += (int)(tmp_ptr - ptr);
		    *cont_s_ipos = TRUE;
		}
		IObuff[len] = NUL;
		ptr = IObuff;
	    }
	    if (len == compl_length)
		return NULL;
	}
    }

    *match_len = len;
    return ptr;
}


    static int get_next_default_completion(ins_compl_next_state_T *st, pos_T *start_pos)
{
    int		found_new_match = FAIL;
    int		save_p_scs;
    int		save_p_ws;
    int		looped_around = FALSE;
    char_u	*ptr;
    int		len;

    
    save_p_scs = p_scs;
    if (st->ins_buf->b_p_inf)
	p_scs = FALSE;

    
    
    
    
    save_p_ws = p_ws;
    if (st->ins_buf != curbuf)
	p_ws = FALSE;
    else if (*st->e_cpt == '.')
	p_ws = TRUE;
    looped_around = FALSE;
    for (;;)
    {
	int	cont_s_ipos = FALSE;

	++msg_silent;  

	
	
	if (ctrl_x_mode_line_or_eval() || (compl_cont_status & CONT_SOL))
	    found_new_match = search_for_exact_line(st->ins_buf, st->cur_match_pos, compl_direction, compl_pattern);
	else found_new_match = searchit(NULL, st->ins_buf, st->cur_match_pos, NULL, compl_direction, compl_pattern, 1L, SEARCH_KEEP + SEARCH_NFMSG, RE_LAST, NULL);


	--msg_silent;
	if (!compl_started || st->set_match_pos)
	{
	    
	    compl_started = TRUE;
	    st->first_match_pos = *st->cur_match_pos;
	    st->last_match_pos = *st->cur_match_pos;
	    st->set_match_pos = FALSE;
	}
	else if (st->first_match_pos.lnum == st->last_match_pos.lnum && st->first_match_pos.col == st->last_match_pos.col)
	{
	    found_new_match = FAIL;
	}
	else if (compl_dir_forward()
		&& (st->prev_match_pos.lnum > st->cur_match_pos->lnum || (st->prev_match_pos.lnum == st->cur_match_pos->lnum && st->prev_match_pos.col >= st->cur_match_pos->col)))

	{
	    if (looped_around)
		found_new_match = FAIL;
	    else looped_around = TRUE;
	}
	else if (!compl_dir_forward()
		&& (st->prev_match_pos.lnum < st->cur_match_pos->lnum || (st->prev_match_pos.lnum == st->cur_match_pos->lnum && st->prev_match_pos.col <= st->cur_match_pos->col)))

	{
	    if (looped_around)
		found_new_match = FAIL;
	    else looped_around = TRUE;
	}
	st->prev_match_pos = *st->cur_match_pos;
	if (found_new_match == FAIL)
	    break;

	
	if (compl_status_adding() && st->ins_buf == curbuf && start_pos->lnum == st->cur_match_pos->lnum && start_pos->col  == st->cur_match_pos->col)

	    continue;

	ptr = ins_comp_get_next_word_or_line(st->ins_buf, st->cur_match_pos, &len, &cont_s_ipos);
	if (ptr == NULL)
	    continue;

	if (ins_compl_add_infercase(ptr, len, p_ic, st->ins_buf == curbuf ? NULL : st->ins_buf->b_sfname, 0, cont_s_ipos) != NOTDONE)

	{
	    found_new_match = OK;
	    break;
	}
    }
    p_scs = save_p_scs;
    p_ws = save_p_ws;

    return found_new_match;
}


    static int get_next_completion_match(int type, ins_compl_next_state_T *st, pos_T *ini)
{
    int	found_new_match = FALSE;

    switch (type)
    {
	case -1:
	    break;

	case CTRL_X_PATH_PATTERNS:
	case CTRL_X_PATH_DEFINES:
	    get_next_include_file_completion(type);
	    break;


	case CTRL_X_DICTIONARY:
	case CTRL_X_THESAURUS:
	    get_next_dict_tsr_completion(type, st->dict, st->dict_f);
	    st->dict = NULL;
	    break;

	case CTRL_X_TAGS:
	    get_next_tag_completion();
	    break;

	case CTRL_X_FILES:
	    get_next_filename_completion();
	    break;

	case CTRL_X_CMDLINE:
	case CTRL_X_CMDLINE_CTRL_X:
	    get_next_cmdline_completion();
	    break;


	case CTRL_X_FUNCTION:
	case CTRL_X_OMNI:
	    expand_by_function(type, compl_pattern);
	    break;


	case CTRL_X_SPELL:
	    get_next_spell_completion(st->first_match_pos.lnum);
	    break;

	default:	
	    found_new_match = get_next_default_completion(st, ini);
	    if (found_new_match == FAIL && st->ins_buf == curbuf)
		st->found_all = TRUE;
    }

    
    
    if (type != 0 && compl_curr_match != compl_old_match)
	found_new_match = OK;

    return found_new_match;
}


    static int ins_compl_get_exp(pos_T *ini)
{
    static ins_compl_next_state_T st;
    int		i;
    int		found_new_match;
    int		type = ctrl_x_mode;

    if (!compl_started)
    {
	FOR_ALL_BUFFERS(st.ins_buf)
	    st.ins_buf->b_scanned = 0;
	st.found_all = FALSE;
	st.ins_buf = curbuf;
	st.e_cpt = (compl_cont_status & CONT_LOCAL)
					    ? (char_u *)"." : curbuf->b_p_cpt;
	st.last_match_pos = st.first_match_pos = *ini;
    }
    else if (st.ins_buf != curbuf && !buf_valid(st.ins_buf))
	st.ins_buf = curbuf;  

    compl_old_match = compl_curr_match;	
    st.cur_match_pos = (compl_dir_forward())
				? &st.last_match_pos : &st.first_match_pos;

    
    for (;;)
    {
	found_new_match = FAIL;
	st.set_match_pos = FALSE;

	
	
	
	if ((ctrl_x_mode_normal() || ctrl_x_mode_line_or_eval())
					&& (!compl_started || st.found_all))
	{
	    int status = process_next_cpt_value(&st, &type, ini);

	    if (status == INS_COMPL_CPT_END)
		break;
	    if (status == INS_COMPL_CPT_CONT)
		continue;
	}

	
	
	if (compl_pattern == NULL)
	    break;

	
	found_new_match = get_next_completion_match(type, &st, ini);

	
	
	
	if ((ctrl_x_mode_not_default() && !ctrl_x_mode_line_or_eval())
						|| found_new_match != FAIL)
	{
	    if (got_int)
		break;
	    
	    if (type != -1)
		ins_compl_check_keys(0, FALSE);

	    if ((ctrl_x_mode_not_default()
			&& !ctrl_x_mode_line_or_eval()) || compl_interrupted)
		break;
	    compl_started = TRUE;
	}
	else {
	    
	    if (type == 0 || type == CTRL_X_PATH_PATTERNS)
		st.ins_buf->b_scanned = TRUE;

	    compl_started = FALSE;
	}
    }
    compl_started = TRUE;

    if ((ctrl_x_mode_normal() || ctrl_x_mode_line_or_eval())
	    && *st.e_cpt == NUL)		
	found_new_match = FAIL;

    i = -1;		
    if (found_new_match == FAIL || (ctrl_x_mode_not_default()
					       && !ctrl_x_mode_line_or_eval()))
	i = ins_compl_make_cyclic();

    if (compl_old_match != NULL)
    {
	
	
	
	compl_curr_match = compl_dir_forward() ? compl_old_match->cp_next : compl_old_match->cp_prev;
	if (compl_curr_match == NULL)
	    compl_curr_match = compl_old_match;
    }
    may_trigger_modechanged();

    return i;
}


    static void ins_compl_update_shown_match(void)
{
    while (!ins_compl_equal(compl_shown_match, compl_leader, (int)STRLEN(compl_leader))
	    && compl_shown_match->cp_next != NULL && !is_first_match(compl_shown_match->cp_next))
	compl_shown_match = compl_shown_match->cp_next;

    
    
    if (compl_shows_dir_backward()
	    && !ins_compl_equal(compl_shown_match, compl_leader, (int)STRLEN(compl_leader))
	    && (compl_shown_match->cp_next == NULL || is_first_match(compl_shown_match->cp_next)))
    {
	while (!ins_compl_equal(compl_shown_match, compl_leader, (int)STRLEN(compl_leader))
		&& compl_shown_match->cp_prev != NULL && !is_first_match(compl_shown_match->cp_prev))
	    compl_shown_match = compl_shown_match->cp_prev;
    }
}


    void ins_compl_delete(void)
{
    int	    col;

    
    
    col = compl_col + (compl_status_adding() ? compl_length : 0);
    if ((int)curwin->w_cursor.col > col)
    {
	if (stop_arrow() == FAIL)
	    return;
	backspace_until_column(col);
    }

    
    
    changed_cline_bef_curs();

    
    set_vim_var_dict(VV_COMPLETED_ITEM, dict_alloc_lock(VAR_FIXED));

}


    void ins_compl_insert(int in_compl_func)
{
    int compl_len = get_compl_len();

    
    
    if (compl_len < (int)STRLEN(compl_shown_match->cp_str))
	ins_bytes(compl_shown_match->cp_str + compl_len);
    if (match_at_original_text(compl_shown_match))
	compl_used_match = FALSE;
    else compl_used_match = TRUE;

    {
	dict_T *dict = ins_compl_dict_alloc(compl_shown_match);

	set_vim_var_dict(VV_COMPLETED_ITEM, dict);
    }

    if (!in_compl_func)
	compl_curr_match = compl_shown_match;
}


    static void ins_compl_show_filename(void)
{
    char	*lead = _("match in file");
    int		space = sc_col - vim_strsize((char_u *)lead) - 2;
    char_u	*s;
    char_u	*e;

    if (space <= 0)
	return;

    
    
    
    for (s = e = compl_shown_match->cp_fname; *e != NUL; MB_PTR_ADV(e))
    {
	space -= ptr2cells(e);
	while (space < 0)
	{
	    space += ptr2cells(s);
	    MB_PTR_ADV(s);
	}
    }
    msg_hist_off = TRUE;
    vim_snprintf((char *)IObuff, IOSIZE, "%s %s%s", lead, s > compl_shown_match->cp_fname ? "<" : "", s);
    msg((char *)IObuff);
    msg_hist_off = FALSE;
    redraw_cmdline = FALSE;	    
}


    static int find_next_completion_match( int	allow_get_expansion, int	todo, int	advance, int	*num_matches)




{
    int	    found_end = FALSE;
    compl_T *found_compl = NULL;

    while (--todo >= 0)
    {
	if (compl_shows_dir_forward() && compl_shown_match->cp_next != NULL)
	{
	    compl_shown_match = compl_shown_match->cp_next;
	    found_end = (compl_first_match != NULL && (is_first_match(compl_shown_match->cp_next)
			|| is_first_match(compl_shown_match)));
	}
	else if (compl_shows_dir_backward()
		&& compl_shown_match->cp_prev != NULL)
	{
	    found_end = is_first_match(compl_shown_match);
	    compl_shown_match = compl_shown_match->cp_prev;
	    found_end |= is_first_match(compl_shown_match);
	}
	else {
	    if (!allow_get_expansion)
	    {
		if (advance)
		{
		    if (compl_shows_dir_backward())
			compl_pending -= todo + 1;
		    else compl_pending += todo + 1;
		}
		return -1;
	    }

	    if (!compl_no_select && advance)
	    {
		if (compl_shows_dir_backward())
		    --compl_pending;
		else ++compl_pending;
	    }

	    
	    *num_matches = ins_compl_get_exp(&compl_startpos);

	    
	    while (compl_pending != 0 && compl_direction == compl_shows_dir && advance)
	    {
		if (compl_pending > 0 && compl_shown_match->cp_next != NULL)
		{
		    compl_shown_match = compl_shown_match->cp_next;
		    --compl_pending;
		}
		if (compl_pending < 0 && compl_shown_match->cp_prev != NULL)
		{
		    compl_shown_match = compl_shown_match->cp_prev;
		    ++compl_pending;
		}
		else break;
	    }
	    found_end = FALSE;
	}
	if (!match_at_original_text(compl_shown_match)
		&& compl_leader != NULL && !ins_compl_equal(compl_shown_match, compl_leader, (int)STRLEN(compl_leader)))

	    ++todo;
	else  found_compl = compl_shown_match;


	
	if (found_end)
	{
	    if (found_compl != NULL)
	    {
		compl_shown_match = found_compl;
		break;
	    }
	    todo = 1;	    
	}
    }

    return OK;
}


    static int ins_compl_next( int	    allow_get_expansion, int	    count,  int	    insert_match, int	    in_compl_func)





{
    int	    num_matches = -1;
    int	    todo = count;
    int	    advance;
    int	    started = compl_started;

    
    
    if (compl_shown_match == NULL)
	return -1;

    if (compl_leader != NULL && !match_at_original_text(compl_shown_match))
	
	ins_compl_update_shown_match();

    if (allow_get_expansion && insert_match && (!(compl_get_longest || compl_restarting) || compl_used_match))
	
	ins_compl_delete();

    
    
    advance = count != 1 || !allow_get_expansion || !compl_get_longest;

    
    if (compl_restarting)
    {
	advance = FALSE;
	compl_restarting = FALSE;
    }

    
    
    if (find_next_completion_match(allow_get_expansion, todo, advance, &num_matches) == -1)
	return -1;

    
    if (compl_no_insert && !started)
    {
	ins_bytes(compl_orig_text + get_compl_len());
	compl_used_match = FALSE;
    }
    else if (insert_match)
    {
	if (!compl_get_longest || compl_used_match)
	    ins_compl_insert(in_compl_func);
	else ins_bytes(compl_leader + get_compl_len());
    }
    else compl_used_match = FALSE;

    if (!allow_get_expansion)
    {
	
	ins_compl_upd_pum();

	if (pum_enough_matches())
	    
	    pum_call_update_screen();
	else   update_screen(0);



	
	ins_compl_show_pum();

	if (gui.in_use)
	{
	    
	    setcursor();
	    out_flush_cursor(FALSE, FALSE);
	}


	
	
	ins_compl_delete();
    }

    
    
    if (compl_no_insert && !started)
	compl_enter_selects = TRUE;
    else compl_enter_selects = !insert_match && compl_match_array != NULL;

    
    if (compl_shown_match->cp_fname != NULL)
	ins_compl_show_filename();

    return num_matches;
}


    void ins_compl_check_keys(int frequency, int in_compl_func)
{
    static int	count = 0;
    int		c;

    
    
    
    if (!in_compl_func && (using_script() || ex_normal_busy))
	return;

    
    if (++count < frequency)
	return;
    count = 0;

    
    
    c = vpeekc_any();
    if (c != NUL)
    {
	if (vim_is_ctrl_x_key(c) && c != Ctrl_X && c != Ctrl_R)
	{
	    c = safe_vgetc();	
	    compl_shows_dir = ins_compl_key2dir(c);
	    (void)ins_compl_next(FALSE, ins_compl_key2count(c), c != K_UP && c != K_DOWN, in_compl_func);
	}
	else {
	    
	    
	    c = safe_vgetc();
	    if (c != K_IGNORE)
	    {
		
		
		if (c != Ctrl_R && KeyTyped)
		    compl_interrupted = TRUE;

		vungetc(c);
	    }
	}
    }
    if (compl_pending != 0 && !got_int && !compl_no_insert)
    {
	int todo = compl_pending > 0 ? compl_pending : -compl_pending;

	compl_pending = 0;
	(void)ins_compl_next(FALSE, todo, TRUE, in_compl_func);
    }
}


    static int ins_compl_key2dir(int c)
{
    if (c == Ctrl_P || c == Ctrl_L || c == K_PAGEUP || c == K_KPAGEUP || c == K_S_UP || c == K_UP)
	return BACKWARD;
    return FORWARD;
}


    static int ins_compl_pum_key(int c)
{
    return pum_visible() && (c == K_PAGEUP || c == K_KPAGEUP || c == K_S_UP || c == K_PAGEDOWN || c == K_KPAGEDOWN || c == K_S_DOWN || c == K_UP || c == K_DOWN);

}


    static int ins_compl_key2count(int c)
{
    int		h;

    if (ins_compl_pum_key(c) && c != K_UP && c != K_DOWN)
    {
	h = pum_get_height();
	if (h > 3)
	    h -= 2; 
	return h;
    }
    return 1;
}


    static int ins_compl_use_match(int c)
{
    switch (c)
    {
	case K_UP:
	case K_DOWN:
	case K_PAGEDOWN:
	case K_KPAGEDOWN:
	case K_S_DOWN:
	case K_PAGEUP:
	case K_KPAGEUP:
	case K_S_UP:
	    return FALSE;
    }
    return TRUE;
}


    static int get_normal_compl_info(char_u *line, int startcol, colnr_T curs_col)
{
    if ((compl_cont_status & CONT_SOL) || ctrl_x_mode_path_defines())
    {
	if (!compl_status_adding())
	{
	    while (--startcol >= 0 && vim_isIDc(line[startcol]))
		;
	    compl_col += ++startcol;
	    compl_length = curs_col - startcol;
	}
	if (p_ic)
	    compl_pattern = str_foldcase(line + compl_col, compl_length, NULL, 0);
	else compl_pattern = vim_strnsave(line + compl_col, compl_length);
	if (compl_pattern == NULL)
	    return FAIL;
    }
    else if (compl_status_adding())
    {
	char_u	    *prefix = (char_u *)"\\<";

	
	compl_pattern = alloc(quote_meta(NULL, line + compl_col, compl_length) + 2);
	if (compl_pattern == NULL)
	    return FAIL;
	if (!vim_iswordp(line + compl_col)
		|| (compl_col > 0 && (vim_iswordp(mb_prevptr(line, line + compl_col)))))
	    prefix = (char_u *)"";
	STRCPY((char *)compl_pattern, prefix);
	(void)quote_meta(compl_pattern + STRLEN(prefix), line + compl_col, compl_length);
    }
    else if (--startcol < 0 || !vim_iswordp(mb_prevptr(line, line + startcol + 1)))
    {
	
	compl_pattern = vim_strsave((char_u *)"\\<\\k\\k");
	if (compl_pattern == NULL)
	    return FAIL;
	compl_col += curs_col;
	compl_length = 0;
    }
    else {
	
	
	if (has_mbyte)
	{
	    int base_class;
	    int head_off;

	    startcol -= (*mb_head_off)(line, line + startcol);
	    base_class = mb_get_class(line + startcol);
	    while (--startcol >= 0)
	    {
		head_off = (*mb_head_off)(line, line + startcol);
		if (base_class != mb_get_class(line + startcol - head_off))
		    break;
		startcol -= head_off;
	    }
	}
	else while (--startcol >= 0 && vim_iswordc(line[startcol]))
		;
	compl_col += ++startcol;
	compl_length = (int)curs_col - startcol;
	if (compl_length == 1)
	{
	    
	    
	    
	    compl_pattern = alloc(7);
	    if (compl_pattern == NULL)
		return FAIL;
	    STRCPY((char *)compl_pattern, "\\<");
	    (void)quote_meta(compl_pattern + 2, line + compl_col, 1);
	    STRCAT((char *)compl_pattern, "\\k");
	}
	else {
	    compl_pattern = alloc(quote_meta(NULL, line + compl_col, compl_length) + 2);
	    if (compl_pattern == NULL)
		return FAIL;
	    STRCPY((char *)compl_pattern, "\\<");
	    (void)quote_meta(compl_pattern + 2, line + compl_col, compl_length);
	}
    }

    return OK;
}


    static int get_wholeline_compl_info(char_u *line, colnr_T curs_col)
{
    compl_col = (colnr_T)getwhitecols(line);
    compl_length = (int)curs_col - (int)compl_col;
    if (compl_length < 0)	
	compl_length = 0;
    if (p_ic)
	compl_pattern = str_foldcase(line + compl_col, compl_length, NULL, 0);
    else compl_pattern = vim_strnsave(line + compl_col, compl_length);
    if (compl_pattern == NULL)
	return FAIL;

    return OK;
}


    static int get_filename_compl_info(char_u *line, int startcol, colnr_T curs_col)
{
    
    if (startcol > 0)
    {
	char_u	*p = line + startcol;

	MB_PTR_BACK(line, p);
	while (p > line && vim_isfilec(PTR2CHAR(p)))
	    MB_PTR_BACK(line, p);
	if (p == line && vim_isfilec(PTR2CHAR(p)))
	    startcol = 0;
	else startcol = (int)(p - line) + 1;
    }

    compl_col += startcol;
    compl_length = (int)curs_col - startcol;
    compl_pattern = addstar(line + compl_col, compl_length, EXPAND_FILES);
    if (compl_pattern == NULL)
	return FAIL;

    return OK;
}


    static int get_cmdline_compl_info(char_u *line, colnr_T curs_col)
{
    compl_pattern = vim_strnsave(line, curs_col);
    if (compl_pattern == NULL)
	return FAIL;
    set_cmd_context(&compl_xp, compl_pattern, (int)STRLEN(compl_pattern), curs_col, FALSE);
    if (compl_xp.xp_context == EXPAND_UNSUCCESSFUL || compl_xp.xp_context == EXPAND_NOTHING)
	
	
	compl_col = curs_col;
    else compl_col = (int)(compl_xp.xp_pattern - compl_pattern);
    compl_length = curs_col - compl_col;

    return OK;
}


    static int get_userdefined_compl_info(colnr_T curs_col UNUSED)
{
    int		ret = FAIL;


    
    
    char_u	*line;
    typval_T	args[3];
    int		col;
    char_u	*funcname;
    pos_T	pos;
    int		save_State = State;
    callback_T	*cb;

    
    
    funcname = get_complete_funcname(ctrl_x_mode);
    if (*funcname == NUL)
    {
	semsg(_(e_option_str_is_not_set), ctrl_x_mode_function()
		? "completefunc" : "omnifunc");
	return FAIL;
    }

    args[0].v_type = VAR_NUMBER;
    args[0].vval.v_number = 1;
    args[1].v_type = VAR_STRING;
    args[1].vval.v_string = (char_u *)"";
    args[2].v_type = VAR_UNKNOWN;
    pos = curwin->w_cursor;
    ++textlock;
    cb = get_insert_callback(ctrl_x_mode);
    col = call_callback_retnr(cb, 2, args);
    --textlock;

    State = save_State;
    curwin->w_cursor = pos;	
    validate_cursor();
    if (!EQUAL_POS(curwin->w_cursor, pos))
    {
	emsg(_(e_complete_function_deleted_text));
	return FAIL;
    }

    
    
    
    if (col == -2 || aborting())
	return FAIL;
    
    if (col == -3)
    {
	ctrl_x_mode = CTRL_X_NORMAL;
	edit_submode = NULL;
	if (!shortmess(SHM_COMPLETIONMENU))
	    msg_clr_cmdline();
	return FAIL;
    }

    
    
    compl_opt_refresh_always = FALSE;
    compl_opt_suppress_empty = FALSE;

    if (col < 0)
	col = curs_col;
    compl_col = col;
    if (compl_col > curs_col)
	compl_col = curs_col;

    
    
    line = ml_get(curwin->w_cursor.lnum);
    compl_length = curs_col - compl_col;
    compl_pattern = vim_strnsave(line + compl_col, compl_length);
    if (compl_pattern == NULL)
	return FAIL;

    ret = OK;


    return ret;
}


    static int get_spell_compl_info(int startcol UNUSED, colnr_T curs_col UNUSED)
{
    int		ret = FAIL;

    char_u	*line;

    if (spell_bad_len > 0)
	compl_col = curs_col - spell_bad_len;
    else compl_col = spell_word_start(startcol);
    if (compl_col >= (colnr_T)startcol)
    {
	compl_length = 0;
	compl_col = curs_col;
    }
    else {
	spell_expand_check_cap(compl_col);
	compl_length = (int)curs_col - compl_col;
    }
    
    line = ml_get(curwin->w_cursor.lnum);
    compl_pattern = vim_strnsave(line + compl_col, compl_length);
    if (compl_pattern == NULL)
	return FAIL;

    ret = OK;


    return ret;
}


    static int compl_get_info(char_u *line, int startcol, colnr_T curs_col, int *line_invalid)
{
    if (ctrl_x_mode_normal()
	    || (ctrl_x_mode & CTRL_X_WANT_IDENT && !thesaurus_func_complete(ctrl_x_mode)))
    {
	return get_normal_compl_info(line, startcol, curs_col);
    }
    else if (ctrl_x_mode_line_or_eval())
    {
	return get_wholeline_compl_info(line, curs_col);
    }
    else if (ctrl_x_mode_files())
    {
	return get_filename_compl_info(line, startcol, curs_col);
    }
    else if (ctrl_x_mode == CTRL_X_CMDLINE)
    {
	return get_cmdline_compl_info(line, curs_col);
    }
    else if (ctrl_x_mode_function() || ctrl_x_mode_omni()
	    || thesaurus_func_complete(ctrl_x_mode))
    {
	if (get_userdefined_compl_info(curs_col) == FAIL)
	    return FAIL;
	*line_invalid = TRUE;	
    }
    else if (ctrl_x_mode_spell())
    {
	if (get_spell_compl_info(startcol, curs_col) == FAIL)
	    return FAIL;
	*line_invalid = TRUE;	
    }
    else {
	internal_error("ins_complete()");
	return FAIL;
    }

    return OK;
}


    static void ins_compl_continue_search(char_u *line)
{
    
    compl_cont_status &= ~CONT_INTRPT;	
    if (ctrl_x_mode_normal() || ctrl_x_mode_path_patterns()
						|| ctrl_x_mode_path_defines())
    {
	if (compl_startpos.lnum != curwin->w_cursor.lnum)
	{
	    
	    
	    
	    
	    compl_col = (colnr_T)getwhitecols(line);
	    compl_startpos.col = compl_col;
	    compl_startpos.lnum = curwin->w_cursor.lnum;
	    compl_cont_status &= ~CONT_SOL;   
	}
	else {
	    
	    
	    
	    if (compl_cont_status & CONT_S_IPOS)
	    {
		compl_cont_status |= CONT_SOL;
		compl_startpos.col = (colnr_T)(skipwhite( line + compl_length + compl_startpos.col) - line);

	    }
	    compl_col = compl_startpos.col;
	}
	compl_length = curwin->w_cursor.col - (int)compl_col;
	
	

	if (compl_length > (IOSIZE - MIN_SPACE))
	{
	    compl_cont_status &= ~CONT_SOL;
	    compl_length = (IOSIZE - MIN_SPACE);
	    compl_col = curwin->w_cursor.col - compl_length;
	}
	compl_cont_status |= CONT_ADDING | CONT_N_ADDS;
	if (compl_length < 1)
	    compl_cont_status &= CONT_LOCAL;
    }
    else if (ctrl_x_mode_line_or_eval())
	compl_cont_status = CONT_ADDING | CONT_N_ADDS;
    else compl_cont_status = 0;
}


    static int ins_compl_start(void)
{
    char_u	*line;
    int		startcol = 0;	    
    colnr_T	curs_col;	    
    int		line_invalid = FALSE;
    int		save_did_ai = did_ai;
    int		flags = CP_ORIGINAL_TEXT;

    

    did_ai = FALSE;
    did_si = FALSE;
    can_si = FALSE;
    can_si_back = FALSE;
    if (stop_arrow() == FAIL)
	return FAIL;

    line = ml_get(curwin->w_cursor.lnum);
    curs_col = curwin->w_cursor.col;
    compl_pending = 0;

    if ((compl_cont_status & CONT_INTRPT) == CONT_INTRPT && compl_cont_mode == ctrl_x_mode)
	
	
	ins_compl_continue_search(line);
    else compl_cont_status &= CONT_LOCAL;

    if (!compl_status_adding())	
    {
	compl_cont_mode = ctrl_x_mode;
	if (ctrl_x_mode_not_default())
	    
	    compl_cont_status = 0;
	compl_cont_status |= CONT_N_ADDS;
	compl_startpos = curwin->w_cursor;
	startcol = (int)curs_col;
	compl_col = 0;
    }

    
    if (compl_get_info(line, startcol, curs_col, &line_invalid) == FAIL)
    {
	if (ctrl_x_mode_function() || ctrl_x_mode_omni()
				|| thesaurus_func_complete(ctrl_x_mode))
	    
	    did_ai = save_did_ai;
	return FAIL;
    }
    
    if (line_invalid)
	line = ml_get(curwin->w_cursor.lnum);

    if (compl_status_adding())
    {
	edit_submode_pre = (char_u *)_(" Adding");
	if (ctrl_x_mode_line_or_eval())
	{
	    
	    char_u *old = curbuf->b_p_com;

	    curbuf->b_p_com = (char_u *)"";
	    compl_startpos.lnum = curwin->w_cursor.lnum;
	    compl_startpos.col = compl_col;
	    ins_eol('\r');
	    curbuf->b_p_com = old;
	    compl_length = 0;
	    compl_col = curwin->w_cursor.col;
	}
    }
    else {
	edit_submode_pre = NULL;
	compl_startpos.col = compl_col;
    }

    if (compl_cont_status & CONT_LOCAL)
	edit_submode = (char_u *)_(ctrl_x_msgs[CTRL_X_LOCAL_MSG]);
    else edit_submode = (char_u *)_(CTRL_X_MSG(ctrl_x_mode));

    
    
    ins_compl_fixRedoBufForLeader(NULL);

    
    vim_free(compl_orig_text);
    compl_orig_text = vim_strnsave(line + compl_col, compl_length);
    if (p_ic)
	flags |= CP_ICASE;
    if (compl_orig_text == NULL || ins_compl_add(compl_orig_text, -1, NULL, NULL, NULL, 0, flags, FALSE) != OK)
    {
	VIM_CLEAR(compl_pattern);
	VIM_CLEAR(compl_orig_text);
	return FAIL;
    }

    
    
    
    edit_submode_extra = (char_u *)_("-- Searching...");
    edit_submode_highl = HLF_COUNT;
    showmode();
    edit_submode_extra = NULL;
    out_flush();

    return OK;
}


    static void ins_compl_show_statusmsg(void)
{
    
    if (is_first_match(compl_first_match->cp_next))
    {
	edit_submode_extra = compl_status_adding() && compl_length > 1 ? (char_u *)_(e_hitend)
				: (char_u *)_(e_pattern_not_found);
	edit_submode_highl = HLF_E;
    }

    if (edit_submode_extra == NULL)
    {
	if (match_at_original_text(compl_curr_match))
	{
	    edit_submode_extra = (char_u *)_("Back at original");
	    edit_submode_highl = HLF_W;
	}
	else if (compl_cont_status & CONT_S_IPOS)
	{
	    edit_submode_extra = (char_u *)_("Word from other line");
	    edit_submode_highl = HLF_COUNT;
	}
	else if (compl_curr_match->cp_next == compl_curr_match->cp_prev)
	{
	    edit_submode_extra = (char_u *)_("The only match");
	    edit_submode_highl = HLF_COUNT;
	    compl_curr_match->cp_number = 1;
	}
	else {

	    
	    if (compl_curr_match->cp_number == -1)
		ins_compl_update_sequence_numbers();

	    
	    
	    if (compl_curr_match->cp_number != -1)
	    {
		
		
		static char_u match_ref[81];

		if (compl_matches > 0)
		    vim_snprintf((char *)match_ref, sizeof(match_ref), _("match %d of %d"), compl_curr_match->cp_number, compl_matches);

		else vim_snprintf((char *)match_ref, sizeof(match_ref), _("match %d"), compl_curr_match->cp_number);


		edit_submode_extra = match_ref;
		edit_submode_highl = HLF_R;
		if (dollar_vcol >= 0)
		    curs_columns(FALSE);
	    }
	}
    }

    
    if (!compl_opt_suppress_empty)
    {
	showmode();
	if (!shortmess(SHM_COMPLETIONMENU))
	{
	    if (edit_submode_extra != NULL)
	    {
		if (!p_smd)
		{
		    msg_hist_off = TRUE;
		    msg_attr((char *)edit_submode_extra, edit_submode_highl < HLF_COUNT ? HL_ATTR(edit_submode_highl) : 0);

		    msg_hist_off = FALSE;
		}
	    }
	    else msg_clr_cmdline();
	}
    }
}


    int ins_complete(int c, int enable_pum)
{
    int		n;
    int		save_w_wrow;
    int		save_w_leftcol;
    int		insert_match;

    compl_direction = ins_compl_key2dir(c);
    insert_match = ins_compl_use_match(c);

    if (!compl_started)
    {
	if (ins_compl_start() == FAIL)
	    return FAIL;
    }
    else if (insert_match && stop_arrow() == FAIL)
	return FAIL;

    compl_shown_match = compl_curr_match;
    compl_shows_dir = compl_direction;

    
    save_w_wrow = curwin->w_wrow;
    save_w_leftcol = curwin->w_leftcol;
    n = ins_compl_next(TRUE, ins_compl_key2count(c), insert_match, FALSE);

    
    ins_compl_upd_pum();

    if (n > 1)		
	compl_matches = n;
    compl_curr_match = compl_shown_match;
    compl_direction = compl_shows_dir;

    
    
    if (got_int && !global_busy)
    {
	(void)vgetc();
	got_int = FALSE;
    }

    
    if (is_first_match(compl_first_match->cp_next))
    {
	
	
	
	
	if (compl_length > 1 || compl_status_adding()
		|| (ctrl_x_mode_not_default()
		    && !ctrl_x_mode_path_patterns()
		    && !ctrl_x_mode_path_defines()))
	    compl_cont_status &= ~CONT_N_ADDS;
    }

    if (compl_curr_match->cp_flags & CP_CONT_S_IPOS)
	compl_cont_status |= CONT_S_IPOS;
    else compl_cont_status &= ~CONT_S_IPOS;

    ins_compl_show_statusmsg();

    
    if (enable_pum && !compl_interrupted)
	show_pum(save_w_wrow, save_w_leftcol);

    compl_was_interrupted = compl_interrupted;
    compl_interrupted = FALSE;

    return OK;
}


    static void show_pum(int prev_w_wrow, int prev_w_leftcol)
{
    
    int n = RedrawingDisabled;

    RedrawingDisabled = 0;

    
    
    setcursor();
    if (prev_w_wrow != curwin->w_wrow || prev_w_leftcol != curwin->w_leftcol)
	ins_compl_del_pum();

    ins_compl_show_pum();
    setcursor();
    RedrawingDisabled = n;
}


    static unsigned quote_meta(char_u *dest, char_u *src, int len)
{
    unsigned	m = (unsigned)len + 1;  

    for ( ; --len >= 0; src++)
    {
	switch (*src)
	{
	    case '.':
	    case '*':
	    case '[':
		if (ctrl_x_mode_dictionary() || ctrl_x_mode_thesaurus())
		    break;
		
	    case '~':
		if (!magic_isset())	
		    break;
		
	    case '\\':
		if (ctrl_x_mode_dictionary() || ctrl_x_mode_thesaurus())
		    break;
		
	    case '^':		
	    case '$':
		m++;
		if (dest != NULL)
		    *dest++ = '\\';
		break;
	}
	if (dest != NULL)
	    *dest++ = *src;
	
	if (has_mbyte)
	{
	    int i, mb_len;

	    mb_len = (*mb_ptr2len)(src) - 1;
	    if (mb_len > 0 && len >= mb_len)
		for (i = 0; i < mb_len; ++i)
		{
		    --len;
		    ++src;
		    if (dest != NULL)
			*dest++ = *src;
		}
	}
    }
    if (dest != NULL)
	*dest = NUL;

    return m;
}


    void free_insexpand_stuff(void)
{
    VIM_CLEAR(compl_orig_text);

    free_callback(&cfu_cb);
    free_callback(&ofu_cb);
    free_callback(&tsrfu_cb);

}




    static void spell_back_to_badword(void)
{
    pos_T	tpos = curwin->w_cursor;

    spell_bad_len = spell_move_to(curwin, BACKWARD, TRUE, TRUE, NULL);
    if (curwin->w_cursor.col != tpos.col)
	start_arrow(&tpos);
}

