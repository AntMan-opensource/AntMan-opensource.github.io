





static void set_vv_searchforward(void);
static int first_submatch(regmmatch_T *rp);


static void show_pat_in_path(char_u *, int, int, int, FILE *, linenr_T *, long);


typedef struct searchstat {
    int	    cur;	    
    int	    cnt;	    
    int	    exact_match;    
    int	    incomplete;	    
			    
			    
    int	    last_maxcount;  
} searchstat_T;

static void cmdline_search_stat(int dirc, pos_T *pos, pos_T *cursor_pos, int show_top_bot_msg, char_u *msgbuf, int recompute, int maxcount, long timeout);
static void update_search_stat(int dirc, pos_T *pos, pos_T *cursor_pos, searchstat_T *stat, int recompute, int maxcount, long timeout);










static spat_T spats[2] = {
    {NULL, TRUE, FALSE, {'/', 0, 0, 0L}},	 {NULL, TRUE, FALSE, {'/', 0, 0, 0L}}
};

static int last_idx = 0;	

static char_u lastc[2] = {NUL, NUL};	
static int lastcdir = FORWARD;		
static int last_t_cmd = TRUE;		
static char_u	lastc_bytes[MB_MAXBYTES + 1];
static int	lastc_bytelen = 1;	


static spat_T	    saved_spats[2];
static char_u	    *saved_mr_pattern = NULL;

static int	    saved_spats_last_idx = 0;
static int	    saved_spats_no_hlsearch = 0;



static char_u	    *mr_pattern = NULL;



typedef struct SearchedFile {
    FILE	*fp;		
    char_u	*name;		
    linenr_T	lnum;		
    int		matched;	
} SearchedFile;



    int search_regcomp( char_u	*pat, char_u	**used_pat, int		pat_save, int		pat_use, int		options, regmmatch_T	*regmatch)






{
    int		magic;
    int		i;

    rc_did_emsg = FALSE;
    magic = magic_isset();

    
    if (pat == NULL || *pat == NUL)
    {
	if (pat_use == RE_LAST)
	    i = last_idx;
	else i = pat_use;
	if (spats[i].pat == NULL)	
	{
	    if (pat_use == RE_SUBST)
		emsg(_(e_no_previous_substitute_regular_expression));
	    else emsg(_(e_no_previous_regular_expression));
	    rc_did_emsg = TRUE;
	    return FAIL;
	}
	pat = spats[i].pat;
	magic = spats[i].magic;
	no_smartcase = spats[i].no_scs;
    }
    else if (options & SEARCH_HIS)	
	add_to_history(HIST_SEARCH, pat, TRUE, NUL);

    if (used_pat)
	*used_pat = pat;

    vim_free(mr_pattern);

    if (curwin->w_p_rl && *curwin->w_p_rlc == 's')
	mr_pattern = reverse_text(pat);
    else  mr_pattern = vim_strsave(pat);


    
    if (!(options & SEARCH_KEEP)
			       && (cmdmod.cmod_flags & CMOD_KEEPPATTERNS) == 0)
    {
	
	if (pat_save == RE_SEARCH || pat_save == RE_BOTH)
	    save_re_pat(RE_SEARCH, pat, magic);
	
	if (pat_save == RE_SUBST || pat_save == RE_BOTH)
	    save_re_pat(RE_SUBST, pat, magic);
    }

    regmatch->rmm_ic = ignorecase(pat);
    regmatch->rmm_maxcol = 0;
    regmatch->regprog = vim_regcomp(pat, magic ? RE_MAGIC : 0);
    if (regmatch->regprog == NULL)
	return FAIL;
    return OK;
}


    char_u * get_search_pat(void)
{
    return mr_pattern;
}



    char_u * reverse_text(char_u *s)
{
    unsigned	len;
    unsigned	s_i, rev_i;
    char_u	*rev;

    
    len = (unsigned)STRLEN(s);
    rev = alloc(len + 1);
    if (rev == NULL)
	return NULL;

    rev_i = len;
    for (s_i = 0; s_i < len; ++s_i)
    {
	if (has_mbyte)
	{
	    int	mb_len;

	    mb_len = (*mb_ptr2len)(s + s_i);
	    rev_i -= mb_len;
	    mch_memmove(rev + rev_i, s + s_i, mb_len);
	    s_i += mb_len - 1;
	}
	else rev[--rev_i] = s[s_i];

    }
    rev[len] = NUL;
    return rev;
}


    void save_re_pat(int idx, char_u *pat, int magic)
{
    if (spats[idx].pat == pat)
	return;

    vim_free(spats[idx].pat);
    spats[idx].pat = vim_strsave(pat);
    spats[idx].magic = magic;
    spats[idx].no_scs = no_smartcase;
    last_idx = idx;

    
    if (p_hls)
	redraw_all_later(UPD_SOME_VALID);
    set_no_hlsearch(FALSE);

}


static int save_level = 0;

    void save_search_patterns(void)
{
    if (save_level++ != 0)
	return;

    saved_spats[0] = spats[0];
    if (spats[0].pat != NULL)
	saved_spats[0].pat = vim_strsave(spats[0].pat);
    saved_spats[1] = spats[1];
    if (spats[1].pat != NULL)
	saved_spats[1].pat = vim_strsave(spats[1].pat);
    if (mr_pattern == NULL)
	saved_mr_pattern = NULL;
    else saved_mr_pattern = vim_strsave(mr_pattern);

    saved_spats_last_idx = last_idx;
    saved_spats_no_hlsearch = no_hlsearch;

}

    void restore_search_patterns(void)
{
    if (--save_level != 0)
	return;

    vim_free(spats[0].pat);
    spats[0] = saved_spats[0];

    set_vv_searchforward();

    vim_free(spats[1].pat);
    spats[1] = saved_spats[1];
    vim_free(mr_pattern);
    mr_pattern = saved_mr_pattern;

    last_idx = saved_spats_last_idx;
    set_no_hlsearch(saved_spats_no_hlsearch);

}


    void free_search_patterns(void)
{
    vim_free(spats[0].pat);
    vim_free(spats[1].pat);
    VIM_CLEAR(mr_pattern);
}





static spat_T	    saved_last_search_spat;
static int	    did_save_last_search_spat = 0;
static int	    saved_last_idx = 0;
static int	    saved_no_hlsearch = 0;
static int	    saved_search_match_endcol;
static int	    saved_search_match_lines;


    void save_last_search_pattern(void)
{
    if (++did_save_last_search_spat != 1)
	
	return;

    saved_last_search_spat = spats[RE_SEARCH];
    if (spats[RE_SEARCH].pat != NULL)
	saved_last_search_spat.pat = vim_strsave(spats[RE_SEARCH].pat);
    saved_last_idx = last_idx;
    saved_no_hlsearch = no_hlsearch;
}

    void restore_last_search_pattern(void)
{
    if (--did_save_last_search_spat > 0)
	
	return;
    if (did_save_last_search_spat != 0)
    {
	iemsg("restore_last_search_pattern() called more often than save_last_search_pattern()");
	return;
    }

    vim_free(spats[RE_SEARCH].pat);
    spats[RE_SEARCH] = saved_last_search_spat;
    saved_last_search_spat.pat = NULL;

    set_vv_searchforward();

    last_idx = saved_last_idx;
    set_no_hlsearch(saved_no_hlsearch);
}


    static void save_incsearch_state(void)
{
    saved_search_match_endcol = search_match_endcol;
    saved_search_match_lines  = search_match_lines;
}

    static void restore_incsearch_state(void)
{
    search_match_endcol = saved_search_match_endcol;
    search_match_lines  = saved_search_match_lines;
}

    char_u * last_search_pattern(void)
{
    return spats[RE_SEARCH].pat;
}



    int ignorecase(char_u *pat)
{
    return ignorecase_opt(pat, p_ic, p_scs);
}


    int ignorecase_opt(char_u *pat, int ic_in, int scs)
{
    int		ic = ic_in;

    if (ic && !no_smartcase && scs && !(ctrl_x_mode_not_default() && curbuf->b_p_inf))
	ic = !pat_has_uppercase(pat);
    no_smartcase = FALSE;

    return ic;
}


    int pat_has_uppercase(char_u *pat)
{
    char_u *p = pat;
    magic_T magic_val = MAGIC_ON;

    
    (void)skip_regexp_ex(pat, NUL, magic_isset(), NULL, NULL, &magic_val);

    while (*p != NUL)
    {
	int		l;

	if (has_mbyte && (l = (*mb_ptr2len)(p)) > 1)
	{
	    if (enc_utf8 && utf_isupper(utf_ptr2char(p)))
		return TRUE;
	    p += l;
	}
	else if (*p == '\\' && magic_val <= MAGIC_ON)
	{
	    if (p[1] == '_' && p[2] != NUL)  
		p += 3;
	    else if (p[1] == '%' && p[2] != NUL)  
		p += 3;
	    else if (p[1] != NUL)  
		p += 2;
	    else p += 1;
	}
	else if ((*p == '%' || *p == '_') && magic_val == MAGIC_ALL)
	{
	    if (p[1] != NUL)  
		p += 2;
	    else p++;
	}
	else if (MB_ISUPPER(*p))
	    return TRUE;
	else ++p;
    }
    return FALSE;
}


    char_u * last_csearch(void)
{
    return lastc_bytes;
}

    int last_csearch_forward(void)
{
    return lastcdir == FORWARD;
}

    int last_csearch_until(void)
{
    return last_t_cmd == TRUE;
}

    void set_last_csearch(int c, char_u *s UNUSED, int len UNUSED)
{
    *lastc = c;
    lastc_bytelen = len;
    if (len)
	memcpy(lastc_bytes, s, len);
    else CLEAR_FIELD(lastc_bytes);
}


    void set_csearch_direction(int cdir)
{
    lastcdir = cdir;
}

    void set_csearch_until(int t_cmd)
{
    last_t_cmd = t_cmd;
}

    char_u * last_search_pat(void)
{
    return spats[last_idx].pat;
}


    void reset_search_dir(void)
{
    spats[0].off.dir = '/';

    set_vv_searchforward();

}



    void set_last_search_pat( char_u	*s, int		idx, int		magic, int		setlast)




{
    vim_free(spats[idx].pat);
    
    if (*s == NUL)
	spats[idx].pat = NULL;
    else spats[idx].pat = vim_strsave(s);
    spats[idx].magic = magic;
    spats[idx].no_scs = FALSE;
    spats[idx].off.dir = '/';

    set_vv_searchforward();

    spats[idx].off.line = FALSE;
    spats[idx].off.end = FALSE;
    spats[idx].off.off = 0;
    if (setlast)
	last_idx = idx;
    if (save_level)
    {
	vim_free(saved_spats[idx].pat);
	saved_spats[idx] = spats[0];
	if (spats[idx].pat == NULL)
	    saved_spats[idx].pat = NULL;
	else saved_spats[idx].pat = vim_strsave(spats[idx].pat);

	saved_spats_last_idx = last_idx;

    }

    
    if (p_hls && idx == last_idx && !no_hlsearch)
	redraw_all_later(UPD_SOME_VALID);

}




    void last_pat_prog(regmmatch_T *regmatch)
{
    if (spats[last_idx].pat == NULL)
    {
	regmatch->regprog = NULL;
	return;
    }
    ++emsg_off;		
    (void)search_regcomp((char_u *)"", NULL, 0, last_idx, SEARCH_KEEP, regmatch);
    --emsg_off;
}



    int searchit( win_T	*win,  buf_T	*buf, pos_T	*pos, pos_T	*end_pos, int		dir, char_u	*pat, long	count, int		options, int		pat_use, searchit_arg_T *extra_arg)











{
    int		found;
    linenr_T	lnum;		
    colnr_T	col;
    regmmatch_T	regmatch;
    char_u	*ptr;
    colnr_T	matchcol;
    lpos_T	endpos;
    lpos_T	matchpos;
    int		loop;
    pos_T	start_pos;
    int		at_first_line;
    int		extra_col;
    int		start_char_len;
    int		match_ok;
    long	nmatched;
    int		submatch = 0;
    int		first_match = TRUE;
    int		called_emsg_before = called_emsg;

    int		break_loop = FALSE;

    linenr_T	stop_lnum = 0;	
    int		unused_timeout_flag = FALSE;
    int		*timed_out = &unused_timeout_flag;  

    if (search_regcomp(pat, NULL, RE_SEARCH, pat_use, (options & (SEARCH_HIS + SEARCH_KEEP)), &regmatch) == FAIL)
    {
	if ((options & SEARCH_MSG) && !rc_did_emsg)
	    semsg(_(e_invalid_search_string_str), mr_pattern);
	return FAIL;
    }

    if (extra_arg != NULL)
    {
	stop_lnum = extra_arg->sa_stop_lnum;

	if (extra_arg->sa_tm > 0)
	    init_regexp_timeout(extra_arg->sa_tm);
	
	
	timed_out = &extra_arg->sa_timed_out;

    }

    
    do	 {
	
	
	
	if (pos->col == MAXCOL)
	    start_char_len = 0;
	
	else if (has_mbyte && pos->lnum >= 1 && pos->lnum <= buf->b_ml.ml_line_count && pos->col < MAXCOL - 2)

	{
	    ptr = ml_get_buf(buf, pos->lnum, FALSE);
	    if ((int)STRLEN(ptr) <= pos->col)
		start_char_len = 1;
	    else start_char_len = (*mb_ptr2len)(ptr + pos->col);
	}
	else start_char_len = 1;
	if (dir == FORWARD)
	{
	    if (options & SEARCH_START)
		extra_col = 0;
	    else extra_col = start_char_len;
	}
	else {
	    if (options & SEARCH_START)
		extra_col = start_char_len;
	    else extra_col = 0;
	}

	start_pos = *pos;	
	found = 0;		
	at_first_line = TRUE;	
	if (pos->lnum == 0)	
	{
	    pos->lnum = 1;
	    pos->col = 0;
	    at_first_line = FALSE;  
	}

	
	if (dir == BACKWARD && start_pos.col == 0 && (options & SEARCH_START) == 0)
	{
	    lnum = pos->lnum - 1;
	    at_first_line = FALSE;
	}
	else lnum = pos->lnum;

	for (loop = 0; loop <= 1; ++loop)   
	{
	    for ( ; lnum > 0 && lnum <= buf->b_ml.ml_line_count;
					   lnum += dir, at_first_line = FALSE)
	    {
		
		if (stop_lnum != 0 && (dir == FORWARD ? lnum > stop_lnum : lnum < stop_lnum))
		    break;
		
		if (*timed_out)
		    break;

		
		col = at_first_line && (options & SEARCH_COL) ? pos->col : (colnr_T)0;
		nmatched = vim_regexec_multi(&regmatch, win, buf, lnum, col, timed_out);
		
		if (regmatch.regprog == NULL)
		    break;
		
		if (called_emsg > called_emsg_before || *timed_out)
		    break;
		if (nmatched > 0)
		{
		    
		    matchpos = regmatch.startpos[0];
		    endpos = regmatch.endpos[0];

		    submatch = first_submatch(&regmatch);

		    
		    if (lnum + matchpos.lnum > buf->b_ml.ml_line_count)
			ptr = (char_u *)"";
		    else ptr = ml_get_buf(buf, lnum + matchpos.lnum, FALSE);

		    
		    if (dir == FORWARD && at_first_line)
		    {
			match_ok = TRUE;

			
			while (matchpos.lnum == 0 && ((options & SEARCH_END) && first_match ?  (nmatched == 1 && (int)endpos.col - 1 < (int)start_pos.col + extra_col)



				    : ((int)matchpos.col - (ptr[matchpos.col] == NUL)
					    < (int)start_pos.col + extra_col)))
			{
			    
			    if (vim_strchr(p_cpo, CPO_SEARCH) != NULL)
			    {
				if (nmatched > 1)
				{
				    
				    
				    match_ok = FALSE;
				    break;
				}
				matchcol = endpos.col;
				
				if (matchcol == matchpos.col && ptr[matchcol] != NUL)
				{
				    if (has_mbyte)
					matchcol += (*mb_ptr2len)(ptr + matchcol);
				    else ++matchcol;
				}
			    }
			    else {
				
				
				
				matchcol = regmatch.rmm_matchcol;
				if (ptr[matchcol] != NUL)
				{
				    if (has_mbyte)
					matchcol += (*mb_ptr2len)(ptr + matchcol);
				    else ++matchcol;
				}
			    }
			    if (matchcol == 0 && (options & SEARCH_START))
				break;
			    if (ptr[matchcol] == NUL || (nmatched = vim_regexec_multi(&regmatch, win, buf, lnum + matchpos.lnum, matchcol, timed_out)) == 0)


			    {
				match_ok = FALSE;
				break;
			    }
			    
			    if (regmatch.regprog == NULL)
				break;
			    matchpos = regmatch.startpos[0];
			    endpos = regmatch.endpos[0];

			    submatch = first_submatch(&regmatch);


			    
			    
			    ptr = ml_get_buf(buf, lnum + matchpos.lnum, FALSE);
			}
			if (!match_ok)
			    continue;
		    }
		    if (dir == BACKWARD)
		    {
			
			match_ok = FALSE;
			for (;;)
			{
			    
			    
			    
			    
			    if (loop || ((options & SEARCH_END)
				    ? (lnum + regmatch.endpos[0].lnum < start_pos.lnum || (lnum + regmatch.endpos[0].lnum == start_pos.lnum && (int)regmatch.endpos[0].col - 1 < (int)start_pos.col + extra_col))





				    : (lnum + regmatch.startpos[0].lnum < start_pos.lnum || (lnum + regmatch.startpos[0].lnum == start_pos.lnum && (int)regmatch.startpos[0].col < (int)start_pos.col + extra_col))))





			    {
				match_ok = TRUE;
				matchpos = regmatch.startpos[0];
				endpos = regmatch.endpos[0];

				submatch = first_submatch(&regmatch);

			    }
			    else break;

			    
			    if (vim_strchr(p_cpo, CPO_SEARCH) != NULL)
			    {
				if (nmatched > 1)
				    break;
				matchcol = endpos.col;
				
				if (matchcol == matchpos.col && ptr[matchcol] != NUL)
				{
				    if (has_mbyte)
					matchcol += (*mb_ptr2len)(ptr + matchcol);
				    else ++matchcol;
				}
			    }
			    else {
				
				if (matchpos.lnum > 0)
				    break;
				matchcol = matchpos.col;
				if (ptr[matchcol] != NUL)
				{
				    if (has_mbyte)
					matchcol += (*mb_ptr2len)(ptr + matchcol);
				    else ++matchcol;
				}
			    }
			    if (ptr[matchcol] == NUL || (nmatched = vim_regexec_multi(&regmatch, win, buf, lnum + matchpos.lnum, matchcol, timed_out)) == 0)


			    {
				
				
				
				if (*timed_out)
				    match_ok = FALSE;
				break;
			    }
			    
			    if (regmatch.regprog == NULL)
				break;

			    
			    
			    ptr = ml_get_buf(buf, lnum + matchpos.lnum, FALSE);
			}

			
			if (!match_ok)
			    continue;
		    }

		    
		    
		    
		    if ((options & SEARCH_END) && !(options & SEARCH_NOOF)
			    && !(matchpos.lnum == endpos.lnum && matchpos.col == endpos.col))
		    {
			
			
			pos->lnum = lnum + endpos.lnum;
			pos->col = endpos.col;
			if (endpos.col == 0)
			{
			    if (pos->lnum > 1)  
			    {
				--pos->lnum;
				pos->col = (colnr_T)STRLEN(ml_get_buf(buf, pos->lnum, FALSE));
			    }
			}
			else {
			    --pos->col;
			    if (has_mbyte && pos->lnum <= buf->b_ml.ml_line_count)
			    {
				ptr = ml_get_buf(buf, pos->lnum, FALSE);
				pos->col -= (*mb_head_off)(ptr, ptr + pos->col);
			    }
			}
			if (end_pos != NULL)
			{
			    end_pos->lnum = lnum + matchpos.lnum;
			    end_pos->col = matchpos.col;
			}
		    }
		    else {
			pos->lnum = lnum + matchpos.lnum;
			pos->col = matchpos.col;
			if (end_pos != NULL)
			{
			    end_pos->lnum = lnum + endpos.lnum;
			    end_pos->col = endpos.col;
			}
		    }
		    pos->coladd = 0;
		    if (end_pos != NULL)
			end_pos->coladd = 0;
		    found = 1;
		    first_match = FALSE;

		    
		    search_match_lines = endpos.lnum - matchpos.lnum;
		    search_match_endcol = endpos.col;
		    break;
		}
		line_breakcheck();	
		if (got_int)
		    break;


		
		
		
		if ((options & SEARCH_PEEK)
			&& ((lnum - pos->lnum) & 0x3f) == 0 && char_avail())
		{
		    break_loop = TRUE;
		    break;
		}


		if (loop && lnum == start_pos.lnum)
		    break;	    
	    }
	    at_first_line = FALSE;

	    
	    if (regmatch.regprog == NULL)
		break;

	    
	    if (!p_ws || stop_lnum != 0 || got_int || called_emsg > called_emsg_before || *timed_out  || break_loop  || found || loop)




		break;

	    
	    if (dir == BACKWARD)    
		lnum = buf->b_ml.ml_line_count;
	    else lnum = 1;
	    if (!shortmess(SHM_SEARCH) && (options & SEARCH_MSG))
		give_warning((char_u *)_(dir == BACKWARD ? top_bot_msg : bot_top_msg), TRUE);
	    if (extra_arg != NULL)
		extra_arg->sa_wrapped = TRUE;
	}
	if (got_int || called_emsg > called_emsg_before || *timed_out  || break_loop  )



	    break;
    }
    while (--count > 0 && found);   


    if (extra_arg != NULL && extra_arg->sa_tm > 0)
	disable_regexp_timeout();

    vim_regfree(regmatch.regprog);

    if (!found)		    
    {
	if (got_int)
	    emsg(_(e_interrupted));
	else if ((options & SEARCH_MSG) == SEARCH_MSG)
	{
	    if (p_ws)
		semsg(_(e_pattern_not_found_str), mr_pattern);
	    else if (lnum == 0)
		semsg(_(e_search_hit_top_without_match_for_str), mr_pattern);
	    else semsg(_(e_search_hit_bottom_without_match_for_str), mr_pattern);
	}
	return FAIL;
    }

    
    if (pos->lnum > buf->b_ml.ml_line_count)
    {
	pos->lnum = buf->b_ml.ml_line_count;
	pos->col = (int)STRLEN(ml_get_buf(buf, pos->lnum, FALSE));
	if (pos->col > 0)
	    --pos->col;
    }

    return submatch + 1;
}


    void set_search_direction(int cdir)
{
    spats[0].off.dir = cdir;
}

    static void set_vv_searchforward(void)
{
    set_vim_var_nr(VV_SEARCHFORWARD, (long)(spats[0].off.dir == '/'));
}


    static int first_submatch(regmmatch_T *rp)
{
    int		submatch;

    for (submatch = 1; ; ++submatch)
    {
	if (rp->startpos[submatch].lnum >= 0)
	    break;
	if (submatch == 9)
	{
	    submatch = 0;
	    break;
	}
    }
    return submatch;
}



    int do_search( oparg_T	    *oap, int		    dirc, int		    search_delim,  char_u	    *pat, long	    count, int		    options, searchit_arg_T  *sia)








{
    pos_T	    pos;	
    char_u	    *searchstr;
    soffset_T	    old_off;
    int		    retval;	
    char_u	    *p;
    long	    c;
    char_u	    *dircp;
    char_u	    *strcopy = NULL;
    char_u	    *ps;
    char_u	    *msgbuf = NULL;
    size_t	    len;
    int		    has_offset = FALSE;

    
    if (spats[0].off.line && vim_strchr(p_cpo, CPO_LINEOFF) != NULL)
    {
	spats[0].off.line = FALSE;
	spats[0].off.off = 0;
    }

    
    old_off = spats[0].off;

    pos = curwin->w_cursor;	

    
    if (dirc == 0)
	dirc = spats[0].off.dir;
    else {
	spats[0].off.dir = dirc;

	set_vv_searchforward();

    }
    if (options & SEARCH_REV)
    {

	
	
	dirc = (dirc == '/')  ?  '?'  :  '/';

	if (dirc == '/')
	    dirc = '?';
	else dirc = '/';

    }


    
    
    if (dirc == '/')
    {
	if (hasFolding(pos.lnum, NULL, &pos.lnum))
	    pos.col = MAXCOL - 2;	
    }
    else {
	if (hasFolding(pos.lnum, &pos.lnum, NULL))
	    pos.col = 0;
    }



    
    if (no_hlsearch && !(options & SEARCH_KEEP))
    {
	redraw_all_later(UPD_SOME_VALID);
	set_no_hlsearch(FALSE);
    }


    
    for (;;)
    {
	int		show_top_bot_msg = FALSE;

	searchstr = pat;
	dircp = NULL;
					    
	if (pat == NULL || *pat == NUL || *pat == search_delim)
	{
	    if (spats[RE_SEARCH].pat == NULL)	    
	    {
		searchstr = spats[RE_SUBST].pat;
		if (searchstr == NULL)
		{
		    emsg(_(e_no_previous_regular_expression));
		    retval = 0;
		    goto end_do_search;
		}
	    }
	    else {
		
		searchstr = (char_u *)"";
	    }
	}

	if (pat != NULL && *pat != NUL)	
	{
	    
	    ps = strcopy;
	    p = skip_regexp_ex(pat, search_delim, magic_isset(), &strcopy, NULL, NULL);
	    if (strcopy != ps)
	    {
		
		searchcmdlen += (int)(STRLEN(pat) - STRLEN(strcopy));
		pat = strcopy;
		searchstr = strcopy;
	    }
	    if (*p == search_delim)
	    {
		dircp = p;	
		*p++ = NUL;
	    }
	    spats[0].off.line = FALSE;
	    spats[0].off.end = FALSE;
	    spats[0].off.off = 0;
	    
	    if (*p == '+' || *p == '-' || VIM_ISDIGIT(*p))
		spats[0].off.line = TRUE;
	    else if ((options & SEARCH_OPT)
				      && (*p == 'e' || *p == 's' || *p == 'b'))
	    {
		if (*p == 'e')		
		    spats[0].off.end = SEARCH_END;
		++p;
	    }
	    if (VIM_ISDIGIT(*p) || *p == '+' || *p == '-')  
	    {
					    
		if (VIM_ISDIGIT(*p) || VIM_ISDIGIT(*(p + 1)))
		    spats[0].off.off = atol((char *)p);
		else if (*p == '-')	    
		    spats[0].off.off = -1;
		else			     spats[0].off.off = 1;
		++p;
		while (VIM_ISDIGIT(*p))	    
		    ++p;
	    }

	    
	    searchcmdlen += (int)(p - pat);

	    pat = p;			    
	}

	if ((options & SEARCH_ECHO) && messaging()
		&& !msg_silent && (!cmd_silent || !shortmess(SHM_SEARCHCOUNT)))
	{
	    char_u	*trunc;
	    char_u	off_buf[40];
	    size_t	off_len = 0;

	    
	    msg_start();

	    
	    if (!cmd_silent && (spats[0].off.line || spats[0].off.end || spats[0].off.off))
	    {
		p = off_buf;
		*p++ = dirc;
		if (spats[0].off.end)
		    *p++ = 'e';
		else if (!spats[0].off.line)
		    *p++ = 's';
		if (spats[0].off.off > 0 || spats[0].off.line)
		    *p++ = '+';
		*p = NUL;
		if (spats[0].off.off != 0 || spats[0].off.line)
		    sprintf((char *)p, "%ld", spats[0].off.off);
		off_len = STRLEN(off_buf);
	    }

	    if (*searchstr == NUL)
		p = spats[0].pat;
	    else p = searchstr;

	    if (!shortmess(SHM_SEARCHCOUNT) || cmd_silent)
	    {
		
		
		
		
		if (msg_scrolled != 0 && !cmd_silent)
		    
		    len = (int)(Rows - msg_row) * Columns - 1;
		else  len = (int)(Rows - msg_row - 1) * Columns + sc_col - 1;

		if (len < STRLEN(p) + off_len + SEARCH_STAT_BUF_LEN + 3)
		    len = STRLEN(p) + off_len + SEARCH_STAT_BUF_LEN + 3;
	    }
	    else  len = STRLEN(p) + off_len + 3;


	    vim_free(msgbuf);
	    msgbuf = alloc(len);
	    if (msgbuf != NULL)
	    {
		vim_memset(msgbuf, ' ', len);
		msgbuf[len - 1] = NUL;
		
		
		if (!cmd_silent)
		{
		    msgbuf[0] = dirc;

		    if (enc_utf8 && utf_iscomposing(utf_ptr2char(p)))
		    {
			
			msgbuf[1] = ' ';
			mch_memmove(msgbuf + 2, p, STRLEN(p));
		    }
		    else mch_memmove(msgbuf + 1, p, STRLEN(p));
		    if (off_len > 0)
			mch_memmove(msgbuf + STRLEN(p) + 1, off_buf, off_len);

		    trunc = msg_strtrunc(msgbuf, TRUE);
		    if (trunc != NULL)
		    {
			vim_free(msgbuf);
			msgbuf = trunc;
		    }


		    
		    
		    
		    
		    if (curwin->w_p_rl && *curwin->w_p_rlc == 's')
		    {
			char_u *r;
			size_t pat_len;

			r = reverse_text(msgbuf);
			if (r != NULL)
			{
			    vim_free(msgbuf);
			    msgbuf = r;
			    
			    while (*r != NUL && *r == ' ')
				r++;
			    pat_len = msgbuf + STRLEN(msgbuf) - r;
			    mch_memmove(msgbuf, r, pat_len);
			    
			    if ((size_t)(r - msgbuf) >= pat_len)
				vim_memset(r, ' ', pat_len);
			    else vim_memset(msgbuf + pat_len, ' ', r - msgbuf);
			}
		    }

		    msg_outtrans(msgbuf);
		    msg_clr_eos();
		    msg_check();

		    gotocmdline(FALSE);
		    out_flush();
		    msg_nowait = TRUE;	    
		}
	    }
	}

	
	if (!spats[0].off.line && spats[0].off.off && pos.col < MAXCOL - 2)
	{
	    if (spats[0].off.off > 0)
	    {
		for (c = spats[0].off.off; c; --c)
		    if (decl(&pos) == -1)
			break;
		if (c)			
		{
		    pos.lnum = 0;	
		    pos.col = MAXCOL;
		}
	    }
	    else {
		for (c = spats[0].off.off; c; ++c)
		    if (incl(&pos) == -1)
			break;
		if (c)			
		{
		    pos.lnum = curbuf->b_ml.ml_line_count + 1;
		    pos.col = 0;
		}
	    }
	}

	
	c = searchit(curwin, curbuf, &pos, NULL, dirc == '/' ? FORWARD : BACKWARD, searchstr, count, spats[0].off.end + (options & (SEARCH_KEEP + SEARCH_PEEK + SEARCH_HIS + SEARCH_MSG + SEARCH_START + ((pat != NULL && *pat == ';') ? 0 : SEARCH_NOOF))), RE_LAST, sia);






	if (dircp != NULL)
	    *dircp = search_delim; 

	if (!shortmess(SHM_SEARCH)
		&& ((dirc == '/' && LT_POS(pos, curwin->w_cursor))
			    || (dirc == '?' && LT_POS(curwin->w_cursor, pos))))
	    show_top_bot_msg = TRUE;

	if (c == FAIL)
	{
	    retval = 0;
	    goto end_do_search;
	}
	if (spats[0].off.end && oap != NULL)
	    oap->inclusive = TRUE;  

	retval = 1;		    

	
	if (!(options & SEARCH_NOOF) || (pat != NULL && *pat == ';'))
	{
	    pos_T org_pos = pos;

	    if (spats[0].off.line)	
	    {
		c = pos.lnum + spats[0].off.off;
		if (c < 1)
		    pos.lnum = 1;
		else if (c > curbuf->b_ml.ml_line_count)
		    pos.lnum = curbuf->b_ml.ml_line_count;
		else pos.lnum = c;
		pos.col = 0;

		retval = 2;	    
	    }
	    else if (pos.col < MAXCOL - 2)	
	    {
		
		c = spats[0].off.off;
		if (c > 0)
		{
		    while (c-- > 0)
			if (incl(&pos) == -1)
			    break;
		}
		
		else {
		    while (c++ < 0)
			if (decl(&pos) == -1)
			    break;
		}
	    }
	    if (!EQUAL_POS(pos, org_pos))
		has_offset = TRUE;
	}

	
	if ((options & SEARCH_ECHO)
		&& messaging()
		&& !msg_silent && c != FAIL && !shortmess(SHM_SEARCHCOUNT)

		&& msgbuf != NULL)
	     cmdline_search_stat(dirc, &pos, &curwin->w_cursor, show_top_bot_msg, msgbuf, (count != 1 || has_offset  || (!(fdo_flags & FDO_SEARCH)



				     && hasFolding(curwin->w_cursor.lnum, NULL, NULL))

				), SEARCH_STAT_DEF_MAX_COUNT, SEARCH_STAT_DEF_TIMEOUT);


	
	if (!(options & SEARCH_OPT) || pat == NULL || *pat != ';')
	    break;

	dirc = *++pat;
	search_delim = dirc;
	if (dirc != '?' && dirc != '/')
	{
	    retval = 0;
	    emsg(_(e_expected_question_or_slash_after_semicolon));
	    goto end_do_search;
	}
	++pat;
    }

    if (options & SEARCH_MARK)
	setpcmark();
    curwin->w_cursor = pos;
    curwin->w_set_curswant = TRUE;

end_do_search:
    if ((options & SEARCH_KEEP) || (cmdmod.cmod_flags & CMOD_KEEPPATTERNS))
	spats[0].off = old_off;
    vim_free(strcopy);
    vim_free(msgbuf);

    return retval;
}


    int search_for_exact_line( buf_T	*buf, pos_T	*pos, int		dir, char_u	*pat)




{
    linenr_T	start = 0;
    char_u	*ptr;
    char_u	*p;

    if (buf->b_ml.ml_line_count == 0)
	return FAIL;
    for (;;)
    {
	pos->lnum += dir;
	if (pos->lnum < 1)
	{
	    if (p_ws)
	    {
		pos->lnum = buf->b_ml.ml_line_count;
		if (!shortmess(SHM_SEARCH))
		    give_warning((char_u *)_(top_bot_msg), TRUE);
	    }
	    else {
		pos->lnum = 1;
		break;
	    }
	}
	else if (pos->lnum > buf->b_ml.ml_line_count)
	{
	    if (p_ws)
	    {
		pos->lnum = 1;
		if (!shortmess(SHM_SEARCH))
		    give_warning((char_u *)_(bot_top_msg), TRUE);
	    }
	    else {
		pos->lnum = 1;
		break;
	    }
	}
	if (pos->lnum == start)
	    break;
	if (start == 0)
	    start = pos->lnum;
	ptr = ml_get_buf(buf, pos->lnum, FALSE);
	p = skipwhite(ptr);
	pos->col = (colnr_T) (p - ptr);

	
	
	if (compl_status_adding() && !compl_status_sol())
	{
	    if ((p_ic ? MB_STRICMP(p, pat) : STRCMP(p, pat)) == 0)
		return OK;
	}
	else if (*p != NUL)	
	{	
	    if ((p_ic ? MB_STRNICMP(p, pat, ins_compl_len())
				   : STRNCMP(p, pat, ins_compl_len())) == 0)
		return OK;
	}
    }
    return FAIL;
}




    int searchc(cmdarg_T *cap, int t_cmd)
{
    int			c = cap->nchar;	
    int			dir = cap->arg;	
    long		count = cap->count1;	
    int			col;
    char_u		*p;
    int			len;
    int			stop = TRUE;

    if (c != NUL)	
    {
	if (!KeyStuffed)    
	{
	    *lastc = c;
	    set_csearch_direction(dir);
	    set_csearch_until(t_cmd);
	    lastc_bytelen = (*mb_char2bytes)(c, lastc_bytes);
	    if (cap->ncharC1 != 0)
	    {
		lastc_bytelen += (*mb_char2bytes)(cap->ncharC1, lastc_bytes + lastc_bytelen);
		if (cap->ncharC2 != 0)
		    lastc_bytelen += (*mb_char2bytes)(cap->ncharC2, lastc_bytes + lastc_bytelen);
	    }
	}
    }
    else		 {
	if (*lastc == NUL && lastc_bytelen == 1)
	    return FAIL;
	if (dir)	
	    dir = -lastcdir;
	else dir = lastcdir;
	t_cmd = last_t_cmd;
	c = *lastc;
	

	
	
	
	if (vim_strchr(p_cpo, CPO_SCOLON) == NULL && count == 1 && t_cmd)
	    stop = FALSE;
    }

    if (dir == BACKWARD)
	cap->oap->inclusive = FALSE;
    else cap->oap->inclusive = TRUE;

    p = ml_get_curline();
    col = curwin->w_cursor.col;
    len = (int)STRLEN(p);

    while (count--)
    {
	if (has_mbyte)
	{
	    for (;;)
	    {
		if (dir > 0)
		{
		    col += (*mb_ptr2len)(p + col);
		    if (col >= len)
			return FAIL;
		}
		else {
		    if (col == 0)
			return FAIL;
		    col -= (*mb_head_off)(p, p + col - 1) + 1;
		}
		if (lastc_bytelen == 1)
		{
		    if (p[col] == c && stop)
			break;
		}
		else if (STRNCMP(p + col, lastc_bytes, lastc_bytelen) == 0 && stop)
		    break;
		stop = TRUE;
	    }
	}
	else {
	    for (;;)
	    {
		if ((col += dir) < 0 || col >= len)
		    return FAIL;
		if (p[col] == c && stop)
		    break;
		stop = TRUE;
	    }
	}
    }

    if (t_cmd)
    {
	
	col -= dir;
	if (has_mbyte)
	{
	    if (dir < 0)
		
		col += lastc_bytelen - 1;
	    else  col -= (*mb_head_off)(p, p + col);

	}
    }
    curwin->w_cursor.col = col;

    return OK;
}




    pos_T * findmatch(oparg_T *oap, int initc)
{
    return findmatchlimit(oap, initc, 0, 0);
}


    static int check_prevcol( char_u	*linep, int		col, int		ch, int		*prevcol)




{
    --col;
    if (col > 0 && has_mbyte)
	col -= (*mb_head_off)(linep, linep + col);
    if (prevcol)
	*prevcol = col;
    return (col >= 0 && linep[col] == ch) ? TRUE : FALSE;
}


    static int find_rawstring_end(char_u *linep, pos_T *startpos, pos_T *endpos)
{
    char_u	*p;
    char_u	*delim_copy;
    size_t	delim_len;
    linenr_T	lnum;
    int		found = FALSE;

    for (p = linep + startpos->col + 1; *p && *p != '('; ++p)
	;
    delim_len = (p - linep) - startpos->col - 1;
    delim_copy = vim_strnsave(linep + startpos->col + 1, delim_len);
    if (delim_copy == NULL)
	return FALSE;
    for (lnum = startpos->lnum; lnum <= endpos->lnum; ++lnum)
    {
	char_u *line = ml_get(lnum);

	for (p = line + (lnum == startpos->lnum ? startpos->col + 1 : 0); *p; ++p)
	{
	    if (lnum == endpos->lnum && (colnr_T)(p - line) >= endpos->col)
		break;
	    if (*p == ')' && STRNCMP(delim_copy, p + 1, delim_len) == 0 && p[delim_len + 1] == '"')
	    {
		found = TRUE;
		break;
	    }
	}
	if (found)
	    break;
    }
    vim_free(delim_copy);
    return found;
}


    static void find_mps_values( int	    *initc, int	    *findc, int	    *backwards, int	    switchit)




{
    char_u	*ptr;

    ptr = curbuf->b_p_mps;
    while (*ptr != NUL)
    {
	if (has_mbyte)
	{
	    char_u *prev;

	    if (mb_ptr2char(ptr) == *initc)
	    {
		if (switchit)
		{
		    *findc = *initc;
		    *initc = mb_ptr2char(ptr + mb_ptr2len(ptr) + 1);
		    *backwards = TRUE;
		}
		else {
		    *findc = mb_ptr2char(ptr + mb_ptr2len(ptr) + 1);
		    *backwards = FALSE;
		}
		return;
	    }
	    prev = ptr;
	    ptr += mb_ptr2len(ptr) + 1;
	    if (mb_ptr2char(ptr) == *initc)
	    {
		if (switchit)
		{
		    *findc = *initc;
		    *initc = mb_ptr2char(prev);
		    *backwards = FALSE;
		}
		else {
		    *findc = mb_ptr2char(prev);
		    *backwards = TRUE;
		}
		return;
	    }
	    ptr += mb_ptr2len(ptr);
	}
	else {
	    if (*ptr == *initc)
	    {
		if (switchit)
		{
		    *backwards = TRUE;
		    *findc = *initc;
		    *initc = ptr[2];
		}
		else {
		    *backwards = FALSE;
		    *findc = ptr[2];
		}
		return;
	    }
	    ptr += 2;
	    if (*ptr == *initc)
	    {
		if (switchit)
		{
		    *backwards = FALSE;
		    *findc = *initc;
		    *initc = ptr[-2];
		}
		else {
		    *backwards = TRUE;
		    *findc =  ptr[-2];
		}
		return;
	    }
	    ++ptr;
	}
	if (*ptr == ',')
	    ++ptr;
    }
}


    pos_T * findmatchlimit( oparg_T	*oap, int		initc, int		flags, int		maxtravel)




{
    static pos_T pos;			
    int		findc = 0;		
    int		c;
    int		count = 0;		
    int		backwards = FALSE;	
    int		raw_string = FALSE;	
    int		inquote = FALSE;	
    char_u	*linep;			
    char_u	*ptr;
    int		do_quotes;		
    int		at_start;		
    int		hash_dir = 0;		
    int		comment_dir = 0;	
    pos_T	match_pos;		
    int		start_in_quotes;	
    int		traveled = 0;		
    int		ignore_cend = FALSE;    
    int		cpo_match;		
    int		cpo_bsl;		
    int		match_escaped = 0;	
    int		dir;			
    int		comment_col = MAXCOL;   
    int		lispcomm = FALSE;	
    int		lisp = curbuf->b_p_lisp; 

    pos = curwin->w_cursor;
    pos.coladd = 0;
    linep = ml_get(pos.lnum);

    cpo_match = (vim_strchr(p_cpo, CPO_MATCH) != NULL);
    cpo_bsl = (vim_strchr(p_cpo, CPO_MATCHBSL) != NULL);

    
    if (flags & FM_BACKWARD)
	dir = BACKWARD;
    else if (flags & FM_FORWARD)
	dir = FORWARD;
    else dir = 0;

    
    if (initc == '/' || initc == '*' || initc == 'R')
    {
	comment_dir = dir;
	if (initc == '/')
	    ignore_cend = TRUE;
	backwards = (dir == FORWARD) ? FALSE : TRUE;
	raw_string = (initc == 'R');
	initc = NUL;
    }
    else if (initc != '#' && initc != NUL)
    {
	find_mps_values(&initc, &findc, &backwards, TRUE);
	if (dir)
	    backwards = (dir == FORWARD) ? FALSE : TRUE;
	if (findc == NUL)
	    return NULL;
    }
    else {
	
	if (initc == '#')
	{
	    hash_dir = dir;
	}
	else {
	    
	    if (!cpo_match)
	    {
		
		ptr = skipwhite(linep);
		if (*ptr == '#' && pos.col <= (colnr_T)(ptr - linep))
		{
		    ptr = skipwhite(ptr + 1);
		    if (   STRNCMP(ptr, "if", 2) == 0 || STRNCMP(ptr, "endif", 5) == 0 || STRNCMP(ptr, "el", 2) == 0)

			hash_dir = 1;
		}

		
		else if (linep[pos.col] == '/')
		{
		    if (linep[pos.col + 1] == '*')
		    {
			comment_dir = FORWARD;
			backwards = FALSE;
			pos.col++;
		    }
		    else if (pos.col > 0 && linep[pos.col - 1] == '*')
		    {
			comment_dir = BACKWARD;
			backwards = TRUE;
			pos.col--;
		    }
		}
		else if (linep[pos.col] == '*')
		{
		    if (linep[pos.col + 1] == '/')
		    {
			comment_dir = BACKWARD;
			backwards = TRUE;
		    }
		    else if (pos.col > 0 && linep[pos.col - 1] == '/')
		    {
			comment_dir = FORWARD;
			backwards = FALSE;
		    }
		}
	    }

	    
	    if (!hash_dir && !comment_dir)
	    {
		
		if (linep[pos.col] == NUL && pos.col)
		    --pos.col;
		for (;;)
		{
		    initc = PTR2CHAR(linep + pos.col);
		    if (initc == NUL)
			break;

		    find_mps_values(&initc, &findc, &backwards, FALSE);
		    if (findc)
			break;
		    pos.col += mb_ptr2len(linep + pos.col);
		}
		if (!findc)
		{
		    
		    if (!cpo_match && *skipwhite(linep) == '#')
			hash_dir = 1;
		    else return NULL;
		}
		else if (!cpo_bsl)
		{
		    int col, bslcnt = 0;

		    
		    
		    for (col = pos.col; check_prevcol(linep, col, '\\', &col);)
			bslcnt++;
		    match_escaped = (bslcnt & 1);
		}
	    }
	}
	if (hash_dir)
	{
	    
	    if (oap != NULL)
		oap->motion_type = MLINE;   
	    if (initc != '#')
	    {
		ptr = skipwhite(skipwhite(linep) + 1);
		if (STRNCMP(ptr, "if", 2) == 0 || STRNCMP(ptr, "el", 2) == 0)
		    hash_dir = 1;
		else if (STRNCMP(ptr, "endif", 5) == 0)
		    hash_dir = -1;
		else return NULL;
	    }
	    pos.col = 0;
	    while (!got_int)
	    {
		if (hash_dir > 0)
		{
		    if (pos.lnum == curbuf->b_ml.ml_line_count)
			break;
		}
		else if (pos.lnum == 1)
		    break;
		pos.lnum += hash_dir;
		linep = ml_get(pos.lnum);
		line_breakcheck();	
		ptr = skipwhite(linep);
		if (*ptr != '#')
		    continue;
		pos.col = (colnr_T) (ptr - linep);
		ptr = skipwhite(ptr + 1);
		if (hash_dir > 0)
		{
		    if (STRNCMP(ptr, "if", 2) == 0)
			count++;
		    else if (STRNCMP(ptr, "el", 2) == 0)
		    {
			if (count == 0)
			    return &pos;
		    }
		    else if (STRNCMP(ptr, "endif", 5) == 0)
		    {
			if (count == 0)
			    return &pos;
			count--;
		    }
		}
		else {
		    if (STRNCMP(ptr, "if", 2) == 0)
		    {
			if (count == 0)
			    return &pos;
			count--;
		    }
		    else if (initc == '#' && STRNCMP(ptr, "el", 2) == 0)
		    {
			if (count == 0)
			    return &pos;
		    }
		    else if (STRNCMP(ptr, "endif", 5) == 0)
			count++;
		}
	    }
	    return NULL;
	}
    }


    
    
    if (curwin->w_p_rl && vim_strchr((char_u *)"()[]{}<>", initc) != NULL)
	backwards = !backwards;


    do_quotes = -1;
    start_in_quotes = MAYBE;
    CLEAR_POS(&match_pos);

    
    if ((backwards && comment_dir) || lisp)
	comment_col = check_linecomment(linep);
    if (lisp && comment_col != MAXCOL && pos.col > (colnr_T)comment_col)
	lispcomm = TRUE;    

    while (!got_int)
    {
	
	if (backwards)
	{
	    
	    if (lispcomm && pos.col < (colnr_T)comment_col)
		break;
	    if (pos.col == 0)		
	    {
		if (pos.lnum == 1)	
		    break;
		--pos.lnum;

		if (maxtravel > 0 && ++traveled > maxtravel)
		    break;

		linep = ml_get(pos.lnum);
		pos.col = (colnr_T)STRLEN(linep); 
		do_quotes = -1;
		line_breakcheck();

		
		if (comment_dir || lisp)
		    comment_col = check_linecomment(linep);
		
		if (lisp && comment_col != MAXCOL)
		    pos.col = comment_col;
	    }
	    else {
		--pos.col;
		if (has_mbyte)
		    pos.col -= (*mb_head_off)(linep, linep + pos.col);
	    }
	}
	else				 {
	    if (linep[pos.col] == NUL   || (lisp && comment_col != MAXCOL && pos.col == (colnr_T)comment_col))



	    {
		if (pos.lnum == curbuf->b_ml.ml_line_count     || lispcomm)


		    break;
		++pos.lnum;

		if (maxtravel && traveled++ > maxtravel)
		    break;

		linep = ml_get(pos.lnum);
		pos.col = 0;
		do_quotes = -1;
		line_breakcheck();
		if (lisp)   
		    comment_col = check_linecomment(linep);
	    }
	    else {
		if (has_mbyte)
		    pos.col += (*mb_ptr2len)(linep + pos.col);
		else ++pos.col;
	    }
	}

	
	if (pos.col == 0 && (flags & FM_BLOCKSTOP)
				       && (linep[0] == '{' || linep[0] == '}'))
	{
	    if (linep[0] == findc && count == 0)	
		return &pos;
	    break;					
	}

	if (comment_dir)
	{
	    
	    
	    if (comment_dir == FORWARD)
	    {
		if (linep[pos.col] == '*' && linep[pos.col + 1] == '/')
		{
		    pos.col++;
		    return &pos;
		}
	    }
	    else     {
		
		if (pos.col == 0)
		    continue;
		else if (raw_string)
		{
		    if (linep[pos.col - 1] == 'R' && linep[pos.col] == '"' && vim_strchr(linep + pos.col + 1, '(') != NULL)

		    {
			
			
			
			
			if (!find_rawstring_end(linep, &pos, count > 0 ? &match_pos : &curwin->w_cursor))
			{
			    count++;
			    match_pos = pos;
			    match_pos.col--;
			}
			linep = ml_get(pos.lnum); 
		    }
		}
		else if (  linep[pos.col - 1] == '/' && linep[pos.col] == '*' && (pos.col == 1 || linep[pos.col - 2] != '*')

			&& (int)pos.col < comment_col)
		{
		    count++;
		    match_pos = pos;
		    match_pos.col--;
		}
		else if (linep[pos.col - 1] == '*' && linep[pos.col] == '/')
		{
		    if (count > 0)
			pos = match_pos;
		    else if (pos.col > 1 && linep[pos.col - 2] == '/' && (int)pos.col <= comment_col)
			pos.col -= 2;
		    else if (ignore_cend)
			continue;
		    else return NULL;
		    return &pos;
		}
	    }
	    continue;
	}

	
	if (cpo_match)
	    do_quotes = 0;
	else if (do_quotes == -1)
	{
	    
	    at_start = do_quotes;
	    for (ptr = linep; *ptr; ++ptr)
	    {
		if (ptr == linep + pos.col + backwards)
		    at_start = (do_quotes & 1);
		if (*ptr == '"' && (ptr == linep || ptr[-1] != '\'' || ptr[1] != '\''))
		    ++do_quotes;
		if (*ptr == '\\' && ptr[1] != NUL)
		    ++ptr;
	    }
	    do_quotes &= 1;	    

	    
	    if (!do_quotes)
	    {
		inquote = FALSE;
		if (ptr[-1] == '\\')
		{
		    do_quotes = 1;
		    if (start_in_quotes == MAYBE)
		    {
			
			inquote = TRUE;
			start_in_quotes = TRUE;
		    }
		    else if (backwards)
			inquote = TRUE;
		}
		if (pos.lnum > 1)
		{
		    ptr = ml_get(pos.lnum - 1);
		    if (*ptr && *(ptr + STRLEN(ptr) - 1) == '\\')
		    {
			do_quotes = 1;
			if (start_in_quotes == MAYBE)
			{
			    inquote = at_start;
			    if (inquote)
				start_in_quotes = TRUE;
			}
			else if (!backwards)
			    inquote = TRUE;
		    }

		    
		    linep = ml_get(pos.lnum);
		}
	    }
	}
	if (start_in_quotes == MAYBE)
	    start_in_quotes = FALSE;

	
	c = PTR2CHAR(linep + pos.col);
	switch (c)
	{
	case NUL:
	    
	    if (pos.col == 0 || linep[pos.col - 1] != '\\')
	    {
		inquote = FALSE;
		start_in_quotes = FALSE;
	    }
	    break;

	case '"':
	    
	    
	    if (do_quotes)
	    {
		int col;

		for (col = pos.col - 1; col >= 0; --col)
		    if (linep[col] != '\\')
			break;
		if ((((int)pos.col - 1 - col) & 1) == 0)
		{
		    inquote = !inquote;
		    start_in_quotes = FALSE;
		}
	    }
	    break;

	
	case '\'':
	    if (!cpo_match && initc != '\'' && findc != '\'')
	    {
		if (backwards)
		{
		    if (pos.col > 1)
		    {
			if (linep[pos.col - 2] == '\'')
			{
			    pos.col -= 2;
			    break;
			}
			else if (linep[pos.col - 2] == '\\' && pos.col > 2 && linep[pos.col - 3] == '\'')
			{
			    pos.col -= 3;
			    break;
			}
		    }
		}
		else if (linep[pos.col + 1])	
		{
		    if (linep[pos.col + 1] == '\\' && linep[pos.col + 2] && linep[pos.col + 3] == '\'')
		    {
			pos.col += 3;
			break;
		    }
		    else if (linep[pos.col + 2] == '\'')
		    {
			pos.col += 2;
			break;
		    }
		}
	    }
	    

	default:
	    
	    if (curbuf->b_p_lisp && vim_strchr((char_u *)"{}()[]", c) != NULL && pos.col > 1 && check_prevcol(linep, pos.col, '\\', NULL)


		    && check_prevcol(linep, pos.col - 1, '#', NULL))
		break;

	    
	    
	    if ((!inquote || start_in_quotes == TRUE)
		    && (c == initc || c == findc))
	    {
		int	col, bslcnt = 0;

		if (!cpo_bsl)
		{
		    for (col = pos.col; check_prevcol(linep, col, '\\', &col);)
			bslcnt++;
		}
		
		
		if (cpo_bsl || (bslcnt & 1) == match_escaped)
		{
		    if (c == initc)
			count++;
		    else {
			if (count == 0)
			    return &pos;
			count--;
		    }
		}
	    }
	}
    }

    if (comment_dir == BACKWARD && count > 0)
    {
	pos = match_pos;
	return &pos;
    }
    return (pos_T *)NULL;	
}


    int check_linecomment(char_u *line)
{
    char_u  *p;

    p = line;
    
    if (curbuf->b_p_lisp)
    {
	if (vim_strchr(p, ';') != NULL) 
	{
	    int in_str = FALSE;	

	    p = line;		
	    while ((p = vim_strpbrk(p, (char_u *)"\";")) != NULL)
	    {
		if (*p == '"')
		{
		    if (in_str)
		    {
			if (*(p - 1) != '\\') 
			    in_str = FALSE;
		    }
		    else if (p == line || ((p - line) >= 2  && *(p - 1) != '\\' && *(p - 2) != '#'))

			in_str = TRUE;
		}
		else if (!in_str && ((p - line) < 2 || (*(p - 1) != '\\' && *(p - 2) != '#'))
			       && !is_pos_in_string(line, (colnr_T)(p - line)))
		    break;	
		++p;
	    }
	}
	else p = NULL;
    }
    else while ((p = vim_strchr(p, '/')) != NULL)
	{
	    
	    
	    
	    if (p[1] == '/' && (p == line || p[-1] != '*' || p[2] != '*')
			       && !is_pos_in_string(line, (colnr_T)(p - line)))
		break;
	    ++p;
	}

    if (p == NULL)
	return MAXCOL;
    return (int)(p - line);
}


    void showmatch( int		c)

{
    pos_T	*lpos, save_cursor;
    pos_T	mpos;
    colnr_T	vcol;
    long	save_so;
    long	save_siso;

    int		save_state;

    colnr_T	save_dollar_vcol;
    char_u	*p;
    long	*so = curwin->w_p_so >= 0 ? &curwin->w_p_so : &p_so;
    long	*siso = curwin->w_p_siso >= 0 ? &curwin->w_p_siso : &p_siso;

    
    
    for (p = curbuf->b_p_mps; *p != NUL; ++p)
    {

	if (PTR2CHAR(p) == c && (curwin->w_p_rl ^ p_ri))
	    break;

	p += mb_ptr2len(p) + 1;
	if (PTR2CHAR(p) == c  && !(curwin->w_p_rl ^ p_ri)


	   )
	    break;
	p += mb_ptr2len(p);
	if (*p == NUL)
	    return;
    }
    if (*p == NUL)
	return;

    if ((lpos = findmatch(NULL, NUL)) == NULL)	    
    {
	vim_beep(BO_MATCH);
	return;
    }

    if (lpos->lnum < curwin->w_topline || lpos->lnum >= curwin->w_botline)
	return;

    if (!curwin->w_p_wrap)
	getvcol(curwin, lpos, NULL, &vcol, NULL);

    int col_visible = (curwin->w_p_wrap || (vcol >= curwin->w_leftcol && vcol < curwin->w_leftcol + curwin->w_width));

    if (!col_visible)
	return;

    mpos = *lpos;    
    save_cursor = curwin->w_cursor;
    save_so = *so;
    save_siso = *siso;
    
    
    if (dollar_vcol >= 0 && dollar_vcol == curwin->w_virtcol)
	dollar_vcol = -1;
    ++curwin->w_virtcol;	
    update_screen(UPD_VALID);	

    save_dollar_vcol = dollar_vcol;

    save_state = State;
    State = MODE_SHOWMATCH;
    ui_cursor_shape();		

    curwin->w_cursor = mpos;	
    *so = 0;			
    *siso = 0;			
    showruler(FALSE);
    setcursor();
    cursor_on();		
    out_flush_cursor(TRUE, FALSE);

    
    
    
    dollar_vcol = save_dollar_vcol;

    
    if (vim_strchr(p_cpo, CPO_SHOWMATCH) != NULL)
	ui_delay(p_mat * 100L + 8, TRUE);
    else if (!char_avail())
	ui_delay(p_mat * 100L + 9, FALSE);
    curwin->w_cursor = save_cursor;	
    *so = save_so;
    *siso = save_siso;

    State = save_state;
    ui_cursor_shape();		

}


    static int is_zero_width(char_u *pattern, int move, pos_T *cur, int direction)
{
    regmmatch_T	regmatch;
    int		nmatched = 0;
    int		result = -1;
    pos_T	pos;
    int		called_emsg_before = called_emsg;
    int		flag = 0;

    if (pattern == NULL)
	pattern = spats[last_idx].pat;

    if (search_regcomp(pattern, NULL, RE_SEARCH, RE_SEARCH, SEARCH_KEEP, &regmatch) == FAIL)
	return -1;

    
    regmatch.startpos[0].col = -1;
    
    if (move)
    {
	CLEAR_POS(&pos);
    }
    else {
	pos = *cur;
	
	flag = SEARCH_START;
    }

    if (searchit(curwin, curbuf, &pos, NULL, direction, pattern, 1, SEARCH_KEEP + flag, RE_SEARCH, NULL) != FAIL)
    {
	
	
	do {
	    regmatch.startpos[0].col++;
	    nmatched = vim_regexec_multi(&regmatch, curwin, curbuf, pos.lnum, regmatch.startpos[0].col, NULL);
	    if (nmatched != 0)
		break;
	} while (regmatch.regprog != NULL && direction == FORWARD ? regmatch.startpos[0].col < pos.col : regmatch.startpos[0].col > pos.col);


	if (called_emsg == called_emsg_before)
	{
	    result = (nmatched != 0 && regmatch.startpos[0].lnum == regmatch.endpos[0].lnum && regmatch.startpos[0].col == regmatch.endpos[0].col);

	}
    }

    vim_regfree(regmatch.regprog);
    return result;
}



    int current_search( long	count, int		forward)


{
    pos_T	start_pos;	
    pos_T	end_pos;	
    pos_T	orig_pos;	
    pos_T	pos;		
    int		i;
    int		dir;
    int		result;		
    char_u	old_p_ws = p_ws;
    int		flags = 0;
    pos_T	save_VIsual = VIsual;
    int		zero_width;
    int		skip_first_backward;

    
    if (VIsual_active && *p_sel == 'e' && LT_POS(VIsual, curwin->w_cursor))
	dec_cursor();

    
    
    skip_first_backward = forward && VIsual_active && LT_POS(curwin->w_cursor, VIsual);

    orig_pos = pos = curwin->w_cursor;
    if (VIsual_active)
    {
	if (forward)
	    incl(&pos);
	else decl(&pos);
    }

    
    zero_width = is_zero_width(spats[last_idx].pat, TRUE, &curwin->w_cursor, FORWARD);
    if (zero_width == -1)
	return FAIL;  

    
    for (i = 0; i < 2; i++)
    {
	if (forward)
	{
	    if (i == 0 && skip_first_backward)
		continue;
	    dir = i;
	}
	else dir = !i;

	flags = 0;
	if (!dir && !zero_width)
	    flags = SEARCH_END;
	end_pos = pos;

	
	if (i == 0)
	    p_ws = FALSE;

	result = searchit(curwin, curbuf, &pos, &end_pos, (dir ? FORWARD : BACKWARD), spats[last_idx].pat, (long) (i ? count : 1), SEARCH_KEEP | flags, RE_SEARCH, NULL);



	p_ws = old_p_ws;

	
	
	
	
	if (i == 1 && !result) 
	{
	    curwin->w_cursor = orig_pos;
	    if (VIsual_active)
		VIsual = save_VIsual;
	    return FAIL;
	}
	else if (i == 0 && !result)
	{
	    if (forward)
	    {
		
		CLEAR_POS(&pos);
	    }
	    else {
		
		
		pos.lnum = curwin->w_buffer->b_ml.ml_line_count;
		pos.col  = (colnr_T)STRLEN( ml_get(curwin->w_buffer->b_ml.ml_line_count));
	    }
	}
    }

    start_pos = pos;

    if (!VIsual_active)
	VIsual = start_pos;

    
    curwin->w_cursor = end_pos;
    if (LT_POS(VIsual, end_pos) && forward)
    {
	if (skip_first_backward)
	    
	    curwin->w_cursor = pos;
	else  dec_cursor();

    }
    else if (VIsual_active && LT_POS(curwin->w_cursor, VIsual) && forward)
	curwin->w_cursor = pos;   
    VIsual_active = TRUE;
    VIsual_mode = 'v';

    if (*p_sel == 'e')
    {
	
	if (forward && LTOREQ_POS(VIsual, curwin->w_cursor))
	    inc_cursor();
	else if (!forward && LTOREQ_POS(curwin->w_cursor, VIsual))
	    inc(&VIsual);
    }


    if (fdo_flags & FDO_SEARCH && KeyTyped)
	foldOpenCursor();


    may_start_select('c');
    setmouse();

    
    
    clip_star.vmode = NUL;

    redraw_curbuf_later(UPD_INVERTED);
    showmode();

    return OK;
}


    int linewhite(linenr_T lnum)
{
    char_u  *p;

    p = skipwhite(ml_get(lnum));
    return (*p == NUL);
}


    static void cmdline_search_stat( int		dirc, pos_T	*pos, pos_T	*cursor_pos, int		show_top_bot_msg, char_u	*msgbuf, int		recompute, int		maxcount, long	timeout)








{
    searchstat_T stat;

    update_search_stat(dirc, pos, cursor_pos, &stat, recompute, maxcount, timeout);
    if (stat.cur <= 0)
	return;

    char	t[SEARCH_STAT_BUF_LEN];
    size_t	len;


    if (curwin->w_p_rl && *curwin->w_p_rlc == 's')
    {
	if (stat.incomplete == 1)
	    vim_snprintf(t, SEARCH_STAT_BUF_LEN, "[?/??]");
	else if (stat.cnt > maxcount && stat.cur > maxcount)
	    vim_snprintf(t, SEARCH_STAT_BUF_LEN, "[>%d/>%d]", maxcount, maxcount);
	else if (stat.cnt > maxcount)
	    vim_snprintf(t, SEARCH_STAT_BUF_LEN, "[>%d/%d]", maxcount, stat.cur);
	else vim_snprintf(t, SEARCH_STAT_BUF_LEN, "[%d/%d]", stat.cnt, stat.cur);

    }
    else  {

	if (stat.incomplete == 1)
	    vim_snprintf(t, SEARCH_STAT_BUF_LEN, "[?/??]");
	else if (stat.cnt > maxcount && stat.cur > maxcount)
	    vim_snprintf(t, SEARCH_STAT_BUF_LEN, "[>%d/>%d]", maxcount, maxcount);
	else if (stat.cnt > maxcount)
	    vim_snprintf(t, SEARCH_STAT_BUF_LEN, "[%d/>%d]", stat.cur, maxcount);
	else vim_snprintf(t, SEARCH_STAT_BUF_LEN, "[%d/%d]", stat.cur, stat.cnt);

    }

    len = STRLEN(t);
    if (show_top_bot_msg && len + 2 < SEARCH_STAT_BUF_LEN)
    {
	mch_memmove(t + 2, t, len);
	t[0] = 'W';
	t[1] = ' ';
	len += 2;
    }

    size_t msgbuf_len = STRLEN(msgbuf);
    if (len > msgbuf_len)
	len = msgbuf_len;
    mch_memmove(msgbuf + msgbuf_len - len, t, len);

    if (dirc == '?' && stat.cur == maxcount + 1)
	stat.cur = -1;

    
    msg_hist_off = TRUE;
    give_warning(msgbuf, FALSE);
    msg_hist_off = FALSE;
}


    static void update_search_stat( int			dirc, pos_T		*pos, pos_T		*cursor_pos, searchstat_T	*stat, int			recompute, int			maxcount, long		timeout UNUSED)







{
    int		    save_ws = p_ws;
    int		    wraparound = FALSE;
    pos_T	    p = (*pos);
    static pos_T    lastpos = {0, 0, 0};
    static int	    cur = 0;
    static int	    cnt = 0;
    static int	    exact_match = FALSE;
    static int	    incomplete = 0;
    static int	    last_maxcount = SEARCH_STAT_DEF_MAX_COUNT;
    static int	    chgtick = 0;
    static char_u   *lastpat = NULL;
    static buf_T    *lbuf = NULL;

    proftime_T  start;


    CLEAR_POINTER(stat);

    if (dirc == 0 && !recompute && !EMPTY_POS(lastpos))
    {
	stat->cur = cur;
	stat->cnt = cnt;
	stat->exact_match = exact_match;
	stat->incomplete = incomplete;
	stat->last_maxcount = last_maxcount;
	return;
    }
    last_maxcount = maxcount;

    wraparound = ((dirc == '?' && LT_POS(lastpos, p))
	       || (dirc == '/' && LT_POS(p, lastpos)));

    
    
    
    
    if (!(chgtick == CHANGEDTICK(curbuf)
	&& MB_STRNICMP(lastpat, spats[last_idx].pat, STRLEN(lastpat)) == 0 && STRLEN(lastpat) == STRLEN(spats[last_idx].pat)
	&& EQUAL_POS(lastpos, *cursor_pos)
	&& lbuf == curbuf) || wraparound || cur < 0 || (maxcount > 0 && cur > maxcount) || recompute)
    {
	cur = 0;
	cnt = 0;
	exact_match = FALSE;
	incomplete = 0;
	CLEAR_POS(&lastpos);
	lbuf = curbuf;
    }

    if (EQUAL_POS(lastpos, *cursor_pos) && !wraparound && (dirc == 0 || dirc == '/' ? cur < cnt : cur > 0))
	cur += dirc == 0 ? 0 : dirc == '/' ? 1 : -1;
    else {
	int	done_search = FALSE;
	pos_T	endpos = {0, 0, 0};

	p_ws = FALSE;

	if (timeout > 0)
	    profile_setlimit(timeout, &start);

	while (!got_int && searchit(curwin, curbuf, &lastpos, &endpos, FORWARD, NULL, 1, SEARCH_KEEP, RE_LAST, NULL) != FAIL)
	{
	    done_search = TRUE;

	    
	    if (timeout > 0 && profile_passed_limit(&start))
	    {
		incomplete = 1;
		break;
	    }

	    cnt++;
	    if (LTOREQ_POS(lastpos, p))
	    {
		cur = cnt;
		if (LT_POS(p, endpos))
		    exact_match = TRUE;
	    }
	    fast_breakcheck();
	    if (maxcount > 0 && cnt > maxcount)
	    {
		incomplete = 2;    
		break;
	    }
	}
	if (got_int)
	    cur = -1; 
	if (done_search)
	{
	    vim_free(lastpat);
	    lastpat = vim_strsave(spats[last_idx].pat);
	    chgtick = CHANGEDTICK(curbuf);
	    lbuf = curbuf;
	    lastpos = p;
	}
    }
    stat->cur = cur;
    stat->cnt = cnt;
    stat->exact_match = exact_match;
    stat->incomplete = incomplete;
    stat->last_maxcount = last_maxcount;
    p_ws = save_ws;
}




    static char_u * get_line_and_copy(linenr_T lnum, char_u *buf)
{
    char_u *line = ml_get(lnum);

    vim_strncpy(buf, line, LSIZE - 1);
    return buf;
}


    void find_pattern_in_path( char_u	*ptr, int		dir UNUSED, int		len, int		whole, int		skip_comments, int		type,  long	count, int		action, linenr_T	start_lnum, linenr_T	end_lnum)











{
    SearchedFile *files;		
    SearchedFile *bigger;		
    int		max_path_depth = 50;
    long	match_count = 1;

    char_u	*pat;
    char_u	*new_fname;
    char_u	*curr_fname = curbuf->b_fname;
    char_u	*prev_fname = NULL;
    linenr_T	lnum;
    int		depth;
    int		depth_displayed;	
    int		old_files;
    int		already_searched;
    char_u	*file_line;
    char_u	*line;
    char_u	*p;
    char_u	save_char;
    int		define_matched;
    regmatch_T	regmatch;
    regmatch_T	incl_regmatch;
    regmatch_T	def_regmatch;
    int		matched = FALSE;
    int		did_show = FALSE;
    int		found = FALSE;
    int		i;
    char_u	*already = NULL;
    char_u	*startp = NULL;
    char_u	*inc_opt = NULL;

    win_T	*curwin_save = NULL;


    regmatch.regprog = NULL;
    incl_regmatch.regprog = NULL;
    def_regmatch.regprog = NULL;

    file_line = alloc(LSIZE);
    if (file_line == NULL)
	return;

    if (type != CHECK_PATH && type != FIND_DEFINE   && !compl_status_sol())


    {
	pat = alloc(len + 5);
	if (pat == NULL)
	    goto fpip_end;
	sprintf((char *)pat, whole ? "\\<%.*s\\>" : "%.*s", len, ptr);
	
	regmatch.rm_ic = ignorecase(pat);
	regmatch.regprog = vim_regcomp(pat, magic_isset() ? RE_MAGIC : 0);
	vim_free(pat);
	if (regmatch.regprog == NULL)
	    goto fpip_end;
    }
    inc_opt = (*curbuf->b_p_inc == NUL) ? p_inc : curbuf->b_p_inc;
    if (*inc_opt != NUL)
    {
	incl_regmatch.regprog = vim_regcomp(inc_opt, magic_isset() ? RE_MAGIC : 0);
	if (incl_regmatch.regprog == NULL)
	    goto fpip_end;
	incl_regmatch.rm_ic = FALSE;	
    }
    if (type == FIND_DEFINE && (*curbuf->b_p_def != NUL || *p_def != NUL))
    {
	def_regmatch.regprog = vim_regcomp(*curbuf->b_p_def == NUL ? p_def : curbuf->b_p_def, magic_isset() ? RE_MAGIC : 0);

	if (def_regmatch.regprog == NULL)
	    goto fpip_end;
	def_regmatch.rm_ic = FALSE;	
    }
    files = lalloc_clear(max_path_depth * sizeof(SearchedFile), TRUE);
    if (files == NULL)
	goto fpip_end;
    old_files = max_path_depth;
    depth = depth_displayed = -1;

    lnum = start_lnum;
    if (end_lnum > curbuf->b_ml.ml_line_count)
	end_lnum = curbuf->b_ml.ml_line_count;
    if (lnum > end_lnum)		
	lnum = end_lnum;
    line = get_line_and_copy(lnum, file_line);

    for (;;)
    {
	if (incl_regmatch.regprog != NULL && vim_regexec(&incl_regmatch, line, (colnr_T)0))
	{
	    char_u *p_fname = (curr_fname == curbuf->b_fname)
					      ? curbuf->b_ffname : curr_fname;

	    if (inc_opt != NULL && strstr((char *)inc_opt, "\\zs") != NULL)
		
		new_fname = find_file_name_in_path(incl_regmatch.startp[0], (int)(incl_regmatch.endp[0] - incl_regmatch.startp[0]), FNAME_EXP|FNAME_INCL|FNAME_REL, 1L, p_fname);

	    else  new_fname = file_name_in_line(incl_regmatch.endp[0], 0, FNAME_EXP|FNAME_INCL|FNAME_REL, 1L, p_fname, NULL);


	    already_searched = FALSE;
	    if (new_fname != NULL)
	    {
		
		for (i = 0;; i++)
		{
		    if (i == depth + 1)
			i = old_files;
		    if (i == max_path_depth)
			break;
		    if (fullpathcmp(new_fname, files[i].name, TRUE, TRUE)
								    & FPC_SAME)
		    {
			if (type != CHECK_PATH && action == ACTION_SHOW_ALL && files[i].matched)

			{
			    msg_putchar('\n');	    
			    if (!got_int)	    
						    
						    
			    {
				msg_home_replace_hl(new_fname);
				msg_puts(_(" (includes previously listed match)"));
				prev_fname = NULL;
			    }
			}
			VIM_CLEAR(new_fname);
			already_searched = TRUE;
			break;
		    }
		}
	    }

	    if (type == CHECK_PATH && (action == ACTION_SHOW_ALL || (new_fname == NULL && !already_searched)))
	    {
		if (did_show)
		    msg_putchar('\n');	    
		else {
		    gotocmdline(TRUE);	    
		    msg_puts_title(_("--- Included files "));
		    if (action != ACTION_SHOW_ALL)
			msg_puts_title(_("not found "));
		    msg_puts_title(_("in path ---\n"));
		}
		did_show = TRUE;
		while (depth_displayed < depth && !got_int)
		{
		    ++depth_displayed;
		    for (i = 0; i < depth_displayed; i++)
			msg_puts("  ");
		    msg_home_replace(files[depth_displayed].name);
		    msg_puts(" -->\n");
		}
		if (!got_int)		    
					    
		{
		    for (i = 0; i <= depth_displayed; i++)
			msg_puts("  ");
		    if (new_fname != NULL)
		    {
			
			
			msg_outtrans_attr(new_fname, HL_ATTR(HLF_D));
		    }
		    else {
			
			if (inc_opt != NULL && strstr((char *)inc_opt, "\\zs") != NULL)
			{
			    
			    p = incl_regmatch.startp[0];
			    i = (int)(incl_regmatch.endp[0] - incl_regmatch.startp[0]);
			}
			else {
			    
			    for (p = incl_regmatch.endp[0];
						  *p && !vim_isfilec(*p); p++)
				;
			    for (i = 0; vim_isfilec(p[i]); i++)
				;
			}

			if (i == 0)
			{
			    
			    p = incl_regmatch.endp[0];
			    i = (int)STRLEN(p);
			}
			
			
			else if (p > line)
			{
			    if (p[-1] == '"' || p[-1] == '<')
			    {
				--p;
				++i;
			    }
			    if (p[i] == '"' || p[i] == '>')
				++i;
			}
			save_char = p[i];
			p[i] = NUL;
			msg_outtrans_attr(p, HL_ATTR(HLF_D));
			p[i] = save_char;
		    }

		    if (new_fname == NULL && action == ACTION_SHOW_ALL)
		    {
			if (already_searched)
			    msg_puts(_("  (Already listed)"));
			else msg_puts(_("  NOT FOUND"));
		    }
		}
		out_flush();	    
	    }

	    if (new_fname != NULL)
	    {
		
		if (depth + 1 == old_files)
		{
		    bigger = ALLOC_MULT(SearchedFile, max_path_depth * 2);
		    if (bigger != NULL)
		    {
			for (i = 0; i <= depth; i++)
			    bigger[i] = files[i];
			for (i = depth + 1; i < old_files + max_path_depth; i++)
			{
			    bigger[i].fp = NULL;
			    bigger[i].name = NULL;
			    bigger[i].lnum = 0;
			    bigger[i].matched = FALSE;
			}
			for (i = old_files; i < max_path_depth; i++)
			    bigger[i + max_path_depth] = files[i];
			old_files += max_path_depth;
			max_path_depth *= 2;
			vim_free(files);
			files = bigger;
		    }
		}
		if ((files[depth + 1].fp = mch_fopen((char *)new_fname, "r"))
								    == NULL)
		    vim_free(new_fname);
		else {
		    if (++depth == old_files)
		    {
			
			vim_free(files[old_files].name);
			++old_files;
		    }
		    files[depth].name = curr_fname = new_fname;
		    files[depth].lnum = 0;
		    files[depth].matched = FALSE;
		    if (action == ACTION_EXPAND)
		    {
			msg_hist_off = TRUE;	
			vim_snprintf((char*)IObuff, IOSIZE, _("Scanning included file: %s"), (char *)new_fname);

			msg_trunc_attr((char *)IObuff, TRUE, HL_ATTR(HLF_R));
		    }
		    else if (p_verbose >= 5)
		    {
			verbose_enter();
			smsg(_("Searching included file %s"), (char *)new_fname);
			verbose_leave();
		    }

		}
	    }
	}
	else {
	    
	    p = line;
search_line:
	    define_matched = FALSE;
	    if (def_regmatch.regprog != NULL && vim_regexec(&def_regmatch, line, (colnr_T)0))
	    {
		
		p = def_regmatch.endp[0];
		while (*p && !vim_iswordc(*p))
		    p++;
		define_matched = TRUE;
	    }

	    
	    if (def_regmatch.regprog == NULL || define_matched)
	    {
		if (define_matched || compl_status_sol())
		{
		    
		    startp = skipwhite(p);
		    if (p_ic)
			matched = !MB_STRNICMP(startp, ptr, len);
		    else matched = !STRNCMP(startp, ptr, len);
		    if (matched && define_matched && whole && vim_iswordc(startp[len]))
			matched = FALSE;
		}
		else if (regmatch.regprog != NULL && vim_regexec(&regmatch, line, (colnr_T)(p - line)))
		{
		    matched = TRUE;
		    startp = regmatch.startp[0];
		    
		    if (!define_matched && skip_comments)
		    {
			if ((*line != '#' || STRNCMP(skipwhite(line + 1), "define", 6) != 0)
				&& get_leader_len(line, NULL, FALSE, TRUE))
			    matched = FALSE;

			
			p = skipwhite(line);
			if (matched || (p[0] == '/' && p[1] == '*') || p[0] == '*')
			    for (p = line; *p && p < startp; ++p)
			    {
				if (matched && p[0] == '/' && (p[1] == '*' || p[1] == '/'))

				{
				    matched = FALSE;
				    
				    if (p[1] == '/')
					break;
				    ++p;
				}
				else if (!matched && p[0] == '*' && p[1] == '/')
				{
				    
				    matched = TRUE;
				    ++p;
				}
			    }
		    }
		}
	    }
	}
	if (matched)
	{
	    if (action == ACTION_EXPAND)
	    {
		int	cont_s_ipos = FALSE;
		int	add_r;
		char_u	*aux;

		if (depth == -1 && lnum == curwin->w_cursor.lnum)
		    break;
		found = TRUE;
		aux = p = startp;
		if (compl_status_adding())
		{
		    p += ins_compl_len();
		    if (vim_iswordp(p))
			goto exit_matched;
		    p = find_word_start(p);
		}
		p = find_word_end(p);
		i = (int)(p - aux);

		if (compl_status_adding() && i == ins_compl_len())
		{
		    
		    STRNCPY(IObuff, aux, i);

		    
		    
		    
		    if (depth < 0)
		    {
			if (lnum >= end_lnum)
			    goto exit_matched;
			line = get_line_and_copy(++lnum, file_line);
		    }
		    else if (vim_fgets(line = file_line, LSIZE, files[depth].fp))
			goto exit_matched;

		    
		    
		    
		    already = aux = p = skipwhite(line);
		    p = find_word_start(p);
		    p = find_word_end(p);
		    if (p > aux)
		    {
			if (*aux != ')' && IObuff[i-1] != TAB)
			{
			    if (IObuff[i-1] != ' ')
				IObuff[i++] = ' ';
			    
			    if (p_js && (IObuff[i-2] == '.' || (vim_strchr(p_cpo, CPO_JOINSP) == NULL && (IObuff[i-2] == '?' || IObuff[i-2] == '!'))))



				IObuff[i++] = ' ';
			}
			
			if (p - aux >= IOSIZE - i)
			    p = aux + IOSIZE - i - 1;
			STRNCPY(IObuff + i, aux, p - aux);
			i += (int)(p - aux);
			cont_s_ipos = TRUE;
		    }
		    IObuff[i] = NUL;
		    aux = IObuff;

		    if (i == ins_compl_len())
			goto exit_matched;
		}

		add_r = ins_compl_add_infercase(aux, i, p_ic, curr_fname == curbuf->b_fname ? NULL : curr_fname, dir, cont_s_ipos);

		if (add_r == OK)
		    
		    dir = FORWARD;
		else if (add_r == FAIL)
		    break;
	    }
	    else if (action == ACTION_SHOW_ALL)
	    {
		found = TRUE;
		if (!did_show)
		    gotocmdline(TRUE);		
		if (curr_fname != prev_fname)
		{
		    if (did_show)
			msg_putchar('\n');	
		    if (!got_int)		
						
			msg_home_replace_hl(curr_fname);
		    prev_fname = curr_fname;
		}
		did_show = TRUE;
		if (!got_int)
		    show_pat_in_path(line, type, TRUE, action, (depth == -1) ? NULL : files[depth].fp, (depth == -1) ? &lnum : &files[depth].lnum, match_count++);



		
		
		for (i = 0; i <= depth; ++i)
		    files[i].matched = TRUE;
	    }
	    else if (--count <= 0)
	    {
		found = TRUE;
		if (depth == -1 && lnum == curwin->w_cursor.lnum  && g_do_tagpreview == 0  )



		    emsg(_(e_match_is_on_current_line));
		else if (action == ACTION_SHOW)
		{
		    show_pat_in_path(line, type, did_show, action, (depth == -1) ? NULL : files[depth].fp, (depth == -1) ? &lnum : &files[depth].lnum, 1L);

		    did_show = TRUE;
		}
		else {

		    need_mouse_correct = TRUE;


		    
		    if (g_do_tagpreview != 0)
		    {
			curwin_save = curwin;
			prepare_tagpreview(TRUE, TRUE, FALSE);
		    }

		    if (action == ACTION_SPLIT)
		    {
			if (win_split(0, 0) == FAIL)
			    break;
			RESET_BINDING(curwin);
		    }
		    if (depth == -1)
		    {
			

			if (g_do_tagpreview != 0)
			{
			    if (!win_valid(curwin_save))
				break;
			    if (!GETFILE_SUCCESS(getfile( curwin_save->w_buffer->b_fnum, NULL, NULL, TRUE, lnum, FALSE)))

				break;	
			}
			else  setpcmark();

			curwin->w_cursor.lnum = lnum;
			check_cursor();
		    }
		    else {
			if (!GETFILE_SUCCESS(getfile( 0, files[depth].name, NULL, TRUE, files[depth].lnum, FALSE)))

			    break;	
			
			
			curwin->w_cursor.lnum = files[depth].lnum;
		    }
		}
		if (action != ACTION_SHOW)
		{
		    curwin->w_cursor.col = (colnr_T)(startp - line);
		    curwin->w_set_curswant = TRUE;
		}


		if (g_do_tagpreview != 0 && curwin != curwin_save && win_valid(curwin_save))
		{
		    
		    validate_cursor();
		    redraw_later(UPD_VALID);
		    win_enter(curwin_save, TRUE);
		}

		else if (WIN_IS_POPUP(curwin))
		    
		    win_enter(firstwin, TRUE);


		break;
	    }
exit_matched:
	    matched = FALSE;
	    
	    
	    if (def_regmatch.regprog == NULL && action == ACTION_EXPAND && !compl_status_sol()

		    && *startp != NUL && *(p = startp + mb_ptr2len(startp)) != NUL)
		goto search_line;
	}
	line_breakcheck();
	if (action == ACTION_EXPAND)
	    ins_compl_check_keys(30, FALSE);
	if (got_int || ins_compl_interrupted())
	    break;

	
	while (depth >= 0 && !already && vim_fgets(line = file_line, LSIZE, files[depth].fp))
	{
	    fclose(files[depth].fp);
	    --old_files;
	    files[old_files].name = files[depth].name;
	    files[old_files].matched = files[depth].matched;
	    --depth;
	    curr_fname = (depth == -1) ? curbuf->b_fname : files[depth].name;
	    if (depth < depth_displayed)
		depth_displayed = depth;
	}
	if (depth >= 0)		
	{
	    files[depth].lnum++;
	    
	    i = (int)STRLEN(line);
	    if (i > 0 && line[i - 1] == '\n')
		line[--i] = NUL;
	    if (i > 0 && line[i - 1] == '\r')
		line[--i] = NUL;
	}
	else if (!already)
	{
	    if (++lnum > end_lnum)
		break;
	    line = get_line_and_copy(lnum, file_line);
	}
	already = NULL;
    }
    

    
    for (i = 0; i <= depth; i++)
    {
	fclose(files[i].fp);
	vim_free(files[i].name);
    }
    for (i = old_files; i < max_path_depth; i++)
	vim_free(files[i].name);
    vim_free(files);

    if (type == CHECK_PATH)
    {
	if (!did_show)
	{
	    if (action != ACTION_SHOW_ALL)
		msg(_("All included files were found"));
	    else msg(_("No included files"));
	}
    }
    else if (!found && action != ACTION_EXPAND)
    {
	if (got_int || ins_compl_interrupted())
	    emsg(_(e_interrupted));
	else if (type == FIND_DEFINE)
	    emsg(_(e_couldnt_find_definition));
	else emsg(_(e_couldnt_find_pattern));
    }
    if (action == ACTION_SHOW || action == ACTION_SHOW_ALL)
	msg_end();

fpip_end:
    vim_free(file_line);
    vim_regfree(regmatch.regprog);
    vim_regfree(incl_regmatch.regprog);
    vim_regfree(def_regmatch.regprog);
}

    static void show_pat_in_path( char_u  *line, int	    type, int	    did_show, int	    action, FILE    *fp, linenr_T *lnum, long    count)







{
    char_u  *p;

    if (did_show)
	msg_putchar('\n');	
    else if (!msg_silent)
	gotocmdline(TRUE);	
    if (got_int)		
	return;
    for (;;)
    {
	p = line + STRLEN(line) - 1;
	if (fp != NULL)
	{
	    
	    if (p >= line && *p == '\n')
		--p;
	    if (p >= line && *p == '\r')
		--p;
	    *(p + 1) = NUL;
	}
	if (action == ACTION_SHOW_ALL)
	{
	    sprintf((char *)IObuff, "%3ld: ", count);	
	    msg_puts((char *)IObuff);
	    sprintf((char *)IObuff, "%4ld", *lnum);	
						
	    msg_puts_attr((char *)IObuff, HL_ATTR(HLF_N));
	    msg_puts(" ");
	}
	msg_prt_line(line, FALSE);
	out_flush();			

	
	if (got_int || type != FIND_DEFINE || p < line || *p != '\\')
	    break;

	if (fp != NULL)
	{
	    if (vim_fgets(line, LSIZE, fp)) 
		break;
	    ++*lnum;
	}
	else {
	    if (++*lnum > curbuf->b_ml.ml_line_count)
		break;
	    line = ml_get(*lnum);
	}
	msg_putchar('\n');
    }
}




    spat_T * get_spat(int idx)
{
    return &spats[idx];
}


    int get_spat_last_idx(void)
{
    return last_idx;
}




    void f_searchcount(typval_T *argvars, typval_T *rettv)
{
    pos_T		pos = curwin->w_cursor;
    char_u		*pattern = NULL;
    int			maxcount = SEARCH_STAT_DEF_MAX_COUNT;
    long		timeout = SEARCH_STAT_DEF_TIMEOUT;
    int			recompute = TRUE;
    searchstat_T	stat;

    if (rettv_dict_alloc(rettv) == FAIL)
	return;

    if (in_vim9script() && check_for_opt_dict_arg(argvars, 0) == FAIL)
	return;

    if (shortmess(SHM_SEARCHCOUNT))	
	recompute = TRUE;

    if (argvars[0].v_type != VAR_UNKNOWN)
    {
	dict_T		*dict;
	dictitem_T	*di;
	listitem_T	*li;
	int		error = FALSE;

	if (check_for_nonnull_dict_arg(argvars, 0) == FAIL)
	    return;
	dict = argvars[0].vval.v_dict;
	di = dict_find(dict, (char_u *)"timeout", -1);
	if (di != NULL)
	{
	    timeout = (long)tv_get_number_chk(&di->di_tv, &error);
	    if (error)
		return;
	}
	di = dict_find(dict, (char_u *)"maxcount", -1);
	if (di != NULL)
	{
	    maxcount = (int)tv_get_number_chk(&di->di_tv, &error);
	    if (error)
		return;
	}
	recompute = dict_get_bool(dict, "recompute", recompute);
	di = dict_find(dict, (char_u *)"pattern", -1);
	if (di != NULL)
	{
	    pattern = tv_get_string_chk(&di->di_tv);
	    if (pattern == NULL)
		return;
	}
	di = dict_find(dict, (char_u *)"pos", -1);
	if (di != NULL)
	{
	    if (di->di_tv.v_type != VAR_LIST)
	    {
		semsg(_(e_invalid_argument_str), "pos");
		return;
	    }
	    if (list_len(di->di_tv.vval.v_list) != 3)
	    {
		semsg(_(e_invalid_argument_str), "List format should be [lnum, col, off]");
		return;
	    }
	    li = list_find(di->di_tv.vval.v_list, 0L);
	    if (li != NULL)
	    {
		pos.lnum = tv_get_number_chk(&li->li_tv, &error);
		if (error)
		    return;
	    }
	    li = list_find(di->di_tv.vval.v_list, 1L);
	    if (li != NULL)
	    {
		pos.col = tv_get_number_chk(&li->li_tv, &error) - 1;
		if (error)
		    return;
	    }
	    li = list_find(di->di_tv.vval.v_list, 2L);
	    if (li != NULL)
	    {
		pos.coladd = tv_get_number_chk(&li->li_tv, &error);
		if (error)
		    return;
	    }
	}
    }

    save_last_search_pattern();

    save_incsearch_state();

    if (pattern != NULL)
    {
	if (*pattern == NUL)
	    goto the_end;
	vim_free(spats[last_idx].pat);
	spats[last_idx].pat = vim_strsave(pattern);
    }
    if (spats[last_idx].pat == NULL || *spats[last_idx].pat == NUL)
	goto the_end;	

    update_search_stat(0, &pos, &pos, &stat, recompute, maxcount, timeout);

    dict_add_number(rettv->vval.v_dict, "current", stat.cur);
    dict_add_number(rettv->vval.v_dict, "total", stat.cnt);
    dict_add_number(rettv->vval.v_dict, "exact_match", stat.exact_match);
    dict_add_number(rettv->vval.v_dict, "incomplete", stat.incomplete);
    dict_add_number(rettv->vval.v_dict, "maxcount", stat.last_maxcount);

the_end:
    restore_last_search_pattern();

    restore_incsearch_state();

}



typedef struct {
    int		idx;		
    listitem_T	*item;
    int		score;
    list_T	*lmatchpos;
} fuzzyItem_T;


























    static int fuzzy_match_compute_score( char_u		*str, int		strSz, int_u		*matches, int		numMatches)




{
    int		score;
    int		penalty;
    int		unmatched;
    int		i;
    char_u	*p = str;
    int_u	sidx = 0;

    
    score = 100;

    
    penalty = LEADING_LETTER_PENALTY * matches[0];
    if (penalty < MAX_LEADING_LETTER_PENALTY)
	penalty = MAX_LEADING_LETTER_PENALTY;
    score += penalty;

    
    unmatched = strSz - numMatches;
    score += UNMATCHED_LETTER_PENALTY * unmatched;

    
    for (i = 0; i < numMatches; ++i)
    {
	int_u	currIdx = matches[i];

	if (i > 0)
	{
	    int_u	prevIdx = matches[i - 1];

	    
	    if (currIdx == (prevIdx + 1))
		score += SEQUENTIAL_BONUS;
	    else score += GAP_PENALTY * (currIdx - prevIdx);
	}

	
	if (currIdx > 0)
	{
	    
	    int	neighbor = ' ';
	    int	curr;

	    if (has_mbyte)
	    {
		while (sidx < currIdx)
		{
		    neighbor = (*mb_ptr2char)(p);
		    MB_PTR_ADV(p);
		    sidx++;
		}
		curr = (*mb_ptr2char)(p);
	    }
	    else {
		neighbor = str[currIdx - 1];
		curr = str[currIdx];
	    }

	    if (vim_islower(neighbor) && vim_isupper(curr))
		score += CAMEL_BONUS;

	    
	    if (neighbor == '/' || neighbor == '\\')
		score += PATH_SEPARATOR_BONUS;
	    else if (neighbor == ' ' || neighbor == '_')
		score += WORD_SEPARATOR_BONUS;
	}
	else {
	    
	    score += FIRST_LETTER_BONUS;
	}
    }
    return score;
}


    static int fuzzy_match_recursive( char_u		*fuzpat, char_u		*str, int_u		strIdx, int		*outScore, char_u		*strBegin, int		strLen, int_u		*srcMatches, int_u		*matches, int		maxMatches, int		nextMatch, int		*recursionCount)











{
    
    int		recursiveMatch = FALSE;
    int_u	bestRecursiveMatches[MAX_FUZZY_MATCHES];
    int		bestRecursiveScore = 0;
    int		first_match;
    int		matched;

    
    ++*recursionCount;
    if (*recursionCount >= FUZZY_MATCH_RECURSION_LIMIT)
	return 0;

    
    if (*fuzpat == NUL || *str == NUL)
	return 0;

    
    first_match = TRUE;
    while (*fuzpat != NUL && *str != NUL)
    {
	int	c1;
	int	c2;

	c1 = PTR2CHAR(fuzpat);
	c2 = PTR2CHAR(str);

	
	if (vim_tolower(c1) == vim_tolower(c2))
	{
	    int_u	recursiveMatches[MAX_FUZZY_MATCHES];
	    int		recursiveScore = 0;
	    char_u	*next_char;

	    
	    if (nextMatch >= maxMatches)
		return 0;

	    
	    if (first_match && srcMatches)
	    {
		memcpy(matches, srcMatches, nextMatch * sizeof(srcMatches[0]));
		first_match = FALSE;
	    }

	    
	    if (has_mbyte)
		next_char = str + (*mb_ptr2len)(str);
	    else next_char = str + 1;
	    if (fuzzy_match_recursive(fuzpat, next_char, strIdx + 1, &recursiveScore, strBegin, strLen, matches, recursiveMatches, ARRAY_LENGTH(recursiveMatches), nextMatch, recursionCount))



	    {
		
		if (!recursiveMatch || recursiveScore > bestRecursiveScore)
		{
		    memcpy(bestRecursiveMatches, recursiveMatches, MAX_FUZZY_MATCHES * sizeof(recursiveMatches[0]));
		    bestRecursiveScore = recursiveScore;
		}
		recursiveMatch = TRUE;
	    }

	    
	    matches[nextMatch++] = strIdx;
	    if (has_mbyte)
		MB_PTR_ADV(fuzpat);
	    else ++fuzpat;
	}
	if (has_mbyte)
	    MB_PTR_ADV(str);
	else ++str;
	strIdx++;
    }

    
    matched = *fuzpat == NUL ? TRUE : FALSE;

    
    if (matched)
	*outScore = fuzzy_match_compute_score(strBegin, strLen, matches, nextMatch);

    
    if (recursiveMatch && (!matched || bestRecursiveScore > *outScore))
    {
	
	memcpy(matches, bestRecursiveMatches, maxMatches * sizeof(matches[0]));
	*outScore = bestRecursiveScore;
	return nextMatch;
    }
    else if (matched)
	return nextMatch;	

    return 0;		
}


    int fuzzy_match( char_u		*str, char_u		*pat_arg, int		matchseq, int		*outScore, int_u		*matches, int		maxMatches)






{
    int		recursionCount = 0;
    int		len = MB_CHARLEN(str);
    char_u	*save_pat;
    char_u	*pat;
    char_u	*p;
    int		complete = FALSE;
    int		score = 0;
    int		numMatches = 0;
    int		matchCount;

    *outScore = 0;

    save_pat = vim_strsave(pat_arg);
    if (save_pat == NULL)
	return FALSE;
    pat = save_pat;
    p = pat;

    
    while (TRUE)
    {
	if (matchseq)
	    complete = TRUE;
	else {
	    
	    p = skipwhite(p);
	    if (*p == NUL)
		break;
	    pat = p;
	    while (*p != NUL && !VIM_ISWHITE(PTR2CHAR(p)))
	    {
		if (has_mbyte)
		    MB_PTR_ADV(p);
		else ++p;
	    }
	    if (*p == NUL)		
		complete = TRUE;
	    *p = NUL;
	}

	score = 0;
	recursionCount = 0;
	matchCount = fuzzy_match_recursive(pat, str, 0, &score, str, len, NULL, matches + numMatches, maxMatches - numMatches, 0, &recursionCount);

	if (matchCount == 0)
	{
	    numMatches = 0;
	    break;
	}

	
	*outScore += score;
	numMatches += matchCount;

	if (complete)
	    break;

	
	++p;
    }

    vim_free(save_pat);
    return numMatches != 0;
}



    static int fuzzy_match_item_compare(const void *s1, const void *s2)
{
    int		v1 = ((fuzzyItem_T *)s1)->score;
    int		v2 = ((fuzzyItem_T *)s2)->score;
    int		idx1 = ((fuzzyItem_T *)s1)->idx;
    int		idx2 = ((fuzzyItem_T *)s2)->idx;

    return v1 == v2 ? (idx1 - idx2) : v1 > v2 ? -1 : 1;
}


    static void fuzzy_match_in_list( list_T		*l, char_u		*str, int		matchseq, char_u		*key, callback_T	*item_cb, int		retmatchpos, list_T		*fmatchlist, long		max_matches)








{
    long	len;
    fuzzyItem_T	*items;
    listitem_T	*li;
    long	i = 0;
    long	match_count = 0;
    int_u	matches[MAX_FUZZY_MATCHES];

    len = list_len(l);
    if (len == 0)
	return;
    if (max_matches > 0 && len > max_matches)
	len = max_matches;

    items = ALLOC_CLEAR_MULT(fuzzyItem_T, len);
    if (items == NULL)
	return;

    
    FOR_ALL_LIST_ITEMS(l, li)
    {
	int		score;
	char_u		*itemstr;
	typval_T	rettv;

	if (max_matches > 0 && match_count >= max_matches)
	    break;

	itemstr = NULL;
	rettv.v_type = VAR_UNKNOWN;
	if (li->li_tv.v_type == VAR_STRING)	
	    itemstr = li->li_tv.vval.v_string;
	else if (li->li_tv.v_type == VAR_DICT && (key != NULL || item_cb->cb_name != NULL))
	{
	    
	    
	    if (key != NULL)
		itemstr = dict_get_string(li->li_tv.vval.v_dict, (char *)key, FALSE);
	    else {
		typval_T	argv[2];

		
		li->li_tv.vval.v_dict->dv_refcount++;
		argv[0].v_type = VAR_DICT;
		argv[0].vval.v_dict = li->li_tv.vval.v_dict;
		argv[1].v_type = VAR_UNKNOWN;
		if (call_callback(item_cb, -1, &rettv, 1, argv) != FAIL)
		{
		    if (rettv.v_type == VAR_STRING)
			itemstr = rettv.vval.v_string;
		}
		dict_unref(li->li_tv.vval.v_dict);
	    }
	}

	if (itemstr != NULL && fuzzy_match(itemstr, str, matchseq, &score, matches, MAX_FUZZY_MATCHES))

	{
	    items[match_count].idx = match_count;
	    items[match_count].item = li;
	    items[match_count].score = score;

	    
	    
	    if (retmatchpos)
	    {
		int	j = 0;
		char_u	*p;

		items[match_count].lmatchpos = list_alloc();
		if (items[match_count].lmatchpos == NULL)
		    goto done;

		p = str;
		while (*p != NUL)
		{
		    if (!VIM_ISWHITE(PTR2CHAR(p)) || matchseq)
		    {
			if (list_append_number(items[match_count].lmatchpos, matches[j]) == FAIL)
			    goto done;
			j++;
		    }
		    if (has_mbyte)
			MB_PTR_ADV(p);
		    else ++p;
		}
	    }
	    ++match_count;
	}
	clear_tv(&rettv);
    }

    if (match_count > 0)
    {
	list_T		*retlist;

	
	qsort((void *)items, (size_t)match_count, sizeof(fuzzyItem_T), fuzzy_match_item_compare);

	
	
	
	
	
	
	
	if (retmatchpos)
	{
	    li = list_find(fmatchlist, 0);
	    if (li == NULL || li->li_tv.vval.v_list == NULL)
		goto done;
	    retlist = li->li_tv.vval.v_list;
	}
	else retlist = fmatchlist;

	
	for (i = 0; i < match_count; i++)
	{
	    if (items[i].score == SCORE_NONE)
		break;
	    list_append_tv(retlist, &items[i].item->li_tv);
	}

	
	if (retmatchpos)
	{
	    li = list_find(fmatchlist, -2);
	    if (li == NULL || li->li_tv.vval.v_list == NULL)
		goto done;
	    retlist = li->li_tv.vval.v_list;

	    for (i = 0; i < match_count; i++)
	    {
		if (items[i].score == SCORE_NONE)
		    break;
		if (items[i].lmatchpos != NULL && list_append_list(retlist, items[i].lmatchpos) == FAIL)
		    goto done;
	    }

	    
	    li = list_find(fmatchlist, -1);
	    if (li == NULL || li->li_tv.vval.v_list == NULL)
		goto done;
	    retlist = li->li_tv.vval.v_list;
	    for (i = 0; i < match_count; i++)
	    {
		if (items[i].score == SCORE_NONE)
		    break;
		if (list_append_number(retlist, items[i].score) == FAIL)
		    goto done;
	    }
	}
    }

done:
    vim_free(items);
}


    static void do_fuzzymatch(typval_T *argvars, typval_T *rettv, int retmatchpos)
{
    callback_T	cb;
    char_u	*key = NULL;
    int		ret;
    int		matchseq = FALSE;
    long	max_matches = 0;

    if (in_vim9script()
	    && (check_for_list_arg(argvars, 0) == FAIL || check_for_string_arg(argvars, 1) == FAIL || check_for_opt_dict_arg(argvars, 2) == FAIL))

	return;

    CLEAR_POINTER(&cb);

    
    if (argvars[0].v_type != VAR_LIST || argvars[0].vval.v_list == NULL)
    {
	semsg(_(e_argument_of_str_must_be_list), retmatchpos ? "matchfuzzypos()" : "matchfuzzy()");
	return;
    }
    if (argvars[1].v_type != VAR_STRING || argvars[1].vval.v_string == NULL)
    {
	semsg(_(e_invalid_argument_str), tv_get_string(&argvars[1]));
	return;
    }

    if (argvars[2].v_type != VAR_UNKNOWN)
    {
	dict_T		*d;
	dictitem_T	*di;

	if (check_for_nonnull_dict_arg(argvars, 2) == FAIL)
	    return;

	
	
	d = argvars[2].vval.v_dict;
	if ((di = dict_find(d, (char_u *)"key", -1)) != NULL)
	{
	    if (di->di_tv.v_type != VAR_STRING || di->di_tv.vval.v_string == NULL || *di->di_tv.vval.v_string == NUL)

	    {
		semsg(_(e_invalid_argument_str), tv_get_string(&di->di_tv));
		return;
	    }
	    key = tv_get_string(&di->di_tv);
	}
	else if ((di = dict_find(d, (char_u *)"text_cb", -1)) != NULL)
	{
	    cb = get_callback(&di->di_tv);
	    if (cb.cb_name == NULL)
	    {
		semsg(_(e_invalid_value_for_argument_str), "text_cb");
		return;
	    }
	}

	if ((di = dict_find(d, (char_u *)"limit", -1)) != NULL)
	{
	    if (di->di_tv.v_type != VAR_NUMBER)
	    {
		semsg(_(e_invalid_argument_str), tv_get_string(&di->di_tv));
		return;
	    }
	    max_matches = (long)tv_get_number_chk(&di->di_tv, NULL);
	}

	if (dict_has_key(d, "matchseq"))
	    matchseq = TRUE;
    }

    
    ret = rettv_list_alloc(rettv);
    if (ret == FAIL)
	goto done;
    if (retmatchpos)
    {
	list_T	*l;

	
	
	
	
	l = list_alloc();
	if (l == NULL)
	    goto done;
	if (list_append_list(rettv->vval.v_list, l) == FAIL)
	{
	    vim_free(l);
	    goto done;
	}
	l = list_alloc();
	if (l == NULL)
	    goto done;
	if (list_append_list(rettv->vval.v_list, l) == FAIL)
	{
	    vim_free(l);
	    goto done;
	}
	l = list_alloc();
	if (l == NULL)
	    goto done;
	if (list_append_list(rettv->vval.v_list, l) == FAIL)
	{
	    vim_free(l);
	    goto done;
	}
    }

    fuzzy_match_in_list(argvars[0].vval.v_list, tv_get_string(&argvars[1]), matchseq, key, &cb, retmatchpos, rettv->vval.v_list, max_matches);

done:
    free_callback(&cb);
}


    void f_matchfuzzy(typval_T *argvars, typval_T *rettv)
{
    do_fuzzymatch(argvars, rettv, FALSE);
}


    void f_matchfuzzypos(typval_T *argvars, typval_T *rettv)
{
    do_fuzzymatch(argvars, rettv, TRUE);
}



    static int fuzzy_match_str_compare(const void *s1, const void *s2)
{
    int		v1 = ((fuzmatch_str_T *)s1)->score;
    int		v2 = ((fuzmatch_str_T *)s2)->score;
    int		idx1 = ((fuzmatch_str_T *)s1)->idx;
    int		idx2 = ((fuzmatch_str_T *)s2)->idx;

    return v1 == v2 ? (idx1 - idx2) : v1 > v2 ? -1 : 1;
}


    static void fuzzy_match_str_sort(fuzmatch_str_T *fm, int sz)
{
    
    qsort((void *)fm, (size_t)sz, sizeof(fuzmatch_str_T), fuzzy_match_str_compare);
}


    static int fuzzy_match_func_compare(const void *s1, const void *s2)
{
    int		v1 = ((fuzmatch_str_T *)s1)->score;
    int		v2 = ((fuzmatch_str_T *)s2)->score;
    int		idx1 = ((fuzmatch_str_T *)s1)->idx;
    int		idx2 = ((fuzmatch_str_T *)s2)->idx;
    char_u	*str1 = ((fuzmatch_str_T *)s1)->str;
    char_u	*str2 = ((fuzmatch_str_T *)s2)->str;

    if (*str1 != '<' && *str2 == '<') return -1;
    if (*str1 == '<' && *str2 != '<') return 1;
    return v1 == v2 ? (idx1 - idx2) : v1 > v2 ? -1 : 1;
}


    static void fuzzy_match_func_sort(fuzmatch_str_T *fm, int sz)
{
    
    qsort((void *)fm, (size_t)sz, sizeof(fuzmatch_str_T), fuzzy_match_func_compare);
}


    int fuzzy_match_str(char_u *str, char_u *pat)
{
    int		score = 0;
    int_u	matchpos[MAX_FUZZY_MATCHES];

    if (str == NULL || pat == NULL)
	return 0;

    fuzzy_match(str, pat, TRUE, &score, matchpos, sizeof(matchpos) / sizeof(matchpos[0]));

    return score;
}


    void fuzmatch_str_free(fuzmatch_str_T *fuzmatch, int count)
{
    int i;

    if (fuzmatch == NULL)
	return;
    for (i = 0; i < count; ++i)
	vim_free(fuzmatch[i].str);
    vim_free(fuzmatch);
}


    int fuzzymatches_to_strmatches( fuzmatch_str_T	*fuzmatch, char_u		***matches, int		count, int		funcsort)




{
    int		i;

    if (count <= 0)
	return OK;

    *matches = ALLOC_MULT(char_u *, count);
    if (*matches == NULL)
    {
	fuzmatch_str_free(fuzmatch, count);
	return FAIL;
    }

    
    if (funcsort)
	fuzzy_match_func_sort((void *)fuzmatch, (size_t)count);
    else fuzzy_match_str_sort((void *)fuzmatch, (size_t)count);

    for (i = 0; i < count; i++)
	(*matches)[i] = fuzmatch[i].str;
    vim_free(fuzmatch);

    return OK;
}
