






















typedef struct matchinf_S {
    langp_T	*mi_lp;			

    
    char_u	*mi_word;		
    char_u	*mi_end;		
    char_u	*mi_fend;		
    char_u	*mi_cend;		
					

    
    char_u	mi_fword[MAXWLEN + 1];	
    int		mi_fwordlen;		

    
    int		mi_prefarridx;		
					
    int		mi_prefcnt;		
    int		mi_prefixlen;		
    int		mi_cprefixlen;		
					

    
    int		mi_compoff;		
    char_u	mi_compflags[MAXWLEN];	
    int		mi_complen;		
    int		mi_compextra;		

    
    int		mi_result;		
    int		mi_capflags;		
    win_T	*mi_win;		

    
    int		mi_result2;		
    char_u	*mi_end2;		
} matchinf_T;


static int spell_mb_isword_class(int cl, win_T *wp);








static void find_word(matchinf_T *mip, int mode);
static void find_prefix(matchinf_T *mip, int mode);
static int fold_more(matchinf_T *mip);
static void spell_load_cb(char_u *fname, void *cookie);
static int count_syllables(slang_T *slang, char_u *word);
static void clear_midword(win_T *buf);
static void use_midword(slang_T *lp, win_T *buf);
static int find_region(char_u *rp, char_u *region);
static void spell_soundfold_sofo(slang_T *slang, char_u *inword, char_u *res);
static void spell_soundfold_sal(slang_T *slang, char_u *inword, char_u *res);
static void spell_soundfold_wsal(slang_T *slang, char_u *inword, char_u *res);
static void dump_word(slang_T *slang, char_u *word, char_u *pat, int *dir, int round, int flags, linenr_T lnum);
static linenr_T dump_prefixes(slang_T *slang, char_u *word, char_u *pat, int *dir, int round, int flags, linenr_T startlnum);


    int spell_check( win_T	*wp, char_u	*ptr, hlf_T	*attrp, int		*capcol, int		docount)





{
    matchinf_T	mi;		
				
    int		nrlen = 0;	
    int		c;
    int		wrongcaplen = 0;
    int		lpi;
    int		count_word = docount;
    int		use_camel_case = *wp->w_s->b_p_spo != NUL;
    int		camel_case = 0;

    
    
    if (*ptr <= ' ')
	return 1;

    
    if (wp->w_s->b_langp.ga_len == 0)
	return 1;

    CLEAR_FIELD(mi);

    
    
    
    if (*ptr >= '0' && *ptr <= '9')
    {
	if (*ptr == '0' && (ptr[1] == 'b' || ptr[1] == 'B'))
	    mi.mi_end = skipbin(ptr + 2);
	else if (*ptr == '0' && (ptr[1] == 'x' || ptr[1] == 'X'))
	    mi.mi_end = skiphex(ptr + 2);
	else mi.mi_end = skipdigits(ptr);
	nrlen = (int)(mi.mi_end - ptr);
    }

    
    mi.mi_word = ptr;
    mi.mi_fend = ptr;
    if (spell_iswordp(mi.mi_fend, wp))
    {
	int prev_upper;
	int this_upper = FALSE;  

	if (use_camel_case)
	{
	    c = PTR2CHAR(mi.mi_fend);
	    this_upper = SPELL_ISUPPER(c);
	}

	do {
	    MB_PTR_ADV(mi.mi_fend);
	    if (use_camel_case)
	    {
		prev_upper = this_upper;
		c = PTR2CHAR(mi.mi_fend);
		this_upper = SPELL_ISUPPER(c);
		camel_case = !prev_upper && this_upper;
	    }
	} while (*mi.mi_fend != NUL && spell_iswordp(mi.mi_fend, wp)
							       && !camel_case);

	if (capcol != NULL && *capcol == 0 && wp->w_s->b_cap_prog != NULL)
	{
	    
	    c = PTR2CHAR(ptr);
	    if (!SPELL_ISUPPER(c))
		wrongcaplen = (int)(mi.mi_fend - ptr);
	}
    }
    if (capcol != NULL)
	*capcol = -1;

    
    
    mi.mi_end = mi.mi_fend;

    
    mi.mi_capflags = 0;
    mi.mi_cend = NULL;
    mi.mi_win = wp;

    
    
    if (*mi.mi_fend != NUL)
	MB_PTR_ADV(mi.mi_fend);

    (void)spell_casefold(wp, ptr, (int)(mi.mi_fend - ptr), mi.mi_fword, MAXWLEN + 1);
    mi.mi_fwordlen = (int)STRLEN(mi.mi_fword);

    if (camel_case && mi.mi_fwordlen > 0)
	
	mi.mi_fword[mi.mi_fwordlen - 1] = ' ';

    
    mi.mi_result = SP_BAD;
    mi.mi_result2 = SP_BAD;

    
    for (lpi = 0; lpi < wp->w_s->b_langp.ga_len; ++lpi)
    {
	mi.mi_lp = LANGP_ENTRY(wp->w_s->b_langp, lpi);

	
	
	if (mi.mi_lp->lp_slang->sl_fidxs == NULL)
	    continue;

	
	find_word(&mi, FIND_FOLDWORD);

	
	find_word(&mi, FIND_KEEPWORD);

	
	find_prefix(&mi, FIND_FOLDWORD);

	
	
	if (mi.mi_lp->lp_slang->sl_nobreak && mi.mi_result == SP_BAD && mi.mi_result2 != SP_BAD)
	{
	    mi.mi_result = mi.mi_result2;
	    mi.mi_end = mi.mi_end2;
	}

	
	if (count_word && mi.mi_result == SP_OK)
	{
	    count_common_word(mi.mi_lp->lp_slang, ptr, (int)(mi.mi_end - ptr), 1);
	    count_word = FALSE;
	}
    }

    if (mi.mi_result != SP_OK)
    {
	
	
	if (nrlen > 0)
	{
	    if (mi.mi_result == SP_BAD || mi.mi_result == SP_BANNED)
		return nrlen;
	}

	
	
	else if (!spell_iswordp_nmw(ptr, wp))
	{
	    if (capcol != NULL && wp->w_s->b_cap_prog != NULL)
	    {
		regmatch_T	regmatch;
		int		r;

		
		regmatch.regprog = wp->w_s->b_cap_prog;
		regmatch.rm_ic = FALSE;
		r = vim_regexec(&regmatch, ptr, 0);
		wp->w_s->b_cap_prog = regmatch.regprog;
		if (r)
		    *capcol = (int)(regmatch.endp[0] - ptr);
	    }

	    if (has_mbyte)
		return (*mb_ptr2len)(ptr);
	    return 1;
	}
	else if (mi.mi_end == ptr)
	    
	    
	    MB_PTR_ADV(mi.mi_end);
	else if (mi.mi_result == SP_BAD && LANGP_ENTRY(wp->w_s->b_langp, 0)->lp_slang->sl_nobreak)
	{
	    char_u	*p, *fp;
	    int		save_result = mi.mi_result;

	    
	    
	    mi.mi_lp = LANGP_ENTRY(wp->w_s->b_langp, 0);
	    if (mi.mi_lp->lp_slang->sl_fidxs != NULL)
	    {
		p = mi.mi_word;
		fp = mi.mi_fword;
		for (;;)
		{
		    MB_PTR_ADV(p);
		    MB_PTR_ADV(fp);
		    if (p >= mi.mi_end)
			break;
		    mi.mi_compoff = (int)(fp - mi.mi_fword);
		    find_word(&mi, FIND_COMPOUND);
		    if (mi.mi_result != SP_BAD)
		    {
			mi.mi_end = p;
			break;
		    }
		}
		mi.mi_result = save_result;
	    }
	}

	if (mi.mi_result == SP_BAD || mi.mi_result == SP_BANNED)
	    *attrp = HLF_SPB;
	else if (mi.mi_result == SP_RARE)
	    *attrp = HLF_SPR;
	else *attrp = HLF_SPL;
    }

    if (wrongcaplen > 0 && (mi.mi_result == SP_OK || mi.mi_result == SP_RARE))
    {
	
	*attrp = HLF_SPC;
	return wrongcaplen;
    }

    return (int)(mi.mi_end - ptr);
}


    static void find_word(matchinf_T *mip, int mode)
{
    idx_T	arridx = 0;
    int		endlen[MAXWLEN];    
    idx_T	endidx[MAXWLEN];    
    int		endidxcnt = 0;
    int		len;
    int		wlen = 0;
    int		flen;
    int		c;
    char_u	*ptr;
    idx_T	lo, hi, m;
    char_u	*s;
    char_u	*p;
    int		res = SP_BAD;
    slang_T	*slang = mip->mi_lp->lp_slang;
    unsigned	flags;
    char_u	*byts;
    idx_T	*idxs;
    int		word_ends;
    int		prefix_found;
    int		nobreak_result;

    if (mode == FIND_KEEPWORD || mode == FIND_KEEPCOMPOUND)
    {
	
	ptr = mip->mi_word;
	flen = 9999;		    
	byts = slang->sl_kbyts;
	idxs = slang->sl_kidxs;

	if (mode == FIND_KEEPCOMPOUND)
	    
	    wlen += mip->mi_compoff;
    }
    else {
	
	ptr = mip->mi_fword;
	flen = mip->mi_fwordlen;    
	byts = slang->sl_fbyts;
	idxs = slang->sl_fidxs;

	if (mode == FIND_PREFIX)
	{
	    
	    wlen = mip->mi_prefixlen;
	    flen -= mip->mi_prefixlen;
	}
	else if (mode == FIND_COMPOUND)
	{
	    
	    wlen = mip->mi_compoff;
	    flen -= mip->mi_compoff;
	}

    }

    if (byts == NULL)
	return;			

    
    for (;;)
    {
	if (flen <= 0 && *mip->mi_fend != NUL)
	    flen = fold_more(mip);

	len = byts[arridx++];

	
	
	if (byts[arridx] == 0)
	{
	    if (endidxcnt == MAXWLEN)
	    {
		
		emsg(_(e_format_error_in_spell_file));
		return;
	    }
	    endlen[endidxcnt] = wlen;
	    endidx[endidxcnt++] = arridx++;
	    --len;

	    
	    
	    while (len > 0 && byts[arridx] == 0)
	    {
		++arridx;
		--len;
	    }
	    if (len == 0)
		break;	    
	}

	
	if (ptr[wlen] == NUL)
	    break;

	
	c = ptr[wlen];
	if (c == TAB)	    
	    c = ' ';
	lo = arridx;
	hi = arridx + len - 1;
	while (lo < hi)
	{
	    m = (lo + hi) / 2;
	    if (byts[m] > c)
		hi = m - 1;
	    else if (byts[m] < c)
		lo = m + 1;
	    else {
		lo = hi = m;
		break;
	    }
	}

	
	if (hi < lo || byts[lo] != c)
	    break;

	
	arridx = idxs[lo];
	++wlen;
	--flen;

	
	
	if (c == ' ')
	{
	    for (;;)
	    {
		if (flen <= 0 && *mip->mi_fend != NUL)
		    flen = fold_more(mip);
		if (ptr[wlen] != ' ' && ptr[wlen] != TAB)
		    break;
		++wlen;
		--flen;
	    }
	}
    }

    
    while (endidxcnt > 0)
    {
	--endidxcnt;
	arridx = endidx[endidxcnt];
	wlen = endlen[endidxcnt];

	if ((*mb_head_off)(ptr, ptr + wlen) > 0)
	    continue;	    
	if (spell_iswordp(ptr + wlen, mip->mi_win))
	{
	    if (slang->sl_compprog == NULL && !slang->sl_nobreak)
		continue;	    
	    word_ends = FALSE;
	}
	else word_ends = TRUE;
	
	
	prefix_found = FALSE;

	if (mode != FIND_KEEPWORD && has_mbyte)
	{
	    
	    
	    
	    p = mip->mi_word;
	    if (STRNCMP(ptr, p, wlen) != 0)
	    {
		for (s = ptr; s < ptr + wlen; MB_PTR_ADV(s))
		    MB_PTR_ADV(p);
		wlen = (int)(p - mip->mi_word);
	    }
	}

	
	
	
	
	res = SP_BAD;
	for (len = byts[arridx - 1]; len > 0 && byts[arridx] == 0;
							      --len, ++arridx)
	{
	    flags = idxs[arridx];

	    
	    
	    
	    
	    if (mode == FIND_FOLDWORD)
	    {
		if (mip->mi_cend != mip->mi_word + wlen)
		{
		    
		    
		    mip->mi_cend = mip->mi_word + wlen;
		    mip->mi_capflags = captype(mip->mi_word, mip->mi_cend);
		}

		if (mip->mi_capflags == WF_KEEPCAP || !spell_valid_case(mip->mi_capflags, flags))
		    continue;
	    }

	    
	    
	    
	    else if (mode == FIND_PREFIX && !prefix_found)
	    {
		c = valid_word_prefix(mip->mi_prefcnt, mip->mi_prefarridx, flags, mip->mi_word + mip->mi_cprefixlen, slang, FALSE);


		if (c == 0)
		    continue;

		
		if (c & WF_RAREPFX)
		    flags |= WF_RARE;
		prefix_found = TRUE;
	    }

	    if (slang->sl_nobreak)
	    {
		if ((mode == FIND_COMPOUND || mode == FIND_KEEPCOMPOUND)
			&& (flags & WF_BANNED) == 0)
		{
		    
		    
		    mip->mi_result = SP_OK;
		    break;
		}
	    }

	    else if ((mode == FIND_COMPOUND || mode == FIND_KEEPCOMPOUND || !word_ends))
	    {
		
		
		
		
		
		if (((unsigned)flags >> 24) == 0 || wlen - mip->mi_compoff < slang->sl_compminlen)
		    continue;
		
		
		if (has_mbyte && slang->sl_compminlen > 0 && mb_charlen_len(mip->mi_word + mip->mi_compoff, wlen - mip->mi_compoff) < slang->sl_compminlen)


			continue;

		
		
		if (!word_ends && mip->mi_complen + mip->mi_compextra + 2 > slang->sl_compmax && slang->sl_compsylmax == MAXWLEN)

		    continue;

		
		
		if (mip->mi_complen > 0 && (flags & WF_NOCOMPBEF))
		    continue;
		if (!word_ends && (flags & WF_NOCOMPAFT))
		    continue;

		
		if (!byte_in_str(mip->mi_complen == 0 ? slang->sl_compstartflags : slang->sl_compallflags, ((unsigned)flags >> 24)))


		    continue;

		
		
		if (match_checkcompoundpattern(ptr, wlen, &slang->sl_comppat))
		    continue;

		if (mode == FIND_COMPOUND)
		{
		    int	    capflags;

		    
		    
		    if (has_mbyte && STRNCMP(ptr, mip->mi_word, mip->mi_compoff) != 0)
		    {
			
			p = mip->mi_word;
			for (s = ptr; s < ptr + mip->mi_compoff; MB_PTR_ADV(s))
			    MB_PTR_ADV(p);
		    }
		    else p = mip->mi_word + mip->mi_compoff;
		    capflags = captype(p, mip->mi_word + wlen);
		    if (capflags == WF_KEEPCAP || (capflags == WF_ALLCAP && (flags & WF_FIXCAP) != 0))
			continue;

		    if (capflags != WF_ALLCAP)
		    {
			
			
			
			
			MB_PTR_BACK(mip->mi_word, p);
			if (spell_iswordp_nmw(p, mip->mi_win)
				? capflags == WF_ONECAP : (flags & WF_ONECAP) != 0 && capflags != WF_ONECAP)

			    continue;
		    }
		}

		
		
		
		mip->mi_compflags[mip->mi_complen] = ((unsigned)flags >> 24);
		mip->mi_compflags[mip->mi_complen + 1] = NUL;
		if (word_ends)
		{
		    char_u	fword[MAXWLEN];

		    if (slang->sl_compsylmax < MAXWLEN)
		    {
			
			if (ptr == mip->mi_word)
			    (void)spell_casefold(mip->mi_win, ptr, wlen, fword, MAXWLEN);
			else vim_strncpy(fword, ptr, endlen[endidxcnt]);
		    }
		    if (!can_compound(slang, fword, mip->mi_compflags))
			continue;
		}
		else if (slang->sl_comprules != NULL && !match_compoundrule(slang, mip->mi_compflags))
		    
		    
		    continue;
	    }

	    
	    else if (flags & WF_NEEDCOMP)
		continue;

	    nobreak_result = SP_OK;

	    if (!word_ends)
	    {
		int	save_result = mip->mi_result;
		char_u	*save_end = mip->mi_end;
		langp_T	*save_lp = mip->mi_lp;
		int	lpi;

		
		
		
		
		
		if (slang->sl_nobreak)
		    mip->mi_result = SP_BAD;

		
		mip->mi_compoff = endlen[endidxcnt];
		if (has_mbyte && mode == FIND_KEEPWORD)
		{
		    
		    
		    
		    
		    p = mip->mi_fword;
		    if (STRNCMP(ptr, p, wlen) != 0)
		    {
			for (s = ptr; s < ptr + wlen; MB_PTR_ADV(s))
			    MB_PTR_ADV(p);
			mip->mi_compoff = (int)(p - mip->mi_fword);
		    }
		}

		c = mip->mi_compoff;

		++mip->mi_complen;
		if (flags & WF_COMPROOT)
		    ++mip->mi_compextra;

		
		
		for (lpi = 0; lpi < mip->mi_win->w_s->b_langp.ga_len; ++lpi)
		{
		    if (slang->sl_nobreak)
		    {
			mip->mi_lp = LANGP_ENTRY(mip->mi_win->w_s->b_langp, lpi);
			if (mip->mi_lp->lp_slang->sl_fidxs == NULL || !mip->mi_lp->lp_slang->sl_nobreak)
			    continue;
		    }

		    find_word(mip, FIND_COMPOUND);

		    
		    
		    
		    if (!slang->sl_nobreak || mip->mi_result == SP_BAD)
		    {
			
			mip->mi_compoff = wlen;
			find_word(mip, FIND_KEEPCOMPOUND);


	    
	    
			if (!slang->sl_nobreak || mip->mi_result == SP_BAD)
			{
			    
			    mip->mi_compoff = c;
			    find_prefix(mip, FIND_COMPOUND);
			}

		    }

		    if (!slang->sl_nobreak)
			break;
		}
		--mip->mi_complen;
		if (flags & WF_COMPROOT)
		    --mip->mi_compextra;
		mip->mi_lp = save_lp;

		if (slang->sl_nobreak)
		{
		    nobreak_result = mip->mi_result;
		    mip->mi_result = save_result;
		    mip->mi_end = save_end;
		}
		else {
		    if (mip->mi_result == SP_OK)
			break;
		    continue;
		}
	    }

	    if (flags & WF_BANNED)
		res = SP_BANNED;
	    else if (flags & WF_REGION)
	    {
		
		if ((mip->mi_lp->lp_region & (flags >> 16)) != 0)
		    res = SP_OK;
		else res = SP_LOCAL;
	    }
	    else if (flags & WF_RARE)
		res = SP_RARE;
	    else res = SP_OK;

	    
	    
	    
	    if (nobreak_result == SP_BAD)
	    {
		if (mip->mi_result2 > res)
		{
		    mip->mi_result2 = res;
		    mip->mi_end2 = mip->mi_word + wlen;
		}
		else if (mip->mi_result2 == res && mip->mi_end2 < mip->mi_word + wlen)
		    mip->mi_end2 = mip->mi_word + wlen;
	    }
	    else if (mip->mi_result > res)
	    {
		mip->mi_result = res;
		mip->mi_end = mip->mi_word + wlen;
	    }
	    else if (mip->mi_result == res && mip->mi_end < mip->mi_word + wlen)
		mip->mi_end = mip->mi_word + wlen;

	    if (mip->mi_result == SP_OK)
		break;
	}

	if (mip->mi_result == SP_OK)
	    break;
    }
}


    int match_checkcompoundpattern( char_u	*ptr, int		wlen, garray_T	*gap)



{
    int		i;
    char_u	*p;
    int		len;

    for (i = 0; i + 1 < gap->ga_len; i += 2)
    {
	p = ((char_u **)gap->ga_data)[i + 1];
	if (STRNCMP(ptr + wlen, p, STRLEN(p)) == 0)
	{
	    
	    
	    p = ((char_u **)gap->ga_data)[i];
	    len = (int)STRLEN(p);
	    if (len <= wlen && STRNCMP(ptr + wlen - len, p, len) == 0)
		return TRUE;
	}
    }
    return FALSE;
}


    int can_compound(slang_T *slang, char_u *word, char_u *flags)
{
    char_u	uflags[MAXWLEN * 2];
    int		i;
    char_u	*p;

    if (slang->sl_compprog == NULL)
	return FALSE;
    if (enc_utf8)
    {
	
	p = uflags;
	for (i = 0; flags[i] != NUL; ++i)
	    p += utf_char2bytes(flags[i], p);
	*p = NUL;
	p = uflags;
    }
    else p = flags;
    if (!vim_regexec_prog(&slang->sl_compprog, FALSE, p, 0))
	return FALSE;

    
    
    
    if (slang->sl_compsylmax < MAXWLEN && count_syllables(slang, word) > slang->sl_compsylmax)
	return (int)STRLEN(flags) < slang->sl_compmax;
    return TRUE;
}


    int match_compoundrule(slang_T *slang, char_u *compflags)
{
    char_u	*p;
    int		i;
    int		c;

    
    for (p = slang->sl_comprules; *p != NUL; ++p)
    {
	
	
	for (i = 0; ; ++i)
	{
	    c = compflags[i];
	    if (c == NUL)
		
		return TRUE;
	    if (*p == '/' || *p == NUL)
		break;  
	    if (*p == '[')
	    {
		int match = FALSE;

		
		++p;
		while (*p != ']' && *p != NUL)
		    if (*p++ == c)
			match = TRUE;
		if (!match)
		    break;  
	    }
	    else if (*p != c)
		break;  
	    ++p;
	}

	
	p = vim_strchr(p, '/');
	if (p == NULL)
	    break;
    }

    
    
    return FALSE;
}


    int valid_word_prefix( int		totprefcnt, int		arridx, int		flags, char_u	*word, slang_T	*slang, int		cond_req)






{
    int		prefcnt;
    int		pidx;
    regprog_T	**rp;
    int		prefid;

    prefid = (unsigned)flags >> 24;
    for (prefcnt = totprefcnt - 1; prefcnt >= 0; --prefcnt)
    {
	pidx = slang->sl_pidxs[arridx + prefcnt];

	
	if (prefid != (pidx & 0xff))
	    continue;

	
	
	if ((flags & WF_HAS_AFF) && (pidx & WF_PFX_NC))
	    continue;

	
	
	rp = &slang->sl_prefprog[((unsigned)pidx >> 8) & 0xffff];
	if (*rp != NULL)
	{
	    if (!vim_regexec_prog(rp, FALSE, word, 0))
		continue;
	}
	else if (cond_req)
	    continue;

	
	return pidx;
    }
    return 0;
}


    static void find_prefix(matchinf_T *mip, int mode)
{
    idx_T	arridx = 0;
    int		len;
    int		wlen = 0;
    int		flen;
    int		c;
    char_u	*ptr;
    idx_T	lo, hi, m;
    slang_T	*slang = mip->mi_lp->lp_slang;
    char_u	*byts;
    idx_T	*idxs;

    byts = slang->sl_pbyts;
    if (byts == NULL)
	return;			

    
    
    ptr = mip->mi_fword;
    flen = mip->mi_fwordlen;    
    if (mode == FIND_COMPOUND)
    {
	
	ptr += mip->mi_compoff;
	flen -= mip->mi_compoff;
    }
    idxs = slang->sl_pidxs;

    
    for (;;)
    {
	if (flen == 0 && *mip->mi_fend != NUL)
	    flen = fold_more(mip);

	len = byts[arridx++];

	
	
	if (byts[arridx] == 0)
	{
	    
	    
	    
	    
	    mip->mi_prefarridx = arridx;
	    mip->mi_prefcnt = len;
	    while (len > 0 && byts[arridx] == 0)
	    {
		++arridx;
		--len;
	    }
	    mip->mi_prefcnt -= len;

	    
	    mip->mi_prefixlen = wlen;
	    if (mode == FIND_COMPOUND)
		
		mip->mi_prefixlen += mip->mi_compoff;

	    if (has_mbyte)
	    {
		
		mip->mi_cprefixlen = nofold_len(mip->mi_fword, mip->mi_prefixlen, mip->mi_word);
	    }
	    else mip->mi_cprefixlen = mip->mi_prefixlen;
	    find_word(mip, FIND_PREFIX);


	    if (len == 0)
		break;	    
	}

	
	if (ptr[wlen] == NUL)
	    break;

	
	c = ptr[wlen];
	lo = arridx;
	hi = arridx + len - 1;
	while (lo < hi)
	{
	    m = (lo + hi) / 2;
	    if (byts[m] > c)
		hi = m - 1;
	    else if (byts[m] < c)
		lo = m + 1;
	    else {
		lo = hi = m;
		break;
	    }
	}

	
	if (hi < lo || byts[lo] != c)
	    break;

	
	arridx = idxs[lo];
	++wlen;
	--flen;
    }
}


    static int fold_more(matchinf_T *mip)
{
    int		flen;
    char_u	*p;

    p = mip->mi_fend;
    do MB_PTR_ADV(mip->mi_fend);
    while (*mip->mi_fend != NUL && spell_iswordp(mip->mi_fend, mip->mi_win));

    
    if (*mip->mi_fend != NUL)
	MB_PTR_ADV(mip->mi_fend);

    (void)spell_casefold(mip->mi_win, p, (int)(mip->mi_fend - p), mip->mi_fword + mip->mi_fwordlen, MAXWLEN - mip->mi_fwordlen);

    flen = (int)STRLEN(mip->mi_fword + mip->mi_fwordlen);
    mip->mi_fwordlen += flen;
    return flen;
}


    int spell_valid_case( int	    wordflags, int	    treeflags)


{
    return ((wordflags == WF_ALLCAP && (treeflags & WF_FIXCAP) == 0)
	    || ((treeflags & (WF_ALLCAP | WF_KEEPCAP)) == 0 && ((treeflags & WF_ONECAP) == 0 || (wordflags & WF_ONECAP) != 0)));

}


    int spell_check_window(win_T *wp)
{
    return wp->w_p_spell && *wp->w_s->b_p_spl != NUL && wp->w_s->b_langp.ga_len > 0 && *(char **)(wp->w_s->b_langp.ga_data) != NULL;


}


    static int no_spell_checking(win_T *wp)
{
    if (spell_check_window(wp))
	return FALSE;
    emsg(_(e_spell_checking_is_not_possible));
    return TRUE;
}


    int spell_move_to( win_T	*wp, int		dir, int		allwords, int		curline, hlf_T	*attrp)





				
{
    linenr_T	lnum;
    pos_T	found_pos;
    int		found_len = 0;
    char_u	*line;
    char_u	*p;
    char_u	*endp;
    hlf_T	attr = 0;
    int		len;

    int		has_syntax = syntax_present(wp);

    int		col;
    int		can_spell;
    char_u	*buf = NULL;
    int		buflen = 0;
    int		skip = 0;
    int		capcol = -1;
    int		found_one = FALSE;
    int		wrapped = FALSE;

    if (no_spell_checking(wp))
	return 0;

    
    lnum = wp->w_cursor.lnum;
    CLEAR_POS(&found_pos);

    while (!got_int)
    {
	int empty_line;

	line = ml_get_buf(wp->w_buffer, lnum, FALSE);

	len = (int)STRLEN(line);
	if (buflen < len + MAXWLEN + 2)
	{
	    vim_free(buf);
	    buflen = len + MAXWLEN + 2;
	    buf = alloc(buflen);
	    if (buf == NULL)
		break;
	}

	
	if (lnum == 1)
	    capcol = 0;

	
	if (capcol == 0)
	    capcol = getwhitecols(line);
	else if (curline && wp == curwin)
	{
	    
	    col = getwhitecols(line);
	    if (check_need_cap(lnum, col))
		capcol = col;

	    
	    
	    line = ml_get_buf(wp->w_buffer, lnum, FALSE);
	}

	
	
	
	empty_line = *skipwhite(line) == NUL;
	STRCPY(buf, line);
	if (lnum < wp->w_buffer->b_ml.ml_line_count)
	    spell_cat_line(buf + STRLEN(buf), ml_get_buf(wp->w_buffer, lnum + 1, FALSE), MAXWLEN);

	p = buf + skip;
	endp = buf + len;
	while (p < endp)
	{
	    
	    
	    if (dir == BACKWARD && lnum == wp->w_cursor.lnum && !wrapped && (colnr_T)(p - buf) >= wp->w_cursor.col)


		break;

	    
	    attr = HLF_COUNT;
	    len = spell_check(wp, p, &attr, &capcol, FALSE);

	    if (attr != HLF_COUNT)
	    {
		
		if (allwords || attr == HLF_SPB)
		{
		    
		    
		    if (dir == BACKWARD || lnum != wp->w_cursor.lnum || (wrapped || (colnr_T)(curline ? p - buf + len : p - buf)



						  > wp->w_cursor.col))
		    {

			if (has_syntax)
			{
			    col = (int)(p - buf);
			    (void)syn_get_id(wp, lnum, (colnr_T)col, FALSE, &can_spell, FALSE);
			    if (!can_spell)
				attr = HLF_COUNT;
			}
			else  can_spell = TRUE;


			if (can_spell)
			{
			    found_one = TRUE;
			    found_pos.lnum = lnum;
			    found_pos.col = (int)(p - buf);
			    found_pos.coladd = 0;
			    if (dir == FORWARD)
			    {
				
				wp->w_cursor = found_pos;
				vim_free(buf);
				if (attrp != NULL)
				    *attrp = attr;
				return len;
			    }
			    else if (curline)
				
				
				found_pos.col += len;
			    found_len = len;
			}
		    }
		    else found_one = TRUE;
		}
	    }

	    
	    p += len;
	    capcol -= len;
	}

	if (dir == BACKWARD && found_pos.lnum != 0)
	{
	    
	    wp->w_cursor = found_pos;
	    vim_free(buf);
	    return found_len;
	}

	if (curline)
	    break;	

	
	
	if (lnum == wp->w_cursor.lnum && wrapped)
	    break;

	
	if (dir == BACKWARD)
	{
	    if (lnum > 1)
		--lnum;
	    else if (!p_ws)
		break;	    
	    else {
		
		
		lnum = wp->w_buffer->b_ml.ml_line_count;
		wrapped = TRUE;
		if (!shortmess(SHM_SEARCH))
		    give_warning((char_u *)_(top_bot_msg), TRUE);
	    }
	    capcol = -1;
	}
	else {
	    if (lnum < wp->w_buffer->b_ml.ml_line_count)
		++lnum;
	    else if (!p_ws)
		break;	    
	    else {
		
		
		lnum = 1;
		wrapped = TRUE;
		if (!shortmess(SHM_SEARCH))
		    give_warning((char_u *)_(bot_top_msg), TRUE);
	    }

	    
	    
	    if (lnum == wp->w_cursor.lnum && !found_one)
		break;

	    
	    
	    if (attr == HLF_COUNT)
		skip = (int)(p - endp);
	    else skip = 0;

	    
	    --capcol;

	    
	    if (empty_line)
		capcol = 0;
	}

	line_breakcheck();
    }

    vim_free(buf);
    return 0;
}


    void spell_cat_line(char_u *buf, char_u *line, int maxlen)
{
    char_u	*p;
    int		n;

    p = skipwhite(line);
    while (vim_strchr((char_u *)"*#/\"\t", *p) != NULL)
	p = skipwhite(p + 1);

    if (*p != NUL)
    {
	
	
	n = (int)(p - line) + 1;
	if (n < maxlen - 1)
	{
	    vim_memset(buf, ' ', n);
	    vim_strncpy(buf +  n, p, maxlen - 1 - n);
	}
    }
}


typedef struct spelload_S {
    char_u  sl_lang[MAXWLEN + 1];	
    slang_T *sl_slang;			
    int	    sl_nobreak;			
} spelload_T;


    static void spell_load_lang(char_u *lang)
{
    char_u	fname_enc[85];
    int		r;
    spelload_T	sl;
    int		round;

    
    
    STRCPY(sl.sl_lang, lang);
    sl.sl_slang = NULL;
    sl.sl_nobreak = FALSE;

    
    
    for (round = 1; round <= 2; ++round)
    {
	
	vim_snprintf((char *)fname_enc, sizeof(fname_enc) - 5,  "spell/%s_%s.spl",  "spell/%s.%s.spl",  lang, spell_enc());





	r = do_in_runtimepath(fname_enc, 0, spell_load_cb, &sl);

	if (r == FAIL && *sl.sl_lang != NUL)
	{
	    
	    vim_snprintf((char *)fname_enc, sizeof(fname_enc) - 5,  "spell/%s_ascii.spl",  "spell/%s.ascii.spl",  lang);





	    r = do_in_runtimepath(fname_enc, 0, spell_load_cb, &sl);

	    if (r == FAIL && *sl.sl_lang != NUL && round == 1 && apply_autocmds(EVENT_SPELLFILEMISSING, lang, curbuf->b_fname, FALSE, curbuf))

		continue;
	    break;
	}
	break;
    }

    if (r == FAIL)
    {
	smsg(  _("Warning: Cannot find word list \"%s_%s.spl\" or \"%s_ascii.spl\""),  _("Warning: Cannot find word list \"%s.%s.spl\" or \"%s.ascii.spl\""),  lang, spell_enc(), lang);





    }
    else if (sl.sl_slang != NULL)
    {
	
	STRCPY(fname_enc + STRLEN(fname_enc) - 3, "add.spl");
	do_in_runtimepath(fname_enc, DIP_ALL, spell_load_cb, &sl);
    }
}


    char_u * spell_enc(void)
{

    if (STRLEN(p_enc) < 60 && STRCMP(p_enc, "iso-8859-15") != 0)
	return p_enc;
    return (char_u *)"latin1";
}


    static void int_wordlist_spl(char_u *fname)
{
    vim_snprintf((char *)fname, MAXPATHL, SPL_FNAME_TMPL, int_wordlist, spell_enc());
}


    slang_T * slang_alloc(char_u *lang)
{
    slang_T *lp;

    lp = ALLOC_CLEAR_ONE(slang_T);
    if (lp != NULL)
    {
	if (lang != NULL)
	    lp->sl_name = vim_strsave(lang);
	ga_init2(&lp->sl_rep, sizeof(fromto_T), 10);
	ga_init2(&lp->sl_repsal, sizeof(fromto_T), 10);
	lp->sl_compmax = MAXWLEN;
	lp->sl_compsylmax = MAXWLEN;
	hash_init(&lp->sl_wordcount);
    }

    return lp;
}


    void slang_free(slang_T *lp)
{
    vim_free(lp->sl_name);
    vim_free(lp->sl_fname);
    slang_clear(lp);
    vim_free(lp);
}


    void slang_clear(slang_T *lp)
{
    garray_T	*gap;
    fromto_T	*ftp;
    salitem_T	*smp;
    int		i;
    int		round;

    VIM_CLEAR(lp->sl_fbyts);
    VIM_CLEAR(lp->sl_kbyts);
    VIM_CLEAR(lp->sl_pbyts);

    VIM_CLEAR(lp->sl_fidxs);
    VIM_CLEAR(lp->sl_kidxs);
    VIM_CLEAR(lp->sl_pidxs);

    for (round = 1; round <= 2; ++round)
    {
	gap = round == 1 ? &lp->sl_rep : &lp->sl_repsal;
	while (gap->ga_len > 0)
	{
	    ftp = &((fromto_T *)gap->ga_data)[--gap->ga_len];
	    vim_free(ftp->ft_from);
	    vim_free(ftp->ft_to);
	}
	ga_clear(gap);
    }

    gap = &lp->sl_sal;
    if (lp->sl_sofo)
    {
	
	if (gap->ga_data != NULL)
	    
	    for (i = 0; i < gap->ga_len; ++i)
		vim_free(((int **)gap->ga_data)[i]);
    }
    else  while (gap->ga_len > 0)

	{
	    smp = &((salitem_T *)gap->ga_data)[--gap->ga_len];
	    vim_free(smp->sm_lead);
	    
	    vim_free(smp->sm_to);
	    vim_free(smp->sm_lead_w);
	    vim_free(smp->sm_oneof_w);
	    vim_free(smp->sm_to_w);
	}
    ga_clear(gap);

    for (i = 0; i < lp->sl_prefixcnt; ++i)
	vim_regfree(lp->sl_prefprog[i]);
    lp->sl_prefixcnt = 0;
    VIM_CLEAR(lp->sl_prefprog);

    VIM_CLEAR(lp->sl_info);

    VIM_CLEAR(lp->sl_midword);

    vim_regfree(lp->sl_compprog);
    lp->sl_compprog = NULL;
    VIM_CLEAR(lp->sl_comprules);
    VIM_CLEAR(lp->sl_compstartflags);
    VIM_CLEAR(lp->sl_compallflags);

    VIM_CLEAR(lp->sl_syllable);
    ga_clear(&lp->sl_syl_items);

    ga_clear_strings(&lp->sl_comppat);

    hash_clear_all(&lp->sl_wordcount, WC_KEY_OFF);
    hash_init(&lp->sl_wordcount);

    hash_clear_all(&lp->sl_map_hash, 0);

    
    slang_clear_sug(lp);

    lp->sl_compmax = MAXWLEN;
    lp->sl_compminlen = 0;
    lp->sl_compsylmax = MAXWLEN;
    lp->sl_regions[0] = NUL;
}


    void slang_clear_sug(slang_T *lp)
{
    VIM_CLEAR(lp->sl_sbyts);
    VIM_CLEAR(lp->sl_sidxs);
    close_spellbuf(lp->sl_sugbuf);
    lp->sl_sugbuf = NULL;
    lp->sl_sugloaded = FALSE;
    lp->sl_sugtime = 0;
}


    static void spell_load_cb(char_u *fname, void *cookie)
{
    spelload_T	*slp = (spelload_T *)cookie;
    slang_T	*slang;

    slang = spell_load_file(fname, slp->sl_lang, NULL, FALSE);
    if (slang != NULL)
    {
	
	
	if (slp->sl_nobreak && slang->sl_add)
	    slang->sl_nobreak = TRUE;
	else if (slang->sl_nobreak)
	    slp->sl_nobreak = TRUE;

	slp->sl_slang = slang;
    }
}



    void count_common_word( slang_T	*lp, char_u	*word, int		len, int		count)




{
    hash_T	hash;
    hashitem_T	*hi;
    wordcount_T	*wc;
    char_u	buf[MAXWLEN];
    char_u	*p;

    if (len == -1)
	p = word;
    else if (len >= MAXWLEN)
	return;
    else {
	vim_strncpy(buf, word, len);
	p = buf;
    }

    hash = hash_hash(p);
    hi = hash_lookup(&lp->sl_wordcount, p, hash);
    if (HASHITEM_EMPTY(hi))
    {
	wc = alloc(sizeof(wordcount_T) + STRLEN(p));
	if (wc == NULL)
	    return;
	STRCPY(wc->wc_word, p);
	wc->wc_count = count;
	hash_add_item(&lp->sl_wordcount, hi, wc->wc_word, hash);
    }
    else {
	wc = HI2WC(hi);
	if ((wc->wc_count += count) < (unsigned)count)	
	    wc->wc_count = MAXWORDCOUNT;
    }
}


    int byte_in_str(char_u *str, int n)
{
    char_u	*p;

    for (p = str; *p != NUL; ++p)
	if (*p == n)
	    return TRUE;
    return FALSE;
}


typedef struct syl_item_S {
    char_u	sy_chars[SY_MAXLEN];	    
    int		sy_len;
} syl_item_T;


    int init_syl_tab(slang_T *slang)
{
    char_u	*p;
    char_u	*s;
    int		l;
    syl_item_T	*syl;

    ga_init2(&slang->sl_syl_items, sizeof(syl_item_T), 4);
    p = vim_strchr(slang->sl_syllable, '/');
    while (p != NULL)
    {
	*p++ = NUL;
	if (*p == NUL)	    
	    break;
	s = p;
	p = vim_strchr(p, '/');
	if (p == NULL)
	    l = (int)STRLEN(s);
	else l = (int)(p - s);
	if (l >= SY_MAXLEN)
	    return SP_FORMERROR;
	if (ga_grow(&slang->sl_syl_items, 1) == FAIL)
	    return SP_OTHERERROR;
	syl = ((syl_item_T *)slang->sl_syl_items.ga_data)
					       + slang->sl_syl_items.ga_len++;
	vim_strncpy(syl->sy_chars, s, l);
	syl->sy_len = l;
    }
    return OK;
}


    static int count_syllables(slang_T *slang, char_u *word)
{
    int		cnt = 0;
    int		skip = FALSE;
    char_u	*p;
    int		len;
    int		i;
    syl_item_T	*syl;
    int		c;

    if (slang->sl_syllable == NULL)
	return 0;

    for (p = word; *p != NUL; p += len)
    {
	
	if (*p == ' ')
	{
	    len = 1;
	    cnt = 0;
	    continue;
	}

	
	len = 0;
	for (i = 0; i < slang->sl_syl_items.ga_len; ++i)
	{
	    syl = ((syl_item_T *)slang->sl_syl_items.ga_data) + i;
	    if (syl->sy_len > len && STRNCMP(p, syl->sy_chars, syl->sy_len) == 0)
		len = syl->sy_len;
	}
	if (len != 0)	
	{
	    ++cnt;
	    skip = FALSE;
	}
	else {
	    
	    c = mb_ptr2char(p);
	    len = (*mb_ptr2len)(p);
	    if (vim_strchr(slang->sl_syllable, c) == NULL)
		skip = FALSE;	    
	    else if (!skip)
	    {
		++cnt;		    
		skip = TRUE;	    
	    }
	}
    }
    return cnt;
}


    char * did_set_spelllang(win_T *wp)
{
    garray_T	ga;
    char_u	*splp;
    char_u	*region;
    char_u	region_cp[3];
    int		filename;
    int		region_mask;
    slang_T	*slang;
    int		c;
    char_u	lang[MAXWLEN + 1];
    char_u	spf_name[MAXPATHL];
    int		len;
    char_u	*p;
    int		round;
    char_u	*spf;
    char_u	*use_region = NULL;
    int		dont_use_region = FALSE;
    int		nobreak = FALSE;
    int		i, j;
    langp_T	*lp, *lp2;
    static int	recursive = FALSE;
    char	*ret_msg = NULL;
    char_u	*spl_copy;
    bufref_T	bufref;

    set_bufref(&bufref, wp->w_buffer);

    
    
    
    if (recursive)
	return NULL;
    recursive = TRUE;

    ga_init2(&ga, sizeof(langp_T), 2);
    clear_midword(wp);

    
    
    spl_copy = vim_strsave(wp->w_s->b_p_spl);
    if (spl_copy == NULL)
	goto theend;

    wp->w_s->b_cjk = 0;

    
    for (splp = spl_copy; *splp != NUL; )
    {
	
	copy_option_part(&splp, lang, MAXWLEN, ",");
	region = NULL;
	len = (int)STRLEN(lang);

	if (!valid_spelllang(lang))
	    continue;

	if (STRCMP(lang, "cjk") == 0)
	{
	    wp->w_s->b_cjk = 1;
	    continue;
	}

	
	
	
	if (len > 4 && fnamecmp(lang + len - 4, ".spl") == 0)
	{
	    filename = TRUE;

	    
	    p = vim_strchr(gettail(lang), '_');
	    if (p != NULL && ASCII_ISALPHA(p[1]) && ASCII_ISALPHA(p[2])
						      && !ASCII_ISALPHA(p[3]))
	    {
		vim_strncpy(region_cp, p + 1, 2);
		mch_memmove(p, p + 3, len - (p - lang) - 2);
		region = region_cp;
	    }
	    else dont_use_region = TRUE;

	    
	    FOR_ALL_SPELL_LANGS(slang)
		if (fullpathcmp(lang, slang->sl_fname, FALSE, TRUE) == FPC_SAME)
		    break;
	}
	else {
	    filename = FALSE;
	    if (len > 3 && lang[len - 3] == '_')
	    {
		region = lang + len - 2;
		len -= 3;
		lang[len] = NUL;
	    }
	    else dont_use_region = TRUE;

	    
	    FOR_ALL_SPELL_LANGS(slang)
		if (STRICMP(lang, slang->sl_name) == 0)
		    break;
	}

	if (region != NULL)
	{
	    
	    
	    if (use_region != NULL && STRCMP(region, use_region) != 0)
		dont_use_region = TRUE;
	    use_region = region;
	}

	
	if (slang == NULL)
	{
	    if (filename)
		(void)spell_load_file(lang, lang, NULL, FALSE);
	    else {
		spell_load_lang(lang);
		
		
		if (!bufref_valid(&bufref))
		{
		    ret_msg = N_(e_spellfilemising_autocommand_deleted_buffer);
		    goto theend;
		}
	    }
	}

	
	FOR_ALL_SPELL_LANGS(slang)
	    if (filename ? fullpathcmp(lang, slang->sl_fname, FALSE, TRUE)
								    == FPC_SAME : STRICMP(lang, slang->sl_name) == 0)
	    {
		region_mask = REGION_ALL;
		if (!filename && region != NULL)
		{
		    
		    c = find_region(slang->sl_regions, region);
		    if (c == REGION_ALL)
		    {
			if (slang->sl_add)
			{
			    if (*slang->sl_regions != NUL)
				
				region_mask = 0;
			}
			else   smsg(_("Warning: region %s not supported"), region);



		    }
		    else region_mask = 1 << c;
		}

		if (region_mask != 0)
		{
		    if (ga_grow(&ga, 1) == FAIL)
		    {
			ga_clear(&ga);
			ret_msg = e_out_of_memory;
			goto theend;
		    }
		    LANGP_ENTRY(ga, ga.ga_len)->lp_slang = slang;
		    LANGP_ENTRY(ga, ga.ga_len)->lp_region = region_mask;
		    ++ga.ga_len;
		    use_midword(slang, wp);
		    if (slang->sl_nobreak)
			nobreak = TRUE;
		}
	    }
    }

    
    
    
    
    spf = curwin->w_s->b_p_spf;
    for (round = 0; round == 0 || *spf != NUL; ++round)
    {
	if (round == 0)
	{
	    
	    if (int_wordlist == NULL)
		continue;
	    int_wordlist_spl(spf_name);
	}
	else {
	    
	    copy_option_part(&spf, spf_name, MAXPATHL - 5, ",");
	    STRCAT(spf_name, ".spl");

	    
	    for (c = 0; c < ga.ga_len; ++c)
	    {
		p = LANGP_ENTRY(ga, c)->lp_slang->sl_fname;
		if (p != NULL && fullpathcmp(spf_name, p, FALSE, TRUE)
								== FPC_SAME)
		    break;
	    }
	    if (c < ga.ga_len)
		continue;
	}

	
	FOR_ALL_SPELL_LANGS(slang)
	    if (fullpathcmp(spf_name, slang->sl_fname, FALSE, TRUE)
								== FPC_SAME)
		break;
	if (slang == NULL)
	{
	    
	    
	    
	    if (round == 0)
		STRCPY(lang, "internal wordlist");
	    else {
		vim_strncpy(lang, gettail(spf_name), MAXWLEN);
		p = vim_strchr(lang, '.');
		if (p != NULL)
		    *p = NUL;	
	    }
	    slang = spell_load_file(spf_name, lang, NULL, TRUE);

	    
	    
	    if (slang != NULL && nobreak)
		slang->sl_nobreak = TRUE;
	}
	if (slang != NULL && ga_grow(&ga, 1) == OK)
	{
	    region_mask = REGION_ALL;
	    if (use_region != NULL && !dont_use_region)
	    {
		
		c = find_region(slang->sl_regions, use_region);
		if (c != REGION_ALL)
		    region_mask = 1 << c;
		else if (*slang->sl_regions != NUL)
		    
		    region_mask = 0;
	    }

	    if (region_mask != 0)
	    {
		LANGP_ENTRY(ga, ga.ga_len)->lp_slang = slang;
		LANGP_ENTRY(ga, ga.ga_len)->lp_sallang = NULL;
		LANGP_ENTRY(ga, ga.ga_len)->lp_replang = NULL;
		LANGP_ENTRY(ga, ga.ga_len)->lp_region = region_mask;
		++ga.ga_len;
		use_midword(slang, wp);
	    }
	}
    }

    
    ga_clear(&wp->w_s->b_langp);
    wp->w_s->b_langp = ga;

    
    
    
    for (i = 0; i < ga.ga_len; ++i)
    {
	lp = LANGP_ENTRY(ga, i);

	
	if (lp->lp_slang->sl_sal.ga_len > 0)
	    
	    lp->lp_sallang = lp->lp_slang;
	else  for (j = 0; j < ga.ga_len; ++j)

	    {
		lp2 = LANGP_ENTRY(ga, j);
		if (lp2->lp_slang->sl_sal.ga_len > 0 && STRNCMP(lp->lp_slang->sl_name, lp2->lp_slang->sl_name, 2) == 0)

		{
		    lp->lp_sallang = lp2->lp_slang;
		    break;
		}
	    }

	
	if (lp->lp_slang->sl_rep.ga_len > 0)
	    
	    lp->lp_replang = lp->lp_slang;
	else  for (j = 0; j < ga.ga_len; ++j)

	    {
		lp2 = LANGP_ENTRY(ga, j);
		if (lp2->lp_slang->sl_rep.ga_len > 0 && STRNCMP(lp->lp_slang->sl_name, lp2->lp_slang->sl_name, 2) == 0)

		{
		    lp->lp_replang = lp2->lp_slang;
		    break;
		}
	    }
    }
    redraw_win_later(wp, UPD_NOT_VALID);

theend:
    vim_free(spl_copy);
    recursive = FALSE;
    return ret_msg;
}


    static void clear_midword(win_T *wp)
{
    CLEAR_FIELD(wp->w_s->b_spell_ismw);
    VIM_CLEAR(wp->w_s->b_spell_ismw_mb);
}


    static void use_midword(slang_T *lp, win_T *wp)
{
    char_u	*p;

    if (lp->sl_midword == NULL)	    
	return;

    for (p = lp->sl_midword; *p != NUL; )
	if (has_mbyte)
	{
	    int	    c, l, n;
	    char_u  *bp;

	    c = mb_ptr2char(p);
	    l = (*mb_ptr2len)(p);
	    if (c < 256 && l <= 2)
		wp->w_s->b_spell_ismw[c] = TRUE;
	    else if (wp->w_s->b_spell_ismw_mb == NULL)
		
		wp->w_s->b_spell_ismw_mb = vim_strnsave(p, l);
	    else {
		
		n = (int)STRLEN(wp->w_s->b_spell_ismw_mb);
		bp = vim_strnsave(wp->w_s->b_spell_ismw_mb, n + l);
		if (bp != NULL)
		{
		    vim_free(wp->w_s->b_spell_ismw_mb);
		    wp->w_s->b_spell_ismw_mb = bp;
		    vim_strncpy(bp + n, p, l);
		}
	    }
	    p += l;
	}
	else wp->w_s->b_spell_ismw[*p++] = TRUE;
}


    static int find_region(char_u *rp, char_u *region)
{
    int		i;

    for (i = 0; ; i += 2)
    {
	if (rp[i] == NUL)
	    return REGION_ALL;
	if (rp[i] == region[0] && rp[i + 1] == region[1])
	    break;
    }
    return i / 2;
}


    int captype( char_u	*word, char_u	*end)


{
    char_u	*p;
    int		c;
    int		firstcap;
    int		allcap;
    int		past_second = FALSE;	

    
    for (p = word; !spell_iswordp_nmw(p, curwin); MB_PTR_ADV(p))
	if (end == NULL ? *p == NUL : p >= end)
	    return 0;	    
    if (has_mbyte)
	c = mb_ptr2char_adv(&p);
    else c = *p++;
    firstcap = allcap = SPELL_ISUPPER(c);

    
    for ( ; end == NULL ? *p != NUL : p < end; MB_PTR_ADV(p))
	if (spell_iswordp_nmw(p, curwin))
	{
	    c = PTR2CHAR(p);
	    if (!SPELL_ISUPPER(c))
	    {
		
		if (past_second && allcap)
		    return WF_KEEPCAP;
		allcap = FALSE;
	    }
	    else if (!allcap)
		
		return WF_KEEPCAP;
	    past_second = TRUE;
	}

    if (allcap)
	return WF_ALLCAP;
    if (firstcap)
	return WF_ONECAP;
    return 0;
}


    void spell_delete_wordlist(void)
{
    char_u	fname[MAXPATHL];

    if (int_wordlist != NULL)
    {
	mch_remove(int_wordlist);
	int_wordlist_spl(fname);
	mch_remove(fname);
	VIM_CLEAR(int_wordlist);
    }
}


    void spell_free_all(void)
{
    slang_T	*slang;
    buf_T	*buf;

    
    FOR_ALL_BUFFERS(buf)
	ga_clear(&buf->b_s.b_langp);

    while (first_lang != NULL)
    {
	slang = first_lang;
	first_lang = slang->sl_next;
	slang_free(slang);
    }

    spell_delete_wordlist();

    VIM_CLEAR(repl_to);
    VIM_CLEAR(repl_from);
}


    void spell_reload(void)
{
    win_T	*wp;

    
    init_spell_chartab();

    
    spell_free_all();

    
    FOR_ALL_WINDOWS(wp)
    {
	
	
	if (*wp->w_s->b_p_spl != NUL)
	{
		if (wp->w_p_spell)
		{
		    (void)did_set_spelllang(wp);
		    break;
		}
	}
    }
}


    buf_T * open_spellbuf(void)
{
    buf_T	*buf;

    buf = ALLOC_CLEAR_ONE(buf_T);
    if (buf != NULL)
    {
	buf->b_spell = TRUE;
	buf->b_p_swf = TRUE;	

	buf->b_p_key = empty_option;

	ml_open(buf);
	ml_open_file(buf);	
    }
    return buf;
}


    void close_spellbuf(buf_T *buf)
{
    if (buf != NULL)
    {
	ml_close(buf, TRUE);
	vim_free(buf);
    }
}


    void clear_spell_chartab(spelltab_T *sp)
{
    int		i;

    
    CLEAR_FIELD(sp->st_isw);
    CLEAR_FIELD(sp->st_isu);
    for (i = 0; i < 256; ++i)
    {
	sp->st_fold[i] = i;
	sp->st_upper[i] = i;
    }

    
    
    for (i = '0'; i <= '9'; ++i)
	sp->st_isw[i] = TRUE;
    for (i = 'A'; i <= 'Z'; ++i)
    {
	sp->st_isw[i] = TRUE;
	sp->st_isu[i] = TRUE;
	sp->st_fold[i] = i + 0x20;
    }
    for (i = 'a'; i <= 'z'; ++i)
    {
	sp->st_isw[i] = TRUE;
	sp->st_upper[i] = i - 0x20;
    }
}


    void init_spell_chartab(void)
{
    int	    i;

    did_set_spelltab = FALSE;
    clear_spell_chartab(&spelltab);
    if (enc_dbcs)
    {
	
	for (i = 128; i <= 255; ++i)
	    if (MB_BYTE2LEN(i) == 2)
		spelltab.st_isw[i] = TRUE;
    }
    else if (enc_utf8)
    {
	for (i = 128; i < 256; ++i)
	{
	    int f = utf_fold(i);
	    int u = utf_toupper(i);

	    spelltab.st_isu[i] = utf_isupper(i);
	    spelltab.st_isw[i] = spelltab.st_isu[i] || utf_islower(i);
	    
	    
	    
	    spelltab.st_fold[i] = (f < 256) ? f : i;
	    spelltab.st_upper[i] = (u < 256) ? u : i;
	}
    }
    else {
	
	for (i = 128; i < 256; ++i)
	{
	    if (MB_ISUPPER(i))
	    {
		spelltab.st_isw[i] = TRUE;
		spelltab.st_isu[i] = TRUE;
		spelltab.st_fold[i] = MB_TOLOWER(i);
	    }
	    else if (MB_ISLOWER(i))
	    {
		spelltab.st_isw[i] = TRUE;
		spelltab.st_upper[i] = MB_TOUPPER(i);
	    }
	}
    }
}



    int spell_iswordp( char_u	*p, win_T	*wp)


{
    char_u	*s;
    int		l;
    int		c;

    if (has_mbyte)
    {
	l = mb_ptr2len(p);
	s = p;
	if (l == 1)
	{
	    
	    if (wp->w_s->b_spell_ismw[*p])
		s = p + 1;		
	}
	else {
	    c = mb_ptr2char(p);
	    if (c < 256 ? wp->w_s->b_spell_ismw[c] : (wp->w_s->b_spell_ismw_mb != NULL && vim_strchr(wp->w_s->b_spell_ismw_mb, c) != NULL))

		s = p + l;
	}

	c = mb_ptr2char(s);
	if (c > 255)
	    return spell_mb_isword_class(mb_get_class(s), wp);
	return spelltab.st_isw[c];
    }

    return spelltab.st_isw[wp->w_s->b_spell_ismw[*p] ? p[1] : p[0]];
}


    int spell_iswordp_nmw(char_u *p, win_T *wp)
{
    int		c;

    if (has_mbyte)
    {
	c = mb_ptr2char(p);
	if (c > 255)
	    return spell_mb_isword_class(mb_get_class(p), wp);
	return spelltab.st_isw[c];
    }
    return spelltab.st_isw[*p];
}


    static int spell_mb_isword_class(int cl, win_T *wp)
{
    if (wp->w_s->b_cjk)
	
	return cl == 2 || cl == 0x2800;
    return cl >= 2 && cl != 0x2070 && cl != 0x2080 && cl != 3;
}


    static int spell_iswordp_w(int *p, win_T *wp)
{
    int		*s;

    if (*p < 256 ? wp->w_s->b_spell_ismw[*p] : (wp->w_s->b_spell_ismw_mb != NULL && vim_strchr(wp->w_s->b_spell_ismw_mb, *p) != NULL))

	s = p + 1;
    else s = p;

    if (*s > 255)
    {
	if (enc_utf8)
	    return spell_mb_isword_class(utf_class(*s), wp);
	if (enc_dbcs)
	    return spell_mb_isword_class( dbcs_class((unsigned)*s >> 8, *s & 0xff), wp);
	return 0;
    }
    return spelltab.st_isw[*s];
}


    int spell_casefold( win_T	*wp, char_u	*str, int		len, char_u	*buf, int		buflen)





{
    int		i;

    if (len >= buflen)
    {
	buf[0] = NUL;
	return FAIL;		
    }

    if (has_mbyte)
    {
	int	outi = 0;
	char_u	*p;
	int	c;

	
	for (p = str; p < str + len; )
	{
	    if (outi + MB_MAXBYTES > buflen)
	    {
		buf[outi] = NUL;
		return FAIL;
	    }
	    c = mb_cptr2char_adv(&p);

	    
	    
	    
	    if (c == 0x03a3 || c == 0x03c2)
	    {
		if (p == str + len || !spell_iswordp(p, wp))
		    c = 0x03c2;
		else c = 0x03c3;
	    }
	    else c = SPELL_TOFOLD(c);

	    outi += mb_char2bytes(c, buf + outi);
	}
	buf[outi] = NUL;
    }
    else {
	
	for (i = 0; i < len; ++i)
	    buf[i] = spelltab.st_fold[str[i]];
	buf[i] = NUL;
    }

    return OK;
}


    int check_need_cap(linenr_T lnum, colnr_T col)
{
    int		need_cap = FALSE;
    char_u	*line;
    char_u	*line_copy = NULL;
    char_u	*p;
    colnr_T	endcol;
    regmatch_T	regmatch;

    if (curwin->w_s->b_cap_prog == NULL)
	return FALSE;

    line = ml_get_curline();
    endcol = 0;
    if (getwhitecols(line) >= (int)col)
    {
	
	
	if (lnum == 1)
	    need_cap = TRUE;
	else {
	    line = ml_get(lnum - 1);
	    if (*skipwhite(line) == NUL)
		need_cap = TRUE;
	    else {
		
		line_copy = concat_str(line, (char_u *)" ");
		line = line_copy;
		endcol = (colnr_T)STRLEN(line);
	    }
	}
    }
    else endcol = col;

    if (endcol > 0)
    {
	
	regmatch.regprog = curwin->w_s->b_cap_prog;
	regmatch.rm_ic = FALSE;
	p = line + endcol;
	for (;;)
	{
	    MB_PTR_BACK(line, p);
	    if (p == line || spell_iswordp_nmw(p, curwin))
		break;
	    if (vim_regexec(&regmatch, p, 0)
					 && regmatch.endp[0] == line + endcol)
	    {
		need_cap = TRUE;
		break;
	    }
	}
	curwin->w_s->b_cap_prog = regmatch.regprog;
    }

    vim_free(line_copy);

    return need_cap;
}



    void ex_spellrepall(exarg_T *eap UNUSED)
{
    pos_T	pos = curwin->w_cursor;
    char_u	*frompat;
    int		addlen;
    char_u	*line;
    char_u	*p;
    int		save_ws = p_ws;
    linenr_T	prev_lnum = 0;

    if (repl_from == NULL || repl_to == NULL)
    {
	emsg(_(e_no_previous_spell_replacement));
	return;
    }
    addlen = (int)(STRLEN(repl_to) - STRLEN(repl_from));

    frompat = alloc(STRLEN(repl_from) + 7);
    if (frompat == NULL)
	return;
    sprintf((char *)frompat, "\\V\\<%s\\>", repl_from);
    p_ws = FALSE;

    sub_nsubs = 0;
    sub_nlines = 0;
    curwin->w_cursor.lnum = 0;
    while (!got_int)
    {
	if (do_search(NULL, '/', '/', frompat, 1L, SEARCH_KEEP, NULL) == 0 || u_save_cursor() == FAIL)
	    break;

	
	
	line = ml_get_curline();
	if (addlen <= 0 || STRNCMP(line + curwin->w_cursor.col, repl_to, STRLEN(repl_to)) != 0)
	{
	    p = alloc(STRLEN(line) + addlen + 1);
	    if (p == NULL)
		break;
	    mch_memmove(p, line, curwin->w_cursor.col);
	    STRCPY(p + curwin->w_cursor.col, repl_to);
	    STRCAT(p, line + curwin->w_cursor.col + STRLEN(repl_from));
	    ml_replace(curwin->w_cursor.lnum, p, FALSE);
	    changed_bytes(curwin->w_cursor.lnum, curwin->w_cursor.col);
	    if (curbuf->b_has_textprop && addlen != 0)
		adjust_prop_columns(curwin->w_cursor.lnum, curwin->w_cursor.col, addlen, APC_SUBSTITUTE);

	    if (curwin->w_cursor.lnum != prev_lnum)
	    {
		++sub_nlines;
		prev_lnum = curwin->w_cursor.lnum;
	    }
	    ++sub_nsubs;
	}
	curwin->w_cursor.col += (colnr_T)STRLEN(repl_to);
    }

    p_ws = save_ws;
    curwin->w_cursor = pos;
    vim_free(frompat);

    if (sub_nsubs == 0)
	semsg(_(e_not_found_str), repl_from);
    else do_sub_msg(FALSE);
}


    void onecap_copy( char_u	*word, char_u	*wcopy, int		upper)



{
    char_u	*p;
    int		c;
    int		l;

    p = word;
    if (has_mbyte)
	c = mb_cptr2char_adv(&p);
    else c = *p++;
    if (upper)
	c = SPELL_TOUPPER(c);
    else c = SPELL_TOFOLD(c);
    if (has_mbyte)
	l = mb_char2bytes(c, wcopy);
    else {
	l = 1;
	wcopy[0] = c;
    }
    vim_strncpy(wcopy + l, p, MAXWLEN - l - 1);
}


    void allcap_copy(char_u *word, char_u *wcopy)
{
    char_u	*s;
    char_u	*d;
    int		c;

    d = wcopy;
    for (s = word; *s != NUL; )
    {
	if (has_mbyte)
	    c = mb_cptr2char_adv(&s);
	else c = *s++;

	
	
	if (enc_latin1like && c == 0xdf)
	{
	    c = 'S';
	    if (d - wcopy >= MAXWLEN - 1)
		break;
	    *d++ = c;
	}
	else c = SPELL_TOUPPER(c);

	if (has_mbyte)
	{
	    if (d - wcopy >= MAXWLEN - MB_MAXBYTES)
		break;
	    d += mb_char2bytes(c, d);
	}
	else {
	    if (d - wcopy >= MAXWLEN - 1)
		break;
	    *d++ = c;
	}
    }
    *d = NUL;
}


    int nofold_len(char_u *fword, int flen, char_u *word)
{
    char_u	*p;
    int		i = 0;

    for (p = fword; p < fword + flen; MB_PTR_ADV(p))
	++i;
    for (p = word; i > 0; MB_PTR_ADV(p))
	--i;
    return (int)(p - word);
}


    void make_case_word(char_u *fword, char_u *cword, int flags)
{
    if (flags & WF_ALLCAP)
	
	allcap_copy(fword, cword);
    else if (flags & WF_ONECAP)
	
	onecap_copy(fword, cword, TRUE);
    else  STRCPY(cword, fword);

}



    char_u * eval_soundfold(char_u *word)
{
    langp_T	*lp;
    char_u	sound[MAXWLEN];
    int		lpi;

    if (curwin->w_p_spell && *curwin->w_s->b_p_spl != NUL)
	
	for (lpi = 0; lpi < curwin->w_s->b_langp.ga_len; ++lpi)
	{
	    lp = LANGP_ENTRY(curwin->w_s->b_langp, lpi);
	    if (lp->lp_slang->sl_sal.ga_len > 0)
	    {
		
		spell_soundfold(lp->lp_slang, word, FALSE, sound);
		return vim_strsave(sound);
	    }
	}

    
    return vim_strsave(word);
}



    void spell_soundfold( slang_T	*slang, char_u	*inword, int		folded, char_u	*res)




{
    char_u	fword[MAXWLEN];
    char_u	*word;

    if (slang->sl_sofo)
	
	spell_soundfold_sofo(slang, inword, res);
    else {
	
	if (folded)
	    word = inword;
	else {
	    (void)spell_casefold(curwin, inword, (int)STRLEN(inword), fword, MAXWLEN);
	    word = fword;
	}

	if (has_mbyte)
	    spell_soundfold_wsal(slang, word, res);
	else spell_soundfold_sal(slang, word, res);
    }
}


    static void spell_soundfold_sofo(slang_T *slang, char_u *inword, char_u *res)
{
    char_u	*s;
    int		ri = 0;
    int		c;

    if (has_mbyte)
    {
	int	prevc = 0;
	int	*ip;

	
	
	for (s = inword; *s != NUL; )
	{
	    c = mb_cptr2char_adv(&s);
	    if (enc_utf8 ? utf_class(c) == 0 : VIM_ISWHITE(c))
		c = ' ';
	    else if (c < 256)
		c = slang->sl_sal_first[c];
	    else {
		ip = ((int **)slang->sl_sal.ga_data)[c & 0xff];
		if (ip == NULL)		
		    c = NUL;
		else for (;;)
		    {
			if (*ip == 0)	
			{
			    c = NUL;
			    break;
			}
			if (*ip == c)	
			{
			    c = ip[1];
			    break;
			}
			ip += 2;
		    }
	    }

	    if (c != NUL && c != prevc)
	    {
		ri += mb_char2bytes(c, res + ri);
		if (ri + MB_MAXBYTES > MAXWLEN)
		    break;
		prevc = c;
	    }
	}
    }
    else {
	
	for (s = inword; (c = *s) != NUL; ++s)
	{
	    if (VIM_ISWHITE(c))
		c = ' ';
	    else c = slang->sl_sal_first[c];
	    if (c != NUL && (ri == 0 || res[ri - 1] != c))
		res[ri++] = c;
	}
    }

    res[ri] = NUL;
}

    static void spell_soundfold_sal(slang_T *slang, char_u *inword, char_u *res)
{
    salitem_T	*smp;
    char_u	word[MAXWLEN];
    char_u	*s = inword;
    char_u	*t;
    char_u	*pf;
    int		i, j, z;
    int		reslen;
    int		n, k = 0;
    int		z0;
    int		k0;
    int		n0;
    int		c;
    int		pri;
    int		p0 = -333;
    int		c0;

    
    
    if (slang->sl_rem_accents)
    {
	t = word;
	while (*s != NUL)
	{
	    if (VIM_ISWHITE(*s))
	    {
		*t++ = ' ';
		s = skipwhite(s);
	    }
	    else {
		if (spell_iswordp_nmw(s, curwin))
		    *t++ = *s;
		++s;
	    }
	}
	*t = NUL;
    }
    else vim_strncpy(word, s, MAXWLEN - 1);

    smp = (salitem_T *)slang->sl_sal.ga_data;

    
    i = reslen = z = 0;
    while ((c = word[i]) != NUL)
    {
	
	n = slang->sl_sal_first[c];
	z0 = 0;

	if (n >= 0)
	{
	    
	    for (; (s = smp[n].sm_lead)[0] == c; ++n)
	    {
		
		
		k = smp[n].sm_leadlen;
		if (k > 1)
		{
		    if (word[i + 1] != s[1])
			continue;
		    if (k > 2)
		    {
			for (j = 2; j < k; ++j)
			    if (word[i + j] != s[j])
				break;
			if (j < k)
			    continue;
		    }
		}

		if ((pf = smp[n].sm_oneof) != NULL)
		{
		    
		    while (*pf != NUL && *pf != word[i + k])
			++pf;
		    if (*pf == NUL)
			continue;
		    ++k;
		}
		s = smp[n].sm_rules;
		pri = 5;    

		p0 = *s;
		k0 = k;
		while (*s == '-' && k > 1)
		{
		    k--;
		    s++;
		}
		if (*s == '<')
		    s++;
		if (VIM_ISDIGIT(*s))
		{
		    
		    pri = *s - '0';
		    s++;
		}
		if (*s == '^' && *(s + 1) == '^')
		    s++;

		if (*s == NUL || (*s == '^' && (i == 0 || !(word[i - 1] == ' ' || spell_iswordp(word + i - 1, curwin)))


			    && (*(s + 1) != '$' || (!spell_iswordp(word + i + k0, curwin))))
			|| (*s == '$' && i > 0 && spell_iswordp(word + i - 1, curwin)
			    && (!spell_iswordp(word + i + k0, curwin))))
		{
		    
		    
		    c0 = word[i + k - 1];
		    n0 = slang->sl_sal_first[c0];

		    if (slang->sl_followup && k > 1 && n0 >= 0 && p0 != '-' && word[i + k] != NUL)
		    {
			
			for ( ; (s = smp[n0].sm_lead)[0] == c0; ++n0)
			{
			    
			    
			    k0 = smp[n0].sm_leadlen;
			    if (k0 > 1)
			    {
				if (word[i + k] != s[1])
				    continue;
				if (k0 > 2)
				{
				    pf = word + i + k + 1;
				    for (j = 2; j < k0; ++j)
					if (*pf++ != s[j])
					    break;
				    if (j < k0)
					continue;
				}
			    }
			    k0 += k - 1;

			    if ((pf = smp[n0].sm_oneof) != NULL)
			    {
				
				
				while (*pf != NUL && *pf != word[i + k0])
				    ++pf;
				if (*pf == NUL)
				    continue;
				++k0;
			    }

			    p0 = 5;
			    s = smp[n0].sm_rules;
			    while (*s == '-')
			    {
				
				
				s++;
			    }
			    if (*s == '<')
				s++;
			    if (VIM_ISDIGIT(*s))
			    {
				p0 = *s - '0';
				s++;
			    }

			    if (*s == NUL  || (*s == '$' && !spell_iswordp(word + i + k0, curwin)))



			    {
				if (k0 == k)
				    
				    continue;

				if (p0 < pri)
				    
				    continue;
				
				break;
			    }
			}

			if (p0 >= pri && smp[n0].sm_lead[0] == c0)
			    continue;
		    }

		    
		    s = smp[n].sm_to;
		    if (s == NULL)
			s = (char_u *)"";
		    pf = smp[n].sm_rules;
		    p0 = (vim_strchr(pf, '<') != NULL) ? 1 : 0;
		    if (p0 == 1 && z == 0)
		    {
			
			if (reslen > 0 && *s != NUL && (res[reslen - 1] == c || res[reslen - 1] == *s))
			    reslen--;
			z0 = 1;
			z = 1;
			k0 = 0;
			while (*s != NUL && word[i + k0] != NUL)
			{
			    word[i + k0] = *s;
			    k0++;
			    s++;
			}
			if (k > k0)
			    STRMOVE(word + i + k0, word + i + k);

			
			c = word[i];
		    }
		    else {
			
			i += k - 1;
			z = 0;
			while (*s != NUL && s[1] != NUL && reslen < MAXWLEN)
			{
			    if (reslen == 0 || res[reslen - 1] != *s)
				res[reslen++] = *s;
			    s++;
			}
			
			c = *s;
			if (strstr((char *)pf, "^^") != NULL)
			{
			    if (c != NUL)
				res[reslen++] = c;
			    STRMOVE(word, word + i + 1);
			    i = 0;
			    z0 = 1;
			}
		    }
		    break;
		}
	    }
	}
	else if (VIM_ISWHITE(c))
	{
	    c = ' ';
	    k = 1;
	}

	if (z0 == 0)
	{
	    if (k && !p0 && reslen < MAXWLEN && c != NUL && (!slang->sl_collapse || reslen == 0 || res[reslen - 1] != c))

		
		res[reslen++] = c;

	    i++;
	    z = 0;
	    k = 0;
	}
    }

    res[reslen] = NUL;
}


    static void spell_soundfold_wsal(slang_T *slang, char_u *inword, char_u *res)
{
    salitem_T	*smp = (salitem_T *)slang->sl_sal.ga_data;
    int		word[MAXWLEN];
    int		wres[MAXWLEN];
    int		l;
    char_u	*s;
    int		*ws;
    char_u	*t;
    int		*pf;
    int		i, j, z;
    int		reslen;
    int		n, k = 0;
    int		z0;
    int		k0;
    int		n0;
    int		c;
    int		pri;
    int		p0 = -333;
    int		c0;
    int		did_white = FALSE;
    int		wordlen;


    
    wordlen = 0;
    for (s = inword; *s != NUL; )
    {
	t = s;
	c = mb_cptr2char_adv(&s);
	if (slang->sl_rem_accents)
	{
	    if (enc_utf8 ? utf_class(c) == 0 : VIM_ISWHITE(c))
	    {
		if (did_white)
		    continue;
		c = ' ';
		did_white = TRUE;
	    }
	    else {
		did_white = FALSE;
		if (!spell_iswordp_nmw(t, curwin))
		    continue;
	    }
	}
	word[wordlen++] = c;
    }
    word[wordlen] = NUL;

    
    i = reslen = z = 0;
    while ((c = word[i]) != NUL)
    {
	
	n = slang->sl_sal_first[c & 0xff];
	z0 = 0;

	if (n >= 0)
	{
	    
	    
	    
	    for (; ((ws = smp[n].sm_lead_w)[0] & 0xff) == (c & 0xff)
							 && ws[0] != NUL; ++n)
	    {
		
		
		if (c != ws[0])
		    continue;
		k = smp[n].sm_leadlen;
		if (k > 1)
		{
		    if (word[i + 1] != ws[1])
			continue;
		    if (k > 2)
		    {
			for (j = 2; j < k; ++j)
			    if (word[i + j] != ws[j])
				break;
			if (j < k)
			    continue;
		    }
		}

		if ((pf = smp[n].sm_oneof_w) != NULL)
		{
		    
		    while (*pf != NUL && *pf != word[i + k])
			++pf;
		    if (*pf == NUL)
			continue;
		    ++k;
		}
		s = smp[n].sm_rules;
		pri = 5;    

		p0 = *s;
		k0 = k;
		while (*s == '-' && k > 1)
		{
		    k--;
		    s++;
		}
		if (*s == '<')
		    s++;
		if (VIM_ISDIGIT(*s))
		{
		    
		    pri = *s - '0';
		    s++;
		}
		if (*s == '^' && *(s + 1) == '^')
		    s++;

		if (*s == NUL || (*s == '^' && (i == 0 || !(word[i - 1] == ' ' || spell_iswordp_w(word + i - 1, curwin)))


			    && (*(s + 1) != '$' || (!spell_iswordp_w(word + i + k0, curwin))))
			|| (*s == '$' && i > 0 && spell_iswordp_w(word + i - 1, curwin)
			    && (!spell_iswordp_w(word + i + k0, curwin))))
		{
		    
		    
		    c0 = word[i + k - 1];
		    n0 = slang->sl_sal_first[c0 & 0xff];

		    if (slang->sl_followup && k > 1 && n0 >= 0 && p0 != '-' && word[i + k] != NUL)
		    {
			
			
			for ( ; ((ws = smp[n0].sm_lead_w)[0] & 0xff)
							 == (c0 & 0xff); ++n0)
			{
			    
			    if (c0 != ws[0])
				continue;
			    k0 = smp[n0].sm_leadlen;
			    if (k0 > 1)
			    {
				if (word[i + k] != ws[1])
				    continue;
				if (k0 > 2)
				{
				    pf = word + i + k + 1;
				    for (j = 2; j < k0; ++j)
					if (*pf++ != ws[j])
					    break;
				    if (j < k0)
					continue;
				}
			    }
			    k0 += k - 1;

			    if ((pf = smp[n0].sm_oneof_w) != NULL)
			    {
				
				
				while (*pf != NUL && *pf != word[i + k0])
				    ++pf;
				if (*pf == NUL)
				    continue;
				++k0;
			    }

			    p0 = 5;
			    s = smp[n0].sm_rules;
			    while (*s == '-')
			    {
				
				
				s++;
			    }
			    if (*s == '<')
				s++;
			    if (VIM_ISDIGIT(*s))
			    {
				p0 = *s - '0';
				s++;
			    }

			    if (*s == NUL  || (*s == '$' && !spell_iswordp_w(word + i + k0, curwin)))



			    {
				if (k0 == k)
				    
				    continue;

				if (p0 < pri)
				    
				    continue;
				
				break;
			    }
			}

			if (p0 >= pri && (smp[n0].sm_lead_w[0] & 0xff)
							       == (c0 & 0xff))
			    continue;
		    }

		    
		    ws = smp[n].sm_to_w;
		    s = smp[n].sm_rules;
		    p0 = (vim_strchr(s, '<') != NULL) ? 1 : 0;
		    if (p0 == 1 && z == 0)
		    {
			
			if (reslen > 0 && ws != NULL && *ws != NUL && (wres[reslen - 1] == c || wres[reslen - 1] == *ws))

			    reslen--;
			z0 = 1;
			z = 1;
			k0 = 0;
			if (ws != NULL)
			    while (*ws != NUL && word[i + k0] != NUL)
			    {
				word[i + k0] = *ws;
				k0++;
				ws++;
			    }
			if (k > k0)
			    mch_memmove(word + i + k0, word + i + k, sizeof(int) * (wordlen - (i + k) + 1));

			
			c = word[i];
		    }
		    else {
			
			i += k - 1;
			z = 0;
			if (ws != NULL)
			    while (*ws != NUL && ws[1] != NUL && reslen < MAXWLEN)
			    {
				if (reslen == 0 || wres[reslen - 1] != *ws)
				    wres[reslen++] = *ws;
				ws++;
			    }
			
			if (ws == NULL)
			    c = NUL;
			else c = *ws;
			if (strstr((char *)s, "^^") != NULL)
			{
			    if (c != NUL)
				wres[reslen++] = c;
			    mch_memmove(word, word + i + 1, sizeof(int) * (wordlen - (i + 1) + 1));
			    i = 0;
			    z0 = 1;
			}
		    }
		    break;
		}
	    }
	}
	else if (VIM_ISWHITE(c))
	{
	    c = ' ';
	    k = 1;
	}

	if (z0 == 0)
	{
	    if (k && !p0 && reslen < MAXWLEN && c != NUL && (!slang->sl_collapse || reslen == 0 || wres[reslen - 1] != c))

		
		wres[reslen++] = c;

	    i++;
	    z = 0;
	    k = 0;
	}
    }

    
    l = 0;
    for (n = 0; n < reslen; ++n)
    {
	l += mb_char2bytes(wres[n], res + l);
	if (l + MB_MAXBYTES > MAXWLEN)
	    break;
    }
    res[l] = NUL;
}


    void ex_spellinfo(exarg_T *eap UNUSED)
{
    int		lpi;
    langp_T	*lp;
    char_u	*p;

    if (no_spell_checking(curwin))
	return;

    msg_start();
    for (lpi = 0; lpi < curwin->w_s->b_langp.ga_len && !got_int; ++lpi)
    {
	lp = LANGP_ENTRY(curwin->w_s->b_langp, lpi);
	msg_puts("file: ");
	msg_puts((char *)lp->lp_slang->sl_fname);
	msg_putchar('\n');
	p = lp->lp_slang->sl_info;
	if (p != NULL)
	{
	    msg_puts((char *)p);
	    msg_putchar('\n');
	}
    }
    msg_end();
}








    void ex_spelldump(exarg_T *eap)
{
    char_u  *spl;
    long    dummy;

    if (no_spell_checking(curwin))
	return;
    (void)get_option_value((char_u*)"spl", &dummy, &spl, NULL, OPT_LOCAL);

    
    do_cmdline_cmd((char_u *)"new");

    
    set_option_value_give_err((char_u*)"spell", TRUE, (char_u*)"", OPT_LOCAL);
    set_option_value_give_err((char_u*)"spl",  dummy, spl, OPT_LOCAL);
    vim_free(spl);

    if (!BUFEMPTY())
	return;

    spell_dump_compl(NULL, 0, NULL, eap->forceit ? DUMPFLAG_COUNT : 0);

    
    if (curbuf->b_ml.ml_line_count > 1)
	ml_delete(curbuf->b_ml.ml_line_count);

    redraw_later(UPD_NOT_VALID);
}


    void spell_dump_compl( char_u	*pat, int		ic, int		*dir, int		dumpflags_arg)




{
    langp_T	*lp;
    slang_T	*slang;
    idx_T	arridx[MAXWLEN];
    int		curi[MAXWLEN];
    char_u	word[MAXWLEN];
    int		c;
    char_u	*byts;
    idx_T	*idxs;
    linenr_T	lnum = 0;
    int		round;
    int		depth;
    int		n;
    int		flags;
    char_u	*region_names = NULL;	    
    int		do_region = TRUE;	    
    char_u	*p;
    int		lpi;
    int		dumpflags = dumpflags_arg;
    int		patlen;

    
    
    if (pat != NULL)
    {
	if (ic)
	    dumpflags |= DUMPFLAG_ICASE;
	else {
	    n = captype(pat, NULL);
	    if (n == WF_ONECAP)
		dumpflags |= DUMPFLAG_ONECAP;
	    else if (n == WF_ALLCAP && (int)STRLEN(pat) > mb_ptr2len(pat))
		dumpflags |= DUMPFLAG_ALLCAP;
	}
    }

    
    
    for (lpi = 0; lpi < curwin->w_s->b_langp.ga_len; ++lpi)
    {
	lp = LANGP_ENTRY(curwin->w_s->b_langp, lpi);
	p = lp->lp_slang->sl_regions;
	if (p[0] != 0)
	{
	    if (region_names == NULL)	    
		region_names = p;
	    else if (STRCMP(region_names, p) != 0)
	    {
		do_region = FALSE;	    
		break;
	    }
	}
    }

    if (do_region && region_names != NULL)
    {
	if (pat == NULL)
	{
	    vim_snprintf((char *)IObuff, IOSIZE, "/regions=%s", region_names);
	    ml_append(lnum++, IObuff, (colnr_T)0, FALSE);
	}
    }
    else do_region = FALSE;

    
    for (lpi = 0; lpi < curwin->w_s->b_langp.ga_len; ++lpi)
    {
	lp = LANGP_ENTRY(curwin->w_s->b_langp, lpi);
	slang = lp->lp_slang;
	if (slang->sl_fbyts == NULL)	    
	    continue;

	if (pat == NULL)
	{
	    vim_snprintf((char *)IObuff, IOSIZE, "# file: %s", slang->sl_fname);
	    ml_append(lnum++, IObuff, (colnr_T)0, FALSE);
	}

	
	
	if (pat != NULL && slang->sl_pbyts == NULL)
	    patlen = (int)STRLEN(pat);
	else patlen = -1;

	
	
	for (round = 1; round <= 2; ++round)
	{
	    if (round == 1)
	    {
		dumpflags &= ~DUMPFLAG_KEEPCASE;
		byts = slang->sl_fbyts;
		idxs = slang->sl_fidxs;
	    }
	    else {
		dumpflags |= DUMPFLAG_KEEPCASE;
		byts = slang->sl_kbyts;
		idxs = slang->sl_kidxs;
	    }
	    if (byts == NULL)
		continue;		

	    depth = 0;
	    arridx[0] = 0;
	    curi[0] = 1;
	    while (depth >= 0 && !got_int && (pat == NULL || !ins_compl_interrupted()))
	    {
		if (curi[depth] > byts[arridx[depth]])
		{
		    
		    --depth;
		    line_breakcheck();
		    ins_compl_check_keys(50, FALSE);
		}
		else {
		    
		    n = arridx[depth] + curi[depth];
		    ++curi[depth];
		    c = byts[n];
		    if (c == 0 || depth >= MAXWLEN - 1)
		    {
			
			
			
			
			
			flags = (int)idxs[n];
			if ((round == 2 || (flags & WF_KEEPCAP) == 0)
				&& (flags & WF_NEEDCOMP) == 0 && (do_region || (flags & WF_REGION) == 0 || (((unsigned)flags >> 16)


						       & lp->lp_region) != 0))
			{
			    word[depth] = NUL;
			    if (!do_region)
				flags &= ~WF_REGION;

			    
			    
			    c = (unsigned)flags >> 24;
			    if (c == 0 || curi[depth] == 2)
			    {
				dump_word(slang, word, pat, dir, dumpflags, flags, lnum);
				if (pat == NULL)
				    ++lnum;
			    }

			    
			    if (c != 0)
				lnum = dump_prefixes(slang, word, pat, dir, dumpflags, flags, lnum);
			}
		    }
		    else {
			
			word[depth++] = c;
			arridx[depth] = idxs[n];
			curi[depth] = 1;

			
			
			
			
			
			
			if (depth <= patlen && MB_STRNICMP(word, pat, depth) != 0)
			    --depth;
		    }
		}
	    }
	}
    }
}


    static void dump_word( slang_T	*slang, char_u	*word, char_u	*pat, int		*dir, int		dumpflags, int		wordflags, linenr_T	lnum)







{
    int		keepcap = FALSE;
    char_u	*p;
    char_u	*tw;
    char_u	cword[MAXWLEN];
    char_u	badword[MAXWLEN + 10];
    int		i;
    int		flags = wordflags;

    if (dumpflags & DUMPFLAG_ONECAP)
	flags |= WF_ONECAP;
    if (dumpflags & DUMPFLAG_ALLCAP)
	flags |= WF_ALLCAP;

    if ((dumpflags & DUMPFLAG_KEEPCASE) == 0 && (flags & WF_CAPMASK) != 0)
    {
	
	make_case_word(word, cword, flags);
	p = cword;
    }
    else {
	p = word;
	if ((dumpflags & DUMPFLAG_KEEPCASE)
		&& ((captype(word, NULL) & WF_KEEPCAP) == 0 || (flags & WF_FIXCAP) != 0))
	    keepcap = TRUE;
    }
    tw = p;

    if (pat == NULL)
    {
	
	if ((flags & (WF_BANNED | WF_RARE | WF_REGION)) || keepcap)
	{
	    STRCPY(badword, p);
	    STRCAT(badword, "/");
	    if (keepcap)
		STRCAT(badword, "=");
	    if (flags & WF_BANNED)
		STRCAT(badword, "!");
	    else if (flags & WF_RARE)
		STRCAT(badword, "?");
	    if (flags & WF_REGION)
		for (i = 0; i < 7; ++i)
		    if (flags & (0x10000 << i))
			sprintf((char *)badword + STRLEN(badword), "%d", i + 1);
	    p = badword;
	}

	if (dumpflags & DUMPFLAG_COUNT)
	{
	    hashitem_T  *hi;

	    
	    hi = hash_find(&slang->sl_wordcount, tw);
	    if (!HASHITEM_EMPTY(hi))
	    {
		vim_snprintf((char *)IObuff, IOSIZE, "%s\t%d", tw, HI2WC(hi)->wc_count);
		p = IObuff;
	    }
	}

	ml_append(lnum, p, (colnr_T)0, FALSE);
    }
    else if (((dumpflags & DUMPFLAG_ICASE)
		    ? MB_STRNICMP(p, pat, STRLEN(pat)) == 0 : STRNCMP(p, pat, STRLEN(pat)) == 0)
		&& ins_compl_add_infercase(p, (int)STRLEN(p), p_ic, NULL, *dir, FALSE) == OK)
	
	*dir = FORWARD;
}


    static linenr_T dump_prefixes( slang_T	*slang, char_u	*word, char_u	*pat, int		*dir, int		dumpflags, int		flags, linenr_T	startlnum)







{
    idx_T	arridx[MAXWLEN];
    int		curi[MAXWLEN];
    char_u	prefix[MAXWLEN];
    char_u	word_up[MAXWLEN];
    int		has_word_up = FALSE;
    int		c;
    char_u	*byts;
    idx_T	*idxs;
    linenr_T	lnum = startlnum;
    int		depth;
    int		n;
    int		len;
    int		i;

    
    
    c = PTR2CHAR(word);
    if (SPELL_TOUPPER(c) != c)
    {
	onecap_copy(word, word_up, TRUE);
	has_word_up = TRUE;
    }

    byts = slang->sl_pbyts;
    idxs = slang->sl_pidxs;
    if (byts != NULL)		
    {
	
	depth = 0;
	arridx[0] = 0;
	curi[0] = 1;
	while (depth >= 0 && !got_int)
	{
	    n = arridx[depth];
	    len = byts[n];
	    if (curi[depth] > len)
	    {
		
		--depth;
		line_breakcheck();
	    }
	    else {
		
		n += curi[depth];
		++curi[depth];
		c = byts[n];
		if (c == 0)
		{
		    
		    for (i = 1; i < len; ++i)
			if (byts[n + i] != 0)
			    break;
		    curi[depth] += i - 1;

		    c = valid_word_prefix(i, n, flags, word, slang, FALSE);
		    if (c != 0)
		    {
			vim_strncpy(prefix + depth, word, MAXWLEN - depth - 1);
			dump_word(slang, prefix, pat, dir, dumpflags, (c & WF_RAREPFX) ? (flags | WF_RARE)
							       : flags, lnum);
			if (lnum != 0)
			    ++lnum;
		    }

		    
		    
		    
		    if (has_word_up)
		    {
			c = valid_word_prefix(i, n, flags, word_up, slang, TRUE);
			if (c != 0)
			{
			    vim_strncpy(prefix + depth, word_up, MAXWLEN - depth - 1);
			    dump_word(slang, prefix, pat, dir, dumpflags, (c & WF_RAREPFX) ? (flags | WF_RARE)
							       : flags, lnum);
			    if (lnum != 0)
				++lnum;
			}
		    }
		}
		else {
		    
		    prefix[depth++] = c;
		    arridx[depth] = idxs[n];
		    curi[depth] = 1;
		}
	    }
	}
    }

    return lnum;
}


    char_u * spell_to_word_end(char_u *start, win_T *win)
{
    char_u  *p = start;

    while (*p != NUL && spell_iswordp(p, win))
	MB_PTR_ADV(p);
    return p;
}


    int spell_word_start(int startcol)
{
    char_u	*line;
    char_u	*p;
    int		col = 0;

    if (no_spell_checking(curwin))
	return startcol;

    
    line = ml_get_curline();
    for (p = line + startcol; p > line; )
    {
	MB_PTR_BACK(line, p);
	if (spell_iswordp_nmw(p, curwin))
	    break;
    }

    
    while (p > line)
    {
	col = (int)(p - line);
	MB_PTR_BACK(line, p);
	if (!spell_iswordp(p, curwin))
	    break;
	col = 0;
    }

    return col;
}


static int spell_expand_need_cap;

    void spell_expand_check_cap(colnr_T col)
{
    spell_expand_need_cap = check_need_cap(curwin->w_cursor.lnum, col);
}


    int expand_spelling( linenr_T	lnum UNUSED, char_u	*pat, char_u	***matchp)



{
    garray_T	ga;

    spell_suggest_list(&ga, pat, 100, spell_expand_need_cap, TRUE);
    *matchp = ga.ga_data;
    return ga.ga_len;
}


    int valid_spelllang(char_u *val)
{
    return valid_name(val, ".-_,@");
}


    int valid_spellfile(char_u *val)
{
    char_u *s;

    for (s = val; *s != NUL; ++s)
	if (!vim_is_fname_char(*s))
	    return FALSE;
    return TRUE;
}


    char * did_set_spell_option(int is_spellfile)
{
    char    *errmsg = NULL;
    win_T   *wp;
    int	    l;

    if (is_spellfile)
    {
	l = (int)STRLEN(curwin->w_s->b_p_spf);
	if (l > 0 && (l < 4 || STRCMP(curwin->w_s->b_p_spf + l - 4, ".add") != 0))
	    errmsg = e_invalid_argument;
    }

    if (errmsg == NULL)
    {
	FOR_ALL_WINDOWS(wp)
	    if (wp->w_buffer == curbuf && wp->w_p_spell)
	    {
		errmsg = did_set_spelllang(wp);
		break;
	    }
    }
    return errmsg;
}


    char * compile_cap_prog(synblock_T *synblock)
{
    regprog_T   *rp = synblock->b_cap_prog;
    char_u	*re;

    if (synblock->b_p_spc == NULL || *synblock->b_p_spc == NUL)
	synblock->b_cap_prog = NULL;
    else {
	
	re = concat_str((char_u *)"^", synblock->b_p_spc);
	if (re != NULL)
	{
	    synblock->b_cap_prog = vim_regcomp(re, RE_MAGIC);
	    vim_free(re);
	    if (synblock->b_cap_prog == NULL)
	    {
		synblock->b_cap_prog = rp; 
		return e_invalid_argument;
	    }
	}
    }

    vim_regfree(rp);
    return NULL;
}


