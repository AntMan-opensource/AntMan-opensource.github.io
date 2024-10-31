























EXTERN_C const struct regexp_engine my_reg_engine;


















struct scan_frame;
typedef struct scan_frame {
    regnode *last_regnode;      
    regnode *next_regnode;      
    U32 prev_recursed_depth;
    I32 stopparen;              

    struct scan_frame *this_prev_frame; 
    struct scan_frame *prev_frame;      
    struct scan_frame *next_frame;      
} scan_frame;





struct RExC_state_t {
    U32		flags;			
    U32		pm_flags;		
    char	*precomp;		
    char	*precomp_end;		
    REGEXP	*rx_sv;			
    regexp	*rx;                    
    regexp_internal	*rxi;           
    char	*start;			
    char	*end;			
    char	*parse;			
    char        *copy_start;            
    char        *save_copy_start;       
    char        *copy_start_in_input;   
    SSize_t	whilem_seen;		
    regnode	*emit_start;		
    regnode_offset emit;		
    I32		naughty;		
    I32		sawback;		
    U32		seen;
    SSize_t	size;			

    
    Size_t	latest_warn_offset;

    I32         npar;                   
    I32         total_par;              
    I32		nestroot;		
    I32		seen_zerolen;
    regnode_offset *open_parens;	
    regnode_offset *close_parens;	
    I32      parens_buf_size;           
    regnode     *end_op;                
    I32		utf8;		
    I32		orig_utf8;	
				
    I32		uni_semantics;	
    HV		*paren_names;		

    regnode	**recurse;		
    I32         recurse_count;          
    U8          *study_chunk_recursed;  
    U32         study_chunk_recursed_bytes;  
    I32		in_lookbehind;
    I32		contains_locale;
    I32		override_recoding;

    I32		recode_x_to_native;

    I32		in_multi_char_class;
    struct reg_code_blocks *code_blocks;
    int		code_index;		
    SSize_t     maxlen;                        
    scan_frame *frame_head;
    scan_frame *frame_last;
    U32         frame_count;
    AV         *warn_text;
    HV         *unlexed_names;

    char 	*starttry;		


    SV		*runtime_code_qr;	

    const char  *lastparse;
    I32         lastnum;
    AV          *paren_name_list;       
    U32         study_chunk_recursed_count;
    SV          *mysv1;
    SV          *mysv2;










    bool        seen_d_op;
    bool        strict;
    bool        study_started;
    bool        in_script_run;
    bool        use_BRANCHJ;
};



























































































































































struct scan_data_substrs {
    SV      *str;       
    SSize_t min_offset; 
    SSize_t max_offset; 
    SSize_t *minlenp;   
    SSize_t lookbehind; 
    I32 flags;          
};

typedef struct scan_data_t {
    
    
    SSize_t pos_min;
    SSize_t pos_delta;
    SV *last_found;
    SSize_t last_end;	    
    SSize_t last_start_min;
    SSize_t last_start_max;
    U8      cur_is_floating; 

    
    struct scan_data_substrs  substrs[2];

    I32 flags;             
    I32 whilem_c;
    SSize_t *last_closep;
    regnode_ssc *start_class;
} scan_data_t;



static const scan_data_t zero_scan_data = {
    0, 0, NULL, 0, 0, 0, 0, {
        { NULL, 0, 0, 0, 0, 0 }, { NULL, 0, 0, 0, 0, 0 }, }, 0, 0, NULL, NULL };



























































































































































































































































































































































int Perl_re_printf(pTHX_ const char *fmt, ...)
{
    va_list ap;
    int result;
    PerlIO *f= Perl_debug_log;
    PERL_ARGS_ASSERT_RE_PRINTF;
    va_start(ap, fmt);
    result = PerlIO_vprintf(f, fmt, ap);
    va_end(ap);
    return result;
}

int Perl_re_indentf(pTHX_ const char *fmt, U32 depth, ...)
{
    va_list ap;
    int result;
    PerlIO *f= Perl_debug_log;
    PERL_ARGS_ASSERT_RE_INDENTF;
    va_start(ap, depth);
    PerlIO_printf(f, "%*s", ( (int)depth % 20 ) * 2, "");
    result = PerlIO_vprintf(f, fmt, ap);
    va_end(ap);
    return result;
}










































static void S_debug_show_study_flags(pTHX_ U32 flags, const char *open_str, const char *close_str)

{
    if (!flags)
        return;

    Perl_re_printf( aTHX_  "%s", open_str);
    DEBUG_SHOW_STUDY_FLAG(flags, SF_BEFORE_SEOL);
    DEBUG_SHOW_STUDY_FLAG(flags, SF_BEFORE_MEOL);
    DEBUG_SHOW_STUDY_FLAG(flags, SF_IS_INF);
    DEBUG_SHOW_STUDY_FLAG(flags, SF_HAS_PAR);
    DEBUG_SHOW_STUDY_FLAG(flags, SF_IN_PAR);
    DEBUG_SHOW_STUDY_FLAG(flags, SF_HAS_EVAL);
    DEBUG_SHOW_STUDY_FLAG(flags, SCF_DO_SUBSTR);
    DEBUG_SHOW_STUDY_FLAG(flags, SCF_DO_STCLASS_AND);
    DEBUG_SHOW_STUDY_FLAG(flags, SCF_DO_STCLASS_OR);
    DEBUG_SHOW_STUDY_FLAG(flags, SCF_DO_STCLASS);
    DEBUG_SHOW_STUDY_FLAG(flags, SCF_WHILEM_VISITED_POS);
    DEBUG_SHOW_STUDY_FLAG(flags, SCF_TRIE_RESTUDY);
    DEBUG_SHOW_STUDY_FLAG(flags, SCF_SEEN_ACCEPT);
    DEBUG_SHOW_STUDY_FLAG(flags, SCF_TRIE_DOING_RESTUDY);
    DEBUG_SHOW_STUDY_FLAG(flags, SCF_IN_DEFINE);
    Perl_re_printf( aTHX_  "%s", close_str);
}


static void S_debug_studydata(pTHX_ const char *where, scan_data_t *data, U32 depth, int is_inf)

{
    GET_RE_DEBUG_FLAGS_DECL;

    DEBUG_OPTIMISE_MORE_r({
        if (!data)
            return;
        Perl_re_indentf(aTHX_  "%s: Pos:%" IVdf "/%" IVdf " Flags: 0x%" UVXf, depth, where, (IV)data->pos_min, (IV)data->pos_delta, (UV)data->flags );






        S_debug_show_study_flags(aTHX_ data->flags," [","]");

        Perl_re_printf( aTHX_ " Whilem_c: %" IVdf " Lcp: %" IVdf " %s", (IV)data->whilem_c, (IV)(data->last_closep ? *((data)->last_closep) : -1), is_inf ? "INF " : "" );





        if (data->last_found) {
            int i;
            Perl_re_printf(aTHX_ "Last:'%s' %" IVdf ":%" IVdf "/%" IVdf, SvPVX_const(data->last_found), (IV)data->last_end, (IV)data->last_start_min, (IV)data->last_start_max );






            for (i = 0; i < 2; i++) {
                Perl_re_printf(aTHX_ " %s%s: '%s' @ %" IVdf "/%" IVdf, data->cur_is_floating == i ? "*" : "", i ? "Float" : "Fixed", SvPVX_const(data->substrs[i].str), (IV)data->substrs[i].min_offset, (IV)data->substrs[i].max_offset );






                S_debug_show_study_flags(aTHX_ data->substrs[i].flags," [","]");
            }
        }

        Perl_re_printf( aTHX_ "\n");
    });
}


static void S_debug_peep(pTHX_ const char *str, const RExC_state_t *pRExC_state, regnode *scan, U32 depth, U32 flags)

{
    GET_RE_DEBUG_FLAGS_DECL;

    DEBUG_OPTIMISE_r({
        regnode *Next;

        if (!scan)
            return;
        Next = regnext(scan);
        regprop(RExC_rx, RExC_mysv, scan, NULL, pRExC_state);
        Perl_re_indentf( aTHX_   "%s>%3d: %s (%d)", depth, str, REG_NODE_NUM(scan), SvPV_nolen_const(RExC_mysv), Next ? (REG_NODE_NUM(Next)) : 0 );



        S_debug_show_study_flags(aTHX_ flags," [ ","]");
        Perl_re_printf( aTHX_  "\n");
   });
}

















struct dictionary{
  UV key;
  UV value;
  struct dictionary* next;
};
typedef struct dictionary item;


PERL_STATIC_INLINE item* push(UV key, item* curr)
{
    item* head;
    Newx(head, 1, item);
    head->key = key;
    head->value = 0;
    head->next = curr;
    return head;
}


PERL_STATIC_INLINE item* find(item* head, UV key)
{
    item* iterator = head;
    while (iterator){
        if (iterator->key == key){
            return iterator;
        }
        iterator = iterator->next;
    }

    return NULL;
}

PERL_STATIC_INLINE item* uniquePush(item* head, UV key)
{
    item* iterator = head;

    while (iterator){
        if (iterator->key == key) {
            return head;
        }
        iterator = iterator->next;
    }

    return push(key, head);
}

PERL_STATIC_INLINE void dict_free(item* head)
{
    item* iterator = head;

    while (iterator) {
        item* temp = iterator;
        iterator = iterator->next;
        Safefree(temp);
    }

    head = NULL;
}




STATIC int S_edit_distance(const UV* src, const UV* tgt, const STRLEN x, const STRLEN y, const SSize_t maxDistance )





{
    item *head = NULL;
    UV swapCount, swapScore, targetCharCount, i, j;
    UV *scores;
    UV score_ceil = x + y;

    PERL_ARGS_ASSERT_EDIT_DISTANCE;

    
    Newx(scores, ( (x + 2) * (y + 2)), UV);
    scores[0] = score_ceil;
    scores[1 * (y + 2) + 0] = score_ceil;
    scores[0 * (y + 2) + 1] = score_ceil;
    scores[1 * (y + 2) + 1] = 0;
    head = uniquePush(uniquePush(head, src[0]), tgt[0]);

    
    
    
    for (i=1;i<=x;i++) {
        if (i < x)
            head = uniquePush(head, src[i]);
        scores[(i+1) * (y + 2) + 1] = i;
        scores[(i+1) * (y + 2) + 0] = score_ceil;
        swapCount = 0;

        for (j=1;j<=y;j++) {
            if (i == 1) {
                if(j < y)
                head = uniquePush(head, tgt[j]);
                scores[1 * (y + 2) + (j + 1)] = j;
                scores[0 * (y + 2) + (j + 1)] = score_ceil;
            }

            targetCharCount = find(head, tgt[j-1])->value;
            swapScore = scores[targetCharCount * (y + 2) + swapCount] + i - targetCharCount - 1 + j - swapCount;

            if (src[i-1] != tgt[j-1]){
                scores[(i+1) * (y + 2) + (j + 1)] = MIN(swapScore,(MIN(scores[i * (y + 2) + j], MIN(scores[(i+1) * (y + 2) + j], scores[i * (y + 2) + (j + 1)])) + 1));
            }
            else {
                swapCount = j;
                scores[(i+1) * (y + 2) + (j + 1)] = MIN(scores[i * (y + 2) + j], swapScore);
            }
        }

        find(head, src[i-1])->value = i;
    }

    {
        IV score = scores[(x+1) * (y + 2) + (y + 1)];
        dict_free(head);
        Safefree(scores);
        return (maxDistance != 0 && maxDistance < score)?(-1):score;
    }
}






STATIC const char * S_cntrl_to_mnemonic(const U8 c)
{
    

    switch (c) {
        case '\a':       return "\\a";
        case '\b':       return "\\b";
        case ESC_NATIVE: return "\\e";
        case '\f':       return "\\f";
        case '\n':       return "\\n";
        case '\r':       return "\\r";
        case '\t':       return "\\t";
    }

    return NULL;
}



STATIC void S_scan_commit(pTHX_ const RExC_state_t *pRExC_state, scan_data_t *data, SSize_t *minlenp, int is_inf)

{
    const STRLEN l = CHR_SVLEN(data->last_found);
    SV * const longest_sv = data->substrs[data->cur_is_floating].str;
    const STRLEN old_l = CHR_SVLEN(longest_sv);
    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_SCAN_COMMIT;

    if ((l >= old_l) && ((l > old_l) || (data->flags & SF_BEFORE_EOL))) {
        const U8 i = data->cur_is_floating;
	SvSetMagicSV(longest_sv, data->last_found);
        data->substrs[i].min_offset = l ? data->last_start_min : data->pos_min;

	if (!i) 
	    data->substrs[0].max_offset = data->substrs[0].min_offset;
	else { 
	    data->substrs[1].max_offset = (l ? data->last_start_max : (data->pos_delta > SSize_t_MAX - data->pos_min ? SSize_t_MAX : data->pos_min + data->pos_delta));



	    if (is_inf || (STRLEN)data->substrs[1].max_offset > (STRLEN)SSize_t_MAX)
		data->substrs[1].max_offset = SSize_t_MAX;
        }

        if (data->flags & SF_BEFORE_EOL)
            data->substrs[i].flags |= (data->flags & SF_BEFORE_EOL);
        else data->substrs[i].flags &= ~SF_BEFORE_EOL;
        data->substrs[i].minlenp = minlenp;
        data->substrs[i].lookbehind = 0;
    }

    SvCUR_set(data->last_found, 0);
    {
	SV * const sv = data->last_found;
	if (SvUTF8(sv) && SvMAGICAL(sv)) {
	    MAGIC * const mg = mg_find(sv, PERL_MAGIC_utf8);
	    if (mg)
		mg->mg_len = 0;
	}
    }
    data->last_end = -1;
    data->flags &= ~SF_BEFORE_EOL;
    DEBUG_STUDYDATA("commit", data, 0, is_inf);
}



STATIC void S_ssc_anything(pTHX_ regnode_ssc *ssc)
{
    

    PERL_ARGS_ASSERT_SSC_ANYTHING;

    assert(is_ANYOF_SYNTHETIC(ssc));

    
    ssc->invlist = sv_2mortal(_add_range_to_invlist(NULL, 0, UV_MAX));
    ANYOF_FLAGS(ssc) |= SSC_MATCHES_EMPTY_STRING;  
}

STATIC int S_ssc_is_anything(const regnode_ssc *ssc)
{
    

    UV start, end;
    bool ret;

    PERL_ARGS_ASSERT_SSC_IS_ANYTHING;

    assert(is_ANYOF_SYNTHETIC(ssc));

    if (! (ANYOF_FLAGS(ssc) & SSC_MATCHES_EMPTY_STRING)) {
        return FALSE;
    }

    
    invlist_iterinit(ssc->invlist);
    ret = invlist_iternext(ssc->invlist, &start, &end)
          && start == 0 && end == UV_MAX;

    invlist_iterfinish(ssc->invlist);

    if (ret) {
        return TRUE;
    }

    
    if (ANYOF_POSIXL_SSC_TEST_ANY_SET(ssc)) {
        int i;
        for (i = 0; i < ANYOF_POSIXL_MAX; i += 2) {
            if (ANYOF_POSIXL_TEST(ssc, i) && ANYOF_POSIXL_TEST(ssc, i+1)) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

STATIC void S_ssc_init(pTHX_ const RExC_state_t *pRExC_state, regnode_ssc *ssc)
{
    

    PERL_ARGS_ASSERT_SSC_INIT;

    Zero(ssc, 1, regnode_ssc);
    set_ANYOF_SYNTHETIC(ssc);
    ARG_SET(ssc, ANYOF_ONLY_HAS_BITMAP);
    ssc_anything(ssc);

    
    if (RExC_contains_locale) {
	ANYOF_POSIXL_SETALL(ssc);
    }
    else {
	ANYOF_POSIXL_ZERO(ssc);
    }
}

STATIC int S_ssc_is_cp_posixl_init(const RExC_state_t *pRExC_state, const regnode_ssc *ssc)

{
    

    UV start, end;
    bool ret;

    PERL_ARGS_ASSERT_SSC_IS_CP_POSIXL_INIT;

    assert(is_ANYOF_SYNTHETIC(ssc));

    invlist_iterinit(ssc->invlist);
    ret = invlist_iternext(ssc->invlist, &start, &end)
          && start == 0 && end == UV_MAX;

    invlist_iterfinish(ssc->invlist);

    if (! ret) {
        return FALSE;
    }

    if (RExC_contains_locale && ! ANYOF_POSIXL_SSC_TEST_ALL_SET(ssc)) {
        return FALSE;
    }

    return TRUE;
}





STATIC SV* S_get_ANYOF_cp_list_for_ssc(pTHX_ const RExC_state_t *pRExC_state, const regnode_charclass* const node)

{
    

    dVAR;
    SV* invlist = NULL;
    SV* only_utf8_locale_invlist = NULL;
    unsigned int i;
    const U32 n = ARG(node);
    bool new_node_has_latin1 = FALSE;
    const U8 flags = OP(node) == ANYOFH ? 0 : ANYOF_FLAGS(node);

    PERL_ARGS_ASSERT_GET_ANYOF_CP_LIST_FOR_SSC;

    
    if (n != ANYOF_ONLY_HAS_BITMAP) {
        SV * const rv = MUTABLE_SV(RExC_rxi->data->data[n]);
        AV * const av = MUTABLE_AV(SvRV(rv));
        SV **const ary = AvARRAY(av);
        assert(RExC_rxi->data->what[n] == 's');

        if (av_tindex_skip_len_mg(av) >= DEFERRED_USER_DEFINED_INDEX) {

            
            invlist = sv_2mortal(_new_invlist(1));
            return _add_range_to_invlist(invlist, 0, UV_MAX);
        }
        else if (ary[INVLIST_INDEX]) {

            
            invlist = sv_2mortal(invlist_clone(ary[INVLIST_INDEX], NULL));
        }

        
        if (   (flags & ANYOFL_FOLD)
            &&  av_tindex_skip_len_mg(av) >= ONLY_LOCALE_MATCHES_INDEX)
        {
            only_utf8_locale_invlist = ary[ONLY_LOCALE_MATCHES_INDEX];
        }
    }

    if (! invlist) {
        invlist = sv_2mortal(_new_invlist(0));
    }

    
    if (flags & ANYOF_INVERT) {
        _invlist_intersection_complement_2nd(invlist, PL_UpperLatin1, &invlist);

    }

    
    if (OP(node) != ANYOFH) {
        for (i = 0; i < NUM_ANYOF_CODE_POINTS; i++) {
            if (ANYOF_BITMAP_TEST(node, i)) {
                unsigned int start = i++;

                for (;    i < NUM_ANYOF_CODE_POINTS && ANYOF_BITMAP_TEST(node, i); ++i)
                {
                    
                }
                invlist = _add_range_to_invlist(invlist, start, i-1);
                new_node_has_latin1 = TRUE;
            }
        }
    }

    
    if (! (flags & ANYOF_INVERT) && OP(node) == ANYOFD && (flags & ANYOF_SHARED_d_MATCHES_ALL_NON_UTF8_NON_ASCII_non_d_WARN_SUPER))
    {
        _invlist_union(invlist, PL_UpperLatin1, &invlist);
    }

    
    if (flags & ANYOF_MATCHES_ALL_ABOVE_BITMAP) {
        _invlist_union_complement_2nd(invlist, PL_InBitmap, &invlist);
    }

    if (flags & ANYOF_INVERT) {
        _invlist_invert(invlist);
    }
    else if (flags & ANYOFL_FOLD) {
        if (new_node_has_latin1) {

            
            _invlist_union(invlist, PL_Latin1, &invlist);

            invlist = add_cp_to_invlist(invlist, LATIN_SMALL_LETTER_DOTLESS_I);
            invlist = add_cp_to_invlist(invlist, LATIN_CAPITAL_LETTER_I_WITH_DOT_ABOVE);
        }
        else {
            if (_invlist_contains_cp(invlist, LATIN_SMALL_LETTER_DOTLESS_I)) {
                invlist = add_cp_to_invlist(invlist, 'I');
            }
            if (_invlist_contains_cp(invlist, LATIN_CAPITAL_LETTER_I_WITH_DOT_ABOVE))
            {
                invlist = add_cp_to_invlist(invlist, 'i');
            }
        }
    }

    
    if (only_utf8_locale_invlist) {
        _invlist_union_maybe_complement_2nd(invlist, only_utf8_locale_invlist, flags & ANYOF_INVERT, &invlist);


    }

    return invlist;
}









STATIC void S_ssc_and(pTHX_ const RExC_state_t *pRExC_state, regnode_ssc *ssc, const regnode_charclass *and_with)

{
    

    SV* anded_cp_list;
    U8  and_with_flags = (OP(and_with) == ANYOFH) ? 0 : ANYOF_FLAGS(and_with);
    U8  anded_flags;

    PERL_ARGS_ASSERT_SSC_AND;

    assert(is_ANYOF_SYNTHETIC(ssc));

    
    if (is_ANYOF_SYNTHETIC(and_with)) {
        anded_cp_list = ((regnode_ssc *)and_with)->invlist;
        anded_flags = and_with_flags;

        
        if (ssc_is_anything((regnode_ssc *)and_with)) {
            anded_flags |= ANYOF_SHARED_d_MATCHES_ALL_NON_UTF8_NON_ASCII_non_d_WARN_SUPER;
        }
    }
    else {
        anded_cp_list = get_ANYOF_cp_list_for_ssc(pRExC_state, and_with);
        if (OP(and_with) == ANYOFD) {
            anded_flags = and_with_flags & ANYOF_COMMON_FLAGS;
        }
        else {
            anded_flags = and_with_flags &( ANYOF_COMMON_FLAGS |ANYOF_SHARED_d_MATCHES_ALL_NON_UTF8_NON_ASCII_non_d_WARN_SUPER |ANYOF_SHARED_d_UPPER_LATIN1_UTF8_STRING_MATCHES_non_d_RUNTIME_USER_PROP);


            if (ANYOFL_UTF8_LOCALE_REQD(and_with_flags)) {
                anded_flags &= ANYOFL_SHARED_UTF8_LOCALE_fold_HAS_MATCHES_nonfold_REQD;
            }
        }
    }

    ANYOF_FLAGS(ssc) &= anded_flags;

    

    if ((and_with_flags & ANYOF_INVERT)
        && ! is_ANYOF_SYNTHETIC(and_with))
    {
        unsigned int i;

        ssc_intersection(ssc, anded_cp_list, FALSE );



        
        if (! (and_with_flags & ANYOF_MATCHES_POSIXL)) {
            ANYOF_POSIXL_ZERO(ssc);
        }
        else if (ANYOF_POSIXL_SSC_TEST_ANY_SET(ssc)) {

            

            regnode_charclass_posixl temp;
            int add = 1;    

            Zero(&temp, 1, regnode_charclass_posixl);
            ANYOF_POSIXL_ZERO(&temp);
            for (i = 0; i < ANYOF_MAX; i++) {
                assert(i % 2 != 0 || ! ANYOF_POSIXL_TEST((regnode_charclass_posixl*) and_with, i)
                       || ! ANYOF_POSIXL_TEST((regnode_charclass_posixl*) and_with, i + 1));

                if (ANYOF_POSIXL_TEST((regnode_charclass_posixl*) and_with, i)) {
                    ANYOF_POSIXL_SET(&temp, i + add);
                }
                add = 0 - add; 
            }
            ANYOF_POSIXL_AND(&temp, ssc);

        } 
    } 
    else if (! is_ANYOF_SYNTHETIC(and_with)
             || ! ssc_is_cp_posixl_init(pRExC_state, (regnode_ssc *)and_with))
    {
        
        if (ssc_is_cp_posixl_init(pRExC_state, ssc)) {
            if (is_ANYOF_SYNTHETIC(and_with)) {
                StructCopy(and_with, ssc, regnode_ssc);
            }
            else {
                ssc->invlist = anded_cp_list;
                ANYOF_POSIXL_ZERO(ssc);
                if (and_with_flags & ANYOF_MATCHES_POSIXL) {
                    ANYOF_POSIXL_OR((regnode_charclass_posixl*) and_with, ssc);
                }
            }
        }
        else if (ANYOF_POSIXL_SSC_TEST_ANY_SET(ssc)
                 || (and_with_flags & ANYOF_MATCHES_POSIXL))
        {
            
            if (and_with_flags & ANYOF_MATCHES_POSIXL) {
                ANYOF_POSIXL_AND((regnode_charclass_posixl*) and_with, ssc);
            }
            ssc_union(ssc, anded_cp_list, FALSE);
        }
        else { 
            ssc_intersection(ssc, anded_cp_list, FALSE);
        }
    }
}

STATIC void S_ssc_or(pTHX_ const RExC_state_t *pRExC_state, regnode_ssc *ssc, const regnode_charclass *or_with)

{
    

    SV* ored_cp_list;
    U8 ored_flags;
    U8  or_with_flags = (OP(or_with) == ANYOFH) ? 0 : ANYOF_FLAGS(or_with);

    PERL_ARGS_ASSERT_SSC_OR;

    assert(is_ANYOF_SYNTHETIC(ssc));

    
    if (is_ANYOF_SYNTHETIC(or_with)) {
        ored_cp_list = ((regnode_ssc*) or_with)->invlist;
        ored_flags = or_with_flags;
    }
    else {
        ored_cp_list = get_ANYOF_cp_list_for_ssc(pRExC_state, or_with);
        ored_flags = or_with_flags & ANYOF_COMMON_FLAGS;
        if (OP(or_with) != ANYOFD) {
            ored_flags |= or_with_flags & ( ANYOF_SHARED_d_MATCHES_ALL_NON_UTF8_NON_ASCII_non_d_WARN_SUPER |ANYOF_SHARED_d_UPPER_LATIN1_UTF8_STRING_MATCHES_non_d_RUNTIME_USER_PROP);


            if (ANYOFL_UTF8_LOCALE_REQD(or_with_flags)) {
                ored_flags |= ANYOFL_SHARED_UTF8_LOCALE_fold_HAS_MATCHES_nonfold_REQD;
            }
        }
    }

    ANYOF_FLAGS(ssc) |= ored_flags;

    

    if ((or_with_flags & ANYOF_INVERT)
        && ! is_ANYOF_SYNTHETIC(or_with))
    {
        
    }   
    else if (or_with_flags & ANYOF_MATCHES_POSIXL) {
        ANYOF_POSIXL_OR((regnode_charclass_posixl*)or_with, ssc);
        if (ANYOF_POSIXL_SSC_TEST_ANY_SET(ssc)) {
            unsigned int i;
            for (i = 0; i < ANYOF_MAX; i += 2) {
                if (ANYOF_POSIXL_TEST(ssc, i) && ANYOF_POSIXL_TEST(ssc, i + 1))
                {
                    ssc_match_all_cp(ssc);
                    ANYOF_POSIXL_CLEAR(ssc, i);
                    ANYOF_POSIXL_CLEAR(ssc, i+1);
                }
            }
        }
    }

    ssc_union(ssc, ored_cp_list, FALSE );


}

PERL_STATIC_INLINE void S_ssc_union(pTHX_ regnode_ssc *ssc, SV* const invlist, const bool invert2nd)
{
    PERL_ARGS_ASSERT_SSC_UNION;

    assert(is_ANYOF_SYNTHETIC(ssc));

    _invlist_union_maybe_complement_2nd(ssc->invlist, invlist, invert2nd, &ssc->invlist);


}

PERL_STATIC_INLINE void S_ssc_intersection(pTHX_ regnode_ssc *ssc, SV* const invlist, const bool invert2nd)


{
    PERL_ARGS_ASSERT_SSC_INTERSECTION;

    assert(is_ANYOF_SYNTHETIC(ssc));

    _invlist_intersection_maybe_complement_2nd(ssc->invlist, invlist, invert2nd, &ssc->invlist);


}

PERL_STATIC_INLINE void S_ssc_add_range(pTHX_ regnode_ssc *ssc, const UV start, const UV end)
{
    PERL_ARGS_ASSERT_SSC_ADD_RANGE;

    assert(is_ANYOF_SYNTHETIC(ssc));

    ssc->invlist = _add_range_to_invlist(ssc->invlist, start, end);
}

PERL_STATIC_INLINE void S_ssc_cp_and(pTHX_ regnode_ssc *ssc, const UV cp)
{
    

    SV* cp_list = _new_invlist(2);

    PERL_ARGS_ASSERT_SSC_CP_AND;

    assert(is_ANYOF_SYNTHETIC(ssc));

    cp_list = add_cp_to_invlist(cp_list, cp);
    ssc_intersection(ssc, cp_list, FALSE );

    SvREFCNT_dec_NN(cp_list);
}

PERL_STATIC_INLINE void S_ssc_clear_locale(regnode_ssc *ssc)
{
    
    PERL_ARGS_ASSERT_SSC_CLEAR_LOCALE;

    assert(is_ANYOF_SYNTHETIC(ssc));

    ANYOF_POSIXL_ZERO(ssc);
    ANYOF_FLAGS(ssc) &= ~ANYOF_LOCALE_FLAGS;
}



STATIC bool S_is_ssc_worth_it(const RExC_state_t * pRExC_state, const regnode_ssc * ssc)
{
    

    U32 count = 0;      
    UV start, end;      
    const U32 max_code_points = (LOC)
                                ?  256 : ((  ! UNI_SEMANTICS ||  invlist_highest(ssc->invlist) < 256)

                                  ? 128 : NON_OTHER_COUNT);
    const U32 max_match = max_code_points / 2;

    PERL_ARGS_ASSERT_IS_SSC_WORTH_IT;

    invlist_iterinit(ssc->invlist);
    while (invlist_iternext(ssc->invlist, &start, &end)) {
        if (start >= max_code_points) {
            break;
        }
        end = MIN(end, max_code_points - 1);
        count += end - start + 1;
        if (count >= max_match) {
            invlist_iterfinish(ssc->invlist);
            return FALSE;
        }
    }

    return TRUE;
}


STATIC void S_ssc_finalize(pTHX_ RExC_state_t *pRExC_state, regnode_ssc *ssc)
{
    

    SV* invlist = invlist_clone(ssc->invlist, NULL);

    PERL_ARGS_ASSERT_SSC_FINALIZE;

    assert(is_ANYOF_SYNTHETIC(ssc));

    
    assert(! (ANYOF_FLAGS(ssc)
        & ~( ANYOF_COMMON_FLAGS |ANYOF_SHARED_d_MATCHES_ALL_NON_UTF8_NON_ASCII_non_d_WARN_SUPER |ANYOF_SHARED_d_UPPER_LATIN1_UTF8_STRING_MATCHES_non_d_RUNTIME_USER_PROP)));


    populate_ANYOF_from_invlist( (regnode *) ssc, &invlist);

    set_ANYOF_arg(pRExC_state, (regnode *) ssc, invlist, NULL, NULL);

    
    ssc->invlist = NULL;

    if (ANYOF_POSIXL_SSC_TEST_ANY_SET(ssc)) {
        ANYOF_FLAGS(ssc) |= ANYOF_MATCHES_POSIXL;
        OP(ssc) = ANYOFPOSIXL;
    }
    else if (RExC_contains_locale) {
        OP(ssc) = ANYOFL;
    }

    assert(! (ANYOF_FLAGS(ssc) & ANYOF_LOCALE_FLAGS) || RExC_contains_locale);
}













STATIC void S_dump_trie(pTHX_ const struct _reg_trie_data *trie, HV *widecharmap, AV *revcharmap, U32 depth)

{
    U32 state;
    SV *sv=sv_newmortal();
    int colwidth= widecharmap ? 6 : 4;
    U16 word;
    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_DUMP_TRIE;

    Perl_re_indentf( aTHX_  "Char : %-6s%-6s%-4s ", depth+1, "Match","Base","Ofs" );

    for( state = 0 ; state < trie->uniquecharcount ; state++ ) {
	SV ** const tmp = av_fetch( revcharmap, state, 0);
        if ( tmp ) {
            Perl_re_printf( aTHX_  "%*s", colwidth, pv_pretty(sv, SvPV_nolen_const(*tmp), SvCUR(*tmp), colwidth, PL_colors[0], PL_colors[1], (SvUTF8(*tmp) ? PERL_PV_ESCAPE_UNI : 0) | PERL_PV_ESCAPE_FIRSTCHAR )





            );
        }
    }
    Perl_re_printf( aTHX_  "\n");
    Perl_re_indentf( aTHX_ "State|-----------------------", depth+1);

    for( state = 0 ; state < trie->uniquecharcount ; state++ )
        Perl_re_printf( aTHX_  "%.*s", colwidth, "--------");
    Perl_re_printf( aTHX_  "\n");

    for( state = 1 ; state < trie->statecount ; state++ ) {
	const U32 base = trie->states[ state ].trans.base;

        Perl_re_indentf( aTHX_  "#%4" UVXf "|", depth+1, (UV)state);

        if ( trie->states[ state ].wordnum ) {
            Perl_re_printf( aTHX_  " W%4X", trie->states[ state ].wordnum );
        } else {
            Perl_re_printf( aTHX_  "%6s", "" );
        }

        Perl_re_printf( aTHX_  " @%4" UVXf " ", (UV)base );

        if ( base ) {
            U32 ofs = 0;

            while( ( base + ofs  < trie->uniquecharcount ) || ( base + ofs - trie->uniquecharcount < trie->lasttrans && trie->trans[ base + ofs - trie->uniquecharcount ].check != state))


                    ofs++;

            Perl_re_printf( aTHX_  "+%2" UVXf "[ ", (UV)ofs);

            for ( ofs = 0 ; ofs < trie->uniquecharcount ; ofs++ ) {
                if ( ( base + ofs >= trie->uniquecharcount )
                        && ( base + ofs - trie->uniquecharcount < trie->lasttrans )
                        && trie->trans[ base + ofs - trie->uniquecharcount ].check == state )
                {
                   Perl_re_printf( aTHX_  "%*" UVXf, colwidth, (UV)trie->trans[ base + ofs - trie->uniquecharcount ].next );

                } else {
                    Perl_re_printf( aTHX_  "%*s", colwidth,"   ." );
                }
            }

            Perl_re_printf( aTHX_  "]");

        }
        Perl_re_printf( aTHX_  "\n" );
    }
    Perl_re_indentf( aTHX_  "word_info N:(prev,len)=", depth);
    for (word=1; word <= trie->wordcount; word++) {
        Perl_re_printf( aTHX_  " %d:(%d,%d)", (int)word, (int)(trie->wordinfo[word].prev), (int)(trie->wordinfo[word].len));

    }
    Perl_re_printf( aTHX_  "\n" );
}

STATIC void S_dump_trie_interim_list(pTHX_ const struct _reg_trie_data *trie, HV *widecharmap, AV *revcharmap, U32 next_alloc, U32 depth)


{
    U32 state;
    SV *sv=sv_newmortal();
    int colwidth= widecharmap ? 6 : 4;
    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_DUMP_TRIE_INTERIM_LIST;

    
    Perl_re_indentf( aTHX_  "State :Word | Transition Data\n", depth+1 );
    Perl_re_indentf( aTHX_  "%s", depth+1, "------:-----+-----------------\n" );

    for( state=1 ; state < next_alloc ; state ++ ) {
        U16 charid;

        Perl_re_indentf( aTHX_  " %4" UVXf " :", depth+1, (UV)state  );
        if ( ! trie->states[ state ].wordnum ) {
            Perl_re_printf( aTHX_  "%5s| ","");
        } else {
            Perl_re_printf( aTHX_  "W%4x| ", trie->states[ state ].wordnum );

        }
        for( charid = 1 ; charid <= TRIE_LIST_USED( state ) ; charid++ ) {
	    SV ** const tmp = av_fetch( revcharmap, TRIE_LIST_ITEM(state, charid).forid, 0);
	    if ( tmp ) {
                Perl_re_printf( aTHX_  "%*s:%3X=%4" UVXf " | ", colwidth, pv_pretty(sv, SvPV_nolen_const(*tmp), SvCUR(*tmp), colwidth, PL_colors[0], PL_colors[1], (SvUTF8(*tmp) ? PERL_PV_ESCAPE_UNI : 0)




                              | PERL_PV_ESCAPE_FIRSTCHAR ) , TRIE_LIST_ITEM(state, charid).forid, (UV)TRIE_LIST_ITEM(state, charid).newstate );



                if (!(charid % 10))
                    Perl_re_printf( aTHX_  "\n%*s| ", (int)((depth * 2) + 14), "");
            }
        }
        Perl_re_printf( aTHX_  "\n");
    }
}


STATIC void S_dump_trie_interim_table(pTHX_ const struct _reg_trie_data *trie, HV *widecharmap, AV *revcharmap, U32 next_alloc, U32 depth)


{
    U32 state;
    U16 charid;
    SV *sv=sv_newmortal();
    int colwidth= widecharmap ? 6 : 4;
    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_DUMP_TRIE_INTERIM_TABLE;

    

    Perl_re_indentf( aTHX_  "Char : ", depth+1 );

    for( charid = 0 ; charid < trie->uniquecharcount ; charid++ ) {
	SV ** const tmp = av_fetch( revcharmap, charid, 0);
        if ( tmp ) {
            Perl_re_printf( aTHX_  "%*s", colwidth, pv_pretty(sv, SvPV_nolen_const(*tmp), SvCUR(*tmp), colwidth, PL_colors[0], PL_colors[1], (SvUTF8(*tmp) ? PERL_PV_ESCAPE_UNI : 0) | PERL_PV_ESCAPE_FIRSTCHAR )





            );
        }
    }

    Perl_re_printf( aTHX_ "\n");
    Perl_re_indentf( aTHX_  "State+-", depth+1 );

    for( charid=0 ; charid < trie->uniquecharcount ; charid++ ) {
        Perl_re_printf( aTHX_  "%.*s", colwidth,"--------");
    }

    Perl_re_printf( aTHX_  "\n" );

    for( state=1 ; state < next_alloc ; state += trie->uniquecharcount ) {

        Perl_re_indentf( aTHX_  "%4" UVXf " : ", depth+1, (UV)TRIE_NODENUM( state ) );


        for( charid = 0 ; charid < trie->uniquecharcount ; charid++ ) {
            UV v=(UV)SAFE_TRIE_NODENUM( trie->trans[ state + charid ].next );
            if (v)
                Perl_re_printf( aTHX_  "%*" UVXf, colwidth, v );
            else Perl_re_printf( aTHX_  "%*s", colwidth, "." );
        }
        if ( ! trie->states[ TRIE_NODENUM( state ) ].wordnum ) {
            Perl_re_printf( aTHX_  " (%4" UVXf ")\n", (UV)trie->trans[ state ].check );
        } else {
            Perl_re_printf( aTHX_  " (%4" UVXf ") W%4X\n", (UV)trie->trans[ state ].check, trie->states[ TRIE_NODENUM( state ) ].wordnum );

        }
    }
}






























































































































STATIC I32 S_make_trie(pTHX_ RExC_state_t *pRExC_state, regnode *startbranch, regnode *first, regnode *last, regnode *tail, U32 word_count, U32 flags, U32 depth)


{
    
    reg_trie_data *trie;
    HV *widecharmap = NULL;
    AV *revcharmap = newAV();
    regnode *cur;
    STRLEN len = 0;
    UV uvc = 0;
    U16 curword = 0;
    U32 next_alloc = 0;
    regnode *jumper = NULL;
    regnode *nextbranch = NULL;
    regnode *convert = NULL;
    U32 *prev_states; 
    
    const U8 * folder = NULL;

    

    const U32 data_slot = add_data( pRExC_state, STR_WITH_LEN("tuaa"));
    AV *trie_words = NULL;
    

    const U32 data_slot = add_data( pRExC_state, STR_WITH_LEN("tu"));
    STRLEN trie_charcount=0;

    SV *re_trie_maxbuff;
    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_MAKE_TRIE;

    PERL_UNUSED_ARG(depth);


    switch (flags) {
        case EXACT: case EXACT_ONLY8: case EXACTL: break;
	case EXACTFAA:
        case EXACTFUP:
	case EXACTFU:
	case EXACTFLU8: folder = PL_fold_latin1; break;
	case EXACTF:  folder = PL_fold; break;
        default: Perl_croak( aTHX_ "panic! In trie construction, unknown node type %u %s", (unsigned) flags, PL_reg_name[flags] );
    }

    trie = (reg_trie_data *) PerlMemShared_calloc( 1, sizeof(reg_trie_data) );
    trie->refcount = 1;
    trie->startstate = 1;
    trie->wordcount = word_count;
    RExC_rxi->data->data[ data_slot ] = (void*)trie;
    trie->charmap = (U16 *) PerlMemShared_calloc( 256, sizeof(U16) );
    if (flags == EXACT || flags == EXACT_ONLY8 || flags == EXACTL)
	trie->bitmap = (char *) PerlMemShared_calloc( ANYOF_BITMAP_SIZE, 1 );
    trie->wordinfo = (reg_trie_wordinfo *) PerlMemShared_calloc( trie->wordcount+1, sizeof(reg_trie_wordinfo));

    DEBUG_r({
        trie_words = newAV();
    });

    re_trie_maxbuff = get_sv(RE_TRIE_MAXBUF_NAME, GV_ADD);
    assert(re_trie_maxbuff);
    if (!SvIOK(re_trie_maxbuff)) {
        sv_setiv(re_trie_maxbuff, RE_TRIE_MAXBUF_INIT);
    }
    DEBUG_TRIE_COMPILE_r({
        Perl_re_indentf( aTHX_ "make_trie start==%d, first==%d, last==%d, tail==%d depth=%d\n", depth+1, REG_NODE_NUM(startbranch), REG_NODE_NUM(first), REG_NODE_NUM(last), REG_NODE_NUM(tail), (int)depth);



    });

   
    if ( first == startbranch && OP( last ) != BRANCH ) {
        
        convert = first;
    } else {
        
        convert = NEXTOPER( first );
    }

    

    for ( cur = first ; cur < last ; cur = regnext( cur ) ) {
        regnode *noper = NEXTOPER( cur );
        const U8 *uc;
        const U8 *e;
        int foldlen = 0;
        U32 wordlen      = 0;         
        STRLEN minchars = 0;
        STRLEN maxchars = 0;
        bool set_bit = trie->bitmap ? 1 : 0; 

        if (OP(noper) == NOTHING) {
            

            regnode *noper_next= regnext(noper);
            if (noper_next < tail)
                noper= noper_next;
        }

        if (    noper < tail && (    OP(noper) == flags || (flags == EXACT && OP(noper) == EXACT_ONLY8)

                || (flags == EXACTFU && (   OP(noper) == EXACTFU_ONLY8 || OP(noper) == EXACTFUP))))
        {
            uc= (U8*)STRING(noper);
            e= uc + STR_LEN(noper);
        } else {
            trie->minlen= 0;
            continue;
        }


        if ( set_bit ) { 
            TRIE_BITMAP_SET(trie,*uc); 
            if (OP( noper ) == EXACTFUP) {
                
                TRIE_BITMAP_SET(trie, LATIN_SMALL_LETTER_SHARP_S);
            }
        }

        for ( ; uc < e ; uc += len ) {  
            TRIE_CHARCOUNT(trie)++;
            TRIE_READ_CHAR;

            

            maxchars++;

            
            if (folder == NULL) {
                minchars++;
            }
            else if (foldlen > 0) {
                foldlen -= (UTF) ? UTF8SKIP(uc) : 1;
            }
            else {
                minchars++;

                
                if (UTF) {
                    if ((foldlen = is_MULTI_CHAR_FOLD_utf8_safe(uc, e))) {
                        foldlen -= UTF8SKIP(uc);
                    }
                }
                else if ((foldlen = is_MULTI_CHAR_FOLD_latin1_safe(uc, e))) {
                    foldlen--;
                }
            }

            
            if ( uvc < 256 ) {
                if ( folder ) {
                    U8 folded= folder[ (U8) uvc ];
                    if ( !trie->charmap[ folded ] ) {
                        trie->charmap[ folded ]=( ++trie->uniquecharcount );
                        TRIE_STORE_REVCHAR( folded );
                    }
                }
                if ( !trie->charmap[ uvc ] ) {
                    trie->charmap[ uvc ]=( ++trie->uniquecharcount );
                    TRIE_STORE_REVCHAR( uvc );
                }
                if ( set_bit ) {
		    
                    TRIE_BITMAP_SET_FOLDED(trie, uvc, folder);
                    set_bit = 0; 
                }
            } else {

                

                SV** svpp;
                if ( !widecharmap )
                    widecharmap = newHV();

                svpp = hv_fetch( widecharmap, (char*)&uvc, sizeof( UV ), 1 );

                if ( !svpp )
                    Perl_croak( aTHX_ "error creating/fetching widecharmap entry for 0x%" UVXf, uvc );

                if ( !SvTRUE( *svpp ) ) {
                    sv_setiv( *svpp, ++trie->uniquecharcount );
                    TRIE_STORE_REVCHAR(uvc);
                }
            }
        } 

        
        if( cur == first ) {
            trie->minlen = minchars;
            trie->maxlen = maxchars;
        } else if (minchars < trie->minlen) {
            trie->minlen = minchars;
        } else if (maxchars > trie->maxlen) {
            trie->maxlen = maxchars;
        }
    } 
    DEBUG_TRIE_COMPILE_r( Perl_re_indentf( aTHX_ "TRIE(%s): W:%d C:%d Uq:%d Min:%d Max:%d\n", depth+1, ( widecharmap ? "UTF8" : "NATIVE" ), (int)word_count, (int)TRIE_CHARCOUNT(trie), trie->uniquecharcount, (int)trie->minlen, (int)trie->maxlen )





    );

    


    Newx(prev_states, TRIE_CHARCOUNT(trie) + 2, U32);
    prev_states[1] = 0;

    if ( (IV)( ( TRIE_CHARCOUNT(trie) + 1 ) * trie->uniquecharcount + 1)
                                                    > SvIV(re_trie_maxbuff) )
    {
        

        STRLEN transcount = 1;

        DEBUG_TRIE_COMPILE_MORE_r( Perl_re_indentf( aTHX_  "Compiling trie using list compiler\n", depth+1));

	trie->states = (reg_trie_state *)
	    PerlMemShared_calloc( TRIE_CHARCOUNT(trie) + 2, sizeof(reg_trie_state) );
        TRIE_LIST_NEW(1);
        next_alloc = 2;

        for ( cur = first ; cur < last ; cur = regnext( cur ) ) {

            regnode *noper   = NEXTOPER( cur );
	    U32 state        = 1;         
	    U16 charid       = 0;         
            U32 wordlen      = 0;         

            if (OP(noper) == NOTHING) {
                regnode *noper_next= regnext(noper);
                if (noper_next < tail)
                    noper= noper_next;
                
            }

            if (    noper < tail && (    OP(noper) == flags || (flags == EXACT && OP(noper) == EXACT_ONLY8)

                    || (flags == EXACTFU && (   OP(noper) == EXACTFU_ONLY8 || OP(noper) == EXACTFUP))))
            {
                const U8 *uc= (U8*)STRING(noper);
                const U8 *e= uc + STR_LEN(noper);

                for ( ; uc < e ; uc += len ) {

                    TRIE_READ_CHAR;

                    if ( uvc < 256 ) {
                        charid = trie->charmap[ uvc ];
		    } else {
                        SV** const svpp = hv_fetch( widecharmap, (char*)&uvc, sizeof( UV ), 0);


                        if ( !svpp ) {
                            charid = 0;
                        } else {
                            charid=(U16)SvIV( *svpp );
                        }
		    }
                    
                    if ( charid ) {

                        U16 check;
                        U32 newstate = 0;

                        charid--;
                        if ( !trie->states[ state ].trans.list ) {
                            TRIE_LIST_NEW( state );
			}
                        for ( check = 1;
                              check <= TRIE_LIST_USED( state );
                              check++ )
                        {
                            if ( TRIE_LIST_ITEM( state, check ).forid == charid )
                            {
                                newstate = TRIE_LIST_ITEM( state, check ).newstate;
                                break;
                            }
                        }
                        if ( ! newstate ) {
                            newstate = next_alloc++;
			    prev_states[newstate] = state;
                            TRIE_LIST_PUSH( state, charid, newstate );
                            transcount++;
                        }
                        state = newstate;
                    } else {
                        Perl_croak( aTHX_ "panic! In trie construction, no char mapping for %" IVdf, uvc );
		    }
		}
            } else {
                
                noper= NEXTOPER(cur);
            }
            TRIE_HANDLE_WORD(state);

        } 

        
        trie->statecount = next_alloc;
        trie->states = (reg_trie_state *)
	    PerlMemShared_realloc( trie->states, next_alloc * sizeof(reg_trie_state) );


        
        DEBUG_TRIE_COMPILE_MORE_r(dump_trie_interim_list(trie, widecharmap, revcharmap, next_alloc, depth+1)

        );

        trie->trans = (reg_trie_trans *)
	    PerlMemShared_calloc( transcount, sizeof(reg_trie_trans) );
        {
            U32 state;
            U32 tp = 0;
            U32 zp = 0;


            for( state=1 ; state < next_alloc ; state ++ ) {
                U32 base=0;

                

                if (trie->states[state].trans.list) {
                    U16 minid=TRIE_LIST_ITEM( state, 1).forid;
                    U16 maxid=minid;
		    U16 idx;

                    for( idx = 2 ; idx <= TRIE_LIST_USED( state ) ; idx++ ) {
			const U16 forid = TRIE_LIST_ITEM( state, idx).forid;
			if ( forid < minid ) {
			    minid=forid;
			} else if ( forid > maxid ) {
			    maxid=forid;
			}
                    }
                    if ( transcount < tp + maxid - minid + 1) {
                        transcount *= 2;
			trie->trans = (reg_trie_trans *)
			    PerlMemShared_realloc( trie->trans, transcount * sizeof(reg_trie_trans) );

                        Zero( trie->trans + (transcount / 2), transcount / 2, reg_trie_trans );

                    }
                    base = trie->uniquecharcount + tp - minid;
                    if ( maxid == minid ) {
                        U32 set = 0;
                        for ( ; zp < tp ; zp++ ) {
                            if ( ! trie->trans[ zp ].next ) {
                                base = trie->uniquecharcount + zp - minid;
                                trie->trans[ zp ].next = TRIE_LIST_ITEM( state, 1).newstate;
                                trie->trans[ zp ].check = state;
                                set = 1;
                                break;
                            }
                        }
                        if ( !set ) {
                            trie->trans[ tp ].next = TRIE_LIST_ITEM( state, 1).newstate;
                            trie->trans[ tp ].check = state;
                            tp++;
                            zp = tp;
                        }
                    } else {
                        for ( idx=1; idx <= TRIE_LIST_USED( state ) ; idx++ ) {
                            const U32 tid = base - trie->uniquecharcount + TRIE_LIST_ITEM( state, idx ).forid;

                            trie->trans[ tid ].next = TRIE_LIST_ITEM( state, idx ).newstate;
                            trie->trans[ tid ].check = state;
                        }
                        tp += ( maxid - minid + 1 );
                    }
                    Safefree(trie->states[ state ].trans.list);
                }
                
                trie->states[ state ].trans.base=base;
            }
            trie->lasttrans = tp + 1;
        }
    } else {
        
        DEBUG_TRIE_COMPILE_MORE_r( Perl_re_indentf( aTHX_  "Compiling trie using table compiler\n", depth+1));

	trie->trans = (reg_trie_trans *)
	    PerlMemShared_calloc( ( TRIE_CHARCOUNT(trie) + 1 )
				  * trie->uniquecharcount + 1, sizeof(reg_trie_trans) );
        trie->states = (reg_trie_state *)
	    PerlMemShared_calloc( TRIE_CHARCOUNT(trie) + 2, sizeof(reg_trie_state) );
        next_alloc = trie->uniquecharcount + 1;


        for ( cur = first ; cur < last ; cur = regnext( cur ) ) {

            regnode *noper   = NEXTOPER( cur );

            U32 state        = 1;         

            U16 charid       = 0;         
            U32 accept_state = 0;         

            U32 wordlen      = 0;         

            if (OP(noper) == NOTHING) {
                regnode *noper_next= regnext(noper);
                if (noper_next < tail)
                    noper= noper_next;
                
            }

            if (    noper < tail && (    OP(noper) == flags || (flags == EXACT && OP(noper) == EXACT_ONLY8)

                    || (flags == EXACTFU && (   OP(noper) == EXACTFU_ONLY8 || OP(noper) == EXACTFUP))))
            {
                const U8 *uc= (U8*)STRING(noper);
                const U8 *e= uc + STR_LEN(noper);

                for ( ; uc < e ; uc += len ) {

                    TRIE_READ_CHAR;

                    if ( uvc < 256 ) {
                        charid = trie->charmap[ uvc ];
                    } else {
                        SV* const * const svpp = hv_fetch( widecharmap, (char*)&uvc, sizeof( UV ), 0);


                        charid = svpp ? (U16)SvIV(*svpp) : 0;
                    }
                    if ( charid ) {
                        charid--;
                        if ( !trie->trans[ state + charid ].next ) {
                            trie->trans[ state + charid ].next = next_alloc;
                            trie->trans[ state ].check++;
			    prev_states[TRIE_NODENUM(next_alloc)] = TRIE_NODENUM(state);
                            next_alloc += trie->uniquecharcount;
                        }
                        state = trie->trans[ state + charid ].next;
                    } else {
                        Perl_croak( aTHX_ "panic! In trie construction, no char mapping for %" IVdf, uvc );
                    }
                    
                }
            } else {
                
                noper= NEXTOPER(cur);
            }
            accept_state = TRIE_NODENUM( state );
            TRIE_HANDLE_WORD(accept_state);

        } 

        
        DEBUG_TRIE_COMPILE_MORE_r(dump_trie_interim_table(trie, widecharmap, revcharmap, next_alloc, depth+1));


        {
        
        const U32 laststate = TRIE_NODENUM( next_alloc );
	U32 state, charid;
        U32 pos = 0, zp=0;
        trie->statecount = laststate;

        for ( state = 1 ; state < laststate ; state++ ) {
            U8 flag = 0;
	    const U32 stateidx = TRIE_NODEIDX( state );
	    const U32 o_used = trie->trans[ stateidx ].check;
	    U32 used = trie->trans[ stateidx ].check;
            trie->trans[ stateidx ].check = 0;

            for ( charid = 0;
                  used && charid < trie->uniquecharcount;
                  charid++ )
            {
                if ( flag || trie->trans[ stateidx + charid ].next ) {
                    if ( trie->trans[ stateidx + charid ].next ) {
                        if (o_used == 1) {
                            for ( ; zp < pos ; zp++ ) {
                                if ( ! trie->trans[ zp ].next ) {
                                    break;
                                }
                            }
                            trie->states[ state ].trans.base = zp + trie->uniquecharcount - charid ;


                            trie->trans[ zp ].next = SAFE_TRIE_NODENUM( trie->trans[ stateidx + charid ].next );

                            trie->trans[ zp ].check = state;
                            if ( ++zp > pos ) pos = zp;
                            break;
                        }
                        used--;
                    }
                    if ( !flag ) {
                        flag = 1;
                        trie->states[ state ].trans.base = pos + trie->uniquecharcount - charid ;
                    }
                    trie->trans[ pos ].next = SAFE_TRIE_NODENUM( trie->trans[ stateidx + charid ].next );

                    trie->trans[ pos ].check = state;
                    pos++;
                }
            }
        }
        trie->lasttrans = pos + 1;
        trie->states = (reg_trie_state *)
	    PerlMemShared_realloc( trie->states, laststate * sizeof(reg_trie_state) );
        DEBUG_TRIE_COMPILE_MORE_r( Perl_re_indentf( aTHX_  "Alloc: %d Orig: %" IVdf " elements, Final:%" IVdf ". Savings of %%%5.2f\n", depth+1, (int)( ( TRIE_CHARCOUNT(trie) + 1 ) * trie->uniquecharcount + 1 ), (IV)next_alloc, (IV)pos, ( ( next_alloc - pos ) * 100 ) / (double)next_alloc );






            );

        } 
    }
    DEBUG_TRIE_COMPILE_MORE_r( Perl_re_indentf( aTHX_  "Statecount:%" UVxf " Lasttrans:%" UVxf "\n", depth+1, (UV)trie->statecount, (UV)trie->lasttrans)



    );
    
    trie->trans = (reg_trie_trans *)
	PerlMemShared_realloc( trie->trans, trie->lasttrans * sizeof(reg_trie_trans) );

    {   
        U8 nodetype =(U8)(flags & 0xFF);
        char *str=NULL;


        regnode *optimize = NULL;


        U32 mjd_offset = 0;
        U32 mjd_nodelen = 0;


        
        
        if ( first != startbranch || OP( last ) == BRANCH ) {
            
            NEXT_OFF( first ) = (U16)(last - first);

            DEBUG_r({
                mjd_offset= Node_Offset((convert));
                mjd_nodelen= Node_Length((convert));
            });

            
        }

        else {
            DEBUG_r({
                const  regnode *nop = NEXTOPER( convert );
                mjd_offset= Node_Offset((nop));
                mjd_nodelen= Node_Length((nop));
            });
        }
        DEBUG_OPTIMISE_r( Perl_re_indentf( aTHX_  "MJD offset:%" UVuf " MJD length:%" UVuf "\n", depth+1, (UV)mjd_offset, (UV)mjd_nodelen)


        );

        
        trie->startstate= 1;
        if ( trie->bitmap && !widecharmap && !trie->jump  ) {
            
            U32 state;
            for ( state = 1 ; state < trie->statecount-1 ; state++ ) {
                U32 ofs = 0;
                I32 first_ofs = -1; 
                U32 count = 0;
                const U32 base = trie->states[ state ].trans.base;

                
                if ( trie->states[state].wordnum )
                        count = 1;

                for ( ofs = 0 ; ofs < trie->uniquecharcount ; ofs++ ) {
                    if ( ( base + ofs >= trie->uniquecharcount ) && ( base + ofs - trie->uniquecharcount < trie->lasttrans ) && trie->trans[ base + ofs - trie->uniquecharcount ].check == state )

                    {
                        if ( ++count > 1 ) {
                            
                            SV **tmp;
                            U8 *ch;
                            
                            if ( state == 1 ) break;
                            tmp = av_fetch( revcharmap, ofs, 0);
                            ch = (U8*)SvPV_nolen_const( *tmp );

                            
                            if ( count == 2 ) {
                                
                                Zero(trie->bitmap, ANYOF_BITMAP_SIZE, char);
                                DEBUG_OPTIMISE_r( Perl_re_indentf( aTHX_  "New Start State=%" UVuf " Class: [", depth+1, (UV)state));


                                if (first_ofs >= 0) {
                                    SV ** const tmp = av_fetch( revcharmap, first_ofs, 0);
				    const U8 * const ch = (U8*)SvPV_nolen_const( *tmp );

                                    TRIE_BITMAP_SET_FOLDED(trie,*ch, folder);
                                    DEBUG_OPTIMISE_r( Perl_re_printf( aTHX_  "%s", (char*)ch)
                                    );
				}
			    }
                            
                            TRIE_BITMAP_SET_FOLDED(trie,*ch, folder);
                            DEBUG_OPTIMISE_r(Perl_re_printf( aTHX_ "%s", ch));
			}
                        first_ofs = ofs;
		    }
                }
                if ( count == 1 ) {
                    
                    SV **tmp = av_fetch( revcharmap, first_ofs, 0);
                    STRLEN len;
                    char *ch = SvPV( *tmp, len );
                    DEBUG_OPTIMISE_r({
                        SV *sv=sv_newmortal();
                        Perl_re_indentf( aTHX_  "Prefix State: %" UVuf " Ofs:%" UVuf " Char='%s'\n", depth+1, (UV)state, (UV)first_ofs, pv_pretty(sv, SvPV_nolen_const(*tmp), SvCUR(*tmp), 6, PL_colors[0], PL_colors[1], (SvUTF8(*tmp) ? PERL_PV_ESCAPE_UNI : 0) | PERL_PV_ESCAPE_FIRSTCHAR )






                        );
                    });
                    if ( state==1 ) {
                        OP( convert ) = nodetype;
                        str=STRING(convert);
                        STR_LEN(convert)=0;
                    }
                    STR_LEN(convert) += len;
                    while (len--)
                        *str++ = *ch++;
		} else {

		    if (state>1)
                        DEBUG_OPTIMISE_r(Perl_re_printf( aTHX_ "]\n"));

		    break;
		}
	    }
	    trie->prefixlen = (state-1);
            if (str) {
                regnode *n = convert+NODE_SZ_STR(convert);
                NEXT_OFF(convert) = NODE_SZ_STR(convert);
                trie->startstate = state;
                trie->minlen -= (state - 1);
                trie->maxlen -= (state - 1);

               
               if (  1  DEBUG_r_TEST  ) {





                   regnode *fix = convert;
                   U32 word = trie->wordcount;

                   mjd_nodelen++;

                   Set_Node_Offset_Length(convert, mjd_offset, state - 1);
                   while( ++fix < n ) {
                       Set_Node_Offset_Length(fix, 0, 0);
                   }
                   while (word--) {
                       SV ** const tmp = av_fetch( trie_words, word, 0 );
                       if (tmp) {
                           if ( STR_LEN(convert) <= SvCUR(*tmp) )
                               sv_chop(*tmp, SvPV_nolen(*tmp) + STR_LEN(convert));
                           else sv_chop(*tmp, SvPV_nolen(*tmp) + SvCUR(*tmp));
                       }
                   }
               }

                if (trie->maxlen) {
                    convert = n;
		} else {
                    NEXT_OFF(convert) = (U16)(tail - convert);
                    DEBUG_r(optimize= n);
                }
            }
        }
        if (!jumper)
            jumper = last;
        if ( trie->maxlen ) {
	    NEXT_OFF( convert ) = (U16)(tail - convert);
	    ARG_SET( convert, data_slot );
	    
	    if (trie->jump)
	        trie->jump[0] = (U16)(nextbranch - convert);

            
            if ( !trie->states[trie->startstate].wordnum && trie->bitmap && ( (char *)jumper - (char *)convert) >= (int)sizeof(struct regnode_charclass) )

            {
                OP( convert ) = TRIEC;
                Copy(trie->bitmap, ((struct regnode_charclass *)convert)->bitmap, ANYOF_BITMAP_SIZE, char);
                PerlMemShared_free(trie->bitmap);
                trie->bitmap= NULL;
            } else OP( convert ) = TRIE;

            
            convert->flags = nodetype;
            DEBUG_r({
            optimize = convert + NODE_STEP_REGNODE + regarglen[ OP( convert ) ];

            });
            
        }
        
        DEBUG_r(if (optimize) {
            regnode *opt = convert;

            while ( ++opt < optimize) {
                Set_Node_Offset_Length(opt, 0, 0);
            }
            
            while( optimize < jumper ) {
                Track_Code( mjd_nodelen += Node_Length((optimize)); );
                OP( optimize ) = OPTIMIZED;
                Set_Node_Offset_Length(optimize, 0, 0);
                optimize++;
            }
            Set_Node_Offset_Length(convert, mjd_offset, mjd_nodelen);
        });
    } 

    
    {
	U16 word;
	U32 state;
	U16 prev;

	for (word=1; word <= trie->wordcount; word++) {
	    prev = 0;
	    if (trie->wordinfo[word].prev)
		continue;
	    state = trie->wordinfo[word].accept;
	    while (state) {
		state = prev_states[state];
		if (!state)
		    break;
		prev = trie->states[state].wordnum;
		if (prev)
		    break;
	    }
	    trie->wordinfo[word].prev = prev;
	}
	Safefree(prev_states);
    }


    
    DEBUG_TRIE_COMPILE_r(dump_trie(trie, widecharmap, revcharmap, depth+1));

    RExC_rxi->data->data[ data_slot + 1 ] = (void*)widecharmap;

    RExC_rxi->data->data[ data_slot + TRIE_WORDS_OFFSET ] = (void*)trie_words;
    RExC_rxi->data->data[ data_slot + 3 ] = (void*)revcharmap;

    SvREFCNT_dec_NN(revcharmap);

    return trie->jump ? MADE_JUMP_TRIE : trie->startstate>1 ? MADE_EXACT_TRIE : MADE_TRIE;



}

STATIC regnode * S_construct_ahocorasick_from_trie(pTHX_ RExC_state_t *pRExC_state, regnode *source, U32 depth)
{

 
    const U32 trie_offset = ARG(source);
    reg_trie_data *trie=(reg_trie_data *)RExC_rxi->data->data[trie_offset];
    U32 *q;
    const U32 ucharcount = trie->uniquecharcount;
    const U32 numstates = trie->statecount;
    const U32 ubound = trie->lasttrans + ucharcount;
    U32 q_read = 0;
    U32 q_write = 0;
    U32 charid;
    U32 base = trie->states[ 1 ].trans.base;
    U32 *fail;
    reg_ac_data *aho;
    const U32 data_slot = add_data( pRExC_state, STR_WITH_LEN("T"));
    regnode *stclass;
    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_CONSTRUCT_AHOCORASICK_FROM_TRIE;
    PERL_UNUSED_CONTEXT;

    PERL_UNUSED_ARG(depth);


    if ( OP(source) == TRIE ) {
        struct regnode_1 *op = (struct regnode_1 *)
            PerlMemShared_calloc(1, sizeof(struct regnode_1));
        StructCopy(source, op, struct regnode_1);
        stclass = (regnode *)op;
    } else {
        struct regnode_charclass *op = (struct regnode_charclass *)
            PerlMemShared_calloc(1, sizeof(struct regnode_charclass));
        StructCopy(source, op, struct regnode_charclass);
        stclass = (regnode *)op;
    }
    OP(stclass)+=2; 

    ARG_SET( stclass, data_slot );
    aho = (reg_ac_data *) PerlMemShared_calloc( 1, sizeof(reg_ac_data) );
    RExC_rxi->data->data[ data_slot ] = (void*)aho;
    aho->trie=trie_offset;
    aho->states=(reg_trie_state *)PerlMemShared_malloc( numstates * sizeof(reg_trie_state) );
    Copy( trie->states, aho->states, numstates, reg_trie_state );
    Newx( q, numstates, U32);
    aho->fail = (U32 *) PerlMemShared_calloc( numstates, sizeof(U32) );
    aho->refcount = 1;
    fail = aho->fail;
    
    fail[ 0 ] = fail[ 1 ] = 1;

    for ( charid = 0; charid < ucharcount ; charid++ ) {
	const U32 newstate = TRIE_TRANS_STATE( 1, base, ucharcount, charid, 0 );
	if ( newstate ) {
            q[ q_write ] = newstate;
            
            fail[ q[ q_write++ ] ]=1;
        }
    }
    while ( q_read < q_write) {
	const U32 cur = q[ q_read++ % numstates ];
        base = trie->states[ cur ].trans.base;

        for ( charid = 0 ; charid < ucharcount ; charid++ ) {
	    const U32 ch_state = TRIE_TRANS_STATE( cur, base, ucharcount, charid, 1 );
	    if (ch_state) {
                U32 fail_state = cur;
                U32 fail_base;
                do {
                    fail_state = fail[ fail_state ];
                    fail_base = aho->states[ fail_state ].trans.base;
                } while ( !TRIE_TRANS_STATE( fail_state, fail_base, ucharcount, charid, 1 ) );

                fail_state = TRIE_TRANS_STATE( fail_state, fail_base, ucharcount, charid, 1 );
                fail[ ch_state ] = fail_state;
                if ( !aho->states[ ch_state ].wordnum && aho->states[ fail_state ].wordnum )
                {
                        aho->states[ ch_state ].wordnum =  aho->states[ fail_state ].wordnum;
                }
                q[ q_write++ % numstates] = ch_state;
            }
        }
    }
    
    fail[ 0 ] = fail[ 1 ] = 0;
    DEBUG_TRIE_COMPILE_r({
        Perl_re_indentf( aTHX_  "Stclass Failtable (%" UVuf " states): 0", depth, (UV)numstates );

        for( q_read=1; q_read<numstates; q_read++ ) {
            Perl_re_printf( aTHX_  ", %" UVuf, (UV)fail[q_read]);
        }
        Perl_re_printf( aTHX_  "\n");
    });
    Safefree(q);
    
    return stclass;
}







STATIC U32 S_join_exact(pTHX_ RExC_state_t *pRExC_state, regnode *scan, UV *min_subtract, bool *unfolded_multi_char, U32 flags, regnode *val, U32 depth)


{
    

    regnode *n = regnext(scan);
    U32 stringok = 1;
    regnode *next = scan + NODE_SZ_STR(scan);
    U32 merged = 0;
    U32 stopnow = 0;

    regnode *stop = scan;
    GET_RE_DEBUG_FLAGS_DECL;

    PERL_UNUSED_ARG(depth);


    PERL_ARGS_ASSERT_JOIN_EXACT;

    PERL_UNUSED_ARG(flags);
    PERL_UNUSED_ARG(val);

    DEBUG_PEEP("join", scan, depth, 0);

    assert(PL_regkind[OP(scan)] == EXACT);

    
    while (    n && (    PL_regkind[OP(n)] == NOTHING || (stringok && PL_regkind[OP(n)] == EXACT))

           && NEXT_OFF(n)
           && NEXT_OFF(scan) + NEXT_OFF(n) < I16_MAX)
    {

        if (OP(n) == TAIL || n > next)
            stringok = 0;
        if (PL_regkind[OP(n)] == NOTHING) {
            DEBUG_PEEP("skip:", n, depth, 0);
            NEXT_OFF(scan) += NEXT_OFF(n);
            next = n + NODE_STEP_REGNODE;

            if (stringok)
                stop = n;

            n = regnext(n);
        }
        else if (stringok) {
            const unsigned int oldl = STR_LEN(scan);
            regnode * const nnext = regnext(n);

            
            
            if (oldl + STR_LEN(n) > U8_MAX)
                break;

            
            if (OP(scan) == EXACT && (OP(n) == EXACT_ONLY8)) {
                OP(scan) = EXACT_ONLY8;
            }
            else if (OP(scan) == EXACT_ONLY8 && (OP(n) == EXACT)) {
                ;   
            }
            else if ((OP(scan) == EXACTFU) && (OP(n) == EXACTFU_ONLY8)) {
                OP(scan) = EXACTFU_ONLY8;
            }
            else if ((OP(scan) == EXACTFU_ONLY8) && (OP(n) == EXACTFU)) {
                ;   
            }
            else if (OP(scan) == EXACTFU && OP(n) == EXACTFU) {
                ;   
            }
            else if (OP(scan) == EXACTFU && OP(n) == EXACTFU_S_EDGE) {

                 

                if (STRING(n)[STR_LEN(n)-1] == 's') {

                    
                    if (OP(nnext) == EXACTF) {
                        break;
                    }

                    OP(scan) = EXACTFU_S_EDGE;

                }   
            }
            else if (OP(scan) == EXACTF && OP(n) == EXACTF) {
                ;   
            }
            else if (OP(scan) == EXACTF && OP(n) == EXACTFU_S_EDGE) {

                
                if (OP(nnext) == EXACTFU) {
                    break;
                }

                
            }
            else if (OP(scan) == EXACTFU_S_EDGE && OP(n) == EXACTFU_S_EDGE) {
                if (   STRING(scan)[STR_LEN(scan)-1] == 's' && STRING(n)[0] == 's')
                {
                    
                    OP(scan) = EXACTF;
                }
            }
            else if (OP(scan) == EXACTFU_S_EDGE && OP(n) == EXACTFU) {
                if (STRING(n)[0] == 's') {
                    ;   
                }
                else {  
                    OP(scan) = EXACTFU;
                }
            }
            else if (OP(scan) == EXACTFU_S_EDGE && OP(n) == EXACTF) {

                
                OP(scan) = EXACTF;
            }
            else if (OP(scan) != OP(n)) {

                
                break;
            }

            DEBUG_PEEP("merg", n, depth, 0);
            merged++;

            NEXT_OFF(scan) += NEXT_OFF(n);
            STR_LEN(scan) += STR_LEN(n);
            next = n + NODE_SZ_STR(n);
            
            Move(STRING(n), STRING(scan) + oldl, STR_LEN(n), char);

            stop = next - 1;

            n = nnext;
            if (stopnow) break;
        }


	if (flags && !NEXT_OFF(n)) {
	    DEBUG_PEEP("atch", val, depth, 0);
	    if (reg_off_by_arg[OP(n)]) {
		ARG_SET(n, val - n);
	    }
	    else {
		NEXT_OFF(n) = val - n;
	    }
	    stopnow = 1;
	}

    }

    
    if (OP(scan) == EXACTFU_S_EDGE) {
        OP(scan) = EXACTFU;
    }

    *min_subtract = 0;
    *unfolded_multi_char = FALSE;

    
    if (OP(scan) != EXACT && OP(scan) != EXACT_ONLY8 && OP(scan) != EXACTL) {
        U8* s0 = (U8*) STRING(scan);
        U8* s = s0;
        U8* s_end = s0 + STR_LEN(scan);

        int total_count_delta = 0;  

	
	if (UTF) {
            U8* folded = NULL;

            if (OP(scan) == EXACTFL) {
                U8 *d;

                

                Newx(folded, UTF8_MAX_FOLD_CHAR_EXPAND * STR_LEN(scan) + 1, U8);
                d = folded;
                while (s < s_end) {
                    STRLEN s_len = UTF8SKIP(s);
                    if (! is_PROBLEMATIC_LOCALE_FOLD_utf8(s)) {
                        Copy(s, d, s_len, U8);
                        d += s_len;
                    }
                    else if (is_FOLDS_TO_MULTI_utf8(s)) {
                        *unfolded_multi_char = TRUE;
                        Copy(s, d, s_len, U8);
                        d += s_len;
                    }
                    else if (isASCII(*s)) {
                        *(d++) = toFOLD(*s);
                    }
                    else {
                        STRLEN len;
                        _toFOLD_utf8_flags(s, s_end, d, &len, FOLD_FLAGS_FULL);
                        d += len;
                    }
                    s += s_len;
                }

                
                s = folded;
                s_end = d;
            } 

            
            while (s < s_end - 1) 
	    {
                int count = 0;  
                int len = is_MULTI_CHAR_FOLD_utf8_safe(s, s_end);
                if (! len) {    
                    s += UTF8SKIP(s);
                    continue;
                }

                { 
                    U8* multi_end  = s + len;

                    
                    if (OP(scan) != EXACTFAA && OP(scan) != EXACTFAA_NO_TRIE) {
                        count = utf8_length(s, multi_end);
                        s = multi_end;
                    }
                    else {
                        while (s < multi_end) {
                            if (isASCII(*s)) {
                                s++;
                                goto next_iteration;
                            }
                            else {
                                s += UTF8SKIP(s);
                            }
                            count++;
                        }
                    }
                }

                
                total_count_delta += count - 1;
              next_iteration: ;
	    }

            
            if (OP(scan) == EXACTFL) {
                int total_chars = utf8_length((U8*) STRING(scan), (U8*) STRING(scan) + STR_LEN(scan));
                if (total_count_delta > total_chars) {
                    total_count_delta = total_chars;
                }
            }

            *min_subtract += total_count_delta;
            Safefree(folded);
	}
	else if (OP(scan) == EXACTFAA) {

            


	    while (s < s_end) {
                if (*s == LATIN_SMALL_LETTER_SHARP_S) {
                    OP(scan) = EXACTFAA_NO_TRIE;
                    *unfolded_multi_char = TRUE;
                    break;
                }
                s++;
            }
        }
	else {

            
	    const U8* upper = (OP(scan) == EXACTF || OP(scan) == EXACTFL)
                              ? s_end : s_end -1;

	    while (s < upper) {
                int len = is_MULTI_CHAR_FOLD_latin1_safe(s, s_end);
                if (! len) {    
                    if (*s == LATIN_SMALL_LETTER_SHARP_S && (OP(scan) == EXACTF || OP(scan) == EXACTFL))
                    {
                        *unfolded_multi_char = TRUE;
                    }
                    s++;
                    continue;
                }

                if (len == 2 && isALPHA_FOLD_EQ(*s, 's')
                    && isALPHA_FOLD_EQ(*(s+1), 's'))
                {

                    
                    if (OP(scan) != EXACTF && OP(scan) != EXACTFL) {
                        OP(scan) = EXACTFUP;
                    }
		}

                *min_subtract += len - 1;
                s += len;
	    }

	}

        if (     STR_LEN(scan) == 1 &&   isALPHA_A(* STRING(scan))
            &&  (         OP(scan) == EXACTFAA || (     OP(scan) == EXACTFU && ! HAS_NONLATIN1_SIMPLE_FOLD_CLOSURE(* STRING(scan)))))

        {
            U8 mask = ~ ('A' ^ 'a'); 

            
            OP(scan) = ANYOFM;
            ARG_SET(scan, *STRING(scan) & mask);
            FLAGS(scan) = mask;
        }
    }


    
    n = scan + NODE_SZ_STR(scan);
    while (n <= stop) {
	OP(n) = OPTIMIZED;
	FLAGS(n) = 0;
	NEXT_OFF(n) = 0;
        n++;
    }

    DEBUG_OPTIMISE_r(if (merged){DEBUG_PEEP("finl", scan, depth, 0);});
    return stopnow;
}










static void S_unwind_scan_frames(pTHX_ const void *p)
{
    scan_frame *f= (scan_frame *)p;
    do {
        scan_frame *n= f->next_frame;
        Safefree(f);
        f= n;
    } while (f);
}


STATIC void S_rck_elide_nothing(pTHX_ regnode *node)
{
    dVAR;

    PERL_ARGS_ASSERT_RCK_ELIDE_NOTHING;

    if (OP(node) != CURLYX) {
        const int max = (reg_off_by_arg[OP(node)] ? I32_MAX  : (I32_MAX < U16_MAX ? I32_MAX : U16_MAX));


        int off = (reg_off_by_arg[OP(node)] ? ARG(node) : NEXT_OFF(node));
        int noff;
        regnode *n = node;

        
        while ( (n = regnext(n))
            && ( (PL_regkind[OP(n)] == NOTHING && (noff = NEXT_OFF(n)))
                || ((OP(n) == LONGJMP) && (noff = ARG(n)))
            )
            && off + noff < max ) {
            off += noff;
        }
        if (reg_off_by_arg[OP(node)])
            ARG(node) = off;
        else NEXT_OFF(node) = off;
    }
    return;
}


STATIC SSize_t S_study_chunk(pTHX_ RExC_state_t *pRExC_state, regnode **scanp, SSize_t *minlenp, SSize_t *deltap, regnode *last, scan_data_t *data, I32 stopparen, U32 recursed_depth, regnode_ssc *and_withp, U32 flags, U32 depth)







			
			
			
			
			
			
			
{
    dVAR;
    
    SSize_t min = 0;
    I32 pars = 0, code;
    regnode *scan = *scanp, *next;
    SSize_t delta = 0;
    int is_inf = (flags & SCF_DO_SUBSTR) && (data->flags & SF_IS_INF);
    int is_inf_internal = 0;		
    I32 is_par = OP(scan) == OPEN ? ARG(scan) : 0;
    scan_data_t data_fake;
    SV *re_trie_maxbuff = NULL;
    regnode *first_non_open = scan;
    SSize_t stopmin = SSize_t_MAX;
    scan_frame *frame = NULL;
    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_STUDY_CHUNK;
    RExC_study_started= 1;

    Zero(&data_fake, 1, scan_data_t);

    if ( depth == 0 ) {
        while (first_non_open && OP(first_non_open) == OPEN)
            first_non_open=regnext(first_non_open);
    }


  fake_study_recurse:
    DEBUG_r( RExC_study_chunk_recursed_count++;
    );
    DEBUG_OPTIMISE_MORE_r( {
        Perl_re_indentf( aTHX_  "study_chunk stopparen=%ld recursed_count=%lu depth=%lu recursed_depth=%lu scan=%p last=%p", depth, (long)stopparen, (unsigned long)RExC_study_chunk_recursed_count, (unsigned long)depth, (unsigned long)recursed_depth, scan, last);




        if (recursed_depth) {
            U32 i;
            U32 j;
            for ( j = 0 ; j < recursed_depth ; j++ ) {
                for ( i = 0 ; i < (U32)RExC_total_parens ; i++ ) {
                    if ( PAREN_TEST(RExC_study_chunk_recursed + ( j * RExC_study_chunk_recursed_bytes), i )

                        && ( !j || !PAREN_TEST(RExC_study_chunk_recursed + (( j - 1 ) * RExC_study_chunk_recursed_bytes), i)


                        )
                    ) {
                        Perl_re_printf( aTHX_ " %d",(int)i);
                        break;
                    }
                }
                if ( j + 1 < recursed_depth ) {
                    Perl_re_printf( aTHX_  ",");
                }
            }
        }
        Perl_re_printf( aTHX_ "\n");
    }
    );
    while ( scan && OP(scan) != END && scan < last ){
        UV min_subtract = 0;    
	bool unfolded_multi_char = FALSE;
	
        DEBUG_STUDYDATA("Peep", data, depth, is_inf);
        DEBUG_PEEP("Peep", scan, depth, flags);


        
        JOIN_EXACT(scan,&min_subtract, &unfolded_multi_char, 0);

        
        rck_elide_nothing(scan);

	
        if ( OP(scan) == DEFINEP ) {
            SSize_t minlen = 0;
            SSize_t deltanext = 0;
            SSize_t fake_last_close = 0;
            I32 f = SCF_IN_DEFINE;

            StructCopy(&zero_scan_data, &data_fake, scan_data_t);
            scan = regnext(scan);
            assert( OP(scan) == IFTHEN );
            DEBUG_PEEP("expect IFTHEN", scan, depth, flags);

            data_fake.last_closep= &fake_last_close;
            minlen = *minlenp;
            next = regnext(scan);
            scan = NEXTOPER(NEXTOPER(scan));
            DEBUG_PEEP("scan", scan, depth, flags);
            DEBUG_PEEP("next", next, depth, flags);

            
            
            (void)study_chunk(pRExC_state, &scan, &minlen, &deltanext, next, &data_fake, stopparen, recursed_depth, NULL, f, depth+1);


            scan = next;
        } else if ( OP(scan) == BRANCH  || OP(scan) == BRANCHJ || OP(scan) == IFTHEN ) {




	    next = regnext(scan);
	    code = OP(scan);

            
	    if (OP(next) == code || code == IFTHEN) {
                
		SSize_t max1 = 0, min1 = SSize_t_MAX, num = 0;
		regnode_ssc accum;
		regnode * const startbranch=scan;

                if (flags & SCF_DO_SUBSTR) {
                    
                    scan_commit(pRExC_state, data, minlenp, is_inf);
                }

                if (flags & SCF_DO_STCLASS)
		    ssc_init_zero(pRExC_state, &accum);

		while (OP(scan) == code) {
		    SSize_t deltanext, minnext, fake;
		    I32 f = 0;
		    regnode_ssc this_class;

                    DEBUG_PEEP("Branch", scan, depth, flags);

		    num++;
                    StructCopy(&zero_scan_data, &data_fake, scan_data_t);
		    if (data) {
			data_fake.whilem_c = data->whilem_c;
			data_fake.last_closep = data->last_closep;
		    }
		    else data_fake.last_closep = &fake;

		    data_fake.pos_delta = delta;
		    next = regnext(scan);

                    scan = NEXTOPER(scan); 
                    if (code != BRANCH)    
			scan = NEXTOPER(scan);

		    if (flags & SCF_DO_STCLASS) {
			ssc_init(pRExC_state, &this_class);
			data_fake.start_class = &this_class;
			f = SCF_DO_STCLASS_AND;
		    }
		    if (flags & SCF_WHILEM_VISITED_POS)
			f |= SCF_WHILEM_VISITED_POS;

		    
                    
		    minnext = study_chunk(pRExC_state, &scan, minlenp, &deltanext, next, &data_fake, stopparen, recursed_depth, NULL, f, depth+1);


		    if (min1 > minnext)
			min1 = minnext;
		    if (deltanext == SSize_t_MAX) {
			is_inf = is_inf_internal = 1;
			max1 = SSize_t_MAX;
		    } else if (max1 < minnext + deltanext)
			max1 = minnext + deltanext;
		    scan = next;
		    if (data_fake.flags & (SF_HAS_PAR|SF_IN_PAR))
			pars++;
	            if (data_fake.flags & SCF_SEEN_ACCEPT) {
	                if ( stopmin > minnext)
	                    stopmin = min + min1;
	                flags &= ~SCF_DO_SUBSTR;
	                if (data)
	                    data->flags |= SCF_SEEN_ACCEPT;
	            }
		    if (data) {
			if (data_fake.flags & SF_HAS_EVAL)
			    data->flags |= SF_HAS_EVAL;
			data->whilem_c = data_fake.whilem_c;
		    }
		    if (flags & SCF_DO_STCLASS)
			ssc_or(pRExC_state, &accum, (regnode_charclass*)&this_class);
		}
		if (code == IFTHEN && num < 2) 
		    min1 = 0;
		if (flags & SCF_DO_SUBSTR) {
		    data->pos_min += min1;
		    if (data->pos_delta >= SSize_t_MAX - (max1 - min1))
		        data->pos_delta = SSize_t_MAX;
		    else data->pos_delta += max1 - min1;
		    if (max1 != min1 || is_inf)
			data->cur_is_floating = 1;
		}
		min += min1;
		if (delta == SSize_t_MAX || SSize_t_MAX - delta - (max1 - min1) < 0)
		    delta = SSize_t_MAX;
		else delta += max1 - min1;
		if (flags & SCF_DO_STCLASS_OR) {
		    ssc_or(pRExC_state, data->start_class, (regnode_charclass*) &accum);
		    if (min1) {
			ssc_and(pRExC_state, data->start_class, (regnode_charclass *) and_withp);
			flags &= ~SCF_DO_STCLASS;
		    }
		}
		else if (flags & SCF_DO_STCLASS_AND) {
		    if (min1) {
			ssc_and(pRExC_state, data->start_class, (regnode_charclass *) &accum);
			flags &= ~SCF_DO_STCLASS;
		    }
		    else {
			
			INIT_AND_WITHP;
			StructCopy(data->start_class, and_withp, regnode_ssc);
			flags &= ~SCF_DO_STCLASS_AND;
			StructCopy(&accum, data->start_class, regnode_ssc);
			flags |= SCF_DO_STCLASS_OR;
		    }
		}

                if (PERL_ENABLE_TRIE_OPTIMISATION && OP( startbranch ) == BRANCH )
                {
		

		    int made=0;
		    if (!re_trie_maxbuff) {
			re_trie_maxbuff = get_sv(RE_TRIE_MAXBUF_NAME, 1);
			if (!SvIOK(re_trie_maxbuff))
			    sv_setiv(re_trie_maxbuff, RE_TRIE_MAXBUF_INIT);
		    }
                    if ( SvIV(re_trie_maxbuff)>=0  ) {
                        regnode *cur;
                        regnode *first = (regnode *)NULL;
                        regnode *last = (regnode *)NULL;
                        regnode *tail = scan;
                        U8 trietype = 0;
                        U32 count=0;

                        

                        while ( OP( tail ) == TAIL ) {
                            
                            tail = regnext( tail );
                        }


                        DEBUG_TRIE_COMPILE_r({
                            regprop(RExC_rx, RExC_mysv, tail, NULL, pRExC_state);
                            Perl_re_indentf( aTHX_  "%s %" UVuf ":%s\n", depth+1, "Looking for TRIE'able sequences. Tail node is ", (UV) REGNODE_OFFSET(tail), SvPV_nolen_const( RExC_mysv )



                            );
                        });

                        















                        
                        for ( cur = startbranch ; cur != scan ; cur = regnext( cur ) ) {
                            regnode * const noper = NEXTOPER( cur );
                            U8 noper_type = OP( noper );
                            U8 noper_trietype = TRIE_TYPE( noper_type );

                            regnode * const noper_next = regnext( noper );
                            U8 noper_next_type = (noper_next && noper_next < tail) ? OP(noper_next) : 0;
                            U8 noper_next_trietype = (noper_next && noper_next < tail) ? TRIE_TYPE( noper_next_type ) :0;


                            DEBUG_TRIE_COMPILE_r({
                                regprop(RExC_rx, RExC_mysv, cur, NULL, pRExC_state);
                                Perl_re_indentf( aTHX_  "- %d:%s (%d)", depth+1, REG_NODE_NUM(cur), SvPV_nolen_const( RExC_mysv ), REG_NODE_NUM(cur) );


                                regprop(RExC_rx, RExC_mysv, noper, NULL, pRExC_state);
                                Perl_re_printf( aTHX_  " -> %d:%s", REG_NODE_NUM(noper), SvPV_nolen_const(RExC_mysv));

                                if ( noper_next ) {
                                  regprop(RExC_rx, RExC_mysv, noper_next, NULL, pRExC_state);
                                  Perl_re_printf( aTHX_ "\t=> %d:%s\t", REG_NODE_NUM(noper_next), SvPV_nolen_const(RExC_mysv));
                                }
                                Perl_re_printf( aTHX_  "(First==%d,Last==%d,Cur==%d,tt==%s,ntt==%s,nntt==%s)\n", REG_NODE_NUM(first), REG_NODE_NUM(last), REG_NODE_NUM(cur), PL_reg_name[trietype], PL_reg_name[noper_trietype], PL_reg_name[noper_next_trietype] );


                            });

                            
                            if ( noper_trietype && ( ( noper_trietype == NOTHING )


                                        || ( trietype == NOTHING )
                                        || ( trietype == noper_trietype )
                                  )

                                  && noper_next >= tail  && count < U16_MAX)

                            {
                                
                                if ( !first ) {
                                    first = cur;
				    if ( noper_trietype == NOTHING ) {

					regnode * const noper_next = regnext( noper );
                                        U8 noper_next_type = (noper_next && noper_next < tail) ? OP(noper_next) : 0;
					U8 noper_next_trietype = noper_next_type ? TRIE_TYPE( noper_next_type ) :0;


                                        if ( noper_next_trietype ) {
					    trietype = noper_next_trietype;
                                        } else if (noper_next_type)  {
                                            
                                            first = NULL;
                                        }
                                    } else {
                                        trietype = noper_trietype;
                                    }
                                } else {
                                    if ( trietype == NOTHING )
                                        trietype = noper_trietype;
                                    last = cur;
                                }
				if (first)
				    count++;
                            } 
                            else {
                                
                                if ( last ) {
                                    
                                    if ( trietype && trietype != NOTHING )
                                        make_trie( pRExC_state, startbranch, first, cur, tail, count, trietype, depth+1 );

                                    last = NULL; 
                                }
                                if ( noper_trietype  && noper_next >= tail  ){



                                    
                                    count = 1;
                                    first = cur;
                                    trietype = noper_trietype;
                                } else if (first) {
                                    
                                    count = 0;
                                    first = NULL;
                                    trietype = 0;
                                }
                            } 
                        } 
                        DEBUG_TRIE_COMPILE_r({
                            regprop(RExC_rx, RExC_mysv, cur, NULL, pRExC_state);
                            Perl_re_indentf( aTHX_  "- %s (%d) <SCAN FINISHED> ", depth+1, SvPV_nolen_const( RExC_mysv ), REG_NODE_NUM(cur));
                            Perl_re_printf( aTHX_  "(First==%d, Last==%d, Cur==%d, tt==%s)\n", REG_NODE_NUM(first), REG_NODE_NUM(last), REG_NODE_NUM(cur), PL_reg_name[trietype] );



                        });
                        if ( last && trietype ) {
                            if ( trietype != NOTHING ) {
                                
                                made= make_trie( pRExC_state, startbranch, first, scan, tail, count, trietype, depth+1 );


                                if ( ((made == MADE_EXACT_TRIE && startbranch == first)
                                     || ( first_non_open == first )) && depth==0 ) {
                                    flags |= SCF_TRIE_RESTUDY;
                                    if ( startbranch == first && scan >= tail )
                                    {
                                        RExC_seen &=~REG_TOP_LEVEL_BRANCHES_SEEN;
                                    }
                                }

                            } else {
                                
                                if ( startbranch == first ) {
                                    regnode *opt;
                                    
                                    DEBUG_TRIE_COMPILE_r({
                                        regprop(RExC_rx, RExC_mysv, cur, NULL, pRExC_state);
                                        Perl_re_indentf( aTHX_  "- %s (%d) <NOTHING BRANCH SEQUENCE>\n", depth+1, SvPV_nolen_const( RExC_mysv ), REG_NODE_NUM(cur));


                                    });
                                    OP(startbranch)= NOTHING;
                                    NEXT_OFF(startbranch)= tail - startbranch;
                                    for ( opt= startbranch + 1; opt < tail ; opt++ )
                                        OP(opt)= OPTIMIZED;
                                }
                            }
                        } 
                    } 

                } 

	    }
	    else if ( code == BRANCHJ ) {  
		scan = NEXTOPER(NEXTOPER(scan));
	    } else			 scan = NEXTOPER(scan);
	    continue;
        } else if (OP(scan) == SUSPEND || OP(scan) == GOSUB) {
            I32 paren = 0;
            regnode *start = NULL;
            regnode *end = NULL;
            U32 my_recursed_depth= recursed_depth;

            if (OP(scan) != SUSPEND) { 
                
                paren = ARG(scan);
                RExC_recurse[ARG2L(scan)] = scan;
                start = REGNODE_p(RExC_open_parens[paren]);
                end   = REGNODE_p(RExC_close_parens[paren]);

                
                if ( ( flags & SCF_IN_DEFINE )
                    || ( (is_inf_internal || is_inf || (data && data->flags & SF_IS_INF))

                        && ( (flags & (SCF_DO_STCLASS | SCF_DO_SUBSTR)) == 0 )
                    )
                ) {
                    
                    
                    scan= regnext(scan);
                    continue;
                }

                if ( !recursed_depth || !PAREN_TEST(RExC_study_chunk_recursed + ((recursed_depth-1) * RExC_study_chunk_recursed_bytes), paren)


                ) {
                    
                    if (!recursed_depth) {
                        Zero(RExC_study_chunk_recursed, RExC_study_chunk_recursed_bytes, U8);
                    } else {
                        Copy(RExC_study_chunk_recursed + ((recursed_depth-1) * RExC_study_chunk_recursed_bytes), RExC_study_chunk_recursed + (recursed_depth * RExC_study_chunk_recursed_bytes), RExC_study_chunk_recursed_bytes, U8);

                    }
                    
                    DEBUG_STUDYDATA("gosub-set", data, depth, is_inf);
                    PAREN_SET(RExC_study_chunk_recursed + (recursed_depth * RExC_study_chunk_recursed_bytes), paren);
                    my_recursed_depth= recursed_depth + 1;
                } else {
                    DEBUG_STUDYDATA("gosub-inf", data, depth, is_inf);
                    
                    if (flags & SCF_DO_SUBSTR) {
                        scan_commit(pRExC_state, data, minlenp, is_inf);
                        data->cur_is_floating = 1;
                    }
                    is_inf = is_inf_internal = 1;
                    if (flags & SCF_DO_STCLASS_OR) 
                        ssc_anything(data->start_class);
                    flags &= ~SCF_DO_STCLASS;

                    start= NULL; 
	        }
            } else {
	        paren = stopparen;
                start = scan + 2;
	        end = regnext(scan);
	    }
            if (start) {
                scan_frame *newframe;
                assert(end);
                if (!RExC_frame_last) {
                    Newxz(newframe, 1, scan_frame);
                    SAVEDESTRUCTOR_X(S_unwind_scan_frames, newframe);
                    RExC_frame_head= newframe;
                    RExC_frame_count++;
                } else if (!RExC_frame_last->next_frame) {
                    Newxz(newframe, 1, scan_frame);
                    RExC_frame_last->next_frame= newframe;
                    newframe->prev_frame= RExC_frame_last;
                    RExC_frame_count++;
                } else {
                    newframe= RExC_frame_last->next_frame;
                }
                RExC_frame_last= newframe;

                newframe->next_regnode = regnext(scan);
                newframe->last_regnode = last;
                newframe->stopparen = stopparen;
                newframe->prev_recursed_depth = recursed_depth;
                newframe->this_prev_frame= frame;

                DEBUG_STUDYDATA("frame-new", data, depth, is_inf);
                DEBUG_PEEP("fnew", scan, depth, flags);

	        frame = newframe;
	        scan =  start;
	        stopparen = paren;
	        last = end;
                depth = depth + 1;
                recursed_depth= my_recursed_depth;

	        continue;
	    }
	}
	else if (   OP(scan) == EXACT || OP(scan) == EXACT_ONLY8 || OP(scan) == EXACTL)

        {
	    SSize_t l = STR_LEN(scan);
	    UV uc;
            assert(l);
	    if (UTF) {
		const U8 * const s = (U8*)STRING(scan);
		uc = utf8_to_uvchr_buf(s, s + l, NULL);
		l = utf8_length(s, s + l);
	    } else {
		uc = *((U8*)STRING(scan));
	    }
	    min += l;
	    if (flags & SCF_DO_SUBSTR) { 
		
		if (data->last_end == -1) { 
		    data->last_start_min = data->pos_min;
 		    data->last_start_max = is_inf ? SSize_t_MAX : data->pos_min + data->pos_delta;
		}
		sv_catpvn(data->last_found, STRING(scan), STR_LEN(scan));
		if (UTF)
		    SvUTF8_on(data->last_found);
		{
		    SV * const sv = data->last_found;
		    MAGIC * const mg = SvUTF8(sv) && SvMAGICAL(sv) ? mg_find(sv, PERL_MAGIC_utf8) : NULL;
		    if (mg && mg->mg_len >= 0)
			mg->mg_len += utf8_length((U8*)STRING(scan), (U8*)STRING(scan)+STR_LEN(scan));
		}
		data->last_end = data->pos_min + l;
		data->pos_min += l; 
		data->flags &= ~SF_BEFORE_EOL;
	    }

            
	    if (flags & SCF_DO_STCLASS_AND) {
                ssc_cp_and(data->start_class, uc);
                ANYOF_FLAGS(data->start_class) &= ~SSC_MATCHES_EMPTY_STRING;
                ssc_clear_locale(data->start_class);
	    }
	    else if (flags & SCF_DO_STCLASS_OR) {
                ssc_add_cp(data->start_class, uc);
		ssc_and(pRExC_state, data->start_class, (regnode_charclass *) and_withp);

                
                ANYOF_FLAGS(data->start_class) &= ~SSC_MATCHES_EMPTY_STRING;
	    }
	    flags &= ~SCF_DO_STCLASS;
	}
        else if (PL_regkind[OP(scan)] == EXACT) {
            
	    SSize_t l = STR_LEN(scan);
            const U8 * s = (U8*)STRING(scan);

	    
	    if (flags & SCF_DO_SUBSTR) {
		assert(data);
                scan_commit(pRExC_state, data, minlenp, is_inf);
	    }
	    if (UTF) {
		l = utf8_length(s, s + l);
	    }
	    if (unfolded_multi_char) {
                RExC_seen |= REG_UNFOLDED_MULTI_SEEN;
	    }
	    min += l - min_subtract;
            assert (min >= 0);
            delta += min_subtract;
	    if (flags & SCF_DO_SUBSTR) {
		data->pos_min += l - min_subtract;
		if (data->pos_min < 0) {
                    data->pos_min = 0;
                }
                data->pos_delta += min_subtract;
		if (min_subtract) {
		    data->cur_is_floating = 1; 
		}
	    }

            if (flags & SCF_DO_STCLASS) {
                SV* EXACTF_invlist = _make_exactf_invlist(pRExC_state, scan);

                assert(EXACTF_invlist);
                if (flags & SCF_DO_STCLASS_AND) {
                    if (OP(scan) != EXACTFL)
                        ssc_clear_locale(data->start_class);
                    ANYOF_FLAGS(data->start_class) &= ~SSC_MATCHES_EMPTY_STRING;
                    ANYOF_POSIXL_ZERO(data->start_class);
                    ssc_intersection(data->start_class, EXACTF_invlist, FALSE);
                }
                else {  
                    ssc_union(data->start_class, EXACTF_invlist, FALSE);
                    ssc_and(pRExC_state, data->start_class, (regnode_charclass *) and_withp);

                    
                    ANYOF_FLAGS(data->start_class) &= ~SSC_MATCHES_EMPTY_STRING;
                }
                flags &= ~SCF_DO_STCLASS;
                SvREFCNT_dec(EXACTF_invlist);
            }
	}
	else if (REGNODE_VARIES(OP(scan))) {
	    SSize_t mincount, maxcount, minnext, deltanext, pos_before = 0;
	    I32 fl = 0, f = flags;
	    regnode * const oscan = scan;
	    regnode_ssc this_class;
	    regnode_ssc *oclass = NULL;
	    I32 next_is_eval = 0;

	    switch (PL_regkind[OP(scan)]) {
	    case WHILEM:		
		scan = NEXTOPER(scan);
		goto finish;
	    case PLUS:
		if (flags & (SCF_DO_SUBSTR | SCF_DO_STCLASS)) {
		    next = NEXTOPER(scan);
		    if (   OP(next) == EXACT || OP(next) == EXACT_ONLY8 || OP(next) == EXACTL || (flags & SCF_DO_STCLASS))


                    {
			mincount = 1;
			maxcount = REG_INFTY;
			next = regnext(scan);
			scan = NEXTOPER(scan);
			goto do_curly;
		    }
		}
		if (flags & SCF_DO_SUBSTR)
		    data->pos_min++;
		min++;
		
	    case STAR:
                next = NEXTOPER(scan);

                
                if (OP(next) == EXACTFU_S_EDGE) {
                    OP(next) = EXACTFU;
                }

                if (     STR_LEN(next) == 1 &&   isALPHA_A(* STRING(next))
                    && (         OP(next) == EXACTFAA || (     OP(next) == EXACTFU && ! HAS_NONLATIN1_SIMPLE_FOLD_CLOSURE(* STRING(next)))))

                {
                    
                    U8 mask = ~ ('A' ^ 'a');

                    assert(isALPHA_A(* STRING(next)));

                    
                    OP(next) = ANYOFM;
                    ARG_SET(next, *STRING(next) & mask);
                    FLAGS(next) = mask;
                }

		if (flags & SCF_DO_STCLASS) {
		    mincount = 0;
		    maxcount = REG_INFTY;
		    next = regnext(scan);
		    scan = NEXTOPER(scan);
		    goto do_curly;
		}
		if (flags & SCF_DO_SUBSTR) {
                    scan_commit(pRExC_state, data, minlenp, is_inf);
                    
		    data->cur_is_floating = 1; 
		}
                is_inf = is_inf_internal = 1;
                scan = regnext(scan);
		goto optimize_curly_tail;
	    case CURLY:
	        if (stopparen>0 && (OP(scan)==CURLYN || OP(scan)==CURLYM)
	            && (scan->flags == stopparen))
		{
		    mincount = 1;
		    maxcount = 1;
		} else {
		    mincount = ARG1(scan);
		    maxcount = ARG2(scan);
		}
		next = regnext(scan);
		if (OP(scan) == CURLYX) {
		    I32 lp = (data ? *(data->last_closep) : 0);
		    scan->flags = ((lp <= (I32)U8_MAX) ? (U8)lp : U8_MAX);
		}
		scan = NEXTOPER(scan) + EXTRA_STEP_2ARGS;
		next_is_eval = (OP(scan) == EVAL);
	      do_curly:
		if (flags & SCF_DO_SUBSTR) {
                    if (mincount == 0)
                        scan_commit(pRExC_state, data, minlenp, is_inf);
                    
		    pos_before = data->pos_min;
		}
		if (data) {
		    fl = data->flags;
		    data->flags &= ~(SF_HAS_PAR|SF_IN_PAR|SF_HAS_EVAL);
		    if (is_inf)
			data->flags |= SF_IS_INF;
		}
		if (flags & SCF_DO_STCLASS) {
		    ssc_init(pRExC_state, &this_class);
		    oclass = data->start_class;
		    data->start_class = &this_class;
		    f |= SCF_DO_STCLASS_AND;
		    f &= ~SCF_DO_STCLASS_OR;
		}
	        
               if ((mincount > 1) || (maxcount > 1 && maxcount != REG_INFTY))
		    f &= ~SCF_WHILEM_VISITED_POS;

		
                
		minnext = study_chunk(pRExC_state, &scan, minlenp, &deltanext, last, data, stopparen, recursed_depth, NULL, (mincount == 0 ? (f & ~SCF_DO_SUBSTR)


                                   : f)
                                  ,depth+1);

		if (flags & SCF_DO_STCLASS)
		    data->start_class = oclass;
		if (mincount == 0 || minnext == 0) {
		    if (flags & SCF_DO_STCLASS_OR) {
			ssc_or(pRExC_state, data->start_class, (regnode_charclass *) &this_class);
		    }
		    else if (flags & SCF_DO_STCLASS_AND) {
			
			INIT_AND_WITHP;
			StructCopy(data->start_class, and_withp, regnode_ssc);
			flags &= ~SCF_DO_STCLASS_AND;
			StructCopy(&this_class, data->start_class, regnode_ssc);
			flags |= SCF_DO_STCLASS_OR;
                        ANYOF_FLAGS(data->start_class)
                                                |= SSC_MATCHES_EMPTY_STRING;
		    }
		} else {		
		    if (flags & SCF_DO_STCLASS_OR) {
			ssc_or(pRExC_state, data->start_class, (regnode_charclass *) &this_class);
			ssc_and(pRExC_state, data->start_class, (regnode_charclass *) and_withp);
		    }
		    else if (flags & SCF_DO_STCLASS_AND)
			ssc_and(pRExC_state, data->start_class, (regnode_charclass *) &this_class);
		    flags &= ~SCF_DO_STCLASS;
		}
		if (!scan) 		
		    scan = next;
		if (((flags & (SCF_TRIE_DOING_RESTUDY|SCF_DO_SUBSTR))==SCF_DO_SUBSTR)
		    
		    && (next_is_eval || !(mincount == 0 && maxcount == 1))
		    && (minnext == 0) && (deltanext == 0)
		    && data && !(data->flags & (SF_HAS_PAR|SF_IN_PAR))
                    && maxcount <= REG_INFTY/3) 
		{
		    _WARN_HELPER(RExC_precomp_end, packWARN(WARN_REGEXP), Perl_ck_warner(aTHX_ packWARN(WARN_REGEXP), "Quantifier unexpected on zero-length expression " "in regex m/%" UTF8f "/", UTF8fARG(UTF, RExC_precomp_end - RExC_precomp, RExC_precomp)));




                }

                if ( ( minnext > 0 && mincount >= SSize_t_MAX / minnext )
                    || min >= SSize_t_MAX - minnext * mincount )
                {
                    FAIL("Regexp out of space");
                }

		min += minnext * mincount;
		is_inf_internal |= deltanext == SSize_t_MAX || (maxcount == REG_INFTY && minnext + deltanext > 0);
		is_inf |= is_inf_internal;
                if (is_inf) {
		    delta = SSize_t_MAX;
                } else {
		    delta += (minnext + deltanext) * maxcount - minnext * mincount;
                }
		
		if (  OP(oscan) == CURLYX && data && data->flags & SF_IN_PAR && !(data->flags & SF_HAS_EVAL)

		      && !deltanext && minnext == 1 ) {
		    
		    regnode *nxt = NEXTOPER(oscan) + EXTRA_STEP_2ARGS;
		    regnode * const nxt1 = nxt;

		    regnode *nxt2;


		    
		    nxt = regnext(nxt);
		    if (!REGNODE_SIMPLE(OP(nxt))
			&& !(PL_regkind[OP(nxt)] == EXACT && STR_LEN(nxt) == 1))
			goto nogo;

		    nxt2 = nxt;

		    nxt = regnext(nxt);
		    if (OP(nxt) != CLOSE)
			goto nogo;
		    if (RExC_open_parens) {

                        
                        RExC_open_parens[ARG(nxt1)] = REGNODE_OFFSET(oscan);

                        
                        RExC_close_parens[ARG(nxt1)] = REGNODE_OFFSET(nxt) + 2;
		    }
		    
		    oscan->flags = (U8)ARG(nxt);
		    OP(oscan) = CURLYN;
		    OP(nxt1) = NOTHING;	


		    OP(nxt1 + 1) = OPTIMIZED; 
		    NEXT_OFF(nxt1+ 1) = 0; 
		    NEXT_OFF(nxt2) = 0;	
		    OP(nxt) = OPTIMIZED;	
		    OP(nxt + 1) = OPTIMIZED; 
		    NEXT_OFF(nxt+ 1) = 0; 

		}
	      nogo:

		
		if (  OP(oscan) == CURLYX && data && !(data->flags & SF_HAS_PAR)
		      && !(data->flags & SF_HAS_EVAL)
		      && !deltanext	 && minnext != 0   && ! (RExC_seen & REG_UNFOLDED_MULTI_SEEN)



		) {
		    
		    
		    regnode *nxt = NEXTOPER(oscan) + EXTRA_STEP_2ARGS; 
		    regnode *nxt2;

		    OP(oscan) = CURLYM;
		    while ( (nxt2 = regnext(nxt)) 
			    && (OP(nxt2) != WHILEM))
			nxt = nxt2;
		    OP(nxt2)  = SUCCEED; 
		    
		    if ((data->flags & SF_IN_PAR) && OP(nxt) == CLOSE) {
			
			regnode *nxt1 = NEXTOPER(oscan) + EXTRA_STEP_2ARGS; 

			oscan->flags = (U8)ARG(nxt);
			if (RExC_open_parens) {
                             
                            RExC_open_parens[ARG(nxt1)] = REGNODE_OFFSET(oscan);

                            
                            RExC_close_parens[ARG(nxt1)] = REGNODE_OFFSET(nxt2)
                                                         + 1;
			}
			OP(nxt1) = OPTIMIZED;	
			OP(nxt) = OPTIMIZED;	


			OP(nxt1 + 1) = OPTIMIZED; 
			OP(nxt + 1) = OPTIMIZED; 
			NEXT_OFF(nxt1 + 1) = 0; 
			NEXT_OFF(nxt + 1) = 0; 


			while ( nxt1 && (OP(nxt1) != WHILEM)) {
			    regnode *nnxt = regnext(nxt1);
			    if (nnxt == nxt) {
				if (reg_off_by_arg[OP(nxt1)])
				    ARG_SET(nxt1, nxt2 - nxt1);
				else if (nxt2 - nxt1 < U16_MAX)
				    NEXT_OFF(nxt1) = nxt2 - nxt1;
				else OP(nxt) = NOTHING;
			    }
			    nxt1 = nnxt;
			}

			
                        
			study_chunk(pRExC_state, &nxt1, minlenp, &deltanext, nxt, NULL, stopparen, recursed_depth, NULL, 0, depth+1);

		    }
		    else oscan->flags = 0;
		}
		else if ((OP(oscan) == CURLYX)
			 && (flags & SCF_WHILEM_VISITED_POS)
			 
			 && (maxcount == REG_INFTY)
			 && data) {
		    
		    
		    regnode *nxt = oscan + NEXT_OFF(oscan);

		    if (OP(PREVOPER(nxt)) == NOTHING) 
			nxt += ARG(nxt);
                    nxt = PREVOPER(nxt);
                    if (nxt->flags & 0xf) {
                        
                    } else if (++data->whilem_c < 16) {
                        assert(data->whilem_c <= RExC_whilem_seen);
                        nxt->flags = (U8)(data->whilem_c | (RExC_whilem_seen << 4));
                    }
		}
		if (data && fl & (SF_HAS_PAR|SF_IN_PAR))
		    pars++;
		if (flags & SCF_DO_SUBSTR) {
		    SV *last_str = NULL;
                    STRLEN last_chrs = 0;
		    int counted = mincount != 0;

                    if (data->last_end > 0 && mincount != 0) { 
			SSize_t b = pos_before >= data->last_start_min ? pos_before : data->last_start_min;
			STRLEN l;
			const char * const s = SvPV_const(data->last_found, l);
			SSize_t old = b - data->last_start_min;
                        assert(old >= 0);

			if (UTF)
			    old = utf8_hop_forward((U8*)s, old, (U8 *) SvEND(data->last_found))
                                - (U8*)s;
			l -= old;
			
			last_str = newSVpvn_utf8(s  + old, l, UTF);
                        last_chrs = UTF ? utf8_length((U8*)(s + old), (U8*)(s + old + l)) : l;
			if (deltanext == 0 && pos_before == b) {
			    
			    if (mincount > 1) {

				SvGROW(last_str, (mincount * l) + 1);
				repeatcpy(SvPVX(last_str) + l, SvPVX_const(last_str), l, mincount - 1);

				SvCUR_set(last_str, SvCUR(last_str) * mincount);
				
				SvCUR_set(data->last_found, SvCUR(data->last_found) - l);
				sv_catsv(data->last_found, last_str);
				{
				    SV * sv = data->last_found;
				    MAGIC *mg = SvUTF8(sv) && SvMAGICAL(sv) ? mg_find(sv, PERL_MAGIC_utf8) : NULL;

				    if (mg && mg->mg_len >= 0)
					mg->mg_len += last_chrs * (mincount-1);
				}
                                last_chrs *= mincount;
				data->last_end += l * (mincount - 1);
			    }
			} else {
			    
			    data->last_start_min += minnext * (mincount - 1);
			    data->last_start_max = is_inf ? SSize_t_MAX : data->last_start_max + (maxcount - 1) * (minnext + data->pos_delta);



			}
		    }
		    
		    data->pos_min += minnext * (mincount - counted);

Perl_re_printf( aTHX_  "counted=%" UVuf " deltanext=%" UVuf " SSize_t_MAX=%" UVuf " minnext=%" UVuf " maxcount=%" UVuf " mincount=%" UVuf "\n", (UV)counted, (UV)deltanext, (UV)SSize_t_MAX, (UV)minnext, (UV)maxcount, (UV)mincount);



if (deltanext != SSize_t_MAX)
Perl_re_printf( aTHX_  "LHS=%" UVuf " RHS=%" UVuf "\n", (UV)(-counted * deltanext + (minnext + deltanext) * maxcount - minnext * mincount), (UV)(SSize_t_MAX - data->pos_delta));


		    if (deltanext == SSize_t_MAX || -counted * deltanext + (minnext + deltanext) * maxcount - minnext * mincount >= SSize_t_MAX - data->pos_delta)
		        data->pos_delta = SSize_t_MAX;
		    else data->pos_delta += - counted * deltanext + (minnext + deltanext) * maxcount - minnext * mincount;

		    if (mincount != maxcount) {
			 
                        scan_commit(pRExC_state, data, minlenp, is_inf);
			if (mincount && last_str) {
			    SV * const sv = data->last_found;
			    MAGIC * const mg = SvUTF8(sv) && SvMAGICAL(sv) ? mg_find(sv, PERL_MAGIC_utf8) : NULL;

			    if (mg)
				mg->mg_len = -1;
			    sv_setsv(sv, last_str);
			    data->last_end = data->pos_min;
			    data->last_start_min = data->pos_min - last_chrs;
			    data->last_start_max = is_inf ? SSize_t_MAX : data->pos_min + data->pos_delta - last_chrs;

			}
			data->cur_is_floating = 1; 
		    }
		    SvREFCNT_dec(last_str);
		}
		if (data && (fl & SF_HAS_EVAL))
		    data->flags |= SF_HAS_EVAL;
	      optimize_curly_tail:
		rck_elide_nothing(oscan);
		continue;

	    default:

                Perl_croak(aTHX_ "panic: unexpected varying REx opcode %d", OP(scan));

            case REF:
            case CLUMP:
		if (flags & SCF_DO_SUBSTR) {
                    
                    scan_commit(pRExC_state, data, minlenp, is_inf);
		    data->cur_is_floating = 1; 
		}
		is_inf = is_inf_internal = 1;
		if (flags & SCF_DO_STCLASS_OR) {
                    if (OP(scan) == CLUMP) {
                        
                        ssc_match_all_cp(data->start_class);
                    }
                    else {
                        ssc_anything(data->start_class);
                    }
                }
		flags &= ~SCF_DO_STCLASS;
		break;
	    }
	}
	else if (OP(scan) == LNBREAK) {
	    if (flags & SCF_DO_STCLASS) {
    	        if (flags & SCF_DO_STCLASS_AND) {
                    ssc_intersection(data->start_class, PL_XPosix_ptrs[_CC_VERTSPACE], FALSE);
                    ssc_clear_locale(data->start_class);
                    ANYOF_FLAGS(data->start_class)
                                                &= ~SSC_MATCHES_EMPTY_STRING;
                }
                else if (flags & SCF_DO_STCLASS_OR) {
                    ssc_union(data->start_class, PL_XPosix_ptrs[_CC_VERTSPACE], FALSE);

		    ssc_and(pRExC_state, data->start_class, (regnode_charclass *) and_withp);

                    
                    ANYOF_FLAGS(data->start_class)
                                                &= ~SSC_MATCHES_EMPTY_STRING;
                }
		flags &= ~SCF_DO_STCLASS;
            }
	    min++;
            if (delta != SSize_t_MAX)
                delta++;    
            if (flags & SCF_DO_SUBSTR) {
                
                scan_commit(pRExC_state, data, minlenp, is_inf);
    	        data->pos_min += 1;
                if (data->pos_delta != SSize_t_MAX) {
                    data->pos_delta += 1;
                }
		data->cur_is_floating = 1; 
    	    }
	}
	else if (REGNODE_SIMPLE(OP(scan))) {

	    if (flags & SCF_DO_SUBSTR) {
                scan_commit(pRExC_state, data, minlenp, is_inf);
		data->pos_min++;
	    }
	    min++;
	    if (flags & SCF_DO_STCLASS) {
                bool invert = 0;
                SV* my_invlist = NULL;
                U8 namedclass;

                
                ANYOF_FLAGS(data->start_class) &= ~SSC_MATCHES_EMPTY_STRING;

		
		switch (OP(scan)) {

		default:

                   Perl_croak(aTHX_ "panic: unexpected simple REx opcode %d", OP(scan));

		case SANY:
		    if (flags & SCF_DO_STCLASS_OR) 
			ssc_match_all_cp(data->start_class);
		    break;

		case REG_ANY:
                    {
                        SV* REG_ANY_invlist = _new_invlist(2);
                        REG_ANY_invlist = add_cp_to_invlist(REG_ANY_invlist, '\n');
                        if (flags & SCF_DO_STCLASS_OR) {
                            ssc_union(data->start_class, REG_ANY_invlist, TRUE );


                        }
                        else if (flags & SCF_DO_STCLASS_AND) {
                            ssc_intersection(data->start_class, REG_ANY_invlist, TRUE );


                            ssc_clear_locale(data->start_class);
                        }
                        SvREFCNT_dec_NN(REG_ANY_invlist);
		    }
		    break;

                case ANYOFD:
                case ANYOFL:
                case ANYOFPOSIXL:
                case ANYOFH:
                case ANYOF:
		    if (flags & SCF_DO_STCLASS_AND)
			ssc_and(pRExC_state, data->start_class, (regnode_charclass *) scan);
		    else ssc_or(pRExC_state, data->start_class, (regnode_charclass *) scan);

		    break;

                case NANYOFM:
                case ANYOFM:
                  {
                    SV* cp_list = get_ANYOFM_contents(scan);

                    if (flags & SCF_DO_STCLASS_OR) {
                        ssc_union(data->start_class, cp_list, invert);
                    }
                    else if (flags & SCF_DO_STCLASS_AND) {
                        ssc_intersection(data->start_class, cp_list, invert);
                    }

                    SvREFCNT_dec_NN(cp_list);
                    break;
                  }

		case NPOSIXL:
                    invert = 1;
                    

		case POSIXL:
                    namedclass = classnum_to_namedclass(FLAGS(scan)) + invert;
                    if (flags & SCF_DO_STCLASS_AND) {
                        bool was_there = cBOOL( ANYOF_POSIXL_TEST(data->start_class, namedclass));

                        ANYOF_POSIXL_ZERO(data->start_class);
                        if (was_there) {    
                            ANYOF_POSIXL_SET(data->start_class, namedclass);
                        }
                        
                        data->start_class->invlist = sv_2mortal(_new_invlist(0));
                    }
                    else {
                        int complement = namedclass + ((invert) ? -1 : 1);

                        assert(flags & SCF_DO_STCLASS_OR);

                        
                        if (ANYOF_POSIXL_TEST(data->start_class, complement)) {
                            ssc_match_all_cp(data->start_class);
                            ANYOF_POSIXL_CLEAR(data->start_class, namedclass);
                            ANYOF_POSIXL_CLEAR(data->start_class, complement);
                        }
                        else {  
                            ANYOF_POSIXL_SET(data->start_class, namedclass);
                        }
                    }
                    break;

                case NPOSIXA:   
                    invert = 1;
                    
		case POSIXA:
                    my_invlist = invlist_clone(PL_Posix_ptrs[FLAGS(scan)], NULL);
                    goto join_posix_and_ascii;

		case NPOSIXD:
		case NPOSIXU:
                    invert = 1;
                    
		case POSIXD:
		case POSIXU:
                    my_invlist = invlist_clone(PL_XPosix_ptrs[FLAGS(scan)], NULL);

                    
                    if (OP(scan) == NPOSIXD) {
                        _invlist_subtract(my_invlist, PL_UpperLatin1, &my_invlist);
                    }

                  join_posix_and_ascii:

                    if (flags & SCF_DO_STCLASS_AND) {
                        ssc_intersection(data->start_class, my_invlist, invert);
                        ssc_clear_locale(data->start_class);
                    }
                    else {
                        assert(flags & SCF_DO_STCLASS_OR);
                        ssc_union(data->start_class, my_invlist, invert);
                    }
                    SvREFCNT_dec(my_invlist);
		}
		if (flags & SCF_DO_STCLASS_OR)
		    ssc_and(pRExC_state, data->start_class, (regnode_charclass *) and_withp);
		flags &= ~SCF_DO_STCLASS;
	    }
	}
	else if (PL_regkind[OP(scan)] == EOL && flags & SCF_DO_SUBSTR) {
	    data->flags |= (OP(scan) == MEOL ? SF_BEFORE_MEOL : SF_BEFORE_SEOL);

            scan_commit(pRExC_state, data, minlenp, is_inf);

	}
	else if (  PL_regkind[OP(scan)] == BRANCHJ  && (scan->flags || data || (flags & SCF_DO_STCLASS))

		   && (OP(scan) == IFMATCH || OP(scan) == UNLESSM))
        {
            if ( !PERL_ENABLE_POSITIVE_ASSERTION_STUDY || OP(scan) == UNLESSM )
            {
                

                SSize_t deltanext, minnext, fake = 0;
                regnode *nscan;
                regnode_ssc intrnl;
                int f = 0;

                StructCopy(&zero_scan_data, &data_fake, scan_data_t);
                if (data) {
                    data_fake.whilem_c = data->whilem_c;
                    data_fake.last_closep = data->last_closep;
		}
                else data_fake.last_closep = &fake;
		data_fake.pos_delta = delta;
                if ( flags & SCF_DO_STCLASS && !scan->flags && OP(scan) == IFMATCH ) {
                    ssc_init(pRExC_state, &intrnl);
                    data_fake.start_class = &intrnl;
                    f |= SCF_DO_STCLASS_AND;
		}
                if (flags & SCF_WHILEM_VISITED_POS)
                    f |= SCF_WHILEM_VISITED_POS;
                next = regnext(scan);
                nscan = NEXTOPER(NEXTOPER(scan));

                
                minnext = study_chunk(pRExC_state, &nscan, minlenp, &deltanext, last, &data_fake, stopparen, recursed_depth, NULL, f, depth+1);

                if (scan->flags) {
                    if (   deltanext < 0 || deltanext > (I32) U8_MAX || minnext > (I32)U8_MAX || minnext + deltanext > (I32)U8_MAX)


                    {
			FAIL2("Lookbehind longer than %" UVuf " not implemented", (UV)U8_MAX);
                    }

                    
                    if (deltanext) {
                        scan->next_off = deltanext;
                        ckWARNexperimental(RExC_parse, WARN_EXPERIMENTAL__VLB, "Variable length lookbehind is experimental");

                    }
                    scan->flags = (U8)minnext + deltanext;
                }
                if (data) {
                    if (data_fake.flags & (SF_HAS_PAR|SF_IN_PAR))
                        pars++;
                    if (data_fake.flags & SF_HAS_EVAL)
                        data->flags |= SF_HAS_EVAL;
                    data->whilem_c = data_fake.whilem_c;
                }
                if (f & SCF_DO_STCLASS_AND) {
		    if (flags & SCF_DO_STCLASS_OR) {
			
			ssc_init(pRExC_state, data->start_class);
		    }  else {
                        
			ssc_and(pRExC_state, data->start_class, (regnode_charclass *) &intrnl);
                        ANYOF_FLAGS(data->start_class)
                                                   |= SSC_MATCHES_EMPTY_STRING;
		    }
                }
	    }

            else {
                
                SSize_t deltanext, fake = 0;
                regnode *nscan;
                regnode_ssc intrnl;
                int f = 0;
                
                SSize_t *minnextp;
                Newx( minnextp, 1, SSize_t );
                SAVEFREEPV(minnextp);

                if (data) {
                    StructCopy(data, &data_fake, scan_data_t);
                    if ((flags & SCF_DO_SUBSTR) && data->last_found) {
                        f |= SCF_DO_SUBSTR;
                        if (scan->flags)
                            scan_commit(pRExC_state, &data_fake, minlenp, is_inf);
                        data_fake.last_found=newSVsv(data->last_found);
                    }
                }
                else data_fake.last_closep = &fake;
                data_fake.flags = 0;
                data_fake.substrs[0].flags = 0;
                data_fake.substrs[1].flags = 0;
		data_fake.pos_delta = delta;
                if (is_inf)
	            data_fake.flags |= SF_IS_INF;
                if ( flags & SCF_DO_STCLASS && !scan->flags && OP(scan) == IFMATCH ) {
                    ssc_init(pRExC_state, &intrnl);
                    data_fake.start_class = &intrnl;
                    f |= SCF_DO_STCLASS_AND;
                }
                if (flags & SCF_WHILEM_VISITED_POS)
                    f |= SCF_WHILEM_VISITED_POS;
                next = regnext(scan);
                nscan = NEXTOPER(NEXTOPER(scan));

                
                *minnextp = study_chunk(pRExC_state, &nscan, minnextp, &deltanext, last, &data_fake, stopparen, recursed_depth, NULL, f, depth+1);


                if (scan->flags) {
                    assert(0);  
                    if (   deltanext < 0 || deltanext > (I32) U8_MAX || *minnextp > (I32)U8_MAX || *minnextp + deltanext > (I32)U8_MAX)


                    {
			FAIL2("Lookbehind longer than %" UVuf " not implemented", (UV)U8_MAX);
                    }

                    if (deltanext) {
                        scan->next_off = deltanext;
                    }
                    scan->flags = (U8)*minnextp + deltanext;
                }

                *minnextp += min;

                if (f & SCF_DO_STCLASS_AND) {
                    ssc_and(pRExC_state, data->start_class, (regnode_charclass *) &intrnl);
                    ANYOF_FLAGS(data->start_class) |= SSC_MATCHES_EMPTY_STRING;
                }
                if (data) {
                    if (data_fake.flags & (SF_HAS_PAR|SF_IN_PAR))
                        pars++;
                    if (data_fake.flags & SF_HAS_EVAL)
                        data->flags |= SF_HAS_EVAL;
                    data->whilem_c = data_fake.whilem_c;
                    if ((flags & SCF_DO_SUBSTR) && data_fake.last_found) {
                        int i;
                        if (RExC_rx->minlen<*minnextp)
                            RExC_rx->minlen=*minnextp;
                        scan_commit(pRExC_state, &data_fake, minnextp, is_inf);
                        SvREFCNT_dec_NN(data_fake.last_found);

                        for (i = 0; i < 2; i++) {
                            if (data_fake.substrs[i].minlenp != minlenp) {
                                data->substrs[i].min_offset = data_fake.substrs[i].min_offset;
                                data->substrs[i].max_offset = data_fake.substrs[i].max_offset;
                                data->substrs[i].minlenp = data_fake.substrs[i].minlenp;
                                data->substrs[i].lookbehind += scan->flags;
                            }
                        }
                    }
                }
	    }

	}

	else if (OP(scan) == OPEN) {
	    if (stopparen != (I32)ARG(scan))
	        pars++;
	}
	else if (OP(scan) == CLOSE) {
	    if (stopparen == (I32)ARG(scan)) {
	        break;
	    }
	    if ((I32)ARG(scan) == is_par) {
		next = regnext(scan);

		if ( next && (OP(next) != WHILEM) && next < last)
		    is_par = 0;		
	    }
	    if (data)
		*(data->last_closep) = ARG(scan);
	}
	else if (OP(scan) == EVAL) {
		if (data)
		    data->flags |= SF_HAS_EVAL;
	}
	else if ( PL_regkind[OP(scan)] == ENDLIKE ) {
	    if (flags & SCF_DO_SUBSTR) {
                scan_commit(pRExC_state, data, minlenp, is_inf);
		flags &= ~SCF_DO_SUBSTR;
	    }
	    if (data && OP(scan)==ACCEPT) {
	        data->flags |= SCF_SEEN_ACCEPT;
	        if (stopmin > min)
	            stopmin = min;
	    }
	}
	else if (OP(scan) == LOGICAL && scan->flags == 2) 
	{
		if (flags & SCF_DO_SUBSTR) {
                    scan_commit(pRExC_state, data, minlenp, is_inf);
		    data->cur_is_floating = 1; 
		}
		is_inf = is_inf_internal = 1;
		if (flags & SCF_DO_STCLASS_OR) 
		    ssc_anything(data->start_class);
		flags &= ~SCF_DO_STCLASS;
	}
	else if (OP(scan) == GPOS) {
            if (!(RExC_rx->intflags & PREGf_GPOS_FLOAT) && !(delta || is_inf || (data && data->pos_delta)))
	    {
                if (!(RExC_rx->intflags & PREGf_ANCH) && (flags & SCF_DO_SUBSTR))
                    RExC_rx->intflags |= PREGf_ANCH_GPOS;
	        if (RExC_rx->gofs < (STRLEN)min)
		    RExC_rx->gofs = min;
            } else {
                RExC_rx->intflags |= PREGf_GPOS_FLOAT;
                RExC_rx->gofs = 0;
            }
	}


        else if (PL_regkind[OP(scan)] == TRIE) {
            
            regnode *trie_node= scan;
            regnode *tail= regnext(scan);
            reg_trie_data *trie = (reg_trie_data*)RExC_rxi->data->data[ ARG(scan) ];
            SSize_t max1 = 0, min1 = SSize_t_MAX;
            regnode_ssc accum;

            if (flags & SCF_DO_SUBSTR) { 
                
                scan_commit(pRExC_state, data, minlenp, is_inf);
            }
            if (flags & SCF_DO_STCLASS)
                ssc_init_zero(pRExC_state, &accum);

            if (!trie->jump) {
                min1= trie->minlen;
                max1= trie->maxlen;
            } else {
                const regnode *nextbranch= NULL;
                U32 word;

                for ( word=1 ; word <= trie->wordcount ; word++)
                {
                    SSize_t deltanext=0, minnext=0, f = 0, fake;
                    regnode_ssc this_class;

                    StructCopy(&zero_scan_data, &data_fake, scan_data_t);
                    if (data) {
                        data_fake.whilem_c = data->whilem_c;
                        data_fake.last_closep = data->last_closep;
                    }
                    else data_fake.last_closep = &fake;
		    data_fake.pos_delta = delta;
                    if (flags & SCF_DO_STCLASS) {
                        ssc_init(pRExC_state, &this_class);
                        data_fake.start_class = &this_class;
                        f = SCF_DO_STCLASS_AND;
                    }
                    if (flags & SCF_WHILEM_VISITED_POS)
                        f |= SCF_WHILEM_VISITED_POS;

                    if (trie->jump[word]) {
                        if (!nextbranch)
                            nextbranch = trie_node + trie->jump[0];
                        scan= trie_node + trie->jump[word];
                        
                        
                        minnext = study_chunk(pRExC_state, &scan, minlenp, &deltanext, (regnode *)nextbranch, &data_fake, stopparen, recursed_depth, NULL, f, depth+1);

                    }
                    if (nextbranch && PL_regkind[OP(nextbranch)]==BRANCH)
                        nextbranch= regnext((regnode*)nextbranch);

                    if (min1 > (SSize_t)(minnext + trie->minlen))
                        min1 = minnext + trie->minlen;
                    if (deltanext == SSize_t_MAX) {
                        is_inf = is_inf_internal = 1;
                        max1 = SSize_t_MAX;
                    } else if (max1 < (SSize_t)(minnext + deltanext + trie->maxlen))
                        max1 = minnext + deltanext + trie->maxlen;

                    if (data_fake.flags & (SF_HAS_PAR|SF_IN_PAR))
                        pars++;
                    if (data_fake.flags & SCF_SEEN_ACCEPT) {
                        if ( stopmin > min + min1)
	                    stopmin = min + min1;
	                flags &= ~SCF_DO_SUBSTR;
	                if (data)
	                    data->flags |= SCF_SEEN_ACCEPT;
	            }
                    if (data) {
                        if (data_fake.flags & SF_HAS_EVAL)
                            data->flags |= SF_HAS_EVAL;
                        data->whilem_c = data_fake.whilem_c;
                    }
                    if (flags & SCF_DO_STCLASS)
                        ssc_or(pRExC_state, &accum, (regnode_charclass *) &this_class);
                }
            }
            if (flags & SCF_DO_SUBSTR) {
                data->pos_min += min1;
                data->pos_delta += max1 - min1;
                if (max1 != min1 || is_inf)
                    data->cur_is_floating = 1; 
            }
            min += min1;
            if (delta != SSize_t_MAX) {
                if (SSize_t_MAX - (max1 - min1) >= delta)
                    delta += max1 - min1;
                else delta = SSize_t_MAX;
            }
            if (flags & SCF_DO_STCLASS_OR) {
                ssc_or(pRExC_state, data->start_class, (regnode_charclass *) &accum);
                if (min1) {
                    ssc_and(pRExC_state, data->start_class, (regnode_charclass *) and_withp);
                    flags &= ~SCF_DO_STCLASS;
                }
            }
            else if (flags & SCF_DO_STCLASS_AND) {
                if (min1) {
                    ssc_and(pRExC_state, data->start_class, (regnode_charclass *) &accum);
                    flags &= ~SCF_DO_STCLASS;
                }
                else {
                    
		    INIT_AND_WITHP;
                    StructCopy(data->start_class, and_withp, regnode_ssc);
                    flags &= ~SCF_DO_STCLASS_AND;
                    StructCopy(&accum, data->start_class, regnode_ssc);
                    flags |= SCF_DO_STCLASS_OR;
                }
            }
            scan= tail;
            continue;
        }

	else if (PL_regkind[OP(scan)] == TRIE) {
	    reg_trie_data *trie = (reg_trie_data*)RExC_rxi->data->data[ ARG(scan) ];
	    U8*bang=NULL;

	    min += trie->minlen;
	    delta += (trie->maxlen - trie->minlen);
	    flags &= ~SCF_DO_STCLASS; 
            if (flags & SCF_DO_SUBSTR) {
                
                scan_commit(pRExC_state, data, minlenp, is_inf);
    	        data->pos_min += trie->minlen;
    	        data->pos_delta += (trie->maxlen - trie->minlen);
		if (trie->maxlen != trie->minlen)
		    data->cur_is_floating = 1; 
    	    }
    	    if (trie->jump) 
               flags &= ~SCF_DO_SUBSTR;
	}



	
	scan = regnext(scan);
    }

  finish:
    if (frame) {
        
        depth = depth - 1;

        DEBUG_STUDYDATA("frame-end", data, depth, is_inf);
        DEBUG_PEEP("fend", scan, depth, flags);

        
        last = frame->last_regnode;
        scan = frame->next_regnode;
        stopparen = frame->stopparen;
        recursed_depth = frame->prev_recursed_depth;

        RExC_frame_last = frame->prev_frame;
        frame = frame->this_prev_frame;
        goto fake_study_recurse;
    }

    assert(!frame);
    DEBUG_STUDYDATA("pre-fin", data, depth, is_inf);

    *scanp = scan;
    *deltap = is_inf_internal ? SSize_t_MAX : delta;

    if (flags & SCF_DO_SUBSTR && is_inf)
	data->pos_delta = SSize_t_MAX - data->pos_min;
    if (is_par > (I32)U8_MAX)
	is_par = 0;
    if (is_par && pars==1 && data) {
	data->flags |= SF_IN_PAR;
	data->flags &= ~SF_HAS_PAR;
    }
    else if (pars && data) {
	data->flags |= SF_HAS_PAR;
	data->flags &= ~SF_IN_PAR;
    }
    if (flags & SCF_DO_STCLASS_OR)
	ssc_and(pRExC_state, data->start_class, (regnode_charclass *) and_withp);
    if (flags & SCF_TRIE_RESTUDY)
        data->flags |= 	SCF_TRIE_RESTUDY;

    DEBUG_STUDYDATA("post-fin", data, depth, is_inf);

    {
        SSize_t final_minlen= min < stopmin ? min : stopmin;

        if (!(RExC_seen & REG_UNBOUNDED_QUANTIFIER_SEEN)) {
            if (final_minlen > SSize_t_MAX - delta)
                RExC_maxlen = SSize_t_MAX;
            else if (RExC_maxlen < final_minlen + delta)
                RExC_maxlen = final_minlen + delta;
        }
        return final_minlen;
    }
    NOT_REACHED; 
}

STATIC U32 S_add_data(RExC_state_t* const pRExC_state, const char* const s, const U32 n)
{
    U32 count = RExC_rxi->data ? RExC_rxi->data->count : 0;

    PERL_ARGS_ASSERT_ADD_DATA;

    Renewc(RExC_rxi->data, sizeof(*RExC_rxi->data) + sizeof(void*) * (count + n - 1), char, struct reg_data);

    if(count)
	Renew(RExC_rxi->data->what, count + n, U8);
    else Newx(RExC_rxi->data->what, n, U8);
    RExC_rxi->data->count = count + n;
    Copy(s, RExC_rxi->data->what + count, n, U8);
    return count;
}



void Perl_reginitcolors(pTHX)
{
    const char * const s = PerlEnv_getenv("PERL_RE_COLORS");
    if (s) {
	char *t = savepv(s);
	int i = 0;
	PL_colors[0] = t;
	while (++i < 6) {
	    t = strchr(t, '\t');
	    if (t) {
		*t = '\0';
		PL_colors[i] = ++t;
	    }
	    else PL_colors[i] = t = (char *)"";
	}
    } else {
	int i = 0;
	while (i < 6)
	    PL_colors[i++] = (char *)"";
    }
    PL_colorset = 1;
}























regexp_engine const * Perl_current_re_engine(pTHX)
{
    if (IN_PERL_COMPILETIME) {
	HV * const table = GvHV(PL_hintgv);
	SV **ptr;

	if (!table || !(PL_hints & HINT_LOCALIZE_HH))
	    return &PL_core_reg_engine;
	ptr = hv_fetchs(table, "regcomp", FALSE);
	if ( !(ptr && SvIOK(*ptr) && SvIV(*ptr)))
	    return &PL_core_reg_engine;
	return INT2PTR(regexp_engine*, SvIV(*ptr));
    }
    else {
	SV *ptr;
	if (!PL_curcop->cop_hints_hash)
	    return &PL_core_reg_engine;
	ptr = cop_hints_fetch_pvs(PL_curcop, "regcomp", 0);
	if ( !(ptr && SvIOK(ptr) && SvIV(ptr)))
	    return &PL_core_reg_engine;
	return INT2PTR(regexp_engine*, SvIV(ptr));
    }
}


REGEXP * Perl_pregcomp(pTHX_ SV * const pattern, const U32 flags)
{
    regexp_engine const *eng = current_re_engine();
    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_PREGCOMP;

    
    DEBUG_COMPILE_r({
        Perl_re_printf( aTHX_  "Using engine %" UVxf "\n", PTR2UV(eng));
    });
    return CALLREGCOMP_ENG(eng, pattern, flags);
}




REGEXP * Perl_re_compile(pTHX_ SV * const pattern, U32 rx_flags)
{
    SV *pat = pattern; 
    PERL_ARGS_ASSERT_RE_COMPILE;
    return Perl_re_op_compile(aTHX_ &pat, 1, NULL,  &my_reg_engine,  &PL_core_reg_engine,  NULL, NULL, rx_flags, 0);





}


static void S_free_codeblocks(pTHX_ struct reg_code_blocks *cbs)
{
    int n;

    if (--cbs->refcnt > 0)
        return;
    for (n = 0; n < cbs->count; n++) {
        REGEXP *rx = cbs->cb[n].src_regex;
        if (rx) {
            cbs->cb[n].src_regex = NULL;
            SvREFCNT_dec_NN(rx);
        }
    }
    Safefree(cbs->cb);
    Safefree(cbs);
}


static struct reg_code_blocks * S_alloc_code_blocks(pTHX_  int ncode)
{
     struct reg_code_blocks *cbs;
    Newx(cbs, 1, struct reg_code_blocks);
    cbs->count = ncode;
    cbs->refcnt = 1;
    SAVEDESTRUCTOR_X(S_free_codeblocks, cbs);
    if (ncode)
        Newx(cbs->cb, ncode, struct reg_code_block);
    else cbs->cb = NULL;
    return cbs;
}




static void S_pat_upgrade_to_utf8(pTHX_ RExC_state_t * const pRExC_state, char **pat_p, STRLEN *plen_p, int num_code_blocks)

{
    U8 *const src = (U8*)*pat_p;
    U8 *dst, *d;
    int n=0;
    STRLEN s = 0;
    bool do_end = 0;
    GET_RE_DEBUG_FLAGS_DECL;

    DEBUG_PARSE_r(Perl_re_printf( aTHX_ "UTF8 mismatch! Converting to utf8 for resizing and compile\n"));

    
    Newx(dst, *plen_p + variant_under_utf8_count(src, src + *plen_p) + 1, U8);
    d = dst;

    while (s < *plen_p) {
        append_utf8_from_native_byte(src[s], &d);

        if (n < num_code_blocks) {
            assert(pRExC_state->code_blocks);
            if (!do_end && pRExC_state->code_blocks->cb[n].start == s) {
                pRExC_state->code_blocks->cb[n].start = d - dst - 1;
                assert(*(d - 1) == '(');
                do_end = 1;
            }
            else if (do_end && pRExC_state->code_blocks->cb[n].end == s) {
                pRExC_state->code_blocks->cb[n].end = d - dst - 1;
                assert(*(d - 1) == ')');
                do_end = 0;
                n++;
            }
        }
        s++;
    }
    *d = '\0';
    *plen_p = d - dst;
    *pat_p = (char*) dst;
    SAVEFREEPV(*pat_p);
    RExC_orig_utf8 = RExC_utf8 = 1;
}





static SV* S_concat_pat(pTHX_ RExC_state_t * const pRExC_state, SV *pat, SV ** const patternp, int pat_count, OP *oplist, bool *recompile_p, SV *delim)


{
    SV **svp;
    int n = 0;
    bool use_delim = FALSE;
    bool alloced = FALSE;

    
    if (!pat && pat_count != 1) {
        pat = newSVpvs("");
        SAVEFREESV(pat);
        alloced = TRUE;
    }

    for (svp = patternp; svp < patternp + pat_count; svp++) {
        SV *sv;
        SV *rx  = NULL;
        STRLEN orig_patlen = 0;
        bool code = 0;
        SV *msv = use_delim ? delim : *svp;
        if (!msv) msv = &PL_sv_undef;

        
        if (use_delim) {
            svp--;
            use_delim = FALSE;
        }
        else if (delim)
            use_delim = TRUE;

        if (SvTYPE(msv) == SVt_PVAV) {
            

            AV *const av = (AV*)msv;
            const SSize_t maxarg = AvFILL(av) + 1;
            SV **array;

            if (oplist) {
                assert(oplist->op_type == OP_PADAV || oplist->op_type == OP_RV2AV);
                oplist = OpSIBLING(oplist);
            }

            if (SvRMAGICAL(av)) {
                SSize_t i;

                Newx(array, maxarg, SV*);
                SAVEFREEPV(array);
                for (i=0; i < maxarg; i++) {
                    SV ** const svp = av_fetch(av, i, FALSE);
                    array[i] = svp ? *svp : &PL_sv_undef;
                }
            }
            else array = AvARRAY(av);

            pat = S_concat_pat(aTHX_ pRExC_state, pat, array, maxarg, NULL, recompile_p,  GvSV((gv_fetchpvs("\"", GV_ADDMULTI, SVt_PV))));



            continue;
        }


        

        if (oplist) {
            if (oplist->op_type == OP_NULL && (oplist->op_flags & OPf_SPECIAL))
            {
                assert(n < pRExC_state->code_blocks->count);
                pRExC_state->code_blocks->cb[n].start = pat ? SvCUR(pat) : 0;
                pRExC_state->code_blocks->cb[n].block = oplist;
                pRExC_state->code_blocks->cb[n].src_regex = NULL;
                n++;
                code = 1;
                oplist = OpSIBLING(oplist); 
                assert(oplist);
            }
            oplist = OpSIBLING(oplist);;
        }

	

        SvGETMAGIC(msv);
        if (SvROK(msv) && SvAMAGIC(msv)) {
            SV *sv = AMG_CALLunary(msv, regexp_amg);
            if (sv) {
                if (SvROK(sv))
                    sv = SvRV(sv);
                if (SvTYPE(sv) != SVt_REGEXP)
                    Perl_croak(aTHX_ "Overloaded qr did not return a REGEXP");
                msv = sv;
            }
        }

        
        if (pat && (SvAMAGIC(pat) || SvAMAGIC(msv)) && (sv = amagic_call(pat, msv, concat_amg, AMGf_assign)))
        {
            sv_setsv(pat, sv);
            
            if (n)
                pRExC_state->code_blocks->count -= n;
            n = 0;
        }
        else  {
            
            while (SvAMAGIC(msv)
                    && (sv = AMG_CALLunary(msv, string_amg))
                    && sv != msv &&  !(   SvROK(msv)
                          && SvROK(sv)
                          && SvRV(msv) == SvRV(sv))
            ) {
                msv = sv;
                SvGETMAGIC(msv);
            }
            if (SvROK(msv) && SvTYPE(SvRV(msv)) == SVt_REGEXP)
                msv = SvRV(msv);

            if (pat) {
                
                STRLEN dlen;
                char *dst = SvPV_force_nomg(pat, dlen);
                orig_patlen = dlen;
                if (SvUTF8(msv) && !SvUTF8(pat)) {
                    S_pat_upgrade_to_utf8(aTHX_ pRExC_state, &dst, &dlen, n);
                    sv_setpvn(pat, dst, dlen);
                    SvUTF8_on(pat);
                }
                sv_catsv_nomg(pat, msv);
                rx = msv;
            }
            else {
                
                if ( SvTYPE(msv) != SVt_PV || (SvLEN(msv) > SvCUR(msv) && *(SvEND(msv)) == 0) || SvIsCOW_shared_hash(msv) ) {
                    
                    pat = msv;
                } else {
                    
                    pat = sv_2mortal(newSVsv(msv));
                }
            }

            if (code)
                pRExC_state->code_blocks->cb[n-1].end = SvCUR(pat)-1;
        }

        
        if (rx && SvTYPE(rx) == SVt_REGEXP && RX_ENGINE((REGEXP*)rx)->op_comp)
        {

            RXi_GET_DECL(ReANY((REGEXP *)rx), ri);
            if (ri->code_blocks && ri->code_blocks->count) {
                int i;
                
                *recompile_p = 1;
                if (pRExC_state->code_blocks) {
                    int new_count = pRExC_state->code_blocks->count + ri->code_blocks->count;
                    Renew(pRExC_state->code_blocks->cb, new_count, struct reg_code_block);
                    pRExC_state->code_blocks->count = new_count;
                }
                else pRExC_state->code_blocks = S_alloc_code_blocks(aTHX_ ri->code_blocks->count);


                for (i=0; i < ri->code_blocks->count; i++) {
                    struct reg_code_block *src, *dst;
                    STRLEN offset =  orig_patlen + ReANY((REGEXP *)rx)->pre_prefix;
                    assert(n < pRExC_state->code_blocks->count);
                    src = &ri->code_blocks->cb[i];
                    dst = &pRExC_state->code_blocks->cb[n];
                    dst->start	    = src->start + offset;
                    dst->end	    = src->end   + offset;
                    dst->block	    = src->block;
                    dst->src_regex  = (REGEXP*) SvREFCNT_inc( (SV*)
                                            src->src_regex ? src->src_regex : (REGEXP*)rx);

                    n++;
                }
            }
        }
    }
    
    if (alloced)
        SvSETMAGIC(pat);

    return pat;
}





static bool S_has_runtime_code(pTHX_ RExC_state_t * const pRExC_state, char *pat, STRLEN plen)

{
    int n = 0;
    STRLEN s;

    PERL_UNUSED_CONTEXT;

    for (s = 0; s < plen; s++) {
	if (   pRExC_state->code_blocks && n < pRExC_state->code_blocks->count && s == pRExC_state->code_blocks->cb[n].start)

	{
	    s = pRExC_state->code_blocks->cb[n].end;
	    n++;
	    continue;
	}
	
	if (pat[s] == '(' && s+2 <= plen && pat[s+1] == '?' && (pat[s+2] == '{' || (s + 2 <= plen && pat[s+2] == '?' && pat[s+3] == '{'))

	)
	    return 1;
    }
    return 0;
}



static bool S_compile_runtime_code(pTHX_ RExC_state_t * const pRExC_state, char *pat, STRLEN plen)

{
    SV *qr;

    GET_RE_DEBUG_FLAGS_DECL;

    if (pRExC_state->runtime_code_qr) {
	
	qr = pRExC_state->runtime_code_qr;
	pRExC_state->runtime_code_qr = NULL;
	assert(RExC_utf8 && SvUTF8(qr));
    }
    else {
	int n = 0;
	STRLEN s;
	char *p, *newpat;
	int newlen = plen + 7; 
	SV *sv, *qr_ref;
	dSP;

	
	for (s = 0; s < plen; s++) {
	    if (pat[s] == '\'' || pat[s] == '\\')
		newlen++;
	}

	Newx(newpat, newlen, char);
	p = newpat;
	*p++ = 'q'; *p++ = 'r'; *p++ = '\'';

	for (s = 0; s < plen; s++) {
	    if (   pRExC_state->code_blocks && n < pRExC_state->code_blocks->count && s == pRExC_state->code_blocks->cb[n].start)

	    {
		
		assert(pat[s]   == '(');
		assert(pat[s+1] == '?');
                *p++ = '(';
                *p++ = '?';
                s += 2;
		while (s < pRExC_state->code_blocks->cb[n].end) {
		    *p++ = '=';
		    s++;
		}
                *p++ = ')';
		n++;
		continue;
	    }
	    if (pat[s] == '\'' || pat[s] == '\\')
		*p++ = '\\';
	    *p++ = pat[s];
	}
	*p++ = '\'';
	if (pRExC_state->pm_flags & RXf_PMf_EXTENDED) {
	    *p++ = 'x';
            if (pRExC_state->pm_flags & RXf_PMf_EXTENDED_MORE) {
                *p++ = 'x';
            }
        }
	*p++ = '\0';
	DEBUG_COMPILE_r({
            Perl_re_printf( aTHX_ "%sre-parsing pattern for runtime code:%s %s\n", PL_colors[4], PL_colors[5], newpat);

	});

	sv = newSVpvn_flags(newpat, p-newpat-1, RExC_utf8 ? SVf_UTF8 : 0);
	Safefree(newpat);

	ENTER;
	SAVETMPS;
	save_re_context();
	PUSHSTACKi(PERLSI_REQUIRE);
        
	eval_sv(sv, G_SCALAR|G_RE_REPARSING);
	SvREFCNT_dec_NN(sv);
	SPAGAIN;
	qr_ref = POPs;
	PUTBACK;
	{
	    SV * const errsv = ERRSV;
	    if (SvTRUE_NN(errsv))
                
		Perl_croak_nocontext("%" SVf, SVfARG(errsv));
	}
	assert(SvROK(qr_ref));
	qr = SvRV(qr_ref);
	assert(SvTYPE(qr) == SVt_REGEXP && RX_ENGINE((REGEXP*)qr)->op_comp);
	
	SvREFCNT_inc(qr);
	POPSTACK;
	FREETMPS;
	LEAVE;

    }

    if (!RExC_utf8 && SvUTF8(qr)) {
	
	assert(!pRExC_state->runtime_code_qr);
	pRExC_state->runtime_code_qr = qr;
	return 0;
    }


    


    
    {
	RXi_GET_DECL(ReANY((REGEXP *)qr), r2);
	struct reg_code_block *new_block, *dst;
	RExC_state_t * const r1 = pRExC_state; 
	int i1 = 0, i2 = 0;
        int r1c, r2c;

	if (!r2->code_blocks || !r2->code_blocks->count) 
	{
	    SvREFCNT_dec_NN(qr);
	    return 1;
	}

        if (!r1->code_blocks)
            r1->code_blocks = S_alloc_code_blocks(aTHX_ 0);

        r1c = r1->code_blocks->count;
        r2c = r2->code_blocks->count;

	Newx(new_block, r1c + r2c, struct reg_code_block);

	dst = new_block;

	while (i1 < r1c || i2 < r2c) {
	    struct reg_code_block *src;
	    bool is_qr = 0;

	    if (i1 == r1c) {
		src = &r2->code_blocks->cb[i2++];
		is_qr = 1;
	    }
	    else if (i2 == r2c)
		src = &r1->code_blocks->cb[i1++];
	    else if (  r1->code_blocks->cb[i1].start < r2->code_blocks->cb[i2].start)
	    {
		src = &r1->code_blocks->cb[i1++];
		assert(src->end < r2->code_blocks->cb[i2].start);
	    }
	    else {
		assert(  r1->code_blocks->cb[i1].start > r2->code_blocks->cb[i2].start);
		src = &r2->code_blocks->cb[i2++];
		is_qr = 1;
		assert(src->end < r1->code_blocks->cb[i1].start);
	    }

	    assert(pat[src->start] == '(');
	    assert(pat[src->end]   == ')');
	    dst->start	    = src->start;
	    dst->end	    = src->end;
	    dst->block	    = src->block;
	    dst->src_regex  = is_qr ? (REGEXP*) SvREFCNT_inc( (SV*) qr)
				    : src->src_regex;
	    dst++;
	}
	r1->code_blocks->count += r2c;
	Safefree(r1->code_blocks->cb);
	r1->code_blocks->cb = new_block;
    }

    SvREFCNT_dec_NN(qr);
    return 1;
}


STATIC bool S_setup_longest(pTHX_ RExC_state_t *pRExC_state, struct reg_substr_datum  *rsd, struct scan_data_substrs *sub, STRLEN longest_length)



{
    

    I32 t;
    SSize_t ml;
    bool eol  = cBOOL(sub->flags & SF_BEFORE_EOL);
    bool meol = cBOOL(sub->flags & SF_BEFORE_MEOL);

    if (! (longest_length || (eol && (! meol || (RExC_flags & RXf_PMf_MULTILINE)))

          )
            
        || (RExC_seen & REG_UNFOLDED_MULTI_SEEN))
    {
        return FALSE;
    }

    
    if (SvUTF8(sub->str)) {
        rsd->substr      = NULL;
        rsd->utf8_substr = sub->str;
    } else {
        rsd->substr      = sub->str;
        rsd->utf8_substr = NULL;
    }
    
    ml = sub->minlenp ? *(sub->minlenp) : (SSize_t)longest_length;
    rsd->end_shift = ml - sub->min_offset - longest_length  + sub->lookbehind;



    t = (eol && (! meol || (RExC_flags & RXf_PMf_MULTILINE)));
    fbm_compile(sub->str, t ? FBMcf_TAIL : 0);

    return TRUE;
}

STATIC void S_set_regex_pv(pTHX_ RExC_state_t *pRExC_state, REGEXP *Rx)
{
    

    bool has_p     = ((RExC_rx->extflags & RXf_PMf_KEEPCOPY) == RXf_PMf_KEEPCOPY);
    bool has_charset = RExC_utf8 || (get_regex_charset(RExC_rx->extflags)
                                                != REGEX_DEPENDS_CHARSET);

    
    bool has_default = (((RExC_rx->extflags & RXf_PMf_STD_PMMOD) != RXf_PMf_STD_PMMOD)
                || ! has_charset);
    bool has_runon = ((RExC_seen & REG_RUN_ON_COMMENT_SEEN)
                                                == REG_RUN_ON_COMMENT_SEEN);
    U8 reganch = (U8)((RExC_rx->extflags & RXf_PMf_STD_PMMOD)
                        >> RXf_PMf_STD_PMMOD_SHIFT);
    const char *fptr = STD_PAT_MODS;        
    char *p;
    STRLEN pat_len = RExC_precomp_end - RExC_precomp;

    
    const STRLEN wraplen = pat_len + has_p + has_runon + has_default + PL_bitcount[reganch]   + ((has_charset) ? MAX_CHARSET_NAME_LENGTH : 0)




        + (sizeof("(?:)") - 1);

    PERL_ARGS_ASSERT_SET_REGEX_PV;

    
    assert(sizeof(STD_PAT_MODS) <= 8);

    p = sv_grow(MUTABLE_SV(Rx), wraplen + 1); 
    SvPOK_on(Rx);
    if (RExC_utf8)
        SvFLAGS(Rx) |= SVf_UTF8;
    *p++='('; *p++='?';

    
    if (has_default) {
        *p++= DEFAULT_PAT_MOD;
    }
    if (has_charset) {
        STRLEN len;
        const char* name;

        name = get_regex_charset_name(RExC_rx->extflags, &len);
        if strEQ(name, DEPENDS_PAT_MODS) {  
            assert(RExC_utf8);
            name = UNICODE_PAT_MODS;
            len = sizeof(UNICODE_PAT_MODS) - 1;
        }
        Copy(name, p, len, char);
        p += len;
    }
    if (has_p)
        *p++ = KEEPCOPY_PAT_MOD; 
    {
        char ch;
        while((ch = *fptr++)) {
            if(reganch & 1)
                *p++ = ch;
            reganch >>= 1;
        }
    }

    *p++ = ':';
    Copy(RExC_precomp, p, pat_len, char);
    assert ((RX_WRAPPED(Rx) - p) < 16);
    RExC_rx->pre_prefix = p - RX_WRAPPED(Rx);
    p += pat_len;

    
    if (has_runon)
        *p++ = '\n';
    *p++ = ')';
    *p = 0;
    SvCUR_set(Rx, p - RX_WRAPPED(Rx));
}



REGEXP * Perl_re_op_compile(pTHX_ SV ** const patternp, int pat_count, OP *expr, const regexp_engine* eng, REGEXP *old_re, bool *is_bare_re, const U32 orig_rx_flags, const U32 pm_flags)


{
    dVAR;
    REGEXP *Rx;         
    STRLEN plen;
    char *exp;
    regnode *scan;
    I32 flags;
    SSize_t minlen = 0;
    U32 rx_flags;
    SV *pat;
    SV** new_patternp = patternp;

    
    I32 sawlookahead = 0;
    I32 sawplus = 0;
    I32 sawopen = 0;
    I32 sawminmod = 0;

    regex_charset initial_charset = get_regex_charset(orig_rx_flags);
    bool recompile = 0;
    bool runtime_code = 0;
    scan_data_t data;
    RExC_state_t RExC_state;
    RExC_state_t * const pRExC_state = &RExC_state;

    int restudied = 0;
    RExC_state_t copyRExC_state;

    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_RE_OP_COMPILE;

    DEBUG_r(if (!PL_colorset) reginitcolors());

    
    if (! PL_InBitmap) {

        char * dump_len_string;


        
	PL_InBitmap = _new_invlist(2);
	PL_InBitmap = _add_range_to_invlist(PL_InBitmap, 0, NUM_ANYOF_CODE_POINTS - 1);

        dump_len_string = PerlEnv_getenv("PERL_DUMP_RE_MAX_LEN");
        if (   ! dump_len_string || ! grok_atoUV(dump_len_string, (UV *)&PL_dump_re_max_len, NULL))
        {
            PL_dump_re_max_len = 60;    
        }

    }

    pRExC_state->warn_text = NULL;
    pRExC_state->unlexed_names = NULL;
    pRExC_state->code_blocks = NULL;

    if (is_bare_re)
	*is_bare_re = FALSE;

    if (expr && (expr->op_type == OP_LIST || (expr->op_type == OP_NULL && expr->op_targ == OP_LIST))) {
	
	OP *o;
	int ncode = 0;

	for (o = cLISTOPx(expr)->op_first; o; o = OpSIBLING(o))
	    if (o->op_type == OP_NULL && (o->op_flags & OPf_SPECIAL))
		ncode++; 

	if (ncode)
            pRExC_state->code_blocks = S_alloc_code_blocks(aTHX_ ncode);
    }

    if (!pat_count) {
        

        int n;
        OP *o;

        
        assert(expr);
        n = 0;
        if (expr->op_type == OP_CONST)
            n = 1;
        else for (o = cLISTOPx(expr)->op_first; o; o = OpSIBLING(o)) {
                if (o->op_type == OP_CONST)
                    n++;
            }

        

        assert(!new_patternp);
        Newx(new_patternp, n, SV*);
        SAVEFREEPV(new_patternp);
        pat_count = n;

        n = 0;
        if (expr->op_type == OP_CONST)
            new_patternp[n] = cSVOPx_sv(expr);
        else for (o = cLISTOPx(expr)->op_first; o; o = OpSIBLING(o)) {
                if (o->op_type == OP_CONST)
                    new_patternp[n++] = cSVOPo_sv;
            }

    }

    DEBUG_PARSE_r(Perl_re_printf( aTHX_ "Assembling pattern from %d elements%s\n", pat_count, orig_rx_flags & RXf_SPLIT ? " for split" : ""));


    

    if (pRExC_state->code_blocks && pRExC_state->code_blocks->count && expr->op_type != OP_CONST)
    {
            expr = cLISTOPx(expr)->op_first;
            assert(   expr->op_type == OP_PUSHMARK || (expr->op_type == OP_NULL && expr->op_targ == OP_PUSHMARK)
                   || expr->op_type == OP_PADRANGE);
            expr = OpSIBLING(expr);
    }

    pat = S_concat_pat(aTHX_ pRExC_state, NULL, new_patternp, pat_count, expr, &recompile, NULL);

    
    {
        SV *re = pat;
        if (SvROK(re))
            re = SvRV(re);
        if (SvTYPE(re) == SVt_REGEXP) {
            if (is_bare_re)
                *is_bare_re = TRUE;
            SvREFCNT_inc(re);
            DEBUG_PARSE_r(Perl_re_printf( aTHX_ "Precompiled pattern%s\n", orig_rx_flags & RXf_SPLIT ? " for split" : ""));


            return (REGEXP*)re;
        }
    }

    exp = SvPV_nomg(pat, plen);

    if (!eng->op_comp) {
	if ((SvUTF8(pat) && IN_BYTES)
		|| SvGMAGICAL(pat) || SvAMAGIC(pat))
	{
	    
	    pat = newSVpvn_flags(exp, plen, SVs_TEMP | (IN_BYTES ? 0 : SvUTF8(pat)));
	}
	return CALLREGCOMP_ENG(eng, pat, orig_rx_flags);
    }

    
    RExC_utf8 = RExC_orig_utf8 = (plen == 0 || IN_BYTES) ? 0 : SvUTF8(pat);
    RExC_uni_semantics = 0;
    RExC_contains_locale = 0;
    RExC_strict = cBOOL(pm_flags & RXf_PMf_STRICT);
    RExC_in_script_run = 0;
    RExC_study_started = 0;
    pRExC_state->runtime_code_qr = NULL;
    RExC_frame_head= NULL;
    RExC_frame_last= NULL;
    RExC_frame_count= 0;
    RExC_latest_warn_offset = 0;
    RExC_use_BRANCHJ = 0;
    RExC_total_parens = 0;
    RExC_open_parens = NULL;
    RExC_close_parens = NULL;
    RExC_paren_names = NULL;
    RExC_size = 0;
    RExC_seen_d_op = FALSE;

    RExC_paren_name_list = NULL;


    DEBUG_r({
        RExC_mysv1= sv_newmortal();
        RExC_mysv2= sv_newmortal();
    });

    DEBUG_COMPILE_r({
            SV *dsv= sv_newmortal();
            RE_PV_QUOTED_DECL(s, RExC_utf8, dsv, exp, plen, PL_dump_re_max_len);
            Perl_re_printf( aTHX_  "%sCompiling REx%s %s\n", PL_colors[4], PL_colors[5], s);
        });

    

    if ((pm_flags & PMf_USE_RE_EVAL)
		
		|| (IN_PERL_COMPILETIME && (PL_hints & HINT_RE_EVAL))
    )
	runtime_code = S_has_runtime_code(aTHX_ pRExC_state, exp, plen);

  redo_parse:
    
    

    if (   old_re && !recompile && !!RX_UTF8(old_re) == !!RExC_utf8 && ( RX_COMPFLAGS(old_re) == ( orig_rx_flags & RXf_PMf_FLAGCOPYMASK ) )


	&& RX_PRECOMP(old_re)
	&& RX_PRELEN(old_re) == plen && memEQ(RX_PRECOMP(old_re), exp, plen)
	&& !runtime_code  )
    {
        return old_re;
    }

    
    RExC_rx_sv = Rx = (REGEXP*) newSV_type(SVt_REGEXP);
    RExC_rx = ReANY(Rx);
    if ( RExC_rx == NULL )
        FAIL("Regexp out of space");

    rx_flags = orig_rx_flags;

    if (   (UTF || RExC_uni_semantics)
        && initial_charset == REGEX_DEPENDS_CHARSET)
    {

	
	set_regex_charset(&rx_flags, REGEX_UNICODE_CHARSET);
        RExC_uni_semantics = 1;
    }

    RExC_pm_flags = pm_flags;

    if (runtime_code) {
        assert(TAINTING_get || !TAINT_get);
	if (TAINT_get)
	    Perl_croak(aTHX_ "Eval-group in insecure regular expression");

	if (!S_compile_runtime_code(aTHX_ pRExC_state, exp, plen)) {
	    
            S_pat_upgrade_to_utf8(aTHX_ pRExC_state, &exp, &plen, pRExC_state->code_blocks ? pRExC_state->code_blocks->count : 0);
            goto redo_parse;
	}
    }
    assert(!pRExC_state->runtime_code_qr);

    RExC_sawback = 0;

    RExC_seen = 0;
    RExC_maxlen = 0;
    RExC_in_lookbehind = 0;
    RExC_seen_zerolen = *exp == '^' ? -1 : 0;

    RExC_recode_x_to_native = 0;

    RExC_in_multi_char_class = 0;

    RExC_start = RExC_copy_start_in_constructed = RExC_copy_start_in_input = RExC_precomp = exp;
    RExC_precomp_end = RExC_end = exp + plen;
    RExC_nestroot = 0;
    RExC_whilem_seen = 0;
    RExC_end_op = NULL;
    RExC_recurse = NULL;
    RExC_study_chunk_recursed = NULL;
    RExC_study_chunk_recursed_bytes= 0;
    RExC_recurse_count = 0;
    pRExC_state->code_index = 0;

    
    set_regex_pv(pRExC_state, Rx);

    DEBUG_PARSE_r({
        Perl_re_printf( aTHX_ "Starting parse and generation\n");
        RExC_lastnum=0;
        RExC_lastparse=NULL;
    });

    
    if (!  RExC_size) {

        
        RExC_size = STR_SZ(RExC_end - RExC_start);
    }

    Newxc(RExC_rxi, sizeof(regexp_internal) + RExC_size, char, regexp_internal);
    if ( RExC_rxi == NULL )
        FAIL("Regexp out of space");

    Zero(RExC_rxi, sizeof(regexp_internal) + RExC_size, char);
    RXi_SET( RExC_rx, RExC_rxi );

    
    RExC_size = 0;

    
    RExC_rx->engine= eng;
    RExC_rx->extflags = rx_flags;
    RXp_COMPFLAGS(RExC_rx) = orig_rx_flags & RXf_PMf_FLAGCOPYMASK;

    if (pm_flags & PMf_IS_QR) {
	RExC_rxi->code_blocks = pRExC_state->code_blocks;
        if (RExC_rxi->code_blocks) {
            RExC_rxi->code_blocks->refcnt++;
        }
    }

    RExC_rx->intflags = 0;

    RExC_flags = rx_flags;	
    RExC_parse = exp;

    
    assert(*RExC_end == '\0');

    RExC_naughty = 0;
    RExC_npar = 1;
    RExC_parens_buf_size = 0;
    RExC_emit_start = RExC_rxi->program;
    pRExC_state->code_index = 0;

    *((char*) RExC_emit_start) = (char) REG_MAGIC;
    RExC_emit = 1;

    
    if (reg(pRExC_state, 0, &flags, 1)) {

        
        if (IN_PARENS_PASS) {
            flags |= RESTART_PARSE;
        }

        
        RExC_total_parens = RExC_npar;

        
        if (RExC_size > U16_MAX && ! RExC_use_BRANCHJ) {
            RExC_use_BRANCHJ = TRUE;
            flags |= RESTART_PARSE;
        }
    }
    else if (! MUST_RESTART(flags)) {
	ReREFCNT_dec(Rx);
        Perl_croak(aTHX_ "panic: reg returned failure to re_op_compile, flags=%#" UVxf, (UV) flags);
    }

    
    if (MUST_RESTART(flags)) {

        
        if (flags & NEED_UTF8) {

            
            if (UNLIKELY(RExC_latest_warn_offset > 0)) {
                RExC_latest_warn_offset += variant_under_utf8_count((U8 *) exp, (U8 *) exp + RExC_latest_warn_offset);

            }
            S_pat_upgrade_to_utf8(aTHX_ pRExC_state, &exp, &plen, pRExC_state->code_blocks ? pRExC_state->code_blocks->count : 0);
            DEBUG_PARSE_r(Perl_re_printf( aTHX_ "Need to redo parse after upgrade\n"));
        }
        else {
            DEBUG_PARSE_r(Perl_re_printf( aTHX_ "Need to redo parse\n"));
        }

        if (ALL_PARENS_COUNTED) {
            
            Renew(RExC_open_parens, RExC_total_parens, regnode_offset);
            Zero(RExC_open_parens, RExC_total_parens, regnode_offset);
            RExC_open_parens[0] = 1;    

            Renew(RExC_close_parens, RExC_total_parens, regnode_offset);
            Zero(RExC_close_parens, RExC_total_parens, regnode_offset);
        }
        else { 
            RExC_total_parens = 0;
            if (RExC_open_parens) {
                Safefree(RExC_open_parens);
                RExC_open_parens = NULL;
            }
            if (RExC_close_parens) {
                Safefree(RExC_close_parens);
                RExC_close_parens = NULL;
            }
        }

        
        SvREFCNT_dec_NN(RExC_rx_sv);

        goto redo_parse;
    }

    

    
    set_regex_pv(pRExC_state, Rx);

    RExC_rx->nparens = RExC_total_parens - 1;

    
    if (RExC_whilem_seen > 15)
        RExC_whilem_seen = 15;

    DEBUG_PARSE_r({
        Perl_re_printf( aTHX_ "Required size %" IVdf " nodes\n", (IV)RExC_size);
        RExC_lastnum=0;
        RExC_lastparse=NULL;
    });


    DEBUG_OFFSETS_r(Perl_re_printf( aTHX_ "%s %" UVuf " bytes for offset annotations.\n", RExC_offsets ? "Got" : "Couldn't get", (UV)((RExC_offsets[0] * 2 + 1))));


    DEBUG_OFFSETS_r(if (RExC_offsets) {
        const STRLEN len = RExC_offsets[0];
        STRLEN i;
        GET_RE_DEBUG_FLAGS_DECL;
        Perl_re_printf( aTHX_ "Offsets: [%" UVuf "]\n\t", (UV)RExC_offsets[0]);
        for (i = 1; i <= len; i++) {
            if (RExC_offsets[i*2-1] || RExC_offsets[i*2])
                Perl_re_printf( aTHX_  "%" UVuf ":%" UVuf "[%" UVuf "] ", (UV)i, (UV)RExC_offsets[i*2-1], (UV)RExC_offsets[i*2]);
        }
        Perl_re_printf( aTHX_  "\n");
    });


    SetProgLen(RExC_rxi,RExC_size);


    DEBUG_OPTIMISE_r( Perl_re_printf( aTHX_  "Starting post parse optimization\n");
    );

    
    Newx(RExC_rx->substrs, 1, struct reg_substr_data);
    if (RExC_recurse_count) {
        Newx(RExC_recurse, RExC_recurse_count, regnode *);
        SAVEFREEPV(RExC_recurse);
    }

    if (RExC_seen & REG_RECURSE_SEEN) {
        
        RExC_study_chunk_recursed_bytes= (RExC_total_parens >> 3) + ((RExC_total_parens & 0x07) != 0);
        Newx(RExC_study_chunk_recursed, RExC_study_chunk_recursed_bytes * RExC_total_parens, U8);
        SAVEFREEPV(RExC_study_chunk_recursed);
    }

  reStudy:
    RExC_rx->minlen = minlen = sawlookahead = sawplus = sawopen = sawminmod = 0;
    DEBUG_r( RExC_study_chunk_recursed_count= 0;
    );
    Zero(RExC_rx->substrs, 1, struct reg_substr_data);
    if (RExC_study_chunk_recursed) {
        Zero(RExC_study_chunk_recursed, RExC_study_chunk_recursed_bytes * RExC_total_parens, U8);
    }



    if (!restudied) {
        StructCopy(&zero_scan_data, &data, scan_data_t);
        copyRExC_state = RExC_state;
    } else {
        U32 seen=RExC_seen;
        DEBUG_OPTIMISE_r(Perl_re_printf( aTHX_ "Restudying\n"));

        RExC_state = copyRExC_state;
        if (seen & REG_TOP_LEVEL_BRANCHES_SEEN)
            RExC_seen |= REG_TOP_LEVEL_BRANCHES_SEEN;
        else RExC_seen &= ~REG_TOP_LEVEL_BRANCHES_SEEN;
	StructCopy(&zero_scan_data, &data, scan_data_t);
    }

    StructCopy(&zero_scan_data, &data, scan_data_t);


    
    RExC_rx->extflags = RExC_flags; 
    

    if (UTF)
	SvUTF8_on(Rx);	
    RExC_rxi->regstclass = NULL;
    if (RExC_naughty >= TOO_NAUGHTY)	
	RExC_rx->intflags |= PREGf_NAUGHTY;
    scan = RExC_rxi->program + 1;		

    
    if (!(RExC_seen & REG_TOP_LEVEL_BRANCHES_SEEN)) { 
	SSize_t fake;
	STRLEN longest_length[2];
	regnode_ssc ch_class; 
	int stclass_flag;
	SSize_t last_close = 0; 
        regnode *first= scan;
        regnode *first_next= regnext(first);
        int i;

	
	while ((OP(first) == OPEN && (sawopen = 1)) ||  (OP(first) == BRANCH && OP(first_next) != BRANCH) ||  (OP(first) == IFMATCH && !first->flags && (sawlookahead = 1)) || (OP(first) == PLUS) || (OP(first) == MINMOD) ||  (PL_regkind[OP(first)] == CURLY && ARG1(first) > 0) || (OP(first) == NOTHING && PL_regkind[OP(first_next)] != END ))








	{
		
		if (OP(first) == PLUS)
		    sawplus = 1;
                else {
                    if (OP(first) == MINMOD)
                        sawminmod = 1;
		    first += regarglen[OP(first)];
                }
		first = NEXTOPER(first);
		first_next= regnext(first);
	}

	
      again:
        DEBUG_PEEP("first:", first, 0, 0);
        
	if (PL_regkind[OP(first)] == EXACT) {
	    if (   OP(first) == EXACT || OP(first) == EXACT_ONLY8 || OP(first) == EXACTL)

            {
		NOOP;	
            }
	    else RExC_rxi->regstclass = first;
	}

	else if (PL_regkind[OP(first)] == TRIE && ((reg_trie_data *)RExC_rxi->data->data[ ARG(first) ])->minlen>0)
	{
            
            RExC_rxi->regstclass = construct_ahocorasick_from_trie(pRExC_state, (regnode *)first, 0);
	}

	else if (REGNODE_SIMPLE(OP(first)))
	    RExC_rxi->regstclass = first;
	else if (PL_regkind[OP(first)] == BOUND || PL_regkind[OP(first)] == NBOUND)
	    RExC_rxi->regstclass = first;
	else if (PL_regkind[OP(first)] == BOL) {
            RExC_rx->intflags |= (OP(first) == MBOL ? PREGf_ANCH_MBOL : PREGf_ANCH_SBOL);

	    first = NEXTOPER(first);
	    goto again;
	}
	else if (OP(first) == GPOS) {
            RExC_rx->intflags |= PREGf_ANCH_GPOS;
	    first = NEXTOPER(first);
	    goto again;
	}
	else if ((!sawopen || !RExC_sawback) && !sawlookahead && (OP(first) == STAR && PL_regkind[OP(NEXTOPER(first))] == REG_ANY) && !(RExC_rx->intflags & PREGf_ANCH) && !pRExC_state->code_blocks)



	{
	    
	    const int type = (OP(NEXTOPER(first)) == REG_ANY)
                    ? PREGf_ANCH_MBOL : PREGf_ANCH_SBOL;
            RExC_rx->intflags |= (type | PREGf_IMPLICIT);
	    first = NEXTOPER(first);
	    goto again;
	}
        if (sawplus && !sawminmod && !sawlookahead && (!sawopen || !RExC_sawback)
	    && !pRExC_state->code_blocks) 
	    
	    RExC_rx->intflags |= PREGf_SKIP;

	

	DEBUG_PARSE_r( if (!restudied)
                Perl_re_printf( aTHX_  "first at %" IVdf "\n", (IV)(first - scan + 1))
        );

	DEBUG_PARSE_r( Perl_re_printf( aTHX_  "first at %" IVdf "\n", (IV)(first - scan + 1))

        );



	

	data.substrs[0].str = newSVpvs("");
	data.substrs[1].str = newSVpvs("");
	data.last_found = newSVpvs("");
	data.cur_is_floating = 0; 
	ENTER_with_name("study_chunk");
	SAVEFREESV(data.substrs[0].str);
	SAVEFREESV(data.substrs[1].str);
	SAVEFREESV(data.last_found);
	first = scan;
	if (!RExC_rxi->regstclass) {
	    ssc_init(pRExC_state, &ch_class);
	    data.start_class = &ch_class;
	    stclass_flag = SCF_DO_STCLASS_AND;
	} else				 stclass_flag = 0;
	data.last_closep = &last_close;

        DEBUG_RExC_seen();
        
	minlen = study_chunk(pRExC_state, &first, &minlen, &fake, scan + RExC_size, &data, -1, 0, NULL, SCF_DO_SUBSTR | SCF_WHILEM_VISITED_POS | stclass_flag | (restudied ? SCF_TRIE_DOING_RESTUDY : 0), 0);






        CHECK_RESTUDY_GOTO_butfirst(LEAVE_with_name("study_chunk"));


	if ( RExC_total_parens == 1 && !data.cur_is_floating && data.last_start_min == 0 && data.last_end > 0 && !RExC_seen_zerolen && !(RExC_seen & REG_VERBARG_SEEN)


             && !(RExC_seen & REG_GPOS_SEEN)
        ){
	    RExC_rx->extflags |= RXf_CHECK_ALL;
        }
	scan_commit(pRExC_state, &data,&minlen, 0);


        
        for (i = 1; i >= 0; i--) {
            longest_length[i] = CHR_SVLEN(data.substrs[i].str);

            if (   !(   i && SvCUR(data.substrs[0].str)
                     &&    data.substrs[0].min_offset == data.substrs[1].min_offset &&    SvCUR(data.substrs[0].str)

                        == SvCUR(data.substrs[1].str)
                    )
                && S_setup_longest (aTHX_ pRExC_state, &(RExC_rx->substrs->data[i]), &(data.substrs[i]), longest_length[i]))


            {
                RExC_rx->substrs->data[i].min_offset = data.substrs[i].min_offset - data.substrs[i].lookbehind;

                RExC_rx->substrs->data[i].max_offset = data.substrs[i].max_offset;
                
                if (data.substrs[i].max_offset < SSize_t_MAX)
                    RExC_rx->substrs->data[i].max_offset -= data.substrs[i].lookbehind;
                SvREFCNT_inc_simple_void_NN(data.substrs[i].str);
            }
            else {
                RExC_rx->substrs->data[i].substr      = NULL;
                RExC_rx->substrs->data[i].utf8_substr = NULL;
                longest_length[i] = 0;
            }
        }

	LEAVE_with_name("study_chunk");

	if (RExC_rxi->regstclass && (OP(RExC_rxi->regstclass) == REG_ANY || OP(RExC_rxi->regstclass) == SANY))
	    RExC_rxi->regstclass = NULL;

	if ((!(RExC_rx->substrs->data[0].substr || RExC_rx->substrs->data[0].utf8_substr)
              || RExC_rx->substrs->data[0].min_offset)
	    && stclass_flag && ! (ANYOF_FLAGS(data.start_class) & SSC_MATCHES_EMPTY_STRING)
	    && is_ssc_worth_it(pRExC_state, data.start_class))
	{
	    const U32 n = add_data(pRExC_state, STR_WITH_LEN("f"));

            ssc_finalize(pRExC_state, data.start_class);

	    Newx(RExC_rxi->data->data[n], 1, regnode_ssc);
	    StructCopy(data.start_class, (regnode_ssc*)RExC_rxi->data->data[n], regnode_ssc);

	    RExC_rxi->regstclass = (regnode*)RExC_rxi->data->data[n];
	    RExC_rx->intflags &= ~PREGf_SKIP;	
	    DEBUG_COMPILE_r({ SV *sv = sv_newmortal();
                      regprop(RExC_rx, sv, (regnode*)data.start_class, NULL, pRExC_state);
                      Perl_re_printf( aTHX_ "synthetic stclass \"%s\".\n", SvPVX_const(sv));});

            data.start_class = NULL;
	}

        
	i = (longest_length[0] <= longest_length[1]);
        RExC_rx->substrs->check_ix = i;
        RExC_rx->check_end_shift  = RExC_rx->substrs->data[i].end_shift;
        RExC_rx->check_substr     = RExC_rx->substrs->data[i].substr;
        RExC_rx->check_utf8       = RExC_rx->substrs->data[i].utf8_substr;
        RExC_rx->check_offset_min = RExC_rx->substrs->data[i].min_offset;
        RExC_rx->check_offset_max = RExC_rx->substrs->data[i].max_offset;
        if (!i && (RExC_rx->intflags & (PREGf_ANCH_SBOL|PREGf_ANCH_GPOS)))
            RExC_rx->intflags |= PREGf_NOSCAN;

	if ((RExC_rx->check_substr || RExC_rx->check_utf8) ) {
	    RExC_rx->extflags |= RXf_USE_INTUIT;
	    if (SvTAIL(RExC_rx->check_substr ? RExC_rx->check_substr : RExC_rx->check_utf8))
		RExC_rx->extflags |= RXf_INTUIT_TAIL;
	}

	
    }
    else {
	
	SSize_t fake;
	regnode_ssc ch_class;
	SSize_t last_close = 0;

        DEBUG_PARSE_r(Perl_re_printf( aTHX_  "\nMulti Top Level\n"));

	scan = RExC_rxi->program + 1;
	ssc_init(pRExC_state, &ch_class);
	data.start_class = &ch_class;
	data.last_closep = &last_close;

        DEBUG_RExC_seen();
        
	minlen = study_chunk(pRExC_state, &scan, &minlen, &fake, scan + RExC_size, &data, -1, 0, NULL, SCF_DO_STCLASS_AND|SCF_WHILEM_VISITED_POS|(restudied ? SCF_TRIE_DOING_RESTUDY : 0), 0);





        CHECK_RESTUDY_GOTO_butfirst(NOOP);

	RExC_rx->check_substr = NULL;
        RExC_rx->check_utf8 = NULL;
        RExC_rx->substrs->data[0].substr      = NULL;
        RExC_rx->substrs->data[0].utf8_substr = NULL;
        RExC_rx->substrs->data[1].substr      = NULL;
        RExC_rx->substrs->data[1].utf8_substr = NULL;

        if (! (ANYOF_FLAGS(data.start_class) & SSC_MATCHES_EMPTY_STRING)
	    && is_ssc_worth_it(pRExC_state, data.start_class))
        {
	    const U32 n = add_data(pRExC_state, STR_WITH_LEN("f"));

            ssc_finalize(pRExC_state, data.start_class);

	    Newx(RExC_rxi->data->data[n], 1, regnode_ssc);
	    StructCopy(data.start_class, (regnode_ssc*)RExC_rxi->data->data[n], regnode_ssc);

	    RExC_rxi->regstclass = (regnode*)RExC_rxi->data->data[n];
	    RExC_rx->intflags &= ~PREGf_SKIP;	
	    DEBUG_COMPILE_r({ SV* sv = sv_newmortal();
                      regprop(RExC_rx, sv, (regnode*)data.start_class, NULL, pRExC_state);
                      Perl_re_printf( aTHX_ "synthetic stclass \"%s\".\n", SvPVX_const(sv));});

            data.start_class = NULL;
	}
    }

    if (RExC_seen & REG_UNBOUNDED_QUANTIFIER_SEEN) {
        RExC_rx->extflags |= RXf_UNBOUNDED_QUANTIFIER_SEEN;
        RExC_rx->maxlen = REG_INFTY;
    }
    else {
        RExC_rx->maxlen = RExC_maxlen;
    }

    
    DEBUG_OPTIMISE_r({
        Perl_re_printf( aTHX_ "minlen: %" IVdf " RExC_rx->minlen:%" IVdf " maxlen:%" IVdf "\n", (IV)minlen, (IV)RExC_rx->minlen, (IV)RExC_maxlen);
    });
    RExC_rx->minlenret = minlen;
    if (RExC_rx->minlen < minlen)
        RExC_rx->minlen = minlen;

    if (RExC_seen & REG_RECURSE_SEEN ) {
        RExC_rx->intflags |= PREGf_RECURSE_SEEN;
        Newx(RExC_rx->recurse_locinput, RExC_rx->nparens + 1, char *);
    }
    if (RExC_seen & REG_GPOS_SEEN)
        RExC_rx->intflags |= PREGf_GPOS_SEEN;
    if (RExC_seen & REG_LOOKBEHIND_SEEN)
        RExC_rx->extflags |= RXf_NO_INPLACE_SUBST; 
    if (pRExC_state->code_blocks)
	RExC_rx->extflags |= RXf_EVAL_SEEN;
    if (RExC_seen & REG_VERBARG_SEEN)
    {
	RExC_rx->intflags |= PREGf_VERBARG_SEEN;
        RExC_rx->extflags |= RXf_NO_INPLACE_SUBST; 
    }
    if (RExC_seen & REG_CUTGROUP_SEEN)
	RExC_rx->intflags |= PREGf_CUTGROUP_SEEN;
    if (pm_flags & PMf_USE_RE_EVAL)
	RExC_rx->intflags |= PREGf_USE_RE_EVAL;
    if (RExC_paren_names)
        RXp_PAREN_NAMES(RExC_rx) = MUTABLE_HV(SvREFCNT_inc(RExC_paren_names));
    else RXp_PAREN_NAMES(RExC_rx) = NULL;

    
    if (RExC_rx->intflags & PREGf_ANCH)
        RExC_rx->extflags |= RXf_IS_ANCHORED;


    {
        
        regnode *first = RExC_rxi->program + 1;
        U8 fop = OP(first);
        regnode *next = regnext(first);
        U8 nop = OP(next);

        if (PL_regkind[fop] == NOTHING && nop == END)
            RExC_rx->extflags |= RXf_NULL;
        else if ((fop == MBOL || (fop == SBOL && !first->flags)) && nop == END)
            
            RExC_rx->extflags |= RXf_START_ONLY;
        else if (fop == PLUS && PL_regkind[nop] == POSIXD && FLAGS(next) == _CC_SPACE && nop == END)

            RExC_rx->extflags |= RXf_WHITE;
        else if ( RExC_rx->extflags & RXf_SPLIT && (fop == EXACT || fop == EXACT_ONLY8 || fop == EXACTL)
                  && STR_LEN(first) == 1 && *(STRING(first)) == ' ' && nop == END )

            RExC_rx->extflags |= (RXf_SKIPWHITE|RXf_WHITE);

    }

    if (RExC_contains_locale) {
        RXp_EXTFLAGS(RExC_rx) |= RXf_TAINTED;
    }


    if (RExC_paren_names) {
        RExC_rxi->name_list_idx = add_data( pRExC_state, STR_WITH_LEN("a"));
        RExC_rxi->data->data[RExC_rxi->name_list_idx] = (void*)SvREFCNT_inc(RExC_paren_name_list);
    } else  RExC_rxi->name_list_idx = 0;


    while ( RExC_recurse_count > 0 ) {
        const regnode *scan = RExC_recurse[ --RExC_recurse_count ];
        
        assert(scan && OP(scan) == GOSUB);
        ARG2L_SET( scan, RExC_open_parens[ARG(scan)] - REGNODE_OFFSET(scan));
    }

    Newxz(RExC_rx->offs, RExC_total_parens, regexp_paren_pair);
    
    DEBUG_TEST_r({
        Perl_re_printf( aTHX_ "study_chunk_recursed_count: %lu\n", (unsigned long)RExC_study_chunk_recursed_count);
    });
    DEBUG_DUMP_r({
        DEBUG_RExC_seen();
        Perl_re_printf( aTHX_ "Final program:\n");
        regdump(RExC_rx);
    });

    if (RExC_open_parens) {
        Safefree(RExC_open_parens);
        RExC_open_parens = NULL;
    }
    if (RExC_close_parens) {
        Safefree(RExC_close_parens);
        RExC_close_parens = NULL;
    }


    
    if (old_re && SvREADONLY(old_re))
        SvREADONLY_on(Rx);

    return Rx;
}


SV* Perl_reg_named_buff(pTHX_ REGEXP * const rx, SV * const key, SV * const value, const U32 flags)

{
    PERL_ARGS_ASSERT_REG_NAMED_BUFF;

    PERL_UNUSED_ARG(value);

    if (flags & RXapif_FETCH) {
        return reg_named_buff_fetch(rx, key, flags);
    } else if (flags & (RXapif_STORE | RXapif_DELETE | RXapif_CLEAR)) {
        Perl_croak_no_modify();
        return NULL;
    } else if (flags & RXapif_EXISTS) {
        return reg_named_buff_exists(rx, key, flags)
            ? &PL_sv_yes : &PL_sv_no;
    } else if (flags & RXapif_REGNAMES) {
        return reg_named_buff_all(rx, flags);
    } else if (flags & (RXapif_SCALAR | RXapif_REGNAMES_COUNT)) {
        return reg_named_buff_scalar(rx, flags);
    } else {
        Perl_croak(aTHX_ "panic: Unknown flags %d in named_buff", (int)flags);
        return NULL;
    }
}

SV* Perl_reg_named_buff_iter(pTHX_ REGEXP * const rx, const SV * const lastkey, const U32 flags)

{
    PERL_ARGS_ASSERT_REG_NAMED_BUFF_ITER;
    PERL_UNUSED_ARG(lastkey);

    if (flags & RXapif_FIRSTKEY)
        return reg_named_buff_firstkey(rx, flags);
    else if (flags & RXapif_NEXTKEY)
        return reg_named_buff_nextkey(rx, flags);
    else {
        Perl_croak(aTHX_ "panic: Unknown flags %d in named_buff_iter", (int)flags);
        return NULL;
    }
}

SV* Perl_reg_named_buff_fetch(pTHX_ REGEXP * const r, SV * const namesv, const U32 flags)

{
    SV *ret;
    struct regexp *const rx = ReANY(r);

    PERL_ARGS_ASSERT_REG_NAMED_BUFF_FETCH;

    if (rx && RXp_PAREN_NAMES(rx)) {
        HE *he_str = hv_fetch_ent( RXp_PAREN_NAMES(rx), namesv, 0, 0 );
        if (he_str) {
            IV i;
            SV* sv_dat=HeVAL(he_str);
            I32 *nums=(I32*)SvPVX(sv_dat);
            AV * const retarray = (flags & RXapif_ALL) ? newAV() : NULL;
            for ( i=0; i<SvIVX(sv_dat); i++ ) {
                if ((I32)(rx->nparens) >= nums[i] && rx->offs[nums[i]].start != -1 && rx->offs[nums[i]].end != -1)

                {
                    ret = newSVpvs("");
                    CALLREG_NUMBUF_FETCH(r, nums[i], ret);
                    if (!retarray)
                        return ret;
                } else {
                    if (retarray)
                        ret = newSVsv(&PL_sv_undef);
                }
                if (retarray)
                    av_push(retarray, ret);
            }
            if (retarray)
                return newRV_noinc(MUTABLE_SV(retarray));
        }
    }
    return NULL;
}

bool Perl_reg_named_buff_exists(pTHX_ REGEXP * const r, SV * const key, const U32 flags)

{
    struct regexp *const rx = ReANY(r);

    PERL_ARGS_ASSERT_REG_NAMED_BUFF_EXISTS;

    if (rx && RXp_PAREN_NAMES(rx)) {
        if (flags & RXapif_ALL) {
            return hv_exists_ent(RXp_PAREN_NAMES(rx), key, 0);
        } else {
	    SV *sv = CALLREG_NAMED_BUFF_FETCH(r, key, flags);
            if (sv) {
		SvREFCNT_dec_NN(sv);
                return TRUE;
            } else {
                return FALSE;
            }
        }
    } else {
        return FALSE;
    }
}

SV* Perl_reg_named_buff_firstkey(pTHX_ REGEXP * const r, const U32 flags)
{
    struct regexp *const rx = ReANY(r);

    PERL_ARGS_ASSERT_REG_NAMED_BUFF_FIRSTKEY;

    if ( rx && RXp_PAREN_NAMES(rx) ) {
	(void)hv_iterinit(RXp_PAREN_NAMES(rx));

	return CALLREG_NAMED_BUFF_NEXTKEY(r, NULL, flags & ~RXapif_FIRSTKEY);
    } else {
	return FALSE;
    }
}

SV* Perl_reg_named_buff_nextkey(pTHX_ REGEXP * const r, const U32 flags)
{
    struct regexp *const rx = ReANY(r);
    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_REG_NAMED_BUFF_NEXTKEY;

    if (rx && RXp_PAREN_NAMES(rx)) {
        HV *hv = RXp_PAREN_NAMES(rx);
        HE *temphe;
        while ( (temphe = hv_iternext_flags(hv, 0)) ) {
            IV i;
            IV parno = 0;
            SV* sv_dat = HeVAL(temphe);
            I32 *nums = (I32*)SvPVX(sv_dat);
            for ( i = 0; i < SvIVX(sv_dat); i++ ) {
                if ((I32)(rx->lastparen) >= nums[i] && rx->offs[nums[i]].start != -1 && rx->offs[nums[i]].end != -1)

                {
                    parno = nums[i];
                    break;
                }
            }
            if (parno || flags & RXapif_ALL) {
		return newSVhek(HeKEY_hek(temphe));
            }
        }
    }
    return NULL;
}

SV* Perl_reg_named_buff_scalar(pTHX_ REGEXP * const r, const U32 flags)
{
    SV *ret;
    AV *av;
    SSize_t length;
    struct regexp *const rx = ReANY(r);

    PERL_ARGS_ASSERT_REG_NAMED_BUFF_SCALAR;

    if (rx && RXp_PAREN_NAMES(rx)) {
        if (flags & (RXapif_ALL | RXapif_REGNAMES_COUNT)) {
            return newSViv(HvTOTALKEYS(RXp_PAREN_NAMES(rx)));
        } else if (flags & RXapif_ONE) {
            ret = CALLREG_NAMED_BUFF_ALL(r, (flags | RXapif_REGNAMES));
            av = MUTABLE_AV(SvRV(ret));
            length = av_tindex(av);
	    SvREFCNT_dec_NN(ret);
            return newSViv(length + 1);
        } else {
            Perl_croak(aTHX_ "panic: Unknown flags %d in named_buff_scalar", (int)flags);
            return NULL;
        }
    }
    return &PL_sv_undef;
}

SV* Perl_reg_named_buff_all(pTHX_ REGEXP * const r, const U32 flags)
{
    struct regexp *const rx = ReANY(r);
    AV *av = newAV();

    PERL_ARGS_ASSERT_REG_NAMED_BUFF_ALL;

    if (rx && RXp_PAREN_NAMES(rx)) {
        HV *hv= RXp_PAREN_NAMES(rx);
        HE *temphe;
        (void)hv_iterinit(hv);
        while ( (temphe = hv_iternext_flags(hv, 0)) ) {
            IV i;
            IV parno = 0;
            SV* sv_dat = HeVAL(temphe);
            I32 *nums = (I32*)SvPVX(sv_dat);
            for ( i = 0; i < SvIVX(sv_dat); i++ ) {
                if ((I32)(rx->lastparen) >= nums[i] && rx->offs[nums[i]].start != -1 && rx->offs[nums[i]].end != -1)

                {
                    parno = nums[i];
                    break;
                }
            }
            if (parno || flags & RXapif_ALL) {
                av_push(av, newSVhek(HeKEY_hek(temphe)));
            }
        }
    }

    return newRV_noinc(MUTABLE_SV(av));
}

void Perl_reg_numbered_buff_fetch(pTHX_ REGEXP * const r, const I32 paren, SV * const sv)

{
    struct regexp *const rx = ReANY(r);
    char *s = NULL;
    SSize_t i = 0;
    SSize_t s1, t1;
    I32 n = paren;

    PERL_ARGS_ASSERT_REG_NUMBERED_BUFF_FETCH;

    if (      n == RX_BUFF_IDX_CARET_PREMATCH || n == RX_BUFF_IDX_CARET_FULLMATCH || n == RX_BUFF_IDX_CARET_POSTMATCH )


    {
        bool keepcopy = cBOOL(rx->extflags & RXf_PMf_KEEPCOPY);
        if (!keepcopy) {
            
            if (PL_curpm && r == PM_GETRE(PL_curpm))
                 keepcopy = cBOOL(PL_curpm->op_pmflags & PMf_KEEPCOPY);
        }
        if (!keepcopy)
            goto ret_undef;
    }

    if (!rx->subbeg)
        goto ret_undef;

    if (n == RX_BUFF_IDX_CARET_FULLMATCH)
        
        n = RX_BUFF_IDX_FULLMATCH;

    if ((n == RX_BUFF_IDX_PREMATCH || n == RX_BUFF_IDX_CARET_PREMATCH)
        && rx->offs[0].start != -1)
    {
        
	i = rx->offs[0].start;
	s = rx->subbeg;
    }
    else if ((n == RX_BUFF_IDX_POSTMATCH || n == RX_BUFF_IDX_CARET_POSTMATCH)
        && rx->offs[0].end != -1)
    {
        
	s = rx->subbeg - rx->suboffset + rx->offs[0].end;
	i = rx->sublen + rx->suboffset - rx->offs[0].end;
    }
    else if ( 0 <= n && n <= (I32)rx->nparens && (s1 = rx->offs[n].start) != -1 && (t1 = rx->offs[n].end) != -1)


    {
        
        i = t1 - s1;
        s = rx->subbeg + s1 - rx->suboffset;
    } else {
        goto ret_undef;
    }

    assert(s >= rx->subbeg);
    assert((STRLEN)rx->sublen >= (STRLEN)((s - rx->subbeg) + i) );
    if (i >= 0) {

        sv_setpvn(sv, s, i);

        const int oldtainted = TAINT_get;
        TAINT_NOT;
        sv_setpvn(sv, s, i);
        TAINT_set(oldtainted);

        if (RXp_MATCH_UTF8(rx))
            SvUTF8_on(sv);
        else SvUTF8_off(sv);
        if (TAINTING_get) {
            if (RXp_MATCH_TAINTED(rx)) {
                if (SvTYPE(sv) >= SVt_PVMG) {
                    MAGIC* const mg = SvMAGIC(sv);
                    MAGIC* mgt;
                    TAINT;
                    SvMAGIC_set(sv, mg->mg_moremagic);
                    SvTAINT(sv);
                    if ((mgt = SvMAGIC(sv))) {
                        mg->mg_moremagic = mgt;
                        SvMAGIC_set(sv, mg);
                    }
                } else {
                    TAINT;
                    SvTAINT(sv);
                }
            } else SvTAINTED_off(sv);
        }
    } else {
      ret_undef:
        sv_set_undef(sv);
        return;
    }
}

void Perl_reg_numbered_buff_store(pTHX_ REGEXP * const rx, const I32 paren, SV const * const value)

{
    PERL_ARGS_ASSERT_REG_NUMBERED_BUFF_STORE;

    PERL_UNUSED_ARG(rx);
    PERL_UNUSED_ARG(paren);
    PERL_UNUSED_ARG(value);

    if (!PL_localizing)
        Perl_croak_no_modify();
}

I32 Perl_reg_numbered_buff_length(pTHX_ REGEXP * const r, const SV * const sv, const I32 paren)

{
    struct regexp *const rx = ReANY(r);
    I32 i;
    I32 s1, t1;

    PERL_ARGS_ASSERT_REG_NUMBERED_BUFF_LENGTH;

    if (   paren == RX_BUFF_IDX_CARET_PREMATCH || paren == RX_BUFF_IDX_CARET_FULLMATCH || paren == RX_BUFF_IDX_CARET_POSTMATCH )


    {
        bool keepcopy = cBOOL(rx->extflags & RXf_PMf_KEEPCOPY);
        if (!keepcopy) {
            
            if (PL_curpm && r == PM_GETRE(PL_curpm))
                 keepcopy = cBOOL(PL_curpm->op_pmflags & PMf_KEEPCOPY);
        }
        if (!keepcopy)
            goto warn_undef;
    }

    
    switch (paren) {
      case RX_BUFF_IDX_CARET_PREMATCH: 
      case RX_BUFF_IDX_PREMATCH:       
        if (rx->offs[0].start != -1) {
			i = rx->offs[0].start;
			if (i > 0) {
				s1 = 0;
				t1 = i;
				goto getlen;
			}
	    }
        return 0;

      case RX_BUFF_IDX_CARET_POSTMATCH: 
      case RX_BUFF_IDX_POSTMATCH:       
	    if (rx->offs[0].end != -1) {
			i = rx->sublen - rx->offs[0].end;
			if (i > 0) {
				s1 = rx->offs[0].end;
				t1 = rx->sublen;
				goto getlen;
			}
	    }
        return 0;

      default: 
	    if (paren <= (I32)rx->nparens && (s1 = rx->offs[paren].start) != -1 && (t1 = rx->offs[paren].end) != -1)

	    {
            i = t1 - s1;
            goto getlen;
        } else {
          warn_undef:
            if (ckWARN(WARN_UNINITIALIZED))
                report_uninit((const SV *)sv);
            return 0;
        }
    }
  getlen:
    if (i > 0 && RXp_MATCH_UTF8(rx)) {
        const char * const s = rx->subbeg - rx->suboffset + s1;
        const U8 *ep;
        STRLEN el;

        i = t1 - s1;
        if (is_utf8_string_loclen((U8*)s, i, &ep, &el))
			i = el;
    }
    return i;
}

SV* Perl_reg_qr_package(pTHX_ REGEXP * const rx)
{
    PERL_ARGS_ASSERT_REG_QR_PACKAGE;
	PERL_UNUSED_ARG(rx);
	if (0)
	    return NULL;
	else return newSVpvs("Regexp");
}







STATIC SV* S_reg_scan_name(pTHX_ RExC_state_t *pRExC_state, U32 flags)
{
    char *name_start = RExC_parse;
    SV* sv_name;

    PERL_ARGS_ASSERT_REG_SCAN_NAME;

    assert (RExC_parse <= RExC_end);
    if (RExC_parse == RExC_end) NOOP;
    else if (isIDFIRST_lazy_if_safe(RExC_parse, RExC_end, UTF)) {
         
	if (UTF)
	    do {
		RExC_parse += UTF8SKIP(RExC_parse);
	    } while (   RExC_parse < RExC_end && isWORDCHAR_utf8_safe((U8*)RExC_parse, (U8*) RExC_end));
	else do {
		RExC_parse++;
	    } while (RExC_parse < RExC_end && isWORDCHAR(*RExC_parse));
    } else {
        RExC_parse++; 
        vFAIL("Group name must start with a non-digit word character");
    }
    sv_name = newSVpvn_flags(name_start, (int)(RExC_parse - name_start), SVs_TEMP | (UTF ? SVf_UTF8 : 0));
    if ( flags == REG_RSN_RETURN_NAME)
        return sv_name;
    else if (flags==REG_RSN_RETURN_DATA) {
        HE *he_str = NULL;
        SV *sv_dat = NULL;
        if ( ! sv_name )      
            Perl_croak(aTHX_ "panic: no svname in reg_scan_name");
        if (RExC_paren_names)
            he_str = hv_fetch_ent( RExC_paren_names, sv_name, 0, 0 );
        if ( he_str )
            sv_dat = HeVAL(he_str);
        if ( ! sv_dat ) {   

            
            if (ALL_PARENS_COUNTED)  {
                vFAIL("Reference to nonexistent named group");
            }
            else {
                REQUIRE_PARENS_PASS;
            }
        }
        return sv_dat;
    }

    Perl_croak(aTHX_ "panic: bad flag %lx in reg_scan_name", (unsigned long) flags);
}











































PERL_STATIC_INLINE UV* S__invlist_array_init(SV* const invlist, const bool will_have_0)
{
    

    bool* offset = get_invlist_offset_addr(invlist);
    UV* zero_addr = (UV *) SvPVX(invlist);

    PERL_ARGS_ASSERT__INVLIST_ARRAY_INIT;

    
    assert(! _invlist_len(invlist));

    *zero_addr = 0;

    
    *offset = 1 ^ will_have_0;
    return zero_addr + *offset;
}

PERL_STATIC_INLINE void S_invlist_set_len(pTHX_ SV* const invlist, const UV len, const bool offset)
{
    
    PERL_UNUSED_CONTEXT;
    PERL_ARGS_ASSERT_INVLIST_SET_LEN;

    assert(is_invlist(invlist));

    SvCUR_set(invlist, (len == 0)
               ? 0 : TO_INTERNAL_SIZE(len + offset));
    assert(SvLEN(invlist) == 0 || SvCUR(invlist) <= SvLEN(invlist));
}

STATIC void S_invlist_replace_list_destroys_src(pTHX_ SV * dest, SV * src)
{
    

    const UV src_len          = _invlist_len(src);
    const bool src_offset     = *get_invlist_offset_addr(src);
    const STRLEN src_byte_len = SvLEN(src);
    char * array              = SvPVX(src);

    const int oldtainted = TAINT_get;

    PERL_ARGS_ASSERT_INVLIST_REPLACE_LIST_DESTROYS_SRC;

    assert(is_invlist(src));
    assert(is_invlist(dest));
    assert(! invlist_is_iterating(src));
    assert(SvCUR(src) == 0 || SvCUR(src) < SvLEN(src));

    
    array[src_byte_len - 1] = '\0';

    TAINT_NOT;      
    sv_usepvn_flags(dest, (char *) array, src_byte_len - 1,   SV_HAS_TRAILING_NUL);




    TAINT_set(oldtainted);
    SvPV_set(src, 0);
    SvLEN_set(src, 0);
    SvCUR_set(src, 0);

    
    *get_invlist_offset_addr(dest) = src_offset;
    invlist_set_len(dest, src_len, src_offset);
    *get_invlist_previous_index_addr(dest) = 0;
    invlist_iterfinish(dest);
}

PERL_STATIC_INLINE IV* S_get_invlist_previous_index_addr(SV* invlist)
{
    
    PERL_ARGS_ASSERT_GET_INVLIST_PREVIOUS_INDEX_ADDR;

    assert(is_invlist(invlist));

    return &(((XINVLIST*) SvANY(invlist))->prev_index);
}

PERL_STATIC_INLINE IV S_invlist_previous_index(SV* const invlist)
{
    

    PERL_ARGS_ASSERT_INVLIST_PREVIOUS_INDEX;

    return *get_invlist_previous_index_addr(invlist);
}

PERL_STATIC_INLINE void S_invlist_set_previous_index(SV* const invlist, const IV index)
{
    

    PERL_ARGS_ASSERT_INVLIST_SET_PREVIOUS_INDEX;

    assert(index == 0 || index < (int) _invlist_len(invlist));

    *get_invlist_previous_index_addr(invlist) = index;
}

PERL_STATIC_INLINE void S_invlist_trim(SV* invlist)
{
    

    
    const UV min_size = TO_INTERNAL_SIZE(1) + 1;

    PERL_ARGS_ASSERT_INVLIST_TRIM;

    assert(is_invlist(invlist));

    SvPV_renew(invlist, MAX(min_size, SvCUR(invlist) + 1));
}

PERL_STATIC_INLINE void S_invlist_clear(pTHX_ SV* invlist)
{
    PERL_ARGS_ASSERT_INVLIST_CLEAR;

    assert(is_invlist(invlist));

    invlist_set_len(invlist, 0, 0);
    invlist_trim(invlist);
}



PERL_STATIC_INLINE bool S_invlist_is_iterating(SV* const invlist)
{
    PERL_ARGS_ASSERT_INVLIST_IS_ITERATING;

    return *(get_invlist_iter_addr(invlist)) < (STRLEN) UV_MAX;
}



PERL_STATIC_INLINE UV S_invlist_max(SV* const invlist)
{
    

    PERL_ARGS_ASSERT_INVLIST_MAX;

    assert(is_invlist(invlist));

    
    return SvLEN(invlist) == 0   ? FROM_INTERNAL_SIZE(SvCUR(invlist)) - 1 : FROM_INTERNAL_SIZE(SvLEN(invlist)) - 1;

}

STATIC void S_initialize_invlist_guts(pTHX_ SV* invlist, const Size_t initial_size)
{
    PERL_ARGS_ASSERT_INITIALIZE_INVLIST_GUTS;

    
    SvGROW(invlist, TO_INTERNAL_SIZE(initial_size + 1) + 1);
    invlist_set_len(invlist, 0, 0);

    
    invlist_iterfinish(invlist);

    *get_invlist_previous_index_addr(invlist) = 0;
}

SV* Perl__new_invlist(pTHX_ IV initial_size)
{

    

    SV* new_list;

    if (initial_size < 0) {
	initial_size = 10;
    }

    new_list = newSV_type(SVt_INVLIST);
    initialize_invlist_guts(new_list, initial_size);

    return new_list;
}

SV* Perl__new_invlist_C_array(pTHX_ const UV* const list)
{
    

    const STRLEN length = (STRLEN) list[0];
    const UV version_id =          list[1];
    const bool offset   =    cBOOL(list[2]);

    


    SV* invlist = newSV_type(SVt_INVLIST);

    PERL_ARGS_ASSERT__NEW_INVLIST_C_ARRAY;

    if (version_id != INVLIST_VERSION_ID) {
        Perl_croak(aTHX_ "panic: Incorrect version for previously generated inversion list");
    }

    
    SvPV_set(invlist, (char *) (list + HEADER_LENGTH));

    SvLEN_set(invlist, 0);  

    *(get_invlist_offset_addr(invlist)) = offset;

    
    invlist_set_len(invlist, length  - offset, offset);

    invlist_set_previous_index(invlist, 0);

    
    invlist_iterfinish(invlist);

    SvREADONLY_on(invlist);

    return invlist;
}

STATIC void S_invlist_extend(pTHX_ SV* const invlist, const UV new_max)
{
    

    PERL_ARGS_ASSERT_INVLIST_EXTEND;

    assert(is_invlist(invlist));

    
    SvGROW((SV *)invlist, TO_INTERNAL_SIZE(new_max + 1));
}

STATIC void S__append_range_to_invlist(pTHX_ SV* const invlist, const UV start, const UV end)

{
   

    UV* array;
    UV max = invlist_max(invlist);
    UV len = _invlist_len(invlist);
    bool offset;

    PERL_ARGS_ASSERT__APPEND_RANGE_TO_INVLIST;

    if (len == 0) { 
        offset = start != 0;
        array = _invlist_array_init(invlist, ! offset);
    }
    else {
	

	UV final_element = len - 1;
	array = invlist_array(invlist);
	if (   array[final_element] > start || ELEMENT_RANGE_MATCHES_INVLIST(final_element))
	{
	    Perl_croak(aTHX_ "panic: attempting to append to an inversion list, but wasn't at the end of the list, final=%" UVuf ", start=%" UVuf ", match=%c", array[final_element], start, ELEMENT_RANGE_MATCHES_INVLIST(final_element) ? 't' : 'f');

	}

        
        offset = *get_invlist_offset_addr(invlist);
	if (array[final_element] == start) {
	    if (end != UV_MAX) {
		array[final_element] = end + 1;
	    }
	    else {
		
		invlist_set_len(invlist, len - 1, offset);
	    }
	    return;
	}
    }

    

    len += 2;	

    
    if (max < len) {
	invlist_extend(invlist, len);

        
        invlist_set_len(invlist, len, offset);

	array = invlist_array(invlist);
    }
    else {
	invlist_set_len(invlist, len, offset);
    }

    
    array[len - 2] = start;
    if (end != UV_MAX) {
	array[len - 1] = end + 1;
    }
    else {
	
	invlist_set_len(invlist, len - 1, offset);
    }
}

SSize_t Perl__invlist_search(SV* const invlist, const UV cp)
{
    

    IV low = 0;
    IV mid;
    IV high = _invlist_len(invlist);
    const IV highest_element = high - 1;
    const UV* array;

    PERL_ARGS_ASSERT__INVLIST_SEARCH;

    
    if (high == 0) {
	return -1;
    }

    
    array = invlist_array(invlist);

    mid = invlist_previous_index(invlist);
    assert(mid >=0);
    if (mid > highest_element) {
        mid = highest_element;
    }

    
    if (cp >= array[mid]) {
        if (cp >= array[highest_element]) {
            return highest_element;
        }

        
        if (cp < array[mid + 1]) {
            return mid;
        }
        high--;
        low = mid + 1;
    }
    else { 
        if (cp < array[0]) { 
            return -1;
        }
        high = mid;
        if (cp >= array[mid - 1]) {
            goto found_entry;
        }
    }

    
    while (low < high) {
	mid = (low + high) / 2;
        assert(mid <= highest_element);
	if (array[mid] <= cp) { 
	    low = mid + 1;

	    
	}
	else { 
	    high = mid;
	}
    }

  found_entry:
    high--;
    invlist_set_previous_index(invlist, high);
    return high;
}

void Perl__invlist_union_maybe_complement_2nd(pTHX_ SV* const a, SV* const b, const bool complement_b, SV** output)

{
    

    const UV* array_a;    
    const UV* array_b;
    UV len_a;	    
    UV len_b;

    SV* u;			
    UV* array_u;
    UV len_u = 0;

    UV i_a = 0;		    
    UV i_b = 0;
    UV i_u = 0;

    
    UV count = 0;

    PERL_ARGS_ASSERT__INVLIST_UNION_MAYBE_COMPLEMENT_2ND;
    assert(a != b);
    assert(*output == NULL || is_invlist(*output));

    len_b = _invlist_len(b);
    if (len_b == 0) {

        
        if (complement_b) {
            SV* everything = _add_range_to_invlist(NULL, 0, UV_MAX);

            if (*output == NULL) { 
                *output = everything;
            }
            else { 
                invlist_replace_list_destroys_src(*output, everything);
                SvREFCNT_dec_NN(everything);
            }

            return;
        }

        

        if (a == NULL || _invlist_len(a) == 0) {
            if (*output == NULL) {
                *output = _new_invlist(0);
            }
            else {
                invlist_clear(*output);
            }
            return;
        }

        
        if (*output == NULL) {
            *output = invlist_clone(a, NULL);
            return;
        }

        
        if (*output == a) {
            return;
        }

        
        u = invlist_clone(a, NULL);
        invlist_replace_list_destroys_src(*output, u);
        SvREFCNT_dec_NN(u);

        return;
    }

    

    if (a == NULL || ((len_a = _invlist_len(a)) == 0)) {

        

        SV ** dest = (*output == NULL) ? output : &u;
        *dest = invlist_clone(b, NULL);
        if (complement_b) {
            _invlist_invert(*dest);
        }

        if (dest == &u) {
            invlist_replace_list_destroys_src(*output, u);
            SvREFCNT_dec_NN(u);
        }

	return;
    }

    
    array_a = invlist_array(a);
    array_b = invlist_array(b);

    
    if (complement_b) {

	
        if (array_b[0] == 0) {
            array_b++;
            len_b--;
        }
        else {

            
            array_b--;
            len_b++;
        }
    }

    
    u = _new_invlist(len_a + len_b);

    
    array_u = _invlist_array_init(u, (    len_a > 0 && array_a[0] == 0)
                                      || (len_b > 0 && array_b[0] == 0));

    
    while (i_a < len_a && i_b < len_b) {
	UV cp;	    
	bool cp_in_set;   

	
	if (       array_a[i_a] < array_b[i_b] || (   array_a[i_a] == array_b[i_b] && ELEMENT_RANGE_MATCHES_INVLIST(i_a)))

	{
	    cp_in_set = ELEMENT_RANGE_MATCHES_INVLIST(i_a);
	    cp = array_a[i_a++];
	}
	else {
	    cp_in_set = ELEMENT_RANGE_MATCHES_INVLIST(i_b);
	    cp = array_b[i_b++];
	}

	
	if (cp_in_set) {
	    if (count == 0) {
		array_u[i_u++] = cp;
	    }
	    count++;
	}
	else {
	    count--;
	    if (count == 0) {
		array_u[i_u++] = cp;
	    }
	}
    }


    
    if (   (i_a != len_a && PREV_RANGE_MATCHES_INVLIST(i_a))
	|| (i_b != len_b && PREV_RANGE_MATCHES_INVLIST(i_b)))
    {
	count--;
    }

    
    if (count != 0) {
        len_u = i_u;
    }
    else {
        IV copy_count = len_a - i_a;
        if (copy_count > 0) {   
	    Copy(array_a + i_a, array_u + i_u, copy_count, UV);
        }
        else { 
            copy_count = len_b - i_b;
	    Copy(array_b + i_b, array_u + i_u, copy_count, UV);
        }
        len_u = i_u + copy_count;
    }

    
    if (len_u != _invlist_len(u)) {
	invlist_set_len(u, len_u, *get_invlist_offset_addr(u));
	invlist_trim(u);
	array_u = invlist_array(u);
    }

    if (*output == NULL) {  
        *output = u;
    }
    else {
        
        invlist_replace_list_destroys_src(*output, u);
        SvREFCNT_dec_NN(u);
    }

    return;
}

void Perl__invlist_intersection_maybe_complement_2nd(pTHX_ SV* const a, SV* const b, const bool complement_b, SV** i)

{
    

    const UV* array_a;		
    const UV* array_b;
    UV len_a;	
    UV len_b;

    SV* r;		     
    UV* array_r;
    UV len_r = 0;

    UV i_a = 0;		    
    UV i_b = 0;
    UV i_r = 0;

    
    UV count = 0;

    PERL_ARGS_ASSERT__INVLIST_INTERSECTION_MAYBE_COMPLEMENT_2ND;
    assert(a != b);
    assert(*i == NULL || is_invlist(*i));

    
    len_a = (a == NULL) ? 0 : _invlist_len(a);
    if ((len_a == 0) || ((len_b = _invlist_len(b)) == 0)) {
        if (len_a != 0 && complement_b) {

            

            if (*i == a) {  
                return;
            }

            if (*i == NULL) {
                *i = invlist_clone(a, NULL);
                return;
            }

            r = invlist_clone(a, NULL);
            invlist_replace_list_destroys_src(*i, r);
            SvREFCNT_dec_NN(r);
            return;
        }

        
        if (*i == NULL) {
            *i = _new_invlist(0);
            return;
        }

        invlist_clear(*i);
	return;
    }

    
    array_a = invlist_array(a);
    array_b = invlist_array(b);

    
    if (complement_b) {

	
        if (array_b[0] == 0) {
            array_b++;
            len_b--;
        }
        else {

            
            array_b--;
            len_b++;
        }
    }

    
    r= _new_invlist(len_a + len_b);

    
    array_r = _invlist_array_init(r,    len_a > 0 && array_a[0] == 0 && len_b > 0 && array_b[0] == 0);

    
    while (i_a < len_a && i_b < len_b) {
	UV cp;	    
	bool cp_in_set;	

	
	if (       array_a[i_a] < array_b[i_b] || (   array_a[i_a] == array_b[i_b] && ! ELEMENT_RANGE_MATCHES_INVLIST(i_a)))

	{
	    cp_in_set = ELEMENT_RANGE_MATCHES_INVLIST(i_a);
	    cp = array_a[i_a++];
	}
	else {
	    cp_in_set = ELEMENT_RANGE_MATCHES_INVLIST(i_b);
	    cp= array_b[i_b++];
	}

	
	if (cp_in_set) {
	    count++;
	    if (count == 2) {
		array_r[i_r++] = cp;
	    }
	}
	else {
	    if (count == 2) {
		array_r[i_r++] = cp;
	    }
	    count--;
	}

    }

    
    if (   (i_a == len_a && PREV_RANGE_MATCHES_INVLIST(i_a))
        || (i_b == len_b && PREV_RANGE_MATCHES_INVLIST(i_b)))
    {
	count++;
    }

    
    if (count < 2) { 
        len_r = i_r;
    }
    else { 
        IV copy_count = len_a - i_a;
        if (copy_count > 0) {   
	    Copy(array_a + i_a, array_r + i_r, copy_count, UV);
        }
        else {  
            copy_count = len_b - i_b;
	    Copy(array_b + i_b, array_r + i_r, copy_count, UV);
        }
        len_r = i_r + copy_count;
    }

    
    if (len_r != _invlist_len(r)) {
	invlist_set_len(r, len_r, *get_invlist_offset_addr(r));
	invlist_trim(r);
	array_r = invlist_array(r);
    }

    if (*i == NULL) { 
        *i = r;
    }
    else { 
        if (len_r) {
            invlist_replace_list_destroys_src(*i, r);
        }
        else {
            invlist_clear(*i);
        }
        SvREFCNT_dec_NN(r);
    }

    return;
}

SV* Perl__add_range_to_invlist(pTHX_ SV* invlist, UV start, UV end)
{
    

    UV* array;              
    UV len;                 
    SSize_t i_s;            
    SSize_t i_e = 0;        
    UV cur_highest;         

    
    if (invlist == NULL) {
	invlist = _new_invlist(2);
        _append_range_to_invlist(invlist, start, end);
        return invlist;
    }

    
    len = _invlist_len(invlist);
    if (len == 0) {
        _append_range_to_invlist(invlist, start, end);
        return invlist;
    }

    
    array = invlist_array(invlist);

    
    cur_highest = invlist_highest(invlist);
    if (end > cur_highest) {

        
        if (start > cur_highest) {
            _append_range_to_invlist(invlist, start, end);
            return invlist;
        }

        
        _append_range_to_invlist(invlist, cur_highest + 1, end);

        
        if (end == UV_MAX) {
            i_e = len;
        }
        else {
            i_e = len - 2;
        }
    }

    
    if (start < array[0]) {

        
        if (UNLIKELY(start == 0)) {
            SV* range_invlist;

            range_invlist = _new_invlist(2);
            _append_range_to_invlist(range_invlist, start, end);

            _invlist_union(invlist, range_invlist, &invlist);

            SvREFCNT_dec_NN(range_invlist);

            return invlist;
        }

        
        if (end < array[0] - 1) {
            i_s = i_e = -1;
            goto splice_in_new_range;
        }

        
        array[0] = start;

        
        i_s = 0;
    }
    else { 
        i_s = _invlist_search(invlist, start);
    }

    
    if (i_e == 0) {
        i_e = (start == end)
              ? i_s : _invlist_search(invlist, end);
    }

    

    if ( ! ELEMENT_RANGE_MATCHES_INVLIST(i_s)) {

        
        const bool extends_the_range_above = (   end == UV_MAX || end + 1 >= array[i_s+1]);

        
        if (start == array[i_s]) {

            
            if (i_e - i_s <= 1) {

                
                if (extends_the_range_above) {
                    Move(array + i_s + 2, array + i_s, len - i_s - 2, UV);
                    invlist_set_len(invlist, len - 2, *(get_invlist_offset_addr(invlist)));

                    return invlist;
                }

                
                i_e--;
            }

            
            array[i_s] = (end == UV_MAX) ? UV_MAX : end + 1;
            i_s--;
            start = array[i_s];
        }
        else if (extends_the_range_above) {

            
            if (i_e == i_s) {
                i_e++;
            }
            i_s++;
            array[i_s] = start;
        }
    }

    
    if (UNLIKELY(end == UV_MAX)) {
        invlist_set_len(invlist, i_s + 1, *(get_invlist_offset_addr(invlist)));
        return invlist;
    }

    
    if (! ELEMENT_RANGE_MATCHES_INVLIST(i_e)) {

        
        if (end + 1 == array[i_e+1]) {
            i_e++;
            array[i_e] = start;
        }
        else if (start <= array[i_e]) {
            array[i_e] = end + 1;
            i_e--;
        }
    }

    if (i_s == i_e) {

        
        if (ELEMENT_RANGE_MATCHES_INVLIST(i_s)) {
            return invlist;
        }

        
      splice_in_new_range:

        invlist_extend(invlist, len + 2);
        array = invlist_array(invlist);
        
        Move(array + i_e + 1, array + i_e + 3, len - i_e - 1, UV);

        
        array[i_e+1] = start;
        array[i_e+2] = end + 1;
        invlist_set_len(invlist, len + 2, *(get_invlist_offset_addr(invlist)));
        return invlist;
    }

    
    Move(array + i_e + 1, array + i_s + 1, len - i_e - 1, UV);
    invlist_set_len(invlist, len - i_e + i_s, *(get_invlist_offset_addr(invlist)));


    return invlist;
}

SV* Perl__setup_canned_invlist(pTHX_ const STRLEN size, const UV element0, UV** other_elements_ptr)

{
    

    SV* invlist = _new_invlist(size);
    bool offset;

    PERL_ARGS_ASSERT__SETUP_CANNED_INVLIST;

    invlist = add_cp_to_invlist(invlist, element0);
    offset = *get_invlist_offset_addr(invlist);

    invlist_set_len(invlist, size, offset);
    *other_elements_ptr = invlist_array(invlist) + 1;
    return invlist;
}



PERL_STATIC_INLINE SV* S_add_cp_to_invlist(pTHX_ SV* invlist, const UV cp) {
    return _add_range_to_invlist(invlist, cp, cp);
}


void Perl__invlist_invert(pTHX_ SV* const invlist)
{
    

    PERL_ARGS_ASSERT__INVLIST_INVERT;

    assert(! invlist_is_iterating(invlist));

    
    if (_invlist_len(invlist) == 0) {
	_append_range_to_invlist(invlist, 0, UV_MAX);
	return;
    }

    *get_invlist_offset_addr(invlist) = ! *get_invlist_offset_addr(invlist);
}

SV* Perl_invlist_clone(pTHX_ SV* const invlist, SV* new_invlist)
{
    

    const STRLEN nominal_length = _invlist_len(invlist);
    const STRLEN physical_length = SvCUR(invlist);
    const bool offset = *(get_invlist_offset_addr(invlist));

    PERL_ARGS_ASSERT_INVLIST_CLONE;

    if (new_invlist == NULL) {
        new_invlist = _new_invlist(nominal_length);
    }
    else {
        sv_upgrade(new_invlist, SVt_INVLIST);
        initialize_invlist_guts(new_invlist, nominal_length);
    }

    *(get_invlist_offset_addr(new_invlist)) = offset;
    invlist_set_len(new_invlist, nominal_length, offset);
    Copy(SvPVX(invlist), SvPVX(new_invlist), physical_length, char);

    return new_invlist;
}



PERL_STATIC_INLINE STRLEN* S_get_invlist_iter_addr(SV* invlist)
{
    

    PERL_ARGS_ASSERT_GET_INVLIST_ITER_ADDR;

    assert(is_invlist(invlist));

    return &(((XINVLIST*) SvANY(invlist))->iterator);
}

PERL_STATIC_INLINE void S_invlist_iterinit(SV* invlist)
{
    PERL_ARGS_ASSERT_INVLIST_ITERINIT;

    *get_invlist_iter_addr(invlist) = 0;
}

PERL_STATIC_INLINE void S_invlist_iterfinish(SV* invlist)
{
    

    PERL_ARGS_ASSERT_INVLIST_ITERFINISH;

    *get_invlist_iter_addr(invlist) = (STRLEN) UV_MAX;
}

STATIC bool S_invlist_iternext(SV* invlist, UV* start, UV* end)
{
    

    STRLEN* pos = get_invlist_iter_addr(invlist);
    UV len = _invlist_len(invlist);
    UV *array;

    PERL_ARGS_ASSERT_INVLIST_ITERNEXT;

    if (*pos >= len) {
	*pos = (STRLEN) UV_MAX;	
	return FALSE;
    }

    array = invlist_array(invlist);

    *start = array[(*pos)++];

    if (*pos >= len) {
	*end = UV_MAX;
    }
    else {
	*end = array[(*pos)++] - 1;
    }

    return TRUE;
}

PERL_STATIC_INLINE UV S_invlist_highest(SV* const invlist)
{
    

    UV len = _invlist_len(invlist);
    UV *array;

    PERL_ARGS_ASSERT_INVLIST_HIGHEST;

    if (len == 0) {
	return 0;
    }

    array = invlist_array(invlist);

    
    return (ELEMENT_RANGE_MATCHES_INVLIST(len - 1))
           ? UV_MAX : array[len - 1] - 1;
}

STATIC SV * S_invlist_contents(pTHX_ SV* const invlist, const bool traditional_style)
{
    

    UV start, end;
    SV* output;
    const char intra_range_delimiter = (traditional_style ? '\t' : '-');
    const char inter_range_delimiter = (traditional_style ? '\n' : ' ');

    if (traditional_style) {
        output = newSVpvs("\n");
    }
    else {
        output = newSVpvs("");
    }

    PERL_ARGS_ASSERT_INVLIST_CONTENTS;

    assert(! invlist_is_iterating(invlist));

    invlist_iterinit(invlist);
    while (invlist_iternext(invlist, &start, &end)) {
	if (end == UV_MAX) {
	    Perl_sv_catpvf(aTHX_ output, "%04" UVXf "%cINFTY%c", start, intra_range_delimiter, inter_range_delimiter);

	}
	else if (end != start) {
	    Perl_sv_catpvf(aTHX_ output, "%04" UVXf "%c%04" UVXf "%c", start, intra_range_delimiter, end, inter_range_delimiter);


	}
	else {
	    Perl_sv_catpvf(aTHX_ output, "%04" UVXf "%c", start, inter_range_delimiter);
	}
    }

    if (SvCUR(output) && ! traditional_style) {
        SvCUR_set(output, SvCUR(output) - 1);
    }

    return output;
}


void Perl__invlist_dump(pTHX_ PerlIO *file, I32 level, const char * const indent, SV* const invlist)

{
    

    UV start, end;
    STRLEN count = 0;

    PERL_ARGS_ASSERT__INVLIST_DUMP;

    if (invlist_is_iterating(invlist)) {
        Perl_dump_indent(aTHX_ level, file, "%sCan't dump inversion list because is in middle of iterating\n", indent);

        return;
    }

    invlist_iterinit(invlist);
    while (invlist_iternext(invlist, &start, &end)) {
	if (end == UV_MAX) {
	    Perl_dump_indent(aTHX_ level, file, "%s[%" UVuf "] 0x%04" UVXf " .. INFTY\n", indent, (UV)count, start);

	}
	else if (end != start) {
	    Perl_dump_indent(aTHX_ level, file, "%s[%" UVuf "] 0x%04" UVXf " .. 0x%04" UVXf "\n", indent, (UV)count, start,         end);

	}
	else {
	    Perl_dump_indent(aTHX_ level, file, "%s[%" UVuf "] 0x%04" UVXf "\n", indent, (UV)count, start);
	}
        count += 2;
    }
}




bool Perl__invlistEQ(pTHX_ SV* const a, SV* const b, const bool complement_b)
{
    

    const UV len_a = _invlist_len(a);
    UV len_b = _invlist_len(b);

    const UV* array_a = NULL;
    const UV* array_b = NULL;

    PERL_ARGS_ASSERT__INVLISTEQ;

    

    if (len_a == 0) {
        if (len_b == 0) {
            return ! complement_b;
        }
    }
    else {
        array_a = invlist_array(a);
    }

    if (len_b != 0) {
        array_b = invlist_array(b);
    }

    
    if (complement_b) {

        
        if (len_b == 0) {
            return (len_a == 1 && array_a[0] == 0);
        }
        if (array_b[0] == 0) {

            

            array_b++;
            len_b--;
        }
        else {

            
            array_b--;
            len_b++;
        }
    }

    return    len_a == len_b && memEQ(array_a, array_b, len_a * sizeof(array_a[0]));

}



STATIC SV* S__make_exactf_invlist(pTHX_ RExC_state_t *pRExC_state, regnode *node)
{
    dVAR;
    const U8 * s = (U8*)STRING(node);
    SSize_t bytelen = STR_LEN(node);
    UV uc;
    
    SV* invlist = _new_invlist(4);

    PERL_ARGS_ASSERT__MAKE_EXACTF_INVLIST;

    if (! UTF) {
        uc = *s;

        
        if (is_MULTI_CHAR_FOLD_latin1_safe(s, s + bytelen)) {
            invlist = _add_range_to_invlist(invlist, 0, UV_MAX);
        }
        else {
            
            if (OP(node) == EXACTFL) {
                _invlist_union(invlist, PL_Latin1, &invlist);
                invlist = add_cp_to_invlist(invlist, LATIN_SMALL_LETTER_DOTLESS_I);
                invlist = add_cp_to_invlist(invlist, LATIN_CAPITAL_LETTER_I_WITH_DOT_ABOVE);
            }
            else {
                
                invlist = add_cp_to_invlist(invlist, uc);
                if (IS_IN_SOME_FOLD_L1(uc))
                    invlist = add_cp_to_invlist(invlist, PL_fold_latin1[uc]);
            }

            
            if (HAS_NONLATIN1_SIMPLE_FOLD_CLOSURE(uc)
                && (! isASCII(uc) || (OP(node) != EXACTFAA && OP(node) != EXACTFAA_NO_TRIE)))
            {
                add_above_Latin1_folds(pRExC_state, (U8) uc, &invlist);
            }
        }
    }
    else {  
        U8 folded[UTF8_MAX_FOLD_CHAR_EXPAND * UTF8_MAXBYTES_CASE + 1] = { '\0' };
        const U8* e = s + bytelen;
        IV fc;

        fc = uc = utf8_to_uvchr_buf(s, s + bytelen, NULL);

        
        if (OP(node) == EXACTFL && is_PROBLEMATIC_LOCALE_FOLDEDS_START_cp(uc)) {
            
            U8 *d = folded;
            int i;

            fc = -1;
            for (i = 0; i < UTF8_MAX_FOLD_CHAR_EXPAND && s < e; i++) {
                if (isASCII(*s)) {
                    *(d++) = (U8) toFOLD(*s);
                    if (fc < 0) {       
                        fc = *(d-1);
                    }
                    s++;
                }
                else {
                    STRLEN len;
                    UV fold = toFOLD_utf8_safe(s, e, d, &len);
                    if (fc < 0) {       
                        fc = fold;
                    }
                    d += len;
                    s += UTF8SKIP(s);
                }
            }

            
            e = d;
            s = folded;
        }

        

        if (is_MULTI_CHAR_FOLD_utf8_safe(s, e)) {
            invlist = _add_range_to_invlist(invlist, 0, UV_MAX);
        }
        else {  
            unsigned int k;
            unsigned int first_fold;
            const unsigned int * remaining_folds;
            Size_t folds_count;

            
            invlist = add_cp_to_invlist(invlist, fc);

            
            folds_count = _inverse_folds(fc, &first_fold, &remaining_folds);
            for (k = 0; k < folds_count; k++) {
                UV c = (k == 0) ? first_fold : remaining_folds[k-1];

                
                if (   (OP(node) == EXACTFAA || OP(node) == EXACTFAA_NO_TRIE)
                    && isASCII(c) != isASCII(fc))
                {
                    continue;
                }

                invlist = add_cp_to_invlist(invlist, c);
            }

            if (OP(node) == EXACTFL) {

                
                if (isALPHA_FOLD_EQ(fc, 'I')) {
                    invlist = add_cp_to_invlist(invlist, LATIN_SMALL_LETTER_DOTLESS_I);
                    invlist = add_cp_to_invlist(invlist, LATIN_CAPITAL_LETTER_I_WITH_DOT_ABOVE);
                }
                else if (fc == LATIN_SMALL_LETTER_DOTLESS_I) {
                    invlist = add_cp_to_invlist(invlist, 'I');
                }
                else if (fc == LATIN_CAPITAL_LETTER_I_WITH_DOT_ABOVE) {
                    invlist = add_cp_to_invlist(invlist, 'i');
                }
            }
        }
    }

    return invlist;
}








STATIC void S_parse_lparen_question_flags(pTHX_ RExC_state_t *pRExC_state)
{
    

    





    I32 wastedflags = 0x00;
    U32 posflags = 0, negflags = 0;
    U32 *flagsp = &posflags;
    char has_charset_modifier = '\0';
    regex_charset cs;
    bool has_use_defaults = FALSE;
    const char* const seqstart = RExC_parse - 1; 
    int x_mod_count = 0;

    PERL_ARGS_ASSERT_PARSE_LPAREN_QUESTION_FLAGS;

    
    if (UCHARAT(RExC_parse) == '^') {
        RExC_parse++;
        has_use_defaults = TRUE;
        STD_PMMOD_FLAGS_CLEAR(&RExC_flags);
        cs = (RExC_uni_semantics)
             ? REGEX_UNICODE_CHARSET : REGEX_DEPENDS_CHARSET;
        set_regex_charset(&RExC_flags, cs);
    }
    else {
        cs = get_regex_charset(RExC_flags);
        if (   cs == REGEX_DEPENDS_CHARSET && RExC_uni_semantics)
        {
            cs = REGEX_UNICODE_CHARSET;
        }
    }

    while (RExC_parse < RExC_end) {
        
        
        switch (*RExC_parse) {

            
            CASE_STD_PMMOD_FLAGS_PARSE_SET(flagsp, x_mod_count);

            case LOCALE_PAT_MOD:
                if (has_charset_modifier) {
                    goto excess_modifier;
                }
                else if (flagsp == &negflags) {
                    goto neg_modifier;
                }
                cs = REGEX_LOCALE_CHARSET;
                has_charset_modifier = LOCALE_PAT_MOD;
                break;
            case UNICODE_PAT_MOD:
                if (has_charset_modifier) {
                    goto excess_modifier;
                }
                else if (flagsp == &negflags) {
                    goto neg_modifier;
                }
                cs = REGEX_UNICODE_CHARSET;
                has_charset_modifier = UNICODE_PAT_MOD;
                break;
            case ASCII_RESTRICT_PAT_MOD:
                if (flagsp == &negflags) {
                    goto neg_modifier;
                }
                if (has_charset_modifier) {
                    if (cs != REGEX_ASCII_RESTRICTED_CHARSET) {
                        goto excess_modifier;
                    }
                    
                    cs = REGEX_ASCII_MORE_RESTRICTED_CHARSET;
                }
                else {
                    cs = REGEX_ASCII_RESTRICTED_CHARSET;
                }
                has_charset_modifier = ASCII_RESTRICT_PAT_MOD;
                break;
            case DEPENDS_PAT_MOD:
                if (has_use_defaults) {
                    goto fail_modifiers;
                }
                else if (flagsp == &negflags) {
                    goto neg_modifier;
                }
                else if (has_charset_modifier) {
                    goto excess_modifier;
                }

                
                cs = (RExC_uni_semantics)
                     ? REGEX_UNICODE_CHARSET : REGEX_DEPENDS_CHARSET;
                has_charset_modifier = DEPENDS_PAT_MOD;
                break;
              excess_modifier:
                RExC_parse++;
                if (has_charset_modifier == ASCII_RESTRICT_PAT_MOD) {
                    vFAIL2("Regexp modifier \"%c\" may appear a maximum of twice", ASCII_RESTRICT_PAT_MOD);
                }
                else if (has_charset_modifier == *(RExC_parse - 1)) {
                    vFAIL2("Regexp modifier \"%c\" may not appear twice", *(RExC_parse - 1));
                }
                else {
                    vFAIL3("Regexp modifiers \"%c\" and \"%c\" are mutually exclusive", has_charset_modifier, *(RExC_parse - 1));
                }
                NOT_REACHED; 
              neg_modifier:
                RExC_parse++;
                vFAIL2("Regexp modifier \"%c\" may not appear after the \"-\"", *(RExC_parse - 1));
                NOT_REACHED; 
            case ONCE_PAT_MOD: 
            case GLOBAL_PAT_MOD: 
                if (ckWARN(WARN_REGEXP)) {
                    const I32 wflagbit = *RExC_parse == 'o' ? WASTED_O : WASTED_G;

                    if (! (wastedflags & wflagbit) ) {
                        wastedflags |= wflagbit;
			
                        vWARN5( RExC_parse + 1, "Useless (%s%c) - %suse /%c modifier", flagsp == &negflags ? "?-" : "?", *RExC_parse, flagsp == &negflags ? "don't " : "", *RExC_parse );






                    }
                }
                break;

            case CONTINUE_PAT_MOD: 
                if (ckWARN(WARN_REGEXP)) {
                    if (! (wastedflags & WASTED_C) ) {
                        wastedflags |= WASTED_GC;
			
                        vWARN3( RExC_parse + 1, "Useless (%sc) - %suse /gc modifier", flagsp == &negflags ? "?-" : "?", flagsp == &negflags ? "don't " : "" );




                    }
                }
                break;
            case KEEPCOPY_PAT_MOD: 
                if (flagsp == &negflags) {
                    ckWARNreg(RExC_parse + 1,"Useless use of (?-p)");
                } else {
                    *flagsp |= RXf_PMf_KEEPCOPY;
                }
                break;
            case '-':
                
                if (has_use_defaults || flagsp == &negflags) {
                    goto fail_modifiers;
                }
                flagsp = &negflags;
                wastedflags = 0;  
                x_mod_count = 0;
                break;
            case ':':
            case ')':

                if ((posflags & (RXf_PMf_EXTENDED|RXf_PMf_EXTENDED_MORE)) == RXf_PMf_EXTENDED) {
                    negflags |= RXf_PMf_EXTENDED_MORE;
                }
                RExC_flags |= posflags;

                if (negflags & RXf_PMf_EXTENDED) {
                    negflags |= RXf_PMf_EXTENDED_MORE;
                }
                RExC_flags &= ~negflags;
                set_regex_charset(&RExC_flags, cs);

                return;
            default:
              fail_modifiers:
                RExC_parse += SKIP_IF_CHAR(RExC_parse, RExC_end);
		
                vFAIL2utf8f("Sequence (%" UTF8f "...) not recognized", UTF8fARG(UTF, RExC_parse-seqstart, seqstart));
                NOT_REACHED; 
        }

        RExC_parse += UTF ? UTF8SKIP(RExC_parse) : 1;
    }

    vFAIL("Sequence (?... not terminated");
}









PERL_STATIC_INLINE regnode_offset S_handle_named_backref(pTHX_ RExC_state_t *pRExC_state, I32 *flagp, char * parse_start, char ch )




{
    regnode_offset ret;
    char* name_start = RExC_parse;
    U32 num = 0;
    SV *sv_dat = reg_scan_name(pRExC_state, REG_RSN_RETURN_DATA);
    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_HANDLE_NAMED_BACKREF;

    if (RExC_parse == name_start || *RExC_parse != ch) {
        
        vFAIL2("Sequence %.3s... not terminated", parse_start);
    }

    if (sv_dat) {
        num = add_data( pRExC_state, STR_WITH_LEN("S"));
        RExC_rxi->data->data[num]=(void*)sv_dat;
        SvREFCNT_inc_simple_void_NN(sv_dat);
    }
    RExC_sawback = 1;
    ret = reganode(pRExC_state, ((! FOLD)
                     ? NREF : (ASCII_FOLD_RESTRICTED)
                       ? NREFFA : (AT_LEAST_UNI_SEMANTICS)
                         ? NREFFU : (LOC)
                           ? NREFFL : NREFF), num);

    *flagp |= HASWIDTH;

    Set_Node_Offset(REGNODE_p(ret), parse_start+1);
    Set_Node_Cur_Length(REGNODE_p(ret), parse_start);

    nextchar(pRExC_state);
    return ret;
}


STATIC regnode_offset S_reg(pTHX_ RExC_state_t *pRExC_state, I32 paren, I32 *flagp, U32 depth)
    
{
    regnode_offset ret = 0;    
    regnode_offset br;
    regnode_offset lastbr;
    regnode_offset ender = 0;
    I32 parno = 0;
    I32 flags;
    U32 oregflags = RExC_flags;
    bool have_branch = 0;
    bool is_open = 0;
    I32 freeze_paren = 0;
    I32 after_freeze = 0;
    I32 num; 
    SV * max_open;  

    char * parse_start = RExC_parse; 
    char * const oregcomp_parse = RExC_parse;

    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_REG;
    DEBUG_PARSE("reg ");


    max_open = get_sv(RE_COMPILE_RECURSION_LIMIT, GV_ADD);
    assert(max_open);
    if (!SvIOK(max_open)) {
        sv_setiv(max_open, RE_COMPILE_RECURSION_INIT);
    }
    if (depth > 4 * (UV) SvIV(max_open)) { 
        vFAIL("Too many nested open parens");
    }

    *flagp = 0;				

    
    assert(*RExC_end == '\0');

    
    if (paren) {

        
        bool has_intervening_patws = (paren == 2)
                                  && *(RExC_parse - 1) != '(';

        if (RExC_parse >= RExC_end) {
	    vFAIL("Unmatched (");
        }

        if (paren == 'r') {     
            paren = '>';
            goto parse_rest;
        }
        else if ( *RExC_parse == '*') { 
	    char *start_verb = RExC_parse + 1;
	    STRLEN verb_len;
	    char *start_arg = NULL;
	    unsigned char op = 0;
            int arg_required = 0;
            int internal_argval = -1; 
            bool has_upper = FALSE;

            if (has_intervening_patws) {
                RExC_parse++;   

                
                if (isUPPER(*RExC_parse)) {
                    vFAIL("In '(*VERB...)', the '(' and '*' must be adjacent");
                }
                else {
                    vFAIL("In '(*...)', the '(' and '*' must be adjacent");
                }
            }
	    while (RExC_parse < RExC_end && *RExC_parse != ')' ) {
	        if ( *RExC_parse == ':' ) {
	            start_arg = RExC_parse + 1;
	            break;
	        }
                else if (! UTF) {
                    if (isUPPER(*RExC_parse)) {
                        has_upper = TRUE;
                    }
                    RExC_parse++;
                }
                else {
                    RExC_parse += UTF8SKIP(RExC_parse);
                }
	    }
	    verb_len = RExC_parse - start_verb;
	    if ( start_arg ) {
                if (RExC_parse >= RExC_end) {
                    goto unterminated_verb_pattern;
                }

	        RExC_parse += UTF ? UTF8SKIP(RExC_parse) : 1;
	        while ( RExC_parse < RExC_end && *RExC_parse != ')' ) {
                    RExC_parse += UTF ? UTF8SKIP(RExC_parse) : 1;
                }
	        if ( RExC_parse >= RExC_end || *RExC_parse != ')' ) {
                  unterminated_verb_pattern:
                    if (has_upper) {
                        vFAIL("Unterminated verb pattern argument");
                    }
                    else {
                        vFAIL("Unterminated '(*...' argument");
                    }
                }
	    } else {
	        if ( RExC_parse >= RExC_end || *RExC_parse != ')' ) {
                    if (has_upper) {
                        vFAIL("Unterminated verb pattern");
                    }
                    else {
                        vFAIL("Unterminated '(*...' construct");
                    }
                }
	    }

            

	    switch ( *start_verb ) {
            case 'A':  
                if ( memEQs(start_verb, verb_len,"ACCEPT") ) {
		    op = ACCEPT;
		    internal_argval = RExC_nestroot;
		}
		break;
            case 'C':  
                if ( memEQs(start_verb, verb_len,"COMMIT") )
                    op = COMMIT;
                break;
            case 'F':  
                if ( verb_len==1 || memEQs(start_verb, verb_len,"FAIL") ) {
		    op = OPFAIL;
		}
		break;
            case ':':  
	    case 'M':  
	        if ( verb_len==0 || memEQs(start_verb, verb_len,"MARK") ) {
                    op = MARKPOINT;
                    arg_required = 1;
                }
                break;
            case 'P':  
                if ( memEQs(start_verb, verb_len,"PRUNE") )
                    op = PRUNE;
                break;
            case 'S':   
                if ( memEQs(start_verb, verb_len,"SKIP") )
                    op = SKIP;
                break;
            case 'T':  
                
                if ( memEQs(start_verb, verb_len,"THEN") ) {
                    op = CUTGROUP;
                    RExC_seen |= REG_CUTGROUP_SEEN;
                }
                break;
            case 'a':
                if (   memEQs(start_verb, verb_len, "asr")
                    || memEQs(start_verb, verb_len, "atomic_script_run"))
                {
                    paren = 'r';        
                    goto script_run;
                }
                else if (memEQs(start_verb, verb_len, "atomic")) {
                    paren = 't';    
                    goto alpha_assertions;
                }
                break;
            case 'p':
                if (   memEQs(start_verb, verb_len, "plb")
                    || memEQs(start_verb, verb_len, "positive_lookbehind"))
                {
                    paren = 'b';
                    goto lookbehind_alpha_assertions;
                }
                else if (   memEQs(start_verb, verb_len, "pla")
                         || memEQs(start_verb, verb_len, "positive_lookahead"))
                {
                    paren = 'a';
                    goto alpha_assertions;
                }
                break;
            case 'n':
                if (   memEQs(start_verb, verb_len, "nlb")
                    || memEQs(start_verb, verb_len, "negative_lookbehind"))
                {
                    paren = 'B';
                    goto lookbehind_alpha_assertions;
                }
                else if (   memEQs(start_verb, verb_len, "nla")
                         || memEQs(start_verb, verb_len, "negative_lookahead"))
                {
                    paren = 'A';
                    goto alpha_assertions;
                }
                break;
            case 's':
                if (   memEQs(start_verb, verb_len, "sr")
                    || memEQs(start_verb, verb_len, "script_run"))
                {
                    regnode_offset atomic;

                    paren = 's';

                   script_run:

                    
                    REQUIRE_UNI_RULES(flagp, 0);

                    if (! start_arg) {
                        goto no_colon;
                    }

                    RExC_parse = start_arg;

                    if (RExC_in_script_run) {

                        

                        ret = 0;

                        if (paren == 's') {
                            paren = ':';
                            goto parse_rest;
                        }

                        
                        paren = '>';
                        goto parse_rest;
                    }

                    
                    ckWARNexperimental(RExC_parse, WARN_EXPERIMENTAL__SCRIPT_RUN, "The script_run feature is experimental");


                    if (paren == 's') {
                        
                        ret = reg_node(pRExC_state, SROPEN);
                        RExC_in_script_run = 1;
                        is_open = 1;
                        goto parse_rest;
                    }

                    

                    ret = reg_node(pRExC_state, SROPEN);

                    RExC_in_script_run = 1;

                    atomic = reg(pRExC_state, 'r', &flags, depth);
                    if (flags & (RESTART_PARSE|NEED_UTF8)) {
                        *flagp = flags & (RESTART_PARSE|NEED_UTF8);
                        return 0;
                    }

                    if (! REGTAIL(pRExC_state, ret, atomic)) {
                        REQUIRE_BRANCHJ(flagp, 0);
                    }

                    if (! REGTAIL(pRExC_state, atomic, reg_node(pRExC_state, SRCLOSE)))
                    {
                        REQUIRE_BRANCHJ(flagp, 0);
                    }

                    RExC_in_script_run = 0;
                    return ret;
                }

                break;

            lookbehind_alpha_assertions:
                RExC_seen |= REG_LOOKBEHIND_SEEN;
                RExC_in_lookbehind++;
                

            alpha_assertions:
                ckWARNexperimental(RExC_parse, WARN_EXPERIMENTAL__ALPHA_ASSERTIONS, "The alpha_assertions feature is experimental");


                RExC_seen_zerolen++;

                if (! start_arg) {
                    goto no_colon;
                }

                
                if (paren == 'A' && RExC_parse == start_arg) {
                    ret=reganode(pRExC_state, OPFAIL, 0);
                    nextchar(pRExC_state);
                    return ret;
	        }

                RExC_parse = start_arg;
                goto parse_rest;

              no_colon:
                vFAIL2utf8f( "'(*%" UTF8f "' requires a terminating ':'", UTF8fARG(UTF, verb_len, start_verb));

		NOT_REACHED; 

	    } 
	    if ( ! op ) {
	        RExC_parse += UTF ? UTF8_SAFE_SKIP(RExC_parse, RExC_end)
                              : 1;
                if (has_upper || verb_len == 0) {
                    vFAIL2utf8f( "Unknown verb pattern '%" UTF8f "'", UTF8fARG(UTF, verb_len, start_verb));

                }
                else {
                    vFAIL2utf8f( "Unknown '(*...)' construct '%" UTF8f "'", UTF8fARG(UTF, verb_len, start_verb));

                }
	    }
            if ( RExC_parse == start_arg ) {
                start_arg = NULL;
            }
            if ( arg_required && !start_arg ) {
                vFAIL3("Verb pattern '%.*s' has a mandatory argument", verb_len, start_verb);
            }
            if (internal_argval == -1) {
                ret = reganode(pRExC_state, op, 0);
            } else {
                ret = reg2Lanode(pRExC_state, op, 0, internal_argval);
            }
            RExC_seen |= REG_VERBARG_SEEN;
            if (start_arg) {
                SV *sv = newSVpvn( start_arg, RExC_parse - start_arg);
                ARG(REGNODE_p(ret)) = add_data( pRExC_state, STR_WITH_LEN("S"));
                RExC_rxi->data->data[ARG(REGNODE_p(ret))]=(void*)sv;
                FLAGS(REGNODE_p(ret)) = 1;
            } else {
                FLAGS(REGNODE_p(ret)) = 0;
            }
            if ( internal_argval != -1 )
                ARG2L_SET(REGNODE_p(ret), internal_argval);
	    nextchar(pRExC_state);
	    return ret;
        }
        else if (*RExC_parse == '?') { 
	    bool is_logical = 0;
	    const char * const seqstart = RExC_parse;
            const char * endptr;
            if (has_intervening_patws) {
                RExC_parse++;
                vFAIL("In '(?...)', the '(' and '?' must be adjacent");
            }

	    RExC_parse++;           
            paren = *RExC_parse;    
            RExC_parse += UTF ? UTF8SKIP(RExC_parse) : 1;
            if (RExC_parse > RExC_end) {
                paren = '\0';
            }
	    ret = 0;			
	    switch (paren) {

	    case 'P':	
	        paren = *RExC_parse;
		if ( paren == '<') {    
                    RExC_parse++;
                    if (RExC_parse >= RExC_end) {
                        vFAIL("Sequence (?P<... not terminated");
                    }
		    goto named_capture;
                }
                else if (paren == '>') {   
                    RExC_parse++;
                    if (RExC_parse >= RExC_end) {
                        vFAIL("Sequence (?P>... not terminated");
                    }
                    goto named_recursion;
                }
                else if (paren == '=') {   
                    RExC_parse++;
                    return handle_named_backref(pRExC_state, flagp, parse_start, ')');
                }
                RExC_parse += SKIP_IF_CHAR(RExC_parse, RExC_end);
                
		vFAIL3("Sequence (%.*s...) not recognized", RExC_parse-seqstart, seqstart);
		NOT_REACHED; 
            case '<':           
		if (*RExC_parse == '!')
		    paren = ',';
		else if (*RExC_parse != '=')
              named_capture:
		{               
		    char *name_start;
		    SV *svname;
		    paren= '>';
                
            case '\'':          
                    name_start = RExC_parse;
                    svname = reg_scan_name(pRExC_state, REG_RSN_RETURN_NAME);
		    if (   RExC_parse == name_start || RExC_parse >= RExC_end || *RExC_parse != paren)

                    {
		        vFAIL2("Sequence (?%c... not terminated", paren=='>' ? '<' : paren);
                    }
		    {
			HE *he_str;
			SV *sv_dat = NULL;
                        if (!svname) 
                            Perl_croak(aTHX_ "panic: reg_scan_name returned NULL");
                        if (!RExC_paren_names) {
                            RExC_paren_names= newHV();
                            sv_2mortal(MUTABLE_SV(RExC_paren_names));

                            RExC_paren_name_list= newAV();
                            sv_2mortal(MUTABLE_SV(RExC_paren_name_list));

                        }
                        he_str = hv_fetch_ent( RExC_paren_names, svname, 1, 0 );
                        if ( he_str )
                            sv_dat = HeVAL(he_str);
                        if ( ! sv_dat ) {
                            
                            Perl_croak(aTHX_ "panic: paren_name hash element allocation failed");
                        } else if ( SvPOK(sv_dat) ) {
                            
                            IV count = SvIV(sv_dat);
                            I32 *pv = (I32*)SvPVX(sv_dat);
                            IV i;
                            for ( i = 0 ; i < count ; i++ ) {
                                if ( pv[i] == RExC_npar ) {
                                    count = 0;
                                    break;
                                }
                            }
                            if ( count ) {
                                pv = (I32*)SvGROW(sv_dat, SvCUR(sv_dat) + sizeof(I32)+1);
                                SvCUR_set(sv_dat, SvCUR(sv_dat) + sizeof(I32));
                                pv[count] = RExC_npar;
                                SvIV_set(sv_dat, SvIVX(sv_dat) + 1);
                            }
                        } else {
                            (void)SvUPGRADE(sv_dat, SVt_PVNV);
                            sv_setpvn(sv_dat, (char *)&(RExC_npar), sizeof(I32));
                            SvIOK_on(sv_dat);
                            SvIV_set(sv_dat, 1);
                        }

                        
                        if (!av_store(RExC_paren_name_list, RExC_npar, SvREFCNT_inc_NN(svname)))
                            SvREFCNT_dec_NN(svname);


                        
                    }
                    nextchar(pRExC_state);
		    paren = 1;
		    goto capturing_parens;
		}

                RExC_seen |= REG_LOOKBEHIND_SEEN;
		RExC_in_lookbehind++;
		RExC_parse++;
                if (RExC_parse >= RExC_end) {
                    vFAIL("Sequence (?... not terminated");
                }

                
	    case '=':           
		RExC_seen_zerolen++;
                break;
	    case '!':           
		RExC_seen_zerolen++;
		
                skip_to_be_ignored_text(pRExC_state, &RExC_parse, FALSE  );
	        if (*RExC_parse == ')') {
                    ret=reganode(pRExC_state, OPFAIL, 0);
	            nextchar(pRExC_state);
	            return ret;
	        }
	        break;
	    case '|':           
	        
	        paren = ':';
	        after_freeze = freeze_paren = RExC_npar;

                
                REQUIRE_PARENS_PASS;
	        break;
	    case ':':           
	    case '>':           
		break;
	    case '$':           
	    case '@':           
		vFAIL2("Sequence (?%c...) not implemented", (int)paren);
		break;
	    case '0' :           
	    case 'R' :           
                if (RExC_parse == RExC_end || *RExC_parse != ')')
		    FAIL("Sequence (?R) not terminated");
                num = 0;
                RExC_seen |= REG_RECURSE_SEEN;

                
                REQUIRE_PARENS_PASS;

		*flagp |= POSTPONED;
                goto gen_recurse_regop;
		
            
            case '&':            
                parse_start = RExC_parse - 1;
              named_recursion:
                {
                    SV *sv_dat = reg_scan_name(pRExC_state, REG_RSN_RETURN_DATA);
                   num = sv_dat ? *((I32 *)SvPVX(sv_dat)) : 0;
                }
                if (RExC_parse >= RExC_end || *RExC_parse != ')')
                    vFAIL("Sequence (?&... not terminated");
                goto gen_recurse_regop;
                
            case '+':
                if (! inRANGE(RExC_parse[0], '1', '9')) {
                    RExC_parse++;
                    vFAIL("Illegal pattern");
                }
                goto parse_recursion;
                
            case '-': 
                if (! inRANGE(RExC_parse[0], '1', '9')) {
                    RExC_parse--; 
                    goto parse_flags;
                }
                
            case '1': case '2': case '3': case '4': 
	    case '5': case '6': case '7': case '8': case '9':
	        RExC_parse = (char *) seqstart + 1;  
              parse_recursion:
                {
                    bool is_neg = FALSE;
                    UV unum;
                    parse_start = RExC_parse - 1; 
                    if (*RExC_parse == '-') {
                        RExC_parse++;
                        is_neg = TRUE;
                    }
                    endptr = RExC_end;
                    if (grok_atoUV(RExC_parse, &unum, &endptr)
                        && unum <= I32_MAX ) {
                        num = (I32)unum;
                        RExC_parse = (char*)endptr;
                    } else num = I32_MAX;
                    if (is_neg) {
                        
                        num = -num;
                    }
                }
	        if (*RExC_parse!=')')
	            vFAIL("Expecting close bracket");

              gen_recurse_regop:
                if ( paren == '-' ) {
                    
                    num = RExC_npar + num;
                    if (num < 1)  {

                        
                        if (ALL_PARENS_COUNTED)  {
                            RExC_parse++;
                            vFAIL("Reference to nonexistent group");
                        }
                        else {
                            REQUIRE_PARENS_PASS;
                        }
                    }
                } else if ( paren == '+' ) {
                    num = RExC_npar + num - 1;
                }
                

                ret = reg2Lanode(pRExC_state, GOSUB, num, RExC_recurse_count);
                if (num >= RExC_npar) {

                    
                    if (ALL_PARENS_COUNTED)  {
                        if (num >= RExC_total_parens) {
                            RExC_parse++;
                            vFAIL("Reference to nonexistent group");
                        }
                    }
                    else {
                        REQUIRE_PARENS_PASS;
                    }
                }
                RExC_recurse_count++;
                DEBUG_OPTIMISE_MORE_r(Perl_re_printf( aTHX_ "%*s%*s Recurse #%" UVuf " to %" IVdf "\n", 22, "|    |", (int)(depth * 2 + 1), "", (UV)ARG(REGNODE_p(ret)), (IV)ARG2L(REGNODE_p(ret))));



                RExC_seen |= REG_RECURSE_SEEN;

                Set_Node_Length(REGNODE_p(ret), 1 + regarglen[OP(REGNODE_p(ret))]);
		Set_Node_Offset(REGNODE_p(ret), parse_start); 

                *flagp |= POSTPONED;
                assert(*RExC_parse == ')');
                nextchar(pRExC_state);
                return ret;

            

	    case '?':           
		is_logical = 1;
		if (*RExC_parse != '{') {
                    RExC_parse += SKIP_IF_CHAR(RExC_parse, RExC_end);
                    
                    vFAIL2utf8f( "Sequence (%" UTF8f "...) not recognized", UTF8fARG(UTF, RExC_parse-seqstart, seqstart));

		    NOT_REACHED; 
		}
		*flagp |= POSTPONED;
		paren = '{';
                RExC_parse++;
		
	    case '{':           
	    {
		U32 n = 0;
		struct reg_code_block *cb;
                OP * o;

		RExC_seen_zerolen++;

		if (   !pRExC_state->code_blocks || pRExC_state->code_index >= pRExC_state->code_blocks->count || pRExC_state->code_blocks->cb[pRExC_state->code_index].start != (STRLEN)((RExC_parse -3 - (is_logical ? 1 : 0))



			    - RExC_start)
		) {
		    if (RExC_pm_flags & PMf_USE_RE_EVAL)
			FAIL("panic: Sequence (?{...}): no code block found\n");
		    FAIL("Eval-group not allowed at runtime, use re 'eval'");
		}
		
		cb = &pRExC_state->code_blocks->cb[pRExC_state->code_index];
		RExC_parse = RExC_start + cb->end;
		o = cb->block;
                if (cb->src_regex) {
                    n = add_data(pRExC_state, STR_WITH_LEN("rl"));
                    RExC_rxi->data->data[n] = (void*)SvREFCNT_inc((SV*)cb->src_regex);
                    RExC_rxi->data->data[n+1] = (void*)o;
                }
                else {
                    n = add_data(pRExC_state, (RExC_pm_flags & PMf_HAS_CV) ? "L" : "l", 1);
                    RExC_rxi->data->data[n] = (void*)o;
                }
		pRExC_state->code_index++;
		nextchar(pRExC_state);

		if (is_logical) {
                    regnode_offset eval;
		    ret = reg_node(pRExC_state, LOGICAL);

                    eval = reg2Lanode(pRExC_state, EVAL, n,   RExC_flags & RXf_PMf_COMPILETIME );




                    FLAGS(REGNODE_p(ret)) = 2;
                    if (! REGTAIL(pRExC_state, ret, eval)) {
                        REQUIRE_BRANCHJ(flagp, 0);
                    }
                    
		    return ret;
		}
		ret = reg2Lanode(pRExC_state, EVAL, n, 0);
		Set_Node_Length(REGNODE_p(ret), RExC_parse - parse_start + 1);
		Set_Node_Offset(REGNODE_p(ret), parse_start);
		return ret;
	    }
	    case '(':           
	    {
	        int is_define= 0;
                const int DEFINE_len = sizeof("DEFINE") - 1;
		if (    RExC_parse < RExC_end - 1 && (   (       RExC_parse[0] == '?' && (   RExC_parse[1] == '=' || RExC_parse[1] == '!' || RExC_parse[1] == '<' || RExC_parse[1] == '{'))




		        || (       RExC_parse[0] == '*'         && (   memBEGINs(RExC_parse + 1, (Size_t) (RExC_end - (RExC_parse + 1)), "pla:")


                                || memBEGINs(RExC_parse + 1, (Size_t) (RExC_end - (RExC_parse + 1)), "plb:")

                                || memBEGINs(RExC_parse + 1, (Size_t) (RExC_end - (RExC_parse + 1)), "nla:")

                                || memBEGINs(RExC_parse + 1, (Size_t) (RExC_end - (RExC_parse + 1)), "nlb:")

                                || memBEGINs(RExC_parse + 1, (Size_t) (RExC_end - (RExC_parse + 1)), "positive_lookahead:")

                                || memBEGINs(RExC_parse + 1, (Size_t) (RExC_end - (RExC_parse + 1)), "positive_lookbehind:")

                                || memBEGINs(RExC_parse + 1, (Size_t) (RExC_end - (RExC_parse + 1)), "negative_lookahead:")

                                || memBEGINs(RExC_parse + 1, (Size_t) (RExC_end - (RExC_parse + 1)), "negative_lookbehind:"))))

                ) { 
                    I32 flag;
                    regnode_offset tail;

                    ret = reg_node(pRExC_state, LOGICAL);
                    FLAGS(REGNODE_p(ret)) = 1;

                    tail = reg(pRExC_state, 1, &flag, depth+1);
                    RETURN_FAIL_ON_RESTART(flag, flagp);
                    if (! REGTAIL(pRExC_state, ret, tail)) {
                        REQUIRE_BRANCHJ(flagp, 0);
                    }
                    goto insert_if;
                }
		else if (   RExC_parse[0] == '<'      || RExC_parse[0] == '\'' )
	        {
	            char ch = RExC_parse[0] == '<' ? '>' : '\'';
	            char *name_start= RExC_parse++;
	            U32 num = 0;
	            SV *sv_dat=reg_scan_name(pRExC_state, REG_RSN_RETURN_DATA);
	            if (   RExC_parse == name_start || RExC_parse >= RExC_end || *RExC_parse != ch)

                    {
                        vFAIL2("Sequence (?(%c... not terminated", (ch == '>' ? '<' : ch));
                    }
                    RExC_parse++;
                    if (sv_dat) {
                        num = add_data( pRExC_state, STR_WITH_LEN("S"));
                        RExC_rxi->data->data[num]=(void*)sv_dat;
                        SvREFCNT_inc_simple_void_NN(sv_dat);
                    }
                    ret = reganode(pRExC_state, NGROUPP, num);
                    goto insert_if_check_paren;
		}
		else if (memBEGINs(RExC_parse, (STRLEN) (RExC_end - RExC_parse), "DEFINE"))

                {
		    ret = reganode(pRExC_state, DEFINEP, 0);
		    RExC_parse += DEFINE_len;
		    is_define = 1;
		    goto insert_if_check_paren;
		}
		else if (RExC_parse[0] == 'R') {
		    RExC_parse++;
                    
		    parno = 0;
                    if (RExC_parse[0] == '0') {
                        parno = 1;
                        RExC_parse++;
                    }
                    else if (inRANGE(RExC_parse[0], '1', '9')) {
                        UV uv;
                        endptr = RExC_end;
                        if (grok_atoUV(RExC_parse, &uv, &endptr)
                            && uv <= I32_MAX ) {
                            parno = (I32)uv + 1;
                            RExC_parse = (char*)endptr;
                        }
                        
		    } else if (RExC_parse[0] == '&') {
		        SV *sv_dat;
		        RExC_parse++;
		        sv_dat = reg_scan_name(pRExC_state, REG_RSN_RETURN_DATA);
                        if (sv_dat)
                            parno = 1 + *((I32 *)SvPVX(sv_dat));
		    }
		    ret = reganode(pRExC_state, INSUBP, parno);
		    goto insert_if_check_paren;
		}
                else if (inRANGE(RExC_parse[0], '1', '9')) {
                    
		    char c;
                    UV uv;
                    endptr = RExC_end;
                    if (grok_atoUV(RExC_parse, &uv, &endptr)
                        && uv <= I32_MAX ) {
                        parno = (I32)uv;
                        RExC_parse = (char*)endptr;
                    }
                    else {
                        vFAIL("panic: grok_atoUV returned FALSE");
                    }
                    ret = reganode(pRExC_state, GROUPP, parno);

                 insert_if_check_paren:
		    if (UCHARAT(RExC_parse) != ')') {
                        RExC_parse += UTF ? UTF8_SAFE_SKIP(RExC_parse, RExC_end)
                                      : 1;
			vFAIL("Switch condition not recognized");
		    }
		    nextchar(pRExC_state);
		  insert_if:
                    if (! REGTAIL(pRExC_state, ret, reganode(pRExC_state, IFTHEN, 0)))
                    {
                        REQUIRE_BRANCHJ(flagp, 0);
                    }
                    br = regbranch(pRExC_state, &flags, 1, depth+1);
		    if (br == 0) {
                        RETURN_FAIL_ON_RESTART(flags,flagp);
                        FAIL2("panic: regbranch returned failure, flags=%#" UVxf, (UV) flags);
                    } else if (! REGTAIL(pRExC_state, br, reganode(pRExC_state, LONGJMP, 0)))

                    {
                        REQUIRE_BRANCHJ(flagp, 0);
                    }
		    c = UCHARAT(RExC_parse);
                    nextchar(pRExC_state);
		    if (flags&HASWIDTH)
			*flagp |= HASWIDTH;
		    if (c == '|') {
		        if (is_define)
		            vFAIL("(?(DEFINE)....) does not allow branches");

                        
                        lastbr = reganode(pRExC_state, IFTHEN, 0);

                        if (!regbranch(pRExC_state, &flags, 1, depth+1)) {
                            RETURN_FAIL_ON_RESTART(flags, flagp);
                            FAIL2("panic: regbranch returned failure, flags=%#" UVxf, (UV) flags);
                        }
                        if (! REGTAIL(pRExC_state, ret, lastbr)) {
                            REQUIRE_BRANCHJ(flagp, 0);
                        }
		 	if (flags&HASWIDTH)
			    *flagp |= HASWIDTH;
                        c = UCHARAT(RExC_parse);
                        nextchar(pRExC_state);
		    }
		    else lastbr = 0;
                    if (c != ')') {
                        if (RExC_parse >= RExC_end)
                            vFAIL("Switch (?(condition)... not terminated");
                        else vFAIL("Switch (?(condition)... contains too many branches");
                    }
		    ender = reg_node(pRExC_state, TAIL);
                    if (! REGTAIL(pRExC_state, br, ender)) {
                        REQUIRE_BRANCHJ(flagp, 0);
                    }
		    if (lastbr) {
                        if (! REGTAIL(pRExC_state, lastbr, ender)) {
                            REQUIRE_BRANCHJ(flagp, 0);
                        }
                        if (! REGTAIL(pRExC_state, REGNODE_OFFSET( NEXTOPER( NEXTOPER(REGNODE_p(lastbr)))), ender))



                        {
                            REQUIRE_BRANCHJ(flagp, 0);
                        }
		    }
		    else if (! REGTAIL(pRExC_state, ret, ender)) {
                            REQUIRE_BRANCHJ(flagp, 0);
                        }

                    RExC_size++; 

		    return ret;
		}
                RExC_parse += UTF ? UTF8_SAFE_SKIP(RExC_parse, RExC_end)
                              : 1;
                vFAIL("Unknown switch condition (?(...))");
	    }
	    case '[':           
                return handle_regex_sets(pRExC_state, NULL, flagp, depth+1, oregcomp_parse);
            case 0: 
		RExC_parse--; 
                vFAIL("Sequence (? incomplete");
                break;

            case ')':
                if (RExC_strict) {  
                    ckWARNreg(RExC_parse, "Empty (?) without any modifiers");
                }
                
	    default: 
	        RExC_parse = (char *) seqstart + 1;
              parse_flags:
		parse_lparen_question_flags(pRExC_state);
                if (UCHARAT(RExC_parse) != ':') {
                    if (RExC_parse < RExC_end)
                        nextchar(pRExC_state);
                    *flagp = TRYAGAIN;
                    return 0;
                }
                paren = ':';
                nextchar(pRExC_state);
                ret = 0;
                goto parse_rest;
            } 
	}
	else {
            if (*RExC_parse == '{') {
                ckWARNregdep(RExC_parse + 1, "Unescaped left brace in regex is " "deprecated here (and will be fatal " "in Perl 5.32), passed through");


            }
            
        if (!(RExC_flags & RXf_PMf_NOCAPTURE)) {   
	  capturing_parens:
	    parno = RExC_npar;
	    RExC_npar++;
            if (! ALL_PARENS_COUNTED) {
                

                if (!RExC_parens_buf_size) {
                    
                    RExC_parens_buf_size = 10;

                    
                    Newxz(RExC_open_parens, RExC_parens_buf_size, regnode_offset);
                    RExC_open_parens[0] = 1;    

                    
                    Newxz(RExC_close_parens, RExC_parens_buf_size, regnode_offset);
                    
                }
                else if (RExC_npar > RExC_parens_buf_size) {
                    I32 old_size = RExC_parens_buf_size;

                    RExC_parens_buf_size *= 2;

                    Renew(RExC_open_parens, RExC_parens_buf_size, regnode_offset);
                    Zero(RExC_open_parens + old_size, RExC_parens_buf_size - old_size, regnode_offset);

                    Renew(RExC_close_parens, RExC_parens_buf_size, regnode_offset);
                    Zero(RExC_close_parens + old_size, RExC_parens_buf_size - old_size, regnode_offset);
                }
            }

	    ret = reganode(pRExC_state, OPEN, parno);
            if (!RExC_nestroot)
                RExC_nestroot = parno;
            if (RExC_open_parens && !RExC_open_parens[parno])
            {
                DEBUG_OPTIMISE_MORE_r(Perl_re_printf( aTHX_ "%*s%*s Setting open paren #%" IVdf " to %d\n", 22, "|    |", (int)(depth * 2 + 1), "", (IV)parno, ret));


                RExC_open_parens[parno]= ret;
            }

            Set_Node_Length(REGNODE_p(ret), 1); 
            Set_Node_Offset(REGNODE_p(ret), RExC_parse); 
	    is_open = 1;
	} else {
            
            paren = ':';
	    ret = 0;
	}
        }
    }
    else                         ret = 0;

   parse_rest:
    
    parse_start = RExC_parse;   
    br = regbranch(pRExC_state, &flags, 1, depth+1);

    

    if (br == 0) {
        RETURN_FAIL_ON_RESTART(flags, flagp);
        FAIL2("panic: regbranch returned failure, flags=%#" UVxf, (UV) flags);
    }
    if (*RExC_parse == '|') {
	if (RExC_use_BRANCHJ) {
	    reginsert(pRExC_state, BRANCHJ, br, depth+1);
	}
	else {                  
	    reginsert(pRExC_state, BRANCH, br, depth+1);
            Set_Node_Length(REGNODE_p(br), paren != 0);
            Set_Node_Offset_To_R(br, parse_start-RExC_start);
        }
	have_branch = 1;
    }
    else if (paren == ':') {
	*flagp |= flags&SIMPLE;
    }
    if (is_open) {				
        if (! REGTAIL(pRExC_state, ret, br)) {  
            REQUIRE_BRANCHJ(flagp, 0);
        }
    }
    else if (paren != '?')		
	ret = br;
    *flagp |= flags & (SPSTART | HASWIDTH | POSTPONED);
    lastbr = br;
    while (*RExC_parse == '|') {
	if (RExC_use_BRANCHJ) {
            bool shut_gcc_up;

	    ender = reganode(pRExC_state, LONGJMP, 0);

            
            shut_gcc_up = REGTAIL(pRExC_state, REGNODE_OFFSET(NEXTOPER(NEXTOPER(REGNODE_p(lastbr)))), ender);

            PERL_UNUSED_VAR(shut_gcc_up);
	}
	nextchar(pRExC_state);
	if (freeze_paren) {
	    if (RExC_npar > after_freeze)
	        after_freeze = RExC_npar;
            RExC_npar = freeze_paren;
        }
        br = regbranch(pRExC_state, &flags, 0, depth+1);

	if (br == 0) {
            RETURN_FAIL_ON_RESTART(flags, flagp);
            FAIL2("panic: regbranch returned failure, flags=%#" UVxf, (UV) flags);
        }
        if (!  REGTAIL(pRExC_state, lastbr, br)) {  
            REQUIRE_BRANCHJ(flagp, 0);
        }
	lastbr = br;
	*flagp |= flags & (SPSTART | HASWIDTH | POSTPONED);
    }

    if (have_branch || paren != ':') {
        regnode * br;

	
	switch (paren) {
	case ':':
	    ender = reg_node(pRExC_state, TAIL);
	    break;
	case 1: case 2:
	    ender = reganode(pRExC_state, CLOSE, parno);
            if ( RExC_close_parens ) {
                DEBUG_OPTIMISE_MORE_r(Perl_re_printf( aTHX_ "%*s%*s Setting close paren #%" IVdf " to %d\n", 22, "|    |", (int)(depth * 2 + 1), "", (IV)parno, ender));


                RExC_close_parens[parno]= ender;
	        if (RExC_nestroot == parno)
	            RExC_nestroot = 0;
	    }
            Set_Node_Offset(REGNODE_p(ender), RExC_parse+1); 
            Set_Node_Length(REGNODE_p(ender), 1); 
	    break;
	case 's':
	    ender = reg_node(pRExC_state, SRCLOSE);
            RExC_in_script_run = 0;
	    break;
	case '<':
        case 'a':
        case 'A':
        case 'b':
        case 'B':
	case ',':
	case '=':
	case '!':
	    *flagp &= ~HASWIDTH;
	    
        case 't':   
	case '>':
	    ender = reg_node(pRExC_state, SUCCEED);
	    break;
	case 0:
	    ender = reg_node(pRExC_state, END);
            assert(!RExC_end_op); 
            RExC_end_op = REGNODE_p(ender);
            if (RExC_close_parens) {
                DEBUG_OPTIMISE_MORE_r(Perl_re_printf( aTHX_ "%*s%*s Setting close paren #0 (END) to %d\n", 22, "|    |", (int)(depth * 2 + 1), "", ender));



                RExC_close_parens[0]= ender;
            }
	    break;
	}
        DEBUG_PARSE_r({
            DEBUG_PARSE_MSG("lsbr");
            regprop(RExC_rx, RExC_mysv1, REGNODE_p(lastbr), NULL, pRExC_state);
            regprop(RExC_rx, RExC_mysv2, REGNODE_p(ender), NULL, pRExC_state);
            Perl_re_printf( aTHX_  "~ tying lastbr %s (%" IVdf ") to ender %s (%" IVdf ") offset %" IVdf "\n", SvPV_nolen_const(RExC_mysv1), (IV)lastbr, SvPV_nolen_const(RExC_mysv2), (IV)ender, (IV)(ender - lastbr)




            );
        });
        if (! REGTAIL(pRExC_state, lastbr, ender)) {
            REQUIRE_BRANCHJ(flagp, 0);
        }

	if (have_branch) {
            char is_nothing= 1;
	    if (depth==1)
                RExC_seen |= REG_TOP_LEVEL_BRANCHES_SEEN;

	    
	    for (br = REGNODE_p(ret); br; br = regnext(br)) {
		const U8 op = PL_regkind[OP(br)];
		if (op == BRANCH) {
                    if (! REGTAIL_STUDY(pRExC_state, REGNODE_OFFSET(NEXTOPER(br)), ender))

                    {
                        REQUIRE_BRANCHJ(flagp, 0);
                    }
                    if ( OP(NEXTOPER(br)) != NOTHING || regnext(NEXTOPER(br)) != REGNODE_p(ender))
                        is_nothing= 0;
		}
		else if (op == BRANCHJ) {
                    bool shut_gcc_up = REGTAIL_STUDY(pRExC_state, REGNODE_OFFSET(NEXTOPER(NEXTOPER(br))), ender);

                    PERL_UNUSED_VAR(shut_gcc_up);
                    
                        is_nothing= 0;
		}
	    }
            if (is_nothing) {
                regnode * ret_as_regnode = REGNODE_p(ret);
                br= PL_regkind[OP(ret_as_regnode)] != BRANCH ? regnext(ret_as_regnode)
                               : ret_as_regnode;
                DEBUG_PARSE_r({
                    DEBUG_PARSE_MSG("NADA");
                    regprop(RExC_rx, RExC_mysv1, ret_as_regnode, NULL, pRExC_state);
                    regprop(RExC_rx, RExC_mysv2, REGNODE_p(ender), NULL, pRExC_state);
                    Perl_re_printf( aTHX_  "~ converting ret %s (%" IVdf ") to ender %s (%" IVdf ") offset %" IVdf "\n", SvPV_nolen_const(RExC_mysv1), (IV)REG_NODE_NUM(ret_as_regnode), SvPV_nolen_const(RExC_mysv2), (IV)ender, (IV)(ender - ret)




                    );
                });
                OP(br)= NOTHING;
                if (OP(REGNODE_p(ender)) == TAIL) {
                    NEXT_OFF(br)= 0;
                    RExC_emit= REGNODE_OFFSET(br) + 1;
                } else {
                    regnode *opt;
                    for ( opt= br + 1; opt < REGNODE_p(ender) ; opt++ )
                        OP(opt)= OPTIMIZED;
                    NEXT_OFF(br)= REGNODE_p(ender) - br;
                }
            }
	}
    }

    {
        const char *p;
         
        static const char parens[] = "=!aA<,>Bbt";
         

	if (paren && (p = strchr(parens, paren))) {
	    U8 node = ((p - parens) % 2) ? UNLESSM : IFMATCH;
	    int flag = (p - parens) > 3;

	    if (paren == '>' || paren == 't') {
		node = SUSPEND, flag = 0;
            }

	    reginsert(pRExC_state, node, ret, depth+1);
            Set_Node_Cur_Length(REGNODE_p(ret), parse_start);
	    Set_Node_Offset(REGNODE_p(ret), parse_start + 1);
	    FLAGS(REGNODE_p(ret)) = flag;
            if (! REGTAIL_STUDY(pRExC_state, ret, reg_node(pRExC_state, TAIL)))
            {
                REQUIRE_BRANCHJ(flagp, 0);
            }
	}
    }

    
    if (paren) {
        
	RExC_flags = oregflags | (RExC_flags & RXf_PMf_KEEPCOPY);
        if (DEPENDS_SEMANTICS && RExC_uni_semantics) {
            set_regex_charset(&RExC_flags, REGEX_UNICODE_CHARSET);
        }
	if (RExC_parse >= RExC_end || UCHARAT(RExC_parse) != ')') {
	    RExC_parse = oregcomp_parse;
	    vFAIL("Unmatched (");
	}
	nextchar(pRExC_state);
    }
    else if (!paren && RExC_parse < RExC_end) {
	if (*RExC_parse == ')') {
	    RExC_parse++;
	    vFAIL("Unmatched )");
	}
	else FAIL("Junk on end of regexp");
	NOT_REACHED; 
    }

    if (RExC_in_lookbehind) {
	RExC_in_lookbehind--;
    }
    if (after_freeze > RExC_npar)
        RExC_npar = after_freeze;
    return(ret);
}


STATIC regnode_offset S_regbranch(pTHX_ RExC_state_t *pRExC_state, I32 *flagp, I32 first, U32 depth)
{
    regnode_offset ret;
    regnode_offset chain = 0;
    regnode_offset latest;
    I32 flags = 0, c = 0;
    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_REGBRANCH;

    DEBUG_PARSE("brnc");

    if (first)
	ret = 0;
    else {
	if (RExC_use_BRANCHJ)
	    ret = reganode(pRExC_state, BRANCHJ, 0);
	else {
	    ret = reg_node(pRExC_state, BRANCH);
            Set_Node_Length(REGNODE_p(ret), 1);
        }
    }

    *flagp = WORST;			

    skip_to_be_ignored_text(pRExC_state, &RExC_parse, FALSE  );
    while (RExC_parse < RExC_end && *RExC_parse != '|' && *RExC_parse != ')') {
	flags &= ~TRYAGAIN;
        latest = regpiece(pRExC_state, &flags, depth+1);
	if (latest == 0) {
	    if (flags & TRYAGAIN)
		continue;
            RETURN_FAIL_ON_RESTART(flags, flagp);
            FAIL2("panic: regpiece returned failure, flags=%#" UVxf, (UV) flags);
	}
	else if (ret == 0)
            ret = latest;
	*flagp |= flags&(HASWIDTH|POSTPONED);
	if (chain == 0) 	
	    *flagp |= flags&SPSTART;
	else {
	    
	    MARK_NAUGHTY(1);
            if (! REGTAIL(pRExC_state, chain, latest)) {
                
                REQUIRE_BRANCHJ(flagp, 0);
            }
	}
	chain = latest;
	c++;
    }
    if (chain == 0) {	
	chain = reg_node(pRExC_state, NOTHING);
	if (ret == 0)
	    ret = chain;
    }
    if (c == 1) {
	*flagp |= flags&SIMPLE;
    }

    return ret;
}


STATIC regnode_offset S_regpiece(pTHX_ RExC_state_t *pRExC_state, I32 *flagp, U32 depth)
{
    regnode_offset ret;
    char op;
    char *next;
    I32 flags;
    const char * const origparse = RExC_parse;
    I32 min;
    I32 max = REG_INFTY;

    char *parse_start;

    const char *maxpos = NULL;
    UV uv;

    
    const regnode_offset orig_emit = RExC_emit;

    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_REGPIECE;

    DEBUG_PARSE("piec");

    ret = regatom(pRExC_state, &flags, depth+1);
    if (ret == 0) {
        RETURN_FAIL_ON_RESTART_OR_FLAGS(flags, flagp, TRYAGAIN);
        FAIL2("panic: regatom returned failure, flags=%#" UVxf, (UV) flags);
    }

    op = *RExC_parse;

    if (op == '{' && regcurly(RExC_parse)) {
	maxpos = NULL;

        parse_start = RExC_parse; 

	next = RExC_parse + 1;
	while (isDIGIT(*next) || *next == ',') {
	    if (*next == ',') {
		if (maxpos)
		    break;
		else maxpos = next;
	    }
	    next++;
	}
	if (*next == '}') {		
            const char* endptr;
	    if (!maxpos)
		maxpos = next;
	    RExC_parse++;
            if (isDIGIT(*RExC_parse)) {
                endptr = RExC_end;
                if (!grok_atoUV(RExC_parse, &uv, &endptr))
                    vFAIL("Invalid quantifier in {,}");
                if (uv >= REG_INFTY)
                    vFAIL2("Quantifier in {,} bigger than %d", REG_INFTY - 1);
                min = (I32)uv;
            } else {
                min = 0;
            }
	    if (*maxpos == ',')
		maxpos++;
	    else maxpos = RExC_parse;
            if (isDIGIT(*maxpos)) {
                endptr = RExC_end;
                if (!grok_atoUV(maxpos, &uv, &endptr))
                    vFAIL("Invalid quantifier in {,}");
                if (uv >= REG_INFTY)
                    vFAIL2("Quantifier in {,} bigger than %d", REG_INFTY - 1);
                max = (I32)uv;
            } else {
		max = REG_INFTY;		
            }
	    RExC_parse = next;
	    nextchar(pRExC_state);
            if (max < min) {    
                reginsert(pRExC_state, OPFAIL, orig_emit, depth+1);
                ckWARNreg(RExC_parse, "Quantifier {n,m} with n > m can't match");
                NEXT_OFF(REGNODE_p(orig_emit)) = regarglen[OPFAIL] + NODE_STEP_REGNODE;
                return ret;
            }
            else if (min == max && *RExC_parse == '?')
            {
                ckWARN2reg(RExC_parse + 1, "Useless use of greediness modifier '%c'", *RExC_parse);

            }

	  do_curly:
	    if ((flags&SIMPLE)) {
                if (min == 0 && max == REG_INFTY) {
                    reginsert(pRExC_state, STAR, ret, depth+1);
                    MARK_NAUGHTY(4);
                    RExC_seen |= REG_UNBOUNDED_QUANTIFIER_SEEN;
                    goto nest_check;
                }
                if (min == 1 && max == REG_INFTY) {
                    reginsert(pRExC_state, PLUS, ret, depth+1);
                    MARK_NAUGHTY(3);
                    RExC_seen |= REG_UNBOUNDED_QUANTIFIER_SEEN;
                    goto nest_check;
                }
                MARK_NAUGHTY_EXP(2, 2);
		reginsert(pRExC_state, CURLY, ret, depth+1);
                Set_Node_Offset(REGNODE_p(ret), parse_start+1); 
                Set_Node_Cur_Length(REGNODE_p(ret), parse_start);
	    }
	    else {
		const regnode_offset w = reg_node(pRExC_state, WHILEM);

		FLAGS(REGNODE_p(w)) = 0;
                if (!  REGTAIL(pRExC_state, ret, w)) {
                    REQUIRE_BRANCHJ(flagp, 0);
                }
		if (RExC_use_BRANCHJ) {
		    reginsert(pRExC_state, LONGJMP, ret, depth+1);
		    reginsert(pRExC_state, NOTHING, ret, depth+1);
		    NEXT_OFF(REGNODE_p(ret)) = 3;	
		}
		reginsert(pRExC_state, CURLYX, ret, depth+1);
                                
                Set_Node_Offset(REGNODE_p(ret), parse_start+1);
                Set_Node_Length(REGNODE_p(ret), op == '{' ? (RExC_parse - parse_start) : 1);

		if (RExC_use_BRANCHJ)
                    NEXT_OFF(REGNODE_p(ret)) = 3;   
                if (! REGTAIL(pRExC_state, ret, reg_node(pRExC_state, NOTHING)))
                {
                    REQUIRE_BRANCHJ(flagp, 0);
                }
                RExC_whilem_seen++;
                MARK_NAUGHTY_EXP(1, 4);     
	    }
	    FLAGS(REGNODE_p(ret)) = 0;

	    if (min > 0)
		*flagp = WORST;
	    if (max > 0)
		*flagp |= HASWIDTH;
            ARG1_SET(REGNODE_p(ret), (U16)min);
            ARG2_SET(REGNODE_p(ret), (U16)max);
            if (max == REG_INFTY)
                RExC_seen |= REG_UNBOUNDED_QUANTIFIER_SEEN;

	    goto nest_check;
	}
    }

    if (!ISMULT1(op)) {
	*flagp = flags;
	return(ret);
    }



    

    if (!(flags&HASWIDTH) && op != '?')
      vFAIL("Regexp *+ operand could be empty");



    parse_start = RExC_parse;

    nextchar(pRExC_state);

    *flagp = (op != '+') ? (WORST|SPSTART|HASWIDTH) : (WORST|HASWIDTH);

    if (op == '*') {
	min = 0;
	goto do_curly;
    }
    else if (op == '+') {
	min = 1;
	goto do_curly;
    }
    else if (op == '?') {
	min = 0; max = 1;
	goto do_curly;
    }
  nest_check:
    if (!(flags&(HASWIDTH|POSTPONED)) && max > REG_INFTY/3) {
	ckWARN2reg(RExC_parse, "%" UTF8f " matches null string many times", UTF8fARG(UTF, (RExC_parse >= origparse ? RExC_parse - origparse : 0), origparse));




    }

    if (*RExC_parse == '?') {
	nextchar(pRExC_state);
	reginsert(pRExC_state, MINMOD, ret, depth+1);
        if (! REGTAIL(pRExC_state, ret, ret + NODE_STEP_REGNODE)) {
            REQUIRE_BRANCHJ(flagp, 0);
        }
    }
    else if (*RExC_parse == '+') {
        regnode_offset ender;
        nextchar(pRExC_state);
        ender = reg_node(pRExC_state, SUCCEED);
        if (! REGTAIL(pRExC_state, ret, ender)) {
            REQUIRE_BRANCHJ(flagp, 0);
        }
        reginsert(pRExC_state, SUSPEND, ret, depth+1);
        ender = reg_node(pRExC_state, TAIL);
        if (! REGTAIL(pRExC_state, ret, ender)) {
            REQUIRE_BRANCHJ(flagp, 0);
        }
    }

    if (ISMULT2(RExC_parse)) {
	RExC_parse++;
	vFAIL("Nested quantifiers");
    }

    return(ret);
}

STATIC bool S_grok_bslash_N(pTHX_ RExC_state_t *pRExC_state, regnode_offset * node_p, UV * code_point_p, int * cp_count, I32 * flagp, const bool strict, const U32 depth )







{
 

    char * endbrace;    
    char* p = RExC_parse; 

    SV * substitute_parse = NULL;
    char *orig_end;
    char *save_start;
    I32 flags;

    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_GROK_BSLASH_N;

    GET_RE_DEBUG_FLAGS;

    assert(cBOOL(node_p) ^ cBOOL(code_point_p));  
    assert(! (node_p && cp_count));               

    if (cp_count) {     
        *cp_count = 1;
    }

    
    skip_to_be_ignored_text(pRExC_state, &p, FALSE  );

    
    if (*p != '{' || regcurly(p)) {
        RExC_parse = p;
        if (cp_count) {
            *cp_count = -1;
        }

        if (! node_p) {
            return FALSE;
        }

        *node_p = reg_node(pRExC_state, REG_ANY);
        *flagp |= HASWIDTH|SIMPLE;
        MARK_NAUGHTY(1);
        Set_Node_Length(REGNODE_p(*(node_p)), 1); 
        return TRUE;
    }

    
    if (*RExC_parse != '{') {
        vFAIL("Missing braces on \\N{}");
    }

    RExC_parse++;       

    endbrace = (char *) memchr(RExC_parse, '}', RExC_end - RExC_parse);
    if (! endbrace) { 
        vFAIL2("Missing right brace on \\%c{}", 'N');
    }

    
    REQUIRE_UNI_RULES(flagp, FALSE);

    
    if (endbrace - RExC_parse == 1 && *RExC_parse == '_') {
        RExC_parse = endbrace;
        if (strict) {
            RExC_parse++;   
            vFAIL("Zero length \\N{}");
        }

        if (cp_count) {
            *cp_count = 0;
        }
        nextchar(pRExC_state);
        if (! node_p) {
            return FALSE;
        }

        *node_p = reg_node(pRExC_state, NOTHING);
        return TRUE;
    }

    if (endbrace - RExC_parse < 2 || ! strBEGINs(RExC_parse, "U+")) {

        

        const STRLEN name_len = endbrace - RExC_parse;
        SV *  value_sv;     
        SV ** value_svp;
        const U8 * value;   
        STRLEN value_len;   

        
        if (! RExC_unlexed_names) {
            RExC_unlexed_names = newHV();
        }

        
        if ((value_svp = hv_fetch(RExC_unlexed_names, RExC_parse, name_len, 0)))
        {
            value_sv = *value_svp;
        }
        else { 
            const char * error_msg = NULL;
            value_sv = get_and_check_backslash_N_name(RExC_parse, endbrace, UTF, &error_msg);

            if (error_msg) {
                RExC_parse = endbrace;
                vFAIL(error_msg);
            }

            
            assert (value_sv);

            
            if (! hv_store(RExC_unlexed_names, RExC_parse, name_len, value_sv, 0))
            {
                Perl_croak(aTHX_ "panic: hv_store() unexpectedly failed");
            }
        }

        
        value = (U8 *) SvPV(value_sv, value_len);

        
        if (value_len > 0 && value_len <= (UV) ((SvUTF8(value_sv))
                                               ? UTF8SKIP(value)
                                               : 1))
        {
            
            if (! code_point_p) {
                RExC_parse = p;
                return FALSE;
            }

            
            *code_point_p = (SvUTF8(value_sv))
                            ? valid_utf8_to_uvchr(value, NULL)
                            : *value;

            
            RExC_parse = endbrace;
            nextchar(pRExC_state);
            return TRUE;
        } 

        
        if (cp_count) {
            *cp_count = 0;

            *cp_count = (SvUTF8(value_sv))
                        ? utf8_length(value, value + value_len)
                        : value_len;
        }

        
        if (! node_p) {
            if (! cp_count) {
                RExC_parse = p;
            }
            return FALSE;
        }

        

        substitute_parse = newSVpvs("?:");
        sv_catsv(substitute_parse, value_sv);
        sv_catpv(substitute_parse, ")");


        
        assert(! RExC_recode_x_to_native);


    }
    else {   
        Size_t count = 0;   

        

        RExC_parse += 2;    

        

        do {    
            UV cp = 0;
            char * start_digit;     
            if (! isXDIGIT(*RExC_parse)) {
                RExC_parse++;
                vFAIL("Invalid hexadecimal number in \\N{U+...}");
            }

            start_digit = RExC_parse;
            count++;

            
            do {
                
                if (cp > MAX_LEGAL_CP >> 4) {

                    
                    do {
                        RExC_parse ++;
                    } while (isXDIGIT(*RExC_parse) || *RExC_parse == '_');

                    
                    vFAIL4("Use of code point 0x%.*s is not allowed; the" " permissible max is 0x%" UVxf, (int) (RExC_parse - start_digit), start_digit, MAX_LEGAL_CP);


                }

                
                cp  = (cp << 4) + READ_XDIGIT(RExC_parse);

                
                if (*RExC_parse == '_' && isXDIGIT(RExC_parse[1])) {
                    RExC_parse++;
                }
            } while (isXDIGIT(*RExC_parse));

            
            if (RExC_parse >= endbrace) {   
                if (count != 1) {
                    goto do_concat;
                }

                
                if (! code_point_p) {
                    RExC_parse = p;
                    return FALSE;
                }

                
                *code_point_p = UNI_TO_NATIVE(cp);
                RExC_parse = endbrace;
                nextchar(pRExC_state);
                return TRUE;
            }

            
            if (*RExC_parse != '.' || RExC_parse + 1 >= endbrace) {
                RExC_parse += (RExC_orig_utf8)  
                                ? UTF8SKIP(RExC_parse)
                                : 1;
                if (RExC_parse >= endbrace) { 
                    RExC_parse = endbrace;
                }
                vFAIL("Invalid hexadecimal number in \\N{U+...}");
            }

            
            if (! node_p && ! cp_count) {
                return FALSE;
            }

            

            if (node_p && count == 1) {
                substitute_parse = newSVpvs("?:");
            }

          do_concat:

            if (node_p) {
                
                sv_catpvs(substitute_parse, "\\x{");
                sv_catpvn(substitute_parse, start_digit, RExC_parse - start_digit);
                sv_catpvs(substitute_parse, "}");
            }

            
            RExC_parse++;
            count++;

        } while (RExC_parse < endbrace);

        if (! node_p) { 
            assert (cp_count);

            *cp_count = count;
            return FALSE;
        }

        sv_catpvs(substitute_parse, ")");


        
        RExC_recode_x_to_native = 1;


    }

    
    save_start = RExC_start;
    orig_end = RExC_end;

    RExC_parse = RExC_start = SvPVX(substitute_parse);
    RExC_end = RExC_parse + SvCUR(substitute_parse);
    TURN_OFF_WARNINGS_IN_SUBSTITUTE_PARSE;

    *node_p = reg(pRExC_state, 1, &flags, depth+1);

    
    RESTORE_WARNINGS;
    RExC_start = save_start;
    RExC_parse = endbrace;
    RExC_end = orig_end;

    RExC_recode_x_to_native = 0;


    SvREFCNT_dec_NN(substitute_parse);

    if (! *node_p) {
        RETURN_FAIL_ON_RESTART(flags, flagp);
        FAIL2("panic: reg returned failure to grok_bslash_N, flags=%#" UVxf, (UV) flags);
    }
    *flagp |= flags&(HASWIDTH|SPSTART|SIMPLE|POSTPONED);

    nextchar(pRExC_state);

    return TRUE;
}


PERL_STATIC_INLINE U8 S_compute_EXACTish(RExC_state_t *pRExC_state)
{
    U8 op;

    PERL_ARGS_ASSERT_COMPUTE_EXACTISH;

    if (! FOLD) {
        return (LOC)
                ? EXACTL : EXACT;
    }

    op = get_regex_charset(RExC_flags);
    if (op >= REGEX_ASCII_RESTRICTED_CHARSET) {
        op--; 
    }

    return op + EXACTF;
}

STATIC bool S_new_regcurly(const char *s, const char *e)
{
    

    bool has_min = FALSE;
    bool has_max = FALSE;

    PERL_ARGS_ASSERT_NEW_REGCURLY;

    if (s >= e || *s++ != '{')
	return FALSE;

    while (s < e && isSPACE(*s)) {
        s++;
    }
    while (s < e && isDIGIT(*s)) {
        has_min = TRUE;
        s++;
    }
    while (s < e && isSPACE(*s)) {
        s++;
    }

    if (*s == ',') {
	s++;
        while (s < e && isSPACE(*s)) {
            s++;
        }
        while (s < e && isDIGIT(*s)) {
            has_max = TRUE;
            s++;
        }
        while (s < e && isSPACE(*s)) {
            s++;
        }
    }

    return s < e && *s == '}' && (has_min || has_max);
}



static I32 S_backref_value(char *p, char *e)
{
    const char* endptr = e;
    UV val;
    if (grok_atoUV(p, &val, &endptr) && val <= I32_MAX)
        return (I32)val;
    return I32_MAX;
}




STATIC regnode_offset S_regatom(pTHX_ RExC_state_t *pRExC_state, I32 *flagp, U32 depth)
{
    dVAR;
    regnode_offset ret = 0;
    I32 flags = 0;
    char *parse_start;
    U8 op;
    int invert = 0;
    U8 arg;

    GET_RE_DEBUG_FLAGS_DECL;

    *flagp = WORST;		

    DEBUG_PARSE("atom");

    PERL_ARGS_ASSERT_REGATOM;

  tryagain:
    parse_start = RExC_parse;
    assert(RExC_parse < RExC_end);
    switch ((U8)*RExC_parse) {
    case '^':
	RExC_seen_zerolen++;
	nextchar(pRExC_state);
	if (RExC_flags & RXf_PMf_MULTILINE)
	    ret = reg_node(pRExC_state, MBOL);
	else ret = reg_node(pRExC_state, SBOL);
        Set_Node_Length(REGNODE_p(ret), 1); 
	break;
    case '$':
	nextchar(pRExC_state);
	if (*RExC_parse)
	    RExC_seen_zerolen++;
	if (RExC_flags & RXf_PMf_MULTILINE)
	    ret = reg_node(pRExC_state, MEOL);
	else ret = reg_node(pRExC_state, SEOL);
        Set_Node_Length(REGNODE_p(ret), 1); 
	break;
    case '.':
	nextchar(pRExC_state);
	if (RExC_flags & RXf_PMf_SINGLELINE)
	    ret = reg_node(pRExC_state, SANY);
	else ret = reg_node(pRExC_state, REG_ANY);
	*flagp |= HASWIDTH|SIMPLE;
	MARK_NAUGHTY(1);
        Set_Node_Length(REGNODE_p(ret), 1); 
	break;
    case '[':
    {
	char * const oregcomp_parse = ++RExC_parse;
        ret = regclass(pRExC_state, flagp, depth+1, FALSE, TRUE, FALSE, (bool) RExC_strict, TRUE, NULL);





        if (ret == 0) {
            RETURN_FAIL_ON_RESTART_FLAGP(flagp);
            FAIL2("panic: regclass returned failure to regatom, flags=%#" UVxf, (UV) *flagp);
        }
	if (*RExC_parse != ']') {
	    RExC_parse = oregcomp_parse;
	    vFAIL("Unmatched [");
	}
	nextchar(pRExC_state);
        Set_Node_Length(REGNODE_p(ret), RExC_parse - oregcomp_parse + 1); 
	break;
    }
    case '(':
	nextchar(pRExC_state);
        ret = reg(pRExC_state, 2, &flags, depth+1);
	if (ret == 0) {
		if (flags & TRYAGAIN) {
		    if (RExC_parse >= RExC_end) {
			 
			*flagp |= TRYAGAIN;
			return(0);
		    }
		    goto tryagain;
		}
                RETURN_FAIL_ON_RESTART(flags, flagp);
                FAIL2("panic: reg returned failure to regatom, flags=%#" UVxf, (UV) flags);
	}
	*flagp |= flags&(HASWIDTH|SPSTART|SIMPLE|POSTPONED);
	break;
    case '|':
    case ')':
	if (flags & TRYAGAIN) {
	    *flagp |= TRYAGAIN;
	    return 0;
	}
	vFAIL("Internal urp");
				
	break;
    case '?':
    case '+':
    case '*':
	RExC_parse++;
	vFAIL("Quantifier follows nothing");
	break;
    case '\\':
	
	RExC_parse++;
	switch ((U8)*RExC_parse) {
	
	case 'A':
	    RExC_seen_zerolen++;
	    ret = reg_node(pRExC_state, SBOL);
            
            FLAGS(REGNODE_p(ret)) = 1;
	    *flagp |= SIMPLE;
	    goto finish_meta_pat;
	case 'G':
	    ret = reg_node(pRExC_state, GPOS);
            RExC_seen |= REG_GPOS_SEEN;
	    *flagp |= SIMPLE;
	    goto finish_meta_pat;
	case 'K':
	    RExC_seen_zerolen++;
	    ret = reg_node(pRExC_state, KEEPS);
	    *flagp |= SIMPLE;
	    
            RExC_seen |= REG_LOOKBEHIND_SEEN;
	    goto finish_meta_pat;
	case 'Z':
	    ret = reg_node(pRExC_state, SEOL);
	    *flagp |= SIMPLE;
	    RExC_seen_zerolen++;		
	    goto finish_meta_pat;
	case 'z':
	    ret = reg_node(pRExC_state, EOS);
	    *flagp |= SIMPLE;
	    RExC_seen_zerolen++;		
	    goto finish_meta_pat;
	case 'C':
	    vFAIL("\\C no longer supported");
	case 'X':
	    ret = reg_node(pRExC_state, CLUMP);
	    *flagp |= HASWIDTH;
	    goto finish_meta_pat;

	case 'W':
            invert = 1;
            
	case 'w':
            arg = ANYOF_WORDCHAR;
            goto join_posix;

	case 'B':
            invert = 1;
            
	case 'b':
          {
            U8 flags = 0;
	    regex_charset charset = get_regex_charset(RExC_flags);

	    RExC_seen_zerolen++;
            RExC_seen |= REG_LOOKBEHIND_SEEN;
	    op = BOUND + charset;

	    if (RExC_parse >= RExC_end || *(RExC_parse + 1) != '{') {
                flags = TRADITIONAL_BOUND;
                if (op > BOUNDA) {  
                    op = BOUNDA;
                }
            }
            else {
                STRLEN length;
                char name = *RExC_parse;
                char * endbrace = NULL;
                RExC_parse += 2;
                endbrace = (char *) memchr(RExC_parse, '}', RExC_end - RExC_parse);

                if (! endbrace) {
                    vFAIL2("Missing right brace on \\%c{}", name);
                }
                
                if (endbrace == RExC_parse) {
                    RExC_parse++;  
                    vFAIL2("Empty \\%c{}", name);
                }
                length = endbrace - RExC_parse;
                
                switch (*RExC_parse) {
                    case 'g':
                        if (    length != 1 && (memNEs(RExC_parse + 1, length - 1, "cb")))
                        {
                            goto bad_bound_type;
                        }
                        flags = GCB_BOUND;
                        break;
                    case 'l':
                        if (length != 2 || *(RExC_parse + 1) != 'b') {
                            goto bad_bound_type;
                        }
                        flags = LB_BOUND;
                        break;
                    case 's':
                        if (length != 2 || *(RExC_parse + 1) != 'b') {
                            goto bad_bound_type;
                        }
                        flags = SB_BOUND;
                        break;
                    case 'w':
                        if (length != 2 || *(RExC_parse + 1) != 'b') {
                            goto bad_bound_type;
                        }
                        flags = WB_BOUND;
                        break;
                    default:
                      bad_bound_type:
                        RExC_parse = endbrace;
			vFAIL2utf8f( "'%" UTF8f "' is an unknown bound type", UTF8fARG(UTF, length, endbrace - length));

                        NOT_REACHED; 
                }
                RExC_parse = endbrace;
                REQUIRE_UNI_RULES(flagp, 0);

                if (op == BOUND) {
                    op = BOUNDU;
                }
                else if (op >= BOUNDA) {  
                    op = BOUNDU;
                    length += 4;

                    
                    ckWARN4reg(RExC_parse + 1,   "Using /u for '%.*s' instead of /%s", (unsigned) length, endbrace - length + 1, (charset == REGEX_ASCII_RESTRICTED_CHARSET)



                              ? ASCII_RESTRICT_PAT_MODS : ASCII_MORE_RESTRICT_PAT_MODS);
                }
	    }

            if (op == BOUND) {
                RExC_seen_d_op = TRUE;
            }
            else if (op == BOUNDL) {
                RExC_contains_locale = 1;
            }

            if (invert) {
                op += NBOUND - BOUND;
            }

	    ret = reg_node(pRExC_state, op);
            FLAGS(REGNODE_p(ret)) = flags;

	    *flagp |= SIMPLE;

	    goto finish_meta_pat;
          }

	case 'D':
            invert = 1;
            
	case 'd':
            arg = ANYOF_DIGIT;
            if (! DEPENDS_SEMANTICS) {
                goto join_posix;
            }

            
            op = POSIXU;
            goto join_posix_op_known;

	case 'R':
	    ret = reg_node(pRExC_state, LNBREAK);
	    *flagp |= HASWIDTH|SIMPLE;
	    goto finish_meta_pat;

	case 'H':
            invert = 1;
            
	case 'h':
	    arg = ANYOF_BLANK;
            op = POSIXU;
            goto join_posix_op_known;

	case 'V':
            invert = 1;
            
	case 'v':
	    arg = ANYOF_VERTWS;
            op = POSIXU;
            goto join_posix_op_known;

	case 'S':
            invert = 1;
            
	case 's':
            arg = ANYOF_SPACE;

          join_posix:

	    op = POSIXD + get_regex_charset(RExC_flags);
            if (op > POSIXA) {  
                op = POSIXA;
            }
            else if (op == POSIXL) {
                RExC_contains_locale = 1;
            }
            else if (op == POSIXD) {
                RExC_seen_d_op = TRUE;
            }

          join_posix_op_known:

            if (invert) {
                op += NPOSIXD - POSIXD;
            }

	    ret = reg_node(pRExC_state, op);
            FLAGS(REGNODE_p(ret)) = namedclass_to_classnum(arg);

	    *flagp |= HASWIDTH|SIMPLE;
            

          finish_meta_pat:
            if (   UCHARAT(RExC_parse + 1) == '{' && UNLIKELY(! new_regcurly(RExC_parse + 1, RExC_end)))
            {
                RExC_parse += 2;
                vFAIL("Unescaped left brace in regex is illegal here");
            }
	    nextchar(pRExC_state);
            Set_Node_Length(REGNODE_p(ret), 2); 
	    break;
	case 'p':
	case 'P':
            RExC_parse--;

            ret = regclass(pRExC_state, flagp, depth+1, TRUE, FALSE, FALSE, (bool) RExC_strict, TRUE, NULL);





            RETURN_FAIL_ON_RESTART_FLAGP(flagp);
            
            if (!ret)
                FAIL2("panic: regclass returned failure to regatom, flags=%#" UVxf, (UV) *flagp);

            RExC_parse--;

            Set_Node_Offset(REGNODE_p(ret), parse_start);
            Set_Node_Cur_Length(REGNODE_p(ret), parse_start - 2);
            nextchar(pRExC_state);
	    break;
        case 'N':
            
            ++RExC_parse;
            if (grok_bslash_N(pRExC_state, &ret, NULL, NULL, flagp, RExC_strict, depth)





            ) {
                break;
            }

            RETURN_FAIL_ON_RESTART_FLAGP(flagp);

            
            RExC_parse = parse_start;
            goto defchar;

	case 'k':    
      parse_named_seq:
        {
            char ch;
            if (   RExC_parse >= RExC_end - 1 || ((   ch = RExC_parse[1]) != '<' && ch != '\'' && ch != '{'))


            {
	        RExC_parse++;
		
	        vFAIL2("Sequence %.2s... not terminated", parse_start);
	    } else {
		RExC_parse += 2;
                ret = handle_named_backref(pRExC_state, flagp, parse_start, (ch == '<')


                                           ? '>' : (ch == '{')
                                             ? '}' : '\'');
            }
            break;
	}
	case 'g':
	case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
	    {
		I32 num;
		bool hasbrace = 0;

		if (*RExC_parse == 'g') {
                    bool isrel = 0;

		    RExC_parse++;
		    if (*RExC_parse == '{') {
		        RExC_parse++;
		        hasbrace = 1;
		    }
		    if (*RExC_parse == '-') {
		        RExC_parse++;
		        isrel = 1;
		    }
		    if (hasbrace && !isDIGIT(*RExC_parse)) {
		        if (isrel) RExC_parse--;
                        RExC_parse -= 2;
		        goto parse_named_seq;
                    }

                    if (RExC_parse >= RExC_end) {
                        goto unterminated_g;
                    }
                    num = S_backref_value(RExC_parse, RExC_end);
                    if (num == 0)
                        vFAIL("Reference to invalid group 0");
                    else if (num == I32_MAX) {
                         if (isDIGIT(*RExC_parse))
			    vFAIL("Reference to nonexistent group");
                        else unterminated_g:
                            vFAIL("Unterminated \\g... pattern");
                    }

                    if (isrel) {
                        num = RExC_npar - num;
                        if (num < 1)
                            vFAIL("Reference to nonexistent or unclosed group");
                    }
                }
                else {
                    num = S_backref_value(RExC_parse, RExC_end);
                    
                    

                    if (  num > 9  && num >= RExC_npar  && *RExC_parse != '8'  && *RExC_parse != '9' ) {








                        
                        RExC_parse = parse_start;
                        goto defchar;
                    }
                }

                
                while (isDIGIT(*RExC_parse))
                    RExC_parse++;
                if (hasbrace) {
                    if (*RExC_parse != '}')
                        vFAIL("Unterminated \\g{...} pattern");
                    RExC_parse++;
                }
                if (num >= (I32)RExC_npar) {

                    
                    if (ALL_PARENS_COUNTED)  {
                        if (num >= RExC_total_parens)  {
                            vFAIL("Reference to nonexistent group");
                        }
                    }
                    else {
                        REQUIRE_PARENS_PASS;
                    }
                }
                RExC_sawback = 1;
                ret = reganode(pRExC_state, ((! FOLD)
                                 ? REF : (ASCII_FOLD_RESTRICTED)
                                   ? REFFA : (AT_LEAST_UNI_SEMANTICS)
                                     ? REFFU : (LOC)
                                       ? REFFL : REFF), num);

                if (OP(REGNODE_p(ret)) == REFF) {
                    RExC_seen_d_op = TRUE;
                }
                *flagp |= HASWIDTH;

                
                Set_Node_Offset(REGNODE_p(ret), parse_start);
                Set_Node_Cur_Length(REGNODE_p(ret), parse_start-1);
                skip_to_be_ignored_text(pRExC_state, &RExC_parse, FALSE  );
	    }
	    break;
	case '\0':
	    if (RExC_parse >= RExC_end)
		FAIL("Trailing \\");
	    
	default:
	    
            RExC_parse = parse_start;
	    goto defchar;
	} 
	break;

    case '#':

        
        assert((RExC_flags & RXf_PMf_EXTENDED) == 0);
	

	

    default:
	  defchar: {

            

	    STRLEN len = 0;
	    UV ender = 0;
	    char *p;
	    char *s;




	    char *s0;
	    U8 upper_parse = MAX_NODE_STRING_SIZE;

            
            U8 node_type = EXACT;

            
            Ptrdiff_t initial_size = STR_SZ(256);

            bool next_is_quantifier;
            char * oldp = NULL;

            
            bool maybe_exactfu = FOLD && (DEPENDS_SEMANTICS || LOC);

            
            U8 maybe_SIMPLE = SIMPLE;

            
            bool requires_utf8_target = FALSE;

            
            bool has_ss = FALSE;

            
            bool has_micro_sign = FALSE;

            
            ret = regnode_guts(pRExC_state, node_type, initial_size, "exact");
            FILL_NODE(ret, node_type);
            RExC_emit++;

	    s = STRING(REGNODE_p(ret));

            s0 = s;

	  reparse:

            

            assert( ! UTF      || UTF8_IS_INVARIANT(UCHARAT(RExC_parse))
                   || UTF8_IS_START(UCHARAT(RExC_parse)));

            
	    for (p = RExC_parse; len < upper_parse && p < RExC_end; ) {

                
                Size_t added_len = 1;

		oldp = p;

                
                assert(   (RExC_flags & RXf_PMf_EXTENDED) == 0 || ! is_PATWS_safe((p), RExC_end, UTF));

		switch ((U8)*p) {
		case '^':
		case '$':
		case '.':
		case '[':
		case '(':
		case ')':
		case '|':
		    goto loopdone;
		case '\\':
		    

		    switch ((U8)*++p) {

		    
		    case 'A':             
		    case 'b': case 'B':   
		    case 'C':             
		    case 'd': case 'D':   
		    case 'g': case 'G':   
		    case 'h': case 'H':   
		    case 'k': case 'K':   
		    case 'p': case 'P':   
		              case 'R':   
		    case 's': case 'S':   
		    case 'v': case 'V':   
		    case 'w': case 'W':   
                    case 'X':             
		    case 'z': case 'Z':   
			--p;
			goto loopdone;

	            
		    case 'n':
			ender = '\n';
			p++;
			break;
		    case 'N': 
                        RExC_parse = p + 1;
                        if (! grok_bslash_N(pRExC_state, NULL, &ender, NULL, flagp, RExC_strict, depth)





                        ) {
                            if (*flagp & NEED_UTF8)
                                FAIL("panic: grok_bslash_N set NEED_UTF8");
                            RETURN_FAIL_ON_RESTART_FLAGP(flagp);

                            
                            RExC_parse = p = oldp;
                            goto loopdone;
                        }
                        p = RExC_parse;
                        RExC_parse = parse_start;

                        
                        if (node_type == EXACTF) {
                            node_type = EXACTFU;

                            
                            if (! maybe_exactfu) {
                                len = 0;
                                s = s0;
                                goto reparse;
                            }
                        }

                        break;
		    case 'r':
			ender = '\r';
			p++;
			break;
		    case 't':
			ender = '\t';
			p++;
			break;
		    case 'f':
			ender = '\f';
			p++;
			break;
		    case 'e':
			ender = ESC_NATIVE;
			p++;
			break;
		    case 'a':
			ender = '\a';
			p++;
			break;
		    case 'o':
			{
			    UV result;
			    const char* error_msg;

			    bool valid = grok_bslash_o(&p, RExC_end, &result, &error_msg, TO_OUTPUT_WARNINGS(p), (bool) RExC_strict, TRUE, UTF);






			    if (! valid) {
				RExC_parse = p;	
				vFAIL(error_msg);
			    }
                            UPDATE_WARNINGS_LOC(p - 1);
                            ender = result;
			    break;
			}
		    case 'x':
			{
                            UV result = UV_MAX; 
			    const char* error_msg;

			    bool valid = grok_bslash_x(&p, RExC_end, &result, &error_msg, TO_OUTPUT_WARNINGS(p), (bool) RExC_strict, TRUE, UTF);






			    if (! valid) {
				RExC_parse = p;	
				vFAIL(error_msg);
			    }
                            UPDATE_WARNINGS_LOC(p - 1);
                            ender = result;

                            if (ender < 0x100) {

                                if (RExC_recode_x_to_native) {
                                    ender = LATIN1_TO_NATIVE(ender);
                                }

			    }
			    break;
			}
		    case 'c':
			p++;
			ender = grok_bslash_c(*p, TO_OUTPUT_WARNINGS(p));
                        UPDATE_WARNINGS_LOC(p);
                        p++;
			break;
                    case '8': case '9': 
                        --p;
                        
                        goto loopdone;
                    case '1': case '2': case '3':case '4':
		    case '5': case '6': case '7':
                        

                        
                        if ( !isDIGIT(p[1]) || S_backref_value(p, RExC_end) < RExC_npar)
                        {  
                            --p;
                            goto loopdone;
                        }
                        
                    case '0':
			{
			    I32 flags = PERL_SCAN_SILENT_ILLDIGIT;
			    STRLEN numlen = 3;
			    ender = grok_oct(p, &numlen, &flags, NULL);
			    p += numlen;
                            if (   isDIGIT(*p)  
                                && ckWARN(WARN_REGEXP)
                                && numlen < 3)
                            {
				reg_warn_non_literal_string( p + 1, form_short_octal_warning(p, numlen));

                            }
			}
			break;
		    case '\0':
			if (p >= RExC_end)
			    FAIL("Trailing \\");
			
		    default:
			if (isALPHANUMERIC(*p)) {
                            
                            if (! isALPHA(*p) || *(p + 1) != '{') {
                                ckWARN2reg(p + 1, "Unrecognized escape \\%.1s" " passed through", p);
                            }
			}
			goto normal_default;
		    } 
		    break;
		case '{':
                    
		    if (len || (p > RExC_start && isALPHA_A(*(p - 1)))) {
                        if (      RExC_strict || (  p > parse_start + 1 && isALPHA_A(*(p - 1))

                                && *(p - 2) == '\\')
                            || new_regcurly(p, RExC_end))
                        {
                            RExC_parse = p + 1;
                            vFAIL("Unescaped left brace in regex is " "illegal here");
                        }
                        ckWARNreg(p + 1, "Unescaped left brace in regex is" " passed through");
		    }
		    goto normal_default;
                case '}':
                case ']':
                    if (p > RExC_parse && RExC_strict) {
                        ckWARN2reg(p + 1, "Unescaped literal '%c'", *p);
                    }
		    
		default:    
		  normal_default:
		    if (! UTF8_IS_INVARIANT(*p) && UTF) {
			STRLEN numlen;
			ender = utf8n_to_uvchr((U8*)p, RExC_end - p, &numlen, UTF8_ALLOW_DEFAULT);
			p += numlen;
		    }
		    else ender = (U8) *p++;
		    break;
		} 

		

                if (ender > 255) {
                    REQUIRE_UTF8(flagp);
                }

                
                skip_to_be_ignored_text(pRExC_state, &p, FALSE  );

                

                next_is_quantifier =    LIKELY(p < RExC_end)
                                     && UNLIKELY(ISMULT2(p));

                if (next_is_quantifier && LIKELY(len)) {
                    p = oldp;
                    goto loopdone;
                }

                

                if (! FOLD) {  

                      not_fold_common:
                        if (UVCHR_IS_INVARIANT(ender) || ! UTF) {
                            *(s++) = (char) ender;
                        }
                        else {
                            U8 * new_s = uvchr_to_utf8((U8*)s, ender);
                            added_len = (char *) new_s - s;
                            s = (char *) new_s;

                            if (ender > 255)  {
                                requires_utf8_target = TRUE;
                            }
                        }
                }
                else if (LOC && is_PROBLEMATIC_LOCALE_FOLD_cp(ender)) {

                    
                    if (! len) {
                        node_type = EXACTFL;
                        RExC_contains_locale = 1;
                    }
                    else if (node_type == EXACT) {
                        p = oldp;
                        goto loopdone;
                    }

                    
                    maybe_exactfu = FALSE;

                    
                    goto not_fold_common;
                }
                else  if (   (ender < 256 && ! IS_IN_SOME_FOLD_L1(ender))
                         || (ender > 255 && ! _invlist_contains_cp(PL_in_some_fold, ender)))
                {
                    
                    if (len && node_type != EXACT) {
                        p = oldp;
                        goto loopdone;
                    }

                    
                    goto not_fold_common;
                }
                else {  

                    
                    if (! len) {
                        node_type = compute_EXACTish(pRExC_state);
                    }
                    else if (node_type == EXACT) {
                        p = oldp;
                        goto loopdone;
                    }

                    if (UTF) {  
                        if (UVCHR_IS_INVARIANT(ender)) {
                            *(s)++ = (U8) toFOLD(ender);
                        }
                        else {
                            ender = _to_uni_fold_flags( ender, (U8 *) s, &added_len, FOLD_FLAGS_FULL | ((ASCII_FOLD_RESTRICTED)



                                                    ? FOLD_FLAGS_NOMIX_ASCII : 0));
                            s += added_len;

                            if (   ender > 255 && LIKELY(ender != GREEK_SMALL_LETTER_MU))
                            {
                                
                                requires_utf8_target = TRUE;
                            }
                        }
                    }
                    else {

                        
                        if (PL_fold[ender] != PL_fold_latin1[ender]) {
                            maybe_exactfu = FALSE;
                        }




                        

                        if (   UNLIKELY(ender == LATIN_SMALL_LETTER_SHARP_S)
                                 || (   isALPHA_FOLD_EQ(ender, 's')
                                     && len > 0 && isALPHA_FOLD_EQ(*(s-1), 's')))
                        {
                            

                            has_ss = TRUE;
                            maybe_exactfu = FALSE;  
                            if (UNLIKELY(ender == LATIN_SMALL_LETTER_SHARP_S)) {
                                maybe_SIMPLE = 0;
                                if (node_type == EXACTFU) {
                                    *(s++) = 's';

                                    
                                    ender = 's';
                                    added_len = 2;
                                }
                            }
                        }


                        else if (UNLIKELY(ender == MICRO_SIGN)) {
                            has_micro_sign = TRUE;
                        }

                        *(s++) = (DEPENDS_SEMANTICS)
                                 ? (char) toFOLD(ender)

                                   
                                 : (char) toLOWER_L1(ender);
                    }
		} 

                len += added_len;

		if (next_is_quantifier) {

                    
                    goto loopdone;
		}

	    } 

            
            if (FOLD && p < RExC_end && upper_parse == MAX_NODE_STRING_SIZE) {
                PERL_UINT_FAST8_T backup_count = 0;

                const STRLEN full_len = len;

		assert(len >= MAX_NODE_STRING_SIZE);

                

		if (! UTF) {

                    
                    if (ASCII_FOLD_RESTRICTED) {
                        goto loopdone;
                    }

                    while (--s >= s0 && IS_NON_FINAL_FOLD(*s)) {
                        backup_count++;
                    }
                    len = s - s0 + 1;
		}
                else {

                    
                    s = (char *) utf8_hop_back((U8 *) s, -1, (U8 *) s0);

                    while (s >= s0) {   
                        if (UTF8_IS_INVARIANT(*s)) {

                            
                            if (ASCII_FOLD_RESTRICTED || ! IS_NON_FINAL_FOLD(*s))
                            {
                                break;
                            }
                        }
                        else if (UTF8_IS_DOWNGRADEABLE_START(*s)) {
                            if (! IS_NON_FINAL_FOLD(EIGHT_BIT_UTF8_TO_NATIVE( *s, *(s+1))))
                            {
                                break;
                            }
                        }
                        else if (! _invlist_contains_cp( PL_NonFinalFold, valid_utf8_to_uvchr((U8 *) s, NULL)))

                        {
                            break;
                        }

                        
                        s = (s == s0) ? s -1 : (char *) utf8_hop((U8 *) s, -1);
                        backup_count++;
                    } 

                    
                    len = (s < s0) ? 0 : s - s0 + UTF8SKIP(s);
		}

                
                if (len == 0) {
                    len = full_len;

                } else {

                    
                    if (backup_count == 0) {
                        goto loopdone;
                    }
                    else if (backup_count == 1) {

                        
                        p = oldp;
                        goto loopdone;
                    }

                    
                    upper_parse = len;
                    len = 0;
                    s = s0;
                    goto reparse;
                }
	    }   

          loopdone:   

            
            change_engine_size(pRExC_state, - (Ptrdiff_t) (initial_size - STR_SZ(len)));

            
            if (len == 0) {
                OP(REGNODE_p(ret)) = NOTHING;
            }
            else {

                
                if (node_type == EXACT) {
                    if (LOC) {
                        node_type = EXACTL;
                    }
                    else if (requires_utf8_target) {
                        node_type = EXACT_ONLY8;
                    }
                } else if (FOLD) {
                    if (    UNLIKELY(has_micro_sign || has_ss)
                        && (node_type == EXACTFU || (   node_type == EXACTF && maybe_exactfu)))
                    {   
                        assert(! UTF);
                        node_type = EXACTFUP;
                    }
                    else if (node_type == EXACTFL) {

                        
                        if (maybe_exactfu) {
                            node_type = EXACTFLU8;
                        }
                        else if (UNLIKELY( _invlist_contains_cp(PL_HasMultiCharFold, ender)))
                        {
                            
                            maybe_SIMPLE = 0;
                        }
                    }
                    else if (node_type == EXACTF) {  

                        
                        if (! maybe_exactfu) {
                            RExC_seen_d_op = TRUE;
                        }
                        else if (   isALPHA_FOLD_EQ(* STRING(REGNODE_p(ret)), 's')
                                 || isALPHA_FOLD_EQ(ender, 's'))
                        {
                            

                            node_type = EXACTFU_S_EDGE;
                        }
                        else {
                            node_type = EXACTFU;
                        }
                    }

                    if (requires_utf8_target && node_type == EXACTFU) {
                        node_type = EXACTFU_ONLY8;
                    }
                }

                OP(REGNODE_p(ret)) = node_type;
                STR_LEN(REGNODE_p(ret)) = len;
                RExC_emit += STR_SZ(len);

                
                if (len > (Size_t) ((UTF) ? UVCHR_SKIP(ender) : 1)) {
                    maybe_SIMPLE = 0;
                }

                *flagp |= HASWIDTH | maybe_SIMPLE;
            }

            Set_Node_Length(REGNODE_p(ret), p - parse_start - 1);
            RExC_parse = p;

	    {
		
		IV iv = len;
		if (iv < 0)
		    vFAIL("Internal disaster");
	    }

	} 
	break;
    } 

    
    skip_to_be_ignored_text(pRExC_state, &RExC_parse, FALSE  );
    if (   *RExC_parse == '{' && OP(REGNODE_p(ret)) != SBOL && ! regcurly(RExC_parse))
    {
        if (RExC_strict || new_regcurly(RExC_parse, RExC_end)) {
            RExC_parse++;
            vFAIL("Unescaped left brace in regex is illegal here");
        }
        ckWARNreg(RExC_parse + 1, "Unescaped left brace in regex is" " passed through");
    }

    return(ret);
}


STATIC void S_populate_ANYOF_from_invlist(pTHX_ regnode *node, SV** invlist_ptr)
{
    

    dVAR;

    PERL_ARGS_ASSERT_POPULATE_ANYOF_FROM_INVLIST;
    assert(PL_regkind[OP(node)] == ANYOF);

    
    if (OP(node) == ANYOFH) {
        return;
    }

    ANYOF_BITMAP_ZERO(node);
    if (*invlist_ptr) {

	
	bool change_invlist = FALSE;

	UV start, end;

	
	invlist_iterinit(*invlist_ptr);
	while (invlist_iternext(*invlist_ptr, &start, &end)) {
	    UV high;
	    int i;

            if (end == UV_MAX && start <= NUM_ANYOF_CODE_POINTS) {
                ANYOF_FLAGS(node) |= ANYOF_MATCHES_ALL_ABOVE_BITMAP;
            }

	    
	    if (start >= NUM_ANYOF_CODE_POINTS) {
		break;
	    }

	    change_invlist = TRUE;

	    
	    high = (end < NUM_ANYOF_CODE_POINTS - 1)
                   ? end : NUM_ANYOF_CODE_POINTS - 1;
	    for (i = start; i <= (int) high; i++) {
		if (! ANYOF_BITMAP_TEST(node, i)) {
		    ANYOF_BITMAP_SET(node, i);
		}
	    }
	}
	invlist_iterfinish(*invlist_ptr);

        
	if (change_invlist) {
	    _invlist_subtract(*invlist_ptr, PL_InBitmap, invlist_ptr);
	}
        if (ANYOF_FLAGS(node) & ANYOF_MATCHES_ALL_ABOVE_BITMAP) {
	    _invlist_intersection(*invlist_ptr, PL_InBitmap, invlist_ptr);
	}

	
	if (_invlist_len(*invlist_ptr) == 0) {
	    SvREFCNT_dec_NN(*invlist_ptr);
	    *invlist_ptr = NULL;
	}
    }
}



































STATIC int S_handle_possible_posix(pTHX_ RExC_state_t *pRExC_state,  const char * const s, char ** updated_parse_ptr, AV ** posix_warnings, const bool check_only )






{
    

    const char* p             = s;
    const char * const e      = RExC_end;
    unsigned complement       = 0;      
    bool found_problem        = FALSE;  
    bool has_opening_bracket  = FALSE;
    bool has_opening_colon    = FALSE;
    int class_number          = OOB_NAMEDCLASS; 
    const char * possible_end = NULL;   
    const char* name_start;             

    
    int max_distance          = 2;

    
    UV input_text[15];
    STATIC_ASSERT_DECL(C_ARRAY_LENGTH(input_text) >= sizeof "alphanumeric");

    PERL_ARGS_ASSERT_HANDLE_POSSIBLE_POSIX;

    CLEAR_POSIX_WARNINGS();

    if (p >= e) {
        return NOT_MEANT_TO_BE_A_POSIX_CLASS;
    }

    if (*(p - 1) != '[') {
        ADD_POSIX_WARNING(p, "it doesn't start with a '['");
        found_problem = TRUE;
    }
    else {
        has_opening_bracket = TRUE;
    }

    
    if (isBLANK(*p)) {
        found_problem = TRUE;

        do {
            p++;
        } while (p < e && isBLANK(*p));

        ADD_POSIX_WARNING(p, NO_BLANKS_POSIX_WARNING);
    }

    
    if (POSIXCC_NOTYET(*p) && p < e - 3) 
    {
        const char open_char  = *p;
        const char * temp_ptr = p + 1;

        
        if (temp_ptr[1] == open_char) {
            temp_ptr++;
        }
        else while (    temp_ptr < e && (isWORDCHAR(*temp_ptr) || *temp_ptr == '-'))
        {
            temp_ptr++;
        }

        if (*temp_ptr == open_char) {
            temp_ptr++;
            if (*temp_ptr == ']') {
                temp_ptr++;
                if (! found_problem && ! check_only) {
                    RExC_parse = (char *) temp_ptr;
                    vFAIL3("POSIX syntax [%c %c] is reserved for future " "extensions", open_char, open_char);
                }

                
                if (updated_parse_ptr) {
                    *updated_parse_ptr = (char *) temp_ptr;
                }

                CLEAR_POSIX_WARNINGS_AND_RETURN(OOB_NAMEDCLASS);
            }
        }

        
    }

    
    if (*p == '^') {
        found_problem = TRUE;
        ADD_POSIX_WARNING(p + 1, "the '^' must come after the colon");
        complement = 1;
        p++;

        if (isBLANK(*p)) {
            found_problem = TRUE;

            do {
                p++;
            } while (p < e && isBLANK(*p));

            ADD_POSIX_WARNING(p, NO_BLANKS_POSIX_WARNING);
        }
    }

    
    if (*p == ':') {
        p++;
        has_opening_colon = TRUE;
    }
    else if (*p == ';') {
        found_problem = TRUE;
        p++;
        ADD_POSIX_WARNING(p, SEMI_COLON_POSIX_WARNING);
        has_opening_colon = TRUE;
    }
    else {
        found_problem = TRUE;
        ADD_POSIX_WARNING(p, "there must be a starting ':'");

        
        if (*p != '^' && *p != ']' && isPUNCT(*p)) {
            p++;
        }
    }

    
    if (isBLANK(*p)) {
        found_problem = TRUE;

        do {
            p++;
        } while (p < e && isBLANK(*p));

        ADD_POSIX_WARNING(p, NO_BLANKS_POSIX_WARNING);
    }

    if (*p == '^') {

        
        if (complement) {
            CLEAR_POSIX_WARNINGS_AND_RETURN(NOT_MEANT_TO_BE_A_POSIX_CLASS);
        }

        complement = 1;
        p++;
    }

    
    if (isBLANK(*p)) {
        found_problem = TRUE;

        do {
            p++;
        } while (p < e && isBLANK(*p));

        ADD_POSIX_WARNING(p, NO_BLANKS_POSIX_WARNING);
    }

    if (*p == ']') {

        
        if (has_opening_bracket) {
            CLEAR_POSIX_WARNINGS_AND_RETURN(NOT_MEANT_TO_BE_A_POSIX_CLASS);
        }

        
        p--;

        if (*p == ';') {
            found_problem = TRUE;
            ADD_POSIX_WARNING(p, SEMI_COLON_POSIX_WARNING);
        }
        else if (*p != ':') {

            
            CLEAR_POSIX_WARNINGS_AND_RETURN(NOT_MEANT_TO_BE_A_POSIX_CLASS);
        }

        
        has_opening_colon = FALSE;
        p--;

        while (p > RExC_start && isWORDCHAR(*p)) {
            p--;
        }
        p++;

        
    }

    

    name_start = p;
  parse_name:
    {
        bool has_blank               = FALSE;
        bool has_upper               = FALSE;
        bool has_terminating_colon   = FALSE;
        bool has_terminating_bracket = FALSE;
        bool has_semi_colon          = FALSE;
        unsigned int name_len        = 0;
        int punct_count              = 0;

        while (p < e) {

            
            if (isBLANK(*p) ) {
                has_blank = TRUE;
                found_problem = TRUE;
                p++;
                continue;
            }

            
            if (isPUNCT(*p)) {
                const char * peek = p + 1;

                
                if (*p != ']') {
                    if (peek < e && isBLANK(*peek)) {
                        has_blank = TRUE;
                        found_problem = TRUE;
                        do {
                            peek++;
                        } while (peek < e && isBLANK(*peek));
                    }

                    if (peek < e && *peek == ']') {
                        has_terminating_bracket = TRUE;
                        if (*p == ':') {
                            has_terminating_colon = TRUE;
                        }
                        else if (*p == ';') {
                            has_semi_colon = TRUE;
                            has_terminating_colon = TRUE;
                        }
                        else {
                            found_problem = TRUE;
                        }
                        p = peek + 1;
                        goto try_posix;
                    }
                }

                
                if (*p == ']' || *p == '[' || *p == ':' || *p == ';') {

                    
                    if (possible_end) {
                        break;
                    }
                    possible_end = p;
                }

                
                if (++punct_count > max_distance) {
                    break;
                }

                
                input_text[name_len++] = *p;
                p++;
            }
            else if (isUPPER(*p)) { 
                input_text[name_len++] = toLOWER(*p);
                has_upper = TRUE;
                found_problem = TRUE;
                p++;
            } else if (! UTF || UTF8_IS_INVARIANT(*p)) {
                input_text[name_len++] = *p;
                p++;
            }
            else {
                input_text[name_len++] = utf8_to_uvchr_buf((U8 *) p, e, NULL);
                p+= UTF8SKIP(p);
            }

            
            if (name_len >= C_ARRAY_LENGTH(input_text)) {
                break;
            }
        }

        

        found_problem = TRUE;

        
        if (   name_len >= C_ARRAY_LENGTH(input_text)
            || punct_count > max_distance)
        {
            
            if (possible_end && possible_end != (char *) -1) {
                possible_end = (char *) -1; 
                p = name_start;
                goto parse_name;
            }

            
            CLEAR_POSIX_WARNINGS_AND_RETURN(NOT_MEANT_TO_BE_A_POSIX_CLASS);
        }

        
        if (name_len && p == e && isPUNCT(*(p-1))) {
            p--;
            name_len--;
        }

        if (p < e && isPUNCT(*p)) {
            if (*p == ']') {
                has_terminating_bracket = TRUE;

                
                if (   possible_end && possible_end != (char *) -1 && *possible_end == ']' && name_len && input_text[name_len - 1] == ']')


                {
                    name_len--;
                    p = possible_end;

                    
                    possible_end = (char *) -1;
                }
            }
            else {
                if (*p == ':') {
                    has_terminating_colon = TRUE;
                }
                else if (*p == ';') {
                    has_semi_colon = TRUE;
                    has_terminating_colon = TRUE;
                }
                p++;
            }
        }

    try_posix:

        
        if (name_len < 3) {
            CLEAR_POSIX_WARNINGS_AND_RETURN(NOT_MEANT_TO_BE_A_POSIX_CLASS);
        }

        
        switch (name_len) {
            case 4:
                if (memEQs(name_start, 4, "word")) {
                    
                    class_number = ANYOF_WORDCHAR;
                }
                break;
            case 5:
                
                switch (name_start[4]) {
                    case 'a':
                        if (memBEGINs(name_start, 5, "alph")) 
                            class_number = ANYOF_ALPHA;
                        break;
                    case 'e':
                        if (memBEGINs(name_start, 5, "spac")) 
                            class_number = ANYOF_SPACE;
                        break;
                    case 'h':
                        if (memBEGINs(name_start, 5, "grap")) 
                            class_number = ANYOF_GRAPH;
                        break;
                    case 'i':
                        if (memBEGINs(name_start, 5, "asci")) 
                            class_number = ANYOF_ASCII;
                        break;
                    case 'k':
                        if (memBEGINs(name_start, 5, "blan")) 
                            class_number = ANYOF_BLANK;
                        break;
                    case 'l':
                        if (memBEGINs(name_start, 5, "cntr")) 
                            class_number = ANYOF_CNTRL;
                        break;
                    case 'm':
                        if (memBEGINs(name_start, 5, "alnu")) 
                            class_number = ANYOF_ALPHANUMERIC;
                        break;
                    case 'r':
                        if (memBEGINs(name_start, 5, "lowe")) 
                            class_number = (FOLD) ? ANYOF_CASED : ANYOF_LOWER;
                        else if (memBEGINs(name_start, 5, "uppe")) 
                            class_number = (FOLD) ? ANYOF_CASED : ANYOF_UPPER;
                        break;
                    case 't':
                        if (memBEGINs(name_start, 5, "digi")) 
                            class_number = ANYOF_DIGIT;
                        else if (memBEGINs(name_start, 5, "prin")) 
                            class_number = ANYOF_PRINT;
                        else if (memBEGINs(name_start, 5, "punc")) 
                            class_number = ANYOF_PUNCT;
                        break;
                }
                break;
            case 6:
                if (memEQs(name_start, 6, "xdigit"))
                    class_number = ANYOF_XDIGIT;
                break;
        }

        
        if (class_number == OOB_NAMEDCLASS && found_problem) {
            const UV posix_names[][6] = {
                                                { 'a', 'l', 'n', 'u', 'm' }, { 'a', 'l', 'p', 'h', 'a' }, { 'a', 's', 'c', 'i', 'i' }, { 'b', 'l', 'a', 'n', 'k' }, { 'c', 'n', 't', 'r', 'l' }, { 'd', 'i', 'g', 'i', 't' }, { 'g', 'r', 'a', 'p', 'h' }, { 'l', 'o', 'w', 'e', 'r' }, { 'p', 'r', 'i', 'n', 't' }, { 'p', 'u', 'n', 'c', 't' }, { 's', 'p', 'a', 'c', 'e' }, { 'u', 'p', 'p', 'e', 'r' }, { 'w', 'o', 'r', 'd' }, { 'x', 'd', 'i', 'g', 'i', 't' }












                                            };
            
            const UV posix_name_lengths[] = {
                                                sizeof("alnum") - 1, sizeof("alpha") - 1, sizeof("ascii") - 1, sizeof("blank") - 1, sizeof("cntrl") - 1, sizeof("digit") - 1, sizeof("graph") - 1, sizeof("lower") - 1, sizeof("print") - 1, sizeof("punct") - 1, sizeof("space") - 1, sizeof("upper") - 1, sizeof("word")  - 1, sizeof("xdigit")- 1 };













            unsigned int i;
            int temp_max = max_distance;    

            
            if (   has_opening_bracket + has_opening_colon < 2 || has_terminating_bracket + has_terminating_colon < 2)
            {
                temp_max--;
            }

            
            for (i = 0; i < C_ARRAY_LENGTH(posix_names); i++) {

                
                if (abs( (int) (name_len - posix_name_lengths[i]))
                    > temp_max)
                {
                    continue;
                }

                if (edit_distance(input_text, posix_names[i], name_len, posix_name_lengths[i], temp_max )




                    > -1)
                { 
                    goto probably_meant_to_be;
                }
            }

            
            if (possible_end && possible_end != (char *) -1) {
                possible_end = (char *) -1;
                p = name_start;
                goto parse_name;
            }

            
            CLEAR_POSIX_WARNINGS_AND_RETURN(NOT_MEANT_TO_BE_A_POSIX_CLASS);
        }

    probably_meant_to_be:

        
        if (updated_parse_ptr) {
            *updated_parse_ptr = (char *) p;
        }

        
        if (found_problem) {

            
            if (has_upper) {
                ADD_POSIX_WARNING(p, "the name must be all lowercase letters");
            }
            if (has_blank) {
                ADD_POSIX_WARNING(p, NO_BLANKS_POSIX_WARNING);
            }
            if (has_semi_colon) {
                ADD_POSIX_WARNING(p, SEMI_COLON_POSIX_WARNING);
            }
            else if (! has_terminating_colon) {
                ADD_POSIX_WARNING(p, "there is no terminating ':'");
            }
            if (! has_terminating_bracket) {
                ADD_POSIX_WARNING(p, "there is no terminating ']'");
            }

            if (   posix_warnings && RExC_warn_text && av_top_index(RExC_warn_text) > -1)

            {
                *posix_warnings = RExC_warn_text;
            }
        }
        else if (class_number != OOB_NAMEDCLASS) {
            
            CLEAR_POSIX_WARNINGS_AND_RETURN(class_number + complement);
        }
        else if (! check_only) {

            
            const char * const complement_string = (complement)
                                                   ? "^" : "";
            RExC_parse = (char *) p;
            vFAIL3utf8f("POSIX class [:%s%" UTF8f ":] unknown", complement_string, UTF8fARG(UTF, RExC_parse - name_start - 2, name_start));

        }
    }

    return OOB_NAMEDCLASS;
}


STATIC unsigned  int S_regex_set_precedence(const U8 my_operator) {

    

    switch (my_operator) {
        case '!':
            return 5;
        case '&':
            return 4;
        case '^':
        case '|':
        case '+':
        case '-':
            return 3;
        case ')':
            return 2;
        case ']':
            return 1;
    }

    NOT_REACHED; 
    return 0;   
}

STATIC regnode_offset S_handle_regex_sets(pTHX_ RExC_state_t *pRExC_state, SV** return_invlist, I32 *flagp, U32 depth, char * const oregcomp_parse)


{
    

    U8 curchar;                     
    UV start, end;	            
    SV* final = NULL;               
    SV* result_string;              
    AV* stack;                      
    AV* fence_stack = NULL;         
    
    volatile IV fence = 0;          
    STRLEN len;                     
    regnode_offset node;                  
    const bool save_fold = FOLD;    
    char *save_end, *save_parse;    
    const bool in_locale = LOC;     

    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_HANDLE_REGEX_SETS;

    DEBUG_PARSE("xcls");

    if (in_locale) {
        set_regex_charset(&RExC_flags, REGEX_UNICODE_CHARSET);
    }

    
    REQUIRE_UNI_RULES(flagp, 0);

    ckWARNexperimental(RExC_parse, WARN_EXPERIMENTAL__REGEX_SETS, "The regex_sets feature is experimental");


    




    

    sv_2mortal((SV *)(stack = newAV()));
    sv_2mortal((SV *)(fence_stack = newAV()));

    while (RExC_parse < RExC_end) {
        I32 top_index;              
        SV** top_ptr;               
        SV* current = NULL;         
        SV* only_to_avoid_leaks;

        skip_to_be_ignored_text(pRExC_state, &RExC_parse, TRUE  );
        if (RExC_parse >= RExC_end) {   
            break;
        }

        curchar = UCHARAT(RExC_parse);

redo_curchar:


                    
        DEBUG_U(dump_regex_sets_structures(pRExC_state, stack, fence, fence_stack));


        top_index = av_tindex_skip_len_mg(stack);

        switch (curchar) {
            SV** stacked_ptr;       
            char stacked_operator;  
            SV* lhs;                
            SV* rhs;                
            SV* fence_ptr;          

            case '(':

                if (   RExC_parse < RExC_end - 2 && UCHARAT(RExC_parse + 1) == '?' && UCHARAT(RExC_parse + 2) == '^')

                {
                    
                    U32 save_flags = RExC_flags;
                    const char * save_parse;

                    RExC_parse += 2;        
                    save_parse = RExC_parse;

                    
                    parse_lparen_question_flags(pRExC_state);

                    if (   RExC_parse >= RExC_end - 4 || UCHARAT(RExC_parse) != ':' || UCHARAT(++RExC_parse) != '(' || UCHARAT(++RExC_parse) != '?' || UCHARAT(++RExC_parse) != '[')



                    {

                        
                        if (RExC_parse >= RExC_end - 4) {
                            RExC_parse = RExC_end;
                        }
                        else if (RExC_parse != save_parse) {
                            RExC_parse += (UTF)
                                          ? UTF8_SAFE_SKIP(RExC_parse, RExC_end)
                                          : 1;
                        }
                        vFAIL("Expecting '(?flags:(?[...'");
                    }

                    
                    RExC_parse++;
                    if (! handle_regex_sets(pRExC_state, &current, flagp, depth+1, oregcomp_parse))
                    {
                        RETURN_FAIL_ON_RESTART(*flagp, flagp);
                    }

                    
                    RExC_parse++;
                    if (UCHARAT(RExC_parse) != ')')
                        vFAIL("Expecting close paren for nested extended charclass");

                    
                    RExC_parse++;
                    if (UCHARAT(RExC_parse) != ')')
                        vFAIL("Expecting close paren for wrapper for nested extended charclass");

                    RExC_flags = save_flags;
                    goto handle_operand;
                }

                
                if (top_index - fence >= 0) {
                    
                    if (   ! (top_ptr = av_fetch(stack, top_index, FALSE))
                        || (IS_OPERATOR(*top_ptr) && SvUV(*top_ptr) != '!')
                        || (   IS_OPERAND(*top_ptr)
                            && (   top_index - fence < 1 || ! (stacked_ptr = av_fetch(stack, top_index - 1, FALSE))


                                || ! IS_OPERATOR(*stacked_ptr))))
                    {
                        RExC_parse++;
                        vFAIL("Unexpected '(' with no preceding operator");
                    }
                }

                
                av_push(fence_stack, newSViv(fence));
                fence = top_index + 1;
                break;

            case '\\':
                
                if (!regclass(pRExC_state, flagp, depth+1, TRUE, FALSE, FALSE, TRUE, FALSE, &current))





                {
                    RETURN_FAIL_ON_RESTART(*flagp, flagp);
                    goto regclass_failed;
                }

                
                RExC_parse--;
                goto handle_operand;

            case '[':   
            {
                
                bool is_posix_class = (OOB_NAMEDCLASS < handle_possible_posix(pRExC_state, RExC_parse + 1, NULL, NULL, TRUE ));




                
                if (! is_posix_class) {
                    RExC_parse++;
                }

                
                if (!regclass(pRExC_state, flagp, depth+1, is_posix_class, FALSE, TRUE, TRUE, FALSE, &current))





                {
                    RETURN_FAIL_ON_RESTART(*flagp, flagp);
                    goto regclass_failed;
                }

                if (! current) {
                    break;
                }

                
                if (is_posix_class) {
                    RExC_parse--;
                }

                goto handle_operand;
            }

            case ']':
                if (top_index >= 1) {
                    goto join_operators;
                }

                
                goto done;

            case ')':
                if (av_tindex_skip_len_mg(fence_stack) < 0) {
                    if (UCHARAT(RExC_parse - 1) == ']')  {
                        break;
                    }
                    RExC_parse++;
                    vFAIL("Unexpected ')'");
                }

                
                if (top_index - fence < 0) {
                    RExC_parse++;
                    goto bad_syntax;
                }
                
                if (top_index - fence >= 1) {
                    goto join_operators;
                }

                
                fence_ptr = av_pop(fence_stack);
                assert(fence_ptr);
                fence = SvIV(fence_ptr);
                SvREFCNT_dec_NN(fence_ptr);
                fence_ptr = NULL;

                if (fence < 0) {
                    fence = 0;
                }

                
                current = av_pop(stack);
                if (IS_OPERAND(current)) {
                    goto handle_operand;
                }

                RExC_parse++;
                goto bad_syntax;

            case '&':
            case '|':
            case '+':
            case '-':
            case '^':

                
                if (   top_index - fence < 0 || top_index - fence == 1 || ( ! (top_ptr = av_fetch(stack, top_index, FALSE)))

                    || ! IS_OPERAND(*top_ptr))
                {
                    goto unexpected_binary;
                }

                
                if (top_index - fence < 2) {

                    

                    SV* lhs = av_pop(stack);
                    av_push(stack, newSVuv(curchar));
                    av_push(stack, lhs);
                    break;
                }

                

             join_operators:

                
                if (   ! (stacked_ptr = av_fetch(stack, top_index - 2, FALSE))
                    || IS_OPERAND(*stacked_ptr))
                {
                    
                    if (curchar == ']') {
                        goto done;
                    }

                  unexpected_binary:
                    RExC_parse++;
                    vFAIL2("Unexpected binary operator '%c' with no " "preceding operand", curchar);
                }
                stacked_operator = (char) SvUV(*stacked_ptr);

                if (regex_set_precedence(curchar)
                    > regex_set_precedence(stacked_operator))
                {
                    
                    lhs = av_pop(stack);
                    assert(IS_OPERAND(lhs));

                    av_push(stack, newSVuv(curchar));
                    av_push(stack, lhs);
                    break;
                }

                

                rhs = av_pop(stack);
                if (! IS_OPERAND(rhs)) {

                    
                    goto bad_syntax;
                }

                lhs = av_pop(stack);

                if (! IS_OPERAND(lhs)) {

                    
                    goto bad_syntax;
                }

                switch (stacked_operator) {
                    case '&':
                        _invlist_intersection(lhs, rhs, &rhs);
                        break;

                    case '|':
                    case '+':
                        _invlist_union(lhs, rhs, &rhs);
                        break;

                    case '-':
                        _invlist_subtract(lhs, rhs, &rhs);
                        break;

                    case '^':   
                    {
                        SV* i = NULL;
                        SV* u = NULL;

                        _invlist_union(lhs, rhs, &u);
                        _invlist_intersection(lhs, rhs, &i);
                        _invlist_subtract(u, i, &rhs);
                        SvREFCNT_dec_NN(i);
                        SvREFCNT_dec_NN(u);
                        break;
                    }
                }
                SvREFCNT_dec(lhs);

                
                only_to_avoid_leaks = av_pop(stack);
                SvREFCNT_dec(only_to_avoid_leaks);
                av_push(stack, rhs);
                goto redo_curchar;

            case '!':   

                
                if (   (top_ptr = av_fetch(stack, top_index, FALSE))
                    && (IS_OPERATOR(*top_ptr) && SvUV(*top_ptr) == '!'))
                {
                    only_to_avoid_leaks = av_pop(stack);
                    SvREFCNT_dec(only_to_avoid_leaks);
                }
                else { 
                    av_push(stack, newSVuv(curchar));
                }
                break;

            default:
                RExC_parse += (UTF) ? UTF8SKIP(RExC_parse) : 1;
                if (RExC_parse >= RExC_end) {
                    break;
                }
                vFAIL("Unexpected character");

          handle_operand:

            

            top_index = av_tindex_skip_len_mg(stack);
            if (top_index - fence >= 0) {
                
                top_ptr = av_fetch(stack, top_index, FALSE);
                assert(top_ptr);
                if (IS_OPERATOR(*top_ptr)) {

                    
                    curchar = (char) SvUV(*top_ptr);
                    if (curchar != '!') {
                        SvREFCNT_dec(current);
                        vFAIL2("Unexpected binary operator '%c' with no " "preceding operand", curchar);
                    }

                    _invlist_invert(current);

                    only_to_avoid_leaks = av_pop(stack);
                    SvREFCNT_dec(only_to_avoid_leaks);

                    
                    goto handle_operand;
                }
                          
                else if ((top_index - fence == 0 && curchar != ')')
                         || (top_index - fence > 0 && (! (stacked_ptr = av_fetch(stack, top_index - 1, FALSE))


                                 || IS_OPERAND(*stacked_ptr))))
                {
                    SvREFCNT_dec(current);
                    vFAIL("Operand with no preceding operator");
                }
            }

            
            av_push(stack, current);

        } 

        RExC_parse += (UTF) ? UTF8SKIP(RExC_parse) : 1;
    } 

    vFAIL("Syntax error in (?[...])");

  done:

    if (RExC_parse >= RExC_end || RExC_parse[1] != ')') {
        if (RExC_parse < RExC_end) {
            RExC_parse++;
        }

        vFAIL("Unexpected ']' with no following ')' in (?[...");
    }

    if (av_tindex_skip_len_mg(fence_stack) >= 0) {
        vFAIL("Unmatched (");
    }

    if (av_tindex_skip_len_mg(stack) < 0    || ((final = av_pop(stack)) == NULL)
        || ! IS_OPERAND(final)
        || ! is_invlist(final)
        || av_tindex_skip_len_mg(stack) >= 0)  
    {
      bad_syntax:
        SvREFCNT_dec(final);
        vFAIL("Incomplete expression within '(?[ ])'");
    }

    
    if (return_invlist) {
        *return_invlist = final;
        return END;
    }

    
    invlist_iterinit(final);
    result_string = newSVpvs("");
    while (invlist_iternext(final, &start, &end)) {
        if (start == end) {
            Perl_sv_catpvf(aTHX_ result_string, "\\x{%" UVXf "}", start);
        }
        else {
            Perl_sv_catpvf(aTHX_ result_string, "\\x{%" UVXf "}-\\x{%" UVXf "}", start,          end);
        }
    }

    
    save_parse = RExC_parse;
    RExC_parse = SvPV(result_string, len);
    save_end = RExC_end;
    RExC_end = RExC_parse + len;
    TURN_OFF_WARNINGS_IN_SUBSTITUTE_PARSE;

    
    RExC_flags &= ~RXf_PMf_FOLD;
    
    node = regclass(pRExC_state, flagp, depth+1, FALSE, FALSE, TRUE, FALSE, FALSE, NULL );







    RESTORE_WARNINGS;
    RExC_parse = save_parse + 1;
    RExC_end = save_end;
    SvREFCNT_dec_NN(final);
    SvREFCNT_dec_NN(result_string);

    if (save_fold) {
        RExC_flags |= RXf_PMf_FOLD;
    }

    if (!node) {
        RETURN_FAIL_ON_RESTART(*flagp, flagp);
        goto regclass_failed;
    }

    
    if (in_locale) {
        set_regex_charset(&RExC_flags, REGEX_LOCALE_CHARSET);

        assert(OP(REGNODE_p(node)) == ANYOF);

        OP(REGNODE_p(node)) = ANYOFL;
        ANYOF_FLAGS(REGNODE_p(node))
                |= ANYOFL_SHARED_UTF8_LOCALE_fold_HAS_MATCHES_nonfold_REQD;
    }

    nextchar(pRExC_state);
    Set_Node_Length(REGNODE_p(node), RExC_parse - oregcomp_parse + 1); 
    return node;

  regclass_failed:
    FAIL2("panic: regclass returned failure to handle_sets, " "flags=%#" UVxf, (UV) *flagp);
}



STATIC void S_dump_regex_sets_structures(pTHX_ RExC_state_t *pRExC_state, AV * stack, const IV fence, AV * fence_stack)

{   

    const SSize_t stack_top = av_tindex_skip_len_mg(stack);
    const SSize_t fence_stack_top = av_tindex_skip_len_mg(fence_stack);
    SSize_t i;

    PERL_ARGS_ASSERT_DUMP_REGEX_SETS_STRUCTURES;

    PerlIO_printf(Perl_debug_log, "\nParse position is:%s\n", RExC_parse);

    if (stack_top < 0) {
        PerlIO_printf(Perl_debug_log, "Nothing on stack\n");
    }
    else {
        PerlIO_printf(Perl_debug_log, "Stack: (fence=%d)\n", (int) fence);
        for (i = stack_top; i >= 0; i--) {
            SV ** element_ptr = av_fetch(stack, i, FALSE);
            if (! element_ptr) {
            }

            if (IS_OPERATOR(*element_ptr)) {
                PerlIO_printf(Perl_debug_log, "[%d]: %c\n", (int) i, (int) SvIV(*element_ptr));
            }
            else {
                PerlIO_printf(Perl_debug_log, "[%d] ", (int) i);
                sv_dump(*element_ptr);
            }
        }
    }

    if (fence_stack_top < 0) {
        PerlIO_printf(Perl_debug_log, "Nothing on fence_stack\n");
    }
    else {
        PerlIO_printf(Perl_debug_log, "Fence_stack: \n");
        for (i = fence_stack_top; i >= 0; i--) {
            SV ** element_ptr = av_fetch(fence_stack, i, FALSE);
            if (! element_ptr) {
            }

            PerlIO_printf(Perl_debug_log, "[%d]: %d\n", (int) i, (int) SvIV(*element_ptr));
        }
    }
}






STATIC void S_add_above_Latin1_folds(pTHX_ RExC_state_t *pRExC_state, const U8 cp, SV** invlist)
{
    

    PERL_ARGS_ASSERT_ADD_ABOVE_LATIN1_FOLDS;

    assert(HAS_NONLATIN1_SIMPLE_FOLD_CLOSURE(cp));

    
    switch (cp) {
        case 'k':
        case 'K':
          *invlist = add_cp_to_invlist(*invlist, KELVIN_SIGN);
            break;
        case 's':
        case 'S':
          *invlist = add_cp_to_invlist(*invlist, LATIN_SMALL_LETTER_LONG_S);
            break;
        case MICRO_SIGN:
          *invlist = add_cp_to_invlist(*invlist, GREEK_CAPITAL_LETTER_MU);
          *invlist = add_cp_to_invlist(*invlist, GREEK_SMALL_LETTER_MU);
            break;
        case LATIN_CAPITAL_LETTER_A_WITH_RING_ABOVE:
        case LATIN_SMALL_LETTER_A_WITH_RING_ABOVE:
          *invlist = add_cp_to_invlist(*invlist, ANGSTROM_SIGN);
            break;
        case LATIN_SMALL_LETTER_Y_WITH_DIAERESIS:
          *invlist = add_cp_to_invlist(*invlist, LATIN_CAPITAL_LETTER_Y_WITH_DIAERESIS);
            break;

        default:    
          {
            Size_t folds_count;
            unsigned int first_fold;
            const unsigned int * remaining_folds;
            UV folded_cp;

            if (isASCII(cp)) {
                folded_cp = toFOLD(cp);
            }
            else {
                U8 dummy_fold[UTF8_MAXBYTES_CASE+1];
                Size_t dummy_len;
                folded_cp = _to_fold_latin1(cp, dummy_fold, &dummy_len, 0);
            }

            if (folded_cp > 255) {
                *invlist = add_cp_to_invlist(*invlist, folded_cp);
            }

            folds_count = _inverse_folds(folded_cp, &first_fold, &remaining_folds);
            if (folds_count == 0) {

                
                ckWARN2reg_d(RExC_parse, "Perl folding rules are not up-to-date for 0x%02X;" " please use the perlbug utility to report;", cp);

            }
            else {
                unsigned int i;

                if (first_fold > 255) {
                    *invlist = add_cp_to_invlist(*invlist, first_fold);
                }
                for (i = 0; i < folds_count - 1; i++) {
                    if (remaining_folds[i] > 255) {
                        *invlist = add_cp_to_invlist(*invlist, remaining_folds[i]);
                    }
                }
            }
            break;
         }
    }
}

STATIC void S_output_posix_warnings(pTHX_ RExC_state_t *pRExC_state, AV* posix_warnings)
{
    

    SV * msg;
    const bool first_is_fatal = ckDEAD(packWARN(WARN_REGEXP));

    PERL_ARGS_ASSERT_OUTPUT_POSIX_WARNINGS;

    if (! TO_OUTPUT_WARNINGS(RExC_parse)) {
        return;
    }

    while ((msg = av_shift(posix_warnings)) != &PL_sv_undef) {
        if (first_is_fatal) {           
            av_undef(posix_warnings);   
            (void) sv_2mortal(msg);
            PREPARE_TO_DIE;
        }
        Perl_warner(aTHX_ packWARN(WARN_REGEXP), "%s", SvPVX(msg));
        SvREFCNT_dec_NN(msg);
    }

    UPDATE_WARNINGS_LOC(RExC_parse);
}

STATIC AV * S_add_multi_match(pTHX_ AV* multi_char_matches, SV* multi_string, const STRLEN cp_count)
{
    

    AV* this_array;
    AV** this_array_ptr;

    PERL_ARGS_ASSERT_ADD_MULTI_MATCH;

    if (! multi_char_matches) {
        multi_char_matches = newAV();
    }

    if (av_exists(multi_char_matches, cp_count)) {
        this_array_ptr = (AV**) av_fetch(multi_char_matches, cp_count, FALSE);
        this_array = *this_array_ptr;
    }
    else {
        this_array = newAV();
        av_store(multi_char_matches, cp_count, (SV*) this_array);
    }
    av_push(this_array, multi_string);

    return multi_char_matches;
}














STATIC regnode_offset S_regclass(pTHX_ RExC_state_t *pRExC_state, I32 *flagp, U32 depth, const bool stop_at_1, bool allow_mutiple_chars, const bool silence_non_portable, const bool strict, bool optimizable, SV** ret_invlist )







{
    

    dVAR;
    UV prevvalue = OOB_UNICODE, save_prevvalue = OOB_UNICODE;
    IV range = 0;
    UV value = OOB_UNICODE, save_value = OOB_UNICODE;
    regnode_offset ret = -1;    
    STRLEN numlen;
    int namedclass = OOB_NAMEDCLASS;
    char *rangebegin = NULL;
    SV *listsv = NULL;      
    STRLEN initial_listsv_len = 0; 
    SV* properties = NULL;    
    SV* posixes = NULL;     
    SV* nposixes = NULL;    
    SV* simple_posixes = NULL; 
    UV element_count = 0;   
    AV * multi_char_matches = NULL; 
    UV n;
    char * stop_ptr = RExC_end;    

    
    const bool skip_white = cBOOL(   ret_invlist || (RExC_flags & RXf_PMf_EXTENDED_MORE));

    
    SV* upper_latin1_only_utf8_matches = NULL;

    
    SV* cp_list = NULL;

    
    SV* cp_foldable_list = NULL;

    
    SV* only_utf8_locale_list = NULL;

    
    unsigned int non_portable_endpoint = 0;

    
    bool unicode_range = FALSE;
    bool invert = FALSE;    

    bool warn_super = ALWAYS_WARN_SUPER;

    const char * orig_parse = RExC_parse;

    
    char *not_posix_region_end = RExC_parse - 1;

    AV* posix_warnings = NULL;
    const bool do_posix_warnings = ckWARN(WARN_REGEXP);
    U8 op = END;    
    U8 anyof_flags = 0;   
    U32 posixl = 0;       






    U32 has_runtime_dependency = 0;     

    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_REGCLASS;

    PERL_UNUSED_ARG(depth);



    
    if (ret_invlist) {
        optimizable = FALSE;
    }

    DEBUG_PARSE("clas");



    allow_mutiple_chars = FALSE;


    
    listsv = sv_2mortal(Perl_newSVpvf(aTHX_ "#%d\n", cBOOL(FOLD)));
    initial_listsv_len = SvCUR(listsv);
    SvTEMP_off(listsv); 

    SKIP_BRACKETED_WHITE_SPACE(skip_white, RExC_parse);

    assert(RExC_parse <= RExC_end);

    if (UCHARAT(RExC_parse) == '^') {	
	RExC_parse++;
        invert = TRUE;
        allow_mutiple_chars = FALSE;
        MARK_NAUGHTY(1);
        SKIP_BRACKETED_WHITE_SPACE(skip_white, RExC_parse);
    }

    
    if (! ret_invlist && MAYBE_POSIXCC(UCHARAT(RExC_parse))) {
        int maybe_class = handle_possible_posix(pRExC_state, RExC_parse, &not_posix_region_end, NULL, TRUE );



        if (maybe_class >= OOB_NAMEDCLASS && do_posix_warnings) {
            ckWARN4reg(not_posix_region_end, "POSIX syntax [%c %c] belongs inside character classes%s", *RExC_parse, *RExC_parse, (maybe_class == OOB_NAMEDCLASS)


                    ? ((POSIXCC_NOTYET(*RExC_parse))
                        ? " (but this one isn't implemented)" : " (but this one isn't fully valid)")
                    : "" );
        }
    }

    
    if (stop_at_1 && RExC_end > RExC_parse) {
        stop_ptr = RExC_parse + 1;
    }

    
    if (UCHARAT(RExC_parse) == ']')
	goto charclassloop;

    while (1) {

        if (   posix_warnings && av_tindex_skip_len_mg(posix_warnings) >= 0 && RExC_parse > not_posix_region_end)

        {
            
            output_posix_warnings(pRExC_state, posix_warnings);
        }

        if  (RExC_parse >= stop_ptr) {
            break;
        }

        SKIP_BRACKETED_WHITE_SPACE(skip_white, RExC_parse);

        if  (UCHARAT(RExC_parse) == ']') {
            break;
        }

      charclassloop:

	namedclass = OOB_NAMEDCLASS; 
        save_value = value;
        save_prevvalue = prevvalue;

	if (!range) {
	    rangebegin = RExC_parse;
	    element_count++;
            non_portable_endpoint = 0;
	}
	if (UTF && ! UTF8_IS_INVARIANT(* RExC_parse)) {
	    value = utf8n_to_uvchr((U8*)RExC_parse, RExC_end - RExC_parse, &numlen, UTF8_ALLOW_DEFAULT);

	    RExC_parse += numlen;
	}
	else value = UCHARAT(RExC_parse++);

        if (value == '[') {
            char * posix_class_end;
            namedclass = handle_possible_posix(pRExC_state, RExC_parse, &posix_class_end, do_posix_warnings ? &posix_warnings : NULL, FALSE    );



            if (namedclass > OOB_NAMEDCLASS) {

                
                if (   posix_warnings && av_tindex_skip_len_mg(posix_warnings) >= 0 && not_posix_region_end >= RExC_parse && not_posix_region_end <= posix_class_end)


                {
                    av_undef(posix_warnings);
                }

                RExC_parse = posix_class_end;
            }
            else if (namedclass == OOB_NAMEDCLASS) {
                not_posix_region_end = posix_class_end;
            }
            else {
                namedclass = OOB_NAMEDCLASS;
            }
        }
        else if (   RExC_parse - 1 > not_posix_region_end && MAYBE_POSIXCC(value))
        {
            (void) handle_possible_posix( pRExC_state, RExC_parse - 1, &not_posix_region_end, do_posix_warnings ? &posix_warnings : NULL, TRUE );




        }
        else if (  strict && ! skip_white && (   _generic_isCC(value, _CC_VERTSPACE)
                     || is_VERTWS_cp_high(value)))
        {
            vFAIL("Literal vertical space in [] is illegal except under /x");
        }
        else if (value == '\\') {
            

            if (RExC_parse >= RExC_end) {
                vFAIL("Unmatched [");
            }

	    if (UTF && ! UTF8_IS_INVARIANT(UCHARAT(RExC_parse))) {
		value = utf8n_to_uvchr((U8*)RExC_parse, RExC_end - RExC_parse, &numlen, UTF8_ALLOW_DEFAULT);

		RExC_parse += numlen;
	    }
	    else value = UCHARAT(RExC_parse++);

	    

            
            if (! skip_white || ! isBLANK_A(value)) switch ((I32)value) {

	    case 'w':	namedclass = ANYOF_WORDCHAR;	break;
	    case 'W':	namedclass = ANYOF_NWORDCHAR;	break;
	    case 's':	namedclass = ANYOF_SPACE;	break;
	    case 'S':	namedclass = ANYOF_NSPACE;	break;
	    case 'd':	namedclass = ANYOF_DIGIT;	break;
	    case 'D':	namedclass = ANYOF_NDIGIT;	break;
	    case 'v':	namedclass = ANYOF_VERTWS;	break;
	    case 'V':	namedclass = ANYOF_NVERTWS;	break;
	    case 'h':	namedclass = ANYOF_HORIZWS;	break;
	    case 'H':	namedclass = ANYOF_NHORIZWS;	break;
            case 'N':  
                {
                    const char * const backslash_N_beg = RExC_parse - 2;
                    int cp_count;

                    if (! grok_bslash_N(pRExC_state, NULL, &value, &cp_count, flagp, strict, depth)





                    ) {

                        if (*flagp & NEED_UTF8)
                            FAIL("panic: grok_bslash_N set NEED_UTF8");

                        RETURN_FAIL_ON_RESTART_FLAGP(flagp);

                        if (cp_count < 0) {
                            vFAIL("\\N in a character class must be a named character: \\N{...}");
                        }
                        else if (cp_count == 0) {
                            ckWARNreg(RExC_parse, "Ignoring zero length \\N{} in character class");
                        }
                        else { 
                            assert(cp_count > 1);
                            if (! RExC_in_multi_char_class) {
                                if ( ! allow_mutiple_chars || invert || range || *RExC_parse == '-')


                                {
                                    if (strict) {
                                        RExC_parse--;
                                        vFAIL("\\N{} in inverted character class or as a range end-point is restricted to one character");
                                    }
                                    ckWARNreg(RExC_parse, "Using just the first character returned by \\N{} in character class");
                                    break; 
                                }
                                else {
                                    SV * multi_char_N = newSVpvn(backslash_N_beg, RExC_parse - backslash_N_beg);
                                    multi_char_matches = add_multi_match(multi_char_matches, multi_char_N, cp_count);


                                }
                            }
                        } 

                        
                        element_count--;
                        value = save_value;
                        prevvalue = save_prevvalue;
                        continue;   
                    }

                    
                    unicode_range = TRUE;   
                }
                break;
	    case 'p':
	    case 'P':
		{
		char *e;

		
		REQUIRE_UNI_RULES(flagp, 0);

		if (RExC_parse >= RExC_end)
		    vFAIL2("Empty \\%c", (U8)value);
		if (*RExC_parse == '{') {
		    const U8 c = (U8)value;
		    e = (char *) memchr(RExC_parse, '}', RExC_end - RExC_parse);
                    if (!e) {
                        RExC_parse++;
                        vFAIL2("Missing right brace on \\%c{}", c);
                    }

                    RExC_parse++;

                    
                    while (isSPACE(*RExC_parse)) {
                         RExC_parse++;
		    }

		    if (UCHARAT(RExC_parse) == '^') {

                        
                        value ^= 'P' ^ 'p';

                        RExC_parse++;
                        while (isSPACE(*RExC_parse)) {
                            RExC_parse++;
                        }
                    }

                    if (e == RExC_parse)
                        vFAIL2("Empty \\%c{}", c);

		    n = e - RExC_parse;
		    while (isSPACE(*(RExC_parse + n - 1)))
		        n--;

		}   
		else if (! isALPHA(*RExC_parse)) {
                    RExC_parse += (UTF)
                                  ? UTF8_SAFE_SKIP(RExC_parse, RExC_end)
                                  : 1;
                    vFAIL2("Character following \\%c must be '{' or a " "single-character Unicode property name", (U8) value);

                }
                else {
		    e = RExC_parse;
		    n = 1;
		}
		{
                    char* name = RExC_parse;

                    
                    SV* msg = newSVpvs_flags("", SVs_TEMP);

                    
                    bool user_defined = FALSE;

                    SV * prop_definition = parse_uniprop_string( name, n, UTF, FOLD, FALSE,   ! cBOOL(ret_invlist),  &user_defined, msg, 0 );









                    if (SvCUR(msg)) {   
                        assert(prop_definition == NULL);
                        RExC_parse = e + 1;
                        if (SvUTF8(msg)) {  
                            RExC_utf8 = TRUE;
                        }
			
                        vFAIL2utf8f("%" UTF8f, UTF8fARG(SvUTF8(msg), SvCUR(msg), SvPVX(msg)));
                    }

                    if (! is_invlist(prop_definition)) {

                        
                        if (value == 'P') {
                            sv_catpvs(listsv, "!");
                        }
                        else {
                            sv_catpvs(listsv, "+");
                        }
                        sv_catsv(listsv, prop_definition);

                        has_runtime_dependency |= HAS_USER_DEFINED_PROPERTY;

                        
                        anyof_flags |= ANYOF_SHARED_d_UPPER_LATIN1_UTF8_STRING_MATCHES_non_d_RUNTIME_USER_PROP;
                    }
                    else {
                        assert (prop_definition && is_invlist(prop_definition));

                        
                        if (     memEQs(RExC_start, e + 1 - RExC_start, "foo\\p{Alnum}")
                            && ! hv_common(GvHVn(PL_incgv), NULL, "utf8.pm", sizeof("utf8.pm") - 1, 0, HV_FETCH_ISEXISTS, NULL, 0))


                        {
                            require_pv("utf8.pm");
                        }

                        if (! user_defined &&  (_invlist_contains_cp(prop_definition, 0x110000)

                                && (! (_invlist_len(prop_definition) == 1 && *invlist_array(prop_definition) == 0))))
                        {
                            warn_super = TRUE;
                        }

                        
                        if (value == 'P') {
			    _invlist_union_complement_2nd(properties, prop_definition, &properties);

                        }
                        else {
                            _invlist_union(properties, prop_definition, &properties);
			}
                    }
                }

		RExC_parse = e + 1;
                namedclass = ANYOF_UNIPROP;  
		}
		break;
	    case 'n':	value = '\n';			break;
	    case 'r':	value = '\r';			break;
	    case 't':	value = '\t';			break;
	    case 'f':	value = '\f';			break;
	    case 'b':	value = '\b';			break;
	    case 'e':	value = ESC_NATIVE;             break;
	    case 'a':	value = '\a';                   break;
	    case 'o':
		RExC_parse--;	
		{
		    const char* error_msg;
		    bool valid = grok_bslash_o(&RExC_parse, RExC_end, &value, &error_msg, TO_OUTPUT_WARNINGS(RExC_parse), strict, silence_non_portable, UTF);






		    if (! valid) {
			vFAIL(error_msg);
		    }
                    UPDATE_WARNINGS_LOC(RExC_parse - 1);
		}
                non_portable_endpoint++;
		break;
	    case 'x':
		RExC_parse--;	
		{
		    const char* error_msg;
		    bool valid = grok_bslash_x(&RExC_parse, RExC_end, &value, &error_msg, TO_OUTPUT_WARNINGS(RExC_parse), strict, silence_non_portable, UTF);






                    if (! valid) {
			vFAIL(error_msg);
		    }
                    UPDATE_WARNINGS_LOC(RExC_parse - 1);
		}
                non_portable_endpoint++;
		break;
	    case 'c':
		value = grok_bslash_c(*RExC_parse, TO_OUTPUT_WARNINGS(RExC_parse));
                UPDATE_WARNINGS_LOC(RExC_parse);
		RExC_parse++;
                non_portable_endpoint++;
		break;
	    case '0': case '1': case '2': case '3': case '4':
	    case '5': case '6': case '7':
		{
		    
		    I32 flags = PERL_SCAN_SILENT_ILLDIGIT;
                    numlen = (strict) ? 4 : 3;
                    value = grok_oct(--RExC_parse, &numlen, &flags, NULL);
		    RExC_parse += numlen;
                    if (numlen != 3) {
                        if (strict) {
                            RExC_parse += (UTF)
                                          ? UTF8_SAFE_SKIP(RExC_parse, RExC_end)
                                          : 1;
                            vFAIL("Need exactly 3 octal digits");
                        }
                        else if (   numlen < 3  && RExC_parse < RExC_end && isDIGIT(*RExC_parse)

                                 && ckWARN(WARN_REGEXP))
                        {
                            reg_warn_non_literal_string( RExC_parse + 1, form_short_octal_warning(RExC_parse, numlen));

                        }
                    }
                    non_portable_endpoint++;
		    break;
		}
	    default:
		
		if (isWORDCHAR(value) && value != '_') {
                    if (strict) {
                        vFAIL2("Unrecognized escape \\%c in character class", (int)value);
                    }
                    else {
                        ckWARN2reg(RExC_parse, "Unrecognized escape \\%c in character class passed through", (int)value);

                    }
		}
		break;
	    }   
	} 

        

	if (namedclass > OOB_NAMEDCLASS) { 
            U8 classnum;

	    
	    if (range) {
                const int w = (RExC_parse >= rangebegin)
                                ? RExC_parse - rangebegin : 0;
                if (strict) {
                    vFAIL2utf8f( "False [] range \"%" UTF8f "\"", UTF8fARG(UTF, w, rangebegin));

                }
                else {
                    ckWARN2reg(RExC_parse, "False [] range \"%" UTF8f "\"", UTF8fARG(UTF, w, rangebegin));

                    cp_list = add_cp_to_invlist(cp_list, '-');
                    cp_foldable_list = add_cp_to_invlist(cp_foldable_list, prevvalue);
                }

		range = 0; 
                element_count += 2; 
	    }

            classnum = namedclass_to_classnum(namedclass);

	    if (LOC && namedclass < ANYOF_POSIXL_MAX  && classnum != _CC_ASCII  ) {



                SV* scratch_list = NULL;

                
                if (POSIXL_TEST(posixl, namedclass ^ 1)) {
                    cp_list = _add_range_to_invlist(cp_list, 0, UV_MAX);
                    POSIXL_ZERO(posixl);
                    has_runtime_dependency &= ~HAS_L_RUNTIME_DEPENDENCY;
                    anyof_flags &= ~ANYOF_MATCHES_POSIXL;
                    continue;   
                }
                else { 
                    POSIXL_SET(posixl, namedclass);
                    has_runtime_dependency |= HAS_L_RUNTIME_DEPENDENCY;
                    anyof_flags |= ANYOF_MATCHES_POSIXL;

                    

                    
                    _invlist_intersection_maybe_complement_2nd(PL_AboveLatin1, PL_XPosix_ptrs[classnum],   namedclass % 2 != 0, &scratch_list);




                    
                    if (! cp_list) {
                        cp_list = scratch_list;
                    }
                    else {
                        _invlist_union(cp_list, scratch_list, &cp_list);
                        SvREFCNT_dec_NN(scratch_list);
                    }
                    continue;   
                }
            }
            else {

                
                if (namedclass >= ANYOF_POSIXL_MAX) {  
                    if (namedclass != ANYOF_UNIPROP) { 

                        
                        if (classnum != _CC_VERTSPACE) {
                            assert(   namedclass == ANYOF_HORIZWS || namedclass == ANYOF_NHORIZWS);

                            
                            classnum = _CC_BLANK;
                        }

                        _invlist_union_maybe_complement_2nd( cp_list, PL_XPosix_ptrs[classnum], namedclass % 2 != 0, &cp_list);



                    }
                }
                else if (   AT_LEAST_UNI_SEMANTICS || classnum == _CC_ASCII || (DEPENDS_SEMANTICS && (   classnum == _CC_DIGIT || classnum == _CC_XDIGIT)))


                {
                    
                    _invlist_union_maybe_complement_2nd( simple_posixes, ((AT_LEAST_ASCII_RESTRICTED)

                                                       ? PL_Posix_ptrs[classnum] : PL_XPosix_ptrs[classnum]), namedclass % 2 != 0, &simple_posixes);


                }
                else {  
                    SV** posixes_ptr = namedclass % 2 == 0 ? &posixes : &nposixes;

                    _invlist_union_maybe_complement_2nd( *posixes_ptr, PL_XPosix_ptrs[classnum], namedclass % 2 != 0, posixes_ptr);



                }
	    }
	} 

        SKIP_BRACKETED_WHITE_SPACE(skip_white, RExC_parse);

        

	if (range) {

            
	    if (unicode_range && prevvalue < 255 && value < 255) {
                if (NATIVE_TO_LATIN1(prevvalue) > NATIVE_TO_LATIN1(value)) {
                    goto backwards_range;
                }
            }
            else  if (prevvalue > value)  {

		int w;

              backwards_range:

                w = RExC_parse - rangebegin;
                vFAIL2utf8f( "Invalid [] range \"%" UTF8f "\"", UTF8fARG(UTF, w, rangebegin));

                NOT_REACHED; 
	    }
	}
	else {
            prevvalue = value; 
            if (! stop_at_1      && *RExC_parse == '-')
            {
                char* next_char_ptr = RExC_parse + 1;

                
                SKIP_BRACKETED_WHITE_SPACE(skip_white, next_char_ptr);

                
                if (next_char_ptr < RExC_end && *next_char_ptr != ']') {
                    RExC_parse = next_char_ptr;

                    
                    if (namedclass > OOB_NAMEDCLASS) {
                        if (strict || ckWARN(WARN_REGEXP)) {
                            const int w = RExC_parse >= rangebegin ?  RExC_parse - rangebegin : 0;

                            if (strict) {
                                vFAIL4("False [] range \"%*.*s\"", w, w, rangebegin);
                            }
                            else {
                                vWARN4(RExC_parse, "False [] range \"%*.*s\"", w, w, rangebegin);

                            }
                        }
                        cp_list = add_cp_to_invlist(cp_list, '-');
                        element_count++;
                    } else range = 1;
                    continue;	
                }
	    }
	}

        if (namedclass > OOB_NAMEDCLASS) {
            continue;
        }

        

	
	if (value > 255) {
            REQUIRE_UNI_RULES(flagp, 0);
	}

        
        if (FOLD && allow_mutiple_chars && value == prevvalue) {
            if (    value == LATIN_SMALL_LETTER_SHARP_S || (value > 255 && _invlist_contains_cp(PL_HasMultiCharFold, value)))

            {
                

                U8 foldbuf[UTF8_MAXBYTES_CASE+1];
                STRLEN foldlen;

                UV folded = _to_uni_fold_flags( value, foldbuf, &foldlen, FOLD_FLAGS_FULL | (ASCII_FOLD_RESTRICTED ? FOLD_FLAGS_NOMIX_ASCII : 0)





                                );

                
                if (folded != value) {

                    
                    if (! RExC_in_multi_char_class) {
                        STRLEN cp_count = utf8_length(foldbuf, foldbuf + foldlen);
                        SV* multi_fold = sv_2mortal(newSVpvs(""));

                        Perl_sv_catpvf(aTHX_ multi_fold, "\\x{%" UVXf "}", value);

                        multi_char_matches = add_multi_match(multi_char_matches, multi_fold, cp_count);



                    }

                    
                    element_count--;
                    value = save_value;
                    prevvalue = save_prevvalue;
                    continue;
                }
            }
        }

        if (strict && ckWARN(WARN_REGEXP)) {
            if (range) {

                
                if (unicode_range && non_portable_endpoint && prevvalue < 256) {
                    vWARN(RExC_parse, "Both or neither range ends should be Unicode");
                }
                else if (prevvalue != value) {

                    
                    if (             (isPRINT_A(prevvalue) || isPRINT_A(value))
                        && (          non_portable_endpoint || ! (   (isDIGIT_A(prevvalue) && isDIGIT_A(value))
                                  || (isLOWER_A(prevvalue) && isLOWER_A(value))
                                  || (isUPPER_A(prevvalue) && isUPPER_A(value))
                    ))) {
                        vWARN(RExC_parse, "Ranges of ASCII printables should" " be some subset of \"0-9\"," " \"A-Z\", or \"a-z\"");

                    }
                    else if (prevvalue >= FIRST_NON_ASCII_DECIMAL_DIGIT) {
                        SSize_t index_start;
                        SSize_t index_final;

                        

                        if (UNLIKELY(value == 0x19DA && prevvalue >= 0x19D0)) {
                            goto warn_bad_digit_range;
                        }
                        else if (UNLIKELY(   prevvalue >= 0x1D7CE &&     value <= 0x1D7FF))
                        {
                            
                            if (         value - prevvalue > 9 ||    (((    value - 0x1D7CE) % 10)
                                     <= (prevvalue - 0x1D7CE) % 10))
                            {
                                goto warn_bad_digit_range;
                            }
                        }
                        else {

                            
                            index_start = _invlist_search( PL_XPosix_ptrs[_CC_DIGIT], prevvalue);


                            
                            if (   index_start >= 0 && ELEMENT_RANGE_MATCHES_INVLIST(index_start)
                                && (index_final = _invlist_search(PL_XPosix_ptrs[_CC_DIGIT], value)) != index_start && index_final >= 0 && ELEMENT_RANGE_MATCHES_INVLIST(index_final))



                            {
                              warn_bad_digit_range:
                                vWARN(RExC_parse, "Ranges of digits should be" " from the same group of" " 10");

                            }
                        }
                    }
                }
            }
            if ((! range || prevvalue == value) && non_portable_endpoint) {
                if (isPRINT_A(value)) {
                    char literal[3];
                    unsigned d = 0;
                    if (isBACKSLASHED_PUNCT(value)) {
                        literal[d++] = '\\';
                    }
                    literal[d++] = (char) value;
                    literal[d++] = '\0';

                    vWARN4(RExC_parse, "\"%.*s\" is more clearly written simply as \"%s\"", (int) (RExC_parse - rangebegin), rangebegin, literal );




                }
                else if isMNEMONIC_CNTRL(value) {
                    vWARN4(RExC_parse, "\"%.*s\" is more clearly written simply as \"%s\"", (int) (RExC_parse - rangebegin), rangebegin, cntrl_to_mnemonic((U8) value)



                        );
                }
            }
        }

        


        cp_foldable_list = _add_range_to_invlist(cp_foldable_list, prevvalue, value);

        
        if ((UNLIKELY(prevvalue == 0) && value >= 255)
            || ! (prevvalue < 256 && (unicode_range || (! non_portable_endpoint && ((isLOWER_A(prevvalue) && isLOWER_A(value))


                                || (isUPPER_A(prevvalue)
                                    && isUPPER_A(value)))))))
        {
            cp_foldable_list = _add_range_to_invlist(cp_foldable_list, prevvalue, value);
        }
        else {
            
            U8 start = NATIVE_TO_LATIN1(prevvalue);
            unsigned j;
            U8 end = (value < 256) ? NATIVE_TO_LATIN1(value) : 255;
            for (j = start; j <= end; j++) {
                cp_foldable_list = add_cp_to_invlist(cp_foldable_list, LATIN1_TO_NATIVE(j));
            }
            if (value > 255) {
                cp_foldable_list = _add_range_to_invlist(cp_foldable_list, 256, value);
            }
        }


	range = 0; 
    } 

    if (   posix_warnings && av_tindex_skip_len_mg(posix_warnings) >= 0) {
        output_posix_warnings(pRExC_state, posix_warnings);
    }

    
    if (multi_char_matches) {
	SV * substitute_parse = newSVpvn_flags("?:", 2, SVs_TEMP);
        I32 cp_count;
	STRLEN len;
	char *save_end = RExC_end;
	char *save_parse = RExC_parse;
	char *save_start = RExC_start;
        Size_t constructed_prefix_len = 0; 
        bool first_time = TRUE;     
        I32 reg_flags;

        assert(! invert);
        
        assert(RExC_copy_start_in_constructed == RExC_precomp);


        if (invert) {
            sv_catpvs(substitute_parse, "(?:");
        }


        
        for (cp_count = av_tindex_skip_len_mg(multi_char_matches);
                        cp_count > 0;
                        cp_count--)
        {

            if (av_exists(multi_char_matches, cp_count)) {
                AV** this_array_ptr;
                SV* this_sequence;

                this_array_ptr = (AV**) av_fetch(multi_char_matches, cp_count, FALSE);
                while ((this_sequence = av_pop(*this_array_ptr)) != &PL_sv_undef)
                {
                    if (! first_time) {
                        sv_catpvs(substitute_parse, "|");
                    }
                    first_time = FALSE;

                    sv_catpv(substitute_parse, SvPVX(this_sequence));
                }
            }
        }

        
        if (element_count) {
            sv_catpvs(substitute_parse, "|[");
            constructed_prefix_len = SvCUR(substitute_parse);
            sv_catpvn(substitute_parse, orig_parse, RExC_parse - orig_parse);

            
            if (RExC_parse < RExC_end) {
                sv_catpvs(substitute_parse, "]");
            }
        }

        sv_catpvs(substitute_parse, ")");

        if (invert) {
            
            sv_catpvs(substitute_parse, "(*THEN)(*SKIP)(*FAIL)|.)");
        }


        
        RExC_copy_start_in_input = (char *) orig_parse;
	RExC_start = RExC_parse = SvPV(substitute_parse, len);
        RExC_copy_start_in_constructed = RExC_start + constructed_prefix_len;
	RExC_end = RExC_parse + len;
        RExC_in_multi_char_class = 1;

	ret = reg(pRExC_state, 1, &reg_flags, depth+1);

        *flagp |= reg_flags & (HASWIDTH|SIMPLE|SPSTART|POSTPONED|RESTART_PARSE|NEED_UTF8);

        
        RExC_parse = save_parse;
	RExC_start = RExC_copy_start_in_constructed = RExC_copy_start_in_input = save_start;
	RExC_end = save_end;
	RExC_in_multi_char_class = 0;
        SvREFCNT_dec_NN(multi_char_matches);
        return ret;
    }

    
    if (cp_foldable_list) {
        if (FOLD) {
            UV start, end;	

            SV* fold_intersection = NULL;
            SV** use_list;

            
            if (LOC) {
                use_list = &only_utf8_locale_list;
            }
            else {
                use_list = &cp_list;
            }

            
            _invlist_intersection(PL_in_some_fold, cp_foldable_list, &fold_intersection);

            
            invlist_iterinit(fold_intersection);
            while (invlist_iternext(fold_intersection, &start, &end)) {
                UV j;
                UV folded;

                
                for (j = start; j <= end; j++) {
                    U8 foldbuf[UTF8_MAXBYTES_CASE+1];
                    STRLEN foldlen;
                    unsigned int k;
                    Size_t folds_count;
                    unsigned int first_fold;
                    const unsigned int * remaining_folds;

                    if (j < 256) {

                        
                        if (      IS_IN_SOME_FOLD_L1(j)
                            && ! (LOC && j != MICRO_SIGN))
                        {

                            
                            if (isASCII(j) || ! DEPENDS_SEMANTICS) {
                                *use_list = add_cp_to_invlist(*use_list, PL_fold_latin1[j]);
                            }
                            else if (j != PL_fold_latin1[j]) {
                                upper_latin1_only_utf8_matches = add_cp_to_invlist( upper_latin1_only_utf8_matches, PL_fold_latin1[j]);


                            }
                        }

                        if (HAS_NONLATIN1_SIMPLE_FOLD_CLOSURE(j)
                            && (! isASCII(j) || ! ASCII_FOLD_RESTRICTED))
                        {
                            add_above_Latin1_folds(pRExC_state, (U8) j, use_list);

                        }
                        continue;
                    }

                    
                    folded = _to_uni_fold_flags(j, foldbuf, &foldlen, (ASCII_FOLD_RESTRICTED)
                                                        ? FOLD_FLAGS_NOMIX_ASCII : 0);

                    
                    folds_count = _inverse_folds(folded, &first_fold, &remaining_folds);
                    for (k = 0; k <= folds_count; k++) {
                        UV c = (k == 0)     
                                ? folded : (k == 1)
                                   ? first_fold   : remaining_folds[k-2];



                        
                        if ((   ASCII_FOLD_RESTRICTED && (isASCII(c) != isASCII(j))))
                        {
                            continue;
                        }

                        
                        if (c < 256 && LOC) {
                            *use_list = add_cp_to_invlist(*use_list, c);
                            continue;
                        }

                        if (isASCII(c) || c > 255 || AT_LEAST_UNI_SEMANTICS)
                        {
                            cp_list = add_cp_to_invlist(cp_list, c);
                        }
                        else {
                            
                            upper_latin1_only_utf8_matches = add_cp_to_invlist( upper_latin1_only_utf8_matches, c);


                        }
                    }
                }
            }
            SvREFCNT_dec_NN(fold_intersection);
        }

        
        _invlist_union(cp_list, cp_foldable_list, &cp_list);
	SvREFCNT_dec_NN(cp_foldable_list);
    }

    
    if (simple_posixes) {   
        if (cp_list) {
            _invlist_union(cp_list, simple_posixes, &cp_list);
            SvREFCNT_dec_NN(simple_posixes);
        }
        else {
            cp_list = simple_posixes;
        }
    }
    if (posixes || nposixes) {
        if (! DEPENDS_SEMANTICS) {

            
            if (posixes) {
                if (cp_list) {
                    _invlist_union(cp_list, posixes, &cp_list);
                    SvREFCNT_dec_NN(posixes);
                }
                else {
                    cp_list = posixes;
                }
            }
            if (nposixes) {
                if (cp_list) {
                    _invlist_union(cp_list, nposixes, &cp_list);
                    SvREFCNT_dec_NN(nposixes);
                }
                else {
                    cp_list = nposixes;
                }
            }
        }
        else {
            
            if (nposixes) {
                SV* only_non_utf8_list = invlist_clone(PL_UpperLatin1, NULL);

                
                if (cp_list) {
                    _invlist_union(cp_list, nposixes, &cp_list);
                    SvREFCNT_dec_NN(nposixes);
                    nposixes = NULL;
                }
                else {
                    cp_list = nposixes;
                }

                
                _invlist_union(posixes, cp_list, &cp_list);
                SvREFCNT_dec(posixes);

                
                if (upper_latin1_only_utf8_matches) {
                    _invlist_union(cp_list, upper_latin1_only_utf8_matches, &cp_list);

                    SvREFCNT_dec_NN(upper_latin1_only_utf8_matches);
                    upper_latin1_only_utf8_matches = NULL;
                }

                
                _invlist_subtract(only_non_utf8_list, cp_list, &only_non_utf8_list);
                if (_invlist_len(only_non_utf8_list) != 0) {
                    anyof_flags |= ANYOF_SHARED_d_MATCHES_ALL_NON_UTF8_NON_ASCII_non_d_WARN_SUPER;
                }
                SvREFCNT_dec_NN(only_non_utf8_list);
            }
            else {
                
                SV* nonascii_but_latin1_properties = NULL;
                _invlist_intersection(posixes, PL_UpperLatin1, &nonascii_but_latin1_properties);

                
                _invlist_union(upper_latin1_only_utf8_matches, nonascii_but_latin1_properties, &upper_latin1_only_utf8_matches);


                
                _invlist_subtract(posixes, nonascii_but_latin1_properties, &posixes);

                
                if (cp_list) {
                    _invlist_union(cp_list, posixes, &cp_list);
                    SvREFCNT_dec_NN(posixes);
                    posixes = NULL;
                }
                else {
                    cp_list = posixes;
                }

                SvREFCNT_dec(nonascii_but_latin1_properties);

                
                _invlist_subtract(upper_latin1_only_utf8_matches, cp_list, &upper_latin1_only_utf8_matches);

                if (_invlist_len(upper_latin1_only_utf8_matches) == 0) {
                    SvREFCNT_dec_NN(upper_latin1_only_utf8_matches);
                    upper_latin1_only_utf8_matches = NULL;
                }
            }
        }
    }

    
    if (properties) {
        if (cp_list) {

            
            if (warn_super) {
                warn_super = ! (invert ^ (invlist_highest(cp_list) > PERL_UNICODE_MAX));
            }

            _invlist_union(properties, cp_list, &cp_list);
            SvREFCNT_dec_NN(properties);
        }
        else {
            cp_list = properties;
        }

        if (warn_super) {
            anyof_flags |= ANYOF_SHARED_d_MATCHES_ALL_NON_UTF8_NON_ASCII_non_d_WARN_SUPER;

            
            optimizable = FALSE;
        }
    }

    

    
    if (LOC && FOLD) {

        
        if (only_utf8_locale_list && cp_list) {
            _invlist_subtract(only_utf8_locale_list, cp_list, &only_utf8_locale_list);

            if (_invlist_len(only_utf8_locale_list) == 0) {
                SvREFCNT_dec_NN(only_utf8_locale_list);
                only_utf8_locale_list = NULL;
            }
        }
        if (    only_utf8_locale_list || (cp_list && (   _invlist_contains_cp(cp_list, LATIN_CAPITAL_LETTER_I_WITH_DOT_ABOVE)
                            || _invlist_contains_cp(cp_list, LATIN_SMALL_LETTER_DOTLESS_I))))
        {
            has_runtime_dependency |= HAS_L_RUNTIME_DEPENDENCY;
            anyof_flags |= ANYOFL_FOLD |  ANYOFL_SHARED_UTF8_LOCALE_fold_HAS_MATCHES_nonfold_REQD;

        }
        else if (cp_list) { 
            UV start, end;
            invlist_iterinit(cp_list);
            if (invlist_iternext(cp_list, &start, &end) && start < 256) {
                anyof_flags |= ANYOFL_FOLD;
                has_runtime_dependency |= HAS_L_RUNTIME_DEPENDENCY;
            }
            invlist_iterfinish(cp_list);
        }
    }
    else if (   DEPENDS_SEMANTICS && (    upper_latin1_only_utf8_matches || (anyof_flags & ANYOF_SHARED_d_MATCHES_ALL_NON_UTF8_NON_ASCII_non_d_WARN_SUPER)))

    {
        RExC_seen_d_op = TRUE;
        has_runtime_dependency |= HAS_D_RUNTIME_DEPENDENCY;
    }

    
    if (     cp_list &&   invert && ! has_runtime_dependency)

    {
        _invlist_invert(cp_list);

	
	invert = FALSE;
    }

    if (ret_invlist) {
        *ret_invlist = cp_list;

        return RExC_emit;
    }

    
    *flagp |= HASWIDTH|SIMPLE;

    if (anyof_flags & ANYOF_LOCALE_FLAGS) {
        RExC_contains_locale = 1;
    }

    

    if (optimizable) {
        PERL_UINT_FAST8_T i;
        Size_t partial_cp_count = 0;
        UV start[MAX_FOLD_FROMS+1] = { 0 }; 
        UV   end[MAX_FOLD_FROMS+1] = { 0 };

        if (cp_list) { 

            invlist_iterinit(cp_list);
            for (i = 0; i <= MAX_FOLD_FROMS; i++) {
                if (! invlist_iternext(cp_list, &start[i], &end[i])) {
                    break;
                }
                partial_cp_count += end[i] - start[i] + 1;
            }

            invlist_iterfinish(cp_list);
        }

        
        if (start[0] == 0 && end[0] == UV_MAX) {
            if (invert) {
                ret = reganode(pRExC_state, OPFAIL, 0);
            }
            else {
                ret = reg_node(pRExC_state, SANY);
                MARK_NAUGHTY(1);
            }
            goto not_anyof;
        }

        
        if (posixl) {
            for (namedclass = 0; namedclass < ANYOF_POSIXL_MAX;
                                                        namedclass += 2)
            {
                if (   POSIXL_TEST(posixl, namedclass)      
                    && POSIXL_TEST(posixl, namedclass + 1)) 
                {
                    if (invert) {
                        ret = reganode(pRExC_state, OPFAIL, 0);
                    }
                    else {
                        ret = reg_node(pRExC_state, SANY);
                        MARK_NAUGHTY(1);
                    }
                    goto not_anyof;
                }
            }
            



            
            if (    isSINGLE_BIT_SET(posixl)
                && (partial_cp_count == 0 || start[0] > 255))
            {
                U8 classnum;
                SV * class_above_latin1 = NULL;
                bool already_inverted;
                bool are_equivalent;

                
                static const int MultiplyDeBruijnBitPosition2[32] = {
                    0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8, 31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9 };


                namedclass = MultiplyDeBruijnBitPosition2[(posixl * 0x077CB531U) >> 27];
                classnum = namedclass_to_classnum(namedclass);

                
                already_inverted = namedclass - classnum_to_namedclass(classnum);

                
                _invlist_intersection_maybe_complement_2nd( PL_AboveLatin1, PL_XPosix_ptrs[classnum], already_inverted, &class_above_latin1);



                are_equivalent = _invlistEQ(class_above_latin1, cp_list, FALSE);
                SvREFCNT_dec_NN(class_above_latin1);

                if (are_equivalent) {

                    
                    invert = invert ^ already_inverted;

                    ret = reg_node(pRExC_state, POSIXL + invert * (NPOSIXL - POSIXL));
                    FLAGS(REGNODE_p(ret)) = classnum;
                    goto not_anyof;
                }
            }
        }

        
        if (has_runtime_dependency & HAS_USER_DEFINED_PROPERTY) {
            goto is_anyof;
        }

        if (! has_runtime_dependency) {

            
            if (partial_cp_count == 0) {
                if (invert) {
                    ret = reg_node(pRExC_state, SANY);
                }
                else {
                    ret = reganode(pRExC_state, OPFAIL, 0);
                }

                goto not_anyof;
            }

            
            if (   start[0] == 0 && end[0] == '\n' - 1 && start[1] == '\n' + 1 && end[1] == UV_MAX)
            {
                assert (! invert);
                ret = reg_node(pRExC_state, REG_ANY);
                MARK_NAUGHTY(1);
                goto not_anyof;
            }
        }

        
        if (   ! posixl && ! invert   &&   partial_cp_count > 0 && partial_cp_count <= MAX_FOLD_FROMS + 1  && (start[0] < 256 || UTF || FOLD))





        {
            if (partial_cp_count == 1 && ! upper_latin1_only_utf8_matches)
            {
                

                if (LOC) {

                    
                    op = (FOLD) ? EXACTFL : EXACTL;
                }
                else if (! FOLD) { 
                    op = (start[0] < 256) ? EXACT : EXACT_ONLY8;
                }
                else if (start[0] < 256) { 

                    
                    op = IS_IN_SOME_FOLD_L1(start[0])
                         ? EXACTFU : EXACT;
                }
                else {  
                    op = _invlist_contains_cp(PL_InMultiCharFold, start[0])
                         ? EXACTFU_ONLY8 : EXACT_ONLY8;
                }

                value = start[0];
            }
            else if (  ! (has_runtime_dependency & ~HAS_D_RUNTIME_DEPENDENCY)
                     && _invlist_contains_cp(PL_in_some_fold, start[0]))
            {
                
                if (partial_cp_count == 2 && isASCII(start[0])) {

                    
                    assert(isALPHA(start[0]));
                    if (   end[0] == start[0]    && isALPHA_FOLD_EQ(start[0], start[1]))
                    {

                        

                        if (   ASCII_FOLD_RESTRICTED || HAS_NONLATIN1_SIMPLE_FOLD_CLOSURE(start[0]))
                        {
                            
                            op = EXACTFAA;
                        }
                        else if (HAS_NONLATIN1_FOLD_CLOSURE(start[0])) {

                            
                            op = (FOLD) ? EXACTFU : EXACTFAA;
                        }
                        else {

                            
                            op = EXACTFU;
                        }

                        value = toFOLD(start[0]);
                    }
                }
                else if (  ! upper_latin1_only_utf8_matches || (   _invlist_len(upper_latin1_only_utf8_matches)
                                                                          == 2 && PL_fold_latin1[ invlist_highest(upper_latin1_only_utf8_matches)] == start[0]))


                {
                    

                    Size_t foldlen;
                    U8 foldbuf[UTF8_MAXBYTES_CASE];
                    UV folded = _to_uni_fold_flags(start[0], foldbuf, &foldlen, 0);
                    unsigned int first_fold;
                    const unsigned int * remaining_folds;
                    Size_t folds_to_this_cp_count = _inverse_folds( folded, &first_fold, &remaining_folds);


                    Size_t folds_count = folds_to_this_cp_count + 1;
                    SV * fold_list = _new_invlist(folds_count);
                    unsigned int i;

                    
                    SV * all_cp_list = NULL;
                    SV ** use_this_list = &cp_list;

                    if (upper_latin1_only_utf8_matches) {
                        all_cp_list = _new_invlist(0);
                        use_this_list = &all_cp_list;
                        _invlist_union(cp_list, upper_latin1_only_utf8_matches, use_this_list);

                    }

                    
                    fold_list = add_cp_to_invlist(fold_list, start[0]);
                    fold_list = add_cp_to_invlist(fold_list, folded);
                    if (folds_to_this_cp_count > 0) {
                        fold_list = add_cp_to_invlist(fold_list, first_fold);
                        for (i = 0; i + 1 < folds_to_this_cp_count; i++) {
                            fold_list = add_cp_to_invlist(fold_list, remaining_folds[i]);
                        }
                    }

                    
                    if (_invlistEQ(*use_this_list, fold_list, 0  )
                    ) {

                        
                        if (start[0] > 255) {    
                            if (FOLD || ! _invlist_contains_cp( PL_InMultiCharFold, folded))
                            {
                                op = (LOC)
                                     ? EXACTFLU8 : (ASCII_FOLD_RESTRICTED)
                                       ? EXACTFAA : EXACTFU_ONLY8;
                                value = folded;
                            }
                        }   
                        else if (    FOLD &&  folded == 's' &&  DEPENDS_SEMANTICS)

                        {   
                            op = EXACTFU_S_EDGE;
                            value = folded;
                        }
                        else if (    FOLD || ! HAS_NONLATIN1_FOLD_CLOSURE(start[0]))
                        {
                            if (upper_latin1_only_utf8_matches) {
                                op = EXACTF;

                                
                                value = start[0];
                            }
                            else if (     UNLIKELY(start[0] == MICRO_SIGN)
                                     && ! UTF)
                            {   
                                op = (ASCII_FOLD_RESTRICTED)
                                     ? EXACTFAA : EXACTFUP;
                                value = MICRO_SIGN;
                            }
                            else if (     ASCII_FOLD_RESTRICTED && ! isASCII(start[0]))
                            {   
                                op = EXACTFAA;
                                value = folded;
                            }
                            else {
                                op = EXACTFU;
                                value = folded;
                            }
                        }
                    }

                    SvREFCNT_dec_NN(fold_list);
                    SvREFCNT_dec(all_cp_list);
                }
            }

            if (op != END) {

                

                if (! UTF && value > 255) {
                    SV * in_multis = NULL;

                    assert(FOLD);

                    
                    _invlist_intersection(PL_InMultiCharFold, cp_list, &in_multis);
                    if (UNLIKELY(_invlist_len(in_multis) != 0)) {
                        REQUIRE_UTF8(flagp);
                    }
                    else {
                        op = END;
                    }
                }

                if (op != END) {
                    U8 len = (UTF) ? UVCHR_SKIP(value) : 1;

                    ret = regnode_guts(pRExC_state, op, len, "exact");
                    FILL_NODE(ret, op);
                    RExC_emit += 1 + STR_SZ(len);
                    STR_LEN(REGNODE_p(ret)) = len;
                    if (len == 1) {
                        *STRING(REGNODE_p(ret)) = (U8) value;
                    }
                    else {
                        uvchr_to_utf8((U8 *) STRING(REGNODE_p(ret)), value);
                    }
                    goto not_anyof;
                }
            }
        }

        if (! has_runtime_dependency) {

            
            PERL_UINT_FAST8_T inverted = 0;

            const PERL_UINT_FAST8_T max_permissible = 0xFF;

            const PERL_UINT_FAST8_T max_permissible = 0x7F;

            
            if (invlist_highest(cp_list) > max_permissible) {
                _invlist_invert(cp_list);
                inverted = 1;
            }

            if (invlist_highest(cp_list) <= max_permissible) {
                UV this_start, this_end;
                UV lowest_cp = UV_MAX;  
                U8 bits_differing = 0;
                Size_t full_cp_count = 0;
                bool first_time = TRUE;

                
                invlist_iterinit(cp_list);
                while (invlist_iternext(cp_list, &this_start, &this_end)) {
                    unsigned int i = this_start;

                    if (first_time) {
                        if (! UVCHR_IS_INVARIANT(i)) {
                            goto done_anyofm;
                        }

                        first_time = FALSE;
                        lowest_cp = this_start;

                        
                        i++;
                    }

                    
                    for (; i <= this_end; i++) {
                        if (! UVCHR_IS_INVARIANT(i)) {
                            goto done_anyofm;
                        }

                        bits_differing  |= i ^ lowest_cp;
                    }

                    full_cp_count += this_end - this_start + 1;
                }
                invlist_iterfinish(cp_list);

                
                if (  (inverted || full_cp_count > 1)
                    && full_cp_count == 1U << PL_bitcount[bits_differing])
                {
                    U8 ANYOFM_mask;

                    op = ANYOFM + inverted;;

                    
                    ANYOFM_mask = ~ bits_differing; 

                    
                    ret = reganode(pRExC_state, op, lowest_cp);
                    FLAGS(REGNODE_p(ret)) = ANYOFM_mask;
                }
            }
          done_anyofm:

            if (inverted) {
                _invlist_invert(cp_list);
            }

            if (op != END) {
                goto not_anyof;
            }
        }

        if (! (anyof_flags & ANYOF_LOCALE_FLAGS)) {
            PERL_UINT_FAST8_T type;
            SV * intersection = NULL;
            SV* d_invlist = NULL;

            

            for (type = POSIXA; type >= POSIXD; type--) {
                int posix_class;

                if (type == POSIXL) {   
                    continue;
                }

                for (posix_class = 0;
                     posix_class <= _HIGHEST_REGCOMP_DOT_H_SYNC;
                     posix_class++)
                {
                    SV** our_code_points = &cp_list;
                    SV** official_code_points;
                    int try_inverted;

                    if (type == POSIXA) {
                        official_code_points = &PL_Posix_ptrs[posix_class];
                    }
                    else {
                        official_code_points = &PL_XPosix_ptrs[posix_class];
                    }

                    
                    if (! *official_code_points) {
                        continue;
                    }

                    
                    for (try_inverted = 0; try_inverted < 2; try_inverted++) {
                        bool this_inverted = invert ^ try_inverted;

                        if (type != POSIXD) {

                            
                            if (has_runtime_dependency & HAS_D_RUNTIME_DEPENDENCY)
                            {
                                continue;
                            }
                        }
                        else  if (! this_inverted) {

                            
                            _invlist_intersection(cp_list, PL_UpperLatin1, &intersection);
                            if (_invlist_len(intersection) != 0) {
                                continue;
                            }

                            SvREFCNT_dec(d_invlist);
                            d_invlist = invlist_clone(cp_list, NULL);

                            
                            if (upper_latin1_only_utf8_matches) {
                                _invlist_union( d_invlist, upper_latin1_only_utf8_matches, &d_invlist);


                            }
                            our_code_points = &d_invlist;
                        }
                        else {  
                            if (! (anyof_flags & ANYOF_SHARED_d_MATCHES_ALL_NON_UTF8_NON_ASCII_non_d_WARN_SUPER))
                            {
                                continue;
                            }
                            our_code_points = &cp_list;
                        }

                        
                        if (_invlistEQ(*our_code_points, *official_code_points, try_inverted))

                        {
                            
                            ret = reg_node(pRExC_state, (try_inverted)
                                                        ? type + NPOSIXA - POSIXA : type);

                            FLAGS(REGNODE_p(ret)) = posix_class;
                            SvREFCNT_dec(d_invlist);
                            SvREFCNT_dec(intersection);
                            goto not_anyof;
                        }
                    }
                }
            }
            SvREFCNT_dec(d_invlist);
            SvREFCNT_dec(intersection);
        }

        
        if (     start[0] >= NUM_ANYOF_CODE_POINTS && ! LOC && ! upper_latin1_only_utf8_matches &&   anyof_flags == 0)


        {
            UV highest_cp = invlist_highest(cp_list);

            
            if (highest_cp > IV_MAX) {
                anyof_flags = 0;
            }
            else {
                U8 low_utf8[UTF8_MAXBYTES+1];
                U8 high_utf8[UTF8_MAXBYTES+1];

                (void) uvchr_to_utf8(low_utf8, start[0]);
                (void) uvchr_to_utf8(high_utf8, invlist_highest(cp_list));

                anyof_flags = (low_utf8[0] == high_utf8[0])
                            ? low_utf8[0] : 0;
            }

            op = ANYOFH;
        }
    }   

  is_anyof: 
    if (op != ANYOFH) {
        op = (has_runtime_dependency & HAS_D_RUNTIME_DEPENDENCY)
             ? ANYOFD : ((posixl)
                ? ANYOFPOSIXL : ((LOC)
                   ? ANYOFL : ANYOF));
    }

    ret = regnode_guts(pRExC_state, op, regarglen[op], "anyof");
    FILL_NODE(ret, op);        
    RExC_emit += 1 + regarglen[op];
    ANYOF_FLAGS(REGNODE_p(ret)) = anyof_flags;

    

    populate_ANYOF_from_invlist(REGNODE_p(ret), &cp_list);

    if (posixl) {
        ANYOF_POSIXL_SET_TO_BITMAP(REGNODE_p(ret), posixl);
    }

    if (invert) {
        ANYOF_FLAGS(REGNODE_p(ret)) |= ANYOF_INVERT;
    }

    
    if (upper_latin1_only_utf8_matches) {
	if (cp_list) {
	    _invlist_union(cp_list, upper_latin1_only_utf8_matches, &cp_list);

	    SvREFCNT_dec_NN(upper_latin1_only_utf8_matches);
	}
	else {
	    cp_list = upper_latin1_only_utf8_matches;
	}
        ANYOF_FLAGS(REGNODE_p(ret)) |= ANYOF_SHARED_d_UPPER_LATIN1_UTF8_STRING_MATCHES_non_d_RUNTIME_USER_PROP;
    }

    set_ANYOF_arg(pRExC_state, REGNODE_p(ret), cp_list, (HAS_NONLOCALE_RUNTIME_PROPERTY_DEFINITION)
                   ? listsv : NULL, only_utf8_locale_list);
    return ret;

  not_anyof:

    

    Set_Node_Offset_Length(REGNODE_p(ret), orig_parse - RExC_start, RExC_parse - orig_parse);;
    SvREFCNT_dec(cp_list);;
    return ret;
}



STATIC void S_set_ANYOF_arg(pTHX_ RExC_state_t* const pRExC_state, regnode* const node, SV* const cp_list, SV* const runtime_defns, SV* const only_utf8_locale_list)




{
    

    UV n;

    PERL_ARGS_ASSERT_SET_ANYOF_ARG;

    if (! cp_list && ! runtime_defns && ! only_utf8_locale_list) {
        assert(! (ANYOF_FLAGS(node)
                & ANYOF_SHARED_d_UPPER_LATIN1_UTF8_STRING_MATCHES_non_d_RUNTIME_USER_PROP));
	ARG_SET(node, ANYOF_ONLY_HAS_BITMAP);
    }
    else {
	AV * const av = newAV();
	SV *rv;

        if (cp_list) {
            av_store(av, INVLIST_INDEX, cp_list);
        }

        if (only_utf8_locale_list) {
            av_store(av, ONLY_LOCALE_MATCHES_INDEX, only_utf8_locale_list);
        }

        if (runtime_defns) {
            av_store(av, DEFERRED_USER_DEFINED_INDEX, SvREFCNT_inc(runtime_defns));
        }

	rv = newRV_noinc(MUTABLE_SV(av));
	n = add_data(pRExC_state, STR_WITH_LEN("s"));
	RExC_rxi->data->data[n] = (void*)rv;
	ARG_SET(node, n);
    }
}


SV * Perl__get_regclass_nonbitmap_data(pTHX_ const regexp *prog, const regnode* node, bool doinit, SV** listsvp, SV** only_utf8_locale_ptr, SV** output_invlist)






{
    

    SV *si  = NULL;         
    SV* invlist = NULL;

    RXi_GET_DECL(prog, progi);
    const struct reg_data * const data = prog ? progi->data : NULL;

    PERL_ARGS_ASSERT__GET_REGCLASS_NONBITMAP_DATA;
    assert(! output_invlist || listsvp);

    if (data && data->count) {
	const U32 n = ARG(node);

	if (data->what[n] == 's') {
	    SV * const rv = MUTABLE_SV(data->data[n]);
	    AV * const av = MUTABLE_AV(SvRV(rv));
	    SV **const ary = AvARRAY(av);

            invlist = ary[INVLIST_INDEX];

            if (av_tindex_skip_len_mg(av) >= ONLY_LOCALE_MATCHES_INDEX) {
                *only_utf8_locale_ptr = ary[ONLY_LOCALE_MATCHES_INDEX];
            }

            if (av_tindex_skip_len_mg(av) >= DEFERRED_USER_DEFINED_INDEX) {
                si = ary[DEFERRED_USER_DEFINED_INDEX];
            }

	    if (doinit && (si || invlist)) {
                if (si) {
                    bool user_defined;
                    SV * msg = newSVpvs_flags("", SVs_TEMP);

                    SV * prop_definition = handle_user_defined_property( "", 0, FALSE, SvPVX_const(si)[1] - '0', TRUE, FALSE, si, &user_defined, msg, 0 );









                    if (SvCUR(msg)) {
                        assert(prop_definition == NULL);

                        Perl_croak(aTHX_ "%" UTF8f, UTF8fARG(SvUTF8(msg), SvCUR(msg), SvPVX(msg)));
                    }

                    if (invlist) {
                        _invlist_union(invlist, prop_definition, &invlist);
                        SvREFCNT_dec_NN(prop_definition);
                    }
                    else {
                        invlist = prop_definition;
                    }

                    STATIC_ASSERT_STMT(ONLY_LOCALE_MATCHES_INDEX == 1 + INVLIST_INDEX);
                    STATIC_ASSERT_STMT(DEFERRED_USER_DEFINED_INDEX == 1 + ONLY_LOCALE_MATCHES_INDEX);

                    av_store(av, INVLIST_INDEX, invlist);
                    av_fill(av, (ary[ONLY_LOCALE_MATCHES_INDEX])
                                 ? ONLY_LOCALE_MATCHES_INDEX:
                                 INVLIST_INDEX);
                    si = NULL;
                }
	    }
	}
    }

    
    if (listsvp) {
	SV* matches_string = NULL;

        
	if (si) {
            
            if (! output_invlist) {
                matches_string = newSVsv(si);
            }
            else {
                
                const char *si_string = SvPVX(si);
                STRLEN remaining = SvCUR(si);
                UV prev_cp = 0;
                U8 count = 0;

                
                while (*si_string != '\n' && remaining > 0) {
                    si_string++;
                    remaining--;
                }
                assert(remaining > 0);

                si_string++;
                remaining--;

                while (remaining > 0) {

                    
                    I32 grok_flags =  PERL_SCAN_SILENT_ILLDIGIT |PERL_SCAN_SILENT_NON_PORTABLE;
                    STRLEN len = remaining;
                    UV cp = grok_hex(si_string, &len, &grok_flags, NULL);

                    
                    if (   *(si_string + len) == '\n') {
                        if (count) {    
                            *output_invlist = _add_range_to_invlist(*output_invlist, prev_cp, cp);
                        }
                        else {
                            *output_invlist = add_cp_to_invlist(*output_invlist, cp);
                        }
                        count = 0;
                        goto prepare_for_next_iteration;
                    }

                    
                    if (*(si_string + len) == '\t') {
                        assert(count == 0);

                        prev_cp = cp;
                        count = 1;
                      prepare_for_next_iteration:
                        si_string += len + 1;
                        remaining -= len + 1;
                        continue;
                    }

                    

                    remaining -= len;
                    while (*(si_string + len) != '\n' && remaining > 0) {
                        remaining--;
                        len++;
                    }
                    if (*(si_string + len) == '\n') {
                        len++;
                        remaining--;
                    }
                    if (matches_string) {
                        sv_catpvn(matches_string, si_string, len - 1);
                    }
                    else {
                        matches_string = newSVpvn(si_string, len - 1);
                    }
                    si_string += len;
                    sv_catpvs(matches_string, " ");
                } 

                assert(matches_string);
                if (SvCUR(matches_string)) {  
                    SvCUR_set(matches_string, SvCUR(matches_string) - 1);
                }
            } 
	}

        
        if (invlist) {

            
            if (! output_invlist) {
                if ( ! matches_string) {
                    matches_string = newSVpvs("\n");
                }
                sv_catsv(matches_string, invlist_contents(invlist, TRUE ));

            }
            else if (! *output_invlist) {
                *output_invlist = invlist_clone(invlist, NULL);
            }
            else {
                _invlist_union(*output_invlist, invlist, output_invlist);
            }
        }

	*listsvp = matches_string;
    }

    return invlist;
}




PERL_STATIC_INLINE char* S_reg_skipcomment(RExC_state_t *pRExC_state, char* p)
{
    PERL_ARGS_ASSERT_REG_SKIPCOMMENT;

    assert(*p == '#');

    while (p < RExC_end) {
        if (*(++p) == '\n') {
            return p+1;
        }
    }

    
    RExC_seen |= REG_RUN_ON_COMMENT_SEEN;
    return p;
}

STATIC void S_skip_to_be_ignored_text(pTHX_ RExC_state_t *pRExC_state, char ** p, const bool force_to_xmod )



{
    

    const bool use_xmod = force_to_xmod || (RExC_flags & RXf_PMf_EXTENDED);

    PERL_ARGS_ASSERT_SKIP_TO_BE_IGNORED_TEXT;

    assert( ! UTF || UTF8_IS_INVARIANT(**p) || UTF8_IS_START(**p));

    for (;;) {
	if (RExC_end - (*p) >= 3 && *(*p)     == '(' && *(*p + 1) == '?' && *(*p + 2) == '#')


	{
	    while (*(*p) != ')') {
		if ((*p) == RExC_end)
		    FAIL("Sequence (?#... not terminated");
		(*p)++;
	    }
	    (*p)++;
	    continue;
	}

	if (use_xmod) {
            const char * save_p = *p;
            while ((*p) < RExC_end) {
                STRLEN len;
                if ((len = is_PATWS_safe((*p), RExC_end, UTF))) {
                    (*p) += len;
                }
                else if (*(*p) == '#') {
                    (*p) = reg_skipcomment(pRExC_state, (*p));
                }
                else {
                    break;
                }
            }
            if (*p != save_p) {
                continue;
            }
	}

        break;
    }

    return;
}



STATIC void S_nextchar(pTHX_ RExC_state_t *pRExC_state)
{
    PERL_ARGS_ASSERT_NEXTCHAR;

    if (RExC_parse < RExC_end) {
        assert(   ! UTF || UTF8_IS_INVARIANT(*RExC_parse)
               || UTF8_IS_START(*RExC_parse));

        RExC_parse += (UTF)
                      ? UTF8_SAFE_SKIP(RExC_parse, RExC_end)
                      : 1;

        skip_to_be_ignored_text(pRExC_state, &RExC_parse, FALSE  );
    }
}

STATIC void S_change_engine_size(pTHX_ RExC_state_t *pRExC_state, const Ptrdiff_t size)
{
    

    PERL_ARGS_ASSERT_CHANGE_ENGINE_SIZE;

    RExC_size += size;

    Renewc(RExC_rxi, sizeof(regexp_internal) + (RExC_size + 1) * sizeof(regnode),  char, regexp_internal);



    if ( RExC_rxi == NULL )
	FAIL("Regexp out of space");
    RXi_SET(RExC_rx, RExC_rxi);

    RExC_emit_start = RExC_rxi->program;
    if (size > 0) {
        Zero(REGNODE_p(RExC_emit), size, regnode);
    }


    Renew(RExC_offsets, 2*RExC_size+1, U32);
    if (size > 0) {
        Zero(RExC_offsets + 2*(RExC_size - size) + 1, 2 * size, U32);
    }
    RExC_offsets[0] = RExC_size;

}

STATIC regnode_offset S_regnode_guts(pTHX_ RExC_state_t *pRExC_state, const U8 op, const STRLEN extra_size, const char* const name)
{
    

    const regnode_offset ret = RExC_emit;

    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_REGNODE_GUTS;

    SIZE_ALIGN(RExC_size);
    change_engine_size(pRExC_state, (Ptrdiff_t) 1 + extra_size);
    NODE_ALIGN_FILL(REGNODE_p(ret));

    PERL_UNUSED_ARG(name);
    PERL_UNUSED_ARG(op);

    assert(extra_size >= regarglen[op] || PL_regkind[op] == ANYOF);

    if (RExC_offsets) {         
	MJD_OFFSET_DEBUG( ("%s:%d: (op %s) %s %" UVuf " (len %" UVuf ") (max %" UVuf ").\n", name, __LINE__, PL_reg_name[op], (UV)(RExC_emit) > RExC_offsets[0] ? "Overwriting end of array!\n" : "OK", (UV)(RExC_emit), (UV)(RExC_parse - RExC_start), (UV)RExC_offsets[0]));







	Set_Node_Offset(REGNODE_p(RExC_emit), RExC_parse + (op == END));
    }

    return(ret);
}


STATIC regnode_offset  S_reg_node(pTHX_ RExC_state_t *pRExC_state, U8 op)
{
    const regnode_offset ret = regnode_guts(pRExC_state, op, regarglen[op], "reg_node");
    regnode_offset ptr = ret;

    PERL_ARGS_ASSERT_REG_NODE;

    assert(regarglen[op] == 0);

    FILL_ADVANCE_NODE(ptr, op);
    RExC_emit = ptr;
    return(ret);
}


STATIC regnode_offset  S_reganode(pTHX_ RExC_state_t *pRExC_state, U8 op, U32 arg)
{
    const regnode_offset ret = regnode_guts(pRExC_state, op, regarglen[op], "reganode");
    regnode_offset ptr = ret;

    PERL_ARGS_ASSERT_REGANODE;

    
    assert(regarglen[op] == 1);

    FILL_ADVANCE_NODE_ARG(ptr, op, arg);
    RExC_emit = ptr;
    return(ret);
}

STATIC regnode_offset S_reg2Lanode(pTHX_ RExC_state_t *pRExC_state, const U8 op, const U32 arg1, const I32 arg2)
{
    

    const regnode_offset ret = regnode_guts(pRExC_state, op, regarglen[op], "reg2Lanode");
    regnode_offset ptr = ret;

    PERL_ARGS_ASSERT_REG2LANODE;

    assert(regarglen[op] == 2);

    FILL_ADVANCE_NODE_2L_ARG(ptr, op, arg1, arg2);
    RExC_emit = ptr;
    return(ret);
}


STATIC void S_reginsert(pTHX_ RExC_state_t *pRExC_state, const U8 op, const regnode_offset operand, const U32 depth)

{
    regnode *src;
    regnode *dst;
    regnode *place;
    const int offset = regarglen[(U8)op];
    const int size = NODE_STEP_REGNODE + offset;
    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_REGINSERT;
    PERL_UNUSED_CONTEXT;
    PERL_UNUSED_ARG(depth);

    DEBUG_PARSE_FMT("inst"," - %s", PL_reg_name[op]);
    assert(!RExC_study_started); 
    change_engine_size(pRExC_state, (Ptrdiff_t) size);
    src = REGNODE_p(RExC_emit);
    RExC_emit += size;
    dst = REGNODE_p(RExC_emit);

    
    if (! IN_PARENS_PASS && RExC_open_parens) {
        int paren;
        
        
        for ( paren=0 ; paren < RExC_npar ; paren++ ) {
            
            if ( paren && RExC_open_parens[paren] >= operand ) {
                
                RExC_open_parens[paren] += size;
            } else {
                
            }
            if ( RExC_close_parens[paren] >= operand ) {
                
                RExC_close_parens[paren] += size;
            } else {
                
            }
        }
    }
    if (RExC_end_op)
        RExC_end_op += size;

    while (src > REGNODE_p(operand)) {
	StructCopy(--src, --dst, regnode);

        if (RExC_offsets) {     
	    MJD_OFFSET_DEBUG( ("%s(%d): (op %s) %s copy %" UVuf " -> %" UVuf " (max %" UVuf ").\n", "reginsert", __LINE__, PL_reg_name[op], (UV)(REGNODE_OFFSET(dst)) > RExC_offsets[0] ? "Overwriting end of array!\n" : "OK", (UV)REGNODE_OFFSET(src), (UV)REGNODE_OFFSET(dst), (UV)RExC_offsets[0]));








	    Set_Node_Offset_To_R(REGNODE_OFFSET(dst), Node_Offset(src));
	    Set_Node_Length_To_R(REGNODE_OFFSET(dst), Node_Length(src));
        }

    }

    place = REGNODE_p(operand);	

    if (RExC_offsets) {         
	MJD_OFFSET_DEBUG( ("%s(%d): (op %s) %s %" UVuf " <- %" UVuf " (max %" UVuf ").\n", "reginsert", __LINE__, PL_reg_name[op], (UV)REGNODE_OFFSET(place) > RExC_offsets[0] ? "Overwriting end of array!\n" : "OK", (UV)REGNODE_OFFSET(place), (UV)(RExC_parse - RExC_start), (UV)RExC_offsets[0]));








	Set_Node_Offset(place, RExC_parse);
	Set_Node_Length(place, 1);
    }

    src = NEXTOPER(place);
    FLAGS(place) = 0;
    FILL_NODE(operand, op);

    
    Zero(src, offset, regnode);
}


STATIC bool S_regtail(pTHX_ RExC_state_t * pRExC_state, const regnode_offset p, const regnode_offset val, const U32 depth)



{
    regnode_offset scan;
    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_REGTAIL;

    PERL_UNUSED_ARG(depth);


    
    scan = (regnode_offset) p;
    for (;;) {
	regnode * const temp = regnext(REGNODE_p(scan));
        DEBUG_PARSE_r({
            DEBUG_PARSE_MSG((scan==p ? "tail" : ""));
            regprop(RExC_rx, RExC_mysv, REGNODE_p(scan), NULL, pRExC_state);
            Perl_re_printf( aTHX_  "~ %s (%d) %s %s\n", SvPV_nolen_const(RExC_mysv), scan, (temp == NULL ? "->" : ""), (temp == NULL ? PL_reg_name[OP(REGNODE_p(val))] : "")


            );
        });
        if (temp == NULL)
            break;
        scan = REGNODE_OFFSET(temp);
    }

    if (reg_off_by_arg[OP(REGNODE_p(scan))]) {
        assert((UV) (val - scan) <= U32_MAX);
        ARG_SET(REGNODE_p(scan), val - scan);
    }
    else {
        if (val - scan > U16_MAX) {
            
            NEXT_OFF(REGNODE_p(scan)) = U16_MAX;
            return FALSE;
        }
        NEXT_OFF(REGNODE_p(scan)) = val - scan;
    }

    return TRUE;
}





STATIC bool S_regtail_study(pTHX_ RExC_state_t *pRExC_state, regnode_offset p, const regnode_offset val, U32 depth)

{
    regnode_offset scan;
    U8 exact = PSEUDO;

    I32 min = 0;

    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_REGTAIL_STUDY;


    

    scan = p;
    for (;;) {
        regnode * const temp = regnext(REGNODE_p(scan));

        if (PL_regkind[OP(REGNODE_p(scan))] == EXACT) {
	    bool unfolded_multi_char;	
            if (join_exact(pRExC_state, scan, &min, &unfolded_multi_char, 1, REGNODE_p(val), depth+1))
                return TRUE; 
	}

        if ( exact ) {
            switch (OP(REGNODE_p(scan))) {
                case EXACT:
                case EXACT_ONLY8:
                case EXACTL:
                case EXACTF:
                case EXACTFU_S_EDGE:
                case EXACTFAA_NO_TRIE:
                case EXACTFAA:
                case EXACTFU:
                case EXACTFU_ONLY8:
                case EXACTFLU8:
                case EXACTFUP:
                case EXACTFL:
                        if( exact == PSEUDO )
                            exact= OP(REGNODE_p(scan));
                        else if ( exact != OP(REGNODE_p(scan)) )
                            exact= 0;
                case NOTHING:
                    break;
                default:
                    exact= 0;
            }
        }
        DEBUG_PARSE_r({
            DEBUG_PARSE_MSG((scan==p ? "tsdy" : ""));
            regprop(RExC_rx, RExC_mysv, REGNODE_p(scan), NULL, pRExC_state);
            Perl_re_printf( aTHX_  "~ %s (%d) -> %s\n", SvPV_nolen_const(RExC_mysv), scan, PL_reg_name[exact]);


        });
	if (temp == NULL)
	    break;
	scan = REGNODE_OFFSET(temp);
    }
    DEBUG_PARSE_r({
        DEBUG_PARSE_MSG("");
        regprop(RExC_rx, RExC_mysv, REGNODE_p(val), NULL, pRExC_state);
        Perl_re_printf( aTHX_ "~ attach to %s (%" IVdf ") offset to %" IVdf "\n", SvPV_nolen_const(RExC_mysv), (IV)val, (IV)(val - scan)



        );
    });
    if (reg_off_by_arg[OP(REGNODE_p(scan))]) {
        assert((UV) (val - scan) <= U32_MAX);
	ARG_SET(REGNODE_p(scan), val - scan);
    }
    else {
        if (val - scan > U16_MAX) {
            
            NEXT_OFF(REGNODE_p(scan)) = U16_MAX;
            return FALSE;
        }
	NEXT_OFF(REGNODE_p(scan)) = val - scan;
    }

    return TRUE; 
}


STATIC SV* S_get_ANYOFM_contents(pTHX_ const regnode * n) {

    

    SV * cp_list = _new_invlist(-1);
    const U8 lowest = (U8) ARG(n);
    unsigned int i;
    U8 count = 0;
    U8 needed = 1U << PL_bitcount[ (U8) ~ FLAGS(n)];

    PERL_ARGS_ASSERT_GET_ANYOFM_CONTENTS;

    
    for (i = lowest; i <= 0xFF; i++) {
        if ((i & FLAGS(n)) == ARG(n)) {
            cp_list = add_cp_to_invlist(cp_list, i);
            count++;

            
            if (count >= needed) break;
        }
    }

    if (OP(n) == NANYOFM) {
        _invlist_invert(cp_list);
    }
    return cp_list;
}




static void S_regdump_intflags(pTHX_ const char *lead, const U32 flags)
{
    int bit;
    int set=0;

    ASSUME(REG_INTFLAGS_NAME_SIZE <= sizeof(flags)*8);

    for (bit=0; bit<REG_INTFLAGS_NAME_SIZE; bit++) {
        if (flags & (1<<bit)) {
            if (!set++ && lead)
                Perl_re_printf( aTHX_  "%s", lead);
            Perl_re_printf( aTHX_  "%s ", PL_reg_intflags_name[bit]);
        }
    }
    if (lead)  {
        if (set)
            Perl_re_printf( aTHX_  "\n");
        else Perl_re_printf( aTHX_  "%s[none-set]\n", lead);
    }
}

static void S_regdump_extflags(pTHX_ const char *lead, const U32 flags)
{
    int bit;
    int set=0;
    regex_charset cs;

    ASSUME(REG_EXTFLAGS_NAME_SIZE <= sizeof(flags)*8);

    for (bit=0; bit<REG_EXTFLAGS_NAME_SIZE; bit++) {
        if (flags & (1<<bit)) {
	    if ((1<<bit) & RXf_PMf_CHARSET) {	
		continue;
	    }
            if (!set++ && lead)
                Perl_re_printf( aTHX_  "%s", lead);
            Perl_re_printf( aTHX_  "%s ", PL_reg_extflags_name[bit]);
        }
    }
    if ((cs = get_regex_charset(flags)) != REGEX_DEPENDS_CHARSET) {
            if (!set++ && lead) {
                Perl_re_printf( aTHX_  "%s", lead);
            }
            switch (cs) {
                case REGEX_UNICODE_CHARSET:
                    Perl_re_printf( aTHX_  "UNICODE");
                    break;
                case REGEX_LOCALE_CHARSET:
                    Perl_re_printf( aTHX_  "LOCALE");
                    break;
                case REGEX_ASCII_RESTRICTED_CHARSET:
                    Perl_re_printf( aTHX_  "ASCII-RESTRICTED");
                    break;
                case REGEX_ASCII_MORE_RESTRICTED_CHARSET:
                    Perl_re_printf( aTHX_  "ASCII-MORE_RESTRICTED");
                    break;
                default:
                    Perl_re_printf( aTHX_  "UNKNOWN CHARACTER SET");
                    break;
            }
    }
    if (lead)  {
        if (set)
            Perl_re_printf( aTHX_  "\n");
        else Perl_re_printf( aTHX_  "%s[none-set]\n", lead);
    }
}


void Perl_regdump(pTHX_ const regexp *r)
{

    int i;
    SV * const sv = sv_newmortal();
    SV *dsv= sv_newmortal();
    RXi_GET_DECL(r, ri);
    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_REGDUMP;

    (void)dumpuntil(r, ri->program, ri->program + 1, NULL, NULL, sv, 0, 0);

    
    for (i = 0; i < 2; i++) {
        if (r->substrs->data[i].substr) {
            RE_PV_QUOTED_DECL(s, 0, dsv, SvPVX_const(r->substrs->data[i].substr), RE_SV_DUMPLEN(r->substrs->data[i].substr), PL_dump_re_max_len);


            Perl_re_printf( aTHX_ "%s %s%s at %" IVdf "..%" UVuf " ", i ? "floating" : "anchored", s, RE_SV_TAIL(r->substrs->data[i].substr), (IV)r->substrs->data[i].min_offset, (UV)r->substrs->data[i].max_offset);





        }
        else if (r->substrs->data[i].utf8_substr) {
            RE_PV_QUOTED_DECL(s, 1, dsv, SvPVX_const(r->substrs->data[i].utf8_substr), RE_SV_DUMPLEN(r->substrs->data[i].utf8_substr), 30);


            Perl_re_printf( aTHX_ "%s utf8 %s%s at %" IVdf "..%" UVuf " ", i ? "floating" : "anchored", s, RE_SV_TAIL(r->substrs->data[i].utf8_substr), (IV)r->substrs->data[i].min_offset, (UV)r->substrs->data[i].max_offset);





        }
    }

    if (r->check_substr || r->check_utf8)
        Perl_re_printf( aTHX_ (const char *)
		      (   r->check_substr == r->substrs->data[1].substr && r->check_utf8   == r->substrs->data[1].utf8_substr ? "(checking floating" : "(checking anchored"));

    if (r->intflags & PREGf_NOSCAN)
        Perl_re_printf( aTHX_  " noscan");
    if (r->extflags & RXf_CHECK_ALL)
        Perl_re_printf( aTHX_  " isall");
    if (r->check_substr || r->check_utf8)
        Perl_re_printf( aTHX_  ") ");

    if (ri->regstclass) {
        regprop(r, sv, ri->regstclass, NULL, NULL);
        Perl_re_printf( aTHX_  "stclass %s ", SvPVX_const(sv));
    }
    if (r->intflags & PREGf_ANCH) {
        Perl_re_printf( aTHX_  "anchored");
        if (r->intflags & PREGf_ANCH_MBOL)
            Perl_re_printf( aTHX_  "(MBOL)");
        if (r->intflags & PREGf_ANCH_SBOL)
            Perl_re_printf( aTHX_  "(SBOL)");
        if (r->intflags & PREGf_ANCH_GPOS)
            Perl_re_printf( aTHX_  "(GPOS)");
        Perl_re_printf( aTHX_ " ");
    }
    if (r->intflags & PREGf_GPOS_SEEN)
        Perl_re_printf( aTHX_  "GPOS:%" UVuf " ", (UV)r->gofs);
    if (r->intflags & PREGf_SKIP)
        Perl_re_printf( aTHX_  "plus ");
    if (r->intflags & PREGf_IMPLICIT)
        Perl_re_printf( aTHX_  "implicit ");
    Perl_re_printf( aTHX_  "minlen %" IVdf " ", (IV)r->minlen);
    if (r->extflags & RXf_EVAL_SEEN)
        Perl_re_printf( aTHX_  "with eval ");
    Perl_re_printf( aTHX_  "\n");
    DEBUG_FLAGS_r({
        regdump_extflags("r->extflags: ", r->extflags);
        regdump_intflags("r->intflags: ", r->intflags);
    });

    PERL_ARGS_ASSERT_REGDUMP;
    PERL_UNUSED_CONTEXT;
    PERL_UNUSED_ARG(r);

}











static const char * const anyofs[] = {
    "\\w", "\\W", "\\d", "\\D", "[:alpha:]", "[:^alpha:]", "[:lower:]", "[:^lower:]", "[:upper:]", "[:^upper:]", "[:punct:]", "[:^punct:]", "[:print:]", "[:^print:]", "[:alnum:]", "[:^alnum:]", "[:graph:]", "[:^graph:]", "[:cased:]", "[:^cased:]", "\\s", "\\S", "[:blank:]", "[:^blank:]", "[:xdigit:]", "[:^xdigit:]", "[:cntrl:]", "[:^cntrl:]", "[:ascii:]", "[:^ascii:]", "\\v", "\\V" };



































void Perl_regprop(pTHX_ const regexp *prog, SV *sv, const regnode *o, const regmatch_info *reginfo, const RExC_state_t *pRExC_state)
{

    dVAR;
    int k;
    RXi_GET_DECL(prog, progi);
    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_REGPROP;

    SvPVCLEAR(sv);

    if (OP(o) > REGNODE_MAX)		
	
	Perl_croak(aTHX_ "Corrupted regexp opcode %d > %d", (int)OP(o), (int)REGNODE_MAX);
    sv_catpv(sv, PL_reg_name[OP(o)]); 

    k = PL_regkind[OP(o)];

    if (k == EXACT) {
	sv_catpvs(sv, " ");
	
	pv_pretty(sv, STRING(o), STR_LEN(o), PL_dump_re_max_len, PL_colors[0], PL_colors[1], PERL_PV_ESCAPE_UNI_DETECT | PERL_PV_ESCAPE_NONASCII   | PERL_PV_PRETTY_ELLIPSES   | PERL_PV_PRETTY_LTGT       | PERL_PV_PRETTY_NOCLEAR );






    } else if (k == TRIE) {
	
        const char op = OP(o);
        const U32 n = ARG(o);
        const reg_ac_data * const ac = IS_TRIE_AC(op) ? (reg_ac_data *)progi->data->data[n] :
               NULL;
        const reg_trie_data * const trie = (reg_trie_data*)progi->data->data[!IS_TRIE_AC(op) ? n : ac->trie];

        Perl_sv_catpvf(aTHX_ sv, "-%s", PL_reg_name[o->flags]);
        DEBUG_TRIE_COMPILE_r({
          if (trie->jump)
            sv_catpvs(sv, "(JUMP)");
          Perl_sv_catpvf(aTHX_ sv, "<S:%" UVuf "/%" IVdf " W:%" UVuf " L:%" UVuf "/%" UVuf " C:%" UVuf "/%" UVuf ">", (UV)trie->startstate, (IV)trie->statecount-1, (UV)trie->wordcount, (UV)trie->minlen, (UV)trie->maxlen, (UV)TRIE_CHARCOUNT(trie), (UV)trie->uniquecharcount );








        });
        if ( IS_ANYOF_TRIE(op) || trie->bitmap ) {
            sv_catpvs(sv, "[");
            (void) put_charclass_bitmap_innards(sv, ((IS_ANYOF_TRIE(op))
                                                 ? ANYOF_BITMAP(o)
                                                 : TRIE_BITMAP(trie)), NULL, NULL, NULL, FALSE );




            sv_catpvs(sv, "]");
        }
    } else if (k == CURLY) {
        U32 lo = ARG1(o), hi = ARG2(o);
	if (OP(o) == CURLYM || OP(o) == CURLYN || OP(o) == CURLYX)
	    Perl_sv_catpvf(aTHX_ sv, "[%d]", o->flags); 
        Perl_sv_catpvf(aTHX_ sv, "{%u,", (unsigned) lo);
        if (hi == REG_INFTY)
            sv_catpvs(sv, "INFTY");
        else Perl_sv_catpvf(aTHX_ sv, "%u", (unsigned) hi);
        sv_catpvs(sv, "}");
    }
    else if (k == WHILEM && o->flags)			
	Perl_sv_catpvf(aTHX_ sv, "[%d/%d]", o->flags & 0xf, o->flags>>4);
    else if (k == REF || k == OPEN || k == CLOSE || k == GROUPP || OP(o)==ACCEPT)
    {
        AV *name_list= NULL;
        U32 parno= OP(o) == ACCEPT ? (U32)ARG2L(o) : ARG(o);
        Perl_sv_catpvf(aTHX_ sv, "%" UVuf, (UV)parno);        
	if ( RXp_PAREN_NAMES(prog) ) {
            name_list= MUTABLE_AV(progi->data->data[progi->name_list_idx]);
        } else if ( pRExC_state ) {
            name_list= RExC_paren_name_list;
        }
        if (name_list) {
            if ( k != REF || (OP(o) < NREF)) {
                SV **name= av_fetch(name_list, parno, 0 );
	        if (name)
	            Perl_sv_catpvf(aTHX_ sv, " '%" SVf "'", SVfARG(*name));
            }
            else {
                SV *sv_dat= MUTABLE_SV(progi->data->data[ parno ]);
                I32 *nums=(I32*)SvPVX(sv_dat);
                SV **name= av_fetch(name_list, nums[0], 0 );
                I32 n;
                if (name) {
                    for ( n=0; n<SvIVX(sv_dat); n++ ) {
                        Perl_sv_catpvf(aTHX_ sv, "%s%" IVdf, (n ? "," : ""), (IV)nums[n]);
                    }
                    Perl_sv_catpvf(aTHX_ sv, " '%" SVf "'", SVfARG(*name));
                }
            }
        }
        if ( k == REF && reginfo) {
            U32 n = ARG(o);  
            I32 ln = prog->offs[n].start;
            if (prog->lastparen < n || ln == -1 || prog->offs[n].end == -1)
                Perl_sv_catpvf(aTHX_ sv, ": FAIL");
            else if (ln == prog->offs[n].end)
                Perl_sv_catpvf(aTHX_ sv, ": ACCEPT - EMPTY STRING");
            else {
                const char *s = reginfo->strbeg + ln;
                Perl_sv_catpvf(aTHX_ sv, ": ");
                Perl_pv_pretty( aTHX_ sv, s, prog->offs[n].end - prog->offs[n].start, 32, 0, 0, PERL_PV_ESCAPE_UNI_DETECT|PERL_PV_PRETTY_NOCLEAR|PERL_PV_PRETTY_ELLIPSES|PERL_PV_PRETTY_QUOTE );
            }
        }
    } else if (k == GOSUB) {
        AV *name_list= NULL;
        if ( RXp_PAREN_NAMES(prog) ) {
            name_list= MUTABLE_AV(progi->data->data[progi->name_list_idx]);
        } else if ( pRExC_state ) {
            name_list= RExC_paren_name_list;
        }

        
        Perl_sv_catpvf(aTHX_ sv, "%d[%+d:%d]", (int)ARG(o),(int)ARG2L(o), (int)((o + (int)ARG2L(o)) - progi->program) );
        if (name_list) {
            SV **name= av_fetch(name_list, ARG(o), 0 );
            if (name)
                Perl_sv_catpvf(aTHX_ sv, " '%" SVf "'", SVfARG(*name));
        }
    }
    else if (k == LOGICAL)
        
	Perl_sv_catpvf(aTHX_ sv, "[%d]", o->flags);
    else if (k == ANYOF) {
	const U8 flags = (OP(o) == ANYOFH) ? 0 : ANYOF_FLAGS(o);
        bool do_sep = FALSE;    
        
        SV *unresolved                = NULL;

        
        SV *only_utf8_locale_invlist = NULL;

        
        SV *nonbitmap_invlist = NULL;

        
        SV* bitmap_range_not_in_bitmap = NULL;

        const bool inverted = flags & ANYOF_INVERT;

	if (OP(o) == ANYOFL || OP(o) == ANYOFPOSIXL) {
            if (ANYOFL_UTF8_LOCALE_REQD(flags)) {
                sv_catpvs(sv, "{utf8-locale-reqd}");
            }
            if (flags & ANYOFL_FOLD) {
                sv_catpvs(sv, "{i}");
            }
        }

        
        if (ARG(o) != ANYOF_ONLY_HAS_BITMAP) {
            (void) _get_regclass_nonbitmap_data(prog, o, FALSE, &unresolved, &only_utf8_locale_invlist, &nonbitmap_invlist);


            
            _invlist_intersection(nonbitmap_invlist, PL_InBitmap, &bitmap_range_not_in_bitmap);

            
            _invlist_subtract(nonbitmap_invlist, PL_InBitmap, &nonbitmap_invlist);

        }

        
        if (flags & ANYOF_MATCHES_ALL_ABOVE_BITMAP) {
            nonbitmap_invlist = _add_range_to_invlist(nonbitmap_invlist, NUM_ANYOF_CODE_POINTS, UV_MAX);

        }

        
	Perl_sv_catpvf(aTHX_ sv, "[%s", PL_colors[0]);

        if (OP(o) != ANYOFH) {
            
            do_sep = put_charclass_bitmap_innards(sv, ANYOF_BITMAP(o), bitmap_range_not_in_bitmap, only_utf8_locale_invlist, o,   unresolved != NULL);






            SvREFCNT_dec(bitmap_range_not_in_bitmap);

            
            if (unresolved) {
                if (inverted) {
                    if (! do_sep) { 
                        sv_catpvs(sv, "^");
                    }
                    sv_catpvs(sv, "{");
                }
                else if (do_sep) {
                    Perl_sv_catpvf(aTHX_ sv,"%s][%s", PL_colors[1], PL_colors[0]);
                }
                sv_catsv(sv, unresolved);
                if (inverted) {
                    sv_catpvs(sv, "}");
                }
                do_sep = ! inverted;
            }
        }

        
        if (nonbitmap_invlist && _invlist_len(nonbitmap_invlist)) {
            SV* contents;

            
            const STRLEN dump_len = (PL_dump_re_max_len > 256)
                                    ? PL_dump_re_max_len : 256;

            
            if (do_sep) {
                Perl_sv_catpvf(aTHX_ sv,"%s][%s", PL_colors[1], PL_colors[0]);
            }

            
            if (inverted && ! unresolved) {
                _invlist_invert(nonbitmap_invlist);
                _invlist_subtract(nonbitmap_invlist, PL_InBitmap, &nonbitmap_invlist);
            }

            contents = invlist_contents(nonbitmap_invlist, FALSE );


            
            if (SvCUR(contents) <= dump_len) {
                sv_catsv(sv, contents);
            }
            else {
                const char * contents_string = SvPVX(contents);
                STRLEN i = dump_len;

                
                while (i > 0 && contents_string[i] != ' ') {
                    i--;
                }
                if (i == 0) {       
                    i = dump_len;
                }

                sv_catpvn(sv, contents_string, i);
                sv_catpvs(sv, "...");
            }

            SvREFCNT_dec_NN(contents);
            SvREFCNT_dec_NN(nonbitmap_invlist);
        }

        
	Perl_sv_catpvf(aTHX_ sv, "%s]", PL_colors[1]);

        if (OP(o) == ANYOFH && FLAGS(o) != 0) {
            Perl_sv_catpvf(aTHX_ sv, " (First UTF-8 byte=\\x%02x)", FLAGS(o));
        }


        SvREFCNT_dec(unresolved);
    }
    else if (k == ANYOFM) {
        SV * cp_list = get_ANYOFM_contents(o);

	Perl_sv_catpvf(aTHX_ sv, "[%s", PL_colors[0]);
        if (OP(o) == NANYOFM) {
            _invlist_invert(cp_list);
        }

        put_charclass_bitmap_innards(sv, NULL, cp_list, NULL, NULL, TRUE);
	Perl_sv_catpvf(aTHX_ sv, "%s]", PL_colors[1]);

        SvREFCNT_dec(cp_list);
    }
    else if (k == POSIXD || k == NPOSIXD) {
        U8 index = FLAGS(o) * 2;
        if (index < C_ARRAY_LENGTH(anyofs)) {
            if (*anyofs[index] != '[')  {
                sv_catpvs(sv, "[");
            }
            sv_catpv(sv, anyofs[index]);
            if (*anyofs[index] != '[')  {
                sv_catpvs(sv, "]");
            }
        }
        else {
            Perl_sv_catpvf(aTHX_ sv, "[illegal type=%d])", index);
        }
    }
    else if (k == BOUND || k == NBOUND) {
        
        const char * const bounds[] = {
            "",       "{gcb}", "{lb}", "{sb}", "{wb}" };




        assert(FLAGS(o) < C_ARRAY_LENGTH(bounds));
        sv_catpv(sv, bounds[FLAGS(o)]);
    }
    else if (k == BRANCHJ && (OP(o) == UNLESSM || OP(o) == IFMATCH)) {
	Perl_sv_catpvf(aTHX_ sv, "[%d", -(o->flags));
        if (o->next_off) {
            Perl_sv_catpvf(aTHX_ sv, "..-%d", o->flags - o->next_off);
        }
	Perl_sv_catpvf(aTHX_ sv, "]");
    }
    else if (OP(o) == SBOL)
        Perl_sv_catpvf(aTHX_ sv, " /%s/", o->flags ? "\\A" : "^");

    
    if ( ( k == VERB || OP(o) == ACCEPT || OP(o) == OPFAIL ) && o->flags) {
        if ( ARG(o) )
            Perl_sv_catpvf(aTHX_ sv, ":%" SVf, SVfARG((MUTABLE_SV(progi->data->data[ ARG( o ) ]))));
        else sv_catpvs(sv, ":NULL");
    }

    PERL_UNUSED_CONTEXT;
    PERL_UNUSED_ARG(sv);
    PERL_UNUSED_ARG(o);
    PERL_UNUSED_ARG(prog);
    PERL_UNUSED_ARG(reginfo);
    PERL_UNUSED_ARG(pRExC_state);

}



SV * Perl_re_intuit_string(pTHX_ REGEXP * const r)
{				
    struct regexp *const prog = ReANY(r);
    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_RE_INTUIT_STRING;
    PERL_UNUSED_CONTEXT;

    DEBUG_COMPILE_r( {
	    const char * const s = SvPV_nolen_const(RX_UTF8(r)
		      ? prog->check_utf8 : prog->check_substr);

	    if (!PL_colorset) reginitcolors();
            Perl_re_printf( aTHX_ "%sUsing REx %ssubstr:%s \"%s%.60s%s%s\"\n", PL_colors[4], RX_UTF8(r) ? "utf8 " : "", PL_colors[5], PL_colors[0], s, PL_colors[1], (strlen(s) > PL_dump_re_max_len ? "..." : ""));






	} );

    
    return RX_UTF8(r) ? prog->check_utf8 : prog->check_substr;
}



void Perl_pregfree(pTHX_ REGEXP *r)
{
    SvREFCNT_dec(r);
}

void Perl_pregfree2(pTHX_ REGEXP *rx)
{
    struct regexp *const r = ReANY(rx);
    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_PREGFREE2;

    if (! r)
        return;

    if (r->mother_re) {
        ReREFCNT_dec(r->mother_re);
    } else {
        CALLREGFREE_PVT(rx); 
        SvREFCNT_dec(RXp_PAREN_NAMES(r));
    }
    if (r->substrs) {
        int i;
        for (i = 0; i < 2; i++) {
            SvREFCNT_dec(r->substrs->data[i].substr);
            SvREFCNT_dec(r->substrs->data[i].utf8_substr);
        }
	Safefree(r->substrs);
    }
    RX_MATCH_COPY_FREE(rx);

    SvREFCNT_dec(r->saved_copy);

    Safefree(r->offs);
    SvREFCNT_dec(r->qr_anoncv);
    if (r->recurse_locinput)
        Safefree(r->recurse_locinput);
}





REGEXP * Perl_reg_temp_copy(pTHX_ REGEXP *dsv, REGEXP *ssv)
{
    struct regexp *drx;
    struct regexp *const srx = ReANY(ssv);
    const bool islv = dsv && SvTYPE(dsv) == SVt_PVLV;

    PERL_ARGS_ASSERT_REG_TEMP_COPY;

    if (!dsv)
	dsv = (REGEXP*) newSV_type(SVt_REGEXP);
    else {
        assert(SvTYPE(dsv) == SVt_REGEXP || (SvTYPE(dsv) == SVt_PVLV));

        
        assert(!SvOOK(dsv));
        assert(!SvIsCOW(dsv));
        assert(!SvROK(dsv));

        if (SvPVX_const(dsv)) {
            if (SvLEN(dsv))
                Safefree(SvPVX(dsv));
            SvPVX(dsv) = NULL;
        }
        SvLEN_set(dsv, 0);
        SvCUR_set(dsv, 0);
	SvOK_off((SV *)dsv);

	if (islv) {
	    
	    REGEXP *temp = (REGEXP *)newSV_type(SVt_REGEXP);
	    assert(!SvPVX(dsv));
            ((XPV*)SvANY(dsv))->xpv_len_u.xpvlenu_rx = temp->sv_any;
	    temp->sv_any = NULL;
	    SvFLAGS(temp) = (SvFLAGS(temp) & ~SVTYPEMASK) | SVt_NULL;
	    SvREFCNT_dec_NN(temp);
	    
	    SvCUR_set(dsv, SvCUR(ssv));
	}
    }
    
    SvFAKE_on(dsv);
    drx = ReANY(dsv);

    SvFLAGS(dsv) |= SvFLAGS(ssv) & (SVf_POK|SVp_POK|SVf_UTF8);
    SvPV_set(dsv, RX_WRAPPED(ssv));
    
    memcpy(&(drx->xpv_cur), &(srx->xpv_cur), sizeof(regexp) - STRUCT_OFFSET(regexp, xpv_cur));
    if (!islv)
        SvLEN_set(dsv, 0);
    if (srx->offs) {
        const I32 npar = srx->nparens+1;
        Newx(drx->offs, npar, regexp_paren_pair);
        Copy(srx->offs, drx->offs, npar, regexp_paren_pair);
    }
    if (srx->substrs) {
        int i;
        Newx(drx->substrs, 1, struct reg_substr_data);
	StructCopy(srx->substrs, drx->substrs, struct reg_substr_data);

        for (i = 0; i < 2; i++) {
            SvREFCNT_inc_void(drx->substrs->data[i].substr);
            SvREFCNT_inc_void(drx->substrs->data[i].utf8_substr);
        }

	
    }
    RX_MATCH_COPIED_off(dsv);

    drx->saved_copy = NULL;

    drx->mother_re = ReREFCNT_inc(srx->mother_re ? srx->mother_re : ssv);
    SvREFCNT_inc_void(drx->qr_anoncv);
    if (srx->recurse_locinput)
        Newx(drx->recurse_locinput, srx->nparens + 1, char *);

    return dsv;
}





void Perl_regfree_internal(pTHX_ REGEXP * const rx)
{
    struct regexp *const r = ReANY(rx);
    RXi_GET_DECL(r, ri);
    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_REGFREE_INTERNAL;

    if (! ri) {
        return;
    }

    DEBUG_COMPILE_r({
	if (!PL_colorset)
	    reginitcolors();
	{
	    SV *dsv= sv_newmortal();
            RE_PV_QUOTED_DECL(s, RX_UTF8(rx), dsv, RX_PRECOMP(rx), RX_PRELEN(rx), PL_dump_re_max_len);
            Perl_re_printf( aTHX_ "%sFreeing REx:%s %s\n", PL_colors[4], PL_colors[5], s);
        }
    });


    if (ri->u.offsets)
        Safefree(ri->u.offsets);             

    if (ri->code_blocks)
        S_free_codeblocks(aTHX_ ri->code_blocks);

    if (ri->data) {
	int n = ri->data->count;

	while (--n >= 0) {
          
	    switch (ri->data->what[n]) {
	    case 'a':
	    case 'r':
	    case 's':
	    case 'S':
	    case 'u':
		SvREFCNT_dec(MUTABLE_SV(ri->data->data[n]));
		break;
	    case 'f':
		Safefree(ri->data->data[n]);
		break;
	    case 'l':
	    case 'L':
	        break;
            case 'T':
                { 
                    U32 refcount;
                    reg_ac_data *aho=(reg_ac_data*)ri->data->data[n];

                    dVAR;

                    OP_REFCNT_LOCK;
                    refcount = --aho->refcount;
                    OP_REFCNT_UNLOCK;
                    if ( !refcount ) {
                        PerlMemShared_free(aho->states);
                        PerlMemShared_free(aho->fail);
			 
                        PerlMemShared_free(ri->data->data[n]);
                        
                        assert(ri->regstclass);
                        if (ri->regstclass) {
                            PerlMemShared_free(ri->regstclass);
                            ri->regstclass = 0;
                        }
                    }
                }
                break;
	    case 't':
	        {
	            
	            U32 refcount;
	            reg_trie_data *trie=(reg_trie_data*)ri->data->data[n];

                    dVAR;

                    OP_REFCNT_LOCK;
                    refcount = --trie->refcount;
                    OP_REFCNT_UNLOCK;
                    if ( !refcount ) {
                        PerlMemShared_free(trie->charmap);
                        PerlMemShared_free(trie->states);
                        PerlMemShared_free(trie->trans);
                        if (trie->bitmap)
                            PerlMemShared_free(trie->bitmap);
                        if (trie->jump)
                            PerlMemShared_free(trie->jump);
			PerlMemShared_free(trie->wordinfo);
                        
                        PerlMemShared_free(ri->data->data[n]);
		    }
		}
		break;
	    default:
		Perl_croak(aTHX_ "panic: regfree data code '%c'", ri->data->what[n]);
	    }
	}
	Safefree(ri->data->what);
	Safefree(ri->data);
    }

    Safefree(ri);
}








void Perl_re_dup_guts(pTHX_ const REGEXP *sstr, REGEXP *dstr, CLONE_PARAMS *param)
{
    dVAR;
    I32 npar;
    const struct regexp *r = ReANY(sstr);
    struct regexp *ret = ReANY(dstr);

    PERL_ARGS_ASSERT_RE_DUP_GUTS;

    npar = r->nparens+1;
    Newx(ret->offs, npar, regexp_paren_pair);
    Copy(r->offs, ret->offs, npar, regexp_paren_pair);

    if (ret->substrs) {
	
        int i;
	const bool anchored = r->check_substr ? r->check_substr == r->substrs->data[0].substr : r->check_utf8   == r->substrs->data[0].utf8_substr;

        Newx(ret->substrs, 1, struct reg_substr_data);
	StructCopy(r->substrs, ret->substrs, struct reg_substr_data);

        for (i = 0; i < 2; i++) {
            ret->substrs->data[i].substr = sv_dup_inc(ret->substrs->data[i].substr, param);
            ret->substrs->data[i].utf8_substr = sv_dup_inc(ret->substrs->data[i].utf8_substr, param);
        }

	

	if (ret->check_substr) {
	    if (anchored) {
		assert(r->check_utf8 == r->substrs->data[0].utf8_substr);

		ret->check_substr = ret->substrs->data[0].substr;
		ret->check_utf8   = ret->substrs->data[0].utf8_substr;
	    } else {
		assert(r->check_substr == r->substrs->data[1].substr);
		assert(r->check_utf8   == r->substrs->data[1].utf8_substr);

		ret->check_substr = ret->substrs->data[1].substr;
		ret->check_utf8   = ret->substrs->data[1].utf8_substr;
	    }
	} else if (ret->check_utf8) {
	    if (anchored) {
		ret->check_utf8 = ret->substrs->data[0].utf8_substr;
	    } else {
		ret->check_utf8 = ret->substrs->data[1].utf8_substr;
	    }
	}
    }

    RXp_PAREN_NAMES(ret) = hv_dup_inc(RXp_PAREN_NAMES(ret), param);
    ret->qr_anoncv = MUTABLE_CV(sv_dup_inc((const SV *)ret->qr_anoncv, param));
    if (r->recurse_locinput)
        Newx(ret->recurse_locinput, r->nparens + 1, char *);

    if (ret->pprivate)
	RXi_SET(ret, CALLREGDUPE_PVT(dstr, param));

    if (RX_MATCH_COPIED(dstr))
	ret->subbeg  = SAVEPVN(ret->subbeg, ret->sublen);
    else ret->subbeg = NULL;

    ret->saved_copy = NULL;


    
    RX_WRAPPED(dstr) = SAVEPVN(RX_WRAPPED_const(sstr), SvCUR(sstr)+1);
    
    SvLEN_set(dstr, SvCUR(sstr)+1);
    ret->mother_re   = NULL;
}




void * Perl_regdupe_internal(pTHX_ REGEXP * const rx, CLONE_PARAMS *param)
{
    dVAR;
    struct regexp *const r = ReANY(rx);
    regexp_internal *reti;
    int len;
    RXi_GET_DECL(r, ri);

    PERL_ARGS_ASSERT_REGDUPE_INTERNAL;

    len = ProgLen(ri);

    Newxc(reti, sizeof(regexp_internal) + len*sizeof(regnode), char, regexp_internal);
    Copy(ri->program, reti->program, len+1, regnode);


    if (ri->code_blocks) {
	int n;
	Newx(reti->code_blocks, 1, struct reg_code_blocks);
	Newx(reti->code_blocks->cb, ri->code_blocks->count, struct reg_code_block);
	Copy(ri->code_blocks->cb, reti->code_blocks->cb, ri->code_blocks->count, struct reg_code_block);
	for (n = 0; n < ri->code_blocks->count; n++)
	     reti->code_blocks->cb[n].src_regex = (REGEXP*)
		    sv_dup_inc((SV*)(ri->code_blocks->cb[n].src_regex), param);
        reti->code_blocks->count = ri->code_blocks->count;
        reti->code_blocks->refcnt = 1;
    }
    else reti->code_blocks = NULL;

    reti->regstclass = NULL;

    if (ri->data) {
	struct reg_data *d;
        const int count = ri->data->count;
	int i;

	Newxc(d, sizeof(struct reg_data) + count*sizeof(void *), char, struct reg_data);
	Newx(d->what, count, U8);

	d->count = count;
	for (i = 0; i < count; i++) {
	    d->what[i] = ri->data->what[i];
	    switch (d->what[i]) {
	        
            case 'a': 
            case 'r': 
            case 's': 
            case 'S': 
            case 'u': 
		d->data[i] = sv_dup_inc((const SV *)ri->data->data[i], param);
		break;
	    case 'f':
                
		
		Newx(d->data[i], 1, regnode_ssc);
		StructCopy(ri->data->data[i], d->data[i], regnode_ssc);
		reti->regstclass = (regnode*)d->data[i];
		break;
	    case 'T':
                
                
		reti->regstclass= ri->regstclass;
		
	    case 't':
                
		OP_REFCNT_LOCK;
		((reg_trie_data*)ri->data->data[i])->refcount++;
		OP_REFCNT_UNLOCK;
		
            case 'l': 
            case 'L': 
		d->data[i] = ri->data->data[i];
		break;
            default:
                Perl_croak(aTHX_ "panic: re_dup_guts unknown data code '%c'", ri->data->what[i]);
	    }
	}

	reti->data = d;
    }
    else reti->data = NULL;

    reti->name_list_idx = ri->name_list_idx;


    if (ri->u.offsets) {
        Newx(reti->u.offsets, 2*len+1, U32);
        Copy(ri->u.offsets, reti->u.offsets, 2*len+1, U32);
    }

    SetProgLen(reti, len);


    return (void*)reti;
}






regnode * Perl_regnext(pTHX_ regnode *p)
{
    I32 offset;

    if (!p)
	return(NULL);

    if (OP(p) > REGNODE_MAX) {		
	Perl_croak(aTHX_ "Corrupted regexp opcode %d > %d", (int)OP(p), (int)REGNODE_MAX);
    }

    offset = (reg_off_by_arg[OP(p)] ? ARG(p) : NEXT_OFF(p));
    if (offset == 0)
	return(NULL);

    return(p+offset);
}



STATIC void S_re_croak2(pTHX_ bool utf8, const char* pat1, const char* pat2,...)
{
    va_list args;
    STRLEN l1 = strlen(pat1);
    STRLEN l2 = strlen(pat2);
    char buf[512];
    SV *msv;
    const char *message;

    PERL_ARGS_ASSERT_RE_CROAK2;

    if (l1 > 510)
	l1 = 510;
    if (l1 + l2 > 510)
	l2 = 510 - l1;
    Copy(pat1, buf, l1 , char);
    Copy(pat2, buf + l1, l2 , char);
    buf[l1 + l2] = '\n';
    buf[l1 + l2 + 1] = '\0';
    va_start(args, pat2);
    msv = vmess(buf, &args);
    va_end(args);
    message = SvPV_const(msv, l1);
    if (l1 > 512)
	l1 = 512;
    Copy(message, buf, l1 , char);
    
    Perl_croak(aTHX_ "%" UTF8f, UTF8fARG(utf8, l1-1, buf));
}




void Perl_save_re_context(pTHX)
{
    I32 nparens = -1;
    I32 i;

    

    if (PL_curpm) {
	const REGEXP * const rx = PM_GETRE(PL_curpm);
	if (rx)
            nparens = RX_NPARENS(rx);
    }

    
    if (nparens == -1)
        nparens = 3;

    for (i = 1; i <= nparens; i++) {
        char digits[TYPE_CHARS(long)];
        const STRLEN len = my_snprintf(digits, sizeof(digits), "%lu", (long)i);
        GV *const *const gvp = (GV**)hv_fetch(PL_defstash, digits, len, 0);

        if (gvp) {
            GV * const gv = *gvp;
            if (SvTYPE(gv) == SVt_PVGV && GvSV(gv))
                save_scalar(gv);
        }
    }
}




STATIC void S_put_code_point(pTHX_ SV *sv, UV c)
{
    PERL_ARGS_ASSERT_PUT_CODE_POINT;

    if (c > 255) {
        Perl_sv_catpvf(aTHX_ sv, "\\x{%04" UVXf "}", c);
    }
    else if (isPRINT(c)) {
	const char string = (char) c;

        
	if (isBACKSLASHED_PUNCT(c) || c == '{' || c == '}')
	    sv_catpvs(sv, "\\");
	sv_catpvn(sv, &string, 1);
    }
    else if (isMNEMONIC_CNTRL(c)) {
        Perl_sv_catpvf(aTHX_ sv, "%s", cntrl_to_mnemonic((U8) c));
    }
    else {
        Perl_sv_catpvf(aTHX_ sv, "\\x%02X", (U8) c);
    }
}



STATIC void S_put_range(pTHX_ SV *sv, UV start, const UV end, const bool allow_literals)
{
    

    const unsigned int min_range_count = 3;

    assert(start <= end);

    PERL_ARGS_ASSERT_PUT_RANGE;

    while (start <= end) {
        UV this_end;
        const char * format;

        if (end - start < min_range_count) {

            
            for (; start <= end; start++) {
                put_code_point(sv, start);
            }
            break;
        }

        
        if (allow_literals && start <= MAX_PRINT_A) {

            
            if (! isPRINT_A(start)) {
                UV temp_end = start + 1;

                
                UV max = MIN(end, MAX_PRINT_A);

                while (temp_end <= max && ! isPRINT_A(temp_end)) {
                    temp_end++;
                }

                
                if (temp_end > MAX_PRINT_A) {
                    temp_end = end + 1;
                }

                
                put_range(sv, start, temp_end - 1, FALSE);

                
                start = temp_end;

                
                continue;
            }

            
            if (isALPHANUMERIC_A(start)) {
                UV mask = (isDIGIT_A(start))
                           ? _CC_DIGIT : isUPPER_A(start)
                               ? _CC_UPPER : _CC_LOWER;
                UV temp_end = start + 1;

                
                while (temp_end <= end && _generic_isCC_A(temp_end, mask)) {
                    temp_end++;
                }
                temp_end--;

                
                if (temp_end - start < min_range_count) {
                    put_range(sv, start, temp_end, FALSE);
                }
                else {  
                    put_code_point(sv, start);
                    sv_catpvs(sv, "-");
                    put_code_point(sv, temp_end);
                }
                start = temp_end + 1;
                continue;
            }

            
            if (isPUNCT_A(start) || isSPACE_A(start)) {
                while (start <= end && (isPUNCT_A(start)
                                        || isSPACE_A(start)))
                {
                    put_code_point(sv, start);
                    start++;
                }
                continue;
            }
        } 

        
        if (   start <= end && (isMNEMONIC_CNTRL(start) || isMNEMONIC_CNTRL(end)))
        {
            while (isMNEMONIC_CNTRL(start) && start <= end) {
                put_code_point(sv, start);
                start++;
            }

            
            if (start <= end) {

                
                UV temp_end = end;
                while (isMNEMONIC_CNTRL(temp_end)) {
                    temp_end--;
                }

                
                put_range(sv, start, temp_end, FALSE);

                
                start = temp_end + 1;
                while (start <= end) {
                    put_code_point(sv, start);
                    start++;
                }
                break;
            }
        }

        

        this_end = (end < NUM_ANYOF_CODE_POINTS)
                    ? end : NUM_ANYOF_CODE_POINTS - 1;

        format = (this_end < 256)
                 ? "\\x%02" UVXf "-\\x%02" UVXf : "\\x{%04" UVXf "}-\\x{%04" UVXf "}";

        format = "\\x%02" UVXf "-\\x%02" UVXf;

        GCC_DIAG_IGNORE_STMT(-Wformat-nonliteral);
        Perl_sv_catpvf(aTHX_ sv, format, start, this_end);
        GCC_DIAG_RESTORE_STMT;
        break;
    }
}

STATIC void S_put_charclass_bitmap_innards_invlist(pTHX_ SV *sv, SV* invlist)
{
    

    UV start, end;
    bool allow_literals = TRUE;

    PERL_ARGS_ASSERT_PUT_CHARCLASS_BITMAP_INNARDS_INVLIST;

    
    invlist_iterinit(invlist);
    while (invlist_iternext(invlist, &start, &end)) {

        
        if (start > MAX_PRINT_A) {
            break;
        }

        
        if (start < ' ' + 2 && end > MAX_PRINT_A - 2) {
            if (end > MAX_PRINT_A) {
                end = MAX_PRINT_A;
            }
            if (start < ' ') {
                start = ' ';
            }
            if (end - start >= MAX_PRINT_A - ' ' - 2) {
                allow_literals = FALSE;
            }
            break;
        }
    }
    invlist_iterfinish(invlist);

    
    invlist_iterinit(invlist);
    while (invlist_iternext(invlist, &start, &end)) {
        if (start >= NUM_ANYOF_CODE_POINTS) {
            break;
        }
        put_range(sv, start, end, allow_literals);
    }
    invlist_iterfinish(invlist);

    return;
}

STATIC SV* S_put_charclass_bitmap_innards_common(pTHX_ SV* invlist, SV* posixes, SV* only_utf8, SV* not_utf8, SV* only_utf8_locale, const bool invert )







{
    

    dVAR;
    SV * output;

    PERL_ARGS_ASSERT_PUT_CHARCLASS_BITMAP_INNARDS_COMMON;

    if (invert) {
        output = newSVpvs("^");
    }
    else {
        output = newSVpvs("");
    }

    
    put_charclass_bitmap_innards_invlist(output, invlist);

    
    if (posixes) {
        sv_catsv(output, posixes);
    }

    if (only_utf8 && _invlist_len(only_utf8)) {
        Perl_sv_catpvf(aTHX_ output, "%s{utf8}%s", PL_colors[1], PL_colors[0]);
        put_charclass_bitmap_innards_invlist(output, only_utf8);
    }

    if (not_utf8 && _invlist_len(not_utf8)) {
        Perl_sv_catpvf(aTHX_ output, "%s{not utf8}%s", PL_colors[1], PL_colors[0]);
        put_charclass_bitmap_innards_invlist(output, not_utf8);
    }

    if (only_utf8_locale && _invlist_len(only_utf8_locale)) {
        Perl_sv_catpvf(aTHX_ output, "%s{utf8 locale}%s", PL_colors[1], PL_colors[0]);
        put_charclass_bitmap_innards_invlist(output, only_utf8_locale);

        
        if (invlist_highest(only_utf8_locale) >= NUM_ANYOF_CODE_POINTS) {
            UV start, end;
            SV* above_bitmap = NULL;

            _invlist_subtract(only_utf8_locale, PL_InBitmap, &above_bitmap);

            invlist_iterinit(above_bitmap);
            while (invlist_iternext(above_bitmap, &start, &end)) {
                UV i;

                for (i = start; i <= end; i++) {
                    put_code_point(output, i);
                }
            }
            invlist_iterfinish(above_bitmap);
            SvREFCNT_dec_NN(above_bitmap);
        }
    }

    if (invert && SvCUR(output) == 1) {
        return NULL;
    }

    return output;
}

STATIC bool S_put_charclass_bitmap_innards(pTHX_ SV *sv, char *bitmap, SV *nonbitmap_invlist, SV *only_utf8_locale_invlist, const regnode * const node, const bool force_as_is_display)





{
    

    

    dVAR;
    bool inverting_allowed = ! force_as_is_display;

    int i;
    STRLEN orig_sv_cur = SvCUR(sv);

    SV* invlist;            
    SV* only_utf8 = NULL;   
    SV* not_utf8 =  NULL;   
    SV* posixes = NULL;     
    SV* only_utf8_locale = NULL;    

    SV* as_is_display;      
    SV* inverted_display;   

    U8 flags = (node) ? ANYOF_FLAGS(node) : 0;

    bool invert = cBOOL(flags & ANYOF_INVERT);  
    
    const int bias = 5;

    PERL_ARGS_ASSERT_PUT_CHARCLASS_BITMAP_INNARDS;

    
    if (nonbitmap_invlist) {
        assert(invlist_highest(nonbitmap_invlist) < NUM_ANYOF_CODE_POINTS);
        invlist = invlist_clone(nonbitmap_invlist, NULL);
    }
    else {  
        invlist = _new_invlist(NUM_ANYOF_CODE_POINTS / 2);
    }

    if (flags) {
        if (OP(node) == ANYOFD) {

            
            if (flags & ANYOF_SHARED_d_UPPER_LATIN1_UTF8_STRING_MATCHES_non_d_RUNTIME_USER_PROP)
            {
                _invlist_intersection(invlist, PL_UpperLatin1, &only_utf8);
                _invlist_subtract(invlist, only_utf8, &invlist);
            }

            
            if (flags & ANYOF_SHARED_d_MATCHES_ALL_NON_UTF8_NON_ASCII_non_d_WARN_SUPER)
            {
                not_utf8 = invlist_clone(PL_UpperLatin1, NULL);
            }
        }
        else if (OP(node) == ANYOFL || OP(node) == ANYOFPOSIXL) {

            
            if (flags & (ANYOFL_FOLD|ANYOF_MATCHES_POSIXL)) {
                inverting_allowed = FALSE;
            }

            
            if (ANYOF_POSIXL_TEST_ANY_SET(node)) {
                int i;

                posixes = newSVpvs("");
                for (i = 0; i < ANYOF_POSIXL_MAX; i++) {
                    if (ANYOF_POSIXL_TEST(node, i)) {
                        sv_catpv(posixes, anyofs[i]);
                    }
                }
            }
        }
    }

    
    if (bitmap) {
        for (i = 0; i < NUM_ANYOF_CODE_POINTS; i++) {
            if (BITMAP_TEST(bitmap, i)) {
                int start = i++;
                for (;
                     i < NUM_ANYOF_CODE_POINTS && BITMAP_TEST(bitmap, i);
                     i++)
                {  }
                invlist = _add_range_to_invlist(invlist, start, i-1);
            }
        }
    }

    
    if (only_utf8) {
        _invlist_subtract(only_utf8, invlist, &only_utf8);
    }
    if (not_utf8) {
        _invlist_subtract(not_utf8, invlist, &not_utf8);
    }

    if (only_utf8_locale_invlist) {

        
        only_utf8_locale = invlist_clone(only_utf8_locale_invlist, NULL);

        _invlist_subtract(only_utf8_locale, invlist, &only_utf8_locale);

        
        if (invlist_highest(only_utf8_locale) >= NUM_ANYOF_CODE_POINTS) {
            inverting_allowed = FALSE;
        }
    }

    
    as_is_display = put_charclass_bitmap_innards_common(invlist, posixes, only_utf8, not_utf8, only_utf8_locale, invert);





    
    if (! inverting_allowed) {
        if (as_is_display) {
            sv_catsv(sv, as_is_display);
            SvREFCNT_dec_NN(as_is_display);
        }
    }
    else { 

        int inverted_bias, as_is_bias;

        
        if (invert) {
            invert = FALSE;
            as_is_bias = bias;
            inverted_bias = 0;
        }
        else {
            invert = TRUE;
            as_is_bias = 0;
            inverted_bias = bias;
        }

        

        
        _invlist_union(only_utf8, invlist, &invlist);
        _invlist_union(not_utf8, invlist, &invlist);
        _invlist_union(only_utf8_locale, invlist, &invlist);
        _invlist_invert(invlist);
        _invlist_intersection(invlist, PL_InBitmap, &invlist);

        if (only_utf8) {
            _invlist_invert(only_utf8);
            _invlist_intersection(only_utf8, PL_UpperLatin1, &only_utf8);
        }
        else if (not_utf8) {

            
            only_utf8 = not_utf8;
            not_utf8 = NULL;
        }

        if (only_utf8_locale) {
            _invlist_invert(only_utf8_locale);
            _invlist_intersection(only_utf8_locale, PL_InBitmap, &only_utf8_locale);

        }

        inverted_display = put_charclass_bitmap_innards_common( invlist, posixes, only_utf8, not_utf8, only_utf8_locale, invert);





        
        if (   inverted_display && (   ! as_is_display || (  SvCUR(inverted_display) + inverted_bias < SvCUR(as_is_display)    + as_is_bias)))


        {
	    sv_catsv(sv, inverted_display);
        }
        else if (as_is_display) {
	    sv_catsv(sv, as_is_display);
        }

        SvREFCNT_dec(as_is_display);
        SvREFCNT_dec(inverted_display);
    }

    SvREFCNT_dec_NN(invlist);
    SvREFCNT_dec(only_utf8);
    SvREFCNT_dec(not_utf8);
    SvREFCNT_dec(posixes);
    SvREFCNT_dec(only_utf8_locale);

    return SvCUR(sv) > orig_sv_cur;
}










STATIC const regnode * S_dumpuntil(pTHX_ const regexp *r, const regnode *start, const regnode *node, const regnode *last, const regnode *plast, SV* sv, I32 indent, U32 depth)


{
    U8 op = PSEUDO;	
    const regnode *next;
    const regnode *optstart= NULL;

    RXi_GET_DECL(r, ri);
    GET_RE_DEBUG_FLAGS_DECL;

    PERL_ARGS_ASSERT_DUMPUNTIL;


    Perl_re_printf( aTHX_  "--- %d : %d - %d - %d\n", indent, node-start, last ? last-start : 0, plast ? plast-start : 0);


    if (plast && plast < last)
        last= plast;

    while (PL_regkind[op] != END && (!last || node < last)) {
        assert(node);
	
	NODE_ALIGN(node);
	op = OP(node);
	if (op == CLOSE || op == SRCLOSE || op == WHILEM)
	    indent--;
	next = regnext((regnode *)node);

	
	if (OP(node) == OPTIMIZED) {
	    if (!optstart && RE_DEBUG_FLAG(RE_DEBUG_COMPILE_OPTIMISE))
	        optstart = node;
	    else goto after_print;
	} else CLEAR_OPTSTART;

        regprop(r, sv, node, NULL, NULL);
        Perl_re_printf( aTHX_  "%4" IVdf ":%*s%s", (IV)(node - start), (int)(2*indent + 1), "", SvPVX_const(sv));

        if (OP(node) != OPTIMIZED) {
            if (next == NULL)		
                Perl_re_printf( aTHX_  " (0)");
            else if (PL_regkind[(U8)op] == BRANCH && PL_regkind[OP(next)] != BRANCH )
                Perl_re_printf( aTHX_  " (FAIL)");
            else Perl_re_printf( aTHX_  " (%" IVdf ")", (IV)(next - start));
            Perl_re_printf( aTHX_ "\n");
        }

      after_print:
	if (PL_regkind[(U8)op] == BRANCHJ) {
	    assert(next);
	    {
                const regnode *nnode = (OP(next) == LONGJMP ? regnext((regnode *)next)
                                       : next);
                if (last && nnode > last)
                    nnode = last;
                DUMPUNTIL(NEXTOPER(NEXTOPER(node)), nnode);
	    }
	}
	else if (PL_regkind[(U8)op] == BRANCH) {
	    assert(next);
	    DUMPUNTIL(NEXTOPER(node), next);
	}
	else if ( PL_regkind[(U8)op]  == TRIE ) {
	    const regnode *this_trie = node;
	    const char op = OP(node);
            const U32 n = ARG(node);
	    const reg_ac_data * const ac = op>=AHOCORASICK ? (reg_ac_data *)ri->data->data[n] :
               NULL;
	    const reg_trie_data * const trie = (reg_trie_data*)ri->data->data[op<AHOCORASICK ? n : ac->trie];

	    AV *const trie_words = MUTABLE_AV(ri->data->data[n + TRIE_WORDS_OFFSET]);

	    const regnode *nextbranch= NULL;
	    I32 word_idx;
            SvPVCLEAR(sv);
	    for (word_idx= 0; word_idx < (I32)trie->wordcount; word_idx++) {
		SV ** const elem_ptr = av_fetch(trie_words, word_idx, 0);

                Perl_re_indentf( aTHX_  "%s ", indent+3, elem_ptr ? pv_pretty(sv, SvPV_nolen_const(*elem_ptr), SvCUR(*elem_ptr), PL_dump_re_max_len, PL_colors[0], PL_colors[1], (SvUTF8(*elem_ptr)





                                 ? PERL_PV_ESCAPE_UNI : 0)
                                | PERL_PV_PRETTY_ELLIPSES | PERL_PV_PRETTY_LTGT )

                    : "???" );
                if (trie->jump) {
                    U16 dist= trie->jump[word_idx+1];
                    Perl_re_printf( aTHX_  "(%" UVuf ")\n", (UV)((dist ? this_trie + dist : next) - start));
                    if (dist) {
                        if (!nextbranch)
                            nextbranch= this_trie + trie->jump[0];
			DUMPUNTIL(this_trie + dist, nextbranch);
                    }
                    if (nextbranch && PL_regkind[OP(nextbranch)]==BRANCH)
                        nextbranch= regnext((regnode *)nextbranch);
                } else {
                    Perl_re_printf( aTHX_  "\n");
		}
	    }
	    if (last && next > last)
	        node= last;
	    else node= next;
	}
	else if ( op == CURLY ) {   
	    DUMPUNTIL(NEXTOPER(node) + EXTRA_STEP_2ARGS, NEXTOPER(node) + EXTRA_STEP_2ARGS + 1);
	}
	else if (PL_regkind[(U8)op] == CURLY && op != CURLYX) {
	    assert(next);
	    DUMPUNTIL(NEXTOPER(node) + EXTRA_STEP_2ARGS, next);
	}
	else if ( op == PLUS || op == STAR) {
	    DUMPUNTIL(NEXTOPER(node), NEXTOPER(node) + 1);
	}
	else if (PL_regkind[(U8)op] == EXACT) {
            
	    node += NODE_SZ_STR(node) - 1;
	    node = NEXTOPER(node);
	}
	else {
	    node = NEXTOPER(node);
	    node += regarglen[(U8)op];
	}
	if (op == CURLYX || op == OPEN || op == SROPEN)
	    indent++;
    }
    CLEAR_OPTSTART;

    Perl_re_printf( aTHX_  "--- %d\n", (int)indent);

    return node;
}







void Perl_init_uniprops(pTHX)
{
    dVAR;

    PL_user_def_props = newHV();



    HvSHAREKEYS_off(PL_user_def_props);
    PL_user_def_props_aTHX = aTHX;



    

    PL_XPosix_ptrs[_CC_ASCII] = _new_invlist_C_array(uni_prop_ptrs[UNI_ASCII]);
    PL_XPosix_ptrs[_CC_ALPHANUMERIC] = _new_invlist_C_array(uni_prop_ptrs[UNI_XPOSIXALNUM]);
    PL_XPosix_ptrs[_CC_ALPHA] = _new_invlist_C_array(uni_prop_ptrs[UNI_XPOSIXALPHA]);
    PL_XPosix_ptrs[_CC_BLANK] = _new_invlist_C_array(uni_prop_ptrs[UNI_XPOSIXBLANK]);
    PL_XPosix_ptrs[_CC_CASED] =  _new_invlist_C_array(uni_prop_ptrs[UNI_CASED]);
    PL_XPosix_ptrs[_CC_CNTRL] = _new_invlist_C_array(uni_prop_ptrs[UNI_XPOSIXCNTRL]);
    PL_XPosix_ptrs[_CC_DIGIT] = _new_invlist_C_array(uni_prop_ptrs[UNI_XPOSIXDIGIT]);
    PL_XPosix_ptrs[_CC_GRAPH] = _new_invlist_C_array(uni_prop_ptrs[UNI_XPOSIXGRAPH]);
    PL_XPosix_ptrs[_CC_LOWER] = _new_invlist_C_array(uni_prop_ptrs[UNI_XPOSIXLOWER]);
    PL_XPosix_ptrs[_CC_PRINT] = _new_invlist_C_array(uni_prop_ptrs[UNI_XPOSIXPRINT]);
    PL_XPosix_ptrs[_CC_PUNCT] = _new_invlist_C_array(uni_prop_ptrs[UNI_XPOSIXPUNCT]);
    PL_XPosix_ptrs[_CC_SPACE] = _new_invlist_C_array(uni_prop_ptrs[UNI_XPOSIXSPACE]);
    PL_XPosix_ptrs[_CC_UPPER] = _new_invlist_C_array(uni_prop_ptrs[UNI_XPOSIXUPPER]);
    PL_XPosix_ptrs[_CC_VERTSPACE] = _new_invlist_C_array(uni_prop_ptrs[UNI_VERTSPACE]);
    PL_XPosix_ptrs[_CC_WORDCHAR] = _new_invlist_C_array(uni_prop_ptrs[UNI_XPOSIXWORD]);
    PL_XPosix_ptrs[_CC_XDIGIT] = _new_invlist_C_array(uni_prop_ptrs[UNI_XPOSIXXDIGIT]);

    PL_Posix_ptrs[_CC_ASCII] = _new_invlist_C_array(uni_prop_ptrs[UNI_ASCII]);
    PL_Posix_ptrs[_CC_ALPHANUMERIC] = _new_invlist_C_array(uni_prop_ptrs[UNI_POSIXALNUM]);
    PL_Posix_ptrs[_CC_ALPHA] = _new_invlist_C_array(uni_prop_ptrs[UNI_POSIXALPHA]);
    PL_Posix_ptrs[_CC_BLANK] = _new_invlist_C_array(uni_prop_ptrs[UNI_POSIXBLANK]);
    PL_Posix_ptrs[_CC_CASED] = PL_Posix_ptrs[_CC_ALPHA];
    PL_Posix_ptrs[_CC_CNTRL] = _new_invlist_C_array(uni_prop_ptrs[UNI_POSIXCNTRL]);
    PL_Posix_ptrs[_CC_DIGIT] = _new_invlist_C_array(uni_prop_ptrs[UNI_POSIXDIGIT]);
    PL_Posix_ptrs[_CC_GRAPH] = _new_invlist_C_array(uni_prop_ptrs[UNI_POSIXGRAPH]);
    PL_Posix_ptrs[_CC_LOWER] = _new_invlist_C_array(uni_prop_ptrs[UNI_POSIXLOWER]);
    PL_Posix_ptrs[_CC_PRINT] = _new_invlist_C_array(uni_prop_ptrs[UNI_POSIXPRINT]);
    PL_Posix_ptrs[_CC_PUNCT] = _new_invlist_C_array(uni_prop_ptrs[UNI_POSIXPUNCT]);
    PL_Posix_ptrs[_CC_SPACE] = _new_invlist_C_array(uni_prop_ptrs[UNI_POSIXSPACE]);
    PL_Posix_ptrs[_CC_UPPER] = _new_invlist_C_array(uni_prop_ptrs[UNI_POSIXUPPER]);
    PL_Posix_ptrs[_CC_VERTSPACE] = NULL;
    PL_Posix_ptrs[_CC_WORDCHAR] = _new_invlist_C_array(uni_prop_ptrs[UNI_POSIXWORD]);
    PL_Posix_ptrs[_CC_XDIGIT] = _new_invlist_C_array(uni_prop_ptrs[UNI_POSIXXDIGIT]);

    PL_GCB_invlist = _new_invlist_C_array(_Perl_GCB_invlist);
    PL_SB_invlist = _new_invlist_C_array(_Perl_SB_invlist);
    PL_WB_invlist = _new_invlist_C_array(_Perl_WB_invlist);
    PL_LB_invlist = _new_invlist_C_array(_Perl_LB_invlist);
    PL_SCX_invlist = _new_invlist_C_array(_Perl_SCX_invlist);

    PL_AboveLatin1 = _new_invlist_C_array(AboveLatin1_invlist);
    PL_Latin1 = _new_invlist_C_array(Latin1_invlist);
    PL_UpperLatin1 = _new_invlist_C_array(UpperLatin1_invlist);

    PL_Assigned_invlist = _new_invlist_C_array(uni_prop_ptrs[UNI_ASSIGNED]);

    PL_utf8_perl_idstart = _new_invlist_C_array(uni_prop_ptrs[UNI__PERL_IDSTART]);
    PL_utf8_perl_idcont = _new_invlist_C_array(uni_prop_ptrs[UNI__PERL_IDCONT]);

    PL_utf8_charname_begin = _new_invlist_C_array(uni_prop_ptrs[UNI__PERL_CHARNAME_BEGIN]);
    PL_utf8_charname_continue = _new_invlist_C_array(uni_prop_ptrs[UNI__PERL_CHARNAME_CONTINUE]);

    PL_in_some_fold = _new_invlist_C_array(uni_prop_ptrs[UNI__PERL_ANY_FOLDS]);
    PL_HasMultiCharFold = _new_invlist_C_array(uni_prop_ptrs[ UNI__PERL_FOLDS_TO_MULTI_CHAR]);
    PL_InMultiCharFold = _new_invlist_C_array(uni_prop_ptrs[ UNI__PERL_IS_IN_MULTI_CHAR_FOLD]);
    PL_NonFinalFold = _new_invlist_C_array(uni_prop_ptrs[ UNI__PERL_NON_FINAL_FOLDS]);

    PL_utf8_toupper = _new_invlist_C_array(Uppercase_Mapping_invlist);
    PL_utf8_tolower = _new_invlist_C_array(Lowercase_Mapping_invlist);
    PL_utf8_totitle = _new_invlist_C_array(Titlecase_Mapping_invlist);
    PL_utf8_tofold = _new_invlist_C_array(Case_Folding_invlist);
    PL_utf8_tosimplefold = _new_invlist_C_array(Simple_Case_Folding_invlist);
    PL_utf8_foldclosures = _new_invlist_C_array(_Perl_IVCF_invlist);
    PL_utf8_mark = _new_invlist_C_array(uni_prop_ptrs[UNI_M]);
    PL_CCC_non0_non230 = _new_invlist_C_array(_Perl_CCC_non0_non230_invlist);
    PL_Private_Use = _new_invlist_C_array(uni_prop_ptrs[UNI_CO]);


    
    PL_utf8_xidcont  = _new_invlist_C_array(uni_prop_ptrs[UNI_XIDC]);
    PL_utf8_idcont   = _new_invlist_C_array(uni_prop_ptrs[UNI_IDC]);
    PL_utf8_xidstart = _new_invlist_C_array(uni_prop_ptrs[UNI_XIDS]);

}



This code was mainly added for backcompat to give a warning for non-portable code points in user-defined properties.  But experiments showed that the warning in earlier perls were only omitted on overflow, which should be an error, so there really isnt a backcompat issue, and actually adding the warning when none was present before might cause breakage, for little gain.  So khw left this code in, but not enabled.  Tests were never added.  embed.fnc entry:






Ei	|const char *|get_extended_utf8_msg|const UV cp  PERL_STATIC_INLINE const char * S_get_extended_utf8_msg(pTHX_ const UV cp)


{
    U8 dummy[UTF8_MAXBYTES + 1];
    HV *msgs;
    SV **msg;

    uvchr_to_utf8_flags_msgs(dummy, cp, UNICODE_WARN_PERL_EXTENDED, &msgs);

    msg = hv_fetchs(msgs, "text", 0);
    assert(msg);

    (void) sv_2mortal((SV *) msgs);

    return SvPVX(*msg);
}



SV * Perl_handle_user_defined_property(pTHX_    const char * name, const STRLEN name_len, const bool is_utf8, const bool to_fold, const bool runtime, const bool deferrable, SV* contents, bool *user_defined_ptr, SV * msg, const STRLEN level)













{
    STRLEN len;
    const char * string         = SvPV_const(contents, len);
    const char * const e        = string + len;
    const bool is_contents_utf8 = cBOOL(SvUTF8(contents));
    const STRLEN msgs_length_on_entry = SvCUR(msg);

    const char * s0 = string;   
    const char overflow_msg[] = "Code point too large in \"";
    SV* running_definition = NULL;

    PERL_ARGS_ASSERT_HANDLE_USER_DEFINED_PROPERTY;

    *user_defined_ptr = TRUE;

    
    while (s0 < e) {
        const char * s;     
        char op = '+';      
        IV   min = 0;       
        IV   max = -1;      
        SV* this_definition;

        
        if (*s0 == '#') {
            s0 = strchr(s0, '\n');
            if (s0 == NULL) {
                break;
            }
            s0++;
            continue;
        }

        
        if (*s0 == '\n') {
            s0++;
            continue;
        }

        
        if (   *s0 == '+' || *s0 == '!' || *s0 == '-' || *s0 == '&')


        {
            op = *s0++;
        }

        

        s = s0;

        if (! isXDIGIT(*s)) {
            goto check_if_property;
        }

        do { 
            if (min > ( (IV) MAX_LEGAL_CP >> 4)) {
                s = strchr(s, '\n');
                if (s == NULL) {
                    s = e;
                }
                if (SvCUR(msg) > 0) sv_catpvs(msg, "; ");
                sv_catpv(msg, overflow_msg);
                Perl_sv_catpvf(aTHX_ msg, "%" UTF8f, UTF8fARG(is_contents_utf8, s - s0, s0));
                sv_catpvs(msg, "\"");
                goto return_failure;
            }

            
            min = (min << 4) + READ_XDIGIT(s);
        } while (isXDIGIT(*s));

        while (isBLANK(*s)) { s++; }

        
        if (*s == '#') {
            s = strchr(s, '\n');
            if (s == NULL) {
                s = e;
            }
            s++;
        }
        else if (s < e && *s != '\n') {
            if (! isXDIGIT(*s)) {
                goto check_if_property;
            }

            
            max = 0;
            do {
                if (max > ( (IV) MAX_LEGAL_CP >> 4)) {
                    s = strchr(s, '\n');
                    if (s == NULL) {
                        s = e;
                    }
                    if (SvCUR(msg) > 0) sv_catpvs(msg, "; ");
                    sv_catpv(msg, overflow_msg);
                    Perl_sv_catpvf(aTHX_ msg, "%" UTF8f, UTF8fARG(is_contents_utf8, s - s0, s0));
                    sv_catpvs(msg, "\"");
                    goto return_failure;
                }

                max = (max << 4) + READ_XDIGIT(s);
            } while (isXDIGIT(*s));

            while (isBLANK(*s)) { s++; }

            if (*s == '#') {
                s = strchr(s, '\n');
                if (s == NULL) {
                    s = e;
                }
            }
            else if (s < e && *s != '\n') {
                goto check_if_property;
            }
        }

        if (max == -1) {    
            max = min;
        }
        else if (max < min) {
            if (SvCUR(msg) > 0) sv_catpvs(msg, "; ");
            sv_catpvs(msg, "Illegal range in \"");
            Perl_sv_catpvf(aTHX_ msg, "%" UTF8f, UTF8fARG(is_contents_utf8, s - s0, s0));
            sv_catpvs(msg, "\"");
            goto return_failure;
        }



        if (   UNICODE_IS_PERL_EXTENDED(min)
            || UNICODE_IS_PERL_EXTENDED(max))
        {
            if (SvCUR(msg) > 0) sv_catpvs(msg, "; ");

            
            sv_catpv(msg, get_extended_utf8_msg( (UNICODE_IS_PERL_EXTENDED(min))
                                            ? min : max));
            sv_catpvs(msg, " in \"");
            Perl_sv_catpvf(aTHX_ msg, "%" UTF8f, UTF8fARG(is_contents_utf8, s - s0, s0));
            sv_catpvs(msg, "\"");
        }



        
        this_definition = sv_2mortal(_new_invlist(2));
        this_definition = _add_range_to_invlist(this_definition, min, max);
        goto calculate;

      check_if_property:

        
        s = strpbrk(s, "#\n");
        if (s == NULL) {
            s = e;
        }

        
        s--;
        while (s > s0 && isBLANK_A(*s)) {
            s--;
        }
        s++;

        this_definition = parse_uniprop_string(s0, s - s0, is_utf8, to_fold, runtime, deferrable, user_defined_ptr, msg, (name_len == 0)



                                                ? level  : level + 1 );

        if (this_definition == NULL) {
            goto return_failure;    
        }

        if (! is_invlist(this_definition)) {    
            return newSVsv(this_definition);
        }

        if (*s != '\n') {
            s = strchr(s, '\n');
            if (s == NULL) {
                s = e;
            }
        }

      calculate:

        switch (op) {
            case '+':
                _invlist_union(running_definition, this_definition, &running_definition);
                break;
            case '-':
                _invlist_subtract(running_definition, this_definition, &running_definition);
                break;
            case '&':
                _invlist_intersection(running_definition, this_definition, &running_definition);
                break;
            case '!':
                _invlist_union_complement_2nd(running_definition, this_definition, &running_definition);
                break;
            default:
                Perl_croak(aTHX_ "panic: %s: %d: Unexpected operation %d", __FILE__, __LINE__, op);
                break;
        }

        
        s0 = s + 1;
    }   

    
    if (msgs_length_on_entry == SvCUR(msg)) {

        
        if (running_definition == NULL) {
            running_definition = _new_invlist(1);
        }

        return running_definition;
    }

    
    goto return_msg;

  return_failure:
    running_definition = NULL;

  return_msg:

    if (name_len > 0) {
        sv_catpvs(msg, " in expansion of ");
        Perl_sv_catpvf(aTHX_ msg, "%" UTF8f, UTF8fARG(is_utf8, name_len, name));
    }

    return running_definition;
}
















STATIC void S_delete_recursion_entry(pTHX_ void *key)
{
    

    dVAR;
    SV ** current_entry;
    const STRLEN key_len = strlen((const char *) key);
    DECLARATION_FOR_GLOBAL_CONTEXT;

    SWITCH_TO_GLOBAL_CONTEXT;

    
    current_entry = hv_fetch(PL_user_def_props, (const char *) key, key_len, 0);
    if (     current_entry && ! is_invlist(*current_entry)
        && ! SvPOK(*current_entry))
    {
        (void) hv_delete(PL_user_def_props, (const char *) key, key_len, G_DISCARD);
    }

    RESTORE_CONTEXT;
}

STATIC SV * S_get_fq_name(pTHX_ const char * const name, const Size_t name_len, const bool is_utf8, const bool has_colon_colon )





{
    

    SV * fq_name;

    fq_name = newSVpvs_flags("", SVs_TEMP);

    
    if (! has_colon_colon) {
        const HV * pkg = (IN_PERL_COMPILETIME)
                         ? PL_curstash : CopSTASH(PL_curcop);
        const char* pkgname = HvNAME(pkg);

        Perl_sv_catpvf(aTHX_ fq_name, "%" UTF8f, UTF8fARG(is_utf8, strlen(pkgname), pkgname));
        sv_catpvs(fq_name, "::");
    }

    Perl_sv_catpvf(aTHX_ fq_name, "%" UTF8f, UTF8fARG(is_utf8, name_len, name));
    return fq_name;
}

SV * Perl_parse_uniprop_string(pTHX_    const char * const name, const Size_t name_len, const bool is_utf8, const bool to_fold, const bool runtime, const bool deferrable, bool *user_defined_ptr, SV * msg, const STRLEN level)












{
    dVAR;
    char* lookup_name;          
    unsigned lookup_len;        
    bool stricter = FALSE;      

    
    bool is_nv_type = FALSE;

    unsigned int i, j = 0;
    int equals_pos = -1;    
    int slash_pos  = -1;    
    int table_index = 0;    
    bool starts_with_In_or_Is = FALSE;  
    Size_t lookup_offset = 0;   
    Size_t non_pkg_begin = 0;   
    bool could_be_user_defined = TRUE;  
    SV * prop_definition = NULL;  
    SV * fq_name = NULL;        
    bool invert_return = FALSE; 

    PERL_ARGS_ASSERT_PARSE_UNIPROP_STRING;

    
    Newx(lookup_name, name_len, char);
    SAVEFREEPV(lookup_name);

    
    for (i = 0; i < name_len; i++) {
        char cur = name[i];

        
        if (isIDCONT_A(cur)) {

            
            if (isUPPER_A(cur)) {
                lookup_name[j++] = toLOWER_A(cur);
                continue;
            }

            if (cur == '_') { 
                continue;
            }

            lookup_name[j++] = cur;

            
            if (i - non_pkg_begin == 0 && ! isIDFIRST_A(cur)) {
                could_be_user_defined = FALSE;
            }

            continue;
        }

        
        if (cur == '-' || isSPACE_A(cur)) {
            could_be_user_defined = FALSE;
            continue;
        }

        
        if (    cur == '=' || (cur == ':' && (i >= name_len - 1 || name[i+1] != ':')))
        {
            lookup_name[j++] = '='; 
            equals_pos = j; 
            could_be_user_defined = FALSE;
            break;
        }

        
        lookup_name[j++] = cur;

        
        if (cur == ':') {

            

            i++;
            non_pkg_begin = i + 1;
            lookup_name[j++] = ':';
        }
        else { 
            could_be_user_defined = FALSE;
        }
    } 



    
    if (non_pkg_begin == STRLENs("utf8::") && memBEGINPs(name, name_len, "utf8::")) {
        lookup_name +=  STRLENs("utf8::");
        j -=  STRLENs("utf8::");
        equals_pos -=  STRLENs("utf8::");
    }

    

    if (equals_pos >= 0) {
        assert(! stricter); 

        
        i++;
        for (; i < name_len; i++) {
            if (! isSPACE_A(name[i])) {
                break;
            }
        }

        
        if (   isPUNCT_A(name[i])
            && name[i] != '-' && name[i] != '+' && name[i] != '_' && name[i] != '{')


        {
            
            table_index = match_uniprop((U8 *) lookup_name, j);
            if (table_index) {
                const char * const * prop_values = UNI_prop_value_ptrs[table_index];
                SV * subpattern;
                Size_t subpattern_len;
                REGEXP * subpattern_re;
                char open = name[i++];
                char close;
                const char * pos_in_brackets;
                bool escaped = 0;

                
                if (open == '\\') {
                    open = name[i++];
                    escaped = 1;
                }

                
                pos_in_brackets = strchr("([<)]>)]>", open);
                close = (pos_in_brackets) ? pos_in_brackets[3] : open;

                if (    i >= name_len ||  name[name_len-1] != close || (escaped && name[name_len-2] != '\\'))

                {
                    sv_catpvs(msg, "Unicode property wildcard not terminated");
                    goto append_name_to_msg;
                }

                Perl_ck_warner_d(aTHX_ packWARN(WARN_EXPERIMENTAL__UNIPROP_WILDCARDS), "The Unicode property wildcards feature is experimental");


                
                subpattern_len = name_len - i - 1 - escaped;
                subpattern = Perl_newSVpvf(aTHX_ "(?iaa:%.*s)", (unsigned) subpattern_len, name + i);

                subpattern = sv_2mortal(subpattern);
                subpattern_re = re_compile(subpattern, 0);
                assert(subpattern_re);  

                
                while (*prop_values) {
                    const char * const entry = *prop_values;
                    const Size_t len = strlen(entry);
                    SV* entry_sv = newSVpvn_flags(entry, len, SVs_TEMP);

                    if (pregexec(subpattern_re, (char *) entry, (char *) entry + len, (char *) entry, 0, entry_sv, 0))




                    { 
                        Size_t total_len = j + len;
                        SV * sub_invlist = NULL;
                        char * this_string;

                        
                        Newxz(this_string, total_len + 1, char);
                        Copy(lookup_name, this_string, j, char);
                        my_strlcat(this_string, entry, total_len + 1);
                        SAVEFREEPV(this_string);
                        sub_invlist = parse_uniprop_string(this_string, total_len, is_utf8, to_fold, runtime, deferrable, user_defined_ptr, msg, level + 1);







                        _invlist_union(prop_definition, sub_invlist, &prop_definition);
                    }

                    prop_values++;  
                } 

                SvREFCNT_dec_NN(subpattern_re);

                if (prop_definition) {
                    return prop_definition;
                }

                sv_catpvs(msg, "No Unicode property value wildcard matches:");
                goto append_name_to_msg;
            }

            
        } 


        
        if (memBEGINPs(lookup_name, j, "is")) {
            lookup_offset = 2;
        }

        
        is_nv_type = memEQs(lookup_name + lookup_offset, j - 1 - lookup_offset, "numericvalue")
                  || memEQs(lookup_name + lookup_offset, j - 1 - lookup_offset, "nv")
                  || (   memENDPs(lookup_name + lookup_offset, j - 1 - lookup_offset, "numeric")
                      && (   memBEGINPs(lookup_name + lookup_offset, j - 1 - lookup_offset, "cjk")
                          || memBEGINPs(lookup_name + lookup_offset, j - 1 - lookup_offset, "k")));
        if (   is_nv_type || memEQs(lookup_name + lookup_offset, j - 1 - lookup_offset, "canonicalcombiningclass")

            || memEQs(lookup_name + lookup_offset, j - 1 - lookup_offset, "ccc")
            || memEQs(lookup_name + lookup_offset, j - 1 - lookup_offset, "age")
            || memEQs(lookup_name + lookup_offset, j - 1 - lookup_offset, "in")
            || memEQs(lookup_name + lookup_offset, j - 1 - lookup_offset, "presentin"))
        {
            unsigned int k;

            
            stricter = TRUE;
            for (k = i; k < name_len; k++) {
                if (   isALPHA_A(name[k])
                    && (! is_nv_type || ! isALPHA_FOLD_EQ(name[k], 'E')))
                {
                    stricter = FALSE;
                    break;
                }
            }
        }

        if (stricter) {

            
            if (name[i] == '+') {
                i++;
            }
            else if (name[i] == '-') {
                lookup_name[j++] = '-';
                i++;
            }

            
            for (; i < name_len - 1; i++) {
                if (    name[i] != '0' && (name[i] != '_' || ! isDIGIT_A(name[i+1])))
                {
                    break;
                }
            }
        }
    }
    else {  

       
        if (   memBEGINPs(lookup_name, j, "perl")
            && memNEs(lookup_name + 4, j - 4, "space")
            && memNEs(lookup_name + 4, j - 4, "word"))
        {
            stricter = TRUE;

            
            i = j = 0;
        }
    }

    
    for (; i < name_len; i++) {
        char cur = name[i];

        
        if (isUPPER_A(cur)) {
            lookup_name[j++] = toLOWER(cur);
            continue;
        }

        
        if (cur == '_') {
            if (    stricter && (     i == 0 || (int) i == equals_pos || i == name_len- 1 || ! isDIGIT_A(name[i-1]) || ! isDIGIT_A(name[i+1])))

            {
                lookup_name[j++] = '_';
            }
            continue;
        }

        
        if (cur == '-' && ! stricter) {
            continue;
        }

        
        if (isSPACE_A(cur) && ! stricter) {
            continue;
        }

        lookup_name[j++] = cur;

        
        if (i >= name_len - 1 || cur != '/') {
            continue;
        }

        slash_pos = j;

        
        if (is_nv_type) {
            i++;
            if (i < name_len && name[i] == '+') {
                i++;
            }

            
            for (; i < name_len - 1; i++) {
                if (   name[i] != '0' && (name[i] != '_' || ! isDIGIT_A(name[i+1])))
                {
                    break;
                }
            }

            
            lookup_name[j++] = name[i];
        }
    }

    
    if (  (   UNLIKELY(memEQs(lookup_name, j, "l"))
           || UNLIKELY(memEQs(lookup_name, j, "gc=l")))
        && UNLIKELY(name[name_len-1] == '_'))
    {
        lookup_name[j++] = '&';
    }

    
    if (    non_pkg_begin + name_len > 2 &&  name[non_pkg_begin+0] == 'I' && (name[non_pkg_begin+1] == 'n' || name[non_pkg_begin+1] == 's'))

    {
        starts_with_In_or_Is = TRUE;
    }
    else {
        could_be_user_defined = FALSE;
    }

    if (could_be_user_defined) {
        CV* user_sub;

        
        bool empty_return = FALSE;

        
        user_sub = get_cvn_flags(name, name_len, 0);
        if (user_sub) {
            const char insecure[] = "Insecure user-defined property";

            
            dSP;
            SV * user_sub_sv = MUTABLE_SV(user_sub);
            SV * error;     
            SV * key;       
            SV * placeholder;
            SV ** saved_user_prop_ptr;      

            
            PERL_INT_FAST8_T retry_countdown = 10;

            DECLARATION_FOR_GLOBAL_CONTEXT;

            
            *user_defined_ptr = TRUE;

            
            if (TAINT_get) {
                if (SvCUR(msg) > 0) sv_catpvs(msg, "; ");
                sv_catpvn(msg, insecure, sizeof(insecure) - 1);
                goto append_name_to_msg;
            }

            
            key = newSVpvn(((to_fold) ? "1" : "0"), 1);
            fq_name = S_get_fq_name(aTHX_ name, name_len, is_utf8, non_pkg_begin != 0);
            sv_catsv(key, fq_name);
            sv_2mortal(key);

            

          re_fetch:
            USER_PROP_MUTEX_LOCK;

            
            saved_user_prop_ptr = hv_fetch(PL_user_def_props, SvPVX(key), SvCUR(key), 0);
            if (saved_user_prop_ptr) {

                
                if (is_invlist(*saved_user_prop_ptr)) {
                    prop_definition = *saved_user_prop_ptr;

                    
                    USER_PROP_MUTEX_UNLOCK;

                    
                    return prop_definition;
                }

                
                if (SvPOK(*saved_user_prop_ptr)) {
                    if (SvCUR(msg) > 0) sv_catpvs(msg, "; ");
                    sv_catsv(msg, *saved_user_prop_ptr);

                    
                    USER_PROP_MUTEX_UNLOCK;

                    return NULL;
                }

                assert(SvIOK(*saved_user_prop_ptr));

                
                if (SvIV(*saved_user_prop_ptr) != PTR2IV(CUR_CONTEXT)) {

                    
                    USER_PROP_MUTEX_UNLOCK;

                    
                    if (retry_countdown-- > 0) {
                        PerlProc_sleep(1);
                        goto re_fetch;
                    }

                    if (SvCUR(msg) > 0) sv_catpvs(msg, "; ");
                    sv_catpvs(msg, "Timeout waiting for another thread to " "define");
                    goto append_name_to_msg;
                }

                
                USER_PROP_MUTEX_UNLOCK;

                if (SvCUR(msg) > 0) sv_catpvs(msg, "; ");
                sv_catpvs(msg, "Infinite recursion in user-defined property");
                goto append_name_to_msg;
            }

            

            PUSHSTACKi(PERLSI_MAGIC);
            ENTER;

            
            SWITCH_TO_GLOBAL_CONTEXT;
            placeholder= newSVuv(PTR2IV(ORIGINAL_CONTEXT));
            (void) hv_store_ent(PL_user_def_props, key, placeholder, 0);
            RESTORE_CONTEXT;

            
            USER_PROP_MUTEX_UNLOCK;

            
            SAVEDESTRUCTOR_X(S_delete_recursion_entry, SvPVX(key));

            PUSHMARK(SP);
            SAVETMPS;

            
            XPUSHs(boolSV(to_fold));
            PUTBACK;

            
            SAVEHINTS();
            save_re_context();
            
            save_item(PL_subname);

            (void) call_sv(user_sub_sv, G_EVAL|G_SCALAR);

            SPAGAIN;

            error = ERRSV;
            if (TAINT_get || SvTRUE(error)) {
                if (SvCUR(msg) > 0) sv_catpvs(msg, "; ");
                if (SvTRUE(error)) {
                    sv_catpvs(msg, "Error \"");
                    sv_catsv(msg, error);
                    sv_catpvs(msg, "\"");
                }
                if (TAINT_get) {
                    if (SvTRUE(error)) sv_catpvs(msg, "; ");
                    sv_catpvn(msg, insecure, sizeof(insecure) - 1);
                }

                if (name_len > 0) {
                    sv_catpvs(msg, " in expansion of ");
                    Perl_sv_catpvf(aTHX_ msg, "%" UTF8f, UTF8fARG(is_utf8, name_len, name));

                }

                (void) POPs;
                prop_definition = NULL;
            }
            else {  
                SV * contents = POPs;

                
                if (      deferrable && (! SvPOK(contents) || SvCUR(contents) == 0))
                {
                        empty_return = TRUE;
                }
                else { 

                    prop_definition = handle_user_defined_property( name, name_len, is_utf8, to_fold, runtime, deferrable, contents, user_defined_ptr, msg, level);





                }
            }

            
            USER_PROP_MUTEX_LOCK;

            S_delete_recursion_entry(aTHX_ SvPVX(key));

            if (    ! empty_return && (! prop_definition || is_invlist(prop_definition)))
            {
                
                SWITCH_TO_GLOBAL_CONTEXT;
                (void) hv_store_ent(PL_user_def_props, key, ((prop_definition)

                                     ? newSVsv(prop_definition)
                                     : newSVsv(msg)), 0);
                RESTORE_CONTEXT;
            }

            
            USER_PROP_MUTEX_UNLOCK;

            FREETMPS;
            LEAVE;
            POPSTACK;

            if (empty_return) {
                goto definition_deferred;
            }

            if (prop_definition) {

                
                if (! is_invlist(prop_definition)) {
                    SvREFCNT_dec_NN(prop_definition);
                    goto definition_deferred;
                }

                sv_2mortal(prop_definition);
            }

            
            return prop_definition;

        }   
    }       

    

    lookup_len = j;     

    
    table_index = match_uniprop((U8 *) lookup_name, lookup_len);

    
    if (table_index == 0) {

        
        if (starts_with_In_or_Is) {
            lookup_name += 2;
            lookup_len -= 2;
            equals_pos -= 2;
            slash_pos -= 2;

            table_index = match_uniprop((U8 *) lookup_name, lookup_len);
        }

        if (table_index == 0) {
            char * canonical;

            
            if (! is_nv_type) {
                if (! could_be_user_defined) {
                    goto failed;
                }

                
                if (! deferrable) {
                    if (SvCUR(msg) > 0) sv_catpvs(msg, "; ");
                    sv_catpvs(msg, "Unknown user-defined property name");
                    goto append_name_to_msg;
                }

                goto definition_deferred;
            } 

            

            if (slash_pos < 0) {    

                

                NV value;
                SSize_t value_len = lookup_len - equals_pos;

                
                if (   value_len <= 0 || my_atof3(lookup_name + equals_pos, &value, value_len)

                          != lookup_name + lookup_len)
                {
                    goto failed;
                }

                
                if (Perl_ceil(value) == value) {
                    canonical = Perl_form(aTHX_ "%.*s%.0" NVff, equals_pos, lookup_name, value);
                }
                else {  
                    char * exp_ptr;

                    canonical = Perl_form(aTHX_ "%.*s%.*" NVef, equals_pos, lookup_name, PL_E_FORMAT_PRECISION, value);


                    
                    exp_ptr = strchr(canonical + equals_pos, 'e');
                    if (exp_ptr) {
                        char * cur_ptr = exp_ptr + 2; 
                        SSize_t excess_exponent_len = strlen(cur_ptr) - 2;

                        assert(*(cur_ptr - 1) == '-' || *(cur_ptr - 1) == '+');

                        if (excess_exponent_len > 0) {
                            SSize_t leading_zeros = strspn(cur_ptr, "0");
                            SSize_t excess_leading_zeros = MIN(leading_zeros, excess_exponent_len);
                            if (excess_leading_zeros > 0) {
                                Move(cur_ptr + excess_leading_zeros, cur_ptr, strlen(cur_ptr) - excess_leading_zeros + 1, char);



                            }
                        }
                    }
                }
            }
            else {  
                UV numerator, denominator, gcd, trial;
                const char * end_ptr;
                const char * sign = "";

                
                const char * this_lookup_name = lookup_name + equals_pos;
                lookup_len -= equals_pos;
                slash_pos -= equals_pos;

                
                if (this_lookup_name[0] == '-') {
                    sign = "-";
                    this_lookup_name++;
                    lookup_len--;
                    slash_pos--;
                }

                
                end_ptr = this_lookup_name + slash_pos;
                if (! grok_atoUV(this_lookup_name, &numerator, &end_ptr)) {
                    goto failed;
                }

                
                if (*end_ptr != '/') {
                    goto failed;
                }

                
                this_lookup_name += slash_pos;
                lookup_len -= slash_pos;
                end_ptr = this_lookup_name + lookup_len;

                
                if (! grok_atoUV(this_lookup_name, &denominator, &end_ptr)) {
                    goto failed;
                }

                
                if (   end_ptr != this_lookup_name + lookup_len || denominator == 0)
                {
                    goto failed;
                }

                
                gcd = numerator;
                trial = denominator;
                while (trial != 0) {
                    UV temp = trial;
                    trial = gcd % trial;
                    gcd = temp;
                }

                
                if (gcd == 1) {
                    goto failed;
                }

                
                numerator /= gcd;
                denominator /= gcd;

                canonical = Perl_form(aTHX_ "%.*s%s%" UVuf "/%" UVuf, equals_pos, lookup_name, sign, numerator, denominator);
            }

            
            table_index = match_uniprop((U8 *) canonical, strlen(canonical));
            if (table_index == 0) {
                goto failed;
            }
        }   
    }       

    
    if (table_index < 0) {
        invert_return = TRUE;
        table_index = -table_index;
    }

    
    if (table_index > MAX_UNI_KEYWORD_INDEX) {
        Size_t warning_offset = table_index / MAX_UNI_KEYWORD_INDEX;
        table_index %= MAX_UNI_KEYWORD_INDEX;
        Perl_ck_warner_d(aTHX_ packWARN(WARN_DEPRECATED), "Use of '%.*s' in \\p{} or \\P{} is deprecated because: %s", (int) name_len, name, deprecated_property_msgs[warning_offset]);

    }

    
    if (to_fold) {
        if (   table_index == UNI_XPOSIXUPPER || table_index == UNI_XPOSIXLOWER || table_index == UNI_TITLE)

        {
            table_index = UNI_CASED;
        }
        else if (   table_index == UNI_UPPERCASELETTER || table_index == UNI_LOWERCASELETTER  || table_index == UNI_TITLECASELETTER  ) {




            table_index = UNI_CASEDLETTER;
        }
        else if (  table_index == UNI_POSIXUPPER || table_index == UNI_POSIXLOWER)
        {
            table_index = UNI_POSIXALPHA;
        }
    }

    
    prop_definition =_new_invlist_C_array(uni_prop_ptrs[table_index]);
    sv_2mortal(prop_definition);


    
    {
        COPHH * hinthash = (IN_PERL_COMPILETIME)
                           ? CopHINTHASH_get(&PL_compiling)
                           : CopHINTHASH_get(PL_curcop);
	SV * pu_overrides = cophh_fetch_pv(hinthash, "private_use", 0, 0);

        if (UNLIKELY(pu_overrides && SvPOK(pu_overrides))) {

            
            SV * pu_lookup = Perl_newSVpvf(aTHX_ "%d=", table_index);
            const char * pos = strstr(SvPVX(pu_overrides), SvPVX(pu_lookup));

            if (pos) {
                bool dummy;
                SV * pu_definition;
                SV * pu_invlist;
                SV * expanded_prop_definition = sv_2mortal(invlist_clone(prop_definition, NULL));

                
                pos += SvCUR(pu_lookup);
                pu_definition = newSVpvn(pos, strchr(pos, '\a') - pos);
                pu_invlist = handle_user_defined_property(lookup_name, lookup_len, 0, 0, runtime, deferrable, pu_definition, &dummy, msg, level);








                if (TAINT_get) {
                    if (SvCUR(msg) > 0) sv_catpvs(msg, "; ");
                    sv_catpvs(msg, "Insecure private-use override");
                    goto append_name_to_msg;
                }

                
                _invlist_intersection(pu_invlist, PL_Private_Use, &pu_invlist);

                
                _invlist_union(prop_definition, pu_invlist, &expanded_prop_definition);
                prop_definition = expanded_prop_definition;
                Perl_ck_warner_d(aTHX_ packWARN(WARN_EXPERIMENTAL__PRIVATE_USE), "The private_use feature is experimental");
            }
        }
    }

    if (invert_return) {
        _invlist_invert(prop_definition);
    }
    return prop_definition;


  failed:
    if (non_pkg_begin != 0) {
        if (SvCUR(msg) > 0) sv_catpvs(msg, "; ");
        sv_catpvs(msg, "Illegal user-defined property name");
    }
    else {
        if (SvCUR(msg) > 0) sv_catpvs(msg, "; ");
        sv_catpvs(msg, "Can't find Unicode property definition");
    }
    

  append_name_to_msg:
    {
        const char * prefix = (runtime && level == 0) ?  " \\p{" : " \"";
        const char * suffix = (runtime && level == 0) ?  "}" : "\"";

        sv_catpv(msg, prefix);
        Perl_sv_catpvf(aTHX_ msg, "%" UTF8f, UTF8fARG(is_utf8, name_len, name));
        sv_catpv(msg, suffix);
    }

    return NULL;

  definition_deferred:

    
    if (! fq_name) {
        fq_name = S_get_fq_name(aTHX_ name, name_len, is_utf8, non_pkg_begin != 0 );

    }
    sv_catpvs(fq_name, "\n");

    *user_defined_ptr = TRUE;
    return fq_name;
}




