







static hashtab_T	func_hashtab;


static garray_T funcargs = GA_EMPTY;


static funccall_T *current_funccal = NULL;



static funccall_T *previous_funccal = NULL;

static void funccal_unref(funccall_T *fc, ufunc_T *fp, int force);
static void func_clear(ufunc_T *fp, int force);
static int func_free(ufunc_T *fp, int force);

    void func_init()
{
    hash_init(&func_hashtab);
}



    hashtab_T * func_tbl_get(void)
{
    return &func_hashtab;
}



    static char_u * one_function_arg( char_u	    *arg, garray_T    *newargs, garray_T    *argtypes, int	    types_optional, evalarg_T   *evalarg, int	    is_vararg, int	    skip)







{
    char_u	*p = arg;
    char_u	*arg_copy = NULL;
    int		is_underscore = FALSE;

    while (ASCII_ISALNUM(*p) || *p == '_')
	++p;
    if (arg == p || isdigit(*arg)
	    || (argtypes == NULL && ((p - arg == 9 && STRNCMP(arg, "firstline", 9) == 0)
		    || (p - arg == 8 && STRNCMP(arg, "lastline", 8) == 0))))
    {
	if (!skip)
	    semsg(_(e_illegal_argument_str), arg);
	return arg;
    }

    
    
    if (!skip && argtypes != NULL && check_defined(arg, p - arg, evalarg == NULL ? NULL : evalarg->eval_cctx, TRUE) == FAIL)
	return arg;

    if (newargs != NULL && ga_grow(newargs, 1) == FAIL)
	return arg;
    if (newargs != NULL)
    {
	int	c;
	int	i;

	c = *p;
	*p = NUL;
	arg_copy = vim_strsave(arg);
	if (arg_copy == NULL)
	{
	    *p = c;
	    return arg;
	}
	is_underscore = arg_copy[0] == '_' && arg_copy[1] == NUL;
	if (argtypes == NULL || !is_underscore)
	    
	    for (i = 0; i < newargs->ga_len; ++i)
		if (STRCMP(((char_u **)(newargs->ga_data))[i], arg_copy) == 0)
		{
		    semsg(_(e_duplicate_argument_name_str), arg_copy);
		    vim_free(arg_copy);
		    return arg;
		}
	((char_u **)(newargs->ga_data))[newargs->ga_len] = arg_copy;
	newargs->ga_len++;

	*p = c;
    }

    
    if (argtypes != NULL && (skip || ga_grow(argtypes, 1) == OK))
    {
	char_u *type = NULL;

	if (VIM_ISWHITE(*p) && *skipwhite(p) == ':')
	{
	    semsg(_(e_no_white_space_allowed_before_colon_str), arg_copy == NULL ? arg : arg_copy);
	    p = skipwhite(p);
	}
	if (*p == ':')
	{
	    ++p;
	    if (!skip && !VIM_ISWHITE(*p))
	    {
		semsg(_(e_white_space_required_after_str_str), ":", p - 1);
		return arg;
	    }
	    type = skipwhite(p);
	    p = skip_type(type, TRUE);
	    if (!skip)
		type = vim_strnsave(type, p - type);
	}
	else if (*skipwhite(p) != '=' && !types_optional && !is_underscore)
	{
	    semsg(_(e_missing_argument_type_for_str), arg_copy == NULL ? arg : arg_copy);
	    return arg;
	}
	if (!skip)
	{
	    if (type == NULL && types_optional)
		
		type = vim_strsave((char_u *)
					    (is_vararg ? "list<any>" : "any"));
	    ((char_u **)argtypes->ga_data)[argtypes->ga_len++] = type;
	}
    }

    return p;
}


    static char_u * get_function_line( exarg_T		*eap, char_u		**line_to_free, int		indent, getline_opt_T	getline_options)




{
    char_u *theline;

    if (eap->getline == NULL)
	theline = getcmdline(':', 0L, indent, 0);
    else theline = eap->getline(':', eap->cookie, indent, getline_options);
    if (theline != NULL)
    {
	if (*eap->cmdlinep == *line_to_free)
	    *eap->cmdlinep = theline;
	vim_free(*line_to_free);
	*line_to_free = theline;
    }

    return theline;
}


    static int get_function_args( char_u	**argp, char_u	endchar, garray_T	*newargs, garray_T	*argtypes, int		types_optional, evalarg_T	*evalarg, int		*varargs, garray_T	*default_args, int		skip, exarg_T	*eap, char_u	**line_to_free)











{
    int		mustend = FALSE;
    char_u	*arg;
    char_u	*p;
    int		c;
    int		any_default = FALSE;
    char_u	*expr;
    char_u	*whitep = *argp;

    if (newargs != NULL)
	ga_init2(newargs, (int)sizeof(char_u *), 3);
    if (argtypes != NULL)
	ga_init2(argtypes, (int)sizeof(char_u *), 3);
    if (!skip && default_args != NULL)
	ga_init2(default_args, (int)sizeof(char_u *), 3);

    if (varargs != NULL)
	*varargs = FALSE;

    
    arg = skipwhite(*argp);
    p = arg;
    while (*p != endchar)
    {
	while (eap != NULL && eap->getline != NULL && (*p == NUL || (VIM_ISWHITE(*whitep) && *p == '#')))
	{
	    
	    char_u *theline = get_function_line(eap, line_to_free, 0, GETLINE_CONCAT_CONT);

	    if (theline == NULL)
		break;
	    whitep = (char_u *)" ";
	    p = skipwhite(theline);
	}

	if (mustend && *p != endchar)
	{
	    if (!skip)
		semsg(_(e_invalid_argument_str), *argp);
	    goto err_ret;
	}
	if (*p == endchar)
	    break;

	if (p[0] == '.' && p[1] == '.' && p[2] == '.')
	{
	    if (varargs != NULL)
		*varargs = TRUE;
	    p += 3;
	    mustend = TRUE;

	    if (argtypes != NULL)
	    {
		
		if (!eval_isnamec1(*p))
		{
		    if (!skip)
			emsg(_(e_missing_name_after_dots));
		    goto err_ret;
		}

		arg = p;
		p = one_function_arg(p, newargs, argtypes, types_optional, evalarg, TRUE, skip);
		if (p == arg)
		    break;
		if (*skipwhite(p) == '=')
		{
		    emsg(_(e_cannot_use_default_for_variable_arguments));
		    break;
		}
	    }
	}
	else {
	    char_u *np;

	    arg = p;
	    p = one_function_arg(p, newargs, argtypes, types_optional, evalarg, FALSE, skip);
	    if (p == arg)
		break;

	    
	    
	    np = skipwhite(p);
	    if (*np == '=' && np[1] != '=' && np[1] != '~' && default_args != NULL)
	    {
		typval_T	rettv;

		
		any_default = TRUE;
		p = skipwhite(p) + 1;
		whitep = p;
		p = skipwhite(p);
		expr = p;
		if (eval1(&p, &rettv, NULL) != FAIL)
		{
		    if (!skip)
		    {
			if (ga_grow(default_args, 1) == FAIL)
			    goto err_ret;

			
			while (p > expr && VIM_ISWHITE(p[-1]))
			    p--;
			c = *p;
			*p = NUL;
			expr = vim_strsave(expr);
			if (expr == NULL)
			{
			    *p = c;
			    goto err_ret;
			}
			((char_u **)(default_args->ga_data))
						 [default_args->ga_len] = expr;
			default_args->ga_len++;
			*p = c;
		    }
		}
		else mustend = TRUE;
	    }
	    else if (any_default)
	    {
		emsg(_(e_non_default_argument_follows_default_argument));
		goto err_ret;
	    }

	    if (VIM_ISWHITE(*p) && *skipwhite(p) == ',')
	    {
		
		if (!skip)
		{
		    semsg(_(e_no_white_space_allowed_before_str_str), ",", p);
		    goto err_ret;
		}
		p = skipwhite(p);
	    }
	    if (*p == ',')
	    {
		++p;
		
		
		
		if (!skip && argtypes != NULL && !IS_WHITE_OR_NUL(*p) && *p != endchar)
		{
		    semsg(_(e_white_space_required_after_str_str), ",", p - 1);
		    goto err_ret;
		}
	    }
	    else mustend = TRUE;
	}
	whitep = p;
	p = skipwhite(p);
    }

    if (*p != endchar)
	goto err_ret;
    ++p;	

    *argp = p;
    return OK;

err_ret:
    if (newargs != NULL)
	ga_clear_strings(newargs);
    if (!skip && default_args != NULL)
	ga_clear_strings(default_args);
    return FAIL;
}


    static int parse_argument_types(ufunc_T *fp, garray_T *argtypes, int varargs)
{
    int len = 0;

    ga_init2(&fp->uf_type_list, sizeof(type_T *), 10);
    if (argtypes->ga_len > 0)
    {
	
	
	len = argtypes->ga_len - (varargs ? 1 : 0);

	if (len > 0)
	    fp->uf_arg_types = ALLOC_CLEAR_MULT(type_T *, len);
	if (fp->uf_arg_types != NULL)
	{
	    int	i;
	    type_T	*type;

	    for (i = 0; i < len; ++ i)
	    {
		char_u *p = ((char_u **)argtypes->ga_data)[i];

		if (p == NULL)
		    
		    type = &t_unknown;
		else type = parse_type(&p, &fp->uf_type_list, TRUE);
		if (type == NULL)
		    return FAIL;
		fp->uf_arg_types[i] = type;
	    }
	}
    }

    if (varargs)
    {
	char_u *p;

	
	
	fp->uf_va_name = ((char_u **)fp->uf_args.ga_data)
					      [fp->uf_args.ga_len - 1];
	--fp->uf_args.ga_len;
	p = ((char_u **)argtypes->ga_data)[len];
	if (p == NULL)
	    
	    fp->uf_va_type = &t_list_any;
	else {
	    fp->uf_va_type = parse_type(&p, &fp->uf_type_list, TRUE);
	    if (fp->uf_va_type != NULL && fp->uf_va_type->tt_type != VAR_LIST)
	    {
		semsg(_(e_variable_arguments_type_must_be_list_str), ((char_u **)argtypes->ga_data)[len]);
		return FAIL;
	    }
	}
	if (fp->uf_va_type == NULL)
	    return FAIL;
    }

    return OK;
}

    static int parse_return_type(ufunc_T *fp, char_u *ret_type)
{
    if (ret_type == NULL)
	fp->uf_ret_type = &t_void;
    else {
	char_u *p = ret_type;

	fp->uf_ret_type = parse_type(&p, &fp->uf_type_list, TRUE);
	if (fp->uf_ret_type == NULL)
	{
	    fp->uf_ret_type = &t_void;
	    return FAIL;
	}
    }
    return OK;
}


    static int register_closure(ufunc_T *fp)
{
    if (fp->uf_scoped == current_funccal)
	
	return OK;
    funccal_unref(fp->uf_scoped, fp, FALSE);
    fp->uf_scoped = current_funccal;
    current_funccal->fc_refcount++;

    if (ga_grow(&current_funccal->fc_funcs, 1) == FAIL)
	return FAIL;
    ((ufunc_T **)current_funccal->fc_funcs.ga_data)
	[current_funccal->fc_funcs.ga_len++] = fp;
    return OK;
}

    static void set_ufunc_name(ufunc_T *fp, char_u *name)
{
    
    
    STRCPY((void *)fp->uf_name, name);

    if (name[0] == K_SPECIAL)
    {
	fp->uf_name_exp = alloc(STRLEN(name) + 3);
	if (fp->uf_name_exp != NULL)
	{
	    STRCPY(fp->uf_name_exp, "<SNR>");
	    STRCAT(fp->uf_name_exp, fp->uf_name + 3);
	}
    }
}


    char_u * get_lambda_name(void)
{
    static char_u   name[30];
    static int	    lambda_no = 0;

    sprintf((char*)name, "<lambda>%d", ++lambda_no);
    return name;
}



    char_u * register_cfunc(cfunc_T cb, cfunc_free_T cb_free, void *state)
{
    char_u	*name = get_lambda_name();
    ufunc_T	*fp;

    fp = alloc_clear(offsetof(ufunc_T, uf_name) + STRLEN(name) + 1);
    if (fp == NULL)
	return NULL;

    fp->uf_def_status = UF_NOT_COMPILED;
    fp->uf_refcount = 1;
    fp->uf_varargs = TRUE;
    fp->uf_flags = FC_CFUNC | FC_LAMBDA;
    fp->uf_calls = 0;
    fp->uf_script_ctx = current_sctx;
    fp->uf_cb = cb;
    fp->uf_cb_free = cb_free;
    fp->uf_cb_state = state;

    set_ufunc_name(fp, name);
    hash_add(&func_hashtab, UF2HIKEY(fp));

    return name;
}



    static char_u * skip_arrow( char_u	*start, int	equal_arrow, char_u	**ret_type, int	*white_error)




{
    char_u  *s = start;
    char_u  *bef = start - 2; 

    if (equal_arrow)
    {
	if (*s == ':')
	{
	    if (white_error != NULL && !VIM_ISWHITE(s[1]))
	    {
		*white_error = TRUE;
		semsg(_(e_white_space_required_after_str_str), ":", s);
		return NULL;
	    }
	    s = skipwhite(s + 1);
	    *ret_type = s;
	    s = skip_type(s, TRUE);
	    if (s == *ret_type)
	    {
		emsg(_(e_missing_return_type));
		return NULL;
	    }
	}
	bef = s;
	s = skipwhite(s);
	if (*s != '=')
	    return NULL;
	++s;
    }
    if (*s != '>')
	return NULL;
    if (white_error != NULL && ((!VIM_ISWHITE(*bef) && *bef != '{')
		|| !IS_WHITE_OR_NUL(s[1])))
    {
	*white_error = TRUE;
	semsg(_(e_white_space_required_before_and_after_str_at_str), equal_arrow ? "=>" : "->", bef);
	return NULL;
    }
    return skipwhite(s + 1);
}


    static int is_function_cmd(char_u **cmd)
{
    char_u *p = *cmd;

    if (checkforcmd(&p, "function", 2))
    {
	if (*p == '(')
	    return FALSE;
	*cmd = p;
	return TRUE;
    }
    return FALSE;
}


    static void function_using_block_scopes(ufunc_T *fp, cstack_T *cstack)
{
    if (cstack != NULL && cstack->cs_idx >= 0)
    {
	int	    count = cstack->cs_idx + 1;
	int	    i;

	fp->uf_block_ids = ALLOC_MULT(int, count);
	if (fp->uf_block_ids != NULL)
	{
	    mch_memmove(fp->uf_block_ids, cstack->cs_block_id, sizeof(int) * count);
	    fp->uf_block_depth = count;
	}

	
	
	
	for (i = 0; i <= cstack->cs_idx; ++i)
	    cstack->cs_flags[i] |= CSF_FUNC_DEF;
    }
}


    static int get_function_body( exarg_T	    *eap, garray_T    *newlines, char_u	    *line_arg_in, char_u	    **line_to_free)




{
    linenr_T	sourcing_lnum_top = SOURCING_LNUM;
    linenr_T	sourcing_lnum_off;
    int		saved_wait_return = need_wait_return;
    char_u	*line_arg = line_arg_in;
    int		vim9_function = eap->cmdidx == CMD_def || eap->cmdidx == CMD_block;

    char	nesting_def[MAX_FUNC_NESTING];
    char	nesting_inline[MAX_FUNC_NESTING];
    int		nesting = 0;
    getline_opt_T getline_options;
    int		indent = 2;
    char_u	*skip_until = NULL;
    int		ret = FAIL;
    int		is_heredoc = FALSE;
    int		heredoc_concat_len = 0;
    garray_T	heredoc_ga;
    char_u	*heredoc_trimmed = NULL;

    ga_init2(&heredoc_ga, 1, 500);

    
    
    sourcing_lnum_off = get_sourced_lnum(eap->getline, eap->cookie);
    if (SOURCING_LNUM < sourcing_lnum_off)
    {
	sourcing_lnum_off -= SOURCING_LNUM;
	if (ga_grow(newlines, sourcing_lnum_off) == FAIL)
	    goto theend;
	while (sourcing_lnum_off-- > 0)
	    ((char_u **)(newlines->ga_data))[newlines->ga_len++] = NULL;
    }

    nesting_def[0] = vim9_function;
    nesting_inline[0] = eap->cmdidx == CMD_block;
    getline_options = vim9_function ? GETLINE_CONCAT_CONTBAR : GETLINE_CONCAT_CONT;
    for (;;)
    {
	char_u	*theline;
	char_u	*p;
	char_u	*arg;

	if (KeyTyped)
	{
	    msg_scroll = TRUE;
	    saved_wait_return = FALSE;
	}
	need_wait_return = FALSE;

	if (line_arg != NULL)
	{
	    
	    theline = line_arg;
	    p = vim_strchr(theline, '\n');
	    if (p == NULL)
		line_arg += STRLEN(line_arg);
	    else {
		*p = NUL;
		line_arg = p + 1;
	    }
	}
	else {
	    theline = get_function_line(eap, line_to_free, indent, getline_options);
	}
	if (KeyTyped)
	    lines_left = Rows - 1;
	if (theline == NULL)
	{
	    
	    SOURCING_LNUM = sourcing_lnum_top;
	    if (skip_until != NULL)
		semsg(_(e_missing_heredoc_end_marker_str), skip_until);
	    else if (nesting_inline[nesting])
		emsg(_(e_missing_end_block));
	    else if (eap->cmdidx == CMD_def)
		emsg(_(e_missing_enddef));
	    else emsg(_(e_missing_endfunction));
	    goto theend;
	}

	
	sourcing_lnum_off = get_sourced_lnum(eap->getline, eap->cookie);
	if (SOURCING_LNUM < sourcing_lnum_off)
	    sourcing_lnum_off -= SOURCING_LNUM;
	else sourcing_lnum_off = 0;

	if (skip_until != NULL)
	{
	    
	    
	    
	    
	    if (heredoc_trimmed == NULL || (is_heredoc && skipwhite(theline) == theline)
		    || STRNCMP(theline, heredoc_trimmed, STRLEN(heredoc_trimmed)) == 0)
	    {
		if (heredoc_trimmed == NULL)
		    p = theline;
		else if (is_heredoc)
		    p = skipwhite(theline) == theline ? theline : theline + STRLEN(heredoc_trimmed);
		else p = theline + STRLEN(heredoc_trimmed);
		if (STRCMP(p, skip_until) == 0)
		{
		    VIM_CLEAR(skip_until);
		    VIM_CLEAR(heredoc_trimmed);
		    getline_options = vim9_function ? GETLINE_CONCAT_CONTBAR : GETLINE_CONCAT_CONT;
		    is_heredoc = FALSE;

		    if (heredoc_concat_len > 0)
		    {
			
			
			ga_concat(&heredoc_ga, theline);
			vim_free(((char_u **)(newlines->ga_data))[ heredoc_concat_len - 1]);
			((char_u **)(newlines->ga_data))[ heredoc_concat_len - 1] = heredoc_ga.ga_data;
			ga_init(&heredoc_ga);
			heredoc_concat_len = 0;
			theline += STRLEN(theline);  
		    }
		}
	    }
	}
	else {
	    int	    c;
	    char_u  *end;

	    
	    for (p = theline; VIM_ISWHITE(*p) || *p == ':'; ++p)
		;

	    
	    
	    if (nesting_inline[nesting] ? *p == '}' : (checkforcmd(&p, nesting_def[nesting] ? "enddef" : "endfunction", 4)


			&& *p != ':'))
	    {
		if (nesting-- == 0)
		{
		    char_u *nextcmd = NULL;

		    if (*p == '|' || *p == '}')
			nextcmd = p + 1;
		    else if (line_arg != NULL && *skipwhite(line_arg) != NUL)
			nextcmd = line_arg;
		    else if (*p != NUL && *p != (vim9_function ? '#' : '"')
					   && (vim9_function || p_verbose > 0))
		    {
			SOURCING_LNUM = sourcing_lnum_top + newlines->ga_len + 1;
			if (eap->cmdidx == CMD_def)
			    semsg(_(e_text_found_after_str_str), "enddef", p);
			else give_warning2((char_u *)
				   _("W22: Text found after :endfunction: %s"), p, TRUE);
		    }
		    if (nextcmd != NULL && *skipwhite(nextcmd) != NUL)
		    {
			
			
			
			eap->nextcmd = nextcmd;
			if (*line_to_free != NULL && *eap->cmdlinep != *line_to_free)
			{
			    vim_free(*eap->cmdlinep);
			    *eap->cmdlinep = *line_to_free;
			    *line_to_free = NULL;
			}
		    }
		    break;
		}
	    }

	    
	    
	    
	    
	    
	    else if (nesting_def[nesting])
	    {
		if (checkforcmd(&p, "endfunction", 4) && *p != ':')
		    emsg(_(e_mismatched_endfunction));
	    }
	    else if (eap->cmdidx == CMD_def && checkforcmd(&p, "enddef", 4))
		emsg(_(e_mismatched_enddef));

	    
	    
	    if (indent > 2 && (*p == '}' || STRNCMP(p, "end", 3) == 0))
		indent -= 2;
	    else if (STRNCMP(p, "if", 2) == 0 || STRNCMP(p, "wh", 2) == 0 || STRNCMP(p, "for", 3) == 0 || STRNCMP(p, "try", 3) == 0)


		indent += 2;

	    
	    
	    
	    c = *p;
	    if (is_function_cmd(&p)
		    || (eap->cmdidx == CMD_def && checkforcmd(&p, "def", 3)))
	    {
		if (*p == '!')
		    p = skipwhite(p + 1);
		p += eval_fname_script(p);
		vim_free(trans_function_name(&p, NULL, TRUE, 0, NULL, NULL, NULL));
		if (*skipwhite(p) == '(')
		{
		    if (nesting == MAX_FUNC_NESTING - 1)
			emsg(_(e_function_nesting_too_deep));
		    else {
			++nesting;
			nesting_def[nesting] = (c == 'd');
			nesting_inline[nesting] = FALSE;
			indent += 2;
		    }
		}
	    }

	    if (nesting_def[nesting] ? *p != '#' : *p != '"')
	    {
		
		end = p + STRLEN(p) - 1;
		while (end > p && VIM_ISWHITE(*end))
		    --end;
		if (end > p + 1 && *end == '{' && VIM_ISWHITE(end[-1]))
		{
		    int	    is_block;

		    
		    --end;
		    while (end > p && VIM_ISWHITE(*end))
			--end;
		    is_block = end > p + 2 && end[-1] == '=' && end[0] == '>';
		    if (!is_block)
		    {
			char_u *s = p;

			
			
			is_block = checkforcmd_noparen(&s, "autocmd", 2)
				      || checkforcmd_noparen(&s, "command", 3);
		    }

		    if (is_block)
		    {
			if (nesting == MAX_FUNC_NESTING - 1)
			    emsg(_(e_function_nesting_too_deep));
			else {
			    ++nesting;
			    nesting_def[nesting] = TRUE;
			    nesting_inline[nesting] = TRUE;
			    indent += 2;
			}
		    }
		}
	    }

	    
	    p = skip_range(p, FALSE, NULL);
	    if (!vim9_function && ((p[0] == 'a' && (!ASCII_ISALPHA(p[1]) || p[1] == 'p'))
		    || (p[0] == 'c' && (!ASCII_ISALPHA(p[1]) || (p[1] == 'h' && (!ASCII_ISALPHA(p[2]) || (p[2] == 'a' && (STRNCMP(&p[3], "nge", 3) != 0 || !ASCII_ISALPHA(p[6])))))))



		    || (p[0] == 'i' && (!ASCII_ISALPHA(p[1]) || (p[1] == 'n' && (!ASCII_ISALPHA(p[2])

				    || (p[2] == 's' && (!ASCII_ISALPHA(p[3])
						|| p[3] == 'e'))))))))
		skip_until = vim_strsave((char_u *)".");

	    
	    arg = skipwhite(skiptowhite(p));
	    if (arg[0] == '<' && arg[1] =='<' && ((p[0] == 'p' && p[1] == 'y' && (!ASCII_ISALNUM(p[2]) || p[2] == 't' || ((p[2] == '3' || p[2] == 'x')


						   && !ASCII_ISALPHA(p[3]))))
			|| (p[0] == 'p' && p[1] == 'e' && (!ASCII_ISALPHA(p[2]) || p[2] == 'r'))
			|| (p[0] == 't' && p[1] == 'c' && (!ASCII_ISALPHA(p[2]) || p[2] == 'l'))
			|| (p[0] == 'l' && p[1] == 'u' && p[2] == 'a' && !ASCII_ISALPHA(p[3]))
			|| (p[0] == 'r' && p[1] == 'u' && p[2] == 'b' && (!ASCII_ISALPHA(p[3]) || p[3] == 'y'))
			|| (p[0] == 'm' && p[1] == 'z' && (!ASCII_ISALPHA(p[2]) || p[2] == 's'))
			))
	    {
		
		p = skipwhite(arg + 2);
		if (STRNCMP(p, "trim", 4) == 0)
		{
		    
		    p = skipwhite(p + 4);
		    heredoc_trimmed = vim_strnsave(theline, skipwhite(theline) - theline);
		}
		if (*p == NUL)
		    skip_until = vim_strsave((char_u *)".");
		else skip_until = vim_strnsave(p, skiptowhite(p) - p);
		getline_options = GETLINE_NONE;
		is_heredoc = TRUE;
		if (eap->cmdidx == CMD_def)
		    heredoc_concat_len = newlines->ga_len + 1;
	    }

	    
	    
	    
	    
	    arg = skipwhite(skiptowhite(p));
	    if (*arg == '[')
		arg = vim_strchr(arg, ']');
	    if (arg != NULL)
	    {
		int found = (eap->cmdidx == CMD_def && arg[0] == '=' && arg[1] == '<' && arg[2] =='<');

		if (!found)
		    
		    arg = skipwhite(skiptowhite(arg));
		if (found || (arg[0] == '=' && arg[1] == '<' && arg[2] =='<' && (checkforcmd(&p, "let", 2)
			    || checkforcmd(&p, "var", 3)
			    || checkforcmd(&p, "final", 5)
			    || checkforcmd(&p, "const", 5))))
		{
		    p = skipwhite(arg + 3);
		    if (STRNCMP(p, "trim", 4) == 0)
		    {
			
			p = skipwhite(p + 4);
			heredoc_trimmed = vim_strnsave(theline, skipwhite(theline) - theline);
		    }
		    skip_until = vim_strnsave(p, skiptowhite(p) - p);
		    getline_options = GETLINE_NONE;
		    is_heredoc = TRUE;
		}
	    }
	}

	
	if (ga_grow(newlines, 1 + sourcing_lnum_off) == FAIL)
	    goto theend;

	if (heredoc_concat_len > 0)
	{
	    
	    
	    ga_concat(&heredoc_ga, theline);
	    ga_concat(&heredoc_ga, (char_u *)"\n");
	    p = vim_strsave((char_u *)"");
	}
	else {
	    
	    
	    
	    p = vim_strsave(theline);
	}
	if (p == NULL)
	    goto theend;
	((char_u **)(newlines->ga_data))[newlines->ga_len++] = p;

	
	
	while (sourcing_lnum_off-- > 0)
	    ((char_u **)(newlines->ga_data))[newlines->ga_len++] = NULL;

	
	if (line_arg != NULL && *line_arg == NUL)
	    line_arg = NULL;
    }

    
    if (!did_emsg)
	ret = OK;

theend:
    vim_free(skip_until);
    vim_free(heredoc_trimmed);
    vim_free(heredoc_ga.ga_data);
    need_wait_return |= saved_wait_return;
    return ret;
}


    static int lambda_function_body( char_u	    **arg, typval_T    *rettv, evalarg_T   *evalarg, garray_T    *newargs, garray_T    *argtypes, int	    varargs, garray_T    *default_args, char_u	    *ret_type)








{
    int		evaluate = (evalarg->eval_flags & EVAL_EVALUATE);
    garray_T	*gap = &evalarg->eval_ga;
    garray_T	*freegap = &evalarg->eval_freega;
    ufunc_T	*ufunc = NULL;
    exarg_T	eap;
    garray_T	newlines;
    char_u	*cmdline = NULL;
    int		ret = FAIL;
    char_u	*line_to_free = NULL;
    partial_T	*pt;
    char_u	*name;
    int		lnum_save = -1;
    linenr_T	sourcing_lnum_top = SOURCING_LNUM;

    if (!ends_excmd2(*arg, skipwhite(*arg + 1)))
    {
	semsg(_(e_trailing_characters_str), *arg + 1);
	return FAIL;
    }

    CLEAR_FIELD(eap);
    eap.cmdidx = CMD_block;
    eap.forceit = FALSE;
    eap.cmdlinep = &cmdline;
    eap.skip = !evaluate;
    if (evalarg->eval_cctx != NULL)
	fill_exarg_from_cctx(&eap, evalarg->eval_cctx);
    else {
	eap.getline = evalarg->eval_getline;
	eap.cookie = evalarg->eval_cookie;
    }

    ga_init2(&newlines, (int)sizeof(char_u *), 10);
    if (get_function_body(&eap, &newlines, NULL, &line_to_free) == FAIL)
    {
	if (cmdline != line_to_free)
	    vim_free(cmdline);
	goto erret;
    }

    
    evalarg->eval_break_count += newlines.ga_len;
    if (gap->ga_itemsize > 0)
    {
	int	idx;
	char_u	*last;
	size_t  plen;
	char_u  *pnl;

	for (idx = 0; idx < newlines.ga_len; ++idx)
	{
	    char_u  *p = skipwhite(((char_u **)newlines.ga_data)[idx]);

	    if (ga_grow(gap, 1) == FAIL || ga_grow(freegap, 1) == FAIL)
		goto erret;

	    
	    
	    
	    
	    if (*p == NUL || vim9_comment_start(p))
		p = (char_u *)"";
	    plen = STRLEN(p);
	    pnl = vim_strnsave((char_u *)"\n", plen + 1);
	    if (pnl != NULL)
		mch_memmove(pnl + 1, p, plen + 1);
	    ((char_u **)gap->ga_data)[gap->ga_len++] = pnl;
	    ((char_u **)freegap->ga_data)[freegap->ga_len++] = pnl;
	}
	if (ga_grow(gap, 1) == FAIL || ga_grow(freegap, 1) == FAIL)
	    goto erret;
	if (eap.nextcmd != NULL)
	    
	    last = cmdline;
	else  last = (char_u *)"}";

	plen = STRLEN(last);
	pnl = vim_strnsave((char_u *)"\n", plen + 1);
	if (pnl != NULL)
	    mch_memmove(pnl + 1, last, plen + 1);
	((char_u **)gap->ga_data)[gap->ga_len++] = pnl;
	((char_u **)freegap->ga_data)[freegap->ga_len++] = pnl;
    }

    if (eap.nextcmd != NULL)
    {
	garray_T *tfgap = &evalarg->eval_tofree_ga;

	
	*arg = eap.nextcmd;

	
	if (ga_grow(tfgap, 1) == OK)
	{
	    ((char_u **)(tfgap->ga_data))[tfgap->ga_len++] = cmdline;
	    evalarg->eval_using_cmdline = TRUE;
	    if (cmdline == line_to_free)
		line_to_free = NULL;
	}
    }
    else *arg = (char_u *)"";

    if (!evaluate)
    {
	ret = OK;
	goto erret;
    }

    name = get_lambda_name();
    ufunc = alloc_clear(offsetof(ufunc_T, uf_name) + STRLEN(name) + 1);
    if (ufunc == NULL)
	goto erret;
    set_ufunc_name(ufunc, name);
    if (hash_add(&func_hashtab, UF2HIKEY(ufunc)) == FAIL)
	goto erret;
    ufunc->uf_flags = FC_LAMBDA;
    ufunc->uf_refcount = 1;
    ufunc->uf_args = *newargs;
    newargs->ga_data = NULL;
    ufunc->uf_def_args = *default_args;
    default_args->ga_data = NULL;
    ufunc->uf_func_type = &t_func_any;

    
    lnum_save = SOURCING_LNUM;
    SOURCING_LNUM = sourcing_lnum_top;

    
    if (parse_argument_types(ufunc, argtypes, varargs) == FAIL)
    {
	SOURCING_LNUM = lnum_save;
	goto erret;
    }

    
    if (parse_return_type(ufunc, ret_type) == FAIL)
	goto erret;

    pt = ALLOC_CLEAR_ONE(partial_T);
    if (pt == NULL)
	goto erret;
    pt->pt_func = ufunc;
    pt->pt_refcount = 1;

    ufunc->uf_lines = newlines;
    newlines.ga_data = NULL;
    if (sandbox)
	ufunc->uf_flags |= FC_SANDBOX;
    if (!ASCII_ISUPPER(*ufunc->uf_name))
	ufunc->uf_flags |= FC_VIM9;
    ufunc->uf_script_ctx = current_sctx;
    ufunc->uf_script_ctx_version = current_sctx.sc_version;
    ufunc->uf_script_ctx.sc_lnum += sourcing_lnum_top;
    set_function_type(ufunc);

    function_using_block_scopes(ufunc, evalarg->eval_cstack);

    rettv->vval.v_partial = pt;
    rettv->v_type = VAR_PARTIAL;
    ufunc = NULL;
    ret = OK;

erret:
    if (lnum_save >= 0)
	SOURCING_LNUM = lnum_save;
    vim_free(line_to_free);
    ga_clear_strings(&newlines);
    if (newargs != NULL)
	ga_clear_strings(newargs);
    ga_clear_strings(default_args);
    if (ufunc != NULL)
    {
	func_clear(ufunc, TRUE);
	func_free(ufunc, TRUE);
    }
    return ret;
}


    int get_lambda_tv( char_u	    **arg, typval_T    *rettv, int	    types_optional, evalarg_T   *evalarg)




{
    int		evaluate = evalarg != NULL && (evalarg->eval_flags & EVAL_EVALUATE);
    garray_T	newargs;
    garray_T	newlines;
    garray_T	*pnewargs;
    garray_T	argtypes;
    garray_T	default_args;
    ufunc_T	*fp = NULL;
    partial_T   *pt = NULL;
    int		varargs;
    char_u	*ret_type = NULL;
    int		ret;
    char_u	*s;
    char_u	*start, *end;
    int		*old_eval_lavars = eval_lavars_used;
    int		eval_lavars = FALSE;
    char_u	*tofree1 = NULL;
    char_u	*tofree2 = NULL;
    int		equal_arrow = **arg == '(';
    int		white_error = FALSE;
    int		called_emsg_start = called_emsg;

    if (equal_arrow && !in_vim9script())
	return NOTDONE;

    ga_init(&newargs);
    ga_init(&newlines);

    
    
    s = *arg + 1;
    ret = get_function_args(&s, equal_arrow ? ')' : '-', NULL, types_optional ? &argtypes : NULL, types_optional, evalarg, NULL, &default_args, TRUE, NULL, NULL);

    if (ret == FAIL || skip_arrow(s, equal_arrow, &ret_type, NULL) == NULL)
    {
	if (types_optional)
	    ga_clear_strings(&argtypes);
	return called_emsg == called_emsg_start ? NOTDONE : FAIL;
    }

    
    if (evaluate)
	pnewargs = &newargs;
    else pnewargs = NULL;
    *arg += 1;
    ret = get_function_args(arg, equal_arrow ? ')' : '-', pnewargs, types_optional ? &argtypes : NULL, types_optional, evalarg, &varargs, &default_args, FALSE, NULL, NULL);


    if (ret == FAIL || (s = skip_arrow(*arg, equal_arrow, &ret_type, equal_arrow || in_vim9script() ? &white_error : NULL)) == NULL)

    {
	if (types_optional)
	    ga_clear_strings(&argtypes);
	ga_clear_strings(&newargs);
	return white_error ? FAIL : NOTDONE;
    }
    *arg = s;

    
    if (ret_type != NULL)
    {
	ret_type = vim_strsave(ret_type);
	tofree2 = ret_type;
    }

    
    if (evaluate)
	eval_lavars_used = &eval_lavars;

    *arg = skipwhite_and_linebreak(*arg, evalarg);

    
    if (equal_arrow && **arg == '{')
    {
	if (evalarg == NULL)
	    
	    goto theend;
	if (lambda_function_body(arg, rettv, evalarg, pnewargs, types_optional ? &argtypes : NULL, varargs, &default_args, ret_type) == FAIL)

	    goto errret;
	goto theend;
    }
    if (default_args.ga_len > 0)
    {
	emsg(_(e_cannot_use_default_values_in_lambda));
	goto errret;
    }

    
    start = *arg;
    ret = skip_expr_concatenate(arg, &start, &end, evalarg);
    if (ret == FAIL)
	goto errret;
    if (evalarg != NULL)
    {
	
	tofree1 = evalarg->eval_tofree;
	evalarg->eval_tofree = NULL;
    }

    if (!equal_arrow)
    {
	*arg = skipwhite_and_linebreak(*arg, evalarg);
	if (**arg != '}')
	{
	    semsg(_(e_expected_right_curly_str), *arg);
	    goto errret;
	}
	++*arg;
    }

    if (evaluate)
    {
	int	    len;
	int	    flags = FC_LAMBDA;
	char_u	    *p;
	char_u	    *line_end;
	char_u	    *name = get_lambda_name();

	fp = alloc_clear(offsetof(ufunc_T, uf_name) + STRLEN(name) + 1);
	if (fp == NULL)
	    goto errret;
	fp->uf_def_status = UF_NOT_COMPILED;
	pt = ALLOC_CLEAR_ONE(partial_T);
	if (pt == NULL)
	    goto errret;

	ga_init2(&newlines, (int)sizeof(char_u *), 1);
	if (ga_grow(&newlines, 1) == FAIL)
	    goto errret;

	
	line_end = vim_strchr(start, '\n');
	if (line_end == NULL || line_end > end)
	    line_end = end;

	
	len = 7 + (int)(line_end - start) + 1;
	p = alloc(len);
	if (p == NULL)
	    goto errret;
	((char_u **)(newlines.ga_data))[newlines.ga_len++] = p;
	STRCPY(p, "return ");
	vim_strncpy(p + 7, start, line_end - start);

	if (line_end != end)
	{
	    
	    
	    while (*line_end == '\n')
	    {
		if (ga_grow(&newlines, 1) == FAIL)
		    goto errret;
		start = line_end + 1;
		line_end = vim_strchr(start, '\n');
		if (line_end == NULL)
		    line_end = end;
		((char_u **)(newlines.ga_data))[newlines.ga_len++] = vim_strnsave(start, line_end - start);
	    }
	}

	if (strstr((char *)p + 7, "a:") == NULL)
	    
	    flags |= FC_NOARGS;

	fp->uf_refcount = 1;
	set_ufunc_name(fp, name);
	fp->uf_args = newargs;
	ga_init(&fp->uf_def_args);
	if (types_optional)
	{
	    if (parse_argument_types(fp, &argtypes, in_vim9script() && varargs) == FAIL)
		goto errret;
	    if (ret_type != NULL)
	    {
		fp->uf_ret_type = parse_type(&ret_type, &fp->uf_type_list, TRUE);
		if (fp->uf_ret_type == NULL)
		    goto errret;
	    }
	    else fp->uf_ret_type = &t_unknown;
	}

	fp->uf_lines = newlines;
	if (current_funccal != NULL && eval_lavars)
	{
	    flags |= FC_CLOSURE;
	    if (register_closure(fp) == FAIL)
		goto errret;
	}


	if (prof_def_func())
	    func_do_profile(fp);

	if (sandbox)
	    flags |= FC_SANDBOX;
	
	
	fp->uf_varargs = !in_vim9script() || varargs;
	fp->uf_flags = flags;
	fp->uf_calls = 0;
	fp->uf_script_ctx = current_sctx;
	fp->uf_script_ctx.sc_lnum += SOURCING_LNUM - newlines.ga_len + 1;

	function_using_block_scopes(fp, evalarg->eval_cstack);

	pt->pt_func = fp;
	pt->pt_refcount = 1;
	rettv->vval.v_partial = pt;
	rettv->v_type = VAR_PARTIAL;

	hash_add(&func_hashtab, UF2HIKEY(fp));
    }

theend:
    eval_lavars_used = old_eval_lavars;
    if (evalarg != NULL && evalarg->eval_tofree == NULL)
	evalarg->eval_tofree = tofree1;
    else vim_free(tofree1);
    vim_free(tofree2);
    if (types_optional)
	ga_clear_strings(&argtypes);

    return OK;

errret:
    ga_clear_strings(&newargs);
    ga_clear_strings(&newlines);
    ga_clear_strings(&default_args);
    if (types_optional)
    {
	ga_clear_strings(&argtypes);
	if (fp != NULL)
	    vim_free(fp->uf_arg_types);
    }
    vim_free(fp);
    vim_free(pt);
    if (evalarg != NULL && evalarg->eval_tofree == NULL)
	evalarg->eval_tofree = tofree1;
    else vim_free(tofree1);
    vim_free(tofree2);
    eval_lavars_used = old_eval_lavars;
    return FAIL;
}


    char_u * deref_func_name( char_u	    *name, int	    *lenp, partial_T   **partialp, type_T	    **type, int	    no_autoload, int	    *found_var)






{
    dictitem_T	*v;
    typval_T	*tv = NULL;
    int		cc;
    char_u	*s = NULL;
    hashtab_T	*ht;
    int		did_type = FALSE;

    if (partialp != NULL)
	*partialp = NULL;

    cc = name[*lenp];
    name[*lenp] = NUL;

    v = find_var_also_in_script(name, &ht, no_autoload);
    name[*lenp] = cc;
    if (v != NULL)
    {
	tv = &v->di_tv;
    }
    else if (in_vim9script() || STRNCMP(name, "s:", 2) == 0)
    {
	imported_T  *import;
	char_u	    *p = name;
	int	    len = *lenp;

	if (STRNCMP(name, "s:", 2) == 0)
	{
	    p = name + 2;
	    len -= 2;
	}
	import = find_imported(p, len, NULL);

	
	if (import != NULL)
	{
	    name[len] = NUL;
	    semsg(_(e_cannot_use_str_itself_it_is_imported), name);
	    name[len] = cc;
	    *lenp = 0;
	    return (char_u *)"";	
	}
    }

    if (tv != NULL)
    {
	if (found_var != NULL)
	    *found_var = TRUE;
	if (tv->v_type == VAR_FUNC)
	{
	    if (tv->vval.v_string == NULL)
	    {
		*lenp = 0;
		return (char_u *)"";	
	    }
	    s = tv->vval.v_string;
	    *lenp = (int)STRLEN(s);
	}

	if (tv->v_type == VAR_PARTIAL)
	{
	    partial_T *pt = tv->vval.v_partial;

	    if (pt == NULL)
	    {
		*lenp = 0;
		return (char_u *)"";	
	    }
	    if (partialp != NULL)
		*partialp = pt;
	    s = partial_name(pt);
	    *lenp = (int)STRLEN(s);
	}

	if (s != NULL)
	{
	    if (!did_type && type != NULL && ht == get_script_local_ht())
	    {
		svar_T  *sv = find_typval_in_script(tv, 0);

		if (sv != NULL)
		    *type = sv->sv_type;
	    }
	    return s;
	}
    }

    return name;
}


    void emsg_funcname(char *ermsg, char_u *name)
{
    char_u	*p;

    if (*name == K_SPECIAL)
	p = concat_str((char_u *)"<SNR>", name + 3);
    else p = name;
    semsg(_(ermsg), p);
    if (p != name)
	vim_free(p);
}


    int get_func_tv( char_u	*name, int		len, typval_T	*rettv, char_u	**arg, evalarg_T	*evalarg, funcexe_T	*funcexe)






{
    char_u	*argp;
    int		ret = OK;
    typval_T	argvars[MAX_FUNC_ARGS + 1];	
    int		argcount = 0;		
    int		vim9script = in_vim9script();

    
    argp = *arg;
    while (argcount < MAX_FUNC_ARGS - (funcexe->fe_partial == NULL ? 0 : funcexe->fe_partial->pt_argc))
    {
	
	argp = skipwhite_and_linebreak(argp + 1, evalarg);

	if (*argp == ')' || *argp == ',' || *argp == NUL)
	    break;
	if (eval1(&argp, &argvars[argcount], evalarg) == FAIL)
	{
	    ret = FAIL;
	    break;
	}
	++argcount;
	
	
	if (vim9script)
	{
	    if (*argp != ',' && *skipwhite(argp) == ',')
	    {
		semsg(_(e_no_white_space_allowed_before_str_str), ",", argp);
		ret = FAIL;
		break;
	    }
	}
	else argp = skipwhite(argp);
	if (*argp != ',')
	    break;
	if (vim9script && !IS_WHITE_OR_NUL(argp[1]))
	{
	    semsg(_(e_white_space_required_after_str_str), ",", argp);
	    ret = FAIL;
	    break;
	}
    }
    argp = skipwhite_and_linebreak(argp, evalarg);
    if (*argp == ')')
	++argp;
    else ret = FAIL;

    if (ret == OK)
    {
	int	i = 0;
	int	did_emsg_before = did_emsg;

	if (get_vim_var_nr(VV_TESTING))
	{
	    
	    
	    if (funcargs.ga_itemsize == 0)
		ga_init2(&funcargs, (int)sizeof(typval_T *), 50);
	    for (i = 0; i < argcount; ++i)
		if (ga_grow(&funcargs, 1) == OK)
		    ((typval_T **)funcargs.ga_data)[funcargs.ga_len++] = &argvars[i];
	}

	ret = call_func(name, len, rettv, argcount, argvars, funcexe);
	if (in_vim9script() && did_emsg > did_emsg_before)
	{
	    
	    
	    ret = FAIL;
	    clear_tv(rettv);
	}

	funcargs.ga_len -= i;
    }
    else if (!aborting())
    {
	if (argcount == MAX_FUNC_ARGS)
	    emsg_funcname(e_too_many_arguments_for_function_str_2, name);
	else emsg_funcname(e_invalid_arguments_for_function_str, name);
    }

    while (--argcount >= 0)
	clear_tv(&argvars[argcount]);

    if (in_vim9script())
	*arg = argp;
    else *arg = skipwhite(argp);
    return ret;
}


    static int eval_fname_sid(char_u *p)
{
    return (*p == 's' || TOUPPER_ASC(p[2]) == 'I');
}


    char_u * fname_trans_sid(char_u *name, char_u *fname_buf, char_u **tofree, int *error)
{
    int		llen;
    char_u	*fname;
    int		i;

    llen = eval_fname_script(name);
    if (llen > 0)
    {
	fname_buf[0] = K_SPECIAL;
	fname_buf[1] = KS_EXTRA;
	fname_buf[2] = (int)KE_SNR;
	i = 3;
	if (eval_fname_sid(name))	
	{
	    if (current_sctx.sc_sid <= 0)
		*error = FCERR_SCRIPT;
	    else {
		sprintf((char *)fname_buf + 3, "%ld_", (long)current_sctx.sc_sid);
		i = (int)STRLEN(fname_buf);
	    }
	}
	if (i + STRLEN(name + llen) < FLEN_FIXED)
	{
	    STRCPY(fname_buf + i, name + llen);
	    fname = fname_buf;
	}
	else {
	    fname = alloc(i + STRLEN(name + llen) + 1);
	    if (fname == NULL)
		*error = FCERR_OTHER;
	    else {
		*tofree = fname;
		mch_memmove(fname, fname_buf, (size_t)i);
		STRCPY(fname + i, name + llen);
	    }
	}
    }
    else fname = name;
    return fname;
}


    static ufunc_T * find_func_with_sid(char_u *name, int sid)
{
    hashitem_T	*hi;
    char_u	buffer[200];

    buffer[0] = K_SPECIAL;
    buffer[1] = KS_EXTRA;
    buffer[2] = (int)KE_SNR;
    vim_snprintf((char *)buffer + 3, sizeof(buffer) - 3, "%ld_%s", (long)sid, name);
    hi = hash_find(&func_hashtab, buffer);
    if (!HASHITEM_EMPTY(hi))
	return HI2UF(hi);

    return NULL;
}


    ufunc_T * find_func_even_dead(char_u *name, int is_global, cctx_T *cctx UNUSED)
{
    hashitem_T	*hi;
    ufunc_T	*func;

    if (!is_global)
    {
	int	find_script_local = in_vim9script() && eval_isnamec1(*name)
					   && (name[1] != ':' || *name == 's');

	if (find_script_local)
	{
	    
	    func = find_func_with_sid(name[0] == 's' && name[1] == ':' ? name + 2 : name, current_sctx.sc_sid);
	    if (func != NULL)
		return func;
	}
    }

    hi = hash_find(&func_hashtab, STRNCMP(name, "g:", 2) == 0 ? name + 2 : name);
    if (!HASHITEM_EMPTY(hi))
	return HI2UF(hi);

    return NULL;
}


    ufunc_T * find_func(char_u *name, int is_global, cctx_T *cctx)
{
    ufunc_T	*fp = find_func_even_dead(name, is_global, cctx);

    if (fp != NULL && (fp->uf_flags & FC_DEAD) == 0)
	return fp;
    return NULL;
}


    int func_is_global(ufunc_T *ufunc)
{
    return ufunc->uf_name[0] != K_SPECIAL;
}


    static void cat_func_name(char_u *buf, ufunc_T *fp)
{
    if (!func_is_global(fp))
    {
	STRCPY(buf, "<SNR>");
	STRCAT(buf, fp->uf_name + 3);
    }
    else STRCPY(buf, fp->uf_name);
}


    static void add_nr_var( dict_T	*dp, dictitem_T	*v, char	*name, varnumber_T nr)




{
    STRCPY(v->di_key, name);
    v->di_flags = DI_FLAGS_RO | DI_FLAGS_FIX;
    hash_add(&dp->dv_hashtab, DI2HIKEY(v));
    v->di_tv.v_type = VAR_NUMBER;
    v->di_tv.v_lock = VAR_FIXED;
    v->di_tv.vval.v_number = nr;
}


    static void free_funccal(funccall_T *fc)
{
    int	i;

    for (i = 0; i < fc->fc_funcs.ga_len; ++i)
    {
	ufunc_T *fp = ((ufunc_T **)(fc->fc_funcs.ga_data))[i];

	
	
	
	
	if (fp != NULL && fp->uf_scoped == fc)
	    fp->uf_scoped = NULL;
    }
    ga_clear(&fc->fc_funcs);

    func_ptr_unref(fc->func);
    vim_free(fc);
}


   static void free_funccal_contents(funccall_T *fc)
{
    listitem_T	*li;

    
    vars_clear(&fc->l_vars.dv_hashtab);

    
    vars_clear(&fc->l_avars.dv_hashtab);

    
    FOR_ALL_LIST_ITEMS(&fc->l_varlist, li)
	clear_tv(&li->li_tv);

    free_funccal(fc);
}


    static void cleanup_function_call(funccall_T *fc)
{
    int	may_free_fc = fc->fc_refcount <= 0;
    int	free_fc = TRUE;

    current_funccal = fc->caller;

    
    if (may_free_fc && fc->l_vars.dv_refcount == DO_NOT_FREE_CNT)
	vars_clear(&fc->l_vars.dv_hashtab);
    else free_fc = FALSE;

    
    
    
    if (may_free_fc && fc->l_avars.dv_refcount == DO_NOT_FREE_CNT)
	vars_clear_ext(&fc->l_avars.dv_hashtab, FALSE);
    else {
	int	    todo;
	hashitem_T  *hi;
	dictitem_T  *di;

	free_fc = FALSE;

	
	todo = (int)fc->l_avars.dv_hashtab.ht_used;
	for (hi = fc->l_avars.dv_hashtab.ht_array; todo > 0; ++hi)
	{
	    if (!HASHITEM_EMPTY(hi))
	    {
		--todo;
		di = HI2DI(hi);
		copy_tv(&di->di_tv, &di->di_tv);
	    }
	}
    }

    if (may_free_fc && fc->l_varlist.lv_refcount == DO_NOT_FREE_CNT)
	fc->l_varlist.lv_first = NULL;
    else {
	listitem_T *li;

	free_fc = FALSE;

	
	FOR_ALL_LIST_ITEMS(&fc->l_varlist, li)
	    copy_tv(&li->li_tv, &li->li_tv);
    }

    if (free_fc)
	free_funccal(fc);
    else {
	static int made_copy = 0;

	
	
	
	fc->caller = previous_funccal;
	previous_funccal = fc;

	if (want_garbage_collect)
	    
	    made_copy = 0;
	else if (++made_copy >= (int)((4096 * 1024) / sizeof(*fc)))
	{
	    
	    
	    
	    
	    made_copy = 0;
	    want_garbage_collect = TRUE;
	}
    }
}


    static int numbered_function(char_u *name)
{
    return isdigit(*name)
	    || (name[0] == 'g' && name[1] == ':' && isdigit(name[2]));
}


    int func_name_refcount(char_u *name)
{
    return numbered_function(name) || *name == '<';
}


    static void funccal_unref(funccall_T *fc, ufunc_T *fp, int force)
{
    funccall_T	**pfc;
    int		i;

    if (fc == NULL)
	return;

    if (--fc->fc_refcount <= 0 && (force || ( fc->l_varlist.lv_refcount == DO_NOT_FREE_CNT && fc->l_vars.dv_refcount == DO_NOT_FREE_CNT && fc->l_avars.dv_refcount == DO_NOT_FREE_CNT)))


	for (pfc = &previous_funccal; *pfc != NULL; pfc = &(*pfc)->caller)
	{
	    if (fc == *pfc)
	    {
		*pfc = fc->caller;
		free_funccal_contents(fc);
		return;
	    }
	}
    for (i = 0; i < fc->fc_funcs.ga_len; ++i)
	if (((ufunc_T **)(fc->fc_funcs.ga_data))[i] == fp)
	    ((ufunc_T **)(fc->fc_funcs.ga_data))[i] = NULL;
}


    static int func_remove(ufunc_T *fp)
{
    hashitem_T	*hi;

    
    if (fp->uf_flags & FC_DEAD)
	return FALSE;

    hi = hash_find(&func_hashtab, UF2HIKEY(fp));
    if (!HASHITEM_EMPTY(hi))
    {
	
	
	
	if (fp->uf_def_status == UF_COMPILED && (fp->uf_flags & FC_COPY) == 0)
	{
	    fp->uf_flags |= FC_DEAD;
	    return FALSE;
	}
	hash_remove(&func_hashtab, hi);
	fp->uf_flags |= FC_DELETED;
	return TRUE;
    }
    return FALSE;
}

    static void func_clear_items(ufunc_T *fp)
{
    ga_clear_strings(&(fp->uf_args));
    ga_clear_strings(&(fp->uf_def_args));
    ga_clear_strings(&(fp->uf_lines));
    VIM_CLEAR(fp->uf_arg_types);
    VIM_CLEAR(fp->uf_block_ids);
    VIM_CLEAR(fp->uf_va_name);
    clear_type_list(&fp->uf_type_list);

    
    
    fp->uf_refcount += 3;
    partial_unref(fp->uf_partial);
    fp->uf_partial = NULL;
    fp->uf_refcount -= 3;


    if (fp->uf_cb_free != NULL)
    {
	fp->uf_cb_free(fp->uf_cb_state);
	fp->uf_cb_free = NULL;
    }

    fp->uf_cb_state = NULL;
    fp->uf_cb = NULL;


    VIM_CLEAR(fp->uf_tml_count);
    VIM_CLEAR(fp->uf_tml_total);
    VIM_CLEAR(fp->uf_tml_self);

}


    static void func_clear(ufunc_T *fp, int force)
{
    if (fp->uf_cleared)
	return;
    fp->uf_cleared = TRUE;

    
    func_clear_items(fp);
    funccal_unref(fp->uf_scoped, fp, force);
    unlink_def_function(fp);
}


    static int func_free(ufunc_T *fp, int force)
{
    
    
    if ((fp->uf_flags & (FC_DELETED | FC_REMOVED)) == 0)
	func_remove(fp);

    if ((fp->uf_flags & FC_DEAD) == 0 || force)
    {
	if (fp->uf_dfunc_idx > 0)
	    unlink_def_function(fp);
	VIM_CLEAR(fp->uf_name_exp);
	vim_free(fp);
	return OK;
    }
    return FAIL;
}


    void func_clear_free(ufunc_T *fp, int force)
{
    func_clear(fp, force);
    if (force || fp->uf_dfunc_idx == 0 || func_name_refcount(fp->uf_name)
						   || (fp->uf_flags & FC_COPY))
	func_free(fp, force);
    else fp->uf_flags |= FC_DEAD;
}


    int copy_func(char_u *lambda, char_u *global, ectx_T *ectx)
{
    ufunc_T *ufunc = find_func_even_dead(lambda, TRUE, NULL);
    ufunc_T *fp = NULL;

    if (ufunc == NULL)
    {
	semsg(_(e_lambda_function_not_found_str), lambda);
	return FAIL;
    }

    fp = find_func(global, TRUE, NULL);
    if (fp != NULL)
    {
	
	semsg(_(e_function_str_already_exists_add_bang_to_replace), global);
	return FAIL;
    }

    fp = alloc_clear(offsetof(ufunc_T, uf_name) + STRLEN(global) + 1);
    if (fp == NULL)
	return FAIL;

    fp->uf_varargs = ufunc->uf_varargs;
    fp->uf_flags = (ufunc->uf_flags & ~FC_VIM9) | FC_COPY;
    fp->uf_def_status = ufunc->uf_def_status;
    fp->uf_dfunc_idx = ufunc->uf_dfunc_idx;
    if (ga_copy_strings(&ufunc->uf_args, &fp->uf_args) == FAIL || ga_copy_strings(&ufunc->uf_def_args, &fp->uf_def_args)
								    == FAIL || ga_copy_strings(&ufunc->uf_lines, &fp->uf_lines) == FAIL)
	goto failed;

    fp->uf_name_exp = ufunc->uf_name_exp == NULL ? NULL : vim_strsave(ufunc->uf_name_exp);
    if (ufunc->uf_arg_types != NULL)
    {
	fp->uf_arg_types = ALLOC_MULT(type_T *, fp->uf_args.ga_len);
	if (fp->uf_arg_types == NULL)
	    goto failed;
	mch_memmove(fp->uf_arg_types, ufunc->uf_arg_types, sizeof(type_T *) * fp->uf_args.ga_len);
    }
    if (ufunc->uf_va_name != NULL)
    {
	fp->uf_va_name = vim_strsave(ufunc->uf_va_name);
	if (fp->uf_va_name == NULL)
	    goto failed;
    }
    fp->uf_ret_type = ufunc->uf_ret_type;

    fp->uf_refcount = 1;
    STRCPY(fp->uf_name, global);
    hash_add(&func_hashtab, UF2HIKEY(fp));

    
    link_def_function(fp);

    
    
    
    if ((ufunc->uf_flags & FC_CLOSURE) && ufunc->uf_partial == NULL)
    {
	partial_T   *pt = ALLOC_CLEAR_ONE(partial_T);

	if (pt == NULL)
	    goto failed;
	if (fill_partial_and_closure(pt, ufunc, ectx) == FAIL)
	{
            vim_free(pt);
	    goto failed;
	}
	ufunc->uf_partial = pt;
	--pt->pt_refcount;  
    }

    return OK;

failed:
    func_clear_free(fp, TRUE);
    return FAIL;
}

static int	funcdepth = 0;


    int funcdepth_increment(void)
{
    if (funcdepth >= p_mfd)
    {
	emsg(_(e_function_call_depth_is_higher_than_macfuncdepth));
	return FAIL;
    }
    ++funcdepth;
    return OK;
}

    void funcdepth_decrement(void)
{
    --funcdepth;
}


    int funcdepth_get(void)
{
    return funcdepth;
}


    void funcdepth_restore(int depth)
{
    funcdepth = depth;
}


    static void call_user_func( ufunc_T	*fp, int		argcount, typval_T	*argvars, typval_T	*rettv, funcexe_T	*funcexe, dict_T	*selfdict)






{
    sctx_T	save_current_sctx;
    int		using_sandbox = FALSE;
    funccall_T	*fc;
    int		save_did_emsg;
    int		default_arg_err = FALSE;
    dictitem_T	*v;
    int		fixvar_idx = 0;	
    int		i;
    int		ai;
    int		islambda = FALSE;
    char_u	numbuf[NUMBUFLEN];
    char_u	*name;
    typval_T	*tv_to_free[MAX_FUNC_ARGS];
    int		tv_to_free_len = 0;

    profinfo_T	profile_info;

    ESTACK_CHECK_DECLARATION   CLEAR_FIELD(profile_info);




    
    if (funcdepth_increment() == FAIL)
    {
	rettv->v_type = VAR_NUMBER;
	rettv->vval.v_number = -1;
	return;
    }

    line_breakcheck();		

    fc = ALLOC_CLEAR_ONE(funccall_T);
    if (fc == NULL)
	return;
    fc->caller = current_funccal;
    current_funccal = fc;
    fc->func = fp;
    fc->rettv = rettv;
    fc->level = ex_nesting_level;
    
    fc->breakpoint = dbg_find_breakpoint(FALSE, fp->uf_name, (linenr_T)0);
    fc->dbg_tick = debug_tick;
    
    ga_init2(&fc->fc_funcs, sizeof(ufunc_T *), 1);
    func_ptr_ref(fp);

    if (fp->uf_def_status != UF_NOT_COMPILED)
    {

	ufunc_T *caller = fc->caller == NULL ? NULL : fc->caller->func;

	

	if (do_profiling == PROF_YES)
	    profile_may_start_func(&profile_info, fp, caller);

	call_def_function(fp, argcount, argvars, funcexe->fe_partial, rettv);
	funcdepth_decrement();

	if (do_profiling == PROF_YES && (fp->uf_profiling || (caller != NULL && caller->uf_profiling)))
	    profile_may_end_func(&profile_info, fp, caller);

	current_funccal = fc->caller;
	free_funccal(fc);
	return;
    }

    islambda = fp->uf_flags & FC_LAMBDA;

    
    
    init_var_dict(&fc->l_vars, &fc->l_vars_var, VAR_DEF_SCOPE);
    if (selfdict != NULL)
    {
	
	
	v = &fc->fixvar[fixvar_idx++].var;
	name = v->di_key;
	STRCPY(name, "self");
	v->di_flags = DI_FLAGS_RO | DI_FLAGS_FIX;
	hash_add(&fc->l_vars.dv_hashtab, DI2HIKEY(v));
	v->di_tv.v_type = VAR_DICT;
	v->di_tv.v_lock = 0;
	v->di_tv.vval.v_dict = selfdict;
	++selfdict->dv_refcount;
    }

    
    init_var_dict(&fc->l_avars, &fc->l_avars_var, VAR_SCOPE);
    if ((fp->uf_flags & FC_NOARGS) == 0)
	add_nr_var(&fc->l_avars, &fc->fixvar[fixvar_idx++].var, "0", (varnumber_T)(argcount >= fp->uf_args.ga_len ? argcount - fp->uf_args.ga_len : 0));

    fc->l_avars.dv_lock = VAR_FIXED;
    if ((fp->uf_flags & FC_NOARGS) == 0)
    {
	
	
	v = &fc->fixvar[fixvar_idx++].var;
	name = v->di_key;
	STRCPY(name, "000");
	v->di_flags = DI_FLAGS_RO | DI_FLAGS_FIX;
	hash_add(&fc->l_avars.dv_hashtab, DI2HIKEY(v));
	v->di_tv.v_type = VAR_LIST;
	v->di_tv.v_lock = VAR_FIXED;
	v->di_tv.vval.v_list = &fc->l_varlist;
    }
    CLEAR_FIELD(fc->l_varlist);
    fc->l_varlist.lv_refcount = DO_NOT_FREE_CNT;
    fc->l_varlist.lv_lock = VAR_FIXED;

    
    if ((fp->uf_flags & FC_NOARGS) == 0)
    {
	add_nr_var(&fc->l_avars, &fc->fixvar[fixvar_idx++].var, "firstline", (varnumber_T)funcexe->fe_firstline);
	add_nr_var(&fc->l_avars, &fc->fixvar[fixvar_idx++].var, "lastline", (varnumber_T)funcexe->fe_lastline);
    }
    for (i = 0; i < argcount || i < fp->uf_args.ga_len; ++i)
    {
	int	    addlocal = FALSE;
	typval_T    def_rettv;
	int	    isdefault = FALSE;

	ai = i - fp->uf_args.ga_len;
	if (ai < 0)
	{
	    
	    name = FUNCARG(fp, i);
	    if (islambda)
		addlocal = TRUE;

	    
	    isdefault = ai + fp->uf_def_args.ga_len >= 0 && (i >= argcount || (argvars[i].v_type == VAR_SPECIAL && argvars[i].vval.v_number == VVAL_NONE));

	    if (isdefault)
	    {
		char_u	    *default_expr = NULL;

		def_rettv.v_type = VAR_NUMBER;
		def_rettv.vval.v_number = -1;

		default_expr = ((char_u **)(fp->uf_def_args.ga_data))
						 [ai + fp->uf_def_args.ga_len];
		if (eval1(&default_expr, &def_rettv, &EVALARG_EVALUATE) == FAIL)
		{
		    default_arg_err = 1;
		    break;
		}
	    }
	}
	else {
	    if ((fp->uf_flags & FC_NOARGS) != 0)
		
		break;

	    
	    sprintf((char *)numbuf, "%d", ai + 1);
	    name = numbuf;
	}
	if (fixvar_idx < FIXVAR_CNT && STRLEN(name) <= VAR_SHORT_LEN)
	{
	    v = &fc->fixvar[fixvar_idx++].var;
	    v->di_flags = DI_FLAGS_RO | DI_FLAGS_FIX;
	    STRCPY(v->di_key, name);
	}
	else {
	    v = dictitem_alloc(name);
	    if (v == NULL)
		break;
	    v->di_flags |= DI_FLAGS_RO | DI_FLAGS_FIX;
	}

	
	
	v->di_tv = isdefault ? def_rettv : argvars[i];
	v->di_tv.v_lock = VAR_FIXED;

	if (isdefault)
	    
	    tv_to_free[tv_to_free_len++] = &v->di_tv;

	if (addlocal)
	{
	    
	    
	    copy_tv(&v->di_tv, &v->di_tv);
	    hash_add(&fc->l_vars.dv_hashtab, DI2HIKEY(v));
	}
	else hash_add(&fc->l_avars.dv_hashtab, DI2HIKEY(v));

	if (ai >= 0 && ai < MAX_FUNC_ARGS)
	{
	    listitem_T *li = &fc->l_listitems[ai];

	    li->li_tv = argvars[i];
	    li->li_tv.v_lock = VAR_FIXED;
	    list_append(&fc->l_varlist, li);
	}
    }

    
    ++RedrawingDisabled;

    if (fp->uf_flags & FC_SANDBOX)
    {
	using_sandbox = TRUE;
	++sandbox;
    }

    estack_push_ufunc(fp, 1);
    ESTACK_CHECK_SETUP if (p_verbose >= 12)
    {
	++no_wait_return;
	verbose_enter_scroll();

	smsg(_("calling %s"), SOURCING_NAME);
	if (p_verbose >= 14)
	{
	    char_u	buf[MSG_BUF_LEN];
	    char_u	numbuf2[NUMBUFLEN];
	    char_u	*tofree;
	    char_u	*s;

	    msg_puts("(");
	    for (i = 0; i < argcount; ++i)
	    {
		if (i > 0)
		    msg_puts(", ");
		if (argvars[i].v_type == VAR_NUMBER)
		    msg_outnum((long)argvars[i].vval.v_number);
		else {
		    
		    ++emsg_off;
		    s = tv2string(&argvars[i], &tofree, numbuf2, 0);
		    --emsg_off;
		    if (s != NULL)
		    {
			if (vim_strsize(s) > MSG_BUF_CLEN)
			{
			    trunc_string(s, buf, MSG_BUF_CLEN, MSG_BUF_LEN);
			    s = buf;
			}
			msg_puts((char *)s);
			vim_free(tofree);
		    }
		}
	    }
	    msg_puts(")");
	}
	msg_puts("\n");   

	verbose_leave_scroll();
	--no_wait_return;
    }

    if (do_profiling == PROF_YES)
	profile_may_start_func(&profile_info, fp, fc->caller == NULL ? NULL : fc->caller->func);


    save_current_sctx = current_sctx;
    current_sctx = fp->uf_script_ctx;
    save_did_emsg = did_emsg;
    did_emsg = FALSE;

    if (default_arg_err && (fp->uf_flags & FC_ABORT))
	did_emsg = TRUE;
    else if (islambda)
    {
	char_u *p = *(char_u **)fp->uf_lines.ga_data + 7;

	
	
	++ex_nesting_level;
	(void)eval1(&p, rettv, &EVALARG_EVALUATE);
	--ex_nesting_level;
    }
    else  do_cmdline(NULL, get_func_line, (void *)fc, DOCMD_NOWAIT|DOCMD_VERBOSE|DOCMD_REPEAT);



    --RedrawingDisabled;

    
    if ((did_emsg && (fp->uf_flags & FC_ABORT)) || rettv->v_type == VAR_UNKNOWN)
    {
	clear_tv(rettv);
	rettv->v_type = VAR_NUMBER;
	rettv->vval.v_number = -1;
    }


    if (do_profiling == PROF_YES)
    {
	ufunc_T *caller = fc->caller == NULL ? NULL : fc->caller->func;

	if (fp->uf_profiling || (caller != NULL && caller->uf_profiling))
	    profile_may_end_func(&profile_info, fp, caller);
    }


    
    if (p_verbose >= 12)
    {
	++no_wait_return;
	verbose_enter_scroll();

	if (aborting())
	    smsg(_("%s aborted"), SOURCING_NAME);
	else if (fc->rettv->v_type == VAR_NUMBER)
	    smsg(_("%s returning #%ld"), SOURCING_NAME, (long)fc->rettv->vval.v_number);
	else {
	    char_u	buf[MSG_BUF_LEN];
	    char_u	numbuf2[NUMBUFLEN];
	    char_u	*tofree;
	    char_u	*s;

	    
	    
	    
	    ++emsg_off;
	    s = tv2string(fc->rettv, &tofree, numbuf2, 0);
	    --emsg_off;
	    if (s != NULL)
	    {
		if (vim_strsize(s) > MSG_BUF_CLEN)
		{
		    trunc_string(s, buf, MSG_BUF_CLEN, MSG_BUF_LEN);
		    s = buf;
		}
		smsg(_("%s returning %s"), SOURCING_NAME, s);
		vim_free(tofree);
	    }
	}
	msg_puts("\n");   

	verbose_leave_scroll();
	--no_wait_return;
    }

    ESTACK_CHECK_NOW estack_pop();
    current_sctx = save_current_sctx;

    if (do_profiling == PROF_YES)
	script_prof_restore(&profile_info.pi_wait_start);

    if (using_sandbox)
	--sandbox;

    if (p_verbose >= 12 && SOURCING_NAME != NULL)
    {
	++no_wait_return;
	verbose_enter_scroll();

	smsg(_("continuing in %s"), SOURCING_NAME);
	msg_puts("\n");   

	verbose_leave_scroll();
	--no_wait_return;
    }

    did_emsg |= save_did_emsg;
    funcdepth_decrement();
    for (i = 0; i < tv_to_free_len; ++i)
	clear_tv(tv_to_free[i]);
    cleanup_function_call(fc);
}


    int check_user_func_argcount(ufunc_T *fp, int argcount)
{
    int regular_args = fp->uf_args.ga_len;

    if (argcount < regular_args - fp->uf_def_args.ga_len)
	return FCERR_TOOFEW;
    else if (!has_varargs(fp) && argcount > regular_args)
	return FCERR_TOOMANY;
    return FCERR_UNKNOWN;
}


    int call_user_func_check( ufunc_T	    *fp, int	    argcount, typval_T    *argvars, typval_T    *rettv, funcexe_T   *funcexe, dict_T	    *selfdict)






{
    int error;

    if (fp->uf_flags & FC_RANGE && funcexe->fe_doesrange != NULL)
	*funcexe->fe_doesrange = TRUE;
    error = check_user_func_argcount(fp, argcount);
    if (error != FCERR_UNKNOWN)
	return error;
    if ((fp->uf_flags & FC_DICT) && selfdict == NULL)
	error = FCERR_DICT;
    else {
	int		did_save_redo = FALSE;
	save_redo_T	save_redo;

	
	save_search_patterns();
	if (!ins_compl_active())
	{
	    saveRedobuff(&save_redo);
	    did_save_redo = TRUE;
	}
	++fp->uf_calls;
	call_user_func(fp, argcount, argvars, rettv, funcexe, (fp->uf_flags & FC_DICT) ? selfdict : NULL);
	if (--fp->uf_calls <= 0 && fp->uf_refcount <= 0)
	    
	    func_clear_free(fp, FALSE);
	if (did_save_redo)
	    restoreRedobuff(&save_redo);
	restore_search_patterns();
	error = FCERR_NONE;
    }
    return error;
}

static funccal_entry_T *funccal_stack = NULL;


    void save_funccal(funccal_entry_T *entry)
{
    entry->top_funccal = current_funccal;
    entry->next = funccal_stack;
    funccal_stack = entry;
    current_funccal = NULL;
}

    void restore_funccal(void)
{
    if (funccal_stack == NULL)
	iemsg("INTERNAL: restore_funccal()");
    else {
	current_funccal = funccal_stack->top_funccal;
	funccal_stack = funccal_stack->next;
    }
}

    funccall_T * get_current_funccal(void)
{
    return current_funccal;
}


    void delete_script_functions(int sid)
{
    hashitem_T	*hi;
    ufunc_T	*fp;
    long_u	todo = 1;
    char_u	buf[30];
    size_t	len;

    buf[0] = K_SPECIAL;
    buf[1] = KS_EXTRA;
    buf[2] = (int)KE_SNR;
    sprintf((char *)buf + 3, "%d_", sid);
    len = STRLEN(buf);

    while (todo > 0)
    {
	todo = func_hashtab.ht_used;
	for (hi = func_hashtab.ht_array; todo > 0; ++hi)
	    if (!HASHITEM_EMPTY(hi))
	    {
		fp = HI2UF(hi);
		if (STRNCMP(fp->uf_name, buf, len) == 0)
		{
		    int changed = func_hashtab.ht_changed;

		    fp->uf_flags |= FC_DEAD;

		    if (fp->uf_calls > 0)
		    {
			
			
			if (func_remove(fp))
			    fp->uf_refcount--;
		    }
		    else {
			func_clear(fp, TRUE);
			
			
			
			if (changed != func_hashtab.ht_changed)
			    break;
		    }
		}
		--todo;
	    }
    }
}


    void free_all_functions(void)
{
    hashitem_T	*hi;
    ufunc_T	*fp;
    long_u	skipped = 0;
    long_u	todo = 1;
    int		changed;

    
    while (current_funccal != NULL)
    {
	clear_tv(current_funccal->rettv);
	cleanup_function_call(current_funccal);
	if (current_funccal == NULL && funccal_stack != NULL)
	    restore_funccal();
    }

    
    
    
    while (todo > 0)
    {
	todo = func_hashtab.ht_used;
	for (hi = func_hashtab.ht_array; todo > 0; ++hi)
	    if (!HASHITEM_EMPTY(hi))
	    {
		
		fp = HI2UF(hi);
		fp->uf_flags &= ~FC_DEAD;
		fp->uf_def_status = UF_NOT_COMPILED;

		
		
		if (func_name_refcount(fp->uf_name))
		    ++skipped;
		else {
		    changed = func_hashtab.ht_changed;
		    func_clear(fp, TRUE);
		    if (changed != func_hashtab.ht_changed)
		    {
			skipped = 0;
			break;
		    }
		}
		--todo;
	    }
    }

    
    
    skipped = 0;
    while (func_hashtab.ht_used > skipped)
    {
	todo = func_hashtab.ht_used;
	for (hi = func_hashtab.ht_array; todo > 0; ++hi)
	    if (!HASHITEM_EMPTY(hi))
	    {
		--todo;
		
		
		fp = HI2UF(hi);
		if (func_name_refcount(fp->uf_name))
		    ++skipped;
		else {
		    if (func_free(fp, FALSE) == OK)
		    {
			skipped = 0;
			break;
		    }
		    
		    ++skipped;
		}
	    }
    }
    if (skipped == 0)
	hash_clear(&func_hashtab);

    free_def_functions();
}



    int builtin_function(char_u *name, int len)
{
    char_u *p;

    if (!ASCII_ISLOWER(name[0]) || name[1] == ':')
	return FALSE;
    p = vim_strchr(name, AUTOLOAD_CHAR);
    return p == NULL || (len > 0 && p > name + len);
}

    int func_call( char_u	*name, typval_T	*args, partial_T	*partial, dict_T	*selfdict, typval_T	*rettv)





{
    list_T	*l = args->vval.v_list;
    listitem_T	*item;
    typval_T	argv[MAX_FUNC_ARGS + 1];
    int		argc = 0;
    int		r = 0;

    CHECK_LIST_MATERIALIZE(l);
    FOR_ALL_LIST_ITEMS(l, item)
    {
	if (argc == MAX_FUNC_ARGS - (partial == NULL ? 0 : partial->pt_argc))
	{
	    emsg(_(e_too_many_arguments));
	    break;
	}
	
	
	copy_tv(&item->li_tv, &argv[argc++]);
    }

    if (item == NULL)
    {
	funcexe_T funcexe;

	CLEAR_FIELD(funcexe);
	funcexe.fe_firstline = curwin->w_cursor.lnum;
	funcexe.fe_lastline = curwin->w_cursor.lnum;
	funcexe.fe_evaluate = TRUE;
	funcexe.fe_partial = partial;
	funcexe.fe_selfdict = selfdict;
	r = call_func(name, -1, rettv, argc, argv, &funcexe);
    }

    
    while (argc > 0)
	clear_tv(&argv[--argc]);

    return r;
}

static int callback_depth = 0;

    int get_callback_depth(void)
{
    return callback_depth;
}


    int call_callback( callback_T	*callback, int		len, typval_T	*rettv, int		argcount, typval_T	*argvars)





				
{
    funcexe_T	funcexe;
    int		ret;

    if (callback->cb_name == NULL || *callback->cb_name == NUL)
	return FAIL;
    CLEAR_FIELD(funcexe);
    funcexe.fe_evaluate = TRUE;
    funcexe.fe_partial = callback->cb_partial;
    ++callback_depth;
    ret = call_func(callback->cb_name, len, rettv, argcount, argvars, &funcexe);
    --callback_depth;

    
    
    if (need_rethrow && current_exception != NULL && trylevel == 0)
    {
	need_rethrow = FALSE;
	handle_did_throw();
    }

    return ret;
}


    varnumber_T call_callback_retnr( callback_T	*callback, int		argcount, typval_T	*argvars)



				
{
    typval_T	rettv;
    varnumber_T	retval;

    if (call_callback(callback, 0, &rettv, argcount, argvars) == FAIL)
	return -2;

    retval = tv_get_number_chk(&rettv, NULL);
    clear_tv(&rettv);
    return retval;
}


    void user_func_error(int error, char_u *name, funcexe_T *funcexe)
{
    switch (error)
    {
	case FCERR_UNKNOWN:
		if (funcexe->fe_found_var)
		    semsg(_(e_not_callable_type_str), name);
		else emsg_funcname(e_unknown_function_str, name);
		break;
	case FCERR_NOTMETHOD:
		emsg_funcname( N_(e_cannot_use_function_as_method_str), name);
		break;
	case FCERR_DELETED:
		emsg_funcname(e_function_was_deleted_str, name);
		break;
	case FCERR_TOOMANY:
		emsg_funcname(e_too_many_arguments_for_function_str, name);
		break;
	case FCERR_TOOFEW:
		emsg_funcname(e_not_enough_arguments_for_function_str, name);
		break;
	case FCERR_SCRIPT:
		emsg_funcname( e_using_sid_not_in_script_context_str, name);
		break;
	case FCERR_DICT:
		emsg_funcname(e_calling_dict_function_without_dictionary_str, name);
		break;
    }
}


    int call_func( char_u	*funcname, int		len, typval_T	*rettv, int		argcount_in, typval_T	*argvars_in,  funcexe_T	*funcexe)







{
    int		ret = FAIL;
    int		error = FCERR_NONE;
    int		i;
    ufunc_T	*fp = NULL;
    char_u	fname_buf[FLEN_FIXED + 1];
    char_u	*tofree = NULL;
    char_u	*fname = NULL;
    char_u	*name = NULL;
    int		argcount = argcount_in;
    typval_T	*argvars = argvars_in;
    dict_T	*selfdict = funcexe->fe_selfdict;
    typval_T	argv[MAX_FUNC_ARGS + 1]; 
					 
    int		argv_clear = 0;
    int		argv_base = 0;
    partial_T	*partial = funcexe->fe_partial;
    type_T	check_type;
    type_T	*check_type_args[MAX_FUNC_ARGS];

    
    
    rettv->v_type = VAR_UNKNOWN;

    if (partial != NULL)
	fp = partial->pt_func;
    if (fp == NULL)
    {
	
	
	name = len > 0 ? vim_strnsave(funcname, len) : vim_strsave(funcname);
	if (name == NULL)
	    return ret;

	fname = fname_trans_sid(name, fname_buf, &tofree, &error);
    }

    if (funcexe->fe_doesrange != NULL)
	*funcexe->fe_doesrange = FALSE;

    if (partial != NULL)
    {
	
	
	
	if (partial->pt_dict != NULL && (selfdict == NULL || !partial->pt_auto))
	    selfdict = partial->pt_dict;
	if (error == FCERR_NONE && partial->pt_argc > 0)
	{
	    for (argv_clear = 0; argv_clear < partial->pt_argc; ++argv_clear)
	    {
		if (argv_clear + argcount_in >= MAX_FUNC_ARGS)
		{
		    error = FCERR_TOOMANY;
		    goto theend;
		}
		copy_tv(&partial->pt_argv[argv_clear], &argv[argv_clear]);
	    }
	    for (i = 0; i < argcount_in; ++i)
		argv[i + argv_clear] = argvars_in[i];
	    argvars = argv;
	    argcount = partial->pt_argc + argcount_in;

	    if (funcexe->fe_check_type != NULL && funcexe->fe_check_type->tt_argcount != -1)
	    {
		
		
		check_type = *funcexe->fe_check_type;
		funcexe->fe_check_type = &check_type;
		check_type.tt_args = check_type_args;
		CLEAR_FIELD(check_type_args);
		for (i = 0; i < check_type.tt_argcount; ++i)
		    check_type_args[i + partial->pt_argc] = check_type.tt_args[i];
		check_type.tt_argcount += partial->pt_argc;
		check_type.tt_min_argcount += partial->pt_argc;
	    }
	}
    }

    if (error == FCERR_NONE && funcexe->fe_check_type != NULL && funcexe->fe_evaluate)
    {
	
	if (check_argument_types(funcexe->fe_check_type, argvars, argcount, (name != NULL) ? name : funcname) == FAIL)
	    error = FCERR_OTHER;
    }

    if (error == FCERR_NONE && funcexe->fe_evaluate)
    {
	char_u *rfname = fname;
	int	is_global = FALSE;

	
	if (fp == NULL && fname[0] == 'g' && fname[1] == ':')
	{
	    is_global = TRUE;
	    rfname = fname + 2;
	}

	rettv->v_type = VAR_NUMBER;	
	rettv->vval.v_number = 0;
	error = FCERR_UNKNOWN;

	if (fp != NULL || !builtin_function(rfname, -1))
	{
	    
	    if (fp == NULL)
		fp = find_func(rfname, is_global, NULL);

	    
	    if (fp == NULL && apply_autocmds(EVENT_FUNCUNDEFINED, rfname, rfname, TRUE, NULL)

		    && !aborting())
	    {
		
		fp = find_func(rfname, is_global, NULL);
	    }
	    
	    if (fp == NULL && script_autoload(rfname, TRUE) && !aborting())
	    {
		
		fp = find_func(rfname, is_global, NULL);
	    }
	    if (fp == NULL)
	    {
		char_u *p = untrans_function_name(rfname);

		
		
		if (p != NULL && (funcname[0] != 's' || funcname[1] != ':'))
		    fp = find_func(p, is_global, NULL);
	    }

	    if (fp != NULL && (fp->uf_flags & FC_DELETED))
		error = FCERR_DELETED;

	    else if (fp != NULL && (fp->uf_flags & FC_CFUNC))
	    {
		cfunc_T cb = fp->uf_cb;

		error = (*cb)(argcount, argvars, rettv, fp->uf_cb_state);
	    }

	    else if (fp != NULL)
	    {
		if (funcexe->fe_argv_func != NULL)
		    
		    argcount = funcexe->fe_argv_func(argcount, argvars, argv_clear, fp->uf_args.ga_len);

		if (funcexe->fe_basetv != NULL)
		{
		    
		    mch_memmove(&argv[1], argvars, sizeof(typval_T) * argcount);
		    argv[0] = *funcexe->fe_basetv;
		    argcount++;
		    argvars = argv;
		    argv_base = 1;
		}

		error = call_user_func_check(fp, argcount, argvars, rettv, funcexe, selfdict);
	    }
	}
	else if (funcexe->fe_basetv != NULL)
	{
	    
	    error = call_internal_method(fname, argcount, argvars, rettv, funcexe->fe_basetv);
	}
	else {
	    
	    error = call_internal_func(fname, argcount, argvars, rettv);
	}

	
	update_force_abort();
    }
    if (error == FCERR_NONE)
	ret = OK;

theend:
    
    if (!aborting())
    {
	user_func_error(error, (name != NULL) ? name : funcname, funcexe);
    }

    
    while (argv_clear > 0)
	clear_tv(&argv[--argv_clear + argv_base]);

    vim_free(tofree);
    vim_free(name);

    return ret;
}

    char_u * printable_func_name(ufunc_T *fp)
{
    return fp->uf_name_exp != NULL ? fp->uf_name_exp : fp->uf_name;
}


    static void list_func_head(ufunc_T *fp, int indent)
{
    int		j;

    msg_start();
    if (indent)
	msg_puts("   ");
    if (fp->uf_def_status != UF_NOT_COMPILED)
	msg_puts("def ");
    else msg_puts("function ");
    msg_puts((char *)printable_func_name(fp));
    msg_putchar('(');
    for (j = 0; j < fp->uf_args.ga_len; ++j)
    {
	if (j)
	    msg_puts(", ");
	msg_puts((char *)FUNCARG(fp, j));
	if (fp->uf_arg_types != NULL)
	{
	    char *tofree;

	    msg_puts(": ");
	    msg_puts(type_name(fp->uf_arg_types[j], &tofree));
	    vim_free(tofree);
	}
	if (j >= fp->uf_args.ga_len - fp->uf_def_args.ga_len)
	{
	    msg_puts(" = ");
	    msg_puts(((char **)(fp->uf_def_args.ga_data))
		       [j - fp->uf_args.ga_len + fp->uf_def_args.ga_len]);
	}
    }
    if (fp->uf_varargs)
    {
	if (j)
	    msg_puts(", ");
	msg_puts("...");
    }
    if (fp->uf_va_name != NULL)
    {
	if (j)
	    msg_puts(", ");
	msg_puts("...");
	msg_puts((char *)fp->uf_va_name);
	if (fp->uf_va_type != NULL)
	{
	    char *tofree;

	    msg_puts(": ");
	    msg_puts(type_name(fp->uf_va_type, &tofree));
	    vim_free(tofree);
	}
    }
    msg_putchar(')');

    if (fp->uf_def_status != UF_NOT_COMPILED)
    {
	if (fp->uf_ret_type != &t_void)
	{
	    char *tofree;

	    msg_puts(": ");
	    msg_puts(type_name(fp->uf_ret_type, &tofree));
	    vim_free(tofree);
	}
    }
    else if (fp->uf_flags & FC_ABORT)
	msg_puts(" abort");
    if (fp->uf_flags & FC_RANGE)
	msg_puts(" range");
    if (fp->uf_flags & FC_DICT)
	msg_puts(" dict");
    if (fp->uf_flags & FC_CLOSURE)
	msg_puts(" closure");
    msg_clr_eos();
    if (p_verbose > 0)
	last_set_msg(fp->uf_script_ctx);
}


    char_u * trans_function_name( char_u	**pp, int		*is_global, int		skip, int		flags, funcdict_T	*fdp, partial_T	**partial, type_T	**type)







{
    char_u	*name = NULL;
    char_u	*start;
    char_u	*end;
    int		lead;
    char_u	sid_buf[20];
    int		len;
    int		extra = 0;
    lval_T	lv;
    int		vim9script;

    if (fdp != NULL)
	CLEAR_POINTER(fdp);
    start = *pp;

    
    
    if ((*pp)[0] == K_SPECIAL && (*pp)[1] == KS_EXTRA && (*pp)[2] == (int)KE_SNR)
    {
	*pp += 3;
	len = get_id_len(pp) + 3;
	return vim_strnsave(start, len);
    }

    
    
    lead = eval_fname_script(start);
    if (lead > 2)
	start += lead;

    
    end = get_lval(start, NULL, &lv, FALSE, skip, flags | GLV_READ_ONLY, lead > 2 ? 0 : FNE_CHECK_START);
    if (end == start)
    {
	if (!skip)
	    emsg(_(e_function_name_required));
	goto theend;
    }
    if (end == NULL || (lv.ll_tv != NULL && (lead > 2 || lv.ll_range)))
    {
	
	if (!aborting())
	{
	    if (end != NULL)
		semsg(_(e_invalid_argument_str), start);
	}
	else *pp = find_name_end(start, NULL, NULL, FNE_INCL_BR);
	goto theend;
    }

    if (lv.ll_tv != NULL)
    {
	if (fdp != NULL)
	{
	    fdp->fd_dict = lv.ll_dict;
	    fdp->fd_newkey = lv.ll_newkey;
	    lv.ll_newkey = NULL;
	    fdp->fd_di = lv.ll_di;
	}
	if (lv.ll_tv->v_type == VAR_FUNC && lv.ll_tv->vval.v_string != NULL)
	{
	    name = vim_strsave(lv.ll_tv->vval.v_string);
	    *pp = end;
	}
	else if (lv.ll_tv->v_type == VAR_PARTIAL && lv.ll_tv->vval.v_partial != NULL)
	{
	    name = vim_strsave(partial_name(lv.ll_tv->vval.v_partial));
	    *pp = end;
	    if (partial != NULL)
		*partial = lv.ll_tv->vval.v_partial;
	}
	else {
	    if (!skip && !(flags & TFN_QUIET) && (fdp == NULL || lv.ll_dict == NULL || fdp->fd_newkey == NULL))
		emsg(_(e_funcref_required));
	    else *pp = end;
	    name = NULL;
	}
	goto theend;
    }

    if (lv.ll_name == NULL)
    {
	
	*pp = end;
	goto theend;
    }

    
    if (lv.ll_exp_name != NULL)
    {
	len = (int)STRLEN(lv.ll_exp_name);
	name = deref_func_name(lv.ll_exp_name, &len, partial, type, flags & TFN_NO_AUTOLOAD, NULL);
	if (name == lv.ll_exp_name)
	    name = NULL;
    }
    else if (!(flags & TFN_NO_DEREF))
    {
	len = (int)(end - *pp);
	name = deref_func_name(*pp, &len, partial, type, flags & TFN_NO_AUTOLOAD, NULL);
	if (name == *pp)
	    name = NULL;
    }
    if (name != NULL)
    {
	name = vim_strsave(name);
	*pp = end;
	if (STRNCMP(name, "<SNR>", 5) == 0)
	{
	    
	    name[0] = K_SPECIAL;
	    name[1] = KS_EXTRA;
	    name[2] = (int)KE_SNR;
	    mch_memmove(name + 3, name + 5, STRLEN(name + 5) + 1);
	}
	goto theend;
    }

    if (lv.ll_exp_name != NULL)
    {
	len = (int)STRLEN(lv.ll_exp_name);
	if (lead <= 2 && lv.ll_name == lv.ll_exp_name && STRNCMP(lv.ll_name, "s:", 2) == 0)
	{
	    
	    
	    lv.ll_name += 2;
	    len -= 2;
	    lead = 2;
	}
    }
    else {
	
	if (lead == 2 || (lv.ll_name[0] == 'g' && lv.ll_name[1] == ':'))
	{
	    if (is_global != NULL && lv.ll_name[0] == 'g')
		*is_global = TRUE;
	    lv.ll_name += 2;
	}
	len = (int)(end - lv.ll_name);
    }
    if (len <= 0)
    {
	if (!skip)
	    emsg(_(e_function_name_required));
	goto theend;
    }

    
    
    vim9script = ASCII_ISUPPER(*start) && in_vim9script();
    if (vim9script)
    {
	char_u *p;

	
	for (p = start; *p != NUL && *p != '('; ++p)
	    if (*p == AUTOLOAD_CHAR)
		vim9script = FALSE;
    }

    
    if (skip)
	lead = 0;	
    else if (lead > 0 || vim9script)
    {
	if (!vim9script)
	    lead = 3;
	if (vim9script || (lv.ll_exp_name != NULL && eval_fname_sid(lv.ll_exp_name))
						       || eval_fname_sid(*pp))
	{
	    
	    if (current_sctx.sc_sid <= 0)
	    {
		emsg(_(e_using_sid_not_in_script_context));
		goto theend;
	    }
	    sprintf((char *)sid_buf, "%ld_", (long)current_sctx.sc_sid);
	    if (vim9script)
		extra = 3 + (int)STRLEN(sid_buf);
	    else lead += (int)STRLEN(sid_buf);
	}
    }
    else if (!(flags & TFN_INT) && (builtin_function(lv.ll_name, len)
				   || (in_vim9script() && *lv.ll_name == '_')))
    {
	semsg(_(e_function_name_must_start_with_capital_or_s_str), start);
	goto theend;
    }
    if (!skip && !(flags & TFN_QUIET) && !(flags & TFN_NO_DEREF))
    {
	char_u *cp = vim_strchr(lv.ll_name, ':');

	if (cp != NULL && cp < end)
	{
	    semsg(_(e_function_name_cannot_contain_colon_str), start);
	    goto theend;
	}
    }

    name = alloc(len + lead + extra + 1);
    if (name != NULL)
    {
	if (!skip && (lead > 0 || vim9script))
	{
	    name[0] = K_SPECIAL;
	    name[1] = KS_EXTRA;
	    name[2] = (int)KE_SNR;
	    if (vim9script || lead > 3)	
		STRCPY(name + 3, sid_buf);
	}
	mch_memmove(name + lead + extra, lv.ll_name, (size_t)len);
	name[lead + extra + len] = NUL;
    }
    *pp = end;

theend:
    clear_lval(&lv);
    return name;
}


    char_u * untrans_function_name(char_u *name)
{
    char_u *p;

    if (*name == K_SPECIAL && in_vim9script())
    {
	p = vim_strchr(name, '_');
	if (p != NULL)
	    return p + 1;
    }
    return NULL;
}


    char_u * get_scriptlocal_funcname(char_u *funcname)
{
    char	sid_buf[25];
    int		off;
    char_u	*newname;

    if (funcname == NULL)
	return NULL;

    if (STRNCMP(funcname, "s:", 2) != 0 && STRNCMP(funcname, "<SID>", 5) != 0)
	
	return NULL;

    if (!SCRIPT_ID_VALID(current_sctx.sc_sid))
    {
	emsg(_(e_using_sid_not_in_script_context));
	return NULL;
    }
    
    vim_snprintf(sid_buf, sizeof(sid_buf), "<SNR>%ld_", (long)current_sctx.sc_sid);
    off = *funcname == 's' ? 2 : 5;
    newname = alloc(STRLEN(sid_buf) + STRLEN(funcname + off) + 1);
    if (newname == NULL)
	return NULL;
    STRCPY(newname, sid_buf);
    STRCAT(newname, funcname + off);

    return newname;
}


    char_u * save_function_name( char_u	    **name, int	    *is_global, int	    skip, int	    flags, funcdict_T  *fudi)





{
    char_u *p = *name;
    char_u *saved;

    if (STRNCMP(p, "<lambda>", 8) == 0)
    {
	p += 8;
	(void)getdigits(&p);
	saved = vim_strnsave(*name, p - *name);
	if (fudi != NULL)
	    CLEAR_POINTER(fudi);
    }
    else saved = trans_function_name(&p, is_global, skip, flags, fudi, NULL, NULL);

    *name = p;
    return saved;
}


    void list_functions(regmatch_T *regmatch)
{
    int		changed = func_hashtab.ht_changed;
    long_u	todo = func_hashtab.ht_used;
    hashitem_T	*hi;

    for (hi = func_hashtab.ht_array; todo > 0 && !got_int; ++hi)
    {
	if (!HASHITEM_EMPTY(hi))
	{
	    ufunc_T	*fp = HI2UF(hi);

	    --todo;
	    if ((fp->uf_flags & FC_DEAD) == 0 && (regmatch == NULL ? !message_filtered(fp->uf_name)

			    && !func_name_refcount(fp->uf_name)
			: !isdigit(*fp->uf_name)
			    && vim_regexec(regmatch, fp->uf_name, 0)))
	    {
		list_func_head(fp, FALSE);
		if (changed != func_hashtab.ht_changed)
		{
		    emsg(_(e_function_list_was_modified));
		    return;
		}
	    }
	}
    }
}


    ufunc_T * define_function(exarg_T *eap, char_u *name_arg, char_u **line_to_free)
{
    int		j;
    int		c;
    int		saved_did_emsg;
    char_u	*name = name_arg;
    int		is_global = FALSE;
    char_u	*p;
    char_u	*arg;
    char_u	*whitep;
    char_u	*line_arg = NULL;
    garray_T	newargs;
    garray_T	argtypes;
    garray_T	default_args;
    garray_T	newlines;
    int		varargs = FALSE;
    int		flags = 0;
    char_u	*ret_type = NULL;
    ufunc_T	*fp = NULL;
    int		fp_allocated = FALSE;
    int		free_fp = FALSE;
    int		overwrite = FALSE;
    dictitem_T	*v;
    funcdict_T	fudi;
    static int	func_nr = 0;	    
    int		paren;
    hashitem_T	*hi;
    linenr_T	sourcing_lnum_top;
    int		vim9script = in_vim9script();
    imported_T	*import = NULL;

    
    if (ends_excmd2(eap->cmd, eap->arg))
    {
	if (!eap->skip)
	    list_functions(NULL);
	set_nextcmd(eap, eap->arg);
	return NULL;
    }

    
    if (*eap->arg == '/')
    {
	p = skip_regexp(eap->arg + 1, '/', TRUE);
	if (!eap->skip)
	{
	    regmatch_T	regmatch;

	    c = *p;
	    *p = NUL;
	    regmatch.regprog = vim_regcomp(eap->arg + 1, RE_MAGIC);
	    *p = c;
	    if (regmatch.regprog != NULL)
	    {
		regmatch.rm_ic = p_ic;
		list_functions(&regmatch);
		vim_regfree(regmatch.regprog);
	    }
	}
	if (*p == '/')
	    ++p;
	set_nextcmd(eap, p);
	return NULL;
    }

    ga_init(&newargs);
    ga_init(&argtypes);
    ga_init(&default_args);

    
    p = eap->arg;
    if (name_arg != NULL)
    {
	
	paren = TRUE;
	CLEAR_FIELD(fudi);
    }
    else {
	name = save_function_name(&p, &is_global, eap->skip, TFN_NO_AUTOLOAD, &fudi);
	paren = (vim_strchr(p, '(') != NULL);
	if (name == NULL && (fudi.fd_dict == NULL || !paren) && !eap->skip)
	{
	    
	    if (!aborting())
	    {
		if (!eap->skip && fudi.fd_newkey != NULL)
		    semsg(_(e_key_not_present_in_dictionary), fudi.fd_newkey);
		vim_free(fudi.fd_newkey);
		return NULL;
	    }
	    else eap->skip = TRUE;
	}
    }

    
    
    saved_did_emsg = did_emsg;
    did_emsg = FALSE;

    
    if (!paren)
    {
	if (!ends_excmd(*skipwhite(p)))
	{
	    semsg(_(e_trailing_characters_str), p);
	    goto ret_free;
	}
	set_nextcmd(eap, p);
	if (eap->nextcmd != NULL)
	    *p = NUL;
	if (!eap->skip && !got_int)
	{
	    fp = find_func(name, is_global, NULL);
	    if (fp == NULL && ASCII_ISUPPER(*eap->arg))
	    {
		char_u *up = untrans_function_name(name);

		
		
		if (up != NULL)
		    fp = find_func(up, FALSE, NULL);
	    }

	    if (fp != NULL)
	    {
		list_func_head(fp, TRUE);
		for (j = 0; j < fp->uf_lines.ga_len && !got_int; ++j)
		{
		    if (FUNCLINE(fp, j) == NULL)
			continue;
		    msg_putchar('\n');
		    msg_outnum((long)(j + 1));
		    if (j < 9)
			msg_putchar(' ');
		    if (j < 99)
			msg_putchar(' ');
		    msg_prt_line(FUNCLINE(fp, j), FALSE);
		    out_flush();	
		    ui_breakcheck();
		}
		if (!got_int)
		{
		    msg_putchar('\n');
		    if (fp->uf_def_status != UF_NOT_COMPILED)
			msg_puts("   enddef");
		    else msg_puts("   endfunction");
		}
	    }
	    else emsg_funcname(e_undefined_function_str, eap->arg);
	}
	goto ret_free;
    }

    
    p = skipwhite(p);
    if (*p != '(')
    {
	if (!eap->skip)
	{
	    semsg(_(e_missing_paren_str), eap->arg);
	    goto ret_free;
	}
	
	if (vim_strchr(p, '(') != NULL)
	    p = vim_strchr(p, '(');
    }

    if ((vim9script || eap->cmdidx == CMD_def) && VIM_ISWHITE(p[-1]))
    {
	semsg(_(e_no_white_space_allowed_before_str_str), "(", p - 1);
	goto ret_free;
    }

    
    if (vim9script && eap->forceit && !is_global)
    {
	emsg(_(e_no_bang_allowed));
	goto ret_free;
    }

    ga_init2(&newlines, (int)sizeof(char_u *), 10);

    if (!eap->skip && name_arg == NULL)
    {
	
	
	if (name != NULL)
	    arg = name;
	else arg = fudi.fd_newkey;
	if (arg != NULL && (fudi.fd_di == NULL || (fudi.fd_di->di_tv.v_type != VAR_FUNC && fudi.fd_di->di_tv.v_type != VAR_PARTIAL)))

	{
	    char_u  *name_base = arg;
	    int	    i;

	    if (*arg == K_SPECIAL)
	    {
		name_base = vim_strchr(arg, '_');
		if (name_base == NULL)
		    name_base = arg + 3;
		else ++name_base;
	    }
	    for (i = 0; name_base[i] != NUL && (i == 0 ? eval_isnamec1(name_base[i])
					: eval_isnamec(name_base[i])); ++i)
		;
	    if (name_base[i] != NUL)
		emsg_funcname(e_invalid_argument_str, arg);

	    
	    
	    if (vim9script && *arg == K_SPECIAL && eval_variable(name_base, (int)STRLEN(name_base), 0, NULL, NULL, EVAL_VAR_NOAUTOLOAD + EVAL_VAR_IMPORT + EVAL_VAR_NO_FUNC) == OK)


	    {
		semsg(_(e_redefining_script_item_str), name_base);
		goto ret_free;
	    }
	}
	
	if (fudi.fd_dict != NULL && fudi.fd_dict->dv_scope == VAR_DEF_SCOPE)
	{
	    emsg(_(e_cannot_use_g_here));
	    goto ret_free;
	}
    }

    
    
    ++p;
    if (get_function_args(&p, ')', &newargs, eap->cmdidx == CMD_def ? &argtypes : NULL, FALSE, NULL, &varargs, &default_args, eap->skip, eap, line_to_free) == FAIL)


	goto errret_2;
    whitep = p;

    if (eap->cmdidx == CMD_def)
    {
	
	if (*skipwhite(p) == ':')
	{
	    if (*p != ':')
	    {
		semsg(_(e_no_white_space_allowed_before_colon_str), p);
		p = skipwhite(p);
	    }
	    else if (!IS_WHITE_OR_NUL(p[1]))
		semsg(_(e_white_space_required_after_str_str), ":", p);
	    ret_type = skipwhite(p + 1);
	    p = skip_type(ret_type, FALSE);
	    if (p > ret_type)
	    {
		ret_type = vim_strnsave(ret_type, p - ret_type);
		whitep = p;
		p = skipwhite(p);
	    }
	    else {
		semsg(_(e_expected_type_str), ret_type);
		ret_type = NULL;
	    }
	}
	p = skipwhite(p);
    }
    else  for (;;)

	{
	    whitep = p;
	    p = skipwhite(p);
	    if (STRNCMP(p, "range", 5) == 0)
	    {
		flags |= FC_RANGE;
		p += 5;
	    }
	    else if (STRNCMP(p, "dict", 4) == 0)
	    {
		flags |= FC_DICT;
		p += 4;
	    }
	    else if (STRNCMP(p, "abort", 5) == 0)
	    {
		flags |= FC_ABORT;
		p += 5;
	    }
	    else if (STRNCMP(p, "closure", 7) == 0)
	    {
		flags |= FC_CLOSURE;
		p += 7;
		if (current_funccal == NULL)
		{
		    emsg_funcname(e_closure_function_should_not_be_at_top_level, name == NULL ? (char_u *)"" : name);
		    goto erret;
		}
	    }
	    else break;
	}

    
    
    if (*p == '\n')
	line_arg = p + 1;
    else if (*p != NUL && !(*p == '"' && (!vim9script || eap->cmdidx == CMD_function)
						     && eap->cmdidx != CMD_def)
	    && !(VIM_ISWHITE(*whitep) && *p == '#' && (vim9script || eap->cmdidx == CMD_def))
	    && !eap->skip && !did_emsg)
	semsg(_(e_trailing_characters_str), p);

    
    if (KeyTyped)
    {
	
	
	
	if (!eap->skip && !eap->forceit)
	{
	    if (fudi.fd_dict != NULL && fudi.fd_newkey == NULL)
		emsg(_(e_dictionary_entry_already_exists));
	    else if (name != NULL && find_func(name, is_global, NULL) != NULL)
		emsg_funcname(e_function_str_already_exists_add_bang_to_replace, name);
	}

	if (!eap->skip && did_emsg)
	    goto erret;

	msg_putchar('\n');	    
	cmdline_row = msg_row;
    }

    
    sourcing_lnum_top = SOURCING_LNUM;

    
    
    if (get_function_body(eap, &newlines, line_arg, line_to_free) == FAIL || eap->skip)
	goto erret;

    
    if (fudi.fd_dict == NULL)
    {
	hashtab_T	*ht;

	v = find_var(name, &ht, TRUE);
	if (v != NULL && v->di_tv.v_type == VAR_FUNC)
	{
	    emsg_funcname(e_function_name_conflicts_with_variable_str, name);
	    goto erret;
	}

	fp = find_func_even_dead(name, is_global, NULL);
	if (vim9script)
	{
	    char_u *uname = untrans_function_name(name);

	    import = find_imported(uname == NULL ? name : uname, 0, NULL);
	}

	if (fp != NULL || import != NULL)
	{
	    int dead = fp != NULL && (fp->uf_flags & FC_DEAD);

	    
	    
	    
	    if (import != NULL || (!dead && !eap->forceit && (fp->uf_script_ctx.sc_sid != current_sctx.sc_sid || fp->uf_script_ctx.sc_seq == current_sctx.sc_seq)))


	    {
		SOURCING_LNUM = sourcing_lnum_top;
		if (vim9script)
		    emsg_funcname(e_name_already_defined_str, name);
		else emsg_funcname(e_function_str_already_exists_add_bang_to_replace, name);
		goto erret;
	    }
	    if (fp->uf_calls > 0)
	    {
		emsg_funcname( e_cannot_redefine_function_str_it_is_in_use, name);
		goto erret;
	    }
	    if (fp->uf_refcount > 1)
	    {
		
		
		--fp->uf_refcount;
		fp->uf_flags |= FC_REMOVED;
		fp = NULL;
		overwrite = TRUE;
	    }
	    else {
		char_u *exp_name = fp->uf_name_exp;

		
		VIM_CLEAR(name);
		fp->uf_name_exp = NULL;
		func_clear_items(fp);
		fp->uf_name_exp = exp_name;
		fp->uf_flags &= ~FC_DEAD;

		fp->uf_profiling = FALSE;
		fp->uf_prof_initialized = FALSE;

		fp->uf_def_status = UF_NOT_COMPILED;
	    }
	}
    }
    else {
	char	numbuf[20];

	fp = NULL;
	if (fudi.fd_newkey == NULL && !eap->forceit)
	{
	    emsg(_(e_dictionary_entry_already_exists));
	    goto erret;
	}
	if (fudi.fd_di == NULL)
	{
	    
	    if (value_check_lock(fudi.fd_dict->dv_lock, eap->arg, FALSE))
		goto erret;
	}
	    
	else if (value_check_lock(fudi.fd_di->di_tv.v_lock, eap->arg, FALSE))
	    goto erret;

	
	
	vim_free(name);
	sprintf(numbuf, "%d", ++func_nr);
	name = vim_strsave((char_u *)numbuf);
	if (name == NULL)
	    goto erret;
    }

    if (fp == NULL)
    {
	if (fudi.fd_dict == NULL && vim_strchr(name, AUTOLOAD_CHAR) != NULL)
	{
	    int	    slen, plen;
	    char_u  *scriptname;

	    
	    j = FAIL;
	    if (SOURCING_NAME != NULL)
	    {
		scriptname = autoload_name(name);
		if (scriptname != NULL)
		{
		    p = vim_strchr(scriptname, '/');
		    plen = (int)STRLEN(p);
		    slen = (int)STRLEN(SOURCING_NAME);
		    if (slen > plen && fnamecmp(p, SOURCING_NAME + slen - plen) == 0)
			j = OK;
		    vim_free(scriptname);
		}
	    }
	    if (j == FAIL)
	    {
		linenr_T save_lnum = SOURCING_LNUM;

		SOURCING_LNUM = sourcing_lnum_top;
		semsg(_(e_function_name_does_not_match_script_file_name_str), name);
		SOURCING_LNUM = save_lnum;
		goto erret;
	    }
	}

	fp = alloc_clear(offsetof(ufunc_T, uf_name) + STRLEN(name) + 1);
	if (fp == NULL)
	    goto erret;
	fp_allocated = TRUE;

	if (fudi.fd_dict != NULL)
	{
	    if (fudi.fd_di == NULL)
	    {
		
		fudi.fd_di = dictitem_alloc(fudi.fd_newkey);
		if (fudi.fd_di == NULL)
		{
		    vim_free(fp);
		    fp = NULL;
		    goto erret;
		}
		if (dict_add(fudi.fd_dict, fudi.fd_di) == FAIL)
		{
		    vim_free(fudi.fd_di);
		    vim_free(fp);
		    fp = NULL;
		    goto erret;
		}
	    }
	    else  clear_tv(&fudi.fd_di->di_tv);

	    fudi.fd_di->di_tv.v_type = VAR_FUNC;
	    fudi.fd_di->di_tv.vval.v_string = vim_strsave(name);

	    
	    flags |= FC_DICT;
	}
    }
    fp->uf_args = newargs;
    fp->uf_def_args = default_args;
    fp->uf_ret_type = &t_any;
    fp->uf_func_type = &t_func_any;

    if (eap->cmdidx == CMD_def)
    {
	int	    lnum_save = SOURCING_LNUM;
	cstack_T    *cstack = eap->cstack;

	fp->uf_def_status = UF_TO_BE_COMPILED;

	
	SOURCING_LNUM = sourcing_lnum_top;

	
	function_using_block_scopes(fp, cstack);

	if (parse_argument_types(fp, &argtypes, varargs) == FAIL)
	{
	    SOURCING_LNUM = lnum_save;
	    free_fp = fp_allocated;
	    goto erret;
	}
	varargs = FALSE;

	
	if (parse_return_type(fp, ret_type) == FAIL)
	{
	    SOURCING_LNUM = lnum_save;
	    free_fp = fp_allocated;
	    goto erret;
	}
	SOURCING_LNUM = lnum_save;
    }
    else fp->uf_def_status = UF_NOT_COMPILED;

    if (fp_allocated)
    {
	
	set_ufunc_name(fp, name);
	if (overwrite)
	{
	    hi = hash_find(&func_hashtab, name);
	    hi->hi_key = UF2HIKEY(fp);
	}
	else if (hash_add(&func_hashtab, UF2HIKEY(fp)) == FAIL)
	{
	    free_fp = TRUE;
	    goto erret;
	}
	fp->uf_refcount = 1;
    }

    fp->uf_lines = newlines;
    newlines.ga_data = NULL;
    if ((flags & FC_CLOSURE) != 0)
    {
	if (register_closure(fp) == FAIL)
	    goto erret;
    }
    else fp->uf_scoped = NULL;


    if (prof_def_func())
	func_do_profile(fp);

    fp->uf_varargs = varargs;
    if (sandbox)
	flags |= FC_SANDBOX;
    if (vim9script && !ASCII_ISUPPER(*fp->uf_name))
	flags |= FC_VIM9;
    fp->uf_flags = flags;
    fp->uf_calls = 0;
    fp->uf_cleared = FALSE;
    fp->uf_script_ctx = current_sctx;
    fp->uf_script_ctx_version = current_sctx.sc_version;
    fp->uf_script_ctx.sc_lnum += sourcing_lnum_top;
    if (is_export)
    {
	fp->uf_flags |= FC_EXPORT;
	
	is_export = FALSE;
    }

    if (eap->cmdidx == CMD_def)
	set_function_type(fp);
    else if (fp->uf_script_ctx.sc_version == SCRIPT_VERSION_VIM9)
	
	fp->uf_script_ctx.sc_version = SCRIPT_VERSION_MAX;

    goto ret_free;

erret:
    ga_clear_strings(&newargs);
    ga_clear_strings(&default_args);
    if (fp != NULL)
    {
	ga_init(&fp->uf_args);
	ga_init(&fp->uf_def_args);
    }
errret_2:
    ga_clear_strings(&newlines);
    if (fp != NULL)
	VIM_CLEAR(fp->uf_arg_types);
    if (free_fp)
    {
	vim_free(fp);
	fp = NULL;
    }
ret_free:
    ga_clear_strings(&argtypes);
    vim_free(fudi.fd_newkey);
    if (name != name_arg)
	vim_free(name);
    vim_free(ret_type);
    did_emsg |= saved_did_emsg;

    return fp;
}


    void ex_function(exarg_T *eap)
{
    char_u *line_to_free = NULL;

    (void)define_function(eap, NULL, &line_to_free);
    vim_free(line_to_free);
}


    void ex_defcompile(exarg_T *eap UNUSED)
{
    long	todo = (long)func_hashtab.ht_used;
    int		changed = func_hashtab.ht_changed;
    hashitem_T	*hi;
    ufunc_T	*ufunc;

    for (hi = func_hashtab.ht_array; todo > 0 && !got_int; ++hi)
    {
	if (!HASHITEM_EMPTY(hi))
	{
	    --todo;
	    ufunc = HI2UF(hi);
	    if (ufunc->uf_script_ctx.sc_sid == current_sctx.sc_sid && ufunc->uf_def_status == UF_TO_BE_COMPILED && (ufunc->uf_flags & FC_DEAD) == 0)

	    {
		(void)compile_def_function(ufunc, FALSE, CT_NONE, NULL);

		if (func_hashtab.ht_changed != changed)
		{
		    
		    todo = (long)func_hashtab.ht_used;
		    changed = func_hashtab.ht_changed;
		    hi = func_hashtab.ht_array;
		    --hi;
		}
	    }
	}
    }
}


    int eval_fname_script(char_u *p)
{
    
    
    if (p[0] == '<' && (MB_STRNICMP(p + 1, "SID>", 4) == 0 || MB_STRNICMP(p + 1, "SNR>", 4) == 0))
	return 5;
    if (p[0] == 's' && p[1] == ':')
	return 2;
    return 0;
}

    int translated_function_exists(char_u *name, int is_global)
{
    if (builtin_function(name, -1))
	return has_internal_func(name);
    return find_func(name, is_global, NULL) != NULL;
}


    int has_varargs(ufunc_T *ufunc)
{
    return ufunc->uf_varargs || ufunc->uf_va_name != NULL;
}


    int function_exists(char_u *name, int no_deref)
{
    char_u  *nm = name;
    char_u  *p;
    int	    n = FALSE;
    int	    flag;
    int	    is_global = FALSE;

    flag = TFN_INT | TFN_QUIET | TFN_NO_AUTOLOAD;
    if (no_deref)
	flag |= TFN_NO_DEREF;
    p = trans_function_name(&nm, &is_global, FALSE, flag, NULL, NULL, NULL);
    nm = skipwhite(nm);

    
    
    if (p != NULL && (*nm == NUL || *nm == '('))
	n = translated_function_exists(p, is_global);
    vim_free(p);
    return n;
}


    char_u * get_expanded_name(char_u *name, int check)
{
    char_u	*nm = name;
    char_u	*p;
    int		is_global = FALSE;

    p = trans_function_name(&nm, &is_global, FALSE, TFN_INT|TFN_QUIET, NULL, NULL, NULL);

    if (p != NULL && *nm == NUL && (!check || translated_function_exists(p, is_global)))
	return p;

    vim_free(p);
    return NULL;
}



    char_u * get_user_func_name(expand_T *xp, int idx)
{
    static long_u	done;
    static int		changed;
    static hashitem_T	*hi;
    ufunc_T		*fp;

    if (idx == 0)
    {
	done = 0;
	hi = func_hashtab.ht_array;
	changed = func_hashtab.ht_changed;
    }
    if (changed == func_hashtab.ht_changed && done < func_hashtab.ht_used)
    {
	if (done++ > 0)
	    ++hi;
	while (HASHITEM_EMPTY(hi))
	    ++hi;
	fp = HI2UF(hi);

	
	if ((fp->uf_flags & FC_DEAD) || (fp->uf_flags & FC_DICT)
				|| STRNCMP(fp->uf_name, "<lambda>", 8) == 0)
	    return (char_u *)"";

	if (STRLEN(fp->uf_name) + 4 >= IOSIZE)
	    return fp->uf_name;	

	cat_func_name(IObuff, fp);
	if (xp->xp_context != EXPAND_USER_FUNC && xp->xp_context != EXPAND_DISASSEMBLE)
	{
	    STRCAT(IObuff, "(");
	    if (!has_varargs(fp) && fp->uf_args.ga_len == 0)
		STRCAT(IObuff, ")");
	}
	return IObuff;
    }
    return NULL;
}


    void ex_delfunction(exarg_T *eap)
{
    ufunc_T	*fp = NULL;
    char_u	*p;
    char_u	*name;
    funcdict_T	fudi;
    int		is_global = FALSE;

    p = eap->arg;
    name = trans_function_name(&p, &is_global, eap->skip, 0, &fudi, NULL, NULL);
    vim_free(fudi.fd_newkey);
    if (name == NULL)
    {
	if (fudi.fd_dict != NULL && !eap->skip)
	    emsg(_(e_funcref_required));
	return;
    }
    if (!ends_excmd(*skipwhite(p)))
    {
	vim_free(name);
	semsg(_(e_trailing_characters_str), p);
	return;
    }
    set_nextcmd(eap, p);
    if (eap->nextcmd != NULL)
	*p = NUL;

    if (numbered_function(name) && fudi.fd_dict == NULL)
    {
	if (!eap->skip)
	    semsg(_(e_invalid_argument_str), eap->arg);
	vim_free(name);
	return;
    }
    if (!eap->skip)
	fp = find_func(name, is_global, NULL);
    vim_free(name);

    if (!eap->skip)
    {
	if (fp == NULL)
	{
	    if (!eap->forceit)
		semsg(_(e_unknown_function_str), eap->arg);
	    return;
	}
	if (fp->uf_calls > 0)
	{
	    semsg(_(e_cannot_delete_function_str_it_is_in_use), eap->arg);
	    return;
	}
	if (fp->uf_flags & FC_VIM9)
	{
	    semsg(_(e_cannot_delete_vim9_script_function_str), eap->arg);
	    return;
	}

	if (fudi.fd_dict != NULL)
	{
	    
	    
	    dictitem_remove(fudi.fd_dict, fudi.fd_di);
	}
	else {
	    
	    
	    
	    
	    
	    if (fp->uf_refcount > (func_name_refcount(fp->uf_name) ? 0 : 1))
	    {
		
		
		if (func_remove(fp))
		    fp->uf_refcount--;
	    }
	    else func_clear_free(fp, FALSE);
	}
    }
}


    void func_unref(char_u *name)
{
    ufunc_T *fp = NULL;

    if (name == NULL || !func_name_refcount(name))
	return;
    fp = find_func(name, FALSE, NULL);
    if (fp == NULL && numbered_function(name))
    {

	if (!entered_free_all_mem)

	    internal_error("func_unref()");
    }
    func_ptr_unref(fp);
}


    void func_ptr_unref(ufunc_T *fp)
{
    if (fp != NULL && (--fp->uf_refcount <= 0 || (fp->uf_refcount == 1 && fp->uf_partial != NULL && fp->uf_partial->pt_refcount <= 1 && fp->uf_partial->pt_func == fp)))


    {
	
	
	if (fp->uf_calls == 0)
	    func_clear_free(fp, FALSE);
    }
}


    void func_ref(char_u *name)
{
    ufunc_T *fp;

    if (name == NULL || !func_name_refcount(name))
	return;
    fp = find_func(name, FALSE, NULL);
    if (fp != NULL)
	++fp->uf_refcount;
    else if (numbered_function(name))
	
	
	internal_error("func_ref()");
}


    void func_ptr_ref(ufunc_T *fp)
{
    if (fp != NULL)
	++fp->uf_refcount;
}


    static int can_free_funccal(funccall_T *fc, int copyID)
{
    return (fc->l_varlist.lv_copyID != copyID && fc->l_vars.dv_copyID != copyID && fc->l_avars.dv_copyID != copyID && fc->fc_copyID != copyID);


}


    void ex_return(exarg_T *eap)
{
    char_u	*arg = eap->arg;
    typval_T	rettv;
    int		returning = FALSE;
    evalarg_T	evalarg;

    if (current_funccal == NULL)
    {
	emsg(_(e_return_not_inside_function));
	return;
    }

    init_evalarg(&evalarg);
    evalarg.eval_flags = eap->skip ? 0 : EVAL_EVALUATE;

    if (eap->skip)
	++emsg_skip;

    eap->nextcmd = NULL;
    if ((*arg != NUL && *arg != '|' && *arg != '\n')
				  && eval0(arg, &rettv, eap, &evalarg) != FAIL)
    {
	if (!eap->skip)
	    returning = do_return(eap, FALSE, TRUE, &rettv);
	else clear_tv(&rettv);
    }
    
    else if (!eap->skip)
    {
	
	update_force_abort();

	
	if (!aborting())
	    returning = do_return(eap, FALSE, TRUE, NULL);
    }

    
    
    
    if (returning)
	eap->nextcmd = NULL;
    else if (eap->nextcmd == NULL)	    
	set_nextcmd(eap, arg);

    if (eap->skip)
	--emsg_skip;
    clear_evalarg(&evalarg, eap);
}


    void ex_call(exarg_T *eap)
{
    char_u	*arg = eap->arg;
    char_u	*startarg;
    char_u	*name;
    char_u	*tofree;
    int		len;
    typval_T	rettv;
    linenr_T	lnum;
    int		doesrange;
    int		failed = FALSE;
    funcdict_T	fudi;
    partial_T	*partial = NULL;
    evalarg_T	evalarg;
    type_T	*type = NULL;
    int		found_var = FALSE;

    fill_evalarg_from_eap(&evalarg, eap, eap->skip);
    if (eap->skip)
    {
	
	
	
	++emsg_skip;
	if (eval0(eap->arg, &rettv, eap, &evalarg) != FAIL)
	    clear_tv(&rettv);
	--emsg_skip;
	clear_evalarg(&evalarg, eap);
	return;
    }

    tofree = trans_function_name(&arg, NULL, eap->skip, TFN_INT, &fudi, &partial, in_vim9script() ? &type : NULL);
    if (fudi.fd_newkey != NULL)
    {
	
	semsg(_(e_key_not_present_in_dictionary), fudi.fd_newkey);
	vim_free(fudi.fd_newkey);
    }
    if (tofree == NULL)
	return;

    
    
    if (fudi.fd_dict != NULL)
	++fudi.fd_dict->dv_refcount;

    
    
    
    len = (int)STRLEN(tofree);
    name = deref_func_name(tofree, &len, partial != NULL ? NULL : &partial, in_vim9script() && type == NULL ? &type : NULL, FALSE, &found_var);

    
    
    startarg = skipwhite(arg);
    if (*startarg != '(')
    {
	semsg(_(e_missing_parenthesis_str), eap->arg);
	goto end;
    }
    if (in_vim9script() && startarg > arg)
    {
	semsg(_(e_no_white_space_allowed_before_str_str), "(", eap->arg);
	goto end;
    }

    
    if (eap->skip)
    {
	++emsg_skip;
	lnum = eap->line2;	
    }
    else lnum = eap->line1;
    for ( ; lnum <= eap->line2; ++lnum)
    {
	funcexe_T funcexe;

	if (!eap->skip && eap->addr_count > 0)
	{
	    if (lnum > curbuf->b_ml.ml_line_count)
	    {
		
		
		emsg(_(e_invalid_range));
		break;
	    }
	    curwin->w_cursor.lnum = lnum;
	    curwin->w_cursor.col = 0;
	    curwin->w_cursor.coladd = 0;
	}
	arg = startarg;

	CLEAR_FIELD(funcexe);
	funcexe.fe_firstline = eap->line1;
	funcexe.fe_lastline = eap->line2;
	funcexe.fe_doesrange = &doesrange;
	funcexe.fe_evaluate = !eap->skip;
	funcexe.fe_partial = partial;
	funcexe.fe_selfdict = fudi.fd_dict;
	funcexe.fe_check_type = type;
	funcexe.fe_found_var = found_var;
	rettv.v_type = VAR_UNKNOWN;	
	if (get_func_tv(name, -1, &rettv, &arg, &evalarg, &funcexe) == FAIL)
	{
	    failed = TRUE;
	    break;
	}
	if (has_watchexpr())
	    dbg_check_breakpoint(eap);

	
	if (handle_subscript(&arg, NULL, &rettv, eap->skip ? NULL : &EVALARG_EVALUATE, TRUE) == FAIL)
	{
	    failed = TRUE;
	    break;
	}

	clear_tv(&rettv);
	if (doesrange || eap->skip)
	    break;

	
	
	
	
	if (aborting())
	    break;
    }
    if (eap->skip)
	--emsg_skip;
    clear_evalarg(&evalarg, eap);

    
    
    if ((!aborting() || did_throw)
				  && (!failed || eap->cstack->cs_trylevel > 0))
    {
	
	arg = skipwhite(arg);
	if (!ends_excmd2(eap->arg, arg))
	{
	    if (!failed && !aborting())
	    {
		emsg_severe = TRUE;
		semsg(_(e_trailing_characters_str), arg);
	    }
	}
	else set_nextcmd(eap, arg);
    }

end:
    dict_unref(fudi.fd_dict);
    vim_free(tofree);
}


    int do_return( exarg_T	*eap, int		reanimate, int		is_cmd, void	*rettv)




{
    int		idx;
    cstack_T	*cstack = eap->cstack;

    if (reanimate)
	
	current_funccal->returned = FALSE;

    
    idx = cleanup_conditionals(eap->cstack, 0, TRUE);
    if (idx >= 0)
    {
	cstack->cs_pending[idx] = CSTP_RETURN;

	if (!is_cmd && !reanimate)
	    
	    
	    
	    cstack->cs_rettv[idx] = rettv;
	else {
	    
	    
	    if (reanimate)
		rettv = current_funccal->rettv;

	    if (rettv != NULL)
	    {
		
		if ((cstack->cs_rettv[idx] = alloc_tv()) != NULL)
		    *(typval_T *)cstack->cs_rettv[idx] = *(typval_T *)rettv;
		else emsg(_(e_out_of_memory));
	    }
	    else cstack->cs_rettv[idx] = NULL;

	    if (reanimate)
	    {
		
		
		
		current_funccal->rettv->v_type = VAR_NUMBER;
		current_funccal->rettv->vval.v_number = 0;
	    }
	}
	report_make_pending(CSTP_RETURN, rettv);
    }
    else {
	current_funccal->returned = TRUE;

	
	
	
	if (!reanimate && rettv != NULL)
	{
	    clear_tv(current_funccal->rettv);
	    *current_funccal->rettv = *(typval_T *)rettv;
	    if (!is_cmd)
		vim_free(rettv);
	}
    }

    return idx < 0;
}


    void discard_pending_return(void *rettv)
{
    free_tv((typval_T *)rettv);
}


    char_u * get_return_cmd(void *rettv)
{
    char_u	*s = NULL;
    char_u	*tofree = NULL;
    char_u	numbuf[NUMBUFLEN];

    if (rettv != NULL)
	s = echo_string((typval_T *)rettv, &tofree, numbuf, 0);
    if (s == NULL)
	s = (char_u *)"";

    STRCPY(IObuff, ":return ");
    STRNCPY(IObuff + 8, s, IOSIZE - 8);
    if (STRLEN(s) + 8 >= IOSIZE)
	STRCPY(IObuff + IOSIZE - 4, "...");
    vim_free(tofree);
    return vim_strsave(IObuff);
}


    char_u * get_func_line( int	    c UNUSED, void    *cookie, int	    indent UNUSED, getline_opt_T options UNUSED)




{
    funccall_T	*fcp = (funccall_T *)cookie;
    ufunc_T	*fp = fcp->func;
    char_u	*retval;
    garray_T	*gap;  

    
    if (fcp->dbg_tick != debug_tick)
    {
	fcp->breakpoint = dbg_find_breakpoint(FALSE, fp->uf_name, SOURCING_LNUM);
	fcp->dbg_tick = debug_tick;
    }

    if (do_profiling == PROF_YES)
	func_line_end(cookie);


    gap = &fp->uf_lines;
    if (((fp->uf_flags & FC_ABORT) && did_emsg && !aborted_in_try())
	    || fcp->returned)
	retval = NULL;
    else {
	
	while (fcp->linenr < gap->ga_len && ((char_u **)(gap->ga_data))[fcp->linenr] == NULL)
	    ++fcp->linenr;
	if (fcp->linenr >= gap->ga_len)
	    retval = NULL;
	else {
	    retval = vim_strsave(((char_u **)(gap->ga_data))[fcp->linenr++]);
	    SOURCING_LNUM = fcp->linenr;

	    if (do_profiling == PROF_YES)
		func_line_start(cookie, SOURCING_LNUM);

	}
    }

    
    if (fcp->breakpoint != 0 && fcp->breakpoint <= SOURCING_LNUM)
    {
	dbg_breakpoint(fp->uf_name, SOURCING_LNUM);
	
	fcp->breakpoint = dbg_find_breakpoint(FALSE, fp->uf_name, SOURCING_LNUM);
	fcp->dbg_tick = debug_tick;
    }

    return retval;
}


    int func_has_ended(void *cookie)
{
    funccall_T  *fcp = (funccall_T *)cookie;

    
    
    return (((fcp->func->uf_flags & FC_ABORT) && did_emsg && !aborted_in_try())
	    || fcp->returned);
}


    int func_has_abort( void    *cookie)

{
    return ((funccall_T *)cookie)->func->uf_flags & FC_ABORT;
}



    dict_T * make_partial(dict_T *selfdict_in, typval_T *rettv)
{
    char_u	*fname;
    char_u	*tofree = NULL;
    ufunc_T	*fp;
    char_u	fname_buf[FLEN_FIXED + 1];
    int		error;
    dict_T	*selfdict = selfdict_in;

    if (rettv->v_type == VAR_PARTIAL && rettv->vval.v_partial->pt_func != NULL)
	fp = rettv->vval.v_partial->pt_func;
    else {
	fname = rettv->v_type == VAR_FUNC ? rettv->vval.v_string : rettv->vval.v_partial->pt_name;
	
	fname = fname_trans_sid(fname, fname_buf, &tofree, &error);
	fp = find_func(fname, FALSE, NULL);
	vim_free(tofree);
    }

    if (fp != NULL && (fp->uf_flags & FC_DICT))
    {
	partial_T	*pt = ALLOC_CLEAR_ONE(partial_T);

	if (pt != NULL)
	{
	    pt->pt_refcount = 1;
	    pt->pt_dict = selfdict;
	    pt->pt_auto = TRUE;
	    selfdict = NULL;
	    if (rettv->v_type == VAR_FUNC)
	    {
		
		
		pt->pt_name = rettv->vval.v_string;
	    }
	    else {
		partial_T	*ret_pt = rettv->vval.v_partial;
		int		i;

		
		
		
		if (ret_pt->pt_name != NULL)
		{
		    pt->pt_name = vim_strsave(ret_pt->pt_name);
		    func_ref(pt->pt_name);
		}
		else {
		    pt->pt_func = ret_pt->pt_func;
		    func_ptr_ref(pt->pt_func);
		}
		if (ret_pt->pt_argc > 0)
		{
		    pt->pt_argv = ALLOC_MULT(typval_T, ret_pt->pt_argc);
		    if (pt->pt_argv == NULL)
			
			pt->pt_argc = 0;
		    else {
			pt->pt_argc = ret_pt->pt_argc;
			for (i = 0; i < pt->pt_argc; i++)
			    copy_tv(&ret_pt->pt_argv[i], &pt->pt_argv[i]);
		    }
		}
		partial_unref(ret_pt);
	    }
	    rettv->v_type = VAR_PARTIAL;
	    rettv->vval.v_partial = pt;
	}
    }
    return selfdict;
}


    char_u * func_name(void *cookie)
{
    return ((funccall_T *)cookie)->func->uf_name;
}


    linenr_T * func_breakpoint(void *cookie)
{
    return &((funccall_T *)cookie)->breakpoint;
}


    int * func_dbg_tick(void *cookie)
{
    return &((funccall_T *)cookie)->dbg_tick;
}


    int func_level(void *cookie)
{
    return ((funccall_T *)cookie)->level;
}


    int current_func_returned(void)
{
    return current_funccal->returned;
}

    int free_unref_funccal(int copyID, int testing)
{
    int		did_free = FALSE;
    int		did_free_funccal = FALSE;
    funccall_T	*fc, **pfc;

    for (pfc = &previous_funccal; *pfc != NULL; )
    {
	if (can_free_funccal(*pfc, copyID))
	{
	    fc = *pfc;
	    *pfc = fc->caller;
	    free_funccal_contents(fc);
	    did_free = TRUE;
	    did_free_funccal = TRUE;
	}
	else pfc = &(*pfc)->caller;
    }
    if (did_free_funccal)
	
	
	(void)garbage_collect(testing);

    return did_free;
}


    static funccall_T * get_funccal(void)
{
    int		i;
    funccall_T	*funccal;
    funccall_T	*temp_funccal;

    funccal = current_funccal;
    if (debug_backtrace_level > 0)
    {
	for (i = 0; i < debug_backtrace_level; i++)
	{
	    temp_funccal = funccal->caller;
	    if (temp_funccal)
		funccal = temp_funccal;
	    else  debug_backtrace_level = i;

	}
    }
    return funccal;
}


    hashtab_T * get_funccal_local_ht()
{
    if (current_funccal == NULL || current_funccal->l_vars.dv_refcount == 0)
	return NULL;
    return &get_funccal()->l_vars.dv_hashtab;
}


    dictitem_T * get_funccal_local_var()
{
    if (current_funccal == NULL || current_funccal->l_vars.dv_refcount == 0)
	return NULL;
    return &get_funccal()->l_vars_var;
}


    hashtab_T * get_funccal_args_ht()
{
    if (current_funccal == NULL || current_funccal->l_vars.dv_refcount == 0)
	return NULL;
    return &get_funccal()->l_avars.dv_hashtab;
}


    dictitem_T * get_funccal_args_var()
{
    if (current_funccal == NULL || current_funccal->l_vars.dv_refcount == 0)
	return NULL;
    return &get_funccal()->l_avars_var;
}


    void list_func_vars(int *first)
{
    if (current_funccal != NULL && current_funccal->l_vars.dv_refcount > 0)
	list_hashtable_vars(&current_funccal->l_vars.dv_hashtab, "l:", FALSE, first);
}


    dict_T * get_current_funccal_dict(hashtab_T *ht)
{
    if (current_funccal != NULL && ht == &current_funccal->l_vars.dv_hashtab)
	return &current_funccal->l_vars;
    return NULL;
}


    hashitem_T * find_hi_in_scoped_ht(char_u *name, hashtab_T **pht)
{
    funccall_T	*old_current_funccal = current_funccal;
    hashtab_T	*ht;
    hashitem_T	*hi = NULL;
    char_u	*varname;

    if (current_funccal == NULL || current_funccal->func->uf_scoped == NULL)
      return NULL;

    
    current_funccal = current_funccal->func->uf_scoped;
    while (current_funccal != NULL)
    {
	ht = find_var_ht(name, &varname);
	if (ht != NULL && *varname != NUL)
	{
	    hi = hash_find(ht, varname);
	    if (!HASHITEM_EMPTY(hi))
	    {
		*pht = ht;
		break;
	    }
	}
	if (current_funccal == current_funccal->func->uf_scoped)
	    break;
	current_funccal = current_funccal->func->uf_scoped;
    }
    current_funccal = old_current_funccal;

    return hi;
}


    dictitem_T * find_var_in_scoped_ht(char_u *name, int no_autoload)
{
    dictitem_T	*v = NULL;
    funccall_T	*old_current_funccal = current_funccal;
    hashtab_T	*ht;
    char_u	*varname;

    if (current_funccal == NULL || current_funccal->func->uf_scoped == NULL)
	return NULL;

    
    current_funccal = current_funccal->func->uf_scoped;
    while (current_funccal)
    {
	ht = find_var_ht(name, &varname);
	if (ht != NULL && *varname != NUL)
	{
	    v = find_var_in_ht(ht, *name, varname, no_autoload);
	    if (v != NULL)
		break;
	}
	if (current_funccal == current_funccal->func->uf_scoped)
	    break;
	current_funccal = current_funccal->func->uf_scoped;
    }
    current_funccal = old_current_funccal;

    return v;
}


    int set_ref_in_previous_funccal(int copyID)
{
    funccall_T	*fc;

    for (fc = previous_funccal; fc != NULL; fc = fc->caller)
    {
	fc->fc_copyID = copyID + 1;
	if (set_ref_in_ht(&fc->l_vars.dv_hashtab, copyID + 1, NULL)
		|| set_ref_in_ht(&fc->l_avars.dv_hashtab, copyID + 1, NULL)
		|| set_ref_in_list_items(&fc->l_varlist, copyID + 1, NULL))
	    return TRUE;
    }
    return FALSE;
}

    static int set_ref_in_funccal(funccall_T *fc, int copyID)
{
    if (fc->fc_copyID != copyID)
    {
	fc->fc_copyID = copyID;
	if (set_ref_in_ht(&fc->l_vars.dv_hashtab, copyID, NULL)
		|| set_ref_in_ht(&fc->l_avars.dv_hashtab, copyID, NULL)
		|| set_ref_in_list_items(&fc->l_varlist, copyID, NULL)
		|| set_ref_in_func(NULL, fc->func, copyID))
	    return TRUE;
    }
    return FALSE;
}


    int set_ref_in_call_stack(int copyID)
{
    funccall_T		*fc;
    funccal_entry_T	*entry;

    for (fc = current_funccal; fc != NULL; fc = fc->caller)
	if (set_ref_in_funccal(fc, copyID))
	    return TRUE;

    
    for (entry = funccal_stack; entry != NULL; entry = entry->next)
	for (fc = entry->top_funccal; fc != NULL; fc = fc->caller)
	    if (set_ref_in_funccal(fc, copyID))
		return TRUE;
    return FALSE;
}


    int set_ref_in_functions(int copyID)
{
    int		todo;
    hashitem_T	*hi = NULL;
    ufunc_T	*fp;

    todo = (int)func_hashtab.ht_used;
    for (hi = func_hashtab.ht_array; todo > 0 && !got_int; ++hi)
    {
	if (!HASHITEM_EMPTY(hi))
	{
	    --todo;
	    fp = HI2UF(hi);
	    if (!func_name_refcount(fp->uf_name)
					  && set_ref_in_func(NULL, fp, copyID))
		return TRUE;
	}
    }
    return FALSE;
}


    int set_ref_in_func_args(int copyID)
{
    int i;

    for (i = 0; i < funcargs.ga_len; ++i)
	if (set_ref_in_item(((typval_T **)funcargs.ga_data)[i], copyID, NULL, NULL))
	    return TRUE;
    return FALSE;
}


    int set_ref_in_func(char_u *name, ufunc_T *fp_in, int copyID)
{
    ufunc_T	*fp = fp_in;
    funccall_T	*fc;
    int		error = FCERR_NONE;
    char_u	fname_buf[FLEN_FIXED + 1];
    char_u	*tofree = NULL;
    char_u	*fname;
    int		abort = FALSE;

    if (name == NULL && fp_in == NULL)
	return FALSE;

    if (fp_in == NULL)
    {
	fname = fname_trans_sid(name, fname_buf, &tofree, &error);
	fp = find_func(fname, FALSE, NULL);
    }
    if (fp != NULL)
    {
	for (fc = fp->uf_scoped; fc != NULL; fc = fc->func->uf_scoped)
	    abort = abort || set_ref_in_funccal(fc, copyID);
    }

    vim_free(tofree);
    return abort;
}


