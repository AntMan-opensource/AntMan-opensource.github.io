








typedef struct ff_stack {
    struct ff_stack	*ffs_prev;

    
    
    char_u		*ffs_fix_path;

    char_u		*ffs_wc_path;


    
    
    char_u		**ffs_filearray;
    int			ffs_filearray_size;
    char_u		ffs_filearray_cur;   

    
    
    
    int			ffs_stage;

    
    
    int			ffs_level;

    
    int			ffs_star_star_empty;
} ff_stack_T;


typedef struct ff_visited {
    struct ff_visited	*ffv_next;


    
    
    char_u		*ffv_wc_path;

    
    

    int			ffv_dev_valid;	
    dev_t		ffv_dev;	
    ino_t		ffv_ino;	

    
    
    char_u		ffv_fname[1];	
} ff_visited_T;


typedef struct ff_visited_list_hdr {
    struct ff_visited_list_hdr	*ffvl_next;

    
    char_u			*ffvl_filename;

    ff_visited_T		*ffvl_visited_list;

} ff_visited_list_hdr_T;






typedef struct ff_search_ctx_T {
     ff_stack_T			*ffsc_stack_ptr;
     ff_visited_list_hdr_T	*ffsc_visited_list;
     ff_visited_list_hdr_T	*ffsc_dir_visited_list;
     ff_visited_list_hdr_T	*ffsc_visited_lists_list;
     ff_visited_list_hdr_T	*ffsc_dir_visited_lists_list;
     char_u			*ffsc_file_to_search;
     char_u			*ffsc_start_dir;
     char_u			*ffsc_fix_path;

     char_u			*ffsc_wc_path;
     int			ffsc_level;
     char_u			**ffsc_stopdirs_v;

     int			ffsc_find_what;
     int			ffsc_tagfile;
} ff_search_ctx_T;



static int ff_check_visited(ff_visited_T **, char_u *, char_u *);

static int ff_check_visited(ff_visited_T **, char_u *);

static void vim_findfile_free_visited(void *search_ctx_arg);
static void vim_findfile_free_visited_list(ff_visited_list_hdr_T **list_headp);
static void ff_free_visited_list(ff_visited_T *vl);
static ff_visited_list_hdr_T* ff_get_visited_list(char_u *, ff_visited_list_hdr_T **list_headp);

static void ff_push(ff_search_ctx_T *search_ctx, ff_stack_T *stack_ptr);
static ff_stack_T *ff_pop(ff_search_ctx_T *search_ctx);
static void ff_clear(ff_search_ctx_T *search_ctx);
static void ff_free_stack_element(ff_stack_T *stack_ptr);

static ff_stack_T *ff_create_stack_element(char_u *, char_u *, int, int);

static ff_stack_T *ff_create_stack_element(char_u *, int, int);


static int ff_path_in_stoplist(char_u *, int, char_u **);


static char_u e_pathtoolong[] = N_("E854: path too long for completion");

static char_u	*ff_expand_buffer = NULL; 




static void *ff_fn_search_context = NULL;

    char_u * vim_findfirst(char_u *path, char_u *filename, int level)
{
    ff_fn_search_context = vim_findfile_init(path, filename, NULL, level, TRUE, FALSE, ff_fn_search_context, rel_fname);

    if (NULL == ff_fn_search_context)
	return NULL;
    else return vim_findnext()
}

    char_u * vim_findnext(void)
{
    char_u *ret = vim_findfile(ff_fn_search_context);

    if (NULL == ret)
    {
	vim_findfile_cleanup(ff_fn_search_context);
	ff_fn_search_context = NULL;
    }
    return ret;
}



    void * vim_findfile_init( char_u	*path, char_u	*filename, char_u	*stopdirs UNUSED, int		level, int		free_visited, int		find_what, void	*search_ctx_arg, int		tagfile, char_u	*rel_fname)









{

    char_u		*wc_part;

    ff_stack_T		*sptr;
    ff_search_ctx_T	*search_ctx;

    
    
    if (search_ctx_arg != NULL)
	search_ctx = search_ctx_arg;
    else {
	search_ctx = ALLOC_CLEAR_ONE(ff_search_ctx_T);
	if (search_ctx == NULL)
	    goto error_return;
    }
    search_ctx->ffsc_find_what = find_what;
    search_ctx->ffsc_tagfile = tagfile;

    
    ff_clear(search_ctx);

    
    if (free_visited == TRUE)
	vim_findfile_free_visited(search_ctx);
    else {
	
	
	
	search_ctx->ffsc_visited_list = ff_get_visited_list(filename, &search_ctx->ffsc_visited_lists_list);
	if (search_ctx->ffsc_visited_list == NULL)
	    goto error_return;
	search_ctx->ffsc_dir_visited_list = ff_get_visited_list(filename, &search_ctx->ffsc_dir_visited_lists_list);
	if (search_ctx->ffsc_dir_visited_list == NULL)
	    goto error_return;
    }

    if (ff_expand_buffer == NULL)
    {
	ff_expand_buffer = alloc(MAXPATHL);
	if (ff_expand_buffer == NULL)
	    goto error_return;
    }

    
    
    if (path[0] == '.' && (vim_ispathsep(path[1]) || path[1] == NUL)
	    && (!tagfile || vim_strchr(p_cpo, CPO_DOTTAG) == NULL)
	    && rel_fname != NULL)
    {
	int	len = (int)(gettail(rel_fname) - rel_fname);

	if (!vim_isAbsName(rel_fname) && len + 1 < MAXPATHL)
	{
	    
	    vim_strncpy(ff_expand_buffer, rel_fname, len);
	    search_ctx->ffsc_start_dir = FullName_save(ff_expand_buffer, FALSE);
	}
	else search_ctx->ffsc_start_dir = vim_strnsave(rel_fname, len);
	if (search_ctx->ffsc_start_dir == NULL)
	    goto error_return;
	if (*++path != NUL)
	    ++path;
    }
    else if (*path == NUL || !vim_isAbsName(path))
    {

	
	if (*path != NUL && path[1] == ':')
	{
	    char_u  drive[3];

	    drive[0] = path[0];
	    drive[1] = ':';
	    drive[2] = NUL;
	    if (vim_FullName(drive, ff_expand_buffer, MAXPATHL, TRUE) == FAIL)
		goto error_return;
	    path += 2;
	}
	else  if (mch_dirname(ff_expand_buffer, MAXPATHL) == FAIL)

	    goto error_return;

	search_ctx->ffsc_start_dir = vim_strsave(ff_expand_buffer);
	if (search_ctx->ffsc_start_dir == NULL)
	    goto error_return;


	
	
	if ((*path == '/' || *path == '\\')
		&& path[1] != path[0] && search_ctx->ffsc_start_dir[1] == ':')
	    search_ctx->ffsc_start_dir[2] = NUL;

    }


    
    if (stopdirs != NULL)
    {
	char_u	*walker = stopdirs;
	int	dircount;

	while (*walker == ';')
	    walker++;

	dircount = 1;
	search_ctx->ffsc_stopdirs_v = ALLOC_ONE(char_u *);

	if (search_ctx->ffsc_stopdirs_v != NULL)
	{
	    do {
		char_u	*helper;
		void	*ptr;

		helper = walker;
		ptr = vim_realloc(search_ctx->ffsc_stopdirs_v, (dircount + 1) * sizeof(char_u *));
		if (ptr)
		    search_ctx->ffsc_stopdirs_v = ptr;
		else  break;

		walker = vim_strchr(walker, ';');
		if (walker)
		{
		    search_ctx->ffsc_stopdirs_v[dircount-1] = vim_strnsave(helper, walker - helper);
		    walker++;
		}
		else   search_ctx->ffsc_stopdirs_v[dircount-1] = vim_strsave(helper);




		dircount++;

	    } while (walker != NULL);
	    search_ctx->ffsc_stopdirs_v[dircount-1] = NULL;
	}
    }



    search_ctx->ffsc_level = level;

    
    wc_part = vim_strchr(path, '*');
    if (wc_part != NULL)
    {
	int	llevel;
	int	len;
	char	*errpt;

	
	search_ctx->ffsc_fix_path = vim_strnsave(path, wc_part - path);

	
	len = 0;
	while (*wc_part != NUL)
	{
	    if (len + 5 >= MAXPATHL)
	    {
		emsg(_(e_pathtoolong));
		break;
	    }
	    if (STRNCMP(wc_part, "**", 2) == 0)
	    {
		ff_expand_buffer[len++] = *wc_part++;
		ff_expand_buffer[len++] = *wc_part++;

		llevel = strtol((char *)wc_part, &errpt, 10);
		if ((char_u *)errpt != wc_part && llevel > 0 && llevel < 255)
		    ff_expand_buffer[len++] = llevel;
		else if ((char_u *)errpt != wc_part && llevel == 0)
		    
		    len -= 2;
		else ff_expand_buffer[len++] = FF_MAX_STAR_STAR_EXPAND;
		wc_part = (char_u *)errpt;
		if (*wc_part != NUL && !vim_ispathsep(*wc_part))
		{
		    semsg(_("E343: Invalid path: '**[number]' must be at the end of the path or be followed by '%s'."), PATHSEPSTR);
		    goto error_return;
		}
	    }
	    else ff_expand_buffer[len++] = *wc_part++;
	}
	ff_expand_buffer[len] = NUL;
	search_ctx->ffsc_wc_path = vim_strsave(ff_expand_buffer);

	if (search_ctx->ffsc_wc_path == NULL)
	    goto error_return;
    }
    else  search_ctx->ffsc_fix_path = vim_strsave(path);


    if (search_ctx->ffsc_start_dir == NULL)
    {
	
	
	search_ctx->ffsc_start_dir = vim_strsave(search_ctx->ffsc_fix_path);
	if (search_ctx->ffsc_start_dir == NULL)
	    goto error_return;
	search_ctx->ffsc_fix_path[0] = NUL;
    }

    
    if (STRLEN(search_ctx->ffsc_start_dir)
			  + STRLEN(search_ctx->ffsc_fix_path) + 3 >= MAXPATHL)
    {
	emsg(_(e_pathtoolong));
	goto error_return;
    }
    STRCPY(ff_expand_buffer, search_ctx->ffsc_start_dir);
    add_pathsep(ff_expand_buffer);
    {
	int    eb_len = (int)STRLEN(ff_expand_buffer);
	char_u *buf = alloc(eb_len + (int)STRLEN(search_ctx->ffsc_fix_path) + 1);

	STRCPY(buf, ff_expand_buffer);
	STRCPY(buf + eb_len, search_ctx->ffsc_fix_path);
	if (mch_isdir(buf))
	{
	    STRCAT(ff_expand_buffer, search_ctx->ffsc_fix_path);
	    add_pathsep(ff_expand_buffer);
	}

	else {
	    char_u *p =  gettail(search_ctx->ffsc_fix_path);
	    char_u *wc_path = NULL;
	    char_u *temp = NULL;
	    int    len = 0;

	    if (p > search_ctx->ffsc_fix_path)
	    {
		
		len = (int)(p - search_ctx->ffsc_fix_path) - 1;
		if ((len >= 2 && STRNCMP(search_ctx->ffsc_fix_path, "..", 2) == 0)
			&& (len == 2 || search_ctx->ffsc_fix_path[2] == PATHSEP))
		{
		    vim_free(buf);
		    goto error_return;
		}
		STRNCAT(ff_expand_buffer, search_ctx->ffsc_fix_path, len);
		add_pathsep(ff_expand_buffer);
	    }
	    else len = (int)STRLEN(search_ctx->ffsc_fix_path);

	    if (search_ctx->ffsc_wc_path != NULL)
	    {
		wc_path = vim_strsave(search_ctx->ffsc_wc_path);
		temp = alloc(STRLEN(search_ctx->ffsc_wc_path)
				 + STRLEN(search_ctx->ffsc_fix_path + len)
				 + 1);
		if (temp == NULL || wc_path == NULL)
		{
		    vim_free(buf);
		    vim_free(temp);
		    vim_free(wc_path);
		    goto error_return;
		}

		STRCPY(temp, search_ctx->ffsc_fix_path + len);
		STRCAT(temp, search_ctx->ffsc_wc_path);
		vim_free(search_ctx->ffsc_wc_path);
		vim_free(wc_path);
		search_ctx->ffsc_wc_path = temp;
	    }
	}

	vim_free(buf);
    }

    sptr = ff_create_stack_element(ff_expand_buffer,  search_ctx->ffsc_wc_path,  level, 0);




    if (sptr == NULL)
	goto error_return;

    ff_push(search_ctx, sptr);

    search_ctx->ffsc_file_to_search = vim_strsave(filename);
    if (search_ctx->ffsc_file_to_search == NULL)
	goto error_return;

    return search_ctx;

error_return:
    
    vim_findfile_cleanup(search_ctx);
    return NULL;
}



    char_u * vim_findfile_stopdir(char_u *buf)
{
    char_u	*r_ptr = buf;

    while (*r_ptr != NUL && *r_ptr != ';')
    {
	if (r_ptr[0] == '\\' && r_ptr[1] == ';')
	{
	    
	    
	    STRMOVE(r_ptr, r_ptr + 1);
	    r_ptr++;
	}
	r_ptr++;
    }
    if (*r_ptr == ';')
    {
	*r_ptr = 0;
	r_ptr++;
    }
    else if (*r_ptr == NUL)
	r_ptr = NULL;
    return r_ptr;
}



    void vim_findfile_cleanup(void *ctx)
{
    if (ctx == NULL)
	return;

    vim_findfile_free_visited(ctx);
    ff_clear(ctx);
    vim_free(ctx);
}


    char_u * vim_findfile(void *search_ctx_arg)
{
    char_u	*file_path;

    char_u	*rest_of_wildcards;
    char_u	*path_end = NULL;

    ff_stack_T	*stackp;

    int		len;

    int		i;
    char_u	*p;

    char_u	*suf;

    ff_search_ctx_T *search_ctx;

    if (search_ctx_arg == NULL)
	return NULL;

    search_ctx = (ff_search_ctx_T *)search_ctx_arg;

    
    if ((file_path = alloc(MAXPATHL)) == NULL)
	return NULL;


    
    if (search_ctx->ffsc_start_dir != NULL)
	path_end = &search_ctx->ffsc_start_dir[ STRLEN(search_ctx->ffsc_start_dir)];



    
    for (;;)
    {

	
	for (;;)
	{
	    
	    ui_breakcheck();
	    if (got_int)
		break;

	    
	    stackp = ff_pop(search_ctx);
	    if (stackp == NULL)
		break;

	    
	    if (stackp->ffs_filearray == NULL && ff_check_visited(&search_ctx->ffsc_dir_visited_list ->ffvl_visited_list, stackp->ffs_fix_path  , stackp->ffs_wc_path  ) == FAIL)






	    {

		if (p_verbose >= 5)
		{
		    verbose_enter_scroll();
		    smsg("Already Searched: %s (%s)", stackp->ffs_fix_path, stackp->ffs_wc_path);
		    
		    msg_puts("\n");
		    verbose_leave_scroll();
		}

		ff_free_stack_element(stackp);
		continue;
	    }

	    else if (p_verbose >= 5)
	    {
		verbose_enter_scroll();
		smsg("Searching: %s (%s)", stackp->ffs_fix_path, stackp->ffs_wc_path);
		
		msg_puts("\n");
		verbose_leave_scroll();
	    }


	    
	    if (stackp->ffs_level <= 0)
	    {
		ff_free_stack_element(stackp);
		continue;
	    }

	    file_path[0] = NUL;

	    
	    if (stackp->ffs_filearray == NULL)
	    {
		char_u *dirptrs[2];

		
		
		dirptrs[0] = file_path;
		dirptrs[1] = NULL;

		
		if (!vim_isAbsName(stackp->ffs_fix_path)
						&& search_ctx->ffsc_start_dir)
		{
		    if (STRLEN(search_ctx->ffsc_start_dir) + 1 < MAXPATHL)
		    {
			STRCPY(file_path, search_ctx->ffsc_start_dir);
			add_pathsep(file_path);
		    }
		    else {
			ff_free_stack_element(stackp);
			goto fail;
		    }
		}

		
		if (STRLEN(file_path) + STRLEN(stackp->ffs_fix_path) + 1 < MAXPATHL)
		{
		    STRCAT(file_path, stackp->ffs_fix_path);
		    add_pathsep(file_path);
		}
		else {
		    ff_free_stack_element(stackp);
		    goto fail;
		}


		rest_of_wildcards = stackp->ffs_wc_path;
		if (*rest_of_wildcards != NUL)
		{
		    len = (int)STRLEN(file_path);
		    if (STRNCMP(rest_of_wildcards, "**", 2) == 0)
		    {
			
			
			p = rest_of_wildcards + 2;

			if (*p > 0)
			{
			    (*p)--;
			    if (len + 1 < MAXPATHL)
				file_path[len++] = '*';
			    else {
				ff_free_stack_element(stackp);
				goto fail;
			    }
			}

			if (*p == 0)
			{
			    
			    STRMOVE(rest_of_wildcards, rest_of_wildcards + 3);
			}
			else rest_of_wildcards += 3;

			if (stackp->ffs_star_star_empty == 0)
			{
			    
			    stackp->ffs_star_star_empty = 1;
			    dirptrs[1] = stackp->ffs_fix_path;
			}
		    }

		    
		    while (*rest_of_wildcards && !vim_ispathsep(*rest_of_wildcards))
			if (len + 1 < MAXPATHL)
			    file_path[len++] = *rest_of_wildcards++;
			else {
			    ff_free_stack_element(stackp);
			    goto fail;
			}

		    file_path[len] = NUL;
		    if (vim_ispathsep(*rest_of_wildcards))
			rest_of_wildcards++;
		}


		
		if (path_with_url(dirptrs[0]))
		{
		    stackp->ffs_filearray = ALLOC_ONE(char_u *);
		    if (stackp->ffs_filearray != NULL && (stackp->ffs_filearray[0] = vim_strsave(dirptrs[0])) != NULL)

			stackp->ffs_filearray_size = 1;
		    else stackp->ffs_filearray_size = 0;
		}
		else    expand_wildcards((dirptrs[1] == NULL) ? 1 : 2, dirptrs, &stackp->ffs_filearray_size, &stackp->ffs_filearray, EW_DIR|EW_ADDSLASH|EW_SILENT|EW_NOTWILD);







		stackp->ffs_filearray_cur = 0;
		stackp->ffs_stage = 0;
	    }

	    else rest_of_wildcards = &stackp->ffs_wc_path[ STRLEN(stackp->ffs_wc_path)];



	    if (stackp->ffs_stage == 0)
	    {
		

		if (*rest_of_wildcards == NUL)

		{
		    
		    for (i = stackp->ffs_filearray_cur;
					  i < stackp->ffs_filearray_size; ++i)
		    {
			if (!path_with_url(stackp->ffs_filearray[i])
				      && !mch_isdir(stackp->ffs_filearray[i]))
			    continue;   

			
			
			if (STRLEN(stackp->ffs_filearray[i]) + 1 + STRLEN(search_ctx->ffsc_file_to_search)
								    < MAXPATHL)
			{
			    STRCPY(file_path, stackp->ffs_filearray[i]);
			    add_pathsep(file_path);
			    STRCAT(file_path, search_ctx->ffsc_file_to_search);
			}
			else {
			    ff_free_stack_element(stackp);
			    goto fail;
			}

			

			len = (int)STRLEN(file_path);
			if (search_ctx->ffsc_tagfile)
			    suf = (char_u *)"";
			else suf = curbuf->b_p_sua;
			for (;;)

			{
			    
			    if ((path_with_url(file_path)
				  || (mch_getperm(file_path) >= 0 && (search_ctx->ffsc_find_what == FINDFILE_BOTH || ((search_ctx->ffsc_find_what == FINDFILE_DIR)



						   == mch_isdir(file_path)))))

				    && (ff_check_visited( &search_ctx->ffsc_visited_list->ffvl_visited_list, file_path  , (char_u *)""  ) == OK)






			       )
			    {

				if (ff_check_visited( &search_ctx->ffsc_visited_list->ffvl_visited_list, file_path  , (char_u *)""  ) == FAIL)





				{
				    if (p_verbose >= 5)
				    {
					verbose_enter_scroll();
					smsg("Already: %s", file_path);
					
					msg_puts("\n");
					verbose_leave_scroll();
				    }
				    continue;
				}


				
				stackp->ffs_filearray_cur = i + 1;
				ff_push(search_ctx, stackp);

				if (!path_with_url(file_path))
				    simplify_filename(file_path);
				if (mch_dirname(ff_expand_buffer, MAXPATHL)
									== OK)
				{
				    p = shorten_fname(file_path, ff_expand_buffer);
				    if (p != NULL)
					STRMOVE(file_path, p);
				}

				if (p_verbose >= 5)
				{
				    verbose_enter_scroll();
				    smsg("HIT: %s", file_path);
				    
				    msg_puts("\n");
				    verbose_leave_scroll();
				}

				return file_path;
			    }


			    
			    if (*suf == NUL)
				break;
			    copy_option_part(&suf, file_path + len, MAXPATHL - len, ",");

			}
		    }
		}

		else {
		    
		    for (i = stackp->ffs_filearray_cur;
					  i < stackp->ffs_filearray_size; ++i)
		    {
			if (!mch_isdir(stackp->ffs_filearray[i]))
			    continue;	

			ff_push(search_ctx, ff_create_stack_element( stackp->ffs_filearray[i], rest_of_wildcards, stackp->ffs_level - 1, 0));



		    }
		}

		stackp->ffs_filearray_cur = 0;
		stackp->ffs_stage = 1;
	    }


	    
	    if (STRNCMP(stackp->ffs_wc_path, "**", 2) == 0)
	    {
		for (i = stackp->ffs_filearray_cur;
					  i < stackp->ffs_filearray_size; ++i)
		{
		    if (fnamecmp(stackp->ffs_filearray[i], stackp->ffs_fix_path) == 0)
			continue; 
		    if (!mch_isdir(stackp->ffs_filearray[i]))
			continue;   
		    ff_push(search_ctx, ff_create_stack_element(stackp->ffs_filearray[i], stackp->ffs_wc_path, stackp->ffs_level - 1, 1));

		}
	    }


	    
	    ff_free_stack_element(stackp);

	}


	
	
	if (search_ctx->ffsc_start_dir && search_ctx->ffsc_stopdirs_v != NULL && !got_int)
	{
	    ff_stack_T  *sptr;

	    
	    if (ff_path_in_stoplist(search_ctx->ffsc_start_dir, (int)(path_end - search_ctx->ffsc_start_dir), search_ctx->ffsc_stopdirs_v) == TRUE)

		break;

	    
	    while (path_end > search_ctx->ffsc_start_dir && vim_ispathsep(*path_end))
		path_end--;
	    while (path_end > search_ctx->ffsc_start_dir && !vim_ispathsep(path_end[-1]))
		path_end--;
	    *path_end = 0;
	    path_end--;

	    if (*search_ctx->ffsc_start_dir == 0)
		break;

	    if (STRLEN(search_ctx->ffsc_start_dir) + 1 + STRLEN(search_ctx->ffsc_fix_path) < MAXPATHL)
	    {
		STRCPY(file_path, search_ctx->ffsc_start_dir);
		add_pathsep(file_path);
		STRCAT(file_path, search_ctx->ffsc_fix_path);
	    }
	    else goto fail;

	    
	    sptr = ff_create_stack_element(file_path, search_ctx->ffsc_wc_path, search_ctx->ffsc_level, 0);
	    if (sptr == NULL)
		break;
	    ff_push(search_ctx, sptr);
	}
	else break;
    }


fail:
    vim_free(file_path);
    return NULL;
}


    static void vim_findfile_free_visited(void *search_ctx_arg)
{
    ff_search_ctx_T *search_ctx;

    if (search_ctx_arg == NULL)
	return;

    search_ctx = (ff_search_ctx_T *)search_ctx_arg;
    vim_findfile_free_visited_list(&search_ctx->ffsc_visited_lists_list);
    vim_findfile_free_visited_list(&search_ctx->ffsc_dir_visited_lists_list);
}

    static void vim_findfile_free_visited_list(ff_visited_list_hdr_T **list_headp)
{
    ff_visited_list_hdr_T *vp;

    while (*list_headp != NULL)
    {
	vp = (*list_headp)->ffvl_next;
	ff_free_visited_list((*list_headp)->ffvl_visited_list);

	vim_free((*list_headp)->ffvl_filename);
	vim_free(*list_headp);
	*list_headp = vp;
    }
    *list_headp = NULL;
}

    static void ff_free_visited_list(ff_visited_T *vl)
{
    ff_visited_T *vp;

    while (vl != NULL)
    {
	vp = vl->ffv_next;

	vim_free(vl->ffv_wc_path);

	vim_free(vl);
	vl = vp;
    }
    vl = NULL;
}


    static ff_visited_list_hdr_T* ff_get_visited_list( char_u			*filename, ff_visited_list_hdr_T	**list_headp)


{
    ff_visited_list_hdr_T  *retptr = NULL;

    
    if (*list_headp != NULL)
    {
	retptr = *list_headp;
	while (retptr != NULL)
	{
	    if (fnamecmp(filename, retptr->ffvl_filename) == 0)
	    {

		if (p_verbose >= 5)
		{
		    verbose_enter_scroll();
		    smsg("ff_get_visited_list: FOUND list for %s", filename);
		    
		    msg_puts("\n");
		    verbose_leave_scroll();
		}

		return retptr;
	    }
	    retptr = retptr->ffvl_next;
	}
    }


    if (p_verbose >= 5)
    {
	verbose_enter_scroll();
	smsg("ff_get_visited_list: new list for %s", filename);
	
	msg_puts("\n");
	verbose_leave_scroll();
    }


    
    retptr = ALLOC_ONE(ff_visited_list_hdr_T);
    if (retptr == NULL)
	return NULL;

    retptr->ffvl_visited_list = NULL;
    retptr->ffvl_filename = vim_strsave(filename);
    if (retptr->ffvl_filename == NULL)
    {
	vim_free(retptr);
	return NULL;
    }
    retptr->ffvl_next = *list_headp;
    *list_headp = retptr;

    return retptr;
}



    static int ff_wc_equal(char_u *s1, char_u *s2)
{
    int		i, j;
    int		c1 = NUL;
    int		c2 = NUL;
    int		prev1 = NUL;
    int		prev2 = NUL;

    if (s1 == s2)
	return TRUE;

    if (s1 == NULL || s2 == NULL)
	return FALSE;

    for (i = 0, j = 0; s1[i] != NUL && s2[j] != NUL;)
    {
	c1 = PTR2CHAR(s1 + i);
	c2 = PTR2CHAR(s2 + j);

	if ((p_fic ? MB_TOLOWER(c1) != MB_TOLOWER(c2) : c1 != c2)
		&& (prev1 != '*' || prev2 != '*'))
	    return FALSE;
	prev2 = prev1;
	prev1 = c1;

	i += mb_ptr2len(s1 + i);
	j += mb_ptr2len(s2 + j);
    }
    return s1[i] == s2[j];
}



    static int ff_check_visited( ff_visited_T	**visited_list, char_u		*fname  , char_u		*wc_path  )






{
    ff_visited_T	*vp;

    stat_T		st;
    int			url = FALSE;


    
    
    if (path_with_url(fname))
    {
	vim_strncpy(ff_expand_buffer, fname, MAXPATHL - 1);

	url = TRUE;

    }
    else {
	ff_expand_buffer[0] = NUL;

	if (mch_stat((char *)fname, &st) < 0)

	if (vim_FullName(fname, ff_expand_buffer, MAXPATHL, TRUE) == FAIL)

	    return FAIL;
    }

    
    for (vp = *visited_list; vp != NULL; vp = vp->ffv_next)
    {
	if (  !url ? (vp->ffv_dev_valid && vp->ffv_dev == st.st_dev && vp->ffv_ino == st.st_ino)


		     :

		fnamecmp(vp->ffv_fname, ff_expand_buffer) == 0 )
	{

	    
	    if (ff_wc_equal(vp->ffv_wc_path, wc_path) == TRUE)

		
		return FAIL;
	}
    }

    
    vp = alloc(sizeof(ff_visited_T) + STRLEN(ff_expand_buffer));

    if (vp != NULL)
    {

	if (!url)
	{
	    vp->ffv_dev_valid = TRUE;
	    vp->ffv_ino = st.st_ino;
	    vp->ffv_dev = st.st_dev;
	    vp->ffv_fname[0] = NUL;
	}
	else {
	    vp->ffv_dev_valid = FALSE;

	    STRCPY(vp->ffv_fname, ff_expand_buffer);

	}


	if (wc_path != NULL)
	    vp->ffv_wc_path = vim_strsave(wc_path);
	else vp->ffv_wc_path = NULL;


	vp->ffv_next = *visited_list;
	*visited_list = vp;
    }

    return OK;
}


    static ff_stack_T * ff_create_stack_element( char_u	*fix_part,  char_u	*wc_part,  int		level, int		star_star_empty)






{
    ff_stack_T	*new;

    new = ALLOC_ONE(ff_stack_T);
    if (new == NULL)
	return NULL;

    new->ffs_prev	   = NULL;
    new->ffs_filearray	   = NULL;
    new->ffs_filearray_size = 0;
    new->ffs_filearray_cur  = 0;
    new->ffs_stage	   = 0;
    new->ffs_level	   = level;
    new->ffs_star_star_empty = star_star_empty;

    
    if (fix_part == NULL)
	fix_part = (char_u *)"";
    new->ffs_fix_path = vim_strsave(fix_part);


    if (wc_part == NULL)
	wc_part  = (char_u *)"";
    new->ffs_wc_path = vim_strsave(wc_part);


    if (new->ffs_fix_path == NULL  || new->ffs_wc_path == NULL  )



    {
	ff_free_stack_element(new);
	new = NULL;
    }

    return new;
}


    static void ff_push(ff_search_ctx_T *search_ctx, ff_stack_T *stack_ptr)
{
    
    
    if (stack_ptr != NULL)
    {
	stack_ptr->ffs_prev = search_ctx->ffsc_stack_ptr;
	search_ctx->ffsc_stack_ptr = stack_ptr;
    }
}


    static ff_stack_T * ff_pop(ff_search_ctx_T *search_ctx)
{
    ff_stack_T  *sptr;

    sptr = search_ctx->ffsc_stack_ptr;
    if (search_ctx->ffsc_stack_ptr != NULL)
	search_ctx->ffsc_stack_ptr = search_ctx->ffsc_stack_ptr->ffs_prev;

    return sptr;
}


    static void ff_free_stack_element(ff_stack_T *stack_ptr)
{
    
    vim_free(stack_ptr->ffs_fix_path);

    vim_free(stack_ptr->ffs_wc_path);


    if (stack_ptr->ffs_filearray != NULL)
	FreeWild(stack_ptr->ffs_filearray_size, stack_ptr->ffs_filearray);

    vim_free(stack_ptr);
}


    static void ff_clear(ff_search_ctx_T *search_ctx)
{
    ff_stack_T   *sptr;

    
    while ((sptr = ff_pop(search_ctx)) != NULL)
	ff_free_stack_element(sptr);

    vim_free(search_ctx->ffsc_file_to_search);
    vim_free(search_ctx->ffsc_start_dir);
    vim_free(search_ctx->ffsc_fix_path);

    vim_free(search_ctx->ffsc_wc_path);



    if (search_ctx->ffsc_stopdirs_v != NULL)
    {
	int  i = 0;

	while (search_ctx->ffsc_stopdirs_v[i] != NULL)
	{
	    vim_free(search_ctx->ffsc_stopdirs_v[i]);
	    i++;
	}
	vim_free(search_ctx->ffsc_stopdirs_v);
    }
    search_ctx->ffsc_stopdirs_v = NULL;


    
    search_ctx->ffsc_file_to_search = NULL;
    search_ctx->ffsc_start_dir = NULL;
    search_ctx->ffsc_fix_path = NULL;

    search_ctx->ffsc_wc_path = NULL;
    search_ctx->ffsc_level = 0;

}



    static int ff_path_in_stoplist(char_u *path, int path_len, char_u **stopdirs_v)
{
    int		i = 0;

    
    while (path_len > 1 && vim_ispathsep(path[path_len - 1]))
	path_len--;

    
    if (path_len == 0)
	return TRUE;

    for (i = 0; stopdirs_v[i] != NULL; i++)
    {
	if ((int)STRLEN(stopdirs_v[i]) > path_len)
	{
	    
	    
	    
	    if (fnamencmp(stopdirs_v[i], path, path_len) == 0 && vim_ispathsep(stopdirs_v[i][path_len]))
		return TRUE;
	}
	else {
	    if (fnamecmp(stopdirs_v[i], path) == 0)
		return TRUE;
	}
    }
    return FALSE;
}




    char_u * find_file_in_path( char_u	*ptr, int		len, int		options, int		first, char_u	*rel_fname)





{
    return find_file_in_path_option(ptr, len, options, first, *curbuf->b_p_path == NUL ? p_path : curbuf->b_p_path, FINDFILE_BOTH, rel_fname, curbuf->b_p_sua);

}

static char_u	*ff_file_to_find = NULL;
static void	*fdip_search_ctx = NULL;


    void free_findfile(void)
{
    vim_free(ff_file_to_find);
    vim_findfile_cleanup(fdip_search_ctx);
    vim_free(ff_expand_buffer);
}



    char_u * find_directory_in_path( char_u	*ptr, int		len, int		options, char_u	*rel_fname)




{
    return find_file_in_path_option(ptr, len, options, TRUE, p_cdpath, FINDFILE_DIR, rel_fname, (char_u *)"");
}

    char_u * find_file_in_path_option( char_u	*ptr, int		len, int		options, int		first, char_u	*path_option, int		find_what, char_u	*rel_fname, char_u	*suffixes)








{
    static char_u	*dir;
    static int		did_findfile_init = FALSE;
    char_u		save_char;
    char_u		*file_name = NULL;
    char_u		*buf = NULL;
    int			rel_to_curdir;

    struct Process	*proc = (struct Process *)FindTask(0L);
    APTR		save_winptr = proc->pr_WindowPtr;

    
    proc->pr_WindowPtr = (APTR)-1L;


    if (first == TRUE)
    {
	
	save_char = ptr[len];
	ptr[len] = NUL;
	expand_env_esc(ptr, NameBuff, MAXPATHL, FALSE, TRUE, NULL);
	ptr[len] = save_char;

	vim_free(ff_file_to_find);
	ff_file_to_find = vim_strsave(NameBuff);
	if (ff_file_to_find == NULL)	
	{
	    file_name = NULL;
	    goto theend;
	}
	if (options & FNAME_UNESC)
	{
	    
	    for (ptr = ff_file_to_find; *ptr != NUL; ++ptr)
		if (ptr[0] == '\\' && ptr[1] == ' ')
		    mch_memmove(ptr, ptr + 1, STRLEN(ptr));
	}
    }

    rel_to_curdir = (ff_file_to_find[0] == '.' && (ff_file_to_find[1] == NUL || vim_ispathsep(ff_file_to_find[1])

			|| (ff_file_to_find[1] == '.' && (ff_file_to_find[2] == NUL || vim_ispathsep(ff_file_to_find[2])))));

    if (vim_isAbsName(ff_file_to_find)
	    
	    || rel_to_curdir   || vim_ispathsep(ff_file_to_find[0])


	    
	    || (ff_file_to_find[0] != NUL && ff_file_to_find[1] == ':')


	    
	    || ff_file_to_find[0] == ':'  )

    {
	
	if (first == TRUE)
	{
	    int		l;
	    int		run;

	    if (path_with_url(ff_file_to_find))
	    {
		file_name = vim_strsave(ff_file_to_find);
		goto theend;
	    }

	    
	    
	    for (run = 1; run <= 2; ++run)
	    {
		l = (int)STRLEN(ff_file_to_find);
		if (run == 1 && rel_to_curdir && (options & FNAME_REL)

			&& rel_fname != NULL && STRLEN(rel_fname) + l < MAXPATHL)
		{
		    STRCPY(NameBuff, rel_fname);
		    STRCPY(gettail(NameBuff), ff_file_to_find);
		    l = (int)STRLEN(NameBuff);
		}
		else {
		    STRCPY(NameBuff, ff_file_to_find);
		    run = 2;
		}

		
		
		buf = suffixes;
		for (;;)
		{
		    if (mch_getperm(NameBuff) >= 0 && (find_what == FINDFILE_BOTH || ((find_what == FINDFILE_DIR)

						    == mch_isdir(NameBuff))))
		    {
			file_name = vim_strsave(NameBuff);
			goto theend;
		    }
		    if (*buf == NUL)
			break;
		    copy_option_part(&buf, NameBuff + l, MAXPATHL - l, ",");
		}
	    }
	}
    }
    else {
	
	if (first == TRUE)
	{
	    
	    vim_findfile_free_visited(fdip_search_ctx);
	    dir = path_option;
	    did_findfile_init = FALSE;
	}

	for (;;)
	{
	    if (did_findfile_init)
	    {
		file_name = vim_findfile(fdip_search_ctx);
		if (file_name != NULL)
		    break;

		did_findfile_init = FALSE;
	    }
	    else {
		char_u  *r_ptr;

		if (dir == NULL || *dir == NUL)
		{
		    
		    
		    vim_findfile_cleanup(fdip_search_ctx);
		    fdip_search_ctx = NULL;
		    break;
		}

		if ((buf = alloc(MAXPATHL)) == NULL)
		    break;

		
		buf[0] = 0;
		copy_option_part(&dir, buf, MAXPATHL, " ,");


		
		r_ptr = vim_findfile_stopdir(buf);

		r_ptr = NULL;

		fdip_search_ctx = vim_findfile_init(buf, ff_file_to_find, r_ptr, 100, FALSE, find_what, fdip_search_ctx, FALSE, rel_fname);

		if (fdip_search_ctx != NULL)
		    did_findfile_init = TRUE;
		vim_free(buf);
	    }
	}
    }
    if (file_name == NULL && (options & FNAME_MESS))
    {
	if (first == TRUE)
	{
	    if (find_what == FINDFILE_DIR)
		semsg(_("E344: Can't find directory \"%s\" in cdpath"), ff_file_to_find);
	    else semsg(_("E345: Can't find file \"%s\" in path"), ff_file_to_find);

	}
	else {
	    if (find_what == FINDFILE_DIR)
		semsg(_("E346: No more directory \"%s\" found in cdpath"), ff_file_to_find);
	    else semsg(_("E347: No more file \"%s\" found in path"), ff_file_to_find);

	}
    }

theend:

    proc->pr_WindowPtr = save_winptr;

    return file_name;
}


    char_u * grab_file_name(long count, linenr_T *file_lnum)
{
    int options = FNAME_MESS|FNAME_EXP|FNAME_REL|FNAME_UNESC;

    if (VIsual_active)
    {
	int	len;
	char_u	*ptr;

	if (get_visual_text(NULL, &ptr, &len) == FAIL)
	    return NULL;
	
	if (file_lnum != NULL && ptr[len] == ':' && isdigit(ptr[len + 1]))
	{
	    char_u *p = ptr + len + 1;

	    *file_lnum = getdigits(&p);
	}
	return find_file_name_in_path(ptr, len, options, count, curbuf->b_ffname);
    }
    return file_name_at_cursor(options | FNAME_HYP, count, file_lnum);
}


    char_u * file_name_at_cursor(int options, long count, linenr_T *file_lnum)
{
    return file_name_in_line(ml_get_curline(), curwin->w_cursor.col, options, count, curbuf->b_ffname, file_lnum);

}


    char_u * file_name_in_line( char_u	*line, int		col, int		options, long	count, char_u	*rel_fname, linenr_T	*file_lnum)






{
    char_u	*ptr;
    int		len;
    int		in_type = TRUE;
    int		is_url = FALSE;

    
    ptr = line + col;
    while (*ptr != NUL && !vim_isfilec(*ptr))
	MB_PTR_ADV(ptr);
    if (*ptr == NUL)		
    {
	if (options & FNAME_MESS)
	    emsg(_("E446: No file name under cursor"));
	return NULL;
    }

    
    while (ptr > line)
    {
	if (has_mbyte && (len = (*mb_head_off)(line, ptr - 1)) > 0)
	    ptr -= len + 1;
	else if (vim_isfilec(ptr[-1])
		|| ((options & FNAME_HYP) && path_is_url(ptr - 1)))
	    --ptr;
	else break;
    }

    
    len = 0;
    while (vim_isfilec(ptr[len]) || (ptr[len] == '\\' && ptr[len + 1] == ' ')
			 || ((options & FNAME_HYP) && path_is_url(ptr + len))
			 || (is_url && vim_strchr((char_u *)":?&=", ptr[len]) != NULL))
    {
	
	
	if ((ptr[len] >= 'A' && ptr[len] <= 'Z') || (ptr[len] >= 'a' && ptr[len] <= 'z'))
	{
	    if (in_type && path_is_url(ptr + len + 1))
		is_url = TRUE;
	}
	else in_type = FALSE;

	if (ptr[len] == '\\')
	    
	    ++len;
	if (has_mbyte)
	    len += (*mb_ptr2len)(ptr + len);
	else ++len;
    }

    
    if (len > 2 && vim_strchr((char_u *)".,:;!", ptr[len - 1]) != NULL && ptr[len - 2] != '.')
	--len;

    if (file_lnum != NULL)
    {
	char_u *p;
	char	*line_english = " line ";
	char	*line_transl = _(line_msg);

	
	
	
	p = ptr + len;
	if (STRNCMP(p, line_english, STRLEN(line_english)) == 0)
	    p += STRLEN(line_english);
	else if (STRNCMP(p, line_transl, STRLEN(line_transl)) == 0)
	    p += STRLEN(line_transl);
	else p = skipwhite(p);
	if (*p != NUL)
	{
	    if (!isdigit(*p))
		++p;		    
	    p = skipwhite(p);
	    if (isdigit(*p))
		*file_lnum = (int)getdigits(&p);
	}
    }

    return find_file_name_in_path(ptr, len, options, count, rel_fname);
}


    static char_u * eval_includeexpr(char_u *ptr, int len)
{
    char_u	*res;

    set_vim_var_string(VV_FNAME, ptr, len);
    res = eval_to_string_safe(curbuf->b_p_inex, was_set_insecurely((char_u *)"includeexpr", OPT_LOCAL));
    set_vim_var_string(VV_FNAME, NULL, 0);
    return res;
}



    char_u * find_file_name_in_path( char_u	*ptr, int		len, int		options, long	count, char_u	*rel_fname)





{
    char_u	*file_name;
    int		c;

    char_u	*tofree = NULL;

    if ((options & FNAME_INCL) && *curbuf->b_p_inex != NUL)
    {
	tofree = eval_includeexpr(ptr, len);
	if (tofree != NULL)
	{
	    ptr = tofree;
	    len = (int)STRLEN(ptr);
	}
    }


    if (options & FNAME_EXP)
    {
	file_name = find_file_in_path(ptr, len, options & ~FNAME_MESS, TRUE, rel_fname);


	
	if (file_name == NULL && !(options & FNAME_INCL) && *curbuf->b_p_inex != NUL)
	{
	    tofree = eval_includeexpr(ptr, len);
	    if (tofree != NULL)
	    {
		ptr = tofree;
		len = (int)STRLEN(ptr);
		file_name = find_file_in_path(ptr, len, options & ~FNAME_MESS, TRUE, rel_fname);
	    }
	}

	if (file_name == NULL && (options & FNAME_MESS))
	{
	    c = ptr[len];
	    ptr[len] = NUL;
	    semsg(_("E447: Can't find file \"%s\" in path"), ptr);
	    ptr[len] = c;
	}

	
	
	while (file_name != NULL && --count > 0)
	{
	    vim_free(file_name);
	    file_name = find_file_in_path(ptr, len, options, FALSE, rel_fname);
	}
    }
    else file_name = vim_strnsave(ptr, len);


    vim_free(tofree);


    return file_name;
}


    static char_u * gettail_dir(char_u *fname)
{
    char_u	*dir_end = fname;
    char_u	*next_dir_end = fname;
    int		look_for_sep = TRUE;
    char_u	*p;

    for (p = fname; *p != NUL; )
    {
	if (vim_ispathsep(*p))
	{
	    if (look_for_sep)
	    {
		next_dir_end = p;
		look_for_sep = FALSE;
	    }
	}
	else {
	    if (!look_for_sep)
		dir_end = next_dir_end;
	    look_for_sep = TRUE;
	}
	MB_PTR_ADV(p);
    }
    return dir_end;
}


    int vim_ispathlistsep(int c)
{

    return (c == ':');

    return (c == ';');	

}


    static int find_previous_pathsep(char_u *path, char_u **psep)
{
    
    if (*psep > path && vim_ispathsep(**psep))
	--*psep;

    
    while (*psep > path)
    {
	if (vim_ispathsep(**psep))
	    return OK;
	MB_PTR_BACK(path, *psep);
    }

    return FAIL;
}


    static int is_unique(char_u *maybe_unique, garray_T *gap, int i)
{
    int	    j;
    int	    candidate_len;
    int	    other_path_len;
    char_u  **other_paths = (char_u **)gap->ga_data;
    char_u  *rival;

    for (j = 0; j < gap->ga_len; j++)
    {
	if (j == i)
	    continue;  

	candidate_len = (int)STRLEN(maybe_unique);
	other_path_len = (int)STRLEN(other_paths[j]);
	if (other_path_len < candidate_len)
	    continue;  

	rival = other_paths[j] + other_path_len - candidate_len;
	if (fnamecmp(maybe_unique, rival) == 0 && (rival == other_paths[j] || vim_ispathsep(*(rival - 1))))
	    return FALSE;  
    }

    return TRUE;  
}


    static void expand_path_option(char_u *curdir, garray_T *gap)
{
    char_u	*path_option = *curbuf->b_p_path == NUL ? p_path : curbuf->b_p_path;
    char_u	*buf;
    char_u	*p;
    int		len;

    if ((buf = alloc(MAXPATHL)) == NULL)
	return;

    while (*path_option != NUL)
    {
	copy_option_part(&path_option, buf, MAXPATHL, " ,");

	if (buf[0] == '.' && (buf[1] == NUL || vim_ispathsep(buf[1])))
	{
	    
	    
	    
	    if (curbuf->b_ffname == NULL)
		continue;
	    p = gettail(curbuf->b_ffname);
	    len = (int)(p - curbuf->b_ffname);
	    if (len + (int)STRLEN(buf) >= MAXPATHL)
		continue;
	    if (buf[1] == NUL)
		buf[len] = NUL;
	    else STRMOVE(buf + len, buf + 2);
	    mch_memmove(buf, curbuf->b_ffname, len);
	    simplify_filename(buf);
	}
	else if (buf[0] == NUL)
	    
	    STRCPY(buf, curdir);
	else if (path_with_url(buf))
	    
	    continue;
	else if (!mch_isFullName(buf))
	{
	    
	    len = (int)STRLEN(curdir);
	    if (len + (int)STRLEN(buf) + 3 > MAXPATHL)
		continue;
	    STRMOVE(buf + len + 1, buf);
	    STRCPY(buf, curdir);
	    buf[len] = PATHSEP;
	    simplify_filename(buf);
	}

	if (ga_grow(gap, 1) == FAIL)
	    break;


	
	
	len = (int)STRLEN(buf);
	if (buf[len - 1] == '\\')
	    buf[len - 1] = '/';


	p = vim_strsave(buf);
	if (p == NULL)
	    break;
	((char_u **)gap->ga_data)[gap->ga_len++] = p;
    }

    vim_free(buf);
}


    static char_u * get_path_cutoff(char_u *fname, garray_T *gap)
{
    int	    i;
    int	    maxlen = 0;
    char_u  **path_part = (char_u **)gap->ga_data;
    char_u  *cutoff = NULL;

    for (i = 0; i < gap->ga_len; i++)
    {
	int j = 0;

	while ((fname[j] == path_part[i][j]  || (vim_ispathsep(fname[j]) && vim_ispathsep(path_part[i][j]))


			     ) && fname[j] != NUL && path_part[i][j] != NUL)
	    j++;
	if (j > maxlen)
	{
	    maxlen = j;
	    cutoff = &fname[j];
	}
    }

    
    if (cutoff != NULL)
	while (vim_ispathsep(*cutoff))
	    MB_PTR_ADV(cutoff);

    return cutoff;
}


    void uniquefy_paths(garray_T *gap, char_u *pattern)
{
    int		i;
    int		len;
    char_u	**fnames = (char_u **)gap->ga_data;
    int		sort_again = FALSE;
    char_u	*pat;
    char_u      *file_pattern;
    char_u	*curdir;
    regmatch_T	regmatch;
    garray_T	path_ga;
    char_u	**in_curdir = NULL;
    char_u	*short_name;

    remove_duplicates(gap);
    ga_init2(&path_ga, (int)sizeof(char_u *), 1);

    
    len = (int)STRLEN(pattern);
    file_pattern = alloc(len + 2);
    if (file_pattern == NULL)
	return;
    file_pattern[0] = '*';
    file_pattern[1] = NUL;
    STRCAT(file_pattern, pattern);
    pat = file_pat_to_reg_pat(file_pattern, NULL, NULL, TRUE);
    vim_free(file_pattern);
    if (pat == NULL)
	return;

    regmatch.rm_ic = TRUE;		
    regmatch.regprog = vim_regcomp(pat, RE_MAGIC + RE_STRING);
    vim_free(pat);
    if (regmatch.regprog == NULL)
	return;

    if ((curdir = alloc(MAXPATHL)) == NULL)
	goto theend;
    mch_dirname(curdir, MAXPATHL);
    expand_path_option(curdir, &path_ga);

    in_curdir = ALLOC_CLEAR_MULT(char_u *, gap->ga_len);
    if (in_curdir == NULL)
	goto theend;

    for (i = 0; i < gap->ga_len && !got_int; i++)
    {
	char_u	    *path = fnames[i];
	int	    is_in_curdir;
	char_u	    *dir_end = gettail_dir(path);
	char_u	    *pathsep_p;
	char_u	    *path_cutoff;

	len = (int)STRLEN(path);
	is_in_curdir = fnamencmp(curdir, path, dir_end - path) == 0 && curdir[dir_end - path] == NUL;
	if (is_in_curdir)
	    in_curdir[i] = vim_strsave(path);

	
	path_cutoff = get_path_cutoff(path, &path_ga);

	
	
	
	if (pattern[0] == '*' && pattern[1] == '*' && vim_ispathsep_nocolon(pattern[2])
		&& path_cutoff != NULL && vim_regexec(&regmatch, path_cutoff, (colnr_T)0)
		&& is_unique(path_cutoff, gap, i))
	{
	    sort_again = TRUE;
	    mch_memmove(path, path_cutoff, STRLEN(path_cutoff) + 1);
	}
	else {
	    
	    
	    pathsep_p = path + len - 1;

	    while (find_previous_pathsep(path, &pathsep_p))
		if (vim_regexec(&regmatch, pathsep_p + 1, (colnr_T)0)
			&& is_unique(pathsep_p + 1, gap, i)
			&& path_cutoff != NULL && pathsep_p + 1 >= path_cutoff)
		{
		    sort_again = TRUE;
		    mch_memmove(path, pathsep_p + 1, STRLEN(pathsep_p));
		    break;
		}
	}

	if (mch_isFullName(path))
	{
	    
	    short_name = shorten_fname(path, curdir);
	    if (short_name != NULL && short_name > path + 1      && !vim_ispathsep(*short_name)






		)
	    {
		STRCPY(path, ".");
		add_pathsep(path);
		STRMOVE(path + STRLEN(path), short_name);
	    }
	}
	ui_breakcheck();
    }

    
    for (i = 0; i < gap->ga_len && !got_int; i++)
    {
	char_u *rel_path;
	char_u *path = in_curdir[i];

	if (path == NULL)
	    continue;

	
	
	short_name = shorten_fname(path, curdir);
	if (short_name == NULL)
	    short_name = path;
	if (is_unique(short_name, gap, i))
	{
	    STRCPY(fnames[i], short_name);
	    continue;
	}

	rel_path = alloc(STRLEN(short_name) + STRLEN(PATHSEPSTR) + 2);
	if (rel_path == NULL)
	    goto theend;
	STRCPY(rel_path, ".");
	add_pathsep(rel_path);
	STRCAT(rel_path, short_name);

	vim_free(fnames[i]);
	fnames[i] = rel_path;
	sort_again = TRUE;
	ui_breakcheck();
    }

theend:
    vim_free(curdir);
    if (in_curdir != NULL)
    {
	for (i = 0; i < gap->ga_len; i++)
	    vim_free(in_curdir[i]);
	vim_free(in_curdir);
    }
    ga_clear_strings(&path_ga);
    vim_regfree(regmatch.regprog);

    if (sort_again)
	remove_duplicates(gap);
}


    int expand_in_path( garray_T	*gap, char_u	*pattern, int		flags)



{
    char_u	*curdir;
    garray_T	path_ga;
    char_u	*paths = NULL;
    int		glob_flags = 0;

    if ((curdir = alloc(MAXPATHL)) == NULL)
	return 0;
    mch_dirname(curdir, MAXPATHL);

    ga_init2(&path_ga, (int)sizeof(char_u *), 1);
    expand_path_option(curdir, &path_ga);
    vim_free(curdir);
    if (path_ga.ga_len == 0)
	return 0;

    paths = ga_concat_strings(&path_ga, ",");
    ga_clear_strings(&path_ga);
    if (paths == NULL)
	return 0;

    if (flags & EW_ICASE)
	glob_flags |= WILD_ICASE;
    if (flags & EW_ADDSLASH)
	glob_flags |= WILD_ADD_SLASH;
    globpath(paths, pattern, gap, glob_flags);
    vim_free(paths);

    return gap->ga_len;
}




    void simplify_filename(char_u *filename)
{

    int		components = 0;
    char_u	*p, *tail, *start;
    int		stripping_disabled = FALSE;
    int		relative = TRUE;

    p = filename;

    if (p[1] == ':')	    
	p += 2;


    if (vim_ispathsep(*p))
    {
	relative = FALSE;
	do ++p;
	while (vim_ispathsep(*p));
    }
    start = p;	    

    
    if (start > filename + 2)
    {
	STRMOVE(filename + 1, p);
	start = p = filename + 1;
    }


    do {
	
	

	
	if ((*p == '[' || *p == '<') && p > filename && p[-1] == ':')
	{
	    
	    ++components;
	    p = getnextcomp(p + 1);
	}
	
	else if (p[0] == ':' && p[1] == ':' && p > filename && p[-1] == '"' )
	{
	    
	    ++components;
	    p = getnextcomp(p + 2);
	}
	else  if (vim_ispathsep(*p))

	    STRMOVE(p, p + 1);		
	else if (p[0] == '.' && (vim_ispathsep(p[1]) || p[1] == NUL))
	{
	    if (p == start && relative)
		p += 1 + (p[1] != NUL);	
	    else {
		
		
		
		
		tail = p + 1;
		if (p[1] != NUL)
		    while (vim_ispathsep(*tail))
			MB_PTR_ADV(tail);
		else if (p > start)
		    --p;		
		STRMOVE(p, tail);
	    }
	}
	else if (p[0] == '.' && p[1] == '.' && (vim_ispathsep(p[2]) || p[2] == NUL))
	{
	    
	    tail = p + 2;
	    while (vim_ispathsep(*tail))
		MB_PTR_ADV(tail);

	    if (components > 0)		
	    {
		int		do_strip = FALSE;
		char_u		saved_char;
		stat_T		st;

		
		if (!stripping_disabled)
		{
		    
		    
		    
		    saved_char = p[-1];
		    p[-1] = NUL;

		    if (mch_lstat((char *)filename, &st) < 0)

			if (mch_stat((char *)filename, &st) < 0)

			    do_strip = TRUE;
		    p[-1] = saved_char;

		    --p;
		    
		    while (p > start && !after_pathsep(start, p))
			MB_PTR_BACK(start, p);

		    if (!do_strip)
		    {
			
			
			
			
			
			
			
			
			
			
			saved_char = *tail;
			*tail = NUL;
			if (mch_stat((char *)filename, &st) >= 0)
			    do_strip = TRUE;
			else stripping_disabled = TRUE;
			*tail = saved_char;

			if (do_strip)
			{
			    stat_T	new_st;

			    
			    
			    
			    
			    
			    
			    
			    if (p == start && relative)
				(void)mch_stat(".", &new_st);
			    else {
				saved_char = *p;
				*p = NUL;
				(void)mch_stat((char *)filename, &new_st);
				*p = saved_char;
			    }

			    if (new_st.st_ino != st.st_ino || new_st.st_dev != st.st_dev)
			    {
				do_strip = FALSE;
				
				
				
			    }
			}

		    }
		}

		if (!do_strip)
		{
		    
		    
		    p = tail;
		    components = 0;
		}
		else {
		    
		    
		    
		    
		    
		    
		    if (p == start && relative && tail[-1] == '.')
		    {
			*p++ = '.';
			*p = NUL;
		    }
		    else {
			if (p > start && tail[-1] == '.')
			    --p;
			STRMOVE(p, tail);	
		    }

		    --components;
		}
	    }
	    else if (p == start && !relative)	
		STRMOVE(p, tail);		
	    else {
		if (p == start + 2 && p[-2] == '.')	
		{
		    STRMOVE(p - 2, p);			
		    tail -= 2;
		}
		p = tail;		
	    }
	}
	else {
	    ++components;		
	    p = getnextcomp(p);
	}
    } while (*p != NUL);

}



    void f_simplify(typval_T *argvars, typval_T *rettv)
{
    char_u	*p;

    if (in_vim9script() && check_for_string_arg(argvars, 0) == FAIL)
	return;

    p = tv_get_string_strict(&argvars[0]);
    rettv->vval.v_string = vim_strsave(p);
    simplify_filename(rettv->vval.v_string);	
    rettv->v_type = VAR_STRING;
}

