




static int scrolljump_value(void);
static int check_top_offset(void);
static void curs_rows(win_T *wp);

typedef struct {
    linenr_T	    lnum;	

    int		    fill;	

    int		    height;	
} lineoff_T;

static void topline_back(lineoff_T *lp);
static void botline_forw(lineoff_T *lp);


    static void comp_botline(win_T *wp)
{
    int		n;
    linenr_T	lnum;
    int		done;

    linenr_T    last;
    int		folded;


    
    check_cursor_moved(wp);
    if (wp->w_valid & VALID_CROW)
    {
	lnum = wp->w_cursor.lnum;
	done = wp->w_cline_row;
    }
    else {
	lnum = wp->w_topline;
	done = 0;
    }

    for ( ; lnum <= wp->w_buffer->b_ml.ml_line_count; ++lnum)
    {

	last = lnum;
	folded = FALSE;
	if (hasFoldingWin(wp, lnum, NULL, &last, TRUE, NULL))
	{
	    n = 1;
	    folded = TRUE;
	}
	else   if (lnum == wp->w_topline)


		n = plines_win_nofill(wp, lnum, TRUE) + wp->w_topfill;
	    else  n = plines_win(wp, lnum, TRUE);

	if (  lnum <= wp->w_cursor.lnum && last >= wp->w_cursor.lnum  lnum == wp->w_cursor.lnum  )





	{
	    wp->w_cline_row = done;
	    wp->w_cline_height = n;

	    wp->w_cline_folded = folded;

	    redraw_for_cursorline(wp);
	    wp->w_valid |= (VALID_CROW|VALID_CHEIGHT);
	}
	if (done + n > wp->w_height)
	    break;
	done += n;

	lnum = last;

    }

    
    wp->w_botline = lnum;
    wp->w_valid |= VALID_BOTLINE|VALID_BOTLINE_AP;

    set_empty_rows(wp, done);
}


    void redraw_for_cursorline(win_T *wp)
{
    if ((wp->w_p_rnu  || wp->w_p_cul  )



	    && (wp->w_valid & VALID_CROW) == 0 && !pum_visible())
    {
	
	redraw_win_later(wp, UPD_VALID);
    }
}



    static void redraw_for_cursorcolumn(win_T *wp)
{
    if ((wp->w_valid & VALID_VIRTCOL) == 0 && !pum_visible())
    {
	
	if (wp->w_p_cuc)
	    redraw_win_later(wp, UPD_SOME_VALID);
	
	
	else if (wp->w_p_cul && (wp->w_p_culopt_flags & CULOPT_SCRLINE))
	    redraw_win_later(wp, UPD_VALID);
    }
}



    void update_topline_redraw(void)
{
    update_topline();
    if (must_redraw)
	update_screen(0);
}


    void update_topline(void)
{
    long	line_count;
    int		halfheight;
    int		n;
    linenr_T	old_topline;

    int		old_topfill;


    linenr_T	lnum;

    int		check_topline = FALSE;
    int		check_botline = FALSE;
    long	*so_ptr = curwin->w_p_so >= 0 ? &curwin->w_p_so : &p_so;
    int		save_so = *so_ptr;

    
    
    if (!screen_valid(TRUE) || curwin->w_height == 0)
    {
	check_cursor_lnum();
	curwin->w_topline = curwin->w_cursor.lnum;
	curwin->w_botline = curwin->w_topline;
	curwin->w_scbind_pos = 1;
	return;
    }

    check_cursor_moved(curwin);
    if (curwin->w_valid & VALID_TOPLINE)
	return;

    
    if (mouse_dragging > 0)
	*so_ptr = mouse_dragging - 1;

    old_topline = curwin->w_topline;

    old_topfill = curwin->w_topfill;


    
    if (BUFEMPTY())		
    {
	if (curwin->w_topline != 1)
	    redraw_later(UPD_NOT_VALID);
	curwin->w_topline = 1;
	curwin->w_botline = 2;
	curwin->w_valid |= VALID_BOTLINE|VALID_BOTLINE_AP;
	curwin->w_scbind_pos = 1;
    }

    
    else {
	if (curwin->w_topline > 1)
	{
	    
	    
	    
	    if (curwin->w_cursor.lnum < curwin->w_topline)
		check_topline = TRUE;
	    else if (check_top_offset())
		check_topline = TRUE;
	}

	    
	if (!check_topline && curwin->w_topfill > diff_check_fill(curwin, curwin->w_topline))
	    check_topline = TRUE;


	if (check_topline)
	{
	    halfheight = curwin->w_height / 2 - 1;
	    if (halfheight < 2)
		halfheight = 2;


	    if (hasAnyFolding(curwin))
	    {
		
		
		
		n = 0;
		for (lnum = curwin->w_cursor.lnum;
				    lnum < curwin->w_topline + *so_ptr; ++lnum)
		{
		    ++n;
		    
		    if (lnum >= curbuf->b_ml.ml_line_count || n >= halfheight)
			break;
		    (void)hasFolding(lnum, NULL, &lnum);
		}
	    }
	    else  n = curwin->w_topline + *so_ptr - curwin->w_cursor.lnum;


	    
	    
	    
	    if (n >= halfheight)
		scroll_cursor_halfway(FALSE);
	    else {
		scroll_cursor_top(scrolljump_value(), FALSE);
		check_botline = TRUE;
	    }
	}

	else {

	    
	    (void)hasFolding(curwin->w_topline, &curwin->w_topline, NULL);

	    check_botline = TRUE;
	}
    }

    
    if (check_botline)
    {
	if (!(curwin->w_valid & VALID_BOTLINE_AP))
	    validate_botline();

	if (curwin->w_botline <= curbuf->b_ml.ml_line_count)
	{
	    if (curwin->w_cursor.lnum < curwin->w_botline)
	    {
	      if (((long)curwin->w_cursor.lnum >= (long)curwin->w_botline - *so_ptr  || hasAnyFolding(curwin)



			))
	      {
		lineoff_T	loff;

		
		
		
		n = curwin->w_empty_rows;
		loff.lnum = curwin->w_cursor.lnum;

		
		(void)hasFolding(loff.lnum, NULL, &loff.lnum);


		loff.fill = 0;
		n += curwin->w_filler_rows;

		loff.height = 0;
		while (loff.lnum < curwin->w_botline  && (loff.lnum + 1 < curwin->w_botline || loff.fill == 0)


			)
		{
		    n += loff.height;
		    if (n >= *so_ptr)
			break;
		    botline_forw(&loff);
		}
		if (n >= *so_ptr)
		    
		    check_botline = FALSE;
	      }
	      else  check_botline = FALSE;

	    }
	    if (check_botline)
	    {

		if (hasAnyFolding(curwin))
		{
		    
		    
		    
		    line_count = 0;
		    for (lnum = curwin->w_cursor.lnum;
				   lnum >= curwin->w_botline - *so_ptr; --lnum)
		    {
			++line_count;
			
			if (lnum <= 0 || line_count > curwin->w_height + 1)
			    break;
			(void)hasFolding(lnum, &lnum, NULL);
		    }
		}
		else  line_count = curwin->w_cursor.lnum - curwin->w_botline + 1 + *so_ptr;


		if (line_count <= curwin->w_height + 1)
		    scroll_cursor_bot(scrolljump_value(), FALSE);
		else scroll_cursor_halfway(FALSE);
	    }
	}
    }
    curwin->w_valid |= VALID_TOPLINE;

    
    if (curwin->w_topline != old_topline  || curwin->w_topfill != old_topfill  )



    {
	dollar_vcol = -1;
	if (curwin->w_skipcol != 0)
	{
	    curwin->w_skipcol = 0;
	    redraw_later(UPD_NOT_VALID);
	}
	else redraw_later(UPD_VALID);
	
	if (curwin->w_cursor.lnum == curwin->w_topline)
	    validate_cursor();
    }

    *so_ptr = save_so;
}


    static int scrolljump_value(void)
{
    if (p_sj >= 0)
	return (int)p_sj;
    return (curwin->w_height * -p_sj) / 100;
}


    static int check_top_offset(void)
{
    lineoff_T	loff;
    int		n;
    long	so = get_scrolloff_value();

    if (curwin->w_cursor.lnum < curwin->w_topline + so  || hasAnyFolding(curwin)


	    )
    {
	loff.lnum = curwin->w_cursor.lnum;

	loff.fill = 0;
	n = curwin->w_topfill;	    

	n = 0;

	
	while (n < so)
	{
	    topline_back(&loff);
	    
	    if (loff.lnum < curwin->w_topline  || (loff.lnum == curwin->w_topline && loff.fill > 0)


		    )
		break;
	    n += loff.height;
	}
	if (n < so)
	    return TRUE;
    }
    return FALSE;
}


    void update_curswant_force(void)
{
    validate_virtcol();
    curwin->w_curswant = curwin->w_virtcol  - curwin->w_virtcol_first_char  ;



    curwin->w_set_curswant = FALSE;
}


    void update_curswant(void)
{
    if (curwin->w_set_curswant)
	update_curswant_force();
}


    void check_cursor_moved(win_T *wp)
{
    if (wp->w_cursor.lnum != wp->w_valid_cursor.lnum)
    {
	wp->w_valid &= ~(VALID_WROW|VALID_WCOL|VALID_VIRTCOL |VALID_CHEIGHT|VALID_CROW|VALID_TOPLINE |VALID_BOTLINE|VALID_BOTLINE_AP);

	wp->w_valid_cursor = wp->w_cursor;
	wp->w_valid_leftcol = wp->w_leftcol;
    }
    else if (wp->w_cursor.col != wp->w_valid_cursor.col || wp->w_leftcol != wp->w_valid_leftcol || wp->w_cursor.coladd != wp->w_valid_cursor.coladd)

    {
	wp->w_valid &= ~(VALID_WROW|VALID_WCOL|VALID_VIRTCOL);
	wp->w_valid_cursor.col = wp->w_cursor.col;
	wp->w_valid_leftcol = wp->w_leftcol;
	wp->w_valid_cursor.coladd = wp->w_cursor.coladd;
    }
}


    void changed_window_setting(void)
{
    changed_window_setting_win(curwin);
}

    void changed_window_setting_win(win_T *wp)
{
    wp->w_lines_valid = 0;
    changed_line_abv_curs_win(wp);
    wp->w_valid &= ~(VALID_BOTLINE|VALID_BOTLINE_AP|VALID_TOPLINE);
    redraw_win_later(wp, UPD_NOT_VALID);
}


    void set_topline(win_T *wp, linenr_T lnum)
{

    linenr_T prev_topline = wp->w_topline;



    
    (void)hasFoldingWin(wp, lnum, &lnum, NULL, TRUE, NULL);

    
    wp->w_botline += lnum - wp->w_topline;
    if (wp->w_botline > wp->w_buffer->b_ml.ml_line_count + 1)
	wp->w_botline = wp->w_buffer->b_ml.ml_line_count + 1;
    wp->w_topline = lnum;
    wp->w_topline_was_set = TRUE;

    if (lnum != prev_topline)
	
	wp->w_topfill = 0;

    wp->w_valid &= ~(VALID_WROW|VALID_CROW|VALID_BOTLINE|VALID_TOPLINE);
    
    redraw_later(UPD_VALID);
}


    void changed_cline_bef_curs(void)
{
    curwin->w_valid &= ~(VALID_WROW|VALID_WCOL|VALID_VIRTCOL |VALID_CHEIGHT|VALID_TOPLINE);
}

    void changed_cline_bef_curs_win(win_T *wp)
{
    wp->w_valid &= ~(VALID_WROW|VALID_WCOL|VALID_VIRTCOL |VALID_CHEIGHT|VALID_TOPLINE);
}


    void changed_line_abv_curs(void)
{
    curwin->w_valid &= ~(VALID_WROW|VALID_WCOL|VALID_VIRTCOL|VALID_CROW |VALID_CHEIGHT|VALID_TOPLINE);
}

    void changed_line_abv_curs_win(win_T *wp)
{
    wp->w_valid &= ~(VALID_WROW|VALID_WCOL|VALID_VIRTCOL|VALID_CROW |VALID_CHEIGHT|VALID_TOPLINE);
}


    void changed_line_display_buf(buf_T *buf)
{
    win_T *wp;

    FOR_ALL_WINDOWS(wp)
	if (wp->w_buffer == buf)
	    wp->w_valid &= ~(VALID_WROW|VALID_WCOL|VALID_VIRTCOL |VALID_CROW|VALID_CHEIGHT |VALID_TOPLINE|VALID_BOTLINE|VALID_BOTLINE_AP);

}


    void validate_botline(void)
{
    validate_botline_win(curwin);
}


    void validate_botline_win(win_T *wp)
{
    if (!(wp->w_valid & VALID_BOTLINE))
	comp_botline(wp);
}


    void invalidate_botline(void)
{
    curwin->w_valid &= ~(VALID_BOTLINE|VALID_BOTLINE_AP);
}

    void invalidate_botline_win(win_T *wp)
{
    wp->w_valid &= ~(VALID_BOTLINE|VALID_BOTLINE_AP);
}

    void approximate_botline_win( win_T	*wp)

{
    wp->w_valid &= ~VALID_BOTLINE;
}


    int cursor_valid(void)
{
    check_cursor_moved(curwin);
    return ((curwin->w_valid & (VALID_WROW|VALID_WCOL)) == (VALID_WROW|VALID_WCOL));
}


    void validate_cursor(void)
{
    check_cursor_moved(curwin);
    if ((curwin->w_valid & (VALID_WCOL|VALID_WROW)) != (VALID_WCOL|VALID_WROW))
	curs_columns(TRUE);
}



    void validate_cline_row(void)
{
    
    update_topline();
    check_cursor_moved(curwin);
    if (!(curwin->w_valid & VALID_CROW))
	curs_rows(curwin);
}



    static void curs_rows(win_T *wp)
{
    linenr_T	lnum;
    int		i;
    int		all_invalid;
    int		valid;

    long	fold_count;


    
    all_invalid = (!redrawing()
			|| wp->w_lines_valid == 0 || wp->w_lines[0].wl_lnum > wp->w_topline);
    i = 0;
    wp->w_cline_row = 0;
    for (lnum = wp->w_topline; lnum < wp->w_cursor.lnum; ++i)
    {
	valid = FALSE;
	if (!all_invalid && i < wp->w_lines_valid)
	{
	    if (wp->w_lines[i].wl_lnum < lnum || !wp->w_lines[i].wl_valid)
		continue;		
	    if (wp->w_lines[i].wl_lnum == lnum)
	    {

		
		
		if (!wp->w_buffer->b_mod_set || wp->w_lines[i].wl_lastlnum < wp->w_cursor.lnum || wp->w_buffer->b_mod_top > wp->w_lines[i].wl_lastlnum + 1)



		valid = TRUE;
	    }
	    else if (wp->w_lines[i].wl_lnum > lnum)
		--i;			
	}
	if (valid  && (lnum != wp->w_topline || !wp->w_p_diff)


		)
	{

	    lnum = wp->w_lines[i].wl_lastlnum + 1;
	    
	    if (lnum > wp->w_cursor.lnum)
		break;

	    ++lnum;

	    wp->w_cline_row += wp->w_lines[i].wl_size;
	}
	else {

	    fold_count = foldedCount(wp, lnum, NULL);
	    if (fold_count)
	    {
		lnum += fold_count;
		if (lnum > wp->w_cursor.lnum)
		    break;
		++wp->w_cline_row;
	    }
	    else   if (lnum == wp->w_topline)


		    wp->w_cline_row += plines_win_nofill(wp, lnum++, TRUE)
							      + wp->w_topfill;
		else  wp->w_cline_row += plines_win(wp, lnum++, TRUE);

	}
    }

    check_cursor_moved(wp);
    if (!(wp->w_valid & VALID_CHEIGHT))
    {
	if (all_invalid || i == wp->w_lines_valid || (i < wp->w_lines_valid && (!wp->w_lines[i].wl_valid || wp->w_lines[i].wl_lnum != wp->w_cursor.lnum)))



	{

	    if (wp->w_cursor.lnum == wp->w_topline)
		wp->w_cline_height = plines_win_nofill(wp, wp->w_cursor.lnum, TRUE) + wp->w_topfill;
	    else  wp->w_cline_height = plines_win(wp, wp->w_cursor.lnum, TRUE);


	    wp->w_cline_folded = hasFoldingWin(wp, wp->w_cursor.lnum, NULL, NULL, TRUE, NULL);

	}
	else if (i > wp->w_lines_valid)
	{
	    
	    wp->w_cline_height = 0;

	    wp->w_cline_folded = hasFoldingWin(wp, wp->w_cursor.lnum, NULL, NULL, TRUE, NULL);

	}
	else {
	    wp->w_cline_height = wp->w_lines[i].wl_size;

	    wp->w_cline_folded = wp->w_lines[i].wl_folded;

	}
    }

    redraw_for_cursorline(curwin);
    wp->w_valid |= VALID_CROW|VALID_CHEIGHT;

}


    void validate_virtcol(void)
{
    validate_virtcol_win(curwin);
}


    void validate_virtcol_win(win_T *wp)
{
    check_cursor_moved(wp);
    if (!(wp->w_valid & VALID_VIRTCOL))
    {

	wp->w_virtcol_first_char = 0;

	getvvcol(wp, &wp->w_cursor, NULL, &(wp->w_virtcol), NULL);

	redraw_for_cursorcolumn(wp);

	wp->w_valid |= VALID_VIRTCOL;
    }
}


    void validate_cheight(void)
{
    check_cursor_moved(curwin);
    if (!(curwin->w_valid & VALID_CHEIGHT))
    {

	if (curwin->w_cursor.lnum == curwin->w_topline)
	    curwin->w_cline_height = plines_nofill(curwin->w_cursor.lnum)
							  + curwin->w_topfill;
	else  curwin->w_cline_height = plines(curwin->w_cursor.lnum);


	curwin->w_cline_folded = hasFolding(curwin->w_cursor.lnum, NULL, NULL);

	curwin->w_valid |= VALID_CHEIGHT;
    }
}


    void validate_cursor_col(void)
{
    colnr_T off;
    colnr_T col;
    int     width;

    validate_virtcol();
    if (!(curwin->w_valid & VALID_WCOL))
    {
	col = curwin->w_virtcol;
	off = curwin_col_off();
	col += off;
	width = curwin->w_width - off + curwin_col_off2();

	
	if (curwin->w_p_wrap && col >= (colnr_T)curwin->w_width && width > 0)

	    
	    col -= ((col - curwin->w_width) / width + 1) * width;
	if (col > (int)curwin->w_leftcol)
	    col -= curwin->w_leftcol;
	else col = 0;
	curwin->w_wcol = col;

	curwin->w_valid |= VALID_WCOL;

	curwin->w_flags &= ~WFLAG_WCOL_OFF_ADDED;

    }
}


    int win_col_off(win_T *wp)
{
    return (((wp->w_p_nu || wp->w_p_rnu) ? number_width(wp) + 1 : 0)

	    + (cmdwin_type == 0 || wp != curwin ? 0 : 1)


	    + wp->w_p_fdc   + (signcolumn_on(wp) ? 2 : 0)



	   );
}

    int curwin_col_off(void)
{
    return win_col_off(curwin);
}


    int win_col_off2(win_T *wp)
{
    if ((wp->w_p_nu || wp->w_p_rnu) && vim_strchr(p_cpo, CPO_NUMCOL) != NULL)
	return number_width(wp) + 1;
    return 0;
}

    int curwin_col_off2(void)
{
    return win_col_off2(curwin);
}


    void curs_columns( int		may_scroll)

{
    int		diff;
    int		extra;		
    int		off_left, off_right;
    int		n;
    int		p_lines;
    int		width = 0;
    int		textwidth;
    int		new_leftcol;
    colnr_T	startcol;
    colnr_T	endcol;
    colnr_T	prev_skipcol;
    long	so = get_scrolloff_value();
    long	siso = get_sidescrolloff_value();

    
    if (!skip_update_topline)
	update_topline();

    
    if (!(curwin->w_valid & VALID_CROW))
	curs_rows(curwin);


    
    curwin->w_virtcol_first_char = 0;


    

    if (curwin->w_cline_folded)
	
	startcol = curwin->w_virtcol = endcol = curwin->w_leftcol;
    else  getvvcol(curwin, &curwin->w_cursor, &startcol, &(curwin->w_virtcol), &endcol);



    
    if (startcol > dollar_vcol)
	dollar_vcol = -1;

    extra = curwin_col_off();
    curwin->w_wcol = curwin->w_virtcol + extra;
    endcol += extra;

    
    curwin->w_wrow = curwin->w_cline_row;

    textwidth = curwin->w_width - extra;
    if (textwidth <= 0)
    {
	
	
	curwin->w_wcol = curwin->w_width - 1;
	if (curwin->w_p_wrap)
	    curwin->w_wrow = curwin->w_height - 1;
	else curwin->w_wrow = curwin->w_height - 1 - curwin->w_empty_rows;
    }
    else if (curwin->w_p_wrap && curwin->w_width != 0)
    {
	width = textwidth + curwin_col_off2();

	
	if (curwin->w_wcol >= curwin->w_width)
	{

	    char_u *sbr;


	    
	    n = (curwin->w_wcol - curwin->w_width) / width + 1;
	    curwin->w_wcol -= n * width;
	    curwin->w_wrow += n;


	    
	    
	    
	    sbr = get_showbreak_value(curwin);
	    if (*sbr && *ml_get_cursor() == NUL && curwin->w_wcol == vim_strsize(sbr))
		curwin->w_wcol = 0;

	}
    }

    
    
    
    else if (may_scroll  && !curwin->w_cline_folded  )



    {

	if (curwin->w_virtcol_first_char > 0)
	{
	    int cols = (curwin->w_width - extra);
	    int rows = cols > 0 ? curwin->w_virtcol_first_char / cols : 1;

	    
	    curwin->w_wrow += rows;
	    curwin->w_wcol -= rows * cols;
	    endcol -= rows * cols;
	    curwin->w_cline_height = rows + 1;
	}

	
	off_left = (int)startcol - (int)curwin->w_leftcol - siso;
	off_right = (int)endcol - (int)(curwin->w_leftcol + curwin->w_width - siso) + 1;
	if (off_left < 0 || off_right > 0)
	{
	    if (off_left < 0)
		diff = -off_left;
	    else diff = off_right;

	    
	    
	    if (p_ss == 0 || diff >= textwidth / 2 || off_right >= off_left)
		new_leftcol = curwin->w_wcol - extra - textwidth / 2;
	    else {
		if (diff < p_ss)
		    diff = p_ss;
		if (off_left < 0)
		    new_leftcol = curwin->w_leftcol - diff;
		else new_leftcol = curwin->w_leftcol + diff;
	    }
	    if (new_leftcol < 0)
		new_leftcol = 0;
	    if (new_leftcol != (int)curwin->w_leftcol)
	    {
		curwin->w_leftcol = new_leftcol;
		
		redraw_later(UPD_NOT_VALID);
	    }
	}
	curwin->w_wcol -= curwin->w_leftcol;
    }
    else if (curwin->w_wcol > (int)curwin->w_leftcol)
	curwin->w_wcol -= curwin->w_leftcol;
    else curwin->w_wcol = 0;


    
    
    if (curwin->w_cursor.lnum == curwin->w_topline)
	curwin->w_wrow += curwin->w_topfill;
    else curwin->w_wrow += diff_check_fill(curwin, curwin->w_cursor.lnum);


    prev_skipcol = curwin->w_skipcol;

    p_lines = 0;

    if ((curwin->w_wrow >= curwin->w_height || ((prev_skipcol > 0 || curwin->w_wrow + so >= curwin->w_height)

		    && (p_lines =  plines_win_nofill  plines_win  (curwin, curwin->w_cursor.lnum, FALSE))





						    - 1 >= curwin->w_height))
	    && curwin->w_height != 0 && curwin->w_cursor.lnum == curwin->w_topline && width > 0 && curwin->w_width != 0)


    {
	
	
	
	
	
	
	extra = 0;
	if (curwin->w_skipcol + so * width > curwin->w_virtcol)
	    extra = 1;
	
	
	if (p_lines == 0)
	    p_lines = plines_win(curwin, curwin->w_cursor.lnum, FALSE);
	--p_lines;
	if (p_lines > curwin->w_wrow + so)
	    n = curwin->w_wrow + so;
	else n = p_lines;
	if ((colnr_T)n >= curwin->w_height + curwin->w_skipcol / width - so)
	    extra += 2;

	if (extra == 3 || p_lines <= so * 2)
	{
	    
	    n = curwin->w_virtcol / width;
	    if (n > curwin->w_height / 2)
		n -= curwin->w_height / 2;
	    else n = 0;
	    
	    if (n > p_lines - curwin->w_height + 1)
		n = p_lines - curwin->w_height + 1;
	    curwin->w_skipcol = n * width;
	}
	else if (extra == 1)
	{
	    
	    extra = (curwin->w_skipcol + so * width - curwin->w_virtcol + width - 1) / width;
	    if (extra > 0)
	    {
		if ((colnr_T)(extra * width) > curwin->w_skipcol)
		    extra = curwin->w_skipcol / width;
		curwin->w_skipcol -= extra * width;
	    }
	}
	else if (extra == 2)
	{
	    
	    endcol = (n - curwin->w_height + 1) * width;
	    while (endcol > curwin->w_virtcol)
		endcol -= width;
	    if (endcol > curwin->w_skipcol)
		curwin->w_skipcol = endcol;
	}

	curwin->w_wrow -= curwin->w_skipcol / width;
	if (curwin->w_wrow >= curwin->w_height)
	{
	    
	    extra = curwin->w_wrow - curwin->w_height + 1;
	    curwin->w_skipcol += extra * width;
	    curwin->w_wrow -= extra;
	}

	extra = ((int)prev_skipcol - (int)curwin->w_skipcol) / width;
	if (extra > 0)
	    win_ins_lines(curwin, 0, extra, FALSE, FALSE);
	else if (extra < 0)
	    win_del_lines(curwin, 0, -extra, FALSE, FALSE, 0);
    }
    else curwin->w_skipcol = 0;
    if (prev_skipcol != curwin->w_skipcol)
	redraw_later(UPD_NOT_VALID);


    redraw_for_cursorcolumn(curwin);


    if (popup_is_popup(curwin) && curbuf->b_term != NULL)
    {
	curwin->w_wrow += popup_top_extra(curwin);
	curwin->w_wcol += popup_left_extra(curwin);
	curwin->w_flags |= WFLAG_WCOL_OFF_ADDED + WFLAG_WROW_OFF_ADDED;
    }
    else curwin->w_flags &= ~(WFLAG_WCOL_OFF_ADDED + WFLAG_WROW_OFF_ADDED);


    
    curwin->w_valid_leftcol = curwin->w_leftcol;

    curwin->w_valid |= VALID_WCOL|VALID_WROW|VALID_VIRTCOL;
}



    void textpos2screenpos( win_T	*wp, pos_T	*pos, int	*rowp, int	*scolp, int	*ccolp, int	*ecolp)






{
    colnr_T	scol = 0, ccol = 0, ecol = 0;
    int		row = 0;
    int		rowoff = 0;
    colnr_T	coloff = 0;

    if (pos->lnum >= wp->w_topline && pos->lnum <= wp->w_botline)
    {
	colnr_T	    off;
	colnr_T	    col;
	int	    width;
	linenr_T    lnum = pos->lnum;

	int	    is_folded;

	is_folded = hasFoldingWin(wp, lnum, &lnum, NULL, TRUE, NULL);

	row = plines_m_win(wp, wp->w_topline, lnum - 1) + 1;

	if (is_folded)
	{
	    row += W_WINROW(wp);
	    coloff = wp->w_wincol + 1;
	}
	else  {

	    getvcol(wp, pos, &scol, &ccol, &ecol);

	    
	    col = scol;
	    off = win_col_off(wp);
	    col += off;
	    width = wp->w_width - off + win_col_off2(wp);

	    
	    if (wp->w_p_wrap && col >= (colnr_T)wp->w_width && width > 0)

	    {
		
		rowoff = ((col - wp->w_width) / width + 1);
		col -= rowoff * width;
	    }
	    col -= wp->w_leftcol;
	    if (col >= wp->w_width)
		col = -1;
	    if (col >= 0 && row + rowoff <= wp->w_height)
	    {
		coloff = col - scol + wp->w_wincol + 1;
		row += W_WINROW(wp);
	    }
	    else  row = rowoff = scol = ccol = ecol = 0;

	}
    }
    *rowp = row + rowoff;
    *scolp = scol + coloff;
    *ccolp = ccol + coloff;
    *ecolp = ecol + coloff;
}




    void f_screenpos(typval_T *argvars UNUSED, typval_T *rettv)
{
    dict_T	*dict;
    win_T	*wp;
    pos_T	pos;
    int		row = 0;
    int		scol = 0, ccol = 0, ecol = 0;

    if (rettv_dict_alloc(rettv) == FAIL)
	return;
    dict = rettv->vval.v_dict;

    if (in_vim9script()
	    && (check_for_number_arg(argvars, 0) == FAIL || check_for_number_arg(argvars, 1) == FAIL || check_for_number_arg(argvars, 2) == FAIL))

	return;

    wp = find_win_by_nr_or_id(&argvars[0]);
    if (wp == NULL)
	return;

    pos.lnum = tv_get_number(&argvars[1]);
    pos.col = tv_get_number(&argvars[2]) - 1;
    pos.coladd = 0;
    textpos2screenpos(wp, &pos, &row, &scol, &ccol, &ecol);

    dict_add_number(dict, "row", row);
    dict_add_number(dict, "col", scol);
    dict_add_number(dict, "curscol", ccol);
    dict_add_number(dict, "endcol", ecol);
}


    void f_virtcol2col(typval_T *argvars UNUSED, typval_T *rettv)
{
    win_T	*wp;
    linenr_T	lnum;
    int		screencol;
    int		error = FALSE;

    rettv->vval.v_number = -1;

    if (check_for_number_arg(argvars, 0) == FAIL || check_for_number_arg(argvars, 1) == FAIL || check_for_number_arg(argvars, 2) == FAIL)

	return;

    wp = find_win_by_nr_or_id(&argvars[0]);
    if (wp == NULL)
	return;

    lnum = tv_get_number_chk(&argvars[1], &error);
    if (error || lnum < 0 || lnum > wp->w_buffer->b_ml.ml_line_count)
	return;

    screencol = tv_get_number_chk(&argvars[2], &error);
    if (error || screencol < 0)
	return;

    rettv->vval.v_number = vcol2col(wp, lnum, screencol);
}



    void scrolldown( long	line_count, int		byfold UNUSED)


{
    long	done = 0;	
    int		wrow;
    int		moved = FALSE;


    linenr_T	first;

    
    (void)hasFolding(curwin->w_topline, &curwin->w_topline, NULL);

    validate_cursor();		
    while (line_count-- > 0)
    {

	if (curwin->w_topfill < diff_check(curwin, curwin->w_topline)
		&& curwin->w_topfill < curwin->w_height - 1)
	{
	    ++curwin->w_topfill;
	    ++done;
	}
	else  {

	    if (curwin->w_topline == 1)
		break;
	    --curwin->w_topline;

	    curwin->w_topfill = 0;


	    
	    if (hasFolding(curwin->w_topline, &first, NULL))
	    {
		++done;
		if (!byfold)
		    line_count -= curwin->w_topline - first - 1;
		curwin->w_botline -= curwin->w_topline - first;
		curwin->w_topline = first;
	    }
	    else  done += PLINES_NOFILL(curwin->w_topline);

	}
	--curwin->w_botline;		
	invalidate_botline();
    }
    curwin->w_wrow += done;		
    curwin->w_cline_row += done;	


    if (curwin->w_cursor.lnum == curwin->w_topline)
	curwin->w_cline_row = 0;
    check_topfill(curwin, TRUE);


    
    wrow = curwin->w_wrow;
    if (curwin->w_p_wrap && curwin->w_width != 0)
    {
	validate_virtcol();
	validate_cheight();
	wrow += curwin->w_cline_height - 1 - curwin->w_virtcol / curwin->w_width;
    }
    while (wrow >= curwin->w_height && curwin->w_cursor.lnum > 1)
    {

	if (hasFolding(curwin->w_cursor.lnum, &first, NULL))
	{
	    --wrow;
	    if (first == 1)
		curwin->w_cursor.lnum = 1;
	    else curwin->w_cursor.lnum = first - 1;
	}
	else  wrow -= plines(curwin->w_cursor.lnum--);

	curwin->w_valid &= ~(VALID_WROW|VALID_WCOL|VALID_CHEIGHT|VALID_CROW|VALID_VIRTCOL);
	moved = TRUE;
    }
    if (moved)
    {

	
	foldAdjustCursor();

	coladvance(curwin->w_curswant);
    }
}


    void scrollup( long	line_count, int		byfold UNUSED)


{

    linenr_T	lnum;

    if (  (byfold && hasAnyFolding(curwin))


	    ||    curwin->w_p_diff  )





    {
	
	lnum = curwin->w_topline;
	while (line_count--)
	{

	    if (curwin->w_topfill > 0)
		--curwin->w_topfill;
	    else  {


		if (byfold)
		    (void)hasFolding(lnum, NULL, &lnum);

		if (lnum >= curbuf->b_ml.ml_line_count)
		    break;
		++lnum;

		curwin->w_topfill = diff_check_fill(curwin, lnum);

	    }
	}
	
	curwin->w_botline += lnum - curwin->w_topline;
	curwin->w_topline = lnum;
    }
    else  {

	curwin->w_topline += line_count;
	curwin->w_botline += line_count;	
    }

    if (curwin->w_topline > curbuf->b_ml.ml_line_count)
	curwin->w_topline = curbuf->b_ml.ml_line_count;
    if (curwin->w_botline > curbuf->b_ml.ml_line_count + 1)
	curwin->w_botline = curbuf->b_ml.ml_line_count + 1;


    check_topfill(curwin, FALSE);



    if (hasAnyFolding(curwin))
	
	(void)hasFolding(curwin->w_topline, &curwin->w_topline, NULL);


    curwin->w_valid &= ~(VALID_WROW|VALID_CROW|VALID_BOTLINE);
    if (curwin->w_cursor.lnum < curwin->w_topline)
    {
	curwin->w_cursor.lnum = curwin->w_topline;
	curwin->w_valid &= ~(VALID_WROW|VALID_WCOL|VALID_CHEIGHT|VALID_CROW|VALID_VIRTCOL);
	coladvance(curwin->w_curswant);
    }
}



    void check_topfill( win_T	*wp, int		down)


{
    int		n;

    if (wp->w_topfill > 0)
    {
	n = plines_win_nofill(wp, wp->w_topline, TRUE);
	if (wp->w_topfill + n > wp->w_height)
	{
	    if (down && wp->w_topline > 1)
	    {
		--wp->w_topline;
		wp->w_topfill = 0;
	    }
	    else {
		wp->w_topfill = wp->w_height - n;
		if (wp->w_topfill < 0)
		    wp->w_topfill = 0;
	    }
	}
    }
}


    static void max_topfill(void)
{
    int		n;

    n = plines_nofill(curwin->w_topline);
    if (n >= curwin->w_height)
	curwin->w_topfill = 0;
    else {
	curwin->w_topfill = diff_check_fill(curwin, curwin->w_topline);
	if (curwin->w_topfill + n > curwin->w_height)
	    curwin->w_topfill = curwin->w_height - n;
    }
}



    void scrolldown_clamp(void)
{
    int		end_row;

    int		can_fill = (curwin->w_topfill < diff_check_fill(curwin, curwin->w_topline));


    if (curwin->w_topline <= 1  && !can_fill  )



	return;

    validate_cursor();	    

    
    end_row = curwin->w_wrow;

    if (can_fill)
	++end_row;
    else end_row += plines_nofill(curwin->w_topline - 1);

    end_row += plines(curwin->w_topline - 1);

    if (curwin->w_p_wrap && curwin->w_width != 0)
    {
	validate_cheight();
	validate_virtcol();
	end_row += curwin->w_cline_height - 1 - curwin->w_virtcol / curwin->w_width;
    }
    if (end_row < curwin->w_height - get_scrolloff_value())
    {

	if (can_fill)
	{
	    ++curwin->w_topfill;
	    check_topfill(curwin, TRUE);
	}
	else {
	    --curwin->w_topline;
	    curwin->w_topfill = 0;
	}

	--curwin->w_topline;


	(void)hasFolding(curwin->w_topline, &curwin->w_topline, NULL);

	--curwin->w_botline;	    
	curwin->w_valid &= ~(VALID_WROW|VALID_CROW|VALID_BOTLINE);
    }
}


    void scrollup_clamp(void)
{
    int	    start_row;

    if (curwin->w_topline == curbuf->b_ml.ml_line_count  && curwin->w_topfill == 0  )



	return;

    validate_cursor();	    

    

    start_row = curwin->w_wrow - plines_nofill(curwin->w_topline)
							  - curwin->w_topfill;

    start_row = curwin->w_wrow - plines(curwin->w_topline);

    if (curwin->w_p_wrap && curwin->w_width != 0)
    {
	validate_virtcol();
	start_row -= curwin->w_virtcol / curwin->w_width;
    }
    if (start_row >= get_scrolloff_value())
    {

	if (curwin->w_topfill > 0)
	    --curwin->w_topfill;
	else  {


	    (void)hasFolding(curwin->w_topline, NULL, &curwin->w_topline);

	    ++curwin->w_topline;
	}
	++curwin->w_botline;		
	curwin->w_valid &= ~(VALID_WROW|VALID_CROW|VALID_BOTLINE);
    }
}


    static void topline_back(lineoff_T *lp)
{

    if (lp->fill < diff_check_fill(curwin, lp->lnum))
    {
	
	++lp->fill;
	lp->height = 1;
    }
    else  {

	--lp->lnum;

	lp->fill = 0;

	if (lp->lnum < 1)
	    lp->height = MAXCOL;
	else  if (hasFolding(lp->lnum, &lp->lnum, NULL))

	    
	    lp->height = 1;
	else  lp->height = PLINES_NOFILL(lp->lnum);

    }
}


    static void botline_forw(lineoff_T *lp)
{

    if (lp->fill < diff_check_fill(curwin, lp->lnum + 1))
    {
	
	++lp->fill;
	lp->height = 1;
    }
    else  {

	++lp->lnum;

	lp->fill = 0;

	if (lp->lnum > curbuf->b_ml.ml_line_count)
	    lp->height = MAXCOL;
	else  if (hasFolding(lp->lnum, NULL, &lp->lnum))

	    
	    lp->height = 1;
	else  lp->height = PLINES_NOFILL(lp->lnum);

    }
}



    static void botline_topline(lineoff_T *lp)
{
    if (lp->fill > 0)
    {
	++lp->lnum;
	lp->fill = diff_check_fill(curwin, lp->lnum) - lp->fill + 1;
    }
}


    static void topline_botline(lineoff_T *lp)
{
    if (lp->fill > 0)
    {
	lp->fill = diff_check_fill(curwin, lp->lnum) - lp->fill + 1;
	--lp->lnum;
    }
}



    void scroll_cursor_top(int min_scroll, int always)
{
    int		scrolled = 0;
    int		extra = 0;
    int		used;
    int		i;
    linenr_T	top;		
    linenr_T	bot;		
    linenr_T	old_topline = curwin->w_topline;

    linenr_T	old_topfill = curwin->w_topfill;

    linenr_T	new_topline;
    int		off = get_scrolloff_value();

    if (mouse_dragging > 0)
	off = mouse_dragging - 1;

    
    validate_cheight();
    used = curwin->w_cline_height; 
    if (curwin->w_cursor.lnum < curwin->w_topline)
	scrolled = used;


    if (hasFolding(curwin->w_cursor.lnum, &top, &bot))
    {
	--top;
	++bot;
    }
    else  {

	top = curwin->w_cursor.lnum - 1;
	bot = curwin->w_cursor.lnum + 1;
    }
    new_topline = top + 1;


    
    
    
    extra += diff_check_fill(curwin, curwin->w_cursor.lnum);


    
    while (top > 0)
    {

	if (hasFolding(top, &top, NULL))
	    
	    i = 1;
	else  i = PLINES_NOFILL(top);

	used += i;
	if (extra + i <= off && bot < curbuf->b_ml.ml_line_count)
	{

	    if (hasFolding(bot, NULL, &bot))
		
		++used;
	    else  used += plines(bot);

	}
	if (used > curwin->w_height)
	    break;
	if (top < curwin->w_topline)
	    scrolled += i;

	
	if ((new_topline >= curwin->w_topline || scrolled > min_scroll)
		&& extra >= off)
	    break;

	extra += i;
	new_topline = top;
	--top;
	++bot;
    }

    
    if (used > curwin->w_height)
	scroll_cursor_halfway(FALSE);
    else {
	
	if (new_topline < curwin->w_topline || always)
	    curwin->w_topline = new_topline;
	if (curwin->w_topline > curwin->w_cursor.lnum)
	    curwin->w_topline = curwin->w_cursor.lnum;

	curwin->w_topfill = diff_check_fill(curwin, curwin->w_topline);
	if (curwin->w_topfill > 0 && extra > off)
	{
	    curwin->w_topfill -= extra - off;
	    if (curwin->w_topfill < 0)
		curwin->w_topfill = 0;
	}
	check_topfill(curwin, FALSE);

	if (curwin->w_topline != old_topline  || curwin->w_topfill != old_topfill  )



	    curwin->w_valid &= ~(VALID_WROW|VALID_CROW|VALID_BOTLINE|VALID_BOTLINE_AP);
	curwin->w_valid |= VALID_TOPLINE;
    }
}


    void set_empty_rows(win_T *wp, int used)
{

    wp->w_filler_rows = 0;

    if (used == 0)
	wp->w_empty_rows = 0;	
    else {
	wp->w_empty_rows = wp->w_height - used;

	if (wp->w_botline <= wp->w_buffer->b_ml.ml_line_count)
	{
	    wp->w_filler_rows = diff_check_fill(wp, wp->w_botline);
	    if (wp->w_empty_rows > wp->w_filler_rows)
		wp->w_empty_rows -= wp->w_filler_rows;
	    else {
		wp->w_filler_rows = wp->w_empty_rows;
		wp->w_empty_rows = 0;
	    }
	}

    }
}


    void scroll_cursor_bot(int min_scroll, int set_topbot)
{
    int		used;
    int		scrolled = 0;
    int		extra = 0;
    int		i;
    linenr_T	line_count;
    linenr_T	old_topline = curwin->w_topline;
    lineoff_T	loff;
    lineoff_T	boff;

    int		old_topfill = curwin->w_topfill;
    int		fill_below_window;

    linenr_T	old_botline = curwin->w_botline;
    linenr_T	old_valid = curwin->w_valid;
    int		old_empty_rows = curwin->w_empty_rows;
    linenr_T	cln;		    
    long	so = get_scrolloff_value();

    cln = curwin->w_cursor.lnum;
    if (set_topbot)
    {
	used = 0;
	curwin->w_botline = cln + 1;

	loff.fill = 0;

	for (curwin->w_topline = curwin->w_botline;
		curwin->w_topline > 1;
		curwin->w_topline = loff.lnum)
	{
	    loff.lnum = curwin->w_topline;
	    topline_back(&loff);
	    if (loff.height == MAXCOL || used + loff.height > curwin->w_height)
		break;
	    used += loff.height;

	    curwin->w_topfill = loff.fill;

	}
	set_empty_rows(curwin, used);
	curwin->w_valid |= VALID_BOTLINE|VALID_BOTLINE_AP;
	if (curwin->w_topline != old_topline  || curwin->w_topfill != old_topfill  )



	    curwin->w_valid &= ~(VALID_WROW|VALID_CROW);
    }
    else validate_botline();

    

    used = plines_nofill(cln);

    validate_cheight();
    used = curwin->w_cline_height;


    
    
    
    if (cln >= curwin->w_botline)
    {
	scrolled = used;
	if (cln == curwin->w_botline)
	    scrolled -= curwin->w_empty_rows;
    }

    

    if (!hasFolding(curwin->w_cursor.lnum, &loff.lnum, &boff.lnum))

    {
	loff.lnum = cln;
	boff.lnum = cln;
    }

    loff.fill = 0;
    boff.fill = 0;
    fill_below_window = diff_check_fill(curwin, curwin->w_botline)
						      - curwin->w_filler_rows;


    while (loff.lnum > 1)
    {
	
	
	if ((((scrolled <= 0 || scrolled >= min_scroll)
		    && extra >= (mouse_dragging > 0 ? mouse_dragging - 1 : so))
		    || boff.lnum + 1 > curbuf->b_ml.ml_line_count)
		&& loff.lnum <= curwin->w_botline  && (loff.lnum < curwin->w_botline || loff.fill >= fill_below_window)



		)
	    break;

	
	topline_back(&loff);
	if (loff.height == MAXCOL)
	    used = MAXCOL;
	else used += loff.height;
	if (used > curwin->w_height)
	    break;
	if (loff.lnum >= curwin->w_botline  && (loff.lnum > curwin->w_botline || loff.fill <= fill_below_window)



		)
	{
	    
	    scrolled += loff.height;
	    if (loff.lnum == curwin->w_botline  && loff.fill == 0  )



		scrolled -= curwin->w_empty_rows;
	}

	if (boff.lnum < curbuf->b_ml.ml_line_count)
	{
	    
	    botline_forw(&boff);
	    used += boff.height;
	    if (used > curwin->w_height)
		break;
	    if (extra < ( mouse_dragging > 0 ? mouse_dragging - 1 : so)
		    || scrolled < min_scroll)
	    {
		extra += boff.height;
		if (boff.lnum >= curwin->w_botline  || (boff.lnum + 1 == curwin->w_botline && boff.fill > curwin->w_filler_rows)



		   )
		{
		    
		    scrolled += boff.height;
		    if (boff.lnum == curwin->w_botline  && boff.fill == 0  )



			scrolled -= curwin->w_empty_rows;
		}
	    }
	}
    }

    
    if (scrolled <= 0)
	line_count = 0;
    
    else if (used > curwin->w_height)
	line_count = used;
    
    else {
	line_count = 0;

	boff.fill = curwin->w_topfill;

	boff.lnum = curwin->w_topline - 1;
	for (i = 0; i < scrolled && boff.lnum < curwin->w_botline; )
	{
	    botline_forw(&boff);
	    i += boff.height;
	    ++line_count;
	}
	if (i < scrolled)	
	    line_count = 9999;
    }

    
    if (line_count >= curwin->w_height && line_count > min_scroll)
	scroll_cursor_halfway(FALSE);
    else scrollup(line_count, TRUE);

    
    if (curwin->w_topline == old_topline && set_topbot)
    {
	curwin->w_botline = old_botline;
	curwin->w_empty_rows = old_empty_rows;
	curwin->w_valid = old_valid;
    }
    curwin->w_valid |= VALID_TOPLINE;
}


    void scroll_cursor_halfway(int atend)
{
    int		above = 0;
    linenr_T	topline;

    int		topfill = 0;

    int		below = 0;
    int		used;
    lineoff_T	loff;
    lineoff_T	boff;

    linenr_T	old_topline = curwin->w_topline;



    
    may_update_popup_position();

    loff.lnum = boff.lnum = curwin->w_cursor.lnum;

    (void)hasFolding(loff.lnum, &loff.lnum, &boff.lnum);


    used = plines_nofill(loff.lnum);
    loff.fill = 0;
    boff.fill = 0;

    used = plines(loff.lnum);

    topline = loff.lnum;
    while (topline > 1)
    {
	if (below <= above)	    
	{
	    if (boff.lnum < curbuf->b_ml.ml_line_count)
	    {
		botline_forw(&boff);
		used += boff.height;
		if (used > curwin->w_height)
		    break;
		below += boff.height;
	    }
	    else {
		++below;	    
		if (atend)
		    ++used;
	    }
	}

	if (below > above)	    
	{
	    topline_back(&loff);
	    if (loff.height == MAXCOL)
		used = MAXCOL;
	    else used += loff.height;
	    if (used > curwin->w_height)
		break;
	    above += loff.height;
	    topline = loff.lnum;

	    topfill = loff.fill;

	}
    }

    if (!hasFolding(topline, &curwin->w_topline, NULL))

	curwin->w_topline = topline;

    curwin->w_topfill = topfill;
    if (old_topline > curwin->w_topline + curwin->w_height)
	curwin->w_botfill = FALSE;
    check_topfill(curwin, FALSE);

    curwin->w_valid &= ~(VALID_WROW|VALID_CROW|VALID_BOTLINE|VALID_BOTLINE_AP);
    curwin->w_valid |= VALID_TOPLINE;
}


    void cursor_correct(void)
{
    int		above = 0;	    
    linenr_T	topline;
    int		below = 0;	    
    linenr_T	botline;
    int		above_wanted, below_wanted;
    linenr_T	cln;		    
    int		max_off;
    long	so = get_scrolloff_value();

    
    above_wanted = so;
    below_wanted = so;
    if (mouse_dragging > 0)
    {
	above_wanted = mouse_dragging - 1;
	below_wanted = mouse_dragging - 1;
    }
    if (curwin->w_topline == 1)
    {
	above_wanted = 0;
	max_off = curwin->w_height / 2;
	if (below_wanted > max_off)
	    below_wanted = max_off;
    }
    validate_botline();
    if (curwin->w_botline == curbuf->b_ml.ml_line_count + 1 && mouse_dragging == 0)
    {
	below_wanted = 0;
	max_off = (curwin->w_height - 1) / 2;
	if (above_wanted > max_off)
	    above_wanted = max_off;
    }

    
    cln = curwin->w_cursor.lnum;
    if (cln >= curwin->w_topline + above_wanted && cln < curwin->w_botline - below_wanted  && !hasAnyFolding(curwin)



	    )
	return;

    
    topline = curwin->w_topline;
    botline = curwin->w_botline - 1;

    
    above = curwin->w_topfill;
    below = curwin->w_filler_rows;

    while ((above < above_wanted || below < below_wanted) && topline < botline)
    {
	if (below < below_wanted && (below <= above || above >= above_wanted))
	{

	    if (hasFolding(botline, &botline, NULL))
		++below;
	    else  below += plines(botline);

	    --botline;
	}
	if (above < above_wanted && (above < below || below >= below_wanted))
	{

	    if (hasFolding(topline, NULL, &topline))
		++above;
	    else  above += PLINES_NOFILL(topline);


	    
	    if (topline < botline)
		above += diff_check_fill(curwin, topline + 1);

	    ++topline;
	}
    }
    if (topline == botline || botline == 0)
	curwin->w_cursor.lnum = topline;
    else if (topline > botline)
	curwin->w_cursor.lnum = botline;
    else {
	if (cln < topline && curwin->w_topline > 1)
	{
	    curwin->w_cursor.lnum = topline;
	    curwin->w_valid &= ~(VALID_WROW|VALID_WCOL|VALID_CHEIGHT|VALID_CROW);
	}
	if (cln > botline && curwin->w_botline <= curbuf->b_ml.ml_line_count)
	{
	    curwin->w_cursor.lnum = botline;
	    curwin->w_valid &= ~(VALID_WROW|VALID_WCOL|VALID_CHEIGHT|VALID_CROW);
	}
    }
    curwin->w_valid |= VALID_TOPLINE;
}

static void get_scroll_overlap(lineoff_T *lp, int dir);


    int onepage(int dir, long count)
{
    long	n;
    int		retval = OK;
    lineoff_T	loff;
    linenr_T	old_topline = curwin->w_topline;
    long	so = get_scrolloff_value();

    if (curbuf->b_ml.ml_line_count == 1)    
    {
	beep_flush();
	return FAIL;
    }

    for ( ; count > 0; --count)
    {
	validate_botline();
	
	if (dir == FORWARD ? ((curwin->w_topline >= curbuf->b_ml.ml_line_count - so)
		    && curwin->w_botline > curbuf->b_ml.ml_line_count)
		: (curwin->w_topline == 1  && curwin->w_topfill == diff_check_fill(curwin, curwin->w_topline)



		    ))
	{
	    beep_flush();
	    retval = FAIL;
	    break;
	}


	loff.fill = 0;

	if (dir == FORWARD)
	{
	    if (ONE_WINDOW && p_window > 0 && p_window < Rows - 1)
	    {
		
		if (p_window <= 2)
		    ++curwin->w_topline;
		else curwin->w_topline += p_window - 2;
		if (curwin->w_topline > curbuf->b_ml.ml_line_count)
		    curwin->w_topline = curbuf->b_ml.ml_line_count;
		curwin->w_cursor.lnum = curwin->w_topline;
	    }
	    else if (curwin->w_botline > curbuf->b_ml.ml_line_count)
	    {
		
		curwin->w_topline = curbuf->b_ml.ml_line_count;

		curwin->w_topfill = 0;

		curwin->w_valid &= ~(VALID_WROW|VALID_CROW);
	    }
	    else {
		
		
		loff.lnum = curwin->w_botline;

		loff.fill = diff_check_fill(curwin, loff.lnum)
						      - curwin->w_filler_rows;

		get_scroll_overlap(&loff, -1);
		curwin->w_topline = loff.lnum;

		curwin->w_topfill = loff.fill;
		check_topfill(curwin, FALSE);

		curwin->w_cursor.lnum = curwin->w_topline;
		curwin->w_valid &= ~(VALID_WCOL|VALID_CHEIGHT|VALID_WROW| VALID_CROW|VALID_BOTLINE|VALID_BOTLINE_AP);
	    }
	}
	else	 {

	    if (curwin->w_topline == 1)
	    {
		
		max_topfill();
		continue;
	    }

	    if (ONE_WINDOW && p_window > 0 && p_window < Rows - 1)
	    {
		
		if (p_window <= 2)
		    --curwin->w_topline;
		else curwin->w_topline -= p_window - 2;
		if (curwin->w_topline < 1)
		    curwin->w_topline = 1;
		curwin->w_cursor.lnum = curwin->w_topline + p_window - 1;
		if (curwin->w_cursor.lnum > curbuf->b_ml.ml_line_count)
		    curwin->w_cursor.lnum = curbuf->b_ml.ml_line_count;
		continue;
	    }

	    
	    
	    
	    loff.lnum = curwin->w_topline - 1;

	    loff.fill = diff_check_fill(curwin, loff.lnum + 1)
							  - curwin->w_topfill;

	    get_scroll_overlap(&loff, 1);

	    if (loff.lnum >= curbuf->b_ml.ml_line_count)
	    {
		loff.lnum = curbuf->b_ml.ml_line_count;

		loff.fill = 0;
	    }
	    else {
		botline_topline(&loff);

	    }
	    curwin->w_cursor.lnum = loff.lnum;

	    
	    
	    n = 0;
	    while (n <= curwin->w_height && loff.lnum >= 1)
	    {
		topline_back(&loff);
		if (loff.height == MAXCOL)
		    n = MAXCOL;
		else n += loff.height;
	    }
	    if (loff.lnum < 1)			
	    {
		curwin->w_topline = 1;

		max_topfill();

		curwin->w_valid &= ~(VALID_WROW|VALID_CROW|VALID_BOTLINE);
	    }
	    else {
		

		topline_botline(&loff);

		botline_forw(&loff);
		botline_forw(&loff);

		botline_topline(&loff);


		
		(void)hasFolding(loff.lnum, &loff.lnum, NULL);


		
		
		if (loff.lnum >= curwin->w_topline  && (loff.lnum > curwin->w_topline || loff.fill >= curwin->w_topfill)



			)
		{

		    
		    
		    loff.fill = curwin->w_topfill;
		    if (curwin->w_topfill < diff_check_fill(curwin, curwin->w_topline))
			max_topfill();
		    if (curwin->w_topfill == loff.fill)

		    {
			--curwin->w_topline;

			curwin->w_topfill = 0;

		    }
		    comp_botline(curwin);
		    curwin->w_cursor.lnum = curwin->w_botline - 1;
		    curwin->w_valid &= ~(VALID_WCOL|VALID_CHEIGHT|VALID_WROW|VALID_CROW);
		}
		else {
		    curwin->w_topline = loff.lnum;

		    curwin->w_topfill = loff.fill;
		    check_topfill(curwin, FALSE);

		    curwin->w_valid &= ~(VALID_WROW|VALID_CROW|VALID_BOTLINE);
		}
	    }
	}
    }

    foldAdjustCursor();

    cursor_correct();
    check_cursor_col();
    if (retval == OK)
	beginline(BL_SOL | BL_FIX);
    curwin->w_valid &= ~(VALID_WCOL|VALID_WROW|VALID_VIRTCOL);

    if (retval == OK && dir == FORWARD)
    {
	
	
	
	if (check_top_offset())
	{
	    scroll_cursor_top(1, FALSE);
	    if (curwin->w_topline <= old_topline && old_topline < curbuf->b_ml.ml_line_count)
	    {
		curwin->w_topline = old_topline + 1;

		(void)hasFolding(curwin->w_topline, &curwin->w_topline, NULL);

	    }
	}

	else if (curwin->w_botline > curbuf->b_ml.ml_line_count)
	    (void)hasFolding(curwin->w_topline, &curwin->w_topline, NULL);

    }

    redraw_later(UPD_VALID);
    return retval;
}


    static void get_scroll_overlap(lineoff_T *lp, int dir)
{
    int		h1, h2, h3, h4;
    int		min_height = curwin->w_height - 2;
    lineoff_T	loff0, loff1, loff2;


    if (lp->fill > 0)
	lp->height = 1;
    else lp->height = plines_nofill(lp->lnum);

    lp->height = plines(lp->lnum);

    h1 = lp->height;
    if (h1 > min_height)
	return;		

    loff0 = *lp;
    if (dir > 0)
	botline_forw(lp);
    else topline_back(lp);
    h2 = lp->height;
    if (h2 == MAXCOL || h2 + h1 > min_height)
    {
	*lp = loff0;	
	return;
    }

    loff1 = *lp;
    if (dir > 0)
	botline_forw(lp);
    else topline_back(lp);
    h3 = lp->height;
    if (h3 == MAXCOL || h3 + h2 > min_height)
    {
	*lp = loff0;	
	return;
    }

    loff2 = *lp;
    if (dir > 0)
	botline_forw(lp);
    else topline_back(lp);
    h4 = lp->height;
    if (h4 == MAXCOL || h4 + h3 + h2 > min_height || h3 + h2 + h1 > min_height)
	*lp = loff1;	
    else *lp = loff2;
}


    void halfpage(int flag, linenr_T Prenum)
{
    long	scrolled = 0;
    int		i;
    int		n;
    int		room;

    if (Prenum)
	curwin->w_p_scr = (Prenum > curwin->w_height) ? curwin->w_height : Prenum;
    n = (curwin->w_p_scr <= curwin->w_height) ? curwin->w_p_scr : curwin->w_height;

    update_topline();
    validate_botline();
    room = curwin->w_empty_rows;

    room += curwin->w_filler_rows;

    if (flag)
    {
	
	while (n > 0 && curwin->w_botline <= curbuf->b_ml.ml_line_count)
	{

	    if (curwin->w_topfill > 0)
	    {
		i = 1;
		--n;
		--curwin->w_topfill;
	    }
	    else  {

		i = PLINES_NOFILL(curwin->w_topline);
		n -= i;
		if (n < 0 && scrolled > 0)
		    break;

		(void)hasFolding(curwin->w_topline, NULL, &curwin->w_topline);

		++curwin->w_topline;

		curwin->w_topfill = diff_check_fill(curwin, curwin->w_topline);


		if (curwin->w_cursor.lnum < curbuf->b_ml.ml_line_count)
		{
		    ++curwin->w_cursor.lnum;
		    curwin->w_valid &= ~(VALID_VIRTCOL|VALID_CHEIGHT|VALID_WCOL);
		}
	    }
	    curwin->w_valid &= ~(VALID_CROW|VALID_WROW);
	    scrolled += i;

	    

	    if (curwin->w_p_diff)
		curwin->w_valid &= ~(VALID_BOTLINE|VALID_BOTLINE_AP);
	    else  {

		room += i;
		do {
		    i = plines(curwin->w_botline);
		    if (i > room)
			break;

		    (void)hasFolding(curwin->w_botline, NULL, &curwin->w_botline);

		    ++curwin->w_botline;
		    room -= i;
		} while (curwin->w_botline <= curbuf->b_ml.ml_line_count);
	    }
	}

	
	if (n > 0)
	{

	    if (hasAnyFolding(curwin))
	    {
		while (--n >= 0 && curwin->w_cursor.lnum < curbuf->b_ml.ml_line_count)
		{
		    (void)hasFolding(curwin->w_cursor.lnum, NULL, &curwin->w_cursor.lnum);
		    ++curwin->w_cursor.lnum;
		}
	    }
	    else  curwin->w_cursor.lnum += n;

	    check_cursor_lnum();
	}
    }
    else {
	
	while (n > 0 && curwin->w_topline > 1)
	{

	    if (curwin->w_topfill < diff_check_fill(curwin, curwin->w_topline))
	    {
		i = 1;
		--n;
		++curwin->w_topfill;
	    }
	    else  {

		i = PLINES_NOFILL(curwin->w_topline - 1);
		n -= i;
		if (n < 0 && scrolled > 0)
		    break;
		--curwin->w_topline;

		(void)hasFolding(curwin->w_topline, &curwin->w_topline, NULL);


		curwin->w_topfill = 0;

	    }
	    curwin->w_valid &= ~(VALID_CROW|VALID_WROW| VALID_BOTLINE|VALID_BOTLINE_AP);
	    scrolled += i;
	    if (curwin->w_cursor.lnum > 1)
	    {
		--curwin->w_cursor.lnum;
		curwin->w_valid &= ~(VALID_VIRTCOL|VALID_CHEIGHT|VALID_WCOL);
	    }
	}

	
	if (n > 0)
	{
	    if (curwin->w_cursor.lnum <= (linenr_T)n)
		curwin->w_cursor.lnum = 1;
	    else  if (hasAnyFolding(curwin))

	    {
		while (--n >= 0 && curwin->w_cursor.lnum > 1)
		{
		    --curwin->w_cursor.lnum;
		    (void)hasFolding(curwin->w_cursor.lnum, &curwin->w_cursor.lnum, NULL);
		}
	    }
	    else  curwin->w_cursor.lnum -= n;

	}
    }

    
    foldAdjustCursor();


    check_topfill(curwin, !flag);

    cursor_correct();
    beginline(BL_SOL | BL_FIX);
    redraw_later(UPD_VALID);
}

    void do_check_cursorbind(void)
{
    linenr_T	line = curwin->w_cursor.lnum;
    colnr_T	col = curwin->w_cursor.col;
    colnr_T	coladd = curwin->w_cursor.coladd;
    colnr_T	curswant = curwin->w_curswant;
    int		set_curswant = curwin->w_set_curswant;
    win_T	*old_curwin = curwin;
    buf_T	*old_curbuf = curbuf;
    int		restart_edit_save;
    int		old_VIsual_select = VIsual_select;
    int		old_VIsual_active = VIsual_active;

    
    VIsual_select = VIsual_active = 0;
    FOR_ALL_WINDOWS(curwin)
    {
	curbuf = curwin->w_buffer;
	
	if (curwin != old_curwin && curwin->w_p_crb)
	{

	    if (curwin->w_p_diff)
		curwin->w_cursor.lnum = diff_get_corresponding_line(old_curbuf, line);
	    else  curwin->w_cursor.lnum = line;

	    curwin->w_cursor.col = col;
	    curwin->w_cursor.coladd = coladd;
	    curwin->w_curswant = curswant;
	    curwin->w_set_curswant = set_curswant;

	    
	    
	    restart_edit_save = restart_edit;
	    restart_edit = TRUE;
	    check_cursor();

	    
	    
	    if (!curwin->w_p_scb)
		validate_cursor();

	    restart_edit = restart_edit_save;
	    
	    if (has_mbyte)
		mb_adjust_cursor();
	    redraw_later(UPD_VALID);

	    
	    if (!curwin->w_p_scb)
		update_topline();
	    curwin->w_redr_status = TRUE;
	}
    }

    
    VIsual_select = old_VIsual_select;
    VIsual_active = old_VIsual_active;
    curwin = old_curwin;
    curbuf = old_curbuf;
}
