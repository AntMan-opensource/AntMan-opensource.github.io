







R_API char *r_cons_hud_file(const char *f) {
	char *s = r_file_slurp (f, NULL);
	if (s) {
		char *ret = r_cons_hud_string (s);
		free (s);
		return ret;
	}
	return NULL;
}



R_API char *r_cons_hud_line_string(const char *s) {
	if (!r_cons_is_interactive ()) {
		R_LOG_ERROR ("Hud mode requires scr.interactive=true");
		return NULL;
	}
	char *os, *track, *ret, *o = strdup (s);
	if (!o) {
		return NULL;
	}
	r_str_replace_ch (o, '\r', 0, true);
	r_str_replace_ch (o, '\t', 0, true);
	RList *fl = r_list_new ();
	int i;
	if (!fl) {
		free (o);
		return NULL;
	}
	fl->free = free;
	for (os = o, i = 0; o[i]; i++) {
		if (o[i] == '\n') {
			o[i] = 0;
			if (*os && *os != '#') {
				track = strdup (os);
				if (!r_list_append (fl, track)) {
					free (track);
					break;
				}
			}
			os = o + i + 1;
		}
	}
	ret = r_cons_hud_line (fl, NULL);
	free (o);
	r_list_free (fl);
	return ret;
}



R_API char *r_cons_hud_string(const char *s) {
	if (!r_cons_is_interactive ()) {
		R_LOG_ERROR ("Hud mode requires scr.interactive=true");
		return NULL;
	}
	char *os, *track, *ret, *o = strdup (s);
	if (!o) {
		return NULL;
	}
	r_str_replace_ch (o, '\r', 0, true);
	r_str_replace_ch (o, '\t', 0, true);
	RList *fl = r_list_new ();
	int i;
	if (!fl) {
		free (o);
		return NULL;
	}
	fl->free = free;
	for (os = o, i = 0; o[i]; i++) {
		if (o[i] == '\n') {
			o[i] = 0;
			if (*os && *os != '#') {
				track = strdup (os);
				if (!r_list_append (fl, track)) {
					free (track);
					break;
				}
			}
			os = o + i + 1;
		}
	}
	ret = r_cons_hud (fl, NULL);
	free (o);
	r_list_free (fl);
	return ret;
}


static bool __matchString(char *entry, char *filter, char *mask, const int mask_size) {
	char *p, *current_token = filter;
	const char *filter_end = filter + strlen (filter);
	char *ansi_filtered = strdup (entry);
	int *cps;
	r_str_ansi_filter (ansi_filtered, NULL, &cps, -1);
	entry = ansi_filtered;
	
	
	for (p = filter; p <= filter_end; p++) {
		if (*p == ' ' || *p == '\0') {
			const char *next_match, *entry_ptr = entry;
			char old_char = *p;
			int token_len;

			
			if (p == current_token) {
				current_token++;
				continue;
			}
			*p = 0;
			token_len = strlen (current_token);
			
			while ((next_match = r_str_casestr (entry_ptr, current_token))) {
				int real_pos, filtered_pos = next_match - entry;
				int end_pos = cps[filtered_pos + token_len];
				for (real_pos = cps[filtered_pos];
					real_pos < end_pos && real_pos < mask_size;
					real_pos = cps[++filtered_pos]) {
					mask[real_pos] = 'x';
				}
				entry_ptr += token_len;
			}
			*p = old_char;
			if (entry_ptr == entry) {
				
				free (cps);
				free (ansi_filtered);
				return false;
			}
			current_token = p + 1;
		}
	}
	free (cps);
	free (ansi_filtered);
	return true;
}

static RList *hud_filter(RList *list, char *user_input, int top_entry_n, int *current_entry_n, char **selected_entry, bool simple) {
	RListIter *iter;
	char *current_entry;
	char mask[HUD_BUF_SIZE];
	char *p, *x;
	int j, rows;
	(void) r_cons_get_size (&rows);
	int counter = 0;
	bool first_line = true;
	RList *res = r_list_newf (free);
	r_list_foreach (list, iter, current_entry) {
		memset (mask, 0, HUD_BUF_SIZE);
		if (*user_input && !__matchString (current_entry, user_input, mask, HUD_BUF_SIZE)) {
			continue;
		}
		if (++counter == rows + top_entry_n) {
			break;
		}
		
		if (!top_entry_n || *current_entry_n >= top_entry_n) {
			
			x = strchr (current_entry, '\t');
			if (x) {
				*x = 0;
			}
			p = strdup (current_entry);
			
			if (simple) {
				for (j = 0; p[j] && user_input[0]; j++) {
					if (mask[j]) {
						p[j] = toupper ((unsigned char) p[j]);
					}
				}
				r_list_append (res, strdup (p));
			} else if (!user_input[0]) {
				r_list_append (res, r_str_newf (" %c %s", first_line? '-': ' ', p));
			} else {
				
				if (I (context->color_mode)) {
					int last_color_change = 0;
					int last_mask = 0;
					char *str = r_str_newf (" %c ", first_line? '-': ' ');
					
					
					for (j = 0; p[j] && j < HUD_BUF_SIZE; j++) {
						if (mask[j] != last_mask) {
							char tmp = p[j];
							p[j] = 0;
							if (mask[j]) {
								str = r_str_appendf (str, Color_RESET "%s", p + last_color_change);
							} else {
								str = r_str_appendf (str, Color_GREEN "%s", p + last_color_change);
							}
							p[j] = tmp;
							last_color_change = j;
							last_mask = mask[j];
						}
					}
					if (last_mask) {
						str = r_str_appendf (str, Color_GREEN "%s"Color_RESET, p + last_color_change);
					} else {
						str = r_str_appendf (str, Color_RESET "%s", p + last_color_change);
					}
					r_list_append (res, str);
				} else {
					
					for (j = 0; p[j]; j++) {
						if (mask[j]) {
							p[j] = toupper ((unsigned char) p[j]);
						}
					}
					r_list_append (res, r_str_newf (" %c %s", first_line? '-': ' ', p));
				}
			}
			
			free (p);
			if (x) {
				*x = '\t';
			}
			if (first_line) {
				*selected_entry = current_entry;
			}
			first_line = false;
		}
		(*current_entry_n)++;

	}
	return res;
}

static void mht_free_kv(HtPPKv *kv) {
	free (kv->key);
	r_list_free (kv->value);
}




R_API char *r_cons_hud(RList *list, const char *prompt) {
	bool demo = r_cons_singleton ()->context->demo;
	char user_input[HUD_BUF_SIZE + 1];
	char *selected_entry = NULL;
	RListIter *iter;

	HtPP *ht = ht_pp_new (NULL, (HtPPKvFreeFunc)mht_free_kv, (HtPPCalcSizeV)strlen);
	RLineHud *hud = (RLineHud*) R_NEW (RLineHud);
	hud->activate = 0;
	hud->vi = 0;
	I(line)->echo = false;
	I(line)->hud = hud;
	user_input [0] = 0;
	user_input[HUD_BUF_SIZE] = 0;
	hud->top_entry_n = 0;
	r_cons_show_cursor (false);
	r_cons_enable_mouse (false);
	r_cons_set_raw (true);
	r_cons_clear ();

	
	for (;;) {
		r_cons_gotoxy (0, 0);
		hud->current_entry_n = 0;

		if (hud->top_entry_n < 0) {
			hud->top_entry_n = 0;
		}
		selected_entry = NULL;
		char *p = NULL;
		if (prompt && *prompt) {
			p = r_str_appendf (p, ">> %s\n", prompt);
		}
		p = r_str_appendf (p, "%d> %s|\n", hud->top_entry_n, user_input);
		if (p) {
			if (demo) {
				char *q = r_str_ss (p, NULL, 0);
				free (p);
				p = q;
			}
			r_cons_printf ("%s", p);
			free (p);
		}
		char *row;
		RList *filtered_list = NULL;

		bool found = false;
		filtered_list = ht_pp_find (ht, user_input, &found);
		if (!found) {
			filtered_list = hud_filter (list, user_input, hud->top_entry_n, &(hud->current_entry_n), &selected_entry, false);

			ht_pp_insert (ht, user_input, filtered_list);

		}
		r_list_foreach (filtered_list, iter, row) {
			r_cons_printf ("%s\n", row);
		}
		if (!filtered_list->length) {				
			printf ("%s", R_CONS_CLEAR_LINE);
		}

		r_list_free (filtered_list);

		r_cons_visual_flush ();
		(void) r_line_readline ();
		r_str_ncpy (user_input, I(line)->buffer.data, HUD_BUF_SIZE);

		if (!hud->activate) {
			hud->top_entry_n = 0;
			if (hud->current_entry_n >= 1 ) {
				if (selected_entry) {
					R_FREE (I(line)->hud);
					I(line)->echo = true;
					r_cons_enable_mouse (false);
					r_cons_show_cursor (true);
					r_cons_set_raw (false);
					return strdup (selected_entry);
				}
			} else {
				goto _beach;
			}
		}
	}
_beach:
	R_FREE (I(line)->hud);
	I(line)->echo = true;
	r_cons_show_cursor (true);
	r_cons_enable_mouse (false);
	r_cons_set_raw (false);
	ht_pp_free (ht);
	return NULL;
}

R_API char *r_cons_hud_line(RList *list, const char *prompt) {
	char user_input[HUD_BUF_SIZE + 1];
	char *selected_entry = NULL;
	RListIter *iter;

	HtPP *ht = ht_pp_new (NULL, (HtPPKvFreeFunc)mht_free_kv, (HtPPCalcSizeV)strlen);
	RLineHud *hud = (RLineHud*) R_NEW (RLineHud);
	hud->activate = 0;
	hud->vi = 0;
	I(line)->echo = false;
	I(line)->hud = hud;
	user_input [0] = 0;
	user_input[HUD_BUF_SIZE] = 0;
	hud->top_entry_n = 0;
	r_cons_show_cursor (false);
	r_cons_enable_mouse (false);
	r_cons_set_raw (true);

	r_cons_reset ();
	
	for (;;) {
		hud->current_entry_n = 0;

		if (hud->top_entry_n < 0) {
			hud->top_entry_n = 0;
		}
		selected_entry = NULL;
		r_cons_printf ("\r%s", R_CONS_CLEAR_LINE);
		if (prompt && *prompt) {
			r_cons_printf (">> %s [ ", prompt);
		}
		char *row;

		bool found = false;
		RList *filtered_list = ht_pp_find (ht, user_input, &found);
		if (!found) {
			filtered_list = hud_filter (list, user_input, hud->top_entry_n, &(hud->current_entry_n), &selected_entry, true);

			ht_pp_insert (ht, user_input, filtered_list);

		}
		r_cons_printf ("(%d)> %s [", r_list_length (filtered_list), user_input);
		int slen = 0;
		int w = r_cons_get_size (NULL);
		r_list_foreach (filtered_list, iter, row) {
			slen += strlen (row);
			if (slen >= w) {
				break;
			}
			r_cons_printf (" %s,", row);
		}

		r_list_free (filtered_list);

		r_cons_printf ("]");
		r_cons_flush ();
		(void) r_line_readline ();
		r_str_ncpy (user_input, I(line)->buffer.data, HUD_BUF_SIZE);

		if (!hud->activate) {
			hud->top_entry_n = 0;
			if (hud->current_entry_n >= 1 ) {
				if (selected_entry) {
					R_FREE (I(line)->hud);
					I(line)->echo = true;
					r_cons_enable_mouse (false);
					r_cons_show_cursor (true);
					r_cons_set_raw (false);
					return strdup (selected_entry);
				}
			} else {
				goto _beach;
			}
		}
	}
_beach:
	R_FREE (I(line)->hud);
	I(line)->echo = true;
	r_cons_show_cursor (true);
	r_cons_enable_mouse (false);
	r_cons_set_raw (false);
	ht_pp_free (ht);
	return NULL;
}


R_API char *r_cons_hud_path(const char *path, int dir) {
	char *tmp, *ret = NULL;
	RList *files;
	if (path) {
		path = r_str_trim_head_ro (path);
		tmp = strdup (*path ? path : "./");
	} else {
		tmp = strdup ("./");
	}
	files = r_sys_dir (tmp);
	if (files) {
		ret = r_cons_hud (files, tmp);
		if (ret) {
			tmp = r_str_append (tmp, "/");
			tmp = r_str_append (tmp, ret);
			free (ret);
			ret = r_file_abspath (tmp);
			free (tmp);
			tmp = ret;
			if (r_file_is_directory (tmp)) {
				ret = r_cons_hud_path (tmp, dir);
				free (tmp);
				tmp = ret;
			}
		}
		r_list_free (files);
	} else {
		R_LOG_ERROR ("No files found");
	}
	if (!ret) {
		free (tmp);
		return NULL;
	}
	return tmp;
}

R_API char *r_cons_message(const char *msg) {
	int len = strlen (msg);
	int rows, cols = r_cons_get_size (&rows);
	r_cons_clear ();
	r_cons_gotoxy ((cols - len) / 2, rows / 2);
	r_cons_println (msg);
	r_cons_flush ();
	r_cons_gotoxy (0, rows - 2);
	r_cons_any_key (NULL);
	return NULL;
}
