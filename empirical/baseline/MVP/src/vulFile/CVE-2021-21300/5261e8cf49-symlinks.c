

static int threaded_check_leading_path(struct cache_def *cache, const char *name, int len);
static int threaded_has_dirs_only_path(struct cache_def *cache, const char *name, int len, int prefix_len);


static int longest_path_match(const char *name_a, int len_a, const char *name_b, int len_b, int *previous_slash)

{
	int max_len, match_len = 0, match_len_prev = 0, i = 0;

	max_len = len_a < len_b ? len_a : len_b;
	while (i < max_len && name_a[i] == name_b[i]) {
		if (name_a[i] == '/') {
			match_len_prev = match_len;
			match_len = i;
		}
		i++;
	}
	
	if (i >= max_len && ((len_a > len_b && name_a[len_b] == '/') || (len_a < len_b && name_b[len_a] == '/') || (len_a == len_b))) {

		match_len_prev = match_len;
		match_len = i;
	}
	*previous_slash = match_len_prev;
	return match_len;
}

static struct cache_def default_cache = CACHE_DEF_INIT;

static inline void reset_lstat_cache(struct cache_def *cache)
{
	strbuf_reset(&cache->path);
	cache->flags = 0;
	
}









static int lstat_cache_matchlen(struct cache_def *cache, const char *name, int len, int *ret_flags, int track_flags, int prefix_len_stat_func)


{
	int match_len, last_slash, last_slash_dir, previous_slash;
	int save_flags, ret;
	struct stat st;

	if (cache->track_flags != track_flags || cache->prefix_len_stat_func != prefix_len_stat_func) {
		
		reset_lstat_cache(cache);
		cache->track_flags = track_flags;
		cache->prefix_len_stat_func = prefix_len_stat_func;
		match_len = last_slash = 0;
	} else {
		
		match_len = last_slash = longest_path_match(name, len, cache->path.buf, cache->path.len, &previous_slash);

		*ret_flags = cache->flags & track_flags & (FL_NOENT|FL_SYMLINK);

		if (!(track_flags & FL_FULLPATH) && match_len == len)
			match_len = last_slash = previous_slash;

		if (*ret_flags && match_len == cache->path.len)
			return match_len;
		
		*ret_flags = track_flags & FL_DIR;
		if (*ret_flags && len == match_len)
			return match_len;
	}

	
	*ret_flags = FL_DIR;
	last_slash_dir = last_slash;
	if (len > cache->path.len)
		strbuf_grow(&cache->path, len - cache->path.len);
	while (match_len < len) {
		do {
			cache->path.buf[match_len] = name[match_len];
			match_len++;
		} while (match_len < len && name[match_len] != '/');
		if (match_len >= len && !(track_flags & FL_FULLPATH))
			break;
		last_slash = match_len;
		cache->path.buf[last_slash] = '\0';

		if (last_slash <= prefix_len_stat_func)
			ret = stat(cache->path.buf, &st);
		else ret = lstat(cache->path.buf, &st);

		if (ret) {
			*ret_flags = FL_LSTATERR;
			if (errno == ENOENT)
				*ret_flags |= FL_NOENT;
		} else if (S_ISDIR(st.st_mode)) {
			last_slash_dir = last_slash;
			continue;
		} else if (S_ISLNK(st.st_mode)) {
			*ret_flags = FL_SYMLINK;
		} else {
			*ret_flags = FL_ERR;
		}
		break;
	}

	
	save_flags = *ret_flags & track_flags & (FL_NOENT|FL_SYMLINK);
	if (save_flags && last_slash > 0) {
		cache->path.buf[last_slash] = '\0';
		cache->path.len = last_slash;
		cache->flags = save_flags;
	} else if ((track_flags & FL_DIR) && last_slash_dir > 0) {
		
		cache->path.buf[last_slash_dir] = '\0';
		cache->path.len = last_slash_dir;
		cache->flags = FL_DIR;
	} else {
		reset_lstat_cache(cache);
	}
	return match_len;
}

static int lstat_cache(struct cache_def *cache, const char *name, int len, int track_flags, int prefix_len_stat_func)
{
	int flags;
	(void)lstat_cache_matchlen(cache, name, len, &flags, track_flags, prefix_len_stat_func);
	return flags;
}




int threaded_has_symlink_leading_path(struct cache_def *cache, const char *name, int len)
{
	return lstat_cache(cache, name, len, FL_SYMLINK|FL_DIR, USE_ONLY_LSTAT) & FL_SYMLINK;
}


int has_symlink_leading_path(const char *name, int len)
{
	return threaded_has_symlink_leading_path(&default_cache, name, len);
}


int check_leading_path(const char *name, int len)
{
    return threaded_check_leading_path(&default_cache, name, len);
}


static int threaded_check_leading_path(struct cache_def *cache, const char *name, int len)
{
	int flags;
	int match_len = lstat_cache_matchlen(cache, name, len, &flags, FL_SYMLINK|FL_NOENT|FL_DIR, USE_ONLY_LSTAT);
	if (flags & FL_NOENT)
		return 0;
	else if (flags & FL_DIR)
		return -1;
	else return match_len;
}


int has_dirs_only_path(const char *name, int len, int prefix_len)
{
	return threaded_has_dirs_only_path(&default_cache, name, len, prefix_len);
}


static int threaded_has_dirs_only_path(struct cache_def *cache, const char *name, int len, int prefix_len)
{
	return lstat_cache(cache, name, len, FL_DIR|FL_FULLPATH, prefix_len) & FL_DIR;

}

static struct strbuf removal = STRBUF_INIT;

static void do_remove_scheduled_dirs(int new_len)
{
	while (removal.len > new_len) {
		removal.buf[removal.len] = '\0';
		if (rmdir(removal.buf))
			break;
		do {
			removal.len--;
		} while (removal.len > new_len && removal.buf[removal.len] != '/');
	}
	removal.len = new_len;
}

void schedule_dir_for_removal(const char *name, int len)
{
	int match_len, last_slash, i, previous_slash;

	match_len = last_slash = i = longest_path_match(name, len, removal.buf, removal.len, &previous_slash);

	
	while (i < len) {
		if (name[i] == '/')
			last_slash = i;
		i++;
	}

	
	if (match_len < last_slash && match_len < removal.len)
		do_remove_scheduled_dirs(match_len);
	
	if (match_len < last_slash)
		strbuf_add(&removal, &name[match_len], last_slash - match_len);
}

void remove_scheduled_dirs(void)
{
	do_remove_scheduled_dirs(0);
}
