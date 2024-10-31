














void sudo_lbuf_init_v1(struct sudo_lbuf *lbuf, sudo_lbuf_output_t output, int indent, const char *continuation, int cols)

{
    debug_decl(sudo_lbuf_init, SUDO_DEBUG_UTIL);

    lbuf->output = output;
    lbuf->continuation = continuation;
    lbuf->indent = indent;
    lbuf->cols = cols;
    lbuf->error = 0;
    lbuf->len = 0;
    lbuf->size = 0;
    lbuf->buf = NULL;

    debug_return;
}

void sudo_lbuf_destroy_v1(struct sudo_lbuf *lbuf)
{
    debug_decl(sudo_lbuf_destroy, SUDO_DEBUG_UTIL);

    free(lbuf->buf);
    lbuf->error = 0;
    lbuf->len = 0;
    lbuf->size = 0;
    lbuf->buf = NULL;

    debug_return;
}

static bool sudo_lbuf_expand(struct sudo_lbuf *lbuf, unsigned int extra)
{
    debug_decl(sudo_lbuf_expand, SUDO_DEBUG_UTIL);

    if (lbuf->len + extra + 1 <= lbuf->len) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO, "integer overflow updating lbuf->len");
	lbuf->error = 1;
	debug_return_bool(false);
    }

    if (lbuf->len + extra + 1 > lbuf->size) {
	unsigned int new_size = sudo_pow2_roundup(lbuf->len + extra + 1);
	char *new_buf;

	if (new_size < 1024)
	    new_size = 1024;
	if ((new_buf = realloc(lbuf->buf, new_size)) == NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO, "unable to allocate memory");
	    lbuf->error = 1;
	    debug_return_bool(false);
	}
	lbuf->buf = new_buf;
	lbuf->size = new_size;
    }
    debug_return_bool(true);
}


bool sudo_lbuf_append_quoted_v1(struct sudo_lbuf *lbuf, const char *set, const char *fmt, ...)
{
    unsigned int saved_len = lbuf->len;
    bool ret = false;
    const char *cp, *s;
    va_list ap;
    int len;
    debug_decl(sudo_lbuf_append_quoted, SUDO_DEBUG_UTIL);

    if (sudo_lbuf_error(lbuf))
	debug_return_bool(false);

    va_start(ap, fmt);
    while (*fmt != '\0') {
	if (fmt[0] == '%' && fmt[1] == 's') {
	    if ((s = va_arg(ap, char *)) == NULL)
		s = "(NULL)";
	    while ((cp = strpbrk(s, set)) != NULL) {
		len = (int)(cp - s);
		if (!sudo_lbuf_expand(lbuf, len + 2))
		    goto done;
		memcpy(lbuf->buf + lbuf->len, s, len);
		lbuf->len += len;
		lbuf->buf[lbuf->len++] = '\\';
		lbuf->buf[lbuf->len++] = *cp;
		s = cp + 1;
	    }
	    if (*s != '\0') {
		len = strlen(s);
		if (!sudo_lbuf_expand(lbuf, len))
		    goto done;
		memcpy(lbuf->buf + lbuf->len, s, len);
		lbuf->len += len;
	    }
	    fmt += 2;
	    continue;
	}
	if (!sudo_lbuf_expand(lbuf, 2))
	    goto done;
	if (strchr(set, *fmt) != NULL)
	    lbuf->buf[lbuf->len++] = '\\';
	lbuf->buf[lbuf->len++] = *fmt++;
    }
    ret = true;

done:
    if (!ret)
	lbuf->len = saved_len;
    if (lbuf->size != 0)
	lbuf->buf[lbuf->len] = '\0';
    va_end(ap);

    debug_return_bool(ret);
}


bool sudo_lbuf_append_v1(struct sudo_lbuf *lbuf, const char *fmt, ...)
{
    unsigned int saved_len = lbuf->len;
    bool ret = false;
    va_list ap;
    const char *s;
    int len;
    debug_decl(sudo_lbuf_append, SUDO_DEBUG_UTIL);

    if (sudo_lbuf_error(lbuf))
	debug_return_bool(false);

    va_start(ap, fmt);
    while (*fmt != '\0') {
	if (fmt[0] == '%' && fmt[1] == 's') {
	    if ((s = va_arg(ap, char *)) == NULL)
		s = "(NULL)";
	    len = strlen(s);
	    if (!sudo_lbuf_expand(lbuf, len))
		goto done;
	    memcpy(lbuf->buf + lbuf->len, s, len);
	    lbuf->len += len;
	    fmt += 2;
	    continue;
	}
	if (!sudo_lbuf_expand(lbuf, 1))
	    goto done;
	lbuf->buf[lbuf->len++] = *fmt++;
    }
    ret = true;

done:
    if (!ret)
	lbuf->len = saved_len;
    if (lbuf->size != 0)
	lbuf->buf[lbuf->len] = '\0';
    va_end(ap);

    debug_return_bool(ret);
}


static void sudo_lbuf_println(struct sudo_lbuf *lbuf, char *line, int len)
{
    char *cp, save;
    int i, have, contlen = 0;
    int indent = lbuf->indent;
    bool is_comment = false;
    debug_decl(sudo_lbuf_println, SUDO_DEBUG_UTIL);

    
    if (line[0] == '#' && isblank((unsigned char)line[1])) {
	is_comment = true;
	indent = 2;
    }
    if (lbuf->continuation != NULL && !is_comment)
	contlen = strlen(lbuf->continuation);

    
    cp = line;
    have = lbuf->cols;
    while (cp != NULL && *cp != '\0') {
	char *ep = NULL;
	int need = len - (int)(cp - line);

	if (need > have) {
	    have -= contlen;		
	    if ((ep = memrchr(cp, ' ', have)) == NULL)
		ep = memchr(cp + have, ' ', need - have);
	    if (ep != NULL)
		need = (int)(ep - cp);
	}
	if (cp != line) {
	    if (is_comment) {
		lbuf->output("# ");
	    } else {
		
		
		for (i = 0; i < indent; i++)
		    lbuf->output(" ");
	    }
	}
	
	save = cp[need];
	cp[need] = '\0';
	lbuf->output(cp);
	cp[need] = save;
	cp = ep;

	
	if (cp != NULL) {
	    have = lbuf->cols - indent;
	    ep = line + len;
	    while (cp < ep && isblank((unsigned char)*cp)) {
		cp++;
	    }
	    if (contlen)
		lbuf->output(lbuf->continuation);
	}
	lbuf->output("\n");
    }

    debug_return;
}


void sudo_lbuf_print_v1(struct sudo_lbuf *lbuf)
{
    char *cp, *ep;
    int len;
    debug_decl(sudo_lbuf_print, SUDO_DEBUG_UTIL);

    if (lbuf->buf == NULL || lbuf->len == 0)
	goto done;

    
    len = lbuf->continuation ? strlen(lbuf->continuation) : 0;
    if (lbuf->cols <= lbuf->indent + len + 20) {
	lbuf->buf[lbuf->len] = '\0';
	lbuf->output(lbuf->buf);
	if (lbuf->buf[lbuf->len - 1] != '\n')
	    lbuf->output("\n");
	goto done;
    }

    
    for (cp = lbuf->buf; cp != NULL && *cp != '\0'; ) {
	if (*cp == '\n') {
	    lbuf->output("\n");
	    cp++;
	} else {
	    len = lbuf->len - (cp - lbuf->buf);
	    if ((ep = memchr(cp, '\n', len)) != NULL)
		len = (int)(ep - cp);
	    if (len)
		sudo_lbuf_println(lbuf, cp, len);
	    cp = ep ? ep + 1 : NULL;
	}
    }

done:
    lbuf->len = 0;		
    lbuf->error = 0;

    debug_return;
}

bool sudo_lbuf_error_v1(struct sudo_lbuf *lbuf)
{
    if (lbuf != NULL && lbuf->error != 0)
	return true;
    return false;
}

void sudo_lbuf_clearerr_v1(struct sudo_lbuf *lbuf)
{
    if (lbuf != NULL)
	lbuf->error = 0;
}
