






















































struct eventlog_args {
    const char *reason;
    const char *errstr;
    const struct timespec *event_time;
    eventlog_json_callback_t json_info_cb;
    void *json_info;
};


static char * new_logline(int event_type, int flags, struct eventlog_args *args, const struct eventlog *evlog)

{
    const struct eventlog_config *evl_conf = eventlog_getconf();
    char *line = NULL, *evstr = NULL;
    const char *iolog_file;
    const char *tty, *tsid = NULL;
    char exit_str[(((sizeof(int) * 8) + 2) / 3) + 2];
    char sessid[7], offsetstr[64] = "";
    size_t len = 0;
    int i;
    debug_decl(new_logline, SUDO_DEBUG_UTIL);

    if (ISSET(flags, EVLOG_RAW) || evlog == NULL) {
	if (args->reason != NULL) {
	    if (args->errstr != NULL) {
		if (asprintf(&line, "%s: %s", args->reason, args->errstr) == -1)
		    goto oom;
	    } else {
		if ((line = strdup(args->reason)) == NULL)
		    goto oom;
	    }
	}
	debug_return_str(line);
    }

    
    iolog_file = evlog->iolog_file;
    if (iolog_file != NULL) {
	if (IS_SESSID(iolog_file)) {
	    sessid[0] = iolog_file[0];
	    sessid[1] = iolog_file[1];
	    sessid[2] = iolog_file[3];
	    sessid[3] = iolog_file[4];
	    sessid[4] = iolog_file[6];
	    sessid[5] = iolog_file[7];
	    sessid[6] = '\0';
	    tsid = sessid;
	} else {
	    tsid = iolog_file;
	}
	if (sudo_timespecisset(&evlog->iolog_offset)) {
	    
	    if (evlog->iolog_offset.tv_nsec > 10000000) {
		(void)snprintf(offsetstr, sizeof(offsetstr), "@%lld.%02ld", (long long)evlog->iolog_offset.tv_sec, evlog->iolog_offset.tv_nsec / 10000000);

	    } else if (evlog->iolog_offset.tv_sec != 0) {
		(void)snprintf(offsetstr, sizeof(offsetstr), "@%lld", (long long)evlog->iolog_offset.tv_sec);
	    }
	}
    }

    
    if ((tty = evlog->ttyname) != NULL) {
	if (strncmp(tty, _PATH_DEV, sizeof(_PATH_DEV) - 1) == 0)
	    tty += sizeof(_PATH_DEV) - 1;
    }

    
    if (args->reason != NULL)
	len += strlen(args->reason) + 3;
    if (args->errstr != NULL)
	len += strlen(args->errstr) + 3;
    if (evlog->submithost != NULL && !evl_conf->omit_hostname)
	len += sizeof(LL_HOST_STR) + 2 + strlen(evlog->submithost);
    if (tty != NULL)
	len += sizeof(LL_TTY_STR) + 2 + strlen(tty);
    if (evlog->runchroot != NULL)
	len += sizeof(LL_CHROOT_STR) + 2 + strlen(evlog->runchroot);
    if (evlog->runcwd != NULL)
	len += sizeof(LL_CWD_STR) + 2 + strlen(evlog->runcwd);
    if (evlog->runuser != NULL)
	len += sizeof(LL_USER_STR) + 2 + strlen(evlog->runuser);
    if (evlog->rungroup != NULL)
	len += sizeof(LL_GROUP_STR) + 2 + strlen(evlog->rungroup);
    if (tsid != NULL) {
	len += sizeof(LL_TSID_STR) + 2 + strlen(tsid) + strlen(offsetstr);
    }
    if (evlog->env_add != NULL) {
	size_t evlen = 0;
	char * const *ep;

	for (ep = evlog->env_add; *ep != NULL; ep++)
	    evlen += strlen(*ep) + 1;
	if (evlen != 0) {
	    if ((evstr = malloc(evlen)) == NULL)
		goto oom;
	    ep = evlog->env_add;
	    if (strlcpy(evstr, *ep, evlen) >= evlen)
		goto toobig;
	    while (*++ep != NULL) {
		if (strlcat(evstr, " ", evlen) >= evlen || strlcat(evstr, *ep, evlen) >= evlen)
		    goto toobig;
	    }
	    len += sizeof(LL_ENV_STR) + 2 + evlen;
	}
    }
    if (evlog->command != NULL) {
	len += sizeof(LL_CMND_STR) - 1 + strlen(evlog->command);
	if (evlog->argv != NULL && evlog->argv[0] != NULL) {
	    for (i = 1; evlog->argv[i] != NULL; i++)
		len += strlen(evlog->argv[i]) + 1;
	}
	if (event_type == EVLOG_EXIT) {
	    if (evlog->signal_name != NULL)
		len += sizeof(LL_SIGNAL_STR) + 2 + strlen(evlog->signal_name);
	    if (evlog->exit_value != -1) {
		(void)snprintf(exit_str, sizeof(exit_str), "%d", evlog->exit_value);
		len += sizeof(LL_EXIT_STR) + 2 + strlen(exit_str);
	    }
	}
    }

    
    if ((line = malloc(++len)) == NULL)
	goto oom;
    line[0] = '\0';

    if (args->reason != NULL) {
	if (strlcat(line, args->reason, len) >= len || strlcat(line, args->errstr ? " : " : " ; ", len) >= len)
	    goto toobig;
    }
    if (args->errstr != NULL) {
	if (strlcat(line, args->errstr, len) >= len || strlcat(line, " ; ", len) >= len)
	    goto toobig;
    }
    if (evlog->submithost != NULL && !evl_conf->omit_hostname) {
	if (strlcat(line, LL_HOST_STR, len) >= len || strlcat(line, evlog->submithost, len) >= len || strlcat(line, " ; ", len) >= len)

	    goto toobig;
    }
    if (tty != NULL) {
	if (strlcat(line, LL_TTY_STR, len) >= len || strlcat(line, tty, len) >= len || strlcat(line, " ; ", len) >= len)

	    goto toobig;
    }
    if (evlog->runchroot != NULL) {
	if (strlcat(line, LL_CHROOT_STR, len) >= len || strlcat(line, evlog->runchroot, len) >= len || strlcat(line, " ; ", len) >= len)

	    goto toobig;
    }
    if (evlog->runcwd != NULL) {
	if (strlcat(line, LL_CWD_STR, len) >= len || strlcat(line, evlog->runcwd, len) >= len || strlcat(line, " ; ", len) >= len)

	    goto toobig;
    }
    if (evlog->runuser != NULL) {
	if (strlcat(line, LL_USER_STR, len) >= len || strlcat(line, evlog->runuser, len) >= len || strlcat(line, " ; ", len) >= len)

	    goto toobig;
    }
    if (evlog->rungroup != NULL) {
	if (strlcat(line, LL_GROUP_STR, len) >= len || strlcat(line, evlog->rungroup, len) >= len || strlcat(line, " ; ", len) >= len)

	    goto toobig;
    }
    if (tsid != NULL) {
	if (strlcat(line, LL_TSID_STR, len) >= len || strlcat(line, tsid, len) >= len || strlcat(line, offsetstr, len) >= len || strlcat(line, " ; ", len) >= len)


	    goto toobig;
    }
    if (evstr != NULL) {
	if (strlcat(line, LL_ENV_STR, len) >= len || strlcat(line, evstr, len) >= len || strlcat(line, " ; ", len) >= len)

	    goto toobig;
	free(evstr);
	evstr = NULL;
    }
    if (evlog->command != NULL) {
	if (strlcat(line, LL_CMND_STR, len) >= len)
	    goto toobig;
	if (strlcat(line, evlog->command, len) >= len)
	    goto toobig;
	if (evlog->argv != NULL && evlog->argv[0] != NULL) {
	    for (i = 1; evlog->argv[i] != NULL; i++) {
		if (strlcat(line, " ", len) >= len || strlcat(line, evlog->argv[i], len) >= len)
		    goto toobig;
	    }
	}
	if (event_type == EVLOG_EXIT) {
	    if (evlog->signal_name != NULL) {
		if (strlcat(line, " ; ", len) >= len || strlcat(line, LL_SIGNAL_STR, len) >= len || strlcat(line, evlog->signal_name, len) >= len)

		    goto toobig;
	    }
	    if (evlog->exit_value != -1) {
		if (strlcat(line, " ; ", len) >= len || strlcat(line, LL_EXIT_STR, len) >= len || strlcat(line, exit_str, len) >= len)

		    goto toobig;
	    }
	}
    }

    debug_return_str(line);
oom:
    free(evstr);
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    debug_return_str(NULL);
toobig:
    free(evstr);
    free(line);
    sudo_warnx(U_("internal error, %s overflow"), __func__);
    debug_return_str(NULL);
}

static void closefrom_nodebug(int lowfd)
{
    unsigned char *debug_fds;
    int fd, startfd;
    debug_decl(closefrom_nodebug, SUDO_DEBUG_UTIL);

    startfd = sudo_debug_get_fds(&debug_fds) + 1;
    if (lowfd > startfd)
	startfd = lowfd;

    
    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO, "closing fds >= %d", startfd);
    closefrom(startfd);

    
    for (fd = lowfd; fd < startfd; fd++) {
	if (sudo_isset(debug_fds, fd))
	    continue;
	sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO, "closing fd %d", fd);

	
	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);

	(void) close(fd);

    }
    debug_return;
}



sudo_noreturn static void exec_mailer(int pipein)
{
    const struct eventlog_config *evl_conf = eventlog_getconf();
    char *last, *mflags, *p, *argv[MAX_MAILFLAGS + 1];
    const char *mpath = evl_conf->mailerpath;
    int i;
    const char * const root_envp[] = {
	"HOME=/", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LOGNAME=root", "USER=root",  "LOGIN=root",  NULL };







    debug_decl(exec_mailer, SUDO_DEBUG_UTIL);

    
    if (dup3(pipein, STDIN_FILENO, 0) == -1) {
	syslog(LOG_ERR, _("unable to dup stdin: %m")); 
	sudo_debug_printf(SUDO_DEBUG_ERROR, "unable to dup stdin: %s", strerror(errno));
	sudo_debug_exit(__func__, __FILE__, __LINE__, sudo_debug_subsys);
	_exit(127);
    }

    
    if ((mflags = strdup(evl_conf->mailerflags)) == NULL) {
	syslog(LOG_ERR, _("unable to allocate memory")); 
	sudo_debug_exit(__func__, __FILE__, __LINE__, sudo_debug_subsys);
	_exit(127);
    }
    argv[0] = sudo_basename(mpath);

    i = 1;
    if ((p = strtok_r(mflags, " \t", &last))) {
	do {
	    argv[i] = p;
	} while (++i < MAX_MAILFLAGS && (p = strtok_r(NULL, " \t", &last)));
    }
    argv[i] = NULL;

    
    if (setuid(ROOT_UID) != 0) {
	sudo_debug_printf(SUDO_DEBUG_ERROR, "unable to change uid to %u", ROOT_UID);
    }
    if (evl_conf->mailuid != ROOT_UID) {
	if (setuid(evl_conf->mailuid) != 0) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR, "unable to change uid to %u", (unsigned int)evl_conf->mailuid);
	}
    }
    sudo_debug_exit(__func__, __FILE__, __LINE__, sudo_debug_subsys);
    if (evl_conf->mailuid == ROOT_UID)
	execve(mpath, argv, (char **)root_envp);
    else execv(mpath, argv);
    syslog(LOG_ERR, _("unable to execute %s: %m"), mpath); 
    sudo_debug_printf(SUDO_DEBUG_ERROR, "unable to execute %s: %s", mpath, strerror(errno));
    _exit(127);
}


static bool send_mail(const struct eventlog *evlog, const char *fmt, ...)
{
    const struct eventlog_config *evl_conf = eventlog_getconf();
    const char *cp, *timefmt = evl_conf->time_fmt;
    struct sigaction sa;
    char timebuf[1024];
    sigset_t chldmask;
    struct tm tm;
    time_t now;
    FILE *mail;
    int fd, len, pfd[2], status;
    pid_t pid, rv;
    struct stat sb;
    va_list ap;

    char *locale;

    debug_decl(send_mail, SUDO_DEBUG_UTIL);

    
    if (evl_conf->mailerpath == NULL || evl_conf->mailto == NULL)
	debug_return_bool(true);

    
    if (stat(evl_conf->mailerpath, &sb) != 0 || !S_ISREG(sb.st_mode))
	debug_return_bool(false);

    time(&now);
    if (localtime_r(&now, &tm) == NULL)
	debug_return_bool(false);

    
    sigemptyset(&chldmask);
    sigaddset(&chldmask, SIGCHLD);
    (void)sigprocmask(SIG_BLOCK, &chldmask, NULL);

    
    switch (pid = sudo_debug_fork()) {
	case -1:
	    
	    sudo_warn("%s", U_("unable to fork"));

	    
	    (void)sigprocmask(SIG_UNBLOCK, &chldmask, NULL);
	    debug_return_bool(false);
	case 0:
	    
	    switch (fork()) {
		case -1:
		    
		    syslog(LOG_ERR, _("unable to fork: %m")); 
		    sudo_debug_printf(SUDO_DEBUG_ERROR, "unable to fork: %s", strerror(errno));
		    sudo_debug_exit(__func__, __FILE__, __LINE__, sudo_debug_subsys);
		    _exit(EXIT_FAILURE);
		case 0:
		    
		    sudo_debug_enter(__func__, __FILE__, __LINE__, sudo_debug_subsys);
		    break;
		default:
		    
		    _exit(EXIT_SUCCESS);
	    }
	    break;
	default:
	    
	    for (;;) {
		rv = waitpid(pid, &status, 0);
		if (rv == -1 && errno != EINTR)
		    break;
		if (rv != -1 && !WIFSTOPPED(status))
		    break;
	    }
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO, "child (%d) exit value %d", (int)rv, status);

	    
	    (void)sigprocmask(SIG_UNBLOCK, &chldmask, NULL);
	    debug_return_bool(true);
    }

    
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SIG_DFL;
    (void)sigaction(SIGCHLD, &sa, NULL);
    (void)sigprocmask(SIG_UNBLOCK, &chldmask, NULL);

    
    if (setsid() == -1)
      sudo_warn("setsid");
    if (chdir("/") == -1)
      sudo_warn("chdir(/)");
    fd = open(_PATH_DEVNULL, O_RDWR, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if (fd != -1) {
	(void) dup2(fd, STDIN_FILENO);
	(void) dup2(fd, STDOUT_FILENO);
	(void) dup2(fd, STDERR_FILENO);
    }

    
    closefrom_nodebug(STDERR_FILENO + 1);

    if (pipe2(pfd, O_CLOEXEC) == -1) {
	syslog(LOG_ERR, _("unable to open pipe: %m")); 
	sudo_debug_printf(SUDO_DEBUG_ERROR, "unable to open pipe: %s", strerror(errno));
	sudo_debug_exit(__func__, __FILE__, __LINE__, sudo_debug_subsys);
	_exit(EXIT_FAILURE);
    }

    switch (pid = sudo_debug_fork()) {
	case -1:
	    
	    syslog(LOG_ERR, _("unable to fork: %m")); 
	    sudo_debug_printf( SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO, "unable to fork");

	    sudo_debug_exit(__func__, __FILE__, __LINE__, sudo_debug_subsys);
	    _exit(EXIT_FAILURE);
	    break;
	case 0:
	    
	    exec_mailer(pfd[0]);
	    
    }

    (void) close(pfd[0]);
    if ((mail = fdopen(pfd[1], "w")) == NULL) {
	syslog(LOG_ERR, "fdopen: %m");
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO, "unable to fdopen pipe");
	sudo_debug_exit(__func__, __FILE__, __LINE__, sudo_debug_subsys);
	_exit(EXIT_FAILURE);
    }

    
    (void) fprintf(mail, "To: %s\nFrom: %s\nAuto-Submitted: %s\nSubject: ", evl_conf->mailto, evl_conf->mailfrom ? evl_conf->mailfrom :

	(evlog ? evlog->submituser : "root"), "auto-generated");
    for (cp = _(evl_conf->mailsub); *cp; cp++) {
	
	if (*cp == '%' && *(cp+1) != '%') {
	    switch (*(++cp)) {
		case 'h':
		    if (evlog != NULL)
			(void) fputs(evlog->submithost, mail);
		    break;
		case 'u':
		    if (evlog != NULL)
			(void) fputs(evlog->submituser, mail);
		    break;
		default:
		    cp--;
		    break;
	    }
	} else (void) fputc(*cp, mail);
    }


    locale = setlocale(LC_ALL, NULL);
    if (locale[0] != 'C' || locale[1] != '\0')
	(void) fprintf(mail, "\nContent-Type: text/plain; charset=\"%s\"\nContent-Transfer-Encoding: 8bit", nl_langinfo(CODESET));


    timebuf[sizeof(timebuf) - 1] = '\0';
    len = strftime(timebuf, sizeof(timebuf), timefmt, &tm);
    if (len == 0 || timebuf[sizeof(timebuf) - 1] != '\0') {
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_ERROR, "strftime() failed to format time: %s", timefmt);
	
	timebuf[sizeof(timebuf) - 1] = '\0';
	len = strftime(timebuf, sizeof(timebuf), "%h %e %T", &tm);
	if (len == 0 || timebuf[sizeof(timebuf) - 1] != '\0') {
	    timebuf[0] = '\0';		
	}
    }
    if (evlog != NULL) {
	(void) fprintf(mail, "\n\n%s : %s : %s : ", evlog->submithost, timebuf, evlog->submituser);
    } else {
	(void) fprintf(mail, "\n\n%s : ", timebuf);
    }
    va_start(ap, fmt);
    (void) vfprintf(mail, fmt, ap);
    va_end(ap);
    fputs("\n\n", mail);

    fclose(mail);
    for (;;) {
	rv = waitpid(pid, &status, 0);
	if (rv == -1 && errno != EINTR)
	    break;
	if (rv != -1 && !WIFSTOPPED(status))
	    break;
    }
    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO, "child (%d) exit value %d", (int)rv, status);
    sudo_debug_exit(__func__, __FILE__, __LINE__, sudo_debug_subsys);
    _exit(EXIT_SUCCESS);
}

static bool json_add_timestamp(struct json_container *jsonc, const char *name, const struct timespec *ts, bool format_timestamp)

{
    struct json_value json_value;
    int len;
    debug_decl(json_add_timestamp, SUDO_DEBUG_PLUGIN);

    if (!sudo_json_open_object(jsonc, name))
	goto oom;

    json_value.type = JSON_NUMBER;
    json_value.u.number = ts->tv_sec;
    if (!sudo_json_add_value(jsonc, "seconds", &json_value))
	goto oom;

    json_value.type = JSON_NUMBER;
    json_value.u.number = ts->tv_nsec;
    if (!sudo_json_add_value(jsonc, "nanoseconds", &json_value))
	goto oom;

    if (format_timestamp) {
	const struct eventlog_config *evl_conf = eventlog_getconf();
	const char *timefmt = evl_conf->time_fmt;
	time_t secs = ts->tv_sec;
	char timebuf[1024];
	struct tm tm;

	if (gmtime_r(&secs, &tm) != NULL) {
	    timebuf[sizeof(timebuf) - 1] = '\0';
	    len = strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%SZ", &tm);
	    if (len != 0 && timebuf[sizeof(timebuf) - 1] == '\0') {
		json_value.type = JSON_STRING;
		json_value.u.string = timebuf; 
		if (!sudo_json_add_value(jsonc, "iso8601", &json_value))
		    goto oom;
	    }
	}

	if (localtime_r(&secs, &tm) != NULL) {
	    timebuf[sizeof(timebuf) - 1] = '\0';
	    len = strftime(timebuf, sizeof(timebuf), timefmt, &tm);
	    if (len != 0 && timebuf[sizeof(timebuf) - 1] == '\0') {
		json_value.type = JSON_STRING;
		json_value.u.string = timebuf; 
		if (!sudo_json_add_value(jsonc, "localtime", &json_value))
		    goto oom;
	    }
	}
    }

    if (!sudo_json_close_object(jsonc))
	goto oom;

    debug_return_bool(true);
oom:
    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO|SUDO_DEBUG_LINENO, "%s: %s", __func__, "unable to allocate memory");
    debug_return_bool(false);
}


bool eventlog_store_json(struct json_container *jsonc, const struct eventlog *evlog)
{
    struct json_value json_value;
    size_t i;
    char *cp;
    debug_decl(eventlog_store_json, SUDO_DEBUG_UTIL);

    
    if (evlog == NULL || evlog->submituser == NULL)
	debug_return_bool(false);

    

    json_value.type = JSON_STRING;
    json_value.u.string = evlog->submituser;
    if (!sudo_json_add_value(jsonc, "submituser", &json_value))
	goto oom;

    if (evlog->command != NULL) {
	json_value.type = JSON_STRING;
	json_value.u.string = evlog->command;
	if (!sudo_json_add_value(jsonc, "command", &json_value))
	    goto oom;
    }

    if (evlog->runuser != NULL) {
	json_value.type = JSON_STRING;
	json_value.u.string = evlog->runuser;
	if (!sudo_json_add_value(jsonc, "runuser", &json_value))
	    goto oom;
    }

    if (evlog->rungroup != NULL) {
	json_value.type = JSON_STRING;
	json_value.u.string = evlog->rungroup;
	if (!sudo_json_add_value(jsonc, "rungroup", &json_value))
	    goto oom;
    }

    if (evlog->runchroot != NULL) {
	json_value.type = JSON_STRING;
	json_value.u.string = evlog->runchroot;
	if (!sudo_json_add_value(jsonc, "runchroot", &json_value))
	    goto oom;
    }

    if (evlog->runcwd != NULL) {
	json_value.type = JSON_STRING;
	json_value.u.string = evlog->runcwd;
	if (!sudo_json_add_value(jsonc, "runcwd", &json_value))
	    goto oom;
    }

    if (evlog->ttyname != NULL) {
	json_value.type = JSON_STRING;
	json_value.u.string = evlog->ttyname;
	if (!sudo_json_add_value(jsonc, "ttyname", &json_value))
	    goto oom;
    }

    if (evlog->submithost != NULL) {
	json_value.type = JSON_STRING;
	json_value.u.string = evlog->submithost;
	if (!sudo_json_add_value(jsonc, "submithost", &json_value))
	    goto oom;
    }

    if (evlog->cwd != NULL) {
	json_value.type = JSON_STRING;
	json_value.u.string = evlog->cwd;
	if (!sudo_json_add_value(jsonc, "submitcwd", &json_value))
	    goto oom;
    }

    if (evlog->rungroup!= NULL && evlog->rungid != (gid_t)-1) {
	json_value.type = JSON_ID;
	json_value.u.id = evlog->rungid;
	if (!sudo_json_add_value(jsonc, "rungid", &json_value))
	    goto oom;
    }

    if (evlog->runuid != (uid_t)-1) {
	json_value.type = JSON_ID;
	json_value.u.id = evlog->runuid;
	if (!sudo_json_add_value(jsonc, "runuid", &json_value))
	    goto oom;
    }

    json_value.type = JSON_NUMBER;
    json_value.u.number = evlog->columns;
    if (!sudo_json_add_value(jsonc, "columns", &json_value))
        goto oom;

    json_value.type = JSON_NUMBER;
    json_value.u.number = evlog->lines;
    if (!sudo_json_add_value(jsonc, "lines", &json_value))
        goto oom;

    if (evlog->argv != NULL) {
	if (!sudo_json_open_array(jsonc, "runargv"))
	    goto oom;
	for (i = 0; (cp = evlog->argv[i]) != NULL; i++) {
	    json_value.type = JSON_STRING;
	    json_value.u.string = cp;
	    if (!sudo_json_add_value(jsonc, NULL, &json_value))
		goto oom;
	}
	if (!sudo_json_close_array(jsonc))
	    goto oom;
    }

    if (evlog->envp != NULL) {
	if (!sudo_json_open_array(jsonc, "runenv"))
	    goto oom;
	for (i = 0; (cp = evlog->envp[i]) != NULL; i++) {
	    json_value.type = JSON_STRING;
	    json_value.u.string = cp;
	    if (!sudo_json_add_value(jsonc, NULL, &json_value))
		goto oom;
	}
	if (!sudo_json_close_array(jsonc))
	    goto oom;
    }

    debug_return_bool(true);

oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    debug_return_bool(false);
}

static bool default_json_cb(struct json_container *jsonc, void *v)
{
    return eventlog_store_json(jsonc, v);
}

static char * format_json(int event_type, struct eventlog_args *args, const struct eventlog *evlog, bool compact)

{
    eventlog_json_callback_t info_cb = args->json_info_cb;
    void *info = args->json_info;
    struct json_container jsonc = { 0 };
    struct json_value json_value;
    const char *time_str, *type_str;
    struct timespec now;
    debug_decl(format_json, SUDO_DEBUG_UTIL);

    if (info_cb == NULL) {
	info_cb = default_json_cb;
	info = (void *)evlog;
    }

    if (sudo_gettime_real(&now) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO, "unable to read the clock");
	debug_return_str(NULL);
    }

    switch (event_type) {
    case EVLOG_ACCEPT:
	type_str = "accept";
	time_str = "submit_time";
	break;
    case EVLOG_REJECT:
	type_str = "reject";
	time_str = "submit_time";
	break;
    case EVLOG_ALERT:
	type_str = "alert";
	time_str = "alert_time";
	break;
    case EVLOG_EXIT:
	type_str = "exit";
	time_str = "exit_time";
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO, "unexpected event type %d", event_type);
	debug_return_str(NULL);
    }

    if (!sudo_json_init(&jsonc, 4, compact, false, false))
	goto bad;
    if (!sudo_json_open_object(&jsonc, type_str))
	goto bad;

    if (evlog != NULL && evlog->uuid_str[0] != '\0') {
	json_value.type = JSON_STRING;
	json_value.u.string = evlog->uuid_str;
	if (!sudo_json_add_value(&jsonc, "uuid", &json_value))
	    goto bad;
    }

    
    if (args->reason != NULL) {
	char *ereason = NULL;

	if (args->errstr != NULL) {
	    const int len = asprintf(&ereason, _("%s: %s"), args->reason, args->errstr);
	    if (len == -1) {
		sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
		goto bad;
	    }
	}
	json_value.type = JSON_STRING;
	json_value.u.string = ereason ? ereason : args->reason;
	if (!sudo_json_add_value(&jsonc, "reason", &json_value)) {
	    free(ereason);
	    goto bad;
	}
	free(ereason);
    }

    
    if (!json_add_timestamp(&jsonc, "server_time", &now, true)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO, "unable format timestamp");
	goto bad;
    }

    
    if (args->event_time != NULL) {
	if (!json_add_timestamp(&jsonc, time_str, args->event_time, true)) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO, "unable format timestamp");
	    goto bad;
	}
    }

    if (event_type == EVLOG_EXIT) {
	
	if (evlog != NULL && evlog->uuid_str[0] != '\0') {
	    if (args->json_info == NULL)
		info = NULL;
	}

	if (sudo_timespecisset(&evlog->run_time)) {
	    if (!json_add_timestamp(&jsonc, "run_time", &evlog->run_time, false)) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO, "unable format timestamp");
		goto bad;
	    }
	}
	if (evlog->signal_name != NULL) {
	    json_value.type = JSON_STRING;
	    json_value.u.string = evlog->signal_name;
	    if (!sudo_json_add_value(&jsonc, "signal", &json_value))
		goto bad;

	    json_value.type = JSON_BOOL;
	    json_value.u.boolean = evlog->dumped_core;
	    if (!sudo_json_add_value(&jsonc, "dumped_core", &json_value))
		goto bad;
	}
	json_value.type = JSON_NUMBER;
	json_value.u.number = evlog->exit_value;
	if (!sudo_json_add_value(&jsonc, "exit_value", &json_value))
	    goto bad;
    }

     
     if (evlog != NULL) {
	if (evlog->peeraddr != NULL) {
	    json_value.type = JSON_STRING;
	    json_value.u.string = evlog->peeraddr;
	    if (!sudo_json_add_value(&jsonc, "peeraddr", &json_value))
		goto bad;
	}

	if (evlog->iolog_path != NULL) {
	    json_value.type = JSON_STRING;
	    json_value.u.string = evlog->iolog_path;
	    if (!sudo_json_add_value(&jsonc, "iolog_path", &json_value))
		goto bad;

	    if (sudo_timespecisset(&evlog->iolog_offset)) {
		if (!json_add_timestamp(&jsonc, "iolog_offset", &evlog->iolog_offset, false)) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO, "unable format timestamp");
		    goto bad;
		}
	    }
	}
    }

    
    if (info != NULL) {
	if (!info_cb(&jsonc, info))
	    goto bad;
    }

    if (!sudo_json_close_object(&jsonc))
	goto bad;

    
    debug_return_str(sudo_json_get_buf(&jsonc));

bad:
    sudo_json_free(&jsonc);
    debug_return_str(NULL);
}


static bool do_syslog_sudo(int pri, char *logline, const struct eventlog *evlog)
{
    const struct eventlog_config *evl_conf = eventlog_getconf();
    size_t len, maxlen;
    char *p, *tmp, save;
    const char *fmt;
    debug_decl(do_syslog_sudo, SUDO_DEBUG_UTIL);

    evl_conf->open_log(EVLOG_SYSLOG, NULL);

    if (evlog == NULL) {
	
	syslog(pri, "%s", logline);
	goto done;
    }

    
    fmt = _("%8s : %s");
    maxlen = evl_conf->syslog_maxlen - (strlen(fmt) - 5 + strlen(evlog->submituser));
    for (p = logline; *p != '\0'; ) {
	len = strlen(p);
	if (len > maxlen) {
	    
	    tmp = memrchr(p, ' ', maxlen);
	    if (tmp == NULL)
		tmp = p + maxlen;

	    
	    save = *tmp;
	    *tmp = '\0';

	    syslog(pri, fmt, evlog->submituser, p);

	    *tmp = save;			

	    
	    for (p = tmp; *p == ' '; p++)
		continue;
	} else {
	    syslog(pri, fmt, evlog->submituser, p);
	    p += len;
	}
	fmt = _("%8s : (command continued) %s");
	maxlen = evl_conf->syslog_maxlen - (strlen(fmt) - 5 + strlen(evlog->submituser));
    }
done:
    evl_conf->close_log(EVLOG_SYSLOG, NULL);

    debug_return_bool(true);
}

static bool do_syslog_json(int pri, int event_type, struct eventlog_args *args, const struct eventlog *evlog)

{
    const struct eventlog_config *evl_conf = eventlog_getconf();
    char *json_str;
    debug_decl(do_syslog_json, SUDO_DEBUG_UTIL);

    
    json_str = format_json(event_type, args, evlog, true);
    if (json_str == NULL)
	debug_return_bool(false);

    
    
    evl_conf->open_log(EVLOG_SYSLOG, NULL);
    syslog(pri, "@cee:{\"sudo\":{%s}}", json_str);
    evl_conf->close_log(EVLOG_SYSLOG, NULL);
    free(json_str);
    debug_return_bool(true);
}


static bool do_syslog(int event_type, int flags, struct eventlog_args *args, const struct eventlog *evlog)

{
    const struct eventlog_config *evl_conf = eventlog_getconf();
    char *logline = NULL;
    bool ret = false;
    int pri;
    debug_decl(do_syslog, SUDO_DEBUG_UTIL);

    
    if (evl_conf->format == EVLOG_SUDO || ISSET(flags, EVLOG_MAIL)) {
	logline = new_logline(event_type, flags, args, evlog);
	if (logline == NULL)
	    debug_return_bool(false);

	if (ISSET(flags, EVLOG_MAIL)) {
	    if (!send_mail(evlog, "%s", logline)) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO, "unable to mail log line");
	    }
	    if (ISSET(flags, EVLOG_MAIL_ONLY)) {
		free(logline);
		debug_return_bool(true);
	    }
	}
    }

    switch (event_type) {
    case EVLOG_ACCEPT:
    case EVLOG_EXIT:
	pri = evl_conf->syslog_acceptpri;
	break;
    case EVLOG_REJECT:
	pri = evl_conf->syslog_rejectpri;
	break;
    case EVLOG_ALERT:
	pri = evl_conf->syslog_alertpri;
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO, "unexpected event type %d", event_type);
	pri = -1;
	break;
    }
    if (pri == -1) {
	
	free(logline);
	debug_return_bool(true);
    }

    switch (evl_conf->format) {
    case EVLOG_SUDO:
	ret = do_syslog_sudo(pri, logline, evlog);
	break;
    case EVLOG_JSON:
	ret = do_syslog_json(pri, event_type, args, evlog);
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO, "unexpected eventlog format %d", evl_conf->format);
	break;
    }
    free(logline);

    debug_return_bool(ret);
}

static bool do_logfile_sudo(const char *logline, const struct eventlog *evlog, const struct timespec *event_time)

{
    const struct eventlog_config *evl_conf = eventlog_getconf();
    char *full_line, timebuf[8192], *timestr = NULL;
    const char *timefmt = evl_conf->time_fmt;
    const char *logfile = evl_conf->logpath;
    struct tm tm;
    bool ret = false;
    FILE *fp;
    int len;
    debug_decl(do_logfile_sudo, SUDO_DEBUG_UTIL);

    if ((fp = evl_conf->open_log(EVLOG_FILE, logfile)) == NULL)
	debug_return_bool(false);

    if (!sudo_lock_file(fileno(fp), SUDO_LOCK)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO, "unable to lock log file %s", logfile);
	goto done;
    }

    if (event_time != NULL) {
	time_t tv_sec = event_time->tv_sec;
	if (localtime_r(&tv_sec, &tm) != NULL) {
	    
	    timebuf[sizeof(timebuf) - 1] = '\0';
	    if (strftime(timebuf, sizeof(timebuf), timefmt, &tm) != 0 && timebuf[sizeof(timebuf) - 1] == '\0') {
		timestr = timebuf;
	    }
	}
    }
    if (evlog != NULL) {
	len = asprintf(&full_line, "%s : %s : %s", timestr ? timestr : "invalid date", evlog->submituser, logline);
    } else {
	len = asprintf(&full_line, "%s : %s", timestr ? timestr : "invalid date", logline);
    }
    if (len == -1) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto done;
    }
    eventlog_writeln(fp, full_line, len, evl_conf->file_maxlen);
    free(full_line);
    (void)fflush(fp);
    if (ferror(fp)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO, "unable to write log file %s", logfile);
	goto done;
    }
    ret = true;

done:
    (void)sudo_lock_file(fileno(fp), SUDO_UNLOCK);
    evl_conf->close_log(EVLOG_FILE, fp);
    debug_return_bool(ret);
}

static bool do_logfile_json(int event_type, struct eventlog_args *args, const struct eventlog *evlog)

{
    const struct eventlog_config *evl_conf = eventlog_getconf();
    const char *logfile = evl_conf->logpath;
    struct stat sb;
    char *json_str;
    int ret = false;
    FILE *fp;
    debug_decl(do_logfile_json, SUDO_DEBUG_UTIL);

    if ((fp = evl_conf->open_log(EVLOG_FILE, logfile)) == NULL)
	debug_return_bool(false);

    json_str = format_json(event_type, args, evlog, false);
    if (json_str == NULL)
	goto done;

    if (!sudo_lock_file(fileno(fp), SUDO_LOCK)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO, "unable to lock log file %s", logfile);
	goto done;
    }

    
    if (fstat(fileno(fp), &sb) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO|SUDO_DEBUG_LINENO, "unable to stat %s", logfile);
	goto done;
    }
    if (sb.st_size == 0) {
	
	putc('{', fp);
    } else if (fseeko(fp, -3, SEEK_END) == 0) {
	
	putc(',', fp);
    } else {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO|SUDO_DEBUG_LINENO, "unable to seek %s", logfile);
	goto done;
    }
    fputs(json_str, fp);
    fputs("\n}\n", fp);			
    fflush(fp);
    

    ret = true;

done:
    free(json_str);
    (void)sudo_lock_file(fileno(fp), SUDO_UNLOCK);
    evl_conf->close_log(EVLOG_FILE, fp);
    debug_return_bool(ret);
}

static bool do_logfile(int event_type, int flags, struct eventlog_args *args, const struct eventlog *evlog)

{
    const struct eventlog_config *evl_conf = eventlog_getconf();
    bool ret = false;
    char *logline = NULL;
    debug_decl(do_logfile, SUDO_DEBUG_UTIL);

    
    if (evl_conf->format == EVLOG_SUDO || ISSET(flags, EVLOG_MAIL)) {
	logline = new_logline(event_type, flags, args, evlog);
	if (logline == NULL)
	    debug_return_bool(false);

	if (ISSET(flags, EVLOG_MAIL)) {
	    if (!send_mail(evlog, "%s", logline)) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO, "unable to mail log line");
	    }
	    if (ISSET(flags, EVLOG_MAIL_ONLY)) {
		free(logline);
		debug_return_bool(true);
	    }
	}
    }

    switch (evl_conf->format) {
    case EVLOG_SUDO:
	ret = do_logfile_sudo(logline ? logline : args->reason, evlog, args->event_time);
	break;
    case EVLOG_JSON:
	ret = do_logfile_json(event_type, args, evlog);
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO, "unexpected eventlog format %d", evl_conf->format);
	break;
    }
    free(logline);

    debug_return_bool(ret);
}

bool eventlog_accept(const struct eventlog *evlog, int flags, eventlog_json_callback_t info_cb, void *info)

{
    const struct eventlog_config *evl_conf = eventlog_getconf();
    const int log_type = evl_conf->type;
    struct eventlog_args args = { NULL };
    bool ret = true;
    debug_decl(log_accept, SUDO_DEBUG_UTIL);

    args.event_time = &evlog->submit_time;
    args.json_info_cb = info_cb;
    args.json_info = info;

    if (ISSET(log_type, EVLOG_SYSLOG)) {
	if (!do_syslog(EVLOG_ACCEPT, flags, &args, evlog))
	    ret = false;
	CLR(flags, EVLOG_MAIL);
    }
    if (ISSET(log_type, EVLOG_FILE)) {
	if (!do_logfile(EVLOG_ACCEPT, flags, &args, evlog))
	    ret = false;
    }

    debug_return_bool(ret);
}

bool eventlog_reject(const struct eventlog *evlog, int flags, const char *reason, eventlog_json_callback_t info_cb, void *info)

{
    const struct eventlog_config *evl_conf = eventlog_getconf();
    const int log_type = evl_conf->type;
    struct eventlog_args args = { NULL };
    bool ret = true;
    debug_decl(log_reject, SUDO_DEBUG_UTIL);

    args.reason = reason;
    args.event_time = &evlog->submit_time;
    args.json_info_cb = info_cb;
    args.json_info = info;

    if (ISSET(log_type, EVLOG_SYSLOG)) {
	if (!do_syslog(EVLOG_REJECT, flags, &args, evlog))
	    ret = false;
	CLR(flags, EVLOG_MAIL);
    }
    if (ISSET(log_type, EVLOG_FILE)) {
	if (!do_logfile(EVLOG_REJECT, flags, &args, evlog))
	    ret = false;
    }

    debug_return_bool(ret);
}

bool eventlog_alert(const struct eventlog *evlog, int flags, struct timespec *alert_time, const char *reason, const char *errstr)

{
    const struct eventlog_config *evl_conf = eventlog_getconf();
    const int log_type = evl_conf->type;
    struct eventlog_args args = { NULL };
    bool ret = true;
    debug_decl(log_alert, SUDO_DEBUG_UTIL);

    args.reason = reason;
    args.errstr = errstr;
    args.event_time = alert_time;

    if (ISSET(log_type, EVLOG_SYSLOG)) {
	if (!do_syslog(EVLOG_ALERT, flags, &args, evlog))
	    ret = false;
	CLR(flags, EVLOG_MAIL);
    }
    if (ISSET(log_type, EVLOG_FILE)) {
	if (!do_logfile(EVLOG_ALERT, flags, &args, evlog))
	    ret = false;
    }

    debug_return_bool(ret);
}

bool eventlog_exit(const struct eventlog *evlog, int flags)
{
    const struct eventlog_config *evl_conf = eventlog_getconf();
    const int log_type = evl_conf->type;
    struct eventlog_args args = { NULL };
    struct timespec exit_time;
    bool ret = true;
    debug_decl(eventlog_exit, SUDO_DEBUG_UTIL);

    if (sudo_timespecisset(&evlog->run_time)) {
	sudo_timespecadd(&evlog->submit_time, &evlog->run_time, &exit_time);
	args.event_time = &exit_time;
    }

    if (ISSET(log_type, EVLOG_SYSLOG)) {
	if (!do_syslog(EVLOG_EXIT, flags, &args, evlog))
	    ret = false;
	CLR(flags, EVLOG_MAIL);
    }
    if (ISSET(log_type, EVLOG_FILE)) {
	if (!do_logfile(EVLOG_EXIT, flags, &args, evlog))
	    ret = false;
    }

    debug_return_bool(ret);
}
