










































struct sinfo {
	char *username;
	char *shell;
};

static void __attribute__((__noreturn__)) usage(void)
{
	FILE *fp = stdout;
	fputs(USAGE_HEADER, fp);
	fprintf(fp, _(" %s [options] [<username>]\n"), program_invocation_short_name);

	fputs(USAGE_SEPARATOR, fp);
	fputs(_("Change your login shell.\n"), fp);

	fputs(USAGE_OPTIONS, fp);
	fputs(_(" -s, --shell <shell>  specify login shell\n"), fp);
	fputs(_(" -l, --list-shells    print list of shells and exit\n"), fp);
	fputs(USAGE_SEPARATOR, fp);
	printf( " -u, --help           %s\n", USAGE_OPTSTR_HELP);
	printf( " -v, --version        %s\n", USAGE_OPTSTR_VERSION);
	printf(USAGE_MAN_TAIL("chsh(1)"));
	exit(EXIT_SUCCESS);
}


static int is_known_shell(const char *shell_name)
{
	char *s, ret = 0;

	if (!shell_name)
		return 0;

	setusershell();
	while ((s = getusershell())) {
		if (strcmp(shell_name, s) == 0) {
			ret = 1;
			break;
		}
	}
	endusershell();
	return ret;
}


static void print_shells(void)
{
	char *s;

	while ((s = getusershell()))
		printf("%s\n", s);
	endusershell();
}


static char *shell_name_generator(const char *text, int state)
{
	static size_t len;
	char *s;

	if (!state) {
		setusershell();
		len = strlen(text);
	}

	while ((s = getusershell())) {
		if (strncmp(s, text, len) == 0)
			return xstrdup(s);
	}
	return NULL;
}

static char **shell_name_completion(const char *text, int start __attribute__((__unused__)), int end __attribute__((__unused__)))

{
	rl_attempted_completion_over = 1;
	return rl_completion_matches(text, shell_name_generator);
}



static void parse_argv(int argc, char **argv, struct sinfo *pinfo)
{
	static const struct option long_options[] = {
		{"shell",       required_argument, NULL, 's', {"list-shells", no_argument,       NULL, 'l', {"help",        no_argument,       NULL, 'h', {"version",     no_argument,       NULL, 'v', {NULL, 0, NULL, 0}, };




	int c;

	while ((c = getopt_long(argc, argv, "s:lhuv", long_options, NULL)) != -1) {
		switch (c) {
		case 'v':
			print_version(EXIT_SUCCESS);
		case 'u': 
		case 'h':
			usage();
		case 'l':
			print_shells();
			exit(EXIT_SUCCESS);
		case 's':
			pinfo->shell = optarg;
			break;
		default:
			errtryhelp(EXIT_FAILURE);
		}
	}
	
	if (optind < argc) {
		if (optind + 1 < argc) {
			errx(EXIT_FAILURE, _("cannot handle multiple usernames"));
		}
		pinfo->username = argv[optind];
	}
}


static char *ask_new_shell(char *question, char *oldshell)
{
	int len;
	char *ans = NULL;

	rl_attempted_completion_function = shell_name_completion;

	size_t dummy = 0;

	if (!oldshell)
		oldshell = "";
	printf("%s [%s]:", question, oldshell);

	if ((ans = readline(" ")) == NULL)

	putchar(' ');
	fflush(stdout);
	if (getline(&ans, &dummy, stdin) < 0)

		return NULL;
	
	ltrim_whitespace((unsigned char *) ans);
	len = rtrim_whitespace((unsigned char *) ans);
	if (len == 0)
		return NULL;
	return ans;
}


static void check_shell(const char *shell)
{
	if (*shell != '/')
		errx(EXIT_FAILURE, _("shell must be a full path name"));
	if (access(shell, F_OK) < 0)
		errx(EXIT_FAILURE, _("\"%s\" does not exist"), shell);
	if (access(shell, X_OK) < 0)
		errx(EXIT_FAILURE, _("\"%s\" is not executable"), shell);
	if (illegal_passwd_chars(shell))
		errx(EXIT_FAILURE, _("%s: has illegal characters"), shell);
	if (!is_known_shell(shell)) {

		if (!getuid())
			warnx(_("Warning: \"%s\" is not listed in %s."), shell, _PATH_SHELLS);
		else errx(EXIT_FAILURE, _("\"%s\" is not listed in %s.\n" "Use %s -l to see list."), shell, _PATH_SHELLS, program_invocation_short_name);




		warnx(_("\"%s\" is not listed in %s.\n" "Use %s -l to see list."), shell, _PATH_SHELLS, program_invocation_short_name);


	}
}

int main(int argc, char **argv)
{
	char *oldshell, *pwbuf;
	int nullshell = 0;
	const uid_t uid = getuid();
	struct sinfo info = { NULL };
	struct passwd *pw;

	sanitize_env();
	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);
	close_stdout_atexit();

	parse_argv(argc, argv, &info);
	if (!info.username) {
		pw = xgetpwuid(uid, &pwbuf);
		if (!pw)
			errx(EXIT_FAILURE, _("you (user %d) don't exist."), uid);
	} else {
		pw = xgetpwnam(info.username, &pwbuf);
		if (!pw)
			errx(EXIT_FAILURE, _("user \"%s\" does not exist."), info.username);
	}


	if (!(is_local(pw->pw_name)))
		errx(EXIT_FAILURE, _("can only change local entries"));



	if (is_selinux_enabled() > 0) {
		char *user_cxt = NULL;

		if (uid == 0 && !ul_selinux_has_access("passwd", "chsh", &user_cxt))
			errx(EXIT_FAILURE, _("%s is not authorized to change the shell of %s"), user_cxt ? : _("Unknown user context"), pw->pw_name);



		if (ul_setfscreatecon_from_file(_PATH_PASSWD) != 0)
			errx(EXIT_FAILURE, _("can't set default context for %s"), _PATH_PASSWD);
	}


	oldshell = pw->pw_shell;
	if (oldshell == NULL || *oldshell == '\0') {
		oldshell = _PATH_BSHELL;	
		nullshell = 1;
	}

	

	
	if (geteuid() != getuid() && uid != pw->pw_uid) {

	if (uid != 0 && uid != pw->pw_uid) {

		errno = EACCES;
		err(EXIT_FAILURE, _("running UID doesn't match UID of user we're " "altering, shell change denied"));

	}
	if (uid != 0 && !is_known_shell(oldshell)) {
		errno = EACCES;
		err(EXIT_FAILURE, _("your shell is not in %s, " "shell change denied"), _PATH_SHELLS);
	}

	printf(_("Changing shell for %s.\n"), pw->pw_name);


	if (!auth_pam("chsh", uid, pw->pw_name)) {
		return EXIT_FAILURE;
	}

	if (!info.shell) {
		info.shell = ask_new_shell(_("New shell"), oldshell);
		if (!info.shell)
			return EXIT_SUCCESS;
	}

	check_shell(info.shell);

	if (!nullshell && strcmp(oldshell, info.shell) == 0)
		errx(EXIT_SUCCESS, _("Shell not changed."));


	if (set_value_libuser("chsh", pw->pw_name, uid, LU_LOGINSHELL, info.shell) < 0)
		errx(EXIT_FAILURE, _("Shell *NOT* changed.  Try again later."));

	pw->pw_shell = info.shell;
	if (setpwnam(pw, ".chsh") < 0)
		err(EXIT_FAILURE, _("setpwnam failed\n" "Shell *NOT* changed.  Try again later."));


	printf(_("Shell changed.\n"));
	return EXIT_SUCCESS;
}
