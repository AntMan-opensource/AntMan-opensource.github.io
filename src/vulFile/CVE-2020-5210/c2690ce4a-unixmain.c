




















extern struct passwd *FDECL(getpwuid, (uid_t));

extern struct passwd *FDECL(getpwuid, (int));



extern struct passwd *FDECL(getpwnam, (const char *));

static void FDECL(chdirx, (const char *, BOOLEAN_P));

static boolean NDECL(whoami);
static void FDECL(process_options, (int, char **));


extern void NDECL(check_sco_console);
extern void NDECL(init_sco_cons);


extern void NDECL(check_linux_console);
extern void NDECL(init_linux_cons);


static void NDECL(wd_message);
static boolean wiz_error_flag = FALSE;
static struct passwd *NDECL(get_unix_pw);

int main(argc, argv)
int argc;
char *argv[];
{
    register int fd;

    register char *dir;

    boolean exact_username;
    boolean resuming = FALSE; 
    boolean plsel_once = FALSE;

    sys_early_init();


    {


        char mac_cwd[1024], *mac_exe = argv[0], *mac_tmp;
        int arg0_len = strlen(mac_exe), mac_tmp_len, mac_lhs_len = 0;
        getcwd(mac_cwd, 1024);
        if (mac_exe[0] == '/' && !strcmp(mac_cwd, "/")) {
            if ((mac_exe = strrchr(mac_exe, '/')))
                mac_exe++;
            else mac_exe = argv[0];
            mac_tmp_len = (strlen(mac_exe) * 2) + strlen(MAC_PATH_VALUE);
            if (mac_tmp_len <= arg0_len) {
                mac_tmp = malloc(mac_tmp_len + 1);
                sprintf(mac_tmp, "%s%s%s", mac_exe, MAC_PATH_VALUE, mac_exe);
                if (!strcmp(argv[0] + (arg0_len - mac_tmp_len), mac_tmp)) {
                    mac_lhs_len = (arg0_len - mac_tmp_len) + strlen(mac_exe) + 5;
                    if (mac_lhs_len > mac_tmp_len - 1)
                        mac_tmp = realloc(mac_tmp, mac_lhs_len);
                    strncpy(mac_tmp, argv[0], mac_lhs_len);
                    mac_tmp[mac_lhs_len] = '\0';
                    chdir(mac_tmp);
                }
                free(mac_tmp);
            }
        }
    }


    hname = argv[0];
    hackpid = getpid();
    (void) umask(0777 & ~FCMASK);

    choose_windows(DEFAULT_WINDOW_SYS);


    
    dir = nh_getenv("NETHACKDIR");
    if (!dir)
        dir = nh_getenv("HACKDIR");

    if (argc > 1) {
        if (argcheck(argc, argv, ARG_VERSION) == 2)
            exit(EXIT_SUCCESS);

        if (argcheck(argc, argv, ARG_SHOWPATHS) == 2) {

            chdirx((char *) 0, 0);

            iflags.initoptions_noterminate = TRUE;
            initoptions();
            iflags.initoptions_noterminate = FALSE;
            reveal_paths();
            exit(EXIT_SUCCESS);
        }
        if (argcheck(argc, argv, ARG_DEBUG) == 1) {
            argc--;
            argv++;
        }
        if (argc > 1 && !strncmp(argv[1], "-d", 2) && argv[1][2] != 'e') {
            
            argc--;
            argv++;
            dir = argv[0] + 2;
            if (*dir == '=' || *dir == ':')
                dir++;
            if (!*dir && argc > 1) {
                argc--;
                argv++;
                dir = argv[0];
            }
            if (!*dir)
                error("Flag -d must be followed by a directory name.");
        }
    }


    if (argc > 1) {
        
        if (!strncmp(argv[1], "-s", 2) && strncmp(argv[1], "-style", 6)) {

            chdirx(dir, 0);


            initoptions();


            ARGV0 = hname; 

            panictrace_setsignals(TRUE);


            prscore(argc, argv);
            
            exit(EXIT_SUCCESS);
        }
    } 



    chdirx(dir, 1);



    check_sco_console();


    check_linux_console();

    initoptions();

    ARGV0 = hname; 

    panictrace_setsignals(TRUE);


    exact_username = whoami();

    
    u.uhp = 1; 
    program_state.preserve_locks = 1;

    sethanguphandler((SIG_RET_TYPE) hangup);


    process_options(argc, argv); 

    commit_windowchain();

    init_nhwindows(&argc, argv); 

    init_sco_cons();


    init_linux_cons();



    if (!(catmore = nh_getenv("HACKPAGER"))
        && !(catmore = nh_getenv("PAGER")))
        catmore = DEF_PAGER;


    getmailstatus();


    
    set_playmode(); 
    if (exact_username) {
        
        
        int len = (int) strlen(plname);
        
        if (++len < (int) sizeof plname)
            (void) strncat(strcat(plname, "-"), pl_character, sizeof plname - len - 1);
    }
    
    plnamesuffix();

    if (wizard) {
        
        locknum = 0;
    } else {
        
        (void) signal(SIGQUIT, SIG_IGN);
        (void) signal(SIGINT, SIG_IGN);
    }

    dlb_init(); 

    
    vision_init();

    display_gamewindows();

    
 attempt_restore:

    
    if (*plname) {
        getlock();
        program_state.preserve_locks = 0; 
    }

    if (*plname && (fd = restore_saved_game()) >= 0) {
        const char *fq_save = fqname(SAVEF, SAVEPREFIX, 1);

        (void) chmod(fq_save, 0); 

        (void) signal(SIGINT, (SIG_RET_TYPE) done1);


        if (iflags.news) {
            display_file(NEWS, FALSE);
            iflags.news = FALSE; 
        }

        pline("Restoring save file...");
        mark_synch(); 
        if (dorecover(fd)) {
            resuming = TRUE; 
            wd_message();
            if (discover || wizard) {
                
                if (yn("Do you want to keep the save file?") == 'n') {
                    (void) delete_savefile();
                } else {
                    (void) chmod(fq_save, FCMASK); 
                    nh_compress(fq_save);
                }
            }
        }
    }

    if (!resuming) {
        boolean neednewlock = (!*plname);
        
        if (!iflags.renameinprogress || iflags.defer_plname || neednewlock) {
            if (!plsel_once)
                player_selection();
            plsel_once = TRUE;
            if (neednewlock && *plname)
                goto attempt_restore;
            if (iflags.renameinprogress) {
                
                if (!locknum) {
                    delete_levelfile(0); 
                    getlock();
                }
                goto attempt_restore;
            }
        }
        newgame();
        wd_message();
    }

    
    moveloop(resuming);

    exit(EXIT_SUCCESS);
    
    return 0;
}

static void process_options(argc, argv)
int argc;
char *argv[];
{
    int i, l;

    
    while (argc > 1 && argv[1][0] == '-') {
        argv++;
        argc--;
        l = (int) strlen(*argv);
        
        if (l < 4)
            l = 4;

        switch (argv[0][1]) {
        case 'D':
        case 'd':
            if ((argv[0][1] == 'D' && !argv[0][2])
                || !strcmpi(*argv, "-debug")) {
                wizard = TRUE, discover = FALSE;
            } else if (!strncmpi(*argv, "-DECgraphics", l)) {
                load_symset("DECGraphics", PRIMARY);
                switch_symbols(TRUE);
            } else {
                raw_printf("Unknown option: %s", *argv);
            }
            break;
        case 'X':

            discover = TRUE, wizard = FALSE;
            break;

        case 'n':
            iflags.news = FALSE;
            break;

        case 'u':
            if (argv[0][2]) {
                (void) strncpy(plname, argv[0] + 2, sizeof plname - 1);
            } else if (argc > 1) {
                argc--;
                argv++;
                (void) strncpy(plname, argv[0], sizeof plname - 1);
            } else {
                raw_print("Player name expected after -u");
            }
            break;
        case 'I':
        case 'i':
            if (!strncmpi(*argv, "-IBMgraphics", l)) {
                load_symset("IBMGraphics", PRIMARY);
                load_symset("RogueIBM", ROGUESET);
                switch_symbols(TRUE);
            } else {
                raw_printf("Unknown option: %s", *argv);
            }
            break;
        case 'p': 
            if (argv[0][2]) {
                if ((i = str2role(&argv[0][2])) >= 0)
                    flags.initrole = i;
            } else if (argc > 1) {
                argc--;
                argv++;
                if ((i = str2role(argv[0])) >= 0)
                    flags.initrole = i;
            }
            break;
        case 'r': 
            if (argv[0][2]) {
                if ((i = str2race(&argv[0][2])) >= 0)
                    flags.initrace = i;
            } else if (argc > 1) {
                argc--;
                argv++;
                if ((i = str2race(argv[0])) >= 0)
                    flags.initrace = i;
            }
            break;
        case 'w': 
            config_error_init(FALSE, "command line", FALSE);
            choose_windows(&argv[0][2]);
            config_error_done();
            break;
        case '@':
            flags.randomall = 1;
            break;
        default:
            if ((i = str2role(&argv[0][1])) >= 0) {
                flags.initrole = i;
                break;
            }
            
        }
    }


    if (argc > 1)
        raw_printf("MAXPLAYERS are set in sysconf file.\n");

    
    if (argc > 1)
        locknum = atoi(argv[1]);


    
    if (!locknum || locknum > MAX_NR_OF_PLAYERS)
        locknum = MAX_NR_OF_PLAYERS;


    
    if (!locknum || (sysopt.maxplayers && locknum > sysopt.maxplayers))
        locknum = sysopt.maxplayers;

}


static void chdirx(dir, wr)
const char *dir;
boolean wr;
{
    if (dir   && strcmp(dir, HACKDIR)


        ) {

        (void) setgid(getgid());
        (void) setuid(getuid()); 

    } else {
        

        int len = strlen(VAR_PLAYGROUND);

        fqn_prefix[SCOREPREFIX] = (char *) alloc(len + 2);
        Strcpy(fqn_prefix[SCOREPREFIX], VAR_PLAYGROUND);
        if (fqn_prefix[SCOREPREFIX][len - 1] != '/') {
            fqn_prefix[SCOREPREFIX][len] = '/';
            fqn_prefix[SCOREPREFIX][len + 1] = '\0';
        }

    }


    if (dir == (const char *) 0)
        dir = HACKDIR;


    if (dir && chdir(dir) < 0) {
        perror(dir);
        error("Cannot chdir to %s.", dir);
    }

    
    if (wr) {

        fqn_prefix[LEVELPREFIX] = fqn_prefix[SCOREPREFIX];
        fqn_prefix[SAVEPREFIX] = fqn_prefix[SCOREPREFIX];
        fqn_prefix[BONESPREFIX] = fqn_prefix[SCOREPREFIX];
        fqn_prefix[LOCKPREFIX] = fqn_prefix[SCOREPREFIX];
        fqn_prefix[TROUBLEPREFIX] = fqn_prefix[SCOREPREFIX];

        check_recordfile(dir);
    }
}



static boolean whoami()
{
    
    if (!*plname) {
        register const char *s;

        s = nh_getenv("USER");
        if (!s || !*s)
            s = nh_getenv("LOGNAME");
        if (!s || !*s)
            s = getlogin();

        if (s && *s) {
            (void) strncpy(plname, s, sizeof plname - 1);
            if (index(plname, '-'))
                return TRUE;
        }
    }
    return FALSE;
}

void sethanguphandler(handler)
void FDECL((*handler), (int));
{

    
    struct sigaction sact;

    (void) memset((genericptr_t) &sact, 0, sizeof sact);
    sact.sa_handler = (SIG_RET_TYPE) handler;
    (void) sigaction(SIGHUP, &sact, (struct sigaction *) 0);

    (void) sigaction(SIGXCPU, &sact, (struct sigaction *) 0);


    (void) signal(SIGHUP, (SIG_RET_TYPE) handler);

    (void) signal(SIGXCPU, (SIG_RET_TYPE) handler);


}


void port_help()
{
    
    display_file(PORT_HELP, TRUE);
}



boolean authorize_wizard_mode()
{
    struct passwd *pw = get_unix_pw();

    if (pw && sysopt.wizards && sysopt.wizards[0]) {
        if (check_user_string(sysopt.wizards))
            return TRUE;
    }
    wiz_error_flag = TRUE; 
    return FALSE;
}

static void wd_message()
{
    if (wiz_error_flag) {
        if (sysopt.wizards && sysopt.wizards[0]) {
            char *tmp = build_english_list(sysopt.wizards);
            pline("Only user%s %s may access debug (wizard) mode.", index(sysopt.wizards, ' ') ? "s" : "", tmp);
            free(tmp);
        } else pline("Entering explore/discovery mode instead.");
        wizard = 0, discover = 1; 
    } else if (discover)
        You("are in non-scoring explore/discovery mode.");
}


void append_slash(name)
char *name;
{
    char *ptr;

    if (!*name)
        return;
    ptr = name + (strlen(name) - 1);
    if (*ptr != '/') {
        *++ptr = '/';
        *++ptr = '\0';
    }
    return;
}

boolean check_user_string(optstr)
char *optstr;
{
    struct passwd *pw;
    int pwlen;
    char *eop, *w;
    char *pwname = 0;

    if (optstr[0] == '*')
        return TRUE; 
    if (sysopt.check_plname)
        pwname = plname;
    else if ((pw = get_unix_pw()) != 0)
        pwname = pw->pw_name;
    if (!pwname || !*pwname)
        return FALSE;
    pwlen = (int) strlen(pwname);
    eop = eos(optstr);
    w = optstr;
    while (w + pwlen <= eop) {
        if (!*w)
            break;
        if (isspace(*w)) {
            w++;
            continue;
        }
        if (!strncmp(w, pwname, pwlen)) {
            if (!w[pwlen] || isspace(w[pwlen]))
                return TRUE;
        }
        while (*w && !isspace(*w))
            w++;
    }
    return FALSE;
}

static struct passwd * get_unix_pw()
{
    char *user;
    unsigned uid;
    static struct passwd *pw = (struct passwd *) 0;

    if (pw)
        return pw; 

    uid = (unsigned) getuid();
    user = getlogin();
    if (user) {
        pw = getpwnam(user);
        if (pw && ((unsigned) pw->pw_uid != uid))
            pw = 0;
    }
    if (pw == 0) {
        user = nh_getenv("USER");
        if (user) {
            pw = getpwnam(user);
            if (pw && ((unsigned) pw->pw_uid != uid))
                pw = 0;
        }
        if (pw == 0) {
            pw = getpwuid(uid);
        }
    }
    return pw;
}

char * get_login_name()
{
    static char buf[BUFSZ];
    struct passwd *pw = get_unix_pw();

    buf[0] = '\0';
    if (pw)
        (void)strcpy(buf, pw->pw_name);

    return buf;
}


extern int errno;

void port_insert_pastebuf(buf)
char *buf;
{
    
    const char *errfmt;
    size_t len;
    FILE *PB = popen("/usr/bin/pbcopy", "w");

    if (!PB) {
        errfmt = "Unable to start pbcopy (%d)\n";
        goto error;
    }

    len = strlen(buf);
    
    if (buf[len - 1] == '\n')
        len--;

    
    if (len != fwrite(buf, 1, len, PB)) {
        errfmt = "Error sending data to pbcopy (%d)\n";
        goto error;
    }

    if (pclose(PB) != -1) {
        return;
    }
    errfmt = "Error finishing pbcopy (%d)\n";

 error:
    raw_printf(errfmt, strerror(errno));
}


unsigned long sys_random_seed()
{
    unsigned long seed = 0L;
    unsigned long pid = (unsigned long) getpid();
    boolean no_seed = TRUE;

    FILE *fptr;

    fptr = fopen(DEV_RANDOM, "r");
    if (fptr) {
        fread(&seed, sizeof (long), 1, fptr);
        has_strong_rngseed = TRUE;  
        no_seed = FALSE;
        (void) fclose(fptr);
    } else {
        
        paniclog("sys_random_seed", "falling back to weak seed");
    }

    if (no_seed) {
        seed = (unsigned long) getnow(); 
        
        if (pid) {
            if (!(pid & 3L))
                pid -= 1L;
            seed *= pid;
        }
    }
    return seed;
}


