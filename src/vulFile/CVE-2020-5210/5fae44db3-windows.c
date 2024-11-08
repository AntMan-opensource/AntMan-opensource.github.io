








extern struct window_procs curses_procs;



extern struct window_procs X11_procs;
extern void FDECL(win_X11_init, (int));


extern struct window_procs Qt_procs;





extern struct window_procs mac_procs;


extern struct window_procs beos_procs;
extern void FDECL(be_win_init, (int));
FAIL    extern struct window_procs amii_procs;


extern struct window_procs amiv_procs;
extern void FDECL(ami_wininit_data, (int));


extern struct window_procs win32_procs;



extern struct window_procs Gnome_procs;


extern struct window_procs mswin_procs;


extern struct window_procs chainin_procs;
extern void FDECL(chainin_procs_init, (int));
extern void *FDECL(chainin_procs_chain, (int, int, void *, void *, void *));

extern struct chain_procs chainout_procs;
extern void FDECL(chainout_procs_init, (int));
extern void *FDECL(chainout_procs_chain, (int, int, void *, void *, void *));

extern struct chain_procs trace_procs;
extern void FDECL(trace_procs_init, (int));
extern void *FDECL(trace_procs_chain, (int, int, void *, void *, void *));


STATIC_DCL void FDECL(def_raw_print, (const char *s));
STATIC_DCL void NDECL(def_wait_synch);


STATIC_DCL winid FDECL(dump_create_nhwindow, (int));
STATIC_DCL void FDECL(dump_clear_nhwindow, (winid));
STATIC_DCL void FDECL(dump_display_nhwindow, (winid, BOOLEAN_P));
STATIC_DCL void FDECL(dump_destroy_nhwindow, (winid));
STATIC_DCL void FDECL(dump_start_menu, (winid));
STATIC_DCL void FDECL(dump_add_menu, (winid, int, const ANY_P *, CHAR_P, CHAR_P, int, const char *, BOOLEAN_P));
STATIC_DCL void FDECL(dump_end_menu, (winid, const char *));
STATIC_DCL int FDECL(dump_select_menu, (winid, int, MENU_ITEM_P **));
STATIC_DCL void FDECL(dump_putstr, (winid, int, const char *));



volatile  NEARDATA struct window_procs windowprocs;








static struct win_choices {
    struct window_procs *procs;
    void FDECL((*ini_routine), (int)); 

    void *FDECL((*chain_routine), (int, int, void *, void *, void *));

} winchoices[] = {

    { &tty_procs, win_tty_init CHAINR(0) },   { &curses_procs, 0 },   { &X11_procs, win_X11_init CHAINR(0) },   { &Qt_procs, 0 CHAINR(0) },   { &Gem_procs, win_Gem_init CHAINR(0) },   { &mac_procs, 0 CHAINR(0) },   { &beos_procs, be_win_init CHAINR(0) },   { &amii_procs, ami_wininit_data CHAINR(0) }, { &amiv_procs, ami_wininit_data CHAINR(0) },   { &win32_procs, 0 CHAINR(0) },   { &Gnome_procs, 0 CHAINR(0) },   { &mswin_procs, 0 CHAINR(0) },   { &chainin_procs, chainin_procs_init, chainin_procs_chain }, { (struct window_procs *) &chainout_procs, chainout_procs_init, chainout_procs_chain },  { (struct window_procs *) &trace_procs, trace_procs_init, trace_procs_chain },  { 0, 0 CHAINR(0) }










































};


struct winlink {
    struct winlink *nextlink;
    struct win_choices *wincp;
    void *linkdata;
};


static struct winlink *chain = 0;

static struct winlink * wl_new()
{
    struct winlink *wl = (struct winlink *) alloc(sizeof *wl);

    wl->nextlink = 0;
    wl->wincp = 0;
    wl->linkdata = 0;

    return wl;
}

static void wl_addhead(struct winlink *wl)
{
    wl->nextlink = chain;
    chain = wl;
}

static void wl_addtail(struct winlink *wl)
{
    struct winlink *p = chain;

    if (!chain) {
        chain = wl;
        return;
    }
    while (p->nextlink) {
        p = p->nextlink;
    }
    p->nextlink = wl;
    return;
}


static struct win_choices *last_winchoice = 0;

boolean genl_can_suspend_no(VOID_ARGS)
{
    return FALSE;
}

boolean genl_can_suspend_yes(VOID_ARGS)
{
    return TRUE;
}

STATIC_OVL void def_raw_print(s)

const char *s;
{
    puts(s);
}

STATIC_OVL void def_wait_synch(VOID_ARGS)

{
    
     return;
}


static struct win_choices * win_choices_find(s)
const char *s;
{
    register int i;

    for (i = 0; winchoices[i].procs; i++) {
        if (!strcmpi(s, winchoices[i].procs->name)) {
            return &winchoices[i];
        }
    }
    return (struct win_choices *) 0;
}


void choose_windows(s)
const char *s;
{
    register int i;

    for (i = 0; winchoices[i].procs; i++) {
        if ('+' == winchoices[i].procs->name[0])
            continue;
        if ('-' == winchoices[i].procs->name[0])
            continue;
        if (!strcmpi(s, winchoices[i].procs->name)) {
            windowprocs = *winchoices[i].procs;

            if (last_winchoice && last_winchoice->ini_routine)
                (*last_winchoice->ini_routine)(WININIT_UNDO);
            if (winchoices[i].ini_routine)
                (*winchoices[i].ini_routine)(WININIT);
            last_winchoice = &winchoices[i];
            return;
        }
    }

    if (!windowprocs.win_raw_print)
        windowprocs.win_raw_print = def_raw_print;
    if (!windowprocs.win_wait_synch)
        
        windowprocs.win_wait_synch = def_wait_synch;

    if (!winchoices[0].procs) {
        raw_printf("No window types?");
        nh_terminate(EXIT_FAILURE);
    }
    if (!winchoices[1].procs) {
        config_error_add( "Window type %s not recognized.  The only choice is: %s", s, winchoices[0].procs->name);

    } else {
        char buf[BUFSZ];
        boolean first = TRUE;

        buf[0] = '\0';
        for (i = 0; winchoices[i].procs; i++) {
            if ('+' == winchoices[i].procs->name[0])
                continue;
            if ('-' == winchoices[i].procs->name[0])
                continue;
            Sprintf(eos(buf), "%s%s", first ? "" : ", ", winchoices[i].procs->name);
            first = FALSE;
        }
        config_error_add("Window type %s not recognized.  Choices are:  %s", s, buf);
    }

    if (windowprocs.win_raw_print == def_raw_print || WINDOWPORT("safe-startup"))
        nh_terminate(EXIT_SUCCESS);
}


void addto_windowchain(s)
const char *s;
{
    register int i;

    for (i = 0; winchoices[i].procs; i++) {
        if ('+' != winchoices[i].procs->name[0])
            continue;
        if (!strcmpi(s, winchoices[i].procs->name)) {
            struct winlink *p = wl_new();

            p->wincp = &winchoices[i];
            wl_addtail(p);
            
            return;
        }
    }

    windowprocs.win_raw_print = def_raw_print;

    raw_printf("Window processor %s not recognized.  Choices are:", s);
    for (i = 0; winchoices[i].procs; i++) {
        if ('+' != winchoices[i].procs->name[0])
            continue;
        raw_printf("        %s", winchoices[i].procs->name);
    }

    nh_terminate(EXIT_FAILURE);
}

void commit_windowchain()
{
    struct winlink *p;
    int n;
    int wincap, wincap2;

    if (!chain)
        return;

    
    wincap = windowprocs.wincap;
    wincap2 = windowprocs.wincap2;

    
    p = wl_new();
    p->wincp = win_choices_find("-chainin");
    if (!p->wincp) {
        raw_printf("Can't locate processor '-chainin'");
        exit(EXIT_FAILURE);
    }
    wl_addhead(p);

    p = wl_new();
    p->wincp = win_choices_find("-chainout");
    if (!p->wincp) {
        raw_printf("Can't locate processor '-chainout'");
        exit(EXIT_FAILURE);
    }
    wl_addtail(p);

    
    for (n = 1, p = chain; p; n++, p = p->nextlink) {
        p->linkdata = (*p->wincp->chain_routine)(WINCHAIN_ALLOC, n, 0, 0, 0);
    }

    for (n = 1, p = chain; p; n++, p = p->nextlink) {
        if (p->nextlink) {
            (void) (*p->wincp->chain_routine)(WINCHAIN_INIT, n, p->linkdata, p->nextlink->wincp->procs, p->nextlink->linkdata);

        } else {
            (void) (*p->wincp->chain_routine)(WINCHAIN_INIT, n, p->linkdata, last_winchoice->procs, 0);
        }
    }

    
    chain->wincp->procs->wincap = wincap;
    chain->wincp->procs->wincap2 = wincap2;

    
    p = chain;
    while (p->nextlink) {
        if (p->wincp->ini_routine) {
            (*p->wincp->ini_routine)(WININIT);
        }
        p = p->nextlink;
    }

    
    windowprocs = *chain->wincp->procs;

    p = chain;
    while (p) {
        struct winlink *np = p->nextlink;
        free(p);
        p = np; 
    }
}




char genl_message_menu(let, how, mesg)
char let UNUSED;
int how UNUSED;
const char *mesg;
{
    pline("%s", mesg);
    return 0;
}


void genl_preference_update(pref)
const char *pref UNUSED;
{
    
    return;
}

char * genl_getmsghistory(init)
boolean init UNUSED;
{
    
    return (char *) 0;
}

void genl_putmsghistory(msg, is_restoring)
const char *msg;
boolean is_restoring;
{
    

    
    if (!is_restoring)
        pline("%s", msg);
    return;
}




static int NDECL(hup_nhgetch);
static char FDECL(hup_yn_function, (const char *, const char *, CHAR_P));
static int FDECL(hup_nh_poskey, (int *, int *, int *));
static void FDECL(hup_getlin, (const char *, char *));
static void FDECL(hup_init_nhwindows, (int *, char **));
static void FDECL(hup_exit_nhwindows, (const char *));
static winid FDECL(hup_create_nhwindow, (int));
static int FDECL(hup_select_menu, (winid, int, MENU_ITEM_P **));
static void FDECL(hup_add_menu, (winid, int, const anything *, CHAR_P, CHAR_P, int, const char *, BOOLEAN_P));
static void FDECL(hup_end_menu, (winid, const char *));
static void FDECL(hup_putstr, (winid, int, const char *));
static void FDECL(hup_print_glyph, (winid, XCHAR_P, XCHAR_P, int, int));
static void FDECL(hup_outrip, (winid, int, time_t));
static void FDECL(hup_curs, (winid, int, int));
static void FDECL(hup_display_nhwindow, (winid, BOOLEAN_P));
static void FDECL(hup_display_file, (const char *, BOOLEAN_P));

static void FDECL(hup_cliparound, (int, int));


static void FDECL(hup_change_color, (int, long, int));

static short FDECL(hup_set_font_name, (winid, char *));

static char *NDECL(hup_get_color_string);

static void FDECL(hup_status_update, (int, genericptr_t, int, int, int, unsigned long *));

static int NDECL(hup_int_ndecl);
static void NDECL(hup_void_ndecl);
static void FDECL(hup_void_fdecl_int, (int));
static void FDECL(hup_void_fdecl_winid, (winid));
static void FDECL(hup_void_fdecl_constchar_p, (const char *));

static struct window_procs hup_procs = {
    "hup", 0L, 0L, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, hup_init_nhwindows, hup_void_ndecl, hup_void_ndecl, hup_void_ndecl, hup_exit_nhwindows, hup_void_fdecl_constchar_p, hup_void_ndecl, hup_create_nhwindow, hup_void_fdecl_winid, hup_display_nhwindow, hup_void_fdecl_winid, hup_curs, hup_putstr, hup_putstr, hup_display_file, hup_void_fdecl_winid, hup_add_menu, hup_end_menu, hup_select_menu, genl_message_menu, hup_void_ndecl, hup_void_ndecl, hup_void_ndecl,  hup_cliparound,   (void FDECL((*), (char *))) hup_void_fdecl_constchar_p,   hup_print_glyph, hup_void_fdecl_constchar_p, hup_void_fdecl_constchar_p, hup_nhgetch, hup_nh_poskey, hup_void_ndecl, hup_int_ndecl, hup_yn_function, hup_getlin, hup_int_ndecl, hup_void_fdecl_int, hup_void_ndecl,  hup_change_color,  hup_void_fdecl_int, hup_set_font_name,  hup_get_color_string,  hup_void_ndecl, hup_void_ndecl, hup_outrip, genl_preference_update, genl_getmsghistory, genl_putmsghistory, hup_void_ndecl, hup_void_ndecl, genl_status_enablefield, hup_status_update, genl_can_suspend_no, };















































static void FDECL((*previnterface_exit_nhwindows), (const char *)) = 0;


void nhwindows_hangup()
{
    char *FDECL((*previnterface_getmsghistory), (BOOLEAN_P)) = 0;


    
    iflags.altmeta = FALSE;


    
    if (iflags.window_inited && windowprocs.win_exit_nhwindows != hup_exit_nhwindows)
        previnterface_exit_nhwindows = windowprocs.win_exit_nhwindows;

    
    if (windowprocs.win_getmsghistory != hup_procs.win_getmsghistory)
        previnterface_getmsghistory = windowprocs.win_getmsghistory;

    windowprocs = hup_procs;

    if (previnterface_getmsghistory)
        windowprocs.win_getmsghistory = previnterface_getmsghistory;
}

static void hup_exit_nhwindows(lastgasp)
const char *lastgasp;
{
    
    if (previnterface_exit_nhwindows) {
        lastgasp = 0; 
        (*previnterface_exit_nhwindows)(lastgasp);
        previnterface_exit_nhwindows = 0;
    }
    iflags.window_inited = 0;
}

static int hup_nhgetch(VOID_ARGS)
{
    return '\033'; 
}


static char hup_yn_function(prompt, resp, deflt)
const char *prompt UNUSED, *resp UNUSED;
char deflt;
{
    if (!deflt)
        deflt = '\033';
    return deflt;
}


static int hup_nh_poskey(x, y, mod)
int *x UNUSED, *y UNUSED, *mod UNUSED;
{
    return '\033';
}


static void hup_getlin(prompt, outbuf)
const char *prompt UNUSED;
char *outbuf;
{
    Strcpy(outbuf, "\033");
}


static void hup_init_nhwindows(argc_p, argv)
int *argc_p UNUSED;
char **argv UNUSED;
{
    iflags.window_inited = 1;
}


static winid hup_create_nhwindow(type)
int type UNUSED;
{
    return WIN_ERR;
}


static int hup_select_menu(window, how, menu_list)
winid window UNUSED;
int how UNUSED;
struct mi **menu_list UNUSED;
{
    return -1;
}


static void hup_add_menu(window, glyph, identifier, sel, grpsel, attr, txt, preselected)
winid window UNUSED;
int glyph UNUSED, attr UNUSED;
const anything *identifier UNUSED;
char sel UNUSED, grpsel UNUSED;
const char *txt UNUSED;
boolean preselected UNUSED;
{
    return;
}


static void hup_end_menu(window, prompt)
winid window UNUSED;
const char *prompt UNUSED;
{
    return;
}


static void hup_putstr(window, attr, text)
winid window UNUSED;
int attr UNUSED;
const char *text UNUSED;
{
    return;
}


static void hup_print_glyph(window, x, y, glyph, bkglyph)
winid window UNUSED;
xchar x UNUSED, y UNUSED;
int glyph UNUSED;
int bkglyph UNUSED;
{
    return;
}


static void hup_outrip(tmpwin, how, when)
winid tmpwin UNUSED;
int how UNUSED;
time_t when UNUSED;
{
    return;
}


static void hup_curs(window, x, y)
winid window UNUSED;
int x UNUSED, y UNUSED;
{
    return;
}


static void hup_display_nhwindow(window, blocking)
winid window UNUSED;
boolean blocking UNUSED;
{
    return;
}


static void hup_display_file(fname, complain)
const char *fname UNUSED;
boolean complain UNUSED;
{
    return;
}



static void hup_cliparound(x, y)
int x UNUSED, y UNUSED;
{
    return;
}




static void hup_change_color(color, rgb, reverse)
int color, reverse;
long rgb;
{
    return;
}



static short hup_set_font_name(window, fontname)
winid window;
char *fontname;
{
    return 0;
}


static char * hup_get_color_string(VOID_ARGS)
{
    return (char *) 0;
}



static void hup_status_update(idx, ptr, chg, pc, color, colormasks)
int idx UNUSED;
genericptr_t ptr UNUSED;
int chg UNUSED, pc UNUSED, color UNUSED;
unsigned long *colormasks UNUSED;

{
    return;
}



static int hup_int_ndecl(VOID_ARGS)
{
    return -1;
}

static void hup_void_ndecl(VOID_ARGS)
{
    return;
}


static void hup_void_fdecl_int(arg)
int arg UNUSED;
{
    return;
}


static void hup_void_fdecl_winid(window)
winid window UNUSED;
{
    return;
}


static void hup_void_fdecl_constchar_p(string)
const char *string UNUSED;
{
    return;
}








const char *status_fieldnm[MAXBLSTATS];
const char *status_fieldfmt[MAXBLSTATS];
char *status_vals[MAXBLSTATS];
boolean status_activefields[MAXBLSTATS];
NEARDATA winid WIN_STATUS;

void genl_status_init()
{
    int i;

    for (i = 0; i < MAXBLSTATS; ++i) {
        status_vals[i] = (char *) alloc(MAXCO);
        *status_vals[i] = '\0';
        status_activefields[i] = FALSE;
        status_fieldfmt[i] = (const char *) 0;
    }
    
    WIN_STATUS = create_nhwindow(NHW_STATUS);
    display_nhwindow(WIN_STATUS, FALSE);
}

void genl_status_finish()
{
    
    int i;

    
    for (i = 0; i < MAXBLSTATS; ++i) {
        if (status_vals[i])
            free((genericptr_t) status_vals[i]), status_vals[i] = (char *) 0;
    }
}

void genl_status_enablefield(fieldidx, nm, fmt, enable)
int fieldidx;
const char *nm;
const char *fmt;
boolean enable;
{
    status_fieldfmt[fieldidx] = fmt;
    status_fieldnm[fieldidx] = nm;
    status_activefields[fieldidx] = enable;
}


void genl_status_update(idx, ptr, chg, percent, color, colormasks)
int idx;
genericptr_t ptr;
int chg UNUSED, percent UNUSED, color UNUSED;
unsigned long *colormasks UNUSED;
{
    char newbot1[MAXCO], newbot2[MAXCO];
    long cond, *condptr = (long *) ptr;
    register int i;
    unsigned pass, lndelta;
    enum statusfields idx1, idx2, *fieldlist;
    char *nb, *text = (char *) ptr;

    static enum statusfields fieldorder[][15] = {
        
        { BL_TITLE, BL_STR, BL_DX, BL_CO, BL_IN, BL_WI, BL_CH, BL_ALIGN, BL_SCORE, BL_FLUSH, BL_FLUSH, BL_FLUSH, BL_FLUSH, BL_FLUSH, BL_FLUSH },  { BL_LEVELDESC, BL_GOLD, BL_HP, BL_HPMAX, BL_ENE, BL_ENEMAX, BL_AC, BL_XP, BL_EXP, BL_HD, BL_TIME, BL_HUNGER, BL_CAP, BL_CONDITION, BL_FLUSH },  { BL_LEVELDESC, BL_GOLD, BL_HP, BL_HPMAX, BL_ENE, BL_ENEMAX, BL_AC, BL_XP, BL_EXP, BL_HD, BL_HUNGER, BL_CAP, BL_CONDITION, BL_TIME, BL_FLUSH },  { BL_LEVELDESC, BL_GOLD, BL_HP, BL_HPMAX, BL_ENE, BL_ENEMAX, BL_AC, BL_HUNGER, BL_CAP, BL_CONDITION, BL_XP, BL_EXP, BL_HD, BL_TIME, BL_FLUSH },  { BL_HP, BL_HPMAX, BL_ENE, BL_ENEMAX, BL_AC, BL_HUNGER, BL_CAP, BL_CONDITION, BL_LEVELDESC, BL_GOLD, BL_XP, BL_EXP, BL_HD, BL_TIME, BL_FLUSH }, };

























    
    windowprocs.wincap2 |= WC2_FLUSH_STATUS;

    if (idx >= 0) {
        if (!status_activefields[idx])
            return;
        switch (idx) {
        case BL_CONDITION:
            cond = condptr ? *condptr : 0L;
            nb = status_vals[idx];
            *nb = '\0';
            if (cond & BL_MASK_STONE)
                Strcpy(nb = eos(nb), " Stone");
            if (cond & BL_MASK_SLIME)
                Strcpy(nb = eos(nb), " Slime");
            if (cond & BL_MASK_STRNGL)
                Strcpy(nb = eos(nb), " Strngl");
            if (cond & BL_MASK_FOODPOIS)
                Strcpy(nb = eos(nb), " FoodPois");
            if (cond & BL_MASK_TERMILL)
                Strcpy(nb = eos(nb), " TermIll");
            if (cond & BL_MASK_BLIND)
                Strcpy(nb = eos(nb), " Blind");
            if (cond & BL_MASK_DEAF)
                Strcpy(nb = eos(nb), " Deaf");
            if (cond & BL_MASK_STUN)
                Strcpy(nb = eos(nb), " Stun");
            if (cond & BL_MASK_CONF)
                Strcpy(nb = eos(nb), " Conf");
            if (cond & BL_MASK_HALLU)
                Strcpy(nb = eos(nb), " Hallu");
            if (cond & BL_MASK_LEV)
                Strcpy(nb = eos(nb), " Lev");
            if (cond & BL_MASK_FLY)
                Strcpy(nb = eos(nb), " Fly");
            if (cond & BL_MASK_RIDE)
                Strcpy(nb = eos(nb), " Ride");
            break;
        default:
            Sprintf(status_vals[idx], status_fieldfmt[idx] ? status_fieldfmt[idx] : "%s", text ? text : "");

            break;
        }
        return; 
    } 

    

    if (!(idx == BL_FLUSH || idx == BL_RESET))
        return;

    
    nb = newbot1;
    *nb = '\0';
    
    for (i = 0; (idx1 = fieldorder[0][i]) != BL_FLUSH; ++i) {
        if (status_activefields[idx1])
            Strcpy(nb = eos(nb), status_vals[idx1]);
    }
    
    lndelta = (status_activefields[BL_GOLD] && strstr(status_vals[BL_GOLD], "\\G")) ? 9 : 0;
    
    for (pass = 1; pass <= 4; pass++) {
        fieldlist = fieldorder[pass];
        nb = newbot2;
        *nb = '\0';
        for (i = 0; (idx2 = fieldlist[i]) != BL_FLUSH; ++i) {
            if (status_activefields[idx2]) {
                const char *val = status_vals[idx2];

                switch (idx2) {
                case BL_HP: 
                case BL_XP: case BL_HD:
                case BL_TIME:
                    Strcpy(nb = eos(nb), " ");
                    break;
                case BL_LEVELDESC:
                    
                    if (i != 0)
                        Strcpy(nb = eos(nb), " ");
                    break;
                
                case BL_HUNGER:
                    
                    if (strcmp(val, " "))
                        Strcpy(nb = eos(nb), " ");
                    break;
                case BL_CAP:
                    
                    if (!strcmp(val, " "))
                        ++val;
                    break;
                default:
                    break;
                }
                Strcpy(nb = eos(nb), val); 
            } 

            if (idx2 == BL_CONDITION && pass < 4 && strlen(newbot2) - lndelta > COLNO)
                break; 
        } 

        if (idx2 == BL_FLUSH) { 
            if (pass > 1)
                mungspaces(newbot2);
            break;
        }
    } 
    curs(WIN_STATUS, 1, 0);
    putstr(WIN_STATUS, 0, newbot1);
    curs(WIN_STATUS, 1, 1);
    putmixed(WIN_STATUS, 0, newbot2); 
}

STATIC_VAR struct window_procs dumplog_windowprocs_backup;
STATIC_VAR FILE *dumplog_file;


STATIC_VAR time_t dumplog_now;

char * dump_fmtstr(fmt, buf, fullsubs)
const char *fmt;
char *buf;
boolean fullsubs; 
{
    const char *fp = fmt;
    char *bp = buf;
    int slen, len = 0;
    char tmpbuf[BUFSZ];
    char verbuf[BUFSZ];
    long uid;
    time_t now;

    now = dumplog_now;
    uid = (long) getuid();

    

    while (fp && *fp && len < BUFSZ - 1) {
        if (*fp == '%') {
            fp++;
            switch (*fp) {
            default:
                goto finish;
            case '\0': 
            case '%':  
                Sprintf(tmpbuf, "%%");
                break;
            case 't': 
                if (fullsubs)
                    Sprintf(tmpbuf, "%lu", (unsigned long) ubirthday);
                else Strcpy(tmpbuf, "{game start cookie}");
                break;
            case 'T': 
                if (fullsubs)
                    Sprintf(tmpbuf, "%lu", (unsigned long) now);
                else Strcpy(tmpbuf, "{current time cookie}");
                break;
            case 'd': 
                if (fullsubs)
                    Sprintf(tmpbuf, "%08ld%06ld", yyyymmdd(ubirthday), hhmmss(ubirthday));
                else Strcpy(tmpbuf, "{game start date+time}");
                break;
            case 'D': 
                if (fullsubs)
                    Sprintf(tmpbuf, "%08ld%06ld", yyyymmdd(now), hhmmss(now));
                else Strcpy(tmpbuf, "{current date+time}");
                break;
            case 'v': 
                Sprintf(tmpbuf, "%s", version_string(verbuf));
                break;
            case 'u': 
                Sprintf(tmpbuf, "%ld", uid);
                break;
            case 'n': 
                if (fullsubs)
                    Sprintf(tmpbuf, "%s", *plname ? plname : "unknown");
                else Strcpy(tmpbuf, "{hero name}");
                break;
            case 'N': 
                if (fullsubs)
                    Sprintf(tmpbuf, "%c", *plname ? *plname : 'u');
                else Strcpy(tmpbuf, "{hero initial}");
                break;
            }
            if (fullsubs) {
                
                (void) strNsubst(tmpbuf, " ", "_", 0);
                (void) strNsubst(tmpbuf, "/", "_", 0);
                (void) strNsubst(tmpbuf, "\\", "_", 0);
                
            }

            slen = (int) strlen(tmpbuf);
            if (len + slen < BUFSZ - 1) {
                len += slen;
                Sprintf(bp, "%s", tmpbuf);
                bp += slen;
                if (*fp)
                    fp++;
            } else break;
        } else {
            *bp = *fp;
            bp++;
            fp++;
            len++;
        }
    }
 finish:
    *bp = '\0';
    return buf;
}


void dump_open_log(now)
time_t now;
{

    char buf[BUFSZ];
    char *fname;

    dumplog_now = now;

    if (!sysopt.dumplogfile)
        return;
    fname = dump_fmtstr(sysopt.dumplogfile, buf, TRUE);

    fname = dump_fmtstr(DUMPLOG_FILE, buf, TRUE);

    dumplog_file = fopen(fname, "w");
    dumplog_windowprocs_backup = windowprocs;


    nhUse(now);

}

void dump_close_log()
{
    if (dumplog_file) {
        (void) fclose(dumplog_file);
        dumplog_file = (FILE *) 0;
    }
}

void dump_forward_putstr(win, attr, str, no_forward)
winid win;
int attr;
const char *str;
int no_forward;
{
    if (dumplog_file)
        fprintf(dumplog_file, "%s\n", str);
    if (!no_forward)
        putstr(win, attr, str);
}


STATIC_OVL void dump_putstr(win, attr, str)
winid win UNUSED;
int attr UNUSED;
const char *str;
{
    if (dumplog_file)
        fprintf(dumplog_file, "%s\n", str);
}

STATIC_OVL winid dump_create_nhwindow(dummy)
int dummy;
{
    return dummy;
}


STATIC_OVL void dump_clear_nhwindow(win)
winid win UNUSED;
{
    return;
}


STATIC_OVL void dump_display_nhwindow(win, p)
winid win UNUSED;
boolean p UNUSED;
{
    return;
}


STATIC_OVL void dump_destroy_nhwindow(win)
winid win UNUSED;
{
    return;
}


STATIC_OVL void dump_start_menu(win)
winid win UNUSED;
{
    return;
}


STATIC_OVL void dump_add_menu(win, glyph, identifier, ch, gch, attr, str, preselected)
winid win UNUSED;
int glyph;
const anything *identifier UNUSED;
char ch;
char gch UNUSED;
int attr UNUSED;
const char *str;
boolean preselected UNUSED;
{
    if (dumplog_file) {
        if (glyph == NO_GLYPH)
            fprintf(dumplog_file, " %s\n", str);
        else fprintf(dumplog_file, "  %c - %s\n", ch, str);
    }
}


STATIC_OVL void dump_end_menu(win, str)
winid win UNUSED;
const char *str;
{
    if (dumplog_file) {
        if (str)
            fprintf(dumplog_file, "%s\n", str);
        else fputs("\n", dumplog_file);
    }
}

STATIC_OVL int dump_select_menu(win, how, item)
winid win UNUSED;
int how UNUSED;
menu_item **item;
{
    *item = (menu_item *) 0;
    return 0;
}

void dump_redirect(onoff_flag)
boolean onoff_flag;
{
    if (dumplog_file) {
        if (onoff_flag) {
            windowprocs.win_create_nhwindow = dump_create_nhwindow;
            windowprocs.win_clear_nhwindow = dump_clear_nhwindow;
            windowprocs.win_display_nhwindow = dump_display_nhwindow;
            windowprocs.win_destroy_nhwindow = dump_destroy_nhwindow;
            windowprocs.win_start_menu = dump_start_menu;
            windowprocs.win_add_menu = dump_add_menu;
            windowprocs.win_end_menu = dump_end_menu;
            windowprocs.win_select_menu = dump_select_menu;
            windowprocs.win_putstr = dump_putstr;
        } else {
            windowprocs = dumplog_windowprocs_backup;
        }
        iflags.in_dumplog = onoff_flag;
    } else {
        iflags.in_dumplog = FALSE;
    }
}




extern const char *hilites[CLR_MAX];

extern NEARDATA char *hilites[CLR_MAX];




int has_color(color)
int color;
{
    return (iflags.use_color && windowprocs.name && (windowprocs.wincap & WC_COLOR) && windowprocs.has_color[color]   && (hilites[color] != 0)





    );
}


