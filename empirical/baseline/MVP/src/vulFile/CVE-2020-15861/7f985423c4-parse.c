














































































netsnmp_feature_child_of(find_module, mib_api)
netsnmp_feature_child_of(get_tc_description, mib_api)


struct node {
    struct node    *next;
    char           *label;  
    u_long          subid;  
    int             modid;  
    char           *parent; 
    int             tc_index; 
    int             type;   
    int             access;
    int             status;
    struct enum_list *enums; 
    struct range_list *ranges;
    struct index_list *indexes;
    char           *augments;
    struct varbind_list *varbinds;
    char           *hint;
    char           *units;
    char           *description; 
    char           *reference; 
    char           *defaultValue;
    char           *filename;
    int             lineno;
};


struct subid_s {
    int             subid;
    int             modid;
    char           *label;
};


struct tc {                     
    int             type;
    int             modid;
    char           *descriptor;
    char           *hint;
    struct enum_list *enums;
    struct range_list *ranges;
    char           *description;
} tclist[MAXTC];

int             mibLine = 0;
const char     *File = "(none)";
static int      anonymous = 0;

struct objgroup {
    char           *name;
    int             line;
    struct objgroup *next;
}              *objgroups = NULL, *objects = NULL, *notifs = NULL;



















































































































struct tok {
    const char     *name;       
    int             len;        
    int             token;      
    int             hash;       
    struct tok     *next;       
};


static struct tok tokens[] = {
    {"obsolete", sizeof("obsolete") - 1, OBSOLETE}
    , {"Opaque", sizeof("Opaque") - 1, KW_OPAQUE}
    , {"optional", sizeof("optional") - 1, KW_OPTIONAL}
    , {"LAST-UPDATED", sizeof("LAST-UPDATED") - 1, LASTUPDATED}
    , {"ORGANIZATION", sizeof("ORGANIZATION") - 1, ORGANIZATION}
    , {"CONTACT-INFO", sizeof("CONTACT-INFO") - 1, CONTACTINFO}
    , {"MODULE-IDENTITY", sizeof("MODULE-IDENTITY") - 1, MODULEIDENTITY}
    , {"MODULE-COMPLIANCE", sizeof("MODULE-COMPLIANCE") - 1, COMPLIANCE}
    , {"DEFINITIONS", sizeof("DEFINITIONS") - 1, DEFINITIONS}
    , {"END", sizeof("END") - 1, END}
    , {"AUGMENTS", sizeof("AUGMENTS") - 1, AUGMENTS}
    , {"not-accessible", sizeof("not-accessible") - 1, NOACCESS}
    , {"write-only", sizeof("write-only") - 1, WRITEONLY}
    , {"NsapAddress", sizeof("NsapAddress") - 1, NSAPADDRESS}
    , {"UNITS", sizeof("Units") - 1, UNITS}
    , {"REFERENCE", sizeof("REFERENCE") - 1, REFERENCE}
    , {"NUM-ENTRIES", sizeof("NUM-ENTRIES") - 1, NUM_ENTRIES}
    , {"BITSTRING", sizeof("BITSTRING") - 1, BITSTRING}
    , {"BIT", sizeof("BIT") - 1, CONTINUE}
    , {"BITS", sizeof("BITS") - 1, BITSTRING}
    , {"Counter64", sizeof("Counter64") - 1, COUNTER64}
    , {"TimeTicks", sizeof("TimeTicks") - 1, TIMETICKS}
    , {"NOTIFICATION-TYPE", sizeof("NOTIFICATION-TYPE") - 1, NOTIFTYPE}
    , {"OBJECT-GROUP", sizeof("OBJECT-GROUP") - 1, OBJGROUP}
    , {"OBJECT-IDENTITY", sizeof("OBJECT-IDENTITY") - 1, OBJIDENTITY}
    , {"IDENTIFIER", sizeof("IDENTIFIER") - 1, IDENTIFIER}
    , {"OBJECT", sizeof("OBJECT") - 1, OBJECT}
    , {"NetworkAddress", sizeof("NetworkAddress") - 1, NETADDR}
    , {"Gauge", sizeof("Gauge") - 1, GAUGE}
    , {"Gauge32", sizeof("Gauge32") - 1, GAUGE}
    , {"Unsigned32", sizeof("Unsigned32") - 1, UNSIGNED32}
    , {"read-write", sizeof("read-write") - 1, READWRITE}
    , {"read-create", sizeof("read-create") - 1, READCREATE}
    , {"OCTETSTRING", sizeof("OCTETSTRING") - 1, OCTETSTR}
    , {"OCTET", sizeof("OCTET") - 1, CONTINUE}
    , {"OF", sizeof("OF") - 1, OF}
    , {"SEQUENCE", sizeof("SEQUENCE") - 1, SEQUENCE}
    , {"NULL", sizeof("NULL") - 1, NUL}
    , {"IpAddress", sizeof("IpAddress") - 1, IPADDR}
    , {"UInteger32", sizeof("UInteger32") - 1, UINTEGER32}
    , {"INTEGER", sizeof("INTEGER") - 1, INTEGER}
    , {"Integer32", sizeof("Integer32") - 1, INTEGER32}
    , {"Counter", sizeof("Counter") - 1, COUNTER}
    , {"Counter32", sizeof("Counter32") - 1, COUNTER}
    , {"read-only", sizeof("read-only") - 1, READONLY}
    , {"DESCRIPTION", sizeof("DESCRIPTION") - 1, DESCRIPTION}
    , {"INDEX", sizeof("INDEX") - 1, INDEX}
    , {"DEFVAL", sizeof("DEFVAL") - 1, DEFVAL}
    , {"deprecated", sizeof("deprecated") - 1, DEPRECATED}
    , {"SIZE", sizeof("SIZE") - 1, SIZE}
    , {"MAX-ACCESS", sizeof("MAX-ACCESS") - 1, ACCESS}
    , {"ACCESS", sizeof("ACCESS") - 1, ACCESS}
    , {"mandatory", sizeof("mandatory") - 1, MANDATORY}
    , {"current", sizeof("current") - 1, CURRENT}
    , {"STATUS", sizeof("STATUS") - 1, STATUS}
    , {"SYNTAX", sizeof("SYNTAX") - 1, SYNTAX}
    , {"OBJECT-TYPE", sizeof("OBJECT-TYPE") - 1, OBJTYPE}
    , {"TRAP-TYPE", sizeof("TRAP-TYPE") - 1, TRAPTYPE}
    , {"ENTERPRISE", sizeof("ENTERPRISE") - 1, ENTERPRISE}
    , {"BEGIN", sizeof("BEGIN") - 1, BEGIN}
    , {"IMPORTS", sizeof("IMPORTS") - 1, IMPORTS}
    , {"EXPORTS", sizeof("EXPORTS") - 1, EXPORTS}
    , {"accessible-for-notify", sizeof("accessible-for-notify") - 1, ACCNOTIFY}

    , {"TEXTUAL-CONVENTION", sizeof("TEXTUAL-CONVENTION") - 1, CONVENTION}
    , {"NOTIFICATION-GROUP", sizeof("NOTIFICATION-GROUP") - 1, NOTIFGROUP}
    , {"DISPLAY-HINT", sizeof("DISPLAY-HINT") - 1, DISPLAYHINT}
    , {"FROM", sizeof("FROM") - 1, FROM}
    , {"AGENT-CAPABILITIES", sizeof("AGENT-CAPABILITIES") - 1, AGENTCAP}
    , {"MACRO", sizeof("MACRO") - 1, MACRO}
    , {"IMPLIED", sizeof("IMPLIED") - 1, IMPLIED}
    , {"SUPPORTS", sizeof("SUPPORTS") - 1, SUPPORTS}
    , {"INCLUDES", sizeof("INCLUDES") - 1, INCLUDES}
    , {"VARIATION", sizeof("VARIATION") - 1, VARIATION}
    , {"REVISION", sizeof("REVISION") - 1, REVISION}
    , {"not-implemented", sizeof("not-implemented") - 1, NOTIMPL}
    , {"OBJECTS", sizeof("OBJECTS") - 1, OBJECTS}
    , {"NOTIFICATIONS", sizeof("NOTIFICATIONS") - 1, NOTIFICATIONS}
    , {"MODULE", sizeof("MODULE") - 1, MODULE}
    , {"MIN-ACCESS", sizeof("MIN-ACCESS") - 1, MINACCESS}
    , {"PRODUCT-RELEASE", sizeof("PRODUCT-RELEASE") - 1, PRODREL}
    , {"WRITE-SYNTAX", sizeof("WRITE-SYNTAX") - 1, WRSYNTAX}
    , {"CREATION-REQUIRES", sizeof("CREATION-REQUIRES") - 1, CREATEREQ}
    , {"MANDATORY-GROUPS", sizeof("MANDATORY-GROUPS") - 1, MANDATORYGROUPS}
    , {"GROUP", sizeof("GROUP") - 1, GROUP}
    , {"CHOICE", sizeof("CHOICE") - 1, CHOICE}
    , {"IMPLICIT", sizeof("IMPLICIT") - 1, IMPLICIT}
    , {"ObjectSyntax", sizeof("ObjectSyntax") - 1, OBJSYNTAX}
    , {"SimpleSyntax", sizeof("SimpleSyntax") - 1, SIMPLESYNTAX}
    , {"ApplicationSyntax", sizeof("ApplicationSyntax") - 1, APPSYNTAX}
    , {"ObjectName", sizeof("ObjectName") - 1, OBJNAME}
    , {"NotificationName", sizeof("NotificationName") - 1, NOTIFNAME}
    , {"VARIABLES", sizeof("VARIABLES") - 1, VARIABLES}
    , {NULL}
};

static struct module_compatability *module_map_head;
static struct module_compatability module_map[] = {
    {"RFC1065-SMI", "RFC1155-SMI", NULL, 0}, {"RFC1066-MIB", "RFC1156-MIB", NULL, 0},  {"RFC1156-MIB", "RFC1158-MIB", NULL, 0},  {"RFC1158-MIB", "RFC1213-MIB", NULL, 0},  {"RFC1155-SMI", "SNMPv2-SMI", NULL, 0}, {"RFC1213-MIB", "SNMPv2-SMI", "mib-2", 0}, {"RFC1213-MIB", "SNMPv2-MIB", "sys", 3}, {"RFC1213-MIB", "IF-MIB", "if", 2}, {"RFC1213-MIB", "IP-MIB", "ip", 2}, {"RFC1213-MIB", "IP-MIB", "icmp", 4}, {"RFC1213-MIB", "TCP-MIB", "tcp", 3}, {"RFC1213-MIB", "UDP-MIB", "udp", 3}, {"RFC1213-MIB", "SNMPv2-SMI", "transmission", 0}, {"RFC1213-MIB", "SNMPv2-MIB", "snmp", 4}, {"RFC1231-MIB", "TOKENRING-MIB", NULL, 0}, {"RFC1271-MIB", "RMON-MIB", NULL, 0}, {"RFC1286-MIB", "SOURCE-ROUTING-MIB", "dot1dSr", 7}, {"RFC1286-MIB", "BRIDGE-MIB", NULL, 0}, {"RFC1315-MIB", "FRAME-RELAY-DTE-MIB", NULL, 0}, {"RFC1316-MIB", "CHARACTER-MIB", NULL, 0}, {"RFC1406-MIB", "DS1-MIB", NULL, 0}, {"RFC-1213", "RFC1213-MIB", NULL, 0}, };
































int gMibError = 0,gLoop = 0;
static char *gpMibErrorString;
char gMibNames[STRINGMAX];







static struct tok *buckets[HASHSIZE];

static struct node *nbuckets[NHASHSIZE];
static struct tree *tbuckets[NHASHSIZE];
static struct module *module_head = NULL;

static struct node *orphan_nodes = NULL;
NETSNMP_IMPORT struct tree *tree_head;
struct tree        *tree_head = NULL;


static struct module_import root_imports[NUMBER_OF_ROOT_NODES];

static int      current_module = 0;
static int      max_module = 0;
static int      first_err_module = 1;
static char    *last_err_module = NULL; 

static void     tree_from_node(struct tree *tp, struct node *np);
static void     do_subtree(struct tree *, struct node **);
static void     do_linkup(struct module *, struct node *);
static void     dump_module_list(void);
static int      get_token(FILE *, char *, int);
static int      parseQuoteString(FILE *, char *, int);
static int      tossObjectIdentifier(FILE *);
static int      name_hash(const char *);
static void     init_node_hash(struct node *);
static void     print_error(const char *, const char *, int);
static void     free_tree(struct tree *);
static void     free_partial_tree(struct tree *, int);
static void     free_node(struct node *);
static void     build_translation_table(void);
static void     init_tree_roots(void);
static void     merge_anon_children(struct tree *, struct tree *);
static void     unlink_tbucket(struct tree *);
static void     unlink_tree(struct tree *);
static int      getoid(FILE *, struct subid_s *, int);
static struct node *parse_objectid(FILE *, char *);
static int      get_tc(const char *, int, int *, struct enum_list **, struct range_list **, char **);
static int      get_tc_index(const char *, int);
static struct enum_list *parse_enumlist(FILE *, struct enum_list **);
static struct range_list *parse_ranges(FILE * fp, struct range_list **);
static struct node *parse_asntype(FILE *, char *, int *, char *);
static struct node *parse_objecttype(FILE *, char *);
static struct node *parse_objectgroup(FILE *, char *, int, struct objgroup **);
static struct node *parse_notificationDefinition(FILE *, char *);
static struct node *parse_trapDefinition(FILE *, char *);
static struct node *parse_compliance(FILE *, char *);
static struct node *parse_capabilities(FILE *, char *);
static struct node *parse_moduleIdentity(FILE *, char *);
static struct node *parse_macro(FILE *, char *);
static void     parse_imports(FILE *);
static struct node *parse(FILE *, struct node *);

static int     read_module_internal(const char *);
static int     read_module_replacements(const char *);
static int     read_import_replacements(const char *, struct module_import *);

static void     new_module(const char *, const char *);

static struct node *merge_parse_objectid(struct node *, FILE *, char *);
static struct index_list *getIndexes(FILE * fp, struct index_list **);
static struct varbind_list *getVarbinds(FILE * fp, struct varbind_list **);
static void     free_indexes(struct index_list **);
static void     free_varbinds(struct varbind_list **);
static void     free_ranges(struct range_list **);
static void     free_enums(struct enum_list **);
static struct range_list *copy_ranges(struct range_list *);
static struct enum_list *copy_enums(struct enum_list *);

static u_int    compute_match(const char *search_base, const char *key);

void snmp_mib_toggle_options_usage(const char *lead, FILE * outf)
{
    fprintf(outf, "%su:  %sallow the use of underlines in MIB symbols\n", lead, ((netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_MIB_PARSE_LABEL)) ? "dis" : ""));


    fprintf(outf, "%sc:  %sallow the use of \"--\" to terminate comments\n", lead, ((netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_MIB_COMMENT_TERM)) ? "" : "dis"));



    fprintf(outf, "%sd:  %ssave the DESCRIPTIONs of the MIB objects\n", lead, ((netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) ? "do not " : ""));



    fprintf(outf, "%se:  disable errors when MIB symbols conflict\n", lead);

    fprintf(outf, "%sw:  enable warnings when MIB symbols conflict\n", lead);

    fprintf(outf, "%sW:  enable detailed warnings when MIB symbols conflict\n", lead);

    fprintf(outf, "%sR:  replace MIB symbols from latest module\n", lead);
}

char           * snmp_mib_toggle_options(char *options)
{
    if (options) {
        while (*options) {
            switch (*options) {
            case 'u':
                netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_MIB_PARSE_LABEL, !netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_MIB_PARSE_LABEL));

                break;

            case 'c':
                netsnmp_ds_toggle_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_MIB_COMMENT_TERM);
                break;

            case 'e':
                netsnmp_ds_toggle_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_MIB_ERRORS);
                break;

            case 'w':
                netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_MIB_WARNINGS, 1);
                break;

            case 'W':
                netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_MIB_WARNINGS, 2);
                break;

            case 'd':
                netsnmp_ds_toggle_boolean(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_SAVE_MIB_DESCRS);
                break;

            case 'R':
                netsnmp_ds_toggle_boolean(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_MIB_REPLACE);
                break;

            default:
                
                return options;
            }
            options++;
        }
    }
    return NULL;
}

static int name_hash(const char *name)
{
    int             hash = 0;
    const char     *cp;

    if (!name)
        return 0;
    for (cp = name; *cp; cp++)
        hash += tolower((unsigned char)(*cp));
    return (hash);
}

void netsnmp_init_mib_internals(void)
{
    register struct tok *tp;
    register int    b, i;
    int             max_modc;

    if (tree_head)
        return;

    
    memset(buckets, 0, sizeof(buckets));
    for (tp = tokens; tp->name; tp++) {
        tp->hash = name_hash(tp->name);
        b = BUCKET(tp->hash);
        if (buckets[b])
            tp->next = buckets[b];      
        buckets[b] = tp;
    }

    

    max_modc = sizeof(module_map) / sizeof(module_map[0]) - 1;
    for (i = 0; i < max_modc; ++i)
        module_map[i].next = &(module_map[i + 1]);
    module_map[max_modc].next = NULL;
    module_map_head = module_map;

    memset(nbuckets, 0, sizeof(nbuckets));
    memset(tbuckets, 0, sizeof(tbuckets));
    memset(tclist, 0, MAXTC * sizeof(struct tc));
    build_translation_table();
    init_tree_roots();          
    
}


void init_mib_internals(void)
{
    netsnmp_init_mib_internals();
}


static void init_node_hash(struct node *nodes)
{
    struct node    *np, *nextp;
    int             hash;

    memset(nbuckets, 0, sizeof(nbuckets));
    for (np = nodes; np;) {
        nextp = np->next;
        hash = NBUCKET(name_hash(np->parent));
        np->next = nbuckets[hash];
        nbuckets[hash] = np;
        np = nextp;
    }
}

static int      erroneousMibs = 0;

netsnmp_feature_child_of(parse_get_error_count, netsnmp_unused)

int get_mib_parse_error_count(void)
{
    return erroneousMibs;
}



static void print_error(const char *str, const char *token, int type)
{
    erroneousMibs++;
    if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_MIB_ERRORS))
	return;
    DEBUGMSGTL(("parse-mibs", "\n"));
    if (type == ENDOFFILE)
        snmp_log(LOG_ERR, "%s (EOF): At line %d in %s\n", str, mibLine, File);
    else if (token && *token)
        snmp_log(LOG_ERR, "%s (%s): At line %d in %s\n", str, token, mibLine, File);
    else snmp_log(LOG_ERR, "%s: At line %d in %s\n", str, mibLine, File);
}

static void print_module_not_found(const char *cp)
{
    if (first_err_module) {
        snmp_log(LOG_ERR, "MIB search path: %s\n", netsnmp_get_mib_directory());
        first_err_module = 0;
    }
    if (!last_err_module || strcmp(cp, last_err_module))
        print_error("Cannot find module", cp, CONTINUE);
    if (last_err_module)
        free(last_err_module);
    last_err_module = strdup(cp);
}

static struct node * alloc_node(int modid)
{
    struct node    *np;
    np = (struct node *) calloc(1, sizeof(struct node));
    if (np) {
        np->tc_index = -1;
        np->modid = modid;
	np->filename = strdup(File);
	np->lineno = mibLine;
    }
    return np;
}

static void unlink_tbucket(struct tree *tp)
{
    int             hash = NBUCKET(name_hash(tp->label));
    struct tree    *otp = NULL, *ntp = tbuckets[hash];

    while (ntp && ntp != tp) {
        otp = ntp;
        ntp = ntp->next;
    }
    if (!ntp)
        snmp_log(LOG_EMERG, "Can't find %s in tbuckets\n", tp->label);
    else if (otp)
        otp->next = ntp->next;
    else tbuckets[hash] = tp->next;
}

static void unlink_tree(struct tree *tp)
{
    struct tree    *otp = NULL, *ntp = tp->parent;

    if (!ntp) {                 
        DEBUGMSGTL(("unlink_tree", "Tree node %s has no parent\n", tp->label));
    } else {
        ntp = ntp->child_list;

        while (ntp && ntp != tp) {
            otp = ntp;
            ntp = ntp->next_peer;
        }
        if (!ntp)
            snmp_log(LOG_EMERG, "Can't find %s in %s's children\n", tp->label, tp->parent->label);
        else if (otp)
            otp->next_peer = ntp->next_peer;
        else tp->parent->child_list = tp->next_peer;
    }

    if (tree_head == tp)
        tree_head = tp->next_peer;
}

static void free_partial_tree(struct tree *tp, int keep_label)
{
    if (!tp)
        return;

    
    free_enums(&tp->enums);
    free_ranges(&tp->ranges);
    free_indexes(&tp->indexes);
    free_varbinds(&tp->varbinds);
    if (!keep_label)
        SNMP_FREE(tp->label);
    SNMP_FREE(tp->hint);
    SNMP_FREE(tp->units);
    SNMP_FREE(tp->description);
    SNMP_FREE(tp->reference);
    SNMP_FREE(tp->augments);
    SNMP_FREE(tp->defaultValue);
}


static void free_tree(struct tree *Tree)
{
    if (!Tree)
        return;

    unlink_tbucket(Tree);
    free_partial_tree(Tree, FALSE);
    if (Tree->module_list != &Tree->modid)
        free(Tree->module_list);
    free(Tree);
}

static void free_node(struct node *np)
{
    if (!np)
        return;

    free_enums(&np->enums);
    free_ranges(&np->ranges);
    free_indexes(&np->indexes);
    free_varbinds(&np->varbinds);
    if (np->label)
        free(np->label);
    if (np->hint)
        free(np->hint);
    if (np->units)
        free(np->units);
    if (np->description)
        free(np->description);
    if (np->reference)
        free(np->reference);
    if (np->defaultValue)
        free(np->defaultValue);
    if (np->parent)
        free(np->parent);
    if (np->augments)
        free(np->augments);
    if (np->filename)
	free(np->filename);
    free((char *) np);
}

static void print_range_value(FILE * fp, int type, struct range_list * rp)
{
    switch (type) {
    case TYPE_INTEGER:
    case TYPE_INTEGER32:
        if (rp->low == rp->high)
            fprintf(fp, "%d", rp->low);
        else fprintf(fp, "%d..%d", rp->low, rp->high);
        break;
    case TYPE_UNSIGNED32:
    case TYPE_OCTETSTR:
    case TYPE_GAUGE:
    case TYPE_UINTEGER:
        if (rp->low == rp->high)
            fprintf(fp, "%u", (unsigned)rp->low);
        else fprintf(fp, "%u..%u", (unsigned)rp->low, (unsigned)rp->high);
        break;
    default:
        
        break;
    }
}


static void print_nodes(FILE * fp, struct node *root)
{
    struct enum_list *ep;
    struct index_list *ip;
    struct varbind_list *vp;
    struct node    *np;

    for (np = root; np; np = np->next) {
        fprintf(fp, "%s ::= { %s %ld } (%d)\n", np->label, np->parent, np->subid, np->type);
        if (np->tc_index >= 0)
            fprintf(fp, "  TC = %s\n", tclist[np->tc_index].descriptor);
        if (np->enums) {
            fprintf(fp, "  Enums: \n");
            for (ep = np->enums; ep; ep = ep->next) {
                fprintf(fp, "    %s(%d)\n", ep->label, ep->value);
            }
        }
        if (np->ranges) {
            struct range_list *rp;
            fprintf(fp, "  Ranges: ");
            for (rp = np->ranges; rp; rp = rp->next) {
                fprintf(fp, "\n    ");
                print_range_value(fp, np->type, rp);
            }
            fprintf(fp, "\n");
        }
        if (np->indexes) {
            fprintf(fp, "  Indexes: \n");
            for (ip = np->indexes; ip; ip = ip->next) {
                fprintf(fp, "    %s\n", ip->ilabel);
            }
        }
        if (np->augments)
            fprintf(fp, "  Augments: %s\n", np->augments);
        if (np->varbinds) {
            fprintf(fp, "  Varbinds: \n");
            for (vp = np->varbinds; vp; vp = vp->next) {
                fprintf(fp, "    %s\n", vp->vblabel);
            }
        }
        if (np->hint)
            fprintf(fp, "  Hint: %s\n", np->hint);
        if (np->units)
            fprintf(fp, "  Units: %s\n", np->units);
        if (np->defaultValue)
            fprintf(fp, "  DefaultValue: %s\n", np->defaultValue);
    }
}


void print_subtree(FILE * f, struct tree *tree, int count)
{
    struct tree    *tp;
    int             i;
    char            modbuf[256];

    for (i = 0; i < count; i++)
        fprintf(f, "  ");
    fprintf(f, "Children of %s(%ld):\n", tree->label, tree->subid);
    count++;
    for (tp = tree->child_list; tp; tp = tp->next_peer) {
        for (i = 0; i < count; i++)
            fprintf(f, "  ");
        fprintf(f, "%s:%s(%ld) type=%d", module_name(tp->module_list[0], modbuf), tp->label, tp->subid, tp->type);

        if (tp->tc_index != -1)
            fprintf(f, " tc=%d", tp->tc_index);
        if (tp->hint)
            fprintf(f, " hint=%s", tp->hint);
        if (tp->units)
            fprintf(f, " units=%s", tp->units);
        if (tp->number_modules > 1) {
            fprintf(f, " modules:");
            for (i = 1; i < tp->number_modules; i++)
                fprintf(f, " %s", module_name(tp->module_list[i], modbuf));
        }
        fprintf(f, "\n");
    }
    for (tp = tree->child_list; tp; tp = tp->next_peer) {
        if (tp->child_list)
            print_subtree(f, tp, count);
    }
}

void print_ascii_dump_tree(FILE * f, struct tree *tree, int count)
{
    struct tree    *tp;

    count++;
    for (tp = tree->child_list; tp; tp = tp->next_peer) {
        fprintf(f, "%s OBJECT IDENTIFIER ::= { %s %ld }\n", tp->label, tree->label, tp->subid);
    }
    for (tp = tree->child_list; tp; tp = tp->next_peer) {
        if (tp->child_list)
            print_ascii_dump_tree(f, tp, count);
    }
}

static int      translation_table[256];

static void build_translation_table(void)
{
    int             count;

    for (count = 0; count < 256; count++) {
        switch (count) {
        case OBJID:
            translation_table[count] = TYPE_OBJID;
            break;
        case OCTETSTR:
            translation_table[count] = TYPE_OCTETSTR;
            break;
        case INTEGER:
            translation_table[count] = TYPE_INTEGER;
            break;
        case NETADDR:
            translation_table[count] = TYPE_NETADDR;
            break;
        case IPADDR:
            translation_table[count] = TYPE_IPADDR;
            break;
        case COUNTER:
            translation_table[count] = TYPE_COUNTER;
            break;
        case GAUGE:
            translation_table[count] = TYPE_GAUGE;
            break;
        case TIMETICKS:
            translation_table[count] = TYPE_TIMETICKS;
            break;
        case KW_OPAQUE:
            translation_table[count] = TYPE_OPAQUE;
            break;
        case NUL:
            translation_table[count] = TYPE_NULL;
            break;
        case COUNTER64:
            translation_table[count] = TYPE_COUNTER64;
            break;
        case BITSTRING:
            translation_table[count] = TYPE_BITSTRING;
            break;
        case NSAPADDRESS:
            translation_table[count] = TYPE_NSAPADDRESS;
            break;
        case INTEGER32:
            translation_table[count] = TYPE_INTEGER32;
            break;
        case UINTEGER32:
            translation_table[count] = TYPE_UINTEGER;
            break;
        case UNSIGNED32:
            translation_table[count] = TYPE_UNSIGNED32;
            break;
        case TRAPTYPE:
            translation_table[count] = TYPE_TRAPTYPE;
            break;
        case NOTIFTYPE:
            translation_table[count] = TYPE_NOTIFTYPE;
            break;
        case NOTIFGROUP:
            translation_table[count] = TYPE_NOTIFGROUP;
            break;
        case OBJGROUP:
            translation_table[count] = TYPE_OBJGROUP;
            break;
        case MODULEIDENTITY:
            translation_table[count] = TYPE_MODID;
            break;
        case OBJIDENTITY:
            translation_table[count] = TYPE_OBJIDENTITY;
            break;
        case AGENTCAP:
            translation_table[count] = TYPE_AGENTCAP;
            break;
        case COMPLIANCE:
            translation_table[count] = TYPE_MODCOMP;
            break;
        default:
            translation_table[count] = TYPE_OTHER;
            break;
        }
    }
}

static void init_tree_roots(void)
{
    struct tree    *tp, *lasttp;
    int             base_modid;
    int             hash;

    base_modid = which_module("SNMPv2-SMI");
    if (base_modid == -1)
        base_modid = which_module("RFC1155-SMI");
    if (base_modid == -1)
        base_modid = which_module("RFC1213-MIB");

    
    tp = (struct tree *) calloc(1, sizeof(struct tree));
    if (tp == NULL)
        return;
    tp->label = strdup("joint-iso-ccitt");
    tp->modid = base_modid;
    tp->number_modules = 1;
    tp->module_list = &(tp->modid);
    tp->subid = 2;
    tp->tc_index = -1;
    set_function(tp);           
    hash = NBUCKET(name_hash(tp->label));
    tp->next = tbuckets[hash];
    tbuckets[hash] = tp;
    lasttp = tp;
    root_imports[0].label = strdup(tp->label);
    root_imports[0].modid = base_modid;

    
    tp = (struct tree *) calloc(1, sizeof(struct tree));
    if (tp == NULL)
        return;
    tp->next_peer = lasttp;
    tp->label = strdup("ccitt");
    tp->modid = base_modid;
    tp->number_modules = 1;
    tp->module_list = &(tp->modid);
    tp->subid = 0;
    tp->tc_index = -1;
    set_function(tp);           
    hash = NBUCKET(name_hash(tp->label));
    tp->next = tbuckets[hash];
    tbuckets[hash] = tp;
    lasttp = tp;
    root_imports[1].label = strdup(tp->label);
    root_imports[1].modid = base_modid;

    
    tp = (struct tree *) calloc(1, sizeof(struct tree));
    if (tp == NULL)
        return;
    tp->next_peer = lasttp;
    tp->label = strdup("iso");
    tp->modid = base_modid;
    tp->number_modules = 1;
    tp->module_list = &(tp->modid);
    tp->subid = 1;
    tp->tc_index = -1;
    set_function(tp);           
    hash = NBUCKET(name_hash(tp->label));
    tp->next = tbuckets[hash];
    tbuckets[hash] = tp;
    lasttp = tp;
    root_imports[2].label = strdup(tp->label);
    root_imports[2].modid = base_modid;

    tree_head = tp;
}








struct tree    * find_tree_node(const char *name, int modid)
{
    struct tree    *tp, *headtp;
    int             count, *int_p;

    if (!name || !*name)
        return (NULL);

    headtp = tbuckets[NBUCKET(name_hash(name))];
    for (tp = headtp; tp; tp = tp->next) {
        if (tp->label && !label_compare(tp->label, name)) {

            if (modid == -1)    
                return (tp);

            for (int_p = tp->module_list, count = 0;
                 count < tp->number_modules; ++count, ++int_p)
                if (*int_p == modid)
                    return (tp);
        }
    }

    return (NULL);
}




static          u_int compute_match(const char *search_base, const char *key)
{

    int             rc;
    regex_t         parsetree;
    regmatch_t      pmatch;
    rc = regcomp(&parsetree, key, REG_ICASE | REG_EXTENDED);
    if (rc == 0)
        rc = regexec(&parsetree, search_base, 1, &pmatch, 0);
    regfree(&parsetree);
    if (rc == 0) {
        
        return pmatch.rm_so;
    }

    
    char           *first = NULL, *result = NULL, *entry;
    const char     *position;
    char           *newkey = strdup(key);
    char           *st;


    entry = strtok_r(newkey, "*", &st);
    position = search_base;
    while (entry) {
        result = strcasestr(position, entry);

        if (result == NULL) {
            free(newkey);
            return MAX_BAD;
        }

        if (first == NULL)
            first = result;

        position = result + strlen(entry);
        entry = strtok_r(NULL, "*", &st);
    }
    free(newkey);
    if (result)
        return (first - search_base);


    
    return MAX_BAD;
}



struct tree    * find_best_tree_node(const char *pattrn, struct tree *tree_top, u_int * match)

{
    struct tree    *tp, *best_so_far = NULL, *retptr;
    u_int           old_match = MAX_BAD, new_match = MAX_BAD;

    if (!pattrn || !*pattrn)
        return (NULL);

    if (!tree_top)
        tree_top = get_tree_head();

    for (tp = tree_top; tp; tp = tp->next_peer) {
        if (!tp->reported && tp->label)
            new_match = compute_match(tp->label, pattrn);
        tp->reported = 1;

        if (new_match < old_match) {
            best_so_far = tp;
            old_match = new_match;
        }
        if (new_match == 0)
            break;              
        if (tp->child_list) {
            retptr = find_best_tree_node(pattrn, tp->child_list, &new_match);
            if (new_match < old_match) {
                best_so_far = retptr;
                old_match = new_match;
            }
            if (new_match == 0)
                break;          
        }
    }
    if (match)
        *match = old_match;
    return (best_so_far);
}


static void merge_anon_children(struct tree *tp1, struct tree *tp2)
                
{
    struct tree    *child1, *child2, *previous;

    for (child1 = tp1->child_list; child1;) {

        for (child2 = tp2->child_list, previous = NULL;
             child2; previous = child2, child2 = child2->next_peer) {

            if (child1->subid == child2->subid) {
                
                if (!strncmp(child1->label, ANON, ANON_LEN)) {
                    merge_anon_children(child1, child2);

                    child1->child_list = NULL;
                    previous = child1;  
                    child1 = child1->next_peer;
                    free_tree(previous);
                    goto next;
                }

                else if (!strncmp(child2->label, ANON, ANON_LEN)) {
                    merge_anon_children(child2, child1);

                    if (previous)
                        previous->next_peer = child2->next_peer;
                    else tp2->child_list = child2->next_peer;
                    free_tree(child2);

                    previous = child1;  
                    child1 = child1->next_peer;
                    previous->next_peer = tp2->child_list;
                    tp2->child_list = previous;
                    for (previous = tp2->child_list;
                         previous; previous = previous->next_peer)
                        previous->parent = tp2;
                    goto next;
                } else if (!label_compare(child1->label, child2->label)) {
                    if (netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_MIB_WARNINGS)) {
                        snmp_log(LOG_WARNING, "Warning: %s.%ld is both %s and %s (%s)\n", tp2->label, child1->subid, child1->label, child2->label, File);


		    }
                    continue;
                } else {
                    

                    if (child2->child_list) {
                        for (previous = child2->child_list; previous->next_peer; previous = previous->next_peer);       
                        previous->next_peer = child1->child_list;
                    } else child2->child_list = child1->child_list;
                    for (previous = child1->child_list;
                         previous; previous = previous->next_peer)
                        previous->parent = child2;
                    child1->child_list = NULL;

                    previous = child1;  
                    child1 = child1->next_peer;
                    free_tree(previous);
                    goto next;
                }
            }
        }
        
        if (child1) {
            previous = child1;
            child1 = child1->next_peer;
            previous->parent = tp2;
            previous->next_peer = tp2->child_list;
            tp2->child_list = previous;
        }
      next:;
    }
}



static void do_subtree(struct tree *root, struct node **nodes)
{
    struct tree    *tp, *anon_tp = NULL;
    struct tree    *xroot = root;
    struct node    *np, **headp;
    struct node    *oldnp = NULL, *child_list = NULL, *childp = NULL;
    int             hash;
    int            *int_p;

    while (xroot->next_peer && xroot->next_peer->subid == root->subid) {

        printf("xroot: %s.%s => %s\n", xroot->parent->label, xroot->label, xroot->next_peer->label);

        xroot = xroot->next_peer;
    }

    tp = root;
    headp = &nbuckets[NBUCKET(name_hash(tp->label))];
    
    for (np = *headp; np; np = np->next) {
        if (!label_compare(tp->label, np->parent)) {
            
            if (oldnp == NULL) {
                *headp = np->next;      
            } else {
                oldnp->next = np->next; 
            }
            if (child_list)
                childp->next = np;
            else child_list = np;
            childp = np;
        } else {
            oldnp = np;
        }

    }
    if (childp)
        childp->next = NULL;
    
    for (np = child_list; np; np = np->next) {
        struct tree    *otp = NULL;
        struct tree    *xxroot = xroot;
        anon_tp = NULL;
        tp = xroot->child_list;

        if (np->subid == -1) {
            
            np->subid = xroot->subid;
            tp = xroot;
            xxroot = xroot->parent;
        }

        while (tp) {
            if (tp->subid == np->subid)
                break;
            else {
                otp = tp;
                tp = tp->next_peer;
            }
        }
        if (tp) {
            if (!label_compare(tp->label, np->label)) {
                
                int_p = malloc((tp->number_modules + 1) * sizeof(int));
                if (int_p == NULL)
                    return;
                memcpy(int_p, tp->module_list, tp->number_modules * sizeof(int));
                int_p[tp->number_modules] = np->modid;
                if (tp->module_list != &tp->modid)
                    free(tp->module_list);
                ++tp->number_modules;
                tp->module_list = int_p;

                if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_MIB_REPLACE)) {
                    
                    tree_from_node(tp, np);
                }
                
                do_subtree(tp, nodes);
                continue;
            }
            if (!strncmp(np->label, ANON, ANON_LEN) || !strncmp(tp->label, ANON, ANON_LEN)) {
                anon_tp = tp;   
            } else if (netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_MIB_WARNINGS)) {
                snmp_log(LOG_WARNING, "Warning: %s.%ld is both %s and %s (%s)\n", root->label, np->subid, tp->label, np->label, File);


	    }
        }

        tp = (struct tree *) calloc(1, sizeof(struct tree));
        if (tp == NULL)
            return;
        tp->parent = xxroot;
        tp->modid = np->modid;
        tp->number_modules = 1;
        tp->module_list = &(tp->modid);
        tree_from_node(tp, np);
        tp->next_peer = otp ? otp->next_peer : xxroot->child_list;
        if (otp)
            otp->next_peer = tp;
        else xxroot->child_list = tp;
        hash = NBUCKET(name_hash(tp->label));
        tp->next = tbuckets[hash];
        tbuckets[hash] = tp;
        do_subtree(tp, nodes);

        if (anon_tp) {
            if (!strncmp(tp->label, ANON, ANON_LEN)) {
                
                merge_anon_children(tp, anon_tp);

                
                unlink_tree(tp);
                free_tree(tp);
            } else if (!strncmp(anon_tp->label, ANON, ANON_LEN)) {
                struct tree    *ntp;
                
                merge_anon_children(anon_tp, tp);

                
                unlink_tbucket(anon_tp);

                
                free_partial_tree(anon_tp, FALSE);

                
                anon_tp->label = tp->label;
                anon_tp->child_list = tp->child_list;
                anon_tp->modid = tp->modid;
                anon_tp->tc_index = tp->tc_index;
                anon_tp->type = tp->type;
                anon_tp->enums = tp->enums;
                anon_tp->indexes = tp->indexes;
                anon_tp->augments = tp->augments;
                anon_tp->varbinds = tp->varbinds;
                anon_tp->ranges = tp->ranges;
                anon_tp->hint = tp->hint;
                anon_tp->units = tp->units;
                anon_tp->description = tp->description;
                anon_tp->reference = tp->reference;
                anon_tp->defaultValue = tp->defaultValue;
                anon_tp->parent = tp->parent;

                set_function(anon_tp);

                
                ntp = anon_tp->child_list;
                while (ntp) {
                    ntp->parent = anon_tp;
                    ntp = ntp->next_peer;
                }

                
                hash = NBUCKET(name_hash(anon_tp->label));
                anon_tp->next = tbuckets[hash];
                tbuckets[hash] = anon_tp;

                
                unlink_tbucket(tp);
                unlink_tree(tp);
                free(tp);
            } else {
                
                if (netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_MIB_WARNINGS)) {
                    snmp_log(LOG_WARNING, "Warning: expected anonymous node (either %s or %s) in %s\n", tp->label, anon_tp->label, File);

		}
            }
            anon_tp = NULL;
        }
    }
    
    oldnp = NULL;
    for (np = child_list; np; np = np->next) {
        if (oldnp)
            free_node(oldnp);
        oldnp = np;
    }
    if (oldnp)
        free_node(oldnp);
}

static void do_linkup(struct module *mp, struct node *np)
{
    struct module_import *mip;
    struct node    *onp, *oldp, *newp;
    struct tree    *tp;
    int             i, more;
    
    if (snmp_get_do_debugging() > 1)
        dump_module_list();
    DEBUGMSGTL(("parse-mibs", "Processing IMPORTS for module %d %s\n", mp->modid, mp->name));
    if (mp->no_imports == 0) {
        mp->no_imports = NUMBER_OF_ROOT_NODES;
        mp->imports = root_imports;
    }

    
    init_node_hash(np);
    for (i = 0, mip = mp->imports; i < mp->no_imports; ++i, ++mip) {
        char            modbuf[256];
        DEBUGMSGTL(("parse-mibs", "  Processing import: %s\n", mip->label));
        if (get_tc_index(mip->label, mip->modid) != -1)
            continue;
        tp = find_tree_node(mip->label, mip->modid);
        if (!tp) {
	    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_MIB_ERRORS))
                snmp_log(LOG_WARNING, "Did not find '%s' in module %s (%s)\n", mip->label, module_name(mip->modid, modbuf), File);


            continue;
        }
        do_subtree(tp, &np);
    }

    

    if (!np)
        return;
    for (tp = tree_head; tp; tp = tp->next_peer)
        do_subtree(tp, &np);
    if (!np)
        return;

    
    oldp = orphan_nodes;
    do {
        for (i = 0; i < NHASHSIZE; i++)
            for (onp = nbuckets[i]; onp; onp = onp->next) {
                struct node    *op = NULL;
                int             hash = NBUCKET(name_hash(onp->label));
                np = nbuckets[hash];
                while (np) {
                    if (label_compare(onp->label, np->parent)) {
                        op = np;
                        np = np->next;
                    } else {
                        if (op)
                            op->next = np->next;
                        else nbuckets[hash] = np->next;
			DEBUGMSGTL(("parse-mibs", "Moving %s to orphanage", np->label));
                        np->next = orphan_nodes;
                        orphan_nodes = np;
                        op = NULL;
                        np = nbuckets[hash];
                    }
                }
            }
        newp = orphan_nodes;
        more = 0;
        for (onp = orphan_nodes; onp != oldp; onp = onp->next) {
            struct node    *op = NULL;
            int             hash = NBUCKET(name_hash(onp->label));
            np = nbuckets[hash];
            while (np) {
                if (label_compare(onp->label, np->parent)) {
                    op = np;
                    np = np->next;
                } else {
                    if (op)
                        op->next = np->next;
                    else nbuckets[hash] = np->next;
                    np->next = orphan_nodes;
                    orphan_nodes = np;
                    op = NULL;
                    np = nbuckets[hash];
                    more = 1;
                }
            }
        }
        oldp = newp;
    } while (more);

    
    for (np = orphan_nodes; np && np->next; np = np->next);     
    for (i = 0; i < NHASHSIZE; i++)
        if (nbuckets[i]) {
            if (orphan_nodes)
                onp = np->next = nbuckets[i];
            else onp = orphan_nodes = nbuckets[i];
            nbuckets[i] = NULL;
            while (onp) {
                snmp_log(LOG_WARNING, "Unlinked OID in %s: %s ::= { %s %ld }\n", (mp->name ? mp->name : "<no module>"), (onp->label ? onp->label : "<no label>"), (onp->parent ? onp->parent : "<no parent>"), onp->subid);




		 snmp_log(LOG_WARNING, "Undefined identifier: %s near line %d of %s\n", (onp->parent ? onp->parent : "<no parent>"), onp->lineno, onp->filename);


                np = onp;
                onp = onp->next;
            }
        }
    return;
}



static int getoid(FILE * fp, struct subid_s *id, int length)

{                               
    register int    count;
    int             type;
    char            token[MAXTOKEN];

    if ((type = get_token(fp, token, MAXTOKEN)) != LEFTBRACKET) {
        print_error("Expected \"{\"", token, type);
        return 0;
    }
    type = get_token(fp, token, MAXTOKEN);
    for (count = 0; count < length; count++, id++) {
        id->label = NULL;
        id->modid = current_module;
        id->subid = -1;
        if (type == RIGHTBRACKET)
            return count;
        if (type == LABEL) {
            
            id->label = strdup(token);
            type = get_token(fp, token, MAXTOKEN);
            if (type == LEFTPAREN) {
                type = get_token(fp, token, MAXTOKEN);
                if (type == NUMBER) {
                    id->subid = strtoul(token, NULL, 10);
                    if ((type = get_token(fp, token, MAXTOKEN)) != RIGHTPAREN) {
                        print_error("Expected a closing parenthesis", token, type);
                        return 0;
                    }
                } else {
                    print_error("Expected a number", token, type);
                    return 0;
                }
            } else {
                continue;
            }
        } else if (type == NUMBER) {
            
            id->subid = strtoul(token, NULL, 10);
        } else {
            print_error("Expected label or number", token, type);
            return 0;
        }
        type = get_token(fp, token, MAXTOKEN);
    }
    print_error("Too long OID", token, type);
    return 0;
}


static struct node * parse_objectid(FILE * fp, char *name)
{
    register int    count;
    register struct subid_s *op, *nop;
    int             length;
    struct subid_s  loid[32];
    struct node    *np, *root = NULL, *oldnp = NULL;
    struct tree    *tp;

    if ((length = getoid(fp, loid, 32)) == 0) {
        print_error("Bad object identifier", NULL, CONTINUE);
        return NULL;
    }

    
    op = loid;
    if (!op->label) {
        if (length == 1) {
            print_error("Attempt to define a root oid", name, OBJECT);
            return NULL;
        }
        for (tp = tree_head; tp; tp = tp->next_peer)
            if ((int) tp->subid == op->subid) {
                op->label = strdup(tp->label);
                break;
            }
    }

    
    if (length == 1) {
        op = loid;
        np = alloc_node(op->modid);
        if (np == NULL)
            return (NULL);
        np->subid = op->subid;
        np->label = strdup(name);
        np->parent = op->label;
        return np;
    }

    
    for (count = 0, op = loid, nop = loid + 1; count < (length - 1);
         count++, op++, nop++) {
        
        
        if (op->label && (nop->label || (nop->subid != -1))) {
            np = alloc_node(nop->modid);
            if (np == NULL)
                goto err;
            if (root == NULL)
                root = np;

            np->parent = strdup(op->label);
            if (count == (length - 2)) {
                
                np->label = strdup(name);
                if (np->label == NULL)
                    goto err;
            } else {
                if (!nop->label) {
                    nop->label = (char *) malloc(20 + ANON_LEN);
                    if (nop->label == NULL)
                        goto err;
                    sprintf(nop->label, "%s%d", ANON, anonymous++);
                }
                np->label = strdup(nop->label);
            }
            if (nop->subid != -1)
                np->subid = nop->subid;
            else print_error("Warning: This entry is pretty silly", np->label, CONTINUE);


            
            if (oldnp)
                oldnp->next = np;
            oldnp = np;
        }                       
    }

out:
    
    for (count = 0, op = loid; count < length; count++, op++) {
        if (op->label)
            free(op->label);
    }

    return root;

err:
    for (; root; root = np) {
        np = root->next;
        free_node(root);
    }
    goto out;
}

static int get_tc(const char *descriptor, int modid, int *tc_index, struct enum_list **ep, struct range_list **rp, char **hint)



{
    int             i;
    struct tc      *tcp;

    i = get_tc_index(descriptor, modid);
    if (tc_index)
        *tc_index = i;
    if (i != -1) {
        tcp = &tclist[i];
        if (ep) {
            free_enums(ep);
            *ep = copy_enums(tcp->enums);
        }
        if (rp) {
            free_ranges(rp);
            *rp = copy_ranges(tcp->ranges);
        }
        if (hint) {
            if (*hint)
                free(*hint);
            *hint = (tcp->hint ? strdup(tcp->hint) : NULL);
        }
        return tcp->type;
    }
    return LABEL;
}


static int get_tc_index(const char *descriptor, int modid)
{
    int             i;
    struct tc      *tcp;
    struct module  *mp;
    struct module_import *mip;

    

    for (mp = module_head; mp; mp = mp->next)
        if (mp->modid == modid)
            break;
    if (mp)
        for (i = 0, mip = mp->imports; i < mp->no_imports; ++i, ++mip) {
            if (!label_compare(mip->label, descriptor)) {
                
                modid = mip->modid;
                break;
            }
        }


    for (i = 0, tcp = tclist; i < MAXTC; i++, tcp++) {
        if (tcp->type == 0)
            break;
        if (!label_compare(descriptor, tcp->descriptor) && ((modid == tcp->modid) || (modid == -1))) {
            return i;
        }
    }
    return -1;
}


const char     * get_tc_descriptor(int tc_index)
{
    if (tc_index < 0 || tc_index >= MAXTC)
        return NULL;
    return (tclist[tc_index].descriptor);
}



const char     * get_tc_description(int tc_index)
{
    if (tc_index < 0 || tc_index >= MAXTC)
        return NULL;
    return (tclist[tc_index].description);
}





static struct enum_list * parse_enumlist(FILE * fp, struct enum_list **retp)
{
    register int    type;
    char            token[MAXTOKEN];
    struct enum_list *ep = NULL, **epp = &ep;

    free_enums(retp);

    while ((type = get_token(fp, token, MAXTOKEN)) != ENDOFFILE) {
        if (type == RIGHTBRACKET)
            break;
        
        
        if (type == LABEL || type == DEPRECATED) {
            
            *epp = (struct enum_list *) calloc(1, sizeof(struct enum_list));
            if (*epp == NULL)
                return (NULL);
            
            (*epp)->label = strdup(token);
            type = get_token(fp, token, MAXTOKEN);
            if (type != LEFTPAREN) {
                print_error("Expected \"(\"", token, type);
                return NULL;
            }
            type = get_token(fp, token, MAXTOKEN);
            if (type != NUMBER) {
                print_error("Expected integer", token, type);
                return NULL;
            }
            (*epp)->value = strtol(token, NULL, 10);
            type = get_token(fp, token, MAXTOKEN);
            if (type != RIGHTPAREN) {
                print_error("Expected \")\"", token, type);
                return NULL;
            }
            epp = &(*epp)->next;
        }
    }
    if (type == ENDOFFILE) {
        print_error("Expected \"}\"", token, type);
        return NULL;
    }
    *retp = ep;
    return ep;
}

static struct range_list * parse_ranges(FILE * fp, struct range_list **retp)
{
    int             low, high;
    char            nexttoken[MAXTOKEN];
    int             nexttype;
    struct range_list *rp = NULL, **rpp = &rp;
    int             size = 0, taken = 1;

    free_ranges(retp);

    nexttype = get_token(fp, nexttoken, MAXTOKEN);
    if (nexttype == SIZE) {
        size = 1;
        taken = 0;
        nexttype = get_token(fp, nexttoken, MAXTOKEN);
        if (nexttype != LEFTPAREN)
            print_error("Expected \"(\" after SIZE", nexttoken, nexttype);
    }

    do {
        if (!taken)
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
        else taken = 0;
        high = low = strtoul(nexttoken, NULL, 10);
        nexttype = get_token(fp, nexttoken, MAXTOKEN);
        if (nexttype == RANGE) {
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
            errno = 0;
            high = strtoul(nexttoken, NULL, 10);
            if ( errno == ERANGE ) {
                if (netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_MIB_WARNINGS))
                    snmp_log(LOG_WARNING, "Warning: Upper bound not handled correctly (%s != %d): At line %d in %s\n", nexttoken, high, mibLine, File);

            }
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
        }
        *rpp = (struct range_list *) calloc(1, sizeof(struct range_list));
        if (*rpp == NULL)
            break;
        (*rpp)->low = low;
        (*rpp)->high = high;
        rpp = &(*rpp)->next;

    } while (nexttype == BAR);
    if (size) {
        if (nexttype != RIGHTPAREN)
            print_error("Expected \")\" after SIZE", nexttoken, nexttype);
        nexttype = get_token(fp, nexttoken, nexttype);
    }
    if (nexttype != RIGHTPAREN)
        print_error("Expected \")\"", nexttoken, nexttype);

    *retp = rp;
    return rp;
}


static struct node * parse_asntype(FILE * fp, char *name, int *ntype, char *ntoken)
{
    int             type, i;
    char            token[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    char           *hint = NULL;
    char           *descr = NULL;
    struct tc      *tcp;
    int             level;

    type = get_token(fp, token, MAXTOKEN);
    if (type == SEQUENCE || type == CHOICE) {
        level = 0;
        while ((type = get_token(fp, token, MAXTOKEN)) != ENDOFFILE) {
            if (type == LEFTBRACKET) {
                level++;
            } else if (type == RIGHTBRACKET && --level == 0) {
                *ntype = get_token(fp, ntoken, MAXTOKEN);
                return NULL;
            }
        }
        print_error("Expected \"}\"", token, type);
        return NULL;
    } else if (type == LEFTBRACKET) {
        struct node    *np;
        int             ch_next = '{';
        ungetc(ch_next, fp);
        np = parse_objectid(fp, name);
        if (np != NULL) {
            *ntype = get_token(fp, ntoken, MAXTOKEN);
            return np;
        }
        return NULL;
    } else if (type == LEFTSQBRACK) {
        int             size = 0;
        do {
            type = get_token(fp, token, MAXTOKEN);
        } while (type != ENDOFFILE && type != RIGHTSQBRACK);
        if (type != RIGHTSQBRACK) {
            print_error("Expected \"]\"", token, type);
            return NULL;
        }
        type = get_token(fp, token, MAXTOKEN);
        if (type == IMPLICIT)
            type = get_token(fp, token, MAXTOKEN);
        *ntype = get_token(fp, ntoken, MAXTOKEN);
        if (*ntype == LEFTPAREN) {
            switch (type) {
            case OCTETSTR:
                *ntype = get_token(fp, ntoken, MAXTOKEN);
                if (*ntype != SIZE) {
                    print_error("Expected SIZE", ntoken, *ntype);
                    return NULL;
                }
                size = 1;
                *ntype = get_token(fp, ntoken, MAXTOKEN);
                if (*ntype != LEFTPAREN) {
                    print_error("Expected \"(\" after SIZE", ntoken, *ntype);
                    return NULL;
                }
                
            case INTEGER:
                *ntype = get_token(fp, ntoken, MAXTOKEN);
                do {
                    if (*ntype != NUMBER)
                        print_error("Expected NUMBER", ntoken, *ntype);
                    *ntype = get_token(fp, ntoken, MAXTOKEN);
                    if (*ntype == RANGE) {
                        *ntype = get_token(fp, ntoken, MAXTOKEN);
                        if (*ntype != NUMBER)
                            print_error("Expected NUMBER", ntoken, *ntype);
                        *ntype = get_token(fp, ntoken, MAXTOKEN);
                    }
                } while (*ntype == BAR);
                if (*ntype != RIGHTPAREN) {
                    print_error("Expected \")\"", ntoken, *ntype);
                    return NULL;
                }
                *ntype = get_token(fp, ntoken, MAXTOKEN);
                if (size) {
                    if (*ntype != RIGHTPAREN) {
                        print_error("Expected \")\" to terminate SIZE", ntoken, *ntype);
                        return NULL;
                    }
                    *ntype = get_token(fp, ntoken, MAXTOKEN);
                }
            }
        }
        return NULL;
    } else {
        if (type == CONVENTION) {
            while (type != SYNTAX && type != ENDOFFILE) {
                if (type == DISPLAYHINT) {
                    type = get_token(fp, token, MAXTOKEN);
                    if (type != QUOTESTRING) {
                        print_error("DISPLAY-HINT must be string", token, type);
                    } else {
                        free(hint);
                        hint = strdup(token);
                    }
                } else if (type == DESCRIPTION && netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) {

                    type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
                    if (type != QUOTESTRING) {
                        print_error("DESCRIPTION must be string", token, type);
                    } else {
                        free(descr);
                        descr = strdup(quoted_string_buffer);
                    }
                } else type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);

            }
            type = get_token(fp, token, MAXTOKEN);
            if (type == OBJECT) {
                type = get_token(fp, token, MAXTOKEN);
                if (type != IDENTIFIER) {
                    print_error("Expected IDENTIFIER", token, type);
                    goto err;
                }
                type = OBJID;
            }
        } else if (type == OBJECT) {
            type = get_token(fp, token, MAXTOKEN);
            if (type != IDENTIFIER) {
                print_error("Expected IDENTIFIER", token, type);
                goto err;
            }
            type = OBJID;
        }

        if (type == LABEL) {
            type = get_tc(token, current_module, NULL, NULL, NULL, NULL);
        }

        
        for (i = 0; i < MAXTC; i++) {
            if (tclist[i].type == 0)
                break;
        }

        if (i == MAXTC) {
            print_error("Too many textual conventions", token, type);
            goto err;
        }
        if (!(type & SYNTAX_MASK)) {
            print_error("Textual convention doesn't map to real type", token, type);
            goto err;
        }
        tcp = &tclist[i];
        tcp->modid = current_module;
        tcp->descriptor = strdup(name);
        tcp->hint = hint;
        tcp->description = descr;
        tcp->type = type;
        *ntype = get_token(fp, ntoken, MAXTOKEN);
        if (*ntype == LEFTPAREN) {
            tcp->ranges = parse_ranges(fp, &tcp->ranges);
            *ntype = get_token(fp, ntoken, MAXTOKEN);
        } else if (*ntype == LEFTBRACKET) {
            
            tcp->enums = parse_enumlist(fp, &tcp->enums);
            *ntype = get_token(fp, ntoken, MAXTOKEN);
        }
        return NULL;
    }

err:
    SNMP_FREE(descr);
    SNMP_FREE(hint);
    return NULL;
}



static struct node * parse_objecttype(FILE * fp, char *name)
{
    register int    type;
    char            token[MAXTOKEN];
    char            nexttoken[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    int             nexttype, tctype;
    register struct node *np;

    type = get_token(fp, token, MAXTOKEN);
    if (type != SYNTAX) {
        print_error("Bad format for OBJECT-TYPE", token, type);
        return NULL;
    }
    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, MAXTOKEN);
    if (type == OBJECT) {
        type = get_token(fp, token, MAXTOKEN);
        if (type != IDENTIFIER) {
            print_error("Expected IDENTIFIER", token, type);
            free_node(np);
            return NULL;
        }
        type = OBJID;
    }
    if (type == LABEL) {
        int             tmp_index;
        tctype = get_tc(token, current_module, &tmp_index, &np->enums, &np->ranges, &np->hint);
        if (tctype == LABEL && netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_MIB_WARNINGS) > 1) {

            print_error("Warning: No known translation for type", token, type);
        }
        type = tctype;
        np->tc_index = tmp_index;       
    }
    np->type = type;
    nexttype = get_token(fp, nexttoken, MAXTOKEN);
    switch (type) {
    case SEQUENCE:
        if (nexttype == OF) {
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
            nexttype = get_token(fp, nexttoken, MAXTOKEN);

        }
        break;
    case INTEGER:
    case INTEGER32:
    case UINTEGER32:
    case UNSIGNED32:
    case COUNTER:
    case GAUGE:
    case BITSTRING:
    case LABEL:
        if (nexttype == LEFTBRACKET) {
            
            np->enums = parse_enumlist(fp, &np->enums);
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
        } else if (nexttype == LEFTPAREN) {
            
            np->ranges = parse_ranges(fp, &np->ranges);
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
        }
        break;
    case OCTETSTR:
    case KW_OPAQUE:
        
        if (nexttype == LEFTPAREN) {
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
            if (nexttype == SIZE) {
                nexttype = get_token(fp, nexttoken, MAXTOKEN);
                if (nexttype == LEFTPAREN) {
                    np->ranges = parse_ranges(fp, &np->ranges);
                    nexttype = get_token(fp, nexttoken, MAXTOKEN);      
                    if (nexttype == RIGHTPAREN) {
                        nexttype = get_token(fp, nexttoken, MAXTOKEN);
                        break;
                    }
                }
            }
            print_error("Bad SIZE syntax", token, type);
            free_node(np);
            return NULL;
        }
        break;
    case OBJID:
    case NETADDR:
    case IPADDR:
    case TIMETICKS:
    case NUL:
    case NSAPADDRESS:
    case COUNTER64:
        break;
    default:
        print_error("Bad syntax", token, type);
        free_node(np);
        return NULL;
    }
    if (nexttype == UNITS) {
        type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
        if (type != QUOTESTRING) {
            print_error("Bad UNITS", quoted_string_buffer, type);
            free_node(np);
            return NULL;
        }
        np->units = strdup(quoted_string_buffer);
        nexttype = get_token(fp, nexttoken, MAXTOKEN);
    }
    if (nexttype != ACCESS) {
        print_error("Should be ACCESS", nexttoken, nexttype);
        free_node(np);
        return NULL;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != READONLY && type != READWRITE && type != WRITEONLY && type != NOACCESS && type != READCREATE && type != ACCNOTIFY) {
        print_error("Bad ACCESS type", token, type);
        free_node(np);
        return NULL;
    }
    np->access = type;
    type = get_token(fp, token, MAXTOKEN);
    if (type != STATUS) {
        print_error("Should be STATUS", token, type);
        free_node(np);
        return NULL;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != MANDATORY && type != CURRENT && type != KW_OPTIONAL && type != OBSOLETE && type != DEPRECATED) {
        print_error("Bad STATUS", token, type);
        free_node(np);
        return NULL;
    }
    np->status = type;
    
    type = get_token(fp, token, MAXTOKEN);
    while (type != EQUALS && type != ENDOFFILE) {
        switch (type) {
        case DESCRIPTION:
            type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);

            if (type != QUOTESTRING) {
                print_error("Bad DESCRIPTION", quoted_string_buffer, type);
                free_node(np);
                return NULL;
            }
            if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) {
                np->description = strdup(quoted_string_buffer);
            }
            break;

        case REFERENCE:
            type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
            if (type != QUOTESTRING) {
                print_error("Bad REFERENCE", quoted_string_buffer, type);
                free_node(np);
                return NULL;
            }
            np->reference = strdup(quoted_string_buffer);
            break;
        case INDEX:
            if (np->augments) {
                print_error("Cannot have both INDEX and AUGMENTS", token, type);
                free_node(np);
                return NULL;
            }
            np->indexes = getIndexes(fp, &np->indexes);
            if (np->indexes == NULL) {
                print_error("Bad INDEX list", token, type);
                free_node(np);
                return NULL;
            }
            break;
        case AUGMENTS:
            if (np->indexes) {
                print_error("Cannot have both INDEX and AUGMENTS", token, type);
                free_node(np);
                return NULL;
            }
            np->indexes = getIndexes(fp, &np->indexes);
            if (np->indexes == NULL) {
                print_error("Bad AUGMENTS list", token, type);
                free_node(np);
                return NULL;
            }
            np->augments = strdup(np->indexes->ilabel);
            free_indexes(&np->indexes);
            break;
        case DEFVAL:
            
            type = get_token(fp, quoted_string_buffer, MAXTOKEN);
            if (type != LEFTBRACKET) {
                print_error("Bad DEFAULTVALUE", quoted_string_buffer, type);
                free_node(np);
                return NULL;
            }

            {
                int             level = 1;
                char            defbuf[512];

                defbuf[0] = 0;
                while (1) {
                    type = get_token(fp, quoted_string_buffer, MAXTOKEN);
                    if ((type == RIGHTBRACKET && --level == 0)
                        || type == ENDOFFILE)
                        break;
                    else if (type == LEFTBRACKET)
                        level++;
                    if (type == QUOTESTRING)
                        strlcat(defbuf, "\\\"", sizeof(defbuf));
                    strlcat(defbuf, quoted_string_buffer, sizeof(defbuf));
                    if (type == QUOTESTRING)
                        strlcat(defbuf, "\\\"", sizeof(defbuf));
                    strlcat(defbuf, " ", sizeof(defbuf));
                }

                if (type != RIGHTBRACKET) {
                    print_error("Bad DEFAULTVALUE", quoted_string_buffer, type);
                    free_node(np);
                    return NULL;
                }

                defbuf[strlen(defbuf) - 1] = 0;
                np->defaultValue = strdup(defbuf);
            }

            break;

        case NUM_ENTRIES:
            if (tossObjectIdentifier(fp) != OBJID) {
                print_error("Bad Object Identifier", token, type);
                free_node(np);
                return NULL;
            }
            break;

        default:
            print_error("Bad format of optional clauses", token, type);
            free_node(np);
            return NULL;

        }
        type = get_token(fp, token, MAXTOKEN);
    }
    if (type != EQUALS) {
        print_error("Bad format", token, type);
        free_node(np);
        return NULL;
    }
    return merge_parse_objectid(np, fp, name);
}


static struct node * parse_objectgroup(FILE * fp, char *name, int what, struct objgroup **ol)
{
    int             type;
    char            token[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    struct node    *np;

    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, MAXTOKEN);
    if (type == what) {
        type = get_token(fp, token, MAXTOKEN);
        if (type != LEFTBRACKET) {
            print_error("Expected \"{\"", token, type);
            goto skip;
        }
        do {
            struct objgroup *o;
            type = get_token(fp, token, MAXTOKEN);
            if (type != LABEL) {
                print_error("Bad identifier", token, type);
                goto skip;
            }
            o = (struct objgroup *) malloc(sizeof(struct objgroup));
            if (!o) {
                print_error("Resource failure", token, type);
                goto skip;
            }
            o->line = mibLine;
            o->name = strdup(token);
            o->next = *ol;
            *ol = o;
            type = get_token(fp, token, MAXTOKEN);
        } while (type == COMMA);
        if (type != RIGHTBRACKET) {
            print_error("Expected \"}\" after list", token, type);
            goto skip;
        }
        type = get_token(fp, token, type);
    }
    if (type != STATUS) {
        print_error("Expected STATUS", token, type);
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != CURRENT && type != DEPRECATED && type != OBSOLETE) {
        print_error("Bad STATUS value", token, type);
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != DESCRIPTION) {
        print_error("Expected DESCRIPTION", token, type);
        goto skip;
    }
    type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
    if (type != QUOTESTRING) {
        print_error("Bad DESCRIPTION", quoted_string_buffer, type);
        free_node(np);
        return NULL;
    }
    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) {
        np->description = strdup(quoted_string_buffer);
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type == REFERENCE) {
        type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
        if (type != QUOTESTRING) {
            print_error("Bad REFERENCE", quoted_string_buffer, type);
            free_node(np);
            return NULL;
        }
        np->reference = strdup(quoted_string_buffer);
        type = get_token(fp, token, MAXTOKEN);
    }
    if (type != EQUALS)
        print_error("Expected \"::=\"", token, type);
  skip:
    while (type != EQUALS && type != ENDOFFILE)
        type = get_token(fp, token, MAXTOKEN);

    return merge_parse_objectid(np, fp, name);
}


static struct node * parse_notificationDefinition(FILE * fp, char *name)
{
    register int    type;
    char            token[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    register struct node *np;

    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, MAXTOKEN);
    while (type != EQUALS && type != ENDOFFILE) {
        switch (type) {
        case DESCRIPTION:
            type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
            if (type != QUOTESTRING) {
                print_error("Bad DESCRIPTION", quoted_string_buffer, type);
                free_node(np);
                return NULL;
            }
            if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) {
                np->description = strdup(quoted_string_buffer);
            }
            break;
        case REFERENCE:
            type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
            if (type != QUOTESTRING) {
                print_error("Bad REFERENCE", quoted_string_buffer, type);
                free_node(np);
                return NULL;
            }
            np->reference = strdup(quoted_string_buffer);
            break;
        case OBJECTS:
            np->varbinds = getVarbinds(fp, &np->varbinds);
            if (!np->varbinds) {
                print_error("Bad OBJECTS list", token, type);
                free_node(np);
                return NULL;
            }
            break;
        default:
            
            break;
        }
        type = get_token(fp, token, MAXTOKEN);
    }
    return merge_parse_objectid(np, fp, name);
}


static struct node * parse_trapDefinition(FILE * fp, char *name)
{
    register int    type;
    char            token[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    register struct node *np;

    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, MAXTOKEN);
    while (type != EQUALS && type != ENDOFFILE) {
        switch (type) {
        case DESCRIPTION:
            type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
            if (type != QUOTESTRING) {
                print_error("Bad DESCRIPTION", quoted_string_buffer, type);
                free_node(np);
                return NULL;
            }
            if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) {
                np->description = strdup(quoted_string_buffer);
            }
            break;
        case REFERENCE:
            
            type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
            if (type != QUOTESTRING) {
                print_error("Bad REFERENCE", quoted_string_buffer, type);
                free_node(np);
                return NULL;
            }
            np->reference = strdup(quoted_string_buffer);
            break;
        case ENTERPRISE:
            type = get_token(fp, token, MAXTOKEN);
            if (type == LEFTBRACKET) {
                type = get_token(fp, token, MAXTOKEN);
                if (type != LABEL) {
                    print_error("Bad Trap Format", token, type);
                    free_node(np);
                    return NULL;
                }
                np->parent = strdup(token);
                
                type = get_token(fp, token, MAXTOKEN);
            } else if (type == LABEL) {
                np->parent = strdup(token);
            } else {
                free_node(np);
                return NULL;
            }
            break;
        case VARIABLES:
            np->varbinds = getVarbinds(fp, &np->varbinds);
            if (!np->varbinds) {
                print_error("Bad VARIABLES list", token, type);
                free_node(np);
                return NULL;
            }
            break;
        default:
            
            break;
        }
        type = get_token(fp, token, MAXTOKEN);
    }
    type = get_token(fp, token, MAXTOKEN);

    np->label = strdup(name);

    if (type != NUMBER) {
        print_error("Expected a Number", token, type);
        free_node(np);
        return NULL;
    }
    np->subid = strtoul(token, NULL, 10);
    np->next = alloc_node(current_module);
    if (np->next == NULL) {
        free_node(np);
        return (NULL);
    }

    
    if (np->parent == NULL) {
        free_node(np->next);
        free_node(np);
        gMibError = MODULE_SYNTAX_ERROR;
        return (NULL);
    }

    np->next->parent = np->parent;
    np->parent = (char *) malloc(strlen(np->parent) + 2);
    if (np->parent == NULL) {
        free_node(np->next);
        free_node(np);
        return (NULL);
    }
    strcpy(np->parent, np->next->parent);
    strcat(np->parent, "#");
    np->next->label = strdup(np->parent);
    return np;
}



static int eat_syntax(FILE * fp, char *token, int maxtoken)
{
    int             type, nexttype;
    struct node    *np = alloc_node(current_module);
    char            nexttoken[MAXTOKEN];

    if (!np)
	return 0;

    type = get_token(fp, token, maxtoken);
    nexttype = get_token(fp, nexttoken, MAXTOKEN);
    switch (type) {
    case INTEGER:
    case INTEGER32:
    case UINTEGER32:
    case UNSIGNED32:
    case COUNTER:
    case GAUGE:
    case BITSTRING:
    case LABEL:
        if (nexttype == LEFTBRACKET) {
            
            np->enums = parse_enumlist(fp, &np->enums);
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
        } else if (nexttype == LEFTPAREN) {
            
            np->ranges = parse_ranges(fp, &np->ranges);
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
        }
        break;
    case OCTETSTR:
    case KW_OPAQUE:
        
        if (nexttype == LEFTPAREN) {
            nexttype = get_token(fp, nexttoken, MAXTOKEN);
            if (nexttype == SIZE) {
                nexttype = get_token(fp, nexttoken, MAXTOKEN);
                if (nexttype == LEFTPAREN) {
                    np->ranges = parse_ranges(fp, &np->ranges);
                    nexttype = get_token(fp, nexttoken, MAXTOKEN);      
                    if (nexttype == RIGHTPAREN) {
                        nexttype = get_token(fp, nexttoken, MAXTOKEN);
                        break;
                    }
                }
            }
            print_error("Bad SIZE syntax", token, type);
            free_node(np);
            return nexttype;
        }
        break;
    case OBJID:
    case NETADDR:
    case IPADDR:
    case TIMETICKS:
    case NUL:
    case NSAPADDRESS:
    case COUNTER64:
        break;
    default:
        print_error("Bad syntax", token, type);
        free_node(np);
        return nexttype;
    }
    free_node(np);
    return nexttype;
}

static int compliance_lookup(const char *name, int modid)
{
    if (modid == -1) {
        struct objgroup *op = (struct objgroup *) malloc(sizeof(struct objgroup));
        if (!op)
            return 0;
        op->next = objgroups;
        op->name = strdup(name);
        op->line = mibLine;
        objgroups = op;
        return 1;
    } else return find_tree_node(name, modid) != NULL;
}

static struct node * parse_compliance(FILE * fp, char *name)
{
    int             type;
    char            token[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    struct node    *np;

    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, MAXTOKEN);
    if (type != STATUS) {
        print_error("Expected STATUS", token, type);
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != CURRENT && type != DEPRECATED && type != OBSOLETE) {
        print_error("Bad STATUS", token, type);
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != DESCRIPTION) {
        print_error("Expected DESCRIPTION", token, type);
        goto skip;
    }
    type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
    if (type != QUOTESTRING) {
        print_error("Bad DESCRIPTION", quoted_string_buffer, type);
        goto skip;
    }
    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_SAVE_MIB_DESCRS))
        np->description = strdup(quoted_string_buffer);
    type = get_token(fp, token, MAXTOKEN);
    if (type == REFERENCE) {
        type = get_token(fp, quoted_string_buffer, MAXTOKEN);
        if (type != QUOTESTRING) {
            print_error("Bad REFERENCE", quoted_string_buffer, type);
            goto skip;
        }
        np->reference = strdup(quoted_string_buffer);
        type = get_token(fp, token, MAXTOKEN);
    }
    if (type != MODULE) {
        print_error("Expected MODULE", token, type);
        goto skip;
    }
    while (type == MODULE) {
        int             modid = -1;
        char            modname[MAXTOKEN];
        type = get_token(fp, token, MAXTOKEN);
        if (type == LABEL && strcmp(token, module_name(current_module, modname))) {
            modid = read_module_internal(token);
            if (modid != MODULE_LOADED_OK && modid != MODULE_ALREADY_LOADED) {
                print_error("Unknown module", token, type);
                goto skip;
            }
            modid = which_module(token);
            type = get_token(fp, token, MAXTOKEN);
        }
        if (type == MANDATORYGROUPS) {
            type = get_token(fp, token, MAXTOKEN);
            if (type != LEFTBRACKET) {
                print_error("Expected \"{\"", token, type);
                goto skip;
            }
            do {
                type = get_token(fp, token, MAXTOKEN);
                if (type != LABEL) {
                    print_error("Bad group name", token, type);
                    goto skip;
                }
                if (!compliance_lookup(token, modid))
                    print_error("Unknown group", token, type);
                type = get_token(fp, token, MAXTOKEN);
            } while (type == COMMA);
            if (type != RIGHTBRACKET) {
                print_error("Expected \"}\"", token, type);
                goto skip;
            }
            type = get_token(fp, token, MAXTOKEN);
        }
        while (type == GROUP || type == OBJECT) {
            if (type == GROUP) {
                type = get_token(fp, token, MAXTOKEN);
                if (type != LABEL) {
                    print_error("Bad group name", token, type);
                    goto skip;
                }
                if (!compliance_lookup(token, modid))
                    print_error("Unknown group", token, type);
                type = get_token(fp, token, MAXTOKEN);
            } else {
                type = get_token(fp, token, MAXTOKEN);
                if (type != LABEL) {
                    print_error("Bad object name", token, type);
                    goto skip;
                }
                if (!compliance_lookup(token, modid))
                    print_error("Unknown group", token, type);
                type = get_token(fp, token, MAXTOKEN);
                if (type == SYNTAX)
                    type = eat_syntax(fp, token, MAXTOKEN);
                if (type == WRSYNTAX)
                    type = eat_syntax(fp, token, MAXTOKEN);
                if (type == MINACCESS) {
                    type = get_token(fp, token, MAXTOKEN);
                    if (type != NOACCESS && type != ACCNOTIFY && type != READONLY && type != WRITEONLY && type != READCREATE && type != READWRITE) {

                        print_error("Bad MIN-ACCESS spec", token, type);
                        goto skip;
                    }
                    type = get_token(fp, token, MAXTOKEN);
                }
            }
            if (type != DESCRIPTION) {
                print_error("Expected DESCRIPTION", token, type);
                goto skip;
            }
            type = get_token(fp, token, MAXTOKEN);
            if (type != QUOTESTRING) {
                print_error("Bad DESCRIPTION", token, type);
                goto skip;
            }
            type = get_token(fp, token, MAXTOKEN);
        }
    }
  skip:
    while (type != EQUALS && type != ENDOFFILE)
        type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);

    return merge_parse_objectid(np, fp, name);
}



static struct node * parse_capabilities(FILE * fp, char *name)
{
    int             type;
    char            token[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    struct node    *np;

    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, MAXTOKEN);
    if (type != PRODREL) {
        print_error("Expected PRODUCT-RELEASE", token, type);
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != QUOTESTRING) {
        print_error("Expected STRING after PRODUCT-RELEASE", token, type);
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != STATUS) {
        print_error("Expected STATUS", token, type);
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != CURRENT && type != OBSOLETE) {
        print_error("STATUS should be current or obsolete", token, type);
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != DESCRIPTION) {
        print_error("Expected DESCRIPTION", token, type);
        goto skip;
    }
    type = get_token(fp, quoted_string_buffer, MAXTOKEN);
    if (type != QUOTESTRING) {
        print_error("Bad DESCRIPTION", quoted_string_buffer, type);
        goto skip;
    }
    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) {
        np->description = strdup(quoted_string_buffer);
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type == REFERENCE) {
        type = get_token(fp, quoted_string_buffer, MAXTOKEN);
        if (type != QUOTESTRING) {
            print_error("Bad REFERENCE", quoted_string_buffer, type);
            goto skip;
        }
        np->reference = strdup(quoted_string_buffer);
        type = get_token(fp, token, type);
    }
    while (type == SUPPORTS) {
        int             modid;
        struct tree    *tp;

        type = get_token(fp, token, MAXTOKEN);
        if (type != LABEL) {
            print_error("Bad module name", token, type);
            goto skip;
        }
        modid = read_module_internal(token);
        if (modid != MODULE_LOADED_OK && modid != MODULE_ALREADY_LOADED) {
            print_error("Module not found", token, type);
            goto skip;
        }
        modid = which_module(token);
        type = get_token(fp, token, MAXTOKEN);
        if (type != INCLUDES) {
            print_error("Expected INCLUDES", token, type);
            goto skip;
        }
        type = get_token(fp, token, MAXTOKEN);
        if (type != LEFTBRACKET) {
            print_error("Expected \"{\"", token, type);
            goto skip;
        }
        do {
            type = get_token(fp, token, MAXTOKEN);
            if (type != LABEL) {
                print_error("Expected group name", token, type);
                goto skip;
            }
            tp = find_tree_node(token, modid);
            if (!tp)
                print_error("Group not found in module", token, type);
            type = get_token(fp, token, MAXTOKEN);
        } while (type == COMMA);
        if (type != RIGHTBRACKET) {
            print_error("Expected \"}\" after group list", token, type);
            goto skip;
        }
        type = get_token(fp, token, MAXTOKEN);
        while (type == VARIATION) {
            type = get_token(fp, token, MAXTOKEN);
            if (type != LABEL) {
                print_error("Bad object name", token, type);
                goto skip;
            }
            tp = find_tree_node(token, modid);
            if (!tp)
                print_error("Object not found in module", token, type);
            type = get_token(fp, token, MAXTOKEN);
            if (type == SYNTAX) {
                type = eat_syntax(fp, token, MAXTOKEN);
            }
            if (type == WRSYNTAX) {
                type = eat_syntax(fp, token, MAXTOKEN);
            }
            if (type == ACCESS) {
                type = get_token(fp, token, MAXTOKEN);
                if (type != ACCNOTIFY && type != READONLY && type != READWRITE && type != READCREATE && type != WRITEONLY && type != NOTIMPL) {

                    print_error("Bad ACCESS", token, type);
                    goto skip;
                }
                type = get_token(fp, token, MAXTOKEN);
            }
            if (type == CREATEREQ) {
                type = get_token(fp, token, MAXTOKEN);
                if (type != LEFTBRACKET) {
                    print_error("Expected \"{\"", token, type);
                    goto skip;
                }
                do {
                    type = get_token(fp, token, MAXTOKEN);
                    if (type != LABEL) {
                        print_error("Bad object name in list", token, type);
                        goto skip;
                    }
                    type = get_token(fp, token, MAXTOKEN);
                } while (type == COMMA);
                if (type != RIGHTBRACKET) {
                    print_error("Expected \"}\" after list", token, type);
                    goto skip;
                }
                type = get_token(fp, token, MAXTOKEN);
            }
            if (type == DEFVAL) {
                int             level = 1;
                type = get_token(fp, token, MAXTOKEN);
                if (type != LEFTBRACKET) {
                    print_error("Expected \"{\" after DEFVAL", token, type);
                    goto skip;
                }
                do {
                    type = get_token(fp, token, MAXTOKEN);
                    if (type == LEFTBRACKET)
                        level++;
                    else if (type == RIGHTBRACKET)
                        level--;
                } while ((type != RIGHTBRACKET || level != 0)
                         && type != ENDOFFILE);
                if (type != RIGHTBRACKET) {
                    print_error("Missing \"}\" after DEFVAL", token, type);
                    goto skip;
                }
                type = get_token(fp, token, MAXTOKEN);
            }
            if (type != DESCRIPTION) {
                print_error("Expected DESCRIPTION", token, type);
                goto skip;
            }
            type = get_token(fp, quoted_string_buffer, MAXTOKEN);
            if (type != QUOTESTRING) {
                print_error("Bad DESCRIPTION", quoted_string_buffer, type);
                goto skip;
            }
            type = get_token(fp, token, MAXTOKEN);
        }
    }
    if (type != EQUALS)
        print_error("Expected \"::=\"", token, type);
  skip:
    while (type != EQUALS && type != ENDOFFILE) {
        type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
    }
    return merge_parse_objectid(np, fp, name);
}


static void check_utc(const char *utc)
{
    int             len, year, month, day, hour, minute;

    len = strlen(utc);
    if (utc[len - 1] != 'Z' && utc[len - 1] != 'z') {
        print_error("Timestamp should end with Z", utc, QUOTESTRING);
        return;
    }
    if (len == 11) {
        len = sscanf(utc, "%2d%2d%2d%2d%2dZ", &year, &month, &day, &hour, &minute);

        year += 1900;
    } else if (len == 13)
        len = sscanf(utc, "%4d%2d%2d%2d%2dZ", &year, &month, &day, &hour, &minute);

    else {
        print_error("Bad timestamp format (11 or 13 characters)", utc, QUOTESTRING);
        return;
    }
    if (len != 5) {
        print_error("Bad timestamp format", utc, QUOTESTRING);
        return;
    }
    if (month < 1 || month > 12)
        print_error("Bad month in timestamp", utc, QUOTESTRING);
    if (day < 1 || day > 31)
        print_error("Bad day in timestamp", utc, QUOTESTRING);
    if (hour < 0 || hour > 23)
        print_error("Bad hour in timestamp", utc, QUOTESTRING);
    if (minute < 0 || minute > 59)
        print_error("Bad minute in timestamp", utc, QUOTESTRING);
}

static struct node * parse_moduleIdentity(FILE * fp, char *name)
{
    register int    type;
    char            token[MAXTOKEN];
    char            quoted_string_buffer[MAXQUOTESTR];
    register struct node *np;

    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, MAXTOKEN);
    if (type != LASTUPDATED) {
        print_error("Expected LAST-UPDATED", token, type);
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != QUOTESTRING) {
        print_error("Need STRING for LAST-UPDATED", token, type);
        goto skip;
    }
    check_utc(token);
    type = get_token(fp, token, MAXTOKEN);
    if (type != ORGANIZATION) {
        print_error("Expected ORGANIZATION", token, type);
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != QUOTESTRING) {
        print_error("Bad ORGANIZATION", token, type);
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != CONTACTINFO) {
        print_error("Expected CONTACT-INFO", token, type);
        goto skip;
    }
    type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
    if (type != QUOTESTRING) {
        print_error("Bad CONTACT-INFO", quoted_string_buffer, type);
        goto skip;
    }
    type = get_token(fp, token, MAXTOKEN);
    if (type != DESCRIPTION) {
        print_error("Expected DESCRIPTION", token, type);
        goto skip;
    }
    type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
    if (type != QUOTESTRING) {
        print_error("Bad DESCRIPTION", quoted_string_buffer, type);
        goto skip;
    }
    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_SAVE_MIB_DESCRS)) {
        np->description = strdup(quoted_string_buffer);
    }
    type = get_token(fp, token, MAXTOKEN);
    while (type == REVISION) {
        type = get_token(fp, token, MAXTOKEN);
        if (type != QUOTESTRING) {
            print_error("Bad REVISION", token, type);
            goto skip;
        }
        check_utc(token);
        type = get_token(fp, token, MAXTOKEN);
        if (type != DESCRIPTION) {
            print_error("Expected DESCRIPTION", token, type);
            goto skip;
        }
        type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
        if (type != QUOTESTRING) {
            print_error("Bad DESCRIPTION", quoted_string_buffer, type);
            goto skip;
        }
        type = get_token(fp, token, MAXTOKEN);
    }
    if (type != EQUALS)
        print_error("Expected \"::=\"", token, type);
  skip:
    while (type != EQUALS && type != ENDOFFILE) {
        type = get_token(fp, quoted_string_buffer, MAXQUOTESTR);
    }
    return merge_parse_objectid(np, fp, name);
}



static struct node * parse_macro(FILE * fp, char *name)
{
    register int    type;
    char            token[MAXTOKEN];
    struct node    *np;
    int             iLine = mibLine;

    np = alloc_node(current_module);
    if (np == NULL)
        return (NULL);
    type = get_token(fp, token, sizeof(token));
    while (type != EQUALS && type != ENDOFFILE) {
        type = get_token(fp, token, sizeof(token));
    }
    if (type != EQUALS) {
        if (np)
            free_node(np);
        return NULL;
    }
    while (type != BEGIN && type != ENDOFFILE) {
        type = get_token(fp, token, sizeof(token));
    }
    if (type != BEGIN) {
        if (np)
            free_node(np);
        return NULL;
    }
    while (type != END && type != ENDOFFILE) {
        type = get_token(fp, token, sizeof(token));
    }
    if (type != END) {
        if (np)
            free_node(np);
        return NULL;
    }

    if (netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_MIB_WARNINGS)) {
        snmp_log(LOG_WARNING, "%s MACRO (lines %d..%d parsed and ignored).\n", name, iLine, mibLine);

    }

    return np;
}


static void parse_imports(FILE * fp)
{
    register int    type;
    char            token[MAXTOKEN];
    char            modbuf[256];

    struct module_import import_list[MAX_IMPORTS];
    int             this_module;
    struct module  *mp;

    int             import_count = 0;   
    int             i = 0, old_i;       

    type = get_token(fp, token, MAXTOKEN);

    
    while (type != SEMI && type != ENDOFFILE) {
        if (type == LABEL) {
            if (import_count == MAX_IMPORTS) {
                print_error("Too many imported symbols", token, type);
                do {
                    type = get_token(fp, token, MAXTOKEN);
                } while (type != SEMI && type != ENDOFFILE);
                return;
            }
            import_list[import_count++].label = strdup(token);
        } else if (type == FROM) {
            type = get_token(fp, token, MAXTOKEN);
            if (import_count == i) {    
                type = get_token(fp, token, MAXTOKEN);
                continue;
            }
            this_module = which_module(token);

            for (old_i = i; i < import_count; ++i)
                import_list[i].modid = this_module;

            
            if (read_module_internal(token) == MODULE_NOT_FOUND) {
		int found = 0;
                for (; old_i < import_count; ++old_i) {
                    found += read_import_replacements(token, &import_list[old_i]);
                }
		if (!found)
		    print_module_not_found(token);
            }
        }
        type = get_token(fp, token, MAXTOKEN);
    }

    
    for (; i < import_count; ++i)
        import_list[i].modid = -1;

    
    for (mp = module_head; mp; mp = mp->next)
        if (mp->modid == current_module) {
            if (import_count == 0)
                return;
            if (mp->imports && (mp->imports != root_imports)) {
                
                for (i = 0; i < mp->no_imports; ++i) {
                    DEBUGMSGTL(("parse-mibs", "#### freeing Module %d '%s' %d\n", mp->modid, mp->imports[i].label, mp->imports[i].modid));


                    free((char *) mp->imports[i].label);
                }
                free((char *) mp->imports);
            }
            mp->imports = (struct module_import *)
                calloc(import_count, sizeof(struct module_import));
            if (mp->imports == NULL)
                return;
            for (i = 0; i < import_count; ++i) {
                mp->imports[i].label = import_list[i].label;
                mp->imports[i].modid = import_list[i].modid;
                DEBUGMSGTL(("parse-mibs", "#### adding Module %d '%s' %d\n", mp->modid, mp->imports[i].label, mp->imports[i].modid));

            }
            mp->no_imports = import_count;
            return;
        }

    
    print_module_not_found(module_name(current_module, modbuf));
    return;
}





static void dump_module_list(void)
{
    struct module  *mp = module_head;

    DEBUGMSGTL(("parse-mibs", "Module list:\n"));
    while (mp) {
        DEBUGMSGTL(("parse-mibs", "  %s %d %s %d\n", mp->name, mp->modid, mp->file, mp->no_imports));
        mp = mp->next;
    }
}

int which_module(const char *name)
{
    struct module  *mp;

    for (mp = module_head; mp; mp = mp->next)
        if (!label_compare(mp->name, name))
            return (mp->modid);

    DEBUGMSGTL(("parse-mibs", "Module %s not found\n", name));
    return (-1);
}


char           * module_name(int modid, char *cp)
{
    struct module  *mp;

    for (mp = module_head; mp; mp = mp->next)
        if (mp->modid == modid) {
            strcpy(cp, mp->name);
            return (cp);
        }

    if (modid != -1) DEBUGMSGTL(("parse-mibs", "Module %d not found\n", modid));
    sprintf(cp, "#%d", modid);
    return (cp);
}


netsnmp_feature_child_of(parse_add_module_replacement, netsnmp_unused)

void add_module_replacement(const char *old_module, const char *new_module_name, const char *tag, int len)


{
    struct module_compatability *mcp;

    mcp = (struct module_compatability *)
        calloc(1, sizeof(struct module_compatability));
    if (mcp == NULL)
        return;

    mcp->old_module = strdup(old_module);
    mcp->new_module = strdup(new_module_name);
    if (tag)
        mcp->tag = strdup(tag);
    mcp->tag_len = len;

    mcp->next = module_map_head;
    module_map_head = mcp;
}


static int read_module_replacements(const char *name)
{
    struct module_compatability *mcp;

    for (mcp = module_map_head; mcp; mcp = mcp->next) {
        if (!label_compare(mcp->old_module, name)) {
            if (netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_MIB_WARNINGS)) {
                snmp_log(LOG_WARNING, "Loading replacement module %s for %s (%s)\n", mcp->new_module, name, File);

	    }
            (void) netsnmp_read_module(mcp->new_module);
            return 1;
        }
    }
    return 0;
}

static int read_import_replacements(const char *old_module_name, struct module_import *identifier)

{
    struct module_compatability *mcp;

    
    for (mcp = module_map_head; mcp; mcp = mcp->next) {
        if (!label_compare(mcp->old_module, old_module_name)) {

            if (                 (mcp->tag_len == 0 && (mcp->tag == NULL || !label_compare(mcp->tag, identifier->label))) ||  (mcp->tag_len != 0 && !strncmp(mcp->tag, identifier->label, mcp->tag_len))





                ) {

                if (netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_MIB_WARNINGS)) {
                    snmp_log(LOG_WARNING, "Importing %s from replacement module %s instead of %s (%s)\n", identifier->label, mcp->new_module, old_module_name, File);


		}
                (void) netsnmp_read_module(mcp->new_module);
                identifier->modid = which_module(mcp->new_module);
                return 1;         
            }
        }
    }

    
    return read_module_replacements(old_module_name);
}



static int read_module_internal(const char *name)
{
    struct module  *mp;
    FILE           *fp;
    struct node    *np;

    netsnmp_init_mib_internals();

    for (mp = module_head; mp; mp = mp->next)
        if (!label_compare(mp->name, name)) {
            const char     *oldFile = File;
            int             oldLine = mibLine;
            int             oldModule = current_module;

            if (mp->no_imports != -1) {
                DEBUGMSGTL(("parse-mibs", "Module %s already loaded\n", name));
                return MODULE_ALREADY_LOADED;
            }
            if ((fp = fopen(mp->file, "r")) == NULL) {
                int rval;
                if (errno == ENOTDIR || errno == ENOENT)
                    rval = MODULE_NOT_FOUND;
                else rval = MODULE_LOAD_FAILED;
                snmp_log_perror(mp->file);
                return rval;
            }

            flockfile(fp);

            mp->no_imports = 0; 
            File = mp->file;
            mibLine = 1;
            current_module = mp->modid;
            
            np = parse(fp, NULL);

            funlockfile(fp);

            fclose(fp);
            File = oldFile;
            mibLine = oldLine;
            current_module = oldModule;
            if ((np == NULL) && (gMibError == MODULE_SYNTAX_ERROR) )
                return MODULE_SYNTAX_ERROR;
            return MODULE_LOADED_OK;
        }

    return MODULE_NOT_FOUND;
}

void adopt_orphans(void)
{
    struct node    *np, *onp;
    struct tree    *tp;
    int             i, adopted = 1;

    if (!orphan_nodes)
        return;
    init_node_hash(orphan_nodes);
    orphan_nodes = NULL;

    while (adopted) {
        adopted = 0;
        for (i = 0; i < NHASHSIZE; i++)
            if (nbuckets[i]) {
                for (np = nbuckets[i]; np != NULL; np = np->next) {
                    tp = find_tree_node(np->parent, -1);
		    if (tp) {
			do_subtree(tp, &np);
			adopted = 1;
                        
                        if(NULL == nbuckets[i])
                            break;

                        
                        for(onp = nbuckets[i]; onp; onp = onp->next)
                            if(onp == np)
                                break;
                        if(NULL == onp) { 
                            np = nbuckets[i]; 
                        }
		    }
		}
            }
    }

    
    for (i = 0; i < NHASHSIZE; i++)
        if (nbuckets[i]) {
            if (orphan_nodes)
                onp = np->next = nbuckets[i];
            else onp = orphan_nodes = nbuckets[i];
            nbuckets[i] = NULL;
            while (onp) {
                char            modbuf[256];
                snmp_log(LOG_WARNING, "Cannot adopt OID in %s: %s ::= { %s %ld }\n", module_name(onp->modid, modbuf), (onp->label ? onp->label : "<no label>"), (onp->parent ? onp->parent : "<no parent>"), onp->subid);





                np = onp;
                onp = onp->next;
            }
        }
}


struct tree    * read_module(const char *name)
{
    return netsnmp_read_module(name);
}


struct tree    * netsnmp_read_module(const char *name)
{
    int status = 0;
    status = read_module_internal(name);

    if (status == MODULE_NOT_FOUND) {
        if (!read_module_replacements(name))
            print_module_not_found(name);
    } else if (status == MODULE_SYNTAX_ERROR) {
        gMibError = 0;
        gLoop = 1;

        strncat(gMibNames, " ", sizeof(gMibNames) - strlen(gMibNames) - 1);
        strncat(gMibNames, name, sizeof(gMibNames) - strlen(gMibNames) - 1);
    }

    return tree_head;
}


void            unload_module_by_ID(int modID, struct tree *tree_top);

void unload_module_by_ID(int modID, struct tree *tree_top)
{
    struct tree    *tp, *next;
    int             i;

    for (tp = tree_top; tp; tp = next) {
        
        int             nmod = tp->number_modules;
        if (nmod > 0) {         
            
            int             cnt = 0, *pi1, *pi2 = tp->module_list;
            for (i = 0, pi1 = pi2; i < nmod; i++, pi2++) {
                if (*pi2 == modID)
                    continue;
                cnt++;
                *pi1++ = *pi2;
            }
            if (nmod != cnt) {  
                
                tp->number_modules = cnt;
                switch (cnt) {
                case 0:
                    tp->module_list[0] = -1;    
		    

                case 1:        
                    if (&(tp->modid) != tp->module_list) {
                        tp->modid = tp->module_list[0];
                        free(tp->module_list);
                        tp->module_list = &(tp->modid);
                    }
                    break;

                default:
                    break;
                }
            }                   
        }
        
        next = tp->next_peer;


        
        if (tp->child_list)
            unload_module_by_ID(modID, tp->child_list);


        if (tp->number_modules == 0) {
            
            if (tp->child_list == NULL) {
                unlink_tree(tp);
                free_tree(tp);
            } else {
                free_partial_tree(tp, TRUE);
            }
        }
    }
}


int unload_module(const char *name)
{
    return netsnmp_unload_module(name);
}


int netsnmp_unload_module(const char *name)
{
    struct module  *mp;
    int             modID = -1;

    for (mp = module_head; mp; mp = mp->next)
        if (!label_compare(mp->name, name)) {
            modID = mp->modid;
            break;
        }

    if (modID == -1) {
        DEBUGMSGTL(("unload-mib", "Module %s not found to unload\n", name));
        return MODULE_NOT_FOUND;
    }
    unload_module_by_ID(modID, tree_head);
    mp->no_imports = -1;        
    return MODULE_LOADED_OK;    
}


void unload_all_mibs(void)
{
    struct module  *mp;
    struct module_compatability *mcp;
    struct tc      *ptc;
    unsigned int    i;

    for (mcp = module_map_head; mcp; mcp = module_map_head) {
        if (mcp == module_map)
            break;
        module_map_head = mcp->next;
        if (mcp->tag) free(NETSNMP_REMOVE_CONST(char *, mcp->tag));
        free(NETSNMP_REMOVE_CONST(char *, mcp->old_module));
        free(NETSNMP_REMOVE_CONST(char *, mcp->new_module));
        free(mcp);
    }

    for (mp = module_head; mp; mp = module_head) {
        struct module_import *mi = mp->imports;
        if (mi) {
            for (i = 0; i < (unsigned int)mp->no_imports; ++i) {
                SNMP_FREE((mi + i)->label);
            }
            mp->no_imports = 0;
            if (mi == root_imports)
                memset(mi, 0, sizeof(*mi));
            else free(mi);
        }

        unload_module_by_ID(mp->modid, tree_head);
        module_head = mp->next;
        free(mp->name);
        free(mp->file);
        free(mp);
    }
    unload_module_by_ID(-1, tree_head);
    

    for (i = 0, ptc = tclist; i < MAXTC; i++, ptc++) {
        if (ptc->type == 0)
            continue;
        free_enums(&ptc->enums);
        free_ranges(&ptc->ranges);
        free(ptc->descriptor);
        if (ptc->hint)
            free(ptc->hint);
        if (ptc->description)
            free(ptc->description);
    }
    memset(tclist, 0, MAXTC * sizeof(struct tc));

    memset(buckets, 0, sizeof(buckets));
    memset(nbuckets, 0, sizeof(nbuckets));
    memset(tbuckets, 0, sizeof(tbuckets));

    for (i = 0; i < sizeof(root_imports) / sizeof(root_imports[0]); i++) {
        SNMP_FREE(root_imports[i].label);
    }

    max_module = 0;
    current_module = 0;
    module_map_head = NULL;
    SNMP_FREE(last_err_module);
}

static void new_module(const char *name, const char *file)
{
    struct module  *mp;

    for (mp = module_head; mp; mp = mp->next)
        if (!label_compare(mp->name, name)) {
            DEBUGMSGTL(("parse-mibs", "  Module %s already noted\n", name));
            
            if (label_compare(mp->file, file)) {
                DEBUGMSGTL(("parse-mibs", "    %s is now in %s\n", name, file));
                if (netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_MIB_WARNINGS)) {
                    snmp_log(LOG_WARNING, "Warning: Module %s was in %s now is %s\n", name, mp->file, file);

		}

                
                free(mp->file);
                mp->file = strdup(file);
            }
            return;
        }

    
    DEBUGMSGTL(("parse-mibs", "  Module %d %s is in %s\n", max_module, name, file));
    mp = (struct module *) calloc(1, sizeof(struct module));
    if (mp == NULL)
        return;
    mp->name = strdup(name);
    mp->file = strdup(file);
    mp->imports = NULL;
    mp->no_imports = -1;        
    mp->modid = max_module;
    ++max_module;

    mp->next = module_head;     
    module_head = mp;
}


static void scan_objlist(struct node *root, struct module *mp, struct objgroup *list, const char *error)
{
    int             oLine = mibLine;

    while (list) {
        struct objgroup *gp = list;
        struct node    *np;
        list = list->next;
        np = root;
        while (np)
            if (label_compare(np->label, gp->name))
                np = np->next;
            else break;
        if (!np) {
	    int i;
	    struct module_import *mip;
	    
	    for (i = 0, mip = mp->imports; i < mp->no_imports; i++, mip++)
		if (strcmp(mip->label, gp->name) == 0)
		    break;
	    if (i == mp->no_imports) {
		mibLine = gp->line;
		print_error(error, gp->name, QUOTESTRING);
	    }
        }
        free(gp->name);
        free(gp);
    }
    mibLine = oLine;
}


static struct node * parse(FILE * fp, struct node *root)
{

    extern void     xmalloc_stats(FILE *);

    char            token[MAXTOKEN];
    char            name[MAXTOKEN+1];
    int             type = LABEL;
    int             lasttype = LABEL;



    int             state = BETWEEN_MIBS;
    struct node    *np, *nnp;
    struct objgroup *oldgroups = NULL, *oldobjects = NULL, *oldnotifs = NULL;

    DEBUGMSGTL(("parse-file", "Parsing file:  %s...\n", File));

    if (last_err_module)
        free(last_err_module);
    last_err_module = NULL;

    np = root;
    if (np != NULL) {
        
        while (np->next)
            np = np->next;
    }

    while (type != ENDOFFILE) {
        if (lasttype == CONTINUE)
            lasttype = type;
        else type = lasttype = get_token(fp, token, MAXTOKEN);

        switch (type) {
        case END:
            if (state != IN_MIB) {
                print_error("Error, END before start of MIB", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            } else {
                struct module  *mp;

                printf("\nNodes for Module %s:\n", name);
                print_nodes(stdout, root);

                for (mp = module_head; mp; mp = mp->next)
                    if (mp->modid == current_module)
                        break;
                scan_objlist(root, mp, objgroups, "Undefined OBJECT-GROUP");
                scan_objlist(root, mp, objects, "Undefined OBJECT");
                scan_objlist(root, mp, notifs, "Undefined NOTIFICATION");
                objgroups = oldgroups;
                objects = oldobjects;
                notifs = oldnotifs;
                do_linkup(mp, root);
                np = root = NULL;
            }
            state = BETWEEN_MIBS;

            if (netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_MIB_WARNINGS)) {
                
	    }

            continue;
        case IMPORTS:
            parse_imports(fp);
            continue;
        case EXPORTS:
            while (type != SEMI && type != ENDOFFILE)
                type = get_token(fp, token, MAXTOKEN);
            continue;
        case LABEL:
        case INTEGER:
        case INTEGER32:
        case UINTEGER32:
        case UNSIGNED32:
        case COUNTER:
        case COUNTER64:
        case GAUGE:
        case IPADDR:
        case NETADDR:
        case NSAPADDRESS:
        case OBJSYNTAX:
        case APPSYNTAX:
        case SIMPLESYNTAX:
        case OBJNAME:
        case NOTIFNAME:
        case KW_OPAQUE:
        case TIMETICKS:
            break;
        case ENDOFFILE:
            continue;
        default:
            strlcpy(name, token, sizeof(name));
            type = get_token(fp, token, MAXTOKEN);
            nnp = NULL;
            if (type == MACRO) {
                nnp = parse_macro(fp, name);
                if (nnp == NULL) {
                    print_error("Bad parse of MACRO", NULL, type);
                    gMibError = MODULE_SYNTAX_ERROR;
                    
                }
                free_node(nnp); 
                nnp = NULL;
            } else print_error(name, "is a reserved word", lasttype);
            continue;           
        }
        strlcpy(name, token, sizeof(name));
        type = get_token(fp, token, MAXTOKEN);
        nnp = NULL;

        
        if (lasttype == LABEL && type == LEFTBRACKET) {
            while (type != RIGHTBRACKET && type != ENDOFFILE)
                type = get_token(fp, token, MAXTOKEN);
            if (type == ENDOFFILE) {
                print_error("Expected \"}\"", token, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            type = get_token(fp, token, MAXTOKEN);
        }

        switch (type) {
        case DEFINITIONS:
            if (state != BETWEEN_MIBS) {
                print_error("Error, nested MIBS", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            state = IN_MIB;
            current_module = which_module(name);
            oldgroups = objgroups;
            objgroups = NULL;
            oldobjects = objects;
            objects = NULL;
            oldnotifs = notifs;
            notifs = NULL;
            if (current_module == -1) {
                new_module(name, File);
                current_module = which_module(name);
            }
            DEBUGMSGTL(("parse-mibs", "Parsing MIB: %d %s\n", current_module, name));
            while ((type = get_token(fp, token, MAXTOKEN)) != ENDOFFILE)
                if (type == BEGIN)
                    break;
            break;
        case OBJTYPE:
            nnp = parse_objecttype(fp, name);
            if (nnp == NULL) {
                print_error("Bad parse of OBJECT-TYPE", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case OBJGROUP:
            nnp = parse_objectgroup(fp, name, OBJECTS, &objects);
            if (nnp == NULL) {
                print_error("Bad parse of OBJECT-GROUP", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case NOTIFGROUP:
            nnp = parse_objectgroup(fp, name, NOTIFICATIONS, &notifs);
            if (nnp == NULL) {
                print_error("Bad parse of NOTIFICATION-GROUP", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case TRAPTYPE:
            nnp = parse_trapDefinition(fp, name);
            if (nnp == NULL) {
                print_error("Bad parse of TRAP-TYPE", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case NOTIFTYPE:
            nnp = parse_notificationDefinition(fp, name);
            if (nnp == NULL) {
                print_error("Bad parse of NOTIFICATION-TYPE", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case COMPLIANCE:
            nnp = parse_compliance(fp, name);
            if (nnp == NULL) {
                print_error("Bad parse of MODULE-COMPLIANCE", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case AGENTCAP:
            nnp = parse_capabilities(fp, name);
            if (nnp == NULL) {
                print_error("Bad parse of AGENT-CAPABILITIES", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case MACRO:
            nnp = parse_macro(fp, name);
            if (nnp == NULL) {
                print_error("Bad parse of MACRO", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                
            }
            free_node(nnp);     
            nnp = NULL;
            break;
        case MODULEIDENTITY:
            nnp = parse_moduleIdentity(fp, name);
            if (nnp == NULL) {
                print_error("Bad parse of MODULE-IDENTITY", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case OBJIDENTITY:
            nnp = parse_objectgroup(fp, name, OBJECTS, &objects);
            if (nnp == NULL) {
                print_error("Bad parse of OBJECT-IDENTITY", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case OBJECT:
            type = get_token(fp, token, MAXTOKEN);
            if (type != IDENTIFIER) {
                print_error("Expected IDENTIFIER", token, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            type = get_token(fp, token, MAXTOKEN);
            if (type != EQUALS) {
                print_error("Expected \"::=\"", token, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            nnp = parse_objectid(fp, name);
            if (nnp == NULL) {
                print_error("Bad parse of OBJECT IDENTIFIER", NULL, type);
                gMibError = MODULE_SYNTAX_ERROR;
                return NULL;
            }
            break;
        case EQUALS:
            nnp = parse_asntype(fp, name, &type, token);
            lasttype = CONTINUE;
            break;
        case ENDOFFILE:
            break;
        default:
            print_error("Bad operator", token, type);
            gMibError = MODULE_SYNTAX_ERROR;
            return NULL;
        }
        if (nnp) {
            if (np)
                np->next = nnp;
            else np = root = nnp;
            while (np->next)
                np = np->next;
            if (np->type == TYPE_OTHER)
                np->type = type;
        }
    }
    DEBUGMSGTL(("parse-file", "End of file (%s)\n", File));
    return root;
}


static int is_labelchar(int ich)
{
    if ((isalnum(ich)) || (ich == '-'))
        return 1;
    if (ich == '_' && netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_MIB_PARSE_LABEL)) {
        return 1;
    }

    return 0;
}


static int netsnmp_getc(FILE *stream)
{

    return fgetc_unlocked(stream);

    return getc(stream);

}


static int get_token(FILE * fp, char *token, int maxtlen)
{
    register int    ch, ch_next;
    register char  *cp = token;
    register int    hash = 0;
    register struct tok *tp;
    int             too_long = 0;
    enum { bdigits, xdigits, other } seenSymbols;

    
    do {
        ch = netsnmp_getc(fp);
        if (ch == '\n')
            mibLine++;
    }
    while (isspace(ch) && ch != EOF);
    *cp++ = ch;
    *cp = '\0';
    switch (ch) {
    case EOF:
        return ENDOFFILE;
    case '"':
        return parseQuoteString(fp, token, maxtlen);
    case '\'':                 
        seenSymbols = bdigits;
        while ((ch = netsnmp_getc(fp)) != EOF && ch != '\'') {
            switch (seenSymbols) {
            case bdigits:
                if (ch == '0' || ch == '1')
                    break;
                seenSymbols = xdigits;
		
            case xdigits:
                if (isxdigit(ch))
                    break;
                seenSymbols = other;
            case other:
                break;
            }
            if (cp - token < maxtlen - 2)
                *cp++ = ch;
        }
        if (ch == '\'') {
            unsigned long   val = 0;
            char           *run = token + 1;
            ch = netsnmp_getc(fp);
            switch (ch) {
            case EOF:
                return ENDOFFILE;
            case 'b':
            case 'B':
                if (seenSymbols > bdigits) {
                    *cp++ = '\'';
                    *cp = 0;
                    return LABEL;
                }
                while (run != cp)
                    val = val * 2 + *run++ - '0';
                break;
            case 'h':
            case 'H':
                if (seenSymbols > xdigits) {
                    *cp++ = '\'';
                    *cp = 0;
                    return LABEL;
                }
                while (run != cp) {
                    ch = *run++;
                    if ('0' <= ch && ch <= '9')
                        val = val * 16 + ch - '0';
                    else if ('a' <= ch && ch <= 'f')
                        val = val * 16 + ch - 'a' + 10;
                    else if ('A' <= ch && ch <= 'F')
                        val = val * 16 + ch - 'A' + 10;
                }
                break;
            default:
                *cp++ = '\'';
                *cp = 0;
                return LABEL;
            }
            sprintf(token, "%ld", val);
            return NUMBER;
        } else return LABEL;
    case '(':
        return LEFTPAREN;
    case ')':
        return RIGHTPAREN;
    case '{':
        return LEFTBRACKET;
    case '}':
        return RIGHTBRACKET;
    case '[':
        return LEFTSQBRACK;
    case ']':
        return RIGHTSQBRACK;
    case ';':
        return SEMI;
    case ',':
        return COMMA;
    case '|':
        return BAR;
    case '.':
        ch_next = netsnmp_getc(fp);
        if (ch_next == '.')
            return RANGE;
        ungetc(ch_next, fp);
        return LABEL;
    case ':':
        ch_next = netsnmp_getc(fp);
        if (ch_next != ':') {
            ungetc(ch_next, fp);
            return LABEL;
        }
        ch_next = netsnmp_getc(fp);
        if (ch_next != '=') {
            ungetc(ch_next, fp);
            return LABEL;
        }
        return EQUALS;
    case '-':
        ch_next = netsnmp_getc(fp);
        if (ch_next == '-') {
            if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_MIB_COMMENT_TERM)) {
                
                while ((ch_next != EOF) && (ch_next != '\n'))
                    ch_next = netsnmp_getc(fp);
            } else {
                
                
                ch = ' ';
                ch_next = netsnmp_getc(fp);
                while (ch_next != EOF && ch_next != '\n' && (ch != '-' || ch_next != '-')) {
                    ch = ch_next;
                    ch_next = netsnmp_getc(fp);
                }
            }
            if (ch_next == EOF)
                return ENDOFFILE;
            if (ch_next == '\n')
                mibLine++;
            return get_token(fp, token, maxtlen);
        }
        ungetc(ch_next, fp);
	
    default:
        
        if (!is_labelchar(ch))
            return LABEL;
        hash += tolower(ch);
      more:
        while (is_labelchar(ch_next = netsnmp_getc(fp))) {
            hash += tolower(ch_next);
            if (cp - token < maxtlen - 1)
                *cp++ = ch_next;
            else too_long = 1;
        }
        ungetc(ch_next, fp);
        *cp = '\0';

        if (too_long)
            print_error("Warning: token too long", token, CONTINUE);
        for (tp = buckets[BUCKET(hash)]; tp; tp = tp->next) {
            if ((tp->hash == hash) && (!label_compare(tp->name, token)))
                break;
        }
        if (tp) {
            if (tp->token != CONTINUE)
                return (tp->token);
            while (isspace((ch_next = netsnmp_getc(fp))))
                if (ch_next == '\n')
                    mibLine++;
            if (ch_next == EOF)
                return ENDOFFILE;
            if (isalnum(ch_next)) {
                *cp++ = ch_next;
                hash += tolower(ch_next);
                goto more;
            }
        }
        if (token[0] == '-' || isdigit((unsigned char)(token[0]))) {
            for (cp = token + 1; *cp; cp++)
                if (!isdigit((unsigned char)(*cp)))
                    return LABEL;
            return NUMBER;
        }
        return LABEL;
    }
}

netsnmp_feature_child_of(parse_get_token, netsnmp_unused)

int snmp_get_token(FILE * fp, char *token, int maxtlen)
{
    return get_token(fp, token, maxtlen);
}


int add_mibfile(const char* tmpstr, const char* d_name, FILE *ip )
{
    FILE           *fp;
    char            token[MAXTOKEN], token2[MAXTOKEN];

    
    if ((fp = fopen(tmpstr, "r")) == NULL) {
        snmp_log_perror(tmpstr);
        return 1;
    }
    DEBUGMSGTL(("parse-mibs", "Checking file: %s...\n", tmpstr));
    mibLine = 1;
    File = tmpstr;
    if (get_token(fp, token, MAXTOKEN) != LABEL) {
	    fclose(fp);
	    return 1;
    }
    
    if (get_token(fp, token2, MAXTOKEN) == DEFINITIONS) {
        new_module(token, tmpstr);
        if (ip)
            fprintf(ip, "%s %s\n", token, d_name);
        fclose(fp);
        return 0;
    } else {
        fclose(fp);
        return 1;
    }
}

static int elemcmp(const void *a, const void *b)
{
    const char *const *s1 = a, *const *s2 = b;

    return strcmp(*s1, *s2);
}


static int scan_directory(char ***result, const char *dirname)
{
    DIR            *dir, *dir2;
    struct dirent  *file;
    char          **filenames = NULL;
    int             fname_len, i, filename_count = 0, array_size = 0;
    char           *tmpstr;

    *result = NULL;

    dir = opendir(dirname);
    if (!dir)
        return -1;

    while ((file = readdir(dir))) {
        
        fname_len = strlen(file->d_name);
        if (fname_len > 0 && file->d_name[0] != '.' && file->d_name[0] != '#' && file->d_name[fname_len-1] != '#' && file->d_name[fname_len-1] != '~') {


            if (asprintf(&tmpstr, "%s/%s", dirname, file->d_name) < 0)
                continue;
            dir2 = opendir(tmpstr);
            if (dir2) {
                
                closedir(dir2);
            } else {
                if (filename_count >= array_size) {
                    char **new_filenames;

                    array_size = (array_size + 16) * 2;
                    new_filenames = realloc(filenames, array_size * sizeof(filenames[0]));
                    if (!new_filenames) {
                        free(tmpstr);
                        for (i = 0; i < filename_count; i++)
                            free(filenames[i]);
                        free(filenames);
                        closedir(dir);
                        return -1;
                    }
                    filenames = new_filenames;
                }
                filenames[filename_count++] = tmpstr;
                tmpstr = NULL;
            }
            free(tmpstr);
        }
    }
    closedir(dir);

    if (filenames)
        qsort(filenames, filename_count, sizeof(filenames[0]), elemcmp);
    *result = filenames;

    return filename_count;
}


int add_mibdir(const char *dirname)
{
    FILE           *ip;
    const char     *oldFile = File;
    char          **filenames;
    int             count = 0;
    int             filename_count, i;

    char           *token;
    char space;
    char newline;
    struct stat     dir_stat, idx_stat;
    char            tmpstr[300];
    char            tmpstr1[300];


    DEBUGMSGTL(("parse-mibs", "Scanning directory %s\n", dirname));

    token = netsnmp_mibindex_lookup( dirname );
    if (token && stat(token, &idx_stat) == 0 && stat(dirname, &dir_stat) == 0) {
        if (dir_stat.st_mtime < idx_stat.st_mtime) {
            DEBUGMSGTL(("parse-mibs", "The index is good\n"));
            if ((ip = fopen(token, "r")) != NULL) {
                fgets(tmpstr, sizeof(tmpstr), ip); 
                while (fscanf(ip, "%127s%c%299[^\n]%c", token, &space, tmpstr, &newline) == 4) {

		    
		    if (space != ' ' || newline != '\n') {
			snmp_log(LOG_ERR, "add_mibdir: strings scanned in from %s/%s "  "are too large.  count = %d\n ", dirname ".index", count);

			    break;
		    }
		   
		    snprintf(tmpstr1, sizeof(tmpstr1), "%s/%s", dirname, tmpstr);
                    tmpstr1[ sizeof(tmpstr1)-1 ] = 0;
                    new_module(token, tmpstr1);
                    count++;
                }
                fclose(ip);
                return count;
            } else DEBUGMSGTL(("parse-mibs", "Can't read index\n"));
        } else DEBUGMSGTL(("parse-mibs", "Index outdated\n"));
    } else DEBUGMSGTL(("parse-mibs", "No index\n"));


    filename_count = scan_directory(&filenames, dirname);

    if (filename_count >= 0) {
        ip = netsnmp_mibindex_new(dirname);
        for (i = 0; i < filename_count; i++) {
            if (add_mibfile(filenames[i], strrchr(filenames[i], '/'), ip) == 0)
                count++;
	    free(filenames[i]);
        }
        File = oldFile;
        if (ip)
            fclose(ip);
        free(filenames);
        return (count);
    }
    else DEBUGMSGTL(("parse-mibs","cannot open MIB directory %s\n", dirname));

    return (-1);
}



struct tree    * read_mib(const char *filename)
{
    FILE           *fp;
    char            token[MAXTOKEN];

    fp = fopen(filename, "r");
    if (fp == NULL) {
        snmp_log_perror(filename);
        return NULL;
    }
    mibLine = 1;
    File = filename;
    DEBUGMSGTL(("parse-mibs", "Parsing file: %s...\n", filename));
    if (get_token(fp, token, MAXTOKEN) != LABEL) {
	    snmp_log(LOG_ERR, "Failed to parse MIB file %s\n", filename);
	    fclose(fp);
	    return NULL;
    }
    fclose(fp);
    new_module(token, filename);
    (void) netsnmp_read_module(token);

    return tree_head;
}


struct tree    * read_all_mibs(void)
{
    struct module  *mp;

    for (mp = module_head; mp; mp = mp->next)
        if (mp->no_imports == -1)
            netsnmp_read_module(mp->name);
    adopt_orphans();

    
    if (gLoop == 1) {
        gLoop = 0;
        free(gpMibErrorString);
        gpMibErrorString = NULL;
        if (asprintf(&gpMibErrorString, "Error in parsing MIB module(s): %s !" " Unable to load corresponding MIB(s)", gMibNames) < 0) {
            snmp_log(LOG_CRIT, "failed to allocated memory for gpMibErrorString\n");
        }
    }

    
    tree_head->parseErrorString = gpMibErrorString;
	
    return tree_head;
}



int main(int argc, char *argv[])
{
    int             i;
    struct tree    *tp;
    netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_MIB_WARNINGS, 2);

    netsnmp_init_mib();

    if (argc == 1)
        (void) read_all_mibs();
    else for (i = 1; i < argc; i++)
            read_mib(argv[i]);

    for (tp = tree_head; tp; tp = tp->next_peer)
        print_subtree(stdout, tp, 0);
    free_tree(tree_head);

    return 0;
}


static int parseQuoteString(FILE * fp, char *token, int maxtlen)
{
    register int    ch;
    int             count = 0;
    int             too_long = 0;
    char           *token_start = token;

    for (ch = netsnmp_getc(fp); ch != EOF; ch = netsnmp_getc(fp)) {
        if (ch == '\r')
            continue;
        if (ch == '\n') {
            mibLine++;
        } else if (ch == '"') {
            *token = '\0';
            if (too_long && netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID,  NETSNMP_DS_LIB_MIB_WARNINGS) > 1) {
                
                char            ch_save = *(token_start + 50);
                *(token_start + 50) = '\0';
                print_error("Warning: string too long", token_start, QUOTESTRING);
                *(token_start + 50) = ch_save;
            }
            return QUOTESTRING;
        }
        
        if (++count < maxtlen)
            *token++ = ch;
        else too_long = 1;
    }

    return 0;
}


static struct index_list * getIndexes(FILE * fp, struct index_list **retp)
{
    int             type;
    char            token[MAXTOKEN];
    char            nextIsImplied = 0;

    struct index_list *mylist = NULL;
    struct index_list **mypp = &mylist;

    free_indexes(retp);

    type = get_token(fp, token, MAXTOKEN);

    if (type != LEFTBRACKET) {
        return NULL;
    }

    type = get_token(fp, token, MAXTOKEN);
    while (type != RIGHTBRACKET && type != ENDOFFILE) {
        if ((type == LABEL) || (type & SYNTAX_MASK)) {
            *mypp = (struct index_list *) calloc(1, sizeof(struct index_list));
            if (*mypp) {
                (*mypp)->ilabel = strdup(token);
                (*mypp)->isimplied = nextIsImplied;
                mypp = &(*mypp)->next;
                nextIsImplied = 0;
            }
        } else if (type == IMPLIED) {
            nextIsImplied = 1;
        }
        type = get_token(fp, token, MAXTOKEN);
    }

    *retp = mylist;
    return mylist;
}

static struct varbind_list * getVarbinds(FILE * fp, struct varbind_list **retp)
{
    int             type;
    char            token[MAXTOKEN];

    struct varbind_list *mylist = NULL;
    struct varbind_list **mypp = &mylist;

    free_varbinds(retp);

    type = get_token(fp, token, MAXTOKEN);

    if (type != LEFTBRACKET) {
        return NULL;
    }

    type = get_token(fp, token, MAXTOKEN);
    while (type != RIGHTBRACKET && type != ENDOFFILE) {
        if ((type == LABEL) || (type & SYNTAX_MASK)) {
            *mypp = (struct varbind_list *) calloc(1, sizeof(struct varbind_list));


            if (*mypp) {
                (*mypp)->vblabel = strdup(token);
                mypp = &(*mypp)->next;
            }
        }
        type = get_token(fp, token, MAXTOKEN);
    }

    *retp = mylist;
    return mylist;
}

static void free_indexes(struct index_list **spp)
{
    if (spp && *spp) {
        struct index_list *pp, *npp;

        pp = *spp;
        *spp = NULL;

        while (pp) {
            npp = pp->next;
            if (pp->ilabel)
                free(pp->ilabel);
            free(pp);
            pp = npp;
        }
    }
}

static void free_varbinds(struct varbind_list **spp)
{
    if (spp && *spp) {
        struct varbind_list *pp, *npp;

        pp = *spp;
        *spp = NULL;

        while (pp) {
            npp = pp->next;
            if (pp->vblabel)
                free(pp->vblabel);
            free(pp);
            pp = npp;
        }
    }
}

static void free_ranges(struct range_list **spp)
{
    if (spp && *spp) {
        struct range_list *pp, *npp;

        pp = *spp;
        *spp = NULL;

        while (pp) {
            npp = pp->next;
            free(pp);
            pp = npp;
        }
    }
}

static void free_enums(struct enum_list **spp)
{
    if (spp && *spp) {
        struct enum_list *pp, *npp;

        pp = *spp;
        *spp = NULL;

        while (pp) {
            npp = pp->next;
            if (pp->label)
                free(pp->label);
            free(pp);
            pp = npp;
        }
    }
}

static struct enum_list * copy_enums(struct enum_list *sp)
{
    struct enum_list *xp = NULL, **spp = &xp;

    while (sp) {
        *spp = (struct enum_list *) calloc(1, sizeof(struct enum_list));
        if (!*spp)
            break;
        (*spp)->label = strdup(sp->label);
        (*spp)->value = sp->value;
        spp = &(*spp)->next;
        sp = sp->next;
    }
    return (xp);
}

static struct range_list * copy_ranges(struct range_list *sp)
{
    struct range_list *xp = NULL, **spp = &xp;

    while (sp) {
        *spp = (struct range_list *) calloc(1, sizeof(struct range_list));
        if (!*spp)
            break;
        (*spp)->low = sp->low;
        (*spp)->high = sp->high;
        spp = &(*spp)->next;
        sp = sp->next;
    }
    return (xp);
}


static int tossObjectIdentifier(FILE * fp)
{
    int             type;
    char            token[MAXTOKEN];
    int             bracketcount = 1;

    type = get_token(fp, token, MAXTOKEN);

    if (type != LEFTBRACKET)
        return 0;
    while ((type != RIGHTBRACKET || bracketcount > 0) && type != ENDOFFILE) {
        type = get_token(fp, token, MAXTOKEN);
        if (type == LEFTBRACKET)
            bracketcount++;
        else if (type == RIGHTBRACKET)
            bracketcount--;
    }

    if (type == RIGHTBRACKET)
        return OBJID;
    else return 0;
}


struct tree    * find_node(const char *name, struct tree *subtree)
{                               
    return (find_tree_node(name, -1));
}

netsnmp_feature_child_of(parse_find_node2, netsnmp_unused)

struct tree    * find_node2(const char *name, const char *module)
{                               
  int modid = -1;
  if (module) {
    modid = which_module(module);
  }
  if (modid == -1)
  {
    return (NULL);
  }
  return (find_tree_node(name, modid));
}




struct module  * find_module(int mid)
{
    struct module  *mp;

    for (mp = module_head; mp != NULL; mp = mp->next) {
        if (mp->modid == mid)
            break;
    }
    return mp;
}



static char     leave_indent[256];
static int      leave_was_simple;

static void print_mib_leaves(FILE * f, struct tree *tp, int width)
{
    struct tree    *ntp;
    char           *ip = leave_indent + strlen(leave_indent) - 1;
    char            last_ipch = *ip;

    *ip = '+';
    if (tp->type == TYPE_OTHER || tp->type > TYPE_SIMPLE_LAST) {
        fprintf(f, "%s--%s(%ld)\n", leave_indent, tp->label, tp->subid);
        if (tp->indexes) {
            struct index_list *xp = tp->indexes;
            int             first = 1, cpos = 0, len, cmax = width - strlen(leave_indent) - 12;
            *ip = last_ipch;
            fprintf(f, "%s  |  Index: ", leave_indent);
            while (xp) {
                if (first)
                    first = 0;
                else fprintf(f, ", ");
                cpos += (len = strlen(xp->ilabel) + 2);
                if (cpos > cmax) {
                    fprintf(f, "\n");
                    fprintf(f, "%s  |         ", leave_indent);
                    cpos = len;
                }
                fprintf(f, "%s", xp->ilabel);
                xp = xp->next;
            }
            fprintf(f, "\n");
            *ip = '+';
        }
    } else {
        const char     *acc, *typ;
        int             size = 0;
        switch (tp->access) {
        case MIB_ACCESS_NOACCESS:
            acc = "----";
            break;
        case MIB_ACCESS_READONLY:
            acc = "-R--";
            break;
        case MIB_ACCESS_WRITEONLY:
            acc = "--W-";
            break;
        case MIB_ACCESS_READWRITE:
            acc = "-RW-";
            break;
        case MIB_ACCESS_NOTIFY:
            acc = "---N";
            break;
        case MIB_ACCESS_CREATE:
            acc = "CR--";
            break;
        default:
            acc = "    ";
            break;
        }
        switch (tp->type) {
        case TYPE_OBJID:
            typ = "ObjID    ";
            break;
        case TYPE_OCTETSTR:
            typ = "String   ";
            size = 1;
            break;
        case TYPE_INTEGER:
            if (tp->enums)
                typ = "EnumVal  ";
            else typ = "INTEGER  ";
            break;
        case TYPE_NETADDR:
            typ = "NetAddr  ";
            break;
        case TYPE_IPADDR:
            typ = "IpAddr   ";
            break;
        case TYPE_COUNTER:
            typ = "Counter  ";
            break;
        case TYPE_GAUGE:
            typ = "Gauge    ";
            break;
        case TYPE_TIMETICKS:
            typ = "TimeTicks";
            break;
        case TYPE_OPAQUE:
            typ = "Opaque   ";
            size = 1;
            break;
        case TYPE_NULL:
            typ = "Null     ";
            break;
        case TYPE_COUNTER64:
            typ = "Counter64";
            break;
        case TYPE_BITSTRING:
            typ = "BitString";
            break;
        case TYPE_NSAPADDRESS:
            typ = "NsapAddr ";
            break;
        case TYPE_UNSIGNED32:
            typ = "Unsigned ";
            break;
        case TYPE_UINTEGER:
            typ = "UInteger ";
            break;
        case TYPE_INTEGER32:
            typ = "Integer32";
            break;
        default:
            typ = "         ";
            break;
        }
        fprintf(f, "%s-- %s %s %s(%ld)\n", leave_indent, acc, typ, tp->label, tp->subid);
        *ip = last_ipch;
        if (tp->tc_index >= 0)
            fprintf(f, "%s        Textual Convention: %s\n", leave_indent, tclist[tp->tc_index].descriptor);
        if (tp->enums) {
            struct enum_list *ep = tp->enums;
            int             cpos = 0, cmax = width - strlen(leave_indent) - 16;
            fprintf(f, "%s        Values: ", leave_indent);
            while (ep) {
                char            buf[80];
                int             bufw;
                if (ep != tp->enums)
                    fprintf(f, ", ");
                snprintf(buf, sizeof(buf), "%s(%d)", ep->label, ep->value);
                buf[ sizeof(buf)-1 ] = 0;
                cpos += (bufw = strlen(buf) + 2);
                if (cpos >= cmax) {
                    fprintf(f, "\n%s                ", leave_indent);
                    cpos = bufw;
                }
                fprintf(f, "%s", buf);
                ep = ep->next;
            }
            fprintf(f, "\n");
        }
        if (tp->ranges) {
            struct range_list *rp = tp->ranges;
            if (size)
                fprintf(f, "%s        Size: ", leave_indent);
            else fprintf(f, "%s        Range: ", leave_indent);
            while (rp) {
                if (rp != tp->ranges)
                    fprintf(f, " | ");
                print_range_value(f, tp->type, rp);
                rp = rp->next;
            }
            fprintf(f, "\n");
        }
    }
    *ip = last_ipch;
    strcat(leave_indent, "  |");
    leave_was_simple = tp->type != TYPE_OTHER;

    {
        int             i, j, count = 0;
        struct leave {
            oid             id;
            struct tree    *tp;
        }              *leaves, *lp;

        for (ntp = tp->child_list; ntp; ntp = ntp->next_peer)
            count++;
        if (count) {
            leaves = (struct leave *) calloc(count, sizeof(struct leave));
            if (!leaves)
                return;
            for (ntp = tp->child_list, count = 0; ntp;
                 ntp = ntp->next_peer) {
                for (i = 0, lp = leaves; i < count; i++, lp++)
                    if (lp->id >= ntp->subid)
                        break;
                for (j = count; j > i; j--)
                    leaves[j] = leaves[j - 1];
                lp->id = ntp->subid;
                lp->tp = ntp;
                count++;
            }
            for (i = 1, lp = leaves; i <= count; i++, lp++) {
                if (!leave_was_simple || lp->tp->type == 0)
                    fprintf(f, "%s\n", leave_indent);
                if (i == count)
                    ip[3] = ' ';
                print_mib_leaves(f, lp->tp, width);
            }
            free(leaves);
            leave_was_simple = 0;
        }
    }
    ip[1] = 0;
}

void print_mib_tree(FILE * f, struct tree *tp, int width)
{
    leave_indent[0] = ' ';
    leave_indent[1] = 0;
    leave_was_simple = 1;
    print_mib_leaves(f, tp, width);
}



static struct node * merge_parse_objectid(struct node *np, FILE * fp, char *name)
{
    struct node    *nnp;
    
    nnp = parse_objectid(fp, name);
    if (nnp) {

        
        
        struct node    *headp, *nextp;
        int             ncount = 0;
        nextp = headp = nnp;
        while (nnp->next) {
            nextp = nnp;
            ncount++;
            nnp = nnp->next;
        }

        np->label = nnp->label;
        np->subid = nnp->subid;
        np->modid = nnp->modid;
        np->parent = nnp->parent;
	if (nnp->filename != NULL) {
	  free(nnp->filename);
	}
        free(nnp);

        if (ncount) {
            nextp->next = np;
            np = headp;
        }
    } else {
        free_node(np);
        np = NULL;
    }

    return np;
}


static void tree_from_node(struct tree *tp, struct node *np)
{
    free_partial_tree(tp, FALSE);

    tp->label = np->label;
    np->label = NULL;
    tp->enums = np->enums;
    np->enums = NULL;
    tp->ranges = np->ranges;
    np->ranges = NULL;
    tp->indexes = np->indexes;
    np->indexes = NULL;
    tp->augments = np->augments;
    np->augments = NULL;
    tp->varbinds = np->varbinds;
    np->varbinds = NULL;
    tp->hint = np->hint;
    np->hint = NULL;
    tp->units = np->units;
    np->units = NULL;
    tp->description = np->description;
    np->description = NULL;
    tp->reference = np->reference;
    np->reference = NULL;
    tp->defaultValue = np->defaultValue;
    np->defaultValue = NULL;
    tp->subid = np->subid;
    tp->tc_index = np->tc_index;
    tp->type = translation_table[np->type];
    tp->access = np->access;
    tp->status = np->status;

    set_function(tp);
}


