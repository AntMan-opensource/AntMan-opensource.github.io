


















static const char copyright[] _U_ = "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000\n The Regents of the University of California.  All rights reserved.\n"                                                                                                     static int Bflag;







































































































static int64_t Cflag;			

static long Cflag;			

static int Cflag_count;			

static int Dflag;			


static char *remote_interfaces_source;	



extern int dflag;
int dflag;				
static int Gflag;			
static int Gflag_count;			
static time_t Gflag_time;		
static int Lflag;			
static int Iflag;			

static int Jflag;			
static int jflag = -1;			

static int lflag;			
static int pflag;			

static int Qflag = -1;			


static int Uflag;			

static int Wflag;			
static int WflagChars;
static char *zflag = NULL;		
static int timeout = 1000;		

static int immediate_mode;

static int count_mode;

static int infodelay;
static int infoprint;

char *program_name;


static void (*setsignal (int sig, void (*func)(int)))(int);
static void cleanup(int);
static void child_cleanup(int);
static void print_version(FILE *);
static void print_usage(FILE *);

static void print_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
static void dump_packet_and_trunc(u_char *, const struct pcap_pkthdr *, const u_char *);
static void dump_packet(u_char *, const struct pcap_pkthdr *, const u_char *);


static void requestinfo(int);



static void flushpcap(int);



    static HANDLE timer_handle = INVALID_HANDLE_VALUE;
    static void CALLBACK verbose_stats_dump(PVOID param, BOOLEAN timer_fired);

  static void verbose_stats_dump(int sig);


static void info(int);
static u_int packets_captured;


static const struct tok status_flags[] = {

	{ PCAP_IF_UP,       "Up"       },   { PCAP_IF_RUNNING,  "Running"  },  { PCAP_IF_LOOPBACK, "Loopback" },  { PCAP_IF_WIRELESS, "Wireless" },  { 0, NULL }








};


static pcap_t *pd;
static pcap_dumper_t *pdd = NULL;

static int supports_monitor_mode;

extern int optind;
extern int opterr;
extern char *optarg;

struct dump_info {
	char	*WFileName;
	char	*CurrentFileName;
	pcap_t	*pd;
	pcap_dumper_t *pdd;
	netdissect_options *ndo;

	int	dirfd;

};




__declspec(dllimport)

extern  void pcap_set_parser_debug(int);



static void pcap_set_parser_debug(int value)
{

	extern int pcap_debug;

	pcap_debug = value;

	extern int yydebug;

	yydebug = value;

}







__declspec(dllimport)

extern  void pcap_set_optimizer_debug(int);



static void NORETURN exit_tcpdump(const int status)
{
	nd_cleanup();
	exit(status);
}


static void NORETURN PRINTFLIKE(1, 2)
error(FORMAT_STRING(const char *fmt), ...)
{
	va_list ap;

	(void)fprintf(stderr, "%s: ", program_name);
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
	exit_tcpdump(S_ERR_HOST_PROGRAM);
	
}


static void PRINTFLIKE(1, 2)
warning(FORMAT_STRING(const char *fmt), ...)
{
	va_list ap;

	(void)fprintf(stderr, "%s: WARNING: ", program_name);
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
}


static void NORETURN show_tstamp_types_and_exit(pcap_t *pc, const char *device)
{
	int n_tstamp_types;
	int *tstamp_types = 0;
	const char *tstamp_type_name;
	int i;

	n_tstamp_types = pcap_list_tstamp_types(pc, &tstamp_types);
	if (n_tstamp_types < 0)
		error("%s", pcap_geterr(pc));

	if (n_tstamp_types == 0) {
		fprintf(stderr, "Time stamp type cannot be set for %s\n", device);
		exit_tcpdump(S_SUCCESS);
	}
	fprintf(stdout, "Time stamp types for %s (use option -j to set):\n", device);
	for (i = 0; i < n_tstamp_types; i++) {
		tstamp_type_name = pcap_tstamp_type_val_to_name(tstamp_types[i]);
		if (tstamp_type_name != NULL) {
			(void) fprintf(stdout, "  %s (%s)\n", tstamp_type_name, pcap_tstamp_type_val_to_description(tstamp_types[i]));
		} else {
			(void) fprintf(stdout, "  %d\n", tstamp_types[i]);
		}
	}
	pcap_free_tstamp_types(tstamp_types);
	exit_tcpdump(S_SUCCESS);
}


static void NORETURN show_dlts_and_exit(pcap_t *pc, const char *device)
{
	int n_dlts, i;
	int *dlts = 0;
	const char *dlt_name;

	n_dlts = pcap_list_datalinks(pc, &dlts);
	if (n_dlts < 0)
		error("%s", pcap_geterr(pc));
	else if (n_dlts == 0 || !dlts)
		error("No data link types.");

	
	(void) fprintf(stdout, "Data link types for ");
	if (supports_monitor_mode)
		(void) fprintf(stdout, "%s %s", device, Iflag ? "when in monitor mode" : "when not in monitor mode");

	else (void) fprintf(stdout, "%s", device);

	(void) fprintf(stdout, " (use option -y to set):\n");

	for (i = 0; i < n_dlts; i++) {
		dlt_name = pcap_datalink_val_to_name(dlts[i]);
		if (dlt_name != NULL) {
			(void) fprintf(stdout, "  %s (%s)", dlt_name, pcap_datalink_val_to_description(dlts[i]));

			
			if (!has_printer(dlts[i]))
				(void) fprintf(stdout, " (printing not supported)");
			fprintf(stdout, "\n");
		} else {
			(void) fprintf(stdout, "  DLT %d (printing not supported)\n", dlts[i]);
		}
	}

	pcap_free_datalinks(dlts);

	exit_tcpdump(S_SUCCESS);
}


static void NORETURN show_devices_and_exit(void)
{
	pcap_if_t *dev, *devlist;
	char ebuf[PCAP_ERRBUF_SIZE];
	int i;

	if (pcap_findalldevs(&devlist, ebuf) < 0)
		error("%s", ebuf);
	for (i = 0, dev = devlist; dev != NULL; i++, dev = dev->next) {
		printf("%d.%s", i+1, dev->name);
		if (dev->description != NULL)
			printf(" (%s)", dev->description);
		if (dev->flags != 0) {
			printf(" [");
			printf("%s", bittok2str(status_flags, "none", dev->flags));

			if (dev->flags & PCAP_IF_WIRELESS) {
				switch (dev->flags & PCAP_IF_CONNECTION_STATUS) {

				case PCAP_IF_CONNECTION_STATUS_UNKNOWN:
					printf(", Association status unknown");
					break;

				case PCAP_IF_CONNECTION_STATUS_CONNECTED:
					printf(", Associated");
					break;

				case PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
					printf(", Not associated");
					break;

				case PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE:
					break;
				}
			} else {
				switch (dev->flags & PCAP_IF_CONNECTION_STATUS) {

				case PCAP_IF_CONNECTION_STATUS_UNKNOWN:
					printf(", Connection status unknown");
					break;

				case PCAP_IF_CONNECTION_STATUS_CONNECTED:
					printf(", Connected");
					break;

				case PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
					printf(", Disconnected");
					break;

				case PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE:
					break;
				}
			}

			printf("]");
		}
		printf("\n");
	}
	pcap_freealldevs(devlist);
	exit_tcpdump(S_SUCCESS);
}



static void NORETURN show_remote_devices_and_exit(void)
{
	pcap_if_t *dev, *devlist;
	char ebuf[PCAP_ERRBUF_SIZE];
	int i;

	if (pcap_findalldevs_ex(remote_interfaces_source, NULL, &devlist, ebuf) < 0)
		error("%s", ebuf);
	for (i = 0, dev = devlist; dev != NULL; i++, dev = dev->next) {
		printf("%d.%s", i+1, dev->name);
		if (dev->description != NULL)
			printf(" (%s)", dev->description);
		if (dev->flags != 0)
			printf(" [%s]", bittok2str(status_flags, "none", dev->flags));
		printf("\n");
	}
	pcap_freealldevs(devlist);
	exit_tcpdump(S_SUCCESS);
}



































































static const struct option longopts[] = {

	{ "buffer-size", required_argument, NULL, 'B' },  { "list-interfaces", no_argument, NULL, 'D' },  { "list-remote-interfaces", required_argument, NULL, OPTION_LIST_REMOTE_INTERFACES },  { "help", no_argument, NULL, 'h' }, { "interface", required_argument, NULL, 'i' },  { "monitor-mode", no_argument, NULL, 'I' },   { "time-stamp-type", required_argument, NULL, 'j' }, { "list-time-stamp-types", no_argument, NULL, 'J' },   { "micro", no_argument, NULL, OPTION_TSTAMP_MICRO}, { "nano", no_argument, NULL, OPTION_TSTAMP_NANO}, { "time-stamp-precision", required_argument, NULL, OPTION_TSTAMP_PRECISION},  { "dont-verify-checksums", no_argument, NULL, 'K' }, { "list-data-link-types", no_argument, NULL, 'L' }, { "no-optimize", no_argument, NULL, 'O' }, { "no-promiscuous-mode", no_argument, NULL, 'p' },  { "direction", required_argument, NULL, 'Q' },  { "snapshot-length", required_argument, NULL, 's' }, { "absolute-tcp-sequence-numbers", no_argument, NULL, 'S' },  { "packet-buffered", no_argument, NULL, 'U' },  { "linktype", required_argument, NULL, 'y' },  { "immediate-mode", no_argument, NULL, OPTION_IMMEDIATE_MODE },   { "debug-filter-parser", no_argument, NULL, 'Y' },  { "relinquish-privileges", required_argument, NULL, 'Z' }, { "count", no_argument, NULL, OPTION_COUNT }, { "fp-type", no_argument, NULL, OPTION_FP_TYPE }, { "number", no_argument, NULL, '#' }, { "print", no_argument, NULL, OPTION_PRINT }, { "print-sampling", required_argument, NULL, OPTION_PRINT_SAMPLING }, { "version", no_argument, NULL, OPTION_VERSION }, { NULL, 0, NULL, 0 }













































};















static void droproot(const char *username, const char *chroot_dir)
{
	struct passwd *pw = NULL;

	if (chroot_dir && !username)
		error("Chroot without dropping root is insecure");

	pw = getpwnam(username);
	if (pw) {
		if (chroot_dir) {
			if (chroot(chroot_dir) != 0 || chdir ("/") != 0)
				error("Couldn't chroot/chdir to '%.64s': %s", chroot_dir, pcap_strerror(errno));
		}

		{
			int ret = capng_change_id(pw->pw_uid, pw->pw_gid, CAPNG_NO_FLAG);
			if (ret < 0)
				error("capng_change_id(): return %d\n", ret);
			else fprintf(stderr, "dropped privs to %s\n", username);
		}

		if (initgroups(pw->pw_name, pw->pw_gid) != 0 || setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0)
			error("Couldn't change to '%.32s' uid=%lu gid=%lu: %s", username, (unsigned long)pw->pw_uid, (unsigned long)pw->pw_gid, pcap_strerror(errno));



		else {
			fprintf(stderr, "dropped privs to %s\n", username);
		}

	} else error("Couldn't find user '%.32s'", username);

	
DIAG_OFF_ASSIGN_ENUM capng_updatev( CAPNG_DROP, CAPNG_EFFECTIVE | CAPNG_PERMITTED, CAP_SETUID, CAP_SETGID, CAP_SYS_CHROOT, -1);






DIAG_ON_ASSIGN_ENUM capng_apply(CAPNG_SELECT_BOTH);


}


static int getWflagChars(int x)
{
	int c = 0;

	x -= 1;
	while (x > 0) {
		c += 1;
		x /= 10;
	}

	return c;
}


static void MakeFilename(char *buffer, char *orig_name, int cnt, int max_chars)
{
        char *filename = malloc(PATH_MAX + 1);
        if (filename == NULL)
            error("%s: malloc", __func__);

        
        if (Gflag != 0) {
          struct tm *local_tm;

          
          if ((local_tm = localtime(&Gflag_time)) == NULL) {
                  error("%s: localtime", __func__);
          }

          
          strftime(filename, PATH_MAX, orig_name, local_tm);
        } else {
          strncpy(filename, orig_name, PATH_MAX);
        }

	if (cnt == 0 && max_chars == 0)
		strncpy(buffer, filename, PATH_MAX + 1);
	else if (snprintf(buffer, PATH_MAX + 1, "%s%0*d", filename, max_chars, cnt) > PATH_MAX)
                  
                  error("too many output files or filename is too long (> %d)", PATH_MAX);
        free(filename);
}

static char * get_next_file(FILE *VFile, char *ptr)
{
	char *ret;
	size_t len;

	ret = fgets(ptr, PATH_MAX, VFile);
	if (!ret)
		return NULL;

	len = strlen (ptr);
	if (len > 0 && ptr[len - 1] == '\n')
		ptr[len - 1] = '\0';

	return ret;
}


static cap_channel_t * capdns_setup(void)
{
	cap_channel_t *capcas, *capdnsloc;
	const char *types[1];
	int families[2];

	capcas = cap_init();
	if (capcas == NULL)
		error("unable to create casper process");
	capdnsloc = cap_service_open(capcas, "system.dns");
	
	cap_close(capcas);
	if (capdnsloc == NULL)
		error("unable to open system.dns service");
	
	types[0] = "ADDR";
	if (cap_dns_type_limit(capdnsloc, types, 1) < 0)
		error("unable to limit access to system.dns service");
	families[0] = AF_INET;
	families[1] = AF_INET6;
	if (cap_dns_family_limit(capdnsloc, families, 2) < 0)
		error("unable to limit access to system.dns service");

	return (capdnsloc);
}



static int tstamp_precision_from_string(const char *precision)
{
	if (strncmp(precision, "nano", strlen("nano")) == 0)
		return PCAP_TSTAMP_PRECISION_NANO;

	if (strncmp(precision, "micro", strlen("micro")) == 0)
		return PCAP_TSTAMP_PRECISION_MICRO;

	return -EINVAL;
}

static const char * tstamp_precision_to_string(int precision)
{
	switch (precision) {

	case PCAP_TSTAMP_PRECISION_MICRO:
		return "micro";

	case PCAP_TSTAMP_PRECISION_NANO:
		return "nano";

	default:
		return "unknown";
	}
}




static void set_dumper_capsicum_rights(pcap_dumper_t *p)
{
	int fd = fileno(pcap_dump_file(p));
	cap_rights_t rights;

	cap_rights_init(&rights, CAP_SEEK, CAP_WRITE, CAP_FCNTL);
	if (cap_rights_limit(fd, &rights) < 0 && errno != ENOSYS) {
		error("unable to limit dump descriptor");
	}
	if (cap_fcntls_limit(fd, CAP_FCNTL_GETFL) < 0 && errno != ENOSYS) {
		error("unable to limit dump descriptor fcntls");
	}
}



static char * copy_argv(char **argv)
{
	char **p;
	size_t len = 0;
	char *buf;
	char *src, *dst;

	p = argv;
	if (*p == NULL)
		return 0;

	while (*p)
		len += strlen(*p++) + 1;

	buf = (char *)malloc(len);
	if (buf == NULL)
		error("%s: malloc", __func__);

	p = argv;
	dst = buf;
	while ((src = *p++) != NULL) {
		while ((*dst++ = *src++) != '\0')
			;
		dst[-1] = ' ';
	}
	dst[-1] = '\0';

	return buf;
}






static char * read_infile(char *fname)
{
	int i, fd;
	ssize_t cc;
	char *cp;
	our_statb buf;

	fd = open(fname, O_RDONLY|O_BINARY);
	if (fd < 0)
		error("can't open %s: %s", fname, pcap_strerror(errno));

	if (our_fstat(fd, &buf) < 0)
		error("can't stat %s: %s", fname, pcap_strerror(errno));

	
	if (buf.st_size > INT_MAX)
		error("%s is too large", fname);

	cp = malloc((u_int)buf.st_size + 1);
	if (cp == NULL)
		error("malloc(%d) for %s: %s", (u_int)buf.st_size + 1, fname, pcap_strerror(errno));
	cc = read(fd, cp, (u_int)buf.st_size);
	if (cc < 0)
		error("read %s: %s", fname, pcap_strerror(errno));
	if (cc != buf.st_size)
		error("short read %s (%d != %d)", fname, (int) cc, (int)buf.st_size);

	close(fd);
	
	for (i = 0; i < cc; i++) {
		if (cp[i] == '#')
			while (i < cc && cp[i] != '\n')
				cp[i++] = ' ';
	}
	cp[cc] = '\0';
	return (cp);
}


static long parse_interface_number(const char *device)
{
	const char *p;
	long devnum;
	char *end;

	
	p = strchr(device, ':');
	if (p != NULL) {
		
		p++;	
		if (strncmp(p, "//", 2) == 0) {
			
			p += 2;	
			p = strchr(p, '/');
			if (p != NULL) {
				
				device = p + 1;
			}
		}
	}
	devnum = strtol(device, &end, 10);
	if (device != end && *end == '\0') {
		
		if (devnum <= 0) {
			
			error("Invalid adapter index");
		}
		return (devnum);
	} else {
		
		return (-1);
	}
}

static char * find_interface_by_number(const char *url  _U_  , long devnum)




{
	pcap_if_t *dev, *devlist;
	long i;
	char ebuf[PCAP_ERRBUF_SIZE];
	char *device;

	const char *endp;
	char *host_url;

	int status;


	
	endp = strchr(url, ':');
	if (endp != NULL) {
		
		endp++;	
		if (strncmp(endp, "//", 2) == 0) {
			
			endp += 2;	
			endp = strchr(endp, '/');
		} else endp = NULL;
	}
	if (endp != NULL) {
		
		endp++;	
		host_url = malloc(endp - url + 1);
		if (host_url == NULL && (endp - url + 1) > 0)
			error("Invalid allocation for host");

		memcpy(host_url, url, endp - url);
		host_url[endp - url] = '\0';
		status = pcap_findalldevs_ex(host_url, NULL, &devlist, ebuf);
		free(host_url);
	} else  status = pcap_findalldevs(&devlist, ebuf);

	if (status < 0)
		error("%s", ebuf);
	
	for (i = 0, dev = devlist; i < devnum-1 && dev != NULL;
	    i++, dev = dev->next)
		;
	if (dev == NULL)
		error("Invalid adapter index");
	device = strdup(dev->name);
	pcap_freealldevs(devlist);
	return (device);
}




static char rpcap_prefix[] = "rpcap://";
static char rpcap_ssl_prefix[] = "rpcaps://";


static pcap_t * open_interface(const char *device, netdissect_options *ndo, char *ebuf)
{
	pcap_t *pc;

	int status;
	char *cp;



	
	if (strncmp(device, rpcap_prefix, sizeof(rpcap_prefix) - 1) == 0 || strncmp(device, rpcap_ssl_prefix, sizeof(rpcap_ssl_prefix) - 1) == 0) {
		
		*ebuf = '\0';
		pc = pcap_open(device, ndo->ndo_snaplen, pflag ? 0 : PCAP_OPENFLAG_PROMISCUOUS, timeout, NULL, ebuf);

		if (pc == NULL) {
			
			if (strstr(ebuf, "No such device") != NULL || strstr(ebuf, "The system cannot find the device specified") != NULL)
				return (NULL);
			error("%s", ebuf);
		}
		if (*ebuf)
			warning("%s", ebuf);
		return (pc);
	}



	pc = pcap_create(device, ebuf);
	if (pc == NULL) {
		
		if (strstr(ebuf, "No such device") != NULL)
			return (NULL);
		error("%s", ebuf);
	}

	if (Jflag)
		show_tstamp_types_and_exit(pc, device);


	status = pcap_set_tstamp_precision(pc, ndo->ndo_tstamp_precision);
	if (status != 0)
		error("%s: Can't set %ssecond time stamp precision: %s", device, tstamp_precision_to_string(ndo->ndo_tstamp_precision), pcap_statustostr(status));





	if (immediate_mode) {
		status = pcap_set_immediate_mode(pc, 1);
		if (status != 0)
			error("%s: Can't set immediate mode: %s", device, pcap_statustostr(status));
	}

	
	if (pcap_can_set_rfmon(pc) == 1)
		supports_monitor_mode = 1;
	else supports_monitor_mode = 0;
	if (ndo->ndo_snaplen != 0) {
		
		status = pcap_set_snaplen(pc, ndo->ndo_snaplen);
		if (status != 0)
			error("%s: Can't set snapshot length: %s", device, pcap_statustostr(status));
	}
	status = pcap_set_promisc(pc, !pflag);
	if (status != 0)
		error("%s: Can't set promiscuous mode: %s", device, pcap_statustostr(status));
	if (Iflag) {
		status = pcap_set_rfmon(pc, 1);
		if (status != 0)
			error("%s: Can't set monitor mode: %s", device, pcap_statustostr(status));
	}
	status = pcap_set_timeout(pc, timeout);
	if (status != 0)
		error("%s: pcap_set_timeout failed: %s", device, pcap_statustostr(status));
	if (Bflag != 0) {
		status = pcap_set_buffer_size(pc, Bflag);
		if (status != 0)
			error("%s: Can't set buffer size: %s", device, pcap_statustostr(status));
	}

	if (jflag != -1) {
		status = pcap_set_tstamp_type(pc, jflag);
		if (status < 0)
			error("%s: Can't set time stamp type: %s", device, pcap_statustostr(status));
		else if (status > 0)
			warning("When trying to set timestamp type '%s' on %s: %s", pcap_tstamp_type_val_to_name(jflag), device, pcap_statustostr(status));

	}

	status = pcap_activate(pc);
	if (status < 0) {
		
		cp = pcap_geterr(pc);
		if (status == PCAP_ERROR)
			error("%s", cp);
		else if (status == PCAP_ERROR_NO_SUCH_DEVICE) {
			
			snprintf(ebuf, PCAP_ERRBUF_SIZE, "%s: %s\n(%s)", device, pcap_statustostr(status), cp);
		} else if (status == PCAP_ERROR_PERM_DENIED && *cp != '\0')
			error("%s: %s\n(%s)", device, pcap_statustostr(status), cp);

		else if (status == PCAP_ERROR_RFMON_NOTSUP && strncmp(device, "wlan", 4) == 0) {
			char parent[8], newdev[8];
			char sysctl[32];
			size_t s = sizeof(parent);

			snprintf(sysctl, sizeof(sysctl), "net.wlan.%d.%%parent", atoi(device + 4));
			sysctlbyname(sysctl, parent, &s, NULL, 0);
			strlcpy(newdev, device, sizeof(newdev));
			
			
			newdev[strlen(newdev)-1]++;
			error("%s is not a monitor mode VAP\n" "To create a new monitor mode VAP use:\n" "  ifconfig %s create wlandev %s wlanmode monitor\n" "and use %s as the tcpdump interface", device, newdev, parent, newdev);



		}

		else error("%s: %s", device, pcap_statustostr(status));

		pcap_close(pc);
		return (NULL);
	} else if (status > 0) {
		
		cp = pcap_geterr(pc);
		if (status == PCAP_WARNING)
			warning("%s", cp);
		else if (status == PCAP_WARNING_PROMISC_NOTSUP && *cp != '\0')
			warning("%s: %s\n(%s)", device, pcap_statustostr(status), cp);
		else warning("%s: %s", device, pcap_statustostr(status));

	}

	if (Qflag != -1) {
		status = pcap_setdirection(pc, Qflag);
		if (status != 0)
			error("%s: pcap_setdirection() failed: %s", device,  pcap_geterr(pc));
		}


	*ebuf = '\0';
	
	if (ndo->ndo_snaplen == 0)
		ndo->ndo_snaplen = MAXIMUM_SNAPLEN;
	pc = pcap_open_live(device, ndo->ndo_snaplen, !pflag, timeout, ebuf);
	if (pc == NULL) {
		
		if (strstr(ebuf, "No such device") != NULL)
			return (NULL);
		error("%s", ebuf);
	}
	if (*ebuf)
		warning("%s", ebuf);


	return (pc);
}

int main(int argc, char **argv)
{
	int cnt, op, i;
	bpf_u_int32 localnet = 0, netmask = 0;
	char *cp, *infile, *cmdbuf, *device, *RFileName, *VFileName, *WFileName;
	char *endp;
	pcap_handler callback;
	int dlt;
	const char *dlt_name;
	struct bpf_program fcode;

	void (*oldhandler)(int);

	struct dump_info dumpinfo;
	u_char *pcap_userdata;
	char ebuf[PCAP_ERRBUF_SIZE];
	char VFileLine[PATH_MAX + 1];
	const char *username = NULL;

	const char *chroot_dir = NULL;

	char *ret = NULL;
	char *end;

	pcap_if_t *devlist;
	long devnum;

	int status;
	FILE *VFile;

	cap_rights_t rights;
	int cansandbox;

	int Oflag = 1;			
	int yflag_dlt = -1;
	const char *yflag_dlt_name = NULL;
	int print = 0;
	long Cflagmult;

	netdissect_options Ndo;
	netdissect_options *ndo = &Ndo;

	
	if (nd_init(ebuf, sizeof(ebuf)) == -1)
		error("%s", ebuf);

	memset(ndo, 0, sizeof(*ndo));
	ndo_set_function_pointers(ndo);

	cnt = -1;
	device = NULL;
	infile = NULL;
	RFileName = NULL;
	VFileName = NULL;
	VFile = NULL;
	WFileName = NULL;
	dlt = -1;
	if ((cp = strrchr(argv[0], PATH_SEPARATOR)) != NULL)
		ndo->program_name = program_name = cp + 1;
	else ndo->program_name = program_name = argv[0];


	if (pcap_wsockinit() != 0)
		error("Attempting to initialize Winsock failed");

	if (wsockinit() != 0)
		error("Attempting to initialize Winsock failed");


	
	if (abort_on_misalignment(ebuf, sizeof(ebuf)) < 0)
		error("%s", ebuf);

	while ( (op = getopt_long(argc, argv, SHORTOPTS, longopts, NULL)) != -1)
		switch (op) {

		case 'a':
			
			break;

		case 'A':
			++ndo->ndo_Aflag;
			break;

		case 'b':
			++ndo->ndo_bflag;
			break;


		case 'B':
			Bflag = atoi(optarg)*1024;
			if (Bflag <= 0)
				error("invalid packet buffer size %s", optarg);
			break;


		case 'c':
			cnt = atoi(optarg);
			if (cnt <= 0)
				error("invalid packet count %s", optarg);
			break;

		case 'C':
			errno = 0;

			Cflag = strtoint64_t(optarg, &endp, 10);

			Cflag = strtol(optarg, &endp, 10);

			if (endp == optarg || errno != 0 || Cflag <= 0)
				error("invalid file size %s", optarg);

			if (*endp == '\0') {
				
				Cflagmult = 1000000;
			} else {
				
				switch (*endp) {

				case 'k':
				case 'K':
					Cflagmult = 1024;
					break;

				case 'm':
				case 'M':
					Cflagmult = 1024*1024;
					break;

				case 'g':
				case 'G':
					Cflagmult = 1024*1024*1024;
					break;

				default:
					error("invalid file size %s", optarg);
				}

				
				endp++;
				if (*endp != '\0') {
					
					error("invalid file size %s", optarg);
				}
			}

			

			if (Cflag > INT64_T_CONSTANT(0x7fffffffffffffff) / Cflagmult)

			if (Cflag > LONG_MAX / Cflagmult)

				error("file size %s is too large", optarg);
			Cflag *= Cflagmult;
			break;

		case 'd':
			++dflag;
			break;


		case 'D':
			Dflag++;
			break;



		case OPTION_LIST_REMOTE_INTERFACES:
			remote_interfaces_source = optarg;
			break;


		case 'L':
			Lflag++;
			break;

		case 'e':
			++ndo->ndo_eflag;
			break;

		case 'E':

			warning("crypto code not compiled in");

			ndo->ndo_espsecret = optarg;
			break;

		case 'f':
			++ndo->ndo_fflag;
			break;

		case 'F':
			infile = optarg;
			break;

		case 'G':
			Gflag = atoi(optarg);
			if (Gflag < 0)
				error("invalid number of seconds %s", optarg);

                        
                        Gflag_count = 0;

			
			if ((Gflag_time = time(NULL)) == (time_t)-1) {
				error("%s: can't get current time: %s", __func__, pcap_strerror(errno));
			}
			break;

		case 'h':
			print_usage(stdout);
			exit_tcpdump(S_SUCCESS);
			break;

		case 'H':
			++ndo->ndo_Hflag;
			break;

		case 'i':
			device = optarg;
			break;


		case 'I':
			++Iflag;
			break;



		case 'j':
			jflag = pcap_tstamp_type_name_to_val(optarg);
			if (jflag < 0)
				error("invalid time stamp type %s", optarg);
			break;

		case 'J':
			Jflag++;
			break;


		case 'l':

			
			setvbuf(stdout, NULL, _IONBF, 0);


			setlinebuf(stdout);

			setvbuf(stdout, NULL, _IOLBF, 0);


			lflag = 1;
			break;

		case 'K':
			++ndo->ndo_Kflag;
			break;

		case 'm':
			if (nd_have_smi_support()) {
				if (nd_load_smi_module(optarg, ebuf, sizeof(ebuf)) == -1)
					error("%s", ebuf);
			} else {
				(void)fprintf(stderr, "%s: ignoring option `-m %s' ", program_name, optarg);
				(void)fprintf(stderr, "(no libsmi support)\n");
			}
			break;

		case 'M':
			

			warning("crypto code not compiled in");

			ndo->ndo_sigsecret = optarg;
			break;

		case 'n':
			++ndo->ndo_nflag;
			break;

		case 'N':
			++ndo->ndo_Nflag;
			break;

		case 'O':
			Oflag = 0;
			break;

		case 'p':
			++pflag;
			break;

		case 'q':
			++ndo->ndo_qflag;
			++ndo->ndo_suppress_default_print;
			break;


		case 'Q':
			if (ascii_strcasecmp(optarg, "in") == 0)
				Qflag = PCAP_D_IN;
			else if (ascii_strcasecmp(optarg, "out") == 0)
				Qflag = PCAP_D_OUT;
			else if (ascii_strcasecmp(optarg, "inout") == 0)
				Qflag = PCAP_D_INOUT;
			else error("unknown capture direction `%s'", optarg);
			break;


		case 'r':
			RFileName = optarg;
			break;

		case 's':
			ndo->ndo_snaplen = (int)strtol(optarg, &end, 0);
			if (optarg == end || *end != '\0' || ndo->ndo_snaplen < 0 || ndo->ndo_snaplen > MAXIMUM_SNAPLEN)
				error("invalid snaplen %s (must be >= 0 and <= %d)", optarg, MAXIMUM_SNAPLEN);
			break;

		case 'S':
			++ndo->ndo_Sflag;
			break;

		case 't':
			++ndo->ndo_tflag;
			break;

		case 'T':
			if (ascii_strcasecmp(optarg, "vat") == 0)
				ndo->ndo_packettype = PT_VAT;
			else if (ascii_strcasecmp(optarg, "wb") == 0)
				ndo->ndo_packettype = PT_WB;
			else if (ascii_strcasecmp(optarg, "rpc") == 0)
				ndo->ndo_packettype = PT_RPC;
			else if (ascii_strcasecmp(optarg, "rtp") == 0)
				ndo->ndo_packettype = PT_RTP;
			else if (ascii_strcasecmp(optarg, "rtcp") == 0)
				ndo->ndo_packettype = PT_RTCP;
			else if (ascii_strcasecmp(optarg, "snmp") == 0)
				ndo->ndo_packettype = PT_SNMP;
			else if (ascii_strcasecmp(optarg, "cnfp") == 0)
				ndo->ndo_packettype = PT_CNFP;
			else if (ascii_strcasecmp(optarg, "tftp") == 0)
				ndo->ndo_packettype = PT_TFTP;
			else if (ascii_strcasecmp(optarg, "aodv") == 0)
				ndo->ndo_packettype = PT_AODV;
			else if (ascii_strcasecmp(optarg, "carp") == 0)
				ndo->ndo_packettype = PT_CARP;
			else if (ascii_strcasecmp(optarg, "radius") == 0)
				ndo->ndo_packettype = PT_RADIUS;
			else if (ascii_strcasecmp(optarg, "zmtp1") == 0)
				ndo->ndo_packettype = PT_ZMTP1;
			else if (ascii_strcasecmp(optarg, "vxlan") == 0)
				ndo->ndo_packettype = PT_VXLAN;
			else if (ascii_strcasecmp(optarg, "pgm") == 0)
				ndo->ndo_packettype = PT_PGM;
			else if (ascii_strcasecmp(optarg, "pgm_zmtp1") == 0)
				ndo->ndo_packettype = PT_PGM_ZMTP1;
			else if (ascii_strcasecmp(optarg, "lmp") == 0)
				ndo->ndo_packettype = PT_LMP;
			else if (ascii_strcasecmp(optarg, "resp") == 0)
				ndo->ndo_packettype = PT_RESP;
			else if (ascii_strcasecmp(optarg, "ptp") == 0)
				ndo->ndo_packettype = PT_PTP;
			else if (ascii_strcasecmp(optarg, "someip") == 0)
				ndo->ndo_packettype = PT_SOMEIP;
			else if (ascii_strcasecmp(optarg, "domain") == 0)
				ndo->ndo_packettype = PT_DOMAIN;
			else if (ascii_strcasecmp(optarg, "quic") == 0)
				ndo->ndo_packettype = PT_QUIC;
			else error("unknown packet type `%s'", optarg);
			break;

		case 'u':
			++ndo->ndo_uflag;
			break;


		case 'U':
			++Uflag;
			break;


		case 'v':
			++ndo->ndo_vflag;
			break;

		case 'V':
			VFileName = optarg;
			break;

		case 'w':
			WFileName = optarg;
			break;

		case 'W':
			Wflag = atoi(optarg);
			if (Wflag <= 0)
				error("invalid number of output files %s", optarg);
			WflagChars = getWflagChars(Wflag);
			break;

		case 'x':
			++ndo->ndo_xflag;
			++ndo->ndo_suppress_default_print;
			break;

		case 'X':
			++ndo->ndo_Xflag;
			++ndo->ndo_suppress_default_print;
			break;

		case 'y':
			yflag_dlt_name = optarg;
			yflag_dlt = pcap_datalink_name_to_val(yflag_dlt_name);
			if (yflag_dlt < 0)
				error("invalid data link type %s", yflag_dlt_name);
			break;


		case 'Y':
			{
			
			pcap_set_parser_debug(1);
			}
			break;

		case 'z':
			zflag = optarg;
			break;

		case 'Z':
			username = optarg;
			break;

		case '#':
			ndo->ndo_packet_number = 1;
			break;

		case OPTION_VERSION:
			print_version(stdout);
			exit_tcpdump(S_SUCCESS);
			break;


		case OPTION_TSTAMP_PRECISION:
			ndo->ndo_tstamp_precision = tstamp_precision_from_string(optarg);
			if (ndo->ndo_tstamp_precision < 0)
				error("unsupported time stamp precision");
			break;



		case OPTION_IMMEDIATE_MODE:
			immediate_mode = 1;
			break;


		case OPTION_PRINT:
			print = 1;
			break;

		case OPTION_PRINT_SAMPLING:
			print = 1;
			++ndo->ndo_Sflag;
			ndo->ndo_print_sampling = atoi(optarg);
			if (ndo->ndo_print_sampling <= 0)
				error("invalid print sampling %s", optarg);
			break;


		case OPTION_TSTAMP_MICRO:
			ndo->ndo_tstamp_precision = PCAP_TSTAMP_PRECISION_MICRO;
			break;

		case OPTION_TSTAMP_NANO:
			ndo->ndo_tstamp_precision = PCAP_TSTAMP_PRECISION_NANO;
			break;


		case OPTION_FP_TYPE:
			
			float_type_check(0x4e93312d);
			return 0;

		case OPTION_COUNT:
			count_mode = 1;
			break;

		default:
			print_usage(stderr);
			exit_tcpdump(S_ERR_HOST_PROGRAM);
			
		}


	if (Dflag)
		show_devices_and_exit();


	if (remote_interfaces_source != NULL)
		show_remote_devices_and_exit();




		if (device != NULL && strncmp (device, "any", strlen("any")) == 0 && yflag_dlt == -1)

			yflag_dlt = DLT_LINUX_SLL2;


	switch (ndo->ndo_tflag) {

	case 0: 
	case 1: 
	case 2: 
	case 3: 
	case 4: 
	case 5: 
		break;

	default: 
		error("only -t, -tt, -ttt, -tttt and -ttttt are supported");
		break;
	}

	if (ndo->ndo_fflag != 0 && (VFileName != NULL || RFileName != NULL))
		error("-f can not be used with -V or -r");

	if (VFileName != NULL && RFileName != NULL)
		error("-V and -r are mutually exclusive.");

	
	if ((WFileName == NULL || print) && (isatty(1) || lflag))
		timeout = 100;


	
	if (getuid() == 0 || geteuid() == 0) {
		
		if (!chroot_dir)
			chroot_dir = WITH_CHROOT;
	}



	
	if (getuid() == 0 || geteuid() == 0) {
		
		if (!username)
			username = WITH_USER;
	}


	if (RFileName != NULL || VFileName != NULL) {
		

		
		if (setgid(getgid()) != 0 || setuid(getuid()) != 0 )
			fprintf(stderr, "Warning: setgid/setuid failed !\n");

		if (VFileName != NULL) {
			if (VFileName[0] == '-' && VFileName[1] == '\0')
				VFile = stdin;
			else VFile = fopen(VFileName, "r");

			if (VFile == NULL)
				error("Unable to open file: %s\n", pcap_strerror(errno));

			ret = get_next_file(VFile, VFileLine);
			if (!ret)
				error("Nothing in %s\n", VFileName);
			RFileName = VFileLine;
		}


		pd = pcap_open_offline_with_tstamp_precision(RFileName, ndo->ndo_tstamp_precision, ebuf);

		pd = pcap_open_offline(RFileName, ebuf);


		if (pd == NULL)
			error("%s", ebuf);

		cap_rights_init(&rights, CAP_READ);
		if (cap_rights_limit(fileno(pcap_file(pd)), &rights) < 0 && errno != ENOSYS) {
			error("unable to limit pcap descriptor");
		}

		dlt = pcap_datalink(pd);
		dlt_name = pcap_datalink_val_to_name(dlt);
		fprintf(stderr, "reading from file %s", RFileName);
		if (dlt_name == NULL) {
			fprintf(stderr, ", link-type %u", dlt);
		} else {
			fprintf(stderr, ", link-type %s (%s)", dlt_name, pcap_datalink_val_to_description(dlt));
		}
		fprintf(stderr, ", snapshot length %d\n", pcap_snapshot(pd));

		if (dlt == DLT_LINUX_SLL2)
			fprintf(stderr, "Warning: interface names might be incorrect\n");

	} else if (dflag && !device) {
		int dump_dlt = DLT_EN10MB;
		
		
		if (ndo->ndo_snaplen == 0)
			ndo->ndo_snaplen = MAXIMUM_SNAPLEN;
		
		if (yflag_dlt != -1)
			dump_dlt = yflag_dlt;
		else fprintf(stderr, "Warning: assuming Ethernet\n");
	        pd = pcap_open_dead(dump_dlt, ndo->ndo_snaplen);
	} else {
		
		if (device == NULL) {
			

			
			if (pcap_findalldevs(&devlist, ebuf) == -1)
				error("%s", ebuf);
			if (devlist == NULL)
				error("no interfaces available for capture");
			device = strdup(devlist->name);
			pcap_freealldevs(devlist);

			
			device = pcap_lookupdev(ebuf);
			if (device == NULL)
				error("%s", ebuf);

		}

		
		pd = open_interface(device, ndo, ebuf);
		if (pd == NULL) {
			

			devnum = parse_interface_number(device);
			if (devnum == -1) {
				
				error("%s", ebuf);
			}

			
			device = find_interface_by_number(device, devnum);
			pd = open_interface(device, ndo, ebuf);
			if (pd == NULL)
				error("%s", ebuf);

			
			error("%s", ebuf);

		}

		

		if (setgid(getgid()) != 0 || setuid(getuid()) != 0)
			fprintf(stderr, "Warning: setgid/setuid failed !\n");


		if(Bflag != 0)
			if(pcap_setbuff(pd, Bflag)==-1){
				error("%s", pcap_geterr(pd));
			}

		if (Lflag)
			show_dlts_and_exit(pd, device);
		if (yflag_dlt >= 0) {

			if (pcap_set_datalink(pd, yflag_dlt) < 0)
				error("%s", pcap_geterr(pd));

			
			if (yflag_dlt != pcap_datalink(pd)) {
				error("%s is not one of the DLTs supported by this device\n", yflag_dlt_name);
			}

			(void)fprintf(stderr, "%s: data link type %s\n", program_name, pcap_datalink_val_to_name(yflag_dlt));

			(void)fflush(stderr);
		}
		i = pcap_snapshot(pd);
		if (ndo->ndo_snaplen < i) {
			if (ndo->ndo_snaplen != 0)
				warning("snaplen raised from %d to %d", ndo->ndo_snaplen, i);
			ndo->ndo_snaplen = i;
		} else if (ndo->ndo_snaplen > i) {
			warning("snaplen lowered from %d to %d", ndo->ndo_snaplen, i);
			ndo->ndo_snaplen = i;
		}
                if(ndo->ndo_fflag != 0) {
                        if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
                                warning("foreign (-f) flag used but: %s", ebuf);
                        }
                }

	}
	if (infile)
		cmdbuf = read_infile(infile);
	else cmdbuf = copy_argv(&argv[optind]);


	pcap_set_optimizer_debug(dflag);

	if (pcap_compile(pd, &fcode, cmdbuf, Oflag, netmask) < 0)
		error("%s", pcap_geterr(pd));
	if (dflag) {
		bpf_dump(&fcode, dflag);
		pcap_close(pd);
		free(cmdbuf);
		pcap_freecode(&fcode);
		exit_tcpdump(S_SUCCESS);
	}


	if (!ndo->ndo_nflag)
		capdns = capdns_setup();


	init_print(ndo, localnet, netmask);


	(void)setsignal(SIGPIPE, cleanup);
	(void)setsignal(SIGTERM, cleanup);

	(void)setsignal(SIGINT, cleanup);

	(void)setsignal(SIGCHLD, child_cleanup);

	

	if ((oldhandler = setsignal(SIGHUP, cleanup)) != SIG_DFL)
		(void)setsignal(SIGHUP, oldhandler);



	

	if (getuid() == 0 || geteuid() == 0) {

		
		capng_clear(CAPNG_SELECT_BOTH);
		if (username) {
DIAG_OFF_ASSIGN_ENUM capng_updatev( CAPNG_ADD, CAPNG_PERMITTED | CAPNG_EFFECTIVE, CAP_SETUID, CAP_SETGID, -1);





DIAG_ON_ASSIGN_ENUM }
		if (chroot_dir) {
DIAG_OFF_ASSIGN_ENUM capng_update( CAPNG_ADD, CAPNG_PERMITTED | CAPNG_EFFECTIVE, CAP_SYS_CHROOT );




DIAG_ON_ASSIGN_ENUM }

		if (WFileName) {
DIAG_OFF_ASSIGN_ENUM capng_update( CAPNG_ADD, CAPNG_PERMITTED | CAPNG_EFFECTIVE, CAP_DAC_OVERRIDE );




DIAG_ON_ASSIGN_ENUM }
		capng_apply(CAPNG_SELECT_BOTH);

		if (username || chroot_dir)
			droproot(username, chroot_dir);

	}


	if (pcap_setfilter(pd, &fcode) < 0)
		error("%s", pcap_geterr(pd));

	if (RFileName == NULL && VFileName == NULL && pcap_fileno(pd) != -1) {
		static const unsigned long cmds[] = { BIOCGSTATS, BIOCROTZBUF };

		
		cap_rights_init(&rights, CAP_IOCTL, CAP_READ, CAP_EVENT);
		if (cap_rights_limit(pcap_fileno(pd), &rights) < 0 && errno != ENOSYS) {
			error("unable to limit pcap descriptor");
		}
		if (cap_ioctls_limit(pcap_fileno(pd), cmds, sizeof(cmds) / sizeof(cmds[0])) < 0 && errno != ENOSYS) {
			error("unable to limit ioctls on pcap descriptor");
		}
	}

	if (WFileName) {
		
		dumpinfo.CurrentFileName = (char *)malloc(PATH_MAX + 1);

		if (dumpinfo.CurrentFileName == NULL)
			error("malloc of dumpinfo.CurrentFileName");

		
		if (Cflag != 0)
		  MakeFilename(dumpinfo.CurrentFileName, WFileName, 0, WflagChars);
		else MakeFilename(dumpinfo.CurrentFileName, WFileName, 0, 0);

		pdd = pcap_dump_open(pd, dumpinfo.CurrentFileName);

		
		capng_update( CAPNG_DROP, (Cflag || Gflag ? 0 : CAPNG_PERMITTED)

				| CAPNG_EFFECTIVE, CAP_DAC_OVERRIDE );

		capng_apply(CAPNG_SELECT_BOTH);

		if (pdd == NULL)
			error("%s", pcap_geterr(pd));

		set_dumper_capsicum_rights(pdd);

		if (Cflag != 0 || Gflag != 0) {

			
			char *WFileName_copy;

			if ((WFileName_copy = strdup(WFileName)) == NULL) {
				error("Unable to allocate memory for file %s", WFileName);
			}
			DIAG_OFF_C11_EXTENSIONS dumpinfo.WFileName = strdup(basename(WFileName_copy));
			DIAG_ON_C11_EXTENSIONS if (dumpinfo.WFileName == NULL) {
				error("Unable to allocate memory for file %s", WFileName);
			}
			free(WFileName_copy);

			if ((WFileName_copy = strdup(WFileName)) == NULL) {
				error("Unable to allocate memory for file %s", WFileName);
			}
			DIAG_OFF_C11_EXTENSIONS char *WFileName_dirname = dirname(WFileName_copy);
			DIAG_ON_C11_EXTENSIONS dumpinfo.dirfd = open(WFileName_dirname, O_DIRECTORY | O_RDONLY);

			if (dumpinfo.dirfd < 0) {
				error("unable to open directory %s", WFileName_dirname);
			}
			free(WFileName_dirname);
			free(WFileName_copy);

			cap_rights_init(&rights, CAP_CREATE, CAP_FCNTL, CAP_FTRUNCATE, CAP_LOOKUP, CAP_SEEK, CAP_WRITE);
			if (cap_rights_limit(dumpinfo.dirfd, &rights) < 0 && errno != ENOSYS) {
				error("unable to limit directory rights");
			}
			if (cap_fcntls_limit(dumpinfo.dirfd, CAP_FCNTL_GETFL) < 0 && errno != ENOSYS) {
				error("unable to limit dump descriptor fcntls");
			}

			dumpinfo.WFileName = WFileName;

			callback = dump_packet_and_trunc;
			dumpinfo.pd = pd;
			dumpinfo.pdd = pdd;
			pcap_userdata = (u_char *)&dumpinfo;
		} else {
			callback = dump_packet;
			dumpinfo.WFileName = WFileName;
			dumpinfo.pd = pd;
			dumpinfo.pdd = pdd;
			pcap_userdata = (u_char *)&dumpinfo;
		}
		if (print) {
			dlt = pcap_datalink(pd);
			ndo->ndo_if_printer = get_if_printer(dlt);
			dumpinfo.ndo = ndo;
		} else dumpinfo.ndo = NULL;


		if (Uflag)
			pcap_dump_flush(pdd);

	} else {
		dlt = pcap_datalink(pd);
		ndo->ndo_if_printer = get_if_printer(dlt);
		callback = print_packet;
		pcap_userdata = (u_char *)ndo;
	}


	
	if (RFileName == NULL)
		(void)setsignal(SIGNAL_REQ_INFO, requestinfo);


	(void)setsignal(SIGNAL_FLUSH_PCAP, flushpcap);


	if (ndo->ndo_vflag > 0 && WFileName && RFileName == NULL && !print) {
		

		
		CreateTimerQueueTimer(&timer_handle, NULL, verbose_stats_dump, NULL, 1000, 1000, WT_EXECUTEDEFAULT|WT_EXECUTELONGFUNCTION);

		setvbuf(stderr, NULL, _IONBF, 0);

		
		struct itimerval timer;
		(void)setsignal(SIGALRM, verbose_stats_dump);
		timer.it_interval.tv_sec = 1;
		timer.it_interval.tv_usec = 0;
		timer.it_value.tv_sec = 1;
		timer.it_value.tv_usec = 1;
		setitimer(ITIMER_REAL, &timer, NULL);

	}

	if (RFileName == NULL) {
		
		if (!ndo->ndo_vflag && !WFileName) {
			(void)fprintf(stderr, "%s: verbose output suppressed, use -v[v]... for full protocol decode\n", program_name);

		} else (void)fprintf(stderr, "%s: ", program_name);
		dlt = pcap_datalink(pd);
		dlt_name = pcap_datalink_val_to_name(dlt);
		(void)fprintf(stderr, "listening on %s", device);
		if (dlt_name == NULL) {
			(void)fprintf(stderr, ", link-type %u", dlt);
		} else {
			(void)fprintf(stderr, ", link-type %s (%s)", dlt_name, pcap_datalink_val_to_description(dlt));
		}
		(void)fprintf(stderr, ", snapshot length %d bytes\n", ndo->ndo_snaplen);
		(void)fflush(stderr);
	}


	cansandbox = (VFileName == NULL && zflag == NULL);

	cansandbox = (cansandbox && (ndo->ndo_nflag || capdns != NULL));

	cansandbox = (cansandbox && ndo->ndo_nflag);

	if (cansandbox && cap_enter() < 0 && errno != ENOSYS)
		error("unable to enter the capability mode");


	do {
		status = pcap_loop(pd, cnt, callback, pcap_userdata);
		if (WFileName == NULL) {
			
			if (status == -2) {
				
				putchar('\n');
			}
			(void)fflush(stdout);
		}
                if (status == -2) {
			
			VFileName = NULL;
			ret = NULL;
		}
		if (status == -1) {
			
			(void)fprintf(stderr, "%s: pcap_loop: %s\n", program_name, pcap_geterr(pd));
		}
		if (RFileName == NULL) {
			
			info(1);
		}
		pcap_close(pd);
		if (VFileName != NULL) {
			ret = get_next_file(VFile, VFileLine);
			if (ret) {
				int new_dlt;

				RFileName = VFileLine;
				pd = pcap_open_offline(RFileName, ebuf);
				if (pd == NULL)
					error("%s", ebuf);

				cap_rights_init(&rights, CAP_READ);
				if (cap_rights_limit(fileno(pcap_file(pd)), &rights) < 0 && errno != ENOSYS) {
					error("unable to limit pcap descriptor");
				}

				new_dlt = pcap_datalink(pd);
				if (new_dlt != dlt) {
					
					if (WFileName != NULL) {
						
						error("%s: new dlt does not match original", RFileName);
					}

					
					dlt = new_dlt;
					ndo->ndo_if_printer = get_if_printer(dlt);
					if (pcap_compile(pd, &fcode, cmdbuf, Oflag, netmask) < 0)
						error("%s", pcap_geterr(pd));
				}

				
				if (pcap_setfilter(pd, &fcode) < 0)
					error("%s", pcap_geterr(pd));

				
				dlt_name = pcap_datalink_val_to_name(dlt);
				fprintf(stderr, "reading from file %s", RFileName);
				if (dlt_name == NULL) {
					fprintf(stderr, ", link-type %u", dlt);
				} else {
					fprintf(stderr, ", link-type %s (%s)", dlt_name, pcap_datalink_val_to_description(dlt));

				}
				fprintf(stderr, ", snapshot length %d\n", pcap_snapshot(pd));
			}
		}
	}
	while (ret != NULL);

	if (count_mode && RFileName != NULL)
		fprintf(stdout, "%u packet%s\n", packets_captured, PLURAL_SUFFIX(packets_captured));

	free(cmdbuf);
	pcap_freecode(&fcode);
	exit_tcpdump(status == -1 ? S_ERR_HOST_PROGRAM : S_SUCCESS);
}


static void (*setsignal (int sig, void (*func)(int)))(int)
{

	return (signal(sig, func));

	struct sigaction old, new;

	memset(&new, 0, sizeof(new));
	new.sa_handler = func;
	if ((sig == SIGCHLD)

		|| (sig == SIGNAL_REQ_INFO)


		|| (sig == SIGNAL_FLUSH_PCAP)

		)
		new.sa_flags = SA_RESTART;
	if (sigaction(sig, &new, &old) < 0)
		return (SIG_ERR);
	return (old.sa_handler);

}


static void cleanup(int signo _U_)
{

	if (timer_handle != INVALID_HANDLE_VALUE) {
		DeleteTimerQueueTimer(NULL, timer_handle, NULL);
		CloseHandle(timer_handle);
		timer_handle = INVALID_HANDLE_VALUE;
        }

	struct itimerval timer;

	timer.it_interval.tv_sec = 0;
	timer.it_interval.tv_usec = 0;
	timer.it_value.tv_sec = 0;
	timer.it_value.tv_usec = 0;
	setitimer(ITIMER_REAL, &timer, NULL);



	
	pcap_breakloop(pd);

	
	if (pd != NULL && pcap_file(pd) == NULL) {
		
		putchar('\n');
		(void)fflush(stdout);
		info(1);
	}
	exit_tcpdump(S_SUCCESS);

}



static void child_cleanup(int signo _U_)
{
  wait(NULL);
}


static void info(int verbose)
{
	struct pcap_stat stats;

	
	stats.ps_ifdrop = 0;
	if (pcap_stats(pd, &stats) < 0) {
		(void)fprintf(stderr, "pcap_stats: %s\n", pcap_geterr(pd));
		infoprint = 0;
		return;
	}

	if (!verbose)
		fprintf(stderr, "%s: ", program_name);

	(void)fprintf(stderr, "%u packet%s captured", packets_captured, PLURAL_SUFFIX(packets_captured));
	if (!verbose)
		fputs(", ", stderr);
	else putc('\n', stderr);
	(void)fprintf(stderr, "%u packet%s received by filter", stats.ps_recv, PLURAL_SUFFIX(stats.ps_recv));
	if (!verbose)
		fputs(", ", stderr);
	else putc('\n', stderr);
	(void)fprintf(stderr, "%u packet%s dropped by kernel", stats.ps_drop, PLURAL_SUFFIX(stats.ps_drop));
	if (stats.ps_ifdrop != 0) {
		if (!verbose)
			fputs(", ", stderr);
		else putc('\n', stderr);
		(void)fprintf(stderr, "%u packet%s dropped by interface\n", stats.ps_ifdrop, PLURAL_SUFFIX(stats.ps_ifdrop));
	} else putc('\n', stderr);
	infoprint = 0;
}







static void compress_savefile(const char *filename)
{
	pid_t child;

	child = fork_subprocess();
	if (child == -1) {
		fprintf(stderr, "compress_savefile: fork failed: %s\n", pcap_strerror(errno));

		return;
	}
	if (child != 0) {
		
		return;
	}

	

	setpriority(PRIO_PROCESS, 0, NZERO - 1);

	setpriority(PRIO_PROCESS, 0, 19);

	if (execlp(zflag, zflag, filename, (char *)NULL) == -1)
		fprintf(stderr, "compress_savefile: execlp(%s, %s) failed: %s\n", zflag, filename, pcap_strerror(errno));




	exit(S_ERR_HOST_PROGRAM);

	_exit(S_ERR_HOST_PROGRAM);

}

static void compress_savefile(const char *filename)
{
	fprintf(stderr, "compress_savefile failed. Functionality not implemented under your system\n");
}


static void dump_packet_and_trunc(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
	struct dump_info *dump_info;

	++packets_captured;

	++infodelay;

	dump_info = (struct dump_info *)user;

	
	if (Gflag != 0) {
		
		time_t t;

		
		if ((t = time(NULL)) == (time_t)-1) {
			error("%s: can't get current_time: %s", __func__, pcap_strerror(errno));
		}


		
		if (t - Gflag_time >= Gflag) {

			FILE *fp;
			int fd;


			
			Gflag_time = t;
			
			Gflag_count++;
			
			pcap_dump_close(dump_info->pdd);

			
			if (zflag != NULL)
				compress_savefile(dump_info->CurrentFileName);

			
			if (Cflag == 0 && Wflag > 0 && Gflag_count >= Wflag) {
				(void)fprintf(stderr, "Maximum file limit reached: %d\n", Wflag);
				info(1);
				exit_tcpdump(S_SUCCESS);
				
			}
			if (dump_info->CurrentFileName != NULL)
				free(dump_info->CurrentFileName);
			
			dump_info->CurrentFileName = (char *)malloc(PATH_MAX + 1);
			if (dump_info->CurrentFileName == NULL)
				error("dump_packet_and_trunc: malloc");
			
			Cflag_count = 0;

			
			if (Cflag != 0)
				MakeFilename(dump_info->CurrentFileName, dump_info->WFileName, 0, WflagChars);
			else MakeFilename(dump_info->CurrentFileName, dump_info->WFileName, 0, 0);


			capng_update(CAPNG_ADD, CAPNG_EFFECTIVE, CAP_DAC_OVERRIDE);
			capng_apply(CAPNG_SELECT_BOTH);


			fd = openat(dump_info->dirfd, dump_info->CurrentFileName, O_CREAT | O_WRONLY | O_TRUNC, 0644);

			if (fd < 0) {
				error("unable to open file %s", dump_info->CurrentFileName);
			}
			fp = fdopen(fd, "w");
			if (fp == NULL) {
				error("unable to fdopen file %s", dump_info->CurrentFileName);
			}
			dump_info->pdd = pcap_dump_fopen(dump_info->pd, fp);

			dump_info->pdd = pcap_dump_open(dump_info->pd, dump_info->CurrentFileName);


			capng_update(CAPNG_DROP, CAPNG_EFFECTIVE, CAP_DAC_OVERRIDE);
			capng_apply(CAPNG_SELECT_BOTH);

			if (dump_info->pdd == NULL)
				error("%s", pcap_geterr(pd));

			set_dumper_capsicum_rights(dump_info->pdd);

		}
	}

	
	if (Cflag != 0) {

		int64_t size = pcap_dump_ftell64(dump_info->pdd);

		
		long size = pcap_dump_ftell(dump_info->pdd);


		if (size == -1)
			error("ftell fails on output file");
		if (size > Cflag) {

			FILE *fp;
			int fd;


			
			pcap_dump_close(dump_info->pdd);

			
			if (zflag != NULL)
				compress_savefile(dump_info->CurrentFileName);

			Cflag_count++;
			if (Wflag > 0) {
				if (Cflag_count >= Wflag)
					Cflag_count = 0;
			}
			if (dump_info->CurrentFileName != NULL)
				free(dump_info->CurrentFileName);
			dump_info->CurrentFileName = (char *)malloc(PATH_MAX + 1);
			if (dump_info->CurrentFileName == NULL)
				error("%s: malloc", __func__);
			MakeFilename(dump_info->CurrentFileName, dump_info->WFileName, Cflag_count, WflagChars);

			capng_update(CAPNG_ADD, CAPNG_EFFECTIVE, CAP_DAC_OVERRIDE);
			capng_apply(CAPNG_SELECT_BOTH);


			fd = openat(dump_info->dirfd, dump_info->CurrentFileName, O_CREAT | O_WRONLY | O_TRUNC, 0644);
			if (fd < 0) {
				error("unable to open file %s", dump_info->CurrentFileName);
			}
			fp = fdopen(fd, "w");
			if (fp == NULL) {
				error("unable to fdopen file %s", dump_info->CurrentFileName);
			}
			dump_info->pdd = pcap_dump_fopen(dump_info->pd, fp);

			dump_info->pdd = pcap_dump_open(dump_info->pd, dump_info->CurrentFileName);


			capng_update(CAPNG_DROP, CAPNG_EFFECTIVE, CAP_DAC_OVERRIDE);
			capng_apply(CAPNG_SELECT_BOTH);

			if (dump_info->pdd == NULL)
				error("%s", pcap_geterr(pd));

			set_dumper_capsicum_rights(dump_info->pdd);

		}
	}

	pcap_dump((u_char *)dump_info->pdd, h, sp);

	if (Uflag)
		pcap_dump_flush(dump_info->pdd);


	if (dump_info->ndo != NULL)
		pretty_print_packet(dump_info->ndo, h, sp, packets_captured);

	--infodelay;
	if (infoprint)
		info(0);
}

static void dump_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
	struct dump_info *dump_info;

	++packets_captured;

	++infodelay;

	dump_info = (struct dump_info *)user;

	pcap_dump((u_char *)dump_info->pdd, h, sp);

	if (Uflag)
		pcap_dump_flush(dump_info->pdd);


	if (dump_info->ndo != NULL)
		pretty_print_packet(dump_info->ndo, h, sp, packets_captured);

	--infodelay;
	if (infoprint)
		info(0);
}

static void print_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
	++packets_captured;

	++infodelay;

	if (!count_mode)
		pretty_print_packet((netdissect_options *)user, h, sp, packets_captured);

	--infodelay;
	if (infoprint)
		info(0);
}


static void requestinfo(int signo _U_)
{
	if (infodelay)
		++infoprint;
	else info(0);
}



static void flushpcap(int signo _U_)
{
	if (pdd != NULL)
		pcap_dump_flush(pdd);
}


static void print_packets_captured (void)
{
	static u_int prev_packets_captured, first = 1;

	if (infodelay == 0 && (first || packets_captured != prev_packets_captured)) {
		fprintf(stderr, "Got %u\r", packets_captured);
		first = 0;
		prev_packets_captured = packets_captured;
	}
}



static void CALLBACK verbose_stats_dump(PVOID param _U_, BOOLEAN timer_fired _U_)
{
	print_packets_captured();
}

static void verbose_stats_dump(int sig _U_)
{
	print_packets_captured();
}


DIAG_OFF_DEPRECATION static void print_version(FILE *f)

{

  #ifdef HAVE_PCAP_VERSION
	extern char pcap_version[];
  #else 
	static char pcap_version[] = "unknown";
  #endif 

	const char *smi_version_string;

	(void)fprintf(f, "%s version " PACKAGE_VERSION "\n", program_name);

	(void)fprintf(f, "%s\n", pcap_lib_version());

	(void)fprintf(f, "libpcap version %s\n", pcap_version);



	(void)fprintf (f, "%s\n", SSLeay_version(SSLEAY_VERSION));


	smi_version_string = nd_smi_version_string();
	if (smi_version_string != NULL)
		(void)fprintf (f, "SMI-library: %s\n", smi_version_string);


	(void)fprintf (f, "Compiled with AddressSanitizer/GCC.\n");


	(void)fprintf (f, "Compiled with AddressSanitizer/Clang.\n");

	(void)fprintf (f, "Compiled with MemorySanitizer/Clang.\n");


}
DIAG_ON_DEPRECATION  static void print_usage(FILE *f)


{
	print_version(f);
	(void)fprintf(f, "Usage: %s [-Abd" D_FLAG "efhH" I_FLAG J_FLAG "KlLnNOpqStu" U_FLAG "vxX#]" B_FLAG_USAGE " [ -c count ] [--count]\n", program_name);
	(void)fprintf(f, "\t\t[ -C file_size ] [ -E algo:secret ] [ -F file ] [ -G seconds ]\n");
	(void)fprintf(f, "\t\t[ -i interface ]" IMMEDIATE_MODE_USAGE j_FLAG_USAGE "\n");

	(void)fprintf(f, "\t\t" LIST_REMOTE_INTERFACES_USAGE "\n");


	(void)fprintf(f, "\t\t" m_FLAG_USAGE "\n");

	(void)fprintf(f, "\t\t[ -M secret ] [ --number ] [ --print ]\n");
	(void)fprintf(f, "\t\t[ --print-sampling nth ]" Q_FLAG_USAGE " [ -r file ]\n");
	(void)fprintf(f, "\t\t[ -s snaplen ] [ -T type ] [ --version ]\n");
	(void)fprintf(f, "\t\t[ -V file ] [ -w file ] [ -W filecount ] [ -y datalinktype ]\n");

	(void)fprintf(f, "\t\t[ --time-stamp-precision precision ] [ --micro ] [ --nano ]\n");

	(void)fprintf(f, "\t\t[ -z postrotate-command ] [ -Z user ] [ expression ]\n");
}
