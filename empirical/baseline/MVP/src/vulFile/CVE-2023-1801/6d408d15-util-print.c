




























enum date_flag { WITHOUT_DATE = 0, WITH_DATE = 1 };
enum time_flag { UTC_TIME = 0, LOCAL_TIME = 1 };


void fn_print_char(netdissect_options *ndo, u_char c)
{
	if (!ND_ISASCII(c)) {
		c = ND_TOASCII(c);
		ND_PRINT("M-");
	}
	if (!ND_ASCII_ISPRINT(c)) {
		c ^= 0x40;	
		ND_PRINT("^");
	}
	ND_PRINT("%c", c);
}


void fn_print_str(netdissect_options *ndo, const u_char *s)
{
	while (*s != '\0') {
		fn_print_char(ndo, *s);
		s++;
       }
}


u_int nd_printztn(netdissect_options *ndo, const u_char *s, u_int n, const u_char *ep)

{
	u_int bytes;
	u_char c;

	bytes = 0;
	for (;;) {
		if (n == 0 || (ep != NULL && s >= ep)) {
			
			bytes = 0;
			break;
		}

		c = GET_U_1(s);
		s++;
		bytes++;
		n--;
		if (c == '\0') {
			
			break;
		}
		fn_print_char(ndo, c);
	}
	return(bytes);
}


int nd_printn(netdissect_options *ndo, const u_char *s, u_int n, const u_char *ep)

{
	u_char c;

	while (n > 0 && (ep == NULL || s < ep)) {
		n--;
		c = GET_U_1(s);
		s++;
		fn_print_char(ndo, c);
	}
	return (n == 0) ? 0 : 1;
}


void nd_printjn(netdissect_options *ndo, const u_char *s, u_int n)
{
	while (n > 0) {
		fn_print_char(ndo, GET_U_1(s));
		n--;
		s++;
	}
}


void nd_printjnp(netdissect_options *ndo, const u_char *s, u_int n)
{
	u_char c;

	while (n > 0) {
		c = GET_U_1(s);
		if (c == '\0')
			break;
		fn_print_char(ndo, c);
		n--;
		s++;
	}
}


static void ts_frac_print(netdissect_options *ndo, long usec)
{

	switch (ndo->ndo_tstamp_precision) {

	case PCAP_TSTAMP_PRECISION_MICRO:
		ND_PRINT(".%06u", (unsigned)usec);
		break;

	case PCAP_TSTAMP_PRECISION_NANO:
		ND_PRINT(".%09u", (unsigned)usec);
		break;

	default:
		ND_PRINT(".{unknown}");
		break;
	}

	ND_PRINT(".%06u", (unsigned)usec);

}


static void ts_date_hmsfrac_print(netdissect_options *ndo, long sec, long usec, enum date_flag date_flag, enum time_flag time_flag)

{
	time_t Time = sec;
	struct tm *tm;
	char timestr[32];

	if ((unsigned)sec & 0x80000000) {
		ND_PRINT("[Error converting time]");
		return;
	}

	if (time_flag == LOCAL_TIME)
		tm = localtime(&Time);
	else tm = gmtime(&Time);

	if (!tm) {
		ND_PRINT("[Error converting time]");
		return;
	}
	if (date_flag == WITH_DATE)
		strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", tm);
	else strftime(timestr, sizeof(timestr), "%H:%M:%S", tm);
	ND_PRINT("%s", timestr);

	ts_frac_print(ndo, usec);
}


static void ts_unix_print(netdissect_options *ndo, long sec, long usec)
{
	if ((unsigned)sec & 0x80000000) {
		ND_PRINT("[Error converting time]");
		return;
	}

	ND_PRINT("%u", (unsigned)sec);
	ts_frac_print(ndo, usec);
}


void ts_print(netdissect_options *ndo, const struct timeval *tvp)

{
	static struct timeval tv_ref;
	struct timeval tv_result;
	int negative_offset;
	int nano_prec;

	switch (ndo->ndo_tflag) {

	case 0: 
		ts_date_hmsfrac_print(ndo, tvp->tv_sec, tvp->tv_usec, WITHOUT_DATE, LOCAL_TIME);
		ND_PRINT(" ");
		break;

	case 1: 
		break;

	case 2: 
		ts_unix_print(ndo, tvp->tv_sec, tvp->tv_usec);
		ND_PRINT(" ");
		break;

	case 3: 
        case 5: 

		switch (ndo->ndo_tstamp_precision) {
		case PCAP_TSTAMP_PRECISION_MICRO:
			nano_prec = 0;
			break;
		case PCAP_TSTAMP_PRECISION_NANO:
			nano_prec = 1;
			break;
		default:
			nano_prec = 0;
			break;
		}

		nano_prec = 0;

		if (!(netdissect_timevalisset(&tv_ref)))
			tv_ref = *tvp; 

		negative_offset = netdissect_timevalcmp(tvp, &tv_ref, <);
		if (negative_offset)
			netdissect_timevalsub(&tv_ref, tvp, &tv_result, nano_prec);
		else netdissect_timevalsub(tvp, &tv_ref, &tv_result, nano_prec);

		ND_PRINT((negative_offset ? "-" : " "));
		ts_date_hmsfrac_print(ndo, tv_result.tv_sec, tv_result.tv_usec, WITHOUT_DATE, UTC_TIME);
		ND_PRINT(" ");

                if (ndo->ndo_tflag == 3)
			tv_ref = *tvp; 
		break;

	case 4: 
		ts_date_hmsfrac_print(ndo, tvp->tv_sec, tvp->tv_usec, WITH_DATE, LOCAL_TIME);
		ND_PRINT(" ");
		break;
	}
}


void unsigned_relts_print(netdissect_options *ndo, uint32_t secs)

{
	static const char *lengths[] = {"y", "w", "d", "h", "m", "s";
	static const u_int seconds[] = {31536000, 604800, 86400, 3600, 60, 1};
	const char **l = lengths;
	const u_int *s = seconds;

	if (secs == 0) {
		ND_PRINT("0s");
		return;
	}
	while (secs > 0) {
		if (secs >= *s) {
			ND_PRINT("%u%s", secs / *s, *l);
			secs -= (secs / *s) * *s;
		}
		s++;
		l++;
	}
}


void signed_relts_print(netdissect_options *ndo, int32_t secs)

{
	if (secs < 0) {
		ND_PRINT("-");
		if (secs == INT32_MIN) {
			
			unsigned_relts_print(ndo, 2147483648U);
		} else {
			
			unsigned_relts_print(ndo, -secs);
		}
		return;
	}
	unsigned_relts_print(ndo, secs);
}


void nd_print_trunc(netdissect_options *ndo)
{
	ND_PRINT(" [|%s]", ndo->ndo_protocol);
}


void nd_print_protocol(netdissect_options *ndo)
{
	ND_PRINT("%s", ndo->ndo_protocol);
}


void nd_print_protocol_caps(netdissect_options *ndo)
{
	const char *p;
        for (p = ndo->ndo_protocol; *p != '\0'; p++)
                ND_PRINT("%c", ND_ASCII_TOUPPER(*p));
}


void nd_print_invalid(netdissect_options *ndo)
{
	ND_PRINT(" (invalid)");
}



int print_unknown_data(netdissect_options *ndo, const u_char *cp, const char *indent, u_int len)

{
	if (!ND_TTEST_LEN(cp, 0)) {
		ND_PRINT("%sDissector error: %s() called with pointer past end of packet", indent, __func__);
		return(0);
	}
	hex_print(ndo, indent, cp, ND_MIN(len, ND_BYTES_AVAILABLE_AFTER(cp)));
	return(1); 
}


static const char * tok2strbuf(const struct tok *lp, const char *fmt, const u_int v, char *buf, const size_t bufsize)

{
	if (lp != NULL) {
		while (lp->s != NULL) {
			if (lp->v == v)
				return (lp->s);
			++lp;
		}
	}
	if (fmt == NULL)
		fmt = "#%d";

	(void)snprintf(buf, bufsize, fmt, v);
	return (const char *)buf;
}


const char * tok2str(const struct tok *lp, const char *fmt, const u_int v)
{
	static char buf[4][TOKBUFSIZE];
	static int idx = 0;
	char *ret;

	ret = buf[idx];
	idx = (idx+1) & 3;
	return tok2strbuf(lp, fmt, v, ret, sizeof(buf[0]));
}


static char * bittok2str_internal(const struct tok *lp, const char *fmt, const u_int v, const char *sep)

{
        static char buf[1024+1]; 
        char *bufp = buf;
        size_t space_left = sizeof(buf), string_size;
        const char * sepstr = "";

        while (lp != NULL && lp->s != NULL) {
            if (lp->v && (v & lp->v) == lp->v) {
                
                if (space_left <= 1)
                    return (buf); 
                string_size = strlcpy(bufp, sepstr, space_left);
                if (string_size >= space_left)
                    return (buf);    
                bufp += string_size;
                space_left -= string_size;
                if (space_left <= 1)
                    return (buf); 
                string_size = strlcpy(bufp, lp->s, space_left);
                if (string_size >= space_left)
                    return (buf);    
                bufp += string_size;
                space_left -= string_size;
                sepstr = sep;
            }
            lp++;
        }

        if (bufp == buf)
            
            (void)snprintf(buf, sizeof(buf), fmt == NULL ? "#%08x" : fmt, v);
        return (buf);
}


char * bittok2str_nosep(const struct tok *lp, const char *fmt, const u_int v)
{
    return (bittok2str_internal(lp, fmt, v, ""));
}


char * bittok2str(const struct tok *lp, const char *fmt, const u_int v)
{
    return (bittok2str_internal(lp, fmt, v, ", "));
}


const char * tok2strary_internal(const char **lp, int n, const char *fmt, const int v)
{
	static char buf[TOKBUFSIZE];

	if (v >= 0 && v < n && lp[v] != NULL)
		return lp[v];
	if (fmt == NULL)
		fmt = "#%d";
	(void)snprintf(buf, sizeof(buf), fmt, v);
	return (buf);
}

const struct tok * uint2tokary_internal(const struct uint_tokary dict[], const size_t size, const u_int val)

{
	size_t i;
	
	if (val < size && dict[val].uintval == val)
		return dict[val].tokary; 
	for (i = 0; i < size; i++)
		if (dict[i].uintval == val)
			return dict[i].tokary; 
	return NULL;
}



int mask2plen(const uint32_t mask)
{
	const uint32_t bitmasks[33] = {
		0x00000000, 0x80000000, 0xc0000000, 0xe0000000, 0xf0000000, 0xf8000000, 0xfc000000, 0xfe000000, 0xff000000, 0xff800000, 0xffc00000, 0xffe00000, 0xfff00000, 0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000, 0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000, 0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00, 0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0, 0xfffffff8, 0xfffffffc, 0xfffffffe, 0xffffffff };








	int prefix_len = 32;

	
	while (prefix_len >= 0) {
		if (bitmasks[prefix_len] == mask)
			break;
		prefix_len--;
	}
	return (prefix_len);
}

int mask62plen(const u_char *mask)
{
	u_char bitmasks[9] = {
		0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff };


	int byte;
	int cidr_len = 0;

	for (byte = 0; byte < 16; byte++) {
		u_int bits;

		for (bits = 0; bits < (sizeof (bitmasks) / sizeof (bitmasks[0])); bits++) {
			if (mask[byte] == bitmasks[bits]) {
				cidr_len += bits;
				break;
			}
		}

		if (mask[byte] != 0xff)
			break;
	}
	return (cidr_len);
}





static int fetch_token(netdissect_options *ndo, const u_char *pptr, u_int idx, u_int len, u_char *tbuf, size_t tbuflen)

{
	size_t toklen = 0;
	u_char c;

	for (; idx < len; idx++) {
		if (!ND_TTEST_1(pptr + idx)) {
			
			return (0);
		}
		c = GET_U_1(pptr + idx);
		if (!ND_ISASCII(c)) {
			
			return (0);
		}
		if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
			
			break;
		}
		if (!ND_ASCII_ISPRINT(c)) {
			
			return (0);
		}
		if (toklen + 2 > tbuflen) {
			
			return (0);
		}
		tbuf[toklen] = c;
		toklen++;
	}
	if (toklen == 0) {
		
		return (0);
	}
	tbuf[toklen] = '\0';

	
	for (; idx < len; idx++) {
		if (!ND_TTEST_1(pptr + idx)) {
			
			break;
		}
		c = GET_U_1(pptr + idx);
		if (c == '\r' || c == '\n') {
			
			break;
		}
		if (!ND_ASCII_ISPRINT(c)) {
			
			break;
		}
		if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
			
			break;
		}
	}
	return (idx);
}


static u_int print_txt_line(netdissect_options *ndo, const char *prefix, const u_char *pptr, u_int idx, u_int len)

{
	u_int startidx;
	u_int linelen;
	u_char c;

	startidx = idx;
	while (idx < len) {
		c = GET_U_1(pptr + idx);
		if (c == '\n') {
			
			linelen = idx - startidx;
			idx++;
			goto print;
		} else if (c == '\r') {
			
			if ((idx+1) >= len) {
				
				return (0);
			}
			if (GET_U_1(pptr + idx + 1) == '\n') {
				
				linelen = idx - startidx;
				idx += 2;
				goto print;
			}

			
			return (0);
		} else if (!ND_ASCII_ISPRINT(c) && c != '\t') {
			
			return (0);
		}
		idx++;
	}

	
	linelen = idx - startidx;
	ND_PRINT("%s%.*s", prefix, (int)linelen, pptr + startidx);
	nd_print_trunc(ndo);
	return (0);

print:
	ND_PRINT("%s%.*s", prefix, (int)linelen, pptr + startidx);
	return (idx);
}


void txtproto_print(netdissect_options *ndo, const u_char *pptr, u_int len, const char **cmds, u_int flags)

{
	u_int idx, eol;
	u_char token[MAX_TOKEN+1];
	const char *cmd;
	int print_this = 0;

	if (cmds != NULL) {
		
		idx = fetch_token(ndo, pptr, 0, len, token, sizeof(token));
		if (idx != 0) {
			
			while ((cmd = *cmds++) != NULL) {
				if (ascii_strcasecmp((const char *)token, cmd) == 0) {
					
					print_this = 1;
					break;
				}
			}

			
			if (flags & RESP_CODE_SECOND_TOKEN) {
				
				idx = fetch_token(ndo, pptr, idx, len, token, sizeof(token));
			}
			if (idx != 0) {
				if (ND_ASCII_ISDIGIT(token[0]) && ND_ASCII_ISDIGIT(token[1]) && ND_ASCII_ISDIGIT(token[2]) && token[3] == '\0') {
					
					print_this = 1;
				}
			}
		}
	} else {
		
		print_this = 1;
	}

	nd_print_protocol_caps(ndo);

	if (print_this) {
		
		if (ndo->ndo_vflag) {
			
			ND_PRINT(", length: %u", len);
			for (idx = 0;
			    idx < len && (eol = print_txt_line(ndo, "\n\t", pptr, idx, len)) != 0;
			    idx = eol)
				;
		} else {
			
			print_txt_line(ndo, ": ", pptr, 0, len);
		}
	}
}









void unaligned_memcpy(void *p, const void *q, size_t l)
{
	memcpy(p, q, l);
}


int unaligned_memcmp(const void *p, const void *q, size_t l)
{
	return (memcmp(p, q, l));
}


