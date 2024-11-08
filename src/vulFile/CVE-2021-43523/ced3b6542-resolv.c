





































































struct resolv_header {
	int id;
	int qr, opcode, aa, tc, rd, ra, rcode;
	int qdcount;
	int ancount;
	int nscount;
	int arcount;
};

struct resolv_question {
	char *dotted;
	int qtype;
	int qclass;
};

struct resolv_answer {
	char *dotted;
	int atype;
	int aclass;
	int ttl;
	int rdlength;
	const unsigned char *rdata;
	int rdoffset;
	char* buf;
	size_t buflen;
	size_t add_count;
};

enum etc_hosts_action {
	GET_HOSTS_BYNAME = 0, GETHOSTENT, GET_HOSTS_BYADDR, };



typedef union sockaddr46_t {
	struct sockaddr sa;

	struct sockaddr_in sa4;


	struct sockaddr_in6 sa6;

} sockaddr46_t;


__UCLIBC_MUTEX_EXTERN(__resolv_lock) attribute_hidden;


extern void (*__res_sync)(void) attribute_hidden;

extern uint8_t __resolv_timeout attribute_hidden;
extern uint8_t __resolv_attempts attribute_hidden;
extern unsigned __nameservers attribute_hidden;
extern unsigned __searchdomains attribute_hidden;
extern sockaddr46_t *__nameserver attribute_hidden;
extern char **__searchdomain attribute_hidden;

extern const struct sockaddr_in __local_nameserver attribute_hidden;

extern const struct sockaddr_in6 __local_nameserver attribute_hidden;






extern void endhostent_unlocked(void) attribute_hidden;
extern int __get_hosts_byname_r(const char *name, int type, struct hostent *result_buf, char *buf, size_t buflen, struct hostent **result, int *h_errnop) attribute_hidden;





extern int __get_hosts_byaddr_r(const char *addr, int len, int type, struct hostent *result_buf, char *buf, size_t buflen, struct hostent **result, int *h_errnop) attribute_hidden;






extern parser_t *__open_etc_hosts(void) attribute_hidden;
extern int __read_etc_hosts_r(parser_t *parser, const char *name, int type, enum etc_hosts_action action, struct hostent *result_buf, char *buf, size_t buflen, struct hostent **result, int *h_errnop) attribute_hidden;







extern int __dns_lookup(const char *name, int type, unsigned char **outpacket, struct resolv_answer *a) attribute_hidden;


extern int __encode_header(struct resolv_header *h, unsigned char *dest, int maxlen) attribute_hidden;

extern void __decode_header(unsigned char *data, struct resolv_header *h) attribute_hidden;
extern int __encode_question(const struct resolv_question *q, unsigned char *dest, int maxlen) attribute_hidden;

extern int __encode_answer(struct resolv_answer *a, unsigned char *dest, int maxlen) attribute_hidden;

extern void __open_nameservers(void) attribute_hidden;
extern void __close_nameservers(void) attribute_hidden;










int __encode_header(struct resolv_header *h, unsigned char *dest, int maxlen)
{
	if (maxlen < HFIXEDSZ)
		return -1;

	dest[0] = (h->id & 0xff00) >> 8;
	dest[1] = (h->id & 0x00ff) >> 0;
	dest[2] = (h->qr ? 0x80 : 0) | ((h->opcode & 0x0f) << 3) | (h->aa ? 0x04 : 0) | (h->tc ? 0x02 : 0) | (h->rd ? 0x01 : 0);



	dest[3] = (h->ra ? 0x80 : 0) | (h->rcode & 0x0f);
	dest[4] = (h->qdcount & 0xff00) >> 8;
	dest[5] = (h->qdcount & 0x00ff) >> 0;
	dest[6] = (h->ancount & 0xff00) >> 8;
	dest[7] = (h->ancount & 0x00ff) >> 0;
	dest[8] = (h->nscount & 0xff00) >> 8;
	dest[9] = (h->nscount & 0x00ff) >> 0;
	dest[10] = (h->arcount & 0xff00) >> 8;
	dest[11] = (h->arcount & 0x00ff) >> 0;

	return HFIXEDSZ;
}





void __decode_header(unsigned char *data, struct resolv_header *h)
{
	h->id = (data[0] << 8) | data[1];
	h->qr = (data[2] & 0x80) ? 1 : 0;
	h->opcode = (data[2] >> 3) & 0x0f;
	h->aa = (data[2] & 0x04) ? 1 : 0;
	h->tc = (data[2] & 0x02) ? 1 : 0;
	h->rd = (data[2] & 0x01) ? 1 : 0;
	h->ra = (data[3] & 0x80) ? 1 : 0;
	h->rcode = data[3] & 0x0f;
	h->qdcount = (data[4] << 8) | data[5];
	h->ancount = (data[6] << 8) | data[7];
	h->nscount = (data[8] << 8) | data[9];
	h->arcount = (data[10] << 8) | data[11];
}





int __encode_question(const struct resolv_question *q, unsigned char *dest, int maxlen)

{
	int i;

	i = __encode_dotted(q->dotted, dest, maxlen);
	if (i < 0)
		return i;

	dest += i;
	maxlen -= i;

	if (maxlen < 4)
		return -1;

	dest[0] = (q->qtype & 0xff00) >> 8;
	dest[1] = (q->qtype & 0x00ff) >> 0;
	dest[2] = (q->qclass & 0xff00) >> 8;
	dest[3] = (q->qclass & 0x00ff) >> 0;

	return i + 4;
}





int __encode_answer(struct resolv_answer *a, unsigned char *dest, int maxlen)
{
	int i;

	i = __encode_dotted(a->dotted, dest, maxlen);
	if (i < 0)
		return i;

	dest += i;
	maxlen -= i;

	if (maxlen < (RRFIXEDSZ + a->rdlength))
		return -1;

	*dest++ = (a->atype & 0xff00) >> 8;
	*dest++ = (a->atype & 0x00ff) >> 0;
	*dest++ = (a->aclass & 0xff00) >> 8;
	*dest++ = (a->aclass & 0x00ff) >> 0;
	*dest++ = (a->ttl & 0xff000000) >> 24;
	*dest++ = (a->ttl & 0x00ff0000) >> 16;
	*dest++ = (a->ttl & 0x0000ff00) >> 8;
	*dest++ = (a->ttl & 0x000000ff) >> 0;
	*dest++ = (a->rdlength & 0xff00) >> 8;
	*dest++ = (a->rdlength & 0x00ff) >> 0;
	memcpy(dest, a->rdata, a->rdlength);

	return i + RRFIXEDSZ + a->rdlength;
}






int __encode_packet(struct resolv_header *h, struct resolv_question **q, struct resolv_answer **an, struct resolv_answer **ns, struct resolv_answer **ar, unsigned char *dest, int maxlen) attribute_hidden;




int __encode_packet(struct resolv_header *h, struct resolv_question **q, struct resolv_answer **an, struct resolv_answer **ns, struct resolv_answer **ar, unsigned char *dest, int maxlen)




{
	int i, total = 0;
	unsigned j;

	i = __encode_header(h, dest, maxlen);
	if (i < 0)
		return i;

	dest += i;
	maxlen -= i;
	total += i;

	for (j = 0; j < h->qdcount; j++) {
		i = __encode_question(q[j], dest, maxlen);
		if (i < 0)
			return i;
		dest += i;
		maxlen -= i;
		total += i;
	}

	for (j = 0; j < h->ancount; j++) {
		i = __encode_answer(an[j], dest, maxlen);
		if (i < 0)
			return i;
		dest += i;
		maxlen -= i;
		total += i;
	}
	for (j = 0; j < h->nscount; j++) {
		i = __encode_answer(ns[j], dest, maxlen);
		if (i < 0)
			return i;
		dest += i;
		maxlen -= i;
		total += i;
	}
	for (j = 0; j < h->arcount; j++) {
		i = __encode_answer(ar[j], dest, maxlen);
		if (i < 0)
			return i;
		dest += i;
		maxlen -= i;
		total += i;
	}

	return total;
}





int __decode_packet(unsigned char *data, struct resolv_header *h) attribute_hidden;
int __decode_packet(unsigned char *data, struct resolv_header *h)
{
	__decode_header(data, h);
	return HFIXEDSZ;
}





int __form_query(int id, const char *name, int type, unsigned char *packet, int maxlen) attribute_hidden;



int __form_query(int id, const char *name, int type, unsigned char *packet, int maxlen)



{
	struct resolv_header h;
	struct resolv_question q;
	int i, j;

	memset(&h, 0, sizeof(h));
	h.id = id;
	h.qdcount = 1;

	q.dotted = (char *) name;
	q.qtype = type;
	q.qclass = C_IN; 

	i = __encode_header(&h, packet, maxlen);
	if (i < 0)
		return i;

	j = __encode_question(&q, packet + i, maxlen - i);
	if (j < 0)
		return j;

	return i + j;
}












__UCLIBC_MUTEX_INIT(__resolv_lock, PTHREAD_MUTEX_INITIALIZER);


void (*__res_sync)(void);

uint8_t __resolv_timeout = RES_TIMEOUT;
uint8_t __resolv_attempts = RES_DFLRETRY;
unsigned __nameservers;
unsigned __searchdomains;
sockaddr46_t *__nameserver;
char **__searchdomain;

const struct sockaddr_in __local_nameserver = {
	.sin_family = AF_INET, .sin_port = NAMESERVER_PORT_N, };


const struct sockaddr_in6 __local_nameserver = {
	.sin6_family = AF_INET6, .sin6_port = NAMESERVER_PORT_N, };




static char *skip_nospace(char *p)
{
	while (*p != '\0' && !isspace(*p)) {
		if (*p == '\n') {
			*p = '\0';
			break;
		}
		p++;
	}
	return p;
}
static char *skip_and_NUL_space(char *p)
{
	
	while (1) {
		char c = *p;
		if (c == '\0' || !isspace(c))
			break;
		*p = '\0';
		if (c == '\n' || c == '#')
			break;
		p++;
	}
	return p;
}


void __open_nameservers(void)
{
	static uint32_t resolv_conf_mtime;

	char szBuffer[MAXLEN_searchdomain];
	FILE *fp;
	int i;
	sockaddr46_t sa;

	if (!__res_sync) {
		
		struct stat sb;
		if (stat(_PATH_RESCONF, &sb) != 0)
			sb.st_mtime = 0;
		if (resolv_conf_mtime != (uint32_t)sb.st_mtime) {
			resolv_conf_mtime = sb.st_mtime;
			__close_nameservers(); 
		}
	}

	if (__nameservers)
		goto sync;

	__resolv_timeout = RES_TIMEOUT;
	__resolv_attempts = RES_DFLRETRY;

	fp = fopen(_PATH_RESCONF, "r");

	if (!fp) {
		
		fp = fopen("/etc/config/resolv.conf", "r");
	}


	if (fp) {
		while (fgets(szBuffer, sizeof(szBuffer), fp) != NULL) {
			void *ptr;
			char *keyword, *p;

			keyword = p = skip_and_NUL_space(szBuffer);
			
			p = skip_nospace(p);
			
			p = skip_and_NUL_space(p);

			if (strcmp(keyword, "nameserver") == 0) {
				
				*skip_nospace(p) = '\0';
				memset(&sa, 0, sizeof(sa));
				if (0) ;

				else if (inet_pton(AF_INET6, p, &sa.sa6.sin6_addr) > 0) {
					sa.sa6.sin6_family = AF_INET6;
					sa.sa6.sin6_port = htons(NAMESERVER_PORT);
				}


				else if (inet_pton(AF_INET, p, &sa.sa4.sin_addr) > 0) {
					sa.sa4.sin_family = AF_INET;
					sa.sa4.sin_port = htons(NAMESERVER_PORT);
				}

				else continue;
				ptr = realloc(__nameserver, (__nameservers + 1) * sizeof(__nameserver[0]));
				if (!ptr)
					continue;
				__nameserver = ptr;
				__nameserver[__nameservers++] = sa; 
				continue;
			}
			if (strcmp(keyword, "domain") == 0 || strcmp(keyword, "search") == 0) {
				char *p1;

				
				while (__searchdomains)
					free(__searchdomain[--__searchdomains]);
				
				
 next_word:
				
				p1 = skip_nospace(p);
				
				p1 = skip_and_NUL_space(p1);
				
				ptr = realloc(__searchdomain, (__searchdomains + 1) * sizeof(__searchdomain[0]));
				if (!ptr)
					continue;
				__searchdomain = ptr;
				
				ptr = strdup(p);
				if (!ptr)
					continue;
				DPRINTF("adding search %s\n", (char*)ptr);
				__searchdomain[__searchdomains++] = (char*)ptr;
				p = p1;
				if (*p)
					goto next_word;
				continue;
			}
			
			if (strcmp(keyword, "options") == 0) {
				char *p1;
				uint8_t *what;

				if (p == NULL || (p1 = strchr(p, ':')) == NULL)
					continue;
				*p1++ = '\0';
				if (strcmp(p, "timeout") == 0)
					what = &__resolv_timeout;
				else if (strcmp(p, "attempts") == 0)
					what = &__resolv_attempts;
				else continue;
				*what = atoi(p1);
				DPRINTF("option %s:%d\n", p, *what);
			}
		}
		fclose(fp);
	}
	if (__nameservers == 0) {
		
		__nameserver = malloc(sizeof(__nameserver[0]));
		if (__nameserver)
			memcpy(__nameserver, &__local_nameserver, sizeof(__local_nameserver));
		else __nameserver = (void*) &__local_nameserver;
		__nameservers++;
	}
	if (__searchdomains == 0) {
		char buf[256];
		char *p;
		i = gethostname(buf, sizeof(buf) - 1);
		buf[sizeof(buf) - 1] = '\0';
		if (i == 0 && (p = strchr(buf, '.')) != NULL && p[1]) {
			p = strdup(p + 1);
			if (!p)
				goto err;
			__searchdomain = malloc(sizeof(__searchdomain[0]));
			if (!__searchdomain) {
				free(p);
				goto err;
			}
			__searchdomain[0] = p;
			__searchdomains++;
 err: ;
		}
	}
	DPRINTF("nameservers = %d\n", __nameservers);

 sync:
	if (__res_sync)
		__res_sync();
}






void __close_nameservers(void)
{
	if (__nameserver != (void*) &__local_nameserver)
		free(__nameserver);
	__nameserver = NULL;
	__nameservers = 0;
	while (__searchdomains)
		free(__searchdomain[--__searchdomains]);
	free(__searchdomain);
	__searchdomain = NULL;
	
}






static int __length_question(const unsigned char *data, int maxlen)
{
	const unsigned char *start;
	unsigned b;

	if (!data)
		return -1;

	start = data;
	while (1) {
		if (maxlen <= 0)
			return -1;
		b = *data++;
		if (b == 0)
			break;
		if ((b & 0xc0) == 0xc0) {
			
			data++; 
			maxlen -= 2;
			break;
		}
		data += b;
		maxlen -= (b + 1); 
	}
	

	
	if (maxlen < 4)
		return -1;
	return data - start + 2 + 2;
}

static int __decode_answer(const unsigned char *message,  int offset, int len, struct resolv_answer *a)


{
	char temp[256];
	int i;

	DPRINTF("decode_answer(start): off %d, len %d\n", offset, len);
	i = __decode_dotted(message, offset, len, temp, sizeof(temp));
	if (i < 0)
		return i;

	message += offset + i;
	len -= i + RRFIXEDSZ + offset;
	if (len < 0) {
		DPRINTF("decode_answer: off %d, len %d, i %d\n", offset, len, i);
		return len;
	}


	a->dotted = strdup(temp);
	a->atype = (message[0] << 8) | message[1];
	message += 2;
	a->aclass = (message[0] << 8) | message[1];
	message += 2;
	a->ttl = (message[0] << 24) | (message[1] << 16) | (message[2] << 8) | (message[3] << 0);
	message += 4;
	a->rdlength = (message[0] << 8) | message[1];
	message += 2;
	a->rdata = message;
	a->rdoffset = offset + i + RRFIXEDSZ;

	DPRINTF("i=%d,rdlength=%d\n", i, a->rdlength);

	if (len < a->rdlength)
		return -1;
	return i + RRFIXEDSZ + a->rdlength;
}


int __dns_lookup(const char *name, int type, unsigned char **outpacket, struct resolv_answer *a)


{
	
	static int last_ns_num = 0;
	static uint16_t last_id = 1;

	int i, j, fd, rc;
	int packet_len;
	int name_len;

	struct timeval tv;
	fd_set fds;

	struct pollfd fds;

	struct resolv_header h;
	struct resolv_question q;
	struct resolv_answer ma;
	bool first_answer = 1;
	int retries_left;
	unsigned char *packet = malloc(PACKETSZ);
	char *lookup;
	int variant = -1;  
	int local_ns_num = -1; 
	int local_id = local_id; 
	int sdomains = 0;
	bool ends_with_dot;
	bool contains_dot;
	sockaddr46_t sa;

	fd = -1;
	lookup = NULL;
	name_len = strlen(name);
	if ((unsigned)name_len >= MAXDNAME - MAXLEN_searchdomain - 2)
		goto fail; 
	lookup = malloc(name_len + 1 + MAXLEN_searchdomain + 1);
	if (!packet || !lookup || !name[0])
		goto fail;
	ends_with_dot = (name[name_len - 1] == '.');
	contains_dot = strchr(name, '.') != NULL;
	
	memcpy(lookup, name, name_len);

	DPRINTF("Looking up type %d answer for '%s'\n", type, name);
	retries_left = 0; 
	do {
		unsigned act_variant;
		int pos;
		unsigned reply_timeout;

		if (fd != -1) {
			close(fd);
			fd = -1;
		}

		
		
		__UCLIBC_MUTEX_LOCK(__resolv_lock);
		__open_nameservers();
		if (type != T_PTR) {
			sdomains = __searchdomains;
		}
		lookup[name_len] = '\0';
		
		act_variant = contains_dot ? variant : variant + 1;
		if (act_variant < sdomains) {
			
			
			lookup[name_len] = '.';
			strcpy(&lookup[name_len + 1], __searchdomain[act_variant]);
		}
		
		if (local_ns_num < 0) {
			local_id = last_id;

				local_ns_num = last_ns_num;
			retries_left = __nameservers * __resolv_attempts;
		}
		if (local_ns_num >= __nameservers)
			local_ns_num = 0;
		local_id++;
		local_id &= 0xffff;
		
		last_id = local_id;
		last_ns_num = local_ns_num;
		
		
		sa = __nameserver[local_ns_num];
		__UCLIBC_MUTEX_UNLOCK(__resolv_lock);

		memset(packet, 0, PACKETSZ);
		memset(&h, 0, sizeof(h));

		
		h.id = local_id;
		h.qdcount = 1;
		h.rd = 1;
		DPRINTF("encoding header\n", h.rd);
		i = __encode_header(&h, packet, PACKETSZ);
		if (i < 0)
			goto fail;

		
		DPRINTF("lookup name: %s\n", lookup);
		q.dotted = lookup;
		q.qtype = type;
		q.qclass = C_IN; 
		j = __encode_question(&q, packet+i, PACKETSZ-i);
		if (j < 0)
			goto fail;
		packet_len = i + j;

		

		{
			const socklen_t plen = sa.sa.sa_family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
			char *pbuf = malloc(plen);
			if (pbuf == NULL) ;

			else if (sa.sa.sa_family == AF_INET6)
				pbuf = (char*)inet_ntop(AF_INET6, &sa.sa6.sin6_addr, pbuf, plen);


			else if (sa.sa.sa_family == AF_INET)
				pbuf = (char*)inet_ntop(AF_INET, &sa.sa4.sin_addr, pbuf, plen);

			DPRINTF("On try %d, sending query to %s, port %d\n", retries_left, pbuf, NAMESERVER_PORT);
			free(pbuf);
		}

		fd = socket(sa.sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);
		if (fd < 0) 
			goto try_next_server;
		rc = connect(fd, &sa.sa, sizeof(sa));
		if (rc < 0) {
			
				
				goto try_next_server;
			

			
			
		}
		DPRINTF("Xmit packet len:%d id:%d qr:%d\n", packet_len, h.id, h.qr);
		
		send(fd, packet, packet_len, 0);


		reply_timeout = __resolv_timeout;
 wait_again:
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		tv.tv_sec = reply_timeout;
		tv.tv_usec = 0;
		if (select(fd + 1, &fds, NULL, NULL, &tv) <= 0) {
			DPRINTF("Timeout\n");
			
			goto try_next_server;
		}
		reply_timeout--;

		reply_timeout = __resolv_timeout * 1000;
 wait_again:
		fds.fd = fd;
		fds.events = POLLIN;
		if (poll(&fds, 1, reply_timeout) <= 0) {
			DPRINTF("Timeout\n");
			
			goto try_next_server;
		}
		if (fds.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			DPRINTF("Bad event\n");
			goto try_next_server;
		}

		reply_timeout -= 1000;




		{
			static const char test_query[32] = "\0\2\1\0\0\1\0\0\0\0\0\0\3www\6google\3com\0\0\34\0\1";
			static const char test_respn[32] = "\0\2\201\200\0\1\0\1\0\0\0\0\3www\6google\3com\0\0\34\0\1";
			pos = memcmp(packet + 2, test_query + 2, 30);
		packet_len = recv(fd, packet, PACKETSZ, MSG_DONTWAIT);
			if (pos == 0) {
				packet_len = 32;
				memcpy(packet + 2, test_respn + 2, 30);
			}
		}

		packet_len = recv(fd, packet, PACKETSZ, MSG_DONTWAIT);


		if (packet_len < HFIXEDSZ) {
			
 bogus_packet:
			if (packet_len >= 0 && reply_timeout)
				goto wait_again;
			goto try_next_server;
		}
		__decode_header(packet, &h);
		DPRINTF("len:%d id:%d qr:%d\n", packet_len, h.id, h.qr);
		if (h.id != local_id || !h.qr) {
			
			goto bogus_packet;
		}

		DPRINTF("Got response (i think)!\n");
		DPRINTF("qrcount=%d,ancount=%d,nscount=%d,arcount=%d\n", h.qdcount, h.ancount, h.nscount, h.arcount);
		DPRINTF("opcode=%d,aa=%d,tc=%d,rd=%d,ra=%d,rcode=%d\n", h.opcode, h.aa, h.tc, h.rd, h.ra, h.rcode);

		
		if (h.rcode == NXDOMAIN || h.rcode == SERVFAIL) {
			
			if (!ends_with_dot) {
				DPRINTF("variant:%d sdomains:%d\n", variant, sdomains);
				if (variant < sdomains - 1) {
					
					variant++;
					continue;
				}
				
			}
			if (h.rcode != SERVFAIL) {
				
				h_errno = HOST_NOT_FOUND;
				goto fail1;
			}
		}
		

		
		if (h.rcode != 0)
			goto try_next_server;

		
		if (h.ancount <= 0) {
			h_errno = NO_DATA; 
			goto fail1;
		}
		pos = HFIXEDSZ;
		for (j = 0; j < h.qdcount; j++) {
			DPRINTF("Skipping question %d at %d\n", j, pos);
			i = __length_question(packet + pos, packet_len - pos);
			if (i < 0) {
				DPRINTF("Packet'question section " "is truncated, trying next server\n");
				goto try_next_server;
			}
			pos += i;
			DPRINTF("Length of question %d is %d\n", j, i);
		}
		DPRINTF("Decoding answer at pos %d\n", pos);

		first_answer = 1;
		a->dotted = NULL;
		for (j = 0; j < h.ancount; j++) {
			i = __decode_answer(packet, pos, packet_len, &ma);
			if (i < 0) {
				DPRINTF("failed decode %d\n", i);
				
				if (j && h.tc)
					break;
				goto try_next_server;
			}
			pos += i;

			if (first_answer) {
				ma.buf = a->buf;
				ma.buflen = a->buflen;
				ma.add_count = a->add_count;
				free(a->dotted);
				memcpy(a, &ma, sizeof(ma));
				if (a->atype != T_SIG && (NULL == a->buf || (type != T_A && type != T_AAAA)))
					break;
				if (a->atype != type)
					continue;
				a->add_count = h.ancount - j - 1;
				if ((a->rdlength + sizeof(struct in_addr*)) * a->add_count > a->buflen)
					break;
				a->add_count = 0;
				first_answer = 0;
			} else {
				free(ma.dotted);
				if (ma.atype != type)
					continue;
				if (a->rdlength != ma.rdlength) {
					free(a->dotted);
					DPRINTF("Answer address len(%u) differs from original(%u)\n", ma.rdlength, a->rdlength);
					goto try_next_server;
				}
				memcpy(a->buf + (a->add_count * ma.rdlength), ma.rdata, ma.rdlength);
				++a->add_count;
			}
		}

		
		DPRINTF("Answer name = |%s|\n", a->dotted);
		DPRINTF("Answer type = |%d|\n", a->atype);
		if (fd != -1)
			close(fd);
		if (outpacket)
			*outpacket = packet;
		else free(packet);
		free(lookup);
		return packet_len;

 try_next_server:
		
		retries_left--;
		local_ns_num++;
		variant = -1;
	} while (retries_left > 0);

 fail:
	h_errno = NETDB_INTERNAL;
 fail1:
	if (fd != -1)
		close(fd);
	free(lookup);
	free(packet);
	return -1;
}





parser_t * __open_etc_hosts(void)
{
	parser_t *parser;
	parser = config_open("/etc/hosts");

	if (parser == NULL)
		parser = config_open("/etc/config/hosts");

	return parser;
}






int __read_etc_hosts_r( parser_t * parser, const char *name, int type, enum etc_hosts_action action, struct hostent *result_buf, char *buf, size_t buflen, struct hostent **result, int *h_errnop)







{
	char **tok = NULL;
	struct in_addr *h_addr0 = NULL;
	const size_t aliaslen = INADDROFF +  sizeof(struct in6_addr)


							sizeof(struct in_addr)

							;
	int ret = HOST_NOT_FOUND;
	
	int i = ALIGN_BUFFER_OFFSET(buf);
	buf += i;
	buflen -= i;

	*h_errnop = NETDB_INTERNAL;
	if ( buflen < aliaslen || (buflen - aliaslen) < BUFSZ + 1)
		return ERANGE;
	if (parser == NULL)
		parser = __open_etc_hosts();
	if (parser == NULL) {
		*result = NULL;
		return errno;
	}
	
	parser->data = buf;
	parser->data_len = aliaslen;
	parser->line_len = buflen - aliaslen;
	*h_errnop = HOST_NOT_FOUND;
	
	while (config_read(parser, &tok, MAXTOKENS, MINTOKENS, "# \t", PARSE_NORMAL)) {
		result_buf->h_aliases = tok+1;
		if (action == GETHOSTENT) {
			
			;
		} else if (action == GET_HOSTS_BYADDR) {
			if (strcmp(name, *tok) != 0)
				continue;
		} else { 
			int aliases = 0;
			char **alias = tok + 1;
			while (aliases < MAXALIASES) {
				char *tmp = *(alias+aliases++);
				if (tmp && strcasecmp(name, tmp) == 0)
					goto found;
			}
			continue;
		}
found:
		result_buf->h_name = *(result_buf->h_aliases++);
		result_buf->h_addr_list = (char**)(buf + HALISTOFF);
		*(result_buf->h_addr_list + 1) = '\0';
		h_addr0 = (struct in_addr*)(buf + INADDROFF);
		result_buf->h_addr = (char*)h_addr0;
		if (0) ;

		else if (type == AF_INET && inet_pton(AF_INET, *tok, h_addr0) > 0) {
			DPRINTF("Found INET\n");
			result_buf->h_addrtype = AF_INET;
			result_buf->h_length = sizeof(struct in_addr);
			*result = result_buf;
			ret = NETDB_SUCCESS;
		}



		else if (type == AF_INET6 && inet_pton(AF_INET6, *tok, h_addr0) > 0) {
			DPRINTF("Found INET6\n");
			result_buf->h_addrtype = AF_INET6;
			result_buf->h_length = sizeof(struct in6_addr);
			*result = result_buf;
			ret = NETDB_SUCCESS;
		}

		else {
			
			DPRINTF("Error: Found host but different address family\n");
			
			ret = TRY_AGAIN;
			continue;
		}
		break;
	}
	if (action != GETHOSTENT)
		config_close(parser);
	return ret;

}





int __get_hosts_byname_r(const char *name, int type, struct hostent *result_buf, char *buf, size_t buflen, struct hostent **result, int *h_errnop)





{
	return __read_etc_hosts_r(NULL, name, type, GET_HOSTS_BYNAME, result_buf, buf, buflen, result, h_errnop);
}





int __get_hosts_byaddr_r(const char *addr, int len, int type, struct hostent *result_buf, char *buf, size_t buflen, struct hostent **result, int *h_errnop)






{

	char	ipaddr[INET_ADDRSTRLEN];

	char	ipaddr[INET6_ADDRSTRLEN];


	switch (type) {

		case AF_INET:
			if (len != sizeof(struct in_addr))
				return 0;
			break;


		case AF_INET6:
			if (len != sizeof(struct in6_addr))
				return 0;
			break;

		default:
			return 0;
	}

	inet_ntop(type, addr, ipaddr, sizeof(ipaddr));

	return __read_etc_hosts_r(NULL, ipaddr, type, GET_HOSTS_BYADDR, result_buf, buf, buflen, result, h_errnop);
}





int getnameinfo(const struct sockaddr *sa, socklen_t addrlen, char *host, socklen_t hostlen, char *serv, socklen_t servlen, unsigned flags)





{
	int serrno = errno;
	bool ok = 0;
	struct hostent *hoste = NULL;
	char domain[256];

	if (flags & ~(NI_NUMERICHOST|NI_NUMERICSERV|NI_NOFQDN|NI_NAMEREQD|NI_DGRAM))
		return EAI_BADFLAGS;

	if (sa == NULL || addrlen < sizeof(sa_family_t))
		return EAI_FAMILY;

	if ((flags & NI_NAMEREQD) && host == NULL && serv == NULL)
		return EAI_NONAME;

	if (sa->sa_family == AF_LOCAL) ;

	else if (sa->sa_family == AF_INET) {
		if (addrlen < sizeof(struct sockaddr_in))
			return EAI_FAMILY;
	}


	else if (sa->sa_family == AF_INET6) {
		if (addrlen < sizeof(struct sockaddr_in6))
			return EAI_FAMILY;
	}

	else return EAI_FAMILY;

	if (host != NULL && hostlen > 0)
		switch (sa->sa_family) {
		case AF_INET:

		case AF_INET6:

			if (!(flags & NI_NUMERICHOST)) {
				if (0) ;

				else if (sa->sa_family == AF_INET6)
					hoste = gethostbyaddr((const void *)
						&(((const struct sockaddr_in6 *) sa)->sin6_addr), sizeof(struct in6_addr), AF_INET6);


				else hoste = gethostbyaddr((const void *)
						&(((const struct sockaddr_in *)sa)->sin_addr), sizeof(struct in_addr), AF_INET);


				if (hoste) {
					char *c;
					if ((flags & NI_NOFQDN)
					 && (getdomainname(domain, sizeof(domain)) == 0)
					 && (c = strstr(hoste->h_name, domain)) != NULL && (c != hoste->h_name) && (*(--c) == '.')
					) {
						strncpy(host, hoste->h_name, MIN(hostlen, (size_t) (c - hoste->h_name)));
						host[MIN(hostlen - 1, (size_t) (c - hoste->h_name))] = '\0';
					} else {
						strncpy(host, hoste->h_name, hostlen);
					}
					ok = 1;
				}
			}

			if (!ok) {
				const char *c = NULL;

				if (flags & NI_NAMEREQD) {
					errno = serrno;
					return EAI_NONAME;
				}
				if (0) ;

				else if (sa->sa_family == AF_INET6) {
					const struct sockaddr_in6 *sin6p;

					sin6p = (const struct sockaddr_in6 *) sa;
					c = inet_ntop(AF_INET6, (const void *) &sin6p->sin6_addr, host, hostlen);


					
					uint32_t scopeid;
					scopeid = sin6p->sin6_scope_id;
					if (scopeid != 0) {
						
						char scopebuf[IFNAMSIZ + 1];
						char *scopeptr;
						int ni_numericscope = 0;
						size_t real_hostlen = strnlen(host, hostlen);
						size_t scopelen = 0;

						scopebuf[0] = SCOPE_DELIMITER;
						scopebuf[1] = '\0';
						scopeptr = &scopebuf[1];

						if (IN6_IS_ADDR_LINKLOCAL(&sin6p->sin6_addr)
						    || IN6_IS_ADDR_MC_LINKLOCAL(&sin6p->sin6_addr)) {
							if (if_indextoname(scopeid, scopeptr) == NULL)
								++ni_numericscope;
							else scopelen = strlen(scopebuf);
						} else {
							++ni_numericscope;
						}

						if (ni_numericscope)
							scopelen = 1 + snprintf(scopeptr, (scopebuf + sizeof scopebuf - scopeptr), "%u", scopeid);




						if (real_hostlen + scopelen + 1 > hostlen)
							return EAI_SYSTEM;
						memcpy(host + real_hostlen, scopebuf, scopelen + 1);
					}

				}


				else {
					c = inet_ntop(AF_INET, (const void *)
						&(((const struct sockaddr_in *) sa)->sin_addr), host, hostlen);
				}

				if (c == NULL) {
					errno = serrno;
					return EAI_SYSTEM;
				}
				ok = 1;
			}
			break;

		case AF_LOCAL:
			if (!(flags & NI_NUMERICHOST)) {
				struct utsname utsname;

				if (!uname(&utsname)) {
					strncpy(host, utsname.nodename, hostlen);
					break;
				};
			};

			if (flags & NI_NAMEREQD) {
				errno = serrno;
				return EAI_NONAME;
			}

			strncpy(host, "localhost", hostlen);
			break;

	}

	if (serv && (servlen > 0)) {
		if (sa->sa_family == AF_LOCAL) {
			strncpy(serv, ((const struct sockaddr_un *) sa)->sun_path, servlen);
		} else { 
			if (!(flags & NI_NUMERICSERV)) {
				struct servent *s;
				s = getservbyport(((const struct sockaddr_in *) sa)->sin_port, ((flags & NI_DGRAM) ? "udp" : "tcp"));
				if (s) {
					strncpy(serv, s->s_name, servlen);
					goto DONE;
				}
			}
			snprintf(serv, servlen, "%d", ntohs(((const struct sockaddr_in *) sa)->sin_port));
		}
	}
DONE:
	if (host && (hostlen > 0))
		host[hostlen-1] = 0;
	if (serv && (servlen > 0))
		serv[servlen-1] = 0;
	errno = serrno;
	return 0;
}
libc_hidden_def(getnameinfo)






int gethostbyname_r(const char *name, struct hostent *result_buf, char *buf, size_t buflen, struct hostent **result, int *h_errnop)




{
	struct in_addr **addr_list;
	char **alias;
	char *alias0;
	unsigned char *packet;
	struct resolv_answer a;
	int i;
	int packet_len;
	int wrong_af = 0;

	*result = NULL;
	if (!name)
		return EINVAL;

	
	{
		int old_errno = errno;  
		__set_errno(0);         
		i = __get_hosts_byname_r(name, AF_INET, result_buf, buf, buflen, result, h_errnop);
		if (i == NETDB_SUCCESS) {
			__set_errno(old_errno);
			return i;
		}
		switch (*h_errnop) {
			case HOST_NOT_FOUND:
				wrong_af = (i == TRY_AGAIN);
			case NO_ADDRESS:
				break;
			case NETDB_INTERNAL:
				if (errno == ENOENT) {
					break;
				}
				
			default:
				return i;
		}
		__set_errno(old_errno);
	}

	DPRINTF("Nothing found in /etc/hosts\n");

	*h_errnop = NETDB_INTERNAL;

	
	i = strlen(name) + 1;
	if ((ssize_t)buflen <= i)
		return ERANGE;
	memcpy(buf, name, i); 
	alias0 = buf;
	buf += i;
	buflen -= i;
	
	i = ALIGN_BUFFER_OFFSET(buf);
	buf += i;
	buflen -= i;
	
	alias = (char **)buf;
	buf += sizeof(alias[0]) * 2;
	buflen -= sizeof(alias[0]) * 2;
	addr_list = (struct in_addr **)buf;
	
	if ((ssize_t)buflen < 256)
		return ERANGE;

	
	alias[0] = alias0;
	alias[1] = NULL;

	
	{
		struct in_addr *in = (struct in_addr *)(buf + sizeof(addr_list[0]) * 2);
		if (inet_aton(name, in)) {
			addr_list[0] = in;
			addr_list[1] = NULL;
			result_buf->h_name = alias0;
			result_buf->h_aliases = alias;
			result_buf->h_addrtype = AF_INET;
			result_buf->h_length = sizeof(struct in_addr);
			result_buf->h_addr_list = (char **) addr_list;
			*result = result_buf;
			*h_errnop = NETDB_SUCCESS;
			return NETDB_SUCCESS;
		}
	}

	
	if (wrong_af) {
		*h_errnop = HOST_NOT_FOUND;
		return TRY_AGAIN;
	}

	
	a.buf = buf;
	
	a.buflen = buflen - ((sizeof(addr_list[0]) * 2 + sizeof(struct in_addr)));
	a.add_count = 0;
	packet_len = __dns_lookup(name, T_A, &packet, &a);
	if (packet_len < 0) {
		*h_errnop = HOST_NOT_FOUND;
		DPRINTF("__dns_lookup returned < 0\n");
		return TRY_AGAIN;
	}

	if (a.atype == T_A) { 
		
		
		int need_bytes = sizeof(addr_list[0]) * (a.add_count + 1 + 1)
				
				+ sizeof(struct in_addr);
		
		int ips_len = a.add_count * a.rdlength;

		buflen -= (need_bytes + ips_len);
		if ((ssize_t)buflen < 0) {
			DPRINTF("buffer too small for all addresses\n");
			
			i = ERANGE;
			goto free_and_ret;
		}

		
		DPRINTF("a.add_count:%d a.rdlength:%d a.rdata:%p\n", a.add_count, a.rdlength, a.rdata);
		memmove(buf + need_bytes, buf, ips_len);

		
		buf += need_bytes - sizeof(struct in_addr);
		memcpy(buf, a.rdata, sizeof(struct in_addr));

		
		for (i = 0; i <= a.add_count; i++) {
			addr_list[i] = (struct in_addr*)buf;
			buf += sizeof(struct in_addr);
		}
		addr_list[i] = NULL;

		
		if (a.dotted && buflen > strlen(a.dotted)) {
			strcpy(buf, a.dotted);
			alias0 = buf;
		}

		result_buf->h_name = alias0;
		result_buf->h_aliases = alias;
		result_buf->h_addrtype = AF_INET;
		result_buf->h_length = sizeof(struct in_addr);
		result_buf->h_addr_list = (char **) addr_list;
		*result = result_buf;
		*h_errnop = NETDB_SUCCESS;
		i = NETDB_SUCCESS;
		goto free_and_ret;
	}

	*h_errnop = HOST_NOT_FOUND;
	__set_h_errno(HOST_NOT_FOUND);
	i = TRY_AGAIN;

 free_and_ret:
	free(a.dotted);
	free(packet);
	return i;
}
libc_hidden_def(gethostbyname_r)





int gethostbyname2_r(const char *name, int family, struct hostent *result_buf, char *buf, size_t buflen, struct hostent **result, int *h_errnop)





{

	return family == (AF_INET)
		? gethostbyname_r(name, result_buf, buf, buflen, result, h_errnop)
		: HOST_NOT_FOUND;

	struct in6_addr **addr_list;
	char **alias;
	char *alias0;
	unsigned char *packet;
	struct resolv_answer a;
	int i;
	int packet_len;
	int wrong_af = 0;

	if (family == AF_INET)
		return gethostbyname_r(name, result_buf, buf, buflen, result, h_errnop);

	*result = NULL;
	if (family != AF_INET6)
		return EINVAL;

	if (!name)
		return EINVAL;

	
	{
		int old_errno = errno;  
		__set_errno(0);         
		i = __get_hosts_byname_r(name, AF_INET6 , result_buf, buf, buflen, result, h_errnop);
		if (i == NETDB_SUCCESS) {
			__set_errno(old_errno);
			return i;
		}
		switch (*h_errnop) {
			case HOST_NOT_FOUND:
				wrong_af = (i == TRY_AGAIN);
			case NO_ADDRESS:
				break;
			case NETDB_INTERNAL:
				if (errno == ENOENT) {
					break;
				}
				
			default:
				return i;
		}
		__set_errno(old_errno);
	}

	DPRINTF("Nothing found in /etc/hosts\n");

	*h_errnop = NETDB_INTERNAL;

	
	i = strlen(name) + 1;
	if ((ssize_t)buflen <= i)
		return ERANGE;
	memcpy(buf, name, i); 
	alias0 = buf;
	buf += i;
	buflen -= i;
	
	i = ALIGN_BUFFER_OFFSET(buf);
	buf += i;
	buflen -= i;
	
	alias = (char **)buf;
	buf += sizeof(alias[0]) * 2;
	buflen -= sizeof(alias[0]) * 2;
	addr_list = (struct in6_addr **)buf;
	
	if ((ssize_t)buflen < 256)
		return ERANGE;

	
	alias[0] = alias0;
	alias[1] = NULL;

	
	{
		struct in6_addr *in = (struct in6_addr *)(buf + sizeof(addr_list[0]) * 2);
		if (inet_pton(AF_INET6, name, in)) {
			addr_list[0] = in;
			addr_list[1] = NULL;
			result_buf->h_name = alias0;
			result_buf->h_aliases = alias;
			result_buf->h_addrtype = AF_INET6;
			result_buf->h_length = sizeof(struct in6_addr);
			result_buf->h_addr_list = (char **) addr_list;
			*result = result_buf;
			*h_errnop = NETDB_SUCCESS;
			return NETDB_SUCCESS;
		}
	}

	
	if (wrong_af) {
		*h_errnop = HOST_NOT_FOUND;
		return TRY_AGAIN;
	}

	
	a.buf = buf;
	
	a.buflen = buflen - ((sizeof(addr_list[0]) * 2 + sizeof(struct in6_addr)));
	a.add_count = 0;
	packet_len = __dns_lookup(name, T_AAAA, &packet, &a);
	if (packet_len < 0) {
		*h_errnop = HOST_NOT_FOUND;
		DPRINTF("__dns_lookup returned < 0\n");
		return TRY_AGAIN;
	}

	if (a.atype == T_AAAA) { 
		
		
		int need_bytes = sizeof(addr_list[0]) * (a.add_count + 1 + 1)
				
				+ sizeof(struct in6_addr);
		
		int ips_len = a.add_count * a.rdlength;

		buflen -= (need_bytes + ips_len);
		if ((ssize_t)buflen < 0) {
			DPRINTF("buffer too small for all addresses\n");
			
			i = ERANGE;
			goto free_and_ret;
		}

		
		DPRINTF("a.add_count:%d a.rdlength:%d a.rdata:%p\n", a.add_count, a.rdlength, a.rdata);
		memmove(buf + need_bytes, buf, ips_len);

		
		buf += need_bytes - sizeof(struct in6_addr);
		memcpy(buf, a.rdata, sizeof(struct in6_addr));

		
		for (i = 0; i <= a.add_count; i++) {
			addr_list[i] = (struct in6_addr*)buf;
			buf += sizeof(struct in6_addr);
		}
		addr_list[i] = NULL;

		
		if (a.dotted && buflen > strlen(a.dotted)) {
			strcpy(buf, a.dotted);
			alias0 = buf;
		}

		result_buf->h_name = alias0;
		result_buf->h_aliases = alias;
		result_buf->h_addrtype = AF_INET6;
		result_buf->h_length = sizeof(struct in6_addr);
		result_buf->h_addr_list = (char **) addr_list;
		*result = result_buf;
		*h_errnop = NETDB_SUCCESS;
		i = NETDB_SUCCESS;
		goto free_and_ret;
	}

	*h_errnop = HOST_NOT_FOUND;
	__set_h_errno(HOST_NOT_FOUND);
	i = TRY_AGAIN;

 free_and_ret:
	free(a.dotted);
	free(packet);
	return i;

}
libc_hidden_def(gethostbyname2_r)





int gethostbyaddr_r(const void *addr, socklen_t addrlen, int type, struct hostent *result_buf, char *buf, size_t buflen, struct hostent **result, int *h_errnop)





{
	struct in_addr *in;
	struct in_addr **addr_list;
	char **alias;
	unsigned char *packet;
	struct resolv_answer a;
	int i;
	int packet_len;
	int nest = 0;

	*result = NULL;
	if (!addr)
		return EINVAL;

	switch (type) {

		case AF_INET:
			if (addrlen != sizeof(struct in_addr))
				return EINVAL;
			break;


		case AF_INET6:
			if (addrlen != sizeof(struct in6_addr))
				return EINVAL;
			break;

		default:
			return EINVAL;
	}

	
	i = __get_hosts_byaddr_r(addr, addrlen, type, result_buf, buf, buflen, result, h_errnop);
	if (i == 0)
		return i;
	switch (*h_errnop) {
		case HOST_NOT_FOUND:
		case NO_ADDRESS:
			break;
		default:
			return i;
	}

	*h_errnop = NETDB_INTERNAL;

	
	i = ALIGN_BUFFER_OFFSET(buf);
	buf += i;
	buflen -= i;
	

	alias = (char **)buf;
	addr_list = (struct in_addr**)buf;
	buf += sizeof(*addr_list) * 2;
	buflen -= sizeof(*addr_list) * 2;
	in = (struct in_addr*)buf;

	buf += sizeof(*in);
	buflen -= sizeof(*in);
	if (addrlen > sizeof(*in))
		return ERANGE;

	buf += sizeof(*in6);
	buflen -= sizeof(*in6);
	if (addrlen > sizeof(*in6))
		return ERANGE;

	if ((ssize_t)buflen < 256)
		return ERANGE;
	alias[0] = buf;
	alias[1] = NULL;
	addr_list[0] = in;
	addr_list[1] = NULL;
	memcpy(in, addr, addrlen);

	if (0) ;

	else IF_HAS_BOTH(if (type == AF_INET)) {
		unsigned char *tp = (unsigned char *)addr;
		sprintf(buf, "%u.%u.%u.%u.in-addr.arpa", tp[3], tp[2], tp[1], tp[0]);
	}


	else {
		char *dst = buf;
		unsigned char *tp = (unsigned char *)addr + addrlen - 1;
		do {
			dst += sprintf(dst, "%x.%x.", tp[0] & 0xf, tp[0] >> 4);
			tp--;
		} while (tp >= (unsigned char *)addr);
		strcpy(dst, "ip6.arpa");
	}


	memset(&a, '\0', sizeof(a));
	for (;;) {

		packet_len = __dns_lookup(buf, T_PTR, &packet, &a);
		if (packet_len < 0) {
			*h_errnop = HOST_NOT_FOUND;
			return TRY_AGAIN;
		}

		strncpy(buf, a.dotted, buflen);
		free(a.dotted);
		if (a.atype != T_CNAME)
			break;

		DPRINTF("Got a CNAME in gethostbyaddr()\n");
		if (++nest > MAX_RECURSE) {
			*h_errnop = NO_RECOVERY;
			return -1;
		}
		
		i = __decode_dotted(packet, a.rdoffset, packet_len, buf, buflen);
		free(packet);
		if (i < 0) {
			*h_errnop = NO_RECOVERY;
			return -1;
		}
	}

	if (a.atype == T_PTR) {	
		i = __decode_dotted(packet, a.rdoffset, packet_len, buf, buflen);
		free(packet);
		result_buf->h_name = buf;
		result_buf->h_addrtype = type;
		result_buf->h_length = addrlen;
		result_buf->h_addr_list = (char **) addr_list;
		result_buf->h_aliases = alias;
		*result = result_buf;
		*h_errnop = NETDB_SUCCESS;
		return NETDB_SUCCESS;
	}

	free(packet);
	*h_errnop = NO_ADDRESS;
	return TRY_AGAIN;

}
libc_hidden_def(gethostbyaddr_r)





__UCLIBC_MUTEX_STATIC(mylock, PTHREAD_MUTEX_INITIALIZER);

static parser_t *hostp = NULL;
static smallint host_stayopen;

void endhostent_unlocked(void)
{
	if (hostp) {
		config_close(hostp);
		hostp = NULL;
	}
	host_stayopen = 0;
}
void endhostent(void)
{
	__UCLIBC_MUTEX_LOCK(mylock);
	endhostent_unlocked();
	__UCLIBC_MUTEX_UNLOCK(mylock);
}

void sethostent(int stay_open)
{
	__UCLIBC_MUTEX_LOCK(mylock);
	if (stay_open)
		host_stayopen = 1;
	__UCLIBC_MUTEX_UNLOCK(mylock);
}

int gethostent_r(struct hostent *result_buf, char *buf, size_t buflen, struct hostent **result, int *h_errnop)
{
	int ret;

	__UCLIBC_MUTEX_LOCK(mylock);
	if (hostp == NULL) {
		hostp = __open_etc_hosts();
		if (hostp == NULL) {
			*result = NULL;
			ret = TRY_AGAIN;
			goto DONE;
		}
	}

	ret = __read_etc_hosts_r(hostp, NULL, AF_INET, GETHOSTENT, result_buf, buf, buflen, result, h_errnop);
	if (!host_stayopen)
		endhostent_unlocked();
DONE:
	__UCLIBC_MUTEX_UNLOCK(mylock);
	return ret;
}
libc_hidden_def(gethostent_r)




 #define GETXX_BUFSZ 	(sizeof(struct in_addr) + sizeof(struct in_addr *) * 2 +  + 384 + 32

 #define GETXX_BUFSZ 	(sizeof(struct in6_addr) + sizeof(struct in6_addr *) * 2 +  + 384 + 32







struct hostent *gethostent(void)
{
	static struct hostent hoste;
	static char *buf = NULL;
	struct hostent *host = NULL;

 #define HOSTENT_BUFSZ	(sizeof(struct in_addr) + sizeof(struct in_addr *) * 2 +  sizeof(char *)*ALIAS_DIM + BUFSZ  + 2

 #define HOSTENT_BUFSZ	(sizeof(struct in6_addr) + sizeof(struct in6_addr *) * 2 +  sizeof(char *)*ALIAS_DIM + BUFSZ  + 2


	__INIT_GETXX_BUF(HOSTENT_BUFSZ);
	gethostent_r(&hoste, buf, HOSTENT_BUFSZ, &host, &h_errno);
	return host;
}






struct hostent *gethostbyname2(const char *name, int family)
{
	static struct hostent hoste;
	static char *buf = NULL;
	struct hostent *hp;

	__INIT_GETXX_BUF(GETXX_BUFSZ);

	if (family != AF_INET)
		return (struct hostent*)NULL;
	gethostbyname_r(name, &hoste, buf, GETXX_BUFSZ, &hp, &h_errno);

	gethostbyname2_r(name, family, &hoste, buf, GETXX_BUFSZ, &hp, &h_errno);


	return hp;
}
libc_hidden_def(gethostbyname2)





struct hostent *gethostbyname(const char *name)
{
	return gethostbyname2(name, AF_INET);
}
libc_hidden_def(gethostbyname)





struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type)
{
	static struct hostent hoste;
	static char *buf = NULL;
	struct hostent *hp;

	__INIT_GETXX_BUF(GETXX_BUFSZ);
	gethostbyaddr_r(addr, len, type, &hoste, buf, GETXX_BUFSZ, &hp, &h_errno);
	return hp;
}
libc_hidden_def(gethostbyaddr)






int dn_expand(const u_char *msg, const u_char *eom, const u_char *src, char *dst, int dstsiz)
{
	int n = ns_name_uncompress(msg, eom, src, dst, (size_t)dstsiz);

	if (n > 0 && dst[0] == '.')
		dst[0] = '\0';
	return n;
}
libc_hidden_def(dn_expand)


int dn_comp(const char *src, u_char *dst, int dstsiz, u_char **dnptrs, u_char **lastdnptr)

{
	return ns_name_compress(src, dst, (size_t) dstsiz, (const u_char **) dnptrs, (const u_char **) lastdnptr);

}
libc_hidden_def(dn_comp)






static int printable(int ch)
{
	return (ch > 0x20 && ch < 0x7f);
}

static int special(int ch)
{
	switch (ch) {
		case 0x22: 
		case 0x2E: 
		case 0x3B: 
		case 0x5C: 
			
		case 0x40: 
		case 0x24: 
			return 1;
		default:
			return 0;
	}
}


int ns_name_uncompress(const u_char *msg, const u_char *eom, const u_char *src, char *dst, size_t dstsiz)
{
	u_char tmp[NS_MAXCDNAME];
	int n;

	n = ns_name_unpack(msg, eom, src, tmp, sizeof tmp);
	if (n == -1)
		return -1;
	if (ns_name_ntop(tmp, dst, dstsiz) == -1)
		return -1;
	return n;
}
libc_hidden_def(ns_name_uncompress)


int ns_name_ntop(const u_char *src, char *dst, size_t dstsiz)
{
	const u_char *cp;
	char *dn, *eom;
	u_char c;
	u_int n;

	cp = src;
	dn = dst;
	eom = dst + dstsiz;

	while ((n = *cp++) != 0) {
		if ((n & NS_CMPRSFLGS) != 0) {
			
			__set_errno(EMSGSIZE);
			return -1;
		}
		if (dn != dst) {
			if (dn >= eom) {
				__set_errno(EMSGSIZE);
				return -1;
			}
			*dn++ = '.';
		}
		if (dn + n >= eom) {
			__set_errno(EMSGSIZE);
			return -1;
		}
		for (; n > 0; n--) {
			c = *cp++;
			if (special(c)) {
				if (dn + 1 >= eom) {
					__set_errno(EMSGSIZE);
					return -1;
				}
				*dn++ = '\\';
				*dn++ = (char)c;
			} else if (!printable(c)) {
				if (dn + 3 >= eom) {
					__set_errno(EMSGSIZE);
					return -1;
				}
				*dn++ = '\\';
				*dn++ = "0123456789"[c / 100];
				c = c % 100;
				*dn++ = "0123456789"[c / 10];
				*dn++ = "0123456789"[c % 10];
			} else {
				if (dn >= eom) {
					__set_errno(EMSGSIZE);
					return -1;
				}
				*dn++ = (char)c;
			}
		}
	}
	if (dn == dst) {
		if (dn >= eom) {
			__set_errno(EMSGSIZE);
			return -1;
		}
		*dn++ = '.';
	}
	if (dn >= eom) {
		__set_errno(EMSGSIZE);
		return -1;
	}
	*dn++ = '\0';
	return (dn - dst);
}
libc_hidden_def(ns_name_ntop)

static int encode_bitstring(const char **bp, const char *end, unsigned char **labelp, unsigned char ** dst, unsigned const char *eom)


{
	int afterslash = 0;
	const char *cp = *bp;
	unsigned char *tp;
	const char *beg_blen;
	int value = 0, count = 0, tbcount = 0, blen = 0;

	beg_blen = NULL;

	
	if (end - cp < 2)
		return EINVAL;

	
	if (*cp++ != 'x')
		return EINVAL;
	if (!isxdigit((unsigned char) *cp)) 
		return EINVAL;

	for (tp = *dst + 1; cp < end && tp < eom; cp++) {
		unsigned char c = *cp;

		switch (c) {
		case ']':       
			if (afterslash) {
				char *end_blen;
				if (beg_blen == NULL)
					return EINVAL;
				blen = (int)strtol(beg_blen, &end_blen, 10);
				if (*end_blen != ']')
					return EINVAL;
			}
			if (count)
				*tp++ = ((value << 4) & 0xff);
			cp++;   
			goto done;
		case '/':
			afterslash = 1;
			break;
		default:
			if (afterslash) {
				if (!__isdigit_char(c))
					return EINVAL;
				if (beg_blen == NULL) {
					if (c == '0') {
						
						return EINVAL;
					}
					beg_blen = cp;
				}
			} else {
				if (!__isdigit_char(c)) {
					c = c | 0x20; 
					c = c - 'a';
					if (c > 5) 
						return EINVAL;
					c += 10 + '0';
				}
				value <<= 4;
				value += (c - '0');
				count += 4;
				tbcount += 4;
				if (tbcount > 256)
					return EINVAL;
				if (count == 8) {
					*tp++ = value;
					count = 0;
				}
			}
			break;
		}
	}
  done:
	if (cp >= end || tp >= eom)
		return EMSGSIZE;

	
	if (blen > 0) {
		int traillen;

		if (((blen + 3) & ~3) != tbcount)
			return EINVAL;
		traillen = tbcount - blen; 
		if (((value << (8 - traillen)) & 0xff) != 0)
			return EINVAL;
	}
	else blen = tbcount;
	if (blen == 256)
		blen = 0;

	
	**labelp = DNS_LABELTYPE_BITSTRING;
	**dst = blen;

	*bp = cp;
	*dst = tp;

	return 0;
}

int ns_name_pton(const char *src, u_char *dst, size_t dstsiz)
{
	static const char digits[] = "0123456789";
	u_char *label, *bp, *eom;
	int c, n, escaped, e = 0;
	char *cp;

	escaped = 0;
	bp = dst;
	eom = dst + dstsiz;
	label = bp++;

	while ((c = *src++) != 0) {
		if (escaped) {
			if (c == '[') { 
				cp = strchr(src, ']');
				if (cp == NULL) {
					errno = EINVAL; 
					return -1;
				}
				e = encode_bitstring(&src, cp + 2, &label, &bp, eom);
				if (e != 0) {
					errno = e;
					return -1;
				}
				escaped = 0;
				label = bp++;
				c = *src++;
				if (c == '\0')
					goto done;
				if (c != '.') {
					errno = EINVAL;
					return -1;
				}
				continue;
			}
			cp = strchr(digits, c);
			if (cp != NULL) {
				n = (cp - digits) * 100;
				c = *src++;
				if (c == '\0')
					goto ret_EMSGSIZE;
				cp = strchr(digits, c);
				if (cp == NULL)
					goto ret_EMSGSIZE;
				n += (cp - digits) * 10;
				c = *src++;
				if (c == '\0')
					goto ret_EMSGSIZE;
				cp = strchr(digits, c);
				if (cp == NULL)
					goto ret_EMSGSIZE;
				n += (cp - digits);
				if (n > 255)
					goto ret_EMSGSIZE;
				c = n;
			}
			escaped = 0;
		} else if (c == '\\') {
			escaped = 1;
			continue;
		} else if (c == '.') {
			c = (bp - label - 1);
			if ((c & NS_CMPRSFLGS) != 0) {  
				goto ret_EMSGSIZE;
			}
			if (label >= eom) {
				goto ret_EMSGSIZE;
			}
			*label = c;
			
			if (*src == '\0') {
				if (c != 0) {
					if (bp >= eom) {
						goto ret_EMSGSIZE;
					}
					*bp++ = '\0';
				}
				if ((bp - dst) > MAXCDNAME) {
					goto ret_EMSGSIZE;
				}

				return 1;
			}
			if (c == 0 || *src == '.') {
				goto ret_EMSGSIZE;
			}
			label = bp++;
			continue;
		}
		if (bp >= eom) {
			goto ret_EMSGSIZE;
		}
		*bp++ = (u_char)c;
	}
	c = (bp - label - 1);
	if ((c & NS_CMPRSFLGS) != 0) {	  
		goto ret_EMSGSIZE;
	}
 done:
	if (label >= eom) {
		goto ret_EMSGSIZE;
	}
	*label = c;
	if (c != 0) {
		if (bp >= eom) {
			goto ret_EMSGSIZE;
		}
		*bp++ = 0;
	}
	if ((bp - dst) > MAXCDNAME) {   
		goto ret_EMSGSIZE;
	}

	return 0;

 ret_EMSGSIZE:
	errno = EMSGSIZE;
	return -1;
}
libc_hidden_def(ns_name_pton)


int ns_name_unpack(const u_char *msg, const u_char *eom, const u_char *src, u_char *dst, size_t dstsiz)
{
	const u_char *srcp, *dstlim;
	u_char *dstp;
	int n, len, checked;

	len = -1;
	checked = 0;
	dstp = dst;
	srcp = src;
	dstlim = dst + dstsiz;
	if (srcp < msg || srcp >= eom) {
		__set_errno(EMSGSIZE);
		return -1;
	}
	
	while ((n = *srcp++) != 0) {
		
		switch (n & NS_CMPRSFLGS) {
			case 0:
				
				if (dstp + n + 1 >= dstlim || srcp + n >= eom) {
					__set_errno(EMSGSIZE);
					return -1;
				}
				checked += n + 1;
				*dstp++ = n;
				memcpy(dstp, srcp, n);
				dstp += n;
				srcp += n;
				break;

			case NS_CMPRSFLGS:
				if (srcp >= eom) {
					__set_errno(EMSGSIZE);
					return -1;
				}
				if (len < 0)
					len = srcp - src + 1;
				srcp = msg + (((n & 0x3f) << 8) | (*srcp & 0xff));
				if (srcp < msg || srcp >= eom) {  
					__set_errno(EMSGSIZE);
					return -1;
				}
				checked += 2;
				
				if (checked >= eom - msg) {
					__set_errno(EMSGSIZE);
					return -1;
				}
				break;

			default:
				__set_errno(EMSGSIZE);
				return -1;                    
		}
	}
	*dstp = '\0';
	if (len < 0)
		len = srcp - src;
	return len;
}
libc_hidden_def(ns_name_unpack)

static int labellen(const unsigned char *lp)
{
	unsigned bitlen;
	unsigned char l = *lp;

	if ((l & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
		
		return -1;
	}

	if ((l & NS_CMPRSFLGS) == NS_TYPE_ELT) {
		if (l == DNS_LABELTYPE_BITSTRING) {
			bitlen = lp[1];
			if (bitlen == 0)
				bitlen = 256;
			return ((bitlen + 7 ) / 8 + 1);
		}

		return -1;    
	}

	return l;
}

static int mklower(int ch)
{
	if (ch >= 0x41 && ch <= 0x5A)
		return (ch + 0x20);

	return ch;
}

static int dn_find(const unsigned char *domain, const unsigned char *msg, const unsigned char * const *dnptrs, const unsigned char * const *lastdnptr)


{
	const unsigned char *dn, *cp, *sp;
	const unsigned char * const *cpp;
	u_int n;

	for (cpp = dnptrs; cpp < lastdnptr; cpp++) {
		sp = *cpp;
		
		while (*sp != 0 && (*sp & NS_CMPRSFLGS) == 0 && (sp - msg) < 0x4000) {
			dn = domain;
			cp = sp;

			while ((n = *cp++) != 0) {
				
				switch (n & NS_CMPRSFLGS) {
				case 0:	 
					n = labellen(cp - 1); 
					if (n != *dn++)
						goto next;

					for (; n > 0; n--)
						if (mklower(*dn++) != mklower(*cp++))
							goto next;
					
					if (*dn == '\0' && *cp == '\0')
						return (sp - msg);
					if (*dn)
						continue;
					goto next;
				case NS_CMPRSFLGS:      
					cp = msg + (((n & 0x3f) << 8) | *cp);
					break;

				default:	
					errno = EMSGSIZE;
					return -1;
				}
			}
next:
			sp += *sp + 1;
		}
	}

	errno = ENOENT;
	return -1;
}

int ns_name_pack(const unsigned char *src, unsigned char *dst, int dstsiz, const unsigned char **dnptrs, const unsigned char **lastdnptr)


{
	unsigned char *dstp;
	const unsigned char **cpp, **lpp, *eob, *msg;
	const unsigned char *srcp;
	int n, l, first = 1;

	srcp = src;
	dstp = dst;
	eob = dstp + dstsiz;
	lpp = cpp = NULL;

	if (dnptrs != NULL) {
		msg = *dnptrs++;
		if (msg != NULL) {
			for (cpp = dnptrs; *cpp != NULL; cpp++)
				continue;

			lpp = cpp;      
		}
	} else {
		msg = NULL;
	}

	
	l = 0;
	do {
		int l0;

		n = *srcp;
		if ((n & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
			errno = EMSGSIZE;
			return -1;
		}

		l0 = labellen(srcp);
		if (l0 < 0) {
			errno = EINVAL;
			return -1;
		}

		l += l0 + 1;
		if (l > MAXCDNAME) {
			errno = EMSGSIZE;
			return -1;
		}

		srcp += l0 + 1;
	} while (n != 0);

	
	srcp = src;

	do {
		
		n = *srcp;

		if (n != 0 && msg != NULL) {
			l = dn_find(srcp, msg, (const unsigned char * const *) dnptrs, (const unsigned char * const *) lpp);
			if (l >= 0) {
				if (dstp + 1 >= eob) {
					goto cleanup;
				}

				*dstp++ = ((u_int32_t)l >> 8) | NS_CMPRSFLGS;
				*dstp++ = l % 256;
				return (dstp - dst);
			}

			
			if (lastdnptr != NULL && cpp < lastdnptr - 1 && (dstp - msg) < 0x4000 && first) {
				*cpp++ = dstp;
				*cpp = NULL;
				first = 0;
			}
		}

		
		if ((n & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
			
			goto cleanup;
		}

		n = labellen(srcp);
		if (dstp + 1 + n >= eob) {
			goto cleanup;
		}

		memcpy(dstp, srcp, (size_t)(n + 1));
		srcp += n + 1;
		dstp += n + 1;
	} while (n != 0);

	if (dstp > eob) {
cleanup:
		if (msg != NULL)
			*lpp = NULL;

			errno = EMSGSIZE;
			return -1;
	}

	return dstp - dst;
}
libc_hidden_def(ns_name_pack)

int ns_name_compress(const char *src, unsigned char *dst, size_t dstsiz, const unsigned char **dnptrs, const unsigned char **lastdnptr)


{
	unsigned char tmp[NS_MAXCDNAME];

	if (ns_name_pton(src, tmp, sizeof(tmp)) == -1)
		return -1;

	return ns_name_pack(tmp, dst, dstsiz, dnptrs, lastdnptr);
}
libc_hidden_def(ns_name_compress)

int ns_name_skip(const unsigned char **ptrptr, const unsigned char *eom)
{
	const unsigned char *cp;
	u_int n;
	int l;

	cp = *ptrptr;
	while (cp < eom && (n = *cp++) != 0) {
		
		switch (n & NS_CMPRSFLGS) {
		case 0:		 
			cp += n;
			continue;
		case NS_TYPE_ELT: 
			l = labellen(cp - 1);
			if (l < 0) {
				errno = EMSGSIZE; 
				return -1;
			}
			cp += l;
			continue;
		case NS_CMPRSFLGS:      
			cp++;
			break;
		default:		
			errno = EMSGSIZE;
			return -1;
		}

		break;
	}

	if (cp > eom) {
		errno = EMSGSIZE;
		return -1;
	}

	*ptrptr = cp;

	return 0;
}
libc_hidden_def(ns_name_skip)

int dn_skipname(const unsigned char *ptr, const unsigned char *eom)
{
	const unsigned char *saveptr = ptr;

	if (ns_name_skip(&ptr, eom) == -1)
		return -1;

	return ptr - saveptr;
}
libc_hidden_def(dn_skipname)






static void res_sync_func(void)
{
	struct __res_state *rp = &(_res);
	int n;

	
	if (__nameserver != (void*) &__local_nameserver) {
		

		if (__nameservers > rp->_u._ext.nscount)
			__nameservers = rp->_u._ext.nscount;
		n = __nameservers;
		while (--n >= 0)
			__nameserver[n].sa6 = *rp->_u._ext.nsaddrs[n]; 

		if (__nameservers > rp->nscount)
			__nameservers = rp->nscount;
		n = __nameservers;
		while (--n >= 0)
			__nameserver[n].sa4 = rp->nsaddr_list[n]; 

	}
	__resolv_timeout = rp->retrans ? : RES_TIMEOUT;
	__resolv_attempts = rp->retry ? : RES_DFLRETRY;
	
}


static int __res_vinit(res_state rp, int preinit)
{
	int i, n, options, retrans, retry, ndots;

	int m = 0;


	__close_nameservers();
	__open_nameservers();

	if (preinit) {
		options = rp->options;
		retrans = rp->retrans;
		retry = rp->retry;
		ndots = rp->ndots;
	}

	memset(rp, 0, sizeof(*rp));

	if (!preinit) {
		rp->options = RES_DEFAULT;
		rp->retrans = RES_TIMEOUT;
		rp->retry = RES_DFLRETRY;
		rp->ndots = 1;
	} else {
		rp->options = options;
		rp->retrans = retrans;
		rp->retry = retry;
		rp->ndots = ndots;
	}


	
	


	rp->_vcsock = -1;


	n = __searchdomains;
	if (n > ARRAY_SIZE(rp->dnsrch))
		n = ARRAY_SIZE(rp->dnsrch);
	for (i = 0; i < n; i++)
		rp->dnsrch[i] = __searchdomain[i];

	
	i = 0;

	n = 0;
	while (n < ARRAY_SIZE(rp->nsaddr_list) && i < __nameservers) {
		if (__nameserver[i].sa.sa_family == AF_INET) {
			rp->nsaddr_list[n] = __nameserver[i].sa4; 

			if (m < ARRAY_SIZE(rp->_u._ext.nsaddrs)) {
				rp->_u._ext.nsaddrs[m] = (void*) &rp->nsaddr_list[n];
				m++;
			}

			n++;
		}

		if (__nameserver[i].sa.sa_family == AF_INET6 && m < ARRAY_SIZE(rp->_u._ext.nsaddrs)
		) {
			struct sockaddr_in6 *sa6 = malloc(sizeof(*sa6));
			if (sa6) {
				*sa6 = __nameserver[i].sa6; 
				rp->_u._ext.nsaddrs[m] = sa6;
				m++;
			}
		}

		i++;
	}
	rp->nscount = n;

	rp->_u._ext.nscount = m;



	while (m < ARRAY_SIZE(rp->_u._ext.nsaddrs) && i < __nameservers) {
		struct sockaddr_in6 *sa6 = malloc(sizeof(*sa6));
		if (sa6) {
			*sa6 = __nameserver[i].sa6; 
			rp->_u._ext.nsaddrs[m] = sa6;
			m++;
		}
		i++;
	}
	rp->_u._ext.nscount = m;


	rp->options |= RES_INIT;

	return 0;
}

static unsigned int res_randomid(void)
{
	return 0xffff & getpid();
}


int res_init(void)
{
	

	__UCLIBC_MUTEX_LOCK(__resolv_lock);

	if (!_res.retrans)
		_res.retrans = RES_TIMEOUT;
	if (!_res.retry)
		_res.retry = 4;
	if (!(_res.options & RES_INIT))
		_res.options = RES_DEFAULT;

	
	if (!_res.id)
		_res.id = res_randomid();

	__res_sync = NULL;
	__res_vinit(&_res, 1);
	__res_sync = res_sync_func;

	__UCLIBC_MUTEX_UNLOCK(__resolv_lock);

	return 0;
}
libc_hidden_def(res_init)

static void __res_iclose(res_state statp)
{
	struct __res_state * rp = statp;
	__UCLIBC_MUTEX_LOCK(__resolv_lock);
	if (rp == NULL)
		rp = __res_state();
	__close_nameservers();
	__res_sync = NULL;

	{
		char *p1 = (char*) &(rp->nsaddr_list[0]);
		unsigned int m = 0;
		
		while (m < ARRAY_SIZE(rp->_u._ext.nsaddrs)) {
			char *p2 = (char*)(rp->_u._ext.nsaddrs[m++]);
			if (p2 < p1 || (p2 - p1) > (signed)sizeof(rp->nsaddr_list))
				free(p2);
		}
	}

	memset(rp, 0, sizeof(struct __res_state));
	__UCLIBC_MUTEX_UNLOCK(__resolv_lock);
}



void res_nclose(res_state statp)
{
	__res_iclose(statp);
}


void res_close(void)
{
	__res_iclose(NULL);
}





static const char Base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char Pad64 = '=';



int b64_ntop(u_char const *src, size_t srclength, char *target, size_t targsize) {
	size_t datalength = 0;
	u_char input[3];
	u_char output[4];
	size_t i;

	while (2 < srclength) {
		input[0] = *src++;
		input[1] = *src++;
		input[2] = *src++;
		srclength -= 3;

		output[0] = input[0] >> 2;
		output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
		output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);
		output[3] = input[2] & 0x3f;
		Assert(output[0] < 64);
		Assert(output[1] < 64);
		Assert(output[2] < 64);
		Assert(output[3] < 64);

		if (datalength + 4 > targsize)
			return (-1);
		target[datalength++] = Base64[output[0]];
		target[datalength++] = Base64[output[1]];
		target[datalength++] = Base64[output[2]];
		target[datalength++] = Base64[output[3]];
	}

	
	if (0 != srclength) {
		
		input[0] = input[1] = input[2] = '\0';
		for (i = 0; i < srclength; i++)
			input[i] = *src++;

		output[0] = input[0] >> 2;
		output[1] = ((input[0] & 0x03) << 4) + (input[1] >> 4);
		output[2] = ((input[1] & 0x0f) << 2) + (input[2] >> 6);
		Assert(output[0] < 64);
		Assert(output[1] < 64);
		Assert(output[2] < 64);

		if (datalength + 4 > targsize)
			return (-1);
		target[datalength++] = Base64[output[0]];
		target[datalength++] = Base64[output[1]];
		if (srclength == 1)
			target[datalength++] = Pad64;
		else target[datalength++] = Base64[output[2]];
		target[datalength++] = Pad64;
	}
	if (datalength >= targsize)
		return (-1);
	target[datalength] = '\0';	
	return (datalength);
}




int b64_pton (char const *src, u_char *target, size_t targsize)
{
	int tarindex, state, ch;
	char *pos;

	state = 0;
	tarindex = 0;

	while ((ch = *src++) != '\0') {
		if (isspace(ch))	
			continue;

		if (ch == Pad64)
			break;

		pos = strchr(Base64, ch);
		if (pos == 0) 		
			return (-1);

		switch (state) {
		case 0:
			if (target) {
				if ((size_t)tarindex >= targsize)
					return (-1);
				target[tarindex] = (pos - Base64) << 2;
			}
			state = 1;
			break;
		case 1:
			if (target) {
				if ((size_t)tarindex + 1 >= targsize)
					return (-1);
				target[tarindex]   |=  (pos - Base64) >> 4;
				target[tarindex+1]  = ((pos - Base64) & 0x0f)
							<< 4 ;
			}
			tarindex++;
			state = 2;
			break;
		case 2:
			if (target) {
				if ((size_t)tarindex + 1 >= targsize)
					return (-1);
				target[tarindex]   |=  (pos - Base64) >> 2;
				target[tarindex+1]  = ((pos - Base64) & 0x03)
							<< 6;
			}
			tarindex++;
			state = 3;
			break;
		case 3:
			if (target) {
				if ((size_t)tarindex >= targsize)
					return (-1);
				target[tarindex] |= (pos - Base64);
			}
			tarindex++;
			state = 0;
			break;
		default:
			abort();
		}
	}

	

	if (ch == Pad64) {		
		ch = *src++;		
		switch (state) {
		case 0:		
		case 1:		
			return (-1);

		case 2:		
			
			for ((void)NULL; ch != '\0'; ch = *src++)
				if (!isspace(ch))
					break;
			
			if (ch != Pad64)
				return (-1);
			ch = *src++;		
			
			

		case 3:		
			
			for ((void)NULL; ch != '\0'; ch = *src++)
				if (!isspace(ch))
					return (-1);

			
			if (target && target[tarindex] != 0)
				return (-1);
		}
	} else {
		
		if (state != 0)
			return (-1);
	}

	return (tarindex);
}







struct __res_state _res __attribute__((section (".bss")));
struct __res_state *__resp = &_res;

struct __res_state _res __attribute__((section (".bss"))) attribute_hidden;



__thread struct __res_state *__resp = &_res;
extern __thread struct __res_state *__libc_resp __attribute__ ((alias ("__resp"))) attribute_hidden attribute_tls_model_ie;


struct __res_state *__resp = &_res;




int res_ninit(res_state statp)
{
	int ret;
	__UCLIBC_MUTEX_LOCK(__resolv_lock);
	ret = __res_vinit(statp, 0);
	__UCLIBC_MUTEX_UNLOCK(__resolv_lock);
	return ret;
}





struct __res_state * __res_state (void)
{
       return __resp;
}


extern struct __res_state _res;


struct __res_state * weak_const_function __res_state (void)

{
       return &_res;
}







int res_query(const char *dname, int class, int type, unsigned char *answer, int anslen)
{
	int i;
	unsigned char *packet = NULL;
	struct resolv_answer a;

	if (!dname || class != 1 ) {
		h_errno = NO_RECOVERY;
		return -1;
	}

	memset(&a, '\0', sizeof(a));
	i = __dns_lookup(dname, type, &packet, &a);

	if (i < 0) {
		if (!h_errno) 
			h_errno = TRY_AGAIN;
		return -1;
	}

	free(a.dotted);

	if (i > anslen)
		i = anslen;
	memcpy(answer, packet, i);

	free(packet);
	return i;
}
libc_hidden_def(res_query)






int res_search(const char *name, int class, int type, u_char *answer, int anslen)
{
	const char *cp;
	char **domain;
	HEADER *hp = (HEADER *)(void *)answer;
	unsigned dots;
	unsigned state;
	int ret, saved_herrno;
	uint32_t _res_options;
	unsigned _res_ndots;
	char **_res_dnsrch;

	if (!name || !answer) {
		h_errno = NETDB_INTERNAL;
		return -1;
	}

 again:
	__UCLIBC_MUTEX_LOCK(__resolv_lock);
	_res_options = _res.options;
	_res_ndots = _res.ndots;
	_res_dnsrch = _res.dnsrch;
	__UCLIBC_MUTEX_UNLOCK(__resolv_lock);
	if (!(_res_options & RES_INIT)) {
		res_init(); 
		goto again;
	}

	state = 0;
	errno = 0;
	h_errno = HOST_NOT_FOUND;	
	dots = 0;
	for (cp = name; *cp; cp++)
		dots += (*cp == '.');

	if (cp > name && *--cp == '.')
		state |= __TRAILING_DOT;

	
	saved_herrno = -1;
	if (dots >= _res_ndots) {
		ret = res_querydomain(name, NULL, class, type, answer, anslen);
		if (ret > 0)
			return ret;
		saved_herrno = h_errno;
		state |= __TRIED_AS_IS;
	}

	
	if ((!dots && (_res_options & RES_DEFNAMES))
	 || (dots && !(state & __TRAILING_DOT) && (_res_options & RES_DNSRCH))
	) {
		bool done = 0;

		for (domain = _res_dnsrch; *domain && !done; domain++) {

			ret = res_querydomain(name, *domain, class, type, answer, anslen);
			if (ret > 0)
				return ret;

			
			if (errno == ECONNREFUSED) {
				h_errno = TRY_AGAIN;
				return -1;
			}

			switch (h_errno) {
				case NO_DATA:
					state |= __GOT_NODATA;
					
				case HOST_NOT_FOUND:
					
					break;
				case TRY_AGAIN:
					if (hp->rcode == SERVFAIL) {
						
						state |= __GOT_SERVFAIL;
						break;
					}
					
				default:
					
					done = 1;
			}
			
			if (!(_res_options & RES_DNSRCH))
				done = 1;
		}
	}

	
	if (!(state & __TRIED_AS_IS)) {
		ret = res_querydomain(name, NULL, class, type, answer, anslen);
		if (ret > 0)
			return ret;
	}

	
	if (saved_herrno != -1)
		h_errno = saved_herrno;
	else if (state & __GOT_NODATA)
		h_errno = NO_DATA;
	else if (state & __GOT_SERVFAIL)
		h_errno = TRY_AGAIN;
	return -1;
}





int res_querydomain(const char *name, const char *domain, int class, int type, u_char *answer, int anslen)
{
	char nbuf[MAXDNAME];
	const char *longname = nbuf;
	size_t n, d;

	uint32_t _res_options;


	if (!name || !answer) {
		h_errno = NETDB_INTERNAL;
		return -1;
	}


 again:
	__UCLIBC_MUTEX_LOCK(__resolv_lock);
	_res_options = _res.options;
	__UCLIBC_MUTEX_UNLOCK(__resolv_lock);
	if (!(_res_options & RES_INIT)) {
		res_init(); 
		goto again;
	}
	if (_res_options & RES_DEBUG)
		printf(";; res_querydomain(%s, %s, %d, %d)\n", name, (domain ? domain : "<Nil>"), class, type);

	if (domain == NULL) {
		
		n = strlen(name);
		if (n + 1 > sizeof(nbuf)) {
			h_errno = NO_RECOVERY;
			return -1;
		}
		if (n > 0 && name[--n] == '.') {
			strncpy(nbuf, name, n);
			nbuf[n] = '\0';
		} else longname = name;
	} else {
		n = strlen(name);
		d = strlen(domain);
		if (n + 1 + d + 1 > sizeof(nbuf)) {
			h_errno = NO_RECOVERY;
			return -1;
		}
		snprintf(nbuf, sizeof(nbuf), "%s.%s", name, domain);
	}
	return res_query(longname, class, type, answer, anslen);
}
libc_hidden_def(res_querydomain)



unsigned int ns_get16(const unsigned char *src)
{
	unsigned int dst;
	NS_GET16(dst, src);
	return dst;
}

unsigned long ns_get32(const unsigned char *src)
{
	unsigned long dst;
	NS_GET32(dst, src);
	return dst;
}

void ns_put16(unsigned int src, unsigned char *dst)
{
	NS_PUT16(src, dst);
}

void ns_put32(unsigned long src, unsigned char *dst)
{
	NS_PUT32(src, dst);
}




struct _ns_flagdata { unsigned short mask, shift; };
static const struct _ns_flagdata _ns_flagdata[16] = {
	{ 0x8000, 15 },          { 0x7800, 11 }, { 0x0400, 10 }, { 0x0200, 9 }, { 0x0100, 8 }, { 0x0080, 7 }, { 0x0040, 6 }, { 0x0020, 5 }, { 0x0010, 4 }, { 0x000f, 0 }, { 0x0000, 0 }, { 0x0000, 0 }, { 0x0000, 0 }, { 0x0000, 0 }, { 0x0000, 0 }, { 0x0000, 0 }, };
















static void setsection(ns_msg *msg, ns_sect sect)
{
	msg->_sect = sect;
	if (sect == ns_s_max) {
		msg->_rrnum = -1;
		msg->_ptr = NULL;
	} else {
		msg->_rrnum = 0;
		msg->_ptr = msg->_sections[(int)sect];
	}
}

int ns_skiprr(const unsigned char *ptr, const unsigned char *eom, ns_sect section, int count)

{
	const u_char *optr = ptr;

	for (; count > 0; count--) {
		int b, rdlength;

		b = dn_skipname(ptr, eom);
		if (b < 0) {
			errno = EMSGSIZE;
			return -1;
		}

		ptr += b + NS_INT16SZ + NS_INT16SZ;
		if (section != ns_s_qd) {
			if (ptr + NS_INT32SZ + NS_INT16SZ > eom) {
				errno = EMSGSIZE;
				return -1;
			}

			ptr += NS_INT32SZ;
			NS_GET16(rdlength, ptr);
			ptr += rdlength;
		}
	}

	if (ptr > eom) {
		errno = EMSGSIZE;
		return -1;
	}

	return ptr - optr;
}
libc_hidden_def(ns_skiprr)

int ns_initparse(const unsigned char *msg, int msglen, ns_msg *handle)
{
	const u_char *eom = msg + msglen;
	int i;

	handle->_msg = msg;
	handle->_eom = eom;
	if (msg + NS_INT16SZ > eom) {
		errno = EMSGSIZE;
		return -1;
	}

	NS_GET16(handle->_id, msg);
	if (msg + NS_INT16SZ > eom) {
		errno = EMSGSIZE;
		return -1;
	}

	NS_GET16(handle->_flags, msg);
	for (i = 0; i < ns_s_max; i++) {
		if (msg + NS_INT16SZ > eom) {
			errno = EMSGSIZE;
			return -1;
		}

		NS_GET16(handle->_counts[i], msg);
	}
	for (i = 0; i < ns_s_max; i++)
		if (handle->_counts[i] == 0)
			handle->_sections[i] = NULL;
		else {
			int b = ns_skiprr(msg, eom, (ns_sect)i, handle->_counts[i]);

			if (b < 0)
				return -1;
			handle->_sections[i] = msg;
			msg += b;
		}

	if (msg != eom) {
		errno = EMSGSIZE;
		return -1;
	}

	setsection(handle, ns_s_max);
	return 0;
}

int ns_parserr(ns_msg *handle, ns_sect section, int rrnum, ns_rr *rr)
{
	int b;
	int tmp;

	
	tmp = section;
	if (tmp < 0 || section >= ns_s_max) {
		errno = ENODEV;
		return -1;
	}

	if (section != handle->_sect)
		setsection(handle, section);

	
	if (rrnum == -1)
		rrnum = handle->_rrnum;
	if (rrnum < 0 || rrnum >= handle->_counts[(int)section]) {
		errno = ENODEV;
		return -1;
	}
	if (rrnum < handle->_rrnum)
		setsection(handle, section);
	if (rrnum > handle->_rrnum) {
		b = ns_skiprr(handle->_ptr, handle->_eom, section, rrnum - handle->_rrnum);

		if (b < 0)
			return -1;
		handle->_ptr += b;
		handle->_rrnum = rrnum;
	}

	
	b = dn_expand(handle->_msg, handle->_eom, handle->_ptr, rr->name, NS_MAXDNAME);
	if (b < 0)
		return -1;
	handle->_ptr += b;
	if (handle->_ptr + NS_INT16SZ + NS_INT16SZ > handle->_eom) {
		errno = EMSGSIZE;
		return -1;
	}
	NS_GET16(rr->type, handle->_ptr);
	NS_GET16(rr->rr_class, handle->_ptr);
	if (section == ns_s_qd) {
		rr->ttl = 0;
		rr->rdlength = 0;
		rr->rdata = NULL;
	} else {
		if (handle->_ptr + NS_INT32SZ + NS_INT16SZ > handle->_eom) {
			errno = EMSGSIZE;
			return -1;
		}
		NS_GET32(rr->ttl, handle->_ptr);
		NS_GET16(rr->rdlength, handle->_ptr);
		if (handle->_ptr + rr->rdlength > handle->_eom) {
			errno = EMSGSIZE;
			return -1;
		}
		rr->rdata = handle->_ptr;
		handle->_ptr += rr->rdlength;
	}
	if (++handle->_rrnum > handle->_counts[(int)section])
		setsection(handle, (ns_sect)((int)section + 1));

	return 0;
}

int ns_msg_getflag(ns_msg handle, int flag)
{
	return ((handle)._flags & _ns_flagdata[flag].mask) >> _ns_flagdata[flag].shift;
}



int res_mkquery(int op, const char *dname, int class, int type, const unsigned char *data, int datalen, const unsigned char *newrr_in, unsigned char *buf, int buflen)


{
	HEADER *hp;
	unsigned char *cp, *ep;
	unsigned char *dnptrs[20], **dpp, **lastdnptr;
	uint32_t _res_options;
	int n;

	if (!buf || buflen < HFIXEDSZ) {
		h_errno = NETDB_INTERNAL;
		return -1;
	}

 again:
	__UCLIBC_MUTEX_LOCK(__resolv_lock);
	_res_options = _res.options;
	__UCLIBC_MUTEX_UNLOCK(__resolv_lock);
	if (!(_res_options & RES_INIT)) {
		res_init(); 
		goto again;
	}


	if (_res_options & RES_DEBUG)
		printf(";; res_mkquery(%d, %s, %d, %d)\n", op, dname && *dname ? dname : "<null>", class, type);


	memset(buf, 0, HFIXEDSZ);
	hp = (HEADER *) buf;
	hp->id = getpid() & 0xffff;
	hp->opcode = op;
	hp->rd = (_res_options & RES_RECURSE) != 0U;
	hp->rcode = NOERROR;

	cp = buf + HFIXEDSZ;
	ep = buf + buflen;
	dpp = dnptrs;
	*dpp++ = buf;
	*dpp++ = NULL;
	lastdnptr = dnptrs + sizeof dnptrs / sizeof dnptrs[0];

	
	switch (op) {
	case QUERY:
	case NS_NOTIFY_OP:
		if (ep - cp < QFIXEDSZ)
			return -1;

		n = dn_comp(dname, cp, ep - cp - QFIXEDSZ, dnptrs, lastdnptr);
		if (n < 0)
			return -1;

		cp += n;
		NS_PUT16(type, cp);
		NS_PUT16(class, cp);
		hp->qdcount = htons(1);

		if (op == QUERY || data == NULL)
			break;

		
		if ((ep - cp) < RRFIXEDSZ)
			return -1;

		n = dn_comp((const char *)data, cp, ep - cp - RRFIXEDSZ, dnptrs, lastdnptr);
		if (n < 0)
			return -1;

		cp += n;
		NS_PUT16(T_NULL, cp);
		NS_PUT16(class, cp);
		NS_PUT32(0, cp);
		NS_PUT16(0, cp);
		hp->arcount = htons(1);

		break;

	case IQUERY:
		
		if (ep - cp < 1 + RRFIXEDSZ + datalen)
			return -1;

		*cp++ = '\0';   
		NS_PUT16(type, cp);
		NS_PUT16(class, cp);
		NS_PUT32(0, cp);
		NS_PUT16(datalen, cp);

		if (datalen) {
			memcpy(cp, data, (size_t)datalen);
			cp += datalen;
		}

		hp->ancount = htons(1);
		break;

	default:
		return -1;
	}

	return cp - buf;
}




