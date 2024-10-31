


















































int			Unix_socket_permissions;
char	   *Unix_socket_group;


static List *sock_paths = NIL;






static char *PqSendBuffer;
static int	PqSendBufferSize;	
static int	PqSendPointer;		
static int	PqSendStart;		

static char PqRecvBuffer[PQ_RECV_BUFFER_SIZE];
static int	PqRecvPointer;		
static int	PqRecvLength;		


static bool PqCommBusy;			
static bool PqCommReadingMsg;	



static void socket_comm_reset(void);
static void socket_close(int code, Datum arg);
static void socket_set_nonblocking(bool nonblocking);
static int	socket_flush(void);
static int	socket_flush_if_writable(void);
static bool socket_is_send_pending(void);
static int	socket_putmessage(char msgtype, const char *s, size_t len);
static void socket_putmessage_noblock(char msgtype, const char *s, size_t len);
static int	internal_putbytes(const char *s, size_t len);
static int	internal_flush(void);


static int	Lock_AF_UNIX(const char *unixSocketDir, const char *unixSocketPath);
static int	Setup_AF_UNIX(const char *sock_path);


static const PQcommMethods PqCommSocketMethods = {
	socket_comm_reset, socket_flush, socket_flush_if_writable, socket_is_send_pending, socket_putmessage, socket_putmessage_noblock };






const PQcommMethods *PqCommMethods = &PqCommSocketMethods;

WaitEventSet *FeBeWaitSet;



void pq_init(void)
{
	int			socket_pos PG_USED_FOR_ASSERTS_ONLY;
	int			latch_pos PG_USED_FOR_ASSERTS_ONLY;

	
	PqSendBufferSize = PQ_SEND_BUFFER_SIZE;
	PqSendBuffer = MemoryContextAlloc(TopMemoryContext, PqSendBufferSize);
	PqSendPointer = PqSendStart = PqRecvPointer = PqRecvLength = 0;
	PqCommBusy = false;
	PqCommReadingMsg = false;

	
	on_proc_exit(socket_close, 0);

	

	if (!pg_set_noblock(MyProcPort->sock))
		ereport(COMMERROR, (errmsg("could not set socket to nonblocking mode: %m")));


	FeBeWaitSet = CreateWaitEventSet(TopMemoryContext, 3);
	socket_pos = AddWaitEventToSet(FeBeWaitSet, WL_SOCKET_WRITEABLE, MyProcPort->sock, NULL, NULL);
	latch_pos = AddWaitEventToSet(FeBeWaitSet, WL_LATCH_SET, PGINVALID_SOCKET, MyLatch, NULL);
	AddWaitEventToSet(FeBeWaitSet, WL_POSTMASTER_DEATH, PGINVALID_SOCKET, NULL, NULL);

	
	Assert(socket_pos == FeBeWaitSetSocketPos);
	Assert(latch_pos == FeBeWaitSetLatchPos);
}


static void socket_comm_reset(void)
{
	
	PqCommBusy = false;
}


static void socket_close(int code, Datum arg)
{
	
	if (MyProcPort != NULL)
	{

		
		if (MyProcPort->gss)
		{
			OM_uint32	min_s;

			if (MyProcPort->gss->ctx != GSS_C_NO_CONTEXT)
				gss_delete_sec_context(&min_s, &MyProcPort->gss->ctx, NULL);

			if (MyProcPort->gss->cred != GSS_C_NO_CREDENTIAL)
				gss_release_cred(&min_s, &MyProcPort->gss->cred);
		}


		
		secure_close(MyProcPort);

		
		MyProcPort->sock = PGINVALID_SOCKET;
	}
}








int StreamServerPort(int family, const char *hostName, unsigned short portNumber, const char *unixSocketDir, pgsocket ListenSocket[], int MaxListen)


{
	pgsocket	fd;
	int			err;
	int			maxconn;
	int			ret;
	char		portNumberStr[32];
	const char *familyDesc;
	char		familyDescBuf[64];
	const char *addrDesc;
	char		addrBuf[NI_MAXHOST];
	char	   *service;
	struct addrinfo *addrs = NULL, *addr;
	struct addrinfo hint;
	int			listen_index = 0;
	int			added = 0;


	char		unixSocketPath[MAXPGPATH];


	int			one = 1;


	
	MemSet(&hint, 0, sizeof(hint));
	hint.ai_family = family;
	hint.ai_flags = AI_PASSIVE;
	hint.ai_socktype = SOCK_STREAM;


	if (family == AF_UNIX)
	{
		
		UNIXSOCK_PATH(unixSocketPath, portNumber, unixSocketDir);
		if (strlen(unixSocketPath) >= UNIXSOCK_PATH_BUFLEN)
		{
			ereport(LOG, (errmsg("Unix-domain socket path \"%s\" is too long (maximum %d bytes)", unixSocketPath, (int) (UNIXSOCK_PATH_BUFLEN - 1))));


			return STATUS_ERROR;
		}
		if (Lock_AF_UNIX(unixSocketDir, unixSocketPath) != STATUS_OK)
			return STATUS_ERROR;
		service = unixSocketPath;
	}
	else  {

		snprintf(portNumberStr, sizeof(portNumberStr), "%d", portNumber);
		service = portNumberStr;
	}

	ret = pg_getaddrinfo_all(hostName, service, &hint, &addrs);
	if (ret || !addrs)
	{
		if (hostName)
			ereport(LOG, (errmsg("could not translate host name \"%s\", service \"%s\" to address: %s", hostName, service, gai_strerror(ret))));

		else ereport(LOG, (errmsg("could not translate service \"%s\" to address: %s", service, gai_strerror(ret))));


		if (addrs)
			pg_freeaddrinfo_all(hint.ai_family, addrs);
		return STATUS_ERROR;
	}

	for (addr = addrs; addr; addr = addr->ai_next)
	{
		if (!IS_AF_UNIX(family) && IS_AF_UNIX(addr->ai_family))
		{
			
			continue;
		}

		
		for (; listen_index < MaxListen; listen_index++)
		{
			if (ListenSocket[listen_index] == PGINVALID_SOCKET)
				break;
		}
		if (listen_index >= MaxListen)
		{
			ereport(LOG, (errmsg("could not bind to all requested addresses: MAXLISTEN (%d) exceeded", MaxListen)));

			break;
		}

		
		switch (addr->ai_family)
		{
			case AF_INET:
				familyDesc = _("IPv4");
				break;

			case AF_INET6:
				familyDesc = _("IPv6");
				break;


			case AF_UNIX:
				familyDesc = _("Unix");
				break;

			default:
				snprintf(familyDescBuf, sizeof(familyDescBuf), _("unrecognized address family %d"), addr->ai_family);

				familyDesc = familyDescBuf;
				break;
		}

		

		if (addr->ai_family == AF_UNIX)
			addrDesc = unixSocketPath;
		else  {

			pg_getnameinfo_all((const struct sockaddr_storage *) addr->ai_addr, addr->ai_addrlen, addrBuf, sizeof(addrBuf), NULL, 0, NI_NUMERICHOST);



			addrDesc = addrBuf;
		}

		if ((fd = socket(addr->ai_family, SOCK_STREAM, 0)) == PGINVALID_SOCKET)
		{
			ereport(LOG, (errcode_for_socket_access(),  errmsg("could not create %s socket for address \"%s\": %m", familyDesc, addrDesc)));



			continue;
		}



		
		if (!IS_AF_UNIX(addr->ai_family))
		{
			if ((setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one))) == -1)
			{
				ereport(LOG, (errcode_for_socket_access(),  errmsg("%s(%s) failed for %s address \"%s\": %m", "setsockopt", "SO_REUSEADDR", familyDesc, addrDesc)));




				closesocket(fd);
				continue;
			}
		}



		if (addr->ai_family == AF_INET6)
		{
			if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &one, sizeof(one)) == -1)
			{
				ereport(LOG, (errcode_for_socket_access(),  errmsg("%s(%s) failed for %s address \"%s\": %m", "setsockopt", "IPV6_V6ONLY", familyDesc, addrDesc)));




				closesocket(fd);
				continue;
			}
		}


		
		err = bind(fd, addr->ai_addr, addr->ai_addrlen);
		if (err < 0)
		{
			int			saved_errno = errno;

			ereport(LOG, (errcode_for_socket_access(),  errmsg("could not bind %s address \"%s\": %m", familyDesc, addrDesc), saved_errno == EADDRINUSE ? (IS_AF_UNIX(addr->ai_family) ? errhint("Is another postmaster already running on port %d?", (int) portNumber) :







					  errhint("Is another postmaster already running on port %d?" " If not, wait a few seconds and retry.", (int) portNumber)) : 0));

			closesocket(fd);
			continue;
		}


		if (addr->ai_family == AF_UNIX)
		{
			if (Setup_AF_UNIX(service) != STATUS_OK)
			{
				closesocket(fd);
				break;
			}
		}


		
		maxconn = MaxBackends * 2;
		if (maxconn > PG_SOMAXCONN)
			maxconn = PG_SOMAXCONN;

		err = listen(fd, maxconn);
		if (err < 0)
		{
			ereport(LOG, (errcode_for_socket_access(),  errmsg("could not listen on %s address \"%s\": %m", familyDesc, addrDesc)));



			closesocket(fd);
			continue;
		}


		if (addr->ai_family == AF_UNIX)
			ereport(LOG, (errmsg("listening on Unix socket \"%s\"", addrDesc)));

		else  ereport(LOG,  (errmsg("listening on %s address \"%s\", port %d", familyDesc, addrDesc, (int) portNumber)));





		ListenSocket[listen_index] = fd;
		added++;
	}

	pg_freeaddrinfo_all(hint.ai_family, addrs);

	if (!added)
		return STATUS_ERROR;

	return STATUS_OK;
}





static int Lock_AF_UNIX(const char *unixSocketDir, const char *unixSocketPath)
{
	
	if (unixSocketPath[0] == '@')
		return STATUS_OK;

	
	CreateSocketLockFile(unixSocketPath, true, unixSocketDir);

	
	(void) unlink(unixSocketPath);

	
	sock_paths = lappend(sock_paths, pstrdup(unixSocketPath));

	return STATUS_OK;
}



static int Setup_AF_UNIX(const char *sock_path)
{
	
	if (sock_path[0] == '@')
		return STATUS_OK;

	
	Assert(Unix_socket_group);
	if (Unix_socket_group[0] != '\0')
	{

		elog(WARNING, "configuration item unix_socket_group is not supported on this platform");

		char	   *endptr;
		unsigned long val;
		gid_t		gid;

		val = strtoul(Unix_socket_group, &endptr, 10);
		if (*endptr == '\0')
		{						
			gid = val;
		}
		else {
			struct group *gr;

			gr = getgrnam(Unix_socket_group);
			if (!gr)
			{
				ereport(LOG, (errmsg("group \"%s\" does not exist", Unix_socket_group)));

				return STATUS_ERROR;
			}
			gid = gr->gr_gid;
		}
		if (chown(sock_path, -1, gid) == -1)
		{
			ereport(LOG, (errcode_for_file_access(), errmsg("could not set group of file \"%s\": %m", sock_path)));


			return STATUS_ERROR;
		}

	}

	if (chmod(sock_path, Unix_socket_permissions) == -1)
	{
		ereport(LOG, (errcode_for_file_access(), errmsg("could not set permissions of file \"%s\": %m", sock_path)));


		return STATUS_ERROR;
	}
	return STATUS_OK;
}




int StreamConnection(pgsocket server_fd, Port *port)
{
	
	port->raddr.salen = sizeof(port->raddr.addr);
	if ((port->sock = accept(server_fd, (struct sockaddr *) &port->raddr.addr, &port->raddr.salen)) == PGINVALID_SOCKET)

	{
		ereport(LOG, (errcode_for_socket_access(), errmsg("could not accept new connection: %m")));


		
		pg_usleep(100000L);		
		return STATUS_ERROR;
	}

	
	port->laddr.salen = sizeof(port->laddr.addr);
	if (getsockname(port->sock, (struct sockaddr *) &port->laddr.addr, &port->laddr.salen) < 0)

	{
		ereport(LOG, (errmsg("%s() failed: %m", "getsockname")));
		return STATUS_ERROR;
	}

	
	if (!IS_AF_UNIX(port->laddr.addr.ss_family))
	{
		int			on;

		int			oldopt;
		int			optlen;
		int			newopt;



		on = 1;
		if (setsockopt(port->sock, IPPROTO_TCP, TCP_NODELAY, (char *) &on, sizeof(on)) < 0)
		{
			ereport(LOG, (errmsg("%s(%s) failed: %m", "setsockopt", "TCP_NODELAY")));
			return STATUS_ERROR;
		}

		on = 1;
		if (setsockopt(port->sock, SOL_SOCKET, SO_KEEPALIVE, (char *) &on, sizeof(on)) < 0)
		{
			ereport(LOG, (errmsg("%s(%s) failed: %m", "setsockopt", "SO_KEEPALIVE")));
			return STATUS_ERROR;
		}



		
		optlen = sizeof(oldopt);
		if (getsockopt(port->sock, SOL_SOCKET, SO_SNDBUF, (char *) &oldopt, &optlen) < 0)
		{
			ereport(LOG, (errmsg("%s(%s) failed: %m", "getsockopt", "SO_SNDBUF")));
			return STATUS_ERROR;
		}
		newopt = PQ_SEND_BUFFER_SIZE * 4;
		if (oldopt < newopt)
		{
			if (setsockopt(port->sock, SOL_SOCKET, SO_SNDBUF, (char *) &newopt, sizeof(newopt)) < 0)
			{
				ereport(LOG, (errmsg("%s(%s) failed: %m", "setsockopt", "SO_SNDBUF")));
				return STATUS_ERROR;
			}
		}


		
		(void) pq_setkeepalivesidle(tcp_keepalives_idle, port);
		(void) pq_setkeepalivesinterval(tcp_keepalives_interval, port);
		(void) pq_setkeepalivescount(tcp_keepalives_count, port);
		(void) pq_settcpusertimeout(tcp_user_timeout, port);
	}

	return STATUS_OK;
}


void StreamClose(pgsocket sock)
{
	closesocket(sock);
}


void TouchSocketFiles(void)
{
	ListCell   *l;

	
	foreach(l, sock_paths)
	{
		char	   *sock_path = (char *) lfirst(l);

		
		(void) utime(sock_path, NULL);
	}
}


void RemoveSocketFiles(void)
{
	ListCell   *l;

	
	foreach(l, sock_paths)
	{
		char	   *sock_path = (char *) lfirst(l);

		
		(void) unlink(sock_path);
	}
	
	sock_paths = NIL;
}





static void socket_set_nonblocking(bool nonblocking)
{
	if (MyProcPort == NULL)
		ereport(ERROR, (errcode(ERRCODE_CONNECTION_DOES_NOT_EXIST), errmsg("there is no client connection")));


	MyProcPort->noblock = nonblocking;
}


static int pq_recvbuf(void)
{
	if (PqRecvPointer > 0)
	{
		if (PqRecvLength > PqRecvPointer)
		{
			
			memmove(PqRecvBuffer, PqRecvBuffer + PqRecvPointer, PqRecvLength - PqRecvPointer);
			PqRecvLength -= PqRecvPointer;
			PqRecvPointer = 0;
		}
		else PqRecvLength = PqRecvPointer = 0;
	}

	
	socket_set_nonblocking(false);

	
	for (;;)
	{
		int			r;

		r = secure_read(MyProcPort, PqRecvBuffer + PqRecvLength, PQ_RECV_BUFFER_SIZE - PqRecvLength);

		if (r < 0)
		{
			if (errno == EINTR)
				continue;		

			
			ereport(COMMERROR, (errcode_for_socket_access(), errmsg("could not receive data from client: %m")));

			return EOF;
		}
		if (r == 0)
		{
			
			return EOF;
		}
		
		PqRecvLength += r;
		return 0;
	}
}


int pq_getbyte(void)
{
	Assert(PqCommReadingMsg);

	while (PqRecvPointer >= PqRecvLength)
	{
		if (pq_recvbuf())		
			return EOF;			
	}
	return (unsigned char) PqRecvBuffer[PqRecvPointer++];
}


int pq_peekbyte(void)
{
	Assert(PqCommReadingMsg);

	while (PqRecvPointer >= PqRecvLength)
	{
		if (pq_recvbuf())		
			return EOF;			
	}
	return (unsigned char) PqRecvBuffer[PqRecvPointer];
}


int pq_getbyte_if_available(unsigned char *c)
{
	int			r;

	Assert(PqCommReadingMsg);

	if (PqRecvPointer < PqRecvLength)
	{
		*c = PqRecvBuffer[PqRecvPointer++];
		return 1;
	}

	
	socket_set_nonblocking(true);

	r = secure_read(MyProcPort, c, 1);
	if (r < 0)
	{
		
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			r = 0;
		else {
			
			ereport(COMMERROR, (errcode_for_socket_access(), errmsg("could not receive data from client: %m")));

			r = EOF;
		}
	}
	else if (r == 0)
	{
		
		r = EOF;
	}

	return r;
}


int pq_getbytes(char *s, size_t len)
{
	size_t		amount;

	Assert(PqCommReadingMsg);

	while (len > 0)
	{
		while (PqRecvPointer >= PqRecvLength)
		{
			if (pq_recvbuf())	
				return EOF;		
		}
		amount = PqRecvLength - PqRecvPointer;
		if (amount > len)
			amount = len;
		memcpy(s, PqRecvBuffer + PqRecvPointer, amount);
		PqRecvPointer += amount;
		s += amount;
		len -= amount;
	}
	return 0;
}


static int pq_discardbytes(size_t len)
{
	size_t		amount;

	Assert(PqCommReadingMsg);

	while (len > 0)
	{
		while (PqRecvPointer >= PqRecvLength)
		{
			if (pq_recvbuf())	
				return EOF;		
		}
		amount = PqRecvLength - PqRecvPointer;
		if (amount > len)
			amount = len;
		PqRecvPointer += amount;
		len -= amount;
	}
	return 0;
}



void pq_startmsgread(void)
{
	
	if (PqCommReadingMsg)
		ereport(FATAL, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("terminating connection because protocol synchronization was lost")));


	PqCommReadingMsg = true;
}



void pq_endmsgread(void)
{
	Assert(PqCommReadingMsg);

	PqCommReadingMsg = false;
}


bool pq_is_reading_msg(void)
{
	return PqCommReadingMsg;
}


int pq_getmessage(StringInfo s, int maxlen)
{
	int32		len;

	Assert(PqCommReadingMsg);

	resetStringInfo(s);

	
	if (pq_getbytes((char *) &len, 4) == EOF)
	{
		ereport(COMMERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("unexpected EOF within message length word")));

		return EOF;
	}

	len = pg_ntoh32(len);

	if (len < 4 || len > maxlen)
	{
		ereport(COMMERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("invalid message length")));

		return EOF;
	}

	len -= 4;					

	if (len > 0)
	{
		
		PG_TRY();
		{
			enlargeStringInfo(s, len);
		}
		PG_CATCH();
		{
			if (pq_discardbytes(len) == EOF)
				ereport(COMMERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("incomplete message from client")));


			
			PqCommReadingMsg = false;
			PG_RE_THROW();
		}
		PG_END_TRY();

		
		if (pq_getbytes(s->data, len) == EOF)
		{
			ereport(COMMERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("incomplete message from client")));

			return EOF;
		}
		s->len = len;
		
		s->data[len] = '\0';
	}

	
	PqCommReadingMsg = false;

	return 0;
}


static int internal_putbytes(const char *s, size_t len)
{
	size_t		amount;

	while (len > 0)
	{
		
		if (PqSendPointer >= PqSendBufferSize)
		{
			socket_set_nonblocking(false);
			if (internal_flush())
				return EOF;
		}
		amount = PqSendBufferSize - PqSendPointer;
		if (amount > len)
			amount = len;
		memcpy(PqSendBuffer + PqSendPointer, s, amount);
		PqSendPointer += amount;
		s += amount;
		len -= amount;
	}
	return 0;
}


static int socket_flush(void)
{
	int			res;

	
	if (PqCommBusy)
		return 0;
	PqCommBusy = true;
	socket_set_nonblocking(false);
	res = internal_flush();
	PqCommBusy = false;
	return res;
}


static int internal_flush(void)
{
	static int	last_reported_send_errno = 0;

	char	   *bufptr = PqSendBuffer + PqSendStart;
	char	   *bufend = PqSendBuffer + PqSendPointer;

	while (bufptr < bufend)
	{
		int			r;

		r = secure_write(MyProcPort, bufptr, bufend - bufptr);

		if (r <= 0)
		{
			if (errno == EINTR)
				continue;		

			
			if (errno == EAGAIN || errno == EWOULDBLOCK)
			{
				return 0;
			}

			
			if (errno != last_reported_send_errno)
			{
				last_reported_send_errno = errno;
				ereport(COMMERROR, (errcode_for_socket_access(), errmsg("could not send data to client: %m")));

			}

			
			PqSendStart = PqSendPointer = 0;
			ClientConnectionLost = 1;
			InterruptPending = 1;
			return EOF;
		}

		last_reported_send_errno = 0;	
		bufptr += r;
		PqSendStart += r;
	}

	PqSendStart = PqSendPointer = 0;
	return 0;
}


static int socket_flush_if_writable(void)
{
	int			res;

	
	if (PqSendPointer == PqSendStart)
		return 0;

	
	if (PqCommBusy)
		return 0;

	
	socket_set_nonblocking(true);

	PqCommBusy = true;
	res = internal_flush();
	PqCommBusy = false;
	return res;
}


static bool socket_is_send_pending(void)
{
	return (PqSendStart < PqSendPointer);
}





static int socket_putmessage(char msgtype, const char *s, size_t len)
{
	uint32		n32;

	Assert(msgtype != 0);

	if (PqCommBusy)
		return 0;
	PqCommBusy = true;
	if (internal_putbytes(&msgtype, 1))
		goto fail;

	n32 = pg_hton32((uint32) (len + 4));
	if (internal_putbytes((char *) &n32, 4))
		goto fail;

	if (internal_putbytes(s, len))
		goto fail;
	PqCommBusy = false;
	return 0;

fail:
	PqCommBusy = false;
	return EOF;
}


static void socket_putmessage_noblock(char msgtype, const char *s, size_t len)
{
	int			res PG_USED_FOR_ASSERTS_ONLY;
	int			required;

	
	required = PqSendPointer + 1 + 4 + len;
	if (required > PqSendBufferSize)
	{
		PqSendBuffer = repalloc(PqSendBuffer, required);
		PqSendBufferSize = required;
	}
	res = pq_putmessage(msgtype, s, len);
	Assert(res == 0);			
}


int pq_putmessage_v2(char msgtype, const char *s, size_t len)
{
	Assert(msgtype != 0);

	if (PqCommBusy)
		return 0;
	PqCommBusy = true;
	if (internal_putbytes(&msgtype, 1))
		goto fail;

	if (internal_putbytes(s, len))
		goto fail;
	PqCommBusy = false;
	return 0;

fail:
	PqCommBusy = false;
	return EOF;
}





static int pq_setkeepaliveswin32(Port *port, int idle, int interval)
{
	struct tcp_keepalive ka;
	DWORD		retsize;

	if (idle <= 0)
		idle = 2 * 60 * 60;		
	if (interval <= 0)
		interval = 1;			

	ka.onoff = 1;
	ka.keepalivetime = idle * 1000;
	ka.keepaliveinterval = interval * 1000;

	if (WSAIoctl(port->sock, SIO_KEEPALIVE_VALS, (LPVOID) &ka, sizeof(ka), NULL, 0, &retsize, NULL, NULL)







		!= 0)
	{
		ereport(LOG, (errmsg("%s(%s) failed: error code %d", "WSAIoctl", "SIO_KEEPALIVE_VALS", WSAGetLastError())));

		return STATUS_ERROR;
	}
	if (port->keepalives_idle != idle)
		port->keepalives_idle = idle;
	if (port->keepalives_interval != interval)
		port->keepalives_interval = interval;
	return STATUS_OK;
}


int pq_getkeepalivesidle(Port *port)
{

	if (port == NULL || IS_AF_UNIX(port->laddr.addr.ss_family))
		return 0;

	if (port->keepalives_idle != 0)
		return port->keepalives_idle;

	if (port->default_keepalives_idle == 0)
	{

		ACCEPT_TYPE_ARG3 size = sizeof(port->default_keepalives_idle);

		if (getsockopt(port->sock, IPPROTO_TCP, PG_TCP_KEEPALIVE_IDLE, (char *) &port->default_keepalives_idle, &size) < 0)

		{
			ereport(LOG, (errmsg("%s(%s) failed: %m", "getsockopt", PG_TCP_KEEPALIVE_IDLE_STR)));
			port->default_keepalives_idle = -1; 
		}

		
		port->default_keepalives_idle = -1;

	}

	return port->default_keepalives_idle;

	return 0;

}

int pq_setkeepalivesidle(int idle, Port *port)
{
	if (port == NULL || IS_AF_UNIX(port->laddr.addr.ss_family))
		return STATUS_OK;



	if (idle == port->keepalives_idle)
		return STATUS_OK;


	if (port->default_keepalives_idle <= 0)
	{
		if (pq_getkeepalivesidle(port) < 0)
		{
			if (idle == 0)
				return STATUS_OK;	
			else return STATUS_ERROR;
		}
	}

	if (idle == 0)
		idle = port->default_keepalives_idle;

	if (setsockopt(port->sock, IPPROTO_TCP, PG_TCP_KEEPALIVE_IDLE, (char *) &idle, sizeof(idle)) < 0)
	{
		ereport(LOG, (errmsg("%s(%s) failed: %m", "setsockopt", PG_TCP_KEEPALIVE_IDLE_STR)));
		return STATUS_ERROR;
	}

	port->keepalives_idle = idle;

	return pq_setkeepaliveswin32(port, idle, port->keepalives_interval);


	if (idle != 0)
	{
		ereport(LOG, (errmsg("setting the keepalive idle time is not supported")));
		return STATUS_ERROR;
	}


	return STATUS_OK;
}

int pq_getkeepalivesinterval(Port *port)
{

	if (port == NULL || IS_AF_UNIX(port->laddr.addr.ss_family))
		return 0;

	if (port->keepalives_interval != 0)
		return port->keepalives_interval;

	if (port->default_keepalives_interval == 0)
	{

		ACCEPT_TYPE_ARG3 size = sizeof(port->default_keepalives_interval);

		if (getsockopt(port->sock, IPPROTO_TCP, TCP_KEEPINTVL, (char *) &port->default_keepalives_interval, &size) < 0)

		{
			ereport(LOG, (errmsg("%s(%s) failed: %m", "getsockopt", "TCP_KEEPINTVL")));
			port->default_keepalives_interval = -1; 
		}

		
		port->default_keepalives_interval = -1;

	}

	return port->default_keepalives_interval;

	return 0;

}

int pq_setkeepalivesinterval(int interval, Port *port)
{
	if (port == NULL || IS_AF_UNIX(port->laddr.addr.ss_family))
		return STATUS_OK;


	if (interval == port->keepalives_interval)
		return STATUS_OK;


	if (port->default_keepalives_interval <= 0)
	{
		if (pq_getkeepalivesinterval(port) < 0)
		{
			if (interval == 0)
				return STATUS_OK;	
			else return STATUS_ERROR;
		}
	}

	if (interval == 0)
		interval = port->default_keepalives_interval;

	if (setsockopt(port->sock, IPPROTO_TCP, TCP_KEEPINTVL, (char *) &interval, sizeof(interval)) < 0)
	{
		ereport(LOG, (errmsg("%s(%s) failed: %m", "setsockopt", "TCP_KEEPINTVL")));
		return STATUS_ERROR;
	}

	port->keepalives_interval = interval;

	return pq_setkeepaliveswin32(port, port->keepalives_idle, interval);


	if (interval != 0)
	{
		ereport(LOG, (errmsg("%s(%s) not supported", "setsockopt", "TCP_KEEPINTVL")));
		return STATUS_ERROR;
	}


	return STATUS_OK;
}

int pq_getkeepalivescount(Port *port)
{

	if (port == NULL || IS_AF_UNIX(port->laddr.addr.ss_family))
		return 0;

	if (port->keepalives_count != 0)
		return port->keepalives_count;

	if (port->default_keepalives_count == 0)
	{
		ACCEPT_TYPE_ARG3 size = sizeof(port->default_keepalives_count);

		if (getsockopt(port->sock, IPPROTO_TCP, TCP_KEEPCNT, (char *) &port->default_keepalives_count, &size) < 0)

		{
			ereport(LOG, (errmsg("%s(%s) failed: %m", "getsockopt", "TCP_KEEPCNT")));
			port->default_keepalives_count = -1;	
		}
	}

	return port->default_keepalives_count;

	return 0;

}

int pq_setkeepalivescount(int count, Port *port)
{
	if (port == NULL || IS_AF_UNIX(port->laddr.addr.ss_family))
		return STATUS_OK;


	if (count == port->keepalives_count)
		return STATUS_OK;

	if (port->default_keepalives_count <= 0)
	{
		if (pq_getkeepalivescount(port) < 0)
		{
			if (count == 0)
				return STATUS_OK;	
			else return STATUS_ERROR;
		}
	}

	if (count == 0)
		count = port->default_keepalives_count;

	if (setsockopt(port->sock, IPPROTO_TCP, TCP_KEEPCNT, (char *) &count, sizeof(count)) < 0)
	{
		ereport(LOG, (errmsg("%s(%s) failed: %m", "setsockopt", "TCP_KEEPCNT")));
		return STATUS_ERROR;
	}

	port->keepalives_count = count;

	if (count != 0)
	{
		ereport(LOG, (errmsg("%s(%s) not supported", "setsockopt", "TCP_KEEPCNT")));
		return STATUS_ERROR;
	}


	return STATUS_OK;
}

int pq_gettcpusertimeout(Port *port)
{

	if (port == NULL || IS_AF_UNIX(port->laddr.addr.ss_family))
		return 0;

	if (port->tcp_user_timeout != 0)
		return port->tcp_user_timeout;

	if (port->default_tcp_user_timeout == 0)
	{
		ACCEPT_TYPE_ARG3 size = sizeof(port->default_tcp_user_timeout);

		if (getsockopt(port->sock, IPPROTO_TCP, TCP_USER_TIMEOUT, (char *) &port->default_tcp_user_timeout, &size) < 0)

		{
			ereport(LOG, (errmsg("%s(%s) failed: %m", "getsockopt", "TCP_USER_TIMEOUT")));
			port->default_tcp_user_timeout = -1;	
		}
	}

	return port->default_tcp_user_timeout;

	return 0;

}

int pq_settcpusertimeout(int timeout, Port *port)
{
	if (port == NULL || IS_AF_UNIX(port->laddr.addr.ss_family))
		return STATUS_OK;


	if (timeout == port->tcp_user_timeout)
		return STATUS_OK;

	if (port->default_tcp_user_timeout <= 0)
	{
		if (pq_gettcpusertimeout(port) < 0)
		{
			if (timeout == 0)
				return STATUS_OK;	
			else return STATUS_ERROR;
		}
	}

	if (timeout == 0)
		timeout = port->default_tcp_user_timeout;

	if (setsockopt(port->sock, IPPROTO_TCP, TCP_USER_TIMEOUT, (char *) &timeout, sizeof(timeout)) < 0)
	{
		ereport(LOG, (errmsg("%s(%s) failed: %m", "setsockopt", "TCP_USER_TIMEOUT")));
		return STATUS_ERROR;
	}

	port->tcp_user_timeout = timeout;

	if (timeout != 0)
	{
		ereport(LOG, (errmsg("%s(%s) not supported", "setsockopt", "TCP_USER_TIMEOUT")));
		return STATUS_ERROR;
	}


	return STATUS_OK;
}


bool pq_check_connection(void)
{

	
	struct pollfd pollfd;
	int			rc;

	pollfd.fd = MyProcPort->sock;
	pollfd.events = POLLOUT | POLLIN | POLLRDHUP;
	pollfd.revents = 0;

	rc = poll(&pollfd, 1, 0);

	if (rc < 0)
	{
		ereport(COMMERROR, (errcode_for_socket_access(), errmsg("could not poll socket: %m")));

		return false;
	}
	else if (rc == 1 && (pollfd.revents & (POLLHUP | POLLRDHUP)))
		return false;


	return true;
}
