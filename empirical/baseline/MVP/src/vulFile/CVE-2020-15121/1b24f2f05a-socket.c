















R_LIB_VERSION(r_socket);




R_API RSocket *r_socket_new (bool is_ssl) {
	return NULL;
}
R_API bool r_socket_is_connected (RSocket *s) {
	return false;
}
R_API bool r_socket_connect (RSocket *s, const char *host, const char *port, int proto, unsigned int timeout) {
	return false;
}
R_API bool r_socket_spawn (RSocket *s, const char *cmd, unsigned int timeout) {
	return -1;
}
R_API int r_socket_close_fd (RSocket *s) {
	return -1;
}
R_API int r_socket_close (RSocket *s) {
	return -1;
}
R_API int r_socket_free (RSocket *s) {
	return -1;
}
R_API int r_socket_port_by_name(const char *name) {
	return -1;
}
R_API bool r_socket_listen (RSocket *s, const char *port, const char *certfile) {
	return false;
}
R_API RSocket *r_socket_accept(RSocket *s) {
	return NULL;
}
R_API RSocket *r_socket_accept_timeout(RSocket *s, unsigned int timeout) {
	return NULL;
}
R_API int r_socket_block_time (RSocket *s, int block, int sec, int usec) {
	return -1;
}
R_API int r_socket_flush(RSocket *s) {
	return -1;
}
R_API int r_socket_ready(RSocket *s, int secs, int usecs) {
	return -1;
}
R_API char *r_socket_to_string(RSocket *s) {
	return NULL;
}
R_API int r_socket_write(RSocket *s, void *buf, int len) {
	return -1;
}
R_API int r_socket_puts(RSocket *s, char *buf) {
	return -1;
}
R_API void r_socket_printf(RSocket *s, const char *fmt, ...) {
	
}
R_API int r_socket_read(RSocket *s, unsigned char *buf, int len) {
	return -1;
}
R_API int r_socket_read_block(RSocket *s, unsigned char *buf, int len) {
	return -1;
}
R_API int r_socket_gets(RSocket *s, char *buf,	int size) {
	return -1;
}
R_API RSocket *r_socket_new_from_fd (int fd) {
	return NULL;
}
R_API ut8* r_socket_slurp(RSocket *s, int *len) {
	return NULL;
}



winsock api notes ================= close: closes the socket without flushing the data WSACleanup: closes all network connections    R_API bool r_socket_is_connected(RSocket *s) {







	char buf[2];
	r_socket_block_time (s, 0, 0, 0);

	int ret = recv (s->fd, (char*)&buf, 1, MSG_PEEK);

	ssize_t ret = recv (s->fd, (char*)&buf, 1, MSG_PEEK);

	r_socket_block_time (s, 1, 0, 0);
	return ret == 1;

	int error = 0;
	socklen_t len = sizeof (error);
	int ret = getsockopt (s->fd, SOL_SOCKET, SO_ERROR, &error, &len);
	if (ret != 0) {
		perror ("getsockopt");
		return false;
	}
	if (error != 0) {
		return false;
	}
	return true;

}


static bool __connect_unix(RSocket *s, const char *file) {
	struct sockaddr_un addr;
	int sock = socket (PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		free (s);
		return false;
	}
	
	addr.sun_family = AF_UNIX;
	strncpy (addr.sun_path, file, sizeof (addr.sun_path)-1);

	if (connect (sock, (struct sockaddr *)&addr, sizeof(addr))==-1) {
		close (sock);
		free (s);
		return false;
	}
	s->fd = sock;
	s->is_ssl = false;
	return true;
}

static bool __listen_unix (RSocket *s, const char *file) {
	struct sockaddr_un unix_name;
	int sock = socket (PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		return false;
	}
	
	unix_name.sun_family = AF_UNIX;
	strncpy (unix_name.sun_path, file, sizeof (unix_name.sun_path)-1);

	
	unlink (unix_name.sun_path);

	if (bind (sock, (struct sockaddr *) &unix_name, sizeof (unix_name)) < 0) {
		close (sock);
		return false;
	}
	r_sys_signal (SIGPIPE, SIG_IGN);

	
	if (chmod (unix_name.sun_path, 0777) != 0) {
		close (sock);
		return false;
	}
	if (listen (sock, 1)) {
		close (sock);
		return false;
	}
	s->fd = sock;
	return true;
}


R_API RSocket *r_socket_new(bool is_ssl) {
	RSocket *s = R_NEW0 (RSocket);
	if (!s) {
		return NULL;
	}
	s->is_ssl = is_ssl;
	s->port = 0;

	r_sys_signal (SIGPIPE, SIG_IGN);

	s->local = 0;
	s->fd = R_INVALID_SOCKET;

	if (is_ssl) {
		s->sfd = NULL;
		s->ctx = NULL;
		s->bio = NULL;

		if (!SSL_library_init ()) {
			r_socket_free (s);
			return NULL;
		}
		SSL_load_error_strings ();

	}

	return s;
}

R_API bool r_socket_spawn(RSocket *s, const char *cmd, unsigned int timeout) {
	
	const int port = 2000 + r_num_rand (2000);
	int childPid = r_sys_fork ();
	if (childPid == 0) {
		char *a = r_str_replace (strdup (cmd), "\\", "\\\\", true);
		int res = r_sys_cmdf ("rarun2 system=\"%s\" listen=%d", a, port);
		free (a);

		
		char *profile = r_str_newf ( "system=%s\n" "listen=%d\n", cmd, port);

		RRunProfile *rp = r_run_new (profile);
		r_run_start (rp);
		r_run_free (rp);
		free (profile);

		if (res != 0) {
			eprintf ("r_socket_spawn: rarun2 failed\n");
			exit (1);
		}
		eprintf ("r_socket_spawn: %s is dead\n", cmd);
		exit (0);
	}
	r_sys_sleep (1);
	r_sys_usleep (timeout);

	char aport[32];
	sprintf (aport, "%d", port);
	
	bool sock = r_socket_connect (s, "127.0.0.1", aport, R_SOCKET_PROTO_TCP, 2000);
	if (!sock) {
		return false;
	}

	r_sys_sleep (4);
	r_sys_usleep (timeout);

	int status = 0;
	int ret = waitpid (childPid, &status, WNOHANG);
	if (ret != 0) {
		r_socket_close (s);
		return false;
	}

	return true;
}

R_API bool r_socket_connect(RSocket *s, const char *host, const char *port, int proto, unsigned int timeout) {
	r_return_val_if_fail (s, false);

	struct sockaddr_in sa;
	struct hostent *he;
	WSADATA wsadata;
	TIMEVAL Timeout;
	Timeout.tv_sec = timeout;
	Timeout.tv_usec = 0;

	if (WSAStartup (MAKEWORD (1, 1), &wsadata) == SOCKET_ERROR) {
		eprintf ("Error creating socket.");
		return false;
	}
	s->fd = socket (AF_INET, SOCK_STREAM, 0);
	if (s->fd == R_INVALID_SOCKET) {
		return false;
	}

	unsigned long iMode = 1;
	int iResult = ioctlsocket (s->fd, FIONBIO, &iMode);
	if (iResult != NO_ERROR) {
		eprintf ("ioctlsocket error: %d\n", iResult);
	}
	memset (&sa, 0, sizeof (sa));
	sa.sin_family = AF_INET;
	he = (struct hostent *)gethostbyname (host);
	if (he == (struct hostent*)0) {

		closesocket (s->fd);

		close (s->fd);

		return false;
	}
	sa.sin_addr = *((struct in_addr *)he->h_addr);
	s->port = r_socket_port_by_name (port);
	s->proto = proto;
	sa.sin_port = htons (s->port);
	if (!connect (s->fd, (const struct sockaddr*)&sa, sizeof (struct sockaddr))) {

		closesocket (s->fd);

		close (s->fd);

		return false;
	}
	iMode = 0;
	iResult = ioctlsocket (s->fd, FIONBIO, &iMode);
	if (iResult != NO_ERROR) {
		eprintf ("ioctlsocket error: %d\n", iResult);
	}
	if (timeout > 0) {
		r_socket_block_time (s, 1, timeout, 0);
	}
	fd_set Write, Err;
	FD_ZERO (&Write);
	FD_ZERO (&Err);
	FD_SET (s->fd, &Write);
	FD_SET (s->fd, &Err);
	select (0, NULL, &Write, &Err, &Timeout);
	if (FD_ISSET (s->fd, &Write)) {
		return true;
	}
	return false;

	int ret;
	struct addrinfo hints = {0};
	struct addrinfo *res, *rp;
	if (!proto) {
		proto = R_SOCKET_PROTO_TCP;
	}
	r_sys_signal (SIGPIPE, SIG_IGN);
	if (proto == R_SOCKET_PROTO_UNIX) {
		if (!__connect_unix (s, host)) {
			return false;
		}
	} else {
		hints.ai_family = AF_UNSPEC; 
		hints.ai_protocol = proto;
		int gai = getaddrinfo (host, port, &hints, &res);
		if (gai != 0) {
			eprintf ("r_socket_connect: Error in getaddrinfo: %s (%s:%s)\n", gai_strerror (gai), host, port);
			return false;
		}
		for (rp = res; rp != NULL; rp = rp->ai_next) {
			int flag = 1;

			s->fd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
			if (s->fd == -1) {
				perror ("socket");
				continue;
			}
			ret = setsockopt (s->fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof (flag));
			if (ret < 0) {
				perror ("setsockopt");
				close (s->fd);
				s->fd = -1;
				continue;
			}

			r_socket_block_time (s, 0, 0, 0);
			ret = connect (s->fd, rp->ai_addr, rp->ai_addrlen);

			if (ret == 0) {
				freeaddrinfo (res);
				return true;
			}
			if (errno == EINPROGRESS) {
				struct timeval tv;
				tv.tv_sec = timeout;
				tv.tv_usec = 0;
				fd_set wfds;
				FD_ZERO(&wfds);
				FD_SET(s->fd, &wfds);

				if ((ret = select (s->fd + 1, NULL, &wfds, NULL, &tv)) != -1) {
					if (r_socket_is_connected (s)) {
						freeaddrinfo (res);
						return true;
					}
				} else {
					perror ("connect");
				}
			}
			r_socket_close (s);
		}
		freeaddrinfo (res);
		if (!rp) {
			eprintf ("Could not resolve address '%s' or failed to connect\n", host);
			return false;
		}
	}


	if (s->is_ssl) {
		s->ctx = SSL_CTX_new (SSLv23_client_method ());
		if (!s->ctx) {
			r_socket_free (s);
			return false;
		}
		s->sfd = SSL_new (s->ctx);
		SSL_set_fd (s->sfd, s->fd);
		if (SSL_connect (s->sfd) != 1) {
			r_socket_free (s);
			return false;
		}
	}

	return true;
}


R_API int r_socket_close_fd(RSocket *s) {

	return s->fd != INVALID_SOCKET ? closesocket (s->fd) : false;

	return s->fd != -1 ? close (s->fd) : false;

}


R_API int r_socket_close(RSocket *s) {
	int ret = false;
	if (!s) {
		return false;
	}
	if (s->fd != R_INVALID_SOCKET) {

		shutdown (s->fd, SHUT_RDWR);


		
		shutdown (s->fd, SD_SEND);
		if (r_socket_ready (s, 0, 250)) {
			do {
				char buf = 0;
				ret = recv (s->fd, &buf, 1, 0);
			} while (ret != 0 && ret != SOCKET_ERROR);
		}
		ret = closesocket (s->fd);

		ret = close (s->fd);

		s->fd = R_INVALID_SOCKET;
	}

	if (s->is_ssl && s->sfd) {
		SSL_free (s->sfd);
		s->sfd = NULL;
	}

	return ret;
}


R_API int r_socket_free(RSocket *s) {
	int res = r_socket_close (s);

	if (s && s->is_ssl) {
		if (s->sfd) {
			SSL_free (s->sfd);
		}
		if (s->ctx) {
			SSL_CTX_free (s->ctx);
		}
	}

	free (s);
	return res;
}

R_API int r_socket_port_by_name(const char *name) {
	struct servent *p = getservbyname (name, "tcp");
	return (p && p->s_port) ? ntohs (p->s_port) : r_num_get (NULL, name);
}

R_API bool r_socket_listen(RSocket *s, const char *port, const char *certfile) {
	int optval = 1;
	int ret;
	struct linger linger = { 0 };

	if (s->proto == R_SOCKET_PROTO_UNIX) {

		return __listen_unix (s, port);

		return false;
	}

	if (r_sandbox_enable (0)) {
		return false;
	}

	WSADATA wsadata;
	if (WSAStartup (MAKEWORD (1, 1), &wsadata) == SOCKET_ERROR) {
		eprintf ("Error creating socket.");
		return false;
	}

	if ((s->fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP)) == R_INVALID_SOCKET) {
		return false;
	}

	linger.l_onoff = 1;
	linger.l_linger = 1;
	ret = setsockopt (s->fd, SOL_SOCKET, SO_LINGER, (void*)&linger, sizeof (linger));
	if (ret < 0) {
		return false;
	}
	{ 
	int x = 1500; 
	ret = setsockopt (s->fd, SOL_SOCKET, SO_SNDBUF, (void*)&x, sizeof (int));
	if (ret < 0) {
		return false;
	}
	}
	ret = setsockopt (s->fd, SOL_SOCKET, SO_REUSEADDR, (void*)&optval, sizeof optval);
	if (ret < 0) {
		return false;
	}

	memset (&s->sa, 0, sizeof (s->sa));
	s->sa.sin_family = AF_INET;
	s->sa.sin_addr.s_addr = htonl (s->local? INADDR_LOOPBACK: INADDR_ANY);
	s->port = r_socket_port_by_name (port);
	if (s->port < 1) {
		return false;
	}
	s->sa.sin_port = htons (s->port); 
	if (bind (s->fd, (struct sockaddr *)&s->sa, sizeof (s->sa)) < 0) {
		r_sys_perror ("bind");

		closesocket (s->fd);

		close (s->fd);

		return false;
	}

	r_sys_signal (SIGPIPE, SIG_IGN);

	if (listen (s->fd, 32) < 0) {

		closesocket (s->fd);

		close (s->fd);

		return false;
	}

	if (s->is_ssl) {
		s->ctx = SSL_CTX_new (SSLv23_method ());
		if (!s->ctx) {
			r_socket_free (s);
			return false;
		}
		if (!SSL_CTX_use_certificate_chain_file (s->ctx, certfile)) {
			r_socket_free (s);
			return false;
		}
		if (!SSL_CTX_use_PrivateKey_file (s->ctx, certfile, SSL_FILETYPE_PEM)) {
			r_socket_free (s);
			return false;
		}
		SSL_CTX_set_verify_depth (s->ctx, 1);
	}

	return true;
}

R_API RSocket *r_socket_accept(RSocket *s) {
	RSocket *sock;
	socklen_t salen = sizeof (s->sa);
	if (!s) {
		return NULL;
	}
	sock = R_NEW0 (RSocket);
	if (!sock) {
		return NULL;
	}
	
	sock->fd = accept (s->fd, (struct sockaddr *)&s->sa, &salen);
	if (sock->fd == R_INVALID_SOCKET) {
		if (errno != EWOULDBLOCK) {
			
			r_sys_perror ("accept");
		}
		free (sock);
		return NULL;
	}

	sock->is_ssl = s->is_ssl;
	if (sock->is_ssl) {
		sock->sfd = NULL;
		sock->ctx = NULL;
		sock->bio = NULL;
		BIO *sbio = BIO_new_socket (sock->fd, BIO_NOCLOSE);
		sock->sfd = SSL_new (s->ctx);
		SSL_set_bio (sock->sfd, sbio, sbio);
		if (SSL_accept (sock->sfd) <= 0) {
			r_socket_free (sock);
			return NULL;
		}
		sock->bio = BIO_new (BIO_f_buffer ());
		sbio = BIO_new (BIO_f_ssl ());
		BIO_set_ssl (sbio, sock->sfd, BIO_CLOSE);
		BIO_push (sock->bio, sbio);
	}

	sock->is_ssl = 0;

	return sock;
}

R_API RSocket *r_socket_accept_timeout(RSocket *s, unsigned int timeout) {
	fd_set read_fds;
	fd_set except_fds;

	FD_ZERO (&read_fds);
	FD_SET (s->fd, &read_fds);

	FD_ZERO (&except_fds);
	FD_SET (s->fd, &except_fds);

	struct timeval t;
	t.tv_sec = timeout;
	t.tv_usec = 0;

	int r = select (s->fd + 1, &read_fds, NULL, &except_fds, &t);
	if(r < 0) {
		perror ("select");
	} else if (r > 0 && FD_ISSET (s->fd, &read_fds)) {
		return r_socket_accept (s);
	}

	return NULL;
}


R_API int r_socket_block_time(RSocket *s, int block, int sec, int usec) {

	int ret, flags;

	if (!s) {
		return false;
	}

	flags = fcntl (s->fd, F_GETFL, 0);
	if (flags < 0) {
		return false;
	}
	ret = fcntl (s->fd, F_SETFL, block? (flags & ~O_NONBLOCK):
			(flags | O_NONBLOCK));
	if (ret < 0) {
		return false;
	}

	ioctlsocket (s->fd, FIONBIO, (u_long FAR*)&block);

	if (sec > 0 || usec > 0) {
		struct timeval tv = {0};
		tv.tv_sec = sec;
		tv.tv_usec = usec;
		if (setsockopt (s->fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof (tv)) < 0) {
			return false;
		}
	}
	return true;
}

R_API int r_socket_flush(RSocket *s) {

	if (s->is_ssl && s->bio) {
		return BIO_flush (s->bio);
	}

	return true;
}




R_API int r_socket_ready(RSocket *s, int secs, int usecs) {

	
	int msecs = (usecs / 1000);
	struct pollfd fds[1];
	fds[0].fd = s->fd;
	fds[0].events = POLLIN | POLLPRI;
	fds[0].revents = POLLNVAL | POLLHUP | POLLERR;
	return poll ((struct pollfd *)&fds, 1, msecs);

	fd_set rfds;
	struct timeval tv;
	if (s->fd == R_INVALID_SOCKET) {
		return -1;
	}
	FD_ZERO (&rfds);
	FD_SET (s->fd, &rfds);
	tv.tv_sec = secs;
	tv.tv_usec = usecs;
	return select (s->fd + 1, &rfds, NULL, NULL, &tv);

	return true; 

}

R_API char *r_socket_to_string(RSocket *s) {

	return r_str_newf ("fd%d", (int)(size_t)s->fd);

	char *str = NULL;
	struct sockaddr sa;
	socklen_t sl = sizeof (sa);
	memset (&sa, 0, sizeof (sa));
	if (!getpeername (s->fd, &sa, &sl)) {
		struct sockaddr_in *sain = (struct sockaddr_in*) &sa;
		ut8 *a = (ut8*) &(sain->sin_addr);
		if ((str = malloc (32))) {
			sprintf (str, "%d.%d.%d.%d:%d", a[0], a[1], a[2], a[3], ntohs (sain->sin_port));
		}
	} else {
		eprintf ("getperrname: failed\n"); 
	}
	return str;

	return NULL;

}


R_API int r_socket_write(RSocket *s, void *buf, int len) {
	D { eprintf ("WRITE "); int i; ut8 *b = buf; for (i = 0; i<len; i++) { eprintf ("%02x ", b[i]); } eprintf ("\n"); }
	int ret, delta = 0;

	r_sys_signal (SIGPIPE, SIG_IGN);

	for (;;) {
		int b = 1500; 
		if (b > len) {
			b = len;
		}

		if (s->is_ssl) {
			if (s->bio) {
				ret = BIO_write (s->bio, buf+delta, b);
			} else {
				ret = SSL_write (s->sfd, buf + delta, b);
			}
		} else  {

			ret = send (s->fd, (char *)buf+delta, b, 0);
		}
		
		if (ret < 1) {
			break;
		}
		if (ret == len) {
			return len;
		}
		delta += ret;
		len -= ret;
	}
	return (ret == -1)? -1 : delta;
}

R_API int r_socket_puts(RSocket *s, char *buf) {
	return r_socket_write (s, buf, strlen (buf));
}

R_API void r_socket_printf(RSocket *s, const char *fmt, ...) {
	char buf[BUFFER_SIZE];
	va_list ap;
	if (s->fd != R_INVALID_SOCKET) {
		va_start (ap, fmt);
		vsnprintf (buf, BUFFER_SIZE, fmt, ap);
		r_socket_write (s, buf, strlen (buf));
		va_end (ap);
	}
}

R_API int r_socket_read(RSocket *s, unsigned char *buf, int len) {
	if (!s) {
		return -1;
	}

	if (s->is_ssl) {
		if (s->bio) {
			return BIO_read (s->bio, buf, len);
		}
		return SSL_read (s->sfd, buf, len);
	}


rep:
	{
	int ret = recv (s->fd, (void *)buf, len, 0);
	if (ret == -1) {
		goto rep;
	}
	return ret;
	}

	
	int r = recv (s->fd, buf, len, 0);
	D { eprintf ("READ "); int i; for (i = 0; i<len; i++) { eprintf ("%02x ", buf[i]); } eprintf ("\n"); }
	return r;

}

R_API int r_socket_read_block(RSocket *s, ut8 *buf, int len) {
	int ret = 0;
	for (ret = 0; ret < len; ) {
		int r = r_socket_read (s, buf + ret, len - ret);
		if (r == -1) {
			return -1;
		}
		if (r < 1) {
			break;
		}
		ret += r;
	}
	return ret;
}

R_API int r_socket_gets(RSocket *s, char *buf,	int size) {
	int i = 0;
	int ret = 0;

	if (s->fd == R_INVALID_SOCKET) {
		return -1;
	}
	while (i < size) {
		ret = r_socket_read (s, (ut8 *)buf + i, 1);
		if (ret == 0) {
			if (i > 0) {
				return i;
			}
			return -1;
		}
		if (ret < 0) {
			r_socket_close (s);
			return i == 0? -1: i;
		}
		if (buf[i] == '\r' || buf[i] == '\n') {
			buf[i] = 0;
			break;
		}
		i += ret;
	}
	buf[i] = '\0';
	return i;
}

R_API RSocket *r_socket_new_from_fd(int fd) {
	RSocket *s = R_NEW0 (RSocket);
	if (s) {
		s->fd = fd;
	}
	return s;
}

R_API ut8* r_socket_slurp(RSocket *s, int *len) {
	int blockSize = 4096;
	ut8 *ptr, *buf = malloc (blockSize);
	if (!buf) {
		return NULL;
	}
	int copied = 0;
	if (len) {
		*len = 0;
	}
	for (;;) {
		int rc = r_socket_read (s, buf + copied, blockSize);
		if (rc > 0) {
			copied += rc;
		}
		ptr = realloc (buf, copied + blockSize);
		if (!ptr) {
			break;
		}
		buf = ptr;
		if (rc < 1) {
			break;
		}
	}
	if (copied == 0) {
		R_FREE (buf);
	}
	if (len) {
		*len = copied;
	}
	return buf;
}


