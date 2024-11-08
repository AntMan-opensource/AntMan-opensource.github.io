

















static int socket_preconnect(void)
{
  if (!C_Preconnect)
    return 0;

  mutt_debug(LL_DEBUG2, "Executing preconnect: %s\n", C_Preconnect);
  const int rc = mutt_system(C_Preconnect);
  mutt_debug(LL_DEBUG2, "Preconnect result: %d\n", rc);
  if (rc != 0)
  {
    const int save_errno = errno;
    mutt_perror(_("Preconnect command failed"));

    return save_errno;
  }

  return 0;
}


int mutt_socket_open(struct Connection *conn)
{
  int rc;

  if (socket_preconnect())
    return -1;

  rc = conn->open(conn);

  mutt_debug(LL_DEBUG2, "Connected to %s:%d on fd=%d\n", conn->account.host, conn->account.port, conn->fd);

  return rc;
}


int mutt_socket_close(struct Connection *conn)
{
  if (!conn)
    return 0;

  int rc = -1;

  if (conn->fd < 0)
    mutt_debug(LL_DEBUG1, "Attempt to close closed connection\n");
  else rc = conn->close(conn);

  conn->fd = -1;
  conn->ssf = 0;
  conn->bufpos = 0;
  conn->available = 0;

  return rc;
}


int mutt_socket_read(struct Connection *conn, char *buf, size_t len)
{
  return conn->read(conn, buf, len);
}


int mutt_socket_write(struct Connection *conn, const char *buf, size_t len)
{
  return conn->write(conn, buf, len);
}


int mutt_socket_write_d(struct Connection *conn, const char *buf, int len, int dbg)
{
  int sent = 0;

  mutt_debug(dbg, "%d> %s", conn->fd, buf);

  if (conn->fd < 0)
  {
    mutt_debug(LL_DEBUG1, "attempt to write to closed connection\n");
    return -1;
  }

  while (sent < len)
  {
    const int rc = conn->write(conn, buf + sent, len - sent);
    if (rc < 0)
    {
      mutt_debug(LL_DEBUG1, "error writing (%s), closing socket\n", strerror(errno));
      mutt_socket_close(conn);

      return -1;
    }

    if (rc < len - sent)
      mutt_debug(LL_DEBUG3, "short write (%d of %d bytes)\n", rc, len - sent);

    sent += rc;
  }

  return sent;
}


int mutt_socket_poll(struct Connection *conn, time_t wait_secs)
{
  if (conn->bufpos < conn->available)
    return conn->available - conn->bufpos;

  if (conn->poll)
    return conn->poll(conn, wait_secs);

  return -1;
}


int mutt_socket_readchar(struct Connection *conn, char *c)
{
  if (conn->bufpos >= conn->available)
  {
    if (conn->fd >= 0)
      conn->available = conn->read(conn, conn->inbuf, sizeof(conn->inbuf));
    else {
      mutt_debug(LL_DEBUG1, "attempt to read from closed connection\n");
      return -1;
    }
    conn->bufpos = 0;
    if (conn->available == 0)
    {
      mutt_error(_("Connection to %s closed"), conn->account.host);
    }
    if (conn->available <= 0)
    {
      mutt_socket_close(conn);
      return -1;
    }
  }
  *c = conn->inbuf[conn->bufpos];
  conn->bufpos++;
  return 1;
}


int mutt_socket_readln_d(char *buf, size_t buflen, struct Connection *conn, int dbg)
{
  char ch;
  int i;

  for (i = 0; i < buflen - 1; i++)
  {
    if (mutt_socket_readchar(conn, &ch) != 1)
    {
      buf[i] = '\0';
      return -1;
    }

    if (ch == '\n')
      break;
    buf[i] = ch;
  }

  
  if (i && (buf[i - 1] == '\r'))
    i--;
  buf[i] = '\0';

  mutt_debug(dbg, "%d< %s\n", conn->fd, buf);

  
  return i + 1;
}


struct Connection *mutt_socket_new(enum ConnectionType type)
{
  struct Connection *conn = mutt_mem_calloc(1, sizeof(struct Connection));
  conn->fd = -1;

  if (type == MUTT_CONNECTION_TUNNEL)
  {
    mutt_tunnel_socket_setup(conn);
  }
  else if (type == MUTT_CONNECTION_SSL)
  {
    int rc = mutt_ssl_socket_setup(conn);
    if (rc < 0)
      FREE(&conn);
  }
  else {
    conn->read = raw_socket_read;
    conn->write = raw_socket_write;
    conn->open = raw_socket_open;
    conn->close = raw_socket_close;
    conn->poll = raw_socket_poll;
  }

  return conn;
}
