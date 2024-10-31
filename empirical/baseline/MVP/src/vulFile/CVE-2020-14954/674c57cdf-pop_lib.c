



























char *C_PopOauthRefreshCommand; 
char *C_PopPass; 
unsigned char C_PopReconnect; 
char *C_PopUser; 


const char *pop_get_field(enum ConnAccountField field)
{
  switch (field)
  {
    case MUTT_CA_LOGIN:
    case MUTT_CA_USER:
      return C_PopUser;
    case MUTT_CA_PASS:
      return C_PopPass;
    case MUTT_CA_OAUTH_CMD:
      return C_PopOauthRefreshCommand;
    case MUTT_CA_HOST:
    default:
      return NULL;
  }
}


int pop_parse_path(const char *path, struct ConnAccount *cac)
{
  
  cac->flags = 0;
  cac->type = MUTT_ACCT_TYPE_POP;
  cac->port = 0;
  cac->service = "pop";
  cac->get_field = pop_get_field;

  struct Url *url = url_parse(path);

  if (!url || ((url->scheme != U_POP) && (url->scheme != U_POPS)) || !url->host || (mutt_account_fromurl(cac, url) < 0))
  {
    url_free(&url);
    mutt_error(_("Invalid POP URL: %s"), path);
    return -1;
  }

  if (url->scheme == U_POPS)
    cac->flags |= MUTT_ACCT_SSL;

  struct servent *service = getservbyname((url->scheme == U_POP) ? "pop3" : "pop3s", "tcp");
  if (cac->port == 0)
  {
    if (service)
      cac->port = ntohs(service->s_port);
    else cac->port = (url->scheme == U_POP) ? POP_PORT : POP_SSL_PORT;
  }

  url_free(&url);
  return 0;
}


static void pop_error(struct PopAccountData *adata, char *msg)
{
  char *t = strchr(adata->err_msg, '\0');
  char *c = msg;

  size_t plen = mutt_str_startswith(msg, "-ERR ", CASE_MATCH);
  if (plen != 0)
  {
    char *c2 = mutt_str_skip_email_wsp(msg + plen);

    if (*c2)
      c = c2;
  }

  mutt_str_strfcpy(t, c, sizeof(adata->err_msg) - strlen(adata->err_msg));
  mutt_str_remove_trailing_ws(adata->err_msg);
}


static int fetch_capa(const char *line, void *data)
{
  struct PopAccountData *adata = data;

  if (mutt_str_startswith(line, "SASL", CASE_IGNORE))
  {
    const char *c = mutt_str_skip_email_wsp(line + 4);
    mutt_buffer_strcpy(&adata->auth_list, c);
  }
  else if (mutt_str_startswith(line, "STLS", CASE_IGNORE))
    adata->cmd_stls = true;
  else if (mutt_str_startswith(line, "USER", CASE_IGNORE))
    adata->cmd_user = 1;
  else if (mutt_str_startswith(line, "UIDL", CASE_IGNORE))
    adata->cmd_uidl = 1;
  else if (mutt_str_startswith(line, "TOP", CASE_IGNORE))
    adata->cmd_top = 1;

  return 0;
}


static int fetch_auth(const char *line, void *data)
{
  struct PopAccountData *adata = data;

  if (!mutt_buffer_is_empty(&adata->auth_list))
  {
    mutt_buffer_addstr(&adata->auth_list, " ");
  }
  mutt_buffer_addstr(&adata->auth_list, line);

  return 0;
}


static int pop_capabilities(struct PopAccountData *adata, int mode)
{
  char buf[1024];

  
  if (adata->capabilities)
    return 0;

  
  if (mode == 0)
  {
    adata->cmd_capa = false;
    adata->cmd_stls = false;
    adata->cmd_user = 0;
    adata->cmd_uidl = 0;
    adata->cmd_top = 0;
    adata->resp_codes = false;
    adata->expire = true;
    adata->login_delay = 0;
    mutt_buffer_init(&adata->auth_list);
  }

  
  if ((mode == 0) || adata->cmd_capa)
  {
    mutt_str_strfcpy(buf, "CAPA\r\n", sizeof(buf));
    switch (pop_fetch_data(adata, buf, NULL, fetch_capa, adata))
    {
      case 0:
      {
        adata->cmd_capa = true;
        break;
      }
      case -1:
        return -1;
    }
  }

  
  if ((mode == 0) && !adata->cmd_capa)
  {
    adata->cmd_user = 2;
    adata->cmd_uidl = 2;
    adata->cmd_top = 2;

    mutt_str_strfcpy(buf, "AUTH\r\n", sizeof(buf));
    if (pop_fetch_data(adata, buf, NULL, fetch_auth, adata) == -1)
      return -1;
  }

  
  if (mode == 2)
  {
    char *msg = NULL;

    if (!adata->expire)
      msg = _("Unable to leave messages on server");
    if (adata->cmd_top == 0)
      msg = _("Command TOP is not supported by server");
    if (adata->cmd_uidl == 0)
      msg = _("Command UIDL is not supported by server");
    if (msg && adata->cmd_capa)
    {
      mutt_error(msg);
      return -2;
    }
    adata->capabilities = true;
  }

  return 0;
}


struct PopEmailData *pop_edata_get(struct Email *e)
{
  if (!e)
    return NULL;
  return e->edata;
}


int pop_connect(struct PopAccountData *adata)
{
  char buf[1024];

  adata->status = POP_NONE;
  if ((mutt_socket_open(adata->conn) < 0) || (mutt_socket_readln(buf, sizeof(buf), adata->conn) < 0))
  {
    mutt_error(_("Error connecting to server: %s"), adata->conn->account.host);
    return -1;
  }

  adata->status = POP_CONNECTED;

  if (!mutt_str_startswith(buf, "+OK", CASE_MATCH))
  {
    *adata->err_msg = '\0';
    pop_error(adata, buf);
    mutt_error("%s", adata->err_msg);
    return -2;
  }

  pop_apop_timestamp(adata, buf);

  return 0;
}


int pop_open_connection(struct PopAccountData *adata)
{
  char buf[1024];

  int rc = pop_connect(adata);
  if (rc < 0)
    return rc;

  rc = pop_capabilities(adata, 0);
  if (rc == -1)
    goto err_conn;
  if (rc == -2)
    return -2;


  
  if (!adata->conn->ssf && (adata->cmd_stls || C_SslForceTls))
  {
    if (C_SslForceTls)
      adata->use_stls = 2;
    if (adata->use_stls == 0)
    {
      enum QuadOption ans = query_quadoption(C_SslStarttls, _("Secure connection with TLS?"));
      if (ans == MUTT_ABORT)
        return -2;
      adata->use_stls = 1;
      if (ans == MUTT_YES)
        adata->use_stls = 2;
    }
    if (adata->use_stls == 2)
    {
      mutt_str_strfcpy(buf, "STLS\r\n", sizeof(buf));
      rc = pop_query(adata, buf, sizeof(buf));
      if (rc == -1)
        goto err_conn;
      if (rc != 0)
      {
        mutt_error("%s", adata->err_msg);
      }
      else if (mutt_ssl_starttls(adata->conn))
      {
        mutt_error(_("Could not negotiate TLS connection"));
        return -2;
      }
      else {
        
        rc = pop_capabilities(adata, 1);
        if (rc == -1)
          goto err_conn;
        if (rc == -2)
          return -2;
      }
    }
  }

  if (C_SslForceTls && !adata->conn->ssf)
  {
    mutt_error(_("Encrypted connection unavailable"));
    return -2;
  }


  rc = pop_authenticate(adata);
  if (rc == -1)
    goto err_conn;
  if (rc == -3)
    mutt_clear_error();
  if (rc != 0)
    return rc;

  
  rc = pop_capabilities(adata, 2);
  if (rc == -1)
    goto err_conn;
  if (rc == -2)
    return -2;

  
  mutt_str_strfcpy(buf, "STAT\r\n", sizeof(buf));
  rc = pop_query(adata, buf, sizeof(buf));
  if (rc == -1)
    goto err_conn;
  if (rc == -2)
  {
    mutt_error("%s", adata->err_msg);
    return rc;
  }

  unsigned int n = 0, size = 0;
  sscanf(buf, "+OK %u %u", &n, &size);
  adata->size = size;
  return 0;

err_conn:
  adata->status = POP_DISCONNECTED;
  mutt_error(_("Server closed connection"));
  return -1;
}


void pop_logout(struct Mailbox *m)
{
  struct PopAccountData *adata = pop_adata_get(m);

  if (adata->status == POP_CONNECTED)
  {
    int ret = 0;
    char buf[1024];
    mutt_message(_("Closing connection to POP server..."));

    if (m->readonly)
    {
      mutt_str_strfcpy(buf, "RSET\r\n", sizeof(buf));
      ret = pop_query(adata, buf, sizeof(buf));
    }

    if (ret != -1)
    {
      mutt_str_strfcpy(buf, "QUIT\r\n", sizeof(buf));
      ret = pop_query(adata, buf, sizeof(buf));
    }

    if (ret < 0)
      mutt_debug(LL_DEBUG1, "Error closing POP connection\n");

    mutt_clear_error();
  }

  adata->status = POP_DISCONNECTED;
}


int pop_query_d(struct PopAccountData *adata, char *buf, size_t buflen, char *msg)
{
  if (adata->status != POP_CONNECTED)
    return -1;

  
  if (msg)
  {
    mutt_debug(MUTT_SOCK_LOG_CMD, "> %s", msg);
  }

  mutt_socket_send_d(adata->conn, buf, MUTT_SOCK_LOG_FULL);

  char *c = strpbrk(buf, " \r\n");
  if (c)
    *c = '\0';
  snprintf(adata->err_msg, sizeof(adata->err_msg), "%s: ", buf);

  if (mutt_socket_readln_d(buf, buflen, adata->conn, MUTT_SOCK_LOG_FULL) < 0)
  {
    adata->status = POP_DISCONNECTED;
    return -1;
  }
  if (mutt_str_startswith(buf, "+OK", CASE_MATCH))
    return 0;

  pop_error(adata, buf);
  return -2;
}


int pop_fetch_data(struct PopAccountData *adata, const char *query, struct Progress *progress, pop_fetch_t callback, void *data)
{
  char buf[1024];
  long pos = 0;
  size_t lenbuf = 0;

  mutt_str_strfcpy(buf, query, sizeof(buf));
  int rc = pop_query(adata, buf, sizeof(buf));
  if (rc < 0)
    return rc;

  char *inbuf = mutt_mem_malloc(sizeof(buf));

  while (true)
  {
    const int chunk = mutt_socket_readln_d(buf, sizeof(buf), adata->conn, MUTT_SOCK_LOG_FULL);
    if (chunk < 0)
    {
      adata->status = POP_DISCONNECTED;
      rc = -1;
      break;
    }

    char *p = buf;
    if (!lenbuf && (buf[0] == '.'))
    {
      if (buf[1] != '.')
        break;
      p++;
    }

    mutt_str_strfcpy(inbuf + lenbuf, p, sizeof(buf));
    pos += chunk;

    
    if ((size_t) chunk >= sizeof(buf))
    {
      lenbuf += strlen(p);
    }
    else {
      if (progress)
        mutt_progress_update(progress, pos, -1);
      if ((rc == 0) && (callback(inbuf, data) < 0))
        rc = -3;
      lenbuf = 0;
    }

    mutt_mem_realloc(&inbuf, lenbuf + sizeof(buf));
  }

  FREE(&inbuf);
  return rc;
}


static int check_uidl(const char *line, void *data)
{
  if (!line || !data)
    return -1;

  char *endp = NULL;

  errno = 0;
  unsigned int index = strtoul(line, &endp, 10);
  if (errno != 0)
    return -1;
  while (*endp == ' ')
    endp++;

  struct Mailbox *m = data;
  for (int i = 0; i < m->msg_count; i++)
  {
    struct PopEmailData *edata = pop_edata_get(m->emails[i]);
    if (mutt_str_strcmp(edata->uid, endp) == 0)
    {
      edata->refno = index;
      break;
    }
  }

  return 0;
}


int pop_reconnect(struct Mailbox *m)
{
  struct PopAccountData *adata = pop_adata_get(m);

  if (adata->status == POP_CONNECTED)
    return 0;

  while (true)
  {
    mutt_socket_close(adata->conn);

    int ret = pop_open_connection(adata);
    if (ret == 0)
    {
      struct Progress progress;
      mutt_progress_init(&progress, _("Verifying message indexes..."), MUTT_PROGRESS_NET, 0);

      for (int i = 0; i < m->msg_count; i++)
      {
        struct PopEmailData *edata = pop_edata_get(m->emails[i]);
        edata->refno = -1;
      }

      ret = pop_fetch_data(adata, "UIDL\r\n", &progress, check_uidl, m);
      if (ret == -2)
      {
        mutt_error("%s", adata->err_msg);
      }
    }
    if (ret == 0)
      return 0;

    pop_logout(m);

    if (ret < -1)
      return -1;

    if (query_quadoption(C_PopReconnect, _("Connection lost. Reconnect to POP server?")) != MUTT_YES)
    {
      return -1;
    }
  }
}


struct PopAccountData *pop_adata_get(struct Mailbox *m)
{
  if (!m || (m->type != MUTT_POP))
    return NULL;
  struct Account *a = m->account;
  if (!a)
    return NULL;
  return a->adata;
}
