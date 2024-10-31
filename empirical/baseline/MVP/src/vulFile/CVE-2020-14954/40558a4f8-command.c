



























bool C_ImapServernoise; 




static const char *const Capabilities[] = {
  "IMAP4", "IMAP4rev1", "STATUS", "ACL", "NAMESPACE", "AUTH=CRAM-MD5", "AUTH=GSSAPI", "AUTH=ANONYMOUS", "AUTH=OAUTHBEARER", "STARTTLS", "LOGINDISABLED", "IDLE", "SASL-IR", "ENABLE", "CONDSTORE", "QRESYNC", "LIST-EXTENDED", "COMPRESS=DEFLATE", "X-GM-EXT-1", NULL, };





















static bool cmd_queue_full(struct ImapAccountData *adata)
{
  if (((adata->nextcmd + 1) % adata->cmdslots) == adata->lastcmd)
    return true;

  return false;
}


static struct ImapCommand *cmd_new(struct ImapAccountData *adata)
{
  struct ImapCommand *cmd = NULL;

  if (cmd_queue_full(adata))
  {
    mutt_debug(LL_DEBUG3, "IMAP command queue full\n");
    return NULL;
  }

  cmd = adata->cmds + adata->nextcmd;
  adata->nextcmd = (adata->nextcmd + 1) % adata->cmdslots;

  snprintf(cmd->seq, sizeof(cmd->seq), "%c%04u", adata->seqid, adata->seqno++);
  if (adata->seqno > 9999)
    adata->seqno = 0;

  cmd->state = IMAP_RES_NEW;

  return cmd;
}


static int cmd_queue(struct ImapAccountData *adata, const char *cmdstr, ImapCmdFlags flags)
{
  if (cmd_queue_full(adata))
  {
    mutt_debug(LL_DEBUG3, "Draining IMAP command pipeline\n");

    const int rc = imap_exec(adata, NULL, flags & IMAP_CMD_POLL);

    if (rc == IMAP_EXEC_ERROR)
      return IMAP_RES_BAD;
  }

  struct ImapCommand *cmd = cmd_new(adata);
  if (!cmd)
    return IMAP_RES_BAD;

  if (mutt_buffer_add_printf(&adata->cmdbuf, "%s %s\r\n", cmd->seq, cmdstr) < 0)
    return IMAP_RES_BAD;

  return 0;
}


static void cmd_handle_fatal(struct ImapAccountData *adata)
{
  adata->status = IMAP_FATAL;

  if (!adata->mailbox)
    return;

  struct ImapMboxData *mdata = adata->mailbox->mdata;

  if ((adata->state >= IMAP_SELECTED) && (mdata->reopen & IMAP_REOPEN_ALLOW))
  {
    mx_fastclose_mailbox(adata->mailbox);
    mutt_socket_close(adata->conn);
    mutt_error(_("Mailbox %s@%s closed"), adata->conn->account.user, adata->conn->account.host);
    adata->state = IMAP_DISCONNECTED;
  }

  imap_close_connection(adata);
  if (!adata->recovering)
  {
    adata->recovering = true;
    if (imap_login(adata))
      mutt_clear_error();
    adata->recovering = false;
  }
}


static int cmd_start(struct ImapAccountData *adata, const char *cmdstr, ImapCmdFlags flags)
{
  int rc;

  if (adata->status == IMAP_FATAL)
  {
    cmd_handle_fatal(adata);
    return -1;
  }

  if (cmdstr && ((rc = cmd_queue(adata, cmdstr, flags)) < 0))
    return rc;

  if (flags & IMAP_CMD_QUEUE)
    return 0;

  if (mutt_buffer_is_empty(&adata->cmdbuf))
    return IMAP_RES_BAD;

  rc = mutt_socket_send_d(adata->conn, adata->cmdbuf.data, (flags & IMAP_CMD_PASS) ? IMAP_LOG_PASS : IMAP_LOG_CMD);
  mutt_buffer_reset(&adata->cmdbuf);

  
  if (adata->state == IMAP_IDLE)
    adata->state = IMAP_SELECTED;

  return (rc < 0) ? IMAP_RES_BAD : 0;
}


static int cmd_status(const char *s)
{
  s = imap_next_word((char *) s);

  if (mutt_str_startswith(s, "OK", CASE_IGNORE))
    return IMAP_RES_OK;
  if (mutt_str_startswith(s, "NO", CASE_IGNORE))
    return IMAP_RES_NO;

  return IMAP_RES_BAD;
}


static void cmd_parse_expunge(struct ImapAccountData *adata, const char *s)
{
  unsigned int exp_msn;
  struct Email *e = NULL;

  mutt_debug(LL_DEBUG2, "Handling EXPUNGE\n");

  struct ImapMboxData *mdata = adata->mailbox->mdata;

  if ((mutt_str_atoui(s, &exp_msn) < 0) || (exp_msn < 1) || (exp_msn > mdata->max_msn))
    return;

  e = mdata->msn_index[exp_msn - 1];
  if (e)
  {
    
    e->index = INT_MAX;
    imap_edata_get(e)->msn = 0;
  }

  
  for (unsigned int cur = exp_msn; cur < mdata->max_msn; cur++)
  {
    e = mdata->msn_index[cur];
    if (e)
      imap_edata_get(e)->msn--;
    mdata->msn_index[cur - 1] = e;
  }

  mdata->msn_index[mdata->max_msn - 1] = NULL;
  mdata->max_msn--;

  mdata->reopen |= IMAP_EXPUNGE_PENDING;
}


static void cmd_parse_vanished(struct ImapAccountData *adata, char *s)
{
  bool earlier = false;
  int rc;
  unsigned int uid = 0;

  struct ImapMboxData *mdata = adata->mailbox->mdata;

  mutt_debug(LL_DEBUG2, "Handling VANISHED\n");

  if (mutt_str_startswith(s, "(EARLIER)", CASE_IGNORE))
  {
    
    earlier = true;
    s = imap_next_word(s);
  }

  char *end_of_seqset = s;
  while (*end_of_seqset)
  {
    if (!strchr("0123456789:,", *end_of_seqset))
      *end_of_seqset = '\0';
    else end_of_seqset++;
  }

  struct SeqsetIterator *iter = mutt_seqset_iterator_new(s);
  if (!iter)
  {
    mutt_debug(LL_DEBUG2, "VANISHED: empty seqset [%s]?\n", s);
    return;
  }

  while ((rc = mutt_seqset_iterator_next(iter, &uid)) == 0)
  {
    struct Email *e = mutt_hash_int_find(mdata->uid_hash, uid);
    if (!e)
      continue;

    unsigned int exp_msn = imap_edata_get(e)->msn;

    
    e->index = INT_MAX;
    imap_edata_get(e)->msn = 0;

    if ((exp_msn < 1) || (exp_msn > mdata->max_msn))
    {
      mutt_debug(LL_DEBUG1, "VANISHED: msn for UID %u is incorrect\n", uid);
      continue;
    }
    if (mdata->msn_index[exp_msn - 1] != e)
    {
      mutt_debug(LL_DEBUG1, "VANISHED: msn_index for UID %u is incorrect\n", uid);
      continue;
    }

    mdata->msn_index[exp_msn - 1] = NULL;

    if (!earlier)
    {
      
      for (unsigned int cur = exp_msn; cur < mdata->max_msn; cur++)
      {
        e = mdata->msn_index[cur];
        if (e)
          imap_edata_get(e)->msn--;
        mdata->msn_index[cur - 1] = e;
      }

      mdata->msn_index[mdata->max_msn - 1] = NULL;
      mdata->max_msn--;
    }
  }

  if (rc < 0)
    mutt_debug(LL_DEBUG1, "VANISHED: illegal seqset %s\n", s);

  mdata->reopen |= IMAP_EXPUNGE_PENDING;

  mutt_seqset_iterator_free(&iter);
}


static void cmd_parse_fetch(struct ImapAccountData *adata, char *s)
{
  unsigned int msn, uid;
  struct Email *e = NULL;
  char *flags = NULL;
  int uid_checked = 0;
  bool server_changes = false;

  struct ImapMboxData *mdata = imap_mdata_get(adata->mailbox);

  mutt_debug(LL_DEBUG3, "Handling FETCH\n");

  if (mutt_str_atoui(s, &msn) < 0)
  {
    mutt_debug(LL_DEBUG3, "Skipping FETCH response - illegal MSN\n");
    return;
  }

  if ((msn < 1) || (msn > mdata->max_msn))
  {
    mutt_debug(LL_DEBUG3, "Skipping FETCH response - MSN %u out of range\n", msn);
    return;
  }

  e = mdata->msn_index[msn - 1];
  if (!e || !e->active)
  {
    mutt_debug(LL_DEBUG3, "Skipping FETCH response - MSN %u not in msn_index\n", msn);
    return;
  }

  mutt_debug(LL_DEBUG2, "Message UID %u updated\n", imap_edata_get(e)->uid);
  
  s = imap_next_word(s);
  s = imap_next_word(s);

  if (*s != '(')
  {
    mutt_debug(LL_DEBUG1, "Malformed FETCH response\n");
    return;
  }
  s++;

  while (*s)
  {
    SKIPWS(s);
    size_t plen = mutt_str_startswith(s, "FLAGS", CASE_IGNORE);
    if (plen != 0)
    {
      flags = s;
      if (uid_checked)
        break;

      s += plen;
      SKIPWS(s);
      if (*s != '(')
      {
        mutt_debug(LL_DEBUG1, "bogus FLAGS response: %s\n", s);
        return;
      }
      s++;
      while (*s && (*s != ')'))
        s++;
      if (*s == ')')
        s++;
      else {
        mutt_debug(LL_DEBUG1, "Unterminated FLAGS response: %s\n", s);
        return;
      }
    }
    else if ((plen = mutt_str_startswith(s, "UID", CASE_IGNORE)))
    {
      s += plen;
      SKIPWS(s);
      if (mutt_str_atoui(s, &uid) < 0)
      {
        mutt_debug(LL_DEBUG1, "Illegal UID.  Skipping update\n");
        return;
      }
      if (uid != imap_edata_get(e)->uid)
      {
        mutt_debug(LL_DEBUG1, "UID vs MSN mismatch.  Skipping update\n");
        return;
      }
      uid_checked = 1;
      if (flags)
        break;
      s = imap_next_word(s);
    }
    else if ((plen = mutt_str_startswith(s, "MODSEQ", CASE_IGNORE)))
    {
      s += plen;
      SKIPWS(s);
      if (*s != '(')
      {
        mutt_debug(LL_DEBUG1, "bogus MODSEQ response: %s\n", s);
        return;
      }
      s++;
      while (*s && (*s != ')'))
        s++;
      if (*s == ')')
        s++;
      else {
        mutt_debug(LL_DEBUG1, "Unterminated MODSEQ response: %s\n", s);
        return;
      }
    }
    else if (*s == ')')
      break; 
    else if (*s)
    {
      mutt_debug(LL_DEBUG2, "Only handle FLAGS updates\n");
      break;
    }
  }

  if (flags)
  {
    imap_set_flags(adata->mailbox, e, flags, &server_changes);
    if (server_changes)
    {
      
      if (e->changed)
        mdata->reopen |= IMAP_EXPUNGE_PENDING;
      else mdata->check_status |= IMAP_FLAGS_PENDING;
    }
  }
}


static void cmd_parse_capability(struct ImapAccountData *adata, char *s)
{
  mutt_debug(LL_DEBUG3, "Handling CAPABILITY\n");

  s = imap_next_word(s);
  char *bracket = strchr(s, ']');
  if (bracket)
    *bracket = '\0';
  FREE(&adata->capstr);
  adata->capstr = mutt_str_strdup(s);
  adata->capabilities = 0;

  while (*s)
  {
    for (size_t i = 0; Capabilities[i]; i++)
    {
      if (mutt_str_word_casecmp(Capabilities[i], s) == 0)
      {
        adata->capabilities |= (1 << i);
        mutt_debug(LL_DEBUG3, " Found capability \"%s\": %lu\n", Capabilities[i], i);
        break;
      }
    }
    s = imap_next_word(s);
  }
}


static void cmd_parse_list(struct ImapAccountData *adata, char *s)
{
  struct ImapList *list = NULL;
  struct ImapList lb = { 0 };
  char delimbuf[5]; 
  unsigned int litlen;

  if (adata->cmdresult)
    list = adata->cmdresult;
  else list = &lb;

  memset(list, 0, sizeof(struct ImapList));

  
  s = imap_next_word(s);
  if (*s != '(')
  {
    mutt_debug(LL_DEBUG1, "Bad LIST response\n");
    return;
  }
  s++;
  while (*s)
  {
    if (mutt_str_startswith(s, "\\NoSelect", CASE_IGNORE))
      list->noselect = true;
    else if (mutt_str_startswith(s, "\\NonExistent", CASE_IGNORE)) 
      list->noselect = true;
    else if (mutt_str_startswith(s, "\\NoInferiors", CASE_IGNORE))
      list->noinferiors = true;
    else if (mutt_str_startswith(s, "\\HasNoChildren", CASE_IGNORE)) 
      list->noinferiors = true;

    s = imap_next_word(s);
    if (*(s - 2) == ')')
      break;
  }

  
  if (!mutt_str_startswith(s, "NIL", CASE_IGNORE))
  {
    delimbuf[0] = '\0';
    mutt_str_strcat(delimbuf, 5, s);
    imap_unquote_string(delimbuf);
    list->delim = delimbuf[0];
  }

  
  s = imap_next_word(s);
  
  if (imap_get_literal_count(s, &litlen) == 0)
  {
    if (imap_cmd_step(adata) != IMAP_RES_CONTINUE)
    {
      adata->status = IMAP_FATAL;
      return;
    }

    if (strlen(adata->buf) < litlen)
    {
      mutt_debug(LL_DEBUG1, "Error parsing LIST mailbox\n");
      return;
    }

    list->name = adata->buf;
    s = list->name + litlen;
    if (s[0] != '\0')
    {
      s[0] = '\0';
      s++;
      SKIPWS(s);
    }
  }
  else {
    list->name = s;
    
    s = imap_next_word(s);
    if (s[0] != '\0')
      s[-1] = '\0';
    imap_unmunge_mbox_name(adata->unicode, list->name);
  }

  if (list->name[0] == '\0')
  {
    adata->delim = list->delim;
    mutt_debug(LL_DEBUG3, "Root delimiter: %c\n", adata->delim);
  }
}


static void cmd_parse_lsub(struct ImapAccountData *adata, char *s)
{
  char buf[256];
  char quoted_name[256];
  struct Buffer err;
  struct Url url = { 0 };
  struct ImapList list = { 0 };

  if (adata->cmdresult)
  {
    
    cmd_parse_list(adata, s);
    return;
  }

  if (!C_ImapCheckSubscribed)
    return;

  adata->cmdresult = &list;
  cmd_parse_list(adata, s);
  adata->cmdresult = NULL;
  
  if (!list.name || list.noselect)
    return;

  mutt_debug(LL_DEBUG3, "Subscribing to %s\n", list.name);

  mutt_str_strfcpy(buf, "mailboxes \"", sizeof(buf));
  mutt_account_tourl(&adata->conn->account, &url);
  
  imap_quote_string(quoted_name, sizeof(quoted_name), list.name, true);
  url.path = quoted_name + 1;
  url.path[strlen(url.path) - 1] = '\0';
  if (mutt_str_strcmp(url.user, C_ImapUser) == 0)
    url.user = NULL;
  url_tostring(&url, buf + 11, sizeof(buf) - 11, 0);
  mutt_str_strcat(buf, sizeof(buf), "\"");
  mutt_buffer_init(&err);
  err.dsize = 256;
  err.data = mutt_mem_malloc(err.dsize);
  if (mutt_parse_rc_line(buf, &err))
    mutt_debug(LL_DEBUG1, "Error adding subscribed mailbox: %s\n", err.data);
  FREE(&err.data);
}


static void cmd_parse_myrights(struct ImapAccountData *adata, const char *s)
{
  mutt_debug(LL_DEBUG2, "Handling MYRIGHTS\n");

  s = imap_next_word((char *) s);
  s = imap_next_word((char *) s);

  
  adata->mailbox->rights = 0;

  while (*s && !isspace((unsigned char) *s))
  {
    switch (*s)
    {
      case 'a':
        adata->mailbox->rights |= MUTT_ACL_ADMIN;
        break;
      case 'e':
        adata->mailbox->rights |= MUTT_ACL_EXPUNGE;
        break;
      case 'i':
        adata->mailbox->rights |= MUTT_ACL_INSERT;
        break;
      case 'k':
        adata->mailbox->rights |= MUTT_ACL_CREATE;
        break;
      case 'l':
        adata->mailbox->rights |= MUTT_ACL_LOOKUP;
        break;
      case 'p':
        adata->mailbox->rights |= MUTT_ACL_POST;
        break;
      case 'r':
        adata->mailbox->rights |= MUTT_ACL_READ;
        break;
      case 's':
        adata->mailbox->rights |= MUTT_ACL_SEEN;
        break;
      case 't':
        adata->mailbox->rights |= MUTT_ACL_DELETE;
        break;
      case 'w':
        adata->mailbox->rights |= MUTT_ACL_WRITE;
        break;
      case 'x':
        adata->mailbox->rights |= MUTT_ACL_DELMX;
        break;

      
      case 'c':
        adata->mailbox->rights |= MUTT_ACL_CREATE | MUTT_ACL_DELMX;
        break;
      case 'd':
        adata->mailbox->rights |= MUTT_ACL_DELETE | MUTT_ACL_EXPUNGE;
        break;
      default:
        mutt_debug(LL_DEBUG1, "Unknown right: %c\n", *s);
    }
    s++;
  }
}


static struct Mailbox *find_mailbox(struct ImapAccountData *adata, const char *name)
{
  if (!adata || !adata->account || !name)
    return NULL;

  struct MailboxNode *np = NULL;
  STAILQ_FOREACH(np, &adata->account->mailboxes, entries)
  {
    struct ImapMboxData *mdata = imap_mdata_get(np->mailbox);
    if (mutt_str_strcmp(name, mdata->name) == 0)
      return np->mailbox;
  }

  return NULL;
}


static void cmd_parse_status(struct ImapAccountData *adata, char *s)
{
  unsigned int litlen = 0;

  char *mailbox = imap_next_word(s);

  
  if (imap_get_literal_count(mailbox, &litlen) == 0)
  {
    if (imap_cmd_step(adata) != IMAP_RES_CONTINUE)
    {
      adata->status = IMAP_FATAL;
      return;
    }

    if (strlen(adata->buf) < litlen)
    {
      mutt_debug(LL_DEBUG1, "Error parsing STATUS mailbox\n");
      return;
    }

    mailbox = adata->buf;
    s = mailbox + litlen;
    s[0] = '\0';
    s++;
    SKIPWS(s);
  }
  else {
    s = imap_next_word(mailbox);
    s[-1] = '\0';
    imap_unmunge_mbox_name(adata->unicode, mailbox);
  }

  struct Mailbox *m = find_mailbox(adata, mailbox);
  struct ImapMboxData *mdata = imap_mdata_get(m);
  if (!mdata)
  {
    mutt_debug(LL_DEBUG3, "Received status for an unexpected mailbox: %s\n", mailbox);
    return;
  }
  uint32_t olduv = mdata->uidvalidity;
  unsigned int oldun = mdata->uid_next;

  if (*s++ != '(')
  {
    mutt_debug(LL_DEBUG1, "Error parsing STATUS\n");
    return;
  }
  while ((s[0] != '\0') && (s[0] != ')'))
  {
    char *value = imap_next_word(s);

    errno = 0;
    const unsigned long ulcount = strtoul(value, &value, 10);
    if (((errno == ERANGE) && (ulcount == ULONG_MAX)) || ((unsigned int) ulcount != ulcount))
    {
      mutt_debug(LL_DEBUG1, "Error parsing STATUS number\n");
      return;
    }
    const unsigned int count = (unsigned int) ulcount;

    if (mutt_str_startswith(s, "MESSAGES", CASE_MATCH))
      mdata->messages = count;
    else if (mutt_str_startswith(s, "RECENT", CASE_MATCH))
      mdata->recent = count;
    else if (mutt_str_startswith(s, "UIDNEXT", CASE_MATCH))
      mdata->uid_next = count;
    else if (mutt_str_startswith(s, "UIDVALIDITY", CASE_MATCH))
      mdata->uidvalidity = count;
    else if (mutt_str_startswith(s, "UNSEEN", CASE_MATCH))
      mdata->unseen = count;

    s = value;
    if ((s[0] != '\0') && (*s != ')'))
      s = imap_next_word(s);
  }
  mutt_debug(LL_DEBUG3, "%s (UIDVALIDITY: %u, UIDNEXT: %u) %d messages, %d recent, %d unseen\n", mdata->name, mdata->uidvalidity, mdata->uid_next, mdata->messages, mdata->recent, mdata->unseen);


  mutt_debug(LL_DEBUG3, "Running default STATUS handler\n");

  mutt_debug(LL_DEBUG3, "Found %s in mailbox list (OV: %u ON: %u U: %d)\n", mailbox, olduv, oldun, mdata->unseen);

  bool new_mail = false;
  if (C_MailCheckRecent)
  {
    if ((olduv != 0) && (olduv == mdata->uidvalidity))
    {
      if (oldun < mdata->uid_next)
        new_mail = (mdata->unseen > 0);
    }
    else if ((olduv == 0) && (oldun == 0))
    {
      
      new_mail = (mdata->recent > 0);
    }
    else new_mail = (mdata->unseen > 0);
  }
  else new_mail = (mdata->unseen > 0);


  if ((m->has_new != new_mail) || (m->msg_count != mdata->messages) || (m->msg_unread != mdata->unseen))
  {
    mutt_menu_set_current_redraw(REDRAW_SIDEBAR);
  }


  m->has_new = new_mail;
  m->msg_count = mdata->messages;
  m->msg_unread = mdata->unseen;

  
  if (m->has_new)
    mdata->uid_next = oldun;
}


static void cmd_parse_enabled(struct ImapAccountData *adata, const char *s)
{
  mutt_debug(LL_DEBUG2, "Handling ENABLED\n");

  while ((s = imap_next_word((char *) s)) && (*s != '\0'))
  {
    if (mutt_str_startswith(s, "UTF8=ACCEPT", CASE_IGNORE) || mutt_str_startswith(s, "UTF8=ONLY", CASE_IGNORE))
    {
      adata->unicode = true;
    }
    if (mutt_str_startswith(s, "QRESYNC", CASE_IGNORE))
      adata->qresync = true;
  }
}

static void cmd_parse_exists(struct ImapAccountData *adata, const char *pn)
{
  unsigned int count = 0;
  mutt_debug(LL_DEBUG2, "Handling EXISTS\n");

  if (mutt_str_atoui(pn, &count) < 0)
  {
    mutt_debug(LL_DEBUG1, "Malformed EXISTS: '%s'\n", pn);
    return;
  }

  struct ImapMboxData *mdata = adata->mailbox->mdata;

  
  if (count < mdata->max_msn)
  {
    
    mutt_debug(LL_DEBUG1, "Message count is out of sync\n");
  }
  
  else if (count == mdata->max_msn)
    mutt_debug(LL_DEBUG3, "superfluous EXISTS message\n");
  else {
    mutt_debug(LL_DEBUG2, "New mail in %s - %d messages total\n", mdata->name, count);
    mdata->reopen |= IMAP_NEWMAIL_PENDING;
    mdata->new_mail_count = count;
  }
}


static int cmd_handle_untagged(struct ImapAccountData *adata)
{
  char *s = imap_next_word(adata->buf);
  char *pn = imap_next_word(s);

  if ((adata->state >= IMAP_SELECTED) && isdigit((unsigned char) *s))
  {
    
    pn = s;
    s = imap_next_word(s);

    
    if (mutt_str_startswith(s, "EXISTS", CASE_IGNORE))
      cmd_parse_exists(adata, pn);
    else if (mutt_str_startswith(s, "EXPUNGE", CASE_IGNORE))
      cmd_parse_expunge(adata, pn);
    else if (mutt_str_startswith(s, "FETCH", CASE_IGNORE))
      cmd_parse_fetch(adata, pn);
  }
  else if ((adata->state >= IMAP_SELECTED) && mutt_str_startswith(s, "VANISHED", CASE_IGNORE))
    cmd_parse_vanished(adata, pn);
  else if (mutt_str_startswith(s, "CAPABILITY", CASE_IGNORE))
    cmd_parse_capability(adata, s);
  else if (mutt_str_startswith(s, "OK [CAPABILITY", CASE_IGNORE))
    cmd_parse_capability(adata, pn);
  else if (mutt_str_startswith(pn, "OK [CAPABILITY", CASE_IGNORE))
    cmd_parse_capability(adata, imap_next_word(pn));
  else if (mutt_str_startswith(s, "LIST", CASE_IGNORE))
    cmd_parse_list(adata, s);
  else if (mutt_str_startswith(s, "LSUB", CASE_IGNORE))
    cmd_parse_lsub(adata, s);
  else if (mutt_str_startswith(s, "MYRIGHTS", CASE_IGNORE))
    cmd_parse_myrights(adata, s);
  else if (mutt_str_startswith(s, "SEARCH", CASE_IGNORE))
    cmd_parse_search(adata, s);
  else if (mutt_str_startswith(s, "STATUS", CASE_IGNORE))
    cmd_parse_status(adata, s);
  else if (mutt_str_startswith(s, "ENABLED", CASE_IGNORE))
    cmd_parse_enabled(adata, s);
  else if (mutt_str_startswith(s, "BYE", CASE_IGNORE))
  {
    mutt_debug(LL_DEBUG2, "Handling BYE\n");

    
    if (adata->status == IMAP_BYE)
      return 0;

    
    s += 3;
    SKIPWS(s);
    mutt_error("%s", s);
    cmd_handle_fatal(adata);

    return -1;
  }
  else if (C_ImapServernoise && mutt_str_startswith(s, "NO", CASE_IGNORE))
  {
    mutt_debug(LL_DEBUG2, "Handling untagged NO\n");

    
    mutt_error("%s", s + 2);
  }

  return 0;
}


int imap_cmd_start(struct ImapAccountData *adata, const char *cmdstr)
{
  return cmd_start(adata, cmdstr, IMAP_CMD_NO_FLAGS);
}


int imap_cmd_step(struct ImapAccountData *adata)
{
  if (!adata)
    return -1;

  size_t len = 0;
  int c;
  int rc;
  int stillrunning = 0;
  struct ImapCommand *cmd = NULL;

  if (adata->status == IMAP_FATAL)
  {
    cmd_handle_fatal(adata);
    return IMAP_RES_BAD;
  }

  
  do {
    if (len == adata->blen)
    {
      mutt_mem_realloc(&adata->buf, adata->blen + IMAP_CMD_BUFSIZE);
      adata->blen = adata->blen + IMAP_CMD_BUFSIZE;
      mutt_debug(LL_DEBUG3, "grew buffer to %lu bytes\n", adata->blen);
    }

    
    if (len)
      len--;
    c = mutt_socket_readln_d(adata->buf + len, adata->blen - len, adata->conn, MUTT_SOCK_LOG_FULL);
    if (c <= 0)
    {
      mutt_debug(LL_DEBUG1, "Error reading server response\n");
      cmd_handle_fatal(adata);
      return IMAP_RES_BAD;
    }

    len += c;
  }
  
  while (len == adata->blen);

  
  if ((adata->blen > IMAP_CMD_BUFSIZE) && (len <= IMAP_CMD_BUFSIZE))
  {
    mutt_mem_realloc(&adata->buf, IMAP_CMD_BUFSIZE);
    adata->blen = IMAP_CMD_BUFSIZE;
    mutt_debug(LL_DEBUG3, "shrank buffer to %lu bytes\n", adata->blen);
  }

  adata->lastread = mutt_date_epoch();

  
  if ((mutt_str_startswith(adata->buf, "* ", CASE_MATCH) || mutt_str_startswith(imap_next_word(adata->buf), "OK [", CASE_MATCH)) && cmd_handle_untagged(adata))

  {
    return IMAP_RES_BAD;
  }

  
  if (adata->buf[0] == '+')
    return IMAP_RES_RESPOND;

  
  rc = IMAP_RES_OK;
  c = adata->lastcmd;
  do {
    cmd = &adata->cmds[c];
    if (cmd->state == IMAP_RES_NEW)
    {
      if (mutt_str_startswith(adata->buf, cmd->seq, CASE_MATCH))
      {
        if (!stillrunning)
        {
          
          adata->lastcmd = (adata->lastcmd + 1) % adata->cmdslots;
        }
        cmd->state = cmd_status(adata->buf);
        rc = cmd->state;
        if (cmd->state == IMAP_RES_NO || cmd->state == IMAP_RES_BAD)
        {
          mutt_message(_("IMAP command failed: %s"), adata->buf);
        }
      }
      else stillrunning++;
    }

    c = (c + 1) % adata->cmdslots;
  } while (c != adata->nextcmd);

  if (stillrunning)
    rc = IMAP_RES_CONTINUE;
  else {
    mutt_debug(LL_DEBUG3, "IMAP queue drained\n");
    imap_cmd_finish(adata);
  }

  return rc;
}


bool imap_code(const char *s)
{
  return cmd_status(s) == IMAP_RES_OK;
}


const char *imap_cmd_trailer(struct ImapAccountData *adata)
{
  static const char *notrailer = "";
  const char *s = adata->buf;

  if (!s)
  {
    mutt_debug(LL_DEBUG2, "not a tagged response\n");
    return notrailer;
  }

  s = imap_next_word((char *) s);
  if (!s || (!mutt_str_startswith(s, "OK", CASE_IGNORE) && !mutt_str_startswith(s, "NO", CASE_IGNORE) && !mutt_str_startswith(s, "BAD", CASE_IGNORE)))

  {
    mutt_debug(LL_DEBUG2, "not a command completion: %s\n", adata->buf);
    return notrailer;
  }

  s = imap_next_word((char *) s);
  if (!s)
    return notrailer;

  return s;
}


int imap_exec(struct ImapAccountData *adata, const char *cmdstr, ImapCmdFlags flags)
{
  int rc;

  rc = cmd_start(adata, cmdstr, flags);
  if (rc < 0)
  {
    cmd_handle_fatal(adata);
    return IMAP_EXEC_FATAL;
  }

  if (flags & IMAP_CMD_QUEUE)
    return IMAP_EXEC_SUCCESS;

  if ((flags & IMAP_CMD_POLL) && (C_ImapPollTimeout > 0) && ((mutt_socket_poll(adata->conn, C_ImapPollTimeout)) == 0))
  {
    mutt_error(_("Connection to %s timed out"), adata->conn->account.host);
    cmd_handle_fatal(adata);
    return IMAP_EXEC_FATAL;
  }

  
  mutt_sig_allow_interrupt(true);
  do {
    rc = imap_cmd_step(adata);
  } while (rc == IMAP_RES_CONTINUE);
  mutt_sig_allow_interrupt(false);

  if (rc == IMAP_RES_NO)
    return IMAP_EXEC_ERROR;
  if (rc != IMAP_RES_OK)
  {
    if (adata->status != IMAP_FATAL)
      return IMAP_EXEC_ERROR;

    mutt_debug(LL_DEBUG1, "command failed: %s\n", adata->buf);
    return IMAP_EXEC_FATAL;
  }

  return IMAP_EXEC_SUCCESS;
}


void imap_cmd_finish(struct ImapAccountData *adata)
{
  if (!adata)
    return;

  if (adata->status == IMAP_FATAL)
  {
    adata->closing = false;
    cmd_handle_fatal(adata);
    return;
  }

  if (!(adata->state >= IMAP_SELECTED) || (adata->mailbox && adata->closing))
  {
    adata->closing = false;
    return;
  }

  adata->closing = false;

  struct ImapMboxData *mdata = imap_mdata_get(adata->mailbox);

  if (mdata && mdata->reopen & IMAP_REOPEN_ALLOW)
  {
    
    if (mdata->reopen & IMAP_EXPUNGE_PENDING)
    {
      mutt_debug(LL_DEBUG2, "Expunging mailbox\n");
      imap_expunge_mailbox(adata->mailbox);
      
      if (!(mdata->reopen & IMAP_EXPUNGE_EXPECTED))
        mdata->check_status |= IMAP_EXPUNGE_PENDING;
      mdata->reopen &= ~(IMAP_EXPUNGE_PENDING | IMAP_EXPUNGE_EXPECTED);
    }

    
    if (mdata->reopen & IMAP_NEWMAIL_PENDING && (mdata->new_mail_count > mdata->max_msn))
    {
      if (!(mdata->reopen & IMAP_EXPUNGE_PENDING))
        mdata->check_status |= IMAP_NEWMAIL_PENDING;

      mutt_debug(LL_DEBUG2, "Fetching new mails from %d to %d\n", mdata->max_msn + 1, mdata->new_mail_count);
      imap_read_headers(adata->mailbox, mdata->max_msn + 1, mdata->new_mail_count, false);
    }

    
    if (mdata->reopen & IMAP_EXPUNGE_PENDING && !(mdata->reopen & IMAP_EXPUNGE_EXPECTED))
      mdata->check_status |= IMAP_EXPUNGE_PENDING;

    if (mdata->reopen & IMAP_EXPUNGE_PENDING)
      mdata->reopen &= ~(IMAP_EXPUNGE_PENDING | IMAP_EXPUNGE_EXPECTED);
  }

  adata->status = 0;
}


int imap_cmd_idle(struct ImapAccountData *adata)
{
  int rc;

  if (cmd_start(adata, "IDLE", IMAP_CMD_POLL) < 0)
  {
    cmd_handle_fatal(adata);
    return -1;
  }

  if ((C_ImapPollTimeout > 0) && ((mutt_socket_poll(adata->conn, C_ImapPollTimeout)) == 0))
  {
    mutt_error(_("Connection to %s timed out"), adata->conn->account.host);
    cmd_handle_fatal(adata);
    return -1;
  }

  do {
    rc = imap_cmd_step(adata);
  } while (rc == IMAP_RES_CONTINUE);

  if (rc == IMAP_RES_RESPOND)
  {
    
    adata->state = IMAP_IDLE;
    
    mutt_buffer_addstr(&adata->cmdbuf, "DONE\r\n");
    rc = IMAP_RES_OK;
  }
  if (rc != IMAP_RES_OK)
  {
    mutt_debug(LL_DEBUG1, "error starting IDLE\n");
    return -1;
  }

  return 0;
}
