


















typedef Oid ConnCacheKey;

typedef struct ConnCacheEntry {
	ConnCacheKey key;			
	PGconn	   *conn;			
	
	int			xact_depth;		
	bool		have_prep_stmt; 
	bool		have_error;		
	bool		changing_xact_state;	
	bool		invalidated;	
	uint32		server_hashvalue;	
	uint32		mapping_hashvalue;	
} ConnCacheEntry;


static HTAB *ConnectionHash = NULL;


static unsigned int cursor_number = 0;
static unsigned int prep_stmt_number = 0;


static bool xact_got_connection = false;


static PGconn *connect_pg_server(ForeignServer *server, UserMapping *user);
static void disconnect_pg_server(ConnCacheEntry *entry);
static void check_conn_params(const char **keywords, const char **values, UserMapping *user);
static void configure_remote_session(PGconn *conn);
static void do_sql_command(PGconn *conn, const char *sql);
static void begin_remote_xact(ConnCacheEntry *entry);
static void pgfdw_xact_callback(XactEvent event, void *arg);
static void pgfdw_subxact_callback(SubXactEvent event, SubTransactionId mySubid, SubTransactionId parentSubid, void *arg);


static void pgfdw_inval_callback(Datum arg, int cacheid, uint32 hashvalue);
static void pgfdw_reject_incomplete_xact_state_change(ConnCacheEntry *entry);
static bool pgfdw_cancel_query(PGconn *conn);
static bool pgfdw_exec_cleanup_query(PGconn *conn, const char *query, bool ignore_errors);
static bool pgfdw_get_cleanup_result(PGconn *conn, TimestampTz endtime, PGresult **result);



PGconn * GetConnection(UserMapping *user, bool will_prep_stmt)
{
	bool		found;
	ConnCacheEntry *entry;
	ConnCacheKey key;

	
	if (ConnectionHash == NULL)
	{
		HASHCTL		ctl;

		MemSet(&ctl, 0, sizeof(ctl));
		ctl.keysize = sizeof(ConnCacheKey);
		ctl.entrysize = sizeof(ConnCacheEntry);
		
		ctl.hcxt = CacheMemoryContext;
		ConnectionHash = hash_create("postgres_fdw connections", 8, &ctl, HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);


		
		RegisterXactCallback(pgfdw_xact_callback, NULL);
		RegisterSubXactCallback(pgfdw_subxact_callback, NULL);
		CacheRegisterSyscacheCallback(FOREIGNSERVEROID, pgfdw_inval_callback, (Datum) 0);
		CacheRegisterSyscacheCallback(USERMAPPINGOID, pgfdw_inval_callback, (Datum) 0);
	}

	
	xact_got_connection = true;

	
	key = user->umid;

	
	entry = hash_search(ConnectionHash, &key, HASH_ENTER, &found);
	if (!found)
	{
		
		entry->conn = NULL;
	}

	
	pgfdw_reject_incomplete_xact_state_change(entry);

	
	if (entry->conn != NULL && entry->invalidated && entry->xact_depth == 0)
	{
		elog(DEBUG3, "closing connection %p for option changes to take effect", entry->conn);
		disconnect_pg_server(entry);
	}

	

	
	if (entry->conn == NULL)
	{
		ForeignServer *server = GetForeignServer(user->serverid);

		
		entry->xact_depth = 0;
		entry->have_prep_stmt = false;
		entry->have_error = false;
		entry->changing_xact_state = false;
		entry->invalidated = false;
		entry->server_hashvalue = GetSysCacheHashValue1(FOREIGNSERVEROID, ObjectIdGetDatum(server->serverid));

		entry->mapping_hashvalue = GetSysCacheHashValue1(USERMAPPINGOID, ObjectIdGetDatum(user->umid));


		
		entry->conn = connect_pg_server(server, user);

		elog(DEBUG3, "new postgres_fdw connection %p for server \"%s\" (user mapping oid %u, userid %u)", entry->conn, server->servername, user->umid, user->userid);
	}

	
	begin_remote_xact(entry);

	
	entry->have_prep_stmt |= will_prep_stmt;

	return entry->conn;
}


static PGconn * connect_pg_server(ForeignServer *server, UserMapping *user)
{
	PGconn	   *volatile conn = NULL;

	
	PG_TRY();
	{
		const char **keywords;
		const char **values;
		int			n;

		
		n = list_length(server->options) + list_length(user->options) + 3;
		keywords = (const char **) palloc(n * sizeof(char *));
		values = (const char **) palloc(n * sizeof(char *));

		n = 0;
		n += ExtractConnectionOptions(server->options, keywords + n, values + n);
		n += ExtractConnectionOptions(user->options, keywords + n, values + n);

		
		keywords[n] = "fallback_application_name";
		values[n] = "postgres_fdw";
		n++;

		
		keywords[n] = "client_encoding";
		values[n] = GetDatabaseEncodingName();
		n++;

		keywords[n] = values[n] = NULL;

		
		check_conn_params(keywords, values, user);

		conn = PQconnectdbParams(keywords, values, false);
		if (!conn || PQstatus(conn) != CONNECTION_OK)
			ereport(ERROR, (errcode(ERRCODE_SQLCLIENT_UNABLE_TO_ESTABLISH_SQLCONNECTION), errmsg("could not connect to server \"%s\"", server->servername), errdetail_internal("%s", pchomp(PQerrorMessage(conn)))));




		
		if (!superuser_arg(user->userid) && !PQconnectionUsedPassword(conn))
			ereport(ERROR, (errcode(ERRCODE_S_R_E_PROHIBITED_SQL_STATEMENT_ATTEMPTED), errmsg("password is required"), errdetail("Non-superuser cannot connect if the server does not request a password."), errhint("Target server's authentication method must be changed.")));




		
		configure_remote_session(conn);

		pfree(keywords);
		pfree(values);
	}
	PG_CATCH();
	{
		
		if (conn)
			PQfinish(conn);
		PG_RE_THROW();
	}
	PG_END_TRY();

	return conn;
}


static void disconnect_pg_server(ConnCacheEntry *entry)
{
	if (entry->conn != NULL)
	{
		PQfinish(entry->conn);
		entry->conn = NULL;
	}
}


static void check_conn_params(const char **keywords, const char **values, UserMapping *user)
{
	int			i;

	
	if (superuser_arg(user->userid))
		return;

	
	for (i = 0; keywords[i] != NULL; i++)
	{
		if (strcmp(keywords[i], "password") == 0 && values[i][0] != '\0')
			return;
	}

	ereport(ERROR, (errcode(ERRCODE_S_R_E_PROHIBITED_SQL_STATEMENT_ATTEMPTED), errmsg("password is required"), errdetail("Non-superusers must provide a password in the user mapping.")));


}


static void configure_remote_session(PGconn *conn)
{
	int			remoteversion = PQserverVersion(conn);

	
	do_sql_command(conn, "SET search_path = pg_catalog");

	
	do_sql_command(conn, "SET timezone = 'UTC'");

	
	do_sql_command(conn, "SET datestyle = ISO");
	if (remoteversion >= 80400)
		do_sql_command(conn, "SET intervalstyle = postgres");
	if (remoteversion >= 90000)
		do_sql_command(conn, "SET extra_float_digits = 3");
	else do_sql_command(conn, "SET extra_float_digits = 2");
}


static void do_sql_command(PGconn *conn, const char *sql)
{
	PGresult   *res;

	if (!PQsendQuery(conn, sql))
		pgfdw_report_error(ERROR, NULL, conn, false, sql);
	res = pgfdw_get_result(conn, sql);
	if (PQresultStatus(res) != PGRES_COMMAND_OK)
		pgfdw_report_error(ERROR, res, conn, true, sql);
	PQclear(res);
}


static void begin_remote_xact(ConnCacheEntry *entry)
{
	int			curlevel = GetCurrentTransactionNestLevel();

	
	if (entry->xact_depth <= 0)
	{
		const char *sql;

		elog(DEBUG3, "starting remote transaction on connection %p", entry->conn);

		if (IsolationIsSerializable())
			sql = "START TRANSACTION ISOLATION LEVEL SERIALIZABLE";
		else sql = "START TRANSACTION ISOLATION LEVEL REPEATABLE READ";
		entry->changing_xact_state = true;
		do_sql_command(entry->conn, sql);
		entry->xact_depth = 1;
		entry->changing_xact_state = false;
	}

	
	while (entry->xact_depth < curlevel)
	{
		char		sql[64];

		snprintf(sql, sizeof(sql), "SAVEPOINT s%d", entry->xact_depth + 1);
		entry->changing_xact_state = true;
		do_sql_command(entry->conn, sql);
		entry->xact_depth++;
		entry->changing_xact_state = false;
	}
}


void ReleaseConnection(PGconn *conn)
{
	
}


unsigned int GetCursorNumber(PGconn *conn)
{
	return ++cursor_number;
}


unsigned int GetPrepStmtNumber(PGconn *conn)
{
	return ++prep_stmt_number;
}


PGresult * pgfdw_exec_query(PGconn *conn, const char *query)
{
	
	if (!PQsendQuery(conn, query))
		pgfdw_report_error(ERROR, NULL, conn, false, query);

	
	return pgfdw_get_result(conn, query);
}


PGresult * pgfdw_get_result(PGconn *conn, const char *query)
{
	PGresult   *volatile last_res = NULL;

	
	PG_TRY();
	{
		for (;;)
		{
			PGresult   *res;

			while (PQisBusy(conn))
			{
				int			wc;

				
				wc = WaitLatchOrSocket(MyLatch, WL_LATCH_SET | WL_SOCKET_READABLE | WL_EXIT_ON_PM_DEATH, PQsocket(conn), -1L, PG_WAIT_EXTENSION);



				ResetLatch(MyLatch);

				CHECK_FOR_INTERRUPTS();

				
				if (wc & WL_SOCKET_READABLE)
				{
					if (!PQconsumeInput(conn))
						pgfdw_report_error(ERROR, NULL, conn, false, query);
				}
			}

			res = PQgetResult(conn);
			if (res == NULL)
				break;			

			PQclear(last_res);
			last_res = res;
		}
	}
	PG_CATCH();
	{
		PQclear(last_res);
		PG_RE_THROW();
	}
	PG_END_TRY();

	return last_res;
}


void pgfdw_report_error(int elevel, PGresult *res, PGconn *conn, bool clear, const char *sql)

{
	
	PG_TRY();
	{
		char	   *diag_sqlstate = PQresultErrorField(res, PG_DIAG_SQLSTATE);
		char	   *message_primary = PQresultErrorField(res, PG_DIAG_MESSAGE_PRIMARY);
		char	   *message_detail = PQresultErrorField(res, PG_DIAG_MESSAGE_DETAIL);
		char	   *message_hint = PQresultErrorField(res, PG_DIAG_MESSAGE_HINT);
		char	   *message_context = PQresultErrorField(res, PG_DIAG_CONTEXT);
		int			sqlstate;

		if (diag_sqlstate)
			sqlstate = MAKE_SQLSTATE(diag_sqlstate[0], diag_sqlstate[1], diag_sqlstate[2], diag_sqlstate[3], diag_sqlstate[4]);



		else sqlstate = ERRCODE_CONNECTION_FAILURE;

		
		if (message_primary == NULL)
			message_primary = pchomp(PQerrorMessage(conn));

		ereport(elevel, (errcode(sqlstate), message_primary ? errmsg_internal("%s", message_primary) :

				 errmsg("could not obtain message string for remote error"), message_detail ? errdetail_internal("%s", message_detail) : 0, message_hint ? errhint("%s", message_hint) : 0, message_context ? errcontext("%s", message_context) : 0, sql ? errcontext("remote SQL command: %s", sql) : 0));



	}
	PG_CATCH();
	{
		if (clear)
			PQclear(res);
		PG_RE_THROW();
	}
	PG_END_TRY();
	if (clear)
		PQclear(res);
}


static void pgfdw_xact_callback(XactEvent event, void *arg)
{
	HASH_SEQ_STATUS scan;
	ConnCacheEntry *entry;

	
	if (!xact_got_connection)
		return;

	
	hash_seq_init(&scan, ConnectionHash);
	while ((entry = (ConnCacheEntry *) hash_seq_search(&scan)))
	{
		PGresult   *res;

		
		if (entry->conn == NULL)
			continue;

		
		if (entry->xact_depth > 0)
		{
			bool		abort_cleanup_failure = false;

			elog(DEBUG3, "closing remote transaction on connection %p", entry->conn);

			switch (event)
			{
				case XACT_EVENT_PARALLEL_PRE_COMMIT:
				case XACT_EVENT_PRE_COMMIT:

					
					pgfdw_reject_incomplete_xact_state_change(entry);

					
					entry->changing_xact_state = true;
					do_sql_command(entry->conn, "COMMIT TRANSACTION");
					entry->changing_xact_state = false;

					
					if (entry->have_prep_stmt && entry->have_error)
					{
						res = PQexec(entry->conn, "DEALLOCATE ALL");
						PQclear(res);
					}
					entry->have_prep_stmt = false;
					entry->have_error = false;
					break;
				case XACT_EVENT_PRE_PREPARE:

					
					break;
				case XACT_EVENT_PARALLEL_COMMIT:
				case XACT_EVENT_COMMIT:
				case XACT_EVENT_PREPARE:
					
					elog(ERROR, "missed cleaning up connection during pre-commit");
					break;
				case XACT_EVENT_PARALLEL_ABORT:
				case XACT_EVENT_ABORT:

					
					if (in_error_recursion_trouble())
						entry->changing_xact_state = true;

					
					if (entry->changing_xact_state)
						break;

					
					entry->changing_xact_state = true;

					
					entry->have_error = true;

					
					if (PQtransactionStatus(entry->conn) == PQTRANS_ACTIVE && !pgfdw_cancel_query(entry->conn))
					{
						
						abort_cleanup_failure = true;
					}
					else if (!pgfdw_exec_cleanup_query(entry->conn, "ABORT TRANSACTION", false))

					{
						
						abort_cleanup_failure = true;
					}
					else if (entry->have_prep_stmt && entry->have_error && !pgfdw_exec_cleanup_query(entry->conn, "DEALLOCATE ALL", true))


					{
						
						abort_cleanup_failure = true;
					}
					else {
						entry->have_prep_stmt = false;
						entry->have_error = false;
					}

					
					entry->changing_xact_state = abort_cleanup_failure;
					break;
			}
		}

		
		entry->xact_depth = 0;

		
		if (PQstatus(entry->conn) != CONNECTION_OK || PQtransactionStatus(entry->conn) != PQTRANS_IDLE || entry->changing_xact_state)

		{
			elog(DEBUG3, "discarding connection %p", entry->conn);
			disconnect_pg_server(entry);
		}
	}

	
	xact_got_connection = false;

	
	cursor_number = 0;
}


static void pgfdw_subxact_callback(SubXactEvent event, SubTransactionId mySubid, SubTransactionId parentSubid, void *arg)

{
	HASH_SEQ_STATUS scan;
	ConnCacheEntry *entry;
	int			curlevel;

	
	if (!(event == SUBXACT_EVENT_PRE_COMMIT_SUB || event == SUBXACT_EVENT_ABORT_SUB))
		return;

	
	if (!xact_got_connection)
		return;

	
	curlevel = GetCurrentTransactionNestLevel();
	hash_seq_init(&scan, ConnectionHash);
	while ((entry = (ConnCacheEntry *) hash_seq_search(&scan)))
	{
		char		sql[100];

		
		if (entry->conn == NULL || entry->xact_depth < curlevel)
			continue;

		if (entry->xact_depth > curlevel)
			elog(ERROR, "missed cleaning up remote subtransaction at level %d", entry->xact_depth);

		if (event == SUBXACT_EVENT_PRE_COMMIT_SUB)
		{
			
			pgfdw_reject_incomplete_xact_state_change(entry);

			
			snprintf(sql, sizeof(sql), "RELEASE SAVEPOINT s%d", curlevel);
			entry->changing_xact_state = true;
			do_sql_command(entry->conn, sql);
			entry->changing_xact_state = false;
		}
		else if (in_error_recursion_trouble())
		{
			
			entry->changing_xact_state = true;
		}
		else if (!entry->changing_xact_state)
		{
			bool		abort_cleanup_failure = false;

			
			entry->changing_xact_state = true;

			
			entry->have_error = true;

			
			if (PQtransactionStatus(entry->conn) == PQTRANS_ACTIVE && !pgfdw_cancel_query(entry->conn))
				abort_cleanup_failure = true;
			else {
				
				snprintf(sql, sizeof(sql), "ROLLBACK TO SAVEPOINT s%d; RELEASE SAVEPOINT s%d", curlevel, curlevel);

				if (!pgfdw_exec_cleanup_query(entry->conn, sql, false))
					abort_cleanup_failure = true;
			}

			
			entry->changing_xact_state = abort_cleanup_failure;
		}

		
		entry->xact_depth--;
	}
}


static void pgfdw_inval_callback(Datum arg, int cacheid, uint32 hashvalue)
{
	HASH_SEQ_STATUS scan;
	ConnCacheEntry *entry;

	Assert(cacheid == FOREIGNSERVEROID || cacheid == USERMAPPINGOID);

	
	hash_seq_init(&scan, ConnectionHash);
	while ((entry = (ConnCacheEntry *) hash_seq_search(&scan)))
	{
		
		if (entry->conn == NULL)
			continue;

		
		if (hashvalue == 0 || (cacheid == FOREIGNSERVEROID && entry->server_hashvalue == hashvalue) || (cacheid == USERMAPPINGOID && entry->mapping_hashvalue == hashvalue))



			entry->invalidated = true;
	}
}


static void pgfdw_reject_incomplete_xact_state_change(ConnCacheEntry *entry)
{
	HeapTuple	tup;
	Form_pg_user_mapping umform;
	ForeignServer *server;

	
	if (entry->conn == NULL || !entry->changing_xact_state)
		return;

	
	disconnect_pg_server(entry);

	
	tup = SearchSysCache1(USERMAPPINGOID, ObjectIdGetDatum(entry->key));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for user mapping %u", entry->key);
	umform = (Form_pg_user_mapping) GETSTRUCT(tup);
	server = GetForeignServer(umform->umserver);
	ReleaseSysCache(tup);

	ereport(ERROR, (errcode(ERRCODE_CONNECTION_EXCEPTION), errmsg("connection to server \"%s\" was lost", server->servername)));


}


static bool pgfdw_cancel_query(PGconn *conn)
{
	PGcancel   *cancel;
	char		errbuf[256];
	PGresult   *result = NULL;
	TimestampTz endtime;

	
	endtime = TimestampTzPlusMilliseconds(GetCurrentTimestamp(), 30000);

	
	if ((cancel = PQgetCancel(conn)))
	{
		if (!PQcancel(cancel, errbuf, sizeof(errbuf)))
		{
			ereport(WARNING, (errcode(ERRCODE_CONNECTION_FAILURE), errmsg("could not send cancel request: %s", errbuf)));


			PQfreeCancel(cancel);
			return false;
		}
		PQfreeCancel(cancel);
	}

	
	if (pgfdw_get_cleanup_result(conn, endtime, &result))
		return false;
	PQclear(result);

	return true;
}


static bool pgfdw_exec_cleanup_query(PGconn *conn, const char *query, bool ignore_errors)
{
	PGresult   *result = NULL;
	TimestampTz endtime;

	
	endtime = TimestampTzPlusMilliseconds(GetCurrentTimestamp(), 30000);

	
	if (!PQsendQuery(conn, query))
	{
		pgfdw_report_error(WARNING, NULL, conn, false, query);
		return false;
	}

	
	if (pgfdw_get_cleanup_result(conn, endtime, &result))
		return false;

	
	if (PQresultStatus(result) != PGRES_COMMAND_OK)
	{
		pgfdw_report_error(WARNING, result, conn, true, query);
		return ignore_errors;
	}
	PQclear(result);

	return true;
}


static bool pgfdw_get_cleanup_result(PGconn *conn, TimestampTz endtime, PGresult **result)
{
	volatile bool timed_out = false;
	PGresult   *volatile last_res = NULL;

	
	PG_TRY();
	{
		for (;;)
		{
			PGresult   *res;

			while (PQisBusy(conn))
			{
				int			wc;
				TimestampTz now = GetCurrentTimestamp();
				long		secs;
				int			microsecs;
				long		cur_timeout;

				
				if (now >= endtime)
				{
					timed_out = true;
					goto exit;
				}
				TimestampDifference(now, endtime, &secs, &microsecs);

				
				cur_timeout = Min(60000, secs * USECS_PER_SEC + microsecs);

				
				wc = WaitLatchOrSocket(MyLatch, WL_LATCH_SET | WL_SOCKET_READABLE | WL_TIMEOUT | WL_EXIT_ON_PM_DEATH, PQsocket(conn), cur_timeout, PG_WAIT_EXTENSION);



				ResetLatch(MyLatch);

				CHECK_FOR_INTERRUPTS();

				
				if (wc & WL_SOCKET_READABLE)
				{
					if (!PQconsumeInput(conn))
					{
						
						timed_out = true;
						goto exit;
					}
				}
			}

			res = PQgetResult(conn);
			if (res == NULL)
				break;			

			PQclear(last_res);
			last_res = res;
		}
exit:	;
	}
	PG_CATCH();
	{
		PQclear(last_res);
		PG_RE_THROW();
	}
	PG_END_TRY();

	if (timed_out)
		PQclear(last_res);
	else *result = last_res;
	return timed_out;
}
