


























static bool DescribeQuery(const char *query, double *elapsed_msec);
static bool ExecQueryUsingCursor(const char *query, double *elapsed_msec);
static bool command_no_begin(const char *query);
static bool is_select_command(const char *query);



bool openQueryOutputFile(const char *fname, FILE **fout, bool *is_pipe)
{
	if (!fname || fname[0] == '\0')
	{
		*fout = stdout;
		*is_pipe = false;
	}
	else if (*fname == '|')
	{
		*fout = popen(fname + 1, "w");
		*is_pipe = true;
	}
	else {
		*fout = fopen(fname, "w");
		*is_pipe = false;
	}

	if (*fout == NULL)
	{
		psql_error("%s: %s\n", fname, strerror(errno));
		return false;
	}

	return true;
}


bool setQFout(const char *fname)
{
	FILE	   *fout;
	bool		is_pipe;

	
	if (!openQueryOutputFile(fname, &fout, &is_pipe))
		return false;

	
	if (pset.queryFout && pset.queryFout != stdout && pset.queryFout != stderr)
	{
		if (pset.queryFoutPipe)
			pclose(pset.queryFout);
		else fclose(pset.queryFout);
	}

	pset.queryFout = fout;
	pset.queryFoutPipe = is_pipe;

	
	set_sigpipe_trap_state(is_pipe);
	restore_sigpipe_trap();

	return true;
}



char * psql_get_variable(const char *varname, PsqlScanQuoteType quote, void *passthrough)

{
	char	   *result = NULL;
	const char *value;

	
	if (passthrough && !conditional_active((ConditionalStack) passthrough))
		return NULL;

	value = GetVariable(pset.vars, varname);
	if (!value)
		return NULL;

	switch (quote)
	{
		case PQUOTE_PLAIN:
			result = pg_strdup(value);
			break;
		case PQUOTE_SQL_LITERAL:
		case PQUOTE_SQL_IDENT:
			{
				
				char	   *escaped_value;

				if (!pset.db)
				{
					psql_error("cannot escape without active connection\n");
					return NULL;
				}

				if (quote == PQUOTE_SQL_LITERAL)
					escaped_value = PQescapeLiteral(pset.db, value, strlen(value));
				else escaped_value = PQescapeIdentifier(pset.db, value, strlen(value));


				if (escaped_value == NULL)
				{
					const char *error = PQerrorMessage(pset.db);

					psql_error("%s", error);
					return NULL;
				}

				
				result = pg_strdup(escaped_value);
				PQfreemem(escaped_value);
				break;
			}
		case PQUOTE_SHELL_ARG:
			{
				
				PQExpBufferData buf;

				initPQExpBuffer(&buf);
				if (!appendShellStringNoError(&buf, value))
				{
					psql_error("shell command argument contains a newline or carriage return: \"%s\"\n", value);
					free(buf.data);
					return NULL;
				}
				result = buf.data;
				break;
			}

			
	}

	return result;
}



void psql_error(const char *fmt,...)
{
	va_list		ap;

	fflush(stdout);
	if (pset.queryFout && pset.queryFout != stdout)
		fflush(pset.queryFout);

	if (pset.inputfile)
		fprintf(stderr, "%s:%s:" UINT64_FORMAT ": ", pset.progname, pset.inputfile, pset.lineno);
	va_start(ap, fmt);
	vfprintf(stderr, _(fmt), ap);
	va_end(ap);
}




void NoticeProcessor(void *arg, const char *message)
{
	(void) arg;					
	psql_error("%s", message);
}




volatile bool sigint_interrupt_enabled = false;

sigjmp_buf	sigint_interrupt_jmp;

static PGcancel *volatile cancelConn = NULL;


static CRITICAL_SECTION cancelConnLock;













static void handle_sigint(SIGNAL_ARGS)
{
	int			save_errno = errno;
	char		errbuf[256];

	
	if (sigint_interrupt_enabled)
	{
		sigint_interrupt_enabled = false;
		siglongjmp(sigint_interrupt_jmp, 1);
	}

	
	cancel_pressed = true;

	
	if (cancelConn != NULL)
	{
		if (PQcancel(cancelConn, errbuf, sizeof(errbuf)))
			write_stderr("Cancel request sent\n");
		else {
			write_stderr("Could not send cancel request: ");
			write_stderr(errbuf);
		}
	}

	errno = save_errno;			
}

void setup_cancel_handler(void)
{
	pqsignal(SIGINT, handle_sigint);
}


static BOOL WINAPI consoleHandler(DWORD dwCtrlType)
{
	char		errbuf[256];

	if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_BREAK_EVENT)
	{
		

		
		cancel_pressed = true;

		
		EnterCriticalSection(&cancelConnLock);
		if (cancelConn != NULL)
		{
			if (PQcancel(cancelConn, errbuf, sizeof(errbuf)))
				write_stderr("Cancel request sent\n");
			else {
				write_stderr("Could not send cancel request: ");
				write_stderr(errbuf);
			}
		}
		LeaveCriticalSection(&cancelConnLock);

		return TRUE;
	}
	else  return FALSE;

}

void setup_cancel_handler(void)
{
	InitializeCriticalSection(&cancelConnLock);

	SetConsoleCtrlHandler(consoleHandler, TRUE);
}




static bool ConnectionUp(void)
{
	return PQstatus(pset.db) != CONNECTION_BAD;
}




static bool CheckConnection(void)
{
	bool		OK;

	OK = ConnectionUp();
	if (!OK)
	{
		if (!pset.cur_cmd_interactive)
		{
			psql_error("connection to server was lost\n");
			exit(EXIT_BADCONN);
		}

		psql_error("The connection to the server was lost. Attempting reset: ");
		PQreset(pset.db);
		OK = ConnectionUp();
		if (!OK)
		{
			psql_error("Failed.\n");
			PQfinish(pset.db);
			pset.db = NULL;
			ResetCancelConn();
			UnsyncVariables();
		}
		else psql_error("Succeeded.\n");
	}

	return OK;
}




void SetCancelConn(void)
{
	PGcancel   *oldCancelConn;


	EnterCriticalSection(&cancelConnLock);


	
	oldCancelConn = cancelConn;
	
	cancelConn = NULL;

	if (oldCancelConn != NULL)
		PQfreeCancel(oldCancelConn);

	cancelConn = PQgetCancel(pset.db);


	LeaveCriticalSection(&cancelConnLock);

}



void ResetCancelConn(void)
{
	PGcancel   *oldCancelConn;


	EnterCriticalSection(&cancelConnLock);


	oldCancelConn = cancelConn;
	
	cancelConn = NULL;

	if (oldCancelConn != NULL)
		PQfreeCancel(oldCancelConn);


	LeaveCriticalSection(&cancelConnLock);

}



static bool AcceptResult(const PGresult *result)
{
	bool		OK;

	if (!result)
		OK = false;
	else switch (PQresultStatus(result))
		{
			case PGRES_COMMAND_OK:
			case PGRES_TUPLES_OK:
			case PGRES_EMPTY_QUERY:
			case PGRES_COPY_IN:
			case PGRES_COPY_OUT:
				
				OK = true;
				break;

			case PGRES_BAD_RESPONSE:
			case PGRES_NONFATAL_ERROR:
			case PGRES_FATAL_ERROR:
				OK = false;
				break;

			default:
				OK = false;
				psql_error("unexpected PQresultStatus: %d\n", PQresultStatus(result));
				break;
		}

	if (!OK)
	{
		const char *error = PQerrorMessage(pset.db);

		if (strlen(error))
			psql_error("%s", error);

		CheckConnection();
	}

	return OK;
}



static void SetResultVariables(PGresult *results, bool success)
{
	if (success)
	{
		const char *ntuples = PQcmdTuples(results);

		SetVariable(pset.vars, "ERROR", "false");
		SetVariable(pset.vars, "SQLSTATE", "00000");
		SetVariable(pset.vars, "ROW_COUNT", *ntuples ? ntuples : "0");
	}
	else {
		const char *code = PQresultErrorField(results, PG_DIAG_SQLSTATE);
		const char *mesg = PQresultErrorField(results, PG_DIAG_MESSAGE_PRIMARY);

		SetVariable(pset.vars, "ERROR", "true");

		
		if (code == NULL)
			code = "";
		SetVariable(pset.vars, "SQLSTATE", code);
		SetVariable(pset.vars, "ROW_COUNT", "0");
		SetVariable(pset.vars, "LAST_ERROR_SQLSTATE", code);
		SetVariable(pset.vars, "LAST_ERROR_MESSAGE", mesg ? mesg : "");
	}
}



static void ClearOrSaveResult(PGresult *result)
{
	if (result)
	{
		switch (PQresultStatus(result))
		{
			case PGRES_NONFATAL_ERROR:
			case PGRES_FATAL_ERROR:
				if (pset.last_error_result)
					PQclear(pset.last_error_result);
				pset.last_error_result = result;
				break;

			default:
				PQclear(result);
				break;
		}
	}
}



static void PrintTiming(double elapsed_msec)
{
	double		seconds;
	double		minutes;
	double		hours;
	double		days;

	if (elapsed_msec < 1000.0)
	{
		
		printf(_("Time: %.3f ms\n"), elapsed_msec);
		return;
	}

	
	seconds = elapsed_msec / 1000.0;
	minutes = floor(seconds / 60.0);
	seconds -= 60.0 * minutes;
	if (minutes < 60.0)
	{
		printf(_("Time: %.3f ms (%02d:%06.3f)\n"), elapsed_msec, (int) minutes, seconds);
		return;
	}

	hours = floor(minutes / 60.0);
	minutes -= 60.0 * hours;
	if (hours < 24.0)
	{
		printf(_("Time: %.3f ms (%02d:%02d:%06.3f)\n"), elapsed_msec, (int) hours, (int) minutes, seconds);
		return;
	}

	days = floor(hours / 24.0);
	hours -= 24.0 * days;
	printf(_("Time: %.3f ms (%.0f d %02d:%02d:%06.3f)\n"), elapsed_msec, days, (int) hours, (int) minutes, seconds);
}



PGresult * PSQLexec(const char *query)
{
	PGresult   *res;

	if (!pset.db)
	{
		psql_error("You are currently not connected to a database.\n");
		return NULL;
	}

	if (pset.echo_hidden != PSQL_ECHO_HIDDEN_OFF)
	{
		printf(_("********* QUERY **********\n" "%s\n" "**************************\n\n"), query);

		fflush(stdout);
		if (pset.logfile)
		{
			fprintf(pset.logfile, _("********* QUERY **********\n" "%s\n" "**************************\n\n"), query);


			fflush(pset.logfile);
		}

		if (pset.echo_hidden == PSQL_ECHO_HIDDEN_NOEXEC)
			return NULL;
	}

	SetCancelConn();

	res = PQexec(pset.db, query);

	ResetCancelConn();

	if (!AcceptResult(res))
	{
		ClearOrSaveResult(res);
		res = NULL;
	}

	return res;
}



int PSQLexecWatch(const char *query, const printQueryOpt *opt)
{
	PGresult   *res;
	double		elapsed_msec = 0;
	instr_time	before;
	instr_time	after;

	if (!pset.db)
	{
		psql_error("You are currently not connected to a database.\n");
		return 0;
	}

	SetCancelConn();

	if (pset.timing)
		INSTR_TIME_SET_CURRENT(before);

	res = PQexec(pset.db, query);

	ResetCancelConn();

	if (!AcceptResult(res))
	{
		ClearOrSaveResult(res);
		return 0;
	}

	if (pset.timing)
	{
		INSTR_TIME_SET_CURRENT(after);
		INSTR_TIME_SUBTRACT(after, before);
		elapsed_msec = INSTR_TIME_GET_MILLISEC(after);
	}

	
	if (cancel_pressed)
	{
		PQclear(res);
		return 0;
	}

	switch (PQresultStatus(res))
	{
		case PGRES_TUPLES_OK:
			printQuery(res, opt, pset.queryFout, false, pset.logfile);
			break;

		case PGRES_COMMAND_OK:
			fprintf(pset.queryFout, "%s\n%s\n\n", opt->title, PQcmdStatus(res));
			break;

		case PGRES_EMPTY_QUERY:
			psql_error(_("\\watch cannot be used with an empty query\n"));
			PQclear(res);
			return -1;

		case PGRES_COPY_OUT:
		case PGRES_COPY_IN:
		case PGRES_COPY_BOTH:
			psql_error(_("\\watch cannot be used with COPY\n"));
			PQclear(res);
			return -1;

		default:
			psql_error(_("unexpected result status for \\watch\n"));
			PQclear(res);
			return -1;
	}

	PQclear(res);

	fflush(pset.queryFout);

	
	if (pset.timing)
		PrintTiming(elapsed_msec);

	return 1;
}



static void PrintNotifications(void)
{
	PGnotify   *notify;

	PQconsumeInput(pset.db);
	while ((notify = PQnotifies(pset.db)) != NULL)
	{
		
		if (notify->extra[0])
			fprintf(pset.queryFout, _("Asynchronous notification \"%s\" with payload \"%s\" received from server process with PID %d.\n"), notify->relname, notify->extra, notify->be_pid);
		else fprintf(pset.queryFout, _("Asynchronous notification \"%s\" received from server process with PID %d.\n"), notify->relname, notify->be_pid);

		fflush(pset.queryFout);
		PQfreemem(notify);
		PQconsumeInput(pset.db);
	}
}



static bool PrintQueryTuples(const PGresult *results)
{
	printQueryOpt my_popt = pset.popt;

	
	if (pset.g_expanded)
		my_popt.topt.expanded = 1;

	
	if (pset.gfname)
	{
		FILE	   *fout;
		bool		is_pipe;

		if (!openQueryOutputFile(pset.gfname, &fout, &is_pipe))
			return false;
		if (is_pipe)
			disable_sigpipe_trap();

		printQuery(results, &my_popt, fout, false, pset.logfile);

		if (is_pipe)
		{
			pclose(fout);
			restore_sigpipe_trap();
		}
		else fclose(fout);
	}
	else printQuery(results, &my_popt, pset.queryFout, false, pset.logfile);

	return true;
}



static bool StoreQueryTuple(const PGresult *result)
{
	bool		success = true;

	if (PQntuples(result) < 1)
	{
		psql_error("no rows returned for \\gset\n");
		success = false;
	}
	else if (PQntuples(result) > 1)
	{
		psql_error("more than one row returned for \\gset\n");
		success = false;
	}
	else {
		int			i;

		for (i = 0; i < PQnfields(result); i++)
		{
			char	   *colname = PQfname(result, i);
			char	   *varname;
			char	   *value;

			
			varname = psprintf("%s%s", pset.gset_prefix, colname);

			if (!PQgetisnull(result, 0, i))
				value = PQgetvalue(result, 0, i);
			else {
				
				value = NULL;
			}

			if (!SetVariable(pset.vars, varname, value))
			{
				free(varname);
				success = false;
				break;
			}

			free(varname);
		}
	}

	return success;
}



static bool ExecQueryTuples(const PGresult *result)
{
	bool		success = true;
	int			nrows = PQntuples(result);
	int			ncolumns = PQnfields(result);
	int			r, c;

	
	pset.gexec_flag = false;

	for (r = 0; r < nrows; r++)
	{
		for (c = 0; c < ncolumns; c++)
		{
			if (!PQgetisnull(result, r, c))
			{
				const char *query = PQgetvalue(result, r, c);

				
				if (cancel_pressed)
					goto loop_exit;

				
				if (pset.echo == PSQL_ECHO_ALL && !pset.singlestep)
				{
					puts(query);
					fflush(stdout);
				}

				if (!SendQuery(query))
				{
					
					success = false;
					if (pset.on_error_stop)
						goto loop_exit;
				}
			}
		}
	}

loop_exit:

	
	pset.gexec_flag = true;

	
	return success;
}



static bool ProcessResult(PGresult **results)
{
	bool		success = true;
	bool		first_cycle = true;

	for (;;)
	{
		ExecStatusType result_status;
		bool		is_copy;
		PGresult   *next_result;

		if (!AcceptResult(*results))
		{
			
			success = false;
			break;
		}

		result_status = PQresultStatus(*results);
		switch (result_status)
		{
			case PGRES_EMPTY_QUERY:
			case PGRES_COMMAND_OK:
			case PGRES_TUPLES_OK:
				is_copy = false;
				break;

			case PGRES_COPY_OUT:
			case PGRES_COPY_IN:
				is_copy = true;
				break;

			default:
				
				is_copy = false;
				psql_error("unexpected PQresultStatus: %d\n", result_status);
				break;
		}

		if (is_copy)
		{
			
			FILE	   *copystream;
			PGresult   *copy_result;

			SetCancelConn();
			if (result_status == PGRES_COPY_OUT)
			{
				bool		need_close = false;
				bool		is_pipe = false;

				if (pset.copyStream)
				{
					
					copystream = pset.copyStream;
				}
				else if (pset.gfname)
				{
					
					if (openQueryOutputFile(pset.gfname, &copystream, &is_pipe))
					{
						need_close = true;
						if (is_pipe)
							disable_sigpipe_trap();
					}
					else copystream = NULL;
				}
				else {
					
					copystream = pset.queryFout;
				}

				success = handleCopyOut(pset.db, copystream, &copy_result)

					&& success && (copystream != NULL);

				
				if (copystream == pset.queryFout)
				{
					PQclear(copy_result);
					copy_result = NULL;
				}

				if (need_close)
				{
					
					if (is_pipe)
					{
						pclose(copystream);
						restore_sigpipe_trap();
					}
					else {
						fclose(copystream);
					}
				}
			}
			else {
				
				copystream = pset.copyStream ? pset.copyStream : pset.cur_cmd_source;
				success = handleCopyIn(pset.db, copystream, PQbinaryTuples(*results), &copy_result) && success;


			}
			ResetCancelConn();

			
			PQclear(*results);
			*results = copy_result;
		}
		else if (first_cycle)
		{
			
			break;
		}

		
		next_result = PQgetResult(pset.db);
		if (!next_result)
			break;

		PQclear(*results);
		*results = next_result;
		first_cycle = false;
	}

	SetResultVariables(*results, success);

	
	if (!first_cycle && !CheckConnection())
		return false;

	return success;
}



static void PrintQueryStatus(PGresult *results)
{
	char		buf[16];

	if (!pset.quiet)
	{
		if (pset.popt.topt.format == PRINT_HTML)
		{
			fputs("<p>", pset.queryFout);
			html_escaped_print(PQcmdStatus(results), pset.queryFout);
			fputs("</p>\n", pset.queryFout);
		}
		else fprintf(pset.queryFout, "%s\n", PQcmdStatus(results));
	}

	if (pset.logfile)
		fprintf(pset.logfile, "%s\n", PQcmdStatus(results));

	snprintf(buf, sizeof(buf), "%u", (unsigned int) PQoidValue(results));
	SetVariable(pset.vars, "LASTOID", buf);
}



static bool PrintQueryResults(PGresult *results)
{
	bool		success;
	const char *cmdstatus;

	if (!results)
		return false;

	switch (PQresultStatus(results))
	{
		case PGRES_TUPLES_OK:
			
			if (pset.gset_prefix)
				success = StoreQueryTuple(results);
			else if (pset.gexec_flag)
				success = ExecQueryTuples(results);
			else if (pset.crosstab_flag)
				success = PrintResultsInCrosstab(results);
			else success = PrintQueryTuples(results);
			
			cmdstatus = PQcmdStatus(results);
			if (strncmp(cmdstatus, "INSERT", 6) == 0 || strncmp(cmdstatus, "UPDATE", 6) == 0 || strncmp(cmdstatus, "DELETE", 6) == 0)

				PrintQueryStatus(results);
			break;

		case PGRES_COMMAND_OK:
			PrintQueryStatus(results);
			success = true;
			break;

		case PGRES_EMPTY_QUERY:
			success = true;
			break;

		case PGRES_COPY_OUT:
		case PGRES_COPY_IN:
			
			success = true;
			break;

		case PGRES_BAD_RESPONSE:
		case PGRES_NONFATAL_ERROR:
		case PGRES_FATAL_ERROR:
			success = false;
			break;

		default:
			success = false;
			psql_error("unexpected PQresultStatus: %d\n", PQresultStatus(results));
			break;
	}

	fflush(pset.queryFout);

	return success;
}



bool SendQuery(const char *query)
{
	PGresult   *results;
	PGTransactionStatusType transaction_status;
	double		elapsed_msec = 0;
	bool		OK = false;
	int			i;
	bool		on_error_rollback_savepoint = false;
	static bool on_error_rollback_warning = false;

	if (!pset.db)
	{
		psql_error("You are currently not connected to a database.\n");
		goto sendquery_cleanup;
	}

	if (pset.singlestep)
	{
		char		buf[3];

		fflush(stderr);
		printf(_("***(Single step mode: verify command)*******************************************\n" "%s\n" "***(press return to proceed or enter x and return to cancel)********************\n"), query);


		fflush(stdout);
		if (fgets(buf, sizeof(buf), stdin) != NULL)
			if (buf[0] == 'x')
				goto sendquery_cleanup;
		if (cancel_pressed)
			goto sendquery_cleanup;
	}
	else if (pset.echo == PSQL_ECHO_QUERIES)
	{
		puts(query);
		fflush(stdout);
	}

	if (pset.logfile)
	{
		fprintf(pset.logfile, _("********* QUERY **********\n" "%s\n" "**************************\n\n"), query);


		fflush(pset.logfile);
	}

	SetCancelConn();

	transaction_status = PQtransactionStatus(pset.db);

	if (transaction_status == PQTRANS_IDLE && !pset.autocommit && !command_no_begin(query))

	{
		results = PQexec(pset.db, "BEGIN");
		if (PQresultStatus(results) != PGRES_COMMAND_OK)
		{
			psql_error("%s", PQerrorMessage(pset.db));
			ClearOrSaveResult(results);
			ResetCancelConn();
			goto sendquery_cleanup;
		}
		ClearOrSaveResult(results);
		transaction_status = PQtransactionStatus(pset.db);
	}

	if (transaction_status == PQTRANS_INTRANS && pset.on_error_rollback != PSQL_ERROR_ROLLBACK_OFF && (pset.cur_cmd_interactive || pset.on_error_rollback == PSQL_ERROR_ROLLBACK_ON))


	{
		if (on_error_rollback_warning == false && pset.sversion < 80000)
		{
			char		sverbuf[32];

			psql_error("The server (version %s) does not support savepoints for ON_ERROR_ROLLBACK.\n", formatPGVersionNumber(pset.sversion, false, sverbuf, sizeof(sverbuf)));

			on_error_rollback_warning = true;
		}
		else {
			results = PQexec(pset.db, "SAVEPOINT pg_psql_temporary_savepoint");
			if (PQresultStatus(results) != PGRES_COMMAND_OK)
			{
				psql_error("%s", PQerrorMessage(pset.db));
				ClearOrSaveResult(results);
				ResetCancelConn();
				goto sendquery_cleanup;
			}
			ClearOrSaveResult(results);
			on_error_rollback_savepoint = true;
		}
	}

	if (pset.gdesc_flag)
	{
		
		OK = DescribeQuery(query, &elapsed_msec);
		ResetCancelConn();
		results = NULL;			
	}
	else if (pset.fetch_count <= 0 || pset.gexec_flag || pset.crosstab_flag || !is_select_command(query))
	{
		
		instr_time	before, after;

		if (pset.timing)
			INSTR_TIME_SET_CURRENT(before);

		results = PQexec(pset.db, query);

		
		ResetCancelConn();
		OK = ProcessResult(&results);

		if (pset.timing)
		{
			INSTR_TIME_SET_CURRENT(after);
			INSTR_TIME_SUBTRACT(after, before);
			elapsed_msec = INSTR_TIME_GET_MILLISEC(after);
		}

		
		if (OK && results)
			OK = PrintQueryResults(results);
	}
	else {
		
		OK = ExecQueryUsingCursor(query, &elapsed_msec);
		ResetCancelConn();
		results = NULL;			
	}

	if (!OK && pset.echo == PSQL_ECHO_ERRORS)
		psql_error("STATEMENT:  %s\n", query);

	
	if (on_error_rollback_savepoint)
	{
		const char *svptcmd = NULL;

		transaction_status = PQtransactionStatus(pset.db);

		switch (transaction_status)
		{
			case PQTRANS_INERROR:
				
				svptcmd = "ROLLBACK TO pg_psql_temporary_savepoint";
				break;

			case PQTRANS_IDLE:
				
				break;

			case PQTRANS_INTRANS:

				
				if (results && (strcmp(PQcmdStatus(results), "SAVEPOINT") == 0 || strcmp(PQcmdStatus(results), "RELEASE") == 0 || strcmp(PQcmdStatus(results), "ROLLBACK") == 0))


					svptcmd = NULL;
				else svptcmd = "RELEASE pg_psql_temporary_savepoint";
				break;

			case PQTRANS_ACTIVE:
			case PQTRANS_UNKNOWN:
			default:
				OK = false;
				
				if (transaction_status != PQTRANS_UNKNOWN || ConnectionUp())
					psql_error("unexpected transaction status (%d)\n", transaction_status);
				break;
		}

		if (svptcmd)
		{
			PGresult   *svptres;

			svptres = PQexec(pset.db, svptcmd);
			if (PQresultStatus(svptres) != PGRES_COMMAND_OK)
			{
				psql_error("%s", PQerrorMessage(pset.db));
				ClearOrSaveResult(svptres);
				OK = false;

				PQclear(results);
				ResetCancelConn();
				goto sendquery_cleanup;
			}
			PQclear(svptres);
		}
	}

	ClearOrSaveResult(results);

	
	if (pset.timing)
		PrintTiming(elapsed_msec);

	

	if (pset.encoding != PQclientEncoding(pset.db) && PQclientEncoding(pset.db) >= 0)
	{
		
		pset.encoding = PQclientEncoding(pset.db);
		pset.popt.topt.encoding = pset.encoding;
		SetVariable(pset.vars, "ENCODING", pg_encoding_to_char(pset.encoding));
	}

	PrintNotifications();

	

sendquery_cleanup:

	
	if (pset.gfname)
	{
		free(pset.gfname);
		pset.gfname = NULL;
	}

	
	pset.g_expanded = false;

	
	if (pset.gset_prefix)
	{
		free(pset.gset_prefix);
		pset.gset_prefix = NULL;
	}

	
	pset.gdesc_flag = false;

	
	pset.gexec_flag = false;

	
	pset.crosstab_flag = false;
	for (i = 0; i < lengthof(pset.ctv_args); i++)
	{
		pg_free(pset.ctv_args[i]);
		pset.ctv_args[i] = NULL;
	}

	return OK;
}



static bool DescribeQuery(const char *query, double *elapsed_msec)
{
	PGresult   *results;
	bool		OK;
	instr_time	before, after;

	*elapsed_msec = 0;

	if (pset.timing)
		INSTR_TIME_SET_CURRENT(before);

	
	results = PQprepare(pset.db, "", query, 0, NULL);
	if (PQresultStatus(results) != PGRES_COMMAND_OK)
	{
		psql_error("%s", PQerrorMessage(pset.db));
		SetResultVariables(results, false);
		ClearOrSaveResult(results);
		return false;
	}
	PQclear(results);

	results = PQdescribePrepared(pset.db, "");
	OK = AcceptResult(results) && (PQresultStatus(results) == PGRES_COMMAND_OK);
	if (OK && results)
	{
		if (PQnfields(results) > 0)
		{
			PQExpBufferData buf;
			int			i;

			initPQExpBuffer(&buf);

			printfPQExpBuffer(&buf, "SELECT name AS \"%s\", pg_catalog.format_type(tp, tpm) AS \"%s\"\n" "FROM (VALUES ", gettext_noop("Column"), gettext_noop("Type"));




			for (i = 0; i < PQnfields(results); i++)
			{
				const char *name;
				char	   *escname;

				if (i > 0)
					appendPQExpBufferStr(&buf, ",");

				name = PQfname(results, i);
				escname = PQescapeLiteral(pset.db, name, strlen(name));

				if (escname == NULL)
				{
					psql_error("%s", PQerrorMessage(pset.db));
					PQclear(results);
					termPQExpBuffer(&buf);
					return false;
				}

				appendPQExpBuffer(&buf, "(%s, '%u'::pg_catalog.oid, %d)", escname, PQftype(results, i), PQfmod(results, i));



				PQfreemem(escname);
			}

			appendPQExpBufferStr(&buf, ") s(name, tp, tpm)");
			PQclear(results);

			results = PQexec(pset.db, buf.data);
			OK = AcceptResult(results);

			if (pset.timing)
			{
				INSTR_TIME_SET_CURRENT(after);
				INSTR_TIME_SUBTRACT(after, before);
				*elapsed_msec += INSTR_TIME_GET_MILLISEC(after);
			}

			if (OK && results)
				OK = PrintQueryResults(results);

			termPQExpBuffer(&buf);
		}
		else fprintf(pset.queryFout, _("The command has no result, or the result has no columns.\n"));

	}

	SetResultVariables(results, OK);
	ClearOrSaveResult(results);

	return OK;
}



static bool ExecQueryUsingCursor(const char *query, double *elapsed_msec)
{
	bool		OK = true;
	PGresult   *results;
	PQExpBufferData buf;
	printQueryOpt my_popt = pset.popt;
	FILE	   *fout;
	bool		is_pipe;
	bool		is_pager = false;
	bool		started_txn = false;
	int64		total_tuples = 0;
	int			ntuples;
	int			fetch_count;
	char		fetch_cmd[64];
	instr_time	before, after;
	int			flush_error;

	*elapsed_msec = 0;

	
	my_popt.topt.start_table = true;
	my_popt.topt.stop_table = false;
	my_popt.topt.prior_records = 0;

	if (pset.timing)
		INSTR_TIME_SET_CURRENT(before);

	
	if (PQtransactionStatus(pset.db) == PQTRANS_IDLE)
	{
		results = PQexec(pset.db, "BEGIN");
		OK = AcceptResult(results) && (PQresultStatus(results) == PGRES_COMMAND_OK);
		ClearOrSaveResult(results);
		if (!OK)
			return false;
		started_txn = true;
	}

	
	initPQExpBuffer(&buf);
	appendPQExpBuffer(&buf, "DECLARE _psql_cursor NO SCROLL CURSOR FOR\n%s", query);

	results = PQexec(pset.db, buf.data);
	OK = AcceptResult(results) && (PQresultStatus(results) == PGRES_COMMAND_OK);
	if (!OK)
		SetResultVariables(results, OK);
	ClearOrSaveResult(results);
	termPQExpBuffer(&buf);
	if (!OK)
		goto cleanup;

	if (pset.timing)
	{
		INSTR_TIME_SET_CURRENT(after);
		INSTR_TIME_SUBTRACT(after, before);
		*elapsed_msec += INSTR_TIME_GET_MILLISEC(after);
	}

	
	if (pset.gset_prefix)
		fetch_count = 2;
	else fetch_count = pset.fetch_count;

	snprintf(fetch_cmd, sizeof(fetch_cmd), "FETCH FORWARD %d FROM _psql_cursor", fetch_count);


	
	if (pset.g_expanded)
		my_popt.topt.expanded = 1;

	
	if (pset.gfname)
	{
		if (!openQueryOutputFile(pset.gfname, &fout, &is_pipe))
		{
			OK = false;
			goto cleanup;
		}
		if (is_pipe)
			disable_sigpipe_trap();
	}
	else {
		fout = pset.queryFout;
		is_pipe = false;		
	}

	
	clearerr(fout);

	for (;;)
	{
		if (pset.timing)
			INSTR_TIME_SET_CURRENT(before);

		
		results = PQexec(pset.db, fetch_cmd);

		if (pset.timing)
		{
			INSTR_TIME_SET_CURRENT(after);
			INSTR_TIME_SUBTRACT(after, before);
			*elapsed_msec += INSTR_TIME_GET_MILLISEC(after);
		}

		if (PQresultStatus(results) != PGRES_TUPLES_OK)
		{
			
			if (is_pager)
			{
				ClosePager(fout);
				is_pager = false;
			}

			OK = AcceptResult(results);
			Assert(!OK);
			SetResultVariables(results, OK);
			ClearOrSaveResult(results);
			break;
		}

		if (pset.gset_prefix)
		{
			
			OK = StoreQueryTuple(results);
			ClearOrSaveResult(results);
			break;
		}

		

		ntuples = PQntuples(results);
		total_tuples += ntuples;

		if (ntuples < fetch_count)
		{
			
			my_popt.topt.stop_table = true;
		}
		else if (fout == stdout && !is_pager)
		{
			
			fout = PageOutput(INT_MAX, &(my_popt.topt));
			is_pager = true;
		}

		printQuery(results, &my_popt, fout, is_pager, pset.logfile);

		ClearOrSaveResult(results);

		
		my_popt.topt.start_table = false;
		my_popt.topt.prior_records += ntuples;

		
		flush_error = fflush(fout);

		
		if (ntuples < fetch_count || cancel_pressed || flush_error || ferror(fout))
			break;
	}

	if (pset.gfname)
	{
		
		if (is_pipe)
		{
			pclose(fout);
			restore_sigpipe_trap();
		}
		else fclose(fout);
	}
	else if (is_pager)
	{
		
		ClosePager(fout);
	}

	if (OK)
	{
		
		char		buf[32];

		SetVariable(pset.vars, "ERROR", "false");
		SetVariable(pset.vars, "SQLSTATE", "00000");
		snprintf(buf, sizeof(buf), INT64_FORMAT, total_tuples);
		SetVariable(pset.vars, "ROW_COUNT", buf);
	}

cleanup:
	if (pset.timing)
		INSTR_TIME_SET_CURRENT(before);

	
	results = PQexec(pset.db, "CLOSE _psql_cursor");
	if (OK)
	{
		OK = AcceptResult(results) && (PQresultStatus(results) == PGRES_COMMAND_OK);
		ClearOrSaveResult(results);
	}
	else PQclear(results);

	if (started_txn)
	{
		results = PQexec(pset.db, OK ? "COMMIT" : "ROLLBACK");
		OK &= AcceptResult(results) && (PQresultStatus(results) == PGRES_COMMAND_OK);
		ClearOrSaveResult(results);
	}

	if (pset.timing)
	{
		INSTR_TIME_SET_CURRENT(after);
		INSTR_TIME_SUBTRACT(after, before);
		*elapsed_msec += INSTR_TIME_GET_MILLISEC(after);
	}

	return OK;
}



static const char * skip_white_space(const char *query)
{
	int			cnestlevel = 0; 

	while (*query)
	{
		int			mblen = PQmblenBounded(query, pset.encoding);

		
		if (isspace((unsigned char) *query))
			query += mblen;
		else if (query[0] == '/' && query[1] == '*')
		{
			cnestlevel++;
			query += 2;
		}
		else if (cnestlevel > 0 && query[0] == '*' && query[1] == '/')
		{
			cnestlevel--;
			query += 2;
		}
		else if (cnestlevel == 0 && query[0] == '-' && query[1] == '-')
		{
			query += 2;

			
			while (*query)
			{
				if (*query == '\n')
				{
					query++;
					break;
				}
				query += PQmblenBounded(query, pset.encoding);
			}
		}
		else if (cnestlevel > 0)
			query += mblen;
		else break;
	}

	return query;
}



static bool command_no_begin(const char *query)
{
	int			wordlen;

	
	query = skip_white_space(query);

	
	wordlen = 0;
	while (isalpha((unsigned char) query[wordlen]))
		wordlen += PQmblenBounded(&query[wordlen], pset.encoding);

	
	if (wordlen == 5 && pg_strncasecmp(query, "abort", 5) == 0)
		return true;
	if (wordlen == 5 && pg_strncasecmp(query, "begin", 5) == 0)
		return true;
	if (wordlen == 5 && pg_strncasecmp(query, "start", 5) == 0)
		return true;
	if (wordlen == 6 && pg_strncasecmp(query, "commit", 6) == 0)
		return true;
	if (wordlen == 3 && pg_strncasecmp(query, "end", 3) == 0)
		return true;
	if (wordlen == 8 && pg_strncasecmp(query, "rollback", 8) == 0)
		return true;
	if (wordlen == 7 && pg_strncasecmp(query, "prepare", 7) == 0)
	{
		
		query += wordlen;

		query = skip_white_space(query);

		wordlen = 0;
		while (isalpha((unsigned char) query[wordlen]))
			wordlen += PQmblenBounded(&query[wordlen], pset.encoding);

		if (wordlen == 11 && pg_strncasecmp(query, "transaction", 11) == 0)
			return true;
		return false;
	}

	
	if (wordlen == 6 && pg_strncasecmp(query, "vacuum", 6) == 0)
		return true;
	if (wordlen == 7 && pg_strncasecmp(query, "cluster", 7) == 0)
	{
		
		query += wordlen;

		query = skip_white_space(query);

		if (isalpha((unsigned char) query[0]))
			return false;		
		return true;			
	}

	if (wordlen == 6 && pg_strncasecmp(query, "create", 6) == 0)
	{
		query += wordlen;

		query = skip_white_space(query);

		wordlen = 0;
		while (isalpha((unsigned char) query[wordlen]))
			wordlen += PQmblenBounded(&query[wordlen], pset.encoding);

		if (wordlen == 8 && pg_strncasecmp(query, "database", 8) == 0)
			return true;
		if (wordlen == 10 && pg_strncasecmp(query, "tablespace", 10) == 0)
			return true;

		
		if (wordlen == 6 && pg_strncasecmp(query, "unique", 6) == 0)
		{
			query += wordlen;

			query = skip_white_space(query);

			wordlen = 0;
			while (isalpha((unsigned char) query[wordlen]))
				wordlen += PQmblenBounded(&query[wordlen], pset.encoding);
		}

		if (wordlen == 5 && pg_strncasecmp(query, "index", 5) == 0)
		{
			query += wordlen;

			query = skip_white_space(query);

			wordlen = 0;
			while (isalpha((unsigned char) query[wordlen]))
				wordlen += PQmblenBounded(&query[wordlen], pset.encoding);

			if (wordlen == 12 && pg_strncasecmp(query, "concurrently", 12) == 0)
				return true;
		}

		return false;
	}

	if (wordlen == 5 && pg_strncasecmp(query, "alter", 5) == 0)
	{
		query += wordlen;

		query = skip_white_space(query);

		wordlen = 0;
		while (isalpha((unsigned char) query[wordlen]))
			wordlen += PQmblenBounded(&query[wordlen], pset.encoding);

		
		if (wordlen == 6 && pg_strncasecmp(query, "system", 6) == 0)
			return true;

		return false;
	}

	
	if ((wordlen == 4 && pg_strncasecmp(query, "drop", 4) == 0) || (wordlen == 7 && pg_strncasecmp(query, "reindex", 7) == 0))
	{
		query += wordlen;

		query = skip_white_space(query);

		wordlen = 0;
		while (isalpha((unsigned char) query[wordlen]))
			wordlen += PQmblenBounded(&query[wordlen], pset.encoding);

		if (wordlen == 8 && pg_strncasecmp(query, "database", 8) == 0)
			return true;
		if (wordlen == 6 && pg_strncasecmp(query, "system", 6) == 0)
			return true;
		if (wordlen == 10 && pg_strncasecmp(query, "tablespace", 10) == 0)
			return true;

		
		if (wordlen == 5 && pg_strncasecmp(query, "index", 5) == 0)
		{
			query += wordlen;

			query = skip_white_space(query);

			wordlen = 0;
			while (isalpha((unsigned char) query[wordlen]))
				wordlen += PQmblenBounded(&query[wordlen], pset.encoding);

			if (wordlen == 12 && pg_strncasecmp(query, "concurrently", 12) == 0)
				return true;

			return false;
		}

		return false;
	}

	
	if (wordlen == 7 && pg_strncasecmp(query, "discard", 7) == 0)
	{
		query += wordlen;

		query = skip_white_space(query);

		wordlen = 0;
		while (isalpha((unsigned char) query[wordlen]))
			wordlen += PQmblenBounded(&query[wordlen], pset.encoding);

		if (wordlen == 3 && pg_strncasecmp(query, "all", 3) == 0)
			return true;
		return false;
	}

	return false;
}



static bool is_select_command(const char *query)
{
	int			wordlen;

	
	for (;;)
	{
		query = skip_white_space(query);
		if (query[0] == '(')
			query++;
		else break;
	}

	
	wordlen = 0;
	while (isalpha((unsigned char) query[wordlen]))
		wordlen += PQmblenBounded(&query[wordlen], pset.encoding);

	if (wordlen == 6 && pg_strncasecmp(query, "select", 6) == 0)
		return true;

	if (wordlen == 6 && pg_strncasecmp(query, "values", 6) == 0)
		return true;

	return false;
}



bool is_superuser(void)
{
	const char *val;

	if (!pset.db)
		return false;

	val = PQparameterStatus(pset.db, "is_superuser");

	if (val && strcmp(val, "on") == 0)
		return true;

	return false;
}



bool standard_strings(void)
{
	const char *val;

	if (!pset.db)
		return false;

	val = PQparameterStatus(pset.db, "standard_conforming_strings");

	if (val && strcmp(val, "on") == 0)
		return true;

	return false;
}



const char * session_username(void)
{
	const char *val;

	if (!pset.db)
		return NULL;

	val = PQparameterStatus(pset.db, "session_authorization");
	if (val)
		return val;
	else return PQuser(pset.db);
}



void expand_tilde(char **filename)
{
	if (!filename || !(*filename))
		return;

	


	
	if (**filename == '~')
	{
		char	   *fn;
		char		oldp, *p;
		struct passwd *pw;
		char		home[MAXPGPATH];

		fn = *filename;
		*home = '\0';

		p = fn + 1;
		while (*p != '/' && *p != '\0')
			p++;

		oldp = *p;
		*p = '\0';

		if (*(fn + 1) == '\0')
			get_home_path(home);	
		else if ((pw = getpwnam(fn + 1)) != NULL)
			strlcpy(home, pw->pw_dir, sizeof(home));	

		*p = oldp;
		if (strlen(home) != 0)
		{
			char	   *newfn;

			newfn = psprintf("%s%s", home, p);
			free(fn);
			*filename = newfn;
		}
	}


	return;
}


static int uri_prefix_length(const char *connstr)
{
	
	static const char uri_designator[] = "postgresql://";
	static const char short_uri_designator[] = "postgres://";

	if (strncmp(connstr, uri_designator, sizeof(uri_designator) - 1) == 0)
		return sizeof(uri_designator) - 1;

	if (strncmp(connstr, short_uri_designator, sizeof(short_uri_designator) - 1) == 0)
		return sizeof(short_uri_designator) - 1;

	return 0;
}


bool recognized_connection_string(const char *connstr)
{
	return uri_prefix_length(connstr) != 0 || strchr(connstr, '=') != NULL;
}
