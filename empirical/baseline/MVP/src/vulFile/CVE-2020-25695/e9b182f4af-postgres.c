


























































































const char *debug_query_string; 


CommandDest whereToSendOutput = DestDebug;


bool		Log_disconnections = false;

int			log_statement = LOGSTMT_NONE;


int			max_stack_depth = 100;


int			PostAuthDelay = 0;



cancel_pending_hook_type cancel_pending_hook = NULL;




static int PostmasterPriority = 0;


static long max_stack_depth_bytes = 100 * 1024L;


char	   *stack_base_ptr = NULL;



char	   *register_stack_base_ptr = NULL;



static bool xact_started = false;


extern bool DoingCommandRead;
bool DoingCommandRead = false;


static bool doing_extended_query_message = false;
static bool ignore_till_sync = false;


static bool stmt_timeout_active = false;


static CachedPlanSource *unnamed_stmt_psrc = NULL;


static const char *userDoption = NULL;	
static bool EchoQuery = false;	
static bool UseSemiNewlineNewline = false;	


pthread_t main_tid = (pthread_t)0;

pthread_t main_tid = {0,0};



static volatile sig_atomic_t in_quickdie = false;


static bool RecoveryConflictPending = false;
static bool RecoveryConflictRetryable = true;
static ProcSignalReason RecoveryConflictReason;


static MemoryContext row_description_context = NULL;
static StringInfoData row_description_buf;

static DtxContextInfo TempDtxContextInfo = DtxContextInfo_StaticInit;


static int	InteractiveBackend(StringInfo inBuf);
static int	interactive_getc(void);
static int	SocketBackend(StringInfo inBuf);
static int	ReadCommand(StringInfo inBuf);
static void forbidden_in_wal_sender(char firstchar);
static List *pg_rewrite_query(Query *query);
static bool check_log_statement(List *stmt_list);
static int	errdetail_execute(List *raw_parsetree_list);
static int	errdetail_params(ParamListInfo params);
static int	errdetail_abort(void);
static int	errdetail_recovery_conflict(void);
static void start_xact_command(void);
static void finish_xact_command(void);
static bool IsTransactionExitStmt(Node *parsetree);
static bool IsTransactionExitStmtList(List *pstmts);
static bool IsTransactionStmtList(List *pstmts);
static void drop_unnamed_stmt(void);
static void log_disconnections(int code, Datum arg);
static void enable_statement_timeout(void);
static void disable_statement_timeout(void);
static bool CheckDebugDtmActionSqlCommandTag(const char *sqlCommandTag);
static bool CheckDebugDtmActionProtocol(DtxProtocolCommand dtxProtocolCommand, DtxContextInfo *contextInfo);
static bool renice_current_process(int nice_level);


static bool renice_current_process(int nice_level)
{

	elog(DEBUG2, "Renicing of processes on Windows currently not supported.");
	return false;

	int prio_out = -1;
	elog(DEBUG2, "Current nice level of the process: %d", getpriority(PRIO_PROCESS, 0));
	prio_out = setpriority(PRIO_PROCESS, 0, nice_level);
	if (prio_out == -1)
	{
		int save_errno = errno;
		switch (save_errno)
		{
		case EACCES:
			elog(DEBUG1, "Could not change priority of the query process, errno: %d (%m).", save_errno);
			break;
		case ESRCH:
			
			break;
		default:
			elog(DEBUG1, "Could not change priority of the query process, errno: %d (%m).", save_errno);
		}
		return false;
	}

	elog(DEBUG2, "Reniced process to level %d", getpriority(PRIO_PROCESS, 0));
	return true;

}





static int InteractiveBackend(StringInfo inBuf)
{
	int			c;				

	
	printf("backend> ");
	fflush(stdout);

	resetStringInfo(inBuf);

	
	while ((c = interactive_getc()) != EOF)
	{
		if (c == '\n')
		{
			if (UseSemiNewlineNewline)
			{
				
				if (inBuf->len > 1 && inBuf->data[inBuf->len - 1] == '\n' && inBuf->data[inBuf->len - 2] == ';')

				{
					
					break;
				}
			}
			else {
				
				if (inBuf->len > 0 && inBuf->data[inBuf->len - 1] == '\\')
				{
					
					inBuf->data[--inBuf->len] = '\0';
					
					continue;
				}
				else {
					
					appendStringInfoChar(inBuf, '\n');
					break;
				}
			}
		}

		
		appendStringInfoChar(inBuf, (char) c);
	}

	
	if (c == EOF && inBuf->len == 0)
		return EOF;

	

	
	appendStringInfoChar(inBuf, (char) '\0');

	
	if (EchoQuery)
		printf("statement: %s\n", inBuf->data);
	fflush(stdout);

	return 'Q';
}


static int interactive_getc(void)
{
	int			c;

	
	CHECK_FOR_INTERRUPTS();

	enable_client_wait_timeout_interrupt();

	c = getc(stdin);

	disable_client_wait_timeout_interrupt();

	ProcessClientReadInterrupt(false);

	return c;
}


static int SocketBackend(StringInfo inBuf)
{
	int			qtype;

	
	HOLD_CANCEL_INTERRUPTS();
	pq_startmsgread();
	qtype = pq_getbyte();

	if (qtype == EOF)			
	{
		if (IsTransactionState())
			ereport(COMMERROR, (errcode(ERRCODE_CONNECTION_FAILURE), errmsg("unexpected EOF on client connection with an open transaction")));

		else {
			
			whereToSendOutput = DestNone;
			ereport(DEBUG1, (errcode(ERRCODE_CONNECTION_DOES_NOT_EXIST), errmsg("unexpected EOF on client connection")));

		}
		return qtype;
	}

	
	switch (qtype)
	{
		case 'Q':				
			doing_extended_query_message = false;
			if (PG_PROTOCOL_MAJOR(FrontendProtocol) < 3)
			{
				
				if (pq_getstring(inBuf))
				{
					if (IsTransactionState())
						ereport(COMMERROR, (errcode(ERRCODE_CONNECTION_FAILURE), errmsg("unexpected EOF on client connection with an open transaction")));

					else {
						
						whereToSendOutput = DestNone;
						ereport(DEBUG1, (errcode(ERRCODE_CONNECTION_DOES_NOT_EXIST), errmsg("unexpected EOF on client connection")));

					}
					return EOF;
				}
			}
			break;

		case 'M':				

			doing_extended_query_message = false;

			
			if( PG_PROTOCOL_MAJOR(FrontendProtocol) < 3 )
					ereport(COMMERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("dispatch unsupported for old FrontendProtocols")));



			break;

		case 'T':				

			doing_extended_query_message = false;

			
			if( PG_PROTOCOL_MAJOR(FrontendProtocol) < 3 )
					ereport(COMMERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("dispatch unsupported for old FrontendProtocols")));



			break;

		case 'F':				
			doing_extended_query_message = false;
			if (PG_PROTOCOL_MAJOR(FrontendProtocol) < 3)
			{
				if (GetOldFunctionMessage(inBuf))
				{
					if (IsTransactionState())
						ereport(COMMERROR, (errcode(ERRCODE_CONNECTION_FAILURE), errmsg("unexpected EOF on client connection with an open transaction")));

					else {
						
						whereToSendOutput = DestNone;
						ereport(DEBUG1, (errcode(ERRCODE_CONNECTION_DOES_NOT_EXIST), errmsg("unexpected EOF on client connection")));

					}
					return EOF;
				}
			}
			break;

		case 'X':				
			doing_extended_query_message = false;
			ignore_till_sync = false;
			break;

		case 'B':				
		case 'C':				
		case 'D':				
		case 'E':				
		case 'H':				
		case 'P':				
			doing_extended_query_message = true;
			
			if (PG_PROTOCOL_MAJOR(FrontendProtocol) < 3)
				ereport(FATAL, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("invalid frontend message type %d", qtype)));

			break;

		case 'S':				
			
			ignore_till_sync = false;
			
			doing_extended_query_message = false;
			
			if (PG_PROTOCOL_MAJOR(FrontendProtocol) < 3)
				ereport(FATAL, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("invalid frontend message type %d", qtype)));

			break;

		case 'd':				
		case 'c':				
		case 'f':				
			doing_extended_query_message = false;
			
			if (PG_PROTOCOL_MAJOR(FrontendProtocol) < 3)
				ereport(FATAL, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("invalid frontend message type %d", qtype)));

			break;

		default:

			
			ereport(FATAL, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("invalid frontend message type %d", qtype)));

			break;
	}

	
	if (PG_PROTOCOL_MAJOR(FrontendProtocol) >= 3)
	{
		if (pq_getmessage(inBuf, 0))
			return EOF;			
	}
	else pq_endmsgread();
	RESUME_CANCEL_INTERRUPTS();

	return qtype;
}


static int ReadCommand(StringInfo inBuf)
{
	int			result;

	
	SIMPLE_FAULT_INJECTOR("before_read_command");

	if (whereToSendOutput == DestRemote)
		result = SocketBackend(inBuf);
	else result = InteractiveBackend(inBuf);
	return result;
}


void ProcessClientReadInterrupt(bool blocked)
{
	int			save_errno = errno;

	if (DoingCommandRead)
	{
		
		CHECK_FOR_INTERRUPTS();

		
		if (catchupInterruptPending)
			ProcessCatchupInterrupt();

		
		if (notifyInterruptPending)
			ProcessNotifyInterrupt();
	}
	else if (ProcDiePending)
	{
		
		if (blocked)
			CHECK_FOR_INTERRUPTS();
		else SetLatch(MyLatch);
	}

	errno = save_errno;
}


void ProcessClientWriteInterrupt(bool blocked)
{
	int			save_errno = errno;

	if (ProcDiePending)
	{
		
		if (blocked)
		{
			
			if (InterruptHoldoffCount == 0 && CritSectionCount == 0)
			{
				
				if (whereToSendOutput == DestRemote)
					whereToSendOutput = DestNone;

				CHECK_FOR_INTERRUPTS();
			}
		}
		else SetLatch(MyLatch);
	}

	errno = save_errno;
}


List * pg_parse_query(const char *query_string)
{
	List	   *raw_parsetree_list;

	TRACE_POSTGRESQL_QUERY_PARSE_START(query_string);

	if (log_parser_stats)
		ResetUsage();

	raw_parsetree_list = raw_parser(query_string);

	if (log_parser_stats)
		ShowUsage("PARSER STATISTICS");


	
	{
		List	   *new_list = copyObject(raw_parsetree_list);

		
		if (!equal(new_list, raw_parsetree_list))
			elog(WARNING, "copyObject() failed to produce an equal raw parse tree");
		else raw_parsetree_list = new_list;
	}


	

	TRACE_POSTGRESQL_QUERY_PARSE_DONE(query_string);

	return raw_parsetree_list;
}


List * pg_analyze_and_rewrite(RawStmt *parsetree, const char *query_string, Oid *paramTypes, int numParams, QueryEnvironment *queryEnv)


{
	Query	   *query;
	List	   *querytree_list;

	TRACE_POSTGRESQL_QUERY_REWRITE_START(query_string);

	
	if (log_parser_stats)
		ResetUsage();

	query = parse_analyze(parsetree, query_string, paramTypes, numParams, queryEnv);

	if (log_parser_stats)
		ShowUsage("PARSE ANALYSIS STATISTICS");

	
	querytree_list = pg_rewrite_query(query);

	TRACE_POSTGRESQL_QUERY_REWRITE_DONE(query_string);

	return querytree_list;
}


List * pg_analyze_and_rewrite_params(RawStmt *parsetree, const char *query_string, ParserSetupHook parserSetup, void *parserSetupArg, QueryEnvironment *queryEnv)




{
	ParseState *pstate;
	Query	   *query;
	List	   *querytree_list;

	Assert(query_string != NULL);	

	TRACE_POSTGRESQL_QUERY_REWRITE_START(query_string);

	
	if (log_parser_stats)
		ResetUsage();

	pstate = make_parsestate(NULL);
	pstate->p_sourcetext = query_string;
	pstate->p_queryEnv = queryEnv;
	(*parserSetup) (pstate, parserSetupArg);

	query = transformTopLevelStmt(pstate, parsetree);

	if (post_parse_analyze_hook)
		(*post_parse_analyze_hook) (pstate, query);

	free_parsestate(pstate);

	if (log_parser_stats)
		ShowUsage("PARSE ANALYSIS STATISTICS");

	
	querytree_list = pg_rewrite_query(query);

	TRACE_POSTGRESQL_QUERY_REWRITE_DONE(query_string);

	return querytree_list;
}


static List * pg_rewrite_query(Query *query)
{
	List	   *querytree_list;

	if (Debug_print_parse)
		elog_node_display(LOG, "parse tree", query, Debug_pretty_print);

	if (log_parser_stats)
		ResetUsage();

	if (query->commandType == CMD_UTILITY)
	{
		
		querytree_list = list_make1(query);
	}
	else {
		
		querytree_list = QueryRewrite(query);
	}

	if (log_parser_stats)
		ShowUsage("REWRITER STATISTICS");


	
	{
		List	   *new_list;

		new_list = copyObject(querytree_list);
		
		if (!equal(new_list, querytree_list))
			elog(WARNING, "copyObject() failed to produce equal parse tree");
		else querytree_list = new_list;
	}



	
	{
		List	   *new_list = NIL;
		ListCell   *lc;

		
		foreach(lc, querytree_list)
		{
			Query	   *query = castNode(Query, lfirst(lc));

			if (query->commandType != CMD_UTILITY)
			{
				char	   *str = nodeToString(query);
				Query	   *new_query = stringToNodeWithLocations(str);

				
				new_query->queryId = query->queryId;

				new_list = lappend(new_list, new_query);
				pfree(str);
			}
			else new_list = lappend(new_list, query);
		}

		
		if (!equal(new_list, querytree_list))
			elog(WARNING, "outfuncs/readfuncs failed to produce equal parse tree");
		else querytree_list = new_list;
	}


	if (Debug_print_rewritten)
		elog_node_display(LOG, "rewritten parse tree", querytree_list, Debug_pretty_print);

	return querytree_list;
}



PlannedStmt * pg_plan_query(Query *querytree, int cursorOptions, ParamListInfo boundParams)
{
	PlannedStmt *plan;

	
	if (querytree->commandType == CMD_UTILITY)
		return NULL;

	
	Assert(ActiveSnapshotSet());

	TRACE_POSTGRESQL_QUERY_PLAN_START();

	if (log_planner_stats)
		ResetUsage();

	
	plan = planner(querytree, cursorOptions, boundParams);

	if (log_planner_stats)
		ShowUsage("PLANNER STATISTICS");


	
	{
		PlannedStmt *new_plan = copyObject(plan);

		

		
		if (!equal(new_plan, plan))
			elog(WARNING, "copyObject() failed to produce an equal plan tree");
		else  plan = new_plan;

	}



	
	{
		char	   *str;
		PlannedStmt *new_plan;

		str = nodeToString(plan);
		new_plan = stringToNodeWithLocations(str);
		pfree(str);

		

		
		if (!equal(new_plan, plan))
			elog(WARNING, "outfuncs/readfuncs failed to produce an equal plan tree");
		else  plan = new_plan;

	}


	
	if (Debug_print_plan)
		elog_node_display(LOG, "plan", plan, Debug_pretty_print);

	TRACE_POSTGRESQL_QUERY_PLAN_DONE();

	return plan;
}


List * pg_plan_queries(List *querytrees, int cursorOptions, ParamListInfo boundParams)
{
	List	   *stmt_list = NIL;
	ListCell   *query_list;

	foreach(query_list, querytrees)
	{
		Query	   *query = lfirst_node(Query, query_list);
		PlannedStmt *stmt;

		if (query->commandType == CMD_UTILITY)
		{
			
			stmt = makeNode(PlannedStmt);
			stmt->commandType = CMD_UTILITY;
			stmt->canSetTag = query->canSetTag;
			stmt->utilityStmt = query->utilityStmt;
			stmt->stmt_location = query->stmt_location;
			stmt->stmt_len = query->stmt_len;
		}
		else {
			stmt = pg_plan_query(query, cursorOptions, boundParams);
		}

		stmt_list = lappend(stmt_list, stmt);
	}

	return stmt_list;
}


static void exec_mpp_query(const char *query_string, const char * serializedPlantree, int serializedPlantreelen, const char * serializedQueryDispatchDesc, int serializedQueryDispatchDesclen)


{
	CommandDest dest = whereToSendOutput;
	MemoryContext oldcontext;
	bool		save_log_statement_stats = log_statement_stats;
	bool		was_logged = false;
	char		msec_str[32];
	PlannedStmt	   *plan = NULL;
	QueryDispatchDesc *ddesc = NULL;
	CmdType		commandType = CMD_UNKNOWN;
	SliceTable *sliceTable = NULL;
	ExecSlice  *slice = NULL;
	ParamListInfo paramLI = NULL;

	Assert(Gp_role == GP_ROLE_EXECUTE);
	
	if (query_string == NULL || strlen(query_string)==0)
		query_string = "mppexec";

	

	debug_query_string = query_string;

	pgstat_report_activity(STATE_RUNNING, query_string);

	
	if (save_log_statement_stats)
		ResetUsage();

	
	start_xact_command();

	
	drop_unnamed_stmt();

	
	oldcontext = MemoryContextSwitchTo(MessageContext);

 	
	if (serializedPlantree != NULL && serializedPlantreelen > 0)
	{
		plan = (PlannedStmt *) deserializeNode(serializedPlantree,serializedPlantreelen);
		if (!plan || !IsA(plan, PlannedStmt))
			elog(ERROR, "MPPEXEC: receive invalid planned statement");
    }

	
    if (serializedQueryDispatchDesc != NULL && serializedQueryDispatchDesclen > 0)
    {
		ddesc = (QueryDispatchDesc *) deserializeNode(serializedQueryDispatchDesc,serializedQueryDispatchDesclen);
		if (!ddesc || !IsA(ddesc, QueryDispatchDesc))
			elog(ERROR, "MPPEXEC: received invalid QueryDispatchDesc with planned statement");

        sliceTable = ddesc->sliceTable;

		if (sliceTable)
		{
			int			i;

			if (!IsA(sliceTable, SliceTable) || sliceTable->localSlice < 0 || sliceTable->localSlice >= sliceTable->numSlices)

				elog(ERROR, "MPPEXEC: received invalid slice table: %d", sliceTable->localSlice);

			
			for (i = 0; i < sliceTable->numSlices; i++)
			{
				slice = &sliceTable->slices[i];

				if (bms_is_member(qe_identifier, slice->processesMap))
					break;
			}
			if (i == sliceTable->numSlices)
				elog(ERROR, "could not find QE identifier in process map");
			sliceTable->localSlice = slice->sliceIndex;

			
			currentSliceId = sliceTable->localSlice;
		}

		if (ddesc->oidAssignments)
			AddPreassignedOids(ddesc->oidAssignments);
    }

	if ( !plan )
		elog(ERROR, "MPPEXEC: received neither Query nor Plan");

	
	if (plan->commandType != CMD_SELECT && plan->commandType != CMD_INSERT && plan->commandType != CMD_UPDATE && plan->commandType != CMD_DELETE && plan->commandType != CMD_UTILITY)



		elog(ERROR, "MPPEXEC: received non-DML Plan");
	commandType = plan->commandType;

	if ( slice )
	{
		
		if (sliceTable->localSlice != slice->rootIndex)
		{
			ListCell       *rtcell;
			RangeTblEntry  *rte;
			AclMode         removeperms = ACL_INSERT | ACL_UPDATE | ACL_DELETE | ACL_SELECT_FOR_UPDATE;

			
			foreach(rtcell, plan->rtable)
			{
				rte = (RangeTblEntry *)lfirst(rtcell);
				if (rte->rtekind == RTE_RELATION && 0 != (rte->requiredPerms & removeperms))
					rte->requiredPerms &= ~removeperms;
			}
		}
	}


	if (log_statement != LOGSTMT_NONE)
	{
		
		if (log_statement == LOGSTMT_ALL || (plan->utilityStmt && log_statement == LOGSTMT_DDL) || (plan && log_statement >= LOGSTMT_MOD))


		{
			ereport(LOG, (errmsg("statement: %s", query_string)
						   ));
			was_logged = true;
		}

	}

	
	if (ddesc && ddesc->paramInfo)
		paramLI = deserializeExternParams(ddesc->paramInfo);
	else paramLI = NULL;

	
	MemoryContextSwitchTo(oldcontext);

	
	{
		const char *commandTag;
		char		completionTag[COMPLETION_TAG_BUFSIZE];

		Portal		portal;
		DestReceiver *receiver;
		int16		format;

		
		if (commandType == CMD_UTILITY)
			commandTag = "MPPEXEC UTILITY";
		else if (commandType == CMD_SELECT)
			commandTag = "MPPEXEC SELECT";
		else if (commandType == CMD_INSERT)
			commandTag = "MPPEXEC INSERT";
		else if (commandType == CMD_UPDATE)
			commandTag = "MPPEXEC UPDATE";
		else if (commandType == CMD_DELETE)
			commandTag = "MPPEXEC DELETE";
		else commandTag = "MPPEXEC";


		set_ps_display(commandTag, false);

		BeginCommand(commandTag, dest);

        
		if (gp_segworker_relative_priority != 0)
		{
			renice_current_process(PostmasterPriority + gp_segworker_relative_priority);
		}

		if (Debug_dtm_action == DEBUG_DTM_ACTION_FAIL_BEGIN_COMMAND && CheckDebugDtmActionSqlCommandTag(commandTag))
		{
			ereport(ERROR, (errcode(ERRCODE_FAULT_INJECT), errmsg("Raise ERROR for debug_dtm_action = %d, commandTag = %s", Debug_dtm_action, commandTag)));


		}

		
		if (IsAbortedTransactionBlockState() 
			)
			ereport(ERROR, (errcode(ERRCODE_IN_FAILED_SQL_TRANSACTION), errmsg("current transaction is aborted, " "commands ignored until end of transaction block")));



		
		start_xact_command();

		
		oldcontext = MemoryContextSwitchTo(MessageContext);

		CHECK_FOR_INTERRUPTS();

		
		portal = CreatePortal("", true, true);
		
		portal->visible = false;

		
		PortalDefineQuery(portal, NULL, query_string,  T_Query, commandTag, list_make1(plan), NULL);







		
		PortalStart(portal, paramLI, 0, InvalidSnapshot, ddesc);

		
		format = 0;
		PortalSetResultFormat(portal, 1, &format);

		
		receiver = CreateDestReceiver(dest);
		if (dest == DestRemote)
			SetRemoteDestReceiverParams(receiver, portal);

		
		MemoryContextSwitchTo(oldcontext);

		
		(void) PortalRun(portal, FETCH_ALL, true, portal->run_once, receiver, receiver, completionTag);






		
		if (Gp_role == GP_ROLE_EXECUTE && Gp_is_writer)
			pgstat_send_qd_tabstats();

		(*receiver->rDestroy) (receiver);

		PortalDrop(portal, false);

		
		finish_xact_command();

		if (Debug_dtm_action == DEBUG_DTM_ACTION_FAIL_END_COMMAND && CheckDebugDtmActionSqlCommandTag(commandTag))
		{
			ereport(ERROR, (errcode(ERRCODE_FAULT_INJECT), errmsg("Raise ERROR for debug_dtm_action = %d, commandTag = %s", Debug_dtm_action, commandTag)));


		}

		
		EndCommand(completionTag, dest);
	}							

	
	finish_xact_command();

	
	switch (check_log_duration(msec_str, was_logged))
	{
		case 1:
			ereport(LOG, (errmsg("duration: %s ms", msec_str), errhidestmt(false)));

			break;
		case 2:
			ereport(LOG, (errmsg("duration: %s ms  statement: %s", msec_str, query_string), errhidestmt(true)));


			break;
	}

	if (save_log_statement_stats)
		ShowUsage("QUERY STATISTICS");


	if (gp_enable_resqueue_priority)
	{
		BackoffBackendEntryExit();
	}

	debug_query_string = NULL;
}

static bool CheckDebugDtmActionProtocol(DtxProtocolCommand dtxProtocolCommand, DtxContextInfo *contextInfo)

{
	if (Debug_dtm_action_nestinglevel == 0)
	{
		return (Debug_dtm_action_target == DEBUG_DTM_ACTION_TARGET_PROTOCOL && Debug_dtm_action_protocol == dtxProtocolCommand && Debug_dtm_action_segment == GpIdentity.segindex);

	}
	else {
		return (Debug_dtm_action_target == DEBUG_DTM_ACTION_TARGET_PROTOCOL && Debug_dtm_action_protocol == dtxProtocolCommand && Debug_dtm_action_segment == GpIdentity.segindex && Debug_dtm_action_nestinglevel == contextInfo->nestingLevel);


	}
}

static void exec_mpp_dtx_protocol_command(DtxProtocolCommand dtxProtocolCommand, const char *loggingStr, const char *gid, DtxContextInfo *contextInfo)



{
	CommandDest dest = whereToSendOutput;
	const char *commandTag = loggingStr;

	if (log_statement == LOGSTMT_ALL)
		elog(LOG,"DTM protocol command '%s' for gid = %s", loggingStr, gid);

	elog((Debug_print_full_dtm ? LOG : DEBUG5),"exec_mpp_dtx_protocol_command received the dtxProtocolCommand = %d (%s) gid = %s", dtxProtocolCommand, loggingStr, gid);

	set_ps_display(commandTag, false);

	if (Debug_dtm_action == DEBUG_DTM_ACTION_FAIL_BEGIN_COMMAND && CheckDebugDtmActionProtocol(dtxProtocolCommand, contextInfo))
	{
		ereport(ERROR, (errcode(ERRCODE_FAULT_INJECT), errmsg("Raise ERROR for debug_dtm_action = %d, debug_dtm_action_protocol = %s", Debug_dtm_action, DtxProtocolCommandToString(dtxProtocolCommand))));


	}
	if (Debug_dtm_action == DEBUG_DTM_ACTION_PANIC_BEGIN_COMMAND && CheckDebugDtmActionProtocol(dtxProtocolCommand, contextInfo))
	{
		
		AvoidCorefileGeneration();
		elog(PANIC,"PANIC for debug_dtm_action = %d, debug_dtm_action_protocol = %s", Debug_dtm_action, DtxProtocolCommandToString(dtxProtocolCommand));
	}

	BeginCommand(commandTag, dest);

	performDtxProtocolCommand(dtxProtocolCommand, gid, contextInfo);

	elog((Debug_print_full_dtm ? LOG : DEBUG5),"exec_mpp_dtx_protocol_command calling EndCommand for dtxProtocolCommand = %d (%s) gid = %s", dtxProtocolCommand, loggingStr, gid);

	if (Debug_dtm_action == DEBUG_DTM_ACTION_FAIL_END_COMMAND && CheckDebugDtmActionProtocol(dtxProtocolCommand, contextInfo))
	{
		ereport(ERROR, (errcode(ERRCODE_FAULT_INJECT), errmsg("Raise error for debug_dtm_action = %d, debug_dtm_action_protocol = %s", Debug_dtm_action, DtxProtocolCommandToString(dtxProtocolCommand))));


	}

	
	if (ProcDiePending)
		ereport(FATAL, (errcode(ERRCODE_ADMIN_SHUTDOWN), errmsg("Terminating the connection (DTM protocol command '%s' " "for gid=%s", loggingStr, gid)));



	EndCommand(commandTag, dest);
}

static bool CheckDebugDtmActionSqlCommandTag(const char *sqlCommandTag)
{
	bool result;

	result = (Debug_dtm_action_target == DEBUG_DTM_ACTION_TARGET_SQL && strcmp(Debug_dtm_action_sql_command_tag, sqlCommandTag) == 0 && Debug_dtm_action_segment == GpIdentity.segindex);


	elog((Debug_print_full_dtm ? LOG : DEBUG5),"CheckDebugDtmActionSqlCommandTag Debug_dtm_action_target = %d, Debug_dtm_action_sql_command_tag = '%s' check '%s', Debug_dtm_action_segment = %d, Debug_dtm_action_primary = %s, result = %s.", Debug_dtm_action_target, Debug_dtm_action_sql_command_tag, (sqlCommandTag == NULL ? "<NULL>" : sqlCommandTag), Debug_dtm_action_segment, (Debug_dtm_action_primary ? "true" : "false"), (result ? "true" : "false"));




	return result;
}

static void restore_guc_to_QE(void )
{
	Assert(Gp_role == GP_ROLE_DISPATCH && gp_guc_restore_list);
	ListCell *lc;

	start_xact_command();

	foreach(lc, gp_guc_restore_list)
	{
		struct config_generic* gconfig = (struct config_generic *)lfirst(lc);
		PG_TRY();
		{
			DispatchSyncPGVariable(gconfig);
		}
		PG_CATCH();
		{
			
			DisconnectAndDestroyAllGangs(false);
		}
		PG_END_TRY();
	}

	finish_xact_command();
	list_free(gp_guc_restore_list);
	gp_guc_restore_list = NIL;
}


static void exec_simple_query(const char *query_string)
{
	CommandDest dest = whereToSendOutput;
	MemoryContext oldcontext;
	List	   *parsetree_list;
	ListCell   *parsetree_item;
	bool		save_log_statement_stats = log_statement_stats;
	bool		was_logged = false;
	bool		use_implicit_block;
	char		msec_str[32];

	SIMPLE_FAULT_INJECTOR("exec_simple_query_start");

	if (Gp_role != GP_ROLE_EXECUTE)
		increment_command_count();

	
	debug_query_string = query_string;

	pgstat_report_activity(STATE_RUNNING, query_string);

	TRACE_POSTGRESQL_QUERY_START(query_string);

	
	if (save_log_statement_stats)
		ResetUsage();

	
	start_xact_command();

	
	drop_unnamed_stmt();

	
	oldcontext = MemoryContextSwitchTo(MessageContext);

	
	parsetree_list = pg_parse_query(query_string);

	
	if (check_log_statement(parsetree_list))
	{
		ereport(LOG, (errmsg("statement: %s", query_string), errhidestmt(true), errdetail_execute(parsetree_list)));


		was_logged = true;
	}

	
	MemoryContextSwitchTo(oldcontext);

	
	use_implicit_block = (list_length(parsetree_list) > 1);

	
	foreach(parsetree_item, parsetree_list)
	{
		RawStmt    *parsetree = lfirst_node(RawStmt, parsetree_item);
		bool		snapshot_set = false;
		const char *commandTag;
		char		completionTag[COMPLETION_TAG_BUFSIZE];
		List	   *querytree_list, *plantree_list;
		Portal		portal;
		DestReceiver *receiver;
		int16		format;

		
		commandTag = CreateCommandTag(parsetree->stmt);

		set_ps_display(commandTag, false);

		BeginCommand(commandTag, dest);

		if (Debug_dtm_action == DEBUG_DTM_ACTION_FAIL_BEGIN_COMMAND && CheckDebugDtmActionSqlCommandTag(commandTag))
		{
			ereport(ERROR, (errcode(ERRCODE_FAULT_INJECT), errmsg("Raise ERROR for debug_dtm_action = %d, commandTag = %s", Debug_dtm_action, commandTag)));


		}

		
		TransactionStmt *transStmt = (TransactionStmt *) parsetree;
		if (Gp_role == GP_ROLE_UTILITY && IsA(parsetree, TransactionStmt) && transStmt->kind == TRANS_STMT_PREPARE)
		{
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("PREPARE TRANSACTION is not supported in utility mode")));

		}

		
		if (IsAbortedTransactionBlockState() && !IsTransactionExitStmt(parsetree->stmt))
			ereport(ERROR, (errcode(ERRCODE_IN_FAILED_SQL_TRANSACTION), errmsg("current transaction is aborted, " "commands ignored until end of transaction block"), errdetail_abort()));




		
		start_xact_command();

		
		if (use_implicit_block)
			BeginImplicitTransactionBlock();

		
		CHECK_FOR_INTERRUPTS();

		
		if (analyze_requires_snapshot(parsetree))
		{
			PushActiveSnapshot(GetTransactionSnapshot());
			snapshot_set = true;
		}

		
		oldcontext = MemoryContextSwitchTo(MessageContext);

		querytree_list = pg_analyze_and_rewrite(parsetree, query_string, NULL, 0, NULL);

		plantree_list = pg_plan_queries(querytree_list, CURSOR_OPT_PARALLEL_OK, NULL);

		
		if (snapshot_set)
			PopActiveSnapshot();

		
		CHECK_FOR_INTERRUPTS();

		
		portal = CreatePortal("", true, true);
		
		portal->visible = false;

		
		PortalDefineQuery(portal, NULL, query_string, nodeTag(parsetree->stmt), commandTag, plantree_list, NULL);






		
		PortalStart(portal, NULL, 0, InvalidSnapshot, NULL);

		
		format = 0;				
		if (IsA(parsetree->stmt, FetchStmt))
		{
			FetchStmt  *stmt = (FetchStmt *) parsetree->stmt;

			if (!stmt->ismove)
			{
				Portal		fportal = GetPortalByName(stmt->portalname);

				if (PortalIsValid(fportal) && (fportal->cursorOptions & CURSOR_OPT_BINARY))
					format = 1; 
			}
		}
		PortalSetResultFormat(portal, 1, &format);

		
		receiver = CreateDestReceiver(dest);
		if (dest == DestRemote)
			SetRemoteDestReceiverParams(receiver, portal);

		
		MemoryContextSwitchTo(oldcontext);

		
		(void) PortalRun(portal, FETCH_ALL, true, true, receiver, receiver, completionTag);






		receiver->rDestroy(receiver);

		PortalDrop(portal, false);

		if (lnext(parsetree_item) == NULL)
		{
			
			if (use_implicit_block)
				EndImplicitTransactionBlock();
			finish_xact_command();
		}
		else if (IsA(parsetree->stmt, TransactionStmt))
		{
			
			finish_xact_command();
		}
		else {
			
			CommandCounterIncrement();
		}

		if (Debug_dtm_action == DEBUG_DTM_ACTION_FAIL_END_COMMAND && CheckDebugDtmActionSqlCommandTag(commandTag))
		{
			ereport(ERROR, (errcode(ERRCODE_FAULT_INJECT), errmsg("Raise ERROR for debug_dtm_action = %d, commandTag = %s", Debug_dtm_action, commandTag)));


		}

		
		EndCommand(completionTag, dest);
	}							

	
	finish_xact_command();

	
	if (!parsetree_list)
		NullCommand(dest);

	
	switch (check_log_duration(msec_str, was_logged))
	{
		case 1:
			ereport(LOG, (errmsg("duration: %s ms", msec_str), errhidestmt(false)));

			break;
		case 2:
			ereport(LOG, (errmsg("duration: %s ms  statement: %s", msec_str, query_string), errhidestmt(true), errdetail_execute(parsetree_list)));



			break;
	}

	if (save_log_statement_stats)
		ShowUsage("QUERY STATISTICS");

	TRACE_POSTGRESQL_QUERY_DONE(query_string);

	debug_query_string = NULL;
}


static void exec_parse_message(const char *query_string, const char *stmt_name, Oid *paramTypes, int numParams)



{
	MemoryContext unnamed_stmt_context = NULL;
	MemoryContext oldcontext;
	List	   *parsetree_list;
	RawStmt    *raw_parse_tree;
	const char *commandTag;
	List	   *querytree_list;
	CachedPlanSource *psrc;
	bool		is_named;
	bool		save_log_statement_stats = log_statement_stats;
	char		msec_str[32];
	NodeTag		sourceTag = T_Query;

	
	debug_query_string = query_string;

	pgstat_report_activity(STATE_RUNNING, query_string);

	set_ps_display("PARSE", false);

	if (save_log_statement_stats)
		ResetUsage();

	ereport(DEBUG2, (errmsg("parse %s: %s", *stmt_name ? stmt_name : "<unnamed>", query_string)));



	
	start_xact_command();

	
	is_named = (stmt_name[0] != '\0');
	if (is_named)
	{
		
		oldcontext = MemoryContextSwitchTo(MessageContext);
	}
	else {
		
		drop_unnamed_stmt();
		
		unnamed_stmt_context = AllocSetContextCreate(MessageContext, "unnamed prepared statement", ALLOCSET_DEFAULT_SIZES);


		oldcontext = MemoryContextSwitchTo(unnamed_stmt_context);
	}

	
	parsetree_list = pg_parse_query(query_string);

	
	if (list_length(parsetree_list) > 1)
		ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("cannot insert multiple commands into a prepared statement")));


	if (parsetree_list != NIL)
	{
		Query	   *query;
		bool		snapshot_set = false;

		raw_parse_tree = linitial_node(RawStmt, parsetree_list);

		if (IsA(raw_parse_tree->stmt, SelectStmt))
		{
			
			((SelectStmt *)raw_parse_tree->stmt)->disableLockingOptimization = true;
		}

		
		commandTag = CreateCommandTag(raw_parse_tree->stmt);

		
		if (IsAbortedTransactionBlockState() && !IsTransactionExitStmt(raw_parse_tree->stmt))
			ereport(ERROR, (errcode(ERRCODE_IN_FAILED_SQL_TRANSACTION), errmsg("current transaction is aborted, " "commands ignored until end of transaction block"), errdetail_abort()));




		
		psrc = CreateCachedPlan(raw_parse_tree, query_string, commandTag);

		
		if (analyze_requires_snapshot(raw_parse_tree))
		{
			PushActiveSnapshot(GetTransactionSnapshot());
			snapshot_set = true;
		}

		
		if (log_parser_stats)
			ResetUsage();

		query = parse_analyze_varparams(raw_parse_tree, query_string, &paramTypes, &numParams);



		
		for (int i = 0; i < numParams; i++)
		{
			Oid			ptype = paramTypes[i];

			if (ptype == InvalidOid || ptype == UNKNOWNOID)
				ereport(ERROR, (errcode(ERRCODE_INDETERMINATE_DATATYPE), errmsg("could not determine data type of parameter $%d", i + 1)));


		}

		if (log_parser_stats)
			ShowUsage("PARSE ANALYSIS STATISTICS");

		querytree_list = pg_rewrite_query(query);

		if (parsetree_list)
		{
			Node	   *parsetree = (Node *) linitial(parsetree_list);
			sourceTag = nodeTag(parsetree);
		}

		
		if (snapshot_set)
			PopActiveSnapshot();
	}
	else {
		
		raw_parse_tree = NULL;
		commandTag = NULL;
		psrc = CreateCachedPlan(raw_parse_tree, query_string, commandTag);
		querytree_list = NIL;
	}

	
	if (unnamed_stmt_context)
		MemoryContextSetParent(psrc->context, MessageContext);

	
	CompleteCachedPlan(psrc, querytree_list, unnamed_stmt_context, sourceTag, paramTypes, numParams, NULL, NULL, CURSOR_OPT_PARALLEL_OK, true);









	
	CHECK_FOR_INTERRUPTS();

	if (is_named)
	{
		
		StorePreparedStatement(stmt_name, psrc, false);
	}
	else {
		
		SaveCachedPlan(psrc);
		unnamed_stmt_psrc = psrc;
	}

	MemoryContextSwitchTo(oldcontext);

	
	CommandCounterIncrement();

	
	if (whereToSendOutput == DestRemote)
		pq_putemptymessage('1');

	
	switch (check_log_duration(msec_str, false))
	{
		case 1:
			ereport(LOG, (errmsg("duration: %s ms", msec_str), errhidestmt(true)));

			break;
		case 2:
			ereport(LOG, (errmsg("duration: %s ms  parse %s: %s", msec_str, *stmt_name ? stmt_name : "<unnamed>", query_string), errhidestmt(true)));




			break;
	}

	if (save_log_statement_stats)
		ShowUsage("PARSE MESSAGE STATISTICS");

	debug_query_string = NULL;
}


static void exec_bind_message(StringInfo input_message)
{
	const char *portal_name;
	const char *stmt_name;
	int			numPFormats;
	int16	   *pformats = NULL;
	int			numParams;
	int			numRFormats;
	int16	   *rformats = NULL;
	CachedPlanSource *psrc;
	CachedPlan *cplan;
	Portal		portal;
	char	   *query_string;
	char	   *saved_stmt_name;
	ParamListInfo params;
	MemoryContext oldContext;
	bool		save_log_statement_stats = log_statement_stats;
	bool		snapshot_set = false;
	char		msec_str[32];

	
	portal_name = pq_getmsgstring(input_message);
	stmt_name = pq_getmsgstring(input_message);

	elog((Debug_print_full_dtm ? LOG : DEBUG5), "Bind: portal %s stmt_name %s", portal_name, stmt_name);

	ereport(DEBUG2, (errmsg("bind %s to %s", *portal_name ? portal_name : "<unnamed>", *stmt_name ? stmt_name : "<unnamed>")));



	
	if (stmt_name[0] != '\0')
	{
		PreparedStatement *pstmt;

		pstmt = FetchPreparedStatement(stmt_name, true);
		psrc = pstmt->plansource;
	}
	else {
		
		psrc = unnamed_stmt_psrc;
		if (!psrc)
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_PSTATEMENT), errmsg("unnamed prepared statement does not exist")));

	}

	
	debug_query_string = psrc->query_string;

	pgstat_report_activity(STATE_RUNNING, psrc->query_string);

	set_ps_display("BIND", false);

	if (save_log_statement_stats)
		ResetUsage();

	
	start_xact_command();

	
	MemoryContextSwitchTo(MessageContext);

	
	numPFormats = pq_getmsgint(input_message, 2);
	if (numPFormats > 0)
	{
		pformats = (int16 *) palloc(numPFormats * sizeof(int16));
		for (int i = 0; i < numPFormats; i++)
			pformats[i] = pq_getmsgint(input_message, 2);
	}

	
	numParams = pq_getmsgint(input_message, 2);

	if (numPFormats > 1 && numPFormats != numParams)
		ereport(ERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("bind message has %d parameter formats but %d parameters", numPFormats, numParams)));



	if (numParams != psrc->num_params)
		ereport(ERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("bind message supplies %d parameters, but prepared statement \"%s\" requires %d", numParams, stmt_name, psrc->num_params)));



	
	if (IsAbortedTransactionBlockState() && (!(psrc->raw_parse_tree && IsTransactionExitStmt(psrc->raw_parse_tree->stmt)) || numParams != 0))


		ereport(ERROR, (errcode(ERRCODE_IN_FAILED_SQL_TRANSACTION), errmsg("current transaction is aborted, " "commands ignored until end of transaction block"), errdetail_abort()));




	
	if (portal_name[0] == '\0')
		portal = CreatePortal(portal_name, true, true);
	else portal = CreatePortal(portal_name, false, false);

	portal->is_extended_query = true;

	
	oldContext = MemoryContextSwitchTo(portal->portalContext);

	
	query_string = pstrdup(psrc->query_string);

	
	if (stmt_name[0])
		saved_stmt_name = pstrdup(stmt_name);
	else saved_stmt_name = NULL;

	
	if (numParams > 0 || (psrc->raw_parse_tree && analyze_requires_snapshot(psrc->raw_parse_tree)))

	{
		PushActiveSnapshot(GetTransactionSnapshot());
		snapshot_set = true;
	}

	
	if (numParams > 0)
	{
		params = makeParamList(numParams);

		for (int paramno = 0; paramno < numParams; paramno++)
		{
			Oid			ptype = psrc->param_types[paramno];
			int32		plength;
			Datum		pval;
			bool		isNull;
			StringInfoData pbuf;
			char		csave;
			int16		pformat;

			plength = pq_getmsgint(input_message, 4);
			isNull = (plength == -1);

			if (!isNull)
			{
				const char *pvalue = pq_getmsgbytes(input_message, plength);

				
				pbuf.data = unconstify(char *, pvalue);
				pbuf.maxlen = plength + 1;
				pbuf.len = plength;
				pbuf.cursor = 0;

				csave = pbuf.data[plength];
				pbuf.data[plength] = '\0';
			}
			else {
				pbuf.data = NULL;	
				csave = 0;
			}

			if (numPFormats > 1)
				pformat = pformats[paramno];
			else if (numPFormats > 0)
				pformat = pformats[0];
			else pformat = 0;

			if (pformat == 0)	
			{
				Oid			typinput;
				Oid			typioparam;
				char	   *pstring;

				getTypeInputInfo(ptype, &typinput, &typioparam);

				
				if (isNull)
					pstring = NULL;
				else pstring = pg_client_to_server(pbuf.data, plength);

				pval = OidInputFunctionCall(typinput, pstring, typioparam, -1);

				
				if (pstring && pstring != pbuf.data)
					pfree(pstring);
			}
			else if (pformat == 1)	
			{
				Oid			typreceive;
				Oid			typioparam;
				StringInfo	bufptr;

				
				getTypeBinaryInputInfo(ptype, &typreceive, &typioparam);

				if (isNull)
					bufptr = NULL;
				else bufptr = &pbuf;

				pval = OidReceiveFunctionCall(typreceive, bufptr, typioparam, -1);

				
				if (!isNull && pbuf.cursor != pbuf.len)
					ereport(ERROR, (errcode(ERRCODE_INVALID_BINARY_REPRESENTATION), errmsg("incorrect binary data format in bind parameter %d", paramno + 1)));


			}
			else {
				ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("unsupported format code: %d", pformat)));


				pval = 0;		
			}

			
			if (!isNull)
				pbuf.data[plength] = csave;

			params->params[paramno].value = pval;
			params->params[paramno].isnull = isNull;

			
			params->params[paramno].pflags = PARAM_FLAG_CONST;
			params->params[paramno].ptype = ptype;
		}
	}
	else params = NULL;

	
	MemoryContextSwitchTo(oldContext);

	
	numRFormats = pq_getmsgint(input_message, 2);
	if (numRFormats > 0)
	{
		rformats = (int16 *) palloc(numRFormats * sizeof(int16));
		for (int i = 0; i < numRFormats; i++)
			rformats[i] = pq_getmsgint(input_message, 2);
	}

	pq_getmsgend(input_message);

	
	cplan = GetCachedPlan(psrc, params, false, NULL, NULL);

	
	PortalDefineQuery(portal, saved_stmt_name, query_string, psrc->sourceTag, psrc->commandTag, cplan->stmt_list, cplan);






	
	if (snapshot_set)
		PopActiveSnapshot();

	
	PortalStart(portal, params, 0, InvalidSnapshot, NULL);

	
	PortalSetResultFormat(portal, numRFormats, rformats);

	
	if (whereToSendOutput == DestRemote)
		pq_putemptymessage('2');

	
	switch (check_log_duration(msec_str, false))
	{
		case 1:
			ereport(LOG, (errmsg("duration: %s ms", msec_str), errhidestmt(true)));

			break;
		case 2:
			ereport(LOG, (errmsg("duration: %s ms  bind %s%s%s: %s", msec_str, *stmt_name ? stmt_name : "<unnamed>", *portal_name ? "/" : "", *portal_name ? portal_name : "", psrc->query_string), errhidestmt(true), errdetail_params(params)));







			break;
	}

	if (save_log_statement_stats)
		ShowUsage("BIND MESSAGE STATISTICS");

	debug_query_string = NULL;
}


static void exec_execute_message(const char *portal_name, int64 max_rows)
{
	CommandDest dest;
	DestReceiver *receiver;
	Portal		portal;
	bool		completed;
	char		completionTag[COMPLETION_TAG_BUFSIZE];
	const char *sourceText;
	const char *prepStmtName;
	ParamListInfo portalParams;
	bool		save_log_statement_stats = log_statement_stats;
	bool		is_xact_command;
	bool		execute_is_fetch;
	bool		was_logged = false;
	char		msec_str[32];

	
	dest = whereToSendOutput;
	if (dest == DestRemote)
		dest = DestRemoteExecute;

	portal = GetPortalByName(portal_name);
	if (!PortalIsValid(portal))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_CURSOR), errmsg("portal \"%s\" does not exist", portal_name)));


	
	if (portal->commandTag == NULL)
	{
		Assert(portal->stmts == NIL);
		NullCommand(dest);
		return;
	}

	if (Gp_role != GP_ROLE_EXECUTE)
	{

		
		bool is_utility_stmt = true;
		ListCell   *stmtlist_item = NULL;
		foreach(stmtlist_item, portal->stmts)
		{
			Node *stmt = lfirst(stmtlist_item);
			if (IsA(stmt, PlannedStmt))
			{
				is_utility_stmt = false;
				break;
			}
		}
		if (is_utility_stmt)
			increment_command_count();
	}

	
	is_xact_command = IsTransactionStmtList(portal->stmts);

	
	if (is_xact_command)
	{
		sourceText = pstrdup(portal->sourceText);
		if (portal->prepStmtName)
			prepStmtName = pstrdup(portal->prepStmtName);
		else prepStmtName = "<unnamed>";

		
		portalParams = NULL;
	}
	else {
		sourceText = portal->sourceText;
		if (portal->prepStmtName)
			prepStmtName = portal->prepStmtName;
		else prepStmtName = "<unnamed>";
		portalParams = portal->portalParams;
	}

	
	debug_query_string = sourceText;

	pgstat_report_activity(STATE_RUNNING, sourceText);

	set_ps_display(portal->commandTag, false);

	if (save_log_statement_stats)
		ResetUsage();

	BeginCommand(portal->commandTag, dest);

	
	receiver = CreateDestReceiver(dest);
	if (dest == DestRemoteExecute)
		SetRemoteDestReceiverParams(receiver, portal);

	
	start_xact_command();

	
	execute_is_fetch = !portal->atStart;

	
	if (check_log_statement(portal->stmts))
	{
		ereport(LOG, (errmsg("%s %s%s%s: %s", execute_is_fetch ? _("execute fetch from") :


						_("execute"), prepStmtName, *portal_name ? "/" : "", *portal_name ? portal_name : "", sourceText), errhidestmt(true), errdetail_params(portalParams)));





		was_logged = true;
	}

	
	if (IsAbortedTransactionBlockState() && !IsTransactionExitStmtList(portal->stmts))
		ereport(ERROR, (errcode(ERRCODE_IN_FAILED_SQL_TRANSACTION), errmsg("current transaction is aborted, " "commands ignored until end of transaction block"), errdetail_abort()));




	
	CHECK_FOR_INTERRUPTS();

	
	if (max_rows <= 0)
		max_rows = FETCH_ALL;

	completed = PortalRun(portal, max_rows, true, !execute_is_fetch && max_rows == FETCH_ALL, receiver, receiver, completionTag);






	receiver->rDestroy(receiver);

	if (completed)
	{
		if (is_xact_command)
		{
			
			finish_xact_command();
		}
		else {
			
			CommandCounterIncrement();

			
			disable_statement_timeout();
		}

		
		EndCommand(completionTag, dest);
	}
	else {
		
		if (whereToSendOutput == DestRemote)
			pq_putemptymessage('s');
	}

	
	switch (check_log_duration(msec_str, was_logged))
	{
		case 1:
			ereport(LOG, (errmsg("duration: %s ms", msec_str), errhidestmt(false)));

			break;
		case 2:
			ereport(LOG, (errmsg("duration: %s ms  %s %s%s%s: %s", msec_str, execute_is_fetch ? _("execute fetch from") :



							_("execute"), prepStmtName, *portal_name ? "/" : "", *portal_name ? portal_name : "", sourceText), errhidestmt(true), errdetail_params(portalParams)));





			break;
	}

	if (save_log_statement_stats)
		ShowUsage("EXECUTE MESSAGE STATISTICS");

	debug_query_string = NULL;
}


static bool check_log_statement(List *stmt_list)
{
	ListCell   *stmt_item;

	if (log_statement == LOGSTMT_NONE)
		return false;
	if (log_statement == LOGSTMT_ALL)
		return true;

	
	foreach(stmt_item, stmt_list)
	{
		Node	   *stmt = (Node *) lfirst(stmt_item);

		if (GetCommandLogLevel(stmt) <= log_statement)
			return true;
	}

	return false;
}


int check_log_duration(char *msec_str, bool was_logged)
{
	if (log_duration || log_min_duration_statement >= 0 || xact_is_sampled)
	{
		long		secs;
		int			usecs;
		int			msecs;
		bool		exceeded;
		bool		in_sample;

		TimestampDifference(GetCurrentStatementStartTimestamp(), GetCurrentTimestamp(), &secs, &usecs);

		msecs = usecs / 1000;

		
		exceeded = (log_min_duration_statement == 0 || (log_min_duration_statement > 0 && (secs > log_min_duration_statement / 1000 || secs * 1000 + msecs >= log_min_duration_statement)));



		
		in_sample = exceeded && log_statement_sample_rate != 0 && (log_statement_sample_rate == 1 || random() <= log_statement_sample_rate * MAX_RANDOM_VALUE);



		if ((exceeded && in_sample) || log_duration || xact_is_sampled)
		{
			snprintf(msec_str, 32, "%ld.%03d", secs * 1000 + msecs, usecs % 1000);
			if ((exceeded || xact_is_sampled) && !was_logged)
				return 2;
			else return 1;
		}
	}

	return 0;
}


static int errdetail_execute(List *raw_parsetree_list)
{
	ListCell   *parsetree_item;

	foreach(parsetree_item, raw_parsetree_list)
	{
		RawStmt    *parsetree = lfirst_node(RawStmt, parsetree_item);

		if (IsA(parsetree->stmt, ExecuteStmt))
		{
			ExecuteStmt *stmt = (ExecuteStmt *) parsetree->stmt;
			PreparedStatement *pstmt;

			pstmt = FetchPreparedStatement(stmt->name, false);
			if (pstmt)
			{
				errdetail("prepare: %s", pstmt->plansource->query_string);
				return 0;
			}
		}
	}

	return 0;
}


static int errdetail_params(ParamListInfo params)
{
	
	if (params && params->numParams > 0 && !IsAbortedTransactionBlockState())
	{
		StringInfoData param_str;
		MemoryContext oldcontext;

		
		Assert(params->paramFetch == NULL);

		
		oldcontext = MemoryContextSwitchTo(MessageContext);

		initStringInfo(&param_str);

		for (int paramno = 0; paramno < params->numParams; paramno++)
		{
			ParamExternData *prm = &params->params[paramno];
			Oid			typoutput;
			bool		typisvarlena;
			char	   *pstring;
			char	   *p;

			appendStringInfo(&param_str, "%s$%d = ", paramno > 0 ? ", " : "", paramno + 1);


			if (prm->isnull || !OidIsValid(prm->ptype))
			{
				appendStringInfoString(&param_str, "NULL");
				continue;
			}

			getTypeOutputInfo(prm->ptype, &typoutput, &typisvarlena);

			pstring = OidOutputFunctionCall(typoutput, prm->value);

			appendStringInfoCharMacro(&param_str, '\'');
			for (p = pstring; *p; p++)
			{
				if (*p == '\'') 
					appendStringInfoCharMacro(&param_str, *p);
				appendStringInfoCharMacro(&param_str, *p);
			}
			appendStringInfoCharMacro(&param_str, '\'');

			pfree(pstring);
		}

		errdetail("parameters: %s", param_str.data);

		pfree(param_str.data);

		MemoryContextSwitchTo(oldcontext);
	}

	return 0;
}


static int errdetail_abort(void)
{
	if (MyProc->recoveryConflictPending)
		errdetail("abort reason: recovery conflict");

	return 0;
}


static int errdetail_recovery_conflict(void)
{
	switch (RecoveryConflictReason)
	{
		case PROCSIG_RECOVERY_CONFLICT_BUFFERPIN:
			errdetail("User was holding shared buffer pin for too long.");
			break;
		case PROCSIG_RECOVERY_CONFLICT_LOCK:
			errdetail("User was holding a relation lock for too long.");
			break;
		case PROCSIG_RECOVERY_CONFLICT_TABLESPACE:
			errdetail("User was or might have been using tablespace that must be dropped.");
			break;
		case PROCSIG_RECOVERY_CONFLICT_SNAPSHOT:
			errdetail("User query might have needed to see row versions that must be removed.");
			break;
		case PROCSIG_RECOVERY_CONFLICT_STARTUP_DEADLOCK:
			errdetail("User transaction caused buffer deadlock with recovery.");
			break;
		case PROCSIG_RECOVERY_CONFLICT_DATABASE:
			errdetail("User was connected to a database that must be dropped.");
			break;
		default:
			break;
			
	}

	return 0;
}


static void exec_describe_statement_message(const char *stmt_name)
{
	CachedPlanSource *psrc;

	
	start_xact_command();

	
	MemoryContextSwitchTo(MessageContext);

	
	if (stmt_name[0] != '\0')
	{
		PreparedStatement *pstmt;

		pstmt = FetchPreparedStatement(stmt_name, true);
		psrc = pstmt->plansource;
	}
	else {
		
		psrc = unnamed_stmt_psrc;
		if (!psrc)
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_PSTATEMENT), errmsg("unnamed prepared statement does not exist")));

	}

	
	Assert(psrc->fixed_result);

	
	if (IsAbortedTransactionBlockState() && psrc->resultDesc)
		ereport(ERROR, (errcode(ERRCODE_IN_FAILED_SQL_TRANSACTION), errmsg("current transaction is aborted, " "commands ignored until end of transaction block"), errdetail_abort()));




	if (whereToSendOutput != DestRemote)
		return;					

	
	pq_beginmessage_reuse(&row_description_buf, 't');	
	pq_sendint16(&row_description_buf, psrc->num_params);

	for (int i = 0; i < psrc->num_params; i++)
	{
		Oid			ptype = psrc->param_types[i];

		pq_sendint32(&row_description_buf, (int) ptype);
	}
	pq_endmessage_reuse(&row_description_buf);

	
	if (psrc->resultDesc)
	{
		List	   *tlist;

		
		tlist = CachedPlanGetTargetList(psrc, NULL);

		SendRowDescriptionMessage(&row_description_buf, psrc->resultDesc, tlist, NULL);


	}
	else pq_putemptymessage('n');

}


static void exec_describe_portal_message(const char *portal_name)
{
	Portal		portal;

	
	start_xact_command();

	
	MemoryContextSwitchTo(MessageContext);

	portal = GetPortalByName(portal_name);
	if (!PortalIsValid(portal))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_CURSOR), errmsg("portal \"%s\" does not exist", portal_name)));


	
	if (IsAbortedTransactionBlockState() && portal->tupDesc)
		ereport(ERROR, (errcode(ERRCODE_IN_FAILED_SQL_TRANSACTION), errmsg("current transaction is aborted, " "commands ignored until end of transaction block"), errdetail_abort()));




	if (whereToSendOutput != DestRemote)
		return;					

	if (portal->tupDesc)
		SendRowDescriptionMessage(&row_description_buf, portal->tupDesc, FetchPortalTargetList(portal), portal->formats);


	else pq_putemptymessage('n');
}



static void start_xact_command(void)
{
	if (!xact_started)
	{
		StartTransactionCommand();

		xact_started = true;
	}

	
	enable_statement_timeout();
}

static void finish_xact_command(void)
{
	
	disable_statement_timeout();

	if (xact_started)
	{
		CommitTransactionCommand();


		
		
		MemoryContextCheck(TopMemoryContext);



		
		MemoryContextStats(TopMemoryContext);


		xact_started = false;
	}
}





static bool IsTransactionExitStmt(Node *parsetree)
{
	if (parsetree && IsA(parsetree, TransactionStmt))
	{
		TransactionStmt *stmt = (TransactionStmt *) parsetree;

		if (stmt->kind == TRANS_STMT_COMMIT || stmt->kind == TRANS_STMT_PREPARE || stmt->kind == TRANS_STMT_ROLLBACK || stmt->kind == TRANS_STMT_ROLLBACK_TO)


			return true;
	}
	return false;
}


static bool IsTransactionExitStmtList(List *pstmts)
{
	if (list_length(pstmts) == 1)
	{
		PlannedStmt *pstmt = linitial_node(PlannedStmt, pstmts);

		if (pstmt->commandType == CMD_UTILITY && IsTransactionExitStmt(pstmt->utilityStmt))
			return true;
	}
	return false;
}


static bool IsTransactionStmtList(List *pstmts)
{
	if (list_length(pstmts) == 1)
	{
		PlannedStmt *pstmt = linitial_node(PlannedStmt, pstmts);

		if (pstmt->commandType == CMD_UTILITY && IsA(pstmt->utilityStmt, TransactionStmt))
			return true;
	}
	return false;
}


static void drop_unnamed_stmt(void)
{
	
	if (unnamed_stmt_psrc)
	{
		CachedPlanSource *psrc = unnamed_stmt_psrc;

		unnamed_stmt_psrc = NULL;
		DropCachedPlan(psrc);
	}
}





void quickdie(SIGNAL_ARGS)
{
	sigaddset(&BlockSig, SIGQUIT);	
	PG_SETMASK(&BlockSig);

	in_quickdie=true;

	
	HOLD_INTERRUPTS();

	
	if (ClientAuthInProgress && whereToSendOutput == DestRemote)
		whereToSendOutput = DestNone;

	
	ereport(WARNING, (errcode(ERRCODE_CRASH_SHUTDOWN), errmsg("terminating connection because of crash of another server process"), errdetail("The postmaster has commanded this server process to roll back" " the current transaction and exit, because another" " server process exited abnormally and possibly corrupted" " shared memory."), errhint("In a moment you should be able to reconnect to the" " database and repeat your command.")));








	
	_exit(2);
}


void die(SIGNAL_ARGS)
{
	int			save_errno = errno;

	
	if (!proc_exit_inprogress)
	{
		InterruptPending = true;
		ProcDiePending = true;
	}

	
	SetLatch(MyLatch);

	
	if (DoingCommandRead && whereToSendOutput != DestRemote)
		ProcessInterrupts(__FILE__, __LINE__);

	errno = save_errno;
}


void StatementCancelHandler(SIGNAL_ARGS)
{
	int			save_errno = errno;

	
	if (!proc_exit_inprogress)
	{
		InterruptPending = true;
		QueryCancelPending = true;
		QueryCancelCleanup = true;

		if (cancel_pending_hook)
			(*cancel_pending_hook)();
	}

	
	SetLatch(MyLatch);

	errno = save_errno;
}



static void CdbProgramErrorHandler(SIGNAL_ARGS)
{
    int			save_errno = errno;
    char       *pts = "process";

	if (!pthread_equal(main_tid, pthread_self()))
	{

		write_stderr("\nUnexpected internal error: Master %d received signal %d in worker thread %lu (forwarding signal to main thread)\n\n", MyProcPid, postgres_signal_arg, (unsigned long)pthread_self());

		write_stderr("\nUnexpected internal error: Master %d received signal %d in worker thread %lu (forwarding signal to main thread)\n\n", MyProcPid, postgres_signal_arg, (unsigned long)pthread_self().p);

		
		if (!in_quickdie)
			pthread_kill(main_tid, postgres_signal_arg);

		
		if (!(gp_reraise_signal && (postgres_signal_arg == SIGSEGV || postgres_signal_arg == SIGILL || postgres_signal_arg == SIGBUS)))


		{
			pthread_exit(NULL);
		}

		return;
	}


    if (Gp_role == GP_ROLE_DISPATCH)
        pts = "Master process";
    else if (Gp_role == GP_ROLE_EXECUTE)
        pts = "Segment process";
    else pts = "Process";

    errno = save_errno;
    StandardHandlerForSigillSigsegvSigbus_OnMainThread(pts, PASS_SIGNAL_ARGS);
}


void FloatExceptionHandler(SIGNAL_ARGS)
{
	
	ereport(ERROR, (errcode(ERRCODE_FLOATING_POINT_EXCEPTION), errmsg("floating-point exception"), errdetail("An invalid floating-point operation was signaled. " "This probably means an out-of-range result or an " "invalid operation, such as division by zero.")));




}


void PostgresSigHupHandler(SIGNAL_ARGS)
{
	int			save_errno = errno;

	ConfigReloadPending = true;
	SetLatch(MyLatch);

	errno = save_errno;
}


void RecoveryConflictInterrupt(ProcSignalReason reason)
{
	int			save_errno = errno;

	
	if (!proc_exit_inprogress)
	{
		RecoveryConflictReason = reason;
		switch (reason)
		{
			case PROCSIG_RECOVERY_CONFLICT_STARTUP_DEADLOCK:

				
				if (!IsWaitingForLock())
					return;

				
				

			case PROCSIG_RECOVERY_CONFLICT_BUFFERPIN:

				
				if (!HoldingBufferPinThatDelaysRecovery())
					return;

				MyProc->recoveryConflictPending = true;

				
				

			case PROCSIG_RECOVERY_CONFLICT_LOCK:
			case PROCSIG_RECOVERY_CONFLICT_TABLESPACE:
			case PROCSIG_RECOVERY_CONFLICT_SNAPSHOT:

				
				if (!IsTransactionOrTransactionBlock())
					return;

				
				if (!IsSubTransaction())
				{
					
					if (IsAbortedTransactionBlockState())
						return;

					RecoveryConflictPending = true;
					QueryCancelPending = true;
					InterruptPending = true;
					break;
				}

				
				

			case PROCSIG_RECOVERY_CONFLICT_DATABASE:
				RecoveryConflictPending = true;
				ProcDiePending = true;
				InterruptPending = true;
				break;

			default:
				elog(FATAL, "unrecognized conflict mode: %d", (int) reason);
		}

		Assert(RecoveryConflictPending && (QueryCancelPending || ProcDiePending));

		
		if (reason == PROCSIG_RECOVERY_CONFLICT_DATABASE)
			RecoveryConflictRetryable = false;
	}

	
	SetLatch(MyLatch);

	errno = save_errno;
}


void ProcessInterrupts(const char* filename, int lineno)
{
	
	if (InterruptHoldoffCount != 0 || CritSectionCount != 0)
		return;
	InterruptPending = false;

	if (ProcDiePending)
	{
		ProcDiePending = false;
		QueryCancelPending = false; 
		LockErrorCleanup();
		
		if (ClientAuthInProgress && whereToSendOutput == DestRemote)
			whereToSendOutput = DestNone;
		if (ClientAuthInProgress)
			ereport(FATAL, (errcode(ERRCODE_QUERY_CANCELED), errmsg("canceling authentication due to timeout")));

		else if (IsAutoVacuumWorkerProcess())
			ereport(FATAL, (errcode(ERRCODE_ADMIN_SHUTDOWN), errmsg("terminating autovacuum process due to administrator command")));

		else if (IsLogicalWorker())
			ereport(FATAL, (errcode(ERRCODE_ADMIN_SHUTDOWN), errmsg("terminating logical replication worker due to administrator command")));

		else if (IsLogicalLauncher())
		{
			ereport(DEBUG1, (errmsg("logical replication launcher shutting down")));

			
			proc_exit(1);
		}
		else if (RecoveryConflictPending && RecoveryConflictRetryable)
		{
			pgstat_report_recovery_conflict(RecoveryConflictReason);
			ereport(FATAL, (errcode(ERRCODE_T_R_SERIALIZATION_FAILURE), errmsg("terminating connection due to conflict with recovery"), errdetail_recovery_conflict()));


		}
		else if (RecoveryConflictPending)
		{
			
			Assert(RecoveryConflictReason == PROCSIG_RECOVERY_CONFLICT_DATABASE);
			pgstat_report_recovery_conflict(RecoveryConflictReason);
			ereport(FATAL, (errcode(ERRCODE_DATABASE_DROPPED), errmsg("terminating connection due to conflict with recovery"), errdetail_recovery_conflict()));


		}
		else {
			if (HasCancelMessage())
			{
				char   *buffer = palloc0(MAX_CANCEL_MSG);

				GetCancelMessage(&buffer, MAX_CANCEL_MSG);
				ereport(FATAL, (errcode(ERRCODE_ADMIN_SHUTDOWN), errmsg("terminating connection due to administrator command: \"%s\"", buffer)));


			}
			else ereport(FATAL, (errcode(ERRCODE_ADMIN_SHUTDOWN), errmsg("terminating connection due to administrator command")));


		}
	}
	if (ClientConnectionLost)
	{
		QueryCancelPending = false; 
		LockErrorCleanup();
		
		whereToSendOutput = DestNone;
		ereport(FATAL, (errcode(ERRCODE_CONNECTION_FAILURE), errmsg("connection to client lost")));

	}

	
	if (RecoveryConflictPending && DoingCommandRead)
	{
		QueryCancelPending = false; 
		RecoveryConflictPending = false;
		LockErrorCleanup();
		pgstat_report_recovery_conflict(RecoveryConflictReason);
		ereport(FATAL, (errcode(ERRCODE_T_R_SERIALIZATION_FAILURE), errmsg("terminating connection due to conflict with recovery"), errdetail_recovery_conflict(), errhint("In a moment you should be able to reconnect to the" " database and repeat your command.")));




	}

	
	if (QueryCancelPending && QueryCancelHoldoffCount != 0)
	{
		
		InterruptPending = true;
	}
	else if (QueryCancelPending)
	{
		bool		lock_timeout_occurred;
		bool		stmt_timeout_occurred;

		elog(LOG,"Process interrupt for 'query cancel pending' (%s:%d)", filename, lineno);

		QueryCancelPending = false;

		
		lock_timeout_occurred = get_timeout_indicator(LOCK_TIMEOUT, true);
		stmt_timeout_occurred = get_timeout_indicator(STATEMENT_TIMEOUT, true);

		
		if (lock_timeout_occurred && stmt_timeout_occurred && get_timeout_finish_time(STATEMENT_TIMEOUT) < get_timeout_finish_time(LOCK_TIMEOUT))
			lock_timeout_occurred = false;	

		if (lock_timeout_occurred)
		{
			LockErrorCleanup();
			ereport(ERROR, (errcode(ERRCODE_LOCK_NOT_AVAILABLE), errmsg("canceling statement due to lock timeout")));

		}
		if (stmt_timeout_occurred)
		{
			LockErrorCleanup();
			ereport(ERROR, (errcode(ERRCODE_QUERY_CANCELED), errmsg("canceling statement due to statement timeout")));

		}
		if (IsAutoVacuumWorkerProcess())
		{
			LockErrorCleanup();
			ereport(ERROR, (errcode(ERRCODE_QUERY_CANCELED), errmsg("canceling autovacuum task")));

		}
		if (RecoveryConflictPending)
		{
			RecoveryConflictPending = false;
			LockErrorCleanup();
			pgstat_report_recovery_conflict(RecoveryConflictReason);
			ereport(ERROR, (errcode(ERRCODE_T_R_SERIALIZATION_FAILURE), errmsg("canceling statement due to conflict with recovery"), errdetail_recovery_conflict()));


		}

		
		if (!DoingCommandRead)
		{
			LockErrorCleanup();

			if (Gp_role == GP_ROLE_EXECUTE)
				ereport(ERROR, (errcode(ERRCODE_GP_OPERATION_CANCELED), errmsg("canceling MPP operation")));

			else if (HasCancelMessage())
			{
				char   *buffer = palloc0(MAX_CANCEL_MSG);

				GetCancelMessage(&buffer, MAX_CANCEL_MSG);
				ereport(ERROR, (errcode(ERRCODE_QUERY_CANCELED), errmsg("canceling statement due to user request: \"%s\"", buffer)));


			}
			else ereport(ERROR, (errcode(ERRCODE_QUERY_CANCELED), errmsg("canceling statement due to user request")));


		}
	}

	if (IdleInTransactionSessionTimeoutPending)
	{
		
		if (IdleInTransactionSessionTimeout > 0)
			ereport(FATAL, (errcode(ERRCODE_IDLE_IN_TRANSACTION_SESSION_TIMEOUT), errmsg("terminating connection due to idle-in-transaction timeout")));

		else IdleInTransactionSessionTimeoutPending = false;

	}

	if (ParallelMessagePending)
		HandleParallelMessages();
}














static __inline__ char * ia64_get_bsp(void)
{
	char	   *ret;

	
	__asm__ __volatile__( ";;\n" "	mov	%0=ar.bsp	\n" :						 "=r"(ret));



	return ret;
}





pg_stack_base_t set_stack_base(void)
{
	char		stack_base;
	pg_stack_base_t old;


	old.stack_base_ptr = stack_base_ptr;
	old.register_stack_base_ptr = register_stack_base_ptr;

	old = stack_base_ptr;


	
	stack_base_ptr = &stack_base;

	register_stack_base_ptr = ia64_get_bsp();


	return old;
}


void restore_stack_base(pg_stack_base_t base)
{

	stack_base_ptr = base.stack_base_ptr;
	register_stack_base_ptr = base.register_stack_base_ptr;

	stack_base_ptr = base;

}


void check_stack_depth(void)
{
	if (stack_is_too_deep())
	{
		ereport(ERROR, (errcode(ERRCODE_STATEMENT_TOO_COMPLEX), errmsg("stack depth limit exceeded"), errhint("Increase the configuration parameter \"max_stack_depth\" (currently %dkB), " "after ensuring the platform's stack depth limit is adequate.", max_stack_depth)));




	}
}

bool stack_is_too_deep(void)
{
	char		stack_top_loc;
	long		stack_depth;

	
	stack_depth = (long) (stack_base_ptr - &stack_top_loc);

	
	if (stack_depth < 0)
		stack_depth = -stack_depth;

	
	if (stack_depth > max_stack_depth_bytes && stack_base_ptr != NULL)
		return true;

	

	stack_depth = (long) (ia64_get_bsp() - register_stack_base_ptr);

	if (stack_depth > max_stack_depth_bytes && register_stack_base_ptr != NULL)
		return true;


	return false;
}


bool check_max_stack_depth(int *newval, void **extra, GucSource source)
{
	long		newval_bytes = *newval * 1024L;
	long		stack_rlimit = get_stack_depth_rlimit();

	if (stack_rlimit > 0 && newval_bytes > stack_rlimit - STACK_DEPTH_SLOP)
	{
		GUC_check_errdetail("\"max_stack_depth\" must not exceed %ldkB.", (stack_rlimit - STACK_DEPTH_SLOP) / 1024L);
		GUC_check_errhint("Increase the platform's stack depth limit via \"ulimit -s\" or local equivalent.");
		return false;
	}
	return true;
}


void assign_max_stack_depth(int newval, void *extra)
{
	long		newval_bytes = newval * 1024L;

	max_stack_depth_bytes = newval_bytes;
}



void set_debug_options(int debug_flag, GucContext context, GucSource source)
{
	if (debug_flag > 0)
	{
		char		debugstr[64];

		sprintf(debugstr, "debug%d", debug_flag);
		SetConfigOption("log_min_messages", debugstr, context, source);
	}
	else SetConfigOption("log_min_messages", "notice", context, source);

	if (debug_flag >= 1 && context == PGC_POSTMASTER)
	{
		SetConfigOption("log_connections", "true", context, source);
		SetConfigOption("log_disconnections", "true", context, source);
	}
	if (debug_flag >= 2)
		SetConfigOption("log_statement", "all", context, source);
	if (debug_flag >= 3)
		SetConfigOption("debug_print_parse", "true", context, source);
	if (debug_flag >= 4)
		SetConfigOption("debug_print_plan", "true", context, source);
	if (debug_flag >= 5)
		SetConfigOption("debug_print_rewritten", "true", context, source);
}


bool set_plan_disabling_options(const char *arg, GucContext context, GucSource source)
{
	const char *tmp = NULL;

	switch (arg[0])
	{
		case 's':				
			tmp = "enable_seqscan";
			break;
		case 'i':				
			tmp = "enable_indexscan";
			break;
		case 'o':				
			tmp = "enable_indexonlyscan";
			break;
		case 'b':				
			tmp = "enable_bitmapscan";
			break;
		case 't':				
			tmp = "enable_tidscan";
			break;
		case 'n':				
			tmp = "enable_nestloop";
			break;
		case 'm':				
			tmp = "enable_mergejoin";
			break;
		case 'h':				
			tmp = "enable_hashjoin";
			break;
	}
	if (tmp)
	{
		SetConfigOption(tmp, "false", context, source);
		return true;
	}
	else return false;
}


const char * get_stats_option_name(const char *arg)
{
	switch (arg[0])
	{
		case 'p':
			if (optarg[1] == 'a')	
				return "log_parser_stats";
			else if (optarg[1] == 'l')	
				return "log_planner_stats";
			break;

		case 'e':				
			return "log_executor_stats";
			break;
	}

	return NULL;
}


void process_postgres_switches(int argc, char *argv[], GucContext ctx, const char **dbname)

{
	bool		secure = (ctx == PGC_POSTMASTER);
	int			errs = 0;
	GucSource	gucsource;
	int			flag;

	if (secure)
	{
		gucsource = PGC_S_ARGV; 

		
		if (argc > 1 && strcmp(argv[1], "--single") == 0)
		{
			argv++;
			argc--;
		}
	}
	else {
		gucsource = PGC_S_CLIENT;	
	}



	
	opterr = 0;


	
	while ((flag = getopt(argc, argv, "B:bc:C:D:d:EeFf:h:ijk:lMm:N:nOo:Pp:r:S:sTt:v:W:-:")) != -1)
	{
		switch (flag)
		{
			case 'B':
				SetConfigOption("shared_buffers", optarg, ctx, gucsource);
				break;

			case 'b':
				
				if (secure)
					IsBinaryUpgrade = true;
				break;

			case 'C':
				
				break;

			case 'D':
				if (secure)
					userDoption = strdup(optarg);
				break;

			case 'd':
				set_debug_options(atoi(optarg), ctx, gucsource);
				break;

			case 'E':
				if (secure)
					EchoQuery = true;
				break;

			case 'e':
				SetConfigOption("datestyle", "euro", ctx, gucsource);
				break;

			case 'F':
				SetConfigOption("fsync", "false", ctx, gucsource);
				break;

			case 'f':
				if (!set_plan_disabling_options(optarg, ctx, gucsource))
					errs++;
				break;

			case 'h':
				SetConfigOption("listen_addresses", optarg, ctx, gucsource);
				break;

			case 'i':
				SetConfigOption("listen_addresses", "*", ctx, gucsource);
				break;

			case 'j':
				if (secure)
					UseSemiNewlineNewline = true;
				break;

			case 'k':
				SetConfigOption("unix_socket_directories", optarg, ctx, gucsource);
				break;

			case 'l':
				SetConfigOption("ssl", "true", ctx, gucsource);
				break;

			case 'M':
				
				if (secure)
					ConvertMasterDataDirToSegment = true;
				break;

			case 'm':
				
				SetConfigOption("maintenance_mode",         "true", ctx, gucsource);
				SetConfigOption("allow_segment_DML",        "true", ctx, gucsource);
				SetConfigOption("allow_system_table_mods",  "true",  ctx, gucsource);
				break;

			case 'N':
				SetConfigOption("max_connections", optarg, ctx, gucsource);
				break;

			case 'n':
				
				break;

			case 'O':
				
				SetConfigOption("allow_system_table_mods", "true", ctx, gucsource);
				break;

			case 'o':
				errs++;
				break;

			case 'P':
				SetConfigOption("ignore_system_indexes", "true", ctx, gucsource);
				break;

			case 'p':
				SetConfigOption("port", optarg, ctx, gucsource);
				break;

			case 'r':
				
				if (secure)
					strlcpy(OutputFileName, optarg, MAXPGPATH);
				break;

			case 'S':
				SetConfigOption("work_mem", optarg, ctx, gucsource);
				break;

			case 's':
				SetConfigOption("log_statement_stats", "true", ctx, gucsource);
				break;

			case 'T':
				
				break;

			case 't':
				{
					const char *tmp = get_stats_option_name(optarg);

					if (tmp)
						SetConfigOption(tmp, "true", ctx, gucsource);
					else errs++;
					break;
				}

			case 'v':

				
				if (secure)
					FrontendProtocol = (ProtocolVersion) atoi(optarg);
				break;

			case 'W':
				SetConfigOption("post_auth_delay", optarg, ctx, gucsource);
				break;

			case 'c':
			case '-':
				{
					char	   *name, *value;

					ParseLongOption(optarg, &name, &value);
					if (!value)
					{
						if (flag == '-')
							ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("--%s requires a value", optarg)));


						else ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("-c %s requires a value", optarg)));



					}
					SetConfigOption(name, value, ctx, gucsource);
					free(name);
					if (value)
						free(value);
					break;
				}

			default:
				errs++;
				break;
		}

		if (errs)
			break;
	}

	
	if (!errs && dbname && *dbname == NULL && argc - optind >= 1)
		*dbname = strdup(argv[optind++]);

	if (errs || argc != optind)
	{
		if (errs)
			optind--;			

		
		if (IsUnderPostmaster)
			ereport(FATAL, errcode(ERRCODE_SYNTAX_ERROR), errmsg("invalid command-line argument for server process: %s", argv[optind]), errhint("Try \"%s --help\" for more information.", progname));


		else ereport(FATAL, errcode(ERRCODE_SYNTAX_ERROR), errmsg("%s: invalid command-line argument: %s", progname, argv[optind]), errhint("Try \"%s --help\" for more information.", progname));




	}

	
	optind = 1;

	optreset = 1;				

}


static void check_forbidden_in_gpdb_handlers(char firstchar)
{
	if (am_ftshandler || IsFaultHandler)
	{
		switch (firstchar)
		{
			case 'Q':
			case 'X':
			case EOF:
				return;
			default:
				ereport(ERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("protocol '%c' is not supported in a GPDB message handler connection", firstchar)));


		}
	}
}



void PostgresMain(int argc, char *argv[], const char *dbname, const char *username)


{
	int			firstchar;
	StringInfoData input_message;
	sigjmp_buf	local_sigjmp_buf;
	volatile bool send_ready_for_query = true;
	bool		disable_idle_in_transaction_timeout = false;

	
	main_tid = pthread_self();

	
	if (!IsUnderPostmaster)
		InitStandaloneProcess(argv[0]);


	PostmasterPriority = getpriority(PRIO_PROCESS, 0);


	set_ps_display("startup", false);

	SetProcessingMode(InitProcessing);

	
	EchoQuery = false;

	if (!IsUnderPostmaster)
		InitializeGUCOptions();

	
	process_postgres_switches(argc, argv, PGC_POSTMASTER, &dbname);

	
	if (dbname == NULL)
	{
		dbname = username;
		if (dbname == NULL)
			ereport(FATAL, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("%s: no database nor user name specified", progname)));


	}

	
	if (!IsUnderPostmaster)
	{
		if (!SelectConfigFiles(userDoption, progname))
			proc_exit(1);

        
	    PgStartTime = GetCurrentTimestamp();
	}

	
	if (am_walsender)
		WalSndSignals();
	else {
		pqsignal(SIGHUP, PostgresSigHupHandler);	
		pqsignal(SIGINT, StatementCancelHandler);	
		pqsignal(SIGTERM, die); 

		
		if (IsUnderPostmaster)
			pqsignal(SIGQUIT, quickdie);	
		else pqsignal(SIGQUIT, die);
		InitializeTimeouts();	

		
		pqsignal(SIGPIPE, SIG_IGN);
		pqsignal(SIGUSR1, procsignal_sigusr1_handler);
		pqsignal(SIGUSR2, SIG_IGN);
		pqsignal(SIGFPE, FloatExceptionHandler);

		
		pqsignal(SIGCHLD, SIG_DFL); 


		pqsignal(SIGILL, CdbProgramErrorHandler);


		pqsignal(SIGSEGV, CdbProgramErrorHandler);


		pqsignal(SIGBUS, CdbProgramErrorHandler);


	}

	pqinitmask();

	if (IsUnderPostmaster)
	{
		
		sigdelset(&BlockSig, SIGQUIT);
	}

	PG_SETMASK(&BlockSig);		

	if (!IsUnderPostmaster)
	{
		
		checkDataDir();

		
		ChangeToDataDir();

		
		CreateDataDirLockFile(false);

		
		LocalProcessControlFile(false);

		
		InitializeMaxBackends();
	}

	
	BaseInit();

	

	if (!IsUnderPostmaster)
		InitProcess();

	InitProcess();


	
	PG_SETMASK(&UnBlockSig);

	
	InitPostgres(dbname, InvalidOid, username, InvalidOid, NULL, false);

	
	if (PostmasterContext)
	{
		MemoryContextDelete(PostmasterContext);
		PostmasterContext = NULL;
	}

	SetProcessingMode(NormalProcessing);

	
	BeginReportingGUCOptions();

	
	if (IsUnderPostmaster && Log_disconnections)
		on_proc_exit(log_disconnections, 0);

	
	if (am_walsender)
		InitWalSender();

	
	process_session_preload_libraries();

	
	DtxContextInfo_Reset(&QEDtxContextInfo);

	
	if (whereToSendOutput == DestRemote)
	{
		StringInfoData buf;

		pq_beginmessage(&buf, 'K');
		pq_sendint32(&buf, (int32) MyProcPid);
		pq_sendint32(&buf, (int32) MyCancelKey);
		pq_endmessage(&buf);
		
	}

	
	if (!(am_ftshandler || IsFaultHandler) && Gp_role == GP_ROLE_EXECUTE)
	{

		if (SIMPLE_FAULT_INJECTOR("send_qe_details_init_backend") != FaultInjectorTypeSkip)

			sendQEDetails();
	}

	
	if (whereToSendOutput == DestDebug)
		printf("\nPostgreSQL stand-alone backend %s\n", PG_VERSION);

	
	MessageContext = AllocSetContextCreate(TopMemoryContext, "MessageContext", ALLOCSET_DEFAULT_SIZES);


	
	row_description_context = AllocSetContextCreate(TopMemoryContext, "RowDescriptionContext", ALLOCSET_DEFAULT_SIZES);

	MemoryContextSwitchTo(row_description_context);
	initStringInfo(&row_description_buf);
	MemoryContextSwitchTo(TopMemoryContext);


	
	if (sigsetjmp(local_sigjmp_buf, 1) != 0)
	{
		

		
		error_context_stack = NULL;

		
		HOLD_INTERRUPTS();

		
		disable_all_timeouts(false);
		QueryCancelPending = false; 
		QueryFinishPending = false;
		stmt_timeout_active = false;

		
		DoingCommandRead = false;
		DisableClientWaitTimeoutInterrupt();

		
		pq_comm_reset();

		
		EmitErrorReport();

		
		if (debug_query_string != NULL)
		{
			elog_exception_statement(debug_query_string);
			debug_query_string = NULL;
		}

		
		AbortCurrentTransaction();

		if (am_walsender)
			WalSndErrorCleanup();

		PortalErrorCleanup();
		SPICleanup();

		
		if (MyReplicationSlot != NULL)
			ReplicationSlotRelease();

		
		ReplicationSlotCleanup();

		jit_reset_after_error();

		
		MemoryContextSwitchTo(TopMemoryContext);
		FlushErrorState();

		
		if (doing_extended_query_message)
			ignore_till_sync = true;

		
		xact_started = false;

		
		creating_extension = false;
		CurrentExtensionObject = InvalidOid;

		
		RunawayCleaner_RunawayCleanupDoneForProcess(false );

		
		if (pq_is_reading_msg())
			ereport(FATAL, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("terminating connection because protocol synchronization was lost")));


		
		RESUME_INTERRUPTS();
	}

	
	PG_exception_stack = &local_sigjmp_buf;

	if (!ignore_till_sync)
		send_ready_for_query = true;	

	

	for (;;)
	{
		
		doing_extended_query_message = false;

		
		MemoryContextSwitchTo(MessageContext);
		MemoryContextResetAndDeleteChildren(MessageContext);
		VmemTracker_ResetMaxVmemReserved();
		VmemTracker_ResetWaiver();

		initStringInfo(&input_message);

        
        currentSliceId = UNSET_SLICE_ID;
        if (Gp_role == GP_ROLE_EXECUTE)
            gp_command_count = 0;

		
		IdleTracker_DeactivateProcess();

		
		InvalidateCatalogSnapshotConditionally();

		
		InvalidateCatalogSnapshotConditionally();

		
		if (send_ready_for_query)
		{
			if (IsAbortedTransactionBlockState())
			{
				set_ps_display("idle in transaction (aborted)", false);
				pgstat_report_activity(STATE_IDLEINTRANSACTION_ABORTED, NULL);

				
				if (IdleInTransactionSessionTimeout > 0)
				{
					disable_idle_in_transaction_timeout = true;
					enable_timeout_after(IDLE_IN_TRANSACTION_SESSION_TIMEOUT, IdleInTransactionSessionTimeout);
				}
			}
			else if (IsTransactionOrTransactionBlock())
			{
				set_ps_display("idle in transaction", false);
				pgstat_report_activity(STATE_IDLEINTRANSACTION, NULL);

				
				if (IdleInTransactionSessionTimeout > 0)
				{
					disable_idle_in_transaction_timeout = true;
					enable_timeout_after(IDLE_IN_TRANSACTION_SESSION_TIMEOUT, IdleInTransactionSessionTimeout);
				}
			}
			else {
				ProcessCompletedNotifies();
				pgstat_report_stat(false);
				pgstat_report_queuestat();

				set_ps_display("idle", false);
				pgstat_report_activity(STATE_IDLE, NULL);
			}

			ReadyForQuery(whereToSendOutput);
			send_ready_for_query = false;
		}

		
		DoingCommandRead = true;

		
		if (Gp_role == GP_ROLE_DISPATCH)
		{
			GpDropTempTables();
			StartIdleResourceCleanupTimers();
		}

		
		firstchar = ReadCommand(&input_message);

		if (Gp_role == GP_ROLE_DISPATCH)
			CancelIdleResourceCleanupTimers();

		
		QueryFinishPending = false;

		IdleTracker_ActivateProcess();

		
		CHECK_FOR_INTERRUPTS();
		DoingCommandRead = false;

		
		if (disable_idle_in_transaction_timeout)
		{
			disable_timeout(IDLE_IN_TRANSACTION_SESSION_TIMEOUT, false);
			disable_idle_in_transaction_timeout = false;
		}

		
		if (ConfigReloadPending)
		{
			ConfigReloadPending = false;
			ProcessConfigFile(PGC_SIGHUP);
		}

		
		if (ignore_till_sync && firstchar != EOF)
			continue;

		
		if(Gp_role == GP_ROLE_DISPATCH && gp_guc_restore_list)
			restore_guc_to_QE();


		
		ereport((Debug_print_full_dtm ? LOG : DEBUG5), (errmsg_internal("First char: '%d'; gp_role = '%s'.", firstchar, role_to_string(Gp_role))));

		check_forbidden_in_gpdb_handlers(firstchar);

		switch (firstchar)
		{
			case 'Q':			
				{
					const char *query_string;

                    elog(DEBUG1, "Message type %c received by from libpq, len = %d", firstchar, input_message.len); 

					
					SetCurrentStatementStartTimestamp();
                    query_string = pq_getmsgstring(&input_message);
					pq_getmsgend(&input_message);

					elog((Debug_print_full_dtm ? LOG : DEBUG5), "Simple query stmt: %s.",query_string);

					if (am_walsender)
					{
						if (!exec_replication_command(query_string))
							exec_simple_query(query_string);
					}
					else if (am_ftshandler)
						HandleFtsMessage(query_string);
					else if (IsFaultHandler)
						HandleFaultMessage(query_string);
					else exec_simple_query(query_string);

					send_ready_for_query = true;
				}
				break;
            case 'M': 
				{
					
					const char *query_string = pstrdup("");

					const char *serializedDtxContextInfo = NULL;
					const char *serializedPlantree = NULL;
					const char *serializedQueryDispatchDesc = NULL;
					const char *resgroupInfoBuf = NULL;

					int query_string_len = 0;
					int serializedDtxContextInfolen = 0;
					int serializedPlantreelen = 0;
					int serializedQueryDispatchDesclen = 0;
					int resgroupInfoLen = 0;
					TimestampTz statementStart;
					Oid suid;
					Oid ouid;
					Oid cuid;

					if (Gp_role != GP_ROLE_EXECUTE)
						ereport(ERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("MPP protocol messages are only supported in QD - QE connections")));

					
					check_function_bodies=false;

					
 					SetCurrentStatementStartTimestamp();

					
					gp_command_count = pq_getmsgint(&input_message, 4);

					elog(DEBUG1, "Message type %c received by from libpq, len = %d", firstchar, input_message.len); 

					
					suid = pq_getmsgint(&input_message, 4);
					ouid = pq_getmsgint(&input_message, 4);
					cuid = pq_getmsgint(&input_message, 4);

					statementStart = pq_getmsgint64(&input_message);
					query_string_len = pq_getmsgint(&input_message, 4);
					serializedPlantreelen = pq_getmsgint(&input_message, 4);
					serializedQueryDispatchDesclen = pq_getmsgint(&input_message, 4);
					serializedDtxContextInfolen = pq_getmsgint(&input_message, 4);

					
					if (serializedDtxContextInfolen == 0)
						serializedDtxContextInfo = NULL;
					else serializedDtxContextInfo = pq_getmsgbytes(&input_message,serializedDtxContextInfolen);

					DtxContextInfo_Deserialize(serializedDtxContextInfo, serializedDtxContextInfolen, &TempDtxContextInfo);
					if (TempDtxContextInfo.distributedXid != InvalidDistributedTransactionId && !IS_QUERY_DISPATCHER())
					{
						
						SpinLockAcquire(shmGxidGenLock);
						if (TempDtxContextInfo.distributedXid > ShmemVariableCache->nextGxid)
							ShmemVariableCache->nextGxid = TempDtxContextInfo.distributedXid;
						SpinLockRelease(shmGxidGenLock);
					}

					
					if (query_string_len > 0)
						query_string = pq_getmsgbytes(&input_message,query_string_len);

					if (serializedPlantreelen > 0)
						serializedPlantree = pq_getmsgbytes(&input_message,serializedPlantreelen);

					if (serializedQueryDispatchDesclen > 0)
						serializedQueryDispatchDesc = pq_getmsgbytes(&input_message,serializedQueryDispatchDesclen);

					
					numsegmentsFromQD = pq_getmsgint(&input_message, 4);

					resgroupInfoLen = pq_getmsgint(&input_message, 4);
					if (resgroupInfoLen > 0)
						resgroupInfoBuf = pq_getmsgbytes(&input_message, resgroupInfoLen);

					pq_getmsgend(&input_message);

					elog((Debug_print_full_dtm ? LOG : DEBUG5), "MPP dispatched stmt from QD: %s.",query_string);

					if (IsResGroupActivated() && resgroupInfoLen > 0)
						SwitchResGroupOnSegment(resgroupInfoBuf, resgroupInfoLen);

					
					if (suid > 0)
						SetSessionUserId(suid, false); 

					if (ouid > 0 && ouid != GetSessionUserId())
						SetCurrentRoleId(ouid, false); 

					setupQEDtxContext(&TempDtxContextInfo);

					if (cuid > 0)
						SetUserIdAndContext(cuid, false); 

					if (serializedPlantreelen==0)
					{
						if (strncmp(query_string, "BEGIN", 5) == 0)
						{
							CommandDest dest = whereToSendOutput;

							
							elog((Debug_print_full_dtm ? LOG : DEBUG5), "PostgresMain explicit %s", query_string);

							
							pgstat_report_activity(STATE_RUNNING, "BEGIN");

							set_ps_display("BEGIN", false);

							BeginCommand("BEGIN", dest);

							EndCommand("BEGIN", dest);

						}
						else {
							exec_simple_query(query_string);
						}
					}
					else exec_mpp_query(query_string, serializedPlantree, serializedPlantreelen, serializedQueryDispatchDesc, serializedQueryDispatchDesclen);



					SetUserIdAndContext(GetOuterUserId(), false);

					send_ready_for_query = true;
				}
				break;

            case 'T': 
				{
					DtxProtocolCommand dtxProtocolCommand;
					int loggingStrLen;
					const char *loggingStr;
					int gidLen;
					const char *gid;
					int serializedDtxContextInfolen;
					const char *serializedDtxContextInfo;

					if (Gp_role != GP_ROLE_EXECUTE)
						ereport(ERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("MPP protocol messages are only supported in QD - QE connections")));


					elog(DEBUG1, "Message type %c received by from libpq, len = %d", firstchar, input_message.len); 

					
					dtxProtocolCommand = (DtxProtocolCommand) pq_getmsgint(&input_message, 4);

					
					loggingStrLen = pq_getmsgint(&input_message, 4);

					
					loggingStr = pq_getmsgbytes(&input_message,loggingStrLen);

					
					gidLen = pq_getmsgint(&input_message, 4);

					
					gid = pq_getmsgbytes(&input_message,gidLen);

					serializedDtxContextInfolen = pq_getmsgint(&input_message, 4);

					
					if (serializedDtxContextInfolen == 0)
						serializedDtxContextInfo = NULL;
					else serializedDtxContextInfo = pq_getmsgbytes(&input_message,serializedDtxContextInfolen);

					DtxContextInfo_Deserialize(serializedDtxContextInfo, serializedDtxContextInfolen, &TempDtxContextInfo);

					pq_getmsgend(&input_message);

					exec_mpp_dtx_protocol_command(dtxProtocolCommand, loggingStr, gid, &TempDtxContextInfo);

					send_ready_for_query = true;
            	}
				break;

			case 'P':			
				{
					const char *stmt_name;
					const char *query_string;
					int			numParams;
					Oid		   *paramTypes = NULL;

					forbidden_in_wal_sender(firstchar);

					
					SetCurrentStatementStartTimestamp();

					stmt_name = pq_getmsgstring(&input_message);
					query_string = pq_getmsgstring(&input_message);
					numParams = pq_getmsgint(&input_message, 2);
					if (numParams > 0)
					{
						paramTypes = (Oid *) palloc(numParams * sizeof(Oid));
						for (int i = 0; i < numParams; i++)
							paramTypes[i] = pq_getmsgint(&input_message, 4);
					}
					pq_getmsgend(&input_message);

					elog((Debug_print_full_dtm ? LOG : DEBUG5), "Parse: %s.",query_string);

					exec_parse_message(query_string, stmt_name, paramTypes, numParams);
				}
				break;

			case 'B':			
				forbidden_in_wal_sender(firstchar);

				
				SetCurrentStatementStartTimestamp();

				
				exec_bind_message(&input_message);
				break;

			case 'E':			
				{
					const char *portal_name;
					int64		max_rows;

					forbidden_in_wal_sender(firstchar);

					
					SetCurrentStatementStartTimestamp();

					portal_name = pq_getmsgstring(&input_message);

					 
					max_rows = (int64)pq_getmsgint(&input_message, 4);
					pq_getmsgend(&input_message);

					elog((Debug_print_full_dtm ? LOG : DEBUG5), "Execute: %s.",portal_name);

					exec_execute_message(portal_name, max_rows);
				}
				break;

			case 'F':			
				forbidden_in_wal_sender(firstchar);

				
				SetCurrentStatementStartTimestamp();

				
				pgstat_report_activity(STATE_FASTPATH, NULL);
				set_ps_display("<FASTPATH>", false);

				elog((Debug_print_full_dtm ? LOG : DEBUG5), "Fast path function call.");

				
				start_xact_command();

				

				
				MemoryContextSwitchTo(MessageContext);

				HandleFunctionRequest(&input_message);

				
				finish_xact_command();

				send_ready_for_query = true;
				break;

			case 'C':			
				{
					int			close_type;
					const char *close_target;

					forbidden_in_wal_sender(firstchar);

					close_type = pq_getmsgbyte(&input_message);
					close_target = pq_getmsgstring(&input_message);
					pq_getmsgend(&input_message);

					switch (close_type)
					{
						case 'S':
							if (close_target[0] != '\0')
								DropPreparedStatement(close_target, false);
							else {
								
								drop_unnamed_stmt();
							}
							break;
						case 'P':
							{
								Portal		portal;

								portal = GetPortalByName(close_target);
								if (PortalIsValid(portal))
									PortalDrop(portal, false);
							}
							break;
						default:
							ereport(ERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("invalid CLOSE message subtype %d", close_type)));


							break;
					}

					if (whereToSendOutput == DestRemote)
						pq_putemptymessage('3');	
				}
				break;

			case 'D':			
				{
					int			describe_type;
					const char *describe_target;

					forbidden_in_wal_sender(firstchar);

					
					SetCurrentStatementStartTimestamp();

					describe_type = pq_getmsgbyte(&input_message);
					describe_target = pq_getmsgstring(&input_message);
					pq_getmsgend(&input_message);

					elog((Debug_print_full_dtm ? LOG : DEBUG5), "Describe: %s.", describe_target);

					switch (describe_type)
					{
						case 'S':
							exec_describe_statement_message(describe_target);
							break;
						case 'P':
							exec_describe_portal_message(describe_target);
							break;
						default:
							ereport(ERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("invalid DESCRIBE message subtype %d", describe_type)));


							break;
					}
				}
				break;

			case 'H':			
				pq_getmsgend(&input_message);
				if (whereToSendOutput == DestRemote)
					pq_flush();
				break;

			case 'S':			
				pq_getmsgend(&input_message);
				finish_xact_command();
				send_ready_for_query = true;
				break;

				
			case 'X':
			case EOF:

				
				if (whereToSendOutput == DestRemote)
					whereToSendOutput = DestNone;

				
				proc_exit(0);
				break;

			case 'd':			
			case 'c':			
			case 'f':			

				
				break;

			default:
				ereport(FATAL, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("invalid frontend message type %d", firstchar)));


		}
	}							
}


static void forbidden_in_wal_sender(char firstchar)
{
	if (am_walsender)
	{
		if (firstchar == 'F')
			ereport(ERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("fastpath function calls not supported in a replication connection")));

		else ereport(ERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("extended query protocol not supported in a replication connection")));


	}
}



long get_stack_depth_rlimit(void)
{

	static long val = 0;

	
	if (val == 0)
	{
		struct rlimit rlim;

		if (getrlimit(RLIMIT_STACK, &rlim) < 0)
			val = -1;
		else if (rlim.rlim_cur == RLIM_INFINITY)
			val = LONG_MAX;
		
		else if (rlim.rlim_cur >= LONG_MAX)
			val = LONG_MAX;
		else val = rlim.rlim_cur;
	}
	return val;


	
	return WIN32_STACK_RLIMIT;

	return -1;


}


static struct rusage Save_r;
static struct timeval Save_t;

void ResetUsage(void)
{
	getrusage(RUSAGE_SELF, &Save_r);
	gettimeofday(&Save_t, NULL);
}

void ShowUsage(const char *title)
{
	StringInfoData str;
	struct timeval user, sys;
	struct timeval elapse_t;
	struct rusage r;

	getrusage(RUSAGE_SELF, &r);
	gettimeofday(&elapse_t, NULL);
	memcpy((char *) &user, (char *) &r.ru_utime, sizeof(user));
	memcpy((char *) &sys, (char *) &r.ru_stime, sizeof(sys));
	if (elapse_t.tv_usec < Save_t.tv_usec)
	{
		elapse_t.tv_sec--;
		elapse_t.tv_usec += 1000000;
	}
	if (r.ru_utime.tv_usec < Save_r.ru_utime.tv_usec)
	{
		r.ru_utime.tv_sec--;
		r.ru_utime.tv_usec += 1000000;
	}
	if (r.ru_stime.tv_usec < Save_r.ru_stime.tv_usec)
	{
		r.ru_stime.tv_sec--;
		r.ru_stime.tv_usec += 1000000;
	}

	
	initStringInfo(&str);

	appendStringInfoString(&str, "! system usage stats:\n");
	appendStringInfo(&str, "!\t%ld.%06ld s user, %ld.%06ld s system, %ld.%06ld s elapsed\n", (long) (r.ru_utime.tv_sec - Save_r.ru_utime.tv_sec), (long) (r.ru_utime.tv_usec - Save_r.ru_utime.tv_usec), (long) (r.ru_stime.tv_sec - Save_r.ru_stime.tv_sec), (long) (r.ru_stime.tv_usec - Save_r.ru_stime.tv_usec), (long) (elapse_t.tv_sec - Save_t.tv_sec), (long) (elapse_t.tv_usec - Save_t.tv_usec));






	appendStringInfo(&str, "!\t[%ld.%06ld s user, %ld.%06ld s system total]\n", (long) user.tv_sec, (long) user.tv_usec, (long) sys.tv_sec, (long) sys.tv_usec);





	appendStringInfo(&str, "!\t%ld kB max resident size\n",   r.ru_maxrss / 1024   r.ru_maxrss  );








	appendStringInfo(&str, "!\t%ld/%ld [%ld/%ld] filesystem blocks in/out\n", r.ru_inblock - Save_r.ru_inblock,  r.ru_oublock - Save_r.ru_oublock, r.ru_inblock, r.ru_oublock);




	appendStringInfo(&str, "!\t%ld/%ld [%ld/%ld] page faults/reclaims, %ld [%ld] swaps\n", r.ru_majflt - Save_r.ru_majflt, r.ru_minflt - Save_r.ru_minflt, r.ru_majflt, r.ru_minflt, r.ru_nswap - Save_r.ru_nswap, r.ru_nswap);





	appendStringInfo(&str, "!\t%ld [%ld] signals rcvd, %ld/%ld [%ld/%ld] messages rcvd/sent\n", r.ru_nsignals - Save_r.ru_nsignals, r.ru_nsignals, r.ru_msgrcv - Save_r.ru_msgrcv, r.ru_msgsnd - Save_r.ru_msgsnd, r.ru_msgrcv, r.ru_msgsnd);





	appendStringInfo(&str, "!\t%ld/%ld [%ld/%ld] voluntary/involuntary context switches\n", r.ru_nvcsw - Save_r.ru_nvcsw, r.ru_nivcsw - Save_r.ru_nivcsw, r.ru_nvcsw, r.ru_nivcsw);





	
	if (str.data[str.len - 1] == '\n')
		str.data[--str.len] = '\0';

	ereport(LOG, (errmsg_internal("%s", title), errdetail_internal("%s", str.data)));


	pfree(str.data);
}


static void log_disconnections(int code, Datum arg pg_attribute_unused())
{
	Port	   *port = MyProcPort;
	long		secs;
	int			usecs;
	int			msecs;
	int			hours, minutes, seconds;


	TimestampDifference(MyStartTimestamp, GetCurrentTimestamp(), &secs, &usecs);

	msecs = usecs / 1000;

	hours = secs / SECS_PER_HOUR;
	secs %= SECS_PER_HOUR;
	minutes = secs / SECS_PER_MINUTE;
	seconds = secs % SECS_PER_MINUTE;

	ereport(LOG, (errmsg("disconnection: session time: %d:%02d:%02d.%03d " "user=%s database=%s host=%s%s%s", hours, minutes, seconds, msecs, port->user_name, port->database_name, port->remote_host, port->remote_port[0] ? " port=" : "", port->remote_port)));




}


static void enable_statement_timeout(void)
{
	
	
	Assert(xact_started);

	if (StatementTimeout > 0)
	{
		if (!stmt_timeout_active)
		{
			enable_timeout_after(STATEMENT_TIMEOUT, StatementTimeout);
			stmt_timeout_active = true;
		}
	}
	else disable_timeout(STATEMENT_TIMEOUT, false);
}


static void disable_statement_timeout(void)
{
	if (stmt_timeout_active)
	{
		disable_timeout(STATEMENT_TIMEOUT, false);

		stmt_timeout_active = false;
	}
}


void enable_client_wait_timeout_interrupt(void)
{
	if (DoingCommandRead)
		EnableClientWaitTimeoutInterrupt();
}


void disable_client_wait_timeout_interrupt(void)
{
	if (DoingCommandRead)
		DisableClientWaitTimeoutInterrupt();
}
