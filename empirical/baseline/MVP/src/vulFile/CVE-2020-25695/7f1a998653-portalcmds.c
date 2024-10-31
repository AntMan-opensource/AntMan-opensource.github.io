






















void PerformCursorOpen(DeclareCursorStmt *cstmt, ParamListInfo params, const char *queryString, bool isTopLevel)

{
	Query	   *query = castNode(Query, cstmt->query);
	List	   *rewritten;
	PlannedStmt *plan;
	Portal		portal;
	MemoryContext oldContext;

	
	if (!cstmt->portalname || cstmt->portalname[0] == '\0')
		ereport(ERROR, (errcode(ERRCODE_INVALID_CURSOR_NAME), errmsg("invalid cursor name: must not be empty")));


	
	if (!(cstmt->options & CURSOR_OPT_HOLD))
		RequireTransactionBlock(isTopLevel, "DECLARE CURSOR");

	
	rewritten = QueryRewrite((Query *) copyObject(query));

	
	if (list_length(rewritten) != 1)
		elog(ERROR, "non-SELECT statement in DECLARE CURSOR");

	query = linitial_node(Query, rewritten);

	if (query->commandType != CMD_SELECT)
		elog(ERROR, "non-SELECT statement in DECLARE CURSOR");

	
	cstmt->options |= CURSOR_OPT_UPDATABLE;

	
	plan = pg_plan_query(query, cstmt->options, params);

	
	if (cstmt->options & CURSOR_OPT_SCROLL)
	{
		

		cstmt->options -= CURSOR_OPT_SCROLL;
	}

	cstmt->options |= CURSOR_OPT_NO_SCROLL;
	
	Assert(!(cstmt->options & CURSOR_OPT_SCROLL && cstmt->options & CURSOR_OPT_NO_SCROLL));

	
	portal = CreatePortal(cstmt->portalname, false, false);

	oldContext = MemoryContextSwitchTo(portal->portalContext);

	plan = copyObject(plan);

	queryString = pstrdup(queryString);

	PortalDefineQuery(portal, NULL, queryString, T_DeclareCursorStmt, "SELECT", list_make1(plan), NULL);






	portal->is_extended_query = true; 

	
	params = copyParamList(params);

	MemoryContextSwitchTo(oldContext);

	portal->cursorOptions = cstmt->options;

	

	portal->cursorOptions = cstmt->options;
	if (!(portal->cursorOptions & (CURSOR_OPT_SCROLL | CURSOR_OPT_NO_SCROLL)))
	{
		if (plan->rowMarks == NIL && ExecSupportsBackwardScan(plan->planTree))
			portal->cursorOptions |= CURSOR_OPT_SCROLL;
		else portal->cursorOptions |= CURSOR_OPT_NO_SCROLL;
	}


	
	PortalStart(portal, params, 0, GetActiveSnapshot(), NULL);

	Assert(portal->strategy == PORTAL_ONE_SELECT);

	
}


void PerformPortalFetch(FetchStmt *stmt, DestReceiver *dest, char *completionTag)


{
	Portal		portal;
	uint64		nprocessed;

	
	if (!stmt->portalname || stmt->portalname[0] == '\0')
		ereport(ERROR, (errcode(ERRCODE_INVALID_CURSOR_NAME), errmsg("invalid cursor name: must not be empty")));


	
	portal = GetPortalByName(stmt->portalname);
	if (!PortalIsValid(portal))
	{
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_CURSOR), errmsg("cursor \"%s\" does not exist", stmt->portalname)));

		return;					
	}

	
	if (stmt->ismove)
		dest = None_Receiver;

	
	nprocessed = PortalRunFetch(portal, stmt->direction, stmt->howMany, dest);



	
	if (completionTag)
		snprintf(completionTag, COMPLETION_TAG_BUFSIZE, "%s " UINT64_FORMAT, stmt->ismove ? "MOVE" : "FETCH", nprocessed);

}


void PerformPortalClose(const char *name)
{
	Portal		portal;

	
	if (name == NULL)
	{
		PortalHashTableDeleteAll();
		return;
	}

	
	if (name[0] == '\0')
		ereport(ERROR, (errcode(ERRCODE_INVALID_CURSOR_NAME), errmsg("invalid cursor name: must not be empty")));


	
	portal = GetPortalByName(name);
	if (!PortalIsValid(portal))
	{
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_CURSOR), errmsg("cursor \"%s\" does not exist", name)));

		return;					
	}

	
	PortalDrop(portal, false);
}


void PortalCleanup(Portal portal)
{
	QueryDesc  *queryDesc;

	
	AssertArg(PortalIsValid(portal));
	AssertArg(portal->cleanup == PortalCleanup);

	
	queryDesc = portal->queryDesc;
	if (queryDesc)
	{
		
		portal->queryDesc = NULL;

		if (portal->status != PORTAL_FAILED)
		{
			ResourceOwner saveResourceOwner;

			
			saveResourceOwner = CurrentResourceOwner;
			if (portal->resowner)
				CurrentResourceOwner = portal->resowner;

			
			queryDesc->estate->cancelUnfinished = true;

			ExecutorFinish(queryDesc);
			ExecutorEnd(queryDesc);
			FreeQueryDesc(queryDesc);

			CurrentResourceOwner = saveResourceOwner;
		}
	}

	
	if (IsResQueueLockedForPortal(portal))
	{
        ResUnLockPortal(portal);
	}

	
	if (gp_enable_resqueue_priority && Gp_role == GP_ROLE_DISPATCH && gp_session_id > -1)

	{
		BackoffBackendEntryExit();
	}
}


void PersistHoldablePortal(Portal portal)
{
	QueryDesc  *queryDesc = portal->queryDesc;
	Portal		saveActivePortal;
	ResourceOwner saveResourceOwner;
	MemoryContext savePortalContext;
	MemoryContext oldcxt;

	
	Assert(portal->createSubid != InvalidSubTransactionId);
	Assert(queryDesc != NULL);

	
	Assert(portal->holdContext != NULL);
	Assert(portal->holdStore != NULL);
	Assert(portal->holdSnapshot == NULL);

	
	oldcxt = MemoryContextSwitchTo(portal->holdContext);

	portal->tupDesc = CreateTupleDescCopy(portal->tupDesc);

	MemoryContextSwitchTo(oldcxt);

	
	MarkPortalActive(portal);

	
	saveActivePortal = ActivePortal;
	saveResourceOwner = CurrentResourceOwner;
	savePortalContext = PortalContext;
	PG_TRY();
	{
		ActivePortal = portal;
		if (portal->resowner)
			CurrentResourceOwner = portal->resowner;
		PortalContext = portal->portalContext;

		MemoryContextSwitchTo(PortalContext);

		PushActiveSnapshot(queryDesc->snapshot);

		
		
		if (Gp_role == GP_ROLE_UTILITY)
			ExecutorRewind(queryDesc);

		
		queryDesc->dest = CreateDestReceiver(DestTuplestore);
		SetTuplestoreDestReceiverParams(queryDesc->dest, portal->holdStore, portal->holdContext, true);



		
		ExecutorRun(queryDesc, ForwardScanDirection, 0L, false);

		queryDesc->dest->rDestroy(queryDesc->dest);
		queryDesc->dest = NULL;

		
		portal->queryDesc = NULL;	
		ExecutorFinish(queryDesc);
		ExecutorEnd(queryDesc);
		FreeQueryDesc(queryDesc);

		
		MemoryContextSwitchTo(portal->holdContext);

		
		if(Gp_role == GP_ROLE_UTILITY)
		{
			if (portal->atEnd)
			{
				
				while (tuplestore_skiptuples(portal->holdStore, 1000000, true))
					 ;
			}
			else {
				tuplestore_rescan(portal->holdStore);

				if (!tuplestore_skiptuples(portal->holdStore, portal->portalPos, true))

					elog(ERROR, "unexpected end of tuple stream");
			}
		}
	}
	PG_CATCH();
	{
		
		MarkPortalFailed(portal);

		
		if (portal->queryDesc)
			mppExecutorCleanup(portal->queryDesc);

		
		ActivePortal = saveActivePortal;
		CurrentResourceOwner = saveResourceOwner;
		PortalContext = savePortalContext;

		PG_RE_THROW();
	}
	PG_END_TRY();

	MemoryContextSwitchTo(oldcxt);

	
	portal->status = PORTAL_READY;

	ActivePortal = saveActivePortal;
	CurrentResourceOwner = saveResourceOwner;
	PortalContext = savePortalContext;

	PopActiveSnapshot();

	
	MemoryContextDeleteChildren(portal->portalContext);
}
