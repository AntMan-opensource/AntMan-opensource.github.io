





































extern bool Test_print_direct_dispatch_info;

typedef struct ParamWalkerContext {
	plan_tree_base_prefix base; 
	List	   *params;
} ParamWalkerContext;


typedef struct {
	int			sliceIndex;
	int			children;
	ExecSlice  *slice;
} SliceVec;


typedef struct DispatchCommandQueryParms {
	
	const char *strCommand;
	int			strCommandlen;
	char	   *serializedPlantree;
	int			serializedPlantreelen;
	char	   *serializedQueryDispatchDesc;
	int			serializedQueryDispatchDesclen;

	
	char	   *serializedOidAssignments;
	int			serializedOidAssignmentslen;

	
	char	   *serializedDtxContextInfo;
	int			serializedDtxContextInfolen;
} DispatchCommandQueryParms;

static int fillSliceVector(SliceTable *sliceTable, int sliceIndex, SliceVec *sliceVector, int len);



static char *buildGpQueryString(DispatchCommandQueryParms *pQueryParms, int *finalLen);

static DispatchCommandQueryParms *cdbdisp_buildPlanQueryParms(struct QueryDesc *queryDesc, bool planRequiresTxn);
static DispatchCommandQueryParms *cdbdisp_buildUtilityQueryParms(struct Node *stmt, int flags, List *oid_assignments);
static DispatchCommandQueryParms *cdbdisp_buildCommandQueryParms(const char *strCommand, int flags);

static void cdbdisp_dispatchCommandInternal(DispatchCommandQueryParms *pQueryParms, int flags, List *segments, CdbPgResults *cdb_pgresults);


static void cdbdisp_dispatchX(QueryDesc *queryDesc, bool planRequiresTxn, bool cancelOnError);



static List *formIdleSegmentIdList(void);

static bool param_walker(Node *node, ParamWalkerContext *context);
static Oid	findParamType(List *params, int paramid);
static Bitmapset *getExecParamsToDispatch(PlannedStmt *stmt, ParamExecData *intPrm, List **paramExecTypes);
static SerializedParams *serializeParamsForDispatch(QueryDesc *queryDesc, ParamListInfo externParams, ParamExecData *execParams, List *paramExecTypes, Bitmapset *sendParams);







void CdbDispatchPlan(struct QueryDesc *queryDesc, ParamExecData *execParams, bool planRequiresTxn, bool cancelOnError)



{
	PlannedStmt *stmt;
	bool		is_SRI = false;
	List	   *paramExecTypes;
	Bitmapset  *sendParams;

	Assert(Gp_role == GP_ROLE_DISPATCH);
	Assert(queryDesc != NULL && queryDesc->estate != NULL);

	
	stmt = queryDesc->plannedstmt;
	Assert(stmt);

	
	if (queryDesc->operation == CMD_INSERT)
	{
		Assert(stmt->commandType == CMD_INSERT);

		
		is_SRI = IsA(stmt->planTree, Result) &&stmt->planTree->lefttree == NULL;
	}

	if (queryDesc->operation == CMD_INSERT || queryDesc->operation == CMD_SELECT || queryDesc->operation == CMD_UPDATE || queryDesc->operation == CMD_DELETE)


	{
		List	   *cursors;

		
		stmt = palloc(sizeof(PlannedStmt));
		memcpy(stmt, queryDesc->plannedstmt, sizeof(PlannedStmt));
		stmt->subplans = list_copy(stmt->subplans);

		stmt->planTree = (Plan *) exec_make_plan_constant(stmt, queryDesc->estate, is_SRI, &cursors);
		queryDesc->plannedstmt = stmt;

		queryDesc->ddesc->cursorPositions = (List *) copyObject(cursors);
	}

	
	sendParams = getExecParamsToDispatch(stmt, execParams, &paramExecTypes);
	queryDesc->ddesc->paramInfo = serializeParamsForDispatch(queryDesc, queryDesc->params, execParams, paramExecTypes, sendParams);



	
	if (queryDesc->extended_query)
	{
		verify_shared_snapshot_ready(gp_command_count);
	}

	cdbdisp_dispatchX(queryDesc, planRequiresTxn, cancelOnError);
}


static void cdbdisp_markNamedPortalGangsDestroyed(void)
{
	dispatcher_handle_t *head = open_dispatcher_handles;
	while (head != NULL)
	{
		if (head->dispatcherState->isExtendedQuery)
			head->dispatcherState->forceDestroyGang = true;
		head = head->next;
	}
}


void CdbDispatchSetCommand(const char *strCommand, bool cancelOnError)
{
	CdbDispatcherState *ds;
	DispatchCommandQueryParms *pQueryParms;
	Gang *primaryGang;
	char	   *queryText;
	int		queryTextLength;
	ListCell   *le;
	ErrorData *qeError = NULL;

	elog((Debug_print_full_dtm ? LOG : DEBUG5), "CdbDispatchSetCommand for command = '%s'", strCommand);


	pQueryParms = cdbdisp_buildCommandQueryParms(strCommand, DF_NONE);

	ds = cdbdisp_makeDispatcherState(false);

	queryText = buildGpQueryString(pQueryParms, &queryTextLength);

	primaryGang = AllocateGang(ds, GANGTYPE_PRIMARY_WRITER, cdbcomponent_getCdbComponentsList());

	
	AllocateGang(ds, GANGTYPE_PRIMARY_READER, formIdleSegmentIdList());
	
	cdbdisp_makeDispatchResults(ds, list_length(ds->allocatedGangs), cancelOnError);
	cdbdisp_makeDispatchParams (ds, list_length(ds->allocatedGangs), queryText, queryTextLength);

	foreach(le, ds->allocatedGangs)
	{
		Gang	   *rg = lfirst(le);

		cdbdisp_dispatchToGang(ds, rg, -1);
	}
	addToGxactDtxSegments(primaryGang);

	

	cdbdisp_waitDispatchFinish(ds);

	cdbdisp_checkDispatchResult(ds, DISPATCH_WAIT_NONE);

	cdbdisp_getDispatchResults(ds, &qeError);

	
	cdbdisp_markNamedPortalGangsDestroyed();

	if (qeError)
	{

		FlushErrorState();
		ReThrowError(qeError);
	}

	cdbdisp_destroyDispatcherState(ds);
}


void CdbDispatchCommand(const char *strCommand, int flags, CdbPgResults *cdb_pgresults)


{
	return CdbDispatchCommandToSegments(strCommand, flags, cdbcomponent_getCdbComponentsList(), cdb_pgresults);


}


void CdbDispatchCommandToSegments(const char *strCommand, int flags, List *segments, CdbPgResults *cdb_pgresults)



{
	DispatchCommandQueryParms *pQueryParms;
	bool needTwoPhase = flags & DF_NEED_TWO_PHASE;

	if (needTwoPhase)
		setupDtxTransaction();

	elogif((Debug_print_full_dtm || log_min_messages <= DEBUG5), LOG, "CdbDispatchCommand: %s (needTwoPhase = %s)", strCommand, (needTwoPhase ? "true" : "false"));


	pQueryParms = cdbdisp_buildCommandQueryParms(strCommand, flags);

	return cdbdisp_dispatchCommandInternal(pQueryParms, flags, segments, cdb_pgresults);


}


void CdbDispatchUtilityStatement(struct Node *stmt, int flags, List *oid_assignments, CdbPgResults *cdb_pgresults)



{
	DispatchCommandQueryParms *pQueryParms;
	bool needTwoPhase = flags & DF_NEED_TWO_PHASE;

	if (needTwoPhase)
		setupDtxTransaction();

	elogif((Debug_print_full_dtm || log_min_messages <= DEBUG5), LOG, "CdbDispatchUtilityStatement: %s (needTwoPhase = %s)", (PointerIsValid(debug_query_string) ? debug_query_string : "\"\""), (needTwoPhase ? "true" : "false"));



	pQueryParms = cdbdisp_buildUtilityQueryParms(stmt, flags, oid_assignments);

	return cdbdisp_dispatchCommandInternal(pQueryParms, flags, cdbcomponent_getCdbComponentsList(), cdb_pgresults);


}

static void cdbdisp_dispatchCommandInternal(DispatchCommandQueryParms *pQueryParms, int flags, List *segments, CdbPgResults *cdb_pgresults)



{
	CdbDispatcherState *ds;
	Gang *primaryGang;
	CdbDispatchResults *pr;
	ErrorData *qeError = NULL;
	char *queryText;
	int queryTextLength;

	
	ds = cdbdisp_makeDispatcherState(false);

	
	ds->destroyIdleReaderGang = true;

	queryText = buildGpQueryString(pQueryParms, &queryTextLength);

	
	primaryGang = AllocateGang(ds, GANGTYPE_PRIMARY_WRITER, segments);
	Assert(primaryGang);

	cdbdisp_makeDispatchResults(ds, 1, flags & DF_CANCEL_ON_ERROR);
	cdbdisp_makeDispatchParams (ds, 1, queryText, queryTextLength);

	cdbdisp_dispatchToGang(ds, primaryGang, -1);

	if ((flags & DF_NEED_TWO_PHASE) != 0 || isDtxExplicitBegin())
		addToGxactDtxSegments(primaryGang);

	cdbdisp_waitDispatchFinish(ds);

	cdbdisp_checkDispatchResult(ds, DISPATCH_WAIT_NONE);

	pr = cdbdisp_getDispatchResults(ds, &qeError);

	if (qeError)
	{
		FlushErrorState();
		ReThrowError(qeError);
	}

	
	pgstat_combine_from_qe(pr, -1);

	cdbdisp_returnResults(pr, cdb_pgresults);

	cdbdisp_destroyDispatcherState(ds);
}

static DispatchCommandQueryParms * cdbdisp_buildCommandQueryParms(const char *strCommand, int flags)
{
	bool needTwoPhase = flags & DF_NEED_TWO_PHASE;
	bool withSnapshot = flags & DF_WITH_SNAPSHOT;
	DispatchCommandQueryParms *pQueryParms;

	pQueryParms = palloc0(sizeof(*pQueryParms));
	pQueryParms->strCommand = strCommand;
	pQueryParms->serializedQueryDispatchDesc = NULL;
	pQueryParms->serializedQueryDispatchDesclen = 0;

	
	pQueryParms->serializedDtxContextInfo = qdSerializeDtxContextInfo(&pQueryParms->serializedDtxContextInfolen, withSnapshot, false, mppTxnOptions(needTwoPhase), "cdbdisp_dispatchCommandInternal");




	return pQueryParms;
}

static DispatchCommandQueryParms * cdbdisp_buildUtilityQueryParms(struct Node *stmt, int flags, List *oid_assignments)


{
	char *serializedPlantree = NULL;
	char *serializedQueryDispatchDesc = NULL;
	int serializedPlantree_len = 0;
	int serializedQueryDispatchDesc_len = 0;
	bool needTwoPhase = flags & DF_NEED_TWO_PHASE;
	bool withSnapshot = flags & DF_WITH_SNAPSHOT;
	QueryDispatchDesc *qddesc;
	PlannedStmt *pstmt;
	DispatchCommandQueryParms *pQueryParms;

	Assert(stmt != NULL);
	Assert(stmt->type < 1000);
	Assert(stmt->type > 0);

	
	pstmt = makeNode(PlannedStmt);
	pstmt->commandType = CMD_UTILITY;

	
	pstmt->canSetTag = true;
	pstmt->utilityStmt = stmt;
	pstmt->stmt_location = 0;
	pstmt->stmt_len = 0;

	
	serializedPlantree = serializeNode((Node *) pstmt, &serializedPlantree_len, NULL  );
	Assert(serializedPlantree != NULL);

	if (oid_assignments)
	{
		qddesc = makeNode(QueryDispatchDesc);
		qddesc->oidAssignments = oid_assignments;

		serializedQueryDispatchDesc = serializeNode((Node *) qddesc, &serializedQueryDispatchDesc_len, NULL  );
	}

	pQueryParms = palloc0(sizeof(*pQueryParms));
	pQueryParms->strCommand = PointerIsValid(debug_query_string) ? debug_query_string : "";
	pQueryParms->serializedPlantree = serializedPlantree;
	pQueryParms->serializedPlantreelen = serializedPlantree_len;
	pQueryParms->serializedQueryDispatchDesc = serializedQueryDispatchDesc;
	pQueryParms->serializedQueryDispatchDesclen = serializedQueryDispatchDesc_len;

	
	pQueryParms->serializedDtxContextInfo = qdSerializeDtxContextInfo(&pQueryParms->serializedDtxContextInfolen, withSnapshot, false, mppTxnOptions(needTwoPhase), "cdbdisp_dispatchCommandInternal");




	return pQueryParms;
}

static DispatchCommandQueryParms * cdbdisp_buildPlanQueryParms(struct QueryDesc *queryDesc, bool planRequiresTxn)

{
	char	   *splan, *sddesc;

	int			splan_len, splan_len_uncompressed, sddesc_len, rootIdx;



	rootIdx = RootSliceIndex(queryDesc->estate);

	DispatchCommandQueryParms *pQueryParms = (DispatchCommandQueryParms *) palloc0(sizeof(*pQueryParms));

	
	splan = serializeNode((Node *) queryDesc->plannedstmt, &splan_len, &splan_len_uncompressed);

	uint64		plan_size_in_kb = ((uint64) splan_len_uncompressed) / (uint64) 1024;

	elog(((gp_log_gang >= GPVARS_VERBOSITY_TERSE) ? LOG : DEBUG1), "Query plan size to dispatch: " UINT64_FORMAT "KB", plan_size_in_kb);

	if (0 < gp_max_plan_size && plan_size_in_kb > gp_max_plan_size)
	{
		ereport(ERROR, (errcode(ERRCODE_STATEMENT_TOO_COMPLEX), (errmsg("Query plan size limit exceeded, current size: " UINT64_FORMAT "KB, max allowed size: %dKB", plan_size_in_kb, gp_max_plan_size), errhint("Size controlled by gp_max_plan_size"))));




	}

	Assert(splan != NULL && splan_len > 0 && splan_len_uncompressed > 0);

	sddesc = serializeNode((Node *) queryDesc->ddesc, &sddesc_len, NULL  );

	pQueryParms->strCommand = queryDesc->sourceText;
	pQueryParms->serializedPlantree = splan;
	pQueryParms->serializedPlantreelen = splan_len;
	pQueryParms->serializedQueryDispatchDesc = sddesc;
	pQueryParms->serializedQueryDispatchDesclen = sddesc_len;

	
	pQueryParms->serializedDtxContextInfo = qdSerializeDtxContextInfo(&pQueryParms->serializedDtxContextInfolen, true  , queryDesc->extended_query, mppTxnOptions(planRequiresTxn), "cdbdisp_buildPlanQueryParms");





	return pQueryParms;
}


static int compare_slice_order(const void *aa, const void *bb)
{
	SliceVec   *a = (SliceVec *) aa;
	SliceVec   *b = (SliceVec *) bb;

	if (a->slice == NULL)
		return 1;
	if (b->slice == NULL)
		return -1;

	
	if (a->slice->primaryGang == NULL)
	{
		Assert(a->slice->gangType == GANGTYPE_UNALLOCATED);
		return 1;
	}
	if (b->slice->primaryGang == NULL)
	{
		Assert(b->slice->gangType == GANGTYPE_UNALLOCATED);
		return -1;
	}

	
	if (a->slice->primaryGang->size > b->slice->primaryGang->size)
		return -1;

	if (a->slice->primaryGang->size < b->slice->primaryGang->size)
		return 1;

	if (a->children == b->children)
		return 0;
	else if (a->children > b->children)
		return 1;
	else return -1;
}


static void mark_bit(char *bits, int nth)
{
	int			nthbyte = nth >> 3;
	char		nthbit = 1 << (nth & 7);

	bits[nthbyte] |= nthbit;
}

static void or_bits(char *dest, char *src, int n)
{
	int			i;

	for (i = 0; i < n; i++)
		dest[i] |= src[i];
}

static int count_bits(char *bits, int nbyte)
{
	int			i;
	int			nbit = 0;

	int			bitcount[] = {
		0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };

	for (i = 0; i < nbyte; i++)
	{
		nbit += bitcount[bits[i] & 0x0F];
		nbit += bitcount[(bits[i] >> 4) & 0x0F];
	}

	return nbit;
}


static int markbit_dep_children(SliceTable *sliceTable, int sliceIdx, SliceVec *sliceVec, int bitmasklen, char *bits)

{
	ListCell   *sublist;
	ExecSlice  *slice = &sliceTable->slices[sliceIdx];

	foreach(sublist, slice->children)
	{
		int			childIndex = lfirst_int(sublist);
		char	   *newbits = palloc0(bitmasklen);

		markbit_dep_children(sliceTable, childIndex, sliceVec, bitmasklen, newbits);
		or_bits(bits, newbits, bitmasklen);
		mark_bit(bits, childIndex);
		pfree(newbits);
	}

	sliceVec[sliceIdx].sliceIndex = sliceIdx;
	sliceVec[sliceIdx].children = count_bits(bits, bitmasklen);
	sliceVec[sliceIdx].slice = slice;

	return sliceVec[sliceIdx].children;
}


static int count_dependent_children(SliceTable *sliceTable, int sliceIndex, SliceVec *sliceVector, int len)

{
	int			ret = 0;
	int			bitmasklen = (len + 7) >> 3;
	char	   *bitmask = palloc0(bitmasklen);

	ret = markbit_dep_children(sliceTable, sliceIndex, sliceVector, bitmasklen, bitmask);
	pfree(bitmask);

	return ret;
}

static int fillSliceVector(SliceTable *sliceTbl, int rootIdx, SliceVec *sliceVector, int nTotalSlices)

{
	int			top_count;

	
	top_count = 1 + count_dependent_children(sliceTbl, rootIdx, sliceVector, nTotalSlices);

	qsort(sliceVector, nTotalSlices, sizeof(SliceVec), compare_slice_order);

	return top_count;
}


static char * buildGpQueryString(DispatchCommandQueryParms *pQueryParms, int *finalLen)

{
	const char *command = pQueryParms->strCommand;
	int			command_len;
	const char *plantree = pQueryParms->serializedPlantree;
	int			plantree_len = pQueryParms->serializedPlantreelen;
	const char *sddesc = pQueryParms->serializedQueryDispatchDesc;
	int			sddesc_len = pQueryParms->serializedQueryDispatchDesclen;
	const char *dtxContextInfo = pQueryParms->serializedDtxContextInfo;
	int			dtxContextInfo_len = pQueryParms->serializedDtxContextInfolen;
	int64		currentStatementStartTimestamp = GetCurrentStatementStartTimestamp();
	Oid			sessionUserId = GetSessionUserId();
	Oid			outerUserId = GetOuterUserId();
	Oid			currentUserId = GetUserId();
	int32		numsegments = getgpsegmentCount();
	StringInfoData resgroupInfo;

	int			tmp, len;
	uint32		n32;
	int			total_query_len;
	char	   *shared_query, *pos;
	MemoryContext oldContext;

	
	Assert(DispatcherContext);
	oldContext = MemoryContextSwitchTo(DispatcherContext);

	
	command_len = strlen(command) + 1;
	if (plantree && command_len > QUERY_STRING_TRUNCATE_SIZE)
		command_len = pg_mbcliplen(command, command_len, QUERY_STRING_TRUNCATE_SIZE-1) + 1;

	initStringInfo(&resgroupInfo);
	if (IsResGroupActivated())
		SerializeResGroupInfo(&resgroupInfo);

	total_query_len = 1  + sizeof(len)  + sizeof(gp_command_count) + sizeof(sessionUserId)  + sizeof(outerUserId)  + sizeof(currentUserId) + sizeof(n32) * 2  + sizeof(command_len) + sizeof(plantree_len) + sizeof(sddesc_len) + sizeof(dtxContextInfo_len) + dtxContextInfo_len + command_len + plantree_len + sddesc_len + sizeof(numsegments) + sizeof(resgroupInfo.len) + resgroupInfo.len;

















	shared_query = palloc(total_query_len);

	pos = shared_query;

	*pos++ = 'M';

	pos += 4;					

	tmp = htonl(gp_command_count);
	memcpy(pos, &tmp, sizeof(gp_command_count));
	pos += sizeof(gp_command_count);

	tmp = htonl(sessionUserId);
	memcpy(pos, &tmp, sizeof(sessionUserId));
	pos += sizeof(sessionUserId);

	tmp = htonl(outerUserId);
	memcpy(pos, &tmp, sizeof(outerUserId));
	pos += sizeof(outerUserId);

	tmp = htonl(currentUserId);
	memcpy(pos, &tmp, sizeof(currentUserId));
	pos += sizeof(currentUserId);

	
	n32 = (uint32) (currentStatementStartTimestamp >> 32);
	n32 = htonl(n32);
	memcpy(pos, &n32, sizeof(n32));
	pos += sizeof(n32);

	
	n32 = (uint32) currentStatementStartTimestamp;
	n32 = htonl(n32);
	memcpy(pos, &n32, sizeof(n32));
	pos += sizeof(n32);

	tmp = htonl(command_len);
	memcpy(pos, &tmp, sizeof(command_len));
	pos += sizeof(command_len);

	tmp = htonl(plantree_len);
	memcpy(pos, &tmp, sizeof(plantree_len));
	pos += sizeof(plantree_len);

	tmp = htonl(sddesc_len);
	memcpy(pos, &tmp, sizeof(tmp));
	pos += sizeof(tmp);

	tmp = htonl(dtxContextInfo_len);
	memcpy(pos, &tmp, sizeof(tmp));
	pos += sizeof(tmp);

	if (dtxContextInfo_len > 0)
	{
		memcpy(pos, dtxContextInfo, dtxContextInfo_len);
		pos += dtxContextInfo_len;
	}

	memcpy(pos, command, command_len);
	
	pos[command_len - 1] = '\0';
	pos += command_len;

	if (plantree_len > 0)
	{
		memcpy(pos, plantree, plantree_len);
		pos += plantree_len;
	}

	if (sddesc_len > 0)
	{
		memcpy(pos, sddesc, sddesc_len);
		pos += sddesc_len;
	}

	tmp = htonl(numsegments);
	memcpy(pos, &tmp, sizeof(numsegments));
	pos += sizeof(numsegments);

	tmp = htonl(resgroupInfo.len);
	memcpy(pos, &tmp, sizeof(resgroupInfo.len));
	pos += sizeof(resgroupInfo.len);

	if (resgroupInfo.len > 0)
	{
		memcpy(pos, resgroupInfo.data, resgroupInfo.len);
		pos += resgroupInfo.len;
	}

	len = pos - shared_query - 1;

	
	tmp = htonl(len);
	memcpy(shared_query + 1, &tmp, sizeof(len));

	Assert(len + 1 == total_query_len);

	if (finalLen)
		*finalLen = len + 1;

	MemoryContextSwitchTo(oldContext);

	return shared_query;
}


static void cdbdisp_dispatchX(QueryDesc* queryDesc, bool planRequiresTxn, bool cancelOnError)


{
	SliceVec   *sliceVector = NULL;
	int			nSlices = 1;	
	int			nTotalSlices = 1;	

	int			iSlice;
	int			rootIdx;
	char	   *queryText = NULL;
	int			queryTextLength = 0;
	struct SliceTable *sliceTbl;
	struct EState *estate;
	CdbDispatcherState *ds;
	ErrorData *qeError = NULL;
	DispatchCommandQueryParms *pQueryParms;

	if (log_dispatch_stats)
		ResetUsage();

	estate = queryDesc->estate;
	sliceTbl = estate->es_sliceTable;
	Assert(sliceTbl != NULL);

	rootIdx = RootSliceIndex(estate);

	ds = cdbdisp_makeDispatcherState(queryDesc->extended_query);

	
	AssignGangs(ds, queryDesc);

	
	nTotalSlices = sliceTbl->numSlices;
	sliceVector = palloc0(nTotalSlices * sizeof(SliceVec));
	nSlices = fillSliceVector(sliceTbl, rootIdx, sliceVector, nTotalSlices);
	
	sliceTbl->ic_instance_id = ++gp_interconnect_id;

	pQueryParms = cdbdisp_buildPlanQueryParms(queryDesc, planRequiresTxn);
	queryText = buildGpQueryString(pQueryParms, &queryTextLength);

	
	cdbdisp_makeDispatchResults(ds, nTotalSlices, cancelOnError);
	cdbdisp_makeDispatchParams(ds, nTotalSlices, queryText, queryTextLength);

	cdb_total_plans++;
	cdb_total_slices += nSlices;
	if (nSlices > cdb_max_slices)
		cdb_max_slices = nSlices;

	if (DEBUG1 >= log_min_messages)
	{
		char		msec_str[32];

		switch (check_log_duration(msec_str, false))
		{
			case 1:
			case 2:
				ereport(LOG, (errmsg("duration to start of dispatch send (root %d): %s ms", rootIdx, msec_str)));

				break;
		}
	}

	for (iSlice = 0; iSlice < nSlices; iSlice++)
	{
		Gang	   *primaryGang = NULL;
		ExecSlice  *slice;
		int			si = -1;

		Assert(sliceVector != NULL);

		slice = sliceVector[iSlice].slice;
		si = slice->sliceIndex;

		
		if (slice && slice->gangType == GANGTYPE_UNALLOCATED)
		{
			Assert(slice->primaryGang == NULL);

			
			continue;
		}

		primaryGang = slice->primaryGang;
		Assert(primaryGang != NULL);
		AssertImply(queryDesc->extended_query, primaryGang->type == GANGTYPE_PRIMARY_READER || primaryGang->type == GANGTYPE_SINGLETON_READER || primaryGang->type == GANGTYPE_ENTRYDB_READER);



		if (Test_print_direct_dispatch_info)
			elog(INFO, "(slice %d) Dispatch command to %s", slice->sliceIndex, segmentsToContentStr(slice->segments));

		
		if (cancelOnError)
		{
			if (ds->primaryResults->errcode)
				break;
			if (InterruptPending)
				break;
		}
		SIMPLE_FAULT_INJECTOR("before_one_slice_dispatched");

		cdbdisp_dispatchToGang(ds, primaryGang, si);
		if (planRequiresTxn || isDtxExplicitBegin())
			addToGxactDtxSegments(primaryGang);

		SIMPLE_FAULT_INJECTOR("after_one_slice_dispatched");
	}

	pfree(sliceVector);

	cdbdisp_waitDispatchFinish(ds);

	
	if (iSlice < nSlices)
	{
		elog(Debug_cancel_print ? LOG : DEBUG2, "Plan dispatch canceled; dispatched %d of %d slices", iSlice, nSlices);


		
		cdbdisp_cancelDispatch(ds);

		
		cdbdisp_getDispatchResults(ds, &qeError);

		if (qeError)
		{
			FlushErrorState();
			ReThrowError(qeError);
		}

		
		CHECK_FOR_INTERRUPTS();

		
		ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR), errmsg_internal("unable to dispatch plan")));

	}

	if (DEBUG1 >= log_min_messages)
	{
		char		msec_str[32];

		switch (check_log_duration(msec_str, false))
		{
			case 1:
			case 2:
				ereport(LOG, (errmsg("duration to dispatch out (root %d): %s ms", rootIdx, msec_str)));

				break;
		}
	}

	estate->dispatcherState = ds;
}


ParamListInfo deserializeExternParams(SerializedParams *sparams)
{
	TupleRemapper *remapper;
	ParamListInfo paramLI;

	if (sparams->nExternParams == 0)
		return NULL;

	
	if (sparams->transientTypes)
	{
		remapper = CreateTupleRemapper();
		TRHandleTypeLists(remapper, sparams->transientTypes);
	}
	else remapper = NULL;

	
	paramLI = palloc(offsetof(ParamListInfoData, params) + sparams->nExternParams * sizeof(ParamExternData));
	
	memset(paramLI, 0, offsetof(ParamListInfoData, params));
	paramLI->numParams = sparams->nExternParams;

	
	for (int i = 0; i < sparams->nExternParams; i++)
	{
		SerializedParamExternData *sprm = &sparams->externParams[i];
		ParamExternData *prm = &paramLI->params[i];

		prm->ptype = sprm->ptype;
		prm->isnull = sprm->isnull;
		prm->pflags = sprm->pflags;

		
		if (remapper && prm->ptype != InvalidOid)
			prm->value = TRRemapDatum(remapper, sprm->ptype, sprm->value);
		else prm->value = sprm->value;
	}

	return paramLI;
}


void CdbDispatchCopyStart(struct CdbCopy *cdbCopy, Node *stmt, int flags)
{
	DispatchCommandQueryParms *pQueryParms;
	char *queryText;
	int queryTextLength;
	CdbDispatcherState *ds;
	Gang *primaryGang;
	ErrorData *error = NULL;
	bool needTwoPhase = flags & DF_NEED_TWO_PHASE;

	if (needTwoPhase)
		setupDtxTransaction();

	elogif((Debug_print_full_dtm || log_min_messages <= DEBUG5), LOG, "CdbDispatchCopyStart: %s (needTwoPhase = %s)", (PointerIsValid(debug_query_string) ? debug_query_string : "\"\""), (needTwoPhase ? "true" : "false"));



	pQueryParms = cdbdisp_buildUtilityQueryParms(stmt, flags, NULL);

	
	ds = cdbdisp_makeDispatcherState(false);

	queryText = buildGpQueryString(pQueryParms, &queryTextLength);

	
	primaryGang = AllocateGang(ds, GANGTYPE_PRIMARY_WRITER, cdbCopy->seglist);
	Assert(primaryGang);

	cdbdisp_makeDispatchResults(ds, 1, flags & DF_CANCEL_ON_ERROR);
	cdbdisp_makeDispatchParams (ds, 1, queryText, queryTextLength);

	cdbdisp_dispatchToGang(ds, primaryGang, -1);
	if ((flags & DF_NEED_TWO_PHASE) != 0 || isDtxExplicitBegin())
		addToGxactDtxSegments(primaryGang);

	cdbdisp_waitDispatchFinish(ds);

	cdbdisp_checkDispatchResult(ds, DISPATCH_WAIT_NONE);

	if (!cdbdisp_getDispatchResults(ds, &error))
	{
		FlushErrorState();
		ReThrowError(error);
	}

	
	cdbCopy->dispatcherState = ds;
}

void CdbDispatchCopyEnd(struct CdbCopy *cdbCopy)
{
	CdbDispatcherState *ds;

	ds = cdbCopy->dispatcherState;
	cdbCopy->dispatcherState = NULL;
	cdbdisp_destroyDispatcherState(ds);
}


static List * formIdleSegmentIdList(void)
{
	CdbComponentDatabases	*cdbs;
	List					*segments = NIL;
	int						i, j;

	cdbs = cdbcomponent_getCdbComponents();

	if (cdbs->segment_db_info != NULL)
	{
		for (i = 0; i < cdbs->total_segment_dbs; i++)
		{
			CdbComponentDatabaseInfo *cdi = &cdbs->segment_db_info[i];
			for (j = 0; j < cdi->numIdleQEs; j++)
				segments = lappend_int(segments, cdi->config->segindex);
		}
	}

	return segments;
}



static SerializedParams * serializeParamsForDispatch(QueryDesc *queryDesc, ParamListInfo externParams, ParamExecData *execParams, List *paramExecTypes, Bitmapset *sendParams)




{
	SerializedParams *result = makeNode(SerializedParams);
	bool		found_records = false;

	
	if (externParams)
	{
		result->nExternParams = externParams->numParams;
		result->externParams = palloc0(externParams->numParams * sizeof(SerializedParamExternData));

		for (int i = 0; i < externParams->numParams; i++)
		{
			ParamExternData *prm;
			SerializedParamExternData *sprm = &result->externParams[i];
			ParamExternData prmdata;

			
			if (externParams->paramFetch != NULL)
				prm = externParams->paramFetch(externParams, i + 1, false, &prmdata);
			else prm = &externParams->params[i];

			sprm->value = prm->value;
			sprm->isnull = prm->isnull;
			sprm->pflags = prm->pflags;
			sprm->ptype = prm->ptype;

			if (OidIsValid(prm->ptype))
			{
				get_typlenbyval(prm->ptype, &sprm->plen, &sprm->pbyval);
				if (prm->ptype == RECORDOID && !prm->isnull)
					found_records = true;
			}
			else {
				sprm->plen = 0;
				sprm->pbyval = true;
			}
		}
	}

	
	if (!bms_is_empty(sendParams))
	{
		int			numExecParams = list_length(paramExecTypes);
		int			x;

		result->nExecParams = numExecParams;
		result->execParams = palloc0(numExecParams * sizeof(SerializedParamExecData));

		x = -1;
		while ((x = bms_next_member(sendParams, x)) >= 0)
		{
			ParamExecData *prm = &execParams[x];
			SerializedParamExecData *sprm = &result->execParams[x];
			Oid			ptype = list_nth_oid(paramExecTypes, x);

			sprm->value = prm->value;
			sprm->isnull = prm->isnull;
			sprm->isvalid = true;

			get_typlenbyval(ptype, &sprm->plen, &sprm->pbyval);
			if (ptype == RECORDOID && !prm->isnull)
				found_records = true;
		}
	}

	
	if (found_records)
		result->transientTypes = build_tuple_node_list(0);

	return result;
}


static Bitmapset * getExecParamsToDispatch(PlannedStmt *stmt, ParamExecData *intPrm, List **paramExecTypes)

{
	ParamWalkerContext context;
	int			i;
	Plan	   *plan = stmt->planTree;
	int			nIntPrm = list_length(stmt->paramExecTypes);
	Bitmapset  *sendParams = NULL;

	if (nIntPrm == 0)
	{
		*paramExecTypes = NIL;
		return NULL;
	}
	Assert(intPrm != NULL);		

	

	exec_init_plan_tree_base(&context.base, stmt);
	context.params = NIL;
	param_walker((Node *) plan, &context);

	
	if (list_length(context.params) < nIntPrm)
	{
		ListCell   *sb;

		foreach(sb, stmt->subplans)
		{
			Node	   *subplan = lfirst(sb);

			param_walker((Node *) subplan, &context);
		}
	}

	
	*paramExecTypes = NIL;
	for (i = 0; i < nIntPrm; i++)
	{
		Oid			paramType = findParamType(context.params, i);

		*paramExecTypes = lappend_oid(*paramExecTypes, paramType);
		if (paramType != InvalidOid)
		{
			sendParams = bms_add_member(sendParams, i);
		}
		else {
			
		}
	}

	list_free(context.params);

	return sendParams;
}


static bool param_walker(Node *node, ParamWalkerContext *context)
{
	if (node == NULL)
		return false;

	if (nodeTag(node) == T_Param)
	{
		Param	   *param = (Param *) node;

		if (param->paramkind == PARAM_EXEC)
		{
			context->params = lappend(context->params, param);
			return false;
		}
	}
	return plan_tree_walker(node, param_walker, context, true);
}


static Oid findParamType(List *params, int paramid)
{
	ListCell   *l;

	foreach(l, params)
	{
		Param	   *p = lfirst(l);

		if (p->paramid == paramid)
			return p->paramtype;
	}

	return InvalidOid;
}
