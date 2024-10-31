








































typedef struct {
	DestReceiver pub;			
	IntoClause *into;			
	
	Relation	rel;			
	ObjectAddress reladdr;		
	CommandId	output_cid;		
	int			ti_options;		
	BulkInsertState bistate;	
} DR_intorel;

static void intorel_startup_dummy(DestReceiver *self, int operation, TupleDesc typeinfo);

static ObjectAddress create_ctas_internal(List *attrList, IntoClause *into, QueryDesc *queryDesc, bool dispatch);
static ObjectAddress create_ctas_nodata(List *tlist, IntoClause *into, QueryDesc *queryDesc);


static bool intorel_receive(TupleTableSlot *slot, DestReceiver *self);
static void intorel_shutdown(DestReceiver *self);
static void intorel_destroy(DestReceiver *self);



static ObjectAddress create_ctas_internal(List *attrList, IntoClause *into, QueryDesc *queryDesc, bool dispatch)
{
	CreateStmt *create = makeNode(CreateStmt);
	bool		is_matview;
	char		relkind;
	Datum		toast_options;
	static char *validnsps[] = HEAP_RELOPT_NAMESPACES;
	ObjectAddress intoRelationAddr;

	
	cdb_sync_oid_to_segments();

	
	is_matview = (into->viewQuery != NULL);
	relkind = is_matview ? RELKIND_MATVIEW : RELKIND_RELATION;

	if (Gp_role == GP_ROLE_EXECUTE)
	{
		create = queryDesc->ddesc->intoCreateStmt;
	}
	
	else {
	
	create->relation = into->rel;
	create->tableElts = attrList;
	create->inhRelations = NIL;
	create->ofTypename = NULL;
	create->constraints = NIL;
	create->options = into->options;
	create->oncommit = into->onCommit;
	create->tablespacename = into->tableSpaceName;
	create->if_not_exists = false;

	create->distributedBy = NULL; 
	create->partitionBy = NULL; 

	create->buildAoBlkdir = false;
	create->attr_encodings = NULL; 

	
	create->relKind = relkind;
	create->ownerid = GetUserId();
	create->accessMethod = into->accessMethod;
	create->isCtas = true;

	create->intoQuery = into->viewQuery;
	create->intoPolicy = queryDesc->plannedstmt->intoPolicy;
  }
	

	
    intoRelationAddr = DefineRelation(create, relkind, InvalidOid, NULL, NULL, false, queryDesc->ddesc ? queryDesc->ddesc->useChangedAOOpts : true, queryDesc->plannedstmt->intoPolicy);







	if (Gp_role == GP_ROLE_DISPATCH)
	{
		queryDesc->ddesc->intoCreateStmt = create;
	}

	
	CommandCounterIncrement();

	
	toast_options = transformRelOptions((Datum) 0, create->options, "toast", validnsps, true, false);




	(void) heap_reloptions(RELKIND_TOASTVALUE, toast_options, true);

	NewRelationCreateToastTable(intoRelationAddr.objectId, toast_options);

	
	if (is_matview)
	{
		
		Query	   *query = (Query *) copyObject(into->viewQuery);

		StoreViewQuery(intoRelationAddr.objectId, query, false);
		CommandCounterIncrement();
	}

	if (Gp_role == GP_ROLE_DISPATCH && dispatch)
		CdbDispatchUtilityStatement((Node *) create, DF_CANCEL_ON_ERROR | DF_NEED_TWO_PHASE | DF_WITH_SNAPSHOT, GetAssignedOidsForDispatch(), NULL);





	return intoRelationAddr;
}



static ObjectAddress create_ctas_nodata(List *tlist, IntoClause *into, QueryDesc *queryDesc)
{
	List	   *attrList;
	ListCell   *t, *lc;
	ObjectAddress intoRelationAddr;

	
	attrList = NIL;
	lc = list_head(into->colNames);
	foreach(t, tlist)
	{
		TargetEntry *tle = (TargetEntry *) lfirst(t);

		if (!tle->resjunk)
		{
			ColumnDef  *col;
			char	   *colname;

			if (lc)
			{
				colname = strVal(lfirst(lc));
				lc = lnext(lc);
			}
			else colname = tle->resname;

			col = makeColumnDef(colname, exprType((Node *) tle->expr), exprTypmod((Node *) tle->expr), exprCollation((Node *) tle->expr));



			
			if (!OidIsValid(col->collOid) && type_is_collatable(col->typeName->typeOid))
				ereport(ERROR, (errcode(ERRCODE_INDETERMINATE_COLLATION), errmsg("no collation was derived for column \"%s\" with collatable type %s", col->colname, format_type_be(col->typeName->typeOid)), errhint("Use the COLLATE clause to set the collation explicitly.")));





			attrList = lappend(attrList, col);
		}
	}

	if (lc != NULL)
		ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("too many column names were specified")));


	
	intoRelationAddr = create_ctas_internal(attrList, into, queryDesc, true);

	return intoRelationAddr;
}



ObjectAddress ExecCreateTableAs(CreateTableAsStmt *stmt, const char *queryString, ParamListInfo params, QueryEnvironment *queryEnv, char *completionTag)


{
	Query	   *query = castNode(Query, stmt->query);
	IntoClause *into = stmt->into;
	bool		is_matview = (into->viewQuery != NULL);
	DestReceiver *dest;
	Oid			save_userid = InvalidOid;
	int			save_sec_context = 0;
	int			save_nestlevel = 0;
	ObjectAddress address;
	List	   *rewritten;
	PlannedStmt *plan;
	QueryDesc  *queryDesc;
	Oid         relationOid = InvalidOid;   
	AutoStatsCmdType cmdType = AUTOSTATS_CMDTYPE_SENTINEL;  

	Assert(Gp_role != GP_ROLE_EXECUTE);

	if (stmt->if_not_exists)
	{
		Oid			nspid;

		nspid = RangeVarGetCreationNamespace(stmt->into->rel);

		if (get_relname_relid(stmt->into->rel->relname, nspid))
		{
			ereport(NOTICE, (errcode(ERRCODE_DUPLICATE_TABLE), errmsg("relation \"%s\" already exists, skipping", stmt->into->rel->relname)));


			return InvalidObjectAddress;
		}
	}
	
	dest = CreateIntoRelDestReceiver(into);

	
	if (query->commandType == CMD_UTILITY && IsA(query->utilityStmt, ExecuteStmt))
	{
		ExecuteStmt *estmt = castNode(ExecuteStmt, query->utilityStmt);

		Assert(!is_matview);	
		ExecuteQuery(estmt, into, queryString, params, dest, completionTag);

		
		address = ((DR_intorel *) dest)->reladdr;

		return address;
	}
	Assert(query->commandType == CMD_SELECT);

	
	if (is_matview)
	{
		GetUserIdAndSecContext(&save_userid, &save_sec_context);
		SetUserIdAndSecContext(save_userid, save_sec_context | SECURITY_RESTRICTED_OPERATION);
		save_nestlevel = NewGUCNestLevel();
	}

	{
		
		rewritten = QueryRewrite(copyObject(query));

		
		if (list_length(rewritten) != 1)
			elog(ERROR, "unexpected rewrite result for %s", is_matview ? "CREATE MATERIALIZED VIEW" :
				 "CREATE TABLE AS SELECT");
		query = linitial_node(Query, rewritten);
		Assert(query->commandType == CMD_SELECT);

		
		plan = pg_plan_query(query, CURSOR_OPT_PARALLEL_OK, params);

		
		
		plan->intoClause = copyObject(stmt->into);

		
		PushCopiedSnapshot(GetActiveSnapshot());
		UpdateActiveSnapshotCommandId();

		
		queryDesc = CreateQueryDesc(plan, queryString, GetActiveSnapshot(), InvalidSnapshot, dest, params, queryEnv, 0);

	}

	
	if (query_info_collect_hook)
		(*query_info_collect_hook)(METRICS_QUERY_SUBMIT, queryDesc);

	if (into->skipData)
	{
		
		queryDesc->ddesc = makeNode(QueryDispatchDesc);
		address = create_ctas_nodata(query->targetList, into, queryDesc);
	}
	else {
		queryDesc->plannedstmt->query_mem = ResourceManagerGetQueryMemoryLimit(queryDesc->plannedstmt);

		
		ExecutorStart(queryDesc, GetIntoRelEFlags(into));

		if (Gp_role == GP_ROLE_DISPATCH)
			autostats_get_cmdtype(queryDesc, &cmdType, &relationOid);

		
		ExecutorRun(queryDesc, ForwardScanDirection, 0L, true);

		
		ExecutorFinish(queryDesc);
		ExecutorEnd(queryDesc);

		
		if (into->distributedBy && ((DistributedBy *)(into->distributedBy))->ptype == POLICYTYPE_REPLICATED)
			queryDesc->es_processed /= ((DistributedBy *)(into->distributedBy))->numsegments;

		
		address = ((DR_intorel *) dest)->reladdr;

		
		if (completionTag)
			snprintf(completionTag, COMPLETION_TAG_BUFSIZE, "SELECT " UINT64_FORMAT, queryDesc->es_processed);


		
		if (Gp_role == GP_ROLE_DISPATCH)
			auto_stats(cmdType, relationOid, queryDesc->es_processed, false );
	}

	{
		dest->rDestroy(dest);

		FreeQueryDesc(queryDesc);

		PopActiveSnapshot();
	}

	if (is_matview)
	{
		
		AtEOXact_GUC(false, save_nestlevel);

		
		SetUserIdAndSecContext(save_userid, save_sec_context);
	}

	return address;
}


int GetIntoRelEFlags(IntoClause *intoClause)
{
	int			flags = 0;

	if (intoClause->skipData)
		flags |= EXEC_FLAG_WITH_NO_DATA;

	return flags;
}


DestReceiver * CreateIntoRelDestReceiver(IntoClause *intoClause)
{
	DR_intorel *self = (DR_intorel *) palloc0(sizeof(DR_intorel));

	self->pub.receiveSlot = intorel_receive;
	self->pub.rStartup = intorel_startup_dummy;
	self->pub.rShutdown = intorel_shutdown;
	self->pub.rDestroy = intorel_destroy;
	self->pub.mydest = DestIntoRel;
	self->into = intoClause;

	return (DestReceiver *) self;
}


static void intorel_startup_dummy(DestReceiver *self, int operation, TupleDesc typeinfo)
{
	

	

	if (RelationIsAoRows(((DR_intorel *)self)->rel))
		appendonly_dml_init(((DR_intorel *)self)->rel, CMD_INSERT);
	else if (RelationIsAoCols(((DR_intorel *)self)->rel))
		aoco_dml_init(((DR_intorel *)self)->rel, CMD_INSERT);
}


void intorel_initplan(struct QueryDesc *queryDesc, int eflags)
{
	DR_intorel *myState;
	
	IntoClause *into = queryDesc->plannedstmt->intoClause;
	bool		is_matview;
	char		relkind;
	List	   *attrList;
	ObjectAddress intoRelationAddr;
	Relation	intoRelationDesc;
	RangeTblEntry *rte;
	ListCell   *lc;
	int			attnum;
	TupleDesc   typeinfo = queryDesc->tupDesc;

	
	if ((eflags & EXEC_FLAG_EXPLAIN_ONLY) || (Gp_role == GP_ROLE_EXECUTE && !Gp_is_writer))
		return;

	
	is_matview = (into->viewQuery != NULL);
	relkind = is_matview ? RELKIND_MATVIEW : RELKIND_RELATION;

	
	attrList = NIL;
	lc = list_head(into->colNames);
	for (attnum = 0; attnum < typeinfo->natts; attnum++)
	{
		Form_pg_attribute attribute = TupleDescAttr(typeinfo, attnum);
		ColumnDef  *col;
		char	   *colname;

		if (lc)
		{
			colname = strVal(lfirst(lc));
			lc = lnext(lc);
		}
		else colname = NameStr(attribute->attname);

		col = makeColumnDef(colname, attribute->atttypid, attribute->atttypmod, attribute->attcollation);



		
		if (!OidIsValid(col->collOid) && type_is_collatable(col->typeName->typeOid))
			ereport(ERROR, (errcode(ERRCODE_INDETERMINATE_COLLATION), errmsg("no collation was derived for column \"%s\" with collatable type %s", col->colname, format_type_be(col->typeName->typeOid)), errhint("Use the COLLATE clause to set the collation explicitly.")));





		attrList = lappend(attrList, col);
	}

	if (lc != NULL)
		ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("too many column names were specified")));


	
	intoRelationAddr = create_ctas_internal(attrList, into, queryDesc, into->skipData ? true : false);

	
	intoRelationDesc = table_open(intoRelationAddr.objectId, AccessExclusiveLock);

	
	rte = makeNode(RangeTblEntry);
	rte->rtekind = RTE_RELATION;
	rte->relid = intoRelationAddr.objectId;
	rte->relkind = relkind;
	rte->rellockmode = RowExclusiveLock;
	rte->requiredPerms = ACL_INSERT;

	for (attnum = 1; attnum <= intoRelationDesc->rd_att->natts; attnum++)
		rte->insertedCols = bms_add_member(rte->insertedCols, attnum - FirstLowInvalidHeapAttributeNumber);

	ExecCheckRTPerms(list_make1(rte), true);

	
	if (check_enable_rls(intoRelationAddr.objectId, InvalidOid, false) == RLS_ENABLED)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), (errmsg("policies not yet implemented for this command"))));


	
	if (is_matview && !into->skipData)
		SetMatViewPopulatedState(intoRelationDesc, true);

	

	if (queryDesc->dest->mydest != DestIntoRel)
		queryDesc->dest = CreateIntoRelDestReceiver(into);
	myState = (DR_intorel *) queryDesc->dest;
	myState->rel = intoRelationDesc;
	myState->reladdr = intoRelationAddr;
	myState->output_cid = GetCurrentCommandId(true);

	
	myState->ti_options = TABLE_INSERT_SKIP_FSM | (XLogIsNeeded() ? 0 : TABLE_INSERT_SKIP_WAL);
	myState->bistate = GetBulkInsertState();

	
	Assert(RelationGetTargetBlock(intoRelationDesc) == InvalidBlockNumber);
}


static bool intorel_receive(TupleTableSlot *slot, DestReceiver *self)
{
	DR_intorel *myState = (DR_intorel *) self;

	

	table_tuple_insert(myState->rel, slot, myState->output_cid, myState->ti_options, myState->bistate);




	

	return true;
}


static void intorel_shutdown(DestReceiver *self)
{
	DR_intorel *myState = (DR_intorel *) self;
	Relation	into_rel = myState->rel;

	if (into_rel == NULL)
		return;

	FreeBulkInsertState(myState->bistate);

	table_finish_bulk_insert(myState->rel, myState->ti_options);

	
	table_close(myState->rel, NoLock);
	myState->rel = NULL;
}


static void intorel_destroy(DestReceiver *self)
{
	pfree(self);
}


Oid GetIntoRelOid(QueryDesc *queryDesc)
{
	DR_intorel *myState = (DR_intorel *) queryDesc->dest;
	Relation    into_rel = myState->rel;

	if (myState && myState->pub.mydest == DestIntoRel && into_rel)
		return RelationGetRelid(into_rel);
	else return InvalidOid;
}
