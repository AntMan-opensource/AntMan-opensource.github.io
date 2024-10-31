

























































int			SessionReplicationRole = SESSION_REPLICATION_ROLE_ORIGIN;


static int	MyTriggerDepth = 0;






static void ConvertTriggerToFK(CreateTrigStmt *stmt, Oid funcoid);
static void SetTriggerFlags(TriggerDesc *trigdesc, Trigger *trigger);
static bool GetTupleForTrigger(EState *estate, EPQState *epqstate, ResultRelInfo *relinfo, ItemPointer tid, LockTupleMode lockmode, TupleTableSlot *oldslot, TupleTableSlot **newSlot);





static bool TriggerEnabled(EState *estate, ResultRelInfo *relinfo, Trigger *trigger, TriggerEvent event, Bitmapset *modifiedCols, TupleTableSlot *oldslot, TupleTableSlot *newslot);


static HeapTuple ExecCallTriggerFunc(TriggerData *trigdata, int tgindx, FmgrInfo *finfo, Instrumentation *instr, MemoryContext per_tuple_context);



static void AfterTriggerSaveEvent(EState *estate, ResultRelInfo *relinfo, int event, bool row_trigger, TupleTableSlot *oldtup, TupleTableSlot *newtup, List *recheckIndexes, Bitmapset *modifiedCols, TransitionCaptureState *transition_capture);



static void AfterTriggerEnlargeQueryState(void);
static bool before_stmt_triggers_fired(Oid relid, CmdType cmdType);



ObjectAddress CreateTrigger(CreateTrigStmt *stmt, const char *queryString, Oid relOid, Oid refRelOid, Oid constraintOid, Oid indexOid, Oid funcoid, Oid parentTriggerOid, Node *whenClause, bool isInternal, bool in_partition)



{
	int16		tgtype;
	int			ncolumns;
	int16	   *columns;
	int2vector *tgattr;
	List	   *whenRtable;
	char	   *qual;
	Datum		values[Natts_pg_trigger];
	bool		nulls[Natts_pg_trigger];
	Relation	rel;
	AclResult	aclresult;
	Relation	tgrel;
	SysScanDesc tgscan;
	ScanKeyData key;
	Relation	pgrel;
	HeapTuple	tuple;
	Oid			funcrettype;
	Oid			trigoid;
	char		internaltrigname[NAMEDATALEN];
	char	   *trigname;
	Oid			constrrelid = InvalidOid;
	ObjectAddress myself, referenced;
	char	   *oldtablename = NULL;
	char	   *newtablename = NULL;
	bool		partition_recurse;

	if (OidIsValid(relOid))
		rel = table_open(relOid, ShareRowExclusiveLock);
	else rel = table_openrv(stmt->relation, ShareRowExclusiveLock);

	
	if (rel->rd_rel->relkind == RELKIND_RELATION)
	{
		
		if (stmt->timing != TRIGGER_TYPE_BEFORE && stmt->timing != TRIGGER_TYPE_AFTER)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is a table", RelationGetRelationName(rel)), errdetail("Tables cannot have INSTEAD OF triggers.")));



	}
	else if (rel->rd_rel->relkind == RELKIND_PARTITIONED_TABLE)
	{
		
		if (stmt->timing != TRIGGER_TYPE_BEFORE && stmt->timing != TRIGGER_TYPE_AFTER)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is a table", RelationGetRelationName(rel)), errdetail("Tables cannot have INSTEAD OF triggers.")));




		
		if (stmt->row)
		{
			
			if (stmt->timing != TRIGGER_TYPE_AFTER)
				ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is a partitioned table", RelationGetRelationName(rel)), errdetail("Partitioned tables cannot have BEFORE / FOR EACH ROW triggers.")));




			
			if (stmt->transitionRels != NIL)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("\"%s\" is a partitioned table", RelationGetRelationName(rel)), errdetail("Triggers on partitioned tables cannot have transition tables.")));



		}
	}
	else if (rel->rd_rel->relkind == RELKIND_VIEW)
	{
		
		if (stmt->timing == TRIGGER_TYPE_INSTEAD)
			ereport(ERROR, (errcode(ERRCODE_GP_FEATURE_NOT_YET), errmsg("INSTEAD OF triggers are not supported in Greenplum")));


		
		if (stmt->timing != TRIGGER_TYPE_INSTEAD && stmt->row)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is a view", RelationGetRelationName(rel)), errdetail("Views cannot have row-level BEFORE or AFTER triggers.")));



		
		if (TRIGGER_FOR_TRUNCATE(stmt->events))
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is a view", RelationGetRelationName(rel)), errdetail("Views cannot have TRUNCATE triggers.")));



	}
	else if (rel->rd_rel->relkind == RELKIND_FOREIGN_TABLE)
	{
		if (stmt->timing != TRIGGER_TYPE_BEFORE && stmt->timing != TRIGGER_TYPE_AFTER)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is a foreign table", RelationGetRelationName(rel)), errdetail("Foreign tables cannot have INSTEAD OF triggers.")));




		if (TRIGGER_FOR_TRUNCATE(stmt->events))
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is a foreign table", RelationGetRelationName(rel)), errdetail("Foreign tables cannot have TRUNCATE triggers.")));




		
		if (stmt->isconstraint)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is a foreign table", RelationGetRelationName(rel)), errdetail("Foreign tables cannot have constraint triggers.")));



	}
	else ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table or view", RelationGetRelationName(rel))));




	if (!allowSystemTableMods && IsSystemRelation(rel))
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied: \"%s\" is a system catalog", RelationGetRelationName(rel))));



	if (stmt->isconstraint)
	{
		
		if (OidIsValid(refRelOid))
		{
			LockRelationOid(refRelOid, AccessShareLock);
			constrrelid = refRelOid;
		}
		else if (stmt->constrrel != NULL)
			constrrelid = RangeVarGetRelid(stmt->constrrel, AccessShareLock, false);
	}

	
	if (!isInternal)
	{
		aclresult = pg_class_aclcheck(RelationGetRelid(rel), GetUserId(), ACL_TRIGGER);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, get_relkind_objtype(rel->rd_rel->relkind), RelationGetRelationName(rel));

		if (OidIsValid(constrrelid))
		{
			aclresult = pg_class_aclcheck(constrrelid, GetUserId(), ACL_TRIGGER);
			if (aclresult != ACLCHECK_OK)
				aclcheck_error(aclresult, get_relkind_objtype(get_rel_relkind(constrrelid)), get_rel_name(constrrelid));
		}
	}

	
	partition_recurse = !isInternal && stmt->row && rel->rd_rel->relkind == RELKIND_PARTITIONED_TABLE;
	if (partition_recurse)
		list_free(find_all_inheritors(RelationGetRelid(rel), ShareRowExclusiveLock, NULL));

	
	TRIGGER_CLEAR_TYPE(tgtype);
	if (stmt->row)
		TRIGGER_SETT_ROW(tgtype);
	tgtype |= stmt->timing;
	tgtype |= stmt->events;

	
	if (TRIGGER_FOR_ROW(tgtype) && TRIGGER_FOR_TRUNCATE(tgtype))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("TRUNCATE FOR EACH ROW triggers are not supported")));


	
	if (TRIGGER_FOR_INSTEAD(tgtype))
	{
		if (!TRIGGER_FOR_ROW(tgtype))
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("INSTEAD OF triggers must be FOR EACH ROW")));

		if (stmt->whenClause)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("INSTEAD OF triggers cannot have WHEN conditions")));

		if (stmt->columns != NIL)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("INSTEAD OF triggers cannot have column lists")));

	}

	
	if (stmt->transitionRels != NIL)
	{
		List	   *varList = stmt->transitionRels;
		ListCell   *lc;

		foreach(lc, varList)
		{
			TriggerTransition *tt = lfirst_node(TriggerTransition, lc);

			if (!(tt->isTable))
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("ROW variable naming in the REFERENCING clause is not supported"), errhint("Use OLD TABLE or NEW TABLE for naming transition tables.")));



			

			if (rel->rd_rel->relkind == RELKIND_FOREIGN_TABLE)
				ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is a foreign table", RelationGetRelationName(rel)), errdetail("Triggers on foreign tables cannot have transition tables.")));




			if (rel->rd_rel->relkind == RELKIND_VIEW)
				ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is a view", RelationGetRelationName(rel)), errdetail("Triggers on views cannot have transition tables.")));




			
			if (TRIGGER_FOR_ROW(tgtype) && has_superclass(rel->rd_id))
			{
				
				if (rel->rd_rel->relispartition)
					ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("ROW triggers with transition tables are not supported on partitions")));

				else ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("ROW triggers with transition tables are not supported on inheritance children")));


			}

			if (stmt->timing != TRIGGER_TYPE_AFTER)
				ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("transition table name can only be specified for an AFTER trigger")));


			if (TRIGGER_FOR_TRUNCATE(tgtype))
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("TRUNCATE triggers with transition tables are not supported")));


			
			if (((TRIGGER_FOR_INSERT(tgtype) ? 1 : 0) + (TRIGGER_FOR_UPDATE(tgtype) ? 1 : 0) + (TRIGGER_FOR_DELETE(tgtype) ? 1 : 0)) != 1)

				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("transition tables cannot be specified for triggers with more than one event")));


			
			if (stmt->columns != NIL)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("transition tables cannot be specified for triggers with column lists")));


			
			Assert(!stmt->isconstraint);

			if (tt->isNew)
			{
				if (!(TRIGGER_FOR_INSERT(tgtype) || TRIGGER_FOR_UPDATE(tgtype)))
					ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("NEW TABLE can only be specified for an INSERT or UPDATE trigger")));


				if (newtablename != NULL)
					ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("NEW TABLE cannot be specified multiple times")));


				newtablename = tt->name;
			}
			else {
				if (!(TRIGGER_FOR_DELETE(tgtype) || TRIGGER_FOR_UPDATE(tgtype)))
					ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("OLD TABLE can only be specified for a DELETE or UPDATE trigger")));


				if (oldtablename != NULL)
					ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("OLD TABLE cannot be specified multiple times")));


				oldtablename = tt->name;
			}
		}

		if (newtablename != NULL && oldtablename != NULL && strcmp(newtablename, oldtablename) == 0)
			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("OLD TABLE name and NEW TABLE name cannot be the same")));

	}

	
	if (!whenClause && stmt->whenClause)
	{
		ParseState *pstate;
		RangeTblEntry *rte;
		List	   *varList;
		ListCell   *lc;

		
		pstate = make_parsestate(NULL);
		pstate->p_sourcetext = queryString;

		
		rte = addRangeTableEntryForRelation(pstate, rel, AccessShareLock, makeAlias("old", NIL), false, false);


		addRTEtoQuery(pstate, rte, false, true, true);
		rte = addRangeTableEntryForRelation(pstate, rel, AccessShareLock, makeAlias("new", NIL), false, false);


		addRTEtoQuery(pstate, rte, false, true, true);

		
		whenClause = transformWhereClause(pstate, copyObject(stmt->whenClause), EXPR_KIND_TRIGGER_WHEN, "WHEN");


		
		assign_expr_collations(pstate, whenClause);

		
		varList = pull_var_clause(whenClause, 0);
		foreach(lc, varList)
		{
			Var		   *var = (Var *) lfirst(lc);

			switch (var->varno)
			{
				case PRS2_OLD_VARNO:
					if (!TRIGGER_FOR_ROW(tgtype))
						ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("statement trigger's WHEN condition cannot reference column values"), parser_errposition(pstate, var->location)));


					if (TRIGGER_FOR_INSERT(tgtype))
						ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("INSERT trigger's WHEN condition cannot reference OLD values"), parser_errposition(pstate, var->location)));


					
					break;
				case PRS2_NEW_VARNO:
					if (!TRIGGER_FOR_ROW(tgtype))
						ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("statement trigger's WHEN condition cannot reference column values"), parser_errposition(pstate, var->location)));


					if (TRIGGER_FOR_DELETE(tgtype))
						ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("DELETE trigger's WHEN condition cannot reference NEW values"), parser_errposition(pstate, var->location)));


					if (var->varattno < 0 && TRIGGER_FOR_BEFORE(tgtype))
						ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("BEFORE trigger's WHEN condition cannot reference NEW system columns"), parser_errposition(pstate, var->location)));


					if (TRIGGER_FOR_BEFORE(tgtype) && var->varattno == 0 && RelationGetDescr(rel)->constr && RelationGetDescr(rel)->constr->has_generated_stored)


						ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("BEFORE trigger's WHEN condition cannot reference NEW generated columns"), errdetail("A whole-row reference is used and the table contains generated columns."), parser_errposition(pstate, var->location)));



					if (TRIGGER_FOR_BEFORE(tgtype) && var->varattno > 0 && TupleDescAttr(RelationGetDescr(rel), var->varattno - 1)->attgenerated)

						ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("BEFORE trigger's WHEN condition cannot reference NEW generated columns"), errdetail("Column \"%s\" is a generated column.", NameStr(TupleDescAttr(RelationGetDescr(rel), var->varattno - 1)->attname)), parser_errposition(pstate, var->location)));




					break;
				default:
					
					elog(ERROR, "trigger WHEN condition cannot contain references to other relations");
					break;
			}
		}

		
		whenRtable = pstate->p_rtable;

		qual = nodeToString(whenClause);

		free_parsestate(pstate);
	}
	else if (!whenClause)
	{
		whenClause = NULL;
		whenRtable = NIL;
		qual = NULL;
	}
	else {
		qual = nodeToString(whenClause);
		whenRtable = NIL;
	}

	
	if (!OidIsValid(funcoid))
		funcoid = LookupFuncName(stmt->funcname, 0, NULL, false);
	if (!isInternal)
	{
		aclresult = pg_proc_aclcheck(funcoid, GetUserId(), ACL_EXECUTE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, OBJECT_FUNCTION, NameListToString(stmt->funcname));
	}
	funcrettype = get_func_rettype(funcoid);
	if (funcrettype != TRIGGEROID)
	{
		
		if (funcrettype == OPAQUEOID)
		{
			if (Gp_role != GP_ROLE_EXECUTE)
			ereport(WARNING, (errmsg("changing return type of function %s from %s to %s", NameListToString(stmt->funcname), "opaque", "trigger")));


			SetFunctionReturnType(funcoid, TRIGGEROID);
		}
		else ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("function %s must return type %s", NameListToString(stmt->funcname), "trigger")));



	}

	
	if (RelationIsAppendOptimized(rel) && TRIGGER_FOR_ROW(tgtype) && !stmt->isconstraint)

	{
		if (TRIGGER_FOR_UPDATE(tgtype))
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("ON UPDATE triggers are not supported on append-only tables")));

		if (TRIGGER_FOR_DELETE(tgtype))
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("ON DELETE triggers are not supported on append-only tables")));

	}

	
	if (stmt->isconstraint && !isInternal && list_length(stmt->args) >= 6 && (list_length(stmt->args) % 2) == 0 && RI_FKey_trigger_type(funcoid) != RI_TRIGGER_NONE)


	{
		
		table_close(rel, NoLock);

		ConvertTriggerToFK(stmt, funcoid);

		return InvalidObjectAddress;
	}

	
	if (stmt->isconstraint && !OidIsValid(constraintOid))
	{
		
		Assert(!isInternal);
		constraintOid = CreateConstraintEntry(stmt->trigname, RelationGetNamespace(rel), CONSTRAINT_TRIGGER, stmt->deferrable, stmt->initdeferred, true, InvalidOid, RelationGetRelid(rel), NULL, 0, 0, InvalidOid, InvalidOid, InvalidOid, NULL, NULL, NULL, NULL, 0, ' ', ' ', ' ', NULL, NULL, NULL, true, 0, true, isInternal);



























	}

	
	tgrel = table_open(TriggerRelationId, RowExclusiveLock);

	
	trigoid = GetNewOidForTrigger(tgrel, TriggerOidIndexId, Anum_pg_trigger_oid, RelationGetRelid(rel), stmt->trigname, constraintOid, funcoid);





	
	if (isInternal)
	{
		snprintf(internaltrigname, sizeof(internaltrigname), "%s_%u", stmt->trigname, trigoid);
		trigname = internaltrigname;
	}
	else {
		
		trigname = stmt->trigname;
	}

	
	if (!isInternal)
	{
		ScanKeyInit(&key, Anum_pg_trigger_tgrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(rel)));


		tgscan = systable_beginscan(tgrel, TriggerRelidNameIndexId, true, NULL, 1, &key);
		while (HeapTupleIsValid(tuple = systable_getnext(tgscan)))
		{
			Form_pg_trigger pg_trigger = (Form_pg_trigger) GETSTRUCT(tuple);

			if (namestrcmp(&(pg_trigger->tgname), trigname) == 0)
				ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("trigger \"%s\" for relation \"%s\" already exists", trigname, RelationGetRelationName(rel))));


		}
		systable_endscan(tgscan);
	}

	
	memset(nulls, false, sizeof(nulls));

	values[Anum_pg_trigger_oid - 1] = ObjectIdGetDatum(trigoid);
	values[Anum_pg_trigger_tgrelid - 1] = ObjectIdGetDatum(RelationGetRelid(rel));
	values[Anum_pg_trigger_tgname - 1] = DirectFunctionCall1(namein, CStringGetDatum(trigname));
	values[Anum_pg_trigger_tgfoid - 1] = ObjectIdGetDatum(funcoid);
	values[Anum_pg_trigger_tgtype - 1] = Int16GetDatum(tgtype);
	
	
	char		tgenabled = TRIGGER_FIRES_ON_ORIGIN;
	if (isInternal)
	{
		if (RI_FKey_trigger_type(funcoid))
		{
			tgenabled = TRIGGER_DISABLED;
		}
		else if (funcoid == F_UNIQUE_KEY_RECHECK)
		{
			
		}
		else elog(WARNING, "unrecognized internal trigger function %u", funcoid);
	}
	values[Anum_pg_trigger_tgenabled - 1] = CharGetDatum(tgenabled);
	values[Anum_pg_trigger_tgisinternal - 1] = BoolGetDatum(isInternal || in_partition);
	values[Anum_pg_trigger_tgconstrrelid - 1] = ObjectIdGetDatum(constrrelid);
	values[Anum_pg_trigger_tgconstrindid - 1] = ObjectIdGetDatum(indexOid);
	values[Anum_pg_trigger_tgconstraint - 1] = ObjectIdGetDatum(constraintOid);
	values[Anum_pg_trigger_tgdeferrable - 1] = BoolGetDatum(stmt->deferrable);
	values[Anum_pg_trigger_tginitdeferred - 1] = BoolGetDatum(stmt->initdeferred);

	if (stmt->args)
	{
		ListCell   *le;
		char	   *args;
		int16		nargs = list_length(stmt->args);
		int			len = 0;

		foreach(le, stmt->args)
		{
			char	   *ar = strVal(lfirst(le));

			len += strlen(ar) + 4;
			for (; *ar; ar++)
			{
				if (*ar == '\\')
					len++;
			}
		}
		args = (char *) palloc(len + 1);
		args[0] = '\0';
		foreach(le, stmt->args)
		{
			char	   *s = strVal(lfirst(le));
			char	   *d = args + strlen(args);

			while (*s)
			{
				if (*s == '\\')
					*d++ = '\\';
				*d++ = *s++;
			}
			strcpy(d, "\\000");
		}
		values[Anum_pg_trigger_tgnargs - 1] = Int16GetDatum(nargs);
		values[Anum_pg_trigger_tgargs - 1] = DirectFunctionCall1(byteain, CStringGetDatum(args));
	}
	else {
		values[Anum_pg_trigger_tgnargs - 1] = Int16GetDatum(0);
		values[Anum_pg_trigger_tgargs - 1] = DirectFunctionCall1(byteain, CStringGetDatum(""));
	}

	
	ncolumns = list_length(stmt->columns);
	if (ncolumns == 0)
		columns = NULL;
	else {
		ListCell   *cell;
		int			i = 0;

		columns = (int16 *) palloc(ncolumns * sizeof(int16));
		foreach(cell, stmt->columns)
		{
			char	   *name = strVal(lfirst(cell));
			int16		attnum;
			int			j;

			
			attnum = attnameAttNum(rel, name, false);
			if (attnum == InvalidAttrNumber)
				ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" of relation \"%s\" does not exist", name, RelationGetRelationName(rel))));



			
			for (j = i - 1; j >= 0; j--)
			{
				if (columns[j] == attnum)
					ereport(ERROR, (errcode(ERRCODE_DUPLICATE_COLUMN), errmsg("column \"%s\" specified more than once", name)));


			}

			columns[i++] = attnum;
		}
	}
	tgattr = buildint2vector(columns, ncolumns);
	values[Anum_pg_trigger_tgattr - 1] = PointerGetDatum(tgattr);

	
	if (qual)
		values[Anum_pg_trigger_tgqual - 1] = CStringGetTextDatum(qual);
	else nulls[Anum_pg_trigger_tgqual - 1] = true;

	if (oldtablename)
		values[Anum_pg_trigger_tgoldtable - 1] = DirectFunctionCall1(namein, CStringGetDatum(oldtablename));
	else nulls[Anum_pg_trigger_tgoldtable - 1] = true;
	if (newtablename)
		values[Anum_pg_trigger_tgnewtable - 1] = DirectFunctionCall1(namein, CStringGetDatum(newtablename));
	else nulls[Anum_pg_trigger_tgnewtable - 1] = true;

	tuple = heap_form_tuple(tgrel->rd_att, values, nulls);

	
	CatalogTupleInsert(tgrel, tuple);

	heap_freetuple(tuple);
	table_close(tgrel, RowExclusiveLock);

	pfree(DatumGetPointer(values[Anum_pg_trigger_tgname - 1]));
	pfree(DatumGetPointer(values[Anum_pg_trigger_tgargs - 1]));
	pfree(DatumGetPointer(values[Anum_pg_trigger_tgattr - 1]));
	if (oldtablename)
		pfree(DatumGetPointer(values[Anum_pg_trigger_tgoldtable - 1]));
	if (newtablename)
		pfree(DatumGetPointer(values[Anum_pg_trigger_tgnewtable - 1]));

	
	pgrel = table_open(RelationRelationId, RowExclusiveLock);
	tuple = SearchSysCacheCopy1(RELOID, ObjectIdGetDatum(RelationGetRelid(rel)));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for relation %u", RelationGetRelid(rel));
	if (!((Form_pg_class) GETSTRUCT(tuple))->relhastriggers)
	{
		((Form_pg_class) GETSTRUCT(tuple))->relhastriggers = true;

		CatalogTupleUpdate(pgrel, &tuple->t_self, tuple);

		CommandCounterIncrement();
	}
	else CacheInvalidateRelcacheByTuple(tuple);

	heap_freetuple(tuple);
	table_close(pgrel, RowExclusiveLock);

	
	myself.classId = TriggerRelationId;
	myself.objectId = trigoid;
	myself.objectSubId = 0;

	referenced.classId = ProcedureRelationId;
	referenced.objectId = funcoid;
	referenced.objectSubId = 0;
	recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);

	if (isInternal && OidIsValid(constraintOid))
	{
		
		referenced.classId = ConstraintRelationId;
		referenced.objectId = constraintOid;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_INTERNAL);
	}
	else {
		
		referenced.classId = RelationRelationId;
		referenced.objectId = RelationGetRelid(rel);
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_AUTO);

		if (OidIsValid(constrrelid))
		{
			referenced.classId = RelationRelationId;
			referenced.objectId = constrrelid;
			referenced.objectSubId = 0;
			recordDependencyOn(&myself, &referenced, DEPENDENCY_AUTO);
		}
		
		Assert(!OidIsValid(indexOid));

		
		if (OidIsValid(constraintOid))
		{
			referenced.classId = ConstraintRelationId;
			referenced.objectId = constraintOid;
			referenced.objectSubId = 0;
			recordDependencyOn(&referenced, &myself, DEPENDENCY_INTERNAL);
		}

		
		if (OidIsValid(parentTriggerOid))
		{
			ObjectAddressSet(referenced, TriggerRelationId, parentTriggerOid);
			recordDependencyOn(&myself, &referenced, DEPENDENCY_PARTITION_PRI);
			ObjectAddressSet(referenced, RelationRelationId, RelationGetRelid(rel));
			recordDependencyOn(&myself, &referenced, DEPENDENCY_PARTITION_SEC);
		}
	}

	
	if (columns != NULL)
	{
		int			i;

		referenced.classId = RelationRelationId;
		referenced.objectId = RelationGetRelid(rel);
		for (i = 0; i < ncolumns; i++)
		{
			referenced.objectSubId = columns[i];
			recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
		}
	}

	
	if (whenRtable != NIL)
		recordDependencyOnExpr(&myself, whenClause, whenRtable, DEPENDENCY_NORMAL);

	
	InvokeObjectPostCreateHookArg(TriggerRelationId, trigoid, 0, isInternal);

	
	if (partition_recurse)
	{
		PartitionDesc partdesc = RelationGetPartitionDesc(rel);
		List	   *idxs = NIL;
		List	   *childTbls = NIL;
		ListCell   *l;
		int			i;
		MemoryContext oldcxt, perChildCxt;

		perChildCxt = AllocSetContextCreate(CurrentMemoryContext, "part trig clone", ALLOCSET_SMALL_SIZES);


		
		if (OidIsValid(indexOid))
		{
			ListCell   *l;
			List	   *idxs = NIL;

			idxs = find_inheritance_children(indexOid, ShareRowExclusiveLock);
			foreach(l, idxs)
				childTbls = lappend_oid(childTbls, IndexGetRelation(lfirst_oid(l), false));

		}

		oldcxt = MemoryContextSwitchTo(perChildCxt);

		
		for (i = 0; i < partdesc->nparts; i++)
		{
			Oid			indexOnChild = InvalidOid;
			ListCell   *l2;
			CreateTrigStmt *childStmt;
			Relation	childTbl;
			Node	   *qual;
			bool		found_whole_row;

			childTbl = table_open(partdesc->oids[i], ShareRowExclusiveLock);

			
			if (OidIsValid(indexOid))
			{
				forboth(l, idxs, l2, childTbls)
				{
					if (lfirst_oid(l2) == partdesc->oids[i])
					{
						indexOnChild = lfirst_oid(l);
						break;
					}
				}
				if (!OidIsValid(indexOnChild))
					elog(ERROR, "failed to find index matching index \"%s\" in partition \"%s\"", get_rel_name(indexOid), get_rel_name(partdesc->oids[i]));

			}

			
			childStmt = (CreateTrigStmt *) copyObject(stmt);
			childStmt->funcname = NIL;
			childStmt->args = NIL;
			childStmt->whenClause = NULL;

			
			qual = copyObject(whenClause);
			qual = (Node *)
				map_partition_varattnos((List *) qual, PRS2_OLD_VARNO, childTbl, rel, &found_whole_row);

			if (found_whole_row)
				elog(ERROR, "unexpected whole-row reference found in trigger WHEN clause");
			qual = (Node *)
				map_partition_varattnos((List *) qual, PRS2_NEW_VARNO, childTbl, rel, &found_whole_row);

			if (found_whole_row)
				elog(ERROR, "unexpected whole-row reference found in trigger WHEN clause");

			CreateTrigger(childStmt, queryString, partdesc->oids[i], refRelOid, InvalidOid, indexOnChild, funcoid, trigoid, qual, isInternal, true);




			table_close(childTbl, NoLock);

			MemoryContextReset(perChildCxt);
		}

		MemoryContextSwitchTo(oldcxt);
		MemoryContextDelete(perChildCxt);
		list_free(idxs);
		list_free(childTbls);
	}

	
	table_close(rel, NoLock);

	return myself;
}



typedef struct {
	List	   *args;			
	Oid			funcoids[3];	
	
} OldTriggerInfo;

static void ConvertTriggerToFK(CreateTrigStmt *stmt, Oid funcoid)
{
	static List *info_list = NIL;

	static const char *const funcdescr[3] = {
		gettext_noop("Found referenced table's UPDATE trigger."), gettext_noop("Found referenced table's DELETE trigger."), gettext_noop("Found referencing table's trigger.")

	};

	char	   *constr_name;
	char	   *fk_table_name;
	char	   *pk_table_name;
	char		fk_matchtype = FKCONSTR_MATCH_SIMPLE;
	List	   *fk_attrs = NIL;
	List	   *pk_attrs = NIL;
	StringInfoData buf;
	int			funcnum;
	OldTriggerInfo *info = NULL;
	ListCell   *l;
	int			i;

	
	constr_name = strVal(linitial(stmt->args));
	fk_table_name = strVal(lsecond(stmt->args));
	pk_table_name = strVal(lthird(stmt->args));
	i = 0;
	foreach(l, stmt->args)
	{
		Value	   *arg = (Value *) lfirst(l);

		i++;
		if (i < 4)				
			continue;
		if (i == 4)				
		{
			if (strcmp(strVal(arg), "FULL") == 0)
				fk_matchtype = FKCONSTR_MATCH_FULL;
			else fk_matchtype = FKCONSTR_MATCH_SIMPLE;
			continue;
		}
		if (i % 2)
			fk_attrs = lappend(fk_attrs, arg);
		else pk_attrs = lappend(pk_attrs, arg);
	}

	
	initStringInfo(&buf);
	appendStringInfo(&buf, "FOREIGN KEY %s(", quote_identifier(fk_table_name));
	i = 0;
	foreach(l, fk_attrs)
	{
		Value	   *arg = (Value *) lfirst(l);

		if (i++ > 0)
			appendStringInfoChar(&buf, ',');
		appendStringInfoString(&buf, quote_identifier(strVal(arg)));
	}
	appendStringInfo(&buf, ") REFERENCES %s(", quote_identifier(pk_table_name));
	i = 0;
	foreach(l, pk_attrs)
	{
		Value	   *arg = (Value *) lfirst(l);

		if (i++ > 0)
			appendStringInfoChar(&buf, ',');
		appendStringInfoString(&buf, quote_identifier(strVal(arg)));
	}
	appendStringInfoChar(&buf, ')');

	
	switch (funcoid)
	{
		case F_RI_FKEY_CASCADE_UPD:
		case F_RI_FKEY_RESTRICT_UPD:
		case F_RI_FKEY_SETNULL_UPD:
		case F_RI_FKEY_SETDEFAULT_UPD:
		case F_RI_FKEY_NOACTION_UPD:
			funcnum = 0;
			break;

		case F_RI_FKEY_CASCADE_DEL:
		case F_RI_FKEY_RESTRICT_DEL:
		case F_RI_FKEY_SETNULL_DEL:
		case F_RI_FKEY_SETDEFAULT_DEL:
		case F_RI_FKEY_NOACTION_DEL:
			funcnum = 1;
			break;

		default:
			funcnum = 2;
			break;
	}

	
	foreach(l, info_list)
	{
		info = (OldTriggerInfo *) lfirst(l);
		if (info->funcoids[funcnum] == InvalidOid && equal(info->args, stmt->args))
		{
			info->funcoids[funcnum] = funcoid;
			break;
		}
	}

	if (l == NULL)
	{
		
		MemoryContext oldContext;

		ereport(NOTICE, (errmsg("ignoring incomplete trigger group for constraint \"%s\" %s", constr_name, buf.data), errdetail_internal("%s", _(funcdescr[funcnum]))));


		oldContext = MemoryContextSwitchTo(TopMemoryContext);
		info = (OldTriggerInfo *) palloc0(sizeof(OldTriggerInfo));
		info->args = copyObject(stmt->args);
		info->funcoids[funcnum] = funcoid;
		info_list = lappend(info_list, info);
		MemoryContextSwitchTo(oldContext);
	}
	else if (info->funcoids[0] == InvalidOid || info->funcoids[1] == InvalidOid || info->funcoids[2] == InvalidOid)

	{
		
		ereport(NOTICE, (errmsg("ignoring incomplete trigger group for constraint \"%s\" %s", constr_name, buf.data), errdetail_internal("%s", _(funcdescr[funcnum]))));


	}
	else {
		
		AlterTableStmt *atstmt = makeNode(AlterTableStmt);
		AlterTableCmd *atcmd = makeNode(AlterTableCmd);
		Constraint *fkcon = makeNode(Constraint);
		PlannedStmt *wrapper = makeNode(PlannedStmt);

		ereport(NOTICE, (errmsg("converting trigger group into constraint \"%s\" %s", constr_name, buf.data), errdetail_internal("%s", _(funcdescr[funcnum]))));


		fkcon->contype = CONSTR_FOREIGN;
		fkcon->location = -1;
		if (funcnum == 2)
		{
			
			atstmt->relation = stmt->relation;
			if (stmt->constrrel)
				fkcon->pktable = stmt->constrrel;
			else {
				
				fkcon->pktable = makeRangeVar(NULL, pk_table_name, -1);
			}
		}
		else {
			
			fkcon->pktable = stmt->relation;
			if (stmt->constrrel)
				atstmt->relation = stmt->constrrel;
			else {
				
				atstmt->relation = makeRangeVar(NULL, fk_table_name, -1);
			}
		}
		atstmt->cmds = list_make1(atcmd);
		atstmt->relkind = OBJECT_TABLE;
		atcmd->subtype = AT_AddConstraint;
		atcmd->def = (Node *) fkcon;
		if (strcmp(constr_name, "<unnamed>") == 0)
			fkcon->conname = NULL;
		else fkcon->conname = constr_name;
		fkcon->fk_attrs = fk_attrs;
		fkcon->pk_attrs = pk_attrs;
		fkcon->fk_matchtype = fk_matchtype;
		switch (info->funcoids[0])
		{
			case F_RI_FKEY_NOACTION_UPD:
				fkcon->fk_upd_action = FKCONSTR_ACTION_NOACTION;
				break;
			case F_RI_FKEY_CASCADE_UPD:
				fkcon->fk_upd_action = FKCONSTR_ACTION_CASCADE;
				break;
			case F_RI_FKEY_RESTRICT_UPD:
				fkcon->fk_upd_action = FKCONSTR_ACTION_RESTRICT;
				break;
			case F_RI_FKEY_SETNULL_UPD:
				fkcon->fk_upd_action = FKCONSTR_ACTION_SETNULL;
				break;
			case F_RI_FKEY_SETDEFAULT_UPD:
				fkcon->fk_upd_action = FKCONSTR_ACTION_SETDEFAULT;
				break;
			default:
				
				elog(ERROR, "confused about RI update function");
		}
		switch (info->funcoids[1])
		{
			case F_RI_FKEY_NOACTION_DEL:
				fkcon->fk_del_action = FKCONSTR_ACTION_NOACTION;
				break;
			case F_RI_FKEY_CASCADE_DEL:
				fkcon->fk_del_action = FKCONSTR_ACTION_CASCADE;
				break;
			case F_RI_FKEY_RESTRICT_DEL:
				fkcon->fk_del_action = FKCONSTR_ACTION_RESTRICT;
				break;
			case F_RI_FKEY_SETNULL_DEL:
				fkcon->fk_del_action = FKCONSTR_ACTION_SETNULL;
				break;
			case F_RI_FKEY_SETDEFAULT_DEL:
				fkcon->fk_del_action = FKCONSTR_ACTION_SETDEFAULT;
				break;
			default:
				
				elog(ERROR, "confused about RI delete function");
		}
		fkcon->deferrable = stmt->deferrable;
		fkcon->initdeferred = stmt->initdeferred;
		fkcon->skip_validation = false;
		fkcon->initially_valid = true;

		
		wrapper->commandType = CMD_UTILITY;
		wrapper->canSetTag = false;
		wrapper->utilityStmt = (Node *) atstmt;
		wrapper->stmt_location = -1;
		wrapper->stmt_len = -1;

		
		ProcessUtility(wrapper, "(generated ALTER TABLE ADD FOREIGN KEY command)", PROCESS_UTILITY_SUBCOMMAND, NULL, NULL, None_Receiver, NULL);



		
		info_list = list_delete_ptr(info_list, info);
		pfree(info);
		
	}
}


void RemoveTriggerById(Oid trigOid)
{
	Relation	tgrel;
	SysScanDesc tgscan;
	ScanKeyData skey[1];
	HeapTuple	tup;
	Oid			relid;
	Relation	rel;

	tgrel = table_open(TriggerRelationId, RowExclusiveLock);

	
	ScanKeyInit(&skey[0], Anum_pg_trigger_oid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(trigOid));



	tgscan = systable_beginscan(tgrel, TriggerOidIndexId, true, NULL, 1, skey);

	tup = systable_getnext(tgscan);
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "could not find tuple for trigger %u", trigOid);

	
	relid = ((Form_pg_trigger) GETSTRUCT(tup))->tgrelid;

	rel = table_open(relid, AccessExclusiveLock);

	if (rel->rd_rel->relkind != RELKIND_RELATION && rel->rd_rel->relkind != RELKIND_VIEW && rel->rd_rel->relkind != RELKIND_FOREIGN_TABLE && rel->rd_rel->relkind != RELKIND_PARTITIONED_TABLE)


		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table, view, or foreign table", RelationGetRelationName(rel))));



	if (!allowSystemTableMods && IsSystemRelation(rel))
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied: \"%s\" is a system catalog", RelationGetRelationName(rel))));



	
	CatalogTupleDelete(tgrel, &tup->t_self);

	systable_endscan(tgscan);
	table_close(tgrel, RowExclusiveLock);

	
	CacheInvalidateRelcache(rel);

	
	table_close(rel, NoLock);
}


Oid get_trigger_oid(Oid relid, const char *trigname, bool missing_ok)
{
	Relation	tgrel;
	ScanKeyData skey[2];
	SysScanDesc tgscan;
	HeapTuple	tup;
	Oid			oid;

	
	tgrel = table_open(TriggerRelationId, AccessShareLock);

	ScanKeyInit(&skey[0], Anum_pg_trigger_tgrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relid));


	ScanKeyInit(&skey[1], Anum_pg_trigger_tgname, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(trigname));



	tgscan = systable_beginscan(tgrel, TriggerRelidNameIndexId, true, NULL, 2, skey);

	tup = systable_getnext(tgscan);

	if (!HeapTupleIsValid(tup))
	{
		if (!missing_ok)
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("trigger \"%s\" for table \"%s\" does not exist", trigname, get_rel_name(relid))));


		oid = InvalidOid;
	}
	else {
		oid = ((Form_pg_trigger) GETSTRUCT(tup))->oid;
	}

	systable_endscan(tgscan);
	table_close(tgrel, AccessShareLock);
	return oid;
}


static void RangeVarCallbackForRenameTrigger(const RangeVar *rv, Oid relid, Oid oldrelid, void *arg)

{
	HeapTuple	tuple;
	Form_pg_class form;

	tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(relid));
	if (!HeapTupleIsValid(tuple))
		return;					
	form = (Form_pg_class) GETSTRUCT(tuple);

	
	if (form->relkind != RELKIND_RELATION && form->relkind != RELKIND_VIEW && form->relkind != RELKIND_FOREIGN_TABLE && form->relkind != RELKIND_PARTITIONED_TABLE)

		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table, view, or foreign table", rv->relname)));



	
	if (!pg_class_ownercheck(relid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, get_relkind_objtype(get_rel_relkind(relid)), rv->relname);
	if (!allowSystemTableMods && IsSystemClass(relid, form))
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied: \"%s\" is a system catalog", rv->relname)));



	ReleaseSysCache(tuple);
}


ObjectAddress renametrig(RenameStmt *stmt)
{
	Oid			tgoid;
	Relation	targetrel;
	Relation	tgrel;
	HeapTuple	tuple;
	SysScanDesc tgscan;
	ScanKeyData key[2];
	Oid			relid;
	ObjectAddress address;

	
	relid = RangeVarGetRelidExtended(stmt->relation, AccessExclusiveLock, 0, RangeVarCallbackForRenameTrigger, NULL);



	
	targetrel = relation_open(relid, NoLock);

	
	tgrel = table_open(TriggerRelationId, RowExclusiveLock);

	
	ScanKeyInit(&key[0], Anum_pg_trigger_tgrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relid));


	ScanKeyInit(&key[1], Anum_pg_trigger_tgname, BTEqualStrategyNumber, F_NAMEEQ, PointerGetDatum(stmt->newname));


	tgscan = systable_beginscan(tgrel, TriggerRelidNameIndexId, true, NULL, 2, key);
	if (HeapTupleIsValid(tuple = systable_getnext(tgscan)))
		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("trigger \"%s\" for relation \"%s\" already exists", stmt->newname, RelationGetRelationName(targetrel))));


	systable_endscan(tgscan);

	
	ScanKeyInit(&key[0], Anum_pg_trigger_tgrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relid));


	ScanKeyInit(&key[1], Anum_pg_trigger_tgname, BTEqualStrategyNumber, F_NAMEEQ, PointerGetDatum(stmt->subname));


	tgscan = systable_beginscan(tgrel, TriggerRelidNameIndexId, true, NULL, 2, key);
	if (HeapTupleIsValid(tuple = systable_getnext(tgscan)))
	{
		Form_pg_trigger trigform;

		
		tuple = heap_copytuple(tuple);	
		trigform = (Form_pg_trigger) GETSTRUCT(tuple);
		tgoid = trigform->oid;

		namestrcpy(&trigform->tgname, stmt->newname);

		CatalogTupleUpdate(tgrel, &tuple->t_self, tuple);

		InvokeObjectPostAlterHook(TriggerRelationId, tgoid, 0);

		
		CacheInvalidateRelcache(targetrel);
	}
	else {
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("trigger \"%s\" for table \"%s\" does not exist", stmt->subname, RelationGetRelationName(targetrel))));


	}

	ObjectAddressSet(address, TriggerRelationId, tgoid);

	systable_endscan(tgscan);

	table_close(tgrel, RowExclusiveLock);

	
	relation_close(targetrel, NoLock);

	return address;
}



void EnableDisableTrigger(Relation rel, const char *tgname, char fires_when, bool skip_system, LOCKMODE lockmode)

{
	Relation	tgrel;
	int			nkeys;
	ScanKeyData keys[2];
	SysScanDesc tgscan;
	HeapTuple	tuple;
	bool		found;
	bool		changed;

	
	tgrel = table_open(TriggerRelationId, RowExclusiveLock);

	ScanKeyInit(&keys[0], Anum_pg_trigger_tgrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(rel)));


	if (tgname)
	{
		ScanKeyInit(&keys[1], Anum_pg_trigger_tgname, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(tgname));


		nkeys = 2;
	}
	else nkeys = 1;

	tgscan = systable_beginscan(tgrel, TriggerRelidNameIndexId, true, NULL, nkeys, keys);

	found = changed = false;

	while (HeapTupleIsValid(tuple = systable_getnext(tgscan)))
	{
		Form_pg_trigger oldtrig = (Form_pg_trigger) GETSTRUCT(tuple);

		if (oldtrig->tgisinternal)
		{
			
			if (skip_system)
				continue;
			if (!superuser())
				ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied: \"%s\" is a system trigger", NameStr(oldtrig->tgname))));


		}

		found = true;

		if (oldtrig->tgenabled != fires_when)
		{
			
			HeapTuple	newtup = heap_copytuple(tuple);
			Form_pg_trigger newtrig = (Form_pg_trigger) GETSTRUCT(newtup);

			newtrig->tgenabled = fires_when;

			CatalogTupleUpdate(tgrel, &newtup->t_self, newtup);

			heap_freetuple(newtup);

			
			if (rel->rd_rel->relkind == RELKIND_PARTITIONED_TABLE && (TRIGGER_FOR_ROW(oldtrig->tgtype)))
			{
				PartitionDesc partdesc = RelationGetPartitionDesc(rel);
				int			i;

				for (i = 0; i < partdesc->nparts; i++)
				{
					Relation	part;

					part = relation_open(partdesc->oids[i], lockmode);
					EnableDisableTrigger(part, NameStr(oldtrig->tgname), fires_when, skip_system, lockmode);
					table_close(part, NoLock);	
				}
			}

			changed = true;
		}

		InvokeObjectPostAlterHook(TriggerRelationId, oldtrig->oid, 0);
	}

	systable_endscan(tgscan);

	table_close(tgrel, RowExclusiveLock);

	if (tgname && !found)
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("trigger \"%s\" for table \"%s\" does not exist", tgname, RelationGetRelationName(rel))));



	
	if (changed)
		CacheInvalidateRelcache(rel);
}



void RelationBuildTriggers(Relation relation)
{
	TriggerDesc *trigdesc;
	int			numtrigs;
	int			maxtrigs;
	Trigger    *triggers;
	Relation	tgrel;
	ScanKeyData skey;
	SysScanDesc tgscan;
	HeapTuple	htup;
	MemoryContext oldContext;
	int			i;

	
	maxtrigs = 16;
	triggers = (Trigger *) palloc(maxtrigs * sizeof(Trigger));
	numtrigs = 0;

	
	ScanKeyInit(&skey, Anum_pg_trigger_tgrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationGetRelid(relation)));



	tgrel = table_open(TriggerRelationId, AccessShareLock);
	tgscan = systable_beginscan(tgrel, TriggerRelidNameIndexId, true, NULL, 1, &skey);

	while (HeapTupleIsValid(htup = systable_getnext(tgscan)))
	{
		Form_pg_trigger pg_trigger = (Form_pg_trigger) GETSTRUCT(htup);
		Trigger    *build;
		Datum		datum;
		bool		isnull;

		if (numtrigs >= maxtrigs)
		{
			maxtrigs *= 2;
			triggers = (Trigger *) repalloc(triggers, maxtrigs * sizeof(Trigger));
		}
		build = &(triggers[numtrigs]);

		build->tgoid = pg_trigger->oid;
		build->tgname = DatumGetCString(DirectFunctionCall1(nameout, NameGetDatum(&pg_trigger->tgname)));
		build->tgfoid = pg_trigger->tgfoid;
		build->tgtype = pg_trigger->tgtype;
		build->tgenabled = pg_trigger->tgenabled;
		build->tgisinternal = pg_trigger->tgisinternal;
		build->tgconstrrelid = pg_trigger->tgconstrrelid;
		build->tgconstrindid = pg_trigger->tgconstrindid;
		build->tgconstraint = pg_trigger->tgconstraint;
		build->tgdeferrable = pg_trigger->tgdeferrable;
		build->tginitdeferred = pg_trigger->tginitdeferred;
		build->tgnargs = pg_trigger->tgnargs;
		
		build->tgnattr = pg_trigger->tgattr.dim1;
		if (build->tgnattr > 0)
		{
			build->tgattr = (int16 *) palloc(build->tgnattr * sizeof(int16));
			memcpy(build->tgattr, &(pg_trigger->tgattr.values), build->tgnattr * sizeof(int16));
		}
		else build->tgattr = NULL;
		if (build->tgnargs > 0)
		{
			bytea	   *val;
			char	   *p;

			val = DatumGetByteaPP(fastgetattr(htup, Anum_pg_trigger_tgargs, tgrel->rd_att, &isnull));

			if (isnull)
				elog(ERROR, "tgargs is null in trigger for relation \"%s\"", RelationGetRelationName(relation));
			p = (char *) VARDATA_ANY(val);
			build->tgargs = (char **) palloc(build->tgnargs * sizeof(char *));
			for (i = 0; i < build->tgnargs; i++)
			{
				build->tgargs[i] = pstrdup(p);
				p += strlen(p) + 1;
			}
		}
		else build->tgargs = NULL;

		datum = fastgetattr(htup, Anum_pg_trigger_tgoldtable, tgrel->rd_att, &isnull);
		if (!isnull)
			build->tgoldtable = DatumGetCString(DirectFunctionCall1(nameout, datum));
		else build->tgoldtable = NULL;

		datum = fastgetattr(htup, Anum_pg_trigger_tgnewtable, tgrel->rd_att, &isnull);
		if (!isnull)
			build->tgnewtable = DatumGetCString(DirectFunctionCall1(nameout, datum));
		else build->tgnewtable = NULL;

		datum = fastgetattr(htup, Anum_pg_trigger_tgqual, tgrel->rd_att, &isnull);
		if (!isnull)
			build->tgqual = TextDatumGetCString(datum);
		else build->tgqual = NULL;

		numtrigs++;
	}

	systable_endscan(tgscan);
	table_close(tgrel, AccessShareLock);

	
	if (numtrigs == 0)
	{
		pfree(triggers);
		return;
	}

	
	trigdesc = (TriggerDesc *) palloc0(sizeof(TriggerDesc));
	trigdesc->triggers = triggers;
	trigdesc->numtriggers = numtrigs;
	for (i = 0; i < numtrigs; i++)
		SetTriggerFlags(trigdesc, &(triggers[i]));

	
	oldContext = MemoryContextSwitchTo(CacheMemoryContext);
	relation->trigdesc = CopyTriggerDesc(trigdesc);
	MemoryContextSwitchTo(oldContext);

	
	FreeTriggerDesc(trigdesc);
}


static void SetTriggerFlags(TriggerDesc *trigdesc, Trigger *trigger)
{
	int16		tgtype = trigger->tgtype;

	trigdesc->trig_insert_before_row |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_INSERT);

	trigdesc->trig_insert_after_row |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_AFTER, TRIGGER_TYPE_INSERT);

	trigdesc->trig_insert_instead_row |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_INSTEAD, TRIGGER_TYPE_INSERT);

	trigdesc->trig_insert_before_statement |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_INSERT);

	trigdesc->trig_insert_after_statement |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_AFTER, TRIGGER_TYPE_INSERT);

	trigdesc->trig_update_before_row |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_UPDATE);

	trigdesc->trig_update_after_row |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_AFTER, TRIGGER_TYPE_UPDATE);

	trigdesc->trig_update_instead_row |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_INSTEAD, TRIGGER_TYPE_UPDATE);

	trigdesc->trig_update_before_statement |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_UPDATE);

	trigdesc->trig_update_after_statement |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_AFTER, TRIGGER_TYPE_UPDATE);

	trigdesc->trig_delete_before_row |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_DELETE);

	trigdesc->trig_delete_after_row |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_AFTER, TRIGGER_TYPE_DELETE);

	trigdesc->trig_delete_instead_row |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_INSTEAD, TRIGGER_TYPE_DELETE);

	trigdesc->trig_delete_before_statement |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_DELETE);

	trigdesc->trig_delete_after_statement |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_AFTER, TRIGGER_TYPE_DELETE);

	
	trigdesc->trig_truncate_before_statement |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_TRUNCATE);

	trigdesc->trig_truncate_after_statement |= TRIGGER_TYPE_MATCHES(tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_AFTER, TRIGGER_TYPE_TRUNCATE);


	trigdesc->trig_insert_new_table |= (TRIGGER_FOR_INSERT(tgtype) && TRIGGER_USES_TRANSITION_TABLE(trigger->tgnewtable));

	trigdesc->trig_update_old_table |= (TRIGGER_FOR_UPDATE(tgtype) && TRIGGER_USES_TRANSITION_TABLE(trigger->tgoldtable));

	trigdesc->trig_update_new_table |= (TRIGGER_FOR_UPDATE(tgtype) && TRIGGER_USES_TRANSITION_TABLE(trigger->tgnewtable));

	trigdesc->trig_delete_old_table |= (TRIGGER_FOR_DELETE(tgtype) && TRIGGER_USES_TRANSITION_TABLE(trigger->tgoldtable));

}


TriggerDesc * CopyTriggerDesc(TriggerDesc *trigdesc)
{
	TriggerDesc *newdesc;
	Trigger    *trigger;
	int			i;

	if (trigdesc == NULL || trigdesc->numtriggers <= 0)
		return NULL;

	newdesc = (TriggerDesc *) palloc(sizeof(TriggerDesc));
	memcpy(newdesc, trigdesc, sizeof(TriggerDesc));

	trigger = (Trigger *) palloc(trigdesc->numtriggers * sizeof(Trigger));
	memcpy(trigger, trigdesc->triggers, trigdesc->numtriggers * sizeof(Trigger));
	newdesc->triggers = trigger;

	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		trigger->tgname = pstrdup(trigger->tgname);
		if (trigger->tgnattr > 0)
		{
			int16	   *newattr;

			newattr = (int16 *) palloc(trigger->tgnattr * sizeof(int16));
			memcpy(newattr, trigger->tgattr, trigger->tgnattr * sizeof(int16));
			trigger->tgattr = newattr;
		}
		if (trigger->tgnargs > 0)
		{
			char	  **newargs;
			int16		j;

			newargs = (char **) palloc(trigger->tgnargs * sizeof(char *));
			for (j = 0; j < trigger->tgnargs; j++)
				newargs[j] = pstrdup(trigger->tgargs[j]);
			trigger->tgargs = newargs;
		}
		if (trigger->tgqual)
			trigger->tgqual = pstrdup(trigger->tgqual);
		if (trigger->tgoldtable)
			trigger->tgoldtable = pstrdup(trigger->tgoldtable);
		if (trigger->tgnewtable)
			trigger->tgnewtable = pstrdup(trigger->tgnewtable);
		trigger++;
	}

	return newdesc;
}


void FreeTriggerDesc(TriggerDesc *trigdesc)
{
	Trigger    *trigger;
	int			i;

	if (trigdesc == NULL)
		return;

	trigger = trigdesc->triggers;
	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		pfree(trigger->tgname);
		if (trigger->tgnattr > 0)
			pfree(trigger->tgattr);
		if (trigger->tgnargs > 0)
		{
			while (--(trigger->tgnargs) >= 0)
				pfree(trigger->tgargs[trigger->tgnargs]);
			pfree(trigger->tgargs);
		}
		if (trigger->tgqual)
			pfree(trigger->tgqual);
		if (trigger->tgoldtable)
			pfree(trigger->tgoldtable);
		if (trigger->tgnewtable)
			pfree(trigger->tgnewtable);
		trigger++;
	}
	pfree(trigdesc->triggers);
	pfree(trigdesc);
}



bool equalTriggerDescs(TriggerDesc *trigdesc1, TriggerDesc *trigdesc2)
{
	int			i, j;

	
	if (trigdesc1 != NULL)
	{
		if (trigdesc2 == NULL)
			return false;
		if (trigdesc1->numtriggers != trigdesc2->numtriggers)
			return false;
		for (i = 0; i < trigdesc1->numtriggers; i++)
		{
			Trigger    *trig1 = trigdesc1->triggers + i;
			Trigger    *trig2 = trigdesc2->triggers + i;

			if (trig1->tgoid != trig2->tgoid)
				return false;
			if (strcmp(trig1->tgname, trig2->tgname) != 0)
				return false;
			if (trig1->tgfoid != trig2->tgfoid)
				return false;
			if (trig1->tgtype != trig2->tgtype)
				return false;
			if (trig1->tgenabled != trig2->tgenabled)
				return false;
			if (trig1->tgisinternal != trig2->tgisinternal)
				return false;
			if (trig1->tgconstrrelid != trig2->tgconstrrelid)
				return false;
			if (trig1->tgconstrindid != trig2->tgconstrindid)
				return false;
			if (trig1->tgconstraint != trig2->tgconstraint)
				return false;
			if (trig1->tgdeferrable != trig2->tgdeferrable)
				return false;
			if (trig1->tginitdeferred != trig2->tginitdeferred)
				return false;
			if (trig1->tgnargs != trig2->tgnargs)
				return false;
			if (trig1->tgnattr != trig2->tgnattr)
				return false;
			if (trig1->tgnattr > 0 && memcmp(trig1->tgattr, trig2->tgattr, trig1->tgnattr * sizeof(int16)) != 0)

				return false;
			for (j = 0; j < trig1->tgnargs; j++)
				if (strcmp(trig1->tgargs[j], trig2->tgargs[j]) != 0)
					return false;
			if (trig1->tgqual == NULL && trig2->tgqual == NULL)
				  ;
			else if (trig1->tgqual == NULL || trig2->tgqual == NULL)
				return false;
			else if (strcmp(trig1->tgqual, trig2->tgqual) != 0)
				return false;
			if (trig1->tgoldtable == NULL && trig2->tgoldtable == NULL)
				  ;
			else if (trig1->tgoldtable == NULL || trig2->tgoldtable == NULL)
				return false;
			else if (strcmp(trig1->tgoldtable, trig2->tgoldtable) != 0)
				return false;
			if (trig1->tgnewtable == NULL && trig2->tgnewtable == NULL)
				  ;
			else if (trig1->tgnewtable == NULL || trig2->tgnewtable == NULL)
				return false;
			else if (strcmp(trig1->tgnewtable, trig2->tgnewtable) != 0)
				return false;
		}
	}
	else if (trigdesc2 != NULL)
		return false;
	return true;
}



const char * FindTriggerIncompatibleWithInheritance(TriggerDesc *trigdesc)
{
	if (trigdesc != NULL)
	{
		int			i;

		for (i = 0; i < trigdesc->numtriggers; ++i)
		{
			Trigger    *trigger = &trigdesc->triggers[i];

			if (trigger->tgoldtable != NULL || trigger->tgnewtable != NULL)
				return trigger->tgname;
		}
	}

	return NULL;
}


static HeapTuple ExecCallTriggerFunc(TriggerData *trigdata, int tgindx, FmgrInfo *finfo, Instrumentation *instr, MemoryContext per_tuple_context)




{
	LOCAL_FCINFO(fcinfo, 0);
	PgStat_FunctionCallUsage fcusage;
	Datum		result;
	MemoryContext oldContext;

	
	Assert(((TRIGGER_FIRED_BY_INSERT(trigdata->tg_event) || TRIGGER_FIRED_BY_UPDATE(trigdata->tg_event) || TRIGGER_FIRED_BY_DELETE(trigdata->tg_event)) && TRIGGER_FIRED_AFTER(trigdata->tg_event) && !(trigdata->tg_event & AFTER_TRIGGER_DEFERRABLE) && !(trigdata->tg_event & AFTER_TRIGGER_INITDEFERRED)) || (trigdata->tg_oldtable == NULL && trigdata->tg_newtable == NULL));






	finfo += tgindx;

	
	if (finfo->fn_oid == InvalidOid)
		fmgr_info(trigdata->tg_trigger->tgfoid, finfo);

	Assert(finfo->fn_oid == trigdata->tg_trigger->tgfoid);

	
	if (instr)
		InstrStartNode(instr + tgindx);

	
	oldContext = MemoryContextSwitchTo(per_tuple_context);

	
	InitFunctionCallInfoData(*fcinfo, finfo, 0, InvalidOid, (Node *) trigdata, NULL);

	pgstat_init_function_usage(fcinfo, &fcusage);

	MyTriggerDepth++;
	PG_TRY();
	{
		result = FunctionCallInvoke(fcinfo);
	}
	PG_CATCH();
	{
		MyTriggerDepth--;
		PG_RE_THROW();
	}
	PG_END_TRY();
	MyTriggerDepth--;

	pgstat_end_function_usage(&fcusage, true);

	MemoryContextSwitchTo(oldContext);

	
	if (fcinfo->isnull)
		ereport(ERROR, (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED), errmsg("trigger function %u returned null value", fcinfo->flinfo->fn_oid)));



	
	if (instr)
		InstrStopNode(instr + tgindx, 1);

	return (HeapTuple) DatumGetPointer(result);
}

void ExecBSInsertTriggers(EState *estate, ResultRelInfo *relinfo)
{
	TriggerDesc *trigdesc;
	int			i;
	TriggerData LocTriggerData;

	if (Gp_role == GP_ROLE_EXECUTE)
	{
		
		return;
	}

	trigdesc = relinfo->ri_TrigDesc;

	if (trigdesc == NULL)
		return;
	if (!trigdesc->trig_insert_before_statement)
		return;

	
	if (before_stmt_triggers_fired(RelationGetRelid(relinfo->ri_RelationDesc), CMD_INSERT))
		return;

	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = TRIGGER_EVENT_INSERT | TRIGGER_EVENT_BEFORE;
	LocTriggerData.tg_relation = relinfo->ri_RelationDesc;
	LocTriggerData.tg_trigtuple = NULL;
	LocTriggerData.tg_newtuple = NULL;
	LocTriggerData.tg_trigslot = NULL;
	LocTriggerData.tg_newslot = NULL;
	LocTriggerData.tg_oldtable = NULL;
	LocTriggerData.tg_newtable = NULL;
	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		Trigger    *trigger = &trigdesc->triggers[i];
		HeapTuple	newtuple;

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_INSERT))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, LocTriggerData.tg_event, NULL, NULL, NULL))
			continue;

		LocTriggerData.tg_trigger = trigger;
		newtuple = ExecCallTriggerFunc(&LocTriggerData, i, relinfo->ri_TrigFunctions, relinfo->ri_TrigInstrument, GetPerTupleMemoryContext(estate));




		if (newtuple)
			ereport(ERROR, (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED), errmsg("BEFORE STATEMENT trigger cannot return a value")));

	}
}

void ExecASInsertTriggers(EState *estate, ResultRelInfo *relinfo, TransitionCaptureState *transition_capture)

{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;

	if (trigdesc && trigdesc->trig_insert_after_statement)
		AfterTriggerSaveEvent(estate, relinfo, TRIGGER_EVENT_INSERT, false, NULL, NULL, NIL, NULL, transition_capture);
}

bool ExecBRInsertTriggers(EState *estate, ResultRelInfo *relinfo, TupleTableSlot *slot)

{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;
	HeapTuple	newtuple = false;
	bool		should_free;
	TriggerData LocTriggerData;
	int			i;

	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = TRIGGER_EVENT_INSERT | TRIGGER_EVENT_ROW | TRIGGER_EVENT_BEFORE;

	LocTriggerData.tg_relation = relinfo->ri_RelationDesc;
	LocTriggerData.tg_trigtuple = NULL;
	LocTriggerData.tg_newtuple = NULL;
	LocTriggerData.tg_trigslot = NULL;
	LocTriggerData.tg_newslot = NULL;
	LocTriggerData.tg_oldtable = NULL;
	LocTriggerData.tg_newtable = NULL;
	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		Trigger    *trigger = &trigdesc->triggers[i];
		HeapTuple	oldtuple;

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_INSERT))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, LocTriggerData.tg_event, NULL, NULL, slot))
			continue;

		if (!newtuple)
			newtuple = ExecFetchSlotHeapTuple(slot, true, &should_free);

		LocTriggerData.tg_trigslot = slot;
		LocTriggerData.tg_trigtuple = oldtuple = newtuple;
		LocTriggerData.tg_trigger = trigger;
		newtuple = ExecCallTriggerFunc(&LocTriggerData, i, relinfo->ri_TrigFunctions, relinfo->ri_TrigInstrument, GetPerTupleMemoryContext(estate));



		if (newtuple == NULL)
		{
			if (should_free)
				heap_freetuple(oldtuple);
			return false;		
		}
		else if (newtuple != oldtuple)
		{
			ExecForceStoreHeapTuple(newtuple, slot, false);

			if (should_free)
				heap_freetuple(oldtuple);

			
			newtuple = NULL;
		}
	}

	return true;
}

void ExecARInsertTriggers(EState *estate, ResultRelInfo *relinfo, TupleTableSlot *slot, List *recheckIndexes, TransitionCaptureState *transition_capture)


{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;

	if ((trigdesc && trigdesc->trig_insert_after_row) || (transition_capture && transition_capture->tcs_insert_new_table))
	{
		if(RelationIsAoCols(relinfo->ri_RelationDesc))
			elog(ERROR, "Trigger is not supported on AOCS yet");

		AfterTriggerSaveEvent(estate, relinfo, TRIGGER_EVENT_INSERT, true, NULL, slot, recheckIndexes, NULL, transition_capture);


	}
}

bool ExecIRInsertTriggers(EState *estate, ResultRelInfo *relinfo, TupleTableSlot *slot)

{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;
	HeapTuple	newtuple = NULL;
	bool		should_free;
	TriggerData LocTriggerData;
	int			i;

	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = TRIGGER_EVENT_INSERT | TRIGGER_EVENT_ROW | TRIGGER_EVENT_INSTEAD;

	LocTriggerData.tg_relation = relinfo->ri_RelationDesc;
	LocTriggerData.tg_trigtuple = NULL;
	LocTriggerData.tg_newtuple = NULL;
	LocTriggerData.tg_trigslot = NULL;
	LocTriggerData.tg_newslot = NULL;
	LocTriggerData.tg_oldtable = NULL;
	LocTriggerData.tg_newtable = NULL;
	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		Trigger    *trigger = &trigdesc->triggers[i];
		HeapTuple	oldtuple;

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_INSTEAD, TRIGGER_TYPE_INSERT))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, LocTriggerData.tg_event, NULL, NULL, slot))
			continue;

		if (!newtuple)
			newtuple = ExecFetchSlotHeapTuple(slot, true, &should_free);

		LocTriggerData.tg_trigslot = slot;
		LocTriggerData.tg_trigtuple = oldtuple = newtuple;
		LocTriggerData.tg_trigger = trigger;
		newtuple = ExecCallTriggerFunc(&LocTriggerData, i, relinfo->ri_TrigFunctions, relinfo->ri_TrigInstrument, GetPerTupleMemoryContext(estate));



		if (newtuple == NULL)
		{
			if (should_free)
				heap_freetuple(oldtuple);
			return false;		
		}
		else if (newtuple != oldtuple)
		{
			ExecForceStoreHeapTuple(newtuple, slot, false);

			if (should_free)
				heap_freetuple(oldtuple);

			
			newtuple = NULL;
		}
	}

	return true;
}

void ExecBSDeleteTriggers(EState *estate, ResultRelInfo *relinfo)
{
	TriggerDesc *trigdesc;
	int			i;
	TriggerData LocTriggerData;

	if (Gp_role == GP_ROLE_EXECUTE)
	{
		
		return;
	}

	trigdesc = relinfo->ri_TrigDesc;

	if (trigdesc == NULL)
		return;
	if (!trigdesc->trig_delete_before_statement)
		return;

	
	if (before_stmt_triggers_fired(RelationGetRelid(relinfo->ri_RelationDesc), CMD_DELETE))
		return;

	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = TRIGGER_EVENT_DELETE | TRIGGER_EVENT_BEFORE;
	LocTriggerData.tg_relation = relinfo->ri_RelationDesc;
	LocTriggerData.tg_trigtuple = NULL;
	LocTriggerData.tg_newtuple = NULL;
	LocTriggerData.tg_trigslot = NULL;
	LocTriggerData.tg_newslot = NULL;
	LocTriggerData.tg_oldtable = NULL;
	LocTriggerData.tg_newtable = NULL;
	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		Trigger    *trigger = &trigdesc->triggers[i];
		HeapTuple	newtuple;

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_DELETE))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, LocTriggerData.tg_event, NULL, NULL, NULL))
			continue;

		LocTriggerData.tg_trigger = trigger;
		newtuple = ExecCallTriggerFunc(&LocTriggerData, i, relinfo->ri_TrigFunctions, relinfo->ri_TrigInstrument, GetPerTupleMemoryContext(estate));




		if (newtuple)
			ereport(ERROR, (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED), errmsg("BEFORE STATEMENT trigger cannot return a value")));

	}
}

void ExecASDeleteTriggers(EState *estate, ResultRelInfo *relinfo, TransitionCaptureState *transition_capture)

{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;

	if (trigdesc && trigdesc->trig_delete_after_statement)
		AfterTriggerSaveEvent(estate, relinfo, TRIGGER_EVENT_DELETE, false, NULL, NULL, NIL, NULL, transition_capture);
}


bool ExecBRDeleteTriggers(EState *estate, EPQState *epqstate, ResultRelInfo *relinfo, ItemPointer tupleid, HeapTuple fdw_trigtuple, TupleTableSlot **epqslot)




{
	TupleTableSlot *slot = ExecGetTriggerOldSlot(estate, relinfo);
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;
	bool		result = true;
	TriggerData LocTriggerData;
	HeapTuple	trigtuple;
	bool		should_free = false;
	int			i;

	Assert(HeapTupleIsValid(fdw_trigtuple) ^ ItemPointerIsValid(tupleid));
	if (fdw_trigtuple == NULL)
	{
		TupleTableSlot *newSlot;

		if (!GetTupleForTrigger(estate, epqstate, relinfo, tupleid, LockTupleExclusive, slot, &newSlot))
			return false;

		
		if (newSlot != NULL && epqslot != NULL)
		{
			*epqslot = newSlot;
			return false;
		}

		trigtuple = ExecFetchSlotHeapTuple(slot, true, &should_free);

	}
	else {
		trigtuple = fdw_trigtuple;
		ExecForceStoreHeapTuple(trigtuple, slot, false);
	}

	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = TRIGGER_EVENT_DELETE | TRIGGER_EVENT_ROW | TRIGGER_EVENT_BEFORE;

	LocTriggerData.tg_relation = relinfo->ri_RelationDesc;
	LocTriggerData.tg_trigtuple = NULL;
	LocTriggerData.tg_newtuple = NULL;
	LocTriggerData.tg_trigslot = NULL;
	LocTriggerData.tg_newslot = NULL;
	LocTriggerData.tg_oldtable = NULL;
	LocTriggerData.tg_newtable = NULL;
	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		HeapTuple	newtuple;
		Trigger    *trigger = &trigdesc->triggers[i];

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_DELETE))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, LocTriggerData.tg_event, NULL, slot, NULL))
			continue;

		LocTriggerData.tg_trigslot = slot;
		LocTriggerData.tg_trigtuple = trigtuple;
		LocTriggerData.tg_trigger = trigger;
		newtuple = ExecCallTriggerFunc(&LocTriggerData, i, relinfo->ri_TrigFunctions, relinfo->ri_TrigInstrument, GetPerTupleMemoryContext(estate));



		if (newtuple == NULL)
		{
			result = false;		
			break;
		}
		if (newtuple != trigtuple)
			heap_freetuple(newtuple);
	}
	if (should_free)
		heap_freetuple(trigtuple);

	return result;
}

void ExecARDeleteTriggers(EState *estate, ResultRelInfo *relinfo, ItemPointer tupleid, HeapTuple fdw_trigtuple, TransitionCaptureState *transition_capture)



{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;
	TupleTableSlot *slot = ExecGetTriggerOldSlot(estate, relinfo);

	if ((trigdesc && trigdesc->trig_delete_after_row) || (transition_capture && transition_capture->tcs_delete_old_table))
	{
		Assert(HeapTupleIsValid(fdw_trigtuple) ^ ItemPointerIsValid(tupleid));
		if (fdw_trigtuple == NULL)
			GetTupleForTrigger(estate, NULL, relinfo, tupleid, LockTupleExclusive, slot, NULL);





		else ExecForceStoreHeapTuple(fdw_trigtuple, slot, false);

		AfterTriggerSaveEvent(estate, relinfo, TRIGGER_EVENT_DELETE, true, slot, NULL, NIL, NULL, transition_capture);

	}
}

bool ExecIRDeleteTriggers(EState *estate, ResultRelInfo *relinfo, HeapTuple trigtuple)

{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;
	TupleTableSlot *slot = ExecGetTriggerOldSlot(estate, relinfo);
	TriggerData LocTriggerData;
	int			i;

	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = TRIGGER_EVENT_DELETE | TRIGGER_EVENT_ROW | TRIGGER_EVENT_INSTEAD;

	LocTriggerData.tg_relation = relinfo->ri_RelationDesc;
	LocTriggerData.tg_trigtuple = NULL;
	LocTriggerData.tg_newtuple = NULL;
	LocTriggerData.tg_trigslot = NULL;
	LocTriggerData.tg_newslot = NULL;
	LocTriggerData.tg_oldtable = NULL;
	LocTriggerData.tg_newtable = NULL;

	ExecForceStoreHeapTuple(trigtuple, slot, false);

	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		HeapTuple	rettuple;
		Trigger    *trigger = &trigdesc->triggers[i];

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_INSTEAD, TRIGGER_TYPE_DELETE))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, LocTriggerData.tg_event, NULL, slot, NULL))
			continue;

		LocTriggerData.tg_trigslot = slot;
		LocTriggerData.tg_trigtuple = trigtuple;
		LocTriggerData.tg_trigger = trigger;
		rettuple = ExecCallTriggerFunc(&LocTriggerData, i, relinfo->ri_TrigFunctions, relinfo->ri_TrigInstrument, GetPerTupleMemoryContext(estate));



		if (rettuple == NULL)
			return false;		
		if (rettuple != trigtuple)
			heap_freetuple(rettuple);
	}
	return true;
}

void ExecBSUpdateTriggers(EState *estate, ResultRelInfo *relinfo)
{
	TriggerDesc *trigdesc;
	int			i;
	TriggerData LocTriggerData;
	Bitmapset  *updatedCols;

	if (Gp_role == GP_ROLE_EXECUTE)
	{
		
		return;
	}

	trigdesc = relinfo->ri_TrigDesc;

	if (trigdesc == NULL)
		return;
	if (!trigdesc->trig_update_before_statement)
		return;

	
	if (before_stmt_triggers_fired(RelationGetRelid(relinfo->ri_RelationDesc), CMD_UPDATE))
		return;

	updatedCols = GetAllUpdatedColumns(relinfo, estate);

	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = TRIGGER_EVENT_UPDATE | TRIGGER_EVENT_BEFORE;
	LocTriggerData.tg_relation = relinfo->ri_RelationDesc;
	LocTriggerData.tg_trigtuple = NULL;
	LocTriggerData.tg_newtuple = NULL;
	LocTriggerData.tg_trigslot = NULL;
	LocTriggerData.tg_newslot = NULL;
	LocTriggerData.tg_oldtable = NULL;
	LocTriggerData.tg_newtable = NULL;
	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		Trigger    *trigger = &trigdesc->triggers[i];
		HeapTuple	newtuple;

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_UPDATE))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, LocTriggerData.tg_event, updatedCols, NULL, NULL))
			continue;

		LocTriggerData.tg_trigger = trigger;
		newtuple = ExecCallTriggerFunc(&LocTriggerData, i, relinfo->ri_TrigFunctions, relinfo->ri_TrigInstrument, GetPerTupleMemoryContext(estate));




		if (newtuple)
			ereport(ERROR, (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED), errmsg("BEFORE STATEMENT trigger cannot return a value")));

	}
}

void ExecASUpdateTriggers(EState *estate, ResultRelInfo *relinfo, TransitionCaptureState *transition_capture)

{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;

	if (trigdesc && trigdesc->trig_update_after_statement)
		AfterTriggerSaveEvent(estate, relinfo, TRIGGER_EVENT_UPDATE, false, NULL, NULL, NIL, GetAllUpdatedColumns(relinfo, estate), transition_capture);


}

bool ExecBRUpdateTriggers(EState *estate, EPQState *epqstate, ResultRelInfo *relinfo, ItemPointer tupleid, HeapTuple fdw_trigtuple, TupleTableSlot *newslot)




{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;
	TupleTableSlot *oldslot = ExecGetTriggerOldSlot(estate, relinfo);
	HeapTuple	newtuple = NULL;
	HeapTuple	trigtuple;
	bool		should_free_trig = false;
	bool		should_free_new = false;
	TriggerData LocTriggerData;
	int			i;
	Bitmapset  *updatedCols;
	LockTupleMode lockmode;

	
	lockmode = ExecUpdateLockMode(estate, relinfo);

	Assert(HeapTupleIsValid(fdw_trigtuple) ^ ItemPointerIsValid(tupleid));
	if (fdw_trigtuple == NULL)
	{
		TupleTableSlot *newSlot = NULL;

		
		if (!GetTupleForTrigger(estate, epqstate, relinfo, tupleid, lockmode, oldslot, &newSlot))
			return false;		

		
		if (newSlot != NULL)
		{
			TupleTableSlot *slot = ExecFilterJunk(relinfo->ri_junkFilter, newSlot);

			ExecCopySlot(newslot, slot);
		}

		trigtuple = ExecFetchSlotHeapTuple(oldslot, true, &should_free_trig);
	}
	else {
		ExecForceStoreHeapTuple(fdw_trigtuple, oldslot, false);
		trigtuple = fdw_trigtuple;
	}

	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = TRIGGER_EVENT_UPDATE | TRIGGER_EVENT_ROW | TRIGGER_EVENT_BEFORE;

	LocTriggerData.tg_relation = relinfo->ri_RelationDesc;
	LocTriggerData.tg_oldtable = NULL;
	LocTriggerData.tg_newtable = NULL;
	updatedCols = GetAllUpdatedColumns(relinfo, estate);
	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		Trigger    *trigger = &trigdesc->triggers[i];
		HeapTuple	oldtuple;

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_UPDATE))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, LocTriggerData.tg_event, updatedCols, oldslot, newslot))
			continue;

		if (!newtuple)
			newtuple = ExecFetchSlotHeapTuple(newslot, true, &should_free_new);

		LocTriggerData.tg_trigslot = oldslot;
		LocTriggerData.tg_trigtuple = trigtuple;
		LocTriggerData.tg_newtuple = oldtuple = newtuple;
		LocTriggerData.tg_newslot = newslot;
		LocTriggerData.tg_trigger = trigger;
		newtuple = ExecCallTriggerFunc(&LocTriggerData, i, relinfo->ri_TrigFunctions, relinfo->ri_TrigInstrument, GetPerTupleMemoryContext(estate));




		if (newtuple == NULL)
		{
			if (should_free_trig)
				heap_freetuple(trigtuple);
			if (should_free_new)
				heap_freetuple(oldtuple);
			return false;		
		}
		else if (newtuple != oldtuple)
		{
			ExecForceStoreHeapTuple(newtuple, newslot, false);

			
			if (should_free_trig && newtuple == trigtuple)
				ExecMaterializeSlot(newslot);

			if (should_free_new)
				heap_freetuple(oldtuple);

			
			newtuple = NULL;
		}
	}
	if (should_free_trig)
		heap_freetuple(trigtuple);

	return true;
}

void ExecARUpdateTriggers(EState *estate, ResultRelInfo *relinfo, ItemPointer tupleid, HeapTuple fdw_trigtuple, TupleTableSlot *newslot, List *recheckIndexes, TransitionCaptureState *transition_capture)





{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;
	TupleTableSlot *oldslot = ExecGetTriggerOldSlot(estate, relinfo);

	ExecClearTuple(oldslot);

	if ((trigdesc && trigdesc->trig_update_after_row) || (transition_capture && (transition_capture->tcs_update_old_table || transition_capture->tcs_update_new_table)))


	{
		
		if (fdw_trigtuple == NULL && ItemPointerIsValid(tupleid))
			GetTupleForTrigger(estate, NULL, relinfo, tupleid, LockTupleExclusive, oldslot, NULL);





		else if (fdw_trigtuple != NULL)
			ExecForceStoreHeapTuple(fdw_trigtuple, oldslot, false);

		AfterTriggerSaveEvent(estate, relinfo, TRIGGER_EVENT_UPDATE, true, oldslot, newslot, recheckIndexes, GetAllUpdatedColumns(relinfo, estate), transition_capture);


	}
}

bool ExecIRUpdateTriggers(EState *estate, ResultRelInfo *relinfo, HeapTuple trigtuple, TupleTableSlot *newslot)

{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;
	TupleTableSlot *oldslot = ExecGetTriggerOldSlot(estate, relinfo);
	HeapTuple	newtuple = false;
	bool		should_free;
	TriggerData LocTriggerData;
	int			i;

	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = TRIGGER_EVENT_UPDATE | TRIGGER_EVENT_ROW | TRIGGER_EVENT_INSTEAD;

	LocTriggerData.tg_relation = relinfo->ri_RelationDesc;
	LocTriggerData.tg_oldtable = NULL;
	LocTriggerData.tg_newtable = NULL;

	ExecForceStoreHeapTuple(trigtuple, oldslot, false);

	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		Trigger    *trigger = &trigdesc->triggers[i];
		HeapTuple	oldtuple;

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, TRIGGER_TYPE_ROW, TRIGGER_TYPE_INSTEAD, TRIGGER_TYPE_UPDATE))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, LocTriggerData.tg_event, NULL, oldslot, newslot))
			continue;

		if (!newtuple)
			newtuple = ExecFetchSlotHeapTuple(newslot, true, &should_free);

		LocTriggerData.tg_trigslot = oldslot;
		LocTriggerData.tg_trigtuple = trigtuple;
		LocTriggerData.tg_newslot = newslot;
		LocTriggerData.tg_newtuple = oldtuple = newtuple;

		LocTriggerData.tg_trigger = trigger;
		newtuple = ExecCallTriggerFunc(&LocTriggerData, i, relinfo->ri_TrigFunctions, relinfo->ri_TrigInstrument, GetPerTupleMemoryContext(estate));



		if (newtuple == NULL)
		{
			return false;		
		}
		else if (newtuple != oldtuple)
		{
			ExecForceStoreHeapTuple(newtuple, newslot, false);

			if (should_free)
				heap_freetuple(oldtuple);

			
			newtuple = NULL;
		}
	}

	return true;
}

void ExecBSTruncateTriggers(EState *estate, ResultRelInfo *relinfo)
{
	TriggerDesc *trigdesc;
	int			i;
	TriggerData LocTriggerData;

	if (Gp_role == GP_ROLE_EXECUTE)
	{
		
		return;
	}

	trigdesc = relinfo->ri_TrigDesc;

	if (trigdesc == NULL)
		return;
	if (!trigdesc->trig_truncate_before_statement)
		return;

	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = TRIGGER_EVENT_TRUNCATE | TRIGGER_EVENT_BEFORE;
	LocTriggerData.tg_relation = relinfo->ri_RelationDesc;
	LocTriggerData.tg_trigtuple = NULL;
	LocTriggerData.tg_newtuple = NULL;
	LocTriggerData.tg_trigslot = NULL;
	LocTriggerData.tg_newslot = NULL;
	LocTriggerData.tg_oldtable = NULL;
	LocTriggerData.tg_newtable = NULL;

	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		Trigger    *trigger = &trigdesc->triggers[i];
		HeapTuple	newtuple;

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, TRIGGER_TYPE_STATEMENT, TRIGGER_TYPE_BEFORE, TRIGGER_TYPE_TRUNCATE))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, LocTriggerData.tg_event, NULL, NULL, NULL))
			continue;

		LocTriggerData.tg_trigger = trigger;
		newtuple = ExecCallTriggerFunc(&LocTriggerData, i, relinfo->ri_TrigFunctions, relinfo->ri_TrigInstrument, GetPerTupleMemoryContext(estate));




		if (newtuple)
			ereport(ERROR, (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED), errmsg("BEFORE STATEMENT trigger cannot return a value")));

	}
}

void ExecASTruncateTriggers(EState *estate, ResultRelInfo *relinfo)
{
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;

	if (trigdesc && trigdesc->trig_truncate_after_statement)
		AfterTriggerSaveEvent(estate, relinfo, TRIGGER_EVENT_TRUNCATE, false, NULL, NULL, NIL, NULL, NULL);
}


static bool GetTupleForTrigger(EState *estate, EPQState *epqstate, ResultRelInfo *relinfo, ItemPointer tid, LockTupleMode lockmode, TupleTableSlot *oldslot, TupleTableSlot **newSlot)






{
	Relation	relation = relinfo->ri_RelationDesc;

	
	if (RelationIsAppendOptimized(relation))
		elog(ERROR, "UPDATE and DELETE triggers are not supported on append-only tables");

	Assert(RelationIsHeap(relation));

	if (newSlot != NULL)
	{
		TM_Result	test;
		TM_FailureData tmfd;
		int			lockflags = 0;

		*newSlot = NULL;

		
		Assert(epqstate != NULL);

		
		if (!IsolationUsesXactSnapshot())
			lockflags |= TUPLE_LOCK_FLAG_FIND_LAST_VERSION;
		test = table_tuple_lock(relation, tid, estate->es_snapshot, oldslot, estate->es_output_cid, lockmode, LockWaitBlock, lockflags, &tmfd);




		switch (test)
		{
			case TM_SelfModified:

				
				if (tmfd.cmax != estate->es_output_cid)
					ereport(ERROR, (errcode(ERRCODE_TRIGGERED_DATA_CHANGE_VIOLATION), errmsg("tuple to be updated was already modified by an operation triggered by the current command"), errhint("Consider using an AFTER trigger instead of a BEFORE trigger to propagate changes to other rows.")));



				
				return false;

			case TM_Ok:
				if (tmfd.traversed)
				{
					TupleTableSlot *epqslot;

					epqslot = EvalPlanQual(estate, epqstate, relation, relinfo->ri_RangeTableIndex, oldslot);




					
					if (TupIsNull(epqslot))
						return false;

					*newSlot = epqslot;
				}
				break;

			case TM_Updated:
				if (IsolationUsesXactSnapshot())
					ereport(ERROR, (errcode(ERRCODE_T_R_SERIALIZATION_FAILURE), errmsg("could not serialize access due to concurrent update")));

				elog(ERROR, "unexpected table_tuple_lock status: %u", test);
				break;

			case TM_Deleted:
				if (IsolationUsesXactSnapshot())
					ereport(ERROR, (errcode(ERRCODE_T_R_SERIALIZATION_FAILURE), errmsg("could not serialize access due to concurrent delete")));

				
				return false;

			case TM_Invisible:
				elog(ERROR, "attempted to lock invisible tuple");
				break;

			default:
				elog(ERROR, "unrecognized table_tuple_lock status: %u", test);
				return false;	
		}
	}
	else {
		
		if (!table_tuple_fetch_row_version(relation, tid, SnapshotAny, oldslot))
			elog(ERROR, "failed to fetch tuple for trigger");
	}

	return true;
}


static bool TriggerEnabled(EState *estate, ResultRelInfo *relinfo, Trigger *trigger, TriggerEvent event, Bitmapset *modifiedCols, TupleTableSlot *oldslot, TupleTableSlot *newslot)



{
	
	if (SessionReplicationRole == SESSION_REPLICATION_ROLE_REPLICA)
	{
		if (trigger->tgenabled == TRIGGER_FIRES_ON_ORIGIN || trigger->tgenabled == TRIGGER_DISABLED)
			return false;
	}
	else						 {
		if (trigger->tgenabled == TRIGGER_FIRES_ON_REPLICA || trigger->tgenabled == TRIGGER_DISABLED)
			return false;
	}

	
	if (trigger->tgnattr > 0 && TRIGGER_FIRED_BY_UPDATE(event))
	{
		int			i;
		bool		modified;

		modified = false;
		for (i = 0; i < trigger->tgnattr; i++)
		{
			if (bms_is_member(trigger->tgattr[i] - FirstLowInvalidHeapAttributeNumber, modifiedCols))
			{
				modified = true;
				break;
			}
		}
		if (!modified)
			return false;
	}

	
	if (trigger->tgqual)
	{
		ExprState **predicate;
		ExprContext *econtext;
		MemoryContext oldContext;
		int			i;

		Assert(estate != NULL);

		
		i = trigger - relinfo->ri_TrigDesc->triggers;
		predicate = &relinfo->ri_TrigWhenExprs[i];

		
		if (*predicate == NULL)
		{
			Node	   *tgqual;

			oldContext = MemoryContextSwitchTo(estate->es_query_cxt);
			tgqual = stringToNode(trigger->tgqual);
			
			ChangeVarNodes(tgqual, PRS2_OLD_VARNO, INNER_VAR, 0);
			ChangeVarNodes(tgqual, PRS2_NEW_VARNO, OUTER_VAR, 0);
			
			tgqual = (Node *) make_ands_implicit((Expr *) tgqual);
			*predicate = ExecPrepareQual((List *) tgqual, estate);
			MemoryContextSwitchTo(oldContext);
		}

		
		econtext = GetPerTupleExprContext(estate);

		
		econtext->ecxt_innertuple = oldslot;
		econtext->ecxt_outertuple = newslot;
		if (!ExecQual(*predicate, econtext))
			return false;
	}

	return true;
}





typedef struct SetConstraintTriggerData {
	Oid			sct_tgoid;
	bool		sct_tgisdeferred;
} SetConstraintTriggerData;

typedef struct SetConstraintTriggerData *SetConstraintTrigger;


typedef struct SetConstraintStateData {
	bool		all_isset;
	bool		all_isdeferred;
	int			numstates;		
	int			numalloc;		
	SetConstraintTriggerData trigstates[FLEXIBLE_ARRAY_MEMBER];
} SetConstraintStateData;

typedef SetConstraintStateData *SetConstraintState;



typedef uint32 TriggerFlags;











typedef struct AfterTriggerSharedData *AfterTriggerShared;

typedef struct AfterTriggerSharedData {
	TriggerEvent ats_event;		
	Oid			ats_tgoid;		
	Oid			ats_relid;		
	CommandId	ats_firing_id;	
	struct AfterTriggersTableData *ats_table;	
} AfterTriggerSharedData;

typedef struct AfterTriggerEventData *AfterTriggerEvent;

typedef struct AfterTriggerEventData {
	TriggerFlags ate_flags;		
	ItemPointerData ate_ctid1;	
	ItemPointerData ate_ctid2;	
} AfterTriggerEventData;


typedef struct AfterTriggerEventDataOneCtid {
	TriggerFlags ate_flags;		
	ItemPointerData ate_ctid1;	
}			AfterTriggerEventDataOneCtid;


typedef struct AfterTriggerEventDataZeroCtids {
	TriggerFlags ate_flags;		
}			AfterTriggerEventDataZeroCtids;










typedef struct AfterTriggerEventChunk {
	struct AfterTriggerEventChunk *next;	
	char	   *freeptr;		
	char	   *endfree;		
	char	   *endptr;			
	
} AfterTriggerEventChunk;




typedef struct AfterTriggerEventList {
	AfterTriggerEventChunk *head;
	AfterTriggerEventChunk *tail;
	char	   *tailfree;		
} AfterTriggerEventList;

















typedef struct AfterTriggersQueryData AfterTriggersQueryData;
typedef struct AfterTriggersTransData AfterTriggersTransData;
typedef struct AfterTriggersTableData AfterTriggersTableData;

typedef struct AfterTriggersData {
	CommandId	firing_counter; 
	SetConstraintState state;	
	AfterTriggerEventList events;	
	MemoryContext event_cxt;	

	
	AfterTriggersQueryData *query_stack;	
	int			query_depth;	
	int			maxquerydepth;	

	
	AfterTriggersTransData *trans_stack;	
	int			maxtransdepth;	
} AfterTriggersData;

struct AfterTriggersQueryData {
	AfterTriggerEventList events;	
	Tuplestorestate *fdw_tuplestore;	
	List	   *tables;			
};

struct AfterTriggersTransData {
	
	SetConstraintState state;	
	AfterTriggerEventList events;	
	int			query_depth;	
	CommandId	firing_counter; 
};

struct AfterTriggersTableData {
	
	Oid			relid;			
	CmdType		cmdType;		
	bool		closed;			
	bool		before_trig_done;	
	bool		after_trig_done;	
	AfterTriggerEventList after_trig_events;	
	Tuplestorestate *old_tuplestore;	
	Tuplestorestate *new_tuplestore;	
	TupleTableSlot *storeslot;	
};

static AfterTriggersData afterTriggers;

static void AfterTriggerExecute(EState *estate, AfterTriggerEvent event, ResultRelInfo *relInfo, TriggerDesc *trigdesc, FmgrInfo *finfo, Instrumentation *instr, MemoryContext per_tuple_context, TupleTableSlot *trig_tuple_slot1, TupleTableSlot *trig_tuple_slot2);







static AfterTriggersTableData *GetAfterTriggersTableData(Oid relid, CmdType cmdType);
static void AfterTriggerFreeQuery(AfterTriggersQueryData *qs);
static SetConstraintState SetConstraintStateCreate(int numalloc);
static SetConstraintState SetConstraintStateCopy(SetConstraintState state);
static SetConstraintState SetConstraintStateAddItem(SetConstraintState state, Oid tgoid, bool tgisdeferred);
static void cancel_prior_stmt_triggers(Oid relid, CmdType cmdType, int tgevent);



static Tuplestorestate * GetCurrentFDWTuplestore(void)
{
	Tuplestorestate *ret;

	ret = afterTriggers.query_stack[afterTriggers.query_depth].fdw_tuplestore;
	if (ret == NULL)
	{
		MemoryContext oldcxt;
		ResourceOwner saveResourceOwner;

		
		oldcxt = MemoryContextSwitchTo(CurTransactionContext);
		saveResourceOwner = CurrentResourceOwner;
		CurrentResourceOwner = CurTransactionResourceOwner;

		ret = tuplestore_begin_heap(false, false, work_mem);

		CurrentResourceOwner = saveResourceOwner;
		MemoryContextSwitchTo(oldcxt);

		afterTriggers.query_stack[afterTriggers.query_depth].fdw_tuplestore = ret;
	}

	return ret;
}


static bool afterTriggerCheckState(AfterTriggerShared evtshared)
{
	Oid			tgoid = evtshared->ats_tgoid;
	SetConstraintState state = afterTriggers.state;
	int			i;

	
	if ((evtshared->ats_event & AFTER_TRIGGER_DEFERRABLE) == 0)
		return false;

	
	if (state != NULL)
	{
		
		for (i = 0; i < state->numstates; i++)
		{
			if (state->trigstates[i].sct_tgoid == tgoid)
				return state->trigstates[i].sct_tgisdeferred;
		}

		
		if (state->all_isset)
			return state->all_isdeferred;
	}

	
	return ((evtshared->ats_event & AFTER_TRIGGER_INITDEFERRED) != 0);
}



static void afterTriggerAddEvent(AfterTriggerEventList *events, AfterTriggerEvent event, AfterTriggerShared evtshared)

{
	Size		eventsize = SizeofTriggerEvent(event);
	Size		needed = eventsize + sizeof(AfterTriggerSharedData);
	AfterTriggerEventChunk *chunk;
	AfterTriggerShared newshared;
	AfterTriggerEvent newevent;

	
	chunk = events->tail;
	if (chunk == NULL || chunk->endfree - chunk->freeptr < needed)
	{
		Size		chunksize;

		
		if (afterTriggers.event_cxt == NULL)
			afterTriggers.event_cxt = AllocSetContextCreate(TopTransactionContext, "AfterTriggerEvents", ALLOCSET_DEFAULT_SIZES);



		







		if (chunk == NULL)
			chunksize = MIN_CHUNK_SIZE;
		else {
			
			chunksize = chunk->endptr - (char *) chunk;
			
			if ((chunk->endptr - chunk->endfree) <= (100 * sizeof(AfterTriggerSharedData)))
				chunksize *= 2; 
			else chunksize /= 2;
			chunksize = Min(chunksize, MAX_CHUNK_SIZE);
		}
		chunk = MemoryContextAlloc(afterTriggers.event_cxt, chunksize);
		chunk->next = NULL;
		chunk->freeptr = CHUNK_DATA_START(chunk);
		chunk->endptr = chunk->endfree = (char *) chunk + chunksize;
		Assert(chunk->endfree - chunk->freeptr >= needed);

		if (events->head == NULL)
			events->head = chunk;
		else events->tail->next = chunk;
		events->tail = chunk;
		
	}

	
	for (newshared = ((AfterTriggerShared) chunk->endptr) - 1;
		 (char *) newshared >= chunk->endfree;
		 newshared--)
	{
		if (newshared->ats_tgoid == evtshared->ats_tgoid && newshared->ats_relid == evtshared->ats_relid && newshared->ats_event == evtshared->ats_event && newshared->ats_table == evtshared->ats_table && newshared->ats_firing_id == 0)



			break;
	}
	if ((char *) newshared < chunk->endfree)
	{
		*newshared = *evtshared;
		newshared->ats_firing_id = 0;	
		chunk->endfree = (char *) newshared;
	}

	
	newevent = (AfterTriggerEvent) chunk->freeptr;
	memcpy(newevent, event, eventsize);
	
	newevent->ate_flags &= ~AFTER_TRIGGER_OFFSET;
	newevent->ate_flags |= (char *) newshared - (char *) newevent;

	chunk->freeptr += eventsize;
	events->tailfree = chunk->freeptr;
}


static void afterTriggerFreeEventList(AfterTriggerEventList *events)
{
	AfterTriggerEventChunk *chunk;

	while ((chunk = events->head) != NULL)
	{
		events->head = chunk->next;
		pfree(chunk);
	}
	events->tail = NULL;
	events->tailfree = NULL;
}


static void afterTriggerRestoreEventList(AfterTriggerEventList *events, const AfterTriggerEventList *old_events)

{
	AfterTriggerEventChunk *chunk;
	AfterTriggerEventChunk *next_chunk;

	if (old_events->tail == NULL)
	{
		
		afterTriggerFreeEventList(events);
	}
	else {
		*events = *old_events;
		
		for (chunk = events->tail->next; chunk != NULL; chunk = next_chunk)
		{
			next_chunk = chunk->next;
			pfree(chunk);
		}
		
		events->tail->next = NULL;
		events->tail->freeptr = events->tailfree;

		
	}
}


static void afterTriggerDeleteHeadEventChunk(AfterTriggersQueryData *qs)
{
	AfterTriggerEventChunk *target = qs->events.head;
	ListCell   *lc;

	Assert(target && target->next);

	
	foreach(lc, qs->tables)
	{
		AfterTriggersTableData *table = (AfterTriggersTableData *) lfirst(lc);

		if (table->after_trig_done && table->after_trig_events.tail == target)
		{
			table->after_trig_events.head = NULL;
			table->after_trig_events.tail = NULL;
			table->after_trig_events.tailfree = NULL;
		}
	}

	
	qs->events.head = target->next;
	pfree(target);
}



static void AfterTriggerExecute(EState *estate, AfterTriggerEvent event, ResultRelInfo *relInfo, TriggerDesc *trigdesc, FmgrInfo *finfo, Instrumentation *instr, MemoryContext per_tuple_context, TupleTableSlot *trig_tuple_slot1, TupleTableSlot *trig_tuple_slot2)







{
	Relation	rel = relInfo->ri_RelationDesc;
	AfterTriggerShared evtshared = GetTriggerSharedData(event);
	Oid			tgoid = evtshared->ats_tgoid;
	TriggerData LocTriggerData;
	HeapTuple	rettuple;
	int			tgindx;
	bool		should_free_trig = false;
	bool		should_free_new = false;

	
	LocTriggerData.tg_trigger = NULL;
	LocTriggerData.tg_trigslot = NULL;
	LocTriggerData.tg_newslot = NULL;

	for (tgindx = 0; tgindx < trigdesc->numtriggers; tgindx++)
	{
		if (trigdesc->triggers[tgindx].tgoid == tgoid)
		{
			LocTriggerData.tg_trigger = &(trigdesc->triggers[tgindx]);
			break;
		}
	}
	if (LocTriggerData.tg_trigger == NULL)
		elog(ERROR, "could not find trigger %u", tgoid);

	
	if (instr)
		InstrStartNode(instr + tgindx);

	
	switch (event->ate_flags & AFTER_TRIGGER_TUP_BITS)
	{
		case AFTER_TRIGGER_FDW_FETCH:
			{
				Tuplestorestate *fdw_tuplestore = GetCurrentFDWTuplestore();

				if (!tuplestore_gettupleslot(fdw_tuplestore, true, false, trig_tuple_slot1))
					elog(ERROR, "failed to fetch tuple1 for AFTER trigger");

				if ((evtshared->ats_event & TRIGGER_EVENT_OPMASK) == TRIGGER_EVENT_UPDATE && !tuplestore_gettupleslot(fdw_tuplestore, true, false, trig_tuple_slot2))


					elog(ERROR, "failed to fetch tuple2 for AFTER trigger");
			}
			
		case AFTER_TRIGGER_FDW_REUSE:

			
			LocTriggerData.tg_trigslot = trig_tuple_slot1;
			LocTriggerData.tg_trigtuple = ExecFetchSlotHeapTuple(trig_tuple_slot1, true, &should_free_trig);

			LocTriggerData.tg_newslot = trig_tuple_slot2;
			LocTriggerData.tg_newtuple = ((evtshared->ats_event & TRIGGER_EVENT_OPMASK) == TRIGGER_EVENT_UPDATE) ? ExecFetchSlotHeapTuple(trig_tuple_slot2, true, &should_free_new) : NULL;



			break;

		default:
			if (ItemPointerIsValid(&(event->ate_ctid1)))
			{
				LocTriggerData.tg_trigslot = ExecGetTriggerOldSlot(estate, relInfo);

				if (!table_tuple_fetch_row_version(rel, &(event->ate_ctid1), SnapshotAny, LocTriggerData.tg_trigslot))

					elog(ERROR, "failed to fetch tuple1 for AFTER trigger");
				LocTriggerData.tg_trigtuple = ExecFetchSlotHeapTuple(LocTriggerData.tg_trigslot, false, &should_free_trig);
			}
			else {
				LocTriggerData.tg_trigtuple = NULL;
			}

			
			if ((event->ate_flags & AFTER_TRIGGER_TUP_BITS) == AFTER_TRIGGER_2CTID && ItemPointerIsValid(&(event->ate_ctid2)))

			{
				LocTriggerData.tg_newslot = ExecGetTriggerNewSlot(estate, relInfo);

				if (!table_tuple_fetch_row_version(rel, &(event->ate_ctid2), SnapshotAny, LocTriggerData.tg_newslot))

					elog(ERROR, "failed to fetch tuple2 for AFTER trigger");
				LocTriggerData.tg_newtuple = ExecFetchSlotHeapTuple(LocTriggerData.tg_newslot, false, &should_free_new);
			}
			else {
				LocTriggerData.tg_newtuple = NULL;
			}
	}

	
	LocTriggerData.tg_oldtable = LocTriggerData.tg_newtable = NULL;
	if (evtshared->ats_table)
	{
		if (LocTriggerData.tg_trigger->tgoldtable)
		{
			LocTriggerData.tg_oldtable = evtshared->ats_table->old_tuplestore;
			evtshared->ats_table->closed = true;
		}

		if (LocTriggerData.tg_trigger->tgnewtable)
		{
			LocTriggerData.tg_newtable = evtshared->ats_table->new_tuplestore;
			evtshared->ats_table->closed = true;
		}
	}

	
	LocTriggerData.type = T_TriggerData;
	LocTriggerData.tg_event = evtshared->ats_event & (TRIGGER_EVENT_OPMASK | TRIGGER_EVENT_ROW);
	LocTriggerData.tg_relation = rel;

	MemoryContextReset(per_tuple_context);

	
	rettuple = ExecCallTriggerFunc(&LocTriggerData, tgindx, finfo, NULL, per_tuple_context);



	if (rettuple != NULL && rettuple != LocTriggerData.tg_trigtuple && rettuple != LocTriggerData.tg_newtuple)

		heap_freetuple(rettuple);

	
	if (should_free_trig)
		heap_freetuple(LocTriggerData.tg_trigtuple);
	if (should_free_new)
		heap_freetuple(LocTriggerData.tg_newtuple);

	if (LocTriggerData.tg_trigslot)
		ExecClearTuple(LocTriggerData.tg_trigslot);
	if (LocTriggerData.tg_newslot)
		ExecClearTuple(LocTriggerData.tg_newslot);

	
	if (instr)
		InstrStopNode(instr + tgindx, 1);
}



static bool afterTriggerMarkEvents(AfterTriggerEventList *events, AfterTriggerEventList *move_list, bool immediate_only)


{
	bool		found = false;
	AfterTriggerEvent event;
	AfterTriggerEventChunk *chunk;

	for_each_event_chunk(event, chunk, *events)
	{
		AfterTriggerShared evtshared = GetTriggerSharedData(event);
		bool		defer_it = false;

		if (!(event->ate_flags & (AFTER_TRIGGER_DONE | AFTER_TRIGGER_IN_PROGRESS)))
		{
			
			if (immediate_only && afterTriggerCheckState(evtshared))
			{
				defer_it = true;
			}
			else {
				
				evtshared->ats_firing_id = afterTriggers.firing_counter;
				event->ate_flags |= AFTER_TRIGGER_IN_PROGRESS;
				found = true;
			}
		}

		
		if (defer_it && move_list != NULL)
		{
			
			afterTriggerAddEvent(move_list, event, evtshared);
			
			event->ate_flags |= AFTER_TRIGGER_DONE;
		}
	}

	return found;
}


static bool afterTriggerInvokeEvents(AfterTriggerEventList *events, CommandId firing_id, EState *estate, bool delete_ok)



{
	bool		all_fired = true;
	AfterTriggerEventChunk *chunk;
	MemoryContext per_tuple_context;
	bool		local_estate = false;
	ResultRelInfo *rInfo = NULL;
	Relation	rel = NULL;
	TriggerDesc *trigdesc = NULL;
	FmgrInfo   *finfo = NULL;
	Instrumentation *instr = NULL;
	TupleTableSlot *slot1 = NULL, *slot2 = NULL;

	
	if (estate == NULL)
	{
		estate = CreateExecutorState();
		local_estate = true;
	}

	
	per_tuple_context = AllocSetContextCreate(CurrentMemoryContext, "AfterTriggerTupleContext", ALLOCSET_DEFAULT_SIZES);



	for_each_chunk(chunk, *events)
	{
		AfterTriggerEvent event;
		bool		all_fired_in_chunk = true;

		for_each_event(event, chunk)
		{
			AfterTriggerShared evtshared = GetTriggerSharedData(event);

			
			if ((event->ate_flags & AFTER_TRIGGER_IN_PROGRESS) && evtshared->ats_firing_id == firing_id)
			{
				
				if (rel == NULL || RelationGetRelid(rel) != evtshared->ats_relid)
				{
					rInfo = ExecGetTriggerResultRel(estate, evtshared->ats_relid);
					rel = rInfo->ri_RelationDesc;
					trigdesc = rInfo->ri_TrigDesc;
					finfo = rInfo->ri_TrigFunctions;
					instr = rInfo->ri_TrigInstrument;
					if (rel->rd_rel->relkind == RELKIND_FOREIGN_TABLE)
					{
						if (slot1 != NULL)
						{
							ExecDropSingleTupleTableSlot(slot1);
							ExecDropSingleTupleTableSlot(slot2);
						}
						slot1 = MakeSingleTupleTableSlot(rel->rd_att, &TTSOpsMinimalTuple);
						slot2 = MakeSingleTupleTableSlot(rel->rd_att, &TTSOpsMinimalTuple);
					}
					if (trigdesc == NULL)	
						elog(ERROR, "relation %u has no triggers", evtshared->ats_relid);
				}

				
				AfterTriggerExecute(estate, event, rInfo, trigdesc, finfo, instr, per_tuple_context, slot1, slot2);

				
				event->ate_flags &= ~AFTER_TRIGGER_IN_PROGRESS;
				event->ate_flags |= AFTER_TRIGGER_DONE;
			}
			else if (!(event->ate_flags & AFTER_TRIGGER_DONE))
			{
				
				all_fired = all_fired_in_chunk = false;
			}
		}

		
		if (delete_ok && all_fired_in_chunk)
		{
			chunk->freeptr = CHUNK_DATA_START(chunk);
			chunk->endfree = chunk->endptr;

			
			if (chunk == events->tail)
				events->tailfree = chunk->freeptr;
		}
	}
	if (slot1 != NULL)
	{
		ExecDropSingleTupleTableSlot(slot1);
		ExecDropSingleTupleTableSlot(slot2);
	}

	
	MemoryContextDelete(per_tuple_context);

	if (local_estate)
	{
		ExecCleanUpTriggerState(estate);
		ExecResetTupleTable(estate->es_tupleTable, false);
		FreeExecutorState(estate);
	}

	return all_fired;
}



static AfterTriggersTableData * GetAfterTriggersTableData(Oid relid, CmdType cmdType)
{
	AfterTriggersTableData *table;
	AfterTriggersQueryData *qs;
	MemoryContext oldcxt;
	ListCell   *lc;

	
	Assert(afterTriggers.query_depth >= 0 && afterTriggers.query_depth < afterTriggers.maxquerydepth);
	qs = &afterTriggers.query_stack[afterTriggers.query_depth];

	foreach(lc, qs->tables)
	{
		table = (AfterTriggersTableData *) lfirst(lc);
		if (table->relid == relid && table->cmdType == cmdType && !table->closed)
			return table;
	}

	oldcxt = MemoryContextSwitchTo(CurTransactionContext);

	table = (AfterTriggersTableData *) palloc0(sizeof(AfterTriggersTableData));
	table->relid = relid;
	table->cmdType = cmdType;
	qs->tables = lappend(qs->tables, table);

	MemoryContextSwitchTo(oldcxt);

	return table;
}



TransitionCaptureState * MakeTransitionCaptureState(TriggerDesc *trigdesc, Oid relid, CmdType cmdType)
{
	TransitionCaptureState *state;
	bool		need_old, need_new;
	AfterTriggersTableData *table;
	MemoryContext oldcxt;
	ResourceOwner saveResourceOwner;

	if (trigdesc == NULL)
		return NULL;

	
	switch (cmdType)
	{
		case CMD_INSERT:
			need_old = false;
			need_new = trigdesc->trig_insert_new_table;
			break;
		case CMD_UPDATE:
			need_old = trigdesc->trig_update_old_table;
			need_new = trigdesc->trig_update_new_table;
			break;
		case CMD_DELETE:
			need_old = trigdesc->trig_delete_old_table;
			need_new = false;
			break;
		default:
			elog(ERROR, "unexpected CmdType: %d", (int) cmdType);
			need_old = need_new = false;	
			break;
	}
	if (!need_old && !need_new)
		return NULL;

	
	if (afterTriggers.query_depth < 0)
		elog(ERROR, "MakeTransitionCaptureState() called outside of query");

	
	if (afterTriggers.query_depth >= afterTriggers.maxquerydepth)
		AfterTriggerEnlargeQueryState();

	
	table = GetAfterTriggersTableData(relid, cmdType);

	
	oldcxt = MemoryContextSwitchTo(CurTransactionContext);
	saveResourceOwner = CurrentResourceOwner;
	CurrentResourceOwner = CurTransactionResourceOwner;

	if (need_old && table->old_tuplestore == NULL)
		table->old_tuplestore = tuplestore_begin_heap(false, false, work_mem);
	if (need_new && table->new_tuplestore == NULL)
		table->new_tuplestore = tuplestore_begin_heap(false, false, work_mem);

	CurrentResourceOwner = saveResourceOwner;
	MemoryContextSwitchTo(oldcxt);

	
	state = (TransitionCaptureState *) palloc0(sizeof(TransitionCaptureState));
	state->tcs_delete_old_table = trigdesc->trig_delete_old_table;
	state->tcs_update_old_table = trigdesc->trig_update_old_table;
	state->tcs_update_new_table = trigdesc->trig_update_new_table;
	state->tcs_insert_new_table = trigdesc->trig_insert_new_table;
	state->tcs_private = table;

	return state;
}



void AfterTriggerBeginXact(void)
{
	
	afterTriggers.firing_counter = (CommandId) 1;	
	afterTriggers.query_depth = -1;

	
	Assert(afterTriggers.state == NULL);
	Assert(afterTriggers.query_stack == NULL);
	Assert(afterTriggers.maxquerydepth == 0);
	Assert(afterTriggers.event_cxt == NULL);
	Assert(afterTriggers.events.head == NULL);
	Assert(afterTriggers.trans_stack == NULL);
	Assert(afterTriggers.maxtransdepth == 0);
}



void AfterTriggerBeginQuery(void)
{
	
	afterTriggers.query_depth++;
}



void AfterTriggerEndQuery(EState *estate)
{
	AfterTriggersQueryData *qs;

	
	Assert(afterTriggers.query_depth >= 0);

	
	if (afterTriggers.query_depth >= afterTriggers.maxquerydepth)
	{
		afterTriggers.query_depth--;
		return;
	}

	
	qs = &afterTriggers.query_stack[afterTriggers.query_depth];

	for (;;)
	{
		if (afterTriggerMarkEvents(&qs->events, &afterTriggers.events, true))
		{
			CommandId	firing_id = afterTriggers.firing_counter++;
			AfterTriggerEventChunk *oldtail = qs->events.tail;

			if (afterTriggerInvokeEvents(&qs->events, firing_id, estate, false))
				break;			

			
			qs = &afterTriggers.query_stack[afterTriggers.query_depth];

			
			Assert(oldtail != NULL);
			while (qs->events.head != oldtail)
				afterTriggerDeleteHeadEventChunk(qs);
		}
		else break;
	}

	
	AfterTriggerFreeQuery(&afterTriggers.query_stack[afterTriggers.query_depth]);

	afterTriggers.query_depth--;
}



static void AfterTriggerFreeQuery(AfterTriggersQueryData *qs)
{
	Tuplestorestate *ts;
	List	   *tables;
	ListCell   *lc;

	
	afterTriggerFreeEventList(&qs->events);

	
	ts = qs->fdw_tuplestore;
	qs->fdw_tuplestore = NULL;
	if (ts)
		tuplestore_end(ts);

	
	tables = qs->tables;
	foreach(lc, tables)
	{
		AfterTriggersTableData *table = (AfterTriggersTableData *) lfirst(lc);

		ts = table->old_tuplestore;
		table->old_tuplestore = NULL;
		if (ts)
			tuplestore_end(ts);
		ts = table->new_tuplestore;
		table->new_tuplestore = NULL;
		if (ts)
			tuplestore_end(ts);
	}

	
	qs->tables = NIL;
	list_free_deep(tables);
}



void AfterTriggerFireDeferred(void)
{
	AfterTriggerEventList *events;
	bool		snap_pushed = false;

	
	Assert(afterTriggers.query_depth == -1);

	
	events = &afterTriggers.events;
	if (events->head != NULL)
	{
		PushActiveSnapshot(GetTransactionSnapshot());
		snap_pushed = true;
	}

	
	while (afterTriggerMarkEvents(events, NULL, false))
	{
		CommandId	firing_id = afterTriggers.firing_counter++;

		if (afterTriggerInvokeEvents(events, firing_id, NULL, true))
			break;				
	}

	

	if (snap_pushed)
		PopActiveSnapshot();
}



void AfterTriggerEndXact(bool isCommit)
{
	
	if (afterTriggers.event_cxt)
	{
		MemoryContextDelete(afterTriggers.event_cxt);
		afterTriggers.event_cxt = NULL;
		afterTriggers.events.head = NULL;
		afterTriggers.events.tail = NULL;
		afterTriggers.events.tailfree = NULL;
	}

	
	afterTriggers.trans_stack = NULL;
	afterTriggers.maxtransdepth = 0;


	
	afterTriggers.query_stack = NULL;
	afterTriggers.maxquerydepth = 0;
	afterTriggers.state = NULL;

	
	afterTriggers.query_depth = -1;
}


void AfterTriggerBeginSubXact(void)
{
	int			my_level = GetCurrentTransactionNestLevel();

	
	while (my_level >= afterTriggers.maxtransdepth)
	{
		if (afterTriggers.maxtransdepth == 0)
		{
			
			afterTriggers.trans_stack = (AfterTriggersTransData *)
				MemoryContextAlloc(TopTransactionContext, 8 * sizeof(AfterTriggersTransData));
			afterTriggers.maxtransdepth = 8;
		}
		else {
			
			int			new_alloc = afterTriggers.maxtransdepth * 2;

			afterTriggers.trans_stack = (AfterTriggersTransData *)
				repalloc(afterTriggers.trans_stack, new_alloc * sizeof(AfterTriggersTransData));
			afterTriggers.maxtransdepth = new_alloc;
		}
	}

	
	afterTriggers.trans_stack[my_level].state = NULL;
	afterTriggers.trans_stack[my_level].events = afterTriggers.events;
	afterTriggers.trans_stack[my_level].query_depth = afterTriggers.query_depth;
	afterTriggers.trans_stack[my_level].firing_counter = afterTriggers.firing_counter;
}


void AfterTriggerEndSubXact(bool isCommit)
{
	int			my_level = GetCurrentTransactionNestLevel();
	SetConstraintState state;
	AfterTriggerEvent event;
	AfterTriggerEventChunk *chunk;
	CommandId	subxact_firing_id;

	
	if (isCommit)
	{
		Assert(my_level < afterTriggers.maxtransdepth);
		
		state = afterTriggers.trans_stack[my_level].state;
		if (state != NULL)
			pfree(state);
		
		afterTriggers.trans_stack[my_level].state = NULL;
		Assert(afterTriggers.query_depth == afterTriggers.trans_stack[my_level].query_depth);
	}
	else {
		
		if (my_level >= afterTriggers.maxtransdepth)
			return;

		
		while (afterTriggers.query_depth > afterTriggers.trans_stack[my_level].query_depth)
		{
			if (afterTriggers.query_depth < afterTriggers.maxquerydepth)
				AfterTriggerFreeQuery(&afterTriggers.query_stack[afterTriggers.query_depth]);
			afterTriggers.query_depth--;
		}
		Assert(afterTriggers.query_depth == afterTriggers.trans_stack[my_level].query_depth);

		
		afterTriggerRestoreEventList(&afterTriggers.events, &afterTriggers.trans_stack[my_level].events);

		
		state = afterTriggers.trans_stack[my_level].state;
		if (state != NULL)
		{
			pfree(afterTriggers.state);
			afterTriggers.state = state;
		}
		
		afterTriggers.trans_stack[my_level].state = NULL;

		
		subxact_firing_id = afterTriggers.trans_stack[my_level].firing_counter;
		for_each_event_chunk(event, chunk, afterTriggers.events)
		{
			AfterTriggerShared evtshared = GetTriggerSharedData(event);

			if (event->ate_flags & (AFTER_TRIGGER_DONE | AFTER_TRIGGER_IN_PROGRESS))
			{
				if (evtshared->ats_firing_id >= subxact_firing_id)
					event->ate_flags &= ~(AFTER_TRIGGER_DONE | AFTER_TRIGGER_IN_PROGRESS);
			}
		}
	}
}


static void AfterTriggerEnlargeQueryState(void)
{
	int			init_depth = afterTriggers.maxquerydepth;

	Assert(afterTriggers.query_depth >= afterTriggers.maxquerydepth);

	if (afterTriggers.maxquerydepth == 0)
	{
		int			new_alloc = Max(afterTriggers.query_depth + 1, 8);

		afterTriggers.query_stack = (AfterTriggersQueryData *)
			MemoryContextAlloc(TopTransactionContext, new_alloc * sizeof(AfterTriggersQueryData));
		afterTriggers.maxquerydepth = new_alloc;
	}
	else {
		
		int			old_alloc = afterTriggers.maxquerydepth;
		int			new_alloc = Max(afterTriggers.query_depth + 1, old_alloc * 2);

		afterTriggers.query_stack = (AfterTriggersQueryData *)
			repalloc(afterTriggers.query_stack, new_alloc * sizeof(AfterTriggersQueryData));
		afterTriggers.maxquerydepth = new_alloc;
	}

	
	while (init_depth < afterTriggers.maxquerydepth)
	{
		AfterTriggersQueryData *qs = &afterTriggers.query_stack[init_depth];

		qs->events.head = NULL;
		qs->events.tail = NULL;
		qs->events.tailfree = NULL;
		qs->fdw_tuplestore = NULL;
		qs->tables = NIL;

		++init_depth;
	}
}


static SetConstraintState SetConstraintStateCreate(int numalloc)
{
	SetConstraintState state;

	
	if (numalloc <= 0)
		numalloc = 1;

	
	state = (SetConstraintState)
		MemoryContextAllocZero(TopTransactionContext, offsetof(SetConstraintStateData, trigstates) + numalloc * sizeof(SetConstraintTriggerData));


	state->numalloc = numalloc;

	return state;
}


static SetConstraintState SetConstraintStateCopy(SetConstraintState origstate)
{
	SetConstraintState state;

	state = SetConstraintStateCreate(origstate->numstates);

	state->all_isset = origstate->all_isset;
	state->all_isdeferred = origstate->all_isdeferred;
	state->numstates = origstate->numstates;
	memcpy(state->trigstates, origstate->trigstates, origstate->numstates * sizeof(SetConstraintTriggerData));

	return state;
}


static SetConstraintState SetConstraintStateAddItem(SetConstraintState state, Oid tgoid, bool tgisdeferred)

{
	if (state->numstates >= state->numalloc)
	{
		int			newalloc = state->numalloc * 2;

		newalloc = Max(newalloc, 8);	
		state = (SetConstraintState)
			repalloc(state, offsetof(SetConstraintStateData, trigstates) + newalloc * sizeof(SetConstraintTriggerData));

		state->numalloc = newalloc;
		Assert(state->numstates < state->numalloc);
	}

	state->trigstates[state->numstates].sct_tgoid = tgoid;
	state->trigstates[state->numstates].sct_tgisdeferred = tgisdeferred;
	state->numstates++;

	return state;
}


void AfterTriggerSetState(ConstraintsSetStmt *stmt)
{
	int			my_level = GetCurrentTransactionNestLevel();

	
	if (afterTriggers.state == NULL)
		afterTriggers.state = SetConstraintStateCreate(8);

	
	if (my_level > 1 && afterTriggers.trans_stack[my_level].state == NULL)
	{
		afterTriggers.trans_stack[my_level].state = SetConstraintStateCopy(afterTriggers.state);
	}

	
	if (stmt->constraints == NIL)
	{
		
		afterTriggers.state->numstates = 0;

		
		afterTriggers.state->all_isset = true;
		afterTriggers.state->all_isdeferred = stmt->deferred;
	}
	else {
		Relation	conrel;
		Relation	tgrel;
		List	   *conoidlist = NIL;
		List	   *tgoidlist = NIL;
		ListCell   *lc;

		
		conrel = table_open(ConstraintRelationId, AccessShareLock);

		foreach(lc, stmt->constraints)
		{
			RangeVar   *constraint = lfirst(lc);
			bool		found;
			List	   *namespacelist;
			ListCell   *nslc;

			if (constraint->catalogname)
			{
				if (strcmp(constraint->catalogname, get_database_name(MyDatabaseId)) != 0)
					ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cross-database references are not implemented: \"%s.%s.%s\"", constraint->catalogname, constraint->schemaname, constraint->relname)));



			}

			
			if (constraint->schemaname)
			{
				Oid			namespaceId = LookupExplicitNamespace(constraint->schemaname, false);

				namespacelist = list_make1_oid(namespaceId);
			}
			else {
				namespacelist = fetch_search_path(true);
			}

			found = false;
			foreach(nslc, namespacelist)
			{
				Oid			namespaceId = lfirst_oid(nslc);
				SysScanDesc conscan;
				ScanKeyData skey[2];
				HeapTuple	tup;

				ScanKeyInit(&skey[0], Anum_pg_constraint_conname, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(constraint->relname));


				ScanKeyInit(&skey[1], Anum_pg_constraint_connamespace, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(namespaceId));



				conscan = systable_beginscan(conrel, ConstraintNameNspIndexId, true, NULL, 2, skey);

				while (HeapTupleIsValid(tup = systable_getnext(conscan)))
				{
					Form_pg_constraint con = (Form_pg_constraint) GETSTRUCT(tup);

					if (con->condeferrable)
						conoidlist = lappend_oid(conoidlist, con->oid);
					else if (stmt->deferred)
						ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("constraint \"%s\" is not deferrable", constraint->relname)));


					found = true;
				}

				systable_endscan(conscan);

				
				if (found)
					break;
			}

			list_free(namespacelist);

			
			if (!found)
				ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("constraint \"%s\" does not exist", constraint->relname)));


		}

		
		foreach(lc, conoidlist)
		{
			Oid			parent = lfirst_oid(lc);
			ScanKeyData key;
			SysScanDesc scan;
			HeapTuple	tuple;

			ScanKeyInit(&key, Anum_pg_constraint_conparentid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(parent));



			scan = systable_beginscan(conrel, ConstraintParentIndexId, true, NULL, 1, &key);

			while (HeapTupleIsValid(tuple = systable_getnext(scan)))
			{
				Form_pg_constraint con = (Form_pg_constraint) GETSTRUCT(tuple);

				conoidlist = lappend_oid(conoidlist, con->oid);
			}

			systable_endscan(scan);
		}

		table_close(conrel, AccessShareLock);

		
		tgrel = table_open(TriggerRelationId, AccessShareLock);

		foreach(lc, conoidlist)
		{
			Oid			conoid = lfirst_oid(lc);
			bool		found;
			ScanKeyData skey;
			SysScanDesc tgscan;
			HeapTuple	htup;

			found = false;

			ScanKeyInit(&skey, Anum_pg_trigger_tgconstraint, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(conoid));



			tgscan = systable_beginscan(tgrel, TriggerConstraintIndexId, true, NULL, 1, &skey);

			while (HeapTupleIsValid(htup = systable_getnext(tgscan)))
			{
				Form_pg_trigger pg_trigger = (Form_pg_trigger) GETSTRUCT(htup);

				
				if (pg_trigger->tgdeferrable)
					tgoidlist = lappend_oid(tgoidlist, pg_trigger->oid);

				found = true;
			}

			systable_endscan(tgscan);

			
			if (!found)
				elog(ERROR, "no triggers found for constraint with OID %u", conoid);
		}

		table_close(tgrel, AccessShareLock);

		
		foreach(lc, tgoidlist)
		{
			Oid			tgoid = lfirst_oid(lc);
			SetConstraintState state = afterTriggers.state;
			bool		found = false;
			int			i;

			for (i = 0; i < state->numstates; i++)
			{
				if (state->trigstates[i].sct_tgoid == tgoid)
				{
					state->trigstates[i].sct_tgisdeferred = stmt->deferred;
					found = true;
					break;
				}
			}
			if (!found)
			{
				afterTriggers.state = SetConstraintStateAddItem(state, tgoid, stmt->deferred);
			}
		}
	}

	
	if (!stmt->deferred)
	{
		AfterTriggerEventList *events = &afterTriggers.events;
		bool		snapshot_set = false;

		while (afterTriggerMarkEvents(events, NULL, true))
		{
			CommandId	firing_id = afterTriggers.firing_counter++;

			
			if (!snapshot_set)
			{
				PushActiveSnapshot(GetTransactionSnapshot());
				snapshot_set = true;
			}

			
			if (afterTriggerInvokeEvents(events, firing_id, NULL, !IsSubTransaction()))
				break;			
		}

		if (snapshot_set)
			PopActiveSnapshot();
	}
	else {
		
	}
	if (Gp_role == GP_ROLE_DISPATCH)
	{
		CdbDispatchUtilityStatement((Node *) stmt, DF_CANCEL_ON_ERROR| DF_NEED_TWO_PHASE, NIL, NULL);



	}
}


bool AfterTriggerPendingOnRel(Oid relid)
{
	AfterTriggerEvent event;
	AfterTriggerEventChunk *chunk;
	int			depth;

	
	for_each_event_chunk(event, chunk, afterTriggers.events)
	{
		AfterTriggerShared evtshared = GetTriggerSharedData(event);

		
		if (event->ate_flags & AFTER_TRIGGER_DONE)
			continue;

		if (evtshared->ats_relid == relid)
			return true;
	}

	
	for (depth = 0; depth <= afterTriggers.query_depth && depth < afterTriggers.maxquerydepth; depth++)
	{
		for_each_event_chunk(event, chunk, afterTriggers.query_stack[depth].events)
		{
			AfterTriggerShared evtshared = GetTriggerSharedData(event);

			if (event->ate_flags & AFTER_TRIGGER_DONE)
				continue;

			if (evtshared->ats_relid == relid)
				return true;
		}
	}

	return false;
}



static void AfterTriggerSaveEvent(EState *estate, ResultRelInfo *relinfo, int event, bool row_trigger, TupleTableSlot *oldslot, TupleTableSlot *newslot, List *recheckIndexes, Bitmapset *modifiedCols, TransitionCaptureState *transition_capture)




{
	Relation	rel = relinfo->ri_RelationDesc;
	TriggerDesc *trigdesc = relinfo->ri_TrigDesc;
	AfterTriggerEventData new_event;
	AfterTriggerSharedData new_shared;
	char		relkind = rel->rd_rel->relkind;
	int			tgtype_event;
	int			tgtype_level;
	int			i;
	Tuplestorestate *fdw_tuplestore = NULL;

	
	if (afterTriggers.query_depth < 0)
		elog(ERROR, "AfterTriggerSaveEvent() called outside of query");

	
	if (!row_trigger && Gp_role == GP_ROLE_EXECUTE)
		return;

	
	if (afterTriggers.query_depth >= afterTriggers.maxquerydepth)
		AfterTriggerEnlargeQueryState();

	
	if (row_trigger && transition_capture != NULL)
	{
		TupleTableSlot *original_insert_tuple = transition_capture->tcs_original_insert_tuple;
		TupleConversionMap *map = transition_capture->tcs_map;
		bool		delete_old_table = transition_capture->tcs_delete_old_table;
		bool		update_old_table = transition_capture->tcs_update_old_table;
		bool		update_new_table = transition_capture->tcs_update_new_table;
		bool		insert_new_table = transition_capture->tcs_insert_new_table;

		
		Assert(!(event == TRIGGER_EVENT_DELETE && delete_old_table && TupIsNull(oldslot)));
		Assert(!(event == TRIGGER_EVENT_INSERT && insert_new_table && TupIsNull(newslot)));

		if (!TupIsNull(oldslot) && ((event == TRIGGER_EVENT_DELETE && delete_old_table) || (event == TRIGGER_EVENT_UPDATE && update_old_table)))

		{
			Tuplestorestate *old_tuplestore;

			old_tuplestore = transition_capture->tcs_private->old_tuplestore;

			if (map != NULL)
			{
				TupleTableSlot *storeslot;

				storeslot = transition_capture->tcs_private->storeslot;
				if (!storeslot)
				{
					storeslot = ExecAllocTableSlot(&estate->es_tupleTable, map->outdesc, &TTSOpsVirtual);

					transition_capture->tcs_private->storeslot = storeslot;
				}

				execute_attr_map_slot(map->attrMap, oldslot, storeslot);
				tuplestore_puttupleslot(old_tuplestore, storeslot);
			}
			else tuplestore_puttupleslot(old_tuplestore, oldslot);
		}
		if (!TupIsNull(newslot) && ((event == TRIGGER_EVENT_INSERT && insert_new_table) || (event == TRIGGER_EVENT_UPDATE && update_new_table)))

		{
			Tuplestorestate *new_tuplestore;

			new_tuplestore = transition_capture->tcs_private->new_tuplestore;

			if (original_insert_tuple != NULL)
				tuplestore_puttupleslot(new_tuplestore, original_insert_tuple);
			else if (map != NULL)
			{
				TupleTableSlot *storeslot;

				storeslot = transition_capture->tcs_private->storeslot;

				if (!storeslot)
				{
					storeslot = ExecAllocTableSlot(&estate->es_tupleTable, map->outdesc, &TTSOpsVirtual);

					transition_capture->tcs_private->storeslot = storeslot;
				}

				execute_attr_map_slot(map->attrMap, newslot, storeslot);
				tuplestore_puttupleslot(new_tuplestore, storeslot);
			}
			else tuplestore_puttupleslot(new_tuplestore, newslot);
		}

		
		if (trigdesc == NULL || (event == TRIGGER_EVENT_DELETE && !trigdesc->trig_delete_after_row) || (event == TRIGGER_EVENT_INSERT && !trigdesc->trig_insert_after_row) || (event == TRIGGER_EVENT_UPDATE && !trigdesc->trig_update_after_row) || (event == TRIGGER_EVENT_UPDATE && (TupIsNull(oldslot) ^ TupIsNull(newslot))))



			return;
	}

	
	switch (event)
	{
		case TRIGGER_EVENT_INSERT:
			tgtype_event = TRIGGER_TYPE_INSERT;
			if (row_trigger)
			{
				Assert(oldslot == NULL);
				Assert(newslot != NULL);
				ItemPointerCopy(&(newslot->tts_tid), &(new_event.ate_ctid1));
				ItemPointerSetInvalid(&(new_event.ate_ctid2));
			}
			else {
				Assert(oldslot == NULL);
				Assert(newslot == NULL);
				ItemPointerSetInvalid(&(new_event.ate_ctid1));
				ItemPointerSetInvalid(&(new_event.ate_ctid2));
				cancel_prior_stmt_triggers(RelationGetRelid(rel), CMD_INSERT, event);
			}
			break;
		case TRIGGER_EVENT_DELETE:
			tgtype_event = TRIGGER_TYPE_DELETE;
			if (row_trigger)
			{
				Assert(oldslot != NULL);
				Assert(newslot == NULL);
				ItemPointerCopy(&(oldslot->tts_tid), &(new_event.ate_ctid1));
				ItemPointerSetInvalid(&(new_event.ate_ctid2));
			}
			else {
				Assert(oldslot == NULL);
				Assert(newslot == NULL);
				ItemPointerSetInvalid(&(new_event.ate_ctid1));
				ItemPointerSetInvalid(&(new_event.ate_ctid2));
				cancel_prior_stmt_triggers(RelationGetRelid(rel), CMD_DELETE, event);
			}
			break;
		case TRIGGER_EVENT_UPDATE:
			tgtype_event = TRIGGER_TYPE_UPDATE;
			if (row_trigger)
			{
				Assert(oldslot != NULL);
				Assert(newslot != NULL);
				ItemPointerCopy(&(oldslot->tts_tid), &(new_event.ate_ctid1));
				ItemPointerCopy(&(newslot->tts_tid), &(new_event.ate_ctid2));
			}
			else {
				Assert(oldslot == NULL);
				Assert(newslot == NULL);
				ItemPointerSetInvalid(&(new_event.ate_ctid1));
				ItemPointerSetInvalid(&(new_event.ate_ctid2));
				cancel_prior_stmt_triggers(RelationGetRelid(rel), CMD_UPDATE, event);
			}
			break;
		case TRIGGER_EVENT_TRUNCATE:
			tgtype_event = TRIGGER_TYPE_TRUNCATE;
			Assert(oldslot == NULL);
			Assert(newslot == NULL);
			ItemPointerSetInvalid(&(new_event.ate_ctid1));
			ItemPointerSetInvalid(&(new_event.ate_ctid2));
			break;
		default:
			elog(ERROR, "invalid after-trigger event code: %d", event);
			tgtype_event = 0;	
			break;
	}

	if (!(relkind == RELKIND_FOREIGN_TABLE && row_trigger))
		new_event.ate_flags = (row_trigger && event == TRIGGER_EVENT_UPDATE) ? AFTER_TRIGGER_2CTID : AFTER_TRIGGER_1CTID;
	

	tgtype_level = (row_trigger ? TRIGGER_TYPE_ROW : TRIGGER_TYPE_STATEMENT);

	for (i = 0; i < trigdesc->numtriggers; i++)
	{
		Trigger    *trigger = &trigdesc->triggers[i];

		if (!TRIGGER_TYPE_MATCHES(trigger->tgtype, tgtype_level, TRIGGER_TYPE_AFTER, tgtype_event))


			continue;
		if (!TriggerEnabled(estate, relinfo, trigger, event, modifiedCols, oldslot, newslot))
			continue;

		if (relkind == RELKIND_FOREIGN_TABLE && row_trigger)
		{
			if (fdw_tuplestore == NULL)
			{
				fdw_tuplestore = GetCurrentFDWTuplestore();
				new_event.ate_flags = AFTER_TRIGGER_FDW_FETCH;
			}
			else  new_event.ate_flags = AFTER_TRIGGER_FDW_REUSE;

		}

		
		if (TRIGGER_FIRED_BY_UPDATE(event) || TRIGGER_FIRED_BY_DELETE(event))
		{
			switch (RI_FKey_trigger_type(trigger->tgfoid))
			{
				case RI_TRIGGER_PK:
					
					if (!RI_FKey_pk_upd_check_required(trigger, rel, oldslot, newslot))
					{
						
						continue;
					}
					break;

				case RI_TRIGGER_FK:
					
					if (!RI_FKey_fk_upd_check_required(trigger, rel, oldslot, newslot))
					{
						
						continue;
					}
					break;

				case RI_TRIGGER_NONE:
					
					break;
			}
		}

		
		if (trigger->tgfoid == F_UNIQUE_KEY_RECHECK)
		{
			if (!list_member_oid(recheckIndexes, trigger->tgconstrindid))
				continue;		
		}

		
		new_shared.ats_event = (event & TRIGGER_EVENT_OPMASK) | (row_trigger ? TRIGGER_EVENT_ROW : 0) | (trigger->tgdeferrable ? AFTER_TRIGGER_DEFERRABLE : 0) | (trigger->tginitdeferred ? AFTER_TRIGGER_INITDEFERRED : 0);



		new_shared.ats_tgoid = trigger->tgoid;
		new_shared.ats_relid = RelationGetRelid(rel);
		new_shared.ats_firing_id = 0;
		if ((trigger->tgoldtable || trigger->tgnewtable) && transition_capture != NULL)
			new_shared.ats_table = transition_capture->tcs_private;
		else new_shared.ats_table = NULL;

		afterTriggerAddEvent(&afterTriggers.query_stack[afterTriggers.query_depth].events, &new_event, &new_shared);
	}

	
	if (fdw_tuplestore)
	{
		if (oldslot != NULL)
			tuplestore_puttupleslot(fdw_tuplestore, oldslot);
		if (newslot != NULL)
			tuplestore_puttupleslot(fdw_tuplestore, newslot);
	}
}


static bool before_stmt_triggers_fired(Oid relid, CmdType cmdType)
{
	bool		result;
	AfterTriggersTableData *table;

	
	if (afterTriggers.query_depth < 0)
		elog(ERROR, "before_stmt_triggers_fired() called outside of query");

	
	if (afterTriggers.query_depth >= afterTriggers.maxquerydepth)
		AfterTriggerEnlargeQueryState();

	
	table = GetAfterTriggersTableData(relid, cmdType);
	result = table->before_trig_done;
	table->before_trig_done = true;
	return result;
}


static void cancel_prior_stmt_triggers(Oid relid, CmdType cmdType, int tgevent)
{
	AfterTriggersTableData *table;
	AfterTriggersQueryData *qs = &afterTriggers.query_stack[afterTriggers.query_depth];

	
	table = GetAfterTriggersTableData(relid, cmdType);

	if (table->after_trig_done)
	{
		
		AfterTriggerEvent event;
		AfterTriggerEventChunk *chunk;

		if (table->after_trig_events.tail)
		{
			chunk = table->after_trig_events.tail;
			event = (AfterTriggerEvent) table->after_trig_events.tailfree;
		}
		else {
			chunk = qs->events.head;
			event = NULL;
		}

		for_each_chunk_from(chunk)
		{
			if (event == NULL)
				event = (AfterTriggerEvent) CHUNK_DATA_START(chunk);
			for_each_event_from(event, chunk)
			{
				AfterTriggerShared evtshared = GetTriggerSharedData(event);

				
				if (evtshared->ats_relid != relid)
					goto done;
				if ((evtshared->ats_event & TRIGGER_EVENT_OPMASK) != tgevent)
					goto done;
				if (!TRIGGER_FIRED_FOR_STATEMENT(evtshared->ats_event))
					goto done;
				if (!TRIGGER_FIRED_AFTER(evtshared->ats_event))
					goto done;
				
				event->ate_flags &= ~AFTER_TRIGGER_IN_PROGRESS;
				event->ate_flags |= AFTER_TRIGGER_DONE;
			}
			
			event = NULL;
		}
	}
done:

	
	table->after_trig_done = true;
	table->after_trig_events = qs->events;
}


Datum pg_trigger_depth(PG_FUNCTION_ARGS)
{
	PG_RETURN_INT32(MyTriggerDepth);
}
