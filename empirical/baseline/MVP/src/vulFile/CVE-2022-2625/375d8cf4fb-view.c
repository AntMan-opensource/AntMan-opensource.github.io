






























static void checkViewTupleDesc(TupleDesc newdesc, TupleDesc olddesc);


void validateWithCheckOption(const char *value)
{
	if (value == NULL || (strcmp(value, "local") != 0 && strcmp(value, "cascaded") != 0))

	{
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid value for \"check_option\" option"), errdetail("Valid values are \"local\" and \"cascaded\".")));


	}
}


static ObjectAddress DefineVirtualRelation(RangeVar *relation, List *tlist, bool replace, List *options, Query *viewParse)

{
	Oid			viewOid;
	LOCKMODE	lockmode;
	CreateStmt *createStmt = makeNode(CreateStmt);
	List	   *attrList;
	ListCell   *t;

	createStmt->ownerid = GetUserId();

	
	attrList = NIL;
	foreach(t, tlist)
	{
		TargetEntry *tle = (TargetEntry *) lfirst(t);

		if (!tle->resjunk)
		{
			ColumnDef  *def = makeColumnDef(tle->resname, exprType((Node *) tle->expr), exprTypmod((Node *) tle->expr), exprCollation((Node *) tle->expr));



			
			if (type_is_collatable(exprType((Node *) tle->expr)))
			{
				if (!OidIsValid(def->collOid))
					ereport(ERROR, (errcode(ERRCODE_INDETERMINATE_COLLATION), errmsg("could not determine which collation to use for view column \"%s\"", def->colname), errhint("Use the COLLATE clause to set the collation explicitly.")));



			}
			else Assert(!OidIsValid(def->collOid));

			attrList = lappend(attrList, def);
		}
	}

	
	lockmode = replace ? AccessExclusiveLock : NoLock;
	(void) RangeVarGetAndCheckCreationNamespace(relation, lockmode, &viewOid);

	if (OidIsValid(viewOid) && replace)
	{
		Relation	rel;
		TupleDesc	descriptor;
		List	   *atcmds = NIL;
		AlterTableCmd *atcmd;
		ObjectAddress address;

		
		rel = relation_open(viewOid, NoLock);

		
		if (rel->rd_rel->relkind != RELKIND_VIEW)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a view", RelationGetRelationName(rel))));



		
		CheckTableNotInUse(rel, "CREATE OR REPLACE VIEW");

		
		Assert(relation->relpersistence == rel->rd_rel->relpersistence);

		
		descriptor = BuildDescForRelation(attrList);
		checkViewTupleDesc(descriptor, rel->rd_att);

		
		if (list_length(attrList) > rel->rd_att->natts)
		{
			ListCell   *c;
			int			skip = rel->rd_att->natts;

			foreach(c, attrList)
			{
				if (skip > 0)
				{
					skip--;
					continue;
				}
				atcmd = makeNode(AlterTableCmd);
				atcmd->subtype = AT_AddColumnToView;
				atcmd->def = (Node *) lfirst(c);
				atcmds = lappend(atcmds, atcmd);
			}

			
			AlterTableInternal(viewOid, atcmds, true);

			
			CommandCounterIncrement();
		}

		
		StoreViewQuery(viewOid, viewParse, replace);

		
		CommandCounterIncrement();

		
		atcmd = makeNode(AlterTableCmd);
		atcmd->subtype = AT_ReplaceRelOptions;
		atcmd->def = (Node *) options;
		atcmds = list_make1(atcmd);

		
		AlterTableInternal(viewOid, atcmds, true);

		ObjectAddressSet(address, RelationRelationId, viewOid);

		
		relation_close(rel, NoLock);	

		return address;
	}
	else {
		ObjectAddress address;

		
		createStmt->relation = relation;
		createStmt->tableElts = attrList;
		createStmt->inhRelations = NIL;
		createStmt->constraints = NIL;
		createStmt->options = options;
		createStmt->oncommit = ONCOMMIT_NOOP;
		createStmt->tablespacename = NULL;
		createStmt->relKind = RELKIND_VIEW;
		createStmt->if_not_exists = false;

		
		address = DefineRelation(createStmt, RELKIND_VIEW, InvalidOid, NULL, NULL, false, true, NULL);

		Assert(address.objectId != InvalidOid);

		
		CommandCounterIncrement();

		
		StoreViewQuery(address.objectId, viewParse, replace);

		return address;
	}
}


static void checkViewTupleDesc(TupleDesc newdesc, TupleDesc olddesc)
{
	int			i;

	if (newdesc->natts < olddesc->natts)
		ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("cannot drop columns from view")));


	for (i = 0; i < olddesc->natts; i++)
	{
		Form_pg_attribute newattr = TupleDescAttr(newdesc, i);
		Form_pg_attribute oldattr = TupleDescAttr(olddesc, i);

		
		if (newattr->attisdropped != oldattr->attisdropped)
			ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("cannot drop columns from view")));


		if (strcmp(NameStr(newattr->attname), NameStr(oldattr->attname)) != 0)
			ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("cannot change name of view column \"%s\" to \"%s\"", NameStr(oldattr->attname), NameStr(newattr->attname))));



		
		if (newattr->atttypid != oldattr->atttypid || newattr->atttypmod != oldattr->atttypmod)
			ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("cannot change data type of view column \"%s\" from %s to %s", NameStr(oldattr->attname), format_type_with_typemod(oldattr->atttypid, oldattr->atttypmod), format_type_with_typemod(newattr->atttypid, newattr->atttypmod))));






		
	}

	
}

static void DefineViewRules(Oid viewOid, Query *viewParse, bool replace)
{
	
	DefineQueryRewrite(pstrdup(ViewSelectRuleName), viewOid, NULL, CMD_SELECT, true, replace, list_make1(viewParse));






	
}


static Query * UpdateRangeTableOfViewParse(Oid viewOid, Query *viewParse)
{
	Relation	viewRel;
	List	   *new_rt;
	RangeTblEntry *rt_entry1, *rt_entry2;
	ParseState *pstate;

	
	viewParse = copyObject(viewParse);

	
	pstate = make_parsestate(NULL);

	
	viewRel = relation_open(viewOid, AccessShareLock);

	
	rt_entry1 = addRangeTableEntryForRelation(pstate, viewRel, AccessShareLock, makeAlias("old", NIL), false, false);


	rt_entry2 = addRangeTableEntryForRelation(pstate, viewRel, AccessShareLock, makeAlias("new", NIL), false, false);


	
	rt_entry1->requiredPerms = 0;
	rt_entry2->requiredPerms = 0;

	new_rt = lcons(rt_entry1, lcons(rt_entry2, viewParse->rtable));

	viewParse->rtable = new_rt;

	
	OffsetVarNodes((Node *) viewParse, 2, 0);

	relation_close(viewRel, AccessShareLock);

	return viewParse;
}


ObjectAddress DefineView(ViewStmt *stmt, const char *queryString, int stmt_location, int stmt_len)

{
	RawStmt    *rawstmt;
	Query	   *viewParse_orig;
	Query	   *viewParse;
	RangeVar   *view;
	ListCell   *cell;
	bool		check_option;
	ObjectAddress address;

	
	if (Gp_role != GP_ROLE_EXECUTE)
	{
		rawstmt = makeNode(RawStmt);
		rawstmt->stmt = (Node *) copyObject(stmt->query);
		rawstmt->stmt_location = stmt_location;
		rawstmt->stmt_len = stmt_len;

		viewParse = parse_analyze(rawstmt, queryString, NULL, 0, NULL);
	}
	else viewParse = (Query *) stmt->query;
	viewParse_orig = copyObject(viewParse);

	
	if (!IsA(viewParse, Query))
		elog(ERROR, "unexpected parse analysis result");
	if (viewParse->utilityStmt != NULL && IsA(viewParse->utilityStmt, CreateTableAsStmt))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("views must not contain SELECT INTO")));

	if (viewParse->commandType != CMD_SELECT)
		elog(ERROR, "unexpected parse analysis result");

	
	if (viewParse->hasModifyingCTE)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("views must not contain data-modifying statements in WITH")));


	
	if (viewParse->hasDynamicFunctions)
		ereport(ERROR, (errcode(ERRCODE_INDETERMINATE_DATATYPE), errmsg("CREATE VIEW statements cannot include calls to " "dynamically typed function")));



	
	if (stmt->withCheckOption == LOCAL_CHECK_OPTION)
		stmt->options = lappend(stmt->options, makeDefElem("check_option", (Node *) makeString("local"), -1));

	else if (stmt->withCheckOption == CASCADED_CHECK_OPTION)
		stmt->options = lappend(stmt->options, makeDefElem("check_option", (Node *) makeString("cascaded"), -1));


	
	check_option = false;

	foreach(cell, stmt->options)
	{
		DefElem    *defel = (DefElem *) lfirst(cell);

		if (strcmp(defel->defname, "check_option") == 0)
			check_option = true;
	}

	
	if (check_option)
	{
		const char *view_updatable_error = view_query_is_auto_updatable(viewParse, true);

		if (view_updatable_error)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("WITH CHECK OPTION is supported only on automatically updatable views"), errhint("%s", _(view_updatable_error))));


	}

	
	if (stmt->aliases != NIL)
	{
		ListCell   *alist_item = list_head(stmt->aliases);
		ListCell   *targetList;

		foreach(targetList, viewParse->targetList)
		{
			TargetEntry *te = lfirst_node(TargetEntry, targetList);

			
			if (te->resjunk)
				continue;
			te->resname = pstrdup(strVal(lfirst(alist_item)));
			alist_item = lnext(alist_item);
			if (alist_item == NULL)
				break;			
		}

		if (alist_item != NULL)
			ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("CREATE VIEW specifies more column " "names than columns")));


	}

	
	if (stmt->view->relpersistence == RELPERSISTENCE_UNLOGGED)
		ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("views cannot be unlogged because they do not have storage")));


	
	view = copyObject(stmt->view);	
	if (view->relpersistence == RELPERSISTENCE_PERMANENT && isQueryUsingTempRelation(viewParse))
	{
		view->relpersistence = RELPERSISTENCE_TEMP;
		if (Gp_role != GP_ROLE_EXECUTE)
			ereport(NOTICE, (errmsg("view \"%s\" will be a temporary view", view->relname)));

	}

	
	address = DefineVirtualRelation(view, viewParse->targetList, stmt->replace, stmt->options, viewParse);

	if (Gp_role == GP_ROLE_DISPATCH)
	{
		ViewStmt *dispatchStmt = (ViewStmt *) copyObject(stmt);
		dispatchStmt->query = (Node *) viewParse_orig;
		CdbDispatchUtilityStatement((Node *) dispatchStmt, DF_CANCEL_ON_ERROR| DF_WITH_SNAPSHOT| DF_NEED_TWO_PHASE, GetAssignedOidsForDispatch(), NULL);




	}

	return address;
}


void StoreViewQuery(Oid viewOid, Query *viewParse, bool replace)
{
	
	viewParse = UpdateRangeTableOfViewParse(viewOid, viewParse);

	
	DefineViewRules(viewOid, viewParse, replace);
}
