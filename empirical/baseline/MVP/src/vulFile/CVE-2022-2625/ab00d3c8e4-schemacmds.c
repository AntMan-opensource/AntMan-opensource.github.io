






























static void AlterSchemaOwner_internal(HeapTuple tup, Relation rel, Oid newOwnerId);


Oid CreateSchemaCommand(CreateSchemaStmt *stmt, const char *queryString, int stmt_location, int stmt_len)

{
	const char *schemaName = stmt->schemaname;
	Oid			namespaceId;
	OverrideSearchPath *overridePath;
	List	   *parsetree_list;
	ListCell   *parsetree_item;
	Oid			owner_uid;
	Oid			saved_uid;
	int			save_sec_context;
	AclResult	aclresult;
	ObjectAddress address;
	bool		shouldDispatch = (Gp_role == GP_ROLE_DISPATCH &&  !IsBootstrapProcessingMode());

	
	if (stmt->istemp)
	{
		Assert(Gp_role == GP_ROLE_EXECUTE);

		Assert(stmt->schemaname == NULL);
		Assert(stmt->authrole == NULL);
		Assert(stmt->schemaElts == NIL);

		InitTempTableNamespace();
		return InvalidOid;
	}

	GetUserIdAndSecContext(&saved_uid, &save_sec_context);

	
	if (stmt->authrole)
		owner_uid = get_rolespec_oid(stmt->authrole, false);
	else owner_uid = saved_uid;

	
	if (!schemaName)
	{
		HeapTuple	tuple;

		tuple = SearchSysCache1(AUTHOID, ObjectIdGetDatum(owner_uid));
		if (!HeapTupleIsValid(tuple))
			elog(ERROR, "cache lookup failed for role %u", owner_uid);
		schemaName = pstrdup(NameStr(((Form_pg_authid) GETSTRUCT(tuple))->rolname));
		ReleaseSysCache(tuple);
	}

	
	aclresult = pg_database_aclcheck(MyDatabaseId, saved_uid, ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, OBJECT_DATABASE, get_database_name(MyDatabaseId));

	check_is_member_of_role(saved_uid, owner_uid);

	
	if (!allowSystemTableMods && IsReservedName(schemaName))
	{
		ereport(ERROR, (errcode(ERRCODE_RESERVED_NAME), errmsg("unacceptable schema name \"%s\"", schemaName), errdetail("The prefix \"%s\" is reserved for system schemas.", GetReservedPrefix(schemaName))));



	}

	
	if (stmt->if_not_exists && SearchSysCacheExists1(NAMESPACENAME, PointerGetDatum(schemaName)))
	{
		ereport(NOTICE, (errcode(ERRCODE_DUPLICATE_SCHEMA), errmsg("schema \"%s\" already exists, skipping", schemaName)));


		return InvalidOid;
	}

	
	if (shouldDispatch || Gp_role != GP_ROLE_EXECUTE)
	{
		namespaceId = NamespaceCreate(schemaName, owner_uid, false);

		if (shouldDispatch)
		{
			elog(DEBUG5, "shouldDispatch = true, namespaceOid = %d", namespaceId);

			
			CdbDispatchUtilityStatement((Node *) stmt, DF_CANCEL_ON_ERROR | DF_WITH_SNAPSHOT | DF_NEED_TWO_PHASE, GetAssignedOidsForDispatch(), NULL);




		}

		
		if (Gp_role == GP_ROLE_DISPATCH)
			MetaTrackAddObject(NamespaceRelationId, namespaceId, saved_uid, "CREATE", "SCHEMA" );



	}
	else {
		namespaceId = NamespaceCreate(schemaName, owner_uid, false);
	}

	
	if (saved_uid != owner_uid)
		SetUserIdAndSecContext(owner_uid, save_sec_context | SECURITY_LOCAL_USERID_CHANGE);

	
	CommandCounterIncrement();

	
	overridePath = GetOverrideSearchPath(CurrentMemoryContext);
	overridePath->schemas = lcons_oid(namespaceId, overridePath->schemas);
	
	PushOverrideSearchPath(overridePath);

	
	ObjectAddressSet(address, NamespaceRelationId, namespaceId);
	EventTriggerCollectSimpleCommand(address, InvalidObjectAddress, (Node *) stmt);

	
	parsetree_list = transformCreateSchemaStmt(stmt);

	
	foreach(parsetree_item, parsetree_list)
	{
		Node	   *stmt = (Node *) lfirst(parsetree_item);
		PlannedStmt *wrapper;

		
		wrapper = makeNode(PlannedStmt);
		wrapper->commandType = CMD_UTILITY;
		wrapper->canSetTag = false;
		wrapper->utilityStmt = stmt;
		wrapper->stmt_location = stmt_location;
		wrapper->stmt_len = stmt_len;

		
		ProcessUtility(wrapper, queryString, PROCESS_UTILITY_SUBCOMMAND, NULL, NULL, None_Receiver, NULL);






		
		CommandCounterIncrement();
	}

	
	PopOverrideSearchPath();

	
	SetUserIdAndSecContext(saved_uid, save_sec_context);

	return namespaceId;
}


void RemoveSchemaById(Oid schemaOid)
{
	Relation	relation;
	HeapTuple	tup;

	relation = table_open(NamespaceRelationId, RowExclusiveLock);

	tup = SearchSysCache1(NAMESPACEOID, ObjectIdGetDatum(schemaOid));
	if (!HeapTupleIsValid(tup)) 
		elog(ERROR, "cache lookup failed for namespace %u", schemaOid);

	CatalogTupleDelete(relation, &tup->t_self);

	ReleaseSysCache(tup);

	table_close(relation, RowExclusiveLock);

	
	PersistentErrorLogDelete(MyDatabaseId, schemaOid, NULL);
}



ObjectAddress RenameSchema(const char *oldname, const char *newname)
{
	Oid			nspOid;
	HeapTuple	tup;
	Relation	rel;
	AclResult	aclresult;
	ObjectAddress address;
	Form_pg_namespace nspform;

	rel = table_open(NamespaceRelationId, RowExclusiveLock);

	tup = SearchSysCacheCopy1(NAMESPACENAME, CStringGetDatum(oldname));
	if (!HeapTupleIsValid(tup))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_SCHEMA), errmsg("schema \"%s\" does not exist", oldname)));


	nspform = (Form_pg_namespace) GETSTRUCT(tup);
	nspOid = nspform->oid;

	
	if (OidIsValid(get_namespace_oid(newname, true)))
		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_SCHEMA), errmsg("schema \"%s\" already exists", newname)));


	
	if (!pg_namespace_ownercheck(nspOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, OBJECT_SCHEMA, oldname);

	
	aclresult = pg_database_aclcheck(MyDatabaseId, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, OBJECT_DATABASE, get_database_name(MyDatabaseId));

	if (!allowSystemTableMods && IsReservedName(oldname))
	{
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied to ALTER SCHEMA \"%s\"", oldname), errdetail("Schema %s is reserved for system use.", oldname)));


	}

	if (!allowSystemTableMods && IsReservedName(newname))
	{
		ereport(ERROR, (errcode(ERRCODE_RESERVED_NAME), errmsg("unacceptable schema name \"%s\"", newname), errdetail("The prefix \"%s\" is reserved for system schemas.", GetReservedPrefix(newname))));



	}

	
	namestrcpy(&nspform->nspname, newname);
	CatalogTupleUpdate(rel, &tup->t_self, tup);

	
	if (Gp_role == GP_ROLE_DISPATCH)
		MetaTrackUpdObject(NamespaceRelationId, nspOid, GetUserId(), "ALTER", "RENAME" );




	InvokeObjectPostAlterHook(NamespaceRelationId, nspOid, 0);

	ObjectAddressSet(address, NamespaceRelationId, nspOid);

	table_close(rel, NoLock);
	heap_freetuple(tup);

	return address;
}

void AlterSchemaOwner_oid(Oid oid, Oid newOwnerId)
{
	HeapTuple	tup;
	Relation	rel;

	rel = table_open(NamespaceRelationId, RowExclusiveLock);

	tup = SearchSysCache1(NAMESPACEOID, ObjectIdGetDatum(oid));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for schema %u", oid);

	AlterSchemaOwner_internal(tup, rel, newOwnerId);

	ReleaseSysCache(tup);

	table_close(rel, RowExclusiveLock);
}



ObjectAddress AlterSchemaOwner(const char *name, Oid newOwnerId)
{
	Oid			nspOid;
	HeapTuple	tup;
	Relation	rel;
	ObjectAddress address;
	Form_pg_namespace nspform;

	rel = table_open(NamespaceRelationId, RowExclusiveLock);

	tup = SearchSysCache1(NAMESPACENAME, CStringGetDatum(name));
	if (!HeapTupleIsValid(tup))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_SCHEMA), errmsg("schema \"%s\" does not exist", name)));


	if (!allowSystemTableMods && IsReservedName(name))
	{
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied to ALTER SCHEMA \"%s\"", name), errdetail("Schema %s is reserved for system use.", name)));


	}

	nspform = (Form_pg_namespace) GETSTRUCT(tup);
	nspOid = nspform->oid;

	AlterSchemaOwner_internal(tup, rel, newOwnerId);

	ObjectAddressSet(address, NamespaceRelationId, nspOid);

	ReleaseSysCache(tup);

	table_close(rel, RowExclusiveLock);

	return address;
}

static void AlterSchemaOwner_internal(HeapTuple tup, Relation rel, Oid newOwnerId)
{
	Form_pg_namespace nspForm;

	Assert(tup->t_tableOid == NamespaceRelationId);
	Assert(RelationGetRelid(rel) == NamespaceRelationId);

	nspForm = (Form_pg_namespace) GETSTRUCT(tup);

	
	if (nspForm->nspowner != newOwnerId)
	{
		Datum		repl_val[Natts_pg_namespace];
		bool		repl_null[Natts_pg_namespace];
		bool		repl_repl[Natts_pg_namespace];
		Acl		   *newAcl;
		Datum		aclDatum;
		bool		isNull;
		HeapTuple	newtuple;
		AclResult	aclresult;

		
		if (!pg_namespace_ownercheck(nspForm->oid, GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, OBJECT_SCHEMA, NameStr(nspForm->nspname));

		
		check_is_member_of_role(GetUserId(), newOwnerId);

		
		aclresult = pg_database_aclcheck(MyDatabaseId, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, OBJECT_DATABASE, get_database_name(MyDatabaseId));

		memset(repl_null, false, sizeof(repl_null));
		memset(repl_repl, false, sizeof(repl_repl));

		repl_repl[Anum_pg_namespace_nspowner - 1] = true;
		repl_val[Anum_pg_namespace_nspowner - 1] = ObjectIdGetDatum(newOwnerId);

		
		aclDatum = SysCacheGetAttr(NAMESPACENAME, tup, Anum_pg_namespace_nspacl, &isNull);

		if (!isNull)
		{
			newAcl = aclnewowner(DatumGetAclP(aclDatum), nspForm->nspowner, newOwnerId);
			repl_repl[Anum_pg_namespace_nspacl - 1] = true;
			repl_val[Anum_pg_namespace_nspacl - 1] = PointerGetDatum(newAcl);
		}

		newtuple = heap_modify_tuple(tup, RelationGetDescr(rel), repl_val, repl_null, repl_repl);

		CatalogTupleUpdate(rel, &newtuple->t_self, newtuple);

		
		if (Gp_role == GP_ROLE_DISPATCH)
			MetaTrackUpdObject(NamespaceRelationId, nspForm->oid, GetUserId(), "ALTER", "OWNER" );




		heap_freetuple(newtuple);

		
		changeDependencyOnOwner(NamespaceRelationId, nspForm->oid, newOwnerId);
	}

	InvokeObjectPostAlterHook(NamespaceRelationId, nspForm->oid, 0);
}
