



































typedef struct {
	char	   *tablename;
	char	   *cmd;
} import_error_callback_arg;


static void import_error_callback(void *arg);



static Datum optionListToArray(List *options)
{
	ArrayBuildState *astate = NULL;
	ListCell   *cell;

	foreach(cell, options)
	{
		DefElem    *def = lfirst(cell);
		const char *value;
		Size		len;
		text	   *t;

		value = defGetString(def);
		len = VARHDRSZ + strlen(def->defname) + 1 + strlen(value);
		t = palloc(len + 1);
		SET_VARSIZE(t, len);
		sprintf(VARDATA(t), "%s=%s", def->defname, value);

		astate = accumArrayResult(astate, PointerGetDatum(t), false, TEXTOID, CurrentMemoryContext);

	}

	if (astate)
		return makeArrayResult(astate, CurrentMemoryContext);

	return PointerGetDatum(NULL);
}



Datum transformGenericOptions(Oid catalogId, Datum oldOptions, List *options, Oid fdwvalidator)



{
	List	   *resultOptions = untransformRelOptions(oldOptions);
	ListCell   *optcell;
	Datum		result;

	foreach(optcell, options)
	{
		DefElem    *od = lfirst(optcell);
		ListCell   *cell;
		ListCell   *prev = NULL;

		
		foreach(cell, resultOptions)
		{
			DefElem    *def = lfirst(cell);

			if (strcmp(def->defname, od->defname) == 0)
				break;
			else prev = cell;
		}

		
		switch (od->defaction)
		{
			case DEFELEM_DROP:
				if (!cell)
					ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("option \"%s\" not found", od->defname)));


				resultOptions = list_delete_cell(resultOptions, cell, prev);
				break;

			case DEFELEM_SET:
				if (!cell)
					ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("option \"%s\" not found", od->defname)));


				lfirst(cell) = od;
				break;

			case DEFELEM_ADD:
			case DEFELEM_UNSPEC:
				if (cell)
					ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("option \"%s\" provided more than once", od->defname)));


				resultOptions = lappend(resultOptions, od);
				break;

			default:
				elog(ERROR, "unrecognized action %d on option \"%s\"", (int) od->defaction, od->defname);
				break;
		}
	}

	result = optionListToArray(resultOptions);

	
	if (catalogId != UserMappingRelationId)
	{
		SeparateOutMppExecute(&resultOptions);
	}

	if (OidIsValid(fdwvalidator))
	{
		Datum valarg = optionListToArray(resultOptions);

		
		if (DatumGetPointer(valarg) == NULL)
			valarg = PointerGetDatum(construct_empty_array(TEXTOID));
		OidFunctionCall2(fdwvalidator, valarg, ObjectIdGetDatum(catalogId));
	}

	return result;
}



static void AlterForeignDataWrapperOwner_internal(Relation rel, HeapTuple tup, Oid newOwnerId)
{
	Form_pg_foreign_data_wrapper form;
	Datum		repl_val[Natts_pg_foreign_data_wrapper];
	bool		repl_null[Natts_pg_foreign_data_wrapper];
	bool		repl_repl[Natts_pg_foreign_data_wrapper];
	Acl		   *newAcl;
	Datum		aclDatum;
	bool		isNull;

	form = (Form_pg_foreign_data_wrapper) GETSTRUCT(tup);

	
	if (!superuser())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied to change owner of foreign-data wrapper \"%s\"", NameStr(form->fdwname)), errhint("Must be superuser to change owner of a foreign-data wrapper.")));




	
	if (!superuser_arg(newOwnerId))
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied to change owner of foreign-data wrapper \"%s\"", NameStr(form->fdwname)), errhint("The owner of a foreign-data wrapper must be a superuser.")));




	if (form->fdwowner != newOwnerId)
	{
		memset(repl_null, false, sizeof(repl_null));
		memset(repl_repl, false, sizeof(repl_repl));

		repl_repl[Anum_pg_foreign_data_wrapper_fdwowner - 1] = true;
		repl_val[Anum_pg_foreign_data_wrapper_fdwowner - 1] = ObjectIdGetDatum(newOwnerId);

		aclDatum = heap_getattr(tup, Anum_pg_foreign_data_wrapper_fdwacl, RelationGetDescr(rel), &isNull);


		
		if (!isNull)
		{
			newAcl = aclnewowner(DatumGetAclP(aclDatum), form->fdwowner, newOwnerId);
			repl_repl[Anum_pg_foreign_data_wrapper_fdwacl - 1] = true;
			repl_val[Anum_pg_foreign_data_wrapper_fdwacl - 1] = PointerGetDatum(newAcl);
		}

		tup = heap_modify_tuple(tup, RelationGetDescr(rel), repl_val, repl_null, repl_repl);

		CatalogTupleUpdate(rel, &tup->t_self, tup);

		
		changeDependencyOnOwner(ForeignDataWrapperRelationId, form->oid, newOwnerId);

	}

	InvokeObjectPostAlterHook(ForeignDataWrapperRelationId, form->oid, 0);
}


ObjectAddress AlterForeignDataWrapperOwner(const char *name, Oid newOwnerId)
{
	Oid			fdwId;
	HeapTuple	tup;
	Relation	rel;
	ObjectAddress address;
	Form_pg_foreign_data_wrapper form;


	rel = table_open(ForeignDataWrapperRelationId, RowExclusiveLock);

	tup = SearchSysCacheCopy1(FOREIGNDATAWRAPPERNAME, CStringGetDatum(name));

	if (!HeapTupleIsValid(tup))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("foreign-data wrapper \"%s\" does not exist", name)));


	form = (Form_pg_foreign_data_wrapper) GETSTRUCT(tup);
	fdwId = form->oid;

	AlterForeignDataWrapperOwner_internal(rel, tup, newOwnerId);

	ObjectAddressSet(address, ForeignDataWrapperRelationId, fdwId);

	heap_freetuple(tup);

	table_close(rel, RowExclusiveLock);

	return address;
}


void AlterForeignDataWrapperOwner_oid(Oid fwdId, Oid newOwnerId)
{
	HeapTuple	tup;
	Relation	rel;

	rel = table_open(ForeignDataWrapperRelationId, RowExclusiveLock);

	tup = SearchSysCacheCopy1(FOREIGNDATAWRAPPEROID, ObjectIdGetDatum(fwdId));

	if (!HeapTupleIsValid(tup))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("foreign-data wrapper with OID %u does not exist", fwdId)));


	AlterForeignDataWrapperOwner_internal(rel, tup, newOwnerId);

	heap_freetuple(tup);

	table_close(rel, RowExclusiveLock);
}


static void AlterForeignServerOwner_internal(Relation rel, HeapTuple tup, Oid newOwnerId)
{
	Form_pg_foreign_server form;
	Datum		repl_val[Natts_pg_foreign_server];
	bool		repl_null[Natts_pg_foreign_server];
	bool		repl_repl[Natts_pg_foreign_server];
	Acl		   *newAcl;
	Datum		aclDatum;
	bool		isNull;

	form = (Form_pg_foreign_server) GETSTRUCT(tup);

	if (form->srvowner != newOwnerId)
	{
		
		if (!superuser())
		{
			Oid			srvId;
			AclResult	aclresult;

			srvId = form->oid;

			
			if (!pg_foreign_server_ownercheck(srvId, GetUserId()))
				aclcheck_error(ACLCHECK_NOT_OWNER, OBJECT_FOREIGN_SERVER, NameStr(form->srvname));

			
			check_is_member_of_role(GetUserId(), newOwnerId);

			
			aclresult = pg_foreign_data_wrapper_aclcheck(form->srvfdw, newOwnerId, ACL_USAGE);
			if (aclresult != ACLCHECK_OK)
			{
				ForeignDataWrapper *fdw = GetForeignDataWrapper(form->srvfdw);

				aclcheck_error(aclresult, OBJECT_FDW, fdw->fdwname);
			}
		}

		memset(repl_null, false, sizeof(repl_null));
		memset(repl_repl, false, sizeof(repl_repl));

		repl_repl[Anum_pg_foreign_server_srvowner - 1] = true;
		repl_val[Anum_pg_foreign_server_srvowner - 1] = ObjectIdGetDatum(newOwnerId);

		aclDatum = heap_getattr(tup, Anum_pg_foreign_server_srvacl, RelationGetDescr(rel), &isNull);


		
		if (!isNull)
		{
			newAcl = aclnewowner(DatumGetAclP(aclDatum), form->srvowner, newOwnerId);
			repl_repl[Anum_pg_foreign_server_srvacl - 1] = true;
			repl_val[Anum_pg_foreign_server_srvacl - 1] = PointerGetDatum(newAcl);
		}

		tup = heap_modify_tuple(tup, RelationGetDescr(rel), repl_val, repl_null, repl_repl);

		CatalogTupleUpdate(rel, &tup->t_self, tup);

		
		changeDependencyOnOwner(ForeignServerRelationId, form->oid, newOwnerId);
	}

	InvokeObjectPostAlterHook(ForeignServerRelationId, form->oid, 0);
}


ObjectAddress AlterForeignServerOwner(const char *name, Oid newOwnerId)
{
	Oid			servOid;
	HeapTuple	tup;
	Relation	rel;
	ObjectAddress address;
	Form_pg_foreign_server form;

	rel = table_open(ForeignServerRelationId, RowExclusiveLock);

	tup = SearchSysCacheCopy1(FOREIGNSERVERNAME, CStringGetDatum(name));

	if (!HeapTupleIsValid(tup))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("server \"%s\" does not exist", name)));


	form = (Form_pg_foreign_server) GETSTRUCT(tup);
	servOid = form->oid;

	AlterForeignServerOwner_internal(rel, tup, newOwnerId);

	ObjectAddressSet(address, ForeignServerRelationId, servOid);

	heap_freetuple(tup);

	table_close(rel, RowExclusiveLock);

	return address;
}


void AlterForeignServerOwner_oid(Oid srvId, Oid newOwnerId)
{
	HeapTuple	tup;
	Relation	rel;

	rel = table_open(ForeignServerRelationId, RowExclusiveLock);

	tup = SearchSysCacheCopy1(FOREIGNSERVEROID, ObjectIdGetDatum(srvId));

	if (!HeapTupleIsValid(tup))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("foreign server with OID %u does not exist", srvId)));


	AlterForeignServerOwner_internal(rel, tup, newOwnerId);

	heap_freetuple(tup);

	table_close(rel, RowExclusiveLock);
}


static Oid lookup_fdw_handler_func(DefElem *handler)
{
	Oid			handlerOid;

	if (handler == NULL || handler->arg == NULL)
		return InvalidOid;

	
	handlerOid = LookupFuncName((List *) handler->arg, 0, NULL, false);

	
	if (get_func_rettype(handlerOid) != FDW_HANDLEROID)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("function %s must return type %s", NameListToString((List *) handler->arg), "fdw_handler")));



	return handlerOid;
}


static Oid lookup_fdw_validator_func(DefElem *validator)
{
	Oid			funcargtypes[2];

	if (validator == NULL || validator->arg == NULL)
		return InvalidOid;

	
	funcargtypes[0] = TEXTARRAYOID;
	funcargtypes[1] = OIDOID;

	return LookupFuncName((List *) validator->arg, 2, funcargtypes, false);
	
}


static void parse_func_options(List *func_options, bool *handler_given, Oid *fdwhandler, bool *validator_given, Oid *fdwvalidator)


{
	ListCell   *cell;

	*handler_given = false;
	*validator_given = false;
	
	*fdwhandler = InvalidOid;
	*fdwvalidator = InvalidOid;

	foreach(cell, func_options)
	{
		DefElem    *def = (DefElem *) lfirst(cell);

		if (strcmp(def->defname, "handler") == 0)
		{
			if (*handler_given)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options")));

			*handler_given = true;
			*fdwhandler = lookup_fdw_handler_func(def);
		}
		else if (strcmp(def->defname, "validator") == 0)
		{
			if (*validator_given)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options")));

			*validator_given = true;
			*fdwvalidator = lookup_fdw_validator_func(def);
		}
		else elog(ERROR, "option \"%s\" not recognized", def->defname);

	}
}


ObjectAddress CreateForeignDataWrapper(CreateFdwStmt *stmt)
{
	Relation	rel;
	Datum		values[Natts_pg_foreign_data_wrapper];
	bool		nulls[Natts_pg_foreign_data_wrapper];
	HeapTuple	tuple;
	Oid			fdwId;
	bool		handler_given;
	bool		validator_given;
	Oid			fdwhandler;
	Oid			fdwvalidator;
	Datum		fdwoptions;
	Oid			ownerId;
	ObjectAddress myself;
	ObjectAddress referenced;

	rel = table_open(ForeignDataWrapperRelationId, RowExclusiveLock);

	
	if (!superuser())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied to create foreign-data wrapper \"%s\"", stmt->fdwname), errhint("Must be superuser to create a foreign-data wrapper.")));




	
	ownerId = GetUserId();

	
	if (GetForeignDataWrapperByName(stmt->fdwname, true) != NULL)
		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("foreign-data wrapper \"%s\" already exists", stmt->fdwname)));



	
	memset(values, 0, sizeof(values));
	memset(nulls, false, sizeof(nulls));

	fdwId = GetNewOidForForeignDataWrapper(rel, ForeignDataWrapperOidIndexId, Anum_pg_foreign_data_wrapper_oid, stmt->fdwname);

	values[Anum_pg_foreign_data_wrapper_oid - 1] = ObjectIdGetDatum(fdwId);
	values[Anum_pg_foreign_data_wrapper_fdwname - 1] = DirectFunctionCall1(namein, CStringGetDatum(stmt->fdwname));
	values[Anum_pg_foreign_data_wrapper_fdwowner - 1] = ObjectIdGetDatum(ownerId);

	
	parse_func_options(stmt->func_options, &handler_given, &fdwhandler, &validator_given, &fdwvalidator);


	values[Anum_pg_foreign_data_wrapper_fdwhandler - 1] = ObjectIdGetDatum(fdwhandler);
	values[Anum_pg_foreign_data_wrapper_fdwvalidator - 1] = ObjectIdGetDatum(fdwvalidator);

	nulls[Anum_pg_foreign_data_wrapper_fdwacl - 1] = true;

	fdwoptions = transformGenericOptions(ForeignDataWrapperRelationId, PointerGetDatum(NULL), stmt->options, fdwvalidator);



	if (PointerIsValid(DatumGetPointer(fdwoptions)))
		values[Anum_pg_foreign_data_wrapper_fdwoptions - 1] = fdwoptions;
	else nulls[Anum_pg_foreign_data_wrapper_fdwoptions - 1] = true;

	tuple = heap_form_tuple(rel->rd_att, values, nulls);

	CatalogTupleInsert(rel, tuple);

	heap_freetuple(tuple);

	
	myself.classId = ForeignDataWrapperRelationId;
	myself.objectId = fdwId;
	myself.objectSubId = 0;

	if (OidIsValid(fdwhandler))
	{
		referenced.classId = ProcedureRelationId;
		referenced.objectId = fdwhandler;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
	}

	if (OidIsValid(fdwvalidator))
	{
		referenced.classId = ProcedureRelationId;
		referenced.objectId = fdwvalidator;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
	}

	recordDependencyOnOwner(ForeignDataWrapperRelationId, fdwId, ownerId);

	
	recordDependencyOnCurrentExtension(&myself, false);

	
	InvokeObjectPostCreateHook(ForeignDataWrapperRelationId, fdwId, 0);

	if (Gp_role == GP_ROLE_DISPATCH)
	{
		CdbDispatchUtilityStatement((Node *) stmt, DF_WITH_SNAPSHOT | DF_CANCEL_ON_ERROR | DF_NEED_TWO_PHASE, GetAssignedOidsForDispatch(), NULL);


	}

	table_close(rel, RowExclusiveLock);

	return myself;
}



ObjectAddress AlterForeignDataWrapper(AlterFdwStmt *stmt)
{
	Relation	rel;
	HeapTuple	tp;
	Form_pg_foreign_data_wrapper fdwForm;
	Datum		repl_val[Natts_pg_foreign_data_wrapper];
	bool		repl_null[Natts_pg_foreign_data_wrapper];
	bool		repl_repl[Natts_pg_foreign_data_wrapper];
	Oid			fdwId;
	bool		isnull;
	Datum		datum;
	bool		handler_given;
	bool		validator_given;
	Oid			fdwhandler;
	Oid			fdwvalidator;
	ObjectAddress myself;

	rel = table_open(ForeignDataWrapperRelationId, RowExclusiveLock);

	
	if (!superuser())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied to alter foreign-data wrapper \"%s\"", stmt->fdwname), errhint("Must be superuser to alter a foreign-data wrapper.")));




	tp = SearchSysCacheCopy1(FOREIGNDATAWRAPPERNAME, CStringGetDatum(stmt->fdwname));

	if (!HeapTupleIsValid(tp))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("foreign-data wrapper \"%s\" does not exist", stmt->fdwname)));


	fdwForm = (Form_pg_foreign_data_wrapper) GETSTRUCT(tp);
	fdwId = fdwForm->oid;

	memset(repl_val, 0, sizeof(repl_val));
	memset(repl_null, false, sizeof(repl_null));
	memset(repl_repl, false, sizeof(repl_repl));

	parse_func_options(stmt->func_options, &handler_given, &fdwhandler, &validator_given, &fdwvalidator);


	if (handler_given)
	{
		repl_val[Anum_pg_foreign_data_wrapper_fdwhandler - 1] = ObjectIdGetDatum(fdwhandler);
		repl_repl[Anum_pg_foreign_data_wrapper_fdwhandler - 1] = true;

		
		ereport(WARNING, (errmsg("changing the foreign-data wrapper handler can change behavior of existing foreign tables")));
	}

	if (validator_given)
	{
		repl_val[Anum_pg_foreign_data_wrapper_fdwvalidator - 1] = ObjectIdGetDatum(fdwvalidator);
		repl_repl[Anum_pg_foreign_data_wrapper_fdwvalidator - 1] = true;

		
		if (OidIsValid(fdwvalidator))
			ereport(WARNING, (errmsg("changing the foreign-data wrapper validator can cause " "the options for dependent objects to become invalid")));

	}
	else {
		
		fdwvalidator = fdwForm->fdwvalidator;
	}

	
	if (stmt->options)
	{
		
		datum = SysCacheGetAttr(FOREIGNDATAWRAPPEROID, tp, Anum_pg_foreign_data_wrapper_fdwoptions, &isnull);


		if (isnull)
			datum = PointerGetDatum(NULL);

		
		datum = transformGenericOptions(ForeignDataWrapperRelationId, datum, stmt->options, fdwvalidator);



		if (PointerIsValid(DatumGetPointer(datum)))
			repl_val[Anum_pg_foreign_data_wrapper_fdwoptions - 1] = datum;
		else repl_null[Anum_pg_foreign_data_wrapper_fdwoptions - 1] = true;

		repl_repl[Anum_pg_foreign_data_wrapper_fdwoptions - 1] = true;
	}

	
	tp = heap_modify_tuple(tp, RelationGetDescr(rel), repl_val, repl_null, repl_repl);

	CatalogTupleUpdate(rel, &tp->t_self, tp);

	heap_freetuple(tp);

	ObjectAddressSet(myself, ForeignDataWrapperRelationId, fdwId);

	
	if (handler_given || validator_given)
	{
		ObjectAddress referenced;

		
		deleteDependencyRecordsForClass(ForeignDataWrapperRelationId, fdwId, ProcedureRelationId, DEPENDENCY_NORMAL);



		

		if (OidIsValid(fdwhandler))
		{
			referenced.classId = ProcedureRelationId;
			referenced.objectId = fdwhandler;
			referenced.objectSubId = 0;
			recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
		}

		if (OidIsValid(fdwvalidator))
		{
			referenced.classId = ProcedureRelationId;
			referenced.objectId = fdwvalidator;
			referenced.objectSubId = 0;
			recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
		}
	}

	if (Gp_role == GP_ROLE_DISPATCH)
	{
		CdbDispatchUtilityStatement((Node *) stmt, DF_WITH_SNAPSHOT | DF_CANCEL_ON_ERROR | DF_NEED_TWO_PHASE, GetAssignedOidsForDispatch(), NULL);


	}
	InvokeObjectPostAlterHook(ForeignDataWrapperRelationId, fdwId, 0);

	table_close(rel, RowExclusiveLock);

	return myself;
}



void RemoveForeignDataWrapperById(Oid fdwId)
{
	HeapTuple	tp;
	Relation	rel;

	rel = table_open(ForeignDataWrapperRelationId, RowExclusiveLock);

	tp = SearchSysCache1(FOREIGNDATAWRAPPEROID, ObjectIdGetDatum(fdwId));

	if (!HeapTupleIsValid(tp))
		elog(ERROR, "cache lookup failed for foreign-data wrapper %u", fdwId);

	CatalogTupleDelete(rel, &tp->t_self);

	ReleaseSysCache(tp);

	table_close(rel, RowExclusiveLock);
}



ObjectAddress CreateForeignServer(CreateForeignServerStmt *stmt)
{
	Relation	rel;
	Datum		srvoptions;
	Datum		values[Natts_pg_foreign_server];
	bool		nulls[Natts_pg_foreign_server];
	HeapTuple	tuple;
	Oid			srvId;
	Oid			ownerId;
	AclResult	aclresult;
	ObjectAddress myself;
	ObjectAddress referenced;
	ForeignDataWrapper *fdw;

	rel = table_open(ForeignServerRelationId, RowExclusiveLock);

	
	ownerId = GetUserId();

	
	if (GetForeignServerByName(stmt->servername, true) != NULL)
	{
		if (stmt->if_not_exists)
		{
			ereport(NOTICE, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("server \"%s\" already exists, skipping", stmt->servername)));


			table_close(rel, RowExclusiveLock);
			return InvalidObjectAddress;
		}
		else ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("server \"%s\" already exists", stmt->servername)));



	}

	
	fdw = GetForeignDataWrapperByName(stmt->fdwname, false);

	aclresult = pg_foreign_data_wrapper_aclcheck(fdw->fdwid, ownerId, ACL_USAGE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, OBJECT_FDW, fdw->fdwname);

	
	memset(values, 0, sizeof(values));
	memset(nulls, false, sizeof(nulls));

	srvId = GetNewOidForForeignServer(rel, ForeignServerOidIndexId, Anum_pg_foreign_server_oid, stmt->servername);

	values[Anum_pg_foreign_server_oid - 1] = ObjectIdGetDatum(srvId);
	values[Anum_pg_foreign_server_srvname - 1] = DirectFunctionCall1(namein, CStringGetDatum(stmt->servername));
	values[Anum_pg_foreign_server_srvowner - 1] = ObjectIdGetDatum(ownerId);
	values[Anum_pg_foreign_server_srvfdw - 1] = ObjectIdGetDatum(fdw->fdwid);

	
	if (stmt->servertype)
		values[Anum_pg_foreign_server_srvtype - 1] = CStringGetTextDatum(stmt->servertype);
	else nulls[Anum_pg_foreign_server_srvtype - 1] = true;

	
	if (stmt->version)
		values[Anum_pg_foreign_server_srvversion - 1] = CStringGetTextDatum(stmt->version);
	else nulls[Anum_pg_foreign_server_srvversion - 1] = true;

	
	nulls[Anum_pg_foreign_server_srvacl - 1] = true;

	
	srvoptions = transformGenericOptions(ForeignServerRelationId, PointerGetDatum(NULL), stmt->options, fdw->fdwvalidator);



	if (PointerIsValid(DatumGetPointer(srvoptions)))
		values[Anum_pg_foreign_server_srvoptions - 1] = srvoptions;
	else nulls[Anum_pg_foreign_server_srvoptions - 1] = true;

	tuple = heap_form_tuple(rel->rd_att, values, nulls);

	CatalogTupleInsert(rel, tuple);

	heap_freetuple(tuple);

	
	myself.classId = ForeignServerRelationId;
	myself.objectId = srvId;
	myself.objectSubId = 0;

	referenced.classId = ForeignDataWrapperRelationId;
	referenced.objectId = fdw->fdwid;
	referenced.objectSubId = 0;
	recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);

	recordDependencyOnOwner(ForeignServerRelationId, srvId, ownerId);

	
	recordDependencyOnCurrentExtension(&myself, false);

	
	InvokeObjectPostCreateHook(ForeignServerRelationId, srvId, 0);

	if (Gp_role == GP_ROLE_DISPATCH)
	{
		CdbDispatchUtilityStatement((Node *) stmt, DF_WITH_SNAPSHOT | DF_CANCEL_ON_ERROR | DF_NEED_TWO_PHASE, GetAssignedOidsForDispatch(), NULL);


	}

	table_close(rel, RowExclusiveLock);

	return myself;
}



ObjectAddress AlterForeignServer(AlterForeignServerStmt *stmt)
{
	Relation	rel;
	HeapTuple	tp;
	Datum		repl_val[Natts_pg_foreign_server];
	bool		repl_null[Natts_pg_foreign_server];
	bool		repl_repl[Natts_pg_foreign_server];
	Oid			srvId;
	Form_pg_foreign_server srvForm;
	ObjectAddress address;

	rel = table_open(ForeignServerRelationId, RowExclusiveLock);

	tp = SearchSysCacheCopy1(FOREIGNSERVERNAME, CStringGetDatum(stmt->servername));

	if (!HeapTupleIsValid(tp))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("server \"%s\" does not exist", stmt->servername)));


	srvForm = (Form_pg_foreign_server) GETSTRUCT(tp);
	srvId = srvForm->oid;

	
	if (!pg_foreign_server_ownercheck(srvId, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, OBJECT_FOREIGN_SERVER, stmt->servername);

	memset(repl_val, 0, sizeof(repl_val));
	memset(repl_null, false, sizeof(repl_null));
	memset(repl_repl, false, sizeof(repl_repl));

	if (stmt->has_version)
	{
		
		if (stmt->version)
			repl_val[Anum_pg_foreign_server_srvversion - 1] = CStringGetTextDatum(stmt->version);
		else repl_null[Anum_pg_foreign_server_srvversion - 1] = true;

		repl_repl[Anum_pg_foreign_server_srvversion - 1] = true;
	}

	if (stmt->options)
	{
		ForeignDataWrapper *fdw = GetForeignDataWrapper(srvForm->srvfdw);
		Datum		datum;
		bool		isnull;

		
		datum = SysCacheGetAttr(FOREIGNSERVEROID, tp, Anum_pg_foreign_server_srvoptions, &isnull);


		if (isnull)
			datum = PointerGetDatum(NULL);

		
		datum = transformGenericOptions(ForeignServerRelationId, datum, stmt->options, fdw->fdwvalidator);



		if (PointerIsValid(DatumGetPointer(datum)))
			repl_val[Anum_pg_foreign_server_srvoptions - 1] = datum;
		else repl_null[Anum_pg_foreign_server_srvoptions - 1] = true;

		repl_repl[Anum_pg_foreign_server_srvoptions - 1] = true;
	}

	
	tp = heap_modify_tuple(tp, RelationGetDescr(rel), repl_val, repl_null, repl_repl);

	CatalogTupleUpdate(rel, &tp->t_self, tp);

	InvokeObjectPostAlterHook(ForeignServerRelationId, srvId, 0);

	ObjectAddressSet(address, ForeignServerRelationId, srvId);

	heap_freetuple(tp);

	if (Gp_role == GP_ROLE_DISPATCH)
	{
		CdbDispatchUtilityStatement((Node *) stmt, DF_WITH_SNAPSHOT | DF_CANCEL_ON_ERROR | DF_NEED_TWO_PHASE, GetAssignedOidsForDispatch(), NULL);


	}

	table_close(rel, RowExclusiveLock);

	return address;
}



void RemoveForeignServerById(Oid srvId)
{
	HeapTuple	tp;
	Relation	rel;

	rel = table_open(ForeignServerRelationId, RowExclusiveLock);

	tp = SearchSysCache1(FOREIGNSERVEROID, ObjectIdGetDatum(srvId));

	if (!HeapTupleIsValid(tp))
		elog(ERROR, "cache lookup failed for foreign server %u", srvId);

	CatalogTupleDelete(rel, &tp->t_self);

	ReleaseSysCache(tp);

	table_close(rel, RowExclusiveLock);
}



static void user_mapping_ddl_aclcheck(Oid umuserid, Oid serverid, const char *servername)
{
	Oid			curuserid = GetUserId();

	if (!pg_foreign_server_ownercheck(serverid, curuserid))
	{
		if (umuserid == curuserid)
		{
			AclResult	aclresult;

			aclresult = pg_foreign_server_aclcheck(serverid, curuserid, ACL_USAGE);
			if (aclresult != ACLCHECK_OK)
				aclcheck_error(aclresult, OBJECT_FOREIGN_SERVER, servername);
		}
		else aclcheck_error(ACLCHECK_NOT_OWNER, OBJECT_FOREIGN_SERVER, servername);

	}
}



ObjectAddress CreateUserMapping(CreateUserMappingStmt *stmt)
{
	Relation	rel;
	Datum		useoptions;
	Datum		values[Natts_pg_user_mapping];
	bool		nulls[Natts_pg_user_mapping];
	HeapTuple	tuple;
	Oid			useId;
	Oid			umId;
	ObjectAddress myself;
	ObjectAddress referenced;
	ForeignServer *srv;
	ForeignDataWrapper *fdw;
	RoleSpec   *role = (RoleSpec *) stmt->user;

	rel = table_open(UserMappingRelationId, RowExclusiveLock);

	if (role->roletype == ROLESPEC_PUBLIC)
		useId = ACL_ID_PUBLIC;
	else useId = get_rolespec_oid(stmt->user, false);

	
	srv = GetForeignServerByName(stmt->servername, false);

	user_mapping_ddl_aclcheck(useId, srv->serverid, stmt->servername);

	
	umId = GetSysCacheOid2(USERMAPPINGUSERSERVER, Anum_pg_user_mapping_oid, ObjectIdGetDatum(useId), ObjectIdGetDatum(srv->serverid));


	if (OidIsValid(umId))
	{
		if (stmt->if_not_exists)
		{
			ereport(NOTICE, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("user mapping for \"%s\" already exists for server \"%s\", skipping", MappingUserName(useId), stmt->servername)));




			table_close(rel, RowExclusiveLock);
			return InvalidObjectAddress;
		}
		else ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("user mapping for \"%s\" already exists for server \"%s\"", MappingUserName(useId), stmt->servername)));




	}

	fdw = GetForeignDataWrapper(srv->fdwid);

	
	memset(values, 0, sizeof(values));
	memset(nulls, false, sizeof(nulls));

	umId = GetNewOidForUserMapping(rel, UserMappingOidIndexId, Anum_pg_user_mapping_oid, useId, srv->serverid);

	values[Anum_pg_user_mapping_oid - 1] = ObjectIdGetDatum(umId);
	values[Anum_pg_user_mapping_umuser - 1] = ObjectIdGetDatum(useId);
	values[Anum_pg_user_mapping_umserver - 1] = ObjectIdGetDatum(srv->serverid);

	
	useoptions = transformGenericOptions(UserMappingRelationId, PointerGetDatum(NULL), stmt->options, fdw->fdwvalidator);



	if (PointerIsValid(DatumGetPointer(useoptions)))
		values[Anum_pg_user_mapping_umoptions - 1] = useoptions;
	else nulls[Anum_pg_user_mapping_umoptions - 1] = true;

	tuple = heap_form_tuple(rel->rd_att, values, nulls);

	CatalogTupleInsert(rel, tuple);

	heap_freetuple(tuple);

	
	myself.classId = UserMappingRelationId;
	myself.objectId = umId;
	myself.objectSubId = 0;

	referenced.classId = ForeignServerRelationId;
	referenced.objectId = srv->serverid;
	referenced.objectSubId = 0;
	recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);

	if (OidIsValid(useId))
	{
		
		recordDependencyOnOwner(UserMappingRelationId, umId, useId);
	}

	

	
	InvokeObjectPostCreateHook(UserMappingRelationId, umId, 0);

	if (Gp_role == GP_ROLE_DISPATCH)
	{
		CdbDispatchUtilityStatement((Node *) stmt, DF_WITH_SNAPSHOT | DF_CANCEL_ON_ERROR | DF_NEED_TWO_PHASE, GetAssignedOidsForDispatch(), NULL);


	}

	table_close(rel, RowExclusiveLock);

	return myself;
}



ObjectAddress AlterUserMapping(AlterUserMappingStmt *stmt)
{
	Relation	rel;
	HeapTuple	tp;
	Datum		repl_val[Natts_pg_user_mapping];
	bool		repl_null[Natts_pg_user_mapping];
	bool		repl_repl[Natts_pg_user_mapping];
	Oid			useId;
	Oid			umId;
	ForeignServer *srv;
	ObjectAddress address;
	RoleSpec   *role = (RoleSpec *) stmt->user;

	rel = table_open(UserMappingRelationId, RowExclusiveLock);

	if (role->roletype == ROLESPEC_PUBLIC)
		useId = ACL_ID_PUBLIC;
	else useId = get_rolespec_oid(stmt->user, false);

	srv = GetForeignServerByName(stmt->servername, false);

	umId = GetSysCacheOid2(USERMAPPINGUSERSERVER, Anum_pg_user_mapping_oid, ObjectIdGetDatum(useId), ObjectIdGetDatum(srv->serverid));

	if (!OidIsValid(umId))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("user mapping for \"%s\" does not exist for server \"%s\"", MappingUserName(useId), stmt->servername)));



	user_mapping_ddl_aclcheck(useId, srv->serverid, stmt->servername);

	tp = SearchSysCacheCopy1(USERMAPPINGOID, ObjectIdGetDatum(umId));

	if (!HeapTupleIsValid(tp))
		elog(ERROR, "cache lookup failed for user mapping %u", umId);

	memset(repl_val, 0, sizeof(repl_val));
	memset(repl_null, false, sizeof(repl_null));
	memset(repl_repl, false, sizeof(repl_repl));

	if (stmt->options)
	{
		ForeignDataWrapper *fdw;
		Datum		datum;
		bool		isnull;

		

		fdw = GetForeignDataWrapper(srv->fdwid);

		datum = SysCacheGetAttr(USERMAPPINGUSERSERVER, tp, Anum_pg_user_mapping_umoptions, &isnull);


		if (isnull)
			datum = PointerGetDatum(NULL);

		
		datum = transformGenericOptions(UserMappingRelationId, datum, stmt->options, fdw->fdwvalidator);



		if (PointerIsValid(DatumGetPointer(datum)))
			repl_val[Anum_pg_user_mapping_umoptions - 1] = datum;
		else repl_null[Anum_pg_user_mapping_umoptions - 1] = true;

		repl_repl[Anum_pg_user_mapping_umoptions - 1] = true;
	}

	
	tp = heap_modify_tuple(tp, RelationGetDescr(rel), repl_val, repl_null, repl_repl);

	CatalogTupleUpdate(rel, &tp->t_self, tp);

	ObjectAddressSet(address, UserMappingRelationId, umId);

	heap_freetuple(tp);

	if (Gp_role == GP_ROLE_DISPATCH)
	{
		CdbDispatchUtilityStatement((Node *) stmt, DF_WITH_SNAPSHOT | DF_CANCEL_ON_ERROR | DF_NEED_TWO_PHASE, GetAssignedOidsForDispatch(), NULL);


	}

	table_close(rel, RowExclusiveLock);

	return address;
}



Oid RemoveUserMapping(DropUserMappingStmt *stmt)
{
	ObjectAddress object;
	Oid			useId;
	Oid			umId;
	ForeignServer *srv;
	RoleSpec   *role = (RoleSpec *) stmt->user;

	if (role->roletype == ROLESPEC_PUBLIC)
		useId = ACL_ID_PUBLIC;
	else {
		useId = get_rolespec_oid(stmt->user, stmt->missing_ok);
		if (!OidIsValid(useId))
		{
			
			elog(NOTICE, "role \"%s\" does not exist, skipping", role->rolename);
			return InvalidOid;
		}
	}

	srv = GetForeignServerByName(stmt->servername, true);

	if (!srv)
	{
		if (!stmt->missing_ok)
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("server \"%s\" does not exist", stmt->servername)));


		
		ereport(NOTICE, (errmsg("server \"%s\" does not exist, skipping", stmt->servername)));

		return InvalidOid;
	}

	umId = GetSysCacheOid2(USERMAPPINGUSERSERVER, Anum_pg_user_mapping_oid, ObjectIdGetDatum(useId), ObjectIdGetDatum(srv->serverid));


	if (!OidIsValid(umId))
	{
		if (!stmt->missing_ok)
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("user mapping for \"%s\" does not exist for server \"%s\"", MappingUserName(useId), stmt->servername)));



		
		ereport(NOTICE, (errmsg("user mapping for \"%s\" does not exist for server \"%s\", skipping", MappingUserName(useId), stmt->servername)));

		return InvalidOid;
	}

	user_mapping_ddl_aclcheck(useId, srv->serverid, srv->servername);

	
	object.classId = UserMappingRelationId;
	object.objectId = umId;
	object.objectSubId = 0;

	performDeletion(&object, DROP_CASCADE, 0);

	if (Gp_role == GP_ROLE_DISPATCH)
	{
		CdbDispatchUtilityStatement((Node *) stmt, DF_WITH_SNAPSHOT | DF_CANCEL_ON_ERROR | DF_NEED_TWO_PHASE, GetAssignedOidsForDispatch(), NULL);


	}
	return umId;
}



void RemoveUserMappingById(Oid umId)
{
	HeapTuple	tp;
	Relation	rel;

	rel = table_open(UserMappingRelationId, RowExclusiveLock);

	tp = SearchSysCache1(USERMAPPINGOID, ObjectIdGetDatum(umId));

	if (!HeapTupleIsValid(tp))
		elog(ERROR, "cache lookup failed for user mapping %u", umId);

	CatalogTupleDelete(rel, &tp->t_self);

	ReleaseSysCache(tp);

	table_close(rel, RowExclusiveLock);
}


void CreateForeignTable(CreateForeignTableStmt *stmt, Oid relid, bool skip_permission_check)
{
	Relation	ftrel;
	Datum		ftoptions;
	Datum		values[Natts_pg_foreign_table];
	bool		nulls[Natts_pg_foreign_table];
	HeapTuple	tuple;
	AclResult	aclresult;
	ObjectAddress myself;
	ObjectAddress referenced;
	Oid			ownerId;
	ForeignDataWrapper *fdw;
	ForeignServer *server;

	
	CommandCounterIncrement();

	ftrel = table_open(ForeignTableRelationId, RowExclusiveLock);

	
	ownerId = GetUserId();

	
	server = GetForeignServerByName(stmt->servername, false);
	if (!skip_permission_check)
	{
		aclresult = pg_foreign_server_aclcheck(server->serverid, ownerId, ACL_USAGE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, OBJECT_FOREIGN_SERVER, server->servername);
	}

	fdw = GetForeignDataWrapper(server->fdwid);

	
	memset(values, 0, sizeof(values));
	memset(nulls, false, sizeof(nulls));

	values[Anum_pg_foreign_table_ftrelid - 1] = ObjectIdGetDatum(relid);
	values[Anum_pg_foreign_table_ftserver - 1] = ObjectIdGetDatum(server->serverid);
	
	ftoptions = transformGenericOptions(ForeignTableRelationId, PointerGetDatum(NULL), stmt->options, fdw->fdwvalidator);



	if (PointerIsValid(DatumGetPointer(ftoptions)))
		values[Anum_pg_foreign_table_ftoptions - 1] = ftoptions;
	else nulls[Anum_pg_foreign_table_ftoptions - 1] = true;

	tuple = heap_form_tuple(ftrel->rd_att, values, nulls);

	CatalogTupleInsert(ftrel, tuple);

	heap_freetuple(tuple);

	
	myself.classId = RelationRelationId;
	myself.objectId = relid;
	myself.objectSubId = 0;

	referenced.classId = ForeignServerRelationId;
	referenced.objectId = server->serverid;
	referenced.objectSubId = 0;
	recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);

	table_close(ftrel, RowExclusiveLock);
}


void ImportForeignSchema(ImportForeignSchemaStmt *stmt)
{
	ForeignServer *server;
	ForeignDataWrapper *fdw;
	FdwRoutine *fdw_routine;
	AclResult	aclresult;
	List	   *cmd_list;
	ListCell   *lc;

	
	server = GetForeignServerByName(stmt->server_name, false);
	aclresult = pg_foreign_server_aclcheck(server->serverid, GetUserId(), ACL_USAGE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, OBJECT_FOREIGN_SERVER, server->servername);

	
	(void) LookupCreationNamespace(stmt->local_schema);

	
	fdw = GetForeignDataWrapper(server->fdwid);
	if (!OidIsValid(fdw->fdwhandler))
		ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("foreign-data wrapper \"%s\" has no handler", fdw->fdwname)));


	fdw_routine = GetFdwRoutine(fdw->fdwhandler);
	if (fdw_routine->ImportForeignSchema == NULL)
		ereport(ERROR, (errcode(ERRCODE_FDW_NO_SCHEMAS), errmsg("foreign-data wrapper \"%s\" does not support IMPORT FOREIGN SCHEMA", fdw->fdwname)));



	
	cmd_list = fdw_routine->ImportForeignSchema(stmt, server->serverid);

	
	foreach(lc, cmd_list)
	{
		char	   *cmd = (char *) lfirst(lc);
		import_error_callback_arg callback_arg;
		ErrorContextCallback sqlerrcontext;
		List	   *raw_parsetree_list;
		ListCell   *lc2;

		
		callback_arg.tablename = NULL;	
		callback_arg.cmd = cmd;
		sqlerrcontext.callback = import_error_callback;
		sqlerrcontext.arg = (void *) &callback_arg;
		sqlerrcontext.previous = error_context_stack;
		error_context_stack = &sqlerrcontext;

		
		raw_parsetree_list = pg_parse_query(cmd);

		
		foreach(lc2, raw_parsetree_list)
		{
			RawStmt    *rs = lfirst_node(RawStmt, lc2);
			CreateForeignTableStmt *cstmt = (CreateForeignTableStmt *) rs->stmt;
			PlannedStmt *pstmt;

			
			if (!IsA(cstmt, CreateForeignTableStmt))
				elog(ERROR, "foreign-data wrapper \"%s\" returned incorrect statement type %d", fdw->fdwname, (int) nodeTag(cstmt));


			
			if (!IsImportableForeignTable(cstmt->base.relation->relname, stmt))
				continue;

			
			callback_arg.tablename = cstmt->base.relation->relname;

			
			cstmt->base.relation->schemaname = pstrdup(stmt->local_schema);

			
			pstmt = makeNode(PlannedStmt);
			pstmt->commandType = CMD_UTILITY;
			pstmt->canSetTag = false;
			pstmt->utilityStmt = (Node *) cstmt;
			pstmt->stmt_location = rs->stmt_location;
			pstmt->stmt_len = rs->stmt_len;

			
			ProcessUtility(pstmt, cmd, PROCESS_UTILITY_SUBCOMMAND, NULL, NULL, None_Receiver, NULL);



			
			CommandCounterIncrement();

			callback_arg.tablename = NULL;
		}

		error_context_stack = sqlerrcontext.previous;
	}
}


static void import_error_callback(void *arg)
{
	import_error_callback_arg *callback_arg = (import_error_callback_arg *) arg;
	int			syntaxerrposition;

	
	syntaxerrposition = geterrposition();
	if (syntaxerrposition > 0)
	{
		errposition(0);
		internalerrposition(syntaxerrposition);
		internalerrquery(callback_arg->cmd);
	}

	if (callback_arg->tablename)
		errcontext("importing foreign table \"%s\"", callback_arg->tablename);
}
