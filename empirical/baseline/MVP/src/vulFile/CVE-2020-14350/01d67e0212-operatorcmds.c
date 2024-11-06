




















static Oid	ValidateRestrictionEstimator(List *restrictionName);
static Oid	ValidateJoinEstimator(List *joinName);


ObjectAddress DefineOperator(List *names, List *parameters)
{
	char	   *oprName;
	Oid			oprNamespace;
	AclResult	aclresult;
	bool		canMerge = false;	
	bool		canHash = false;	
	List	   *functionName = NIL; 
	TypeName   *typeName1 = NULL;	
	TypeName   *typeName2 = NULL;	
	Oid			typeId1 = InvalidOid;	
	Oid			typeId2 = InvalidOid;
	Oid			rettype;
	List	   *commutatorName = NIL;	
	List	   *negatorName = NIL;	
	List	   *restrictionName = NIL;	
	List	   *joinName = NIL; 
	Oid			functionOid;	
	Oid			restrictionOid;
	Oid			joinOid;
	Oid			typeId[2];		
	int			nargs;
	ListCell   *pl;

	
	oprNamespace = QualifiedNameGetCreationNamespace(names, &oprName);

	
	aclresult = pg_namespace_aclcheck(oprNamespace, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, OBJECT_SCHEMA, get_namespace_name(oprNamespace));

	
	foreach(pl, parameters)
	{
		DefElem    *defel = (DefElem *) lfirst(pl);

		if (strcmp(defel->defname, "leftarg") == 0)
		{
			typeName1 = defGetTypeName(defel);
			if (typeName1->setof)
				ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("SETOF type not allowed for operator argument")));

		}
		else if (strcmp(defel->defname, "rightarg") == 0)
		{
			typeName2 = defGetTypeName(defel);
			if (typeName2->setof)
				ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("SETOF type not allowed for operator argument")));

		}
		
		else if (strcmp(defel->defname, "function") == 0)
			functionName = defGetQualifiedName(defel);
		else if (strcmp(defel->defname, "procedure") == 0)
			functionName = defGetQualifiedName(defel);
		else if (strcmp(defel->defname, "commutator") == 0)
			commutatorName = defGetQualifiedName(defel);
		else if (strcmp(defel->defname, "negator") == 0)
			negatorName = defGetQualifiedName(defel);
		else if (strcmp(defel->defname, "restrict") == 0)
			restrictionName = defGetQualifiedName(defel);
		else if (strcmp(defel->defname, "join") == 0)
			joinName = defGetQualifiedName(defel);
		else if (strcmp(defel->defname, "hashes") == 0)
			canHash = defGetBoolean(defel);
		else if (strcmp(defel->defname, "merges") == 0)
			canMerge = defGetBoolean(defel);
		
		else if (strcmp(defel->defname, "sort1") == 0)
			canMerge = true;
		else if (strcmp(defel->defname, "sort2") == 0)
			canMerge = true;
		else if (strcmp(defel->defname, "ltcmp") == 0)
			canMerge = true;
		else if (strcmp(defel->defname, "gtcmp") == 0)
			canMerge = true;
		else {
			
			ereport(WARNING, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("operator attribute \"%s\" not recognized", defel->defname)));


		}
	}

	
	if (functionName == NIL)
		ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("operator function must be specified")));


	
	if (typeName1)
		typeId1 = typenameTypeId(NULL, typeName1);
	if (typeName2)
		typeId2 = typenameTypeId(NULL, typeName2);

	if (!OidIsValid(typeId1) && !OidIsValid(typeId2))
		ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("at least one of leftarg or rightarg must be specified")));


	if (typeName1)
	{
		aclresult = pg_type_aclcheck(typeId1, GetUserId(), ACL_USAGE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error_type(aclresult, typeId1);
	}

	if (typeName2)
	{
		aclresult = pg_type_aclcheck(typeId2, GetUserId(), ACL_USAGE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error_type(aclresult, typeId2);
	}

	
	if (!OidIsValid(typeId1))
	{
		typeId[0] = typeId2;
		nargs = 1;
	}
	else if (!OidIsValid(typeId2))
	{
		typeId[0] = typeId1;
		nargs = 1;
	}
	else {
		typeId[0] = typeId1;
		typeId[1] = typeId2;
		nargs = 2;
	}
	functionOid = LookupFuncName(functionName, nargs, typeId, false);

	
	aclresult = pg_proc_aclcheck(functionOid, GetUserId(), ACL_EXECUTE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, OBJECT_FUNCTION, NameListToString(functionName));

	rettype = get_func_rettype(functionOid);
	aclresult = pg_type_aclcheck(rettype, GetUserId(), ACL_USAGE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error_type(aclresult, rettype);

	
	if (restrictionName)
		restrictionOid = ValidateRestrictionEstimator(restrictionName);
	else restrictionOid = InvalidOid;
	if (joinName)
		joinOid = ValidateJoinEstimator(joinName);
	else joinOid = InvalidOid;

	
	return OperatorCreate(oprName, oprNamespace, typeId1, typeId2, functionOid, commutatorName, negatorName, restrictionOid, joinOid, canMerge, canHash);










}


static Oid ValidateRestrictionEstimator(List *restrictionName)
{
	Oid			typeId[4];
	Oid			restrictionOid;
	AclResult	aclresult;

	typeId[0] = INTERNALOID;	
	typeId[1] = OIDOID;			
	typeId[2] = INTERNALOID;	
	typeId[3] = INT4OID;		

	restrictionOid = LookupFuncName(restrictionName, 4, typeId, false);

	
	if (get_func_rettype(restrictionOid) != FLOAT8OID)
		ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("restriction estimator function %s must return type %s", NameListToString(restrictionName), "float8")));



	
	aclresult = pg_proc_aclcheck(restrictionOid, GetUserId(), ACL_EXECUTE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, OBJECT_FUNCTION, NameListToString(restrictionName));

	return restrictionOid;
}


static Oid ValidateJoinEstimator(List *joinName)
{
	Oid			typeId[5];
	Oid			joinOid;
	AclResult	aclresult;

	typeId[0] = INTERNALOID;	
	typeId[1] = OIDOID;			
	typeId[2] = INTERNALOID;	
	typeId[3] = INT2OID;		
	typeId[4] = INTERNALOID;	

	
	joinOid = LookupFuncName(joinName, 5, typeId, true);
	if (!OidIsValid(joinOid))
		joinOid = LookupFuncName(joinName, 4, typeId, true);
	
	if (!OidIsValid(joinOid))
		joinOid = LookupFuncName(joinName, 5, typeId, false);

	
	if (get_func_rettype(joinOid) != FLOAT8OID)
		ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("join estimator function %s must return type %s", NameListToString(joinName), "float8")));



	
	aclresult = pg_proc_aclcheck(joinOid, GetUserId(), ACL_EXECUTE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, OBJECT_FUNCTION, NameListToString(joinName));

	return joinOid;
}


void RemoveOperatorById(Oid operOid)
{
	Relation	relation;
	HeapTuple	tup;
	Form_pg_operator op;

	relation = heap_open(OperatorRelationId, RowExclusiveLock);

	tup = SearchSysCache1(OPEROID, ObjectIdGetDatum(operOid));
	if (!HeapTupleIsValid(tup)) 
		elog(ERROR, "cache lookup failed for operator %u", operOid);
	op = (Form_pg_operator) GETSTRUCT(tup);

	
	if (OidIsValid(op->oprcom) || OidIsValid(op->oprnegate))
	{
		OperatorUpd(operOid, op->oprcom, op->oprnegate, true);
		if (operOid == op->oprcom || operOid == op->oprnegate)
		{
			ReleaseSysCache(tup);
			tup = SearchSysCache1(OPEROID, ObjectIdGetDatum(operOid));
			if (!HeapTupleIsValid(tup)) 
				elog(ERROR, "cache lookup failed for operator %u", operOid);
		}
	}

	CatalogTupleDelete(relation, &tup->t_self);

	ReleaseSysCache(tup);

	heap_close(relation, RowExclusiveLock);
}


ObjectAddress AlterOperator(AlterOperatorStmt *stmt)
{
	ObjectAddress address;
	Oid			oprId;
	Relation	catalog;
	HeapTuple	tup;
	Form_pg_operator oprForm;
	int			i;
	ListCell   *pl;
	Datum		values[Natts_pg_operator];
	bool		nulls[Natts_pg_operator];
	bool		replaces[Natts_pg_operator];
	List	   *restrictionName = NIL;	
	bool		updateRestriction = false;
	Oid			restrictionOid;
	List	   *joinName = NIL; 
	bool		updateJoin = false;
	Oid			joinOid;

	
	oprId = LookupOperWithArgs(stmt->opername, false);
	catalog = heap_open(OperatorRelationId, RowExclusiveLock);
	tup = SearchSysCacheCopy1(OPEROID, ObjectIdGetDatum(oprId));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for operator %u", oprId);
	oprForm = (Form_pg_operator) GETSTRUCT(tup);

	
	foreach(pl, stmt->options)
	{
		DefElem    *defel = (DefElem *) lfirst(pl);
		List	   *param;

		if (defel->arg == NULL)
			param = NIL;		
		else param = defGetQualifiedName(defel);

		if (strcmp(defel->defname, "restrict") == 0)
		{
			restrictionName = param;
			updateRestriction = true;
		}
		else if (strcmp(defel->defname, "join") == 0)
		{
			joinName = param;
			updateJoin = true;
		}

		
		else if (strcmp(defel->defname, "leftarg") == 0 || strcmp(defel->defname, "rightarg") == 0 || strcmp(defel->defname, "function") == 0 || strcmp(defel->defname, "procedure") == 0 || strcmp(defel->defname, "commutator") == 0 || strcmp(defel->defname, "negator") == 0 || strcmp(defel->defname, "hashes") == 0 || strcmp(defel->defname, "merges") == 0)






		{
			ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("operator attribute \"%s\" cannot be changed", defel->defname)));


		}
		else ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("operator attribute \"%s\" not recognized", defel->defname)));



	}

	
	if (!pg_oper_ownercheck(oprId, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, OBJECT_OPERATOR, NameStr(oprForm->oprname));

	
	if (restrictionName)
		restrictionOid = ValidateRestrictionEstimator(restrictionName);
	else restrictionOid = InvalidOid;
	if (joinName)
		joinOid = ValidateJoinEstimator(joinName);
	else joinOid = InvalidOid;

	
	if (!(OidIsValid(oprForm->oprleft) && OidIsValid(oprForm->oprright)))
	{
		
		if (OidIsValid(joinOid))
			ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("only binary operators can have join selectivity")));

	}

	if (oprForm->oprresult != BOOLOID)
	{
		if (OidIsValid(restrictionOid))
			ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("only boolean operators can have restriction selectivity")));

		if (OidIsValid(joinOid))
			ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("only boolean operators can have join selectivity")));

	}

	
	for (i = 0; i < Natts_pg_operator; ++i)
	{
		values[i] = (Datum) 0;
		replaces[i] = false;
		nulls[i] = false;
	}
	if (updateRestriction)
	{
		replaces[Anum_pg_operator_oprrest - 1] = true;
		values[Anum_pg_operator_oprrest - 1] = restrictionOid;
	}
	if (updateJoin)
	{
		replaces[Anum_pg_operator_oprjoin - 1] = true;
		values[Anum_pg_operator_oprjoin - 1] = joinOid;
	}

	tup = heap_modify_tuple(tup, RelationGetDescr(catalog), values, nulls, replaces);

	CatalogTupleUpdate(catalog, &tup->t_self, tup);

	address = makeOperatorDependencies(tup, true);

	InvokeObjectPostAlterHook(OperatorRelationId, oprId, 0);

	heap_close(catalog, NoLock);

	return address;
}
