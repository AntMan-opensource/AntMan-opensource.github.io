

























static Oid	OperatorGet(const char *operatorName, Oid operatorNamespace, Oid leftObjectId, Oid rightObjectId, bool *defined);




static Oid	OperatorLookup(List *operatorName, Oid leftObjectId, Oid rightObjectId, bool *defined);



static Oid	OperatorShellMake(const char *operatorName, Oid operatorNamespace, Oid leftTypeId, Oid rightTypeId);



static Oid	get_other_operator(List *otherOp, Oid otherLeftTypeId, Oid otherRightTypeId, const char *operatorName, Oid operatorNamespace, Oid leftTypeId, Oid rightTypeId, bool isCommutator);






static bool validOperatorName(const char *name)
{
	size_t		len = strlen(name);

	
	if (len == 0 || len >= NAMEDATALEN)
		return false;

	
	
	if (strspn(name, "~!@#^&|`?+-*/%<>=") != len)
		return false;

	
	if (strstr(name, "/*") || strstr(name, "--"))
		return false;

	
	if (len > 1 && (name[len - 1] == '+' || name[len - 1] == '-'))

	{
		int			ic;

		for (ic = len - 2; ic >= 0; ic--)
		{
			if (strchr("~!@#^&|`?%", name[ic]))
				break;
		}
		if (ic < 0)
			return false;		
	}

	
	if (strcmp(name, "!=") == 0)
		return false;

	return true;
}



static Oid OperatorGet(const char *operatorName, Oid operatorNamespace, Oid leftObjectId, Oid rightObjectId, bool *defined)




{
	HeapTuple	tup;
	Oid			operatorObjectId;

	tup = SearchSysCache4(OPERNAMENSP, PointerGetDatum(operatorName), ObjectIdGetDatum(leftObjectId), ObjectIdGetDatum(rightObjectId), ObjectIdGetDatum(operatorNamespace));



	if (HeapTupleIsValid(tup))
	{
		Form_pg_operator oprform = (Form_pg_operator) GETSTRUCT(tup);

		operatorObjectId = oprform->oid;
		*defined = RegProcedureIsValid(oprform->oprcode);
		ReleaseSysCache(tup);
	}
	else {
		operatorObjectId = InvalidOid;
		*defined = false;
	}

	return operatorObjectId;
}


static Oid OperatorLookup(List *operatorName, Oid leftObjectId, Oid rightObjectId, bool *defined)



{
	Oid			operatorObjectId;
	RegProcedure oprcode;

	operatorObjectId = LookupOperName(NULL, operatorName, leftObjectId, rightObjectId, true, -1);

	if (!OidIsValid(operatorObjectId))
	{
		*defined = false;
		return InvalidOid;
	}

	oprcode = get_opcode(operatorObjectId);
	*defined = RegProcedureIsValid(oprcode);

	return operatorObjectId;
}



static Oid OperatorShellMake(const char *operatorName, Oid operatorNamespace, Oid leftTypeId, Oid rightTypeId)



{
	Relation	pg_operator_desc;
	Oid			operatorObjectId;
	int			i;
	HeapTuple	tup;
	Datum		values[Natts_pg_operator];
	bool		nulls[Natts_pg_operator];
	NameData	oname;
	TupleDesc	tupDesc;

	
	if (!validOperatorName(operatorName))
		ereport(ERROR, (errcode(ERRCODE_INVALID_NAME), errmsg("\"%s\" is not a valid operator name", operatorName)));



	
	pg_operator_desc = table_open(OperatorRelationId, RowExclusiveLock);
	tupDesc = pg_operator_desc->rd_att;

	
	for (i = 0; i < Natts_pg_operator; ++i)
	{
		nulls[i] = false;
		values[i] = (Datum) NULL;	
	}

	
	operatorObjectId = GetNewOidForOperator(pg_operator_desc, OperatorOidIndexId, Anum_pg_operator_oid, unconstify(char *, operatorName), leftTypeId, rightTypeId, operatorNamespace);



	values[Anum_pg_operator_oid - 1] = ObjectIdGetDatum(operatorObjectId);
	namestrcpy(&oname, operatorName);
	values[Anum_pg_operator_oprname - 1] = NameGetDatum(&oname);
	values[Anum_pg_operator_oprnamespace - 1] = ObjectIdGetDatum(operatorNamespace);
	values[Anum_pg_operator_oprowner - 1] = ObjectIdGetDatum(GetUserId());
	values[Anum_pg_operator_oprkind - 1] = CharGetDatum(leftTypeId ? (rightTypeId ? 'b' : 'r') : 'l');
	values[Anum_pg_operator_oprcanmerge - 1] = BoolGetDatum(false);
	values[Anum_pg_operator_oprcanhash - 1] = BoolGetDatum(false);
	values[Anum_pg_operator_oprleft - 1] = ObjectIdGetDatum(leftTypeId);
	values[Anum_pg_operator_oprright - 1] = ObjectIdGetDatum(rightTypeId);
	values[Anum_pg_operator_oprresult - 1] = ObjectIdGetDatum(InvalidOid);
	values[Anum_pg_operator_oprcom - 1] = ObjectIdGetDatum(InvalidOid);
	values[Anum_pg_operator_oprnegate - 1] = ObjectIdGetDatum(InvalidOid);
	values[Anum_pg_operator_oprcode - 1] = ObjectIdGetDatum(InvalidOid);
	values[Anum_pg_operator_oprrest - 1] = ObjectIdGetDatum(InvalidOid);
	values[Anum_pg_operator_oprjoin - 1] = ObjectIdGetDatum(InvalidOid);

	
	tup = heap_form_tuple(tupDesc, values, nulls);

	
	CatalogTupleInsert(pg_operator_desc, tup);

	
	makeOperatorDependencies(tup, false);

	heap_freetuple(tup);

	
	InvokeObjectPostCreateHook(OperatorRelationId, operatorObjectId, 0);

	
	CommandCounterIncrement();

	
	table_close(pg_operator_desc, RowExclusiveLock);

	return operatorObjectId;
}


ObjectAddress OperatorCreate(const char *operatorName, Oid operatorNamespace, Oid leftTypeId, Oid rightTypeId, Oid procedureId, List *commutatorName, List *negatorName, Oid restrictionId, Oid joinId, bool canMerge, bool canHash)










{
	Relation	pg_operator_desc;
	HeapTuple	tup;
	bool		isUpdate;
	bool		nulls[Natts_pg_operator];
	bool		replaces[Natts_pg_operator];
	Datum		values[Natts_pg_operator];
	Oid			operatorObjectId;
	bool		operatorAlreadyDefined;
	Oid			operResultType;
	Oid			commutatorId, negatorId;
	bool		selfCommutator = false;
	NameData	oname;
	int			i;
	ObjectAddress address;

	
	if (!validOperatorName(operatorName))
		ereport(ERROR, (errcode(ERRCODE_INVALID_NAME), errmsg("\"%s\" is not a valid operator name", operatorName)));



	if (!(OidIsValid(leftTypeId) && OidIsValid(rightTypeId)))
	{
		
		if (commutatorName)
			ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("only binary operators can have commutators")));

		if (OidIsValid(joinId))
			ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("only binary operators can have join selectivity")));

		if (canMerge)
			ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("only binary operators can merge join")));

		if (canHash)
			ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("only binary operators can hash")));

	}

	operResultType = get_func_rettype(procedureId);

	if (operResultType != BOOLOID)
	{
		
		if (negatorName)
			ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("only boolean operators can have negators")));

		if (OidIsValid(restrictionId))
			ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("only boolean operators can have restriction selectivity")));

		if (OidIsValid(joinId))
			ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("only boolean operators can have join selectivity")));

		if (canMerge)
			ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("only boolean operators can merge join")));

		if (canHash)
			ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("only boolean operators can hash")));

	}

	operatorObjectId = OperatorGet(operatorName, operatorNamespace, leftTypeId, rightTypeId, &operatorAlreadyDefined);




	if (operatorAlreadyDefined)
		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_FUNCTION), errmsg("operator %s already exists", operatorName)));



	
	if (OidIsValid(operatorObjectId) && !pg_oper_ownercheck(operatorObjectId, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, OBJECT_OPERATOR, operatorName);

	

	if (commutatorName)
	{
		
		commutatorId = get_other_operator(commutatorName, rightTypeId, leftTypeId, operatorName, operatorNamespace, leftTypeId, rightTypeId, true);




		
		if (OidIsValid(commutatorId) && !pg_oper_ownercheck(commutatorId, GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, OBJECT_OPERATOR, NameListToString(commutatorName));

		
		if (!OidIsValid(commutatorId))
			selfCommutator = true;
	}
	else commutatorId = InvalidOid;

	if (negatorName)
	{
		
		negatorId = get_other_operator(negatorName, leftTypeId, rightTypeId, operatorName, operatorNamespace, leftTypeId, rightTypeId, false);




		
		if (OidIsValid(negatorId) && !pg_oper_ownercheck(negatorId, GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, OBJECT_OPERATOR, NameListToString(negatorName));
	}
	else negatorId = InvalidOid;

	

	for (i = 0; i < Natts_pg_operator; ++i)
	{
		values[i] = (Datum) NULL;
		replaces[i] = true;
		nulls[i] = false;
	}

	namestrcpy(&oname, operatorName);
	values[Anum_pg_operator_oprname - 1] = NameGetDatum(&oname);
	values[Anum_pg_operator_oprnamespace - 1] = ObjectIdGetDatum(operatorNamespace);
	values[Anum_pg_operator_oprowner - 1] = ObjectIdGetDatum(GetUserId());
	values[Anum_pg_operator_oprkind - 1] = CharGetDatum(leftTypeId ? (rightTypeId ? 'b' : 'r') : 'l');
	values[Anum_pg_operator_oprcanmerge - 1] = BoolGetDatum(canMerge);
	values[Anum_pg_operator_oprcanhash - 1] = BoolGetDatum(canHash);
	values[Anum_pg_operator_oprleft - 1] = ObjectIdGetDatum(leftTypeId);
	values[Anum_pg_operator_oprright - 1] = ObjectIdGetDatum(rightTypeId);
	values[Anum_pg_operator_oprresult - 1] = ObjectIdGetDatum(operResultType);
	values[Anum_pg_operator_oprcom - 1] = ObjectIdGetDatum(commutatorId);
	values[Anum_pg_operator_oprnegate - 1] = ObjectIdGetDatum(negatorId);
	values[Anum_pg_operator_oprcode - 1] = ObjectIdGetDatum(procedureId);
	values[Anum_pg_operator_oprrest - 1] = ObjectIdGetDatum(restrictionId);
	values[Anum_pg_operator_oprjoin - 1] = ObjectIdGetDatum(joinId);

	pg_operator_desc = table_open(OperatorRelationId, RowExclusiveLock);

	
	if (operatorObjectId)
	{
		isUpdate = true;

		tup = SearchSysCacheCopy1(OPEROID, ObjectIdGetDatum(operatorObjectId));
		if (!HeapTupleIsValid(tup))
			elog(ERROR, "cache lookup failed for operator %u", operatorObjectId);

		replaces[Anum_pg_operator_oid - 1] = false;
		tup = heap_modify_tuple(tup, RelationGetDescr(pg_operator_desc), values, nulls, replaces);




		CatalogTupleUpdate(pg_operator_desc, &tup->t_self, tup);
	}
	else {
		isUpdate = false;

		operatorObjectId = GetNewOidForOperator(pg_operator_desc, OperatorOidIndexId, Anum_pg_operator_oid, NameStr(oname), leftTypeId, rightTypeId, operatorNamespace);



		values[Anum_pg_operator_oid - 1] = ObjectIdGetDatum(operatorObjectId);

		tup = heap_form_tuple(RelationGetDescr(pg_operator_desc), values, nulls);

		CatalogTupleInsert(pg_operator_desc, tup);
	}

	
	address = makeOperatorDependencies(tup, isUpdate);

	
	InvokeObjectPostCreateHook(OperatorRelationId, operatorObjectId, 0);

	table_close(pg_operator_desc, RowExclusiveLock);

	
	if (selfCommutator)
		commutatorId = operatorObjectId;

	if (OidIsValid(commutatorId) || OidIsValid(negatorId))
		OperatorUpd(operatorObjectId, commutatorId, negatorId, false);

	return address;
}


static Oid get_other_operator(List *otherOp, Oid otherLeftTypeId, Oid otherRightTypeId, const char *operatorName, Oid operatorNamespace, Oid leftTypeId, Oid rightTypeId, bool isCommutator)


{
	Oid			other_oid;
	bool		otherDefined;
	char	   *otherName;
	Oid			otherNamespace;
	AclResult	aclresult;

	other_oid = OperatorLookup(otherOp, otherLeftTypeId, otherRightTypeId, &otherDefined);



	if (OidIsValid(other_oid))
	{
		
		return other_oid;
	}

	otherNamespace = QualifiedNameGetCreationNamespace(otherOp, &otherName);

	if (strcmp(otherName, operatorName) == 0 && otherNamespace == operatorNamespace && otherLeftTypeId == leftTypeId && otherRightTypeId == rightTypeId)


	{
		
		if (!isCommutator)
			ereport(ERROR, (errcode(ERRCODE_INVALID_FUNCTION_DEFINITION), errmsg("operator cannot be its own negator or sort operator")));

		return InvalidOid;
	}

	

	aclresult = pg_namespace_aclcheck(otherNamespace, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, OBJECT_SCHEMA, get_namespace_name(otherNamespace));

	other_oid = OperatorShellMake(otherName, otherNamespace, otherLeftTypeId, otherRightTypeId);


	return other_oid;
}


void OperatorUpd(Oid baseId, Oid commId, Oid negId, bool isDelete)
{
	Relation	pg_operator_desc;
	HeapTuple	tup;

	
	if (!isDelete)
		CommandCounterIncrement();

	
	pg_operator_desc = table_open(OperatorRelationId, RowExclusiveLock);

	
	if (OidIsValid(commId))
		tup = SearchSysCacheCopy1(OPEROID, ObjectIdGetDatum(commId));
	else tup = NULL;

	
	if (HeapTupleIsValid(tup))
	{
		Form_pg_operator t = (Form_pg_operator) GETSTRUCT(tup);
		bool		update_commutator = false;

		
		if (isDelete && t->oprcom == baseId)
		{
			t->oprcom = InvalidOid;
			update_commutator = true;
		}
		else if (!isDelete && !OidIsValid(t->oprcom))
		{
			t->oprcom = baseId;
			update_commutator = true;
		}

		
		if (update_commutator)
		{
			CatalogTupleUpdate(pg_operator_desc, &tup->t_self, tup);

			
			CommandCounterIncrement();
		}
	}

	
	if (OidIsValid(negId))
		tup = SearchSysCacheCopy1(OPEROID, ObjectIdGetDatum(negId));
	else tup = NULL;

	if (HeapTupleIsValid(tup))
	{
		Form_pg_operator t = (Form_pg_operator) GETSTRUCT(tup);
		bool		update_negator = false;

		
		if (isDelete && t->oprnegate == baseId)
		{
			t->oprnegate = InvalidOid;
			update_negator = true;
		}
		else if (!isDelete && !OidIsValid(t->oprnegate))
		{
			t->oprnegate = baseId;
			update_negator = true;
		}

		
		if (update_negator)
		{
			CatalogTupleUpdate(pg_operator_desc, &tup->t_self, tup);

			
			if (isDelete)
				CommandCounterIncrement();
		}
	}

	
	table_close(pg_operator_desc, RowExclusiveLock);
}


ObjectAddress makeOperatorDependencies(HeapTuple tuple, bool isUpdate)
{
	Form_pg_operator oper = (Form_pg_operator) GETSTRUCT(tuple);
	ObjectAddress myself, referenced;

	myself.classId = OperatorRelationId;
	myself.objectId = oper->oid;
	myself.objectSubId = 0;

	
	if (isUpdate)
	{
		deleteDependencyRecordsFor(myself.classId, myself.objectId, true);
		deleteSharedDependencyRecordsFor(myself.classId, myself.objectId, 0);
	}

	
	if (OidIsValid(oper->oprnamespace))
	{
		referenced.classId = NamespaceRelationId;
		referenced.objectId = oper->oprnamespace;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
	}

	
	if (OidIsValid(oper->oprleft))
	{
		referenced.classId = TypeRelationId;
		referenced.objectId = oper->oprleft;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
	}

	
	if (OidIsValid(oper->oprright))
	{
		referenced.classId = TypeRelationId;
		referenced.objectId = oper->oprright;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
	}

	
	if (OidIsValid(oper->oprresult))
	{
		referenced.classId = TypeRelationId;
		referenced.objectId = oper->oprresult;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
	}

	

	
	if (OidIsValid(oper->oprcode))
	{
		referenced.classId = ProcedureRelationId;
		referenced.objectId = oper->oprcode;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
	}

	
	if (OidIsValid(oper->oprrest))
	{
		referenced.classId = ProcedureRelationId;
		referenced.objectId = oper->oprrest;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
	}

	
	if (OidIsValid(oper->oprjoin))
	{
		referenced.classId = ProcedureRelationId;
		referenced.objectId = oper->oprjoin;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
	}

	
	recordDependencyOnOwner(OperatorRelationId, oper->oid, oper->oprowner);

	
	recordDependencyOnCurrentExtension(&myself, true);

	return myself;
}
