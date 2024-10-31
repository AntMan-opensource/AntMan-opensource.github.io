

































void add_type_encoding(Oid typid, Datum typoptions)
{
	Relation	pg_type_encoding_desc;
	TupleDesc	tupDesc;
	Datum		 values[Natts_pg_type_encoding];
	bool		 nulls[Natts_pg_type_encoding];
	HeapTuple	 tuple;

	
	pg_type_encoding_desc = table_open(TypeEncodingRelationId, RowExclusiveLock);
	tupDesc = pg_type_encoding_desc->rd_att;

	MemSet(nulls, false, sizeof(nulls));
	
	values[Anum_pg_type_encoding_typid - 1] = ObjectIdGetDatum(typid);
	values[Anum_pg_type_encoding_typoptions - 1] = typoptions;

	tuple = heap_form_tuple(tupDesc, values, nulls);

	
	CatalogTupleInsert(pg_type_encoding_desc, tuple);

	table_close(pg_type_encoding_desc, RowExclusiveLock);
}


List * get_type_encoding(TypeName *typname)
{
	Relation	rel;
	ScanKeyData 	scankey;
	SysScanDesc 	sscan;
	HeapTuple	tuple;
	Oid		typid;
	List 		*out = NIL;

	typid = typenameTypeId(NULL, typname);

	rel = heap_open(TypeEncodingRelationId, AccessShareLock);

	
	ScanKeyInit(&scankey, Anum_pg_type_encoding_typid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(typid));


	sscan = systable_beginscan(rel, TypeEncodingTypidIndexId, true, NULL, 1, &scankey);
	tuple = systable_getnext(sscan);
	if (HeapTupleIsValid(tuple))
	{
		Datum options;
		bool isnull;

		options = heap_getattr(tuple, Anum_pg_type_encoding_typoptions, RelationGetDescr(rel), &isnull);



		if (isnull)
			elog(ERROR, "null typoptions attribute encountered for pg_type_encoding for typid %d", typid);

		out = untransformRelOptions(options);
	}

	systable_endscan(sscan);
	heap_close(rel, AccessShareLock);

	return out;
}


void remove_type_encoding(Oid typid)
{
	Relation 	rel;
	ScanKeyData 	scankey;
	SysScanDesc 	sscan;
	HeapTuple 	tuple;

	rel = heap_open(TypeEncodingRelationId, RowExclusiveLock);

	ScanKeyInit(&scankey, Anum_pg_type_encoding_typid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(typid));



	sscan = systable_beginscan(rel, TypeEncodingTypidIndexId, true, NULL, 1, &scankey);
	while((tuple = systable_getnext(sscan)) != NULL)
	{
		simple_heap_delete(rel, &tuple->t_self);
	}
	systable_endscan(sscan);

	heap_close(rel, RowExclusiveLock);
}


void update_type_encoding(Oid typid, Datum typoptions)
{
	Relation 	pgtypeenc;
	ScanKeyData 	scankey;
	SysScanDesc 	scan;
	HeapTuple	tup;

	
	pgtypeenc = heap_open(TypeEncodingRelationId, RowExclusiveLock);
	ScanKeyInit(&scankey, Anum_pg_type_encoding_typid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(typid));

	scan = systable_beginscan(pgtypeenc, TypeEncodingTypidIndexId, true, NULL, 1, &scankey);

	tup = systable_getnext(scan);
	if (HeapTupleIsValid(tup))
	{
		
		Datum values[Natts_pg_type_encoding];
		bool nulls[Natts_pg_type_encoding];
		bool replaces[Natts_pg_type_encoding];
		HeapTuple newtuple;

		MemSet(values, 0, sizeof(values));
		MemSet(nulls, false, sizeof(nulls));
		MemSet(replaces, false, sizeof(replaces));

		replaces[Anum_pg_type_encoding_typoptions - 1] = true;
		values[Anum_pg_type_encoding_typoptions - 1] = typoptions;

		newtuple = heap_modify_tuple(tup, RelationGetDescr(pgtypeenc), values, nulls, replaces);

		CatalogTupleUpdate(pgtypeenc, &tup->t_self, newtuple);
	}
	else {
		add_type_encoding(typid, typoptions);
	}	
	systable_endscan(scan);
	heap_close(pgtypeenc, NoLock);

}


ObjectAddress TypeShellMake(const char *typeName, Oid typeNamespace, Oid ownerId)
{
	Relation	pg_type_desc;
	TupleDesc	tupDesc;
	int			i;
	HeapTuple	tup;
	Datum		values[Natts_pg_type];
	bool		nulls[Natts_pg_type];
	Oid			typoid;
	NameData	name;
	ObjectAddress address;

	Assert(PointerIsValid(typeName));

	
	pg_type_desc = table_open(TypeRelationId, RowExclusiveLock);
	tupDesc = pg_type_desc->rd_att;

	
	for (i = 0; i < Natts_pg_type; ++i)
	{
		nulls[i] = false;
		values[i] = (Datum) NULL;	
	}

	
	namestrcpy(&name, typeName);
	values[Anum_pg_type_typname - 1] = NameGetDatum(&name);
	values[Anum_pg_type_typnamespace - 1] = ObjectIdGetDatum(typeNamespace);
	values[Anum_pg_type_typowner - 1] = ObjectIdGetDatum(ownerId);
	values[Anum_pg_type_typlen - 1] = Int16GetDatum(sizeof(int32));
	values[Anum_pg_type_typbyval - 1] = BoolGetDatum(true);
	values[Anum_pg_type_typtype - 1] = CharGetDatum(TYPTYPE_PSEUDO);
	values[Anum_pg_type_typcategory - 1] = CharGetDatum(TYPCATEGORY_PSEUDOTYPE);
	values[Anum_pg_type_typispreferred - 1] = BoolGetDatum(false);
	values[Anum_pg_type_typisdefined - 1] = BoolGetDatum(false);
	values[Anum_pg_type_typdelim - 1] = CharGetDatum(DEFAULT_TYPDELIM);
	values[Anum_pg_type_typrelid - 1] = ObjectIdGetDatum(InvalidOid);
	values[Anum_pg_type_typelem - 1] = ObjectIdGetDatum(InvalidOid);
	values[Anum_pg_type_typarray - 1] = ObjectIdGetDatum(InvalidOid);
	values[Anum_pg_type_typinput - 1] = ObjectIdGetDatum(F_SHELL_IN);
	values[Anum_pg_type_typoutput - 1] = ObjectIdGetDatum(F_SHELL_OUT);
	values[Anum_pg_type_typreceive - 1] = ObjectIdGetDatum(InvalidOid);
	values[Anum_pg_type_typsend - 1] = ObjectIdGetDatum(InvalidOid);
	values[Anum_pg_type_typmodin - 1] = ObjectIdGetDatum(InvalidOid);
	values[Anum_pg_type_typmodout - 1] = ObjectIdGetDatum(InvalidOid);
	values[Anum_pg_type_typanalyze - 1] = ObjectIdGetDatum(InvalidOid);
	values[Anum_pg_type_typalign - 1] = CharGetDatum('i');
	values[Anum_pg_type_typstorage - 1] = CharGetDatum('p');
	values[Anum_pg_type_typnotnull - 1] = BoolGetDatum(false);
	values[Anum_pg_type_typbasetype - 1] = ObjectIdGetDatum(InvalidOid);
	values[Anum_pg_type_typtypmod - 1] = Int32GetDatum(-1);
	values[Anum_pg_type_typndims - 1] = Int32GetDatum(0);
	values[Anum_pg_type_typcollation - 1] = ObjectIdGetDatum(InvalidOid);
	nulls[Anum_pg_type_typdefaultbin - 1] = true;
	nulls[Anum_pg_type_typdefault - 1] = true;
	nulls[Anum_pg_type_typacl - 1] = true;

	typoid = GetNewOidForType(pg_type_desc, TypeOidIndexId, Anum_pg_type_oid, NameStr(name), typeNamespace);


	values[Anum_pg_type_oid - 1] = ObjectIdGetDatum(typoid);

	
	tup = heap_form_tuple(tupDesc, values, nulls);

	
	CatalogTupleInsert(pg_type_desc, tup);

	
	if (!IsBootstrapProcessingMode())
		GenerateTypeDependencies(typoid, (Form_pg_type) GETSTRUCT(tup), NULL, NULL, 0, false, false, false);







	
	InvokeObjectPostCreateHook(TypeRelationId, typoid, 0);

	ObjectAddressSet(address, TypeRelationId, typoid);

	
	heap_freetuple(tup);
	table_close(pg_type_desc, RowExclusiveLock);

	return address;
}


ObjectAddress TypeCreate(Oid newTypeOid, const char *typeName, Oid typeNamespace, Oid relationOid, char relationKind, Oid ownerId, int16 internalSize, char typeType, char typeCategory, bool typePreferred, char typDelim, Oid inputProcedure, Oid outputProcedure, Oid receiveProcedure, Oid sendProcedure, Oid typmodinProcedure, Oid typmodoutProcedure, Oid analyzeProcedure, Oid elementType, bool isImplicitArray, Oid arrayType, Oid baseType, const char *defaultTypeValue, char *defaultTypeBin, bool passedByValue, char alignment, char storage, int32 typeMod, int32 typNDims, bool typeNotNull, Oid typeCollation)






























{
	Relation	pg_type_desc;
	Oid			typeObjectId;
	bool		isDependentType;
	bool		rebuildDeps = false;
	Acl		   *typacl;
	HeapTuple	tup;
	bool		nulls[Natts_pg_type];
	bool		replaces[Natts_pg_type];
	Datum		values[Natts_pg_type];
	NameData	name;
	int			i;
	ObjectAddress address;

	
	if (!(internalSize > 0 || internalSize == -1 || internalSize == -2))

		ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("invalid type internal size %d", internalSize)));



	if (passedByValue)
	{
		
		if (internalSize == (int16) sizeof(char))
		{
			if (alignment != 'c')
				ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("alignment \"%c\" is invalid for passed-by-value type of size %d", alignment, internalSize)));


		}
		else if (internalSize == (int16) sizeof(int16))
		{
			if (alignment != 's')
				ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("alignment \"%c\" is invalid for passed-by-value type of size %d", alignment, internalSize)));


		}
		else if (internalSize == (int16) sizeof(int32))
		{
			if (alignment != 'i')
				ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("alignment \"%c\" is invalid for passed-by-value type of size %d", alignment, internalSize)));


		}

		else if (internalSize == (int16) sizeof(Datum))
		{
			if (alignment != 'd')
				ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("alignment \"%c\" is invalid for passed-by-value type of size %d", alignment, internalSize)));


		}

		else ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("internal size %d is invalid for passed-by-value type", internalSize)));



	}
	else {
		
		if (internalSize == -1 && !(alignment == 'i' || alignment == 'd'))
			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("alignment \"%c\" is invalid for variable-length type", alignment)));


		
		if (internalSize == -2 && !(alignment == 'c'))
			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("alignment \"%c\" is invalid for variable-length type", alignment)));


	}

	
	if (storage != 'p' && internalSize != -1)
		ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("fixed-size types must have storage PLAIN")));


	
	isDependentType = isImplicitArray || (OidIsValid(relationOid) && relationKind != RELKIND_COMPOSITE_TYPE);

	
	for (i = 0; i < Natts_pg_type; ++i)
	{
		nulls[i] = false;
		replaces[i] = true;
		values[i] = (Datum) 0;
	}

	
	namestrcpy(&name, typeName);
	values[Anum_pg_type_typname - 1] = NameGetDatum(&name);
	values[Anum_pg_type_typnamespace - 1] = ObjectIdGetDatum(typeNamespace);
	values[Anum_pg_type_typowner - 1] = ObjectIdGetDatum(ownerId);
	values[Anum_pg_type_typlen - 1] = Int16GetDatum(internalSize);
	values[Anum_pg_type_typbyval - 1] = BoolGetDatum(passedByValue);
	values[Anum_pg_type_typtype - 1] = CharGetDatum(typeType);
	values[Anum_pg_type_typcategory - 1] = CharGetDatum(typeCategory);
	values[Anum_pg_type_typispreferred - 1] = BoolGetDatum(typePreferred);
	values[Anum_pg_type_typisdefined - 1] = BoolGetDatum(true);
	values[Anum_pg_type_typdelim - 1] = CharGetDatum(typDelim);
	values[Anum_pg_type_typrelid - 1] = ObjectIdGetDatum(relationOid);
	values[Anum_pg_type_typelem - 1] = ObjectIdGetDatum(elementType);
	values[Anum_pg_type_typarray - 1] = ObjectIdGetDatum(arrayType);
	values[Anum_pg_type_typinput - 1] = ObjectIdGetDatum(inputProcedure);
	values[Anum_pg_type_typoutput - 1] = ObjectIdGetDatum(outputProcedure);
	values[Anum_pg_type_typreceive - 1] = ObjectIdGetDatum(receiveProcedure);
	values[Anum_pg_type_typsend - 1] = ObjectIdGetDatum(sendProcedure);
	values[Anum_pg_type_typmodin - 1] = ObjectIdGetDatum(typmodinProcedure);
	values[Anum_pg_type_typmodout - 1] = ObjectIdGetDatum(typmodoutProcedure);
	values[Anum_pg_type_typanalyze - 1] = ObjectIdGetDatum(analyzeProcedure);
	values[Anum_pg_type_typalign - 1] = CharGetDatum(alignment);
	values[Anum_pg_type_typstorage - 1] = CharGetDatum(storage);
	values[Anum_pg_type_typnotnull - 1] = BoolGetDatum(typeNotNull);
	values[Anum_pg_type_typbasetype - 1] = ObjectIdGetDatum(baseType);
	values[Anum_pg_type_typtypmod - 1] = Int32GetDatum(typeMod);
	values[Anum_pg_type_typndims - 1] = Int32GetDatum(typNDims);
	values[Anum_pg_type_typcollation - 1] = ObjectIdGetDatum(typeCollation);

	
	if (defaultTypeBin)
		values[Anum_pg_type_typdefaultbin - 1] = CStringGetTextDatum(defaultTypeBin);
	else nulls[Anum_pg_type_typdefaultbin - 1] = true;

	
	if (defaultTypeValue)
		values[Anum_pg_type_typdefault - 1] = CStringGetTextDatum(defaultTypeValue);
	else nulls[Anum_pg_type_typdefault - 1] = true;

	
	if (isDependentType)
		typacl = NULL;
	else typacl = get_user_default_acl(OBJECT_TYPE, ownerId, typeNamespace);

	if (typacl != NULL)
		values[Anum_pg_type_typacl - 1] = PointerGetDatum(typacl);
	else nulls[Anum_pg_type_typacl - 1] = true;

	
	pg_type_desc = table_open(TypeRelationId, RowExclusiveLock);

	tup = SearchSysCacheCopy2(TYPENAMENSP, CStringGetDatum(typeName), ObjectIdGetDatum(typeNamespace));

	if (HeapTupleIsValid(tup))
	{
		Form_pg_type typform = (Form_pg_type) GETSTRUCT(tup);

		
		if (typform->typisdefined)
			ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("type \"%s\" already exists", typeName)));


		
		if (typform->typowner != ownerId)
			aclcheck_error(ACLCHECK_NOT_OWNER, OBJECT_TYPE, typeName);

		
		if (OidIsValid(newTypeOid))
			elog(ERROR, "cannot assign new OID to existing shell type");

		replaces[Anum_pg_type_oid - 1] = false;

		
		tup = heap_modify_tuple(tup, RelationGetDescr(pg_type_desc), values, nulls, replaces);




		CatalogTupleUpdate(pg_type_desc, &tup->t_self, tup);

		typeObjectId = typform->oid;

		rebuildDeps = true;		
	}
	else {
		
		if (OidIsValid(newTypeOid))
			typeObjectId = newTypeOid;
		else {
			typeObjectId = GetNewOidForType(pg_type_desc, TypeOidIndexId, Anum_pg_type_oid, NameStr(name), typeNamespace);

		}

		values[Anum_pg_type_oid - 1] = ObjectIdGetDatum(typeObjectId);

		tup = heap_form_tuple(RelationGetDescr(pg_type_desc), values, nulls);

		CatalogTupleInsert(pg_type_desc, tup);
	}

	
	if (!IsBootstrapProcessingMode())
		GenerateTypeDependencies(typeObjectId, (Form_pg_type) GETSTRUCT(tup), (defaultTypeBin ? stringToNode(defaultTypeBin) :


								  NULL), typacl, relationKind, isImplicitArray, isDependentType, rebuildDeps);





	
	InvokeObjectPostCreateHook(TypeRelationId, typeObjectId, 0);

	ObjectAddressSet(address, TypeRelationId, typeObjectId);

	
	table_close(pg_type_desc, RowExclusiveLock);

	return address;
}


void GenerateTypeDependencies(Oid typeObjectId, Form_pg_type typeForm, Node *defaultExpr, void *typacl, char relationKind, bool isImplicitArray, bool isDependentType, bool rebuild)







{
	ObjectAddress myself, referenced;

	
	if (rebuild)
	{
		deleteDependencyRecordsFor(TypeRelationId, typeObjectId, true);
		deleteSharedDependencyRecordsFor(TypeRelationId, typeObjectId, 0);
	}

	myself.classId = TypeRelationId;
	myself.objectId = typeObjectId;
	myself.objectSubId = 0;

	
	if (!isDependentType)
	{
		referenced.classId = NamespaceRelationId;
		referenced.objectId = typeForm->typnamespace;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);

		recordDependencyOnOwner(TypeRelationId, typeObjectId, typeForm->typowner);

		recordDependencyOnNewAcl(TypeRelationId, typeObjectId, 0, typeForm->typowner, typacl);

		recordDependencyOnCurrentExtension(&myself, rebuild);
	}

	
	if (OidIsValid(typeForm->typinput))
	{
		referenced.classId = ProcedureRelationId;
		referenced.objectId = typeForm->typinput;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
	}

	if (OidIsValid(typeForm->typoutput))
	{
		referenced.classId = ProcedureRelationId;
		referenced.objectId = typeForm->typoutput;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
	}

	if (OidIsValid(typeForm->typreceive))
	{
		referenced.classId = ProcedureRelationId;
		referenced.objectId = typeForm->typreceive;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
	}

	if (OidIsValid(typeForm->typsend))
	{
		referenced.classId = ProcedureRelationId;
		referenced.objectId = typeForm->typsend;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
	}

	if (OidIsValid(typeForm->typmodin))
	{
		referenced.classId = ProcedureRelationId;
		referenced.objectId = typeForm->typmodin;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
	}

	if (OidIsValid(typeForm->typmodout))
	{
		referenced.classId = ProcedureRelationId;
		referenced.objectId = typeForm->typmodout;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
	}

	if (OidIsValid(typeForm->typanalyze))
	{
		referenced.classId = ProcedureRelationId;
		referenced.objectId = typeForm->typanalyze;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
	}

	
	if (OidIsValid(typeForm->typrelid))
	{
		referenced.classId = RelationRelationId;
		referenced.objectId = typeForm->typrelid;
		referenced.objectSubId = 0;

		if (relationKind != RELKIND_COMPOSITE_TYPE)
			recordDependencyOn(&myself, &referenced, DEPENDENCY_INTERNAL);
		else recordDependencyOn(&referenced, &myself, DEPENDENCY_INTERNAL);
	}

	
	if (OidIsValid(typeForm->typelem))
	{
		referenced.classId = TypeRelationId;
		referenced.objectId = typeForm->typelem;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, isImplicitArray ? DEPENDENCY_INTERNAL : DEPENDENCY_NORMAL);
	}

	
	if (OidIsValid(typeForm->typbasetype))
	{
		referenced.classId = TypeRelationId;
		referenced.objectId = typeForm->typbasetype;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
	}

	
	
	if (OidIsValid(typeForm->typcollation) && typeForm->typcollation != DEFAULT_COLLATION_OID)
	{
		referenced.classId = CollationRelationId;
		referenced.objectId = typeForm->typcollation;
		referenced.objectSubId = 0;
		recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);
	}

	
	if (defaultExpr)
		recordDependencyOnExpr(&myself, defaultExpr, NIL, DEPENDENCY_NORMAL);
}


void RenameTypeInternal(Oid typeOid, const char *newTypeName, Oid typeNamespace)
{
	Relation	pg_type_desc;
	HeapTuple	tuple;
	Form_pg_type typ;
	Oid			arrayOid;
	Oid			oldTypeOid;

	pg_type_desc = table_open(TypeRelationId, RowExclusiveLock);

	tuple = SearchSysCacheCopy1(TYPEOID, ObjectIdGetDatum(typeOid));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for type %u", typeOid);
	typ = (Form_pg_type) GETSTRUCT(tuple);

	
	Assert(typeNamespace == typ->typnamespace);

	arrayOid = typ->typarray;

	
	oldTypeOid = GetSysCacheOid2(TYPENAMENSP, Anum_pg_type_oid, CStringGetDatum(newTypeName), ObjectIdGetDatum(typeNamespace));


	
	if (OidIsValid(oldTypeOid))
	{
		if (get_typisdefined(oldTypeOid) && moveArrayTypeName(oldTypeOid, newTypeName, typeNamespace))
			  ;
		else ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("type \"%s\" already exists", newTypeName)));


	}

	
	namestrcpy(&(typ->typname), newTypeName);

	CatalogTupleUpdate(pg_type_desc, &tuple->t_self, tuple);

	InvokeObjectPostAlterHook(TypeRelationId, typeOid, 0);

	heap_freetuple(tuple);
	table_close(pg_type_desc, RowExclusiveLock);

	
	if (OidIsValid(arrayOid) && arrayOid != oldTypeOid)
	{
		char	   *arrname = makeArrayTypeName(newTypeName, typeNamespace);

		RenameTypeInternal(arrayOid, arrname, typeNamespace);
		pfree(arrname);
	}
}



char * makeArrayTypeName(const char *typeName, Oid typeNamespace)
{
	char	   *arr = (char *) palloc(NAMEDATALEN);
	int			namelen = strlen(typeName);
	Relation	pg_type_desc;
	int			i;

	
	pg_type_desc = table_open(TypeRelationId, AccessShareLock);

	for (i = 1; i < NAMEDATALEN - 1; i++)
	{
		arr[i - 1] = '_';
		if (i + namelen < NAMEDATALEN)
			strcpy(arr + i, typeName);
		else {
			memcpy(arr + i, typeName, NAMEDATALEN - i);
			truncate_identifier(arr, NAMEDATALEN, false);
		}
		if (!SearchSysCacheExists2(TYPENAMENSP, CStringGetDatum(arr), ObjectIdGetDatum(typeNamespace)))

			break;
	}

	table_close(pg_type_desc, AccessShareLock);

	if (i >= NAMEDATALEN - 1)
		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("could not form array type name for type \"%s\"", typeName)));



	return arr;
}



bool moveArrayTypeName(Oid typeOid, const char *typeName, Oid typeNamespace)
{
	Oid			elemOid;
	char	   *newname;

	
	if (!get_typisdefined(typeOid))
		return true;

	
	elemOid = get_element_type(typeOid);
	if (!OidIsValid(elemOid) || get_array_type(elemOid) != typeOid)
		return false;

	
	newname = makeArrayTypeName(typeName, typeNamespace);

	
	RenameTypeInternal(typeOid, newname, typeNamespace);

	
	CommandCounterIncrement();

	pfree(newname);

	return true;
}

