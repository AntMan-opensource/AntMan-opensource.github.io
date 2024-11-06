























Oid CollationCreate(const char *collname, Oid collnamespace, Oid collowner, char collprovider, bool collisdeterministic, int32 collencoding, const char *collcollate, const char *collctype, const char *collversion, bool if_not_exists, bool quiet)








{
	Relation	rel;
	TupleDesc	tupDesc;
	HeapTuple	tup;
	Datum		values[Natts_pg_collation];
	bool		nulls[Natts_pg_collation];
	NameData	name_name, name_collate, name_ctype;

	Oid			oid;
	ObjectAddress myself, referenced;

	AssertArg(collname);
	AssertArg(collnamespace);
	AssertArg(collowner);
	AssertArg(collcollate);
	AssertArg(collctype);

	
	if (SearchSysCacheExists3(COLLNAMEENCNSP, PointerGetDatum(collname), Int32GetDatum(collencoding), ObjectIdGetDatum(collnamespace)))


	{
		if (quiet)
			return InvalidOid;
		else if (if_not_exists)
		{
			ereport(NOTICE, (errcode(ERRCODE_DUPLICATE_OBJECT), collencoding == -1 ? errmsg("collation \"%s\" already exists, skipping", collname)



					 : errmsg("collation \"%s\" for encoding \"%s\" already exists, skipping", collname, pg_encoding_to_char(collencoding))));
			return InvalidOid;
		}
		else ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), collencoding == -1 ? errmsg("collation \"%s\" already exists", collname)




					 : errmsg("collation \"%s\" for encoding \"%s\" already exists", collname, pg_encoding_to_char(collencoding))));
	}

	
	rel = table_open(CollationRelationId, ShareRowExclusiveLock);

	
	if ((collencoding == -1 && SearchSysCacheExists3(COLLNAMEENCNSP, PointerGetDatum(collname), Int32GetDatum(GetDatabaseEncoding()), ObjectIdGetDatum(collnamespace))) || (collencoding != -1 && SearchSysCacheExists3(COLLNAMEENCNSP, PointerGetDatum(collname), Int32GetDatum(-1), ObjectIdGetDatum(collnamespace))))








	{
		if (quiet)
		{
			table_close(rel, NoLock);
			return InvalidOid;
		}
		else if (if_not_exists)
		{
			table_close(rel, NoLock);
			ereport(NOTICE, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("collation \"%s\" already exists, skipping", collname)));


			return InvalidOid;
		}
		else ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("collation \"%s\" already exists", collname)));



	}

	tupDesc = RelationGetDescr(rel);

	
	memset(nulls, 0, sizeof(nulls));

	namestrcpy(&name_name, collname);
	oid = GetNewOidForCollation(rel, CollationOidIndexId, Anum_pg_collation_oid, collnamespace, NameStr(name_name));
	values[Anum_pg_collation_oid - 1] = ObjectIdGetDatum(oid);
	values[Anum_pg_collation_collname - 1] = NameGetDatum(&name_name);
	values[Anum_pg_collation_collnamespace - 1] = ObjectIdGetDatum(collnamespace);
	values[Anum_pg_collation_collowner - 1] = ObjectIdGetDatum(collowner);
	values[Anum_pg_collation_collprovider - 1] = CharGetDatum(collprovider);
	values[Anum_pg_collation_collisdeterministic - 1] = BoolGetDatum(collisdeterministic);
	values[Anum_pg_collation_collencoding - 1] = Int32GetDatum(collencoding);
	namestrcpy(&name_collate, collcollate);
	values[Anum_pg_collation_collcollate - 1] = NameGetDatum(&name_collate);
	namestrcpy(&name_ctype, collctype);
	values[Anum_pg_collation_collctype - 1] = NameGetDatum(&name_ctype);
	if (collversion)
		values[Anum_pg_collation_collversion - 1] = CStringGetTextDatum(collversion);
	else nulls[Anum_pg_collation_collversion - 1] = true;

	tup = heap_form_tuple(tupDesc, values, nulls);

	
	CatalogTupleInsert(rel, tup);
	Assert(OidIsValid(oid));

	
	myself.classId = CollationRelationId;
	myself.objectId = oid;
	myself.objectSubId = 0;

	
	referenced.classId = NamespaceRelationId;
	referenced.objectId = collnamespace;
	referenced.objectSubId = 0;
	recordDependencyOn(&myself, &referenced, DEPENDENCY_NORMAL);

	
	recordDependencyOnOwner(CollationRelationId, oid, collowner);

	
	recordDependencyOnCurrentExtension(&myself, false);

	
	InvokeObjectPostCreateHook(CollationRelationId, oid, 0);

	heap_freetuple(tup);
	table_close(rel, NoLock);

	return oid;
}


void RemoveCollationById(Oid collationOid)
{
	Relation	rel;
	ScanKeyData scanKeyData;
	SysScanDesc scandesc;
	HeapTuple	tuple;

	rel = table_open(CollationRelationId, RowExclusiveLock);

	ScanKeyInit(&scanKeyData, Anum_pg_collation_oid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(collationOid));



	scandesc = systable_beginscan(rel, CollationOidIndexId, true, NULL, 1, &scanKeyData);

	tuple = systable_getnext(scandesc);

	if (HeapTupleIsValid(tuple))
		CatalogTupleDelete(rel, &tuple->t_self);
	else elog(ERROR, "could not find tuple for collation %u", collationOid);

	systable_endscan(scandesc);

	table_close(rel, RowExclusiveLock);
}
