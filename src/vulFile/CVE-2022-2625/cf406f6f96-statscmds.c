
























static char *ChooseExtendedStatisticName(const char *name1, const char *name2, const char *label, Oid namespaceid);
static char *ChooseExtendedStatisticNameAddition(List *exprs);



static int compare_int16(const void *a, const void *b)
{
	int			av = *(const int16 *) a;
	int			bv = *(const int16 *) b;

	
	return (av - bv);
}


ObjectAddress CreateStatistics(CreateStatsStmt *stmt)
{
	int16		attnums[STATS_MAX_DIMENSIONS];
	int			numcols = 0;
	char	   *namestr;
	NameData	stxname;
	Oid			statoid;
	Oid			namespaceId;
	Oid			stxowner = GetUserId();
	HeapTuple	htup;
	Datum		values[Natts_pg_statistic_ext];
	bool		nulls[Natts_pg_statistic_ext];
	Datum		datavalues[Natts_pg_statistic_ext_data];
	bool		datanulls[Natts_pg_statistic_ext_data];
	int2vector *stxkeys;
	Relation	statrel;
	Relation	datarel;
	Relation	rel = NULL;
	Oid			relid;
	ObjectAddress parentobject, myself;
	Datum		types[3];		
	int			ntypes;
	ArrayType  *stxkind;
	bool		build_ndistinct;
	bool		build_dependencies;
	bool		build_mcv;
	bool		requested_type = false;
	int			i;
	ListCell   *cell;

	Assert(IsA(stmt, CreateStatsStmt));

	
	if (list_length(stmt->relations) != 1)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("only a single relation is allowed in CREATE STATISTICS")));


	foreach(cell, stmt->relations)
	{
		Node	   *rln = (Node *) lfirst(cell);

		if (!IsA(rln, RangeVar))
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("only a single relation is allowed in CREATE STATISTICS")));


		
		rel = relation_openrv((RangeVar *) rln, ShareUpdateExclusiveLock);

		
		if (rel->rd_rel->relkind != RELKIND_RELATION && rel->rd_rel->relkind != RELKIND_MATVIEW && rel->rd_rel->relkind != RELKIND_FOREIGN_TABLE && rel->rd_rel->relkind != RELKIND_PARTITIONED_TABLE)


			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("relation \"%s\" is not a table, foreign table, or materialized view", RelationGetRelationName(rel))));



		
		if (!pg_class_ownercheck(RelationGetRelid(rel), stxowner))
			aclcheck_error(ACLCHECK_NOT_OWNER, get_relkind_objtype(rel->rd_rel->relkind), RelationGetRelationName(rel));
	}

	Assert(rel);
	relid = RelationGetRelid(rel);

	
	if (stmt->defnames)
		namespaceId = QualifiedNameGetCreationNamespace(stmt->defnames, &namestr);
	else {
		namespaceId = RelationGetNamespace(rel);
		namestr = ChooseExtendedStatisticName(RelationGetRelationName(rel), ChooseExtendedStatisticNameAddition(stmt->exprs), "stat", namespaceId);


	}
	namestrcpy(&stxname, namestr);

	
	if (SearchSysCacheExists2(STATEXTNAMENSP, CStringGetDatum(namestr), ObjectIdGetDatum(namespaceId)))

	{
		if (stmt->if_not_exists)
		{
			ereport(NOTICE, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("statistics object \"%s\" already exists, skipping", namestr)));


			relation_close(rel, NoLock);
			return InvalidObjectAddress;
		}

		ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("statistics object \"%s\" already exists", namestr)));

	}

	
	foreach(cell, stmt->exprs)
	{
		Node	   *expr = (Node *) lfirst(cell);
		ColumnRef  *cref;
		char	   *attname;
		HeapTuple	atttuple;
		Form_pg_attribute attForm;
		TypeCacheEntry *type;

		if (!IsA(expr, ColumnRef))
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("only simple column references are allowed in CREATE STATISTICS")));

		cref = (ColumnRef *) expr;

		if (list_length(cref->fields) != 1)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("only simple column references are allowed in CREATE STATISTICS")));

		attname = strVal((Value *) linitial(cref->fields));

		atttuple = SearchSysCacheAttName(relid, attname);
		if (!HeapTupleIsValid(atttuple))
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" does not exist", attname)));


		attForm = (Form_pg_attribute) GETSTRUCT(atttuple);

		
		if (attForm->attnum <= 0)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("statistics creation on system columns is not supported")));


		
		type = lookup_type_cache(attForm->atttypid, TYPECACHE_LT_OPR);
		if (type->lt_opr == InvalidOid)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("column \"%s\" cannot be used in statistics because its type %s has no default btree operator class", attname, format_type_be(attForm->atttypid))));



		
		if (numcols >= STATS_MAX_DIMENSIONS)
			ereport(ERROR, (errcode(ERRCODE_TOO_MANY_COLUMNS), errmsg("cannot have more than %d columns in statistics", STATS_MAX_DIMENSIONS)));



		attnums[numcols] = attForm->attnum;
		numcols++;
		ReleaseSysCache(atttuple);
	}

	
	if (numcols < 2)
		ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("extended statistics require at least 2 columns")));


	
	qsort(attnums, numcols, sizeof(int16), compare_int16);

	
	for (i = 1; i < numcols; i++)
	{
		if (attnums[i] == attnums[i - 1])
			ereport(ERROR, (errcode(ERRCODE_DUPLICATE_COLUMN), errmsg("duplicate column name in statistics definition")));

	}

	
	stxkeys = buildint2vector(attnums, numcols);

	
	build_ndistinct = false;
	build_dependencies = false;
	build_mcv = false;
	foreach(cell, stmt->stat_types)
	{
		char	   *type = strVal((Value *) lfirst(cell));

		if (strcmp(type, "ndistinct") == 0)
		{
			build_ndistinct = true;
			requested_type = true;
		}
		else if (strcmp(type, "dependencies") == 0)
		{
			build_dependencies = true;
			requested_type = true;
		}
		else if (strcmp(type, "mcv") == 0)
		{
			build_mcv = true;
			requested_type = true;
		}
		else ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("unrecognized statistics kind \"%s\"", type)));



	}
	
	if (!requested_type)
	{
		build_ndistinct = true;
		build_dependencies = true;
		build_mcv = true;
	}

	
	ntypes = 0;
	if (build_ndistinct)
		types[ntypes++] = CharGetDatum(STATS_EXT_NDISTINCT);
	if (build_dependencies)
		types[ntypes++] = CharGetDatum(STATS_EXT_DEPENDENCIES);
	if (build_mcv)
		types[ntypes++] = CharGetDatum(STATS_EXT_MCV);
	Assert(ntypes > 0 && ntypes <= lengthof(types));
	stxkind = construct_array(types, ntypes, CHAROID, 1, true, 'c');

	statrel = table_open(StatisticExtRelationId, RowExclusiveLock);

	
	memset(values, 0, sizeof(values));
	memset(nulls, false, sizeof(nulls));

	statoid = GetNewOidWithIndex(statrel, StatisticExtOidIndexId, Anum_pg_statistic_ext_oid);
	values[Anum_pg_statistic_ext_oid - 1] = ObjectIdGetDatum(statoid);
	values[Anum_pg_statistic_ext_stxrelid - 1] = ObjectIdGetDatum(relid);
	values[Anum_pg_statistic_ext_stxname - 1] = NameGetDatum(&stxname);
	values[Anum_pg_statistic_ext_stxnamespace - 1] = ObjectIdGetDatum(namespaceId);
	values[Anum_pg_statistic_ext_stxowner - 1] = ObjectIdGetDatum(stxowner);
	values[Anum_pg_statistic_ext_stxkeys - 1] = PointerGetDatum(stxkeys);
	values[Anum_pg_statistic_ext_stxkind - 1] = PointerGetDatum(stxkind);

	
	htup = heap_form_tuple(statrel->rd_att, values, nulls);
	CatalogTupleInsert(statrel, htup);
	heap_freetuple(htup);

	relation_close(statrel, RowExclusiveLock);

	
	datarel = table_open(StatisticExtDataRelationId, RowExclusiveLock);

	memset(datavalues, 0, sizeof(datavalues));
	memset(datanulls, false, sizeof(datanulls));

	datavalues[Anum_pg_statistic_ext_data_stxoid - 1] = ObjectIdGetDatum(statoid);

	
	datanulls[Anum_pg_statistic_ext_data_stxdndistinct - 1] = true;
	datanulls[Anum_pg_statistic_ext_data_stxddependencies - 1] = true;
	datanulls[Anum_pg_statistic_ext_data_stxdmcv - 1] = true;

	
	htup = heap_form_tuple(datarel->rd_att, datavalues, datanulls);
	CatalogTupleInsert(datarel, htup);
	heap_freetuple(htup);

	relation_close(datarel, RowExclusiveLock);

	
	CacheInvalidateRelcache(rel);

	relation_close(rel, NoLock);

	
	ObjectAddressSet(myself, StatisticExtRelationId, statoid);

	for (i = 0; i < numcols; i++)
	{
		ObjectAddressSubSet(parentobject, RelationRelationId, relid, attnums[i]);
		recordDependencyOn(&myself, &parentobject, DEPENDENCY_AUTO);
	}

	
	ObjectAddressSet(parentobject, NamespaceRelationId, namespaceId);
	recordDependencyOn(&myself, &parentobject, DEPENDENCY_NORMAL);

	recordDependencyOnOwner(StatisticExtRelationId, statoid, stxowner);

	

	
	if (stmt->stxcomment != NULL)
		CreateComments(statoid, StatisticExtRelationId, 0, stmt->stxcomment);

	
	return myself;
}


void RemoveStatisticsById(Oid statsOid)
{
	Relation	relation;
	HeapTuple	tup;
	Form_pg_statistic_ext statext;
	Oid			relid;

	
	relation = table_open(StatisticExtDataRelationId, RowExclusiveLock);

	tup = SearchSysCache1(STATEXTDATASTXOID, ObjectIdGetDatum(statsOid));

	if (!HeapTupleIsValid(tup)) 
		elog(ERROR, "cache lookup failed for statistics data %u", statsOid);

	CatalogTupleDelete(relation, &tup->t_self);

	ReleaseSysCache(tup);

	table_close(relation, RowExclusiveLock);

	
	relation = table_open(StatisticExtRelationId, RowExclusiveLock);

	tup = SearchSysCache1(STATEXTOID, ObjectIdGetDatum(statsOid));

	if (!HeapTupleIsValid(tup)) 
		elog(ERROR, "cache lookup failed for statistics object %u", statsOid);

	statext = (Form_pg_statistic_ext) GETSTRUCT(tup);
	relid = statext->stxrelid;

	CacheInvalidateRelcacheByRelid(relid);

	CatalogTupleDelete(relation, &tup->t_self);

	ReleaseSysCache(tup);

	table_close(relation, RowExclusiveLock);
}


void UpdateStatisticsForTypeChange(Oid statsOid, Oid relationOid, int attnum, Oid oldColumnType, Oid newColumnType)

{
	HeapTuple	stup, oldtup;

	Relation	rel;

	Datum		values[Natts_pg_statistic_ext_data];
	bool		nulls[Natts_pg_statistic_ext_data];
	bool		replaces[Natts_pg_statistic_ext_data];

	oldtup = SearchSysCache1(STATEXTDATASTXOID, ObjectIdGetDatum(statsOid));
	if (!HeapTupleIsValid(oldtup))
		elog(ERROR, "cache lookup failed for statistics object %u", statsOid);

	
	if (!statext_is_kind_built(oldtup, STATS_EXT_MCV))
	{
		ReleaseSysCache(oldtup);
		return;
	}

	
	memset(nulls, 0, Natts_pg_statistic_ext_data * sizeof(bool));
	memset(replaces, 0, Natts_pg_statistic_ext_data * sizeof(bool));
	memset(values, 0, Natts_pg_statistic_ext_data * sizeof(Datum));

	replaces[Anum_pg_statistic_ext_data_stxdmcv - 1] = true;
	nulls[Anum_pg_statistic_ext_data_stxdmcv - 1] = true;

	rel = heap_open(StatisticExtDataRelationId, RowExclusiveLock);

	
	stup = heap_modify_tuple(oldtup, RelationGetDescr(rel), values, nulls, replaces);




	ReleaseSysCache(oldtup);
	CatalogTupleUpdate(rel, &stup->t_self, stup);

	heap_freetuple(stup);

	heap_close(rel, RowExclusiveLock);
}


static char * ChooseExtendedStatisticName(const char *name1, const char *name2, const char *label, Oid namespaceid)

{
	int			pass = 0;
	char	   *stxname = NULL;
	char		modlabel[NAMEDATALEN];

	
	StrNCpy(modlabel, label, sizeof(modlabel));

	for (;;)
	{
		Oid			existingstats;

		stxname = makeObjectName(name1, name2, modlabel);

		existingstats = GetSysCacheOid2(STATEXTNAMENSP, Anum_pg_statistic_ext_oid, PointerGetDatum(stxname), ObjectIdGetDatum(namespaceid));

		if (!OidIsValid(existingstats))
			break;

		
		pfree(stxname);
		snprintf(modlabel, sizeof(modlabel), "%s%d", label, ++pass);
	}

	return stxname;
}


static char * ChooseExtendedStatisticNameAddition(List *exprs)
{
	char		buf[NAMEDATALEN * 2];
	int			buflen = 0;
	ListCell   *lc;

	buf[0] = '\0';
	foreach(lc, exprs)
	{
		ColumnRef  *cref = (ColumnRef *) lfirst(lc);
		const char *name;

		
		if (!IsA(cref, ColumnRef))
			continue;

		name = strVal((Value *) linitial(cref->fields));

		if (buflen > 0)
			buf[buflen++] = '_';	

		
		strlcpy(buf + buflen, name, NAMEDATALEN);
		buflen += strlen(buf + buflen);
		if (buflen >= NAMEDATALEN)
			break;
	}
	return pstrdup(buf);
}
