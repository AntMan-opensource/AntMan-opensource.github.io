

















static bool isObjectPinned(const ObjectAddress *object, Relation rel);



void recordDependencyOn(const ObjectAddress *depender, const ObjectAddress *referenced, DependencyType behavior)


{
	recordMultipleDependencies(depender, referenced, 1, behavior);
}


void recordMultipleDependencies(const ObjectAddress *depender, const ObjectAddress *referenced, int nreferenced, DependencyType behavior)



{
	Relation	dependDesc;
	CatalogIndexState indstate;
	HeapTuple	tup;
	int			i;
	bool		nulls[Natts_pg_depend];
	Datum		values[Natts_pg_depend];

	if (nreferenced <= 0)
		return;					

	
	if (IsBootstrapProcessingMode())
		return;

	dependDesc = table_open(DependRelationId, RowExclusiveLock);

	
	indstate = NULL;

	memset(nulls, false, sizeof(nulls));

	for (i = 0; i < nreferenced; i++, referenced++)
	{
		
		if (!isObjectPinned(referenced, dependDesc))
		{
			
			values[Anum_pg_depend_classid - 1] = ObjectIdGetDatum(depender->classId);
			values[Anum_pg_depend_objid - 1] = ObjectIdGetDatum(depender->objectId);
			values[Anum_pg_depend_objsubid - 1] = Int32GetDatum(depender->objectSubId);

			values[Anum_pg_depend_refclassid - 1] = ObjectIdGetDatum(referenced->classId);
			values[Anum_pg_depend_refobjid - 1] = ObjectIdGetDatum(referenced->objectId);
			values[Anum_pg_depend_refobjsubid - 1] = Int32GetDatum(referenced->objectSubId);

			values[Anum_pg_depend_deptype - 1] = CharGetDatum((char) behavior);

			tup = heap_form_tuple(dependDesc->rd_att, values, nulls);

			
			if (indstate == NULL)
				indstate = CatalogOpenIndexes(dependDesc);

			CatalogTupleInsertWithInfo(dependDesc, tup, indstate);

			heap_freetuple(tup);
		}
	}

	if (indstate != NULL)
		CatalogCloseIndexes(indstate);

	table_close(dependDesc, RowExclusiveLock);
}


void recordDependencyOnCurrentExtension(const ObjectAddress *object, bool isReplace)

{
	
	Assert(object->objectSubId == 0);

	if (creating_extension)
	{
		ObjectAddress extension;

		
		if (isReplace)
		{
			Oid			oldext;

			oldext = getExtensionOfObject(object->classId, object->objectId);
			if (OidIsValid(oldext))
			{
				
				if (oldext == CurrentExtensionObject)
					return;
				
				ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("%s is already a member of extension \"%s\"", getObjectDescription(object), get_extension_name(oldext))));



			}
		}

		
		extension.classId = ExtensionRelationId;
		extension.objectId = CurrentExtensionObject;
		extension.objectSubId = 0;

		recordDependencyOn(object, &extension, DEPENDENCY_EXTENSION);
	}
}


long deleteDependencyRecordsFor(Oid classId, Oid objectId, bool skipExtensionDeps)

{
	long		count = 0;
	Relation	depRel;
	ScanKeyData key[2];
	SysScanDesc scan;
	HeapTuple	tup;

	depRel = table_open(DependRelationId, RowExclusiveLock);

	ScanKeyInit(&key[0], Anum_pg_depend_classid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(classId));


	ScanKeyInit(&key[1], Anum_pg_depend_objid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(objectId));



	scan = systable_beginscan(depRel, DependDependerIndexId, true, NULL, 2, key);

	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		if (skipExtensionDeps && ((Form_pg_depend) GETSTRUCT(tup))->deptype == DEPENDENCY_EXTENSION)
			continue;

		CatalogTupleDelete(depRel, &tup->t_self);
		count++;
	}

	systable_endscan(scan);

	table_close(depRel, RowExclusiveLock);

	return count;
}


long deleteDependencyRecordsForClass(Oid classId, Oid objectId, Oid refclassId, char deptype)

{
	long		count = 0;
	Relation	depRel;
	ScanKeyData key[2];
	SysScanDesc scan;
	HeapTuple	tup;

	depRel = table_open(DependRelationId, RowExclusiveLock);

	ScanKeyInit(&key[0], Anum_pg_depend_classid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(classId));


	ScanKeyInit(&key[1], Anum_pg_depend_objid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(objectId));



	scan = systable_beginscan(depRel, DependDependerIndexId, true, NULL, 2, key);

	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		Form_pg_depend depform = (Form_pg_depend) GETSTRUCT(tup);

		if (depform->refclassid == refclassId && depform->deptype == deptype)
		{
			CatalogTupleDelete(depRel, &tup->t_self);
			count++;
		}
	}

	systable_endscan(scan);

	table_close(depRel, RowExclusiveLock);

	return count;
}


long changeDependencyFor(Oid classId, Oid objectId, Oid refClassId, Oid oldRefObjectId, Oid newRefObjectId)


{
	long		count = 0;
	Relation	depRel;
	ScanKeyData key[2];
	SysScanDesc scan;
	HeapTuple	tup;
	ObjectAddress objAddr;
	ObjectAddress depAddr;
	bool		oldIsPinned;
	bool		newIsPinned;

	depRel = table_open(DependRelationId, RowExclusiveLock);

	
	objAddr.classId = refClassId;
	objAddr.objectId = oldRefObjectId;
	objAddr.objectSubId = 0;

	oldIsPinned = isObjectPinned(&objAddr, depRel);

	objAddr.objectId = newRefObjectId;

	newIsPinned = isObjectPinned(&objAddr, depRel);

	if (oldIsPinned)
	{
		table_close(depRel, RowExclusiveLock);

		
		if (newIsPinned)
			return 1;

		
		depAddr.classId = classId;
		depAddr.objectId = objectId;
		depAddr.objectSubId = 0;
		recordDependencyOn(&depAddr, &objAddr, DEPENDENCY_NORMAL);

		return 1;
	}

	
	ScanKeyInit(&key[0], Anum_pg_depend_classid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(classId));


	ScanKeyInit(&key[1], Anum_pg_depend_objid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(objectId));



	scan = systable_beginscan(depRel, DependDependerIndexId, true, NULL, 2, key);

	while (HeapTupleIsValid((tup = systable_getnext(scan))))
	{
		Form_pg_depend depform = (Form_pg_depend) GETSTRUCT(tup);

		if (depform->refclassid == refClassId && depform->refobjid == oldRefObjectId)
		{
			if (newIsPinned)
				CatalogTupleDelete(depRel, &tup->t_self);
			else {
				
				tup = heap_copytuple(tup);
				depform = (Form_pg_depend) GETSTRUCT(tup);

				depform->refobjid = newRefObjectId;

				CatalogTupleUpdate(depRel, &tup->t_self, tup);

				heap_freetuple(tup);
			}

			count++;
		}
	}

	systable_endscan(scan);

	table_close(depRel, RowExclusiveLock);

	return count;
}


long changeDependenciesOf(Oid classId, Oid oldObjectId, Oid newObjectId)

{
	long		count = 0;
	Relation	depRel;
	ScanKeyData key[2];
	SysScanDesc scan;
	HeapTuple	tup;

	depRel = table_open(DependRelationId, RowExclusiveLock);

	ScanKeyInit(&key[0], Anum_pg_depend_classid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(classId));


	ScanKeyInit(&key[1], Anum_pg_depend_objid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(oldObjectId));



	scan = systable_beginscan(depRel, DependDependerIndexId, true, NULL, 2, key);

	while (HeapTupleIsValid((tup = systable_getnext(scan))))
	{
		Form_pg_depend depform = (Form_pg_depend) GETSTRUCT(tup);

		
		tup = heap_copytuple(tup);
		depform = (Form_pg_depend) GETSTRUCT(tup);

		depform->objid = newObjectId;

		CatalogTupleUpdate(depRel, &tup->t_self, tup);

		heap_freetuple(tup);

		count++;
	}

	systable_endscan(scan);

	table_close(depRel, RowExclusiveLock);

	return count;
}


long changeDependenciesOn(Oid refClassId, Oid oldRefObjectId, Oid newRefObjectId)

{
	long		count = 0;
	Relation	depRel;
	ScanKeyData key[2];
	SysScanDesc scan;
	HeapTuple	tup;
	ObjectAddress objAddr;
	bool		newIsPinned;

	depRel = table_open(DependRelationId, RowExclusiveLock);

	
	objAddr.classId = refClassId;
	objAddr.objectId = oldRefObjectId;
	objAddr.objectSubId = 0;

	if (isObjectPinned(&objAddr, depRel))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot remove dependency on %s because it is a system object", getObjectDescription(&objAddr))));



	
	objAddr.objectId = newRefObjectId;

	newIsPinned = isObjectPinned(&objAddr, depRel);

	
	ScanKeyInit(&key[0], Anum_pg_depend_refclassid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(refClassId));


	ScanKeyInit(&key[1], Anum_pg_depend_refobjid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(oldRefObjectId));



	scan = systable_beginscan(depRel, DependReferenceIndexId, true, NULL, 2, key);

	while (HeapTupleIsValid((tup = systable_getnext(scan))))
	{
		Form_pg_depend depform = (Form_pg_depend) GETSTRUCT(tup);

		if (newIsPinned)
			CatalogTupleDelete(depRel, &tup->t_self);
		else {
			
			tup = heap_copytuple(tup);
			depform = (Form_pg_depend) GETSTRUCT(tup);

			depform->refobjid = newRefObjectId;

			CatalogTupleUpdate(depRel, &tup->t_self, tup);

			heap_freetuple(tup);
		}

		count++;
	}

	systable_endscan(scan);

	table_close(depRel, RowExclusiveLock);

	return count;
}


static bool isObjectPinned(const ObjectAddress *object, Relation rel)
{
	bool		ret = false;
	SysScanDesc scan;
	HeapTuple	tup;
	ScanKeyData key[2];

	ScanKeyInit(&key[0], Anum_pg_depend_refclassid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(object->classId));



	ScanKeyInit(&key[1], Anum_pg_depend_refobjid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(object->objectId));



	scan = systable_beginscan(rel, DependReferenceIndexId, true, NULL, 2, key);

	
	tup = systable_getnext(scan);
	if (HeapTupleIsValid(tup))
	{
		Form_pg_depend foundDep = (Form_pg_depend) GETSTRUCT(tup);

		if (foundDep->deptype == DEPENDENCY_PIN)
			ret = true;
	}

	systable_endscan(scan);

	return ret;
}






Oid getExtensionOfObject(Oid classId, Oid objectId)
{
	Oid			result = InvalidOid;
	Relation	depRel;
	ScanKeyData key[2];
	SysScanDesc scan;
	HeapTuple	tup;

	depRel = table_open(DependRelationId, AccessShareLock);

	ScanKeyInit(&key[0], Anum_pg_depend_classid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(classId));


	ScanKeyInit(&key[1], Anum_pg_depend_objid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(objectId));



	scan = systable_beginscan(depRel, DependDependerIndexId, true, NULL, 2, key);

	while (HeapTupleIsValid((tup = systable_getnext(scan))))
	{
		Form_pg_depend depform = (Form_pg_depend) GETSTRUCT(tup);

		if (depform->refclassid == ExtensionRelationId && depform->deptype == DEPENDENCY_EXTENSION)
		{
			result = depform->refobjid;
			break;				
		}
	}

	systable_endscan(scan);

	table_close(depRel, AccessShareLock);

	return result;
}


bool sequenceIsOwned(Oid seqId, char deptype, Oid *tableId, int32 *colId)
{
	bool		ret = false;
	Relation	depRel;
	ScanKeyData key[2];
	SysScanDesc scan;
	HeapTuple	tup;

	depRel = table_open(DependRelationId, AccessShareLock);

	ScanKeyInit(&key[0], Anum_pg_depend_classid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationRelationId));


	ScanKeyInit(&key[1], Anum_pg_depend_objid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(seqId));



	scan = systable_beginscan(depRel, DependDependerIndexId, true, NULL, 2, key);

	while (HeapTupleIsValid((tup = systable_getnext(scan))))
	{
		Form_pg_depend depform = (Form_pg_depend) GETSTRUCT(tup);

		if (depform->refclassid == RelationRelationId && depform->deptype == deptype)
		{
			*tableId = depform->refobjid;
			*colId = depform->refobjsubid;
			ret = true;
			break;				
		}
	}

	systable_endscan(scan);

	table_close(depRel, AccessShareLock);

	return ret;
}


List * getOwnedSequences(Oid relid, AttrNumber attnum)
{
	List	   *result = NIL;
	Relation	depRel;
	ScanKeyData key[3];
	SysScanDesc scan;
	HeapTuple	tup;

	depRel = table_open(DependRelationId, AccessShareLock);

	ScanKeyInit(&key[0], Anum_pg_depend_refclassid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationRelationId));


	ScanKeyInit(&key[1], Anum_pg_depend_refobjid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(relid));


	if (attnum)
		ScanKeyInit(&key[2], Anum_pg_depend_refobjsubid, BTEqualStrategyNumber, F_INT4EQ, Int32GetDatum(attnum));



	scan = systable_beginscan(depRel, DependReferenceIndexId, true, NULL, attnum ? 3 : 2, key);

	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		Form_pg_depend deprec = (Form_pg_depend) GETSTRUCT(tup);

		
		if (deprec->classid == RelationRelationId && deprec->objsubid == 0 && deprec->refobjsubid != 0 && (deprec->deptype == DEPENDENCY_AUTO || deprec->deptype == DEPENDENCY_INTERNAL) && get_rel_relkind(deprec->objid) == RELKIND_SEQUENCE)



		{
			result = lappend_oid(result, deprec->objid);
		}
	}

	systable_endscan(scan);

	table_close(depRel, AccessShareLock);

	return result;
}


Oid getOwnedSequence(Oid relid, AttrNumber attnum)
{
	List	   *seqlist = getOwnedSequences(relid, attnum);

	if (list_length(seqlist) > 1)
		elog(ERROR, "more than one owned sequence found");
	else if (list_length(seqlist) < 1)
		elog(ERROR, "no owned sequence found");

	return linitial_oid(seqlist);
}


Oid get_constraint_index(Oid constraintId)
{
	Oid			indexId = InvalidOid;
	Relation	depRel;
	ScanKeyData key[3];
	SysScanDesc scan;
	HeapTuple	tup;

	
	depRel = table_open(DependRelationId, AccessShareLock);

	ScanKeyInit(&key[0], Anum_pg_depend_refclassid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(ConstraintRelationId));


	ScanKeyInit(&key[1], Anum_pg_depend_refobjid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(constraintId));


	ScanKeyInit(&key[2], Anum_pg_depend_refobjsubid, BTEqualStrategyNumber, F_INT4EQ, Int32GetDatum(0));



	scan = systable_beginscan(depRel, DependReferenceIndexId, true, NULL, 3, key);

	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		Form_pg_depend deprec = (Form_pg_depend) GETSTRUCT(tup);

		
		if (deprec->classid == RelationRelationId && deprec->objsubid == 0 && deprec->deptype == DEPENDENCY_INTERNAL)

		{
			char		relkind = get_rel_relkind(deprec->objid);

			
			if (relkind != RELKIND_INDEX && relkind != RELKIND_PARTITIONED_INDEX)
				continue;

			indexId = deprec->objid;
			break;
		}
	}

	systable_endscan(scan);
	table_close(depRel, AccessShareLock);

	return indexId;
}


Oid get_index_constraint(Oid indexId)
{
	Oid			constraintId = InvalidOid;
	Relation	depRel;
	ScanKeyData key[3];
	SysScanDesc scan;
	HeapTuple	tup;

	
	depRel = table_open(DependRelationId, AccessShareLock);

	ScanKeyInit(&key[0], Anum_pg_depend_classid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationRelationId));


	ScanKeyInit(&key[1], Anum_pg_depend_objid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(indexId));


	ScanKeyInit(&key[2], Anum_pg_depend_objsubid, BTEqualStrategyNumber, F_INT4EQ, Int32GetDatum(0));



	scan = systable_beginscan(depRel, DependDependerIndexId, true, NULL, 3, key);

	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		Form_pg_depend deprec = (Form_pg_depend) GETSTRUCT(tup);

		
		if (deprec->refclassid == ConstraintRelationId && deprec->refobjsubid == 0 && deprec->deptype == DEPENDENCY_INTERNAL)

		{
			constraintId = deprec->refobjid;
			break;
		}
	}

	systable_endscan(scan);
	table_close(depRel, AccessShareLock);

	return constraintId;
}


List * get_index_ref_constraints(Oid indexId)
{
	List	   *result = NIL;
	Relation	depRel;
	ScanKeyData key[3];
	SysScanDesc scan;
	HeapTuple	tup;

	
	depRel = table_open(DependRelationId, AccessShareLock);

	ScanKeyInit(&key[0], Anum_pg_depend_refclassid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(RelationRelationId));


	ScanKeyInit(&key[1], Anum_pg_depend_refobjid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(indexId));


	ScanKeyInit(&key[2], Anum_pg_depend_refobjsubid, BTEqualStrategyNumber, F_INT4EQ, Int32GetDatum(0));



	scan = systable_beginscan(depRel, DependReferenceIndexId, true, NULL, 3, key);

	while (HeapTupleIsValid(tup = systable_getnext(scan)))
	{
		Form_pg_depend deprec = (Form_pg_depend) GETSTRUCT(tup);

		
		if (deprec->classid == ConstraintRelationId && deprec->objsubid == 0 && deprec->deptype == DEPENDENCY_NORMAL)

		{
			result = lappend_oid(result, deprec->objid);
		}
	}

	systable_endscan(scan);
	table_close(depRel, AccessShareLock);

	return result;
}
