





















































typedef struct sequence_magic {
	uint32		magic;
} sequence_magic;

typedef struct SeqTableKey {
	Oid relid;						
	bool called_from_dispatcher;	
}

			pg_attribute_packed()

SeqTableKey;


typedef struct SeqTableData {
	SeqTableKey	key;			
	Oid			filenode;		
	LocalTransactionId lxid;	
	bool		last_valid;		
	int64		last;			
	int64		cached;			
	
	int64		increment;		
	
} SeqTableData;

typedef SeqTableData *SeqTable;

static HTAB *seqhashtab = NULL; 


static SeqTableData *last_used_seq = NULL;

static void fill_seq_with_data(Relation rel, HeapTuple tuple);
static Relation lock_and_open_sequence(SeqTable seq);
static void create_seq_hashtable(void);
static void init_sequence(Oid relid, SeqTable *p_elm, Relation *p_rel);
static void init_sequence_internal(Oid relid, SeqTable *p_elm, Relation *p_rel, bool called_from_dispatcher);
static Form_pg_sequence_data read_seq_tuple(Relation rel, Buffer *buf, HeapTuple seqdatatuple);
static void init_params(ParseState *pstate, List *options, bool for_identity, bool isInit, Form_pg_sequence seqform, Form_pg_sequence_data seqdataform, bool *need_seq_rewrite, List **owned_by);




static void do_setval(Oid relid, int64 next, bool iscalled);
static void process_owned_by(Relation seqrel, List *owned_by, bool for_identity);

static void cdb_sequence_nextval_qe(Relation seqrel, int64   *plast, int64   *pcached, int64   *pincrement, bool    *pvalid);






ObjectAddress DefineSequence(ParseState *pstate, CreateSeqStmt *seq)
{
	FormData_pg_sequence seqform;
	FormData_pg_sequence_data seqdataform;
	bool		need_seq_rewrite;
	List	   *owned_by;
	CreateStmt *stmt = makeNode(CreateStmt);
	Oid			seqoid;
	ObjectAddress address;
	Relation	rel;
	HeapTuple	tuple;
	TupleDesc	tupDesc;
	Datum		value[SEQ_COL_LASTCOL];
	bool		null[SEQ_COL_LASTCOL];
	Datum		pgs_values[Natts_pg_sequence];
	bool		pgs_nulls[Natts_pg_sequence];
	int			i;

	bool shouldDispatch =  Gp_role == GP_ROLE_DISPATCH && !IsBootstrapProcessingMode();

	
	if (seq->sequence->relpersistence == RELPERSISTENCE_UNLOGGED)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("unlogged sequences are not supported")));


	
	if (seq->if_not_exists)
	{
		RangeVarGetAndCheckCreationNamespace(seq->sequence, NoLock, &seqoid);
		if (OidIsValid(seqoid))
		{
			ereport(NOTICE, (errcode(ERRCODE_DUPLICATE_TABLE), errmsg("relation \"%s\" already exists, skipping", seq->sequence->relname)));


			return InvalidObjectAddress;
		}
	}

	
	init_params(pstate, seq->options, seq->for_identity, true, &seqform, &seqdataform, &need_seq_rewrite, &owned_by);


	
	stmt->tableElts = NIL;
	for (i = SEQ_COL_FIRSTCOL; i <= SEQ_COL_LASTCOL; i++)
	{
		ColumnDef  *coldef = makeNode(ColumnDef);

		coldef->inhcount = 0;
		coldef->is_local = true;
		coldef->is_not_null = true;
		coldef->is_from_type = false;
		coldef->storage = 0;
		coldef->raw_default = NULL;
		coldef->cooked_default = NULL;
		coldef->collClause = NULL;
		coldef->collOid = InvalidOid;
		coldef->constraints = NIL;
		coldef->location = -1;

		null[i - 1] = false;

		switch (i)
		{
			case SEQ_COL_LASTVAL:
				coldef->typeName = makeTypeNameFromOid(INT8OID, -1);
				coldef->colname = "last_value";
				value[i - 1] = Int64GetDatumFast(seqdataform.last_value);
				break;
			case SEQ_COL_LOG:
				coldef->typeName = makeTypeNameFromOid(INT8OID, -1);
				coldef->colname = "log_cnt";
				value[i - 1] = Int64GetDatum((int64) 0);
				break;
			case SEQ_COL_CALLED:
				coldef->typeName = makeTypeNameFromOid(BOOLOID, -1);
				coldef->colname = "is_called";
				value[i - 1] = BoolGetDatum(false);
				break;
		}
		stmt->tableElts = lappend(stmt->tableElts, coldef);
	}

	stmt->relation = seq->sequence;
	stmt->inhRelations = NIL;
	stmt->constraints = NIL;
	stmt->options = NIL;
	stmt->oncommit = ONCOMMIT_NOOP;
	stmt->tablespacename = NULL;
	stmt->if_not_exists = seq->if_not_exists;
	stmt->relKind = RELKIND_SEQUENCE;
	stmt->ownerid = GetUserId();

	address = DefineRelation(stmt, RELKIND_SEQUENCE, seq->ownerId, NULL, NULL, false, true, NULL);


	seqoid = address.objectId;
	Assert(seqoid != InvalidOid);

	rel = table_open(seqoid, AccessExclusiveLock);
	tupDesc = RelationGetDescr(rel);

	
	tuple = heap_form_tuple(tupDesc, value, null);
	fill_seq_with_data(rel, tuple);

	
	if (shouldDispatch)
	{
		CdbDispatchUtilityStatement((Node *) seq, DF_CANCEL_ON_ERROR| DF_WITH_SNAPSHOT| DF_NEED_TWO_PHASE, GetAssignedOidsForDispatch(), NULL);




	}

	
	if (owned_by)
		process_owned_by(rel, owned_by, seq->for_identity);

	table_close(rel, NoLock);

	
	rel = table_open(SequenceRelationId, RowExclusiveLock);
	tupDesc = RelationGetDescr(rel);

	memset(pgs_nulls, 0, sizeof(pgs_nulls));

	pgs_values[Anum_pg_sequence_seqrelid - 1] = ObjectIdGetDatum(seqoid);
	pgs_values[Anum_pg_sequence_seqtypid - 1] = ObjectIdGetDatum(seqform.seqtypid);
	pgs_values[Anum_pg_sequence_seqstart - 1] = Int64GetDatumFast(seqform.seqstart);
	pgs_values[Anum_pg_sequence_seqincrement - 1] = Int64GetDatumFast(seqform.seqincrement);
	pgs_values[Anum_pg_sequence_seqmax - 1] = Int64GetDatumFast(seqform.seqmax);
	pgs_values[Anum_pg_sequence_seqmin - 1] = Int64GetDatumFast(seqform.seqmin);
	pgs_values[Anum_pg_sequence_seqcache - 1] = Int64GetDatumFast(seqform.seqcache);
	pgs_values[Anum_pg_sequence_seqcycle - 1] = BoolGetDatum(seqform.seqcycle);

	tuple = heap_form_tuple(tupDesc, pgs_values, pgs_nulls);
	CatalogTupleInsert(rel, tuple);

	heap_freetuple(tuple);
	table_close(rel, RowExclusiveLock);

	return address;
}


void ResetSequence(Oid seq_relid)
{
	Relation	seq_rel;
	SeqTable	elm;
	Form_pg_sequence_data seq;
	Buffer		buf;
	HeapTupleData seqdatatuple;
	HeapTuple	tuple;
	HeapTuple	pgstuple;
	Form_pg_sequence pgsform;
	int64		startv;

	
	init_sequence(seq_relid, &elm, &seq_rel);
	(void) read_seq_tuple(seq_rel, &buf, &seqdatatuple);

	pgstuple = SearchSysCache1(SEQRELID, ObjectIdGetDatum(seq_relid));
	if (!HeapTupleIsValid(pgstuple))
		elog(ERROR, "cache lookup failed for sequence %u", seq_relid);
	pgsform = (Form_pg_sequence) GETSTRUCT(pgstuple);
	startv = pgsform->seqstart;
	ReleaseSysCache(pgstuple);

	
	tuple = heap_copytuple(&seqdatatuple);

	
	UnlockReleaseBuffer(buf);

	
	seq = (Form_pg_sequence_data) GETSTRUCT(tuple);
	seq->last_value = startv;
	seq->is_called = false;
	seq->log_cnt = 0;

	
	RelationSetNewRelfilenode(seq_rel, seq_rel->rd_rel->relpersistence);

	
	Assert(seq_rel->rd_rel->relfrozenxid == InvalidTransactionId);
	Assert(seq_rel->rd_rel->relminmxid == InvalidMultiXactId);

	
	fill_seq_with_data(seq_rel, tuple);

	
	
	elm->cached = elm->last;

	relation_close(seq_rel, NoLock);
}


static void fill_seq_with_data(Relation rel, HeapTuple tuple)
{
	Buffer		buf;
	Page		page;
	sequence_magic *sm;
	OffsetNumber offnum;

	

	buf = ReadBuffer(rel, P_NEW);
	Assert(BufferGetBlockNumber(buf) == 0);

	page = BufferGetPage(buf);

	LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);

	PageInit(page, BufferGetPageSize(buf), sizeof(sequence_magic));
	sm = (sequence_magic *) PageGetSpecialPointer(page);
	sm->magic = SEQ_MAGIC;

	

	
	HeapTupleHeaderSetXmin(tuple->t_data, FrozenTransactionId);
	HeapTupleHeaderSetXminFrozen(tuple->t_data);
	HeapTupleHeaderSetCmin(tuple->t_data, FirstCommandId);
	HeapTupleHeaderSetXmax(tuple->t_data, InvalidTransactionId);
	tuple->t_data->t_infomask |= HEAP_XMAX_INVALID;
	ItemPointerSet(&tuple->t_data->t_ctid, 0, FirstOffsetNumber);

	
	if (RelationNeedsWAL(rel))
		GetTopTransactionId();

	START_CRIT_SECTION();

	MarkBufferDirty(buf);

	offnum = PageAddItem(page, (Item) tuple->t_data, tuple->t_len, InvalidOffsetNumber, false, false);
	if (offnum != FirstOffsetNumber)
		elog(ERROR, "failed to add sequence tuple to page");

	
	if (RelationNeedsWAL(rel))
	{
		xl_seq_rec	xlrec;
		XLogRecPtr	recptr;

		XLogBeginInsert();
		XLogRegisterBuffer(0, buf, REGBUF_WILL_INIT);

		xlrec.node = rel->rd_node;

		XLogRegisterData((char *) &xlrec, sizeof(xl_seq_rec));
		XLogRegisterData((char *) tuple->t_data, tuple->t_len);

		recptr = XLogInsert(RM_SEQ_ID, XLOG_SEQ_LOG);

		PageSetLSN(page, recptr);
	}

	END_CRIT_SECTION();

	UnlockReleaseBuffer(buf);
}


ObjectAddress AlterSequence(ParseState *pstate, AlterSeqStmt *stmt)
{
	Oid			relid;
	SeqTable	elm;
	Relation	seqrel;
	Buffer		buf;
	HeapTupleData datatuple;
	Form_pg_sequence seqform;
	Form_pg_sequence_data newdataform;
	bool		need_seq_rewrite;
	List	   *owned_by;
	ObjectAddress address;
	bool        bSeqIsTemp = false;
	int			numopts;
	char	   *alter_subtype = "";		
	Relation	rel;
	HeapTuple	seqtuple;
	HeapTuple	newdatatuple;

	
	relid = RangeVarGetRelidExtended(stmt->sequence, ShareRowExclusiveLock, stmt->missing_ok ? RVR_MISSING_OK : 0, RangeVarCallbackOwnsRelation, NULL);



	if (relid == InvalidOid)
	{
		ereport(NOTICE, (errmsg("relation \"%s\" does not exist, skipping", stmt->sequence->relname)));

		return InvalidObjectAddress;
	}

	init_sequence(relid, &elm, &seqrel);

	rel = table_open(SequenceRelationId, RowExclusiveLock);
	seqtuple = SearchSysCacheCopy1(SEQRELID, ObjectIdGetDatum(relid));
	if (!HeapTupleIsValid(seqtuple))
		elog(ERROR, "cache lookup failed for sequence %u", relid);

	seqform = (Form_pg_sequence) GETSTRUCT(seqtuple);

	
	(void) read_seq_tuple(seqrel, &buf, &datatuple);

	
	newdatatuple = heap_copytuple(&datatuple);
	newdataform = (Form_pg_sequence_data) GETSTRUCT(newdatatuple);

	UnlockReleaseBuffer(buf);

	
	init_params(pstate, stmt->options, stmt->for_identity, false, seqform, newdataform, &need_seq_rewrite, &owned_by);


	
	
	elm->cached = elm->last;

	
	if (need_seq_rewrite)
	{
		
		if (RelationNeedsWAL(seqrel))
			GetTopTransactionId();

		
		RelationSetNewRelfilenode(seqrel, seqrel->rd_rel->relpersistence);

		
		Assert(seqrel->rd_rel->relfrozenxid == InvalidTransactionId);
		Assert(seqrel->rd_rel->relminmxid == InvalidMultiXactId);

		
		fill_seq_with_data(seqrel, newdatatuple);
	}

	
	if (owned_by)
		process_owned_by(seqrel, owned_by, stmt->for_identity);

	
	CatalogTupleUpdate(rel, &seqtuple->t_self, seqtuple);

	bSeqIsTemp = (seqrel->rd_rel->relpersistence == RELPERSISTENCE_TEMP);

	numopts = list_length(stmt->options);
	if (numopts > 1)
	{
		alter_subtype = psprintf("%d OPTIONS", numopts);
	}
	else if (0 == numopts)
	{
		alter_subtype = "0 OPTIONS";
	}
	else if (Gp_role == GP_ROLE_DISPATCH && !bSeqIsTemp)
	{
		ListCell		*option = list_head(stmt->options);
		DefElem			*defel	= (DefElem *) lfirst(option);
		char			*tempo	= NULL;

		alter_subtype = defel->defname;
		if (0 == strcmp(alter_subtype, "owned_by"))
			alter_subtype = "OWNED BY";

		tempo = asc_toupper(alter_subtype, strlen(alter_subtype));

		alter_subtype = tempo;
	}

	if (Gp_role == GP_ROLE_DISPATCH && !bSeqIsTemp)
	{
		
		MetaTrackUpdObject(RelationRelationId, relid, GetUserId(), "ALTER", alter_subtype);


	}

	if (Gp_role == GP_ROLE_DISPATCH)
		CdbDispatchUtilityStatement((Node *) stmt, DF_CANCEL_ON_ERROR| DF_WITH_SNAPSHOT| DF_NEED_TWO_PHASE, NIL, NULL);




	InvokeObjectPostAlterHook(RelationRelationId, relid, 0);

	ObjectAddressSet(address, RelationRelationId, relid);

	table_close(rel, RowExclusiveLock);
	relation_close(seqrel, NoLock);

	return address;
}

void DeleteSequenceTuple(Oid relid)
{
	Relation	rel;
	HeapTuple	tuple;

	rel = table_open(SequenceRelationId, RowExclusiveLock);

	tuple = SearchSysCache1(SEQRELID, ObjectIdGetDatum(relid));
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for sequence %u", relid);

	CatalogTupleDelete(rel, &tuple->t_self);

	ReleaseSysCache(tuple);
	table_close(rel, RowExclusiveLock);
}


Datum nextval(PG_FUNCTION_ARGS)
{
	text	   *seqin = PG_GETARG_TEXT_PP(0);
	RangeVar   *sequence;
	Oid			relid;

	sequence = makeRangeVarFromNameList(textToQualifiedNameList(seqin));

	
	relid = RangeVarGetRelid(sequence, NoLock, false);

	PG_RETURN_INT64(nextval_internal(relid, true, false));
}

Datum nextval_oid(PG_FUNCTION_ARGS)
{
	Oid			relid = PG_GETARG_OID(0);

	PG_RETURN_INT64(nextval_internal(relid, true, false));
}

void nextval_qd(Oid relid, int64 *plast, int64 *pcached, int64  *pincrement, bool *poverflow)
{
	Assert(IS_QUERY_DISPATCHER());

	*plast = nextval_internal(relid, false, true);
	*pcached = last_used_seq->cached;
	*pincrement = last_used_seq->increment;
	*poverflow = !last_used_seq->last_valid;
}

int64 nextval_internal(Oid relid, bool check_permissions, bool called_from_dispatcher)
{
	SeqTable	elm;
	Relation	seqrel;
	Buffer		buf;
	Page		page;
	HeapTuple	pgstuple;
	Form_pg_sequence pgsform;
	HeapTupleData seqdatatuple;
	Form_pg_sequence_data seq;
	int64		incby, maxv, minv, cache, log, fetch, last;





	int64		result, next, rescnt = 0;

	bool		cycle;
	bool		logit = false;

	
	init_sequence_internal(relid, &elm, &seqrel, called_from_dispatcher);

	if (check_permissions && pg_class_aclcheck(elm->key.relid, GetUserId(), ACL_USAGE | ACL_UPDATE) != ACLCHECK_OK)

		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied for sequence %s", RelationGetRelationName(seqrel))));



	
	if (!seqrel->rd_islocaltemp)
		PreventCommandIfReadOnly("nextval()");

	
	PreventCommandIfParallelMode("nextval()");

	if (elm->last != elm->cached	 && !called_from_dispatcher)
	{
		Assert(elm->last_valid);
		Assert(elm->increment != 0);
		elm->last += elm->increment;
		relation_close(seqrel, NoLock);
		last_used_seq = elm;
		return elm->last;
	}

	
	if (Gp_role == GP_ROLE_EXECUTE)
	{
		cdb_sequence_nextval_qe(seqrel, &elm->last, &elm->cached, &elm->increment, &elm->last_valid);




		last_used_seq = elm;
		relation_close(seqrel, NoLock);

		return elm->last;
	}
	pgstuple = SearchSysCache1(SEQRELID, ObjectIdGetDatum(relid));
	if (!HeapTupleIsValid(pgstuple))
		elog(ERROR, "cache lookup failed for sequence %u", relid);
	pgsform = (Form_pg_sequence) GETSTRUCT(pgstuple);
	incby = pgsform->seqincrement;
	maxv = pgsform->seqmax;
	minv = pgsform->seqmin;
	cache = pgsform->seqcache;
	cycle = pgsform->seqcycle;
	ReleaseSysCache(pgstuple);

	
	seq = read_seq_tuple(seqrel, &buf, &seqdatatuple);
	page = BufferGetPage(buf);

	elm->increment = incby;
	last = next = result = seq->last_value;
	fetch = cache;
	log = seq->log_cnt;

	if (!seq->is_called)
	{
		rescnt++;				
		fetch--;
	}

	
	if (log < fetch || !seq->is_called)
	{
		
		fetch = log = fetch + SEQ_LOG_VALS;
		logit = true;
	}
	else {
		XLogRecPtr	redoptr = GetRedoRecPtr();

		if (PageGetLSN(page) <= redoptr)
		{
			
			fetch = log = fetch + SEQ_LOG_VALS;
			logit = true;
		}
	}

	while (fetch)				
	{
		
		if (incby > 0)
		{
			
			if ((maxv >= 0 && next > maxv - incby) || (maxv < 0 && next + incby > maxv))
			{
				if (rescnt > 0)
					break;		
				if (!cycle)
				{
					char		buf[100];

					snprintf(buf, sizeof(buf), INT64_FORMAT, maxv);
					ereport(ERROR, (errcode(ERRCODE_SEQUENCE_GENERATOR_LIMIT_EXCEEDED), errmsg("nextval: reached maximum value of sequence \"%s\" (%s)", RelationGetRelationName(seqrel), buf)));


				}
				next = minv;
			}
			else next += incby;
		}
		else {
			
			if ((minv < 0 && next < minv - incby) || (minv >= 0 && next + incby < minv))
			{
				if (rescnt > 0)
					break;		
				if (!cycle)
				{
					char		buf[100];

					snprintf(buf, sizeof(buf), INT64_FORMAT, minv);
					ereport(ERROR, (errcode(ERRCODE_SEQUENCE_GENERATOR_LIMIT_EXCEEDED), errmsg("nextval: reached minimum value of sequence \"%s\" (%s)", RelationGetRelationName(seqrel), buf)));


				}
				next = maxv;
			}
			else next += incby;
		}
		fetch--;
		if (rescnt < cache)
		{
			log--;
			rescnt++;
			last = next;
			if (rescnt == 1)	
				result = next;	
		}
	}

	log -= fetch;				
	Assert(log >= 0);

	
	elm->last = result;			
	elm->cached = last;			
	elm->last_valid = true;
	elm->increment = incby;

	last_used_seq = elm;

	
	if (logit && RelationNeedsWAL(seqrel))
		GetTopTransactionId();

	
	START_CRIT_SECTION();

	
	MarkBufferDirty(buf);

	
	if (logit && RelationNeedsWAL(seqrel))
	{
		xl_seq_rec	xlrec;
		XLogRecPtr	recptr;

		
		XLogBeginInsert();
		XLogRegisterBuffer(0, buf, REGBUF_WILL_INIT);

		
		seq->last_value = next;
		seq->is_called = true;
		seq->log_cnt = 0;

		xlrec.node = seqrel->rd_node;

		XLogRegisterData((char *) &xlrec, sizeof(xl_seq_rec));
		XLogRegisterData((char *) seqdatatuple.t_data, seqdatatuple.t_len);

		recptr = XLogInsert(RM_SEQ_ID, XLOG_SEQ_LOG);

		PageSetLSN(page, recptr);
	}

	
	seq->last_value = last;		
	seq->is_called = true;
	seq->log_cnt = log;			

	END_CRIT_SECTION();

	UnlockReleaseBuffer(buf);

	relation_close(seqrel, NoLock);

	return result;
}

Datum currval_oid(PG_FUNCTION_ARGS)
{
	Oid			relid = PG_GETARG_OID(0);
	int64		result;
	SeqTable	elm;
	Relation	seqrel;

	
	if (Gp_role == GP_ROLE_DISPATCH || Gp_role == GP_ROLE_EXECUTE)
	{
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("currval() not supported")));

	}

	
	init_sequence(relid, &elm, &seqrel);

	if (pg_class_aclcheck(elm->key.relid, GetUserId(), ACL_SELECT | ACL_USAGE) != ACLCHECK_OK)
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied for sequence %s", RelationGetRelationName(seqrel))));



	if (!elm->last_valid)
		ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("currval of sequence \"%s\" is not yet defined in this session", RelationGetRelationName(seqrel))));



	result = elm->last;

	relation_close(seqrel, NoLock);

	PG_RETURN_INT64(result);
}

Datum lastval(PG_FUNCTION_ARGS)
{
	Relation	seqrel;
	int64		result;

	
	if (Gp_role == GP_ROLE_DISPATCH || Gp_role == GP_ROLE_EXECUTE)
	{
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("lastval() not supported")));

	}

	if (last_used_seq == NULL)
		ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("lastval is not yet defined in this session")));


	
	if (!SearchSysCacheExists1(RELOID, ObjectIdGetDatum(last_used_seq->key.relid)))
		ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("lastval is not yet defined in this session")));


	seqrel = lock_and_open_sequence(last_used_seq);

	
	Assert(last_used_seq->last_valid);

	if (pg_class_aclcheck(last_used_seq->key.relid, GetUserId(), ACL_SELECT | ACL_USAGE) != ACLCHECK_OK)
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied for sequence %s", RelationGetRelationName(seqrel))));



	result = last_used_seq->last;
	relation_close(seqrel, NoLock);

	PG_RETURN_INT64(result);
}


static void do_setval(Oid relid, int64 next, bool iscalled)
{
	SeqTable	elm;
	Relation	seqrel;
	Buffer		buf;
	HeapTupleData seqdatatuple;
	Form_pg_sequence_data seq;
	HeapTuple	pgstuple;
	Form_pg_sequence pgsform;
	int64		maxv, minv;

	if (Gp_role == GP_ROLE_EXECUTE)
	{
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("setval() not supported in this context")));

	}

	
	init_sequence(relid, &elm, &seqrel);

	if (pg_class_aclcheck(elm->key.relid, GetUserId(), ACL_UPDATE) != ACLCHECK_OK)
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied for sequence %s", RelationGetRelationName(seqrel))));



	pgstuple = SearchSysCache1(SEQRELID, ObjectIdGetDatum(relid));
	if (!HeapTupleIsValid(pgstuple))
		elog(ERROR, "cache lookup failed for sequence %u", relid);
	pgsform = (Form_pg_sequence) GETSTRUCT(pgstuple);
	maxv = pgsform->seqmax;
	minv = pgsform->seqmin;
	ReleaseSysCache(pgstuple);

	
	if (!seqrel->rd_islocaltemp)
		PreventCommandIfReadOnly("setval()");

	
	PreventCommandIfParallelMode("setval()");

	
	seq = read_seq_tuple(seqrel, &buf, &seqdatatuple);

	if ((next < minv) || (next > maxv))
	{
		char		bufv[100], bufm[100], bufx[100];


		snprintf(bufv, sizeof(bufv), INT64_FORMAT, next);
		snprintf(bufm, sizeof(bufm), INT64_FORMAT, minv);
		snprintf(bufx, sizeof(bufx), INT64_FORMAT, maxv);
		ereport(ERROR, (errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE), errmsg("setval: value %s is out of bounds for sequence \"%s\" (%s..%s)", bufv, RelationGetRelationName(seqrel), bufm, bufx)));



	}

	
	if (iscalled)
	{
		elm->last = next;		
		elm->last_valid = true;
	}

	
	elm->cached = elm->last;

	
	if (RelationNeedsWAL(seqrel))
		GetTopTransactionId();

	
	START_CRIT_SECTION();

	seq->last_value = next;		
	seq->is_called = iscalled;
	seq->log_cnt = 0;

	MarkBufferDirty(buf);

	
	if (RelationNeedsWAL(seqrel))
	{
		xl_seq_rec	xlrec;
		XLogRecPtr	recptr;
		Page		page = BufferGetPage(buf);

		XLogBeginInsert();
		XLogRegisterBuffer(0, buf, REGBUF_WILL_INIT);

		xlrec.node = seqrel->rd_node;
		XLogRegisterData((char *) &xlrec, sizeof(xl_seq_rec));
		XLogRegisterData((char *) seqdatatuple.t_data, seqdatatuple.t_len);

		recptr = XLogInsert(RM_SEQ_ID, XLOG_SEQ_LOG);

		PageSetLSN(page, recptr);
	}

	END_CRIT_SECTION();

	UnlockReleaseBuffer(buf);

	relation_close(seqrel, NoLock);
}


Datum setval_oid(PG_FUNCTION_ARGS)
{
	Oid			relid = PG_GETARG_OID(0);
	int64		next = PG_GETARG_INT64(1);

	do_setval(relid, next, true);

	PG_RETURN_INT64(next);
}


Datum setval3_oid(PG_FUNCTION_ARGS)
{
	Oid			relid = PG_GETARG_OID(0);
	int64		next = PG_GETARG_INT64(1);
	bool		iscalled = PG_GETARG_BOOL(2);

	do_setval(relid, next, iscalled);

	PG_RETURN_INT64(next);
}



static Relation lock_and_open_sequence(SeqTable seq)
{
	LocalTransactionId thislxid = MyProc->lxid;

	
	if (seq->lxid != thislxid)
	{
		ResourceOwner currentOwner;

		currentOwner = CurrentResourceOwner;
		CurrentResourceOwner = TopTransactionResourceOwner;

		LockRelationOid(seq->key.relid, RowExclusiveLock);

		CurrentResourceOwner = currentOwner;

		
		seq->lxid = thislxid;
	}

	
	return relation_open(seq->key.relid, NoLock);
}


static void create_seq_hashtable(void)
{
	HASHCTL		ctl;

	memset(&ctl, 0, sizeof(ctl));
	ctl.keysize = sizeof(struct SeqTableKey);
	ctl.entrysize = sizeof(SeqTableData);

	seqhashtab = hash_create("Sequence values", 16, &ctl, HASH_ELEM | HASH_BLOBS);
}


static void init_sequence(Oid relid, SeqTable *p_elm, Relation *p_rel)
{
	init_sequence_internal(relid, p_elm, p_rel, false);
}


static void init_sequence_internal(Oid _relid, SeqTable *p_elm, Relation *p_rel, bool called_from_dispatcher)

{
	SeqTable	elm;
	Relation	seqrel;
	bool		found;

	SeqTableKey relid;
	relid.relid = _relid;
	relid.called_from_dispatcher = called_from_dispatcher;

	
	if (seqhashtab == NULL)
		create_seq_hashtable();

	elm = (SeqTable) hash_search(seqhashtab, &relid, HASH_ENTER, &found);

	
	if (!found)
	{
		
		elm->filenode = InvalidOid;
		elm->lxid = InvalidLocalTransactionId;
		elm->last_valid = false;
		elm->last = elm->cached = 0;
	}

	
	seqrel = lock_and_open_sequence(elm);

	if (seqrel->rd_rel->relkind != RELKIND_SEQUENCE)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a sequence", RelationGetRelationName(seqrel))));



	
	if (seqrel->rd_rel->relfilenode != elm->filenode && called_from_dispatcher)
	{
		elm->filenode = seqrel->rd_rel->relfilenode;
		elm->cached = elm->last;
	}

	
	*p_elm = elm;
	*p_rel = seqrel;
}



static Form_pg_sequence_data read_seq_tuple(Relation rel, Buffer *buf, HeapTuple seqdatatuple)
{
	Page		page;
	ItemId		lp;
	sequence_magic *sm;
	Form_pg_sequence_data seq;

	*buf = ReadBuffer(rel, 0);
	LockBuffer(*buf, BUFFER_LOCK_EXCLUSIVE);

	page = BufferGetPage(*buf);
	sm = (sequence_magic *) PageGetSpecialPointer(page);

	if (sm->magic != SEQ_MAGIC)
		elog(ERROR, "bad magic number in sequence \"%s\": %08X", RelationGetRelationName(rel), sm->magic);

	lp = PageGetItemId(page, FirstOffsetNumber);
	Assert(ItemIdIsNormal(lp));

	
	seqdatatuple->t_data = (HeapTupleHeader) PageGetItem(page, lp);
	seqdatatuple->t_len = ItemIdGetLength(lp);

	
	Assert(!(seqdatatuple->t_data->t_infomask & HEAP_XMAX_IS_MULTI));
	if (HeapTupleHeaderGetRawXmax(seqdatatuple->t_data) != InvalidTransactionId)
	{
		HeapTupleHeaderSetXmax(seqdatatuple->t_data, InvalidTransactionId);
		seqdatatuple->t_data->t_infomask &= ~HEAP_XMAX_COMMITTED;
		seqdatatuple->t_data->t_infomask |= HEAP_XMAX_INVALID;
		MarkBufferDirtyHint(*buf, true);
	}

	seq = (Form_pg_sequence_data) GETSTRUCT(seqdatatuple);

	return seq;
}


static void init_params(ParseState *pstate, List *options, bool for_identity, bool isInit, Form_pg_sequence seqform, Form_pg_sequence_data seqdataform, bool *need_seq_rewrite, List **owned_by)





{
	DefElem    *as_type = NULL;
	DefElem    *start_value = NULL;
	DefElem    *restart_value = NULL;
	DefElem    *increment_by = NULL;
	DefElem    *max_value = NULL;
	DefElem    *min_value = NULL;
	DefElem    *cache_value = NULL;
	DefElem    *is_cycled = NULL;
	ListCell   *option;
	bool		reset_max_value = false;
	bool		reset_min_value = false;

	*need_seq_rewrite = false;
	*owned_by = NIL;

	foreach(option, options)
	{
		DefElem    *defel = (DefElem *) lfirst(option);

		if (strcmp(defel->defname, "as") == 0)
		{
			if (as_type)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options"), parser_errposition(pstate, defel->location)));


			as_type = defel;
			*need_seq_rewrite = true;
		}
		else if (strcmp(defel->defname, "increment") == 0)
		{
			if (increment_by)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options"), parser_errposition(pstate, defel->location)));


			increment_by = defel;
			*need_seq_rewrite = true;
		}
		else if (strcmp(defel->defname, "start") == 0)
		{
			if (start_value)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options"), parser_errposition(pstate, defel->location)));


			start_value = defel;
			*need_seq_rewrite = true;
		}
		else if (strcmp(defel->defname, "restart") == 0)
		{
			if (restart_value)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options"), parser_errposition(pstate, defel->location)));


			restart_value = defel;
			*need_seq_rewrite = true;
		}
		else if (strcmp(defel->defname, "maxvalue") == 0)
		{
			if (max_value)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options"), parser_errposition(pstate, defel->location)));


			max_value = defel;
			*need_seq_rewrite = true;
		}
		else if (strcmp(defel->defname, "minvalue") == 0)
		{
			if (min_value)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options"), parser_errposition(pstate, defel->location)));


			min_value = defel;
			*need_seq_rewrite = true;
		}
		else if (strcmp(defel->defname, "cache") == 0)
		{
			if (cache_value)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options"), parser_errposition(pstate, defel->location)));


			cache_value = defel;
			*need_seq_rewrite = true;
		}
		else if (strcmp(defel->defname, "cycle") == 0)
		{
			if (is_cycled)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options"), parser_errposition(pstate, defel->location)));


			is_cycled = defel;
			*need_seq_rewrite = true;
		}
		else if (strcmp(defel->defname, "owned_by") == 0)
		{
			if (*owned_by)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options"), parser_errposition(pstate, defel->location)));


			*owned_by = defGetQualifiedName(defel);
		}
		else if (strcmp(defel->defname, "sequence_name") == 0)
		{
			
			ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("invalid sequence option SEQUENCE NAME"), parser_errposition(pstate, defel->location)));


		}
		else elog(ERROR, "option \"%s\" not recognized", defel->defname);

	}

	
	if (isInit)
		seqdataform->log_cnt = 0;

	
	if (as_type != NULL)
	{
		Oid			newtypid = typenameTypeId(pstate, defGetTypeName(as_type));

		if (newtypid != INT2OID && newtypid != INT4OID && newtypid != INT8OID)

			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), for_identity ? errmsg("identity column type must be smallint, integer, or bigint")


					 : errmsg("sequence type must be smallint, integer, or bigint")));

		if (!isInit)
		{
			
			if ((seqform->seqtypid == INT2OID && seqform->seqmax == PG_INT16_MAX) || (seqform->seqtypid == INT4OID && seqform->seqmax == PG_INT32_MAX) || (seqform->seqtypid == INT8OID && seqform->seqmax == PG_INT64_MAX))

				reset_max_value = true;
			if ((seqform->seqtypid == INT2OID && seqform->seqmin == PG_INT16_MIN) || (seqform->seqtypid == INT4OID && seqform->seqmin == PG_INT32_MIN) || (seqform->seqtypid == INT8OID && seqform->seqmin == PG_INT64_MIN))

				reset_min_value = true;
		}

		seqform->seqtypid = newtypid;
	}
	else if (isInit)
	{
		seqform->seqtypid = INT8OID;
	}

	
	if (increment_by != NULL)
	{
		seqform->seqincrement = defGetInt64(increment_by);
		if (seqform->seqincrement == 0)
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("INCREMENT must not be zero")));

		seqdataform->log_cnt = 0;
	}
	else if (isInit)
	{
		seqform->seqincrement = 1;
	}

	
	if (is_cycled != NULL)
	{
		seqform->seqcycle = intVal(is_cycled->arg);
		Assert(BoolIsValid(seqform->seqcycle));
		seqdataform->log_cnt = 0;
	}
	else if (isInit)
	{
		seqform->seqcycle = false;
	}

	
	if (max_value != NULL && max_value->arg)
	{
		seqform->seqmax = defGetInt64(max_value);
		seqdataform->log_cnt = 0;
	}
	else if (isInit || max_value != NULL || reset_max_value)
	{
		if (seqform->seqincrement > 0 || reset_max_value)
		{
			
			if (seqform->seqtypid == INT2OID)
				seqform->seqmax = PG_INT16_MAX;
			else if (seqform->seqtypid == INT4OID)
				seqform->seqmax = PG_INT32_MAX;
			else seqform->seqmax = PG_INT64_MAX;
		}
		else seqform->seqmax = -1;
		seqdataform->log_cnt = 0;
	}

	if ((seqform->seqtypid == INT2OID && (seqform->seqmax < PG_INT16_MIN || seqform->seqmax > PG_INT16_MAX))
		|| (seqform->seqtypid == INT4OID && (seqform->seqmax < PG_INT32_MIN || seqform->seqmax > PG_INT32_MAX))
		|| (seqform->seqtypid == INT8OID && (seqform->seqmax < PG_INT64_MIN || seqform->seqmax > PG_INT64_MAX)))
	{
		char		bufx[100];

		snprintf(bufx, sizeof(bufx), INT64_FORMAT, seqform->seqmax);

		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("MAXVALUE (%s) is out of range for sequence data type %s", bufx, format_type_be(seqform->seqtypid))));


	}

	
	if (min_value != NULL && min_value->arg)
	{
		seqform->seqmin = defGetInt64(min_value);
		seqdataform->log_cnt = 0;
	}
	else if (isInit || min_value != NULL || reset_min_value)
	{
		if (seqform->seqincrement < 0 || reset_min_value)
		{
			
			if (seqform->seqtypid == INT2OID)
				seqform->seqmin = PG_INT16_MIN;
			else if (seqform->seqtypid == INT4OID)
				seqform->seqmin = PG_INT32_MIN;
			else seqform->seqmin = PG_INT64_MIN;
		}
		else seqform->seqmin = 1;
		seqdataform->log_cnt = 0;
	}

	if ((seqform->seqtypid == INT2OID && (seqform->seqmin < PG_INT16_MIN || seqform->seqmin > PG_INT16_MAX))
		|| (seqform->seqtypid == INT4OID && (seqform->seqmin < PG_INT32_MIN || seqform->seqmin > PG_INT32_MAX))
		|| (seqform->seqtypid == INT8OID && (seqform->seqmin < PG_INT64_MIN || seqform->seqmin > PG_INT64_MAX)))
	{
		char		bufm[100];

		snprintf(bufm, sizeof(bufm), INT64_FORMAT, seqform->seqmin);

		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("MINVALUE (%s) is out of range for sequence data type %s", bufm, format_type_be(seqform->seqtypid))));


	}

	
	if (seqform->seqmin >= seqform->seqmax)
	{
		char		bufm[100], bufx[100];

		snprintf(bufm, sizeof(bufm), INT64_FORMAT, seqform->seqmin);
		snprintf(bufx, sizeof(bufx), INT64_FORMAT, seqform->seqmax);
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("MINVALUE (%s) must be less than MAXVALUE (%s)", bufm, bufx)));


	}

	
	if (start_value != NULL)
	{
		seqform->seqstart = defGetInt64(start_value);
	}
	else if (isInit)
	{
		if (seqform->seqincrement > 0)
			seqform->seqstart = seqform->seqmin;	
		else seqform->seqstart = seqform->seqmax;
	}

	
	if (seqform->seqstart < seqform->seqmin)
	{
		char		bufs[100], bufm[100];

		snprintf(bufs, sizeof(bufs), INT64_FORMAT, seqform->seqstart);
		snprintf(bufm, sizeof(bufm), INT64_FORMAT, seqform->seqmin);
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("START value (%s) cannot be less than MINVALUE (%s)", bufs, bufm)));


	}
	if (seqform->seqstart > seqform->seqmax)
	{
		char		bufs[100], bufm[100];

		snprintf(bufs, sizeof(bufs), INT64_FORMAT, seqform->seqstart);
		snprintf(bufm, sizeof(bufm), INT64_FORMAT, seqform->seqmax);
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("START value (%s) cannot be greater than MAXVALUE (%s)", bufs, bufm)));


	}

	
	if (restart_value != NULL)
	{
		if (restart_value->arg != NULL)
			seqdataform->last_value = defGetInt64(restart_value);
		else seqdataform->last_value = seqform->seqstart;
		seqdataform->is_called = false;
		seqdataform->log_cnt = 0;
	}
	else if (isInit)
	{
		seqdataform->last_value = seqform->seqstart;
		seqdataform->is_called = false;
	}

	
	if (seqdataform->last_value < seqform->seqmin)
	{
		char		bufs[100], bufm[100];

		snprintf(bufs, sizeof(bufs), INT64_FORMAT, seqdataform->last_value);
		snprintf(bufm, sizeof(bufm), INT64_FORMAT, seqform->seqmin);
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("RESTART value (%s) cannot be less than MINVALUE (%s)", bufs, bufm)));


	}
	if (seqdataform->last_value > seqform->seqmax)
	{
		char		bufs[100], bufm[100];

		snprintf(bufs, sizeof(bufs), INT64_FORMAT, seqdataform->last_value);
		snprintf(bufm, sizeof(bufm), INT64_FORMAT, seqform->seqmax);
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("RESTART value (%s) cannot be greater than MAXVALUE (%s)", bufs, bufm)));


	}

	
	if (cache_value != NULL)
	{
		seqform->seqcache = defGetInt64(cache_value);
		if (seqform->seqcache <= 0)
		{
			char		buf[100];

			snprintf(buf, sizeof(buf), INT64_FORMAT, seqform->seqcache);
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("CACHE (%s) must be greater than zero", buf)));


		}
		seqdataform->log_cnt = 0;
	}
	else if (isInit)
	{
		
		seqform->seqcache = 20;
	}
}


static void process_owned_by(Relation seqrel, List *owned_by, bool for_identity)
{
	DependencyType deptype;
	int			nnames;
	Relation	tablerel;
	AttrNumber	attnum;

	deptype = for_identity ? DEPENDENCY_INTERNAL : DEPENDENCY_AUTO;

	nnames = list_length(owned_by);
	Assert(nnames > 0);
	if (nnames == 1)
	{
		
		if (strcmp(strVal(linitial(owned_by)), "none") != 0)
			ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("invalid OWNED BY option"), errhint("Specify OWNED BY table.column or OWNED BY NONE.")));


		tablerel = NULL;
		attnum = 0;
	}
	else {
		List	   *relname;
		char	   *attrname;
		RangeVar   *rel;

		
		relname = list_truncate(list_copy(owned_by), nnames - 1);
		attrname = strVal(lfirst(list_tail(owned_by)));

		
		rel = makeRangeVarFromNameList(relname);
		tablerel = relation_openrv(rel, AccessShareLock);

		
		if (!(tablerel->rd_rel->relkind == RELKIND_RELATION || tablerel->rd_rel->relkind == RELKIND_FOREIGN_TABLE || tablerel->rd_rel->relkind == RELKIND_VIEW || tablerel->rd_rel->relkind == RELKIND_PARTITIONED_TABLE))


			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("referenced relation \"%s\" is not a table or foreign table", RelationGetRelationName(tablerel))));



		
		if (seqrel->rd_rel->relowner != tablerel->rd_rel->relowner)
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("sequence must have same owner as table it is linked to")));

		if (RelationGetNamespace(seqrel) != RelationGetNamespace(tablerel))
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("sequence must be in same schema as table it is linked to")));


		
		attnum = get_attnum(RelationGetRelid(tablerel), attrname);
		if (attnum == InvalidAttrNumber)
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" of relation \"%s\" does not exist", attrname, RelationGetRelationName(tablerel))));


	}

	
	if (deptype == DEPENDENCY_AUTO)
	{
		Oid			tableId;
		int32		colId;

		if (sequenceIsOwned(RelationGetRelid(seqrel), DEPENDENCY_INTERNAL, &tableId, &colId))
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot change ownership of identity sequence"), errdetail("Sequence \"%s\" is linked to table \"%s\".", RelationGetRelationName(seqrel), get_rel_name(tableId))));




	}

	
	deleteDependencyRecordsForClass(RelationRelationId, RelationGetRelid(seqrel), RelationRelationId, deptype);

	if (tablerel)
	{
		ObjectAddress refobject, depobject;

		refobject.classId = RelationRelationId;
		refobject.objectId = RelationGetRelid(tablerel);
		refobject.objectSubId = attnum;
		depobject.classId = RelationRelationId;
		depobject.objectId = RelationGetRelid(seqrel);
		depobject.objectSubId = 0;
		recordDependencyOn(&depobject, &refobject, deptype);
	}

	
	if (tablerel)
		relation_close(tablerel, NoLock);
}



List * sequence_options(Oid relid)
{
	HeapTuple	pgstuple;
	Form_pg_sequence pgsform;
	List	   *options = NIL;

	pgstuple = SearchSysCache1(SEQRELID, relid);
	if (!HeapTupleIsValid(pgstuple))
		elog(ERROR, "cache lookup failed for sequence %u", relid);
	pgsform = (Form_pg_sequence) GETSTRUCT(pgstuple);

	
	options = lappend(options, makeDefElem("cache", (Node *) makeFloat(psprintf(INT64_FORMAT, pgsform->seqcache)), -1));
	options = lappend(options, makeDefElem("cycle", (Node *) makeInteger(pgsform->seqcycle), -1));
	options = lappend(options, makeDefElem("increment", (Node *) makeFloat(psprintf(INT64_FORMAT, pgsform->seqincrement)), -1));
	options = lappend(options, makeDefElem("maxvalue", (Node *) makeFloat(psprintf(INT64_FORMAT, pgsform->seqmax)), -1));
	options = lappend(options, makeDefElem("minvalue", (Node *) makeFloat(psprintf(INT64_FORMAT, pgsform->seqmin)), -1));
	options = lappend(options, makeDefElem("start", (Node *) makeFloat(psprintf(INT64_FORMAT, pgsform->seqstart)), -1));

	ReleaseSysCache(pgstuple);

	return options;
}


Datum pg_sequence_parameters(PG_FUNCTION_ARGS)
{
	Oid			relid = PG_GETARG_OID(0);
	TupleDesc	tupdesc;
	Datum		values[7];
	bool		isnull[7];
	HeapTuple	pgstuple;
	Form_pg_sequence pgsform;

	if (pg_class_aclcheck(relid, GetUserId(), ACL_SELECT | ACL_UPDATE | ACL_USAGE) != ACLCHECK_OK)
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied for sequence %s", get_rel_name(relid))));



	tupdesc = CreateTemplateTupleDesc(7);
	TupleDescInitEntry(tupdesc, (AttrNumber) 1, "start_value", INT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 2, "minimum_value", INT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 3, "maximum_value", INT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 4, "increment", INT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 5, "cycle_option", BOOLOID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 6, "cache_size", INT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 7, "data_type", OIDOID, -1, 0);

	BlessTupleDesc(tupdesc);

	memset(isnull, 0, sizeof(isnull));

	pgstuple = SearchSysCache1(SEQRELID, relid);
	if (!HeapTupleIsValid(pgstuple))
		elog(ERROR, "cache lookup failed for sequence %u", relid);
	pgsform = (Form_pg_sequence) GETSTRUCT(pgstuple);

	values[0] = Int64GetDatum(pgsform->seqstart);
	values[1] = Int64GetDatum(pgsform->seqmin);
	values[2] = Int64GetDatum(pgsform->seqmax);
	values[3] = Int64GetDatum(pgsform->seqincrement);
	values[4] = BoolGetDatum(pgsform->seqcycle);
	values[5] = Int64GetDatum(pgsform->seqcache);
	values[6] = ObjectIdGetDatum(pgsform->seqtypid);

	ReleaseSysCache(pgstuple);

	return HeapTupleGetDatum(heap_form_tuple(tupdesc, values, isnull));
}


Datum pg_sequence_last_value(PG_FUNCTION_ARGS)
{
	Oid			relid = PG_GETARG_OID(0);
	SeqTable	elm;
	Relation	seqrel;
	Buffer		buf;
	HeapTupleData seqtuple;
	Form_pg_sequence_data seq;
	bool		is_called;
	int64		result;

	
	init_sequence(relid, &elm, &seqrel);

	if (pg_class_aclcheck(relid, GetUserId(), ACL_SELECT | ACL_USAGE) != ACLCHECK_OK)
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied for sequence %s", RelationGetRelationName(seqrel))));



	seq = read_seq_tuple(seqrel, &buf, &seqtuple);

	is_called = seq->is_called;
	result = seq->last_value;

	UnlockReleaseBuffer(buf);
	relation_close(seqrel, NoLock);

	if (is_called)
		PG_RETURN_INT64(result);
	else PG_RETURN_NULL();
}


void seq_redo(XLogReaderState *record)
{
	XLogRecPtr	lsn = record->EndRecPtr;
	uint8		info = XLogRecGetInfo(record) & ~XLR_INFO_MASK;
	Buffer		buffer;
	Page		page;
	Page		localpage;
	char	   *item;
	Size		itemsz;
	xl_seq_rec *xlrec = (xl_seq_rec *) XLogRecGetData(record);
	sequence_magic *sm;

	if (info != XLOG_SEQ_LOG)
		elog(PANIC, "seq_redo: unknown op code %u", info);

	buffer = XLogInitBufferForRedo(record, 0);
	page = (Page) BufferGetPage(buffer);

	
	localpage = (Page) palloc(BufferGetPageSize(buffer));

	PageInit(localpage, BufferGetPageSize(buffer), sizeof(sequence_magic));
	sm = (sequence_magic *) PageGetSpecialPointer(localpage);
	sm->magic = SEQ_MAGIC;

	item = (char *) xlrec + sizeof(xl_seq_rec);
	itemsz = XLogRecGetDataLen(record) - sizeof(xl_seq_rec);

	if (PageAddItem(localpage, (Item) item, itemsz, FirstOffsetNumber, false, false) == InvalidOffsetNumber)
		elog(PANIC, "seq_redo: failed to add item to page");

	PageSetLSN(localpage, lsn);

	memcpy(page, localpage, BufferGetPageSize(buffer));
	MarkBufferDirty(buffer);
	UnlockReleaseBuffer(buffer);

	pfree(localpage);
}


void ResetSequenceCaches(void)
{
	if (seqhashtab)
	{
		hash_destroy(seqhashtab);
		seqhashtab = NULL;
	}

	last_used_seq = NULL;
}


void seq_mask(char *page, BlockNumber blkno)
{
	mask_page_lsn_and_checksum(page);

	mask_unused_space(page);
}


static void cdb_sequence_nextval_qe(Relation	seqrel, int64   *plast, int64   *pcached, int64   *pincrement, bool    *pvalid)




{
	Oid oid;
	int64 last;
	int64 cached;
	int64 increment;
	char overflow;
	char error;
	unsigned char	qtype;
	int retval;
	char *current;
	int *pint32;
	StringInfoData buf;
	Oid dbid = seqrel->rd_node.dbNode;
	Oid seq_oid = seqrel->rd_id;

	
	char payload[128];
	snprintf(payload, sizeof(payload), "%d:%d", dbid, seq_oid);
	NotifyMyFrontEnd("nextval", payload, gp_session_id);
	pq_flush();

	
	do {
		pq_startmsgread();
		retval = pq_getbyte_if_available(&qtype);
		if (retval == 0)
		{
			pq_endmsgread();
			CHECK_FOR_INTERRUPTS();
		}

		if (retval == EOF)
			ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR), errmsg("nextval: connection is gone unexpectedly")));

	} while (retval != 1);
	if (qtype == 'X')
		ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR), errmsg("nextval: QD closed the connection")));
	if (qtype != SEQ_NEXTVAL_QUERY_RESPONSE)
		ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR), errmsg("nextval: unexpected message type='%c'", qtype)));

	initStringInfo(&buf);
	if (pq_getmessage(&buf, 0) != 0)
		elog(ERROR, "nextval: unable to parse nextval response from QD");

	current = buf.data;

	oid = ntohl(*((int32 *) current));
	current += sizeof(int32);

	pint32 = (int32 *) &last;
	*pint32 = ntohl(*((int32 *) current + 1));
	pint32++;
	*pint32 = ntohl(*((int32 *) current));
	current += sizeof(int64);

	pint32 = (int32 *) &cached;
	*pint32 = ntohl(*((int32 *) current + 1));
	pint32++;
	*pint32 = ntohl(*((int32 *) current));
	current += sizeof(int64);

	pint32 = (int32 *) &increment;
	*pint32 = ntohl(*((int32 *) current + 1));
	pint32++;
	*pint32 = ntohl(*((int32 *) current));
	current += sizeof(int64);

	overflow = *current;
	current += sizeof(char);
	error = *current;

	if (overflow == SEQ_NEXTVAL_TRUE)
		ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("nextval: reached %s value of sequence \"%s\" (" INT64_FORMAT ")", increment>0 ? "maximum":"minimum", RelationGetRelationName(seqrel), last)));




	if (error == SEQ_NEXTVAL_TRUE)
		ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR), errmsg("nextval: QD encountered error")));


	Assert(overflow == SEQ_NEXTVAL_FALSE);
	Assert(error == SEQ_NEXTVAL_FALSE);

	if (oid != seq_oid)
		ereport(ERROR, (errcode(ERRCODE_INTERNAL_ERROR), errmsg("nextval: request oid:%d of QE doesn't match the response oid:%d from QD", seq_oid, oid)));



	*plast = last;
	*pcached = cached;
	*pincrement = increment;
	*pvalid = true;
}
