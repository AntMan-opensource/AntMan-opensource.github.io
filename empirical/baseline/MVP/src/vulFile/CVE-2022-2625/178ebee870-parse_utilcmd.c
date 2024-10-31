





























































typedef struct {
	ParseState *pstate;			
	const char *stmtType;		
	RangeVar   *relation;		
	Relation	rel;			
	List	   *inhRelations;	
	bool		isforeign;		
	bool		isalter;		
	List	   *columns;		
	List	   *ckconstraints;	
	List	   *fkconstraints;	
	List	   *ixconstraints;	
	List	   *attr_encodings; 
	List	   *inh_indexes;	
	List	   *extstats;		
	List	   *blist;			
	List	   *alist;			
	IndexStmt  *pkey;			
	bool		ispartitioned;	
	PartitionBoundSpec *partbound;	
	bool		ofType;			

	MemoryContext tempCtx;
} CreateStmtContext;


typedef struct {
	const char *stmtType;		
	char	   *schemaname;		
	RoleSpec   *authrole;		
	List	   *sequences;		
	List	   *tables;			
	List	   *views;			
	List	   *indexes;		
	List	   *triggers;		
	List	   *grants;			
} CreateSchemaStmtContext;


static void transformColumnDefinition(CreateStmtContext *cxt, ColumnDef *column);
static void transformTableConstraint(CreateStmtContext *cxt, Constraint *constraint);
static void transformTableLikeClause(CreateStmtContext *cxt, TableLikeClause *table_like_clause, bool forceBareCol, CreateStmt *stmt);

static void transformOfType(CreateStmtContext *cxt, TypeName *ofTypename);
static CreateStatsStmt *generateClonedExtStatsStmt(RangeVar *heapRel, Oid heapRelid, Oid source_statsid);
static List *get_collation(Oid collation, Oid actual_datatype);
static List *get_opclass(Oid opclass, Oid actual_datatype);
static void transformIndexConstraints(CreateStmtContext *cxt);
static IndexStmt *transformIndexConstraint(Constraint *constraint, CreateStmtContext *cxt);
static void transformExtendedStatistics(CreateStmtContext *cxt);
static void transformFKConstraints(CreateStmtContext *cxt, bool skipValidation, bool isAddConstraint);

static void transformCheckConstraints(CreateStmtContext *cxt, bool skipValidation);
static void transformConstraintAttrs(CreateStmtContext *cxt, List *constraintList);
static void transformColumnType(CreateStmtContext *cxt, ColumnDef *column);
static void setSchemaName(char *context_schema, char **stmt_schema_name);
static void transformPartitionCmd(CreateStmtContext *cxt, PartitionCmd *cmd);
static List *transformPartitionRangeBounds(ParseState *pstate, List *blist, Relation parent);
static void validateInfiniteBounds(ParseState *pstate, List *blist);

static DistributedBy *getLikeDistributionPolicy(TableLikeClause *e);
static DistributedBy *transformDistributedBy(ParseState *pstate, CreateStmtContext *cxt, DistributedBy *distributedBy, DistributedBy *likeDistributedBy, bool bQuiet);





List * transformCreateStmt(CreateStmt *stmt, const char *queryString)
{
	ParseState *pstate;
	CreateStmtContext cxt;
	List	   *result;
	List	   *save_alist;
	ListCell   *elements;
	Oid			namespaceid;
	Oid			existing_relid;
	ParseCallbackState pcbstate;
	bool		is_foreign_table = IsA(stmt, CreateForeignTableStmt);

	DistributedBy *likeDistributedBy = NULL;
	bool		bQuiet = false;		

 	
	cxt.tempCtx = AllocSetContextCreate(CurrentMemoryContext, "CreateStmt analyze context", ALLOCSET_DEFAULT_MINSIZE, ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE);





	
	stmt = copyObject(stmt);

	
	pstate = make_parsestate(NULL);
	pstate->p_sourcetext = queryString;

	
	setup_parser_errposition_callback(&pcbstate, pstate, stmt->relation->location);
	namespaceid = RangeVarGetAndCheckCreationNamespace(stmt->relation, NoLock, &existing_relid);

	cancel_parser_errposition_callback(&pcbstate);

	
	if (stmt->if_not_exists && OidIsValid(existing_relid))
	{
		ereport(NOTICE, (errcode(ERRCODE_DUPLICATE_TABLE), errmsg("relation \"%s\" already exists, skipping", stmt->relation->relname)));


		return NIL;
	}

	
	if (stmt->relation->schemaname == NULL && stmt->relation->relpersistence != RELPERSISTENCE_TEMP)
		stmt->relation->schemaname = get_namespace_name(namespaceid);

	
	cxt.pstate = pstate;
	if (IsA(stmt, CreateForeignTableStmt))
	{
		cxt.stmtType = "CREATE FOREIGN TABLE";
		cxt.isforeign = true;
	}
	else {
		cxt.stmtType = "CREATE TABLE";
		cxt.isforeign = false;
	}
	cxt.relation = stmt->relation;
	cxt.rel = NULL;
	cxt.inhRelations = stmt->inhRelations;
	cxt.isalter = false;
	cxt.columns = NIL;
	cxt.ckconstraints = NIL;
	cxt.fkconstraints = NIL;
	cxt.ixconstraints = NIL;
	cxt.inh_indexes = NIL;
	cxt.extstats = NIL;
	cxt.attr_encodings = stmt->attr_encodings;
	cxt.blist = NIL;
	cxt.alist = NIL;
	cxt.pkey = NULL;
	cxt.ispartitioned = stmt->partspec != NULL;
	cxt.partbound = stmt->partbound;
	cxt.ofType = (stmt->ofTypename != NULL);

	Assert(!stmt->ofTypename || !stmt->inhRelations);	

	if (stmt->ofTypename)
		transformOfType(&cxt, stmt->ofTypename);

	if (stmt->partspec)
	{
		if (stmt->inhRelations && !stmt->partbound)
			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("cannot create partitioned table as inheritance child")));

	}

	
	foreach(elements, stmt->tableElts)
	{
		Node	   *element = lfirst(elements);

		switch (nodeTag(element))
		{
			case T_ColumnDef:
				transformColumnDefinition(&cxt, (ColumnDef *) element);
				break;

			case T_Constraint:
				transformTableConstraint(&cxt, (Constraint *) element);
				break;

			case T_TableLikeClause:
			{
				bool            isBeginning = (cxt.columns == NIL);

				transformTableLikeClause(&cxt, (TableLikeClause *) element, false, stmt);

				if (Gp_role == GP_ROLE_DISPATCH && isBeginning && stmt->distributedBy == NULL && stmt->inhRelations == NIL)

				{
					likeDistributedBy = getLikeDistributionPolicy((TableLikeClause*) element);
				}
				break;
			}
			case T_ColumnReferenceStorageDirective:
				
				cxt.attr_encodings = lappend(cxt.attr_encodings, element);
				break;

			default:
				elog(ERROR, "unrecognized node type: %d", (int) nodeTag(element));
				break;
		}
	}

	
	save_alist = cxt.alist;
	cxt.alist = NIL;

	Assert(stmt->constraints == NIL);

	
	transformIndexConstraints(&cxt);

	
	transformFKConstraints(&cxt, true, false);

	
	if (stmt->relKind == RELKIND_RELATION)
	{
		stmt->distributedBy = transformDistributedBy(pstate, &cxt, stmt->distributedBy, likeDistributedBy, bQuiet);

	}

	if (IsA(stmt, CreateForeignTableStmt))
	{
		DistributedBy *ft_distributedBy = ((CreateForeignTableStmt *)stmt)->distributedBy;
		if (ft_distributedBy || likeDistributedBy)
			stmt->distributedBy = transformDistributedBy(pstate, &cxt, ft_distributedBy, likeDistributedBy, bQuiet);
	}

	
	transformCheckConstraints(&cxt, !is_foreign_table ? true : false);

	
	transformExtendedStatistics(&cxt);

	
	stmt->tableElts = cxt.columns;
	stmt->constraints = cxt.ckconstraints;
	stmt->attr_encodings = cxt.attr_encodings;

	result = lappend(cxt.blist, stmt);
	result = list_concat(result, cxt.alist);
	result = list_concat(result, save_alist);

	MemoryContextDelete(cxt.tempCtx);

	return result;
}


static void generateSerialExtraStmts(CreateStmtContext *cxt, ColumnDef *column, Oid seqtypid, List *seqoptions, bool for_identity, char **snamespace_p, char **sname_p)


{
	ListCell   *option;
	DefElem    *nameEl = NULL;
	Oid			snamespaceid;
	char	   *snamespace;
	char	   *sname;
	CreateSeqStmt *seqstmt;
	AlterSeqStmt *altseqstmt;
	List	   *attnamelist;
	bool		has_cache_option = false;

	
	foreach(option, seqoptions)
	{
		DefElem    *defel = lfirst_node(DefElem, option);

		if (strcmp(defel->defname, "sequence_name") == 0)
		{
			if (nameEl)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options")));

			nameEl = defel;
		}

		if (strcmp(defel->defname, "cache") == 0)
			has_cache_option = true;
	}

	if (nameEl)
	{
		RangeVar   *rv = makeRangeVarFromNameList(castNode(List, nameEl->arg));

		snamespace = rv->schemaname;
		if (!snamespace)
		{
			
			if (cxt->rel)
				snamespaceid = RelationGetNamespace(cxt->rel);
			else snamespaceid = RangeVarGetCreationNamespace(cxt->relation);
			snamespace = get_namespace_name(snamespaceid);
		}
		sname = rv->relname;
		
		seqoptions = list_delete_ptr(seqoptions, nameEl);
	}
	else {
		if (cxt->rel)
			snamespaceid = RelationGetNamespace(cxt->rel);
		else {
			snamespaceid = RangeVarGetCreationNamespace(cxt->relation);
			RangeVarAdjustRelationPersistence(cxt->relation, snamespaceid);
		}
		snamespace = get_namespace_name(snamespaceid);
		sname = ChooseRelationName(cxt->relation->relname, column->colname, "seq", snamespaceid, false);



	}

	ereport(DEBUG1, (errmsg("%s will create implicit sequence \"%s\" for serial column \"%s.%s\"", cxt->stmtType, sname, cxt->relation->relname, column->colname)));



	
	seqstmt = makeNode(CreateSeqStmt);
	seqstmt->for_identity = for_identity;
	seqstmt->sequence = makeRangeVar(snamespace, sname, -1);
	seqstmt->options = seqoptions;

	
	if (seqtypid)
		seqstmt->options = lcons(makeDefElem("as", (Node *) makeTypeNameFromOid(seqtypid, -1), -1), seqstmt->options);



	
	if (!has_cache_option)
		seqstmt->options = lappend(seqstmt->options, makeDefElem("cache", (Node *) makeInteger((long) 1), -1));

	
	if (cxt->rel)
		seqstmt->ownerId = cxt->rel->rd_rel->relowner;
	else seqstmt->ownerId = InvalidOid;

	cxt->blist = lappend(cxt->blist, seqstmt);

	
	column->identitySequence = seqstmt->sequence;

	
	altseqstmt = makeNode(AlterSeqStmt);
	altseqstmt->sequence = makeRangeVar(snamespace, sname, -1);
	attnamelist = list_make3(makeString(snamespace), makeString(cxt->relation->relname), makeString(column->colname));

	altseqstmt->options = list_make1(makeDefElem("owned_by", (Node *) attnamelist, -1));
	altseqstmt->for_identity = for_identity;

	cxt->alist = lappend(cxt->alist, altseqstmt);

	if (snamespace_p)
		*snamespace_p = snamespace;
	if (sname_p)
		*sname_p = sname;
}


static void transformColumnDefinition(CreateStmtContext *cxt, ColumnDef *column)
{
	bool		is_serial;
	bool		saw_nullable;
	bool		saw_default;
	bool		saw_identity;
	bool		saw_generated;
	ListCell   *clist;

	cxt->columns = lappend(cxt->columns, column);

	
	is_serial = false;
	if (column->typeName && list_length(column->typeName->names) == 1 && !column->typeName->pct_type)

	{
		char	   *typname = strVal(linitial(column->typeName->names));

		if (strcmp(typname, "smallserial") == 0 || strcmp(typname, "serial2") == 0)
		{
			is_serial = true;
			column->typeName->names = NIL;
			column->typeName->typeOid = INT2OID;
		}
		else if (strcmp(typname, "serial") == 0 || strcmp(typname, "serial4") == 0)
		{
			is_serial = true;
			column->typeName->names = NIL;
			column->typeName->typeOid = INT4OID;
		}
		else if (strcmp(typname, "bigserial") == 0 || strcmp(typname, "serial8") == 0)
		{
			is_serial = true;
			column->typeName->names = NIL;
			column->typeName->typeOid = INT8OID;
		}

		
		if (is_serial && column->typeName->arrayBounds != NIL)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("array of serial is not implemented"), parser_errposition(cxt->pstate, column->typeName->location)));



	}

	
	if (column->typeName)
		transformColumnType(cxt, column);

	
	if (is_serial)
	{
		char	   *snamespace;
		char	   *sname;
		char	   *qstring;
		A_Const    *snamenode;
		TypeCast   *castnode;
		FuncCall   *funccallnode;
		Constraint *constraint;

		generateSerialExtraStmts(cxt, column, column->typeName->typeOid, NIL, false, &snamespace, &sname);


		
		qstring = quote_qualified_identifier(snamespace, sname);
		snamenode = makeNode(A_Const);
		snamenode->val.type = T_String;
		snamenode->val.val.str = qstring;
		snamenode->location = -1;
		castnode = makeNode(TypeCast);
		castnode->typeName = SystemTypeName("regclass");
		castnode->arg = (Node *) snamenode;
		castnode->location = -1;
		funccallnode = makeFuncCall(SystemFuncName("nextval"), list_make1(castnode), -1);

		constraint = makeNode(Constraint);
		constraint->contype = CONSTR_DEFAULT;
		constraint->location = -1;
		constraint->raw_expr = (Node *) funccallnode;
		constraint->cooked_expr = NULL;
		column->constraints = lappend(column->constraints, constraint);

		constraint = makeNode(Constraint);
		constraint->contype = CONSTR_NOTNULL;
		constraint->location = -1;
		column->constraints = lappend(column->constraints, constraint);
	}

	
	transformConstraintAttrs(cxt, column->constraints);

	saw_nullable = false;
	saw_default = false;
	saw_identity = false;
	saw_generated = false;

	foreach(clist, column->constraints)
	{
		Constraint *constraint = lfirst_node(Constraint, clist);

		switch (constraint->contype)
		{
			case CONSTR_NULL:
				if (saw_nullable && column->is_not_null)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting NULL/NOT NULL declarations for column \"%s\" of table \"%s\"", column->colname, cxt->relation->relname), parser_errposition(cxt->pstate, constraint->location)));




				column->is_not_null = false;
				saw_nullable = true;
				break;

			case CONSTR_NOTNULL:
				if (saw_nullable && !column->is_not_null)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting NULL/NOT NULL declarations for column \"%s\" of table \"%s\"", column->colname, cxt->relation->relname), parser_errposition(cxt->pstate, constraint->location)));




				column->is_not_null = true;
				saw_nullable = true;
				break;

			case CONSTR_DEFAULT:
				if (saw_default)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("multiple default values specified for column \"%s\" of table \"%s\"", column->colname, cxt->relation->relname), parser_errposition(cxt->pstate, constraint->location)));




				column->raw_default = constraint->raw_expr;
				Assert(constraint->cooked_expr == NULL);
				saw_default = true;
				break;

			case CONSTR_IDENTITY:
				{
					Type		ctype;
					Oid			typeOid;

					if (cxt->ofType)
						ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("identity columns are not supported on typed tables")));

					if (cxt->partbound)
						ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("identity columns are not supported on partitions")));


					ctype = typenameType(cxt->pstate, column->typeName, NULL);
					typeOid = ((Form_pg_type) GETSTRUCT(ctype))->oid;
					ReleaseSysCache(ctype);

					if (saw_identity)
						ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("multiple identity specifications for column \"%s\" of table \"%s\"", column->colname, cxt->relation->relname), parser_errposition(cxt->pstate, constraint->location)));





					generateSerialExtraStmts(cxt, column, typeOid, constraint->options, true, NULL, NULL);


					column->identity = constraint->generated_when;
					saw_identity = true;
					column->is_not_null = true;
					break;
				}

			case CONSTR_GENERATED:
				if (cxt->ofType)
					ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("generated columns are not supported on typed tables")));

				if (cxt->partbound)
					ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("generated columns are not supported on partitions")));


				if (saw_generated)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("multiple generation clauses specified for column \"%s\" of table \"%s\"", column->colname, cxt->relation->relname), parser_errposition(cxt->pstate, constraint->location)));




				column->generated = ATTRIBUTE_GENERATED_STORED;
				column->raw_default = constraint->raw_expr;
				Assert(constraint->cooked_expr == NULL);
				saw_generated = true;
				break;

			case CONSTR_CHECK:
				cxt->ckconstraints = lappend(cxt->ckconstraints, constraint);
				break;

			case CONSTR_PRIMARY:
				if (cxt->isforeign)
					ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("primary key constraints are not supported on foreign tables"), parser_errposition(cxt->pstate, constraint->location)));



				

			case CONSTR_UNIQUE:
				if (cxt->isforeign)
					ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("unique constraints are not supported on foreign tables"), parser_errposition(cxt->pstate, constraint->location)));



				if (constraint->keys == NIL)
					constraint->keys = list_make1(makeString(column->colname));
				cxt->ixconstraints = lappend(cxt->ixconstraints, constraint);
				break;

			case CONSTR_EXCLUSION:
				
				elog(ERROR, "column exclusion constraints are not supported");
				break;

			case CONSTR_FOREIGN:
				if (cxt->isforeign)
					ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("foreign key constraints are not supported on foreign tables"), parser_errposition(cxt->pstate, constraint->location)));




				
				constraint->fk_attrs = list_make1(makeString(column->colname));
				cxt->fkconstraints = lappend(cxt->fkconstraints, constraint);
				break;

			case CONSTR_ATTR_DEFERRABLE:
			case CONSTR_ATTR_NOT_DEFERRABLE:
			case CONSTR_ATTR_DEFERRED:
			case CONSTR_ATTR_IMMEDIATE:
				
				break;

			default:
				elog(ERROR, "unrecognized constraint type: %d", constraint->contype);
				break;
		}

		if (saw_default && saw_identity)
			ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("both default and identity specified for column \"%s\" of table \"%s\"", column->colname, cxt->relation->relname), parser_errposition(cxt->pstate, constraint->location)));





		if (saw_default && saw_generated)
			ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("both default and generation expression specified for column \"%s\" of table \"%s\"", column->colname, cxt->relation->relname), parser_errposition(cxt->pstate, constraint->location)));





		if (saw_identity && saw_generated)
			ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("both identity and generation expression specified for column \"%s\" of table \"%s\"", column->colname, cxt->relation->relname), parser_errposition(cxt->pstate, constraint->location)));




	}

	
	if (column->fdwoptions != NIL)
	{
		AlterTableStmt *stmt;
		AlterTableCmd *cmd;

		cmd = makeNode(AlterTableCmd);
		cmd->subtype = AT_AlterColumnGenericOptions;
		cmd->name = column->colname;
		cmd->def = (Node *) column->fdwoptions;
		cmd->behavior = DROP_RESTRICT;
		cmd->missing_ok = false;

		stmt = makeNode(AlterTableStmt);
		stmt->relation = cxt->relation;
		stmt->cmds = NIL;
		stmt->relkind = OBJECT_FOREIGN_TABLE;
		stmt->cmds = lappend(stmt->cmds, cmd);

		cxt->alist = lappend(cxt->alist, stmt);
	}
}


static void transformTableConstraint(CreateStmtContext *cxt, Constraint *constraint)
{
	switch (constraint->contype)
	{
		case CONSTR_PRIMARY:
			if (cxt->isforeign)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("primary key constraints are not supported on foreign tables"), parser_errposition(cxt->pstate, constraint->location)));



			cxt->ixconstraints = lappend(cxt->ixconstraints, constraint);
			break;

		case CONSTR_UNIQUE:
			if (cxt->isforeign)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("unique constraints are not supported on foreign tables"), parser_errposition(cxt->pstate, constraint->location)));



			cxt->ixconstraints = lappend(cxt->ixconstraints, constraint);
			break;

		case CONSTR_EXCLUSION:
			if (cxt->isforeign)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("exclusion constraints are not supported on foreign tables"), parser_errposition(cxt->pstate, constraint->location)));



			if (cxt->ispartitioned)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("exclusion constraints are not supported on partitioned tables"), parser_errposition(cxt->pstate, constraint->location)));



			cxt->ixconstraints = lappend(cxt->ixconstraints, constraint);
			break;

		case CONSTR_CHECK:
			cxt->ckconstraints = lappend(cxt->ckconstraints, constraint);
			break;

		case CONSTR_FOREIGN:
			if (cxt->isforeign)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("foreign key constraints are not supported on foreign tables"), parser_errposition(cxt->pstate, constraint->location)));



			cxt->fkconstraints = lappend(cxt->fkconstraints, constraint);
			break;

		case CONSTR_NULL:
		case CONSTR_NOTNULL:
		case CONSTR_DEFAULT:
		case CONSTR_ATTR_DEFERRABLE:
		case CONSTR_ATTR_NOT_DEFERRABLE:
		case CONSTR_ATTR_DEFERRED:
		case CONSTR_ATTR_IMMEDIATE:
			elog(ERROR, "invalid context for constraint type %d", constraint->contype);
			break;

		default:
			elog(ERROR, "unrecognized constraint type: %d", constraint->contype);
			break;
	}
}


static void transformTableLikeClause(CreateStmtContext *cxt, TableLikeClause *table_like_clause, bool forceBareCol, CreateStmt *stmt)

{
	AttrNumber	parent_attno;
	Relation	relation;
	TupleDesc	tupleDesc;
	TupleConstr *constr;
	AttrNumber *attmap;
	AclResult	aclresult;
	char	   *comment;
	ParseCallbackState pcbstate;

	setup_parser_errposition_callback(&pcbstate, cxt->pstate, table_like_clause->relation->location);

	
	if (forceBareCol && table_like_clause->options != 0)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("LIKE INCLUDING may not be used with this kind of relation")));


	
	if (cxt->isforeign)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("LIKE is not supported for creating foreign tables")));


	relation = relation_openrv(table_like_clause->relation, AccessShareLock);

	if (relation->rd_rel->relkind != RELKIND_RELATION && relation->rd_rel->relkind != RELKIND_VIEW && relation->rd_rel->relkind != RELKIND_MATVIEW && relation->rd_rel->relkind != RELKIND_COMPOSITE_TYPE && relation->rd_rel->relkind != RELKIND_FOREIGN_TABLE && relation->rd_rel->relkind != RELKIND_PARTITIONED_TABLE)




		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a table, view, materialized view, composite type, or foreign table", RelationGetRelationName(relation))));



	cancel_parser_errposition_callback(&pcbstate);

	
	if (relation->rd_rel->relkind == RELKIND_COMPOSITE_TYPE)
	{
		aclresult = pg_type_aclcheck(relation->rd_rel->reltype, GetUserId(), ACL_USAGE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, OBJECT_TYPE, RelationGetRelationName(relation));
	}
	else {
		aclresult = pg_class_aclcheck(RelationGetRelid(relation), GetUserId(), ACL_SELECT);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, get_relkind_objtype(relation->rd_rel->relkind), RelationGetRelationName(relation));
	}

	tupleDesc = RelationGetDescr(relation);
	constr = tupleDesc->constr;

	
	attmap = (AttrNumber *) palloc0(sizeof(AttrNumber) * tupleDesc->natts);

	
	for (parent_attno = 1; parent_attno <= tupleDesc->natts;
		 parent_attno++)
	{
		Form_pg_attribute attribute = TupleDescAttr(tupleDesc, parent_attno - 1);
		char	   *attributeName = NameStr(attribute->attname);
		ColumnDef  *def;

		
		if (attribute->attisdropped)
			continue;

		
		def = makeNode(ColumnDef);
		def->colname = pstrdup(attributeName);
		def->typeName = makeTypeNameFromOid(attribute->atttypid, attribute->atttypmod);
		def->inhcount = 0;
		def->is_local = true;
		def->is_not_null = (forceBareCol ? false : attribute->attnotnull);
		def->is_from_type = false;
		def->storage = 0;
		def->raw_default = NULL;
		def->cooked_default = NULL;
		def->collClause = NULL;
		def->collOid = attribute->attcollation;
		def->constraints = NIL;
		def->location = -1;

		
		cxt->columns = lappend(cxt->columns, def);

		attmap[parent_attno - 1] = list_length(cxt->columns);

		
		if (attribute->atthasdef && (table_like_clause->options & CREATE_TABLE_LIKE_DEFAULTS || table_like_clause->options & CREATE_TABLE_LIKE_GENERATED))

		{
			Node	   *this_default = NULL;
			AttrDefault *attrdef;
			int			i;
			bool		found_whole_row;

			
			Assert(constr != NULL);
			attrdef = constr->defval;
			for (i = 0; i < constr->num_defval; i++)
			{
				if (attrdef[i].adnum == parent_attno)
				{
					this_default = stringToNode(attrdef[i].adbin);
					break;
				}
			}
			Assert(this_default != NULL);

			def->cooked_default = map_variable_attnos(this_default, 1, 0, attmap, tupleDesc->natts, InvalidOid, &found_whole_row);



			
			if (found_whole_row)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot convert whole-row table reference"), errdetail("Generation expression for column \"%s\" contains a whole-row reference to table \"%s\".", attributeName, RelationGetRelationName(relation))));





			if (attribute->attgenerated && (table_like_clause->options & CREATE_TABLE_LIKE_GENERATED))
				def->generated = attribute->attgenerated;
		}

		
		if (attribute->attidentity && (table_like_clause->options & CREATE_TABLE_LIKE_IDENTITY))
		{
			Oid			seq_relid;
			List	   *seq_options;

			
			seq_relid = getOwnedSequence(RelationGetRelid(relation), attribute->attnum);
			seq_options = sequence_options(seq_relid);
			generateSerialExtraStmts(cxt, def, InvalidOid, seq_options, true, NULL, NULL);

			def->identity = attribute->attidentity;
		}

		
		if (table_like_clause->options & CREATE_TABLE_LIKE_STORAGE)
			def->storage = attribute->attstorage;
		else def->storage = 0;

		
		if ((table_like_clause->options & CREATE_TABLE_LIKE_COMMENTS) && (comment = GetComment(attribute->attrelid, RelationRelationId, attribute->attnum)) != NULL)


		{
			CommentStmt *stmt = makeNode(CommentStmt);

			stmt->objtype = OBJECT_COLUMN;
			stmt->object = (Node *) list_make3(makeString(cxt->relation->schemaname), makeString(cxt->relation->relname), makeString(def->colname));

			stmt->comment = comment;

			cxt->alist = lappend(cxt->alist, stmt);
		}
	}

	
	if ((table_like_clause->options & CREATE_TABLE_LIKE_CONSTRAINTS) && tupleDesc->constr)
	{
		int			ccnum;

		for (ccnum = 0; ccnum < tupleDesc->constr->num_check; ccnum++)
		{
			char	   *ccname = tupleDesc->constr->check[ccnum].ccname;
			char	   *ccbin = tupleDesc->constr->check[ccnum].ccbin;
			Constraint *n = makeNode(Constraint);
			Node	   *ccbin_node;
			bool		found_whole_row;

			ccbin_node = map_variable_attnos(stringToNode(ccbin), 1, 0, attmap, tupleDesc->natts, InvalidOid, &found_whole_row);



			
			if (found_whole_row)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot convert whole-row table reference"), errdetail("Constraint \"%s\" contains a whole-row reference to table \"%s\".", ccname, RelationGetRelationName(relation))));





			n->contype = CONSTR_CHECK;
			n->location = -1;
			n->conname = pstrdup(ccname);
			n->raw_expr = NULL;
			n->cooked_expr = nodeToString(ccbin_node);
			cxt->ckconstraints = lappend(cxt->ckconstraints, n);

			
			if ((table_like_clause->options & CREATE_TABLE_LIKE_COMMENTS) && (comment = GetComment(get_relation_constraint_oid(RelationGetRelid(relation), n->conname, false), ConstraintRelationId, 0)) != NULL)



			{
				CommentStmt *stmt = makeNode(CommentStmt);

				stmt->objtype = OBJECT_TABCONSTRAINT;
				stmt->object = (Node *) list_make3(makeString(cxt->relation->schemaname), makeString(cxt->relation->relname), makeString(n->conname));

				stmt->comment = comment;

				cxt->alist = lappend(cxt->alist, stmt);
			}
		}
	}

	
	if ((table_like_clause->options & CREATE_TABLE_LIKE_INDEXES) && relation->rd_rel->relhasindex)
	{
		List	   *parent_indexes;
		ListCell   *l;

		parent_indexes = RelationGetIndexList(relation);

		foreach(l, parent_indexes)
		{
			Oid			parent_index_oid = lfirst_oid(l);
			Relation	parent_index;
			IndexStmt  *index_stmt;

			parent_index = index_open(parent_index_oid, AccessShareLock);

			
			index_stmt = generateClonedIndexStmt(cxt->relation, parent_index, attmap, tupleDesc->natts, NULL);



			
			if (table_like_clause->options & CREATE_TABLE_LIKE_COMMENTS)
			{
				comment = GetComment(parent_index_oid, RelationRelationId, 0);

				
				index_stmt->idxcomment = comment;
			}

			
			cxt->inh_indexes = lappend(cxt->inh_indexes, index_stmt);

			index_close(parent_index, AccessShareLock);
		}
	}

	
	
	if (stmt && table_like_clause->options & CREATE_TABLE_LIKE_STORAGE)
	{
		MemoryContext oldcontext;
		
		oldcontext = MemoryContextSwitchTo(CurTransactionContext);

		if (RelationIsAppendOptimized(relation))
		{
			int32 blocksize;
			int32 safefswritersize;
			int16 compresslevel;
			bool  checksum;
			NameData compresstype;

			GetAppendOnlyEntryAttributes(relation->rd_id, &blocksize, &safefswritersize,&compresslevel, &checksum,&compresstype);


			stmt->accessMethod = get_am_name(relation->rd_rel->relam);

			stmt->options = lappend(stmt->options, makeDefElem("blocksize", (Node *) makeInteger(blocksize), -1));
			stmt->options = lappend(stmt->options, makeDefElem("checksum", (Node *) makeInteger(checksum), -1));
			stmt->options = lappend(stmt->options, makeDefElem("compresslevel", (Node *) makeInteger(compresslevel), -1));
			if (strlen(NameStr(compresstype)) > 0)
				stmt->options = lappend(stmt->options, makeDefElem("compresstype", (Node *) makeString(pstrdup(NameStr(compresstype))), -1));
		}

		
		cxt->attr_encodings = list_union(cxt->attr_encodings, rel_get_column_encodings(relation));
		MemoryContextSwitchTo(oldcontext);
	}

	
	if (table_like_clause->options & CREATE_TABLE_LIKE_STATISTICS)
	{
		List	   *parent_extstats;
		ListCell   *l;

		parent_extstats = RelationGetStatExtList(relation);

		foreach(l, parent_extstats)
		{
			Oid			parent_stat_oid = lfirst_oid(l);
			CreateStatsStmt *stats_stmt;

			stats_stmt = generateClonedExtStatsStmt(cxt->relation, RelationGetRelid(relation), parent_stat_oid);


			
			if (table_like_clause->options & CREATE_TABLE_LIKE_COMMENTS)
			{
				comment = GetComment(parent_stat_oid, StatisticExtRelationId, 0);

				
				stats_stmt->stxcomment = comment;
			}

			cxt->extstats = lappend(cxt->extstats, stats_stmt);
		}

		list_free(parent_extstats);
	}

	
	table_close(relation, NoLock);
}

static void transformOfType(CreateStmtContext *cxt, TypeName *ofTypename)
{
	HeapTuple	tuple;
	TupleDesc	tupdesc;
	int			i;
	Oid			ofTypeId;

	AssertArg(ofTypename);

	tuple = typenameType(NULL, ofTypename, NULL);
	check_of_type(tuple);
	ofTypeId = ((Form_pg_type) GETSTRUCT(tuple))->oid;
	ofTypename->typeOid = ofTypeId; 

	tupdesc = lookup_rowtype_tupdesc(ofTypeId, -1);
	for (i = 0; i < tupdesc->natts; i++)
	{
		Form_pg_attribute attr = TupleDescAttr(tupdesc, i);
		ColumnDef  *n;

		if (attr->attisdropped)
			continue;

		n = makeNode(ColumnDef);
		n->colname = pstrdup(NameStr(attr->attname));
		n->typeName = makeTypeNameFromOid(attr->atttypid, attr->atttypmod);
		n->inhcount = 0;
		n->is_local = true;
		n->is_not_null = false;
		n->is_from_type = true;
		n->storage = 0;
		n->raw_default = NULL;
		n->cooked_default = NULL;
		n->collClause = NULL;
		n->collOid = attr->attcollation;
		n->constraints = NIL;
		n->location = -1;
		cxt->columns = lappend(cxt->columns, n);
	}
	DecrTupleDescRefCount(tupdesc);

	ReleaseSysCache(tuple);
}


IndexStmt * generateClonedIndexStmt(RangeVar *heapRel, Relation source_idx, const AttrNumber *attmap, int attmap_length, Oid *constraintOid)


{
	Oid			source_relid = RelationGetRelid(source_idx);
	HeapTuple	ht_idxrel;
	HeapTuple	ht_idx;
	HeapTuple	ht_am;
	Form_pg_class idxrelrec;
	Form_pg_index idxrec;
	Form_pg_am	amrec;
	oidvector  *indcollation;
	oidvector  *indclass;
	IndexStmt  *index;
	List	   *indexprs;
	ListCell   *indexpr_item;
	Oid			indrelid;
	Oid			constraintId = InvalidOid;
	int			keyno;
	Oid			keycoltype;
	Datum		datum;
	bool		isnull;

	if (constraintOid)
		*constraintOid = InvalidOid;

	
	ht_idxrel = SearchSysCache1(RELOID, ObjectIdGetDatum(source_relid));
	if (!HeapTupleIsValid(ht_idxrel))
		elog(ERROR, "cache lookup failed for relation %u", source_relid);
	idxrelrec = (Form_pg_class) GETSTRUCT(ht_idxrel);

	
	ht_idx = source_idx->rd_indextuple;
	idxrec = (Form_pg_index) GETSTRUCT(ht_idx);
	indrelid = idxrec->indrelid;

	
	ht_am = SearchSysCache1(AMOID, ObjectIdGetDatum(idxrelrec->relam));
	if (!HeapTupleIsValid(ht_am))
		elog(ERROR, "cache lookup failed for access method %u", idxrelrec->relam);
	amrec = (Form_pg_am) GETSTRUCT(ht_am);

	
	datum = SysCacheGetAttr(INDEXRELID, ht_idx, Anum_pg_index_indcollation, &isnull);
	Assert(!isnull);
	indcollation = (oidvector *) DatumGetPointer(datum);

	
	datum = SysCacheGetAttr(INDEXRELID, ht_idx, Anum_pg_index_indclass, &isnull);
	Assert(!isnull);
	indclass = (oidvector *) DatumGetPointer(datum);

	
	index = makeNode(IndexStmt);
	index->relation = heapRel;
	index->accessMethod = pstrdup(NameStr(amrec->amname));
	if (OidIsValid(idxrelrec->reltablespace))
		index->tableSpace = get_tablespace_name(idxrelrec->reltablespace);
	else index->tableSpace = NULL;
	index->excludeOpNames = NIL;
	index->idxcomment = NULL;
	index->indexOid = InvalidOid;
	index->oldNode = InvalidOid;
	index->unique = idxrec->indisunique;
	index->primary = idxrec->indisprimary;
	index->transformed = true;	
	index->concurrent = false;
	index->if_not_exists = false;
	index->reset_default_tblspc = false;

	
	index->idxname = NULL;

	
	if (index->primary || index->unique || idxrec->indisexclusion)
	{
		constraintId = get_index_constraint(source_relid);

		if (OidIsValid(constraintId))
		{
			HeapTuple	ht_constr;
			Form_pg_constraint conrec;

			if (constraintOid)
				*constraintOid = constraintId;

			ht_constr = SearchSysCache1(CONSTROID, ObjectIdGetDatum(constraintId));
			if (!HeapTupleIsValid(ht_constr))
				elog(ERROR, "cache lookup failed for constraint %u", constraintId);
			conrec = (Form_pg_constraint) GETSTRUCT(ht_constr);

			index->isconstraint = true;
			index->deferrable = conrec->condeferrable;
			index->initdeferred = conrec->condeferred;

			
			if (idxrec->indisexclusion)
			{
				Datum	   *elems;
				int			nElems;
				int			i;

				Assert(conrec->contype == CONSTRAINT_EXCLUSION);
				
				datum = SysCacheGetAttr(CONSTROID, ht_constr, Anum_pg_constraint_conexclop, &isnull);

				if (isnull)
					elog(ERROR, "null conexclop for constraint %u", constraintId);

				deconstruct_array(DatumGetArrayTypeP(datum), OIDOID, sizeof(Oid), true, 'i', &elems, NULL, &nElems);


				for (i = 0; i < nElems; i++)
				{
					Oid			operid = DatumGetObjectId(elems[i]);
					HeapTuple	opertup;
					Form_pg_operator operform;
					char	   *oprname;
					char	   *nspname;
					List	   *namelist;

					opertup = SearchSysCache1(OPEROID, ObjectIdGetDatum(operid));
					if (!HeapTupleIsValid(opertup))
						elog(ERROR, "cache lookup failed for operator %u", operid);
					operform = (Form_pg_operator) GETSTRUCT(opertup);
					oprname = pstrdup(NameStr(operform->oprname));
					
					nspname = get_namespace_name(operform->oprnamespace);
					namelist = list_make2(makeString(nspname), makeString(oprname));
					index->excludeOpNames = lappend(index->excludeOpNames, namelist);
					ReleaseSysCache(opertup);
				}
			}

			ReleaseSysCache(ht_constr);
		}
		else index->isconstraint = false;
	}
	else index->isconstraint = false;

	
	datum = SysCacheGetAttr(INDEXRELID, ht_idx, Anum_pg_index_indexprs, &isnull);
	if (!isnull)
	{
		char	   *exprsString;

		exprsString = TextDatumGetCString(datum);
		indexprs = (List *) stringToNode(exprsString);
	}
	else indexprs = NIL;

	
	index->indexParams = NIL;
	index->indexIncludingParams = NIL;

	indexpr_item = list_head(indexprs);
	for (keyno = 0; keyno < idxrec->indnkeyatts; keyno++)
	{
		IndexElem  *iparam;
		AttrNumber	attnum = idxrec->indkey.values[keyno];
		Form_pg_attribute attr = TupleDescAttr(RelationGetDescr(source_idx), keyno);
		int16		opt = source_idx->rd_indoption[keyno];

		iparam = makeNode(IndexElem);

		if (AttributeNumberIsValid(attnum))
		{
			
			char	   *attname;

			attname = get_attname(indrelid, attnum, false);
			keycoltype = get_atttype(indrelid, attnum);

			iparam->name = attname;
			iparam->expr = NULL;
		}
		else {
			
			Node	   *indexkey;
			bool		found_whole_row;

			if (indexpr_item == NULL)
				elog(ERROR, "too few entries in indexprs list");
			indexkey = (Node *) lfirst(indexpr_item);
			indexpr_item = lnext(indexpr_item);

			
			indexkey = map_variable_attnos(indexkey, 1, 0, attmap, attmap_length, InvalidOid, &found_whole_row);



			
			if (found_whole_row)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot convert whole-row table reference"), errdetail("Index \"%s\" contains a whole-row table reference.", RelationGetRelationName(source_idx))));




			iparam->name = NULL;
			iparam->expr = indexkey;

			keycoltype = exprType(indexkey);
		}

		
		iparam->indexcolname = pstrdup(NameStr(attr->attname));

		
		iparam->collation = get_collation(indcollation->values[keyno], keycoltype);

		
		iparam->opclass = get_opclass(indclass->values[keyno], keycoltype);

		iparam->ordering = SORTBY_DEFAULT;
		iparam->nulls_ordering = SORTBY_NULLS_DEFAULT;

		
		if (source_idx->rd_indam->amcanorder)
		{
			
			if (opt & INDOPTION_DESC)
			{
				iparam->ordering = SORTBY_DESC;
				if ((opt & INDOPTION_NULLS_FIRST) == 0)
					iparam->nulls_ordering = SORTBY_NULLS_LAST;
			}
			else {
				if (opt & INDOPTION_NULLS_FIRST)
					iparam->nulls_ordering = SORTBY_NULLS_FIRST;
			}
		}

		index->indexParams = lappend(index->indexParams, iparam);
	}

	
	for (keyno = idxrec->indnkeyatts; keyno < idxrec->indnatts; keyno++)
	{
		IndexElem  *iparam;
		AttrNumber	attnum = idxrec->indkey.values[keyno];
		Form_pg_attribute attr = TupleDescAttr(RelationGetDescr(source_idx), keyno);

		iparam = makeNode(IndexElem);

		if (AttributeNumberIsValid(attnum))
		{
			
			char	   *attname;

			attname = get_attname(indrelid, attnum, false);
			keycoltype = get_atttype(indrelid, attnum);

			iparam->name = attname;
			iparam->expr = NULL;
		}
		else ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("expressions are not supported in included columns")));



		
		iparam->indexcolname = pstrdup(NameStr(attr->attname));

		index->indexIncludingParams = lappend(index->indexIncludingParams, iparam);
	}
	
	datum = SysCacheGetAttr(RELOID, ht_idxrel, Anum_pg_class_reloptions, &isnull);
	if (!isnull)
		index->options = untransformRelOptions(datum);

	
	datum = SysCacheGetAttr(INDEXRELID, ht_idx, Anum_pg_index_indpred, &isnull);
	if (!isnull)
	{
		char	   *pred_str;
		Node	   *pred_tree;
		bool		found_whole_row;

		
		pred_str = TextDatumGetCString(datum);
		pred_tree = (Node *) stringToNode(pred_str);

		
		pred_tree = map_variable_attnos(pred_tree, 1, 0, attmap, attmap_length, InvalidOid, &found_whole_row);



		
		if (found_whole_row)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot convert whole-row table reference"), errdetail("Index \"%s\" contains a whole-row table reference.", RelationGetRelationName(source_idx))));




		index->whereClause = pred_tree;
	}

	
	ReleaseSysCache(ht_idxrel);
	ReleaseSysCache(ht_am);

	return index;
}


static CreateStatsStmt * generateClonedExtStatsStmt(RangeVar *heapRel, Oid heapRelid, Oid source_statsid)

{
	HeapTuple	ht_stats;
	Form_pg_statistic_ext statsrec;
	CreateStatsStmt *stats;
	List	   *stat_types = NIL;
	List	   *def_names = NIL;
	bool		isnull;
	Datum		datum;
	ArrayType  *arr;
	char	   *enabled;
	int			i;

	Assert(OidIsValid(heapRelid));
	Assert(heapRel != NULL);

	
	ht_stats = SearchSysCache1(STATEXTOID, ObjectIdGetDatum(source_statsid));
	if (!HeapTupleIsValid(ht_stats))
		elog(ERROR, "cache lookup failed for statistics object %u", source_statsid);
	statsrec = (Form_pg_statistic_ext) GETSTRUCT(ht_stats);

	
	datum = SysCacheGetAttr(STATEXTOID, ht_stats, Anum_pg_statistic_ext_stxkind, &isnull);
	Assert(!isnull);
	arr = DatumGetArrayTypeP(datum);
	if (ARR_NDIM(arr) != 1 || ARR_HASNULL(arr) || ARR_ELEMTYPE(arr) != CHAROID)

		elog(ERROR, "stxkind is not a 1-D char array");
	enabled = (char *) ARR_DATA_PTR(arr);
	for (i = 0; i < ARR_DIMS(arr)[0]; i++)
	{
		if (enabled[i] == STATS_EXT_NDISTINCT)
			stat_types = lappend(stat_types, makeString("ndistinct"));
		else if (enabled[i] == STATS_EXT_DEPENDENCIES)
			stat_types = lappend(stat_types, makeString("dependencies"));
		else if (enabled[i] == STATS_EXT_MCV)
			stat_types = lappend(stat_types, makeString("mcv"));
		else elog(ERROR, "unrecognized statistics kind %c", enabled[i]);
	}

	
	for (i = 0; i < statsrec->stxkeys.dim1; i++)
	{
		ColumnRef  *cref = makeNode(ColumnRef);
		AttrNumber	attnum = statsrec->stxkeys.values[i];

		cref->fields = list_make1(makeString(get_attname(heapRelid, attnum, false)));
		cref->location = -1;

		def_names = lappend(def_names, cref);
	}

	
	stats = makeNode(CreateStatsStmt);
	stats->defnames = NULL;
	stats->stat_types = stat_types;
	stats->exprs = def_names;
	stats->relations = list_make1(heapRel);
	stats->stxcomment = NULL;
	stats->if_not_exists = false;

	
	ReleaseSysCache(ht_stats);

	return stats;
}


static List * get_collation(Oid collation, Oid actual_datatype)
{
	List	   *result;
	HeapTuple	ht_coll;
	Form_pg_collation coll_rec;
	char	   *nsp_name;
	char	   *coll_name;

	if (!OidIsValid(collation))
		return NIL;				
	if (collation == get_typcollation(actual_datatype))
		return NIL;				

	ht_coll = SearchSysCache1(COLLOID, ObjectIdGetDatum(collation));
	if (!HeapTupleIsValid(ht_coll))
		elog(ERROR, "cache lookup failed for collation %u", collation);
	coll_rec = (Form_pg_collation) GETSTRUCT(ht_coll);

	
	nsp_name = get_namespace_name(coll_rec->collnamespace);
	coll_name = pstrdup(NameStr(coll_rec->collname));
	result = list_make2(makeString(nsp_name), makeString(coll_name));

	ReleaseSysCache(ht_coll);
	return result;
}


static List * get_opclass(Oid opclass, Oid actual_datatype)
{
	List	   *result = NIL;
	HeapTuple	ht_opc;
	Form_pg_opclass opc_rec;

	ht_opc = SearchSysCache1(CLAOID, ObjectIdGetDatum(opclass));
	if (!HeapTupleIsValid(ht_opc))
		elog(ERROR, "cache lookup failed for opclass %u", opclass);
	opc_rec = (Form_pg_opclass) GETSTRUCT(ht_opc);

	if (GetDefaultOpClass(actual_datatype, opc_rec->opcmethod) != opclass)
	{
		
		char	   *nsp_name = get_namespace_name(opc_rec->opcnamespace);
		char	   *opc_name = pstrdup(NameStr(opc_rec->opcname));

		result = list_make2(makeString(nsp_name), makeString(opc_name));
	}

	ReleaseSysCache(ht_opc);
	return result;
}

List * transformCreateExternalStmt(CreateExternalStmt *stmt, const char *queryString)
{
	ParseState *pstate;
	CreateStmtContext cxt;
	List	   *result;
	ListCell   *elements;
	DistributedBy *likeDistributedBy = NULL;
	bool	    bQuiet = false;	
	bool		iswritable = false;

	
	pstate = make_parsestate(NULL);
	pstate->p_sourcetext = queryString;

	memset(&cxt, 0, sizeof(CreateStmtContext));

	
	cxt.tempCtx = AllocSetContextCreate(CurrentMemoryContext, "CreateExteranlStmt analyze context", ALLOCSET_DEFAULT_MINSIZE, ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE);




	
	stmt = (CreateExternalStmt *)copyObject(stmt);

	cxt.pstate = pstate;
	cxt.stmtType = "CREATE EXTERNAL TABLE";
	cxt.relation = stmt->relation;
	cxt.inhRelations = NIL;
	cxt.isalter = false;
	cxt.columns = NIL;
	cxt.ckconstraints = NIL;
	cxt.fkconstraints = NIL;
	cxt.ixconstraints = NIL;
	cxt.attr_encodings = NIL;
	cxt.pkey = NULL;
	cxt.rel = NULL;

	cxt.blist = NIL;
	cxt.alist = NIL;

	iswritable = stmt->iswritable;

	
	foreach(elements, stmt->tableElts)
	{
		Node	   *element = lfirst(elements);

		switch (nodeTag(element))
		{
			case T_ColumnDef:
				transformColumnDefinition(&cxt, (ColumnDef *) element);
				break;

			case T_Constraint:
				
				elog(ERROR, "node type %d not supported for external tables", (int) nodeTag(element));
				break;

			case T_TableLikeClause:
				{
					
					bool	isBeginning = (cxt.columns == NIL);

					transformTableLikeClause(&cxt, (TableLikeClause *) element, true, NULL);

					if (Gp_role == GP_ROLE_DISPATCH && isBeginning && stmt->distributedBy == NULL && iswritable )

					{
						likeDistributedBy = getLikeDistributionPolicy((TableLikeClause *) element);
					}
				}
				break;

			default:
				elog(ERROR, "unrecognized node type: %d", (int) nodeTag(element));
				break;
		}
	}

	
	if (stmt->exttypedesc->exttabletype == EXTTBL_TYPE_EXECUTE)
	{
		ListCell   *exec_location_opt;

		foreach(exec_location_opt, stmt->exttypedesc->on_clause)
		{
			DefElem    *defel = (DefElem *) lfirst(exec_location_opt);

			if (strcmp(defel->defname, "coordinator") == 0)
			{
				SingleRowErrorDesc *srehDesc = (SingleRowErrorDesc *)stmt->sreh;

				if(srehDesc && srehDesc->log_error_type != LOG_ERRORS_DISABLE)
					ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("external web table with ON COORDINATOR clause cannot use LOG ERRORS feature")));

			}
		}
	}

	
	if (iswritable)
	{
		if (stmt->distributedBy == NULL && likeDistributedBy == NULL)
		{
			
			stmt->distributedBy = makeNode(DistributedBy);
			stmt->distributedBy->ptype = POLICYTYPE_PARTITIONED;
			stmt->distributedBy->keyCols = NIL;
			stmt->distributedBy->numsegments = GP_POLICY_DEFAULT_NUMSEGMENTS();
		}
		else {
			
			stmt->distributedBy = transformDistributedBy(pstate, &cxt, stmt->distributedBy, (DistributedBy *) likeDistributedBy, bQuiet);

			if (stmt->distributedBy->ptype == POLICYTYPE_REPLICATED)
				ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("external tables can't have DISTRIBUTED REPLICATED clause")));

		}
	}
	else if (stmt->distributedBy != NULL)
		ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("readable external tables can\'t specify a DISTRIBUTED BY clause")));


	Assert(cxt.ckconstraints == NIL);
	Assert(cxt.fkconstraints == NIL);
	Assert(cxt.ixconstraints == NIL);

	
	stmt->tableElts = cxt.columns;

	result = lappend(cxt.blist, stmt);
	result = list_concat(result, cxt.alist);

	MemoryContextDelete(cxt.tempCtx);

	return result;
}


static DistributedBy * transformDistributedBy(ParseState *pstate, CreateStmtContext *cxt, DistributedBy *distributedBy, DistributedBy *likeDistributedBy, bool bQuiet)




{
	ListCell	*keys = NULL;
	List		*distrkeys = NIL;
	ListCell   *lc;
	int			numsegments;

	
	if (Gp_role != GP_ROLE_DISPATCH && !IsBinaryUpgrade)
		return NULL;

	if (distributedBy && distributedBy->numsegments > 0)
		
		numsegments = distributedBy->numsegments;
	else  numsegments = GP_POLICY_DEFAULT_NUMSEGMENTS();


	
	if (distributedBy && (distributedBy->ptype == POLICYTYPE_PARTITIONED && distributedBy->keyCols == NIL))
	{
		distributedBy->numsegments = numsegments;
		return distributedBy;
	}

	
	if (distributedBy && distributedBy->ptype == POLICYTYPE_REPLICATED)
	{
		if (cxt->inhRelations != NIL)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("INHERITS clause cannot be used with DISTRIBUTED REPLICATED clause")));


		distributedBy->numsegments = numsegments;
		return distributedBy;
	}

	if (distributedBy)
		distrkeys = distributedBy->keyCols;

	
	if (distrkeys == NIL)
	{
		
		
		if (cxt->pkey != NULL)
		{
			IndexStmt  *index = cxt->pkey;
			List	   *indexParams;
			ListCell   *ip;

			Assert(index->indexParams != NULL);
			indexParams = index->indexParams;

			foreach(ip, indexParams)
			{
				IndexElem  *iparam = lfirst(ip);

				if (iparam && iparam->name != 0)
				{
					IndexElem *distrkey = makeNode(IndexElem);

					distrkey->name = iparam->name;
					distrkey->opclass = NULL;

					distrkeys = lappend(distrkeys, distrkey);
				}
			}
		}

		
		foreach(lc, cxt->ixconstraints)
		{
			Constraint *constraint = (Constraint *) lfirst(lc);
			ListCell   *ip;
			List	   *new_distrkeys = NIL;

			if (constraint->contype != CONSTR_UNIQUE)
				continue;

			if (distrkeys)
			{
				
				foreach(ip, constraint->keys)
				{
					Value	   *v = lfirst(ip);
					ListCell   *dkcell;

					foreach(dkcell, distrkeys)
					{
						DistributionKeyElem  *dk = (DistributionKeyElem *) lfirst(dkcell);

						if (strcmp(dk->name, strVal(v)) == 0)
						{
							new_distrkeys = lappend(new_distrkeys, dk);
							break;
						}
					}
				}

				
				if (new_distrkeys == NIL)
					ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("UNIQUE or PRIMARY KEY definitions are incompatible with each other"), errhint("When there are multiple PRIMARY KEY / UNIQUE constraints, they must have at least one column in common.")));


			}
			else {
				
				new_distrkeys = NIL;
				foreach(ip, constraint->keys)
				{
					Value	   *v = lfirst(ip);
					DistributionKeyElem  *dk = makeNode(DistributionKeyElem);

					dk->name = strVal(v);
					dk->opclass = NULL;
					dk->location = -1;

					new_distrkeys = lappend(new_distrkeys, dk);
				}
			}

			distrkeys = new_distrkeys;
		}
	}

	
	if (cxt->inhRelations != NIL)
	{
		ListCell   *entry;

		foreach(entry, cxt->inhRelations)
		{
			RangeVar   *parent = (RangeVar *) lfirst(entry);
			GpPolicy   *parentPolicy;
			Relation	parentrel;

			parentrel = heap_openrv(parent, AccessShareLock);
			parentPolicy = parentrel->rd_cdbpolicy;

			if (parentrel->rd_rel->relkind == RELKIND_FOREIGN_TABLE)
			{
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot inherit from foreign table \"%s\" to create table \"%s\"", parent->relname, cxt->relation->relname), errdetail("An inheritance hierarchy cannot contain a mixture of distributed and non-distributed tables.")));



			}

			
			if ((parentPolicy == NULL || parentPolicy->ptype == POLICYTYPE_ENTRY) && !IsBinaryUpgrade)

			{
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot inherit from catalog table \"%s\" to create table \"%s\"", parent->relname, cxt->relation->relname), errdetail("An inheritance hierarchy cannot contain a mixture of distributed and non-distributed tables.")));



			}

			if ((parentPolicy == NULL || GpPolicyIsReplicated(parentPolicy)) && !IsBinaryUpgrade)

			{
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot inherit from replicated table \"%s\" to create table \"%s\"", parent->relname, cxt->relation->relname), errdetail("An inheritance hierarchy cannot contain a mixture of distributed and non-distributed tables.")));



			}

			
			if (distrkeys == NIL && parentPolicy->nattrs >= 0)
			{
				if (!bQuiet)
					ereport(NOTICE, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("table has parent, setting distribution columns to match parent table")));


				distributedBy = make_distributedby_for_rel(parentrel);
				heap_close(parentrel, AccessShareLock);

				distributedBy->numsegments = numsegments;
				return distributedBy;
			}
			heap_close(parentrel, AccessShareLock);
		}
	}

	if (distrkeys == NIL && likeDistributedBy != NULL)
	{
		if (!bQuiet)
			ereport(NOTICE, (errmsg("table doesn't have 'DISTRIBUTED BY' clause, defaulting to distribution columns from LIKE table")));

		if (likeDistributedBy->ptype == POLICYTYPE_PARTITIONED && likeDistributedBy->keyCols == NIL)
		{
			distributedBy = makeNode(DistributedBy);
			distributedBy->ptype = POLICYTYPE_PARTITIONED;
			distributedBy->numsegments = numsegments;
			return distributedBy;
		}
		else if (likeDistributedBy->ptype == POLICYTYPE_REPLICATED)
		{
			distributedBy = makeNode(DistributedBy);
			distributedBy->ptype = POLICYTYPE_REPLICATED;
			distributedBy->numsegments = numsegments;
			return distributedBy;
		}

		distrkeys = likeDistributedBy->keyCols;
	}

	
	foreach(lc, cxt->inh_indexes)
	{
		IndexStmt  *index_stmt;
		ListCell *cell;
		List *new_distrkeys = NIL;

		index_stmt = (IndexStmt *) lfirst(lc);
		if (!index_stmt->unique && !index_stmt->primary)
			continue;

		if (distrkeys)
		{
			foreach(cell, index_stmt->indexParams)
			{
				IndexElem *iparam = lfirst(cell);
				ListCell *dkcell;

				
				if (!iparam || !iparam->name)
					continue;
				foreach(dkcell, distrkeys)
				{
					DistributionKeyElem  *dk = (DistributionKeyElem *) lfirst(dkcell);
					if (strcmp(dk->name, iparam->name) == 0)
					{
						new_distrkeys = lappend(new_distrkeys, dk);
						break;
					}
				}
			}
			
			if (new_distrkeys == NIL)
				ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("UNIQUE or PRIMARY KEY definitions are incompatible with each other"), errhint("When there are multiple PRIMARY KEY / UNIQUE constraints, they must have at least one column in common.")));


		}
		else {
			foreach(cell, index_stmt->indexParams)
			{
				IndexElem *iparam = lfirst(cell);
				if (iparam && iparam->name)
				{
					IndexElem *distrkey = makeNode(IndexElem);
					distrkey->name = iparam->name;
					distrkey->opclass = NULL;
					new_distrkeys = lappend(new_distrkeys, distrkey);
				}
			}
		}

		distrkeys = new_distrkeys;
	}

	if (gp_create_table_random_default_distribution && NIL == distrkeys)
	{
		Assert(NULL == likeDistributedBy);

		if (!bQuiet)
		{
			ereport(NOTICE, (errcode(ERRCODE_SUCCESSFUL_COMPLETION), errmsg("using default RANDOM distribution since no distribution was specified"), errhint("Consider including the 'DISTRIBUTED BY' clause to determine the distribution of rows.")));


		}

		distributedBy = makeNode(DistributedBy);
		distributedBy->ptype = POLICYTYPE_PARTITIONED;
		distributedBy->numsegments = numsegments;
		return distributedBy;
	}
	else if (distrkeys == NIL)
	{
		

		ListCell   *columns;

		if (cxt->inhRelations)
		{
			bool		found = false;
			
			ListCell   *inher;

			foreach(inher, cxt->inhRelations)
			{
				RangeVar   *inh = (RangeVar *) lfirst(inher);
				Relation	rel;
				int			count;

				Assert(IsA(inh, RangeVar));
				rel = heap_openrv(inh, AccessShareLock);
				
				if (rel->rd_rel->relkind != RELKIND_RELATION && rel->rd_rel->relkind != RELKIND_FOREIGN_TABLE && rel->rd_rel->relkind != RELKIND_PARTITIONED_TABLE)

					ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("inherited relation \"%s\" is not a table or foreign table", inh->relname)));


				for (count = 0; count < rel->rd_att->natts; count++)
				{
					Form_pg_attribute inhattr = TupleDescAttr(rel->rd_att, count);
					Oid typeOid = inhattr->atttypid;

					if (inhattr->attisdropped)
						continue;
					if (cdb_default_distribution_opclass_for_type(typeOid) != InvalidOid)
					{
						char	   *inhname = NameStr(inhattr->attname);
						DistributionKeyElem  *dkelem;

						dkelem = makeNode(DistributionKeyElem);
						dkelem->name = inhname;
						dkelem->opclass = NULL;
						dkelem->location = -1;

						distrkeys = list_make1(dkelem);
						if (!bQuiet)
							ereport(NOTICE, (errcode(ERRCODE_SUCCESSFUL_COMPLETION), errmsg("Table doesn't have 'DISTRIBUTED BY' clause -- Using column " "named '%s' from parent table as the Greenplum Database data distribution key for this " "table. ", inhname), errhint("The 'DISTRIBUTED BY' clause determines the distribution of data." " Make sure column(s) chosen are the optimal data distribution key to minimize skew.")));





						found = true;
						break;
					}
				}
				heap_close(rel, NoLock);

				if (distrkeys != NIL)
					break;
			}

		}

		if (distrkeys == NIL)
		{
			foreach(columns, cxt->columns)
			{
				ColumnDef  *column = (ColumnDef *) lfirst(columns);
				Oid			typeOid;

				if (column->generated == ATTRIBUTE_GENERATED_STORED)
				{
					
					continue;
				}

				typeOid = typenameTypeId(NULL, column->typeName);

				
				if (cdb_default_distribution_opclass_for_type(typeOid))
				{
					DistributionKeyElem *dkelem = makeNode(DistributionKeyElem);

					dkelem->name = column->colname;
					dkelem->opclass = NULL;		
					dkelem->location = -1;

					distrkeys = list_make1(dkelem);
					if (!bQuiet)
						ereport(NOTICE, (errcode(ERRCODE_SUCCESSFUL_COMPLETION), errmsg("Table doesn't have 'DISTRIBUTED BY' clause -- Using column " "named '%s' as the Greenplum Database data distribution key for this " "table. ", column->colname), errhint("The 'DISTRIBUTED BY' clause determines the distribution of data." " Make sure column(s) chosen are the optimal data distribution key to minimize skew.")));





					break;
				}
			}
		}

		if (distrkeys == NIL)
		{
			
			if (!bQuiet)
				ereport(NOTICE, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("Table doesn't have 'DISTRIBUTED BY' clause, and no column type is suitable for a distribution key. Creating a NULL policy entry.")));


			distributedBy = makeNode(DistributedBy);
			distributedBy->ptype = POLICYTYPE_PARTITIONED;
			distributedBy->numsegments = numsegments;
			return distributedBy;
		}
	}
	else {
		
		foreach(keys, distrkeys)
		{
			DistributionKeyElem *dkelem = (DistributionKeyElem *) lfirst(keys);
			char	   *colname = dkelem->name;
			bool		found = false;
			ListCell   *columns;

			if (cxt->inhRelations)
			{
				
				ListCell   *inher;

				foreach(inher, cxt->inhRelations)
				{
					RangeVar   *inh = (RangeVar *) lfirst(inher);
					Relation	rel;
					int			count;

					Assert(IsA(inh, RangeVar));
					rel = heap_openrv(inh, AccessShareLock);
					
					if (rel->rd_rel->relkind != RELKIND_RELATION && rel->rd_rel->relkind != RELKIND_FOREIGN_TABLE && rel->rd_rel->relkind != RELKIND_PARTITIONED_TABLE)

						ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("inherited relation \"%s\" is not a table or foreign table", inh->relname)));


					for (count = 0; count < rel->rd_att->natts; count++)
					{
						Form_pg_attribute inhattr = TupleDescAttr(rel->rd_att, count);
						char	   *inhname = NameStr(inhattr->attname);

						if (inhattr->attisdropped)
							continue;
						if (strcmp(colname, inhname) == 0)
						{
							found = true;

							break;
						}
					}
					heap_close(rel, NoLock);
					if (found)
						elog(DEBUG1, "DISTRIBUTED BY clause refers to columns of inherited table");

					if (found)
						break;
				}
			}

			if (!found)
			{
				foreach(columns, cxt->columns)
				{
					ColumnDef *column = (ColumnDef *) lfirst(columns);
					Assert(IsA(column, ColumnDef));

					if (strcmp(column->colname, colname) == 0)
					{
						if (column->generated == ATTRIBUTE_GENERATED_STORED)
						{
							
							ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("cannot use generated column in distribution key"), errdetail("Column \"%s\" is a generated column.", column->colname), parser_errposition(pstate, column->location)));




						}
						found = true;
						break;
					}
				}
			}

			
			if (!found && !cxt->isalter)
				ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" named in DISTRIBUTED BY clause does not exist", colname), parser_errposition(pstate, dkelem->location)));


		}
	}

	
	if (cxt && cxt->pkey)
	{
		
		IndexStmt  *index = cxt->pkey;
		ListCell   *dk;

		foreach(dk, distrkeys)
		{
			char	   *distcolname = strVal(lfirst(dk));
			ListCell   *ip;
			bool		found = false;

			foreach(ip, index->indexParams)
			{
				IndexElem  *iparam = lfirst(ip);

				if (!iparam->name)
					elog(ERROR, "PRIMARY KEY on an expression index not supported");

				if (strcmp(iparam->name, distcolname) == 0)
				{
					found = true;
					break;
				}
			}

			if (!found)
			{
				ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("PRIMARY KEY and DISTRIBUTED BY definitions are incompatible"), errhint("When there is both a PRIMARY KEY and a DISTRIBUTED BY clause, the DISTRIBUTED BY clause must be a subset of the PRIMARY KEY.")));


			}
		}
	}

	
	foreach (lc, cxt->ixconstraints)
	{
		Constraint *constraint = (Constraint *) lfirst(lc);
		ListCell   *dk;

		if (constraint->contype != CONSTR_PRIMARY && constraint->contype != CONSTR_UNIQUE)
			continue;

		foreach(dk, distrkeys)
		{
			char	   *distcolname = strVal(lfirst(dk));
			ListCell   *ip;
			bool		found = false;

			foreach (ip, constraint->keys)
			{
				IndexElem  *iparam = lfirst(ip);

				if (!iparam->name)
					elog(ERROR, "UNIQUE constraint on an expression index not supported");

				if (strcmp(iparam->name, distcolname) == 0)
				{
					found = true;
					break;
				}
			}

			if (!found)
			{
				ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("UNIQUE constraint and DISTRIBUTED BY definitions are incompatible"), errhint("When there is both a UNIQUE constraint and a DISTRIBUTED BY clause, the DISTRIBUTED BY clause must be a subset of the UNIQUE constraint.")));


			}
		}
	}

	
	distributedBy = makeNode(DistributedBy);
	distributedBy->ptype = POLICYTYPE_PARTITIONED;
	distributedBy->keyCols = distrkeys;
	distributedBy->numsegments = numsegments;

	return distributedBy;
}


GpPolicy * getPolicyForDistributedBy(DistributedBy *distributedBy, TupleDesc tupdesc)
{
	List	   *policykeys;
	List	   *policyopclasses;
	ListCell   *lc;

	if (!distributedBy)
		return NULL; 

	switch(distributedBy->ptype)
	{
		case POLICYTYPE_PARTITIONED:
			
			policykeys = NIL;
			policyopclasses = NIL;
			foreach(lc, distributedBy->keyCols)
			{
				DistributionKeyElem *dkelem = (DistributionKeyElem *) lfirst(lc);
				char	   *colname = dkelem->name;
				int			i;
				bool		found = false;

				for (i = 0; i < tupdesc->natts; i++)
				{
					Form_pg_attribute attr = TupleDescAttr(tupdesc, i);

					if (strcmp(colname, NameStr(attr->attname)) == 0)
					{
						Oid			opclass;

						opclass = cdb_get_opclass_for_column_def(dkelem->opclass, attr->atttypid);

						policykeys = lappend_int(policykeys, attr->attnum);
						policyopclasses = lappend_oid(policyopclasses, opclass);
						found = true;
					}
				}
				if (!found)
					ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" does not exist", colname)));

			}

			return createHashPartitionedPolicy(policykeys, policyopclasses, distributedBy->numsegments);;


		case POLICYTYPE_ENTRY:
			elog(ERROR, "unexpected entry distribution policy");
			return NULL;

		case POLICYTYPE_REPLICATED:
			return createReplicatedGpPolicy(distributedBy->numsegments);
	}
	elog(ERROR, "unrecognized policy type %d", distributedBy->ptype);
	return NULL;
}


static void transformIndexConstraints(CreateStmtContext *cxt)
{
	IndexStmt  *index;
	List	   *indexlist = NIL;
	List	   *finalindexlist = NIL;
	ListCell   *lc;

	
	foreach(lc, cxt->ixconstraints)
	{
		Constraint *constraint = lfirst_node(Constraint, lc);

		Assert(constraint->contype == CONSTR_PRIMARY || constraint->contype == CONSTR_UNIQUE || constraint->contype == CONSTR_EXCLUSION);


		index = transformIndexConstraint(constraint, cxt);

		indexlist = lappend(indexlist, index);
	}

	
	foreach(lc, cxt->inh_indexes)
	{
		index = (IndexStmt *) lfirst(lc);

		if (index->primary)
		{
			if (cxt->pkey != NULL)
				ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("multiple primary keys for table \"%s\" are not allowed", cxt->relation->relname)));


			cxt->pkey = index;
		}

		indexlist = lappend(indexlist, index);
	}

	
	if (cxt->pkey != NULL)
	{
		
		finalindexlist = list_make1(cxt->pkey);
	}

	foreach(lc, indexlist)
	{
		bool		keep = true;
		bool		defer = false;
		ListCell   *k;

		index = lfirst(lc);

		
		if (index == cxt->pkey)
			continue;

		foreach(k, finalindexlist)
		{
			IndexStmt  *priorindex = lfirst(k);

			if (equal(index->indexParams, priorindex->indexParams) && equal(index->indexIncludingParams, priorindex->indexIncludingParams) && equal(index->whereClause, priorindex->whereClause) && equal(index->excludeOpNames, priorindex->excludeOpNames) && strcmp(index->accessMethod, priorindex->accessMethod) == 0 && index->deferrable == priorindex->deferrable && index->initdeferred == priorindex->initdeferred)





			{
				priorindex->unique |= index->unique;

				
				if (priorindex->idxname == NULL)
					priorindex->idxname = index->idxname;
				keep = false;
				break;
			}
		}
		
		defer = index->whereClause != NULL;
		if ( !defer )
		{
			ListCell *j;
			foreach(j, index->indexParams)
			{
				IndexElem *elt = (IndexElem*)lfirst(j);
				Assert(IsA(elt, IndexElem));
				
				if (elt->expr != NULL)
				{
					defer = true;
					break;
				}
			}
		}

		if (keep)
			finalindexlist = lappend(finalindexlist, index);
	}

	
	cxt->alist = list_concat(cxt->alist, finalindexlist);
}


static IndexStmt * transformIndexConstraint(Constraint *constraint, CreateStmtContext *cxt)
{
	IndexStmt  *index;
	List	   *notnullcmds = NIL;
	ListCell   *lc;

	index = makeNode(IndexStmt);

	index->unique = (constraint->contype != CONSTR_EXCLUSION);
	index->primary = (constraint->contype == CONSTR_PRIMARY);
	if (index->primary)
	{
		if (cxt->pkey != NULL)
			ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("multiple primary keys for table \"%s\" are not allowed", cxt->relation->relname), parser_errposition(cxt->pstate, constraint->location)));



		cxt->pkey = index;

		
	}
	index->isconstraint = true;
	index->deferrable = constraint->deferrable;
	index->initdeferred = constraint->initdeferred;

	if (constraint->conname != NULL)
		index->idxname = pstrdup(constraint->conname);
	else index->idxname = NULL;

	index->relation = cxt->relation;
	index->accessMethod = constraint->access_method ? constraint->access_method : DEFAULT_INDEX_TYPE;
	index->options = constraint->options;
	index->tableSpace = constraint->indexspace;
	index->whereClause = constraint->where_clause;
	index->indexParams = NIL;
	index->indexIncludingParams = NIL;
	index->excludeOpNames = NIL;
	index->idxcomment = NULL;
	index->indexOid = InvalidOid;
	index->oldNode = InvalidOid;
	index->transformed = false;
	index->concurrent = false;
	index->if_not_exists = false;
	index->reset_default_tblspc = constraint->reset_default_tblspc;

	
	if (constraint->indexname != NULL)
	{
		char	   *index_name = constraint->indexname;
		Relation	heap_rel = cxt->rel;
		Oid			index_oid;
		Relation	index_rel;
		Form_pg_index index_form;
		oidvector  *indclass;
		Datum		indclassDatum;
		bool		isnull;
		int			i;

		
		Assert(constraint->keys == NIL);

		
		Assert(constraint->contype == CONSTR_PRIMARY || constraint->contype == CONSTR_UNIQUE);

		
		if (!cxt->isalter)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot use an existing index in CREATE TABLE"), parser_errposition(cxt->pstate, constraint->location)));



		
		index_oid = get_relname_relid(index_name, RelationGetNamespace(heap_rel));

		if (!OidIsValid(index_oid))
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("index \"%s\" does not exist", index_name), parser_errposition(cxt->pstate, constraint->location)));



		
		index_rel = index_open(index_oid, AccessShareLock);
		index_form = index_rel->rd_index;

		
		if (OidIsValid(get_index_constraint(index_oid)))
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("index \"%s\" is already associated with a constraint", index_name), parser_errposition(cxt->pstate, constraint->location)));




		
		if (index_form->indrelid != RelationGetRelid(heap_rel))
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("index \"%s\" does not belong to table \"%s\"", index_name, RelationGetRelationName(heap_rel)), parser_errposition(cxt->pstate, constraint->location)));




		if (!index_form->indisvalid)
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("index \"%s\" is not valid", index_name), parser_errposition(cxt->pstate, constraint->location)));



		if (!index_form->indisunique)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is not a unique index", index_name), errdetail("Cannot create a primary key or unique constraint using such an index."), parser_errposition(cxt->pstate, constraint->location)));




		if (RelationGetIndexExpressions(index_rel) != NIL)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("index \"%s\" contains expressions", index_name), errdetail("Cannot create a primary key or unique constraint using such an index."), parser_errposition(cxt->pstate, constraint->location)));




		if (RelationGetIndexPredicate(index_rel) != NIL)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is a partial index", index_name), errdetail("Cannot create a primary key or unique constraint using such an index."), parser_errposition(cxt->pstate, constraint->location)));




		
		if (!index_form->indimmediate && !constraint->deferrable)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("\"%s\" is a deferrable index", index_name), errdetail("Cannot create a non-deferrable constraint using a deferrable index."), parser_errposition(cxt->pstate, constraint->location)));




		
		if (index_rel->rd_rel->relam != get_index_am_oid(DEFAULT_INDEX_TYPE, false))
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("index \"%s\" is not a btree", index_name), parser_errposition(cxt->pstate, constraint->location)));



		
		indclassDatum = SysCacheGetAttr(INDEXRELID, index_rel->rd_indextuple, Anum_pg_index_indclass, &isnull);
		Assert(!isnull);
		indclass = (oidvector *) DatumGetPointer(indclassDatum);

		for (i = 0; i < index_form->indnatts; i++)
		{
			int16		attnum = index_form->indkey.values[i];
			const FormData_pg_attribute *attform;
			char	   *attname;
			Oid			defopclass;

			
			if (attnum > 0)
			{
				Assert(attnum <= heap_rel->rd_att->natts);
				attform = TupleDescAttr(heap_rel->rd_att, attnum - 1);
			}
			else attform = SystemAttributeDefinition(attnum);
			attname = pstrdup(NameStr(attform->attname));

			if (i < index_form->indnkeyatts)
			{
				
				defopclass = GetDefaultOpClass(attform->atttypid, index_rel->rd_rel->relam);
				if (indclass->values[i] != defopclass || index_rel->rd_indoption[i] != 0)
					ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("index \"%s\" column number %d does not have default sorting behavior", index_name, i + 1), errdetail("Cannot create a primary key or unique constraint using such an index."), parser_errposition(cxt->pstate, constraint->location)));




				constraint->keys = lappend(constraint->keys, makeString(attname));
			}
			else constraint->including = lappend(constraint->including, makeString(attname));
		}

		
		relation_close(index_rel, NoLock);

		index->indexOid = index_oid;
	}

	
	if (constraint->contype == CONSTR_EXCLUSION)
	{
		foreach(lc, constraint->exclusions)
		{
			List	   *pair = (List *) lfirst(lc);
			IndexElem  *elem;
			List	   *opname;

			Assert(list_length(pair) == 2);
			elem = linitial_node(IndexElem, pair);
			opname = lsecond_node(List, pair);

			index->indexParams = lappend(index->indexParams, elem);
			index->excludeOpNames = lappend(index->excludeOpNames, opname);
		}
	}

	
	else {
		foreach(lc, constraint->keys)
		{
			char	   *key = strVal(lfirst(lc));
			bool		found = false;
			bool		forced_not_null = false;
			ColumnDef  *column = NULL;
			ListCell   *columns;
			IndexElem  *iparam;

			
			foreach(columns, cxt->columns)
			{
				column = castNode(ColumnDef, lfirst(columns));
				if (strcmp(column->colname, key) == 0)
				{
					found = true;
					break;
				}
			}
			if (found)
			{
				
				if (constraint->contype == CONSTR_PRIMARY && !column->is_from_type)
				{
					column->is_not_null = true;
					forced_not_null = true;
				}
			}
			else if (SystemAttributeByName(key) != NULL)
			{
				
				found = true;
			}
			else if (cxt->inhRelations)
			{
				
				ListCell   *inher;

				foreach(inher, cxt->inhRelations)
				{
					RangeVar   *inh = castNode(RangeVar, lfirst(inher));
					Relation	rel;
					int			count;

					rel = table_openrv(inh, AccessShareLock);
					
					if (rel->rd_rel->relkind != RELKIND_RELATION && rel->rd_rel->relkind != RELKIND_FOREIGN_TABLE && rel->rd_rel->relkind != RELKIND_PARTITIONED_TABLE)

						ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("inherited relation \"%s\" is not a table or foreign table", inh->relname)));


					for (count = 0; count < rel->rd_att->natts; count++)
					{
						Form_pg_attribute inhattr = TupleDescAttr(rel->rd_att, count);
						char	   *inhname = NameStr(inhattr->attname);

						if (inhattr->attisdropped)
							continue;
						if (strcmp(key, inhname) == 0)
						{
							found = true;

							
							break;
						}
					}
					table_close(rel, NoLock);
					if (found)
						break;
				}
			}

			
			if (!found && !cxt->isalter)
				ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" named in key does not exist", key), parser_errposition(cxt->pstate, constraint->location)));



			
			foreach(columns, index->indexParams)
			{
				iparam = (IndexElem *) lfirst(columns);
				if (iparam->name && strcmp(key, iparam->name) == 0)
				{
					if (index->primary)
						ereport(ERROR, (errcode(ERRCODE_DUPLICATE_COLUMN), errmsg("column \"%s\" appears twice in primary key constraint", key), parser_errposition(cxt->pstate, constraint->location)));



					else ereport(ERROR, (errcode(ERRCODE_DUPLICATE_COLUMN), errmsg("column \"%s\" appears twice in unique constraint", key), parser_errposition(cxt->pstate, constraint->location)));




				}
			}

			
			iparam = makeNode(IndexElem);
			iparam->name = pstrdup(key);
			iparam->expr = NULL;
			iparam->indexcolname = NULL;
			iparam->collation = NIL;
			iparam->opclass = NIL;
			iparam->ordering = SORTBY_DEFAULT;
			iparam->nulls_ordering = SORTBY_NULLS_DEFAULT;
			index->indexParams = lappend(index->indexParams, iparam);

			
			if (constraint->contype == CONSTR_PRIMARY && !forced_not_null)
			{
				AlterTableCmd *notnullcmd = makeNode(AlterTableCmd);

				notnullcmd->subtype = AT_SetNotNull;
				notnullcmd->name = pstrdup(key);
				notnullcmds = lappend(notnullcmds, notnullcmd);
			}
		}
	}

	
	foreach(lc, constraint->including)
	{
		char	   *key = strVal(lfirst(lc));
		bool		found = false;
		ColumnDef  *column = NULL;
		ListCell   *columns;
		IndexElem  *iparam;

		foreach(columns, cxt->columns)
		{
			column = lfirst_node(ColumnDef, columns);
			if (strcmp(column->colname, key) == 0)
			{
				found = true;
				break;
			}
		}

		if (!found)
		{
			if (SystemAttributeByName(key) != NULL)
			{
				
				found = true;
			}
			else if (cxt->inhRelations)
			{
				
				ListCell   *inher;

				foreach(inher, cxt->inhRelations)
				{
					RangeVar   *inh = lfirst_node(RangeVar, inher);
					Relation	rel;
					int			count;

					rel = table_openrv(inh, AccessShareLock);
					
					if (rel->rd_rel->relkind != RELKIND_RELATION && rel->rd_rel->relkind != RELKIND_FOREIGN_TABLE && rel->rd_rel->relkind != RELKIND_PARTITIONED_TABLE)

						ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("inherited relation \"%s\" is not a table or foreign table", inh->relname)));


					for (count = 0; count < rel->rd_att->natts; count++)
					{
						Form_pg_attribute inhattr = TupleDescAttr(rel->rd_att, count);
						char	   *inhname = NameStr(inhattr->attname);

						if (inhattr->attisdropped)
							continue;
						if (strcmp(key, inhname) == 0)
						{
							found = true;
							break;
						}
					}
					table_close(rel, NoLock);
					if (found)
						break;
				}
			}
		}

		
		if (!found && !cxt->isalter)
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_COLUMN), errmsg("column \"%s\" named in key does not exist", key), parser_errposition(cxt->pstate, constraint->location)));



		
		iparam = makeNode(IndexElem);
		iparam->name = pstrdup(key);
		iparam->expr = NULL;
		iparam->indexcolname = NULL;
		iparam->collation = NIL;
		iparam->opclass = NIL;
		index->indexIncludingParams = lappend(index->indexIncludingParams, iparam);
	}

	
	if (notnullcmds)
	{
		AlterTableStmt *alterstmt = makeNode(AlterTableStmt);

		alterstmt->relation = copyObject(cxt->relation);
		alterstmt->cmds = notnullcmds;
		alterstmt->relkind = OBJECT_TABLE;
		alterstmt->missing_ok = false;

		cxt->alist = lappend(cxt->alist, alterstmt);
	}

	return index;
}


static void transformExtendedStatistics(CreateStmtContext *cxt)
{
	cxt->alist = list_concat(cxt->alist, cxt->extstats);
}


static void transformCheckConstraints(CreateStmtContext *cxt, bool skipValidation)
{
	ListCell   *ckclist;

	if (cxt->ckconstraints == NIL)
		return;

	
	if (skipValidation)
	{
		foreach(ckclist, cxt->ckconstraints)
		{
			Constraint *constraint = (Constraint *) lfirst(ckclist);

			constraint->skip_validation = true;
			constraint->initially_valid = true;
		}
	}
}


static void transformFKConstraints(CreateStmtContext *cxt, bool skipValidation, bool isAddConstraint)

{
	ListCell   *fkclist;

	if (cxt->fkconstraints == NIL)
		return;

	
	if (skipValidation)
	{
		foreach(fkclist, cxt->fkconstraints)
		{
			Constraint *constraint = (Constraint *) lfirst(fkclist);

			constraint->skip_validation = true;
			constraint->initially_valid = true;
		}
	}

	
	if (!isAddConstraint)
	{
		AlterTableStmt *alterstmt = makeNode(AlterTableStmt);

		alterstmt->relation = cxt->relation;
		alterstmt->cmds = NIL;
		alterstmt->relkind = OBJECT_TABLE;

		foreach(fkclist, cxt->fkconstraints)
		{
			Constraint *constraint = (Constraint *) lfirst(fkclist);
			AlterTableCmd *altercmd = makeNode(AlterTableCmd);

			altercmd->subtype = AT_ProcessedConstraint;
			altercmd->name = NULL;
			altercmd->def = (Node *) constraint;
			alterstmt->cmds = lappend(alterstmt->cmds, altercmd);
		}

		cxt->alist = lappend(cxt->alist, alterstmt);
	}
}


IndexStmt * transformIndexStmt(Oid relid, IndexStmt *stmt, const char *queryString)
{
	ParseState *pstate;
	RangeTblEntry *rte;
	ListCell   *l;
	Relation	rel;

	
	if (stmt->transformed)
		return stmt;

	
	stmt = copyObject(stmt);

	
	pstate = make_parsestate(NULL);
	pstate->p_sourcetext = queryString;

	
	rel = relation_open(relid, NoLock);
	rte = addRangeTableEntryForRelation(pstate, rel, AccessShareLock, NULL, false, true);


	
	addRTEtoQuery(pstate, rte, false, true, true);

	
	if (stmt->whereClause)
	{
		stmt->whereClause = transformWhereClause(pstate, stmt->whereClause, EXPR_KIND_INDEX_PREDICATE, "WHERE");


		
		assign_expr_collations(pstate, stmt->whereClause);
	}

	
	foreach(l, stmt->indexParams)
	{
		IndexElem  *ielem = (IndexElem *) lfirst(l);

		if (ielem->expr)
		{
			
			if (ielem->indexcolname == NULL)
				ielem->indexcolname = FigureIndexColname(ielem->expr);

			
			ielem->expr = transformExpr(pstate, ielem->expr, EXPR_KIND_INDEX_EXPRESSION);

			
			assign_expr_collations(pstate, ielem->expr);

			
		}
	}

	
	if (list_length(pstate->p_rtable) != 1)
		ereport(ERROR, (errcode(ERRCODE_INVALID_COLUMN_REFERENCE), errmsg("index expressions and predicates can refer only to the table being indexed")));


	free_parsestate(pstate);

	
	table_close(rel, NoLock);

	
	stmt->transformed = true;

	return stmt;
}



void transformRuleStmt(RuleStmt *stmt, const char *queryString, List **actions, Node **whereClause)

{
	Relation	rel;
	ParseState *pstate;
	RangeTblEntry *oldrte;
	RangeTblEntry *newrte;

	
	rel = table_openrv(stmt->relation, AccessExclusiveLock);

	if (rel->rd_rel->relkind == RELKIND_MATVIEW)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("rules on materialized views are not supported")));


	
	pstate = make_parsestate(NULL);
	pstate->p_sourcetext = queryString;

	
	oldrte = addRangeTableEntryForRelation(pstate, rel, AccessShareLock, makeAlias("old", NIL), false, false);


	newrte = addRangeTableEntryForRelation(pstate, rel, AccessShareLock, makeAlias("new", NIL), false, false);


	
	oldrte->requiredPerms = 0;
	newrte->requiredPerms = 0;

	
	switch (stmt->event)
	{
		case CMD_SELECT:
			addRTEtoQuery(pstate, oldrte, false, true, true);
			break;
		case CMD_UPDATE:
			addRTEtoQuery(pstate, oldrte, false, true, true);
			addRTEtoQuery(pstate, newrte, false, true, true);
			break;
		case CMD_INSERT:
			addRTEtoQuery(pstate, newrte, false, true, true);
			break;
		case CMD_DELETE:
			addRTEtoQuery(pstate, oldrte, false, true, true);
			break;
		default:
			elog(ERROR, "unrecognized event type: %d", (int) stmt->event);
			break;
	}

	
	*whereClause = transformWhereClause(pstate, (Node *) copyObject(stmt->whereClause), EXPR_KIND_WHERE, "WHERE");


	
	assign_expr_collations(pstate, *whereClause);

	
	if (list_length(pstate->p_rtable) != 2) 
		ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("rule WHERE condition cannot contain references to other relations")));


	
	if (stmt->actions == NIL)
	{
		Query	   *nothing_qry = makeNode(Query);

		nothing_qry->commandType = CMD_NOTHING;
		nothing_qry->rtable = pstate->p_rtable;
		nothing_qry->jointree = makeFromExpr(NIL, NULL);	

		*actions = list_make1(nothing_qry);
	}
	else {
		ListCell   *l;
		List	   *newactions = NIL;

		
		foreach(l, stmt->actions)
		{
			Node	   *action = (Node *) lfirst(l);
			ParseState *sub_pstate = make_parsestate(NULL);
			Query	   *sub_qry, *top_subqry;
			bool		has_old, has_new;

			
			sub_pstate->p_sourcetext = queryString;

			
			oldrte = addRangeTableEntryForRelation(sub_pstate, rel, AccessShareLock, makeAlias("old", NIL), false, false);


			newrte = addRangeTableEntryForRelation(sub_pstate, rel, AccessShareLock, makeAlias("new", NIL), false, false);


			oldrte->requiredPerms = 0;
			newrte->requiredPerms = 0;
			addRTEtoQuery(sub_pstate, oldrte, false, true, false);
			addRTEtoQuery(sub_pstate, newrte, false, true, false);

			
			top_subqry = transformStmt(sub_pstate, (Node *) copyObject(action));

			
			if (top_subqry->commandType == CMD_UTILITY && *whereClause != NULL)
				ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("rules with WHERE conditions can only have SELECT, INSERT, UPDATE, or DELETE actions")));


			
			sub_qry = getInsertSelectQuery(top_subqry, NULL);

			
			if (sub_qry->setOperations != NULL && *whereClause != NULL)
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("conditional UNION/INTERSECT/EXCEPT statements are not implemented")));


			
			has_old = rangeTableEntry_used((Node *) sub_qry, PRS2_OLD_VARNO, 0) || rangeTableEntry_used(*whereClause, PRS2_OLD_VARNO, 0);

			has_new = rangeTableEntry_used((Node *) sub_qry, PRS2_NEW_VARNO, 0) || rangeTableEntry_used(*whereClause, PRS2_NEW_VARNO, 0);


			switch (stmt->event)
			{
				case CMD_SELECT:
					if (has_old)
						ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("ON SELECT rule cannot use OLD")));

					if (has_new)
						ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("ON SELECT rule cannot use NEW")));

					break;
				case CMD_UPDATE:
					
					break;
				case CMD_INSERT:
					if (has_old)
						ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("ON INSERT rule cannot use OLD")));

					break;
				case CMD_DELETE:
					if (has_new)
						ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("ON DELETE rule cannot use NEW")));

					break;
				default:
					elog(ERROR, "unrecognized event type: %d", (int) stmt->event);
					break;
			}

			
			if (rangeTableEntry_used((Node *) top_subqry->cteList, PRS2_OLD_VARNO, 0) || rangeTableEntry_used((Node *) sub_qry->cteList, PRS2_OLD_VARNO, 0))


				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot refer to OLD within WITH query")));

			if (rangeTableEntry_used((Node *) top_subqry->cteList, PRS2_NEW_VARNO, 0) || rangeTableEntry_used((Node *) sub_qry->cteList, PRS2_NEW_VARNO, 0))


				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot refer to NEW within WITH query")));


			
			if (has_old || (has_new && stmt->event == CMD_UPDATE))
			{
				
				if (sub_qry->setOperations != NULL)
					ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("conditional UNION/INTERSECT/EXCEPT statements are not implemented")));

				
				sub_pstate->p_rtable = sub_qry->rtable;
				sub_pstate->p_joinlist = sub_qry->jointree->fromlist;
				addRTEtoQuery(sub_pstate, oldrte, true, false, false);
				sub_qry->jointree->fromlist = sub_pstate->p_joinlist;
			}

			newactions = lappend(newactions, top_subqry);

			free_parsestate(sub_pstate);
		}

		*actions = newactions;
	}

	free_parsestate(pstate);

	
	table_close(rel, NoLock);
}


List * transformAlterTableStmt(Oid relid, AlterTableStmt *stmt, const char *queryString)

{
	Relation	rel;
	TupleDesc	tupdesc;
	ParseState *pstate;
	CreateStmtContext cxt;
	List	   *result;
	List	   *save_alist;
	ListCell   *lcmd, *l;
	List	   *newcmds = NIL;
	bool		skipValidation = true;
	AlterTableCmd *newcmd;
	RangeTblEntry *rte;

	
	stmt = copyObject(stmt);

	
	rel = relation_open(relid, NoLock);
	tupdesc = RelationGetDescr(rel);

	
	pstate = make_parsestate(NULL);
	pstate->p_sourcetext = queryString;
	rte = addRangeTableEntryForRelation(pstate, rel, AccessShareLock, NULL, false, true);




	addRTEtoQuery(pstate, rte, false, true, true);

	
	cxt.pstate = pstate;
	if (stmt->relkind == OBJECT_FOREIGN_TABLE)
	{
		cxt.stmtType = "ALTER FOREIGN TABLE";
		cxt.isforeign = true;
	}
	else {
		cxt.stmtType = "ALTER TABLE";
		cxt.isforeign = false;
	}
	cxt.relation = stmt->relation;
	cxt.rel = rel;
	cxt.inhRelations = NIL;
	cxt.isalter = true;
	cxt.columns = NIL;
	cxt.ckconstraints = NIL;
	cxt.fkconstraints = NIL;
	cxt.ixconstraints = NIL;
	cxt.inh_indexes = NIL;
	cxt.attr_encodings = NIL;
	cxt.extstats = NIL;
	cxt.blist = NIL;
	cxt.alist = NIL;
	cxt.pkey = NULL;
	cxt.ispartitioned = (rel->rd_rel->relkind == RELKIND_PARTITIONED_TABLE);
	cxt.partbound = NULL;
	cxt.ofType = false;

	
	foreach(lcmd, stmt->cmds)
	{
		AlterTableCmd *cmd = (AlterTableCmd *) lfirst(lcmd);

		switch (cmd->subtype)
		{
			case AT_AddColumn:
			case AT_AddColumnToView:
				{
					ColumnDef  *def = castNode(ColumnDef, cmd->def);

					
					if (Gp_role == GP_ROLE_DISPATCH)
					{
						ListCell *c;
						foreach(c, def->constraints)
						{
							Constraint *cons = (Constraint *) lfirst(c);
							if (cons->contype == CONSTR_PRIMARY)
								ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot add column with primary key constraint")));

							if (cons->contype == CONSTR_UNIQUE)
								ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("cannot add column with unique constraint")));

						}
					}
					transformColumnDefinition(&cxt, def);

					
					if (def->raw_default != NULL)
						skipValidation = false;

					
					def->constraints = NIL;

					newcmds = lappend(newcmds, cmd);
					break;
				}

			case AT_AddConstraint:

				
				if (IsA(cmd->def, Constraint))
				{
					transformTableConstraint(&cxt, (Constraint *) cmd->def);
					if (((Constraint *) cmd->def)->contype == CONSTR_FOREIGN)
					{
						
						skipValidation = true;
					}
				}
				else elog(ERROR, "unrecognized node type: %d", (int) nodeTag(cmd->def));

				break;

			case AT_ProcessedConstraint:

				
				cmd->subtype = AT_AddConstraint;
				newcmds = lappend(newcmds, cmd);
				break;

				

			case AT_PartAdd:
			case AT_PartDrop:
			case AT_PartAlter:
			case AT_PartSplit:
			case AT_PartRename:
			case AT_PartTruncate:
			case AT_PartExchange:
			case AT_PartSetTemplate:
				
				cmd->queryString = queryString;
				newcmds = lappend(newcmds, cmd);
				break;

			case AT_AlterColumnType:
				{
					ColumnDef  *def = (ColumnDef *) cmd->def;
					AttrNumber	attnum;

					
					if (def->raw_default)
					{
						def->cooked_default = transformExpr(pstate, def->raw_default, EXPR_KIND_ALTER_COL_TRANSFORM);

					}

					
					attnum = get_attnum(relid, cmd->name);

					
					if (attnum != InvalidAttrNumber && TupleDescAttr(tupdesc, attnum - 1)->attidentity)
					{
						Oid			seq_relid = getOwnedSequence(relid, attnum);
						Oid			typeOid = typenameTypeId(pstate, def->typeName);
						AlterSeqStmt *altseqstmt = makeNode(AlterSeqStmt);

						altseqstmt->sequence = makeRangeVar(get_namespace_name(get_rel_namespace(seq_relid)), get_rel_name(seq_relid), -1);

						altseqstmt->options = list_make1(makeDefElem("as", (Node *) makeTypeNameFromOid(typeOid, -1), -1));
						altseqstmt->for_identity = true;
						cxt.blist = lappend(cxt.blist, altseqstmt);
					}

					newcmds = lappend(newcmds, cmd);
					break;
				}

			case AT_AddIdentity:
				{
					Constraint *def = castNode(Constraint, cmd->def);
					ColumnDef  *newdef = makeNode(ColumnDef);
					AttrNumber	attnum;

					newdef->colname = cmd->name;
					newdef->identity = def->generated_when;
					cmd->def = (Node *) newdef;

					attnum = get_attnum(relid, cmd->name);

					
					if (attnum != InvalidAttrNumber)
						generateSerialExtraStmts(&cxt, newdef, get_atttype(relid, attnum), def->options, true, NULL, NULL);



					newcmds = lappend(newcmds, cmd);
					break;
				}

			case AT_SetIdentity:
				{
					
					ListCell   *lc;
					List	   *newseqopts = NIL;
					List	   *newdef = NIL;
					List	   *seqlist;
					AttrNumber	attnum;

					
					foreach(lc, castNode(List, cmd->def))
					{
						DefElem    *def = lfirst_node(DefElem, lc);

						if (strcmp(def->defname, "generated") == 0)
							newdef = lappend(newdef, def);
						else newseqopts = lappend(newseqopts, def);
					}

					attnum = get_attnum(relid, cmd->name);

					if (attnum)
					{
						seqlist = getOwnedSequences(relid, attnum);
						if (seqlist)
						{
							AlterSeqStmt *seqstmt;
							Oid			seq_relid;

							seqstmt = makeNode(AlterSeqStmt);
							seq_relid = linitial_oid(seqlist);
							seqstmt->sequence = makeRangeVar(get_namespace_name(get_rel_namespace(seq_relid)), get_rel_name(seq_relid), -1);
							seqstmt->options = newseqopts;
							seqstmt->for_identity = true;
							seqstmt->missing_ok = false;

							cxt.alist = lappend(cxt.alist, seqstmt);
						}
					}

					

					cmd->def = (Node *) newdef;
					newcmds = lappend(newcmds, cmd);
					break;
				}

			case AT_AttachPartition:
			case AT_DetachPartition:
				{
					PartitionCmd *partcmd = (PartitionCmd *) cmd->def;

					if (!stmt->is_internal)
					{
						transformPartitionCmd(&cxt, partcmd);
						
						partcmd->bound = cxt.partbound;
					}
				}

				newcmds = lappend(newcmds, cmd);
				break;

			default:
				newcmds = lappend(newcmds, cmd);
				break;
		}
	}

	
	save_alist = cxt.alist;
	cxt.alist = NIL;

	
	transformIndexConstraints(&cxt);
	transformFKConstraints(&cxt, skipValidation, true);
	transformCheckConstraints(&cxt, false);

	
	foreach(l, cxt.alist)
	{
		Node	   *istmt = (Node *) lfirst(l);

		
		if (IsA(istmt, IndexStmt))
		{
			IndexStmt  *idxstmt = (IndexStmt *) istmt;

			idxstmt = transformIndexStmt(relid, idxstmt, queryString);
			newcmd = makeNode(AlterTableCmd);
			newcmd->subtype = OidIsValid(idxstmt->indexOid) ? AT_AddIndexConstraint : AT_AddIndex;
			newcmd->def = (Node *) idxstmt;
			newcmds = lappend(newcmds, newcmd);
		}
		else if (IsA(istmt, AlterTableStmt))
		{
			AlterTableStmt *alterstmt = (AlterTableStmt *) istmt;

			newcmds = list_concat(newcmds, alterstmt->cmds);
		}
		else elog(ERROR, "unexpected stmt type %d", (int) nodeTag(istmt));
	}
	cxt.alist = NIL;

	
	foreach(l, cxt.ckconstraints)
	{
		newcmd = makeNode(AlterTableCmd);
		newcmd->subtype = AT_AddConstraint;
		newcmd->def = (Node *) lfirst(l);
		newcmds = lappend(newcmds, newcmd);
	}
	foreach(l, cxt.fkconstraints)
	{
		newcmd = makeNode(AlterTableCmd);
		newcmd->subtype = AT_AddConstraint;
		newcmd->def = (Node *) lfirst(l);
		newcmds = lappend(newcmds, newcmd);
	}

	
	transformExtendedStatistics(&cxt);

	
	relation_close(rel, NoLock);

	
	stmt->cmds = newcmds;

	result = lappend(cxt.blist, stmt);
	result = list_concat(result, cxt.alist);
	result = list_concat(result, save_alist);

	return result;
}



static void transformConstraintAttrs(CreateStmtContext *cxt, List *constraintList)
{
	Constraint *lastprimarycon = NULL;
	bool		saw_deferrability = false;
	bool		saw_initially = false;
	ListCell   *clist;







	foreach(clist, constraintList)
	{
		Constraint *con = (Constraint *) lfirst(clist);

		if (!IsA(con, Constraint))
			elog(ERROR, "unrecognized node type: %d", (int) nodeTag(con));
		switch (con->contype)
		{
			case CONSTR_ATTR_DEFERRABLE:
				if (!SUPPORTS_ATTRS(lastprimarycon))
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("misplaced DEFERRABLE clause"), parser_errposition(cxt->pstate, con->location)));


				if (saw_deferrability)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("multiple DEFERRABLE/NOT DEFERRABLE clauses not allowed"), parser_errposition(cxt->pstate, con->location)));


				saw_deferrability = true;
				lastprimarycon->deferrable = true;
				break;

			case CONSTR_ATTR_NOT_DEFERRABLE:
				if (!SUPPORTS_ATTRS(lastprimarycon))
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("misplaced NOT DEFERRABLE clause"), parser_errposition(cxt->pstate, con->location)));


				if (saw_deferrability)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("multiple DEFERRABLE/NOT DEFERRABLE clauses not allowed"), parser_errposition(cxt->pstate, con->location)));


				saw_deferrability = true;
				lastprimarycon->deferrable = false;
				if (saw_initially && lastprimarycon->initdeferred)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("constraint declared INITIALLY DEFERRED must be DEFERRABLE"), parser_errposition(cxt->pstate, con->location)));


				break;

			case CONSTR_ATTR_DEFERRED:
				if (!SUPPORTS_ATTRS(lastprimarycon))
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("misplaced INITIALLY DEFERRED clause"), parser_errposition(cxt->pstate, con->location)));


				if (saw_initially)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("multiple INITIALLY IMMEDIATE/DEFERRED clauses not allowed"), parser_errposition(cxt->pstate, con->location)));


				saw_initially = true;
				lastprimarycon->initdeferred = true;

				
				if (!saw_deferrability)
					lastprimarycon->deferrable = true;
				else if (!lastprimarycon->deferrable)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("constraint declared INITIALLY DEFERRED must be DEFERRABLE"), parser_errposition(cxt->pstate, con->location)));


				break;

			case CONSTR_ATTR_IMMEDIATE:
				if (!SUPPORTS_ATTRS(lastprimarycon))
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("misplaced INITIALLY IMMEDIATE clause"), parser_errposition(cxt->pstate, con->location)));


				if (saw_initially)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("multiple INITIALLY IMMEDIATE/DEFERRED clauses not allowed"), parser_errposition(cxt->pstate, con->location)));


				saw_initially = true;
				lastprimarycon->initdeferred = false;
				break;

			default:
				
				lastprimarycon = con;
				
				saw_deferrability = false;
				saw_initially = false;
				break;
		}
	}
}


static void transformColumnType(CreateStmtContext *cxt, ColumnDef *column)
{
	
	Type		ctype = typenameType(cxt->pstate, column->typeName, NULL);

	if (column->collClause)
	{
		Form_pg_type typtup = (Form_pg_type) GETSTRUCT(ctype);

		LookupCollation(cxt->pstate, column->collClause->collname, column->collClause->location);

		
		if (!OidIsValid(typtup->typcollation))
			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("collations are not supported by type %s", format_type_be(typtup->oid)), parser_errposition(cxt->pstate, column->collClause->location)));




	}

	ReleaseSysCache(ctype);
}



List * transformCreateSchemaStmt(CreateSchemaStmt *stmt)
{
	CreateSchemaStmtContext cxt;
	List	   *result;
	ListCell   *elements;

	cxt.stmtType = "CREATE SCHEMA";
	cxt.schemaname = stmt->schemaname;
	cxt.authrole = (RoleSpec *) stmt->authrole;
	cxt.sequences = NIL;
	cxt.tables = NIL;
	cxt.views = NIL;
	cxt.indexes = NIL;
	cxt.triggers = NIL;
	cxt.grants = NIL;

	
	foreach(elements, stmt->schemaElts)
	{
		Node	   *element = lfirst(elements);

		switch (nodeTag(element))
		{
			case T_CreateSeqStmt:
				{
					CreateSeqStmt *elp = (CreateSeqStmt *) element;

					setSchemaName(cxt.schemaname, &elp->sequence->schemaname);
					cxt.sequences = lappend(cxt.sequences, element);
				}
				break;

			case T_CreateStmt:
				{
					CreateStmt *elp = (CreateStmt *) element;

					setSchemaName(cxt.schemaname, &elp->relation->schemaname);

					
					cxt.tables = lappend(cxt.tables, element);
				}
				break;

			case T_ViewStmt:
				{
					ViewStmt   *elp = (ViewStmt *) element;

					setSchemaName(cxt.schemaname, &elp->view->schemaname);

					
					cxt.views = lappend(cxt.views, element);
				}
				break;

			case T_IndexStmt:
				{
					IndexStmt  *elp = (IndexStmt *) element;

					setSchemaName(cxt.schemaname, &elp->relation->schemaname);
					cxt.indexes = lappend(cxt.indexes, element);
				}
				break;

			case T_CreateTrigStmt:
				{
					CreateTrigStmt *elp = (CreateTrigStmt *) element;

					setSchemaName(cxt.schemaname, &elp->relation->schemaname);
					cxt.triggers = lappend(cxt.triggers, element);
				}
				break;

			case T_GrantStmt:
				cxt.grants = lappend(cxt.grants, element);
				break;

			default:
				elog(ERROR, "unrecognized node type: %d", (int) nodeTag(element));
		}
	}

	result = NIL;
	result = list_concat(result, cxt.sequences);
	result = list_concat(result, cxt.tables);
	result = list_concat(result, cxt.views);
	result = list_concat(result, cxt.indexes);
	result = list_concat(result, cxt.triggers);
	result = list_concat(result, cxt.grants);

	return result;
}


static void setSchemaName(char *context_schema, char **stmt_schema_name)
{
	if (*stmt_schema_name == NULL)
		*stmt_schema_name = context_schema;
	else if (strcmp(context_schema, *stmt_schema_name) != 0)
		ereport(ERROR, (errcode(ERRCODE_INVALID_SCHEMA_DEFINITION), errmsg("CREATE specifies a schema (%s) " "different from the one being created (%s)", *stmt_schema_name, context_schema)));



}


static DistributedBy * getLikeDistributionPolicy(TableLikeClause *e)
{
	DistributedBy *likeDistributedBy = NULL;
	Relation	rel;

	rel = relation_openrv(e->relation, AccessShareLock);

	if (rel->rd_cdbpolicy != NULL && rel->rd_cdbpolicy->ptype != POLICYTYPE_ENTRY)
	{
		likeDistributedBy = make_distributedby_for_rel(rel);
	}

	relation_close(rel, AccessShareLock);

	return likeDistributedBy;
}



static void transformPartitionCmd(CreateStmtContext *cxt, PartitionCmd *cmd)
{
	Relation	parentRel = cxt->rel;

	switch (parentRel->rd_rel->relkind)
	{
		case RELKIND_PARTITIONED_TABLE:
			
			Assert(RelationGetPartitionKey(parentRel) != NULL);
			if (cmd->bound != NULL)
				cxt->partbound = transformPartitionBound(cxt->pstate, parentRel, cmd->bound);
			break;
		case RELKIND_PARTITIONED_INDEX:
			
			Assert(cmd->bound == NULL);
			break;
		case RELKIND_RELATION:
			
			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("table \"%s\" is not partitioned", RelationGetRelationName(parentRel))));


			break;
		case RELKIND_INDEX:
			
			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("index \"%s\" is not partitioned", RelationGetRelationName(parentRel))));


			break;
		default:
			
			elog(ERROR, "\"%s\" is not a partitioned table or index", RelationGetRelationName(parentRel));
			break;
	}
}


PartitionBoundSpec * transformPartitionBound(ParseState *pstate, Relation parent, PartitionBoundSpec *spec)

{
	PartitionBoundSpec *result_spec;
	PartitionKey key = RelationGetPartitionKey(parent);
	char		strategy = get_partition_strategy(key);
	int			partnatts = get_partition_natts(key);
	List	   *partexprs = get_partition_exprs(key);

	
	result_spec = copyObject(spec);

	if (spec->is_default)
	{
		if (strategy == PARTITION_STRATEGY_HASH)
			ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("a hash-partitioned table may not have a default partition")));


		
		result_spec->strategy = strategy;

		return result_spec;
	}

	if (strategy == PARTITION_STRATEGY_HASH)
	{
		if (spec->strategy != PARTITION_STRATEGY_HASH)
			ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("invalid bound specification for a hash partition"), parser_errposition(pstate, exprLocation((Node *) spec))));



		if (spec->modulus <= 0)
			ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("modulus for hash partition must be a positive integer")));


		Assert(spec->remainder >= 0);

		if (spec->remainder >= spec->modulus)
			ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("remainder for hash partition must be less than modulus")));

	}
	else if (strategy == PARTITION_STRATEGY_LIST)
	{
		ListCell   *cell;
		char	   *colname;
		Oid			coltype;
		int32		coltypmod;
		Oid			partcollation;

		if (spec->strategy != PARTITION_STRATEGY_LIST)
			ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("invalid bound specification for a list partition"), parser_errposition(pstate, exprLocation((Node *) spec))));



		
		if (key->partattrs[0] != 0)
			colname = get_attname(RelationGetRelid(parent), key->partattrs[0], false);
		else colname = deparse_expression((Node *) linitial(partexprs), deparse_context_for(RelationGetRelationName(parent), RelationGetRelid(parent)), false, false);



		
		coltype = get_partition_col_typid(key, 0);
		coltypmod = get_partition_col_typmod(key, 0);
		partcollation = get_partition_col_collation(key, 0);

		result_spec->listdatums = NIL;
		foreach(cell, spec->listdatums)
		{
			Node	   *expr = lfirst(cell);
			Const	   *value;
			ListCell   *cell2;
			bool		duplicate;

			value = transformPartitionBoundValue(pstate, expr, colname, coltype, coltypmod, partcollation);


			
			duplicate = false;
			foreach(cell2, result_spec->listdatums)
			{
				Const	   *value2 = castNode(Const, lfirst(cell2));

				if (equal(value, value2))
				{
					duplicate = true;
					break;
				}
			}
			if (duplicate)
				continue;

			result_spec->listdatums = lappend(result_spec->listdatums, value);
		}
	}
	else if (strategy == PARTITION_STRATEGY_RANGE)
	{
		if (spec->strategy != PARTITION_STRATEGY_RANGE)
			ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("invalid bound specification for a range partition"), parser_errposition(pstate, exprLocation((Node *) spec))));



		if (list_length(spec->lowerdatums) != partnatts)
			ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("FROM must specify exactly one value per partitioning column")));

		if (list_length(spec->upperdatums) != partnatts)
			ereport(ERROR, (errcode(ERRCODE_INVALID_TABLE_DEFINITION), errmsg("TO must specify exactly one value per partitioning column")));


		
		result_spec->lowerdatums = transformPartitionRangeBounds(pstate, spec->lowerdatums, parent);

		result_spec->upperdatums = transformPartitionRangeBounds(pstate, spec->upperdatums, parent);

	}
	else elog(ERROR, "unexpected partition strategy: %d", (int) strategy);

	return result_spec;
}


static List * transformPartitionRangeBounds(ParseState *pstate, List *blist, Relation parent)

{
	List	   *result = NIL;
	PartitionKey key = RelationGetPartitionKey(parent);
	List	   *partexprs = get_partition_exprs(key);
	ListCell   *lc;
	int			i, j;

	i = j = 0;
	foreach(lc, blist)
	{
		Node	   *expr = lfirst(lc);
		PartitionRangeDatum *prd = NULL;

		
		if (IsA(expr, ColumnRef))
		{
			ColumnRef  *cref = (ColumnRef *) expr;
			char	   *cname = NULL;

			
			if (list_length(cref->fields) == 1 && IsA(linitial(cref->fields), String))
				cname = strVal(linitial(cref->fields));

			if (cname == NULL)
			{
				
			}
			else if (strcmp("minvalue", cname) == 0)
			{
				prd = makeNode(PartitionRangeDatum);
				prd->kind = PARTITION_RANGE_DATUM_MINVALUE;
				prd->value = NULL;
			}
			else if (strcmp("maxvalue", cname) == 0)
			{
				prd = makeNode(PartitionRangeDatum);
				prd->kind = PARTITION_RANGE_DATUM_MAXVALUE;
				prd->value = NULL;
			}
		}
		else if (IsA(expr, PartitionRangeDatum))
		{
			
			prd = (PartitionRangeDatum *) expr;
		}

		if (prd == NULL)
		{
			char	   *colname;
			Oid			coltype;
			int32		coltypmod;
			Oid			partcollation;
			Const	   *value;

			
			if (key->partattrs[i] != 0)
				colname = get_attname(RelationGetRelid(parent), key->partattrs[i], false);
			else {
				colname = deparse_expression((Node *) list_nth(partexprs, j), deparse_context_for(RelationGetRelationName(parent), RelationGetRelid(parent)), false, false);


				++j;
			}

			
			coltype = get_partition_col_typid(key, i);
			coltypmod = get_partition_col_typmod(key, i);
			partcollation = get_partition_col_collation(key, i);

			value = transformPartitionBoundValue(pstate, expr, colname, coltype, coltypmod, partcollation);


			if (value->constisnull)
				ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("cannot specify NULL in range bound")));

			prd = makeNode(PartitionRangeDatum);
			prd->kind = PARTITION_RANGE_DATUM_VALUE;
			prd->value = (Node *) value;
			++i;
		}

		prd->location = exprLocation(expr);

		result = lappend(result, prd);
	}

	
	validateInfiniteBounds(pstate, result);

	return result;
}


static void validateInfiniteBounds(ParseState *pstate, List *blist)
{
	ListCell   *lc;
	PartitionRangeDatumKind kind = PARTITION_RANGE_DATUM_VALUE;

	foreach(lc, blist)
	{
		PartitionRangeDatum *prd = castNode(PartitionRangeDatum, lfirst(lc));

		if (kind == prd->kind)
			continue;

		switch (kind)
		{
			case PARTITION_RANGE_DATUM_VALUE:
				kind = prd->kind;
				break;

			case PARTITION_RANGE_DATUM_MAXVALUE:
				ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("every bound following MAXVALUE must also be MAXVALUE"), parser_errposition(pstate, exprLocation((Node *) prd))));


				break;

			case PARTITION_RANGE_DATUM_MINVALUE:
				ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("every bound following MINVALUE must also be MINVALUE"), parser_errposition(pstate, exprLocation((Node *) prd))));


				break;
		}
	}
}


Const * transformPartitionBoundValue(ParseState *pstate, Node *val, const char *colName, Oid colType, int32 colTypmod, Oid partCollation)


{
	Node	   *value;

	
	value = transformExpr(pstate, val, EXPR_KIND_PARTITION_BOUND);

	
	if (IsA(value, CollateExpr))
	{
		Oid			exprCollOid = exprCollation(value);

		if (OidIsValid(exprCollOid) && exprCollOid != DEFAULT_COLLATION_OID && exprCollOid != partCollation)

			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("collation of partition bound value for column \"%s\" does not match partition key collation \"%s\"", colName, get_collation_name(partCollation)), parser_errposition(pstate, exprLocation(value))));



	}

	
	value = coerce_to_target_type(pstate, value, exprType(value), colType, colTypmod, COERCION_ASSIGNMENT, COERCE_IMPLICIT_CAST, -1);






	if (value == NULL)
		ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("specified value cannot be cast to type %s for column \"%s\"", format_type_be(colType), colName), parser_errposition(pstate, exprLocation(val))));




	
	if (!IsA(value, Const))
		value = (Node *) expression_planner((Expr *) value);

	
	Assert(!contain_var_clause(value));

	
	value = (Node *) evaluate_expr((Expr *) value, colType, colTypmod, partCollation);
	if (!IsA(value, Const))
		elog(ERROR, "could not evaluate partition bound expression");

	return (Const *) value;
}
