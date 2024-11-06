










































typedef struct {
	Relation	rel;			
	int			natts;			
	int		   *atts;			
	
} RelToCheck;


Oid			binary_upgrade_next_array_pg_type_oid = InvalidOid;

static void makeRangeConstructors(const char *name, Oid namespace, Oid rangeOid, Oid subtype);
static Oid	findTypeInputFunction(List *procname, Oid typeOid);
static Oid	findTypeOutputFunction(List *procname, Oid typeOid);
static Oid	findTypeReceiveFunction(List *procname, Oid typeOid);
static Oid	findTypeSendFunction(List *procname, Oid typeOid);
static Oid	findTypeTypmodinFunction(List *procname);
static Oid	findTypeTypmodoutFunction(List *procname);
static Oid	findTypeAnalyzeFunction(List *procname, Oid typeOid);
static Oid	findRangeSubOpclass(List *opcname, Oid subtype);
static Oid	findRangeCanonicalFunction(List *procname, Oid typeOid);
static Oid	findRangeSubtypeDiffFunction(List *procname, Oid subtype);
static void validateDomainConstraint(Oid domainoid, char *ccbin);
static List *get_rels_with_domain(Oid domainOid, LOCKMODE lockmode);
static void checkEnumOwner(HeapTuple tup);
static char *domainAddConstraint(Oid domainOid, Oid domainNamespace, Oid baseTypeOid, int typMod, Constraint *constr, const char *domainName, ObjectAddress *constrAddr);


static Node *replace_domain_constraint_value(ParseState *pstate, ColumnRef *cref);



ObjectAddress DefineType(ParseState *pstate, List *names, List *parameters)
{
	char	   *typeName;
	Oid			typeNamespace;
	int16		internalLength = -1;	
	List	   *inputName = NIL;
	List	   *outputName = NIL;
	List	   *receiveName = NIL;
	List	   *sendName = NIL;
	List	   *typmodinName = NIL;
	List	   *typmodoutName = NIL;
	List	   *analyzeName = NIL;
	char		category = TYPCATEGORY_USER;
	bool		preferred = false;
	char		delimiter = DEFAULT_TYPDELIM;
	Oid			elemType = InvalidOid;
	char	   *defaultValue = NULL;
	bool		byValue = false;
	char		alignment = 'i';	
	char		storage = 'p';	
	Oid			collation = InvalidOid;
	DefElem    *likeTypeEl = NULL;
	DefElem    *internalLengthEl = NULL;
	DefElem    *inputNameEl = NULL;
	DefElem    *outputNameEl = NULL;
	DefElem    *receiveNameEl = NULL;
	DefElem    *sendNameEl = NULL;
	DefElem    *typmodinNameEl = NULL;
	DefElem    *typmodoutNameEl = NULL;
	DefElem    *analyzeNameEl = NULL;
	DefElem    *categoryEl = NULL;
	DefElem    *preferredEl = NULL;
	DefElem    *delimiterEl = NULL;
	DefElem    *elemTypeEl = NULL;
	DefElem    *defaultValueEl = NULL;
	DefElem    *byValueEl = NULL;
	DefElem    *alignmentEl = NULL;
	DefElem    *storageEl = NULL;
	DefElem    *collatableEl = NULL;
	Oid			inputOid;
	Oid			outputOid;
	Oid			receiveOid = InvalidOid;
	Oid			sendOid = InvalidOid;
	Oid			typmodinOid = InvalidOid;
	Oid			typmodoutOid = InvalidOid;
	Oid			analyzeOid = InvalidOid;
	char	   *array_type;
	Oid			array_oid;
	Oid			typoid;
	Oid			resulttype;
	ListCell   *pl;
	ObjectAddress address;

	
	if (!superuser())
		ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("must be superuser to create a base type")));


	
	typeNamespace = QualifiedNameGetCreationNamespace(names, &typeName);


	
	
	aclresult = pg_namespace_aclcheck(typeNamespace, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, OBJECT_SCHEMA, get_namespace_name(typeNamespace));


	
	typoid = GetSysCacheOid2(TYPENAMENSP, CStringGetDatum(typeName), ObjectIdGetDatum(typeNamespace));


	
	if (OidIsValid(typoid) && get_typisdefined(typoid))
	{
		if (moveArrayTypeName(typoid, typeName, typeNamespace))
			typoid = InvalidOid;
	}

	
	if (!OidIsValid(typoid))
	{
		address = TypeShellMake(typeName, typeNamespace, GetUserId());
		typoid = address.objectId;
		
		CommandCounterIncrement();

		
		if (parameters == NIL)
			return address;
	}
	else {
		
		if (parameters == NIL)
			ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("type \"%s\" already exists", typeName)));

	}

	
	foreach(pl, parameters)
	{
		DefElem    *defel = (DefElem *) lfirst(pl);
		DefElem   **defelp;

		if (strcmp(defel->defname, "like") == 0)
			defelp = &likeTypeEl;
		else if (strcmp(defel->defname, "internallength") == 0)
			defelp = &internalLengthEl;
		else if (strcmp(defel->defname, "input") == 0)
			defelp = &inputNameEl;
		else if (strcmp(defel->defname, "output") == 0)
			defelp = &outputNameEl;
		else if (strcmp(defel->defname, "receive") == 0)
			defelp = &receiveNameEl;
		else if (strcmp(defel->defname, "send") == 0)
			defelp = &sendNameEl;
		else if (strcmp(defel->defname, "typmod_in") == 0)
			defelp = &typmodinNameEl;
		else if (strcmp(defel->defname, "typmod_out") == 0)
			defelp = &typmodoutNameEl;
		else if (strcmp(defel->defname, "analyze") == 0 || strcmp(defel->defname, "analyse") == 0)
			defelp = &analyzeNameEl;
		else if (strcmp(defel->defname, "category") == 0)
			defelp = &categoryEl;
		else if (strcmp(defel->defname, "preferred") == 0)
			defelp = &preferredEl;
		else if (strcmp(defel->defname, "delimiter") == 0)
			defelp = &delimiterEl;
		else if (strcmp(defel->defname, "element") == 0)
			defelp = &elemTypeEl;
		else if (strcmp(defel->defname, "default") == 0)
			defelp = &defaultValueEl;
		else if (strcmp(defel->defname, "passedbyvalue") == 0)
			defelp = &byValueEl;
		else if (strcmp(defel->defname, "alignment") == 0)
			defelp = &alignmentEl;
		else if (strcmp(defel->defname, "storage") == 0)
			defelp = &storageEl;
		else if (strcmp(defel->defname, "collatable") == 0)
			defelp = &collatableEl;
		else {
			
			ereport(WARNING, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("type attribute \"%s\" not recognized", defel->defname), parser_errposition(pstate, defel->location)));



			continue;
		}
		if (*defelp != NULL)
			ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options"), parser_errposition(pstate, defel->location)));


		*defelp = defel;
	}

	
	if (likeTypeEl)
	{
		Type		likeType;
		Form_pg_type likeForm;

		likeType = typenameType(NULL, defGetTypeName(likeTypeEl), NULL);
		likeForm = (Form_pg_type) GETSTRUCT(likeType);
		internalLength = likeForm->typlen;
		byValue = likeForm->typbyval;
		alignment = likeForm->typalign;
		storage = likeForm->typstorage;
		ReleaseSysCache(likeType);
	}
	if (internalLengthEl)
		internalLength = defGetTypeLength(internalLengthEl);
	if (inputNameEl)
		inputName = defGetQualifiedName(inputNameEl);
	if (outputNameEl)
		outputName = defGetQualifiedName(outputNameEl);
	if (receiveNameEl)
		receiveName = defGetQualifiedName(receiveNameEl);
	if (sendNameEl)
		sendName = defGetQualifiedName(sendNameEl);
	if (typmodinNameEl)
		typmodinName = defGetQualifiedName(typmodinNameEl);
	if (typmodoutNameEl)
		typmodoutName = defGetQualifiedName(typmodoutNameEl);
	if (analyzeNameEl)
		analyzeName = defGetQualifiedName(analyzeNameEl);
	if (categoryEl)
	{
		char	   *p = defGetString(categoryEl);

		category = p[0];
		
		if (category < 32 || category > 126)
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid type category \"%s\": must be simple ASCII", p)));


	}
	if (preferredEl)
		preferred = defGetBoolean(preferredEl);
	if (delimiterEl)
	{
		char	   *p = defGetString(delimiterEl);

		delimiter = p[0];
		
	}
	if (elemTypeEl)
	{
		elemType = typenameTypeId(NULL, defGetTypeName(elemTypeEl));
		
		if (get_typtype(elemType) == TYPTYPE_PSEUDO)
			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("array element type cannot be %s", format_type_be(elemType))));


	}
	if (defaultValueEl)
		defaultValue = defGetString(defaultValueEl);
	if (byValueEl)
		byValue = defGetBoolean(byValueEl);
	if (alignmentEl)
	{
		char	   *a = defGetString(alignmentEl);

		
		if (pg_strcasecmp(a, "double") == 0 || pg_strcasecmp(a, "float8") == 0 || pg_strcasecmp(a, "pg_catalog.float8") == 0)

			alignment = 'd';
		else if (pg_strcasecmp(a, "int4") == 0 || pg_strcasecmp(a, "pg_catalog.int4") == 0)
			alignment = 'i';
		else if (pg_strcasecmp(a, "int2") == 0 || pg_strcasecmp(a, "pg_catalog.int2") == 0)
			alignment = 's';
		else if (pg_strcasecmp(a, "char") == 0 || pg_strcasecmp(a, "pg_catalog.bpchar") == 0)
			alignment = 'c';
		else ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("alignment \"%s\" not recognized", a)));


	}
	if (storageEl)
	{
		char	   *a = defGetString(storageEl);

		if (pg_strcasecmp(a, "plain") == 0)
			storage = 'p';
		else if (pg_strcasecmp(a, "external") == 0)
			storage = 'e';
		else if (pg_strcasecmp(a, "extended") == 0)
			storage = 'x';
		else if (pg_strcasecmp(a, "main") == 0)
			storage = 'm';
		else ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("storage \"%s\" not recognized", a)));


	}
	if (collatableEl)
		collation = defGetBoolean(collatableEl) ? DEFAULT_COLLATION_OID : InvalidOid;

	
	if (inputName == NIL)
		ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("type input function must be specified")));

	if (outputName == NIL)
		ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("type output function must be specified")));


	if (typmodinName == NIL && typmodoutName != NIL)
		ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("type modifier output function is useless without a type modifier input function")));


	
	inputOid = findTypeInputFunction(inputName, typoid);
	outputOid = findTypeOutputFunction(outputName, typoid);
	if (receiveName)
		receiveOid = findTypeReceiveFunction(receiveName, typoid);
	if (sendName)
		sendOid = findTypeSendFunction(sendName, typoid);

	
	resulttype = get_func_rettype(inputOid);
	if (resulttype != typoid)
	{
		if (resulttype == OPAQUEOID)
		{
			
			ereport(WARNING, (errmsg("changing return type of function %s from %s to %s", NameListToString(inputName), "opaque", typeName)));

			SetFunctionReturnType(inputOid, typoid);
		}
		else ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("type input function %s must return type %s", NameListToString(inputName), typeName)));



	}
	resulttype = get_func_rettype(outputOid);
	if (resulttype != CSTRINGOID)
	{
		if (resulttype == OPAQUEOID)
		{
			
			ereport(WARNING, (errmsg("changing return type of function %s from %s to %s", NameListToString(outputName), "opaque", "cstring")));

			SetFunctionReturnType(outputOid, CSTRINGOID);
		}
		else ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("type output function %s must return type %s", NameListToString(outputName), "cstring")));



	}
	if (receiveOid)
	{
		resulttype = get_func_rettype(receiveOid);
		if (resulttype != typoid)
			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("type receive function %s must return type %s", NameListToString(receiveName), typeName)));


	}
	if (sendOid)
	{
		resulttype = get_func_rettype(sendOid);
		if (resulttype != BYTEAOID)
			ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("type send function %s must return type %s", NameListToString(sendName), "bytea")));


	}

	
	if (typmodinName)
		typmodinOid = findTypeTypmodinFunction(typmodinName);
	if (typmodoutName)
		typmodoutOid = findTypeTypmodoutFunction(typmodoutName);

	
	if (analyzeName)
		analyzeOid = findTypeAnalyzeFunction(analyzeName, typoid);

	

	
	if (inputOid && !pg_proc_ownercheck(inputOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, OBJECT_FUNCTION, NameListToString(inputName));
	if (outputOid && !pg_proc_ownercheck(outputOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, OBJECT_FUNCTION, NameListToString(outputName));
	if (receiveOid && !pg_proc_ownercheck(receiveOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, OBJECT_FUNCTION, NameListToString(receiveName));
	if (sendOid && !pg_proc_ownercheck(sendOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, OBJECT_FUNCTION, NameListToString(sendName));
	if (typmodinOid && !pg_proc_ownercheck(typmodinOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, OBJECT_FUNCTION, NameListToString(typmodinName));
	if (typmodoutOid && !pg_proc_ownercheck(typmodoutOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, OBJECT_FUNCTION, NameListToString(typmodoutName));
	if (analyzeOid && !pg_proc_ownercheck(analyzeOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, OBJECT_FUNCTION, NameListToString(analyzeName));


	
	if (inputOid && func_volatile(inputOid) == PROVOLATILE_VOLATILE)
		ereport(WARNING, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("type input function %s should not be volatile", NameListToString(inputName))));


	if (outputOid && func_volatile(outputOid) == PROVOLATILE_VOLATILE)
		ereport(WARNING, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("type output function %s should not be volatile", NameListToString(outputName))));


	if (receiveOid && func_volatile(receiveOid) == PROVOLATILE_VOLATILE)
		ereport(WARNING, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("type receive function %s should not be volatile", NameListToString(receiveName))));


	if (sendOid && func_volatile(sendOid) == PROVOLATILE_VOLATILE)
		ereport(WARNING, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("type send function %s should not be volatile", NameListToString(sendName))));


	if (typmodinOid && func_volatile(typmodinOid) == PROVOLATILE_VOLATILE)
		ereport(WARNING, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("type modifier input function %s should not be volatile", NameListToString(typmodinName))));


	if (typmodoutOid && func_volatile(typmodoutOid) == PROVOLATILE_VOLATILE)
		ereport(WARNING, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("type modifier output function %s should not be volatile", NameListToString(typmodoutName))));



	
	array_oid = AssignTypeArrayOid();

	
	address = TypeCreate(InvalidOid, typeName, typeNamespace, InvalidOid, 0, GetUserId(), internalLength, TYPTYPE_BASE, category, preferred, delimiter, inputOid, outputOid, receiveOid, sendOid, typmodinOid, typmodoutOid, analyzeOid, elemType, false, array_oid, InvalidOid, defaultValue, NULL, byValue, alignment, storage, -1, 0, false, collation);






























	Assert(typoid == address.objectId);

	
	array_type = makeArrayTypeName(typeName, typeNamespace);

	
	alignment = (alignment == 'd') ? 'd' : 'i';

	TypeCreate(array_oid,		 array_type, typeNamespace, InvalidOid, 0, GetUserId(), -1, TYPTYPE_BASE, TYPCATEGORY_ARRAY, false, delimiter, F_ARRAY_IN, F_ARRAY_OUT, F_ARRAY_RECV, F_ARRAY_SEND, typmodinOid, typmodoutOid, F_ARRAY_TYPANALYZE, typoid, true, InvalidOid, InvalidOid, NULL, NULL, false, alignment, 'x', -1, 0, false, collation);






























	pfree(array_type);

	return address;
}


void RemoveTypeById(Oid typeOid)
{
	Relation	relation;
	HeapTuple	tup;

	relation = heap_open(TypeRelationId, RowExclusiveLock);

	tup = SearchSysCache1(TYPEOID, ObjectIdGetDatum(typeOid));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for type %u", typeOid);

	CatalogTupleDelete(relation, &tup->t_self);

	
	if (((Form_pg_type) GETSTRUCT(tup))->typtype == TYPTYPE_ENUM)
		EnumValuesDelete(typeOid);

	
	if (((Form_pg_type) GETSTRUCT(tup))->typtype == TYPTYPE_RANGE)
		RangeDelete(typeOid);

	ReleaseSysCache(tup);

	heap_close(relation, RowExclusiveLock);
}



ObjectAddress DefineDomain(CreateDomainStmt *stmt)
{
	char	   *domainName;
	char	   *domainArrayName;
	Oid			domainNamespace;
	AclResult	aclresult;
	int16		internalLength;
	Oid			inputProcedure;
	Oid			outputProcedure;
	Oid			receiveProcedure;
	Oid			sendProcedure;
	Oid			analyzeProcedure;
	bool		byValue;
	char		category;
	char		delimiter;
	char		alignment;
	char		storage;
	char		typtype;
	Datum		datum;
	bool		isnull;
	char	   *defaultValue = NULL;
	char	   *defaultValueBin = NULL;
	bool		saw_default = false;
	bool		typNotNull = false;
	bool		nullDefined = false;
	int32		typNDims = list_length(stmt->typeName->arrayBounds);
	HeapTuple	typeTup;
	List	   *schema = stmt->constraints;
	ListCell   *listptr;
	Oid			basetypeoid;
	Oid			old_type_oid;
	Oid			domaincoll;
	Oid			domainArrayOid;
	Form_pg_type baseType;
	int32		basetypeMod;
	Oid			baseColl;
	ObjectAddress address;

	
	domainNamespace = QualifiedNameGetCreationNamespace(stmt->domainname, &domainName);

	
	aclresult = pg_namespace_aclcheck(domainNamespace, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, OBJECT_SCHEMA, get_namespace_name(domainNamespace));

	
	old_type_oid = GetSysCacheOid2(TYPENAMENSP, CStringGetDatum(domainName), ObjectIdGetDatum(domainNamespace));

	if (OidIsValid(old_type_oid))
	{
		if (!moveArrayTypeName(old_type_oid, domainName, domainNamespace))
			ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("type \"%s\" already exists", domainName)));

	}

	
	typeTup = typenameType(NULL, stmt->typeName, &basetypeMod);
	baseType = (Form_pg_type) GETSTRUCT(typeTup);
	basetypeoid = HeapTupleGetOid(typeTup);

	
	typtype = baseType->typtype;
	if (typtype != TYPTYPE_BASE && typtype != TYPTYPE_COMPOSITE && typtype != TYPTYPE_DOMAIN && typtype != TYPTYPE_ENUM && typtype != TYPTYPE_RANGE)



		ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("\"%s\" is not a valid base type for a domain", TypeNameToString(stmt->typeName))));



	aclresult = pg_type_aclcheck(basetypeoid, GetUserId(), ACL_USAGE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error_type(aclresult, basetypeoid);

	
	baseColl = baseType->typcollation;
	if (stmt->collClause)
		domaincoll = get_collation_oid(stmt->collClause->collname, false);
	else domaincoll = baseColl;

	
	if (OidIsValid(domaincoll) && !OidIsValid(baseColl))
		ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("collations are not supported by type %s", format_type_be(basetypeoid))));



	
	byValue = baseType->typbyval;

	
	alignment = baseType->typalign;

	
	storage = baseType->typstorage;

	
	internalLength = baseType->typlen;

	
	category = baseType->typcategory;

	
	delimiter = baseType->typdelim;

	
	inputProcedure = F_DOMAIN_IN;
	outputProcedure = baseType->typoutput;
	receiveProcedure = F_DOMAIN_RECV;
	sendProcedure = baseType->typsend;

	

	
	analyzeProcedure = baseType->typanalyze;

	
	datum = SysCacheGetAttr(TYPEOID, typeTup, Anum_pg_type_typdefault, &isnull);
	if (!isnull)
		defaultValue = TextDatumGetCString(datum);

	
	datum = SysCacheGetAttr(TYPEOID, typeTup, Anum_pg_type_typdefaultbin, &isnull);
	if (!isnull)
		defaultValueBin = TextDatumGetCString(datum);

	
	foreach(listptr, schema)
	{
		Constraint *constr = lfirst(listptr);

		if (!IsA(constr, Constraint))
			elog(ERROR, "unrecognized node type: %d", (int) nodeTag(constr));
		switch (constr->contype)
		{
			case CONSTR_DEFAULT:

				
				if (saw_default)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("multiple default expressions")));

				saw_default = true;

				if (constr->raw_expr)
				{
					ParseState *pstate;
					Node	   *defaultExpr;

					
					pstate = make_parsestate(NULL);

					
					defaultExpr = cookDefault(pstate, constr->raw_expr, basetypeoid, basetypeMod, domainName);



					
					if (defaultExpr == NULL || (IsA(defaultExpr, Const) && ((Const *) defaultExpr)->constisnull))

					{
						defaultValue = NULL;
						defaultValueBin = NULL;
					}
					else {
						
						defaultValue = deparse_expression(defaultExpr, NIL, false, false);

						defaultValueBin = nodeToString(defaultExpr);
					}
				}
				else {
					
					defaultValue = NULL;
					defaultValueBin = NULL;
				}
				break;

			case CONSTR_NOTNULL:
				if (nullDefined && !typNotNull)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting NULL/NOT NULL constraints")));

				typNotNull = true;
				nullDefined = true;
				break;

			case CONSTR_NULL:
				if (nullDefined && typNotNull)
					ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting NULL/NOT NULL constraints")));

				typNotNull = false;
				nullDefined = true;
				break;

			case CONSTR_CHECK:

				
				if (constr->is_no_inherit)
					ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("check constraints for domains cannot be marked NO INHERIT")));

				break;

				
			case CONSTR_UNIQUE:
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("unique constraints not possible for domains")));

				break;

			case CONSTR_PRIMARY:
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("primary key constraints not possible for domains")));

				break;

			case CONSTR_EXCLUSION:
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("exclusion constraints not possible for domains")));

				break;

			case CONSTR_FOREIGN:
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("foreign key constraints not possible for domains")));

				break;

			case CONSTR_ATTR_DEFERRABLE:
			case CONSTR_ATTR_NOT_DEFERRABLE:
			case CONSTR_ATTR_DEFERRED:
			case CONSTR_ATTR_IMMEDIATE:
				ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("specifying constraint deferrability not supported for domains")));

				break;

			default:
				elog(ERROR, "unrecognized constraint subtype: %d", (int) constr->contype);
				break;
		}
	}

	
	domainArrayOid = AssignTypeArrayOid();

	
	address = TypeCreate(InvalidOid, domainName, domainNamespace, InvalidOid, 0, GetUserId(), internalLength, TYPTYPE_DOMAIN, category, false, delimiter, inputProcedure, outputProcedure, receiveProcedure, sendProcedure, InvalidOid, InvalidOid, analyzeProcedure, InvalidOid, false, domainArrayOid, basetypeoid, defaultValue, defaultValueBin, byValue, alignment, storage, basetypeMod, typNDims, typNotNull, domaincoll);































	
	domainArrayName = makeArrayTypeName(domainName, domainNamespace);

	
	alignment = (alignment == 'd') ? 'd' : 'i';

	TypeCreate(domainArrayOid,	 domainArrayName, domainNamespace, InvalidOid, 0, GetUserId(), -1, TYPTYPE_BASE, TYPCATEGORY_ARRAY, false, delimiter, F_ARRAY_IN, F_ARRAY_OUT, F_ARRAY_RECV, F_ARRAY_SEND, InvalidOid, InvalidOid, F_ARRAY_TYPANALYZE, address.objectId, true, InvalidOid, InvalidOid, NULL, NULL, false, alignment, 'x', -1, 0, false, domaincoll);






























	pfree(domainArrayName);

	
	foreach(listptr, schema)
	{
		Constraint *constr = lfirst(listptr);

		

		switch (constr->contype)
		{
			case CONSTR_CHECK:
				domainAddConstraint(address.objectId, domainNamespace, basetypeoid, basetypeMod, constr, domainName, NULL);

				break;

				

			default:
				break;
		}

		
		CommandCounterIncrement();
	}

	
	ReleaseSysCache(typeTup);

	return address;
}



ObjectAddress DefineEnum(CreateEnumStmt *stmt)
{
	char	   *enumName;
	char	   *enumArrayName;
	Oid			enumNamespace;
	AclResult	aclresult;
	Oid			old_type_oid;
	Oid			enumArrayOid;
	ObjectAddress enumTypeAddr;

	
	enumNamespace = QualifiedNameGetCreationNamespace(stmt->typeName, &enumName);

	
	aclresult = pg_namespace_aclcheck(enumNamespace, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, OBJECT_SCHEMA, get_namespace_name(enumNamespace));

	
	old_type_oid = GetSysCacheOid2(TYPENAMENSP, CStringGetDatum(enumName), ObjectIdGetDatum(enumNamespace));

	if (OidIsValid(old_type_oid))
	{
		if (!moveArrayTypeName(old_type_oid, enumName, enumNamespace))
			ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("type \"%s\" already exists", enumName)));

	}

	
	enumArrayOid = AssignTypeArrayOid();

	
	enumTypeAddr = TypeCreate(InvalidOid, enumName, enumNamespace, InvalidOid, 0, GetUserId(), sizeof(Oid), TYPTYPE_ENUM, TYPCATEGORY_ENUM, false, DEFAULT_TYPDELIM, F_ENUM_IN, F_ENUM_OUT, F_ENUM_RECV, F_ENUM_SEND, InvalidOid, InvalidOid, InvalidOid, InvalidOid, false, enumArrayOid, InvalidOid, NULL, NULL, true, 'i', 'p', -1, 0, false, InvalidOid);































	
	EnumValuesCreate(enumTypeAddr.objectId, stmt->vals);

	
	enumArrayName = makeArrayTypeName(enumName, enumNamespace);

	TypeCreate(enumArrayOid,	 enumArrayName, enumNamespace, InvalidOid, 0, GetUserId(), -1, TYPTYPE_BASE, TYPCATEGORY_ARRAY, false, DEFAULT_TYPDELIM, F_ARRAY_IN, F_ARRAY_OUT, F_ARRAY_RECV, F_ARRAY_SEND, InvalidOid, InvalidOid, F_ARRAY_TYPANALYZE, enumTypeAddr.objectId, true, InvalidOid, InvalidOid, NULL, NULL, false, 'i', 'x', -1, 0, false, InvalidOid);






























	pfree(enumArrayName);

	return enumTypeAddr;
}


ObjectAddress AlterEnum(AlterEnumStmt *stmt, bool isTopLevel)
{
	Oid			enum_type_oid;
	TypeName   *typename;
	HeapTuple	tup;
	ObjectAddress address;

	
	typename = makeTypeNameFromNameList(stmt->typeName);
	enum_type_oid = typenameTypeId(NULL, typename);

	tup = SearchSysCache1(TYPEOID, ObjectIdGetDatum(enum_type_oid));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for type %u", enum_type_oid);

	
	checkEnumOwner(tup);

	if (stmt->oldVal)
	{
		
		RenameEnumLabel(enum_type_oid, stmt->oldVal, stmt->newVal);
	}
	else {
		

		
		if (HeapTupleHeaderGetXmin(tup->t_data) == GetCurrentTransactionId() && !(tup->t_data->t_infomask & HEAP_UPDATED))
			  ;
		else PreventInTransactionBlock(isTopLevel, "ALTER TYPE ... ADD");

		AddEnumLabel(enum_type_oid, stmt->newVal, stmt->newValNeighbor, stmt->newValIsAfter, stmt->skipIfNewValExists);

	}

	InvokeObjectPostAlterHook(TypeRelationId, enum_type_oid, 0);

	ObjectAddressSet(address, TypeRelationId, enum_type_oid);

	ReleaseSysCache(tup);

	return address;
}



static void checkEnumOwner(HeapTuple tup)
{
	Form_pg_type typTup = (Form_pg_type) GETSTRUCT(tup);

	
	if (typTup->typtype != TYPTYPE_ENUM)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("%s is not an enum", format_type_be(HeapTupleGetOid(tup)))));



	
	if (!pg_type_ownercheck(HeapTupleGetOid(tup), GetUserId()))
		aclcheck_error_type(ACLCHECK_NOT_OWNER, HeapTupleGetOid(tup));
}



ObjectAddress DefineRange(CreateRangeStmt *stmt)
{
	char	   *typeName;
	Oid			typeNamespace;
	Oid			typoid;
	char	   *rangeArrayName;
	Oid			rangeArrayOid;
	Oid			rangeSubtype = InvalidOid;
	List	   *rangeSubOpclassName = NIL;
	List	   *rangeCollationName = NIL;
	List	   *rangeCanonicalName = NIL;
	List	   *rangeSubtypeDiffName = NIL;
	Oid			rangeSubOpclass;
	Oid			rangeCollation;
	regproc		rangeCanonical;
	regproc		rangeSubtypeDiff;
	int16		subtyplen;
	bool		subtypbyval;
	char		subtypalign;
	char		alignment;
	AclResult	aclresult;
	ListCell   *lc;
	ObjectAddress address;

	
	typeNamespace = QualifiedNameGetCreationNamespace(stmt->typeName, &typeName);

	
	aclresult = pg_namespace_aclcheck(typeNamespace, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, OBJECT_SCHEMA, get_namespace_name(typeNamespace));

	
	typoid = GetSysCacheOid2(TYPENAMENSP, CStringGetDatum(typeName), ObjectIdGetDatum(typeNamespace));


	
	if (OidIsValid(typoid) && get_typisdefined(typoid))
	{
		if (moveArrayTypeName(typoid, typeName, typeNamespace))
			typoid = InvalidOid;
		else ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("type \"%s\" already exists", typeName)));


	}

	
	if (!OidIsValid(typoid))
	{
		address = TypeShellMake(typeName, typeNamespace, GetUserId());
		typoid = address.objectId;
		
		CommandCounterIncrement();
	}

	
	foreach(lc, stmt->params)
	{
		DefElem    *defel = (DefElem *) lfirst(lc);

		if (strcmp(defel->defname, "subtype") == 0)
		{
			if (OidIsValid(rangeSubtype))
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options")));

			
			rangeSubtype = typenameTypeId(NULL, defGetTypeName(defel));
		}
		else if (strcmp(defel->defname, "subtype_opclass") == 0)
		{
			if (rangeSubOpclassName != NIL)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options")));

			rangeSubOpclassName = defGetQualifiedName(defel);
		}
		else if (strcmp(defel->defname, "collation") == 0)
		{
			if (rangeCollationName != NIL)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options")));

			rangeCollationName = defGetQualifiedName(defel);
		}
		else if (strcmp(defel->defname, "canonical") == 0)
		{
			if (rangeCanonicalName != NIL)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options")));

			rangeCanonicalName = defGetQualifiedName(defel);
		}
		else if (strcmp(defel->defname, "subtype_diff") == 0)
		{
			if (rangeSubtypeDiffName != NIL)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options")));

			rangeSubtypeDiffName = defGetQualifiedName(defel);
		}
		else ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("type attribute \"%s\" not recognized", defel->defname)));



	}

	
	if (!OidIsValid(rangeSubtype))
		ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("type attribute \"subtype\" is required")));

	
	if (get_typtype(rangeSubtype) == TYPTYPE_PSEUDO)
		ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("range subtype cannot be %s", format_type_be(rangeSubtype))));



	
	rangeSubOpclass = findRangeSubOpclass(rangeSubOpclassName, rangeSubtype);

	
	if (type_is_collatable(rangeSubtype))
	{
		if (rangeCollationName != NIL)
			rangeCollation = get_collation_oid(rangeCollationName, false);
		else rangeCollation = get_typcollation(rangeSubtype);
	}
	else {
		if (rangeCollationName != NIL)
			ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("range collation specified but subtype does not support collation")));

		rangeCollation = InvalidOid;
	}

	
	if (rangeCanonicalName != NIL)
		rangeCanonical = findRangeCanonicalFunction(rangeCanonicalName, typoid);
	else rangeCanonical = InvalidOid;

	if (rangeSubtypeDiffName != NIL)
		rangeSubtypeDiff = findRangeSubtypeDiffFunction(rangeSubtypeDiffName, rangeSubtype);
	else rangeSubtypeDiff = InvalidOid;

	get_typlenbyvalalign(rangeSubtype, &subtyplen, &subtypbyval, &subtypalign);

	
	alignment = (subtypalign == 'd') ? 'd' : 'i';

	
	rangeArrayOid = AssignTypeArrayOid();

	
	address = TypeCreate(InvalidOid, typeName, typeNamespace, InvalidOid, 0, GetUserId(), -1, TYPTYPE_RANGE, TYPCATEGORY_RANGE, false, DEFAULT_TYPDELIM, F_RANGE_IN, F_RANGE_OUT, F_RANGE_RECV, F_RANGE_SEND, InvalidOid, InvalidOid, F_RANGE_TYPANALYZE, InvalidOid, false, rangeArrayOid, InvalidOid, NULL, NULL, false, alignment, 'x', -1, 0, false, InvalidOid);






























	Assert(typoid == address.objectId);

	
	RangeCreate(typoid, rangeSubtype, rangeCollation, rangeSubOpclass, rangeCanonical, rangeSubtypeDiff);

	
	rangeArrayName = makeArrayTypeName(typeName, typeNamespace);

	TypeCreate(rangeArrayOid,	 rangeArrayName, typeNamespace, InvalidOid, 0, GetUserId(), -1, TYPTYPE_BASE, TYPCATEGORY_ARRAY, false, DEFAULT_TYPDELIM, F_ARRAY_IN, F_ARRAY_OUT, F_ARRAY_RECV, F_ARRAY_SEND, InvalidOid, InvalidOid, F_ARRAY_TYPANALYZE, typoid, true, InvalidOid, InvalidOid, NULL, NULL, false, alignment, 'x', -1, 0, false, InvalidOid);






























	pfree(rangeArrayName);

	
	makeRangeConstructors(typeName, typeNamespace, typoid, rangeSubtype);

	return address;
}


static void makeRangeConstructors(const char *name, Oid namespace, Oid rangeOid, Oid subtype)

{
	static const char *const prosrc[2] = {"range_constructor2", "range_constructor3";
	static const int pronargs[2] = {2, 3};

	Oid			constructorArgTypes[3];
	ObjectAddress myself, referenced;
	int			i;

	constructorArgTypes[0] = subtype;
	constructorArgTypes[1] = subtype;
	constructorArgTypes[2] = TEXTOID;

	referenced.classId = TypeRelationId;
	referenced.objectId = rangeOid;
	referenced.objectSubId = 0;

	for (i = 0; i < lengthof(prosrc); i++)
	{
		oidvector  *constructorArgTypesVector;

		constructorArgTypesVector = buildoidvector(constructorArgTypes, pronargs[i]);

		myself = ProcedureCreate(name,	 namespace, false, false, rangeOid, BOOTSTRAP_SUPERUSERID, INTERNALlanguageId, F_FMGR_INTERNAL_VALIDATOR, prosrc[i], NULL, PROKIND_FUNCTION, false, false, false, PROVOLATILE_IMMUTABLE, PROPARALLEL_SAFE, constructorArgTypesVector, PointerGetDatum(NULL), PointerGetDatum(NULL), PointerGetDatum(NULL), NIL, PointerGetDatum(NULL), PointerGetDatum(NULL), 1.0, 0.0);
























		
		recordDependencyOn(&myself, &referenced, DEPENDENCY_INTERNAL);
	}
}




static Oid findTypeInputFunction(List *procname, Oid typeOid)
{
	Oid			argList[3];
	Oid			procOid;

	
	argList[0] = CSTRINGOID;

	procOid = LookupFuncName(procname, 1, argList, true);
	if (OidIsValid(procOid))
		return procOid;

	argList[1] = OIDOID;
	argList[2] = INT4OID;

	procOid = LookupFuncName(procname, 3, argList, true);
	if (OidIsValid(procOid))
		return procOid;

	
	argList[0] = OPAQUEOID;

	procOid = LookupFuncName(procname, 1, argList, true);

	if (!OidIsValid(procOid))
	{
		argList[1] = OIDOID;
		argList[2] = INT4OID;

		procOid = LookupFuncName(procname, 3, argList, true);
	}

	if (OidIsValid(procOid))
	{
		
		ereport(WARNING, (errmsg("changing argument type of function %s from \"opaque\" to \"cstring\"", NameListToString(procname))));

		SetFunctionArgType(procOid, 0, CSTRINGOID);

		
		CommandCounterIncrement();

		return procOid;
	}

	
	argList[0] = CSTRINGOID;

	ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("function %s does not exist", func_signature_string(procname, 1, NIL, argList))));



	return InvalidOid;			
}

static Oid findTypeOutputFunction(List *procname, Oid typeOid)
{
	Oid			argList[1];
	Oid			procOid;

	
	argList[0] = typeOid;

	procOid = LookupFuncName(procname, 1, argList, true);
	if (OidIsValid(procOid))
		return procOid;

	
	argList[0] = OPAQUEOID;

	procOid = LookupFuncName(procname, 1, argList, true);

	if (OidIsValid(procOid))
	{
		
		ereport(WARNING, (errmsg("changing argument type of function %s from \"opaque\" to %s", NameListToString(procname), format_type_be(typeOid))));

		SetFunctionArgType(procOid, 0, typeOid);

		
		CommandCounterIncrement();

		return procOid;
	}

	
	argList[0] = typeOid;

	ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("function %s does not exist", func_signature_string(procname, 1, NIL, argList))));



	return InvalidOid;			
}

static Oid findTypeReceiveFunction(List *procname, Oid typeOid)
{
	Oid			argList[3];
	Oid			procOid;

	
	argList[0] = INTERNALOID;

	procOid = LookupFuncName(procname, 1, argList, true);
	if (OidIsValid(procOid))
		return procOid;

	argList[1] = OIDOID;
	argList[2] = INT4OID;

	procOid = LookupFuncName(procname, 3, argList, true);
	if (OidIsValid(procOid))
		return procOid;

	ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("function %s does not exist", func_signature_string(procname, 1, NIL, argList))));



	return InvalidOid;			
}

static Oid findTypeSendFunction(List *procname, Oid typeOid)
{
	Oid			argList[1];
	Oid			procOid;

	
	argList[0] = typeOid;

	procOid = LookupFuncName(procname, 1, argList, true);
	if (OidIsValid(procOid))
		return procOid;

	ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("function %s does not exist", func_signature_string(procname, 1, NIL, argList))));



	return InvalidOid;			
}

static Oid findTypeTypmodinFunction(List *procname)
{
	Oid			argList[1];
	Oid			procOid;

	
	argList[0] = CSTRINGARRAYOID;

	procOid = LookupFuncName(procname, 1, argList, true);
	if (!OidIsValid(procOid))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("function %s does not exist", func_signature_string(procname, 1, NIL, argList))));



	if (get_func_rettype(procOid) != INT4OID)
		ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("typmod_in function %s must return type %s", NameListToString(procname), "integer")));



	return procOid;
}

static Oid findTypeTypmodoutFunction(List *procname)
{
	Oid			argList[1];
	Oid			procOid;

	
	argList[0] = INT4OID;

	procOid = LookupFuncName(procname, 1, argList, true);
	if (!OidIsValid(procOid))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("function %s does not exist", func_signature_string(procname, 1, NIL, argList))));



	if (get_func_rettype(procOid) != CSTRINGOID)
		ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("typmod_out function %s must return type %s", NameListToString(procname), "cstring")));



	return procOid;
}

static Oid findTypeAnalyzeFunction(List *procname, Oid typeOid)
{
	Oid			argList[1];
	Oid			procOid;

	
	argList[0] = INTERNALOID;

	procOid = LookupFuncName(procname, 1, argList, true);
	if (!OidIsValid(procOid))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("function %s does not exist", func_signature_string(procname, 1, NIL, argList))));



	if (get_func_rettype(procOid) != BOOLOID)
		ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("type analyze function %s must return type %s", NameListToString(procname), "boolean")));



	return procOid;
}




static Oid findRangeSubOpclass(List *opcname, Oid subtype)
{
	Oid			opcid;
	Oid			opInputType;

	if (opcname != NIL)
	{
		opcid = get_opclass_oid(BTREE_AM_OID, opcname, false);

		
		opInputType = get_opclass_input_type(opcid);
		if (!IsBinaryCoercible(subtype, opInputType))
			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("operator class \"%s\" does not accept data type %s", NameListToString(opcname), format_type_be(subtype))));



	}
	else {
		opcid = GetDefaultOpClass(subtype, BTREE_AM_OID);
		if (!OidIsValid(opcid))
		{
			
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("data type %s has no default operator class for access method \"%s\"", format_type_be(subtype), "btree"), errhint("You must specify an operator class for the range type or define a default operator class for the subtype.")));



		}
	}

	return opcid;
}

static Oid findRangeCanonicalFunction(List *procname, Oid typeOid)
{
	Oid			argList[1];
	Oid			procOid;
	AclResult	aclresult;

	
	argList[0] = typeOid;

	procOid = LookupFuncName(procname, 1, argList, true);

	if (!OidIsValid(procOid))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("function %s does not exist", func_signature_string(procname, 1, NIL, argList))));



	if (get_func_rettype(procOid) != typeOid)
		ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("range canonical function %s must return range type", func_signature_string(procname, 1, NIL, argList))));



	if (func_volatile(procOid) != PROVOLATILE_IMMUTABLE)
		ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("range canonical function %s must be immutable", func_signature_string(procname, 1, NIL, argList))));



	
	aclresult = pg_proc_aclcheck(procOid, GetUserId(), ACL_EXECUTE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, OBJECT_FUNCTION, get_func_name(procOid));

	return procOid;
}

static Oid findRangeSubtypeDiffFunction(List *procname, Oid subtype)
{
	Oid			argList[2];
	Oid			procOid;
	AclResult	aclresult;

	
	argList[0] = subtype;
	argList[1] = subtype;

	procOid = LookupFuncName(procname, 2, argList, true);

	if (!OidIsValid(procOid))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("function %s does not exist", func_signature_string(procname, 2, NIL, argList))));



	if (get_func_rettype(procOid) != FLOAT8OID)
		ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("range subtype diff function %s must return type %s", func_signature_string(procname, 2, NIL, argList), "double precision")));




	if (func_volatile(procOid) != PROVOLATILE_IMMUTABLE)
		ereport(ERROR, (errcode(ERRCODE_INVALID_OBJECT_DEFINITION), errmsg("range subtype diff function %s must be immutable", func_signature_string(procname, 2, NIL, argList))));



	
	aclresult = pg_proc_aclcheck(procOid, GetUserId(), ACL_EXECUTE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, OBJECT_FUNCTION, get_func_name(procOid));

	return procOid;
}


Oid AssignTypeArrayOid(void)
{
	Oid			type_array_oid;

	
	if (IsBinaryUpgrade)
	{
		if (!OidIsValid(binary_upgrade_next_array_pg_type_oid))
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("pg_type array OID value not set when in binary upgrade mode")));


		type_array_oid = binary_upgrade_next_array_pg_type_oid;
		binary_upgrade_next_array_pg_type_oid = InvalidOid;
	}
	else {
		Relation	pg_type = heap_open(TypeRelationId, AccessShareLock);

		type_array_oid = GetNewOid(pg_type);
		heap_close(pg_type, AccessShareLock);
	}

	return type_array_oid;
}



ObjectAddress DefineCompositeType(RangeVar *typevar, List *coldeflist)
{
	CreateStmt *createStmt = makeNode(CreateStmt);
	Oid			old_type_oid;
	Oid			typeNamespace;
	ObjectAddress address;

	
	createStmt->relation = typevar;
	createStmt->tableElts = coldeflist;
	createStmt->inhRelations = NIL;
	createStmt->constraints = NIL;
	createStmt->options = NIL;
	createStmt->oncommit = ONCOMMIT_NOOP;
	createStmt->tablespacename = NULL;
	createStmt->if_not_exists = false;

	
	typeNamespace = RangeVarGetAndCheckCreationNamespace(createStmt->relation, NoLock, NULL);
	RangeVarAdjustRelationPersistence(createStmt->relation, typeNamespace);
	old_type_oid = GetSysCacheOid2(TYPENAMENSP, CStringGetDatum(createStmt->relation->relname), ObjectIdGetDatum(typeNamespace));


	if (OidIsValid(old_type_oid))
	{
		if (!moveArrayTypeName(old_type_oid, createStmt->relation->relname, typeNamespace))
			ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("type \"%s\" already exists", createStmt->relation->relname)));

	}

	
	DefineRelation(createStmt, RELKIND_COMPOSITE_TYPE, InvalidOid, &address, NULL);

	return address;
}


ObjectAddress AlterDomainDefault(List *names, Node *defaultRaw)
{
	TypeName   *typename;
	Oid			domainoid;
	HeapTuple	tup;
	ParseState *pstate;
	Relation	rel;
	char	   *defaultValue;
	Node	   *defaultExpr = NULL; 
	Acl		   *typacl;
	Datum		aclDatum;
	bool		isNull;
	Datum		new_record[Natts_pg_type];
	bool		new_record_nulls[Natts_pg_type];
	bool		new_record_repl[Natts_pg_type];
	HeapTuple	newtuple;
	Form_pg_type typTup;
	ObjectAddress address;

	
	typename = makeTypeNameFromNameList(names);
	domainoid = typenameTypeId(NULL, typename);

	
	rel = heap_open(TypeRelationId, RowExclusiveLock);

	tup = SearchSysCacheCopy1(TYPEOID, ObjectIdGetDatum(domainoid));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for type %u", domainoid);
	typTup = (Form_pg_type) GETSTRUCT(tup);

	
	checkDomainOwner(tup);

	
	MemSet(new_record, (Datum) 0, sizeof(new_record));
	MemSet(new_record_nulls, false, sizeof(new_record_nulls));
	MemSet(new_record_repl, false, sizeof(new_record_repl));

	
	if (defaultRaw)
	{
		
		pstate = make_parsestate(NULL);

		
		defaultExpr = cookDefault(pstate, defaultRaw, typTup->typbasetype, typTup->typtypmod, NameStr(typTup->typname));



		
		if (defaultExpr == NULL || (IsA(defaultExpr, Const) &&((Const *) defaultExpr)->constisnull))
		{
			
			new_record_nulls[Anum_pg_type_typdefaultbin - 1] = true;
			new_record_repl[Anum_pg_type_typdefaultbin - 1] = true;
			new_record_nulls[Anum_pg_type_typdefault - 1] = true;
			new_record_repl[Anum_pg_type_typdefault - 1] = true;
		}
		else {
			
			defaultValue = deparse_expression(defaultExpr, NIL, false, false);

			
			new_record[Anum_pg_type_typdefaultbin - 1] = CStringGetTextDatum(nodeToString(defaultExpr));

			new_record_repl[Anum_pg_type_typdefaultbin - 1] = true;
			new_record[Anum_pg_type_typdefault - 1] = CStringGetTextDatum(defaultValue);
			new_record_repl[Anum_pg_type_typdefault - 1] = true;
		}
	}
	else {
		
		new_record_nulls[Anum_pg_type_typdefaultbin - 1] = true;
		new_record_repl[Anum_pg_type_typdefaultbin - 1] = true;
		new_record_nulls[Anum_pg_type_typdefault - 1] = true;
		new_record_repl[Anum_pg_type_typdefault - 1] = true;
	}

	newtuple = heap_modify_tuple(tup, RelationGetDescr(rel), new_record, new_record_nulls, new_record_repl);


	CatalogTupleUpdate(rel, &tup->t_self, newtuple);

	
	aclDatum = heap_getattr(newtuple, Anum_pg_type_typacl, RelationGetDescr(rel), &isNull);
	if (isNull)
		typacl = NULL;
	else typacl = DatumGetAclPCopy(aclDatum);

	
	GenerateTypeDependencies(domainoid, (Form_pg_type) GETSTRUCT(newtuple), defaultExpr, typacl, 0, false, false, true);







	InvokeObjectPostAlterHook(TypeRelationId, domainoid, 0);

	ObjectAddressSet(address, TypeRelationId, domainoid);

	
	heap_close(rel, NoLock);
	heap_freetuple(newtuple);

	return address;
}


ObjectAddress AlterDomainNotNull(List *names, bool notNull)
{
	TypeName   *typename;
	Oid			domainoid;
	Relation	typrel;
	HeapTuple	tup;
	Form_pg_type typTup;
	ObjectAddress address = InvalidObjectAddress;

	
	typename = makeTypeNameFromNameList(names);
	domainoid = typenameTypeId(NULL, typename);

	
	typrel = heap_open(TypeRelationId, RowExclusiveLock);

	tup = SearchSysCacheCopy1(TYPEOID, ObjectIdGetDatum(domainoid));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for type %u", domainoid);
	typTup = (Form_pg_type) GETSTRUCT(tup);

	
	checkDomainOwner(tup);

	
	if (typTup->typnotnull == notNull)
	{
		heap_close(typrel, RowExclusiveLock);
		return address;
	}

	
	if (notNull)
	{
		List	   *rels;
		ListCell   *rt;

		
		

		rels = get_rels_with_domain(domainoid, ShareLock);

		foreach(rt, rels)
		{
			RelToCheck *rtc = (RelToCheck *) lfirst(rt);
			Relation	testrel = rtc->rel;
			TupleDesc	tupdesc = RelationGetDescr(testrel);
			HeapScanDesc scan;
			HeapTuple	tuple;
			Snapshot	snapshot;

			
			snapshot = RegisterSnapshot(GetLatestSnapshot());
			scan = heap_beginscan(testrel, snapshot, 0, NULL);
			while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
			{
				int			i;

				
				for (i = 0; i < rtc->natts; i++)
				{
					int			attnum = rtc->atts[i];
					Form_pg_attribute attr = TupleDescAttr(tupdesc, attnum - 1);

					if (heap_attisnull(tuple, attnum, tupdesc))
					{
						
						ereport(ERROR, (errcode(ERRCODE_NOT_NULL_VIOLATION), errmsg("column \"%s\" of table \"%s\" contains null values", NameStr(attr->attname), RelationGetRelationName(testrel)), errtablecol(testrel, attnum)));




					}
				}
			}
			heap_endscan(scan);
			UnregisterSnapshot(snapshot);

			
			heap_close(testrel, NoLock);
		}
	}

	
	typTup->typnotnull = notNull;

	CatalogTupleUpdate(typrel, &tup->t_self, tup);

	InvokeObjectPostAlterHook(TypeRelationId, domainoid, 0);

	ObjectAddressSet(address, TypeRelationId, domainoid);

	
	heap_freetuple(tup);
	heap_close(typrel, RowExclusiveLock);

	return address;
}


ObjectAddress AlterDomainDropConstraint(List *names, const char *constrName, DropBehavior behavior, bool missing_ok)

{
	TypeName   *typename;
	Oid			domainoid;
	HeapTuple	tup;
	Relation	rel;
	Relation	conrel;
	SysScanDesc conscan;
	ScanKeyData skey[3];
	HeapTuple	contup;
	bool		found = false;
	ObjectAddress address;

	
	typename = makeTypeNameFromNameList(names);
	domainoid = typenameTypeId(NULL, typename);

	
	rel = heap_open(TypeRelationId, RowExclusiveLock);

	tup = SearchSysCacheCopy1(TYPEOID, ObjectIdGetDatum(domainoid));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for type %u", domainoid);

	
	checkDomainOwner(tup);

	
	conrel = heap_open(ConstraintRelationId, RowExclusiveLock);

	
	ScanKeyInit(&skey[0], Anum_pg_constraint_conrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(InvalidOid));


	ScanKeyInit(&skey[1], Anum_pg_constraint_contypid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(domainoid));


	ScanKeyInit(&skey[2], Anum_pg_constraint_conname, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(constrName));



	conscan = systable_beginscan(conrel, ConstraintRelidTypidNameIndexId, true, NULL, 3, skey);

	
	if ((contup = systable_getnext(conscan)) != NULL)
	{
		ObjectAddress conobj;

		conobj.classId = ConstraintRelationId;
		conobj.objectId = HeapTupleGetOid(contup);
		conobj.objectSubId = 0;

		performDeletion(&conobj, behavior, 0);
		found = true;
	}

	
	systable_endscan(conscan);
	heap_close(conrel, RowExclusiveLock);

	heap_close(rel, NoLock);

	if (!found)
	{
		if (!missing_ok)
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("constraint \"%s\" of domain \"%s\" does not exist", constrName, TypeNameToString(typename))));


		else ereport(NOTICE, (errmsg("constraint \"%s\" of domain \"%s\" does not exist, skipping", constrName, TypeNameToString(typename))));


	}

	ObjectAddressSet(address, TypeRelationId, domainoid);

	return address;
}


ObjectAddress AlterDomainAddConstraint(List *names, Node *newConstraint, ObjectAddress *constrAddr)

{
	TypeName   *typename;
	Oid			domainoid;
	Relation	typrel;
	HeapTuple	tup;
	Form_pg_type typTup;
	Constraint *constr;
	char	   *ccbin;
	ObjectAddress address;

	
	typename = makeTypeNameFromNameList(names);
	domainoid = typenameTypeId(NULL, typename);

	
	typrel = heap_open(TypeRelationId, RowExclusiveLock);

	tup = SearchSysCacheCopy1(TYPEOID, ObjectIdGetDatum(domainoid));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for type %u", domainoid);
	typTup = (Form_pg_type) GETSTRUCT(tup);

	
	checkDomainOwner(tup);

	if (!IsA(newConstraint, Constraint))
		elog(ERROR, "unrecognized node type: %d", (int) nodeTag(newConstraint));

	constr = (Constraint *) newConstraint;

	switch (constr->contype)
	{
		case CONSTR_CHECK:
			
			break;

		case CONSTR_UNIQUE:
			ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("unique constraints not possible for domains")));

			break;

		case CONSTR_PRIMARY:
			ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("primary key constraints not possible for domains")));

			break;

		case CONSTR_EXCLUSION:
			ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("exclusion constraints not possible for domains")));

			break;

		case CONSTR_FOREIGN:
			ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("foreign key constraints not possible for domains")));

			break;

		case CONSTR_ATTR_DEFERRABLE:
		case CONSTR_ATTR_NOT_DEFERRABLE:
		case CONSTR_ATTR_DEFERRED:
		case CONSTR_ATTR_IMMEDIATE:
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("specifying constraint deferrability not supported for domains")));

			break;

		default:
			elog(ERROR, "unrecognized constraint subtype: %d", (int) constr->contype);
			break;
	}

	

	ccbin = domainAddConstraint(domainoid, typTup->typnamespace, typTup->typbasetype, typTup->typtypmod, constr, NameStr(typTup->typname), constrAddr);


	
	if (!constr->skip_validation)
		validateDomainConstraint(domainoid, ccbin);

	ObjectAddressSet(address, TypeRelationId, domainoid);

	
	heap_close(typrel, RowExclusiveLock);

	return address;
}


ObjectAddress AlterDomainValidateConstraint(List *names, const char *constrName)
{
	TypeName   *typename;
	Oid			domainoid;
	Relation	typrel;
	Relation	conrel;
	HeapTuple	tup;
	Form_pg_constraint con;
	Form_pg_constraint copy_con;
	char	   *conbin;
	SysScanDesc scan;
	Datum		val;
	bool		isnull;
	HeapTuple	tuple;
	HeapTuple	copyTuple;
	ScanKeyData skey[3];
	ObjectAddress address;

	
	typename = makeTypeNameFromNameList(names);
	domainoid = typenameTypeId(NULL, typename);

	
	typrel = heap_open(TypeRelationId, AccessShareLock);

	tup = SearchSysCache1(TYPEOID, ObjectIdGetDatum(domainoid));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for type %u", domainoid);

	
	checkDomainOwner(tup);

	
	conrel = heap_open(ConstraintRelationId, RowExclusiveLock);

	ScanKeyInit(&skey[0], Anum_pg_constraint_conrelid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(InvalidOid));


	ScanKeyInit(&skey[1], Anum_pg_constraint_contypid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(domainoid));


	ScanKeyInit(&skey[2], Anum_pg_constraint_conname, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(constrName));



	scan = systable_beginscan(conrel, ConstraintRelidTypidNameIndexId, true, NULL, 3, skey);

	
	if (!HeapTupleIsValid(tuple = systable_getnext(scan)))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("constraint \"%s\" of domain \"%s\" does not exist", constrName, TypeNameToString(typename))));



	con = (Form_pg_constraint) GETSTRUCT(tuple);
	if (con->contype != CONSTRAINT_CHECK)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("constraint \"%s\" of domain \"%s\" is not a check constraint", constrName, TypeNameToString(typename))));



	val = SysCacheGetAttr(CONSTROID, tuple, Anum_pg_constraint_conbin, &isnull);

	if (isnull)
		elog(ERROR, "null conbin for constraint %u", HeapTupleGetOid(tuple));
	conbin = TextDatumGetCString(val);

	validateDomainConstraint(domainoid, conbin);

	
	copyTuple = heap_copytuple(tuple);
	copy_con = (Form_pg_constraint) GETSTRUCT(copyTuple);
	copy_con->convalidated = true;
	CatalogTupleUpdate(conrel, &copyTuple->t_self, copyTuple);

	InvokeObjectPostAlterHook(ConstraintRelationId, HeapTupleGetOid(copyTuple), 0);

	ObjectAddressSet(address, TypeRelationId, domainoid);

	heap_freetuple(copyTuple);

	systable_endscan(scan);

	heap_close(typrel, AccessShareLock);
	heap_close(conrel, RowExclusiveLock);

	ReleaseSysCache(tup);

	return address;
}

static void validateDomainConstraint(Oid domainoid, char *ccbin)
{
	Expr	   *expr = (Expr *) stringToNode(ccbin);
	List	   *rels;
	ListCell   *rt;
	EState	   *estate;
	ExprContext *econtext;
	ExprState  *exprstate;

	
	estate = CreateExecutorState();
	econtext = GetPerTupleExprContext(estate);

	
	exprstate = ExecPrepareExpr(expr, estate);

	
	

	rels = get_rels_with_domain(domainoid, ShareLock);

	foreach(rt, rels)
	{
		RelToCheck *rtc = (RelToCheck *) lfirst(rt);
		Relation	testrel = rtc->rel;
		TupleDesc	tupdesc = RelationGetDescr(testrel);
		HeapScanDesc scan;
		HeapTuple	tuple;
		Snapshot	snapshot;

		
		snapshot = RegisterSnapshot(GetLatestSnapshot());
		scan = heap_beginscan(testrel, snapshot, 0, NULL);
		while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
		{
			int			i;

			
			for (i = 0; i < rtc->natts; i++)
			{
				int			attnum = rtc->atts[i];
				Datum		d;
				bool		isNull;
				Datum		conResult;
				Form_pg_attribute attr = TupleDescAttr(tupdesc, attnum - 1);

				d = heap_getattr(tuple, attnum, tupdesc, &isNull);

				econtext->domainValue_datum = d;
				econtext->domainValue_isNull = isNull;

				conResult = ExecEvalExprSwitchContext(exprstate, econtext, &isNull);


				if (!isNull && !DatumGetBool(conResult))
				{
					
					ereport(ERROR, (errcode(ERRCODE_CHECK_VIOLATION), errmsg("column \"%s\" of table \"%s\" contains values that violate the new constraint", NameStr(attr->attname), RelationGetRelationName(testrel)), errtablecol(testrel, attnum)));




				}
			}

			ResetExprContext(econtext);
		}
		heap_endscan(scan);
		UnregisterSnapshot(snapshot);

		
		heap_close(testrel, NoLock);
	}

	FreeExecutorState(estate);
}


static List * get_rels_with_domain(Oid domainOid, LOCKMODE lockmode)
{
	List	   *result = NIL;
	char	   *domainTypeName = format_type_be(domainOid);
	Relation	depRel;
	ScanKeyData key[2];
	SysScanDesc depScan;
	HeapTuple	depTup;

	Assert(lockmode != NoLock);

	
	check_stack_depth();

	
	depRel = heap_open(DependRelationId, AccessShareLock);

	ScanKeyInit(&key[0], Anum_pg_depend_refclassid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(TypeRelationId));


	ScanKeyInit(&key[1], Anum_pg_depend_refobjid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(domainOid));



	depScan = systable_beginscan(depRel, DependReferenceIndexId, true, NULL, 2, key);

	while (HeapTupleIsValid(depTup = systable_getnext(depScan)))
	{
		Form_pg_depend pg_depend = (Form_pg_depend) GETSTRUCT(depTup);
		RelToCheck *rtc = NULL;
		ListCell   *rellist;
		Form_pg_attribute pg_att;
		int			ptr;

		
		if (pg_depend->classid == TypeRelationId)
		{
			if (get_typtype(pg_depend->objid) == TYPTYPE_DOMAIN)
			{
				
				result = list_concat(result, get_rels_with_domain(pg_depend->objid, lockmode));

			}
			else {
				
				find_composite_type_dependencies(pg_depend->objid, NULL, domainTypeName);

			}
			continue;
		}

		
		
		if (pg_depend->classid != RelationRelationId || pg_depend->objsubid <= 0)
			continue;

		
		foreach(rellist, result)
		{
			RelToCheck *rt = (RelToCheck *) lfirst(rellist);

			if (RelationGetRelid(rt->rel) == pg_depend->objid)
			{
				rtc = rt;
				break;
			}
		}

		if (rtc == NULL)
		{
			
			Relation	rel;

			
			rel = relation_open(pg_depend->objid, lockmode);

			
			if (OidIsValid(rel->rd_rel->reltype))
				find_composite_type_dependencies(rel->rd_rel->reltype, NULL, domainTypeName);


			
			if (rel->rd_rel->relkind != RELKIND_RELATION && rel->rd_rel->relkind != RELKIND_MATVIEW)
			{
				relation_close(rel, lockmode);
				continue;
			}

			
			rtc = (RelToCheck *) palloc(sizeof(RelToCheck));
			rtc->rel = rel;
			rtc->natts = 0;
			rtc->atts = (int *) palloc(sizeof(int) * RelationGetNumberOfAttributes(rel));
			result = lcons(rtc, result);
		}

		
		if (pg_depend->objsubid > RelationGetNumberOfAttributes(rtc->rel))
			continue;
		pg_att = TupleDescAttr(rtc->rel->rd_att, pg_depend->objsubid - 1);
		if (pg_att->attisdropped || pg_att->atttypid != domainOid)
			continue;

		
		Assert(rtc->natts < RelationGetNumberOfAttributes(rtc->rel));

		ptr = rtc->natts++;
		while (ptr > 0 && rtc->atts[ptr - 1] > pg_depend->objsubid)
		{
			rtc->atts[ptr] = rtc->atts[ptr - 1];
			ptr--;
		}
		rtc->atts[ptr] = pg_depend->objsubid;
	}

	systable_endscan(depScan);

	relation_close(depRel, AccessShareLock);

	return result;
}


void checkDomainOwner(HeapTuple tup)
{
	Form_pg_type typTup = (Form_pg_type) GETSTRUCT(tup);

	
	if (typTup->typtype != TYPTYPE_DOMAIN)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("%s is not a domain", format_type_be(HeapTupleGetOid(tup)))));



	
	if (!pg_type_ownercheck(HeapTupleGetOid(tup), GetUserId()))
		aclcheck_error_type(ACLCHECK_NOT_OWNER, HeapTupleGetOid(tup));
}


static char * domainAddConstraint(Oid domainOid, Oid domainNamespace, Oid baseTypeOid, int typMod, Constraint *constr, const char *domainName, ObjectAddress *constrAddr)


{
	Node	   *expr;
	char	   *ccsrc;
	char	   *ccbin;
	ParseState *pstate;
	CoerceToDomainValue *domVal;
	Oid			ccoid;

	
	if (constr->conname)
	{
		if (ConstraintNameIsUsed(CONSTRAINT_DOMAIN, domainOid, constr->conname))

			ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("constraint \"%s\" for domain \"%s\" already exists", constr->conname, domainName)));


	}
	else constr->conname = ChooseConstraintName(domainName, NULL, "check", domainNamespace, NIL);





	
	pstate = make_parsestate(NULL);

	
	domVal = makeNode(CoerceToDomainValue);
	domVal->typeId = baseTypeOid;
	domVal->typeMod = typMod;
	domVal->collation = get_typcollation(baseTypeOid);
	domVal->location = -1;		

	pstate->p_pre_columnref_hook = replace_domain_constraint_value;
	pstate->p_ref_hook_state = (void *) domVal;

	expr = transformExpr(pstate, constr->raw_expr, EXPR_KIND_DOMAIN_CHECK);

	
	expr = coerce_to_boolean(pstate, expr, "CHECK");

	
	assign_expr_collations(pstate, expr);

	
	if (list_length(pstate->p_rtable) != 0 || contain_var_clause(expr))
		ereport(ERROR, (errcode(ERRCODE_INVALID_COLUMN_REFERENCE), errmsg("cannot use table references in domain check constraint")));


	
	ccbin = nodeToString(expr);

	
	ccsrc = deparse_expression(expr, NIL, false, false);

	
	ccoid = CreateConstraintEntry(constr->conname, domainNamespace, CONSTRAINT_CHECK, false, false, !constr->skip_validation, InvalidOid, InvalidOid, NULL, 0, 0, domainOid, InvalidOid, InvalidOid, NULL, NULL, NULL, NULL, 0, ' ', ' ', ' ', NULL, expr, ccbin, ccsrc, true, 0, false, false);





























	if (constrAddr)
		ObjectAddressSet(*constrAddr, ConstraintRelationId, ccoid);

	
	return ccbin;
}


static Node * replace_domain_constraint_value(ParseState *pstate, ColumnRef *cref)
{
	
	if (list_length(cref->fields) == 1)
	{
		Node	   *field1 = (Node *) linitial(cref->fields);
		char	   *colname;

		Assert(IsA(field1, String));
		colname = strVal(field1);
		if (strcmp(colname, "value") == 0)
		{
			CoerceToDomainValue *domVal = copyObject(pstate->p_ref_hook_state);

			
			domVal->location = cref->location;
			return (Node *) domVal;
		}
	}
	return NULL;
}



ObjectAddress RenameType(RenameStmt *stmt)
{
	List	   *names = castNode(List, stmt->object);
	const char *newTypeName = stmt->newname;
	TypeName   *typename;
	Oid			typeOid;
	Relation	rel;
	HeapTuple	tup;
	Form_pg_type typTup;
	ObjectAddress address;

	
	typename = makeTypeNameFromNameList(names);
	typeOid = typenameTypeId(NULL, typename);

	
	rel = heap_open(TypeRelationId, RowExclusiveLock);

	tup = SearchSysCacheCopy1(TYPEOID, ObjectIdGetDatum(typeOid));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for type %u", typeOid);
	typTup = (Form_pg_type) GETSTRUCT(tup);

	
	if (!pg_type_ownercheck(typeOid, GetUserId()))
		aclcheck_error_type(ACLCHECK_NOT_OWNER, typeOid);

	
	if (stmt->renameType == OBJECT_DOMAIN && typTup->typtype != TYPTYPE_DOMAIN)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("%s is not a domain", format_type_be(typeOid))));



	
	if (typTup->typtype == TYPTYPE_COMPOSITE && get_rel_relkind(typTup->typrelid) != RELKIND_COMPOSITE_TYPE)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("%s is a table's row type", format_type_be(typeOid)), errhint("Use ALTER TABLE instead.")));




	
	if (OidIsValid(typTup->typelem) && get_array_type(typTup->typelem) == typeOid)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cannot alter array type %s", format_type_be(typeOid)), errhint("You can alter type %s, which will alter the array type as well.", format_type_be(typTup->typelem))));





	
	if (typTup->typtype == TYPTYPE_COMPOSITE)
		RenameRelationInternal(typTup->typrelid, newTypeName, false);
	else RenameTypeInternal(typeOid, newTypeName, typTup->typnamespace);


	ObjectAddressSet(address, TypeRelationId, typeOid);
	
	heap_close(rel, RowExclusiveLock);

	return address;
}


ObjectAddress AlterTypeOwner(List *names, Oid newOwnerId, ObjectType objecttype)
{
	TypeName   *typename;
	Oid			typeOid;
	Relation	rel;
	HeapTuple	tup;
	HeapTuple	newtup;
	Form_pg_type typTup;
	AclResult	aclresult;
	ObjectAddress address;

	rel = heap_open(TypeRelationId, RowExclusiveLock);

	
	typename = makeTypeNameFromNameList(names);

	
	tup = LookupTypeName(NULL, typename, NULL, false);
	if (tup == NULL)
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("type \"%s\" does not exist", TypeNameToString(typename))));


	typeOid = typeTypeId(tup);

	
	newtup = heap_copytuple(tup);
	ReleaseSysCache(tup);
	tup = newtup;
	typTup = (Form_pg_type) GETSTRUCT(tup);

	
	if (objecttype == OBJECT_DOMAIN && typTup->typtype != TYPTYPE_DOMAIN)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("%s is not a domain", format_type_be(typeOid))));



	
	if (typTup->typtype == TYPTYPE_COMPOSITE && get_rel_relkind(typTup->typrelid) != RELKIND_COMPOSITE_TYPE)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("%s is a table's row type", format_type_be(typeOid)), errhint("Use ALTER TABLE instead.")));




	
	if (OidIsValid(typTup->typelem) && get_array_type(typTup->typelem) == typeOid)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cannot alter array type %s", format_type_be(typeOid)), errhint("You can alter type %s, which will alter the array type as well.", format_type_be(typTup->typelem))));





	
	if (typTup->typowner != newOwnerId)
	{
		
		if (!superuser())
		{
			
			if (!pg_type_ownercheck(HeapTupleGetOid(tup), GetUserId()))
				aclcheck_error_type(ACLCHECK_NOT_OWNER, HeapTupleGetOid(tup));

			
			check_is_member_of_role(GetUserId(), newOwnerId);

			
			aclresult = pg_namespace_aclcheck(typTup->typnamespace, newOwnerId, ACL_CREATE);

			if (aclresult != ACLCHECK_OK)
				aclcheck_error(aclresult, OBJECT_SCHEMA, get_namespace_name(typTup->typnamespace));
		}

		AlterTypeOwner_oid(typeOid, newOwnerId, true);
	}

	ObjectAddressSet(address, TypeRelationId, typeOid);

	
	heap_close(rel, RowExclusiveLock);

	return address;
}


void AlterTypeOwner_oid(Oid typeOid, Oid newOwnerId, bool hasDependEntry)
{
	Relation	rel;
	HeapTuple	tup;
	Form_pg_type typTup;

	rel = heap_open(TypeRelationId, RowExclusiveLock);

	tup = SearchSysCache1(TYPEOID, ObjectIdGetDatum(typeOid));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for type %u", typeOid);
	typTup = (Form_pg_type) GETSTRUCT(tup);

	
	if (typTup->typtype == TYPTYPE_COMPOSITE)
		ATExecChangeOwner(typTup->typrelid, newOwnerId, true, AccessExclusiveLock);
	else AlterTypeOwnerInternal(typeOid, newOwnerId);

	
	if (hasDependEntry)
		changeDependencyOnOwner(TypeRelationId, typeOid, newOwnerId);

	InvokeObjectPostAlterHook(TypeRelationId, typeOid, 0);

	ReleaseSysCache(tup);
	heap_close(rel, RowExclusiveLock);
}


void AlterTypeOwnerInternal(Oid typeOid, Oid newOwnerId)
{
	Relation	rel;
	HeapTuple	tup;
	Form_pg_type typTup;
	Datum		repl_val[Natts_pg_type];
	bool		repl_null[Natts_pg_type];
	bool		repl_repl[Natts_pg_type];
	Acl		   *newAcl;
	Datum		aclDatum;
	bool		isNull;

	rel = heap_open(TypeRelationId, RowExclusiveLock);

	tup = SearchSysCacheCopy1(TYPEOID, ObjectIdGetDatum(typeOid));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for type %u", typeOid);
	typTup = (Form_pg_type) GETSTRUCT(tup);

	memset(repl_null, false, sizeof(repl_null));
	memset(repl_repl, false, sizeof(repl_repl));

	repl_repl[Anum_pg_type_typowner - 1] = true;
	repl_val[Anum_pg_type_typowner - 1] = ObjectIdGetDatum(newOwnerId);

	aclDatum = heap_getattr(tup, Anum_pg_type_typacl, RelationGetDescr(rel), &isNull);


	
	if (!isNull)
	{
		newAcl = aclnewowner(DatumGetAclP(aclDatum), typTup->typowner, newOwnerId);
		repl_repl[Anum_pg_type_typacl - 1] = true;
		repl_val[Anum_pg_type_typacl - 1] = PointerGetDatum(newAcl);
	}

	tup = heap_modify_tuple(tup, RelationGetDescr(rel), repl_val, repl_null, repl_repl);

	CatalogTupleUpdate(rel, &tup->t_self, tup);

	
	if (OidIsValid(typTup->typarray))
		AlterTypeOwnerInternal(typTup->typarray, newOwnerId);

	
	heap_close(rel, RowExclusiveLock);
}


ObjectAddress AlterTypeNamespace(List *names, const char *newschema, ObjectType objecttype, Oid *oldschema)

{
	TypeName   *typename;
	Oid			typeOid;
	Oid			nspOid;
	Oid			oldNspOid;
	ObjectAddresses *objsMoved;
	ObjectAddress myself;

	
	typename = makeTypeNameFromNameList(names);
	typeOid = typenameTypeId(NULL, typename);

	
	if (objecttype == OBJECT_DOMAIN && get_typtype(typeOid) != TYPTYPE_DOMAIN)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("%s is not a domain", format_type_be(typeOid))));



	
	nspOid = LookupCreationNamespace(newschema);

	objsMoved = new_object_addresses();
	oldNspOid = AlterTypeNamespace_oid(typeOid, nspOid, objsMoved);
	free_object_addresses(objsMoved);

	if (oldschema)
		*oldschema = oldNspOid;

	ObjectAddressSet(myself, TypeRelationId, typeOid);

	return myself;
}

Oid AlterTypeNamespace_oid(Oid typeOid, Oid nspOid, ObjectAddresses *objsMoved)
{
	Oid			elemOid;

	
	if (!pg_type_ownercheck(typeOid, GetUserId()))
		aclcheck_error_type(ACLCHECK_NOT_OWNER, typeOid);

	
	elemOid = get_element_type(typeOid);
	if (OidIsValid(elemOid) && get_array_type(elemOid) == typeOid)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("cannot alter array type %s", format_type_be(typeOid)), errhint("You can alter type %s, which will alter the array type as well.", format_type_be(elemOid))));





	
	return AlterTypeNamespaceInternal(typeOid, nspOid, false, true, objsMoved);
}


Oid AlterTypeNamespaceInternal(Oid typeOid, Oid nspOid, bool isImplicitArray, bool errorOnTableType, ObjectAddresses *objsMoved)



{
	Relation	rel;
	HeapTuple	tup;
	Form_pg_type typform;
	Oid			oldNspOid;
	Oid			arrayOid;
	bool		isCompositeType;
	ObjectAddress thisobj;

	
	thisobj.classId = TypeRelationId;
	thisobj.objectId = typeOid;
	thisobj.objectSubId = 0;

	if (object_address_present(&thisobj, objsMoved))
		return InvalidOid;

	rel = heap_open(TypeRelationId, RowExclusiveLock);

	tup = SearchSysCacheCopy1(TYPEOID, ObjectIdGetDatum(typeOid));
	if (!HeapTupleIsValid(tup))
		elog(ERROR, "cache lookup failed for type %u", typeOid);
	typform = (Form_pg_type) GETSTRUCT(tup);

	oldNspOid = typform->typnamespace;
	arrayOid = typform->typarray;

	
	if (oldNspOid != nspOid)
	{
		
		CheckSetNamespace(oldNspOid, nspOid);

		
		if (SearchSysCacheExists2(TYPENAMENSP, NameGetDatum(&typform->typname), ObjectIdGetDatum(nspOid)))

			ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("type \"%s\" already exists in schema \"%s\"", NameStr(typform->typname), get_namespace_name(nspOid))));



	}

	
	isCompositeType = (typform->typtype == TYPTYPE_COMPOSITE && get_rel_relkind(typform->typrelid) == RELKIND_COMPOSITE_TYPE);


	
	if (typform->typtype == TYPTYPE_COMPOSITE && !isCompositeType && errorOnTableType)
		ereport(ERROR, (errcode(ERRCODE_WRONG_OBJECT_TYPE), errmsg("%s is a table's row type", format_type_be(typeOid)), errhint("Use ALTER TABLE instead.")));




	if (oldNspOid != nspOid)
	{
		

		
		typform->typnamespace = nspOid;

		CatalogTupleUpdate(rel, &tup->t_self, tup);
	}

	
	if (isCompositeType)
	{
		Relation	classRel;

		classRel = heap_open(RelationRelationId, RowExclusiveLock);

		AlterRelationNamespaceInternal(classRel, typform->typrelid, oldNspOid, nspOid, false, objsMoved);


		heap_close(classRel, RowExclusiveLock);

		
		AlterConstraintNamespaces(typform->typrelid, oldNspOid, nspOid, false, objsMoved);
	}
	else {
		
		if (typform->typtype == TYPTYPE_DOMAIN)
			AlterConstraintNamespaces(typeOid, oldNspOid, nspOid, true, objsMoved);
	}

	
	if (oldNspOid != nspOid && (isCompositeType || typform->typtype != TYPTYPE_COMPOSITE) && !isImplicitArray)

		if (changeDependencyFor(TypeRelationId, typeOid, NamespaceRelationId, oldNspOid, nspOid) != 1)
			elog(ERROR, "failed to change schema dependency for type %s", format_type_be(typeOid));

	InvokeObjectPostAlterHook(TypeRelationId, typeOid, 0);

	heap_freetuple(tup);

	heap_close(rel, RowExclusiveLock);

	add_exact_object_address(&thisobj, objsMoved);

	
	if (OidIsValid(arrayOid))
		AlterTypeNamespaceInternal(arrayOid, nspOid, true, true, objsMoved);

	return oldNspOid;
}
