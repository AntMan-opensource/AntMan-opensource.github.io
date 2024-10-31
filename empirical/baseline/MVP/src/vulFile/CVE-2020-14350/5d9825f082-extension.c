











































bool		creating_extension = false;
Oid			CurrentExtensionObject = InvalidOid;


typedef struct ExtensionControlFile {
	char	   *name;			
	char	   *directory;		
	char	   *default_version;	
	char	   *module_pathname;	
	char	   *comment;		
	char	   *schema;			
	bool		relocatable;	
	bool		superuser;		
	int			encoding;		
	List	   *requires;		
} ExtensionControlFile;


typedef struct ExtensionVersionInfo {
	char	   *name;			
	List	   *reachable;		
	bool		installable;	
	
	bool		distance_known; 
	int			distance;		
	struct ExtensionVersionInfo *previous;	
} ExtensionVersionInfo;


static List *find_update_path(List *evi_list, ExtensionVersionInfo *evi_start, ExtensionVersionInfo *evi_target, bool reject_indirect, bool reinitialize);



static Oid get_required_extension(char *reqExtensionName, char *extensionName, char *origSchemaName, bool cascade, List *parents, bool is_create);




static void get_available_versions_for_extension(ExtensionControlFile *pcontrol, Tuplestorestate *tupstore, TupleDesc tupdesc);

static Datum convert_requires_to_datum(List *requires);
static void ApplyExtensionUpdates(Oid extensionOid, ExtensionControlFile *pcontrol, const char *initialVersion, List *updateVersions, char *origSchemaName, bool cascade, bool is_create);





static char *read_whole_file(const char *filename, int *length);



Oid get_extension_oid(const char *extname, bool missing_ok)
{
	Oid			result;
	Relation	rel;
	SysScanDesc scandesc;
	HeapTuple	tuple;
	ScanKeyData entry[1];

	rel = heap_open(ExtensionRelationId, AccessShareLock);

	ScanKeyInit(&entry[0], Anum_pg_extension_extname, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(extname));



	scandesc = systable_beginscan(rel, ExtensionNameIndexId, true, NULL, 1, entry);

	tuple = systable_getnext(scandesc);

	
	if (HeapTupleIsValid(tuple))
		result = HeapTupleGetOid(tuple);
	else result = InvalidOid;

	systable_endscan(scandesc);

	heap_close(rel, AccessShareLock);

	if (!OidIsValid(result) && !missing_ok)
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("extension \"%s\" does not exist", extname)));



	return result;
}


char * get_extension_name(Oid ext_oid)
{
	char	   *result;
	Relation	rel;
	SysScanDesc scandesc;
	HeapTuple	tuple;
	ScanKeyData entry[1];

	rel = heap_open(ExtensionRelationId, AccessShareLock);

	ScanKeyInit(&entry[0], ObjectIdAttributeNumber, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(ext_oid));



	scandesc = systable_beginscan(rel, ExtensionOidIndexId, true, NULL, 1, entry);

	tuple = systable_getnext(scandesc);

	
	if (HeapTupleIsValid(tuple))
		result = pstrdup(NameStr(((Form_pg_extension) GETSTRUCT(tuple))->extname));
	else result = NULL;

	systable_endscan(scandesc);

	heap_close(rel, AccessShareLock);

	return result;
}


static Oid get_extension_schema(Oid ext_oid)
{
	Oid			result;
	Relation	rel;
	SysScanDesc scandesc;
	HeapTuple	tuple;
	ScanKeyData entry[1];

	rel = heap_open(ExtensionRelationId, AccessShareLock);

	ScanKeyInit(&entry[0], ObjectIdAttributeNumber, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(ext_oid));



	scandesc = systable_beginscan(rel, ExtensionOidIndexId, true, NULL, 1, entry);

	tuple = systable_getnext(scandesc);

	
	if (HeapTupleIsValid(tuple))
		result = ((Form_pg_extension) GETSTRUCT(tuple))->extnamespace;
	else result = InvalidOid;

	systable_endscan(scandesc);

	heap_close(rel, AccessShareLock);

	return result;
}


static void check_valid_extension_name(const char *extensionname)
{
	int			namelen = strlen(extensionname);

	
	if (namelen == 0)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid extension name: \"%s\"", extensionname), errdetail("Extension names must not be empty.")));



	
	if (strstr(extensionname, "--"))
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid extension name: \"%s\"", extensionname), errdetail("Extension names must not contain \"--\".")));



	
	if (extensionname[0] == '-' || extensionname[namelen - 1] == '-')
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid extension name: \"%s\"", extensionname), errdetail("Extension names must not begin or end with \"-\".")));



	
	if (first_dir_separator(extensionname) != NULL)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid extension name: \"%s\"", extensionname), errdetail("Extension names must not contain directory separator characters.")));


}

static void check_valid_version_name(const char *versionname)
{
	int			namelen = strlen(versionname);

	
	if (namelen == 0)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid extension version name: \"%s\"", versionname), errdetail("Version names must not be empty.")));



	
	if (strstr(versionname, "--"))
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid extension version name: \"%s\"", versionname), errdetail("Version names must not contain \"--\".")));



	
	if (versionname[0] == '-' || versionname[namelen - 1] == '-')
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid extension version name: \"%s\"", versionname), errdetail("Version names must not begin or end with \"-\".")));



	
	if (first_dir_separator(versionname) != NULL)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid extension version name: \"%s\"", versionname), errdetail("Version names must not contain directory separator characters.")));


}


static bool is_extension_control_filename(const char *filename)
{
	const char *extension = strrchr(filename, '.');

	return (extension != NULL) && (strcmp(extension, ".control") == 0);
}

static bool is_extension_script_filename(const char *filename)
{
	const char *extension = strrchr(filename, '.');

	return (extension != NULL) && (strcmp(extension, ".sql") == 0);
}

static char * get_extension_control_directory(void)
{
	char		sharepath[MAXPGPATH];
	char	   *result;

	get_share_path(my_exec_path, sharepath);
	result = (char *) palloc(MAXPGPATH);
	snprintf(result, MAXPGPATH, "%s/extension", sharepath);

	return result;
}

static char * get_extension_control_filename(const char *extname)
{
	char		sharepath[MAXPGPATH];
	char	   *result;

	get_share_path(my_exec_path, sharepath);
	result = (char *) palloc(MAXPGPATH);
	snprintf(result, MAXPGPATH, "%s/extension/%s.control", sharepath, extname);

	return result;
}

static char * get_extension_script_directory(ExtensionControlFile *control)
{
	char		sharepath[MAXPGPATH];
	char	   *result;

	
	if (!control->directory)
		return get_extension_control_directory();

	if (is_absolute_path(control->directory))
		return pstrdup(control->directory);

	get_share_path(my_exec_path, sharepath);
	result = (char *) palloc(MAXPGPATH);
	snprintf(result, MAXPGPATH, "%s/%s", sharepath, control->directory);

	return result;
}

static char * get_extension_aux_control_filename(ExtensionControlFile *control, const char *version)

{
	char	   *result;
	char	   *scriptdir;

	scriptdir = get_extension_script_directory(control);

	result = (char *) palloc(MAXPGPATH);
	snprintf(result, MAXPGPATH, "%s/%s--%s.control", scriptdir, control->name, version);

	pfree(scriptdir);

	return result;
}

static char * get_extension_script_filename(ExtensionControlFile *control, const char *from_version, const char *version)

{
	char	   *result;
	char	   *scriptdir;

	scriptdir = get_extension_script_directory(control);

	result = (char *) palloc(MAXPGPATH);
	if (from_version)
		snprintf(result, MAXPGPATH, "%s/%s--%s--%s.sql", scriptdir, control->name, from_version, version);
	else snprintf(result, MAXPGPATH, "%s/%s--%s.sql", scriptdir, control->name, version);


	pfree(scriptdir);

	return result;
}



static void parse_extension_control_file(ExtensionControlFile *control, const char *version)

{
	char	   *filename;
	FILE	   *file;
	ConfigVariable *item, *head = NULL, *tail = NULL;


	
	if (version)
		filename = get_extension_aux_control_filename(control, version);
	else filename = get_extension_control_filename(control->name);

	if ((file = AllocateFile(filename, "r")) == NULL)
	{
		if (version && errno == ENOENT)
		{
			
			pfree(filename);
			return;
		}
		ereport(ERROR, (errcode_for_file_access(), errmsg("could not open extension control file \"%s\": %m", filename)));


	}

	
	(void) ParseConfigFp(file, filename, 0, ERROR, &head, &tail);

	FreeFile(file);

	
	for (item = head; item != NULL; item = item->next)
	{
		if (strcmp(item->name, "directory") == 0)
		{
			if (version)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("parameter \"%s\" cannot be set in a secondary extension control file", item->name)));



			control->directory = pstrdup(item->value);
		}
		else if (strcmp(item->name, "default_version") == 0)
		{
			if (version)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("parameter \"%s\" cannot be set in a secondary extension control file", item->name)));



			control->default_version = pstrdup(item->value);
		}
		else if (strcmp(item->name, "module_pathname") == 0)
		{
			control->module_pathname = pstrdup(item->value);
		}
		else if (strcmp(item->name, "comment") == 0)
		{
			control->comment = pstrdup(item->value);
		}
		else if (strcmp(item->name, "schema") == 0)
		{
			control->schema = pstrdup(item->value);
		}
		else if (strcmp(item->name, "relocatable") == 0)
		{
			if (!parse_bool(item->value, &control->relocatable))
				ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("parameter \"%s\" requires a Boolean value", item->name)));


		}
		else if (strcmp(item->name, "superuser") == 0)
		{
			if (!parse_bool(item->value, &control->superuser))
				ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("parameter \"%s\" requires a Boolean value", item->name)));


		}
		else if (strcmp(item->name, "encoding") == 0)
		{
			control->encoding = pg_valid_server_encoding(item->value);
			if (control->encoding < 0)
				ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("\"%s\" is not a valid encoding name", item->value)));


		}
		else if (strcmp(item->name, "requires") == 0)
		{
			
			char	   *rawnames = pstrdup(item->value);

			
			if (!SplitIdentifierString(rawnames, ',', &control->requires))
			{
				
				ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("parameter \"%s\" must be a list of extension names", item->name)));


			}
		}
		else ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("unrecognized parameter \"%s\" in file \"%s\"", item->name, filename)));



	}

	FreeConfigVariables(head);

	if (control->relocatable && control->schema != NULL)
		ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("parameter \"schema\" cannot be specified when \"relocatable\" is true")));


	pfree(filename);
}


static ExtensionControlFile * read_extension_control_file(const char *extname)
{
	ExtensionControlFile *control;

	
	control = (ExtensionControlFile *) palloc0(sizeof(ExtensionControlFile));
	control->name = pstrdup(extname);
	control->relocatable = false;
	control->superuser = true;
	control->encoding = -1;

	
	parse_extension_control_file(control, NULL);

	return control;
}


static ExtensionControlFile * read_extension_aux_control_file(const ExtensionControlFile *pcontrol, const char *version)

{
	ExtensionControlFile *acontrol;

	
	acontrol = (ExtensionControlFile *) palloc(sizeof(ExtensionControlFile));
	memcpy(acontrol, pcontrol, sizeof(ExtensionControlFile));

	
	parse_extension_control_file(acontrol, version);

	return acontrol;
}


static char * read_extension_script_file(const ExtensionControlFile *control, const char *filename)

{
	int			src_encoding;
	char	   *src_str;
	char	   *dest_str;
	int			len;

	src_str = read_whole_file(filename, &len);

	
	if (control->encoding < 0)
		src_encoding = GetDatabaseEncoding();
	else src_encoding = control->encoding;

	
	pg_verify_mbstr_len(src_encoding, src_str, len, false);

	
	dest_str = pg_any_to_server(src_str, len, src_encoding);

	return dest_str;
}


static void execute_sql_string(const char *sql, const char *filename)
{
	List	   *raw_parsetree_list;
	DestReceiver *dest;
	ListCell   *lc1;

	
	raw_parsetree_list = pg_parse_query(sql);

	
	dest = CreateDestReceiver(DestNone);

	
	foreach(lc1, raw_parsetree_list)
	{
		RawStmt    *parsetree = lfirst_node(RawStmt, lc1);
		List	   *stmt_list;
		ListCell   *lc2;

		
		CommandCounterIncrement();

		stmt_list = pg_analyze_and_rewrite(parsetree, sql, NULL, 0, NULL);



		stmt_list = pg_plan_queries(stmt_list, CURSOR_OPT_PARALLEL_OK, NULL);

		foreach(lc2, stmt_list)
		{
			PlannedStmt *stmt = lfirst_node(PlannedStmt, lc2);

			CommandCounterIncrement();

			PushActiveSnapshot(GetTransactionSnapshot());

			if (stmt->utilityStmt == NULL)
			{
				QueryDesc  *qdesc;

				qdesc = CreateQueryDesc(stmt, sql, GetActiveSnapshot(), NULL, dest, NULL, NULL, 0);



				ExecutorStart(qdesc, 0);
				ExecutorRun(qdesc, ForwardScanDirection, 0, true);
				ExecutorFinish(qdesc);
				ExecutorEnd(qdesc);

				FreeQueryDesc(qdesc);
			}
			else {
				if (IsA(stmt->utilityStmt, TransactionStmt))
					ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("transaction control statements are not allowed within an extension script")));


				ProcessUtility(stmt, sql, PROCESS_UTILITY_QUERY, NULL, NULL, dest, NULL);





			}

			PopActiveSnapshot();
		}
	}

	
	CommandCounterIncrement();
}


static void execute_extension_script(Oid extensionOid, ExtensionControlFile *control, const char *from_version, const char *version, List *requiredSchemas, const char *schemaName, Oid schemaOid)




{
	char	   *filename;
	int			save_nestlevel;
	StringInfoData pathbuf;
	ListCell   *lc;

	
	if (control->superuser && !superuser())
	{
		if (from_version == NULL)
			ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied to create extension \"%s\"", control->name), errhint("Must be superuser to create this extension.")));



		else ereport(ERROR, (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE), errmsg("permission denied to update extension \"%s\"", control->name), errhint("Must be superuser to update this extension.")));




	}

	filename = get_extension_script_filename(control, from_version, version);

	
	save_nestlevel = NewGUCNestLevel();

	if (client_min_messages < WARNING)
		(void) set_config_option("client_min_messages", "warning", PGC_USERSET, PGC_S_SESSION, GUC_ACTION_SAVE, true, 0, false);

	if (log_min_messages < WARNING)
		(void) set_config_option("log_min_messages", "warning", PGC_SUSET, PGC_S_SESSION, GUC_ACTION_SAVE, true, 0, false);


	
	initStringInfo(&pathbuf);
	appendStringInfoString(&pathbuf, quote_identifier(schemaName));
	foreach(lc, requiredSchemas)
	{
		Oid			reqschema = lfirst_oid(lc);
		char	   *reqname = get_namespace_name(reqschema);

		if (reqname)
			appendStringInfo(&pathbuf, ", %s", quote_identifier(reqname));
	}

	(void) set_config_option("search_path", pathbuf.data, PGC_USERSET, PGC_S_SESSION, GUC_ACTION_SAVE, true, 0, false);


	
	creating_extension = true;
	CurrentExtensionObject = extensionOid;
	PG_TRY();
	{
		char	   *c_sql = read_extension_script_file(control, filename);
		Datum		t_sql;

		
		t_sql = CStringGetTextDatum(c_sql);

		
		t_sql = DirectFunctionCall4Coll(textregexreplace, C_COLLATION_OID, t_sql, CStringGetTextDatum("^\\\\echo.*$"), CStringGetTextDatum(""), CStringGetTextDatum("ng"));





		
		if (!control->relocatable)
		{
			const char *qSchemaName = quote_identifier(schemaName);

			t_sql = DirectFunctionCall3(replace_text, t_sql, CStringGetTextDatum("@extschema@"), CStringGetTextDatum(qSchemaName));


		}

		
		if (control->module_pathname)
		{
			t_sql = DirectFunctionCall3(replace_text, t_sql, CStringGetTextDatum("MODULE_PATHNAME"), CStringGetTextDatum(control->module_pathname));


		}

		
		c_sql = text_to_cstring(DatumGetTextPP(t_sql));

		execute_sql_string(c_sql, filename);
	}
	PG_CATCH();
	{
		creating_extension = false;
		CurrentExtensionObject = InvalidOid;
		PG_RE_THROW();
	}
	PG_END_TRY();

	creating_extension = false;
	CurrentExtensionObject = InvalidOid;

	
	AtEOXact_GUC(true, save_nestlevel);
}


static ExtensionVersionInfo * get_ext_ver_info(const char *versionname, List **evi_list)
{
	ExtensionVersionInfo *evi;
	ListCell   *lc;

	foreach(lc, *evi_list)
	{
		evi = (ExtensionVersionInfo *) lfirst(lc);
		if (strcmp(evi->name, versionname) == 0)
			return evi;
	}

	evi = (ExtensionVersionInfo *) palloc(sizeof(ExtensionVersionInfo));
	evi->name = pstrdup(versionname);
	evi->reachable = NIL;
	evi->installable = false;
	
	evi->distance_known = false;
	evi->distance = INT_MAX;
	evi->previous = NULL;

	*evi_list = lappend(*evi_list, evi);

	return evi;
}


static ExtensionVersionInfo * get_nearest_unprocessed_vertex(List *evi_list)
{
	ExtensionVersionInfo *evi = NULL;
	ListCell   *lc;

	foreach(lc, evi_list)
	{
		ExtensionVersionInfo *evi2 = (ExtensionVersionInfo *) lfirst(lc);

		
		if (evi2->distance_known)
			continue;
		
		if (evi == NULL || evi->distance > evi2->distance)
			evi = evi2;
	}

	return evi;
}


static List * get_ext_ver_list(ExtensionControlFile *control)
{
	List	   *evi_list = NIL;
	int			extnamelen = strlen(control->name);
	char	   *location;
	DIR		   *dir;
	struct dirent *de;

	location = get_extension_script_directory(control);
	dir = AllocateDir(location);
	while ((de = ReadDir(dir, location)) != NULL)
	{
		char	   *vername;
		char	   *vername2;
		ExtensionVersionInfo *evi;
		ExtensionVersionInfo *evi2;

		
		if (!is_extension_script_filename(de->d_name))
			continue;

		
		if (strncmp(de->d_name, control->name, extnamelen) != 0 || de->d_name[extnamelen] != '-' || de->d_name[extnamelen + 1] != '-')

			continue;

		
		vername = pstrdup(de->d_name + extnamelen + 2);
		*strrchr(vername, '.') = '\0';
		vername2 = strstr(vername, "--");
		if (!vername2)
		{
			
			evi = get_ext_ver_info(vername, &evi_list);
			evi->installable = true;
			continue;
		}
		*vername2 = '\0';		
		vername2 += 2;			

		
		if (strstr(vername2, "--"))
			continue;

		
		evi = get_ext_ver_info(vername, &evi_list);
		evi2 = get_ext_ver_info(vername2, &evi_list);
		evi->reachable = lappend(evi->reachable, evi2);
	}
	FreeDir(dir);

	return evi_list;
}


static List * identify_update_path(ExtensionControlFile *control, const char *oldVersion, const char *newVersion)

{
	List	   *result;
	List	   *evi_list;
	ExtensionVersionInfo *evi_start;
	ExtensionVersionInfo *evi_target;

	
	evi_list = get_ext_ver_list(control);

	
	evi_start = get_ext_ver_info(oldVersion, &evi_list);
	evi_target = get_ext_ver_info(newVersion, &evi_list);

	
	result = find_update_path(evi_list, evi_start, evi_target, false, false);

	if (result == NIL)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("extension \"%s\" has no update path from version \"%s\" to version \"%s\"", control->name, oldVersion, newVersion)));



	return result;
}


static List * find_update_path(List *evi_list, ExtensionVersionInfo *evi_start, ExtensionVersionInfo *evi_target, bool reject_indirect, bool reinitialize)




{
	List	   *result;
	ExtensionVersionInfo *evi;
	ListCell   *lc;

	
	Assert(evi_start != evi_target);
	
	Assert(!(reject_indirect && evi_target->installable));

	if (reinitialize)
	{
		foreach(lc, evi_list)
		{
			evi = (ExtensionVersionInfo *) lfirst(lc);
			evi->distance_known = false;
			evi->distance = INT_MAX;
			evi->previous = NULL;
		}
	}

	evi_start->distance = 0;

	while ((evi = get_nearest_unprocessed_vertex(evi_list)) != NULL)
	{
		if (evi->distance == INT_MAX)
			break;				
		evi->distance_known = true;
		if (evi == evi_target)
			break;				
		foreach(lc, evi->reachable)
		{
			ExtensionVersionInfo *evi2 = (ExtensionVersionInfo *) lfirst(lc);
			int			newdist;

			
			if (reject_indirect && evi2->installable)
				continue;
			newdist = evi->distance + 1;
			if (newdist < evi2->distance)
			{
				evi2->distance = newdist;
				evi2->previous = evi;
			}
			else if (newdist == evi2->distance && evi2->previous != NULL && strcmp(evi->name, evi2->previous->name) < 0)

			{
				
				evi2->previous = evi;
			}
		}
	}

	
	if (!evi_target->distance_known)
		return NIL;

	
	result = NIL;
	for (evi = evi_target; evi != evi_start; evi = evi->previous)
		result = lcons(evi->name, result);

	return result;
}


static ExtensionVersionInfo * find_install_path(List *evi_list, ExtensionVersionInfo *evi_target, List **best_path)

{
	ExtensionVersionInfo *evi_start = NULL;
	ListCell   *lc;

	*best_path = NIL;

	
	if (evi_target->installable)
		return evi_target;

	
	foreach(lc, evi_list)
	{
		ExtensionVersionInfo *evi1 = (ExtensionVersionInfo *) lfirst(lc);
		List	   *path;

		if (!evi1->installable)
			continue;

		
		path = find_update_path(evi_list, evi1, evi_target, true, true);
		if (path == NIL)
			continue;

		
		if (evi_start == NULL || list_length(path) < list_length(*best_path) || (list_length(path) == list_length(*best_path) && strcmp(evi_start->name, evi1->name) < 0))


		{
			evi_start = evi1;
			*best_path = path;
		}
	}

	return evi_start;
}


static ObjectAddress CreateExtensionInternal(char *extensionName, char *schemaName, const char *versionName, const char *oldVersionName, bool cascade, List *parents, bool is_create)






{
	char	   *origSchemaName = schemaName;
	Oid			schemaOid = InvalidOid;
	Oid			extowner = GetUserId();
	ExtensionControlFile *pcontrol;
	ExtensionControlFile *control;
	List	   *updateVersions;
	List	   *requiredExtensions;
	List	   *requiredSchemas;
	Oid			extensionOid;
	ObjectAddress address;
	ListCell   *lc;

	
	pcontrol = read_extension_control_file(extensionName);

	
	if (versionName == NULL)
	{
		if (pcontrol->default_version)
			versionName = pcontrol->default_version;
		else ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("version to install must be specified")));


	}
	check_valid_version_name(versionName);

	
	if (oldVersionName)
	{
		
		check_valid_version_name(oldVersionName);

		if (strcmp(oldVersionName, versionName) == 0)
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("FROM version must be different from installation target version \"%s\"", versionName)));



		updateVersions = identify_update_path(pcontrol, oldVersionName, versionName);


		if (list_length(updateVersions) == 1)
		{
			
			Assert(strcmp((char *) linitial(updateVersions), versionName) == 0);
			updateVersions = NIL;
		}
		else {
			
			versionName = (char *) linitial(updateVersions);
			updateVersions = list_delete_first(updateVersions);
		}
	}
	else {
		
		char	   *filename;
		struct stat fst;

		oldVersionName = NULL;

		filename = get_extension_script_filename(pcontrol, NULL, versionName);
		if (stat(filename, &fst) == 0)
		{
			
			updateVersions = NIL;
		}
		else {
			
			List	   *evi_list;
			ExtensionVersionInfo *evi_start;
			ExtensionVersionInfo *evi_target;

			
			evi_list = get_ext_ver_list(pcontrol);

			
			evi_target = get_ext_ver_info(versionName, &evi_list);

			
			evi_start = find_install_path(evi_list, evi_target, &updateVersions);

			
			if (evi_start == NULL)
				ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("extension \"%s\" has no installation script nor update path for version \"%s\"", pcontrol->name, versionName)));



			
			versionName = evi_start->name;
		}
	}

	
	control = read_extension_aux_control_file(pcontrol, versionName);

	
	if (schemaName)
	{
		
		schemaOid = get_namespace_oid(schemaName, false);
	}

	if (control->schema != NULL)
	{
		
		if (schemaName && strcmp(control->schema, schemaName) != 0 && !cascade)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("extension \"%s\" must be installed in schema \"%s\"", control->name, control->schema)));




		
		schemaName = control->schema;

		
		schemaOid = get_namespace_oid(schemaName, true);

		if (!OidIsValid(schemaOid))
		{
			CreateSchemaStmt *csstmt = makeNode(CreateSchemaStmt);

			csstmt->schemaname = schemaName;
			csstmt->authrole = NULL;	
			csstmt->schemaElts = NIL;
			csstmt->if_not_exists = false;
			CreateSchemaCommand(csstmt, "(generated CREATE SCHEMA command)", -1, -1);

			
			schemaOid = get_namespace_oid(schemaName, false);
		}
	}
	else if (!OidIsValid(schemaOid))
	{
		
		List	   *search_path = fetch_search_path(false);

		if (search_path == NIL) 
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_SCHEMA), errmsg("no schema has been selected to create in")));

		schemaOid = linitial_oid(search_path);
		schemaName = get_namespace_name(schemaOid);
		if (schemaName == NULL) 
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_SCHEMA), errmsg("no schema has been selected to create in")));


		list_free(search_path);
	}

	
	if (isTempNamespace(schemaOid))
		MyXactFlags |= XACT_FLAGS_ACCESSEDTEMPNAMESPACE;

	

	
	requiredExtensions = NIL;
	requiredSchemas = NIL;
	foreach(lc, control->requires)
	{
		char	   *curreq = (char *) lfirst(lc);
		Oid			reqext;
		Oid			reqschema;

		reqext = get_required_extension(curreq, extensionName, origSchemaName, cascade, parents, is_create);




		reqschema = get_extension_schema(reqext);
		requiredExtensions = lappend_oid(requiredExtensions, reqext);
		requiredSchemas = lappend_oid(requiredSchemas, reqschema);
	}

	
	address = InsertExtensionTuple(control->name, extowner, schemaOid, control->relocatable, versionName, PointerGetDatum(NULL), PointerGetDatum(NULL), requiredExtensions);




	extensionOid = address.objectId;

	
	if (control->comment != NULL)
		CreateComments(extensionOid, ExtensionRelationId, 0, control->comment);

	
	execute_extension_script(extensionOid, control, oldVersionName, versionName, requiredSchemas, schemaName, schemaOid);



	
	ApplyExtensionUpdates(extensionOid, pcontrol, versionName, updateVersions, origSchemaName, cascade, is_create);


	return address;
}


static Oid get_required_extension(char *reqExtensionName, char *extensionName, char *origSchemaName, bool cascade, List *parents, bool is_create)





{
	Oid			reqExtensionOid;

	reqExtensionOid = get_extension_oid(reqExtensionName, true);
	if (!OidIsValid(reqExtensionOid))
	{
		if (cascade)
		{
			
			ObjectAddress addr;
			List	   *cascade_parents;
			ListCell   *lc;

			
			check_valid_extension_name(reqExtensionName);

			
			foreach(lc, parents)
			{
				char	   *pname = (char *) lfirst(lc);

				if (strcmp(pname, reqExtensionName) == 0)
					ereport(ERROR, (errcode(ERRCODE_INVALID_RECURSION), errmsg("cyclic dependency detected between extensions \"%s\" and \"%s\"", reqExtensionName, extensionName)));


			}

			ereport(NOTICE, (errmsg("installing required extension \"%s\"", reqExtensionName)));


			
			cascade_parents = lappend(list_copy(parents), extensionName);

			
			addr = CreateExtensionInternal(reqExtensionName, origSchemaName, NULL, NULL, cascade, cascade_parents, is_create);






			
			reqExtensionOid = addr.objectId;
		}
		else ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("required extension \"%s\" is not installed", reqExtensionName), is_create ? errhint("Use CREATE EXTENSION ... CASCADE to install required extensions too.") : 0));





	}

	return reqExtensionOid;
}


ObjectAddress CreateExtension(ParseState *pstate, CreateExtensionStmt *stmt)
{
	DefElem    *d_schema = NULL;
	DefElem    *d_new_version = NULL;
	DefElem    *d_old_version = NULL;
	DefElem    *d_cascade = NULL;
	char	   *schemaName = NULL;
	char	   *versionName = NULL;
	char	   *oldVersionName = NULL;
	bool		cascade = false;
	ListCell   *lc;

	
	check_valid_extension_name(stmt->extname);

	
	if (get_extension_oid(stmt->extname, true) != InvalidOid)
	{
		if (stmt->if_not_exists)
		{
			ereport(NOTICE, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("extension \"%s\" already exists, skipping", stmt->extname)));


			return InvalidObjectAddress;
		}
		else ereport(ERROR, (errcode(ERRCODE_DUPLICATE_OBJECT), errmsg("extension \"%s\" already exists", stmt->extname)));



	}

	
	if (creating_extension)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("nested CREATE EXTENSION is not supported")));


	
	foreach(lc, stmt->options)
	{
		DefElem    *defel = (DefElem *) lfirst(lc);

		if (strcmp(defel->defname, "schema") == 0)
		{
			if (d_schema)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options"), parser_errposition(pstate, defel->location)));


			d_schema = defel;
			schemaName = defGetString(d_schema);
		}
		else if (strcmp(defel->defname, "new_version") == 0)
		{
			if (d_new_version)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options"), parser_errposition(pstate, defel->location)));


			d_new_version = defel;
			versionName = defGetString(d_new_version);
		}
		else if (strcmp(defel->defname, "old_version") == 0)
		{
			if (d_old_version)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options"), parser_errposition(pstate, defel->location)));


			d_old_version = defel;
			oldVersionName = defGetString(d_old_version);
		}
		else if (strcmp(defel->defname, "cascade") == 0)
		{
			if (d_cascade)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options"), parser_errposition(pstate, defel->location)));


			d_cascade = defel;
			cascade = defGetBoolean(d_cascade);
		}
		else elog(ERROR, "unrecognized option: %s", defel->defname);
	}

	
	return CreateExtensionInternal(stmt->extname, schemaName, versionName, oldVersionName, cascade, NIL, true);





}


ObjectAddress InsertExtensionTuple(const char *extName, Oid extOwner, Oid schemaOid, bool relocatable, const char *extVersion, Datum extConfig, Datum extCondition, List *requiredExtensions)



{
	Oid			extensionOid;
	Relation	rel;
	Datum		values[Natts_pg_extension];
	bool		nulls[Natts_pg_extension];
	HeapTuple	tuple;
	ObjectAddress myself;
	ObjectAddress nsp;
	ListCell   *lc;

	
	rel = heap_open(ExtensionRelationId, RowExclusiveLock);

	memset(values, 0, sizeof(values));
	memset(nulls, 0, sizeof(nulls));

	values[Anum_pg_extension_extname - 1] = DirectFunctionCall1(namein, CStringGetDatum(extName));
	values[Anum_pg_extension_extowner - 1] = ObjectIdGetDatum(extOwner);
	values[Anum_pg_extension_extnamespace - 1] = ObjectIdGetDatum(schemaOid);
	values[Anum_pg_extension_extrelocatable - 1] = BoolGetDatum(relocatable);
	values[Anum_pg_extension_extversion - 1] = CStringGetTextDatum(extVersion);

	if (extConfig == PointerGetDatum(NULL))
		nulls[Anum_pg_extension_extconfig - 1] = true;
	else values[Anum_pg_extension_extconfig - 1] = extConfig;

	if (extCondition == PointerGetDatum(NULL))
		nulls[Anum_pg_extension_extcondition - 1] = true;
	else values[Anum_pg_extension_extcondition - 1] = extCondition;

	tuple = heap_form_tuple(rel->rd_att, values, nulls);

	extensionOid = CatalogTupleInsert(rel, tuple);

	heap_freetuple(tuple);
	heap_close(rel, RowExclusiveLock);

	
	recordDependencyOnOwner(ExtensionRelationId, extensionOid, extOwner);

	myself.classId = ExtensionRelationId;
	myself.objectId = extensionOid;
	myself.objectSubId = 0;

	nsp.classId = NamespaceRelationId;
	nsp.objectId = schemaOid;
	nsp.objectSubId = 0;

	recordDependencyOn(&myself, &nsp, DEPENDENCY_NORMAL);

	foreach(lc, requiredExtensions)
	{
		Oid			reqext = lfirst_oid(lc);
		ObjectAddress otherext;

		otherext.classId = ExtensionRelationId;
		otherext.objectId = reqext;
		otherext.objectSubId = 0;

		recordDependencyOn(&myself, &otherext, DEPENDENCY_NORMAL);
	}
	
	InvokeObjectPostCreateHook(ExtensionRelationId, extensionOid, 0);

	return myself;
}


void RemoveExtensionById(Oid extId)
{
	Relation	rel;
	SysScanDesc scandesc;
	HeapTuple	tuple;
	ScanKeyData entry[1];

	
	if (extId == CurrentExtensionObject)
		ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("cannot drop extension \"%s\" because it is being modified", get_extension_name(extId))));



	rel = heap_open(ExtensionRelationId, RowExclusiveLock);

	ScanKeyInit(&entry[0], ObjectIdAttributeNumber, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(extId));


	scandesc = systable_beginscan(rel, ExtensionOidIndexId, true, NULL, 1, entry);

	tuple = systable_getnext(scandesc);

	
	if (HeapTupleIsValid(tuple))
		CatalogTupleDelete(rel, &tuple->t_self);

	systable_endscan(scandesc);

	heap_close(rel, RowExclusiveLock);
}


Datum pg_available_extensions(PG_FUNCTION_ARGS)
{
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	TupleDesc	tupdesc;
	Tuplestorestate *tupstore;
	MemoryContext per_query_ctx;
	MemoryContext oldcontext;
	char	   *location;
	DIR		   *dir;
	struct dirent *de;

	
	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("set-valued function called in context that cannot accept a set")));

	if (!(rsinfo->allowedModes & SFRM_Materialize))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("materialize mode required, but it is not "  "allowed in this context")))


	
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	
	per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
	oldcontext = MemoryContextSwitchTo(per_query_ctx);

	tupstore = tuplestore_begin_heap(true, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;

	MemoryContextSwitchTo(oldcontext);

	location = get_extension_control_directory();
	dir = AllocateDir(location);

	
	if (dir == NULL && errno == ENOENT)
	{
		
	}
	else {
		while ((de = ReadDir(dir, location)) != NULL)
		{
			ExtensionControlFile *control;
			char	   *extname;
			Datum		values[3];
			bool		nulls[3];

			if (!is_extension_control_filename(de->d_name))
				continue;

			
			extname = pstrdup(de->d_name);
			*strrchr(extname, '.') = '\0';

			
			if (strstr(extname, "--"))
				continue;

			control = read_extension_control_file(extname);

			memset(values, 0, sizeof(values));
			memset(nulls, 0, sizeof(nulls));

			
			values[0] = DirectFunctionCall1(namein, CStringGetDatum(control->name));
			
			if (control->default_version == NULL)
				nulls[1] = true;
			else values[1] = CStringGetTextDatum(control->default_version);
			
			if (control->comment == NULL)
				nulls[2] = true;
			else values[2] = CStringGetTextDatum(control->comment);

			tuplestore_putvalues(tupstore, tupdesc, values, nulls);
		}

		FreeDir(dir);
	}

	
	tuplestore_donestoring(tupstore);

	return (Datum) 0;
}


Datum pg_available_extension_versions(PG_FUNCTION_ARGS)
{
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	TupleDesc	tupdesc;
	Tuplestorestate *tupstore;
	MemoryContext per_query_ctx;
	MemoryContext oldcontext;
	char	   *location;
	DIR		   *dir;
	struct dirent *de;

	
	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("set-valued function called in context that cannot accept a set")));

	if (!(rsinfo->allowedModes & SFRM_Materialize))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("materialize mode required, but it is not "  "allowed in this context")))


	
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	
	per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
	oldcontext = MemoryContextSwitchTo(per_query_ctx);

	tupstore = tuplestore_begin_heap(true, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;

	MemoryContextSwitchTo(oldcontext);

	location = get_extension_control_directory();
	dir = AllocateDir(location);

	
	if (dir == NULL && errno == ENOENT)
	{
		
	}
	else {
		while ((de = ReadDir(dir, location)) != NULL)
		{
			ExtensionControlFile *control;
			char	   *extname;

			if (!is_extension_control_filename(de->d_name))
				continue;

			
			extname = pstrdup(de->d_name);
			*strrchr(extname, '.') = '\0';

			
			if (strstr(extname, "--"))
				continue;

			
			control = read_extension_control_file(extname);

			
			get_available_versions_for_extension(control, tupstore, tupdesc);
		}

		FreeDir(dir);
	}

	
	tuplestore_donestoring(tupstore);

	return (Datum) 0;
}


static void get_available_versions_for_extension(ExtensionControlFile *pcontrol, Tuplestorestate *tupstore, TupleDesc tupdesc)


{
	List	   *evi_list;
	ListCell   *lc;

	
	evi_list = get_ext_ver_list(pcontrol);

	
	foreach(lc, evi_list)
	{
		ExtensionVersionInfo *evi = (ExtensionVersionInfo *) lfirst(lc);
		ExtensionControlFile *control;
		Datum		values[7];
		bool		nulls[7];
		ListCell   *lc2;

		if (!evi->installable)
			continue;

		
		control = read_extension_aux_control_file(pcontrol, evi->name);

		memset(values, 0, sizeof(values));
		memset(nulls, 0, sizeof(nulls));

		
		values[0] = DirectFunctionCall1(namein, CStringGetDatum(control->name));
		
		values[1] = CStringGetTextDatum(evi->name);
		
		values[2] = BoolGetDatum(control->superuser);
		
		values[3] = BoolGetDatum(control->relocatable);
		
		if (control->schema == NULL)
			nulls[4] = true;
		else values[4] = DirectFunctionCall1(namein, CStringGetDatum(control->schema));

		
		if (control->requires == NIL)
			nulls[5] = true;
		else values[5] = convert_requires_to_datum(control->requires);
		
		if (control->comment == NULL)
			nulls[6] = true;
		else values[6] = CStringGetTextDatum(control->comment);

		tuplestore_putvalues(tupstore, tupdesc, values, nulls);

		
		foreach(lc2, evi_list)
		{
			ExtensionVersionInfo *evi2 = (ExtensionVersionInfo *) lfirst(lc2);
			List	   *best_path;

			if (evi2->installable)
				continue;
			if (find_install_path(evi_list, evi2, &best_path) == evi)
			{
				
				control = read_extension_aux_control_file(pcontrol, evi2->name);

				
				
				values[1] = CStringGetTextDatum(evi2->name);
				
				values[2] = BoolGetDatum(control->superuser);
				
				values[3] = BoolGetDatum(control->relocatable);
				
				
				if (control->requires == NIL)
					nulls[5] = true;
				else {
					values[5] = convert_requires_to_datum(control->requires);
					nulls[5] = false;
				}
				

				tuplestore_putvalues(tupstore, tupdesc, values, nulls);
			}
		}
	}
}


static Datum convert_requires_to_datum(List *requires)
{
	Datum	   *datums;
	int			ndatums;
	ArrayType  *a;
	ListCell   *lc;

	ndatums = list_length(requires);
	datums = (Datum *) palloc(ndatums * sizeof(Datum));
	ndatums = 0;
	foreach(lc, requires)
	{
		char	   *curreq = (char *) lfirst(lc);

		datums[ndatums++] = DirectFunctionCall1(namein, CStringGetDatum(curreq));
	}
	a = construct_array(datums, ndatums, NAMEOID, NAMEDATALEN, false, 'c');

	return PointerGetDatum(a);
}


Datum pg_extension_update_paths(PG_FUNCTION_ARGS)
{
	Name		extname = PG_GETARG_NAME(0);
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	TupleDesc	tupdesc;
	Tuplestorestate *tupstore;
	MemoryContext per_query_ctx;
	MemoryContext oldcontext;
	List	   *evi_list;
	ExtensionControlFile *control;
	ListCell   *lc1;

	
	check_valid_extension_name(NameStr(*extname));

	
	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("set-valued function called in context that cannot accept a set")));

	if (!(rsinfo->allowedModes & SFRM_Materialize))
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("materialize mode required, but it is not "  "allowed in this context")))


	
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	
	per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
	oldcontext = MemoryContextSwitchTo(per_query_ctx);

	tupstore = tuplestore_begin_heap(true, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;

	MemoryContextSwitchTo(oldcontext);

	
	control = read_extension_control_file(NameStr(*extname));

	
	evi_list = get_ext_ver_list(control);

	
	foreach(lc1, evi_list)
	{
		ExtensionVersionInfo *evi1 = (ExtensionVersionInfo *) lfirst(lc1);
		ListCell   *lc2;

		foreach(lc2, evi_list)
		{
			ExtensionVersionInfo *evi2 = (ExtensionVersionInfo *) lfirst(lc2);
			List	   *path;
			Datum		values[3];
			bool		nulls[3];

			if (evi1 == evi2)
				continue;

			
			path = find_update_path(evi_list, evi1, evi2, false, true);

			
			memset(values, 0, sizeof(values));
			memset(nulls, 0, sizeof(nulls));

			
			values[0] = CStringGetTextDatum(evi1->name);
			
			values[1] = CStringGetTextDatum(evi2->name);
			
			if (path == NIL)
				nulls[2] = true;
			else {
				StringInfoData pathbuf;
				ListCell   *lcv;

				initStringInfo(&pathbuf);
				
				appendStringInfoString(&pathbuf, evi1->name);
				foreach(lcv, path)
				{
					char	   *versionName = (char *) lfirst(lcv);

					appendStringInfoString(&pathbuf, "--");
					appendStringInfoString(&pathbuf, versionName);
				}
				values[2] = CStringGetTextDatum(pathbuf.data);
				pfree(pathbuf.data);
			}

			tuplestore_putvalues(tupstore, tupdesc, values, nulls);
		}
	}

	
	tuplestore_donestoring(tupstore);

	return (Datum) 0;
}


Datum pg_extension_config_dump(PG_FUNCTION_ARGS)
{
	Oid			tableoid = PG_GETARG_OID(0);
	text	   *wherecond = PG_GETARG_TEXT_PP(1);
	char	   *tablename;
	Relation	extRel;
	ScanKeyData key[1];
	SysScanDesc extScan;
	HeapTuple	extTup;
	Datum		arrayDatum;
	Datum		elementDatum;
	int			arrayLength;
	int			arrayIndex;
	bool		isnull;
	Datum		repl_val[Natts_pg_extension];
	bool		repl_null[Natts_pg_extension];
	bool		repl_repl[Natts_pg_extension];
	ArrayType  *a;

	
	if (!creating_extension)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("pg_extension_config_dump() can only be called " "from an SQL script executed by CREATE EXTENSION")));



	
	tablename = get_rel_name(tableoid);
	if (tablename == NULL)
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_TABLE), errmsg("OID %u does not refer to a table", tableoid)));

	if (getExtensionOfObject(RelationRelationId, tableoid) != CurrentExtensionObject)
		ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("table \"%s\" is not a member of the extension being created", tablename)));



	

	
	extRel = heap_open(ExtensionRelationId, RowExclusiveLock);

	ScanKeyInit(&key[0], ObjectIdAttributeNumber, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(CurrentExtensionObject));



	extScan = systable_beginscan(extRel, ExtensionOidIndexId, true, NULL, 1, key);

	extTup = systable_getnext(extScan);

	if (!HeapTupleIsValid(extTup))	
		elog(ERROR, "could not find tuple for extension %u", CurrentExtensionObject);

	memset(repl_val, 0, sizeof(repl_val));
	memset(repl_null, false, sizeof(repl_null));
	memset(repl_repl, false, sizeof(repl_repl));

	
	elementDatum = ObjectIdGetDatum(tableoid);

	arrayDatum = heap_getattr(extTup, Anum_pg_extension_extconfig, RelationGetDescr(extRel), &isnull);
	if (isnull)
	{
		
		arrayLength = 0;
		arrayIndex = 1;

		a = construct_array(&elementDatum, 1, OIDOID, sizeof(Oid), true, 'i');

	}
	else {
		
		Oid		   *arrayData;
		int			i;

		a = DatumGetArrayTypeP(arrayDatum);

		arrayLength = ARR_DIMS(a)[0];
		if (ARR_NDIM(a) != 1 || ARR_LBOUND(a)[0] != 1 || arrayLength < 0 || ARR_HASNULL(a) || ARR_ELEMTYPE(a) != OIDOID)



			elog(ERROR, "extconfig is not a 1-D Oid array");
		arrayData = (Oid *) ARR_DATA_PTR(a);

		arrayIndex = arrayLength + 1;	

		for (i = 0; i < arrayLength; i++)
		{
			if (arrayData[i] == tableoid)
			{
				arrayIndex = i + 1; 
				break;
			}
		}

		a = array_set(a, 1, &arrayIndex, elementDatum, false, -1  , sizeof(Oid)  , true  , 'i'  );





	}
	repl_val[Anum_pg_extension_extconfig - 1] = PointerGetDatum(a);
	repl_repl[Anum_pg_extension_extconfig - 1] = true;

	
	elementDatum = PointerGetDatum(wherecond);

	arrayDatum = heap_getattr(extTup, Anum_pg_extension_extcondition, RelationGetDescr(extRel), &isnull);
	if (isnull)
	{
		if (arrayLength != 0)
			elog(ERROR, "extconfig and extcondition arrays do not match");

		a = construct_array(&elementDatum, 1, TEXTOID, -1, false, 'i');

	}
	else {
		a = DatumGetArrayTypeP(arrayDatum);

		if (ARR_NDIM(a) != 1 || ARR_LBOUND(a)[0] != 1 || ARR_HASNULL(a) || ARR_ELEMTYPE(a) != TEXTOID)


			elog(ERROR, "extcondition is not a 1-D text array");
		if (ARR_DIMS(a)[0] != arrayLength)
			elog(ERROR, "extconfig and extcondition arrays do not match");

		
		a = array_set(a, 1, &arrayIndex, elementDatum, false, -1  , -1  , false  , 'i'  );





	}
	repl_val[Anum_pg_extension_extcondition - 1] = PointerGetDatum(a);
	repl_repl[Anum_pg_extension_extcondition - 1] = true;

	extTup = heap_modify_tuple(extTup, RelationGetDescr(extRel), repl_val, repl_null, repl_repl);

	CatalogTupleUpdate(extRel, &extTup->t_self, extTup);

	systable_endscan(extScan);

	heap_close(extRel, RowExclusiveLock);

	PG_RETURN_VOID();
}


static void extension_config_remove(Oid extensionoid, Oid tableoid)
{
	Relation	extRel;
	ScanKeyData key[1];
	SysScanDesc extScan;
	HeapTuple	extTup;
	Datum		arrayDatum;
	int			arrayLength;
	int			arrayIndex;
	bool		isnull;
	Datum		repl_val[Natts_pg_extension];
	bool		repl_null[Natts_pg_extension];
	bool		repl_repl[Natts_pg_extension];
	ArrayType  *a;

	
	extRel = heap_open(ExtensionRelationId, RowExclusiveLock);

	ScanKeyInit(&key[0], ObjectIdAttributeNumber, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(extensionoid));



	extScan = systable_beginscan(extRel, ExtensionOidIndexId, true, NULL, 1, key);

	extTup = systable_getnext(extScan);

	if (!HeapTupleIsValid(extTup))	
		elog(ERROR, "could not find tuple for extension %u", extensionoid);

	
	arrayDatum = heap_getattr(extTup, Anum_pg_extension_extconfig, RelationGetDescr(extRel), &isnull);
	if (isnull)
	{
		
		a = NULL;
		arrayLength = 0;
		arrayIndex = -1;
	}
	else {
		Oid		   *arrayData;
		int			i;

		a = DatumGetArrayTypeP(arrayDatum);

		arrayLength = ARR_DIMS(a)[0];
		if (ARR_NDIM(a) != 1 || ARR_LBOUND(a)[0] != 1 || arrayLength < 0 || ARR_HASNULL(a) || ARR_ELEMTYPE(a) != OIDOID)



			elog(ERROR, "extconfig is not a 1-D Oid array");
		arrayData = (Oid *) ARR_DATA_PTR(a);

		arrayIndex = -1;		

		for (i = 0; i < arrayLength; i++)
		{
			if (arrayData[i] == tableoid)
			{
				arrayIndex = i; 
				break;
			}
		}
	}

	
	if (arrayIndex < 0)
	{
		systable_endscan(extScan);
		heap_close(extRel, RowExclusiveLock);
		return;
	}

	
	memset(repl_val, 0, sizeof(repl_val));
	memset(repl_null, false, sizeof(repl_null));
	memset(repl_repl, false, sizeof(repl_repl));

	if (arrayLength <= 1)
	{
		
		repl_null[Anum_pg_extension_extconfig - 1] = true;
	}
	else {
		
		Datum	   *dvalues;
		bool	   *dnulls;
		int			nelems;
		int			i;

		deconstruct_array(a, OIDOID, sizeof(Oid), true, 'i', &dvalues, &dnulls, &nelems);

		
		for (i = arrayIndex; i < arrayLength - 1; i++)
			dvalues[i] = dvalues[i + 1];

		a = construct_array(dvalues, arrayLength - 1, OIDOID, sizeof(Oid), true, 'i');

		repl_val[Anum_pg_extension_extconfig - 1] = PointerGetDatum(a);
	}
	repl_repl[Anum_pg_extension_extconfig - 1] = true;

	
	arrayDatum = heap_getattr(extTup, Anum_pg_extension_extcondition, RelationGetDescr(extRel), &isnull);
	if (isnull)
	{
		elog(ERROR, "extconfig and extcondition arrays do not match");
	}
	else {
		a = DatumGetArrayTypeP(arrayDatum);

		if (ARR_NDIM(a) != 1 || ARR_LBOUND(a)[0] != 1 || ARR_HASNULL(a) || ARR_ELEMTYPE(a) != TEXTOID)


			elog(ERROR, "extcondition is not a 1-D text array");
		if (ARR_DIMS(a)[0] != arrayLength)
			elog(ERROR, "extconfig and extcondition arrays do not match");
	}

	if (arrayLength <= 1)
	{
		
		repl_null[Anum_pg_extension_extcondition - 1] = true;
	}
	else {
		
		Datum	   *dvalues;
		bool	   *dnulls;
		int			nelems;
		int			i;

		deconstruct_array(a, TEXTOID, -1, false, 'i', &dvalues, &dnulls, &nelems);

		
		for (i = arrayIndex; i < arrayLength - 1; i++)
			dvalues[i] = dvalues[i + 1];

		a = construct_array(dvalues, arrayLength - 1, TEXTOID, -1, false, 'i');

		repl_val[Anum_pg_extension_extcondition - 1] = PointerGetDatum(a);
	}
	repl_repl[Anum_pg_extension_extcondition - 1] = true;

	extTup = heap_modify_tuple(extTup, RelationGetDescr(extRel), repl_val, repl_null, repl_repl);

	CatalogTupleUpdate(extRel, &extTup->t_self, extTup);

	systable_endscan(extScan);

	heap_close(extRel, RowExclusiveLock);
}


ObjectAddress AlterExtensionNamespace(const char *extensionName, const char *newschema, Oid *oldschema)
{
	Oid			extensionOid;
	Oid			nspOid;
	Oid			oldNspOid = InvalidOid;
	AclResult	aclresult;
	Relation	extRel;
	ScanKeyData key[2];
	SysScanDesc extScan;
	HeapTuple	extTup;
	Form_pg_extension extForm;
	Relation	depRel;
	SysScanDesc depScan;
	HeapTuple	depTup;
	ObjectAddresses *objsMoved;
	ObjectAddress extAddr;

	extensionOid = get_extension_oid(extensionName, false);

	nspOid = LookupCreationNamespace(newschema);

	
	if (!pg_extension_ownercheck(extensionOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, OBJECT_EXTENSION, extensionName);

	
	aclresult = pg_namespace_aclcheck(nspOid, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, OBJECT_SCHEMA, newschema);

	
	if (getExtensionOfObject(NamespaceRelationId, nspOid) == extensionOid)
		ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("cannot move extension \"%s\" into schema \"%s\" " "because the extension contains the schema", extensionName, newschema)));




	
	extRel = heap_open(ExtensionRelationId, RowExclusiveLock);

	ScanKeyInit(&key[0], ObjectIdAttributeNumber, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(extensionOid));



	extScan = systable_beginscan(extRel, ExtensionOidIndexId, true, NULL, 1, key);

	extTup = systable_getnext(extScan);

	if (!HeapTupleIsValid(extTup))	
		elog(ERROR, "could not find tuple for extension %u", extensionOid);

	
	extTup = heap_copytuple(extTup);
	extForm = (Form_pg_extension) GETSTRUCT(extTup);

	systable_endscan(extScan);

	
	if (extForm->extnamespace == nspOid)
	{
		heap_close(extRel, RowExclusiveLock);
		return InvalidObjectAddress;
	}

	
	if (!extForm->extrelocatable)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("extension \"%s\" does not support SET SCHEMA", NameStr(extForm->extname))));



	objsMoved = new_object_addresses();

	
	depRel = heap_open(DependRelationId, AccessShareLock);

	ScanKeyInit(&key[0], Anum_pg_depend_refclassid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(ExtensionRelationId));


	ScanKeyInit(&key[1], Anum_pg_depend_refobjid, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(extensionOid));



	depScan = systable_beginscan(depRel, DependReferenceIndexId, true, NULL, 2, key);

	while (HeapTupleIsValid(depTup = systable_getnext(depScan)))
	{
		Form_pg_depend pg_depend = (Form_pg_depend) GETSTRUCT(depTup);
		ObjectAddress dep;
		Oid			dep_oldNspOid;

		
		if (pg_depend->deptype != DEPENDENCY_EXTENSION)
			continue;

		dep.classId = pg_depend->classid;
		dep.objectId = pg_depend->objid;
		dep.objectSubId = pg_depend->objsubid;

		if (dep.objectSubId != 0)	
			elog(ERROR, "extension should not have a sub-object dependency");

		
		dep_oldNspOid = AlterObjectNamespace_oid(dep.classId, dep.objectId, nspOid, objsMoved);



		
		if (oldNspOid == InvalidOid && dep_oldNspOid != InvalidOid)
			oldNspOid = dep_oldNspOid;

		
		if (dep_oldNspOid != InvalidOid && dep_oldNspOid != oldNspOid)
			ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("extension \"%s\" does not support SET SCHEMA", NameStr(extForm->extname)), errdetail("%s is not in the extension's schema \"%s\"", getObjectDescription(&dep), get_namespace_name(oldNspOid))));





	}

	
	if (oldschema)
		*oldschema = oldNspOid;

	systable_endscan(depScan);

	relation_close(depRel, AccessShareLock);

	
	extForm->extnamespace = nspOid;

	CatalogTupleUpdate(extRel, &extTup->t_self, extTup);

	heap_close(extRel, RowExclusiveLock);

	
	changeDependencyFor(ExtensionRelationId, extensionOid, NamespaceRelationId, oldNspOid, nspOid);

	InvokeObjectPostAlterHook(ExtensionRelationId, extensionOid, 0);

	ObjectAddressSet(extAddr, ExtensionRelationId, extensionOid);

	return extAddr;
}


ObjectAddress ExecAlterExtensionStmt(ParseState *pstate, AlterExtensionStmt *stmt)
{
	DefElem    *d_new_version = NULL;
	char	   *versionName;
	char	   *oldVersionName;
	ExtensionControlFile *control;
	Oid			extensionOid;
	Relation	extRel;
	ScanKeyData key[1];
	SysScanDesc extScan;
	HeapTuple	extTup;
	List	   *updateVersions;
	Datum		datum;
	bool		isnull;
	ListCell   *lc;
	ObjectAddress address;

	
	if (creating_extension)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("nested ALTER EXTENSION is not supported")));


	
	extRel = heap_open(ExtensionRelationId, AccessShareLock);

	ScanKeyInit(&key[0], Anum_pg_extension_extname, BTEqualStrategyNumber, F_NAMEEQ, CStringGetDatum(stmt->extname));



	extScan = systable_beginscan(extRel, ExtensionNameIndexId, true, NULL, 1, key);

	extTup = systable_getnext(extScan);

	if (!HeapTupleIsValid(extTup))
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("extension \"%s\" does not exist", stmt->extname)));



	extensionOid = HeapTupleGetOid(extTup);

	
	datum = heap_getattr(extTup, Anum_pg_extension_extversion, RelationGetDescr(extRel), &isnull);
	if (isnull)
		elog(ERROR, "extversion is null");
	oldVersionName = text_to_cstring(DatumGetTextPP(datum));

	systable_endscan(extScan);

	heap_close(extRel, AccessShareLock);

	
	if (!pg_extension_ownercheck(extensionOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, OBJECT_EXTENSION, stmt->extname);

	
	control = read_extension_control_file(stmt->extname);

	
	foreach(lc, stmt->options)
	{
		DefElem    *defel = (DefElem *) lfirst(lc);

		if (strcmp(defel->defname, "new_version") == 0)
		{
			if (d_new_version)
				ereport(ERROR, (errcode(ERRCODE_SYNTAX_ERROR), errmsg("conflicting or redundant options"), parser_errposition(pstate, defel->location)));


			d_new_version = defel;
		}
		else elog(ERROR, "unrecognized option: %s", defel->defname);
	}

	
	if (d_new_version && d_new_version->arg)
		versionName = strVal(d_new_version->arg);
	else if (control->default_version)
		versionName = control->default_version;
	else {
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("version to install must be specified")));

		versionName = NULL;		
	}
	check_valid_version_name(versionName);

	
	if (strcmp(oldVersionName, versionName) == 0)
	{
		ereport(NOTICE, (errmsg("version \"%s\" of extension \"%s\" is already installed", versionName, stmt->extname)));

		return InvalidObjectAddress;
	}

	
	updateVersions = identify_update_path(control, oldVersionName, versionName);


	
	ApplyExtensionUpdates(extensionOid, control, oldVersionName, updateVersions, NULL, false, false);


	ObjectAddressSet(address, ExtensionRelationId, extensionOid);

	return address;
}


static void ApplyExtensionUpdates(Oid extensionOid, ExtensionControlFile *pcontrol, const char *initialVersion, List *updateVersions, char *origSchemaName, bool cascade, bool is_create)






{
	const char *oldVersionName = initialVersion;
	ListCell   *lcv;

	foreach(lcv, updateVersions)
	{
		char	   *versionName = (char *) lfirst(lcv);
		ExtensionControlFile *control;
		char	   *schemaName;
		Oid			schemaOid;
		List	   *requiredExtensions;
		List	   *requiredSchemas;
		Relation	extRel;
		ScanKeyData key[1];
		SysScanDesc extScan;
		HeapTuple	extTup;
		Form_pg_extension extForm;
		Datum		values[Natts_pg_extension];
		bool		nulls[Natts_pg_extension];
		bool		repl[Natts_pg_extension];
		ObjectAddress myself;
		ListCell   *lc;

		
		control = read_extension_aux_control_file(pcontrol, versionName);

		
		extRel = heap_open(ExtensionRelationId, RowExclusiveLock);

		ScanKeyInit(&key[0], ObjectIdAttributeNumber, BTEqualStrategyNumber, F_OIDEQ, ObjectIdGetDatum(extensionOid));



		extScan = systable_beginscan(extRel, ExtensionOidIndexId, true, NULL, 1, key);

		extTup = systable_getnext(extScan);

		if (!HeapTupleIsValid(extTup))	
			elog(ERROR, "could not find tuple for extension %u", extensionOid);

		extForm = (Form_pg_extension) GETSTRUCT(extTup);

		
		schemaOid = extForm->extnamespace;
		schemaName = get_namespace_name(schemaOid);

		
		memset(values, 0, sizeof(values));
		memset(nulls, 0, sizeof(nulls));
		memset(repl, 0, sizeof(repl));

		values[Anum_pg_extension_extrelocatable - 1] = BoolGetDatum(control->relocatable);
		repl[Anum_pg_extension_extrelocatable - 1] = true;
		values[Anum_pg_extension_extversion - 1] = CStringGetTextDatum(versionName);
		repl[Anum_pg_extension_extversion - 1] = true;

		extTup = heap_modify_tuple(extTup, RelationGetDescr(extRel), values, nulls, repl);

		CatalogTupleUpdate(extRel, &extTup->t_self, extTup);

		systable_endscan(extScan);

		heap_close(extRel, RowExclusiveLock);

		
		requiredExtensions = NIL;
		requiredSchemas = NIL;
		foreach(lc, control->requires)
		{
			char	   *curreq = (char *) lfirst(lc);
			Oid			reqext;
			Oid			reqschema;

			reqext = get_required_extension(curreq, control->name, origSchemaName, cascade, NIL, is_create);




			reqschema = get_extension_schema(reqext);
			requiredExtensions = lappend_oid(requiredExtensions, reqext);
			requiredSchemas = lappend_oid(requiredSchemas, reqschema);
		}

		
		deleteDependencyRecordsForClass(ExtensionRelationId, extensionOid, ExtensionRelationId, DEPENDENCY_NORMAL);


		myself.classId = ExtensionRelationId;
		myself.objectId = extensionOid;
		myself.objectSubId = 0;

		foreach(lc, requiredExtensions)
		{
			Oid			reqext = lfirst_oid(lc);
			ObjectAddress otherext;

			otherext.classId = ExtensionRelationId;
			otherext.objectId = reqext;
			otherext.objectSubId = 0;

			recordDependencyOn(&myself, &otherext, DEPENDENCY_NORMAL);
		}

		InvokeObjectPostAlterHook(ExtensionRelationId, extensionOid, 0);

		
		execute_extension_script(extensionOid, control, oldVersionName, versionName, requiredSchemas, schemaName, schemaOid);



		
		oldVersionName = versionName;
	}
}


ObjectAddress ExecAlterExtensionContentsStmt(AlterExtensionContentsStmt *stmt, ObjectAddress *objAddr)

{
	ObjectAddress extension;
	ObjectAddress object;
	Relation	relation;
	Oid			oldExtension;

	extension.classId = ExtensionRelationId;
	extension.objectId = get_extension_oid(stmt->extname, false);
	extension.objectSubId = 0;

	
	if (!pg_extension_ownercheck(extension.objectId, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, OBJECT_EXTENSION, stmt->extname);

	
	object = get_object_address(stmt->objtype, stmt->object, &relation, ShareUpdateExclusiveLock, false);

	Assert(object.objectSubId == 0);
	if (objAddr)
		*objAddr = object;

	
	check_object_ownership(GetUserId(), stmt->objtype, object, stmt->object, relation);

	
	oldExtension = getExtensionOfObject(object.classId, object.objectId);

	if (stmt->action > 0)
	{
		
		if (OidIsValid(oldExtension))
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("%s is already a member of extension \"%s\"", getObjectDescription(&object), get_extension_name(oldExtension))));




		
		if (object.classId == NamespaceRelationId && object.objectId == get_extension_schema(extension.objectId))
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("cannot add schema \"%s\" to extension \"%s\" " "because the schema contains the extension", get_namespace_name(object.objectId), stmt->extname)));





		
		recordDependencyOn(&object, &extension, DEPENDENCY_EXTENSION);

		
		recordExtObjInitPriv(object.objectId, object.classId);
	}
	else {
		
		if (oldExtension != extension.objectId)
			ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE), errmsg("%s is not a member of extension \"%s\"", getObjectDescription(&object), stmt->extname)));




		
		if (deleteDependencyRecordsForClass(object.classId, object.objectId, ExtensionRelationId, DEPENDENCY_EXTENSION) != 1)

			elog(ERROR, "unexpected number of extension dependency records");

		
		if (object.classId == RelationRelationId)
			extension_config_remove(extension.objectId, object.objectId);

		
		removeExtObjInitPriv(object.objectId, object.classId);
	}

	InvokeObjectPostAlterHook(ExtensionRelationId, extension.objectId, 0);

	
	if (relation != NULL)
		relation_close(relation, NoLock);

	return extension;
}


static char * read_whole_file(const char *filename, int *length)
{
	char	   *buf;
	FILE	   *file;
	size_t		bytes_to_read;
	struct stat fst;

	if (stat(filename, &fst) < 0)
		ereport(ERROR, (errcode_for_file_access(), errmsg("could not stat file \"%s\": %m", filename)));


	if (fst.st_size > (MaxAllocSize - 1))
		ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("file \"%s\" is too large", filename)));

	bytes_to_read = (size_t) fst.st_size;

	if ((file = AllocateFile(filename, PG_BINARY_R)) == NULL)
		ereport(ERROR, (errcode_for_file_access(), errmsg("could not open file \"%s\" for reading: %m", filename)));



	buf = (char *) palloc(bytes_to_read + 1);

	*length = fread(buf, 1, bytes_to_read, file);

	if (ferror(file))
		ereport(ERROR, (errcode_for_file_access(), errmsg("could not read file \"%s\": %m", filename)));


	FreeFile(file);

	buf[*length] = '\0';
	return buf;
}
