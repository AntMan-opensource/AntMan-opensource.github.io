










static struct {
	sqlite3 *db;
	char *error_msg;
} db_data = {
	NULL, NULL };



static char* db_gettime(char* d)
{
	time_t date = (time_t)atoi(d);
	struct tm *timeinfo = localtime(&date);
	char* tmp = asctime(timeinfo);
	tmp[strlen(tmp)-1] = '\0';
	return tmp;
}


static unsigned int db_getstamp(char* d)
{
	struct tm *timeinfo;
	
	if (strcmp(d,"now") == 0) {
		return (unsigned int)time(NULL);
	}

	
	if (getenv("DATEMSK") == 0) {
		create_datemask();
	}

	
	timeinfo = getdate(d);

	
	if (timeinfo == NULL) {
		fprintf(stderr,"invalid date format\n");
		return db_getstamp("now");
	}

	
	return mktime(timeinfo);
}


static int db_check()
{
	db_data.error_msg = NULL;
	sqlite3_exec(db_data.db, "CREATE TABLE IF NOT EXISTS nodau(name VARCHAR(255), date INTEGER UNSIGNED, text TEXT, encrypted BOOLEAN DEFAULT 'false')", NULL, 0, &db_data.error_msg);

	if (db_data.error_msg) {
		fprintf(stderr,"%s\n",db_data.error_msg);
		return 1;
	}

	return 0;
}


static sql_result *db_get(char* sql,...)
{
	
	sql_result *result;
	char dtmp[512];

	
	va_list ap;
	va_start(ap, sql);
	vsnprintf(dtmp, 512, sql, ap);
	va_end(ap);

	
	result = db_result_alloc();

	
	if (result == NULL)
		return NULL;

	db_data.error_msg = NULL;

	
	sqlite3_get_table(db_data.db, dtmp, &result->data, &result->num_rows, &result->num_cols, &db_data.error_msg);

	
	if (db_data.error_msg)
		return NULL;

	
	return result;
}


static int db_insert(char* name, char* value)
{
	
	char sql[1024];

	
	unsigned int date = (unsigned int)time(NULL);

	
	sprintf(sql, "INSERT INTO nodau values('%s','%u','%s','false')", name, date, value);

	
	return sqlite3_exec(db_data.db, sql, NULL, 0, &db_data.error_msg);
}


int db_connect()
{
	int c;
	char* f;
	char* xdh;
	char* fl;
	db_data.error_msg = NULL;

	f = getenv("HOME");
	xdh = getenv("XDG_DATA_HOME");

	
	if (!xdh || !xdh[0]) {
		if (asprintf(&fl,"%s/.local/share/nodau",f) < 0)
			return 1;
	}else{
		if (asprintf(&fl,"%s/nodau",xdh) < 0)
			return 1;
	}

	dir_create(fl);

	if (asprintf(&xdh,"%s/nodau.db",fl) < 0)
		return 1;

	free(fl);
	fl = xdh;

	
	c = sqlite3_open_v2(fl, &db_data.db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
	free(fl);

	
	if (c)
		return 1;

	c = db_check();

	
	if (c)
		return 1;

	
	if (!config_read("import_old_db","false")) {
		sqlite3 *odb;
		int i;
		sql_result *res = db_result_alloc();

		if (asprintf(&fl,"%s/.nodau",f) < 0)
			return 1;

		i = sqlite3_open_v2(fl, &odb, SQLITE_OPEN_READWRITE, NULL);
		if (!i) {
			sqlite3_get_table(odb, "SELECT * FROM nodau", &res->data, &res->num_rows, &res->num_cols, &db_data.error_msg);
			if (!db_data.error_msg) {
				if (res->num_rows) {
					puts("Importing from old database\n");
					for (i=0; i<res->num_rows; i++) {
						db_insert(res->data[OCOLUMN(i,COL_NAME)],res->data[OCOLUMN(i,COL_TEXT)]);
					}
				}
				db_result_free(res);
			}
		}
		config_write("import_old_db","false");
		free(fl);
	}

	
	return c;
}


void db_close()
{
	sqlite3_close(db_data.db);
}

const char* db_err()
{
	const char* m;

	m = sqlite3_errmsg(db_data.db);

	if (m)
		return m;

	return "Unknown Error";
}


sql_result *db_result_alloc()
{
	
	sql_result *res = malloc(sizeof(sql_result));

	
	if (res == NULL) {
		fprintf(stderr,"allocation failure\n");
		return NULL;
	}

	
	res->num_cols = 0;
	res->num_rows = 0;
	res->data = NULL;

	
	return res;
}


int db_result_free(sql_result *result)
{
	
	if (result == NULL)
		return 1;

	
	if (result->num_cols && result->num_rows && result->data) {
		sqlite3_free_table(result->data);
	}

	
	free(result);

	
	return 0;
}


int db_update(char* name, char* value)
{
	char* sql;
	int r = 0;
	
	if (crypt_key) {
		value = note_encrypt(value,crypt_key);
		r = asprintf(&sql, "UPDATE nodau set text='%s' , encrypted='true' WHERE name='%s'", value, name);
		free(value);
		if (r < 0)
			return 1;
	}else{
		if (asprintf(&sql, "UPDATE nodau set text='%s' , encrypted='false' WHERE name='%s'", value, name) < 0)
			return 1;
	}

	
	r = sqlite3_exec(db_data.db, sql, NULL, 0, &db_data.error_msg);
	free(sql);
	return r;
}


int db_list(char* search)
{
	sql_result *res = NULL;
	int i;
	char* pref = "match";

	
	if (search == NULL) {
		pref = "note";
		res = db_get("SELECT * FROM nodau");

		
		if (res->num_rows == 0) {
			printf("No notes to list\n");
			db_result_free(res);
			return 0;
		}
	}else{
		
		res = db_get("SELECT * FROM nodau WHERE name LIKE '%%%s%%'",search);

		
		if (res->num_rows == 0) {
			unsigned int idate;
			db_result_free(res);
			res = NULL;
			
			if (strncmp(search,"t@",2) == 0) {
				idate = db_getstamp(search+2);
				res = db_get("SELECT * FROM nodau WHERE date = %u", idate);
			
			}else if (strncmp(search,"t+",2) == 0) {
				idate = db_getstamp(search+2);
				res = db_get("SELECT * FROM nodau WHERE date > %u", idate);
			
			}else if (strncmp(search,"t-",2) == 0) {
				idate = db_getstamp(search+2);
				res = db_get("SELECT * FROM nodau WHERE date < %u", idate);
			}
		}
		
		if (!res || !res->num_rows || !res->num_cols) {
			printf("No notes match '%s'\n",search);
			return 0;
		}
	}

	
	for (i=0; i<res->num_rows; i++) {
		printf("%s %d: %s\n",pref,i+1,res->data[COLUMN(i,COL_NAME)]);
	}

	
	if (res)
		db_result_free(res);

	return 0;
}


int db_edit(char* search)
{
	char* date;
	char* name;
	char* text;
	char* crypt;
	int r;
	
	sql_result *result;
	result = db_get("SELECT * FROM nodau WHERE name = '%s'",search);

	
	if (result->num_rows == 0) {
		db_result_free(result);
		if (config_read("edit_autocreate","false")) {
			printf("No notes match '%s'\n",search);
		}else{
			 return db_new(search);
		}
		return 0;
	}

	
	date = db_gettime(result->data[COLUMN(0,COL_DATE)]);
	name = result->data[COLUMN(0,COL_NAME)];
	text = result->data[COLUMN(0,COL_TEXT)];
	crypt = result->data[COLUMN(0,COL_CRYPT)];

	
	if (!strcmp(crypt,"true")) {
		crypt = crypt_get_key();
		text = note_decrypt(text,crypt);
		if (!text)
			return 1;
	}

	
	r = edit(name, date, text);

	
	db_result_free(result);

	return r;
}


int db_append(char* search)
{
	char* date;
	char* name;
	char* text;
	char* crypt;
	int r;
	
	sql_result *result;
	result = db_get("SELECT * FROM nodau WHERE name = '%s'",search);

	
	if (result->num_rows == 0) {
		db_result_free(result);
		return db_new(search);
	}

	
	date = db_gettime(result->data[COLUMN(0,COL_DATE)]);
	name = result->data[COLUMN(0,COL_NAME)];
	text = result->data[COLUMN(0,COL_TEXT)];
	crypt = result->data[COLUMN(0,COL_CRYPT)];

	
	if (!strcmp(crypt,"true")) {
		crypt = crypt_get_key();
		text = note_decrypt(text,crypt);
		if (!text)
			return 1;
	}

	
	r = edit_stdin(name, date, text,1);

	
	db_result_free(result);

	return r;
}


int db_show(char* search)
{
	char* date;
	char* name;
	char* text;
	char* crypt;
	
	sql_result *result;
	result = db_get("SELECT * FROM nodau WHERE name = '%s'",search);

	
	if (result->num_rows == 0) {
		printf("No notes match '%s'\n",search);
		db_result_free(result);
		return 0;
	}

	
	date = db_gettime(result->data[COLUMN(0,COL_DATE)]);
	name = result->data[COLUMN(0,COL_NAME)];
	text = result->data[COLUMN(0,COL_TEXT)];
	crypt = result->data[COLUMN(0,COL_CRYPT)];

	
	if (!strcmp(crypt,"true")) {
		crypt = crypt_get_key();
		text = note_decrypt(text,crypt);
		if (!text)
			return 1;
	}

	
	printf("%s (%s):\n%s\n",name,date,text);

	
	db_result_free(result);

	return 0;
}


int db_del(char* search)
{
	char sql[512];
	unsigned int date = 0;
	
	sql_result *result;
	result = db_get("SELECT * FROM nodau WHERE name = '%s'",search);

	

	
	if (result->num_rows) {
		sprintf(sql, "DELETE FROM nodau WHERE name = '%s'", search);
	
	}else if (strncmp(search,"t@",2) == 0) {
		date = db_getstamp(search+2);
		sprintf(sql, "DELETE FROM nodau WHERE date = %u", date);
	
	}else if (strncmp(search,"t+",2) == 0) {
		date = db_getstamp(search+2);
		sprintf(sql, "DELETE FROM nodau WHERE date > %u", date);
	
	}else if (strncmp(search,"t-",2) == 0) {
		date = db_getstamp(search+2);
		sprintf(sql, "DELETE FROM nodau WHERE date < %u", date);
	
	}else{
		printf("No notes matches '%s'\n",search);
		return 0;
	}

	
	sqlite3_exec(db_data.db, sql, NULL, 0, &db_data.error_msg);

	
	db_result_free(result);

	return 0;
}


int db_new(char* search)
{
	
	sql_result *result;
	result = db_get("SELECT * FROM nodau WHERE name = '%s'",search);

	if (result) {
		
		if (result->num_rows) {
			printf("There is already a note called '%s'\n",search);
			db_result_free(result);
			return 1;
		}

		
		db_result_free(result);
	}

	
	db_insert(search,"new entry");

	if (db_data.error_msg)
		printf("%s\n",db_data.error_msg);

	
	return db_edit(search);
}


int db_encrypt(char* search)
{
	
	sql_result *result;
	char* crypt;
	int r = 0;
	result = db_get("SELECT * FROM nodau WHERE name = '%s'",search);

	
	if (result->num_rows) {
		char* name;
		char* text;

		
		name = result->data[COLUMN(0,COL_NAME)];
		text = result->data[COLUMN(0,COL_TEXT)];
		crypt = result->data[COLUMN(0,COL_CRYPT)];

		
		if (!strcmp(crypt,"false")) {
			crypt = crypt_get_key();
			r = db_update(name,text);
		}else{
			printf("Note '%s' is already encrypted\n",search);
		}
		db_result_free(result);
		return r;
	}

	
	db_result_free(result);

	
	db_insert(search,"new entry");

	if (db_data.error_msg)
		fprintf(stderr,"%s\n",db_data.error_msg);

	crypt = crypt_get_key();
	
	return db_edit(search);
}



int db_decrypt(char* search)
{
	
	sql_result *result;
	int r;
	result = db_get("SELECT * FROM nodau WHERE name = '%s'",search);

	
	if (result->num_rows) {
		char* text;
		char* crypt;

		
		text = result->data[COLUMN(0,COL_TEXT)];
		crypt = result->data[COLUMN(0,COL_CRYPT)];

		
		if (!strcmp(crypt,"true")) {
			char* t;
			crypt = crypt_get_key();
			t = note_decrypt(text,crypt);
			if (!t)
				return 1;
			free(crypt_key);
			crypt_key = NULL;
			r = db_update(search,t);
			db_result_free(result);
			return r;
		}else{
			printf("Note '%s' is not encrypted\n",search);
			db_result_free(result);
		}
		return 0;
	}

	printf("No notes matches '%s'\n",search);
	db_result_free(result);

	return 0;
}
