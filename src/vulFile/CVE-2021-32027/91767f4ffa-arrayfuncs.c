























bool		Array_nulls = true;









typedef enum {
	ARRAY_NO_LEVEL, ARRAY_LEVEL_STARTED, ARRAY_ELEM_STARTED, ARRAY_ELEM_COMPLETED, ARRAY_QUOTED_ELEM_STARTED, ARRAY_QUOTED_ELEM_COMPLETED, ARRAY_ELEM_DELIMITED, ARRAY_LEVEL_COMPLETED, ARRAY_LEVEL_DELIMITED } ArrayParseState;










typedef struct ArrayIteratorData {
	
	ArrayType  *arr;			
	bits8	   *nullbitmap;		
	int			nitems;			
	int16		typlen;			
	bool		typbyval;		
	char		typalign;		

	
	int			slice_ndim;		
	int			slice_len;		
	int		   *slice_dims;		
	int		   *slice_lbound;	
	Datum	   *slice_values;	
	bool	   *slice_nulls;	

	
	char	   *data_ptr;		
	int			current_item;	
}			ArrayIteratorData;

static bool array_isspace(char ch);
static int	ArrayCount(const char *str, int *dim, char typdelim);
static void ReadArrayStr(char *arrayStr, const char *origStr, int nitems, int ndim, int *dim, FmgrInfo *inputproc, Oid typioparam, int32 typmod, char typdelim, int typlen, bool typbyval, char typalign, Datum *values, bool *nulls, bool *hasnulls, int32 *nbytes);





static void ReadArrayBinary(StringInfo buf, int nitems, FmgrInfo *receiveproc, Oid typioparam, int32 typmod, int typlen, bool typbyval, char typalign, Datum *values, bool *nulls, bool *hasnulls, int32 *nbytes);



static Datum array_get_element_expanded(Datum arraydatum, int nSubscripts, int *indx, int arraytyplen, int elmlen, bool elmbyval, char elmalign, bool *isNull);



static Datum array_set_element_expanded(Datum arraydatum, int nSubscripts, int *indx, Datum dataValue, bool isNull, int arraytyplen, int elmlen, bool elmbyval, char elmalign);



static bool array_get_isnull(const bits8 *nullbitmap, int offset);
static void array_set_isnull(bits8 *nullbitmap, int offset, bool isNull);
static Datum ArrayCast(char *value, bool byval, int len);
static int ArrayCastAndSet(Datum src, int typlen, bool typbyval, char typalign, char *dest);

static char *array_seek(char *ptr, int offset, bits8 *nullbitmap, int nitems, int typlen, bool typbyval, char typalign);
static int array_nelems_size(char *ptr, int offset, bits8 *nullbitmap, int nitems, int typlen, bool typbyval, char typalign);
static int array_copy(char *destptr, int nitems, char *srcptr, int offset, bits8 *nullbitmap, int typlen, bool typbyval, char typalign);

static int array_slice_size(char *arraydataptr, bits8 *arraynullsptr, int ndim, int *dim, int *lb, int *st, int *endp, int typlen, bool typbyval, char typalign);


static void array_extract_slice(ArrayType *newarray, int ndim, int *dim, int *lb, char *arraydataptr, bits8 *arraynullsptr, int *st, int *endp, int typlen, bool typbyval, char typalign);



static void array_insert_slice(ArrayType *destArray, ArrayType *origArray, ArrayType *srcArray, int ndim, int *dim, int *lb, int *st, int *endp, int typlen, bool typbyval, char typalign);



static int	array_cmp(FunctionCallInfo fcinfo);
static ArrayType *create_array_envelope(int ndims, int *dimv, int *lbv, int nbytes, Oid elmtype, int dataoffset);
static ArrayType *array_fill_internal(ArrayType *dims, ArrayType *lbs, Datum value, bool isnull, Oid elmtype, FunctionCallInfo fcinfo);

static ArrayType *array_replace_internal(ArrayType *array, Datum search, bool search_isnull, Datum replace, bool replace_isnull, bool remove, Oid collation, FunctionCallInfo fcinfo);



static int	width_bucket_array_float8(Datum operand, ArrayType *thresholds);
static int width_bucket_array_fixed(Datum operand, ArrayType *thresholds, Oid collation, TypeCacheEntry *typentry);


static int width_bucket_array_variable(Datum operand, ArrayType *thresholds, Oid collation, TypeCacheEntry *typentry);





Datum array_in(PG_FUNCTION_ARGS)
{
	char	   *string = PG_GETARG_CSTRING(0);	
	Oid			element_type = PG_GETARG_OID(1);	
	int32		typmod = PG_GETARG_INT32(2);	
	int			typlen;
	bool		typbyval;
	char		typalign;
	char		typdelim;
	Oid			typioparam;
	char	   *string_save, *p;
	int			i, nitems;
	Datum	   *dataPtr;
	bool	   *nullsPtr;
	bool		hasnulls;
	int32		nbytes;
	int32		dataoffset;
	ArrayType  *retval;
	int			ndim, dim[MAXDIM], lBound[MAXDIM];

	ArrayMetaState *my_extra;

	
	my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;
	if (my_extra == NULL)
	{
		fcinfo->flinfo->fn_extra = MemoryContextAlloc(fcinfo->flinfo->fn_mcxt, sizeof(ArrayMetaState));
		my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;
		my_extra->element_type = ~element_type;
	}

	if (my_extra->element_type != element_type)
	{
		
		get_type_io_data(element_type, IOFunc_input, &my_extra->typlen, &my_extra->typbyval, &my_extra->typalign, &my_extra->typdelim, &my_extra->typioparam, &my_extra->typiofunc);


		fmgr_info_cxt(my_extra->typiofunc, &my_extra->proc, fcinfo->flinfo->fn_mcxt);
		my_extra->element_type = element_type;
	}
	typlen = my_extra->typlen;
	typbyval = my_extra->typbyval;
	typalign = my_extra->typalign;
	typdelim = my_extra->typdelim;
	typioparam = my_extra->typioparam;

	
	string_save = pstrdup(string);

	
	p = string_save;
	ndim = 0;
	for (;;)
	{
		char	   *q;
		int			ub;

		
		while (array_isspace(*p))
			p++;
		if (*p != '[')
			break;				
		p++;
		if (ndim >= MAXDIM)
			ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("number of array dimensions (%d) exceeds the maximum allowed (%d)", ndim + 1, MAXDIM)));



		for (q = p; isdigit((unsigned char) *q) || (*q == '-') || (*q == '+'); q++)
			  ;
		if (q == p)				
			ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", string), errdetail("\"[\" must introduce explicitly-specified array dimensions.")));



		if (*q == ':')
		{
			
			*q = '\0';
			lBound[ndim] = atoi(p);
			p = q + 1;
			for (q = p; isdigit((unsigned char) *q) || (*q == '-') || (*q == '+'); q++)
				  ;
			if (q == p)			
				ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", string), errdetail("Missing array dimension value.")));


		}
		else {
			
			lBound[ndim] = 1;
		}
		if (*q != ']')
			ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", string), errdetail("Missing \"%s\" after array dimensions.", "]")));




		*q = '\0';
		ub = atoi(p);
		p = q + 1;
		if (ub < lBound[ndim])
			ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("upper bound cannot be less than lower bound")));


		dim[ndim] = ub - lBound[ndim] + 1;
		ndim++;
	}

	if (ndim == 0)
	{
		
		if (*p != '{')
			ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", string), errdetail("Array value must start with \"{\" or dimension information.")));


		ndim = ArrayCount(p, dim, typdelim);
		for (i = 0; i < ndim; i++)
			lBound[i] = 1;
	}
	else {
		int			ndim_braces, dim_braces[MAXDIM];

		
		if (strncmp(p, ASSGN, strlen(ASSGN)) != 0)
			ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", string), errdetail("Missing \"%s\" after array dimensions.", ASSGN)));



		p += strlen(ASSGN);
		while (array_isspace(*p))
			p++;

		
		if (*p != '{')
			ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", string), errdetail("Array contents must start with \"{\".")));


		ndim_braces = ArrayCount(p, dim_braces, typdelim);
		if (ndim_braces != ndim)
			ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", string), errdetail("Specified array dimensions do not match array contents.")));


		for (i = 0; i < ndim; ++i)
		{
			if (dim[i] != dim_braces[i])
				ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", string), errdetail("Specified array dimensions do not match array contents.")));


		}
	}


	printf("array_in- ndim %d (", ndim);
	for (i = 0; i < ndim; i++)
	{
		printf(" %d", dim[i]);
	};
	printf(") for %s\n", string);


	
	nitems = ArrayGetNItems(ndim, dim);
	
	if (nitems == 0)
		PG_RETURN_ARRAYTYPE_P(construct_empty_array(element_type));

	dataPtr = (Datum *) palloc(nitems * sizeof(Datum));
	nullsPtr = (bool *) palloc(nitems * sizeof(bool));
	ReadArrayStr(p, string, nitems, ndim, dim, &my_extra->proc, typioparam, typmod, typdelim, typlen, typbyval, typalign, dataPtr, nullsPtr, &hasnulls, &nbytes);





	if (hasnulls)
	{
		dataoffset = ARR_OVERHEAD_WITHNULLS(ndim, nitems);
		nbytes += dataoffset;
	}
	else {
		dataoffset = 0;			
		nbytes += ARR_OVERHEAD_NONULLS(ndim);
	}
	retval = (ArrayType *) palloc0(nbytes);
	SET_VARSIZE(retval, nbytes);
	retval->ndim = ndim;
	retval->dataoffset = dataoffset;

	
	retval->elemtype = element_type;
	memcpy(ARR_DIMS(retval), dim, ndim * sizeof(int));
	memcpy(ARR_LBOUND(retval), lBound, ndim * sizeof(int));

	CopyArrayEls(retval, dataPtr, nullsPtr, nitems, typlen, typbyval, typalign, true);



	pfree(dataPtr);
	pfree(nullsPtr);
	pfree(string_save);

	PG_RETURN_ARRAYTYPE_P(retval);
}


static bool array_isspace(char ch)
{
	if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\v' || ch == '\f')




		return true;
	return false;
}


static int ArrayCount(const char *str, int *dim, char typdelim)
{
	int			nest_level = 0, i;
	int			ndim = 1, temp[MAXDIM], nelems[MAXDIM], nelems_last[MAXDIM];


	bool		in_quotes = false;
	bool		eoArray = false;
	bool		empty_array = true;
	const char *ptr;
	ArrayParseState parse_state = ARRAY_NO_LEVEL;

	for (i = 0; i < MAXDIM; ++i)
	{
		temp[i] = dim[i] = nelems_last[i] = 0;
		nelems[i] = 1;
	}

	ptr = str;
	while (!eoArray)
	{
		bool		itemdone = false;

		while (!itemdone)
		{
			if (parse_state == ARRAY_ELEM_STARTED || parse_state == ARRAY_QUOTED_ELEM_STARTED)
				empty_array = false;

			switch (*ptr)
			{
				case '\0':
					
					ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", str), errdetail("Unexpected end of input.")));


					break;
				case '\\':

					
					if (parse_state != ARRAY_LEVEL_STARTED && parse_state != ARRAY_ELEM_STARTED && parse_state != ARRAY_QUOTED_ELEM_STARTED && parse_state != ARRAY_ELEM_DELIMITED)


						ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", str), errdetail("Unexpected \"%c\" character.", '\\')));



					if (parse_state != ARRAY_QUOTED_ELEM_STARTED)
						parse_state = ARRAY_ELEM_STARTED;
					
					if (*(ptr + 1))
						ptr++;
					else ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", str), errdetail("Unexpected end of input.")));



					break;
				case '"':

					
					if (parse_state != ARRAY_LEVEL_STARTED && parse_state != ARRAY_QUOTED_ELEM_STARTED && parse_state != ARRAY_ELEM_DELIMITED)

						ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", str), errdetail("Unexpected array element.")));


					in_quotes = !in_quotes;
					if (in_quotes)
						parse_state = ARRAY_QUOTED_ELEM_STARTED;
					else parse_state = ARRAY_QUOTED_ELEM_COMPLETED;
					break;
				case '{':
					if (!in_quotes)
					{
						
						if (parse_state != ARRAY_NO_LEVEL && parse_state != ARRAY_LEVEL_STARTED && parse_state != ARRAY_LEVEL_DELIMITED)

							ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", str), errdetail("Unexpected \"%c\" character.", '{')));



						parse_state = ARRAY_LEVEL_STARTED;
						if (nest_level >= MAXDIM)
							ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("number of array dimensions (%d) exceeds the maximum allowed (%d)", nest_level + 1, MAXDIM)));


						temp[nest_level] = 0;
						nest_level++;
						if (ndim < nest_level)
							ndim = nest_level;
					}
					break;
				case '}':
					if (!in_quotes)
					{
						
						if (parse_state != ARRAY_ELEM_STARTED && parse_state != ARRAY_ELEM_COMPLETED && parse_state != ARRAY_QUOTED_ELEM_COMPLETED && parse_state != ARRAY_LEVEL_COMPLETED && !(nest_level == 1 && parse_state == ARRAY_LEVEL_STARTED))



							ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", str), errdetail("Unexpected \"%c\" character.", '}')));



						parse_state = ARRAY_LEVEL_COMPLETED;
						if (nest_level == 0)
							ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", str), errdetail("Unmatched \"%c\" character.", '}')));


						nest_level--;

						if (nelems_last[nest_level] != 0 && nelems[nest_level] != nelems_last[nest_level])
							ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", str), errdetail("Multidimensional arrays must have " "sub-arrays with matching " "dimensions.")));




						nelems_last[nest_level] = nelems[nest_level];
						nelems[nest_level] = 1;
						if (nest_level == 0)
							eoArray = itemdone = true;
						else {
							
							temp[nest_level - 1]++;
						}
					}
					break;
				default:
					if (!in_quotes)
					{
						if (*ptr == typdelim)
						{
							
							if (parse_state != ARRAY_ELEM_STARTED && parse_state != ARRAY_ELEM_COMPLETED && parse_state != ARRAY_QUOTED_ELEM_COMPLETED && parse_state != ARRAY_LEVEL_COMPLETED)


								ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", str), errdetail("Unexpected \"%c\" character.", typdelim)));



							if (parse_state == ARRAY_LEVEL_COMPLETED)
								parse_state = ARRAY_LEVEL_DELIMITED;
							else parse_state = ARRAY_ELEM_DELIMITED;
							itemdone = true;
							nelems[nest_level - 1]++;
						}
						else if (!array_isspace(*ptr))
						{
							
							if (parse_state != ARRAY_LEVEL_STARTED && parse_state != ARRAY_ELEM_STARTED && parse_state != ARRAY_ELEM_DELIMITED)

								ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", str), errdetail("Unexpected array element.")));


							parse_state = ARRAY_ELEM_STARTED;
						}
					}
					break;
			}
			if (!itemdone)
				ptr++;
		}
		temp[ndim - 1]++;
		ptr++;
	}

	
	while (*ptr)
	{
		if (!array_isspace(*ptr++))
			ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", str), errdetail("Junk after closing right brace.")));


	}

	
	if (empty_array)
		return 0;

	for (i = 0; i < ndim; ++i)
		dim[i] = temp[i];

	return ndim;
}


static void ReadArrayStr(char *arrayStr, const char *origStr, int nitems, int ndim, int *dim, FmgrInfo *inputproc, Oid typioparam, int32 typmod, char typdelim, int typlen, bool typbyval, char typalign, Datum *values, bool *nulls, bool *hasnulls, int32 *nbytes)















{
	int			i, nest_level = 0;
	char	   *srcptr;
	bool		in_quotes = false;
	bool		eoArray = false;
	bool		hasnull;
	int32		totbytes;
	int			indx[MAXDIM], prod[MAXDIM];

	mda_get_prod(ndim, dim, prod);
	MemSet(indx, 0, sizeof(indx));

	
	memset(nulls, true, nitems * sizeof(bool));

	
	srcptr = arrayStr;
	while (!eoArray)
	{
		bool		itemdone = false;
		bool		leadingspace = true;
		bool		hasquoting = false;
		char	   *itemstart;
		char	   *dstptr;
		char	   *dstendptr;

		i = -1;
		itemstart = dstptr = dstendptr = srcptr;

		while (!itemdone)
		{
			switch (*srcptr)
			{
				case '\0':
					
					ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", origStr)));


					break;
				case '\\':
					
					srcptr++;
					if (*srcptr == '\0')
						ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", origStr)));


					*dstptr++ = *srcptr++;
					
					leadingspace = false;
					dstendptr = dstptr;
					hasquoting = true;	
					break;
				case '"':
					in_quotes = !in_quotes;
					if (in_quotes)
						leadingspace = false;
					else {
						
						dstendptr = dstptr;
					}
					hasquoting = true;	
					srcptr++;
					break;
				case '{':
					if (!in_quotes)
					{
						if (nest_level >= ndim)
							ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", origStr)));


						nest_level++;
						indx[nest_level - 1] = 0;
						srcptr++;
					}
					else *dstptr++ = *srcptr++;
					break;
				case '}':
					if (!in_quotes)
					{
						if (nest_level == 0)
							ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", origStr)));


						if (i == -1)
							i = ArrayGetOffset0(ndim, indx, prod);
						indx[nest_level - 1] = 0;
						nest_level--;
						if (nest_level == 0)
							eoArray = itemdone = true;
						else indx[nest_level - 1]++;
						srcptr++;
					}
					else *dstptr++ = *srcptr++;
					break;
				default:
					if (in_quotes)
						*dstptr++ = *srcptr++;
					else if (*srcptr == typdelim)
					{
						if (i == -1)
							i = ArrayGetOffset0(ndim, indx, prod);
						itemdone = true;
						indx[ndim - 1]++;
						srcptr++;
					}
					else if (array_isspace(*srcptr))
					{
						
						if (leadingspace)
							srcptr++;
						else *dstptr++ = *srcptr++;
					}
					else {
						*dstptr++ = *srcptr++;
						leadingspace = false;
						dstendptr = dstptr;
					}
					break;
			}
		}

		Assert(dstptr < srcptr);
		*dstendptr = '\0';

		if (i < 0 || i >= nitems)
			ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION), errmsg("malformed array literal: \"%s\"", origStr)));



		if (Array_nulls && !hasquoting && pg_strcasecmp(itemstart, "NULL") == 0)
		{
			
			values[i] = InputFunctionCall(inputproc, NULL, typioparam, typmod);
			nulls[i] = true;
		}
		else {
			values[i] = InputFunctionCall(inputproc, itemstart, typioparam, typmod);
			nulls[i] = false;
		}
	}

	
	hasnull = false;
	totbytes = 0;
	for (i = 0; i < nitems; i++)
	{
		if (nulls[i])
			hasnull = true;
		else {
			
			if (typlen == -1)
				values[i] = PointerGetDatum(PG_DETOAST_DATUM(values[i]));
			totbytes = att_addlength_datum(totbytes, typlen, values[i]);
			totbytes = att_align_nominal(totbytes, typalign);
			
			if (!AllocSizeIsValid(totbytes))
				ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("array size exceeds the maximum allowed (%d)", (int) MaxAllocSize)));


		}
	}
	*hasnulls = hasnull;
	*nbytes = totbytes;
}



void CopyArrayEls(ArrayType *array, Datum *values, bool *nulls, int nitems, int typlen, bool typbyval, char typalign, bool freedata)







{
	char	   *p = ARR_DATA_PTR(array);
	bits8	   *bitmap = ARR_NULLBITMAP(array);
	int			bitval = 0;
	int			bitmask = 1;
	int			i;

	if (typbyval)
		freedata = false;

	for (i = 0; i < nitems; i++)
	{
		if (nulls && nulls[i])
		{
			if (!bitmap)		
				elog(ERROR, "null array element where not supported");
			
		}
		else {
			bitval |= bitmask;
			p += ArrayCastAndSet(values[i], typlen, typbyval, typalign, p);
			if (freedata)
				pfree(DatumGetPointer(values[i]));
		}
		if (bitmap)
		{
			bitmask <<= 1;
			if (bitmask == 0x100)
			{
				*bitmap++ = bitval;
				bitval = 0;
				bitmask = 1;
			}
		}
	}

	if (bitmap && bitmask != 1)
		*bitmap = bitval;
}


Datum array_out(PG_FUNCTION_ARGS)
{
	AnyArrayType *v = PG_GETARG_ANY_ARRAY_P(0);
	Oid			element_type = AARR_ELEMTYPE(v);
	int			typlen;
	bool		typbyval;
	char		typalign;
	char		typdelim;
	char	   *p, *tmp, *retval, **values, dims_str[(MAXDIM * 33) + 2];




	
	bool	   *needquotes, needdims = false;
	size_t		overall_length;
	int			nitems, i, j, k, indx[MAXDIM];



	int			ndim, *dims, *lb;

	array_iter	iter;
	ArrayMetaState *my_extra;

	
	my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;
	if (my_extra == NULL)
	{
		fcinfo->flinfo->fn_extra = MemoryContextAlloc(fcinfo->flinfo->fn_mcxt, sizeof(ArrayMetaState));
		my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;
		my_extra->element_type = ~element_type;
	}

	if (my_extra->element_type != element_type)
	{
		
		get_type_io_data(element_type, IOFunc_output, &my_extra->typlen, &my_extra->typbyval, &my_extra->typalign, &my_extra->typdelim, &my_extra->typioparam, &my_extra->typiofunc);


		fmgr_info_cxt(my_extra->typiofunc, &my_extra->proc, fcinfo->flinfo->fn_mcxt);
		my_extra->element_type = element_type;
	}
	typlen = my_extra->typlen;
	typbyval = my_extra->typbyval;
	typalign = my_extra->typalign;
	typdelim = my_extra->typdelim;

	ndim = AARR_NDIM(v);
	dims = AARR_DIMS(v);
	lb = AARR_LBOUND(v);
	nitems = ArrayGetNItems(ndim, dims);

	if (nitems == 0)
	{
		retval = pstrdup("{}");
		PG_RETURN_CSTRING(retval);
	}

	
	for (i = 0; i < ndim; i++)
	{
		if (lb[i] != 1)
		{
			needdims = true;
			break;
		}
	}

	
	values = (char **) palloc(nitems * sizeof(char *));
	needquotes = (bool *) palloc(nitems * sizeof(bool));
	overall_length = 0;

	array_iter_setup(&iter, v);

	for (i = 0; i < nitems; i++)
	{
		Datum		itemvalue;
		bool		isnull;
		bool		needquote;

		
		itemvalue = array_iter_next(&iter, &isnull, i, typlen, typbyval, typalign);

		if (isnull)
		{
			values[i] = pstrdup("NULL");
			overall_length += 4;
			needquote = false;
		}
		else {
			values[i] = OutputFunctionCall(&my_extra->proc, itemvalue);

			
			if (values[i][0] == '\0')
				needquote = true;	
			else if (pg_strcasecmp(values[i], "NULL") == 0)
				needquote = true;	
			else needquote = false;

			for (tmp = values[i]; *tmp != '\0'; tmp++)
			{
				char		ch = *tmp;

				overall_length += 1;
				if (ch == '"' || ch == '\\')
				{
					needquote = true;
					overall_length += 1;
				}
				else if (ch == '{' || ch == '}' || ch == typdelim || array_isspace(ch))
					needquote = true;
			}
		}

		needquotes[i] = needquote;

		
		if (needquote)
			overall_length += 2;
		
		overall_length += 1;
	}

	
	for (i = j = 0, k = 1; i < ndim; i++)
	{
		j += k, k *= dims[i];
	}
	overall_length += 2 * j;

	
	dims_str[0] = '\0';
	if (needdims)
	{
		char	   *ptr = dims_str;

		for (i = 0; i < ndim; i++)
		{
			sprintf(ptr, "[%d:%d]", lb[i], lb[i] + dims[i] - 1);
			ptr += strlen(ptr);
		}
		*ptr++ = *ASSGN;
		*ptr = '\0';
		overall_length += ptr - dims_str;
	}

	
	retval = (char *) palloc(overall_length);
	p = retval;




	if (needdims)
		APPENDSTR(dims_str);
	APPENDCHAR('{');
	for (i = 0; i < ndim; i++)
		indx[i] = 0;
	j = 0;
	k = 0;
	do {
		for (i = j; i < ndim - 1; i++)
			APPENDCHAR('{');

		if (needquotes[k])
		{
			APPENDCHAR('"');
			for (tmp = values[k]; *tmp; tmp++)
			{
				char		ch = *tmp;

				if (ch == '"' || ch == '\\')
					*p++ = '\\';
				*p++ = ch;
			}
			*p = '\0';
			APPENDCHAR('"');
		}
		else APPENDSTR(values[k]);
		pfree(values[k++]);

		for (i = ndim - 1; i >= 0; i--)
		{
			if (++(indx[i]) < dims[i])
			{
				APPENDCHAR(typdelim);
				break;
			}
			else {
				indx[i] = 0;
				APPENDCHAR('}');
			}
		}
		j = i;
	} while (j != -1);




	
	Assert(overall_length == (p - retval + 1));

	pfree(values);
	pfree(needquotes);

	PG_RETURN_CSTRING(retval);
}


Datum array_recv(PG_FUNCTION_ARGS)
{
	StringInfo	buf = (StringInfo) PG_GETARG_POINTER(0);
	Oid			spec_element_type = PG_GETARG_OID(1);	
	int32		typmod = PG_GETARG_INT32(2);	
	Oid			element_type;
	int			typlen;
	bool		typbyval;
	char		typalign;
	Oid			typioparam;
	int			i, nitems;
	Datum	   *dataPtr;
	bool	   *nullsPtr;
	bool		hasnulls;
	int32		nbytes;
	int32		dataoffset;
	ArrayType  *retval;
	int			ndim, flags, dim[MAXDIM], lBound[MAXDIM];


	ArrayMetaState *my_extra;

	
	ndim = pq_getmsgint(buf, 4);
	if (ndim < 0)				
		ereport(ERROR, (errcode(ERRCODE_INVALID_BINARY_REPRESENTATION), errmsg("invalid number of dimensions: %d", ndim)));

	if (ndim > MAXDIM)
		ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("number of array dimensions (%d) exceeds the maximum allowed (%d)", ndim, MAXDIM)));



	flags = pq_getmsgint(buf, 4);
	if (flags != 0 && flags != 1)
		ereport(ERROR, (errcode(ERRCODE_INVALID_BINARY_REPRESENTATION), errmsg("invalid array flags")));


	element_type = pq_getmsgint(buf, sizeof(Oid));
	if (element_type != spec_element_type)
	{
		
		ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("wrong element type")));

	}

	for (i = 0; i < ndim; i++)
	{
		dim[i] = pq_getmsgint(buf, 4);
		lBound[i] = pq_getmsgint(buf, 4);

		
		if (dim[i] != 0)
		{
			int			ub = lBound[i] + dim[i] - 1;

			if (lBound[i] > ub)
				ereport(ERROR, (errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE), errmsg("integer out of range")));

		}
	}

	
	nitems = ArrayGetNItems(ndim, dim);

	
	my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;
	if (my_extra == NULL)
	{
		fcinfo->flinfo->fn_extra = MemoryContextAlloc(fcinfo->flinfo->fn_mcxt, sizeof(ArrayMetaState));
		my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;
		my_extra->element_type = ~element_type;
	}

	if (my_extra->element_type != element_type)
	{
		
		get_type_io_data(element_type, IOFunc_receive, &my_extra->typlen, &my_extra->typbyval, &my_extra->typalign, &my_extra->typdelim, &my_extra->typioparam, &my_extra->typiofunc);


		if (!OidIsValid(my_extra->typiofunc))
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("no binary input function available for type %s", format_type_be(element_type))));


		fmgr_info_cxt(my_extra->typiofunc, &my_extra->proc, fcinfo->flinfo->fn_mcxt);
		my_extra->element_type = element_type;
	}

	if (nitems == 0)
	{
		
		PG_RETURN_ARRAYTYPE_P(construct_empty_array(element_type));
	}

	typlen = my_extra->typlen;
	typbyval = my_extra->typbyval;
	typalign = my_extra->typalign;
	typioparam = my_extra->typioparam;

	dataPtr = (Datum *) palloc(nitems * sizeof(Datum));
	nullsPtr = (bool *) palloc(nitems * sizeof(bool));
	ReadArrayBinary(buf, nitems, &my_extra->proc, typioparam, typmod, typlen, typbyval, typalign, dataPtr, nullsPtr, &hasnulls, &nbytes);



	if (hasnulls)
	{
		dataoffset = ARR_OVERHEAD_WITHNULLS(ndim, nitems);
		nbytes += dataoffset;
	}
	else {
		dataoffset = 0;			
		nbytes += ARR_OVERHEAD_NONULLS(ndim);
	}
	retval = (ArrayType *) palloc0(nbytes);
	SET_VARSIZE(retval, nbytes);
	retval->ndim = ndim;
	retval->dataoffset = dataoffset;
	retval->elemtype = element_type;
	memcpy(ARR_DIMS(retval), dim, ndim * sizeof(int));
	memcpy(ARR_LBOUND(retval), lBound, ndim * sizeof(int));

	CopyArrayEls(retval, dataPtr, nullsPtr, nitems, typlen, typbyval, typalign, true);



	pfree(dataPtr);
	pfree(nullsPtr);

	PG_RETURN_ARRAYTYPE_P(retval);
}


static void ReadArrayBinary(StringInfo buf, int nitems, FmgrInfo *receiveproc, Oid typioparam, int32 typmod, int typlen, bool typbyval, char typalign, Datum *values, bool *nulls, bool *hasnulls, int32 *nbytes)











{
	int			i;
	bool		hasnull;
	int32		totbytes;

	for (i = 0; i < nitems; i++)
	{
		int			itemlen;
		StringInfoData elem_buf;
		char		csave;

		
		itemlen = pq_getmsgint(buf, 4);
		if (itemlen < -1 || itemlen > (buf->len - buf->cursor))
			ereport(ERROR, (errcode(ERRCODE_INVALID_BINARY_REPRESENTATION), errmsg("insufficient data left in message")));


		if (itemlen == -1)
		{
			
			values[i] = ReceiveFunctionCall(receiveproc, NULL, typioparam, typmod);
			nulls[i] = true;
			continue;
		}

		
		elem_buf.data = &buf->data[buf->cursor];
		elem_buf.maxlen = itemlen + 1;
		elem_buf.len = itemlen;
		elem_buf.cursor = 0;

		buf->cursor += itemlen;

		csave = buf->data[buf->cursor];
		buf->data[buf->cursor] = '\0';

		
		values[i] = ReceiveFunctionCall(receiveproc, &elem_buf, typioparam, typmod);
		nulls[i] = false;

		
		if (elem_buf.cursor != itemlen)
			ereport(ERROR, (errcode(ERRCODE_INVALID_BINARY_REPRESENTATION), errmsg("improper binary format in array element %d", i + 1)));



		buf->data[buf->cursor] = csave;
	}

	
	hasnull = false;
	totbytes = 0;
	for (i = 0; i < nitems; i++)
	{
		if (nulls[i])
			hasnull = true;
		else {
			
			if (typlen == -1)
				values[i] = PointerGetDatum(PG_DETOAST_DATUM(values[i]));
			totbytes = att_addlength_datum(totbytes, typlen, values[i]);
			totbytes = att_align_nominal(totbytes, typalign);
			
			if (!AllocSizeIsValid(totbytes))
				ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("array size exceeds the maximum allowed (%d)", (int) MaxAllocSize)));


		}
	}
	*hasnulls = hasnull;
	*nbytes = totbytes;
}



Datum array_send(PG_FUNCTION_ARGS)
{
	AnyArrayType *v = PG_GETARG_ANY_ARRAY_P(0);
	Oid			element_type = AARR_ELEMTYPE(v);
	int			typlen;
	bool		typbyval;
	char		typalign;
	int			nitems, i;
	int			ndim, *dim, *lb;

	StringInfoData buf;
	array_iter	iter;
	ArrayMetaState *my_extra;

	
	my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;
	if (my_extra == NULL)
	{
		fcinfo->flinfo->fn_extra = MemoryContextAlloc(fcinfo->flinfo->fn_mcxt, sizeof(ArrayMetaState));
		my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;
		my_extra->element_type = ~element_type;
	}

	if (my_extra->element_type != element_type)
	{
		
		get_type_io_data(element_type, IOFunc_send, &my_extra->typlen, &my_extra->typbyval, &my_extra->typalign, &my_extra->typdelim, &my_extra->typioparam, &my_extra->typiofunc);


		if (!OidIsValid(my_extra->typiofunc))
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("no binary output function available for type %s", format_type_be(element_type))));


		fmgr_info_cxt(my_extra->typiofunc, &my_extra->proc, fcinfo->flinfo->fn_mcxt);
		my_extra->element_type = element_type;
	}
	typlen = my_extra->typlen;
	typbyval = my_extra->typbyval;
	typalign = my_extra->typalign;

	ndim = AARR_NDIM(v);
	dim = AARR_DIMS(v);
	lb = AARR_LBOUND(v);
	nitems = ArrayGetNItems(ndim, dim);

	pq_begintypsend(&buf);

	
	pq_sendint32(&buf, ndim);
	pq_sendint32(&buf, AARR_HASNULL(v) ? 1 : 0);
	pq_sendint32(&buf, element_type);
	for (i = 0; i < ndim; i++)
	{
		pq_sendint32(&buf, dim[i]);
		pq_sendint32(&buf, lb[i]);
	}

	
	array_iter_setup(&iter, v);

	for (i = 0; i < nitems; i++)
	{
		Datum		itemvalue;
		bool		isnull;

		
		itemvalue = array_iter_next(&iter, &isnull, i, typlen, typbyval, typalign);

		if (isnull)
		{
			
			pq_sendint32(&buf, -1);
		}
		else {
			bytea	   *outputbytes;

			outputbytes = SendFunctionCall(&my_extra->proc, itemvalue);
			pq_sendint32(&buf, VARSIZE(outputbytes) - VARHDRSZ);
			pq_sendbytes(&buf, VARDATA(outputbytes), VARSIZE(outputbytes) - VARHDRSZ);
			pfree(outputbytes);
		}
	}

	PG_RETURN_BYTEA_P(pq_endtypsend(&buf));
}


Datum array_ndims(PG_FUNCTION_ARGS)
{
	AnyArrayType *v = PG_GETARG_ANY_ARRAY_P(0);

	
	if (AARR_NDIM(v) <= 0 || AARR_NDIM(v) > MAXDIM)
		PG_RETURN_NULL();

	PG_RETURN_INT32(AARR_NDIM(v));
}


Datum array_dims(PG_FUNCTION_ARGS)
{
	AnyArrayType *v = PG_GETARG_ANY_ARRAY_P(0);
	char	   *p;
	int			i;
	int		   *dimv, *lb;

	
	char		buf[MAXDIM * 33 + 1];

	
	if (AARR_NDIM(v) <= 0 || AARR_NDIM(v) > MAXDIM)
		PG_RETURN_NULL();

	dimv = AARR_DIMS(v);
	lb = AARR_LBOUND(v);

	p = buf;
	for (i = 0; i < AARR_NDIM(v); i++)
	{
		sprintf(p, "[%d:%d]", lb[i], dimv[i] + lb[i] - 1);
		p += strlen(p);
	}

	PG_RETURN_TEXT_P(cstring_to_text(buf));
}


Datum array_lower(PG_FUNCTION_ARGS)
{
	AnyArrayType *v = PG_GETARG_ANY_ARRAY_P(0);
	int			reqdim = PG_GETARG_INT32(1);
	int		   *lb;
	int			result;

	
	if (AARR_NDIM(v) <= 0 || AARR_NDIM(v) > MAXDIM)
		PG_RETURN_NULL();

	
	if (reqdim <= 0 || reqdim > AARR_NDIM(v))
		PG_RETURN_NULL();

	lb = AARR_LBOUND(v);
	result = lb[reqdim - 1];

	PG_RETURN_INT32(result);
}


Datum array_upper(PG_FUNCTION_ARGS)
{
	AnyArrayType *v = PG_GETARG_ANY_ARRAY_P(0);
	int			reqdim = PG_GETARG_INT32(1);
	int		   *dimv, *lb;
	int			result;

	
	if (AARR_NDIM(v) <= 0 || AARR_NDIM(v) > MAXDIM)
		PG_RETURN_NULL();

	
	if (reqdim <= 0 || reqdim > AARR_NDIM(v))
		PG_RETURN_NULL();

	lb = AARR_LBOUND(v);
	dimv = AARR_DIMS(v);

	result = dimv[reqdim - 1] + lb[reqdim - 1] - 1;

	PG_RETURN_INT32(result);
}


Datum array_length(PG_FUNCTION_ARGS)
{
	AnyArrayType *v = PG_GETARG_ANY_ARRAY_P(0);
	int			reqdim = PG_GETARG_INT32(1);
	int		   *dimv;
	int			result;

	
	if (AARR_NDIM(v) <= 0 || AARR_NDIM(v) > MAXDIM)
		PG_RETURN_NULL();

	
	if (reqdim <= 0 || reqdim > AARR_NDIM(v))
		PG_RETURN_NULL();

	dimv = AARR_DIMS(v);

	result = dimv[reqdim - 1];

	PG_RETURN_INT32(result);
}


Datum array_cardinality(PG_FUNCTION_ARGS)
{
	AnyArrayType *v = PG_GETARG_ANY_ARRAY_P(0);

	PG_RETURN_INT32(ArrayGetNItems(AARR_NDIM(v), AARR_DIMS(v)));
}



Datum array_get_element(Datum arraydatum, int nSubscripts, int *indx, int arraytyplen, int elmlen, bool elmbyval, char elmalign, bool *isNull)







{
	int			i, ndim, *dim, *lb, offset, fixedDim[1], fixedLb[1];





	char	   *arraydataptr, *retptr;
	bits8	   *arraynullsptr;

	if (arraytyplen > 0)
	{
		
		ndim = 1;
		fixedDim[0] = arraytyplen / elmlen;
		fixedLb[0] = 0;
		dim = fixedDim;
		lb = fixedLb;
		arraydataptr = (char *) DatumGetPointer(arraydatum);
		arraynullsptr = NULL;
	}
	else if (VARATT_IS_EXTERNAL_EXPANDED(DatumGetPointer(arraydatum)))
	{
		
		return array_get_element_expanded(arraydatum, nSubscripts, indx, arraytyplen, elmlen, elmbyval, elmalign, isNull);






	}
	else {
		
		ArrayType  *array = DatumGetArrayTypeP(arraydatum);

		ndim = ARR_NDIM(array);
		dim = ARR_DIMS(array);
		lb = ARR_LBOUND(array);
		arraydataptr = ARR_DATA_PTR(array);
		arraynullsptr = ARR_NULLBITMAP(array);
	}

	
	if (ndim != nSubscripts || ndim <= 0 || ndim > MAXDIM)
	{
		*isNull = true;
		return (Datum) 0;
	}
	for (i = 0; i < ndim; i++)
	{
		if (indx[i] < lb[i] || indx[i] >= (dim[i] + lb[i]))
		{
			*isNull = true;
			return (Datum) 0;
		}
	}

	
	offset = ArrayGetOffset(nSubscripts, dim, lb, indx);

	
	if (array_get_isnull(arraynullsptr, offset))
	{
		*isNull = true;
		return (Datum) 0;
	}

	
	*isNull = false;
	retptr = array_seek(arraydataptr, 0, arraynullsptr, offset, elmlen, elmbyval, elmalign);
	return ArrayCast(retptr, elmbyval, elmlen);
}


static Datum array_get_element_expanded(Datum arraydatum, int nSubscripts, int *indx, int arraytyplen, int elmlen, bool elmbyval, char elmalign, bool *isNull)




{
	ExpandedArrayHeader *eah;
	int			i, ndim, *dim, *lb, offset;



	Datum	   *dvalues;
	bool	   *dnulls;

	eah = (ExpandedArrayHeader *) DatumGetEOHP(arraydatum);
	Assert(eah->ea_magic == EA_MAGIC);

	
	Assert(arraytyplen == -1);
	Assert(elmlen == eah->typlen);
	Assert(elmbyval == eah->typbyval);
	Assert(elmalign == eah->typalign);

	ndim = eah->ndims;
	dim = eah->dims;
	lb = eah->lbound;

	
	if (ndim != nSubscripts || ndim <= 0 || ndim > MAXDIM)
	{
		*isNull = true;
		return (Datum) 0;
	}
	for (i = 0; i < ndim; i++)
	{
		if (indx[i] < lb[i] || indx[i] >= (dim[i] + lb[i]))
		{
			*isNull = true;
			return (Datum) 0;
		}
	}

	
	offset = ArrayGetOffset(nSubscripts, dim, lb, indx);

	
	deconstruct_expanded_array(eah);

	dvalues = eah->dvalues;
	dnulls = eah->dnulls;

	
	if (dnulls && dnulls[offset])
	{
		*isNull = true;
		return (Datum) 0;
	}

	
	*isNull = false;
	return dvalues[offset];
}


Datum array_get_slice(Datum arraydatum, int nSubscripts, int *upperIndx, int *lowerIndx, bool *upperProvided, bool *lowerProvided, int arraytyplen, int elmlen, bool elmbyval, char elmalign)









{
	ArrayType  *array;
	ArrayType  *newarray;
	int			i, ndim, *dim, *lb, *newlb;



	int			fixedDim[1], fixedLb[1];
	Oid			elemtype;
	char	   *arraydataptr;
	bits8	   *arraynullsptr;
	int32		dataoffset;
	int			bytes, span[MAXDIM];

	if (arraytyplen > 0)
	{
		
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("slices of fixed-length arrays not implemented")));


		
		ndim = 1;
		fixedDim[0] = arraytyplen / elmlen;
		fixedLb[0] = 0;
		dim = fixedDim;
		lb = fixedLb;
		elemtype = InvalidOid;	
		arraydataptr = (char *) DatumGetPointer(arraydatum);
		arraynullsptr = NULL;
	}
	else {
		
		array = DatumGetArrayTypeP(arraydatum);

		ndim = ARR_NDIM(array);
		dim = ARR_DIMS(array);
		lb = ARR_LBOUND(array);
		elemtype = ARR_ELEMTYPE(array);
		arraydataptr = ARR_DATA_PTR(array);
		arraynullsptr = ARR_NULLBITMAP(array);
	}

	
	if (ndim < nSubscripts || ndim <= 0 || ndim > MAXDIM)
		return PointerGetDatum(construct_empty_array(elemtype));

	for (i = 0; i < nSubscripts; i++)
	{
		if (!lowerProvided[i] || lowerIndx[i] < lb[i])
			lowerIndx[i] = lb[i];
		if (!upperProvided[i] || upperIndx[i] >= (dim[i] + lb[i]))
			upperIndx[i] = dim[i] + lb[i] - 1;
		if (lowerIndx[i] > upperIndx[i])
			return PointerGetDatum(construct_empty_array(elemtype));
	}
	
	for (; i < ndim; i++)
	{
		lowerIndx[i] = lb[i];
		upperIndx[i] = dim[i] + lb[i] - 1;
		if (lowerIndx[i] > upperIndx[i])
			return PointerGetDatum(construct_empty_array(elemtype));
	}

	mda_get_range(ndim, span, lowerIndx, upperIndx);

	bytes = array_slice_size(arraydataptr, arraynullsptr, ndim, dim, lb, lowerIndx, upperIndx, elmlen, elmbyval, elmalign);



	
	if (arraynullsptr)
	{
		dataoffset = ARR_OVERHEAD_WITHNULLS(ndim, ArrayGetNItems(ndim, span));
		bytes += dataoffset;
	}
	else {
		dataoffset = 0;			
		bytes += ARR_OVERHEAD_NONULLS(ndim);
	}

	newarray = (ArrayType *) palloc0(bytes);
	SET_VARSIZE(newarray, bytes);
	newarray->ndim = ndim;
	newarray->dataoffset = dataoffset;
	newarray->elemtype = elemtype;
	memcpy(ARR_DIMS(newarray), span, ndim * sizeof(int));

	
	newlb = ARR_LBOUND(newarray);
	for (i = 0; i < ndim; i++)
		newlb[i] = 1;

	array_extract_slice(newarray, ndim, dim, lb, arraydataptr, arraynullsptr, lowerIndx, upperIndx, elmlen, elmbyval, elmalign);




	return PointerGetDatum(newarray);
}


Datum array_set_element(Datum arraydatum, int nSubscripts, int *indx, Datum dataValue, bool isNull, int arraytyplen, int elmlen, bool elmbyval, char elmalign)








{
	ArrayType  *array;
	ArrayType  *newarray;
	int			i, ndim, dim[MAXDIM], lb[MAXDIM], offset;



	char	   *elt_ptr;
	bool		newhasnulls;
	bits8	   *oldnullbitmap;
	int			oldnitems, newnitems, olddatasize, newsize, olditemlen, newitemlen, overheadlen, oldoverheadlen, addedbefore, addedafter, lenbefore, lenafter;











	if (arraytyplen > 0)
	{
		
		char	   *resultarray;

		if (nSubscripts != 1)
			ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("wrong number of array subscripts")));


		if (indx[0] < 0 || indx[0] * elmlen >= arraytyplen)
			ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("array subscript out of range")));


		if (isNull)
			ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("cannot assign null value to an element of a fixed-length array")));


		resultarray = (char *) palloc(arraytyplen);
		memcpy(resultarray, DatumGetPointer(arraydatum), arraytyplen);
		elt_ptr = (char *) resultarray + indx[0] * elmlen;
		ArrayCastAndSet(dataValue, elmlen, elmbyval, elmalign, elt_ptr);
		return PointerGetDatum(resultarray);
	}

	if (nSubscripts <= 0 || nSubscripts > MAXDIM)
		ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("wrong number of array subscripts")));


	
	if (elmlen == -1 && !isNull)
		dataValue = PointerGetDatum(PG_DETOAST_DATUM(dataValue));

	if (VARATT_IS_EXTERNAL_EXPANDED(DatumGetPointer(arraydatum)))
	{
		
		return array_set_element_expanded(arraydatum, nSubscripts, indx, dataValue, isNull, arraytyplen, elmlen, elmbyval, elmalign);







	}

	
	array = DatumGetArrayTypeP(arraydatum);

	ndim = ARR_NDIM(array);

	
	if (ndim == 0)
	{
		Oid			elmtype = ARR_ELEMTYPE(array);

		for (i = 0; i < nSubscripts; i++)
		{
			dim[i] = 1;
			lb[i] = indx[i];
		}

		return PointerGetDatum(construct_md_array(&dataValue, &isNull, nSubscripts, dim, lb, elmtype, elmlen, elmbyval, elmalign));


	}

	if (ndim != nSubscripts)
		ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("wrong number of array subscripts")));


	
	memcpy(dim, ARR_DIMS(array), ndim * sizeof(int));
	memcpy(lb, ARR_LBOUND(array), ndim * sizeof(int));

	newhasnulls = (ARR_HASNULL(array) || isNull);
	addedbefore = addedafter = 0;

	
	if (ndim == 1)
	{
		if (indx[0] < lb[0])
		{
			addedbefore = lb[0] - indx[0];
			dim[0] += addedbefore;
			lb[0] = indx[0];
			if (addedbefore > 1)
				newhasnulls = true; 
		}
		if (indx[0] >= (dim[0] + lb[0]))
		{
			addedafter = indx[0] - (dim[0] + lb[0]) + 1;
			dim[0] += addedafter;
			if (addedafter > 1)
				newhasnulls = true; 
		}
	}
	else {
		
		for (i = 0; i < ndim; i++)
		{
			if (indx[i] < lb[i] || indx[i] >= (dim[i] + lb[i]))
				ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("array subscript out of range")));

		}
	}

	
	newnitems = ArrayGetNItems(ndim, dim);
	if (newhasnulls)
		overheadlen = ARR_OVERHEAD_WITHNULLS(ndim, newnitems);
	else overheadlen = ARR_OVERHEAD_NONULLS(ndim);
	oldnitems = ArrayGetNItems(ndim, ARR_DIMS(array));
	oldnullbitmap = ARR_NULLBITMAP(array);
	oldoverheadlen = ARR_DATA_OFFSET(array);
	olddatasize = ARR_SIZE(array) - oldoverheadlen;
	if (addedbefore)
	{
		offset = 0;
		lenbefore = 0;
		olditemlen = 0;
		lenafter = olddatasize;
	}
	else if (addedafter)
	{
		offset = oldnitems;
		lenbefore = olddatasize;
		olditemlen = 0;
		lenafter = 0;
	}
	else {
		offset = ArrayGetOffset(nSubscripts, dim, lb, indx);
		elt_ptr = array_seek(ARR_DATA_PTR(array), 0, oldnullbitmap, offset, elmlen, elmbyval, elmalign);
		lenbefore = (int) (elt_ptr - ARR_DATA_PTR(array));
		if (array_get_isnull(oldnullbitmap, offset))
			olditemlen = 0;
		else {
			olditemlen = att_addlength_pointer(0, elmlen, elt_ptr);
			olditemlen = att_align_nominal(olditemlen, elmalign);
		}
		lenafter = (int) (olddatasize - lenbefore - olditemlen);
	}

	if (isNull)
		newitemlen = 0;
	else {
		newitemlen = att_addlength_datum(0, elmlen, dataValue);
		newitemlen = att_align_nominal(newitemlen, elmalign);
	}

	newsize = overheadlen + lenbefore + newitemlen + lenafter;

	
	newarray = (ArrayType *) palloc0(newsize);
	SET_VARSIZE(newarray, newsize);
	newarray->ndim = ndim;
	newarray->dataoffset = newhasnulls ? overheadlen : 0;
	newarray->elemtype = ARR_ELEMTYPE(array);
	memcpy(ARR_DIMS(newarray), dim, ndim * sizeof(int));
	memcpy(ARR_LBOUND(newarray), lb, ndim * sizeof(int));

	
	memcpy((char *) newarray + overheadlen, (char *) array + oldoverheadlen, lenbefore);

	if (!isNull)
		ArrayCastAndSet(dataValue, elmlen, elmbyval, elmalign, (char *) newarray + overheadlen + lenbefore);
	memcpy((char *) newarray + overheadlen + lenbefore + newitemlen, (char *) array + oldoverheadlen + lenbefore + olditemlen, lenafter);


	
	if (newhasnulls)
	{
		bits8	   *newnullbitmap = ARR_NULLBITMAP(newarray);

		
		MemSet(newnullbitmap, 0, (newnitems + 7) / 8);
		
		if (addedafter)
			array_set_isnull(newnullbitmap, newnitems - 1, isNull);
		else array_set_isnull(newnullbitmap, offset, isNull);
		
		if (addedbefore)
			array_bitmap_copy(newnullbitmap, addedbefore, oldnullbitmap, 0, oldnitems);

		else {
			array_bitmap_copy(newnullbitmap, 0, oldnullbitmap, 0, offset);

			if (addedafter == 0)
				array_bitmap_copy(newnullbitmap, offset + 1, oldnullbitmap, offset + 1, oldnitems - offset - 1);

		}
	}

	return PointerGetDatum(newarray);
}


static Datum array_set_element_expanded(Datum arraydatum, int nSubscripts, int *indx, Datum dataValue, bool isNull, int arraytyplen, int elmlen, bool elmbyval, char elmalign)




{
	ExpandedArrayHeader *eah;
	Datum	   *dvalues;
	bool	   *dnulls;
	int			i, ndim, dim[MAXDIM], lb[MAXDIM], offset;



	bool		dimschanged, newhasnulls;
	int			addedbefore, addedafter;
	char	   *oldValue;

	
	eah = DatumGetExpandedArray(arraydatum);

	
	Assert(arraytyplen == -1);
	Assert(elmlen == eah->typlen);
	Assert(elmbyval == eah->typbyval);
	Assert(elmalign == eah->typalign);

	
	ndim = eah->ndims;
	Assert(ndim >= 0 && ndim <= MAXDIM);
	memcpy(dim, eah->dims, ndim * sizeof(int));
	memcpy(lb, eah->lbound, ndim * sizeof(int));
	dimschanged = false;

	
	if (ndim == 0)
	{
		
		Assert(nSubscripts > 0 && nSubscripts <= MAXDIM);
		eah->dims = (int *) MemoryContextAllocZero(eah->hdr.eoh_context, nSubscripts * sizeof(int));
		eah->lbound = (int *) MemoryContextAllocZero(eah->hdr.eoh_context, nSubscripts * sizeof(int));

		
		ndim = nSubscripts;
		for (i = 0; i < nSubscripts; i++)
		{
			dim[i] = 0;
			lb[i] = indx[i];
		}
		dimschanged = true;
	}
	else if (ndim != nSubscripts)
		ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("wrong number of array subscripts")));


	
	deconstruct_expanded_array(eah);

	
	if (!eah->typbyval && !isNull)
	{
		MemoryContext oldcxt = MemoryContextSwitchTo(eah->hdr.eoh_context);

		dataValue = datumCopy(dataValue, false, eah->typlen);
		MemoryContextSwitchTo(oldcxt);
	}

	dvalues = eah->dvalues;
	dnulls = eah->dnulls;

	newhasnulls = ((dnulls != NULL) || isNull);
	addedbefore = addedafter = 0;

	
	if (ndim == 1)
	{
		if (indx[0] < lb[0])
		{
			addedbefore = lb[0] - indx[0];
			dim[0] += addedbefore;
			lb[0] = indx[0];
			dimschanged = true;
			if (addedbefore > 1)
				newhasnulls = true; 
		}
		if (indx[0] >= (dim[0] + lb[0]))
		{
			addedafter = indx[0] - (dim[0] + lb[0]) + 1;
			dim[0] += addedafter;
			dimschanged = true;
			if (addedafter > 1)
				newhasnulls = true; 
		}
	}
	else {
		
		for (i = 0; i < ndim; i++)
		{
			if (indx[i] < lb[i] || indx[i] >= (dim[i] + lb[i]))
				ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("array subscript out of range")));

		}
	}

	
	offset = ArrayGetOffset(nSubscripts, dim, lb, indx);

	
	if (dim[0] > eah->dvalueslen)
	{
		
		int			newlen = dim[0] + dim[0] / 8;

		newlen = Max(newlen, dim[0]);	
		eah->dvalues = dvalues = (Datum *)
			repalloc(dvalues, newlen * sizeof(Datum));
		if (dnulls)
			eah->dnulls = dnulls = (bool *)
				repalloc(dnulls, newlen * sizeof(bool));
		eah->dvalueslen = newlen;
	}

	
	if (newhasnulls && dnulls == NULL)
		eah->dnulls = dnulls = (bool *)
			MemoryContextAllocZero(eah->hdr.eoh_context, eah->dvalueslen * sizeof(bool));

	

	
	eah->fvalue = NULL;
	
	eah->flat_size = 0;

	
	if (dimschanged)
	{
		eah->ndims = ndim;
		memcpy(eah->dims, dim, ndim * sizeof(int));
		memcpy(eah->lbound, lb, ndim * sizeof(int));
	}

	
	if (addedbefore > 0)
	{
		memmove(dvalues + addedbefore, dvalues, eah->nelems * sizeof(Datum));
		for (i = 0; i < addedbefore; i++)
			dvalues[i] = (Datum) 0;
		if (dnulls)
		{
			memmove(dnulls + addedbefore, dnulls, eah->nelems * sizeof(bool));
			for (i = 0; i < addedbefore; i++)
				dnulls[i] = true;
		}
		eah->nelems += addedbefore;
	}

	
	if (addedafter > 0)
	{
		for (i = 0; i < addedafter; i++)
			dvalues[eah->nelems + i] = (Datum) 0;
		if (dnulls)
		{
			for (i = 0; i < addedafter; i++)
				dnulls[eah->nelems + i] = true;
		}
		eah->nelems += addedafter;
	}

	
	if (!eah->typbyval && (dnulls == NULL || !dnulls[offset]))
		oldValue = (char *) DatumGetPointer(dvalues[offset]);
	else oldValue = NULL;

	
	dvalues[offset] = dataValue;
	if (dnulls)
		dnulls[offset] = isNull;

	
	if (oldValue)
	{
		
		if (oldValue < eah->fstartptr || oldValue >= eah->fendptr)
			pfree(oldValue);
	}

	
	return EOHPGetRWDatum(&eah->hdr);
}


Datum array_set_slice(Datum arraydatum, int nSubscripts, int *upperIndx, int *lowerIndx, bool *upperProvided, bool *lowerProvided, Datum srcArrayDatum, bool isNull, int arraytyplen, int elmlen, bool elmbyval, char elmalign)











{
	ArrayType  *array;
	ArrayType  *srcArray;
	ArrayType  *newarray;
	int			i, ndim, dim[MAXDIM], lb[MAXDIM], span[MAXDIM];



	bool		newhasnulls;
	int			nitems, nsrcitems, olddatasize, newsize, olditemsize, newitemsize, overheadlen, oldoverheadlen, addedbefore, addedafter, lenbefore, lenafter, itemsbefore, itemsafter, nolditems;














	
	if (isNull)
		return arraydatum;

	if (arraytyplen > 0)
	{
		
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("updates on slices of fixed-length arrays not implemented")));

	}

	
	array = DatumGetArrayTypeP(arraydatum);
	srcArray = DatumGetArrayTypeP(srcArrayDatum);

	

	ndim = ARR_NDIM(array);

	
	if (ndim == 0)
	{
		Datum	   *dvalues;
		bool	   *dnulls;
		int			nelems;
		Oid			elmtype = ARR_ELEMTYPE(array);

		deconstruct_array(srcArray, elmtype, elmlen, elmbyval, elmalign, &dvalues, &dnulls, &nelems);

		for (i = 0; i < nSubscripts; i++)
		{
			if (!upperProvided[i] || !lowerProvided[i])
				ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("array slice subscript must provide both boundaries"), errdetail("When assigning to a slice of an empty array value," " slice boundaries must be fully specified.")));




			dim[i] = 1 + upperIndx[i] - lowerIndx[i];
			lb[i] = lowerIndx[i];
		}

		
		if (nelems < ArrayGetNItems(nSubscripts, dim))
			ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("source array too small")));


		return PointerGetDatum(construct_md_array(dvalues, dnulls, nSubscripts, dim, lb, elmtype, elmlen, elmbyval, elmalign));

	}

	if (ndim < nSubscripts || ndim <= 0 || ndim > MAXDIM)
		ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("wrong number of array subscripts")));


	
	memcpy(dim, ARR_DIMS(array), ndim * sizeof(int));
	memcpy(lb, ARR_LBOUND(array), ndim * sizeof(int));

	newhasnulls = (ARR_HASNULL(array) || ARR_HASNULL(srcArray));
	addedbefore = addedafter = 0;

	
	if (ndim == 1)
	{
		Assert(nSubscripts == 1);
		if (!lowerProvided[0])
			lowerIndx[0] = lb[0];
		if (!upperProvided[0])
			upperIndx[0] = dim[0] + lb[0] - 1;
		if (lowerIndx[0] > upperIndx[0])
			ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("upper bound cannot be less than lower bound")));

		if (lowerIndx[0] < lb[0])
		{
			if (upperIndx[0] < lb[0] - 1)
				newhasnulls = true; 
			addedbefore = lb[0] - lowerIndx[0];
			dim[0] += addedbefore;
			lb[0] = lowerIndx[0];
		}
		if (upperIndx[0] >= (dim[0] + lb[0]))
		{
			if (lowerIndx[0] > (dim[0] + lb[0]))
				newhasnulls = true; 
			addedafter = upperIndx[0] - (dim[0] + lb[0]) + 1;
			dim[0] += addedafter;
		}
	}
	else {
		
		for (i = 0; i < nSubscripts; i++)
		{
			if (!lowerProvided[i])
				lowerIndx[i] = lb[i];
			if (!upperProvided[i])
				upperIndx[i] = dim[i] + lb[i] - 1;
			if (lowerIndx[i] > upperIndx[i])
				ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("upper bound cannot be less than lower bound")));

			if (lowerIndx[i] < lb[i] || upperIndx[i] >= (dim[i] + lb[i]))
				ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("array subscript out of range")));

		}
		
		for (; i < ndim; i++)
		{
			lowerIndx[i] = lb[i];
			upperIndx[i] = dim[i] + lb[i] - 1;
			if (lowerIndx[i] > upperIndx[i])
				ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("upper bound cannot be less than lower bound")));

		}
	}

	
	nitems = ArrayGetNItems(ndim, dim);

	
	mda_get_range(ndim, span, lowerIndx, upperIndx);
	nsrcitems = ArrayGetNItems(ndim, span);
	if (nsrcitems > ArrayGetNItems(ARR_NDIM(srcArray), ARR_DIMS(srcArray)))
		ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("source array too small")));


	
	if (newhasnulls)
		overheadlen = ARR_OVERHEAD_WITHNULLS(ndim, nitems);
	else overheadlen = ARR_OVERHEAD_NONULLS(ndim);
	newitemsize = array_nelems_size(ARR_DATA_PTR(srcArray), 0, ARR_NULLBITMAP(srcArray), nsrcitems, elmlen, elmbyval, elmalign);

	oldoverheadlen = ARR_DATA_OFFSET(array);
	olddatasize = ARR_SIZE(array) - oldoverheadlen;
	if (ndim > 1)
	{
		
		olditemsize = array_slice_size(ARR_DATA_PTR(array), ARR_NULLBITMAP(array), ndim, dim, lb, lowerIndx, upperIndx, elmlen, elmbyval, elmalign);



		lenbefore = lenafter = 0;	
		itemsbefore = itemsafter = nolditems = 0;
	}
	else {
		
		int			oldlb = ARR_LBOUND(array)[0];
		int			oldub = oldlb + ARR_DIMS(array)[0] - 1;
		int			slicelb = Max(oldlb, lowerIndx[0]);
		int			sliceub = Min(oldub, upperIndx[0]);
		char	   *oldarraydata = ARR_DATA_PTR(array);
		bits8	   *oldarraybitmap = ARR_NULLBITMAP(array);

		
		itemsbefore = Min(slicelb, oldub + 1) - oldlb;
		lenbefore = array_nelems_size(oldarraydata, 0, oldarraybitmap, itemsbefore, elmlen, elmbyval, elmalign);

		
		if (slicelb > sliceub)
		{
			nolditems = 0;
			olditemsize = 0;
		}
		else {
			nolditems = sliceub - slicelb + 1;
			olditemsize = array_nelems_size(oldarraydata + lenbefore, itemsbefore, oldarraybitmap, nolditems, elmlen, elmbyval, elmalign);


		}
		
		itemsafter = oldub + 1 - Max(sliceub + 1, oldlb);
		lenafter = olddatasize - lenbefore - olditemsize;
	}

	newsize = overheadlen + olddatasize - olditemsize + newitemsize;

	newarray = (ArrayType *) palloc0(newsize);
	SET_VARSIZE(newarray, newsize);
	newarray->ndim = ndim;
	newarray->dataoffset = newhasnulls ? overheadlen : 0;
	newarray->elemtype = ARR_ELEMTYPE(array);
	memcpy(ARR_DIMS(newarray), dim, ndim * sizeof(int));
	memcpy(ARR_LBOUND(newarray), lb, ndim * sizeof(int));

	if (ndim > 1)
	{
		
		array_insert_slice(newarray, array, srcArray, ndim, dim, lb, lowerIndx, upperIndx, elmlen, elmbyval, elmalign);


	}
	else {
		
		memcpy((char *) newarray + overheadlen, (char *) array + oldoverheadlen, lenbefore);

		memcpy((char *) newarray + overheadlen + lenbefore, ARR_DATA_PTR(srcArray), newitemsize);

		memcpy((char *) newarray + overheadlen + lenbefore + newitemsize, (char *) array + oldoverheadlen + lenbefore + olditemsize, lenafter);

		
		if (newhasnulls)
		{
			bits8	   *newnullbitmap = ARR_NULLBITMAP(newarray);
			bits8	   *oldnullbitmap = ARR_NULLBITMAP(array);

			
			MemSet(newnullbitmap, 0, (nitems + 7) / 8);
			array_bitmap_copy(newnullbitmap, addedbefore, oldnullbitmap, 0, itemsbefore);

			array_bitmap_copy(newnullbitmap, lowerIndx[0] - lb[0], ARR_NULLBITMAP(srcArray), 0, nsrcitems);

			array_bitmap_copy(newnullbitmap, addedbefore + itemsbefore + nolditems, oldnullbitmap, itemsbefore + nolditems, itemsafter);

		}
	}

	return PointerGetDatum(newarray);
}


Datum array_ref(ArrayType *array, int nSubscripts, int *indx, int arraytyplen, int elmlen, bool elmbyval, char elmalign, bool *isNull)


{
	return array_get_element(PointerGetDatum(array), nSubscripts, indx, arraytyplen, elmlen, elmbyval, elmalign, isNull);

}


ArrayType * array_set(ArrayType *array, int nSubscripts, int *indx, Datum dataValue, bool isNull, int arraytyplen, int elmlen, bool elmbyval, char elmalign)


{
	return DatumGetArrayTypeP(array_set_element(PointerGetDatum(array), nSubscripts, indx, dataValue, isNull, arraytyplen, elmlen, elmbyval, elmalign));



}


Datum array_map(Datum arrayd, ExprState *exprstate, ExprContext *econtext, Oid retType, ArrayMapState *amstate)


{
	AnyArrayType *v = DatumGetAnyArrayP(arrayd);
	ArrayType  *result;
	Datum	   *values;
	bool	   *nulls;
	int		   *dim;
	int			ndim;
	int			nitems;
	int			i;
	int32		nbytes = 0;
	int32		dataoffset;
	bool		hasnulls;
	Oid			inpType;
	int			inp_typlen;
	bool		inp_typbyval;
	char		inp_typalign;
	int			typlen;
	bool		typbyval;
	char		typalign;
	array_iter	iter;
	ArrayMetaState *inp_extra;
	ArrayMetaState *ret_extra;
	Datum	   *transform_source = exprstate->innermost_caseval;
	bool	   *transform_source_isnull = exprstate->innermost_casenull;

	inpType = AARR_ELEMTYPE(v);
	ndim = AARR_NDIM(v);
	dim = AARR_DIMS(v);
	nitems = ArrayGetNItems(ndim, dim);

	
	if (nitems <= 0)
	{
		
		return PointerGetDatum(construct_empty_array(retType));
	}

	
	inp_extra = &amstate->inp_extra;
	ret_extra = &amstate->ret_extra;

	if (inp_extra->element_type != inpType)
	{
		get_typlenbyvalalign(inpType, &inp_extra->typlen, &inp_extra->typbyval, &inp_extra->typalign);


		inp_extra->element_type = inpType;
	}
	inp_typlen = inp_extra->typlen;
	inp_typbyval = inp_extra->typbyval;
	inp_typalign = inp_extra->typalign;

	if (ret_extra->element_type != retType)
	{
		get_typlenbyvalalign(retType, &ret_extra->typlen, &ret_extra->typbyval, &ret_extra->typalign);


		ret_extra->element_type = retType;
	}
	typlen = ret_extra->typlen;
	typbyval = ret_extra->typbyval;
	typalign = ret_extra->typalign;

	
	values = (Datum *) palloc(nitems * sizeof(Datum));
	nulls = (bool *) palloc(nitems * sizeof(bool));

	
	array_iter_setup(&iter, v);
	hasnulls = false;

	for (i = 0; i < nitems; i++)
	{
		
		*transform_source = array_iter_next(&iter, transform_source_isnull, i, inp_typlen, inp_typbyval, inp_typalign);


		
		values[i] = ExecEvalExpr(exprstate, econtext, &nulls[i]);

		if (nulls[i])
			hasnulls = true;
		else {
			
			if (typlen == -1)
				values[i] = PointerGetDatum(PG_DETOAST_DATUM(values[i]));
			
			nbytes = att_addlength_datum(nbytes, typlen, values[i]);
			nbytes = att_align_nominal(nbytes, typalign);
			
			if (!AllocSizeIsValid(nbytes))
				ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("array size exceeds the maximum allowed (%d)", (int) MaxAllocSize)));


		}
	}

	
	if (hasnulls)
	{
		dataoffset = ARR_OVERHEAD_WITHNULLS(ndim, nitems);
		nbytes += dataoffset;
	}
	else {
		dataoffset = 0;			
		nbytes += ARR_OVERHEAD_NONULLS(ndim);
	}
	result = (ArrayType *) palloc0(nbytes);
	SET_VARSIZE(result, nbytes);
	result->ndim = ndim;
	result->dataoffset = dataoffset;
	result->elemtype = retType;
	memcpy(ARR_DIMS(result), AARR_DIMS(v), ndim * sizeof(int));
	memcpy(ARR_LBOUND(result), AARR_LBOUND(v), ndim * sizeof(int));

	CopyArrayEls(result, values, nulls, nitems, typlen, typbyval, typalign, false);



	
	pfree(values);
	pfree(nulls);

	return PointerGetDatum(result);
}


ArrayType * construct_array(Datum *elems, int nelems, Oid elmtype, int elmlen, bool elmbyval, char elmalign)


{
	int			dims[1];
	int			lbs[1];

	dims[0] = nelems;
	lbs[0] = 1;

	return construct_md_array(elems, NULL, 1, dims, lbs, elmtype, elmlen, elmbyval, elmalign);
}


ArrayType * construct_md_array(Datum *elems, bool *nulls, int ndims, int *dims, int *lbs, Oid elmtype, int elmlen, bool elmbyval, char elmalign)





{
	ArrayType  *result;
	bool		hasnulls;
	int32		nbytes;
	int32		dataoffset;
	int			i;
	int			nelems;

	if (ndims < 0)				
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid number of dimensions: %d", ndims)));

	if (ndims > MAXDIM)
		ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("number of array dimensions (%d) exceeds the maximum allowed (%d)", ndims, MAXDIM)));



	nelems = ArrayGetNItems(ndims, dims);

	
	if (nelems <= 0)
		return construct_empty_array(elmtype);

	
	nbytes = 0;
	hasnulls = false;
	for (i = 0; i < nelems; i++)
	{
		if (nulls && nulls[i])
		{
			hasnulls = true;
			continue;
		}
		
		if (elmlen == -1)
			elems[i] = PointerGetDatum(PG_DETOAST_DATUM(elems[i]));
		nbytes = att_addlength_datum(nbytes, elmlen, elems[i]);
		nbytes = att_align_nominal(nbytes, elmalign);
		
		if (!AllocSizeIsValid(nbytes))
			ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("array size exceeds the maximum allowed (%d)", (int) MaxAllocSize)));


	}

	
	if (hasnulls)
	{
		dataoffset = ARR_OVERHEAD_WITHNULLS(ndims, nelems);
		nbytes += dataoffset;
	}
	else {
		dataoffset = 0;			
		nbytes += ARR_OVERHEAD_NONULLS(ndims);
	}
	result = (ArrayType *) palloc0(nbytes);
	SET_VARSIZE(result, nbytes);
	result->ndim = ndims;
	result->dataoffset = dataoffset;
	result->elemtype = elmtype;
	memcpy(ARR_DIMS(result), dims, ndims * sizeof(int));
	memcpy(ARR_LBOUND(result), lbs, ndims * sizeof(int));

	CopyArrayEls(result, elems, nulls, nelems, elmlen, elmbyval, elmalign, false);



	return result;
}


ArrayType * construct_empty_array(Oid elmtype)
{
	ArrayType  *result;

	result = (ArrayType *) palloc0(sizeof(ArrayType));
	SET_VARSIZE(result, sizeof(ArrayType));
	result->ndim = 0;
	result->dataoffset = 0;
	result->elemtype = elmtype;
	return result;
}


ExpandedArrayHeader * construct_empty_expanded_array(Oid element_type, MemoryContext parentcontext, ArrayMetaState *metacache)


{
	ArrayType  *array = construct_empty_array(element_type);
	Datum		d;

	d = expand_array(PointerGetDatum(array), parentcontext, metacache);
	pfree(array);
	return (ExpandedArrayHeader *) DatumGetEOHP(d);
}


void deconstruct_array(ArrayType *array, Oid elmtype, int elmlen, bool elmbyval, char elmalign, Datum **elemsp, bool **nullsp, int *nelemsp)



{
	Datum	   *elems;
	bool	   *nulls;
	int			nelems;
	char	   *p;
	bits8	   *bitmap;
	int			bitmask;
	int			i;

	Assert(ARR_ELEMTYPE(array) == elmtype);

	nelems = ArrayGetNItems(ARR_NDIM(array), ARR_DIMS(array));
	*elemsp = elems = (Datum *) palloc(nelems * sizeof(Datum));
	if (nullsp)
		*nullsp = nulls = (bool *) palloc0(nelems * sizeof(bool));
	else nulls = NULL;
	*nelemsp = nelems;

	p = ARR_DATA_PTR(array);
	bitmap = ARR_NULLBITMAP(array);
	bitmask = 1;

	for (i = 0; i < nelems; i++)
	{
		
		if (bitmap && (*bitmap & bitmask) == 0)
		{
			elems[i] = (Datum) 0;
			if (nulls)
				nulls[i] = true;
			else ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("null array element not allowed in this context")));


		}
		else {
			elems[i] = fetch_att(p, elmbyval, elmlen);
			p = att_addlength_pointer(p, elmlen, p);
			p = (char *) att_align_nominal(p, elmalign);
		}

		
		if (bitmap)
		{
			bitmask <<= 1;
			if (bitmask == 0x100)
			{
				bitmap++;
				bitmask = 1;
			}
		}
	}
}


bool array_contains_nulls(ArrayType *array)
{
	int			nelems;
	bits8	   *bitmap;
	int			bitmask;

	
	if (!ARR_HASNULL(array))
		return false;

	nelems = ArrayGetNItems(ARR_NDIM(array), ARR_DIMS(array));

	bitmap = ARR_NULLBITMAP(array);

	
	while (nelems >= 8)
	{
		if (*bitmap != 0xFF)
			return true;
		bitmap++;
		nelems -= 8;
	}

	
	bitmask = 1;
	while (nelems > 0)
	{
		if ((*bitmap & bitmask) == 0)
			return true;
		bitmask <<= 1;
		nelems--;
	}

	return false;
}



Datum array_eq(PG_FUNCTION_ARGS)
{
	LOCAL_FCINFO(locfcinfo, 2);
	AnyArrayType *array1 = PG_GETARG_ANY_ARRAY_P(0);
	AnyArrayType *array2 = PG_GETARG_ANY_ARRAY_P(1);
	Oid			collation = PG_GET_COLLATION();
	int			ndims1 = AARR_NDIM(array1);
	int			ndims2 = AARR_NDIM(array2);
	int		   *dims1 = AARR_DIMS(array1);
	int		   *dims2 = AARR_DIMS(array2);
	int		   *lbs1 = AARR_LBOUND(array1);
	int		   *lbs2 = AARR_LBOUND(array2);
	Oid			element_type = AARR_ELEMTYPE(array1);
	bool		result = true;
	int			nitems;
	TypeCacheEntry *typentry;
	int			typlen;
	bool		typbyval;
	char		typalign;
	array_iter	it1;
	array_iter	it2;
	int			i;

	if (element_type != AARR_ELEMTYPE(array2))
		ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("cannot compare arrays of different element types")));


	
	if (ndims1 != ndims2 || memcmp(dims1, dims2, ndims1 * sizeof(int)) != 0 || memcmp(lbs1, lbs2, ndims1 * sizeof(int)) != 0)

		result = false;
	else {
		
		typentry = (TypeCacheEntry *) fcinfo->flinfo->fn_extra;
		if (typentry == NULL || typentry->type_id != element_type)
		{
			typentry = lookup_type_cache(element_type, TYPECACHE_EQ_OPR_FINFO);
			if (!OidIsValid(typentry->eq_opr_finfo.fn_oid))
				ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("could not identify an equality operator for type %s", format_type_be(element_type))));


			fcinfo->flinfo->fn_extra = (void *) typentry;
		}
		typlen = typentry->typlen;
		typbyval = typentry->typbyval;
		typalign = typentry->typalign;

		
		InitFunctionCallInfoData(*locfcinfo, &typentry->eq_opr_finfo, 2, collation, NULL, NULL);

		
		nitems = ArrayGetNItems(ndims1, dims1);
		array_iter_setup(&it1, array1);
		array_iter_setup(&it2, array2);

		for (i = 0; i < nitems; i++)
		{
			Datum		elt1;
			Datum		elt2;
			bool		isnull1;
			bool		isnull2;
			bool		oprresult;

			
			elt1 = array_iter_next(&it1, &isnull1, i, typlen, typbyval, typalign);
			elt2 = array_iter_next(&it2, &isnull2, i, typlen, typbyval, typalign);

			
			if (isnull1 && isnull2)
				continue;
			if (isnull1 || isnull2)
			{
				result = false;
				break;
			}

			
			locfcinfo->args[0].value = elt1;
			locfcinfo->args[0].isnull = false;
			locfcinfo->args[1].value = elt2;
			locfcinfo->args[1].isnull = false;
			locfcinfo->isnull = false;
			oprresult = DatumGetBool(FunctionCallInvoke(locfcinfo));
			if (!oprresult)
			{
				result = false;
				break;
			}
		}
	}

	
	AARR_FREE_IF_COPY(array1, 0);
	AARR_FREE_IF_COPY(array2, 1);

	PG_RETURN_BOOL(result);
}




Datum array_ne(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(!DatumGetBool(array_eq(fcinfo)));
}

Datum array_lt(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(array_cmp(fcinfo) < 0);
}

Datum array_gt(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(array_cmp(fcinfo) > 0);
}

Datum array_le(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(array_cmp(fcinfo) <= 0);
}

Datum array_ge(PG_FUNCTION_ARGS)
{
	PG_RETURN_BOOL(array_cmp(fcinfo) >= 0);
}

Datum btarraycmp(PG_FUNCTION_ARGS)
{
	PG_RETURN_INT32(array_cmp(fcinfo));
}


static int array_cmp(FunctionCallInfo fcinfo)
{
	LOCAL_FCINFO(locfcinfo, 2);
	AnyArrayType *array1 = PG_GETARG_ANY_ARRAY_P(0);
	AnyArrayType *array2 = PG_GETARG_ANY_ARRAY_P(1);
	Oid			collation = PG_GET_COLLATION();
	int			ndims1 = AARR_NDIM(array1);
	int			ndims2 = AARR_NDIM(array2);
	int		   *dims1 = AARR_DIMS(array1);
	int		   *dims2 = AARR_DIMS(array2);
	int			nitems1 = ArrayGetNItems(ndims1, dims1);
	int			nitems2 = ArrayGetNItems(ndims2, dims2);
	Oid			element_type = AARR_ELEMTYPE(array1);
	int			result = 0;
	TypeCacheEntry *typentry;
	int			typlen;
	bool		typbyval;
	char		typalign;
	int			min_nitems;
	array_iter	it1;
	array_iter	it2;
	int			i;

	if (element_type != AARR_ELEMTYPE(array2))
		ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("cannot compare arrays of different element types")));


	
	typentry = (TypeCacheEntry *) fcinfo->flinfo->fn_extra;
	if (typentry == NULL || typentry->type_id != element_type)
	{
		typentry = lookup_type_cache(element_type, TYPECACHE_CMP_PROC_FINFO);
		if (!OidIsValid(typentry->cmp_proc_finfo.fn_oid))
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("could not identify a comparison function for type %s", format_type_be(element_type))));


		fcinfo->flinfo->fn_extra = (void *) typentry;
	}
	typlen = typentry->typlen;
	typbyval = typentry->typbyval;
	typalign = typentry->typalign;

	
	InitFunctionCallInfoData(*locfcinfo, &typentry->cmp_proc_finfo, 2, collation, NULL, NULL);

	
	min_nitems = Min(nitems1, nitems2);
	array_iter_setup(&it1, array1);
	array_iter_setup(&it2, array2);

	for (i = 0; i < min_nitems; i++)
	{
		Datum		elt1;
		Datum		elt2;
		bool		isnull1;
		bool		isnull2;
		int32		cmpresult;

		
		elt1 = array_iter_next(&it1, &isnull1, i, typlen, typbyval, typalign);
		elt2 = array_iter_next(&it2, &isnull2, i, typlen, typbyval, typalign);

		
		if (isnull1 && isnull2)
			continue;
		if (isnull1)
		{
			
			result = 1;
			break;
		}
		if (isnull2)
		{
			
			result = -1;
			break;
		}

		
		locfcinfo->args[0].value = elt1;
		locfcinfo->args[0].isnull = false;
		locfcinfo->args[1].value = elt2;
		locfcinfo->args[1].isnull = false;
		locfcinfo->isnull = false;
		cmpresult = DatumGetInt32(FunctionCallInvoke(locfcinfo));

		if (cmpresult == 0)
			continue;			

		if (cmpresult < 0)
		{
			
			result = -1;
			break;
		}
		else {
			
			result = 1;
			break;
		}
	}

	
	if (result == 0)
	{
		if (nitems1 != nitems2)
			result = (nitems1 < nitems2) ? -1 : 1;
		else if (ndims1 != ndims2)
			result = (ndims1 < ndims2) ? -1 : 1;
		else {
			for (i = 0; i < ndims1; i++)
			{
				if (dims1[i] != dims2[i])
				{
					result = (dims1[i] < dims2[i]) ? -1 : 1;
					break;
				}
			}
			if (result == 0)
			{
				int		   *lbound1 = AARR_LBOUND(array1);
				int		   *lbound2 = AARR_LBOUND(array2);

				for (i = 0; i < ndims1; i++)
				{
					if (lbound1[i] != lbound2[i])
					{
						result = (lbound1[i] < lbound2[i]) ? -1 : 1;
						break;
					}
				}
			}
		}
	}

	
	AARR_FREE_IF_COPY(array1, 0);
	AARR_FREE_IF_COPY(array2, 1);

	return result;
}




Datum hash_array(PG_FUNCTION_ARGS)
{
	LOCAL_FCINFO(locfcinfo, 1);
	AnyArrayType *array = PG_GETARG_ANY_ARRAY_P(0);
	int			ndims = AARR_NDIM(array);
	int		   *dims = AARR_DIMS(array);
	Oid			element_type = AARR_ELEMTYPE(array);
	uint32		result = 1;
	int			nitems;
	TypeCacheEntry *typentry;
	int			typlen;
	bool		typbyval;
	char		typalign;
	int			i;
	array_iter	iter;

	
	typentry = (TypeCacheEntry *) fcinfo->flinfo->fn_extra;
	if (typentry == NULL || typentry->type_id != element_type)
	{
		typentry = lookup_type_cache(element_type, TYPECACHE_HASH_PROC_FINFO);
		if (!OidIsValid(typentry->hash_proc_finfo.fn_oid))
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("could not identify a hash function for type %s", format_type_be(element_type))));


		fcinfo->flinfo->fn_extra = (void *) typentry;
	}
	typlen = typentry->typlen;
	typbyval = typentry->typbyval;
	typalign = typentry->typalign;

	
	InitFunctionCallInfoData(*locfcinfo, &typentry->hash_proc_finfo, 1, InvalidOid, NULL, NULL);

	
	nitems = ArrayGetNItems(ndims, dims);
	array_iter_setup(&iter, array);

	for (i = 0; i < nitems; i++)
	{
		Datum		elt;
		bool		isnull;
		uint32		elthash;

		
		elt = array_iter_next(&iter, &isnull, i, typlen, typbyval, typalign);

		if (isnull)
		{
			
			elthash = 0;
		}
		else {
			
			locfcinfo->args[0].value = elt;
			locfcinfo->args[0].isnull = false;
			locfcinfo->isnull = false;
			elthash = DatumGetUInt32(FunctionCallInvoke(locfcinfo));
		}

		
		result = (result << 5) - result + elthash;
	}

	
	AARR_FREE_IF_COPY(array, 0);

	PG_RETURN_UINT32(result);
}


Datum hash_array_extended(PG_FUNCTION_ARGS)
{
	LOCAL_FCINFO(locfcinfo, 2);
	AnyArrayType *array = PG_GETARG_ANY_ARRAY_P(0);
	uint64		seed = PG_GETARG_INT64(1);
	int			ndims = AARR_NDIM(array);
	int		   *dims = AARR_DIMS(array);
	Oid			element_type = AARR_ELEMTYPE(array);
	uint64		result = 1;
	int			nitems;
	TypeCacheEntry *typentry;
	int			typlen;
	bool		typbyval;
	char		typalign;
	int			i;
	array_iter	iter;

	typentry = (TypeCacheEntry *) fcinfo->flinfo->fn_extra;
	if (typentry == NULL || typentry->type_id != element_type)
	{
		typentry = lookup_type_cache(element_type, TYPECACHE_HASH_EXTENDED_PROC_FINFO);
		if (!OidIsValid(typentry->hash_extended_proc_finfo.fn_oid))
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("could not identify an extended hash function for type %s", format_type_be(element_type))));


		fcinfo->flinfo->fn_extra = (void *) typentry;
	}
	typlen = typentry->typlen;
	typbyval = typentry->typbyval;
	typalign = typentry->typalign;

	InitFunctionCallInfoData(*locfcinfo, &typentry->hash_extended_proc_finfo, 2, InvalidOid, NULL, NULL);

	
	nitems = ArrayGetNItems(ndims, dims);
	array_iter_setup(&iter, array);

	for (i = 0; i < nitems; i++)
	{
		Datum		elt;
		bool		isnull;
		uint64		elthash;

		
		elt = array_iter_next(&iter, &isnull, i, typlen, typbyval, typalign);

		if (isnull)
		{
			elthash = 0;
		}
		else {
			
			locfcinfo->args[0].value = elt;
			locfcinfo->args[0].isnull = false;
			locfcinfo->args[1].value = Int64GetDatum(seed);
			locfcinfo->args[1].isnull = false;
			elthash = DatumGetUInt64(FunctionCallInvoke(locfcinfo));
		}

		result = (result << 5) - result + elthash;
	}

	AARR_FREE_IF_COPY(array, 0);

	PG_RETURN_UINT64(result);
}





static bool array_contain_compare(AnyArrayType *array1, AnyArrayType *array2, Oid collation, bool matchall, void **fn_extra)

{
	LOCAL_FCINFO(locfcinfo, 2);
	bool		result = matchall;
	Oid			element_type = AARR_ELEMTYPE(array1);
	TypeCacheEntry *typentry;
	int			nelems1;
	Datum	   *values2;
	bool	   *nulls2;
	int			nelems2;
	int			typlen;
	bool		typbyval;
	char		typalign;
	int			i;
	int			j;
	array_iter	it1;

	if (element_type != AARR_ELEMTYPE(array2))
		ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("cannot compare arrays of different element types")));


	
	typentry = (TypeCacheEntry *) *fn_extra;
	if (typentry == NULL || typentry->type_id != element_type)
	{
		typentry = lookup_type_cache(element_type, TYPECACHE_EQ_OPR_FINFO);
		if (!OidIsValid(typentry->eq_opr_finfo.fn_oid))
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("could not identify an equality operator for type %s", format_type_be(element_type))));


		*fn_extra = (void *) typentry;
	}
	typlen = typentry->typlen;
	typbyval = typentry->typbyval;
	typalign = typentry->typalign;

	
	if (VARATT_IS_EXPANDED_HEADER(array2))
	{
		
		deconstruct_expanded_array(&(array2->xpn));
		values2 = array2->xpn.dvalues;
		nulls2 = array2->xpn.dnulls;
		nelems2 = array2->xpn.nelems;
	}
	else deconstruct_array(&(array2->flt), element_type, typlen, typbyval, typalign, &values2, &nulls2, &nelems2);



	
	InitFunctionCallInfoData(*locfcinfo, &typentry->eq_opr_finfo, 2, collation, NULL, NULL);

	
	nelems1 = ArrayGetNItems(AARR_NDIM(array1), AARR_DIMS(array1));
	array_iter_setup(&it1, array1);

	for (i = 0; i < nelems1; i++)
	{
		Datum		elt1;
		bool		isnull1;

		
		elt1 = array_iter_next(&it1, &isnull1, i, typlen, typbyval, typalign);

		
		if (isnull1)
		{
			if (matchall)
			{
				result = false;
				break;
			}
			continue;
		}

		for (j = 0; j < nelems2; j++)
		{
			Datum		elt2 = values2[j];
			bool		isnull2 = nulls2 ? nulls2[j] : false;
			bool		oprresult;

			if (isnull2)
				continue;		

			
			locfcinfo->args[0].value = elt1;
			locfcinfo->args[0].isnull = false;
			locfcinfo->args[1].value = elt2;
			locfcinfo->args[1].isnull = false;
			locfcinfo->isnull = false;
			oprresult = DatumGetBool(FunctionCallInvoke(locfcinfo));
			if (oprresult)
				break;
		}

		if (j < nelems2)
		{
			
			if (!matchall)
			{
				result = true;
				break;
			}
		}
		else {
			
			if (matchall)
			{
				result = false;
				break;
			}
		}
	}

	return result;
}

Datum arrayoverlap(PG_FUNCTION_ARGS)
{
	AnyArrayType *array1 = PG_GETARG_ANY_ARRAY_P(0);
	AnyArrayType *array2 = PG_GETARG_ANY_ARRAY_P(1);
	Oid			collation = PG_GET_COLLATION();
	bool		result;

	result = array_contain_compare(array1, array2, collation, false, &fcinfo->flinfo->fn_extra);

	
	AARR_FREE_IF_COPY(array1, 0);
	AARR_FREE_IF_COPY(array2, 1);

	PG_RETURN_BOOL(result);
}

Datum arraycontains(PG_FUNCTION_ARGS)
{
	AnyArrayType *array1 = PG_GETARG_ANY_ARRAY_P(0);
	AnyArrayType *array2 = PG_GETARG_ANY_ARRAY_P(1);
	Oid			collation = PG_GET_COLLATION();
	bool		result;

	result = array_contain_compare(array2, array1, collation, true, &fcinfo->flinfo->fn_extra);

	
	AARR_FREE_IF_COPY(array1, 0);
	AARR_FREE_IF_COPY(array2, 1);

	PG_RETURN_BOOL(result);
}

Datum arraycontained(PG_FUNCTION_ARGS)
{
	AnyArrayType *array1 = PG_GETARG_ANY_ARRAY_P(0);
	AnyArrayType *array2 = PG_GETARG_ANY_ARRAY_P(1);
	Oid			collation = PG_GET_COLLATION();
	bool		result;

	result = array_contain_compare(array1, array2, collation, true, &fcinfo->flinfo->fn_extra);

	
	AARR_FREE_IF_COPY(array1, 0);
	AARR_FREE_IF_COPY(array2, 1);

	PG_RETURN_BOOL(result);
}





ArrayIterator array_create_iterator(ArrayType *arr, int slice_ndim, ArrayMetaState *mstate)
{
	ArrayIterator iterator = palloc0(sizeof(ArrayIteratorData));

	
	Assert(PointerIsValid(arr));
	if (slice_ndim < 0 || slice_ndim > ARR_NDIM(arr))
		elog(ERROR, "invalid arguments to array_create_iterator");

	
	iterator->arr = arr;
	iterator->nullbitmap = ARR_NULLBITMAP(arr);
	iterator->nitems = ArrayGetNItems(ARR_NDIM(arr), ARR_DIMS(arr));

	if (mstate != NULL)
	{
		Assert(mstate->element_type == ARR_ELEMTYPE(arr));

		iterator->typlen = mstate->typlen;
		iterator->typbyval = mstate->typbyval;
		iterator->typalign = mstate->typalign;
	}
	else get_typlenbyvalalign(ARR_ELEMTYPE(arr), &iterator->typlen, &iterator->typbyval, &iterator->typalign);




	
	iterator->slice_ndim = slice_ndim;

	if (slice_ndim > 0)
	{
		
		iterator->slice_dims = ARR_DIMS(arr) + ARR_NDIM(arr) - slice_ndim;
		iterator->slice_lbound = ARR_LBOUND(arr) + ARR_NDIM(arr) - slice_ndim;

		
		iterator->slice_len = ArrayGetNItems(slice_ndim, iterator->slice_dims);

		
		iterator->slice_values = (Datum *)
			palloc(iterator->slice_len * sizeof(Datum));
		iterator->slice_nulls = (bool *)
			palloc(iterator->slice_len * sizeof(bool));
	}

	
	iterator->data_ptr = ARR_DATA_PTR(arr);
	iterator->current_item = 0;

	return iterator;
}


bool array_iterate(ArrayIterator iterator, Datum *value, bool *isnull)
{
	
	if (iterator->current_item >= iterator->nitems)
		return false;

	if (iterator->slice_ndim == 0)
	{
		
		if (array_get_isnull(iterator->nullbitmap, iterator->current_item++))
		{
			*isnull = true;
			*value = (Datum) 0;
		}
		else {
			
			char	   *p = iterator->data_ptr;

			*isnull = false;
			*value = fetch_att(p, iterator->typbyval, iterator->typlen);

			
			p = att_addlength_pointer(p, iterator->typlen, p);
			p = (char *) att_align_nominal(p, iterator->typalign);
			iterator->data_ptr = p;
		}
	}
	else {
		
		ArrayType  *result;
		Datum	   *values = iterator->slice_values;
		bool	   *nulls = iterator->slice_nulls;
		char	   *p = iterator->data_ptr;
		int			i;

		for (i = 0; i < iterator->slice_len; i++)
		{
			if (array_get_isnull(iterator->nullbitmap, iterator->current_item++))
			{
				nulls[i] = true;
				values[i] = (Datum) 0;
			}
			else {
				nulls[i] = false;
				values[i] = fetch_att(p, iterator->typbyval, iterator->typlen);

				
				p = att_addlength_pointer(p, iterator->typlen, p);
				p = (char *) att_align_nominal(p, iterator->typalign);
			}
		}

		iterator->data_ptr = p;

		result = construct_md_array(values, nulls, iterator->slice_ndim, iterator->slice_dims, iterator->slice_lbound, ARR_ELEMTYPE(iterator->arr), iterator->typlen, iterator->typbyval, iterator->typalign);








		*isnull = false;
		*value = PointerGetDatum(result);
	}

	return true;
}


void array_free_iterator(ArrayIterator iterator)
{
	if (iterator->slice_ndim > 0)
	{
		pfree(iterator->slice_values);
		pfree(iterator->slice_nulls);
	}
	pfree(iterator);
}







static bool array_get_isnull(const bits8 *nullbitmap, int offset)
{
	if (nullbitmap == NULL)
		return false;			
	if (nullbitmap[offset / 8] & (1 << (offset % 8)))
		return false;			
	return true;
}


static void array_set_isnull(bits8 *nullbitmap, int offset, bool isNull)
{
	int			bitmask;

	nullbitmap += offset / 8;
	bitmask = 1 << (offset % 8);
	if (isNull)
		*nullbitmap &= ~bitmask;
	else *nullbitmap |= bitmask;
}


static Datum ArrayCast(char *value, bool byval, int len)
{
	return fetch_att(value, byval, len);
}


static int ArrayCastAndSet(Datum src, int typlen, bool typbyval, char typalign, char *dest)




{
	int			inc;

	if (typlen > 0)
	{
		if (typbyval)
			store_att_byval(dest, src, typlen);
		else memmove(dest, DatumGetPointer(src), typlen);
		inc = att_align_nominal(typlen, typalign);
	}
	else {
		Assert(!typbyval);
		inc = att_addlength_datum(0, typlen, src);
		memmove(dest, DatumGetPointer(src), inc);
		inc = att_align_nominal(inc, typalign);
	}

	return inc;
}


static char * array_seek(char *ptr, int offset, bits8 *nullbitmap, int nitems, int typlen, bool typbyval, char typalign)

{
	int			bitmask;
	int			i;

	
	if (typlen > 0 && !nullbitmap)
		return ptr + nitems * ((Size) att_align_nominal(typlen, typalign));

	
	if (nullbitmap)
	{
		nullbitmap += offset / 8;
		bitmask = 1 << (offset % 8);

		for (i = 0; i < nitems; i++)
		{
			if (*nullbitmap & bitmask)
			{
				ptr = att_addlength_pointer(ptr, typlen, ptr);
				ptr = (char *) att_align_nominal(ptr, typalign);
			}
			bitmask <<= 1;
			if (bitmask == 0x100)
			{
				nullbitmap++;
				bitmask = 1;
			}
		}
	}
	else {
		for (i = 0; i < nitems; i++)
		{
			ptr = att_addlength_pointer(ptr, typlen, ptr);
			ptr = (char *) att_align_nominal(ptr, typalign);
		}
	}
	return ptr;
}


static int array_nelems_size(char *ptr, int offset, bits8 *nullbitmap, int nitems, int typlen, bool typbyval, char typalign)

{
	return array_seek(ptr, offset, nullbitmap, nitems, typlen, typbyval, typalign) - ptr;
}


static int array_copy(char *destptr, int nitems, char *srcptr, int offset, bits8 *nullbitmap, int typlen, bool typbyval, char typalign)


{
	int			numbytes;

	numbytes = array_nelems_size(srcptr, offset, nullbitmap, nitems, typlen, typbyval, typalign);
	memcpy(destptr, srcptr, numbytes);
	return numbytes;
}


void array_bitmap_copy(bits8 *destbitmap, int destoffset, const bits8 *srcbitmap, int srcoffset, int nitems)


{
	int			destbitmask, destbitval, srcbitmask, srcbitval;



	Assert(destbitmap);
	if (nitems <= 0)
		return;					
	destbitmap += destoffset / 8;
	destbitmask = 1 << (destoffset % 8);
	destbitval = *destbitmap;
	if (srcbitmap)
	{
		srcbitmap += srcoffset / 8;
		srcbitmask = 1 << (srcoffset % 8);
		srcbitval = *srcbitmap;
		while (nitems-- > 0)
		{
			if (srcbitval & srcbitmask)
				destbitval |= destbitmask;
			else destbitval &= ~destbitmask;
			destbitmask <<= 1;
			if (destbitmask == 0x100)
			{
				*destbitmap++ = destbitval;
				destbitmask = 1;
				if (nitems > 0)
					destbitval = *destbitmap;
			}
			srcbitmask <<= 1;
			if (srcbitmask == 0x100)
			{
				srcbitmap++;
				srcbitmask = 1;
				if (nitems > 0)
					srcbitval = *srcbitmap;
			}
		}
		if (destbitmask != 1)
			*destbitmap = destbitval;
	}
	else {
		while (nitems-- > 0)
		{
			destbitval |= destbitmask;
			destbitmask <<= 1;
			if (destbitmask == 0x100)
			{
				*destbitmap++ = destbitval;
				destbitmask = 1;
				if (nitems > 0)
					destbitval = *destbitmap;
			}
		}
		if (destbitmask != 1)
			*destbitmap = destbitval;
	}
}


static int array_slice_size(char *arraydataptr, bits8 *arraynullsptr, int ndim, int *dim, int *lb, int *st, int *endp, int typlen, bool typbyval, char typalign)



{
	int			src_offset, span[MAXDIM], prod[MAXDIM], dist[MAXDIM], indx[MAXDIM];



	char	   *ptr;
	int			i, j, inc;

	int			count = 0;

	mda_get_range(ndim, span, st, endp);

	
	if (typlen > 0 && !arraynullsptr)
		return ArrayGetNItems(ndim, span) * att_align_nominal(typlen, typalign);

	
	src_offset = ArrayGetOffset(ndim, dim, lb, st);
	ptr = array_seek(arraydataptr, 0, arraynullsptr, src_offset, typlen, typbyval, typalign);
	mda_get_prod(ndim, dim, prod);
	mda_get_offset_values(ndim, dist, prod, span);
	for (i = 0; i < ndim; i++)
		indx[i] = 0;
	j = ndim - 1;
	do {
		if (dist[j])
		{
			ptr = array_seek(ptr, src_offset, arraynullsptr, dist[j], typlen, typbyval, typalign);
			src_offset += dist[j];
		}
		if (!array_get_isnull(arraynullsptr, src_offset))
		{
			inc = att_addlength_pointer(0, typlen, ptr);
			inc = att_align_nominal(inc, typalign);
			ptr += inc;
			count += inc;
		}
		src_offset++;
	} while ((j = mda_next_tuple(ndim, indx, span)) != -1);
	return count;
}


static void array_extract_slice(ArrayType *newarray, int ndim, int *dim, int *lb, char *arraydataptr, bits8 *arraynullsptr, int *st, int *endp, int typlen, bool typbyval, char typalign)










{
	char	   *destdataptr = ARR_DATA_PTR(newarray);
	bits8	   *destnullsptr = ARR_NULLBITMAP(newarray);
	char	   *srcdataptr;
	int			src_offset, dest_offset, prod[MAXDIM], span[MAXDIM], dist[MAXDIM], indx[MAXDIM];




	int			i, j, inc;


	src_offset = ArrayGetOffset(ndim, dim, lb, st);
	srcdataptr = array_seek(arraydataptr, 0, arraynullsptr, src_offset, typlen, typbyval, typalign);
	mda_get_prod(ndim, dim, prod);
	mda_get_range(ndim, span, st, endp);
	mda_get_offset_values(ndim, dist, prod, span);
	for (i = 0; i < ndim; i++)
		indx[i] = 0;
	dest_offset = 0;
	j = ndim - 1;
	do {
		if (dist[j])
		{
			
			srcdataptr = array_seek(srcdataptr, src_offset, arraynullsptr, dist[j], typlen, typbyval, typalign);

			src_offset += dist[j];
		}
		inc = array_copy(destdataptr, 1, srcdataptr, src_offset, arraynullsptr, typlen, typbyval, typalign);

		if (destnullsptr)
			array_bitmap_copy(destnullsptr, dest_offset, arraynullsptr, src_offset, 1);

		destdataptr += inc;
		srcdataptr += inc;
		src_offset++;
		dest_offset++;
	} while ((j = mda_next_tuple(ndim, indx, span)) != -1);
}


static void array_insert_slice(ArrayType *destArray, ArrayType *origArray, ArrayType *srcArray, int ndim, int *dim, int *lb, int *st, int *endp, int typlen, bool typbyval, char typalign)










{
	char	   *destPtr = ARR_DATA_PTR(destArray);
	char	   *origPtr = ARR_DATA_PTR(origArray);
	char	   *srcPtr = ARR_DATA_PTR(srcArray);
	bits8	   *destBitmap = ARR_NULLBITMAP(destArray);
	bits8	   *origBitmap = ARR_NULLBITMAP(origArray);
	bits8	   *srcBitmap = ARR_NULLBITMAP(srcArray);
	int			orignitems = ArrayGetNItems(ARR_NDIM(origArray), ARR_DIMS(origArray));
	int			dest_offset, orig_offset, src_offset, prod[MAXDIM], span[MAXDIM], dist[MAXDIM], indx[MAXDIM];





	int			i, j, inc;


	dest_offset = ArrayGetOffset(ndim, dim, lb, st);
	
	inc = array_copy(destPtr, dest_offset, origPtr, 0, origBitmap, typlen, typbyval, typalign);

	destPtr += inc;
	origPtr += inc;
	if (destBitmap)
		array_bitmap_copy(destBitmap, 0, origBitmap, 0, dest_offset);
	orig_offset = dest_offset;
	mda_get_prod(ndim, dim, prod);
	mda_get_range(ndim, span, st, endp);
	mda_get_offset_values(ndim, dist, prod, span);
	for (i = 0; i < ndim; i++)
		indx[i] = 0;
	src_offset = 0;
	j = ndim - 1;
	do {
		
		if (dist[j])
		{
			inc = array_copy(destPtr, dist[j], origPtr, orig_offset, origBitmap, typlen, typbyval, typalign);

			destPtr += inc;
			origPtr += inc;
			if (destBitmap)
				array_bitmap_copy(destBitmap, dest_offset, origBitmap, orig_offset, dist[j]);

			dest_offset += dist[j];
			orig_offset += dist[j];
		}
		
		inc = array_copy(destPtr, 1, srcPtr, src_offset, srcBitmap, typlen, typbyval, typalign);

		if (destBitmap)
			array_bitmap_copy(destBitmap, dest_offset, srcBitmap, src_offset, 1);

		destPtr += inc;
		srcPtr += inc;
		dest_offset++;
		src_offset++;
		
		origPtr = array_seek(origPtr, orig_offset, origBitmap, 1, typlen, typbyval, typalign);
		orig_offset++;
	} while ((j = mda_next_tuple(ndim, indx, span)) != -1);

	
	array_copy(destPtr, orignitems - orig_offset, origPtr, orig_offset, origBitmap, typlen, typbyval, typalign);

	if (destBitmap)
		array_bitmap_copy(destBitmap, dest_offset, origBitmap, orig_offset, orignitems - orig_offset);

}


ArrayBuildState * initArrayResult(Oid element_type, MemoryContext rcontext, bool subcontext)
{
	ArrayBuildState *astate;
	MemoryContext arr_context = rcontext;

	
	if (subcontext)
		arr_context = AllocSetContextCreate(rcontext, "accumArrayResult", ALLOCSET_DEFAULT_SIZES);


	astate = (ArrayBuildState *)
		MemoryContextAlloc(arr_context, sizeof(ArrayBuildState));
	astate->mcontext = arr_context;
	astate->private_cxt = subcontext;
	astate->alen = (subcontext ? 64 : 8);	
	astate->dvalues = (Datum *)
		MemoryContextAlloc(arr_context, astate->alen * sizeof(Datum));
	astate->dnulls = (bool *)
		MemoryContextAlloc(arr_context, astate->alen * sizeof(bool));
	astate->nelems = 0;
	astate->element_type = element_type;
	get_typlenbyvalalign(element_type, &astate->typlen, &astate->typbyval, &astate->typalign);



	return astate;
}


ArrayBuildState * accumArrayResult(ArrayBuildState *astate, Datum dvalue, bool disnull, Oid element_type, MemoryContext rcontext)



{
	MemoryContext oldcontext;

	if (astate == NULL)
	{
		
		astate = initArrayResult(element_type, rcontext, true);
	}
	else {
		Assert(astate->element_type == element_type);
	}

	oldcontext = MemoryContextSwitchTo(astate->mcontext);

	
	if (astate->nelems >= astate->alen)
	{
		astate->alen *= 2;
		astate->dvalues = (Datum *)
			repalloc(astate->dvalues, astate->alen * sizeof(Datum));
		astate->dnulls = (bool *)
			repalloc(astate->dnulls, astate->alen * sizeof(bool));
	}

	
	if (!disnull && !astate->typbyval)
	{
		if (astate->typlen == -1)
			dvalue = PointerGetDatum(PG_DETOAST_DATUM_COPY(dvalue));
		else dvalue = datumCopy(dvalue, astate->typbyval, astate->typlen);
	}

	astate->dvalues[astate->nelems] = dvalue;
	astate->dnulls[astate->nelems] = disnull;
	astate->nelems++;

	MemoryContextSwitchTo(oldcontext);

	return astate;
}


Datum makeArrayResult(ArrayBuildState *astate, MemoryContext rcontext)

{
	int			ndims;
	int			dims[1];
	int			lbs[1];

	
	ndims = (astate->nelems > 0) ? 1 : 0;
	dims[0] = astate->nelems;
	lbs[0] = 1;

	return makeMdArrayResult(astate, ndims, dims, lbs, rcontext, astate->private_cxt);
}


Datum makeMdArrayResult(ArrayBuildState *astate, int ndims, int *dims, int *lbs, MemoryContext rcontext, bool release)





{
	ArrayType  *result;
	MemoryContext oldcontext;

	
	oldcontext = MemoryContextSwitchTo(rcontext);

	result = construct_md_array(astate->dvalues, astate->dnulls, ndims, dims, lbs, astate->element_type, astate->typlen, astate->typbyval, astate->typalign);








	MemoryContextSwitchTo(oldcontext);

	
	if (release)
	{
		Assert(astate->private_cxt);
		MemoryContextDelete(astate->mcontext);
	}

	return PointerGetDatum(result);
}




ArrayBuildStateArr * initArrayResultArr(Oid array_type, Oid element_type, MemoryContext rcontext, bool subcontext)

{
	ArrayBuildStateArr *astate;
	MemoryContext arr_context = rcontext;	

	
	if (!OidIsValid(element_type))
	{
		element_type = get_element_type(array_type);

		if (!OidIsValid(element_type))
			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("data type %s is not an array type", format_type_be(array_type))));


	}

	
	if (subcontext)
		arr_context = AllocSetContextCreate(rcontext, "accumArrayResultArr", ALLOCSET_DEFAULT_SIZES);


	
	astate = (ArrayBuildStateArr *)
		MemoryContextAllocZero(arr_context, sizeof(ArrayBuildStateArr));
	astate->mcontext = arr_context;
	astate->private_cxt = subcontext;

	
	astate->array_type = array_type;
	astate->element_type = element_type;

	return astate;
}


ArrayBuildStateArr * accumArrayResultArr(ArrayBuildStateArr *astate, Datum dvalue, bool disnull, Oid array_type, MemoryContext rcontext)



{
	ArrayType  *arg;
	MemoryContext oldcontext;
	int		   *dims, *lbs, ndims, nitems, ndatabytes;



	char	   *data;
	int			i;

	
	if (disnull)
		ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("cannot accumulate null arrays")));


	
	arg = DatumGetArrayTypeP(dvalue);

	if (astate == NULL)
		astate = initArrayResultArr(array_type, InvalidOid, rcontext, true);
	else Assert(astate->array_type == array_type);

	oldcontext = MemoryContextSwitchTo(astate->mcontext);

	
	ndims = ARR_NDIM(arg);
	dims = ARR_DIMS(arg);
	lbs = ARR_LBOUND(arg);
	data = ARR_DATA_PTR(arg);
	nitems = ArrayGetNItems(ndims, dims);
	ndatabytes = ARR_SIZE(arg) - ARR_DATA_OFFSET(arg);

	if (astate->ndims == 0)
	{
		

		
		if (ndims == 0)
			ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("cannot accumulate empty arrays")));

		if (ndims + 1 > MAXDIM)
			ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("number of array dimensions (%d) exceeds the maximum allowed (%d)", ndims + 1, MAXDIM)));



		
		astate->ndims = ndims + 1;
		astate->dims[0] = 0;
		memcpy(&astate->dims[1], dims, ndims * sizeof(int));
		astate->lbs[0] = 1;
		memcpy(&astate->lbs[1], lbs, ndims * sizeof(int));

		
		astate->abytes = 1024;
		while (astate->abytes <= ndatabytes)
			astate->abytes *= 2;
		astate->data = (char *) palloc(astate->abytes);
	}
	else {
		
		if (astate->ndims != ndims + 1)
			ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("cannot accumulate arrays of different dimensionality")));

		for (i = 0; i < ndims; i++)
		{
			if (astate->dims[i + 1] != dims[i] || astate->lbs[i + 1] != lbs[i])
				ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("cannot accumulate arrays of different dimensionality")));

		}

		
		if (astate->nbytes + ndatabytes > astate->abytes)
		{
			astate->abytes = Max(astate->abytes * 2, astate->nbytes + ndatabytes);
			astate->data = (char *) repalloc(astate->data, astate->abytes);
		}
	}

	
	memcpy(astate->data + astate->nbytes, data, ndatabytes);
	astate->nbytes += ndatabytes;

	
	if (astate->nullbitmap || ARR_HASNULL(arg))
	{
		int			newnitems = astate->nitems + nitems;

		if (astate->nullbitmap == NULL)
		{
			
			astate->aitems = 256;
			while (astate->aitems <= newnitems)
				astate->aitems *= 2;
			astate->nullbitmap = (bits8 *) palloc((astate->aitems + 7) / 8);
			array_bitmap_copy(astate->nullbitmap, 0, NULL, 0, astate->nitems);

		}
		else if (newnitems > astate->aitems)
		{
			astate->aitems = Max(astate->aitems * 2, newnitems);
			astate->nullbitmap = (bits8 *)
				repalloc(astate->nullbitmap, (astate->aitems + 7) / 8);
		}
		array_bitmap_copy(astate->nullbitmap, astate->nitems, ARR_NULLBITMAP(arg), 0, nitems);

	}

	astate->nitems += nitems;
	astate->dims[0] += 1;

	MemoryContextSwitchTo(oldcontext);

	
	if ((Pointer) arg != DatumGetPointer(dvalue))
		pfree(arg);

	return astate;
}


Datum makeArrayResultArr(ArrayBuildStateArr *astate, MemoryContext rcontext, bool release)


{
	ArrayType  *result;
	MemoryContext oldcontext;

	
	oldcontext = MemoryContextSwitchTo(rcontext);

	if (astate->ndims == 0)
	{
		
		result = construct_empty_array(astate->element_type);
	}
	else {
		int			dataoffset, nbytes;

		
		nbytes = astate->nbytes;
		if (astate->nullbitmap != NULL)
		{
			dataoffset = ARR_OVERHEAD_WITHNULLS(astate->ndims, astate->nitems);
			nbytes += dataoffset;
		}
		else {
			dataoffset = 0;
			nbytes += ARR_OVERHEAD_NONULLS(astate->ndims);
		}

		result = (ArrayType *) palloc0(nbytes);
		SET_VARSIZE(result, nbytes);
		result->ndim = astate->ndims;
		result->dataoffset = dataoffset;
		result->elemtype = astate->element_type;

		memcpy(ARR_DIMS(result), astate->dims, astate->ndims * sizeof(int));
		memcpy(ARR_LBOUND(result), astate->lbs, astate->ndims * sizeof(int));
		memcpy(ARR_DATA_PTR(result), astate->data, astate->nbytes);

		if (astate->nullbitmap != NULL)
			array_bitmap_copy(ARR_NULLBITMAP(result), 0, astate->nullbitmap, 0, astate->nitems);

	}

	MemoryContextSwitchTo(oldcontext);

	
	if (release)
	{
		Assert(astate->private_cxt);
		MemoryContextDelete(astate->mcontext);
	}

	return PointerGetDatum(result);
}




ArrayBuildStateAny * initArrayResultAny(Oid input_type, MemoryContext rcontext, bool subcontext)
{
	ArrayBuildStateAny *astate;
	Oid			element_type = get_element_type(input_type);

	if (OidIsValid(element_type))
	{
		
		ArrayBuildStateArr *arraystate;

		arraystate = initArrayResultArr(input_type, InvalidOid, rcontext, subcontext);
		astate = (ArrayBuildStateAny *)
			MemoryContextAlloc(arraystate->mcontext, sizeof(ArrayBuildStateAny));
		astate->scalarstate = NULL;
		astate->arraystate = arraystate;
	}
	else {
		
		ArrayBuildState *scalarstate;

		
		Assert(OidIsValid(get_array_type(input_type)));

		scalarstate = initArrayResult(input_type, rcontext, subcontext);
		astate = (ArrayBuildStateAny *)
			MemoryContextAlloc(scalarstate->mcontext, sizeof(ArrayBuildStateAny));
		astate->scalarstate = scalarstate;
		astate->arraystate = NULL;
	}

	return astate;
}


ArrayBuildStateAny * accumArrayResultAny(ArrayBuildStateAny *astate, Datum dvalue, bool disnull, Oid input_type, MemoryContext rcontext)



{
	if (astate == NULL)
		astate = initArrayResultAny(input_type, rcontext, true);

	if (astate->scalarstate)
		(void) accumArrayResult(astate->scalarstate, dvalue, disnull, input_type, rcontext);

	else (void) accumArrayResultArr(astate->arraystate, dvalue, disnull, input_type, rcontext);



	return astate;
}


Datum makeArrayResultAny(ArrayBuildStateAny *astate, MemoryContext rcontext, bool release)

{
	Datum		result;

	if (astate->scalarstate)
	{
		
		int			ndims;
		int			dims[1];
		int			lbs[1];

		
		ndims = (astate->scalarstate->nelems > 0) ? 1 : 0;
		dims[0] = astate->scalarstate->nelems;
		lbs[0] = 1;

		result = makeMdArrayResult(astate->scalarstate, ndims, dims, lbs, rcontext, release);
	}
	else {
		result = makeArrayResultArr(astate->arraystate, rcontext, release);
	}
	return result;
}


Datum array_larger(PG_FUNCTION_ARGS)
{
	if (array_cmp(fcinfo) > 0)
		PG_RETURN_DATUM(PG_GETARG_DATUM(0));
	else PG_RETURN_DATUM(PG_GETARG_DATUM(1));
}

Datum array_smaller(PG_FUNCTION_ARGS)
{
	if (array_cmp(fcinfo) < 0)
		PG_RETURN_DATUM(PG_GETARG_DATUM(0));
	else PG_RETURN_DATUM(PG_GETARG_DATUM(1));
}


typedef struct generate_subscripts_fctx {
	int32		lower;
	int32		upper;
	bool		reverse;
} generate_subscripts_fctx;


Datum generate_subscripts(PG_FUNCTION_ARGS)
{
	FuncCallContext *funcctx;
	MemoryContext oldcontext;
	generate_subscripts_fctx *fctx;

	
	if (SRF_IS_FIRSTCALL())
	{
		AnyArrayType *v = PG_GETARG_ANY_ARRAY_P(0);
		int			reqdim = PG_GETARG_INT32(1);
		int		   *lb, *dimv;

		
		funcctx = SRF_FIRSTCALL_INIT();

		
		if (AARR_NDIM(v) <= 0 || AARR_NDIM(v) > MAXDIM)
			SRF_RETURN_DONE(funcctx);

		
		if (reqdim <= 0 || reqdim > AARR_NDIM(v))
			SRF_RETURN_DONE(funcctx);

		
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);
		fctx = (generate_subscripts_fctx *) palloc(sizeof(generate_subscripts_fctx));

		lb = AARR_LBOUND(v);
		dimv = AARR_DIMS(v);

		fctx->lower = lb[reqdim - 1];
		fctx->upper = dimv[reqdim - 1] + lb[reqdim - 1] - 1;
		fctx->reverse = (PG_NARGS() < 3) ? false : PG_GETARG_BOOL(2);

		funcctx->user_fctx = fctx;

		MemoryContextSwitchTo(oldcontext);
	}

	funcctx = SRF_PERCALL_SETUP();

	fctx = funcctx->user_fctx;

	if (fctx->lower <= fctx->upper)
	{
		if (!fctx->reverse)
			SRF_RETURN_NEXT(funcctx, Int32GetDatum(fctx->lower++));
		else SRF_RETURN_NEXT(funcctx, Int32GetDatum(fctx->upper--));
	}
	else  SRF_RETURN_DONE(funcctx);

}


Datum generate_subscripts_nodir(PG_FUNCTION_ARGS)
{
	
	return generate_subscripts(fcinfo);
}


Datum array_fill_with_lower_bounds(PG_FUNCTION_ARGS)
{
	ArrayType  *dims;
	ArrayType  *lbs;
	ArrayType  *result;
	Oid			elmtype;
	Datum		value;
	bool		isnull;

	if (PG_ARGISNULL(1) || PG_ARGISNULL(2))
		ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("dimension array or low bound array cannot be null")));


	dims = PG_GETARG_ARRAYTYPE_P(1);
	lbs = PG_GETARG_ARRAYTYPE_P(2);

	if (!PG_ARGISNULL(0))
	{
		value = PG_GETARG_DATUM(0);
		isnull = false;
	}
	else {
		value = 0;
		isnull = true;
	}

	elmtype = get_fn_expr_argtype(fcinfo->flinfo, 0);
	if (!OidIsValid(elmtype))
		elog(ERROR, "could not determine data type of input");

	result = array_fill_internal(dims, lbs, value, isnull, elmtype, fcinfo);
	PG_RETURN_ARRAYTYPE_P(result);
}


Datum array_fill(PG_FUNCTION_ARGS)
{
	ArrayType  *dims;
	ArrayType  *result;
	Oid			elmtype;
	Datum		value;
	bool		isnull;

	if (PG_ARGISNULL(1))
		ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("dimension array or low bound array cannot be null")));


	dims = PG_GETARG_ARRAYTYPE_P(1);

	if (!PG_ARGISNULL(0))
	{
		value = PG_GETARG_DATUM(0);
		isnull = false;
	}
	else {
		value = 0;
		isnull = true;
	}

	elmtype = get_fn_expr_argtype(fcinfo->flinfo, 0);
	if (!OidIsValid(elmtype))
		elog(ERROR, "could not determine data type of input");

	result = array_fill_internal(dims, NULL, value, isnull, elmtype, fcinfo);
	PG_RETURN_ARRAYTYPE_P(result);
}

static ArrayType * create_array_envelope(int ndims, int *dimv, int *lbsv, int nbytes, Oid elmtype, int dataoffset)

{
	ArrayType  *result;

	result = (ArrayType *) palloc0(nbytes);
	SET_VARSIZE(result, nbytes);
	result->ndim = ndims;
	result->dataoffset = dataoffset;
	result->elemtype = elmtype;
	memcpy(ARR_DIMS(result), dimv, ndims * sizeof(int));
	memcpy(ARR_LBOUND(result), lbsv, ndims * sizeof(int));

	return result;
}

static ArrayType * array_fill_internal(ArrayType *dims, ArrayType *lbs, Datum value, bool isnull, Oid elmtype, FunctionCallInfo fcinfo)


{
	ArrayType  *result;
	int		   *dimv;
	int		   *lbsv;
	int			ndims;
	int			nitems;
	int			deflbs[MAXDIM];
	int16		elmlen;
	bool		elmbyval;
	char		elmalign;
	ArrayMetaState *my_extra;

	
	if (ARR_NDIM(dims) > 1)
		ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("wrong number of array subscripts"), errdetail("Dimension array must be one dimensional.")));



	if (array_contains_nulls(dims))
		ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("dimension values cannot be null")));


	dimv = (int *) ARR_DATA_PTR(dims);
	ndims = (ARR_NDIM(dims) > 0) ? ARR_DIMS(dims)[0] : 0;

	if (ndims < 0)				
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("invalid number of dimensions: %d", ndims)));

	if (ndims > MAXDIM)
		ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("number of array dimensions (%d) exceeds the maximum allowed (%d)", ndims, MAXDIM)));



	if (lbs != NULL)
	{
		if (ARR_NDIM(lbs) > 1)
			ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("wrong number of array subscripts"), errdetail("Dimension array must be one dimensional.")));



		if (array_contains_nulls(lbs))
			ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("dimension values cannot be null")));


		if (ndims != ((ARR_NDIM(lbs) > 0) ? ARR_DIMS(lbs)[0] : 0))
			ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("wrong number of array subscripts"), errdetail("Low bound array has different size than dimensions array.")));



		lbsv = (int *) ARR_DATA_PTR(lbs);
	}
	else {
		int			i;

		for (i = 0; i < MAXDIM; i++)
			deflbs[i] = 1;

		lbsv = deflbs;
	}

	nitems = ArrayGetNItems(ndims, dimv);

	
	if (nitems <= 0)
		return construct_empty_array(elmtype);

	
	my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;
	if (my_extra == NULL)
	{
		fcinfo->flinfo->fn_extra = MemoryContextAlloc(fcinfo->flinfo->fn_mcxt, sizeof(ArrayMetaState));
		my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;
		my_extra->element_type = InvalidOid;
	}

	if (my_extra->element_type != elmtype)
	{
		
		get_typlenbyvalalign(elmtype, &my_extra->typlen, &my_extra->typbyval, &my_extra->typalign);


		my_extra->element_type = elmtype;
	}

	elmlen = my_extra->typlen;
	elmbyval = my_extra->typbyval;
	elmalign = my_extra->typalign;

	
	if (!isnull)
	{
		int			i;
		char	   *p;
		int			nbytes;
		int			totbytes;

		
		if (elmlen == -1)
			value = PointerGetDatum(PG_DETOAST_DATUM(value));

		nbytes = att_addlength_datum(0, elmlen, value);
		nbytes = att_align_nominal(nbytes, elmalign);
		Assert(nbytes > 0);

		totbytes = nbytes * nitems;

		
		if (totbytes / nbytes != nitems || !AllocSizeIsValid(totbytes))
			ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("array size exceeds the maximum allowed (%d)", (int) MaxAllocSize)));



		
		totbytes += ARR_OVERHEAD_NONULLS(ndims);

		result = create_array_envelope(ndims, dimv, lbsv, totbytes, elmtype, 0);

		p = ARR_DATA_PTR(result);
		for (i = 0; i < nitems; i++)
			p += ArrayCastAndSet(value, elmlen, elmbyval, elmalign, p);
	}
	else {
		int			nbytes;
		int			dataoffset;

		dataoffset = ARR_OVERHEAD_WITHNULLS(ndims, nitems);
		nbytes = dataoffset;

		result = create_array_envelope(ndims, dimv, lbsv, nbytes, elmtype, dataoffset);

		
	}

	return result;
}



Datum array_unnest(PG_FUNCTION_ARGS)
{
	typedef struct {
		array_iter	iter;
		int			nextelem;
		int			numelems;
		int16		elmlen;
		bool		elmbyval;
		char		elmalign;
	} array_unnest_fctx;

	FuncCallContext *funcctx;
	array_unnest_fctx *fctx;
	MemoryContext oldcontext;

	
	if (SRF_IS_FIRSTCALL())
	{
		AnyArrayType *arr;

		
		funcctx = SRF_FIRSTCALL_INIT();

		
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		
		arr = PG_GETARG_ANY_ARRAY_P(0);

		
		fctx = (array_unnest_fctx *) palloc(sizeof(array_unnest_fctx));

		
		array_iter_setup(&fctx->iter, arr);
		fctx->nextelem = 0;
		fctx->numelems = ArrayGetNItems(AARR_NDIM(arr), AARR_DIMS(arr));

		if (VARATT_IS_EXPANDED_HEADER(arr))
		{
			
			fctx->elmlen = arr->xpn.typlen;
			fctx->elmbyval = arr->xpn.typbyval;
			fctx->elmalign = arr->xpn.typalign;
		}
		else get_typlenbyvalalign(AARR_ELEMTYPE(arr), &fctx->elmlen, &fctx->elmbyval, &fctx->elmalign);




		funcctx->user_fctx = fctx;
		MemoryContextSwitchTo(oldcontext);
	}

	
	funcctx = SRF_PERCALL_SETUP();
	fctx = funcctx->user_fctx;

	if (fctx->nextelem < fctx->numelems)
	{
		int			offset = fctx->nextelem++;
		Datum		elem;

		elem = array_iter_next(&fctx->iter, &fcinfo->isnull, offset, fctx->elmlen, fctx->elmbyval, fctx->elmalign);

		SRF_RETURN_NEXT(funcctx, elem);
	}
	else {
		
		SRF_RETURN_DONE(funcctx);
	}
}



static ArrayType * array_replace_internal(ArrayType *array, Datum search, bool search_isnull, Datum replace, bool replace_isnull, bool remove, Oid collation, FunctionCallInfo fcinfo)




{
	LOCAL_FCINFO(locfcinfo, 2);
	ArrayType  *result;
	Oid			element_type;
	Datum	   *values;
	bool	   *nulls;
	int		   *dim;
	int			ndim;
	int			nitems, nresult;
	int			i;
	int32		nbytes = 0;
	int32		dataoffset;
	bool		hasnulls;
	int			typlen;
	bool		typbyval;
	char		typalign;
	char	   *arraydataptr;
	bits8	   *bitmap;
	int			bitmask;
	bool		changed = false;
	TypeCacheEntry *typentry;

	element_type = ARR_ELEMTYPE(array);
	ndim = ARR_NDIM(array);
	dim = ARR_DIMS(array);
	nitems = ArrayGetNItems(ndim, dim);

	
	if (nitems <= 0)
		return array;

	
	if (remove && ndim > 1)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("removing elements from multidimensional arrays is not supported")));


	
	typentry = (TypeCacheEntry *) fcinfo->flinfo->fn_extra;
	if (typentry == NULL || typentry->type_id != element_type)
	{
		typentry = lookup_type_cache(element_type, TYPECACHE_EQ_OPR_FINFO);
		if (!OidIsValid(typentry->eq_opr_finfo.fn_oid))
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("could not identify an equality operator for type %s", format_type_be(element_type))));


		fcinfo->flinfo->fn_extra = (void *) typentry;
	}
	typlen = typentry->typlen;
	typbyval = typentry->typbyval;
	typalign = typentry->typalign;

	
	if (typlen == -1)
	{
		if (!search_isnull)
			search = PointerGetDatum(PG_DETOAST_DATUM(search));
		if (!replace_isnull)
			replace = PointerGetDatum(PG_DETOAST_DATUM(replace));
	}

	
	InitFunctionCallInfoData(*locfcinfo, &typentry->eq_opr_finfo, 2, collation, NULL, NULL);

	
	values = (Datum *) palloc(nitems * sizeof(Datum));
	nulls = (bool *) palloc(nitems * sizeof(bool));

	
	arraydataptr = ARR_DATA_PTR(array);
	bitmap = ARR_NULLBITMAP(array);
	bitmask = 1;
	hasnulls = false;
	nresult = 0;

	for (i = 0; i < nitems; i++)
	{
		Datum		elt;
		bool		isNull;
		bool		oprresult;
		bool		skip = false;

		
		if (bitmap && (*bitmap & bitmask) == 0)
		{
			isNull = true;
			
			if (search_isnull)
			{
				if (remove)
				{
					skip = true;
					changed = true;
				}
				else if (!replace_isnull)
				{
					values[nresult] = replace;
					isNull = false;
					changed = true;
				}
			}
		}
		else {
			isNull = false;
			elt = fetch_att(arraydataptr, typbyval, typlen);
			arraydataptr = att_addlength_datum(arraydataptr, typlen, elt);
			arraydataptr = (char *) att_align_nominal(arraydataptr, typalign);

			if (search_isnull)
			{
				
				values[nresult] = elt;
			}
			else {
				
				locfcinfo->args[0].value = elt;
				locfcinfo->args[0].isnull = false;
				locfcinfo->args[1].value = search;
				locfcinfo->args[1].isnull = false;
				locfcinfo->isnull = false;
				oprresult = DatumGetBool(FunctionCallInvoke(locfcinfo));
				if (!oprresult)
				{
					
					values[nresult] = elt;
				}
				else {
					
					changed = true;
					if (remove)
						skip = true;
					else {
						values[nresult] = replace;
						isNull = replace_isnull;
					}
				}
			}
		}

		if (!skip)
		{
			nulls[nresult] = isNull;
			if (isNull)
				hasnulls = true;
			else {
				
				nbytes = att_addlength_datum(nbytes, typlen, values[nresult]);
				nbytes = att_align_nominal(nbytes, typalign);
				
				if (!AllocSizeIsValid(nbytes))
					ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("array size exceeds the maximum allowed (%d)", (int) MaxAllocSize)));


			}
			nresult++;
		}

		
		if (bitmap)
		{
			bitmask <<= 1;
			if (bitmask == 0x100)
			{
				bitmap++;
				bitmask = 1;
			}
		}
	}

	
	if (!changed)
	{
		pfree(values);
		pfree(nulls);
		return array;
	}

	
	if (nresult == 0)
	{
		pfree(values);
		pfree(nulls);
		return construct_empty_array(element_type);
	}

	
	if (hasnulls)
	{
		dataoffset = ARR_OVERHEAD_WITHNULLS(ndim, nresult);
		nbytes += dataoffset;
	}
	else {
		dataoffset = 0;			
		nbytes += ARR_OVERHEAD_NONULLS(ndim);
	}
	result = (ArrayType *) palloc0(nbytes);
	SET_VARSIZE(result, nbytes);
	result->ndim = ndim;
	result->dataoffset = dataoffset;
	result->elemtype = element_type;
	memcpy(ARR_DIMS(result), ARR_DIMS(array), ndim * sizeof(int));
	memcpy(ARR_LBOUND(result), ARR_LBOUND(array), ndim * sizeof(int));

	if (remove)
	{
		
		ARR_DIMS(result)[0] = nresult;
	}

	
	CopyArrayEls(result, values, nulls, nresult, typlen, typbyval, typalign, false);



	pfree(values);
	pfree(nulls);

	return result;
}


Datum array_remove(PG_FUNCTION_ARGS)
{
	ArrayType  *array;
	Datum		search = PG_GETARG_DATUM(1);
	bool		search_isnull = PG_ARGISNULL(1);

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	array = PG_GETARG_ARRAYTYPE_P(0);

	array = array_replace_internal(array, search, search_isnull, (Datum) 0, true, true, PG_GET_COLLATION(), fcinfo);



	PG_RETURN_ARRAYTYPE_P(array);
}


Datum array_replace(PG_FUNCTION_ARGS)
{
	ArrayType  *array;
	Datum		search = PG_GETARG_DATUM(1);
	bool		search_isnull = PG_ARGISNULL(1);
	Datum		replace = PG_GETARG_DATUM(2);
	bool		replace_isnull = PG_ARGISNULL(2);

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	array = PG_GETARG_ARRAYTYPE_P(0);

	array = array_replace_internal(array, search, search_isnull, replace, replace_isnull, false, PG_GET_COLLATION(), fcinfo);



	PG_RETURN_ARRAYTYPE_P(array);
}


Datum width_bucket_array(PG_FUNCTION_ARGS)
{
	Datum		operand = PG_GETARG_DATUM(0);
	ArrayType  *thresholds = PG_GETARG_ARRAYTYPE_P(1);
	Oid			collation = PG_GET_COLLATION();
	Oid			element_type = ARR_ELEMTYPE(thresholds);
	int			result;

	
	if (ARR_NDIM(thresholds) > 1)
		ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("thresholds must be one-dimensional array")));


	if (array_contains_nulls(thresholds))
		ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("thresholds array must not contain NULLs")));


	
	if (element_type == FLOAT8OID)
		result = width_bucket_array_float8(operand, thresholds);
	else {
		TypeCacheEntry *typentry;

		
		typentry = (TypeCacheEntry *) fcinfo->flinfo->fn_extra;
		if (typentry == NULL || typentry->type_id != element_type)
		{
			typentry = lookup_type_cache(element_type, TYPECACHE_CMP_PROC_FINFO);
			if (!OidIsValid(typentry->cmp_proc_finfo.fn_oid))
				ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("could not identify a comparison function for type %s", format_type_be(element_type))));


			fcinfo->flinfo->fn_extra = (void *) typentry;
		}

		
		if (typentry->typlen > 0)
			result = width_bucket_array_fixed(operand, thresholds, collation, typentry);
		else result = width_bucket_array_variable(operand, thresholds, collation, typentry);

	}

	
	PG_FREE_IF_COPY(thresholds, 1);

	PG_RETURN_INT32(result);
}


static int width_bucket_array_float8(Datum operand, ArrayType *thresholds)
{
	float8		op = DatumGetFloat8(operand);
	float8	   *thresholds_data;
	int			left;
	int			right;

	
	thresholds_data = (float8 *) ARR_DATA_PTR(thresholds);

	left = 0;
	right = ArrayGetNItems(ARR_NDIM(thresholds), ARR_DIMS(thresholds));

	
	if (isnan(op))
		return right;

	
	while (left < right)
	{
		int			mid = (left + right) / 2;

		if (isnan(thresholds_data[mid]) || op < thresholds_data[mid])
			right = mid;
		else left = mid + 1;
	}

	return left;
}


static int width_bucket_array_fixed(Datum operand, ArrayType *thresholds, Oid collation, TypeCacheEntry *typentry)



{
	LOCAL_FCINFO(locfcinfo, 2);
	char	   *thresholds_data;
	int			typlen = typentry->typlen;
	bool		typbyval = typentry->typbyval;
	int			left;
	int			right;

	
	thresholds_data = (char *) ARR_DATA_PTR(thresholds);

	InitFunctionCallInfoData(*locfcinfo, &typentry->cmp_proc_finfo, 2, collation, NULL, NULL);

	
	left = 0;
	right = ArrayGetNItems(ARR_NDIM(thresholds), ARR_DIMS(thresholds));
	while (left < right)
	{
		int			mid = (left + right) / 2;
		char	   *ptr;
		int32		cmpresult;

		ptr = thresholds_data + mid * typlen;

		locfcinfo->args[0].value = operand;
		locfcinfo->args[0].isnull = false;
		locfcinfo->args[1].value = fetch_att(ptr, typbyval, typlen);
		locfcinfo->args[1].isnull = false;
		locfcinfo->isnull = false;

		cmpresult = DatumGetInt32(FunctionCallInvoke(locfcinfo));

		if (cmpresult < 0)
			right = mid;
		else left = mid + 1;
	}

	return left;
}


static int width_bucket_array_variable(Datum operand, ArrayType *thresholds, Oid collation, TypeCacheEntry *typentry)



{
	LOCAL_FCINFO(locfcinfo, 2);
	char	   *thresholds_data;
	int			typlen = typentry->typlen;
	bool		typbyval = typentry->typbyval;
	char		typalign = typentry->typalign;
	int			left;
	int			right;

	thresholds_data = (char *) ARR_DATA_PTR(thresholds);

	InitFunctionCallInfoData(*locfcinfo, &typentry->cmp_proc_finfo, 2, collation, NULL, NULL);

	
	left = 0;
	right = ArrayGetNItems(ARR_NDIM(thresholds), ARR_DIMS(thresholds));
	while (left < right)
	{
		int			mid = (left + right) / 2;
		char	   *ptr;
		int			i;
		int32		cmpresult;

		
		ptr = thresholds_data;
		for (i = left; i < mid; i++)
		{
			ptr = att_addlength_pointer(ptr, typlen, ptr);
			ptr = (char *) att_align_nominal(ptr, typalign);
		}

		locfcinfo->args[0].value = operand;
		locfcinfo->args[0].isnull = false;
		locfcinfo->args[1].value = fetch_att(ptr, typbyval, typlen);
		locfcinfo->args[1].isnull = false;

		cmpresult = DatumGetInt32(FunctionCallInvoke(locfcinfo));

		if (cmpresult < 0)
			right = mid;
		else {
			left = mid + 1;

			
			ptr = att_addlength_pointer(ptr, typlen, ptr);
			thresholds_data = (char *) att_align_nominal(ptr, typalign);
		}
	}

	return left;
}
