










static Datum array_position_common(FunctionCallInfo fcinfo);



static ExpandedArrayHeader * fetch_array_arg_replace_nulls(FunctionCallInfo fcinfo, int argno)
{
	ExpandedArrayHeader *eah;
	Oid			element_type;
	ArrayMetaState *my_extra;
	MemoryContext resultcxt;

	
	my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;
	if (my_extra == NULL)
	{
		my_extra = (ArrayMetaState *)
			MemoryContextAlloc(fcinfo->flinfo->fn_mcxt, sizeof(ArrayMetaState));
		my_extra->element_type = InvalidOid;
		fcinfo->flinfo->fn_extra = my_extra;
	}

	
	if (!AggCheckCallContext(fcinfo, &resultcxt))
		resultcxt = GetCurrentMemoryContext();

	
	if (!PG_ARGISNULL(argno))
	{
		MemoryContext oldcxt = MemoryContextSwitchTo(resultcxt);

		eah = PG_GETARG_EXPANDED_ARRAYX(argno, my_extra);
		MemoryContextSwitchTo(oldcxt);
	}
	else {
		
		Oid			arr_typeid = get_fn_expr_argtype(fcinfo->flinfo, argno);

		if (!OidIsValid(arr_typeid))
			ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("could not determine input data type")));

		element_type = get_element_type(arr_typeid);
		if (!OidIsValid(element_type))
			ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("input data type is not an array")));


		eah = construct_empty_expanded_array(element_type, resultcxt, my_extra);

	}

	return eah;
}


Datum array_append(PG_FUNCTION_ARGS)
{
	ExpandedArrayHeader *eah;
	Datum		newelem;
	bool		isNull;
	Datum		result;
	int		   *dimv, *lb;
	int			indx;
	ArrayMetaState *my_extra;

	eah = fetch_array_arg_replace_nulls(fcinfo, 0);
	isNull = PG_ARGISNULL(1);
	if (isNull)
		newelem = (Datum) 0;
	else newelem = PG_GETARG_DATUM(1);

	if (eah->ndims == 1)
	{
		
		lb = eah->lbound;
		dimv = eah->dims;

		
		if (pg_add_s32_overflow(lb[0], dimv[0], &indx))
			ereport(ERROR, (errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE), errmsg("integer out of range")));

	}
	else if (eah->ndims == 0)
		indx = 1;
	else ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION), errmsg("argument must be empty or one-dimensional array")));



	
	my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;

	result = array_set_element(EOHPGetRWDatum(&eah->hdr), 1, &indx, newelem, isNull, -1, my_extra->typlen, my_extra->typbyval, my_extra->typalign);


	PG_RETURN_DATUM(result);
}


Datum array_prepend(PG_FUNCTION_ARGS)
{
	ExpandedArrayHeader *eah;
	Datum		newelem;
	bool		isNull;
	Datum		result;
	int		   *lb;
	int			indx;
	int			lb0;
	ArrayMetaState *my_extra;

	isNull = PG_ARGISNULL(0);
	if (isNull)
		newelem = (Datum) 0;
	else newelem = PG_GETARG_DATUM(0);
	eah = fetch_array_arg_replace_nulls(fcinfo, 1);

	if (eah->ndims == 1)
	{
		
		lb = eah->lbound;
		lb0 = lb[0];

		if (pg_sub_s32_overflow(lb0, 1, &indx))
			ereport(ERROR, (errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE), errmsg("integer out of range")));

	}
	else if (eah->ndims == 0)
	{
		indx = 1;
		lb0 = 1;
	}
	else ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION), errmsg("argument must be empty or one-dimensional array")));



	
	my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;

	result = array_set_element(EOHPGetRWDatum(&eah->hdr), 1, &indx, newelem, isNull, -1, my_extra->typlen, my_extra->typbyval, my_extra->typalign);


	
	Assert(result == EOHPGetRWDatum(&eah->hdr));
	if (eah->ndims == 1)
	{
		
		eah->lbound[0] = lb0;
	}

	PG_RETURN_DATUM(result);
}


Datum array_cat(PG_FUNCTION_ARGS)
{
	ArrayType  *v1, *v2;
	ArrayType  *result;
	int		   *dims, *lbs, ndims, nitems, ndatabytes, nbytes;




	int		   *dims1, *lbs1, ndims1, nitems1, ndatabytes1;



	int		   *dims2, *lbs2, ndims2, nitems2, ndatabytes2;



	int			i;
	char	   *dat1, *dat2;
	bits8	   *bitmap1, *bitmap2;
	Oid			element_type;
	Oid			element_type1;
	Oid			element_type2;
	int32		dataoffset;

	
	if (PG_ARGISNULL(0))
	{
		if (PG_ARGISNULL(1))
			PG_RETURN_NULL();
		result = PG_GETARG_ARRAYTYPE_P(1);
		PG_RETURN_ARRAYTYPE_P(result);
	}
	if (PG_ARGISNULL(1))
	{
		result = PG_GETARG_ARRAYTYPE_P(0);
		PG_RETURN_ARRAYTYPE_P(result);
	}

	v1 = PG_GETARG_ARRAYTYPE_P(0);
	v2 = PG_GETARG_ARRAYTYPE_P(1);

	element_type1 = ARR_ELEMTYPE(v1);
	element_type2 = ARR_ELEMTYPE(v2);

	
	if (element_type1 != element_type2)
		ereport(ERROR, (errcode(ERRCODE_DATATYPE_MISMATCH), errmsg("cannot concatenate incompatible arrays"), errdetail("Arrays with element types %s and %s are not " "compatible for concatenation.", format_type_be(element_type1), format_type_be(element_type2))));






	
	element_type = element_type1;

	
	ndims1 = ARR_NDIM(v1);
	ndims2 = ARR_NDIM(v2);

	
	if (ndims1 == 0 && ndims2 > 0)
		PG_RETURN_ARRAYTYPE_P(v2);

	if (ndims2 == 0)
		PG_RETURN_ARRAYTYPE_P(v1);

	
	if (ndims1 != ndims2 && ndims1 != ndims2 - 1 && ndims1 != ndims2 + 1)

		ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("cannot concatenate incompatible arrays"), errdetail("Arrays of %d and %d dimensions are not " "compatible for concatenation.", ndims1, ndims2)));





	
	lbs1 = ARR_LBOUND(v1);
	lbs2 = ARR_LBOUND(v2);
	dims1 = ARR_DIMS(v1);
	dims2 = ARR_DIMS(v2);
	dat1 = ARR_DATA_PTR(v1);
	dat2 = ARR_DATA_PTR(v2);
	bitmap1 = ARR_NULLBITMAP(v1);
	bitmap2 = ARR_NULLBITMAP(v2);
	nitems1 = ArrayGetNItems(ndims1, dims1);
	nitems2 = ArrayGetNItems(ndims2, dims2);
	ndatabytes1 = ARR_SIZE(v1) - ARR_DATA_OFFSET(v1);
	ndatabytes2 = ARR_SIZE(v2) - ARR_DATA_OFFSET(v2);

	if (ndims1 == ndims2)
	{
		
		ndims = ndims1;
		dims = (int *) palloc(ndims * sizeof(int));
		lbs = (int *) palloc(ndims * sizeof(int));

		dims[0] = dims1[0] + dims2[0];
		lbs[0] = lbs1[0];

		for (i = 1; i < ndims; i++)
		{
			if (dims1[i] != dims2[i] || lbs1[i] != lbs2[i])
				ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("cannot concatenate incompatible arrays"), errdetail("Arrays with differing element dimensions are " "not compatible for concatenation.")));




			dims[i] = dims1[i];
			lbs[i] = lbs1[i];
		}
	}
	else if (ndims1 == ndims2 - 1)
	{
		
		ndims = ndims2;
		dims = (int *) palloc(ndims * sizeof(int));
		lbs = (int *) palloc(ndims * sizeof(int));
		memcpy(dims, dims2, ndims * sizeof(int));
		memcpy(lbs, lbs2, ndims * sizeof(int));

		
		dims[0] += 1;

		
		for (i = 0; i < ndims1; i++)
		{
			if (dims1[i] != dims[i + 1] || lbs1[i] != lbs[i + 1])
				ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("cannot concatenate incompatible arrays"), errdetail("Arrays with differing dimensions are not " "compatible for concatenation.")));



		}
	}
	else {
		
		ndims = ndims1;
		dims = (int *) palloc(ndims * sizeof(int));
		lbs = (int *) palloc(ndims * sizeof(int));
		memcpy(dims, dims1, ndims * sizeof(int));
		memcpy(lbs, lbs1, ndims * sizeof(int));

		
		dims[0] += 1;

		
		for (i = 0; i < ndims2; i++)
		{
			if (dims2[i] != dims[i + 1] || lbs2[i] != lbs[i + 1])
				ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("cannot concatenate incompatible arrays"), errdetail("Arrays with differing dimensions are not " "compatible for concatenation.")));



		}
	}

	
	nitems = ArrayGetNItems(ndims, dims);

	
	ndatabytes = ndatabytes1 + ndatabytes2;
	if (ARR_HASNULL(v1) || ARR_HASNULL(v2))
	{
		dataoffset = ARR_OVERHEAD_WITHNULLS(ndims, nitems);
		nbytes = ndatabytes + dataoffset;
	}
	else {
		dataoffset = 0;			
		nbytes = ndatabytes + ARR_OVERHEAD_NONULLS(ndims);
	}
	result = (ArrayType *) palloc0(nbytes);
	SET_VARSIZE(result, nbytes);
	result->ndim = ndims;
	result->dataoffset = dataoffset;
	result->elemtype = element_type;
	memcpy(ARR_DIMS(result), dims, ndims * sizeof(int));
	memcpy(ARR_LBOUND(result), lbs, ndims * sizeof(int));
	
	memcpy(ARR_DATA_PTR(result), dat1, ndatabytes1);
	memcpy(ARR_DATA_PTR(result) + ndatabytes1, dat2, ndatabytes2);
	
	if (ARR_HASNULL(result))
	{
		array_bitmap_copy(ARR_NULLBITMAP(result), 0, bitmap1, 0, nitems1);

		array_bitmap_copy(ARR_NULLBITMAP(result), nitems1, bitmap2, 0, nitems2);

	}

	PG_RETURN_ARRAYTYPE_P(result);
}



Datum array_agg_transfn(PG_FUNCTION_ARGS)
{
	Oid			arg1_typeid = get_fn_expr_argtype(fcinfo->flinfo, 1);
	MemoryContext aggcontext;
	ArrayBuildState *state;
	Datum		elem;

	if (arg1_typeid == InvalidOid)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("could not determine input data type")));


	

	if (!AggCheckCallContext(fcinfo, &aggcontext))
	{
		
		elog(ERROR, "array_agg_transfn called in non-aggregate context");
	}

	if (PG_ARGISNULL(0))
		state = initArrayResult(arg1_typeid, aggcontext, false);
	else state = (ArrayBuildState *) PG_GETARG_POINTER(0);

	elem = PG_ARGISNULL(1) ? (Datum) 0 : PG_GETARG_DATUM(1);

	state = accumArrayResult(state, elem, PG_ARGISNULL(1), arg1_typeid, aggcontext);




	
	PG_RETURN_POINTER(state);
}

Datum array_agg_finalfn(PG_FUNCTION_ARGS)
{
	Datum		result;
	ArrayBuildState *state;
	int			dims[1];
	int			lbs[1];

	
	Assert(AggCheckCallContext(fcinfo, NULL));

	state = PG_ARGISNULL(0) ? NULL : (ArrayBuildState *) PG_GETARG_POINTER(0);

	if (state == NULL)
		PG_RETURN_NULL();		

	dims[0] = state->nelems;
	lbs[0] = 1;

	
	result = makeMdArrayResult(state, 1, dims, lbs, GetCurrentMemoryContext(), false);


	PG_RETURN_DATUM(result);
}


Datum array_agg_array_transfn(PG_FUNCTION_ARGS)
{
	Oid			arg1_typeid = get_fn_expr_argtype(fcinfo->flinfo, 1);
	MemoryContext aggcontext;
	ArrayBuildStateArr *state;

	if (arg1_typeid == InvalidOid)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("could not determine input data type")));


	

	if (!AggCheckCallContext(fcinfo, &aggcontext))
	{
		
		elog(ERROR, "array_agg_array_transfn called in non-aggregate context");
	}


	if (PG_ARGISNULL(0))
		state = initArrayResultArr(arg1_typeid, InvalidOid, aggcontext, false);
	else state = (ArrayBuildStateArr *) PG_GETARG_POINTER(0);

	state = accumArrayResultArr(state, PG_GETARG_DATUM(1), PG_ARGISNULL(1), arg1_typeid, aggcontext);




	
	PG_RETURN_POINTER(state);
}

Datum array_agg_array_finalfn(PG_FUNCTION_ARGS)
{
	Datum		result;
	ArrayBuildStateArr *state;

	
	Assert(AggCheckCallContext(fcinfo, NULL));

	state = PG_ARGISNULL(0) ? NULL : (ArrayBuildStateArr *) PG_GETARG_POINTER(0);

	if (state == NULL)
		PG_RETURN_NULL();		

	
	result = makeArrayResultArr(state, GetCurrentMemoryContext(), false);

	PG_RETURN_DATUM(result);
}


Datum array_position(PG_FUNCTION_ARGS)
{
	return array_position_common(fcinfo);
}

Datum array_position_start(PG_FUNCTION_ARGS)
{
	return array_position_common(fcinfo);
}


static Datum array_position_common(FunctionCallInfo fcinfo)
{
	ArrayType  *array;
	Oid			collation = PG_GET_COLLATION();
	Oid			element_type;
	Datum		searched_element, value;
	bool		isnull;
	int			position, position_min;
	bool		found = false;
	TypeCacheEntry *typentry;
	ArrayMetaState *my_extra;
	bool		null_search;
	ArrayIterator array_iterator;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();

	array = PG_GETARG_ARRAYTYPE_P(0);
	element_type = ARR_ELEMTYPE(array);

	
	if (ARR_NDIM(array) > 1)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("searching for elements in multidimensional arrays is not supported")));


	if (PG_ARGISNULL(1))
	{
		
		if (!array_contains_nulls(array))
			PG_RETURN_NULL();
		searched_element = (Datum) 0;
		null_search = true;
	}
	else {
		searched_element = PG_GETARG_DATUM(1);
		null_search = false;
	}

	position = (ARR_LBOUND(array))[0] - 1;

	
	if (PG_NARGS() == 3)
	{
		if (PG_ARGISNULL(2))
			ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("initial position must not be null")));


		position_min = PG_GETARG_INT32(2);
	}
	else position_min = (ARR_LBOUND(array))[0];

	
	my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;
	if (my_extra == NULL)
	{
		fcinfo->flinfo->fn_extra = MemoryContextAlloc(fcinfo->flinfo->fn_mcxt, sizeof(ArrayMetaState));
		my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;
		my_extra->element_type = ~element_type;
	}

	if (my_extra->element_type != element_type)
	{
		get_typlenbyvalalign(element_type, &my_extra->typlen, &my_extra->typbyval, &my_extra->typalign);



		typentry = lookup_type_cache(element_type, TYPECACHE_EQ_OPR_FINFO);

		if (!OidIsValid(typentry->eq_opr_finfo.fn_oid))
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("could not identify an equality operator for type %s", format_type_be(element_type))));



		my_extra->element_type = element_type;
		fmgr_info_cxt(typentry->eq_opr_finfo.fn_oid, &my_extra->proc, fcinfo->flinfo->fn_mcxt);
	}

	
	array_iterator = array_create_iterator(array, 0, my_extra);
	while (array_iterate(array_iterator, &value, &isnull))
	{
		position++;

		
		if (position < position_min)
			continue;

		
		if (isnull || null_search)
		{
			if (isnull && null_search)
			{
				found = true;
				break;
			}
			else continue;
		}

		
		if (DatumGetBool(FunctionCall2Coll(&my_extra->proc, collation, searched_element, value)))
		{
			found = true;
			break;
		}
	}

	array_free_iterator(array_iterator);

	
	PG_FREE_IF_COPY(array, 0);

	if (!found)
		PG_RETURN_NULL();

	PG_RETURN_INT32(position);
}


Datum array_positions(PG_FUNCTION_ARGS)
{
	ArrayType  *array;
	Oid			collation = PG_GET_COLLATION();
	Oid			element_type;
	Datum		searched_element, value;
	bool		isnull;
	int			position;
	TypeCacheEntry *typentry;
	ArrayMetaState *my_extra;
	bool		null_search;
	ArrayIterator array_iterator;
	ArrayBuildState *astate = NULL;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();

	array = PG_GETARG_ARRAYTYPE_P(0);
	element_type = ARR_ELEMTYPE(array);

	position = (ARR_LBOUND(array))[0] - 1;

	
	if (ARR_NDIM(array) > 1)
		ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("searching for elements in multidimensional arrays is not supported")));


	astate = initArrayResult(INT4OID, GetCurrentMemoryContext(), false);

	if (PG_ARGISNULL(1))
	{
		
		if (!array_contains_nulls(array))
			PG_RETURN_DATUM(makeArrayResult(astate, GetCurrentMemoryContext()));
		searched_element = (Datum) 0;
		null_search = true;
	}
	else {
		searched_element = PG_GETARG_DATUM(1);
		null_search = false;
	}

	
	my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;
	if (my_extra == NULL)
	{
		fcinfo->flinfo->fn_extra = MemoryContextAlloc(fcinfo->flinfo->fn_mcxt, sizeof(ArrayMetaState));
		my_extra = (ArrayMetaState *) fcinfo->flinfo->fn_extra;
		my_extra->element_type = ~element_type;
	}

	if (my_extra->element_type != element_type)
	{
		get_typlenbyvalalign(element_type, &my_extra->typlen, &my_extra->typbyval, &my_extra->typalign);



		typentry = lookup_type_cache(element_type, TYPECACHE_EQ_OPR_FINFO);

		if (!OidIsValid(typentry->eq_opr_finfo.fn_oid))
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_FUNCTION), errmsg("could not identify an equality operator for type %s", format_type_be(element_type))));



		my_extra->element_type = element_type;
		fmgr_info_cxt(typentry->eq_opr_finfo.fn_oid, &my_extra->proc, fcinfo->flinfo->fn_mcxt);
	}

	
	array_iterator = array_create_iterator(array, 0, my_extra);
	while (array_iterate(array_iterator, &value, &isnull))
	{
		position += 1;

		
		if (isnull || null_search)
		{
			if (isnull && null_search)
				astate = accumArrayResult(astate, Int32GetDatum(position), false, INT4OID, GetCurrentMemoryContext());


			continue;
		}

		
		if (DatumGetBool(FunctionCall2Coll(&my_extra->proc, collation, searched_element, value)))
			astate = accumArrayResult(astate, Int32GetDatum(position), false, INT4OID, GetCurrentMemoryContext());

	}

	array_free_iterator(array_iterator);

	
	PG_FREE_IF_COPY(array, 0);

	PG_RETURN_DATUM(makeArrayResult(astate, GetCurrentMemoryContext()));
}
