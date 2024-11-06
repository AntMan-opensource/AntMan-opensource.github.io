










int ArrayGetOffset(int n, const int *dim, const int *lb, const int *indx)
{
	int			i, scale = 1, offset = 0;


	for (i = n - 1; i >= 0; i--)
	{
		offset += (indx[i] - lb[i]) * scale;
		scale *= dim[i];
	}
	return offset;
}


int ArrayGetOffset0(int n, const int *tup, const int *scale)
{
	int			i, lin = 0;

	for (i = 0; i < n; i++)
		lin += tup[i] * scale[i];
	return lin;
}


int ArrayGetNItems(int ndim, const int *dims)
{
	int32		ret;
	int			i;



	if (ndim <= 0)
		return 0;
	ret = 1;
	for (i = 0; i < ndim; i++)
	{
		int64		prod;

		
		if (dims[i] < 0)
			ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("array size exceeds the maximum allowed (%d)", (int) MaxArraySize)));



		prod = (int64) ret * (int64) dims[i];

		ret = (int32) prod;
		if ((int64) ret != prod)
			ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("array size exceeds the maximum allowed (%d)", (int) MaxArraySize)));


	}
	Assert(ret >= 0);
	if ((Size) ret > MaxArraySize)
		ereport(ERROR, (errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED), errmsg("array size exceeds the maximum allowed (%d)", (int) MaxArraySize)));


	return (int) ret;
}


void mda_get_range(int n, int *span, const int *st, const int *endp)
{
	int			i;

	for (i = 0; i < n; i++)
		span[i] = endp[i] - st[i] + 1;
}


void mda_get_prod(int n, const int *range, int *prod)
{
	int			i;

	prod[n - 1] = 1;
	for (i = n - 2; i >= 0; i--)
		prod[i] = prod[i + 1] * range[i + 1];
}


void mda_get_offset_values(int n, int *dist, const int *prod, const int *span)
{
	int			i, j;

	dist[n - 1] = 0;
	for (j = n - 2; j >= 0; j--)
	{
		dist[j] = prod[j] - 1;
		for (i = j + 1; i < n; i++)
			dist[j] -= (span[i] - 1) * prod[i];
	}
}


int mda_next_tuple(int n, int *curr, const int *span)
{
	int			i;

	if (n <= 0)
		return -1;

	curr[n - 1] = (curr[n - 1] + 1) % span[n - 1];
	for (i = n - 1; i && curr[i] == 0; i--)
		curr[i - 1] = (curr[i - 1] + 1) % span[i - 1];

	if (i)
		return i;
	if (curr[0])
		return 0;

	return -1;
}


int32 * ArrayGetIntegerTypmods(ArrayType *arr, int *n)
{
	int32	   *result;
	Datum	   *elem_values;
	int			i;

	if (ARR_ELEMTYPE(arr) != CSTRINGOID)
		ereport(ERROR, (errcode(ERRCODE_ARRAY_ELEMENT_ERROR), errmsg("typmod array must be type cstring[]")));


	if (ARR_NDIM(arr) != 1)
		ereport(ERROR, (errcode(ERRCODE_ARRAY_SUBSCRIPT_ERROR), errmsg("typmod array must be one-dimensional")));


	if (array_contains_nulls(arr))
		ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("typmod array must not contain nulls")));


	
	deconstruct_array(arr, CSTRINGOID, -2, false, 'c', &elem_values, NULL, n);


	result = (int32 *) palloc(*n * sizeof(int32));

	for (i = 0; i < *n; i++)
		result[i] = pg_atoi(DatumGetCString(elem_values[i]), sizeof(int32), '\0');

	pfree(elem_values);

	return result;
}
