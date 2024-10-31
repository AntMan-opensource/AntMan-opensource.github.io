



















static int	compare_pairs(_pdfio_pair_t *a, _pdfio_pair_t *b);






void _pdfioDictClear(pdfio_dict_t *dict, const char   *key)

{
  size_t	idx;			
  _pdfio_pair_t	*pair,			 pkey;


  PDFIO_DEBUG("_pdfioDictClear(dict=%p, key=\"%s\")\n", dict, key);

  
  if (dict->num_pairs > 0)
  {
    pkey.key = key;

    if ((pair = (_pdfio_pair_t *)bsearch(&pkey, dict->pairs, dict->num_pairs, sizeof(_pdfio_pair_t), (int (*)(const void *, const void *))compare_pairs)) != NULL)
    {
      
      if (pair->value.type == PDFIO_VALTYPE_BINARY)
        free(pair->value.value.binary.data);

      idx = (size_t)(pair - dict->pairs);
      dict->num_pairs --;

      if (idx < dict->num_pairs)
        memmove(pair, pair + 1, (dict->num_pairs - idx) * sizeof(_pdfio_pair_t));
    }
  }
}






pdfio_dict_t *				 pdfioDictCopy(pdfio_file_t *pdf, pdfio_dict_t *dict)

{
  pdfio_dict_t		*ndict;		
  size_t		i;		
  _pdfio_pair_t		*p;		
  const char		*key;		
  _pdfio_value_t	v;		


  PDFIO_DEBUG("pdfioDictCopy(pdf=%p, dict=%p(%p))\n", pdf, dict, dict ? dict->pdf : NULL);

  
  if ((ndict = pdfioDictCreate(pdf)) == NULL)
    return (NULL);

  
  if ((ndict->pairs = (_pdfio_pair_t *)malloc(dict->num_pairs * sizeof(_pdfio_pair_t))) == NULL)
    return (NULL);			

  ndict->alloc_pairs = dict->num_pairs;

  
  for (i = dict->num_pairs, p = dict->pairs; i > 0; i --, p ++)
  {
    if (!strcmp(p->key, "Length") && p->value.type == PDFIO_VALTYPE_INDIRECT && dict->pdf != pdf)
    {
      
      pdfio_obj_t *lenobj = pdfioFileFindObj(dict->pdf, p->value.value.indirect.number);
					

      v.type = PDFIO_VALTYPE_NUMBER;
      if (lenobj)
      {
        if (lenobj->value.type == PDFIO_VALTYPE_NONE)
          _pdfioObjLoad(lenobj);

	v.value.number = lenobj->value.value.number;
      }
      else v.value.number = 0.0;
    }
    else if (!_pdfioValueCopy(pdf, &v, dict->pdf, &p->value))
      return (NULL);			

    if (_pdfioStringIsAllocated(dict->pdf, p->key))
      key = pdfioStringCreate(pdf, p->key);
    else key = p->key;

    if (!key)
      return (NULL);			

    
    _pdfioDictSetValue(ndict, key, &v);
  }

  
  return (ndict);
}






pdfio_dict_t *				 pdfioDictCreate(pdfio_file_t *pdf)
{
  pdfio_dict_t	*dict;			


  if (!pdf)
    return (NULL);

  if ((dict = (pdfio_dict_t *)calloc(1, sizeof(pdfio_dict_t))) == NULL)
    return (NULL);

  dict->pdf = pdf;

  if (pdf->num_dicts >= pdf->alloc_dicts)
  {
    pdfio_dict_t **temp = (pdfio_dict_t **)realloc(pdf->dicts, (pdf->alloc_dicts + 16) * sizeof(pdfio_dict_t *));

    if (!temp)
    {
      free(dict);
      return (NULL);
    }

    pdf->dicts       = temp;
    pdf->alloc_dicts += 16;
  }

  pdf->dicts[pdf->num_dicts ++] = dict;

  return (dict);
}






void _pdfioDictDebug(pdfio_dict_t *dict, FILE         *fp)

{
  size_t	i;			
  _pdfio_pair_t	*pair;			


  for (i = dict->num_pairs, pair = dict->pairs; i > 0; i --, pair ++)
  {
    fprintf(fp, "/%s", pair->key);
    _pdfioValueDebug(&pair->value, fp);
  }
}






void _pdfioDictDelete(pdfio_dict_t *dict)
{
  if (dict)
  {
    size_t	i;			
    _pdfio_pair_t *pair;		

    for (i = dict->num_pairs, pair = dict->pairs; i > 0; i --, pair ++)
    {
      if (pair->value.type == PDFIO_VALTYPE_BINARY)
        free(pair->value.value.binary.data);
    }

    free(dict->pairs);
  }

  free(dict);
}






pdfio_array_t *				 pdfioDictGetArray(pdfio_dict_t *dict, const char   *key)

{
  _pdfio_value_t *value = _pdfioDictGetValue(dict, key);


  if (value && value->type == PDFIO_VALTYPE_ARRAY)
    return (value->value.array);
  else return (NULL);
}






unsigned char *				 pdfioDictGetBinary(pdfio_dict_t *dict, const char   *key, size_t       *length)


{
  _pdfio_value_t *value = _pdfioDictGetValue(dict, key);


  if (!length)
    return (NULL);

  if (value && value->type == PDFIO_VALTYPE_BINARY)
  {
    *length = value->value.binary.datalen;
    return (value->value.binary.data);
  }
  else if (value && value->type == PDFIO_VALTYPE_STRING)
  {
    *length = strlen(value->value.string);
    return ((unsigned char *)value->value.string);
  }
  else {
    *length = 0;
    return (NULL);
  }
}






bool					 pdfioDictGetBoolean(pdfio_dict_t *dict, const char   *key)

{
  _pdfio_value_t *value = _pdfioDictGetValue(dict, key);


  if (value && value->type == PDFIO_VALTYPE_BOOLEAN)
    return (value->value.boolean);
  else return (false);
}






time_t					 pdfioDictGetDate(pdfio_dict_t *dict, const char   *key)

{
  _pdfio_value_t *value = _pdfioDictGetValue(dict, key);


  if (value && value->type == PDFIO_VALTYPE_DATE)
    return (value->value.date);
  else return (0);
}






pdfio_dict_t *				 pdfioDictGetDict(pdfio_dict_t *dict, const char   *key)

{
  _pdfio_value_t *value = _pdfioDictGetValue(dict, key);


  if (value && value->type == PDFIO_VALTYPE_DICT)
    return (value->value.dict);
  else return (NULL);
}






const char *				 pdfioDictGetName(pdfio_dict_t *dict, const char   *key)

{
  _pdfio_value_t *value = _pdfioDictGetValue(dict, key);


  if (value && value->type == PDFIO_VALTYPE_NAME)
    return (value->value.name);
  else return (NULL);
}






double					 pdfioDictGetNumber(pdfio_dict_t *dict, const char   *key)

{
  _pdfio_value_t *value = _pdfioDictGetValue(dict, key);


  if (value && value->type == PDFIO_VALTYPE_NUMBER)
    return (value->value.number);
  else return (0.0);
}






pdfio_obj_t *				 pdfioDictGetObj(pdfio_dict_t *dict, const char   *key)

{
  _pdfio_value_t *value = _pdfioDictGetValue(dict, key);


  if (value && value->type == PDFIO_VALTYPE_INDIRECT)
    return (pdfioFileFindObj(dict->pdf, value->value.indirect.number));
  else return (NULL);
}






pdfio_rect_t *				 pdfioDictGetRect(pdfio_dict_t *dict, const char   *key, pdfio_rect_t *rect)


{
  _pdfio_value_t *value = _pdfioDictGetValue(dict, key);


  if (value && value->type == PDFIO_VALTYPE_ARRAY && pdfioArrayGetSize(value->value.array) == 4)
  {
    rect->x1 = pdfioArrayGetNumber(value->value.array, 0);
    rect->y1 = pdfioArrayGetNumber(value->value.array, 1);
    rect->x2 = pdfioArrayGetNumber(value->value.array, 2);
    rect->y2 = pdfioArrayGetNumber(value->value.array, 3);
    return (rect);
  }
  else {
    memset(rect, 0, sizeof(pdfio_rect_t));
    return (NULL);
  }
}






const char *				 pdfioDictGetString(pdfio_dict_t *dict, const char   *key)

{
  _pdfio_value_t *value = _pdfioDictGetValue(dict, key);


  if (value && value->type == PDFIO_VALTYPE_STRING)
    return (value->value.string);
  else return (NULL);
}






pdfio_valtype_t				 pdfioDictGetType(pdfio_dict_t *dict, const char   *key)

{
  _pdfio_value_t *value = _pdfioDictGetValue(dict, key);


  return (value ? value->type : PDFIO_VALTYPE_NONE);
}






_pdfio_value_t *			 _pdfioDictGetValue(pdfio_dict_t *dict, const char   *key)

{
  _pdfio_pair_t	temp,			 *match;


  PDFIO_DEBUG("_pdfioDictGetValue(dict=%p, key=\"%s\")\n", dict, key);

  if (!dict || !dict->num_pairs || !key)
  {
    PDFIO_DEBUG("_pdfioDictGetValue: Returning NULL.\n");
    return (NULL);
  }

  temp.key = key;

  if ((match = bsearch(&temp, dict->pairs, dict->num_pairs, sizeof(_pdfio_pair_t), (int (*)(const void *, const void *))compare_pairs)) != NULL)
  {
    PDFIO_DEBUG("_pdfioDictGetValue: Match, returning ");
    PDFIO_DEBUG_VALUE(&(match->value));
    PDFIO_DEBUG(".\n");
    return (&(match->value));
  }
  else {
    PDFIO_DEBUG("_pdfioDictGetValue: No match, returning NULL.\n");
    return (NULL);
  }
}





















void pdfioDictIterateKeys( pdfio_dict_t    *dict, pdfio_dict_cb_t cb, void            *cb_data)



{
  size_t	i;			
  _pdfio_pair_t	*pair;			


  
  if (!dict || !cb)
    return;

  for (i = dict->num_pairs, pair = dict->pairs; i > 0; i --, pair ++)
  {
    if (!(cb)(dict, pair->key, cb_data))
      break;
  }
}








pdfio_dict_t *				 _pdfioDictRead(pdfio_file_t   *pdf, pdfio_obj_t    *obj, _pdfio_token_t *tb, size_t         depth)



{
  pdfio_dict_t		*dict;		
  char			key[256];	
  _pdfio_value_t	value;		


  PDFIO_DEBUG("_pdfioDictRead(pdf=%p)\n", pdf);

  
  if ((dict = pdfioDictCreate(pdf)) == NULL)
    return (NULL);

  while (_pdfioTokenGet(tb, key, sizeof(key)))
  {
    
    if (!strcmp(key, ">>"))
    {
      
      return (dict);
    }
    else if (key[0] != '/')
    {
      _pdfioFileError(pdf, "Invalid dictionary contents.");
      break;
    }

    
    if (!_pdfioValueRead(pdf, obj, tb, &value, depth))
    {
      _pdfioFileError(pdf, "Missing value for dictionary key.");
      break;
    }

    if (!_pdfioDictSetValue(dict, pdfioStringCreate(pdf, key + 1), &value))
      break;


  }

  
  
  return (NULL);
}






bool					 pdfioDictSetArray(pdfio_dict_t  *dict, const char    *key, pdfio_array_t *value)


{
  _pdfio_value_t temp;			


  
  if (!dict || !key || !value)
    return (false);

  
  temp.type        = PDFIO_VALTYPE_ARRAY;
  temp.value.array = value;

  return (_pdfioDictSetValue(dict, key, &temp));
}







bool					 pdfioDictSetBinary( pdfio_dict_t        *dict, const char          *key, const unsigned char *value, size_t              valuelen)




{
  _pdfio_value_t temp;			


  
  if (!dict || !key || !value || !valuelen)
    return (false);

  
  temp.type                 = PDFIO_VALTYPE_BINARY;
  temp.value.binary.datalen = valuelen;

  if ((temp.value.binary.data = (unsigned char *)malloc(valuelen)) == NULL)
    return (false);

  memcpy(temp.value.binary.data, value, valuelen);

  if (!_pdfioDictSetValue(dict, key, &temp))
  {
    free(temp.value.binary.data);
    return (false);
  }

  return (true);
}






bool					 pdfioDictSetBoolean(pdfio_dict_t *dict, const char   *key, bool         value)


{
  _pdfio_value_t temp;			


  
  if (!dict || !key)
    return (false);

  
  temp.type          = PDFIO_VALTYPE_BOOLEAN;
  temp.value.boolean = value;

  return (_pdfioDictSetValue(dict, key, &temp));
}






bool					 pdfioDictSetDate(pdfio_dict_t *dict, const char   *key, time_t       value)


{
  _pdfio_value_t temp;			


  
  if (!dict || !key)
    return (false);

  
  temp.type       = PDFIO_VALTYPE_DATE;
  temp.value.date = value;

  return (_pdfioDictSetValue(dict, key, &temp));
}






bool					 pdfioDictSetDict(pdfio_dict_t *dict, const char   *key, pdfio_dict_t *value)


{
  _pdfio_value_t temp;			


  
  if (!dict || !key || !value)
    return (false);

  
  temp.type       = PDFIO_VALTYPE_DICT;
  temp.value.dict = value;

  return (_pdfioDictSetValue(dict, key, &temp));
}






bool					 pdfioDictSetName(pdfio_dict_t  *dict, const char    *key, const char    *value)


{
  _pdfio_value_t temp;			


  
  if (!dict || !key || !value)
    return (false);

  
  temp.type       = PDFIO_VALTYPE_NAME;
  temp.value.name = value;

  return (_pdfioDictSetValue(dict, key, &temp));
}






bool					 pdfioDictSetNull(pdfio_dict_t *dict, const char   *key)

{
  _pdfio_value_t temp;			


  
  if (!dict || !key)
    return (false);

  
  temp.type = PDFIO_VALTYPE_NULL;

  return (_pdfioDictSetValue(dict, key, &temp));
}






bool					 pdfioDictSetNumber(pdfio_dict_t  *dict, const char    *key, double        value)


{
  _pdfio_value_t temp;			


  
  if (!dict || !key)
    return (false);

  
  temp.type         = PDFIO_VALTYPE_NUMBER;
  temp.value.number = value;

  return (_pdfioDictSetValue(dict, key, &temp));
}






bool					 pdfioDictSetObj(pdfio_dict_t *dict, const char    *key, pdfio_obj_t   *value)


{
  _pdfio_value_t temp;			


  
  if (!dict || !key || !value)
    return (false);

  
  temp.type                      = PDFIO_VALTYPE_INDIRECT;
  temp.value.indirect.number     = value->number;
  temp.value.indirect.generation = value->generation;

  return (_pdfioDictSetValue(dict, key, &temp));
}






bool					 pdfioDictSetRect(pdfio_dict_t *dict, const char   *key, pdfio_rect_t *value)


{
  _pdfio_value_t temp;			


  
  if (!dict || !key || !value)
    return (false);

  
  temp.type        = PDFIO_VALTYPE_ARRAY;
  temp.value.array = pdfioArrayCreate(dict->pdf);

  pdfioArrayAppendNumber(temp.value.array, value->x1);
  pdfioArrayAppendNumber(temp.value.array, value->y1);
  pdfioArrayAppendNumber(temp.value.array, value->x2);
  pdfioArrayAppendNumber(temp.value.array, value->y2);

  return (_pdfioDictSetValue(dict, key, &temp));
}






bool					 pdfioDictSetString(pdfio_dict_t  *dict, const char     *key, const char     *value)


{
  _pdfio_value_t temp;			


  
  if (!dict || !key || !value)
    return (false);

  
  temp.type         = PDFIO_VALTYPE_STRING;
  temp.value.string = value;

  return (_pdfioDictSetValue(dict, key, &temp));
}






bool					 pdfioDictSetStringf( pdfio_dict_t  *dict, const char    *key, const char    *format, ...)




{
  char		buffer[8192];		
  va_list	ap;			


  
  if (!dict || !key || !format)
    return (false);

  
  va_start(ap, format);
  vsnprintf(buffer, sizeof(buffer), format, ap);
  va_end(ap);

  return (pdfioDictSetString(dict, key, buffer));
}






bool					 _pdfioDictSetValue( pdfio_dict_t   *dict, const char     *key, _pdfio_value_t *value)



{
  _pdfio_pair_t	*pair;			


  PDFIO_DEBUG("_pdfioDictSetValue(dict=%p, key=\"%s\", value=%p)\n", dict, key, (void *)value);

  
  if (dict->num_pairs > 0)
  {
    _pdfio_pair_t	pkey;		

    pkey.key = key;

    if ((pair = (_pdfio_pair_t *)bsearch(&pkey, dict->pairs, dict->num_pairs, sizeof(_pdfio_pair_t), (int (*)(const void *, const void *))compare_pairs)) != NULL)
    {
      
      PDFIO_DEBUG("_pdfioDictSetValue: Replacing existing value.\n");
      if (pair->value.type == PDFIO_VALTYPE_BINARY)
        free(pair->value.value.binary.data);
      pair->value = *value;
      return (true);
    }
  }

  
  if (dict->num_pairs >= dict->alloc_pairs)
  {
    
    _pdfio_pair_t *temp = (_pdfio_pair_t *)realloc(dict->pairs, (dict->alloc_pairs + 8) * sizeof(_pdfio_pair_t));

    if (!temp)
    {
      PDFIO_DEBUG("_pdfioDictSetValue: Out of memory.\n");
      return (false);
    }

    dict->pairs       = temp;
    dict->alloc_pairs += 8;
  }

  pair = dict->pairs + dict->num_pairs;
  dict->num_pairs ++;

  pair->key   = key;
  pair->value = *value;

  
  if (dict->num_pairs > 1 && compare_pairs(pair - 1, pair) > 0)
    qsort(dict->pairs, dict->num_pairs, sizeof(_pdfio_pair_t), (int (*)(const void *, const void *))compare_pairs);


  PDFIO_DEBUG("_pdfioDictSetValue(%p): %lu pairs\n", (void *)dict, (unsigned long)dict->num_pairs);
  PDFIO_DEBUG("_pdfioDictSetValue(%p): ", (void *)dict);
  PDFIO_DEBUG_DICT(dict);
  PDFIO_DEBUG("\n");


  return (true);
}






bool					 _pdfioDictWrite(pdfio_dict_t *dict, pdfio_obj_t  *obj, off_t        *length)


{
  pdfio_file_t	*pdf = dict->pdf;	
  size_t	i;			
  _pdfio_pair_t	*pair;			


  if (length)
    *length = 0;

  
  if (!_pdfioFilePuts(pdf, "<<"))
    return (false);

  
  for (i = dict->num_pairs, pair = dict->pairs; i > 0; i --, pair ++)
  {
    if (!_pdfioFilePrintf(pdf, "/%s", pair->key))
      return (false);

    if (length && !strcmp(pair->key, "Length") && pair->value.type == PDFIO_VALTYPE_NUMBER && pair->value.value.number <= 0.0)
    {
      
      *length = _pdfioFileTell(pdf) + 1;
      if (!_pdfioFilePuts(pdf, " 9999999999"))
        return (false);
    }
    else if (!_pdfioValueWrite(pdf, obj, &pair->value, NULL))
      return (false);
  }

  
  return (_pdfioFilePuts(pdf, ">>"));
}






static int				 compare_pairs(_pdfio_pair_t *a, _pdfio_pair_t *b)

{
  return (strcmp(a->key, b->key));
}
