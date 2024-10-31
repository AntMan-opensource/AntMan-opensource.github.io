



















static bool	write_obj_header(pdfio_obj_t *obj);







bool					 pdfioObjClose(pdfio_obj_t *obj)
{
  
  if (!obj)
    return (false);

  
  obj->pdf->current_obj = NULL;

  if (obj->pdf->mode != _PDFIO_MODE_WRITE)
  {
    
    return (true);
  }

  
  if (!obj->offset)
  {
    
    if (!write_obj_header(obj))
      return (false);

    
    return (_pdfioFilePuts(obj->pdf, "endobj\n"));
  }
  else if (obj->stream)
  {
    
    return (pdfioStreamClose(obj->stream));
  }
  else {
    
    return (true);
  }
}






pdfio_obj_t *				 pdfioObjCopy(pdfio_file_t *pdf, pdfio_obj_t  *srcobj)

{
  pdfio_obj_t	*dstobj;		
  pdfio_stream_t *srcst,		 *dstst;
  char		buffer[32768];		
  ssize_t	bytes;			


  PDFIO_DEBUG("pdfioObjCopy(pdf=%p, srcobj=%p(%p))\n", pdf, srcobj, srcobj ? srcobj->pdf : NULL);

  
  if (!pdf || !srcobj)
    return (NULL);

  
  if (srcobj->value.type == PDFIO_VALTYPE_NONE)
    _pdfioObjLoad(srcobj);

  
  if ((dstobj = _pdfioFileCreateObj(pdf, srcobj->pdf, NULL)) == NULL)
    return (NULL);

  
  if (!_pdfioFileAddMappedObj(pdf, dstobj, srcobj))
    return (NULL);

  
  if (!_pdfioValueCopy(pdf, &dstobj->value, srcobj->pdf, &srcobj->value))
    return (NULL);

  if (dstobj->value.type == PDFIO_VALTYPE_DICT)
    _pdfioDictClear(dstobj->value.value.dict, "Length");

  if (srcobj->stream_offset)
  {
    
    if ((srcst = pdfioObjOpenStream(srcobj, false)) == NULL)
    {
      pdfioObjClose(dstobj);
      return (NULL);
    }

    if ((dstst = pdfioObjCreateStream(dstobj, PDFIO_FILTER_NONE)) == NULL)
    {
      pdfioStreamClose(srcst);
      pdfioObjClose(dstobj);
      return (NULL);
    }

    while ((bytes = pdfioStreamRead(srcst, buffer, sizeof(buffer))) > 0)
    {
      if (!pdfioStreamWrite(dstst, buffer, (size_t)bytes))
      {
        bytes = -1;
        break;
      }
    }

    pdfioStreamClose(srcst);
    pdfioStreamClose(dstst);

    if (bytes < 0)
      return (NULL);
  }
  else pdfioObjClose(dstobj);

  return (dstobj);
}






pdfio_stream_t *			 pdfioObjCreateStream( pdfio_obj_t    *obj, pdfio_filter_t filter)


{
  pdfio_obj_t	*length_obj = NULL;	


  
  if (!obj || obj->pdf->mode != _PDFIO_MODE_WRITE || obj->value.type != PDFIO_VALTYPE_DICT)
    return (NULL);

  if (obj->offset)
  {
    _pdfioFileError(obj->pdf, "Object has already been written.");
    return (NULL);
  }

  if (filter != PDFIO_FILTER_NONE && filter != PDFIO_FILTER_FLATE)
  {
    _pdfioFileError(obj->pdf, "Unsupported filter value for PDFioObjCreateStream.");
    return (NULL);
  }

  if (obj->pdf->current_obj)
  {
    _pdfioFileError(obj->pdf, "Another object (%u) is already open.", (unsigned)obj->pdf->current_obj->number);
    return (NULL);
  }

  
  if (!_pdfioDictGetValue(obj->value.value.dict, "Length"))
  {
    if (obj->pdf->output_cb)
    {
      
      _pdfio_value_t	length_value;	

      length_value.type         = PDFIO_VALTYPE_NUMBER;
      length_value.value.number = 0.0f;

      length_obj = _pdfioFileCreateObj(obj->pdf, obj->pdf, &length_value);
      pdfioDictSetObj(obj->value.value.dict, "Length", length_obj);
    }
    else {
      
      
      pdfioDictSetNumber(obj->value.value.dict, "Length", 0.0);
    }
  }

  if (!write_obj_header(obj))
    return (NULL);

  if (!_pdfioFilePuts(obj->pdf, "stream\n"))
    return (NULL);

  obj->stream_offset    = _pdfioFileTell(obj->pdf);
  obj->pdf->current_obj = obj;

  
  return (_pdfioStreamCreate(obj, length_obj, filter));
}






void _pdfioObjDelete(pdfio_obj_t *obj)
{
  if (obj)
    pdfioStreamClose(obj->stream);

  free(obj);
}






pdfio_array_t *				 pdfioObjGetArray(pdfio_obj_t *obj)
{
  if (!obj)
    return (NULL);

  if (obj->value.type == PDFIO_VALTYPE_NONE)
    _pdfioObjLoad(obj);

  if (obj->value.type == PDFIO_VALTYPE_ARRAY)
    return (obj->value.value.array);
  else return (NULL);
}






pdfio_dict_t *				 pdfioObjGetDict(pdfio_obj_t *obj)
{
  if (!obj)
    return (NULL);

  if (obj->value.type == PDFIO_VALTYPE_NONE)
    _pdfioObjLoad(obj);

  if (obj->value.type == PDFIO_VALTYPE_DICT)
    return (obj->value.value.dict);
  else return (NULL);
}






unsigned short				 pdfioObjGetGeneration(pdfio_obj_t *obj)
{
  return (obj ? obj->generation : 0);
}






size_t					 pdfioObjGetLength(pdfio_obj_t *obj)
{
  size_t	length;			
  pdfio_obj_t	*lenobj;		


  
  if (!obj || !obj->stream_offset || obj->value.type != PDFIO_VALTYPE_DICT)
    return (0);

  
  if ((length = (size_t)pdfioDictGetNumber(obj->value.value.dict, "Length")) > 0)
  {
    PDFIO_DEBUG("pdfioObjGetLength(obj=%p) returning %lu.\n", obj, (unsigned long)length);
    return (length);
  }

  if ((lenobj = pdfioDictGetObj(obj->value.value.dict, "Length")) == NULL)
  {
    _pdfioFileError(obj->pdf, "Unable to get length of stream.");
    return (0);
  }

  if (lenobj->value.type == PDFIO_VALTYPE_NONE)
    _pdfioObjLoad(lenobj);

  if (lenobj->value.type != PDFIO_VALTYPE_NUMBER || lenobj->value.value.number <= 0.0)
  {
    _pdfioFileError(obj->pdf, "Unable to get length of stream.");
    return (0);
  }

  PDFIO_DEBUG("pdfioObjGetLength(obj=%p) returning %lu.\n", obj, (unsigned long)lenobj->value.value.number);

  return ((size_t)lenobj->value.value.number);
}






size_t					 pdfioObjGetNumber(pdfio_obj_t *obj)
{
  return (obj ? obj->number : 0);
}






const char *				 pdfioObjGetSubtype(pdfio_obj_t *obj)
{
  pdfio_dict_t	*dict;			


  if ((dict = pdfioObjGetDict(obj)) == NULL)
    return (NULL);
  else return (pdfioDictGetName(dict, "Subtype"));
}






const char *				 pdfioObjGetType(pdfio_obj_t *obj)
{
  pdfio_dict_t	*dict;			


  if ((dict = pdfioObjGetDict(obj)) == NULL)
    return (NULL);
  else return (pdfioDictGetName(dict, "Type"));
}






bool					 _pdfioObjLoad(pdfio_obj_t *obj)
{
  char			line[64],	 *ptr;
  ssize_t		bytes;		
  _pdfio_token_t	tb;		


  PDFIO_DEBUG("_pdfioObjLoad(obj=%p(%lu)), offset=%lu\n", obj, (unsigned long)obj->number, (unsigned long)obj->offset);

  
  if (_pdfioFileSeek(obj->pdf, obj->offset, SEEK_SET) != obj->offset)
  {
    _pdfioFileError(obj->pdf, "Unable to seek to object %lu.", (unsigned long)obj->number);
    return (false);
  }

  if ((bytes = _pdfioFilePeek(obj->pdf, line, sizeof(line) - 1)) < 0)
  {
    _pdfioFileError(obj->pdf, "Unable to read header for object %lu.", (unsigned long)obj->number);
    return (false);
  }

  line[bytes] = '\0';

  PDFIO_DEBUG("_pdfioObjLoad: Header is '%s'.\n", line);

  if (strtoimax(line, &ptr, 10) != (intmax_t)obj->number)
  {
    _pdfioFileError(obj->pdf, "Bad header for object %lu.", (unsigned long)obj->number);
    return (false);
  }

  if (strtol(ptr, &ptr, 10) != (long)obj->generation)
  {
    _pdfioFileError(obj->pdf, "Bad header for object %lu.", (unsigned long)obj->number);
    return (false);
  }

  while (isspace(*ptr & 255))
    ptr ++;

  if (strncmp(ptr, "obj", 3) || (ptr[3] && ptr[3] != '<' && ptr[3] != '[' && !isspace(ptr[3] & 255)))
  {
    _pdfioFileError(obj->pdf, "Bad header for object %lu.", (unsigned long)obj->number);
    return (false);
  }

  ptr += 3;
  _pdfioFileConsume(obj->pdf, (size_t)(ptr - line));

  
  _pdfioTokenInit(&tb, obj->pdf, (_pdfio_tconsume_cb_t)_pdfioFileConsume, (_pdfio_tpeek_cb_t)_pdfioFilePeek, obj->pdf);

  if (!_pdfioValueRead(obj->pdf, obj, &tb, &obj->value, 0))
  {
    _pdfioFileError(obj->pdf, "Unable to read value for object %lu.", (unsigned long)obj->number);
    return (false);
  }

  
  if (!_pdfioTokenGet(&tb, line, sizeof(line)))
  {
    _pdfioFileError(obj->pdf, "Early end-of-file for object %lu.", (unsigned long)obj->number);
    return (false);
  }

  _pdfioTokenFlush(&tb);

  if (!strcmp(line, "stream"))
  {
    
    obj->stream_offset = _pdfioFileTell(obj->pdf);
    PDFIO_DEBUG("_pdfioObjLoad: stream_offset=%lu.\n", (unsigned long)obj->stream_offset);
  }

  PDFIO_DEBUG("_pdfioObjLoad: ");
  PDFIO_DEBUG_VALUE(&obj->value);
  PDFIO_DEBUG("\n");

  return (true);
}






pdfio_stream_t *			 pdfioObjOpenStream(pdfio_obj_t *obj, bool        decode)

{
  
  if (!obj)
    return (NULL);

  if (obj->pdf->current_obj)
  {
    _pdfioFileError(obj->pdf, "Another object (%u) is already open.", (unsigned)obj->pdf->current_obj->number);
    return (NULL);
  }

  
  if (!obj->value.type)
  {
    if (!_pdfioObjLoad(obj))
      return (NULL);
  }

  
  if (obj->value.type != PDFIO_VALTYPE_DICT || !obj->stream_offset)
    return (NULL);

  
  obj->pdf->current_obj = obj;

  return (_pdfioStreamOpen(obj, decode));
}






static bool				 write_obj_header(pdfio_obj_t *obj)
{
  obj->offset = _pdfioFileTell(obj->pdf);

  if (!_pdfioFilePrintf(obj->pdf, "%lu %u obj\n", (unsigned long)obj->number, obj->generation))
    return (false);

  if (!_pdfioValueWrite(obj->pdf, obj, &obj->value, &obj->length_offset))
    return (false);

  return (_pdfioFilePuts(obj->pdf, "\n"));
}
