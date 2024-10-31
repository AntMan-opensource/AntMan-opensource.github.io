



















_pdfio_value_t	* _pdfioValueCopy(pdfio_file_t   *pdfdst, _pdfio_value_t *vdst, pdfio_file_t   *pdfsrc, _pdfio_value_t *vsrc)



{
  pdfio_obj_t	*obj;			

  static const char * const types[] =	 {
    "PDFIO_VALTYPE_NONE", "PDFIO_VALTYPE_ARRAY", "PDFIO_VALTYPE_BINARY", "PDFIO_VALTYPE_BOOLEAN", "PDFIO_VALTYPE_DATE", "PDFIO_VALTYPE_DICT", "PDFIO_VALTYPE_INDIRECT", "PDFIO_VALTYPE_NAME", "PDFIO_VALTYPE_NULL", "PDFIO_VALTYPE_NUMBER", "PDFIO_VALTYPE_STRING" };













  PDFIO_DEBUG("_pdfioValueCopy(pdfdst=%p, vdst=%p, pdfsrc=%p, vsrc=%p(%s))\n", pdfdst, vdst, pdfsrc, vsrc, types[vsrc->type]);

  if (pdfdst == pdfsrc && vsrc->type != PDFIO_VALTYPE_BINARY)
  {
    
    
    *vdst = *vsrc;
    return (vdst);
  }

  
  switch (vsrc->type)
  {
    case PDFIO_VALTYPE_INDIRECT :
        if ((obj = _pdfioFileFindMappedObj(pdfdst, pdfsrc, vsrc->value.indirect.number)) == NULL)
        {
          obj = pdfioObjCopy(pdfdst, pdfioFileFindObj(pdfsrc, vsrc->value.indirect.number));
	}

        if (!obj)
          return (NULL);

	vdst->value.indirect.number     = obj->number;
	vdst->value.indirect.generation = obj->generation;
	break;

    default :
        return (NULL);

    case PDFIO_VALTYPE_ARRAY :
        vdst->value.array = pdfioArrayCopy(pdfdst, vsrc->value.array);
        break;

    case PDFIO_VALTYPE_BINARY :
        if ((vdst->value.binary.data = (unsigned char *)malloc(vsrc->value.binary.datalen)) == NULL)
        {
          _pdfioFileError(pdfdst, "Unable to allocate memory for a binary string - %s", strerror(errno));
          return (NULL);
        }

        vdst->value.binary.datalen = vsrc->value.binary.datalen;
        memcpy(vdst->value.binary.data, vsrc->value.binary.data, vdst->value.binary.datalen);
        break;

    case PDFIO_VALTYPE_BOOLEAN :
    case PDFIO_VALTYPE_DATE :
    case PDFIO_VALTYPE_NUMBER :
	*vdst = *vsrc;
        return (vdst);

    case PDFIO_VALTYPE_DICT :
        vdst->value.dict = pdfioDictCopy(pdfdst, vsrc->value.dict);
        break;

    case PDFIO_VALTYPE_NAME :
    case PDFIO_VALTYPE_STRING :
        vdst->value.name = pdfioStringCreate(pdfdst, vsrc->value.name);
        break;
  }

  vdst->type = vsrc->type;

  return (vdst);
}






void _pdfioValueDebug(_pdfio_value_t *v, FILE           *fp)

{
  switch (v->type)
  {
    case PDFIO_VALTYPE_ARRAY :
        _pdfioArrayDebug(v->value.array, fp);
	break;
    case PDFIO_VALTYPE_BINARY :
	{
	  size_t	i;		
	  unsigned char	*ptr;		

	  putc('<', fp);
	  for (i = v->value.binary.datalen, ptr = v->value.binary.data; i > 0; i --, ptr ++)
	    fprintf(fp, "%02X", *ptr);
	  putc('>', fp);
	}
	break;
    case PDFIO_VALTYPE_BOOLEAN :
	fputs(v->value.boolean ? " true" : " false", fp);
	break;
    case PDFIO_VALTYPE_DATE :
        {
	  struct tm	dateval;	


          gmtime_s(&dateval, &v->value.date);

          gmtime_r(&v->value.date, &dateval);


          fprintf(fp, "(D:%04d%02d%02d%02d%02d%02dZ)", dateval.tm_year + 1900, dateval.tm_mon + 1, dateval.tm_mday, dateval.tm_hour, dateval.tm_min, dateval.tm_sec);
        }
        break;
    case PDFIO_VALTYPE_DICT :
	fputs("<<", fp);
	_pdfioDictDebug(v->value.dict, fp);
	fputs(">>", fp);
	break;
    case PDFIO_VALTYPE_INDIRECT :
	fprintf(fp, " %lu %u R", (unsigned long)v->value.indirect.number, v->value.indirect.generation);
	break;
    case PDFIO_VALTYPE_NAME :
	fprintf(fp, "/%s", v->value.name);
	break;
    case PDFIO_VALTYPE_NULL :
	fputs(" null", fp);
	break;
    case PDFIO_VALTYPE_NUMBER :
	fprintf(fp, " %g", v->value.number);
	break;
    case PDFIO_VALTYPE_STRING :
	fprintf(fp, "(%s)", v->value.string);
	break;

    default :
        break;
  }
}






void _pdfioValueDelete(_pdfio_value_t *v)
{
  if (v->type == PDFIO_VALTYPE_BINARY)
    free(v->value.binary.data);
}






_pdfio_value_t *			 _pdfioValueRead(pdfio_file_t   *pdf, pdfio_obj_t    *obj, _pdfio_token_t *tb, _pdfio_value_t *v, size_t         depth)




{
  char		token[32768];		

  static const char * const valtypes[] = {
    "<<none>>",				 "array", "hex-string", "boolean", "date", "dict", "indirect", "name", "null", "number", "string" };













  PDFIO_DEBUG("_pdfioValueRead(pdf=%p, obj=%p, v=%p)\n", pdf, obj, v);

  if (!_pdfioTokenGet(tb, token, sizeof(token)))
    return (NULL);

  if (!strcmp(token, "["))
  {
    
    if (depth >= PDFIO_MAX_DEPTH)
    {
      _pdfioFileError(pdf, "Too many nested arrays.");
      return (NULL);
    }

    v->type = PDFIO_VALTYPE_ARRAY;
    if ((v->value.array = _pdfioArrayRead(pdf, obj, tb, depth + 1)) == NULL)
      return (NULL);
  }
  else if (!strcmp(token, "<<"))
  {
    
    if (depth >= PDFIO_MAX_DEPTH)
    {
      _pdfioFileError(pdf, "Too many nested dictionaries.");
      return (NULL);
    }

    v->type = PDFIO_VALTYPE_DICT;
    if ((v->value.dict = _pdfioDictRead(pdf, obj, tb, depth + 1)) == NULL)
      return (NULL);
  }
  else if (!strncmp(token, "(D:", 3))
  {
    
    
    
    
    
    
    int		i;			
    struct tm	dateval;		
    int		offset;			

    for (i = 3; i < 17; i ++)
    {
      if (!isdigit(token[i] & 255))
        break;
    }

    if (i >= 17)
    {
      if (token[i] == 'Z')
      {
        i ++;
      }
      else if (token[i] == '-' || token[i] == '+')
      {
        if (isdigit(token[i + 1] & 255) && isdigit(token[i + 2] & 255) && token[i + 3] == '\'' && isdigit(token[i + 4] & 255) && isdigit(token[i + 5] & 255))
        {
          i += 6;
          if (token[i] == '\'')
            i ++;
	}
      }
    }

    if (token[i])
    {
      
      v->type         = PDFIO_VALTYPE_STRING;
      v->value.string = pdfioStringCreate(pdf, token + 1);
    }
    else {
      
      memset(&dateval, 0, sizeof(dateval));

      dateval.tm_year = (token[3] - '0') * 1000 + (token[4] - '0') * 100 + (token[5] - '0') * 10 + token[6] - '0' - 1900;
      dateval.tm_mon  = (token[7] - '0') * 10 + token[8] - '0' - 1;
      dateval.tm_mday = (token[9] - '0') * 10 + token[10] - '0';
      dateval.tm_hour = (token[11] - '0') * 10 + token[12] - '0';
      dateval.tm_min  = (token[13] - '0') * 10 + token[14] - '0';
      dateval.tm_sec  = (token[15] - '0') * 10 + token[16] - '0';

      if (token[17] == 'Z')
      {
        offset = 0;
      }
      else {
        offset = (token[18] - '0') * 600 + (token[19] - '0') * 60 + (token[20] - '0') * 10 + token[21] - '0';
        if (token[17] == '-')
          offset = -offset;
      }

      v->type       = PDFIO_VALTYPE_DATE;
      v->value.date = mktime(&dateval) + offset;
    }
  }
  else if (token[0] == '(')
  {
    
    v->type         = PDFIO_VALTYPE_STRING;
    v->value.string = pdfioStringCreate(pdf, token + 1);
  }
  else if (token[0] == '/')
  {
    
    v->type       = PDFIO_VALTYPE_NAME;
    v->value.name = pdfioStringCreate(pdf, token + 1);
  }
  else if (token[0] == '<')
  {
    
    const char		*tokptr;	
    unsigned char	*dataptr;	

    v->type                 = PDFIO_VALTYPE_BINARY;
    v->value.binary.datalen = strlen(token) / 2;
    if ((v->value.binary.data = (unsigned char *)malloc(v->value.binary.datalen)) == NULL)
    {
      _pdfioFileError(pdf, "Out of memory for hex string.");
      return (NULL);
    }

    
    tokptr  = token + 1;
    dataptr = v->value.binary.data;

    while (*tokptr)
    {
      int	d;			

      if (isdigit(*tokptr))
	d = (*tokptr++ - '0') << 4;
      else d = (tolower(*tokptr++) - 'a' + 10) << 4;

      if (*tokptr)
      {
	
	if (isdigit(*tokptr))
	  d |= *tokptr++ - '0';
	else d |= tolower(*tokptr++) - 'a' + 10;
      }

      *dataptr++ = (unsigned char)d;
    }

    if (obj && pdf->encryption)
    {
      
      _pdfio_crypto_ctx_t ctx;		
      _pdfio_crypto_cb_t cb;		
      size_t	ivlen;			
      uint8_t	temp[32768];		
      size_t	templen;		

      if (v->value.binary.datalen > (sizeof(temp) - 32))
      {
	_pdfioFileError(pdf, "Unable to read encrypted binary string - too long.");
	return (false);
      }

      cb      = _pdfioCryptoMakeReader(pdf, obj, &ctx, v->value.binary.data, &ivlen);
      templen = (cb)(&ctx, temp, v->value.binary.data + ivlen, v->value.binary.datalen - ivlen);

      
      memcpy(v->value.binary.data, temp, templen);

      if (pdf->encryption >= PDFIO_ENCRYPTION_AES_128)
        v->value.binary.datalen = templen - temp[templen - 1];
      else v->value.binary.datalen = templen;
    }
  }
  else if (strchr("0123456789-+.", token[0]) != NULL)
  {
    
    if (isdigit(token[0]) && !strchr(token, '.'))
    {
      
      unsigned char *tempptr;		


      PDFIO_DEBUG("_pdfioValueRead: %d bytes left in buffer: '", (int)(tb->bufend - tb->bufptr));
      for (tempptr = tb->bufptr; tempptr < tb->bufend; tempptr ++)
      {
	if (*tempptr < ' ' || *tempptr == 0x7f)
	  PDFIO_DEBUG("\\%03o", *tempptr);
	else PDFIO_DEBUG("%c", *tempptr);
      }
      PDFIO_DEBUG("'.\n");


      if ((tb->bufend - tb->bufptr) < 10)
      {
        
        ssize_t	bytes;			

        _pdfioTokenFlush(tb);

        if ((bytes = (tb->peek_cb)(tb->cb_data, tb->buffer, sizeof(tb->buffer))) > 0)
	  tb->bufend = tb->buffer + bytes;


	PDFIO_DEBUG("_pdfioValueRead: %d bytes now in buffer: '", (int)(tb->bufend - tb->bufptr));
	for (tempptr = tb->bufptr; tempptr < tb->bufend; tempptr ++)
	{
	  if (*tempptr < ' ' || *tempptr == 0x7f)
	    PDFIO_DEBUG("\\%03o", *tempptr);
	  else PDFIO_DEBUG("%c", *tempptr);
	}
	PDFIO_DEBUG("'.\n");

      }

      tempptr = tb->bufptr;

      while (tempptr < tb->bufend && isspace(*tempptr & 255))
        tempptr ++;			

      if (tempptr < tb->bufend && isdigit(*tempptr & 255))
      {
        
        long generation = 0;		

        while (tempptr < tb->bufend && isdigit(*tempptr & 255))
        {
          generation = generation * 10 + *tempptr - '0';
          tempptr ++;
        }

	while (tempptr < tb->bufend && isspace(*tempptr & 255))
	  tempptr ++;			

	if (tempptr < tb->bufend && *tempptr == 'R')
	{
	  
	  PDFIO_DEBUG("_pdfioValueRead: Consuming %d bytes.\n", (int)(tempptr - tb->bufptr + 1));
	  tb->bufptr = tempptr + 1;


	  PDFIO_DEBUG("_pdfioValueRead: Next bytes are '");
	  for (tempptr = tb->bufptr; tempptr < tb->bufend; tempptr ++)
	  {
	    if (*tempptr < ' ' || *tempptr == 0x7f)
	      PDFIO_DEBUG("\\%03o", *tempptr);
	    else PDFIO_DEBUG("%c", *tempptr);
	  }
	  PDFIO_DEBUG("'.\n");


	  v->type                      = PDFIO_VALTYPE_INDIRECT;
	  v->value.indirect.number     = (size_t)strtoimax(token, NULL, 10);
	  v->value.indirect.generation = (unsigned short)generation;

	  PDFIO_DEBUG("_pdfioValueRead: Returning indirect value %lu %u R.\n", (unsigned long)v->value.indirect.number, v->value.indirect.generation);

	  return (v);
	}
      }
    }

    
    v->type         = PDFIO_VALTYPE_NUMBER;
    v->value.number = (double)strtod(token, NULL);
  }
  else if (!strcmp(token, "true") || !strcmp(token, "false"))
  {
    
    v->type          = PDFIO_VALTYPE_BOOLEAN;
    v->value.boolean = !strcmp(token, "true");
  }
  else if (!strcmp(token, "null"))
  {
    
    v->type = PDFIO_VALTYPE_NULL;
  }
  else {
    _pdfioFileError(pdf, "Unexpected '%s' token seen.", token);
    return (NULL);
  }

  PDFIO_DEBUG("_pdfioValueRead: Returning %s value.\n", valtypes[v->type]);

  return (v);
}






bool					 _pdfioValueWrite(pdfio_file_t   *pdf, pdfio_obj_t    *obj, _pdfio_value_t *v, off_t          *length)



{
  switch (v->type)
  {
    default :
        return (false);

    case PDFIO_VALTYPE_ARRAY :
        return (_pdfioArrayWrite(v->value.array, obj));

    case PDFIO_VALTYPE_BINARY :
        {
          size_t	databytes;	
          uint8_t	temp[32768],	 *dataptr;

          if (obj && pdf->encryption)
          {
	    
	    _pdfio_crypto_ctx_t ctx;	
	    _pdfio_crypto_cb_t cb;	
	    size_t	ivlen;		

            if (v->value.binary.datalen > (sizeof(temp) - 32))
            {
	      _pdfioFileError(pdf, "Unable to write encrypted binary string - too long.");
	      return (false);
            }

	    cb        = _pdfioCryptoMakeWriter(pdf, obj, &ctx, temp, &ivlen);
	    databytes = (cb)(&ctx, temp + ivlen, v->value.binary.data, v->value.binary.datalen) + ivlen;
	    dataptr   = temp;
          }
          else {
            dataptr   = v->value.binary.data;
            databytes = v->value.binary.datalen;
          }

          if (!_pdfioFilePuts(pdf, "<"))
            return (false);

          for (; databytes > 1; databytes -= 2, dataptr += 2)
          {
            if (!_pdfioFilePrintf(pdf, "%02X%02X", dataptr[0], dataptr[1]))
              return (false);
          }

          if (databytes > 0)
            return (_pdfioFilePrintf(pdf, "%02X>", dataptr[0]));
          else return (_pdfioFilePuts(pdf, ">"));
        }

    case PDFIO_VALTYPE_BOOLEAN :
        if (v->value.boolean)
          return (_pdfioFilePuts(pdf, " true"));
        else return (_pdfioFilePuts(pdf, " false"));

    case PDFIO_VALTYPE_DATE :
        {
          struct tm	date;		
          char		datestr[32];	


          gmtime_s(&date, &v->value.date);

	  gmtime_r(&v->value.date, &date);


	  snprintf(datestr, sizeof(datestr), "D:%04d%02d%02d%02d%02d%02dZ", date.tm_year + 1900, date.tm_mon + 1, date.tm_mday, date.tm_hour, date.tm_min, date.tm_sec);

	  if (obj && pdf->encryption)
	  {
	    
	    uint8_t	temp[32768],	 *tempptr;
	    _pdfio_crypto_ctx_t ctx;	
	    _pdfio_crypto_cb_t cb;	
	    size_t	len = strlen(datestr),  ivlen, tempbytes;



	    cb        = _pdfioCryptoMakeWriter(pdf, obj, &ctx, temp, &ivlen);
	    tempbytes = (cb)(&ctx, temp + ivlen, (const uint8_t *)datestr, len) + ivlen;

	    if (!_pdfioFilePuts(pdf, "<"))
	      return (false);

	    for (tempptr = temp; tempbytes > 1; tempbytes -= 2, tempptr += 2)
	    {
	      if (!_pdfioFilePrintf(pdf, "%02X%02X", tempptr[0], tempptr[1]))
		return (false);
	    }

            if (tempbytes > 0)
              return (_pdfioFilePrintf(pdf, "%02X>", *tempptr));
            else return (_pdfioFilePuts(pdf, ">"));
	  }
	  else {
	    return (_pdfioFilePrintf(pdf, "(%s)", datestr));
	  }
        }

    case PDFIO_VALTYPE_DICT :
        return (_pdfioDictWrite(v->value.dict, obj, length));

    case PDFIO_VALTYPE_INDIRECT :
        return (_pdfioFilePrintf(pdf, " %lu %u R", (unsigned long)v->value.indirect.number, v->value.indirect.generation));

    case PDFIO_VALTYPE_NAME :
        return (_pdfioFilePrintf(pdf, "/%s", v->value.name));

    case PDFIO_VALTYPE_NULL :
        return (_pdfioFilePuts(pdf, " null"));

    case PDFIO_VALTYPE_NUMBER :
        return (_pdfioFilePrintf(pdf, " %g", v->value.number));

    case PDFIO_VALTYPE_STRING :
        if (obj && pdf->encryption)
        {
          
          uint8_t	temp[32768],	 *tempptr;
          _pdfio_crypto_ctx_t ctx;	
          _pdfio_crypto_cb_t cb;	
          size_t	len = strlen(v->value.string),  ivlen, tempbytes;



          if (len > (sizeof(temp) - 32))
          {
            _pdfioFileError(pdf, "Unable to write encrypted string - too long.");
            return (false);
          }

          cb        = _pdfioCryptoMakeWriter(pdf, obj, &ctx, temp, &ivlen);
          tempbytes = (cb)(&ctx, temp + ivlen, (const uint8_t *)v->value.string, len) + ivlen;

          if (!_pdfioFilePuts(pdf, "<"))
            return (false);

          for (tempptr = temp; tempbytes > 1; tempbytes -= 2, tempptr += 2)
          {
            if (!_pdfioFilePrintf(pdf, "%02X%02X", tempptr[0], tempptr[1]))
              return (false);
          }

          if (tempbytes > 0)
            return (_pdfioFilePrintf(pdf, "%02X>", *tempptr));
          else return (_pdfioFilePuts(pdf, ">"));
        }
        else {
          
          const char *start,		 *end;

          if (!_pdfioFilePuts(pdf, "("))
            return (false);

          
          for (start = v->value.string; *start; start = end)
          {
            
            for (end = start; *end; end ++)
            {
              if (*end == '\\' || *end == ')' || (*end & 255) < ' ')
                break;
            }

            if (end > start)
            {
              
	      if (!_pdfioFileWrite(pdf, start, (size_t)(end - start)))
		return (false);
	    }

            if (*end)
            {
              
              bool success;		

              if (*end == '\\' || *end == ')')
                success = _pdfioFilePrintf(pdf, "\\%c", *end);
              else success = _pdfioFilePrintf(pdf, "\\%03o", *end);

              if (!success)
                return (false);

              end ++;
            }
          }

          return (_pdfioFilePuts(pdf, ")"));
        }
  }

  return (false);
}
