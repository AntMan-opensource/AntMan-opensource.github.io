






















static pdfio_obj_t	*add_obj(pdfio_file_t *pdf, size_t number, unsigned short generation, off_t offset);
static int		compare_objmaps(_pdfio_objmap_t *a, _pdfio_objmap_t *b);
static int		compare_objs(pdfio_obj_t **a, pdfio_obj_t **b);
static const char	*get_info_string(pdfio_file_t *pdf, const char *key);
static bool		load_obj_stream(pdfio_obj_t *obj);
static bool		load_pages(pdfio_file_t *pdf, pdfio_obj_t *obj, size_t depth);
static bool		load_xref(pdfio_file_t *pdf, off_t xref_offset, pdfio_password_cb_t password_cb, void *password_data);
static bool		write_catalog(pdfio_file_t *pdf);
static bool		write_pages(pdfio_file_t *pdf);
static bool		write_trailer(pdfio_file_t *pdf);






bool					 _pdfioFileAddMappedObj( pdfio_file_t *pdf, pdfio_obj_t  *dst_obj, pdfio_obj_t  *src_obj)



{
  _pdfio_objmap_t	*map;		


  
  if (pdf->num_objmaps >= pdf->alloc_objmaps)
  {
    if ((map = realloc(pdf->objmaps, (pdf->alloc_objmaps + 16) * sizeof(_pdfio_objmap_t))) == NULL)
    {
      _pdfioFileError(pdf, "Unable to allocate memory for object map.");
      return (false);
    }

    pdf->alloc_objmaps += 16;
    pdf->objmaps       = map;
  }

  
  map = pdf->objmaps + pdf->num_objmaps;
  pdf->num_objmaps ++;

  map->obj        = dst_obj;
  map->src_pdf    = src_obj->pdf;
  map->src_number = src_obj->number;

  
  if (pdf->num_objmaps > 1 && compare_objmaps(map, pdf->objmaps + pdf->num_objmaps - 2) < 0)
    qsort(pdf->objmaps, pdf->num_objmaps, sizeof(_pdfio_objmap_t), (int (*)(const void *, const void *))compare_objmaps);

  return (true);
}






bool					 _pdfioFileAddPage(pdfio_file_t *pdf, pdfio_obj_t  *obj)

{
  
  if (pdf->num_pages >= pdf->alloc_pages)
  {
    pdfio_obj_t **temp = (pdfio_obj_t **)realloc(pdf->pages, (pdf->alloc_pages + 16) * sizeof(pdfio_obj_t *));

    if (!temp)
    {
      _pdfioFileError(pdf, "Unable to allocate memory for pages.");
      return (false);
    }

    pdf->alloc_pages += 16;
    pdf->pages       = temp;
  }

  pdf->pages[pdf->num_pages ++] = obj;

  return (true);
}






bool					 pdfioFileClose(pdfio_file_t *pdf)
{
  bool		ret = true;		
  size_t	i;			


  
  if (!pdf)
    return (false);

  
  if (pdf->mode == _PDFIO_MODE_WRITE)
  {
    ret = false;

    if (pdfioObjClose(pdf->info_obj))
      if (write_pages(pdf))
	if (write_catalog(pdf))
	  if (write_trailer(pdf))
	    ret = _pdfioFileFlush(pdf);
  }

  if (pdf->fd >= 0 && close(pdf->fd) < 0)
    ret = false;

  
  free(pdf->filename);
  free(pdf->version);

  for (i = 0; i < pdf->num_arrays; i ++)
    _pdfioArrayDelete(pdf->arrays[i]);
  free(pdf->arrays);

  for (i = 0; i < pdf->num_dicts; i ++)
    _pdfioDictDelete(pdf->dicts[i]);
  free(pdf->dicts);

  for (i = 0; i < pdf->num_objs; i ++)
    _pdfioObjDelete(pdf->objs[i]);
  free(pdf->objs);

  free(pdf->objmaps);

  free(pdf->pages);

  for (i = 0; i < pdf->num_strings; i ++)
    free(pdf->strings[i]);
  free(pdf->strings);

  free(pdf);

  return (ret);
}




















pdfio_file_t *				 pdfioFileCreate( const char       *filename, const char       *version, pdfio_rect_t     *media_box, pdfio_rect_t     *crop_box, pdfio_error_cb_t error_cb, void             *error_data)






{
  pdfio_file_t	*pdf;			
  pdfio_dict_t	*dict;			
  pdfio_dict_t	*info_dict;		
  unsigned char	id_value[16];		


  
  if (!filename)
    return (NULL);

  if (!version)
    version = "2.0";

  if (!error_cb)
  {
    error_cb   = _pdfioFileDefaultError;
    error_data = NULL;
  }

  
  if ((pdf = (pdfio_file_t *)calloc(1, sizeof(pdfio_file_t))) == NULL)
  {
    pdfio_file_t temp;			
    char	message[8192];		

    temp.filename = (char *)filename;
    snprintf(message, sizeof(message), "Unable to allocate memory for PDF file - %s", strerror(errno));
    (error_cb)(&temp, message, error_data);
    return (NULL);
  }

  pdf->filename    = strdup(filename);
  pdf->version     = strdup(version);
  pdf->mode        = _PDFIO_MODE_WRITE;
  pdf->error_cb    = error_cb;
  pdf->error_data  = error_data;
  pdf->permissions = PDFIO_PERMISSION_ALL;
  pdf->bufptr      = pdf->buffer;
  pdf->bufend      = pdf->buffer + sizeof(pdf->buffer);

  if (media_box)
  {
    pdf->media_box = *media_box;
  }
  else {
    
    pdf->media_box.x2 = 210.0 * 72.0f / 25.4f;
    pdf->media_box.y2 = 11.0f * 72.0f;
  }

  if (crop_box)
  {
    pdf->crop_box = *crop_box;
  }
  else {
    
    pdf->crop_box.x2 = 210.0 * 72.0f / 25.4f;
    pdf->crop_box.y2 = 11.0f * 72.0f;
  }

  
  if ((pdf->fd = open(filename, O_WRONLY | O_BINARY | O_CREAT | O_TRUNC, 0666)) < 0)
  {
    _pdfioFileError(pdf, "Unable to create file - %s", strerror(errno));
    free(pdf->filename);
    free(pdf->version);
    free(pdf);
    return (NULL);
  }

  
  if (!_pdfioFilePrintf(pdf, "%%PDF-%s\n%%\342\343\317\323\n", version))
    goto error;

  
  if ((dict = pdfioDictCreate(pdf)) == NULL)
    goto error;

  pdfioDictSetName(dict, "Type", "Pages");

  if ((pdf->pages_obj = pdfioFileCreateObj(pdf, dict)) == NULL)
    goto error;

  
  if ((info_dict = pdfioDictCreate(pdf)) == NULL)
    goto error;

  pdfioDictSetDate(info_dict, "CreationDate", time(NULL));
  pdfioDictSetString(info_dict, "Producer", "pdfio/" PDFIO_VERSION);

  if ((pdf->info_obj = pdfioFileCreateObj(pdf, info_dict)) == NULL)
    goto error;

  
  _pdfioCryptoMakeRandom(id_value, sizeof(id_value));

  if ((pdf->id_array = pdfioArrayCreate(pdf)) != NULL)
  {
    pdfioArrayAppendBinary(pdf->id_array, id_value, sizeof(id_value));
    pdfioArrayAppendBinary(pdf->id_array, id_value, sizeof(id_value));
  }

  return (pdf);

  
  error:

  pdfioFileClose(pdf);

  unlink(filename);

  return (NULL);
}









pdfio_obj_t *				 pdfioFileCreateArrayObj( pdfio_file_t  *pdf, pdfio_array_t *array)


{
  _pdfio_value_t	value;		


  
  if (!pdf || !array)
    return (NULL);

  value.type        = PDFIO_VALTYPE_ARRAY;
  value.value.array = array;

  return (_pdfioFileCreateObj(pdf, array->pdf, &value));
}






pdfio_obj_t *				 pdfioFileCreateObj( pdfio_file_t *pdf, pdfio_dict_t *dict)


{
  _pdfio_value_t	value;		


  
  if (!pdf || !dict)
    return (NULL);

  value.type       = PDFIO_VALTYPE_DICT;
  value.value.dict = dict;

  return (_pdfioFileCreateObj(pdf, dict->pdf, &value));
}






pdfio_obj_t *				 _pdfioFileCreateObj( pdfio_file_t   *pdf, pdfio_file_t   *srcpdf, _pdfio_value_t *value)



{
  pdfio_obj_t	*obj;			


  
  if (!pdf)
    return (NULL);

  if (pdf->mode != _PDFIO_MODE_WRITE)
    return (NULL);

  
  if ((obj = (pdfio_obj_t *)calloc(1, sizeof(pdfio_obj_t))) == NULL)
  {
    _pdfioFileError(pdf, "Unable to allocate memory for object - %s", strerror(errno));
    return (NULL);
  }

  
  if (pdf->num_objs >= pdf->alloc_objs)
  {
    pdfio_obj_t **temp = (pdfio_obj_t **)realloc(pdf->objs, (pdf->alloc_objs + 32) * sizeof(pdfio_obj_t *));

    if (!temp)
    {
      _pdfioFileError(pdf, "Unable to allocate memory for object - %s", strerror(errno));
      free(obj);
      return (NULL);
    }

    pdf->objs       = temp;
    pdf->alloc_objs += 32;
  }

  pdf->objs[pdf->num_objs ++] = obj;

  
  obj->pdf    = pdf;
  obj->number = pdf->num_objs;

  if (value)
    _pdfioValueCopy(pdf, &obj->value, srcpdf, value);

  
  return (obj);
}


































pdfio_file_t *				 pdfioFileCreateOutput( pdfio_output_cb_t output_cb, void              *output_ctx, const char        *version, pdfio_rect_t      *media_box, pdfio_rect_t      *crop_box, pdfio_error_cb_t  error_cb, void              *error_data)







{
  pdfio_file_t	*pdf;			
  pdfio_dict_t	*dict;			
  pdfio_dict_t	*info_dict;		
  unsigned char	id_value[16];		


  
  if (!output_cb)
    return (NULL);

  if (!version)
    version = "2.0";

  if (!error_cb)
  {
    error_cb   = _pdfioFileDefaultError;
    error_data = NULL;
  }

  
  if ((pdf = (pdfio_file_t *)calloc(1, sizeof(pdfio_file_t))) == NULL)
  {
    pdfio_file_t temp;			
    char	message[8192];		

    temp.filename = (char *)"output.pdf";
    snprintf(message, sizeof(message), "Unable to allocate memory for PDF file - %s", strerror(errno));
    (error_cb)(&temp, message, error_data);
    return (NULL);
  }

  pdf->filename    = strdup("output.pdf");
  pdf->version     = strdup(version);
  pdf->mode        = _PDFIO_MODE_WRITE;
  pdf->error_cb    = error_cb;
  pdf->error_data  = error_data;
  pdf->permissions = PDFIO_PERMISSION_ALL;
  pdf->bufptr      = pdf->buffer;
  pdf->bufend      = pdf->buffer + sizeof(pdf->buffer);

  if (media_box)
  {
    pdf->media_box = *media_box;
  }
  else {
    
    pdf->media_box.x2 = 210.0 * 72.0f / 25.4f;
    pdf->media_box.y2 = 11.0f * 72.0f;
  }

  if (crop_box)
  {
    pdf->crop_box = *crop_box;
  }
  else {
    
    pdf->crop_box.x2 = 210.0 * 72.0f / 25.4f;
    pdf->crop_box.y2 = 11.0f * 72.0f;
  }

  
  pdf->fd         = -1;
  pdf->output_cb  = output_cb;
  pdf->output_ctx = output_ctx;

  
  if (!_pdfioFilePrintf(pdf, "%%PDF-%s\n%%\342\343\317\323\n", version))
    goto error;

  
  if ((dict = pdfioDictCreate(pdf)) == NULL)
    goto error;

  pdfioDictSetName(dict, "Type", "Pages");

  if ((pdf->pages_obj = pdfioFileCreateObj(pdf, dict)) == NULL)
    goto error;

  
  if ((info_dict = pdfioDictCreate(pdf)) == NULL)
    goto error;

  pdfioDictSetDate(info_dict, "CreationDate", time(NULL));
  pdfioDictSetString(info_dict, "Producer", "pdfio/" PDFIO_VERSION);

  if ((pdf->info_obj = pdfioFileCreateObj(pdf, info_dict)) == NULL)
    goto error;

  
  _pdfioCryptoMakeRandom(id_value, sizeof(id_value));

  if ((pdf->id_array = pdfioArrayCreate(pdf)) != NULL)
  {
    pdfioArrayAppendBinary(pdf->id_array, id_value, sizeof(id_value));
    pdfioArrayAppendBinary(pdf->id_array, id_value, sizeof(id_value));
  }

  return (pdf);

  
  error:

  pdfioFileClose(pdf);

  return (NULL);
}






pdfio_stream_t *			 pdfioFileCreatePage(pdfio_file_t *pdf, pdfio_dict_t *dict)

{
  pdfio_obj_t	*page,			 *contents;
  pdfio_dict_t	*contents_dict;		


  
  if (!pdf)
    return (NULL);

  
  if (dict)
    dict = pdfioDictCopy(pdf, dict);
  else dict = pdfioDictCreate(pdf);

  if (!dict)
    return (NULL);

  
  if (!_pdfioDictGetValue(dict, "CropBox"))
    pdfioDictSetRect(dict, "CropBox", &pdf->crop_box);

  if (!_pdfioDictGetValue(dict, "MediaBox"))
    pdfioDictSetRect(dict, "MediaBox", &pdf->media_box);

  pdfioDictSetObj(dict, "Parent", pdf->pages_obj);

  if (!_pdfioDictGetValue(dict, "Resources"))
    pdfioDictSetDict(dict, "Resources", pdfioDictCreate(pdf));

  if (!_pdfioDictGetValue(dict, "Type"))
    pdfioDictSetName(dict, "Type", "Page");

  
  if ((page = pdfioFileCreateObj(pdf, dict)) == NULL)
    return (NULL);

  
  if ((contents_dict = pdfioDictCreate(pdf)) == NULL)
    return (NULL);


  pdfioDictSetName(contents_dict, "Filter", "FlateDecode");


  if ((contents = pdfioFileCreateObj(pdf, contents_dict)) == NULL)
    return (NULL);

  
  pdfioDictSetObj(dict, "Contents", contents);
  if (!pdfioObjClose(page))
    return (NULL);

  if (!_pdfioFileAddPage(pdf, page))
    return (NULL);

  

  return (pdfioObjCreateStream(contents, PDFIO_FILTER_NONE));

  return (pdfioObjCreateStream(contents, PDFIO_FILTER_FLATE));

}













pdfio_file_t * pdfioFileCreateTemporary( char             *buffer, size_t           bufsize, const char       *version, pdfio_rect_t     *media_box, pdfio_rect_t     *crop_box, pdfio_error_cb_t error_cb, void             *error_data)







{
  pdfio_file_t	*pdf;			
  pdfio_dict_t	*dict;			
  pdfio_dict_t	*info_dict;		
  unsigned char	id_value[16];		
  int		i;			
  const char	*tmpdir;		

  char		tmppath[256];		

  unsigned	tmpnum;			


  
  if (!buffer || bufsize < 32)
  {
    if (buffer)
      *buffer = '\0';
    return (NULL);
  }

  if (!version)
    version = "2.0";

  if (!error_cb)
  {
    error_cb   = _pdfioFileDefaultError;
    error_data = NULL;
  }

  
  if ((pdf = (pdfio_file_t *)calloc(1, sizeof(pdfio_file_t))) == NULL)
  {
    pdfio_file_t temp;			
    char	message[8192];		

    temp.filename = (char *)"temporary.pdf";
    snprintf(message, sizeof(message), "Unable to allocate memory for PDF file - %s", strerror(errno));
    (error_cb)(&temp, message, error_data);

    *buffer = '\0';

    return (NULL);
  }

  

  if ((tmpdir = getenv("TEMP")) == NULL)
  {
    GetTempPathA(sizeof(tmppath), tmppath);
    tmpdir = tmppath;
  }


  if ((tmpdir = getenv("TMPDIR")) != NULL && access(tmpdir, W_OK))
    tmpdir = NULL;

  if (!tmpdir)
  {
    

    if (confstr(_CS_DARWIN_USER_TEMP_DIR, tmppath, sizeof(tmppath)))
      tmpdir = tmppath;
    else  tmpdir = "/private/tmp";

  }


  if ((tmpdir = getenv("TMPDIR")) == NULL || access(tmpdir, W_OK))
    tmpdir = "/tmp";


  for (i = 0; i < 1000; i ++)
  {
    _pdfioCryptoMakeRandom((uint8_t *)&tmpnum, sizeof(tmpnum));
    snprintf(buffer, bufsize, "%s/%08x.pdf", tmpdir, tmpnum);
    if ((pdf->fd = open(buffer, O_WRONLY | O_BINARY | O_CREAT | O_TRUNC | O_EXCL, 0666)) >= 0)
      break;
  }

  pdf->filename = strdup(buffer);

  if (i >= 1000)
  {
    _pdfioFileError(pdf, "Unable to create file - %s", strerror(errno));
    free(pdf->filename);
    free(pdf);
    *buffer = '\0';
    return (NULL);
  }

  pdf->version     = strdup(version);
  pdf->mode        = _PDFIO_MODE_WRITE;
  pdf->error_cb    = error_cb;
  pdf->error_data  = error_data;
  pdf->permissions = PDFIO_PERMISSION_ALL;
  pdf->bufptr      = pdf->buffer;
  pdf->bufend      = pdf->buffer + sizeof(pdf->buffer);

  if (media_box)
  {
    pdf->media_box = *media_box;
  }
  else {
    
    pdf->media_box.x2 = 210.0 * 72.0f / 25.4f;
    pdf->media_box.y2 = 11.0f * 72.0f;
  }

  if (crop_box)
  {
    pdf->crop_box = *crop_box;
  }
  else {
    
    pdf->crop_box.x2 = 210.0 * 72.0f / 25.4f;
    pdf->crop_box.y2 = 11.0f * 72.0f;
  }

  
  if (!_pdfioFilePrintf(pdf, "%%PDF-%s\n%%\342\343\317\323\n", version))
    goto error;

  
  if ((dict = pdfioDictCreate(pdf)) == NULL)
    goto error;

  pdfioDictSetName(dict, "Type", "Pages");

  if ((pdf->pages_obj = pdfioFileCreateObj(pdf, dict)) == NULL)
    goto error;

  
  if ((info_dict = pdfioDictCreate(pdf)) == NULL)
    goto error;

  pdfioDictSetDate(info_dict, "CreationDate", time(NULL));
  pdfioDictSetString(info_dict, "Producer", "pdfio/" PDFIO_VERSION);

  if ((pdf->info_obj = pdfioFileCreateObj(pdf, info_dict)) == NULL)
    goto error;

  
  _pdfioCryptoMakeRandom(id_value, sizeof(id_value));

  if ((pdf->id_array = pdfioArrayCreate(pdf)) != NULL)
  {
    pdfioArrayAppendBinary(pdf->id_array, id_value, sizeof(id_value));
    pdfioArrayAppendBinary(pdf->id_array, id_value, sizeof(id_value));
  }

  return (pdf);

  
  error:

  pdfioFileClose(pdf);

  unlink(buffer);
  *buffer = '\0';

  return (NULL);
}






pdfio_obj_t *				 _pdfioFileFindMappedObj( pdfio_file_t *pdf, pdfio_file_t *src_pdf, size_t       src_number)



{
  _pdfio_objmap_t	key,		 *match;


  
  if (pdf->num_objmaps == 0)
    return (NULL);

  
  key.src_pdf    = src_pdf;
  key.src_number = src_number;

  if ((match = (_pdfio_objmap_t *)bsearch(&key, pdf->objmaps, pdf->num_objmaps, sizeof(_pdfio_objmap_t), (int (*)(const void *, const void *))compare_objmaps)) != NULL)
    return (match->obj);
  else return (NULL);
}









pdfio_obj_t *				 pdfioFileFindObj( pdfio_file_t *pdf, size_t       number)


{
  pdfio_obj_t	key,			 *keyptr, **match;



  if (pdf->num_objs > 0)
  {
    key.number = number;
    keyptr     = &key;
    match      = (pdfio_obj_t **)bsearch(&keyptr, pdf->objs, pdf->num_objs, sizeof(pdfio_obj_t *), (int (*)(const void *, const void *))compare_objs);

    return (match ? *match : NULL);
  }

  return (NULL);
}






const char *				 pdfioFileGetAuthor(pdfio_file_t *pdf)
{
  return (get_info_string(pdf, "Author"));
}






time_t					 pdfioFileGetCreationDate( pdfio_file_t *pdf)

{
  return (pdf && pdf->info_obj ? pdfioDictGetDate(pdfioObjGetDict(pdf->info_obj), "CreationDate") : 0);
}






const char *				 pdfioFileGetCreator(pdfio_file_t *pdf)
{
  return (get_info_string(pdf, "Creator"));
}






pdfio_array_t *				 pdfioFileGetID(pdfio_file_t *pdf)
{
  return (pdf ? pdf->id_array : NULL);
}






const char *				 pdfioFileGetKeywords(pdfio_file_t *pdf)
{
  return (get_info_string(pdf, "Keywords"));
}






const char *				 pdfioFileGetName(pdfio_file_t *pdf)
{
  return (pdf ? pdf->filename : NULL);
}






size_t					 pdfioFileGetNumObjs( pdfio_file_t *pdf)

{
  return (pdf ? pdf->num_objs : 0);
}






size_t					 pdfioFileGetNumPages(pdfio_file_t *pdf)
{
  return (pdf ? pdf->num_pages : 0);
}






pdfio_obj_t *				 pdfioFileGetObj(pdfio_file_t *pdf, size_t       n)

{
  if (!pdf || n >= pdf->num_objs)
    return (NULL);
  else return (pdf->objs[n]);
}






pdfio_obj_t *				 pdfioFileGetPage(pdfio_file_t *pdf, size_t       n)

{
  if (!pdf || n >= pdf->num_pages)
    return (NULL);
  else return (pdf->pages[n]);
}









pdfio_permission_t			 pdfioFileGetPermissions( pdfio_file_t       *pdf, pdfio_encryption_t *encryption)


{
  
  if (!pdf)
  {
    if (encryption)
      *encryption = PDFIO_ENCRYPTION_NONE;

    return (PDFIO_PERMISSION_ALL);
  }

  
  if (encryption)
    *encryption = pdf->encryption;

  return (pdf->permissions);
}






const char *				 pdfioFileGetProducer(pdfio_file_t *pdf)
{
  return (get_info_string(pdf, "Producer"));
}






const char *				 pdfioFileGetSubject(pdfio_file_t *pdf)
{
  return (get_info_string(pdf, "Subject"));
}






const char *				 pdfioFileGetTitle(pdfio_file_t *pdf)
{
  return (get_info_string(pdf, "Title"));
}






const char *				 pdfioFileGetVersion( pdfio_file_t *pdf)

{
  return (pdf ? pdf->version : NULL);
}



















pdfio_file_t *				 pdfioFileOpen( const char          *filename, pdfio_password_cb_t password_cb, void                *password_data, pdfio_error_cb_t    error_cb, void                *error_data)





{
  pdfio_file_t	*pdf;			
  char		line[1024],		 *ptr;
  off_t		xref_offset;		


  
  if (!filename)
    return (NULL);

  if (!error_cb)
  {
    error_cb   = _pdfioFileDefaultError;
    error_data = NULL;
  }

  
  if ((pdf = (pdfio_file_t *)calloc(1, sizeof(pdfio_file_t))) == NULL)
  {
    pdfio_file_t temp;			
    char	message[8192];		

    temp.filename = (char *)filename;
    snprintf(message, sizeof(message), "Unable to allocate memory for PDF file - %s", strerror(errno));
    (error_cb)(&temp, message, error_data);
    return (NULL);
  }

  pdf->filename    = strdup(filename);
  pdf->mode        = _PDFIO_MODE_READ;
  pdf->error_cb    = error_cb;
  pdf->error_data  = error_data;
  pdf->permissions = PDFIO_PERMISSION_ALL;

  
  if ((pdf->fd = open(filename, O_RDONLY | O_BINARY)) < 0)
  {
    _pdfioFileError(pdf, "Unable to open file - %s", strerror(errno));
    free(pdf->filename);
    free(pdf);
    return (NULL);
  }

  
  if (!_pdfioFileGets(pdf, line, sizeof(line)))
    goto error;

  if ((strncmp(line, "%PDF-1.", 7) && strncmp(line, "%PDF-2.", 7)) || !isdigit(line[7] & 255))
  {
    
    _pdfioFileError(pdf, "Bad header '%s'.", line);
    goto error;
  }

  
  pdf->version = strdup(line + 5);

  
  if (_pdfioFileSeek(pdf, -32, SEEK_END) < 0)
  {
    _pdfioFileError(pdf, "Unable to read startxref data.");
    goto error;
  }

  if (_pdfioFileRead(pdf, line, 32) < 32)
  {
    _pdfioFileError(pdf, "Unable to read startxref data.");
    goto error;
  }
  line[32] = '\0';

  if ((ptr = strstr(line, "startxref")) == NULL)
  {
    _pdfioFileError(pdf, "Unable to find start of xref table.");
    goto error;
  }

  xref_offset = (off_t)strtol(ptr + 9, NULL, 10);

  if (!load_xref(pdf, xref_offset, password_cb, password_data))
    goto error;

  return (pdf);


  
  error:

  pdfioFileClose(pdf);

  return (NULL);
}






void pdfioFileSetAuthor(pdfio_file_t *pdf, const char   *value)

{
  if (pdf && pdf->info_obj)
    pdfioDictSetString(pdf->info_obj->value.value.dict, "Author", pdfioStringCreate(pdf, value));
}






void pdfioFileSetCreationDate( pdfio_file_t *pdf, time_t       value)


{
  if (pdf && pdf->info_obj)
    pdfioDictSetDate(pdf->info_obj->value.value.dict, "CreationDate", value);
}






void pdfioFileSetCreator(pdfio_file_t *pdf, const char   *value)

{
  if (pdf && pdf->info_obj)
    pdfioDictSetString(pdf->info_obj->value.value.dict, "Creator", pdfioStringCreate(pdf, value));
}






void pdfioFileSetKeywords( pdfio_file_t *pdf, const char   *value)


{
  if (pdf && pdf->info_obj)
    pdfioDictSetString(pdf->info_obj->value.value.dict, "Keywords", pdfioStringCreate(pdf, value));
}














bool					 pdfioFileSetPermissions( pdfio_file_t       *pdf, pdfio_permission_t permissions, pdfio_encryption_t encryption, const char         *owner_password, const char         *user_password)





{
  if (!pdf)
    return (false);

  if (pdf->num_objs > 2)		
  {
    _pdfioFileError(pdf, "You must call pdfioFileSetPermissions before adding any objects.");
    return (false);
  }

  if (encryption == PDFIO_ENCRYPTION_NONE)
    return (true);

  return (_pdfioCryptoLock(pdf, permissions, encryption, owner_password, user_password));
}






void pdfioFileSetSubject( pdfio_file_t *pdf, const char   *value)


{
  if (pdf && pdf->info_obj)
    pdfioDictSetString(pdf->info_obj->value.value.dict, "Subject", pdfioStringCreate(pdf, value));
}






void pdfioFileSetTitle(pdfio_file_t *pdf, const char   *value)

{
  if (pdf && pdf->info_obj)
    pdfioDictSetString(pdf->info_obj->value.value.dict, "Title", pdfioStringCreate(pdf, value));
}






static pdfio_obj_t *			 add_obj(pdfio_file_t   *pdf, size_t         number, unsigned short generation, off_t          offset)



{
  pdfio_obj_t	*obj;			


  
  if ((obj = (pdfio_obj_t *)calloc(1, sizeof(pdfio_obj_t))) == NULL)
  {
    _pdfioFileError(pdf, "Unable to allocate memory for object - %s", strerror(errno));
    return (NULL);
  }

  
  if (pdf->num_objs >= pdf->alloc_objs)
  {
    pdfio_obj_t **temp = (pdfio_obj_t **)realloc(pdf->objs, (pdf->alloc_objs + 32) * sizeof(pdfio_obj_t *));

    if (!temp)
    {
      _pdfioFileError(pdf, "Unable to allocate memory for object - %s", strerror(errno));
      free(obj);
      return (NULL);
    }

    pdf->objs       = temp;
    pdf->alloc_objs += 32;
  }

  pdf->objs[pdf->num_objs ++] = obj;

  obj->pdf        = pdf;
  obj->number     = number;
  obj->generation = generation;
  obj->offset     = offset;

  PDFIO_DEBUG("add_obj: obj=%p, ->pdf=%p, ->number=%lu\n", obj, pdf, (unsigned long)obj->number);

  
  if (pdf->num_objs > 1 && pdf->objs[pdf->num_objs - 2]->number > number)
    qsort(pdf->objs, pdf->num_objs, sizeof(pdfio_obj_t *), (int (*)(const void *, const void *))compare_objs);

  return (obj);
}






static int				 compare_objmaps(_pdfio_objmap_t *a, _pdfio_objmap_t *b)

{
  if (a->src_pdf < b->src_pdf)
    return (-1);
  else if (a->src_pdf > b->src_pdf)
    return (1);
  else if (a->src_number < b->src_number)
    return (-1);
  else if (a->src_number > b->src_number)
    return (1);
  else return (0);
}






static int				 compare_objs(pdfio_obj_t **a, pdfio_obj_t **b)

{
  if ((*a)->number < (*b)->number)
    return (-1);
  else if ((*a)->number == (*b)->number)
    return (0);
  else return (1);
}









static const char *			 get_info_string(pdfio_file_t *pdf, const char   *key)

{
  pdfio_dict_t	*dict;			
  _pdfio_value_t *value;		

  
  if (!pdf || !pdf->info_obj || (dict = pdfioObjGetDict(pdf->info_obj)) == NULL || (value = _pdfioDictGetValue(dict, key)) == NULL)
    return (NULL);

  
  if (value->type == PDFIO_VALTYPE_NAME || value->type == PDFIO_VALTYPE_STRING)
  {
    return (value->value.string);
  }
  else if (value->type == PDFIO_VALTYPE_BINARY && value->value.binary.datalen < 4096)
  {
    
    char	temp[4096];		

    memcpy(temp, value->value.binary.data, value->value.binary.datalen);
    temp[value->value.binary.datalen] = '\0';

    free(value->value.binary.data);
    value->type         = PDFIO_VALTYPE_STRING;
    value->value.string = pdfioStringCreate(pdf, temp);

    return (value->value.string);
  }
  else {
    
    return (NULL);
  }
}
















static bool				 load_obj_stream(pdfio_obj_t *obj)
{
  pdfio_stream_t	*st;		
  _pdfio_token_t	tb;		
  char			buffer[32];	
  size_t		number,		 cur_obj, num_objs = 0;

  pdfio_obj_t		*objs[16384];	


  PDFIO_DEBUG("load_obj_stream(obj=%p(%d))\n", obj, (int)obj->number);

  
  if ((st = pdfioObjOpenStream(obj, true)) == NULL)
  {
    _pdfioFileError(obj->pdf, "Unable to open compressed object stream %lu.", (unsigned long)obj->number);
    return (false);
  }

  _pdfioTokenInit(&tb, obj->pdf, (_pdfio_tconsume_cb_t)pdfioStreamConsume, (_pdfio_tpeek_cb_t)pdfioStreamPeek, st);

  
  while (_pdfioTokenGet(&tb, buffer, sizeof(buffer)))
  {
    
    if (!isdigit(buffer[0] & 255))
      break;

    
    if (num_objs >= (sizeof(objs) / sizeof(objs[0])))
    {
      _pdfioFileError(obj->pdf, "Too many compressed objects in one stream.");
      pdfioStreamClose(st);
      return (false);
    }

    
    number = (size_t)strtoimax(buffer, NULL, 10);

    if ((objs[num_objs] = pdfioFileFindObj(obj->pdf, number)) == NULL)
      objs[num_objs] = add_obj(obj->pdf, number, 0, 0);

    num_objs ++;

    
    _pdfioTokenGet(&tb, buffer, sizeof(buffer));
  }

  if (!buffer[0])
  {
    pdfioStreamClose(st);
    return (false);
  }

  _pdfioTokenPush(&tb, buffer);

  
  for (cur_obj = 0; cur_obj < num_objs; cur_obj ++)
  {
    if (!_pdfioValueRead(obj->pdf, obj, &tb, &(objs[cur_obj]->value), 0))
    {
      pdfioStreamClose(st);
      return (false);
    }
  }

  
  pdfioStreamClose(st);

  return (true);
}






static bool				 load_pages(pdfio_file_t *pdf, pdfio_obj_t  *obj, size_t       depth)


{
  pdfio_dict_t	*dict;			
  const char	*type;			
  pdfio_array_t	*kids;			


  
  if (!obj)
  {
    _pdfioFileError(pdf, "Unable to find pages object.");
    return (false);
  }

  
  if ((dict = pdfioObjGetDict(obj)) == NULL)
  {
    _pdfioFileError(pdf, "No dictionary for pages object.");
    return (false);
  }

  if ((type = pdfioDictGetName(dict, "Type")) == NULL || (strcmp(type, "Pages") && strcmp(type, "Page")))
    return (false);

  
  
  if ((kids = pdfioDictGetArray(dict, "Kids")) != NULL)
  {
    
    size_t	i,			 num_kids;

    if (depth >= PDFIO_MAX_DEPTH)
    {
      _pdfioFileError(pdf, "Depth of pages objects too great to load.");
      return (false);
    }

    for (i = 0, num_kids = pdfioArrayGetSize(kids); i < num_kids; i ++)
    {
      if (!load_pages(pdf, pdfioArrayGetObj(kids, i), depth + 1))
        return (false);
    }
  }
  else {
    
    if (pdf->num_pages >= pdf->alloc_pages)
    {
      pdfio_obj_t **temp = (pdfio_obj_t **)realloc(pdf->pages, (pdf->alloc_pages + 32) * sizeof(pdfio_obj_t *));

      if (!temp)
      {
        _pdfioFileError(pdf, "Unable to allocate memory for pages.");
        return (false);
      }

      pdf->alloc_pages += 32;
      pdf->pages       = temp;
    }

    pdf->pages[pdf->num_pages ++] = obj;
  }

  return (true);
}






static bool				 load_xref( pdfio_file_t        *pdf, off_t               xref_offset, pdfio_password_cb_t password_cb, void                *password_data)




{
  bool		done = false;		
  char		line[1024],		 *ptr;
  _pdfio_value_t trailer;		
  intmax_t	number,			 num_objects, offset;

  int		generation;		
  _pdfio_token_t tb;			
  off_t		line_offset;		


  while (!done)
  {
    if (_pdfioFileSeek(pdf, xref_offset, SEEK_SET) != xref_offset)
    {
      _pdfioFileError(pdf, "Unable to seek to start of xref table.");
      return (false);
    }

    do {
      line_offset = _pdfioFileTell(pdf);

      if (!_pdfioFileGets(pdf, line, sizeof(line)))
      {
	_pdfioFileError(pdf, "Unable to read start of xref table.");
	return (false);
      }
    }
    while (!line[0]);

    PDFIO_DEBUG("load_xref: line_offset=%lu, line='%s'\n", (unsigned long)line_offset, line);

    if (isdigit(line[0] & 255) && strlen(line) > 4 && (!strcmp(line + strlen(line) - 4, " obj") || ((ptr = strstr(line, " obj")) != NULL && ptr[4] == '<')))
    {
      
      pdfio_obj_t	*obj;		
      size_t		i;		
      pdfio_array_t	*index_array;	
      size_t		index_n,	 index_count, count;

      pdfio_array_t	*w_array;	
      size_t		w[3];		
      size_t		w_2,		 w_3;
      size_t		w_total;	
      pdfio_stream_t	*st;		
      unsigned char	buffer[32];	
      size_t		num_sobjs = 0,	 sobjs[4096];
      pdfio_obj_t	*current;	

      if ((number = strtoimax(line, &ptr, 10)) < 1)
      {
	_pdfioFileError(pdf, "Bad xref table header '%s'.", line);
	return (false);
      }

      if ((generation = (int)strtol(ptr, &ptr, 10)) < 0 || generation > 65535)
      {
	_pdfioFileError(pdf, "Bad xref table header '%s'.", line);
	return (false);
      }

      while (isspace(*ptr & 255))
	ptr ++;

      if (strncmp(ptr, "obj", 3))
      {
	_pdfioFileError(pdf, "Bad xref table header '%s'.", line);
	return (false);
      }

      if (_pdfioFileSeek(pdf, line_offset + ptr + 3 - line, SEEK_SET) < 0)
      {
        _pdfioFileError(pdf, "Unable to seek to xref object %lu %u.", (unsigned long)number, (unsigned)generation);
        return (false);
      }

      PDFIO_DEBUG("load_xref: Loading object %lu %u.\n", (unsigned long)number, (unsigned)generation);

      if ((obj = add_obj(pdf, (size_t)number, (unsigned short)generation, xref_offset)) == NULL)
      {
        _pdfioFileError(pdf, "Unable to allocate memory for object.");
        return (false);
      }

      _pdfioTokenInit(&tb, pdf, (_pdfio_tconsume_cb_t)_pdfioFileConsume, (_pdfio_tpeek_cb_t)_pdfioFilePeek, pdf);

      if (!_pdfioValueRead(pdf, obj, &tb, &trailer, 0))
      {
        _pdfioFileError(pdf, "Unable to read cross-reference stream dictionary.");
        return (false);
      }
      else if (trailer.type != PDFIO_VALTYPE_DICT)
      {
	_pdfioFileError(pdf, "Cross-reference stream does not have a dictionary.");
	return (false);
      }

      obj->value = trailer;

      if (!_pdfioTokenGet(&tb, line, sizeof(line)) || strcmp(line, "stream"))
      {
        _pdfioFileError(pdf, "Unable to get stream after xref dictionary.");
        return (false);
      }

      _pdfioTokenFlush(&tb);

      obj->stream_offset = _pdfioFileTell(pdf);

      if ((index_array = pdfioDictGetArray(trailer.value.dict, "Index")) != NULL)
        index_count = index_array->num_values;
      else index_count = 1;

      if ((w_array = pdfioDictGetArray(trailer.value.dict, "W")) == NULL)
      {
	_pdfioFileError(pdf, "Cross-reference stream does not have required W key.");
	return (false);
      }

      w[0]    = (size_t)pdfioArrayGetNumber(w_array, 0);
      w[1]    = (size_t)pdfioArrayGetNumber(w_array, 1);
      w[2]    = (size_t)pdfioArrayGetNumber(w_array, 2);
      w_total = w[0] + w[1] + w[2];
      w_2     = w[0];
      w_3     = w[0] + w[1];

      if (w[1] == 0 || w[2] > 2 || w[0] > sizeof(buffer) || w[1] > sizeof(buffer) || w[2] > sizeof(buffer) || w_total > sizeof(buffer))
      {
	_pdfioFileError(pdf, "Cross-reference stream has invalid W key.");
	return (false);
      }

      if ((st = pdfioObjOpenStream(obj, true)) == NULL)
      {
	_pdfioFileError(pdf, "Unable to open cross-reference stream.");
	return (false);
      }

      for (index_n = 0; index_n < index_count; index_n += 2)
      {
        if (index_count == 1)
        {
          number = 0;
          count  = 999999999;
	}
	else {
          number = (intmax_t)pdfioArrayGetNumber(index_array, index_n);
          count  = (size_t)pdfioArrayGetNumber(index_array, index_n + 1);
	}

	while (count > 0 && pdfioStreamRead(st, buffer, w_total) > 0)
	{
	  count --;

	  PDFIO_DEBUG("load_xref: number=%u %02X%02X%02X%02X%02X\n", (unsigned)number, buffer[0], buffer[1], buffer[2], buffer[3], buffer[4]);

	  
	  if (w[0] > 0)
	  {
	    if (buffer[0] == 0)
	    {
	      
	      number ++;
	      continue;
	    }
	  }

	  for (i = 1, offset = buffer[w_2]; i < w[1]; i ++)
	    offset = (offset << 8) | buffer[w_2 + i];

	  switch (w[2])
	  {
	    default :
		generation = 0;
		break;
	    case 1 :
		generation = buffer[w_3];
		break;
	    case 2 :
		generation = (buffer[w_3] << 8) | buffer[w_3 + 1];
		break;
	  }

	  
	  if ((current = pdfioFileFindObj(pdf, (size_t)number)) != NULL)
	  {
	    PDFIO_DEBUG("load_xref: existing object, prev offset=%u\n", (unsigned)current->offset);

            if (w[0] == 0 || buffer[0] == 1)
            {
              
	      current->offset = offset;
	    }
	    else if (number != offset)
	    {
	      
	      current->offset = 0;
	    }

	    PDFIO_DEBUG("load_xref: new offset=%u\n", (unsigned)current->offset);
	  }

	  if (w[0] > 0 && buffer[0] == 2)
	  {
	    
	    
	    for (i = 0; i < num_sobjs; i ++)
	    {
	      if (sobjs[i] == (size_t)offset)
		break;
	    }

	    if (i >= num_sobjs && num_sobjs < (sizeof(sobjs) / sizeof(sobjs[0])))
	      sobjs[num_sobjs ++] = (size_t)offset;
	  }
	  else if (!current)
	  {
	    
	    if (!add_obj(pdf, (size_t)number, (unsigned short)generation, offset))
	      return (false);
	  }

	  number ++;
	}
      }

      pdfioStreamClose(st);

      if (!pdf->trailer_dict)
      {
	
	
	pdf->trailer_dict = trailer.value.dict;
	pdf->info_obj     = pdfioDictGetObj(pdf->trailer_dict, "Info");
	pdf->encrypt_obj  = pdfioDictGetObj(pdf->trailer_dict, "Encrypt");
	pdf->id_array     = pdfioDictGetArray(pdf->trailer_dict, "ID");

	
	if (pdf->encrypt_obj && !_pdfioCryptoUnlock(pdf, password_cb, password_data))
	  return (false);
      }

      
      PDFIO_DEBUG("load_xref: %lu compressed object streams to load.\n", (unsigned long)num_sobjs);

      for (i = 0; i < num_sobjs; i ++)
      {
        if ((obj = pdfioFileFindObj(pdf, sobjs[i])) != NULL)
        {
	  PDFIO_DEBUG("load_xref: Loading compressed object stream %lu (pdf=%p, obj->pdf=%p).\n", (unsigned long)sobjs[i], pdf, obj->pdf);

          if (!load_obj_stream(obj))
            return (false);
	}
	else {
	  _pdfioFileError(pdf, "Unable to find compressed object stream %lu.", (unsigned long)sobjs[i]);
	  return (false);
	}
      }
    }
    else if (!strcmp(line, "xref"))
    {
      
      while (_pdfioFileGets(pdf, line, sizeof(line)))
      {
	if (!strcmp(line, "trailer"))
	  break;
	else if (!line[0])
	  continue;

	if (sscanf(line, "%jd%jd", &number, &num_objects) != 2)
	{
	  _pdfioFileError(pdf, "Malformed xref table section '%s'.", line);
	  return (false);
	}

	
	for (; num_objects > 0; num_objects --, number ++)
	{
	  
	  if (_pdfioFileRead(pdf, line, 20) != 20)
	    return (false);

	  line[20] = '\0';

	  if (strcmp(line + 18, "\r\n") && strcmp(line + 18, " \n") && strcmp(line + 18, " \r"))
	  {
	    _pdfioFileError(pdf, "Malformed xref table entry '%s'.", line);
	    return (false);
	  }
	  line[18] = '\0';

	  
	  if ((offset = strtoimax(line, &ptr, 10)) < 0)
	  {
	    _pdfioFileError(pdf, "Malformed xref table entry '%s'.", line);
	    return (false);
	  }

	  if ((generation = (int)strtol(ptr, &ptr, 10)) < 0 || generation > 65535)
	  {
	    _pdfioFileError(pdf, "Malformed xref table entry '%s'.", line);
	    return (false);
	  }

	  if (*ptr != ' ')
	  {
	    _pdfioFileError(pdf, "Malformed xref table entry '%s'.", line);
	    return (false);
	  }

	  ptr ++;
	  if (*ptr != 'f' && *ptr != 'n')
	  {
	    _pdfioFileError(pdf, "Malformed xref table entry '%s'.", line);
	    return (false);
	  }

	  if (*ptr == 'f')
	    continue;			

	  
	  if (pdfioFileFindObj(pdf, (size_t)number))
	    continue;			

	  if (!add_obj(pdf, (size_t)number, (unsigned short)generation, offset))
	    return (false);
	}
      }

      if (strcmp(line, "trailer"))
      {
	_pdfioFileError(pdf, "Missing trailer.");
	return (false);
      }

      _pdfioTokenInit(&tb, pdf, (_pdfio_tconsume_cb_t)_pdfioFileConsume, (_pdfio_tpeek_cb_t)_pdfioFilePeek, pdf);

      if (!_pdfioValueRead(pdf, NULL, &tb, &trailer, 0))
      {
	_pdfioFileError(pdf, "Unable to read trailer dictionary.");
	return (false);
      }
      else if (trailer.type != PDFIO_VALTYPE_DICT)
      {
	_pdfioFileError(pdf, "Trailer is not a dictionary.");
	return (false);
      }

      _pdfioTokenFlush(&tb);

      if (!pdf->trailer_dict)
      {
	
	
	pdf->trailer_dict = trailer.value.dict;
	pdf->info_obj     = pdfioDictGetObj(pdf->trailer_dict, "Info");
	pdf->encrypt_obj  = pdfioDictGetObj(pdf->trailer_dict, "Encrypt");
	pdf->id_array     = pdfioDictGetArray(pdf->trailer_dict, "ID");

	
	if (pdf->encrypt_obj && !_pdfioCryptoUnlock(pdf, password_cb, password_data))
	  return (false);
      }
    }
    else {
      _pdfioFileError(pdf, "Bad xref table header '%s'.", line);
      return (false);
    }

    PDFIO_DEBUG("load_xref: Contents of trailer dictionary:\n");
    PDFIO_DEBUG("load_xref: ");
    PDFIO_DEBUG_VALUE(&trailer);
    PDFIO_DEBUG("\n");

    if ((xref_offset = (off_t)pdfioDictGetNumber(trailer.value.dict, "Prev")) <= 0)
      done = true;
  }

  
  
  if ((pdf->root_obj = pdfioDictGetObj(pdf->trailer_dict, "Root")) == NULL)
  {
    _pdfioFileError(pdf, "Missing Root object.");
    return (false);
  }

  PDFIO_DEBUG("load_xref: Root=%p(%lu)\n", pdf->root_obj, (unsigned long)pdf->root_obj->number);

  return (load_pages(pdf, pdfioDictGetObj(pdfioObjGetDict(pdf->root_obj), "Pages"), 0));
}






static bool				 write_catalog(pdfio_file_t *pdf)
{
  pdfio_dict_t	*dict;			


  if ((dict = pdfioDictCreate(pdf)) == NULL)
    return (false);

  pdfioDictSetName(dict, "Type", "Catalog");
  pdfioDictSetObj(dict, "Pages", pdf->pages_obj);
  

  if ((pdf->root_obj = pdfioFileCreateObj(pdf, dict)) == NULL)
    return (false);
  else return (pdfioObjClose(pdf->root_obj));
}






static bool				 write_pages(pdfio_file_t *pdf)
{
  pdfio_array_t	*kids;			
  size_t	i;			


  
  if ((kids = pdfioArrayCreate(pdf)) == NULL)
    return (false);

  for (i = 0; i < pdf->num_pages; i ++)
    pdfioArrayAppendObj(kids, pdf->pages[i]);

  pdfioDictSetNumber(pdf->pages_obj->value.value.dict, "Count", pdf->num_pages);
  pdfioDictSetArray(pdf->pages_obj->value.value.dict, "Kids", kids);

  
  return (pdfioObjClose(pdf->pages_obj));
}






static bool				 write_trailer(pdfio_file_t *pdf)
{
  bool		ret = true;		
  off_t		xref_offset;		
  size_t	i;			


  
  
  xref_offset = _pdfioFileTell(pdf);

  if (!_pdfioFilePrintf(pdf, "xref\n0 %lu \n0000000000 65535 f \n", (unsigned long)pdf->num_objs + 1))
  {
    _pdfioFileError(pdf, "Unable to write cross-reference table.");
    ret = false;
    goto done;
  }

  for (i = 0; i < pdf->num_objs; i ++)
  {
    pdfio_obj_t	*obj = pdf->objs[i];	

    if (!_pdfioFilePrintf(pdf, "%010lu %05u n \n", (unsigned long)obj->offset, obj->generation))
    {
      _pdfioFileError(pdf, "Unable to write cross-reference table.");
      ret = false;
      goto done;
    }
  }

  
  if (!_pdfioFilePuts(pdf, "trailer\n"))
  {
    _pdfioFileError(pdf, "Unable to write trailer.");
    ret = false;
    goto done;
  }

  if ((pdf->trailer_dict = pdfioDictCreate(pdf)) == NULL)
  {
    _pdfioFileError(pdf, "Unable to create trailer.");
    ret = false;
    goto done;
  }

  if (pdf->encrypt_obj)
    pdfioDictSetObj(pdf->trailer_dict, "Encrypt", pdf->encrypt_obj);
  if (pdf->id_array)
    pdfioDictSetArray(pdf->trailer_dict, "ID", pdf->id_array);
  pdfioDictSetObj(pdf->trailer_dict, "Info", pdf->info_obj);
  pdfioDictSetObj(pdf->trailer_dict, "Root", pdf->root_obj);
  pdfioDictSetNumber(pdf->trailer_dict, "Size", pdf->num_objs + 1);

  if (!_pdfioDictWrite(pdf->trailer_dict, NULL, NULL))
  {
    _pdfioFileError(pdf, "Unable to write trailer.");
    ret = false;
    goto done;
  }

  if (!_pdfioFilePrintf(pdf, "\nstartxref\n%lu\n%%EOF\n", (unsigned long)xref_offset))
  {
    _pdfioFileError(pdf, "Unable to write xref offset.");
    ret = false;
  }

  done:

  return (ret);
}
