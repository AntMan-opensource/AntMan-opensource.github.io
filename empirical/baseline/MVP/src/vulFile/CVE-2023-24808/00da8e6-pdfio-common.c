



















static bool	fill_buffer(pdfio_file_t *pdf);
static ssize_t	read_buffer(pdfio_file_t *pdf, char *buffer, size_t bytes);
static bool	write_buffer(pdfio_file_t *pdf, const void *buffer, size_t bytes);






bool					 _pdfioFileConsume(pdfio_file_t *pdf, size_t       bytes)

{
  PDFIO_DEBUG("_pdfioFileConsume(pdf=%p, bytes=%u)\n", pdf, (unsigned)bytes);

  if ((size_t)(pdf->bufend - pdf->bufptr) > bytes)
    pdf->bufptr += bytes;
  else if (_pdfioFileSeek(pdf, (off_t)bytes, SEEK_CUR) < 0)
    return (false);

  return (true);
}









bool					 _pdfioFileDefaultError( pdfio_file_t *pdf, const char   *message, void         *data)



{
  (void)data;

  fprintf(stderr, "%s: %s\n", pdf->filename, message);

  return (false);
}






bool					 _pdfioFileError(pdfio_file_t *pdf, const char   *format, ...)


{
  char		buffer[8192];		
  va_list	ap;			


  va_start(ap, format);
  vsnprintf(buffer, sizeof(buffer), format, ap);
  va_end(ap);

  PDFIO_DEBUG("_pdfioFileError: %s\n", buffer);

  return ((pdf->error_cb)(pdf, buffer, pdf->error_data));
}






bool					 _pdfioFileFlush(pdfio_file_t *pdf)
{
  PDFIO_DEBUG("_pdfioFileFlush(pdf=%p)\n", pdf);

  if (pdf->bufptr > pdf->buffer)
  {
    if (!write_buffer(pdf, pdf->buffer, (size_t)(pdf->bufptr - pdf->buffer)))
      return (false);

    pdf->bufpos += pdf->bufptr - pdf->buffer;
  }

  pdf->bufptr = pdf->buffer;

  return (true);
}






int					 _pdfioFileGetChar(pdfio_file_t *pdf)
{
  
  if (pdf->bufptr < pdf->bufend)
    return (*(pdf->bufptr ++));

  
  if (!fill_buffer(pdf))
    return (-1);

  
  return (*(pdf->bufptr ++));
}






bool					 _pdfioFileGets(pdfio_file_t *pdf, char         *buffer, size_t       bufsize)


{
  bool	eol = false;			
  char	*bufptr = buffer,		 *bufend = buffer + bufsize - 1;


  PDFIO_DEBUG("_pdfioFileGets(pdf=%p, buffer=%p, bufsize=%lu) bufpos=%ld, buffer=%p, bufptr=%p, bufend=%p\n", pdf, buffer, (unsigned long)bufsize, (long)pdf->bufpos, pdf->buffer, pdf->bufptr, pdf->bufend);

  while (!eol)
  {
    
    while (!eol && pdf->bufptr < pdf->bufend && bufptr < bufend)
    {
      char ch = *(pdf->bufptr++);	

      if (ch == '\n' || ch == '\r')
      {
        
        eol = true;

        if (ch == '\r')
        {
          
          if (pdf->bufptr >= pdf->bufend)
          {
            if (!fill_buffer(pdf))
              break;
	  }

	  if (pdf->bufptr < pdf->bufend && *(pdf->bufptr) == '\n')
	    pdf->bufptr ++;
	}
      }
      else *bufptr++ = ch;
    }

    
    if (!eol)
    {
      if (!fill_buffer(pdf))
        break;
    }
  }

  *bufptr = '\0';

  PDFIO_DEBUG("_pdfioFileGets: Returning %s, '%s'\n", eol ? "true" : "false", buffer);

  return (eol);
}






ssize_t					 _pdfioFilePeek(pdfio_file_t *pdf, void         *buffer, size_t       bytes)


{
  ssize_t	total;			


  
  if (pdf->bufptr >= pdf->bufend)
  {
    
    if (!fill_buffer(pdf))
      return (-1);
  }

  if ((total = pdf->bufend - pdf->bufptr) < (ssize_t)bytes && total < (ssize_t)(sizeof(pdf->buffer) / 2))
  {
    
    ssize_t	rbytes;			

    PDFIO_DEBUG("_pdfioFilePeek: Sliding buffer, total=%ld\n", (long)total);

    memmove(pdf->buffer, pdf->bufptr, total);
    pdf->bufpos += pdf->bufptr - pdf->buffer;
    pdf->bufptr = pdf->buffer;
    pdf->bufend = pdf->buffer + total;

    
    while ((rbytes = read(pdf->fd, pdf->bufend, sizeof(pdf->buffer) - (size_t)total)) < 0)
    {
      if (errno != EINTR && errno != EAGAIN)
	break;
    }

    if (rbytes > 0)
    {
      
      pdf->bufend += rbytes;
      total       += rbytes;
    }
  }

  
  if (total > (ssize_t)bytes)
    total = (ssize_t)bytes;

  if (total > 0)
    memcpy(buffer, pdf->bufptr, total);

  return (total);
}






bool					 _pdfioFilePrintf(pdfio_file_t *pdf, const char   *format, ...)


{
  char		buffer[8102];		
  va_list	ap;			


  
  va_start(ap, format);
  vsnprintf(buffer, sizeof(buffer), format, ap);
  va_end(ap);

  
  return (_pdfioFileWrite(pdf, buffer, strlen(buffer)));
}






bool					 _pdfioFilePuts(pdfio_file_t *pdf, const char   *s)

{
  
  return (_pdfioFileWrite(pdf, s, strlen(s)));
}






ssize_t					 _pdfioFileRead(pdfio_file_t *pdf, void         *buffer, size_t       bytes)


{
  char		*bufptr = (char *)buffer;
					
  ssize_t	total,			 rbytes;


  
  for (total = 0; bytes > 0; total += rbytes, bytes -= (size_t)rbytes, bufptr += rbytes)
  {
    
    if ((rbytes = pdf->bufend - pdf->bufptr) > 0)
    {
      if ((size_t)rbytes > bytes)
        rbytes = (ssize_t)bytes;

      memcpy(bufptr, pdf->bufptr, rbytes);
      pdf->bufptr += rbytes;
      continue;
    }

    
    if (bytes > 1024)
    {
      
      if (pdf->bufend)
      {
	pdf->bufpos += pdf->bufend - pdf->buffer;
	pdf->bufptr = pdf->bufend = NULL;
      }

      
      if ((rbytes = read_buffer(pdf, bufptr, bytes)) > 0)
      {
	pdf->bufpos += rbytes;
	continue;
      }
      else if (rbytes < 0 && (errno == EINTR || errno == EAGAIN))
      {
        rbytes = 0;
        continue;
      }
      else break;
    }
    else {
      
      if (!fill_buffer(pdf))
	break;
    }
  }

  return (total);
}






off_t					 _pdfioFileSeek(pdfio_file_t *pdf, off_t        offset, int          whence)


{
  PDFIO_DEBUG("_pdfioFileSeek(pdf=%p, offset=%ld, whence=%d)\n", pdf, (long)offset, whence);

  
  if (whence == SEEK_CUR)
  {
    offset += pdf->bufpos;
    whence = SEEK_SET;
  }

  if (pdf->mode == _PDFIO_MODE_READ)
  {
    
    if (whence != SEEK_END && offset >= pdf->bufpos && offset < (pdf->bufpos + pdf->bufend - pdf->buffer))
    {
      
      pdf->bufptr = pdf->buffer + offset - pdf->bufpos;
      PDFIO_DEBUG("_pdfioFileSeek: Seek within buffer, bufpos=%ld.\n", (long)pdf->bufpos);
      PDFIO_DEBUG("_pdfioFileSeek: buffer=%p, bufptr=%p, bufend=%p\n", pdf->buffer, pdf->bufptr, pdf->bufend);
      return (offset);
    }

    
    pdf->bufptr = pdf->bufend = NULL;
  }
  else if (pdf->output_cb)
  {
    _pdfioFileError(pdf, "Unable to seek within output stream.");
    return (-1);
  }
  else {
    
    if (pdf->bufptr > pdf->buffer)
    {
      if (!write_buffer(pdf, pdf->buffer, (size_t)(pdf->bufptr - pdf->buffer)))
	return (-1);
    }

    pdf->bufptr = pdf->buffer;
  }

  
  if ((offset = lseek(pdf->fd, offset, whence)) < 0)
  {
    _pdfioFileError(pdf, "Unable to seek within file - %s", strerror(errno));
    return (-1);
  }

  PDFIO_DEBUG("_pdfioFileSeek: Reset bufpos=%ld.\n", (long)pdf->bufpos);
  PDFIO_DEBUG("_pdfioFileSeek: buffer=%p, bufptr=%p, bufend=%p\n", pdf->buffer, pdf->bufptr, pdf->bufend);

  pdf->bufpos = offset;

  return (offset);
}






off_t					 _pdfioFileTell(pdfio_file_t *pdf)
{
  if (pdf->bufptr)
    return (pdf->bufpos + (pdf->bufptr - pdf->buffer));
  else return (pdf->bufpos);
}






bool					 _pdfioFileWrite(pdfio_file_t *pdf, const void   *buffer, size_t       bytes)


{
  
  if (bytes > (size_t)(pdf->bufend - pdf->bufptr))
  {
    
    if (!_pdfioFileFlush(pdf))
      return (false);

    if (bytes >= sizeof(pdf->buffer))
    {
      
      if (!write_buffer(pdf, buffer, bytes))
        return (false);

      pdf->bufpos += bytes;

      return (true);
    }
  }

  
  memcpy(pdf->bufptr, buffer, bytes);
  pdf->bufptr += bytes;

  return (true);
}






static bool				 fill_buffer(pdfio_file_t *pdf)
{
  ssize_t	bytes;			


  
  if (pdf->bufend)
    pdf->bufpos += pdf->bufend - pdf->buffer;

  
  if ((bytes = read_buffer(pdf, pdf->buffer, sizeof(pdf->buffer))) <= 0)
  {
    
    pdf->bufptr = pdf->bufend = NULL;
    return (false);
  }
  else {
    
    pdf->bufptr = pdf->buffer;
    pdf->bufend = pdf->buffer + bytes;
    return (true);
  }
}






static ssize_t				 read_buffer(pdfio_file_t *pdf, char         *buffer, size_t       bytes)


{
  ssize_t	rbytes;			


  
  while ((rbytes = read(pdf->fd, buffer, bytes)) < 0)
  {
    
    if (errno != EINTR && errno != EAGAIN)
      break;
  }

  if (rbytes < 0)
  {
    
    _pdfioFileError(pdf, "Unable to read from file - %s", strerror(errno));
  }

  return (rbytes);
}

  




static bool				 write_buffer(pdfio_file_t *pdf, const void   *buffer, size_t       bytes)


{
  const char	*bufptr = (const char *)buffer;
					
  ssize_t	wbytes;			


  if (pdf->output_cb)
  {
    
    if ((pdf->output_cb)(pdf->output_ctx, buffer, bytes) < 0)
    {
      _pdfioFileError(pdf, "Unable to write to output callback.");
      return (false);
    }
  }
  else {
    
    while (bytes > 0)
    {
      while ((wbytes = write(pdf->fd, bufptr, bytes)) < 0)
      {
	
	if (errno != EINTR && errno != EAGAIN)
	  break;
      }

      if (wbytes < 0)
      {
	
	_pdfioFileError(pdf, "Unable to write to file - %s", strerror(errno));
	return (false);
      }

      bufptr += wbytes;
      bytes  -= (size_t)wbytes;
    }
  }

  return (true);
}
