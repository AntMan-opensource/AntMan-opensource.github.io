

































static int		job_canceled = 0; 






static int		call_backend(char *uri, int argc, char **argv, char *tempfile);
static void		sigterm_handler(int sig);






int					 main(int  argc, char *argv[])

{
  char *uri, *ptr, *filename;
  char tmpfilename[1024], buf[8192];
  int dd, att, delay, retval;

  struct sigaction action;		


  
  
  

  setbuf(stderr, NULL);


  sigset(SIGTERM, sigterm_handler);

  memset(&action, 0, sizeof(action));

  sigemptyset(&action.sa_mask);
  action.sa_handler = sigterm_handler;
  sigaction(SIGTERM, &action, NULL);

  signal(SIGTERM, sigterm_handler);


  
  
  

  if (argc == 1)
  {
    if ((ptr = strrchr(argv[0], '/')) != NULL)
      ptr ++;
    else ptr = argv[0];
    printf("network %s \"Unknown\" \"Backend Error Handler\"\n", ptr);
    return (CUPS_BACKEND_OK);
  }
  else if (argc < 6)
  {
    fprintf(stderr, "Usage: %s job-id user title copies options [file]\n", argv[0]);

    return (CUPS_BACKEND_FAILED);
  }

  
  
  

  uri = getenv("DEVICE_URI");
  if (!uri)
  {
    fprintf(stderr, "ERROR: No device URI supplied!");
    return (CUPS_BACKEND_FAILED);
  }

  ptr = strstr(uri, ":/");
  if (!ptr)
    goto bad_uri;
  ptr += 2;
  if (*ptr == '0')
    dd = 0;
  else if (*ptr == '1')
    dd = 1;
  else goto bad_uri;
  ptr ++;
  if (*ptr != '/')
    goto bad_uri;
  ptr ++;
  att = 0;
  while (isdigit(*ptr))
  {
    att = att * 10 + (int)(*ptr) - 48;
    ptr ++;
  }
  if (*ptr != '/')
    goto bad_uri;
  ptr ++;
  delay = 0;
  while (isdigit(*ptr))
  {
    delay = delay * 10 + (int)(*ptr) - 48;
    ptr ++;
  }
  if (*ptr != '/')
    goto bad_uri;
  ptr ++;
  fprintf(stderr, "DEBUG: beh: Don't disable: %d; Attempts: %d; Delay: %d; Destination URI: %s\n", dd, att, delay, ptr);


  
  
  

  if (argc == 6)
  {
    char *tmpdir;
    int fd;
    FILE *tmpfile;
    size_t bytes;

    tmpdir = getenv("TMPDIR");
    if (!tmpdir)
      tmpdir = "/tmp";
    snprintf(tmpfilename, sizeof(tmpfilename), "%s/beh-XXXXXX", tmpdir);
    fd = mkstemp(tmpfilename);
    if (fd < 0)
    {
      fprintf(stderr, "ERROR: beh: Could not create temporary file: %s\n", strerror(errno));

      return (CUPS_BACKEND_FAILED);
    }
    tmpfile = fdopen(fd, "r+");
    while ((bytes = fread(buf, 1, sizeof(buf), stdin)))
      fwrite(buf, 1, bytes, tmpfile);
    fclose(tmpfile);
		    
    filename = tmpfilename;
  }
  else {
    tmpfilename[0] = '\0';
    filename = argv[6];
  }

  
  
  

  while ((retval = call_backend(ptr, argc, argv, filename)) != CUPS_BACKEND_OK && !job_canceled)

  {
    if (att > 0)
    {
      att --;
      if (att == 0)
	break;
    }
    if (delay > 0)
      sleep (delay);
  }

  if (strlen(tmpfilename) > 0)
    unlink(tmpfilename);

  
  
  

  if (!dd)
    return (retval);
  else return (CUPS_BACKEND_OK);

  
  
  

 bad_uri:

  fprintf(stderr, "ERROR: URI must be \"beh:/<dd>/<att>/<delay>/<original uri>\"!\n");
  return (CUPS_BACKEND_FAILED);
}






static int call_backend(char *uri, int  argc,  char **argv, char *filename)




{
  const char	*cups_serverbin;	
  char		scheme[1024],            *ptr, cmdline[65536];

  int           retval;

  
  
  

  strncpy(scheme, uri, sizeof(scheme) - 1);
  if (strlen(uri) > 1023)
    scheme[1023] = '\0';
  if ((ptr = strchr(scheme, ':')) != NULL)
    *ptr = '\0';

  if ((cups_serverbin = getenv("CUPS_SERVERBIN")) == NULL)
    cups_serverbin = CUPS_SERVERBIN;

  if (!strncasecmp(uri, "file:", 5) || uri[0] == '/')
  {
    fprintf(stderr, "ERROR: beh: Direct output into a file not supported.\n");
    exit (CUPS_BACKEND_FAILED);
  }
  else snprintf(cmdline, sizeof(cmdline), "%s/backend/%s '%s' '%s' '%s' '%s' '%s' %s", cups_serverbin, scheme, argv[1], argv[2], argv[3],     (argc == 6 ? "1" : argv[4]), argv[5], filename);









  
  
  

  setenv("DEVICE_URI", uri, 1);

  fprintf(stderr, "DEBUG: beh: Executing backend command line \"%s\"...\n", cmdline);

  fprintf(stderr, "DEBUG: beh: Using device URI: %s\n", uri);


  retval = system(cmdline) >> 8;

  if (retval == -1)
    fprintf(stderr, "ERROR: Unable to execute backend command line: %s\n", strerror(errno));

  return (retval);
}






static void sigterm_handler(int sig)
{
  (void)sig;

  fprintf(stderr, "DEBUG: beh: Job canceled.\n");

  if (job_canceled)
    _exit(CUPS_BACKEND_OK);
  else job_canceled = 1;
}
