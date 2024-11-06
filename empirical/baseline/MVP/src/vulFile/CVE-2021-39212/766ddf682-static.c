
















ModuleExport size_t RegisterUndefinedImage(void)
{
  return(MagickImageCoderSignature);
}

ModuleExport void UnregisterUndefinedImage(void)
{
}


static struct {
  const char *module;

  MagickBooleanType registered;

  size_t (*register_module)(void);

  void (*unregister_module)(void);
} MagickModules[] = {

  #include "coders/coders-list.h"

  { (const char *) NULL, MagickFalse, RegisterUndefinedImage, UnregisterUndefinedImage }
};



MagickExport MagickBooleanType InvokeStaticImageFilter(const char *tag, Image **image,const int argc,const char **argv,ExceptionInfo *exception)
{
  PolicyRights rights;

  assert(image != (Image **) NULL);
  assert((*image)->signature == MagickCoreSignature);
  if ((*image)->debug != MagickFalse)
    (void) LogMagickEvent(TraceEvent,GetMagickModule(),"%s",(*image)->filename);
  rights=ReadPolicyRights;
  if (IsRightsAuthorized(FilterPolicyDomain,rights,tag) == MagickFalse)
    {
      errno=EPERM;
      (void) ThrowMagickException(exception,GetMagickModule(),PolicyError, "NotAuthorized","`%s'",tag);
      return(MagickFalse);
    }

  (void) tag;
  (void) argc;
  (void) argv;
  (void) exception;

  {
    extern size_t analyzeImage(Image **,const int,char **,ExceptionInfo *);

    ImageFilterHandler *image_filter;

    image_filter=(ImageFilterHandler *) NULL;
    if (LocaleCompare("analyze",tag) == 0)
      image_filter=(ImageFilterHandler *) analyzeImage;
    if (image_filter == (ImageFilterHandler *) NULL)
      (void) ThrowMagickException(exception,GetMagickModule(),ModuleError, "UnableToLoadModule","`%s'",tag);
    else {
        size_t signature;

        if ((*image)->debug != MagickFalse)
          (void) LogMagickEvent(CoderEvent,GetMagickModule(), "Invoking \"%s\" static image filter",tag);
        signature=image_filter(image,argc,argv,exception);
        if ((*image)->debug != MagickFalse)
          (void) LogMagickEvent(CoderEvent,GetMagickModule(),"\"%s\" completes", tag);
        if (signature != MagickImageFilterSignature)
          {
            (void) ThrowMagickException(exception,GetMagickModule(),ModuleError, "ImageFilterSignatureMismatch","'%s': %8lx != %8lx",tag, (unsigned long) signature,(unsigned long)

              MagickImageFilterSignature);
            return(MagickFalse);
          }
      }
  }

  return(MagickTrue);
}



MagickExport MagickBooleanType RegisterStaticModule(const char *module, ExceptionInfo *exception)
{
  char module_name[MagickPathExtent];

  PolicyRights rights;

  const CoderInfo *p;

  size_t extent;

  ssize_t i;

  
  assert(module != (const char *) NULL);
  (void) CopyMagickString(module_name,module,MagickPathExtent);
  p=GetCoderInfo(module,exception);
  if (p != (CoderInfo *) NULL)
    (void) CopyMagickString(module_name,p->name,MagickPathExtent);
  rights=ReadPolicyRights;
  if (IsRightsAuthorized(ModulePolicyDomain,rights,module_name) == MagickFalse)
    {
      errno=EPERM;
      (void) ThrowMagickException(exception,GetMagickModule(),PolicyError, "NotAuthorized","`%s'",module);
      return(MagickFalse);
    }
  extent=sizeof(MagickModules)/sizeof(MagickModules[0]);
  for (i=0; i < (ssize_t) extent; i++)
    if (LocaleCompare(MagickModules[i].module,module_name) == 0)
      {
        if (MagickModules[i].registered == MagickFalse)
          {
            (void) (MagickModules[i].register_module)();
            MagickModules[i].registered=MagickTrue;
          }
        return(MagickTrue);
      }
  return(MagickFalse);
}


MagickExport void RegisterStaticModules(void)
{
  size_t extent;

  ssize_t i;

  extent=sizeof(MagickModules)/sizeof(MagickModules[0]);
  for (i=0; i < (ssize_t) extent; i++)
  {
    if (MagickModules[i].registered == MagickFalse)
      {
        (void) (MagickModules[i].register_module)();
        MagickModules[i].registered=MagickTrue;
      }
  }
}


MagickExport MagickBooleanType UnregisterStaticModule(const char *module)
{
  size_t extent;

  ssize_t i;

  extent=sizeof(MagickModules)/sizeof(MagickModules[0]);
  for (i=0; i < (ssize_t) extent; i++)
    if (LocaleCompare(MagickModules[i].module,module) == 0)
      {
        if (MagickModules[i].registered != MagickFalse)
          {
            (MagickModules[i].unregister_module)();
            MagickModules[i].registered=MagickFalse;
          }
        return(MagickTrue);
      }
  return(MagickFalse);
}


MagickExport void UnregisterStaticModules(void)
{
  size_t extent;

  ssize_t i;

  extent=sizeof(MagickModules)/sizeof(MagickModules[0]);
  for (i=0; i < (ssize_t) extent; i++)
  {
    if (MagickModules[i].registered != MagickFalse)
      {
        (MagickModules[i].unregister_module)();
        MagickModules[i].registered=MagickFalse;
      }
  }
}
