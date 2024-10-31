

















static void init_library (void);
static void mark_named_operators (cpp_reader *, int);
static bool read_original_filename (cpp_reader *);
static void read_original_directory (cpp_reader *);
static void post_options (cpp_reader *);




















TRIGRAPH_MAP s('=', '#')	s(')', ']')	s('!', '|')
  s('(', '[')	s('\'', '^')	s('>', '}')
  s('/', '\\')	s('<', '{')	s('-', '~')
END       struct lang_flags {







  char c99;
  char cplusplus;
  char extended_numbers;
  char extended_identifiers;
  char c11_identifiers;
  char cxx23_identifiers;
  char std;
  char digraphs;
  char uliterals;
  char rliterals;
  char user_literals;
  char binary_constants;
  char digit_separators;
  char trigraphs;
  char utf8_char_literals;
  char va_opt;
  char scope;
  char dfp_constants;
  char size_t_literals;
  char elifdef;
};

static const struct lang_flags lang_defaults[] = {
    { 0,  0,  1,  0,  0,  0,    0,  1,   0,   0,   0,    0,     0,     0,   0,      1,   1,     0,   0,   0 }, { 1,  0,  1,  1,  0,  0,    0,  1,   1,   1,   0,    0,     0,     0,   0,      1,   1,     0,   0,   0 }, { 1,  0,  1,  1,  1,  0,    0,  1,   1,   1,   0,    0,     0,     0,   0,      1,   1,     0,   0,   0 }, { 1,  0,  1,  1,  1,  0,    0,  1,   1,   1,   0,    0,     0,     0,   0,      1,   1,     0,   0,   0 }, { 1,  0,  1,  1,  1,  0,    0,  1,   1,   1,   0,    1,     1,     0,   1,      1,   1,     1,   0,   1 }, { 0,  0,  0,  0,  0,  0,    1,  0,   0,   0,   0,    0,     0,     1,   0,      0,   0,     0,   0,   0 }, { 0,  0,  0,  0,  0,  0,    1,  1,   0,   0,   0,    0,     0,     1,   0,      0,   0,     0,   0,   0 }, { 1,  0,  1,  1,  0,  0,    1,  1,   0,   0,   0,    0,     0,     1,   0,      0,   0,     0,   0,   0 }, { 1,  0,  1,  1,  1,  0,    1,  1,   1,   0,   0,    0,     0,     1,   0,      0,   0,     0,   0,   0 }, { 1,  0,  1,  1,  1,  0,    1,  1,   1,   0,   0,    0,     0,     1,   0,      0,   0,     0,   0,   0 }, { 1,  0,  1,  1,  1,  0,    1,  1,   1,   0,   0,    1,     1,     1,   1,      0,   1,     1,   0,   1 }, { 0,  1,  1,  1,  0,  0,    0,  1,   0,   0,   0,    0,     0,     0,   0,      1,   1,     0,   0,   0 }, { 0,  1,  0,  1,  0,  0,    1,  1,   0,   0,   0,    0,     0,     1,   0,      0,   1,     0,   0,   0 }, { 1,  1,  1,  1,  1,  0,    0,  1,   1,   1,   1,    0,     0,     0,   0,      1,   1,     0,   0,   0 }, { 1,  1,  0,  1,  1,  0,    1,  1,   1,   1,   1,    0,     0,     1,   0,      0,   1,     0,   0,   0 }, { 1,  1,  1,  1,  1,  0,    0,  1,   1,   1,   1,    1,     1,     0,   0,      1,   1,     0,   0,   0 }, { 1,  1,  0,  1,  1,  0,    1,  1,   1,   1,   1,    1,     1,     1,   0,      0,   1,     0,   0,   0 }, { 1,  1,  1,  1,  1,  0,    0,  1,   1,   1,   1,    1,     1,     0,   1,      1,   1,     0,   0,   0 }, { 1,  1,  1,  1,  1,  0,    1,  1,   1,   1,   1,    1,     1,     0,   1,      0,   1,     0,   0,   0 }, { 1,  1,  1,  1,  1,  0,    0,  1,   1,   1,   1,    1,     1,     0,   1,      1,   1,     0,   0,   0 }, { 1,  1,  1,  1,  1,  0,    1,  1,   1,   1,   1,    1,     1,     0,   1,      1,   1,     0,   0,   0 }, { 1,  1,  1,  1,  1,  1,    0,  1,   1,   1,   1,    1,     1,     0,   1,      1,   1,     0,   1,   1 }, { 1,  1,  1,  1,  1,  1,    1,  1,   1,   1,   1,    1,     1,     0,   1,      1,   1,     0,   1,   1 }, { 0,  0,  1,  0,  0,  0,    0,  0,   0,   0,   0,    0,     0,     0,   0,      0,   0,     0,   0,   0 }






















};


void cpp_set_lang (cpp_reader *pfile, enum c_lang lang)
{
  const struct lang_flags *l = &lang_defaults[(int) lang];

  CPP_OPTION (pfile, lang) = lang;

  CPP_OPTION (pfile, c99)			 = l->c99;
  CPP_OPTION (pfile, cplusplus)			 = l->cplusplus;
  CPP_OPTION (pfile, extended_numbers)		 = l->extended_numbers;
  CPP_OPTION (pfile, extended_identifiers)	 = l->extended_identifiers;
  CPP_OPTION (pfile, c11_identifiers)		 = l->c11_identifiers;
  CPP_OPTION (pfile, cxx23_identifiers)		 = l->cxx23_identifiers;
  CPP_OPTION (pfile, std)			 = l->std;
  CPP_OPTION (pfile, digraphs)			 = l->digraphs;
  CPP_OPTION (pfile, uliterals)			 = l->uliterals;
  CPP_OPTION (pfile, rliterals)			 = l->rliterals;
  CPP_OPTION (pfile, user_literals)		 = l->user_literals;
  CPP_OPTION (pfile, binary_constants)		 = l->binary_constants;
  CPP_OPTION (pfile, digit_separators)		 = l->digit_separators;
  CPP_OPTION (pfile, trigraphs)			 = l->trigraphs;
  CPP_OPTION (pfile, utf8_char_literals)	 = l->utf8_char_literals;
  CPP_OPTION (pfile, va_opt)			 = l->va_opt;
  CPP_OPTION (pfile, scope)			 = l->scope;
  CPP_OPTION (pfile, dfp_constants)		 = l->dfp_constants;
  CPP_OPTION (pfile, size_t_literals)		 = l->size_t_literals;
  CPP_OPTION (pfile, elifdef)			 = l->elifdef;
}


static void init_library (void)
{
  static int initialized = 0;

  if (! initialized)
    {
      initialized = 1;

      _cpp_init_lexer ();

      
      init_trigraph_map ();


       (void) bindtextdomain (PACKAGE, LOCALEDIR);

    }
}


cpp_reader * cpp_create_reader (enum c_lang lang, cpp_hash_table *table, class line_maps *line_table)

{
  cpp_reader *pfile;

  
  init_library ();

  pfile = XCNEW (cpp_reader);
  memset (&pfile->base_context, 0, sizeof (pfile->base_context));

  cpp_set_lang (pfile, lang);
  CPP_OPTION (pfile, warn_multichar) = 1;
  CPP_OPTION (pfile, discard_comments) = 1;
  CPP_OPTION (pfile, discard_comments_in_macro_exp) = 1;
  CPP_OPTION (pfile, max_include_depth) = 200;
  CPP_OPTION (pfile, operator_names) = 1;
  CPP_OPTION (pfile, warn_trigraphs) = 2;
  CPP_OPTION (pfile, warn_endif_labels) = 1;
  CPP_OPTION (pfile, cpp_warn_c90_c99_compat) = -1;
  CPP_OPTION (pfile, cpp_warn_c11_c2x_compat) = -1;
  CPP_OPTION (pfile, cpp_warn_cxx11_compat) = 0;
  CPP_OPTION (pfile, cpp_warn_deprecated) = 1;
  CPP_OPTION (pfile, cpp_warn_long_long) = 0;
  CPP_OPTION (pfile, dollars_in_ident) = 1;
  CPP_OPTION (pfile, warn_dollars) = 1;
  CPP_OPTION (pfile, warn_variadic_macros) = 1;
  CPP_OPTION (pfile, warn_builtin_macro_redefined) = 1;
  CPP_OPTION (pfile, cpp_warn_implicit_fallthrough) = 0;
  
  CPP_OPTION (pfile, track_macro_expansion) = 2;
  CPP_OPTION (pfile, warn_normalize) = normalized_C;
  CPP_OPTION (pfile, warn_literal_suffix) = 1;
  CPP_OPTION (pfile, canonical_system_headers)
      = ENABLE_CANONICAL_SYSTEM_HEADERS;
  CPP_OPTION (pfile, ext_numeric_literals) = 1;
  CPP_OPTION (pfile, warn_date_time) = 0;

  
  CPP_OPTION (pfile, precision) = CHAR_BIT * sizeof (long);
  CPP_OPTION (pfile, char_precision) = CHAR_BIT;
  CPP_OPTION (pfile, wchar_precision) = CHAR_BIT * sizeof (int);
  CPP_OPTION (pfile, int_precision) = CHAR_BIT * sizeof (int);
  CPP_OPTION (pfile, unsigned_char) = 0;
  CPP_OPTION (pfile, unsigned_wchar) = 1;
  CPP_OPTION (pfile, bytes_big_endian) = 1;  

  
  CPP_OPTION (pfile, narrow_charset) = _cpp_default_encoding ();
  CPP_OPTION (pfile, wide_charset) = 0;

  
  CPP_OPTION (pfile, input_charset) = _cpp_default_encoding ();

  
  pfile->no_search_path.name = (char *) "";

  
  pfile->line_table = line_table;

  
  pfile->state.save_comments = ! CPP_OPTION (pfile, discard_comments);

  
  pfile->avoid_paste.type = CPP_PADDING;
  pfile->avoid_paste.val.source = NULL;
  pfile->avoid_paste.src_loc = 0;
  pfile->endarg.type = CPP_EOF;
  pfile->endarg.flags = 0;
  pfile->endarg.src_loc = 0;

  
  _cpp_init_tokenrun (&pfile->base_run, 250);
  pfile->cur_run = &pfile->base_run;
  pfile->cur_token = pfile->base_run.base;

  
  pfile->context = &pfile->base_context;
  pfile->base_context.c.macro = 0;
  pfile->base_context.prev = pfile->base_context.next = 0;

  
  pfile->a_buff = _cpp_get_buff (pfile, 0);
  pfile->u_buff = _cpp_get_buff (pfile, 0);

  
  pfile->pushed_macros = 0;

  
  pfile->forced_token_location = 0;

  
  pfile->time_stamp = time_t (-1);
  pfile->time_stamp_kind = 0;

  
  _cpp_expand_op_stack (pfile);

  
  obstack_specify_allocation (&pfile->buffer_ob, 0, 0, xmalloc, free);

  _cpp_init_files (pfile);

  _cpp_init_hashtable (pfile, table);

  return pfile;
}


void cpp_set_line_map (cpp_reader *pfile, class line_maps *line_table)
{
  pfile->line_table = line_table;
}


void cpp_destroy (cpp_reader *pfile)
{
  cpp_context *context, *contextn;
  struct def_pragma_macro *pmacro;
  tokenrun *run, *runn;
  int i;

  free (pfile->op_stack);

  while (CPP_BUFFER (pfile) != NULL)
    _cpp_pop_buffer (pfile);

  free (pfile->out.base);

  if (pfile->macro_buffer)
    {
      free (pfile->macro_buffer);
      pfile->macro_buffer = NULL;
      pfile->macro_buffer_len = 0;
    }

  if (pfile->deps)
    deps_free (pfile->deps);
  obstack_free (&pfile->buffer_ob, 0);

  _cpp_destroy_hashtable (pfile);
  _cpp_cleanup_files (pfile);
  _cpp_destroy_iconv (pfile);

  _cpp_free_buff (pfile->a_buff);
  _cpp_free_buff (pfile->u_buff);
  _cpp_free_buff (pfile->free_buffs);

  for (run = &pfile->base_run; run; run = runn)
    {
      runn = run->next;
      free (run->base);
      if (run != &pfile->base_run)
	free (run);
    }

  for (context = pfile->base_context.next; context; context = contextn)
    {
      contextn = context->next;
      free (context);
    }

  if (pfile->comments.entries)
    {
      for (i = 0; i < pfile->comments.count; i++)
	free (pfile->comments.entries[i].comment);

      free (pfile->comments.entries);
    }
  if (pfile->pushed_macros)
    {
      do {
	  pmacro = pfile->pushed_macros;
	  pfile->pushed_macros = pmacro->next;
	  free (pmacro->name);
	  free (pmacro);
	}
      while (pfile->pushed_macros);
    }

  free (pfile);
}


struct builtin_macro {
  const uchar *const name;
  const unsigned short len;
  const unsigned short value;
  const bool always_warn_if_redefined;
};


static const struct builtin_macro builtin_array[] = {
  B("__TIMESTAMP__",	 BT_TIMESTAMP,     false), B("__TIME__",		 BT_TIME,          false), B("__DATE__",		 BT_DATE,          false), B("__FILE__",		 BT_FILE,          false), B("__FILE_NAME__",	 BT_FILE_NAME,     false), B("__BASE_FILE__",	 BT_BASE_FILE,     false), B("__LINE__",		 BT_SPECLINE,      true), B("__INCLUDE_LEVEL__", BT_INCLUDE_LEVEL, true), B("__COUNTER__",	 BT_COUNTER,       true),  B("__has_attribute",	 BT_HAS_ATTRIBUTE, true), B("__has_c_attribute", BT_HAS_STD_ATTRIBUTE, true), B("__has_cpp_attribute", BT_HAS_ATTRIBUTE, true), B("__has_builtin",	 BT_HAS_BUILTIN,   true), B("__has_include",	 BT_HAS_INCLUDE,   true), B("__has_include_next",BT_HAS_INCLUDE_NEXT,   true),  B("_Pragma",		 BT_PRAGMA,        true), B("__STDC__",		 BT_STDC,          true), };




















struct builtin_operator {
  const uchar *const name;
  const unsigned short len;
  const unsigned short value;
};


static const struct builtin_operator operator_array[] = {
  B("and",	CPP_AND_AND), B("and_eq",	CPP_AND_EQ), B("bitand",	CPP_AND), B("bitor",	CPP_OR), B("compl",	CPP_COMPL), B("not",	CPP_NOT), B("not_eq",	CPP_NOT_EQ), B("or",	CPP_OR_OR), B("or_eq",	CPP_OR_EQ), B("xor",	CPP_XOR), B("xor_eq",	CPP_XOR_EQ)









};



static void mark_named_operators (cpp_reader *pfile, int flags)
{
  const struct builtin_operator *b;

  for (b = operator_array;
       b < (operator_array + ARRAY_SIZE (operator_array));
       b++)
    {
      cpp_hashnode *hp = cpp_lookup (pfile, b->name, b->len);
      hp->flags |= flags;
      hp->is_directive = 0;
      hp->directive_index = b->value;
    }
}


const char * cpp_named_operator2name (enum cpp_ttype type)
{
  const struct builtin_operator *b;

  for (b = operator_array;
       b < (operator_array + ARRAY_SIZE (operator_array));
       b++)
    {
      if (type == b->value)
	return (const char *) b->name;
    }

  return NULL;
}

void cpp_init_special_builtins (cpp_reader *pfile)
{
  const struct builtin_macro *b;
  size_t n = ARRAY_SIZE (builtin_array);

  if (CPP_OPTION (pfile, traditional))
    n -= 2;
  else if (! CPP_OPTION (pfile, stdc_0_in_system_headers)
	   || CPP_OPTION (pfile, std))
    n--;

  for (b = builtin_array; b < builtin_array + n; b++)
    {
      if ((b->value == BT_HAS_ATTRIBUTE || b->value == BT_HAS_STD_ATTRIBUTE || b->value == BT_HAS_BUILTIN)

	  && (CPP_OPTION (pfile, lang) == CLK_ASM || pfile->cb.has_attribute == NULL))
	continue;
      cpp_hashnode *hp = cpp_lookup (pfile, b->name, b->len);
      hp->type = NT_BUILTIN_MACRO;
      if (b->always_warn_if_redefined)
	hp->flags |= NODE_WARN;
      hp->value.builtin = (enum cpp_builtin_type) b->value;
    }
}



void _cpp_restore_special_builtin (cpp_reader *pfile, struct def_pragma_macro *c)
{
  size_t len = strlen (c->name);

  for (const struct builtin_macro *b = builtin_array;
       b < builtin_array + ARRAY_SIZE (builtin_array); b++)
    if (b->len == len && memcmp (c->name, b->name, len + 1) == 0)
      {
	cpp_hashnode *hp = cpp_lookup (pfile, b->name, b->len);
	hp->type = NT_BUILTIN_MACRO;
	if (b->always_warn_if_redefined)
	  hp->flags |= NODE_WARN;
	hp->value.builtin = (enum cpp_builtin_type) b->value;
      }
}


void cpp_init_builtins (cpp_reader *pfile, int hosted)
{
  cpp_init_special_builtins (pfile);

  if (!CPP_OPTION (pfile, traditional)
      && (! CPP_OPTION (pfile, stdc_0_in_system_headers)
	  || CPP_OPTION (pfile, std)))
    _cpp_define_builtin (pfile, "__STDC__ 1");

  if (CPP_OPTION (pfile, cplusplus))
    {
      
      if (CPP_OPTION (pfile, lang) == CLK_CXX23 || CPP_OPTION (pfile, lang) == CLK_GNUCXX23)
	_cpp_define_builtin (pfile, "__cplusplus 202100L");
      else if (CPP_OPTION (pfile, lang) == CLK_CXX20 || CPP_OPTION (pfile, lang) == CLK_GNUCXX20)
	_cpp_define_builtin (pfile, "__cplusplus 202002L");
      else if (CPP_OPTION (pfile, lang) == CLK_CXX17 || CPP_OPTION (pfile, lang) == CLK_GNUCXX17)
	_cpp_define_builtin (pfile, "__cplusplus 201703L");
      else if (CPP_OPTION (pfile, lang) == CLK_CXX14 || CPP_OPTION (pfile, lang) == CLK_GNUCXX14)
	_cpp_define_builtin (pfile, "__cplusplus 201402L");
      else if (CPP_OPTION (pfile, lang) == CLK_CXX11 || CPP_OPTION (pfile, lang) == CLK_GNUCXX11)
	_cpp_define_builtin (pfile, "__cplusplus 201103L");
      else _cpp_define_builtin (pfile, "__cplusplus 199711L");
    }
  else if (CPP_OPTION (pfile, lang) == CLK_ASM)
    _cpp_define_builtin (pfile, "__ASSEMBLER__ 1");
  else if (CPP_OPTION (pfile, lang) == CLK_STDC94)
    _cpp_define_builtin (pfile, "__STDC_VERSION__ 199409L");
  else if (CPP_OPTION (pfile, lang) == CLK_STDC2X || CPP_OPTION (pfile, lang) == CLK_GNUC2X)
    _cpp_define_builtin (pfile, "__STDC_VERSION__ 202000L");
  else if (CPP_OPTION (pfile, lang) == CLK_STDC17 || CPP_OPTION (pfile, lang) == CLK_GNUC17)
    _cpp_define_builtin (pfile, "__STDC_VERSION__ 201710L");
  else if (CPP_OPTION (pfile, lang) == CLK_STDC11 || CPP_OPTION (pfile, lang) == CLK_GNUC11)
    _cpp_define_builtin (pfile, "__STDC_VERSION__ 201112L");
  else if (CPP_OPTION (pfile, c99))
    _cpp_define_builtin (pfile, "__STDC_VERSION__ 199901L");

  if (CPP_OPTION (pfile, uliterals)
      && !(CPP_OPTION (pfile, cplusplus)
	   && (CPP_OPTION (pfile, lang) == CLK_GNUCXX || CPP_OPTION (pfile, lang) == CLK_CXX98)))
    {
      _cpp_define_builtin (pfile, "__STDC_UTF_16__ 1");
      _cpp_define_builtin (pfile, "__STDC_UTF_32__ 1");
    }

  if (hosted)
    _cpp_define_builtin (pfile, "__STDC_HOSTED__ 1");
  else _cpp_define_builtin (pfile, "__STDC_HOSTED__ 0");

  if (CPP_OPTION (pfile, objc))
    _cpp_define_builtin (pfile, "__OBJC__ 1");
}



static void sanity_checks (cpp_reader *);
static void sanity_checks (cpp_reader *pfile)
{
  cppchar_t test = 0;
  size_t max_precision = 2 * CHAR_BIT * sizeof (cpp_num_part);

  
  test--;
  if (test < 1)
    cpp_error (pfile, CPP_DL_ICE, "cppchar_t must be an unsigned type");

  if (CPP_OPTION (pfile, precision) > max_precision)
    cpp_error (pfile, CPP_DL_ICE, "preprocessor arithmetic has maximum precision of %lu bits;" " target requires %lu bits", (unsigned long) max_precision, (unsigned long) CPP_OPTION (pfile, precision));




  if (CPP_OPTION (pfile, precision) < CPP_OPTION (pfile, int_precision))
    cpp_error (pfile, CPP_DL_ICE, "CPP arithmetic must be at least as precise as a target int");

  if (CPP_OPTION (pfile, char_precision) < 8)
    cpp_error (pfile, CPP_DL_ICE, "target char is less than 8 bits wide");

  if (CPP_OPTION (pfile, wchar_precision) < CPP_OPTION (pfile, char_precision))
    cpp_error (pfile, CPP_DL_ICE, "target wchar_t is narrower than target char");

  if (CPP_OPTION (pfile, int_precision) < CPP_OPTION (pfile, char_precision))
    cpp_error (pfile, CPP_DL_ICE, "target int is narrower than target char");

  
  if (sizeof (cppchar_t) > sizeof (cpp_num_part))
    cpp_error (pfile, CPP_DL_ICE, "CPP half-integer narrower than CPP character");

  if (CPP_OPTION (pfile, wchar_precision) > BITS_PER_CPPCHAR_T)
    cpp_error (pfile, CPP_DL_ICE, "CPP on this host cannot handle wide character constants over" " %lu bits, but the target requires %lu bits", (unsigned long) BITS_PER_CPPCHAR_T, (unsigned long) CPP_OPTION (pfile, wchar_precision));



}





void cpp_post_options (cpp_reader *pfile)
{
  int flags;

  sanity_checks (pfile);

  post_options (pfile);

  
  flags = 0;
  if (CPP_OPTION (pfile, cplusplus) && CPP_OPTION (pfile, operator_names))
    flags |= NODE_OPERATOR;
  if (CPP_OPTION (pfile, warn_cxx_operator_names))
    flags |= NODE_DIAGNOSTIC | NODE_WARN_OPERATOR;
  if (flags != 0)
    mark_named_operators (pfile, flags);
}


const char * cpp_read_main_file (cpp_reader *pfile, const char *fname, bool injecting)
{
  if (mkdeps *deps = cpp_get_deps (pfile))
    
    deps_add_default_target (deps, fname);

  pfile->main_file = _cpp_find_file (pfile, fname, CPP_OPTION (pfile, preprocessed) ? &pfile->no_search_path : CPP_OPTION (pfile, main_search) == CMS_user ? pfile->quote_include : CPP_OPTION (pfile, main_search) == CMS_system ? pfile->bracket_include : &pfile->no_search_path, 0, _cpp_FFK_NORMAL, 0);







  if (_cpp_find_failed (pfile->main_file))
    return NULL;

  _cpp_stack_file (pfile, pfile->main_file, injecting || CPP_OPTION (pfile, preprocessed)
		   ? IT_PRE_MAIN : IT_MAIN, 0);

  
  if (CPP_OPTION (pfile, preprocessed))
    if (!read_original_filename (pfile))
      {
	
	auto *last = linemap_check_ordinary (LINEMAPS_LAST_MAP (pfile->line_table, false));
	last->to_line = 1;
	
	_cpp_do_file_change (pfile, LC_RENAME_VERBATIM, LINEMAP_FILE (last), LINEMAP_LINE (last), LINEMAP_SYSP (last));
      }

  auto *map = LINEMAPS_LAST_ORDINARY_MAP (pfile->line_table);
  pfile->main_loc = MAP_START_LOCATION (map);

  return ORDINARY_MAP_FILE_NAME (map);
}

location_t cpp_main_loc (const cpp_reader *pfile)
{
  return pfile->main_loc;
}



static bool read_original_filename (cpp_reader *pfile)
{
  auto *buf = pfile->buffer->next_line;

  if (pfile->buffer->rlimit - buf > 4 && buf[0] == '#' && buf[1] == ' '  && (buf[2] == '0' || buf[2] == '1')



      && buf[3] == ' ')
    {
      const cpp_token *token = _cpp_lex_direct (pfile);
      gcc_checking_assert (token->type == CPP_HASH);
      if (_cpp_handle_directive (pfile, token->flags & PREV_WHITE))
	{
	  read_original_directory (pfile);

	  auto *penult = &linemap_check_ordinary (LINEMAPS_LAST_MAP (pfile->line_table, false))[-1];
	  if (penult[1].reason == LC_RENAME_VERBATIM)
	    {
	      
	      pfile->line_table->highest_location = pfile->line_table->highest_line = penult[0].start_location;


	      penult[1].start_location = penult[0].start_location;
	      penult[1].reason = penult[0].reason;
	      penult[0] = penult[1];
	      pfile->line_table->info_ordinary.used--;
	      pfile->line_table->info_ordinary.cache = 0;
	    }

	  return true;
	}
    }

  return false;
}


static void read_original_directory (cpp_reader *pfile)
{
  auto *buf = pfile->buffer->next_line;

  if (pfile->buffer->rlimit - buf > 4 && buf[0] == '#' && buf[1] == ' '  && (buf[2] == '0' || buf[2] == '1')



      && buf[3] == ' ')
    {
      const cpp_token *hash = _cpp_lex_direct (pfile);
      gcc_checking_assert (hash->type == CPP_HASH);
      pfile->state.in_directive = 1;
      const cpp_token *number = _cpp_lex_direct (pfile);
      gcc_checking_assert (number->type == CPP_NUMBER);
      const cpp_token *string = _cpp_lex_direct (pfile);
      pfile->state.in_directive = 0;

      const unsigned char *text = nullptr;
      size_t len = 0;
      if (string->type == CPP_STRING)
	{
	  
	  text = string->val.str.text;
	  len = string->val.str.len;
	}
      if (len < 5 || !IS_DIR_SEPARATOR (text[len - 2])
	  || !IS_DIR_SEPARATOR (text[len - 3]))
	{
	  
	  _cpp_backup_tokens (pfile, 3);
	  return;
	}

      if (pfile->cb.dir_change)
	{
	  
	  char *smashy = (char *)text;
	  smashy[len - 3] = 0;
	  
	  pfile->cb.dir_change (pfile, smashy + 1);
	}

      
    }
}


void cpp_finish (cpp_reader *pfile, FILE *deps_stream)
{
  
  if (CPP_OPTION (pfile, warn_unused_macros))
    cpp_forall_identifiers (pfile, _cpp_warn_if_unused_macro, NULL);

  
  while (pfile->buffer)
    _cpp_pop_buffer (pfile);

  if (deps_stream)
    deps_write (pfile, deps_stream, 72);

  
  if (CPP_OPTION (pfile, print_include_names))
    _cpp_report_missing_guards (pfile);
}

static void post_options (cpp_reader *pfile)
{
  
  if (CPP_OPTION (pfile, cplusplus))
    CPP_OPTION (pfile, cpp_warn_traditional) = 0;

  
  if (CPP_OPTION (pfile, preprocessed))
    {
      if (!CPP_OPTION (pfile, directives_only))
	pfile->state.prevent_expansion = 1;
      CPP_OPTION (pfile, traditional) = 0;
    }

  if (CPP_OPTION (pfile, warn_trigraphs) == 2)
    CPP_OPTION (pfile, warn_trigraphs) = !CPP_OPTION (pfile, trigraphs);

  if (CPP_OPTION (pfile, traditional))
    {
      CPP_OPTION (pfile, trigraphs) = 0;
      CPP_OPTION (pfile, warn_trigraphs) = 0;
    }

  if (CPP_OPTION (pfile, module_directives))
    {
      
      const char *const inits[spec_nodes::M_HWM] = {"export ", "module ", "import ", "__import";

      for (int ix = 0; ix != spec_nodes::M_HWM; ix++)
	{
	  cpp_hashnode *node = cpp_lookup (pfile, UC (inits[ix]), strlen (inits[ix]));

	  
	  pfile->spec_nodes.n_modules[ix][1] = node;

	  if (ix != spec_nodes::M__IMPORT)
	    
	    node = cpp_lookup (pfile, NODE_NAME (node), NODE_LEN (node) - 1);

	  node->flags |= NODE_MODULE;
	  pfile->spec_nodes.n_modules[ix][0] = node;
	}
    }
}
