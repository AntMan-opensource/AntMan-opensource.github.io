






enum spell_type {
  SPELL_OPERATOR = 0, SPELL_IDENT, SPELL_LITERAL, SPELL_NONE };




struct token_spelling {
  enum spell_type category;
  const unsigned char *name;
};

static const unsigned char *const digraph_spellings[] = { UC"%:", UC"%:%:", UC"<:", UC":>", UC"<%", UC"%>" };



static const struct token_spelling token_spellings[N_TTYPES] = { TTYPE_TABLE };






static void add_line_note (cpp_buffer *, const uchar *, unsigned int);
static int skip_line_comment (cpp_reader *);
static void skip_whitespace (cpp_reader *, cppchar_t);
static void lex_string (cpp_reader *, cpp_token *, const uchar *);
static void save_comment (cpp_reader *, cpp_token *, const uchar *, cppchar_t);
static void store_comment (cpp_reader *, cpp_token *);
static void create_literal (cpp_reader *, cpp_token *, const uchar *, unsigned int, enum cpp_ttype);
static bool warn_in_comment (cpp_reader *, _cpp_line_note *);
static int name_p (cpp_reader *, const cpp_string *);
static tokenrun *next_tokenrun (tokenrun *);

static _cpp_buff *new_buff (size_t);



int cpp_ideq (const cpp_token *token, const char *string)
{
  if (token->type != CPP_NAME)
    return 0;

  return !ustrcmp (NODE_NAME (token->val.node.node), (const uchar *) string);
}


static void add_line_note (cpp_buffer *buffer, const uchar *pos, unsigned int type)
{
  if (buffer->notes_used == buffer->notes_cap)
    {
      buffer->notes_cap = buffer->notes_cap * 2 + 200;
      buffer->notes = XRESIZEVEC (_cpp_line_note, buffer->notes, buffer->notes_cap);
    }

  buffer->notes[buffer->notes_used].pos = pos;
  buffer->notes[buffer->notes_used].type = type;
  buffer->notes_used++;
}











typedef unsigned int word_type __attribute__((__mode__(__word__)));

typedef unsigned long word_type;



typedef char check_word_type_size [(sizeof(word_type) == 8 || sizeof(word_type) == 4) * 2 - 1];



static inline word_type acc_char_mask_misalign (word_type val, unsigned int n)
{
  word_type mask = -1;
  if (WORDS_BIGENDIAN)
    mask >>= n * 8;
  else mask <<= n * 8;
  return val & mask;
}



static inline word_type acc_char_replicate (uchar x)
{
  word_type ret;

  ret = (x << 24) | (x << 16) | (x << 8) | x;
  if (sizeof(word_type) == 8)
    ret = (ret << 16 << 16) | ret;
  return ret;
}



static inline word_type acc_char_cmp (word_type val, word_type c)
{

  
  return __builtin_alpha_cmpbge (0, val ^ c);

  word_type magic = 0x7efefefeU;
  if (sizeof(word_type) == 8)
    magic = (magic << 16 << 16) | 0xfefefefeU;
  magic |= 1;

  val ^= c;
  return ((val + magic) ^ ~val) & ~magic;

}



static inline int acc_char_index (word_type cmp ATTRIBUTE_UNUSED, word_type val ATTRIBUTE_UNUSED)

{

  
  return __builtin_ctzl (cmp);

  unsigned int i;

  
  for (i = 0; i < sizeof(word_type); ++i)
    {
      uchar c;
      if (WORDS_BIGENDIAN)
	c = (val >> (sizeof(word_type) - i - 1) * 8) & 0xff;
      else c = (val >> i * 8) & 0xff;

      if (c == '\n' || c == '\r' || c == '\\' || c == '?')
	return i;
    }

  return -1;

}



static const uchar * search_line_acc_char (const uchar *, const uchar *)
  ATTRIBUTE_UNUSED;

static const uchar * search_line_acc_char (const uchar *s, const uchar *end ATTRIBUTE_UNUSED)
{
  const word_type repl_nl = acc_char_replicate ('\n');
  const word_type repl_cr = acc_char_replicate ('\r');
  const word_type repl_bs = acc_char_replicate ('\\');
  const word_type repl_qm = acc_char_replicate ('?');

  unsigned int misalign;
  const word_type *p;
  word_type val, t;
  
  
  p = (word_type *)((uintptr_t)s & -sizeof(word_type));
  val = *p;
  misalign = (uintptr_t)s & (sizeof(word_type) - 1);
  if (misalign)
    val = acc_char_mask_misalign (val, misalign);

  
  while (1)
    {
      t  = acc_char_cmp (val, repl_nl);
      t |= acc_char_cmp (val, repl_cr);
      t |= acc_char_cmp (val, repl_bs);
      t |= acc_char_cmp (val, repl_qm);

      if (__builtin_expect (t != 0, 0))
	{
	  int i = acc_char_index (t, val);
	  if (i >= 0)
	    return (const uchar *)p + i;
	}

      val = *++p;
    }
}






static const char repl_chars[4][16] __attribute__((aligned(16))) = {
  { '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n' }, { '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r' }, { '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\' }, { '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?', '?' }, };










static const uchar *  __attribute__((__target__("sse")))


search_line_mmx (const uchar *s, const uchar *end ATTRIBUTE_UNUSED)
{
  typedef char v8qi __attribute__ ((__vector_size__ (8)));
  typedef int __m64 __attribute__ ((__vector_size__ (8), __may_alias__));

  const v8qi repl_nl = *(const v8qi *)repl_chars[0];
  const v8qi repl_cr = *(const v8qi *)repl_chars[1];
  const v8qi repl_bs = *(const v8qi *)repl_chars[2];
  const v8qi repl_qm = *(const v8qi *)repl_chars[3];

  unsigned int misalign, found, mask;
  const v8qi *p;
  v8qi data, t, c;

  
  misalign = (uintptr_t)s & 7;
  p = (const v8qi *)((uintptr_t)s & -8);
  data = *p;

  
  mask = -1u << misalign;

  
  goto start;
  do {
      data = *++p;
      mask = -1;

    start:
      t = __builtin_ia32_pcmpeqb(data, repl_nl);
      c = __builtin_ia32_pcmpeqb(data, repl_cr);
      t = (v8qi) __builtin_ia32_por ((__m64)t, (__m64)c);
      c = __builtin_ia32_pcmpeqb(data, repl_bs);
      t = (v8qi) __builtin_ia32_por ((__m64)t, (__m64)c);
      c = __builtin_ia32_pcmpeqb(data, repl_qm);
      t = (v8qi) __builtin_ia32_por ((__m64)t, (__m64)c);
      found = __builtin_ia32_pmovmskb (t);
      found &= mask;
    }
  while (!found);

  __builtin_ia32_emms ();

  
  found = __builtin_ctz(found);
  return (const uchar *)p + found;
}



static const uchar *  __attribute__((__target__("sse2")))


search_line_sse2 (const uchar *s, const uchar *end ATTRIBUTE_UNUSED)
{
  typedef char v16qi __attribute__ ((__vector_size__ (16)));

  const v16qi repl_nl = *(const v16qi *)repl_chars[0];
  const v16qi repl_cr = *(const v16qi *)repl_chars[1];
  const v16qi repl_bs = *(const v16qi *)repl_chars[2];
  const v16qi repl_qm = *(const v16qi *)repl_chars[3];

  unsigned int misalign, found, mask;
  const v16qi *p;
  v16qi data, t;

  
  misalign = (uintptr_t)s & 15;
  p = (const v16qi *)((uintptr_t)s & -16);
  data = *p;

  
  mask = -1u << misalign;

  
  goto start;
  do {
      data = *++p;
      mask = -1;

    start:
      t  = data == repl_nl;
      t |= data == repl_cr;
      t |= data == repl_bs;
      t |= data == repl_qm;
      found = __builtin_ia32_pmovmskb128 (t);
      found &= mask;
    }
  while (!found);

  
  found = __builtin_ctz(found);
  return (const uchar *)p + found;
}




static const uchar *  __attribute__((__target__("sse4.2")))


search_line_sse42 (const uchar *s, const uchar *end)
{
  typedef char v16qi __attribute__ ((__vector_size__ (16)));
  static const v16qi search = { '\n', '\r', '?', '\\' };

  uintptr_t si = (uintptr_t)s;
  uintptr_t index;

  
  if (si & 15)
    {
      v16qi sv;

      if (__builtin_expect (end - s < 16, 0)
	  && __builtin_expect ((si & 0xfff) > 0xff0, 0))
	{
	  
	  return search_line_sse2 (s, end);
	}

      
      sv = __builtin_ia32_loaddqu ((const char *) s);
      index = __builtin_ia32_pcmpestri128 (search, 4, sv, 16, 0);

      if (__builtin_expect (index < 16, 0))
	goto found;

      
      s = (const uchar *)((si + 15) & -16);
    }

  

  while (1)
    {
      char f;

      
      __asm ("%vpcmpestri\t$0, %2, %3" : "=c"(index), "=@ccc"(f)
	     : "m"(*s), "x"(search), "a"(4), "d"(16));
      if (f)
	break;
      
      s += 16;
    }

  s -= 16;
  
  __asm (      ".balign 16\n" "0:	add $16, %1\n" "	%vpcmpestri\t$0, (%1), %2\n" "	jnc 0b" : "=&c"(index), "+r"(s)



	: "x"(search), "a"(4), "d"(16));


 found:
  return s + index;
}










typedef const uchar * (*search_line_fast_type) (const uchar *, const uchar *);
static search_line_fast_type search_line_fast;


static inline void init_vectorized_lexer (void)
{
  unsigned dummy, ecx = 0, edx = 0;
  search_line_fast_type impl = search_line_acc_char;
  int minimum = 0;


  minimum = 3;

  minimum = 2;

  minimum = 1;


  if (minimum == 3)
    impl = search_line_sse42;
  else if (__get_cpuid (1, &dummy, &dummy, &ecx, &edx) || minimum == 2)
    {
      if (minimum == 3 || (ecx & bit_SSE4_2))
        impl = search_line_sse42;
      else if (minimum == 2 || (edx & bit_SSE2))
	impl = search_line_sse2;
      else if (minimum == 1 || (edx & bit_SSE))
	impl = search_line_mmx;
    }
  else if (__get_cpuid (0x80000001, &dummy, &dummy, &dummy, &edx))
    {
      if (minimum == 1 || (edx & (bit_MMXEXT | bit_CMOV)) == (bit_MMXEXT | bit_CMOV))
	impl = search_line_mmx;
    }

  search_line_fast = impl;
}





ATTRIBUTE_NO_SANITIZE_UNDEFINED static const uchar * search_line_fast (const uchar *s, const uchar *end ATTRIBUTE_UNUSED)

{
  typedef __attribute__((altivec(vector))) unsigned char vc;

  const vc repl_nl = {
    '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n',  '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n' };

  const vc repl_cr = {
    '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r',  '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r' };

  const vc repl_bs = {
    '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\',  '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\' };

  const vc repl_qm = {
    '?', '?', '?', '?', '?', '?', '?', '?',  '?', '?', '?', '?', '?', '?', '?', '?', };

  const vc zero = { 0 };

  vc data, t;

  
  do {
      vc m_nl, m_cr, m_bs, m_qm;

      data = __builtin_vec_vsx_ld (0, s);
      s += 16;

      m_nl = (vc) __builtin_vec_cmpeq(data, repl_nl);
      m_cr = (vc) __builtin_vec_cmpeq(data, repl_cr);
      m_bs = (vc) __builtin_vec_cmpeq(data, repl_bs);
      m_qm = (vc) __builtin_vec_cmpeq(data, repl_qm);
      t = (m_nl | m_cr) | (m_bs | m_qm);

      
    }
  while (!__builtin_vec_vcmpeq_p(3, t, zero));

  
  s -= 16;

  {


    union {
      vc v;
      
      unsigned long l[(N == 2 || N == 4) ? N : -1];
    } u;
    unsigned long l, i = 0;

    u.v = t;

    
    switch (N)
      {
      case 4:
	l = u.l[i++];
	if (l != 0)
	  break;
	s += sizeof(unsigned long);
	l = u.l[i++];
	if (l != 0)
	  break;
	s += sizeof(unsigned long);
	
      case 2:
	l = u.l[i++];
	if (l != 0)
	  break;
	s += sizeof(unsigned long);
	l = u.l[i];
      }

    

    l = __builtin_clzl(l) >> 3;

    l = __builtin_ctzl(l) >> 3;

    return s + l;


  }
}






static const uchar * search_line_fast (const uchar *s, const uchar *end ATTRIBUTE_UNUSED)
{
  typedef __attribute__((altivec(vector))) unsigned char vc;

  const vc repl_nl = {
    '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n',  '\n', '\n', '\n', '\n', '\n', '\n', '\n', '\n' };

  const vc repl_cr = {
    '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r',  '\r', '\r', '\r', '\r', '\r', '\r', '\r', '\r' };

  const vc repl_bs = {
    '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\',  '\\', '\\', '\\', '\\', '\\', '\\', '\\', '\\' };

  const vc repl_qm = {
    '?', '?', '?', '?', '?', '?', '?', '?',  '?', '?', '?', '?', '?', '?', '?', '?', };

  const vc ones = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, };

  const vc zero = { 0 };

  vc data, mask, t;

  
  data = __builtin_vec_ld(0, (const vc *)s);

  
  mask = __builtin_vec_lvsr(0, s);
  mask = __builtin_vec_perm(zero, ones, mask);
  data &= mask;

  
  s = (const uchar *)((uintptr_t)s & -16);

  
  goto start;
  do {
      vc m_nl, m_cr, m_bs, m_qm;

      s += 16;
      data = __builtin_vec_ld(0, (const vc *)s);

    start:
      m_nl = (vc) __builtin_vec_cmpeq(data, repl_nl);
      m_cr = (vc) __builtin_vec_cmpeq(data, repl_cr);
      m_bs = (vc) __builtin_vec_cmpeq(data, repl_bs);
      m_qm = (vc) __builtin_vec_cmpeq(data, repl_qm);
      t = (m_nl | m_cr) | (m_bs | m_qm);

      
    }
  while (!__builtin_vec_vcmpeq_p(3, t, zero));

  {


    union {
      vc v;
      
      unsigned long l[(N == 2 || N == 4) ? N : -1];
    } u;
    unsigned long l, i = 0;

    u.v = t;

    
    switch (N)
      {
      case 4:
	l = u.l[i++];
	if (l != 0)
	  break;
	s += sizeof(unsigned long);
	l = u.l[i++];
	if (l != 0)
	  break;
	s += sizeof(unsigned long);
	
      case 2:
	l = u.l[i++];
	if (l != 0)
	  break;
	s += sizeof(unsigned long);
	l = u.l[i];
      }

    
    l = __builtin_clzl(l) >> 3;
    return s + l;


  }
}








static const uchar * search_line_fast (const uchar *s, const uchar *end ATTRIBUTE_UNUSED)
{
  const uint8x16_t repl_nl = vdupq_n_u8 ('\n');
  const uint8x16_t repl_cr = vdupq_n_u8 ('\r');
  const uint8x16_t repl_bs = vdupq_n_u8 ('\\');
  const uint8x16_t repl_qm = vdupq_n_u8 ('?');
  const uint8x16_t xmask = (uint8x16_t) vdupq_n_u64 (0x8040201008040201ULL);


  const int16x8_t shift = {8, 8, 8, 8, 0, 0, 0, 0};

  const int16x8_t shift = {0, 0, 0, 0, 8, 8, 8, 8};


  unsigned int found;
  const uint8_t *p;
  uint8x16_t data;
  uint8x16_t t;
  uint16x8_t m;
  uint8x16_t u, v, w;

  
  p = (const uint8_t *)((uintptr_t)s & -16);

  
  if (__builtin_expect ((AARCH64_MIN_PAGE_SIZE - (((uintptr_t) s) & (AARCH64_MIN_PAGE_SIZE - 1)))
			< 16, 0))
    {
      
      uint32_t misalign, mask;

      misalign = (uintptr_t)s & 15;
      mask = (-1u << misalign) & 0xffff;
      data = vld1q_u8 (p);
      t = vceqq_u8 (data, repl_nl);
      u = vceqq_u8 (data, repl_cr);
      v = vorrq_u8 (t, vceqq_u8 (data, repl_bs));
      w = vorrq_u8 (u, vceqq_u8 (data, repl_qm));
      t = vorrq_u8 (v, w);
      t = vandq_u8 (t, xmask);
      m = vpaddlq_u8 (t);
      m = vshlq_u16 (m, shift);
      found = vaddvq_u16 (m);
      found &= mask;
      if (found)
	return (const uchar*)p + __builtin_ctz (found);
    }
  else {
      data = vld1q_u8 ((const uint8_t *) s);
      t = vceqq_u8 (data, repl_nl);
      u = vceqq_u8 (data, repl_cr);
      v = vorrq_u8 (t, vceqq_u8 (data, repl_bs));
      w = vorrq_u8 (u, vceqq_u8 (data, repl_qm));
      t = vorrq_u8 (v, w);
      if (__builtin_expect (vpaddd_u64 ((uint64x2_t)t) != 0, 0))
	goto done;
    }

  do {
      p += 16;
      data = vld1q_u8 (p);
      t = vceqq_u8 (data, repl_nl);
      u = vceqq_u8 (data, repl_cr);
      v = vorrq_u8 (t, vceqq_u8 (data, repl_bs));
      w = vorrq_u8 (u, vceqq_u8 (data, repl_qm));
      t = vorrq_u8 (v, w);
    } while (!vpaddd_u64 ((uint64x2_t)t));

done:
  
  t = vandq_u8 (t, xmask);
  m = vpaddlq_u8 (t);
  m = vshlq_u16 (m, shift);
  found = vaddvq_u16 (m);
  return (((((uintptr_t) p) < (uintptr_t) s) ? s : (const uchar *)p)
	  + __builtin_ctz (found));
}




static const uchar * search_line_fast (const uchar *s, const uchar *end ATTRIBUTE_UNUSED)
{
  const uint8x16_t repl_nl = vdupq_n_u8 ('\n');
  const uint8x16_t repl_cr = vdupq_n_u8 ('\r');
  const uint8x16_t repl_bs = vdupq_n_u8 ('\\');
  const uint8x16_t repl_qm = vdupq_n_u8 ('?');
  const uint8x16_t xmask = (uint8x16_t) vdupq_n_u64 (0x8040201008040201ULL);

  unsigned int misalign, found, mask;
  const uint8_t *p;
  uint8x16_t data;

  
  misalign = (uintptr_t)s & 15;
  p = (const uint8_t *)((uintptr_t)s & -16);
  data = vld1q_u8 (p);

  
  mask = (-1u << misalign) & 0xffff;

  
  goto start;

  do {
      uint8x8_t l;
      uint16x4_t m;
      uint32x2_t n;
      uint8x16_t t, u, v, w;

      p += 16;
      data = vld1q_u8 (p);
      mask = 0xffff;

    start:
      t = vceqq_u8 (data, repl_nl);
      u = vceqq_u8 (data, repl_cr);
      v = vorrq_u8 (t, vceqq_u8 (data, repl_bs));
      w = vorrq_u8 (u, vceqq_u8 (data, repl_qm));
      t = vandq_u8 (vorrq_u8 (v, w), xmask);
      l = vpadd_u8 (vget_low_u8 (t), vget_high_u8 (t));
      m = vpaddl_u8 (l);
      n = vpaddl_u16 (m);
      
      found = vget_lane_u32 ((uint32x2_t) vorr_u64 ((uint64x1_t) n,  vshr_n_u64 ((uint64x1_t) n, 24)), 0);
      found &= mask;
    }
  while (!found);

  
  found = __builtin_ctz (found);
  return (const uchar *)p + found;
}











void _cpp_init_lexer (void)
{

  init_vectorized_lexer ();

}


void _cpp_clean_line (cpp_reader *pfile)
{
  cpp_buffer *buffer;
  const uchar *s;
  uchar c, *d, *p;

  buffer = pfile->buffer;
  buffer->cur_note = buffer->notes_used = 0;
  buffer->cur = buffer->line_base = buffer->next_line;
  buffer->need_line = false;
  s = buffer->next_line;

  if (!buffer->from_stage3)
    {
      const uchar *pbackslash = NULL;

      
      while (1)
	{
	  
	  s = search_line_fast (s, buffer->rlimit);

	  c = *s;
	  if (c == '\\')
	    {
	      
	      pbackslash = s++;
	    }
	  else if (__builtin_expect (c == '?', 0))
	    {
	      if (__builtin_expect (s[1] == '?', false)
		   && _cpp_trigraph_map[s[2]])
		{
		  
		  add_line_note (buffer, s, s[2]);
		  if (CPP_OPTION (pfile, trigraphs))
		    {
		      
		      d = (uchar *) s;
		      *d = _cpp_trigraph_map[s[2]];
		      s += 2;
		      goto slow_path;
		    }
		}
	      
	      s++;
	    }
	  else break;
	}

      
      d = (uchar *) s;

      if (__builtin_expect (s == buffer->rlimit, false))
	goto done;

      
      if (__builtin_expect (c == '\r', false) && s[1] == '\n')
	{
	  s++;
	  if (s == buffer->rlimit)
	    goto done;
	}

      if (__builtin_expect (pbackslash == NULL, true))
	goto done;

      
      p = d;
      while (is_nvspace (p[-1]))
	p--;
      if (p - 1 != pbackslash)
	goto done;

      
      add_line_note (buffer, p - 1, p != d ? ' ' : '\\');
      d = p - 2;
      buffer->next_line = p - 1;

    slow_path:
      while (1)
	{
	  c = *++s;
	  *++d = c;

	  if (c == '\n' || c == '\r')
	    {
	      
	      if (c == '\r' && s != buffer->rlimit && s[1] == '\n')
		s++;
	      if (s == buffer->rlimit)
		break;

	      
	      p = d;
	      while (p != buffer->next_line && is_nvspace (p[-1]))
		p--;
	      if (p == buffer->next_line || p[-1] != '\\')
		break;

	      add_line_note (buffer, p - 1, p != d ? ' ': '\\');
	      d = p - 2;
	      buffer->next_line = p - 1;
	    }
	  else if (c == '?' && s[1] == '?' && _cpp_trigraph_map[s[2]])
	    {
	      
	      add_line_note (buffer, d, s[2]);
	      if (CPP_OPTION (pfile, trigraphs))
		{
		  *d = _cpp_trigraph_map[s[2]];
		  s += 2;
		}
	    }
	}
    }
  else {
      while (*s != '\n' && *s != '\r')
	s++;
      d = (uchar *) s;

      
      if (*s == '\r' && s + 1 != buffer->rlimit && s[1] == '\n')
	s++;
    }

 done:
  *d = '\n';
  
  add_line_note (buffer, d + 1, '\n');
  buffer->next_line = s + 1;
}


static bool warn_in_comment (cpp_reader *pfile, _cpp_line_note *note)
{
  const uchar *p;

  
  if (note->type != '/')
    return false;

  
  if (CPP_OPTION (pfile, trigraphs))
    return note[1].pos == note->pos;

  
  p = note->pos + 3;
  while (is_nvspace (*p))
    p++;

  
  return (*p == '\n' && p < note[1].pos);
}


void _cpp_process_line_notes (cpp_reader *pfile, int in_comment)
{
  cpp_buffer *buffer = pfile->buffer;

  for (;;)
    {
      _cpp_line_note *note = &buffer->notes[buffer->cur_note];
      unsigned int col;

      if (note->pos > buffer->cur)
	break;

      buffer->cur_note++;
      col = CPP_BUF_COLUMN (buffer, note->pos + 1);

      if (note->type == '\\' || note->type == ' ')
	{
	  if (note->type == ' ' && !in_comment)
	    cpp_error_with_line (pfile, CPP_DL_WARNING, pfile->line_table->highest_line, col, "backslash and newline separated by space");

	  if (buffer->next_line > buffer->rlimit)
	    {
	      cpp_error_with_line (pfile, CPP_DL_PEDWARN, pfile->line_table->highest_line, col, "backslash-newline at end of file");
	      
	      buffer->next_line = buffer->rlimit;
	    }

	  buffer->line_base = note->pos;
	  CPP_INCREMENT_LINE (pfile, 0);
	}
      else if (_cpp_trigraph_map[note->type])
	{
	  if (CPP_OPTION (pfile, warn_trigraphs)
	      && (!in_comment || warn_in_comment (pfile, note)))
	    {
	      if (CPP_OPTION (pfile, trigraphs))
		cpp_warning_with_line (pfile, CPP_W_TRIGRAPHS, pfile->line_table->highest_line, col, "trigraph ??%c converted to %c", note->type, (int) _cpp_trigraph_map[note->type]);



	      else {
		  cpp_warning_with_line  (pfile, CPP_W_TRIGRAPHS, pfile->line_table->highest_line, col, "trigraph ??%c ignored, use -trigraphs to enable", note->type);



		}
	    }
	}
      else if (note->type == 0)
	;
      else abort ();
    }
}


bool _cpp_skip_block_comment (cpp_reader *pfile)
{
  cpp_buffer *buffer = pfile->buffer;
  const uchar *cur = buffer->cur;
  uchar c;

  cur++;
  if (*cur == '/')
    cur++;

  for (;;)
    {
      
      c = *cur++;

      if (c == '/')
	{
	  if (cur[-2] == '*')
	    break;

	  
	  if (CPP_OPTION (pfile, warn_comments)
	      && cur[0] == '*' && cur[1] != '/')
	    {
	      buffer->cur = cur;
	      cpp_warning_with_line (pfile, CPP_W_COMMENTS, pfile->line_table->highest_line, CPP_BUF_COL (buffer), "\"/*\" within comment");


	    }
	}
      else if (c == '\n')
	{
	  unsigned int cols;
	  buffer->cur = cur - 1;
	  _cpp_process_line_notes (pfile, true);
	  if (buffer->next_line >= buffer->rlimit)
	    return true;
	  _cpp_clean_line (pfile);

	  cols = buffer->next_line - buffer->line_base;
	  CPP_INCREMENT_LINE (pfile, cols);

	  cur = buffer->cur;
	}
    }

  buffer->cur = cur;
  _cpp_process_line_notes (pfile, true);
  return false;
}


static int skip_line_comment (cpp_reader *pfile)
{
  cpp_buffer *buffer = pfile->buffer;
  location_t orig_line = pfile->line_table->highest_line;

  while (*buffer->cur != '\n')
    buffer->cur++;

  _cpp_process_line_notes (pfile, true);
  return orig_line != pfile->line_table->highest_line;
}


static void skip_whitespace (cpp_reader *pfile, cppchar_t c)
{
  cpp_buffer *buffer = pfile->buffer;
  bool saw_NUL = false;

  do {
      
      if (c == ' ' || c == '\t')
	;
      
      else if (c == '\0')
	saw_NUL = true;
      else if (pfile->state.in_directive && CPP_PEDANTIC (pfile))
	cpp_error_with_line (pfile, CPP_DL_PEDWARN, pfile->line_table->highest_line, CPP_BUF_COL (buffer), "%s in preprocessing directive", c == '\f' ? "form feed" : "vertical tab");



      c = *buffer->cur++;
    }
  
  while (is_nvspace (c));

  if (saw_NUL)
    {
      encoding_rich_location rich_loc (pfile);
      cpp_error_at (pfile, CPP_DL_WARNING, &rich_loc, "null character(s) ignored");
    }

  buffer->cur--;
}


static int name_p (cpp_reader *pfile, const cpp_string *string)
{
  unsigned int i;

  for (i = 0; i < string->len; i++)
    if (!is_idchar (string->text[i]))
      return 0;

  return 1;
}


static void warn_about_normalization (cpp_reader *pfile, const cpp_token *token, const struct normalize_state *s)


{
  if (CPP_OPTION (pfile, warn_normalize) < NORMALIZE_STATE_RESULT (s)
      && !pfile->state.skipping)
    {
      location_t loc = token->src_loc;

      
      if (loc >= RESERVED_LOCATION_COUNT && token->type != CPP_EOF  && (!(pfile->buffer->cur >= pfile->buffer->notes[pfile->buffer->cur_note].pos && !pfile->overlaid_buffer)))




	{
	  source_range tok_range;
	  tok_range.m_start = loc;
	  tok_range.m_finish = linemap_position_for_column (pfile->line_table, CPP_BUF_COLUMN (pfile->buffer, pfile->buffer->cur));


	  loc = COMBINE_LOCATION_DATA (pfile->line_table, loc, tok_range, NULL);
	}

      encoding_rich_location rich_loc (pfile, loc);

      
      unsigned char *buf = XNEWVEC (unsigned char, cpp_token_len (token));
      size_t sz;

      sz = cpp_spell_token (pfile, token, buf, false) - buf;
      if (NORMALIZE_STATE_RESULT (s) == normalized_C)
	cpp_warning_at (pfile, CPP_W_NORMALIZE, &rich_loc, "`%.*s' is not in NFKC", (int) sz, buf);
      else if (CPP_OPTION (pfile, cxx23_identifiers))
	cpp_pedwarning_at (pfile, CPP_W_NORMALIZE, &rich_loc, "`%.*s' is not in NFC", (int) sz, buf);
      else cpp_warning_at (pfile, CPP_W_NORMALIZE, &rich_loc, "`%.*s' is not in NFC", (int) sz, buf);

      free (buf);
    }
}

static const cppchar_t utf8_signifier = 0xC0;


static bool forms_identifier_p (cpp_reader *pfile, int first, struct normalize_state *state)

{
  cpp_buffer *buffer = pfile->buffer;

  if (*buffer->cur == '$')
    {
      if (!CPP_OPTION (pfile, dollars_in_ident))
	return false;

      buffer->cur++;
      if (CPP_OPTION (pfile, warn_dollars) && !pfile->state.skipping)
	{
	  CPP_OPTION (pfile, warn_dollars) = 0;
	  cpp_error (pfile, CPP_DL_PEDWARN, "'$' in identifier or number");
	}

      return true;
    }

  
  if (CPP_OPTION (pfile, extended_identifiers))
    {
      cppchar_t s;
      if (*buffer->cur >= utf8_signifier)
	{
	  if (_cpp_valid_utf8 (pfile, &buffer->cur, buffer->rlimit, 1 + !first, state, &s))
	    return true;
	}
      else if (*buffer->cur == '\\' && (buffer->cur[1] == 'u' || buffer->cur[1] == 'U'))
	{
	  buffer->cur += 2;
	  if (_cpp_valid_ucn (pfile, &buffer->cur, buffer->rlimit, 1 + !first, state, &s, NULL, NULL))
	    return true;
	  buffer->cur -= 2;
	}
    }

  return false;
}


static void maybe_va_opt_error (cpp_reader *pfile)
{
  if (CPP_PEDANTIC (pfile) && !CPP_OPTION (pfile, va_opt))
    {
      
      if (!_cpp_in_system_header (pfile))
	cpp_error (pfile, CPP_DL_PEDWARN, "__VA_OPT__ is not available until C++20");
    }
  else if (!pfile->state.va_args_ok)
    {
      
      cpp_error (pfile, CPP_DL_PEDWARN, "__VA_OPT__ can only appear in the expansion" " of a C++20 variadic macro");

    }
}


static cpp_hashnode * lex_identifier_intern (cpp_reader *pfile, const uchar *base)
{
  cpp_hashnode *result;
  const uchar *cur;
  unsigned int len;
  unsigned int hash = HT_HASHSTEP (0, *base);

  cur = base + 1;
  while (ISIDNUM (*cur))
    {
      hash = HT_HASHSTEP (hash, *cur);
      cur++;
    }
  len = cur - base;
  hash = HT_HASHFINISH (hash, len);
  result = CPP_HASHNODE (ht_lookup_with_hash (pfile->hash_table, base, len, hash, HT_ALLOC));

  
  if (__builtin_expect ((result->flags & NODE_DIAGNOSTIC)
			&& !pfile->state.skipping, 0))
    {
      
      if ((result->flags & NODE_POISONED) && !pfile->state.poisoned_ok)
	cpp_error (pfile, CPP_DL_ERROR, "attempt to use poisoned \"%s\"", NODE_NAME (result));

      
      if (result == pfile->spec_nodes.n__VA_ARGS__ && !pfile->state.va_args_ok)
	{
	  if (CPP_OPTION (pfile, cplusplus))
	    cpp_error (pfile, CPP_DL_PEDWARN, "__VA_ARGS__ can only appear in the expansion" " of a C++11 variadic macro");

	  else cpp_error (pfile, CPP_DL_PEDWARN, "__VA_ARGS__ can only appear in the expansion" " of a C99 variadic macro");


	}

      if (result == pfile->spec_nodes.n__VA_OPT__)
	maybe_va_opt_error (pfile);

      
      if (result->flags & NODE_WARN_OPERATOR)
	cpp_warning (pfile, CPP_W_CXX_OPERATOR_NAMES, "identifier \"%s\" is a special operator name in C++", NODE_NAME (result));

    }

  return result;
}


cpp_hashnode * _cpp_lex_identifier (cpp_reader *pfile, const char *name)
{
  cpp_hashnode *result;
  result = lex_identifier_intern (pfile, (uchar *) name);
  return result;
}


static cpp_hashnode * lex_identifier (cpp_reader *pfile, const uchar *base, bool starts_ucn, struct normalize_state *nst, cpp_hashnode **spelling)

{
  cpp_hashnode *result;
  const uchar *cur;
  unsigned int len;
  unsigned int hash = HT_HASHSTEP (0, *base);

  cur = pfile->buffer->cur;
  if (! starts_ucn)
    {
      while (ISIDNUM (*cur))
	{
	  hash = HT_HASHSTEP (hash, *cur);
	  cur++;
	}
      NORMALIZE_STATE_UPDATE_IDNUM (nst, *(cur - 1));
    }
  pfile->buffer->cur = cur;
  if (starts_ucn || forms_identifier_p (pfile, false, nst))
    {
      
      do {
	while (ISIDNUM (*pfile->buffer->cur))
	  {
	    NORMALIZE_STATE_UPDATE_IDNUM (nst, *pfile->buffer->cur);
	    pfile->buffer->cur++;
	  }
      } while (forms_identifier_p (pfile, false, nst));
      result = _cpp_interpret_identifier (pfile, base, pfile->buffer->cur - base);
      *spelling = cpp_lookup (pfile, base, pfile->buffer->cur - base);
    }
  else {
      len = cur - base;
      hash = HT_HASHFINISH (hash, len);

      result = CPP_HASHNODE (ht_lookup_with_hash (pfile->hash_table, base, len, hash, HT_ALLOC));
      *spelling = result;
    }

  
  if (__builtin_expect ((result->flags & NODE_DIAGNOSTIC)
			&& !pfile->state.skipping, 0))
    {
      
      if ((result->flags & NODE_POISONED) && !pfile->state.poisoned_ok)
	cpp_error (pfile, CPP_DL_ERROR, "attempt to use poisoned \"%s\"", NODE_NAME (result));

      
      if (result == pfile->spec_nodes.n__VA_ARGS__ && !pfile->state.va_args_ok)
	{
	  if (CPP_OPTION (pfile, cplusplus))
	    cpp_error (pfile, CPP_DL_PEDWARN, "__VA_ARGS__ can only appear in the expansion" " of a C++11 variadic macro");

	  else cpp_error (pfile, CPP_DL_PEDWARN, "__VA_ARGS__ can only appear in the expansion" " of a C99 variadic macro");


	}

      
      if (result == pfile->spec_nodes.n__VA_OPT__)
	maybe_va_opt_error (pfile);

      
      if (result->flags & NODE_WARN_OPERATOR)
	cpp_warning (pfile, CPP_W_CXX_OPERATOR_NAMES, "identifier \"%s\" is a special operator name in C++", NODE_NAME (result));

    }

  return result;
}


static void lex_number (cpp_reader *pfile, cpp_string *number, struct normalize_state *nst)

{
  const uchar *cur;
  const uchar *base;
  uchar *dest;

  base = pfile->buffer->cur - 1;
  do {
      const uchar *adj_digit_sep = NULL;
      cur = pfile->buffer->cur;

      
      while (ISIDNUM (*cur)
	     || (*cur == '.' && !DIGIT_SEP (cur[-1]))
	     || DIGIT_SEP (*cur)
	     || (VALID_SIGN (*cur, cur[-1]) && !DIGIT_SEP (cur[-2])))
	{
	  NORMALIZE_STATE_UPDATE_IDNUM (nst, *cur);
	  
	  if (DIGIT_SEP (*cur) && DIGIT_SEP (cur[-1]) && !adj_digit_sep)
	    adj_digit_sep = cur;
	  cur++;
	}
      
      while (cur > pfile->buffer->cur && DIGIT_SEP (cur[-1]))
	--cur;
      if (adj_digit_sep && adj_digit_sep < cur)
	cpp_error (pfile, CPP_DL_ERROR, "adjacent digit separators");

      pfile->buffer->cur = cur;
    }
  while (forms_identifier_p (pfile, false, nst));

  number->len = cur - base;
  dest = _cpp_unaligned_alloc (pfile, number->len + 1);
  memcpy (dest, base, number->len);
  dest[number->len] = '\0';
  number->text = dest;
}


static void create_literal (cpp_reader *pfile, cpp_token *token, const uchar *base, unsigned int len, enum cpp_ttype type)

{
  token->type = type;
  token->val.str.len = len;
  token->val.str.text = cpp_alloc_token_string (pfile, base, len);
}

const uchar * cpp_alloc_token_string (cpp_reader *pfile, const unsigned char *ptr, unsigned len)

{
  uchar *dest = _cpp_unaligned_alloc (pfile, len + 1);

  dest[len] = 0;
  memcpy (dest, ptr, len);
  return dest;
}


struct lit_accum {
  _cpp_buff *first;
  _cpp_buff *last;
  const uchar *rpos;
  size_t accum;

  lit_accum ()
    : first (NULL), last (NULL), rpos (0), accum (0)
  {
  }

  void append (cpp_reader *, const uchar *, size_t);

  void read_begin (cpp_reader *);
  bool reading_p () const {
    return rpos != NULL;
  }
  char read_char ()
  {
    char c = *rpos++;
    if (rpos == BUFF_FRONT (last))
      rpos = NULL;
    return c;
  }
};



void lit_accum::append (cpp_reader *pfile, const uchar *base, size_t len)
{
  if (!last)
    
    first = last = _cpp_get_buff (pfile, len);
  else if (len > BUFF_ROOM (last))
    {
      
      size_t room = BUFF_ROOM (last);
      memcpy (BUFF_FRONT (last), base, room);
      BUFF_FRONT (last) += room;
      base += room;
      len -= room;
      accum += room;

      gcc_checking_assert (!rpos);

      last = _cpp_append_extend_buff (pfile, last, len);
    }

  memcpy (BUFF_FRONT (last), base, len);
  BUFF_FRONT (last) += len;
  accum += len;
}

void lit_accum::read_begin (cpp_reader *pfile)
{
  
  if (BUFF_ROOM (last) < 4)

    last = _cpp_append_extend_buff (pfile, last, 4);
  rpos = BUFF_FRONT (last);
}



static bool is_macro(cpp_reader *pfile, const uchar *base)
{
  const uchar *cur = base;
  if (! ISIDST (*cur))
    return false;
  unsigned int hash = HT_HASHSTEP (0, *cur);
  ++cur;
  while (ISIDNUM (*cur))
    {
      hash = HT_HASHSTEP (hash, *cur);
      ++cur;
    }
  hash = HT_HASHFINISH (hash, cur - base);

  cpp_hashnode *result = CPP_HASHNODE (ht_lookup_with_hash (pfile->hash_table, base, cur - base, hash, HT_NO_INSERT));

  return result && cpp_macro_p (result);
}



static bool is_macro_not_literal_suffix(cpp_reader *pfile, const uchar *base)
{
  
  if (base[0] == '_' && base[1] != '_')
    return false;
  return is_macro (pfile, base);
}



static void lex_raw_string (cpp_reader *pfile, cpp_token *token, const uchar *base)
{
  const uchar *pos = base;

  
  enum cpp_ttype type = CPP_STRING;

  if (*pos == 'L')
    {
      type = CPP_WSTRING;
      pos++;
    }
  else if (*pos == 'U')
    {
      type = CPP_STRING32;
      pos++;
    }
  else if (*pos == 'u')
    {
      if (pos[1] == '8')
	{
	  type = CPP_UTF8STRING;
	  pos++;
	}
      else type = CPP_STRING16;
      pos++;
    }

  gcc_checking_assert (pos[0] == 'R' && pos[1] == '"');
  pos += 2;

  _cpp_line_note *note = &pfile->buffer->notes[pfile->buffer->cur_note];

  
  while (note->pos < pos)
    ++note;

  lit_accum accum;
  
  uchar prefix[17];
  unsigned prefix_len = 0;
  enum Phase {
   PHASE_PREFIX = -2, PHASE_NONE = -1, PHASE_SUFFIX = 0 } phase = PHASE_PREFIX;



  for (;;)
    {
      gcc_checking_assert (note->pos >= pos);

      
      if (!accum.reading_p () && note->pos == pos)
	switch (note->type)
	  {
	  case '\\':
	  case ' ':
	    
	    accum.append (pfile, base, pos - base);
	    base = pos;
	    accum.read_begin (pfile);
	    accum.append (pfile, UC"\\", 1);

	  after_backslash:
	    if (note->type == ' ')
	      
	      accum.append (pfile, UC" ", 1);

	    accum.append (pfile, UC"\n", 1);
	    note++;
	    break;

	  case '\n':
	    
	    gcc_checking_assert (!CPP_OPTION (pfile, trigraphs));
	    note->type = 0;
	    note++;
	    break;

	  default:
	    gcc_checking_assert (_cpp_trigraph_map[note->type]);

	    
	    uchar type = note->type;
	    note->type = 0;

	    if (CPP_OPTION (pfile, trigraphs))
	      {
		accum.append (pfile, base, pos - base);
		base = pos;
		accum.read_begin (pfile);
		accum.append (pfile, UC"??", 2);
		accum.append (pfile, &type, 1);

		
		if (type == '/' && note[1].pos == pos)
		  {
		    note++;
		    gcc_assert (note->type == '\\' || note->type == ' ');
		    goto after_backslash;
		  }
		
		base = ++pos;
	      }

	    note++;
	    break;
	  }

      
      bool read_note = accum.reading_p ();
      char c = read_note ? accum.read_char () : *pos++;

      if (phase == PHASE_PREFIX)
	{
	  if (c == '(')
	    {
	      
	      phase = PHASE_NONE;
	      prefix[prefix_len++] = '"';
	    }
	  else if (prefix_len < 16   && (('Z' - 'A' == 25 ? ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))



			: ISIDST (c))
		       || (c >= '0' && c <= '9')
		       || c == '_' || c == '{' || c == '}' || c == '[' || c == ']' || c == '#' || c == '<' || c == '>' || c == '%' || c == ':' || c == ';' || c == '.' || c == '?' || c == '*' || c == '+' || c == '-' || c == '/' || c == '^' || c == '&' || c == '|' || c == '~' || c == '!' || c == '=' || c == ',' || c == '"' || c == '\''))






	    prefix[prefix_len++] = c;
	  else {
	      
	      int col = CPP_BUF_COLUMN (pfile->buffer, pos) + read_note;
	      if (prefix_len == 16)
		cpp_error_with_line (pfile, CPP_DL_ERROR, token->src_loc, col, "raw string delimiter longer " "than 16 characters");

	      else if (c == '\n')
		cpp_error_with_line (pfile, CPP_DL_ERROR, token->src_loc, col, "invalid new-line in raw " "string delimiter");

	      else cpp_error_with_line (pfile, CPP_DL_ERROR, token->src_loc, col, "invalid character '%c' in " "raw string delimiter", c);


	      type = CPP_OTHER;
	      phase = PHASE_NONE;
	      
	      prefix_len = 0;
	    }
	  if (c != '\n')
	    continue;
	}

      if (phase != PHASE_NONE)
	{
	  if (prefix[phase] != c)
	    phase = PHASE_NONE;
	  else if (unsigned (phase + 1) == prefix_len)
	    break;
	  else {
	      phase = Phase (phase + 1);
	      continue;
	    }
	}

      if (!prefix_len && c == '"')
	
	goto out;
      else if (prefix_len && c == ')')
	phase = PHASE_SUFFIX;
      else if (!read_note && c == '\n')
	{
	  pos--;
	  pfile->buffer->cur = pos;
	  if (pfile->state.in_directive || (pfile->state.parsing_args && pfile->buffer->next_line >= pfile->buffer->rlimit))

	    {
	      cpp_error_with_line (pfile, CPP_DL_ERROR, token->src_loc, 0, "unterminated raw string");
	      type = CPP_OTHER;
	      goto out;
	    }

	  accum.append (pfile, base, pos - base + 1);
	  _cpp_process_line_notes (pfile, false);

	  if (pfile->buffer->next_line < pfile->buffer->rlimit)
	    CPP_INCREMENT_LINE (pfile, 0);
	  pfile->buffer->need_line = true;

	  if (!_cpp_get_fresh_line (pfile))
	    {
	      
	      location_t src_loc = token->src_loc;
	      token->type = CPP_EOF;
	      
	      token->src_loc = pfile->line_table->highest_line;
	      token->flags = BOL;
	      if (accum.first)
		_cpp_release_buff (pfile, accum.first);
	      cpp_error_with_line (pfile, CPP_DL_ERROR, src_loc, 0, "unterminated raw string");
	      
	      _cpp_pop_buffer (pfile);
	      return;
	    }

	  pos = base = pfile->buffer->cur;
	  note = &pfile->buffer->notes[pfile->buffer->cur_note];
	}
    }

  if (CPP_OPTION (pfile, user_literals))
    {
      
      if (is_macro_not_literal_suffix (pfile, pos))
	{
	  
	  if (CPP_OPTION (pfile, warn_literal_suffix) && !pfile->state.skipping)
	    cpp_warning_with_line (pfile, CPP_W_LITERAL_SUFFIX, token->src_loc, 0, "invalid suffix on literal; C++11 requires " "a space between literal and string macro");


	}
      
      else if (ISIDST (*pos))
	{
	  type = cpp_userdef_string_add_type (type);
	  ++pos;

	  while (ISIDNUM (*pos))
	    ++pos;
	}
    }

 out:
  pfile->buffer->cur = pos;
  if (!accum.accum)
    create_literal (pfile, token, base, pos - base, type);
  else {
      size_t extra_len = pos - base;
      uchar *dest = _cpp_unaligned_alloc (pfile, accum.accum + extra_len + 1);

      token->type = type;
      token->val.str.len = accum.accum + extra_len;
      token->val.str.text = dest;
      for (_cpp_buff *buf = accum.first; buf; buf = buf->next)
	{
	  size_t len = BUFF_FRONT (buf) - buf->base;
	  memcpy (dest, buf->base, len);
	  dest += len;
	}
      _cpp_release_buff (pfile, accum.first);
      memcpy (dest, base, extra_len);
      dest[extra_len] = '\0';
    }
}


static void lex_string (cpp_reader *pfile, cpp_token *token, const uchar *base)
{
  bool saw_NUL = false;
  const uchar *cur;
  cppchar_t terminator;
  enum cpp_ttype type;

  cur = base;
  terminator = *cur++;
  if (terminator == 'L' || terminator == 'U')
    terminator = *cur++;
  else if (terminator == 'u')
    {
      terminator = *cur++;
      if (terminator == '8')
	terminator = *cur++;
    }
  if (terminator == 'R')
    {
      lex_raw_string (pfile, token, base);
      return;
    }
  if (terminator == '"')
    type = (*base == 'L' ? CPP_WSTRING :
	    *base == 'U' ? CPP_STRING32 :
	    *base == 'u' ? (base[1] == '8' ? CPP_UTF8STRING : CPP_STRING16)
			 : CPP_STRING);
  else if (terminator == '\'')
    type = (*base == 'L' ? CPP_WCHAR :
	    *base == 'U' ? CPP_CHAR32 :
	    *base == 'u' ? (base[1] == '8' ? CPP_UTF8CHAR : CPP_CHAR16)
			 : CPP_CHAR);
  else terminator = '>', type = CPP_HEADER_NAME;

  for (;;)
    {
      cppchar_t c = *cur++;

      
      if (c == '\\' && !pfile->state.angled_headers && *cur != '\n')
	cur++;
      else if (c == terminator)
	break;
      else if (c == '\n')
	{
	  cur--;
	  
	  if (terminator == '>')
	    {
	      token->type = CPP_LESS;
	      return;
	    }
	  type = CPP_OTHER;
	  break;
	}
      else if (c == '\0')
	saw_NUL = true;
    }

  if (saw_NUL && !pfile->state.skipping)
    cpp_error (pfile, CPP_DL_WARNING, "null character(s) preserved in literal");

  if (type == CPP_OTHER && CPP_OPTION (pfile, lang) != CLK_ASM)
    cpp_error (pfile, CPP_DL_PEDWARN, "missing terminating %c character", (int) terminator);

  if (CPP_OPTION (pfile, user_literals))
    {
      
      if (is_macro_not_literal_suffix (pfile, cur))
	{
	  
	  if (CPP_OPTION (pfile, warn_literal_suffix) && !pfile->state.skipping)
	    cpp_warning_with_line (pfile, CPP_W_LITERAL_SUFFIX, token->src_loc, 0, "invalid suffix on literal; C++11 requires " "a space between literal and string macro");


	}
      
      else if (ISIDST (*cur))
	{
	  type = cpp_userdef_char_add_type (type);
	  type = cpp_userdef_string_add_type (type);
          ++cur;

	  while (ISIDNUM (*cur))
	    ++cur;
	}
    }
  else if (CPP_OPTION (pfile, cpp_warn_cxx11_compat)
	   && is_macro (pfile, cur)
	   && !pfile->state.skipping)
    cpp_warning_with_line (pfile, CPP_W_CXX11_COMPAT, token->src_loc, 0, "C++11 requires a space " "between string literal and macro");


  pfile->buffer->cur = cur;
  create_literal (pfile, token, base, cur - base, type);
}


cpp_comment_table * cpp_get_comments (cpp_reader *pfile)
{
  return &pfile->comments;
}


static void  store_comment (cpp_reader *pfile, cpp_token *token)
{
  int len;

  if (pfile->comments.allocated == 0)
    {
      pfile->comments.allocated = 256; 
      pfile->comments.entries = (cpp_comment *) xmalloc (pfile->comments.allocated * sizeof (cpp_comment));
    }

  if (pfile->comments.count == pfile->comments.allocated)
    {
      pfile->comments.allocated *= 2;
      pfile->comments.entries = (cpp_comment *) xrealloc (pfile->comments.entries, pfile->comments.allocated * sizeof (cpp_comment));

    }

  len = token->val.str.len;

  
  pfile->comments.entries[pfile->comments.count].comment =  (char *) xmalloc (sizeof (char) * (len + 1));
  memcpy (pfile->comments.entries[pfile->comments.count].comment, token->val.str.text, len);
  pfile->comments.entries[pfile->comments.count].comment[len] = '\0';

  
  pfile->comments.entries[pfile->comments.count].sloc = token->src_loc;

  
  pfile->comments.count++;
}


static void save_comment (cpp_reader *pfile, cpp_token *token, const unsigned char *from, cppchar_t type)

{
  unsigned char *buffer;
  unsigned int len, clen, i;

  len = pfile->buffer->cur - from + 1; 

  
  if (is_vspace (pfile->buffer->cur[-1]))
    len--;

  
  clen = ((pfile->state.in_directive || pfile->state.parsing_args)
	  && type == '/') ? len + 2 : len;

  buffer = _cpp_unaligned_alloc (pfile, clen);

  token->type = CPP_COMMENT;
  token->val.str.len = clen;
  token->val.str.text = buffer;

  buffer[0] = '/';
  memcpy (buffer + 1, from, len - 1);

  
  if ((pfile->state.in_directive || pfile->state.parsing_args) && type == '/')
    {
      buffer[1] = '*';
      buffer[clen - 2] = '*';
      buffer[clen - 1] = '/';
      
      for (i = 2; i < (clen - 2); i++)
        if (buffer[i] == '/' && (buffer[i - 1] == '*' || buffer[i + 1] == '*'))
          buffer[i] = '|';
    }

  
  store_comment (pfile, token);
}



static bool fallthrough_comment_p (cpp_reader *pfile, const unsigned char *comment_start)
{
  const unsigned char *from = comment_start + 1;

  switch (CPP_OPTION (pfile, cpp_warn_implicit_fallthrough))
    {
      
    case 0:
    default:
      return false;
      
    case 1:
      return true;
    case 2:
      
      for (; (size_t) (pfile->buffer->cur - from) >= sizeof "fallthru" - 1;
	   from++)
	{
	  
	  if (from[0] != 'f' && from[0] != 'F')
	    continue;
	  if (from[1] != 'a' && from[1] != 'A')
	    continue;
	  if (from[2] != 'l' && from[2] != 'L')
	    continue;
	  if (from[3] != 'l' && from[3] != 'L')
	    continue;
	  from += sizeof "fall" - 1;
	  if (from[0] == 's' || from[0] == 'S')
	    from++;
	  while (*from == ' ' || *from == '\t' || *from == '-')
	    from++;
	  if (from[0] != 't' && from[0] != 'T')
	    continue;
	  if (from[1] != 'h' && from[1] != 'H')
	    continue;
	  if (from[2] != 'r' && from[2] != 'R')
	    continue;
	  if (from[3] == 'u' || from[3] == 'U')
	    return true;
	  if (from[3] != 'o' && from[3] != 'O')
	    continue;
	  if (from[4] != 'u' && from[4] != 'U')
	    continue;
	  if (from[5] != 'g' && from[5] != 'G')
	    continue;
	  if (from[6] != 'h' && from[6] != 'H')
	    continue;
	  return true;
	}
      return false;
    case 3:
    case 4:
      break;
    }

  
  if (*from == '-' || *from == '@')
    {
      size_t len = sizeof "fallthrough" - 1;
      if ((size_t) (pfile->buffer->cur - from - 1) < len)
	return false;
      if (memcmp (from + 1, "fallthrough", len))
	return false;
      if (*from == '@')
	{
	  if (from[len + 1] != '@')
	    return false;
	  len++;
	}
      from += 1 + len;
    }
  
  else if (*from == 'l')
    {
      size_t len = sizeof "int -fallthrough" - 1;
      if ((size_t) (pfile->buffer->cur - from - 1) < len)
	return false;
      if (memcmp (from + 1, "int -fallthrough", len))
	return false;
      from += 1 + len;
      while (*from == ' ' || *from == '\t')
	from++;
    }
  
  else if (CPP_OPTION (pfile, cpp_warn_implicit_fallthrough) == 4)
    {
      while (*from == ' ' || *from == '\t')
	from++;
      if ((size_t) (pfile->buffer->cur - from)  < sizeof "FALLTHRU" - 1)
	return false;
      if (memcmp (from, "FALLTHR", sizeof "FALLTHR" - 1))
	return false;
      from += sizeof "FALLTHR" - 1;
      if (*from == 'U')
	from++;
      else if ((size_t) (pfile->buffer->cur - from)  < sizeof "OUGH" - 1)
	return false;
      else if (memcmp (from, "OUGH", sizeof "OUGH" - 1))
	return false;
      else from += sizeof "OUGH" - 1;
      while (*from == ' ' || *from == '\t')
	from++;
    }
  
  else {
      while (*from == ' ' || *from == '\t' || *from == '.' || *from == '!')
	from++;
      unsigned char f = *from;
      bool all_upper = false;
      if (f == 'E' || f == 'e')
	{
	  if ((size_t) (pfile->buffer->cur - from)
	      < sizeof "else fallthru" - 1)
	    return false;
	  if (f == 'E' && memcmp (from + 1, "LSE", sizeof "LSE" - 1) == 0)
	    all_upper = true;
	  else if (memcmp (from + 1, "lse", sizeof "lse" - 1))
	    return false;
	  from += sizeof "else" - 1;
	  if (*from == ',')
	    from++;
	  if (*from != ' ')
	    return false;
	  from++;
	  if (all_upper && *from == 'f')
	    return false;
	  if (f == 'e' && *from == 'F')
	    return false;
	  f = *from;
	}
      else if (f == 'I' || f == 'i')
	{
	  if ((size_t) (pfile->buffer->cur - from)
	      < sizeof "intentional fallthru" - 1)
	    return false;
	  if (f == 'I' && memcmp (from + 1, "NTENTIONAL", sizeof "NTENTIONAL" - 1) == 0)
	    all_upper = true;
	  else if (memcmp (from + 1, "ntentional", sizeof "ntentional" - 1))
	    return false;
	  from += sizeof "intentional" - 1;
	  if (*from == ' ')
	    {
	      from++;
	      if (all_upper && *from == 'f')
		return false;
	    }
	  else if (all_upper)
	    {
	      if (memcmp (from, "LY F", sizeof "LY F" - 1))
		return false;
	      from += sizeof "LY " - 1;
	    }
	  else {
	      if (memcmp (from, "ly ", sizeof "ly " - 1))
		return false;
	      from += sizeof "ly " - 1;
	    }
	  if (f == 'i' && *from == 'F')
	    return false;
	  f = *from;
	}
      if (f != 'F' && f != 'f')
	return false;
      if ((size_t) (pfile->buffer->cur - from) < sizeof "fallthru" - 1)
	return false;
      if (f == 'F' && memcmp (from + 1, "ALL", sizeof "ALL" - 1) == 0)
	all_upper = true;
      else if (all_upper)
	return false;
      else if (memcmp (from + 1, "all", sizeof "all" - 1))
	return false;
      from += sizeof "fall" - 1;
      if (*from == (all_upper ? 'S' : 's') && from[1] == ' ')
	from += 2;
      else if (*from == ' ' || *from == '-')
	from++;
      else if (*from != (all_upper ? 'T' : 't'))
	return false;
      if ((f == 'f' || *from != 'T') && (all_upper || *from != 't'))
	return false;
      if ((size_t) (pfile->buffer->cur - from) < sizeof "thru" - 1)
	return false;
      if (memcmp (from + 1, all_upper ? "HRU" : "hru", sizeof "hru" - 1))
	{
	  if ((size_t) (pfile->buffer->cur - from) < sizeof "through" - 1)
	    return false;
	  if (memcmp (from + 1, all_upper ? "HROUGH" : "hrough", sizeof "hrough" - 1))
	    return false;
	  from += sizeof "through" - 1;
	}
      else from += sizeof "thru" - 1;
      while (*from == ' ' || *from == '\t' || *from == '.' || *from == '!')
	from++;
      if (*from == '-')
	{
	  from++;
	  if (*comment_start == '*')
	    {
	      do {
		  while (*from && *from != '*' && *from != '\n' && *from != '\r')
		    from++;
		  if (*from != '*' || from[1] == '/')
		    break;
		  from++;
		}
	      while (1);
	    }
	  else while (*from && *from != '\n' && *from != '\r')
	      from++;
	}
    }
  
  if (*comment_start == '*')
    {
      if (*from != '*' || from[1] != '/')
	return false;
    }
  
  else if (*from != '\n')
    return false;

  return true;
}


void _cpp_init_tokenrun (tokenrun *run, unsigned int count)
{
  run->base = XNEWVEC (cpp_token, count);
  run->limit = run->base + count;
  run->next = NULL;
}


static tokenrun * next_tokenrun (tokenrun *run)
{
  if (run->next == NULL)
    {
      run->next = XNEW (tokenrun);
      run->next->prev = run;
      _cpp_init_tokenrun (run->next, 250);
    }

  return run->next;
}


int _cpp_remaining_tokens_num_in_context (cpp_context *context)
{
  if (context->tokens_kind == TOKENS_KIND_DIRECT)
    return (LAST (context).token - FIRST (context).token);
  else if (context->tokens_kind == TOKENS_KIND_INDIRECT || context->tokens_kind == TOKENS_KIND_EXTENDED)
    return (LAST (context).ptoken - FIRST (context).ptoken);
  else abort ();
}


static const cpp_token* _cpp_token_from_context_at (cpp_context *context, int index)
{
  if (context->tokens_kind == TOKENS_KIND_DIRECT)
    return &(FIRST (context).token[index]);
  else if (context->tokens_kind == TOKENS_KIND_INDIRECT || context->tokens_kind == TOKENS_KIND_EXTENDED)
    return FIRST (context).ptoken[index];
 else abort ();
}


const cpp_token * cpp_peek_token (cpp_reader *pfile, int index)
{
  cpp_context *context = pfile->context;
  const cpp_token *peektok;
  int count;

  
  while (context->prev)
    {
      ptrdiff_t sz = _cpp_remaining_tokens_num_in_context (context);

      if (index < (int) sz)
        return _cpp_token_from_context_at (context, index);
      index -= (int) sz;
      context = context->prev;
    }

  
  count = index;
  pfile->keep_tokens++;

  
  void (*line_change) (cpp_reader *, const cpp_token *, int)
    = pfile->cb.line_change;
  pfile->cb.line_change = NULL;

  do {
      peektok = _cpp_lex_token (pfile);
      if (peektok->type == CPP_EOF)
	{
	  index--;
	  break;
	}
      else if (peektok->type == CPP_PRAGMA)
	{
	  
	  if (peektok == &pfile->directive_result)
	    
	    *pfile->cur_token++ = *peektok;
	  index--;
	  break;
	}
    }
  while (index--);

  _cpp_backup_tokens_direct (pfile, count - index);
  pfile->keep_tokens--;
  pfile->cb.line_change = line_change;

  return peektok;
}


cpp_token * _cpp_temp_token (cpp_reader *pfile)
{
  cpp_token *old, *result;
  ptrdiff_t sz = pfile->cur_run->limit - pfile->cur_token;
  ptrdiff_t la = (ptrdiff_t) pfile->lookaheads;

  old = pfile->cur_token - 1;
  
  if (la)
    {
      if (sz <= la)
        {
          tokenrun *next = next_tokenrun (pfile->cur_run);

          if (sz < la)
            memmove (next->base + 1, next->base, (la - sz) * sizeof (cpp_token));

          next->base[0] = pfile->cur_run->limit[-1];
        }

      if (sz > 1)
        memmove (pfile->cur_token + 1, pfile->cur_token, MIN (la, sz - 1) * sizeof (cpp_token));
    }

  if (!sz && pfile->cur_token == pfile->cur_run->limit)
    {
      pfile->cur_run = next_tokenrun (pfile->cur_run);
      pfile->cur_token = pfile->cur_run->base;
    }

  result = pfile->cur_token++;
  result->src_loc = old->src_loc;
  return result;
}



static void cpp_maybe_module_directive (cpp_reader *pfile, cpp_token *result)
{
  unsigned backup = 0; 
  cpp_hashnode *node = result->val.node.node;
  cpp_token *peek = result;
  cpp_token *keyword = peek;
  cpp_hashnode *(&n_modules)[spec_nodes::M_HWM][2] = pfile->spec_nodes.n_modules;
  int header_count = 0;

  
  gcc_checking_assert (!pfile->state.in_deferred_pragma && !pfile->state.skipping && !pfile->state.parsing_args && !pfile->state.angled_headers && (pfile->state.save_comments == !CPP_OPTION (pfile, discard_comments)));





  
  pfile->state.in_deferred_pragma = true;

  
  pfile->state.pragma_allow_expansion = true;
  pfile->directive_line = result->src_loc;

  
  pfile->state.save_comments = 0;

  if (node == n_modules[spec_nodes::M_EXPORT][0])
    {
      peek = _cpp_lex_direct (pfile);
      keyword = peek;
      backup++;
      if (keyword->type != CPP_NAME)
	goto not_module;
      node = keyword->val.node.node;
      if (!(node->flags & NODE_MODULE))
	goto not_module;
    }

  if (node == n_modules[spec_nodes::M__IMPORT][0])
    
    header_count = backup + 2 + 16;
  else if (node == n_modules[spec_nodes::M_IMPORT][0])
    
    header_count = backup + 2 + (CPP_OPTION (pfile, preprocessed) ? 16 : 0);
  else if (node == n_modules[spec_nodes::M_MODULE][0])
    ; 
  else goto not_module;

  
  if (header_count)
    
    pfile->state.angled_headers = true;
  peek = _cpp_lex_direct (pfile);
  backup++;

  
  if (peek->type == CPP_NAME || peek->type == CPP_COLON ||  (header_count ? (peek->type == CPP_LESS || (peek->type == CPP_STRING && peek->val.str.text[0] != 'R')



	      || peek->type == CPP_HEADER_NAME)
	   : peek->type == CPP_SEMICOLON))
    {
      pfile->state.pragma_allow_expansion = !CPP_OPTION (pfile, preprocessed);
      if (!pfile->state.pragma_allow_expansion)
	pfile->state.prevent_expansion++;

      if (!header_count && linemap_included_from (LINEMAPS_LAST_ORDINARY_MAP (pfile->line_table)))
	cpp_error_with_line (pfile, CPP_DL_ERROR, keyword->src_loc, 0, "module control-line cannot be in included file");

      
      for (int ix = backup; ix--;)
	{
	  cpp_token *tok = ix ? keyword : result;
	  cpp_hashnode *node = tok->val.node.node;

	  
	  tok->flags |= NO_EXPAND;
	  if (_cpp_defined_macro_p (node)
	      && _cpp_maybe_notify_macro_use (pfile, node, tok->src_loc)
	      && !cpp_fun_like_macro_p (node))
	    cpp_error_with_line (pfile, CPP_DL_ERROR, tok->src_loc, 0,  "module control-line \"%s\" cannot be" " an object-like macro", NODE_NAME (node));


	}

      
      keyword->val.node.node = n_modules[header_count ? spec_nodes::M_IMPORT : spec_nodes::M_MODULE][1];

      if (backup != 1)
	result->val.node.node = n_modules[spec_nodes::M_EXPORT][1];

      
      pfile->state.directive_file_token = header_count;
    }
  else {
    not_module:
      
      
      pfile->state.save_comments = !CPP_OPTION (pfile, discard_comments);
      pfile->state.in_deferred_pragma = false;
      
      pfile->state.angled_headers = false;
    }

  
  if (backup)
    {
      
      bool eol = peek->type == CPP_PRAGMA_EOL;
      if (!eol || backup > 1)
	{
	  
	  _cpp_backup_tokens_direct (pfile, backup);
	  
	  if (eol)
	    pfile->lookaheads--;
	}
    }
}


const cpp_token * _cpp_lex_token (cpp_reader *pfile)
{
  cpp_token *result;

  for (;;)
    {
      if (pfile->cur_token == pfile->cur_run->limit)
	{
	  pfile->cur_run = next_tokenrun (pfile->cur_run);
	  pfile->cur_token = pfile->cur_run->base;
	}
      
      if (pfile->cur_token < pfile->cur_run->base || pfile->cur_token >= pfile->cur_run->limit)
	abort ();

      if (pfile->lookaheads)
	{
	  pfile->lookaheads--;
	  result = pfile->cur_token++;
	}
      else result = _cpp_lex_direct (pfile);

      if (result->flags & BOL)
	{
	  
	  if (result->type == CPP_HASH  && pfile->state.parsing_args != 1)

	    {
	      if (_cpp_handle_directive (pfile, result->flags & PREV_WHITE))
		{
		  if (pfile->directive_result.type == CPP_PADDING)
		    continue;
		  result = &pfile->directive_result;
		}
	    }
	  else if (pfile->state.in_deferred_pragma)
	    result = &pfile->directive_result;
	  else if (result->type == CPP_NAME && (result->val.node.node->flags & NODE_MODULE)
		   && !pfile->state.skipping  && !pfile->state.parsing_args)

	    {
	      
	      
	      gcc_checking_assert (!pfile->lookaheads);

	      cpp_maybe_module_directive (pfile, result);
	    }

	  if (pfile->cb.line_change && !pfile->state.skipping)
	    pfile->cb.line_change (pfile, result, pfile->state.parsing_args);
	}

      
      if (pfile->state.in_directive || pfile->state.in_deferred_pragma)
	break;

      
      pfile->mi_valid = false;

      if (!pfile->state.skipping || result->type == CPP_EOF)
	break;
    }

  return result;
}


bool _cpp_get_fresh_line (cpp_reader *pfile)
{
  
  if (pfile->state.in_directive)
    return false;

  for (;;)
    {
      cpp_buffer *buffer = pfile->buffer;

      if (!buffer->need_line)
	return true;

      if (buffer->next_line < buffer->rlimit)
	{
	  _cpp_clean_line (pfile);
	  return true;
	}

      
      if (pfile->state.parsing_args)
	return false;

      
      if (buffer->buf != buffer->rlimit && buffer->next_line > buffer->rlimit && !buffer->from_stage3)

	{
	  
	  buffer->next_line = buffer->rlimit;
	}

      if (buffer->prev && !buffer->return_at_eof)
	_cpp_pop_buffer (pfile);
      else {
	  
	  CPP_INCREMENT_LINE (pfile, 0);
	  return false;
	}
    }
}










cpp_token * _cpp_lex_direct (cpp_reader *pfile)
{
  cppchar_t c;
  cpp_buffer *buffer;
  const unsigned char *comment_start;
  bool fallthrough_comment = false;
  cpp_token *result = pfile->cur_token++;

 fresh_line:
  result->flags = 0;
  buffer = pfile->buffer;
  if (buffer->need_line)
    {
      gcc_assert (!pfile->state.in_deferred_pragma);
      if (!_cpp_get_fresh_line (pfile))
	{
	  result->type = CPP_EOF;
	  
	  if (!pfile->state.in_directive && !pfile->state.parsing_args)
	    {
	      
	      result->src_loc = pfile->line_table->highest_line;
	      result->flags = BOL;
	      
	      _cpp_pop_buffer (pfile);
	    }
	  return result;
	}
      if (buffer != pfile->buffer)
	fallthrough_comment = false;
      if (!pfile->keep_tokens)
	{
	  pfile->cur_run = &pfile->base_run;
	  result = pfile->base_run.base;
	  pfile->cur_token = result + 1;
	}
      result->flags = BOL;
      if (pfile->state.parsing_args == 2)
	result->flags |= PREV_WHITE;
    }
  buffer = pfile->buffer;
 update_tokens_line:
  result->src_loc = pfile->line_table->highest_line;

 skipped_white:
  if (buffer->cur >= buffer->notes[buffer->cur_note].pos && !pfile->overlaid_buffer)
    {
      _cpp_process_line_notes (pfile, false);
      result->src_loc = pfile->line_table->highest_line;
    }
  c = *buffer->cur++;

  if (pfile->forced_token_location)
    result->src_loc = pfile->forced_token_location;
  else result->src_loc = linemap_position_for_column (pfile->line_table, CPP_BUF_COLUMN (buffer, buffer->cur));


  switch (c)
    {
    case ' ': case '\t': case '\f': case '\v': case '\0':
      result->flags |= PREV_WHITE;
      skip_whitespace (pfile, c);
      goto skipped_white;

    case '\n':
      
      if (buffer->cur < buffer->rlimit  || (pfile->state.in_directive > 1  && !CPP_OPTION (pfile, traditional)))



	CPP_INCREMENT_LINE (pfile, 0);
      buffer->need_line = true;
      if (pfile->state.in_deferred_pragma)
	{
	  
	  result->type = CPP_PRAGMA_EOL;
	  result->flags &= ~PREV_WHITE;
	  pfile->state.in_deferred_pragma = false;
	  if (!pfile->state.pragma_allow_expansion)
	    pfile->state.prevent_expansion--;
	  return result;
	}
      goto fresh_line;

    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
      {
	struct normalize_state nst = INITIAL_NORMALIZE_STATE;
	result->type = CPP_NUMBER;
	lex_number (pfile, &result->val.str, &nst);
	warn_about_normalization (pfile, result, &nst);
	break;
      }

    case 'L':
    case 'u':
    case 'U':
    case 'R':
      
      if (c == 'L' || CPP_OPTION (pfile, rliterals)
	  || (c != 'R' && CPP_OPTION (pfile, uliterals)))
	{
	  if ((*buffer->cur == '\'' && c != 'R')
	      || *buffer->cur == '"' || (*buffer->cur == 'R' && c != 'R' && buffer->cur[1] == '"' && CPP_OPTION (pfile, rliterals))



	      || (*buffer->cur == '8' && c == 'u' && ((buffer->cur[1] == '"' || (buffer->cur[1] == '\'' && CPP_OPTION (pfile, utf8_char_literals)))


		      || (buffer->cur[1] == 'R' && buffer->cur[2] == '"' && CPP_OPTION (pfile, rliterals)))))
	    {
	      lex_string (pfile, result, buffer->cur - 1);
	      break;
	    }
	}
      

    case '_':
    case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
    case 'g': case 'h': case 'i': case 'j': case 'k': case 'l':
    case 'm': case 'n': case 'o': case 'p': case 'q': case 'r':
    case 's': case 't':           case 'v': case 'w': case 'x':
    case 'y': case 'z':
    case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
    case 'G': case 'H': case 'I': case 'J': case 'K':
    case 'M': case 'N': case 'O': case 'P': case 'Q':
    case 'S': case 'T':           case 'V': case 'W': case 'X':
    case 'Y': case 'Z':
      result->type = CPP_NAME;
      {
	struct normalize_state nst = INITIAL_NORMALIZE_STATE;
	result->val.node.node = lex_identifier (pfile, buffer->cur - 1, false, &nst, &result->val.node.spelling);

	warn_about_normalization (pfile, result, &nst);
      }

      
      if (result->val.node.node->flags & NODE_OPERATOR)
	{
	  result->flags |= NAMED_OP;
	  result->type = (enum cpp_ttype) result->val.node.node->directive_index;
	}

      
      if (fallthrough_comment)
	result->flags |= PREV_FALLTHROUGH;
      break;

    case '\'':
    case '"':
      lex_string (pfile, result, buffer->cur - 1);
      break;

    case '/':
      
      comment_start = buffer->cur;
      c = *buffer->cur;
      
      if (c == '*')
	{
	  if (_cpp_skip_block_comment (pfile))
	    cpp_error (pfile, CPP_DL_ERROR, "unterminated comment");
	}
      else if (c == '/' && ! CPP_OPTION (pfile, traditional))
	{
	  
	  if (_cpp_in_system_header (pfile))
	    ;
	  
	  else if (CPP_OPTION (pfile, lang) == CLK_GNUC89 && CPP_PEDANTIC (pfile)
		   && ! buffer->warned_cplusplus_comments)
	    {
	      if (cpp_error (pfile, CPP_DL_PEDWARN, "C++ style comments are not allowed in ISO C90"))
		cpp_error (pfile, CPP_DL_NOTE, "(this will be reported only once per input file)");
	      buffer->warned_cplusplus_comments = 1;
	    }
	  
	  else if (CPP_OPTION (pfile, cpp_warn_c90_c99_compat) > 0 && ! CPP_OPTION (pfile, cplusplus)
		   && ! buffer->warned_cplusplus_comments)
	    {
	      if (cpp_error (pfile, CPP_DL_WARNING, "C++ style comments are incompatible with C90"))
		cpp_error (pfile, CPP_DL_NOTE, "(this will be reported only once per input file)");
	      buffer->warned_cplusplus_comments = 1;
	    }
	  
	  else if ((CPP_OPTION (pfile, lang) == CLK_STDC89 || CPP_OPTION (pfile, lang) == CLK_STDC94))
	    {
	      
	      if (buffer->cur[1] == '*' || pfile->state.in_directive || pfile->state.skipping)

		{
		  result->type = CPP_DIV;
		  break;
		}
	      else if (! buffer->warned_cplusplus_comments)
		{
		  if (cpp_error (pfile, CPP_DL_ERROR, "C++ style comments are not allowed in " "ISO C90"))

		    cpp_error (pfile, CPP_DL_NOTE, "(this will be reported only once per input " "file)");

		  buffer->warned_cplusplus_comments = 1;
		}
	    }
	  if (skip_line_comment (pfile) && CPP_OPTION (pfile, warn_comments))
	    cpp_warning (pfile, CPP_W_COMMENTS, "multi-line comment");
	}
      else if (c == '=')
	{
	  buffer->cur++;
	  result->type = CPP_DIV_EQ;
	  break;
	}
      else {
	  result->type = CPP_DIV;
	  break;
	}

      if (fallthrough_comment_p (pfile, comment_start))
	fallthrough_comment = true;

      if (pfile->cb.comment)
	{
	  size_t len = pfile->buffer->cur - comment_start;
	  pfile->cb.comment (pfile, result->src_loc, comment_start - 1, len + 1);
	}

      if (!pfile->state.save_comments)
	{
	  result->flags |= PREV_WHITE;
	  goto update_tokens_line;
	}

      if (fallthrough_comment)
	result->flags |= PREV_FALLTHROUGH;

      
      save_comment (pfile, result, comment_start, c);
      break;

    case '<':
      if (pfile->state.angled_headers)
	{
	  lex_string (pfile, result, buffer->cur - 1);
	  if (result->type != CPP_LESS)
	    break;
	}

      result->type = CPP_LESS;
      if (*buffer->cur == '=')
	{
	  buffer->cur++, result->type = CPP_LESS_EQ;
	  if (*buffer->cur == '>' && CPP_OPTION (pfile, cplusplus)
	      && CPP_OPTION (pfile, lang) >= CLK_GNUCXX20)
	    buffer->cur++, result->type = CPP_SPACESHIP;
	}
      else if (*buffer->cur == '<')
	{
	  buffer->cur++;
	  IF_NEXT_IS ('=', CPP_LSHIFT_EQ, CPP_LSHIFT);
	}
      else if (CPP_OPTION (pfile, digraphs))
	{
	  if (*buffer->cur == ':')
	    {
	      
	      if (CPP_OPTION (pfile, cplusplus)
		  && CPP_OPTION (pfile, lang) != CLK_CXX98 && CPP_OPTION (pfile, lang) != CLK_GNUCXX && buffer->cur[1] == ':' && buffer->cur[2] != ':' && buffer->cur[2] != '>')


		break;

	      buffer->cur++;
	      result->flags |= DIGRAPH;
	      result->type = CPP_OPEN_SQUARE;
	    }
	  else if (*buffer->cur == '%')
	    {
	      buffer->cur++;
	      result->flags |= DIGRAPH;
	      result->type = CPP_OPEN_BRACE;
	    }
	}
      break;

    case '>':
      result->type = CPP_GREATER;
      if (*buffer->cur == '=')
	buffer->cur++, result->type = CPP_GREATER_EQ;
      else if (*buffer->cur == '>')
	{
	  buffer->cur++;
	  IF_NEXT_IS ('=', CPP_RSHIFT_EQ, CPP_RSHIFT);
	}
      break;

    case '%':
      result->type = CPP_MOD;
      if (*buffer->cur == '=')
	buffer->cur++, result->type = CPP_MOD_EQ;
      else if (CPP_OPTION (pfile, digraphs))
	{
	  if (*buffer->cur == ':')
	    {
	      buffer->cur++;
	      result->flags |= DIGRAPH;
	      result->type = CPP_HASH;
	      if (*buffer->cur == '%' && buffer->cur[1] == ':')
		buffer->cur += 2, result->type = CPP_PASTE, result->val.token_no = 0;
	    }
	  else if (*buffer->cur == '>')
	    {
	      buffer->cur++;
	      result->flags |= DIGRAPH;
	      result->type = CPP_CLOSE_BRACE;
	    }
	}
      break;

    case '.':
      result->type = CPP_DOT;
      if (ISDIGIT (*buffer->cur))
	{
	  struct normalize_state nst = INITIAL_NORMALIZE_STATE;
	  result->type = CPP_NUMBER;
	  lex_number (pfile, &result->val.str, &nst);
	  warn_about_normalization (pfile, result, &nst);
	}
      else if (*buffer->cur == '.' && buffer->cur[1] == '.')
	buffer->cur += 2, result->type = CPP_ELLIPSIS;
      else if (*buffer->cur == '*' && CPP_OPTION (pfile, cplusplus))
	buffer->cur++, result->type = CPP_DOT_STAR;
      break;

    case '+':
      result->type = CPP_PLUS;
      if (*buffer->cur == '+')
	buffer->cur++, result->type = CPP_PLUS_PLUS;
      else if (*buffer->cur == '=')
	buffer->cur++, result->type = CPP_PLUS_EQ;
      break;

    case '-':
      result->type = CPP_MINUS;
      if (*buffer->cur == '>')
	{
	  buffer->cur++;
	  result->type = CPP_DEREF;
	  if (*buffer->cur == '*' && CPP_OPTION (pfile, cplusplus))
	    buffer->cur++, result->type = CPP_DEREF_STAR;
	}
      else if (*buffer->cur == '-')
	buffer->cur++, result->type = CPP_MINUS_MINUS;
      else if (*buffer->cur == '=')
	buffer->cur++, result->type = CPP_MINUS_EQ;
      break;

    case '&':
      result->type = CPP_AND;
      if (*buffer->cur == '&')
	buffer->cur++, result->type = CPP_AND_AND;
      else if (*buffer->cur == '=')
	buffer->cur++, result->type = CPP_AND_EQ;
      break;

    case '|':
      result->type = CPP_OR;
      if (*buffer->cur == '|')
	buffer->cur++, result->type = CPP_OR_OR;
      else if (*buffer->cur == '=')
	buffer->cur++, result->type = CPP_OR_EQ;
      break;

    case ':':
      result->type = CPP_COLON;
      if (*buffer->cur == ':' && CPP_OPTION (pfile, scope))
	buffer->cur++, result->type = CPP_SCOPE;
      else if (*buffer->cur == '>' && CPP_OPTION (pfile, digraphs))
	{
	  buffer->cur++;
	  result->flags |= DIGRAPH;
	  result->type = CPP_CLOSE_SQUARE;
	}
      break;

    case '*': IF_NEXT_IS ('=', CPP_MULT_EQ, CPP_MULT); break;
    case '=': IF_NEXT_IS ('=', CPP_EQ_EQ, CPP_EQ); break;
    case '!': IF_NEXT_IS ('=', CPP_NOT_EQ, CPP_NOT); break;
    case '^': IF_NEXT_IS ('=', CPP_XOR_EQ, CPP_XOR); break;
    case '#': IF_NEXT_IS ('#', CPP_PASTE, CPP_HASH); result->val.token_no = 0; break;

    case '?': result->type = CPP_QUERY; break;
    case '~': result->type = CPP_COMPL; break;
    case ',': result->type = CPP_COMMA; break;
    case '(': result->type = CPP_OPEN_PAREN; break;
    case ')': result->type = CPP_CLOSE_PAREN; break;
    case '[': result->type = CPP_OPEN_SQUARE; break;
    case ']': result->type = CPP_CLOSE_SQUARE; break;
    case '{': result->type = CPP_OPEN_BRACE; break;
    case '}': result->type = CPP_CLOSE_BRACE; break;
    case ';': result->type = CPP_SEMICOLON; break;

      
    case '@': result->type = CPP_ATSIGN; break;

    default:
      {
	const uchar *base = --buffer->cur;

	
	struct normalize_state nst = INITIAL_NORMALIZE_STATE;
	if (forms_identifier_p (pfile, true, &nst))
	  {
	    result->type = CPP_NAME;
	    result->val.node.node = lex_identifier (pfile, base, true, &nst, &result->val.node.spelling);
	    warn_about_normalization (pfile, result, &nst);
	    break;
	  }

	
	buffer->cur++;
	if (c >= utf8_signifier)
	  {
	    const uchar *pstr = base;
	    cppchar_t s;
	    if (_cpp_valid_utf8 (pfile, &pstr, buffer->rlimit, 0, NULL, &s))
	      buffer->cur = pstr;
	  }
	create_literal (pfile, result, base, buffer->cur - base, CPP_OTHER);
	break;
      }

    }

  
  if (result->src_loc >= RESERVED_LOCATION_COUNT && result->type != CPP_EOF)
    {
      
      if (buffer->cur >= buffer->notes[buffer->cur_note].pos && !pfile->overlaid_buffer)
	_cpp_process_line_notes (pfile, false);

      source_range tok_range;
      tok_range.m_start = result->src_loc;
      tok_range.m_finish = linemap_position_for_column (pfile->line_table, CPP_BUF_COLUMN (buffer, buffer->cur));


      result->src_loc = COMBINE_LOCATION_DATA (pfile->line_table, result->src_loc, tok_range, NULL);

    }

  return result;
}


unsigned int cpp_token_len (const cpp_token *token)
{
  unsigned int len;

  switch (TOKEN_SPELL (token))
    {
    default:		len = 6;				break;
    case SPELL_LITERAL:	len = token->val.str.len;		break;
    case SPELL_IDENT:	len = NODE_LEN (token->val.node.node) * 10;	break;
    }

  return len;
}



static size_t utf8_to_ucn (unsigned char *buffer, const unsigned char *name)
{
  int j;
  int ucn_len = 0;
  int ucn_len_c;
  unsigned t;
  unsigned long utf32;
  
  
  for (t = *name; t & 0x80; t <<= 1)
    ucn_len++;
  
  utf32 = *name & (0x7F >> ucn_len);
  for (ucn_len_c = 1; ucn_len_c < ucn_len; ucn_len_c++)
    {
      utf32 = (utf32 << 6) | (*++name & 0x3F);
      
      
      if ((*name & ~0x3F) != 0x80)
	abort ();
    }
  
  *buffer++ = '\\';
  *buffer++ = 'U';
  for (j = 7; j >= 0; j--)
    *buffer++ = "0123456789abcdef"[(utf32 >> (4 * j)) & 0xF];
  return ucn_len;
}


static const unsigned char * cpp_digraph2name (enum cpp_ttype type)
{
  return digraph_spellings[(int) type - (int) CPP_FIRST_DIGRAPH];
}


unsigned char * _cpp_spell_ident_ucns (unsigned char *buffer, cpp_hashnode *ident)
{
  size_t i;
  const unsigned char *name = NODE_NAME (ident);
	  
  for (i = 0; i < NODE_LEN (ident); i++)
    if (name[i] & ~0x7F)
      {
	i += utf8_to_ucn (buffer, name + i) - 1;
	buffer += 10;
      }
    else *buffer++ = name[i];

  return buffer;
}


unsigned char * cpp_spell_token (cpp_reader *pfile, const cpp_token *token, unsigned char *buffer, bool forstring)

{
  switch (TOKEN_SPELL (token))
    {
    case SPELL_OPERATOR:
      {
	const unsigned char *spelling;
	unsigned char c;

	if (token->flags & DIGRAPH)
	  spelling = cpp_digraph2name (token->type);
	else if (token->flags & NAMED_OP)
	  goto spell_ident;
	else spelling = TOKEN_NAME (token);

	while ((c = *spelling++) != '\0')
	  *buffer++ = c;
      }
      break;

    spell_ident:
    case SPELL_IDENT:
      if (forstring)
	{
	  memcpy (buffer, NODE_NAME (token->val.node.spelling), NODE_LEN (token->val.node.spelling));
	  buffer += NODE_LEN (token->val.node.spelling);
	}
      else buffer = _cpp_spell_ident_ucns (buffer, token->val.node.node);
      break;

    case SPELL_LITERAL:
      memcpy (buffer, token->val.str.text, token->val.str.len);
      buffer += token->val.str.len;
      break;

    case SPELL_NONE:
      cpp_error (pfile, CPP_DL_ICE, "unspellable token %s", TOKEN_NAME (token));
      break;
    }

  return buffer;
}


unsigned char * cpp_token_as_text (cpp_reader *pfile, const cpp_token *token)
{ 
  unsigned int len = cpp_token_len (token) + 1;
  unsigned char *start = _cpp_unaligned_alloc (pfile, len), *end;

  end = cpp_spell_token (pfile, token, start, false);
  end[0] = '\0';

  return start;
}


const char * cpp_type2name (enum cpp_ttype type, unsigned char flags)
{
  if (flags & DIGRAPH)
    return (const char *) cpp_digraph2name (type);
  else if (flags & NAMED_OP)
    return cpp_named_operator2name (type);

  return (const char *) token_spellings[type].name;
}


void cpp_output_token (const cpp_token *token, FILE *fp)
{
  switch (TOKEN_SPELL (token))
    {
    case SPELL_OPERATOR:
      {
	const unsigned char *spelling;
	int c;

	if (token->flags & DIGRAPH)
	  spelling = cpp_digraph2name (token->type);
	else if (token->flags & NAMED_OP)
	  goto spell_ident;
	else spelling = TOKEN_NAME (token);

	c = *spelling;
	do putc (c, fp);
	while ((c = *++spelling) != '\0');
      }
      break;

    spell_ident:
    case SPELL_IDENT:
      {
	size_t i;
	const unsigned char * name = NODE_NAME (token->val.node.node);
	
	for (i = 0; i < NODE_LEN (token->val.node.node); i++)
	  if (name[i] & ~0x7F)
	    {
	      unsigned char buffer[10];
	      i += utf8_to_ucn (buffer, name + i) - 1;
	      fwrite (buffer, 1, 10, fp);
	    }
	  else fputc (NODE_NAME (token->val.node.node)[i], fp);
      }
      break;

    case SPELL_LITERAL:
      if (token->type == CPP_HEADER_NAME)
	fputc ('"', fp);
      fwrite (token->val.str.text, 1, token->val.str.len, fp);
      if (token->type == CPP_HEADER_NAME)
	fputc ('"', fp);
      break;

    case SPELL_NONE:
      
      break;
    }
}


int _cpp_equiv_tokens (const cpp_token *a, const cpp_token *b)
{
  if (a->type == b->type && a->flags == b->flags)
    switch (TOKEN_SPELL (a))
      {
      default:			
      case SPELL_OPERATOR:
	
	return (a->type != CPP_PASTE || a->val.token_no == b->val.token_no);
      case SPELL_NONE:
	return (a->type != CPP_MACRO_ARG || (a->val.macro_arg.arg_no == b->val.macro_arg.arg_no && a->val.macro_arg.spelling == b->val.macro_arg.spelling));

      case SPELL_IDENT:
	return (a->val.node.node == b->val.node.node && a->val.node.spelling == b->val.node.spelling);
      case SPELL_LITERAL:
	return (a->val.str.len == b->val.str.len && !memcmp (a->val.str.text, b->val.str.text, a->val.str.len));

      }

  return 0;
}


int cpp_avoid_paste (cpp_reader *pfile, const cpp_token *token1, const cpp_token *token2)

{
  enum cpp_ttype a = token1->type, b = token2->type;
  cppchar_t c;

  if (token1->flags & NAMED_OP)
    a = CPP_NAME;
  if (token2->flags & NAMED_OP)
    b = CPP_NAME;

  c = EOF;
  if (token2->flags & DIGRAPH)
    c = digraph_spellings[(int) b - (int) CPP_FIRST_DIGRAPH][0];
  else if (token_spellings[b].category == SPELL_OPERATOR)
    c = token_spellings[b].name[0];

  
  if ((int) a <= (int) CPP_LAST_EQ && c == '=')
    return 1;

  switch (a)
    {
    case CPP_GREATER:	return c == '>';
    case CPP_LESS:	return c == '<' || c == '%' || c == ':';
    case CPP_PLUS:	return c == '+';
    case CPP_MINUS:	return c == '-' || c == '>';
    case CPP_DIV:	return c == '/' || c == '*'; 
    case CPP_MOD:	return c == ':' || c == '>';
    case CPP_AND:	return c == '&';
    case CPP_OR:	return c == '|';
    case CPP_COLON:	return c == ':' || c == '>';
    case CPP_DEREF:	return c == '*';
    case CPP_DOT:	return c == '.' || c == '%' || b == CPP_NUMBER;
    case CPP_HASH:	return c == '#' || c == '%'; 
    case CPP_PRAGMA:
    case CPP_NAME:	return ((b == CPP_NUMBER && name_p (pfile, &token2->val.str))
				|| b == CPP_NAME || b == CPP_CHAR || b == CPP_STRING);
    case CPP_NUMBER:	return (b == CPP_NUMBER || b == CPP_NAME || b == CPP_CHAR || c == '.' || c == '+' || c == '-');

				      
    case CPP_OTHER:	return ((token1->val.str.text[0] == '\\' && b == CPP_NAME)
				|| (CPP_OPTION (pfile, objc)
				    && token1->val.str.text[0] == '@' && (b == CPP_NAME || b == CPP_STRING)));
    case CPP_LESS_EQ:	return c == '>';
    case CPP_STRING:
    case CPP_WSTRING:
    case CPP_UTF8STRING:
    case CPP_STRING16:
    case CPP_STRING32:	return (CPP_OPTION (pfile, user_literals)
				&& (b == CPP_NAME || (TOKEN_SPELL (token2) == SPELL_LITERAL && ISIDST (token2->val.str.text[0]))));


    default:		break;
    }

  return 0;
}


void cpp_output_line (cpp_reader *pfile, FILE *fp)
{
  const cpp_token *token;

  token = cpp_get_token (pfile);
  while (token->type != CPP_EOF)
    {
      cpp_output_token (token, fp);
      token = cpp_get_token (pfile);
      if (token->flags & PREV_WHITE)
	putc (' ', fp);
    }

  putc ('\n', fp);
}


unsigned char * cpp_output_line_to_string (cpp_reader *pfile, const unsigned char *dir_name)
{
  const cpp_token *token;
  unsigned int out = dir_name ? ustrlen (dir_name) : 0;
  unsigned int alloced = 120 + out;
  unsigned char *result = (unsigned char *) xmalloc (alloced);

  
  if (dir_name)
    {
      sprintf ((char *) result, "#%s ", dir_name);
      out += 2;
    }

  token = cpp_get_token (pfile);
  while (token->type != CPP_EOF)
    {
      unsigned char *last;
      
      unsigned int len = cpp_token_len (token) + 2;

      if (out + len > alloced)
	{
	  alloced *= 2;
	  if (out + len > alloced)
	    alloced = out + len;
	  result = (unsigned char *) xrealloc (result, alloced);
	}

      last = cpp_spell_token (pfile, token, &result[out], 0);
      out = last - result;

      token = cpp_get_token (pfile);
      if (token->flags & PREV_WHITE)
	result[out++] = ' ';
    }

  result[out] = '\0';
  return result;
}







  #error BUFF_SIZE_UPPER_BOUND must be at least as large as MIN_BUFF_SIZE!



static _cpp_buff * new_buff (size_t len)
{
  _cpp_buff *result;
  unsigned char *base;

  if (len < MIN_BUFF_SIZE)
    len = MIN_BUFF_SIZE;
  len = CPP_ALIGN (len);


  
  size_t slen = CPP_ALIGN2 (sizeof (_cpp_buff), 2 * DEFAULT_ALIGNMENT);
  base = XNEWVEC (unsigned char, len + slen);
  result = (_cpp_buff *) base;
  base += slen;

  base = XNEWVEC (unsigned char, len + sizeof (_cpp_buff));
  result = (_cpp_buff *) (base + len);

  result->base = base;
  result->cur = base;
  result->limit = base + len;
  result->next = NULL;
  return result;
}


void _cpp_release_buff (cpp_reader *pfile, _cpp_buff *buff)
{
  _cpp_buff *end = buff;

  while (end->next)
    end = end->next;
  end->next = pfile->free_buffs;
  pfile->free_buffs = buff;
}


_cpp_buff * _cpp_get_buff (cpp_reader *pfile, size_t min_size)
{
  _cpp_buff *result, **p;

  for (p = &pfile->free_buffs;; p = &(*p)->next)
    {
      size_t size;

      if (*p == NULL)
	return new_buff (min_size);
      result = *p;
      size = result->limit - result->base;
      
      if (size >= min_size && size <= BUFF_SIZE_UPPER_BOUND (min_size))
	break;
    }

  *p = result->next;
  result->next = NULL;
  result->cur = result->base;
  return result;
}


_cpp_buff * _cpp_append_extend_buff (cpp_reader *pfile, _cpp_buff *buff, size_t min_extra)
{
  size_t size = EXTENDED_BUFF_SIZE (buff, min_extra);
  _cpp_buff *new_buff = _cpp_get_buff (pfile, size);

  buff->next = new_buff;
  memcpy (new_buff->base, buff->cur, BUFF_ROOM (buff));
  return new_buff;
}


void _cpp_extend_buff (cpp_reader *pfile, _cpp_buff **pbuff, size_t min_extra)
{
  _cpp_buff *new_buff, *old_buff = *pbuff;
  size_t size = EXTENDED_BUFF_SIZE (old_buff, min_extra);

  new_buff = _cpp_get_buff (pfile, size);
  memcpy (new_buff->base, old_buff->cur, BUFF_ROOM (old_buff));
  new_buff->next = old_buff;
  *pbuff = new_buff;
}


void _cpp_free_buff (_cpp_buff *buff)
{
  _cpp_buff *next;

  for (; buff; buff = next)
    {
      next = buff->next;

      free (buff);

      free (buff->base);

    }
}


unsigned char * _cpp_unaligned_alloc (cpp_reader *pfile, size_t len)
{
  _cpp_buff *buff = pfile->u_buff;
  unsigned char *result = buff->cur;

  if (len > (size_t) (buff->limit - result))
    {
      buff = _cpp_get_buff (pfile, len);
      buff->next = pfile->u_buff;
      pfile->u_buff = buff;
      result = buff->cur;
    }

  buff->cur = result + len;
  return result;
}


unsigned char * _cpp_aligned_alloc (cpp_reader *pfile, size_t len)
{
  _cpp_buff *buff = pfile->a_buff;
  unsigned char *result = buff->cur;

  if (len > (size_t) (buff->limit - result))
    {
      buff = _cpp_get_buff (pfile, len);
      buff->next = pfile->a_buff;
      pfile->a_buff = buff;
      result = buff->cur;
    }

  buff->cur = result + len;
  return result;
}



void * _cpp_commit_buff (cpp_reader *pfile, size_t size)
{
  void *ptr = BUFF_FRONT (pfile->a_buff);

  if (pfile->hash_table->alloc_subobject)
    {
      void *copy = pfile->hash_table->alloc_subobject (size);
      memcpy (copy, ptr, size);
      ptr = copy;
    }
  else BUFF_FRONT (pfile->a_buff) += size;

  return ptr;
}



enum cpp_token_fld_kind cpp_token_val_index (const cpp_token *tok)
{
  switch (TOKEN_SPELL (tok))
    {
    case SPELL_IDENT:
      return CPP_TOKEN_FLD_NODE;
    case SPELL_LITERAL:
      return CPP_TOKEN_FLD_STR;
    case SPELL_OPERATOR:
      
      if (tok->flags & NAMED_OP)
	return CPP_TOKEN_FLD_NODE;
      else if (tok->type == CPP_PASTE)
	return CPP_TOKEN_FLD_TOKEN_NO;
      else return CPP_TOKEN_FLD_NONE;
    case SPELL_NONE:
      if (tok->type == CPP_MACRO_ARG)
	return CPP_TOKEN_FLD_ARG_NO;
      else if (tok->type == CPP_PADDING)
	return CPP_TOKEN_FLD_SOURCE;
      else if (tok->type == CPP_PRAGMA)
	return CPP_TOKEN_FLD_PRAGMA;
      
    default:
      return CPP_TOKEN_FLD_NONE;
    }
}



void cpp_force_token_locations (cpp_reader *r, location_t loc)
{
  r->forced_token_location = loc;
}



void cpp_stop_forcing_token_locations (cpp_reader *r)
{
  r->forced_token_location = 0;
}



static const unsigned char * do_peek_backslash (const unsigned char *peek, const unsigned char *limit)
{
  const unsigned char *probe = peek;

  if (__builtin_expect (peek[1] == '\n', true))
    {
    eol:
      probe += 2;
      if (__builtin_expect (probe < limit, true))
	{
	  peek = probe;
	  if (*peek == '\\')
	    
	    return do_peek_backslash (peek, limit);
	}
    }
  else if (__builtin_expect (peek[1] == '\r', false))
    {
      if (probe[2] == '\n')
	probe++;
      goto eol;
    }

  return peek;
}

static const unsigned char * do_peek_next (const unsigned char *peek, const unsigned char *limit)
{
  if (__builtin_expect (*peek == '\\', false))
    peek = do_peek_backslash (peek, limit);
  return peek;
}

static const unsigned char * do_peek_prev (const unsigned char *peek, const unsigned char *bound)
{
  if (peek == bound)
    return NULL;

  unsigned char c = *--peek;
  if (__builtin_expect (c == '\n', false)
      || __builtin_expect (c == 'r', false))
    {
      if (peek == bound)
	return peek;
      int ix = -1;
      if (c == '\n' && peek[ix] == '\r')
	{
	  if (peek + ix == bound)
	    return peek;
	  ix--;
	}

      if (peek[ix] == '\\')
	return do_peek_prev (peek + ix, bound);

      return peek;
    }
  else return peek;
}



static const unsigned char * do_peek_ident (const char *match, const unsigned char *peek, const unsigned char *limit)

{
  for (; *++match; peek++)
    if (*peek != *match)
      {
	peek = do_peek_next (peek, limit);
	if (*peek != *match)
	  return NULL;
      }

  
  peek = do_peek_next (peek, limit);
  if (ISIDNUM (*peek))
    return NULL;

  
 ws:
  while (*peek == ' ' || *peek == '\t')
    peek++;
  if (__builtin_expect (*peek == '\\', false))
    {
      peek = do_peek_backslash (peek, limit);
      if (*peek != '\\')
	goto ws;
    }

  return peek;
}



static bool do_peek_module (cpp_reader *pfile, unsigned char c, const unsigned char *peek, const unsigned char *limit)

{
  bool import = false;

  if (__builtin_expect (c == 'e', false))
    {
      if (!((peek[0] == 'x' || peek[0] == '\\')
	    && (peek = do_peek_ident ("export", peek, limit))))
	return false;

      
      if (peek[0] == 'i')
	{
	  if (!((peek[1] == 'm' || peek[1] == '\\')
		&& (peek = do_peek_ident ("import", peek + 1, limit))))
	    return false;
	  import = true;
	}
      else if (peek[0] == 'm')
	{
	  if (!((peek[1] == 'o' || peek[1] == '\\')
		&& (peek = do_peek_ident ("module", peek + 1, limit))))
	    return false;
	}
      else return false;
    }
  else if (__builtin_expect (c == 'i', false))
    {
      if (!((peek[0] == 'm' || peek[0] == '\\')
	    && (peek = do_peek_ident ("import", peek, limit))))
	return false;
      import = true;
    }
  else if (__builtin_expect (c == '_', false))
    {
      
      if (!((peek[0] == '_' || peek[0] == '\\')
	    && (peek = do_peek_ident ("__import", peek, limit))))
	return false;
      import = true;
    }
  else if (__builtin_expect (c == 'm', false))
    {
      if (!((peek[0] == 'o' || peek[0] == '\\')
	    && (peek = do_peek_ident ("module", peek, limit))))
	return false;
    }
  else return false;

  
  
  unsigned char p = *peek++;
      
  
  
  if (p == 'u')
    {
      peek = do_peek_next (peek, limit);
      if (*peek == '8')
	{
	  peek++;
	  goto peek_u8;
	}
      goto peek_u;
    }
  else if (p == 'U' || p == 'L')
    {
    peek_u8:
      peek = do_peek_next (peek, limit);
    peek_u:
      if (*peek == '\"' || *peek == '\'')
	return false;

      if (*peek == 'R')
	goto peek_R;
      
    }
  else if (p == 'R')
    {
    peek_R:
      if (CPP_OPTION (pfile, rliterals))
	{
	  peek = do_peek_next (peek, limit);
	  if (*peek == '\"')
	    return false;
	}
      
    }
  else if ('Z' - 'A' == 25 ? ((p >= 'A' && p <= 'Z') || (p >= 'a' && p <= 'z') || p == '_')
	   : ISIDST (p))
    {
      
    }
  else if (p == '<')
    {
      
      if (!import)
	return false;
      peek = do_peek_next (peek, limit);
      if (*peek == '=' || *peek == '<' || (*peek == ':' && CPP_OPTION (pfile, digraphs)))
	return false;
    }
  else if (p == ';')
    {
      
      if (import)
	return false;
    }
  else if (p == '"')
    {
      
      if (!import)
	return false;
    }
  else if (p == ':')
    {
      
      peek = do_peek_next (peek, limit);
      if (*peek == ':' || (*peek == '>' && CPP_OPTION (pfile, digraphs)))
	return false;
    }
  else  return false;


  return true;
}



void cpp_directive_only_process (cpp_reader *pfile, void *data, void (*cb) (cpp_reader *, CPP_DO_task, void *, ...))


{
  bool module_p = CPP_OPTION (pfile, module_directives);

  do {
    restart:
      
      cpp_buffer *buffer = pfile->buffer;
      buffer->cur_note = buffer->notes_used = 0;
      buffer->cur = buffer->line_base = buffer->next_line;
      buffer->need_line = false;
      
      gcc_assert (buffer->rlimit[0] == '\n' || buffer->rlimit[0] == '\r');

      const unsigned char *base = buffer->cur;
      unsigned line_count = 0;
      const unsigned char *line_start = base;

      bool bol = true;
      bool raw = false;

      const unsigned char *lwm = base;
      for (const unsigned char *pos = base, *limit = buffer->rlimit;
	   pos < limit;)
	{
	  unsigned char c = *pos++;
	  
	  switch (c)
	    {
	    case ' ': case '\t': case '\f': case '\v':
	      
	      break;

	    case '\r': 
	      if (*pos == '\n')
		pos++;
	      

	    case '\n':
	      bol = true;

	    next_line:
	      CPP_INCREMENT_LINE (pfile, 0);
	      line_count++;
	      line_start = pos;
	      break;

	    case '\\':
	      
	      if (*pos == '\n')
		{
		  pos++;
		  goto next_line;
		}
	      else if (*pos == '\r')
		{
		  if (pos[1] == '\n')
		    pos++;
		  pos++;
		  goto next_line;
		}
	      goto dflt;
	      
	    case '#':
	      if (bol)
		{
		  
		  if (pos - 1 > base && !pfile->state.skipping)
		    cb (pfile, CPP_DO_print, data, line_count, base, pos - 1 - base);

		  
		  buffer->next_line = pos;
		  buffer->need_line = true;
		  bool ok = _cpp_get_fresh_line (pfile);
		  gcc_checking_assert (ok);

		  
		  buffer->line_base -= pos - line_start;

		  _cpp_handle_directive (pfile, line_start + 1 != pos);

		  
		  
		  pfile->line_table->highest_location = pfile->line_table->highest_line;

		  if (!pfile->state.skipping && pfile->buffer->next_line < pfile->buffer->rlimit)
		    cb (pfile, CPP_DO_location, data, pfile->line_table->highest_line);

		  goto restart;
		}
	      goto dflt;

	    case '/':
	      {
		const unsigned char *peek = do_peek_next (pos, limit);
		if (!(*peek == '/' || *peek == '*'))
		  goto dflt;

		
		bool is_block = *peek == '*';
		bool star = false;
		bool esc = false;
		location_t sloc = linemap_position_for_column (pfile->line_table, pos - line_start);


		while (pos < limit)
		  {
		    char c = *pos++;
		    switch (c)
		      {
		      case '\\':
			esc = true;
			break;

		      case '\r':
			if (*pos == '\n')
			  pos++;
			

		      case '\n':
			{
			  CPP_INCREMENT_LINE (pfile, 0);
			  line_count++;
			  line_start = pos;
			  if (!esc && !is_block)
			    {
			      bol = true;
			      goto done_comment;
			    }
			}
			if (!esc)
			  star = false;
			esc = false;
			break;

		      case '*':
			if (pos > peek && !esc)
			  star = is_block;
			esc = false;
			break;

		      case '/':
			if (star)
			  goto done_comment;
			

		      default:
			star = false;
			esc = false;
			break;
		      }
		  }
		if (pos < limit || is_block)
		  cpp_error_with_line (pfile, CPP_DL_ERROR, sloc, 0, "unterminated comment");
	      done_comment:
		lwm = pos;
		break;
	      }

	    case '\'':
	      if (!CPP_OPTION (pfile, digit_separators))
		goto delimited_string;

	      
	      if (!ISIDNUM (*do_peek_next (pos, limit)))
		goto delimited_string;

	      goto quote_peek;

	    case '\"':
	      if (!CPP_OPTION (pfile, rliterals))
		goto delimited_string;

	    quote_peek:
	      {
		
		
		const unsigned char *peek = pos - 1;
		bool quote_first = c == '"';
		bool quote_eight = false;
		bool maybe_number_start = false;
		bool want_number = false;

		while ((peek = do_peek_prev (peek, lwm)))
		  {
		    unsigned char p = *peek;
		    if (quote_first)
		      {
			if (!raw)
			  {
			    if (p != 'R')
			      break;
			    raw = true;
			    continue;
			  }

			quote_first = false;
			if (p == 'L' || p == 'U' || p == 'u')
			  ;
			else if (p == '8')
			  quote_eight = true;
			else goto second_raw;
		      }
		    else if (quote_eight)
		      {
			if (p != 'u')
			  {
			    raw = false;
			    break;
			  }
			quote_eight = false;
		      }
		    else if (c == '"')
		      {
		      second_raw:;
			if (!want_number && ISIDNUM (p))
			  {
			    raw = false;
			    break;
			  }
		      }

		    if (ISDIGIT (p))
		      maybe_number_start = true;
		    else if (p == '.')
		      want_number = true;
		    else if (ISIDNUM (p))
		      maybe_number_start = false;
		    else if (p == '+' || p == '-')
		      {
			if (const unsigned char *peek_prev = do_peek_prev (peek, lwm))
			  {
			    p = *peek_prev;
			    if (p == 'e' || p == 'E' || p == 'p' || p == 'P')
			      {
				want_number = true;
				maybe_number_start = false;
			      }
			    else break;
			  }
			else break;
		      }
		    else if (p == '\'' || p == '\"')
		      {
			
			if (peek == lwm && CPP_OPTION (pfile, uliterals))
			  {
			    if  (!maybe_number_start && !want_number)
			      
			      raw = false;
			  }
			else if (p == '\'' && CPP_OPTION (pfile, digit_separators))
			  maybe_number_start = true;
			break;
		      }
		    else if (c == '\'')
		      break;
		    else if (!quote_first && !quote_eight)
		      break;
		  }

		if (maybe_number_start)
		  {
		    if (c == '\'')
		      
		      goto dflt;
		    raw = false;
		  }

		goto delimited_string;
	      }

	    delimited_string:
	      {
		
		unsigned char end = c;
		int delim_len = -1;
		const unsigned char *delim = NULL;
		location_t sloc = linemap_position_for_column (pfile->line_table, pos - line_start);
		int esc = 0;

		if (raw)
		  {
		    
		    delim = pos;
		    for (delim_len = 0; (c = *pos++) != '('; delim_len++)
		      {
			if (delim_len == 16)
			  {
			    cpp_error_with_line (pfile, CPP_DL_ERROR, sloc, 0, "raw string delimiter" " longer than %d" " characters", delim_len);




			    raw = false;
			    pos = delim;
			    break;
			  }
			if (strchr (") \\\t\v\f\n", c))
			  {
			    cpp_error_with_line (pfile, CPP_DL_ERROR, sloc, 0, "invalid character '%c'" " in raw string" " delimiter", c);



			    raw = false;
			    pos = delim;
			    break;
			  }
			if (pos >= limit)
			  goto bad_string;
		      }
		  }

		while (pos < limit)
		  {
		    char c = *pos++;
		    switch (c)
		      {
		      case '\\':
			if (!raw)
			  esc++;
			break;

		      case '\r':
			if (*pos == '\n')
			  pos++;
			

		      case '\n':
			{
			  CPP_INCREMENT_LINE (pfile, 0);
			  line_count++;
			  line_start = pos;
			}
			if (esc)
			  esc--;
			break;

		      case ')':
			if (raw && pos + delim_len + 1 < limit && pos[delim_len] == end && !memcmp (delim, pos, delim_len))


			  {
			    pos += delim_len + 1;
			    raw = false;
			    goto done_string;
			  }
			break;

		      default:
			if (!raw && !(esc & 1) && c == end)
			  goto done_string;
			esc = 0;
			break;
		      }
		  }
	      bad_string:
		cpp_error_with_line (pfile, CPP_DL_ERROR, sloc, 0, "unterminated literal");
		
	      done_string:
		raw = false;
		lwm = pos - 1;
	      }
	      goto dflt;

	    case '_':
	    case 'e':
	    case 'i':
	    case 'm':
	      if (bol && module_p && !pfile->state.skipping && do_peek_module (pfile, c, pos, limit))
		{
		  
		  pos--; 

		  
		  while (pos > line_start && (pos[-1] == ' ' || pos[-1] == '\t'))
		    pos--;

		  if (pos > base)
		    cb (pfile, CPP_DO_print, data, line_count, base, pos - base);

		  
		  buffer->next_line = pos;
		  buffer->need_line = true;

		  
		  do {
		      location_t spelling;
		      const cpp_token *tok = cpp_get_token_with_location (pfile, &spelling);

		      gcc_assert (pfile->state.in_deferred_pragma || tok->type == CPP_PRAGMA_EOL);
		      cb (pfile, CPP_DO_token, data, tok, spelling);
		    }
		  while (pfile->state.in_deferred_pragma);

		  if (pfile->buffer->next_line < pfile->buffer->rlimit)
		    cb (pfile, CPP_DO_location, data, pfile->line_table->highest_line);

		  pfile->mi_valid = false;
		  goto restart;
		}
	      goto dflt;

	    default:
	    dflt:
	      bol = false;
	      pfile->mi_valid = false;
	      break;
	    }
	}

      if (buffer->rlimit > base && !pfile->state.skipping)
	{
	  const unsigned char *limit = buffer->rlimit;
	  
	  if (limit[-1] != '\n')
	    {
	      limit++;
	      CPP_INCREMENT_LINE (pfile, 0);
	      line_count++;
	    }
	  cb (pfile, CPP_DO_print, data, line_count, base, limit - base);
	}

      _cpp_pop_buffer (pfile);
    }
  while (pfile->buffer);
}
