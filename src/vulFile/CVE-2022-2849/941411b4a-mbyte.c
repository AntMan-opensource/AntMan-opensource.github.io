










    
    









































static int dbcs_char2len(int c);
static int dbcs_char2bytes(int c, char_u *buf);
static int dbcs_ptr2len(char_u *p);
static int dbcs_ptr2len_len(char_u *p, int size);
static int utf_ptr2cells_len(char_u *p, int size);
static int dbcs_char2cells(int c);
static int dbcs_ptr2cells_len(char_u *p, int size);
static int dbcs_ptr2char(char_u *p);
static int dbcs_head_off(char_u *base, char_u *p);

static int cw_value(int c);



static char utf8len_tab[256] = {
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, 3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,6,6,1,1, };









static char utf8len_tab_zero[256] = {
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, 3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,6,6,0,0, };










static struct {   char *name;		int prop;		int codepage;}
enc_canon_table[] = {

    {"latin1",		ENC_8BIT + ENC_LATIN1,	1252},  {"iso-8859-2",	ENC_8BIT,		0},  {"iso-8859-3",	ENC_8BIT,		0},  {"iso-8859-4",	ENC_8BIT,		0},  {"iso-8859-5",	ENC_8BIT,		0},  {"iso-8859-6",	ENC_8BIT,		0},  {"iso-8859-7",	ENC_8BIT,		0},  {"iso-8859-8",	ENC_8BIT,		0},  {"iso-8859-9",	ENC_8BIT,		0},  {"iso-8859-10",	ENC_8BIT,		0},  {"iso-8859-11",	ENC_8BIT,		0},  {"iso-8859-13",	ENC_8BIT,		0},  {"iso-8859-14",	ENC_8BIT,		0},  {"iso-8859-15",	ENC_8BIT + ENC_LATIN9,	0},  {"koi8-r",		ENC_8BIT,		0},  {"koi8-u",		ENC_8BIT,		0},  {"utf-8",		ENC_UNICODE,		0},  {"ucs-2",		ENC_UNICODE + ENC_ENDIAN_B + ENC_2BYTE, 0},  {"ucs-2le",		ENC_UNICODE + ENC_ENDIAN_L + ENC_2BYTE, 0},  {"utf-16",		ENC_UNICODE + ENC_ENDIAN_B + ENC_2WORD, 0},  {"utf-16le",	ENC_UNICODE + ENC_ENDIAN_L + ENC_2WORD, 0},  {"ucs-4",		ENC_UNICODE + ENC_ENDIAN_B + ENC_4BYTE, 0},  {"ucs-4le",		ENC_UNICODE + ENC_ENDIAN_L + ENC_4BYTE, 0},    {"debug",		ENC_DBCS,		DBCS_DEBUG},  {"euc-jp",		ENC_DBCS,		DBCS_JPNU},  {"sjis",		ENC_DBCS,		DBCS_JPN},  {"euc-kr",		ENC_DBCS,		DBCS_KORU},  {"euc-cn",		ENC_DBCS,		DBCS_CHSU},  {"euc-tw",		ENC_DBCS,		DBCS_CHTU},  {"big5",		ENC_DBCS,		DBCS_CHT},      {"cp437",		ENC_8BIT,		437},  {"cp737",		ENC_8BIT,		737},  {"cp775",		ENC_8BIT,		775},  {"cp850",		ENC_8BIT,		850},  {"cp852",		ENC_8BIT,		852},  {"cp855",		ENC_8BIT,		855},  {"cp857",		ENC_8BIT,		857},  {"cp860",		ENC_8BIT,		860},  {"cp861",		ENC_8BIT,		861},  {"cp862",		ENC_8BIT,		862},  {"cp863",		ENC_8BIT,		863},  {"cp865",		ENC_8BIT,		865},  {"cp866",		ENC_8BIT,		866},  {"cp869",		ENC_8BIT,		869},  {"cp874",		ENC_8BIT,		874},  {"cp932",		ENC_DBCS,		DBCS_JPN},  {"cp936",		ENC_DBCS,		DBCS_CHS},  {"cp949",		ENC_DBCS,		DBCS_KOR},  {"cp950",		ENC_DBCS,		DBCS_CHT},  {"cp1250",		ENC_8BIT,		1250},  {"cp1251",		ENC_8BIT,		1251},   {"cp1253",		ENC_8BIT,		1253},  {"cp1254",		ENC_8BIT,		1254},  {"cp1255",		ENC_8BIT,		1255},  {"cp1256",		ENC_8BIT,		1256},  {"cp1257",		ENC_8BIT,		1257},  {"cp1258",		ENC_8BIT,		1258},   {"macroman",	ENC_8BIT + ENC_MACROMAN, 0},  {"dec-mcs",		ENC_8BIT,		0},  {"hp-roman8",	ENC_8BIT,		0},  };

































































































































static struct {   char *name;		int canon;}
enc_alias_table[] = {
    {"ansi",		IDX_LATIN_1}, {"iso-8859-1",	IDX_LATIN_1}, {"iso-8859",	IDX_LATIN_1}, {"latin2",		IDX_ISO_2}, {"latin3",		IDX_ISO_3}, {"latin4",		IDX_ISO_4}, {"cyrillic",	IDX_ISO_5}, {"arabic",		IDX_ISO_6}, {"greek",		IDX_ISO_7},  {"hebrew",		IDX_CP1255},  {"hebrew",		IDX_ISO_8},  {"latin5",		IDX_ISO_9}, {"turkish",		IDX_ISO_9}, {"latin6",		IDX_ISO_10}, {"nordic",		IDX_ISO_10}, {"thai",		IDX_ISO_11}, {"latin7",		IDX_ISO_13}, {"latin8",		IDX_ISO_14}, {"latin9",		IDX_ISO_15}, {"utf8",		IDX_UTF8}, {"unicode",		IDX_UCS2}, {"ucs2",		IDX_UCS2}, {"ucs2be",		IDX_UCS2}, {"ucs-2be",		IDX_UCS2}, {"ucs2le",		IDX_UCS2LE}, {"utf16",		IDX_UTF16}, {"utf16be",		IDX_UTF16}, {"utf-16be",	IDX_UTF16}, {"utf16le",		IDX_UTF16LE}, {"ucs4",		IDX_UCS4}, {"ucs4be",		IDX_UCS4}, {"ucs-4be",		IDX_UCS4}, {"ucs4le",		IDX_UCS4LE}, {"utf32",		IDX_UCS4}, {"utf-32",		IDX_UCS4}, {"utf32be",		IDX_UCS4}, {"utf-32be",	IDX_UCS4}, {"utf32le",		IDX_UCS4LE}, {"utf-32le",	IDX_UCS4LE}, {"932",		IDX_CP932}, {"949",		IDX_CP949}, {"936",		IDX_CP936}, {"gbk",		IDX_CP936}, {"950",		IDX_CP950}, {"eucjp",		IDX_EUC_JP}, {"unix-jis",	IDX_EUC_JP}, {"ujis",		IDX_EUC_JP}, {"shift-jis",	IDX_SJIS}, {"pck",		IDX_SJIS}, {"euckr",		IDX_EUC_KR}, {"5601",		IDX_EUC_KR}, {"euccn",		IDX_EUC_CN}, {"gb2312",		IDX_EUC_CN}, {"euctw",		IDX_EUC_TW},  {"japan",		IDX_CP932}, {"korea",		IDX_CP949}, {"prc",		IDX_CP936}, {"chinese",		IDX_CP936}, {"taiwan",		IDX_CP950}, {"big5",		IDX_CP950},  {"japan",		IDX_EUC_JP}, {"korea",		IDX_EUC_KR}, {"prc",		IDX_EUC_CN}, {"chinese",		IDX_EUC_CN}, {"taiwan",		IDX_EUC_TW}, {"cp950",		IDX_BIG5}, {"950",		IDX_BIG5},  {"mac",		IDX_MACROMAN}, {"mac-roman",	IDX_MACROMAN}, {NULL,		0}










































































};






    static int enc_canon_search(char_u *name)
{
    int		i;

    for (i = 0; i < IDX_COUNT; ++i)
	if (STRCMP(name, enc_canon_table[i].name) == 0)
	    return i;
    return -1;
}



    int enc_canon_props(char_u *name)
{
    int		i;

    i = enc_canon_search(name);
    if (i >= 0)
	return enc_canon_table[i].prop;

    if (name[0] == 'c' && name[1] == 'p' && VIM_ISDIGIT(name[2]))
    {
	CPINFO	cpinfo;

	
	if (GetCPInfo(atoi((char *)name + 2), &cpinfo) != 0)
	{
	    if (cpinfo.MaxCharSize == 1) 
		return ENC_8BIT;
	    if (cpinfo.MaxCharSize == 2 && (cpinfo.LeadByte[0] != 0 || cpinfo.LeadByte[1] != 0))
		
		return ENC_DBCS;
	}
	return 0;
    }

    if (STRNCMP(name, "2byte-", 6) == 0)
	return ENC_DBCS;
    if (STRNCMP(name, "8bit-", 5) == 0 || STRNCMP(name, "iso-8859-", 9) == 0)
	return ENC_8BIT;
    return 0;
}


    char * mb_init(void)
{
    int		i;
    int		idx;
    int		n;
    int		enc_dbcs_new = 0;


    vimconv_T	vimconv;
    char_u	*p;


    if (p_enc == NULL)
    {
	
	for (i = 0; i < 256; ++i)
	    mb_bytelen_tab[i] = 1;
	input_conv.vc_type = CONV_NONE;
	input_conv.vc_factor = 1;
	output_conv.vc_type = CONV_NONE;
	return NULL;
    }


    if (p_enc[0] == 'c' && p_enc[1] == 'p' && VIM_ISDIGIT(p_enc[2]))
    {
	CPINFO	cpinfo;

	
	if (GetCPInfo(atoi((char *)p_enc + 2), &cpinfo) != 0)
	{
	    if (cpinfo.MaxCharSize == 1)
	    {
		
		enc_unicode = 0;
		enc_utf8 = FALSE;
	    }
	    else if (cpinfo.MaxCharSize == 2 && (cpinfo.LeadByte[0] != 0 || cpinfo.LeadByte[1] != 0))
	    {
		
		enc_dbcs_new = atoi((char *)p_enc + 2);
	    }
	    else goto codepage_invalid;
	}
	else if (GetLastError() == ERROR_INVALID_PARAMETER)
	{
codepage_invalid:
	    return N_(e_not_valid_codepage);
	}
    }

    else if (STRNCMP(p_enc, "8bit-", 5) == 0 || STRNCMP(p_enc, "iso-8859-", 9) == 0)
    {
	
	enc_unicode = 0;
	enc_utf8 = FALSE;
    }
    else if (STRNCMP(p_enc, "2byte-", 6) == 0)
    {

	
	if (p_enc[6] != 'c' || p_enc[7] != 'p' || (enc_dbcs_new = atoi((char *)p_enc + 8)) == 0)
	    return e_invalid_argument;

	
	enc_dbcs_new = DBCS_2BYTE;

    }
    else if ((idx = enc_canon_search(p_enc)) >= 0)
    {
	i = enc_canon_table[idx].prop;
	if (i & ENC_UNICODE)
	{
	    
	    enc_utf8 = TRUE;
	    if (i & (ENC_2BYTE | ENC_2WORD))
		enc_unicode = 2;
	    else if (i & ENC_4BYTE)
		enc_unicode = 4;
	    else enc_unicode = 0;
	}
	else if (i & ENC_DBCS)
	{
	    
	    enc_dbcs_new = enc_canon_table[idx].codepage;
	}
	else {
	    
	    enc_unicode = 0;
	    enc_utf8 = FALSE;
	}
    }
    else     return e_invalid_argument;

    if (enc_dbcs_new != 0)
    {

	
	if (!IsValidCodePage(enc_dbcs_new))
	    goto codepage_invalid;

	enc_unicode = 0;
	enc_utf8 = FALSE;
    }
    enc_dbcs = enc_dbcs_new;
    has_mbyte = (enc_dbcs != 0 || enc_utf8);


    enc_codepage = encname2codepage(p_enc);
    enc_latin9 = (STRCMP(p_enc, "iso-8859-15") == 0);


    
    enc_latin1like = (enc_utf8 || STRCMP(p_enc, "latin1") == 0 || STRCMP(p_enc, "iso-8859-15") == 0);

    
    if (enc_utf8)
    {
	mb_ptr2len = utfc_ptr2len;
	mb_ptr2len_len = utfc_ptr2len_len;
	mb_char2len = utf_char2len;
	mb_char2bytes = utf_char2bytes;
	mb_ptr2cells = utf_ptr2cells;
	mb_ptr2cells_len = utf_ptr2cells_len;
	mb_char2cells = utf_char2cells;
	mb_off2cells = utf_off2cells;
	mb_ptr2char = utf_ptr2char;
	mb_head_off = utf_head_off;
    }
    else if (enc_dbcs != 0)
    {
	mb_ptr2len = dbcs_ptr2len;
	mb_ptr2len_len = dbcs_ptr2len_len;
	mb_char2len = dbcs_char2len;
	mb_char2bytes = dbcs_char2bytes;
	mb_ptr2cells = dbcs_ptr2cells;
	mb_ptr2cells_len = dbcs_ptr2cells_len;
	mb_char2cells = dbcs_char2cells;
	mb_off2cells = dbcs_off2cells;
	mb_ptr2char = dbcs_ptr2char;
	mb_head_off = dbcs_head_off;
    }
    else {
	mb_ptr2len = latin_ptr2len;
	mb_ptr2len_len = latin_ptr2len_len;
	mb_char2len = latin_char2len;
	mb_char2bytes = latin_char2bytes;
	mb_ptr2cells = latin_ptr2cells;
	mb_ptr2cells_len = latin_ptr2cells_len;
	mb_char2cells = latin_char2cells;
	mb_off2cells = latin_off2cells;
	mb_ptr2char = latin_ptr2char;
	mb_head_off = latin_head_off;
    }

    

    
    
    vimconv.vc_type = CONV_NONE;
    if (enc_dbcs)
    {
	p = enc_locale();
	if (p == NULL || STRCMP(p, p_enc) != 0)
	{
	    convert_setup(&vimconv, p_enc, (char_u *)"utf-8");
	    vimconv.vc_fail = TRUE;
	}
	vim_free(p);
    }


    for (i = 0; i < 256; ++i)
    {
	
	
	if (enc_utf8)
	    n = utf8len_tab[i];
	else if (enc_dbcs == 0)
	    n = 1;
	else {

	    
	    
	    
	    n = IsDBCSLeadByteEx(enc_dbcs, (WINBYTE)i) ? 2 : 1;


	    
	    n = (i & 0x80) ? 2 : 1;

	    char buf[MB_MAXBYTES + 1];

	    if (i == NUL)	
		n = 1;
	    else {
		buf[0] = i;
		buf[1] = 0;

		if (vimconv.vc_type != CONV_NONE)
		{
		    
		    p = string_convert(&vimconv, (char_u *)buf, NULL);
		    if (p != NULL)
		    {
			vim_free(p);
			n = 1;
		    }
		    else n = 2;
		}
		else  {

		    
		    vim_ignored = mblen(NULL, 0);  
		    if (mblen(buf, (size_t)1) <= 0)
			n = 2;
		    else n = 1;
		}
	    }


	}

	mb_bytelen_tab[i] = n;
    }


    convert_setup(&vimconv, NULL, NULL);


    
    (void)init_chartab();

    
    screenalloc(FALSE);

    
    if (enc_utf8 && !option_was_set((char_u *)"fencs"))
	set_fencs_unicode();


    
    
    (void)bind_textdomain_codeset(VIMPACKAGE, enc_utf8 ? "utf-8" : (char *)p_enc);



    
    
    if (starting != 0)
	fix_arg_enc();


    
    
    apply_autocmds(EVENT_ENCODINGCHANGED, NULL, (char_u *)"", FALSE, curbuf);


    
    spell_reload();


    return NULL;
}


    int bomb_size(void)
{
    int n = 0;

    if (curbuf->b_p_bomb && !curbuf->b_p_bin)
    {
	if (*curbuf->b_p_fenc == NUL)
	{
	    if (enc_utf8)
	    {
		if (enc_unicode != 0)
		    n = enc_unicode;
		else n = 3;
	    }
	}
	else if (STRCMP(curbuf->b_p_fenc, "utf-8") == 0)
	    n = 3;
	else if (STRNCMP(curbuf->b_p_fenc, "ucs-2", 5) == 0 || STRNCMP(curbuf->b_p_fenc, "utf-16", 6) == 0)
	    n = 2;
	else if (STRNCMP(curbuf->b_p_fenc, "ucs-4", 5) == 0)
	    n = 4;
    }
    return n;
}



    void remove_bom(char_u *s)
{
    if (enc_utf8)
    {
	char_u *p = s;

	while ((p = vim_strbyte(p, 0xef)) != NULL)
	{
	    if (p[1] == 0xbb && p[2] == 0xbf)
		STRMOVE(p, p + 3);
	    else ++p;
	}
    }
}



    int mb_get_class(char_u *p)
{
    return mb_get_class_buf(p, curbuf);
}

    int mb_get_class_buf(char_u *p, buf_T *buf)
{
    if (MB_BYTE2LEN(p[0]) == 1)
    {
	if (p[0] == NUL || VIM_ISWHITE(p[0]))
	    return 0;
	if (vim_iswordc_buf(p[0], buf))
	    return 2;
	return 1;
    }
    if (enc_dbcs != 0 && p[0] != NUL && p[1] != NUL)
	return dbcs_class(p[0], p[1]);
    if (enc_utf8)
	return utf_class_buf(utf_ptr2char(p), buf);
    return 0;
}


    int dbcs_class(unsigned lead, unsigned trail)
{
    switch (enc_dbcs)
    {
	

	case DBCS_JPNU:	
	case DBCS_JPN:
	    {
		
		unsigned char lb = lead;
		unsigned char tb = trail;

		

		
		if (lb <= 0x9f)
		    lb = (lb - 0x81) * 2 + 0x21;
		else lb = (lb - 0xc1) * 2 + 0x21;
		if (tb <= 0x7e)
		    tb -= 0x1f;
		else if (tb <= 0x9e)
		    tb -= 0x20;
		else {
		    tb -= 0x7e;
		    lb += 1;
		}

		
		
		lb &= 0x7f;
		tb &= 0x7f;

		
		switch (lb << 8 | tb)
		{
		    case 0x2121: 
			return 0;
		    case 0x2122: 
		    case 0x2123: 
		    case 0x2124: 
		    case 0x2125: 
			return 1;
		    case 0x213c: 
			return 13;
		}
		
		switch (lb)
		{
		    case 0x21:
		    case 0x22:
			
			return 10;
		    case 0x23:
			
			return 11;
		    case 0x24:
			
			return 12;
		    case 0x25:
			
			return 13;
		    case 0x26:
			
			return 14;
		    case 0x27:
			
			return 15;
		    case 0x28:
			
			return 16;
		    default:
			
			return 17;
		}
	    }

	case DBCS_KORU:	
	case DBCS_KOR:
	    {
		
		unsigned char c1 = lead;
		unsigned char c2 = trail;

		

		if (c1 >= 0xB0 && c1 <= 0xC8)
		    
		    return 20;

		else if (c1 <= 0xA0 || c2 <= 0xA0)
		    
		    
		    
		    return 20;


		else if (c1 >= 0xCA && c1 <= 0xFD)
		    
		    return 21;
		else switch (c1)
		{
		    case 0xA1:
		    case 0xA2:
			
			return 22;
		    case 0xA3:
			
			return 23;
		    case 0xA4:
			
			return 24;
		    case 0xA5:
			
			return 25;
		    case 0xA6:
			
			return 26;
		    case 0xA7:
			
			return 27;
		    case 0xA8:
		    case 0xA9:
			if (c2 <= 0xAF)
			    return 25;  
			else if (c2 >= 0xF6)
			    return 22;  
			else  return 28;

		    case 0xAA:
		    case 0xAB:
			
			return 29;
		    case 0xAC:
			
			return 30;
		}
	    }
	default:
	    break;
    }
    return 3;
}


    int latin_char2len(int c UNUSED)
{
    return 1;
}

    static int dbcs_char2len( int		c)

{
    if (c >= 0x100)
	return 2;
    return 1;
}


    int latin_char2bytes(int c, char_u *buf)
{
    buf[0] = c;
    return 1;
}

    static int dbcs_char2bytes(int c, char_u *buf)
{
    if (c >= 0x100)
    {
	buf[0] = (unsigned)c >> 8;
	buf[1] = c;
	
	
	if (buf[1] == NUL)
	    buf[1] = '\n';
	return 2;
    }
    buf[0] = c;
    return 1;
}


    int latin_ptr2len(char_u *p)
{
 return MB_BYTE2LEN(*p);
}

    static int dbcs_ptr2len( char_u	*p)

{
    int		len;

    
    len = MB_BYTE2LEN(*p);
    if (len == 2 && p[1] == NUL)
	len = 1;
    return len;
}


    int latin_ptr2len_len(char_u *p, int size)
{
    if (size < 1 || *p == NUL)
	return 0;
    return 1;
}

    static int dbcs_ptr2len_len(char_u *p, int size)
{
    int		len;

    if (size < 1 || *p == NUL)
	return 0;
    if (size == 1)
	return 1;
    
    len = MB_BYTE2LEN(*p);
    if (len == 2 && p[1] == NUL)
	len = 1;
    return len;
}

struct interval {
    long first;
    long last;
};


    static int intable(struct interval *table, size_t size, int c)
{
    int mid, bot, top;

    
    if (c < table[0].first)
	return FALSE;

    
    bot = 0;
    top = (int)(size / sizeof(struct interval) - 1);
    while (top >= bot)
    {
	mid = (bot + top) / 2;
	if (table[mid].last < c)
	    bot = mid + 1;
	else if (table[mid].first > c)
	    top = mid - 1;
	else return TRUE;
    }
    return FALSE;
}



static struct interval ambiguous[] = {
    {0x00a1, 0x00a1}, {0x00a4, 0x00a4}, {0x00a7, 0x00a8}, {0x00aa, 0x00aa}, {0x00ad, 0x00ae}, {0x00b0, 0x00b4}, {0x00b6, 0x00ba}, {0x00bc, 0x00bf}, {0x00c6, 0x00c6}, {0x00d0, 0x00d0}, {0x00d7, 0x00d8}, {0x00de, 0x00e1}, {0x00e6, 0x00e6}, {0x00e8, 0x00ea}, {0x00ec, 0x00ed}, {0x00f0, 0x00f0}, {0x00f2, 0x00f3}, {0x00f7, 0x00fa}, {0x00fc, 0x00fc}, {0x00fe, 0x00fe}, {0x0101, 0x0101}, {0x0111, 0x0111}, {0x0113, 0x0113}, {0x011b, 0x011b}, {0x0126, 0x0127}, {0x012b, 0x012b}, {0x0131, 0x0133}, {0x0138, 0x0138}, {0x013f, 0x0142}, {0x0144, 0x0144}, {0x0148, 0x014b}, {0x014d, 0x014d}, {0x0152, 0x0153}, {0x0166, 0x0167}, {0x016b, 0x016b}, {0x01ce, 0x01ce}, {0x01d0, 0x01d0}, {0x01d2, 0x01d2}, {0x01d4, 0x01d4}, {0x01d6, 0x01d6}, {0x01d8, 0x01d8}, {0x01da, 0x01da}, {0x01dc, 0x01dc}, {0x0251, 0x0251}, {0x0261, 0x0261}, {0x02c4, 0x02c4}, {0x02c7, 0x02c7}, {0x02c9, 0x02cb}, {0x02cd, 0x02cd}, {0x02d0, 0x02d0}, {0x02d8, 0x02db}, {0x02dd, 0x02dd}, {0x02df, 0x02df}, {0x0300, 0x036f}, {0x0391, 0x03a1}, {0x03a3, 0x03a9}, {0x03b1, 0x03c1}, {0x03c3, 0x03c9}, {0x0401, 0x0401}, {0x0410, 0x044f}, {0x0451, 0x0451}, {0x2010, 0x2010}, {0x2013, 0x2016}, {0x2018, 0x2019}, {0x201c, 0x201d}, {0x2020, 0x2022}, {0x2024, 0x2027}, {0x2030, 0x2030}, {0x2032, 0x2033}, {0x2035, 0x2035}, {0x203b, 0x203b}, {0x203e, 0x203e}, {0x2074, 0x2074}, {0x207f, 0x207f}, {0x2081, 0x2084}, {0x20ac, 0x20ac}, {0x2103, 0x2103}, {0x2105, 0x2105}, {0x2109, 0x2109}, {0x2113, 0x2113}, {0x2116, 0x2116}, {0x2121, 0x2122}, {0x2126, 0x2126}, {0x212b, 0x212b}, {0x2153, 0x2154}, {0x215b, 0x215e}, {0x2160, 0x216b}, {0x2170, 0x2179}, {0x2189, 0x2189}, {0x2190, 0x2199}, {0x21b8, 0x21b9}, {0x21d2, 0x21d2}, {0x21d4, 0x21d4}, {0x21e7, 0x21e7}, {0x2200, 0x2200}, {0x2202, 0x2203}, {0x2207, 0x2208}, {0x220b, 0x220b}, {0x220f, 0x220f}, {0x2211, 0x2211}, {0x2215, 0x2215}, {0x221a, 0x221a}, {0x221d, 0x2220}, {0x2223, 0x2223}, {0x2225, 0x2225}, {0x2227, 0x222c}, {0x222e, 0x222e}, {0x2234, 0x2237}, {0x223c, 0x223d}, {0x2248, 0x2248}, {0x224c, 0x224c}, {0x2252, 0x2252}, {0x2260, 0x2261}, {0x2264, 0x2267}, {0x226a, 0x226b}, {0x226e, 0x226f}, {0x2282, 0x2283}, {0x2286, 0x2287}, {0x2295, 0x2295}, {0x2299, 0x2299}, {0x22a5, 0x22a5}, {0x22bf, 0x22bf}, {0x2312, 0x2312}, {0x2460, 0x24e9}, {0x24eb, 0x254b}, {0x2550, 0x2573}, {0x2580, 0x258f}, {0x2592, 0x2595}, {0x25a0, 0x25a1}, {0x25a3, 0x25a9}, {0x25b2, 0x25b3}, {0x25b6, 0x25b7}, {0x25bc, 0x25bd}, {0x25c0, 0x25c1}, {0x25c6, 0x25c8}, {0x25cb, 0x25cb}, {0x25ce, 0x25d1}, {0x25e2, 0x25e5}, {0x25ef, 0x25ef}, {0x2605, 0x2606}, {0x2609, 0x2609}, {0x260e, 0x260f}, {0x261c, 0x261c}, {0x261e, 0x261e}, {0x2640, 0x2640}, {0x2642, 0x2642}, {0x2660, 0x2661}, {0x2663, 0x2665}, {0x2667, 0x266a}, {0x266c, 0x266d}, {0x266f, 0x266f}, {0x269e, 0x269f}, {0x26bf, 0x26bf}, {0x26c6, 0x26cd}, {0x26cf, 0x26d3}, {0x26d5, 0x26e1}, {0x26e3, 0x26e3}, {0x26e8, 0x26e9}, {0x26eb, 0x26f1}, {0x26f4, 0x26f4}, {0x26f6, 0x26f9}, {0x26fb, 0x26fc}, {0x26fe, 0x26ff}, {0x273d, 0x273d}, {0x2776, 0x277f}, {0x2b56, 0x2b59}, {0x3248, 0x324f}, {0xe000, 0xf8ff}, {0xfe00, 0xfe0f}, {0xfffd, 0xfffd}, {0x1f100, 0x1f10a}, {0x1f110, 0x1f12d}, {0x1f130, 0x1f169}, {0x1f170, 0x1f18d}, {0x1f18f, 0x1f190}, {0x1f19b, 0x1f1ac}, {0xe0100, 0xe01ef}, {0xf0000, 0xffffd}, {0x100000, 0x10fffd}

















































































































































































};



    int utf_uint2cells(UINT32_T c)
{
    if (c >= 0x100 && utf_iscomposing((int)c))
	return 0;
    return utf_char2cells((int)c);
}



    int utf_char2cells(int c)
{
    
    
    static struct interval doublewidth[] = {
	{0x1100, 0x115f}, {0x231a, 0x231b}, {0x2329, 0x232a}, {0x23e9, 0x23ec}, {0x23f0, 0x23f0}, {0x23f3, 0x23f3}, {0x25fd, 0x25fe}, {0x2614, 0x2615}, {0x2648, 0x2653}, {0x267f, 0x267f}, {0x2693, 0x2693}, {0x26a1, 0x26a1}, {0x26aa, 0x26ab}, {0x26bd, 0x26be}, {0x26c4, 0x26c5}, {0x26ce, 0x26ce}, {0x26d4, 0x26d4}, {0x26ea, 0x26ea}, {0x26f2, 0x26f3}, {0x26f5, 0x26f5}, {0x26fa, 0x26fa}, {0x26fd, 0x26fd}, {0x2705, 0x2705}, {0x270a, 0x270b}, {0x2728, 0x2728}, {0x274c, 0x274c}, {0x274e, 0x274e}, {0x2753, 0x2755}, {0x2757, 0x2757}, {0x2795, 0x2797}, {0x27b0, 0x27b0}, {0x27bf, 0x27bf}, {0x2b1b, 0x2b1c}, {0x2b50, 0x2b50}, {0x2b55, 0x2b55}, {0x2e80, 0x2e99}, {0x2e9b, 0x2ef3}, {0x2f00, 0x2fd5}, {0x2ff0, 0x2ffb}, {0x3000, 0x303e}, {0x3041, 0x3096}, {0x3099, 0x30ff}, {0x3105, 0x312f}, {0x3131, 0x318e}, {0x3190, 0x31e3}, {0x31f0, 0x321e}, {0x3220, 0x3247}, {0x3250, 0x4dbf}, {0x4e00, 0xa48c}, {0xa490, 0xa4c6}, {0xa960, 0xa97c}, {0xac00, 0xd7a3}, {0xf900, 0xfaff}, {0xfe10, 0xfe19}, {0xfe30, 0xfe52}, {0xfe54, 0xfe66}, {0xfe68, 0xfe6b}, {0xff01, 0xff60}, {0xffe0, 0xffe6}, {0x16fe0, 0x16fe3}, {0x16ff0, 0x16ff1}, {0x17000, 0x187f7}, {0x18800, 0x18cd5}, {0x18d00, 0x18d08}, {0x1b000, 0x1b11e}, {0x1b150, 0x1b152}, {0x1b164, 0x1b167}, {0x1b170, 0x1b2fb}, {0x1f004, 0x1f004}, {0x1f0cf, 0x1f0cf}, {0x1f18e, 0x1f18e}, {0x1f191, 0x1f19a}, {0x1f200, 0x1f202}, {0x1f210, 0x1f23b}, {0x1f240, 0x1f248}, {0x1f250, 0x1f251}, {0x1f260, 0x1f265}, {0x1f300, 0x1f320}, {0x1f32d, 0x1f335}, {0x1f337, 0x1f37c}, {0x1f37e, 0x1f393}, {0x1f3a0, 0x1f3ca}, {0x1f3cf, 0x1f3d3}, {0x1f3e0, 0x1f3f0}, {0x1f3f4, 0x1f3f4}, {0x1f3f8, 0x1f43e}, {0x1f440, 0x1f440}, {0x1f442, 0x1f4fc}, {0x1f4ff, 0x1f53d}, {0x1f54b, 0x1f54e}, {0x1f550, 0x1f567}, {0x1f57a, 0x1f57a}, {0x1f595, 0x1f596}, {0x1f5a4, 0x1f5a4}, {0x1f5fb, 0x1f64f}, {0x1f680, 0x1f6c5}, {0x1f6cc, 0x1f6cc}, {0x1f6d0, 0x1f6d2}, {0x1f6d5, 0x1f6d7}, {0x1f6eb, 0x1f6ec}, {0x1f6f4, 0x1f6fc}, {0x1f7e0, 0x1f7eb}, {0x1f90c, 0x1f93a}, {0x1f93c, 0x1f945}, {0x1f947, 0x1f978}, {0x1f97a, 0x1f9cb}, {0x1f9cd, 0x1f9ff}, {0x1fa70, 0x1fa74}, {0x1fa78, 0x1fa7a}, {0x1fa80, 0x1fa86}, {0x1fa90, 0x1faa8}, {0x1fab0, 0x1fab6}, {0x1fac0, 0x1fac2}, {0x1fad0, 0x1fad6}, {0x20000, 0x2fffd}, {0x30000, 0x3fffd}


















































































































    };

    
    
    
    static struct interval emoji_wide[] = {
	{0x23ed, 0x23ef}, {0x23f1, 0x23f2}, {0x23f8, 0x23fa}, {0x24c2, 0x24c2}, {0x261d, 0x261d}, {0x26c8, 0x26c8}, {0x26cf, 0x26cf}, {0x26d1, 0x26d1}, {0x26d3, 0x26d3}, {0x26e9, 0x26e9}, {0x26f0, 0x26f1}, {0x26f7, 0x26f9}, {0x270c, 0x270d}, {0x2934, 0x2935}, {0x1f170, 0x1f189}, {0x1f1e6, 0x1f1ff}, {0x1f321, 0x1f321}, {0x1f324, 0x1f32c}, {0x1f336, 0x1f336}, {0x1f37d, 0x1f37d}, {0x1f396, 0x1f397}, {0x1f399, 0x1f39b}, {0x1f39e, 0x1f39f}, {0x1f3cb, 0x1f3ce}, {0x1f3d4, 0x1f3df}, {0x1f3f3, 0x1f3f5}, {0x1f3f7, 0x1f3f7}, {0x1f43f, 0x1f43f}, {0x1f441, 0x1f441}, {0x1f4fd, 0x1f4fd}, {0x1f549, 0x1f54a}, {0x1f56f, 0x1f570}, {0x1f573, 0x1f579}, {0x1f587, 0x1f587}, {0x1f58a, 0x1f58d}, {0x1f590, 0x1f590}, {0x1f5a5, 0x1f5a5}, {0x1f5a8, 0x1f5a8}, {0x1f5b1, 0x1f5b2}, {0x1f5bc, 0x1f5bc}, {0x1f5c2, 0x1f5c4}, {0x1f5d1, 0x1f5d3}, {0x1f5dc, 0x1f5de}, {0x1f5e1, 0x1f5e1}, {0x1f5e3, 0x1f5e3}, {0x1f5e8, 0x1f5e8}, {0x1f5ef, 0x1f5ef}, {0x1f5f3, 0x1f5f3}, {0x1f5fa, 0x1f5fa}, {0x1f6cb, 0x1f6cf}, {0x1f6e0, 0x1f6e5}, {0x1f6e9, 0x1f6e9}, {0x1f6f0, 0x1f6f0}, {0x1f6f3, 0x1f6f3}






















































	
	
	
	
	
	, {0x100000, 0x100d7f}

    };

    if (c >= 0x100)
    {

	int	n;



	n = cw_value(c);
	if (n != 0)
	    return n;



	
	n = wcwidth(c);

	if (n < 0)
	    return 6;		
	if (n > 1)
	    return n;

	if (!utf_printable(c))
	    return 6;		
	if (intable(doublewidth, sizeof(doublewidth), c))
	    return 2;

	if (p_emoji && intable(emoji_wide, sizeof(emoji_wide), c))
	    return 2;
    }

    
    else if (c >= 0x80 && !vim_isprintc(c))
	return 4;		

    if (c >= 0x80 && *p_ambw == 'd' && intable(ambiguous, sizeof(ambiguous), c))
	return 2;

    return 1;
}


    int latin_ptr2cells(char_u *p UNUSED)
{
    return 1;
}

    int utf_ptr2cells( char_u	*p)

{
    int		c;

    
    if (*p >= 0x80)
    {
	c = utf_ptr2char(p);
	
	if (utf_ptr2len(p) == 1 || c == NUL)
	    return 4;
	
	if (c < 0x80)
	    return char2cells(c);
	return utf_char2cells(c);
    }
    return 1;
}

    int dbcs_ptr2cells(char_u *p)
{
    
    
    if (enc_dbcs == DBCS_JPNU && *p == 0x8e)
	return 1;
    return MB_BYTE2LEN(*p);
}


    int latin_ptr2cells_len(char_u *p UNUSED, int size UNUSED)
{
    return 1;
}

    static int utf_ptr2cells_len(char_u *p, int size)
{
    int		c;

    
    if (size > 0 && *p >= 0x80)
    {
	if (utf_ptr2len_len(p, size) < utf8len_tab[*p])
	    return 1;  
	c = utf_ptr2char(p);
	
	if (utf_ptr2len(p) == 1 || c == NUL)
	    return 4;
	
	if (c < 0x80)
	    return char2cells(c);
	return utf_char2cells(c);
    }
    return 1;
}

    static int dbcs_ptr2cells_len(char_u *p, int size)
{
    
    
    if (size <= 1 || (enc_dbcs == DBCS_JPNU && *p == 0x8e))
	return 1;
    return MB_BYTE2LEN(*p);
}


    int latin_char2cells(int c UNUSED)
{
    return 1;
}

    static int dbcs_char2cells(int c)
{
    
    
    if (enc_dbcs == DBCS_JPNU && ((unsigned)c >> 8) == 0x8e)
	return 1;
    
    return MB_BYTE2LEN((unsigned)c >> 8);
}


    int mb_string2cells(char_u *p, int len)
{
    int i;
    int clen = 0;

    for (i = 0; (len < 0 || i < len) && p[i] != NUL; i += (*mb_ptr2len)(p + i))
	clen += (*mb_ptr2cells)(p + i);
    return clen;
}


    int latin_off2cells(unsigned off UNUSED, unsigned max_off UNUSED)
{
    return 1;
}

    int dbcs_off2cells(unsigned off, unsigned max_off)
{
    
    if (off >= max_off)
	return 1;

    
    
    if (enc_dbcs == DBCS_JPNU && ScreenLines[off] == 0x8e)
	return 1;
    return MB_BYTE2LEN(ScreenLines[off]);
}

    int utf_off2cells(unsigned off, unsigned max_off)
{
    return (off + 1 < max_off && ScreenLines[off + 1] == 0) ? 2 : 1;
}


    int latin_ptr2char(char_u *p)
{
    return *p;
}

    static int dbcs_ptr2char(char_u *p)
{
    if (MB_BYTE2LEN(*p) > 1 && p[1] != NUL)
	return (p[0] << 8) + p[1];
    return *p;
}


    int utf_ptr2char(char_u *p)
{
    int		len;

    if (p[0] < 0x80)	
	return p[0];

    len = utf8len_tab_zero[p[0]];
    if (len > 1 && (p[1] & 0xc0) == 0x80)
    {
	if (len == 2)
	    return ((p[0] & 0x1f) << 6) + (p[1] & 0x3f);
	if ((p[2] & 0xc0) == 0x80)
	{
	    if (len == 3)
		return ((p[0] & 0x0f) << 12) + ((p[1] & 0x3f) << 6)
		    + (p[2] & 0x3f);
	    if ((p[3] & 0xc0) == 0x80)
	    {
		if (len == 4)
		    return ((p[0] & 0x07) << 18) + ((p[1] & 0x3f) << 12)
			+ ((p[2] & 0x3f) << 6) + (p[3] & 0x3f);
		if ((p[4] & 0xc0) == 0x80)
		{
		    if (len == 5)
			return ((p[0] & 0x03) << 24) + ((p[1] & 0x3f) << 18)
			    + ((p[2] & 0x3f) << 12) + ((p[3] & 0x3f) << 6)
			    + (p[4] & 0x3f);
		    if ((p[5] & 0xc0) == 0x80 && len == 6)
			return ((p[0] & 0x01) << 30) + ((p[1] & 0x3f) << 24)
			    + ((p[2] & 0x3f) << 18) + ((p[3] & 0x3f) << 12)
			    + ((p[4] & 0x3f) << 6) + (p[5] & 0x3f);
		}
	    }
	}
    }
    
    return p[0];
}


    static int utf_safe_read_char_adv(char_u **s, size_t *n)
{
    int		c, k;

    if (*n == 0) 
	return 0;

    k = utf8len_tab_zero[**s];

    if (k == 1)
    {
	
	(*n)--;
	return *(*s)++;
    }

    if ((size_t)k <= *n)
    {
	
	
	
	c = utf_ptr2char(*s);

	
	
	
	
	
	if (c != (int)(**s) || (c == 0xC3 && (*s)[1] == 0x83))
	{
	    
	    *s += k;
	    *n -= k;
	    return c;
	}
    }

    
    return -1;
}


    int mb_ptr2char_adv(char_u **pp)
{
    int		c;

    c = (*mb_ptr2char)(*pp);
    *pp += (*mb_ptr2len)(*pp);
    return c;
}


    int mb_cptr2char_adv(char_u **pp)
{
    int		c;

    c = (*mb_ptr2char)(*pp);
    if (enc_utf8)
	*pp += utf_ptr2len(*pp);
    else *pp += (*mb_ptr2len)(*pp);
    return c;
}



    int utf_composinglike(char_u *p1, char_u *p2)
{
    int		c2;

    c2 = utf_ptr2char(p2);
    if (utf_iscomposing(c2))
	return TRUE;
    if (!arabic_maycombine(c2))
	return FALSE;
    return arabic_combine(utf_ptr2char(p1), c2);
}



    int utfc_ptr2char( char_u	*p, int		*pcc)


{
    int		len;
    int		c;
    int		cc;
    int		i = 0;

    c = utf_ptr2char(p);
    len = utf_ptr2len(p);

    
    if ((len > 1 || *p < 0x80)
	    && p[len] >= 0x80 && UTF_COMPOSINGLIKE(p, p + len))
    {
	cc = utf_ptr2char(p + len);
	for (;;)
	{
	    pcc[i++] = cc;
	    if (i == MAX_MCO)
		break;
	    len += utf_ptr2len(p + len);
	    if (p[len] < 0x80 || !utf_iscomposing(cc = utf_ptr2char(p + len)))
		break;
	}
    }

    if (i < MAX_MCO)	
	pcc[i] = 0;

    return c;
}


    int utfc_ptr2char_len( char_u	*p, int		*pcc, int		maxlen)



{
    int		len;
    int		c;
    int		cc;
    int		i = 0;

    c = utf_ptr2char(p);
    len = utf_ptr2len_len(p, maxlen);
    
    if ((len > 1 || *p < 0x80)
	    && len < maxlen && p[len] >= 0x80 && UTF_COMPOSINGLIKE(p, p + len))

    {
	cc = utf_ptr2char(p + len);
	for (;;)
	{
	    pcc[i++] = cc;
	    if (i == MAX_MCO)
		break;
	    len += utf_ptr2len_len(p + len, maxlen - len);
	    if (len >= maxlen || p[len] < 0x80 || !utf_iscomposing(cc = utf_ptr2char(p + len)))

		break;
	}
    }

    if (i < MAX_MCO)	
	pcc[i] = 0;

    return c;
}


    int utfc_char2bytes(int off, char_u *buf)
{
    int		len;
    int		i;

    len = utf_char2bytes(ScreenLinesUC[off], buf);
    for (i = 0; i < Screen_mco; ++i)
    {
	if (ScreenLinesC[i][off] == 0)
	    break;
	len += utf_char2bytes(ScreenLinesC[i][off], buf + len);
    }
    return len;
}


    int utf_ptr2len(char_u *p)
{
    int		len;
    int		i;

    if (*p == NUL)
	return 0;
    len = utf8len_tab[*p];
    for (i = 1; i < len; ++i)
	if ((p[i] & 0xc0) != 0x80)
	    return 1;
    return len;
}


    int utf_byte2len(int b)
{
    return utf8len_tab[b];
}


    int utf_ptr2len_len(char_u *p, int size)
{
    int		len;
    int		i;
    int		m;

    len = utf8len_tab[*p];
    if (len == 1)
	return 1;	
    if (len > size)
	m = size;	
    else m = len;
    for (i = 1; i < m; ++i)
	if ((p[i] & 0xc0) != 0x80)
	    return 1;
    return len;
}


    int utfc_ptr2len(char_u *p)
{
    int		len;
    int		b0 = *p;

    int		prevlen;


    if (b0 == NUL)
	return 0;
    if (b0 < 0x80 && p[1] < 0x80)	
	return 1;

    
    len = utf_ptr2len(p);

    
    if (len == 1 && b0 >= 0x80)
	return 1;

    

    prevlen = 0;

    for (;;)
    {
	if (p[len] < 0x80 || !UTF_COMPOSINGLIKE(p + prevlen, p + len))
	    return len;

	

	prevlen = len;

	len += utf_ptr2len(p + len);
    }
}


    int utfc_ptr2len_len(char_u *p, int size)
{
    int		len;

    int		prevlen;


    if (size < 1 || *p == NUL)
	return 0;
    if (p[0] < 0x80 && (size == 1 || p[1] < 0x80)) 
	return 1;

    
    len = utf_ptr2len_len(p, size);

    
    if ((len == 1 && p[0] >= 0x80) || len > size)
	return 1;

    

    prevlen = 0;

    while (len < size)
    {
	int	len_next_char;

	if (p[len] < 0x80)
	    break;

	
	len_next_char = utf_ptr2len_len(p + len, size - len);
	if (len_next_char > size - len)
	    break;

	if (!UTF_COMPOSINGLIKE(p + prevlen, p + len))
	    break;

	

	prevlen = len;

	len += len_next_char;
    }
    return len;
}


    int utf_char2len(int c)
{
    if (c < 0x80)
	return 1;
    if (c < 0x800)
	return 2;
    if (c < 0x10000)
	return 3;
    if (c < 0x200000)
	return 4;
    if (c < 0x4000000)
	return 5;
    return 6;
}


    int utf_char2bytes(int c, char_u *buf)
{
    if (c < 0x80)		
    {
	buf[0] = c;
	return 1;
    }
    if (c < 0x800)		
    {
	buf[0] = 0xc0 + ((unsigned)c >> 6);
	buf[1] = 0x80 + (c & 0x3f);
	return 2;
    }
    if (c < 0x10000)		
    {
	buf[0] = 0xe0 + ((unsigned)c >> 12);
	buf[1] = 0x80 + (((unsigned)c >> 6) & 0x3f);
	buf[2] = 0x80 + (c & 0x3f);
	return 3;
    }
    if (c < 0x200000)		
    {
	buf[0] = 0xf0 + ((unsigned)c >> 18);
	buf[1] = 0x80 + (((unsigned)c >> 12) & 0x3f);
	buf[2] = 0x80 + (((unsigned)c >> 6) & 0x3f);
	buf[3] = 0x80 + (c & 0x3f);
	return 4;
    }
    if (c < 0x4000000)		
    {
	buf[0] = 0xf8 + ((unsigned)c >> 24);
	buf[1] = 0x80 + (((unsigned)c >> 18) & 0x3f);
	buf[2] = 0x80 + (((unsigned)c >> 12) & 0x3f);
	buf[3] = 0x80 + (((unsigned)c >> 6) & 0x3f);
	buf[4] = 0x80 + (c & 0x3f);
	return 5;
    }
				
    buf[0] = 0xfc + ((unsigned)c >> 30);
    buf[1] = 0x80 + (((unsigned)c >> 24) & 0x3f);
    buf[2] = 0x80 + (((unsigned)c >> 18) & 0x3f);
    buf[3] = 0x80 + (((unsigned)c >> 12) & 0x3f);
    buf[4] = 0x80 + (((unsigned)c >> 6) & 0x3f);
    buf[5] = 0x80 + (c & 0x3f);
    return 6;
}



    int utf_iscomposing_uint(UINT32_T c)
{
    return utf_iscomposing((int)c);
}



    int utf_iscomposing(int c)
{
    
    
    static struct interval combining[] = {
	{0x0300, 0x036f}, {0x0483, 0x0489}, {0x0591, 0x05bd}, {0x05bf, 0x05bf}, {0x05c1, 0x05c2}, {0x05c4, 0x05c5}, {0x05c7, 0x05c7}, {0x0610, 0x061a}, {0x064b, 0x065f}, {0x0670, 0x0670}, {0x06d6, 0x06dc}, {0x06df, 0x06e4}, {0x06e7, 0x06e8}, {0x06ea, 0x06ed}, {0x0711, 0x0711}, {0x0730, 0x074a}, {0x07a6, 0x07b0}, {0x07eb, 0x07f3}, {0x07fd, 0x07fd}, {0x0816, 0x0819}, {0x081b, 0x0823}, {0x0825, 0x0827}, {0x0829, 0x082d}, {0x0859, 0x085b}, {0x08d3, 0x08e1}, {0x08e3, 0x0903}, {0x093a, 0x093c}, {0x093e, 0x094f}, {0x0951, 0x0957}, {0x0962, 0x0963}, {0x0981, 0x0983}, {0x09bc, 0x09bc}, {0x09be, 0x09c4}, {0x09c7, 0x09c8}, {0x09cb, 0x09cd}, {0x09d7, 0x09d7}, {0x09e2, 0x09e3}, {0x09fe, 0x09fe}, {0x0a01, 0x0a03}, {0x0a3c, 0x0a3c}, {0x0a3e, 0x0a42}, {0x0a47, 0x0a48}, {0x0a4b, 0x0a4d}, {0x0a51, 0x0a51}, {0x0a70, 0x0a71}, {0x0a75, 0x0a75}, {0x0a81, 0x0a83}, {0x0abc, 0x0abc}, {0x0abe, 0x0ac5}, {0x0ac7, 0x0ac9}, {0x0acb, 0x0acd}, {0x0ae2, 0x0ae3}, {0x0afa, 0x0aff}, {0x0b01, 0x0b03}, {0x0b3c, 0x0b3c}, {0x0b3e, 0x0b44}, {0x0b47, 0x0b48}, {0x0b4b, 0x0b4d}, {0x0b55, 0x0b57}, {0x0b62, 0x0b63}, {0x0b82, 0x0b82}, {0x0bbe, 0x0bc2}, {0x0bc6, 0x0bc8}, {0x0bca, 0x0bcd}, {0x0bd7, 0x0bd7}, {0x0c00, 0x0c04}, {0x0c3e, 0x0c44}, {0x0c46, 0x0c48}, {0x0c4a, 0x0c4d}, {0x0c55, 0x0c56}, {0x0c62, 0x0c63}, {0x0c81, 0x0c83}, {0x0cbc, 0x0cbc}, {0x0cbe, 0x0cc4}, {0x0cc6, 0x0cc8}, {0x0cca, 0x0ccd}, {0x0cd5, 0x0cd6}, {0x0ce2, 0x0ce3}, {0x0d00, 0x0d03}, {0x0d3b, 0x0d3c}, {0x0d3e, 0x0d44}, {0x0d46, 0x0d48}, {0x0d4a, 0x0d4d}, {0x0d57, 0x0d57}, {0x0d62, 0x0d63}, {0x0d81, 0x0d83}, {0x0dca, 0x0dca}, {0x0dcf, 0x0dd4}, {0x0dd6, 0x0dd6}, {0x0dd8, 0x0ddf}, {0x0df2, 0x0df3}, {0x0e31, 0x0e31}, {0x0e34, 0x0e3a}, {0x0e47, 0x0e4e}, {0x0eb1, 0x0eb1}, {0x0eb4, 0x0ebc}, {0x0ec8, 0x0ecd}, {0x0f18, 0x0f19}, {0x0f35, 0x0f35}, {0x0f37, 0x0f37}, {0x0f39, 0x0f39}, {0x0f3e, 0x0f3f}, {0x0f71, 0x0f84}, {0x0f86, 0x0f87}, {0x0f8d, 0x0f97}, {0x0f99, 0x0fbc}, {0x0fc6, 0x0fc6}, {0x102b, 0x103e}, {0x1056, 0x1059}, {0x105e, 0x1060}, {0x1062, 0x1064}, {0x1067, 0x106d}, {0x1071, 0x1074}, {0x1082, 0x108d}, {0x108f, 0x108f}, {0x109a, 0x109d}, {0x135d, 0x135f}, {0x1712, 0x1714}, {0x1732, 0x1734}, {0x1752, 0x1753}, {0x1772, 0x1773}, {0x17b4, 0x17d3}, {0x17dd, 0x17dd}, {0x180b, 0x180d}, {0x1885, 0x1886}, {0x18a9, 0x18a9}, {0x1920, 0x192b}, {0x1930, 0x193b}, {0x1a17, 0x1a1b}, {0x1a55, 0x1a5e}, {0x1a60, 0x1a7c}, {0x1a7f, 0x1a7f}, {0x1ab0, 0x1ac0}, {0x1b00, 0x1b04}, {0x1b34, 0x1b44}, {0x1b6b, 0x1b73}, {0x1b80, 0x1b82}, {0x1ba1, 0x1bad}, {0x1be6, 0x1bf3}, {0x1c24, 0x1c37}, {0x1cd0, 0x1cd2}, {0x1cd4, 0x1ce8}, {0x1ced, 0x1ced}, {0x1cf4, 0x1cf4}, {0x1cf7, 0x1cf9}, {0x1dc0, 0x1df9}, {0x1dfb, 0x1dff}, {0x20d0, 0x20f0}, {0x2cef, 0x2cf1}, {0x2d7f, 0x2d7f}, {0x2de0, 0x2dff}, {0x302a, 0x302f}, {0x3099, 0x309a}, {0xa66f, 0xa672}, {0xa674, 0xa67d}, {0xa69e, 0xa69f}, {0xa6f0, 0xa6f1}, {0xa802, 0xa802}, {0xa806, 0xa806}, {0xa80b, 0xa80b}, {0xa823, 0xa827}, {0xa82c, 0xa82c}, {0xa880, 0xa881}, {0xa8b4, 0xa8c5}, {0xa8e0, 0xa8f1}, {0xa8ff, 0xa8ff}, {0xa926, 0xa92d}, {0xa947, 0xa953}, {0xa980, 0xa983}, {0xa9b3, 0xa9c0}, {0xa9e5, 0xa9e5}, {0xaa29, 0xaa36}, {0xaa43, 0xaa43}, {0xaa4c, 0xaa4d}, {0xaa7b, 0xaa7d}, {0xaab0, 0xaab0}, {0xaab2, 0xaab4}, {0xaab7, 0xaab8}, {0xaabe, 0xaabf}, {0xaac1, 0xaac1}, {0xaaeb, 0xaaef}, {0xaaf5, 0xaaf6}, {0xabe3, 0xabea}, {0xabec, 0xabed}, {0xfb1e, 0xfb1e}, {0xfe00, 0xfe0f}, {0xfe20, 0xfe2f}, {0x101fd, 0x101fd}, {0x102e0, 0x102e0}, {0x10376, 0x1037a}, {0x10a01, 0x10a03}, {0x10a05, 0x10a06}, {0x10a0c, 0x10a0f}, {0x10a38, 0x10a3a}, {0x10a3f, 0x10a3f}, {0x10ae5, 0x10ae6}, {0x10d24, 0x10d27}, {0x10eab, 0x10eac}, {0x10f46, 0x10f50}, {0x11000, 0x11002}, {0x11038, 0x11046}, {0x1107f, 0x11082}, {0x110b0, 0x110ba}, {0x11100, 0x11102}, {0x11127, 0x11134}, {0x11145, 0x11146}, {0x11173, 0x11173}, {0x11180, 0x11182}, {0x111b3, 0x111c0}, {0x111c9, 0x111cc}, {0x111ce, 0x111cf}, {0x1122c, 0x11237}, {0x1123e, 0x1123e}, {0x112df, 0x112ea}, {0x11300, 0x11303}, {0x1133b, 0x1133c}, {0x1133e, 0x11344}, {0x11347, 0x11348}, {0x1134b, 0x1134d}, {0x11357, 0x11357}, {0x11362, 0x11363}, {0x11366, 0x1136c}, {0x11370, 0x11374}, {0x11435, 0x11446}, {0x1145e, 0x1145e}, {0x114b0, 0x114c3}, {0x115af, 0x115b5}, {0x115b8, 0x115c0}, {0x115dc, 0x115dd}, {0x11630, 0x11640}, {0x116ab, 0x116b7}, {0x1171d, 0x1172b}, {0x1182c, 0x1183a}, {0x11930, 0x11935}, {0x11937, 0x11938}, {0x1193b, 0x1193e}, {0x11940, 0x11940}, {0x11942, 0x11943}, {0x119d1, 0x119d7}, {0x119da, 0x119e0}, {0x119e4, 0x119e4}, {0x11a01, 0x11a0a}, {0x11a33, 0x11a39}, {0x11a3b, 0x11a3e}, {0x11a47, 0x11a47}, {0x11a51, 0x11a5b}, {0x11a8a, 0x11a99}, {0x11c2f, 0x11c36}, {0x11c38, 0x11c3f}, {0x11c92, 0x11ca7}, {0x11ca9, 0x11cb6}, {0x11d31, 0x11d36}, {0x11d3a, 0x11d3a}, {0x11d3c, 0x11d3d}, {0x11d3f, 0x11d45}, {0x11d47, 0x11d47}, {0x11d8a, 0x11d8e}, {0x11d90, 0x11d91}, {0x11d93, 0x11d97}, {0x11ef3, 0x11ef6}, {0x16af0, 0x16af4}, {0x16b30, 0x16b36}, {0x16f4f, 0x16f4f}, {0x16f51, 0x16f87}, {0x16f8f, 0x16f92}, {0x16fe4, 0x16fe4}, {0x16ff0, 0x16ff1}, {0x1bc9d, 0x1bc9e}, {0x1d165, 0x1d169}, {0x1d16d, 0x1d172}, {0x1d17b, 0x1d182}, {0x1d185, 0x1d18b}, {0x1d1aa, 0x1d1ad}, {0x1d242, 0x1d244}, {0x1da00, 0x1da36}, {0x1da3b, 0x1da6c}, {0x1da75, 0x1da75}, {0x1da84, 0x1da84}, {0x1da9b, 0x1da9f}, {0x1daa1, 0x1daaf}, {0x1e000, 0x1e006}, {0x1e008, 0x1e018}, {0x1e01b, 0x1e021}, {0x1e023, 0x1e024}, {0x1e026, 0x1e02a}, {0x1e130, 0x1e136}, {0x1e2ec, 0x1e2ef}, {0x1e8d0, 0x1e8d6}, {0x1e944, 0x1e94a}, {0xe0100, 0xe01ef}
































































































































































































































































































    };

    return intable(combining, sizeof(combining), c);
}


    int utf_printable(int c)
{

    
    return iswprint(c);

    
    
    static struct interval nonprint[] = {
	{0x070f, 0x070f}, {0x180b, 0x180e}, {0x200b, 0x200f}, {0x202a, 0x202e}, {0x2060, 0x206f}, {0xd800, 0xdfff}, {0xfeff, 0xfeff}, {0xfff9, 0xfffb}, {0xfffe, 0xffff}

    };

    return !intable(nonprint, sizeof(nonprint), c);

}





static struct interval emoji_all[] = {
    {0x203c, 0x203c}, {0x2049, 0x2049}, {0x2122, 0x2122}, {0x2139, 0x2139}, {0x2194, 0x2199}, {0x21a9, 0x21aa}, {0x231a, 0x231b}, {0x2328, 0x2328}, {0x23cf, 0x23cf}, {0x23e9, 0x23f3}, {0x23f8, 0x23fa}, {0x24c2, 0x24c2}, {0x25aa, 0x25ab}, {0x25b6, 0x25b6}, {0x25c0, 0x25c0}, {0x25fb, 0x25fe}, {0x2600, 0x2604}, {0x260e, 0x260e}, {0x2611, 0x2611}, {0x2614, 0x2615}, {0x2618, 0x2618}, {0x261d, 0x261d}, {0x2620, 0x2620}, {0x2622, 0x2623}, {0x2626, 0x2626}, {0x262a, 0x262a}, {0x262e, 0x262f}, {0x2638, 0x263a}, {0x2640, 0x2640}, {0x2642, 0x2642}, {0x2648, 0x2653}, {0x265f, 0x2660}, {0x2663, 0x2663}, {0x2665, 0x2666}, {0x2668, 0x2668}, {0x267b, 0x267b}, {0x267e, 0x267f}, {0x2692, 0x2697}, {0x2699, 0x2699}, {0x269b, 0x269c}, {0x26a0, 0x26a1}, {0x26a7, 0x26a7}, {0x26aa, 0x26ab}, {0x26b0, 0x26b1}, {0x26bd, 0x26be}, {0x26c4, 0x26c5}, {0x26c8, 0x26c8}, {0x26ce, 0x26cf}, {0x26d1, 0x26d1}, {0x26d3, 0x26d4}, {0x26e9, 0x26ea}, {0x26f0, 0x26f5}, {0x26f7, 0x26fa}, {0x26fd, 0x26fd}, {0x2702, 0x2702}, {0x2705, 0x2705}, {0x2708, 0x270d}, {0x270f, 0x270f}, {0x2712, 0x2712}, {0x2714, 0x2714}, {0x2716, 0x2716}, {0x271d, 0x271d}, {0x2721, 0x2721}, {0x2728, 0x2728}, {0x2733, 0x2734}, {0x2744, 0x2744}, {0x2747, 0x2747}, {0x274c, 0x274c}, {0x274e, 0x274e}, {0x2753, 0x2755}, {0x2757, 0x2757}, {0x2763, 0x2764}, {0x2795, 0x2797}, {0x27a1, 0x27a1}, {0x27b0, 0x27b0}, {0x27bf, 0x27bf}, {0x2934, 0x2935}, {0x2b05, 0x2b07}, {0x2b1b, 0x2b1c}, {0x2b50, 0x2b50}, {0x2b55, 0x2b55}, {0x3030, 0x3030}, {0x303d, 0x303d}, {0x3297, 0x3297}, {0x3299, 0x3299}, {0x1f004, 0x1f004}, {0x1f0cf, 0x1f0cf}, {0x1f170, 0x1f171}, {0x1f17e, 0x1f17f}, {0x1f18e, 0x1f18e}, {0x1f191, 0x1f19a}, {0x1f1e6, 0x1f1ff}, {0x1f201, 0x1f202}, {0x1f21a, 0x1f21a}, {0x1f22f, 0x1f22f}, {0x1f232, 0x1f23a}, {0x1f250, 0x1f251}, {0x1f300, 0x1f321}, {0x1f324, 0x1f393}, {0x1f396, 0x1f397}, {0x1f399, 0x1f39b}, {0x1f39e, 0x1f3f0}, {0x1f3f3, 0x1f3f5}, {0x1f3f7, 0x1f4fd}, {0x1f4ff, 0x1f53d}, {0x1f549, 0x1f54e}, {0x1f550, 0x1f567}, {0x1f56f, 0x1f570}, {0x1f573, 0x1f57a}, {0x1f587, 0x1f587}, {0x1f58a, 0x1f58d}, {0x1f590, 0x1f590}, {0x1f595, 0x1f596}, {0x1f5a4, 0x1f5a5}, {0x1f5a8, 0x1f5a8}, {0x1f5b1, 0x1f5b2}, {0x1f5bc, 0x1f5bc}, {0x1f5c2, 0x1f5c4}, {0x1f5d1, 0x1f5d3}, {0x1f5dc, 0x1f5de}, {0x1f5e1, 0x1f5e1}, {0x1f5e3, 0x1f5e3}, {0x1f5e8, 0x1f5e8}, {0x1f5ef, 0x1f5ef}, {0x1f5f3, 0x1f5f3}, {0x1f5fa, 0x1f64f}, {0x1f680, 0x1f6c5}, {0x1f6cb, 0x1f6d2}, {0x1f6d5, 0x1f6d7}, {0x1f6e0, 0x1f6e5}, {0x1f6e9, 0x1f6e9}, {0x1f6eb, 0x1f6ec}, {0x1f6f0, 0x1f6f0}, {0x1f6f3, 0x1f6fc}, {0x1f7e0, 0x1f7eb}, {0x1f90c, 0x1f93a}, {0x1f93c, 0x1f945}, {0x1f947, 0x1f978}, {0x1f97a, 0x1f9cb}, {0x1f9cd, 0x1f9ff}, {0x1fa70, 0x1fa74}, {0x1fa78, 0x1fa7a}, {0x1fa80, 0x1fa86}, {0x1fa90, 0x1faa8}, {0x1fab0, 0x1fab6}, {0x1fac0, 0x1fac2}, {0x1fad0, 0x1fad6}

















































































































































};


    int utf_class(int c)
{
    return utf_class_buf(c, curbuf);
}

    int utf_class_buf(int c, buf_T *buf)
{
    
    static struct clinterval {
	unsigned int first;
	unsigned int last;
	unsigned int class;
    } classes[] = {
	{0x037e, 0x037e, 1},		 {0x0387, 0x0387, 1}, {0x055a, 0x055f, 1}, {0x0589, 0x0589, 1}, {0x05be, 0x05be, 1}, {0x05c0, 0x05c0, 1}, {0x05c3, 0x05c3, 1}, {0x05f3, 0x05f4, 1}, {0x060c, 0x060c, 1}, {0x061b, 0x061b, 1}, {0x061f, 0x061f, 1}, {0x066a, 0x066d, 1}, {0x06d4, 0x06d4, 1}, {0x0700, 0x070d, 1}, {0x0964, 0x0965, 1}, {0x0970, 0x0970, 1}, {0x0df4, 0x0df4, 1}, {0x0e4f, 0x0e4f, 1}, {0x0e5a, 0x0e5b, 1}, {0x0f04, 0x0f12, 1}, {0x0f3a, 0x0f3d, 1}, {0x0f85, 0x0f85, 1}, {0x104a, 0x104f, 1}, {0x10fb, 0x10fb, 1}, {0x1361, 0x1368, 1}, {0x166d, 0x166e, 1}, {0x1680, 0x1680, 0}, {0x169b, 0x169c, 1}, {0x16eb, 0x16ed, 1}, {0x1735, 0x1736, 1}, {0x17d4, 0x17dc, 1}, {0x1800, 0x180a, 1}, {0x2000, 0x200b, 0}, {0x200c, 0x2027, 1}, {0x2028, 0x2029, 0}, {0x202a, 0x202e, 1}, {0x202f, 0x202f, 0}, {0x2030, 0x205e, 1}, {0x205f, 0x205f, 0}, {0x2060, 0x27ff, 1}, {0x2070, 0x207f, 0x2070}, {0x2080, 0x2094, 0x2080}, {0x20a0, 0x27ff, 1}, {0x2800, 0x28ff, 0x2800}, {0x2900, 0x2998, 1}, {0x29d8, 0x29db, 1}, {0x29fc, 0x29fd, 1}, {0x2e00, 0x2e7f, 1}, {0x3000, 0x3000, 0}, {0x3001, 0x3020, 1}, {0x3030, 0x3030, 1}, {0x303d, 0x303d, 1}, {0x3040, 0x309f, 0x3040}, {0x30a0, 0x30ff, 0x30a0}, {0x3300, 0x9fff, 0x4e00}, {0xac00, 0xd7a3, 0xac00}, {0xf900, 0xfaff, 0x4e00}, {0xfd3e, 0xfd3f, 1}, {0xfe30, 0xfe6b, 1}, {0xff00, 0xff0f, 1}, {0xff1a, 0xff20, 1}, {0xff3b, 0xff40, 1}, {0xff5b, 0xff65, 1}, {0x1d000, 0x1d24f, 1}, {0x1d400, 0x1d7ff, 1}, {0x1f000, 0x1f2ff, 1}, {0x1f300, 0x1f9ff, 1}, {0x20000, 0x2a6df, 0x4e00}, {0x2a700, 0x2b73f, 0x4e00}, {0x2b740, 0x2b81f, 0x4e00}, {0x2f800, 0x2fa1f, 0x4e00}, };







































































    int bot = 0;
    int top = ARRAY_LENGTH(classes) - 1;
    int mid;

    
    if (c < 0x100)
    {
	if (c == ' ' || c == '\t' || c == NUL || c == 0xa0)
	    return 0;	    
	if (vim_iswordc_buf(c, buf))
	    return 2;	    
	return 1;	    
    }

    
    if (intable(emoji_all, sizeof(emoji_all), c))
	return 3;

    
    while (top >= bot)
    {
	mid = (bot + top) / 2;
	if (classes[mid].last < (unsigned int)c)
	    bot = mid + 1;
	else if (classes[mid].first > (unsigned int)c)
	    top = mid - 1;
	else return (int)classes[mid].class;
    }

    
    return 2;
}

    int utf_ambiguous_width(int c)
{
    return c >= 0x80 && (intable(ambiguous, sizeof(ambiguous), c)
	    || intable(emoji_all, sizeof(emoji_all), c));
}




typedef struct {
    int rangeStart;
    int rangeEnd;
    int step;
    int offset;
} convertStruct;

static convertStruct foldCase[] = {
	{0x41,0x5a,1,32}, {0xb5,0xb5,-1,775}, {0xc0,0xd6,1,32}, {0xd8,0xde,1,32}, {0x100,0x12e,2,1}, {0x132,0x136,2,1}, {0x139,0x147,2,1}, {0x14a,0x176,2,1}, {0x178,0x178,-1,-121}, {0x179,0x17d,2,1}, {0x17f,0x17f,-1,-268}, {0x181,0x181,-1,210}, {0x182,0x184,2,1}, {0x186,0x186,-1,206}, {0x187,0x187,-1,1}, {0x189,0x18a,1,205}, {0x18b,0x18b,-1,1}, {0x18e,0x18e,-1,79}, {0x18f,0x18f,-1,202}, {0x190,0x190,-1,203}, {0x191,0x191,-1,1}, {0x193,0x193,-1,205}, {0x194,0x194,-1,207}, {0x196,0x196,-1,211}, {0x197,0x197,-1,209}, {0x198,0x198,-1,1}, {0x19c,0x19c,-1,211}, {0x19d,0x19d,-1,213}, {0x19f,0x19f,-1,214}, {0x1a0,0x1a4,2,1}, {0x1a6,0x1a6,-1,218}, {0x1a7,0x1a7,-1,1}, {0x1a9,0x1a9,-1,218}, {0x1ac,0x1ac,-1,1}, {0x1ae,0x1ae,-1,218}, {0x1af,0x1af,-1,1}, {0x1b1,0x1b2,1,217}, {0x1b3,0x1b5,2,1}, {0x1b7,0x1b7,-1,219}, {0x1b8,0x1bc,4,1}, {0x1c4,0x1c4,-1,2}, {0x1c5,0x1c5,-1,1}, {0x1c7,0x1c7,-1,2}, {0x1c8,0x1c8,-1,1}, {0x1ca,0x1ca,-1,2}, {0x1cb,0x1db,2,1}, {0x1de,0x1ee,2,1}, {0x1f1,0x1f1,-1,2}, {0x1f2,0x1f4,2,1}, {0x1f6,0x1f6,-1,-97}, {0x1f7,0x1f7,-1,-56}, {0x1f8,0x21e,2,1}, {0x220,0x220,-1,-130}, {0x222,0x232,2,1}, {0x23a,0x23a,-1,10795}, {0x23b,0x23b,-1,1}, {0x23d,0x23d,-1,-163}, {0x23e,0x23e,-1,10792}, {0x241,0x241,-1,1}, {0x243,0x243,-1,-195}, {0x244,0x244,-1,69}, {0x245,0x245,-1,71}, {0x246,0x24e,2,1}, {0x345,0x345,-1,116}, {0x370,0x372,2,1}, {0x376,0x376,-1,1}, {0x37f,0x37f,-1,116}, {0x386,0x386,-1,38}, {0x388,0x38a,1,37}, {0x38c,0x38c,-1,64}, {0x38e,0x38f,1,63}, {0x391,0x3a1,1,32}, {0x3a3,0x3ab,1,32}, {0x3c2,0x3c2,-1,1}, {0x3cf,0x3cf,-1,8}, {0x3d0,0x3d0,-1,-30}, {0x3d1,0x3d1,-1,-25}, {0x3d5,0x3d5,-1,-15}, {0x3d6,0x3d6,-1,-22}, {0x3d8,0x3ee,2,1}, {0x3f0,0x3f0,-1,-54}, {0x3f1,0x3f1,-1,-48}, {0x3f4,0x3f4,-1,-60}, {0x3f5,0x3f5,-1,-64}, {0x3f7,0x3f7,-1,1}, {0x3f9,0x3f9,-1,-7}, {0x3fa,0x3fa,-1,1}, {0x3fd,0x3ff,1,-130}, {0x400,0x40f,1,80}, {0x410,0x42f,1,32}, {0x460,0x480,2,1}, {0x48a,0x4be,2,1}, {0x4c0,0x4c0,-1,15}, {0x4c1,0x4cd,2,1}, {0x4d0,0x52e,2,1}, {0x531,0x556,1,48}, {0x10a0,0x10c5,1,7264}, {0x10c7,0x10cd,6,7264}, {0x13f8,0x13fd,1,-8}, {0x1c80,0x1c80,-1,-6222}, {0x1c81,0x1c81,-1,-6221}, {0x1c82,0x1c82,-1,-6212}, {0x1c83,0x1c84,1,-6210}, {0x1c85,0x1c85,-1,-6211}, {0x1c86,0x1c86,-1,-6204}, {0x1c87,0x1c87,-1,-6180}, {0x1c88,0x1c88,-1,35267}, {0x1c90,0x1cba,1,-3008}, {0x1cbd,0x1cbf,1,-3008}, {0x1e00,0x1e94,2,1}, {0x1e9b,0x1e9b,-1,-58}, {0x1e9e,0x1e9e,-1,-7615}, {0x1ea0,0x1efe,2,1}, {0x1f08,0x1f0f,1,-8}, {0x1f18,0x1f1d,1,-8}, {0x1f28,0x1f2f,1,-8}, {0x1f38,0x1f3f,1,-8}, {0x1f48,0x1f4d,1,-8}, {0x1f59,0x1f5f,2,-8}, {0x1f68,0x1f6f,1,-8}, {0x1f88,0x1f8f,1,-8}, {0x1f98,0x1f9f,1,-8}, {0x1fa8,0x1faf,1,-8}, {0x1fb8,0x1fb9,1,-8}, {0x1fba,0x1fbb,1,-74}, {0x1fbc,0x1fbc,-1,-9}, {0x1fbe,0x1fbe,-1,-7173}, {0x1fc8,0x1fcb,1,-86}, {0x1fcc,0x1fcc,-1,-9}, {0x1fd8,0x1fd9,1,-8}, {0x1fda,0x1fdb,1,-100}, {0x1fe8,0x1fe9,1,-8}, {0x1fea,0x1feb,1,-112}, {0x1fec,0x1fec,-1,-7}, {0x1ff8,0x1ff9,1,-128}, {0x1ffa,0x1ffb,1,-126}, {0x1ffc,0x1ffc,-1,-9}, {0x2126,0x2126,-1,-7517}, {0x212a,0x212a,-1,-8383}, {0x212b,0x212b,-1,-8262}, {0x2132,0x2132,-1,28}, {0x2160,0x216f,1,16}, {0x2183,0x2183,-1,1}, {0x24b6,0x24cf,1,26}, {0x2c00,0x2c2e,1,48}, {0x2c60,0x2c60,-1,1}, {0x2c62,0x2c62,-1,-10743}, {0x2c63,0x2c63,-1,-3814}, {0x2c64,0x2c64,-1,-10727}, {0x2c67,0x2c6b,2,1}, {0x2c6d,0x2c6d,-1,-10780}, {0x2c6e,0x2c6e,-1,-10749}, {0x2c6f,0x2c6f,-1,-10783}, {0x2c70,0x2c70,-1,-10782}, {0x2c72,0x2c75,3,1}, {0x2c7e,0x2c7f,1,-10815}, {0x2c80,0x2ce2,2,1}, {0x2ceb,0x2ced,2,1}, {0x2cf2,0xa640,31054,1}, {0xa642,0xa66c,2,1}, {0xa680,0xa69a,2,1}, {0xa722,0xa72e,2,1}, {0xa732,0xa76e,2,1}, {0xa779,0xa77b,2,1}, {0xa77d,0xa77d,-1,-35332}, {0xa77e,0xa786,2,1}, {0xa78b,0xa78b,-1,1}, {0xa78d,0xa78d,-1,-42280}, {0xa790,0xa792,2,1}, {0xa796,0xa7a8,2,1}, {0xa7aa,0xa7aa,-1,-42308}, {0xa7ab,0xa7ab,-1,-42319}, {0xa7ac,0xa7ac,-1,-42315}, {0xa7ad,0xa7ad,-1,-42305}, {0xa7ae,0xa7ae,-1,-42308}, {0xa7b0,0xa7b0,-1,-42258}, {0xa7b1,0xa7b1,-1,-42282}, {0xa7b2,0xa7b2,-1,-42261}, {0xa7b3,0xa7b3,-1,928}, {0xa7b4,0xa7be,2,1}, {0xa7c2,0xa7c2,-1,1}, {0xa7c4,0xa7c4,-1,-48}, {0xa7c5,0xa7c5,-1,-42307}, {0xa7c6,0xa7c6,-1,-35384}, {0xa7c7,0xa7c9,2,1}, {0xa7f5,0xa7f5,-1,1}, {0xab70,0xabbf,1,-38864}, {0xff21,0xff3a,1,32}, {0x10400,0x10427,1,40}, {0x104b0,0x104d3,1,40}, {0x10c80,0x10cb2,1,64}, {0x118a0,0x118bf,1,32}, {0x16e40,0x16e5f,1,32}, {0x1e900,0x1e921,1,34}
































































































































































































};


    static int utf_convert( int			a, convertStruct	table[], int			tableSize)



{
    int start, mid, end; 
    int entries = tableSize / sizeof(convertStruct);

    start = 0;
    end = entries;
    while (start < end)
    {
	
	mid = (end + start) / 2;
	if (table[mid].rangeEnd < a)
	    start = mid + 1;
	else end = mid;
    }
    if (start < entries && table[start].rangeStart <= a && a <= table[start].rangeEnd && (a - table[start].rangeStart) % table[start].step == 0)


	return (a + table[start].offset);
    else return a;
}


    int utf_fold(int a)
{
    if (a < 0x80)
	
	return a >= 0x41 && a <= 0x5a ? a + 32 : a;
    return utf_convert(a, foldCase, (int)sizeof(foldCase));
}

static convertStruct toLower[] = {
	{0x41,0x5a,1,32}, {0xc0,0xd6,1,32}, {0xd8,0xde,1,32}, {0x100,0x12e,2,1}, {0x130,0x130,-1,-199}, {0x132,0x136,2,1}, {0x139,0x147,2,1}, {0x14a,0x176,2,1}, {0x178,0x178,-1,-121}, {0x179,0x17d,2,1}, {0x181,0x181,-1,210}, {0x182,0x184,2,1}, {0x186,0x186,-1,206}, {0x187,0x187,-1,1}, {0x189,0x18a,1,205}, {0x18b,0x18b,-1,1}, {0x18e,0x18e,-1,79}, {0x18f,0x18f,-1,202}, {0x190,0x190,-1,203}, {0x191,0x191,-1,1}, {0x193,0x193,-1,205}, {0x194,0x194,-1,207}, {0x196,0x196,-1,211}, {0x197,0x197,-1,209}, {0x198,0x198,-1,1}, {0x19c,0x19c,-1,211}, {0x19d,0x19d,-1,213}, {0x19f,0x19f,-1,214}, {0x1a0,0x1a4,2,1}, {0x1a6,0x1a6,-1,218}, {0x1a7,0x1a7,-1,1}, {0x1a9,0x1a9,-1,218}, {0x1ac,0x1ac,-1,1}, {0x1ae,0x1ae,-1,218}, {0x1af,0x1af,-1,1}, {0x1b1,0x1b2,1,217}, {0x1b3,0x1b5,2,1}, {0x1b7,0x1b7,-1,219}, {0x1b8,0x1bc,4,1}, {0x1c4,0x1c4,-1,2}, {0x1c5,0x1c5,-1,1}, {0x1c7,0x1c7,-1,2}, {0x1c8,0x1c8,-1,1}, {0x1ca,0x1ca,-1,2}, {0x1cb,0x1db,2,1}, {0x1de,0x1ee,2,1}, {0x1f1,0x1f1,-1,2}, {0x1f2,0x1f4,2,1}, {0x1f6,0x1f6,-1,-97}, {0x1f7,0x1f7,-1,-56}, {0x1f8,0x21e,2,1}, {0x220,0x220,-1,-130}, {0x222,0x232,2,1}, {0x23a,0x23a,-1,10795}, {0x23b,0x23b,-1,1}, {0x23d,0x23d,-1,-163}, {0x23e,0x23e,-1,10792}, {0x241,0x241,-1,1}, {0x243,0x243,-1,-195}, {0x244,0x244,-1,69}, {0x245,0x245,-1,71}, {0x246,0x24e,2,1}, {0x370,0x372,2,1}, {0x376,0x376,-1,1}, {0x37f,0x37f,-1,116}, {0x386,0x386,-1,38}, {0x388,0x38a,1,37}, {0x38c,0x38c,-1,64}, {0x38e,0x38f,1,63}, {0x391,0x3a1,1,32}, {0x3a3,0x3ab,1,32}, {0x3cf,0x3cf,-1,8}, {0x3d8,0x3ee,2,1}, {0x3f4,0x3f4,-1,-60}, {0x3f7,0x3f7,-1,1}, {0x3f9,0x3f9,-1,-7}, {0x3fa,0x3fa,-1,1}, {0x3fd,0x3ff,1,-130}, {0x400,0x40f,1,80}, {0x410,0x42f,1,32}, {0x460,0x480,2,1}, {0x48a,0x4be,2,1}, {0x4c0,0x4c0,-1,15}, {0x4c1,0x4cd,2,1}, {0x4d0,0x52e,2,1}, {0x531,0x556,1,48}, {0x10a0,0x10c5,1,7264}, {0x10c7,0x10cd,6,7264}, {0x13a0,0x13ef,1,38864}, {0x13f0,0x13f5,1,8}, {0x1c90,0x1cba,1,-3008}, {0x1cbd,0x1cbf,1,-3008}, {0x1e00,0x1e94,2,1}, {0x1e9e,0x1e9e,-1,-7615}, {0x1ea0,0x1efe,2,1}, {0x1f08,0x1f0f,1,-8}, {0x1f18,0x1f1d,1,-8}, {0x1f28,0x1f2f,1,-8}, {0x1f38,0x1f3f,1,-8}, {0x1f48,0x1f4d,1,-8}, {0x1f59,0x1f5f,2,-8}, {0x1f68,0x1f6f,1,-8}, {0x1f88,0x1f8f,1,-8}, {0x1f98,0x1f9f,1,-8}, {0x1fa8,0x1faf,1,-8}, {0x1fb8,0x1fb9,1,-8}, {0x1fba,0x1fbb,1,-74}, {0x1fbc,0x1fbc,-1,-9}, {0x1fc8,0x1fcb,1,-86}, {0x1fcc,0x1fcc,-1,-9}, {0x1fd8,0x1fd9,1,-8}, {0x1fda,0x1fdb,1,-100}, {0x1fe8,0x1fe9,1,-8}, {0x1fea,0x1feb,1,-112}, {0x1fec,0x1fec,-1,-7}, {0x1ff8,0x1ff9,1,-128}, {0x1ffa,0x1ffb,1,-126}, {0x1ffc,0x1ffc,-1,-9}, {0x2126,0x2126,-1,-7517}, {0x212a,0x212a,-1,-8383}, {0x212b,0x212b,-1,-8262}, {0x2132,0x2132,-1,28}, {0x2160,0x216f,1,16}, {0x2183,0x2183,-1,1}, {0x24b6,0x24cf,1,26}, {0x2c00,0x2c2e,1,48}, {0x2c60,0x2c60,-1,1}, {0x2c62,0x2c62,-1,-10743}, {0x2c63,0x2c63,-1,-3814}, {0x2c64,0x2c64,-1,-10727}, {0x2c67,0x2c6b,2,1}, {0x2c6d,0x2c6d,-1,-10780}, {0x2c6e,0x2c6e,-1,-10749}, {0x2c6f,0x2c6f,-1,-10783}, {0x2c70,0x2c70,-1,-10782}, {0x2c72,0x2c75,3,1}, {0x2c7e,0x2c7f,1,-10815}, {0x2c80,0x2ce2,2,1}, {0x2ceb,0x2ced,2,1}, {0x2cf2,0xa640,31054,1}, {0xa642,0xa66c,2,1}, {0xa680,0xa69a,2,1}, {0xa722,0xa72e,2,1}, {0xa732,0xa76e,2,1}, {0xa779,0xa77b,2,1}, {0xa77d,0xa77d,-1,-35332}, {0xa77e,0xa786,2,1}, {0xa78b,0xa78b,-1,1}, {0xa78d,0xa78d,-1,-42280}, {0xa790,0xa792,2,1}, {0xa796,0xa7a8,2,1}, {0xa7aa,0xa7aa,-1,-42308}, {0xa7ab,0xa7ab,-1,-42319}, {0xa7ac,0xa7ac,-1,-42315}, {0xa7ad,0xa7ad,-1,-42305}, {0xa7ae,0xa7ae,-1,-42308}, {0xa7b0,0xa7b0,-1,-42258}, {0xa7b1,0xa7b1,-1,-42282}, {0xa7b2,0xa7b2,-1,-42261}, {0xa7b3,0xa7b3,-1,928}, {0xa7b4,0xa7be,2,1}, {0xa7c2,0xa7c2,-1,1}, {0xa7c4,0xa7c4,-1,-48}, {0xa7c5,0xa7c5,-1,-42307}, {0xa7c6,0xa7c6,-1,-35384}, {0xa7c7,0xa7c9,2,1}, {0xa7f5,0xa7f5,-1,1}, {0xff21,0xff3a,1,32}, {0x10400,0x10427,1,40}, {0x104b0,0x104d3,1,40}, {0x10c80,0x10cb2,1,64}, {0x118a0,0x118bf,1,32}, {0x16e40,0x16e5f,1,32}, {0x1e900,0x1e921,1,34}












































































































































































};

static convertStruct toUpper[] = {
	{0x61,0x7a,1,-32}, {0xb5,0xb5,-1,743}, {0xe0,0xf6,1,-32}, {0xf8,0xfe,1,-32}, {0xff,0xff,-1,121}, {0x101,0x12f,2,-1}, {0x131,0x131,-1,-232}, {0x133,0x137,2,-1}, {0x13a,0x148,2,-1}, {0x14b,0x177,2,-1}, {0x17a,0x17e,2,-1}, {0x17f,0x17f,-1,-300}, {0x180,0x180,-1,195}, {0x183,0x185,2,-1}, {0x188,0x18c,4,-1}, {0x192,0x192,-1,-1}, {0x195,0x195,-1,97}, {0x199,0x199,-1,-1}, {0x19a,0x19a,-1,163}, {0x19e,0x19e,-1,130}, {0x1a1,0x1a5,2,-1}, {0x1a8,0x1ad,5,-1}, {0x1b0,0x1b4,4,-1}, {0x1b6,0x1b9,3,-1}, {0x1bd,0x1bd,-1,-1}, {0x1bf,0x1bf,-1,56}, {0x1c5,0x1c5,-1,-1}, {0x1c6,0x1c6,-1,-2}, {0x1c8,0x1c8,-1,-1}, {0x1c9,0x1c9,-1,-2}, {0x1cb,0x1cb,-1,-1}, {0x1cc,0x1cc,-1,-2}, {0x1ce,0x1dc,2,-1}, {0x1dd,0x1dd,-1,-79}, {0x1df,0x1ef,2,-1}, {0x1f2,0x1f2,-1,-1}, {0x1f3,0x1f3,-1,-2}, {0x1f5,0x1f9,4,-1}, {0x1fb,0x21f,2,-1}, {0x223,0x233,2,-1}, {0x23c,0x23c,-1,-1}, {0x23f,0x240,1,10815}, {0x242,0x247,5,-1}, {0x249,0x24f,2,-1}, {0x250,0x250,-1,10783}, {0x251,0x251,-1,10780}, {0x252,0x252,-1,10782}, {0x253,0x253,-1,-210}, {0x254,0x254,-1,-206}, {0x256,0x257,1,-205}, {0x259,0x259,-1,-202}, {0x25b,0x25b,-1,-203}, {0x25c,0x25c,-1,42319}, {0x260,0x260,-1,-205}, {0x261,0x261,-1,42315}, {0x263,0x263,-1,-207}, {0x265,0x265,-1,42280}, {0x266,0x266,-1,42308}, {0x268,0x268,-1,-209}, {0x269,0x269,-1,-211}, {0x26a,0x26a,-1,42308}, {0x26b,0x26b,-1,10743}, {0x26c,0x26c,-1,42305}, {0x26f,0x26f,-1,-211}, {0x271,0x271,-1,10749}, {0x272,0x272,-1,-213}, {0x275,0x275,-1,-214}, {0x27d,0x27d,-1,10727}, {0x280,0x280,-1,-218}, {0x282,0x282,-1,42307}, {0x283,0x283,-1,-218}, {0x287,0x287,-1,42282}, {0x288,0x288,-1,-218}, {0x289,0x289,-1,-69}, {0x28a,0x28b,1,-217}, {0x28c,0x28c,-1,-71}, {0x292,0x292,-1,-219}, {0x29d,0x29d,-1,42261}, {0x29e,0x29e,-1,42258}, {0x345,0x345,-1,84}, {0x371,0x373,2,-1}, {0x377,0x377,-1,-1}, {0x37b,0x37d,1,130}, {0x3ac,0x3ac,-1,-38}, {0x3ad,0x3af,1,-37}, {0x3b1,0x3c1,1,-32}, {0x3c2,0x3c2,-1,-31}, {0x3c3,0x3cb,1,-32}, {0x3cc,0x3cc,-1,-64}, {0x3cd,0x3ce,1,-63}, {0x3d0,0x3d0,-1,-62}, {0x3d1,0x3d1,-1,-57}, {0x3d5,0x3d5,-1,-47}, {0x3d6,0x3d6,-1,-54}, {0x3d7,0x3d7,-1,-8}, {0x3d9,0x3ef,2,-1}, {0x3f0,0x3f0,-1,-86}, {0x3f1,0x3f1,-1,-80}, {0x3f2,0x3f2,-1,7}, {0x3f3,0x3f3,-1,-116}, {0x3f5,0x3f5,-1,-96}, {0x3f8,0x3fb,3,-1}, {0x430,0x44f,1,-32}, {0x450,0x45f,1,-80}, {0x461,0x481,2,-1}, {0x48b,0x4bf,2,-1}, {0x4c2,0x4ce,2,-1}, {0x4cf,0x4cf,-1,-15}, {0x4d1,0x52f,2,-1}, {0x561,0x586,1,-48}, {0x10d0,0x10fa,1,3008}, {0x10fd,0x10ff,1,3008}, {0x13f8,0x13fd,1,-8}, {0x1c80,0x1c80,-1,-6254}, {0x1c81,0x1c81,-1,-6253}, {0x1c82,0x1c82,-1,-6244}, {0x1c83,0x1c84,1,-6242}, {0x1c85,0x1c85,-1,-6243}, {0x1c86,0x1c86,-1,-6236}, {0x1c87,0x1c87,-1,-6181}, {0x1c88,0x1c88,-1,35266}, {0x1d79,0x1d79,-1,35332}, {0x1d7d,0x1d7d,-1,3814}, {0x1d8e,0x1d8e,-1,35384}, {0x1e01,0x1e95,2,-1}, {0x1e9b,0x1e9b,-1,-59}, {0x1ea1,0x1eff,2,-1}, {0x1f00,0x1f07,1,8}, {0x1f10,0x1f15,1,8}, {0x1f20,0x1f27,1,8}, {0x1f30,0x1f37,1,8}, {0x1f40,0x1f45,1,8}, {0x1f51,0x1f57,2,8}, {0x1f60,0x1f67,1,8}, {0x1f70,0x1f71,1,74}, {0x1f72,0x1f75,1,86}, {0x1f76,0x1f77,1,100}, {0x1f78,0x1f79,1,128}, {0x1f7a,0x1f7b,1,112}, {0x1f7c,0x1f7d,1,126}, {0x1f80,0x1f87,1,8}, {0x1f90,0x1f97,1,8}, {0x1fa0,0x1fa7,1,8}, {0x1fb0,0x1fb1,1,8}, {0x1fb3,0x1fb3,-1,9}, {0x1fbe,0x1fbe,-1,-7205}, {0x1fc3,0x1fc3,-1,9}, {0x1fd0,0x1fd1,1,8}, {0x1fe0,0x1fe1,1,8}, {0x1fe5,0x1fe5,-1,7}, {0x1ff3,0x1ff3,-1,9}, {0x214e,0x214e,-1,-28}, {0x2170,0x217f,1,-16}, {0x2184,0x2184,-1,-1}, {0x24d0,0x24e9,1,-26}, {0x2c30,0x2c5e,1,-48}, {0x2c61,0x2c61,-1,-1}, {0x2c65,0x2c65,-1,-10795}, {0x2c66,0x2c66,-1,-10792}, {0x2c68,0x2c6c,2,-1}, {0x2c73,0x2c76,3,-1}, {0x2c81,0x2ce3,2,-1}, {0x2cec,0x2cee,2,-1}, {0x2cf3,0x2cf3,-1,-1}, {0x2d00,0x2d25,1,-7264}, {0x2d27,0x2d2d,6,-7264}, {0xa641,0xa66d,2,-1}, {0xa681,0xa69b,2,-1}, {0xa723,0xa72f,2,-1}, {0xa733,0xa76f,2,-1}, {0xa77a,0xa77c,2,-1}, {0xa77f,0xa787,2,-1}, {0xa78c,0xa791,5,-1}, {0xa793,0xa793,-1,-1}, {0xa794,0xa794,-1,48}, {0xa797,0xa7a9,2,-1}, {0xa7b5,0xa7bf,2,-1}, {0xa7c3,0xa7c8,5,-1}, {0xa7ca,0xa7f6,44,-1}, {0xab53,0xab53,-1,-928}, {0xab70,0xabbf,1,-38864}, {0xff41,0xff5a,1,-32}, {0x10428,0x1044f,1,-40}, {0x104d8,0x104fb,1,-40}, {0x10cc0,0x10cf2,1,-64}, {0x118c0,0x118df,1,-32}, {0x16e60,0x16e7f,1,-32}, {0x1e922,0x1e943,1,-34}


























































































































































































};


    int utf_toupper(int a)
{
    
    if (a < 128 && (cmp_flags & CMP_KEEPASCII))
	return TOUPPER_ASC(a);


    
    if (!(cmp_flags & CMP_INTERNAL))
	return towupper(a);


    
    if (a < 128)
	return TOUPPER_LOC(a);

    
    return utf_convert(a, toUpper, (int)sizeof(toUpper));
}

    int utf_islower(int a)
{
    
    return (utf_toupper(a) != a) || a == 0xdf;
}


    int utf_tolower(int a)
{
    
    if (a < 128 && (cmp_flags & CMP_KEEPASCII))
	return TOLOWER_ASC(a);


    
    if (!(cmp_flags & CMP_INTERNAL))
	return towlower(a);


    
    if (a < 128)
	return TOLOWER_LOC(a);

    
    return utf_convert(a, toLower, (int)sizeof(toLower));
}

    int utf_isupper(int a)
{
    return (utf_tolower(a) != a);
}

    static int utf_strnicmp( char_u      *s1, char_u      *s2, size_t      n1, size_t      n2)




{
    int		c1, c2, cdiff;
    char_u	buffer[6];

    for (;;)
    {
	c1 = utf_safe_read_char_adv(&s1, &n1);
	c2 = utf_safe_read_char_adv(&s2, &n2);

	if (c1 <= 0 || c2 <= 0)
	    break;

	if (c1 == c2)
	    continue;

	cdiff = utf_fold(c1) - utf_fold(c2);
	if (cdiff != 0)
	    return cdiff;
    }

    

    if (c1 == 0 || c2 == 0)
    {
	
	if (c1 == 0 && c2 == 0)
	    return 0;
	return c1 == 0 ? -1 : 1;
    }

    
    
    
    
    
    

    if (c1 != -1 && c2 == -1)
    {
	n1 = utf_char2bytes(utf_fold(c1), buffer);
	s1 = buffer;
    }
    else if (c2 != -1 && c1 == -1)
    {
	n2 = utf_char2bytes(utf_fold(c2), buffer);
	s2 = buffer;
    }

    while (n1 > 0 && n2 > 0 && *s1 != NUL && *s2 != NUL)
    {
	cdiff = (int)(*s1) - (int)(*s2);
	if (cdiff != 0)
	    return cdiff;

	s1++;
	s2++;
	n1--;
	n2--;
    }

    if (n1 > 0 && *s1 == NUL)
	n1 = 0;
    if (n2 > 0 && *s2 == NUL)
	n2 = 0;

    if (n1 == 0 && n2 == 0)
	return 0;
    return n1 == 0 ? -1 : 1;
}


    int mb_strnicmp(char_u *s1, char_u *s2, size_t nn)
{
    int		i, l;
    int		cdiff;
    int		n = (int)nn;

    if (enc_utf8)
    {
	return utf_strnicmp(s1, s2, nn, nn);
    }
    else {
	for (i = 0; i < n; i += l)
	{
	    if (s1[i] == NUL && s2[i] == NUL)	
		return 0;

	    l = (*mb_ptr2len)(s1 + i);
	    if (l <= 1)
	    {
		
		if (s1[i] != s2[i])
		{
		    cdiff = MB_TOLOWER(s1[i]) - MB_TOLOWER(s2[i]);
		    if (cdiff != 0)
			return cdiff;
		}
	    }
	    else {
		
		if (l > n - i)
		    l = n - i;
		cdiff = STRNCMP(s1 + i, s2 + i, l);
		if (cdiff != 0)
		    return cdiff;
	    }
	}
    }
    return 0;
}


    void show_utf8(void)
{
    int		len;
    int		rlen = 0;
    char_u	*line;
    int		clen;
    int		i;

    
    
    line = ml_get_cursor();
    len = utfc_ptr2len(line);
    if (len == 0)
    {
	msg("NUL");
	return;
    }

    clen = 0;
    for (i = 0; i < len; ++i)
    {
	if (clen == 0)
	{
	    
	    if (i > 0)
	    {
		STRCPY(IObuff + rlen, "+ ");
		rlen += 2;
	    }
	    clen = utf_ptr2len(line + i);
	}
	sprintf((char *)IObuff + rlen, "%02x ", (line[i] == NL) ? NUL : line[i]);
	--clen;
	rlen += (int)STRLEN(IObuff + rlen);
	if (rlen > IOSIZE - 20)
	    break;
    }

    msg((char *)IObuff);
}


    int latin_head_off(char_u *base UNUSED, char_u *p UNUSED)
{
    return 0;
}

    static int dbcs_head_off(char_u *base, char_u *p)
{
    char_u	*q;

    
    
    if (p <= base || MB_BYTE2LEN(p[-1]) == 1 || *p == NUL)
	return 0;

    
    
    q = base;
    while (q < p)
	q += dbcs_ptr2len(q);
    return (q == p) ? 0 : 1;
}


    int dbcs_screen_head_off(char_u *base, char_u *p)
{
    char_u	*q;

    
    
    
    
    if (p <= base || (enc_dbcs == DBCS_JPNU && p[-1] == 0x8e)
	    || MB_BYTE2LEN(p[-1]) == 1 || *p == NUL)
	return 0;

    
    
    
    
    q = base;
    while (q < p)
    {
	if (enc_dbcs == DBCS_JPNU && *q == 0x8e)
	    ++q;
	else q += dbcs_ptr2len(q);
    }
    return (q == p) ? 0 : 1;
}


    int utf_head_off(char_u *base, char_u *p)
{
    char_u	*q;
    char_u	*s;
    int		c;
    int		len;

    char_u	*j;


    if (*p < 0x80)		
	return 0;

    
    
    for (q = p; ; --q)
    {
	
	for (s = q; (s[1] & 0xc0) == 0x80; ++s)
	    ;
	
	while (q > base && (*q & 0xc0) == 0x80)
	    --q;
	
	
	len = utf8len_tab[*q];
	if (len != (int)(s - q + 1) && len != (int)(p - q + 1))
	    return 0;

	if (q <= base)
	    break;

	c = utf_ptr2char(q);
	if (utf_iscomposing(c))
	    continue;


	if (arabic_maycombine(c))
	{
	    
	    j = q;
	    --j;
	    
	    while (j > base && (*j & 0xc0) == 0x80)
		--j;
	    if (arabic_combine(utf_ptr2char(j), c))
		continue;
	}

	break;
    }

    return (int)(p - q);
}


    int utf_eat_space(int cc)
{
    return ((cc >= 0x2000 && cc <= 0x206F)	
	 || (cc >= 0x2e00 && cc <= 0x2e7f)	
	 || (cc >= 0x3000 && cc <= 0x303f)	
	 || (cc >= 0xff01 && cc <= 0xff0f)	
	 || (cc >= 0xff1a && cc <= 0xff20)	
	 || (cc >= 0xff3b && cc <= 0xff40)	
	 || (cc >= 0xff5b && cc <= 0xff65));	
}


    int utf_allow_break_before(int cc)
{
    static const int BOL_prohibition_punct[] = {
	'!', '%', ')', ',', ':', ';', '>', '?', ']', '}', 0x2019, 0x201d, 0x2020, 0x2021, 0x2026, 0x2030, 0x2031, 0x203c, 0x2047, 0x2048, 0x2049, 0x2103, 0x2109, 0x3001, 0x3002, 0x3009, 0x300b, 0x300d, 0x300f, 0x3011, 0x3015, 0x3017, 0x3019, 0x301b, 0xff01, 0xff09, 0xff0c, 0xff0e, 0xff1a, 0xff1b, 0xff1f, 0xff3d, 0xff5d, };











































    int first = 0;
    int last  = ARRAY_LENGTH(BOL_prohibition_punct) - 1;
    int mid   = 0;

    while (first < last)
    {
	mid = (first + last)/2;

	if (cc == BOL_prohibition_punct[mid])
	    return FALSE;
	else if (cc > BOL_prohibition_punct[mid])
	    first = mid + 1;
	else last = mid - 1;
    }

    return cc != BOL_prohibition_punct[first];
}


    static int utf_allow_break_after(int cc)
{
    static const int EOL_prohibition_punct[] = {
	'(', '<', '[', '`', '{',  0x2018, 0x201c,  0x3008, 0x300a, 0x300c, 0x300e, 0x3010, 0x3014, 0x3016, 0x3018, 0x301a, 0xff08, 0xff3b, 0xff5b, };





















    int first = 0;
    int last  = ARRAY_LENGTH(EOL_prohibition_punct) - 1;
    int mid   = 0;

    while (first < last)
    {
	mid = (first + last)/2;

	if (cc == EOL_prohibition_punct[mid])
	    return FALSE;
	else if (cc > EOL_prohibition_punct[mid])
	    first = mid + 1;
	else last = mid - 1;
    }

    return cc != EOL_prohibition_punct[first];
}


    int utf_allow_break(int cc, int ncc)
{
    
    if (cc == ncc && (cc == 0x2014 || cc == 0x2026))

	return FALSE;

    return utf_allow_break_after(cc) && utf_allow_break_before(ncc);
}


    void mb_copy_char(char_u **fp, char_u **tp)
{
    int	    l = (*mb_ptr2len)(*fp);

    mch_memmove(*tp, *fp, (size_t)l);
    *tp += l;
    *fp += l;
}


    int mb_off_next(char_u *base, char_u *p)
{
    int		i;
    int		j;

    if (enc_utf8)
    {
	if (*p < 0x80)		
	    return 0;

	
	for (i = 0; (p[i] & 0xc0) == 0x80; ++i)
	    ;
	if (i > 0)
	{
	    
	    for (j = 0; p - j > base; ++j)
		if ((p[-j] & 0xc0) != 0x80)
		    break;
	    if (utf8len_tab[p[-j]] != i + j)
		return 0;
	}
	return i;
    }

    
    
    return (*mb_head_off)(base, p);
}


    int mb_tail_off(char_u *base, char_u *p)
{
    int		i;
    int		j;

    if (*p == NUL)
	return 0;

    if (enc_utf8)
    {
	
	for (i = 0; (p[i + 1] & 0xc0) == 0x80; ++i)
	    ;
	
	for (j = 0; p - j > base; ++j)
	    if ((p[-j] & 0xc0) != 0x80)
		break;
	if (utf8len_tab[p[-j]] != i + j + 1)
	    return 0;
	return i;
    }

    
    
    if (enc_dbcs == 0 || p[1] == NUL || MB_BYTE2LEN(*p) == 1)
	return 0;

    
    return 1 - dbcs_head_off(base, p);
}


    void utf_find_illegal(void)
{
    pos_T	pos = curwin->w_cursor;
    char_u	*p;
    int		len;
    vimconv_T	vimconv;
    char_u	*tofree = NULL;

    vimconv.vc_type = CONV_NONE;
    if (enc_utf8 && (enc_canon_props(curbuf->b_p_fenc) & ENC_8BIT))
    {
	
	
	
	convert_setup(&vimconv, p_enc, curbuf->b_p_fenc);
    }

    curwin->w_cursor.coladd = 0;
    for (;;)
    {
	p = ml_get_cursor();
	if (vimconv.vc_type != CONV_NONE)
	{
	    vim_free(tofree);
	    tofree = string_convert(&vimconv, p, NULL);
	    if (tofree == NULL)
		break;
	    p = tofree;
	}

	while (*p != NUL)
	{
	    
	    
	    len = utf_ptr2len(p);
	    if (*p >= 0x80 && (len == 1 || utf_char2len(utf_ptr2char(p)) != len))
	    {
		if (vimconv.vc_type == CONV_NONE)
		    curwin->w_cursor.col += (colnr_T)(p - ml_get_cursor());
		else {
		    int	    l;

		    len = (int)(p - tofree);
		    for (p = ml_get_cursor(); *p != NUL && len-- > 0; p += l)
		    {
			l = utf_ptr2len(p);
			curwin->w_cursor.col += l;
		    }
		}
		goto theend;
	    }
	    p += len;
	}
	if (curwin->w_cursor.lnum == curbuf->b_ml.ml_line_count)
	    break;
	++curwin->w_cursor.lnum;
	curwin->w_cursor.col = 0;
    }

    
    curwin->w_cursor = pos;
    beep_flush();

theend:
    vim_free(tofree);
    convert_setup(&vimconv, NULL, NULL);
}



    int utf_valid_string(char_u *s, char_u *end)
{
    int		l;
    char_u	*p = s;

    while (end == NULL ? *p != NUL : p < end)
    {
	l = utf8len_tab_zero[*p];
	if (l == 0)
	    return FALSE;	
	if (end != NULL && p + l > end)
	    return FALSE;	
	++p;
	while (--l > 0)
	    if ((*p++ & 0xc0) != 0x80)
		return FALSE;	
    }
    return TRUE;
}




    int dbcs_screen_tail_off(char_u *base, char_u *p)
{
    
    
    
    
    if (*p == NUL || p[1] == NUL || (enc_dbcs == DBCS_JPNU && *p == 0x8e)
	    || MB_BYTE2LEN(*p) == 1)
	return 0;

    
    return 1 - dbcs_screen_head_off(base, p);
}



    void mb_adjust_cursor(void)
{
    mb_adjustpos(curbuf, &curwin->w_cursor);
}


    void mb_adjustpos(buf_T *buf, pos_T *lp)
{
    char_u	*p;

    if (lp->col > 0 || lp->coladd > 1)
    {
	p = ml_get_buf(buf, lp->lnum, FALSE);
	if (*p == NUL || (int)STRLEN(p) < lp->col)
	    lp->col = 0;
	else lp->col -= (*mb_head_off)(p, p + lp->col);
	
	
	if (lp->coladd == 1 && p[lp->col] != TAB && vim_isprintc((*mb_ptr2char)(p + lp->col))

		&& ptr2cells(p + lp->col) > 1)
	    lp->coladd = 0;
    }
}


    char_u * mb_prevptr( char_u *line, char_u *p)


{
    if (p > line)
	MB_PTR_BACK(line, p);
    return p;
}


    int mb_charlen(char_u *str)
{
    char_u	*p = str;
    int		count;

    if (p == NULL)
	return 0;

    for (count = 0; *p != NUL; count++)
	p += (*mb_ptr2len)(p);

    return count;
}


    int mb_charlen_len(char_u *str, int len)
{
    char_u	*p = str;
    int		count;

    for (count = 0; *p != NUL && p < str + len; count++)
	p += (*mb_ptr2len)(p);

    return count;
}


    char_u * mb_unescape(char_u **pp)
{
    static char_u	buf[6];
    int			n;
    int			m = 0;
    char_u		*str = *pp;

    
    
    
    for (n = 0; str[n] != NUL && m < 4; ++n)
    {
	if (str[n] == K_SPECIAL && str[n + 1] == KS_SPECIAL && str[n + 2] == KE_FILLER)

	{
	    buf[m++] = K_SPECIAL;
	    n += 2;
	}
	else if ((str[n] == K_SPECIAL  || str[n] == CSI  )



		&& str[n + 1] == KS_EXTRA && str[n + 2] == (int)KE_CSI)
	{
	    buf[m++] = CSI;
	    n += 2;
	}
	else if (str[n] == K_SPECIAL  || str[n] == CSI  )



	    break;		
	else buf[m++] = str[n];
	buf[m] = NUL;

	
	
	if ((*mb_ptr2len)(buf) > 1)
	{
	    *pp = str + n + 1;
	    return buf;
	}

	
	if (buf[0] < 128)
	    break;
    }
    return NULL;
}


    int mb_lefthalve(int row, int col)
{
    return (*mb_off2cells)(LineOffset[row] + col, LineOffset[row] + screen_Columns) > 1;
}


    int mb_fix_col(int col, int row)
{
    int off;

    col = check_col(col);
    row = check_row(row);
    off = LineOffset[row] + col;
    if (has_mbyte && ScreenLines != NULL && col > 0 && ((enc_dbcs && ScreenLines[off] != NUL && dbcs_screen_head_off(ScreenLines + LineOffset[row], ScreenLines + off))



		|| (enc_utf8 && ScreenLines[off] == 0 && ScreenLinesUC[off] == 0)))
	return col - 1;
    return col;
}

static int enc_alias_search(char_u *name);


    char_u * enc_skip(char_u *p)
{
    if (STRNCMP(p, "2byte-", 6) == 0)
	return p + 6;
    if (STRNCMP(p, "8bit-", 5) == 0)
	return p + 5;
    return p;
}


    char_u * enc_canonize(char_u *enc)
{
    char_u	*r;
    char_u	*p, *s;
    int		i;

    if (STRCMP(enc, "default") == 0)
    {

	
	r = enc_locale();

	
	r = get_encoding_default();

	if (r == NULL)
	    r = (char_u *)ENC_DFLT;
	return vim_strsave(r);
    }

    
    r = alloc(STRLEN(enc) + 3);
    if (r != NULL)
    {
	
	p = r;
	for (s = enc; *s != NUL; ++s)
	{
	    if (*s == '_')
		*p++ = '-';
	    else *p++ = TOLOWER_ASC(*s);
	}
	*p = NUL;

	
	p = enc_skip(r);

	
	if (STRNCMP(p, "microsoft-cp", 12) == 0)
	    STRMOVE(p, p + 10);

	
	if (STRNCMP(p, "iso8859", 7) == 0)
	{
	    STRMOVE(p + 4, p + 3);
	    p[3] = '-';
	}

	
	if (STRNCMP(p, "iso-8859", 8) == 0 && isdigit(p[8]))
	{
	    STRMOVE(p + 9, p + 8);
	    p[8] = '-';
	}

	
	if (STRNCMP(p, "latin-", 6) == 0)
	    STRMOVE(p + 5, p + 6);

	if (enc_canon_search(p) >= 0)
	{
	    
	    if (p != r)
		STRMOVE(r, p);
	}
	else if ((i = enc_alias_search(p)) >= 0)
	{
	    
	    vim_free(r);
	    r = vim_strsave((char_u *)enc_canon_table[i].name);
	}
    }
    return r;
}


    static int enc_alias_search(char_u *name)
{
    int		i;

    for (i = 0; enc_alias_table[i].name != NULL; ++i)
	if (STRCMP(name, enc_alias_table[i].name) == 0)
	    return enc_alias_table[i].canon;
    return -1;
}








    char_u * enc_locale_env(char *locale)
{
    char	*s = locale;
    char	*p;
    int		i;
    char	buf[50];

    if (s == NULL || *s == NUL)
	if ((s = getenv("LC_ALL")) == NULL || *s == NUL)
	    if ((s = getenv("LC_CTYPE")) == NULL || *s == NUL)
		s = getenv("LANG");

    if (s == NULL || *s == NUL)
	return NULL;

    
    
    
    
    
    
    
    if ((p = (char *)vim_strchr((char_u *)s, '.')) != NULL)
    {
	if (p > s + 2 && STRNICMP(p + 1, "EUC", 3) == 0 && !isalnum((int)p[4]) && p[4] != '-' && p[-3] == '_')
	{
	    
	    STRCPY(buf + 10, "euc-");
	    buf[14] = p[-2];
	    buf[15] = p[-1];
	    buf[16] = 0;
	    s = buf + 10;
	}
	else s = p + 1;
    }
    for (i = 0; i < (int)sizeof(buf) - 1 && s[i] != NUL; ++i)
    {
	if (s[i] == '_' || s[i] == '-')
	    buf[i] = '-';
	else if (isalnum((int)s[i]))
	    buf[i] = TOLOWER_ASC(s[i]);
	else break;
    }
    buf[i] = NUL;

    return enc_canonize((char_u *)buf);
}



    char_u * enc_locale(void)
{

    char	buf[50];
    long	acp = GetACP();

    if (acp == 1200)
	STRCPY(buf, "ucs-2le");
    else if (acp == 1252)	    
	STRCPY(buf, "latin1");
    else if (acp == 65001)
	STRCPY(buf, "utf-8");
    else sprintf(buf, "cp%ld", acp);

    return enc_canonize((char_u *)buf);

    char	*s;


    if ((s = nl_langinfo(CODESET)) == NULL || *s == NUL)


	if ((s = setlocale(LC_CTYPE, NULL)) == NULL || *s == NUL)

	    s = NULL;

    return enc_locale_env(s);

}



    int encname2codepage(char_u *name)
{
    int		cp;
    char_u	*p = name;
    int		idx;

    if (STRNCMP(p, "8bit-", 5) == 0)
	p += 5;
    else if (STRNCMP(p_enc, "2byte-", 6) == 0)
	p += 6;

    if (p[0] == 'c' && p[1] == 'p')
	cp = atoi((char *)p + 2);
    else if ((idx = enc_canon_search(p)) >= 0)
	cp = enc_canon_table[idx].codepage;
    else return 0;
    if (IsValidCodePage(cp))
	return cp;
    return 0;
}





    void * my_iconv_open(char_u *to, char_u *from)
{
    iconv_t	fd;

    char_u	tobuf[ICONV_TESTLEN];
    char	*p;
    size_t	tolen;
    static int	iconv_ok = -1;

    if (iconv_ok == FALSE)
	return (void *)-1;	


    
    if (!iconv_enabled(TRUE))
	return (void *)-1;


    fd = iconv_open((char *)enc_skip(to), (char *)enc_skip(from));

    if (fd != (iconv_t)-1 && iconv_ok == -1)
    {
	
	p = (char *)tobuf;
	tolen = ICONV_TESTLEN;
	(void)iconv(fd, NULL, NULL, &p, &tolen);
	if (p == NULL)
	{
	    iconv_ok = FALSE;
	    iconv_close(fd);
	    fd = (iconv_t)-1;
	}
	else iconv_ok = TRUE;
    }

    return (void *)fd;
}


    static char_u * iconv_string( vimconv_T	*vcp, char_u	*str, int		slen, int		*unconvlenp, int		*resultlenp)





{
    const char	*from;
    size_t	fromlen;
    char	*to;
    size_t	tolen;
    size_t	len = 0;
    size_t	done = 0;
    char_u	*result = NULL;
    char_u	*p;
    int		l;

    from = (char *)str;
    fromlen = slen;
    for (;;)
    {
	if (len == 0 || ICONV_ERRNO == ICONV_E2BIG)
	{
	    
	    
	    len = len + fromlen * 2 + 40;
	    p = alloc(len);
	    if (p != NULL && done > 0)
		mch_memmove(p, result, done);
	    vim_free(result);
	    result = p;
	    if (result == NULL)	
		break;
	}

	to = (char *)result + done;
	tolen = len - done - 2;
	
	
	if (iconv(vcp->vc_fd, (void *)&from, &fromlen, &to, &tolen)
								!= (size_t)-1)
	{
	    
	    *to = NUL;
	    break;
	}

	
	
	if (!vcp->vc_fail && unconvlenp != NULL && (ICONV_ERRNO == ICONV_EINVAL || ICONV_ERRNO == EINVAL))
	{
	    
	    *to = NUL;
	    *unconvlenp = (int)fromlen;
	    break;
	}

	
	
	else if (!vcp->vc_fail && (ICONV_ERRNO == ICONV_EILSEQ || ICONV_ERRNO == EILSEQ || ICONV_ERRNO == ICONV_EINVAL || ICONV_ERRNO == EINVAL))

	{
	    
	    
	    
	    *to++ = '?';
	    if ((*mb_ptr2cells)((char_u *)from) > 1)
		*to++ = '?';
	    if (enc_utf8)
		l = utfc_ptr2len_len((char_u *)from, (int)fromlen);
	    else {
		l = (*mb_ptr2len)((char_u *)from);
		if (l > (int)fromlen)
		    l = (int)fromlen;
	    }
	    from += l;
	    fromlen -= l;
	}
	else if (ICONV_ERRNO != ICONV_E2BIG)
	{
	    
	    VIM_CLEAR(result);
	    break;
	}
	
	done = to - (char *)result;
    }

    if (resultlenp != NULL && result != NULL)
	*resultlenp = (int)(to - (char *)result);
    return result;
}







static HINSTANCE hIconvDLL = 0;
static HINSTANCE hMsvcrtDLL = 0;












    int iconv_enabled(int verbose)
{
    if (hIconvDLL != 0 && hMsvcrtDLL != 0)
	return TRUE;

    
    

    if (hIconvDLL == 0)
	hIconvDLL = vimLoadLib(DYNAMIC_ICONV_DLL_ALT2);


    if (hIconvDLL == 0)
	hIconvDLL = vimLoadLib(DYNAMIC_ICONV_DLL_ALT3);

    if (hIconvDLL == 0)
	hIconvDLL = vimLoadLib(DYNAMIC_ICONV_DLL);

    if (hIconvDLL == 0)
	hIconvDLL = vimLoadLib(DYNAMIC_ICONV_DLL_ALT1);


    if (hIconvDLL != 0)
	hMsvcrtDLL = vimLoadLib(DYNAMIC_MSVCRT_DLL);
    if (hIconvDLL == 0 || hMsvcrtDLL == 0)
    {
	
	
	if (verbose && p_verbose > 0)
	{
	    verbose_enter();
	    semsg(_(e_could_not_load_library_str_str), hIconvDLL == 0 ? DYNAMIC_ICONV_DLL : DYNAMIC_MSVCRT_DLL, GetWin32Error());

	    verbose_leave();
	}
	iconv_end();
	return FALSE;
    }

    iconv	= (size_t (*)(iconv_t, const char **, size_t *, char **, size_t *))
				GetProcAddress(hIconvDLL, "libiconv");
    iconv_open	= (iconv_t (*)(const char *, const char *))
				GetProcAddress(hIconvDLL, "libiconv_open");
    iconv_close	= (int (*)(iconv_t))
				GetProcAddress(hIconvDLL, "libiconv_close");
    iconvctl	= (int (*)(iconv_t, int, void *))
				GetProcAddress(hIconvDLL, "libiconvctl");
    iconv_errno	= (int *(*)(void))get_dll_import_func(hIconvDLL, "_errno");
    if (iconv_errno == NULL)
	iconv_errno = (int *(*)(void))GetProcAddress(hMsvcrtDLL, "_errno");
    if (iconv == NULL || iconv_open == NULL || iconv_close == NULL || iconvctl == NULL || iconv_errno == NULL)
    {
	iconv_end();
	if (verbose && p_verbose > 0)
	{
	    verbose_enter();
	    semsg(_(e_could_not_load_library_function_str), "for libiconv");
	    verbose_leave();
	}
	return FALSE;
    }
    return TRUE;
}

    void iconv_end(void)
{
    
    if (input_conv.vc_type == CONV_ICONV)
	convert_setup(&input_conv, NULL, NULL);
    if (output_conv.vc_type == CONV_ICONV)
	convert_setup(&output_conv, NULL, NULL);

    if (hIconvDLL != 0)
	FreeLibrary(hIconvDLL);
    if (hMsvcrtDLL != 0)
	FreeLibrary(hMsvcrtDLL);
    hIconvDLL = 0;
    hMsvcrtDLL = 0;
}





    void f_getimstatus(typval_T *argvars UNUSED, typval_T *rettv)
{

    rettv->vval.v_number = im_get_status();

}


    void f_iconv(typval_T *argvars UNUSED, typval_T *rettv)
{
    char_u	buf1[NUMBUFLEN];
    char_u	buf2[NUMBUFLEN];
    char_u	*from, *to, *str;
    vimconv_T	vimconv;

    rettv->v_type = VAR_STRING;
    rettv->vval.v_string = NULL;

    if (in_vim9script()
	    && (check_for_string_arg(argvars, 0) == FAIL || check_for_string_arg(argvars, 1) == FAIL || check_for_string_arg(argvars, 2) == FAIL))

	return;

    str = tv_get_string(&argvars[0]);
    from = enc_canonize(enc_skip(tv_get_string_buf(&argvars[1], buf1)));
    to = enc_canonize(enc_skip(tv_get_string_buf(&argvars[2], buf2)));
    vimconv.vc_type = CONV_NONE;
    convert_setup(&vimconv, from, to);

    
    if (vimconv.vc_type == CONV_NONE)
	rettv->vval.v_string = vim_strsave(str);
    else rettv->vval.v_string = string_convert(&vimconv, str, NULL);

    convert_setup(&vimconv, NULL, NULL);
    vim_free(from);
    vim_free(to);
}



    int convert_setup(vimconv_T *vcp, char_u *from, char_u *to)
{
    return convert_setup_ext(vcp, from, TRUE, to, TRUE);
}


    int convert_setup_ext( vimconv_T	*vcp, char_u	*from, int		from_unicode_is_utf8, char_u	*to, int		to_unicode_is_utf8)





{
    int		from_prop;
    int		to_prop;
    int		from_is_utf8;
    int		to_is_utf8;

    

    if (vcp->vc_type == CONV_ICONV && vcp->vc_fd != (iconv_t)-1)
	iconv_close(vcp->vc_fd);

    vcp->vc_type = CONV_NONE;
    vcp->vc_factor = 1;
    vcp->vc_fail = FALSE;

    
    if (from == NULL || *from == NUL || to == NULL || *to == NUL || STRCMP(from, to) == 0)
	return OK;

    from_prop = enc_canon_props(from);
    to_prop = enc_canon_props(to);
    if (from_unicode_is_utf8)
	from_is_utf8 = from_prop & ENC_UNICODE;
    else from_is_utf8 = from_prop == ENC_UNICODE;
    if (to_unicode_is_utf8)
	to_is_utf8 = to_prop & ENC_UNICODE;
    else to_is_utf8 = to_prop == ENC_UNICODE;

    if ((from_prop & ENC_LATIN1) && to_is_utf8)
    {
	
	vcp->vc_type = CONV_TO_UTF8;
	vcp->vc_factor = 2;	
    }
    else if ((from_prop & ENC_LATIN9) && to_is_utf8)
    {
	
	vcp->vc_type = CONV_9_TO_UTF8;
	vcp->vc_factor = 3;	
    }
    else if (from_is_utf8 && (to_prop & ENC_LATIN1))
    {
	
	vcp->vc_type = CONV_TO_LATIN1;
    }
    else if (from_is_utf8 && (to_prop & ENC_LATIN9))
    {
	
	vcp->vc_type = CONV_TO_LATIN9;
    }

    
    else if ((from_is_utf8 || encname2codepage(from) > 0)
	    && (to_is_utf8 || encname2codepage(to) > 0))
    {
	vcp->vc_type = CONV_CODEPAGE;
	vcp->vc_factor = 2;	
	vcp->vc_cpfrom = from_is_utf8 ? 0 : encname2codepage(from);
	vcp->vc_cpto = to_is_utf8 ? 0 : encname2codepage(to);
    }


    else if ((from_prop & ENC_MACROMAN) && (to_prop & ENC_LATIN1))
    {
	vcp->vc_type = CONV_MAC_LATIN1;
    }
    else if ((from_prop & ENC_MACROMAN) && to_is_utf8)
    {
	vcp->vc_type = CONV_MAC_UTF8;
	vcp->vc_factor = 2;	
    }
    else if ((from_prop & ENC_LATIN1) && (to_prop & ENC_MACROMAN))
    {
	vcp->vc_type = CONV_LATIN1_MAC;
    }
    else if (from_is_utf8 && (to_prop & ENC_MACROMAN))
    {
	vcp->vc_type = CONV_UTF8_MAC;
    }


    else {
	
	vcp->vc_fd = (iconv_t)my_iconv_open( to_is_utf8 ? (char_u *)"utf-8" : to, from_is_utf8 ? (char_u *)"utf-8" : from);

	if (vcp->vc_fd != (iconv_t)-1)
	{
	    vcp->vc_type = CONV_ICONV;
	    vcp->vc_factor = 4;	
	}
    }

    if (vcp->vc_type == CONV_NONE)
	return FAIL;

    return OK;
}



    int convert_input(char_u *ptr, int len, int maxlen)
{
    return convert_input_safe(ptr, len, maxlen, NULL, NULL);
}



    int convert_input_safe( char_u	*ptr, int		len, int		maxlen, char_u	**restp, int		*restlenp)





{
    char_u	*d;
    int		dlen = len;
    int		unconvertlen = 0;

    d = string_convert_ext(&input_conv, ptr, &dlen, restp == NULL ? NULL : &unconvertlen);
    if (d != NULL)
    {
	if (dlen <= maxlen)
	{
	    if (unconvertlen > 0)
	    {
		
		*restp = alloc(unconvertlen);
		if (*restp != NULL)
		    mch_memmove(*restp, ptr + len - unconvertlen, unconvertlen);
		*restlenp = unconvertlen;
	    }
	    mch_memmove(ptr, d, dlen);
	}
	else   dlen = len;


	vim_free(d);
    }
    return dlen;
}


    char_u * string_convert( vimconv_T	*vcp, char_u	*ptr, int		*lenp)



{
    return string_convert_ext(vcp, ptr, lenp, NULL);
}


    char_u * string_convert_ext( vimconv_T	*vcp, char_u	*ptr, int		*lenp, int		*unconvlenp)




{
    char_u	*retval = NULL;
    char_u	*d;
    int		len;
    int		i;
    int		l;
    int		c;

    if (lenp == NULL)
	len = (int)STRLEN(ptr);
    else len = *lenp;
    if (len == 0)
	return vim_strsave((char_u *)"");

    switch (vcp->vc_type)
    {
	case CONV_TO_UTF8:	
	    retval = alloc(len * 2 + 1);
	    if (retval == NULL)
		break;
	    d = retval;
	    for (i = 0; i < len; ++i)
	    {
		c = ptr[i];
		if (c < 0x80)
		    *d++ = c;
		else {
		    *d++ = 0xc0 + ((unsigned)c >> 6);
		    *d++ = 0x80 + (c & 0x3f);
		}
	    }
	    *d = NUL;
	    if (lenp != NULL)
		*lenp = (int)(d - retval);
	    break;

	case CONV_9_TO_UTF8:	
	    retval = alloc(len * 3 + 1);
	    if (retval == NULL)
		break;
	    d = retval;
	    for (i = 0; i < len; ++i)
	    {
		c = ptr[i];
		switch (c)
		{
		    case 0xa4: c = 0x20ac; break;   
		    case 0xa6: c = 0x0160; break;   
		    case 0xa8: c = 0x0161; break;   
		    case 0xb4: c = 0x017d; break;   
		    case 0xb8: c = 0x017e; break;   
		    case 0xbc: c = 0x0152; break;   
		    case 0xbd: c = 0x0153; break;   
		    case 0xbe: c = 0x0178; break;   
		}
		d += utf_char2bytes(c, d);
	    }
	    *d = NUL;
	    if (lenp != NULL)
		*lenp = (int)(d - retval);
	    break;

	case CONV_TO_LATIN1:	
	case CONV_TO_LATIN9:	
	    retval = alloc(len + 1);
	    if (retval == NULL)
		break;
	    d = retval;
	    for (i = 0; i < len; ++i)
	    {
		l = utf_ptr2len_len(ptr + i, len - i);
		if (l == 0)
		    *d++ = NUL;
		else if (l == 1)
		{
		    int l_w = utf8len_tab_zero[ptr[i]];

		    if (l_w == 0)
		    {
			
			vim_free(retval);
			return NULL;
		    }
		    if (unconvlenp != NULL && l_w > len - i)
		    {
			
			*unconvlenp = len - i;
			break;
		    }
		    *d++ = ptr[i];
		}
		else {
		    c = utf_ptr2char(ptr + i);
		    if (vcp->vc_type == CONV_TO_LATIN9)
			switch (c)
			{
			    case 0x20ac: c = 0xa4; break;   
			    case 0x0160: c = 0xa6; break;   
			    case 0x0161: c = 0xa8; break;   
			    case 0x017d: c = 0xb4; break;   
			    case 0x017e: c = 0xb8; break;   
			    case 0x0152: c = 0xbc; break;   
			    case 0x0153: c = 0xbd; break;   
			    case 0x0178: c = 0xbe; break;   
			    case 0xa4:
			    case 0xa6:
			    case 0xa8:
			    case 0xb4:
			    case 0xb8:
			    case 0xbc:
			    case 0xbd:
			    case 0xbe: c = 0x100; break; 
			}
		    if (!utf_iscomposing(c))	
		    {
			if (c < 0x100)
			    *d++ = c;
			else if (vcp->vc_fail)
			{
			    vim_free(retval);
			    return NULL;
			}
			else {
			    *d++ = 0xbf;
			    if (utf_char2cells(c) > 1)
				*d++ = '?';
			}
		    }
		    i += l - 1;
		}
	    }
	    *d = NUL;
	    if (lenp != NULL)
		*lenp = (int)(d - retval);
	    break;


	case CONV_MAC_LATIN1:
	    retval = mac_string_convert(ptr, len, lenp, vcp->vc_fail, 'm', 'l', unconvlenp);
	    break;

	case CONV_LATIN1_MAC:
	    retval = mac_string_convert(ptr, len, lenp, vcp->vc_fail, 'l', 'm', unconvlenp);
	    break;

	case CONV_MAC_UTF8:
	    retval = mac_string_convert(ptr, len, lenp, vcp->vc_fail, 'm', 'u', unconvlenp);
	    break;

	case CONV_UTF8_MAC:
	    retval = mac_string_convert(ptr, len, lenp, vcp->vc_fail, 'u', 'm', unconvlenp);
	    break;



	case CONV_ICONV:	
	    retval = iconv_string(vcp, ptr, len, unconvlenp, lenp);
	    break;


	case CONV_CODEPAGE:		
	{
	    int		retlen;
	    int		tmp_len;
	    short_u	*tmp;

	    
	    if (vcp->vc_cpfrom == 0)
		tmp_len = utf8_to_utf16(ptr, len, NULL, NULL);
	    else {
		tmp_len = MultiByteToWideChar(vcp->vc_cpfrom, unconvlenp ? MB_ERR_INVALID_CHARS : 0, (char *)ptr, len, 0, 0);

		if (tmp_len == 0 && GetLastError() == ERROR_NO_UNICODE_TRANSLATION)
		{
		    if (lenp != NULL)
			*lenp = 0;
		    if (unconvlenp != NULL)
			*unconvlenp = len;
		    retval = alloc(1);
		    if (retval)
			retval[0] = NUL;
		    return retval;
		}
	    }
	    tmp = ALLOC_MULT(short_u, tmp_len);
	    if (tmp == NULL)
		break;
	    if (vcp->vc_cpfrom == 0)
		utf8_to_utf16(ptr, len, tmp, unconvlenp);
	    else MultiByteToWideChar(vcp->vc_cpfrom, 0, (char *)ptr, len, tmp, tmp_len);


	    
	    if (vcp->vc_cpto == 0)
		retlen = utf16_to_utf8(tmp, tmp_len, NULL);
	    else retlen = WideCharToMultiByte(vcp->vc_cpto, 0, tmp, tmp_len, 0, 0, 0, 0);

	    retval = alloc(retlen + 1);
	    if (retval != NULL)
	    {
		if (vcp->vc_cpto == 0)
		    utf16_to_utf8(tmp, tmp_len, retval);
		else WideCharToMultiByte(vcp->vc_cpto, 0, tmp, tmp_len, (char *)retval, retlen, 0, 0);


		retval[retlen] = NUL;
		if (lenp != NULL)
		    *lenp = retlen;
	    }
	    vim_free(tmp);
	    break;
	}

    }

    return retval;
}




typedef struct {
    long    first;
    long    last;
    char    width;
} cw_interval_T;

static cw_interval_T	*cw_table = NULL;
static size_t		cw_table_size = 0;


    static int cw_value(int c)
{
    int mid, bot, top;

    if (cw_table == NULL)
	return 0;

    
    if (c < cw_table[0].first)
	return 0;

    
    bot = 0;
    top = (int)cw_table_size - 1;
    while (top >= bot)
    {
	mid = (bot + top) / 2;
	if (cw_table[mid].last < c)
	    bot = mid + 1;
	else if (cw_table[mid].first > c)
	    top = mid - 1;
	else return cw_table[mid].width;
    }
    return 0;
}

    static int tv_nr_compare(const void *a1, const void *a2)
{
    listitem_T *li1 = *(listitem_T **)a1;
    listitem_T *li2 = *(listitem_T **)a2;

    return li1->li_tv.vval.v_number - li2->li_tv.vval.v_number;
}

    void f_setcellwidths(typval_T *argvars, typval_T *rettv UNUSED)
{
    list_T	    *l;
    listitem_T	    *li;
    int		    item;
    int		    i;
    listitem_T	    **ptrs;
    cw_interval_T   *table;
    cw_interval_T   *cw_table_save;
    size_t	    cw_table_size_save;
    char	    *error = NULL;

    if (in_vim9script() && check_for_list_arg(argvars, 0) == FAIL)
	return;

    if (argvars[0].v_type != VAR_LIST || argvars[0].vval.v_list == NULL)
    {
	emsg(_(e_list_required));
	return;
    }
    l = argvars[0].vval.v_list;
    if (l->lv_len == 0)
    {
	
	vim_free(cw_table);
	cw_table = NULL;
	cw_table_size = 0;
	return;
    }

    ptrs = ALLOC_MULT(listitem_T *, l->lv_len);
    if (ptrs == NULL)
	return;

    
    
    item = 0;
    for (li = l->lv_first; li != NULL; li = li->li_next)
    {
	listitem_T *lili;
	varnumber_T n1;

	if (li->li_tv.v_type != VAR_LIST || li->li_tv.vval.v_list == NULL)
	{
	    semsg(_(e_list_item_nr_is_not_list), item);
	    vim_free(ptrs);
	    return;
	}

	lili = li->li_tv.vval.v_list->lv_first;
	ptrs[item] = lili;
	for (i = 0; lili != NULL; lili = lili->li_next, ++i)
	{
	    if (lili->li_tv.v_type != VAR_NUMBER)
		break;
	    if (i == 0)
	    {
		n1 = lili->li_tv.vval.v_number;
		if (n1 < 0x100)
		{
		    emsg(_(e_only_values_of_0x100_and_higher_supported));
		    vim_free(ptrs);
		    return;
		}
	    }
	    else if (i == 1 && lili->li_tv.vval.v_number < n1)
	    {
		semsg(_(e_list_item_nr_range_invalid), item);
		vim_free(ptrs);
		return;
	    }
	    else if (i == 2 && (lili->li_tv.vval.v_number < 1 || lili->li_tv.vval.v_number > 2))
	    {
		semsg(_(e_list_item_nr_cell_width_invalid), item);
		vim_free(ptrs);
		return;
	    }
	}
	if (i != 3)
	{
	    semsg(_(e_list_item_nr_does_not_contain_3_numbers), item);
	    vim_free(ptrs);
	    return;
	}
	++item;
    }

    
    qsort((void *)ptrs, (size_t)l->lv_len, sizeof(listitem_T *), tv_nr_compare);

    table = ALLOC_MULT(cw_interval_T, l->lv_len);
    if (table == NULL)
    {
	vim_free(ptrs);
	return;
    }

    
    item = 0;
    for (item = 0; item < l->lv_len; ++item)
    {
	listitem_T	*lili = ptrs[item];
	varnumber_T	n1;

	n1 = lili->li_tv.vval.v_number;
	if (item > 0 && n1 <= table[item - 1].last)
	{
	    semsg(_(e_overlapping_ranges_for_nr), (long)n1);
	    vim_free(ptrs);
	    vim_free(table);
	    return;
	}
	table[item].first = n1;
	lili = lili->li_next;
	table[item].last = lili->li_tv.vval.v_number;
	lili = lili->li_next;
	table[item].width = lili->li_tv.vval.v_number;
    }

    vim_free(ptrs);

    cw_table_save = cw_table;
    cw_table_size_save = cw_table_size;
    cw_table = table;
    cw_table_size = l->lv_len;

    
    
    error = check_chars_options();
    if (error != NULL)
    {
	emsg(_(error));
	cw_table = cw_table_save;
	cw_table_size = cw_table_size_save;
	vim_free(table);
	return;
    }

    vim_free(cw_table_save);
}

    void f_charclass(typval_T *argvars, typval_T *rettv UNUSED)
{
    if (check_for_string_arg(argvars, 0) == FAIL || argvars[0].vval.v_string == NULL)
	return;
    rettv->vval.v_number = mb_get_class(argvars[0].vval.v_string);
}

