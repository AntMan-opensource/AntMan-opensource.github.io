













typedef enum _line_status_ {
    LINE_UNPROCESSED, LINE_ERROR, LINE_EMPTY, LINE_COMMENT, LINE_SECTION, LINE_VALUE } line_status ;









static const char * strlwc(const char * in, char *out, unsigned len)
{
    unsigned i ;

    if (in==NULL || out == NULL || len==0) return NULL ;
    i=0 ;
    while (in[i] != '\0' && i < len-1) {
        out[i] = (char)tolower((int)in[i]);
        i++ ;
    }
    out[i] = '\0';
    return out ;
}




static char * _strdup(const char *s)
{
    char * copy = (char*) malloc(strlen(s));
    strcpy(copy, s);
    return copy ;
}




unsigned strstrip(char * s)
{
    char *last = NULL ;
    char *dest = s;

    if (s==NULL) return 0;

    last = s + strlen(s);
    while (isspace((int)*s) && *s) s++;
    while (last > s) {
        if (!isspace((int)*(last-1)))
            break ;
        last -- ;
    }
    *last = (char)0;

    memmove(dest,s,last - s + 1);
    return last - s;
}




int iniparser_getnsec(const dictionary * d)
{
    int i ;
    int nsec ;

    if (d==NULL) return -1 ;
    nsec=0 ;
    for (i=0 ; i<d->size ; i++) {
        if (d->key[i]==NULL)
            continue ;
        if (strchr(d->key[i], ':')==NULL) {
            nsec ++ ;
        }
    }
    return nsec ;
}




const char * iniparser_getsecname(const dictionary * d, int n)
{
    int i ;
    int foundsec ;

    if (d==NULL || n<0) return NULL ;
    foundsec=0 ;
    for (i=0 ; i<d->size ; i++) {
        if (d->key[i]==NULL)
            continue ;
        if (strchr(d->key[i], ':')==NULL) {
            foundsec++ ;
            if (foundsec>n)
                break ;
        }
    }
    if (foundsec<=n) {
        return NULL ;
    }
    return d->key[i] ;
}




void iniparser_dump(const dictionary * d, FILE * f)
{
    int     i ;

    if (d==NULL || f==NULL) return ;
    for (i=0 ; i<d->size ; i++) {
        if (d->key[i]==NULL)
            continue ;
        if (d->val[i]!=NULL) {
            fprintf(f, "[%s]=[%s]\n", d->key[i], d->val[i]);
        } else {
            fprintf(f, "[%s]=UNDEF\n", d->key[i]);
        }
    }
    return ;
}




void iniparser_dump_ini(const dictionary * d, FILE * f)
{
    int          i ;
    int          nsec ;
    const char * secname ;

    if (d==NULL || f==NULL) return ;

    nsec = iniparser_getnsec(d);
    if (nsec<1) {
        
        for (i=0 ; i<d->size ; i++) {
            if (d->key[i]==NULL)
                continue ;
            fprintf(f, "%s = %s\n", d->key[i], d->val[i]);
        }
        return ;
    }
    for (i=0 ; i<nsec ; i++) {
        secname = iniparser_getsecname(d, i) ;
        iniparser_dumpsection_ini(d, secname, f);
    }
    fprintf(f, "\n");
    return ;
}




void iniparser_dumpsection_ini(const dictionary * d, const char * s, FILE * f)
{
    int     j ;
    char    keym[ASCIILINESZ+1];
    int     seclen ;

    if (d==NULL || f==NULL) return ;
    if (! iniparser_find_entry(d, s)) return ;

    seclen  = (int)strlen(s);
    fprintf(f, "\n[%s]\n", s);
    sprintf(keym, "%s:", s);
    for (j=0 ; j<d->size ; j++) {
        if (d->key[j]==NULL)
            continue ;
        if (!strncmp(d->key[j], keym, seclen+1)) {
            fprintf(f, "%-30s = %s\n", d->key[j]+seclen+1, d->val[j] ? d->val[j] : "");


        }
    }
    fprintf(f, "\n");
    return ;
}




int iniparser_getsecnkeys(const dictionary * d, const char * s)
{
    int     seclen, nkeys ;
    char    keym[ASCIILINESZ+1];
    int j ;

    nkeys = 0;

    if (d==NULL) return nkeys;
    if (! iniparser_find_entry(d, s)) return nkeys;

    seclen  = (int)strlen(s);
    sprintf(keym, "%s:", s);

    for (j=0 ; j<d->size ; j++) {
        if (d->key[j]==NULL)
            continue ;
        if (!strncmp(d->key[j], keym, seclen+1))
            nkeys++;
    }

    return nkeys;

}




const char ** iniparser_getseckeys(const dictionary * d, const char * s, const char ** keys)
{
    int i, j, seclen ;
    char keym[ASCIILINESZ+1];

    if (d==NULL || keys==NULL) return NULL;
    if (! iniparser_find_entry(d, s)) return NULL;

    seclen  = (int)strlen(s);
    sprintf(keym, "%s:", s);

    i = 0;

    for (j=0 ; j<d->size ; j++) {
        if (d->key[j]==NULL)
            continue ;
        if (!strncmp(d->key[j], keym, seclen+1)) {
            keys[i] = d->key[j];
            i++;
        }
    }

    return keys;
}




const char * iniparser_getstring(const dictionary * d, const char * key, const char * def)
{
    const char * lc_key ;
    const char * sval ;
    char tmp_str[ASCIILINESZ+1];

    if (d==NULL || key==NULL)
        return def ;

    lc_key = strlwc(key, tmp_str, sizeof(tmp_str));
    sval = dictionary_get(d, lc_key, def);
    return sval ;
}




int iniparser_getint(const dictionary * d, const char * key, int notfound)
{
    const char * str ;

    str = iniparser_getstring(d, key, INI_INVALID_KEY);
    if (str==INI_INVALID_KEY) return notfound ;
    return (int)strtol(str, NULL, 0);
}




double iniparser_getdouble(const dictionary * d, const char * key, double notfound)
{
    const char * str ;

    str = iniparser_getstring(d, key, INI_INVALID_KEY);
    if (str==INI_INVALID_KEY) return notfound ;
    return atof(str);
}




int iniparser_getboolean(const dictionary * d, const char * key, int notfound)
{
    int          ret ;
    const char * c ;

    c = iniparser_getstring(d, key, INI_INVALID_KEY);
    if (c==INI_INVALID_KEY) return notfound ;
    if (c[0]=='y' || c[0]=='Y' || c[0]=='1' || c[0]=='t' || c[0]=='T') {
        ret = 1 ;
    } else if (c[0]=='n' || c[0]=='N' || c[0]=='0' || c[0]=='f' || c[0]=='F') {
        ret = 0 ;
    } else {
        ret = notfound ;
    }
    return ret;
}




int iniparser_find_entry(const dictionary * ini, const char * entry)
{
    int found=0 ;
    if (iniparser_getstring(ini, entry, INI_INVALID_KEY)!=INI_INVALID_KEY) {
        found = 1 ;
    }
    return found ;
}




int iniparser_set(dictionary * ini, const char * entry, const char * val)
{
    char tmp_str[ASCIILINESZ+1];
    return dictionary_set(ini, strlwc(entry, tmp_str, sizeof(tmp_str)), val) ;
}




void iniparser_unset(dictionary * ini, const char * entry)
{
    char tmp_str[ASCIILINESZ+1];
    dictionary_unset(ini, strlwc(entry, tmp_str, sizeof(tmp_str)));
}




static line_status iniparser_line( const char * input_line, char * section, char * key, char * value)



{
    line_status sta ;
    char * line = NULL;
    size_t      len ;

    line = _strdup(input_line);
    len = strstrip(line);

    sta = LINE_UNPROCESSED ;
    if (len<1) {
        
        sta = LINE_EMPTY ;
    } else if (line[0]=='#' || line[0]==';') {
        
        sta = LINE_COMMENT ;
    } else if (line[0]=='[' && line[len-1]==']') {
        
        sscanf(line, "[%[^]]", section);
        strstrip(section);
        strlwc(section, section, len);
        sta = LINE_SECTION ;
    } else if (sscanf (line, "%[^=] = \"%[^\"]\"", key, value) == 2 ||  sscanf (line, "%[^=] = '%[^\']'",   key, value) == 2 ||  sscanf (line, "%[^=] = %[^;#]",     key, value) == 2) {

        
        strstrip(key);
        strlwc(key, key, len);
        strstrip(value);
        
        if (!strcmp(value, "\"\"") || (!strcmp(value, "''"))) {
            value[0]=0 ;
        }
        sta = LINE_VALUE ;
    } else if (sscanf(line, "%[^=] = %[;#]", key, value)==2 ||  sscanf(line, "%[^=] %[=]", key, value) == 2) {
        
        strstrip(key);
        strlwc(key, key, len);
        value[0]=0 ;
        sta = LINE_VALUE ;
    } else {
        
        sta = LINE_ERROR ;
    }

    free(line);
    return sta ;
}




dictionary * iniparser_load(const char * ininame)
{
    FILE * in ;

    char line    [ASCIILINESZ+1] ;
    char section [ASCIILINESZ+1] ;
    char key     [ASCIILINESZ+1] ;
    char tmp     [(ASCIILINESZ * 2) + 1] ;
    char val     [ASCIILINESZ+1] ;

    int  last=0 ;
    int  len ;
    int  lineno=0 ;
    int  errs=0;

    dictionary * dict ;

    if ((in=fopen(ininame, "r"))==NULL) {
        fprintf(stderr, "iniparser: cannot open %s\n", ininame);
        return NULL ;
    }

    dict = dictionary_new(0) ;
    if (!dict) {
        fclose(in);
        return NULL ;
    }

    memset(line,    0, ASCIILINESZ);
    memset(section, 0, ASCIILINESZ);
    memset(key,     0, ASCIILINESZ);
    memset(val,     0, ASCIILINESZ);
    last=0 ;

    while (fgets(line+last, ASCIILINESZ-last, in)!=NULL) {
        lineno++ ;
        len = (int)strlen(line)-1;
        if (len==0)
            continue;
        
        if (line[len]!='\n' && !feof(in)) {
            fprintf(stderr, "iniparser: input line too long in %s (%d)\n", ininame, lineno);


            dictionary_del(dict);
            fclose(in);
            return NULL ;
        }
        
        while ((len>=0) && ((line[len]=='\n') || (isspace(line[len])))) {
            line[len]=0 ;
            len-- ;
        }
        if (len < 0) { 
            len = 0;
        }
        
        if (line[len]=='\\') {
            
            last=len ;
            continue ;
        } else {
            last=0 ;
        }
        switch (iniparser_line(line, section, key, val)) {
            case LINE_EMPTY:
            case LINE_COMMENT:
            break ;

            case LINE_SECTION:
            errs = dictionary_set(dict, section, NULL);
            break ;

            case LINE_VALUE:
            sprintf(tmp, "%s:%s", section, key);
            errs = dictionary_set(dict, tmp, val) ;
            break ;

            case LINE_ERROR:
            fprintf(stderr, "iniparser: syntax error in %s (%d):\n", ininame, lineno);

            fprintf(stderr, "-> %s\n", line);
            errs++ ;
            break;

            default:
            break ;
        }
        memset(line, 0, ASCIILINESZ);
        last=0;
        if (errs<0) {
            fprintf(stderr, "iniparser: memory allocation failure\n");
            break ;
        }
    }
    if (errs) {
        dictionary_del(dict);
        dict = NULL ;
    }
    fclose(in);
    return dict ;
}




void iniparser_freedict(dictionary * d)
{
    dictionary_del(d);
}
