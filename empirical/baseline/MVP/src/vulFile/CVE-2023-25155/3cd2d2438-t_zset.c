










int zslLexValueGteMin(sds value, zlexrangespec *spec);
int zslLexValueLteMax(sds value, zlexrangespec *spec);


zskiplistNode *zslCreateNode(int level, double score, sds ele) {
    zskiplistNode *zn = zmalloc(sizeof(*zn)+level*sizeof(struct zskiplistLevel));
    zn->score = score;
    zn->ele = ele;
    return zn;
}


zskiplist *zslCreate(void) {
    int j;
    zskiplist *zsl;

    zsl = zmalloc(sizeof(*zsl));
    zsl->level = 1;
    zsl->length = 0;
    zsl->header = zslCreateNode(ZSKIPLIST_MAXLEVEL,0,NULL);
    for (j = 0; j < ZSKIPLIST_MAXLEVEL; j++) {
        zsl->header->level[j].forward = NULL;
        zsl->header->level[j].span = 0;
    }
    zsl->header->backward = NULL;
    zsl->tail = NULL;
    return zsl;
}


void zslFreeNode(zskiplistNode *node) {
    sdsfree(node->ele);
    zfree(node);
}


void zslFree(zskiplist *zsl) {
    zskiplistNode *node = zsl->header->level[0].forward, *next;

    zfree(zsl->header);
    while(node) {
        next = node->level[0].forward;
        zslFreeNode(node);
        node = next;
    }
    zfree(zsl);
}


int zslRandomLevel(void) {
    static const int threshold = ZSKIPLIST_P*RAND_MAX;
    int level = 1;
    while (random() < threshold)
        level += 1;
    return (level<ZSKIPLIST_MAXLEVEL) ? level : ZSKIPLIST_MAXLEVEL;
}


zskiplistNode *zslInsert(zskiplist *zsl, double score, sds ele) {
    zskiplistNode *update[ZSKIPLIST_MAXLEVEL], *x;
    unsigned long rank[ZSKIPLIST_MAXLEVEL];
    int i, level;

    serverAssert(!isnan(score));
    x = zsl->header;
    for (i = zsl->level-1; i >= 0; i--) {
        
        rank[i] = i == (zsl->level-1) ? 0 : rank[i+1];
        while (x->level[i].forward && (x->level[i].forward->score < score || (x->level[i].forward->score == score && sdscmp(x->level[i].forward->ele,ele) < 0)))


        {
            rank[i] += x->level[i].span;
            x = x->level[i].forward;
        }
        update[i] = x;
    }
    
    level = zslRandomLevel();
    if (level > zsl->level) {
        for (i = zsl->level; i < level; i++) {
            rank[i] = 0;
            update[i] = zsl->header;
            update[i]->level[i].span = zsl->length;
        }
        zsl->level = level;
    }
    x = zslCreateNode(level,score,ele);
    for (i = 0; i < level; i++) {
        x->level[i].forward = update[i]->level[i].forward;
        update[i]->level[i].forward = x;

        
        x->level[i].span = update[i]->level[i].span - (rank[0] - rank[i]);
        update[i]->level[i].span = (rank[0] - rank[i]) + 1;
    }

    
    for (i = level; i < zsl->level; i++) {
        update[i]->level[i].span++;
    }

    x->backward = (update[0] == zsl->header) ? NULL : update[0];
    if (x->level[0].forward)
        x->level[0].forward->backward = x;
    else zsl->tail = x;
    zsl->length++;
    return x;
}


void zslDeleteNode(zskiplist *zsl, zskiplistNode *x, zskiplistNode **update) {
    int i;
    for (i = 0; i < zsl->level; i++) {
        if (update[i]->level[i].forward == x) {
            update[i]->level[i].span += x->level[i].span - 1;
            update[i]->level[i].forward = x->level[i].forward;
        } else {
            update[i]->level[i].span -= 1;
        }
    }
    if (x->level[0].forward) {
        x->level[0].forward->backward = x->backward;
    } else {
        zsl->tail = x->backward;
    }
    while(zsl->level > 1 && zsl->header->level[zsl->level-1].forward == NULL)
        zsl->level--;
    zsl->length--;
}


int zslDelete(zskiplist *zsl, double score, sds ele, zskiplistNode **node) {
    zskiplistNode *update[ZSKIPLIST_MAXLEVEL], *x;
    int i;

    x = zsl->header;
    for (i = zsl->level-1; i >= 0; i--) {
        while (x->level[i].forward && (x->level[i].forward->score < score || (x->level[i].forward->score == score && sdscmp(x->level[i].forward->ele,ele) < 0)))


        {
            x = x->level[i].forward;
        }
        update[i] = x;
    }
    
    x = x->level[0].forward;
    if (x && score == x->score && sdscmp(x->ele,ele) == 0) {
        zslDeleteNode(zsl, x, update);
        if (!node)
            zslFreeNode(x);
        else *node = x;
        return 1;
    }
    return 0; 
}


zskiplistNode *zslUpdateScore(zskiplist *zsl, double curscore, sds ele, double newscore) {
    zskiplistNode *update[ZSKIPLIST_MAXLEVEL], *x;
    int i;

    
    x = zsl->header;
    for (i = zsl->level-1; i >= 0; i--) {
        while (x->level[i].forward && (x->level[i].forward->score < curscore || (x->level[i].forward->score == curscore && sdscmp(x->level[i].forward->ele,ele) < 0)))


        {
            x = x->level[i].forward;
        }
        update[i] = x;
    }

    
    x = x->level[0].forward;
    serverAssert(x && curscore == x->score && sdscmp(x->ele,ele) == 0);

    
    if ((x->backward == NULL || x->backward->score < newscore) && (x->level[0].forward == NULL || x->level[0].forward->score > newscore))
    {
        x->score = newscore;
        return x;
    }

    
    zslDeleteNode(zsl, x, update);
    zskiplistNode *newnode = zslInsert(zsl,newscore,x->ele);
    
    x->ele = NULL;
    zslFreeNode(x);
    return newnode;
}

int zslValueGteMin(double value, zrangespec *spec) {
    return spec->minex ? (value > spec->min) : (value >= spec->min);
}

int zslValueLteMax(double value, zrangespec *spec) {
    return spec->maxex ? (value < spec->max) : (value <= spec->max);
}


int zslIsInRange(zskiplist *zsl, zrangespec *range) {
    zskiplistNode *x;

    
    if (range->min > range->max || (range->min == range->max && (range->minex || range->maxex)))
        return 0;
    x = zsl->tail;
    if (x == NULL || !zslValueGteMin(x->score,range))
        return 0;
    x = zsl->header->level[0].forward;
    if (x == NULL || !zslValueLteMax(x->score,range))
        return 0;
    return 1;
}


zskiplistNode *zslFirstInRange(zskiplist *zsl, zrangespec *range) {
    zskiplistNode *x;
    int i;

    
    if (!zslIsInRange(zsl,range)) return NULL;

    x = zsl->header;
    for (i = zsl->level-1; i >= 0; i--) {
        
        while (x->level[i].forward && !zslValueGteMin(x->level[i].forward->score,range))
                x = x->level[i].forward;
    }

    
    x = x->level[0].forward;
    serverAssert(x != NULL);

    
    if (!zslValueLteMax(x->score,range)) return NULL;
    return x;
}


zskiplistNode *zslLastInRange(zskiplist *zsl, zrangespec *range) {
    zskiplistNode *x;
    int i;

    
    if (!zslIsInRange(zsl,range)) return NULL;

    x = zsl->header;
    for (i = zsl->level-1; i >= 0; i--) {
        
        while (x->level[i].forward && zslValueLteMax(x->level[i].forward->score,range))
                x = x->level[i].forward;
    }

    
    serverAssert(x != NULL);

    
    if (!zslValueGteMin(x->score,range)) return NULL;
    return x;
}


unsigned long zslDeleteRangeByScore(zskiplist *zsl, zrangespec *range, dict *dict) {
    zskiplistNode *update[ZSKIPLIST_MAXLEVEL], *x;
    unsigned long removed = 0;
    int i;

    x = zsl->header;
    for (i = zsl->level-1; i >= 0; i--) {
        while (x->level[i].forward && !zslValueGteMin(x->level[i].forward->score, range))
                x = x->level[i].forward;
        update[i] = x;
    }

    
    x = x->level[0].forward;

    
    while (x && zslValueLteMax(x->score, range)) {
        zskiplistNode *next = x->level[0].forward;
        zslDeleteNode(zsl,x,update);
        dictDelete(dict,x->ele);
        zslFreeNode(x); 
        removed++;
        x = next;
    }
    return removed;
}

unsigned long zslDeleteRangeByLex(zskiplist *zsl, zlexrangespec *range, dict *dict) {
    zskiplistNode *update[ZSKIPLIST_MAXLEVEL], *x;
    unsigned long removed = 0;
    int i;


    x = zsl->header;
    for (i = zsl->level-1; i >= 0; i--) {
        while (x->level[i].forward && !zslLexValueGteMin(x->level[i].forward->ele,range))
                x = x->level[i].forward;
        update[i] = x;
    }

    
    x = x->level[0].forward;

    
    while (x && zslLexValueLteMax(x->ele,range)) {
        zskiplistNode *next = x->level[0].forward;
        zslDeleteNode(zsl,x,update);
        dictDelete(dict,x->ele);
        zslFreeNode(x); 
        removed++;
        x = next;
    }
    return removed;
}


unsigned long zslDeleteRangeByRank(zskiplist *zsl, unsigned int start, unsigned int end, dict *dict) {
    zskiplistNode *update[ZSKIPLIST_MAXLEVEL], *x;
    unsigned long traversed = 0, removed = 0;
    int i;

    x = zsl->header;
    for (i = zsl->level-1; i >= 0; i--) {
        while (x->level[i].forward && (traversed + x->level[i].span) < start) {
            traversed += x->level[i].span;
            x = x->level[i].forward;
        }
        update[i] = x;
    }

    traversed++;
    x = x->level[0].forward;
    while (x && traversed <= end) {
        zskiplistNode *next = x->level[0].forward;
        zslDeleteNode(zsl,x,update);
        dictDelete(dict,x->ele);
        zslFreeNode(x);
        removed++;
        traversed++;
        x = next;
    }
    return removed;
}


unsigned long zslGetRank(zskiplist *zsl, double score, sds ele) {
    zskiplistNode *x;
    unsigned long rank = 0;
    int i;

    x = zsl->header;
    for (i = zsl->level-1; i >= 0; i--) {
        while (x->level[i].forward && (x->level[i].forward->score < score || (x->level[i].forward->score == score && sdscmp(x->level[i].forward->ele,ele) <= 0))) {


            rank += x->level[i].span;
            x = x->level[i].forward;
        }

        
        if (x->ele && x->score == score && sdscmp(x->ele,ele) == 0) {
            return rank;
        }
    }
    return 0;
}


zskiplistNode* zslGetElementByRank(zskiplist *zsl, unsigned long rank) {
    zskiplistNode *x;
    unsigned long traversed = 0;
    int i;

    x = zsl->header;
    for (i = zsl->level-1; i >= 0; i--) {
        while (x->level[i].forward && (traversed + x->level[i].span) <= rank)
        {
            traversed += x->level[i].span;
            x = x->level[i].forward;
        }
        if (traversed == rank) {
            return x;
        }
    }
    return NULL;
}


static int zslParseRange(robj *min, robj *max, zrangespec *spec) {
    char *eptr;
    spec->minex = spec->maxex = 0;

    
    if (min->encoding == OBJ_ENCODING_INT) {
        spec->min = (long)min->ptr;
    } else {
        if (((char*)min->ptr)[0] == '(') {
            spec->min = strtod((char*)min->ptr+1,&eptr);
            if (eptr[0] != '\0' || isnan(spec->min)) return C_ERR;
            spec->minex = 1;
        } else {
            spec->min = strtod((char*)min->ptr,&eptr);
            if (eptr[0] != '\0' || isnan(spec->min)) return C_ERR;
        }
    }
    if (max->encoding == OBJ_ENCODING_INT) {
        spec->max = (long)max->ptr;
    } else {
        if (((char*)max->ptr)[0] == '(') {
            spec->max = strtod((char*)max->ptr+1,&eptr);
            if (eptr[0] != '\0' || isnan(spec->max)) return C_ERR;
            spec->maxex = 1;
        } else {
            spec->max = strtod((char*)max->ptr,&eptr);
            if (eptr[0] != '\0' || isnan(spec->max)) return C_ERR;
        }
    }

    return C_OK;
}




int zslParseLexRangeItem(robj *item, sds *dest, int *ex) {
    char *c = item->ptr;

    switch(c[0]) {
    case '+':
        if (c[1] != '\0') return C_ERR;
        *ex = 1;
        *dest = shared.maxstring;
        return C_OK;
    case '-':
        if (c[1] != '\0') return C_ERR;
        *ex = 1;
        *dest = shared.minstring;
        return C_OK;
    case '(':
        *ex = 1;
        *dest = sdsnewlen(c+1,sdslen(c)-1);
        return C_OK;
    case '[':
        *ex = 0;
        *dest = sdsnewlen(c+1,sdslen(c)-1);
        return C_OK;
    default:
        return C_ERR;
    }
}


void zslFreeLexRange(zlexrangespec *spec) {
    if (spec->min != shared.minstring && spec->min != shared.maxstring) sdsfree(spec->min);
    if (spec->max != shared.minstring && spec->max != shared.maxstring) sdsfree(spec->max);
}


int zslParseLexRange(robj *min, robj *max, zlexrangespec *spec) {
    
    if (min->encoding == OBJ_ENCODING_INT || max->encoding == OBJ_ENCODING_INT) return C_ERR;

    spec->min = spec->max = NULL;
    if (zslParseLexRangeItem(min, &spec->min, &spec->minex) == C_ERR || zslParseLexRangeItem(max, &spec->max, &spec->maxex) == C_ERR) {
        zslFreeLexRange(spec);
        return C_ERR;
    } else {
        return C_OK;
    }
}


int sdscmplex(sds a, sds b) {
    if (a == b) return 0;
    if (a == shared.minstring || b == shared.maxstring) return -1;
    if (a == shared.maxstring || b == shared.minstring) return 1;
    return sdscmp(a,b);
}

int zslLexValueGteMin(sds value, zlexrangespec *spec) {
    return spec->minex ? (sdscmplex(value,spec->min) > 0) :
        (sdscmplex(value,spec->min) >= 0);
}

int zslLexValueLteMax(sds value, zlexrangespec *spec) {
    return spec->maxex ? (sdscmplex(value,spec->max) < 0) :
        (sdscmplex(value,spec->max) <= 0);
}


int zslIsInLexRange(zskiplist *zsl, zlexrangespec *range) {
    zskiplistNode *x;

    
    int cmp = sdscmplex(range->min,range->max);
    if (cmp > 0 || (cmp == 0 && (range->minex || range->maxex)))
        return 0;
    x = zsl->tail;
    if (x == NULL || !zslLexValueGteMin(x->ele,range))
        return 0;
    x = zsl->header->level[0].forward;
    if (x == NULL || !zslLexValueLteMax(x->ele,range))
        return 0;
    return 1;
}


zskiplistNode *zslFirstInLexRange(zskiplist *zsl, zlexrangespec *range) {
    zskiplistNode *x;
    int i;

    
    if (!zslIsInLexRange(zsl,range)) return NULL;

    x = zsl->header;
    for (i = zsl->level-1; i >= 0; i--) {
        
        while (x->level[i].forward && !zslLexValueGteMin(x->level[i].forward->ele,range))
                x = x->level[i].forward;
    }

    
    x = x->level[0].forward;
    serverAssert(x != NULL);

    
    if (!zslLexValueLteMax(x->ele,range)) return NULL;
    return x;
}


zskiplistNode *zslLastInLexRange(zskiplist *zsl, zlexrangespec *range) {
    zskiplistNode *x;
    int i;

    
    if (!zslIsInLexRange(zsl,range)) return NULL;

    x = zsl->header;
    for (i = zsl->level-1; i >= 0; i--) {
        
        while (x->level[i].forward && zslLexValueLteMax(x->level[i].forward->ele,range))
                x = x->level[i].forward;
    }

    
    serverAssert(x != NULL);

    
    if (!zslLexValueGteMin(x->ele,range)) return NULL;
    return x;
}



double zzlStrtod(unsigned char *vstr, unsigned int vlen) {
    char buf[128];
    if (vlen > sizeof(buf) - 1)
        vlen = sizeof(buf) - 1;
    memcpy(buf,vstr,vlen);
    buf[vlen] = '\0';
    return strtod(buf,NULL);
 }

double zzlGetScore(unsigned char *sptr) {
    unsigned char *vstr;
    unsigned int vlen;
    long long vlong;
    double score;

    serverAssert(sptr != NULL);
    vstr = lpGetValue(sptr,&vlen,&vlong);

    if (vstr) {
        score = zzlStrtod(vstr,vlen);
    } else {
        score = vlong;
    }

    return score;
}


sds lpGetObject(unsigned char *sptr) {
    unsigned char *vstr;
    unsigned int vlen;
    long long vlong;

    serverAssert(sptr != NULL);
    vstr = lpGetValue(sptr,&vlen,&vlong);

    if (vstr) {
        return sdsnewlen((char*)vstr,vlen);
    } else {
        return sdsfromlonglong(vlong);
    }
}


int zzlCompareElements(unsigned char *eptr, unsigned char *cstr, unsigned int clen) {
    unsigned char *vstr;
    unsigned int vlen;
    long long vlong;
    unsigned char vbuf[32];
    int minlen, cmp;

    vstr = lpGetValue(eptr,&vlen,&vlong);
    if (vstr == NULL) {
        
        vlen = ll2string((char*)vbuf,sizeof(vbuf),vlong);
        vstr = vbuf;
    }

    minlen = (vlen < clen) ? vlen : clen;
    cmp = memcmp(vstr,cstr,minlen);
    if (cmp == 0) return vlen-clen;
    return cmp;
}

unsigned int zzlLength(unsigned char *zl) {
    return lpLength(zl)/2;
}


void zzlNext(unsigned char *zl, unsigned char **eptr, unsigned char **sptr) {
    unsigned char *_eptr, *_sptr;
    serverAssert(*eptr != NULL && *sptr != NULL);

    _eptr = lpNext(zl,*sptr);
    if (_eptr != NULL) {
        _sptr = lpNext(zl,_eptr);
        serverAssert(_sptr != NULL);
    } else {
        
        _sptr = NULL;
    }

    *eptr = _eptr;
    *sptr = _sptr;
}


void zzlPrev(unsigned char *zl, unsigned char **eptr, unsigned char **sptr) {
    unsigned char *_eptr, *_sptr;
    serverAssert(*eptr != NULL && *sptr != NULL);

    _sptr = lpPrev(zl,*eptr);
    if (_sptr != NULL) {
        _eptr = lpPrev(zl,_sptr);
        serverAssert(_eptr != NULL);
    } else {
        
        _eptr = NULL;
    }

    *eptr = _eptr;
    *sptr = _sptr;
}


int zzlIsInRange(unsigned char *zl, zrangespec *range) {
    unsigned char *p;
    double score;

    
    if (range->min > range->max || (range->min == range->max && (range->minex || range->maxex)))
        return 0;

    p = lpSeek(zl,-1); 
    if (p == NULL) return 0; 
    score = zzlGetScore(p);
    if (!zslValueGteMin(score,range))
        return 0;

    p = lpSeek(zl,1); 
    serverAssert(p != NULL);
    score = zzlGetScore(p);
    if (!zslValueLteMax(score,range))
        return 0;

    return 1;
}


unsigned char *zzlFirstInRange(unsigned char *zl, zrangespec *range) {
    unsigned char *eptr = lpSeek(zl,0), *sptr;
    double score;

    
    if (!zzlIsInRange(zl,range)) return NULL;

    while (eptr != NULL) {
        sptr = lpNext(zl,eptr);
        serverAssert(sptr != NULL);

        score = zzlGetScore(sptr);
        if (zslValueGteMin(score,range)) {
            
            if (zslValueLteMax(score,range))
                return eptr;
            return NULL;
        }

        
        eptr = lpNext(zl,sptr);
    }

    return NULL;
}


unsigned char *zzlLastInRange(unsigned char *zl, zrangespec *range) {
    unsigned char *eptr = lpSeek(zl,-2), *sptr;
    double score;

    
    if (!zzlIsInRange(zl,range)) return NULL;

    while (eptr != NULL) {
        sptr = lpNext(zl,eptr);
        serverAssert(sptr != NULL);

        score = zzlGetScore(sptr);
        if (zslValueLteMax(score,range)) {
            
            if (zslValueGteMin(score,range))
                return eptr;
            return NULL;
        }

        
        sptr = lpPrev(zl,eptr);
        if (sptr != NULL)
            serverAssert((eptr = lpPrev(zl,sptr)) != NULL);
        else eptr = NULL;
    }

    return NULL;
}

int zzlLexValueGteMin(unsigned char *p, zlexrangespec *spec) {
    sds value = lpGetObject(p);
    int res = zslLexValueGteMin(value,spec);
    sdsfree(value);
    return res;
}

int zzlLexValueLteMax(unsigned char *p, zlexrangespec *spec) {
    sds value = lpGetObject(p);
    int res = zslLexValueLteMax(value,spec);
    sdsfree(value);
    return res;
}


int zzlIsInLexRange(unsigned char *zl, zlexrangespec *range) {
    unsigned char *p;

    
    int cmp = sdscmplex(range->min,range->max);
    if (cmp > 0 || (cmp == 0 && (range->minex || range->maxex)))
        return 0;

    p = lpSeek(zl,-2); 
    if (p == NULL) return 0;
    if (!zzlLexValueGteMin(p,range))
        return 0;

    p = lpSeek(zl,0); 
    serverAssert(p != NULL);
    if (!zzlLexValueLteMax(p,range))
        return 0;

    return 1;
}


unsigned char *zzlFirstInLexRange(unsigned char *zl, zlexrangespec *range) {
    unsigned char *eptr = lpSeek(zl,0), *sptr;

    
    if (!zzlIsInLexRange(zl,range)) return NULL;

    while (eptr != NULL) {
        if (zzlLexValueGteMin(eptr,range)) {
            
            if (zzlLexValueLteMax(eptr,range))
                return eptr;
            return NULL;
        }

        
        sptr = lpNext(zl,eptr); 
        serverAssert(sptr != NULL);
        eptr = lpNext(zl,sptr); 
    }

    return NULL;
}


unsigned char *zzlLastInLexRange(unsigned char *zl, zlexrangespec *range) {
    unsigned char *eptr = lpSeek(zl,-2), *sptr;

    
    if (!zzlIsInLexRange(zl,range)) return NULL;

    while (eptr != NULL) {
        if (zzlLexValueLteMax(eptr,range)) {
            
            if (zzlLexValueGteMin(eptr,range))
                return eptr;
            return NULL;
        }

        
        sptr = lpPrev(zl,eptr);
        if (sptr != NULL)
            serverAssert((eptr = lpPrev(zl,sptr)) != NULL);
        else eptr = NULL;
    }

    return NULL;
}

unsigned char *zzlFind(unsigned char *lp, sds ele, double *score) {
    unsigned char *eptr, *sptr;

    if ((eptr = lpFirst(lp)) == NULL) return NULL;
    eptr = lpFind(lp, eptr, (unsigned char*)ele, sdslen(ele), 1);
    if (eptr) {
        sptr = lpNext(lp,eptr);
        serverAssert(sptr != NULL);

        
        if (score != NULL) *score = zzlGetScore(sptr);
        return eptr;
    }

    return NULL;
}


unsigned char *zzlDelete(unsigned char *zl, unsigned char *eptr) {
    return lpDeleteRangeWithEntry(zl,&eptr,2);
}

unsigned char *zzlInsertAt(unsigned char *zl, unsigned char *eptr, sds ele, double score) {
    unsigned char *sptr;
    char scorebuf[MAX_D2STRING_CHARS];
    int scorelen;
    long long lscore;
    int score_is_long = double2ll(score, &lscore);
    if (!score_is_long)
        scorelen = d2string(scorebuf,sizeof(scorebuf),score);
    if (eptr == NULL) {
        zl = lpAppend(zl,(unsigned char*)ele,sdslen(ele));
        if (score_is_long)
            zl = lpAppendInteger(zl,lscore);
        else zl = lpAppend(zl,(unsigned char*)scorebuf,scorelen);
    } else {
        
        zl = lpInsertString(zl,(unsigned char*)ele,sdslen(ele),eptr,LP_BEFORE,&sptr);

        
        if (score_is_long)
            zl = lpInsertInteger(zl,lscore,sptr,LP_AFTER,NULL);
        else zl = lpInsertString(zl,(unsigned char*)scorebuf,scorelen,sptr,LP_AFTER,NULL);
    }
    return zl;
}


unsigned char *zzlInsert(unsigned char *zl, sds ele, double score) {
    unsigned char *eptr = lpSeek(zl,0), *sptr;
    double s;

    while (eptr != NULL) {
        sptr = lpNext(zl,eptr);
        serverAssert(sptr != NULL);
        s = zzlGetScore(sptr);

        if (s > score) {
            
            zl = zzlInsertAt(zl,eptr,ele,score);
            break;
        } else if (s == score) {
            
            if (zzlCompareElements(eptr,(unsigned char*)ele,sdslen(ele)) > 0) {
                zl = zzlInsertAt(zl,eptr,ele,score);
                break;
            }
        }

        
        eptr = lpNext(zl,sptr);
    }

    
    if (eptr == NULL)
        zl = zzlInsertAt(zl,NULL,ele,score);
    return zl;
}

unsigned char *zzlDeleteRangeByScore(unsigned char *zl, zrangespec *range, unsigned long *deleted) {
    unsigned char *eptr, *sptr;
    double score;
    unsigned long num = 0;

    if (deleted != NULL) *deleted = 0;

    eptr = zzlFirstInRange(zl,range);
    if (eptr == NULL) return zl;

    
    while (eptr && (sptr = lpNext(zl,eptr)) != NULL) {
        score = zzlGetScore(sptr);
        if (zslValueLteMax(score,range)) {
            
            zl = lpDeleteRangeWithEntry(zl,&eptr,2);
            num++;
        } else {
            
            break;
        }
    }

    if (deleted != NULL) *deleted = num;
    return zl;
}

unsigned char *zzlDeleteRangeByLex(unsigned char *zl, zlexrangespec *range, unsigned long *deleted) {
    unsigned char *eptr, *sptr;
    unsigned long num = 0;

    if (deleted != NULL) *deleted = 0;

    eptr = zzlFirstInLexRange(zl,range);
    if (eptr == NULL) return zl;

    
    while (eptr && (sptr = lpNext(zl,eptr)) != NULL) {
        if (zzlLexValueLteMax(eptr,range)) {
            
            zl = lpDeleteRangeWithEntry(zl,&eptr,2);
            num++;
        } else {
            
            break;
        }
    }

    if (deleted != NULL) *deleted = num;
    return zl;
}


unsigned char *zzlDeleteRangeByRank(unsigned char *zl, unsigned int start, unsigned int end, unsigned long *deleted) {
    unsigned int num = (end-start)+1;
    if (deleted) *deleted = num;
    zl = lpDeleteRange(zl,2*(start-1),2*num);
    return zl;
}



unsigned long zsetLength(const robj *zobj) {
    unsigned long length = 0;
    if (zobj->encoding == OBJ_ENCODING_LISTPACK) {
        length = zzlLength(zobj->ptr);
    } else if (zobj->encoding == OBJ_ENCODING_SKIPLIST) {
        length = ((const zset*)zobj->ptr)->zsl->length;
    } else {
        serverPanic("Unknown sorted set encoding");
    }
    return length;
}

void zsetConvert(robj *zobj, int encoding) {
    zset *zs;
    zskiplistNode *node, *next;
    sds ele;
    double score;

    if (zobj->encoding == encoding) return;
    if (zobj->encoding == OBJ_ENCODING_LISTPACK) {
        unsigned char *zl = zobj->ptr;
        unsigned char *eptr, *sptr;
        unsigned char *vstr;
        unsigned int vlen;
        long long vlong;

        if (encoding != OBJ_ENCODING_SKIPLIST)
            serverPanic("Unknown target encoding");

        zs = zmalloc(sizeof(*zs));
        zs->dict = dictCreate(&zsetDictType);
        zs->zsl = zslCreate();

        eptr = lpSeek(zl,0);
        if (eptr != NULL) {
            sptr = lpNext(zl,eptr);
            serverAssertWithInfo(NULL,zobj,sptr != NULL);
        }

        while (eptr != NULL) {
            score = zzlGetScore(sptr);
            vstr = lpGetValue(eptr,&vlen,&vlong);
            if (vstr == NULL)
                ele = sdsfromlonglong(vlong);
            else ele = sdsnewlen((char*)vstr,vlen);

            node = zslInsert(zs->zsl,score,ele);
            serverAssert(dictAdd(zs->dict,ele,&node->score) == DICT_OK);
            zzlNext(zl,&eptr,&sptr);
        }

        zfree(zobj->ptr);
        zobj->ptr = zs;
        zobj->encoding = OBJ_ENCODING_SKIPLIST;
    } else if (zobj->encoding == OBJ_ENCODING_SKIPLIST) {
        unsigned char *zl = lpNew(0);

        if (encoding != OBJ_ENCODING_LISTPACK)
            serverPanic("Unknown target encoding");

        
        zs = zobj->ptr;
        dictRelease(zs->dict);
        node = zs->zsl->header->level[0].forward;
        zfree(zs->zsl->header);
        zfree(zs->zsl);

        while (node) {
            zl = zzlInsertAt(zl,NULL,node->ele,node->score);
            next = node->level[0].forward;
            zslFreeNode(node);
            node = next;
        }

        zfree(zs);
        zobj->ptr = zl;
        zobj->encoding = OBJ_ENCODING_LISTPACK;
    } else {
        serverPanic("Unknown sorted set encoding");
    }
}


void zsetConvertToListpackIfNeeded(robj *zobj, size_t maxelelen, size_t totelelen) {
    if (zobj->encoding == OBJ_ENCODING_LISTPACK) return;
    zset *zset = zobj->ptr;

    if (zset->zsl->length <= server.zset_max_listpack_entries && maxelelen <= server.zset_max_listpack_value && lpSafeToAdd(NULL, totelelen))

    {
        zsetConvert(zobj,OBJ_ENCODING_LISTPACK);
    }
}


int zsetScore(robj *zobj, sds member, double *score) {
    if (!zobj || !member) return C_ERR;

    if (zobj->encoding == OBJ_ENCODING_LISTPACK) {
        if (zzlFind(zobj->ptr, member, score) == NULL) return C_ERR;
    } else if (zobj->encoding == OBJ_ENCODING_SKIPLIST) {
        zset *zs = zobj->ptr;
        dictEntry *de = dictFind(zs->dict, member);
        if (de == NULL) return C_ERR;
        *score = *(double*)dictGetVal(de);
    } else {
        serverPanic("Unknown sorted set encoding");
    }
    return C_OK;
}


int zsetAdd(robj *zobj, double score, sds ele, int in_flags, int *out_flags, double *newscore) {
    
    int incr = (in_flags & ZADD_IN_INCR) != 0;
    int nx = (in_flags & ZADD_IN_NX) != 0;
    int xx = (in_flags & ZADD_IN_XX) != 0;
    int gt = (in_flags & ZADD_IN_GT) != 0;
    int lt = (in_flags & ZADD_IN_LT) != 0;
    *out_flags = 0; 
    double curscore;

    
    if (isnan(score)) {
        *out_flags = ZADD_OUT_NAN;
        return 0;
    }

    
    if (zobj->encoding == OBJ_ENCODING_LISTPACK) {
        unsigned char *eptr;

        if ((eptr = zzlFind(zobj->ptr,ele,&curscore)) != NULL) {
            
            if (nx) {
                *out_flags |= ZADD_OUT_NOP;
                return 1;
            }

            
            if (incr) {
                score += curscore;
                if (isnan(score)) {
                    *out_flags |= ZADD_OUT_NAN;
                    return 0;
                }
            }

            
            if ((lt && score >= curscore) || (gt && score <= curscore)) {
                *out_flags |= ZADD_OUT_NOP;
                return 1;
            }

            if (newscore) *newscore = score;

            
            if (score != curscore) {
                zobj->ptr = zzlDelete(zobj->ptr,eptr);
                zobj->ptr = zzlInsert(zobj->ptr,ele,score);
                *out_flags |= ZADD_OUT_UPDATED;
            }
            return 1;
        } else if (!xx) {
            
            if (zzlLength(zobj->ptr)+1 > server.zset_max_listpack_entries || sdslen(ele) > server.zset_max_listpack_value || !lpSafeToAdd(zobj->ptr, sdslen(ele)))

            {
                zsetConvert(zobj,OBJ_ENCODING_SKIPLIST);
            } else {
                zobj->ptr = zzlInsert(zobj->ptr,ele,score);
                if (newscore) *newscore = score;
                *out_flags |= ZADD_OUT_ADDED;
                return 1;
            }
        } else {
            *out_flags |= ZADD_OUT_NOP;
            return 1;
        }
    }

    
    if (zobj->encoding == OBJ_ENCODING_SKIPLIST) {
        zset *zs = zobj->ptr;
        zskiplistNode *znode;
        dictEntry *de;

        de = dictFind(zs->dict,ele);
        if (de != NULL) {
            
            if (nx) {
                *out_flags |= ZADD_OUT_NOP;
                return 1;
            }

            curscore = *(double*)dictGetVal(de);

            
            if (incr) {
                score += curscore;
                if (isnan(score)) {
                    *out_flags |= ZADD_OUT_NAN;
                    return 0;
                }
            }

            
            if ((lt && score >= curscore) || (gt && score <= curscore)) {
                *out_flags |= ZADD_OUT_NOP;
                return 1;
            }

            if (newscore) *newscore = score;

            
            if (score != curscore) {
                znode = zslUpdateScore(zs->zsl,curscore,ele,score);
                
                dictGetVal(de) = &znode->score; 
                *out_flags |= ZADD_OUT_UPDATED;
            }
            return 1;
        } else if (!xx) {
            ele = sdsdup(ele);
            znode = zslInsert(zs->zsl,score,ele);
            serverAssert(dictAdd(zs->dict,ele,&znode->score) == DICT_OK);
            *out_flags |= ZADD_OUT_ADDED;
            if (newscore) *newscore = score;
            return 1;
        } else {
            *out_flags |= ZADD_OUT_NOP;
            return 1;
        }
    } else {
        serverPanic("Unknown sorted set encoding");
    }
    return 0; 
}


static int zsetRemoveFromSkiplist(zset *zs, sds ele) {
    dictEntry *de;
    double score;

    de = dictUnlink(zs->dict,ele);
    if (de != NULL) {
        
        score = *(double*)dictGetVal(de);

        
        dictFreeUnlinkedEntry(zs->dict,de);

        
        int retval = zslDelete(zs->zsl,score,ele,NULL);
        serverAssert(retval);

        return 1;
    }

    return 0;
}


int zsetDel(robj *zobj, sds ele) {
    if (zobj->encoding == OBJ_ENCODING_LISTPACK) {
        unsigned char *eptr;

        if ((eptr = zzlFind(zobj->ptr,ele,NULL)) != NULL) {
            zobj->ptr = zzlDelete(zobj->ptr,eptr);
            return 1;
        }
    } else if (zobj->encoding == OBJ_ENCODING_SKIPLIST) {
        zset *zs = zobj->ptr;
        if (zsetRemoveFromSkiplist(zs, ele)) {
            if (htNeedsResize(zs->dict)) dictResize(zs->dict);
            return 1;
        }
    } else {
        serverPanic("Unknown sorted set encoding");
    }
    return 0; 
}


long zsetRank(robj *zobj, sds ele, int reverse) {
    unsigned long llen;
    unsigned long rank;

    llen = zsetLength(zobj);

    if (zobj->encoding == OBJ_ENCODING_LISTPACK) {
        unsigned char *zl = zobj->ptr;
        unsigned char *eptr, *sptr;

        eptr = lpSeek(zl,0);
        serverAssert(eptr != NULL);
        sptr = lpNext(zl,eptr);
        serverAssert(sptr != NULL);

        rank = 1;
        while(eptr != NULL) {
            if (lpCompare(eptr,(unsigned char*)ele,sdslen(ele)))
                break;
            rank++;
            zzlNext(zl,&eptr,&sptr);
        }

        if (eptr != NULL) {
            if (reverse)
                return llen-rank;
            else return rank-1;
        } else {
            return -1;
        }
    } else if (zobj->encoding == OBJ_ENCODING_SKIPLIST) {
        zset *zs = zobj->ptr;
        zskiplist *zsl = zs->zsl;
        dictEntry *de;
        double score;

        de = dictFind(zs->dict,ele);
        if (de != NULL) {
            score = *(double*)dictGetVal(de);
            rank = zslGetRank(zsl,score,ele);
            
            serverAssert(rank != 0);
            if (reverse)
                return llen-rank;
            else return rank-1;
        } else {
            return -1;
        }
    } else {
        serverPanic("Unknown sorted set encoding");
    }
}


robj *zsetDup(robj *o) {
    robj *zobj;
    zset *zs;
    zset *new_zs;

    serverAssert(o->type == OBJ_ZSET);

    
    if (o->encoding == OBJ_ENCODING_LISTPACK) {
        unsigned char *zl = o->ptr;
        size_t sz = lpBytes(zl);
        unsigned char *new_zl = zmalloc(sz);
        memcpy(new_zl, zl, sz);
        zobj = createObject(OBJ_ZSET, new_zl);
        zobj->encoding = OBJ_ENCODING_LISTPACK;
    } else if (o->encoding == OBJ_ENCODING_SKIPLIST) {
        zobj = createZsetObject();
        zs = o->ptr;
        new_zs = zobj->ptr;
        dictExpand(new_zs->dict,dictSize(zs->dict));
        zskiplist *zsl = zs->zsl;
        zskiplistNode *ln;
        sds ele;
        long llen = zsetLength(o);

        
        ln = zsl->tail;
        while (llen--) {
            ele = ln->ele;
            sds new_ele = sdsdup(ele);
            zskiplistNode *znode = zslInsert(new_zs->zsl,ln->score,new_ele);
            dictAdd(new_zs->dict,new_ele,&znode->score);
            ln = ln->backward;
        }
    } else {
        serverPanic("Unknown sorted set encoding");
    }
    return zobj;
}


sds zsetSdsFromListpackEntry(listpackEntry *e) {
    return e->sval ? sdsnewlen(e->sval, e->slen) : sdsfromlonglong(e->lval);
}


void zsetReplyFromListpackEntry(client *c, listpackEntry *e) {
    if (e->sval)
        addReplyBulkCBuffer(c, e->sval, e->slen);
    else addReplyBulkLongLong(c, e->lval);
}



void zsetTypeRandomElement(robj *zsetobj, unsigned long zsetsize, listpackEntry *key, double *score) {
    if (zsetobj->encoding == OBJ_ENCODING_SKIPLIST) {
        zset *zs = zsetobj->ptr;
        dictEntry *de = dictGetFairRandomKey(zs->dict);
        sds s = dictGetKey(de);
        key->sval = (unsigned char*)s;
        key->slen = sdslen(s);
        if (score)
            *score = *(double*)dictGetVal(de);
    } else if (zsetobj->encoding == OBJ_ENCODING_LISTPACK) {
        listpackEntry val;
        lpRandomPair(zsetobj->ptr, zsetsize, key, &val);
        if (score) {
            if (val.sval) {
                *score = zzlStrtod(val.sval,val.slen);
            } else {
                *score = (double)val.lval;
            }
        }
    } else {
        serverPanic("Unknown zset encoding");
    }
}




void zaddGenericCommand(client *c, int flags) {
    static char *nanerr = "resulting score is not a number (NaN)";
    robj *key = c->argv[1];
    robj *zobj;
    sds ele;
    double score = 0, *scores = NULL;
    int j, elements, ch = 0;
    int scoreidx = 0;
    
    int added = 0;      
    int updated = 0;    
    int processed = 0;  

    
    scoreidx = 2;
    while(scoreidx < c->argc) {
        char *opt = c->argv[scoreidx]->ptr;
        if (!strcasecmp(opt,"nx")) flags |= ZADD_IN_NX;
        else if (!strcasecmp(opt,"xx")) flags |= ZADD_IN_XX;
        else if (!strcasecmp(opt,"ch")) ch = 1; 
        else if (!strcasecmp(opt,"incr")) flags |= ZADD_IN_INCR;
        else if (!strcasecmp(opt,"gt")) flags |= ZADD_IN_GT;
        else if (!strcasecmp(opt,"lt")) flags |= ZADD_IN_LT;
        else break;
        scoreidx++;
    }

    
    int incr = (flags & ZADD_IN_INCR) != 0;
    int nx = (flags & ZADD_IN_NX) != 0;
    int xx = (flags & ZADD_IN_XX) != 0;
    int gt = (flags & ZADD_IN_GT) != 0;
    int lt = (flags & ZADD_IN_LT) != 0;

    
    elements = c->argc-scoreidx;
    if (elements % 2 || !elements) {
        addReplyErrorObject(c,shared.syntaxerr);
        return;
    }
    elements /= 2; 

    
    if (nx && xx) {
        addReplyError(c, "XX and NX options at the same time are not compatible");
        return;
    }
    
    if ((gt && nx) || (lt && nx) || (gt && lt)) {
        addReplyError(c, "GT, LT, and/or NX options at the same time are not compatible");
        return;
    }
    

    if (incr && elements > 1) {
        addReplyError(c, "INCR option supports a single increment-element pair");
        return;
    }

    
    scores = zmalloc(sizeof(double)*elements);
    for (j = 0; j < elements; j++) {
        if (getDoubleFromObjectOrReply(c,c->argv[scoreidx+j*2],&scores[j],NULL)
            != C_OK) goto cleanup;
    }

    
    zobj = lookupKeyWrite(c->db,key);
    if (checkType(c,zobj,OBJ_ZSET)) goto cleanup;
    if (zobj == NULL) {
        if (xx) goto reply_to_client; 
        if (server.zset_max_listpack_entries == 0 || server.zset_max_listpack_value < sdslen(c->argv[scoreidx+1]->ptr))
        {
            zobj = createZsetObject();
        } else {
            zobj = createZsetListpackObject();
        }
        dbAdd(c->db,key,zobj);
    }

    for (j = 0; j < elements; j++) {
        double newscore;
        score = scores[j];
        int retflags = 0;

        ele = c->argv[scoreidx+1+j*2]->ptr;
        int retval = zsetAdd(zobj, score, ele, flags, &retflags, &newscore);
        if (retval == 0) {
            addReplyError(c,nanerr);
            goto cleanup;
        }
        if (retflags & ZADD_OUT_ADDED) added++;
        if (retflags & ZADD_OUT_UPDATED) updated++;
        if (!(retflags & ZADD_OUT_NOP)) processed++;
        score = newscore;
    }
    server.dirty += (added+updated);

reply_to_client:
    if (incr) { 
        if (processed)
            addReplyDouble(c,score);
        else addReplyNull(c);
    } else { 
        addReplyLongLong(c,ch ? added+updated : added);
    }

cleanup:
    zfree(scores);
    if (added || updated) {
        signalModifiedKey(c,c->db,key);
        notifyKeyspaceEvent(NOTIFY_ZSET, incr ? "zincr" : "zadd", key, c->db->id);
    }
}

void zaddCommand(client *c) {
    zaddGenericCommand(c,ZADD_IN_NONE);
}

void zincrbyCommand(client *c) {
    zaddGenericCommand(c,ZADD_IN_INCR);
}

void zremCommand(client *c) {
    robj *key = c->argv[1];
    robj *zobj;
    int deleted = 0, keyremoved = 0, j;

    if ((zobj = lookupKeyWriteOrReply(c,key,shared.czero)) == NULL || checkType(c,zobj,OBJ_ZSET)) return;

    for (j = 2; j < c->argc; j++) {
        if (zsetDel(zobj,c->argv[j]->ptr)) deleted++;
        if (zsetLength(zobj) == 0) {
            dbDelete(c->db,key);
            keyremoved = 1;
            break;
        }
    }

    if (deleted) {
        notifyKeyspaceEvent(NOTIFY_ZSET,"zrem",key,c->db->id);
        if (keyremoved)
            notifyKeyspaceEvent(NOTIFY_GENERIC,"del",key,c->db->id);
        signalModifiedKey(c,c->db,key);
        server.dirty += deleted;
    }
    addReplyLongLong(c,deleted);
}

typedef enum {
    ZRANGE_AUTO = 0, ZRANGE_RANK, ZRANGE_SCORE, ZRANGE_LEX, } zrange_type;





void zremrangeGenericCommand(client *c, zrange_type rangetype) {
    robj *key = c->argv[1];
    robj *zobj;
    int keyremoved = 0;
    unsigned long deleted = 0;
    zrangespec range;
    zlexrangespec lexrange;
    long start, end, llen;
    char *notify_type = NULL;

    
    if (rangetype == ZRANGE_RANK) {
        notify_type = "zremrangebyrank";
        if ((getLongFromObjectOrReply(c,c->argv[2],&start,NULL) != C_OK) || (getLongFromObjectOrReply(c,c->argv[3],&end,NULL) != C_OK))
            return;
    } else if (rangetype == ZRANGE_SCORE) {
        notify_type = "zremrangebyscore";
        if (zslParseRange(c->argv[2],c->argv[3],&range) != C_OK) {
            addReplyError(c,"min or max is not a float");
            return;
        }
    } else if (rangetype == ZRANGE_LEX) {
        notify_type = "zremrangebylex";
        if (zslParseLexRange(c->argv[2],c->argv[3],&lexrange) != C_OK) {
            addReplyError(c,"min or max not valid string range item");
            return;
        }
    } else {
        serverPanic("unknown rangetype %d", (int)rangetype);
    }

    
    if ((zobj = lookupKeyWriteOrReply(c,key,shared.czero)) == NULL || checkType(c,zobj,OBJ_ZSET)) goto cleanup;

    if (rangetype == ZRANGE_RANK) {
        
        llen = zsetLength(zobj);
        if (start < 0) start = llen+start;
        if (end < 0) end = llen+end;
        if (start < 0) start = 0;

        
        if (start > end || start >= llen) {
            addReply(c,shared.czero);
            goto cleanup;
        }
        if (end >= llen) end = llen-1;
    }

    
    if (zobj->encoding == OBJ_ENCODING_LISTPACK) {
        switch(rangetype) {
        case ZRANGE_AUTO:
        case ZRANGE_RANK:
            zobj->ptr = zzlDeleteRangeByRank(zobj->ptr,start+1,end+1,&deleted);
            break;
        case ZRANGE_SCORE:
            zobj->ptr = zzlDeleteRangeByScore(zobj->ptr,&range,&deleted);
            break;
        case ZRANGE_LEX:
            zobj->ptr = zzlDeleteRangeByLex(zobj->ptr,&lexrange,&deleted);
            break;
        }
        if (zzlLength(zobj->ptr) == 0) {
            dbDelete(c->db,key);
            keyremoved = 1;
        }
    } else if (zobj->encoding == OBJ_ENCODING_SKIPLIST) {
        zset *zs = zobj->ptr;
        switch(rangetype) {
        case ZRANGE_AUTO:
        case ZRANGE_RANK:
            deleted = zslDeleteRangeByRank(zs->zsl,start+1,end+1,zs->dict);
            break;
        case ZRANGE_SCORE:
            deleted = zslDeleteRangeByScore(zs->zsl,&range,zs->dict);
            break;
        case ZRANGE_LEX:
            deleted = zslDeleteRangeByLex(zs->zsl,&lexrange,zs->dict);
            break;
        }
        if (htNeedsResize(zs->dict)) dictResize(zs->dict);
        if (dictSize(zs->dict) == 0) {
            dbDelete(c->db,key);
            keyremoved = 1;
        }
    } else {
        serverPanic("Unknown sorted set encoding");
    }

    
    if (deleted) {
        signalModifiedKey(c,c->db,key);
        notifyKeyspaceEvent(NOTIFY_ZSET,notify_type,key,c->db->id);
        if (keyremoved)
            notifyKeyspaceEvent(NOTIFY_GENERIC,"del",key,c->db->id);
    }
    server.dirty += deleted;
    addReplyLongLong(c,deleted);

cleanup:
    if (rangetype == ZRANGE_LEX) zslFreeLexRange(&lexrange);
}

void zremrangebyrankCommand(client *c) {
    zremrangeGenericCommand(c,ZRANGE_RANK);
}

void zremrangebyscoreCommand(client *c) {
    zremrangeGenericCommand(c,ZRANGE_SCORE);
}

void zremrangebylexCommand(client *c) {
    zremrangeGenericCommand(c,ZRANGE_LEX);
}

typedef struct {
    robj *subject;
    int type; 
    int encoding;
    double weight;

    union {
        
        union _iterset {
            struct {
                intset *is;
                int ii;
            } is;
            struct {
                dict *dict;
                dictIterator *di;
                dictEntry *de;
            } ht;
        } set;

        
        union _iterzset {
            struct {
                unsigned char *zl;
                unsigned char *eptr, *sptr;
            } zl;
            struct {
                zset *zs;
                zskiplistNode *node;
            } sl;
        } zset;
    } iter;
} zsetopsrc;








typedef struct {
    int flags;
    unsigned char _buf[32]; 
    sds ele;
    unsigned char *estr;
    unsigned int elen;
    long long ell;
    double score;
} zsetopval;

typedef union _iterset iterset;
typedef union _iterzset iterzset;

void zuiInitIterator(zsetopsrc *op) {
    if (op->subject == NULL)
        return;

    if (op->type == OBJ_SET) {
        iterset *it = &op->iter.set;
        if (op->encoding == OBJ_ENCODING_INTSET) {
            it->is.is = op->subject->ptr;
            it->is.ii = 0;
        } else if (op->encoding == OBJ_ENCODING_HT) {
            it->ht.dict = op->subject->ptr;
            it->ht.di = dictGetIterator(op->subject->ptr);
            it->ht.de = dictNext(it->ht.di);
        } else {
            serverPanic("Unknown set encoding");
        }
    } else if (op->type == OBJ_ZSET) {
        
        iterzset *it = &op->iter.zset;
        if (op->encoding == OBJ_ENCODING_LISTPACK) {
            it->zl.zl = op->subject->ptr;
            it->zl.eptr = lpSeek(it->zl.zl,-2);
            if (it->zl.eptr != NULL) {
                it->zl.sptr = lpNext(it->zl.zl,it->zl.eptr);
                serverAssert(it->zl.sptr != NULL);
            }
        } else if (op->encoding == OBJ_ENCODING_SKIPLIST) {
            it->sl.zs = op->subject->ptr;
            it->sl.node = it->sl.zs->zsl->tail;
        } else {
            serverPanic("Unknown sorted set encoding");
        }
    } else {
        serverPanic("Unsupported type");
    }
}

void zuiClearIterator(zsetopsrc *op) {
    if (op->subject == NULL)
        return;

    if (op->type == OBJ_SET) {
        iterset *it = &op->iter.set;
        if (op->encoding == OBJ_ENCODING_INTSET) {
            UNUSED(it); 
        } else if (op->encoding == OBJ_ENCODING_HT) {
            dictReleaseIterator(it->ht.di);
        } else {
            serverPanic("Unknown set encoding");
        }
    } else if (op->type == OBJ_ZSET) {
        iterzset *it = &op->iter.zset;
        if (op->encoding == OBJ_ENCODING_LISTPACK) {
            UNUSED(it); 
        } else if (op->encoding == OBJ_ENCODING_SKIPLIST) {
            UNUSED(it); 
        } else {
            serverPanic("Unknown sorted set encoding");
        }
    } else {
        serverPanic("Unsupported type");
    }
}

void zuiDiscardDirtyValue(zsetopval *val) {
    if (val->flags & OPVAL_DIRTY_SDS) {
        sdsfree(val->ele);
        val->ele = NULL;
        val->flags &= ~OPVAL_DIRTY_SDS;
    }
}

unsigned long zuiLength(zsetopsrc *op) {
    if (op->subject == NULL)
        return 0;

    if (op->type == OBJ_SET) {
        if (op->encoding == OBJ_ENCODING_INTSET) {
            return intsetLen(op->subject->ptr);
        } else if (op->encoding == OBJ_ENCODING_HT) {
            dict *ht = op->subject->ptr;
            return dictSize(ht);
        } else {
            serverPanic("Unknown set encoding");
        }
    } else if (op->type == OBJ_ZSET) {
        if (op->encoding == OBJ_ENCODING_LISTPACK) {
            return zzlLength(op->subject->ptr);
        } else if (op->encoding == OBJ_ENCODING_SKIPLIST) {
            zset *zs = op->subject->ptr;
            return zs->zsl->length;
        } else {
            serverPanic("Unknown sorted set encoding");
        }
    } else {
        serverPanic("Unsupported type");
    }
}


int zuiNext(zsetopsrc *op, zsetopval *val) {
    if (op->subject == NULL)
        return 0;

    zuiDiscardDirtyValue(val);

    memset(val,0,sizeof(zsetopval));

    if (op->type == OBJ_SET) {
        iterset *it = &op->iter.set;
        if (op->encoding == OBJ_ENCODING_INTSET) {
            int64_t ell;

            if (!intsetGet(it->is.is,it->is.ii,&ell))
                return 0;
            val->ell = ell;
            val->score = 1.0;

            
            it->is.ii++;
        } else if (op->encoding == OBJ_ENCODING_HT) {
            if (it->ht.de == NULL)
                return 0;
            val->ele = dictGetKey(it->ht.de);
            val->score = 1.0;

            
            it->ht.de = dictNext(it->ht.di);
        } else {
            serverPanic("Unknown set encoding");
        }
    } else if (op->type == OBJ_ZSET) {
        iterzset *it = &op->iter.zset;
        if (op->encoding == OBJ_ENCODING_LISTPACK) {
            
            if (it->zl.eptr == NULL || it->zl.sptr == NULL)
                return 0;
            val->estr = lpGetValue(it->zl.eptr,&val->elen,&val->ell);
            val->score = zzlGetScore(it->zl.sptr);

            
            zzlPrev(it->zl.zl,&it->zl.eptr,&it->zl.sptr);
        } else if (op->encoding == OBJ_ENCODING_SKIPLIST) {
            if (it->sl.node == NULL)
                return 0;
            val->ele = it->sl.node->ele;
            val->score = it->sl.node->score;

            
            it->sl.node = it->sl.node->backward;
        } else {
            serverPanic("Unknown sorted set encoding");
        }
    } else {
        serverPanic("Unsupported type");
    }
    return 1;
}

int zuiLongLongFromValue(zsetopval *val) {
    if (!(val->flags & OPVAL_DIRTY_LL)) {
        val->flags |= OPVAL_DIRTY_LL;

        if (val->ele != NULL) {
            if (string2ll(val->ele,sdslen(val->ele),&val->ell))
                val->flags |= OPVAL_VALID_LL;
        } else if (val->estr != NULL) {
            if (string2ll((char*)val->estr,val->elen,&val->ell))
                val->flags |= OPVAL_VALID_LL;
        } else {
            
            val->flags |= OPVAL_VALID_LL;
        }
    }
    return val->flags & OPVAL_VALID_LL;
}

sds zuiSdsFromValue(zsetopval *val) {
    if (val->ele == NULL) {
        if (val->estr != NULL) {
            val->ele = sdsnewlen((char*)val->estr,val->elen);
        } else {
            val->ele = sdsfromlonglong(val->ell);
        }
        val->flags |= OPVAL_DIRTY_SDS;
    }
    return val->ele;
}


sds zuiNewSdsFromValue(zsetopval *val) {
    if (val->flags & OPVAL_DIRTY_SDS) {
        
        sds ele = val->ele;
        val->flags &= ~OPVAL_DIRTY_SDS;
        val->ele = NULL;
        return ele;
    } else if (val->ele) {
        return sdsdup(val->ele);
    } else if (val->estr) {
        return sdsnewlen((char*)val->estr,val->elen);
    } else {
        return sdsfromlonglong(val->ell);
    }
}

int zuiBufferFromValue(zsetopval *val) {
    if (val->estr == NULL) {
        if (val->ele != NULL) {
            val->elen = sdslen(val->ele);
            val->estr = (unsigned char*)val->ele;
        } else {
            val->elen = ll2string((char*)val->_buf,sizeof(val->_buf),val->ell);
            val->estr = val->_buf;
        }
    }
    return 1;
}


int zuiFind(zsetopsrc *op, zsetopval *val, double *score) {
    if (op->subject == NULL)
        return 0;

    if (op->type == OBJ_SET) {
        if (op->encoding == OBJ_ENCODING_INTSET) {
            if (zuiLongLongFromValue(val) && intsetFind(op->subject->ptr,val->ell))
            {
                *score = 1.0;
                return 1;
            } else {
                return 0;
            }
        } else if (op->encoding == OBJ_ENCODING_HT) {
            dict *ht = op->subject->ptr;
            zuiSdsFromValue(val);
            if (dictFind(ht,val->ele) != NULL) {
                *score = 1.0;
                return 1;
            } else {
                return 0;
            }
        } else {
            serverPanic("Unknown set encoding");
        }
    } else if (op->type == OBJ_ZSET) {
        zuiSdsFromValue(val);

        if (op->encoding == OBJ_ENCODING_LISTPACK) {
            if (zzlFind(op->subject->ptr,val->ele,score) != NULL) {
                
                return 1;
            } else {
                return 0;
            }
        } else if (op->encoding == OBJ_ENCODING_SKIPLIST) {
            zset *zs = op->subject->ptr;
            dictEntry *de;
            if ((de = dictFind(zs->dict,val->ele)) != NULL) {
                *score = *(double*)dictGetVal(de);
                return 1;
            } else {
                return 0;
            }
        } else {
            serverPanic("Unknown sorted set encoding");
        }
    } else {
        serverPanic("Unsupported type");
    }
}

int zuiCompareByCardinality(const void *s1, const void *s2) {
    unsigned long first = zuiLength((zsetopsrc*)s1);
    unsigned long second = zuiLength((zsetopsrc*)s2);
    if (first > second) return 1;
    if (first < second) return -1;
    return 0;
}

static int zuiCompareByRevCardinality(const void *s1, const void *s2) {
    return zuiCompareByCardinality(s1, s2) * -1;
}






inline static void zunionInterAggregate(double *target, double val, int aggregate) {
    if (aggregate == REDIS_AGGR_SUM) {
        *target = *target + val;
        
        if (isnan(*target)) *target = 0.0;
    } else if (aggregate == REDIS_AGGR_MIN) {
        *target = val < *target ? val : *target;
    } else if (aggregate == REDIS_AGGR_MAX) {
        *target = val > *target ? val : *target;
    } else {
        
        serverPanic("Unknown ZUNION/INTER aggregate type");
    }
}

static size_t zsetDictGetMaxElementLength(dict *d, size_t *totallen) {
    dictIterator *di;
    dictEntry *de;
    size_t maxelelen = 0;

    di = dictGetIterator(d);

    while((de = dictNext(di)) != NULL) {
        sds ele = dictGetKey(de);
        if (sdslen(ele) > maxelelen) maxelelen = sdslen(ele);
        if (totallen)
            (*totallen) += sdslen(ele);
    }

    dictReleaseIterator(di);

    return maxelelen;
}

static void zdiffAlgorithm1(zsetopsrc *src, long setnum, zset *dstzset, size_t *maxelelen, size_t *totelelen) {
    
    int j;
    zsetopval zval;
    zskiplistNode *znode;
    sds tmp;

    
    qsort(src+1,setnum-1,sizeof(zsetopsrc),zuiCompareByRevCardinality);

    memset(&zval, 0, sizeof(zval));
    zuiInitIterator(&src[0]);
    while (zuiNext(&src[0],&zval)) {
        double value;
        int exists = 0;

        for (j = 1; j < setnum; j++) {
            
            if (src[j].subject == src[0].subject || zuiFind(&src[j],&zval,&value)) {
                exists = 1;
                break;
            }
        }

        if (!exists) {
            tmp = zuiNewSdsFromValue(&zval);
            znode = zslInsert(dstzset->zsl,zval.score,tmp);
            dictAdd(dstzset->dict,tmp,&znode->score);
            if (sdslen(tmp) > *maxelelen) *maxelelen = sdslen(tmp);
            (*totelelen) += sdslen(tmp);
        }
    }
    zuiClearIterator(&src[0]);
}


static void zdiffAlgorithm2(zsetopsrc *src, long setnum, zset *dstzset, size_t *maxelelen, size_t *totelelen) {
    
    int j;
    int cardinality = 0;
    zsetopval zval;
    zskiplistNode *znode;
    sds tmp;

    for (j = 0; j < setnum; j++) {
        if (zuiLength(&src[j]) == 0) continue;

        memset(&zval, 0, sizeof(zval));
        zuiInitIterator(&src[j]);
        while (zuiNext(&src[j],&zval)) {
            if (j == 0) {
                tmp = zuiNewSdsFromValue(&zval);
                znode = zslInsert(dstzset->zsl,zval.score,tmp);
                dictAdd(dstzset->dict,tmp,&znode->score);
                cardinality++;
            } else {
                tmp = zuiSdsFromValue(&zval);
                if (zsetRemoveFromSkiplist(dstzset, tmp)) {
                    cardinality--;
                }
            }

            
            if (cardinality == 0) break;
        }
        zuiClearIterator(&src[j]);

        if (cardinality == 0) break;
    }

    
    if (htNeedsResize(dstzset->dict)) dictResize(dstzset->dict);

    
    *maxelelen = zsetDictGetMaxElementLength(dstzset->dict, totelelen);
}

static int zsetChooseDiffAlgorithm(zsetopsrc *src, long setnum) {
    int j;

    
    long long algo_one_work = 0;
    long long algo_two_work = 0;

    for (j = 0; j < setnum; j++) {
        
        if (j > 0 && src[0].subject == src[j].subject) {
            return 0;
        }

        algo_one_work += zuiLength(&src[0]);
        algo_two_work += zuiLength(&src[j]);
    }

    
    algo_one_work /= 2;
    return (algo_one_work <= algo_two_work) ? 1 : 2;
}

static void zdiff(zsetopsrc *src, long setnum, zset *dstzset, size_t *maxelelen, size_t *totelelen) {
    
    if (zuiLength(&src[0]) > 0) {
        int diff_algo = zsetChooseDiffAlgorithm(src, setnum);
        if (diff_algo == 1) {
            zdiffAlgorithm1(src, setnum, dstzset, maxelelen, totelelen);
        } else if (diff_algo == 2) {
            zdiffAlgorithm2(src, setnum, dstzset, maxelelen, totelelen);
        } else if (diff_algo != 0) {
            serverPanic("Unknown algorithm");
        }
    }
}

dictType setAccumulatorDictType = {
    dictSdsHash,                NULL, NULL, dictSdsKeyCompare, NULL, NULL, NULL };








void zunionInterDiffGenericCommand(client *c, robj *dstkey, int numkeysIndex, int op, int cardinality_only) {
    int i, j;
    long setnum;
    int aggregate = REDIS_AGGR_SUM;
    zsetopsrc *src;
    zsetopval zval;
    sds tmp;
    size_t maxelelen = 0, totelelen = 0;
    robj *dstobj;
    zset *dstzset;
    zskiplistNode *znode;
    int withscores = 0;
    unsigned long cardinality = 0;
    long limit = 0; 

    
    if ((getLongFromObjectOrReply(c, c->argv[numkeysIndex], &setnum, NULL) != C_OK))
        return;

    if (setnum < 1) {
        addReplyErrorFormat(c, "at least 1 input key is needed for '%s' command", c->cmd->fullname);
        return;
    }

    
    if (setnum > (c->argc-(numkeysIndex+1))) {
        addReplyErrorObject(c,shared.syntaxerr);
        return;
    }

    
    src = zcalloc(sizeof(zsetopsrc) * setnum);
    for (i = 0, j = numkeysIndex+1; i < setnum; i++, j++) {
        robj *obj = lookupKeyRead(c->db, c->argv[j]);
        if (obj != NULL) {
            if (obj->type != OBJ_ZSET && obj->type != OBJ_SET) {
                zfree(src);
                addReplyErrorObject(c,shared.wrongtypeerr);
                return;
            }

            src[i].subject = obj;
            src[i].type = obj->type;
            src[i].encoding = obj->encoding;
        } else {
            src[i].subject = NULL;
        }

        
        src[i].weight = 1.0;
    }

    
    if (j < c->argc) {
        int remaining = c->argc - j;

        while (remaining) {
            if (op != SET_OP_DIFF && !cardinality_only && remaining >= (setnum + 1) && !strcasecmp(c->argv[j]->ptr,"weights"))

            {
                j++; remaining--;
                for (i = 0; i < setnum; i++, j++, remaining--) {
                    if (getDoubleFromObjectOrReply(c,c->argv[j],&src[i].weight, "weight value is not a float") != C_OK)
                    {
                        zfree(src);
                        return;
                    }
                }
            } else if (op != SET_OP_DIFF && !cardinality_only && remaining >= 2 && !strcasecmp(c->argv[j]->ptr,"aggregate"))

            {
                j++; remaining--;
                if (!strcasecmp(c->argv[j]->ptr,"sum")) {
                    aggregate = REDIS_AGGR_SUM;
                } else if (!strcasecmp(c->argv[j]->ptr,"min")) {
                    aggregate = REDIS_AGGR_MIN;
                } else if (!strcasecmp(c->argv[j]->ptr,"max")) {
                    aggregate = REDIS_AGGR_MAX;
                } else {
                    zfree(src);
                    addReplyErrorObject(c,shared.syntaxerr);
                    return;
                }
                j++; remaining--;
            } else if (remaining >= 1 && !dstkey && !cardinality_only && !strcasecmp(c->argv[j]->ptr,"withscores"))

            {
                j++; remaining--;
                withscores = 1;
            } else if (cardinality_only && remaining >= 2 && !strcasecmp(c->argv[j]->ptr, "limit"))
            {
                j++; remaining--;
                if (getPositiveLongFromObjectOrReply(c, c->argv[j], &limit, "LIMIT can't be negative") != C_OK)
                {
                    zfree(src);
                    return;
                }
                j++; remaining--;
            } else {
                zfree(src);
                addReplyErrorObject(c,shared.syntaxerr);
                return;
            }
        }
    }

    if (op != SET_OP_DIFF) {
        
        qsort(src,setnum,sizeof(zsetopsrc),zuiCompareByCardinality);
    }

    dstobj = createZsetObject();
    dstzset = dstobj->ptr;
    memset(&zval, 0, sizeof(zval));

    if (op == SET_OP_INTER) {
        
        if (zuiLength(&src[0]) > 0) {
            
            zuiInitIterator(&src[0]);
            while (zuiNext(&src[0],&zval)) {
                double score, value;

                score = src[0].weight * zval.score;
                if (isnan(score)) score = 0;

                for (j = 1; j < setnum; j++) {
                    
                    if (src[j].subject == src[0].subject) {
                        value = zval.score*src[j].weight;
                        zunionInterAggregate(&score,value,aggregate);
                    } else if (zuiFind(&src[j],&zval,&value)) {
                        value *= src[j].weight;
                        zunionInterAggregate(&score,value,aggregate);
                    } else {
                        break;
                    }
                }

                
                if (j == setnum && cardinality_only) {
                    cardinality++;

                    
                    if (limit && cardinality >= (unsigned long)limit) {
                        
                        zuiDiscardDirtyValue(&zval);
                        break;
                    }
                } else if (j == setnum) {
                    tmp = zuiNewSdsFromValue(&zval);
                    znode = zslInsert(dstzset->zsl,score,tmp);
                    dictAdd(dstzset->dict,tmp,&znode->score);
                    totelelen += sdslen(tmp);
                    if (sdslen(tmp) > maxelelen) maxelelen = sdslen(tmp);
                }
            }
            zuiClearIterator(&src[0]);
        }
    } else if (op == SET_OP_UNION) {
        dict *accumulator = dictCreate(&setAccumulatorDictType);
        dictIterator *di;
        dictEntry *de, *existing;
        double score;

        if (setnum) {
            
            dictExpand(accumulator,zuiLength(&src[setnum-1]));
        }

        
        for (i = 0; i < setnum; i++) {
            if (zuiLength(&src[i]) == 0) continue;

            zuiInitIterator(&src[i]);
            while (zuiNext(&src[i],&zval)) {
                
                score = src[i].weight * zval.score;
                if (isnan(score)) score = 0;

                
                de = dictAddRaw(accumulator,zuiSdsFromValue(&zval),&existing);
                
                if (!existing) {
                    tmp = zuiNewSdsFromValue(&zval);
                    
                     totelelen += sdslen(tmp);
                     if (sdslen(tmp) > maxelelen) maxelelen = sdslen(tmp);
                    
                    dictSetKey(accumulator, de, tmp);
                    dictSetDoubleVal(de,score);
                } else {
                    
                    zunionInterAggregate(&existing->v.d,score,aggregate);
                }
            }
            zuiClearIterator(&src[i]);
        }

        
        di = dictGetIterator(accumulator);

        
        dictExpand(dstzset->dict,dictSize(accumulator));

        while((de = dictNext(di)) != NULL) {
            sds ele = dictGetKey(de);
            score = dictGetDoubleVal(de);
            znode = zslInsert(dstzset->zsl,score,ele);
            dictAdd(dstzset->dict,ele,&znode->score);
        }
        dictReleaseIterator(di);
        dictRelease(accumulator);
    } else if (op == SET_OP_DIFF) {
        zdiff(src, setnum, dstzset, &maxelelen, &totelelen);
    } else {
        serverPanic("Unknown operator");
    }

    if (dstkey) {
        if (dstzset->zsl->length) {
            zsetConvertToListpackIfNeeded(dstobj, maxelelen, totelelen);
            setKey(c, c->db, dstkey, dstobj, 0);
            addReplyLongLong(c, zsetLength(dstobj));
            notifyKeyspaceEvent(NOTIFY_ZSET, (op == SET_OP_UNION) ? "zunionstore" :
                                    (op == SET_OP_INTER ? "zinterstore" : "zdiffstore"), dstkey, c->db->id);
            server.dirty++;
        } else {
            addReply(c, shared.czero);
            if (dbDelete(c->db, dstkey)) {
                signalModifiedKey(c, c->db, dstkey);
                notifyKeyspaceEvent(NOTIFY_GENERIC, "del", dstkey, c->db->id);
                server.dirty++;
            }
        }
    } else if (cardinality_only) {
        addReplyLongLong(c, cardinality);
    } else {
        unsigned long length = dstzset->zsl->length;
        zskiplist *zsl = dstzset->zsl;
        zskiplistNode *zn = zsl->header->level[0].forward;
        
        if (withscores && c->resp == 2)
            addReplyArrayLen(c, length*2);
        else addReplyArrayLen(c, length);

        while (zn != NULL) {
            if (withscores && c->resp > 2) addReplyArrayLen(c,2);
            addReplyBulkCBuffer(c,zn->ele,sdslen(zn->ele));
            if (withscores) addReplyDouble(c,zn->score);
            zn = zn->level[0].forward;
        }
    }
    decrRefCount(dstobj);
    zfree(src);
}


void zunionstoreCommand(client *c) {
    zunionInterDiffGenericCommand(c, c->argv[1], 2, SET_OP_UNION, 0);
}


void zinterstoreCommand(client *c) {
    zunionInterDiffGenericCommand(c, c->argv[1], 2, SET_OP_INTER, 0);
}


void zdiffstoreCommand(client *c) {
    zunionInterDiffGenericCommand(c, c->argv[1], 2, SET_OP_DIFF, 0);
}


void zunionCommand(client *c) {
    zunionInterDiffGenericCommand(c, NULL, 1, SET_OP_UNION, 0);
}


void zinterCommand(client *c) {
    zunionInterDiffGenericCommand(c, NULL, 1, SET_OP_INTER, 0);
}


void zinterCardCommand(client *c) {
    zunionInterDiffGenericCommand(c, NULL, 1, SET_OP_INTER, 1);
}


void zdiffCommand(client *c) {
    zunionInterDiffGenericCommand(c, NULL, 1, SET_OP_DIFF, 0);
}

typedef enum {
    ZRANGE_DIRECTION_AUTO = 0, ZRANGE_DIRECTION_FORWARD, ZRANGE_DIRECTION_REVERSE } zrange_direction;



typedef enum {
    ZRANGE_CONSUMER_TYPE_CLIENT = 0, ZRANGE_CONSUMER_TYPE_INTERNAL } zrange_consumer_type;


typedef struct zrange_result_handler zrange_result_handler;

typedef void (*zrangeResultBeginFunction)(zrange_result_handler *c, long length);
typedef void (*zrangeResultFinalizeFunction)( zrange_result_handler *c, size_t result_count);
typedef void (*zrangeResultEmitCBufferFunction)( zrange_result_handler *c, const void *p, size_t len, double score);
typedef void (*zrangeResultEmitLongLongFunction)( zrange_result_handler *c, long long ll, double score);

void zrangeGenericCommand (zrange_result_handler *handler, int argc_start, int store, zrange_type rangetype, zrange_direction direction);


struct zrange_result_handler {
    zrange_consumer_type                 type;
    client                              *client;
    robj                                *dstkey;
    robj                                *dstobj;
    void                                *userdata;
    int                                  withscores;
    int                                  should_emit_array_length;
    zrangeResultBeginFunction            beginResultEmission;
    zrangeResultFinalizeFunction         finalizeResultEmission;
    zrangeResultEmitCBufferFunction      emitResultFromCBuffer;
    zrangeResultEmitLongLongFunction     emitResultFromLongLong;
};


static void zrangeResultBeginClient(zrange_result_handler *handler, long length) {
    if (length > 0) {
        
        if (handler->withscores && (handler->client->resp == 2)) {
            length *= 2;
        }
        addReplyArrayLen(handler->client, length);
        handler->userdata = NULL;
        return;
    }
    handler->userdata = addReplyDeferredLen(handler->client);
}

static void zrangeResultEmitCBufferToClient(zrange_result_handler *handler, const void *value, size_t value_length_in_bytes, double score)
{
    if (handler->should_emit_array_length) {
        addReplyArrayLen(handler->client, 2);
    }

    addReplyBulkCBuffer(handler->client, value, value_length_in_bytes);

    if (handler->withscores) {
        addReplyDouble(handler->client, score);
    }
}

static void zrangeResultEmitLongLongToClient(zrange_result_handler *handler, long long value, double score)
{
    if (handler->should_emit_array_length) {
        addReplyArrayLen(handler->client, 2);
    }

    addReplyBulkLongLong(handler->client, value);

    if (handler->withscores) {
        addReplyDouble(handler->client, score);
    }
}

static void zrangeResultFinalizeClient(zrange_result_handler *handler, size_t result_count)
{
    
    if (!handler->userdata)
        return;
    
    if (handler->withscores && (handler->client->resp == 2)) {
        result_count *= 2;
    }

    setDeferredArrayLen(handler->client, handler->userdata, result_count);
}


static void zrangeResultBeginStore(zrange_result_handler *handler, long length)
{
    if (length > (long)server.zset_max_listpack_entries)
        handler->dstobj = createZsetObject();
    else handler->dstobj = createZsetListpackObject();
}

static void zrangeResultEmitCBufferForStore(zrange_result_handler *handler, const void *value, size_t value_length_in_bytes, double score)
{
    double newscore;
    int retflags = 0;
    sds ele = sdsnewlen(value, value_length_in_bytes);
    int retval = zsetAdd(handler->dstobj, score, ele, ZADD_IN_NONE, &retflags, &newscore);
    sdsfree(ele);
    serverAssert(retval);
}

static void zrangeResultEmitLongLongForStore(zrange_result_handler *handler, long long value, double score)
{
    double newscore;
    int retflags = 0;
    sds ele = sdsfromlonglong(value);
    int retval = zsetAdd(handler->dstobj, score, ele, ZADD_IN_NONE, &retflags, &newscore);
    sdsfree(ele);
    serverAssert(retval);
}

static void zrangeResultFinalizeStore(zrange_result_handler *handler, size_t result_count)
{
    if (result_count) {
        setKey(handler->client, handler->client->db, handler->dstkey, handler->dstobj, 0);
        addReplyLongLong(handler->client, result_count);
        notifyKeyspaceEvent(NOTIFY_ZSET, "zrangestore", handler->dstkey, handler->client->db->id);
        server.dirty++;
    } else {
        addReply(handler->client, shared.czero);
        if (dbDelete(handler->client->db, handler->dstkey)) {
            signalModifiedKey(handler->client, handler->client->db, handler->dstkey);
            notifyKeyspaceEvent(NOTIFY_GENERIC, "del", handler->dstkey, handler->client->db->id);
            server.dirty++;
        }
    }
    decrRefCount(handler->dstobj);
}


static void zrangeResultHandlerInit(zrange_result_handler *handler, client *client, zrange_consumer_type type)
{
    memset(handler, 0, sizeof(*handler));

    handler->client = client;

    switch (type) {
    case ZRANGE_CONSUMER_TYPE_CLIENT:
        handler->beginResultEmission = zrangeResultBeginClient;
        handler->finalizeResultEmission = zrangeResultFinalizeClient;
        handler->emitResultFromCBuffer = zrangeResultEmitCBufferToClient;
        handler->emitResultFromLongLong = zrangeResultEmitLongLongToClient;
        break;

    case ZRANGE_CONSUMER_TYPE_INTERNAL:
        handler->beginResultEmission = zrangeResultBeginStore;
        handler->finalizeResultEmission = zrangeResultFinalizeStore;
        handler->emitResultFromCBuffer = zrangeResultEmitCBufferForStore;
        handler->emitResultFromLongLong = zrangeResultEmitLongLongForStore;
        break;
    }
}

static void zrangeResultHandlerScoreEmissionEnable(zrange_result_handler *handler) {
    handler->withscores = 1;
    handler->should_emit_array_length = (handler->client->resp > 2);
}

static void zrangeResultHandlerDestinationKeySet (zrange_result_handler *handler, robj *dstkey)
{
    handler->dstkey = dstkey;
}


void genericZrangebyrankCommand(zrange_result_handler *handler, robj *zobj, long start, long end, int withscores, int reverse) {

    client *c = handler->client;
    long llen;
    long rangelen;
    size_t result_cardinality;

    
    llen = zsetLength(zobj);
    if (start < 0) start = llen+start;
    if (end < 0) end = llen+end;
    if (start < 0) start = 0;


    
    if (start > end || start >= llen) {
        handler->beginResultEmission(handler, 0);
        handler->finalizeResultEmission(handler, 0);
        return;
    }
    if (end >= llen) end = llen-1;
    rangelen = (end-start)+1;
    result_cardinality = rangelen;

    handler->beginResultEmission(handler, rangelen);
    if (zobj->encoding == OBJ_ENCODING_LISTPACK) {
        unsigned char *zl = zobj->ptr;
        unsigned char *eptr, *sptr;
        unsigned char *vstr;
        unsigned int vlen;
        long long vlong;
        double score = 0.0;

        if (reverse)
            eptr = lpSeek(zl,-2-(2*start));
        else eptr = lpSeek(zl,2*start);

        serverAssertWithInfo(c,zobj,eptr != NULL);
        sptr = lpNext(zl,eptr);

        while (rangelen--) {
            serverAssertWithInfo(c,zobj,eptr != NULL && sptr != NULL);
            vstr = lpGetValue(eptr,&vlen,&vlong);

            if (withscores) 
                score = zzlGetScore(sptr);

            if (vstr == NULL) {
                handler->emitResultFromLongLong(handler, vlong, score);
            } else {
                handler->emitResultFromCBuffer(handler, vstr, vlen, score);
            }

            if (reverse)
                zzlPrev(zl,&eptr,&sptr);
            else zzlNext(zl,&eptr,&sptr);
        }

    } else if (zobj->encoding == OBJ_ENCODING_SKIPLIST) {
        zset *zs = zobj->ptr;
        zskiplist *zsl = zs->zsl;
        zskiplistNode *ln;

        
        if (reverse) {
            ln = zsl->tail;
            if (start > 0)
                ln = zslGetElementByRank(zsl,llen-start);
        } else {
            ln = zsl->header->level[0].forward;
            if (start > 0)
                ln = zslGetElementByRank(zsl,start+1);
        }

        while(rangelen--) {
            serverAssertWithInfo(c,zobj,ln != NULL);
            sds ele = ln->ele;
            handler->emitResultFromCBuffer(handler, ele, sdslen(ele), ln->score);
            ln = reverse ? ln->backward : ln->level[0].forward;
        }
    } else {
        serverPanic("Unknown sorted set encoding");
    }

    handler->finalizeResultEmission(handler, result_cardinality);
}


void zrangestoreCommand (client *c) {
    robj *dstkey = c->argv[1];
    zrange_result_handler handler;
    zrangeResultHandlerInit(&handler, c, ZRANGE_CONSUMER_TYPE_INTERNAL);
    zrangeResultHandlerDestinationKeySet(&handler, dstkey);
    zrangeGenericCommand(&handler, 2, 1, ZRANGE_AUTO, ZRANGE_DIRECTION_AUTO);
}


void zrangeCommand(client *c) {
    zrange_result_handler handler;
    zrangeResultHandlerInit(&handler, c, ZRANGE_CONSUMER_TYPE_CLIENT);
    zrangeGenericCommand(&handler, 1, 0, ZRANGE_AUTO, ZRANGE_DIRECTION_AUTO);
}


void zrevrangeCommand(client *c) {
    zrange_result_handler handler;
    zrangeResultHandlerInit(&handler, c, ZRANGE_CONSUMER_TYPE_CLIENT);
    zrangeGenericCommand(&handler, 1, 0, ZRANGE_RANK, ZRANGE_DIRECTION_REVERSE);
}


void genericZrangebyscoreCommand(zrange_result_handler *handler, zrangespec *range, robj *zobj, long offset, long limit, int reverse) {

    unsigned long rangelen = 0;

    handler->beginResultEmission(handler, -1);

    
    if (offset > 0 && offset >= (long)zsetLength(zobj)) {
        handler->finalizeResultEmission(handler, 0);
        return;
    }

    if (zobj->encoding == OBJ_ENCODING_LISTPACK) {
        unsigned char *zl = zobj->ptr;
        unsigned char *eptr, *sptr;
        unsigned char *vstr;
        unsigned int vlen;
        long long vlong;

        
        if (reverse) {
            eptr = zzlLastInRange(zl,range);
        } else {
            eptr = zzlFirstInRange(zl,range);
        }

        
        if (eptr)
            sptr = lpNext(zl,eptr);

        
        while (eptr && offset--) {
            if (reverse) {
                zzlPrev(zl,&eptr,&sptr);
            } else {
                zzlNext(zl,&eptr,&sptr);
            }
        }

        while (eptr && limit--) {
            double score = zzlGetScore(sptr);

            
            if (reverse) {
                if (!zslValueGteMin(score,range)) break;
            } else {
                if (!zslValueLteMax(score,range)) break;
            }

            vstr = lpGetValue(eptr,&vlen,&vlong);
            rangelen++;
            if (vstr == NULL) {
                handler->emitResultFromLongLong(handler, vlong, score);
            } else {
                handler->emitResultFromCBuffer(handler, vstr, vlen, score);
            }

            
            if (reverse) {
                zzlPrev(zl,&eptr,&sptr);
            } else {
                zzlNext(zl,&eptr,&sptr);
            }
        }
    } else if (zobj->encoding == OBJ_ENCODING_SKIPLIST) {
        zset *zs = zobj->ptr;
        zskiplist *zsl = zs->zsl;
        zskiplistNode *ln;

        
        if (reverse) {
            ln = zslLastInRange(zsl,range);
        } else {
            ln = zslFirstInRange(zsl,range);
        }

        
        while (ln && offset--) {
            if (reverse) {
                ln = ln->backward;
            } else {
                ln = ln->level[0].forward;
            }
        }

        while (ln && limit--) {
            
            if (reverse) {
                if (!zslValueGteMin(ln->score,range)) break;
            } else {
                if (!zslValueLteMax(ln->score,range)) break;
            }

            rangelen++;
            handler->emitResultFromCBuffer(handler, ln->ele, sdslen(ln->ele), ln->score);

            
            if (reverse) {
                ln = ln->backward;
            } else {
                ln = ln->level[0].forward;
            }
        }
    } else {
        serverPanic("Unknown sorted set encoding");
    }

    handler->finalizeResultEmission(handler, rangelen);
}


void zrangebyscoreCommand(client *c) {
    zrange_result_handler handler;
    zrangeResultHandlerInit(&handler, c, ZRANGE_CONSUMER_TYPE_CLIENT);
    zrangeGenericCommand(&handler, 1, 0, ZRANGE_SCORE, ZRANGE_DIRECTION_FORWARD);
}


void zrevrangebyscoreCommand(client *c) {
    zrange_result_handler handler;
    zrangeResultHandlerInit(&handler, c, ZRANGE_CONSUMER_TYPE_CLIENT);
    zrangeGenericCommand(&handler, 1, 0, ZRANGE_SCORE, ZRANGE_DIRECTION_REVERSE);
}

void zcountCommand(client *c) {
    robj *key = c->argv[1];
    robj *zobj;
    zrangespec range;
    unsigned long count = 0;

    
    if (zslParseRange(c->argv[2],c->argv[3],&range) != C_OK) {
        addReplyError(c,"min or max is not a float");
        return;
    }

    
    if ((zobj = lookupKeyReadOrReply(c, key, shared.czero)) == NULL || checkType(c, zobj, OBJ_ZSET)) return;

    if (zobj->encoding == OBJ_ENCODING_LISTPACK) {
        unsigned char *zl = zobj->ptr;
        unsigned char *eptr, *sptr;
        double score;

        
        eptr = zzlFirstInRange(zl,&range);

        
        if (eptr == NULL) {
            addReply(c, shared.czero);
            return;
        }

        
        sptr = lpNext(zl,eptr);
        score = zzlGetScore(sptr);
        serverAssertWithInfo(c,zobj,zslValueLteMax(score,&range));

        
        while (eptr) {
            score = zzlGetScore(sptr);

            
            if (!zslValueLteMax(score,&range)) {
                break;
            } else {
                count++;
                zzlNext(zl,&eptr,&sptr);
            }
        }
    } else if (zobj->encoding == OBJ_ENCODING_SKIPLIST) {
        zset *zs = zobj->ptr;
        zskiplist *zsl = zs->zsl;
        zskiplistNode *zn;
        unsigned long rank;

        
        zn = zslFirstInRange(zsl, &range);

        
        if (zn != NULL) {
            rank = zslGetRank(zsl, zn->score, zn->ele);
            count = (zsl->length - (rank - 1));

            
            zn = zslLastInRange(zsl, &range);

            
            if (zn != NULL) {
                rank = zslGetRank(zsl, zn->score, zn->ele);
                count -= (zsl->length - rank);
            }
        }
    } else {
        serverPanic("Unknown sorted set encoding");
    }

    addReplyLongLong(c, count);
}

void zlexcountCommand(client *c) {
    robj *key = c->argv[1];
    robj *zobj;
    zlexrangespec range;
    unsigned long count = 0;

    
    if (zslParseLexRange(c->argv[2],c->argv[3],&range) != C_OK) {
        addReplyError(c,"min or max not valid string range item");
        return;
    }

    
    if ((zobj = lookupKeyReadOrReply(c, key, shared.czero)) == NULL || checkType(c, zobj, OBJ_ZSET))
    {
        zslFreeLexRange(&range);
        return;
    }

    if (zobj->encoding == OBJ_ENCODING_LISTPACK) {
        unsigned char *zl = zobj->ptr;
        unsigned char *eptr, *sptr;

        
        eptr = zzlFirstInLexRange(zl,&range);

        
        if (eptr == NULL) {
            zslFreeLexRange(&range);
            addReply(c, shared.czero);
            return;
        }

        
        sptr = lpNext(zl,eptr);
        serverAssertWithInfo(c,zobj,zzlLexValueLteMax(eptr,&range));

        
        while (eptr) {
            
            if (!zzlLexValueLteMax(eptr,&range)) {
                break;
            } else {
                count++;
                zzlNext(zl,&eptr,&sptr);
            }
        }
    } else if (zobj->encoding == OBJ_ENCODING_SKIPLIST) {
        zset *zs = zobj->ptr;
        zskiplist *zsl = zs->zsl;
        zskiplistNode *zn;
        unsigned long rank;

        
        zn = zslFirstInLexRange(zsl, &range);

        
        if (zn != NULL) {
            rank = zslGetRank(zsl, zn->score, zn->ele);
            count = (zsl->length - (rank - 1));

            
            zn = zslLastInLexRange(zsl, &range);

            
            if (zn != NULL) {
                rank = zslGetRank(zsl, zn->score, zn->ele);
                count -= (zsl->length - rank);
            }
        }
    } else {
        serverPanic("Unknown sorted set encoding");
    }

    zslFreeLexRange(&range);
    addReplyLongLong(c, count);
}


void genericZrangebylexCommand(zrange_result_handler *handler, zlexrangespec *range, robj *zobj, int withscores, long offset, long limit, int reverse)

{
    unsigned long rangelen = 0;

    handler->beginResultEmission(handler, -1);

    if (zobj->encoding == OBJ_ENCODING_LISTPACK) {
        unsigned char *zl = zobj->ptr;
        unsigned char *eptr, *sptr;
        unsigned char *vstr;
        unsigned int vlen;
        long long vlong;

        
        if (reverse) {
            eptr = zzlLastInLexRange(zl,range);
        } else {
            eptr = zzlFirstInLexRange(zl,range);
        }

        
        if (eptr)
            sptr = lpNext(zl,eptr);

        
        while (eptr && offset--) {
            if (reverse) {
                zzlPrev(zl,&eptr,&sptr);
            } else {
                zzlNext(zl,&eptr,&sptr);
            }
        }

        while (eptr && limit--) {
            double score = 0;
            if (withscores) 
                score = zzlGetScore(sptr);

            
            if (reverse) {
                if (!zzlLexValueGteMin(eptr,range)) break;
            } else {
                if (!zzlLexValueLteMax(eptr,range)) break;
            }

            vstr = lpGetValue(eptr,&vlen,&vlong);
            rangelen++;
            if (vstr == NULL) {
                handler->emitResultFromLongLong(handler, vlong, score);
            } else {
                handler->emitResultFromCBuffer(handler, vstr, vlen, score);
            }

            
            if (reverse) {
                zzlPrev(zl,&eptr,&sptr);
            } else {
                zzlNext(zl,&eptr,&sptr);
            }
        }
    } else if (zobj->encoding == OBJ_ENCODING_SKIPLIST) {
        zset *zs = zobj->ptr;
        zskiplist *zsl = zs->zsl;
        zskiplistNode *ln;

        
        if (reverse) {
            ln = zslLastInLexRange(zsl,range);
        } else {
            ln = zslFirstInLexRange(zsl,range);
        }

        
        while (ln && offset--) {
            if (reverse) {
                ln = ln->backward;
            } else {
                ln = ln->level[0].forward;
            }
        }

        while (ln && limit--) {
            
            if (reverse) {
                if (!zslLexValueGteMin(ln->ele,range)) break;
            } else {
                if (!zslLexValueLteMax(ln->ele,range)) break;
            }

            rangelen++;
            handler->emitResultFromCBuffer(handler, ln->ele, sdslen(ln->ele), ln->score);

            
            if (reverse) {
                ln = ln->backward;
            } else {
                ln = ln->level[0].forward;
            }
        }
    } else {
        serverPanic("Unknown sorted set encoding");
    }

    handler->finalizeResultEmission(handler, rangelen);
}


void zrangebylexCommand(client *c) {
    zrange_result_handler handler;
    zrangeResultHandlerInit(&handler, c, ZRANGE_CONSUMER_TYPE_CLIENT);
    zrangeGenericCommand(&handler, 1, 0, ZRANGE_LEX, ZRANGE_DIRECTION_FORWARD);
}


void zrevrangebylexCommand(client *c) {
    zrange_result_handler handler;
    zrangeResultHandlerInit(&handler, c, ZRANGE_CONSUMER_TYPE_CLIENT);
    zrangeGenericCommand(&handler, 1, 0, ZRANGE_LEX, ZRANGE_DIRECTION_REVERSE);
}


void zrangeGenericCommand(zrange_result_handler *handler, int argc_start, int store, zrange_type rangetype, zrange_direction direction)
{
    client *c = handler->client;
    robj *key = c->argv[argc_start];
    robj *zobj;
    zrangespec range;
    zlexrangespec lexrange;
    int minidx = argc_start + 1;
    int maxidx = argc_start + 2;

    
    long opt_start = 0;
    long opt_end = 0;
    int opt_withscores = 0;
    long opt_offset = 0;
    long opt_limit = -1;

    
    for (int j=argc_start + 3; j < c->argc; j++) {
        int leftargs = c->argc-j-1;
        if (!store && !strcasecmp(c->argv[j]->ptr,"withscores")) {
            opt_withscores = 1;
        } else if (!strcasecmp(c->argv[j]->ptr,"limit") && leftargs >= 2) {
            if ((getLongFromObjectOrReply(c, c->argv[j+1], &opt_offset, NULL) != C_OK) || (getLongFromObjectOrReply(c, c->argv[j+2], &opt_limit, NULL) != C_OK))
            {
                return;
            }
            j += 2;
        } else if (direction == ZRANGE_DIRECTION_AUTO && !strcasecmp(c->argv[j]->ptr,"rev"))
        {
            direction = ZRANGE_DIRECTION_REVERSE;
        } else if (rangetype == ZRANGE_AUTO && !strcasecmp(c->argv[j]->ptr,"bylex"))
        {
            rangetype = ZRANGE_LEX;
        } else if (rangetype == ZRANGE_AUTO && !strcasecmp(c->argv[j]->ptr,"byscore"))
        {
            rangetype = ZRANGE_SCORE;
        } else {
            addReplyErrorObject(c,shared.syntaxerr);
            return;
        }
    }

    
    if (direction == ZRANGE_DIRECTION_AUTO)
        direction = ZRANGE_DIRECTION_FORWARD;
    if (rangetype == ZRANGE_AUTO)
        rangetype = ZRANGE_RANK;

    
    if (opt_limit != -1 && rangetype == ZRANGE_RANK) {
        addReplyError(c,"syntax error, LIMIT is only supported in combination with either BYSCORE or BYLEX");
        return;
    }
    if (opt_withscores && rangetype == ZRANGE_LEX) {
        addReplyError(c,"syntax error, WITHSCORES not supported in combination with BYLEX");
        return;
    }

    if (direction == ZRANGE_DIRECTION_REVERSE && ((ZRANGE_SCORE == rangetype) || (ZRANGE_LEX == rangetype)))
    {
        
        int tmp = maxidx;
        maxidx = minidx;
        minidx = tmp;
    }

    
    switch (rangetype) {
    case ZRANGE_AUTO:
    case ZRANGE_RANK:
        
        if ((getLongFromObjectOrReply(c, c->argv[minidx], &opt_start,NULL) != C_OK) || (getLongFromObjectOrReply(c, c->argv[maxidx], &opt_end,NULL) != C_OK))
        {
            return;
        }
        break;

    case ZRANGE_SCORE:
        
        if (zslParseRange(c->argv[minidx], c->argv[maxidx], &range) != C_OK) {
            addReplyError(c, "min or max is not a float");
            return;
        }
        break;

    case ZRANGE_LEX:
        
        if (zslParseLexRange(c->argv[minidx], c->argv[maxidx], &lexrange) != C_OK) {
            addReplyError(c, "min or max not valid string range item");
            return;
        }
        break;
    }

    if (opt_withscores || store) {
        zrangeResultHandlerScoreEmissionEnable(handler);
    }

    
    zobj = lookupKeyRead(c->db, key);
    if (zobj == NULL) {
        if (store) {
            handler->beginResultEmission(handler, -1);
            handler->finalizeResultEmission(handler, 0);
        } else {
            addReply(c, shared.emptyarray);
        }
        goto cleanup;
    }

    if (checkType(c,zobj,OBJ_ZSET)) goto cleanup;

    
    switch (rangetype) {
    case ZRANGE_AUTO:
    case ZRANGE_RANK:
        genericZrangebyrankCommand(handler, zobj, opt_start, opt_end, opt_withscores || store, direction == ZRANGE_DIRECTION_REVERSE);
        break;

    case ZRANGE_SCORE:
        genericZrangebyscoreCommand(handler, &range, zobj, opt_offset, opt_limit, direction == ZRANGE_DIRECTION_REVERSE);
        break;

    case ZRANGE_LEX:
        genericZrangebylexCommand(handler, &lexrange, zobj, opt_withscores || store, opt_offset, opt_limit, direction == ZRANGE_DIRECTION_REVERSE);
        break;
    }

    

cleanup:

    if (rangetype == ZRANGE_LEX) {
        zslFreeLexRange(&lexrange);
    }
}

void zcardCommand(client *c) {
    robj *key = c->argv[1];
    robj *zobj;

    if ((zobj = lookupKeyReadOrReply(c,key,shared.czero)) == NULL || checkType(c,zobj,OBJ_ZSET)) return;

    addReplyLongLong(c,zsetLength(zobj));
}

void zscoreCommand(client *c) {
    robj *key = c->argv[1];
    robj *zobj;
    double score;

    if ((zobj = lookupKeyReadOrReply(c,key,shared.null[c->resp])) == NULL || checkType(c,zobj,OBJ_ZSET)) return;

    if (zsetScore(zobj,c->argv[2]->ptr,&score) == C_ERR) {
        addReplyNull(c);
    } else {
        addReplyDouble(c,score);
    }
}

void zmscoreCommand(client *c) {
    robj *key = c->argv[1];
    robj *zobj;
    double score;
    zobj = lookupKeyRead(c->db,key);
    if (checkType(c,zobj,OBJ_ZSET)) return;

    addReplyArrayLen(c,c->argc - 2);
    for (int j = 2; j < c->argc; j++) {
        
        if (zobj == NULL || zsetScore(zobj,c->argv[j]->ptr,&score) == C_ERR) {
            addReplyNull(c);
        } else {
            addReplyDouble(c,score);
        }
    }
}

void zrankGenericCommand(client *c, int reverse) {
    robj *key = c->argv[1];
    robj *ele = c->argv[2];
    robj *zobj;
    long rank;

    if ((zobj = lookupKeyReadOrReply(c,key,shared.null[c->resp])) == NULL || checkType(c,zobj,OBJ_ZSET)) return;

    serverAssertWithInfo(c,ele,sdsEncodedObject(ele));
    rank = zsetRank(zobj,ele->ptr,reverse);
    if (rank >= 0) {
        addReplyLongLong(c,rank);
    } else {
        addReplyNull(c);
    }
}

void zrankCommand(client *c) {
    zrankGenericCommand(c, 0);
}

void zrevrankCommand(client *c) {
    zrankGenericCommand(c, 1);
}

void zscanCommand(client *c) {
    robj *o;
    unsigned long cursor;

    if (parseScanCursorOrReply(c,c->argv[2],&cursor) == C_ERR) return;
    if ((o = lookupKeyReadOrReply(c,c->argv[1],shared.emptyscan)) == NULL || checkType(c,o,OBJ_ZSET)) return;
    scanGenericCommand(c,o,cursor);
}


void genericZpopCommand(client *c, robj **keyv, int keyc, int where, int emitkey, long count, int use_nested_array, int reply_nil_when_empty, int *deleted) {
    int idx;
    robj *key = NULL;
    robj *zobj = NULL;
    sds ele;
    double score;

    if (deleted) *deleted = 0;

    
    idx = 0;
    while (idx < keyc) {
        key = keyv[idx++];
        zobj = lookupKeyWrite(c->db,key);
        if (!zobj) continue;
        if (checkType(c,zobj,OBJ_ZSET)) return;
        break;
    }

    
    if (!zobj) {
        if (reply_nil_when_empty) {
            addReplyNullArray(c);
        } else {
            addReply(c,shared.emptyarray);
        }
        return;
    }

    if (count == 0) {
        
        addReply(c, shared.emptyarray);
        return;
    }

    long result_count = 0;

    
    if (count == -1) count = 1;

    long llen = zsetLength(zobj);
    long rangelen = (count > llen) ? llen : count;

    if (!use_nested_array && !emitkey) {
        
        addReplyArrayLen(c, rangelen * 2);
    } else if (use_nested_array && !emitkey) {
        
        addReplyArrayLen(c, rangelen);
    } else if (!use_nested_array && emitkey) {
        
        addReplyArrayLen(c, rangelen * 2 + 1);
        addReplyBulk(c, key);
    } else if (use_nested_array && emitkey) {
        
        addReplyArrayLen(c, 2);
        addReplyBulk(c, key);
        addReplyArrayLen(c, rangelen);
    }

    
    do {
        if (zobj->encoding == OBJ_ENCODING_LISTPACK) {
            unsigned char *zl = zobj->ptr;
            unsigned char *eptr, *sptr;
            unsigned char *vstr;
            unsigned int vlen;
            long long vlong;

            
            eptr = lpSeek(zl,where == ZSET_MAX ? -2 : 0);
            serverAssertWithInfo(c,zobj,eptr != NULL);
            vstr = lpGetValue(eptr,&vlen,&vlong);
            if (vstr == NULL)
                ele = sdsfromlonglong(vlong);
            else ele = sdsnewlen(vstr,vlen);

            
            sptr = lpNext(zl,eptr);
            serverAssertWithInfo(c,zobj,sptr != NULL);
            score = zzlGetScore(sptr);
        } else if (zobj->encoding == OBJ_ENCODING_SKIPLIST) {
            zset *zs = zobj->ptr;
            zskiplist *zsl = zs->zsl;
            zskiplistNode *zln;

            
            zln = (where == ZSET_MAX ? zsl->tail :
                                       zsl->header->level[0].forward);

            
            serverAssertWithInfo(c,zobj,zln != NULL);
            ele = sdsdup(zln->ele);
            score = zln->score;
        } else {
            serverPanic("Unknown sorted set encoding");
        }

        serverAssertWithInfo(c,zobj,zsetDel(zobj,ele));
        server.dirty++;

        if (result_count == 0) { 
            char *events[2] = {"zpopmin","zpopmax";
            notifyKeyspaceEvent(NOTIFY_ZSET,events[where],key,c->db->id);
            signalModifiedKey(c,c->db,key);
        }

        if (use_nested_array) {
            addReplyArrayLen(c,2);
        }
        addReplyBulkCBuffer(c,ele,sdslen(ele));
        addReplyDouble(c,score);
        sdsfree(ele);
        ++result_count;
    } while(--rangelen);

    
    if (zsetLength(zobj) == 0) {
        if (deleted) *deleted = 1;

        dbDelete(c->db,key);
        notifyKeyspaceEvent(NOTIFY_GENERIC,"del",key,c->db->id);
    }

    if (c->cmd->proc == zmpopCommand) {
        
        robj *count_obj = createStringObjectFromLongLong((count > llen) ? llen : count);
        rewriteClientCommandVector(c, 3, (where == ZSET_MAX) ? shared.zpopmax : shared.zpopmin, key, count_obj);

        decrRefCount(count_obj);
    }
}


void zpopMinMaxCommand(client *c, int where) {
    if (c->argc > 3) {
        addReplyErrorObject(c,shared.syntaxerr);
        return;
    }

    long count = -1; 
    if (c->argc == 3 && getPositiveLongFromObjectOrReply(c, c->argv[2], &count, NULL) != C_OK)
        return;

    
    int use_nested_array = (c->resp > 2 && count != -1);

    genericZpopCommand(c, &c->argv[1], 1, where, 0, count, use_nested_array, 0, NULL);
}


void zpopminCommand(client *c) {
    zpopMinMaxCommand(c, ZSET_MIN);
}


void zpopmaxCommand(client *c) {
    zpopMinMaxCommand(c, ZSET_MAX);
}


void blockingGenericZpopCommand(client *c, robj **keys, int numkeys, int where, int timeout_idx, long count, int use_nested_array, int reply_nil_when_empty) {
    robj *o;
    robj *key;
    mstime_t timeout;
    int j;

    if (getTimeoutFromObjectOrReply(c,c->argv[timeout_idx],&timeout,UNIT_SECONDS)
        != C_OK) return;

    for (j = 0; j < numkeys; j++) {
        key = keys[j];
        o = lookupKeyWrite(c->db,key);
        
        if (o == NULL) continue;

        if (checkType(c,o,OBJ_ZSET)) return;

        long llen = zsetLength(o);
        
        if (llen == 0) continue;

        
        genericZpopCommand(c, &key, 1, where, 1, count, use_nested_array, reply_nil_when_empty, NULL);

        if (count == -1) {
            
            rewriteClientCommandVector(c,2, (where == ZSET_MAX) ? shared.zpopmax : shared.zpopmin, key);

        } else {
            
            robj *count_obj = createStringObjectFromLongLong((count > llen) ? llen : count);
            rewriteClientCommandVector(c, 3, (where == ZSET_MAX) ? shared.zpopmax : shared.zpopmin, key, count_obj);

            decrRefCount(count_obj);
        }

        return;
    }

    
    if (c->flags & CLIENT_DENY_BLOCKING) {
        addReplyNullArray(c);
        return;
    }

    
    struct blockPos pos = {where};
    blockForKeys(c,BLOCKED_ZSET,keys,numkeys,count,timeout,NULL,&pos,NULL);
}


void bzpopminCommand(client *c) {
    blockingGenericZpopCommand(c, c->argv+1, c->argc-2, ZSET_MIN, c->argc-1, -1, 0, 0);
}


void bzpopmaxCommand(client *c) {
    blockingGenericZpopCommand(c, c->argv+1, c->argc-2, ZSET_MAX, c->argc-1, -1, 0, 0);
}

static void zrandmemberReplyWithListpack(client *c, unsigned int count, listpackEntry *keys, listpackEntry *vals) {
    for (unsigned long i = 0; i < count; i++) {
        if (vals && c->resp > 2)
            addReplyArrayLen(c,2);
        if (keys[i].sval)
            addReplyBulkCBuffer(c, keys[i].sval, keys[i].slen);
        else addReplyBulkLongLong(c, keys[i].lval);
        if (vals) {
            if (vals[i].sval) {
                addReplyDouble(c, zzlStrtod(vals[i].sval,vals[i].slen));
            } else addReplyDouble(c, vals[i].lval);
        }
    }
}







void zrandmemberWithCountCommand(client *c, long l, int withscores) {
    unsigned long count, size;
    int uniq = 1;
    robj *zsetobj;

    if ((zsetobj = lookupKeyReadOrReply(c, c->argv[1], shared.emptyarray))
        == NULL || checkType(c, zsetobj, OBJ_ZSET)) return;
    size = zsetLength(zsetobj);

    if(l >= 0) {
        count = (unsigned long) l;
    } else {
        count = -l;
        uniq = 0;
    }

    
    if (count == 0) {
        addReply(c,shared.emptyarray);
        return;
    }

    
    if (!uniq || count == 1) {
        if (withscores && c->resp == 2)
            addReplyArrayLen(c, count*2);
        else addReplyArrayLen(c, count);
        if (zsetobj->encoding == OBJ_ENCODING_SKIPLIST) {
            zset *zs = zsetobj->ptr;
            while (count--) {
                dictEntry *de = dictGetFairRandomKey(zs->dict);
                sds key = dictGetKey(de);
                if (withscores && c->resp > 2)
                    addReplyArrayLen(c,2);
                addReplyBulkCBuffer(c, key, sdslen(key));
                if (withscores)
                    addReplyDouble(c, *(double*)dictGetVal(de));
                if (c->flags & CLIENT_CLOSE_ASAP)
                    break;
            }
        } else if (zsetobj->encoding == OBJ_ENCODING_LISTPACK) {
            listpackEntry *keys, *vals = NULL;
            unsigned long limit, sample_count;
            limit = count > ZRANDMEMBER_RANDOM_SAMPLE_LIMIT ? ZRANDMEMBER_RANDOM_SAMPLE_LIMIT : count;
            keys = zmalloc(sizeof(listpackEntry)*limit);
            if (withscores)
                vals = zmalloc(sizeof(listpackEntry)*limit);
            while (count) {
                sample_count = count > limit ? limit : count;
                count -= sample_count;
                lpRandomPairs(zsetobj->ptr, sample_count, keys, vals);
                zrandmemberReplyWithListpack(c, sample_count, keys, vals);
                if (c->flags & CLIENT_CLOSE_ASAP)
                    break;
            }
            zfree(keys);
            zfree(vals);
        }
        return;
    }

    zsetopsrc src;
    zsetopval zval;
    src.subject = zsetobj;
    src.type = zsetobj->type;
    src.encoding = zsetobj->encoding;
    zuiInitIterator(&src);
    memset(&zval, 0, sizeof(zval));

    
    long reply_size = count < size ? count : size;
    if (withscores && c->resp == 2)
        addReplyArrayLen(c, reply_size*2);
    else addReplyArrayLen(c, reply_size);

    
    if (count >= size) {
        while (zuiNext(&src, &zval)) {
            if (withscores && c->resp > 2)
                addReplyArrayLen(c,2);
            addReplyBulkSds(c, zuiNewSdsFromValue(&zval));
            if (withscores)
                addReplyDouble(c, zval.score);
        }
        zuiClearIterator(&src);
        return;
    }

    
    if (count*ZRANDMEMBER_SUB_STRATEGY_MUL > size) {
        dict *d = dictCreate(&sdsReplyDictType);
        dictExpand(d, size);
        
        while (zuiNext(&src, &zval)) {
            sds key = zuiNewSdsFromValue(&zval);
            dictEntry *de = dictAddRaw(d, key, NULL);
            serverAssert(de);
            if (withscores)
                dictSetDoubleVal(de, zval.score);
        }
        serverAssert(dictSize(d) == size);

        
        while (size > count) {
            dictEntry *de;
            de = dictGetFairRandomKey(d);
            dictUnlink(d,dictGetKey(de));
            sdsfree(dictGetKey(de));
            dictFreeUnlinkedEntry(d,de);
            size--;
        }

        
        dictIterator *di;
        dictEntry *de;
        di = dictGetIterator(d);
        while ((de = dictNext(di)) != NULL) {
            if (withscores && c->resp > 2)
                addReplyArrayLen(c,2);
            addReplyBulkSds(c, dictGetKey(de));
            if (withscores)
                addReplyDouble(c, dictGetDoubleVal(de));
        }

        dictReleaseIterator(di);
        dictRelease(d);
    }

    
    else {
        if (zsetobj->encoding == OBJ_ENCODING_LISTPACK) {
            
            listpackEntry *keys, *vals = NULL;
            keys = zmalloc(sizeof(listpackEntry)*count);
            if (withscores)
                vals = zmalloc(sizeof(listpackEntry)*count);
            serverAssert(lpRandomPairsUnique(zsetobj->ptr, count, keys, vals) == count);
            zrandmemberReplyWithListpack(c, count, keys, vals);
            zfree(keys);
            zfree(vals);
            zuiClearIterator(&src);
            return;
        }

        
        unsigned long added = 0;
        dict *d = dictCreate(&hashDictType);
        dictExpand(d, count);

        while (added < count) {
            listpackEntry key;
            double score;
            zsetTypeRandomElement(zsetobj, size, &key, withscores ? &score: NULL);

            
            sds skey = zsetSdsFromListpackEntry(&key);
            if (dictAdd(d,skey,NULL) != DICT_OK) {
                sdsfree(skey);
                continue;
            }
            added++;

            if (withscores && c->resp > 2)
                addReplyArrayLen(c,2);
            zsetReplyFromListpackEntry(c, &key);
            if (withscores)
                addReplyDouble(c, score);
        }

        
        dictRelease(d);
    }
    zuiClearIterator(&src);
}


void zrandmemberCommand(client *c) {
    long l;
    int withscores = 0;
    robj *zset;
    listpackEntry ele;

    if (c->argc >= 3) {
        if (getLongFromObjectOrReply(c,c->argv[2],&l,NULL) != C_OK) return;
        if (c->argc > 4 || (c->argc == 4 && strcasecmp(c->argv[3]->ptr,"withscores"))) {
            addReplyErrorObject(c,shared.syntaxerr);
            return;
        } else if (c->argc == 4) {
            withscores = 1;
            if (l < LONG_MIN/2 || l > LONG_MAX/2) {
                addReplyError(c,"value is out of range");
                return;
            }
        }
        zrandmemberWithCountCommand(c, l, withscores);
        return;
    }

    
    if ((zset = lookupKeyReadOrReply(c,c->argv[1],shared.null[c->resp]))== NULL || checkType(c,zset,OBJ_ZSET)) {
        return;
    }

    zsetTypeRandomElement(zset, zsetLength(zset), &ele,NULL);
    zsetReplyFromListpackEntry(c,&ele);
}


void zmpopGenericCommand(client *c, int numkeys_idx, int is_block) {
    long j;
    long numkeys = 0;      
    int where = 0;         
    long count = -1;       

    
    if (getRangeLongFromObjectOrReply(c, c->argv[numkeys_idx], 1, LONG_MAX, &numkeys, "numkeys should be greater than 0") != C_OK)
        return;

    
    long where_idx = numkeys_idx + numkeys + 1;
    if (where_idx >= c->argc) {
        addReplyErrorObject(c, shared.syntaxerr);
        return;
    }
    if (!strcasecmp(c->argv[where_idx]->ptr, "MIN")) {
        where = ZSET_MIN;
    } else if (!strcasecmp(c->argv[where_idx]->ptr, "MAX")) {
        where = ZSET_MAX;
    } else {
        addReplyErrorObject(c, shared.syntaxerr);
        return;
    }

    
    for (j = where_idx + 1; j < c->argc; j++) {
        char *opt = c->argv[j]->ptr;
        int moreargs = (c->argc - 1) - j;

        if (count == -1 && !strcasecmp(opt, "COUNT") && moreargs) {
            j++;
            if (getRangeLongFromObjectOrReply(c, c->argv[j], 1, LONG_MAX, &count,"count should be greater than 0") != C_OK)
                return;
        } else {
            addReplyErrorObject(c, shared.syntaxerr);
            return;
        }
    }

    if (count == -1) count = 1;

    if (is_block) {
        
        blockingGenericZpopCommand(c, c->argv+numkeys_idx+1, numkeys, where, 1, count, 1, 1);
    } else {
        
        genericZpopCommand(c, c->argv+numkeys_idx+1, numkeys, where, 1, count, 1, 1, NULL);
    }
}


void zmpopCommand(client *c) {
    zmpopGenericCommand(c, 1, 0);
}


void bzmpopCommand(client *c) {
    zmpopGenericCommand(c, 2, 1);
}
