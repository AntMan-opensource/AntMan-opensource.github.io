






size_t redisPopcount(void *s, long count) {
    size_t bits = 0;
    unsigned char *p = s;
    uint32_t *p4;
    static const unsigned char bitsinbyte[256] = {0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4,1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,4,5,5,6,5,6,6,7,5,6,6,7,6,7,7,8};

    
    while((unsigned long)p & 3 && count) {
        bits += bitsinbyte[*p++];
        count--;
    }

    
    p4 = (uint32_t*)p;
    while(count>=28) {
        uint32_t aux1, aux2, aux3, aux4, aux5, aux6, aux7;

        aux1 = *p4++;
        aux2 = *p4++;
        aux3 = *p4++;
        aux4 = *p4++;
        aux5 = *p4++;
        aux6 = *p4++;
        aux7 = *p4++;
        count -= 28;

        aux1 = aux1 - ((aux1 >> 1) & 0x55555555);
        aux1 = (aux1 & 0x33333333) + ((aux1 >> 2) & 0x33333333);
        aux2 = aux2 - ((aux2 >> 1) & 0x55555555);
        aux2 = (aux2 & 0x33333333) + ((aux2 >> 2) & 0x33333333);
        aux3 = aux3 - ((aux3 >> 1) & 0x55555555);
        aux3 = (aux3 & 0x33333333) + ((aux3 >> 2) & 0x33333333);
        aux4 = aux4 - ((aux4 >> 1) & 0x55555555);
        aux4 = (aux4 & 0x33333333) + ((aux4 >> 2) & 0x33333333);
        aux5 = aux5 - ((aux5 >> 1) & 0x55555555);
        aux5 = (aux5 & 0x33333333) + ((aux5 >> 2) & 0x33333333);
        aux6 = aux6 - ((aux6 >> 1) & 0x55555555);
        aux6 = (aux6 & 0x33333333) + ((aux6 >> 2) & 0x33333333);
        aux7 = aux7 - ((aux7 >> 1) & 0x55555555);
        aux7 = (aux7 & 0x33333333) + ((aux7 >> 2) & 0x33333333);
        bits += ((((aux1 + (aux1 >> 4)) & 0x0F0F0F0F) + ((aux2 + (aux2 >> 4)) & 0x0F0F0F0F) + ((aux3 + (aux3 >> 4)) & 0x0F0F0F0F) + ((aux4 + (aux4 >> 4)) & 0x0F0F0F0F) + ((aux5 + (aux5 >> 4)) & 0x0F0F0F0F) + ((aux6 + (aux6 >> 4)) & 0x0F0F0F0F) + ((aux7 + (aux7 >> 4)) & 0x0F0F0F0F))* 0x01010101) >> 24;





    }
    
    p = (unsigned char*)p4;
    while(count--) bits += bitsinbyte[*p++];
    return bits;
}


long redisBitpos(void *s, unsigned long count, int bit) {
    unsigned long *l;
    unsigned char *c;
    unsigned long skipval, word = 0, one;
    long pos = 0; 
    unsigned long j;
    int found;

    

    
    skipval = bit ? 0 : UCHAR_MAX;
    c = (unsigned char*) s;
    found = 0;
    while((unsigned long)c & (sizeof(*l)-1) && count) {
        if (*c != skipval) {
            found = 1;
            break;
        }
        c++;
        count--;
        pos += 8;
    }

    
    l = (unsigned long*) c;
    if (!found) {
        skipval = bit ? 0 : ULONG_MAX;
        while (count >= sizeof(*l)) {
            if (*l != skipval) break;
            l++;
            count -= sizeof(*l);
            pos += sizeof(*l)*8;
        }
    }

    
    c = (unsigned char*)l;
    for (j = 0; j < sizeof(*l); j++) {
        word <<= 8;
        if (count) {
            word |= *c;
            c++;
            count--;
        }
    }

    
    if (bit == 1 && word == 0) return -1;

    
    one = ULONG_MAX; 
    one >>= 1;       
    one = ~one;      

    while(one) {
        if (((one & word) != 0) == bit) return pos;
        pos++;
        one >>= 1;
    }

    
    serverPanic("End of redisBitpos() reached.");
    return 0; 
}



void setUnsignedBitfield(unsigned char *p, uint64_t offset, uint64_t bits, uint64_t value) {
    uint64_t byte, bit, byteval, bitval, j;

    for (j = 0; j < bits; j++) {
        bitval = (value & ((uint64_t)1<<(bits-1-j))) != 0;
        byte = offset >> 3;
        bit = 7 - (offset & 0x7);
        byteval = p[byte];
        byteval &= ~(1 << bit);
        byteval |= bitval << bit;
        p[byte] = byteval & 0xff;
        offset++;
    }
}

void setSignedBitfield(unsigned char *p, uint64_t offset, uint64_t bits, int64_t value) {
    uint64_t uv = value; 
    setUnsignedBitfield(p,offset,bits,uv);
}

uint64_t getUnsignedBitfield(unsigned char *p, uint64_t offset, uint64_t bits) {
    uint64_t byte, bit, byteval, bitval, j, value = 0;

    for (j = 0; j < bits; j++) {
        byte = offset >> 3;
        bit = 7 - (offset & 0x7);
        byteval = p[byte];
        bitval = (byteval >> bit) & 1;
        value = (value<<1) | bitval;
        offset++;
    }
    return value;
}

int64_t getSignedBitfield(unsigned char *p, uint64_t offset, uint64_t bits) {
    int64_t value;
    union {uint64_t u; int64_t i;} conv;

    
    conv.u = getUnsignedBitfield(p,offset,bits);
    value = conv.i;

    
    if (bits < 64 && (value & ((uint64_t)1 << (bits-1))))
        value |= ((uint64_t)-1) << bits;
    return value;
}







int checkUnsignedBitfieldOverflow(uint64_t value, int64_t incr, uint64_t bits, int owtype, uint64_t *limit) {
    uint64_t max = (bits == 64) ? UINT64_MAX : (((uint64_t)1<<bits)-1);
    int64_t maxincr = max-value;
    int64_t minincr = -value;

    if (value > max || (incr > 0 && incr > maxincr)) {
        if (limit) {
            if (owtype == BFOVERFLOW_WRAP) {
                goto handle_wrap;
            } else if (owtype == BFOVERFLOW_SAT) {
                *limit = max;
            }
        }
        return 1;
    } else if (incr < 0 && incr < minincr) {
        if (limit) {
            if (owtype == BFOVERFLOW_WRAP) {
                goto handle_wrap;
            } else if (owtype == BFOVERFLOW_SAT) {
                *limit = 0;
            }
        }
        return -1;
    }
    return 0;

handle_wrap:
    {
        uint64_t mask = ((uint64_t)-1) << bits;
        uint64_t res = value+incr;

        res &= ~mask;
        *limit = res;
    }
    return 1;
}

int checkSignedBitfieldOverflow(int64_t value, int64_t incr, uint64_t bits, int owtype, int64_t *limit) {
    int64_t max = (bits == 64) ? INT64_MAX : (((int64_t)1<<(bits-1))-1);
    int64_t min = (-max)-1;

    
    int64_t maxincr = max-value;
    int64_t minincr = min-value;

    if (value > max || (bits != 64 && incr > maxincr) || (value >= 0 && incr > 0 && incr > maxincr))
    {
        if (limit) {
            if (owtype == BFOVERFLOW_WRAP) {
                goto handle_wrap;
            } else if (owtype == BFOVERFLOW_SAT) {
                *limit = max;
            }
        }
        return 1;
    } else if (value < min || (bits != 64 && incr < minincr) || (value < 0 && incr < 0 && incr < minincr)) {
        if (limit) {
            if (owtype == BFOVERFLOW_WRAP) {
                goto handle_wrap;
            } else if (owtype == BFOVERFLOW_SAT) {
                *limit = min;
            }
        }
        return -1;
    }
    return 0;

handle_wrap:
    {
        uint64_t msb = (uint64_t)1 << (bits-1);
        uint64_t a = value, b = incr, c;
        c = a+b; 

        
        if (bits < 64) {
            uint64_t mask = ((uint64_t)-1) << bits;
            if (c & msb) {
                c |= mask;
            } else {
                c &= ~mask;
            }
        }
        *limit = c;
    }
    return 1;
}


void printBits(unsigned char *p, unsigned long count) {
    unsigned long j, i, byte;

    for (j = 0; j < count; j++) {
        byte = p[j];
        for (i = 0x80; i > 0; i /= 2)
            printf("%c", (byte & i) ? '1' : '0');
        printf("|");
    }
    printf("\n");
}













int getBitOffsetFromArgument(client *c, robj *o, size_t *offset, int hash, int bits) {
    long long loffset;
    char *err = "bit offset is not an integer or out of range";
    char *p = o->ptr;
    size_t plen = sdslen(p);
    int usehash = 0;

    
    if (p[0] == '#' && hash && bits > 0) usehash = 1;

    if (string2ll(p+usehash,plen-usehash,&loffset) == 0) {
        addReplyError(c,err);
        return C_ERR;
    }

    
    if (usehash) loffset *= bits;

    
    if ((loffset < 0) || (loffset >> 3) >= server.proto_max_bulk_len)
    {
        addReplyError(c,err);
        return C_ERR;
    }

    *offset = (size_t)loffset;
    return C_OK;
}


int getBitfieldTypeFromArgument(client *c, robj *o, int *sign, int *bits) {
    char *p = o->ptr;
    char *err = "Invalid bitfield type. Use something like i16 u8. Note that u64 is not supported but i64 is.";
    long long llbits;

    if (p[0] == 'i') {
        *sign = 1;
    } else if (p[0] == 'u') {
        *sign = 0;
    } else {
        addReplyError(c,err);
        return C_ERR;
    }

    if ((string2ll(p+1,strlen(p+1),&llbits)) == 0 || llbits < 1 || (*sign == 1 && llbits > 64) || (*sign == 0 && llbits > 63))


    {
        addReplyError(c,err);
        return C_ERR;
    }
    *bits = llbits;
    return C_OK;
}


robj *lookupStringForBitCommand(client *c, size_t maxbit) {
    size_t byte = maxbit >> 3;
    robj *o = lookupKeyWrite(c->db,c->argv[1]);
    if (checkType(c,o,OBJ_STRING)) return NULL;

    if (o == NULL) {
        o = createObject(OBJ_STRING,sdsnewlen(NULL, byte+1));
        dbAdd(c->db,c->argv[1],o);
    } else {
        o = dbUnshareStringValue(c->db,c->argv[1],o);
        o->ptr = sdsgrowzero(o->ptr,byte+1);
    }
    return o;
}


unsigned char *getObjectReadOnlyString(robj *o, long *len, char *llbuf) {
    serverAssert(o->type == OBJ_STRING);
    unsigned char *p = NULL;

    
    if (o && o->encoding == OBJ_ENCODING_INT) {
        p = (unsigned char*) llbuf;
        if (len) *len = ll2string(llbuf,LONG_STR_SIZE,(long)o->ptr);
    } else if (o) {
        p = (unsigned char*) o->ptr;
        if (len) *len = sdslen(o->ptr);
    } else {
        if (len) *len = 0;
    }
    return p;
}


void setbitCommand(client *c) {
    robj *o;
    char *err = "bit is not an integer or out of range";
    size_t bitoffset;
    ssize_t byte, bit;
    int byteval, bitval;
    long on;

    if (getBitOffsetFromArgument(c,c->argv[2],&bitoffset,0,0) != C_OK)
        return;

    if (getLongFromObjectOrReply(c,c->argv[3],&on,err) != C_OK)
        return;

    
    if (on & ~1) {
        addReplyError(c,err);
        return;
    }

    if ((o = lookupStringForBitCommand(c,bitoffset)) == NULL) return;

    
    byte = bitoffset >> 3;
    byteval = ((uint8_t*)o->ptr)[byte];
    bit = 7 - (bitoffset & 0x7);
    bitval = byteval & (1 << bit);

    
    byteval &= ~(1 << bit);
    byteval |= ((on & 0x1) << bit);
    ((uint8_t*)o->ptr)[byte] = byteval;
    signalModifiedKey(c,c->db,c->argv[1]);
    notifyKeyspaceEvent(NOTIFY_STRING,"setbit",c->argv[1],c->db->id);
    server.dirty++;
    addReply(c, bitval ? shared.cone : shared.czero);
}


void getbitCommand(client *c) {
    robj *o;
    char llbuf[32];
    size_t bitoffset;
    size_t byte, bit;
    size_t bitval = 0;

    if (getBitOffsetFromArgument(c,c->argv[2],&bitoffset,0,0) != C_OK)
        return;

    if ((o = lookupKeyReadOrReply(c,c->argv[1],shared.czero)) == NULL || checkType(c,o,OBJ_STRING)) return;

    byte = bitoffset >> 3;
    bit = 7 - (bitoffset & 0x7);
    if (sdsEncodedObject(o)) {
        if (byte < sdslen(o->ptr))
            bitval = ((uint8_t*)o->ptr)[byte] & (1 << bit);
    } else {
        if (byte < (size_t)ll2string(llbuf,sizeof(llbuf),(long)o->ptr))
            bitval = llbuf[byte] & (1 << bit);
    }

    addReply(c, bitval ? shared.cone : shared.czero);
}


void bitopCommand(client *c) {
    char *opname = c->argv[1]->ptr;
    robj *o, *targetkey = c->argv[2];
    unsigned long op, j, numkeys;
    robj **objects;      
    unsigned char **src; 
    unsigned long *len, maxlen = 0; 
    unsigned long minlen = 0;    
    unsigned char *res = NULL; 

    
    if ((opname[0] == 'a' || opname[0] == 'A') && !strcasecmp(opname,"and"))
        op = BITOP_AND;
    else if((opname[0] == 'o' || opname[0] == 'O') && !strcasecmp(opname,"or"))
        op = BITOP_OR;
    else if((opname[0] == 'x' || opname[0] == 'X') && !strcasecmp(opname,"xor"))
        op = BITOP_XOR;
    else if((opname[0] == 'n' || opname[0] == 'N') && !strcasecmp(opname,"not"))
        op = BITOP_NOT;
    else {
        addReplyErrorObject(c,shared.syntaxerr);
        return;
    }

    
    if (op == BITOP_NOT && c->argc != 4) {
        addReplyError(c,"BITOP NOT must be called with a single source key.");
        return;
    }

    
    numkeys = c->argc - 3;
    src = zmalloc(sizeof(unsigned char*) * numkeys);
    len = zmalloc(sizeof(long) * numkeys);
    objects = zmalloc(sizeof(robj*) * numkeys);
    for (j = 0; j < numkeys; j++) {
        o = lookupKeyRead(c->db,c->argv[j+3]);
        
        if (o == NULL) {
            objects[j] = NULL;
            src[j] = NULL;
            len[j] = 0;
            minlen = 0;
            continue;
        }
        
        if (checkType(c,o,OBJ_STRING)) {
            unsigned long i;
            for (i = 0; i < j; i++) {
                if (objects[i])
                    decrRefCount(objects[i]);
            }
            zfree(src);
            zfree(len);
            zfree(objects);
            return;
        }
        objects[j] = getDecodedObject(o);
        src[j] = objects[j]->ptr;
        len[j] = sdslen(objects[j]->ptr);
        if (len[j] > maxlen) maxlen = len[j];
        if (j == 0 || len[j] < minlen) minlen = len[j];
    }

    
    if (maxlen) {
        res = (unsigned char*) sdsnewlen(NULL,maxlen);
        unsigned char output, byte;
        unsigned long i;

        
        j = 0;
        #ifndef USE_ALIGNED_ACCESS
        if (minlen >= sizeof(unsigned long)*4 && numkeys <= 16) {
            unsigned long *lp[16];
            unsigned long *lres = (unsigned long*) res;

            
            memcpy(lp,src,sizeof(unsigned long*)*numkeys);
            memcpy(res,src[0],minlen);

            
            if (op == BITOP_AND) {
                while(minlen >= sizeof(unsigned long)*4) {
                    for (i = 1; i < numkeys; i++) {
                        lres[0] &= lp[i][0];
                        lres[1] &= lp[i][1];
                        lres[2] &= lp[i][2];
                        lres[3] &= lp[i][3];
                        lp[i]+=4;
                    }
                    lres+=4;
                    j += sizeof(unsigned long)*4;
                    minlen -= sizeof(unsigned long)*4;
                }
            } else if (op == BITOP_OR) {
                while(minlen >= sizeof(unsigned long)*4) {
                    for (i = 1; i < numkeys; i++) {
                        lres[0] |= lp[i][0];
                        lres[1] |= lp[i][1];
                        lres[2] |= lp[i][2];
                        lres[3] |= lp[i][3];
                        lp[i]+=4;
                    }
                    lres+=4;
                    j += sizeof(unsigned long)*4;
                    minlen -= sizeof(unsigned long)*4;
                }
            } else if (op == BITOP_XOR) {
                while(minlen >= sizeof(unsigned long)*4) {
                    for (i = 1; i < numkeys; i++) {
                        lres[0] ^= lp[i][0];
                        lres[1] ^= lp[i][1];
                        lres[2] ^= lp[i][2];
                        lres[3] ^= lp[i][3];
                        lp[i]+=4;
                    }
                    lres+=4;
                    j += sizeof(unsigned long)*4;
                    minlen -= sizeof(unsigned long)*4;
                }
            } else if (op == BITOP_NOT) {
                while(minlen >= sizeof(unsigned long)*4) {
                    lres[0] = ~lres[0];
                    lres[1] = ~lres[1];
                    lres[2] = ~lres[2];
                    lres[3] = ~lres[3];
                    lres+=4;
                    j += sizeof(unsigned long)*4;
                    minlen -= sizeof(unsigned long)*4;
                }
            }
        }
        #endif

        
        for (; j < maxlen; j++) {
            output = (len[0] <= j) ? 0 : src[0][j];
            if (op == BITOP_NOT) output = ~output;
            for (i = 1; i < numkeys; i++) {
                int skip = 0;
                byte = (len[i] <= j) ? 0 : src[i][j];
                switch(op) {
                case BITOP_AND:
                    output &= byte;
                    skip = (output == 0);
                    break;
                case BITOP_OR:
                    output |= byte;
                    skip = (output == 0xff);
                    break;
                case BITOP_XOR: output ^= byte; break;
                }

                if (skip) {
                    break;
                }
            }
            res[j] = output;
        }
    }
    for (j = 0; j < numkeys; j++) {
        if (objects[j])
            decrRefCount(objects[j]);
    }
    zfree(src);
    zfree(len);
    zfree(objects);

    
    if (maxlen) {
        o = createObject(OBJ_STRING,res);
        setKey(c,c->db,targetkey,o);
        notifyKeyspaceEvent(NOTIFY_STRING,"set",targetkey,c->db->id);
        decrRefCount(o);
        server.dirty++;
    } else if (dbDelete(c->db,targetkey)) {
        signalModifiedKey(c,c->db,targetkey);
        notifyKeyspaceEvent(NOTIFY_GENERIC,"del",targetkey,c->db->id);
        server.dirty++;
    }
    addReplyLongLong(c,maxlen); 
}


void bitcountCommand(client *c) {
    robj *o;
    long start, end, strlen;
    unsigned char *p;
    char llbuf[LONG_STR_SIZE];

    
    if ((o = lookupKeyReadOrReply(c,c->argv[1],shared.czero)) == NULL || checkType(c,o,OBJ_STRING)) return;
    p = getObjectReadOnlyString(o,&strlen,llbuf);

    
    if (c->argc == 4) {
        if (getLongFromObjectOrReply(c,c->argv[2],&start,NULL) != C_OK)
            return;
        if (getLongFromObjectOrReply(c,c->argv[3],&end,NULL) != C_OK)
            return;
        
        if (start < 0 && end < 0 && start > end) {
            addReply(c,shared.czero);
            return;
        }
        if (start < 0) start = strlen+start;
        if (end < 0) end = strlen+end;
        if (start < 0) start = 0;
        if (end < 0) end = 0;
        if (end >= strlen) end = strlen-1;
    } else if (c->argc == 2) {
        
        start = 0;
        end = strlen-1;
    } else {
        
        addReplyErrorObject(c,shared.syntaxerr);
        return;
    }

    
    if (start > end) {
        addReply(c,shared.czero);
    } else {
        long bytes = end-start+1;

        addReplyLongLong(c,redisPopcount(p+start,bytes));
    }
}


void bitposCommand(client *c) {
    robj *o;
    long bit, start, end, strlen;
    unsigned char *p;
    char llbuf[LONG_STR_SIZE];
    int end_given = 0;

    
    if (getLongFromObjectOrReply(c,c->argv[2],&bit,NULL) != C_OK)
        return;
    if (bit != 0 && bit != 1) {
        addReplyError(c, "The bit argument must be 1 or 0.");
        return;
    }

    
    if ((o = lookupKeyRead(c->db,c->argv[1])) == NULL) {
        addReplyLongLong(c, bit ? -1 : 0);
        return;
    }
    if (checkType(c,o,OBJ_STRING)) return;
    p = getObjectReadOnlyString(o,&strlen,llbuf);

    
    if (c->argc == 4 || c->argc == 5) {
        if (getLongFromObjectOrReply(c,c->argv[3],&start,NULL) != C_OK)
            return;
        if (c->argc == 5) {
            if (getLongFromObjectOrReply(c,c->argv[4],&end,NULL) != C_OK)
                return;
            end_given = 1;
        } else {
            end = strlen-1;
        }
        
        if (start < 0) start = strlen+start;
        if (end < 0) end = strlen+end;
        if (start < 0) start = 0;
        if (end < 0) end = 0;
        if (end >= strlen) end = strlen-1;
    } else if (c->argc == 3) {
        
        start = 0;
        end = strlen-1;
    } else {
        
        addReplyErrorObject(c,shared.syntaxerr);
        return;
    }

    
    if (start > end) {
        addReplyLongLong(c, -1);
    } else {
        long bytes = end-start+1;
        long pos = redisBitpos(p+start,bytes,bit);

        
        if (end_given && bit == 0 && pos == bytes*8) {
            addReplyLongLong(c,-1);
            return;
        }
        if (pos != -1) pos += start*8; 
        addReplyLongLong(c,pos);
    }
}






struct bitfieldOp {
    uint64_t offset;    
    int64_t i64;        
    int opcode;         
    int owtype;         
    int bits;           
    int sign;           
};


void bitfieldGeneric(client *c, int flags) {
    robj *o;
    size_t bitoffset;
    int j, numops = 0, changes = 0;
    struct bitfieldOp *ops = NULL; 
    int owtype = BFOVERFLOW_WRAP; 
    int readonly = 1;
    size_t highest_write_offset = 0;

    for (j = 2; j < c->argc; j++) {
        int remargs = c->argc-j-1; 
        char *subcmd = c->argv[j]->ptr; 
        int opcode; 
        long long i64 = 0;  
        int sign = 0; 
        int bits = 0; 

        if (!strcasecmp(subcmd,"get") && remargs >= 2)
            opcode = BITFIELDOP_GET;
        else if (!strcasecmp(subcmd,"set") && remargs >= 3)
            opcode = BITFIELDOP_SET;
        else if (!strcasecmp(subcmd,"incrby") && remargs >= 3)
            opcode = BITFIELDOP_INCRBY;
        else if (!strcasecmp(subcmd,"overflow") && remargs >= 1) {
            char *owtypename = c->argv[j+1]->ptr;
            j++;
            if (!strcasecmp(owtypename,"wrap"))
                owtype = BFOVERFLOW_WRAP;
            else if (!strcasecmp(owtypename,"sat"))
                owtype = BFOVERFLOW_SAT;
            else if (!strcasecmp(owtypename,"fail"))
                owtype = BFOVERFLOW_FAIL;
            else {
                addReplyError(c,"Invalid OVERFLOW type specified");
                zfree(ops);
                return;
            }
            continue;
        } else {
            addReplyErrorObject(c,shared.syntaxerr);
            zfree(ops);
            return;
        }

        
        if (getBitfieldTypeFromArgument(c,c->argv[j+1],&sign,&bits) != C_OK) {
            zfree(ops);
            return;
        }

        if (getBitOffsetFromArgument(c,c->argv[j+2],&bitoffset,1,bits) != C_OK){
            zfree(ops);
            return;
        }

        if (opcode != BITFIELDOP_GET) {
            readonly = 0;
            if (highest_write_offset < bitoffset + bits - 1)
                highest_write_offset = bitoffset + bits - 1;
            
            if (getLongLongFromObjectOrReply(c,c->argv[j+3],&i64,NULL) != C_OK){
                zfree(ops);
                return;
            }
        }

        
        ops = zrealloc(ops,sizeof(*ops)*(numops+1));
        ops[numops].offset = bitoffset;
        ops[numops].i64 = i64;
        ops[numops].opcode = opcode;
        ops[numops].owtype = owtype;
        ops[numops].bits = bits;
        ops[numops].sign = sign;
        numops++;

        j += 3 - (opcode == BITFIELDOP_GET);
    }

    if (readonly) {
        
        o = lookupKeyRead(c->db,c->argv[1]);
        if (o != NULL && checkType(c,o,OBJ_STRING)) {
            zfree(ops);
            return;
        }
    } else {
        if (flags & BITFIELD_FLAG_READONLY) {
            zfree(ops);
            addReplyError(c, "BITFIELD_RO only supports the GET subcommand");
            return;
        }

        
        if ((o = lookupStringForBitCommand(c, highest_write_offset)) == NULL) {
            zfree(ops);
            return;
        }
    }

    addReplyArrayLen(c,numops);

    
    for (j = 0; j < numops; j++) {
        struct bitfieldOp *thisop = ops+j;

        
        if (thisop->opcode == BITFIELDOP_SET || thisop->opcode == BITFIELDOP_INCRBY)
        {
            

            
            if (thisop->sign) {
                int64_t oldval, newval, wrapped, retval;
                int overflow;

                oldval = getSignedBitfield(o->ptr,thisop->offset, thisop->bits);

                if (thisop->opcode == BITFIELDOP_INCRBY) {
                    newval = oldval + thisop->i64;
                    overflow = checkSignedBitfieldOverflow(oldval, thisop->i64,thisop->bits,thisop->owtype,&wrapped);
                    if (overflow) newval = wrapped;
                    retval = newval;
                } else {
                    newval = thisop->i64;
                    overflow = checkSignedBitfieldOverflow(newval, 0,thisop->bits,thisop->owtype,&wrapped);
                    if (overflow) newval = wrapped;
                    retval = oldval;
                }

                
                if (!(overflow && thisop->owtype == BFOVERFLOW_FAIL)) {
                    addReplyLongLong(c,retval);
                    setSignedBitfield(o->ptr,thisop->offset, thisop->bits,newval);
                } else {
                    addReplyNull(c);
                }
            } else {
                uint64_t oldval, newval, wrapped, retval;
                int overflow;

                oldval = getUnsignedBitfield(o->ptr,thisop->offset, thisop->bits);

                if (thisop->opcode == BITFIELDOP_INCRBY) {
                    newval = oldval + thisop->i64;
                    overflow = checkUnsignedBitfieldOverflow(oldval, thisop->i64,thisop->bits,thisop->owtype,&wrapped);
                    if (overflow) newval = wrapped;
                    retval = newval;
                } else {
                    newval = thisop->i64;
                    overflow = checkUnsignedBitfieldOverflow(newval, 0,thisop->bits,thisop->owtype,&wrapped);
                    if (overflow) newval = wrapped;
                    retval = oldval;
                }
                
                if (!(overflow && thisop->owtype == BFOVERFLOW_FAIL)) {
                    addReplyLongLong(c,retval);
                    setUnsignedBitfield(o->ptr,thisop->offset, thisop->bits,newval);
                } else {
                    addReplyNull(c);
                }
            }
            changes++;
        } else {
            
            unsigned char buf[9];
            long strlen = 0;
            unsigned char *src = NULL;
            char llbuf[LONG_STR_SIZE];

            if (o != NULL)
                src = getObjectReadOnlyString(o,&strlen,llbuf);

            
            memset(buf,0,9);
            int i;
            size_t byte = thisop->offset >> 3;
            for (i = 0; i < 9; i++) {
                if (src == NULL || i+byte >= (size_t)strlen) break;
                buf[i] = src[i+byte];
            }

            
            if (thisop->sign) {
                int64_t val = getSignedBitfield(buf,thisop->offset-(byte*8), thisop->bits);
                addReplyLongLong(c,val);
            } else {
                uint64_t val = getUnsignedBitfield(buf,thisop->offset-(byte*8), thisop->bits);
                addReplyLongLong(c,val);
            }
        }
    }

    if (changes) {
        signalModifiedKey(c,c->db,c->argv[1]);
        notifyKeyspaceEvent(NOTIFY_STRING,"setbit",c->argv[1],c->db->id);
        server.dirty += changes;
    }
    zfree(ops);
}

void bitfieldCommand(client *c) {
    bitfieldGeneric(c, BITFIELD_FLAG_NONE);
}

void bitfieldroCommand(client *c) {
    bitfieldGeneric(c, BITFIELD_FLAG_READONLY);
}
