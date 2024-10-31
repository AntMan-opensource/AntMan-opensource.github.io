












void streamFreeCG(streamCG *cg);
void streamFreeNACK(streamNACK *na);
size_t streamReplyWithRangeFromConsumerPEL(client *c, stream *s, streamID *start, streamID *end, size_t count, streamConsumer *consumer);




stream *streamNew(void) {
    stream *s = zmalloc(sizeof(*s));
    s->rax = raxNew();
    s->length = 0;
    s->last_id.ms = 0;
    s->last_id.seq = 0;
    s->cgroups = NULL; 
    return s;
}


void freeStream(stream *s) {
    raxFreeWithCallback(s->rax,(void(*)(void*))lpFree);
    if (s->cgroups)
        raxFreeWithCallback(s->cgroups,(void(*)(void*))streamFreeCG);
    zfree(s);
}


unsigned long streamLength(const robj *subject) {
    stream *s = subject->ptr;
    return s->length;
}


void streamIncrID(streamID *id) {
    if (id->seq == UINT64_MAX) {
        if (id->ms == UINT64_MAX) {
            
            id->ms = id->seq = 0;
        } else {
            id->ms++;
            id->seq = 0;
        }
    } else {
        id->seq++;
    }
}


void streamNextID(streamID *last_id, streamID *new_id) {
    uint64_t ms = mstime();
    if (ms > last_id->ms) {
        new_id->ms = ms;
        new_id->seq = 0;
    } else {
        *new_id = *last_id;
        streamIncrID(new_id);
    }
}


unsigned char *lpAppendInteger(unsigned char *lp, int64_t value) {
    char buf[LONG_STR_SIZE];
    int slen = ll2string(buf,sizeof(buf),value);
    return lpAppend(lp,(unsigned char*)buf,slen);
}


unsigned char *lpReplaceInteger(unsigned char *lp, unsigned char **pos, int64_t value) {
    char buf[LONG_STR_SIZE];
    int slen = ll2string(buf,sizeof(buf),value);
    return lpInsert(lp, (unsigned char*)buf, slen, *pos, LP_REPLACE, pos);
}


int64_t lpGetInteger(unsigned char *ele) {
    int64_t v;
    unsigned char *e = lpGet(ele,&v,NULL);
    if (e == NULL) return v;
    
    long long ll;
    int retval = string2ll((char*)e,v,&ll);
    serverAssert(retval != 0);
    v = ll;
    return v;
}


void streamLogListpackContent(unsigned char *lp) {
    unsigned char *p = lpFirst(lp);
    while(p) {
        unsigned char buf[LP_INTBUF_SIZE];
        int64_t v;
        unsigned char *ele = lpGet(p,&v,buf);
        serverLog(LL_WARNING,"- [%d] '%.*s'", (int)v, (int)v, ele);
        p = lpNext(lp,p);
    }
}


void streamEncodeID(void *buf, streamID *id) {
    uint64_t e[2];
    e[0] = htonu64(id->ms);
    e[1] = htonu64(id->seq);
    memcpy(buf,e,sizeof(e));
}


void streamDecodeID(void *buf, streamID *id) {
    uint64_t e[2];
    memcpy(e,buf,sizeof(e));
    id->ms = ntohu64(e[0]);
    id->seq = ntohu64(e[1]);
}


int streamCompareID(streamID *a, streamID *b) {
    if (a->ms > b->ms) return 1;
    else if (a->ms < b->ms) return -1;
    
    else if (a->seq > b->seq) return 1;
    else if (a->seq < b->seq) return -1;
    
    return 0;
}


int streamAppendItem(stream *s, robj **argv, int64_t numfields, streamID *added_id, streamID *use_id) {
    
    
    streamID id;
    if (use_id)
        id = *use_id;
    else streamNextID(&s->last_id,&id);

    
    if (streamCompareID(&id,&s->last_id) <= 0) return C_ERR;

    
    raxIterator ri;
    raxStart(&ri,s->rax);
    raxSeek(&ri,"$",NULL,0);

    size_t lp_bytes = 0;        
    unsigned char *lp = NULL;   

    
    if (raxNext(&ri)) {
        lp = ri.data;
        lp_bytes = lpBytes(lp);
    }
    raxStop(&ri);

    
    uint64_t rax_key[2];    
    streamID master_id;     

    

    
    if (lp != NULL) {
        if (server.stream_node_max_bytes && lp_bytes >= server.stream_node_max_bytes)
        {
            lp = NULL;
        } else if (server.stream_node_max_entries) {
            int64_t count = lpGetInteger(lpFirst(lp));
            if (count >= server.stream_node_max_entries) lp = NULL;
        }
    }

    int flags = STREAM_ITEM_FLAG_NONE;
    if (lp == NULL || lp_bytes >= server.stream_node_max_bytes) {
        master_id = id;
        streamEncodeID(rax_key,&id);
        
        lp = lpNew();
        lp = lpAppendInteger(lp,1); 
        lp = lpAppendInteger(lp,0); 
        lp = lpAppendInteger(lp,numfields);
        for (int64_t i = 0; i < numfields; i++) {
            sds field = argv[i*2]->ptr;
            lp = lpAppend(lp,(unsigned char*)field,sdslen(field));
        }
        lp = lpAppendInteger(lp,0); 
        raxInsert(s->rax,(unsigned char*)&rax_key,sizeof(rax_key),lp,NULL);
        
        flags |= STREAM_ITEM_FLAG_SAMEFIELDS;
    } else {
        serverAssert(ri.key_len == sizeof(rax_key));
        memcpy(rax_key,ri.key,sizeof(rax_key));

        
        streamDecodeID(rax_key,&master_id);
        unsigned char *lp_ele = lpFirst(lp);

        
        int64_t count = lpGetInteger(lp_ele);
        lp = lpReplaceInteger(lp,&lp_ele,count+1);
        lp_ele = lpNext(lp,lp_ele); 
        lp_ele = lpNext(lp,lp_ele); 

        
        int64_t master_fields_count = lpGetInteger(lp_ele);
        lp_ele = lpNext(lp,lp_ele);
        if (numfields == master_fields_count) {
            int64_t i;
            for (i = 0; i < master_fields_count; i++) {
                sds field = argv[i*2]->ptr;
                int64_t e_len;
                unsigned char buf[LP_INTBUF_SIZE];
                unsigned char *e = lpGet(lp_ele,&e_len,buf);
                
                if (sdslen(field) != (size_t)e_len || memcmp(e,field,e_len) != 0) break;
                lp_ele = lpNext(lp,lp_ele);
            }
            
            if (i == master_fields_count) flags |= STREAM_ITEM_FLAG_SAMEFIELDS;
        }
    }

    
    lp = lpAppendInteger(lp,flags);
    lp = lpAppendInteger(lp,id.ms - master_id.ms);
    lp = lpAppendInteger(lp,id.seq - master_id.seq);
    if (!(flags & STREAM_ITEM_FLAG_SAMEFIELDS))
        lp = lpAppendInteger(lp,numfields);
    for (int64_t i = 0; i < numfields; i++) {
        sds field = argv[i*2]->ptr, value = argv[i*2+1]->ptr;
        if (!(flags & STREAM_ITEM_FLAG_SAMEFIELDS))
            lp = lpAppend(lp,(unsigned char*)field,sdslen(field));
        lp = lpAppend(lp,(unsigned char*)value,sdslen(value));
    }
    
    int64_t lp_count = numfields;
    lp_count += 3; 
    if (!(flags & STREAM_ITEM_FLAG_SAMEFIELDS)) {
        
        lp_count += numfields+1;
    }
    lp = lpAppendInteger(lp,lp_count);

    
    if (ri.data != lp)
        raxInsert(s->rax,(unsigned char*)&rax_key,sizeof(rax_key),lp,NULL);
    s->length++;
    s->last_id = id;
    if (added_id) *added_id = id;
    return C_OK;
}


int64_t streamTrimByLength(stream *s, size_t maxlen, int approx) {
    if (s->length <= maxlen) return 0;

    raxIterator ri;
    raxStart(&ri,s->rax);
    raxSeek(&ri,"^",NULL,0);

    int64_t deleted = 0;
    while(s->length > maxlen && raxNext(&ri)) {
        unsigned char *lp = ri.data, *p = lpFirst(lp);
        int64_t entries = lpGetInteger(p);

        
        if (s->length - entries >= maxlen) {
            lpFree(lp);
            raxRemove(s->rax,ri.key,ri.key_len,NULL);
            raxSeek(&ri,">=",ri.key,ri.key_len);
            s->length -= entries;
            deleted += entries;
            continue;
        }

        
        if (approx) break;

        
        int64_t to_delete = s->length - maxlen;
        serverAssert(to_delete < entries);
        lp = lpReplaceInteger(lp,&p,entries-to_delete);
        p = lpNext(lp,p); 
        int64_t marked_deleted = lpGetInteger(p);
        lp = lpReplaceInteger(lp,&p,marked_deleted+to_delete);
        p = lpNext(lp,p); 

        
        int64_t master_fields_count = lpGetInteger(p);
        p = lpNext(lp,p); 
        for (int64_t j = 0; j < master_fields_count; j++)
            p = lpNext(lp,p); 
        p = lpNext(lp,p); 

        
        while(p) {
            int flags = lpGetInteger(p);
            int to_skip;

            
            if (!(flags & STREAM_ITEM_FLAG_DELETED)) {
                flags |= STREAM_ITEM_FLAG_DELETED;
                lp = lpReplaceInteger(lp,&p,flags);
                deleted++;
                s->length--;
                if (s->length <= maxlen) break; 
            }

            p = lpNext(lp,p); 
            p = lpNext(lp,p); 
            p = lpNext(lp,p); 
            if (flags & STREAM_ITEM_FLAG_SAMEFIELDS) {
                to_skip = master_fields_count;
            } else {
                to_skip = lpGetInteger(p);
                to_skip = 1+(to_skip*2);
            }

            while(to_skip--) p = lpNext(lp,p); 
            p = lpNext(lp,p); 
        }

        
        entries -= to_delete;
        marked_deleted += to_delete;
        if (entries + marked_deleted > 10 && marked_deleted > entries/2) {
            
        }

        
        raxInsert(s->rax,ri.key,ri.key_len,lp,NULL);

        break; 
    }

    raxStop(&ri);
    return deleted;
}


void streamIteratorStart(streamIterator *si, stream *s, streamID *start, streamID *end, int rev) {
    
    if (start) {
        streamEncodeID(si->start_key,start);
    } else {
        si->start_key[0] = 0;
        si->start_key[1] = 0;
    }

    if (end) {
        streamEncodeID(si->end_key,end);
    } else {
        si->end_key[0] = UINT64_MAX;
        si->end_key[1] = UINT64_MAX;
    }

    
    raxStart(&si->ri,s->rax);
    if (!rev) {
        if (start && (start->ms || start->seq)) {
            raxSeek(&si->ri,"<=",(unsigned char*)si->start_key, sizeof(si->start_key));
            if (raxEOF(&si->ri)) raxSeek(&si->ri,"^",NULL,0);
        } else {
            raxSeek(&si->ri,"^",NULL,0);
        }
    } else {
        if (end && (end->ms || end->seq)) {
            raxSeek(&si->ri,"<=",(unsigned char*)si->end_key, sizeof(si->end_key));
            if (raxEOF(&si->ri)) raxSeek(&si->ri,"$",NULL,0);
        } else {
            raxSeek(&si->ri,"$",NULL,0);
        }
    }
    si->stream = s;
    si->lp = NULL; 
    si->lp_ele = NULL; 
    si->rev = rev;  
}


int streamIteratorGetID(streamIterator *si, streamID *id, int64_t *numfields) {
    while(1) { 
        
        if (si->lp == NULL || si->lp_ele == NULL) {
            if (!si->rev && !raxNext(&si->ri)) return 0;
            else if (si->rev && !raxPrev(&si->ri)) return 0;
            serverAssert(si->ri.key_len == sizeof(streamID));
            
            streamDecodeID(si->ri.key,&si->master_id);
            
            si->lp = si->ri.data;
            si->lp_ele = lpFirst(si->lp);           
            si->lp_ele = lpNext(si->lp,si->lp_ele); 
            si->lp_ele = lpNext(si->lp,si->lp_ele); 
            si->master_fields_count = lpGetInteger(si->lp_ele);
            si->lp_ele = lpNext(si->lp,si->lp_ele); 
            si->master_fields_start = si->lp_ele;
            
            if (!si->rev) {
                
                for (uint64_t i = 0; i < si->master_fields_count; i++)
                    si->lp_ele = lpNext(si->lp,si->lp_ele);
            } else {
                
                si->lp_ele = lpLast(si->lp);
            }
        } else if (si->rev) {
            
            int lp_count = lpGetInteger(si->lp_ele);
            while(lp_count--) si->lp_ele = lpPrev(si->lp,si->lp_ele);
            
            si->lp_ele = lpPrev(si->lp,si->lp_ele);
        }

        
        while(1) {
            if (!si->rev) {
                
                si->lp_ele = lpNext(si->lp,si->lp_ele);
                if (si->lp_ele == NULL) break;
            } else {
                
                int64_t lp_count = lpGetInteger(si->lp_ele);
                if (lp_count == 0) { 
                    si->lp = NULL;
                    si->lp_ele = NULL;
                    break;
                }
                while(lp_count--) si->lp_ele = lpPrev(si->lp,si->lp_ele);
            }

            
            si->lp_flags = si->lp_ele;
            int flags = lpGetInteger(si->lp_ele);
            si->lp_ele = lpNext(si->lp,si->lp_ele); 

            
            *id = si->master_id;
            id->ms += lpGetInteger(si->lp_ele);
            si->lp_ele = lpNext(si->lp,si->lp_ele);
            id->seq += lpGetInteger(si->lp_ele);
            si->lp_ele = lpNext(si->lp,si->lp_ele);
            unsigned char buf[sizeof(streamID)];
            streamEncodeID(buf,id);

            
            if (flags & STREAM_ITEM_FLAG_SAMEFIELDS) {
                *numfields = si->master_fields_count;
            } else {
                *numfields = lpGetInteger(si->lp_ele);
                si->lp_ele = lpNext(si->lp,si->lp_ele);
            }

            
            if (!si->rev) {
                if (memcmp(buf,si->start_key,sizeof(streamID)) >= 0 && !(flags & STREAM_ITEM_FLAG_DELETED))
                {
                    if (memcmp(buf,si->end_key,sizeof(streamID)) > 0)
                        return 0; 
                    si->entry_flags = flags;
                    if (flags & STREAM_ITEM_FLAG_SAMEFIELDS)
                        si->master_fields_ptr = si->master_fields_start;
                    return 1; 
                }
            } else {
                if (memcmp(buf,si->end_key,sizeof(streamID)) <= 0 && !(flags & STREAM_ITEM_FLAG_DELETED))
                {
                    if (memcmp(buf,si->start_key,sizeof(streamID)) < 0)
                        return 0; 
                    si->entry_flags = flags;
                    if (flags & STREAM_ITEM_FLAG_SAMEFIELDS)
                        si->master_fields_ptr = si->master_fields_start;
                    return 1; 
                }
            }

            
            if (!si->rev) {
                int64_t to_discard = (flags & STREAM_ITEM_FLAG_SAMEFIELDS) ? *numfields : *numfields*2;
                for (int64_t i = 0; i < to_discard; i++)
                    si->lp_ele = lpNext(si->lp,si->lp_ele);
            } else {
                int64_t prev_times = 4; 
                
                if (!(flags & STREAM_ITEM_FLAG_SAMEFIELDS)) prev_times++;
                while(prev_times--) si->lp_ele = lpPrev(si->lp,si->lp_ele);
            }
        }

        
    }
}


void streamIteratorGetField(streamIterator *si, unsigned char **fieldptr, unsigned char **valueptr, int64_t *fieldlen, int64_t *valuelen) {
    if (si->entry_flags & STREAM_ITEM_FLAG_SAMEFIELDS) {
        *fieldptr = lpGet(si->master_fields_ptr,fieldlen,si->field_buf);
        si->master_fields_ptr = lpNext(si->lp,si->master_fields_ptr);
    } else {
        *fieldptr = lpGet(si->lp_ele,fieldlen,si->field_buf);
        si->lp_ele = lpNext(si->lp,si->lp_ele);
    }
    *valueptr = lpGet(si->lp_ele,valuelen,si->value_buf);
    si->lp_ele = lpNext(si->lp,si->lp_ele);
}


void streamIteratorRemoveEntry(streamIterator *si, streamID *current) {
    unsigned char *lp = si->lp;
    int64_t aux;

    
    int flags = lpGetInteger(si->lp_flags);
    flags |= STREAM_ITEM_FLAG_DELETED;
    lp = lpReplaceInteger(lp,&si->lp_flags,flags);

    
    unsigned char *p = lpFirst(lp);
    aux = lpGetInteger(p);

    if (aux == 1) {
        
        lpFree(lp);
        raxRemove(si->stream->rax,si->ri.key,si->ri.key_len,NULL);
    } else {
        
        lp = lpReplaceInteger(lp,&p,aux-1);
        p = lpNext(lp,p); 
        aux = lpGetInteger(p);
        lp = lpReplaceInteger(lp,&p,aux+1);

        
        if (si->lp != lp)
            raxInsert(si->stream->rax,si->ri.key,si->ri.key_len,lp,NULL);
    }

    
    si->stream->length--;

    
    streamID start, end;
    if (si->rev) {
        streamDecodeID(si->start_key,&start);
        end = *current;
    } else {
        start = *current;
        streamDecodeID(si->end_key,&end);
    }
    streamIteratorStop(si);
    streamIteratorStart(si,si->stream,&start,&end,si->rev);

    
}


void streamIteratorStop(streamIterator *si) {
    raxStop(&si->ri);
}


int streamDeleteItem(stream *s, streamID *id) {
    int deleted = 0;
    streamIterator si;
    streamIteratorStart(&si,s,id,id,0);
    streamID myid;
    int64_t numfields;
    if (streamIteratorGetID(&si,&myid,&numfields)) {
        streamIteratorRemoveEntry(&si,&myid);
        deleted = 1;
    }
    streamIteratorStop(&si);
    return deleted;
}


void streamLastValidID(stream *s, streamID *maxid)
{
    streamIterator si;
    streamIteratorStart(&si,s,NULL,NULL,1);
    int64_t numfields;
    streamIteratorGetID(&si,maxid,&numfields);
    streamIteratorStop(&si);
}


void addReplyStreamID(client *c, streamID *id) {
    sds replyid = sdscatfmt(sdsempty(),"%U-%U",id->ms,id->seq);
    addReplyBulkSds(c,replyid);
}


robj *createObjectFromStreamID(streamID *id) {
    return createObject(OBJ_STRING, sdscatfmt(sdsempty(),"%U-%U", id->ms,id->seq));
}


void streamPropagateXCLAIM(client *c, robj *key, streamCG *group, robj *groupname, robj *id, streamNACK *nack) {
    
    robj *argv[14];
    argv[0] = createStringObject("XCLAIM",6);
    argv[1] = key;
    argv[2] = groupname;
    argv[3] = createStringObject(nack->consumer->name,sdslen(nack->consumer->name));
    argv[4] = createStringObjectFromLongLong(0);
    argv[5] = id;
    argv[6] = createStringObject("TIME",4);
    argv[7] = createStringObjectFromLongLong(nack->delivery_time);
    argv[8] = createStringObject("RETRYCOUNT",10);
    argv[9] = createStringObjectFromLongLong(nack->delivery_count);
    argv[10] = createStringObject("FORCE",5);
    argv[11] = createStringObject("JUSTID",6);
    argv[12] = createStringObject("LASTID",6);
    argv[13] = createObjectFromStreamID(&group->last_id);

    
    propagate(server.xclaimCommand,c->db->id,argv,14,PROPAGATE_AOF|PROPAGATE_REPL);
    decrRefCount(argv[0]);
    decrRefCount(argv[3]);
    decrRefCount(argv[4]);
    decrRefCount(argv[6]);
    decrRefCount(argv[7]);
    decrRefCount(argv[8]);
    decrRefCount(argv[9]);
    decrRefCount(argv[10]);
    decrRefCount(argv[11]);
    decrRefCount(argv[12]);
    decrRefCount(argv[13]);
}


void streamPropagateGroupID(client *c, robj *key, streamCG *group, robj *groupname) {
    robj *argv[5];
    argv[0] = createStringObject("XGROUP",6);
    argv[1] = createStringObject("SETID",5);
    argv[2] = key;
    argv[3] = groupname;
    argv[4] = createObjectFromStreamID(&group->last_id);

    
    propagate(server.xgroupCommand,c->db->id,argv,5,PROPAGATE_AOF|PROPAGATE_REPL);
    decrRefCount(argv[0]);
    decrRefCount(argv[1]);
    decrRefCount(argv[4]);
}





size_t streamReplyWithRange(client *c, stream *s, streamID *start, streamID *end, size_t count, int rev, streamCG *group, streamConsumer *consumer, int flags, streamPropInfo *spi) {
    void *arraylen_ptr = NULL;
    size_t arraylen = 0;
    streamIterator si;
    int64_t numfields;
    streamID id;
    int propagate_last_id = 0;
    int noack = flags & STREAM_RWR_NOACK;

    
    if (group && (flags & STREAM_RWR_HISTORY)) {
        return streamReplyWithRangeFromConsumerPEL(c,s,start,end,count, consumer);
    }

    if (!(flags & STREAM_RWR_RAWENTRIES))
        arraylen_ptr = addReplyDeferredLen(c);
    streamIteratorStart(&si,s,start,end,rev);
    while(streamIteratorGetID(&si,&id,&numfields)) {
        
        if (group && streamCompareID(&id,&group->last_id) > 0) {
            group->last_id = id;
            
            if (noack) propagate_last_id = 1;
        }

        
        addReplyArrayLen(c,2);
        addReplyStreamID(c,&id);

        addReplyArrayLen(c,numfields*2);

        
        while(numfields--) {
            unsigned char *key, *value;
            int64_t key_len, value_len;
            streamIteratorGetField(&si,&key,&value,&key_len,&value_len);
            addReplyBulkCBuffer(c,key,key_len);
            addReplyBulkCBuffer(c,value,value_len);
        }

        
        if (group && !noack) {
            unsigned char buf[sizeof(streamID)];
            streamEncodeID(buf,&id);

            
            streamNACK *nack = streamCreateNACK(consumer);
            int group_inserted = raxTryInsert(group->pel,buf,sizeof(buf),nack,NULL);
            int consumer_inserted = raxTryInsert(consumer->pel,buf,sizeof(buf),nack,NULL);

            
            if (group_inserted == 0) {
                streamFreeNACK(nack);
                nack = raxFind(group->pel,buf,sizeof(buf));
                serverAssert(nack != raxNotFound);
                raxRemove(nack->consumer->pel,buf,sizeof(buf),NULL);
                
                nack->consumer = consumer;
                nack->delivery_time = mstime();
                nack->delivery_count = 1;
                
                raxInsert(consumer->pel,buf,sizeof(buf),nack,NULL);
            } else if (group_inserted == 1 && consumer_inserted == 0) {
                serverPanic("NACK half-created. Should not be possible.");
            }

            
            if (spi) {
                robj *idarg = createObjectFromStreamID(&id);
                streamPropagateXCLAIM(c,spi->keyname,group,spi->groupname,idarg,nack);
                decrRefCount(idarg);
            }
        }

        arraylen++;
        if (count && count == arraylen) break;
    }

    if (spi && propagate_last_id)
        streamPropagateGroupID(c,spi->keyname,group,spi->groupname);

    streamIteratorStop(&si);
    if (arraylen_ptr) setDeferredArrayLen(c,arraylen_ptr,arraylen);
    return arraylen;
}


size_t streamReplyWithRangeFromConsumerPEL(client *c, stream *s, streamID *start, streamID *end, size_t count, streamConsumer *consumer) {
    raxIterator ri;
    unsigned char startkey[sizeof(streamID)];
    unsigned char endkey[sizeof(streamID)];
    streamEncodeID(startkey,start);
    if (end) streamEncodeID(endkey,end);

    size_t arraylen = 0;
    void *arraylen_ptr = addReplyDeferredLen(c);
    raxStart(&ri,consumer->pel);
    raxSeek(&ri,">=",startkey,sizeof(startkey));
    while(raxNext(&ri) && (!count || arraylen < count)) {
        if (end && memcmp(ri.key,end,ri.key_len) > 0) break;
        streamID thisid;
        streamDecodeID(ri.key,&thisid);
        if (streamReplyWithRange(c,s,&thisid,&thisid,1,0,NULL,NULL, STREAM_RWR_RAWENTRIES,NULL) == 0)
        {
            
            addReplyArrayLen(c,2);
            addReplyStreamID(c,&thisid);
            addReplyNullArray(c);
        } else {
            streamNACK *nack = ri.data;
            nack->delivery_time = mstime();
            nack->delivery_count++;
        }
        arraylen++;
    }
    raxStop(&ri);
    setDeferredArrayLen(c,arraylen_ptr,arraylen);
    return arraylen;
}




robj *streamTypeLookupWriteOrCreate(client *c, robj *key) {
    robj *o = lookupKeyWrite(c->db,key);
    if (o == NULL) {
        o = createStreamObject();
        dbAdd(c->db,key,o);
    } else {
        if (o->type != OBJ_STREAM) {
            addReply(c,shared.wrongtypeerr);
            return NULL;
        }
    }
    return o;
}


int streamGenericParseIDOrReply(client *c, robj *o, streamID *id, uint64_t missing_seq, int strict) {
    char buf[128];
    if (sdslen(o->ptr) > sizeof(buf)-1) goto invalid;
    memcpy(buf,o->ptr,sdslen(o->ptr)+1);

    if (strict && (buf[0] == '-' || buf[0] == '+') && buf[1] == '\0')
        goto invalid;

    
    if (buf[0] == '-' && buf[1] == '\0') {
        id->ms = 0;
        id->seq = 0;
        return C_OK;
    } else if (buf[0] == '+' && buf[1] == '\0') {
        id->ms = UINT64_MAX;
        id->seq = UINT64_MAX;
        return C_OK;
    }

    
    char *dot = strchr(buf,'-');
    if (dot) *dot = '\0';
    unsigned long long ms, seq;
    if (string2ull(buf,&ms) == 0) goto invalid;
    if (dot && string2ull(dot+1,&seq) == 0) goto invalid;
    if (!dot) seq = missing_seq;
    id->ms = ms;
    id->seq = seq;
    return C_OK;

invalid:
    if (c) addReplyError(c,"Invalid stream ID specified as stream " "command argument");
    return C_ERR;
}


int streamParseIDOrReply(client *c, robj *o, streamID *id, uint64_t missing_seq) {
    return streamGenericParseIDOrReply(c,o,id,missing_seq,0);
}


int streamParseStrictIDOrReply(client *c, robj *o, streamID *id, uint64_t missing_seq) {
    return streamGenericParseIDOrReply(c,o,id,missing_seq,1);
}


void streamRewriteApproxMaxlen(client *c, stream *s, int maxlen_arg_idx) {
    robj *maxlen_obj = createStringObjectFromLongLong(s->length);
    robj *equal_obj = createStringObject("=",1);

    rewriteClientCommandArgument(c,maxlen_arg_idx,maxlen_obj);
    rewriteClientCommandArgument(c,maxlen_arg_idx-1,equal_obj);

    decrRefCount(equal_obj);
    decrRefCount(maxlen_obj);
}


void xaddCommand(client *c) {
    streamID id;
    int id_given = 0; 
    long long maxlen = -1;  
    int approx_maxlen = 0;  
    int maxlen_arg_idx = 0; 

    
    int i = 2; 
    for (; i < c->argc; i++) {
        int moreargs = (c->argc-1) - i; 
        char *opt = c->argv[i]->ptr;
        if (opt[0] == '*' && opt[1] == '\0') {
            
            break;
        } else if (!strcasecmp(opt,"maxlen") && moreargs) {
            approx_maxlen = 0;
            char *next = c->argv[i+1]->ptr;
            
            if (moreargs >= 2 && next[0] == '~' && next[1] == '\0') {
                approx_maxlen = 1;
                i++;
            } else if (moreargs >= 2 && next[0] == '=' && next[1] == '\0') {
                i++;
            }
            if (getLongLongFromObjectOrReply(c,c->argv[i+1],&maxlen,NULL)
                != C_OK) return;

            if (maxlen < 0) {
                addReplyError(c,"The MAXLEN argument must be >= 0.");
                return;
            }
            i++;
            maxlen_arg_idx = i;
        } else {
            
            if (streamParseStrictIDOrReply(c,c->argv[i],&id,0) != C_OK) return;
            id_given = 1;
            break;
        }
    }
    int field_pos = i+1;

    
    if ((c->argc - field_pos) < 2 || ((c->argc-field_pos) % 2) == 1) {
        addReplyError(c,"wrong number of arguments for XADD");
        return;
    }

    
    if (id_given && id.ms == 0 && id.seq == 0) {
        addReplyError(c,"The ID specified in XADD must be greater than 0-0");
        return;
    }

    
    robj *o;
    stream *s;
    if ((o = streamTypeLookupWriteOrCreate(c,c->argv[1])) == NULL) return;
    s = o->ptr;

    
    if (s->last_id.ms == UINT64_MAX && s->last_id.seq == UINT64_MAX) {
        addReplyError(c,"The stream has exhausted the last possible ID, " "unable to add more items");
        return;
    }

    
    if (streamAppendItem(s,c->argv+field_pos,(c->argc-field_pos)/2, &id, id_given ? &id : NULL)
        == C_ERR)
    {
        addReplyError(c,"The ID specified in XADD is equal or smaller than the " "target stream top item");
        return;
    }
    addReplyStreamID(c,&id);

    signalModifiedKey(c,c->db,c->argv[1]);
    notifyKeyspaceEvent(NOTIFY_STREAM,"xadd",c->argv[1],c->db->id);
    server.dirty++;

    if (maxlen >= 0) {
        
        if (streamTrimByLength(s,maxlen,approx_maxlen)) {
            notifyKeyspaceEvent(NOTIFY_STREAM,"xtrim",c->argv[1],c->db->id);
        }
        if (approx_maxlen) streamRewriteApproxMaxlen(c,s,maxlen_arg_idx);
    }

    
    robj *idarg = createObjectFromStreamID(&id);
    rewriteClientCommandArgument(c,i,idarg);
    decrRefCount(idarg);

    
    if (server.blocked_clients_by_type[BLOCKED_STREAM])
        signalKeyAsReady(c->db, c->argv[1]);
}


void xrangeGenericCommand(client *c, int rev) {
    robj *o;
    stream *s;
    streamID startid, endid;
    long long count = -1;
    robj *startarg = rev ? c->argv[3] : c->argv[2];
    robj *endarg = rev ? c->argv[2] : c->argv[3];

    if (streamParseIDOrReply(c,startarg,&startid,0) == C_ERR) return;
    if (streamParseIDOrReply(c,endarg,&endid,UINT64_MAX) == C_ERR) return;

    
    if (c->argc > 4) {
        for (int j = 4; j < c->argc; j++) {
            int additional = c->argc-j-1;
            if (strcasecmp(c->argv[j]->ptr,"COUNT") == 0 && additional >= 1) {
                if (getLongLongFromObjectOrReply(c,c->argv[j+1],&count,NULL)
                    != C_OK) return;
                if (count < 0) count = 0;
                j++; 
            } else {
                addReply(c,shared.syntaxerr);
                return;
            }
        }
    }

    
    if ((o = lookupKeyReadOrReply(c,c->argv[1],shared.emptyarray)) == NULL || checkType(c,o,OBJ_STREAM)) return;

    s = o->ptr;

    if (count == 0) {
        addReplyNullArray(c);
    } else {
        if (count == -1) count = 0;
        streamReplyWithRange(c,s,&startid,&endid,count,rev,NULL,NULL,0,NULL);
    }
}


void xrangeCommand(client *c) {
    xrangeGenericCommand(c,0);
}


void xrevrangeCommand(client *c) {
    xrangeGenericCommand(c,1);
}


void xlenCommand(client *c) {
    robj *o;
    if ((o = lookupKeyReadOrReply(c,c->argv[1],shared.czero)) == NULL || checkType(c,o,OBJ_STREAM)) return;
    stream *s = o->ptr;
    addReplyLongLong(c,s->length);
}



void xreadCommand(client *c) {
    long long timeout = -1; 
    long long count = 0;
    int streams_count = 0;
    int streams_arg = 0;
    int noack = 0;          
    #define STREAMID_STATIC_VECTOR_LEN 8
    streamID static_ids[STREAMID_STATIC_VECTOR_LEN];
    streamID *ids = static_ids;
    streamCG **groups = NULL;
    int xreadgroup = sdslen(c->argv[0]->ptr) == 10; 
    robj *groupname = NULL;
    robj *consumername = NULL;

    
    for (int i = 1; i < c->argc; i++) {
        int moreargs = c->argc-i-1;
        char *o = c->argv[i]->ptr;
        if (!strcasecmp(o,"BLOCK") && moreargs) {
            if (c->flags & CLIENT_LUA) {
                
                addReplyErrorFormat(c, "%s command is not allowed with BLOCK option from scripts", (char *)c->argv[0]->ptr);
                return;
            }
            i++;
            if (getTimeoutFromObjectOrReply(c,c->argv[i],&timeout, UNIT_MILLISECONDS) != C_OK) return;
        } else if (!strcasecmp(o,"COUNT") && moreargs) {
            i++;
            if (getLongLongFromObjectOrReply(c,c->argv[i],&count,NULL) != C_OK)
                return;
            if (count < 0) count = 0;
        } else if (!strcasecmp(o,"STREAMS") && moreargs) {
            streams_arg = i+1;
            streams_count = (c->argc-streams_arg);
            if ((streams_count % 2) != 0) {
                addReplyError(c,"Unbalanced XREAD list of streams: " "for each stream key an ID or '$' must be " "specified.");

                return;
            }
            streams_count /= 2; 
            break;
        } else if (!strcasecmp(o,"GROUP") && moreargs >= 2) {
            if (!xreadgroup) {
                addReplyError(c,"The GROUP option is only supported by " "XREADGROUP. You called XREAD instead.");
                return;
            }
            groupname = c->argv[i+1];
            consumername = c->argv[i+2];
            i += 2;
        } else if (!strcasecmp(o,"NOACK")) {
            if (!xreadgroup) {
                addReplyError(c,"The NOACK option is only supported by " "XREADGROUP. You called XREAD instead.");
                return;
            }
            noack = 1;
        } else {
            addReply(c,shared.syntaxerr);
            return;
        }
    }

    
    if (streams_arg == 0) {
        addReply(c,shared.syntaxerr);
        return;
    }

    
    if (xreadgroup && groupname == NULL) {
        addReplyError(c,"Missing GROUP option for XREADGROUP");
        return;
    }

    
    if (streams_count > STREAMID_STATIC_VECTOR_LEN)
        ids = zmalloc(sizeof(streamID)*streams_count);
    if (groupname) groups = zmalloc(sizeof(streamCG*)*streams_count);

    for (int i = streams_arg + streams_count; i < c->argc; i++) {
        
        int id_idx = i - streams_arg - streams_count;
        robj *key = c->argv[i-streams_count];
        robj *o = lookupKeyRead(c->db,key);
        if (o && checkType(c,o,OBJ_STREAM)) goto cleanup;
        streamCG *group = NULL;

        
        if (groupname) {
            if (o == NULL || (group = streamLookupCG(o->ptr,groupname->ptr)) == NULL)
            {
                addReplyErrorFormat(c, "-NOGROUP No such key '%s' or consumer " "group '%s' in XREADGROUP with GROUP " "option", (char*)key->ptr,(char*)groupname->ptr);


                goto cleanup;
            }
            groups[id_idx] = group;
        }

        if (strcmp(c->argv[i]->ptr,"$") == 0) {
            if (xreadgroup) {
                addReplyError(c,"The $ ID is meaningless in the context of " "XREADGROUP: you want to read the history of " "this consumer by specifying a proper ID, or " "use the > ID to get new messages. The $ ID would " "just return an empty result set.");



                goto cleanup;
            }
            if (o) {
                stream *s = o->ptr;
                ids[id_idx] = s->last_id;
            } else {
                ids[id_idx].ms = 0;
                ids[id_idx].seq = 0;
            }
            continue;
        } else if (strcmp(c->argv[i]->ptr,">") == 0) {
            if (!xreadgroup) {
                addReplyError(c,"The > ID can be specified only when calling " "XREADGROUP using the GROUP <group> " "<consumer> option.");

                goto cleanup;
            }
            
            ids[id_idx].ms = UINT64_MAX;
            ids[id_idx].seq = UINT64_MAX;
            continue;
        }
        if (streamParseStrictIDOrReply(c,c->argv[i],ids+id_idx,0) != C_OK)
            goto cleanup;
    }

    
    size_t arraylen = 0;
    void *arraylen_ptr = NULL;
    for (int i = 0; i < streams_count; i++) {
        robj *o = lookupKeyRead(c->db,c->argv[streams_arg+i]);
        if (o == NULL) continue;
        stream *s = o->ptr;
        streamID *gt = ids+i; 
        int serve_synchronously = 0;
        int serve_history = 0; 

        
        if (groups) {
            
            if (gt->ms != UINT64_MAX || gt->seq != UINT64_MAX)
            {
                serve_synchronously = 1;
                serve_history = 1;
            } else if (s->length) {
                
                streamID maxid, *last = &groups[i]->last_id;
                streamLastValidID(s, &maxid);
                if (streamCompareID(&maxid, last) > 0) {
                    serve_synchronously = 1;
                    *gt = *last;
                }
            }
        } else if (s->length) {
            
            streamID maxid;
            streamLastValidID(s, &maxid);
            if (streamCompareID(&maxid, gt) > 0) {
                serve_synchronously = 1;
            }
        }

        if (serve_synchronously) {
            arraylen++;
            if (arraylen == 1) arraylen_ptr = addReplyDeferredLen(c);
            
            streamID start = *gt;
            streamIncrID(&start);

            
            if (c->resp == 2) addReplyArrayLen(c,2);
            addReplyBulk(c,c->argv[streams_arg+i]);
            streamConsumer *consumer = NULL;
            if (groups) consumer = streamLookupConsumer(groups[i], consumername->ptr, SLC_NONE);

            streamPropInfo spi = {c->argv[i+streams_arg],groupname};
            int flags = 0;
            if (noack) flags |= STREAM_RWR_NOACK;
            if (serve_history) flags |= STREAM_RWR_HISTORY;
            streamReplyWithRange(c,s,&start,NULL,count,0, groups ? groups[i] : NULL, consumer, flags, &spi);

            if (groups) server.dirty++;
        }
    }

     
    if (arraylen) {
        if (c->resp == 2)
            setDeferredArrayLen(c,arraylen_ptr,arraylen);
        else setDeferredMapLen(c,arraylen_ptr,arraylen);
        goto cleanup;
    }

    
    if (timeout != -1) {
        
        if (c->flags & CLIENT_MULTI) {
            addReplyNullArray(c);
            goto cleanup;
        }
        blockForKeys(c, BLOCKED_STREAM, c->argv+streams_arg, streams_count, timeout, NULL, ids);
        
        c->bpop.xread_count = count ? count : XREAD_BLOCKED_DEFAULT_COUNT;

        
        if (groupname) {
            incrRefCount(groupname);
            incrRefCount(consumername);
            c->bpop.xread_group = groupname;
            c->bpop.xread_consumer = consumername;
            c->bpop.xread_group_noack = noack;
        } else {
            c->bpop.xread_group = NULL;
            c->bpop.xread_consumer = NULL;
        }
        goto cleanup;
    }

    
    addReplyNullArray(c);
    

cleanup: 

    
    preventCommandPropagation(c);
    if (ids != static_ids) zfree(ids);
    zfree(groups);
}




streamNACK *streamCreateNACK(streamConsumer *consumer) {
    streamNACK *nack = zmalloc(sizeof(*nack));
    nack->delivery_time = mstime();
    nack->delivery_count = 1;
    nack->consumer = consumer;
    return nack;
}


void streamFreeNACK(streamNACK *na) {
    zfree(na);
}


void streamFreeConsumer(streamConsumer *sc) {
    raxFree(sc->pel); 
    sdsfree(sc->name);
    zfree(sc);
}


streamCG *streamCreateCG(stream *s, char *name, size_t namelen, streamID *id) {
    if (s->cgroups == NULL) s->cgroups = raxNew();
    if (raxFind(s->cgroups,(unsigned char*)name,namelen) != raxNotFound)
        return NULL;

    streamCG *cg = zmalloc(sizeof(*cg));
    cg->pel = raxNew();
    cg->consumers = raxNew();
    cg->last_id = *id;
    raxInsert(s->cgroups,(unsigned char*)name,namelen,cg,NULL);
    return cg;
}


void streamFreeCG(streamCG *cg) {
    raxFreeWithCallback(cg->pel,(void(*)(void*))streamFreeNACK);
    raxFreeWithCallback(cg->consumers,(void(*)(void*))streamFreeConsumer);
    zfree(cg);
}


streamCG *streamLookupCG(stream *s, sds groupname) {
    if (s->cgroups == NULL) return NULL;
    streamCG *cg = raxFind(s->cgroups,(unsigned char*)groupname, sdslen(groupname));
    return (cg == raxNotFound) ? NULL : cg;
}


streamConsumer *streamLookupConsumer(streamCG *cg, sds name, int flags) {
    int create = !(flags & SLC_NOCREAT);
    int refresh = !(flags & SLC_NOREFRESH);
    streamConsumer *consumer = raxFind(cg->consumers,(unsigned char*)name, sdslen(name));
    if (consumer == raxNotFound) {
        if (!create) return NULL;
        consumer = zmalloc(sizeof(*consumer));
        consumer->name = sdsdup(name);
        consumer->pel = raxNew();
        raxInsert(cg->consumers,(unsigned char*)name,sdslen(name), consumer,NULL);
    }
    if (refresh) consumer->seen_time = mstime();
    return consumer;
}


uint64_t streamDelConsumer(streamCG *cg, sds name) {
    streamConsumer *consumer = streamLookupConsumer(cg,name,SLC_NOCREAT|SLC_NOREFRESH);
    if (consumer == NULL) return 0;

    uint64_t retval = raxSize(consumer->pel);

    
    raxIterator ri;
    raxStart(&ri,consumer->pel);
    raxSeek(&ri,"^",NULL,0);
    while(raxNext(&ri)) {
        streamNACK *nack = ri.data;
        raxRemove(cg->pel,ri.key,ri.key_len,NULL);
        streamFreeNACK(nack);
    }
    raxStop(&ri);

    
    raxRemove(cg->consumers,(unsigned char*)name,sdslen(name),NULL);
    streamFreeConsumer(consumer);
    return retval;
}




void xgroupCommand(client *c) {
    const char *help[] = {
"CREATE      <key> <groupname> <id or $> [opt] -- Create a new consumer group.", "            option MKSTREAM: create the empty stream if it does not exist.", "SETID       <key> <groupname> <id or $>  -- Set the current group ID.", "DESTROY     <key> <groupname>            -- Remove the specified group.", "DELCONSUMER <key> <groupname> <consumer> -- Remove the specified consumer.", "HELP                                     -- Prints this help.", NULL };






    stream *s = NULL;
    sds grpname = NULL;
    streamCG *cg = NULL;
    char *opt = c->argv[1]->ptr; 
    int mkstream = 0;
    robj *o;

    
    if (c->argc == 6 && !strcasecmp(opt,"CREATE")) {
        if (strcasecmp(c->argv[5]->ptr,"MKSTREAM")) {
            addReplySubcommandSyntaxError(c);
            return;
        }
        mkstream = 1;
        grpname = c->argv[3]->ptr;
    }

    
    if (c->argc >= 4) {
        o = lookupKeyWrite(c->db,c->argv[2]);
        if (o) {
            if (checkType(c,o,OBJ_STREAM)) return;
            s = o->ptr;
        }
        grpname = c->argv[3]->ptr;
    }

    
    if (c->argc >= 4 && !mkstream) {
        
        if (s == NULL) {
            addReplyError(c, "The XGROUP subcommand requires the key to exist. " "Note that for CREATE you may want to use the MKSTREAM " "option to create an empty stream automatically.");


            return;
        }

        
        if ((cg = streamLookupCG(s,grpname)) == NULL && (!strcasecmp(opt,"SETID") || !strcasecmp(opt,"DELCONSUMER")))

        {
            addReplyErrorFormat(c, "-NOGROUP No such consumer group '%s' " "for key name '%s'", (char*)grpname, (char*)c->argv[2]->ptr);

            return;
        }
    }

    
    if (!strcasecmp(opt,"CREATE") && (c->argc == 5 || c->argc == 6)) {
        streamID id;
        if (!strcmp(c->argv[4]->ptr,"$")) {
            if (s) {
                id = s->last_id;
            } else {
                id.ms = 0;
                id.seq = 0;
            }
        } else if (streamParseStrictIDOrReply(c,c->argv[4],&id,0) != C_OK) {
            return;
        }

        
        if (s == NULL) {
            serverAssert(mkstream);
            o = createStreamObject();
            dbAdd(c->db,c->argv[2],o);
            s = o->ptr;
            signalModifiedKey(c,c->db,c->argv[2]);
        }

        streamCG *cg = streamCreateCG(s,grpname,sdslen(grpname),&id);
        if (cg) {
            addReply(c,shared.ok);
            server.dirty++;
            notifyKeyspaceEvent(NOTIFY_STREAM,"xgroup-create", c->argv[2],c->db->id);
        } else {
            addReplySds(c, sdsnew("-BUSYGROUP Consumer Group name already exists\r\n"));
        }
    } else if (!strcasecmp(opt,"SETID") && c->argc == 5) {
        streamID id;
        if (!strcmp(c->argv[4]->ptr,"$")) {
            id = s->last_id;
        } else if (streamParseIDOrReply(c,c->argv[4],&id,0) != C_OK) {
            return;
        }
        cg->last_id = id;
        addReply(c,shared.ok);
        server.dirty++;
        notifyKeyspaceEvent(NOTIFY_STREAM,"xgroup-setid",c->argv[2],c->db->id);
    } else if (!strcasecmp(opt,"DESTROY") && c->argc == 4) {
        if (cg) {
            raxRemove(s->cgroups,(unsigned char*)grpname,sdslen(grpname),NULL);
            streamFreeCG(cg);
            addReply(c,shared.cone);
            server.dirty++;
            notifyKeyspaceEvent(NOTIFY_STREAM,"xgroup-destroy", c->argv[2],c->db->id);
            
            signalKeyAsReady(c->db,c->argv[2]);
        } else {
            addReply(c,shared.czero);
        }
    } else if (!strcasecmp(opt,"DELCONSUMER") && c->argc == 5) {
        
        long long pending = streamDelConsumer(cg,c->argv[4]->ptr);
        addReplyLongLong(c,pending);
        server.dirty++;
        notifyKeyspaceEvent(NOTIFY_STREAM,"xgroup-delconsumer", c->argv[2],c->db->id);
    } else if (c->argc == 2 && !strcasecmp(opt,"HELP")) {
        addReplyHelp(c, help);
    } else {
        addReplySubcommandSyntaxError(c);
    }
}


void xsetidCommand(client *c) {
    robj *o = lookupKeyWriteOrReply(c,c->argv[1],shared.nokeyerr);
    if (o == NULL || checkType(c,o,OBJ_STREAM)) return;

    stream *s = o->ptr;
    streamID id;
    if (streamParseStrictIDOrReply(c,c->argv[2],&id,0) != C_OK) return;

    
    if (s->length > 0) {
        streamID maxid;
        streamLastValidID(s,&maxid);

        if (streamCompareID(&id,&maxid) < 0) {
            addReplyError(c,"The ID specified in XSETID is smaller than the " "target stream top item");
            return;
        }
    }
    s->last_id = id;
    addReply(c,shared.ok);
    server.dirty++;
    notifyKeyspaceEvent(NOTIFY_STREAM,"xsetid",c->argv[1],c->db->id);
}


void xackCommand(client *c) {
    streamCG *group = NULL;
    robj *o = lookupKeyRead(c->db,c->argv[1]);
    if (o) {
        if (checkType(c,o,OBJ_STREAM)) return; 
        group = streamLookupCG(o->ptr,c->argv[2]->ptr);
    }

    
    if (o == NULL || group == NULL) {
        addReply(c,shared.czero);
        return;
    }

    
    for (int j = 3; j < c->argc; j++) {
        streamID id;
        if (streamParseStrictIDOrReply(c,c->argv[j],&id,0) != C_OK) return;
    }

    int acknowledged = 0;
    for (int j = 3; j < c->argc; j++) {
        streamID id;
        unsigned char buf[sizeof(streamID)];
        if (streamParseStrictIDOrReply(c,c->argv[j],&id,0) != C_OK)
            serverPanic("StreamID invalid after check. Should not be possible.");
        streamEncodeID(buf,&id);

        
        streamNACK *nack = raxFind(group->pel,buf,sizeof(buf));
        if (nack != raxNotFound) {
            raxRemove(group->pel,buf,sizeof(buf),NULL);
            raxRemove(nack->consumer->pel,buf,sizeof(buf),NULL);
            streamFreeNACK(nack);
            acknowledged++;
            server.dirty++;
        }
    }
    addReplyLongLong(c,acknowledged);
}


void xpendingCommand(client *c) {
    int justinfo = c->argc == 3; 
    robj *key = c->argv[1];
    robj *groupname = c->argv[2];
    robj *consumername = (c->argc == 7) ? c->argv[6] : NULL;
    streamID startid, endid;
    long long count;

    
    if (c->argc != 3 && c->argc != 6 && c->argc != 7) {
        addReply(c,shared.syntaxerr);
        return;
    }

    
    if (c->argc >= 6) {
        if (getLongLongFromObjectOrReply(c,c->argv[5],&count,NULL) == C_ERR)
            return;
        if (count < 0) count = 0;
        if (streamParseIDOrReply(c,c->argv[3],&startid,0) == C_ERR)
            return;
        if (streamParseIDOrReply(c,c->argv[4],&endid,UINT64_MAX) == C_ERR)
            return;
    }

    
    robj *o = lookupKeyRead(c->db,c->argv[1]);
    streamCG *group;

    if (o && checkType(c,o,OBJ_STREAM)) return;
    if (o == NULL || (group = streamLookupCG(o->ptr,groupname->ptr)) == NULL)
    {
        addReplyErrorFormat(c, "-NOGROUP No such key '%s' or consumer " "group '%s'", (char*)key->ptr,(char*)groupname->ptr);

        return;
    }

    
    if (justinfo) {
        addReplyArrayLen(c,4);
        
        addReplyLongLong(c,raxSize(group->pel));
        
        if (raxSize(group->pel) == 0) {
            addReplyNull(c); 
            addReplyNull(c); 
            addReplyNullArray(c); 
        } else {
            
            raxIterator ri;
            raxStart(&ri,group->pel);
            raxSeek(&ri,"^",NULL,0);
            raxNext(&ri);
            streamDecodeID(ri.key,&startid);
            addReplyStreamID(c,&startid);

            
            raxSeek(&ri,"$",NULL,0);
            raxNext(&ri);
            streamDecodeID(ri.key,&endid);
            addReplyStreamID(c,&endid);
            raxStop(&ri);

            
            raxStart(&ri,group->consumers);
            raxSeek(&ri,"^",NULL,0);
            void *arraylen_ptr = addReplyDeferredLen(c);
            size_t arraylen = 0;
            while(raxNext(&ri)) {
                streamConsumer *consumer = ri.data;
                if (raxSize(consumer->pel) == 0) continue;
                addReplyArrayLen(c,2);
                addReplyBulkCBuffer(c,ri.key,ri.key_len);
                addReplyBulkLongLong(c,raxSize(consumer->pel));
                arraylen++;
            }
            setDeferredArrayLen(c,arraylen_ptr,arraylen);
            raxStop(&ri);
        }
    }
    
    else {
        streamConsumer *consumer = NULL;
        if (consumername) {
            consumer = streamLookupConsumer(group, consumername->ptr, SLC_NOCREAT|SLC_NOREFRESH);


            
            if (consumer == NULL) {
                addReplyArrayLen(c,0);
                return;
            }
        }

        rax *pel = consumer ? consumer->pel : group->pel;
        unsigned char startkey[sizeof(streamID)];
        unsigned char endkey[sizeof(streamID)];
        raxIterator ri;
        mstime_t now = mstime();

        streamEncodeID(startkey,&startid);
        streamEncodeID(endkey,&endid);
        raxStart(&ri,pel);
        raxSeek(&ri,">=",startkey,sizeof(startkey));
        void *arraylen_ptr = addReplyDeferredLen(c);
        size_t arraylen = 0;

        while(count && raxNext(&ri) && memcmp(ri.key,endkey,ri.key_len) <= 0) {
            streamNACK *nack = ri.data;

            arraylen++;
            count--;
            addReplyArrayLen(c,4);

            
            streamID id;
            streamDecodeID(ri.key,&id);
            addReplyStreamID(c,&id);

            
            addReplyBulkCBuffer(c,nack->consumer->name, sdslen(nack->consumer->name));

            
            mstime_t elapsed = now - nack->delivery_time;
            if (elapsed < 0) elapsed = 0;
            addReplyLongLong(c,elapsed);

            
            addReplyLongLong(c,nack->delivery_count);
        }
        raxStop(&ri);
        setDeferredArrayLen(c,arraylen_ptr,arraylen);
    }
}


void xclaimCommand(client *c) {
    streamCG *group = NULL;
    robj *o = lookupKeyRead(c->db,c->argv[1]);
    long long minidle; 
    long long retrycount = -1;   
    mstime_t deliverytime = -1;  
    int force = 0;
    int justid = 0;

    if (o) {
        if (checkType(c,o,OBJ_STREAM)) return; 
        group = streamLookupCG(o->ptr,c->argv[2]->ptr);
    }

    
    if (o == NULL || group == NULL) {
        addReplyErrorFormat(c,"-NOGROUP No such key '%s' or " "consumer group '%s'", (char*)c->argv[1]->ptr, (char*)c->argv[2]->ptr);

        return;
    }

    if (getLongLongFromObjectOrReply(c,c->argv[4],&minidle, "Invalid min-idle-time argument for XCLAIM")
        != C_OK) return;
    if (minidle < 0) minidle = 0;

    
    int j;
    for (j = 5; j < c->argc; j++) {
        streamID id;
        if (streamParseStrictIDOrReply(NULL,c->argv[j],&id,0) != C_OK) break;
    }
    int last_id_arg = j-1; 

    
    mstime_t now = mstime();
    streamID last_id = {0,0};
    int propagate_last_id = 0;
    for (; j < c->argc; j++) {
        int moreargs = (c->argc-1) - j; 
        char *opt = c->argv[j]->ptr;
        if (!strcasecmp(opt,"FORCE")) {
            force = 1;
        } else if (!strcasecmp(opt,"JUSTID")) {
            justid = 1;
        } else if (!strcasecmp(opt,"IDLE") && moreargs) {
            j++;
            if (getLongLongFromObjectOrReply(c,c->argv[j],&deliverytime, "Invalid IDLE option argument for XCLAIM")
                != C_OK) return;
            deliverytime = now - deliverytime;
        } else if (!strcasecmp(opt,"TIME") && moreargs) {
            j++;
            if (getLongLongFromObjectOrReply(c,c->argv[j],&deliverytime, "Invalid TIME option argument for XCLAIM")
                != C_OK) return;
        } else if (!strcasecmp(opt,"RETRYCOUNT") && moreargs) {
            j++;
            if (getLongLongFromObjectOrReply(c,c->argv[j],&retrycount, "Invalid RETRYCOUNT option argument for XCLAIM")
                != C_OK) return;
        } else if (!strcasecmp(opt,"LASTID") && moreargs) {
            j++;
            if (streamParseStrictIDOrReply(c,c->argv[j],&last_id,0) != C_OK) return;
        } else {
            addReplyErrorFormat(c,"Unrecognized XCLAIM option '%s'",opt);
            return;
        }
    }

    if (streamCompareID(&last_id,&group->last_id) > 0) {
        group->last_id = last_id;
        propagate_last_id = 1;
    }

    if (deliverytime != -1) {
        
        if (deliverytime < 0 || deliverytime > now) deliverytime = now;
    } else {
        
        deliverytime = now;
    }

    
    streamConsumer *consumer = NULL;
    void *arraylenptr = addReplyDeferredLen(c);
    size_t arraylen = 0;
    for (int j = 5; j <= last_id_arg; j++) {
        streamID id;
        unsigned char buf[sizeof(streamID)];
        if (streamParseStrictIDOrReply(c,c->argv[j],&id,0) != C_OK)
            serverPanic("StreamID invalid after check. Should not be possible.");
        streamEncodeID(buf,&id);

        
        streamNACK *nack = raxFind(group->pel,buf,sizeof(buf));

        
        if (force && nack == raxNotFound) {
            streamIterator myiterator;
            streamIteratorStart(&myiterator,o->ptr,&id,&id,0);
            int64_t numfields;
            int found = 0;
            streamID item_id;
            if (streamIteratorGetID(&myiterator,&item_id,&numfields)) found = 1;
            streamIteratorStop(&myiterator);

            
            if (!found) continue;

            
            nack = streamCreateNACK(NULL);
            raxInsert(group->pel,buf,sizeof(buf),nack,NULL);
        }

        if (nack != raxNotFound) {
            
            if (nack->consumer && minidle) {
                mstime_t this_idle = now - nack->delivery_time;
                if (this_idle < minidle) continue;
            }
            
            if (nack->consumer)
                raxRemove(nack->consumer->pel,buf,sizeof(buf),NULL);
            
            if (consumer == NULL)
                consumer = streamLookupConsumer(group,c->argv[3]->ptr,SLC_NONE);
            nack->consumer = consumer;
            nack->delivery_time = deliverytime;
            
            if (retrycount >= 0) {
                nack->delivery_count = retrycount;
            } else if (!justid) {
                nack->delivery_count++;
            }
            
            raxInsert(consumer->pel,buf,sizeof(buf),nack,NULL);
            
            if (justid) {
                addReplyStreamID(c,&id);
            } else {
                size_t emitted = streamReplyWithRange(c,o->ptr,&id,&id,1,0, NULL,NULL,STREAM_RWR_RAWENTRIES,NULL);
                if (!emitted) addReplyNull(c);
            }
            arraylen++;

            
            streamPropagateXCLAIM(c,c->argv[1],group,c->argv[2],c->argv[j],nack);
            propagate_last_id = 0; 
            server.dirty++;
        }
    }
    if (propagate_last_id) {
        streamPropagateGroupID(c,c->argv[1],group,c->argv[2]);
        server.dirty++;
    }
    setDeferredArrayLen(c,arraylenptr,arraylen);
    preventCommandPropagation(c);
}



void xdelCommand(client *c) {
    robj *o;

    if ((o = lookupKeyWriteOrReply(c,c->argv[1],shared.czero)) == NULL || checkType(c,o,OBJ_STREAM)) return;
    stream *s = o->ptr;

    
    streamID id;
    for (int j = 2; j < c->argc; j++) {
        if (streamParseStrictIDOrReply(c,c->argv[j],&id,0) != C_OK) return;
    }

    
    int deleted = 0;
    for (int j = 2; j < c->argc; j++) {
        streamParseStrictIDOrReply(c,c->argv[j],&id,0); 
        deleted += streamDeleteItem(s,&id);
    }

    
    if (deleted) {
        signalModifiedKey(c,c->db,c->argv[1]);
        notifyKeyspaceEvent(NOTIFY_STREAM,"xdel",c->argv[1],c->db->id);
        server.dirty += deleted;
    }
    addReplyLongLong(c,deleted);
}





void xtrimCommand(client *c) {
    robj *o;

    
    if ((o = lookupKeyWriteOrReply(c,c->argv[1],shared.czero)) == NULL || checkType(c,o,OBJ_STREAM)) return;
    stream *s = o->ptr;

    
    int trim_strategy = TRIM_STRATEGY_NONE;
    long long maxlen = -1;  
    int approx_maxlen = 0;  
    int maxlen_arg_idx = 0; 

    
    int i = 2; 
    for (; i < c->argc; i++) {
        int moreargs = (c->argc-1) - i; 
        char *opt = c->argv[i]->ptr;
        if (!strcasecmp(opt,"maxlen") && moreargs) {
            approx_maxlen = 0;
            trim_strategy = TRIM_STRATEGY_MAXLEN;
            char *next = c->argv[i+1]->ptr;
            
            if (moreargs >= 2 && next[0] == '~' && next[1] == '\0') {
                approx_maxlen = 1;
                i++;
            } else if (moreargs >= 2 && next[0] == '=' && next[1] == '\0') {
                i++;
            }
            if (getLongLongFromObjectOrReply(c,c->argv[i+1],&maxlen,NULL)
                != C_OK) return;

            if (maxlen < 0) {
                addReplyError(c,"The MAXLEN argument must be >= 0.");
                return;
            }
            i++;
            maxlen_arg_idx = i;
        } else {
            addReply(c,shared.syntaxerr);
            return;
        }
    }

    
    int64_t deleted = 0;
    if (trim_strategy == TRIM_STRATEGY_MAXLEN) {
        deleted = streamTrimByLength(s,maxlen,approx_maxlen);
    } else {
        addReplyError(c,"XTRIM called without an option to trim the stream");
        return;
    }

    
    if (deleted) {
        signalModifiedKey(c,c->db,c->argv[1]);
        notifyKeyspaceEvent(NOTIFY_STREAM,"xtrim",c->argv[1],c->db->id);
        server.dirty += deleted;
        if (approx_maxlen) streamRewriteApproxMaxlen(c,s,maxlen_arg_idx);
    }
    addReplyLongLong(c,deleted);
}


void xinfoReplyWithStreamInfo(client *c, stream *s) {
    int full = 1;
    long long count = 10; 
    robj **optv = c->argv + 3; 
    int optc = c->argc - 3;

    
    if (optc == 0) {
        full = 0;
    } else {
        
        if (optc != 1 && optc != 3) {
            addReplySubcommandSyntaxError(c);
            return;
        }

        
        if (strcasecmp(optv[0]->ptr,"full")) {
            addReplySubcommandSyntaxError(c);
            return;
        }

        if (optc == 3) {
            
            if (strcasecmp(optv[1]->ptr,"count")) {
                addReplySubcommandSyntaxError(c);
                return;
            }
            if (getLongLongFromObjectOrReply(c,optv[2],&count,NULL) == C_ERR)
                return;
            if (count < 0) count = 10;
        }
    }

    addReplyMapLen(c,full ? 6 : 7);
    addReplyBulkCString(c,"length");
    addReplyLongLong(c,s->length);
    addReplyBulkCString(c,"radix-tree-keys");
    addReplyLongLong(c,raxSize(s->rax));
    addReplyBulkCString(c,"radix-tree-nodes");
    addReplyLongLong(c,s->rax->numnodes);
    addReplyBulkCString(c,"last-generated-id");
    addReplyStreamID(c,&s->last_id);

    if (!full) {
        

        addReplyBulkCString(c,"groups");
        addReplyLongLong(c,s->cgroups ? raxSize(s->cgroups) : 0);

        
        int emitted;
        streamID start, end;
        start.ms = start.seq = 0;
        end.ms = end.seq = UINT64_MAX;
        addReplyBulkCString(c,"first-entry");
        emitted = streamReplyWithRange(c,s,&start,&end,1,0,NULL,NULL, STREAM_RWR_RAWENTRIES,NULL);
        if (!emitted) addReplyNull(c);
        addReplyBulkCString(c,"last-entry");
        emitted = streamReplyWithRange(c,s,&start,&end,1,1,NULL,NULL, STREAM_RWR_RAWENTRIES,NULL);
        if (!emitted) addReplyNull(c);
    } else {
        

        
        addReplyBulkCString(c,"entries");
        streamReplyWithRange(c,s,NULL,NULL,count,0,NULL,NULL,0,NULL);

        
        addReplyBulkCString(c,"groups");
        if (s->cgroups == NULL) {
            addReplyArrayLen(c,0);
        } else {
            addReplyArrayLen(c,raxSize(s->cgroups));
            raxIterator ri_cgroups;
            raxStart(&ri_cgroups,s->cgroups);
            raxSeek(&ri_cgroups,"^",NULL,0);
            while(raxNext(&ri_cgroups)) {
                streamCG *cg = ri_cgroups.data;
                addReplyMapLen(c,5);

                
                addReplyBulkCString(c,"name");
                addReplyBulkCBuffer(c,ri_cgroups.key,ri_cgroups.key_len);

                
                addReplyBulkCString(c,"last-delivered-id");
                addReplyStreamID(c,&cg->last_id);

                
                addReplyBulkCString(c,"pel-count");
                addReplyLongLong(c,raxSize(cg->pel));

                
                addReplyBulkCString(c,"pending");
                long long arraylen_cg_pel = 0;
                void *arrayptr_cg_pel = addReplyDeferredLen(c);
                raxIterator ri_cg_pel;
                raxStart(&ri_cg_pel,cg->pel);
                raxSeek(&ri_cg_pel,"^",NULL,0);
                while(raxNext(&ri_cg_pel) && (!count || arraylen_cg_pel < count)) {
                    streamNACK *nack = ri_cg_pel.data;
                    addReplyArrayLen(c,4);

                    
                    streamID id;
                    streamDecodeID(ri_cg_pel.key,&id);
                    addReplyStreamID(c,&id);

                    
                    addReplyBulkCBuffer(c,nack->consumer->name, sdslen(nack->consumer->name));

                    
                    addReplyLongLong(c,nack->delivery_time);

                    
                    addReplyLongLong(c,nack->delivery_count);

                    arraylen_cg_pel++;
                }
                setDeferredArrayLen(c,arrayptr_cg_pel,arraylen_cg_pel);
                raxStop(&ri_cg_pel);

                
                addReplyBulkCString(c,"consumers");
                addReplyArrayLen(c,raxSize(cg->consumers));
                raxIterator ri_consumers;
                raxStart(&ri_consumers,cg->consumers);
                raxSeek(&ri_consumers,"^",NULL,0);
                while(raxNext(&ri_consumers)) {
                    streamConsumer *consumer = ri_consumers.data;
                    addReplyMapLen(c,4);

                    
                    addReplyBulkCString(c,"name");
                    addReplyBulkCBuffer(c,consumer->name,sdslen(consumer->name));

                    
                    addReplyBulkCString(c,"seen-time");
                    addReplyLongLong(c,consumer->seen_time);

                    
                    addReplyBulkCString(c,"pel-count");
                    addReplyLongLong(c,raxSize(consumer->pel));

                    
                    addReplyBulkCString(c,"pending");
                    long long arraylen_cpel = 0;
                    void *arrayptr_cpel = addReplyDeferredLen(c);
                    raxIterator ri_cpel;
                    raxStart(&ri_cpel,consumer->pel);
                    raxSeek(&ri_cpel,"^",NULL,0);
                    while(raxNext(&ri_cpel) && (!count || arraylen_cpel < count)) {
                        streamNACK *nack = ri_cpel.data;
                        addReplyArrayLen(c,3);

                        
                        streamID id;
                        streamDecodeID(ri_cpel.key,&id);
                        addReplyStreamID(c,&id);

                        
                        addReplyLongLong(c,nack->delivery_time);

                        
                        addReplyLongLong(c,nack->delivery_count);

                        arraylen_cpel++;
                    }
                    setDeferredArrayLen(c,arrayptr_cpel,arraylen_cpel);
                    raxStop(&ri_cpel);
                }
                raxStop(&ri_consumers);
            }
            raxStop(&ri_cgroups);
        }
    }
}


void xinfoCommand(client *c) {
    const char *help[] = {
"CONSUMERS <key> <groupname>         -- Show consumer groups of group <groupname>.", "GROUPS <key>                        -- Show the stream consumer groups.", "STREAM <key> [FULL [COUNT <count>]] -- Show information about the stream.", "                                       FULL will return the full state of the stream,", "                                            including all entries, groups, consumers and PELs.", "                                            It's possible to show only the first stream/PEL entries", "                                            by using the COUNT modifier (Default is 10)", "HELP                                -- Print this help.", NULL };








    stream *s = NULL;
    char *opt;
    robj *key;

    
    if (!strcasecmp(c->argv[1]->ptr,"HELP")) {
        addReplyHelp(c, help);
        return;
    } else if (c->argc < 3) {
        addReplyError(c,"syntax error, try 'XINFO HELP'");
        return;
    }

    
    opt = c->argv[1]->ptr;
    key = c->argv[2];

    
    robj *o = lookupKeyReadOrReply(c,key,shared.nokeyerr);
    if (o == NULL || checkType(c,o,OBJ_STREAM)) return;
    s = o->ptr;

    
    if (!strcasecmp(opt,"CONSUMERS") && c->argc == 4) {
        
        streamCG *cg = streamLookupCG(s,c->argv[3]->ptr);
        if (cg == NULL) {
            addReplyErrorFormat(c, "-NOGROUP No such consumer group '%s' " "for key name '%s'", (char*)c->argv[3]->ptr, (char*)key->ptr);

            return;
        }

        addReplyArrayLen(c,raxSize(cg->consumers));
        raxIterator ri;
        raxStart(&ri,cg->consumers);
        raxSeek(&ri,"^",NULL,0);
        mstime_t now = mstime();
        while(raxNext(&ri)) {
            streamConsumer *consumer = ri.data;
            mstime_t idle = now - consumer->seen_time;
            if (idle < 0) idle = 0;

            addReplyMapLen(c,3);
            addReplyBulkCString(c,"name");
            addReplyBulkCBuffer(c,consumer->name,sdslen(consumer->name));
            addReplyBulkCString(c,"pending");
            addReplyLongLong(c,raxSize(consumer->pel));
            addReplyBulkCString(c,"idle");
            addReplyLongLong(c,idle);
        }
        raxStop(&ri);
    } else if (!strcasecmp(opt,"GROUPS") && c->argc == 3) {
        
        if (s->cgroups == NULL) {
            addReplyArrayLen(c,0);
            return;
        }

        addReplyArrayLen(c,raxSize(s->cgroups));
        raxIterator ri;
        raxStart(&ri,s->cgroups);
        raxSeek(&ri,"^",NULL,0);
        while(raxNext(&ri)) {
            streamCG *cg = ri.data;
            addReplyMapLen(c,4);
            addReplyBulkCString(c,"name");
            addReplyBulkCBuffer(c,ri.key,ri.key_len);
            addReplyBulkCString(c,"consumers");
            addReplyLongLong(c,raxSize(cg->consumers));
            addReplyBulkCString(c,"pending");
            addReplyLongLong(c,raxSize(cg->pel));
            addReplyBulkCString(c,"last-delivered-id");
            addReplyStreamID(c,&cg->last_id);
        }
        raxStop(&ri);
    } else if (!strcasecmp(opt,"STREAM")) {
        
        xinfoReplyWithStreamInfo(c,s);
    } else {
        addReplySubcommandSyntaxError(c);
    }
}
