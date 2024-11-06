






unsigned char *zzlFirstInRange(unsigned char *zl, zrangespec *range);
int zslValueLteMax(double value, zrangespec *spec);






geoArray *geoArrayCreate(void) {
    geoArray *ga = zmalloc(sizeof(*ga));
    
    ga->array = NULL;
    ga->buckets = 0;
    ga->used = 0;
    return ga;
}


geoPoint *geoArrayAppend(geoArray *ga) {
    if (ga->used == ga->buckets) {
        ga->buckets = (ga->buckets == 0) ? 8 : ga->buckets*2;
        ga->array = zrealloc(ga->array,sizeof(geoPoint)*ga->buckets);
    }
    geoPoint *gp = ga->array+ga->used;
    ga->used++;
    return gp;
}


void geoArrayFree(geoArray *ga) {
    size_t i;
    for (i = 0; i < ga->used; i++) sdsfree(ga->array[i].member);
    zfree(ga->array);
    zfree(ga);
}


int decodeGeohash(double bits, double *xy) {
    GeoHashBits hash = { .bits = (uint64_t)bits, .step = GEO_STEP_MAX };
    return geohashDecodeToLongLatWGS84(hash, xy);
}



int extractLongLatOrReply(client *c, robj **argv, double *xy) {
    int i;
    for (i = 0; i < 2; i++) {
        if (getDoubleFromObjectOrReply(c, argv[i], xy + i, NULL) != C_OK) {
            return C_ERR;
        }
    }
    if (xy[0] < GEO_LONG_MIN || xy[0] > GEO_LONG_MAX || xy[1] < GEO_LAT_MIN  || xy[1] > GEO_LAT_MAX) {
        addReplySds(c, sdscatprintf(sdsempty(), "-ERR invalid longitude,latitude pair %f,%f\r\n",xy[0],xy[1]));
        return C_ERR;
    }
    return C_OK;
}



int longLatFromMember(robj *zobj, robj *member, double *xy) {
    double score = 0;

    if (zsetScore(zobj, member->ptr, &score) == C_ERR) return C_ERR;
    if (!decodeGeohash(score, xy)) return C_ERR;
    return C_OK;
}


double extractUnitOrReply(client *c, robj *unit) {
    char *u = unit->ptr;

    if (!strcmp(u, "m")) {
        return 1;
    } else if (!strcmp(u, "km")) {
        return 1000;
    } else if (!strcmp(u, "ft")) {
        return 0.3048;
    } else if (!strcmp(u, "mi")) {
        return 1609.34;
    } else {
        addReplyError(c, "unsupported unit provided. please use m, km, ft, mi");
        return -1;
    }
}


double extractDistanceOrReply(client *c, robj **argv, double *conversion) {
    double distance;
    if (getDoubleFromObjectOrReply(c, argv[0], &distance, "need numeric radius") != C_OK) {
        return -1;
    }

    if (distance < 0) {
        addReplyError(c,"radius cannot be negative");
        return -1;
    }

    double to_meters = extractUnitOrReply(c,argv[1]);
    if (to_meters < 0) {
        return -1;
    }

    if (conversion) *conversion = to_meters;
    return distance * to_meters;
}


void addReplyDoubleDistance(client *c, double d) {
    char dbuf[128];
    int dlen = snprintf(dbuf, sizeof(dbuf), "%.4f", d);
    addReplyBulkCBuffer(c, dbuf, dlen);
}


int geoAppendIfWithinRadius(geoArray *ga, double lon, double lat, double radius, double score, sds member) {
    double distance, xy[2];

    if (!decodeGeohash(score,xy)) return C_ERR; 
    
    if (!geohashGetDistanceIfInRadiusWGS84(lon,lat, xy[0], xy[1], radius, &distance))
    {
        return C_ERR;
    }

    
    geoPoint *gp = geoArrayAppend(ga);
    gp->longitude = xy[0];
    gp->latitude = xy[1];
    gp->dist = distance;
    gp->member = member;
    gp->score = score;
    return C_OK;
}


int geoGetPointsInRange(robj *zobj, double min, double max, double lon, double lat, double radius, geoArray *ga) {
    
    
    zrangespec range = { .min = min, .max = max, .minex = 0, .maxex = 1 };
    size_t origincount = ga->used;
    sds member;

    if (zobj->encoding == OBJ_ENCODING_ZIPLIST) {
        unsigned char *zl = zobj->ptr;
        unsigned char *eptr, *sptr;
        unsigned char *vstr = NULL;
        unsigned int vlen = 0;
        long long vlong = 0;
        double score = 0;

        if ((eptr = zzlFirstInRange(zl, &range)) == NULL) {
            
            return 0;
        }

        sptr = ziplistNext(zl, eptr);
        while (eptr) {
            score = zzlGetScore(sptr);

            
            if (!zslValueLteMax(score, &range))
                break;

            
            ziplistGet(eptr, &vstr, &vlen, &vlong);
            member = (vstr == NULL) ? sdsfromlonglong(vlong) :
                                      sdsnewlen(vstr,vlen);
            if (geoAppendIfWithinRadius(ga,lon,lat,radius,score,member)
                == C_ERR) sdsfree(member);
            zzlNext(zl, &eptr, &sptr);
        }
    } else if (zobj->encoding == OBJ_ENCODING_SKIPLIST) {
        zset *zs = zobj->ptr;
        zskiplist *zsl = zs->zsl;
        zskiplistNode *ln;

        if ((ln = zslFirstInRange(zsl, &range)) == NULL) {
            
            return 0;
        }

        while (ln) {
            sds ele = ln->ele;
            
            if (!zslValueLteMax(ln->score, &range))
                break;

            ele = sdsdup(ele);
            if (geoAppendIfWithinRadius(ga,lon,lat,radius,ln->score,ele)
                == C_ERR) sdsfree(ele);
            ln = ln->level[0].forward;
        }
    }
    return ga->used - origincount;
}


void scoresOfGeoHashBox(GeoHashBits hash, GeoHashFix52Bits *min, GeoHashFix52Bits *max) {
    
    *min = geohashAlign52Bits(hash);
    hash.bits++;
    *max = geohashAlign52Bits(hash);
}


int membersOfGeoHashBox(robj *zobj, GeoHashBits hash, geoArray *ga, double lon, double lat, double radius) {
    GeoHashFix52Bits min, max;

    scoresOfGeoHashBox(hash,&min,&max);
    return geoGetPointsInRange(zobj, min, max, lon, lat, radius, ga);
}


int membersOfAllNeighbors(robj *zobj, GeoHashRadius n, double lon, double lat, double radius, geoArray *ga) {
    GeoHashBits neighbors[9];
    unsigned int i, count = 0, last_processed = 0;
    int debugmsg = 0;

    neighbors[0] = n.hash;
    neighbors[1] = n.neighbors.north;
    neighbors[2] = n.neighbors.south;
    neighbors[3] = n.neighbors.east;
    neighbors[4] = n.neighbors.west;
    neighbors[5] = n.neighbors.north_east;
    neighbors[6] = n.neighbors.north_west;
    neighbors[7] = n.neighbors.south_east;
    neighbors[8] = n.neighbors.south_west;

    
    for (i = 0; i < sizeof(neighbors) / sizeof(*neighbors); i++) {
        if (HASHISZERO(neighbors[i])) {
            if (debugmsg) D("neighbors[%d] is zero",i);
            continue;
        }

        
        if (debugmsg) {
            GeoHashRange long_range, lat_range;
            geohashGetCoordRange(&long_range,&lat_range);
            GeoHashArea myarea = {{0}};
            geohashDecode(long_range, lat_range, neighbors[i], &myarea);

            
            D("neighbors[%d]:\n",i);
            D("area.longitude.min: %f\n", myarea.longitude.min);
            D("area.longitude.max: %f\n", myarea.longitude.max);
            D("area.latitude.min: %f\n", myarea.latitude.min);
            D("area.latitude.max: %f\n", myarea.latitude.max);
            D("\n");
        }

        
        if (last_processed && neighbors[i].bits == neighbors[last_processed].bits && neighbors[i].step == neighbors[last_processed].step)

        {
            if (debugmsg)
                D("Skipping processing of %d, same as previous\n",i);
            continue;
        }
        count += membersOfGeoHashBox(zobj, neighbors[i], ga, lon, lat, radius);
        last_processed = i;
    }
    return count;
}


static int sort_gp_asc(const void *a, const void *b) {
    const struct geoPoint *gpa = a, *gpb = b;
    
    if (gpa->dist > gpb->dist)
        return 1;
    else if (gpa->dist == gpb->dist)
        return 0;
    else return -1;
}

static int sort_gp_desc(const void *a, const void *b) {
    return -sort_gp_asc(a, b);
}




void geoaddCommand(client *c) {
    
    if ((c->argc - 2) % 3 != 0) {
        
        addReplyError(c, "syntax error. Try GEOADD key [x1] [y1] [name1] " "[x2] [y2] [name2] ... ");
        return;
    }

    int elements = (c->argc - 2) / 3;
    int argc = 2+elements*2; 
    robj **argv = zcalloc(argc*sizeof(robj*));
    argv[0] = createRawStringObject("zadd",4);
    argv[1] = c->argv[1]; 
    incrRefCount(argv[1]);

    
    int i;
    for (i = 0; i < elements; i++) {
        double xy[2];

        if (extractLongLatOrReply(c, (c->argv+2)+(i*3),xy) == C_ERR) {
            for (i = 0; i < argc; i++)
                if (argv[i]) decrRefCount(argv[i]);
            zfree(argv);
            return;
        }

        
        GeoHashBits hash;
        geohashEncodeWGS84(xy[0], xy[1], GEO_STEP_MAX, &hash);
        GeoHashFix52Bits bits = geohashAlign52Bits(hash);
        robj *score = createObject(OBJ_STRING, sdsfromlonglong(bits));
        robj *val = c->argv[2 + i * 3 + 2];
        argv[2+i*2] = score;
        argv[3+i*2] = val;
        incrRefCount(val);
    }

    
    replaceClientCommandVector(c,argc,argv);
    zaddCommand(c);
}










void georadiusGeneric(client *c, int flags) {
    robj *key = c->argv[1];
    robj *storekey = NULL;
    int storedist = 0; 

    
    robj *zobj = NULL;
    if ((zobj = lookupKeyReadOrReply(c, key, shared.emptyarray)) == NULL || checkType(c, zobj, OBJ_ZSET)) {
        return;
    }

    
    int base_args;
    double xy[2] = { 0 };
    if (flags & RADIUS_COORDS) {
        base_args = 6;
        if (extractLongLatOrReply(c, c->argv + 2, xy) == C_ERR)
            return;
    } else if (flags & RADIUS_MEMBER) {
        base_args = 5;
        robj *member = c->argv[2];
        if (longLatFromMember(zobj, member, xy) == C_ERR) {
            addReplyError(c, "could not decode requested zset member");
            return;
        }
    } else {
        addReplyError(c, "Unknown georadius search type");
        return;
    }

    
    double radius_meters = 0, conversion = 1;
    if ((radius_meters = extractDistanceOrReply(c, c->argv + base_args - 2, &conversion)) < 0) {
        return;
    }

    
    int withdist = 0, withhash = 0, withcoords = 0;
    int sort = SORT_NONE;
    long long count = 0;
    if (c->argc > base_args) {
        int remaining = c->argc - base_args;
        for (int i = 0; i < remaining; i++) {
            char *arg = c->argv[base_args + i]->ptr;
            if (!strcasecmp(arg, "withdist")) {
                withdist = 1;
            } else if (!strcasecmp(arg, "withhash")) {
                withhash = 1;
            } else if (!strcasecmp(arg, "withcoord")) {
                withcoords = 1;
            } else if (!strcasecmp(arg, "asc")) {
                sort = SORT_ASC;
            } else if (!strcasecmp(arg, "desc")) {
                sort = SORT_DESC;
            } else if (!strcasecmp(arg, "count") && (i+1) < remaining) {
                if (getLongLongFromObjectOrReply(c, c->argv[base_args+i+1], &count, NULL) != C_OK) return;
                if (count <= 0) {
                    addReplyError(c,"COUNT must be > 0");
                    return;
                }
                i++;
            } else if (!strcasecmp(arg, "store") && (i+1) < remaining && !(flags & RADIUS_NOSTORE))

            {
                storekey = c->argv[base_args+i+1];
                storedist = 0;
                i++;
            } else if (!strcasecmp(arg, "storedist") && (i+1) < remaining && !(flags & RADIUS_NOSTORE))

            {
                storekey = c->argv[base_args+i+1];
                storedist = 1;
                i++;
            } else {
                addReply(c, shared.syntaxerr);
                return;
            }
        }
    }

    
    if (storekey && (withdist || withhash || withcoords)) {
        addReplyError(c, "STORE option in GEORADIUS is not compatible with " "WITHDIST, WITHHASH and WITHCOORDS options");

        return;
    }

    
    if (count != 0 && sort == SORT_NONE) sort = SORT_ASC;

    
    GeoHashRadius georadius = geohashGetAreasByRadiusWGS84(xy[0], xy[1], radius_meters);

    
    geoArray *ga = geoArrayCreate();
    membersOfAllNeighbors(zobj, georadius, xy[0], xy[1], radius_meters, ga);

    
    if (ga->used == 0 && storekey == NULL) {
        addReply(c,shared.emptyarray);
        geoArrayFree(ga);
        return;
    }

    long result_length = ga->used;
    long returned_items = (count == 0 || result_length < count) ? result_length : count;
    long option_length = 0;

    
    if (sort == SORT_ASC) {
        qsort(ga->array, result_length, sizeof(geoPoint), sort_gp_asc);
    } else if (sort == SORT_DESC) {
        qsort(ga->array, result_length, sizeof(geoPoint), sort_gp_desc);
    }

    if (storekey == NULL) {
        

        
        if (withdist)
            option_length++;

        if (withcoords)
            option_length++;

        if (withhash)
            option_length++;

        
        addReplyArrayLen(c, returned_items);

        
        int i;
        for (i = 0; i < returned_items; i++) {
            geoPoint *gp = ga->array+i;
            gp->dist /= conversion; 

            
            if (option_length)
                addReplyArrayLen(c, option_length + 1);

            addReplyBulkSds(c,gp->member);
            gp->member = NULL;

            if (withdist)
                addReplyDoubleDistance(c, gp->dist);

            if (withhash)
                addReplyLongLong(c, gp->score);

            if (withcoords) {
                addReplyArrayLen(c, 2);
                addReplyHumanLongDouble(c, gp->longitude);
                addReplyHumanLongDouble(c, gp->latitude);
            }
        }
    } else {
        
        robj *zobj;
        zset *zs;
        int i;
        size_t maxelelen = 0;

        if (returned_items) {
            zobj = createZsetObject();
            zs = zobj->ptr;
        }

        for (i = 0; i < returned_items; i++) {
            zskiplistNode *znode;
            geoPoint *gp = ga->array+i;
            gp->dist /= conversion; 
            double score = storedist ? gp->dist : gp->score;
            size_t elelen = sdslen(gp->member);

            if (maxelelen < elelen) maxelelen = elelen;
            znode = zslInsert(zs->zsl,score,gp->member);
            serverAssert(dictAdd(zs->dict,gp->member,&znode->score) == DICT_OK);
            gp->member = NULL;
        }

        if (returned_items) {
            zsetConvertToZiplistIfNeeded(zobj,maxelelen);
            setKey(c,c->db,storekey,zobj);
            decrRefCount(zobj);
            notifyKeyspaceEvent(NOTIFY_ZSET,"georadiusstore",storekey, c->db->id);
            server.dirty += returned_items;
        } else if (dbDelete(c->db,storekey)) {
            signalModifiedKey(c,c->db,storekey);
            notifyKeyspaceEvent(NOTIFY_GENERIC,"del",storekey,c->db->id);
            server.dirty++;
        }
        addReplyLongLong(c, returned_items);
    }
    geoArrayFree(ga);
}


void georadiusCommand(client *c) {
    georadiusGeneric(c, RADIUS_COORDS);
}


void georadiusbymemberCommand(client *c) {
    georadiusGeneric(c, RADIUS_MEMBER);
}


void georadiusroCommand(client *c) {
    georadiusGeneric(c, RADIUS_COORDS|RADIUS_NOSTORE);
}


void georadiusbymemberroCommand(client *c) {
    georadiusGeneric(c, RADIUS_MEMBER|RADIUS_NOSTORE);
}


void geohashCommand(client *c) {
    char *geoalphabet= "0123456789bcdefghjkmnpqrstuvwxyz";
    int j;

    
    robj *zobj = lookupKeyRead(c->db, c->argv[1]);
    if (zobj && checkType(c, zobj, OBJ_ZSET)) return;

    
    addReplyArrayLen(c,c->argc-2);
    for (j = 2; j < c->argc; j++) {
        double score;
        if (!zobj || zsetScore(zobj, c->argv[j]->ptr, &score) == C_ERR) {
            addReplyNull(c);
        } else {
            

            
            double xy[2];
            if (!decodeGeohash(score,xy)) {
                addReplyNull(c);
                continue;
            }

            
            GeoHashRange r[2];
            GeoHashBits hash;
            r[0].min = -180;
            r[0].max = 180;
            r[1].min = -90;
            r[1].max = 90;
            geohashEncode(&r[0],&r[1],xy[0],xy[1],26,&hash);

            char buf[12];
            int i;
            for (i = 0; i < 11; i++) {
                int idx;
                if (i == 10) {
                    
                    idx = 0;
                } else {
                    idx = (hash.bits >> (52-((i+1)*5))) & 0x1f;
                }
                buf[i] = geoalphabet[idx];
            }
            buf[11] = '\0';
            addReplyBulkCBuffer(c,buf,11);
        }
    }
}


void geoposCommand(client *c) {
    int j;

    
    robj *zobj = lookupKeyRead(c->db, c->argv[1]);
    if (zobj && checkType(c, zobj, OBJ_ZSET)) return;

    
    addReplyArrayLen(c,c->argc-2);
    for (j = 2; j < c->argc; j++) {
        double score;
        if (!zobj || zsetScore(zobj, c->argv[j]->ptr, &score) == C_ERR) {
            addReplyNullArray(c);
        } else {
            
            double xy[2];
            if (!decodeGeohash(score,xy)) {
                addReplyNullArray(c);
                continue;
            }
            addReplyArrayLen(c,2);
            addReplyHumanLongDouble(c,xy[0]);
            addReplyHumanLongDouble(c,xy[1]);
        }
    }
}


void geodistCommand(client *c) {
    double to_meter = 1;

    
    if (c->argc == 5) {
        to_meter = extractUnitOrReply(c,c->argv[4]);
        if (to_meter < 0) return;
    } else if (c->argc > 5) {
        addReply(c,shared.syntaxerr);
        return;
    }

    
    robj *zobj = NULL;
    if ((zobj = lookupKeyReadOrReply(c, c->argv[1], shared.null[c->resp]))
        == NULL || checkType(c, zobj, OBJ_ZSET)) return;

    
    double score1, score2, xyxy[4];
    if (zsetScore(zobj, c->argv[2]->ptr, &score1) == C_ERR || zsetScore(zobj, c->argv[3]->ptr, &score2) == C_ERR)
    {
        addReplyNull(c);
        return;
    }

    
    if (!decodeGeohash(score1,xyxy) || !decodeGeohash(score2,xyxy+2))
        addReplyNull(c);
    else addReplyDoubleDistance(c, geohashGetDistance(xyxy[0],xyxy[1],xyxy[2],xyxy[3]) / to_meter);

}
