










































































static void reallymarkobject (global_State *g, GCObject *o);
static lu_mem atomic (lua_State *L);
static void entersweep (lua_State *L);









static GCObject **getgclist (GCObject *o) {
  switch (o->tt) {
    case LUA_VTABLE: return &gco2t(o)->gclist;
    case LUA_VLCL: return &gco2lcl(o)->gclist;
    case LUA_VCCL: return &gco2ccl(o)->gclist;
    case LUA_VTHREAD: return &gco2th(o)->gclist;
    case LUA_VPROTO: return &gco2p(o)->gclist;
    case LUA_VUSERDATA: {
      Udata *u = gco2u(o);
      lua_assert(u->nuvalue > 0);
      return &u->gclist;
    }
    default: lua_assert(0); return 0;
  }
}












static void clearkey (Node *n) {
  lua_assert(isempty(gval(n)));
  if (keyiswhite(n))
    setdeadkey(n);  
}



static int iscleared (global_State *g, const GCObject *o) {
  if (o == NULL) return 0;  
  else if (novariant(o->tt) == LUA_TSTRING) {
    markobject(g, o);  
    return 0;
  }
  else return iswhite(o);
}



void luaC_barrier_ (lua_State *L, GCObject *o, GCObject *v) {
  global_State *g = G(L);
  lua_assert(isblack(o) && iswhite(v) && !isdead(g, v) && !isdead(g, o));
  if (keepinvariant(g)) {  
    reallymarkobject(g, v);  
    if (isold(o)) {
      lua_assert(!isold(v));  
      setage(v, G_OLD0);  
    }
  }
  else {  
    lua_assert(issweepphase(g));
    makewhite(g, o);  
  }
}



void luaC_barrierback_ (lua_State *L, GCObject *o) {
  global_State *g = G(L);
  lua_assert(isblack(o) && !isdead(g, o));
  lua_assert(g->gckind != KGC_GEN || (isold(o) && getage(o) != G_TOUCHED1));
  if (getage(o) != G_TOUCHED2)  
    linkobjgclist(o, g->grayagain);  
  black2gray(o);  
  setage(o, G_TOUCHED1);  
}


void luaC_fix (lua_State *L, GCObject *o) {
  global_State *g = G(L);
  lua_assert(g->allgc == o);  
  white2gray(o);  
  setage(o, G_OLD);  
  g->allgc = o->next;  
  o->next = g->fixedgc;  
  g->fixedgc = o;
}



GCObject *luaC_newobj (lua_State *L, int tt, size_t sz) {
  global_State *g = G(L);
  GCObject *o = cast(GCObject *, luaM_newobject(L, novariant(tt), sz));
  o->marked = luaC_white(g);
  o->tt = tt;
  o->next = g->allgc;
  g->allgc = o;
  return o;
}









static void reallymarkobject (global_State *g, GCObject *o) {
  white2gray(o);
  switch (o->tt) {
    case LUA_VSHRSTR:
    case LUA_VLNGSTR: {
      gray2black(o);
      break;
    }
    case LUA_VUPVAL: {
      UpVal *uv = gco2upv(o);
      if (!upisopen(uv))  
        gray2black(o);
      markvalue(g, uv->v);  
      break;
    }
    case LUA_VUSERDATA: {
      Udata *u = gco2u(o);
      if (u->nuvalue == 0) {  
        markobjectN(g, u->metatable);  
        gray2black(o);  
        break;
      }
      
    }  
    case LUA_VLCL: case LUA_VCCL: case LUA_VTABLE:
    case LUA_VTHREAD: case LUA_VPROTO: {
      linkobjgclist(o, g->gray);
      break;
    }
    default: lua_assert(0); break;
  }
}



static void markmt (global_State *g) {
  int i;
  for (i=0; i < LUA_NUMTAGS; i++)
    markobjectN(g, g->mt[i]);
}



static lu_mem markbeingfnz (global_State *g) {
  GCObject *o;
  lu_mem count = 0;
  for (o = g->tobefnz; o != NULL; o = o->next) {
    count++;
    markobject(g, o);
  }
  return count;
}



static int remarkupvals (global_State *g) {
  lua_State *thread;
  lua_State **p = &g->twups;
  int work = 0;
  while ((thread = *p) != NULL) {
    work++;
    lua_assert(!isblack(thread));  
    if (isgray(thread) && thread->openupval != NULL)
      p = &thread->twups;  
    else {  
      UpVal *uv;
      *p = thread->twups;  
      thread->twups = thread;  
      for (uv = thread->openupval; uv != NULL; uv = uv->u.open.next) {
        work++;
        if (!iswhite(uv))  
          markvalue(g, uv->v);  
      }
    }
  }
  return work;
}



static void restartcollection (global_State *g) {
  g->gray = g->grayagain = NULL;
  g->weak = g->allweak = g->ephemeron = NULL;
  markobject(g, g->mainthread);
  markvalue(g, &g->l_registry);
  markmt(g);
  markbeingfnz(g);  
}







static void traverseweakvalue (global_State *g, Table *h) {
  Node *n, *limit = gnodelast(h);
  
  int hasclears = (h->alimit > 0);
  for (n = gnode(h, 0); n < limit; n++) {  
    if (isempty(gval(n)))  
      clearkey(n);  
    else {
      lua_assert(!keyisnil(n));
      markkey(g, n);
      if (!hasclears && iscleared(g, gcvalueN(gval(n))))  
        hasclears = 1;  
    }
  }
  if (g->gcstate == GCSatomic && hasclears)
    linkgclist(h, g->weak);  
  else linkgclist(h, g->grayagain);
}



static int traverseephemeron (global_State *g, Table *h, int inv) {
  int marked = 0;  
  int hasclears = 0;  
  int hasww = 0;  
  unsigned int i;
  unsigned int asize = luaH_realasize(h);
  unsigned int nsize = sizenode(h);
  
  for (i = 0; i < asize; i++) {
    if (valiswhite(&h->array[i])) {
      marked = 1;
      reallymarkobject(g, gcvalue(&h->array[i]));
    }
  }
  
  for (i = 0; i < nsize; i++) {
    Node *n = inv ? gnode(h, nsize - 1 - i) : gnode(h, i);
    if (isempty(gval(n)))  
      clearkey(n);  
    else if (iscleared(g, gckeyN(n))) {  
      hasclears = 1;  
      if (valiswhite(gval(n)))  
        hasww = 1;  
    }
    else if (valiswhite(gval(n))) {  
      marked = 1;
      reallymarkobject(g, gcvalue(gval(n)));  
    }
  }
  
  if (g->gcstate == GCSpropagate)
    linkgclist(h, g->grayagain);  
  else if (hasww)  
    linkgclist(h, g->ephemeron);  
  else if (hasclears)  
    linkgclist(h, g->allweak);  
  else if (g->gckind == KGC_GEN)
    linkgclist(h, g->grayagain);  
  else gray2black(h);
  return marked;
}


static void traversestrongtable (global_State *g, Table *h) {
  Node *n, *limit = gnodelast(h);
  unsigned int i;
  unsigned int asize = luaH_realasize(h);
  for (i = 0; i < asize; i++)  
    markvalue(g, &h->array[i]);
  for (n = gnode(h, 0); n < limit; n++) {  
    if (isempty(gval(n)))  
      clearkey(n);  
    else {
      lua_assert(!keyisnil(n));
      markkey(g, n);
      markvalue(g, gval(n));
    }
  }
  if (g->gckind == KGC_GEN) {
    linkgclist(h, g->grayagain);  
    black2gray(h);
  }
}


static lu_mem traversetable (global_State *g, Table *h) {
  const char *weakkey, *weakvalue;
  const TValue *mode = gfasttm(g, h->metatable, TM_MODE);
  markobjectN(g, h->metatable);
  if (mode && ttisstring(mode) &&   (cast_void(weakkey = strchr(svalue(mode), 'k')), cast_void(weakvalue = strchr(svalue(mode), 'v')), (weakkey || weakvalue))) {


    black2gray(h);  
    if (!weakkey)  
      traverseweakvalue(g, h);
    else if (!weakvalue)  
      traverseephemeron(g, h, 0);
    else   linkgclist(h, g->allweak);
  }
  else   traversestrongtable(g, h);
  return 1 + h->alimit + 2 * allocsizenode(h);
}


static int traverseudata (global_State *g, Udata *u) {
  int i;
  markobjectN(g, u->metatable);  
  for (i = 0; i < u->nuvalue; i++)
    markvalue(g, &u->uv[i].uv);
  if (g->gckind == KGC_GEN) {
    linkgclist(u, g->grayagain);  
    black2gray(u);
  }
  return 1 + u->nuvalue;
}



static int traverseproto (global_State *g, Proto *f) {
  int i;
  markobjectN(g, f->source);
  for (i = 0; i < f->sizek; i++)  
    markvalue(g, &f->k[i]);
  for (i = 0; i < f->sizeupvalues; i++)  
    markobjectN(g, f->upvalues[i].name);
  for (i = 0; i < f->sizep; i++)  
    markobjectN(g, f->p[i]);
  for (i = 0; i < f->sizelocvars; i++)  
    markobjectN(g, f->locvars[i].varname);
  return 1 + f->sizek + f->sizeupvalues + f->sizep + f->sizelocvars;
}


static int traverseCclosure (global_State *g, CClosure *cl) {
  int i;
  for (i = 0; i < cl->nupvalues; i++)  
    markvalue(g, &cl->upvalue[i]);
  return 1 + cl->nupvalues;
}


static int traverseLclosure (global_State *g, LClosure *cl) {
  int i;
  markobjectN(g, cl->p);  
  for (i = 0; i < cl->nupvalues; i++) {  
    UpVal *uv = cl->upvals[i];
    markobjectN(g, uv);  
  }
  return 1 + cl->nupvalues;
}



static int traversethread (global_State *g, lua_State *th) {
  UpVal *uv;
  StkId o = th->stack;
  if (o == NULL)
    return 1;  
  lua_assert(g->gcstate == GCSatomic || th->openupval == NULL || isintwups(th));
  for (; o < th->top; o++)  
    markvalue(g, s2v(o));
  for (uv = th->openupval; uv != NULL; uv = uv->u.open.next)
    markobject(g, uv);  
  if (g->gcstate == GCSatomic) {  
    StkId lim = th->stack + th->stacksize;  
    for (; o < lim; o++)  
      setnilvalue(s2v(o));
    
    if (!isintwups(th) && th->openupval != NULL) {
      th->twups = g->twups;  
      g->twups = th;
    }
  }
  else if (!g->gcemergency)
    luaD_shrinkstack(th); 
  return 1 + th->stacksize;
}



static lu_mem propagatemark (global_State *g) {
  GCObject *o = g->gray;
  gray2black(o);
  g->gray = *getgclist(o);  
  switch (o->tt) {
    case LUA_VTABLE: return traversetable(g, gco2t(o));
    case LUA_VUSERDATA: return traverseudata(g, gco2u(o));
    case LUA_VLCL: return traverseLclosure(g, gco2lcl(o));
    case LUA_VCCL: return traverseCclosure(g, gco2ccl(o));
    case LUA_VPROTO: return traverseproto(g, gco2p(o));
    case LUA_VTHREAD: {
      lua_State *th = gco2th(o);
      linkgclist(th, g->grayagain);  
      black2gray(o);
      return traversethread(g, th);
    }
    default: lua_assert(0); return 0;
  }
}


static lu_mem propagateall (global_State *g) {
  lu_mem tot = 0;
  while (g->gray)
    tot += propagatemark(g);
  return tot;
}



static void convergeephemerons (global_State *g) {
  int changed;
  int dir = 0;
  do {
    GCObject *w;
    GCObject *next = g->ephemeron;  
    g->ephemeron = NULL;  
    changed = 0;
    while ((w = next) != NULL) {  
      next = gco2t(w)->gclist;  
      if (traverseephemeron(g, gco2t(w), dir)) {  
        propagateall(g);  
        changed = 1;  
      }
    }
    dir = !dir;  
  } while (changed);  
}








static void clearbykeys (global_State *g, GCObject *l) {
  for (; l; l = gco2t(l)->gclist) {
    Table *h = gco2t(l);
    Node *limit = gnodelast(h);
    Node *n;
    for (n = gnode(h, 0); n < limit; n++) {
      if (iscleared(g, gckeyN(n)))  
        setempty(gval(n));  
      if (isempty(gval(n)))  
        clearkey(n);  
    }
  }
}



static void clearbyvalues (global_State *g, GCObject *l, GCObject *f) {
  for (; l != f; l = gco2t(l)->gclist) {
    Table *h = gco2t(l);
    Node *n, *limit = gnodelast(h);
    unsigned int i;
    unsigned int asize = luaH_realasize(h);
    for (i = 0; i < asize; i++) {
      TValue *o = &h->array[i];
      if (iscleared(g, gcvalueN(o)))  
        setempty(o);  
    }
    for (n = gnode(h, 0); n < limit; n++) {
      if (iscleared(g, gcvalueN(gval(n))))  
        setempty(gval(n));  
      if (isempty(gval(n)))  
        clearkey(n);  
    }
  }
}


static void freeupval (lua_State *L, UpVal *uv) {
  if (upisopen(uv))
    luaF_unlinkupval(uv);
  luaM_free(L, uv);
}


static void freeobj (lua_State *L, GCObject *o) {
  switch (o->tt) {
    case LUA_VPROTO:
      luaF_freeproto(L, gco2p(o));
      break;
    case LUA_VUPVAL:
      freeupval(L, gco2upv(o));
      break;
    case LUA_VLCL:
      luaM_freemem(L, o, sizeLclosure(gco2lcl(o)->nupvalues));
      break;
    case LUA_VCCL:
      luaM_freemem(L, o, sizeCclosure(gco2ccl(o)->nupvalues));
      break;
    case LUA_VTABLE:
      luaH_free(L, gco2t(o));
      break;
    case LUA_VTHREAD:
      luaE_freethread(L, gco2th(o));
      break;
    case LUA_VUSERDATA: {
      Udata *u = gco2u(o);
      luaM_freemem(L, o, sizeudata(u->nuvalue, u->len));
      break;
    }
    case LUA_VSHRSTR:
      luaS_remove(L, gco2ts(o));  
      luaM_freemem(L, o, sizelstring(gco2ts(o)->shrlen));
      break;
    case LUA_VLNGSTR:
      luaM_freemem(L, o, sizelstring(gco2ts(o)->u.lnglen));
      break;
    default: lua_assert(0);
  }
}



static GCObject **sweeplist (lua_State *L, GCObject **p, int countin, int *countout) {
  global_State *g = G(L);
  int ow = otherwhite(g);
  int i;
  int white = luaC_white(g);  
  for (i = 0; *p != NULL && i < countin; i++) {
    GCObject *curr = *p;
    int marked = curr->marked;
    if (isdeadm(ow, marked)) {  
      *p = curr->next;  
      freeobj(L, curr);  
    }
    else {  
      curr->marked = cast_byte((marked & maskcolors) | white);
      p = &curr->next;  
    }
  }
  if (countout)
    *countout = i;  
  return (*p == NULL) ? NULL : p;
}



static GCObject **sweeptolive (lua_State *L, GCObject **p) {
  GCObject **old = p;
  do {
    p = sweeplist(L, p, 1, NULL);
  } while (p == old);
  return p;
}







static void checkSizes (lua_State *L, global_State *g) {
  if (!g->gcemergency) {
    if (g->strt.nuse < g->strt.size / 4) {  
      l_mem olddebt = g->GCdebt;
      luaS_resize(L, g->strt.size / 2);
      g->GCestimate += g->GCdebt - olddebt;  
    }
  }
}



static GCObject *udata2finalize (global_State *g) {
  GCObject *o = g->tobefnz;  
  lua_assert(tofinalize(o));
  g->tobefnz = o->next;  
  o->next = g->allgc;  
  g->allgc = o;
  resetbit(o->marked, FINALIZEDBIT);  
  if (issweepphase(g))
    makewhite(g, o);  
  return o;
}


static void dothecall (lua_State *L, void *ud) {
  UNUSED(ud);
  luaD_callnoyield(L, L->top - 2, 0);
}


static void GCTM (lua_State *L) {
  global_State *g = G(L);
  const TValue *tm;
  TValue v;
  lua_assert(!g->gcemergency);
  setgcovalue(L, &v, udata2finalize(g));
  tm = luaT_gettmbyobj(L, &v, TM_GC);
  if (!notm(tm)) {  
    int status;
    lu_byte oldah = L->allowhook;
    int running  = g->gcrunning;
    L->allowhook = 0;  
    g->gcrunning = 0;  
    setobj2s(L, L->top++, tm);  
    setobj2s(L, L->top++, &v);  
    L->ci->callstatus |= CIST_FIN;  
    status = luaD_pcall(L, dothecall, NULL, savestack(L, L->top - 2), 0);
    L->ci->callstatus &= ~CIST_FIN;  
    L->allowhook = oldah;  
    g->gcrunning = running;  
    if (unlikely(status != LUA_OK)) {  
      luaE_warnerror(L, "__gc metamethod");
      L->top--;  
    }
  }
}



static int runafewfinalizers (lua_State *L, int n) {
  global_State *g = G(L);
  int i;
  for (i = 0; i < n && g->tobefnz; i++)
    GCTM(L);  
  return i;
}



static void callallpendingfinalizers (lua_State *L) {
  global_State *g = G(L);
  while (g->tobefnz)
    GCTM(L);
}



static GCObject **findlast (GCObject **p) {
  while (*p != NULL)
    p = &(*p)->next;
  return p;
}



static void separatetobefnz (global_State *g, int all) {
  GCObject *curr;
  GCObject **p = &g->finobj;
  GCObject **lastnext = findlast(&g->tobefnz);
  while ((curr = *p) != g->finobjold) {  
    lua_assert(tofinalize(curr));
    if (!(iswhite(curr) || all))  
      p = &curr->next;  
    else {
      if (curr == g->finobjsur)  
        g->finobjsur = curr->next;  
      *p = curr->next;  
      curr->next = *lastnext;  
      *lastnext = curr;
      lastnext = &curr->next;
    }
  }
}



void luaC_checkfinalizer (lua_State *L, GCObject *o, Table *mt) {
  global_State *g = G(L);
  if (tofinalize(o) ||                  gfasttm(g, mt, TM_GC) == NULL)
    return;  
  else {  
    GCObject **p;
    if (issweepphase(g)) {
      makewhite(g, o);  
      if (g->sweepgc == &o->next)  
        g->sweepgc = sweeptolive(L, g->sweepgc);  
    }
    else {  
      if (o == g->survival)
        g->survival = o->next;
      if (o == g->old)
        g->old = o->next;
      if (o == g->reallyold)
        g->reallyold = o->next;
    }
    
    for (p = &g->allgc; *p != o; p = &(*p)->next) {  }
    *p = o->next;  
    o->next = g->finobj;  
    g->finobj = o;
    l_setbit(o->marked, FINALIZEDBIT);  
  }
}






static void setpause (global_State *g);







static void sweep2old (lua_State *L, GCObject **p) {
  GCObject *curr;
  while ((curr = *p) != NULL) {
    if (iswhite(curr)) {  
      lua_assert(isdead(G(L), curr));
      *p = curr->next;  
      freeobj(L, curr);  
    }
    else {  
      setage(curr, G_OLD);
      p = &curr->next;  
    }
  }
}



static GCObject **sweepgen (lua_State *L, global_State *g, GCObject **p, GCObject *limit) {
  static const lu_byte nextage[] = {
    G_SURVIVAL,   G_OLD1, G_OLD1, G_OLD, G_OLD, G_TOUCHED1, G_TOUCHED2 };






  int white = luaC_white(g);
  GCObject *curr;
  while ((curr = *p) != limit) {
    if (iswhite(curr)) {  
      lua_assert(!isold(curr) && isdead(g, curr));
      *p = curr->next;  
      freeobj(L, curr);  
    }
    else {  
      if (getage(curr) == G_NEW)
        curr->marked = cast_byte((curr->marked & maskgencolors) | white);
      setage(curr, nextage[getage(curr)]);
      p = &curr->next;  
    }
  }
  return p;
}



static void whitelist (global_State *g, GCObject *p) {
  int white = luaC_white(g);
  for (; p != NULL; p = p->next)
    p->marked = cast_byte((p->marked & maskcolors) | white);
}



static GCObject **correctgraylist (GCObject **p) {
  GCObject *curr;
  while ((curr = *p) != NULL) {
    switch (curr->tt) {
      case LUA_VTABLE: case LUA_VUSERDATA: {
        GCObject **next = getgclist(curr);
        if (getage(curr) == G_TOUCHED1) {  
          lua_assert(isgray(curr));
          gray2black(curr);  
          changeage(curr, G_TOUCHED1, G_TOUCHED2);
          p = next;  
        }
        else {  
          if (!iswhite(curr)) {  
            lua_assert(isold(curr));
            if (getage(curr) == G_TOUCHED2)  
              changeage(curr, G_TOUCHED2, G_OLD);  
            gray2black(curr);  
          }
          
          *p = *next;  
        }
        break;
      }
      case LUA_VTHREAD: {
        lua_State *th = gco2th(curr);
        lua_assert(!isblack(th));
        if (iswhite(th))  
          *p = th->gclist;  
        else   p = &th->gclist;
        break;
      }
      default: lua_assert(0);  
    }
  }
  return p;
}



static void correctgraylists (global_State *g) {
  GCObject **list = correctgraylist(&g->grayagain);
  *list = g->weak; g->weak = NULL;
  list = correctgraylist(list);
  *list = g->allweak; g->allweak = NULL;
  list = correctgraylist(list);
  *list = g->ephemeron; g->ephemeron = NULL;
  correctgraylist(list);
}



static void markold (global_State *g, GCObject *from, GCObject *to) {
  GCObject *p;
  for (p = from; p != to; p = p->next) {
    if (getage(p) == G_OLD1) {
      lua_assert(!iswhite(p));
      if (isblack(p)) {
        black2gray(p);  
        reallymarkobject(g, p);
      }
    }
  }
}



static void finishgencycle (lua_State *L, global_State *g) {
  correctgraylists(g);
  checkSizes(L, g);
  g->gcstate = GCSpropagate;  
  if (!g->gcemergency)
    callallpendingfinalizers(L);
}



static void youngcollection (lua_State *L, global_State *g) {
  GCObject **psurvival;  
  lua_assert(g->gcstate == GCSpropagate);
  markold(g, g->allgc, g->reallyold);
  markold(g, g->finobj, g->finobjrold);
  atomic(L);

  
  psurvival = sweepgen(L, g, &g->allgc, g->survival);
  
  sweepgen(L, g, psurvival, g->reallyold);
  g->reallyold = g->old;
  g->old = *psurvival;  
  g->survival = g->allgc;  

  
  psurvival = sweepgen(L, g, &g->finobj, g->finobjsur);
  
  sweepgen(L, g, psurvival, g->finobjrold);
  g->finobjrold = g->finobjold;
  g->finobjold = *psurvival;  
  g->finobjsur = g->finobj;  

  sweepgen(L, g, &g->tobefnz, NULL);

  finishgencycle(L, g);
}


static void atomic2gen (lua_State *L, global_State *g) {
  
  sweep2old(L, &g->allgc);
  
  g->reallyold = g->old = g->survival = g->allgc;

  
  sweep2old(L, &g->finobj);
  g->finobjrold = g->finobjold = g->finobjsur = g->finobj;

  sweep2old(L, &g->tobefnz);

  g->gckind = KGC_GEN;
  g->lastatomic = 0;
  g->GCestimate = gettotalbytes(g);  
  finishgencycle(L, g);
}



static lu_mem entergen (lua_State *L, global_State *g) {
  lu_mem numobjs;
  luaC_runtilstate(L, bitmask(GCSpause));  
  luaC_runtilstate(L, bitmask(GCSpropagate));  
  numobjs = atomic(L);  
  atomic2gen(L, g);
  return numobjs;
}



static void enterinc (global_State *g) {
  whitelist(g, g->allgc);
  g->reallyold = g->old = g->survival = NULL;
  whitelist(g, g->finobj);
  whitelist(g, g->tobefnz);
  g->finobjrold = g->finobjold = g->finobjsur = NULL;
  g->gcstate = GCSpause;
  g->gckind = KGC_INC;
  g->lastatomic = 0;
}



void luaC_changemode (lua_State *L, int newmode) {
  global_State *g = G(L);
  if (newmode != g->gckind) {
    if (newmode == KGC_GEN)  
      entergen(L, g);
    else enterinc(g);
  }
  g->lastatomic = 0;
}



static lu_mem fullgen (lua_State *L, global_State *g) {
  enterinc(g);
  return entergen(L, g);
}



static void setminordebt (global_State *g) {
  luaE_setdebt(g, -(cast(l_mem, (gettotalbytes(g) / 100)) * g->genminormul));
}



static void stepgenfull (lua_State *L, global_State *g) {
  lu_mem newatomic;  
  lu_mem lastatomic = g->lastatomic;  
  if (g->gckind == KGC_GEN)  
    enterinc(g);  
  luaC_runtilstate(L, bitmask(GCSpropagate));  
  newatomic = atomic(L);  
  if (newatomic < lastatomic + (lastatomic >> 3)) {  
    atomic2gen(L, g);  
    setminordebt(g);
  }
  else {  
    g->GCestimate = gettotalbytes(g);  ;
    entersweep(L);
    luaC_runtilstate(L, bitmask(GCSpause));  
    setpause(g);
    g->lastatomic = newatomic;
  }
}



static void genstep (lua_State *L, global_State *g) {
  if (g->lastatomic != 0)  
    stepgenfull(L, g);  
  else {
    lu_mem majorbase = g->GCestimate;  
    lu_mem majorinc = (majorbase / 100) * getgcparam(g->genmajormul);
    if (g->GCdebt > 0 && gettotalbytes(g) > majorbase + majorinc) {
      lu_mem numobjs = fullgen(L, g);  
      if (gettotalbytes(g) < majorbase + (majorinc / 2)) {
        
        setminordebt(g);
      }
      else {  
        g->lastatomic = numobjs;  
        setpause(g);  
      }
    }
    else {  
      youngcollection(L, g);
      setminordebt(g);
      g->GCestimate = majorbase;  
    }
  }
  lua_assert(isdecGCmodegen(g));
}








static void setpause (global_State *g) {
  l_mem threshold, debt;
  int pause = getgcparam(g->gcpause);
  l_mem estimate = g->GCestimate / PAUSEADJ;  
  lua_assert(estimate > 0);
  threshold = (pause < MAX_LMEM / estimate)  
            ? estimate * pause   : MAX_LMEM;
  debt = gettotalbytes(g) - threshold;
  if (debt > 0) debt = 0;
  luaE_setdebt(g, debt);
}



static void entersweep (lua_State *L) {
  global_State *g = G(L);
  g->gcstate = GCSswpallgc;
  lua_assert(g->sweepgc == NULL);
  g->sweepgc = sweeptolive(L, &g->allgc);
}



static void deletelist (lua_State *L, GCObject *p, GCObject *limit) {
  while (p != limit) {
    GCObject *next = p->next;
    freeobj(L, p);
    p = next;
  }
}



void luaC_freeallobjects (lua_State *L) {
  global_State *g = G(L);
  luaC_changemode(L, KGC_INC);
  separatetobefnz(g, 1);  
  lua_assert(g->finobj == NULL);
  callallpendingfinalizers(L);
  deletelist(L, g->allgc, obj2gco(g->mainthread));
  deletelist(L, g->finobj, NULL);
  deletelist(L, g->fixedgc, NULL);  
  lua_assert(g->strt.nuse == 0);
}


static lu_mem atomic (lua_State *L) {
  global_State *g = G(L);
  lu_mem work = 0;
  GCObject *origweak, *origall;
  GCObject *grayagain = g->grayagain;  
  g->grayagain = NULL;
  lua_assert(g->ephemeron == NULL && g->weak == NULL);
  lua_assert(!iswhite(g->mainthread));
  g->gcstate = GCSatomic;
  markobject(g, L);  
  
  markvalue(g, &g->l_registry);
  markmt(g);  
  work += propagateall(g);  
  
  work += remarkupvals(g);
  work += propagateall(g);  
  g->gray = grayagain;
  work += propagateall(g);  
  convergeephemerons(g);
  
  
  clearbyvalues(g, g->weak, NULL);
  clearbyvalues(g, g->allweak, NULL);
  origweak = g->weak; origall = g->allweak;
  separatetobefnz(g, 0);  
  work += markbeingfnz(g);  
  work += propagateall(g);  
  convergeephemerons(g);
  
  
  clearbykeys(g, g->ephemeron);  
  clearbykeys(g, g->allweak);  
  
  clearbyvalues(g, g->weak, origweak);
  clearbyvalues(g, g->allweak, origall);
  luaS_clearcache(g);
  g->currentwhite = cast_byte(otherwhite(g));  
  lua_assert(g->gray == NULL);
  return work;  
}


static int sweepstep (lua_State *L, global_State *g, int nextstate, GCObject **nextlist) {
  if (g->sweepgc) {
    l_mem olddebt = g->GCdebt;
    int count;
    g->sweepgc = sweeplist(L, g->sweepgc, GCSWEEPMAX, &count);
    g->GCestimate += g->GCdebt - olddebt;  
    return count;
  }
  else {  
    g->gcstate = nextstate;
    g->sweepgc = nextlist;
    return 0;  
  }
}


static lu_mem singlestep (lua_State *L) {
  global_State *g = G(L);
  switch (g->gcstate) {
    case GCSpause: {
      restartcollection(g);
      g->gcstate = GCSpropagate;
      return 1;
    }
    case GCSpropagate: {
      if (g->gray == NULL) {  
        g->gcstate = GCSenteratomic;  
        return 0;
      }
      else return propagatemark(g);
    }
    case GCSenteratomic: {
      lu_mem work = atomic(L);  
      entersweep(L);
      g->GCestimate = gettotalbytes(g);  ;
      return work;
    }
    case GCSswpallgc: {  
      return sweepstep(L, g, GCSswpfinobj, &g->finobj);
    }
    case GCSswpfinobj: {  
      return sweepstep(L, g, GCSswptobefnz, &g->tobefnz);
    }
    case GCSswptobefnz: {  
      return sweepstep(L, g, GCSswpend, NULL);
    }
    case GCSswpend: {  
      checkSizes(L, g);
      g->gcstate = GCScallfin;
      return 0;
    }
    case GCScallfin: {  
      if (g->tobefnz && !g->gcemergency) {
        int n = runafewfinalizers(L, GCFINMAX);
        return n * GCFINALIZECOST;
      }
      else {  
        g->gcstate = GCSpause;  
        return 0;
      }
    }
    default: lua_assert(0); return 0;
  }
}



void luaC_runtilstate (lua_State *L, int statesmask) {
  global_State *g = G(L);
  while (!testbit(statesmask, g->gcstate))
    singlestep(L);
}



static void incstep (lua_State *L, global_State *g) {
  int stepmul = (getgcparam(g->gcstepmul) | 1);  
  l_mem debt = (g->GCdebt / WORK2MEM) * stepmul;
  l_mem stepsize = (g->gcstepsize <= log2maxs(l_mem))
                 ? ((cast(l_mem, 1) << g->gcstepsize) / WORK2MEM) * stepmul : MAX_LMEM;
  do {  
    lu_mem work = singlestep(L);  
    debt -= work;
  } while (debt > -stepsize && g->gcstate != GCSpause);
  if (g->gcstate == GCSpause)
    setpause(g);  
  else {
    debt = (debt / stepmul) * WORK2MEM;  
    luaE_setdebt(g, debt);
  }
}


void luaC_step (lua_State *L) {
  global_State *g = G(L);
  lua_assert(!g->gcemergency);
  if (g->gcrunning) {  
    if(isdecGCmodegen(g))
      genstep(L, g);
    else incstep(L, g);
  }
}



static void fullinc (lua_State *L, global_State *g) {
  if (keepinvariant(g))  
    entersweep(L); 
  
  luaC_runtilstate(L, bitmask(GCSpause));
  luaC_runtilstate(L, bitmask(GCScallfin));  
  
  lua_assert(g->GCestimate == gettotalbytes(g));
  luaC_runtilstate(L, bitmask(GCSpause));  
  setpause(g);
}



void luaC_fullgc (lua_State *L, int isemergency) {
  global_State *g = G(L);
  lua_assert(!g->gcemergency);
  g->gcemergency = isemergency;  
  if (g->gckind == KGC_INC)
    fullinc(L, g);
  else fullgen(L, g);
  g->gcemergency = 0;
}




