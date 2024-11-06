



























typedef struct LX {
  lu_byte extra_[LUA_EXTRASPACE];
  lua_State l;
} LX;



typedef struct LG {
  LX l;
  global_State g;
} LG;















static unsigned int luai_makeseed (lua_State *L) {
  char buff[3 * sizeof(size_t)];
  unsigned int h = cast_uint(time(NULL));
  int p = 0;
  addbuff(buff, p, L);  
  addbuff(buff, p, &h);  
  addbuff(buff, p, &lua_newstate);  
  lua_assert(p == sizeof(buff));
  return luaS_hash(buff, p, h, 1);
}





void luaE_setdebt (global_State *g, l_mem debt) {
  l_mem tb = gettotalbytes(g);
  lua_assert(tb > 0);
  if (debt < tb - MAX_LMEM)
    debt = tb - MAX_LMEM;  
  g->totalbytes = tb - debt;
  g->GCdebt = debt;
}


LUA_API int lua_setcstacklimit (lua_State *L, unsigned int limit) {
  global_State *g = G(L);
  int ccalls;
  luaE_freeCI(L);  
  ccalls = getCcalls(L);
  if (limit >= 40000)
    return 0;  
  limit += CSTACKERR;
  if (L != g-> mainthread)
    return 0;  
  else if (ccalls <= CSTACKERR)
    return 0;  
  else {
    int diff = limit - g->Cstacklimit;
    if (ccalls + diff <= CSTACKERR)
      return 0;  
    g->Cstacklimit = limit;  
    L->nCcalls += diff;  
    return limit - diff - CSTACKERR;  
  }
}




void luaE_enterCcall (lua_State *L) {
  int ncalls = getCcalls(L);
  L->nCcalls--;
  if (ncalls <= CSTACKERR) {  
    luaE_freeCI(L);  
    ncalls = getCcalls(L);  
    if (ncalls <= CSTACKERR) {  
      if (ncalls <= CSTACKERRMARK)  
        luaD_throw(L, LUA_ERRERR);  
      else if (ncalls >= CSTACKMARK) {
        
        L->nCcalls = (CSTACKMARK - 1);  
        luaG_runerror(L, "C stack overflow");
      }
      
    }
  }
}


CallInfo *luaE_extendCI (lua_State *L) {
  CallInfo *ci;
  lua_assert(L->ci->next == NULL);
  luaE_enterCcall(L);
  ci = luaM_new(L, CallInfo);
  lua_assert(L->ci->next == NULL);
  L->ci->next = ci;
  ci->previous = L->ci;
  ci->next = NULL;
  ci->u.l.trap = 0;
  L->nci++;
  return ci;
}



void luaE_freeCI (lua_State *L) {
  CallInfo *ci = L->ci;
  CallInfo *next = ci->next;
  ci->next = NULL;
  L->nCcalls += L->nci;  
  while ((ci = next) != NULL) {
    next = ci->next;
    luaM_free(L, ci);
    L->nci--;
  }
  L->nCcalls -= L->nci;  
}



void luaE_shrinkCI (lua_State *L) {
  CallInfo *ci = L->ci->next;  
  CallInfo *next;
  if (ci == NULL)
    return;  
  L->nCcalls += L->nci;  
  while ((next = ci->next) != NULL) {  
    CallInfo *next2 = next->next;  
    ci->next = next2;  
    L->nci--;
    luaM_free(L, next);  
    if (next2 == NULL)
      break;  
    else {
      next2->previous = ci;
      ci = next2;  
    }
  }
  L->nCcalls -= L->nci;  
}


static void stack_init (lua_State *L1, lua_State *L) {
  int i; CallInfo *ci;
  
  L1->stack = luaM_newvector(L, BASIC_STACK_SIZE, StackValue);
  L1->stacksize = BASIC_STACK_SIZE;
  for (i = 0; i < BASIC_STACK_SIZE; i++)
    setnilvalue(s2v(L1->stack + i));  
  L1->top = L1->stack;
  L1->stack_last = L1->stack + L1->stacksize - EXTRA_STACK;
  
  ci = &L1->base_ci;
  ci->next = ci->previous = NULL;
  ci->callstatus = CIST_C;
  ci->func = L1->top;
  ci->u.c.k = NULL;
  ci->nresults = 0;
  setnilvalue(s2v(L1->top));  
  L1->top++;
  ci->top = L1->top + LUA_MINSTACK;
  L1->ci = ci;
}


static void freestack (lua_State *L) {
  if (L->stack == NULL)
    return;  
  L->ci = &L->base_ci;  
  luaE_freeCI(L);
  lua_assert(L->nci == 0);
  luaM_freearray(L, L->stack, L->stacksize);  
}



static void init_registry (lua_State *L, global_State *g) {
  TValue temp;
  
  Table *registry = luaH_new(L);
  sethvalue(L, &g->l_registry, registry);
  luaH_resize(L, registry, LUA_RIDX_LAST, 0);
  
  setthvalue(L, &temp, L);  
  luaH_setint(L, registry, LUA_RIDX_MAINTHREAD, &temp);
  
  sethvalue(L, &temp, luaH_new(L));  
  luaH_setint(L, registry, LUA_RIDX_GLOBALS, &temp);
}



static void f_luaopen (lua_State *L, void *ud) {
  global_State *g = G(L);
  UNUSED(ud);
  stack_init(L, L);  
  init_registry(L, g);
  luaS_init(L);
  luaT_init(L);
  luaX_init(L);
  g->gcrunning = 1;  
  setnilvalue(&g->nilvalue);
  luai_userstateopen(L);
}



static void preinit_thread (lua_State *L, global_State *g) {
  G(L) = g;
  L->stack = NULL;
  L->ci = NULL;
  L->nci = 0;
  L->stacksize = 0;
  L->twups = L;  
  L->errorJmp = NULL;
  L->hook = NULL;
  L->hookmask = 0;
  L->basehookcount = 0;
  L->allowhook = 1;
  resethookcount(L);
  L->openupval = NULL;
  L->status = LUA_OK;
  L->errfunc = 0;
}


static void close_state (lua_State *L) {
  global_State *g = G(L);
  luaF_close(L, L->stack, CLOSEPROTECT);  
  luaC_freeallobjects(L);  
  if (ttisnil(&g->nilvalue))  
    luai_userstateclose(L);
  luaM_freearray(L, G(L)->strt.hash, G(L)->strt.size);
  freestack(L);
  lua_assert(gettotalbytes(g) == sizeof(LG));
  (*g->frealloc)(g->ud, fromstate(L), sizeof(LG), 0);  
}


LUA_API lua_State *lua_newthread (lua_State *L) {
  global_State *g;
  lua_State *L1;
  lua_lock(L);
  g = G(L);
  luaC_checkGC(L);
  
  L1 = &cast(LX *, luaM_newobject(L, LUA_TTHREAD, sizeof(LX)))->l;
  L1->marked = luaC_white(g);
  L1->tt = LUA_VTHREAD;
  
  L1->next = g->allgc;
  g->allgc = obj2gco(L1);
  
  setthvalue2s(L, L->top, L1);
  api_incr_top(L);
  preinit_thread(L1, g);
  L1->nCcalls = getCcalls(L);
  L1->hookmask = L->hookmask;
  L1->basehookcount = L->basehookcount;
  L1->hook = L->hook;
  resethookcount(L1);
  
  memcpy(lua_getextraspace(L1), lua_getextraspace(g->mainthread), LUA_EXTRASPACE);
  luai_userstatethread(L, L1);
  stack_init(L1, L);  
  lua_unlock(L);
  return L1;
}


void luaE_freethread (lua_State *L, lua_State *L1) {
  LX *l = fromstate(L1);
  luaF_close(L1, L1->stack, NOCLOSINGMETH);  
  lua_assert(L1->openupval == NULL);
  luai_userstatefree(L, L1);
  freestack(L1);
  luaM_free(L, l);
}


int lua_resetthread (lua_State *L) {
  CallInfo *ci;
  int status;
  lua_lock(L);
  L->ci = ci = &L->base_ci;  
  setnilvalue(s2v(L->stack));  
  ci->func = L->stack;
  ci->callstatus = CIST_C;
  status = luaF_close(L, L->stack, CLOSEPROTECT);
  if (status != CLOSEPROTECT)  
    luaD_seterrorobj(L, status, L->stack + 1);
  else {
    status = LUA_OK;
    L->top = L->stack + 1;
  }
  ci->top = L->top + LUA_MINSTACK;
  L->status = status;
  lua_unlock(L);
  return status;
}


LUA_API lua_State *lua_newstate (lua_Alloc f, void *ud) {
  int i;
  lua_State *L;
  global_State *g;
  LG *l = cast(LG *, (*f)(ud, NULL, LUA_TTHREAD, sizeof(LG)));
  if (l == NULL) return NULL;
  L = &l->l.l;
  g = &l->g;
  L->tt = LUA_VTHREAD;
  g->currentwhite = bitmask(WHITE0BIT);
  L->marked = luaC_white(g);
  preinit_thread(L, g);
  g->allgc = obj2gco(L);  
  L->next = NULL;
  g->Cstacklimit = L->nCcalls = LUAI_MAXCSTACK + CSTACKERR;
  incnny(L);  
  g->frealloc = f;
  g->ud = ud;
  g->warnf = NULL;
  g->ud_warn = NULL;
  g->mainthread = L;
  g->seed = luai_makeseed(L);
  g->gcrunning = 0;  
  g->strt.size = g->strt.nuse = 0;
  g->strt.hash = NULL;
  setnilvalue(&g->l_registry);
  g->panic = NULL;
  g->gcstate = GCSpause;
  g->gckind = KGC_INC;
  g->gcemergency = 0;
  g->finobj = g->tobefnz = g->fixedgc = NULL;
  g->survival = g->old = g->reallyold = NULL;
  g->finobjsur = g->finobjold = g->finobjrold = NULL;
  g->sweepgc = NULL;
  g->gray = g->grayagain = NULL;
  g->weak = g->ephemeron = g->allweak = NULL;
  g->twups = NULL;
  g->totalbytes = sizeof(LG);
  g->GCdebt = 0;
  g->lastatomic = 0;
  setivalue(&g->nilvalue, 0);  
  setgcparam(g->gcpause, LUAI_GCPAUSE);
  setgcparam(g->gcstepmul, LUAI_GCMUL);
  g->gcstepsize = LUAI_GCSTEPSIZE;
  setgcparam(g->genmajormul, LUAI_GENMAJORMUL);
  g->genminormul = LUAI_GENMINORMUL;
  for (i=0; i < LUA_NUMTAGS; i++) g->mt[i] = NULL;
  if (luaD_rawrunprotected(L, f_luaopen, NULL) != LUA_OK) {
    
    close_state(L);
    L = NULL;
  }
  return L;
}


LUA_API void lua_close (lua_State *L) {
  lua_lock(L);
  L = G(L)->mainthread;  
  close_state(L);
}


void luaE_warning (lua_State *L, const char *msg, int tocont) {
  lua_WarnFunction wf = G(L)->warnf;
  if (wf != NULL)
    wf(G(L)->ud_warn, msg, tocont);
}



void luaE_warnerror (lua_State *L, const char *where) {
  TValue *errobj = s2v(L->top - 1);  
  const char *msg = (ttisstring(errobj))
                  ? svalue(errobj)
                  : "error object is not a string";
  
  luaE_warning(L, "error in ", 1);
  luaE_warning(L, where, 1);
  luaE_warning(L, " (", 1);
  luaE_warning(L, msg, 1);
  luaE_warning(L, ")", 0);
}

