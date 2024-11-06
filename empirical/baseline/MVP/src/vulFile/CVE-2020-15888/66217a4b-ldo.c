




































































struct lua_longjmp {
  struct lua_longjmp *previous;
  luai_jmpbuf b;
  volatile int status;  
};


void luaD_seterrorobj (lua_State *L, int errcode, StkId oldtop) {
  switch (errcode) {
    case LUA_ERRMEM: {  
      setsvalue2s(L, oldtop, G(L)->memerrmsg); 
      break;
    }
    case LUA_ERRERR: {
      setsvalue2s(L, oldtop, luaS_newliteral(L, "error in error handling"));
      break;
    }
    case CLOSEPROTECT: {
      setnilvalue(s2v(oldtop));  
      break;
    }
    default: {
      setobjs2s(L, oldtop, L->top - 1);  
      break;
    }
  }
  L->top = oldtop + 1;
}


l_noret luaD_throw (lua_State *L, int errcode) {
  if (L->errorJmp) {  
    L->errorJmp->status = errcode;  
    LUAI_THROW(L, L->errorJmp);  
  }
  else {  
    global_State *g = G(L);
    errcode = luaF_close(L, L->stack, errcode);  
    L->status = cast_byte(errcode);  
    if (g->mainthread->errorJmp) {  
      setobjs2s(L, g->mainthread->top++, L->top - 1);  
      luaD_throw(g->mainthread, errcode);  
    }
    else {  
      if (g->panic) {  
        luaD_seterrorobj(L, errcode, L->top);  
        if (L->ci->top < L->top)
          L->ci->top = L->top;  
        lua_unlock(L);
        g->panic(L);  
      }
      abort();
    }
  }
}


int luaD_rawrunprotected (lua_State *L, Pfunc f, void *ud) {
  global_State *g = G(L);
  l_uint32 oldnCcalls = g->Cstacklimit - (L->nCcalls + L->nci);
  struct lua_longjmp lj;
  lj.status = LUA_OK;
  lj.previous = L->errorJmp;  
  L->errorJmp = &lj;
  LUAI_TRY(L, &lj, (*f)(L, ud);
  );
  L->errorJmp = lj.previous;  
  L->nCcalls = g->Cstacklimit - oldnCcalls - L->nci;
  return lj.status;
}





static void correctstack (lua_State *L, StkId oldstack, StkId newstack) {
  CallInfo *ci;
  UpVal *up;
  if (oldstack == newstack)
    return;  
  L->top = (L->top - oldstack) + newstack;
  for (up = L->openupval; up != NULL; up = up->u.open.next)
    up->v = s2v((uplevel(up) - oldstack) + newstack);
  for (ci = L->ci; ci != NULL; ci = ci->previous) {
    ci->top = (ci->top - oldstack) + newstack;
    ci->func = (ci->func - oldstack) + newstack;
    if (isLua(ci))
      ci->u.l.trap = 1;  
  }
}






int luaD_reallocstack (lua_State *L, int newsize, int raiseerror) {
  int lim = L->stacksize;
  StkId newstack = luaM_reallocvector(L, L->stack, lim, newsize, StackValue);
  lua_assert(newsize <= LUAI_MAXSTACK || newsize == ERRORSTACKSIZE);
  lua_assert(L->stack_last - L->stack == L->stacksize - EXTRA_STACK);
  if (unlikely(newstack == NULL)) {  
    if (raiseerror)
      luaM_error(L);
    else return 0;  
  }
  for (; lim < newsize; lim++)
    setnilvalue(s2v(newstack + lim)); 
  correctstack(L, L->stack, newstack);
  L->stack = newstack;
  L->stacksize = newsize;
  L->stack_last = L->stack + newsize - EXTRA_STACK;
  return 1;
}



int luaD_growstack (lua_State *L, int n, int raiseerror) {
  int size = L->stacksize;
  int newsize = 2 * size;  
  if (unlikely(size > LUAI_MAXSTACK)) {  
    if (raiseerror)
      luaD_throw(L, LUA_ERRERR);  
    else return 0;
  }
  else {
    int needed = cast_int(L->top - L->stack) + n + EXTRA_STACK;
    if (newsize > LUAI_MAXSTACK)  
      newsize = LUAI_MAXSTACK;
    if (newsize < needed)  
      newsize = needed;
    if (unlikely(newsize > LUAI_MAXSTACK)) {  
      
      luaD_reallocstack(L, ERRORSTACKSIZE, raiseerror);
      if (raiseerror)
        luaG_runerror(L, "stack overflow");
      else return 0;
    }
  }  
  return luaD_reallocstack(L, newsize, raiseerror);
}


static int stackinuse (lua_State *L) {
  CallInfo *ci;
  StkId lim = L->top;
  for (ci = L->ci; ci != NULL; ci = ci->previous) {
    if (lim < ci->top) lim = ci->top;
  }
  lua_assert(lim <= L->stack_last);
  return cast_int(lim - L->stack) + 1;  
}


void luaD_shrinkstack (lua_State *L) {
  int inuse = stackinuse(L);
  int goodsize = inuse + BASIC_STACK_SIZE;
  if (goodsize > LUAI_MAXSTACK)
    goodsize = LUAI_MAXSTACK;  
  
  if (inuse <= (LUAI_MAXSTACK - EXTRA_STACK) && goodsize < L->stacksize)
    luaD_reallocstack(L, goodsize, 0);  
  else   condmovestack(L,{},{});
  luaE_shrinkCI(L);  
}


void luaD_inctop (lua_State *L) {
  luaD_checkstack(L, 1);
  L->top++;
}





void luaD_hook (lua_State *L, int event, int line, int ftransfer, int ntransfer) {
  lua_Hook hook = L->hook;
  if (hook && L->allowhook) {  
    int mask = CIST_HOOKED;
    CallInfo *ci = L->ci;
    ptrdiff_t top = savestack(L, L->top);
    ptrdiff_t ci_top = savestack(L, ci->top);
    lua_Debug ar;
    ar.event = event;
    ar.currentline = line;
    ar.i_ci = ci;
    if (ntransfer != 0) {
      mask |= CIST_TRAN;  
      ci->u2.transferinfo.ftransfer = ftransfer;
      ci->u2.transferinfo.ntransfer = ntransfer;
    }
    luaD_checkstack(L, LUA_MINSTACK);  
    if (L->top + LUA_MINSTACK > ci->top)
      ci->top = L->top + LUA_MINSTACK;
    L->allowhook = 0;  
    ci->callstatus |= mask;
    lua_unlock(L);
    (*hook)(L, &ar);
    lua_lock(L);
    lua_assert(!L->allowhook);
    L->allowhook = 1;
    ci->top = restorestack(L, ci_top);
    L->top = restorestack(L, top);
    ci->callstatus &= ~mask;
  }
}



void luaD_hookcall (lua_State *L, CallInfo *ci) {
  int hook = (ci->callstatus & CIST_TAIL) ? LUA_HOOKTAILCALL : LUA_HOOKCALL;
  Proto *p;
  if (!(L->hookmask & LUA_MASKCALL))  
    return;  
  p = clLvalue(s2v(ci->func))->p;
  L->top = ci->top;  
  ci->u.l.savedpc++;  
  luaD_hook(L, hook, -1, 1, p->numparams);
  ci->u.l.savedpc--;  
}


static StkId rethook (lua_State *L, CallInfo *ci, StkId firstres, int nres) {
  ptrdiff_t oldtop = savestack(L, L->top);  
  int delta = 0;
  if (isLuacode(ci)) {
    Proto *p = clLvalue(s2v(ci->func))->p;
    if (p->is_vararg)
      delta = ci->u.l.nextraargs + p->numparams + 1;
    if (L->top < ci->top)
      L->top = ci->top;  
  }
  if (L->hookmask & LUA_MASKRET) {  
    int ftransfer;
    ci->func += delta;  
    ftransfer = cast(unsigned short, firstres - ci->func);
    luaD_hook(L, LUA_HOOKRET, -1, ftransfer, nres);  
    ci->func -= delta;
  }
  if (isLua(ci->previous))
    L->oldpc = ci->previous->u.l.savedpc;  
  return restorestack(L, oldtop);
}



void luaD_tryfuncTM (lua_State *L, StkId func) {
  const TValue *tm = luaT_gettmbyobj(L, s2v(func), TM_CALL);
  StkId p;
  if (unlikely(ttisnil(tm)))
    luaG_typeerror(L, s2v(func), "call");  
  for (p = L->top; p > func; p--)  
    setobjs2s(L, p, p-1);
  L->top++;  
  setobj2s(L, func, tm);  
}



static void moveresults (lua_State *L, StkId res, int nres, int wanted) {
  StkId firstresult;
  int i;
  switch (wanted) {  
    case 0:  
      L->top = res;
      return;
    case 1:  
      if (nres == 0)   
        setnilvalue(s2v(res));  
      else setobjs2s(L, res, L->top - nres);
      L->top = res + 1;
      return;
    case LUA_MULTRET:
      wanted = nres;  
      break;
    default:  
      if (hastocloseCfunc(wanted)) {  
        ptrdiff_t savedres = savestack(L, res);
        luaF_close(L, res, LUA_OK);  
        res = restorestack(L, savedres);
        wanted = codeNresults(wanted);  
        if (wanted == LUA_MULTRET)
          wanted = nres;
      }
      break;
  }
  firstresult = L->top - nres;  
  
  for (i = 0; i < nres && i < wanted; i++)
    setobjs2s(L, res + i, firstresult + i);
  for (; i < wanted; i++)  
    setnilvalue(s2v(res + i));
  L->top = res + wanted;  
}



void luaD_poscall (lua_State *L, CallInfo *ci, int nres) {
  if (L->hookmask)
    L->top = rethook(L, ci, L->top - nres, nres);
  L->ci = ci->previous;  
  
  moveresults(L, ci->func, nres, ci->nresults);
}







void luaD_pretailcall (lua_State *L, CallInfo *ci, StkId func, int narg1) {
  Proto *p = clLvalue(s2v(func))->p;
  int fsize = p->maxstacksize;  
  int nfixparams = p->numparams;
  int i;
  for (i = 0; i < narg1; i++)  
    setobjs2s(L, ci->func + i, func + i);
  checkstackGC(L, fsize);
  func = ci->func;  
  for (; narg1 <= nfixparams; narg1++)
    setnilvalue(s2v(func + narg1));  
  ci->top = func + 1 + fsize;  
  lua_assert(ci->top <= L->stack_last);
  ci->u.l.savedpc = p->code;  
  ci->callstatus |= CIST_TAIL;
  L->top = func + narg1;  
}



void luaD_call (lua_State *L, StkId func, int nresults) {
  lua_CFunction f;
 retry:
  switch (ttypetag(s2v(func))) {
    case LUA_VCCL:  
      f = clCvalue(s2v(func))->f;
      goto Cfunc;
    case LUA_VLCF:  
      f = fvalue(s2v(func));
     Cfunc: {
      int n;  
      CallInfo *ci = next_ci(L);
      checkstackp(L, LUA_MINSTACK, func);  
      ci->nresults = nresults;
      ci->callstatus = CIST_C;
      ci->top = L->top + LUA_MINSTACK;
      ci->func = func;
      L->ci = ci;
      lua_assert(ci->top <= L->stack_last);
      if (L->hookmask & LUA_MASKCALL) {
        int narg = cast_int(L->top - func) - 1;
        luaD_hook(L, LUA_HOOKCALL, -1, 1, narg);
      }
      lua_unlock(L);
      n = (*f)(L);  
      lua_lock(L);
      api_checknelems(L, n);
      luaD_poscall(L, ci, n);
      break;
    }
    case LUA_VLCL: {  
      CallInfo *ci = next_ci(L);
      Proto *p = clLvalue(s2v(func))->p;
      int narg = cast_int(L->top - func) - 1;  
      int nfixparams = p->numparams;
      int fsize = p->maxstacksize;  
      checkstackp(L, fsize, func);
      ci->nresults = nresults;
      ci->u.l.savedpc = p->code;  
      ci->callstatus = 0;
      ci->top = func + 1 + fsize;
      ci->func = func;
      L->ci = ci;
      for (; narg < nfixparams; narg++)
        setnilvalue(s2v(L->top++));  
      lua_assert(ci->top <= L->stack_last);
      luaV_execute(L, ci);  
      break;
    }
    default: {  
      checkstackp(L, 1, func);  
      luaD_tryfuncTM(L, func);  
      goto retry;  
    }
  }
}



void luaD_callnoyield (lua_State *L, StkId func, int nResults) {
  incXCcalls(L);
  if (getCcalls(L) <= CSTACKERR)  
    luaE_freeCI(L);
  luaD_call(L, func, nResults);
  decXCcalls(L);
}



static void finishCcall (lua_State *L, int status) {
  CallInfo *ci = L->ci;
  int n;
  
  lua_assert(ci->u.c.k != NULL && yieldable(L));
  
  lua_assert((ci->callstatus & CIST_YPCALL) || status == LUA_YIELD);
  if (ci->callstatus & CIST_YPCALL) {  
    ci->callstatus &= ~CIST_YPCALL;  
    L->errfunc = ci->u.c.old_errfunc;  
  }
  
  adjustresults(L, ci->nresults);
  lua_unlock(L);
  n = (*ci->u.c.k)(L, status, ci->u.c.ctx);  
  lua_lock(L);
  api_checknelems(L, n);
  luaD_poscall(L, ci, n);  
}



static void unroll (lua_State *L, void *ud) {
  CallInfo *ci;
  if (ud != NULL)  
    finishCcall(L, *(int *)ud);  
  while ((ci = L->ci) != &L->base_ci) {  
    if (!isLua(ci))  
      finishCcall(L, LUA_YIELD);  
    else {  
      luaV_finishOp(L);  
      luaV_execute(L, ci);  
    }
  }
}



static CallInfo *findpcall (lua_State *L) {
  CallInfo *ci;
  for (ci = L->ci; ci != NULL; ci = ci->previous) {  
    if (ci->callstatus & CIST_YPCALL)
      return ci;
  }
  return NULL;  
}



static int recover (lua_State *L, int status) {
  StkId oldtop;
  CallInfo *ci = findpcall(L);
  if (ci == NULL) return 0;  
  
  oldtop = restorestack(L, ci->u2.funcidx);
  luaF_close(L, oldtop, status);  
  oldtop = restorestack(L, ci->u2.funcidx);
  luaD_seterrorobj(L, status, oldtop);
  L->ci = ci;
  L->allowhook = getoah(ci->callstatus);  
  luaD_shrinkstack(L);
  L->errfunc = ci->u.c.old_errfunc;
  return 1;  
}



static int resume_error (lua_State *L, const char *msg, int narg) {
  L->top -= narg;  
  setsvalue2s(L, L->top, luaS_new(L, msg));  
  api_incr_top(L);
  lua_unlock(L);
  return LUA_ERRRUN;
}



static void resume (lua_State *L, void *ud) {
  int n = *(cast(int*, ud));  
  StkId firstArg = L->top - n;  
  CallInfo *ci = L->ci;
  if (L->status == LUA_OK) {  
    luaD_call(L, firstArg - 1, LUA_MULTRET);
  }
  else {  
    lua_assert(L->status == LUA_YIELD);
    L->status = LUA_OK;  
    if (isLua(ci))  
      luaV_execute(L, ci);  
    else {  
      if (ci->u.c.k != NULL) {  
        lua_unlock(L);
        n = (*ci->u.c.k)(L, LUA_YIELD, ci->u.c.ctx); 
        lua_lock(L);
        api_checknelems(L, n);
      }
      luaD_poscall(L, ci, n);  
    }
    unroll(L, NULL);  
  }
}

LUA_API int lua_resume (lua_State *L, lua_State *from, int nargs, int *nresults) {
  int status;
  lua_lock(L);
  if (L->status == LUA_OK) {  
    if (L->ci != &L->base_ci)  
      return resume_error(L, "cannot resume non-suspended coroutine", nargs);
    else if (L->top - (L->ci->func + 1) == nargs)  
      return resume_error(L, "cannot resume dead coroutine", nargs);
  }
  else if (L->status != LUA_YIELD)  
    return resume_error(L, "cannot resume dead coroutine", nargs);
  if (from == NULL)
    L->nCcalls = CSTACKTHREAD;
  else   L->nCcalls = getCcalls(from) + from->nci - L->nci - CSTACKCF;
  if (L->nCcalls <= CSTACKERR)
    return resume_error(L, "C stack overflow", nargs);
  luai_userstateresume(L, nargs);
  api_checknelems(L, (L->status == LUA_OK) ? nargs + 1 : nargs);
  status = luaD_rawrunprotected(L, resume, &nargs);
   
  while (errorstatus(status) && recover(L, status)) {
    
    status = luaD_rawrunprotected(L, unroll, &status);
  }
  if (likely(!errorstatus(status)))
    lua_assert(status == L->status);  
  else {  
    L->status = cast_byte(status);  
    luaD_seterrorobj(L, status, L->top);  
    L->ci->top = L->top;
  }
  *nresults = (status == LUA_YIELD) ? L->ci->u2.nyield : cast_int(L->top - (L->ci->func + 1));
  lua_unlock(L);
  return status;
}


LUA_API int lua_isyieldable (lua_State *L) {
  return yieldable(L);
}


LUA_API int lua_yieldk (lua_State *L, int nresults, lua_KContext ctx, lua_KFunction k) {
  CallInfo *ci;
  luai_userstateyield(L, nresults);
  lua_lock(L);
  ci = L->ci;
  api_checknelems(L, nresults);
  if (unlikely(!yieldable(L))) {
    if (L != G(L)->mainthread)
      luaG_runerror(L, "attempt to yield across a C-call boundary");
    else luaG_runerror(L, "attempt to yield from outside a coroutine");
  }
  L->status = LUA_YIELD;
  if (isLua(ci)) {  
    lua_assert(!isLuacode(ci));
    api_check(L, k == NULL, "hooks cannot continue after yielding");
    ci->u2.nyield = 0;  
  }
  else {
    if ((ci->u.c.k = k) != NULL)  
      ci->u.c.ctx = ctx;  
    ci->u2.nyield = nresults;  
    luaD_throw(L, LUA_YIELD);
  }
  lua_assert(ci->callstatus & CIST_HOOKED);  
  lua_unlock(L);
  return 0;  
}



int luaD_pcall (lua_State *L, Pfunc func, void *u, ptrdiff_t old_top, ptrdiff_t ef) {
  int status;
  CallInfo *old_ci = L->ci;
  lu_byte old_allowhooks = L->allowhook;
  ptrdiff_t old_errfunc = L->errfunc;
  L->errfunc = ef;
  status = luaD_rawrunprotected(L, func, u);
  if (unlikely(status != LUA_OK)) {  
    StkId oldtop = restorestack(L, old_top);
    L->ci = old_ci;
    L->allowhook = old_allowhooks;
    status = luaF_close(L, oldtop, status);
    oldtop = restorestack(L, old_top);  
    luaD_seterrorobj(L, status, oldtop);
    luaD_shrinkstack(L);
  }
  L->errfunc = old_errfunc;
  return status;
}




struct SParser {  
  ZIO *z;
  Mbuffer buff;  
  Dyndata dyd;  
  const char *mode;
  const char *name;
};


static void checkmode (lua_State *L, const char *mode, const char *x) {
  if (mode && strchr(mode, x[0]) == NULL) {
    luaO_pushfstring(L, "attempt to load a %s chunk (mode is '%s')", x, mode);
    luaD_throw(L, LUA_ERRSYNTAX);
  }
}


static void f_parser (lua_State *L, void *ud) {
  LClosure *cl;
  struct SParser *p = cast(struct SParser *, ud);
  int c = zgetc(p->z);  
  if (c == LUA_SIGNATURE[0]) {
    checkmode(L, p->mode, "binary");
    cl = luaU_undump(L, p->z, p->name);
  }
  else {
    checkmode(L, p->mode, "text");
    cl = luaY_parser(L, p->z, &p->buff, &p->dyd, p->name, c);
  }
  lua_assert(cl->nupvalues == cl->p->sizeupvalues);
  luaF_initupvals(L, cl);
}


int luaD_protectedparser (lua_State *L, ZIO *z, const char *name, const char *mode) {
  struct SParser p;
  int status;
  incnny(L);  
  p.z = z; p.name = name; p.mode = mode;
  p.dyd.actvar.arr = NULL; p.dyd.actvar.size = 0;
  p.dyd.gt.arr = NULL; p.dyd.gt.size = 0;
  p.dyd.label.arr = NULL; p.dyd.label.size = 0;
  luaZ_initbuffer(L, &p.buff);
  status = luaD_pcall(L, f_parser, &p, savestack(L, L->top), L->errfunc);
  luaZ_freebuffer(L, &p.buff);
  luaM_freearray(L, p.dyd.actvar.arr, p.dyd.actvar.size);
  luaM_freearray(L, p.dyd.gt.arr, p.dyd.gt.size);
  luaM_freearray(L, p.dyd.label.arr, p.dyd.label.size);
  decnny(L);
  return status;
}


