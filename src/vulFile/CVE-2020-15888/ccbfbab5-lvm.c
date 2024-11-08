

































































static int l_strton (const TValue *obj, TValue *result) {
  lua_assert(obj != result);
  if (!cvt2num(obj))  
    return 0;
  else return (luaO_str2num(svalue(obj), result) == vslen(obj) + 1);
}



int luaV_tonumber_ (const TValue *obj, lua_Number *n) {
  TValue v;
  if (ttisinteger(obj)) {
    *n = cast_num(ivalue(obj));
    return 1;
  }
  else if (l_strton(obj, &v)) {  
    *n = nvalue(&v);  
    return 1;
  }
  else return 0;
}



int luaV_flttointeger (lua_Number n, lua_Integer *p, F2Imod mode) {
  lua_Number f = l_floor(n);
  if (n != f) {  
    if (mode == F2Ieq) return 0;  
    else if (mode == F2Iceil)  
      f += 1;  
  }
  return lua_numbertointeger(f, p);
}



int luaV_tointegerns (const TValue *obj, lua_Integer *p, F2Imod mode) {
  if (ttisfloat(obj))
    return luaV_flttointeger(fltvalue(obj), p, mode);
  else if (ttisinteger(obj)) {
    *p = ivalue(obj);
    return 1;
  }
  else return 0;
}



int luaV_tointeger (const TValue *obj, lua_Integer *p, F2Imod mode) {
  TValue v;
  if (l_strton(obj, &v))  
    obj = &v;  
  return luaV_tointegerns(obj, p, mode);
}



static int forlimit (lua_State *L, lua_Integer init, const TValue *lim, lua_Integer *p, lua_Integer step) {
  if (!luaV_tointeger(lim, p, (step < 0 ? F2Iceil : F2Ifloor))) {
    
    lua_Number flim;  
    if (!tonumber(lim, &flim)) 
      luaG_forerror(L, lim, "limit");
    
    if (luai_numlt(0, flim)) {  
      if (step < 0) return 1;  
      *p = LUA_MAXINTEGER;  
    }
    else {  
      if (step > 0) return 1;  
      *p = LUA_MININTEGER;  
    }
  }
  return (step > 0 ? init > *p : init < *p);  
}



static int forprep (lua_State *L, StkId ra) {
  TValue *pinit = s2v(ra);
  TValue *plimit = s2v(ra + 1);
  TValue *pstep = s2v(ra + 2);
  if (ttisinteger(pinit) && ttisinteger(pstep)) { 
    lua_Integer init = ivalue(pinit);
    lua_Integer step = ivalue(pstep);
    lua_Integer limit;
    if (step == 0)
      luaG_runerror(L, "'for' step is zero");
    setivalue(s2v(ra + 3), init);  
    if (forlimit(L, init, plimit, &limit, step))
      return 1;  
    else {  
      lua_Unsigned count;
      if (step > 0) {  
        count = l_castS2U(limit) - l_castS2U(init);
        if (step != 1)  
          count /= l_castS2U(step);
      }
      else {  
        count = l_castS2U(init) - l_castS2U(limit);
        
        count /= l_castS2U(-(step + 1)) + 1u;
      }
      
      setivalue(plimit, l_castU2S(count));
    }
  }
  else {  
    lua_Number init; lua_Number limit; lua_Number step;
    if (unlikely(!tonumber(plimit, &limit)))
      luaG_forerror(L, plimit, "limit");
    if (unlikely(!tonumber(pstep, &step)))
      luaG_forerror(L, pstep, "step");
    if (unlikely(!tonumber(pinit, &init)))
      luaG_forerror(L, pinit, "initial value");
    if (step == 0)
      luaG_runerror(L, "'for' step is zero");
    if (luai_numlt(0, step) ? luai_numlt(limit, init)
                            : luai_numlt(init, limit))
      return 1;  
    else {
      
      setfltvalue(plimit, limit);
      setfltvalue(pstep, step);
      setfltvalue(s2v(ra), init);  
      setfltvalue(s2v(ra + 3), init);  
    }
  }
  return 0;
}



static int floatforloop (StkId ra) {
  lua_Number step = fltvalue(s2v(ra + 2));
  lua_Number limit = fltvalue(s2v(ra + 1));
  lua_Number idx = fltvalue(s2v(ra));  
  idx = luai_numadd(L, idx, step);  
  if (luai_numlt(0, step) ? luai_numle(idx, limit)
                          : luai_numle(limit, idx)) {
    chgfltvalue(s2v(ra), idx);  
    setfltvalue(s2v(ra + 3), idx);  
    return 1;  
  }
  else return 0;
}



void luaV_finishget (lua_State *L, const TValue *t, TValue *key, StkId val, const TValue *slot) {
  int loop;  
  const TValue *tm;  
  for (loop = 0; loop < MAXTAGLOOP; loop++) {
    if (slot == NULL) {  
      lua_assert(!ttistable(t));
      tm = luaT_gettmbyobj(L, t, TM_INDEX);
      if (unlikely(notm(tm)))
        luaG_typeerror(L, t, "index");  
      
    }
    else {  
      lua_assert(isempty(slot));
      tm = fasttm(L, hvalue(t)->metatable, TM_INDEX);  
      if (tm == NULL) {  
        setnilvalue(s2v(val));  
        return;
      }
      
    }
    if (ttisfunction(tm)) {  
      luaT_callTMres(L, tm, t, key, val);  
      return;
    }
    t = tm;  
    if (luaV_fastget(L, t, key, slot, luaH_get)) {  
      setobj2s(L, val, slot);  
      return;
    }
    
  }
  luaG_runerror(L, "'__index' chain too long; possible loop");
}



void luaV_finishset (lua_State *L, const TValue *t, TValue *key, TValue *val, const TValue *slot) {
  int loop;  
  for (loop = 0; loop < MAXTAGLOOP; loop++) {
    const TValue *tm;  
    if (slot != NULL) {  
      Table *h = hvalue(t);  
      lua_assert(isempty(slot));  
      tm = fasttm(L, h->metatable, TM_NEWINDEX);  
      if (tm == NULL) {  
        if (isabstkey(slot))  
          slot = luaH_newkey(L, h, key);  
        
        setobj2t(L, cast(TValue *, slot), val);  
        invalidateTMcache(h);
        luaC_barrierback(L, obj2gco(h), val);
        return;
      }
      
    }
    else {  
      tm = luaT_gettmbyobj(L, t, TM_NEWINDEX);
      if (unlikely(notm(tm)))
        luaG_typeerror(L, t, "index");
    }
    
    if (ttisfunction(tm)) {
      luaT_callTM(L, tm, t, key, val);
      return;
    }
    t = tm;  
    if (luaV_fastget(L, t, key, slot, luaH_get)) {
      luaV_finishfastset(L, t, slot, val);
      return;  
    }
    
  }
  luaG_runerror(L, "'__newindex' chain too long; possible loop");
}



static int l_strcmp (const TString *ls, const TString *rs) {
  const char *l = getstr(ls);
  size_t ll = tsslen(ls);
  const char *r = getstr(rs);
  size_t lr = tsslen(rs);
  for (;;) {  
    int temp = strcoll(l, r);
    if (temp != 0)  
      return temp;  
    else {  
      size_t len = strlen(l);  
      if (len == lr)  
        return (len == ll) ? 0 : 1;  
      else if (len == ll)  
        return -1;  
      
      len++;
      l += len; ll -= len; r += len; lr -= len;
    }
  }
}



static int LTintfloat (lua_Integer i, lua_Number f) {
  if (l_intfitsf(i))
    return luai_numlt(cast_num(i), f);  
  else {  
    lua_Integer fi;
    if (luaV_flttointeger(f, &fi, F2Iceil))  
      return i < fi;   
    else   return f > 0;
  }
}



static int LEintfloat (lua_Integer i, lua_Number f) {
  if (l_intfitsf(i))
    return luai_numle(cast_num(i), f);  
  else {  
    lua_Integer fi;
    if (luaV_flttointeger(f, &fi, F2Ifloor))  
      return i <= fi;   
    else   return f > 0;
  }
}



static int LTfloatint (lua_Number f, lua_Integer i) {
  if (l_intfitsf(i))
    return luai_numlt(f, cast_num(i));  
  else {  
    lua_Integer fi;
    if (luaV_flttointeger(f, &fi, F2Ifloor))  
      return fi < i;   
    else   return f < 0;
  }
}



static int LEfloatint (lua_Number f, lua_Integer i) {
  if (l_intfitsf(i))
    return luai_numle(f, cast_num(i));  
  else {  
    lua_Integer fi;
    if (luaV_flttointeger(f, &fi, F2Iceil))  
      return fi <= i;   
    else   return f < 0;
  }
}



static int LTnum (const TValue *l, const TValue *r) {
  lua_assert(ttisnumber(l) && ttisnumber(r));
  if (ttisinteger(l)) {
    lua_Integer li = ivalue(l);
    if (ttisinteger(r))
      return li < ivalue(r);  
    else   return LTintfloat(li, fltvalue(r));
  }
  else {
    lua_Number lf = fltvalue(l);  
    if (ttisfloat(r))
      return luai_numlt(lf, fltvalue(r));  
    else   return LTfloatint(lf, ivalue(r));
  }
}



static int LEnum (const TValue *l, const TValue *r) {
  lua_assert(ttisnumber(l) && ttisnumber(r));
  if (ttisinteger(l)) {
    lua_Integer li = ivalue(l);
    if (ttisinteger(r))
      return li <= ivalue(r);  
    else   return LEintfloat(li, fltvalue(r));
  }
  else {
    lua_Number lf = fltvalue(l);  
    if (ttisfloat(r))
      return luai_numle(lf, fltvalue(r));  
    else   return LEfloatint(lf, ivalue(r));
  }
}



static int lessthanothers (lua_State *L, const TValue *l, const TValue *r) {
  lua_assert(!ttisnumber(l) || !ttisnumber(r));
  if (ttisstring(l) && ttisstring(r))  
    return l_strcmp(tsvalue(l), tsvalue(r)) < 0;
  else return luaT_callorderTM(L, l, r, TM_LT);
}



int luaV_lessthan (lua_State *L, const TValue *l, const TValue *r) {
  if (ttisnumber(l) && ttisnumber(r))  
    return LTnum(l, r);
  else return lessthanothers(L, l, r);
}



static int lessequalothers (lua_State *L, const TValue *l, const TValue *r) {
  lua_assert(!ttisnumber(l) || !ttisnumber(r));
  if (ttisstring(l) && ttisstring(r))  
    return l_strcmp(tsvalue(l), tsvalue(r)) <= 0;
  else return luaT_callorderTM(L, l, r, TM_LE);
}



int luaV_lessequal (lua_State *L, const TValue *l, const TValue *r) {
  if (ttisnumber(l) && ttisnumber(r))  
    return LEnum(l, r);
  else return lessequalothers(L, l, r);
}



int luaV_equalobj (lua_State *L, const TValue *t1, const TValue *t2) {
  const TValue *tm;
  if (ttypetag(t1) != ttypetag(t2)) {  
    if (ttype(t1) != ttype(t2) || ttype(t1) != LUA_TNUMBER)
      return 0;  
    else {  
      lua_Integer i1, i2;  
      return (tointegerns(t1, &i1) && tointegerns(t2, &i2) && i1 == i2);
    }
  }
  
  switch (ttypetag(t1)) {
    case LUA_VNIL: case LUA_VFALSE: case LUA_VTRUE: return 1;
    case LUA_VNUMINT: return (ivalue(t1) == ivalue(t2));
    case LUA_VNUMFLT: return luai_numeq(fltvalue(t1), fltvalue(t2));
    case LUA_VLIGHTUSERDATA: return pvalue(t1) == pvalue(t2);
    case LUA_VLCF: return fvalue(t1) == fvalue(t2);
    case LUA_VSHRSTR: return eqshrstr(tsvalue(t1), tsvalue(t2));
    case LUA_VLNGSTR: return luaS_eqlngstr(tsvalue(t1), tsvalue(t2));
    case LUA_VUSERDATA: {
      if (uvalue(t1) == uvalue(t2)) return 1;
      else if (L == NULL) return 0;
      tm = fasttm(L, uvalue(t1)->metatable, TM_EQ);
      if (tm == NULL)
        tm = fasttm(L, uvalue(t2)->metatable, TM_EQ);
      break;  
    }
    case LUA_VTABLE: {
      if (hvalue(t1) == hvalue(t2)) return 1;
      else if (L == NULL) return 0;
      tm = fasttm(L, hvalue(t1)->metatable, TM_EQ);
      if (tm == NULL)
        tm = fasttm(L, hvalue(t2)->metatable, TM_EQ);
      break;  
    }
    default:
      return gcvalue(t1) == gcvalue(t2);
  }
  if (tm == NULL)  
    return 0;  
  else {
    luaT_callTMres(L, tm, t1, t2, L->top);  
    return !l_isfalse(s2v(L->top));
  }
}








static void copy2buff (StkId top, int n, char *buff) {
  size_t tl = 0;  
  do {
    size_t l = vslen(s2v(top - n));  
    memcpy(buff + tl, svalue(s2v(top - n)), l * sizeof(char));
    tl += l;
  } while (--n > 0);
}



void luaV_concat (lua_State *L, int total) {
  if (total == 1)
    return;  
  do {
    StkId top = L->top;
    int n = 2;  
    if (!(ttisstring(s2v(top - 2)) || cvt2str(s2v(top - 2))) || !tostring(L, s2v(top - 1)))
      luaT_tryconcatTM(L);
    else if (isemptystr(s2v(top - 1)))  
      cast_void(tostring(L, s2v(top - 2)));  
    else if (isemptystr(s2v(top - 2))) {  
      setobjs2s(L, top - 2, top - 1);  
    }
    else {
      
      size_t tl = vslen(s2v(top - 1));
      TString *ts;
      
      for (n = 1; n < total && tostring(L, s2v(top - n - 1)); n++) {
        size_t l = vslen(s2v(top - n - 1));
        if (unlikely(l >= (MAX_SIZE/sizeof(char)) - tl))
          luaG_runerror(L, "string length overflow");
        tl += l;
      }
      if (tl <= LUAI_MAXSHORTLEN) {  
        char buff[LUAI_MAXSHORTLEN];
        copy2buff(top, n, buff);  
        ts = luaS_newlstr(L, buff, tl);
      }
      else {  
        ts = luaS_createlngstrobj(L, tl);
        copy2buff(top, n, getstr(ts));
      }
      setsvalue2s(L, top - n, ts);  
    }
    total -= n-1;  
    L->top -= n-1;  
  } while (total > 1);  
}



void luaV_objlen (lua_State *L, StkId ra, const TValue *rb) {
  const TValue *tm;
  switch (ttypetag(rb)) {
    case LUA_VTABLE: {
      Table *h = hvalue(rb);
      tm = fasttm(L, h->metatable, TM_LEN);
      if (tm) break;  
      setivalue(s2v(ra), luaH_getn(h));  
      return;
    }
    case LUA_VSHRSTR: {
      setivalue(s2v(ra), tsvalue(rb)->shrlen);
      return;
    }
    case LUA_VLNGSTR: {
      setivalue(s2v(ra), tsvalue(rb)->u.lnglen);
      return;
    }
    default: {  
      tm = luaT_gettmbyobj(L, rb, TM_LEN);
      if (unlikely(notm(tm)))  
        luaG_typeerror(L, rb, "get length of");
      break;
    }
  }
  luaT_callTMres(L, tm, rb, rb, ra);
}



lua_Integer luaV_idiv (lua_State *L, lua_Integer m, lua_Integer n) {
  if (unlikely(l_castS2U(n) + 1u <= 1u)) {  
    if (n == 0)
      luaG_runerror(L, "attempt to divide by zero");
    return intop(-, 0, m);   
  }
  else {
    lua_Integer q = m / n;  
    if ((m ^ n) < 0 && m % n != 0)  
      q -= 1;  
    return q;
  }
}



lua_Integer luaV_mod (lua_State *L, lua_Integer m, lua_Integer n) {
  if (unlikely(l_castS2U(n) + 1u <= 1u)) {  
    if (n == 0)
      luaG_runerror(L, "attempt to perform 'n%%0'");
    return 0;   
  }
  else {
    lua_Integer r = m % n;
    if (r != 0 && (r ^ n) < 0)  
      r += n;  
    return r;
  }
}



lua_Number luaV_modf (lua_State *L, lua_Number m, lua_Number n) {
  lua_Number r;
  luai_nummod(L, m, n, r);
  return r;
}








lua_Integer luaV_shiftl (lua_Integer x, lua_Integer y) {
  if (y < 0) {  
    if (y <= -NBITS) return 0;
    else return intop(>>, x, -y);
  }
  else {  
    if (y >= NBITS) return 0;
    else return intop(<<, x, y);
  }
}



static void pushclosure (lua_State *L, Proto *p, UpVal **encup, StkId base, StkId ra) {
  int nup = p->sizeupvalues;
  Upvaldesc *uv = p->upvalues;
  int i;
  LClosure *ncl = luaF_newLclosure(L, nup);
  ncl->p = p;
  setclLvalue2s(L, ra, ncl);  
  for (i = 0; i < nup; i++) {  
    if (uv[i].instack)  
      ncl->upvals[i] = luaF_findupval(L, base + uv[i].idx);
    else   ncl->upvals[i] = encup[uv[i].idx];
    luaC_objbarrier(L, ncl, ncl->upvals[i]);
  }
}



void luaV_finishOp (lua_State *L) {
  CallInfo *ci = L->ci;
  StkId base = ci->func + 1;
  Instruction inst = *(ci->u.l.savedpc - 1);  
  OpCode op = GET_OPCODE(inst);
  switch (op) {  
    case OP_MMBIN: case OP_MMBINI: case OP_MMBINK: {
      setobjs2s(L, base + GETARG_A(*(ci->u.l.savedpc - 2)), --L->top);
      break;
    }
    case OP_UNM: case OP_BNOT: case OP_LEN:
    case OP_GETTABUP: case OP_GETTABLE: case OP_GETI:
    case OP_GETFIELD: case OP_SELF: {
      setobjs2s(L, base + GETARG_A(inst), --L->top);
      break;
    }
    case OP_LT: case OP_LE:
    case OP_LTI: case OP_LEI:
    case OP_GTI: case OP_GEI:
    case OP_EQ: {  
      int res = !l_isfalse(s2v(L->top - 1));
      L->top--;

      if (ci->callstatus & CIST_LEQ) {  
        ci->callstatus ^= CIST_LEQ;  
        res = !res;  
      }

      lua_assert(GET_OPCODE(*ci->u.l.savedpc) == OP_JMP);
      if (res != GETARG_k(inst))  
        ci->u.l.savedpc++;  
      break;
    }
    case OP_CONCAT: {
      StkId top = L->top - 1;  
      int a = GETARG_A(inst);      
      int total = cast_int(top - 1 - (base + a));  
      setobjs2s(L, top - 2, top);  
      L->top = top - 1;  
      luaV_concat(L, total);  
      break;
    }
    default: {
      
      lua_assert(op == OP_TFORCALL || op == OP_CALL || op == OP_TAILCALL || op == OP_SETTABUP || op == OP_SETTABLE || op == OP_SETI || op == OP_SETFIELD);

      break;
    }
  }
}








































































































































































































void luaV_execute (lua_State *L, CallInfo *ci) {
  LClosure *cl;
  TValue *k;
  StkId base;
  const Instruction *pc;
  int trap;



 tailcall:
  trap = L->hookmask;
  cl = clLvalue(s2v(ci->func));
  k = cl->p->k;
  pc = ci->u.l.savedpc;
  if (trap) {
    if (cl->p->is_vararg)
      trap = 0;  
    else if (pc == cl->p->code)  
      luaD_hookcall(L, ci);
    ci->u.l.trap = 1;  
  }
  base = ci->func + 1;
  
  for (;;) {
    Instruction i;  
    StkId ra;  
    vmfetch();
    lua_assert(base == ci->func + 1);
    lua_assert(base <= L->top && L->top < L->stack + L->stacksize);
    
    lua_assert(isIT(i) || (cast_void(L->top = base), 1));
    vmdispatch (GET_OPCODE(i)) {
      vmcase(OP_MOVE) {
        setobjs2s(L, ra, RB(i));
        vmbreak;
      }
      vmcase(OP_LOADI) {
        lua_Integer b = GETARG_sBx(i);
        setivalue(s2v(ra), b);
        vmbreak;
      }
      vmcase(OP_LOADF) {
        int b = GETARG_sBx(i);
        setfltvalue(s2v(ra), cast_num(b));
        vmbreak;
      }
      vmcase(OP_LOADK) {
        TValue *rb = k + GETARG_Bx(i);
        setobj2s(L, ra, rb);
        vmbreak;
      }
      vmcase(OP_LOADKX) {
        TValue *rb;
        rb = k + GETARG_Ax(*pc); pc++;
        setobj2s(L, ra, rb);
        vmbreak;
      }
      vmcase(OP_LOADFALSE) {
        setbfvalue(s2v(ra));
        vmbreak;
      }
      vmcase(OP_LFALSESKIP) {
        setbfvalue(s2v(ra));
        pc++;  
        vmbreak;
      }
      vmcase(OP_LOADTRUE) {
        setbtvalue(s2v(ra));
        vmbreak;
      }
      vmcase(OP_LOADNIL) {
        int b = GETARG_B(i);
        do {
          setnilvalue(s2v(ra++));
        } while (b--);
        vmbreak;
      }
      vmcase(OP_GETUPVAL) {
        int b = GETARG_B(i);
        setobj2s(L, ra, cl->upvals[b]->v);
        vmbreak;
      }
      vmcase(OP_SETUPVAL) {
        UpVal *uv = cl->upvals[GETARG_B(i)];
        setobj(L, uv->v, s2v(ra));
        luaC_barrier(L, uv, s2v(ra));
        vmbreak;
      }
      vmcase(OP_GETTABUP) {
        const TValue *slot;
        TValue *upval = cl->upvals[GETARG_B(i)]->v;
        TValue *rc = KC(i);
        TString *key = tsvalue(rc);  
        if (luaV_fastget(L, upval, key, slot, luaH_getshortstr)) {
          setobj2s(L, ra, slot);
        }
        else Protect(luaV_finishget(L, upval, rc, ra, slot));
        vmbreak;
      }
      vmcase(OP_GETTABLE) {
        const TValue *slot;
        TValue *rb = vRB(i);
        TValue *rc = vRC(i);
        lua_Unsigned n;
        if (ttisinteger(rc)  
            ? (cast_void(n = ivalue(rc)), luaV_fastgeti(L, rb, n, slot))
            : luaV_fastget(L, rb, rc, slot, luaH_get)) {
          setobj2s(L, ra, slot);
        }
        else Protect(luaV_finishget(L, rb, rc, ra, slot));
        vmbreak;
      }
      vmcase(OP_GETI) {
        const TValue *slot;
        TValue *rb = vRB(i);
        int c = GETARG_C(i);
        if (luaV_fastgeti(L, rb, c, slot)) {
          setobj2s(L, ra, slot);
        }
        else {
          TValue key;
          setivalue(&key, c);
          Protect(luaV_finishget(L, rb, &key, ra, slot));
        }
        vmbreak;
      }
      vmcase(OP_GETFIELD) {
        const TValue *slot;
        TValue *rb = vRB(i);
        TValue *rc = KC(i);
        TString *key = tsvalue(rc);  
        if (luaV_fastget(L, rb, key, slot, luaH_getshortstr)) {
          setobj2s(L, ra, slot);
        }
        else Protect(luaV_finishget(L, rb, rc, ra, slot));
        vmbreak;
      }
      vmcase(OP_SETTABUP) {
        const TValue *slot;
        TValue *upval = cl->upvals[GETARG_A(i)]->v;
        TValue *rb = KB(i);
        TValue *rc = RKC(i);
        TString *key = tsvalue(rb);  
        if (luaV_fastget(L, upval, key, slot, luaH_getshortstr)) {
          luaV_finishfastset(L, upval, slot, rc);
        }
        else Protect(luaV_finishset(L, upval, rb, rc, slot));
        vmbreak;
      }
      vmcase(OP_SETTABLE) {
        const TValue *slot;
        TValue *rb = vRB(i);  
        TValue *rc = RKC(i);  
        lua_Unsigned n;
        if (ttisinteger(rb)  
            ? (cast_void(n = ivalue(rb)), luaV_fastgeti(L, s2v(ra), n, slot))
            : luaV_fastget(L, s2v(ra), rb, slot, luaH_get)) {
          luaV_finishfastset(L, s2v(ra), slot, rc);
        }
        else Protect(luaV_finishset(L, s2v(ra), rb, rc, slot));
        vmbreak;
      }
      vmcase(OP_SETI) {
        const TValue *slot;
        int c = GETARG_B(i);
        TValue *rc = RKC(i);
        if (luaV_fastgeti(L, s2v(ra), c, slot)) {
          luaV_finishfastset(L, s2v(ra), slot, rc);
        }
        else {
          TValue key;
          setivalue(&key, c);
          Protect(luaV_finishset(L, s2v(ra), &key, rc, slot));
        }
        vmbreak;
      }
      vmcase(OP_SETFIELD) {
        const TValue *slot;
        TValue *rb = KB(i);
        TValue *rc = RKC(i);
        TString *key = tsvalue(rb);  
        if (luaV_fastget(L, s2v(ra), key, slot, luaH_getshortstr)) {
          luaV_finishfastset(L, s2v(ra), slot, rc);
        }
        else Protect(luaV_finishset(L, s2v(ra), rb, rc, slot));
        vmbreak;
      }
      vmcase(OP_NEWTABLE) {
        int b = GETARG_B(i);  
        int c = GETARG_C(i);  
        Table *t;
        if (b > 0)
          b = 1 << (b - 1);  
        lua_assert((!TESTARG_k(i)) == (GETARG_Ax(*pc) == 0));
        if (TESTARG_k(i))  
          c += GETARG_Ax(*pc) * (MAXARG_C + 1);  
        pc++;  
        L->top = ra + 1;  
        t = luaH_new(L);  
        sethvalue2s(L, ra, t);
        if (b != 0 || c != 0)
          luaH_resize(L, t, c, b);  
        checkGC(L, ra + 1);
        vmbreak;
      }
      vmcase(OP_SELF) {
        const TValue *slot;
        TValue *rb = vRB(i);
        TValue *rc = RKC(i);
        TString *key = tsvalue(rc);  
        setobj2s(L, ra + 1, rb);
        if (luaV_fastget(L, rb, key, slot, luaH_getstr)) {
          setobj2s(L, ra, slot);
        }
        else Protect(luaV_finishget(L, rb, rc, ra, slot));
        vmbreak;
      }
      vmcase(OP_ADDI) {
        op_arithI(L, l_addi, luai_numadd);
        vmbreak;
      }
      vmcase(OP_ADDK) {
        op_arithK(L, l_addi, luai_numadd);
        vmbreak;
      }
      vmcase(OP_SUBK) {
        op_arithK(L, l_subi, luai_numsub);
        vmbreak;
      }
      vmcase(OP_MULK) {
        op_arithK(L, l_muli, luai_nummul);
        vmbreak;
      }
      vmcase(OP_MODK) {
        op_arithK(L, luaV_mod, luaV_modf);
        vmbreak;
      }
      vmcase(OP_POWK) {
        op_arithfK(L, luai_numpow);
        vmbreak;
      }
      vmcase(OP_DIVK) {
        op_arithfK(L, luai_numdiv);
        vmbreak;
      }
      vmcase(OP_IDIVK) {
        op_arithK(L, luaV_idiv, luai_numidiv);
        vmbreak;
      }
      vmcase(OP_BANDK) {
        op_bitwiseK(L, l_band);
        vmbreak;
      }
      vmcase(OP_BORK) {
        op_bitwiseK(L, l_bor);
        vmbreak;
      }
      vmcase(OP_BXORK) {
        op_bitwiseK(L, l_bxor);
        vmbreak;
      }
      vmcase(OP_SHRI) {
        TValue *rb = vRB(i);
        int ic = GETARG_sC(i);
        lua_Integer ib;
        if (tointegerns(rb, &ib)) {
          pc++; setivalue(s2v(ra), luaV_shiftl(ib, -ic));
        }
        vmbreak;
      }
      vmcase(OP_SHLI) {
        TValue *rb = vRB(i);
        int ic = GETARG_sC(i);
        lua_Integer ib;
        if (tointegerns(rb, &ib)) {
          pc++; setivalue(s2v(ra), luaV_shiftl(ic, ib));
        }
        vmbreak;
      }
      vmcase(OP_ADD) {
        op_arith(L, l_addi, luai_numadd);
        vmbreak;
      }
      vmcase(OP_SUB) {
        op_arith(L, l_subi, luai_numsub);
        vmbreak;
      }
      vmcase(OP_MUL) {
        op_arith(L, l_muli, luai_nummul);
        vmbreak;
      }
      vmcase(OP_MOD) {
        op_arith(L, luaV_mod, luaV_modf);
        vmbreak;
      }
      vmcase(OP_POW) {
        op_arithf(L, luai_numpow);
        vmbreak;
      }
      vmcase(OP_DIV) {  
        op_arithf(L, luai_numdiv);
        vmbreak;
      }
      vmcase(OP_IDIV) {  
        op_arith(L, luaV_idiv, luai_numidiv);
        vmbreak;
      }
      vmcase(OP_BAND) {
        op_bitwise(L, l_band);
        vmbreak;
      }
      vmcase(OP_BOR) {
        op_bitwise(L, l_bor);
        vmbreak;
      }
      vmcase(OP_BXOR) {
        op_bitwise(L, l_bxor);
        vmbreak;
      }
      vmcase(OP_SHR) {
        op_bitwise(L, luaV_shiftr);
        vmbreak;
      }
      vmcase(OP_SHL) {
        op_bitwise(L, luaV_shiftl);
        vmbreak;
      }
      vmcase(OP_MMBIN) {
        Instruction pi = *(pc - 2);  
        TValue *rb = vRB(i);
        TMS tm = (TMS)GETARG_C(i);
        StkId result = RA(pi);
        lua_assert(OP_ADD <= GET_OPCODE(pi) && GET_OPCODE(pi) <= OP_SHR);
        Protect(luaT_trybinTM(L, s2v(ra), rb, result, tm));
        vmbreak;
      }
      vmcase(OP_MMBINI) {
        Instruction pi = *(pc - 2);  
        int imm = GETARG_sB(i);
        TMS tm = (TMS)GETARG_C(i);
        int flip = GETARG_k(i);
        StkId result = RA(pi);
        Protect(luaT_trybiniTM(L, s2v(ra), imm, flip, result, tm));
        vmbreak;
      }
      vmcase(OP_MMBINK) {
        Instruction pi = *(pc - 2);  
        TValue *imm = KB(i);
        TMS tm = (TMS)GETARG_C(i);
        int flip = GETARG_k(i);
        StkId result = RA(pi);
        Protect(luaT_trybinassocTM(L, s2v(ra), imm, flip, result, tm));
        vmbreak;
      }
      vmcase(OP_UNM) {
        TValue *rb = vRB(i);
        lua_Number nb;
        if (ttisinteger(rb)) {
          lua_Integer ib = ivalue(rb);
          setivalue(s2v(ra), intop(-, 0, ib));
        }
        else if (tonumberns(rb, nb)) {
          setfltvalue(s2v(ra), luai_numunm(L, nb));
        }
        else Protect(luaT_trybinTM(L, rb, rb, ra, TM_UNM));
        vmbreak;
      }
      vmcase(OP_BNOT) {
        TValue *rb = vRB(i);
        lua_Integer ib;
        if (tointegerns(rb, &ib)) {
          setivalue(s2v(ra), intop(^, ~l_castS2U(0), ib));
        }
        else Protect(luaT_trybinTM(L, rb, rb, ra, TM_BNOT));
        vmbreak;
      }
      vmcase(OP_NOT) {
        TValue *rb = vRB(i);
        if (l_isfalse(rb))
          setbtvalue(s2v(ra));
        else setbfvalue(s2v(ra));
        vmbreak;
      }
      vmcase(OP_LEN) {
        Protect(luaV_objlen(L, ra, vRB(i)));
        vmbreak;
      }
      vmcase(OP_CONCAT) {
        int n = GETARG_B(i);  
        L->top = ra + n;  
        ProtectNT(luaV_concat(L, n));
        checkGC(L, L->top); 
        vmbreak;
      }
      vmcase(OP_CLOSE) {
        Protect(luaF_close(L, ra, LUA_OK));
        vmbreak;
      }
      vmcase(OP_TBC) {
        
        halfProtect(luaF_newtbcupval(L, ra));
        vmbreak;
      }
      vmcase(OP_JMP) {
        dojump(ci, i, 0);
        vmbreak;
      }
      vmcase(OP_EQ) {
        int cond;
        TValue *rb = vRB(i);
        Protect(cond = luaV_equalobj(L, s2v(ra), rb));
        docondjump();
        vmbreak;
      }
      vmcase(OP_LT) {
        op_order(L, l_lti, LTnum, lessthanothers);
        vmbreak;
      }
      vmcase(OP_LE) {
        op_order(L, l_lei, LEnum, lessequalothers);
        vmbreak;
      }
      vmcase(OP_EQK) {
        TValue *rb = KB(i);
        
        int cond = luaV_rawequalobj(s2v(ra), rb);
        docondjump();
        vmbreak;
      }
      vmcase(OP_EQI) {
        int cond;
        int im = GETARG_sB(i);
        if (ttisinteger(s2v(ra)))
          cond = (ivalue(s2v(ra)) == im);
        else if (ttisfloat(s2v(ra)))
          cond = luai_numeq(fltvalue(s2v(ra)), cast_num(im));
        else cond = 0;
        docondjump();
        vmbreak;
      }
      vmcase(OP_LTI) {
        op_orderI(L, l_lti, luai_numlt, 0, TM_LT);
        vmbreak;
      }
      vmcase(OP_LEI) {
        op_orderI(L, l_lei, luai_numle, 0, TM_LE);
        vmbreak;
      }
      vmcase(OP_GTI) {
        op_orderI(L, l_gti, luai_numgt, 1, TM_LT);
        vmbreak;
      }
      vmcase(OP_GEI) {
        op_orderI(L, l_gei, luai_numge, 1, TM_LE);
        vmbreak;
      }
      vmcase(OP_TEST) {
        int cond = !l_isfalse(s2v(ra));
        docondjump();
        vmbreak;
      }
      vmcase(OP_TESTSET) {
        TValue *rb = vRB(i);
        if (l_isfalse(rb) == GETARG_k(i))
          pc++;
        else {
          setobj2s(L, ra, rb);
          donextjump(ci);
        }
        vmbreak;
      }
      vmcase(OP_CALL) {
        int b = GETARG_B(i);
        int nresults = GETARG_C(i) - 1;
        if (b != 0)  
          L->top = ra + b;  
        
        ProtectNT(luaD_call(L, ra, nresults));
        vmbreak;
      }
      vmcase(OP_TAILCALL) {
        int b = GETARG_B(i);  
        int nparams1 = GETARG_C(i);
        
        int delta = (nparams1) ? ci->u.l.nextraargs + nparams1 : 0;
        if (b != 0)
          L->top = ra + b;
        else   b = cast_int(L->top - ra);
        savepc(ci);  
        if (TESTARG_k(i)) {
          
          luaF_close(L, base, NOCLOSINGMETH);
          lua_assert(base == ci->func + 1);
        }
        while (!ttisfunction(s2v(ra))) {  
          luaD_tryfuncTM(L, ra);  
          b++;  
          checkstackp(L, 1, ra);
        }
        if (!ttisLclosure(s2v(ra))) {  
          luaD_call(L, ra, LUA_MULTRET);  
          updatetrap(ci);
          updatestack(ci);  
          ci->func -= delta;
          luaD_poscall(L, ci, cast_int(L->top - ra));
          return;
        }
        ci->func -= delta;
        luaD_pretailcall(L, ci, ra, b);  
        goto tailcall;
      }
      vmcase(OP_RETURN) {
        int n = GETARG_B(i) - 1;  
        int nparams1 = GETARG_C(i);
        if (n < 0)  
          n = cast_int(L->top - ra);  
        savepc(ci);
        if (TESTARG_k(i)) {  
          if (L->top < ci->top)
            L->top = ci->top;
          luaF_close(L, base, LUA_OK);
          updatetrap(ci);
          updatestack(ci);
        }
        if (nparams1)  
          ci->func -= ci->u.l.nextraargs + nparams1;
        L->top = ra + n;  
        luaD_poscall(L, ci, n);
        return;
      }
      vmcase(OP_RETURN0) {
        if (L->hookmask) {
          L->top = ra;
          halfProtectNT(luaD_poscall(L, ci, 0));  
        }
        else {  
          int nres = ci->nresults;
          L->ci = ci->previous;  
          L->top = base - 1;
          while (nres-- > 0)
            setnilvalue(s2v(L->top++));  
        }
        return;
      }
      vmcase(OP_RETURN1) {
        if (L->hookmask) {
          L->top = ra + 1;
          halfProtectNT(luaD_poscall(L, ci, 1));  
        }
        else {  
          int nres = ci->nresults;
          L->ci = ci->previous;  
          if (nres == 0)
            L->top = base - 1;  
          else {
            setobjs2s(L, base - 1, ra);  
            L->top = base;
            while (--nres > 0)  
              setnilvalue(s2v(L->top++));
          }
        }
        return;
      }
      vmcase(OP_FORLOOP) {
        if (ttisinteger(s2v(ra + 2))) {  
          lua_Unsigned count = l_castS2U(ivalue(s2v(ra + 1)));
          if (count > 0) {  
            lua_Integer step = ivalue(s2v(ra + 2));
            lua_Integer idx = ivalue(s2v(ra));  
            chgivalue(s2v(ra + 1), count - 1);  
            idx = intop(+, idx, step);  
            chgivalue(s2v(ra), idx);  
            setivalue(s2v(ra + 3), idx);  
            pc -= GETARG_Bx(i);  
          }
        }
        else if (floatforloop(ra))  
          pc -= GETARG_Bx(i);  
        updatetrap(ci);  
        vmbreak;
      }
      vmcase(OP_FORPREP) {
        savestate(L, ci);  
        if (forprep(L, ra))
          pc += GETARG_Bx(i) + 1;  
        vmbreak;
      }
      vmcase(OP_TFORPREP) {
        
        halfProtect(luaF_newtbcupval(L, ra + 3));
        pc += GETARG_Bx(i);
        i = *(pc++);  
        lua_assert(GET_OPCODE(i) == OP_TFORCALL && ra == RA(i));
        goto l_tforcall;
      }
      vmcase(OP_TFORCALL) {
       l_tforcall:
        
        
        memcpy(ra + 4, ra, 3 * sizeof(*ra));
        L->top = ra + 4 + 3;
        ProtectNT(luaD_call(L, ra + 4, GETARG_C(i)));  
        updatestack(ci);  
        i = *(pc++);  
        lua_assert(GET_OPCODE(i) == OP_TFORLOOP && ra == RA(i));
        goto l_tforloop;
      }
      vmcase(OP_TFORLOOP) {
        l_tforloop:
        if (!ttisnil(s2v(ra + 4))) {  
          setobjs2s(L, ra + 2, ra + 4);  
          pc -= GETARG_Bx(i);  
        }
        vmbreak;
      }
      vmcase(OP_SETLIST) {
        int n = GETARG_B(i);
        unsigned int last = GETARG_C(i);
        Table *h = hvalue(s2v(ra));
        if (n == 0)
          n = cast_int(L->top - ra) - 1;  
        else L->top = ci->top;
        last += n;
        if (TESTARG_k(i)) {
          last += GETARG_Ax(*pc) * (MAXARG_C + 1);
          pc++;
        }
        if (last > luaH_realasize(h))  
          luaH_resizearray(L, h, last);  
        for (; n > 0; n--) {
          TValue *val = s2v(ra + n);
          setobj2t(L, &h->array[last - 1], val);
          last--;
          luaC_barrierback(L, obj2gco(h), val);
        }
        vmbreak;
      }
      vmcase(OP_CLOSURE) {
        Proto *p = cl->p->p[GETARG_Bx(i)];
        halfProtect(pushclosure(L, p, cl->upvals, base, ra));
        checkGC(L, ra + 1);
        vmbreak;
      }
      vmcase(OP_VARARG) {
        int n = GETARG_C(i) - 1;  
        Protect(luaT_getvarargs(L, ci, ra, n));
        vmbreak;
      }
      vmcase(OP_VARARGPREP) {
        luaT_adjustvarargs(L, GETARG_A(i), ci, cl->p);
        updatetrap(ci);
        if (trap) {
          luaD_hookcall(L, ci);
          L->oldpc = pc + 1;  
        }
        updatebase(ci);  
        vmbreak;
      }
      vmcase(OP_EXTRAARG) {
        lua_assert(0);
        vmbreak;
      }
    }
  }
}


