












  
  #define CLEAR_MEMORY_ON_FREE





JsVar **jsVarBlocks = 0;
unsigned int jsVarsSize = 0;




unsigned int jsVarsSize = 0;
JsVar *jsVars = NULL;

JsVar jsVars[JSVAR_CACHE_SIZE] __attribute__((aligned(4)));
unsigned int jsVarsSize = JSVAR_CACHE_SIZE;



typedef enum {
  MEM_NOT_BUSY, MEMBUSY_SYSTEM, MEMBUSY_GC } MemBusyType;



volatile bool touchedFreeList = false;
volatile JsVarRef jsVarFirstEmpty; 
volatile MemBusyType isMemoryBusy; 




JsVarRef jsvGetFirstChild(const JsVar *v) { return v->varData.ref.firstChild; }
JsVarRefSigned jsvGetFirstChildSigned(const JsVar *v) {
  if (v->varData.ref.firstChild > JSVARREF_MAX)
    return ((JsVarRefSigned)v->varData.ref.firstChild) + JSVARREF_MIN*2;
  return (JsVarRefSigned)v->varData.ref.firstChild;
}
JsVarRef jsvGetLastChild(const JsVar *v) { return v->varData.ref.lastChild; }
JsVarRef jsvGetNextSibling(const JsVar *v) { return v->varData.ref.nextSibling; }
JsVarRef jsvGetPrevSibling(const JsVar *v) { return v->varData.ref.prevSibling; }
void jsvSetFirstChild(JsVar *v, JsVarRef r) { v->varData.ref.firstChild = r; }
void jsvSetLastChild(JsVar *v, JsVarRef r) { v->varData.ref.lastChild = r; }
void jsvSetNextSibling(JsVar *v, JsVarRef r) { v->varData.ref.nextSibling = r; }
void jsvSetPrevSibling(JsVar *v, JsVarRef r) { v->varData.ref.prevSibling = r; }

JsVarRefCounter jsvGetRefs(JsVar *v) { return v->varData.ref.refs; }
void jsvSetRefs(JsVar *v, JsVarRefCounter refs) { v->varData.ref.refs = refs; }
unsigned char jsvGetLocks(JsVar *v) { return (unsigned char)((v->flags>>JSV_LOCK_SHIFT) & JSV_LOCK_MAX); }

bool jsvIsRoot(const JsVar *v) { return v && (v->flags&JSV_VARTYPEMASK)==JSV_ROOT; }
bool jsvIsPin(const JsVar *v) { return v && (v->flags&JSV_VARTYPEMASK)==JSV_PIN; }
bool jsvIsSimpleInt(const JsVar *v) { return v && (v->flags&JSV_VARTYPEMASK)==JSV_INTEGER; } 
bool jsvIsInt(const JsVar *v) { return v && ((v->flags&JSV_VARTYPEMASK)==JSV_INTEGER || (v->flags&JSV_VARTYPEMASK)==JSV_PIN || (v->flags&JSV_VARTYPEMASK)==JSV_NAME_INT || (v->flags&JSV_VARTYPEMASK)==JSV_NAME_INT_INT || (v->flags&JSV_VARTYPEMASK)==JSV_NAME_INT_BOOL); }
bool jsvIsFloat(const JsVar *v) { return v && (v->flags&JSV_VARTYPEMASK)==JSV_FLOAT; }
bool jsvIsBoolean(const JsVar *v) { return v && ((v->flags&JSV_VARTYPEMASK)==JSV_BOOLEAN || (v->flags&JSV_VARTYPEMASK)==JSV_NAME_INT_BOOL); }
bool jsvIsString(const JsVar *v) { return v && (v->flags&JSV_VARTYPEMASK)>=_JSV_STRING_START && (v->flags&JSV_VARTYPEMASK)<=_JSV_STRING_END; } 
bool jsvIsBasicString(const JsVar *v) { return v && (v->flags&JSV_VARTYPEMASK)>=JSV_STRING_0 && (v->flags&JSV_VARTYPEMASK)<=JSV_STRING_MAX; } 
bool jsvIsStringExt(const JsVar *v) { return v && (v->flags&JSV_VARTYPEMASK)>=JSV_STRING_EXT_0 && (v->flags&JSV_VARTYPEMASK)<=JSV_STRING_EXT_MAX; } 
bool jsvIsFlatString(const JsVar *v) { return v && (v->flags&JSV_VARTYPEMASK)==JSV_FLAT_STRING; }
bool jsvIsNativeString(const JsVar *v) { return v && (v->flags&JSV_VARTYPEMASK)==JSV_NATIVE_STRING; }
bool jsvIsFlashString(const JsVar *v) {

  return v && (v->flags&JSV_VARTYPEMASK)==JSV_FLASH_STRING;

  return false;

}
bool jsvIsNumeric(const JsVar *v) { return v && (v->flags&JSV_VARTYPEMASK)>=_JSV_NUMERIC_START && (v->flags&JSV_VARTYPEMASK)<=_JSV_NUMERIC_END; }
bool jsvIsFunction(const JsVar *v) { return v && ((v->flags&JSV_VARTYPEMASK)==JSV_FUNCTION || (v->flags&JSV_VARTYPEMASK)==JSV_FUNCTION_RETURN || (v->flags&JSV_VARTYPEMASK)==JSV_NATIVE_FUNCTION); }
bool jsvIsFunctionReturn(const JsVar *v) { return v && ((v->flags&JSV_VARTYPEMASK)==JSV_FUNCTION_RETURN); } 
bool jsvIsFunctionParameter(const JsVar *v) { return v && (v->flags&JSV_NATIVE) && jsvIsString(v); }
bool jsvIsObject(const JsVar *v) { return v && (((v->flags&JSV_VARTYPEMASK)==JSV_OBJECT) || ((v->flags&JSV_VARTYPEMASK)==JSV_ROOT)); }
bool jsvIsArray(const JsVar *v) { return v && (v->flags&JSV_VARTYPEMASK)==JSV_ARRAY; }
bool jsvIsArrayBuffer(const JsVar *v) { return v && (v->flags&JSV_VARTYPEMASK)==JSV_ARRAYBUFFER; }
bool jsvIsArrayBufferName(const JsVar *v) { return v && (v->flags&(JSV_VARTYPEMASK))==JSV_ARRAYBUFFERNAME; }
bool jsvIsNativeFunction(const JsVar *v) { return v && (v->flags&(JSV_VARTYPEMASK))==JSV_NATIVE_FUNCTION; }
bool jsvIsUndefined(const JsVar *v) { return v==0; }
bool jsvIsNull(const JsVar *v) { return v && (v->flags&JSV_VARTYPEMASK)==JSV_NULL; }
bool jsvIsBasic(const JsVar *v) { return jsvIsNumeric(v) || jsvIsString(v);} 
bool jsvIsName(const JsVar *v) { return v && (v->flags&JSV_VARTYPEMASK)>=_JSV_NAME_START && (v->flags&JSV_VARTYPEMASK)<=_JSV_NAME_END; } 
bool jsvIsBasicName(const JsVar *v) { return v && (v->flags&JSV_VARTYPEMASK)>=JSV_NAME_STRING_0 && (v->flags&JSV_VARTYPEMASK)<=JSV_NAME_STRING_MAX; } 

bool jsvIsNameWithValue(const JsVar *v) { return v && (v->flags&JSV_VARTYPEMASK)>=_JSV_NAME_WITH_VALUE_START && (v->flags&JSV_VARTYPEMASK)<=_JSV_NAME_WITH_VALUE_END; }
bool jsvIsNameInt(const JsVar *v) { return v && ((v->flags&JSV_VARTYPEMASK)==JSV_NAME_INT_INT || ((v->flags&JSV_VARTYPEMASK)>=JSV_NAME_STRING_INT_0 && (v->flags&JSV_VARTYPEMASK)<=JSV_NAME_STRING_INT_MAX)); } 
bool jsvIsNameIntInt(const JsVar *v) { return v && (v->flags&JSV_VARTYPEMASK)==JSV_NAME_INT_INT; }
bool jsvIsNameIntBool(const JsVar *v) { return v && (v->flags&JSV_VARTYPEMASK)==JSV_NAME_INT_BOOL; }

bool jsvIsNewChild(const JsVar *v) { return jsvIsName(v) && jsvGetNextSibling(v) && jsvGetNextSibling(v)==jsvGetPrevSibling(v); }

bool jsvIsGetterOrSetter(const JsVar *v) {

  return false;

  return v && (v->flags&JSV_VARTYPEMASK)==JSV_GET_SET;

}

bool jsvIsRefUsedForData(const JsVar *v) { return jsvIsStringExt(v) || (jsvIsString(v)&&!jsvIsName(v)) ||  jsvIsFloat(v) || jsvIsNativeFunction(v) || jsvIsArrayBuffer(v) || jsvIsArrayBufferName(v); }


bool jsvIsIntegerish(const JsVar *v) { return jsvIsInt(v) || jsvIsPin(v) || jsvIsBoolean(v) || jsvIsNull(v); }

bool jsvIsIterable(const JsVar *v) {
  return jsvIsArray(v) || jsvIsObject(v) || jsvIsFunction(v) || jsvIsString(v) || jsvIsArrayBuffer(v);
}






static ALWAYS_INLINE JsVar *jsvGetAddressOf(JsVarRef ref) {
  assert(ref);

  assert(ref <= jsVarsSize);
  JsVarRef t = ref-1;
  return &jsVarBlocks[t>>JSVAR_BLOCK_SHIFT][t&(JSVAR_BLOCK_SIZE-1)];

  assert(ref <= jsVarsSize);
  return &jsVars[ref-1];

  assert(ref <= JSVAR_CACHE_SIZE);
  return &jsVars[ref-1];

}

JsVar *_jsvGetAddressOf(JsVarRef ref) {
  return jsvGetAddressOf(ref);
}


void jsvSetMaxVarsUsed(unsigned int size) {

  assert(size < JSVAR_BLOCK_SIZE); 

  assert(size < JSVAR_CACHE_SIZE);

  jsVarsSize = size;
}


void jsvCreateEmptyVarList() {
  assert(!isMemoryBusy);
  isMemoryBusy = MEMBUSY_SYSTEM;
  jsVarFirstEmpty = 0;
  JsVar firstVar; 
  jsvSetNextSibling(&firstVar, 0);
  JsVar *lastEmpty = &firstVar;

  JsVarRef i;
  for (i=1;i<=jsVarsSize;i++) {
    JsVar *var = jsvGetAddressOf(i);
    if ((var->flags&JSV_VARTYPEMASK) == JSV_UNUSED) {
      jsvSetNextSibling(lastEmpty, i);
      lastEmpty = var;
    } else if (jsvIsFlatString(var)) {
      
      i = (JsVarRef)(i+jsvGetFlatStringBlocks(var));
    }
  }
  jsvSetNextSibling(lastEmpty, 0);
  jsVarFirstEmpty = jsvGetNextSibling(&firstVar);
  isMemoryBusy = MEM_NOT_BUSY;
}


void jsvClearEmptyVarList() {
  assert(!isMemoryBusy);
  isMemoryBusy = MEMBUSY_SYSTEM;
  jsVarFirstEmpty = 0;
  JsVarRef i;
  for (i=1;i<=jsVarsSize;i++) {
    JsVar *var = jsvGetAddressOf(i);
    if ((var->flags&JSV_VARTYPEMASK) == JSV_UNUSED) {
      
      memset((void*)var,0,sizeof(JsVar));
    } else if (jsvIsFlatString(var)) {
      
      i = (JsVarRef)(i+jsvGetFlatStringBlocks(var));
    }
  }
  isMemoryBusy = MEM_NOT_BUSY;
}

void jsvSoftInit() {
  jsvCreateEmptyVarList();
}

void jsvSoftKill() {
  jsvClearEmptyVarList();
}


static JsVarRef jsvInitJsVars(JsVarRef start, unsigned int count) {
  JsVarRef i;
  for (i=start;i<start+count;i++) {
    JsVar *v = jsvGetAddressOf(i);
    v->flags = JSV_UNUSED;
    
    jsvSetNextSibling(v, (JsVarRef)(i+1)); 
  }
  jsvSetNextSibling(jsvGetAddressOf((JsVarRef)(start+count-1)), (JsVarRef)0); 
  return start;
}

void jsvInit(unsigned int size) {

  assert(size==0);
  jsVarsSize = JSVAR_BLOCK_SIZE;
  jsVarBlocks = malloc(sizeof(JsVar*)); 
  jsVarBlocks[0] = malloc(sizeof(JsVar) * JSVAR_BLOCK_SIZE);

  if (size) jsVarsSize = size;
  if(!jsVars) jsVars = (JsVar *)malloc(sizeof(JsVar) * jsVarsSize);

  assert(size==0);


  jsVarFirstEmpty = jsvInitJsVars(1, jsVarsSize);
  jsvSoftInit();
}

void jsvKill() {

  unsigned int i;
  for (i=0;i<jsVarsSize>>JSVAR_BLOCK_SHIFT;i++)
    free(jsVarBlocks[i]);
  free(jsVarBlocks);
  jsVarBlocks = 0;
  jsVarsSize = 0;

}


JsVar *jsvFindOrCreateRoot() {
  JsVarRef i;
  for (i=1;i<=jsVarsSize;i++)
    if (jsvIsRoot(jsvGetAddressOf(i)))
      return jsvLock(i);

  return jsvRef(jsvNewWithFlags(JSV_ROOT));
}


unsigned int jsvGetMemoryUsage() {
  unsigned int usage = 0;
  for (unsigned int i=1;i<=jsVarsSize;i++) {
    JsVar *v = jsvGetAddressOf((JsVarRef)i);
    if ((v->flags&JSV_VARTYPEMASK) != JSV_UNUSED) {
      usage++;
      if (jsvIsFlatString(v)) {
        unsigned int b = (unsigned int)jsvGetFlatStringBlocks(v);
        i+=b;
        usage+=b;
      }
    }
  }
  return usage;
}


unsigned int jsvGetMemoryTotal() {
  return jsVarsSize;
}


void jsvSetMemoryTotal(unsigned int jsNewVarCount) {

  assert(!isMemoryBusy);
  if (jsNewVarCount <= jsVarsSize) return; 
  isMemoryBusy = MEMBUSY_SYSTEM;
  
  unsigned int oldSize = jsVarsSize;
  unsigned int oldBlockCount = jsVarsSize >> JSVAR_BLOCK_SHIFT;
  unsigned int newBlockCount = (jsNewVarCount+JSVAR_BLOCK_SIZE-1) >> JSVAR_BLOCK_SHIFT;
  jsVarsSize = newBlockCount << JSVAR_BLOCK_SHIFT;
  
  jsVarBlocks = realloc(jsVarBlocks, sizeof(JsVar*)*newBlockCount);
  
  unsigned int i;
  for (i=oldBlockCount;i<newBlockCount;i++)
    jsVarBlocks[i] = malloc(sizeof(JsVar) * JSVAR_BLOCK_SIZE);
  
  assert(!jsVarFirstEmpty);
  jsVarFirstEmpty = jsvInitJsVars(oldSize+1, jsVarsSize-oldSize);
  
  touchedFreeList = true;
  isMemoryBusy = MEM_NOT_BUSY;

  NOT_USED(jsNewVarCount);
  assert(0);

}


void jsvUpdateMemoryAddress(size_t oldAddr, size_t length, size_t newAddr) {
  for (unsigned int i=1;i<=jsVarsSize;i++) {
    JsVar *v = jsvGetAddressOf((JsVarRef)i);
    if (jsvIsNativeString(v) || jsvIsFlashString(v)) {
      size_t p = (size_t)v->varData.nativeStr.ptr;
      if (p>=oldAddr && p<oldAddr+length)
        v->varData.nativeStr.ptr = (char*)(p+newAddr-oldAddr);
    } else if (jsvIsFlatString(v)) {
      i += (unsigned int)jsvGetFlatStringBlocks(v);
    }
  }
}

bool jsvMoreFreeVariablesThan(unsigned int vars) {
  if (!vars) return false;
  JsVarRef r = jsVarFirstEmpty;
  while (r) {
    if (!vars--) return true;
    r = jsvGetNextSibling(jsvGetAddressOf(r));
  }
  return false;
}


bool jsvIsMemoryFull() {
  return !jsVarFirstEmpty;
}


void jsvShowAllocated() {
  JsVarRef i;
  for (i=1;i<=jsVarsSize;i++) {
    if ((jsvGetAddressOf(i)->flags&JSV_VARTYPEMASK) != JSV_UNUSED) {
      jsiConsolePrintf("USED VAR #%d:",i);
      jsvTrace(jsvGetAddressOf(i), 2);
    }
  }
}

bool jsvHasCharacterData(const JsVar *v) {
  return jsvIsString(v) || jsvIsStringExt(v);
}

bool jsvHasStringExt(const JsVar *v) {
  return jsvIsString(v) || jsvIsStringExt(v);
}

bool jsvHasChildren(const JsVar *v) {
  return jsvIsFunction(v) || jsvIsObject(v) || jsvIsArray(v) || jsvIsRoot(v) || jsvIsGetterOrSetter(v);
}


bool jsvHasSingleChild(const JsVar *v) {
  return jsvIsArrayBuffer(v) || (jsvIsName(v) && !jsvIsNameWithValue(v));
}


size_t jsvGetMaxCharactersInVar(const JsVar *v) {
  
  if (jsvIsStringExt(v)) return JSVAR_DATA_STRING_MAX_LEN;
  assert(jsvHasCharacterData(v));
  if (jsvIsName(v)) return JSVAR_DATA_STRING_NAME_LEN;
  return JSVAR_DATA_STRING_LEN;
}


size_t jsvGetCharactersInVar(const JsVar *v) {
  unsigned int f = v->flags&JSV_VARTYPEMASK;
  if (f == JSV_FLAT_STRING)
    return (size_t)v->varData.integer;
  if ((f == JSV_NATIVE_STRING)

  || (f == JSV_FLASH_STRING)

      )
    return (size_t)v->varData.nativeStr.len;

  assert(f >= JSV_NAME_STRING_INT_0);
  assert((JSV_NAME_STRING_INT_0 < JSV_NAME_STRING_0) && (JSV_NAME_STRING_0 < JSV_STRING_0) && (JSV_STRING_0 < JSV_STRING_EXT_0));

  if (f<=JSV_NAME_STRING_MAX) {
    if (f<=JSV_NAME_STRING_INT_MAX)
      return f-JSV_NAME_STRING_INT_0;
    else return f-JSV_NAME_STRING_0;
  } else {
    if (f<=JSV_STRING_MAX) return f-JSV_STRING_0;
    assert(f <= JSV_STRING_EXT_MAX);
    return f - JSV_STRING_EXT_0;
  }
}


void jsvSetCharactersInVar(JsVar *v, size_t chars) {
  unsigned int f = v->flags&JSV_VARTYPEMASK;
  assert(!(jsvIsFlatString(v) || jsvIsNativeString(v) || jsvIsFlashString(v)));

  JsVarFlags m = (JsVarFlags)(v->flags&~JSV_VARTYPEMASK);
  assert(f >= JSV_NAME_STRING_INT_0);
  assert((JSV_NAME_STRING_INT_0 < JSV_NAME_STRING_0) && (JSV_NAME_STRING_0 < JSV_STRING_0) && (JSV_STRING_0 < JSV_STRING_EXT_0));

  if (f<=JSV_NAME_STRING_MAX) {
    assert(chars <= JSVAR_DATA_STRING_NAME_LEN);
    if (f<=JSV_NAME_STRING_INT_MAX)
      v->flags = (JsVarFlags)(m | (JSV_NAME_STRING_INT_0+chars));
    else v->flags = (JsVarFlags)(m | (JSV_NAME_STRING_0+chars));
  } else {
    if (f<=JSV_STRING_MAX) {
      assert(chars <= JSVAR_DATA_STRING_LEN);
      v->flags = (JsVarFlags)(m | (JSV_STRING_0+chars));
    } else {
      assert(chars <= JSVAR_DATA_STRING_MAX_LEN);
      assert(f <= JSV_STRING_EXT_MAX);
      v->flags = (JsVarFlags)(m | (JSV_STRING_EXT_0+chars));
    }
  }
}

void jsvResetVariable(JsVar *v, JsVarFlags flags) {
  assert((v->flags&JSV_VARTYPEMASK) == JSV_UNUSED);
  
  
  unsigned int i;
  if ((sizeof(JsVar)&3) == 0) {
    for (i=0;i<sizeof(JsVar)/sizeof(uint32_t);i++)
      ((uint32_t*)v)[i] = 0;
  } else { 
    for (i=0;i<sizeof(JsVar);i++)
      ((uint8_t*)v)[i] = 0;
  }
  
  assert(!(flags & JSV_LOCK_MASK));
  v->flags = flags | JSV_LOCK_ONE;
}

JsVar *jsvNewWithFlags(JsVarFlags flags) {
  if (isMemoryBusy) {
    jsErrorFlags |= JSERR_MEMORY_BUSY;
    return 0;
  }
  JsVar *v = 0;
  jshInterruptOff(); 
  if (jsVarFirstEmpty!=0) {
    v = jsvGetAddressOf(jsVarFirstEmpty); 
    jsVarFirstEmpty = jsvGetNextSibling(v); 
    touchedFreeList = true;
  }
  jshInterruptOn();
  if (v) {
    assert(v->flags == JSV_UNUSED);
    
 
    jsvResetVariable(v, flags); 
    
    return v;
  }
  jsErrorFlags |= JSERR_LOW_MEMORY;
  
  if (jshIsInInterrupt()) {
    return 0;
  }
  
  if (jsvGarbageCollect()) {
    return jsvNewWithFlags(flags); 
  }
  
  if (jsiFreeMoreMemory()) {
    return jsvNewWithFlags(flags);
  }
  

  jsvSetMemoryTotal(jsVarsSize*2);
  return jsvNewWithFlags(flags);

  
  jsErrorFlags |= JSERR_MEMORY;
  jspSetInterrupted(true);
  return 0;

}

static void jsvFreePtrInternal(JsVar *var) {
  assert(jsvGetLocks(var)==0);
  var->flags = JSV_UNUSED;
  
  jshInterruptOff(); 
  jsvSetNextSibling(var, jsVarFirstEmpty);
  jsVarFirstEmpty = jsvGetRef(var);
  touchedFreeList = true;
  jshInterruptOn();
}

ALWAYS_INLINE void jsvFreePtr(JsVar *var) {
  
  assert((!jsvGetNextSibling(var) && !jsvGetPrevSibling(var)) ||  jsvIsRefUsedForData(var) || (jsvIsName(var) && (jsvGetNextSibling(var)==jsvGetPrevSibling(var))));


  
  if (jsvIsNameWithValue(var)) {

    jsvSetFirstChild(var, 0); 

  } else if (jsvHasSingleChild(var)) {
    if (jsvGetFirstChild(var)) {
      JsVar *child = jsvLock(jsvGetFirstChild(var));
      jsvUnRef(child);

      jsvSetFirstChild(var, 0); 

      jsvUnLock(child); 
    }
  }
  

  
  if (jsvHasStringExt(var)) {
    
    JsVarRef stringDataRef = jsvGetLastChild(var);

    jsvSetLastChild(var, 0);

    while (stringDataRef) {
      JsVar *child = jsvGetAddressOf(stringDataRef);
      assert(jsvIsStringExt(child));
      stringDataRef = jsvGetLastChild(child);
      jsvFreePtrInternal(child);
    }
    
    if (jsvIsFlatString(var)) {
      
      size_t count = jsvGetFlatStringBlocks(var);
      JsVarRef i = (JsVarRef)(jsvGetRef(var)+count);
      
      
      
      
      jshInterruptOff(); 
      JsVarRef insertBefore = jsVarFirstEmpty;
      JsVarRef insertAfter = 0;
      while (insertBefore && insertBefore<i) {
        insertAfter = insertBefore;
        insertBefore = jsvGetNextSibling(jsvGetAddressOf(insertBefore));
      }
      
      while (count--) {
        JsVar *p = jsvGetAddressOf(i--);
        p->flags = JSV_UNUSED; 
        
        jsvSetNextSibling(p, insertBefore);
        insertBefore = jsvGetRef(p);
      }
      
      if (insertAfter)
        jsvSetNextSibling(jsvGetAddressOf(insertAfter), insertBefore);
      else jsVarFirstEmpty = insertBefore;
      touchedFreeList = true;
      jshInterruptOn();
    } else if (jsvIsBasicString(var)) {

      jsvSetFirstChild(var, 0); 

    }

  }
  

  if (jsvHasChildren(var)) {
    JsVarRef childref = jsvGetFirstChild(var);

    jsvSetFirstChild(var, 0);
    jsvSetLastChild(var, 0);

    while (childref) {
      JsVar *child = jsvLock(childref);
      assert(jsvIsName(child));
      childref = jsvGetNextSibling(child);
      jsvSetPrevSibling(child, 0);
      jsvSetNextSibling(child, 0);
      jsvUnRef(child);
      jsvUnLock(child);
    }
  } else {

    assert(jsvIsFloat(var) || !jsvGetFirstChild(var));
    assert(jsvIsFloat(var) || !jsvGetLastChild(var));

    if (jsvIsName(var)) {
      assert(jsvGetNextSibling(var)==jsvGetPrevSibling(var)); 
      if (jsvGetNextSibling(var)) {
        jsvUnRefRef(jsvGetNextSibling(var));
        jsvUnRefRef(jsvGetPrevSibling(var));
      }
    }
  }

  
  jsvFreePtrInternal(var);
}


JsVarRef jsvGetRef(JsVar *var) {
  if (!var) return 0;

  unsigned int i, c = jsVarsSize>>JSVAR_BLOCK_SHIFT;
  for (i=0;i<c;i++) {
    if (var>=jsVarBlocks[i] && var<&jsVarBlocks[i][JSVAR_BLOCK_SIZE]) {
      JsVarRef r = (JsVarRef)(1 + (i<<JSVAR_BLOCK_SHIFT) + (var - jsVarBlocks[i]));
      return r;
    }
  }
  return 0;

  return (JsVarRef)(1 + (var - jsVars));

}


JsVar *jsvLock(JsVarRef ref) {
  JsVar *var = jsvGetAddressOf(ref);
  
  assert(jsvGetLocks(var) < JSV_LOCK_MAX);
  var->flags += JSV_LOCK_ONE;

  if (jsvGetLocks(var)==0) {
    jsError("Too many locks to Variable!");
    
  }

  return var;
}


JsVar *jsvLockSafe(JsVarRef ref) {
  if (!ref) return 0;
  return jsvLock(ref);
}


JsVar *jsvLockAgain(JsVar *var) {
  assert(var);
  assert(jsvGetLocks(var) < JSV_LOCK_MAX);
  var->flags += JSV_LOCK_ONE;
  return var;
}


JsVar *jsvLockAgainSafe(JsVar *var) {
  return var ? jsvLockAgain(var) : 0;
}



static NO_INLINE void jsvUnLockFreeIfNeeded(JsVar *var) {
  assert(jsvGetLocks(var) == 0);
  
  if (jsvGetRefs(var) == 0 && jsvHasRef(var) && (var->flags&JSV_VARTYPEMASK)!=JSV_UNUSED) {

    jsvFreePtr(var);
  }
}



void jsvUnLock(JsVar *var) {
  if (!var) return;
  assert(jsvGetLocks(var)>0);
  var->flags -= JSV_LOCK_ONE;
  
  
  if ((var->flags & JSV_LOCK_MASK) == 0) jsvUnLockFreeIfNeeded(var);
}


void jsvUnLock2(JsVar *var1, JsVar *var2) {
  jsvUnLock(var1);
  jsvUnLock(var2);
}

void jsvUnLock3(JsVar *var1, JsVar *var2, JsVar *var3) {
  jsvUnLock(var1);
  jsvUnLock(var2);
  jsvUnLock(var3);
}

void jsvUnLock4(JsVar *var1, JsVar *var2, JsVar *var3, JsVar *var4) {
  jsvUnLock(var1);
  jsvUnLock(var2);
  jsvUnLock(var3);
  jsvUnLock(var4);
}


NO_INLINE void jsvUnLockMany(unsigned int count, JsVar **vars) {
  while (count) jsvUnLock(vars[--count]);
}


JsVar *jsvRef(JsVar *var) {
  assert(var && jsvHasRef(var));
  if (jsvGetRefs(var) < JSVARREFCOUNT_MAX) 
    jsvSetRefs(var, (JsVarRefCounter)(jsvGetRefs(var)+1));
  assert(jsvGetRefs(var));
  return var;
}


void jsvUnRef(JsVar *var) {
  assert(var && jsvGetRefs(var)>0 && jsvHasRef(var));
  if (jsvGetRefs(var) < JSVARREFCOUNT_MAX) 
    jsvSetRefs(var, (JsVarRefCounter)(jsvGetRefs(var)-1));
}


JsVarRef jsvRefRef(JsVarRef ref) {
  JsVar *v;
  assert(ref);
  v = jsvLock(ref);
  assert(!jsvIsStringExt(v));
  jsvRef(v);
  jsvUnLock(v);
  return ref;
}


JsVarRef jsvUnRefRef(JsVarRef ref) {
  JsVar *v;
  assert(ref);
  v = jsvLock(ref);
  assert(!jsvIsStringExt(v));
  jsvUnRef(v);
  jsvUnLock(v);
  return 0;
}

JsVar *jsvNewFlatStringOfLength(unsigned int byteLength) {
  bool firstRun = true;
  
  size_t requiredBlocks = 1 + ((byteLength+sizeof(JsVar)-1) / sizeof(JsVar));
  JsVar *flatString = 0;
  if (isMemoryBusy) {
    jsErrorFlags |= JSERR_MEMORY_BUSY;
    return 0;
  }
  while (true) {
    
    bool memoryTouched = true;
    while (memoryTouched) {
      memoryTouched = false;
      touchedFreeList = false;
      JsVarRef beforeStartBlock = 0;
      JsVarRef curr = jsVarFirstEmpty;
      JsVarRef startBlock = curr;
      unsigned int blockCount = 0;
      while (curr && !touchedFreeList) {
        JsVar *currVar = jsvGetAddressOf(curr);
        JsVarRef next = jsvGetNextSibling(currVar);
  #ifdef RESIZABLE_JSVARS
        if (blockCount && next && (jsvGetAddressOf(next)==currVar+1)) {
  #else
        if (blockCount && (next == curr+1)) {
  #endif
          blockCount++;
          if (blockCount>=requiredBlocks) {
            JsVar *nextVar = jsvGetAddressOf(next);
            JsVarRef nextFree = jsvGetNextSibling(nextVar);
            jshInterruptOff();
            if (!touchedFreeList) {
              
              if (beforeStartBlock) {
                jsvSetNextSibling(jsvGetAddressOf(beforeStartBlock),nextFree);
              } else {
                jsVarFirstEmpty = nextFree;
              }
              flatString = jsvGetAddressOf(startBlock);
              
              jsvResetVariable(flatString, JSV_FLAT_STRING);
              flatString->varData.integer = (JsVarInt)byteLength;
            }
            jshInterruptOn();
            
            if (flatString) break;
          }
        } else {
          
          beforeStartBlock = curr;
          startBlock = next;
          
          if (((size_t)(jsvGetAddressOf(startBlock+1)))&3)
            blockCount = 0; 
          else blockCount = 1;
        }
        
        curr = next;
      }
      
      if (touchedFreeList) {
        memoryTouched = true;
      }
    }

    
    if (flatString || !firstRun)
      break;
    
    firstRun = false;
    jsvGarbageCollect();
  };
  if (!flatString) return 0;
  
  
  memset((char*)&flatString[1], 0, sizeof(JsVar)*(requiredBlocks-1));
  
  touchedFreeList = true;
  
  return flatString;
}

JsVar *jsvNewFromString(const char *str) {
  
  JsVar *first = jsvNewWithFlags(JSV_STRING_0);
  if (!first) return 0; 
  
  
  JsVar *var = jsvLockAgain(first);
  while (*str) {
    
    size_t i, l = jsvGetMaxCharactersInVar(var);
    for (i=0;i<l && *str;i++)
      var->varData.str[i] = *(str++);
    

    
    jsvSetCharactersInVar(var, i);

    
    
    if (*str) {
      JsVar *next = jsvNewWithFlags(JSV_STRING_EXT_0);
      if (!next) {
        
        jsvUnLock(var);
        return first;
      }
      
      jsvSetLastChild(var, jsvGetRef(next));
      jsvUnLock(var);
      var = next;
    }
  }
  jsvUnLock(var);
  
  return first;
}

JsVar *jsvNewStringOfLength(unsigned int byteLength, const char *initialData) {
  
  if (byteLength > JSV_FLAT_STRING_BREAK_EVEN) {
    JsVar *v = jsvNewFlatStringOfLength(byteLength);
    if (v) {
      if (initialData) jsvSetString(v, initialData, byteLength);
      return v;
    }
  }
  
  JsVar *first = jsvNewWithFlags(JSV_STRING_0);
  if (!first) return 0; 
  
  JsVar *var = jsvLockAgain(first);
  while (true) {
    
    unsigned int l = (unsigned int)jsvGetMaxCharactersInVar(var);
    if (l>=byteLength) {
      if (initialData)
        memcpy(var->varData.str, initialData, byteLength);
      
      jsvSetCharactersInVar(var, byteLength);
      break;
    } else {
      if (initialData) {
        memcpy(var->varData.str, initialData, l);
        initialData+=l;
      }
      
      jsvSetCharactersInVar(var, l);
      byteLength -= l;
      
      JsVar *next = jsvNewWithFlags(JSV_STRING_EXT_0);
      if (!next) break; 
      
      jsvSetLastChild(var, jsvGetRef(next));
      jsvUnLock(var);
      var = next;
    }
  }
  jsvUnLock(var);
  
  return first;
}

JsVar *jsvNewFromInteger(JsVarInt value) {
  JsVar *var = jsvNewWithFlags(JSV_INTEGER);
  if (!var) return 0; 
  var->varData.integer = value;
  return var;
}
JsVar *jsvNewFromBool(bool value) {
  JsVar *var = jsvNewWithFlags(JSV_BOOLEAN);
  if (!var) return 0; 
  var->varData.integer = value ? 1 : 0;
  return var;
}
JsVar *jsvNewFromFloat(JsVarFloat value) {
  JsVar *var = jsvNewWithFlags(JSV_FLOAT);
  if (!var) return 0; 
  var->varData.floating = value;
  return var;
}
JsVar *jsvNewFromLongInteger(long long value) {
  if (value>=-2147483648LL && value<=2147483647LL)
    return jsvNewFromInteger((JsVarInt)value);
  else return jsvNewFromFloat((JsVarFloat)value);
}

JsVar *jsvNewFromPin(int pin) {
  JsVar *v = jsvNewFromInteger((JsVarInt)pin);
  if (v) {
    v->flags = (JsVarFlags)((v->flags & ~JSV_VARTYPEMASK) | JSV_PIN);
  }
  return v;
}

JsVar *jsvNewObject() {
  return jsvNewWithFlags(JSV_OBJECT);
}

JsVar *jsvNewEmptyArray() {
  return jsvNewWithFlags(JSV_ARRAY);
}


JsVar *jsvNewArray(JsVar **elements, int elementCount) {
  JsVar *arr = jsvNewEmptyArray();
  if (!arr) return 0;
  int i;
  for (i=0;i<elementCount;i++)
    jsvArrayPush(arr, elements[i]);
  return arr;
}

JsVar *jsvNewArrayFromBytes(uint8_t *elements, int elementCount) {
  JsVar *arr = jsvNewEmptyArray();
  if (!arr) return 0;
  int i;
  for (i=0;i<elementCount;i++)
    jsvArrayPushAndUnLock(arr, jsvNewFromInteger(elements[i]));
  return arr;
}

JsVar *jsvNewNativeFunction(void (*ptr)(void), unsigned short argTypes) {
  JsVar *func = jsvNewWithFlags(JSV_NATIVE_FUNCTION);
  if (!func) return 0;
  func->varData.native.ptr = ptr;
  func->varData.native.argTypes = argTypes;
  return func;
}

JsVar *jsvNewNativeString(char *ptr, size_t len) {
  if (len>JSV_NATIVE_STR_MAX_LENGTH) len=JSV_NATIVE_STR_MAX_LENGTH; 
  JsVar *str = jsvNewWithFlags(JSV_NATIVE_STRING);
  if (!str) return 0;
  str->varData.nativeStr.ptr = ptr;
  str->varData.nativeStr.len = len;
  return str;
}


JsVar *jsvNewFlashString(char *ptr, size_t len) {
  if (len>JSV_NATIVE_STR_MAX_LENGTH) len=JSV_NATIVE_STR_MAX_LENGTH; 
    JsVar *str = jsvNewWithFlags(JSV_FLASH_STRING);
    if (!str) return 0;
    str->varData.nativeStr.ptr = ptr;
    str->varData.nativeStr.len = len;
    return str;
}



JsVar *jsvNewArrayBufferFromString(JsVar *str, unsigned int lengthOrZero) {
  JsVar *arr = jsvNewWithFlags(JSV_ARRAYBUFFER);
  if (!arr) return 0;
  jsvSetFirstChild(arr, jsvGetRef(jsvRef(str)));
  arr->varData.arraybuffer.type = ARRAYBUFFERVIEW_ARRAYBUFFER;
  assert(arr->varData.arraybuffer.byteOffset == 0);
  if (lengthOrZero==0) lengthOrZero = (unsigned int)jsvGetStringLength(str);
  arr->varData.arraybuffer.length = (unsigned short)lengthOrZero;
  return arr;
}

JsVar *jsvMakeIntoVariableName(JsVar *var, JsVar *valueOrZero) {
  if (!var) return 0;
  assert(jsvGetRefs(var)==0); 
  assert(jsvIsSimpleInt(var) || jsvIsString(var));
  JsVarFlags varType = (var->flags & JSV_VARTYPEMASK);
  if (varType==JSV_INTEGER) {
    int t = JSV_NAME_INT;
    if ((jsvIsInt(valueOrZero) || jsvIsBoolean(valueOrZero)) && !jsvIsPin(valueOrZero)) {
      JsVarInt v = valueOrZero->varData.integer;
      if (v>=JSVARREF_MIN && v<=JSVARREF_MAX) {
        t = jsvIsInt(valueOrZero) ? JSV_NAME_INT_INT : JSV_NAME_INT_BOOL;
        jsvSetFirstChild(var, (JsVarRef)v);
        valueOrZero = 0;
      }
    }
    var->flags = (JsVarFlags)(var->flags & ~JSV_VARTYPEMASK) | t;
  } else if (varType>=_JSV_STRING_START && varType<=_JSV_STRING_END) {
    if (jsvGetCharactersInVar(var) > JSVAR_DATA_STRING_NAME_LEN) {
      
      JsvStringIterator it;
      jsvStringIteratorNew(&it, var, JSVAR_DATA_STRING_NAME_LEN);
      JsVar *startExt = jsvNewWithFlags(JSV_STRING_EXT_0);
      JsVar *ext = jsvLockAgainSafe(startExt);
      size_t nChars = 0;
      while (ext && jsvStringIteratorHasChar(&it)) {
        if (nChars >= JSVAR_DATA_STRING_MAX_LEN) {
          jsvSetCharactersInVar(ext, nChars);
          JsVar *ext2 = jsvNewWithFlags(JSV_STRING_EXT_0);
          if (ext2) {
            jsvSetLastChild(ext, jsvGetRef(ext2));
          }
          jsvUnLock(ext);
          ext = ext2;
          nChars = 0;
        }
        ext->varData.str[nChars++] = jsvStringIteratorGetCharAndNext(&it);
      }
      jsvStringIteratorFree(&it);
      if (ext) {
        jsvSetCharactersInVar(ext, nChars);
        jsvUnLock(ext);
      }
      jsvSetCharactersInVar(var, JSVAR_DATA_STRING_NAME_LEN);
      
      JsVarRef oldRef = jsvGetLastChild(var);
      while (oldRef) {
        JsVar *v = jsvGetAddressOf(oldRef);
        oldRef = jsvGetLastChild(v);
        jsvFreePtrInternal(v);
      }
      
      jsvSetLastChild(var, jsvGetRef(startExt));
      jsvSetNextSibling(var, 0);
      jsvSetPrevSibling(var, 0);
      jsvSetFirstChild(var, 0);
      jsvUnLock(startExt);
    }

    size_t t = JSV_NAME_STRING_0;
    if (jsvIsInt(valueOrZero) && !jsvIsPin(valueOrZero)) {
      JsVarInt v = valueOrZero->varData.integer;
      if (v>=JSVARREF_MIN && v<=JSVARREF_MAX) {
        t = JSV_NAME_STRING_INT_0;
        jsvSetFirstChild(var, (JsVarRef)v);
        valueOrZero = 0;
      }
    } else jsvSetFirstChild(var, 0);
    var->flags = (var->flags & (JsVarFlags)~JSV_VARTYPEMASK) | (t+jsvGetCharactersInVar(var));
  } else assert(0);

  if (valueOrZero)
    jsvSetFirstChild(var, jsvGetRef(jsvRef(valueOrZero)));
  return var;
}

void jsvMakeFunctionParameter(JsVar *v) {
  assert(jsvIsString(v));
  if (!jsvIsName(v)) jsvMakeIntoVariableName(v,0);
  v->flags = (JsVarFlags)(v->flags | JSV_NATIVE);
}


void jsvAddFunctionParameter(JsVar *fn, JsVar *paramName, JsVar *value) {
  assert(jsvIsFunction(fn));
  if (!paramName) paramName = jsvNewFromEmptyString();
  assert(jsvIsString(paramName));
  if (paramName) {
    jsvMakeFunctionParameter(paramName); 
    jsvSetValueOfName(paramName, value);
    jsvAddName(fn, paramName);
    jsvUnLock(paramName);
  }
}

void *jsvGetNativeFunctionPtr(const JsVar *function) {
  
  JsVar *flatString = jsvFindChildFromString((JsVar*)function, JSPARSE_FUNCTION_CODE_NAME, 0);
  if (flatString) {
    flatString = jsvSkipNameAndUnLock(flatString);
    void *v = (void*)((size_t)function->varData.native.ptr + (char*)jsvGetFlatStringPointer(flatString));
    jsvUnLock(flatString);
    return v;
  } else return (void *)function->varData.native.ptr;
}


bool jsvIsBasicVarEqual(JsVar *a, JsVar *b) {
  
  if (a==b) return true;
  if (!a || !b) return false; 
  
  assert(jsvIsBasic(a) && jsvIsBasic(b));
  if (jsvIsNumeric(a) && jsvIsNumeric(b)) {
    if (jsvIsIntegerish(a)) {
      if (jsvIsIntegerish(b)) {
        return a->varData.integer == b->varData.integer;
      } else {
        assert(jsvIsFloat(b));
        return a->varData.integer == b->varData.floating;
      }
    } else {
      assert(jsvIsFloat(a));
      if (jsvIsIntegerish(b)) {
        return a->varData.floating == b->varData.integer;
      } else {
        assert(jsvIsFloat(b));
        return a->varData.floating == b->varData.floating;
      }
    }
  } else if (jsvIsString(a) && jsvIsString(b)) {
    JsvStringIterator ita, itb;
    jsvStringIteratorNew(&ita, a, 0);
    jsvStringIteratorNew(&itb, b, 0);
    while (true) {
      char a = jsvStringIteratorGetCharAndNext(&ita);
      char b = jsvStringIteratorGetCharAndNext(&itb);
      if (a != b) {
        jsvStringIteratorFree(&ita);
        jsvStringIteratorFree(&itb);
        return false;
      }
      if (!a) { 
        jsvStringIteratorFree(&ita);
        jsvStringIteratorFree(&itb);
        return true;
      }
    }
    
    return false; 
  } else {
    
    return false;
  }
}

bool jsvIsEqual(JsVar *a, JsVar *b) {
  if (jsvIsBasic(a) && jsvIsBasic(b))
    return jsvIsBasicVarEqual(a,b);
  return jsvGetRef(a)==jsvGetRef(b);
}


const char *jsvGetConstString(const JsVar *v) {
  if (jsvIsUndefined(v)) {
    return "undefined";
  } else if (jsvIsNull(v)) {
    return "null";
  } else if (jsvIsBoolean(v) && !jsvIsNameIntBool(v)) {
    return jsvGetBool(v) ? "true" : "false";
  }
  return 0;
}


const char *jsvGetTypeOf(const JsVar *v) {
  if (jsvIsUndefined(v)) return "undefined";
  if (jsvIsNull(v) || jsvIsObject(v) || jsvIsArray(v) || jsvIsArrayBuffer(v)) return "object";
  if (jsvIsFunction(v)) return "function";
  if (jsvIsString(v)) return "string";
  if (jsvIsBoolean(v)) return "boolean";
  if (jsvIsNumeric(v)) return "number";
  return "?";
}


JsVar *jsvGetValueOf(JsVar *v) {
  if (!jsvIsObject(v)) return jsvLockAgainSafe(v);
  JsVar *valueOf = jspGetNamedField(v, "valueOf", false);
  if (!jsvIsFunction(valueOf)) {
    jsvUnLock(valueOf);
    return jsvLockAgain(v);
  }
  v = jspeFunctionCall(valueOf, 0, v, false, 0, 0);
  jsvUnLock(valueOf);
  return v;
}


size_t jsvGetString(const JsVar *v, char *str, size_t len) {
  assert(len>0);
  const char *s = jsvGetConstString(v);
  if (s) {
    
    len--;
    size_t l = 0;
    while (s[l] && l<len) {
      str[l] = s[l];
      l++;
    }
    str[l] = 0;
    return l;
  } else if (jsvIsInt(v)) {
    itostr(v->varData.integer, str, 10);
    return strlen(str);
  } else if (jsvIsFloat(v)) {
    ftoa_bounded(v->varData.floating, str, len);
    return strlen(str);
  } else if (jsvHasCharacterData(v)) {
    assert(!jsvIsStringExt(v));
    size_t l = len;
    JsvStringIterator it;
    jsvStringIteratorNewConst(&it, v, 0);
    while (jsvStringIteratorHasChar(&it)) {
      if (l--<=1) {
        *str = 0;
        jsvStringIteratorFree(&it);
        return len;
      }
      *(str++) = jsvStringIteratorGetChar(&it);
      jsvStringIteratorNext(&it);
    }
    jsvStringIteratorFree(&it);
    *str = 0;
    return len-l;
  } else {
    
    JsVar *stringVar = jsvAsString((JsVar*)v); 
    if (stringVar) {
      size_t l = jsvGetStringChars(stringVar, 0, str, len); 
      jsvUnLock(stringVar);
      return l;
    } else {
      str[0] = 0;
      jsExceptionHere(JSET_INTERNALERROR, "Variable type cannot be converted to string");
      return 0;
    }
  }
}


size_t jsvGetStringChars(const JsVar *v, size_t startChar, char *str, size_t len) {
  assert(jsvHasCharacterData(v));
  size_t l = len;
  JsvStringIterator it;
  jsvStringIteratorNewConst(&it, v, startChar);
  while (jsvStringIteratorHasChar(&it)) {
    if (l--<=0) {
      jsvStringIteratorFree(&it);
      return len;
    }
    *(str++) = jsvStringIteratorGetCharAndNext(&it);
  }
  jsvStringIteratorFree(&it);
  return len-l;
}


void jsvSetString(JsVar *v, const char *str, size_t len) {
  assert(jsvHasCharacterData(v));
  
  


  JsvStringIterator it;
  jsvStringIteratorNew(&it, v, 0);
  size_t i;
  for (i=0;i<len;i++) {
    jsvStringIteratorSetCharAndNext(&it, str[i]);
  }
  jsvStringIteratorFree(&it);
}


JsVar *jsvAsString(JsVar *v) {
  JsVar *str = 0;
  
  if (jsvHasCharacterData(v) && jsvIsName(v)) {
    str = jsvNewFromStringVar(v,0,JSVAPPENDSTRINGVAR_MAXLENGTH);
  } else if (jsvIsString(v)) { 
    str = jsvLockAgain(v);
  } else if (jsvIsObject(v)) { 
    JsVar *toStringFn = jspGetNamedField(v, "toString", false);
    if (toStringFn && toStringFn->varData.native.ptr != (void (*)(void))jswrap_object_toString) {
      
      JsVar *result = jspExecuteFunction(toStringFn,v,0,0);
      jsvUnLock(toStringFn);
      str = jsvAsStringAndUnLock(result);
    } else {
      jsvUnLock(toStringFn);
      str = jsvNewFromString("[object Object]");
    }
  } else {
    const char *constChar = jsvGetConstString(v);
    assert(JS_NUMBER_BUFFER_SIZE>=10);
    char buf[JS_NUMBER_BUFFER_SIZE];
    if (constChar) {
      
      str = jsvNewFromString(constChar);
    } else if (jsvIsPin(v)) {
      jshGetPinString(buf, (Pin)v->varData.integer);
      str = jsvNewFromString(buf);
    } else if (jsvIsInt(v)) {
      itostr(v->varData.integer, buf, 10);
      str = jsvNewFromString(buf);
    } else if (jsvIsFloat(v)) {
      ftoa_bounded(v->varData.floating, buf, sizeof(buf));
      str = jsvNewFromString(buf);
    } else if (jsvIsArray(v) || jsvIsArrayBuffer(v)) {
      JsVar *filler = jsvNewFromString(",");
      str = jsvArrayJoin(v, filler, true);
      jsvUnLock(filler);
    } else if (jsvIsFunction(v)) {
      str = jsvNewFromEmptyString();
      if (str) jsfGetJSON(v, str, JSON_NONE);
    } else {
      jsExceptionHere(JSET_INTERNALERROR, "Variable type cannot be converted to string");
    }
  }
  return str;
}

JsVar *jsvAsStringAndUnLock(JsVar *var) {
  JsVar *s = jsvAsString(var);
  jsvUnLock(var);
  return s;
}

JsVar *jsvAsFlatString(JsVar *var) {
  if (jsvIsFlatString(var)) return jsvLockAgain(var);
  JsVar *str = jsvAsString(var);
  size_t len = jsvGetStringLength(str);
  JsVar *flat = jsvNewFlatStringOfLength((unsigned int)len);
  if (flat) {
    JsvStringIterator src;
    JsvStringIterator dst;
    jsvStringIteratorNew(&src, str, 0);
    jsvStringIteratorNew(&dst, flat, 0);
    while (len--) {
      jsvStringIteratorSetCharAndNext(&dst, jsvStringIteratorGetCharAndNext(&src));
    }
    jsvStringIteratorFree(&src);
    jsvStringIteratorFree(&dst);
  }
  jsvUnLock(str);
  return flat;
}


JsVar *jsvAsArrayIndex(JsVar *index) {
  if (jsvIsSimpleInt(index) && jsvGetInteger(index)>=0) {
    return jsvLockAgain(index); 
  } else if (jsvIsString(index)) {
    
    if (jsvIsStringNumericStrict(index)) {
      JsVar *i = jsvNewFromInteger(jsvGetInteger(index));
      JsVar *is = jsvAsString(i);
      if (jsvCompareString(index,is,0,0,false)==0) {
        
        jsvUnLock(is);
        return i;
      } else {
        
        jsvUnLock2(i,is);
      }
    }
  } else if (jsvIsFloat(index)) {
    
    JsVarFloat v = jsvGetFloat(index);
    JsVarInt vi = jsvGetInteger(index);
    if (v == vi) return jsvNewFromInteger(vi);
  }

  
  return jsvAsString(index);
}


JsVar *jsvAsArrayIndexAndUnLock(JsVar *a) {
  JsVar *b = jsvAsArrayIndex(a);
  jsvUnLock(a);
  return b;
}


bool jsvIsEmptyString(JsVar *v) {
  if (!jsvHasCharacterData(v)) return true;
  return jsvGetCharactersInVar(v)==0;
}

size_t jsvGetStringLength(const JsVar *v) {
  size_t strLength = 0;
  const JsVar *var = v;
  JsVar *newVar = 0;
  if (!jsvHasCharacterData(v)) return 0;

  while (var) {
    JsVarRef ref = jsvGetLastChild(var);
    strLength += jsvGetCharactersInVar(var);

    
    jsvUnLock(newVar); 
    var = newVar = jsvLockSafe(ref);
  }
  jsvUnLock(newVar); 
  return strLength;
}

size_t jsvGetFlatStringBlocks(const JsVar *v) {
  assert(jsvIsFlatString(v));
  return ((size_t)v->varData.integer+sizeof(JsVar)-1) / sizeof(JsVar);
}

char *jsvGetFlatStringPointer(JsVar *v) {
  assert(jsvIsFlatString(v));
  if (!jsvIsFlatString(v)) return 0;
  return (char*)(v+1); 
}

JsVar *jsvGetFlatStringFromPointer(char *v) {
  JsVar *secondVar = (JsVar*)v;
  JsVar *flatStr = secondVar-1;
  assert(jsvIsFlatString(flatStr));
  return flatStr;
}


char *jsvGetDataPointer(JsVar *v, size_t *len) {
  assert(len);
  if (jsvIsArrayBuffer(v)) {
    
    JsVar *d = jsvGetArrayBufferBackingString(v, NULL);
    char *r = jsvGetDataPointer(d, len);
    jsvUnLock(d);
    if (r) {
      r += v->varData.arraybuffer.byteOffset;
      *len = v->varData.arraybuffer.length;
    }
    return r;
  }
  if (jsvIsNativeString(v)) {
    *len = v->varData.nativeStr.len;
    return (char*)v->varData.nativeStr.ptr;
  }
  if (jsvIsFlatString(v)) {
    *len = jsvGetStringLength(v);
    return jsvGetFlatStringPointer(v);
  }
  if (jsvIsBasicString(v) && !jsvGetLastChild(v)) {
    
    *len = jsvGetCharactersInVar(v);
    return (char*)v->varData.str;
  }
  return 0;
}


size_t jsvGetLinesInString(JsVar *v) {
  size_t lines = 1;
  JsvStringIterator it;
  jsvStringIteratorNew(&it, v, 0);
  while (jsvStringIteratorHasChar(&it)) {
    if (jsvStringIteratorGetCharAndNext(&it)=='\n') lines++;
  }
  jsvStringIteratorFree(&it);
  return lines;
}


size_t jsvGetCharsOnLine(JsVar *v, size_t line) {
  size_t currentLine = 1;
  size_t chars = 0;
  JsvStringIterator it;
  jsvStringIteratorNew(&it, v, 0);
  while (jsvStringIteratorHasChar(&it)) {
    if (jsvStringIteratorGetCharAndNext(&it)=='\n') {
      currentLine++;
      if (currentLine > line) break;
    } else if (currentLine==line) chars++;
  }
  jsvStringIteratorFree(&it);
  return chars;
}


void jsvGetLineAndCol(JsVar *v, size_t charIdx, size_t *line, size_t *col) {
  size_t x = 1;
  size_t y = 1;
  size_t n = 0;
  assert(line && col);

  JsvStringIterator it;
  jsvStringIteratorNew(&it, v, 0);
  while (jsvStringIteratorHasChar(&it)) {
    char ch = jsvStringIteratorGetCharAndNext(&it);
    if (n==charIdx) {
      jsvStringIteratorFree(&it);
      *line = y;
      *col = x;
      return;
    }
    x++;
    if (ch=='\n') {
      x=1; y++;
    }
    n++;
  }
  jsvStringIteratorFree(&it);
  
  *line = y;
  *col = x;
}


size_t jsvGetIndexFromLineAndCol(JsVar *v, size_t line, size_t col) {
  size_t x = 1;
  size_t y = 1;
  size_t n = 0;
  JsvStringIterator it;
  jsvStringIteratorNew(&it, v, 0);
  while (jsvStringIteratorHasChar(&it)) {
    char ch = jsvStringIteratorGetCharAndNext(&it);
    if ((y==line && x>=col) || y>line) {
      jsvStringIteratorFree(&it);
      return (y>line) ? (n-1) : n;
    }
    x++;
    if (ch=='\n') {
      x=1; y++;
    }
    n++;
  }
  jsvStringIteratorFree(&it);
  return n;
}

void jsvAppendString(JsVar *var, const char *str) {
  assert(jsvIsString(var));
  JsvStringIterator dst;
  jsvStringIteratorNew(&dst, var, 0);
  jsvStringIteratorGotoEnd(&dst);
  
  
  while (*str)
    jsvStringIteratorAppend(&dst, *(str++));
  jsvStringIteratorFree(&dst);
}


void jsvAppendStringBuf(JsVar *var, const char *str, size_t length) {
  assert(jsvIsString(var));
  JsvStringIterator dst;
  jsvStringIteratorNew(&dst, var, 0);
  jsvStringIteratorGotoEnd(&dst);
  
  
  while (length) {
    jsvStringIteratorAppend(&dst, *(str++));
    length--;
  }
  jsvStringIteratorFree(&dst);
}


void jsvStringIteratorPrintfCallback(const char *str, void *user_data) {
  while (*str)
    jsvStringIteratorAppend((JsvStringIterator *)user_data, *(str++));
}

void jsvAppendPrintf(JsVar *var, const char *fmt, ...) {
  JsvStringIterator it;
  jsvStringIteratorNew(&it, var, 0);
  jsvStringIteratorGotoEnd(&it);

  va_list argp;
  va_start(argp, fmt);
  vcbprintf((vcbprintf_callback)jsvStringIteratorPrintfCallback,&it, fmt, argp);
  va_end(argp);

  jsvStringIteratorFree(&it);
}

JsVar *jsvVarPrintf( const char *fmt, ...) {
  JsVar *str = jsvNewFromEmptyString();
  if (!str) return 0;
  JsvStringIterator it;
  jsvStringIteratorNew(&it, str, 0);
  jsvStringIteratorGotoEnd(&it);

  va_list argp;
  va_start(argp, fmt);
  vcbprintf((vcbprintf_callback)jsvStringIteratorPrintfCallback,&it, fmt, argp);
  va_end(argp);

  jsvStringIteratorFree(&it);
  return str;
}


void jsvAppendStringVar(JsVar *var, const JsVar *str, size_t stridx, size_t maxLength) {
  assert(jsvIsString(var));

  JsvStringIterator dst;
  jsvStringIteratorNew(&dst, var, 0);
  jsvStringIteratorGotoEnd(&dst);
  
  
  JsvStringIterator it;
  jsvStringIteratorNewConst(&it, str, stridx);
  while (jsvStringIteratorHasChar(&it) && (maxLength-->0)) {
    char ch = jsvStringIteratorGetCharAndNext(&it);
    jsvStringIteratorAppend(&dst, ch);
  }
  jsvStringIteratorFree(&it);
  jsvStringIteratorFree(&dst);
}


JsVar *jsvNewFromStringVar(const JsVar *str, size_t stridx, size_t maxLength) {
  JsVar *var = jsvNewFromEmptyString();
  if (var) jsvAppendStringVar(var, str, stridx, maxLength);
  return var;
}


void jsvAppendStringVarComplete(JsVar *var, const JsVar *str) {
  jsvAppendStringVar(var, str, 0, JSVAPPENDSTRINGVAR_MAXLENGTH);
}

char jsvGetCharInString(JsVar *v, size_t idx) {
  if (!jsvIsString(v)) return 0;

  JsvStringIterator it;
  jsvStringIteratorNew(&it, v, idx);
  char ch = jsvStringIteratorGetChar(&it);
  jsvStringIteratorFree(&it);
  return ch;
}

void jsvSetCharInString(JsVar *v, size_t idx, char ch, bool bitwiseOR) {
  if (!jsvIsString(v)) return;
  JsvStringIterator it;
  jsvStringIteratorNew(&it, v, idx);
  if (bitwiseOR) ch |= jsvStringIteratorGetChar(&it);
  jsvStringIteratorSetChar(&it, ch);
  jsvStringIteratorFree(&it);
}


int jsvGetStringIndexOf(JsVar *str, char ch) {
  JsvStringIterator it;
  jsvStringIteratorNew(&it, str, 0);
  while (jsvStringIteratorHasChar(&it)) {
    if (jsvStringIteratorGetChar(&it) == ch) {
      int idx = (int)jsvStringIteratorGetIndex(&it);
      jsvStringIteratorFree(&it);
      return idx;
    };
    jsvStringIteratorNext(&it);
  }
  jsvStringIteratorFree(&it);
  return -1;
}


bool jsvIsStringNumericInt(const JsVar *var, bool allowDecimalPoint) {
  assert(jsvIsString(var));
  JsvStringIterator it;
  jsvStringIteratorNewConst(&it, var, 0); 

  
  while (jsvStringIteratorHasChar(&it) && isWhitespace(jsvStringIteratorGetChar(&it)))
    jsvStringIteratorNext(&it);

  
  if (jsvStringIteratorGetChar(&it)=='-' || jsvStringIteratorGetChar(&it)=='+')
    jsvStringIteratorNext(&it);

  int radix = 0;
  if (jsvStringIteratorGetChar(&it)=='0') {
    jsvStringIteratorNext(&it);
    char buf[3];
    buf[0] = '0';
    buf[1] = jsvStringIteratorGetChar(&it);
    buf[2] = 0;
    const char *p = buf;
    radix = getRadix(&p,0);
    if (p>&buf[1]) jsvStringIteratorNext(&it);
  }
  if (radix==0) radix=10;

  
  int chars=0;
  while (jsvStringIteratorHasChar(&it)) {
    chars++;
    char ch = jsvStringIteratorGetCharAndNext(&it);
    if (ch=='.' && allowDecimalPoint) {
      allowDecimalPoint = false; 
    } else {
      int n = chtod(ch);
      if (n<0 || n>=radix) {
        jsvStringIteratorFree(&it);
        return false;
      }
    }
  }
  jsvStringIteratorFree(&it);
  return chars>0;
}


bool jsvIsStringNumericStrict(const JsVar *var) {
  assert(jsvIsString(var));
  JsvStringIterator it;
  jsvStringIteratorNewConst(&it, var, 0);  
  bool hadNonZero = false;
  bool hasLeadingZero = false;
  int chars = 0;
  while (jsvStringIteratorHasChar(&it)) {
    chars++;
    char ch = jsvStringIteratorGetCharAndNext(&it);
    if (!isNumeric(ch)) {
      
      jsvStringIteratorFree(&it);
      return false;
    }
    if (!hadNonZero && ch=='0') hasLeadingZero=true;
    if (ch!='0') hadNonZero=true;
  }
  jsvStringIteratorFree(&it);
  return chars>0 && (!hasLeadingZero || chars==1);
}


JsVarInt jsvGetInteger(const JsVar *v) {
  if (!v) return 0; 
  
  if (jsvIsNull(v)) return 0;
  if (jsvIsUndefined(v)) return 0;
  if (jsvIsIntegerish(v) || jsvIsArrayBufferName(v)) return v->varData.integer;
  if (jsvIsArray(v) || jsvIsArrayBuffer(v)) {
    JsVarInt l = jsvGetLength((JsVar *)v);
    if (l==0) return 0; 
    if (l==1) {
      if (jsvIsArrayBuffer(v))
        return jsvGetIntegerAndUnLock(jsvArrayBufferGet((JsVar*)v,0));
      return jsvGetIntegerAndUnLock(jsvSkipNameAndUnLock(jsvGetArrayItem(v,0)));
    }
  }
  if (jsvIsFloat(v)) {
    if (isfinite(v->varData.floating))
      return (JsVarInt)(long long)v->varData.floating;
    return 0;
  }
  if (jsvIsString(v) && jsvIsStringNumericInt(v, true)) {
    char buf[32];
    if (jsvGetString(v, buf, sizeof(buf))==sizeof(buf))
      jsExceptionHere(JSET_ERROR, "String too big to convert to integer\n");
    else return (JsVarInt)stringToInt(buf);
  }
  return 0;
}

long long jsvGetLongInteger(const JsVar *v) {
  if (jsvIsInt(v)) return jsvGetInteger(v);
  return (long long)jsvGetFloat(v);
}

long long jsvGetLongIntegerAndUnLock(JsVar *v) {
  long long i = jsvGetLongInteger(v);
  jsvUnLock(v);
  return i;
}


void jsvSetInteger(JsVar *v, JsVarInt value) {
  assert(jsvIsInt(v));
  v->varData.integer  = value;
}


bool jsvGetBool(const JsVar *v) {
  if (jsvIsString(v))
    return jsvGetStringLength((JsVar*)v)!=0;
  if (jsvIsPin(v))
    return jshIsPinValid(jshGetPinFromVar((JsVar*)v));
  if (jsvIsFunction(v) || jsvIsArray(v) || jsvIsObject(v) || jsvIsArrayBuffer(v))
    return true;
  if (jsvIsFloat(v)) {
    JsVarFloat f = jsvGetFloat(v);
    return !isnan(f) && f!=0.0;
  }
  return jsvGetInteger(v)!=0;
}

JsVarFloat jsvGetFloat(const JsVar *v) {
  if (!v) return NAN; 
  if (jsvIsFloat(v)) return v->varData.floating;
  if (jsvIsIntegerish(v)) return (JsVarFloat)v->varData.integer;
  if (jsvIsArray(v) || jsvIsArrayBuffer(v)) {
    JsVarInt l = jsvGetLength(v);
    if (l==0) return 0; 
    if (l==1) {
      if (jsvIsArrayBuffer(v))
        return jsvGetFloatAndUnLock(jsvArrayBufferGet((JsVar*)v,0));
      return jsvGetFloatAndUnLock(jsvSkipNameAndUnLock(jsvGetArrayItem(v,0)));
    }
  }
  if (jsvIsString(v)) {
    char buf[64];
    if (jsvGetString(v, buf, sizeof(buf))==sizeof(buf)) {
      jsExceptionHere(JSET_ERROR, "String too big to convert to float\n");
    } else {
      if (buf[0]==0) return 0; 
      if (!strcmp(buf,"Infinity")) return INFINITY;
      if (!strcmp(buf,"-Infinity")) return -INFINITY;
      return stringToFloat(buf);
    }
  }
  return NAN;
}


JsVar *jsvAsNumber(JsVar *var) {
  
  if (jsvIsInt(var) || jsvIsFloat(var)) return jsvLockAgain(var);
  
  if (jsvIsBoolean(var) || jsvIsPin(var) || jsvIsNull(var) || jsvIsBoolean(var) || jsvIsArrayBufferName(var))



    return jsvNewFromInteger(jsvGetInteger(var));
  if (jsvIsString(var) && (jsvIsEmptyString(var) || jsvIsStringNumericInt(var, false))) {
    
    char buf[64];
    if (jsvGetString(var, buf, sizeof(buf))==sizeof(buf)) {
      jsExceptionHere(JSET_ERROR, "String too big to convert to integer\n");
      return jsvNewFromFloat(NAN);
    } else return jsvNewFromLongInteger(stringToInt(buf));
  }
  
  return jsvNewFromFloat(jsvGetFloat(var));
}

JsVarInt jsvGetIntegerAndUnLock(JsVar *v) { return _jsvGetIntegerAndUnLock(v); }
JsVarFloat jsvGetFloatAndUnLock(JsVar *v) { return _jsvGetFloatAndUnLock(v); }
bool jsvGetBoolAndUnLock(JsVar *v) { return _jsvGetBoolAndUnLock(v); }




JsVar *jsvExecuteGetter(JsVar *parent, JsVar *getset) {
  assert(jsvIsGetterOrSetter(getset));
  if (!jsvIsGetterOrSetter(getset)) return 0; 
  JsVar *fn = jsvObjectGetChild(getset, "get", 0);
  if (!jsvIsFunction(fn)) {
    jsvUnLock(fn);
    return 0;
  }
  JsVar *result = jspExecuteFunction(fn, parent, 0, NULL);
  jsvUnLock(fn);
  return result;
}


void jsvExecuteSetter(JsVar *parent, JsVar *getset, JsVar *value) {
  assert(jsvIsGetterOrSetter(getset));
  if (!jsvIsGetterOrSetter(getset)) return; 
  JsVar *fn = jsvObjectGetChild(getset, "set", 0);
  if (!jsvIsFunction(fn)) {
    jsvUnLock(fn);
    return;
  }
  if (!fn) return;
  jsvUnLock2(jspExecuteFunction(fn, parent, 1, &value), fn);
}


void jsvAddGetterOrSetter(JsVar *obj, JsVar *varName, bool isGetter, JsVar *method) {
  
  JsVar *getsetName = jsvFindChildFromVar(obj, varName, true);
  if (jsvIsName(getsetName)) {
    JsVar *getset = jsvGetValueOfName(getsetName);
    if (!jsvIsGetterOrSetter(getset)) {
      jsvUnLock(getset);
      getset = jsvNewWithFlags(JSV_GET_SET);
      jsvSetValueOfName(getsetName, getset);
    }
    if (jsvIsGetterOrSetter(getset))
      jsvObjectSetChild(getset, isGetter?"get":"set", method);
    jsvUnLock(getset);
  }
  jsvUnLock(getsetName);
}




void jsvReplaceWith(JsVar *dst, JsVar *src) {
  
  if (jsvIsArrayBufferName(dst)) {
    size_t idx = (size_t)jsvGetInteger(dst);
    JsVar *arrayBuffer = jsvLock(jsvGetFirstChild(dst));
    jsvArrayBufferSet(arrayBuffer, idx, src);
    jsvUnLock(arrayBuffer);
    return;
  }
  
  if (!jsvIsName(dst)) {
    jsExceptionHere(JSET_ERROR, "Unable to assign value to non-reference %t", dst);
    return;
  }

  JsVar *v = jsvGetValueOfName(dst);
  if (jsvIsGetterOrSetter(v)) {
    JsVar *parent = jsvIsNewChild(dst)?jsvLock(jsvGetNextSibling(dst)):0;
    jsvExecuteSetter(parent,v,src);
    jsvUnLock2(v,parent);
    return;
  }
  jsvUnLock(v);

  jsvSetValueOfName(dst, src);
  
  if (jsvIsNewChild(dst)) {
    
    JsVar *parent = jsvLock(jsvGetNextSibling(dst));
    if (!jsvIsString(parent)) {
      
      
      if (!jsvHasChildren(parent)) {
        jsExceptionHere(JSET_ERROR, "Field or method \"%v\" does not already exist, and can't create it on %t", dst, parent);
      } else {
        
        jsvUnRef(parent);
        jsvSetNextSibling(dst, 0);
        jsvUnRef(parent);
        jsvSetPrevSibling(dst, 0);
        
        jsvAddName(parent, dst);
      }
    }
    jsvUnLock(parent);
  }
}


void jsvReplaceWithOrAddToRoot(JsVar *dst, JsVar *src) {
  
  if (!jsvGetRefs(dst) && jsvIsName(dst)) {
    if (!jsvIsArrayBufferName(dst) && !jsvIsNewChild(dst))
      jsvAddName(execInfo.root, dst);
  }
  jsvReplaceWith(dst, src);
}


size_t jsvGetArrayBufferLength(const JsVar *arrayBuffer) {
  assert(jsvIsArrayBuffer(arrayBuffer));
  return arrayBuffer->varData.arraybuffer.length;
}


JsVar *jsvGetArrayBufferBackingString(JsVar *arrayBuffer, uint32_t *offset) {
  jsvLockAgain(arrayBuffer);
  if (offset) *offset = 0;
  while (jsvIsArrayBuffer(arrayBuffer)) {
    if (offset) *offset += arrayBuffer->varData.arraybuffer.byteOffset;
    JsVar *s = jsvLock(jsvGetFirstChild(arrayBuffer));
    jsvUnLock(arrayBuffer);
    arrayBuffer = s;
  }
  assert(jsvIsString(arrayBuffer));
  return arrayBuffer;
}


JsVar *jsvArrayBufferGet(JsVar *arrayBuffer, size_t idx) {
  JsvArrayBufferIterator it;
  jsvArrayBufferIteratorNew(&it, arrayBuffer, idx);
  JsVar *v = jsvArrayBufferIteratorGetValue(&it);
  jsvArrayBufferIteratorFree(&it);
  return v;
}


void jsvArrayBufferSet(JsVar *arrayBuffer, size_t idx, JsVar *value) {
  JsvArrayBufferIterator it;
  jsvArrayBufferIteratorNew(&it, arrayBuffer, idx);
  jsvArrayBufferIteratorSetValue(&it, value);
  jsvArrayBufferIteratorFree(&it);
}



JsVar *jsvArrayBufferGetFromName(JsVar *name) {
  assert(jsvIsArrayBufferName(name));
  size_t idx = (size_t)jsvGetInteger(name);
  JsVar *arrayBuffer = jsvLock(jsvGetFirstChild(name));
  JsVar *value = jsvArrayBufferGet(arrayBuffer, idx);
  jsvUnLock(arrayBuffer);
  return value;
}


JsVar *jsvGetFunctionArgumentLength(JsVar *functionScope) {
  JsVar *args = jsvNewEmptyArray();
  if (!args) return 0; 

  JsvObjectIterator it;
  jsvObjectIteratorNew(&it, functionScope);
  while (jsvObjectIteratorHasValue(&it)) {
    JsVar *idx = jsvObjectIteratorGetKey(&it);
    if (jsvIsFunctionParameter(idx)) {
      JsVar *val = jsvSkipOneName(idx);
      jsvArrayPushAndUnLock(args, val);
    }
    jsvUnLock(idx);
    jsvObjectIteratorNext(&it);
  }
  jsvObjectIteratorFree(&it);

  return args;
}


bool jsvIsVariableDefined(JsVar *a) {
  return !jsvIsName(a) || jsvIsNameWithValue(a) || (jsvGetFirstChild(a)!=0);

}


JsVar *jsvGetValueOfName(JsVar *a) {
  if (!a) return 0;
  if (jsvIsArrayBufferName(a)) return jsvArrayBufferGetFromName(a);
  if (jsvIsNameInt(a)) return jsvNewFromInteger((JsVarInt)jsvGetFirstChildSigned(a));
  if (jsvIsNameIntBool(a)) return jsvNewFromBool(jsvGetFirstChild(a)!=0);
  assert(!jsvIsNameWithValue(a));
  if (jsvIsName(a))
    return jsvLockSafe(jsvGetFirstChild(a));
  return 0;
}


void jsvCheckReferenceError(JsVar *a) {
  if (jsvIsBasicName(a) && jsvGetRefs(a)==0 && !jsvIsNewChild(a) && !jsvGetFirstChild(a))
    jsExceptionHere(JSET_REFERENCEERROR, "%q is not defined", a);
}




JsVar *jsvSkipNameWithParent(JsVar *a, bool repeat, JsVar *parent) {
  if (!a) return 0;
  if (jsvIsArrayBufferName(a)) return jsvArrayBufferGetFromName(a);
  if (jsvIsNameInt(a)) return jsvNewFromInteger((JsVarInt)jsvGetFirstChildSigned(a));
  if (jsvIsNameIntBool(a)) return jsvNewFromBool(jsvGetFirstChild(a)!=0);
  JsVar *pa = jsvLockAgain(a);
  while (jsvIsName(pa)) {
    JsVarRef n = jsvGetFirstChild(pa);
    jsvUnLock(pa);
    if (!n) {
      
      if (pa==a) jsvCheckReferenceError(a);
      return 0;
    }
    pa = jsvLock(n);
    assert(pa!=a);
    if (!repeat) break;
  }

  if (jsvIsGetterOrSetter(pa)) {
    JsVar *getterParent = jsvIsNewChild(a)?jsvLock(jsvGetNextSibling(a)):0;
    JsVar *v = jsvExecuteGetter(getterParent?getterParent:parent, pa);
    jsvUnLock2(getterParent,pa);
    pa = v;
  }

  return pa;
}


JsVar *jsvSkipName(JsVar *a) {
  return jsvSkipNameWithParent(a, true, 0);
}


JsVar *jsvSkipOneName(JsVar *a) {
  return jsvSkipNameWithParent(a, false, 0);
}


JsVar *jsvSkipToLastName(JsVar *a) {
  assert(jsvIsName(a));
  a = jsvLockAgain(a);
  while (true) {
    if (!jsvGetFirstChild(a)) return a;
    JsVar *child = jsvLock(jsvGetFirstChild(a));
    if (jsvIsName(child)) {
      jsvUnLock(a);
      a = child;
    } else {
      jsvUnLock(child);
      return a;
    }
  }
  return 0; 
}


JsVar *jsvSkipNameAndUnLock(JsVar *a) {
  JsVar *b = jsvSkipName(a);
  jsvUnLock(a);
  return b;
}


JsVar *jsvSkipOneNameAndUnLock(JsVar *a) {
  JsVar *b = jsvSkipOneName(a);
  jsvUnLock(a);
  return b;
}

bool jsvIsStringEqualOrStartsWithOffset(JsVar *var, const char *str, bool isStartsWith, size_t startIdx, bool ignoreCase) {
  if (!jsvHasCharacterData(var)) {
    return 0; 
  }

  JsvStringIterator it;
  jsvStringIteratorNew(&it, var, startIdx);
  if (ignoreCase) {
      while (jsvStringIteratorHasChar(&it) && *str && charToLowerCase(jsvStringIteratorGetChar(&it)) == charToLowerCase(*str)) {
        str++;
        jsvStringIteratorNext(&it);
      }
  } else {
      while (jsvStringIteratorHasChar(&it) && *str && jsvStringIteratorGetChar(&it) == *str) {
        str++;
        jsvStringIteratorNext(&it);
      }
  }
  bool eq = (isStartsWith && !*str) || jsvStringIteratorGetChar(&it)==*str;
  jsvStringIteratorFree(&it);
  return eq;
}


bool jsvIsStringEqualOrStartsWith(JsVar *var, const char *str, bool isStartsWith) {
  return jsvIsStringEqualOrStartsWithOffset(var, str, isStartsWith, 0, false);
}


bool jsvIsStringEqual(JsVar *var, const char *str) {
  return jsvIsStringEqualOrStartsWith(var, str, false);
}


bool jsvIsStringIEqualAndUnLock(JsVar *var, const char *str) {
  bool b = jsvIsStringEqualOrStartsWithOffset(var, str, false, 0, true);
  jsvUnLock(var);
  return b;
}



int jsvCompareString(JsVar *va, JsVar *vb, size_t starta, size_t startb, bool equalAtEndOfString) {
  JsvStringIterator ita, itb;
  jsvStringIteratorNew(&ita, va, starta);
  jsvStringIteratorNew(&itb, vb, startb);
  
  while (true) {
    int ca = jsvStringIteratorGetCharOrMinusOne(&ita);
    int cb = jsvStringIteratorGetCharOrMinusOne(&itb);

    if (ca != cb) {
      jsvStringIteratorFree(&ita);
      jsvStringIteratorFree(&itb);
      if ((ca<0 || cb<0) && equalAtEndOfString) return 0;
      return ca - cb;
    }
    if (ca < 0) { 
      jsvStringIteratorFree(&ita);
      jsvStringIteratorFree(&itb);
      return 0;
    }
    jsvStringIteratorNext(&ita);
    jsvStringIteratorNext(&itb);
  }
  
  return true;
}


JsVar *jsvGetCommonCharacters(JsVar *va, JsVar *vb) {
  JsVar *v = jsvNewFromEmptyString();
  if (!v) return 0;
  JsvStringIterator ita, itb;
  jsvStringIteratorNew(&ita, va, 0);
  jsvStringIteratorNew(&itb, vb, 0);
  int ca = jsvStringIteratorGetCharOrMinusOne(&ita);
  int cb = jsvStringIteratorGetCharOrMinusOne(&itb);
  while (ca>0 && cb>0 && ca == cb) {
    jsvAppendCharacter(v, (char)ca);
    jsvStringIteratorNext(&ita);
    jsvStringIteratorNext(&itb);
    ca = jsvStringIteratorGetCharOrMinusOne(&ita);
    cb = jsvStringIteratorGetCharOrMinusOne(&itb);
  }
  jsvStringIteratorFree(&ita);
  jsvStringIteratorFree(&itb);
  return v;
}



int jsvCompareInteger(JsVar *va, JsVar *vb) {
  if (jsvIsInt(va) && jsvIsInt(vb))
    return (int)(jsvGetInteger(va) - jsvGetInteger(vb));
  else if (jsvIsInt(va))
    return -1;
  else if (jsvIsInt(vb))
    return 1;
  else return 0;
}


JsVar *jsvCopyNameOnly(JsVar *src, bool linkChildren, bool keepAsName) {
  assert(jsvIsName(src));
  JsVarFlags flags = src->flags;
  JsVar *dst = 0;
  if (!keepAsName) {
    JsVarFlags t = src->flags & JSV_VARTYPEMASK;
    if (t>=_JSV_NAME_INT_START && t<=_JSV_NAME_INT_END) {
      flags = (flags & ~JSV_VARTYPEMASK) | JSV_INTEGER;
    } else {
      assert((JSV_NAME_STRING_INT_0 < JSV_NAME_STRING_0) && (JSV_NAME_STRING_0 < JSV_STRING_0) && (JSV_STRING_0 < JSV_STRING_EXT_0));

      assert(t>=JSV_NAME_STRING_INT_0 && t<=JSV_NAME_STRING_MAX);
      if (jsvGetLastChild(src)) {
        
        dst = jsvNewFromStringVar(src, 0, JSVAPPENDSTRINGVAR_MAXLENGTH);
        if (!dst) return 0;
      } else {
        flags = (flags & (JsVarFlags)~JSV_VARTYPEMASK) | (JSV_STRING_0 + jsvGetCharactersInVar(src));
      }
    }
  }
  if (!dst) {
    dst = jsvNewWithFlags(flags & JSV_VARIABLEINFOMASK);
    if (!dst) return 0; 

    memcpy(&dst->varData, &src->varData, JSVAR_DATA_STRING_NAME_LEN);

    assert(jsvGetLastChild(dst) == 0);
    assert(jsvGetFirstChild(dst) == 0);
    assert(jsvGetPrevSibling(dst) == 0);
    assert(jsvGetNextSibling(dst) == 0);
    
    if (jsvHasStringExt(src)) {
      
      assert(keepAsName || !jsvGetLastChild(src));
      
      if (jsvGetLastChild(src)) {
        JsVar *child = jsvLock(jsvGetLastChild(src));
        JsVar *childCopy = jsvCopy(child, true);
        if (childCopy) { 
          jsvSetLastChild(dst, jsvGetRef(childCopy)); 
          jsvUnLock(childCopy);
        }
        jsvUnLock(child);
      }
    } else {
      assert(jsvIsBasic(src)); 
    }
  }
  
  if (linkChildren && jsvGetFirstChild(src)) {
    if (jsvIsNameWithValue(src))
      jsvSetFirstChild(dst, jsvGetFirstChild(src));
    else jsvSetFirstChild(dst, jsvRefRef(jsvGetFirstChild(src)));
  }
  return dst;
}

JsVar *jsvCopy(JsVar *src, bool copyChildren) {
  if (jsvIsFlatString(src)) {
    
    return jsvNewFromStringVar(src, 0, JSVAPPENDSTRINGVAR_MAXLENGTH);
  }
  JsVar *dst = jsvNewWithFlags(src->flags & JSV_VARIABLEINFOMASK);
  if (!dst) return 0; 
  if (!jsvIsStringExt(src)) {
      bool refsAsData = jsvIsBasicString(src)||jsvIsNativeString(src)||jsvIsFlashString(src)||jsvIsNativeFunction(src);
      memcpy(&dst->varData, &src->varData, refsAsData ? JSVAR_DATA_STRING_LEN : JSVAR_DATA_STRING_NAME_LEN);
      if (jsvIsNativeFunction(src)) {
        jsvSetFirstChild(dst,0);
      }
      if (!refsAsData) {
        assert(jsvGetPrevSibling(dst) == 0);
        assert(jsvGetNextSibling(dst) == 0);
        assert(jsvGetFirstChild(dst) == 0);
      }
      assert(jsvGetLastChild(dst) == 0);
  } else {
    
    
    memcpy(&dst->varData, &src->varData, JSVAR_DATA_STRING_MAX_LEN);
    assert(jsvGetLastChild(dst) == 0);
  }

  
  if (copyChildren && jsvIsName(src)) {
    if (jsvGetFirstChild(src)) {
      if (jsvIsNameWithValue(src)) {
        
        jsvSetFirstChild(dst, jsvGetFirstChild(src));
      } else {
        JsVar *child = jsvLock(jsvGetFirstChild(src));
        JsVar *childCopy = jsvRef(jsvCopy(child, true));
        jsvUnLock(child);
        if (childCopy) { 
          jsvSetFirstChild(dst, jsvGetRef(childCopy));
          jsvUnLock(childCopy);
        }
      }
    }
  }

  if (jsvHasStringExt(src)) {
    
    src = jsvLockAgain(src);
    JsVar *dstChild = jsvLockAgain(dst);
    while (jsvGetLastChild(src)) {
      JsVar *child = jsvLock(jsvGetLastChild(src));
      if (jsvIsStringExt(child)) {
        JsVar *childCopy = jsvNewWithFlags(child->flags & JSV_VARIABLEINFOMASK);
        if (childCopy) {
          memcpy(&childCopy->varData, &child->varData, JSVAR_DATA_STRING_MAX_LEN);
          jsvSetLastChild(dstChild, jsvGetRef(childCopy)); 
        }
        jsvUnLock2(src,dstChild);
        src = child;
        dstChild = childCopy;
      } else {
        JsVar *childCopy = jsvCopy(child, true);
        if (childCopy) {
          jsvSetLastChild(dstChild, jsvGetRef(childCopy)); 
          jsvUnLock(childCopy);
        }
        jsvUnLock2(src, dstChild);
        return dst;
      }
    }
    jsvUnLock2(src,dstChild);
  } else if (jsvHasChildren(src)) {
    if (copyChildren) {
      
      JsVarRef vr;
      vr = jsvGetFirstChild(src);
      while (vr) {
        JsVar *name = jsvLock(vr);
        JsVar *child = jsvCopyNameOnly(name, true, true); 
        if (child) { 
          jsvAddName(dst, child);
          jsvUnLock(child);
        }
        vr = jsvGetNextSibling(name);
        jsvUnLock(name);
      }
    }
  } else {
    assert(jsvIsBasic(src)); 
  }

  return dst;
}

void jsvAddName(JsVar *parent, JsVar *namedChild) {
  namedChild = jsvRef(namedChild); 
  assert(jsvIsName(namedChild));

  
  if (jsvIsArray(parent) && jsvIsInt(namedChild)) {
    JsVarInt index = namedChild->varData.integer;
    if (index >= jsvGetArrayLength(parent)) {
      jsvSetArrayLength(parent, index + 1, false);
    }
  }

  if (jsvGetLastChild(parent)) { 
    JsVar *insertAfter = jsvLock(jsvGetLastChild(parent));
    if (jsvIsArray(parent)) {
      
      while (insertAfter && jsvCompareInteger(namedChild, insertAfter)<0) {
        JsVarRef prev = jsvGetPrevSibling(insertAfter);
        jsvUnLock(insertAfter);
        insertAfter = jsvLockSafe(prev);
      }
    }

    if (insertAfter) {
      if (jsvGetNextSibling(insertAfter)) {
        
        JsVar *insertBefore = jsvLock(jsvGetNextSibling(insertAfter));
        jsvSetPrevSibling(insertBefore, jsvGetRef(namedChild));
        jsvSetNextSibling(namedChild, jsvGetRef(insertBefore));
        jsvUnLock(insertBefore);
      } else {
        
        jsvSetLastChild(parent, jsvGetRef(namedChild));
      }
      jsvSetNextSibling(insertAfter, jsvGetRef(namedChild));
      jsvSetPrevSibling(namedChild, jsvGetRef(insertAfter));
      jsvUnLock(insertAfter);
    } else { 
      
      JsVar *firstChild = jsvLock(jsvGetFirstChild(parent));
      jsvSetPrevSibling(firstChild, jsvGetRef(namedChild));
      jsvUnLock(firstChild);

      jsvSetNextSibling(namedChild, jsvGetFirstChild(parent));
      
      jsvSetFirstChild(parent, jsvGetRef(namedChild));
    }
  } else { 
    JsVarRef r = jsvGetRef(namedChild);
    jsvSetFirstChild(parent, r);
    jsvSetLastChild(parent, r);
  }
}

JsVar *jsvAddNamedChild(JsVar *parent, JsVar *child, const char *name) {
  JsVar *namedChild = jsvMakeIntoVariableName(jsvNewFromString(name), child);
  if (!namedChild) return 0; 
  jsvAddName(parent, namedChild);
  return namedChild;
}

JsVar *jsvSetNamedChild(JsVar *parent, JsVar *child, const char *name) {
  JsVar *namedChild = jsvFindChildFromString(parent, name, true);
  if (namedChild) 
    return jsvSetValueOfName(namedChild, child);
  return 0;
}

JsVar *jsvSetValueOfName(JsVar *name, JsVar *src) {
  assert(name && jsvIsName(name));
  assert(name!=src); 
  
  
  if (jsvIsNameWithValue(name)) {
    if (jsvIsString(name))
      name->flags = (name->flags & (JsVarFlags)~JSV_VARTYPEMASK) | (JSV_NAME_STRING_0 + jsvGetCharactersInVar(name));
    else name->flags = (name->flags & (JsVarFlags)~JSV_VARTYPEMASK) | JSV_NAME_INT;
    jsvSetFirstChild(name, 0);
  } else if (jsvGetFirstChild(name))
    jsvUnRefRef(jsvGetFirstChild(name)); 
  if (src) {
    if (jsvIsInt(name)) {
      if ((jsvIsInt(src) || jsvIsBoolean(src)) && !jsvIsPin(src)) {
        JsVarInt v = src->varData.integer;
        if (v>=JSVARREF_MIN && v<=JSVARREF_MAX) {
          name->flags = (name->flags & (JsVarFlags)~JSV_VARTYPEMASK) | (jsvIsInt(src) ? JSV_NAME_INT_INT : JSV_NAME_INT_BOOL);
          jsvSetFirstChild(name, (JsVarRef)v);
          return name;
        }
      }
    } else if (jsvIsString(name)) {
      if (jsvIsInt(src) && !jsvIsPin(src)) {
        JsVarInt v = src->varData.integer;
        if (v>=JSVARREF_MIN && v<=JSVARREF_MAX) {
          name->flags = (name->flags & (JsVarFlags)~JSV_VARTYPEMASK) | (JSV_NAME_STRING_INT_0 + jsvGetCharactersInVar(name));
          jsvSetFirstChild(name, (JsVarRef)v);
          return name;
        }
      }
    }
    
    jsvSetFirstChild(name, jsvGetRef(jsvRef(src)));
  } else jsvSetFirstChild(name, 0);
  return name;
}

JsVar *jsvFindChildFromString(JsVar *parent, const char *name, bool addIfNotFound) {
  
  char fastCheck[4];
  fastCheck[0] = name[0];
  if (name[0]) {
    fastCheck[1] = name[1];
    if (name[1]) {
      fastCheck[2] = name[2];
      if (name[2]) {
        fastCheck[3] = name[3];
      } else {
        fastCheck[3] = 0;
      }
    } else {
      fastCheck[2] = 0;
      fastCheck[3] = 0;
    }
  } else {
    fastCheck[1] = 0;
    fastCheck[2] = 0;
    fastCheck[3] = 0;
  }

  assert(jsvHasChildren(parent));
  JsVarRef childref = jsvGetFirstChild(parent);
  while (childref) {
    
    
    JsVar *child = jsvGetAddressOf(childref);
    if (*(int*)fastCheck==*(int*)child->varData.str &&  jsvIsStringEqual(child, name)) {
      
      return jsvLockAgain(child);
    }
    childref = jsvGetNextSibling(child);
  }

  JsVar *child = 0;
  if (addIfNotFound) {
    child = jsvMakeIntoVariableName(jsvNewFromString(name), 0);
    if (child) 
      jsvAddName(parent, child);
  }
  return child;
}


JsVar *jsvFindChildFromStringI(JsVar *parent, const char *name) {
  assert(jsvHasChildren(parent));
  JsVarRef childref = jsvGetFirstChild(parent);
  while (childref) {
    
    
    JsVar *child = jsvGetAddressOf(childref);
    if (jsvHasCharacterData(child) && jsvIsStringEqualOrStartsWithOffset(child, name, false, 0, true)) {
      
      return jsvLockAgain(child);
    }
    childref = jsvGetNextSibling(child);
  }
  return 0;
}


JsVar *jsvCreateNewChild(JsVar *parent, JsVar *index, JsVar *child) {
  JsVar *newChild = jsvAsName(index);
  if (!newChild) return 0;
  assert(!jsvGetFirstChild(newChild));
  if (child) jsvSetValueOfName(newChild, child);
  assert(!jsvGetNextSibling(newChild) && !jsvGetPrevSibling(newChild));
  
  
  JsVarRef r = jsvGetRef(jsvRef(jsvRef(parent)));
  jsvSetNextSibling(newChild, r);
  jsvSetPrevSibling(newChild, r);

  return newChild;
}


JsVar *jsvAsName(JsVar *var) {
  if (!var) return 0;
  if (jsvGetRefs(var) == 0) {
    
    if (!jsvIsName(var))
      var = jsvMakeIntoVariableName(var, 0);
    return jsvLockAgain(var);
  } else { 
    return jsvMakeIntoVariableName(jsvCopy(var, false), 0);
  }
}


JsVar *jsvFindChildFromVar(JsVar *parent, JsVar *childName, bool addIfNotFound) {
  JsVar *child;
  JsVarRef childref = jsvGetFirstChild(parent);

  while (childref) {
    child = jsvLock(childref);
    if (jsvIsBasicVarEqual(child, childName)) {
      
      return child;
    }
    childref = jsvGetNextSibling(child);
    jsvUnLock(child);
  }

  child = 0;
  if (addIfNotFound && childName) {
    child = jsvAsName(childName);
    jsvAddName(parent, child);
  }
  return child;
}

void jsvRemoveChild(JsVar *parent, JsVar *child) {
  assert(jsvHasChildren(parent));
  assert(jsvIsName(child));
  JsVarRef childref = jsvGetRef(child);
  bool wasChild = false;
  
  if (jsvGetFirstChild(parent) == childref) {
    jsvSetFirstChild(parent, jsvGetNextSibling(child));
    wasChild = true;
  }
  if (jsvGetLastChild(parent) == childref) {
    jsvSetLastChild(parent, jsvGetPrevSibling(child));
    wasChild = true;
    
    
    if (jsvIsArray(parent)) {
      JsVarInt l = 0;
      
      if (jsvGetLastChild(parent))
        l = jsvGetIntegerAndUnLock(jsvLock(jsvGetLastChild(parent)))+1;
      
      jsvSetArrayLength(parent, l, false);
    }
  }
  
  if (jsvGetPrevSibling(child)) {
    JsVar *v = jsvLock(jsvGetPrevSibling(child));
    assert(jsvGetNextSibling(v) == jsvGetRef(child));
    jsvSetNextSibling(v, jsvGetNextSibling(child));
    jsvUnLock(v);
    wasChild = true;
  }
  if (jsvGetNextSibling(child)) {
    JsVar *v = jsvLock(jsvGetNextSibling(child));
    assert(jsvGetPrevSibling(v) == jsvGetRef(child));
    jsvSetPrevSibling(v, jsvGetPrevSibling(child));
    jsvUnLock(v);
    wasChild = true;
  }

  jsvSetPrevSibling(child, 0);
  jsvSetNextSibling(child, 0);
  if (wasChild)
    jsvUnRef(child);
}

void jsvRemoveAllChildren(JsVar *parent) {
  assert(jsvHasChildren(parent));
  while (jsvGetFirstChild(parent)) {
    JsVar *v = jsvLock(jsvGetFirstChild(parent));
    jsvRemoveChild(parent, v);
    jsvUnLock(v);
  }
}


bool jsvIsChild(JsVar *parent, JsVar *child) {
  assert(jsvIsArray(parent) || jsvIsObject(parent));
  assert(jsvIsName(child));
  JsVarRef childref = jsvGetRef(child);
  JsVarRef indexref;
  indexref = jsvGetFirstChild(parent);
  while (indexref) {
    if (indexref == childref) return true;
    
    JsVar *indexVar = jsvLock(indexref);
    indexref = jsvGetNextSibling(indexVar);
    jsvUnLock(indexVar);
  }
  return false; 
}


JsVar *jsvObjectGetChild(JsVar *obj, const char *name, JsVarFlags createChild) {
  if (!obj) return 0;
  assert(jsvHasChildren(obj));
  JsVar *childName = jsvFindChildFromString(obj, name, createChild!=0);
  JsVar *child = jsvSkipName(childName);
  if (!child && createChild && childName!=0) {
    child = jsvNewWithFlags(createChild);
    jsvSetValueOfName(childName, child);
    jsvUnLock(childName);
    return child;
  }
  jsvUnLock(childName);
  return child;
}


JsVar *jsvObjectGetChildI(JsVar *obj, const char *name) {
  if (!obj) return 0;
  assert(jsvHasChildren(obj));
  return jsvSkipNameAndUnLock(jsvFindChildFromStringI(obj, name));
}


JsVar *jsvObjectSetChild(JsVar *obj, const char *name, JsVar *child) {
  assert(jsvHasChildren(obj));
  if (!jsvHasChildren(obj)) return 0;
  
  JsVar *childName = jsvFindChildFromString(obj, name, true);
  if (!childName) return 0; 
  jsvSetValueOfName(childName, child);
  jsvUnLock(childName);
  return child;
}


JsVar *jsvObjectSetChildVar(JsVar *obj, JsVar *name, JsVar *child) {
  assert(jsvHasChildren(obj));
  if (!jsvHasChildren(obj)) return 0;
  
  JsVar *childName = jsvFindChildFromVar(obj, name, true);
  if (!childName) return 0; 
  jsvSetValueOfName(childName, child);
  jsvUnLock(childName);
  return child;
}

void jsvObjectSetChildAndUnLock(JsVar *obj, const char *name, JsVar *child) {
  jsvUnLock(jsvObjectSetChild(obj, name, child));
}

void jsvObjectRemoveChild(JsVar *obj, const char *name) {
  JsVar *child = jsvFindChildFromString(obj, name, false);
  if (child) {
    jsvRemoveChild(obj, child);
    jsvUnLock(child);
  }
}


JsVar *jsvObjectSetOrRemoveChild(JsVar *obj, const char *name, JsVar *child) {
  if (child)
    jsvObjectSetChild(obj, name, child);
  else jsvObjectRemoveChild(obj, name);
  return child;
}


void jsvObjectAppendAll(JsVar *target, JsVar *source) {
  assert(jsvIsObject(target));
  assert(jsvIsObject(source));
  JsvObjectIterator it;
  jsvObjectIteratorNew(&it, source);
  while (jsvObjectIteratorHasValue(&it)) {
    JsVar *k = jsvObjectIteratorGetKey(&it);
    JsVar *v = jsvSkipName(k);
    if (!jsvIsInternalObjectKey(k))
      jsvObjectSetChildVar(target, k, v);
    jsvUnLock2(k,v);
    jsvObjectIteratorNext(&it);
  }
  jsvObjectIteratorFree(&it);
}

int jsvGetChildren(const JsVar *v) {
  
  int children = 0;
  JsVarRef childref = jsvGetFirstChild(v);
  while (childref) {
    JsVar *child = jsvLock(childref);
    children++;
    childref = jsvGetNextSibling(child);
    jsvUnLock(child);
  }
  return children;
}


JsVar *jsvGetFirstName(JsVar *v) {
  assert(jsvHasChildren(v));
  if (!jsvGetFirstChild(v)) return 0;
  return jsvLock(jsvGetFirstChild(v));
}

JsVarInt jsvGetArrayLength(const JsVar *arr) {
  if (!arr) return 0;
  assert(jsvIsArray(arr));
  return arr->varData.integer;
}

JsVarInt jsvSetArrayLength(JsVar *arr, JsVarInt length, bool truncate) {
  assert(jsvIsArray(arr));
  if (truncate && length < arr->varData.integer) {
    
  }
  arr->varData.integer = length;
  return length;
}

JsVarInt jsvGetLength(const JsVar *src) {
  if (jsvIsArray(src)) {
    return jsvGetArrayLength(src);
  } else if (jsvIsArrayBuffer(src)) {
    return (JsVarInt)jsvGetArrayBufferLength(src);
  } else if (jsvIsString(src)) {
    return (JsVarInt)jsvGetStringLength(src);
  } else if (jsvIsObject(src) || jsvIsFunction(src)) {
    return jsvGetChildren(src);
  } else {
    return 1;
  }
}


static size_t _jsvCountJsVarsUsedRecursive(JsVar *v, bool resetRecursionFlag) {
  if (!v) return 0;
  
  if (resetRecursionFlag) {
    if (!(v->flags & JSV_IS_RECURSING))
      return 0;
    v->flags &= ~JSV_IS_RECURSING;
  } else {
    if (v->flags & JSV_IS_RECURSING)
      return 0;
    v->flags |= JSV_IS_RECURSING;
  }

  size_t count = 1;
  if (jsvHasSingleChild(v) || jsvHasChildren(v)) {
    JsVarRef childref = jsvGetFirstChild(v);
    while (childref) {
      JsVar *child = jsvLock(childref);
      count += _jsvCountJsVarsUsedRecursive(child, resetRecursionFlag);
      if (jsvHasChildren(v)) childref = jsvGetNextSibling(child);
      else childref = 0;
      jsvUnLock(child);
    }
  } else if (jsvIsFlatString(v))
    count += jsvGetFlatStringBlocks(v);
  if (jsvHasCharacterData(v)) {
    JsVarRef childref = jsvGetLastChild(v);
    while (childref) {
      JsVar *child = jsvLock(childref);
      count++;
      childref = jsvGetLastChild(child);
      jsvUnLock(child);
    }
  }
  if (jsvIsName(v) && !jsvIsNameWithValue(v) && jsvGetFirstChild(v)) {
    JsVar *child = jsvLock(jsvGetFirstChild(v));
    count += _jsvCountJsVarsUsedRecursive(child, resetRecursionFlag);
    jsvUnLock(child);
  }
  return count;
}


size_t jsvCountJsVarsUsed(JsVar *v) {
  
  if ((execInfo.root) && (v != execInfo.root)) execInfo.root->flags |= JSV_IS_RECURSING;
  
  size_t c = _jsvCountJsVarsUsedRecursive(v, false);
  _jsvCountJsVarsUsedRecursive(v, true);
  
  if ((execInfo.root) && (v != execInfo.root)) execInfo.root->flags &= ~JSV_IS_RECURSING;
  return c;
}

JsVar *jsvGetArrayIndex(const JsVar *arr, JsVarInt index) {
  JsVarRef childref = jsvGetLastChild(arr);
  JsVarInt lastArrayIndex = 0;
  
  while (childref) {
    JsVar *child = jsvLock(childref);
    if (jsvIsInt(child)) {
      lastArrayIndex = child->varData.integer;
      
      if (lastArrayIndex == index) {
        return child;
      }
      jsvUnLock(child);
      break;
    }
    
    childref = jsvGetPrevSibling(child);
    jsvUnLock(child);
  }
  
  if (index > lastArrayIndex)
    return 0;
  
  if (index > lastArrayIndex/2) {
    
    while (childref) {
      JsVar *child = jsvLock(childref);

      assert(jsvIsInt(child));
      if (child->varData.integer == index) {
        return child;
      }
      childref = jsvGetPrevSibling(child);
      jsvUnLock(child);
    }
  } else {
    
    childref = jsvGetFirstChild(arr);
    while (childref) {
      JsVar *child = jsvLock(childref);

      assert(jsvIsInt(child));
      if (child->varData.integer == index) {
        return child;
      }
      childref = jsvGetNextSibling(child);
      jsvUnLock(child);
    }
  }
  return 0; 
}

JsVar *jsvGetArrayItem(const JsVar *arr, JsVarInt index) {
  return jsvSkipNameAndUnLock(jsvGetArrayIndex(arr,index));
}

JsVar *jsvGetLastArrayItem(const JsVar *arr) {
  JsVarRef childref = jsvGetLastChild(arr);
  if (!childref) return 0;
  return jsvSkipNameAndUnLock(jsvLock(childref));
}

void jsvSetArrayItem(JsVar *arr, JsVarInt index, JsVar *item) {
  JsVar *indexVar = jsvGetArrayIndex(arr, index);
  if (indexVar) {
    jsvSetValueOfName(indexVar, item);
  } else {
    indexVar = jsvMakeIntoVariableName(jsvNewFromInteger(index), item);
    if (indexVar) 
      jsvAddName(arr, indexVar);
  }
  jsvUnLock(indexVar);
}



void jsvGetArrayItems(JsVar *arr, unsigned int itemCount, JsVar **itemPtr) {
  JsvObjectIterator it;
  jsvObjectIteratorNew(&it, arr);
  unsigned int i = 0;
  while (jsvObjectIteratorHasValue(&it)) {
    if (i<itemCount)
      itemPtr[i++] = jsvObjectIteratorGetValue(&it);
    jsvObjectIteratorNext(&it);
  }
  jsvObjectIteratorFree(&it);
  while (i<itemCount)
    itemPtr[i++] = 0; 
}


JsVar *jsvGetIndexOfFull(JsVar *arr, JsVar *value, bool matchExact, bool matchIntegerIndices, int startIdx) {
  if (!jsvIsIterable(arr)) return 0;
  JsvIterator it;
  jsvIteratorNew(&it, arr, JSIF_DEFINED_ARRAY_ElEMENTS);
  while (jsvIteratorHasElement(&it)) {
    JsVar *childIndex = jsvIteratorGetKey(&it);
    if (!matchIntegerIndices || (jsvIsInt(childIndex) && jsvGetInteger(childIndex)>=startIdx)) {
      JsVar *childValue = jsvIteratorGetValue(&it);
      if (childValue==value || (!matchExact && jsvMathsOpTypeEqual(childValue, value))) {
        jsvUnLock(childValue);
        jsvIteratorFree(&it);
        return childIndex;
      }
      jsvUnLock(childValue);
    }
    jsvUnLock(childIndex);
    jsvIteratorNext(&it);
  }
  jsvIteratorFree(&it);
  return 0; 
}


JsVar *jsvGetIndexOf(JsVar *arr, JsVar *value, bool matchExact) {
  return jsvGetIndexOfFull(arr, value, matchExact, false, 0);
}



JsVarInt jsvArrayAddToEnd(JsVar *arr, JsVar *value, JsVarInt initialValue) {
  assert(jsvIsArray(arr));
  JsVarInt index = initialValue;
  if (jsvGetLastChild(arr)) {
    JsVar *last = jsvLock(jsvGetLastChild(arr));
    index = jsvGetInteger(last)+1;
    jsvUnLock(last);
  }

  JsVar *idx = jsvMakeIntoVariableName(jsvNewFromInteger(index), value);
  if (!idx) return 0; 
  jsvAddName(arr, idx);
  jsvUnLock(idx);
  return index+1;
}


JsVarInt jsvArrayPush(JsVar *arr, JsVar *value) {
  assert(jsvIsArray(arr));
  JsVarInt index = jsvGetArrayLength(arr);
  JsVar *idx = jsvMakeIntoVariableName(jsvNewFromInteger(index), value);
  if (!idx) return 0; 
  jsvAddName(arr, idx);
  jsvUnLock(idx);
  return jsvGetArrayLength(arr);
}


JsVarInt jsvArrayPushAndUnLock(JsVar *arr, JsVar *value) {
  JsVarInt l = jsvArrayPush(arr, value);
  jsvUnLock(value);
  return l;
}


void jsvArrayPush2Int(JsVar *arr, JsVarInt a, JsVarInt b) {
  jsvArrayPushAndUnLock(arr, jsvNewFromInteger(a));
  jsvArrayPushAndUnLock(arr, jsvNewFromInteger(b));
}


void jsvArrayPushAll(JsVar *target, JsVar *source, bool checkDuplicates) {
  assert(jsvIsArray(target));
  assert(jsvIsArray(source));
  JsvObjectIterator it;
  jsvObjectIteratorNew(&it, source);
  while (jsvObjectIteratorHasValue(&it)) {
    JsVar *v = jsvObjectIteratorGetValue(&it);
    bool add = true;
    if (checkDuplicates) {
      JsVar *idx = jsvGetIndexOf(target, v, false);
      if (idx) {
        add = false;
        jsvUnLock(idx);
      }
    }
    if (add) jsvArrayPush(target, v);
    jsvUnLock(v);
    jsvObjectIteratorNext(&it);
  }
  jsvObjectIteratorFree(&it);
}


JsVar *jsvArrayPop(JsVar *arr) {
  assert(jsvIsArray(arr));
  JsVar *child = 0;
  JsVarInt length = jsvGetArrayLength(arr);
  if (length > 0) {
    length--;

    if (jsvGetLastChild(arr)) {
      
      JsVarRef ref = jsvGetLastChild(arr);
      child = jsvLock(ref);
      while (child && !jsvIsInt(child)) {
        ref = jsvGetPrevSibling(child);
        jsvUnLock(child);
        if (ref) {
          child = jsvLock(ref);
        } else {
          child = 0;
        }
      }
      
      if (child) {
        if (jsvGetInteger(child) == length) {
          
          jsvRemoveChild(arr, child);
        } else {
          
          jsvUnLock(child);
          child = 0;
        }
      }
    }
    
    jsvSetArrayLength(arr, length, false);
  }

  return child;
}


JsVar *jsvArrayPopFirst(JsVar *arr) {
  assert(jsvIsArray(arr));
  if (jsvGetFirstChild(arr)) {
    JsVar *child = jsvLock(jsvGetFirstChild(arr));
    if (jsvGetFirstChild(arr) == jsvGetLastChild(arr))
      jsvSetLastChild(arr, 0); 
    jsvSetFirstChild(arr, jsvGetNextSibling(child)); 
    jsvUnRef(child); 
    if (jsvGetNextSibling(child)) {
      JsVar *v = jsvLock(jsvGetNextSibling(child));
      jsvSetPrevSibling(v, 0);
      jsvUnLock(v);
    }
    jsvSetNextSibling(child, 0);
    return child; 
  } else {
    
    return 0;
  }
}


void jsvArrayAddUnique(JsVar *arr, JsVar *v) {
  JsVar *idx = jsvGetIndexOf(arr, v, false); 
  if (!idx) {
    jsvArrayPush(arr, v); 
  } else {
    jsvUnLock(idx);
  }
}


JsVar *jsvArrayJoin(JsVar *arr, JsVar *filler, bool ignoreNull) {
  JsVar *str = jsvNewFromEmptyString();
  if (!str) return 0; 
  assert(!filler || jsvIsString(filler));

  JsvIterator it;
  jsvIteratorNew(&it, arr, JSIF_EVERY_ARRAY_ELEMENT);
  JsvStringIterator itdst;
  jsvStringIteratorNew(&itdst, str, 0);
  bool first = true;
  while (!jspIsInterrupted() && jsvIteratorHasElement(&it)) {
    JsVar *key = jsvIteratorGetKey(&it);
    if (jsvIsInt(key)) {
      
      if (filler && !first)
        jsvStringIteratorAppendString(&itdst, filler, 0, JSVAPPENDSTRINGVAR_MAXLENGTH);
      first = false;
      
      JsVar *value = jsvIteratorGetValue(&it);
      if (value && (!ignoreNull || !jsvIsNull(value))) {
        JsVar *valueStr = jsvAsString(value);
        if (valueStr) { 
          jsvStringIteratorAppendString(&itdst, valueStr, 0, JSVAPPENDSTRINGVAR_MAXLENGTH);
          jsvUnLock(valueStr);
        }
      }
      jsvUnLock(value);
    }
    jsvUnLock(key);
    jsvIteratorNext(&it);
  }
  jsvIteratorFree(&it);
  jsvStringIteratorFree(&itdst);
  return str;
}


void jsvArrayInsertBefore(JsVar *arr, JsVar *beforeIndex, JsVar *element) {
  if (beforeIndex) {
    JsVar *idxVar = jsvMakeIntoVariableName(jsvNewFromInteger(0), element);
    if (!idxVar) return; 

    JsVarRef idxRef = jsvGetRef(jsvRef(idxVar));
    JsVarRef prev = jsvGetPrevSibling(beforeIndex);
    if (prev) {
      JsVar *prevVar = jsvRef(jsvLock(prev));
      jsvSetInteger(idxVar, jsvGetInteger(prevVar)+1); 
      jsvSetNextSibling(prevVar, idxRef);
      jsvUnLock(prevVar);
      jsvSetPrevSibling(idxVar, prev);
    } else {
      jsvSetPrevSibling(idxVar, 0);
      jsvSetFirstChild(arr, idxRef);
    }
    jsvSetPrevSibling(beforeIndex, idxRef);
    jsvSetNextSibling(idxVar, jsvGetRef(jsvRef(beforeIndex)));
    jsvUnLock(idxVar);
  } else jsvArrayPush(arr, element);
}


JsVar *jsvMathsOpSkipNames(JsVar *a, JsVar *b, int op) {
  JsVar *pa = jsvSkipName(a);
  JsVar *pb = jsvSkipName(b);
  JsVar *oa = jsvGetValueOf(pa);
  JsVar *ob = jsvGetValueOf(pb);
  jsvUnLock2(pa, pb);
  JsVar *res = jsvMathsOp(oa,ob,op);
  jsvUnLock2(oa, ob);
  return res;
}


JsVar *jsvMathsOpError(int op, const char *datatype) {
  char opName[32];
  jslTokenAsString(op, opName, sizeof(opName));
  jsError("Operation %s not supported on the %s datatype", opName, datatype);
  return 0;
}

bool jsvMathsOpTypeEqual(JsVar *a, JsVar *b) {
  
  bool eql = (a==0) == (b==0);
  if (a && b) {
    
    
    eql = ((jsvIsInt(a)||jsvIsFloat(a)) && (jsvIsInt(b)||jsvIsFloat(b))) || (jsvIsString(a) && jsvIsString(b)) || ((a->flags & JSV_VARTYPEMASK) == (b->flags & JSV_VARTYPEMASK));

  }
  if (eql) {
    JsVar *contents = jsvMathsOp(a,b, LEX_EQUAL);
    if (!jsvGetBool(contents)) eql = false;
    jsvUnLock(contents);
  } else {
    
    assert(!(jsvIsString(a) && jsvIsString(b) && jsvIsBasicVarEqual(a,b)));
  }
  return eql;
}

JsVar *jsvMathsOp(JsVar *a, JsVar *b, int op) {
  
  if (op == LEX_TYPEEQUAL || op == LEX_NTYPEEQUAL) {
    bool eql = jsvMathsOpTypeEqual(a,b);
    if (op == LEX_TYPEEQUAL)
      return jsvNewFromBool(eql);
    else return jsvNewFromBool(!eql);
  }

  bool needsInt = op=='&' || op=='|' || op=='^' || op==LEX_LSHIFT || op==LEX_RSHIFT || op==LEX_RSHIFTUNSIGNED;
  bool needsNumeric = needsInt || op=='*' || op=='/' || op=='%' || op=='-';
  bool isCompare = op==LEX_EQUAL || op==LEX_NEQUAL || op=='<' || op==LEX_LEQUAL || op=='>'|| op==LEX_GEQUAL;
  if (isCompare) {
    if (jsvIsNumeric(a) && jsvIsString(b)) {
      needsNumeric = true;
      needsInt = jsvIsIntegerish(a) && jsvIsStringNumericInt(b, false);
    } else if (jsvIsNumeric(b) && jsvIsString(a)) {
      needsNumeric = true;
      needsInt = jsvIsIntegerish(b) && jsvIsStringNumericInt(a, false);
    }
  }

  
  if (jsvIsUndefined(a) && jsvIsUndefined(b)) {
    if (op == LEX_EQUAL)
      return jsvNewFromBool(true);
    else if (op == LEX_NEQUAL)
      return jsvNewFromBool(false);
    else return 0;
  } else if (needsNumeric || ((jsvIsNumeric(a) || jsvIsUndefined(a) || jsvIsNull(a)) && (jsvIsNumeric(b) || jsvIsUndefined(b) || jsvIsNull(b)))) {

    if (needsInt || (jsvIsIntegerish(a) && jsvIsIntegerish(b))) {
      
      
      JsVarInt da = jsvGetInteger(a);
      JsVarInt db = jsvGetInteger(b);
      switch (op) {
      case '+': return jsvNewFromLongInteger((long long)da + (long long)db);
      case '-': return jsvNewFromLongInteger((long long)da - (long long)db);
      case '*': return jsvNewFromLongInteger((long long)da * (long long)db);
      case '/': return jsvNewFromFloat((JsVarFloat)da/(JsVarFloat)db);
      case '&': return jsvNewFromInteger(da&db);
      case '|': return jsvNewFromInteger(da|db);
      case '^': return jsvNewFromInteger(da^db);
      case '%': if (db<0) db=-db; 
                return db ? jsvNewFromInteger(da%db) : jsvNewFromFloat(NAN);
      case LEX_LSHIFT: return jsvNewFromInteger(da << db);
      case LEX_RSHIFT: return jsvNewFromInteger(da >> db);
      case LEX_RSHIFTUNSIGNED: return jsvNewFromLongInteger(((JsVarIntUnsigned)da) >> db);
      case LEX_EQUAL:     return jsvNewFromBool(da==db && jsvIsNull(a)==jsvIsNull(b));
      case LEX_NEQUAL:    return jsvNewFromBool(da!=db || jsvIsNull(a)!=jsvIsNull(b));
      case '<':           return jsvNewFromBool(da<db);
      case LEX_LEQUAL:    return jsvNewFromBool(da<=db);
      case '>':           return jsvNewFromBool(da>db);
      case LEX_GEQUAL:    return jsvNewFromBool(da>=db);
      default: return jsvMathsOpError(op, "Integer");
      }
    } else {
      
      JsVarFloat da = jsvGetFloat(a);
      JsVarFloat db = jsvGetFloat(b);
      switch (op) {
      case '+': return jsvNewFromFloat(da+db);
      case '-': return jsvNewFromFloat(da-db);
      case '*': return jsvNewFromFloat(da*db);
      case '/': return jsvNewFromFloat(da/db);
      case '%': return jsvNewFromFloat(jswrap_math_mod(da, db));
      case LEX_EQUAL:
      case LEX_NEQUAL:  { bool equal = da==db && jsvIsNull(a)==jsvIsNull(b);
      if ((jsvIsNull(a) && jsvIsUndefined(b)) || (jsvIsNull(b) && jsvIsUndefined(a))) equal = true;
      return jsvNewFromBool((op==LEX_EQUAL) ? equal : ((bool)!equal));
      }
      case '<':           return jsvNewFromBool(da<db);
      case LEX_LEQUAL:    return jsvNewFromBool(da<=db);
      case '>':           return jsvNewFromBool(da>db);
      case LEX_GEQUAL:    return jsvNewFromBool(da>=db);
      default: return jsvMathsOpError(op, "Double");
      }
    }
  } else if ((jsvIsArray(a) || jsvIsObject(a) || jsvIsFunction(a) || jsvIsArray(b) || jsvIsObject(b) || jsvIsFunction(b)) && jsvIsArray(a)==jsvIsArray(b) && (op == LEX_EQUAL || op==LEX_NEQUAL)) {


    bool equal = a==b;

    if (jsvIsNativeFunction(a) || jsvIsNativeFunction(b)) {
      
      equal = a && b &&  a->varData.native.ptr == b->varData.native.ptr && a->varData.native.argTypes == b->varData.native.argTypes && jsvGetFirstChild(a) == jsvGetFirstChild(b);


    }

    
    switch (op) {
    case LEX_EQUAL:  return jsvNewFromBool(equal);
    case LEX_NEQUAL: return jsvNewFromBool(!equal);
    default: return jsvMathsOpError(op, jsvIsArray(a)?"Array":"Object");
    }
  } else {
    JsVar *da = jsvAsString(a);
    JsVar *db = jsvAsString(b);
    if (!da || !db) { 
      jsvUnLock2(da, db);
      return 0;
    }
    if (op=='+') {
      JsVar *v;
      
      if (jsvIsBasicString(da) && jsvGetLocks(da)==1 && jsvGetRefs(da)==0)
        v = jsvLockAgain(da);
      else v = jsvCopy(da, false);
      if (v) 
        jsvAppendStringVarComplete(v, db);
      jsvUnLock2(da, db);
      return v;
    }

    int cmp = jsvCompareString(da,db,0,0,false);
    jsvUnLock2(da, db);
    
    switch (op) {
    case LEX_EQUAL:     return jsvNewFromBool(cmp==0);
    case LEX_NEQUAL:    return jsvNewFromBool(cmp!=0);
    case '<':           return jsvNewFromBool(cmp<0);
    case LEX_LEQUAL:    return jsvNewFromBool(cmp<=0);
    case '>':           return jsvNewFromBool(cmp>0);
    case LEX_GEQUAL:    return jsvNewFromBool(cmp>=0);
    default: return jsvMathsOpError(op, "String");
    }
  }
}

JsVar *jsvNegateAndUnLock(JsVar *v) {
  JsVar *zero = jsvNewFromInteger(0);
  JsVar *res = jsvMathsOpSkipNames(zero, v, '-');
  jsvUnLock2(zero, v);
  return res;
}


static JsVar *jsvGetPathTo_int(JsVar *root, JsVar *element, int maxDepth, JsVar *ignoreParent, int *depth) {
  if (maxDepth<=0) return 0;

  int bestDepth = maxDepth+1;
  JsVar *found = 0;

  JsvIterator it;
  jsvIteratorNew(&it, root, JSIF_DEFINED_ARRAY_ElEMENTS);
  while (jsvIteratorHasElement(&it)) {
    JsVar *el = jsvIteratorGetValue(&it);
    if (el == element && root != ignoreParent) {
      
      JsVar *name = jsvAsStringAndUnLock(jsvIteratorGetKey(&it));
      jsvIteratorFree(&it);
      return name;
    } else if (jsvIsObject(el) || jsvIsArray(el) || jsvIsFunction(el)) {
      
      int d;
      JsVar *n = jsvGetPathTo_int(el, element, maxDepth-1, ignoreParent, &d);
      if (n && d<bestDepth) {
        bestDepth = d;
        
        JsVar *keyName = jsvIteratorGetKey(&it);
        jsvUnLock(found);
        found = jsvVarPrintf(jsvIsObject(el) ? "%v.%v" : "%v[%q]",keyName,n);
        jsvUnLock(keyName);
      }
      jsvUnLock(n);
    }
    jsvIteratorNext(&it);
  }
  jsvIteratorFree(&it);
  *depth = bestDepth;
  return found;
}


JsVar *jsvGetPathTo(JsVar *root, JsVar *element, int maxDepth, JsVar *ignoreParent) {
  int depth = 0;
  return jsvGetPathTo_int(root, element, maxDepth, ignoreParent, &depth);
}

void jsvTraceLockInfo(JsVar *v) {
  jsiConsolePrintf("#%d[r%d,l%d] ",jsvGetRef(v),jsvGetRefs(v),jsvGetLocks(v));
}


int _jsvTraceGetLowestLevel(JsVar *var, JsVar *searchVar) {
  if (var == searchVar) return 0;
  int found = -1;

  
  if (var->flags & JSV_IS_RECURSING)
    return -1;
  var->flags |= JSV_IS_RECURSING;

  if (jsvHasSingleChild(var) && jsvGetFirstChild(var)) {
    JsVar *child = jsvLock(jsvGetFirstChild(var));
    int f = _jsvTraceGetLowestLevel(child, searchVar);
    jsvUnLock(child);
    if (f>=0 && (found<0 || f<found)) found=f+1;
  }
  if (jsvHasChildren(var)) {
    JsVarRef childRef = jsvGetFirstChild(var);
    while (childRef) {
      JsVar *child = jsvLock(childRef);
      int f = _jsvTraceGetLowestLevel(child, searchVar);
      if (f>=0 && (found<0 || f<found)) found=f+1;
      childRef = jsvGetNextSibling(child);
      jsvUnLock(child);
    }
  }

  var->flags &= ~JSV_IS_RECURSING;

  return found; 
}

void _jsvTrace(JsVar *var, int indent, JsVar *baseVar, int level) {

  jsiConsolePrint("Trace unimplemented in this version.\n");

  int i;
  for (i=0;i<indent;i++) jsiConsolePrint(" ");


  if (!var) {
    jsiConsolePrint("undefined");
    return;
  }
  if (level>0 && var==execInfo.root) {
    jsiConsolePrint("ROOT");
    return;
  }

  jsvTraceLockInfo(var);

  int lowestLevel = _jsvTraceGetLowestLevel(baseVar, var);
  if (level>16 || (lowestLevel>=0 && lowestLevel < level)) {
    
    
    
    jsiConsolePrint("...\n");
    return;
  }

  if (jsvIsNewChild(var)) {
    jsiConsolePrint("NewChild PARENT:");
    JsVar *parent = jsvGetAddressOf(jsvGetNextSibling(var));
    _jsvTrace(parent, indent+2, baseVar, level+1);
    jsiConsolePrint("CHILD: ");
  } else if (jsvIsName(var)) jsiConsolePrint("Name ");

  char endBracket = ' ';
  if (jsvIsObject(var)) { jsiConsolePrint("Object { "); endBracket = '}'; }
  else if (jsvIsGetterOrSetter(var)) { jsiConsolePrint("Getter/Setter { "); endBracket = '}'; }
  else if (jsvIsArray(var)) { jsiConsolePrintf("Array(%d) [ ", var->varData.integer); endBracket = ']'; }
  else if (jsvIsNativeFunction(var)) { jsiConsolePrintf("NativeFunction 0x%x (%d) { ", var->varData.native.ptr, var->varData.native.argTypes); endBracket = '}'; }
  else if (jsvIsFunction(var)) {
    jsiConsolePrint("Function { ");
    if (jsvIsFunctionReturn(var)) jsiConsolePrint("return ");
    endBracket = '}';
  } else if (jsvIsPin(var)) jsiConsolePrintf("Pin %d", jsvGetInteger(var));
  else if (jsvIsInt(var)) jsiConsolePrintf("Integer %d", jsvGetInteger(var));
  else if (jsvIsBoolean(var)) jsiConsolePrintf("Bool %s", jsvGetBool(var)?"true":"false");
  else if (jsvIsFloat(var)) jsiConsolePrintf("Double %f", jsvGetFloat(var));
  else if (jsvIsFunctionParameter(var)) jsiConsolePrintf("Param %q ", var);
  else if (jsvIsArrayBufferName(var)) jsiConsolePrintf("ArrayBufferName[%d] ", jsvGetInteger(var));
  else if (jsvIsArrayBuffer(var)) jsiConsolePrintf("%s (offs %d, len %d)", jswGetBasicObjectName(var)?jswGetBasicObjectName(var):"unknown ArrayBuffer", var->varData.arraybuffer.byteOffset, var->varData.arraybuffer.length); 
  else if (jsvIsString(var)) {
    size_t blocks = 1;
    if (jsvGetLastChild(var)) {
      JsVar *v = jsvGetAddressOf(jsvGetLastChild(var));
      blocks += jsvCountJsVarsUsed(v);
    }
    if (jsvIsFlatString(var)) {
      blocks += jsvGetFlatStringBlocks(var);
    }
    const char *name = "";
    if (jsvIsFlatString(var)) name="Flat";
    if (jsvIsNativeString(var)) name="Native";
    if (jsvIsFlashString(var)) name="Flash";
    jsiConsolePrintf("%sString [%d blocks] %q", name, blocks, var);
  } else {
    jsiConsolePrintf("Unknown %d", var->flags & (JsVarFlags)~(JSV_LOCK_MASK));
  }

  
  if (jsvIsNameInt(var)) {
    jsiConsolePrintf("= int %d\n", (int)jsvGetFirstChildSigned(var));
    return;
  } else if (jsvIsNameIntBool(var)) {
    jsiConsolePrintf("= bool %s\n", jsvGetFirstChild(var)?"true":"false");
    return;
  }

  if (jsvHasSingleChild(var)) {
    JsVar *child = jsvGetFirstChild(var) ? jsvGetAddressOf(jsvGetFirstChild(var)) : 0;
    _jsvTrace(child, indent+2, baseVar, level+1);
  } else if (jsvHasChildren(var)) {
    JsvIterator it;
    jsvIteratorNew(&it, var, JSIF_DEFINED_ARRAY_ElEMENTS);
    bool first = true;
    while (jsvIteratorHasElement(&it) && !jspIsInterrupted()) {
      if (first) jsiConsolePrintf("\n");
      first = false;
      JsVar *child = jsvIteratorGetKey(&it);
      _jsvTrace(child, indent+2, baseVar, level+1);
      jsvUnLock(child);
      jsiConsolePrintf("\n");
      jsvIteratorNext(&it);
    }
    jsvIteratorFree(&it);
    if (!first)
      for (i=0;i<indent;i++) jsiConsolePrint(" ");
  }
  jsiConsolePrintf("%c", endBracket);

}


void jsvTrace(JsVar *var, int indent) {
  
  MemBusyType t = isMemoryBusy;
  isMemoryBusy = 0;
  _jsvTrace(var,indent,var,0);
  isMemoryBusy = t;
  jsiConsolePrintf("\n");
}



static bool jsvGarbageCollectMarkUsed(JsVar *var) {
  var->flags &= (JsVarFlags)~JSV_GARBAGE_COLLECT;
  JsVarRef child;
  JsVar *childVar;

  if (jsvHasCharacterData(var)) {
    
    child = jsvGetLastChild(var);
    while (child) {
      childVar = jsvGetAddressOf(child);
      childVar->flags &= (JsVarFlags)~JSV_GARBAGE_COLLECT;
      child = jsvGetLastChild(childVar);
    }
  }
  
  if (jsvHasSingleChild(var)) {
    if (jsvGetFirstChild(var)) {
      childVar = jsvGetAddressOf(jsvGetFirstChild(var));
      if (childVar->flags & JSV_GARBAGE_COLLECT)
        if (!jsvGarbageCollectMarkUsed(childVar)) return false;
    }
  } else if (jsvHasChildren(var)) {
    if (jsuGetFreeStack() < 256) return false;

    child = jsvGetFirstChild(var);
    while (child) {
      childVar = jsvGetAddressOf(child);
      if (childVar->flags & JSV_GARBAGE_COLLECT)
        if (!jsvGarbageCollectMarkUsed(childVar)) return false;
      child = jsvGetNextSibling(childVar);
    }
  }

  return true;
}


int jsvGarbageCollect() {
  if (isMemoryBusy) return 0;
  isMemoryBusy = MEMBUSY_GC;
  JsVarRef i;
  
  for (i=1;i<=jsVarsSize;i++)  {
    JsVar *var = jsvGetAddressOf(i);
    if ((var->flags&JSV_VARTYPEMASK) != JSV_UNUSED) { 
      var->flags |= (JsVarFlags)JSV_GARBAGE_COLLECT;
      
      if (jsvIsFlatString(var))
        i = (JsVarRef)(i+jsvGetFlatStringBlocks(var));
    }
  }
  
  for (i=1;i<=jsVarsSize;i++)  {
    JsVar *var = jsvGetAddressOf(i);
    if ((var->flags & JSV_GARBAGE_COLLECT) &&  jsvGetLocks(var)>0) {
      if (!jsvGarbageCollectMarkUsed(var)) {
        
        
        isMemoryBusy = MEM_NOT_BUSY;
        return 0;
      }
    }
    
    if (jsvIsFlatString(var))
      i = (JsVarRef)(i+jsvGetFlatStringBlocks(var));
  }
  
  unsigned int freedCount = 0;
  jsVarFirstEmpty = 0;
  JsVar *lastEmpty = 0;
  for (i=1;i<=jsVarsSize;i++)  {
    JsVar *var = jsvGetAddressOf(i);
    if (var->flags & JSV_GARBAGE_COLLECT) {
      if (jsvIsFlatString(var)) {
        
        unsigned int count = (unsigned int)jsvGetFlatStringBlocks(var);
        freedCount+=count;
        
        var->flags = JSV_UNUSED;
        
        if (lastEmpty) jsvSetNextSibling(lastEmpty, i);
        else jsVarFirstEmpty = i;
        lastEmpty = var;
        
        while (count-- > 0) {
          i++;
          var = jsvGetAddressOf((JsVarRef)(i));
          var->flags = JSV_UNUSED;
          
          if (lastEmpty) jsvSetNextSibling(lastEmpty, i);
          else jsVarFirstEmpty = i;
          lastEmpty = var;
        }
      } else {
        
        if (jsvHasSingleChild(var)) {
          
          JsVarRef ch = jsvGetFirstChild(var);
          if (ch) {
            JsVar *child = jsvGetAddressOf(ch); 
            if (child->flags!=JSV_UNUSED &&  !(child->flags&JSV_GARBAGE_COLLECT))
              jsvUnRef(child);
          }
        }
        
        assert(!jsvHasChildren(var) || !jsvGetFirstChild(var) || jsvGetLocks(jsvGetAddressOf(jsvGetFirstChild(var))) || jsvGetAddressOf(jsvGetFirstChild(var))->flags==JSV_UNUSED || (jsvGetAddressOf(jsvGetFirstChild(var))->flags&JSV_GARBAGE_COLLECT));


        assert(!jsvHasChildren(var) || !jsvGetLastChild(var) || jsvGetLocks(jsvGetAddressOf(jsvGetLastChild(var))) || jsvGetAddressOf(jsvGetLastChild(var))->flags==JSV_UNUSED || (jsvGetAddressOf(jsvGetLastChild(var))->flags&JSV_GARBAGE_COLLECT));


        assert(!jsvIsName(var) || !jsvGetPrevSibling(var) || jsvGetLocks(jsvGetAddressOf(jsvGetPrevSibling(var))) || jsvGetAddressOf(jsvGetPrevSibling(var))->flags==JSV_UNUSED || (jsvGetAddressOf(jsvGetPrevSibling(var))->flags&JSV_GARBAGE_COLLECT));


        assert(!jsvIsName(var) || !jsvGetNextSibling(var) || jsvGetLocks(jsvGetAddressOf(jsvGetNextSibling(var))) || jsvGetAddressOf(jsvGetNextSibling(var))->flags==JSV_UNUSED || (jsvGetAddressOf(jsvGetNextSibling(var))->flags&JSV_GARBAGE_COLLECT));


        
        var->flags = JSV_UNUSED;
        
        if (lastEmpty) jsvSetNextSibling(lastEmpty, i);
        else jsVarFirstEmpty = i;
        lastEmpty = var;
        freedCount++;
      }
    } else if (jsvIsFlatString(var)) {
      
      i = (JsVarRef)(i+jsvGetFlatStringBlocks(var));
    } else if (var->flags == JSV_UNUSED) {
      
      if (lastEmpty) jsvSetNextSibling(lastEmpty, i);
      else jsVarFirstEmpty = i;
      lastEmpty = var;
    }
  }
  if (lastEmpty) jsvSetNextSibling(lastEmpty, 0);
  isMemoryBusy = MEM_NOT_BUSY;
  return (int)freedCount;
}

void jsvDefragment() {
  
  
  jsvGarbageCollect();
  
  jshInterruptOff();
  const int DEFRAGVARS = 256; 
  JsVarRef defragVars[DEFRAGVARS];
  memset(defragVars, 0, sizeof(defragVars));
  int defragVarIdx = 0;
  for (int i=0;i<jsvGetMemoryTotal();i++) {
    JsVarRef vr = i+1;
    JsVar *v = _jsvGetAddressOf(vr);
    if ((v->flags&JSV_VARTYPEMASK)!=JSV_UNUSED) {
      if (jsvIsFlatString(v)) {
        i += jsvGetFlatStringBlocks(v); 
      } else if (jsvGetLocks(v)==0) {
        defragVars[defragVarIdx] = vr;
        defragVarIdx = (defragVarIdx+1) & (DEFRAGVARS-1);
      }
    }
  }
  
  defragVarIdx--;
  if (defragVarIdx<0) defragVarIdx+=DEFRAGVARS;
  while (defragVars[defragVarIdx]) {
    JsVarRef defragFromRef = defragVars[defragVarIdx];
    JsVarRef defragToRef = jsVarFirstEmpty;
    if (!defragToRef || defragFromRef<defragToRef) {
      
      break;
    }
    
    JsVar *defragFrom = _jsvGetAddressOf(defragFromRef);
    JsVar *defragTo = _jsvGetAddressOf(defragToRef);
    jsVarFirstEmpty = jsvGetNextSibling(defragTo); 
    
    *defragTo = *defragFrom;
    defragFrom->flags = JSV_UNUSED;
    
    for (int i=0;i<jsvGetMemoryTotal();i++) {
      JsVarRef vr = i+1;
      JsVar *v = _jsvGetAddressOf(vr);
      if ((v->flags&JSV_VARTYPEMASK)!=JSV_UNUSED) {
        if (jsvIsFlatString(v)) {
          i += jsvGetFlatStringBlocks(v); 
        } else {
          if (jsvHasSingleChild(v))
            if (jsvGetFirstChild(v)==defragFromRef)
              jsvSetFirstChild(v,defragToRef);
          if (jsvHasStringExt(v))
            if (jsvGetLastChild(v)==defragFromRef)
              jsvSetLastChild(v,defragToRef);
          if (jsvHasChildren(v)) {
            if (jsvGetFirstChild(v)==defragFromRef)
              jsvSetFirstChild(v,defragToRef);
            if (jsvGetLastChild(v)==defragFromRef)
              jsvSetLastChild(v,defragToRef);
          }
          if (jsvIsName(v)) {
            if (jsvGetNextSibling(v)==defragFromRef)
              jsvSetNextSibling(v,defragToRef);
            if (jsvGetPrevSibling(v)==defragFromRef)
              jsvSetPrevSibling(v,defragToRef);
          }
        }
      }
    }
    
    defragVars[defragVarIdx] = 0;
    defragVarIdx--;
    if (defragVarIdx<0) defragVarIdx+=DEFRAGVARS;
  }
  
  jsvCreateEmptyVarList();
  jshInterruptOn();
}


void jsvDumpLockedVars() {
  jsvGarbageCollect();
  if (isMemoryBusy) return;
  isMemoryBusy = MEMBUSY_SYSTEM;
  JsVarRef i;
  
  for (i=1;i<=jsVarsSize;i++)  {
    JsVar *var = jsvGetAddressOf(i);
    if ((var->flags&JSV_VARTYPEMASK) != JSV_UNUSED) { 
      var->flags |= (JsVarFlags)JSV_GARBAGE_COLLECT;
      
      if (jsvIsFlatString(var))
        i = (JsVarRef)(i+jsvGetFlatStringBlocks(var));
    }
  }
  
  jsvGarbageCollectMarkUsed(execInfo.root);
  
  for (i=1;i<=jsVarsSize;i++)  {
    JsVar *var = jsvGetAddressOf(i);
    if ((var->flags&JSV_VARTYPEMASK) != JSV_UNUSED) {
      if (var->flags & JSV_GARBAGE_COLLECT) {
        jsvGarbageCollectMarkUsed(var);
        jsvTrace(var, 0);
      }
    }
  }
  isMemoryBusy = MEM_NOT_BUSY;
}


void jsvDumpFreeList() {
  JsVarRef ref = jsVarFirstEmpty;
  int n = 0;
  while (ref) {
    jsiConsolePrintf("%5d ", (int)ref);
    if (++n >= 16) {
      n = 0;
      jsiConsolePrintf("\n");
    }
    JsVar *v = jsvGetAddressOf(ref);
    ref = jsvGetNextSibling(v);
  }
  jsiConsolePrintf("\n");
}



JsVar *jsvStringTrimRight(JsVar *srcString) {
  JsvStringIterator src, dst;
  JsVar *dstString = jsvNewFromEmptyString();
  jsvStringIteratorNew(&src, srcString, 0);
  jsvStringIteratorNew(&dst, dstString, 0);
  int spaces = 0;
  while (jsvStringIteratorHasChar(&src)) {
    char ch = jsvStringIteratorGetCharAndNext(&src);

    if (ch==' ') spaces++;
    else if (ch=='\n') {
      spaces = 0;
      jsvStringIteratorAppend(&dst, ch);
    } else {
      for (;spaces>0;spaces--)
        jsvStringIteratorAppend(&dst, ' ');
      jsvStringIteratorAppend(&dst, ch);
    }
  }
  jsvStringIteratorFree(&src);
  jsvStringIteratorFree(&dst);
  return dstString;
}


bool jsvIsInternalFunctionKey(JsVar *v) {
  return (jsvIsString(v) && ( v->varData.str[0]==JS_HIDDEN_CHAR)
  ) || jsvIsFunctionParameter(v);
}


bool jsvIsInternalObjectKey(JsVar *v) {
  return (jsvIsString(v) && ( v->varData.str[0]==JS_HIDDEN_CHAR || jsvIsStringEqual(v, JSPARSE_INHERITS_VAR) || jsvIsStringEqual(v, JSPARSE_CONSTRUCTOR_VAR)


  ));
}


JsvIsInternalChecker jsvGetInternalFunctionCheckerFor(JsVar *v) {
  if (jsvIsFunction(v)) return jsvIsInternalFunctionKey;
  if (jsvIsObject(v)) return jsvIsInternalObjectKey;
  return 0;
}


bool jsvReadConfigObject(JsVar *object, jsvConfigObject *configs, int nConfigs) {
  if (jsvIsUndefined(object)) return true;
  if (!jsvIsObject(object)) {
    jsExceptionHere(JSET_ERROR, "Expecting an Object, or undefined");
    return false;
  }
  
  JsvObjectIterator it;
  jsvObjectIteratorNew(&it, object);
  bool ok = true;
  while (ok && jsvObjectIteratorHasValue(&it)) {
    JsVar *key = jsvObjectIteratorGetKey(&it);
    bool found = false;
    for (int i=0;i<nConfigs;i++) {
      if (jsvIsStringEqual(key, configs[i].name)) {
        found = true;
        if (configs[i].ptr) {
          JsVar *val = jsvObjectIteratorGetValue(&it);
          switch (configs[i].type) {
          case 0: break;
          case JSV_OBJECT:
          case JSV_STRING_0:
          case JSV_ARRAY:
          case JSV_FUNCTION:
            *((JsVar**)configs[i].ptr) = jsvLockAgain(val); break;
          case JSV_PIN: *((Pin*)configs[i].ptr) = jshGetPinFromVar(val); break;
          case JSV_BOOLEAN: *((bool*)configs[i].ptr) = jsvGetBool(val); break;
          case JSV_INTEGER: *((JsVarInt*)configs[i].ptr) = jsvGetInteger(val); break;
          case JSV_FLOAT: *((JsVarFloat*)configs[i].ptr) = jsvGetFloat(val); break;
          default: assert(0); break;
          }
          jsvUnLock(val);
        }
      }
    }
    if (!found) {
      jsExceptionHere(JSET_ERROR, "Unknown option %q", key);
      ok = false;
    }
    jsvUnLock(key);

    jsvObjectIteratorNext(&it);
  }
  jsvObjectIteratorFree(&it);
  return ok;
}


JsVar *jsvCreateConfigObject(jsvConfigObject *configs, int nConfigs) {
  JsVar *o = jsvNewObject();
  if (!o) return 0;
  for (int i=0;i<nConfigs;i++) {
     if (configs[i].ptr) {
      JsVar *v = 0;
      switch (configs[i].type) {
      case 0: break;
      case JSV_OBJECT:
      case JSV_STRING_0:
      case JSV_ARRAY:
      case JSV_FUNCTION:
        v = jsvLockAgain(*((JsVar**)configs[i].ptr)); break;
      case JSV_PIN:
        v = jsvNewFromPin(*((Pin*)configs[i].ptr)); break;
      case JSV_BOOLEAN:
        v = jsvNewFromBool(*((bool*)configs[i].ptr)); break;
      case JSV_INTEGER:
        v = jsvNewFromInteger(*((JsVarInt*)configs[i].ptr)); break;
      case JSV_FLOAT:
        v = jsvNewFromFloat(*((JsVarFloat*)configs[i].ptr)); break;
      }
      jsvObjectSetChildAndUnLock(o, configs[i].name, v);
    }
  }
  return o;
}


bool jsvIsInstanceOf(JsVar *var, const char *constructorName) {
  bool isInst = false;
  if (!jsvHasChildren(var)) return false;
  JsVar *proto = jsvObjectGetChild(var, JSPARSE_INHERITS_VAR, 0);
  if (jsvIsObject(proto)) {
    JsVar *constr = jsvObjectGetChild(proto, JSPARSE_CONSTRUCTOR_VAR, 0);
    if (constr)
      isInst = jspIsConstructor(constr, constructorName);
    jsvUnLock(constr);
  }
  jsvUnLock(proto);
  return isInst;
}

JsVar *jsvNewTypedArray(JsVarDataArrayBufferViewType type, JsVarInt length) {
  JsVar *lenVar = jsvNewFromInteger(length);
  if (!lenVar) return 0;
  JsVar *array = jswrap_typedarray_constructor(type, lenVar,0,0);
  jsvUnLock(lenVar);
  return array;
}


JsVar *jsvNewDataViewWithData(JsVarInt length, unsigned char *data) {
  JsVar *buf = jswrap_arraybuffer_constructor(length);
  if (!buf) return 0;
  JsVar *view = jswrap_dataview_constructor(buf, 0, 0);
  if (!view) {
    jsvUnLock(buf);
    return 0;
  }
  if (data) {
    JsVar *arrayBufferData = jsvGetArrayBufferBackingString(buf, NULL);
    if (arrayBufferData)
      jsvSetString(arrayBufferData, (char *)data, (size_t)length);
    jsvUnLock(arrayBufferData);
  }
  jsvUnLock(buf);
  return view;
}


JsVar *jsvNewArrayBufferWithPtr(unsigned int length, char **ptr) {
  assert(ptr);
  *ptr=0;
  JsVar *backingString = jsvNewFlatStringOfLength(length);
  if (!backingString) return 0;
  JsVar *arr = jsvNewArrayBufferFromString(backingString, length);
  if (!arr) {
    jsvUnLock(backingString);
    return 0;
  }
  *ptr = jsvGetFlatStringPointer(backingString);
  jsvUnLock(backingString);
  return arr;
}

JsVar *jsvNewArrayBufferWithData(JsVarInt length, unsigned char *data) {
  assert(data);
  assert(length>0);
  JsVar *dst = 0;
  JsVar *arr = jsvNewArrayBufferWithPtr((unsigned int)length, (char**)&dst);
  if (!dst) {
    jsvUnLock(arr);
    return 0;
  }
  memcpy(dst, data, (size_t)length);
  return arr;
}

void *jsvMalloc(size_t size) {
  assert(size>0);
  
  JsVar *flatStr = jsvNewFlatStringOfLength((unsigned int)size);
  if (!flatStr) {
    jsErrorFlags |= JSERR_LOW_MEMORY;
    
    while (jsiFreeMoreMemory());
    
    jsvGarbageCollect();
    
    flatStr = jsvNewFlatStringOfLength((unsigned int)size);
  }
  
  void *p = (void*)jsvGetFlatStringPointer(flatStr);
  if (p) {
    
    memset(p,0,size);
  }
  return p;
}

void jsvFree(void *ptr) {
  JsVar *flatStr = jsvGetFlatStringFromPointer((char *)ptr);
  

  jsvUnLock(flatStr);
}
