













JsExecInfo execInfo;


JsVar *jspeAssignmentExpression();
JsVar *jspeExpression();
JsVar *jspeUnaryExpression();
void jspeBlock();
void jspeBlockNoBrackets();
JsVar *jspeStatement();
JsVar *jspeFactor();
void jspEnsureIsPrototype(JsVar *instanceOf, JsVar *prototypeName);

JsVar *jspeArrowFunction(JsVar *funcVar, JsVar *a);












ALWAYS_INLINE void jspDebuggerLoopIfCtrlC() {

  if (execInfo.execute & EXEC_CTRL_C_WAIT && JSP_SHOULD_EXECUTE)
    jsiDebuggerLoop();

}


bool jspIsInterrupted() {
  return (execInfo.execute & EXEC_INTERRUPTED)!=0;
}


void jspSetInterrupted(bool interrupt) {
  if (interrupt)
    execInfo.execute = execInfo.execute | EXEC_INTERRUPTED;
  else execInfo.execute = execInfo.execute & (JsExecFlags)~EXEC_INTERRUPTED;
}


void jspSetError(bool lineReported) {
  execInfo.execute = (execInfo.execute & (JsExecFlags)~EXEC_YES) | EXEC_ERROR;
  if (lineReported)
    execInfo.execute |= EXEC_ERROR_LINE_REPORTED;
}

bool jspHasError() {
  return JSP_HAS_ERROR;
}
void jspeiClearScopes() {
  jsvUnLock(execInfo.scopesVar);
  execInfo.scopesVar = 0;
}

bool jspeiAddScope(JsVar *scope) {
  if (!execInfo.scopesVar)
    execInfo.scopesVar = jsvNewEmptyArray();
  if (!execInfo.scopesVar) return false;
  jsvArrayPush(execInfo.scopesVar, scope);
  return true;
}

void jspeiRemoveScope() {
  if (!execInfo.scopesVar || !jsvGetArrayLength(execInfo.scopesVar)) {
    jsExceptionHere(JSET_INTERNALERROR, "Too many scopes removed");
    jspSetError(false);
    return;
  }
  jsvUnLock(jsvArrayPop(execInfo.scopesVar));
  if (!jsvGetFirstChild(execInfo.scopesVar)) {
    jsvUnLock(execInfo.scopesVar);
    execInfo.scopesVar = 0;
  }
}

JsVar *jspeiFindInScopes(const char *name) {
  if (execInfo.scopesVar) {
    JsVar *it = jsvLockSafe(jsvGetLastChild(execInfo.scopesVar));
    while (it) {
      JsVar *scope = jsvSkipName(it);
      JsVarRef next = jsvGetPrevSibling(it);
      JsVar *ref = jsvFindChildFromString(scope, name, false);
      jsvUnLock2(it, scope);
      if (ref) return ref;
      it = jsvLockSafe(next);
    }
  }
  return jsvFindChildFromString(execInfo.root, name, false);
}

JsVar *jspeiGetTopScope() {
  if (execInfo.scopesVar) {
    JsVar *scope = jsvGetLastArrayItem(execInfo.scopesVar);
    if (scope) return scope;
  }
  return jsvLockAgain(execInfo.root);
}
JsVar *jspeiFindOnTop(const char *name, bool createIfNotFound) {
  JsVar *scope = jspeiGetTopScope();
  JsVar *result = jsvFindChildFromString(scope, name, createIfNotFound);
  jsvUnLock(scope);
  return result;
}
JsVar *jspeiFindNameOnTop(JsVar *childName, bool createIfNotFound) {
  JsVar *scope = jspeiGetTopScope();
  JsVar *result = jsvFindChildFromVar(scope, childName, createIfNotFound);
  jsvUnLock(scope);
  return result;
}

JsVar *jspFindPrototypeFor(const char *className) {
  JsVar *obj = jsvObjectGetChild(execInfo.root, className, 0);
  if (!obj) return 0;
  JsVar *proto = jsvObjectGetChild(obj, JSPARSE_PROTOTYPE_VAR, 0);
  jsvUnLock(obj);
  return proto;
}


JsVar *jspeiFindChildFromStringInParents(JsVar *parent, const char *name) {
  if (jsvIsObject(parent)) {
    
    JsVar *inheritsFrom = jsvObjectGetChild(parent, JSPARSE_INHERITS_VAR, 0);

    
    if (!inheritsFrom)
      inheritsFrom = jspFindPrototypeFor("Object");

    if (inheritsFrom && inheritsFrom!=parent) {
      
      
      JsVar *child = jsvFindChildFromString(inheritsFrom, name, false);
      if (!child)
        child = jspeiFindChildFromStringInParents(inheritsFrom, name);
      jsvUnLock(inheritsFrom);
      if (child) return child;
    } else jsvUnLock(inheritsFrom);
  } else { 
    const char *objectName = jswGetBasicObjectName(parent);
    while (objectName) {
      JsVar *objName = jsvFindChildFromString(execInfo.root, objectName, false);
      if (objName) {
        JsVar *result = 0;
        JsVar *obj = jsvSkipNameAndUnLock(objName);
        
        if (jsvHasChildren(obj)) {
          
          JsVar *proto = jsvObjectGetChild(obj, JSPARSE_PROTOTYPE_VAR, 0);
          if (proto) {
            result = jsvFindChildFromString(proto, name, false);
            jsvUnLock(proto);
          }
        }
        jsvUnLock(obj);
        if (result) return result;
      }
      
      objectName = jswGetBasicObjectPrototypeName(objectName);
    }
  }

  
  return 0;
}

JsVar *jspeiGetScopesAsVar() {
  if (!execInfo.scopesVar) return 0; 
  
  if (jsvGetArrayLength(execInfo.scopesVar)==1) {
    JsVar *v = jsvGetLastArrayItem(execInfo.scopesVar); 
    return v;
  }
  
  return jsvCopy(execInfo.scopesVar, true);
}

void jspeiLoadScopesFromVar(JsVar *arr) {
  jsvUnLock(execInfo.scopesVar);
  execInfo.scopesVar = 0;
  if (arr) {
    if (jsvIsArray(arr)) {
      
      execInfo.scopesVar = jsvCopy(arr, true);
    } else {
      
      execInfo.scopesVar = jsvNewArray(&arr, 1);
    }
  }
}


bool jspCheckStackPosition() {
  if (jsuGetFreeStack() < 512) { 
    jsExceptionHere(JSET_ERROR, "Too much recursion - the stack is about to overflow");
    jspSetInterrupted(true);
    return false;
  }
  return true;
}



void jspSetNoExecute() {
  execInfo.execute = (execInfo.execute & (JsExecFlags)(int)~EXEC_RUN_MASK) | EXEC_NO;
}

void jspAppendStackTrace(JsVar *stackTrace) {
  JsvStringIterator it;
  jsvStringIteratorNew(&it, stackTrace, 0);
  jsvStringIteratorGotoEnd(&it);
  jslPrintPosition((vcbprintf_callback)jsvStringIteratorPrintfCallback, &it, lex->tokenLastStart);
  jslPrintTokenLineMarker((vcbprintf_callback)jsvStringIteratorPrintfCallback, &it, lex->tokenLastStart, 0);
  jsvStringIteratorFree(&it);
}


void jspSetException(JsVar *value) {
  
  JsVar *exception = jsvFindChildFromString(execInfo.hiddenRoot, JSPARSE_EXCEPTION_VAR, true);
  if (exception) {
    jsvSetValueOfName(exception, value);
    jsvUnLock(exception);
  }
  
  execInfo.execute = execInfo.execute | EXEC_EXCEPTION;
  
  if (lex) {
    JsVar *stackTrace = jsvObjectGetChild(execInfo.hiddenRoot, JSPARSE_STACKTRACE_VAR, JSV_STRING_0);
    if (stackTrace) {
      jsvAppendPrintf(stackTrace, " at ");
      jspAppendStackTrace(stackTrace);
      jsvUnLock(stackTrace);
      
      execInfo.execute = execInfo.execute | EXEC_ERROR_LINE_REPORTED;
    }
  }

}


JsVar *jspGetException() {
  JsVar *exceptionName = jsvFindChildFromString(execInfo.hiddenRoot, JSPARSE_EXCEPTION_VAR, false);
  if (exceptionName) {
    JsVar *exception = jsvSkipName(exceptionName);
    jsvRemoveChild(execInfo.hiddenRoot, exceptionName);
    jsvUnLock(exceptionName);

    JsVar *stack = jspGetStackTrace();
    if (stack && jsvHasChildren(exception)) {
      jsvObjectSetChild(exception, "stack", stack);
    }
    jsvUnLock(stack);

    return exception;
  }
  return 0;
}


JsVar *jspGetStackTrace() {
  JsVar *stackTraceName = jsvFindChildFromString(execInfo.hiddenRoot, JSPARSE_STACKTRACE_VAR, false);
  if (stackTraceName) {
    JsVar *stackTrace = jsvSkipName(stackTraceName);
    jsvRemoveChild(execInfo.hiddenRoot, stackTraceName);
    jsvUnLock(stackTraceName);
    return stackTrace;
  }
  return 0;
}




NO_INLINE bool jspeFunctionArguments(JsVar *funcVar) {
  JSP_MATCH('(');
  while (lex->tk!=')') {
    if (funcVar) {
      char buf[JSLEX_MAX_TOKEN_LENGTH+1];
      buf[0] = '\xFF';
      strcpy(&buf[1], jslGetTokenValueAsString());
      JsVar *param = jsvAddNamedChild(funcVar, 0, buf);
      if (!param) { 
        jspSetError(false);
        return false;
      }
      jsvMakeFunctionParameter(param); 
      jsvUnLock(param);
    }
    JSP_MATCH(LEX_ID);
    if (lex->tk!=')') JSP_MATCH(',');
  }
  JSP_MATCH(')');
  return true;
}


NO_INLINE bool jspeFunctionDefinitionInternal(JsVar *funcVar, bool expressionOnly) {
  bool forcePretokenise = false;

  if (expressionOnly) {
    if (funcVar)
      funcVar->flags = (funcVar->flags & ~JSV_VARTYPEMASK) | JSV_FUNCTION_RETURN;
  } else {
    JSP_MATCH('{');
  #ifndef SAVE_ON_FLASH
    if (lex->tk==LEX_STR) {
      if (!strcmp(jslGetTokenValueAsString(), "compiled"))
        jsWarn("Function marked with \"compiled\" uploaded in source form");
      if (lex->tk==LEX_STR && !strcmp(jslGetTokenValueAsString(), "ram")) {
        JSP_ASSERT_MATCH(LEX_STR);
        forcePretokenise = true;
      }
    }
  #endif

    
    if (funcVar && lex->tk==LEX_R_RETURN) {
      funcVar->flags = (funcVar->flags & ~JSV_VARTYPEMASK) | JSV_FUNCTION_RETURN;
      JSP_ASSERT_MATCH(LEX_R_RETURN);
    }
  }

  
  JsVarInt lineNumber = 0;
  if (funcVar && lex->lineNumberOffset && !(forcePretokenise||jsfGetFlag(JSF_PRETOKENISE))) {
    
    lineNumber = (JsVarInt)jslGetLineNumber() + (JsVarInt)lex->lineNumberOffset - 1;
  }

  
  JslCharPos funcBegin;
  jslSkipWhiteSpace();
  jslCharPosNew(&funcBegin, lex->sourceVar, lex->tokenStart);
  int lastTokenEnd = -1;
  lex->hadThisKeyword = lex->tk == LEX_R_THIS;
  if (!expressionOnly) {
    int brackets = 0;
    while (lex->tk && (brackets || lex->tk != '}')) {
      if (lex->tk == '{') brackets++;
      if (lex->tk == '}') brackets--;
      lastTokenEnd = (int)jsvStringIteratorGetIndex(&lex->it)-1;
      JSP_ASSERT_MATCH(lex->tk);
    }
    
  } else {
    JsExecFlags oldExec = execInfo.execute;
    execInfo.execute = EXEC_NO;
    jsvUnLock(jspeAssignmentExpression());
    execInfo.execute = oldExec;
    lastTokenEnd = (int)lex->tokenStart;
  }
  bool hadThisKeyword = lex->hadThisKeyword;
  
  if (funcVar && lastTokenEnd>0) {
    
    JsVar *funcCodeVar;
    if (!forcePretokenise && jsvIsNativeString(lex->sourceVar)) {
      
      int s = (int)jsvStringIteratorGetIndex(&funcBegin.it) - 1;
      funcCodeVar = jsvNewNativeString(lex->sourceVar->varData.nativeStr.ptr + s, (unsigned int)(lastTokenEnd - s));

    } else if (!forcePretokenise && jsvIsFlashString(lex->sourceVar)) {
        
        int s = (int)jsvStringIteratorGetIndex(&funcBegin.it) - 1;
        funcCodeVar = jsvNewFlashString(lex->sourceVar->varData.nativeStr.ptr + s, (unsigned int)(lastTokenEnd - s));

    } else {
      if (jsfGetFlag(JSF_PRETOKENISE) || forcePretokenise) {
        funcCodeVar = jslNewTokenisedStringFromLexer(&funcBegin, (size_t)lastTokenEnd);
      } else {
        funcCodeVar = jslNewStringFromLexer(&funcBegin, (size_t)lastTokenEnd);
      }
    }
    jsvUnLock2(jsvAddNamedChild(funcVar, funcCodeVar, JSPARSE_FUNCTION_CODE_NAME), funcCodeVar);
    
    JsVar *funcScopeVar = jspeiGetScopesAsVar();
    if (funcScopeVar) {
      jsvUnLock2(jsvAddNamedChild(funcVar, funcScopeVar, JSPARSE_FUNCTION_SCOPE_NAME), funcScopeVar);
    }

    
    if (lineNumber) {
      JsVar *funcLineNumber = jsvNewFromInteger(lineNumber);
      if (funcLineNumber) {
        jsvUnLock2(jsvAddNamedChild(funcVar, funcLineNumber, JSPARSE_FUNCTION_LINENUMBER_NAME), funcLineNumber);
      }
    }

  }

  jslCharPosFree(&funcBegin);
  if (!expressionOnly) JSP_MATCH('}');
  return hadThisKeyword;
}


NO_INLINE JsVar *jspeFunctionDefinition(bool parseNamedFunction) {
  
  
  JsVar *funcVar = 0;

  bool actuallyCreateFunction = JSP_SHOULD_EXECUTE;
  if (actuallyCreateFunction)
    funcVar = jsvNewWithFlags(JSV_FUNCTION);

  JsVar *functionInternalName = 0;
  if (parseNamedFunction && lex->tk==LEX_ID) {
    
    if (funcVar) functionInternalName = jslGetTokenValueAsVar();
    
    JSP_ASSERT_MATCH(LEX_ID);
  }

  
  if (!jspeFunctionArguments(funcVar)) {
    jsvUnLock2(functionInternalName, funcVar);
    
    return 0;
  }

  
  jspeFunctionDefinitionInternal(funcVar, false);

  
  if (funcVar && functionInternalName)
    jsvObjectSetChildAndUnLock(funcVar, JSPARSE_FUNCTION_NAME_NAME, functionInternalName);

  return funcVar;
}


NO_INLINE bool jspeParseFunctionCallBrackets() {
  assert(!JSP_SHOULD_EXECUTE);
  JSP_MATCH('(');
  while (!JSP_SHOULDNT_PARSE && lex->tk != ')') {
    jsvUnLock(jspeAssignmentExpression());

    if (lex->tk==LEX_ARROW_FUNCTION) {
      jsvUnLock(jspeArrowFunction(0, 0));
    }

    if (lex->tk!=')') JSP_MATCH(',');
  }
  if (!JSP_SHOULDNT_PARSE) JSP_MATCH(')');
  return 0;
}


NO_INLINE JsVar *jspeFunctionCall(JsVar *function, JsVar *functionName, JsVar *thisArg, bool isParsing, int argCount, JsVar **argPtr) {
  if (JSP_SHOULD_EXECUTE && !function) {
    if (functionName)
      jsExceptionHere(JSET_ERROR, "Function %q not found!", functionName);
    else jsExceptionHere(JSET_ERROR, "Function not found!", functionName);
    return 0;
  }

  if (JSP_SHOULD_EXECUTE) if (!jspCheckStackPosition()) return 0; 

  if (JSP_SHOULD_EXECUTE && function) {
    JsVar *returnVar = 0;

    if (!jsvIsFunction(function)) {
      jsExceptionHere(JSET_ERROR, "Expecting a function to call, got %t", function);
      return 0;
    }
    JsVar *thisVar = jsvLockAgainSafe(thisArg);
    if (isParsing) JSP_MATCH('(');

    
    if (jsvIsNativeFunction(function)) { 
      unsigned int argPtrSize = 0;
      int boundArgs = 0;
      
      JsvObjectIterator it;
      jsvObjectIteratorNew(&it, function);
      JsVar *param = jsvObjectIteratorGetKey(&it);
      while (jsvIsFunctionParameter(param)) {
        if ((unsigned)argCount>=argPtrSize) {
          
          unsigned int newArgPtrSize = (argPtrSize?argPtrSize:(unsigned int)argCount)*4;
          size_t newArgPtrByteSize = sizeof(JsVar*)*newArgPtrSize;
          if (jsuGetFreeStack() < 256+newArgPtrByteSize) {
            jsExceptionHere(JSET_ERROR, "Insufficient stack for this many arguments");
            jsvUnLock(thisVar);
            return 0;
          }
          JsVar **newArgPtr = (JsVar**)alloca(newArgPtrByteSize);
          memcpy(newArgPtr, argPtr, (unsigned)argCount*sizeof(JsVar*));
          argPtr = newArgPtr;
          argPtrSize = newArgPtrSize;
        }
        
        int i;
        for (i=argCount-1;i>=boundArgs;i--)
          argPtr[i+1] = argPtr[i];
        
        argPtr[boundArgs] = jsvSkipName(param);
        argCount++;
        boundArgs++;
        jsvUnLock(param);
        jsvObjectIteratorNext(&it);
        param = jsvObjectIteratorGetKey(&it);
      }
      
      while (param) {
        if (jsvIsStringEqual(param, JSPARSE_FUNCTION_THIS_NAME)) {
          jsvUnLock(thisVar);
          thisVar = jsvSkipName(param);
          break;
        }
        jsvUnLock(param);
        jsvObjectIteratorNext(&it);
        param = jsvObjectIteratorGetKey(&it);
      }
      jsvUnLock(param);
      jsvObjectIteratorFree(&it);

      
      int allocatedArgCount = boundArgs;
      if (isParsing) {
        while (!JSP_HAS_ERROR && lex->tk!=')' && lex->tk!=LEX_EOF) {
          if ((unsigned)argCount>=argPtrSize) {
            
            unsigned int newArgPtrSize = argPtrSize?argPtrSize*4:16;
            JsVar **newArgPtr = (JsVar**)alloca(sizeof(JsVar*)*newArgPtrSize);
            memcpy(newArgPtr, argPtr, (unsigned)argCount*sizeof(JsVar*));
            argPtr = newArgPtr;
            argPtrSize = newArgPtrSize;
          }
          argPtr[argCount++] = jsvSkipNameAndUnLock(jspeAssignmentExpression());
          if (lex->tk!=')') JSP_MATCH_WITH_CLEANUP_AND_RETURN(',',jsvUnLockMany((unsigned)argCount, argPtr);jsvUnLock(thisVar);, 0);
        }

        JSP_MATCH(')');
        allocatedArgCount = argCount;
      }

      void *nativePtr = jsvGetNativeFunctionPtr(function);

      JsVar *oldThisVar = execInfo.thisVar;
      if (thisVar)
        execInfo.thisVar = jsvRef(thisVar);
      else {
        if (nativePtr==jswrap_eval) { 
          
          if (execInfo.thisVar) execInfo.thisVar = jsvRef(execInfo.thisVar);
        } else {
          execInfo.thisVar = jsvRef(execInfo.root); 
        }
      }



      if (nativePtr && !JSP_HAS_ERROR) {
        returnVar = jsnCallFunction(nativePtr, function->varData.native.argTypes, thisVar, argPtr, argCount);
        assert(!jsvIsName(returnVar));
      } else {
        returnVar = 0;
      }

      
      jsvUnLockMany((unsigned)allocatedArgCount, argPtr);

      
      if (execInfo.thisVar) jsvUnRef(execInfo.thisVar);
      execInfo.thisVar = oldThisVar;

    } else { 
      
      
      
      JsVar *functionRoot = jsvNewWithFlags(JSV_FUNCTION);
      if (!functionRoot) { 
        jspSetError(false);
        jsvUnLock(thisVar);
        return 0;
      }

      JsVar *functionScope = 0;
      JsVar *functionCode = 0;
      JsVar *functionInternalName = 0;

      uint16_t functionLineNumber = 0;


      
      JsvObjectIterator it;
      jsvObjectIteratorNew(&it, function);

      JsVar *param = jsvObjectIteratorGetKey(&it);
      JsVar *value = jsvObjectIteratorGetValue(&it);
      while (jsvIsFunctionParameter(param) && value) {
        jsvAddFunctionParameter(functionRoot, jsvNewFromStringVar(param,1,JSVAPPENDSTRINGVAR_MAXLENGTH), value);
        jsvUnLock2(value, param);
        jsvObjectIteratorNext(&it);
        param = jsvObjectIteratorGetKey(&it);
        value = jsvObjectIteratorGetValue(&it);
      }
      jsvUnLock2(value, param);
      if (isParsing) {
        int hadParams = 0;
        
        
        while (!JSP_SHOULDNT_PARSE && lex->tk!=')') {
          JsVar *param = jsvObjectIteratorGetKey(&it);
          bool paramDefined = jsvIsFunctionParameter(param);
          if (lex->tk!=')' || paramDefined) {
            hadParams++;
            JsVar *value = 0;
            
            if (lex->tk!=')')
              value = jspeAssignmentExpression();
            
            value = jsvSkipNameAndUnLock(value);
            jsvAddFunctionParameter(functionRoot, paramDefined?jsvNewFromStringVar(param,1,JSVAPPENDSTRINGVAR_MAXLENGTH):0, value);
            jsvUnLock(value);
            if (lex->tk!=')') JSP_MATCH(',');
          }
          jsvUnLock(param);
          if (paramDefined) jsvObjectIteratorNext(&it);
        }
        JSP_MATCH(')');
      } else {  
        int args = 0;
        while (args<argCount) {
          JsVar *param = jsvObjectIteratorGetKey(&it);
          bool paramDefined = jsvIsFunctionParameter(param);
          jsvAddFunctionParameter(functionRoot, paramDefined?jsvNewFromStringVar(param,1,JSVAPPENDSTRINGVAR_MAXLENGTH):0, argPtr[args]);
          args++;
          jsvUnLock(param);
          if (paramDefined) jsvObjectIteratorNext(&it);
        }
      }
      
      while (jsvObjectIteratorHasValue(&it)) {
        JsVar *param = jsvObjectIteratorGetKey(&it);
        if (jsvIsString(param)) {
          if (jsvIsStringEqual(param, JSPARSE_FUNCTION_SCOPE_NAME)) functionScope = jsvSkipName(param);
          else if (jsvIsStringEqual(param, JSPARSE_FUNCTION_CODE_NAME)) functionCode = jsvSkipName(param);
          else if (jsvIsStringEqual(param, JSPARSE_FUNCTION_NAME_NAME)) functionInternalName = jsvSkipName(param);
          else if (jsvIsStringEqual(param, JSPARSE_FUNCTION_THIS_NAME)) {
            jsvUnLock(thisVar);
            thisVar = jsvSkipName(param);
          }

          else if (jsvIsStringEqual(param, JSPARSE_FUNCTION_LINENUMBER_NAME)) functionLineNumber = (uint16_t)jsvGetIntegerAndUnLock(jsvSkipName(param));

          else if (jsvIsFunctionParameter(param)) {
            JsVar *defaultVal = jsvSkipName(param);
            jsvAddFunctionParameter(functionRoot, jsvNewFromStringVar(param,1,JSVAPPENDSTRINGVAR_MAXLENGTH), defaultVal);
            jsvUnLock(defaultVal);
          }
        }
        jsvUnLock(param);
        jsvObjectIteratorNext(&it);
      }
      jsvObjectIteratorFree(&it);

      
      if (functionInternalName) {
        JsVar *name = jsvMakeIntoVariableName(jsvNewFromStringVar(functionInternalName,0,JSVAPPENDSTRINGVAR_MAXLENGTH), function);
        jsvAddName(functionRoot, name);
        jsvUnLock2(name, functionInternalName);
      }

      if (!JSP_HAS_ERROR) {
        
        JsVar *oldScopeVar = execInfo.scopesVar;
        execInfo.scopesVar = 0;
        
        if (functionScope) {
          jspeiLoadScopesFromVar(functionScope);
          jsvUnLock(functionScope);
        }
        
        if (jspeiAddScope(functionRoot)) {
          

          JsVar *oldThisVar = execInfo.thisVar;
          if (thisVar)
            execInfo.thisVar = jsvRef(thisVar);
          else execInfo.thisVar = jsvRef(execInfo.root);


          
          if (functionCode) {

            bool hadDebuggerNextLineOnly = false;

            if (execInfo.execute&EXEC_DEBUGGER_STEP_INTO) {
	      if (functionName)
		jsiConsolePrintf("Stepping into %v\n", functionName);
	      else jsiConsolePrintf("Stepping into function\n", functionName);
            } else {
              hadDebuggerNextLineOnly = execInfo.execute&EXEC_DEBUGGER_NEXT_LINE;
              if (hadDebuggerNextLineOnly)
                execInfo.execute &= (JsExecFlags)~EXEC_DEBUGGER_NEXT_LINE;
            }



            JsLex newLex;
            JsLex *oldLex = jslSetLex(&newLex);
            jslInit(functionCode);

            newLex.lineNumberOffset = functionLineNumber;

            JSP_SAVE_EXECUTE();
            

            execInfo.execute = EXEC_YES | (execInfo.execute&(EXEC_CTRL_C_MASK|EXEC_ERROR_MASK|EXEC_DEBUGGER_NEXT_LINE));

            execInfo.execute = EXEC_YES | (execInfo.execute&(EXEC_CTRL_C_MASK|EXEC_ERROR_MASK));

            if (jsvIsFunctionReturn(function)) {
              #ifdef USE_DEBUGGER
                
                if (execInfo.execute&EXEC_DEBUGGER_NEXT_LINE && JSP_SHOULD_EXECUTE) {
                  lex->tokenLastStart = lex->tokenStart;
                  jsiDebuggerLoop();
                }
              #endif
              
              if (lex->tk != ';' && lex->tk != '}')
                returnVar = jsvSkipNameAndUnLock(jspeExpression());
            } else {
              
              JsVar *returnVarName = jsvAddNamedChild(functionRoot, 0, JSPARSE_RETURN_VAR);
              
              jspeBlockNoBrackets();
              
              returnVar = jsvSkipNameAndUnLock(returnVarName);
              if (returnVarName) 
                jsvSetValueOfName(returnVarName, 0); 
            }
            
            JsExecFlags hasError = execInfo.execute&EXEC_ERROR_MASK;
            JSP_RESTORE_EXECUTE(); 


            bool calledDebugger = false;
            if (execInfo.execute & EXEC_DEBUGGER_MASK) {
              jsiConsolePrint("Value returned is =");
              jsfPrintJSON(returnVar, JSON_LIMIT | JSON_SOME_NEWLINES | JSON_PRETTY | JSON_SHOW_DEVICES);
              jsiConsolePrintChar('\n');
              if (execInfo.execute & EXEC_DEBUGGER_FINISH_FUNCTION) {
                calledDebugger = true;
                jsiDebuggerLoop();
              }
            }
            if (hadDebuggerNextLineOnly && !calledDebugger)
              execInfo.execute |= EXEC_DEBUGGER_NEXT_LINE;


            jslKill();
            jslSetLex(oldLex);

            if (hasError) {
              execInfo.execute |= hasError; 
              JsVar *stackTrace = jsvObjectGetChild(execInfo.hiddenRoot, JSPARSE_STACKTRACE_VAR, JSV_STRING_0);
              if (stackTrace) {
                jsvAppendPrintf(stackTrace, jsvIsString(functionName)?"in function %q called from ":
                    "in function called from ", functionName);
                if (lex) {
                  jspAppendStackTrace(stackTrace);
                } else jsvAppendPrintf(stackTrace, "system\n");
                jsvUnLock(stackTrace);
              }
            }
          }

          
          if (execInfo.thisVar) jsvUnRef(execInfo.thisVar);
          execInfo.thisVar = oldThisVar;

          jspeiRemoveScope();
        }

        
        jsvUnLock(execInfo.scopesVar);
        execInfo.scopesVar = oldScopeVar;
      }
      jsvUnLock(functionCode);
      jsvUnLock(functionRoot);
    }

    jsvUnLock(thisVar);

    return returnVar;
  } else if (isParsing) { 
    jspeParseFunctionCallBrackets();
    
    return 0;
  } else return 0;
}


JsVar *jspGetNamedVariable(const char *tokenName) {
  JsVar *a = JSP_SHOULD_EXECUTE ? jspeiFindInScopes(tokenName) : 0;
  if (JSP_SHOULD_EXECUTE && !a) {
    
    if (jswIsBuiltInObject(tokenName)) {
      
      
      JsVar *obj = jswFindBuiltInFunction(0, tokenName);
      
      if (!obj)
        obj = jspNewBuiltin(tokenName);
      if (obj) { 
        a = jsvAddNamedChild(execInfo.root, obj, tokenName);
        jsvUnLock(obj);
      }
    } else {
      a = jswFindBuiltInFunction(0, tokenName);
      if (!a) {
        
        a = jsvMakeIntoVariableName(jsvNewFromString(tokenName), 0);
      }
    }
  }
  return a;
}


static NO_INLINE JsVar *jspGetNamedFieldInParents(JsVar *object, const char* name, bool returnName) {
  
  JsVar * child = jspeiFindChildFromStringInParents(object, name);

  
  if (!child) {
    child = jswFindBuiltInFunction(object, name);
  }

  
  if (child && returnName) {
    
    if (jsvIsName(child)) {
      JsVar *t = jsvGetValueOfName(child);
      jsvUnLock(child);
      child = t;
    }
    
    JsVar *nameVar = jsvNewFromString(name);
    JsVar *newChild = jsvCreateNewChild(object, nameVar, child);
    jsvUnLock2(nameVar, child);
    child = newChild;
  }

  
  if (!child) {
    if (jsvIsFunction(object) && strcmp(name, JSPARSE_PROTOTYPE_VAR)==0) {
      
      JsVar *proto = jsvNewObject();
      
      jsvObjectSetChild(proto, JSPARSE_CONSTRUCTOR_VAR, object);
      child = jsvAddNamedChild(object, proto, JSPARSE_PROTOTYPE_VAR);
      jspEnsureIsPrototype(object, child);
      jsvUnLock(proto);
    } else if (strcmp(name, JSPARSE_INHERITS_VAR)==0) {
      const char *objName = jswGetBasicObjectName(object);
      if (objName) {
        child = jspNewPrototype(objName);
      }
    }
  }

  return child;
}


JsVar *jspGetNamedField(JsVar *object, const char* name, bool returnName) {

  JsVar *child = 0;
  
  if (jsvHasChildren(object))
    child = jsvFindChildFromString(object, name, false);

  if (!child) {
    child = jspGetNamedFieldInParents(object, name, returnName);

    
    if (!child && jsvIsFunction(object) && strcmp(name, JSPARSE_PROTOTYPE_VAR)==0) {
      JsVar *value = jsvNewObject(); 
      child = jsvAddNamedChild(object, value, JSPARSE_PROTOTYPE_VAR);
      jsvUnLock(value);
    }
  }

  if (returnName) return child;
  else return jsvSkipNameAndUnLock(child);
}


JsVar *jspGetVarNamedField(JsVar *object, JsVar *nameVar, bool returnName) {

  JsVar *child = 0;
  
  if (jsvHasChildren(object))
    child = jsvFindChildFromVar(object, nameVar, false);

  if (!child) {
    if (jsvIsArrayBuffer(object) && jsvIsInt(nameVar)) {
      
      child = jsvMakeIntoVariableName(jsvNewFromInteger(jsvGetInteger(nameVar)), object);
      if (child) 
        child->flags = (child->flags & ~JSV_VARTYPEMASK) | JSV_ARRAYBUFFERNAME;
    } else if (jsvIsString(object) && jsvIsInt(nameVar)) {
      JsVarInt idx = jsvGetInteger(nameVar);
      if (idx>=0 && idx<(JsVarInt)jsvGetStringLength(object)) {
        char ch = jsvGetCharInString(object, (size_t)idx);
        child = jsvNewStringOfLength(1, &ch);
      } else if (returnName)
        child = jsvCreateNewChild(object, nameVar, 0); 
    } else {
      
      char name[JSLEX_MAX_TOKEN_LENGTH];
      jsvGetString(nameVar, name, JSLEX_MAX_TOKEN_LENGTH);
      
      child = jspGetNamedFieldInParents(object, name, returnName);

      
      if (!child && jsvIsFunction(object) && jsvIsStringEqual(nameVar, JSPARSE_PROTOTYPE_VAR)) {
        JsVar *value = jsvNewObject(); 
        child = jsvAddNamedChild(object, value, JSPARSE_PROTOTYPE_VAR);
        jsvUnLock(value);
      }
    }
  }

  if (returnName) return child;
  else return jsvSkipNameAndUnLock(child);
}


JsVar *jspCallNamedFunction(JsVar *object, char* name, int argCount, JsVar **argPtr) {
  JsVar *child = jspGetNamedField(object, name, false);
  JsVar *r = 0;
  if (jsvIsFunction(child))
    r = jspeFunctionCall(child, 0, object, false, argCount, argPtr);
  jsvUnLock(child);
  return r;
}

NO_INLINE JsVar *jspeFactorMember(JsVar *a, JsVar **parentResult) {
  
  JsVar *parent = 0;

  while (lex->tk=='.' || lex->tk=='[') {
    if (lex->tk == '.') { 
      JSP_ASSERT_MATCH('.');
      if (jslIsIDOrReservedWord()) {
        if (JSP_SHOULD_EXECUTE) {
          
          const char *name = jslGetTokenValueAsString();

          JsVar *aVar = jsvSkipNameWithParent(a,true,parent);
          JsVar *child = 0;
          if (aVar)
            child = jspGetNamedField(aVar, name, true);
          if (!child) {
            if (!jsvIsUndefined(aVar)) {
              
              
              JsVar *nameVar = jslGetTokenValueAsVar();
              child = jsvCreateNewChild(aVar, nameVar, 0);
              jsvUnLock(nameVar);
            } else {
              
              jsExceptionHere(JSET_ERROR, "Cannot read property '%s' of undefined", name);
            }
          }
          jsvUnLock(parent);
          parent = aVar;
          jsvUnLock(a);
          a = child;
        }
        
        jslGetNextToken();
      } else {
        
        JSP_MATCH_WITH_RETURN(LEX_ID, a);
      }
    } else if (lex->tk == '[') { 
      JsVar *index;
      JSP_ASSERT_MATCH('[');
      if (!jspCheckStackPosition()) return parent;
      index = jsvSkipNameAndUnLock(jspeAssignmentExpression());
      JSP_MATCH_WITH_CLEANUP_AND_RETURN(']', jsvUnLock2(parent, index);, a);
      if (JSP_SHOULD_EXECUTE) {
        index = jsvAsArrayIndexAndUnLock(index);
        JsVar *aVar = jsvSkipNameWithParent(a,true,parent);
        JsVar *child = 0;
        if (aVar)
          child = jspGetVarNamedField(aVar, index, true);

        if (!child) {
          if (jsvHasChildren(aVar)) {
            
            
            child = jsvCreateNewChild(aVar, index, 0);
          } else {
            jsExceptionHere(JSET_ERROR, "Field or method %q does not already exist, and can't create it on %t", index, aVar);
          }
        }
        jsvUnLock(parent);
        parent = jsvLockAgainSafe(aVar);
        jsvUnLock(a);
        a = child;
        jsvUnLock(aVar);
      }
      jsvUnLock(index);
    } else {
      assert(0);
    }
  }

  if (parentResult) *parentResult = parent;
  else jsvUnLock(parent);
  return a;
}

NO_INLINE JsVar *jspeConstruct(JsVar *func, JsVar *funcName, bool hasArgs) {
  assert(JSP_SHOULD_EXECUTE);
  if (!jsvIsFunction(func)) {
    jsExceptionHere(JSET_ERROR, "Constructor should be a function, but is %t", func);
    return 0;
  }

  JsVar *thisObj = jsvNewObject();
  if (!thisObj) return 0; 
  
  JsVar *prototypeName = jsvFindChildFromString(func, JSPARSE_PROTOTYPE_VAR, true);
  jspEnsureIsPrototype(func, prototypeName); 
  JsVar *prototypeVar = jsvSkipName(prototypeName);
  jsvUnLock3(jsvAddNamedChild(thisObj, prototypeVar, JSPARSE_INHERITS_VAR), prototypeVar, prototypeName);

  JsVar *a = jspeFunctionCall(func, funcName, thisObj, hasArgs, 0, 0);

  
  if (a) {
    jsvUnLock(thisObj);
    thisObj = a;
  } else {
    jsvUnLock(a);
  }
  return thisObj;
}

NO_INLINE JsVar *jspeFactorFunctionCall() {
  
  bool isConstructor = false;
  if (lex->tk==LEX_R_NEW) {
    JSP_ASSERT_MATCH(LEX_R_NEW);
    isConstructor = true;

    if (lex->tk==LEX_R_NEW) {
      jsExceptionHere(JSET_ERROR, "Nesting 'new' operators is unsupported");
      jspSetError(false);
      return 0;
    }
  }

  JsVar *parent = 0;

  bool wasSuper = lex->tk==LEX_R_SUPER;

  JsVar *a = jspeFactorMember(jspeFactor(), &parent);

  if (wasSuper) {
    
    jsvUnLock(parent);
    parent = jsvLockAgainSafe(execInfo.thisVar);
  }


  while ((lex->tk=='(' || (isConstructor && JSP_SHOULD_EXECUTE)) && !jspIsInterrupted()) {
    JsVar *funcName = a;
    JsVar *func = jsvSkipName(funcName);

    
    if (isConstructor && JSP_SHOULD_EXECUTE) {
      
      bool parseArgs = lex->tk=='(';
      a = jspeConstruct(func, funcName, parseArgs);
      isConstructor = false; 
    } else a = jspeFunctionCall(func, funcName, parent, true, 0, 0);

    jsvUnLock3(funcName, func, parent);
    parent=0;
    a = jspeFactorMember(a, &parent);
  }

  
  if (parent && jsvIsBasicName(a) && !jsvIsNewChild(a)) {
    JsVar *value = jsvLockSafe(jsvGetFirstChild(a));
    if (jsvIsGetterOrSetter(value)) { 
      JsVar *nameVar = jsvCopyNameOnly(a,false,true);
      JsVar *newChild = jsvCreateNewChild(parent, nameVar, value);
      jsvUnLock2(nameVar, a);
      a = newChild;
    }
    jsvUnLock(value);
  }

  jsvUnLock(parent);
  return a;
}


NO_INLINE JsVar *jspeFactorObject() {
  if (JSP_SHOULD_EXECUTE) {
    JsVar *contents = jsvNewObject();
    if (!contents) { 
      jspSetError(false);
      return 0;
    }
    
    JSP_MATCH_WITH_RETURN('{', contents);
    while (!JSP_SHOULDNT_PARSE && lex->tk != '}') {
      JsVar *varName = 0;
      
      if (jslIsIDOrReservedWord()) {
        if (JSP_SHOULD_EXECUTE)
          varName = jslGetTokenValueAsVar();
        jslGetNextToken(); 
      } else if ( lex->tk==LEX_STR || lex->tk==LEX_FLOAT || lex->tk==LEX_INT || lex->tk==LEX_R_TRUE || lex->tk==LEX_R_FALSE || lex->tk==LEX_R_NULL || lex->tk==LEX_R_UNDEFINED) {






        varName = jspeFactor();
      } else {
        JSP_MATCH_WITH_RETURN(LEX_ID, contents);
      }

      if (lex->tk==LEX_ID && jsvIsString(varName)) {
        bool isGetter = jsvIsStringEqual(varName, "get");
        bool isSetter = jsvIsStringEqual(varName, "set");
        if (isGetter || isSetter) {
          jsvUnLock(varName);
          varName = jslGetTokenValueAsVar();
          JSP_ASSERT_MATCH(LEX_ID);
          JsVar *method = jspeFunctionDefinition(false);
          jsvAddGetterOrSetter(contents, varName, isGetter, method);
          jsvUnLock(method);
        }
      } else  {

        JSP_MATCH_WITH_CLEANUP_AND_RETURN(':', jsvUnLock(varName), contents);
        if (JSP_SHOULD_EXECUTE) {
          varName = jsvAsArrayIndexAndUnLock(varName);
          JsVar *contentsName = jsvFindChildFromVar(contents, varName, true);
          if (contentsName) {
            JsVar *value = jsvSkipNameAndUnLock(jspeAssignmentExpression()); 
            jsvUnLock2(jsvSetValueOfName(contentsName, value), value);
          }
        }
      }
      jsvUnLock(varName);
      
      if (lex->tk != '}') JSP_MATCH_WITH_RETURN(',', contents);
    }
    JSP_MATCH_WITH_RETURN('}', contents);
    return contents;
  } else {
    
    jspeBlock();
    return 0;
  }
}

NO_INLINE JsVar *jspeFactorArray() {
  int idx = 0;
  JsVar *contents = 0;
  if (JSP_SHOULD_EXECUTE) {
    contents = jsvNewEmptyArray();
    if (!contents) { 
      jspSetError(false);
      return 0;
    }
  }
  
  JSP_MATCH_WITH_RETURN('[', contents);
  while (!JSP_SHOULDNT_PARSE && lex->tk != ']') {
    if (JSP_SHOULD_EXECUTE) {
      JsVar *aVar = 0;
      JsVar *indexName = 0;
      if (lex->tk != ',') { 
        aVar = jsvSkipNameAndUnLock(jspeAssignmentExpression());
        indexName = jsvMakeIntoVariableName(jsvNewFromInteger(idx),  aVar);
      }
      if (indexName) { 
        jsvAddName(contents, indexName);
        jsvUnLock(indexName);
      }
      jsvUnLock(aVar);
    } else {
      jsvUnLock(jspeAssignmentExpression());
    }
    
    if (lex->tk != ']') JSP_MATCH_WITH_RETURN(',', contents);
    idx++;
  }
  if (contents) jsvSetArrayLength(contents, idx, false);
  JSP_MATCH_WITH_RETURN(']', contents);
  return contents;
}

NO_INLINE void jspEnsureIsPrototype(JsVar *instanceOf, JsVar *prototypeName) {
  if (!prototypeName) return;
  JsVar *prototypeVar = jsvSkipName(prototypeName);
  if (!(jsvIsObject(prototypeVar) || jsvIsFunction(prototypeVar))) {
    if (!jsvIsUndefined(prototypeVar))
      jsExceptionHere(JSET_TYPEERROR, "Prototype should be an object, got %t", prototypeVar);
    jsvUnLock(prototypeVar);
    prototypeVar = jsvNewObject(); 
    JsVar *lastName = jsvSkipToLastName(prototypeName);
    jsvSetValueOfName(lastName, prototypeVar);
    jsvUnLock(lastName);
  }
  JsVar *constructor = jsvFindChildFromString(prototypeVar, JSPARSE_CONSTRUCTOR_VAR, true);
  if (constructor) jsvSetValueOfName(constructor, instanceOf);
  jsvUnLock2(constructor, prototypeVar);
}

NO_INLINE JsVar *jspeFactorTypeOf() {
  JSP_ASSERT_MATCH(LEX_R_TYPEOF);
  JsVar *a = jspeUnaryExpression();
  JsVar *result = 0;
  if (JSP_SHOULD_EXECUTE) {
    if (!jsvIsVariableDefined(a)) {
      
      result=jsvNewFromString("undefined");
    } else {
      a = jsvSkipNameAndUnLock(a);
      result=jsvNewFromString(jsvGetTypeOf(a));
    }
  }
  jsvUnLock(a);
  return result;
}

NO_INLINE JsVar *jspeFactorDelete() {
  JSP_ASSERT_MATCH(LEX_R_DELETE);
  JsVar *parent = 0;
  JsVar *a = jspeFactorMember(jspeFactor(), &parent);
  JsVar *result = 0;
  if (JSP_SHOULD_EXECUTE) {
    bool ok = false;
    if (jsvIsName(a) && !jsvIsNewChild(a)) {
      
      if (!parent && jsvIsChild(execInfo.root, a))
        parent = jsvLockAgain(execInfo.root);

      if (jsvHasChildren(parent)) {
        
        if (jsvIsArray(parent)) {
          
          JsVarInt l = jsvGetArrayLength(parent);
          jsvRemoveChild(parent, a);
          jsvSetArrayLength(parent, l, false);
        } else {
          jsvRemoveChild(parent, a);
        }
        ok = true;
      }
    }

    result = jsvNewFromBool(ok);
  }
  jsvUnLock2(a, parent);
  return result;
}


JsVar *jspeTemplateLiteral() {
  JsVar *a = 0;
  if (JSP_SHOULD_EXECUTE) {
    JsVar *template = jslGetTokenValueAsVar();
    a = jsvNewFromEmptyString();
    if (a && template) {
      JsvStringIterator it, dit;
      jsvStringIteratorNew(&it, template, 0);
      jsvStringIteratorNew(&dit, a, 0);
      while (jsvStringIteratorHasChar(&it)) {
        char ch = jsvStringIteratorGetCharAndNext(&it);
        if (ch=='$') {
          ch = jsvStringIteratorGetChar(&it);
          if (ch=='{') {
            
            jsvStringIteratorNext(&it);
            int brackets = 1;
            JsVar *expr = jsvNewFromEmptyString();
            if (!expr) break;
            JsvStringIterator eit;
            jsvStringIteratorNew(&eit, expr, 0);
            while (jsvStringIteratorHasChar(&it)) {
              ch = jsvStringIteratorGetCharAndNext(&it);
              if (ch=='{') brackets++;
              if (ch=='}') {
                brackets--;
                if (!brackets) break;
              }
              jsvStringIteratorAppend(&eit, ch);
            }
            jsvStringIteratorFree(&eit);
            JsVar *result = jspEvaluateExpressionVar(expr);
            jsvUnLock(expr);
            result = jsvAsStringAndUnLock(result);
            jsvStringIteratorAppendString(&dit, result, 0, JSVAPPENDSTRINGVAR_MAXLENGTH);
            jsvUnLock(result);
          } else {
            jsvStringIteratorAppend(&dit, '$');
          }
        } else {
          jsvStringIteratorAppend(&dit, ch);
        }
      }
      jsvStringIteratorFree(&it);
      jsvStringIteratorFree(&dit);
    }
    jsvUnLock(template);
  }
  JSP_ASSERT_MATCH(LEX_TEMPLATE_LITERAL);
  return a;
}



NO_INLINE JsVar *jspeAddNamedFunctionParameter(JsVar *funcVar, JsVar *name) {
  if (!funcVar) funcVar = jsvNewWithFlags(JSV_FUNCTION);
  char buf[JSLEX_MAX_TOKEN_LENGTH+1];
  buf[0] = '\xFF';
  size_t l = jsvGetString(name, &buf[1], JSLEX_MAX_TOKEN_LENGTH);
  buf[l+1] = 0; 
  JsVar *param = jsvAddNamedChild(funcVar, 0, buf);
  jsvMakeFunctionParameter(param);
  jsvUnLock(param);
  return funcVar;
}



NO_INLINE JsVar *jspeArrowFunction(JsVar *funcVar, JsVar *a) {
  assert(!a || jsvIsName(a));
  JSP_ASSERT_MATCH(LEX_ARROW_FUNCTION);
  funcVar = jspeAddNamedFunctionParameter(funcVar, a);

  bool expressionOnly = lex->tk!='{';
  bool fnIncludesThis = jspeFunctionDefinitionInternal(funcVar, expressionOnly);
  
  if (fnIncludesThis)
    jsvObjectSetChild(funcVar, JSPARSE_FUNCTION_THIS_NAME, execInfo.thisVar);

  return funcVar;
}


NO_INLINE JsVar *jspeExpressionOrArrowFunction() {
  JsVar *a = 0;
  JsVar *funcVar = 0;
  bool allNames = true;
  while (lex->tk!=')' && !JSP_SHOULDNT_PARSE) {
    if (allNames && a) {
      
      funcVar = jspeAddNamedFunctionParameter(funcVar, a);
    }
    jsvUnLock(a);
    a = jspeAssignmentExpression();
    
    if (JSP_SHOULD_EXECUTE && !(jsvIsName(a) && jsvIsString(a))) allNames = false;
    if (lex->tk!=')') JSP_MATCH_WITH_CLEANUP_AND_RETURN(',', jsvUnLock2(a,funcVar), 0);
  }
  JSP_MATCH_WITH_CLEANUP_AND_RETURN(')', jsvUnLock2(a,funcVar), 0);
  
  if (allNames && lex->tk==LEX_ARROW_FUNCTION) {
    funcVar = jspeArrowFunction(funcVar, a);
    jsvUnLock(a);
    return funcVar;
  } else {
    jsvUnLock(funcVar);
    return a;
  }
}


NO_INLINE JsVar *jspeClassDefinition(bool parseNamedClass) {
  JsVar *classFunction = 0;
  JsVar *classPrototype = 0;
  JsVar *classInternalName = 0;

  bool actuallyCreateClass = JSP_SHOULD_EXECUTE;
  if (actuallyCreateClass) {
    classFunction = jsvNewWithFlags(JSV_FUNCTION);
    JsVar *scopeVar = jspeiGetScopesAsVar();
    if (scopeVar)
      jsvUnLock2(jsvAddNamedChild(classFunction, scopeVar, JSPARSE_FUNCTION_SCOPE_NAME), scopeVar);
  }

  if (parseNamedClass && lex->tk==LEX_ID) {
    if (classFunction)
      classInternalName = jslGetTokenValueAsVar();
    JSP_ASSERT_MATCH(LEX_ID);
  }
  if (classFunction) {
    JsVar *prototypeName = jsvFindChildFromString(classFunction, JSPARSE_PROTOTYPE_VAR, true);
    jspEnsureIsPrototype(classFunction, prototypeName); 
    classPrototype = jsvSkipName(prototypeName);
    jsvUnLock(prototypeName);
  }
  if (lex->tk==LEX_R_EXTENDS) {
    JSP_ASSERT_MATCH(LEX_R_EXTENDS);
    JsVar *extendsFrom = actuallyCreateClass ? jsvSkipNameAndUnLock(jspGetNamedVariable(jslGetTokenValueAsString())) : 0;
    JSP_MATCH_WITH_CLEANUP_AND_RETURN(LEX_ID,jsvUnLock4(extendsFrom,classFunction,classInternalName,classPrototype),0);
    if (classPrototype) {
      if (jsvIsFunction(extendsFrom)) {
        JsVar *extendsFromProto = jsvObjectGetChild(extendsFrom, JSPARSE_PROTOTYPE_VAR, 0);
        if (extendsFromProto) {
          jsvObjectSetChild(classPrototype, JSPARSE_INHERITS_VAR, extendsFromProto);
          
          jsvObjectSetChildAndUnLock(classFunction, JSPARSE_FUNCTION_CODE_NAME, jsvNewFromString("if(this.__proto__.__proto__.constructor)this.__proto__.__proto__.constructor.apply(this,arguments)"));
          jsvUnLock(extendsFromProto);
        }
      } else jsExceptionHere(JSET_SYNTAXERROR, "'extends' argument should be a function, got %t", extendsFrom);
    }
    jsvUnLock(extendsFrom);
  }
  JSP_MATCH_WITH_CLEANUP_AND_RETURN('{',jsvUnLock3(classFunction,classInternalName,classPrototype),0);

  while ((lex->tk==LEX_ID || lex->tk==LEX_R_STATIC) && !jspIsInterrupted()) {
    bool isStatic = lex->tk==LEX_R_STATIC;
    if (isStatic) JSP_ASSERT_MATCH(LEX_R_STATIC);

    JsVar *funcName = jslGetTokenValueAsVar();
    JSP_MATCH_WITH_CLEANUP_AND_RETURN(LEX_ID,jsvUnLock4(funcName,classFunction,classInternalName,classPrototype),0);

    bool isGetter = false, isSetter = false;
    if (lex->tk==LEX_ID) {
      isGetter = jsvIsStringEqual(funcName, "get");
      isSetter = jsvIsStringEqual(funcName, "set");
      if (isGetter || isSetter) {
        jsvUnLock(funcName);
        funcName = jslGetTokenValueAsVar();
        JSP_ASSERT_MATCH(LEX_ID);
      }
    }

    JsVar *method = jspeFunctionDefinition(false);
    if (classFunction && classPrototype) {
      JsVar *obj = isStatic ? classFunction : classPrototype;
      if (jsvIsStringEqual(funcName, "constructor")) {
        jswrap_function_replaceWith(classFunction, method);

      } else if (isGetter || isSetter) {
        jsvAddGetterOrSetter(obj, funcName, isGetter, method);

      } else {
        funcName = jsvMakeIntoVariableName(funcName, 0);
        jsvSetValueOfName(funcName, method);
        jsvAddName(obj, funcName);
      }

    }
    jsvUnLock2(method,funcName);
  }
  jsvUnLock(classPrototype);
  
  if (classInternalName)
    jsvObjectSetChildAndUnLock(classFunction, JSPARSE_FUNCTION_NAME_NAME, classInternalName);

  JSP_MATCH_WITH_CLEANUP_AND_RETURN('}',jsvUnLock(classFunction),0);
  return classFunction;
}



NO_INLINE JsVar *jspeFactor() {
  if (lex->tk==LEX_ID) {
    JsVar *a = jspGetNamedVariable(jslGetTokenValueAsString());
    JSP_ASSERT_MATCH(LEX_ID);

    if (lex->tk==LEX_TEMPLATE_LITERAL)
      jsExceptionHere(JSET_SYNTAXERROR, "Tagged template literals not supported");
    else if (lex->tk==LEX_ARROW_FUNCTION && (jsvIsName(a) || (a==0 && !JSP_SHOULD_EXECUTE))) {
      
      JsVar *funcVar = jspeArrowFunction(0,a);
      jsvUnLock(a);
      a=funcVar;
    }

    return a;
  } else if (lex->tk==LEX_INT) {
    JsVar *v = 0;
    if (JSP_SHOULD_EXECUTE) {
      v = jsvNewFromLongInteger(stringToInt(jslGetTokenValueAsString()));
    }
    JSP_ASSERT_MATCH(LEX_INT);
    return v;
  } else if (lex->tk==LEX_FLOAT) {
    JsVar *v = 0;
    if (JSP_SHOULD_EXECUTE) {
      v = jsvNewFromFloat(stringToFloat(jslGetTokenValueAsString()));
    }
    JSP_ASSERT_MATCH(LEX_FLOAT);
    return v;
  } else if (lex->tk=='(') {
    JSP_ASSERT_MATCH('(');
    if (!jspCheckStackPosition()) return 0;

    
    JsVar *a = jspeExpression();
    if (!JSP_SHOULDNT_PARSE) JSP_MATCH_WITH_RETURN(')',a);
    return a;

    return jspeExpressionOrArrowFunction();


  } else if (lex->tk==LEX_R_TRUE) {
    JSP_ASSERT_MATCH(LEX_R_TRUE);
    return JSP_SHOULD_EXECUTE ? jsvNewFromBool(true) : 0;
  } else if (lex->tk==LEX_R_FALSE) {
    JSP_ASSERT_MATCH(LEX_R_FALSE);
    return JSP_SHOULD_EXECUTE ? jsvNewFromBool(false) : 0;
  } else if (lex->tk==LEX_R_NULL) {
    JSP_ASSERT_MATCH(LEX_R_NULL);
    return JSP_SHOULD_EXECUTE ? jsvNewWithFlags(JSV_NULL) : 0;
  } else if (lex->tk==LEX_R_UNDEFINED) {
    JSP_ASSERT_MATCH(LEX_R_UNDEFINED);
    return 0;
  } else if (lex->tk==LEX_STR) {
    JsVar *a = 0;
    if (JSP_SHOULD_EXECUTE)
      a = jslGetTokenValueAsVar();
    JSP_ASSERT_MATCH(LEX_STR);
    return a;

  } else if (lex->tk==LEX_TEMPLATE_LITERAL) {
    return jspeTemplateLiteral();

  } else if (lex->tk==LEX_REGEX) {
    JsVar *a = 0;

    jsExceptionHere(JSET_SYNTAXERROR, "RegEx are not supported in this version of Espruino\n");

    JsVar *regex = jslGetTokenValueAsVar();
    size_t regexEnd = 0, regexLen = 0;
    JsvStringIterator it;
    jsvStringIteratorNew(&it, regex, 0);
    while (jsvStringIteratorHasChar(&it)) {
      regexLen++;
      if (jsvStringIteratorGetCharAndNext(&it)=='/')
        regexEnd = regexLen;
    }
    jsvStringIteratorFree(&it);
    JsVar *flags = 0;
    if (regexEnd < regexLen)
      flags = jsvNewFromStringVar(regex, regexEnd, JSVAPPENDSTRINGVAR_MAXLENGTH);
    JsVar *regexSource = jsvNewFromStringVar(regex, 1, regexEnd-2);
    a = jswrap_regexp_constructor(regexSource, flags);
    jsvUnLock3(regex, flags, regexSource);

    JSP_ASSERT_MATCH(LEX_REGEX);
    return a;
  } else if (lex->tk=='{') {
    if (!jspCheckStackPosition()) return 0;
    return jspeFactorObject();
  } else if (lex->tk=='[') {
    if (!jspCheckStackPosition()) return 0;
    return jspeFactorArray();
  } else if (lex->tk==LEX_R_FUNCTION) {
    if (!jspCheckStackPosition()) return 0;
    JSP_ASSERT_MATCH(LEX_R_FUNCTION);
    return jspeFunctionDefinition(true);

  } else if (lex->tk==LEX_R_CLASS) {
    if (!jspCheckStackPosition()) return 0;
    JSP_ASSERT_MATCH(LEX_R_CLASS);
    return jspeClassDefinition(true);
  } else if (lex->tk==LEX_R_SUPER) {
    JSP_ASSERT_MATCH(LEX_R_SUPER);
    

    if (jsvIsObject(execInfo.thisVar)) {
      
      JsVar *proto1 = jsvObjectGetChild(execInfo.thisVar, JSPARSE_INHERITS_VAR, 0); 
      JsVar *proto2 = jsvIsObject(proto1) ? jsvObjectGetChild(proto1, JSPARSE_INHERITS_VAR, 0) : 0; 
      jsvUnLock(proto1);
      if (!proto2) {
        jsExceptionHere(JSET_SYNTAXERROR, "Calling 'super' outside of class");
        return 0;
      }
      
      if (lex->tk=='(') {
        JsVar *constr = jsvObjectGetChild(proto2, JSPARSE_CONSTRUCTOR_VAR, 0);
        jsvUnLock(proto2);
        return constr;
      }
      
      return proto2;
    } else if (jsvIsFunction(execInfo.thisVar)) {
      
      JsVar *proto1 = jsvObjectGetChild(execInfo.thisVar, JSPARSE_PROTOTYPE_VAR, 0);
      JsVar *proto2 = jsvIsObject(proto1) ? jsvObjectGetChild(proto1, JSPARSE_INHERITS_VAR, 0) : 0;
      jsvUnLock(proto1);
      if (!proto2) {
        jsExceptionHere(JSET_SYNTAXERROR, "Calling 'super' outside of class");
        return 0;
      }
      JsVar *constr = jsvObjectGetChild(proto2, JSPARSE_CONSTRUCTOR_VAR, 0);
      jsvUnLock(proto2);
      return constr;
    }
    jsExceptionHere(JSET_SYNTAXERROR, "Calling 'super' outside of class");
    return 0;

  } else if (lex->tk==LEX_R_THIS) {
    JSP_ASSERT_MATCH(LEX_R_THIS);
    return jsvLockAgain( execInfo.thisVar ? execInfo.thisVar : execInfo.root );
  } else if (lex->tk==LEX_R_DELETE) {
    if (!jspCheckStackPosition()) return 0;
    return jspeFactorDelete();
  } else if (lex->tk==LEX_R_TYPEOF) {
    if (!jspCheckStackPosition()) return 0;
    return jspeFactorTypeOf();
  } else if (lex->tk==LEX_R_VOID) {
    if (!jspCheckStackPosition()) return 0;
    JSP_ASSERT_MATCH(LEX_R_VOID);
    jsvUnLock(jspeUnaryExpression());
    return 0;
  }
  JSP_MATCH(LEX_EOF);
  jsExceptionHere(JSET_SYNTAXERROR, "Unexpected end of Input\n");
  return 0;
}

NO_INLINE JsVar *__jspePostfixExpression(JsVar *a) {
  while (lex->tk==LEX_PLUSPLUS || lex->tk==LEX_MINUSMINUS) {
    int op = lex->tk;
    JSP_ASSERT_MATCH(op);
    if (JSP_SHOULD_EXECUTE) {
      JsVar *one = jsvNewFromInteger(1);
      JsVar *oldValue = jsvAsNumberAndUnLock(jsvSkipName(a)); 
      JsVar *res = jsvMathsOpSkipNames(oldValue, one, op==LEX_PLUSPLUS ? '+' : '-');
      jsvUnLock(one);

      
      jsvReplaceWith(a, res);
      jsvUnLock(res);
      
      jsvUnLock(a);
      a = oldValue;
    }
  }
  return a;
}

NO_INLINE JsVar *jspePostfixExpression() {
  JsVar *a;
  
  if (lex->tk==LEX_PLUSPLUS || lex->tk==LEX_MINUSMINUS) {
    int op = lex->tk;
    JSP_ASSERT_MATCH(op);
    a = jspePostfixExpression();
    if (JSP_SHOULD_EXECUTE) {
      JsVar *one = jsvNewFromInteger(1);
      JsVar *res = jsvMathsOpSkipNames(a, one, op==LEX_PLUSPLUS ? '+' : '-');
      jsvUnLock(one);
      
      jsvReplaceWith(a, res);
      jsvUnLock(res);
    }
  } else a = jspeFactorFunctionCall();
  return __jspePostfixExpression(a);
}

NO_INLINE JsVar *jspeUnaryExpression() {
  if (lex->tk=='!' || lex->tk=='~' || lex->tk=='-' || lex->tk=='+') {
    short tk = lex->tk;
    JSP_ASSERT_MATCH(tk);
    if (!JSP_SHOULD_EXECUTE) {
      return jspeUnaryExpression();
    }
    if (tk=='!') { 
      return jsvNewFromBool(!jsvGetBoolAndUnLock(jsvSkipNameAndUnLock(jspeUnaryExpression())));
    } else if (tk=='~') { 
      return jsvNewFromInteger(~jsvGetIntegerAndUnLock(jsvSkipNameAndUnLock(jspeUnaryExpression())));
    } else if (tk=='-') { 
      return jsvNegateAndUnLock(jspeUnaryExpression()); 
    }  else if (tk=='+') { 
      JsVar *v = jsvSkipNameAndUnLock(jspeUnaryExpression());
      JsVar *r = jsvAsNumber(v); 
      jsvUnLock(v);
      return r;
    }
    assert(0);
    return 0;
  } else return jspePostfixExpression();
}



unsigned int jspeGetBinaryExpressionPrecedence(int op) {
  switch (op) {
  case LEX_OROR: return 1; break;
  case LEX_ANDAND: return 2; break;
  case '|' : return 3; break;
  case '^' : return 4; break;
  case '&' : return 5; break;
  case LEX_EQUAL:
  case LEX_NEQUAL:
  case LEX_TYPEEQUAL:
  case LEX_NTYPEEQUAL: return 6;
  case LEX_LEQUAL:
  case LEX_GEQUAL:
  case '<':
  case '>':
  case LEX_R_INSTANCEOF: return 7;
  case LEX_R_IN: return (execInfo.execute&EXEC_FOR_INIT)?0:7;
  case LEX_LSHIFT:
  case LEX_RSHIFT:
  case LEX_RSHIFTUNSIGNED: return 8;
  case '+':
  case '-': return 9;
  case '*':
  case '/':
  case '%': return 10;
  default: return 0;
  }
}

NO_INLINE JsVar *__jspeBinaryExpression(JsVar *a, unsigned int lastPrecedence) {
  
  unsigned int precedence = jspeGetBinaryExpressionPrecedence(lex->tk);
  while (precedence && precedence>lastPrecedence) {
    int op = lex->tk;
    JSP_ASSERT_MATCH(op);

    
    
    
    if (op==LEX_ANDAND || op==LEX_OROR) {
      bool aValue = jsvGetBoolAndUnLock(jsvSkipName(a));
      if ((!aValue && op==LEX_ANDAND) || (aValue && op==LEX_OROR)) {
        
        JSP_SAVE_EXECUTE();
        jspSetNoExecute();
        jsvUnLock(__jspeBinaryExpression(jspeUnaryExpression(),precedence));
        JSP_RESTORE_EXECUTE();
      } else {
        
        jsvUnLock(a);
        a = __jspeBinaryExpression(jspeUnaryExpression(),precedence);
      }
    } else { 
      JsVar *b = __jspeBinaryExpression(jspeUnaryExpression(),precedence);
      if (JSP_SHOULD_EXECUTE) {
        if (op==LEX_R_IN) {
          JsVar *av = jsvSkipName(a); 
          JsVar *bv = jsvSkipName(b); 
          if (jsvHasChildren(bv)) { 
            av = jsvAsArrayIndexAndUnLock(av);
            JsVar *varFound = jspGetVarNamedField( bv, av, true);
            jsvUnLock2(a,varFound);
            a = jsvNewFromBool(varFound!=0);
          } else { 
            const JswSymList *syms = jswGetSymbolListForObjectProto(bv);
            if (syms) {
              JsVar *varFound = 0;
              char nameBuf[JSLEX_MAX_TOKEN_LENGTH];
              if (jsvGetString(av, nameBuf, sizeof(nameBuf)) < sizeof(nameBuf))
                varFound = jswBinarySearch(syms, bv, nameBuf);
              bool found = varFound!=0;
              jsvUnLock2(a, varFound);
              if (!found && jsvIsArrayBuffer(bv)) {
                JsVarFloat f = jsvGetFloat(av); 
                if (f==floor(f) && f>=0 && f<jsvGetArrayBufferLength(bv))
                  found = true;
              }
              a = jsvNewFromBool(found);
            } else { 
              jsExceptionHere(JSET_ERROR, "Cannot use 'in' operator to search a %t", bv);
              jsvUnLock(a);
              a = 0;
            }
          }
          jsvUnLock2(av, bv);
        } else if (op==LEX_R_INSTANCEOF) {
          bool inst = false;
          JsVar *av = jsvSkipName(a);
          JsVar *bv = jsvSkipName(b);
          if (!jsvIsFunction(bv)) {
            jsExceptionHere(JSET_ERROR, "Expecting a function on RHS in instanceof check, got %t", bv);
          } else {
            if (jsvIsObject(av) || jsvIsFunction(av)) {
              JsVar *bproto = jspGetNamedField(bv, JSPARSE_PROTOTYPE_VAR, false);
              JsVar *proto = jsvObjectGetChild(av, JSPARSE_INHERITS_VAR, 0);
              while (proto) {
                if (proto == bproto) inst=true;
                
                JsVar *childProto = jsvObjectGetChild(proto, JSPARSE_INHERITS_VAR, 0);
                jsvUnLock(proto);
                proto = childProto;
              }
              if (jspIsConstructor(bv, "Object")) inst = true;
              jsvUnLock(bproto);
            }
            if (!inst) {
              const char *name = jswGetBasicObjectName(av);
              if (name) {
                inst = jspIsConstructor(bv, name);
              }
              
              if (!inst && (jsvIsArray(av) || jsvIsArrayBuffer(av)) && jspIsConstructor(bv, "Object"))
                inst = true;
            }
          }
          jsvUnLock3(av, bv, a);
          a = jsvNewFromBool(inst);
        } else {  
          JsVar *res = jsvMathsOpSkipNames(a, b, op);
          jsvUnLock(a); a = res;
        }
      }
      jsvUnLock(b);
    }
    precedence = jspeGetBinaryExpressionPrecedence(lex->tk);
  }
  return a;
}

JsVar *jspeBinaryExpression() {
  return __jspeBinaryExpression(jspeUnaryExpression(),0);
}

NO_INLINE JsVar *__jspeConditionalExpression(JsVar *lhs) {
  if (lex->tk=='?') {
    JSP_ASSERT_MATCH('?');
    if (!JSP_SHOULD_EXECUTE) {
      
      jsvUnLock(jspeAssignmentExpression());
      JSP_MATCH(':');
      jsvUnLock(jspeAssignmentExpression());
    } else {
      bool first = jsvGetBoolAndUnLock(jsvSkipName(lhs));
      jsvUnLock(lhs);
      if (first) {
        lhs = jspeAssignmentExpression();
        JSP_MATCH(':');
        JSP_SAVE_EXECUTE();
        jspSetNoExecute();
        jsvUnLock(jspeAssignmentExpression());
        JSP_RESTORE_EXECUTE();
      } else {
        JSP_SAVE_EXECUTE();
        jspSetNoExecute();
        jsvUnLock(jspeAssignmentExpression());
        JSP_RESTORE_EXECUTE();
        JSP_MATCH(':');
        lhs = jspeAssignmentExpression();
      }
    }
  }

  return lhs;
}

JsVar *jspeConditionalExpression() {
  return __jspeConditionalExpression(jspeBinaryExpression());
}

NO_INLINE JsVar *__jspeAssignmentExpression(JsVar *lhs) {
  if (lex->tk=='=' || lex->tk==LEX_PLUSEQUAL || lex->tk==LEX_MINUSEQUAL || lex->tk==LEX_MULEQUAL || lex->tk==LEX_DIVEQUAL || lex->tk==LEX_MODEQUAL || lex->tk==LEX_ANDEQUAL || lex->tk==LEX_OREQUAL || lex->tk==LEX_XOREQUAL || lex->tk==LEX_RSHIFTEQUAL || lex->tk==LEX_LSHIFTEQUAL || lex->tk==LEX_RSHIFTUNSIGNEDEQUAL) {



    JsVar *rhs;

    int op = lex->tk;
    JSP_ASSERT_MATCH(op);
    rhs = jspeAssignmentExpression();
    rhs = jsvSkipNameAndUnLock(rhs); 

    if (JSP_SHOULD_EXECUTE && lhs) {
      if (op=='=') {
        jsvReplaceWithOrAddToRoot(lhs, rhs);
      } else {
        if (op==LEX_PLUSEQUAL) op='+';
        else if (op==LEX_MINUSEQUAL) op='-';
        else if (op==LEX_MULEQUAL) op='*';
        else if (op==LEX_DIVEQUAL) op='/';
        else if (op==LEX_MODEQUAL) op='%';
        else if (op==LEX_ANDEQUAL) op='&';
        else if (op==LEX_OREQUAL) op='|';
        else if (op==LEX_XOREQUAL) op='^';
        else if (op==LEX_RSHIFTEQUAL) op=LEX_RSHIFT;
        else if (op==LEX_LSHIFTEQUAL) op=LEX_LSHIFT;
        else if (op==LEX_RSHIFTUNSIGNEDEQUAL) op=LEX_RSHIFTUNSIGNED;
        if (op=='+' && jsvIsName(lhs)) {
          JsVar *currentValue = jsvSkipName(lhs);
          if (jsvIsBasicString(currentValue) && jsvGetRefs(currentValue)==1 && rhs!=currentValue) {
            
            JsVar *str = jsvAsString(rhs);
            jsvAppendStringVarComplete(currentValue, str);
            jsvUnLock(str);
            op = 0;
          }
          jsvUnLock(currentValue);
        }
        if (op) {
          
          JsVar *res = jsvMathsOpSkipNames(lhs,rhs,op);
          jsvReplaceWith(lhs, res);
          jsvUnLock(res);
        }
      }
    }
    jsvUnLock(rhs);
  }
  return lhs;
}


JsVar *jspeAssignmentExpression() {
  return __jspeAssignmentExpression(jspeConditionalExpression());
}


NO_INLINE JsVar *jspeExpression() {
  while (!JSP_SHOULDNT_PARSE) {
    JsVar *a = jspeAssignmentExpression();
    if (lex->tk!=',') return a;
    
    jsvCheckReferenceError(a);
    jsvUnLock(a);
    JSP_ASSERT_MATCH(',');
  }
  return 0;
}


NO_INLINE void jspeSkipBlock() {
  
  int brackets = 1;
  while (lex->tk && brackets) {
    if (lex->tk == '{') brackets++;
    else if (lex->tk == '}') {
      brackets--;
      if (!brackets) return;
    }
    JSP_ASSERT_MATCH(lex->tk);
  }
}


NO_INLINE void jspeBlockNoBrackets() {
  if (JSP_SHOULD_EXECUTE) {
    while (lex->tk && lex->tk!='}') {
      JsVar *a = jspeStatement();
      jsvCheckReferenceError(a);
      jsvUnLock(a);
      if (JSP_HAS_ERROR) {
        if (lex && !(execInfo.execute&EXEC_ERROR_LINE_REPORTED)) {
          execInfo.execute = (JsExecFlags)(execInfo.execute | EXEC_ERROR_LINE_REPORTED);
          JsVar *stackTrace = jsvObjectGetChild(execInfo.hiddenRoot, JSPARSE_STACKTRACE_VAR, JSV_STRING_0);
          if (stackTrace) {
            jsvAppendPrintf(stackTrace, "at ");
            jspAppendStackTrace(stackTrace);
            jsvUnLock(stackTrace);
          }
        }
      }
      if (JSP_SHOULDNT_PARSE)
        return;
      if (!JSP_SHOULD_EXECUTE) {
        jspeSkipBlock();
        return;
      }
    }
  } else {
    jspeSkipBlock();
  }
  return;
}


NO_INLINE void jspeBlock() {
  JSP_MATCH_WITH_RETURN('{',);
  jspeBlockNoBrackets();
  if (!JSP_SHOULDNT_PARSE) JSP_MATCH_WITH_RETURN('}',);
  return;
}

NO_INLINE JsVar *jspeBlockOrStatement() {
  if (lex->tk=='{') {
    jspeBlock();
    return 0;
  } else {
    JsVar *v = jspeStatement();
    if (lex->tk==';') JSP_ASSERT_MATCH(';');
    return v;
  }
}


NO_INLINE JsVar *jspParse() {
  JsVar *v = 0;
  while (!JSP_SHOULDNT_PARSE && lex->tk != LEX_EOF) {
    jsvUnLock(v);
    v = jspeBlockOrStatement();
    jsvCheckReferenceError(v);
  }
  return v;
}

NO_INLINE JsVar *jspeStatementVar() {
  JsVar *lastDefined = 0;
  
  assert(lex->tk==LEX_R_VAR || lex->tk==LEX_R_LET || lex->tk==LEX_R_CONST);
  jslGetNextToken();
  
  bool hasComma = true; 
  while (hasComma && lex->tk == LEX_ID && !jspIsInterrupted()) {
    JsVar *a = 0;
    if (JSP_SHOULD_EXECUTE) {
      a = jspeiFindOnTop(jslGetTokenValueAsString(), true);
      if (!a) { 
        jspSetError(false);
        return lastDefined;
      }
    }
    JSP_MATCH_WITH_CLEANUP_AND_RETURN(LEX_ID, jsvUnLock(a), lastDefined);
    
    if (lex->tk == '=') {
      JsVar *var;
      JSP_MATCH_WITH_CLEANUP_AND_RETURN('=', jsvUnLock(a), lastDefined);
      var = jsvSkipNameAndUnLock(jspeAssignmentExpression());
      if (JSP_SHOULD_EXECUTE)
        jsvReplaceWith(a, var);
      jsvUnLock(var);
    }
    jsvUnLock(lastDefined);
    lastDefined = a;
    hasComma = lex->tk == ',';
    if (hasComma) JSP_MATCH_WITH_RETURN(',', lastDefined);
  }
  return lastDefined;
}

NO_INLINE JsVar *jspeStatementIf() {
  bool cond;
  JsVar *var, *result = 0;
  JSP_ASSERT_MATCH(LEX_R_IF);
  JSP_MATCH('(');
  var = jspeExpression();
  if (JSP_SHOULDNT_PARSE) return var;
  JSP_MATCH(')');
  cond = JSP_SHOULD_EXECUTE && jsvGetBoolAndUnLock(jsvSkipName(var));
  jsvUnLock(var);

  JSP_SAVE_EXECUTE();
  if (!cond) jspSetNoExecute();
  JsExecFlags hasError = 0;
  JsVar *a = jspeBlockOrStatement();
  hasError |= execInfo.execute&EXEC_ERROR_MASK;
  if (!cond) {
    jsvUnLock(a);
    JSP_RESTORE_EXECUTE();
    execInfo.execute |= hasError;
  } else {
    result = a;
  }
  if (lex->tk==LEX_R_ELSE) {
    JSP_ASSERT_MATCH(LEX_R_ELSE);
    JSP_SAVE_EXECUTE();
    if (cond) jspSetNoExecute();
    JsVar *a = jspeBlockOrStatement();
    hasError |= execInfo.execute&EXEC_ERROR_MASK;
    if (cond) {
      jsvUnLock(a);
      JSP_RESTORE_EXECUTE();
      execInfo.execute |= hasError;
    } else {
      result = a;
    }
  }
  return result;
}

NO_INLINE JsVar *jspeStatementSwitch() {
  JSP_ASSERT_MATCH(LEX_R_SWITCH);
  JSP_MATCH('(');
  JsVar *switchOn = jspeExpression();
  JSP_SAVE_EXECUTE();
  bool execute = JSP_SHOULD_EXECUTE;
  JSP_MATCH_WITH_CLEANUP_AND_RETURN(')', jsvUnLock(switchOn), 0);
  
  if (!execute) { jsvUnLock(switchOn); jspeBlock(); return 0; }
  JSP_MATCH_WITH_CLEANUP_AND_RETURN('{', jsvUnLock(switchOn), 0);

  bool executeDefault = true;
  if (execute) execInfo.execute=EXEC_NO|EXEC_IN_SWITCH;
  while (lex->tk==LEX_R_CASE) {
    JSP_MATCH_WITH_CLEANUP_AND_RETURN(LEX_R_CASE, jsvUnLock(switchOn), 0);
    JsExecFlags oldFlags = execInfo.execute;
    if (execute) execInfo.execute=EXEC_YES|EXEC_IN_SWITCH;
    JsVar *test = jspeAssignmentExpression();
    execInfo.execute = oldFlags|EXEC_IN_SWITCH;;
    JSP_MATCH_WITH_CLEANUP_AND_RETURN(':', jsvUnLock2(switchOn, test), 0);
    bool cond = false;
    if (execute)
      cond = jsvGetBoolAndUnLock(jsvMathsOpSkipNames(switchOn, test, LEX_TYPEEQUAL));
    if (cond) executeDefault = false;
    jsvUnLock(test);
    if (cond && (execInfo.execute&EXEC_RUN_MASK)==EXEC_NO)
      execInfo.execute=EXEC_YES|EXEC_IN_SWITCH;
    while (!JSP_SHOULDNT_PARSE && lex->tk!=LEX_EOF && lex->tk!=LEX_R_CASE && lex->tk!=LEX_R_DEFAULT && lex->tk!='}')
      jsvUnLock(jspeBlockOrStatement());
    oldExecute |= execInfo.execute & (EXEC_ERROR_MASK|EXEC_RETURN); 
  }
  jsvUnLock(switchOn);
  if (execute && (execInfo.execute&EXEC_RUN_MASK)==EXEC_BREAK) {
    execInfo.execute=EXEC_YES|EXEC_IN_SWITCH;
  } else {
    executeDefault = true;
  }
  JSP_RESTORE_EXECUTE();

  if (lex->tk==LEX_R_DEFAULT) {
    JSP_ASSERT_MATCH(LEX_R_DEFAULT);
    JSP_MATCH(':');
    JSP_SAVE_EXECUTE();
    if (!executeDefault) jspSetNoExecute();
    else execInfo.execute |= EXEC_IN_SWITCH;
    while (!JSP_SHOULDNT_PARSE && lex->tk!=LEX_EOF && lex->tk!='}' && lex->tk!=LEX_R_CASE)
      jsvUnLock(jspeBlockOrStatement());
    oldExecute |= execInfo.execute & (EXEC_ERROR_MASK|EXEC_RETURN); 
    execInfo.execute = execInfo.execute & (JsExecFlags)~EXEC_BREAK;
    JSP_RESTORE_EXECUTE();
  }
  if (lex->tk==LEX_R_CASE) {
    jsExceptionHere(JSET_SYNTAXERROR, "Espruino doesn't support CASE after DEFAULT");
    return 0;
  }
  JSP_MATCH('}');
  return 0;
}


static NO_INLINE bool jspeCheckBreakContinue() {
  if (execInfo.execute & EXEC_CONTINUE)
    execInfo.execute = (execInfo.execute & ~EXEC_RUN_MASK) | EXEC_YES;
  else if (execInfo.execute & EXEC_BREAK) {
    execInfo.execute = (execInfo.execute & ~EXEC_RUN_MASK) | EXEC_YES;
    return true;
  }
  return false;
}

NO_INLINE JsVar *jspeStatementDoOrWhile(bool isWhile) {
  JsVar *cond;
  bool loopCond = true; 
  bool hasHadBreak = false;
  JslCharPos whileCondStart;
  
  

  bool wasInLoop = (execInfo.execute&EXEC_IN_LOOP)!=0;
  JslCharPos whileBodyStart;
  if (isWhile) { 
    JSP_ASSERT_MATCH(LEX_R_WHILE);
    jslCharPosFromLex(&whileCondStart);
    JSP_MATCH_WITH_CLEANUP_AND_RETURN('(',jslCharPosFree(&whileCondStart);,0);
    cond = jspeExpression();
    loopCond = JSP_SHOULD_EXECUTE && jsvGetBoolAndUnLock(jsvSkipName(cond));
    jsvUnLock(cond);
    jslCharPosFromLex(&whileBodyStart);
    JSP_MATCH_WITH_CLEANUP_AND_RETURN(')',jslCharPosFree(&whileBodyStart);jslCharPosFree(&whileCondStart);,0);
  } else {
    jslCharPosFromLex(&whileBodyStart);
    JSP_MATCH_WITH_CLEANUP_AND_RETURN(LEX_R_DO, jslCharPosFree(&whileBodyStart);,0);
  }
  JSP_SAVE_EXECUTE();
  
  if (!loopCond) jspSetNoExecute();
  execInfo.execute |= EXEC_IN_LOOP;
  jsvUnLock(jspeBlockOrStatement());
  if (!wasInLoop) execInfo.execute &= (JsExecFlags)~EXEC_IN_LOOP;

  hasHadBreak |= jspeCheckBreakContinue();
  if (!loopCond) JSP_RESTORE_EXECUTE();

  if (!isWhile) { 
    JSP_MATCH_WITH_CLEANUP_AND_RETURN(LEX_R_WHILE,jslCharPosFree(&whileBodyStart);,0);
    jslCharPosFromLex(&whileCondStart);
    JSP_MATCH_WITH_CLEANUP_AND_RETURN('(',jslCharPosFree(&whileBodyStart);jslCharPosFree(&whileCondStart);,0);
    cond = jspeExpression();
    loopCond = JSP_SHOULD_EXECUTE && jsvGetBoolAndUnLock(jsvSkipName(cond));
    jsvUnLock(cond);
    JSP_MATCH_WITH_CLEANUP_AND_RETURN(')',jslCharPosFree(&whileBodyStart);jslCharPosFree(&whileCondStart);,0);
  }

  JslCharPos whileBodyEnd;
  jslCharPosNew(&whileBodyEnd, lex->sourceVar, lex->tokenStart);

  int loopCount = 0;
  while (!hasHadBreak && loopCond  && loopCount<JSPARSE_MAX_LOOP_ITERATIONS  ) {



    if (isWhile || loopCount) { 
      jslSeekToP(&whileCondStart);
      cond = jspeExpression();
      loopCond = JSP_SHOULD_EXECUTE && jsvGetBoolAndUnLock(jsvSkipName(cond));
      jsvUnLock(cond);
    }
    if (loopCond) {
      jslSeekToP(&whileBodyStart);
      execInfo.execute |= EXEC_IN_LOOP;
      jspDebuggerLoopIfCtrlC();
      jsvUnLock(jspeBlockOrStatement());
      if (!wasInLoop) execInfo.execute &= (JsExecFlags)~EXEC_IN_LOOP;
      hasHadBreak |= jspeCheckBreakContinue();
    }
    loopCount++;
  }
  jslSeekToP(&whileBodyEnd);
  jslCharPosFree(&whileCondStart);
  jslCharPosFree(&whileBodyStart);
  jslCharPosFree(&whileBodyEnd);

  if (loopCount > JSPARSE_MAX_LOOP_ITERATIONS) {
    jsExceptionHere(JSET_ERROR, "WHILE Loop exceeded the maximum number of iterations (" STRINGIFY(JSPARSE_MAX_LOOP_ITERATIONS) ")");
  }

  return 0;
}

NO_INLINE JsVar *jspGetBuiltinPrototype(JsVar *obj) {
  if (jsvIsArray(obj)) {
    JsVar *v = jspFindPrototypeFor("Array");
    if (v) return v;
  }
  if (jsvIsObject(obj) || jsvIsArray(obj)) {
    JsVar *v = jspFindPrototypeFor("Object");
    if (v==obj) { 
      jsvUnLock(v);
      v = 0;
    }
    return v;
  }
  return 0;
}

NO_INLINE JsVar *jspeStatementFor() {
  JSP_ASSERT_MATCH(LEX_R_FOR);
  JSP_MATCH('(');
  bool wasInLoop = (execInfo.execute&EXEC_IN_LOOP)!=0;
  execInfo.execute |= EXEC_FOR_INIT;
  
  JsVar *forStatement = 0;
  
  if (lex->tk != ';')
    forStatement = jspeStatement();
  if (jspIsInterrupted()) {
    jsvUnLock(forStatement);
    return 0;
  }
  execInfo.execute &= (JsExecFlags)~EXEC_FOR_INIT;

  if (lex->tk == LEX_R_IN || lex->tk == LEX_R_OF) {
    bool isForOf = lex->tk == LEX_R_OF;
    
    
    if (JSP_SHOULD_EXECUTE && !jsvIsName(forStatement)) {
      jsvUnLock(forStatement);
      jsExceptionHere(JSET_ERROR, "for(a %s b) - 'a' must be a variable name, not %t", isForOf?"of":"in", forStatement);
      return 0;
    }

    JSP_ASSERT_MATCH(lex->tk); 
    JsVar *array = jsvSkipNameAndUnLock(jspeExpression());

    JslCharPos forBodyStart;
    jslCharPosFromLex(&forBodyStart);
    JSP_MATCH_WITH_CLEANUP_AND_RETURN(')', jsvUnLock2(forStatement, array);jslCharPosFree(&forBodyStart), 0);

    
    
    JSP_SAVE_EXECUTE();
    jspSetNoExecute();
    execInfo.execute |= EXEC_IN_LOOP;
    jsvUnLock(jspeBlockOrStatement());
    JslCharPos forBodyEnd;
    jslCharPosNew(&forBodyEnd, lex->sourceVar, lex->tokenStart);
    if (!wasInLoop) execInfo.execute &= (JsExecFlags)~EXEC_IN_LOOP;
    JSP_RESTORE_EXECUTE();
    
    if (JSP_SHOULD_EXECUTE) {
      if (jsvIsIterable(array)) {
        JsvIsInternalChecker checkerFunction = jsvGetInternalFunctionCheckerFor(array);
        JsVar *foundPrototype = 0;
        if (!isForOf) 
          foundPrototype = jspGetBuiltinPrototype(array);

        JsvIterator it;
        jsvIteratorNew(&it, array, isForOf ? JSIF_EVERY_ARRAY_ELEMENT :
             JSIF_DEFINED_ARRAY_ElEMENTS);
        bool hasHadBreak = false;
        while (JSP_SHOULD_EXECUTE && jsvIteratorHasElement(&it) && !hasHadBreak) {
          JsVar *loopIndexVar = jsvIteratorGetKey(&it);
          bool ignore = false;
          if (checkerFunction && checkerFunction(loopIndexVar)) {
            ignore = true;
            if (jsvIsString(loopIndexVar) && jsvIsStringEqual(loopIndexVar, JSPARSE_INHERITS_VAR))
              foundPrototype = jsvSkipName(loopIndexVar);
          }
          if (!ignore) {
            JsVar *iteratorValue;
            if (isForOf) { 
              iteratorValue = jsvIteratorGetValue(&it);
            } else { 
              iteratorValue = jsvIsName(loopIndexVar) ? jsvCopyNameOnly(loopIndexVar, false, false) :
                  loopIndexVar;
              assert(jsvGetRefs(iteratorValue)==0);
            }
            if (isForOf || iteratorValue) { 
              assert(!jsvIsName(iteratorValue));
              jsvReplaceWithOrAddToRoot(forStatement, iteratorValue);
              if (iteratorValue!=loopIndexVar) jsvUnLock(iteratorValue);

              jslSeekToP(&forBodyStart);
              execInfo.execute |= EXEC_IN_LOOP;
              jspDebuggerLoopIfCtrlC();
              jsvUnLock(jspeBlockOrStatement());
              if (!wasInLoop) execInfo.execute &= (JsExecFlags)~EXEC_IN_LOOP;

              hasHadBreak |= jspeCheckBreakContinue();
            }
          }
          jsvIteratorNext(&it);
          jsvUnLock(loopIndexVar);
          
          if (!jsvIteratorHasElement(&it) && !isForOf && foundPrototype) {
            jsvIteratorFree(&it);
            JsVar *iterable = foundPrototype;
            jsvIteratorNew(&it, iterable, JSIF_DEFINED_ARRAY_ElEMENTS);
            checkerFunction = jsvGetInternalFunctionCheckerFor(iterable);
            foundPrototype = jspGetBuiltinPrototype(iterable);
            jsvUnLock(iterable);
          }
        }
        assert(!foundPrototype);
        jsvIteratorFree(&it);
      } else if (!jsvIsUndefined(array)) {
        jsExceptionHere(JSET_ERROR, "FOR loop can only iterate over Arrays, Strings or Objects, not %t", array);
      }
    }
    jslSeekToP(&forBodyEnd);
    jslCharPosFree(&forBodyStart);
    jslCharPosFree(&forBodyEnd);

    jsvUnLock2(forStatement, array);

  if (false) {

  } else { 

    int loopCount = JSPARSE_MAX_LOOP_ITERATIONS;

    bool loopCond = true;
    bool hasHadBreak = false;

    jsvUnLock(forStatement);
    JslCharPos forCondStart;
    jslCharPosFromLex(&forCondStart);
    JSP_MATCH_WITH_CLEANUP_AND_RETURN(';',jslCharPosFree(&forCondStart);,0);

    if (lex->tk != ';') {
      JsVar *cond = jspeExpression(); 
      loopCond = JSP_SHOULD_EXECUTE && jsvGetBoolAndUnLock(jsvSkipName(cond));
      jsvUnLock(cond);
    }
    JslCharPos forIterStart;
    jslCharPosFromLex(&forIterStart);
    JSP_MATCH_WITH_CLEANUP_AND_RETURN(';',jslCharPosFree(&forCondStart);jslCharPosFree(&forIterStart);,0);
    if (lex->tk != ')')  { 
      JSP_SAVE_EXECUTE();
      jspSetNoExecute();
      jsvUnLock(jspeExpression()); 
      JSP_RESTORE_EXECUTE();
    }
    JslCharPos forBodyStart;
    jslSkipWhiteSpace();
    jslCharPosFromLex(&forBodyStart); 
    JSP_MATCH_WITH_CLEANUP_AND_RETURN(')',jslCharPosFree(&forCondStart);jslCharPosFree(&forIterStart);jslCharPosFree(&forBodyStart);,0);

    JSP_SAVE_EXECUTE();
    if (!loopCond) jspSetNoExecute();
    execInfo.execute |= EXEC_IN_LOOP;
    jsvUnLock(jspeBlockOrStatement());
    JslCharPos forBodyEnd;
    jslSkipWhiteSpace();
    jslCharPosNew(&forBodyEnd, lex->sourceVar, lex->tokenStart);
    if (!wasInLoop) execInfo.execute &= (JsExecFlags)~EXEC_IN_LOOP;
    if (loopCond || !JSP_SHOULD_EXECUTE) {
      hasHadBreak |= jspeCheckBreakContinue();
    }
    if (!loopCond) JSP_RESTORE_EXECUTE();
    if (loopCond) {
      jslSeekToP(&forIterStart);
      if (lex->tk != ')') jsvUnLock(jspeExpression());
    }
    while (!hasHadBreak && JSP_SHOULD_EXECUTE && loopCond  && loopCount-->0  ) {



      jslSeekToP(&forCondStart);
      ;
      if (lex->tk == ';') {
        loopCond = true;
      } else {
        JsVar *cond = jspeExpression();
        loopCond = jsvGetBoolAndUnLock(jsvSkipName(cond));
        jsvUnLock(cond);
      }
      if (JSP_SHOULD_EXECUTE && loopCond) {
        jslSeekToP(&forBodyStart);
        execInfo.execute |= EXEC_IN_LOOP;
        jspDebuggerLoopIfCtrlC();
        jsvUnLock(jspeBlockOrStatement());
        if (!wasInLoop) execInfo.execute &= (JsExecFlags)~EXEC_IN_LOOP;
        hasHadBreak |= jspeCheckBreakContinue();
      }
      if (JSP_SHOULD_EXECUTE && loopCond && !hasHadBreak) {
        jslSeekToP(&forIterStart);
        if (lex->tk != ')') jsvUnLock(jspeExpression());
      }
    }
    jslSeekToP(&forBodyEnd);

    jslCharPosFree(&forCondStart);
    jslCharPosFree(&forIterStart);
    jslCharPosFree(&forBodyStart);
    jslCharPosFree(&forBodyEnd);


    if (loopCount<=0) {
      jsExceptionHere(JSET_ERROR, "FOR Loop exceeded the maximum number of iterations ("STRINGIFY(JSPARSE_MAX_LOOP_ITERATIONS)")");
    }

  }
  return 0;
}

NO_INLINE JsVar *jspeStatementTry() {
  
  JSP_ASSERT_MATCH(LEX_R_TRY);
  bool shouldExecuteBefore = JSP_SHOULD_EXECUTE;
  jspeBlock();
  bool hadException = shouldExecuteBefore && ((execInfo.execute & EXEC_EXCEPTION)!=0);

  bool hadCatch = false;
  if (lex->tk == LEX_R_CATCH) {
    JSP_ASSERT_MATCH(LEX_R_CATCH);
    hadCatch = true;
    JSP_MATCH('(');
    JsVar *scope = 0;
    JsVar *exceptionVar = 0;
    if (hadException) {
      scope = jsvNewObject();
      if (scope)
        exceptionVar = jsvFindChildFromString(scope, jslGetTokenValueAsString(), true);
    }
    JSP_MATCH_WITH_CLEANUP_AND_RETURN(LEX_ID,jsvUnLock2(scope,exceptionVar),0);
    JSP_MATCH_WITH_CLEANUP_AND_RETURN(')',jsvUnLock2(scope,exceptionVar),0);
    if (exceptionVar) {
      
      JsVar *exception = jspGetException();
      if (exception) {
        jsvSetValueOfName(exceptionVar, exception);
        jsvUnLock(exception);
      }
      
      execInfo.execute = execInfo.execute & (JsExecFlags)~(EXEC_EXCEPTION|EXEC_ERROR_LINE_REPORTED);
      jsvUnLock(exceptionVar);
    }

    if (shouldExecuteBefore && !hadException) {
      JSP_SAVE_EXECUTE();
      jspSetNoExecute();
      jspeBlock();
      JSP_RESTORE_EXECUTE();
    } else {
      if (!scope || jspeiAddScope(scope)) {
        jspeBlock();
        if (scope) jspeiRemoveScope();
      }
    }
    jsvUnLock(scope);
  }
  if (lex->tk == LEX_R_FINALLY || (!hadCatch && ((execInfo.execute&(EXEC_ERROR|EXEC_INTERRUPTED))==0))) {
    JSP_MATCH(LEX_R_FINALLY);
    
    if (hadException) execInfo.execute = execInfo.execute & (JsExecFlags)~EXEC_EXCEPTION;
    jspeBlock();
    
    if (hadException && !hadCatch) execInfo.execute = execInfo.execute | EXEC_EXCEPTION;
  }
  return 0;
}

NO_INLINE JsVar *jspeStatementReturn() {
  JsVar *result = 0;
  JSP_ASSERT_MATCH(LEX_R_RETURN);
  if (lex->tk != ';' && lex->tk != '}') {
    
    result = jsvSkipNameAndUnLock(jspeExpression());
  }
  if (JSP_SHOULD_EXECUTE) {
    JsVar *resultVar = jspeiFindInScopes(JSPARSE_RETURN_VAR);
    if (resultVar) {
      jsvReplaceWith(resultVar, result);
      jsvUnLock(resultVar);
      execInfo.execute |= EXEC_RETURN; 
    } else {
      jsExceptionHere(JSET_SYNTAXERROR, "RETURN statement, but not in a function.\n");
    }
  }
  jsvUnLock(result);
  return 0;
}

NO_INLINE JsVar *jspeStatementThrow() {
  JsVar *result = 0;
  JSP_ASSERT_MATCH(LEX_R_THROW);
  result = jsvSkipNameAndUnLock(jspeExpression());
  if (JSP_SHOULD_EXECUTE) {
    jspSetException(result); 
  }
  jsvUnLock(result);
  return 0;
}

NO_INLINE JsVar *jspeStatementFunctionDecl(bool isClass) {
  JsVar *funcName = 0;
  JsVar *funcVar;


  JSP_ASSERT_MATCH(isClass ? LEX_R_CLASS : LEX_R_FUNCTION);

  JSP_ASSERT_MATCH(LEX_R_FUNCTION);


  bool actuallyCreateFunction = JSP_SHOULD_EXECUTE;
  if (actuallyCreateFunction) {
    funcName = jsvMakeIntoVariableName(jslGetTokenValueAsVar(), 0);
    if (!funcName) { 
      return 0;
    }
  }
  JSP_MATCH_WITH_CLEANUP_AND_RETURN(LEX_ID, jsvUnLock(funcName), 0);

  funcVar = isClass ? jspeClassDefinition(false) : jspeFunctionDefinition(false);

  funcVar = jspeFunctionDefinition(false);

  if (actuallyCreateFunction) {
    
    
    JsVar *existingName = jspeiFindNameOnTop(funcName, true);
    JsVar *existingFunc = jsvSkipName(existingName);
    if (jsvIsFunction(existingFunc)) {
      
      funcVar = jsvSkipNameAndUnLock(funcVar);
      jswrap_function_replaceWith(existingFunc, funcVar);
    } else {
      jsvReplaceWith(existingName, funcVar);
    }
    jsvUnLock(funcName);
    funcName = existingName;
    jsvUnLock(existingFunc);
    
  }
  jsvUnLock(funcVar);
  return funcName;
}

NO_INLINE JsVar *jspeStatement() {

  if (execInfo.execute&EXEC_DEBUGGER_NEXT_LINE && lex->tk!=';' && JSP_SHOULD_EXECUTE) {

    lex->tokenLastStart = lex->tokenStart;
    jsiDebuggerLoop();
  }

  if (lex->tk==LEX_ID || lex->tk==LEX_INT || lex->tk==LEX_FLOAT || lex->tk==LEX_STR || lex->tk==LEX_TEMPLATE_LITERAL || lex->tk==LEX_REGEX || lex->tk==LEX_R_NEW || lex->tk==LEX_R_NULL || lex->tk==LEX_R_UNDEFINED || lex->tk==LEX_R_TRUE || lex->tk==LEX_R_FALSE || lex->tk==LEX_R_THIS || lex->tk==LEX_R_DELETE || lex->tk==LEX_R_TYPEOF || lex->tk==LEX_R_VOID || lex->tk==LEX_R_SUPER || lex->tk==LEX_PLUSPLUS || lex->tk==LEX_MINUSMINUS || lex->tk=='!' || lex->tk=='-' || lex->tk=='+' || lex->tk=='~' || lex->tk=='[' || lex->tk=='(') {






















    
    return jspeExpression();
  } else if (lex->tk=='{') {
    
    if (!jspCheckStackPosition()) return 0;
    jspeBlock();
    return 0;
  } else if (lex->tk==';') {
    
    JSP_ASSERT_MATCH(';');
    return 0;
  } else if (lex->tk==LEX_R_VAR || lex->tk==LEX_R_LET || lex->tk==LEX_R_CONST) {

    return jspeStatementVar();
  } else if (lex->tk==LEX_R_IF) {
    return jspeStatementIf();
  } else if (lex->tk==LEX_R_DO) {
    return jspeStatementDoOrWhile(false);
  } else if (lex->tk==LEX_R_WHILE) {
    return jspeStatementDoOrWhile(true);
  } else if (lex->tk==LEX_R_FOR) {
    return jspeStatementFor();
  } else if (lex->tk==LEX_R_TRY) {
    return jspeStatementTry();
  } else if (lex->tk==LEX_R_RETURN) {
    return jspeStatementReturn();
  } else if (lex->tk==LEX_R_THROW) {
    return jspeStatementThrow();
  } else if (lex->tk==LEX_R_FUNCTION) {
    return jspeStatementFunctionDecl(false);

  } else if (lex->tk==LEX_R_CLASS) {
      return jspeStatementFunctionDecl(true);

  } else if (lex->tk==LEX_R_CONTINUE) {
    JSP_ASSERT_MATCH(LEX_R_CONTINUE);
    if (JSP_SHOULD_EXECUTE) {
      if (!(execInfo.execute & EXEC_IN_LOOP))
        jsExceptionHere(JSET_SYNTAXERROR, "CONTINUE statement outside of FOR or WHILE loop");
      else execInfo.execute = (execInfo.execute & (JsExecFlags)~EXEC_RUN_MASK) | EXEC_CONTINUE;
    }
  } else if (lex->tk==LEX_R_BREAK) {
    JSP_ASSERT_MATCH(LEX_R_BREAK);
    if (JSP_SHOULD_EXECUTE) {
      if (!(execInfo.execute & (EXEC_IN_LOOP|EXEC_IN_SWITCH)))
        jsExceptionHere(JSET_SYNTAXERROR, "BREAK statement outside of SWITCH, FOR or WHILE loop");
      else execInfo.execute = (execInfo.execute & (JsExecFlags)~EXEC_RUN_MASK) | EXEC_BREAK;
    }
  } else if (lex->tk==LEX_R_SWITCH) {
    return jspeStatementSwitch();
  } else if (lex->tk==LEX_R_DEBUGGER) {
    JSP_ASSERT_MATCH(LEX_R_DEBUGGER);

    if (JSP_SHOULD_EXECUTE)
      jsiDebuggerLoop();

  } else JSP_MATCH(LEX_EOF);
  return 0;
}



JsVar *jspNewBuiltin(const char *instanceOf) {
  JsVar *objFunc = jswFindBuiltInFunction(0, instanceOf);
  if (!objFunc) return 0; 
  return objFunc;
}


NO_INLINE JsVar *jspNewPrototype(const char *instanceOf) {
  JsVar *objFuncName = jsvFindChildFromString(execInfo.root, instanceOf, true);
  if (!objFuncName) 
    return 0;

  JsVar *objFunc = jsvSkipName(objFuncName);
  if (!objFunc) {
    objFunc = jspNewBuiltin(instanceOf);
    if (!objFunc) { 
      jsvUnLock(objFuncName);
      return 0;
    }

    
    jsvSetValueOfName(objFuncName, objFunc);
  }

  JsVar *prototypeName = jsvFindChildFromString(objFunc, JSPARSE_PROTOTYPE_VAR, true);
  jspEnsureIsPrototype(objFunc, prototypeName); 
  jsvUnLock2(objFunc, objFuncName);

  return prototypeName;
}


NO_INLINE JsVar *jspNewObject(const char *name, const char *instanceOf) {
  JsVar *prototypeName = jspNewPrototype(instanceOf);

  JsVar *obj = jsvNewObject();
  if (!obj) { 
    jsvUnLock(prototypeName);
    return 0;
  }
  if (name) {
    
    
    IOEventFlags device = jshFromDeviceString(name);
    if (device!=EV_NONE) {
      obj->varData.str[0] = 'D';
      obj->varData.str[1] = 'E';
      obj->varData.str[2] = 'V';
      obj->varData.str[3] = (char)device;
    }

  }
  
  JsVar *prototypeVar = jsvSkipName(prototypeName);
  jsvUnLock3(jsvAddNamedChild(obj, prototypeVar, JSPARSE_INHERITS_VAR), prototypeVar, prototypeName);prototypeName=0;

  if (name) {
    JsVar *objName = jsvFindChildFromString(execInfo.root, name, true);
    if (objName) jsvSetValueOfName(objName, obj);
    jsvUnLock(obj);
    if (!objName) { 
      return 0;
    }
    return objName;
  } else return obj;
}


bool jspIsConstructor(JsVar *constructor, const char *constructorName) {
  JsVar *objFunc = jsvObjectGetChild(execInfo.root, constructorName, 0);
  if (!objFunc) return false;
  bool isConstructor = objFunc == constructor;
  jsvUnLock(objFunc);
  return isConstructor;
}


JsVar *jspGetPrototype(JsVar *object) {
  if (!jsvIsObject(object)) return 0;
  JsVar *proto = jsvObjectGetChild(object, JSPARSE_INHERITS_VAR, 0);
  if (jsvIsObject(proto))
    return proto;
  jsvUnLock(proto);
  return 0;
}


JsVar *jspGetConstructor(JsVar *object) {
  JsVar *proto = jspGetPrototype(object);
  if (proto) {
    JsVar *constr = jsvObjectGetChild(proto, JSPARSE_CONSTRUCTOR_VAR, 0);
    if (jsvIsFunction(constr)) {
      jsvUnLock(proto);
      return constr;
    }
    jsvUnLock2(constr, proto);
  }
  return 0;
}



void jspSoftInit() {
  execInfo.root = jsvFindOrCreateRoot();
  
  execInfo.hiddenRoot = jsvObjectGetChild(execInfo.root, JS_HIDDEN_CHAR_STR, JSV_OBJECT);
  execInfo.execute = EXEC_YES;
}

void jspSoftKill() {
  jsvUnLock(execInfo.scopesVar);
  execInfo.scopesVar = 0;
  jsvUnLock(execInfo.hiddenRoot);
  execInfo.hiddenRoot = 0;
  jsvUnLock(execInfo.root);
  execInfo.root = 0;
  
}

void jspInit() {
  jspSoftInit();
}

void jspKill() {
  jspSoftKill();
  
  JsVar *r = jsvFindOrCreateRoot();
  jsvUnRef(r);
  jsvUnLock(r);
}


JsVar *jspEvaluateExpressionVar(JsVar *str) {
  JsLex lex;

  assert(jsvIsString(str));
  JsLex *oldLex = jslSetLex(&lex);
  jslInit(str);

  lex.lineNumberOffset = oldLex->lineNumberOffset;


  
  JsVar *v = jspeExpression();
  jslKill();
  jslSetLex(oldLex);

  return jsvSkipNameAndUnLock(v);
}


JsVar *jspEvaluateVar(JsVar *str, JsVar *scope, uint16_t lineNumberOffset) {
  JsLex lex;

  assert(jsvIsString(str));
  JsLex *oldLex = jslSetLex(&lex);
  jslInit(str);

  lex.lineNumberOffset = lineNumberOffset;



  JsExecInfo oldExecInfo = execInfo;
  execInfo.execute = EXEC_YES;
  if (scope) {
    
    execInfo.scopesVar = 0;
    if (scope!=execInfo.root) jspeiAddScope(scope); 
  }

  
  JsVar *v = jspParse();
  
  if (scope) jspeiClearScopes();
  jslKill();
  jslSetLex(oldLex);

  
  oldExecInfo.execute |= execInfo.execute & EXEC_PERSIST;
  execInfo = oldExecInfo;

  
  return jsvSkipNameAndUnLock(v);
}

JsVar *jspEvaluate(const char *str, bool stringIsStatic) {

  
  JsVar *evCode;
  if (stringIsStatic)
    evCode = jsvNewNativeString((char*)str, strlen(str));
  else evCode = jsvNewFromString(str);
  if (!evCode) return 0;

  JsVar *v = 0;
  if (!jsvIsMemoryFull())
    v = jspEvaluateVar(evCode, 0, 0);
  jsvUnLock(evCode);

  return v;
}

JsVar *jspExecuteJSFunction(const char *jsCode, JsVar *thisArg, int argCount, JsVar **argPtr) {
  JsVar *fn = jspEvaluate(jsCode,true);
  JsVar *result = jspExecuteFunction(fn,thisArg,argCount,argPtr);
  jsvUnLock(fn);
  return result;
}

JsVar *jspExecuteFunction(JsVar *func, JsVar *thisArg, int argCount, JsVar **argPtr) {
  JsExecInfo oldExecInfo = execInfo;
  execInfo.scopesVar = 0;
  execInfo.execute = EXEC_YES;
  execInfo.thisVar = 0;
  JsVar *result = jspeFunctionCall(func, 0, thisArg, false, argCount, argPtr);
  
  jspeiClearScopes();
  
  oldExecInfo.execute |= execInfo.execute&EXEC_PERSIST;
  jspeiClearScopes();
  execInfo = oldExecInfo;

  return result;
}



JsVar *jspEvaluateModule(JsVar *moduleContents) {
  assert(jsvIsString(moduleContents) || jsvIsFunction(moduleContents));
  if (jsvIsFunction(moduleContents)) {
    moduleContents = jsvObjectGetChild(moduleContents,JSPARSE_FUNCTION_CODE_NAME,0);
    if (!jsvIsString(moduleContents)) {
      jsvUnLock(moduleContents);
      return 0;
    }
  } else jsvLockAgain(moduleContents);
  JsVar *scope = jsvNewObject();
  JsVar *scopeExports = jsvNewObject();
  if (!scope || !scopeExports) { 
    jsvUnLock3(scope, scopeExports, moduleContents);
    return 0;
  }
  JsVar *exportsName = jsvAddNamedChild(scope, scopeExports, "exports");
  jsvUnLock2(scopeExports, jsvAddNamedChild(scope, scope, "module"));

  JsExecFlags oldExecute = execInfo.execute;
  JsVar *oldThisVar = execInfo.thisVar;
  execInfo.thisVar = scopeExports; 
  jsvUnLock(jspEvaluateVar(moduleContents, scope, 0));
  execInfo.thisVar = oldThisVar;
  execInfo.execute = oldExecute; 

  jsvUnLock2(moduleContents, scope);
  return jsvSkipNameAndUnLock(exportsName);
}


JsVar *jspGetPrototypeOwner(JsVar *proto) {
  if (jsvIsObject(proto) || jsvIsArray(proto)) {
    return jsvSkipNameAndUnLock(jsvObjectGetChild(proto, JSPARSE_CONSTRUCTOR_VAR, 0));
  }
  return 0;
}
