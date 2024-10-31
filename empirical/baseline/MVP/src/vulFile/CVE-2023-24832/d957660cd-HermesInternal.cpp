
























namespace hermes {
namespace vm {


static inline CallResult<Handle<SymbolID>> symbolForCStr( Runtime &rt, const char *s) {

  return rt.getIdentifierTable().getSymbolHandle(rt, ASCIIRef{s, strlen(s)});
}


CallResult<HermesValue> hermesInternalDetachArrayBuffer(void *, Runtime &runtime, NativeArgs args) {
  auto buffer = args.dyncastArg<JSArrayBuffer>(0);
  if (!buffer) {
    return runtime.raiseTypeError( "Cannot use detachArrayBuffer on something which " "is not an ArrayBuffer foo");

  }
  if (LLVM_UNLIKELY( JSArrayBuffer::detach(runtime, buffer) == ExecutionStatus::EXCEPTION))
    return ExecutionStatus::EXCEPTION;
  
  return HermesValue::encodeUndefinedValue();
}

CallResult<HermesValue> hermesInternalGetEpilogues(void *, Runtime &runtime, NativeArgs args) {
  
  auto eps = runtime.getEpilogues();
  auto outerLen = eps.size();
  auto outerResult = JSArray::create(runtime, outerLen, outerLen);

  if (outerResult == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto outer = *outerResult;
  if (outer->setStorageEndIndex(outer, runtime, outerLen) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  
  for (unsigned i = 0; i < outerLen; ++i) {
    auto innerLen = eps[i].size();
    if (innerLen != 0) {
      auto result = Uint8Array::allocate(runtime, innerLen);
      if (result == ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
      auto ta = result.getValue();
      std::memcpy(ta->begin(runtime), eps[i].begin(), innerLen);
      const auto shv = SmallHermesValue::encodeObjectValue(*ta, runtime);
      JSArray::unsafeSetExistingElementAt(*outer, runtime, i, shv);
    }
  }
  return HermesValue::encodeObjectValue(*outer);
}



CallResult<HermesValue> hermesInternalGetWeakSize(void *, Runtime &runtime, NativeArgs args) {
  if (auto M = args.dyncastArg<JSWeakMap>(0)) {
    return HermesValue::encodeNumberValue( JSWeakMap::debugFreeSlotsAndGetSize(runtime, *M));
  }

  if (auto S = args.dyncastArg<JSWeakSet>(0)) {
    return HermesValue::encodeNumberValue( JSWeakSet::debugFreeSlotsAndGetSize(runtime, *S));
  }

  return runtime.raiseTypeError( "getWeakSize can only be called on a WeakMap/WeakSet");
}

namespace {








template <typename AP> ExecutionStatus populateInstrumentedStats(Runtime &runtime, AP addProp) {
  constexpr bool addPropTakesValue = std::is_invocable_v<AP, const char *, double>;
  constexpr bool addPropGeneratesValue = std::is_invocable_v<AP, const char *>;
  static_assert( addPropGeneratesValue || addPropTakesValue, "invalid addProp prototype");

  
  
  


















  auto &heap = runtime.getHeap();
  GCBase::HeapInfo info;
  heap.getHeapInfo(info);

  
  
  PASSTHROUGH_PROP("js_hostFunctionTime");
  PASSTHROUGH_PROP("js_hostFunctionCPUTime");
  PASSTHROUGH_PROP("js_hostFunctionCount");
  PASSTHROUGH_PROP("js_evaluateJSTime");
  PASSTHROUGH_PROP("js_evaluateJSCPUTime");
  PASSTHROUGH_PROP("js_evaluateJSCount");
  PASSTHROUGH_PROP("js_incomingFunctionTime");
  PASSTHROUGH_PROP("js_incomingFunctionCPUTime");
  PASSTHROUGH_PROP("js_incomingFunctionCount");
  ADD_PROP("js_VMExperiments", runtime.getVMExperimentFlags());
  PASSTHROUGH_PROP("js_hermesTime");
  PASSTHROUGH_PROP("js_hermesCPUTime");
  PASSTHROUGH_PROP("js_hermesThreadMinorFaults");
  PASSTHROUGH_PROP("js_hermesThreadMajorFaults");
  ADD_PROP("js_numGCs", heap.getNumGCs());
  ADD_PROP("js_gcCPUTime", heap.getGCCPUTime());
  ADD_PROP("js_gcTime", heap.getGCTime());
  ADD_PROP("js_totalAllocatedBytes", info.totalAllocatedBytes);
  ADD_PROP("js_allocatedBytes", info.allocatedBytes);
  ADD_PROP("js_heapSize", info.heapSize);
  ADD_PROP("js_mallocSizeEstimate", info.mallocSizeEstimate);
  ADD_PROP("js_vaSize", info.va);
  ADD_PROP("js_markStackOverflows", info.numMarkStackOverflows);
  PASSTHROUGH_PROP("js_hermesVolCtxSwitches");
  PASSTHROUGH_PROP("js_hermesInvolCtxSwitches");
  PASSTHROUGH_PROP("js_pageSize");
  PASSTHROUGH_PROP("js_threadAffinityMask");
  PASSTHROUGH_PROP("js_threadCPU");
  PASSTHROUGH_PROP("js_bytecodePagesResident");
  PASSTHROUGH_PROP("js_bytecodePagesResidentRuns");
  PASSTHROUGH_PROP("js_bytecodePagesAccessed");
  PASSTHROUGH_PROP("js_bytecodeSize");
  PASSTHROUGH_PROP("js_bytecodePagesTraceHash");
  PASSTHROUGH_PROP("js_bytecodeIOTime");
  PASSTHROUGH_PROP("js_bytecodePagesTraceSample");




  return ExecutionStatus::RETURNED;
}


CallResult<HermesValue> statsTableValueToHermesValue( Runtime &runtime, const MockedEnvironment::StatsTableValue &val) {

  if (val.isNum()) {
    return HermesValue::encodeDoubleValue(val.num());
  }

  auto strRes = StringPrimitive::create(runtime, createASCIIRef(val.str().c_str()));
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return *strRes;
}
} 


CallResult<HermesValue> hermesInternalGetInstrumentedStats(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);
  auto resultHandle = runtime.makeHandle(JSObject::create(runtime));
  
  if (runtime.shouldStabilizeInstructionCount())
    return resultHandle.getHermesValue();

  MockedEnvironment::StatsTable *statsTable = nullptr;
  auto *const storage = runtime.getCommonStorage();
  if (storage->env) {
    if (!storage->env->callsToHermesInternalGetInstrumentedStats.empty()) {
      statsTable = &storage->env->callsToHermesInternalGetInstrumentedStats.front();
    }
  }

  std::unique_ptr<MockedEnvironment::StatsTable> newStatsTable;
  if (storage->shouldTrace) {
    newStatsTable.reset(new MockedEnvironment::StatsTable());
  }

  
  
  
  auto addToResultHandle = [&](llvh::StringRef key, HermesValue val, auto newStatsTableVal) {
        Handle<> valHandle = runtime.makeHandle(val);
        auto keySym = symbolForCStr(runtime, key.data());
        if (LLVM_UNLIKELY(keySym == ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }

        auto status = JSObject::defineNewOwnProperty( resultHandle, runtime, **keySym, PropertyFlags::defaultNewNamedPropertyFlags(), valHandle);





        if (LLVM_UNLIKELY(status == ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }

        if (newStatsTable) {
          newStatsTable->try_emplace(key, newStatsTableVal);
        }

        return ExecutionStatus::RETURNED;
      };

  ExecutionStatus populateRes;
  if (!statsTable) {
    
    
    populateRes = populateInstrumentedStats( runtime, [&](llvh::StringRef key, double val) {
          GCScopeMarkerRAII marker{gcScope};

          return addToResultHandle( key, HermesValue::encodeDoubleValue(val), val);
        });
  } else {
    
    
    
    populateRes = populateInstrumentedStats(runtime, [&](llvh::StringRef key) {
      auto it = statsTable->find(key);
      if (it == statsTable->end()) {
        return ExecutionStatus::RETURNED;
      }

      GCScopeMarkerRAII marker{gcScope};

      auto valRes = statsTableValueToHermesValue(runtime, it->getValue());
      if (LLVM_UNLIKELY(valRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }

      return addToResultHandle(key, *valRes, it->getValue());
    });
  }

  if (LLVM_UNLIKELY(populateRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  if (storage->env && statsTable) {
    storage->env->callsToHermesInternalGetInstrumentedStats.pop_front();
  }
  if (LLVM_UNLIKELY(storage->shouldTrace)) {
    storage->tracedEnv.callsToHermesInternalGetInstrumentedStats.push_back( *newStatsTable);
  }

  return resultHandle.getHermesValue();
}




static const char *getCJSModuleModeDescription(Runtime &runtime) {
  bool hasCJSModulesDynamic = false;
  bool hasCJSModulesStatic = false;
  for (const auto &runtimeModule : runtime.getRuntimeModules()) {
    if (runtimeModule.hasCJSModules()) {
      hasCJSModulesDynamic = true;
    }
    if (runtimeModule.hasCJSModulesStatic()) {
      hasCJSModulesStatic = true;
    }
  }
  if (hasCJSModulesDynamic && hasCJSModulesStatic) {
    return "Mixed dynamic/static";
  }
  if (hasCJSModulesDynamic) {
    return "Dynamically resolved";
  }
  if (hasCJSModulesStatic) {
    return "Statically resolved";
  }
  return "None";
}


CallResult<HermesValue> hermesInternalGetRuntimeProperties(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);
  auto resultHandle = runtime.makeHandle(JSObject::create(runtime));
  MutableHandle<> tmpHandle{runtime};

  
  
  auto addProperty = [&](Handle<> value, const char *key) {
    auto keySym = symbolForCStr(runtime, key);
    if (LLVM_UNLIKELY(keySym == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    return JSObject::defineNewOwnProperty( resultHandle, runtime, **keySym, PropertyFlags::defaultNewNamedPropertyFlags(), value);




  };


  tmpHandle = HermesValue::encodeBoolValue(std::strstr(__FILE__, "hermes-snapshot"));
  if (LLVM_UNLIKELY( addProperty(tmpHandle, "Snapshot VM") == ExecutionStatus::EXCEPTION)) {

    return ExecutionStatus::EXCEPTION;
  }


  tmpHandle = HermesValue::encodeDoubleValue(::hermes::hbc::BYTECODE_VERSION);
  if (LLVM_UNLIKELY( addProperty(tmpHandle, "Bytecode Version") == ExecutionStatus::EXCEPTION)) {

    return ExecutionStatus::EXCEPTION;
  }

  tmpHandle = HermesValue::encodeBoolValue(runtime.builtinsAreFrozen());
  if (LLVM_UNLIKELY( addProperty(tmpHandle, "Builtins Frozen") == ExecutionStatus::EXCEPTION)) {

    return ExecutionStatus::EXCEPTION;
  }

  tmpHandle = HermesValue::encodeNumberValue(runtime.getVMExperimentFlags());
  if (LLVM_UNLIKELY( addProperty(tmpHandle, "VM Experiments") == ExecutionStatus::EXCEPTION)) {

    return ExecutionStatus::EXCEPTION;
  }

  const char buildMode[] =  "SlowDebug"  "Debug"  "Release"  ;







  auto buildModeRes = StringPrimitive::create( runtime, ASCIIRef(buildMode, sizeof(buildMode) - 1));
  if (LLVM_UNLIKELY(buildModeRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  tmpHandle = *buildModeRes;
  if (LLVM_UNLIKELY( addProperty(tmpHandle, "Build") == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  std::string gcKind = runtime.getHeap().getKindAsStr();
  auto gcKindRes = StringPrimitive::create( runtime, ASCIIRef(gcKind.c_str(), gcKind.length()));
  if (LLVM_UNLIKELY(gcKindRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  tmpHandle = *gcKindRes;
  if (LLVM_UNLIKELY( addProperty(tmpHandle, "GC") == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }


  auto relVerRes = StringPrimitive::create(runtime, createASCIIRef(HERMES_RELEASE_VERSION));
  if (LLVM_UNLIKELY(relVerRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  tmpHandle = *relVerRes;
  if (LLVM_UNLIKELY( addProperty(tmpHandle, "OSS Release Version") == ExecutionStatus::EXCEPTION)) {

    return ExecutionStatus::EXCEPTION;
  }


  const char *cjsModuleMode = getCJSModuleModeDescription(runtime);
  auto cjsModuleModeRes = StringPrimitive::create(runtime, createASCIIRef(cjsModuleMode));
  if (LLVM_UNLIKELY(cjsModuleModeRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  tmpHandle = *cjsModuleModeRes;
  if (LLVM_UNLIKELY( addProperty(tmpHandle, "CommonJS Modules") == ExecutionStatus::EXCEPTION)) {

    return ExecutionStatus::EXCEPTION;
  }

  return resultHandle.getHermesValue();
}


static void logGCStats(Runtime &runtime, const char *msg) {
  
  
  std::string stats;
  {
    llvh::raw_string_ostream os(stats);
    runtime.printHeapStats(os);
  }
  auto copyRegionFrom = [&stats](size_t from) -> size_t {
    size_t rBrace = stats.find("},", from);
    if (rBrace == std::string::npos) {
      std::string portion = stats.substr(from);
      hermesLog("HermesVM", "%s", portion.c_str());
      return stats.size();
    }

    
    const size_t to = rBrace + 2;
    std::string portion = stats.substr(from, to - from);
    hermesLog("HermesVM", "%s", portion.c_str());
    return to;
  };

  hermesLog("HermesVM", "%s:", msg);
  for (size_t ind = 0; ind < stats.size(); ind = copyRegionFrom(ind))
    ;
}


CallResult<HermesValue> hermesInternalTTIReached(void *, Runtime &runtime, NativeArgs args) {
  runtime.ttiReached();

  __llvm_profile_dump();
  throw jsi::JSINativeException("TTI reached; profiling done");


  logGCStats(runtime, "TTI call");

  return HermesValue::encodeUndefinedValue();
}

CallResult<HermesValue> hermesInternalTTRCReached(void *, Runtime &runtime, NativeArgs args) {
  
  return HermesValue::encodeUndefinedValue();
}

CallResult<HermesValue> hermesInternalIsProxy(void *, Runtime &runtime, NativeArgs args) {
  Handle<JSObject> obj = args.dyncastArg<JSObject>(0);
  return HermesValue::encodeBoolValue(obj && obj->isProxyObject());
}

CallResult<HermesValue> hermesInternalHasPromise(void *, Runtime &runtime, NativeArgs args) {
  return HermesValue::encodeBoolValue(runtime.hasES6Promise());
}

CallResult<HermesValue> hermesInternalUseEngineQueue(void *, Runtime &runtime, NativeArgs args) {
  return HermesValue::encodeBoolValue(runtime.hasMicrotaskQueue());
}




CallResult<HermesValue> hermesInternalEnqueueJob(void *, Runtime &runtime, NativeArgs args) {
  auto callable = args.dyncastArg<Callable>(0);
  if (!callable) {
    return runtime.raiseTypeError( "Argument to HermesInternal.enqueueJob must be callable");
  }
  runtime.enqueueJob(callable.get());
  return HermesValue::encodeUndefinedValue();
}





CallResult<HermesValue> hermesInternalDrainJobs(void *, Runtime &runtime, NativeArgs args) {
  auto drainRes = runtime.drainJobs();
  if (drainRes == ExecutionStatus::EXCEPTION) {
    
    return ExecutionStatus::EXCEPTION;
  }
  return HermesValue::encodeUndefinedValue();
}




CallResult<HermesValue> hermesInternalGetCallStack(void *, Runtime &runtime, NativeArgs args) {
  std::string stack = runtime.getCallStackNoAlloc();
  return StringPrimitive::create(runtime, ASCIIRef(stack.data(), stack.size()));
}




static const CodeBlock *getLeafCodeBlock( Handle<Callable> callableHandle, Runtime &runtime) {

  const Callable *callable = callableHandle.get();
  while (auto *bound = dyn_vmcast<BoundFunction>(callable)) {
    callable = bound->getTarget(runtime);
  }
  if (auto *asFunction = dyn_vmcast<const JSFunction>(callable)) {
    return asFunction->getCodeBlock(runtime);
  }
  return nullptr;
}



static CallResult<HermesValue> getCodeBlockFileName( Runtime &runtime, const CodeBlock *codeBlock, OptValue<hbc::DebugSourceLocation> location) {


  RuntimeModule *runtimeModule = codeBlock->getRuntimeModule();
  if (location) {
    auto debugInfo = runtimeModule->getBytecode()->getDebugInfo();
    return StringPrimitive::createEfficient( runtime, debugInfo->getFilenameByID(location->filenameId));
  } else {
    llvh::StringRef sourceURL = runtimeModule->getSourceURL();
    if (!sourceURL.empty()) {
      return StringPrimitive::createEfficient(runtime, sourceURL);
    }
  }
  return HermesValue::encodeUndefinedValue();
}













CallResult<HermesValue> hermesInternalGetFunctionLocation(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);

  auto callable = args.dyncastArg<Callable>(0);
  if (!callable) {
    return runtime.raiseTypeError( "Argument to HermesInternal.getFunctionLocation must be callable");
  }
  auto resultHandle = runtime.makeHandle(JSObject::create(runtime));
  MutableHandle<> tmpHandle{runtime};

  auto codeBlock = getLeafCodeBlock(callable, runtime);
  bool isNative = !codeBlock;
  auto res = JSObject::defineOwnProperty( resultHandle, runtime, Predefined::getSymbolID(Predefined::isNative), DefinePropertyFlags::getDefaultNewPropertyFlags(), runtime.getBoolValue(isNative));




  assert(res != ExecutionStatus::EXCEPTION && "Failed to set isNative");
  (void)res;

  if (codeBlock) {
    OptValue<hbc::DebugSourceLocation> location = codeBlock->getSourceLocation();
    if (location) {
      tmpHandle = HermesValue::encodeNumberValue(location->line);
      res = JSObject::defineOwnProperty( resultHandle, runtime, Predefined::getSymbolID(Predefined::lineNumber), DefinePropertyFlags::getDefaultNewPropertyFlags(), tmpHandle);




      assert(res != ExecutionStatus::EXCEPTION && "Failed to set lineNumber");
      (void)res;

      tmpHandle = HermesValue::encodeNumberValue(location->column);
      res = JSObject::defineOwnProperty( resultHandle, runtime, Predefined::getSymbolID(Predefined::columnNumber), DefinePropertyFlags::getDefaultNewPropertyFlags(), tmpHandle);




      assert(res != ExecutionStatus::EXCEPTION && "Failed to set columnNumber");
      (void)res;
    } else {
      tmpHandle = HermesValue::encodeNumberValue( codeBlock->getRuntimeModule()->getBytecode()->getSegmentID());
      res = JSObject::defineOwnProperty( resultHandle, runtime, Predefined::getSymbolID(Predefined::segmentID), DefinePropertyFlags::getDefaultNewPropertyFlags(), tmpHandle);




      assert(res != ExecutionStatus::EXCEPTION && "Failed to set segmentID");
      (void)res;

      tmpHandle = HermesValue::encodeNumberValue(codeBlock->getVirtualOffset());
      res = JSObject::defineOwnProperty( resultHandle, runtime, Predefined::getSymbolID(Predefined::virtualOffset), DefinePropertyFlags::getDefaultNewPropertyFlags(), tmpHandle);




      assert( res != ExecutionStatus::EXCEPTION && "Failed to set virtualOffset");
      (void)res;
    }

    auto fileNameRes = getCodeBlockFileName(runtime, codeBlock, location);
    if (LLVM_UNLIKELY(fileNameRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    tmpHandle = *fileNameRes;
    res = JSObject::defineOwnProperty( resultHandle, runtime, Predefined::getSymbolID(Predefined::fileName), DefinePropertyFlags::getDefaultNewPropertyFlags(), tmpHandle);




    assert(res != ExecutionStatus::EXCEPTION && "Failed to set fileName");
    (void)res;
  }
  JSObject::preventExtensions(*resultHandle);
  return resultHandle.getHermesValue();
}












CallResult<HermesValue> hermesInternalSetPromiseRejectionTrackingHook( void *, Runtime &runtime, NativeArgs args) {


  runtime.promiseRejectionTrackingHook_ = args.getArg(0);
  return HermesValue::encodeUndefinedValue();
}





CallResult<HermesValue> hermesInternalEnablePromiseRejectionTracker( void *, Runtime &runtime, NativeArgs args) {


  auto opts = args.getArgHandle(0);
  auto func = Handle<Callable>::dyn_vmcast( Handle<>(&runtime.promiseRejectionTrackingHook_));
  if (!func) {
    return runtime.raiseTypeError( "Promise rejection tracking hook was not registered");
  }
  return Callable::executeCall1( func, runtime, Runtime::getUndefinedValue(), opts.getHermesValue())
      .toCallResultHermesValue();
}





















CallResult<HermesValue> hermesInternalFuzzilli(void *, Runtime &runtime, NativeArgs args) {
  
  
  constexpr int REPRL_DWFD = 103; 

  auto operationRes = toString_RJS(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(operationRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto operation = StringPrimitive::createStringView( runtime, runtime.makeHandle(std::move(*operationRes)));

  if (operation.equals(createUTF16Ref(u"FUZZILLI_CRASH"))) {
    auto crashTypeRes = toIntegerOrInfinity(runtime, args.getArgHandle(1));
    if (LLVM_UNLIKELY(crashTypeRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    switch (crashTypeRes->getNumberAs<int>()) {
      case 0:
        *((int *)0x41414141) = 0x1337;
        break;
      case 1:
        assert(0);
        break;
      case 2:
        std::abort();
        break;
    }
  } else if (operation.equals(createUTF16Ref(u"FUZZILLI_PRINT"))) {
    static FILE *fzliout = fdopen(REPRL_DWFD, "w");
    if (!fzliout) {
      fprintf( stderr, "Fuzzer output channel not available, printing to stdout instead\n");

      fzliout = stdout;
    }

    auto printRes = toString_RJS(runtime, args.getArgHandle(1));
    if (LLVM_UNLIKELY(printRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    auto print = StringPrimitive::createStringView( runtime, runtime.makeHandle(std::move(*printRes)));

    vm::SmallU16String<32> allocator;
    std::string outputString;
    ::hermes::convertUTF16ToUTF8WithReplacements( outputString, print.getUTF16Ref(allocator));
    fprintf(fzliout, "%s\n", outputString.c_str());
    fflush(fzliout);
  }

  return HermesValue::encodeUndefinedValue();
}


Handle<JSObject> createHermesInternalObject( Runtime &runtime, const JSLibFlags &flags) {

  namespace P = Predefined;
  Handle<JSObject> intern = runtime.makeHandle(JSObject::create(runtime));
  GCScope gcScope{runtime};

  DefinePropertyFlags constantDPF = DefinePropertyFlags::getDefaultNewPropertyFlags();
  constantDPF.enumerable = 0;
  constantDPF.writable = 0;
  constantDPF.configurable = 0;

  auto defineInternMethod = [&](Predefined::Str symID, NativeFunctionPtr func, uint8_t count = 0) {
        (void)defineMethod( runtime, intern, Predefined::getSymbolID(symID), nullptr , func, count, constantDPF);






      };

  auto defineInternMethodAndSymbol = [&](const char *name, NativeFunctionPtr func, uint8_t count = 0) {
        ASCIIRef ref = createASCIIRef(name);
        Handle<SymbolID> symHandle = runtime.ignoreAllocationFailure( runtime.getIdentifierTable().getSymbolHandle(runtime, ref));
        (void)defineMethod( runtime, intern, *symHandle, nullptr , func, count, constantDPF);






      };

  
  (void)defineInternMethodAndSymbol;

  
  
  
  
  
  auto propRes = JSObject::getNamed_RJS( runtime.makeHandle<JSObject>(runtime.stringPrototype), runtime, Predefined::getSymbolID(Predefined::concat));


  assert( propRes != ExecutionStatus::EXCEPTION && !(*propRes)->isUndefined() && "Failed to get String.prototype.concat.");

  auto putRes = JSObject::defineOwnProperty( intern, runtime, Predefined::getSymbolID(Predefined::concat), constantDPF, runtime.makeHandle(std::move(*propRes)));




  assert( putRes != ExecutionStatus::EXCEPTION && *putRes && "Failed to set HermesInternal.concat.");

  (void)putRes;

  
  
  
  defineInternMethod(P::hasPromise, hermesInternalHasPromise);
  defineInternMethod(P::enqueueJob, hermesInternalEnqueueJob);
  defineInternMethod( P::setPromiseRejectionTrackingHook, hermesInternalSetPromiseRejectionTrackingHook);

  defineInternMethod( P::enablePromiseRejectionTracker, hermesInternalEnablePromiseRejectionTracker);

  defineInternMethod(P::useEngineQueue, hermesInternalUseEngineQueue);


  defineInternMethod(P::fuzzilli, hermesInternalFuzzilli);


  
  if (!flags.enableHermesInternal) {
    JSObject::preventExtensions(*intern);
    return intern;
  }

  
  
  defineInternMethod(P::getEpilogues, hermesInternalGetEpilogues);
  defineInternMethod( P::getInstrumentedStats, hermesInternalGetInstrumentedStats);
  defineInternMethod( P::getRuntimeProperties, hermesInternalGetRuntimeProperties);
  defineInternMethod(P::ttiReached, hermesInternalTTIReached);
  defineInternMethod(P::ttrcReached, hermesInternalTTRCReached);
  defineInternMethod(P::getFunctionLocation, hermesInternalGetFunctionLocation);

  
  
  if (flags.enableHermesInternalTestMethods) {
    defineInternMethod( P::detachArrayBuffer, hermesInternalDetachArrayBuffer, 1);
    defineInternMethod(P::getWeakSize, hermesInternalGetWeakSize);
    defineInternMethod( P::copyDataProperties, hermesBuiltinCopyDataProperties, 3);
    defineInternMethodAndSymbol("isProxy", hermesInternalIsProxy);
    defineInternMethod(P::drainJobs, hermesInternalDrainJobs);
  }


  defineInternMethodAndSymbol("getCallStack", hermesInternalGetCallStack, 0);


  JSObject::preventExtensions(*intern);

  return intern;
}

} 
} 
