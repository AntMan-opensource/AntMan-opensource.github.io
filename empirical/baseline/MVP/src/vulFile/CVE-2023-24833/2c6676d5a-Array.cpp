






















namespace hermes {
namespace vm {




Handle<JSObject> createArrayConstructor(Runtime &runtime) {
  auto arrayPrototype = Handle<JSArray>::vmcast(&runtime.arrayPrototype);

  
  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::toString), nullptr, arrayPrototypeToString, 0);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::toLocaleString), nullptr, arrayPrototypeToLocaleString, 0);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::at), nullptr, arrayPrototypeAt, 1);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::concat), nullptr, arrayPrototypeConcat, 1);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::join), nullptr, arrayPrototypeJoin, 1);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::push), nullptr, arrayPrototypePush, 1);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::sort), nullptr, arrayPrototypeSort, 1);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::forEach), nullptr, arrayPrototypeForEach, 1);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::flat), nullptr, arrayPrototypeFlat, 0);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::flatMap), nullptr, arrayPrototypeFlatMap, 1);






  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::keys), (void *)IterationKind::Key, arrayPrototypeIterator, 0);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::values), (void *)IterationKind::Value, arrayPrototypeIterator, 0);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::entries), (void *)IterationKind::Entry, arrayPrototypeIterator, 0);






  auto propValue = runtime.ignoreAllocationFailure(JSObject::getNamed_RJS( arrayPrototype, runtime, Predefined::getSymbolID(Predefined::values)));
  runtime.arrayPrototypeValues = std::move(propValue);

  DefinePropertyFlags dpf = DefinePropertyFlags::getNewNonEnumerableFlags();

  runtime.ignoreAllocationFailure(JSObject::defineOwnProperty( arrayPrototype, runtime, Predefined::getSymbolID(Predefined::SymbolIterator), dpf, Handle<>(&runtime.arrayPrototypeValues)));





  auto cons = defineSystemConstructor<JSArray>( runtime, Predefined::getSymbolID(Predefined::Array), arrayConstructor, arrayPrototype, 1, CellKind::JSArrayKind);






  defineMethod( runtime, cons, Predefined::getSymbolID(Predefined::isArray), nullptr, arrayIsArray, 1);






  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::slice), nullptr, arrayPrototypeSlice, 2);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::splice), nullptr, arrayPrototypeSplice, 2);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::copyWithin), nullptr, arrayPrototypeCopyWithin, 2);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::pop), nullptr, arrayPrototypePop, 0);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::shift), nullptr, arrayPrototypeShift, 0);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::unshift), nullptr, arrayPrototypeUnshift, 1);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::indexOf), nullptr, arrayPrototypeIndexOf, 1);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::lastIndexOf), nullptr, arrayPrototypeLastIndexOf, 1);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::every), nullptr, arrayPrototypeEvery, 1);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::some), nullptr, arrayPrototypeSome, 1);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::map), nullptr, arrayPrototypeMap, 1);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::filter), nullptr, arrayPrototypeFilter, 1);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::fill), nullptr, arrayPrototypeFill, 1);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::find), nullptr, arrayPrototypeFind, 1);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::findIndex),  (void *)true, arrayPrototypeFind, 1);






  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::findLast), nullptr, arrayPrototypeFindLast, 1);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::findLastIndex),  (void *)true, arrayPrototypeFindLast, 1);






  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::reduce), nullptr, arrayPrototypeReduce, 1);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::reduceRight), nullptr, arrayPrototypeReduceRight, 1);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::reverse), nullptr, arrayPrototypeReverse, 0);





  defineMethod( runtime, arrayPrototype, Predefined::getSymbolID(Predefined::includes), nullptr, arrayPrototypeIncludes, 1);






  defineMethod( runtime, cons, Predefined::getSymbolID(Predefined::of), nullptr, arrayOf, 0);





  defineMethod( runtime, cons, Predefined::getSymbolID(Predefined::from), nullptr, arrayFrom, 1);






  return cons;
}

CallResult<HermesValue> arrayConstructor(void *, Runtime &runtime, NativeArgs args) {
  MutableHandle<JSArray> selfHandle{runtime};

  
  
  if (args.isConstructorCall())
    selfHandle = vmcast<JSArray>(args.getThisArg());
  else {
    auto arrRes = JSArray::create(runtime, 0, 0);
    if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    selfHandle = arrRes->get();
  }

  
  if (args.getArgCount() == 1 && args.getArg(0).isNumber()) {
    double number = args.getArg(0).getNumber();
    uint32_t len = truncateToUInt32(number);
    if (len != number) {
      return runtime.raiseRangeError("invalid array length");
    }

    auto st = JSArray::setLengthProperty(selfHandle, runtime, len);
    (void)st;
    assert( st != ExecutionStatus::EXCEPTION && *st && "Cannot set length of a new array");


    return selfHandle.getHermesValue();
  }

  
  uint32_t len = args.getArgCount();

  
  auto st = JSArray::setLengthProperty(selfHandle, runtime, len);
  (void)st;
  assert( st != ExecutionStatus::EXCEPTION && *st && "Cannot set length of a new array");


  
  uint32_t index = 0;
  GCScopeMarkerRAII marker(runtime);
  for (Handle<> arg : args.handles()) {
    JSArray::setElementAt(selfHandle, runtime, index++, arg);
    marker.flush();
  }

  return selfHandle.getHermesValue();
}

CallResult<HermesValue> arrayIsArray(void *, Runtime &runtime, NativeArgs args) {
  CallResult<bool> res = isArray(runtime, dyn_vmcast<JSObject>(args.getArg(0)));
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return HermesValue::encodeBoolValue(*res);
}


CallResult<HermesValue> arrayPrototypeToString(void *, Runtime &runtime, NativeArgs args) {
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto array = runtime.makeHandle<JSObject>(objRes.getValue());

  auto propRes = JSObject::getNamed_RJS( array, runtime, Predefined::getSymbolID(Predefined::join));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto func = Handle<Callable>::dyn_vmcast(runtime.makeHandle(std::move(*propRes)));

  if (!func) {
    
    return directObjectPrototypeToString(runtime, array);
  }

  return Callable::executeCall0(func, runtime, array).toCallResultHermesValue();
}

CallResult<HermesValue> arrayPrototypeToLocaleString(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto array = runtime.makeHandle<JSObject>(objRes.getValue());

  auto emptyString = runtime.getPredefinedStringHandle(Predefined::emptyString);

  if (runtime.insertVisitedObject(*array))
    return emptyString.getHermesValue();
  auto cycleScope = llvh::make_scope_exit([&] { runtime.removeVisitedObject(*array); });

  auto propRes = JSObject::getNamed_RJS( array, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto intRes = toUInt32_RJS(runtime, runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  uint32_t len = intRes->getNumber();

  
  
  const char16_t separator = u',';

  
  SafeUInt32 size(len - 1);

  if (len == 0) {
    return emptyString.getHermesValue();
  }

  
  auto arrRes = JSArray::create(runtime, len, len);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto strings = *arrRes;

  
  MutableHandle<> i{runtime, HermesValue::encodeNumberValue(0)};

  auto marker = gcScope.createMarker();
  while (i->getNumber() < len) {
    gcScope.flushToMarker(marker);
    if (LLVM_UNLIKELY( (propRes = JSObject::getComputed_RJS(array, runtime, i)) == ExecutionStatus::EXCEPTION)) {

      return ExecutionStatus::EXCEPTION;
    }
    auto E = runtime.makeHandle(std::move(*propRes));
    if (E->isUndefined() || E->isNull()) {
      
      JSArray::setElementAt(strings, runtime, i->getNumber(), emptyString);
    } else {
      if (LLVM_UNLIKELY( (objRes = toObject(runtime, E)) == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      auto elementObj = runtime.makeHandle<JSObject>(objRes.getValue());

      
      if (LLVM_UNLIKELY( (propRes = JSObject::getNamed_RJS( elementObj, runtime, Predefined::getSymbolID(Predefined::toLocaleString))) == ExecutionStatus::EXCEPTION)) {




        return ExecutionStatus::EXCEPTION;
      }
      if (auto func = Handle<Callable>::dyn_vmcast( runtime.makeHandle(std::move(*propRes)))) {
        
        
        
        
        
        
        auto callRes =  Callable::executeCall2( func, runtime, elementObj, args.getArg(0), args.getArg(1));



            Callable::executeCall0(func, runtime, elementObj);

        if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }
        auto strRes = toString_RJS(runtime, runtime.makeHandle(std::move(*callRes)));
        if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }
        auto elementStr = runtime.makeHandle(std::move(*strRes));
        uint32_t strLength = elementStr->getStringLength();
        
        size.add(strLength);
        if (LLVM_UNLIKELY(size.isOverflowed())) {
          return runtime.raiseRangeError( "resulting string length exceeds limit");
        }
        JSArray::setElementAt(strings, runtime, i->getNumber(), elementStr);
      } else {
        return runtime.raiseTypeError("toLocaleString() not callable");
      }
    }
    i = HermesValue::encodeNumberValue(i->getNumber() + 1);
  }

  
  auto builder = StringBuilder::createStringBuilder(runtime, size);
  if (builder == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  MutableHandle<StringPrimitive> element{runtime};
  element = strings->at(runtime, 0).getString(runtime);
  builder->appendStringPrim(element);
  for (uint32_t j = 1; j < len; ++j) {
    
    builder->appendCharacter(separator);
    element = strings->at(runtime, j).getString(runtime);
    builder->appendStringPrim(element);
  }
  return HermesValue::encodeStringValue(*builder->getStringPrimitive());
}


CallResult<HermesValue> arrayPrototypeAt(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);
  
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(objRes.getValue());

  
  Handle<JSArray> jsArr = Handle<JSArray>::dyn_vmcast(O);
  uint32_t len = 0;
  if (LLVM_LIKELY(jsArr)) {
    
    len = JSArray::getLength(jsArr.get(), runtime);
  } else {
    
    CallResult<PseudoHandle<>> propRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    auto lenRes = toLength(runtime, runtime.makeHandle(std::move(*propRes)));
    if (LLVM_UNLIKELY(lenRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    len = lenRes->getNumber();
  }

  
  auto idx = args.getArgHandle(0);
  auto relativeIndexRes = toIntegerOrInfinity(runtime, idx);
  if (relativeIndexRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  const double relativeIndex = relativeIndexRes->getNumber();

  double k;
  
  if (relativeIndex >= 0) {
    
    k = relativeIndex;
  } else {
    
    
    k = len + relativeIndex;
  }

  
  if (k < 0 || k >= len) {
    return HermesValue::encodeUndefinedValue();
  }

  
  if (LLVM_LIKELY(jsArr)) {
    const SmallHermesValue elm = jsArr->at(runtime, k);
    if (elm.isEmpty()) {
      return HermesValue::encodeUndefinedValue();
    } else {
      return elm.unboxToHV(runtime);
    }
  }
  CallResult<PseudoHandle<>> propRes = JSObject::getComputed_RJS( O, runtime, runtime.makeHandle(HermesValue::encodeDoubleValue(k)));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return propRes->getHermesValue();
}

CallResult<HermesValue> arrayPrototypeConcat(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(objRes.getValue());

  
  int64_t argCount = args.getArgCount();

  
  
  
  SafeUInt32 finalSizeEstimate{0};
  if (JSArray *arr = dyn_vmcast<JSArray>(O.get())) {
    finalSizeEstimate.add(JSArray::getLength(arr, runtime));
  } else {
    finalSizeEstimate.add(1);
  }
  for (int64_t i = 0; i < argCount; ++i) {
    if (JSArray *arr = dyn_vmcast<JSArray>(args.getArg(i))) {
      finalSizeEstimate.add(JSArray::getLength(arr, runtime));
    } else {
      finalSizeEstimate.add(1);
    }
  }
  if (finalSizeEstimate.isOverflowed()) {
    return runtime.raiseTypeError("Array.prototype.concat result out of space");
  }

  
  auto arrRes = JSArray::create(runtime, *finalSizeEstimate, *finalSizeEstimate);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto A = *arrRes;

  
  uint64_t n = 0;

  
  MutableHandle<JSObject> objHandle{runtime};
  
  MutableHandle<JSArray> arrHandle{runtime};
  
  MutableHandle<> kHandle{runtime};
  
  MutableHandle<> nHandle{runtime};
  
  MutableHandle<> tmpHandle{runtime};
  
  MutableHandle<JSObject> propObj{runtime};
  MutableHandle<SymbolID> tmpPropNameStorage{runtime};
  auto marker = gcScope.createMarker();
  ComputedPropertyDescriptor desc;

  
  
  tmpHandle = O.getHermesValue();
  for (int64_t i = -1; i < argCount; ++i, tmpHandle = args.getArg(i)) {
    CallResult<bool> spreadable = isConcatSpreadable(runtime, tmpHandle);
    if (LLVM_UNLIKELY(spreadable == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (*spreadable) {
      
      objHandle = vmcast<JSObject>(*tmpHandle);
      arrHandle = dyn_vmcast<JSArray>(*tmpHandle);

      uint64_t len;
      if (LLVM_LIKELY(arrHandle)) {
        
        len = JSArray::getLength(*arrHandle, runtime);
      } else {
        CallResult<PseudoHandle<>> propRes = JSObject::getNamed_RJS( objHandle, runtime, Predefined::getSymbolID(Predefined::length));
        if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }
        tmpHandle = std::move(*propRes);
        auto lengthRes = toLength(runtime, tmpHandle);
        if (LLVM_UNLIKELY(lengthRes == ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }
        len = lengthRes->getNumberAs<uint64_t>();
      }

      
      if (LLVM_UNLIKELY(n + len > ((uint64_t)1 << 53) - 1)) {
        return runtime.raiseTypeError( "Array.prototype.concat result out of space");
      }

      
      
      
      if (LLVM_UNLIKELY(n + len > A->getEndIndex()) && LLVM_LIKELY(n + len < UINT32_MAX)) {
        
        if (LLVM_UNLIKELY( A->setStorageEndIndex(A, runtime, n + len) == ExecutionStatus::EXCEPTION)) {

          return ExecutionStatus::EXCEPTION;
        }
      }

      
      
      
      for (uint64_t k = 0; k < len; ++k, ++n) {
        SmallHermesValue subElement = LLVM_LIKELY(arrHandle)
            ? arrHandle->at(runtime, k)
            : SmallHermesValue::encodeEmptyValue();
        if (LLVM_LIKELY(!subElement.isEmpty()) && LLVM_LIKELY(n < A->getEndIndex())) {
          
          
          JSArray::unsafeSetExistingElementAt( A.get(), runtime, static_cast<uint32_t>(n), subElement);
        } else {
          
          
          
          kHandle = HermesValue::encodeDoubleValue(k);
          JSObject::getComputedPrimitiveDescriptor( objHandle, runtime, kHandle, propObj, tmpPropNameStorage, desc);
          CallResult<PseudoHandle<>> propRes = JSObject::getComputedPropertyValue_RJS( objHandle, runtime, propObj, tmpPropNameStorage, desc, kHandle);






          if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
            return ExecutionStatus::EXCEPTION;
          }
          if (LLVM_LIKELY(!(*propRes)->isEmpty())) {
            tmpHandle = std::move(*propRes);
            nHandle = HermesValue::encodeDoubleValue(n);
            if (LLVM_UNLIKELY( JSArray::defineOwnComputedPrimitive( A, runtime, nHandle, DefinePropertyFlags::getDefaultNewPropertyFlags(), tmpHandle) == ExecutionStatus::EXCEPTION)) {





              return ExecutionStatus::EXCEPTION;
            }
          }
          gcScope.flushToMarker(marker);
        }
      }
      gcScope.flushToMarker(marker);
    } else {
      
      
      if (LLVM_UNLIKELY(n >= ((uint64_t)1 << 53) - 1)) {
        return runtime.raiseTypeError( "Array.prototype.concat result out of space");
      }
      
      if (LLVM_LIKELY(n < UINT32_MAX)) {
        JSArray::setElementAt(A, runtime, n, tmpHandle);
      } else {
        nHandle = HermesValue::encodeDoubleValue(n);
        auto cr = valueToSymbolID(runtime, nHandle);
        if (LLVM_UNLIKELY(cr == ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }
        if (LLVM_UNLIKELY( JSArray::defineOwnProperty( A, runtime, **cr, DefinePropertyFlags::getDefaultNewPropertyFlags(), tmpHandle) == ExecutionStatus::EXCEPTION)) {





          return ExecutionStatus::EXCEPTION;
        }
      }
      gcScope.flushToMarker(marker);
      ++n;
    }
  }
  
  
  if (n > UINT32_MAX) {
    return runtime.raiseRangeError("invalid array length");
  }
  auto res = JSArray::setLengthProperty(A, runtime, static_cast<uint32_t>(n));
  assert( res == ExecutionStatus::RETURNED && "Setting length of new array should never fail");

  (void)res;
  return A.getHermesValue();
}


CallResult<HermesValue> arrayPrototypeJoin(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(objRes.getValue());

  auto emptyString = runtime.getPredefinedStringHandle(Predefined::emptyString);

  if (runtime.insertVisitedObject(*O))
    return emptyString.getHermesValue();
  auto cycleScope = llvh::make_scope_exit([&] { runtime.removeVisitedObject(*O); });

  auto propRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto intRes = toLengthU64(runtime, runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  uint64_t len = *intRes;

  
  auto separator = args.getArg(0).isUndefined()
      ? runtime.makeHandle(HermesValue::encodeStringValue( runtime.getPredefinedString(Predefined::comma)))
      : args.getArgHandle(0);
  auto strRes = toString_RJS(runtime, separator);
  if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto sep = runtime.makeHandle(std::move(*strRes));

  if (len == 0) {
    return HermesValue::encodeStringValue( runtime.getPredefinedString(Predefined::emptyString));
  }

  
  
  SafeUInt32 size;

  
  if (LLVM_UNLIKELY(len > JSArray::StorageType::maxElements())) {
    return runtime.raiseRangeError("Out of memory for array elements.");
  }
  auto arrRes = JSArray::create(runtime, len, 0);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto strings = *arrRes;

  
  for (MutableHandle<> i{runtime, HermesValue::encodeNumberValue(0)};
       i->getNumber() < len;
       i = HermesValue::encodeNumberValue(i->getNumber() + 1)) {
    
    if (i->getNumberAs<uint32_t>())
      size.add(sep->getStringLength());

    GCScope gcScope2(runtime);
    if (LLVM_UNLIKELY( (propRes = JSObject::getComputed_RJS(O, runtime, i)) == ExecutionStatus::EXCEPTION)) {

      return ExecutionStatus::EXCEPTION;
    }

    auto elem = runtime.makeHandle(std::move(*propRes));

    if (elem->isUndefined() || elem->isNull()) {
      JSArray::setElementAt(strings, runtime, i->getNumber(), emptyString);
    } else {
      
      auto strRes = toString_RJS(runtime, elem);
      if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      auto S = runtime.makeHandle(std::move(*strRes));
      size.add(S->getStringLength());
      JSArray::setElementAt(strings, runtime, i->getNumber(), S);
    }

    
    
    if (size.isOverflowed()) {
      return runtime.raiseRangeError("String is too long");
    }
  }

  
  auto builder = StringBuilder::createStringBuilder(runtime, size);
  if (builder == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  MutableHandle<StringPrimitive> element{runtime};
  element = strings->at(runtime, 0).getString(runtime);
  builder->appendStringPrim(element);
  for (size_t i = 1; i < len; ++i) {
    builder->appendStringPrim(sep);
    element = strings->at(runtime, i).getString(runtime);
    builder->appendStringPrim(element);
  }
  return HermesValue::encodeStringValue(*builder->getStringPrimitive());
}


CallResult<HermesValue> arrayPrototypePush(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);

  
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(objRes.getValue());

  MutableHandle<> len{runtime};

  
  Handle<JSArray> arr = Handle<JSArray>::dyn_vmcast(O);
  if (LLVM_LIKELY(arr)) {
    
    len = HermesValue::encodeNumberValue(JSArray::getLength(arr.get(), runtime));
  } else {
    
    auto propRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    auto lenRes = toLength(runtime, runtime.makeHandle(std::move(*propRes)));
    if (LLVM_UNLIKELY(lenRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    len = lenRes.getValue();
  }

  
  
  
  uint32_t argCount = args.getArgCount();

  
  if (len->getNumber() + (double)argCount > std::pow(2.0, 53) - 1) {
    return runtime.raiseTypeError("Array length exceeded in push()");
  }

  auto marker = gcScope.createMarker();
  
  for (auto arg : args.handles()) {
    
    
    
    
    
    
    
    
    
    if (LLVM_UNLIKELY( JSObject::putComputed_RJS( O, runtime, len, arg, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {


      return ExecutionStatus::EXCEPTION;
    }
    gcScope.flushToMarker(marker);
    
    len = HermesValue::encodeDoubleValue(len->getNumber() + 1);
  }

  
  if (LLVM_UNLIKELY( JSObject::putNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length), len, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {






    return ExecutionStatus::EXCEPTION;
  }

  
  return len.get();
}

namespace {











class StandardSortModel : public SortModel {
 private:
  
  Runtime &runtime_;

  
  GCScope gcScope_;

  
  
  Handle<Callable> compareFn_;

  
  Handle<JSObject> obj_;

  
  MutableHandle<SymbolID> aTmpNameStorage_;
  MutableHandle<SymbolID> bTmpNameStorage_;

  
  

  
  MutableHandle<> aHandle_;
  MutableHandle<> bHandle_;

  
  MutableHandle<> aValue_;
  MutableHandle<> bValue_;

  
  MutableHandle<JSObject> aDescObjHandle_;
  MutableHandle<JSObject> bDescObjHandle_;

  
  
  GCScope::Marker gcMarker_;

 public:
  StandardSortModel( Runtime &runtime, Handle<JSObject> obj, Handle<Callable> compareFn)


      : runtime_(runtime), gcScope_(runtime), compareFn_(compareFn), obj_(obj), aTmpNameStorage_(runtime), bTmpNameStorage_(runtime), aHandle_(runtime), bHandle_(runtime), aValue_(runtime), bValue_(runtime), aDescObjHandle_(runtime), bDescObjHandle_(runtime), gcMarker_(gcScope_.createMarker()) {}












  
  ExecutionStatus swap(uint32_t a, uint32_t b) override {
    
    GCScopeMarkerRAII gcMarker{gcScope_, gcMarker_};

    aHandle_ = HermesValue::encodeDoubleValue(a);
    bHandle_ = HermesValue::encodeDoubleValue(b);

    ComputedPropertyDescriptor aDesc;
    JSObject::getComputedPrimitiveDescriptor( obj_, runtime_, aHandle_, aDescObjHandle_, aTmpNameStorage_, aDesc);

    ComputedPropertyDescriptor bDesc;
    JSObject::getComputedPrimitiveDescriptor( obj_, runtime_, bHandle_, bDescObjHandle_, bTmpNameStorage_, bDesc);

    if (aDescObjHandle_) {
      if (LLVM_LIKELY(!aDesc.flags.proxyObject)) {
        auto res = JSObject::getComputedPropertyValue_RJS( obj_, runtime_, aDescObjHandle_, aTmpNameStorage_, aDesc, aDescObjHandle_);





        if (res == ExecutionStatus::EXCEPTION) {
          return ExecutionStatus::EXCEPTION;
        }
        if (LLVM_LIKELY(!(*res)->isEmpty())) {
          aValue_ = std::move(*res);
        }
      } else {
        auto keyRes = toPropertyKey(runtime_, aHandle_);
        if (keyRes == ExecutionStatus::EXCEPTION) {
          return ExecutionStatus::EXCEPTION;
        }
        aHandle_ = keyRes->get();
        CallResult<bool> hasPropRes = JSProxy::getOwnProperty( aDescObjHandle_, runtime_, aHandle_, aDesc, nullptr);
        if (hasPropRes == ExecutionStatus::EXCEPTION) {
          return ExecutionStatus::EXCEPTION;
        }
        if (*hasPropRes) {
          auto res = JSProxy::getComputed(aDescObjHandle_, runtime_, aHandle_, obj_);
          if (res == ExecutionStatus::EXCEPTION) {
            return ExecutionStatus::EXCEPTION;
          }
          aValue_ = std::move(*res);
        } else {
          aDescObjHandle_ = nullptr;
        }
      }
    }
    if (bDescObjHandle_) {
      if (LLVM_LIKELY(!bDesc.flags.proxyObject)) {
        auto res = JSObject::getComputedPropertyValue_RJS( obj_, runtime_, bDescObjHandle_, bTmpNameStorage_, bDesc, bDescObjHandle_);





        if (res == ExecutionStatus::EXCEPTION) {
          return ExecutionStatus::EXCEPTION;
        }
        if (LLVM_LIKELY(!(*res)->isEmpty())) {
          bValue_ = std::move(*res);
        }
      } else {
        auto keyRes = toPropertyKey(runtime_, bHandle_);
        if (keyRes == ExecutionStatus::EXCEPTION) {
          return ExecutionStatus::EXCEPTION;
        }
        bHandle_ = keyRes->get();
        CallResult<bool> hasPropRes = JSProxy::getOwnProperty( bDescObjHandle_, runtime_, bHandle_, bDesc, nullptr);
        if (hasPropRes == ExecutionStatus::EXCEPTION) {
          return ExecutionStatus::EXCEPTION;
        }
        if (*hasPropRes) {
          auto res = JSProxy::getComputed(bDescObjHandle_, runtime_, bHandle_, obj_);
          if (res == ExecutionStatus::EXCEPTION) {
            return ExecutionStatus::EXCEPTION;
          }
          bValue_ = std::move(*res);
        } else {
          bDescObjHandle_ = nullptr;
        }
      }
    }

    if (bDescObjHandle_) {
      if (LLVM_UNLIKELY( JSObject::putComputed_RJS( obj_, runtime_, aHandle_, bValue_, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {






        return ExecutionStatus::EXCEPTION;
      }
    } else {
      if (LLVM_UNLIKELY( JSObject::deleteComputed( obj_, runtime_, aHandle_, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {


        return ExecutionStatus::EXCEPTION;
      }
    }

    if (aDescObjHandle_) {
      if (LLVM_UNLIKELY( JSObject::putComputed_RJS( obj_, runtime_, bHandle_, aValue_, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {






        return ExecutionStatus::EXCEPTION;
      }
    } else {
      if (LLVM_UNLIKELY( JSObject::deleteComputed( obj_, runtime_, bHandle_, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {


        return ExecutionStatus::EXCEPTION;
      }
    }

    return ExecutionStatus::RETURNED;
  }

  
  
  
  CallResult<int> compare(uint32_t a, uint32_t b) override {
    
    GCScopeMarkerRAII gcMarker{gcScope_, gcMarker_};

    aHandle_ = HermesValue::encodeDoubleValue(a);
    bHandle_ = HermesValue::encodeDoubleValue(b);

    ComputedPropertyDescriptor aDesc;
    JSObject::getComputedPrimitiveDescriptor( obj_, runtime_, aHandle_, aDescObjHandle_, aTmpNameStorage_, aDesc);
    CallResult<PseudoHandle<>> propRes = JSObject::getComputedPropertyValue_RJS( obj_, runtime_, aDescObjHandle_, aTmpNameStorage_, aDesc, aHandle_);
    if (propRes == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    if ((*propRes)->isEmpty()) {
      
      return 1;
    }
    aValue_ = std::move(*propRes);
    assert(!aValue_->isEmpty());

    ComputedPropertyDescriptor bDesc;
    JSObject::getComputedPrimitiveDescriptor( obj_, runtime_, bHandle_, bDescObjHandle_, bTmpNameStorage_, bDesc);
    if ((propRes = JSObject::getComputedPropertyValue_RJS( obj_, runtime_, bDescObjHandle_, bTmpNameStorage_, bDesc, bHandle_)) == ExecutionStatus::EXCEPTION) {





      return ExecutionStatus::EXCEPTION;
    }
    if ((*propRes)->isEmpty()) {
      
      return -1;
    }
    bValue_ = std::move(*propRes);
    assert(!bValue_->isEmpty());

    if (aValue_->isUndefined()) {
      
      return 1;
    }
    if (bValue_->isUndefined()) {
      
      return -1;
    }

    if (compareFn_) {
      
      auto callRes = Callable::executeCall2( compareFn_, runtime_, Runtime::getUndefinedValue(), aValue_.get(), bValue_.get());




      if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      auto intRes = toNumber_RJS(runtime_, runtime_.makeHandle(std::move(*callRes)));
      if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      
      auto res = intRes->getNumber();
      return (res < 0) ? -1 : (res > 0 ? 1 : 0);
    } else {
      
      auto aValueRes = toString_RJS(runtime_, aValue_);
      if (LLVM_UNLIKELY(aValueRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      aValue_ = aValueRes->getHermesValue();

      auto bValueRes = toString_RJS(runtime_, bValue_);
      if (LLVM_UNLIKELY(bValueRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      bValue_ = bValueRes->getHermesValue();

      return aValue_->getString()->compare(bValue_->getString());
    }
  }
};




CallResult<HermesValue> sortSparse( Runtime &runtime, Handle<JSObject> O, Handle<Callable> compareFn, uint64_t len) {



  GCScope gcScope{runtime};

  assert( !O->isHostObject() && !O->isProxyObject() && "only non-exotic objects can be sparsely sorted");


  
  
  

  auto crNames = JSObject::getOwnPropertyNames(O, runtime, false);
  if (crNames == ExecutionStatus::EXCEPTION)
    return ExecutionStatus::EXCEPTION;
  
  auto names = runtime.makeHandle((*crNames)->getIndexedStorage(runtime));
  if (!names) {
    
    return O.getHermesValue();
  }

  
  JSArray::StorageType::size_type numProps = 0;
  for (JSArray::StorageType::size_type e = names->size(runtime); numProps != e;
       ++numProps) {
    SmallHermesValue hv = names->at(runtime, numProps);
    
    if (!hv.isNumber())
      break;
    
    if (hv.getNumber(runtime) >= len)
      break;
  }

  
  if (numProps == 0)
    return O.getHermesValue();

  
  auto crArray = JSArray::create(runtime, numProps, numProps);
  if (crArray == ExecutionStatus::EXCEPTION)
    return ExecutionStatus::EXCEPTION;
  auto array = *crArray;
  if (JSArray::setStorageEndIndex(array, runtime, numProps) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }

  MutableHandle<> propName{runtime};
  MutableHandle<> propVal{runtime};
  GCScopeMarkerRAII gcMarker{gcScope};

  
  
  
  for (decltype(numProps) i = 0; i != numProps; ++i) {
    gcMarker.flush();

    propName = names->at(runtime, i).unboxToHV(runtime);
    auto res = JSObject::getComputed_RJS(O, runtime, propName);
    if (res == ExecutionStatus::EXCEPTION)
      return ExecutionStatus::EXCEPTION;
    
    if (res->getHermesValue().isEmpty())
      continue;

    const auto shv = SmallHermesValue::encodeHermesValue(res->get(), runtime);
    JSArray::unsafeSetExistingElementAt(*array, runtime, i, shv);

    if (JSObject::deleteComputed( O, runtime, propName, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION) {

      return ExecutionStatus::EXCEPTION;
    }
  }
  gcMarker.flush();

  {
    StandardSortModel sm(runtime, array, compareFn);
    if (LLVM_UNLIKELY( quickSort(&sm, 0u, numProps) == ExecutionStatus::EXCEPTION))
      return ExecutionStatus::EXCEPTION;
  }

  
  for (decltype(numProps) i = 0; i != numProps; ++i) {
    gcMarker.flush();

    auto hv = array->at(runtime, i).unboxToHV(runtime);
    assert( !hv.isEmpty() && "empty values cannot appear in the array out of nowhere");

    propVal = hv;

    propName = HermesValue::encodeNumberValue(i);

    if (JSObject::putComputed_RJS( O, runtime, propName, propVal, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION) {

      return ExecutionStatus::EXCEPTION;
    }
  }

  return O.getHermesValue();
}
} 


CallResult<HermesValue> arrayPrototypeSort(void *, Runtime &runtime, NativeArgs args) {
  
  auto compareFn = Handle<Callable>::dyn_vmcast(args.getArgHandle(0));
  if (!args.getArg(0).isUndefined() && !compareFn) {
    return runtime.raiseTypeError("Array sort argument must be callable");
  }

  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(objRes.getValue());

  auto propRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto intRes = toLengthU64(runtime, runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  uint64_t len = *intRes;

  
  
  
  if (!O->isProxyObject() && !O->isHostObject() && !O->hasFastIndexProperties())
    return sortSparse(runtime, O, compareFn, len);

  
  StandardSortModel sm(runtime, O, compareFn);

  
  
  
  if (LLVM_UNLIKELY(quickSort(&sm, 0u, len) == ExecutionStatus::EXCEPTION))
    return ExecutionStatus::EXCEPTION;

  return O.getHermesValue();
}

inline CallResult<HermesValue> arrayPrototypeForEach(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(objRes.getValue());

  auto propRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto intRes = toLengthU64(runtime, runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  uint64_t len = *intRes;

  auto callbackFn = args.dyncastArg<Callable>(0);
  if (!callbackFn) {
    return runtime.raiseTypeError( "Array.prototype.forEach() requires a callable argument");
  }

  
  MutableHandle<> k{runtime, HermesValue::encodeDoubleValue(0)};

  MutableHandle<JSObject> descObjHandle{runtime};
  MutableHandle<SymbolID> tmpPropNameStorage{runtime};

  
  
  auto marker = gcScope.createMarker();
  while (k->getDouble() < len) {
    gcScope.flushToMarker(marker);

    ComputedPropertyDescriptor desc;
    JSObject::getComputedPrimitiveDescriptor( O, runtime, k, descObjHandle, tmpPropNameStorage, desc);
    CallResult<PseudoHandle<>> propRes = JSObject::getComputedPropertyValue_RJS( O, runtime, descObjHandle, tmpPropNameStorage, desc, k);
    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (LLVM_LIKELY(!(*propRes)->isEmpty())) {
      auto kValue = std::move(*propRes);
      if (LLVM_UNLIKELY( Callable::executeCall3( callbackFn, runtime, args.getArgHandle(1), kValue.get(), k.get(), O.getHermesValue()) == ExecutionStatus::EXCEPTION)) {






        return ExecutionStatus::EXCEPTION;
      }
    }

    k = HermesValue::encodeDoubleValue(k->getDouble() + 1);
  }

  return HermesValue::encodeUndefinedValue();
}




static CallResult<uint64_t> flattenIntoArray( Runtime &runtime, Handle<JSArray> target, Handle<JSObject> source, uint64_t sourceLen, uint64_t start, double depth, Handle<Callable> mapperFunction, Handle<> thisArg) {







  ScopedNativeDepthTracker depthTracker{runtime};
  if (LLVM_UNLIKELY(depthTracker.overflowed())) {
    return runtime.raiseStackOverflow(Runtime::StackOverflowKind::NativeStack);
  }

  if (!mapperFunction) {
    assert( thisArg->isUndefined() && "thisArg must be undefined if there is no mapper");

  }

  GCScope gcScope{runtime};
  
  uint64_t targetIndex = start;
  
  uint64_t sourceIndex = 0;

  
  MutableHandle<> indexHandle{runtime};
  MutableHandle<SymbolID> tmpPropNameStorage{runtime};
  MutableHandle<JSObject> propObj{runtime};
  MutableHandle<> element{runtime};
  MutableHandle<> lenResHandle{runtime};

  auto marker = gcScope.createMarker();

  
  while (sourceIndex < sourceLen) {
    gcScope.flushToMarker(marker);

    
    
    ComputedPropertyDescriptor desc{};
    indexHandle = HermesValue::encodeNumberValue(sourceIndex);
    if (LLVM_UNLIKELY( JSObject::getComputedDescriptor( source, runtime, indexHandle, propObj, tmpPropNameStorage, desc) == ExecutionStatus::EXCEPTION)) {






      return ExecutionStatus::EXCEPTION;
    }
    
    
    CallResult<PseudoHandle<>> elementRes = JSObject::getComputedPropertyValue_RJS( source, runtime, propObj, tmpPropNameStorage, desc, indexHandle);

    if (LLVM_UNLIKELY(elementRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (LLVM_LIKELY(!(*elementRes)->isEmpty())) {
      element = std::move(*elementRes);

      
      if (mapperFunction) {
        
        assert(!thisArg->isEmpty() && "mapperFunction requires a thisArg");
        
        
        elementRes = Callable::executeCall3( mapperFunction, runtime, thisArg, element.getHermesValue(), HermesValue::encodeNumberValue(sourceIndex), source.getHermesValue());





        if (LLVM_UNLIKELY(elementRes == ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }
        element = std::move(*elementRes);
      }
      
      bool shouldFlatten = false;
      if (depth > 0) {
        
        
        
        CallResult<bool> shouldFlattenRes = isArray(runtime, dyn_vmcast<JSObject>(element.get()));
        if (LLVM_UNLIKELY(shouldFlattenRes == ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }
        shouldFlatten = *shouldFlattenRes;
      }
      if (shouldFlatten) {
        
        
        
        
        CallResult<PseudoHandle<>> lenRes = JSObject::getNamed_RJS( Handle<JSObject>::vmcast(element), runtime, Predefined::getSymbolID(Predefined::length));


        if (LLVM_UNLIKELY(lenRes == ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }
        lenResHandle = std::move(*lenRes);
        CallResult<uint64_t> elementLenRes = toLengthU64(runtime, lenResHandle);
        if (LLVM_UNLIKELY(elementLenRes == ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }
        uint64_t elementLen = *elementLenRes;
        
        
        CallResult<uint64_t> targetIndexRes = flattenIntoArray( runtime, target, Handle<JSObject>::vmcast(element), elementLen, targetIndex, depth - 1, runtime.makeNullHandle<Callable>(), runtime.getUndefinedValue());







        if (LLVM_UNLIKELY(targetIndexRes == ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }
        targetIndex = *targetIndexRes;
      } else {
        
        
        if (targetIndex >= ((uint64_t)1 << 53) - 1) {
          return runtime.raiseTypeError("flattened array exceeds length limit");
        }
        
        
        indexHandle = HermesValue::encodeNumberValue(targetIndex);
        if (LLVM_UNLIKELY( JSObject::defineOwnComputed( target, runtime, indexHandle, DefinePropertyFlags::getDefaultNewPropertyFlags(), element, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {







          return ExecutionStatus::EXCEPTION;
        }

        
        ++targetIndex;
      }
    }
    
    ++sourceIndex;
  }
  
  return targetIndex;
}

CallResult<HermesValue> arrayPrototypeFlat(void *ctx, Runtime &runtime, NativeArgs args) {
  
  CallResult<HermesValue> ORes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(ORes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(*ORes);

  
  CallResult<PseudoHandle<>> lenRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(lenRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  CallResult<uint64_t> sourceLenRes = toLengthU64(runtime, runtime.makeHandle(std::move(*lenRes)));
  if (LLVM_UNLIKELY(sourceLenRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  uint64_t sourceLen = *sourceLenRes;

  
  double depthNum = 1;
  if (!args.getArg(0).isUndefined()) {
    
    
    auto depthNumRes = toIntegerOrInfinity(runtime, args.getArgHandle(0));
    if (LLVM_UNLIKELY(depthNumRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    depthNum = depthNumRes->getNumber();
  }
  
  auto ARes = JSArray::create(runtime, 0, 0);
  if (LLVM_UNLIKELY(ARes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto A = *ARes;

  
  if (LLVM_UNLIKELY( flattenIntoArray( runtime, A, O, sourceLen, 0, depthNum, runtime.makeNullHandle<Callable>(), runtime.getUndefinedValue()) == ExecutionStatus::EXCEPTION)) {








    return ExecutionStatus::EXCEPTION;
  }

  
  return A.getHermesValue();
}

CallResult<HermesValue> arrayPrototypeFlatMap(void *ctx, Runtime &runtime, NativeArgs args) {
  
  CallResult<HermesValue> ORes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(ORes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(*ORes);

  
  CallResult<PseudoHandle<>> lenRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(lenRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  CallResult<uint64_t> sourceLenRes = toLengthU64(runtime, runtime.makeHandle(std::move(*lenRes)));
  if (LLVM_UNLIKELY(sourceLenRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  uint64_t sourceLen = *sourceLenRes;

  
  Handle<Callable> mapperFunction = args.dyncastArg<Callable>(0);
  if (!mapperFunction) {
    return runtime.raiseTypeError("flatMap mapper must be callable");
  }
  
  auto T = args.getArgHandle(1);
  
  auto ARes = JSArray::create(runtime, 0, 0);
  if (LLVM_UNLIKELY(ARes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto A = *ARes;

  
  if (LLVM_UNLIKELY( flattenIntoArray(runtime, A, O, sourceLen, 0, 1, mapperFunction, T) == ExecutionStatus::EXCEPTION)) {

    return ExecutionStatus::EXCEPTION;
  }
  
  return A.getHermesValue();
}

CallResult<HermesValue> arrayPrototypeIterator(void *ctx, Runtime &runtime, NativeArgs args) {
  IterationKind kind = *reinterpret_cast<IterationKind *>(&ctx);
  assert( kind < IterationKind::NumKinds && "arrayPrototypeIterator with wrong kind");

  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto obj = runtime.makeHandle<JSObject>(*objRes);
  return JSArrayIterator::create(runtime, obj, kind).getHermesValue();
}

CallResult<HermesValue> arrayPrototypeSlice(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(objRes.getValue());

  auto propRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto lenRes = toLengthU64(runtime, runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(lenRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double len = *lenRes;

  auto intRes = toIntegerOrInfinity(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  
  double relativeStart = intRes->getNumber();
  
  
  MutableHandle<> k{
      runtime, HermesValue::encodeDoubleValue( relativeStart < 0 ? std::max(len + relativeStart, 0.0)

                            : std::min(relativeStart, len))};

  
  double relativeEnd;
  if (args.getArg(1).isUndefined()) {
    relativeEnd = len;
  } else {
    if (LLVM_UNLIKELY( (intRes = toIntegerOrInfinity(runtime, args.getArgHandle(1))) == ExecutionStatus::EXCEPTION)) {

      return ExecutionStatus::EXCEPTION;
    }
    relativeEnd = intRes->getNumber();
  }
  
  double fin = relativeEnd < 0 ? std::max(len + relativeEnd, 0.0)
                               : std::min(relativeEnd, len);

  
  double count = std::max(fin - k->getNumber(), 0.0);
  if (LLVM_UNLIKELY(count > JSArray::StorageType::maxElements())) {
    return runtime.raiseRangeError("Out of memory for array elements.");
  }
  auto arrRes = JSArray::create(runtime, count, count);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto A = *arrRes;

  
  uint32_t n = 0;

  MutableHandle<JSObject> descObjHandle{runtime};
  MutableHandle<SymbolID> tmpPropNameStorage{runtime};
  MutableHandle<> kValue{runtime};
  auto marker = gcScope.createMarker();

  
  
  while (k->getNumber() < fin) {
    ComputedPropertyDescriptor desc;
    JSObject::getComputedPrimitiveDescriptor( O, runtime, k, descObjHandle, tmpPropNameStorage, desc);
    CallResult<PseudoHandle<>> propRes = JSObject::getComputedPropertyValue_RJS( O, runtime, descObjHandle, tmpPropNameStorage, desc, k);
    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (LLVM_LIKELY(!(*propRes)->isEmpty())) {
      kValue = std::move(*propRes);
      JSArray::setElementAt(A, runtime, n, kValue);
    }
    k = HermesValue::encodeDoubleValue(k->getNumber() + 1);
    ++n;

    gcScope.flushToMarker(marker);
  }

  if (LLVM_UNLIKELY( JSArray::setLengthProperty(A, runtime, n) == ExecutionStatus::EXCEPTION))

    return ExecutionStatus::EXCEPTION;
  return A.getHermesValue();
}

CallResult<HermesValue> arrayPrototypeSplice(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(objRes.getValue());

  auto propRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto lenRes = toLengthU64(runtime, runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(lenRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double len = *lenRes;

  auto intRes = toIntegerOrInfinity(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double relativeStart = intRes->getNumber();
  
  double actualStart = relativeStart < 0 ? std::max(len + relativeStart, 0.0)
                                         : std::min(relativeStart, len);

  
  
  uint32_t argCount = args.getArgCount();
  uint64_t actualDeleteCount;
  uint64_t insertCount;
  switch (argCount) {
    case 0:
      insertCount = 0;
      actualDeleteCount = 0;
      break;
    case 1:
      
      insertCount = 0;
      actualDeleteCount = len - actualStart;
      break;
    default:
      
      if (LLVM_UNLIKELY( (intRes = toIntegerOrInfinity(runtime, args.getArgHandle(1))) == ExecutionStatus::EXCEPTION)) {

        return ExecutionStatus::EXCEPTION;
      }
      insertCount = argCount - 2;
      actualDeleteCount = std::min(std::max(intRes->getNumber(), 0.0), len - actualStart);
  }

  
  
  auto lenAfterInsert = len + insertCount;
  if (LLVM_UNLIKELY( lenAfterInsert < len || lenAfterInsert - actualDeleteCount > (1LLU << 53) - 1)) {

    return runtime.raiseTypeError("Array.prototype.splice result out of space");
  }

  
  if (LLVM_UNLIKELY(actualDeleteCount > JSArray::StorageType::maxElements())) {
    return runtime.raiseRangeError("Out of memory for array elements.");
  }
  auto arrRes = JSArray::create(runtime, actualDeleteCount, actualDeleteCount);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto A = *arrRes;

  
  MutableHandle<> from{runtime};
  MutableHandle<> to{runtime};

  
  MutableHandle<SymbolID> tmpPropNameStorage{runtime};
  MutableHandle<JSObject> fromDescObjHandle{runtime};
  MutableHandle<> fromValue{runtime};

  MutableHandle<> i{runtime};
  MutableHandle<> k{runtime};

  auto gcMarker = gcScope.createMarker();

  {
    
    
    for (uint32_t j = 0; j < actualDeleteCount; ++j) {
      from = HermesValue::encodeDoubleValue(actualStart + j);

      ComputedPropertyDescriptor fromDesc;
      JSObject::getComputedPrimitiveDescriptor( O, runtime, from, fromDescObjHandle, tmpPropNameStorage, fromDesc);
      CallResult<PseudoHandle<>> propRes = JSObject::getComputedPropertyValue_RJS( O, runtime, fromDescObjHandle, tmpPropNameStorage, fromDesc, from);






      if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      if (LLVM_LIKELY(!(*propRes)->isEmpty())) {
        fromValue = std::move(*propRes);
        JSArray::setElementAt(A, runtime, j, fromValue);
      }

      gcScope.flushToMarker(gcMarker);
    }

    if (LLVM_UNLIKELY( JSArray::setLengthProperty(A, runtime, actualDeleteCount) == ExecutionStatus::EXCEPTION))

      return ExecutionStatus::EXCEPTION;
  }

  
  if (LLVM_UNLIKELY( JSObject::putNamed_RJS( A, runtime, Predefined::getSymbolID(Predefined::length), runtime.makeHandle( HermesValue::encodeNumberValue(actualDeleteCount)), PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {







    return ExecutionStatus::EXCEPTION;
  }

  
  uint32_t itemCount = args.getArgCount() > 2 ? args.getArgCount() - 2 : 0;

  if (itemCount < actualDeleteCount) {
    

    
    
    
    for (double j = actualStart; j < len - actualDeleteCount; ++j) {
      from = HermesValue::encodeDoubleValue(j + actualDeleteCount);
      to = HermesValue::encodeDoubleValue(j + itemCount);
      ComputedPropertyDescriptor fromDesc;
      JSObject::getComputedPrimitiveDescriptor( O, runtime, from, fromDescObjHandle, tmpPropNameStorage, fromDesc);
      CallResult<PseudoHandle<>> propRes = JSObject::getComputedPropertyValue_RJS( O, runtime, fromDescObjHandle, tmpPropNameStorage, fromDesc, from);






      if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      if (LLVM_LIKELY(!(*propRes)->isEmpty())) {
        fromValue = std::move(*propRes);
        if (LLVM_UNLIKELY( JSObject::putComputed_RJS( O, runtime, to, fromValue, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {






          return ExecutionStatus::EXCEPTION;
        }
      } else {
        if (LLVM_UNLIKELY( JSObject::deleteComputed( O, runtime, to, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {


          return ExecutionStatus::EXCEPTION;
        }
      }

      gcScope.flushToMarker(gcMarker);
    }

    
    i = HermesValue::encodeDoubleValue(len - 1);

    
    
    while (i->getNumber() > len - actualDeleteCount + itemCount - 1) {
      if (LLVM_UNLIKELY( JSObject::deleteComputed( O, runtime, i, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {


        return ExecutionStatus::EXCEPTION;
      }
      i = HermesValue::encodeDoubleValue(i->getDouble() - 1);
      gcScope.flushToMarker(gcMarker);
    }
  } else if (itemCount > actualDeleteCount) {
    

    
    
    
    for (double j = len - actualDeleteCount; j > actualStart; --j) {
      from = HermesValue::encodeDoubleValue(j + actualDeleteCount - 1);
      to = HermesValue::encodeDoubleValue(j + itemCount - 1);

      ComputedPropertyDescriptor fromDesc;
      JSObject::getComputedPrimitiveDescriptor( O, runtime, from, fromDescObjHandle, tmpPropNameStorage, fromDesc);
      CallResult<PseudoHandle<>> propRes = JSObject::getComputedPropertyValue_RJS( O, runtime, fromDescObjHandle, tmpPropNameStorage, fromDesc, from);






      if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      if (LLVM_LIKELY(!(*propRes)->isEmpty())) {
        fromValue = std::move(*propRes);
        if (LLVM_UNLIKELY( JSObject::putComputed_RJS( O, runtime, to, fromValue, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {






          return ExecutionStatus::EXCEPTION;
        }
      } else {
        
        if (LLVM_UNLIKELY( JSObject::deleteComputed( O, runtime, to, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {


          return ExecutionStatus::EXCEPTION;
        }
      }

      gcScope.flushToMarker(gcMarker);
    }
  }

  {
    
    
    k = HermesValue::encodeDoubleValue(actualStart);
    for (size_t j = 2; j < argCount; ++j) {
      if (LLVM_UNLIKELY( JSObject::putComputed_RJS( O, runtime, k, args.getArgHandle(j), PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {






        return ExecutionStatus::EXCEPTION;
      }
      k = HermesValue::encodeDoubleValue(k->getDouble() + 1);
      gcScope.flushToMarker(gcMarker);
    }
  }

  if (LLVM_UNLIKELY( JSObject::putNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length), runtime.makeHandle(HermesValue::encodeDoubleValue( len - actualDeleteCount + itemCount)), PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {







    return ExecutionStatus::EXCEPTION;
  }

  return A.getHermesValue();
}

CallResult<HermesValue> arrayPrototypeCopyWithin(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};

  
  
  auto oRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(oRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(*oRes);

  
  
  
  
  
  auto propRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto lenRes = toLengthU64(runtime, runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(lenRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double len = *lenRes;

  
  
  auto relativeTargetRes = toIntegerOrInfinity(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(relativeTargetRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double relativeTarget = relativeTargetRes->getNumber();

  
  
  double to = relativeTarget < 0 ? std::max((len + relativeTarget), (double)0)
                                 : std::min(relativeTarget, len);

  
  
  auto relativeStartRes = toIntegerOrInfinity(runtime, args.getArgHandle(1));
  if (LLVM_UNLIKELY(relativeStartRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double relativeStart = relativeStartRes->getNumber();

  
  
  double from = relativeStart < 0 ? std::max((len + relativeStart), (double)0)
                                  : std::min(relativeStart, len);

  
  
  
  double relativeEnd;
  if (args.getArg(2).isUndefined()) {
    relativeEnd = len;
  } else {
    auto relativeEndRes = toIntegerOrInfinity(runtime, args.getArgHandle(2));
    if (LLVM_UNLIKELY(relativeEndRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    relativeEnd = relativeEndRes->getNumber();
  }

  
  
  double fin = relativeEnd < 0 ? std::max((len + relativeEnd), (double)0)
                               : std::min(relativeEnd, len);

  
  double count = std::min(fin - from, len - to);

  int direction;
  if (from < to && to < from + count) {
    
    
    direction = -1;
    
    from = from + count - 1;
    
    to = to + count - 1;
  } else {
    
    
    direction = 1;
  }

  MutableHandle<> fromHandle{runtime, HermesValue::encodeNumberValue(from)};
  MutableHandle<> toHandle{runtime, HermesValue::encodeNumberValue(to)};

  MutableHandle<SymbolID> fromNameTmpStorage{runtime};
  MutableHandle<JSObject> fromObj{runtime};
  MutableHandle<> fromVal{runtime};

  GCScopeMarkerRAII marker{gcScope};
  for (; count > 0; marker.flush()) {
    
    
    

    
    
    ComputedPropertyDescriptor fromDesc;
    if (LLVM_UNLIKELY( JSObject::getComputedDescriptor( O, runtime, fromHandle, fromObj, fromNameTmpStorage, fromDesc) == ExecutionStatus::EXCEPTION)) {






      return ExecutionStatus::EXCEPTION;
    }
    CallResult<PseudoHandle<>> fromValRes = JSObject::getComputedPropertyValue_RJS( O, runtime, fromObj, fromNameTmpStorage, fromDesc, fromHandle);

    if (LLVM_UNLIKELY(fromValRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    
    if (LLVM_LIKELY(!(*fromValRes)->isEmpty())) {
      
      
      fromVal = std::move(*fromValRes);

      
      
      if (LLVM_UNLIKELY( JSObject::putComputed_RJS( O, runtime, toHandle, fromVal, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {






        return ExecutionStatus::EXCEPTION;
      }
    } else {
      
      
      
      if (LLVM_UNLIKELY( JSObject::deleteComputed( O, runtime, toHandle, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {


        return ExecutionStatus::EXCEPTION;
      }
    }

    
    fromHandle = HermesValue::encodeNumberValue(fromHandle->getNumber() + direction);
    
    toHandle = HermesValue::encodeNumberValue(toHandle->getNumber() + direction);

    
    --count;
  }
  
  return O.getHermesValue();
}

CallResult<HermesValue> arrayPrototypePop(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);
  auto res = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(res.getValue());

  auto propRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto intRes = toLengthU64(runtime, runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  uint64_t len = *intRes;

  if (len == 0) {
    if (LLVM_UNLIKELY( JSObject::putNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length), runtime.makeHandle(HermesValue::encodeDoubleValue(0)), PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION))






      return ExecutionStatus::EXCEPTION;
    return HermesValue::encodeUndefinedValue();
  }

  auto idxVal = runtime.makeHandle(HermesValue::encodeDoubleValue(len - 1));
  if (LLVM_UNLIKELY( (propRes = JSObject::getComputed_RJS(O, runtime, idxVal)) == ExecutionStatus::EXCEPTION)) {

    return ExecutionStatus::EXCEPTION;
  }
  auto element = runtime.makeHandle(std::move(*propRes));
  if (LLVM_UNLIKELY( JSObject::deleteComputed( O, runtime, idxVal, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {


    return ExecutionStatus::EXCEPTION;
  }

  if (LLVM_UNLIKELY( JSObject::putNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length), runtime.makeHandle(HermesValue::encodeDoubleValue(len - 1)), PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION))





    return ExecutionStatus::EXCEPTION;
  return element.get();
}

CallResult<HermesValue> arrayPrototypeShift(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(objRes.getValue());

  auto propRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto intRes = toLengthU64(runtime, runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  uint64_t len = *intRes;

  if (len == 0) {
    
    if (JSObject::putNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length), runtime.makeHandle(HermesValue::encodeDoubleValue(0)), PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)




      return ExecutionStatus::EXCEPTION;
    return HermesValue::encodeUndefinedValue();
  }

  auto idxVal = runtime.makeHandle(HermesValue::encodeDoubleValue(0));
  if (LLVM_UNLIKELY( (propRes = JSObject::getComputed_RJS(O, runtime, idxVal)) == ExecutionStatus::EXCEPTION)) {

    return ExecutionStatus::EXCEPTION;
  }
  auto first = runtime.makeHandle(std::move(*propRes));

  MutableHandle<> from{runtime, HermesValue::encodeDoubleValue(1)};
  MutableHandle<> to{runtime};

  MutableHandle<SymbolID> fromNameTmpStorage{runtime};
  MutableHandle<JSObject> fromDescObjHandle{runtime};
  MutableHandle<> fromVal{runtime};

  
  
  while (from->getDouble() < len) {
    GCScopeMarkerRAII marker{gcScope};

    
    to = HermesValue::encodeDoubleValue(from->getDouble() - 1);

    ComputedPropertyDescriptor fromDesc;
    JSObject::getComputedPrimitiveDescriptor( O, runtime, from, fromDescObjHandle, fromNameTmpStorage, fromDesc);
    CallResult<PseudoHandle<>> propRes = JSObject::getComputedPropertyValue_RJS( O, runtime, fromDescObjHandle, fromNameTmpStorage, fromDesc, from);
    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }

    if (LLVM_LIKELY(!(*propRes)->isEmpty())) {
      
      fromVal = std::move(*propRes);
      if (LLVM_UNLIKELY( JSObject::putComputed_RJS( O, runtime, to, fromVal, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {


        return ExecutionStatus::EXCEPTION;
      }
    } else {
      
      if (LLVM_UNLIKELY( JSObject::deleteComputed( O, runtime, to, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {


        return ExecutionStatus::EXCEPTION;
      }
    }

    from = HermesValue::encodeDoubleValue(from->getDouble() + 1);
  }

  
  if (LLVM_UNLIKELY( JSObject::deleteComputed( O, runtime, runtime.makeHandle(HermesValue::encodeDoubleValue(len - 1)), PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {





    return ExecutionStatus::EXCEPTION;
  }

  
  if (LLVM_UNLIKELY( JSObject::putNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length), runtime.makeHandle(HermesValue::encodeDoubleValue(len - 1)), PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION))





    return ExecutionStatus::EXCEPTION;
  return first.get();
}



static inline CallResult<HermesValue> indexOfHelper(Runtime &runtime, NativeArgs args, const bool reverse) {
  GCScope gcScope(runtime);
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(objRes.getValue());

  auto propRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto lenRes = toLengthU64(runtime, runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(lenRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double len = *lenRes;

  
  
  
  if (len == 0) {
    return HermesValue::encodeDoubleValue(-1);
  }

  
  auto intRes = toIntegerOrInfinity(runtime, args.getArgHandle(1));
  double n;
  if (args.getArgCount() > 1) {
    if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    n = intRes->getNumber();
    if (LLVM_UNLIKELY(n == 0)) {
      
      n = 0;
    }
  } else {
    n = !reverse ? 0 : len - 1;
  }

  
  MutableHandle<> k{runtime};
  if (!reverse) {
    if (n >= 0) {
      k = HermesValue::encodeDoubleValue(n);
    } else {
      
      k = HermesValue::encodeDoubleValue(std::max(len - std::abs(n), 0.0));
    }
  } else {
    if (n >= 0) {
      k = HermesValue::encodeDoubleValue(std::min(n, len - 1));
    } else {
      k = HermesValue::encodeDoubleValue(len - std::abs(n));
    }
  }

  MutableHandle<SymbolID> tmpPropNameStorage{runtime};
  MutableHandle<JSObject> descObjHandle{runtime};

  
  auto searchElement = args.getArgHandle(0);
  auto marker = gcScope.createMarker();
  while (true) {
    gcScope.flushToMarker(marker);
    
    if (!reverse) {
      if (k->getDouble() >= len) {
        break;
      }
    } else {
      if (k->getDouble() < 0) {
        break;
      }
    }
    ComputedPropertyDescriptor desc;
    JSObject::getComputedPrimitiveDescriptor( O, runtime, k, descObjHandle, tmpPropNameStorage, desc);
    CallResult<PseudoHandle<>> propRes = JSObject::getComputedPropertyValue_RJS( O, runtime, descObjHandle, tmpPropNameStorage, desc, k);
    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (!(*propRes)->isEmpty() && strictEqualityTest(searchElement.get(), propRes->get())) {
      return k.get();
    }
    
    k = HermesValue::encodeDoubleValue(k->getDouble() + (reverse ? -1 : 1));
  }

  
  return HermesValue::encodeDoubleValue(-1);
}

CallResult<HermesValue> arrayPrototypeUnshift(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(objRes.getValue());

  auto propRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto intRes = toLengthU64(runtime, runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  uint64_t len = *intRes;
  size_t argCount = args.getArgCount();

  
  if (argCount > 0) {
    
    if (LLVM_UNLIKELY(len + argCount >= ((uint64_t)1 << 53) - 1)) {
      return runtime.raiseTypeError( "Array.prototype.unshift result out of space");
    }

    
    MutableHandle<> k{runtime, HermesValue::encodeDoubleValue(len)};
    MutableHandle<> j{runtime, HermesValue::encodeDoubleValue(0)};

    
    MutableHandle<> from{runtime};
    MutableHandle<> to{runtime};

    
    MutableHandle<SymbolID> fromNameTmpStorage{runtime};
    MutableHandle<JSObject> fromDescObjHandle{runtime};
    MutableHandle<> fromValue{runtime};

    
    
    auto marker = gcScope.createMarker();
    while (k->getDouble() > 0) {
      gcScope.flushToMarker(marker);
      from = HermesValue::encodeDoubleValue(k->getDouble() - 1);
      to = HermesValue::encodeDoubleValue(k->getDouble() + argCount - 1);

      ComputedPropertyDescriptor fromDesc;
      JSObject::getComputedPrimitiveDescriptor( O, runtime, from, fromDescObjHandle, fromNameTmpStorage, fromDesc);
      CallResult<PseudoHandle<>> propRes = JSObject::getComputedPropertyValue_RJS( O, runtime, fromDescObjHandle, fromNameTmpStorage, fromDesc, from);






      if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }

      if (LLVM_LIKELY(!(*propRes)->isEmpty())) {
        fromValue = std::move(*propRes);
        if (LLVM_UNLIKELY( JSObject::putComputed_RJS( O, runtime, to, fromValue, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {






          return ExecutionStatus::EXCEPTION;
        }
      } else {
        
        if (LLVM_UNLIKELY( JSObject::deleteComputed( O, runtime, to, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {


          return ExecutionStatus::EXCEPTION;
        }
      }
      k = HermesValue::encodeDoubleValue(k->getDouble() - 1);
    }

    
    for (auto arg : args.handles()) {
      if (LLVM_UNLIKELY( JSObject::putComputed_RJS( O, runtime, j, arg, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {


        return ExecutionStatus::EXCEPTION;
      }
      gcScope.flushToMarker(marker);
      j = HermesValue::encodeDoubleValue(j->getDouble() + 1);
    }
  }

  
  auto newLen = HermesValue::encodeDoubleValue(len + argCount);
  if (LLVM_UNLIKELY( JSObject::putNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length), runtime.makeHandle(newLen), PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION))





    return ExecutionStatus::EXCEPTION;
  return newLen;
}

CallResult<HermesValue> arrayPrototypeIndexOf(void *, Runtime &runtime, NativeArgs args) {
  return indexOfHelper(runtime, args, false);
}

CallResult<HermesValue> arrayPrototypeLastIndexOf(void *, Runtime &runtime, NativeArgs args) {
  return indexOfHelper(runtime, args, true);
}



static inline CallResult<HermesValue> everySomeHelper(Runtime &runtime, NativeArgs args, const bool every) {
  GCScope gcScope(runtime);
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(objRes.getValue());

  auto propRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto intRes = toLengthU64(runtime, runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  uint64_t len = *intRes;

  auto callbackFn = args.dyncastArg<Callable>(0);
  if (!callbackFn) {
    return runtime.raiseTypeError( "Array.prototype.every() requires a callable argument");
  }

  
  MutableHandle<> k{runtime, HermesValue::encodeDoubleValue(0)};

  
  MutableHandle<SymbolID> tmpPropNameStorage{runtime};
  MutableHandle<JSObject> descObjHandle{runtime};
  MutableHandle<> kValue{runtime};

  
  auto marker = gcScope.createMarker();
  while (k->getDouble() < len) {
    gcScope.flushToMarker(marker);

    ComputedPropertyDescriptor desc;
    JSObject::getComputedPrimitiveDescriptor( O, runtime, k, descObjHandle, tmpPropNameStorage, desc);
    CallResult<PseudoHandle<>> propRes = JSObject::getComputedPropertyValue_RJS( O, runtime, descObjHandle, tmpPropNameStorage, desc, k);
    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (LLVM_LIKELY(!(*propRes)->isEmpty())) {
      
      kValue = std::move(*propRes);
      auto callRes = Callable::executeCall3( callbackFn, runtime, args.getArgHandle(1), kValue.get(), k.get(), O.getHermesValue());





      if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      auto testResult = std::move(*callRes);
      if (every) {
        
        if (!toBoolean(testResult.get())) {
          return HermesValue::encodeBoolValue(false);
        }
      } else {
        
        if (toBoolean(testResult.get())) {
          return HermesValue::encodeBoolValue(true);
        }
      }
    }

    k = HermesValue::encodeDoubleValue(k->getDouble() + 1);
  }

  
  
  return HermesValue::encodeBoolValue(every);
}

CallResult<HermesValue> arrayPrototypeEvery(void *, Runtime &runtime, NativeArgs args) {
  return everySomeHelper(runtime, args, true);
}

CallResult<HermesValue> arrayPrototypeSome(void *, Runtime &runtime, NativeArgs args) {
  return everySomeHelper(runtime, args, false);
}

CallResult<HermesValue> arrayPrototypeMap(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(objRes.getValue());

  auto propRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto intRes = toLengthU64(runtime, runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  uint64_t len = *intRes;

  auto callbackFn = args.dyncastArg<Callable>(0);
  if (!callbackFn) {
    return runtime.raiseTypeError( "Array.prototype.map() requires a callable argument");
  }

  
  if (LLVM_UNLIKELY(len > JSArray::StorageType::maxElements())) {
    return runtime.raiseRangeError("Out of memory for array elements.");
  }
  auto arrRes = JSArray::create(runtime, len, len);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto A = *arrRes;

  
  MutableHandle<> k{runtime, HermesValue::encodeDoubleValue(0)};

  MutableHandle<SymbolID> tmpPropNameStorage{runtime};
  MutableHandle<JSObject> descObjHandle{runtime};

  
  
  auto marker = gcScope.createMarker();
  while (k->getDouble() < len) {
    gcScope.flushToMarker(marker);

    ComputedPropertyDescriptor desc;
    JSObject::getComputedPrimitiveDescriptor( O, runtime, k, descObjHandle, tmpPropNameStorage, desc);
    CallResult<PseudoHandle<>> propRes = JSObject::getComputedPropertyValue_RJS( O, runtime, descObjHandle, tmpPropNameStorage, desc, k);
    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (LLVM_LIKELY(!(*propRes)->isEmpty())) {
      
      auto kValue = std::move(*propRes);
      auto callRes = Callable::executeCall3( callbackFn, runtime, args.getArgHandle(1), kValue.get(), k.get(), O.getHermesValue());





      if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      JSArray::setElementAt( A, runtime, k->getDouble(), runtime.makeHandle(std::move(*callRes)));
    }

    k = HermesValue::encodeDoubleValue(k->getDouble() + 1);
  }

  return A.getHermesValue();
}

CallResult<HermesValue> arrayPrototypeFilter(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(objRes.getValue());

  auto propRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto intRes = toLengthU64(runtime, runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  uint64_t len = *intRes;

  auto callbackFn = args.dyncastArg<Callable>(0);
  if (!callbackFn) {
    return runtime.raiseTypeError( "Array.prototype.filter() requires a callable argument");
  }

  if (LLVM_UNLIKELY(len > JSArray::StorageType::maxElements())) {
    return runtime.raiseRangeError("Out of memory for array elements.");
  }
  auto arrRes = JSArray::create(runtime, len, 0);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto A = *arrRes;

  
  MutableHandle<> k{runtime, HermesValue::encodeDoubleValue(0)};
  
  uint32_t to = 0;

  
  MutableHandle<SymbolID> tmpPropNameStorage{runtime};
  MutableHandle<JSObject> descObjHandle{runtime};
  MutableHandle<> kValue{runtime};

  auto marker = gcScope.createMarker();
  while (k->getDouble() < len) {
    gcScope.flushToMarker(marker);

    ComputedPropertyDescriptor desc;
    JSObject::getComputedPrimitiveDescriptor( O, runtime, k, descObjHandle, tmpPropNameStorage, desc);
    CallResult<PseudoHandle<>> propRes = JSObject::getComputedPropertyValue_RJS( O, runtime, descObjHandle, tmpPropNameStorage, desc, k);
    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (LLVM_LIKELY(!(*propRes)->isEmpty())) {
      kValue = std::move(*propRes);
      
      auto callRes = Callable::executeCall3( callbackFn, runtime, args.getArgHandle(1), kValue.get(), k.get(), O.getHermesValue());





      if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      if (toBoolean(callRes->get())) {
        
        JSArray::setElementAt(A, runtime, to, kValue);
        ++to;
      }
    }

    k = HermesValue::encodeDoubleValue(k->getDouble() + 1);
  }

  if (LLVM_UNLIKELY( JSArray::setLengthProperty(A, runtime, to) == ExecutionStatus::EXCEPTION))

    return ExecutionStatus::EXCEPTION;
  return A.getHermesValue();
}

CallResult<HermesValue> arrayPrototypeFill(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(objRes.getValue());
  
  auto propRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto lenRes = toLengthU64(runtime, runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(lenRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double len = *lenRes;
  
  MutableHandle<> value(runtime, args.getArg(0));
  
  auto intRes = toIntegerOrInfinity(runtime, args.getArgHandle(1));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double relativeStart = intRes->getNumber();
  
  double actualStart = relativeStart < 0 ? std::max(len + relativeStart, 0.0)
                                         : std::min(relativeStart, len);
  double relativeEnd;
  if (args.getArg(2).isUndefined()) {
    relativeEnd = len;
  } else {
    if (LLVM_UNLIKELY( (intRes = toIntegerOrInfinity(runtime, args.getArgHandle(2))) == ExecutionStatus::EXCEPTION)) {

      return ExecutionStatus::EXCEPTION;
    }
    relativeEnd = intRes->getNumber();
  }
  
  double actualEnd = relativeEnd < 0 ? std::max(len + relativeEnd, 0.0)
                                     : std::min(relativeEnd, len);
  MutableHandle<> k(runtime, HermesValue::encodeDoubleValue(actualStart));
  auto marker = gcScope.createMarker();
  while (k->getDouble() < actualEnd) {
    if (LLVM_UNLIKELY( JSObject::putComputed_RJS( O, runtime, k, value, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {


      return ExecutionStatus::EXCEPTION;
    }
    k.set(HermesValue::encodeDoubleValue(k->getDouble() + 1));
    gcScope.flushToMarker(marker);
  }
  return O.getHermesValue();
}

static CallResult<HermesValue> findHelper(void *ctx, bool reverse, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};
  bool findIndex = ctx != nullptr;
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(objRes.getValue());

  
  auto propRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto intRes = toLengthU64(runtime, runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double len = *intRes;

  auto predicate = args.dyncastArg<Callable>(0);
  if (!predicate) {
    return runtime.raiseTypeError("Find argument must be a function");
  }

  
  auto T = args.getArgHandle(1);
  MutableHandle<> kHandle{runtime};
  MutableHandle<> kValue{runtime};
  auto marker = gcScope.createMarker();
  for (size_t i = 0; i < len; ++i) {
    kHandle = HermesValue::encodeNumberValue(reverse ? (len - i - 1) : i);
    gcScope.flushToMarker(marker);
    if (LLVM_UNLIKELY( (propRes = JSObject::getComputed_RJS(O, runtime, kHandle)) == ExecutionStatus::EXCEPTION)) {

      return ExecutionStatus::EXCEPTION;
    }
    kValue = std::move(*propRes);
    auto callRes = Callable::executeCall3( predicate, runtime, T, kValue.getHermesValue(), kHandle.getHermesValue(), O.getHermesValue());





    if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    bool testResult = toBoolean(callRes->get());
    if (testResult) {
      
      
      return findIndex ? kHandle.getHermesValue() : kValue.getHermesValue();
    }
  }

  
  
  
  return findIndex ? HermesValue::encodeNumberValue(-1)
                   : HermesValue::encodeUndefinedValue();
}

CallResult<HermesValue> arrayPrototypeFind(void *ctx, Runtime &runtime, NativeArgs args) {
  return findHelper(ctx, false, runtime, args);
}

CallResult<HermesValue> arrayPrototypeFindLast(void *ctx, Runtime &runtime, NativeArgs args) {
  return findHelper(ctx, true, runtime, args);
}



static inline CallResult<HermesValue> reduceHelper(Runtime &runtime, NativeArgs args, const bool reverse) {
  GCScope gcScope(runtime);
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(objRes.getValue());

  auto propRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto intRes = toLengthU64(runtime, runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(intRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double len = *intRes;

  size_t argCount = args.getArgCount();

  auto callbackFn = args.dyncastArg<Callable>(0);
  if (!callbackFn) {
    return runtime.raiseTypeError( "Array.prototype.reduce() requires a callable argument");
  }

  
  if (len == 0 && argCount < 2) {
    return runtime.raiseTypeError( "Array.prototype.reduce() requires an initial value with empty array");
  }

  
  MutableHandle<> k{
      runtime, HermesValue::encodeDoubleValue(reverse ? len - 1 : 0)};
  MutableHandle<SymbolID> kNameTmpStorage{runtime};
  MutableHandle<JSObject> kDescObjHandle{runtime};

  MutableHandle<> accumulator{runtime};

  auto marker = gcScope.createMarker();

  
  double increment = reverse ? -1 : 1;

  
  
  if (argCount >= 2) {
    accumulator = args.getArg(1);
  } else {
    bool kPresent = false;
    while (!kPresent) {
      gcScope.flushToMarker(marker);
      if (!reverse) {
        if (k->getDouble() >= len) {
          break;
        }
      } else {
        if (k->getDouble() < 0) {
          break;
        }
      }
      ComputedPropertyDescriptor kDesc;
      JSObject::getComputedPrimitiveDescriptor( O, runtime, k, kDescObjHandle, kNameTmpStorage, kDesc);
      CallResult<PseudoHandle<>> propRes = JSObject::getComputedPropertyValue_RJS( O, runtime, kDescObjHandle, kNameTmpStorage, kDesc, k);

      if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      if (LLVM_LIKELY(!(*propRes)->isEmpty())) {
        kPresent = true;
        accumulator = std::move(*propRes);
      }
      k = HermesValue::encodeDoubleValue(k->getDouble() + increment);
    }
    if (!kPresent) {
      return runtime.raiseTypeError( "Array.prototype.reduce() requires an intial value with empty array");
    }
  }

  
  while (true) {
    gcScope.flushToMarker(marker);
    if (!reverse) {
      if (k->getDouble() >= len) {
        break;
      }
    } else {
      if (k->getDouble() < 0) {
        break;
      }
    }

    ComputedPropertyDescriptor kDesc;
    JSObject::getComputedPrimitiveDescriptor( O, runtime, k, kDescObjHandle, kNameTmpStorage, kDesc);
    CallResult<PseudoHandle<>> propRes = JSObject::getComputedPropertyValue_RJS( O, runtime, kDescObjHandle, kNameTmpStorage, kDesc, k);
    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (LLVM_LIKELY(!(*propRes)->isEmpty())) {
      
      auto kValue = std::move(*propRes);
      auto callRes = Callable::executeCall4( callbackFn, runtime, Runtime::getUndefinedValue(), accumulator.get(), kValue.get(), k.get(), O.getHermesValue());






      if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      accumulator = std::move(*callRes);
    }
    k = HermesValue::encodeDoubleValue(k->getDouble() + increment);
  }

  return accumulator.get();
}

CallResult<HermesValue> arrayPrototypeReduce(void *, Runtime &runtime, NativeArgs args) {
  return reduceHelper(runtime, args, false);
}

CallResult<HermesValue> arrayPrototypeReduceRight(void *, Runtime &runtime, NativeArgs args) {
  return reduceHelper(runtime, args, true);
}


CallResult<HermesValue> arrayPrototypeReverse(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);
  auto objRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(objRes.getValue());

  MutableHandle<> lower{runtime, HermesValue::encodeDoubleValue(0)};
  MutableHandle<> upper{runtime};

  
  MutableHandle<> lowerValue{runtime};
  MutableHandle<> upperValue{runtime};

  auto marker = gcScope.createMarker();

  auto propRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto lenRes = toLengthU64(runtime, runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(lenRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  uint64_t len = *lenRes;

  
  uint64_t middle = len / 2;

  while (lower->getDouble() != middle) {
    gcScope.flushToMarker(marker);
    upper = HermesValue::encodeDoubleValue(len - lower->getNumber() - 1);

    CallResult<bool> lowerExistsRes = JSObject::hasComputed(O, runtime, lower);
    if (LLVM_UNLIKELY(lowerExistsRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (*lowerExistsRes) {
      CallResult<PseudoHandle<>> lowerValueRes = JSObject::getComputed_RJS(O, runtime, lower);
      if (LLVM_UNLIKELY(lowerValueRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      lowerValue = std::move(*lowerValueRes);
      gcScope.flushToMarker(marker);
    }

    CallResult<bool> upperExistsRes = JSObject::hasComputed(O, runtime, upper);
    if (LLVM_UNLIKELY(upperExistsRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (*upperExistsRes) {
      CallResult<PseudoHandle<>> upperValueRes = JSObject::getComputed_RJS(O, runtime, upper);
      if (LLVM_UNLIKELY(upperValueRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      upperValue = std::move(*upperValueRes);
      gcScope.flushToMarker(marker);
    }

    
    if (*lowerExistsRes && *upperExistsRes) {
      if (LLVM_UNLIKELY( JSObject::putComputed_RJS( O, runtime, lower, upperValue, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {






        return ExecutionStatus::EXCEPTION;
      }
      if (LLVM_UNLIKELY( JSObject::putComputed_RJS( O, runtime, upper, lowerValue, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {






        return ExecutionStatus::EXCEPTION;
      }
    } else if (*upperExistsRes) {
      if (LLVM_UNLIKELY( JSObject::putComputed_RJS( O, runtime, lower, upperValue, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {






        return ExecutionStatus::EXCEPTION;
      }
      if (LLVM_UNLIKELY( JSObject::deleteComputed( O, runtime, upper, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {


        return ExecutionStatus::EXCEPTION;
      }
    } else if (*lowerExistsRes) {
      if (LLVM_UNLIKELY( JSObject::deleteComputed( O, runtime, lower, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {


        return ExecutionStatus::EXCEPTION;
      }
      if (LLVM_UNLIKELY( JSObject::putComputed_RJS( O, runtime, upper, lowerValue, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {






        return ExecutionStatus::EXCEPTION;
      }
    }

    lower = HermesValue::encodeDoubleValue(lower->getDouble() + 1);
  }

  return O.getHermesValue();
}

CallResult<HermesValue> arrayPrototypeIncludes(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};

  
  auto oRes = toObject(runtime, args.getThisHandle());
  if (LLVM_UNLIKELY(oRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto O = runtime.makeHandle<JSObject>(*oRes);

  
  auto lenPropRes = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(lenPropRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto lenRes = toLengthU64(runtime, runtime.makeHandle(std::move(*lenPropRes)));
  if (LLVM_UNLIKELY(lenRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double len = *lenRes;

  
  if (len == 0) {
    return HermesValue::encodeBoolValue(false);
  }

  
  
  auto nRes = toIntegerOrInfinity(runtime, args.getArgHandle(1));
  if (LLVM_UNLIKELY(nRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  
  double n = nRes->getNumber();

  double k;
  if (n >= 0) {
    
    
    k = n;
  } else {
    
    
    k = len + n;
    
    if (k < 0) {
      k = 0;
    }
  }

  MutableHandle<> kHandle{runtime};

  
  auto marker = gcScope.createMarker();
  while (k < len) {
    gcScope.flushToMarker(marker);

    
    kHandle = HermesValue::encodeNumberValue(k);
    auto elementKRes = JSObject::getComputed_RJS(O, runtime, kHandle);
    if (LLVM_UNLIKELY(elementKRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }

    
    if (isSameValueZero(args.getArg(0), elementKRes->get())) {
      return HermesValue::encodeBoolValue(true);
    }

    
    ++k;
  }

  
  return HermesValue::encodeBoolValue(false);
}

CallResult<HermesValue> arrayOf(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};

  
  uint32_t len = args.getArgCount();
  
  
  auto C = args.getThisHandle();

  MutableHandle<JSObject> A{runtime};
  CallResult<bool> isConstructorRes = isConstructor(runtime, *C);
  if (LLVM_UNLIKELY(isConstructorRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  
  if (*isConstructorRes) {
    
    auto aRes = Callable::executeConstruct1( Handle<Callable>::vmcast(C), runtime, runtime.makeHandle(HermesValue::encodeNumberValue(len)));


    if (LLVM_UNLIKELY(aRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    A = PseudoHandle<JSObject>::vmcast(std::move(*aRes));
  } else {
    
    
    auto aRes = JSArray::create(runtime, len, len);
    if (LLVM_UNLIKELY(aRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    A = vmcast<JSObject>(aRes->getHermesValue());
  }
  
  MutableHandle<> k{runtime, HermesValue::encodeNumberValue(0)};
  MutableHandle<> kValue{runtime};

  GCScopeMarkerRAII marker{gcScope};
  
  for (; k->getNumberAs<uint32_t>() < len; marker.flush()) {
    
    kValue = args.getArg(k->getNumber());

    
    if (LLVM_UNLIKELY( JSObject::defineOwnComputedPrimitive( A, runtime, k, DefinePropertyFlags::getDefaultNewPropertyFlags(), kValue, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {







      return ExecutionStatus::EXCEPTION;
    }

    
    k = HermesValue::encodeNumberValue(k->getNumber() + 1);
  }

  
  
  auto setStatus = JSObject::putNamed_RJS( A, runtime, Predefined::getSymbolID(Predefined::length), runtime.makeHandle(HermesValue::encodeNumberValue(len)), PropOpFlags().plusThrowOnError());




  if (LLVM_UNLIKELY(setStatus == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  
  return A.getHermesValue();
}


CallResult<HermesValue> arrayFrom(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};
  auto itemsHandle = args.getArgHandle(0);
  
  auto C = args.getThisHandle();
  
  
  MutableHandle<Callable> mapfn{runtime};
  MutableHandle<> T{runtime, HermesValue::encodeUndefinedValue()};
  if (!args.getArg(1).isUndefined()) {
    mapfn = dyn_vmcast<Callable>(args.getArg(1));
    
    if (LLVM_UNLIKELY(!mapfn)) {
      return runtime.raiseTypeError("Mapping function is not callable.");
    }
    
    if (args.getArgCount() >= 3) {
      T = args.getArg(2);
    }
    
  }
  
  
  auto methodRes = getMethod( runtime, itemsHandle, runtime.makeHandle(Predefined::getSymbolID(Predefined::SymbolIterator)));


  if (LLVM_UNLIKELY(methodRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto usingIterator = runtime.makeHandle(methodRes->getHermesValue());

  MutableHandle<JSObject> A{runtime};
  
  if (!usingIterator->isUndefined()) {
    CallResult<bool> isConstructorRes = isConstructor(runtime, *C);
    if (LLVM_UNLIKELY(isConstructorRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    
    if (*isConstructorRes) {
      GCScopeMarkerRAII markerConstruct{gcScope};
      
      auto callRes = Callable::executeConstruct0(Handle<Callable>::vmcast(C), runtime);
      if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      A = PseudoHandle<JSObject>::vmcast(std::move(*callRes));
    } else {
      
      
      auto arrRes = JSArray::create(runtime, 0, 0);
      if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      A = arrRes->get();
    }
    
    
    
    
    
    auto iterRes = getIterator( runtime, args.getArgHandle(0), Handle<Callable>::vmcast(usingIterator));
    if (LLVM_UNLIKELY(iterRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    auto iteratorRecord = *iterRes;
    
    MutableHandle<> k{runtime, HermesValue::encodeNumberValue(0)};
    
    MutableHandle<> mappedValue{runtime};
    MutableHandle<> nextValue{runtime};
    while (true) {
      GCScopeMarkerRAII marker1{runtime};
      
      
      auto next = iteratorStep(runtime, iteratorRecord);
      if (LLVM_UNLIKELY(next == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      
      if (!next.getValue()) {
        
        
        
        auto setStatus = JSObject::putNamed_RJS( A, runtime, Predefined::getSymbolID(Predefined::length), k, PropOpFlags().plusThrowOnError());




        if (LLVM_UNLIKELY(setStatus == ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }
        return A.getHermesValue();
      }
      
      
      auto propRes = JSObject::getNamed_RJS( *next, runtime, Predefined::getSymbolID(Predefined::value));
      if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      nextValue = std::move(*propRes);
      
      if (mapfn) {
        
        auto callRes = Callable::executeCall2( mapfn, runtime, T, nextValue.getHermesValue(), k.getHermesValue());
        
        
        if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
          return iteratorCloseAndRethrow(runtime, iteratorRecord.iterator);
        }
        
        mappedValue = std::move(*callRes);
      } else {
        
        mappedValue = nextValue.getHermesValue();
      }
      
      
      
      if (LLVM_UNLIKELY( JSObject::defineOwnComputedPrimitive( A, runtime, k, DefinePropertyFlags::getDefaultNewPropertyFlags(), mappedValue, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {







        return iteratorCloseAndRethrow(runtime, iteratorRecord.iterator);
      }
      
      k = HermesValue::encodeNumberValue(k->getNumber() + 1);
    }
  }
  
  
  auto objRes = toObject(runtime, itemsHandle);
  
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto arrayLike = runtime.makeHandle<JSObject>(objRes.getValue());
  
  
  auto propRes = JSObject::getNamed_RJS( arrayLike, runtime, Predefined::getSymbolID(Predefined::length));
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto lengthRes = toLength(runtime, runtime.makeHandle(std::move(*propRes)));
  if (LLVM_UNLIKELY(lengthRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  uint64_t len = lengthRes->getNumberAs<uint64_t>();
  CallResult<bool> isConstructorRes = isConstructor(runtime, *C);
  if (LLVM_UNLIKELY(isConstructorRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  
  if (*isConstructorRes) {
    
    auto callRes = Callable::executeConstruct1( Handle<Callable>::vmcast(C), runtime, runtime.makeHandle(lengthRes.getValue()));


    if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    A = PseudoHandle<JSObject>::vmcast(std::move(*callRes));
  } else {
    
    
    if (LLVM_UNLIKELY(len > JSArray::StorageType::maxElements())) {
      return runtime.raiseRangeError("Out of memory for array elements.");
    }
    auto arrRes = JSArray::create(runtime, len, len);
    if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    A = arrRes->get();
  }
  
  
  MutableHandle<> k{runtime, HermesValue::encodeNumberValue(0)};
  
  MutableHandle<> mappedValue{runtime};
  while (k->getNumberAs<uint32_t>() < len) {
    GCScopeMarkerRAII marker2{runtime};
    
    propRes = JSObject::getComputed_RJS(arrayLike, runtime, k);
    
    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    
    if (mapfn) {
      
      
      auto callRes = Callable::executeCall2( mapfn, runtime, T, propRes->get(), k.getHermesValue());
      if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      mappedValue = std::move(*callRes);
    } else {
      
      mappedValue = std::move(*propRes);
    }
    
    
    if (LLVM_UNLIKELY( JSObject::defineOwnComputedPrimitive( A, runtime, k, DefinePropertyFlags::getDefaultNewPropertyFlags(), mappedValue, PropOpFlags().plusThrowOnError()) == ExecutionStatus::EXCEPTION)) {







      return ExecutionStatus::EXCEPTION;
    }
    
    k = HermesValue::encodeNumberValue(k->getNumber() + 1);
  }
  
  auto setStatus = JSObject::putNamed_RJS( A, runtime, Predefined::getSymbolID(Predefined::length), k, PropOpFlags().plusThrowOnError());




  
  if (LLVM_UNLIKELY(setStatus == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  
  return A.getHermesValue();
}

} 
} 
