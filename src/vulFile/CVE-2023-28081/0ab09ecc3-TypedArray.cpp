


















namespace hermes {
namespace vm {

namespace {





CallResult<HermesValue> iterableToArrayLike(Runtime &runtime, Handle<> items) {
  
  
  return toObject(runtime, items);
}




template <typename T> T convertNegativeBoundsRelativeToLength(T value, T length) {
  
  T zero = 0;
  return value < 0 ? std::max(length + value, zero) : std::min(value, length);
}


CallResult<Handle<JSTypedArrayBase>> typedArrayCreate( Runtime &runtime, Handle<Callable> constructor, uint64_t length) {


  auto callRes = Callable::executeConstruct1( constructor, runtime, runtime.makeHandle(HermesValue::encodeNumberValue(length)));


  if (callRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  PseudoHandle<> retval = std::move(*callRes);
  if (!vmisa<JSTypedArrayBase>(retval.get())) {
    return runtime.raiseTypeError( "The constructor needs to construct a TypedArray");
  }
  auto newTypedArray = Handle<JSTypedArrayBase>::vmcast(runtime.makeHandle(std::move(retval)));
  
  
  
  if (LLVM_UNLIKELY(newTypedArray->getLength() < length)) {
    return runtime.raiseTypeError( "TypedArray constructor created an array that was too small");
  }
  return newTypedArray;
}





template <typename T, CellKind C> CallResult<HermesValue> typedArrayConstructorFromLength( Runtime &runtime, Handle<JSTypedArray<T, C>> self, Handle<> length) {



  auto resIndex = toIndex(runtime, length);
  if (resIndex == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  if (JSTypedArray<T, C>::createBuffer( runtime, self, resIndex.getValue().getNumberAs<uint64_t>()) == ExecutionStatus::EXCEPTION) {

    return ExecutionStatus::EXCEPTION;
  }
  return self.getHermesValue();
}


template <typename T, CellKind C> CallResult<HermesValue> typedArrayConstructorFromTypedArray( Runtime &runtime, Handle<JSTypedArray<T, C>> self, Handle<JSTypedArrayBase> other) {



  if (JSTypedArray<T, C>::createBuffer(runtime, self, other->getLength()) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  if (JSTypedArrayBase::setToCopyOfTypedArray( runtime, self, 0, other, 0, other->getLength()) == ExecutionStatus::EXCEPTION) {

    return ExecutionStatus::EXCEPTION;
  }
  return self.getHermesValue();
}


template <typename T, CellKind C> CallResult<HermesValue> typedArrayConstructorFromArrayBuffer( Runtime &runtime, Handle<JSTypedArray<T, C>> self, Handle<JSArrayBuffer> buffer, Handle<> byteOffset, Handle<> length) {





  
  
  
  auto res = toIndex(runtime, byteOffset);
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  uint64_t offset = res->getNumberAs<uint64_t>();
  if (offset % sizeof(T) != 0) {
    return runtime.raiseRangeError( "new TypedArray(buffer, [byteOffset], " "[length]): if byteOffset is specified, it " "must be evenly divisible by the element size");


  }
  auto bufferByteLength = buffer->size();
  uint64_t newByteLength = 0;
  if (length->isUndefined()) {
    if (bufferByteLength % sizeof(T) != 0) {
      return runtime.raiseRangeError( "new TypedArray(buffer, [byteOffset], " "[length]): buffer's size must be evenly " "divisible by the element size");


    }
    if (bufferByteLength < offset) {
      return runtime.raiseRangeError( "new TypedArray(buffer, [byteOffset], " "[length]): byteOffset must be less than " "buffer.byteLength");


    }
    newByteLength = bufferByteLength - offset;
  } else {
    auto res2 = toLength(runtime, length);
    if (res2 == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    uint64_t newLength = res2->getNumberAs<uint64_t>();
    newByteLength = newLength * sizeof(T);
    if (offset + newByteLength > bufferByteLength) {
      return runtime.raiseRangeError( "new TypedArray(buffer, [byteOffset], [length]): byteOffset + " "length * elementSize must be less than buffer.byteLength");

    }
  }
  JSTypedArrayBase::setBuffer( runtime, *self, *buffer, offset, newByteLength, sizeof(T));
  return self.getHermesValue();
}


template <typename T, CellKind C> CallResult<HermesValue> typedArrayConstructorFromObject( Runtime &runtime, Handle<JSTypedArray<T, C>> self, Handle<> obj) {



  
  
  auto objRes = iterableToArrayLike(runtime, obj);
  if (objRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto arrayLike = runtime.makeHandle<JSObject>(objRes.getValue());
  
  auto propRes = JSObject::getNamed_RJS( arrayLike, runtime, Predefined::getSymbolID(Predefined::length));
  if (propRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto intRes = toLength(runtime, runtime.makeHandle(std::move(*propRes)));
  if (intRes == ExecutionStatus::EXCEPTION)
    return ExecutionStatus::EXCEPTION;
  uint64_t len = intRes->getNumberAs<uint64_t>();
  
  
  
  if (JSTypedArray<T, C>::createBuffer(runtime, self, len) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  GCScope scope(runtime);
  
  MutableHandle<HermesValue> i(runtime, HermesValue::encodeNumberValue(0));
  auto marker = scope.createMarker();
  
  for (; i->getNumberAs<uint64_t>() < len;
       i = HermesValue::encodeNumberValue(i->getNumberAs<uint64_t>() + 1)) {
    
    
    
    if ((propRes = JSObject::getComputed_RJS(arrayLike, runtime, i)) == ExecutionStatus::EXCEPTION || JSTypedArray<T, C>::putComputed_RJS( self, runtime, i, runtime.makeHandle(std::move(*propRes))) == ExecutionStatus::EXCEPTION) {



      return ExecutionStatus::EXCEPTION;
    }
    scope.flushToMarker(marker);
    
  }
  
  return self.getHermesValue();
}

template <typename T, CellKind C> CallResult<HermesValue> typedArrayConstructor(void *, Runtime &runtime, NativeArgs args) {

  
  if (!args.isConstructorCall()) {
    return runtime.raiseTypeError( "JSTypedArray() called in function context instead of constructor");
  }
  auto self = args.vmcastThis<JSTypedArray<T, C>>();
  if (args.getArgCount() == 0) {
    
    if (JSTypedArray<T, C>::createBuffer(runtime, self, 0) == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    return self.getHermesValue();
  }
  auto firstArg = args.getArgHandle(0);
  if (!firstArg->isObject()) {
    return typedArrayConstructorFromLength<T, C>(runtime, self, firstArg);
  }
  if (auto otherTA = Handle<JSTypedArrayBase>::dyn_vmcast(firstArg)) {
    return typedArrayConstructorFromTypedArray<T, C>(runtime, self, otherTA);
  }
  if (auto buffer = Handle<JSArrayBuffer>::dyn_vmcast(firstArg)) {
    return typedArrayConstructorFromArrayBuffer<T, C>( runtime, self, buffer, args.getArgHandle(1), args.getArgHandle(2));
  }
  return typedArrayConstructorFromObject<T, C>(runtime, self, firstArg);
}

template <typename T, CellKind C, NativeFunctionPtr Ctor> Handle<JSObject> createTypedArrayConstructor(Runtime &runtime) {
  using TA = JSTypedArray<T, C>;
  auto proto = TA::getPrototype(runtime);

  auto cons = defineSystemConstructor( runtime, TA::getName(runtime), Ctor, proto, Handle<JSObject>::vmcast(&runtime.typedArrayBaseConstructor), 3, NativeConstructor::creatorFunction<TA>, C);








  DefinePropertyFlags dpf = DefinePropertyFlags::getDefaultNewPropertyFlags();
  dpf.enumerable = 0;
  dpf.configurable = 0;
  dpf.writable = 0;

  auto bytesPerElement = runtime.makeHandle(HermesValue::encodeNumberValue(sizeof(T)));
  
  defineProperty( runtime, proto, Predefined::getSymbolID(Predefined::BYTES_PER_ELEMENT), bytesPerElement, dpf);





  
  defineProperty( runtime, cons, Predefined::getSymbolID(Predefined::BYTES_PER_ELEMENT), bytesPerElement, dpf);




  return cons;
}



template <bool MapOrFilter> CallResult<HermesValue> mapFilterLoop( Runtime &runtime, Handle<JSTypedArrayBase> self, Handle<Callable> callbackfn, Handle<> thisArg, Handle<JSArray> values, JSTypedArrayBase::size_type insert, JSTypedArrayBase::size_type len) {







  MutableHandle<> storage(runtime);
  MutableHandle<> val{runtime};
  GCScopeMarkerRAII marker{runtime};
  for (JSTypedArrayBase::size_type i = 0; i < len; ++i) {
    if (!self->attached(runtime)) {
      
      
      return runtime.raiseTypeError("Detached the TypedArray in the callback");
    }
    val = JSObject::getOwnIndexed(createPseudoHandle(self.get()), runtime, i);
    auto callRes = Callable::executeCall3( callbackfn, runtime, thisArg, *val, HermesValue::encodeNumberValue(i), self.getHermesValue());





    if (callRes == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    if (MapOrFilter) {
      
      storage = std::move(*callRes);
      JSArray::setElementAt(values, runtime, insert++, storage);
    } else if (toBoolean(callRes->get())) {
      storage = *val;
      JSArray::setElementAt(values, runtime, insert++, storage);
    }
    marker.flush();
  }
  return HermesValue::encodeNumberValue(insert);
}




template <bool WithCompareFn> class TypedArraySortModel : public SortModel {
 protected:
  
  Runtime &runtime_;

  
  GCScope gcScope_;

  
  
  Handle<Callable> compareFn_;

  
  Handle<JSTypedArrayBase> self_;

  MutableHandle<HermesValue> aHandle_;
  MutableHandle<HermesValue> bHandle_;

  
  
  GCScope::Marker gcMarker_;

 public:
  TypedArraySortModel( Runtime &runtime, Handle<JSTypedArrayBase> obj, Handle<Callable> compareFn)


      : runtime_(runtime), gcScope_(runtime), compareFn_(compareFn), self_(obj), aHandle_(runtime), bHandle_(runtime), gcMarker_(gcScope_.createMarker()) {}






  
  virtual ExecutionStatus swap(uint32_t a, uint32_t b) override {
    aHandle_ = JSObject::getOwnIndexed(createPseudoHandle(self_.get()), runtime_, a);
    bHandle_ = JSObject::getOwnIndexed(createPseudoHandle(self_.get()), runtime_, b);
    if (JSObject::setOwnIndexed(self_, runtime_, a, bHandle_) == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    if (JSObject::setOwnIndexed(self_, runtime_, b, aHandle_) == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    return ExecutionStatus::RETURNED;
  }

  
  virtual CallResult<int> compare(uint32_t a, uint32_t b) override {
    GCScopeMarkerRAII gcMarker{gcScope_, gcMarker_};

    CallResult<PseudoHandle<HermesValue>> callRes{ExecutionStatus::EXCEPTION};
    {
      Handle<> aValHandle = runtime_.makeHandle(JSObject::getOwnIndexed( createPseudoHandle(self_.get()), runtime_, a));
      
      
      HermesValue bVal = JSObject::getOwnIndexed(createPseudoHandle(self_.get()), runtime_, b);

      
      
      HermesValue aVal = *aValHandle;

      {
        NoAllocScope noAllocs{runtime_};
        if (!WithCompareFn) {
          if (LLVM_UNLIKELY(aVal.isBigInt())) {
            return aVal.getBigInt()->compare(bVal.getBigInt());
          } else {
            double a = aVal.getNumber();
            double b = bVal.getNumber();
            if (LLVM_UNLIKELY(a == 0) && LLVM_UNLIKELY(b == 0) && LLVM_UNLIKELY(std::signbit(a)) && LLVM_UNLIKELY(!std::signbit(b))) {

              
              return -1;
            }
            return (a < b) ? -1 : (a > b ? 1 : 0);
          }
          assert( compareFn_ && "Cannot use this version if the compareFn is null");
        }
      }
      
      
      callRes = Callable::executeCall2( compareFn_, runtime_, Runtime::getUndefinedValue(), aVal, bVal);
    }

    if (callRes == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    auto intRes = toNumber_RJS(runtime_, runtime_.makeHandle(std::move(*callRes)));
    if (intRes == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    
    
    if (LLVM_UNLIKELY(!self_->attached(runtime_))) {
      return runtime_.raiseTypeError("Callback to sort() detached the array");
    }
    
    auto res = intRes->getNumber();
    return (res < 0) ? -1 : (res > 0 ? 1 : 0);
  }
};


CallResult<HermesValue> typedArrayPrototypeSetObject( Runtime &runtime, Handle<JSTypedArrayBase> self, Handle<> obj, double offset) {



  double targetLength = self->getLength();
  auto objRes = toObject(runtime, obj);
  if (objRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto src = runtime.makeHandle<JSObject>(objRes.getValue());
  auto propRes = JSObject::getNamed_RJS( src, runtime, Predefined::getSymbolID(Predefined::length));
  if (propRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto intRes = toLength(runtime, runtime.makeHandle(std::move(*propRes)));
  if (intRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  uint64_t srcLength = intRes->getNumberAs<uint64_t>();
  if (srcLength + offset > targetLength) {
    return runtime.raiseRangeError( "The sum of the length of the given object " "and the offset cannot be greater than the length " "of this TypedArray");


  }
  
  
  GCScope scope(runtime);
  MutableHandle<> k(runtime, HermesValue::encodeNumberValue(0));
  auto marker = scope.createMarker();
  for (; k->getNumberAs<uint64_t>() < srcLength;
       k = HermesValue::encodeNumberValue(k->getNumberAs<uint64_t>() + 1)) {
    if ((propRes = JSObject::getComputed_RJS(src, runtime, k)) == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    auto kValue = runtime.makeHandle(std::move(*propRes));
    if (JSObject::setOwnIndexed(self, runtime, offset++, kValue) == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    scope.flushToMarker(marker);
  }
  return HermesValue::encodeUndefinedValue();
}


CallResult<HermesValue> typedArrayPrototypeSetTypedArray( Runtime &runtime, Handle<JSTypedArrayBase> self, Handle<JSTypedArrayBase> src, double offset) {



  if (!src->attached(runtime)) {
    return runtime.raiseTypeError( "The src TypedArray must be attached in order to use set()");
  }
  const JSTypedArrayBase::size_type srcLength = src->getLength();
  if (static_cast<double>(srcLength) + offset > self->getLength()) {
    return runtime.raiseRangeError( "The sum of the length of the given TypedArray " "and the offset cannot be greater than the length " "of this TypedArray");


  }
  
  
  if (self->getBuffer(runtime)->getDataBlock(runtime) != src->getBuffer(runtime)->getDataBlock(runtime)) {
    if (JSTypedArrayBase::setToCopyOfTypedArray( runtime, self, offset, src, 0, srcLength) == ExecutionStatus::EXCEPTION) {

      return ExecutionStatus::EXCEPTION;
    }
    return HermesValue::encodeUndefinedValue();
  }
  
  
  
  
  
  
  
  auto possibleTA = src->allocate(runtime, srcLength);
  if (possibleTA == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto newSrc = possibleTA.getValue();
  if (JSTypedArrayBase::setToCopyOfBuffer( runtime, newSrc, 0, runtime.makeHandle(src->getBuffer(runtime)), src->getByteOffset(), src->getByteLength()) == ExecutionStatus::EXCEPTION) {





    return ExecutionStatus::EXCEPTION;
  }
  
  if (JSTypedArrayBase::setToCopyOfTypedArray( runtime, self, offset, newSrc, 0, srcLength) == ExecutionStatus::EXCEPTION) {

    return ExecutionStatus::EXCEPTION;
  }
  return HermesValue::encodeUndefinedValue();
}



} 






CallResult<HermesValue> typedArrayBaseConstructor(void *, Runtime &runtime, NativeArgs) {
  return runtime.raiseTypeError( "TypedArray is abstract, it cannot be constructed");
}












CallResult<HermesValue> typedArrayFrom(void *, Runtime &runtime, NativeArgs args) {
  auto source = args.getArgHandle(0);
  CallResult<bool> isConstructorRes = isConstructor(runtime, args.getThisArg());
  if (LLVM_UNLIKELY(isConstructorRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  
  if (!*isConstructorRes) {
    
    return runtime.raiseTypeError( "Cannot invoke when the this is not a constructor");
  }
  auto C = Handle<Callable>::vmcast(runtime, args.getThisArg());
  
  auto mapfn = Handle<Callable>::dyn_vmcast(args.getArgHandle(1));
  if (!mapfn) {
    
    if (args.getArgCount() >= 2 && !vmisa<Callable>(args.getArg(1))) {
      return runtime.raiseTypeError( "Second argument to TypedArray.from must be callable");
    }
    
  }
  
  
  auto T = args.getArgCount() >= 3 ? args.getArgHandle(2)
                                   : Runtime::getUndefinedValue();
  
  auto objRes = iterableToArrayLike(runtime, source);
  if (objRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto arrayLike = runtime.makeHandle<JSObject>(objRes.getValue());
  
  auto propRes = JSObject::getNamed_RJS( arrayLike, runtime, Predefined::getSymbolID(Predefined::length));
  if (propRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto intRes = toLength(runtime, runtime.makeHandle(std::move(*propRes)));
  if (intRes == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  uint64_t len = intRes.getValue().getNumberAs<uint64_t>();
  
  auto targetObj = typedArrayCreate(runtime, C, len);
  if (targetObj == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  
  MutableHandle<> k(runtime, HermesValue::encodeNumberValue(0));
  
  for (; k->getNumberAs<uint64_t>() < len;
       k = HermesValue::encodeNumberValue(k->getNumberAs<uint64_t>() + 1)) {
    GCScopeMarkerRAII marker{runtime};
    
    if ((propRes = JSObject::getComputed_RJS(arrayLike, runtime, k)) == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    
    if (mapfn) {
      
      auto callRes = Callable::executeCall2( mapfn, runtime, T, propRes->get(), k.getHermesValue());
      if (callRes == ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
      propRes = std::move(callRes);
    }
    
    
    
    auto mappedValue = runtime.makeHandle(std::move(*propRes));
    
    if (JSObject::putComputed_RJS(*targetObj, runtime, k, mappedValue) == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    
  }
  
  return targetObj->getHermesValue();
}


CallResult<HermesValue> typedArrayOf(void *, Runtime &runtime, NativeArgs args) {
  
  uint64_t len = args.getArgCount();
  
  
  
  CallResult<bool> isConstructorRes = isConstructor(runtime, args.getThisArg());
  if (LLVM_UNLIKELY(isConstructorRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  if (!*isConstructorRes) {
    
    return runtime.raiseTypeError( "Cannot invoke %TypedArray%.of when %TypedArray% is not a constructor " "function");

  }
  auto C = Handle<Callable>::vmcast(args.getThisHandle());
  
  auto newObj = typedArrayCreate(runtime, C, len);
  if (newObj == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  
  MutableHandle<> k(runtime, HermesValue::encodeNumberValue(0));
  GCScope scope(runtime);
  auto marker = scope.createMarker();
  
  for (; k->getNumberAs<uint64_t>() < len;
       k = HermesValue::encodeNumberValue(k->getNumberAs<uint64_t>() + 1)) {
    
    auto kValue = args.getArg(k->getNumberAs<uint64_t>());
    
    
    if (JSObject::putComputed_RJS( *newObj, runtime, k, runtime.makeHandle(kValue)) == ExecutionStatus::EXCEPTION) {

      return ExecutionStatus::EXCEPTION;
    }
    
    scope.flushToMarker(marker);
  }
  
  return newObj->getHermesValue();
}






CallResult<HermesValue> typedArrayPrototypeBuffer(void *, Runtime &runtime, NativeArgs args) {
  if (JSTypedArrayBase::validateTypedArray( runtime, args.getThisHandle(), false) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto self = args.vmcastThis<JSTypedArrayBase>();
  return HermesValue::encodeObjectValue(self->getBuffer(runtime));
}

CallResult<HermesValue> typedArrayPrototypeByteLength(void *, Runtime &runtime, NativeArgs args) {
  if (JSTypedArrayBase::validateTypedArray( runtime, args.getThisHandle(), false) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto self = args.vmcastThis<JSTypedArrayBase>();
  return HermesValue::encodeNumberValue( self->attached(runtime) ? self->getByteLength() : 0);
}


CallResult<HermesValue> typedArrayPrototypeByteOffset(void *, Runtime &runtime, NativeArgs args) {
  if (JSTypedArrayBase::validateTypedArray( runtime, args.getThisHandle(), false) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto self = args.vmcastThis<JSTypedArrayBase>();
  return HermesValue::encodeNumberValue( self->attached(runtime) && self->getLength() != 0 ? self->getByteOffset()
                                                        : 0);
}


CallResult<HermesValue> typedArrayPrototypeAt(void *, Runtime &runtime, NativeArgs args) {
  
  
  if (LLVM_UNLIKELY( JSTypedArrayBase::validateTypedArray( runtime, args.getThisHandle(), true) == ExecutionStatus::EXCEPTION)) {


    return ExecutionStatus::EXCEPTION;
  }
  GCScope gcScope{runtime};

  auto O = args.vmcastThis<JSTypedArrayBase>();

  
  
  
  double len = O->getLength();

  
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

  
  
  







  switch (O->getKind()) {

    default:
      llvm_unreachable("Invalid TypedArray after ValidateTypedArray call");
  }
}


CallResult<HermesValue> typedArrayPrototypeCopyWithin(void *, Runtime &runtime, NativeArgs args) {
  if (JSTypedArrayBase::validateTypedArray( runtime, args.getThisHandle(), true) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }

  GCScope gcScope{runtime};

  auto O = args.vmcastThis<JSTypedArrayBase>();

  
  
  double len = O->getLength();

  
  
  auto relativeTargetRes = toIntegerOrInfinity(runtime, args.getArgHandle(0));
  if (LLVM_UNLIKELY(relativeTargetRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double relativeTarget = relativeTargetRes->getNumber();

  
  
  double to = convertNegativeBoundsRelativeToLength(relativeTarget, len);

  
  
  auto relativeStartRes = toIntegerOrInfinity(runtime, args.getArgHandle(1));
  if (LLVM_UNLIKELY(relativeStartRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  double relativeStart = relativeStartRes->getNumber();

  
  
  double from = convertNegativeBoundsRelativeToLength(relativeStart, len);

  
  
  
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

  
  
  double fin = convertNegativeBoundsRelativeToLength(relativeEnd, len);

  
  double count = std::min(fin - from, len - to);

  int direction;
  if (from < to && to < from + count) {
    
    
    direction = -1;
    
    from = from + count - 1;
    
    to = to + count - 1;
  } else {
    
    
    direction = 1;
  }

  
  
  















  switch (O->getKind()) {

    default:
      llvm_unreachable("Invalid TypedArray after ValidateTypedArray call");
  }

  return O.getHermesValue();
}


CallResult<HermesValue> typedArrayPrototypeEverySome(void *ctx, Runtime &runtime, NativeArgs args) {
  
  
  GCScope gcScope(runtime);
  auto every = static_cast<bool>(ctx);
  if (JSTypedArrayBase::validateTypedArray(runtime, args.getThisHandle()) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto self = args.vmcastThis<JSTypedArrayBase>();
  auto callbackfn = args.dyncastArg<Callable>(0);
  if (!callbackfn) {
    return runtime.raiseTypeError("callbackfn must be a Callable");
  }
  auto thisArg = args.getArgHandle(1);
  
  auto marker = gcScope.createMarker();
  for (JSTypedArrayBase::size_type i = 0; i < self->getLength(); ++i) {
    HermesValue val = JSObject::getOwnIndexed(createPseudoHandle(self.get()), runtime, i);
    auto callRes = Callable::executeCall3( callbackfn, runtime, thisArg, val, HermesValue::encodeNumberValue(i), self.getHermesValue());





    if (callRes == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    gcScope.flushToMarker(marker);
    auto testResult = toBoolean(callRes->get());
    if (every && !testResult) {
      return HermesValue::encodeBoolValue(false);
    } else if (!every && testResult) {
      return HermesValue::encodeBoolValue(true);
    }
  }
  
  
  return HermesValue::encodeBoolValue(every);
}


CallResult<HermesValue> typedArrayPrototypeFill(void *, Runtime &runtime, NativeArgs args) {
  if (JSTypedArrayBase::validateTypedArray(runtime, args.getThisHandle()) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto self = args.vmcastThis<JSTypedArrayBase>();
  const double len = self->getLength();
  CallResult<HermesValue> res = ExecutionStatus::EXCEPTION;
  switch (self->getKind()) {
    default:
      res = toNumber_RJS(runtime, args.getArgHandle(0));
      break;
    case CellKind::BigInt64ArrayKind:
    case CellKind::BigUint64ArrayKind:
      res = toBigInt_RJS(runtime, args.getArgHandle(0));
      break;
  }
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto value = runtime.makeHandle(res.getValue());
  res = toIntegerOrInfinity(runtime, args.getArgHandle(1));
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  const double relativeStart = res->getNumber();
  auto end = args.getArgHandle(2);
  if (!end->isUndefined()) {
    res = toIntegerOrInfinity(runtime, end);
    if (res == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
  }
  const double relativeEnd = end->isUndefined() ? len : res->getNumber();
  
  
  const int64_t k = convertNegativeBoundsRelativeToLength(relativeStart, len);
  const int64_t last = convertNegativeBoundsRelativeToLength(relativeEnd, len);

  
  
  if (!self->attached(runtime)) {
    return runtime.raiseTypeError("Cannot fill a detached TypedArray");
  }

  if (k >= last) {
    
    return self.getHermesValue();
  }

  if (JSObject::setOwnIndexed(self, runtime, k, value) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto elementSize = self->getByteWidth();
  uint8_t *begin = self->begin(runtime);
  
  switch (elementSize) {
    case 1:
      std::fill(begin + k, begin + last, *(begin + k));
      break;
    case 2: {
      auto *src = reinterpret_cast<uint16_t *>(begin);
      std::fill(src + k, src + last, *(src + k));
      break;
    }
    case 4: {
      auto *src = reinterpret_cast<uint32_t *>(begin);
      std::fill(src + k, src + last, *(src + k));
      break;
    }
    case 8: {
      auto *src = reinterpret_cast<uint64_t *>(begin);
      std::fill(src + k, src + last, *(src + k));
      break;
    }
    default:
      llvm_unreachable("No element that is that wide");
      break;
  }
  return self.getHermesValue();
}

static CallResult<HermesValue> typedFindHelper(void *ctx, bool reverse, Runtime &runtime, NativeArgs args) {
  bool index = static_cast<bool>(ctx);
  if (JSTypedArrayBase::validateTypedArray(runtime, args.getThisHandle()) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto self = args.vmcastThis<JSTypedArrayBase>();
  auto len = self->getLength();
  auto callbackfn = args.dyncastArg<Callable>(0);
  if (!callbackfn) {
    return runtime.raiseTypeError("callbackfn must be a Callable");
  }
  auto thisArg = args.getArgHandle(1);
  MutableHandle<> val{runtime};
  GCScope gcScope(runtime);
  auto marker = gcScope.createMarker();
  for (JSTypedArrayBase::size_type counter = 0; counter < len; counter++) {
    auto i = reverse ? (len - counter - 1) : counter;
    val = JSObject::getOwnIndexed(createPseudoHandle(self.get()), runtime, i);
    auto idx = HermesValue::encodeNumberValue(i);
    auto callRes = Callable::executeCall3( callbackfn, runtime, thisArg, *val, idx, self.getHermesValue());
    if (callRes == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    if (toBoolean(callRes->get())) {
      
      return index ? idx : *val;
    }
    gcScope.flushToMarker(marker);
  }
  return index ? HermesValue::encodeNumberValue(-1)
               : HermesValue::encodeUndefinedValue();
}

CallResult<HermesValue> typedArrayPrototypeFind(void *ctx, Runtime &runtime, NativeArgs args) {
  return typedFindHelper(ctx, false, runtime, args);
}

CallResult<HermesValue> typedArrayPrototypeFindLast(void *ctx, Runtime &runtime, NativeArgs args) {
  return typedFindHelper(ctx, true, runtime, args);
}

CallResult<HermesValue> typedArrayPrototypeForEach(void *, Runtime &runtime, NativeArgs args) {
  if (JSTypedArrayBase::validateTypedArray(runtime, args.getThisHandle()) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto self = args.vmcastThis<JSTypedArrayBase>();
  auto len = self->getLength();
  auto callbackfn = args.dyncastArg<Callable>(0);
  if (!callbackfn) {
    return runtime.raiseTypeError("callbackfn must be a Callable");
  }
  auto thisArg = args.getArgHandle(1);
  GCScope gcScope(runtime);
  auto marker = gcScope.createMarker();
  for (JSTypedArrayBase::size_type i = 0; i < len; ++i) {
    
    if (!self->attached(runtime)) {
      return runtime.raiseTypeError("Detached the ArrayBuffer in the callback");
    }
    HermesValue val = JSObject::getOwnIndexed(createPseudoHandle(self.get()), runtime, i);
    if (Callable::executeCall3( callbackfn, runtime, thisArg, val, HermesValue::encodeNumberValue(i), self.getHermesValue()) == ExecutionStatus::EXCEPTION) {





      return ExecutionStatus::EXCEPTION;
    }
    gcScope.flushToMarker(marker);
  }
  return HermesValue::encodeUndefinedValue();
}

enum class IndexOfMode { includes, indexOf, lastIndexOf };
CallResult<HermesValue> typedArrayPrototypeIndexOf(void *ctx, Runtime &runtime, NativeArgs args) {
  const auto indexOfMode = *reinterpret_cast<const IndexOfMode *>(&ctx);
  
  
  auto ret = [indexOfMode](bool x = false, double y = -1) {
    switch (indexOfMode) {
      case IndexOfMode::includes:
        return HermesValue::encodeBoolValue(x);
      default:
        return HermesValue::encodeNumberValue(y);
    }
  };
  if (JSTypedArrayBase::validateTypedArray(runtime, args.getThisHandle()) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto self = args.vmcastThis<JSTypedArrayBase>();
  double len = self->getLength();
  if (len == 0) {
    return ret();
  }
  auto searchElement = args.getArgHandle(0);
  if (!searchElement->isNumber() && !searchElement->isBigInt()) {
    
    return ret();
  }
  double fromIndex = 0;
  if (args.getArgCount() < 2) {
    
    if (indexOfMode == IndexOfMode::lastIndexOf) {
      fromIndex = len - 1;
    }
  } else {
    auto res = toIntegerOrInfinity(runtime, args.getArgHandle(1));
    if (res == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    fromIndex = res->getNumber();
    if (LLVM_UNLIKELY(!self->attached(runtime))) {
      
      
      return runtime.raiseTypeError("Detached the TypedArray in the callback");
    }
  }
  
  if (fromIndex == 0) {
    fromIndex = 0;
  }
  double k = 0;
  if (indexOfMode == IndexOfMode::lastIndexOf) {
    k = fromIndex >= 0 ? std::min(fromIndex, len - 1) : len + fromIndex;
  } else {
    k = fromIndex >= 0 ? fromIndex : std::max(len + fromIndex, 0.0);
  }
  auto delta = indexOfMode == IndexOfMode::lastIndexOf ? -1 : 1;
  auto inRange = [indexOfMode](double k, double len) {
    if (indexOfMode == IndexOfMode::lastIndexOf) {
      return k >= 0;
    } else {
      return k < len;
    }
  };
  for (; inRange(k, len); k += delta) {
    HermesValue curr = JSObject::getOwnIndexed(createPseudoHandle(self.get()), runtime, k);
    NoAllocScope noAllocs{runtime};

    bool comp = indexOfMode == IndexOfMode::includes ? isSameValueZero(curr, *searchElement)
        : strictEqualityTest(curr, *searchElement);
    if (comp) {
      return ret(true, k);
    }
  }
  return ret();
}

CallResult<HermesValue> typedArrayPrototypeIterator(void *ctx, Runtime &runtime, NativeArgs args) {
  IterationKind kind = *reinterpret_cast<IterationKind *>(&ctx);
  assert( kind <= IterationKind::NumKinds && "typeArrayPrototypeIterator with wrong kind");

  if (JSTypedArrayBase::validateTypedArray(runtime, args.getThisHandle()) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto self = args.vmcastThis<JSTypedArrayBase>();
  return JSArrayIterator::create(runtime, self, kind).getHermesValue();
}

CallResult<HermesValue> typedArrayPrototypeMapFilter(void *ctx, Runtime &runtime, NativeArgs args) {
  GCScope gcScope{runtime};

  
  bool map = static_cast<bool>(ctx);
  if (JSTypedArrayBase::validateTypedArray(runtime, args.getThisHandle()) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto self = args.vmcastThis<JSTypedArrayBase>();
  JSTypedArrayBase::size_type len = self->getLength();
  auto callbackfn = args.dyncastArg<Callable>(0);
  if (!callbackfn) {
    return runtime.raiseTypeError("callbackfn must be a Callable");
  }
  auto thisArg = args.getArgHandle(1);
  
  auto arrRes = JSArray::create(runtime, len, 0);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto values = *arrRes;
  JSTypedArrayBase::size_type insert = 0;
  CallResult<HermesValue> res{ExecutionStatus::EXCEPTION};
  if (map) {
    if ((res = mapFilterLoop<true>( runtime, self, callbackfn, thisArg, values, insert, len)) == ExecutionStatus::EXCEPTION) {

      return ExecutionStatus::EXCEPTION;
    }
  } else {
    if ((res = mapFilterLoop<false>( runtime, self, callbackfn, thisArg, values, insert, len)) == ExecutionStatus::EXCEPTION) {

      return ExecutionStatus::EXCEPTION;
    }
  }
  insert = res->getNumberAs<JSTypedArrayBase::size_type>();
  
  auto result = JSTypedArrayBase::allocateSpecies(runtime, self, insert);
  if (result == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto TA = result.getValue();
  MutableHandle<> storage(runtime);
  auto marker = gcScope.createMarker();
  for (JSTypedArrayBase::size_type i = 0; i < insert; ++i) {
    storage = values->at(runtime, i).unboxToHV(runtime);
    if (JSObject::setOwnIndexed(TA, runtime, i, storage) == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    gcScope.flushToMarker(marker);
  }
  return TA.getHermesValue();
}


CallResult<HermesValue> typedArrayPrototypeLength(void *, Runtime &runtime, NativeArgs args) {
  if (JSTypedArrayBase::validateTypedArray( runtime, args.getThisHandle(), false) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto self = args.vmcastThis<JSTypedArrayBase>();
  return HermesValue::encodeNumberValue( self->attached(runtime) ? self->getLength() : 0);
}

CallResult<HermesValue> typedArrayPrototypeJoin(void *, Runtime &runtime, NativeArgs args) {
  
  
  if (JSTypedArrayBase::validateTypedArray(runtime, args.getThisHandle()) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto self = args.vmcastThis<JSTypedArrayBase>();
  auto len = self->getLength();
  auto separator = args.getArg(0).isUndefined()
      ? runtime.makeHandle(HermesValue::encodeStringValue( runtime.getPredefinedString(Predefined::comma)))
      : args.getArgHandle(0);
  auto res = toString_RJS(runtime, separator);
  if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto sep = runtime.makeHandle(std::move(*res));
  if (len == 0) {
    
    
    
    return HermesValue::encodeStringValue( runtime.getPredefinedString(Predefined::emptyString));
  }

  if (len > std::numeric_limits<uint32_t>::max() || sep->getStringLength() > (double)StringPrimitive::MAX_STRING_LENGTH / len) {

    
    return runtime.raiseRangeError( "String.prototype.repeat result exceeds limit");
  }

  
  
  SafeUInt32 size(sep->getStringLength() * (len - 1));

  
  auto arrRes = JSArray::create(runtime, len, 0);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto strings = *arrRes;

  
  {
    
    MutableHandle<> elem(runtime);
    for (decltype(len) i = 0; i < len; ++i) {
      GCScope gcScope(runtime);
      elem = JSObject::getOwnIndexed(createPseudoHandle(self.get()), runtime, i);

      auto res2 = toString_RJS(runtime, elem);
      if (LLVM_UNLIKELY(res2 == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      auto S = runtime.makeHandle(std::move(*res2));
      size.add(S->getStringLength());
      JSArray::setElementAt(strings, runtime, i, S);
    }
  }

  
  auto builder = StringBuilder::createStringBuilder(runtime, size);
  if (builder == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  MutableHandle<StringPrimitive> element{runtime};
  element = strings->at(runtime, 0).getString(runtime);
  builder->appendStringPrim(element);
  
  for (decltype(len) i = 1; i < len; ++i) {
    builder->appendStringPrim(sep);
    element = strings->at(runtime, i).getString(runtime);
    builder->appendStringPrim(element);
  }
  return HermesValue::encodeStringValue(*builder->getStringPrimitive());
}

CallResult<HermesValue> typedArrayPrototypeReduce(void *ctx, Runtime &runtime, NativeArgs args) {
  
  bool right = static_cast<bool>(ctx);
  if (JSTypedArrayBase::validateTypedArray(runtime, args.getThisHandle()) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto self = args.vmcastThis<JSTypedArrayBase>();
  double len = self->getLength();
  auto callbackfn = args.dyncastArg<Callable>(0);
  if (!callbackfn) {
    return runtime.raiseTypeError("callbackfn must be a Callable");
  }
  const bool calledWithInitialValue = args.getArgCount() >= 2;
  if (len == 0 && !calledWithInitialValue) {
    return runtime.raiseTypeError( "reduce needs to provide an initial value for an empty TypedArray");
  }
  
  
  MutableHandle<> accumulator(runtime);
  if (calledWithInitialValue) {
    accumulator = args.getArg(1);
  } else {
    accumulator = JSObject::getOwnIndexed( createPseudoHandle(self.get()), runtime, right ? len - 1 : 0);
  }

  auto inRange = [right](double i, double len) {
    return right ? i >= 0 : i < len;
  };
  double i = right ? len - 1 : 0;
  
  if (!calledWithInitialValue) {
    i += right ? -1 : 1;
  }

  Handle<> undefinedThis = Runtime::getUndefinedValue();
  GCScope scope(runtime);
  auto marker = scope.createMarker();
  for (; inRange(i, len); i += right ? -1 : 1) {
    if (!self->attached(runtime)) {
      
      
      return runtime.raiseTypeError("Detached the TypedArray in the callback");
    }
    HermesValue val = JSObject::getOwnIndexed(createPseudoHandle(self.get()), runtime, i);
    auto callRes = Callable::executeCall4( callbackfn, runtime, undefinedThis, accumulator.getHermesValue(), val, HermesValue::encodeNumberValue(i), self.getHermesValue());






    if (callRes == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    accumulator = std::move(*callRes);
    scope.flushToMarker(marker);
  }
  return accumulator.getHermesValue();
}


CallResult<HermesValue> typedArrayPrototypeReverse(void *, Runtime &runtime, NativeArgs args) {
  if (JSTypedArrayBase::validateTypedArray(runtime, args.getThisHandle()) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto self = args.vmcastThis<JSTypedArrayBase>();
  const JSTypedArrayBase::size_type len = self->getLength();
  const JSTypedArrayBase::size_type middle = len / 2;
  MutableHandle<> lowerHandle(runtime);
  MutableHandle<> upperHandle(runtime);
  for (JSTypedArrayBase::size_type lower = 0; lower != middle; ++lower) {
    auto upper = len - lower - 1;
    lowerHandle = JSObject::getOwnIndexed(createPseudoHandle(self.get()), runtime, lower);
    upperHandle = JSObject::getOwnIndexed(createPseudoHandle(self.get()), runtime, upper);
    if (JSObject::setOwnIndexed(self, runtime, lower, upperHandle) == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    if (JSObject::setOwnIndexed(self, runtime, upper, lowerHandle) == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
  }
  return self.getHermesValue();
}


CallResult<HermesValue> typedArrayPrototypeSort(void *, Runtime &runtime, NativeArgs args) {
  if (JSTypedArrayBase::validateTypedArray(runtime, args.getThisHandle()) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto self = args.vmcastThis<JSTypedArrayBase>();
  const JSTypedArrayBase::size_type len = self->getLength();

  
  auto compareFn = Handle<Callable>::dyn_vmcast(args.getArgHandle(0));
  if (!args.getArg(0).isUndefined() && !compareFn) {
    return runtime.raiseTypeError("TypedArray sort argument must be callable");
  }

  
  
  
  if (compareFn) {
    TypedArraySortModel<true> sm(runtime, self, compareFn);
    if (LLVM_UNLIKELY(quickSort(&sm, 0, len) == ExecutionStatus::EXCEPTION))
      return ExecutionStatus::EXCEPTION;
  } else {
    TypedArraySortModel<false> sm(runtime, self, compareFn);
    if (LLVM_UNLIKELY(quickSort(&sm, 0, len) == ExecutionStatus::EXCEPTION))
      return ExecutionStatus::EXCEPTION;
  }
  return self.getHermesValue();
}


CallResult<HermesValue> typedArrayPrototypeSet(void *, Runtime &runtime, NativeArgs args) {
  if (JSTypedArrayBase::validateTypedArray( runtime, args.getThisHandle(), false) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto self = args.vmcastThis<JSTypedArrayBase>();
  
  auto offset = runtime.makeHandle( args.getArgCount() >= 2 ? args.getArg(1)
                              : HermesValue::encodeNumberValue(0));
  auto res = toIntegerOrInfinity(runtime, offset);
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  double targetOffset = res->getNumber();
  
  if (targetOffset < 0) {
    return runtime.raiseRangeError("Offset must not be negative if supplied");
  }
  if (!self->attached(runtime)) {
    return runtime.raiseTypeError( "TypedArray.prototype.set called on a detached TypedArray");
  }
  
  auto arr = args.getArgHandle(0);
  if (auto typedarr = Handle<JSTypedArrayBase>::dyn_vmcast(arr)) {
    return typedArrayPrototypeSetTypedArray( runtime, self, typedarr, targetOffset);
  } else {
    return typedArrayPrototypeSetObject(runtime, self, arr, targetOffset);
  }
}


CallResult<HermesValue> typedArrayPrototypeSlice(void *, Runtime &runtime, NativeArgs args) {
  if (JSTypedArrayBase::validateTypedArray(runtime, args.getThisHandle()) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto self = args.vmcastThis<JSTypedArrayBase>();
  double len = self->getLength();
  auto res = toIntegerOrInfinity(runtime, args.getArgHandle(0));
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto relativeStart = res->getNumber();
  double relativeEnd = 0;
  if (args.getArg(1).isUndefined()) {
    relativeEnd = len;
  } else {
    res = toIntegerOrInfinity(runtime, args.getArgHandle(1));
    if (res == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    relativeEnd = res->getNumber();
  }
  double k = convertNegativeBoundsRelativeToLength(relativeStart, len);
  double last = convertNegativeBoundsRelativeToLength(relativeEnd, len);
  double count = std::max(last - k, 0.0);
  auto status = JSTypedArrayBase::allocateSpecies(runtime, self, count);
  if (status == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  if (!self->attached(runtime)) {
    
    return runtime.raiseTypeError( "Detached the buffer in the species constructor");
  }
  auto A = status.getValue();
  if (count > 0) {
    JSTypedArrayBase::setToCopyOfTypedArray(runtime, A, 0, self, k, count);
  }
  return A.getHermesValue();
}


CallResult<HermesValue> typedArrayPrototypeSubarray(void *, Runtime &runtime, NativeArgs args) {
  if (JSTypedArrayBase::validateTypedArray( runtime, args.getThisHandle(), false) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto self = args.vmcastThis<JSTypedArrayBase>();
  double srcLength = self->getLength();
  auto res = toIntegerOrInfinity(runtime, args.getArgHandle(0));
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  double relativeBegin = res->getNumber();
  double relativeEnd = srcLength;
  if (!args.getArg(1).isUndefined()) {
    res = toIntegerOrInfinity(runtime, args.getArgHandle(1));
    if (res == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    relativeEnd = res->getNumber();
  }
  double beginIndex = convertNegativeBoundsRelativeToLength(relativeBegin, srcLength);
  double endIndex = convertNegativeBoundsRelativeToLength(relativeEnd, srcLength);
  double newLength = std::max(endIndex - beginIndex, 0.0);
  auto result = JSTypedArrayBase::allocateToSameBuffer( runtime, self, beginIndex, beginIndex + newLength);
  if (result == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  return result.getValue().getHermesValue();
}

CallResult<HermesValue> typedArrayPrototypeSymbolToStringTag( void *, Runtime &runtime, NativeArgs args) {


  auto O = args.dyncastThis<JSObject>();
  if (!O) {
    return HermesValue::encodeUndefinedValue();
  }

  






  
  return HermesValue::encodeUndefinedValue();
}

CallResult<HermesValue> typedArrayPrototypeToLocaleString(void *, Runtime &runtime, NativeArgs args) {
  GCScope gcScope(runtime);
  if (JSTypedArrayBase::validateTypedArray(runtime, args.getThisHandle()) == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<JSTypedArrayBase> self = args.vmcastThis<JSTypedArrayBase>();

  auto emptyString = runtime.getPredefinedStringHandle(Predefined::emptyString);

  const JSTypedArrayBase::size_type len = self->getLength();
  if (len == 0) {
    return emptyString.getHermesValue();
  }

  
  
  auto separator = createASCIIRef(",");

  
  SafeUInt32 size(len - 1);

  
  auto arrRes = JSArray::create(runtime, len, len);
  if (LLVM_UNLIKELY(arrRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto strings = *arrRes;

  
  MutableHandle<> storage(runtime);

  auto marker = gcScope.createMarker();
  for (JSTypedArrayBase::size_type i = 0; i < len; ++i) {
    storage = JSObject::getOwnIndexed(createPseudoHandle(self.get()), runtime, i);
    auto objRes = toObject(runtime, storage);
    if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    auto elementObj = runtime.makeHandle<JSObject>(objRes.getValue());

    
    auto propRes = JSObject::getNamed_RJS( elementObj, runtime, Predefined::getSymbolID(Predefined::toLocaleString));


    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (auto func = Handle<Callable>::dyn_vmcast( runtime.makeHandle(std::move(*propRes)))) {

      auto callRes = Callable::executeCall2( func, runtime, elementObj, args.getArg(0), args.getArg(1));

      auto callRes = Callable::executeCall0(func, runtime, elementObj);

      if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      auto strRes = toString_RJS(runtime, runtime.makeHandle(std::move(*callRes)));
      if (LLVM_UNLIKELY(strRes == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      auto elementStr = runtime.makeHandle(std::move(*strRes));
      JSArray::setElementAt(strings, runtime, i, elementStr);
      size.add(elementStr->getStringLength());
    } else {
      return runtime.raiseTypeError("toLocaleString() not callable");
    }
    gcScope.flushToMarker(marker);
  }

  auto builder = StringBuilder::createStringBuilder(runtime, size);
  if (builder == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  MutableHandle<StringPrimitive> element{runtime};
  element = strings->at(runtime, 0).getString(runtime);
  builder->appendStringPrim(element);

  for (uint32_t i = 1; i < len; ++i) {
    
    builder->appendASCIIRef(separator);
    element = strings->at(runtime, i).getString(runtime);
    builder->appendStringPrim(element);
  }
  return HermesValue::encodeStringValue(*builder->getStringPrimitive());
}

Handle<JSObject> createTypedArrayBaseConstructor(Runtime &runtime) {
  auto proto = Handle<JSObject>::vmcast(&runtime.typedArrayBasePrototype);

  
  
  
  auto cons = runtime.makeHandle(NativeConstructor::create( runtime, Handle<JSObject>::vmcast(&runtime.functionPrototype), nullptr, typedArrayBaseConstructor, 0, NativeConstructor::creatorFunction<JSObject>, CellKind::JSObjectKind));







  
  auto st = Callable::defineNameLengthAndPrototype( cons, runtime, Predefined::getSymbolID(Predefined::TypedArray), 0, proto, Callable::WritablePrototype::No, false);






  (void)st;
  assert( st != ExecutionStatus::EXCEPTION && "defineNameLengthAndPrototype() failed");


  
  
  defineAccessor( runtime, proto, Predefined::getSymbolID(Predefined::buffer), nullptr, typedArrayPrototypeBuffer, nullptr, false, true);







  defineAccessor( runtime, proto, Predefined::getSymbolID(Predefined::byteLength), nullptr, typedArrayPrototypeByteLength, nullptr, false, true);







  defineAccessor( runtime, proto, Predefined::getSymbolID(Predefined::byteOffset), nullptr, typedArrayPrototypeByteOffset, nullptr, false, true);







  defineAccessor( runtime, proto, Predefined::getSymbolID(Predefined::length), nullptr, typedArrayPrototypeLength, nullptr, false, true);







  defineAccessor( runtime, proto, Predefined::getSymbolID(Predefined::SymbolToStringTag), Predefined::getSymbolID(Predefined::squareSymbolToStringTag), nullptr, typedArrayPrototypeSymbolToStringTag, nullptr, false, true);








  
  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::at), nullptr, typedArrayPrototypeAt, 1);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::copyWithin), nullptr, typedArrayPrototypeCopyWithin, 2);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::every), (void *)true, typedArrayPrototypeEverySome, 1);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::some), (void *)false, typedArrayPrototypeEverySome, 1);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::fill), nullptr, typedArrayPrototypeFill, 1);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::filter), (void *)false, typedArrayPrototypeMapFilter, 1);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::find), (void *)false, typedArrayPrototypeFind, 1);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::findIndex), (void *)true, typedArrayPrototypeFind, 1);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::findLast), (void *)false, typedArrayPrototypeFindLast, 1);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::findLastIndex), (void *)true, typedArrayPrototypeFindLast, 1);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::forEach), nullptr, typedArrayPrototypeForEach, 1);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::includes), (void *)IndexOfMode::includes, typedArrayPrototypeIndexOf, 1);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::indexOf), (void *)IndexOfMode::indexOf, typedArrayPrototypeIndexOf, 1);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::lastIndexOf), (void *)IndexOfMode::lastIndexOf, typedArrayPrototypeIndexOf, 1);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::join), nullptr, typedArrayPrototypeJoin, 1);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::map), (void *)true, typedArrayPrototypeMapFilter, 1);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::reduce), (void *)false, typedArrayPrototypeReduce, 1);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::reduceRight), (void *)true, typedArrayPrototypeReduce, 1);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::reverse), nullptr, typedArrayPrototypeReverse, 0);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::set), nullptr, typedArrayPrototypeSet, 1);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::slice), nullptr, typedArrayPrototypeSlice, 2);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::sort), nullptr, typedArrayPrototypeSort, 1);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::subarray), nullptr, typedArrayPrototypeSubarray, 2);






  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::keys), (void *)IterationKind::Key, typedArrayPrototypeIterator, 0);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::values), (void *)IterationKind::Value, typedArrayPrototypeIterator, 0);





  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::entries), (void *)IterationKind::Entry, typedArrayPrototypeIterator, 0);






  DefinePropertyFlags dpf = DefinePropertyFlags::getNewNonEnumerableFlags();

  
  {
    auto propValue = runtime.ignoreAllocationFailure(JSObject::getNamed_RJS( proto, runtime, Predefined::getSymbolID(Predefined::values)));
    runtime.ignoreAllocationFailure(JSObject::defineOwnProperty( proto, runtime, Predefined::getSymbolID(Predefined::SymbolIterator), dpf, runtime.makeHandle<NativeFunction>(propValue.getHermesValue())));




  }

  {
    auto propValue = runtime.ignoreAllocationFailure(JSObject::getNamed_RJS( Handle<JSArray>::vmcast(&runtime.arrayPrototype), runtime, Predefined::getSymbolID(Predefined::toString)));


    runtime.ignoreAllocationFailure(JSObject::defineOwnProperty( proto, runtime, Predefined::getSymbolID(Predefined::toString), dpf, Handle<NativeFunction>::vmcast( runtime.makeHandle(std::move(propValue)))));





  }

  defineMethod( runtime, proto, Predefined::getSymbolID(Predefined::toLocaleString), nullptr, typedArrayPrototypeToLocaleString, 0);






  
  defineMethod( runtime, cons, Predefined::getSymbolID(Predefined::from), nullptr, typedArrayFrom, 1);






  defineMethod( runtime, cons, Predefined::getSymbolID(Predefined::of), nullptr, typedArrayOf, 0);






  return cons;
}










} 
} 
