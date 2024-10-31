



























namespace hermes {
namespace vm {

CallResult<Handle<SymbolID>> stringToSymbolID( Runtime &runtime, PseudoHandle<StringPrimitive> strPrim) {

  
  return runtime.getIdentifierTable().getSymbolHandleFromPrimitive( runtime, std::move(strPrim));
}

CallResult<Handle<SymbolID>> valueToSymbolID( Runtime &runtime, Handle<> nameValHnd) {

  if (nameValHnd->isSymbol()) {
    return Handle<SymbolID>::vmcast(nameValHnd);
  }
  
  auto res = toString_RJS(runtime, nameValHnd);
  if (res == ExecutionStatus::EXCEPTION)
    return ExecutionStatus::EXCEPTION;

  
  return stringToSymbolID(runtime, std::move(*res));
}

HermesValue typeOf(Runtime &runtime, Handle<> valueHandle) {
  switch (valueHandle->getETag()) {
    case HermesValue::ETag::Undefined:
      return HermesValue::encodeStringValue( runtime.getPredefinedString(Predefined::undefined));
    case HermesValue::ETag::Null:
      return HermesValue::encodeStringValue( runtime.getPredefinedString(Predefined::object));
    case HermesValue::ETag::Str1:
    case HermesValue::ETag::Str2:
      return HermesValue::encodeStringValue( runtime.getPredefinedString(Predefined::string));
    case HermesValue::ETag::BigInt1:
    case HermesValue::ETag::BigInt2:
      return HermesValue::encodeStringValue( runtime.getPredefinedString(Predefined::bigint));
    case HermesValue::ETag::Bool:
      return HermesValue::encodeStringValue( runtime.getPredefinedString(Predefined::boolean));
    case HermesValue::ETag::Symbol:
      return HermesValue::encodeStringValue( runtime.getPredefinedString(Predefined::symbol));
    case HermesValue::ETag::Object1:
    case HermesValue::ETag::Object2:
      if (vmisa<Callable>(*valueHandle))
        return HermesValue::encodeStringValue( runtime.getPredefinedString(Predefined::function));
      return HermesValue::encodeStringValue( runtime.getPredefinedString(Predefined::object));
    default:
      assert(valueHandle->isNumber() && "Invalid type.");
      return HermesValue::encodeStringValue( runtime.getPredefinedString(Predefined::number));
  }
}

OptValue<uint32_t> toArrayIndex( Runtime &runtime, Handle<StringPrimitive> strPrim) {

  auto view = StringPrimitive::createStringView(runtime, strPrim);
  return toArrayIndex(view);
}

OptValue<uint32_t> toArrayIndex(StringView str) {
  auto len = str.length();
  if (str.isASCII()) {
    const char *ptr = str.castToCharPtr();
    return hermes::toArrayIndex(ptr, ptr + len);
  }
  const char16_t *ptr = str.castToChar16Ptr();
  return hermes::toArrayIndex(ptr, ptr + len);
}

bool isSameValue(HermesValue x, HermesValue y) {
  if (x.getTag() != y.getTag()) {
    
    return false;
  }
  assert( !x.isEmpty() && !x.isNativeValue() && "Empty and Native Value cannot be compared");


  
  if (x.isString()) {
    
    return x.getString()->equals(y.getString());
  }

  
  if (x.isBigInt()) {
    
    return x.getBigInt()->compare(y.getBigInt()) == 0;
  }

  
  return x.getRaw() == y.getRaw();
}

bool isSameValueZero(HermesValue x, HermesValue y) {
  if (x.isNumber() && y.isNumber() && x.getNumber() == y.getNumber()) {
    
    return true;
  }
  return isSameValue(x, y);
}

bool isPrimitive(HermesValue val) {
  assert(!val.isEmpty() && "empty value encountered");
  assert(!val.isNativeValue() && "native value encountered");
  return !val.isObject();
}

CallResult<HermesValue> ordinaryToPrimitive( Handle<JSObject> selfHandle, Runtime &runtime, PreferredType preferredType) {


  GCScope gcScope{runtime};
  assert( preferredType != PreferredType::NONE && "OrdinaryToPrimitive requires a type hint");


  for (int i = 0; i < 2; ++i) {
    if (preferredType == PreferredType::STRING) {
      auto propRes = JSObject::getNamed_RJS( selfHandle, runtime, Predefined::getSymbolID(Predefined::toString));
      if (propRes == ExecutionStatus::EXCEPTION)
        return ExecutionStatus::EXCEPTION;
      if (auto funcHandle = Handle<Callable>::dyn_vmcast( runtime.makeHandle(std::move(*propRes)))) {
        auto callRes = funcHandle->executeCall0(funcHandle, runtime, selfHandle);
        if (callRes == ExecutionStatus::EXCEPTION)
          return ExecutionStatus::EXCEPTION;
        if (isPrimitive(callRes->get()))
          return callRes.toCallResultHermesValue();
      }

      
      preferredType = PreferredType::NUMBER;
    } else {
      auto propRes = JSObject::getNamed_RJS( selfHandle, runtime, Predefined::getSymbolID(Predefined::valueOf));
      if (propRes == ExecutionStatus::EXCEPTION)
        return ExecutionStatus::EXCEPTION;
      if (auto funcHandle = Handle<Callable>::dyn_vmcast( runtime.makeHandle(std::move(*propRes)))) {
        auto callRes = funcHandle->executeCall0(funcHandle, runtime, selfHandle);
        if (callRes == ExecutionStatus::EXCEPTION)
          return ExecutionStatus::EXCEPTION;
        if (isPrimitive(callRes->get()))
          return callRes.toCallResultHermesValue();
      }

      
      preferredType = PreferredType::STRING;
    }
  }

  
  return runtime.raiseTypeError("Cannot determine default value of object");
}


CallResult<HermesValue> toPrimitive_RJS(Runtime &runtime, Handle<> valueHandle, PreferredType hint) {
  assert(!valueHandle->isEmpty() && "empty value is not allowed");
  assert(!valueHandle->isNativeValue() && "native value is not allowed");

  if (!valueHandle->isObject())
    return *valueHandle;

  
  auto exoticToPrim = getMethod( runtime, valueHandle, runtime.makeHandle( Predefined::getSymbolID(Predefined::SymbolToPrimitive)));



  if (LLVM_UNLIKELY(exoticToPrim == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  
  if (vmisa<Callable>(exoticToPrim->getHermesValue())) {
    auto callable = runtime.makeHandle<Callable>( dyn_vmcast<Callable>(exoticToPrim->getHermesValue()));
    CallResult<PseudoHandle<>> resultRes = Callable::executeCall1( callable, runtime, valueHandle, HermesValue::encodeStringValue(runtime.getPredefinedString( hint == PreferredType::NONE         ? Predefined::defaultStr : hint == PreferredType::STRING ? Predefined::string : Predefined::number)));






    if (LLVM_UNLIKELY(resultRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    PseudoHandle<> result = std::move(*resultRes);
    if (!result->isObject()) {
      return result.getHermesValue();
    }
    return runtime.raiseTypeError( "Symbol.toPrimitive function must return a primitive");
  }

  
  
  return ordinaryToPrimitive( Handle<JSObject>::vmcast(valueHandle), runtime, hint == PreferredType::NONE ? PreferredType::NUMBER : hint);


}

bool toBoolean(HermesValue value) {
  switch (value.getETag()) {

    case HermesValue::ETag::Invalid:
      llvm_unreachable("invalid value");

    case HermesValue::ETag::Empty:
      llvm_unreachable("empty value");
    case HermesValue::ETag::Native1:
    case HermesValue::ETag::Native2:
      llvm_unreachable("native value");
    case HermesValue::ETag::Undefined:
    case HermesValue::ETag::Null:
      return false;
    case HermesValue::ETag::Bool:
      return value.getBool();
    case HermesValue::ETag::Symbol:
    case HermesValue::ETag::Object1:
    case HermesValue::ETag::Object2:
      return true;
    case HermesValue::ETag::BigInt1:
    case HermesValue::ETag::BigInt2:
      return value.getBigInt()->compare(0) != 0;
    case HermesValue::ETag::Str1:
    case HermesValue::ETag::Str2:
      return value.getString()->getStringLength() != 0;
    default: {
      auto m = value.getNumber();
      return !(m == 0 || std::isnan(m));
    }
  }
}


static CallResult<PseudoHandle<StringPrimitive>> numberToString( Runtime &runtime, double m) LLVM_NO_SANITIZE("float-cast-overflow");


static CallResult<PseudoHandle<StringPrimitive>> numberToString( Runtime &runtime, double m) {

  char buf8[hermes::NUMBER_TO_STRING_BUF_SIZE];

  
  int32_t n = static_cast<int32_t>(m);
  if (m == static_cast<double>(n) && n > 0) {
    
    char *p = buf8 + sizeof(buf8);
    do {
      *--p = '0' + (n % 10);
      n /= 10;
    } while (n);
    size_t len = buf8 + sizeof(buf8) - p;
    
    auto result = StringPrimitive::create(runtime, ASCIIRef(p, len));
    if (LLVM_UNLIKELY(result == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    return createPseudoHandle(vmcast<StringPrimitive>(*result));
  }

  auto getPredefined = [&runtime](Predefined::Str predefinedID) {
    return createPseudoHandle(runtime.getPredefinedString(predefinedID));
  };

  if (std::isnan(m))
    return getPredefined(Predefined::NaN);
  if (m == 0)
    return getPredefined(Predefined::zero);
  if (m == std::numeric_limits<double>::infinity())
    return getPredefined(Predefined::Infinity);
  if (m == -std::numeric_limits<double>::infinity())
    return getPredefined(Predefined::NegativeInfinity);

  
  size_t len = hermes::numberToString(m, buf8, sizeof(buf8));

  auto result = StringPrimitive::create(runtime, ASCIIRef(buf8, len));
  if (LLVM_UNLIKELY(result == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  return createPseudoHandle(vmcast<StringPrimitive>(*result));
}

CallResult<PseudoHandle<StringPrimitive>> toString_RJS( Runtime &runtime, Handle<> valueHandle) {

  HermesValue value = valueHandle.get();
  StringPrimitive *result;
  switch (value.getETag()) {

    case HermesValue::ETag::Invalid:
      llvm_unreachable("invalid value");

    case HermesValue::ETag::Empty:
      llvm_unreachable("empty value");
    case HermesValue::ETag::Native1:
    case HermesValue::ETag::Native2:
      llvm_unreachable("native value");
    case HermesValue::ETag::BigInt1:
    case HermesValue::ETag::BigInt2: {
      const uint8_t kDefaultRadix = 10;
      auto res = vmcast<BigIntPrimitive>(value)->toString(runtime, kDefaultRadix);
      if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      result = res->getString();
      break;
    }
    case HermesValue::ETag::Str1:
    case HermesValue::ETag::Str2:
      result = vmcast<StringPrimitive>(value);
      break;
    case HermesValue::ETag::Undefined:
      result = runtime.getPredefinedString(Predefined::undefined);
      break;
    case HermesValue::ETag::Null:
      result = runtime.getPredefinedString(Predefined::null);
      break;
    case HermesValue::ETag::Bool:
      result = value.getBool()
          ? runtime.getPredefinedString(Predefined::trueStr)
          : runtime.getPredefinedString(Predefined::falseStr);
      break;
    case HermesValue::ETag::Object1:
    case HermesValue::ETag::Object2: {
      auto res = toPrimitive_RJS(runtime, valueHandle, PreferredType::STRING);
      if (res == ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
      return toString_RJS(runtime, runtime.makeHandle(res.getValue()));
    }
    case HermesValue::ETag::Symbol:
      return runtime.raiseTypeError("Cannot convert Symbol to string");
    default:
      return numberToString(runtime, value.getNumber());
  }

  return createPseudoHandle(result);
}

double parseIntWithRadix(const StringView str, int radix) {
  auto res = hermes::parseIntWithRadix< false>(str, radix);
  return res ? res.getValue() : std::numeric_limits<double>::quiet_NaN();
}


static inline double stringToNumber( Runtime &runtime, Handle<StringPrimitive> strPrim) {

  auto &idTable = runtime.getIdentifierTable();

  
  if (runtime.symbolEqualsToStringPrim( Predefined::getSymbolID(Predefined::Infinity), *strPrim)) {
    return std::numeric_limits<double>::infinity();
  }
  if (runtime.symbolEqualsToStringPrim( Predefined::getSymbolID(Predefined::PositiveInfinity), *strPrim)) {
    return std::numeric_limits<double>::infinity();
  }
  if (runtime.symbolEqualsToStringPrim( Predefined::getSymbolID(Predefined::NegativeInfinity), *strPrim)) {
  }
  if (runtime.symbolEqualsToStringPrim( Predefined::getSymbolID(Predefined::NaN), *strPrim)) {
    return std::numeric_limits<double>::quiet_NaN();
  }

  
  auto orig = StringPrimitive::createStringView(runtime, strPrim);
  auto begin = orig.begin();
  auto end = orig.end();

  
  while (begin != end && (isWhiteSpaceChar(*begin) || isLineTerminatorChar(*begin))) {
    ++begin;
  }
  while (begin != end && (isWhiteSpaceChar(*(end - 1)) || isLineTerminatorChar(*(end - 1)))) {
    --end;
  }
  
  if (begin == end) {
    return 0;
  }

  
  StringView str16 = orig.slice(begin, end);

  
  
  
  if (LLVM_UNLIKELY(str16.equals(idTable.getStringView( runtime, Predefined::getSymbolID(Predefined::Infinity))))) {
    return std::numeric_limits<double>::infinity();
  }
  if (LLVM_UNLIKELY(str16.equals(idTable.getStringView( runtime, Predefined::getSymbolID(Predefined::PositiveInfinity))))) {
    return std::numeric_limits<double>::infinity();
  }
  if (LLVM_UNLIKELY(str16.equals(idTable.getStringView( runtime, Predefined::getSymbolID(Predefined::NegativeInfinity))))) {
    return -std::numeric_limits<double>::infinity();
  }
  if (LLVM_UNLIKELY(str16.equals(idTable.getStringView( runtime, Predefined::getSymbolID(Predefined::NaN))))) {
    return std::numeric_limits<double>::quiet_NaN();
  }

  auto len = str16.length();

  
  
  
  if (len > 2) {
    if (str16[0] == u'0' && letterToLower(str16[1]) == u'x') {
      return parseIntWithRadix(str16.slice(2), 16);
    }
    if (str16[0] == u'0' && letterToLower(str16[1]) == u'o') {
      return parseIntWithRadix(str16.slice(2), 8);
    }
    if (str16[0] == u'0' && letterToLower(str16[1]) == u'b') {
      return parseIntWithRadix(str16.slice(2), 2);
    }
  }

  
  llvh::SmallVector<char, 32> str8(len + 1);
  uint32_t i = 0;
  for (auto c16 : str16) {
    
    if ((u'0' <= c16 && c16 <= u'9') || c16 == u'.' || letterToLower(c16) == u'e' || c16 == u'+' || c16 == u'-') {
      str8[i] = static_cast<char>(c16);
    } else {
      return std::numeric_limits<double>::quiet_NaN();
    }
    ++i;
  }
  str8[len] = '\0';
  char *endPtr;
  double result = ::hermes_g_strtod(str8.data(), &endPtr);
  if (endPtr == str8.data() + len) {
    return result;
  }

  
  return std::numeric_limits<double>::quiet_NaN();
}

CallResult<HermesValue> toNumber_RJS(Runtime &runtime, Handle<> valueHandle) {
  auto value = valueHandle.get();
  double result;
  switch (value.getETag()) {

    case HermesValue::ETag::Invalid:
      llvm_unreachable("invalid value");

    case HermesValue::ETag::Empty:
      llvm_unreachable("empty value");
    case HermesValue::ETag::Native1:
    case HermesValue::ETag::Native2:
      llvm_unreachable("native value");
    case HermesValue::ETag::Object1:
    case HermesValue::ETag::Object2: {
      auto res = toPrimitive_RJS(runtime, valueHandle, PreferredType::NUMBER);
      if (res == ExecutionStatus::EXCEPTION) {
        return ExecutionStatus::EXCEPTION;
      }
      return toNumber_RJS(runtime, runtime.makeHandle(res.getValue()));
    }
    case HermesValue::ETag::Str1:
    case HermesValue::ETag::Str2:
      result = stringToNumber(runtime, Handle<StringPrimitive>::vmcast(valueHandle));
      break;
    case HermesValue::ETag::BigInt1:
    case HermesValue::ETag::BigInt2:
      return runtime.raiseTypeError("Cannot convert BigInt to number");
    case HermesValue::ETag::Undefined:
      result = std::numeric_limits<double>::quiet_NaN();
      break;
    case HermesValue::ETag::Null:
      result = +0.0;
      break;
    case HermesValue::ETag::Bool:
      result = value.getBool();
      break;
    case HermesValue::ETag::Symbol:
      return runtime.raiseTypeError("Cannot convert Symbol to number");
    default:
      
      return value;
  }
  return HermesValue::encodeDoubleValue(result);
}

CallResult<HermesValue> toNumeric_RJS(Runtime &runtime, Handle<> valueHandle) {
  GCScopeMarkerRAII marker{runtime};
  auto primValue = toPrimitive_RJS(runtime, valueHandle, PreferredType::NUMBER);

  if (LLVM_UNLIKELY(primValue == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  if (primValue->isBigInt()) {
    return *primValue;
  }

  return toNumber_RJS(runtime, runtime.makeHandle(*primValue));
}

CallResult<HermesValue> toLength(Runtime &runtime, Handle<> valueHandle) {
  constexpr double maxLength = 9007199254740991.0; 
  auto res = toIntegerOrInfinity(runtime, valueHandle);
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto len = res->getNumber();
  if (len <= 0) {
    len = 0;
  } else if (len > maxLength) {
    len = maxLength;
  }
  return HermesValue::encodeDoubleValue(len);
}

CallResult<uint64_t> toLengthU64(Runtime &runtime, Handle<> valueHandle) {
  constexpr double highestIntegralDouble = ((uint64_t)1 << std::numeric_limits<double>::digits) - 1;
  auto res = toIntegerOrInfinity(runtime, valueHandle);
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto len = res->getNumber();
  if (len <= 0) {
    len = 0;
  } else if (len > highestIntegralDouble) {
    len = highestIntegralDouble;
  }
  return len;
}

CallResult<HermesValue> toIndex(Runtime &runtime, Handle<> valueHandle) {
  auto value = (valueHandle->isUndefined())
      ? runtime.makeHandle(HermesValue::encodeDoubleValue(0))
      : valueHandle;
  auto res = toIntegerOrInfinity(runtime, value);
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto integerIndex = res->getNumber();
  if (integerIndex < 0) {
    return runtime.raiseRangeError("A negative value cannot be an index");
  }
  auto integerIndexHandle = runtime.makeHandle(HermesValue::encodeDoubleValue(integerIndex));
  res = toLength(runtime, integerIndexHandle);
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto index = res.getValue();
  if (index.getNumber() != integerIndex) {
    return runtime.raiseRangeError( "The value given for the index must be between 0 and 2 ^ 53 - 1");
  }
  return res;
}

CallResult<HermesValue> toIntegerOrInfinity( Runtime &runtime, Handle<> valueHandle) {

  auto res = toNumber_RJS(runtime, valueHandle);
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  double num = res->getNumber();

  double result;
  if (std::isnan(num)) {
    result = 0;
  } else {
    result = std::trunc(num);
  }

  return HermesValue::encodeDoubleValue(result);
}


template <typename T> static inline CallResult<HermesValue> toInt( Runtime &runtime, Handle<> valueHandle) {


  auto res = toNumber_RJS(runtime, valueHandle);
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  double num = res->getNumber();
  T result = static_cast<T>(hermes::truncateToInt32(num));
  return HermesValue::encodeNumberValue(result);
}

CallResult<HermesValue> toInt8(Runtime &runtime, Handle<> valueHandle) {
  return toInt<int8_t>(runtime, valueHandle);
}

CallResult<HermesValue> toInt16(Runtime &runtime, Handle<> valueHandle) {
  return toInt<int16_t>(runtime, valueHandle);
}

CallResult<HermesValue> toInt32_RJS(Runtime &runtime, Handle<> valueHandle) {
  return toInt<int32_t>(runtime, valueHandle);
}

CallResult<HermesValue> toUInt8(Runtime &runtime, Handle<> valueHandle) {
  return toInt<uint8_t>(runtime, valueHandle);
}

uint8_t toUInt8Clamp(double number) {
  
  
  
  
  if (!(number >= 0.5)) {
    return 0;
  }

  
  if (number > 255) {
    return 255;
  }

  
  
  double toTruncate = number + 0.5;
  uint8_t x = static_cast<uint8_t>(toTruncate);

  
  if (x == toTruncate) {
    
    
    
    return (x & ~1);
  } else {
    
    return x;
  }
}

CallResult<HermesValue> toUInt8Clamp(Runtime &runtime, Handle<> valueHandle) {
  
  auto res = toNumber_RJS(runtime, valueHandle);
  if (res == ExecutionStatus::EXCEPTION) {
    
    return ExecutionStatus::EXCEPTION;
  }
  return HermesValue::encodeNumberValue(toUInt8Clamp(res->getNumber()));
}

CallResult<HermesValue> toUInt16(Runtime &runtime, Handle<> valueHandle) {
  return toInt<uint16_t>(runtime, valueHandle);
}

CallResult<HermesValue> toUInt32_RJS(Runtime &runtime, Handle<> valueHandle) {
  return toInt<uint32_t>(runtime, valueHandle);
}

CallResult<Handle<JSObject>> getPrimitivePrototype( Runtime &runtime, Handle<> base) {

  switch (base->getETag()) {

    case HermesValue::ETag::Invalid:
      llvm_unreachable("invalid value");

    case HermesValue::ETag::Empty:
      llvm_unreachable("empty value");
    case HermesValue::ETag::Native1:
    case HermesValue::ETag::Native2:
      llvm_unreachable("native value");
    case HermesValue::ETag::Object1:
    case HermesValue::ETag::Object2:
      llvm_unreachable("object value");
    case HermesValue::ETag::Undefined:
      return runtime.raiseTypeError("Cannot convert undefined value to object");
    case HermesValue::ETag::Null:
      return runtime.raiseTypeError("Cannot convert null value to object");
    case HermesValue::ETag::Str1:
    case HermesValue::ETag::Str2:
      return Handle<JSObject>::vmcast(&runtime.stringPrototype);
    case HermesValue::ETag::BigInt1:
    case HermesValue::ETag::BigInt2:
      return Handle<JSObject>::vmcast(&runtime.bigintPrototype);
    case HermesValue::ETag::Bool:
      return Handle<JSObject>::vmcast(&runtime.booleanPrototype);
    case HermesValue::ETag::Symbol:
      return Handle<JSObject>::vmcast(&runtime.symbolPrototype);
    default:
      assert(base->isNumber() && "Unknown tag in getPrimitivePrototype.");
      return Handle<JSObject>::vmcast(&runtime.numberPrototype);
  }
}

CallResult<HermesValue> toObject(Runtime &runtime, Handle<> valueHandle) {
  auto value = valueHandle.get();
  switch (value.getETag()) {

    case HermesValue::ETag::Invalid:
      llvm_unreachable("invalid value");

    case HermesValue::ETag::Empty:
      llvm_unreachable("empty value");
    case HermesValue::ETag::Native1:
    case HermesValue::ETag::Native2:
      llvm_unreachable("native value");
    case HermesValue::ETag::Undefined:
      return runtime.raiseTypeError("Cannot convert undefined value to object");
    case HermesValue::ETag::Null:
      return runtime.raiseTypeError("Cannot convert null value to object");
    case HermesValue::ETag::Object1:
    case HermesValue::ETag::Object2:
      return value;
    case HermesValue::ETag::Bool:
      return JSBoolean::create( runtime, value.getBool(), Handle<JSObject>::vmcast(&runtime.booleanPrototype))


          .getHermesValue();
    case HermesValue::ETag::BigInt1:
    case HermesValue::ETag::BigInt2:
      return JSBigInt::create( runtime, Handle<BigIntPrimitive>::vmcast(valueHandle), Handle<JSObject>::vmcast(&runtime.bigintPrototype))


          .getHermesValue();
    case HermesValue::ETag::Str1:
    case HermesValue::ETag::Str2: {
      auto res = JSString::create( runtime, Handle<StringPrimitive>::vmcast(valueHandle), Handle<JSObject>::vmcast(&runtime.stringPrototype));


      if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      return res->getHermesValue();
    }
    case HermesValue::ETag::Symbol:
      return JSSymbol::create( runtime, *Handle<SymbolID>::vmcast(valueHandle), Handle<JSObject>::vmcast(&runtime.symbolPrototype))


          .getHermesValue();
    default:
      assert(valueHandle->isNumber() && "Unknown tag in toObject.");
      return JSNumber::create( runtime, value.getNumber(), Handle<JSObject>::vmcast(&runtime.numberPrototype))


          .getHermesValue();
  }
}

ExecutionStatus amendPropAccessErrorMsgWithPropName( Runtime &runtime, Handle<> valueHandle, llvh::StringRef operationStr, SymbolID id) {



  if (!valueHandle->isNull() && !valueHandle->isUndefined()) {
    
    return ExecutionStatus::EXCEPTION;
  }
  assert(!runtime.getThrownValue().isEmpty() && "Error must have been thrown");
  
  runtime.clearThrownValue();

  
  llvh::StringRef valueStr = valueHandle->isNull() ? "null" : "undefined";
  return runtime.raiseTypeError( TwineChar16("Cannot ") + operationStr + " property '" + runtime.getIdentifierTable().getStringView(runtime, id) + "' of " + valueStr);


}







static CallResult<bool> compareBigIntAndString( Runtime &runtime, Handle<BigIntPrimitive> leftHandle, Handle<> rightHandle, bool (*comparator)(int)) {



  assert(rightHandle->isString() && "rhs should be string");

  auto bigintRight = stringToBigInt_RJS(runtime, rightHandle);
  if (LLVM_UNLIKELY(bigintRight == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  if (bigintRight->isUndefined()) { 
    return false;
  }
  assert(bigintRight->isBigInt() && "stringToBigInt resulted in non-bigint");
  return comparator(leftHandle->compare(bigintRight->getBigInt()));
}







static CallResult<bool> compareBigIntAndNumber( Runtime &runtime, Handle<BigIntPrimitive> leftHandle, double right, bool (*comparator)(int)) {



  switch (std::fpclassify(right)) {
    case FP_NAN:
      
      return false;
    case FP_INFINITE:
      
      
      return comparator(right > 0 ? -1 : 1);
    default:
      break;
  }

  
  double integralPart;
  const double fractionalPart = std::modf(right, &integralPart);

  
  
  auto rightHandle = BigIntPrimitive::fromDouble(runtime, integralPart);
  if (LLVM_UNLIKELY(rightHandle == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  
  
  if (int comparisonResult = leftHandle->compare(rightHandle->getBigInt())) {
    return comparator(comparisonResult);
  }

  
  
  if (fractionalPart != 0) {
    
    
    return comparator(right < 0 ? 1 : -1);
  }

  
  
  return comparator(0);
}










































































IMPLEMENT_COMPARISON_OP(lessOp_RJS, <);
IMPLEMENT_COMPARISON_OP(greaterOp_RJS, >);
IMPLEMENT_COMPARISON_OP(lessEqualOp_RJS, <=);
IMPLEMENT_COMPARISON_OP(greaterEqualOp_RJS, >=);


CallResult<bool> abstractEqualityTest_RJS(Runtime &runtime, Handle<> xHandle, Handle<> yHandle) {
  MutableHandle<> x{runtime, xHandle.get()};
  MutableHandle<> y{runtime, yHandle.get()};

  while (true) {
    
    
    assert( !x->isNativeValue() && !x->isEmpty() && "invalid value for comparison");
    assert( !y->isNativeValue() && !y->isEmpty() && "invalid value for comparison");

    
    
    
    

















    
    
    HermesValue::ETag xType = x->isNumber() ? HermesValue::ETag::NUMBER_TAG : x->getETag();
    HermesValue::ETag yType = y->isNumber() ? HermesValue::ETag::NUMBER_TAG : y->getETag();

    switch (HermesValue::combineETags(xType, yType)) {
      
      
      CASE_S_S(Undefined, Undefined)
      CASE_S_S(Null, Null) {
        return true;
      }
      CASE_S_S(NUMBER_TAG, NUMBER_TAG) {
        return x->getNumber() == y->getNumber();
      }
      CASE_M_M(Str, Str) {
        return x->getString()->equals(y->getString());
      }
      CASE_M_M(BigInt, BigInt) {
        return x->getBigInt()->compare(y->getBigInt()) == 0;
      }
      CASE_S_S(Bool, Bool)
      CASE_S_S(Symbol, Symbol)
      CASE_M_M(Object, Object) {
        return x->getRaw() == y->getRaw();
      }
      
      
      CASE_S_S(Undefined, Null)
      CASE_S_S(Null, Undefined) {
        return true;
      }
      
      
      CASE_S_M(NUMBER_TAG, Str) {
        return x->getNumber() == stringToNumber(runtime, Handle<StringPrimitive>::vmcast(y));
      }
      
      
      CASE_M_S(Str, NUMBER_TAG) {
        return stringToNumber(runtime, Handle<StringPrimitive>::vmcast(x)) == y->getNumber();
      }
      
      CASE_M_M(BigInt, Str) {
        
        auto n = stringToBigInt_RJS(runtime, y);
        if (LLVM_UNLIKELY(n == ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }
        
        
        
        if (n->isUndefined()) {
          return false;
        }
        
        y = n.getValue();
        break;
      }
      
      
      CASE_M_M(Str, BigInt) {
        std::swap(x, y);
        break;
      }
      
      
      CASE_S_S(Bool, NUMBER_TAG) {
        
        return x->getBool() == y->getNumber();
      }
      CASE_S_M(Bool, Str) {
        
        return x->getBool() == stringToNumber(runtime, Handle<StringPrimitive>::vmcast(y));
      }
      CASE_S_M(Bool, BigInt) {
        return y->getBigInt()->compare(static_cast<int32_t>(x->getBool())) == 0;
      }
      CASE_S_M(Bool, Object) {
        x = HermesValue::encodeDoubleValue(x->getBool());
        break;
      }
      
      
      CASE_S_S(NUMBER_TAG, Bool) {
        return x->getNumber() == y->getBool();
      }
      CASE_M_S(Str, Bool) {
        return stringToNumber(runtime, Handle<StringPrimitive>::vmcast(x)) == y->getBool();
      }
      CASE_M_S(BigInt, Bool) {
        return x->getBigInt()->compare(static_cast<int32_t>(y->getBool())) == 0;
      }
      CASE_M_S(Object, Bool) {
        y = HermesValue::encodeDoubleValue(y->getBool());
        break;
      }
      
      
      CASE_M_M(Str, Object)
      CASE_M_M(BigInt, Object)
      CASE_S_M(Symbol, Object)
      CASE_S_M(NUMBER_TAG, Object) {
        auto status = toPrimitive_RJS(runtime, y, PreferredType::NONE);
        if (status == ExecutionStatus::EXCEPTION) {
          return ExecutionStatus::EXCEPTION;
        }
        y = status.getValue();
        break;
      }
      
      
      CASE_M_M(Object, Str)
      CASE_M_M(Object, BigInt)
      CASE_M_S(Object, Symbol)
      CASE_M_S(Object, NUMBER_TAG) {
        auto status = toPrimitive_RJS(runtime, x, PreferredType::NONE);
        if (status == ExecutionStatus::EXCEPTION) {
          return ExecutionStatus::EXCEPTION;
        }
        x = status.getValue();
        break;
      }
      
      
      
      
      CASE_M_S(BigInt, NUMBER_TAG) {
        std::swap(x, y);
        LLVM_FALLTHROUGH;
      }
      CASE_S_M(NUMBER_TAG, BigInt) {
        if (!isIntegralNumber(x->getNumber())) {
          return false;
        }

        auto xAsBigInt = BigIntPrimitive::fromDouble(runtime, x->getNumber());
        if (LLVM_UNLIKELY(xAsBigInt == ExecutionStatus::EXCEPTION)) {
          return ExecutionStatus::EXCEPTION;
        }
        return xAsBigInt->getBigInt()->compare(y->getBigInt()) == 0;
      }

      
      default:
        return false;
    }






  }
}

bool strictEqualityTest(HermesValue x, HermesValue y) {
  
  
  if (x.isNumber())
    return y.isNumber() && x.getNumber() == y.getNumber();
  
  if (x.getRaw() == y.getRaw())
    return true;
  
  if (x.getTag() != y.getTag())
    return false;
  
  if (x.isString())
    return x.getString()->equals(y.getString());

  
  return x.isBigInt() && x.getBigInt()->compare(y.getBigInt()) == 0;
}

CallResult<HermesValue> addOp_RJS(Runtime &runtime, Handle<> xHandle, Handle<> yHandle) {
  auto resX = toPrimitive_RJS(runtime, xHandle, PreferredType::NONE);
  if (resX == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto xPrim = runtime.makeHandle(resX.getValue());

  auto resY = toPrimitive_RJS(runtime, yHandle, PreferredType::NONE);
  if (resY == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  auto yPrim = runtime.makeHandle(resY.getValue());

  
  if (xPrim->isString() || yPrim->isString()) {
    auto resX = toString_RJS(runtime, xPrim);
    if (resX == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    auto xStr = runtime.makeHandle(std::move(*resX));

    auto resY = toString_RJS(runtime, yPrim);
    if (resY == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
    auto yStr = runtime.makeHandle(std::move(*resY));

    return StringPrimitive::concat(runtime, xStr, yStr);
  }

  
  
  if (LLVM_LIKELY(!xPrim->isBigInt())) {
    
    auto res = toNumber_RJS(runtime, xPrim);
    if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    const double xNum = res->getNumber();
    
    
    
    res = toNumber_RJS(runtime, yPrim);
    if (LLVM_UNLIKELY(res == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    const double yNum = res->getNumber();
    return HermesValue::encodeDoubleValue(xNum + yNum);
  }

  
  
  if (!yPrim->isBigInt()) {
    return runtime.raiseTypeErrorForValue( "Cannot convert ", yHandle, " to BigInt");
  }

  return BigIntPrimitive::add( runtime, runtime.makeHandle(resX->getBigInt()), runtime.makeHandle(resY->getBigInt()));


}

static const size_t MIN_RADIX = 2;
static const size_t MAX_RADIX = 36;

static inline char toRadixChar(unsigned x, unsigned radix) {
  const char chars[] = "0123456789abcdefghijklmnopqrstuvwxyz";
  static_assert(sizeof(chars) - 1 == MAX_RADIX, "Invalid chars array");
  assert( x < radix && x < std::strlen(chars) && "invalid number to radix conversion");

  return chars[x];
}


static inline int doubleExponent(double x) {
  int e;
  std::frexp(x, &e);
  return e;
}

Handle<StringPrimitive> numberToStringWithRadix(Runtime &runtime, double number, unsigned radix) {
  (void)MIN_RADIX;
  (void)MAX_RADIX;
  assert(MIN_RADIX <= radix && radix <= MAX_RADIX && "Invalid radix");
  
  llvh::SmallString<64> result{};

  
  llvh::SmallString<32> fStr{};

  
  bool negative = false;
  if (number < 0) {
    negative = true;
    number = -number;
  }

  
  double iPart;
  double fPart = std::modf(number, &iPart);

  
  if (fPart != 0) {
    
    double next = std::nextafter(number, std::numeric_limits<double>::infinity());
    double minDenorm = std::nextafter(0.0, std::numeric_limits<double>::infinity());

    
    
    
    
    double delta = std::max(0.5 * (next - number), minDenorm);

    while (fPart > delta) {
      
      fPart *= radix;
      delta *= radix;
      
      unsigned digit = static_cast<unsigned>(fPart);
      fStr.push_back(toRadixChar(digit, radix));
      
      fPart -= digit;
      
      if (fPart > 0.5 || (fPart == 0.5 && (digit & 1))) {
        
        if (fPart + delta > 1) {
          
          
          
          
          
          while (true) {
            
            if (fStr.size() == 0) {
              
              
              ++iPart;
              break;
            }
            
            char &c = fStr.back();
            unsigned digitForC = c <= '9' ? c - '0' : c - 'a' + 10;
            if (digitForC + 1 < radix) {
              
              c = toRadixChar(digitForC + 1, radix);
              break;
            }
            
            
            
            fStr.pop_back();
          }
          
          break;
        }
      }
    }
  }

  
  if (iPart == 0) {
    result.push_back('0');
  } else {
    

    
    
    
    
    
    constexpr const int MANTISSA_SIZE = DBL_MANT_DIG - 1;

    
    while (doubleExponent(iPart / radix) > MANTISSA_SIZE) {
      
      
      
      
      result.push_back('0');
      iPart /= radix;
    }

    
    
    while (iPart > 0) {
      
      int digit = static_cast<int>(std::fmod(iPart, radix));
      result.push_back(toRadixChar(digit, radix));
      iPart = (iPart - digit) / radix;
    }

    
    std::reverse(result.begin(), result.end());
  }

  
  if (!fStr.empty()) {
    result += '.';
    result += fStr;
  }

  
  if (negative) {
    result.insert(result.begin(), '-');
  }

  return runtime.makeHandle<StringPrimitive>(runtime.ignoreAllocationFailure( StringPrimitive::create(runtime, result)));
}

CallResult<PseudoHandle<>> getMethod(Runtime &runtime, Handle<> O, Handle<> key) {
  GCScopeMarkerRAII gcScope{runtime};
  auto objRes = toObject(runtime, O);
  if (LLVM_UNLIKELY(objRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto obj = runtime.makeHandle<JSObject>(*objRes);
  auto funcRes = JSObject::getComputed_RJS(obj, runtime, key);
  if (LLVM_UNLIKELY(funcRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  if ((*funcRes)->isUndefined() || (*funcRes)->isNull()) {
    return PseudoHandle<>::create(HermesValue::encodeUndefinedValue());
  }
  if (!vmisa<Callable>(funcRes->get())) {
    return runtime.raiseTypeError("Could not get callable method from object");
  }
  return funcRes;
}

CallResult<IteratorRecord> getIterator( Runtime &runtime, Handle<> obj, llvh::Optional<Handle<Callable>> methodOpt) {


  MutableHandle<Callable> method{runtime};
  if (LLVM_LIKELY(!methodOpt.hasValue())) {
    auto methodRes = getMethod( runtime, obj, runtime.makeHandle( Predefined::getSymbolID(Predefined::SymbolIterator)));



    if (LLVM_UNLIKELY(methodRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    if (!vmisa<Callable>(methodRes->getHermesValue())) {
      return runtime.raiseTypeError("iterator method is not callable");
    }
    method = vmcast<Callable>(methodRes->getHermesValue());
  } else {
    method = **methodOpt;
  }
  auto iteratorRes = Callable::executeCall0(method, runtime, obj);
  if (LLVM_UNLIKELY(iteratorRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  if (LLVM_UNLIKELY(!(*iteratorRes)->isObject())) {
    return runtime.raiseTypeError("iterator is not an object");
  }
  auto iterator = runtime.makeHandle<JSObject>(std::move(*iteratorRes));

  CallResult<PseudoHandle<>> nextMethodRes = JSObject::getNamed_RJS( iterator, runtime, Predefined::getSymbolID(Predefined::next));
  if (LLVM_UNLIKELY(nextMethodRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  
  
  if (!vmisa<Callable>(nextMethodRes->get())) {
    return runtime.raiseTypeError("'next' method on iterator must be callable");
  }

  auto nextMethod = Handle<Callable>::vmcast(runtime.makeHandle(std::move(*nextMethodRes)));

  return IteratorRecord{iterator, nextMethod};
}

CallResult<PseudoHandle<JSObject>> iteratorNext( Runtime &runtime, const IteratorRecord &iteratorRecord, llvh::Optional<Handle<>> value) {


  GCScopeMarkerRAII marker{runtime};
  auto resultRes = value ? Callable::executeCall1( iteratorRecord.nextMethod, runtime, iteratorRecord.iterator, value->getHermesValue())




      : Callable::executeCall0( iteratorRecord.nextMethod, runtime, iteratorRecord.iterator);
  if (LLVM_UNLIKELY(resultRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  if (LLVM_UNLIKELY(!(*resultRes)->isObject())) {
    return runtime.raiseTypeError("iterator.next() did not return an object");
  }
  return PseudoHandle<JSObject>::vmcast(std::move(*resultRes));
}

CallResult<Handle<JSObject>> iteratorStep( Runtime &runtime, const IteratorRecord &iteratorRecord) {

  auto resultRes = iteratorNext(runtime, iteratorRecord);
  if (LLVM_UNLIKELY(resultRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  Handle<JSObject> result = runtime.makeHandle(std::move(*resultRes));
  auto completeRes = JSObject::getNamed_RJS( result, runtime, Predefined::getSymbolID(Predefined::done));
  if (LLVM_UNLIKELY(completeRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  if (toBoolean(completeRes->get())) {
    return Runtime::makeNullHandle<JSObject>();
  }
  return result;
}

ExecutionStatus iteratorClose( Runtime &runtime, Handle<JSObject> iterator, Handle<> completion) {


  ExecutionStatus completionStatus = completion->isEmpty()
      ? ExecutionStatus::RETURNED : ExecutionStatus::EXCEPTION;

  
  
  
  
  auto returnRes = getMethod( runtime, iterator, runtime.makeHandle(Predefined::getSymbolID(Predefined::returnStr)));



  MutableHandle<> innerResult{runtime};
  if (LLVM_LIKELY(returnRes != ExecutionStatus::EXCEPTION)) {
    if (!vmisa<Callable>(returnRes->getHermesValue())) {
      runtime.setThrownValue(*completion);
      return completionStatus;
    }
    Handle<Callable> returnFn = runtime.makeHandle(vmcast<Callable>(returnRes->getHermesValue()));
    auto innerResultRes = Callable::executeCall0(returnFn, runtime, iterator);
    if (LLVM_UNLIKELY(innerResultRes == ExecutionStatus::EXCEPTION)) {
      if (isUncatchableError(runtime.getThrownValue())) {
        
        
        
        return ExecutionStatus::EXCEPTION;
      }
      
      
      
    } else {
      innerResult = std::move(*innerResultRes);
    }
  }
  
  
  
  if (completionStatus == ExecutionStatus::EXCEPTION) {
    
    
    runtime.setThrownValue(*completion);
    return ExecutionStatus::EXCEPTION;
  }
  if (LLVM_UNLIKELY(!runtime.getThrownValue().isEmpty())) {
    
    
    
    return ExecutionStatus::EXCEPTION;
  }
  if (!innerResult->isObject()) {
    
    
    return runtime.raiseTypeError("iterator.return() did not return an object");
  }
  return ExecutionStatus::RETURNED;
}

bool isUncatchableError(HermesValue value) {
  if (auto *jsError = dyn_vmcast<JSError>(value)) {
    return !jsError->catchable();
  }
  return false;
}

Handle<JSObject> createIterResultObject(Runtime &runtime, Handle<> value, bool done) {
  auto objHandle = runtime.makeHandle(JSObject::create(runtime));
  auto status = JSObject::defineOwnProperty( objHandle, runtime, Predefined::getSymbolID(Predefined::value), DefinePropertyFlags::getDefaultNewPropertyFlags(), value);




  (void)status;
  assert( status != ExecutionStatus::EXCEPTION && *status && "put own value property cannot fail");

  status = JSObject::defineOwnProperty( objHandle, runtime, Predefined::getSymbolID(Predefined::done), DefinePropertyFlags::getDefaultNewPropertyFlags(), Runtime::getBoolValue(done));




  assert( status != ExecutionStatus::EXCEPTION && *status && "put own value property cannot fail");

  return objHandle;
}

CallResult<Handle<Callable>> speciesConstructor( Handle<JSObject> O, Runtime &runtime, Handle<Callable> defaultConstructor) {


  
  
  auto res = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::constructor));
  if (res == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }
  PseudoHandle<> cons = std::move(*res);
  if (cons->isUndefined()) {
    return defaultConstructor;
  }
  if (!cons->isObject()) {
    return runtime.raiseTypeError( "Constructor must be an object if it is not undefined");
  }
  
  
  return defaultConstructor;
}

CallResult<bool> isConstructor(Runtime &runtime, HermesValue value) {
  return isConstructor(runtime, dyn_vmcast<Callable>(value));
}

CallResult<bool> isConstructor(Runtime &runtime, Callable *callable) {
  
  
  
  if (!callable) {
    return false;
  }

  
  while (BoundFunction *b = dyn_vmcast<BoundFunction>(callable)) {
    callable = b->getTarget(runtime);
  }

  
  if (auto *func = dyn_vmcast<JSFunction>(callable)) {
    auto *cb = func->getCodeBlock(runtime);
    
    
    cb->lazyCompile(runtime);
    return !func->getCodeBlock(runtime)->getHeaderFlags().isCallProhibited( true);
  }

  
  
  if (!vmisa<NativeFunction>(callable) || vmisa<NativeConstructor>(callable)) {
    return true;
  }

  
  
  if (auto *cproxy = dyn_vmcast<JSCallableProxy>(callable)) {
    return cproxy->isConstructor(runtime);
  }

  return false;
}

CallResult<bool> ordinaryHasInstance(Runtime &runtime, Handle<> constructor, Handle<> object) {
  
  if (!vmisa<Callable>(*constructor)) {
    return false;
  }

  Callable *ctor = vmcast<Callable>(*constructor);

  BoundFunction *bound;
  
  while (LLVM_UNLIKELY(bound = dyn_vmcast<BoundFunction>(ctor))) {
    
    
    
    
    
    
    
    ctor = bound->getTarget(runtime);
  }

  
  assert(ctor != nullptr && "ctor must not be null");

  
  if (LLVM_UNLIKELY(!object->isObject())) {
    return false;
  }

  
  auto propRes = JSObject::getNamed_RJS( runtime.makeHandle(ctor), runtime, Predefined::getSymbolID(Predefined::prototype));


  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  
  Handle<JSObject> ctorPrototype = runtime.makeHandle( PseudoHandle<JSObject>::dyn_vmcast(std::move(*propRes)));
  if (LLVM_UNLIKELY(!ctorPrototype)) {
    return runtime.raiseTypeError( "function's '.prototype' is not an object in 'instanceof'");
  }

  
  
  
  
  
  
  
  constexpr unsigned int kMaxProxyCount = 1024;
  unsigned int proxyCount = 0;
  MutableHandle<JSObject> head{runtime, vmcast<JSObject>(object.get())};
  GCScopeMarkerRAII gcScope{runtime};
  
  while (true) {
    
    CallResult<PseudoHandle<JSObject>> parentRes = JSObject::getPrototypeOf(head, runtime);
    if (LLVM_UNLIKELY(parentRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    
    if (!*parentRes) {
      return false;
    }
    
    if (parentRes->get() == ctorPrototype.get()) {
      return true;
    }
    if (head->isProxyObject()) {
      ++proxyCount;
      if (proxyCount > kMaxProxyCount) {
        return runtime.raiseRangeError( "Maximum prototype chain length exceeded");
      }
    }
    head = parentRes->get();
    gcScope.flush();
  }
}

CallResult<bool> instanceOfOperator_RJS( Runtime &runtime, Handle<> object, Handle<> constructor) {


  
  if (LLVM_UNLIKELY(!constructor->isObject())) {
    return runtime.raiseTypeError( "right operand of 'instanceof' is not an object");
  }

  
  
  
  if (vmisa<JSFunction>(*constructor)) {
    return ordinaryHasInstance(runtime, constructor, object);
  }

  
  CallResult<PseudoHandle<>> instOfHandlerRes = JSObject::getNamed_RJS( Handle<JSObject>::vmcast(constructor), runtime, Predefined::getSymbolID(Predefined::SymbolHasInstance));


  if (LLVM_UNLIKELY(instOfHandlerRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  auto instOfHandler = runtime.makeHandle(std::move(*instOfHandlerRes));

  
  if (!instOfHandler->isUndefined()) {
    
    if (!vmisa<Callable>(*instOfHandler)) {
      return runtime.raiseTypeError("instanceof handler must be callable");
    }
    auto callRes = Callable::executeCall1( Handle<Callable>::vmcast(instOfHandler), runtime, constructor, *object);
    if (LLVM_UNLIKELY(callRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    return toBoolean(callRes->get());
  }

  
  if (!vmisa<Callable>(*constructor)) {
    return runtime.raiseTypeError( "right operand of 'instanceof' is not callable");
  }

  
  return ordinaryHasInstance(runtime, constructor, object);
}




CallResult<bool> isRegExp(Runtime &runtime, Handle<> arg) {
  
  if (!arg->isObject()) {
    return false;
  }
  Handle<JSObject> obj = Handle<JSObject>::vmcast(arg);
  
  auto propRes = JSObject::getNamed_RJS( obj, runtime, Predefined::getSymbolID(Predefined::SymbolMatch));
  
  if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  
  if (!(*propRes)->isUndefined()) {
    return toBoolean(propRes->get());
  }
  
  
  return vmisa<JSRegExp>(arg.get());
}

CallResult<Handle<StringPrimitive>> symbolDescriptiveString( Runtime &runtime, Handle<SymbolID> sym) {

  
  
  
  
  auto desc = runtime.makeHandle<StringPrimitive>( runtime.getStringPrimFromSymbolID(*sym));
  SafeUInt32 descLen(desc->getStringLength());
  descLen.add(8);

  
  auto builder = StringBuilder::createStringBuilder(runtime, descLen);
  if (LLVM_UNLIKELY(builder == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }
  builder->appendASCIIRef({"Symbol(", 7});
  builder->appendStringPrim(desc);
  builder->appendCharacter(')');

  return builder->getStringPrimitive();
}

CallResult<bool> isArray(Runtime &runtime, JSObject *obj) {
  if (!obj) {
    return false;
  }
  while (true) {
    if (vmisa<JSArray>(obj)) {
      return true;
    }
    if (LLVM_LIKELY(!obj->isProxyObject())) {
      return false;
    }
    if (JSProxy::isRevoked(obj, runtime)) {
      return runtime.raiseTypeError("Proxy has been revoked");
    }
    obj = JSProxy::getTarget(obj, runtime).get();
    assert(obj && "target of non-revoked Proxy is null");
  }
}

CallResult<bool> isConcatSpreadable(Runtime &runtime, Handle<> value) {
  auto O = Handle<JSObject>::dyn_vmcast(value);
  if (!O) {
    return false;
  }

  CallResult<PseudoHandle<>> spreadable = JSObject::getNamed_RJS( O, runtime, Predefined::getSymbolID(Predefined::SymbolIsConcatSpreadable));


  if (LLVM_UNLIKELY(spreadable == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  if (!(*spreadable)->isUndefined()) {
    return toBoolean(spreadable->get());
  }

  return isArray(runtime, *O);
}

ExecutionStatus toPropertyDescriptor( Handle<> obj, Runtime &runtime, DefinePropertyFlags &flags, MutableHandle<> &valueOrAccessor) {



  GCScopeMarkerRAII gcMarker{runtime};

  
  auto attributes = Handle<JSObject>::dyn_vmcast(obj);
  if (!attributes) {
    return runtime.raiseTypeError( "Object.defineProperty() Attributes argument is not an object");
  }

  NamedPropertyDescriptor desc;

  
  if (JSObject::getNamedDescriptorPredefined( attributes, runtime, Predefined::enumerable, desc)) {
    auto propRes = JSObject::getNamed_RJS( attributes, runtime, Predefined::getSymbolID(Predefined::enumerable), PropOpFlags().plusThrowOnError());



    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    flags.enumerable = toBoolean(propRes->get());
    flags.setEnumerable = true;
  }

  
  if (JSObject::getNamedDescriptorPredefined( attributes, runtime, Predefined::configurable, desc)) {
    auto propRes = JSObject::getNamed_RJS( attributes, runtime, Predefined::getSymbolID(Predefined::configurable), PropOpFlags().plusThrowOnError());



    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    flags.configurable = toBoolean(propRes->get());
    flags.setConfigurable = true;
  }

  
  if (JSObject::getNamedDescriptorPredefined( attributes, runtime, Predefined::value, desc)) {
    auto propRes = JSObject::getNamed_RJS( attributes, runtime, Predefined::getSymbolID(Predefined::value), PropOpFlags().plusThrowOnError());



    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    valueOrAccessor = std::move(*propRes);
    flags.setValue = true;
  }

  
  if (JSObject::getNamedDescriptorPredefined( attributes, runtime, Predefined::writable, desc)) {
    auto propRes = JSObject::getNamed_RJS( attributes, runtime, Predefined::getSymbolID(Predefined::writable), PropOpFlags().plusThrowOnError());



    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    flags.writable = toBoolean(propRes->get());
    flags.setWritable = true;
  }

  
  MutableHandle<Callable> getterPtr{runtime};
  if (JSObject::getNamedDescriptorPredefined( attributes, runtime, Predefined::get, desc)) {
    auto propRes = JSObject::getNamed_RJS( attributes, runtime, Predefined::getSymbolID(Predefined::get), PropOpFlags().plusThrowOnError());



    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    flags.setGetter = true;
    PseudoHandle<> getter = std::move(*propRes);
    if (LLVM_LIKELY(!getter->isUndefined())) {
      getterPtr = dyn_vmcast<Callable>(getter.get());
      if (LLVM_UNLIKELY(!getterPtr)) {
        return runtime.raiseTypeError( "Invalid property descriptor. Getter must be a function.");
      }
    }
  }

  
  MutableHandle<Callable> setterPtr{runtime};
  if (JSObject::getNamedDescriptorPredefined( attributes, runtime, Predefined::set, desc)) {
    auto propRes = JSObject::getNamed_RJS( attributes, runtime, Predefined::getSymbolID(Predefined::set), PropOpFlags().plusThrowOnError());



    if (LLVM_UNLIKELY(propRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    flags.setSetter = true;
    PseudoHandle<> setter = std::move(*propRes);
    if (LLVM_LIKELY(!setter->isUndefined())) {
      setterPtr = PseudoHandle<Callable>::dyn_vmcast(std::move(setter));
      if (LLVM_UNLIKELY(!setterPtr)) {
        return runtime.raiseTypeError( "Invalid property descriptor. Setter must be a function.");
      }
    }
  }

  
  if (flags.setSetter || flags.setGetter) {
    if (flags.setValue) {
      return runtime.raiseTypeError( "Invalid property descriptor. Can't set both accessor and value.");
    }
    if (flags.setWritable) {
      return runtime.raiseTypeError( "Invalid property descriptor. Can't set both accessor and writable.");
    }
    auto crtRes = PropertyAccessor::create(runtime, getterPtr, setterPtr);
    if (LLVM_UNLIKELY(crtRes == ExecutionStatus::EXCEPTION)) {
      return ExecutionStatus::EXCEPTION;
    }
    valueOrAccessor = *crtRes;
  }

  return ExecutionStatus::RETURNED;
}

CallResult<HermesValue> objectFromPropertyDescriptor( Runtime &runtime, ComputedPropertyDescriptor desc, Handle<> valueOrAccessor) {


  Handle<JSObject> obj = runtime.makeHandle(JSObject::create(runtime));

  DefinePropertyFlags dpf = DefinePropertyFlags::getDefaultNewPropertyFlags();

  if (!desc.flags.accessor) {
    
    auto result = JSObject::defineOwnProperty( obj, runtime, Predefined::getSymbolID(Predefined::value), dpf, valueOrAccessor, PropOpFlags().plusThrowOnError());





    assert( result != ExecutionStatus::EXCEPTION && "defineOwnProperty() failed on a new object");

    if (result == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }

    result = JSObject::defineOwnProperty( obj, runtime, Predefined::getSymbolID(Predefined::writable), dpf, Runtime::getBoolValue(desc.flags.writable), PropOpFlags().plusThrowOnError());





    assert( result != ExecutionStatus::EXCEPTION && "defineOwnProperty() failed on a new object");

    if (result == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
  } else {
    
    auto *accessor = vmcast<PropertyAccessor>(valueOrAccessor.get());

    auto getter = runtime.makeHandle( accessor->getter ? HermesValue::encodeObjectValue( accessor->getter.getNonNull(runtime))

                         : HermesValue::encodeUndefinedValue());

    auto setter = runtime.makeHandle( accessor->setter ? HermesValue::encodeObjectValue( accessor->setter.getNonNull(runtime))

                         : HermesValue::encodeUndefinedValue());

    auto result = JSObject::defineOwnProperty( obj, runtime, Predefined::getSymbolID(Predefined::get), dpf, getter, PropOpFlags().plusThrowOnError());





    assert( result != ExecutionStatus::EXCEPTION && "defineOwnProperty() failed on a new object");

    if (result == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }

    result = JSObject::defineOwnProperty( obj, runtime, Predefined::getSymbolID(Predefined::set), dpf, setter, PropOpFlags().plusThrowOnError());





    assert( result != ExecutionStatus::EXCEPTION && "defineOwnProperty() failed on a new object");

    if (result == ExecutionStatus::EXCEPTION) {
      return ExecutionStatus::EXCEPTION;
    }
  }

  auto result = JSObject::defineOwnProperty( obj, runtime, Predefined::getSymbolID(Predefined::enumerable), dpf, Runtime::getBoolValue(desc.flags.enumerable), PropOpFlags().plusThrowOnError());





  assert( result != ExecutionStatus::EXCEPTION && "defineOwnProperty() failed on a new object");

  if (result == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }

  result = JSObject::defineOwnProperty( obj, runtime, Predefined::getSymbolID(Predefined::configurable), dpf, Runtime::getBoolValue(desc.flags.configurable), PropOpFlags().plusThrowOnError());





  assert( result != ExecutionStatus::EXCEPTION && "defineOwnProperty() failed on a new object");

  if (result == ExecutionStatus::EXCEPTION) {
    return ExecutionStatus::EXCEPTION;
  }

  return obj.getHermesValue();
}

CallResult<HermesValue> numberToBigInt(Runtime &runtime, double number) {
  if (!isIntegralNumber(number)) {
    return runtime.raiseRangeError("number is not integral");
  }

  return BigIntPrimitive::fromDouble(runtime, number);
}

bool isIntegralNumber(double number) {
  
  

  
  if (std::isnan(number) || number == std::numeric_limits<double>::infinity() || number == -std::numeric_limits<double>::infinity()) {
    return false;
  }

  
  if (std::floor(std::abs(number)) != std::abs(number)) {
    return false;
  }

  
  return true;
}

CallResult<HermesValue> toBigInt_RJS(Runtime &runtime, Handle<> value) {
  auto prim = toPrimitive_RJS(runtime, value, PreferredType::NUMBER);
  if (LLVM_UNLIKELY(prim == ExecutionStatus::EXCEPTION)) {
    return ExecutionStatus::EXCEPTION;
  }

  switch (prim->getETag()) {
    default:
      break;
    case HermesValue::ETag::Undefined:
      return runtime.raiseTypeError("invalid argument to BigInt()");
    case HermesValue::ETag::Null:
      return runtime.raiseTypeError("invalid argument to BigInt()");
    case HermesValue::ETag::Bool:
      return BigIntPrimitive::fromSigned(runtime, prim->getBool() ? 1 : 0);
    case HermesValue::ETag::BigInt1:
    case HermesValue::ETag::BigInt2:
      return *prim;
    case HermesValue::ETag::Str1:
    case HermesValue::ETag::Str2: {
      auto n = stringToBigInt_RJS(runtime, runtime.makeHandle(*prim));
      if (LLVM_UNLIKELY(n == ExecutionStatus::EXCEPTION)) {
        return ExecutionStatus::EXCEPTION;
      }
      if (n->isUndefined()) {
        return runtime.raiseSyntaxError("can't convert string to bigint");
      }
      return *n;
    }
    case HermesValue::ETag::Symbol:
      return runtime.raiseTypeError("invalid argument to BigInt()");
  }

  return runtime.raiseTypeError("invalid argument to BigInt()");
}

CallResult<HermesValue> stringToBigInt_RJS(Runtime &runtime, Handle<> value) {
  if (value->isString()) {
    auto str = value->getString();

    std::string outError;
    auto parsedBigInt = str->isASCII()
        ? bigint::ParsedBigInt::parsedBigIntFromStringIntegerLiteral( str->getStringRef<char>(), &outError)
        : bigint::ParsedBigInt::parsedBigIntFromStringIntegerLiteral( str->getStringRef<char16_t>(), &outError);
    if (!parsedBigInt) {
      return HermesValue::encodeUndefinedValue();
    }

    return BigIntPrimitive::fromBytes(runtime, parsedBigInt->getBytes());
  }

  return runtime.raiseTypeError("Invalid argument to stringToBigInt");
}

CallResult<HermesValue> thisBigIntValue(Runtime &runtime, Handle<> value) {
  if (value->isBigInt())
    return *value;
  if (auto *jsBigInt = dyn_vmcast<JSBigInt>(*value))
    return HermesValue::encodeBigIntValue( JSBigInt::getPrimitiveBigInt(jsBigInt, runtime));
  return runtime.raiseTypeError("value is not a bigint");
}

} 
} 
