





































namespace HPHP {

namespace {

enum class ArrayKind { PHP, Dict, Vec, Keyset };

[[noreturn]] NEVER_INLINE void throwUnexpectedSep(char expect, char actual) {
  throw Exception("Expected '%c' but got '%c'", expect, actual);
}

[[noreturn]] NEVER_INLINE void throwOutOfRange(int64_t id) {
  throw Exception("Id %" PRId64 " out of range", id);
}

[[noreturn]] NEVER_INLINE void throwUnexpectedStr(const char* expect, folly::StringPiece& actual) {
  throw Exception("Expected '%s' but got '%.*s'", expect, (int)actual.size(), actual.data());
}

[[noreturn]] NEVER_INLINE void throwUnknownType(char type) {
  throw Exception("Unknown type '%c'", type);
}

[[noreturn]] NEVER_INLINE void throwInvalidPair() {
  throw Exception("Pair objects must have exactly 2 elements");
}

[[noreturn]] NEVER_INLINE void throwInvalidOFormat(const String& clsName) {
  throw Exception("%s does not support the 'O' serialization format", clsName.data());
}

[[noreturn]] NEVER_INLINE void throwMangledPrivateProperty() {
  throw Exception("Mangled private object property");
}

[[noreturn]] NEVER_INLINE void throwUnterminatedProperty() {
  throw Exception("Object property not terminated properly");
}

[[noreturn]] NEVER_INLINE void throwNotCollection(const String& clsName) {
  throw Exception("%s is not a collection class", clsName.data());
}

[[noreturn]] NEVER_INLINE void throwUnexpectedType(const String& key, const ObjectData* obj, TypedValue type) {

  auto msg = folly::format( "Property {} for class {} was deserialized with type ({}) that " "didn't match what we inferred in static analysis", key, obj->getVMClass()->name(), tname(type.m_type)




  ).str();
  throw Exception(msg);
}

[[noreturn]] NEVER_INLINE void throwUnexpectedType(const StringData* key, const ObjectData* obj, TypedValue type) {

  String str(key->data(), key->size(), CopyString);
  throwUnexpectedType(str, obj, type);
}

[[noreturn]] NEVER_INLINE void throwArraySizeOutOfBounds() {
  throw Exception("Array size out of bounds");
}

[[noreturn]] NEVER_INLINE void throwInvalidKey() {
  throw Exception("Invalid key");
}

[[noreturn]] NEVER_INLINE void throwUnterminatedElement() {
  throw Exception("Array element not terminated properly");
}

[[noreturn]] NEVER_INLINE void throwLargeStringSize(int64_t size) {
  throw Exception("Size of serialized string (%" PRId64 ") exceeds max", size);
}

[[noreturn]] NEVER_INLINE void throwNegativeStringSize(int64_t size) {
  throw Exception("Size of serialized string (%" PRId64 ") " "must not be negative", size);
}

[[noreturn]] NEVER_INLINE void throwBadFormat(const ObjectData* obj, char type) {
  throw Exception("%s does not support the '%c' serialization format", header_names[(int)obj->headerKind()], type);
}

[[noreturn]] NEVER_INLINE void throwInvalidHashKey(const ObjectData* obj) {
  throw Exception("%s values must be integers or strings", header_names[(int)obj->headerKind()]);
}

[[noreturn]] NEVER_INLINE void throwColRKey() {
  throw Exception("Referring to collection keys using the 'r' encoding " "is not supported");
}

[[noreturn]] NEVER_INLINE void throwColRefValue() {
  throw Exception("Collection values cannot be taken by reference");
}

[[noreturn]] NEVER_INLINE void throwColRefKey() {
  throw Exception("Collection keys cannot be taken by reference");
}

[[noreturn]] NEVER_INLINE void throwUnexpectedEOB() {
  throw Exception("Unexpected end of buffer during unserialization");
}

[[noreturn]] NEVER_INLINE void throwVecRefValue() {
  throw Exception("Vecs cannot contain references");
}

[[noreturn]] NEVER_INLINE void throwDictRefValue() {
  throw Exception("Dicts cannot contain references");
}

[[noreturn]] NEVER_INLINE void throwKeysetValue() {
  throw Exception("Keysets can only contain integers and strings");
}

[[noreturn]] NEVER_INLINE void throwInvalidClassName() {
  throw Exception("Provided class name is invalid");
}

void warnOrThrowUnknownClass(const String& clsName) {
  if (RuntimeOption::EvalForbidUnserializeIncompleteClass) {
    auto const msg = folly::sformat( "Attempted to unserialize class named '{}' but it doesn't exist", clsName.toCppString()

    );
    if (RuntimeOption::EvalForbidUnserializeIncompleteClass > 1) {
      throw_object("Exception", make_vec_array(msg));
    } else {
      raise_warning(msg);
    }
  }
}
}

const StaticString s_serialized("serialized"), s_unserialize("unserialize"), s_PHP_Incomplete_Class("__PHP_Incomplete_Class"), s_PHP_Incomplete_Class_Name("__PHP_Incomplete_Class_Name"), s___wakeup("__wakeup");







const StaticString s_force_darrays{"force_darrays";
const StaticString s_mark_legacy_arrays{"mark_legacy_arrays";

VariableUnserializer::VariableUnserializer( const char* str, size_t len, Type type, bool allowUnknownSerializableClass, const Array& options)




    : m_type(type)
    , m_readOnly(false)
    , m_buf(str)
    , m_end(str + len)
    , m_unknownSerializable(allowUnknownSerializableClass)
    , m_options(options)
    , m_begin(str)
    , m_forceDArrays{m_options[s_force_darrays].toBoolean()}
    , m_markLegacyArrays{m_options[s_mark_legacy_arrays].toBoolean()}
{}

VariableUnserializer::Type VariableUnserializer::type() const {
  return m_type;
}

bool VariableUnserializer::allowUnknownSerializableClass() const {
  return m_unknownSerializable;
}

const char* VariableUnserializer::head() const {
  return m_buf;
}

const char* VariableUnserializer::begin() const {
  return m_begin;
}

const char* VariableUnserializer::end() const {
  return m_end;
}

char VariableUnserializer::peek() const {
  check();
  return *m_buf;
}

char VariableUnserializer::peekBack() const {
  return m_buf[-1];
}

bool VariableUnserializer::endOfBuffer() const {
  return m_buf >= m_end;
}

char VariableUnserializer::readChar() {
  check();
  return *(m_buf++);
}

void VariableUnserializer::add(tv_lval v, UnserializeMode mode) {
  switch (mode) {
    case UnserializeMode::Value:  m_refs.emplace_back(v); break;
    
    case UnserializeMode::ColKey: m_refs.emplace_back(nullptr); break;
    case UnserializeMode::Key:    break;
  }
}

void VariableUnserializer::reserveForAdd(size_t count) {
  
  
  
  
  
  auto const newSize = m_refs.size() + count;
  auto const capacity = m_refs.capacity();
  if (newSize <= capacity) return;
  auto const total = (folly::nextPowTwo(newSize) - capacity) * sizeof(decltype(m_refs)::value_type);

  if (UNLIKELY(total > kMaxSmallSize && tl_heap->preAllocOOM(total))) {
    check_non_safepoint_surprise();
  }
  m_refs.reserve(newSize);
}

TypedValue VariableUnserializer::getByVal(int id) {
  if (id <= 0 || id > m_refs.size()) throwOutOfRange(id);
  auto const result = m_refs[id - 1];
  if (!result) throwColRKey();
  return result.tv();
}

void VariableUnserializer::check() const {
  if (m_buf >= m_end) throwUnexpectedEOB();
}

void VariableUnserializer::checkElemTermination() const {
  auto const ch = peekBack();
  if (ch != ';' && ch != '}') throwUnterminatedElement();
}

void VariableUnserializer::set(const char* buf, const char* end) {
  m_buf = buf;
  m_end = end;
}

Variant VariableUnserializer::unserialize() {
  Variant v;
  unserializeVariant(v.asTypedValue());
  if (UNLIKELY(StructuredLog::coinflip(RuntimeOption::EvalSerDesSampleRate))) {
    String ser(m_begin, m_end - m_begin, CopyString);
    auto const fmt = folly::sformat("VU{}", (int)m_type);
    StructuredLog::logSerDes(fmt.c_str(), "des", ser, v);
  }

  for (auto& obj : m_sleepingObjects) {
    obj->invokeWakeup();
  }

  return v;
}

namespace {
std::pair<int64_t,const char*> hh_strtoll_base10(const char* p) {
  int64_t x = 0;
  bool neg = false;
  if (*p == '-') {
    neg = true;
    ++p;
  }
  while (*p >= '0' && *p <= '9') {
    x = (x * 10) + ('0' - *p);
    ++p;
  }
  if (!neg) {
    x = -x;
  }
  return std::pair<int64_t,const char*>(x, p);
}
}

int64_t VariableUnserializer::readInt() {
  check();
  auto r = hh_strtoll_base10(m_buf);
  m_buf = r.second;
  return r.first;
}

double VariableUnserializer::readDouble() {
  check();
  const char* newBuf;
  double r = zend_strtod(m_buf, &newBuf);
  m_buf = newBuf;
  return r;
}

folly::StringPiece VariableUnserializer::readStr(unsigned n) {
  check();
  auto const bufferLimit = std::min(size_t(m_end - m_buf), size_t(n));
  auto str = folly::StringPiece(m_buf, bufferLimit);
  m_buf += bufferLimit;
  return str;
}

void VariableUnserializer::expectChar(char expected) {
  char ch = readChar();
  if (UNLIKELY(ch != expected)) {
    throwUnexpectedSep(expected, ch);
  }
}

namespace {
bool isWhitelistClass(const String& requestedClassName, const Array& list, bool includeSubclasses) {

  if (!list.empty()) {
    for (ArrayIter iter(list); iter; ++iter) {
      auto allowedClassName = iter.second().toString();
      auto const matches = includeSubclasses ? HHVM_FN(is_a)(requestedClassName, allowedClassName, true)
        : allowedClassName.get()->isame(requestedClassName.get());
      if (matches) return true;
    }
  }
  return false;
}
}

const StaticString s_throw("throw");
const StaticString s_allowed_classes("allowed_classes");
const StaticString s_include_subclasses("include_subclasses");

bool VariableUnserializer::whitelistCheck(const String& clsName) const {
  if (m_type != Type::Serialize || m_options.isNull()) {
    return true;
  }

  
  
  
  if (m_options.exists(s_allowed_classes)) {
    auto allowed_classes = m_options[s_allowed_classes];
    auto const ok = [&] {
      if (allowed_classes.isArray()) {
        auto const subs = m_options[s_include_subclasses].toBoolean();
        return isWhitelistClass(clsName, allowed_classes.toArray(), subs);

      } else if (allowed_classes.isBoolean()) {
        return allowed_classes.toBoolean();
      } else {
        throw InvalidAllowedClassesException();
      }
    }();

    if (!ok && m_options[s_throw].toBoolean()) {
      throw_object(m_options[s_throw].toString(), make_vec_array(clsName));
    }
    return ok;
  }

  if (!RuntimeOption::UnserializationWhitelistCheck) {
    
    
    
    return true;
  }

  
  if (isWhitelistClass(clsName, m_options, false)) {
    return true;
  }

  
  
  const char* err_msg = "The object being unserialized with class name '%s' " "is not in the given whitelist";


  if (RuntimeOption::UnserializationWhitelistCheckWarningOnly) {
    
    raise_warning(err_msg, clsName.c_str());
    return true;
  } else {
    
    raise_error(err_msg, clsName.c_str());
    return false;
  }
}

void VariableUnserializer::addSleepingObject(const Object& o) {
  m_sleepingObjects.emplace_back(o);
}

bool VariableUnserializer::matchString(folly::StringPiece str) {
  const char* p = m_buf;
  assertx(p <= m_end);
  int total = 0;
  if (*p == 'S' && type() == VariableUnserializer::Type::APCSerialize) {
    total = 2 + 8 + 1;
    if (p + total > m_end) return false;
    p++;
    if (*p++ != ':') return false;
    auto const sd = *reinterpret_cast<StringData*const*>(p);
    assertx(sd->isStatic());
    if (str.compare(sd->slice()) != 0) return false;
    p += size_t(8);
  } else {
    const auto ss = str.size();
    if (ss >= 100) return false;
    int digits = ss >= 10 ? 2 : 1;
    total = 2 + digits + 2 + ss + 2;
    if (p + total > m_end) return false;
    if (*p++ != 's') return false;
    if (*p++ != ':') return false;
    if (digits == 2) {
      if (*p++ != '0' + ss/10) return false;
      if (*p++ != '0' + ss%10) return false;
    } else {
      if (*p++ != '0' + ss) return false;
    }
    if (*p++ != ':') return false;
    if (*p++ != '\"') return false;
    if (memcmp(p, str.data(), ss)) return false;
    p += ss;
    if (*p++ != '\"') return false;
  }
  if (*p++ != ';') return false;
  assertx(m_buf + total == p);
  m_buf = p;
  return true;
}




void VariableUnserializer::unserializePropertyValue(tv_lval v, int remainingProps) {
  assertx(remainingProps > 0);
  unserializeVariant(v);
  if (--remainingProps > 0) {
    auto lastChar = peekBack();
    if (lastChar != ';' && lastChar != '}') {
      throwUnterminatedProperty();
    }
  }
}


NEVER_INLINE void VariableUnserializer::unserializeProp(ObjectData* obj, const String& key, Class* ctx, const String& realKey, int nProp) {





  auto const cls = obj->getVMClass();
  auto const lookup = cls->getDeclPropSlot(ctx, key.get());
  auto const slot = lookup.slot;
  tv_lval t;

  if (slot == kInvalidSlot || !lookup.accessible) {
    
    
    
    t = obj->makeDynProp(realKey.get());
  } else {
    
    
    t = obj->getPropLval(ctx, key.get());
  }

  unserializePropertyValue(t, nProp);
  if (!RuntimeOption::RepoAuthoritative) return;
  if (!Repo::get().global().HardPrivatePropInference) return;

  
  if (UNLIKELY(slot == kInvalidSlot)) return;
  auto const repoTy = cls->declPropRepoAuthType(slot);
  if (LIKELY(tvMatchesRepoAuthType(*t, repoTy))) return;
  if (t.type() == KindOfUninit && (cls->declProperties()[slot].attrs & AttrLateInit)) {
    return;
  }
  throwUnexpectedType(key, obj, *t);
}


NEVER_INLINE void VariableUnserializer::unserializeRemainingProps( Object& obj, int remainingProps, Variant& serializedNativeData, bool& hasSerializedNativeData) {




  obj->unlockObject();
  SCOPE_EXIT { obj->lockObject(); };
  while (remainingProps > 0) {
    
    Variant v;
    unserializeVariant(v.asTypedValue(), UnserializeMode::Key);
    String key = v.toString();
    int ksize = key.size();
    const char *kdata = key.data();
    int subLen = 0;
    if (key == s_serializedNativeDataKey) {
      unserializePropertyValue(serializedNativeData.asTypedValue(), remainingProps--);
      hasSerializedNativeData = true;
    } else if (kdata[0] == '\0') {
      if (UNLIKELY(!ksize)) {
        raise_error("Cannot access empty property");
      }
      
      subLen = strlen(folly::launder(kdata) + 1) + 2;
      if (UNLIKELY(subLen >= ksize)) {
        if (subLen == ksize) {
          raise_error("Cannot access empty property");
        } else {
          throwMangledPrivateProperty();
        }
      }
      String k(kdata + subLen, ksize - subLen, CopyString);
      Class* ctx = (Class*)-1;
      if (kdata[1] != '*') {
        ctx = Unit::lookupClass( String(kdata + 1, subLen - 2, CopyString).get());
      }
      unserializeProp(obj.get(), k, ctx, key, remainingProps--);
    } else {
      unserializeProp(obj.get(), key, nullptr, key, remainingProps--);
    }
  }
}

namespace {

static const StaticString s_Vector("Vector"), s_HH_Vector("HH\\Vector"), s_Map("Map"), s_HH_Map("HH\\Map"), s_Set("Set"), s_HH_Set("HH\\Set"), s_Pair("Pair"), s_HH_Pair("HH\\Pair"), s_StableMap("StableMap");






const StringData* getAlternateCollectionName(const StringData* clsName) {
  typedef hphp_hash_map<const StringData*, const StringData*, string_data_hash, string_data_isame> ClsNameMap;

  auto getAltMap = [] {
    typedef std::pair<StaticString, StaticString> SStringPair;

    static ClsNameMap m;

    static std::vector<SStringPair> mappings {
      std::make_pair(s_Vector, s_HH_Vector), std::make_pair(s_Map, s_HH_Map), std::make_pair(s_Set, s_HH_Set), std::make_pair(s_Pair, s_HH_Pair)


    };

    for (const auto& p : mappings) {
      m[p.first.get()] = p.second.get();
      m[p.second.get()] = p.first.get();
    }

    
    
    m[s_StableMap.get()] = s_HH_Map.get();
    return &m;
  };

  static const ClsNameMap* altMap = getAltMap();

  auto it = altMap->find(clsName);
  return it != altMap->end() ? it->second : nullptr;
}

Class* tryAlternateCollectionClass(const StringData* clsName) {
  auto altName = getAlternateCollectionName(clsName);
  return altName ? Unit::getClass(altName,  false) : nullptr;
}


ALWAYS_INLINE static bool match(const char*& cur, const char* expected, const char* const end) {


  if (cur + strlen(expected) >= end) return false;
  while (*expected) {
    if (*cur++ != *expected++) return false;
  }
  return true;
}

ALWAYS_INLINE static int64_t read64(const char*& cur) {
  auto p = hh_strtoll_base10(cur);
  cur = p.second;
  return p.first;
}


ALWAYS_INLINE bool readInt64(const char*& cur, const char* const end, int64_t& out) {
  if (!match(cur, "i:", end)) return false;
  out = read64(cur);
  return match(cur, ";", end);
}


ALWAYS_INLINE static StringData* readStringData(const char*& cur, const char* const end, int maxLen) {

  if (!match(cur, "s:", end)) return nullptr;
  auto len = read64(cur);
  if (len < 0 || len >= maxLen) return nullptr;
  if (!match(cur, ":\"", end)) return nullptr;
  auto const slice = folly::StringPiece(cur, len);
  if ((cur += len) >= end) return nullptr;
  if (!match(cur, "\";", end)) return nullptr;
  
  auto sd = StringData::Make(slice, CopyString);
  return sd;
}
}

NEVER_INLINE void VariableUnserializer::unserializeVariant( tv_lval self, UnserializeMode mode ) {



  
  
  if (isRefcountedType(self.type()) && mode == UnserializeMode::Value) {
    m_overwrittenList.append(*self);
  }

  
  
  

  char type = readChar();
  char sep = readChar();

  if (type != 'R') {
    add(self, mode);
  }

  if (type == 'N') {
    if (sep != ';') throwUnexpectedSep(';', sep);
    tvSetNull(self); 
    return;
  }
  if (sep != ':') throwUnexpectedSep(':', sep);

  switch (type) {
  case 'r':
  case 'R':
    {
      int64_t id = readInt();
      tvSet(getByVal(id), self);
    }
    break;
  case 'b':
    {
      int64_t v = readInt();
      tvSetBool((bool)v, self);
      break;
    }
  case 'i':
    {
      int64_t v = readInt();
      tvSetInt(v, self);
      break;
    }
  case 'd':
    {
      char ch = peek();
      bool negative = false;
      if (ch == '-') {
        negative = true;
        readChar();
        ch = peek();
      }
      double v;
      if (ch == 'I') {
        auto str = readStr(3);
        if (str.size() != 3 || str[1] != 'N' || str[2] != 'F') {
          throwUnexpectedStr("INF", str);
        }
        v = std::numeric_limits<double>::infinity();
      } else if (ch == 'N') {
        auto str = readStr(3);
        if (str.size() != 3 || str[1] != 'A' || str[2] != 'N') {
          throwUnexpectedStr("NAN", str);
        }
        v = std::numeric_limits<double>::quiet_NaN();
      } else {
        v = readDouble();
      }
      tvSetDouble(negative ? -v : v, self);
    }
    break;
  case 's':
    {
      String v = unserializeString();
      tvMove(make_tv<KindOfString>(v.detach()), self);
      if (!endOfBuffer()) {
        
        
        
        
        
        readChar();
      }
    }
    return;
  case 'S':
    if (this->type() == VariableUnserializer::Type::APCSerialize) {
      auto str = readStr(8);
      assertx(str.size() == 8);
      auto const sd = *reinterpret_cast<StringData*const*>(&str[0]);
      assertx(sd->isStatic());
      tvMove(make_tv<KindOfPersistentString>(sd), self);
    } else {
      throwUnknownType(type);
    }
    break;
  case 'a': 
  case 'D': 
    {
      
      check_recursion_throw();
      
      
      auto a = (type == 'a') ? unserializeArray() :
        unserializeDict();
      if (UNLIKELY(m_markLegacyArrays && type == 'a')) {
        a.setLegacyArray(true);
      }
      tvMove(make_array_like_tv(a.detach()), self);
    }
    return; 
  case 'x': 
    {
      
      check_recursion_throw();
      auto a = unserializeDict();
      a.setLegacyArray(true);
      tvMove(make_array_like_tv(a.detach()), self);
    }
    return; 
  case 'Y': 
    {
      
      check_recursion_throw();
      auto a = unserializeDArray();
      if (UNLIKELY(m_markLegacyArrays)) {
        a.setLegacyArray(true);
      }
      tvMove(make_array_like_tv(a.detach()), self);
    }
    return; 
  case 'y': 
    {
      
      check_recursion_throw();
      auto a = unserializeVArray();
      if (UNLIKELY(m_markLegacyArrays)) {
        a.setLegacyArray(true);
      }
      tvMove(make_array_like_tv(a.detach()), self);
    }
    return; 
  case 'v': 
    {
      
      check_recursion_throw();
      auto a = unserializeVec();
      tvMove(make_tv<KindOfVec>(a.detach()), self);
    }
    return; 
  case 'X': 
  {
    
    check_recursion_throw();
    auto a = unserializeVec();
    a.setLegacyArray(true);
    tvMove(make_tv<KindOfVec>(a.detach()), self);
  }
  return; 
  case 'k': 
    {
      
      check_recursion_throw();
      auto a = unserializeKeyset();
      tvMove(make_tv<KindOfKeyset>(a.detach()), self);
    }
    return; 
  case 'L':
    {
      int64_t id = readInt();
      expectChar(':');
      String rsrcName = unserializeString();
      expectChar('{');
      expectChar('}');
      auto rsrc = req::make<DummyResource>();
      rsrc->o_setResourceId(id);
      rsrc->m_class_name = std::move(rsrcName);
      tvMove(make_tv<KindOfResource>(rsrc.detach()->hdr()), self);
    }
    return; 
  case 'O':
  case 'V':
  case 'K':
    {
      String clsName = unserializeString();

      expectChar(':');
      const int64_t size = readInt();
      expectChar(':');
      expectChar('{');

      const bool allowObjectFormatForCollections = true;

      Class* cls = nullptr;

      
      
      
      

      if (type == 'O') {
        if (whitelistCheck(clsName)) {
          if (allowObjectFormatForCollections) {
            
            
            
            cls = Unit::getClass(clsName.get(),  false);
            if (!cls) {
              cls = tryAlternateCollectionClass(clsName.get());
            }
          }

          
          if (!cls) {
            if (!is_valid_class_name(clsName.slice())) {
              throwInvalidClassName();
            }
            cls = Unit::loadClass(clsName.get()); 
          }
        }
      } else {
        
        cls = Unit::getClass(clsName.get(),  false);
        if (!cls) {
          cls = tryAlternateCollectionClass(clsName.get());
        }
        if (!cls || !cls->isCollectionClass()) {
          throwNotCollection(clsName);
        }
      }

      Object obj;
      auto remainingProps = size;
      if (cls) {
        
        
        
        if (cls->instanceCtor() && !cls->isCppSerializable() && !cls->isCollectionClass()) {
          assertx(obj.isNull());
          throw_null_pointer_exception();
        } else {
          if (UNLIKELY(collections::isType(cls, CollectionType::Pair))) {
            if (UNLIKELY(size != 2)) {
              throwInvalidPair();
            }
            
            obj = Object{req::make<c_Pair>(make_tv<KindOfNull>(), make_tv<KindOfNull>(), c_Pair::NoIncRef{})};

          } else if (UNLIKELY(cls->hasReifiedGenerics())) {
            
            if (!matchString(s_86reified_prop.slice())) {
              throwInvalidOFormat(clsName);
            }
            TypedValue tv = make_tv<KindOfNull>();
            auto const t = tv_lval{&tv};
            unserializePropertyValue(t, remainingProps--);
            if (!TypeStructure::coerceToTypeStructureList_SERDE_ONLY(t)) {
              throwInvalidOFormat(clsName);
            }
            assertx(tvIsHAMSafeVArray(t));
            obj = Object{cls, t.val().parr};
          } else {
            obj = Object{cls};
          }
        }
      } else {
        warnOrThrowUnknownClass(clsName);
        obj = Object{SystemLib::s___PHP_Incomplete_ClassClass};
        obj->setProp(nullptr, s_PHP_Incomplete_Class_Name.get(), clsName.asTypedValue());
      }
      assertx(!obj.isNull());
      tvSet(make_tv<KindOfObject>(obj.get()), self);

      if (remainingProps > 0) {
        
        check_recursion_throw();

        if (type == 'O') {
          
          if (obj->isCollection()) {
            throwInvalidOFormat(clsName);
          }

          Variant serializedNativeData = init_null();
          bool hasSerializedNativeData = false;
          bool checkRepoAuthType = RuntimeOption::RepoAuthoritative && Repo::get().global().HardPrivatePropInference;

          Class* objCls = obj->getVMClass();
          
          if (remainingProps >= objCls->numDeclProperties() - (objCls->hasReifiedGenerics() ? 1 : 0)) {
            auto mismatch = false;
            auto const objProps = obj->props();

            auto const declProps = objCls->declProperties();
            for (auto const& p : declProps) {
              auto slot = p.serializationIdx;
              auto index = objCls->propSlotToIndex(slot);
              auto const& prop = declProps[slot];
              if (prop.name == s_86reified_prop.get()) continue;
              if (!matchString(prop.mangledName->slice())) {
                mismatch = true;
                break;
              }

              
              
              
              auto const t = objProps->at(index);
              unserializePropertyValue(t, remainingProps--);

              if (UNLIKELY(checkRepoAuthType && !tvMatchesRepoAuthType(*t, prop.repoAuthType))) {
                throwUnexpectedType(prop.name, obj.get(), *t);
              }
            }
            
            if (!mismatch && remainingProps > 0) {
              
              
              
              obj->reserveDynProps(remainingProps);
              while (remainingProps > 0) {
                Variant v;
                unserializeVariant(v.asTypedValue(), UnserializeMode::Key);
                String key = v.toString();
                if (key == s_serializedNativeDataKey) {
                  unserializePropertyValue(serializedNativeData.asTypedValue(), remainingProps--);
                  hasSerializedNativeData = true;
                } else {
                  auto kdata = key.data();
                  if (kdata[0] == '\0') {
                    auto ksize = key.size();
                    if (UNLIKELY(ksize == 0)) {
                      raise_error("Cannot access empty property");
                    }
                    
                    auto subLen = strlen(folly::launder(kdata) + 1) + 2;
                    if (UNLIKELY(subLen >= ksize)) {
                      if (subLen == ksize) {
                        raise_error("Cannot access empty property");
                      } else {
                        throwMangledPrivateProperty();
                      }
                    }
                  }
                  auto const lval = obj->makeDynProp(key.get());
                  unserializePropertyValue(lval, remainingProps--);
                }
              }
            }
          }
          if (remainingProps > 0) {
            INC_TPC(unser_prop_slow);
            unserializeRemainingProps(obj, remainingProps, serializedNativeData, hasSerializedNativeData);

            remainingProps = 0;
          } else {
            INC_TPC(unser_prop_fast);
          }

          
          
          
          
          obj->verifyPropTypeHints();

          
          
          
          
          if (obj->hasNativeData() && obj->getVMClass()->getNativeDataInfo()->isSerializable()) {
            Native::nativeDataWakeup(obj.get(), serializedNativeData);
          } else if (hasSerializedNativeData) {
            raise_warning("%s does not expect any serialized native data.", clsName.data());
          }
        } else {
          assertx(type == 'V' || type == 'K');
          if (!obj->isCollection()) {
            throwNotCollection(clsName);
          }
          unserializeCollection(obj.get(), size, type);
        }
      }
      expectChar('}');

      if (cls && cls->lookupMethod(s___wakeup.get()) && (this->type() != VariableUnserializer::Type::DebuggerSerialize || (cls->instanceCtor() && cls->isCppSerializable()))) {


        
        
        addSleepingObject(obj);
      }

      check_non_safepoint_surprise();
    }
    return; 
  case 'C':
    {
      if (this->type() == VariableUnserializer::Type::DebuggerSerialize) {
        raise_error("Debugger shouldn't call custom unserialize method");
      }
      String clsName = unserializeString();

      expectChar(':');
      String serialized = unserializeString('{', '}');

      auto obj = [&]() -> Object {
        if (whitelistCheck(clsName)) {
          
          auto cls = Unit::getClass(clsName.get(),  false);
          if (!cls) {
            if (!is_valid_class_name(clsName.slice())) {
              throwInvalidClassName();
            }
            cls = Unit::loadClass(clsName.get());
          }
          if (cls) {
            return Object::attach(g_context->createObject(cls, init_null_variant, false ));
          }
        }
        if (!allowUnknownSerializableClass()) {
          raise_error("unknown class %s", clsName.data());
        }
        warnOrThrowUnknownClass(clsName);
        Object ret = create_object_only(s_PHP_Incomplete_Class);
        ret->setProp(nullptr, s_PHP_Incomplete_Class_Name.get(), clsName.asTypedValue());
        ret->setProp(nullptr, s_serialized.get(), serialized.asTypedValue());
        return ret;
      }();

      if (!obj->instanceof(SystemLib::s_SerializableClass)) {
        raise_warning("Class %s has no unserializer", obj->getClassName().data());
      } else {
        obj->o_invoke_few_args(s_unserialize, 1, serialized);
      }

      tvMove(make_tv<KindOfObject>(obj.detach()), self);
    }
    return; 
  default:
    throwUnknownType(type);
  }
  expectChar(';');
}

Array VariableUnserializer::unserializeArray() {
  int64_t size = readInt();
  expectChar(':');
  expectChar('{');
  if (size == 0) {
    expectChar('}');
    return m_forceDArrays || type() == Type::Serialize ? Array::CreateDArray()
      : Array::Create();
  }
  if (UNLIKELY(size < 0 || size > std::numeric_limits<int>::max())) {
    throwArraySizeOutOfBounds();
  }
  
  auto const allocsz = MixedArray::computeAllocBytesFromMaxElms(size);
  if (UNLIKELY(allocsz > kMaxSmallSize && tl_heap->preAllocOOM(allocsz))) {
    check_non_safepoint_surprise();
  }

  
  
  auto arr = m_forceDArrays || type() == Type::Serialize ? DArrayInit(size).toArray()
    : MixedArrayInit(size).toArray();
  reserveForAdd(size);

  for (int64_t i = 0; i < size; i++) {
    Variant key;
    unserializeVariant(key.asTypedValue(), UnserializeMode::Key);
    if (!key.isString() && !key.isInteger()) throwInvalidKey();
    unserializeVariant(MixedArray::LvalInPlace(arr.get(), key));
    if (i < size - 1) checkElemTermination();
  }

  check_non_safepoint_surprise();
  expectChar('}');
  return arr;
}

arrprov::Tag VariableUnserializer::unserializeProvenanceTag() {
  auto const finish = [&] (auto tag) -> arrprov::Tag {
    if (!RuntimeOption::EvalArrayProvenance) return {};
    return tag;
  };

  auto const read_filename = [&]() -> const StringData* {
    if (peek() == 't') {
      assertx(m_unitFilename);
      expectChar('t');
      return m_unitFilename;
    } else {
      expectChar('s');
      expectChar(':');
      return makeStaticString(unserializeString().get());
    }
  };

  if (type() != VariableUnserializer::Type::Internal) return {};
  if (peek() == 'p') {
    expectChar('p');
    expectChar(':');
    expectChar('i');
    expectChar(':');
    auto const line = static_cast<int>(readInt());
    expectChar(';');
    auto const filename = read_filename();
    expectChar(';');
    return finish( arrprov::Tag { filename, line }
    );
  } else if (peek() == 'P') {
    expectChar('P');
    expectChar(';');
    return finish( arrprov::Tag::RepoUnion()
    );
  } else if (peek() == 'r') {
    expectChar('r');
    expectChar(':');
    auto const filename = read_filename();
    expectChar(';');
    return finish( arrprov::Tag::TraitMerge(filename)
    );
  } else if (peek() == 'e') {
    expectChar('e');
    expectChar(':');
    auto const filename = read_filename();
    expectChar(';');
    return finish( arrprov::Tag::LargeEnum(filename)
    );
  } else {
    return {};
  }
}

Array VariableUnserializer::unserializeDict() {
  if (m_dvOverrides) m_dvOverrides->push_back(false);

  int64_t size = readInt();
  expectChar(':');
  expectChar('{');

  auto provTag = unserializeProvenanceTag();
  if (!RO::EvalArrProvHackArrays) provTag = {};

  if (size == 0) {
    expectChar('}');
    return Array::attach(provTag ? arrprov::tagStaticArr(staticEmptyDictArray(), provTag)
      : staticEmptyDictArray()
    );
  }
  if (UNLIKELY(size < 0 || size > std::numeric_limits<int>::max())) {
    throwArraySizeOutOfBounds();
  }

  
  auto const allocsz = MixedArray::computeAllocBytesFromMaxElms(size);
  if (UNLIKELY(allocsz > kMaxSmallSize && tl_heap->preAllocOOM(allocsz))) {
    check_non_safepoint_surprise();
  }

  Array arr = DictInit(size).toArray();
  for (int64_t i = 0; i < size; i++) {
    Variant key;
    unserializeVariant(key.asTypedValue(), UnserializeMode::Key);
    if (!key.isString() && !key.isInteger()) throwInvalidKey();
    unserializeVariant(MixedArray::LvalInPlace(arr.get(), key));
    if (i < size - 1) checkElemTermination();
  }

  check_non_safepoint_surprise();
  expectChar('}');
  if (provTag) arrprov::setTag<arrprov::Mode::Emplace>(arr.get(), provTag);
  return arr;
}

Array VariableUnserializer::unserializeVec() {
  if (m_dvOverrides) m_dvOverrides->push_back(false);

  int64_t size = readInt();
  expectChar(':');
  expectChar('{');

  auto provTag = unserializeProvenanceTag();
  if (!RO::EvalArrProvHackArrays) provTag = {};

  if (size == 0) {
    expectChar('}');
    return Array::attach(provTag ? arrprov::tagStaticArr(staticEmptyVec(), provTag)
      : staticEmptyVec()
    );
  }
  if (UNLIKELY(size < 0 || size > std::numeric_limits<int>::max())) {
    throwArraySizeOutOfBounds();
  }
  auto const sizeClass = PackedArray::capacityToSizeIndex(size);
  auto const allocsz = MemoryManager::sizeIndex2Size(sizeClass);

  
  if (UNLIKELY(allocsz > kMaxSmallSize && tl_heap->preAllocOOM(allocsz))) {
    check_non_safepoint_surprise();
  }

  Array arr = VecInit(size).toArray();
  reserveForAdd(size);

  for (int64_t i = 0; i < size; i++) {
    unserializeVariant(PackedArray::LvalNewInPlace(arr.get()));
    if (i < size - 1) checkElemTermination();
  }
  check_non_safepoint_surprise();
  expectChar('}');
  if (provTag) arrprov::setTag<arrprov::Mode::Emplace>(arr.get(), provTag);
  return arr;
}

Array VariableUnserializer::unserializeVArray() {
  if (m_dvOverrides) m_dvOverrides->push_back(true);

  int64_t size = readInt();
  expectChar(':');
  expectChar('{');

  auto provTag = unserializeProvenanceTag();
  if (!RO::EvalArrProvDVArrays) provTag = {};

  if (size == 0) {
    expectChar('}');
    if (m_type != Type::Serialize) {
      return Array::attach(provTag ? arrprov::tagStaticArr(staticEmptyVArray(), provTag)
        : staticEmptyVArray()
      );
    }
    return m_forceDArrays ? Array::attach(provTag ? arrprov::tagStaticArr(staticEmptyDArray(), provTag)

          : staticEmptyDArray()
        )
      : Array::attach(provTag ? arrprov::tagStaticArr(staticEmptyVArray(), provTag)
          : staticEmptyVArray()
        );
  }
  if (UNLIKELY(size < 0 || size > std::numeric_limits<int>::max())) {
    throwArraySizeOutOfBounds();
  }

  auto const oomCheck = [&](size_t allocsz) {
    
    if (UNLIKELY(allocsz > kMaxSmallSize && tl_heap->preAllocOOM(allocsz))) {
      check_non_safepoint_surprise();
    }
  };

  auto arr = Array{};
  if (m_forceDArrays && m_type == Type::Serialize) {
    
    oomCheck(MixedArray::computeAllocBytesFromMaxElms(size));

    arr = DArrayInit(size).toArray();
    reserveForAdd(size);

    for (int64_t i = 0; i < size; i++) {
      unserializeVariant(MixedArray::LvalInPlace(arr.get(), i));
      if (i < size - 1) checkElemTermination();
    }
  } else {
    
    auto const index = PackedArray::capacityToSizeIndex(size);
    oomCheck(MemoryManager::sizeIndex2Size(index));

    arr = VArrayInit(size).toArray();
    reserveForAdd(size);

    for (int64_t i = 0; i < size; i++) {
      unserializeVariant(PackedArray::LvalNewInPlace(arr.get()));
      if (i < size - 1) checkElemTermination();
    }
  }

  check_non_safepoint_surprise();
  expectChar('}');
  if (provTag) arrprov::setTag<arrprov::Mode::Emplace>(arr.get(), provTag);
  return arr;
}

Array VariableUnserializer::unserializeDArray() {
  if (m_dvOverrides) m_dvOverrides->push_back(true);

  int64_t size = readInt();
  expectChar(':');
  expectChar('{');

  auto provTag = unserializeProvenanceTag();
  if (!RO::EvalArrProvDVArrays) provTag = {};

  if (size == 0) {
    expectChar('}');
    return Array::attach(provTag ? arrprov::tagStaticArr(staticEmptyDArray(), provTag)
      : staticEmptyDArray()
    );
  }
  if (UNLIKELY(size < 0 || size > std::numeric_limits<int>::max())) {
    throwArraySizeOutOfBounds();
  }

  
  auto const allocsz = MixedArray::computeAllocBytesFromMaxElms(size);
  if (UNLIKELY(allocsz > kMaxSmallSize && tl_heap->preAllocOOM(allocsz))) {
    check_non_safepoint_surprise();
  }

  auto arr = DArrayInit(size).toArray();
  reserveForAdd(size);

  for (int64_t i = 0; i < size; i++) {
    Variant key;
    unserializeVariant(key.asTypedValue(), UnserializeMode::Key);
    if (!key.isString() && !key.isInteger()) throwInvalidKey();
    unserializeVariant(MixedArray::LvalInPlace(arr.get(), key));
    if (i < size - 1) checkElemTermination();
  }

  check_non_safepoint_surprise();
  expectChar('}');
  if (provTag) arrprov::setTag<arrprov::Mode::Emplace>(arr.get(), provTag);
  return arr;
}

Array VariableUnserializer::unserializeKeyset() {
  int64_t size = readInt();
  expectChar(':');
  expectChar('{');
  if (size == 0) {
    expectChar('}');
    return Array::CreateKeyset();
  }
  if (UNLIKELY(size < 0 || size > std::numeric_limits<int>::max())) {
    throwArraySizeOutOfBounds();
  }

  
  auto const allocsz = SetArray::computeAllocBytesFromMaxElms(size);
  if (UNLIKELY(allocsz > kMaxSmallSize && tl_heap->preAllocOOM(allocsz))) {
    check_non_safepoint_surprise();
  }

  KeysetInit init(size);
  for (int64_t i = 0; i < size; i++) {
    Variant key;
    
    
    unserializeVariant(key.asTypedValue(), UnserializeMode::Key);

    auto const type = key.getType();
    if (UNLIKELY(!isStringType(type) && !isIntType(type))) {
      throwKeysetValue();
    }

    init.add(key);

    if (i < (size - 1)) {
      auto lastChar = peekBack();
      if ((lastChar != ';' && lastChar != '}')) {
        throwUnterminatedElement();
      }
    }
  }
  check_non_safepoint_surprise();
  expectChar('}');
  return init.toArray();
}


folly::StringPiece VariableUnserializer::unserializeStringPiece(char delimiter0, char delimiter1) {
  int64_t size = readInt();
  if (size >= RuntimeOption::MaxSerializedStringSize) {
    throwLargeStringSize(size);
  }
  if (size < 0) {
    throwNegativeStringSize(size);
  }
  expectChar(':');
  expectChar(delimiter0);
  auto const piece = readStr(size);
  expectChar(delimiter1);
  return piece;
}

String VariableUnserializer::unserializeString(char delimiter0, char delimiter1) {
  auto const piece = unserializeStringPiece(delimiter0, delimiter1);
  return String::attach(readOnly() ? makeStaticString(piece) :
                        StringData::Make(piece, CopyString));
}

void VariableUnserializer::unserializeCollection(ObjectData* obj, int64_t sz, char type) {
  switch (obj->collectionType()) {
    case CollectionType::Pair:
      unserializePair(obj, sz, type);
      break;
    case CollectionType::Vector:
    case CollectionType::ImmVector:
      unserializeVector(obj, sz, type);
      break;
    case CollectionType::Map:
    case CollectionType::ImmMap:
      unserializeMap(obj, sz, type);
      break;
    case CollectionType::Set:
    case CollectionType::ImmSet:
      unserializeSet(obj, sz, type);
      break;
  }
}

void VariableUnserializer::unserializeVector(ObjectData* obj, int64_t sz, char type) {
  if (type != 'V') throwBadFormat(obj, type);

  auto const sizeClass = PackedArray::capacityToSizeIndex(sz);
  auto const allocsz = MemoryManager::sizeIndex2Size(sizeClass);
  
  if (UNLIKELY(allocsz > kMaxSmallSize && tl_heap->preAllocOOM(allocsz))) {
    check_non_safepoint_surprise();
  }

  auto bvec = static_cast<BaseVector*>(obj);
  bvec->reserve(sz);
  reserveForAdd(sz);
  for (int64_t i = 0; i < sz; ++i) {
    auto tv = bvec->appendForUnserialize(i);
    HPHP::type(tv) = KindOfNull;
    unserializeVariant(tv);
  }
}


NEVER_INLINE bool VariableUnserializer::tryUnserializeStrIntMap(BaseMap* map, int64_t sz) {
  auto b = head();
  
  if (folly::StringPiece(begin(), b) != folly::to<std::string>("K:6:\"HH\\Map\":", sz, ":{")) {
    return false;
  }
  auto const end = this->end();
  auto const maxKeyLen = RuntimeOption::MaxSerializedStringSize;
  
  auto checkPoint = map->batchInsertBegin(sz);
  int64_t i = 0;
  for (; i < sz; ++i) {
    auto sd = readStringData(b, end, maxKeyLen);
    if (!sd) break;
    String key = String::attach(sd);
    auto tv = map->batchInsert(key.get());
    tv->m_type = KindOfNull;
    if (*b == 'i') {
      if (!readInt64(b, end, tv->m_data.num)) break;
      tv->m_type = KindOfInt64;
    } else if (*b == 's') {
      auto sd = readStringData(b, end, maxKeyLen);
      if (!sd) break;
      tv->m_data.pstr = sd;
      tv->m_type = KindOfString;
    } else {
      break;
    }
  }
  
  if (i == sz && map->tryBatchInsertEnd(checkPoint)) {
    set(b, end);
    return true;
  }
  map->batchInsertAbort(checkPoint);
  return false;
}

void VariableUnserializer::unserializeMap(ObjectData* obj, int64_t sz, char type) {
  if (type != 'K') throwBadFormat(obj, type);

  
  auto const allocsz = MixedArray::computeAllocBytesFromMaxElms(sz);
  if (UNLIKELY(allocsz > kMaxSmallSize && tl_heap->preAllocOOM(allocsz))) {
    check_non_safepoint_surprise();
  }

  auto map = static_cast<BaseMap*>(obj);
  map->reserve(sz);
  if (sz >= RuntimeOption::UnserializationBigMapThreshold && tryUnserializeStrIntMap(map, sz)) {
    return;
  }

  reserveForAdd(sz + sz); 
  for (int64_t i = 0; i < sz; ++i) {
    Variant k;
    unserializeVariant(k.asTypedValue(), UnserializeMode::ColKey);
    TypedValue* tv = nullptr;
    if (k.isInteger()) {
      auto h = k.toInt64();
      tv = map->findForUnserialize(h);
      
      if (UNLIKELY(!tv)) {
        tv = k.asTypedValue();
        goto do_unserialize;
      }
    } else if (k.isString()) {
      auto key = k.getStringData();
      tv = map->findForUnserialize(key);
      
      if (UNLIKELY(!tv)) {
        tv = k.asTypedValue();
        goto do_unserialize;
      }
    } else {
      throwInvalidKey();
    }
    tv->m_type = KindOfNull;
do_unserialize:
    unserializeVariant(tv);
  }
}

void VariableUnserializer::unserializeSet(ObjectData* obj, int64_t sz, char type) {
  if (type != 'V') throwBadFormat(obj, type);

  
  auto const allocsz = MixedArray::computeAllocBytesFromMaxElms(sz);
  if (UNLIKELY(allocsz > kMaxSmallSize && tl_heap->preAllocOOM(allocsz))) {
    check_non_safepoint_surprise();
  }

  auto set = static_cast<BaseSet*>(obj);
  set->reserve(sz);

  reserveForAdd(sz);
  for (int64_t i = 0; i < sz; ++i) {
    
    
    
    Variant k;
    unserializeVariant(k.asTypedValue(), UnserializeMode::ColKey);
    if (k.isInteger()) {
      auto h = k.toInt64();
      auto tv = set->findForUnserialize(h);
      
      if (UNLIKELY(!tv)) continue;
      tv->m_type = KindOfInt64;
      tv->m_data.num = h;
    } else if (k.isString()) {
      auto key = k.getStringData();
      auto tv = set->findForUnserialize(key);
      if (UNLIKELY(!tv)) continue;
      
      
      tvDup(make_tv<KindOfString>(key), *tv);
    } else {
      throwInvalidHashKey(obj);
    }
  }
}

void VariableUnserializer::unserializePair(ObjectData* obj, int64_t sz, char type) {
  assertx(sz == 2);
  if (type != 'V') throwBadFormat(obj, type);
  auto pair = static_cast<c_Pair*>(obj);
  unserializeVariant(pair->at(0));
  unserializeVariant(pair->at(1));
}



void VariableUnserializer::reserialize(StringBuffer& buf) {

  char type = readChar();
  char sep = readChar();

  if (type == 'N') {
    buf.append(type);
    buf.append(sep);
    return;
  }

  switch (type) {
  case 'r':
  case 'R':
  case 'b':
  case 'i':
  case 'd':
    {
      buf.append(type);
      buf.append(sep);
      while (peek() != ';') {
        char ch;
        ch = readChar();
        buf.append(ch);
      }
    }
    break;
  case 'S':
  case 'A':
    {
      
      buf.append(type);
      buf.append(sep);
      auto str = readStr(8);
      buf.append(str.data(), str.size());
    }
    break;
  case 's':
    {
      String v = unserializeString();
      assertx(!v.isNull());
      if (v.get()->isStatic()) {
        union {
          char pointer[8];
          StringData *sd;
        } u;
        u.sd = v.get();
        buf.append("S:");
        buf.append(u.pointer, 8);
        buf.append(';');
      } else {
        buf.append("s:");
        buf.append(v.size());
        buf.append(":\"");
        buf.append(v.data(), v.size());
        buf.append("\";");
      }
      sep = readChar();
      return;
    }
    break;
  case 'a':
  case 'D':
  case 'Y':
  case 'H':
    {
      buf.append(type == 'a' ? "a:" : (type == 'Y' ? "Y:" :
            (type == 'D' ? "D:" : "H:")));
      int64_t size = readInt();
      char sep2 = readChar();
      buf.append(size);
      buf.append(sep2);
      sep2 = readChar();
      buf.append(sep2);
      for (int64_t i = 0; i < size; i++) {
        reserialize(buf); 
        reserialize(buf); 
      }
      sep2 = readChar(); 
      buf.append(sep2);
      return;
    }
    break;
  case 'v':
  case 'k':
  case 'y':
    {
      buf.append(type == 'v' ? "v:" : (type == 'y' ? "y:" : "k:"));
      int64_t size = readInt();
      char sep2 = readChar();
      buf.append(size);
      buf.append(sep2);
      sep2 = readChar();
      buf.append(sep2);
      for (int64_t i = 0; i < size; ++i) {
        reserialize(buf);
      }
      sep2 = readChar(); 
      buf.append(sep2);
      return;
    }
  case 'o':
  case 'O':
  case 'V':
  case 'K':
    {
      buf.append(type);
      buf.append(sep);

      auto const clsName = unserializeStringPiece();
      buf.append(static_cast<int>(clsName.size()));
      buf.append(":\"");
      buf.append(clsName.data(), clsName.size());
      buf.append("\":");

      readChar();
      int64_t size = readInt();
      char sep2 = readChar();

      buf.append(size);
      buf.append(sep2);
      sep2 = readChar(); 
      buf.append(sep2);
      
      
      int64_t i = type == 'V' ? size : size * 2;
      while (i--) {
        reserialize(buf);
      }
      sep2 = readChar(); 
      buf.append(sep2);
      return;
    }
    break;
  case 'C':
    {
      buf.append(type);
      buf.append(sep);

      auto const clsName = unserializeStringPiece();
      buf.append(static_cast<int>(clsName.size()));
      buf.append(":\"");
      buf.append(clsName.data(), clsName.size());
      buf.append("\":");

      sep = readChar(); 
      auto const serialized = unserializeStringPiece('{', '}');
      buf.append(static_cast<int>(serialized.size()));
      buf.append(":{");
      buf.append(serialized.data(), serialized.size());
      buf.append('}');
      return;
    }
    break;
  default:
    throwUnknownType(type);
  }

  sep = readChar(); 
  buf.append(sep);
}

}
