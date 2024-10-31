





































namespace HPHP {


const int64_t k_FB_SERIALIZE_HACK_ARRAYS = 1<<1;
const int64_t k_FB_SERIALIZE_VARRAY_DARRAY = 1<<2;
const int64_t k_FB_SERIALIZE_HACK_ARRAYS_AND_KEYSETS = 1<<3;



static const UChar32 SUBSTITUTION_CHARACTER = 0xFFFD;















enum TType {
  T_STOP    = 1, T_BYTE    = 2, T_U16     = 3, T_I16     = 4, T_U32     = 5, T_I32     = 6, T_U64     = 7, T_I64     = 8, T_STRING  = 9, T_STRUCT  = 10, T_MAP     = 11, T_SET     = 12, T_LIST    = 13, T_NULL    = 14, T_VARCHAR = 15, T_DOUBLE  = 16, T_BOOLEAN = 17, };
























Variant HHVM_FUNCTION(fb_serialize, const Variant& thing, int64_t options) {
  try {
    if (options & k_FB_SERIALIZE_HACK_ARRAYS) {
      size_t len = HPHP::serialize ::FBSerializer<VariantControllerUsingHackArrays> ::serializedSize(thing);

      String s(len, ReserveString);
      HPHP::serialize ::FBSerializer<VariantControllerUsingHackArrays> ::serialize(thing, s.mutableData());

      s.setSize(len);
      return s;
    } else if (options & k_FB_SERIALIZE_HACK_ARRAYS_AND_KEYSETS) {
      size_t len = HPHP::serialize ::FBSerializer<VariantControllerUsingHackArraysAndKeyset> ::serializedSize(thing);

      String s(len, ReserveString);
      HPHP::serialize ::FBSerializer<VariantControllerUsingHackArraysAndKeyset> ::serialize(thing, s.mutableData());

      s.setSize(len);
      return s;
    } else if (options & k_FB_SERIALIZE_VARRAY_DARRAY) {
      size_t len = HPHP::serialize ::FBSerializer<VariantControllerUsingVarrayDarray> ::serializedSize(thing);

      String s(len, ReserveString);
      HPHP::serialize ::FBSerializer<VariantControllerUsingVarrayDarray> ::serialize(thing, s.mutableData());

      s.setSize(len);
      return s;
    } else {
      size_t len = HPHP::serialize::FBSerializer<VariantController>::serializedSize(thing);
      String s(len, ReserveString);
      HPHP::serialize::FBSerializer<VariantController>::serialize( thing, s.mutableData());
      s.setSize(len);
      return s;
    }
  } catch (const HPHP::serialize::KeysetSerializeError&) {
    SystemLib::throwInvalidArgumentExceptionObject( "Serializing Keysets requires the FB_SERIALIZE_HACK_ARRAYS_AND_KEYSETS " "option to be provided" );


  } catch (const HPHP::serialize::HackArraySerializeError&) {
    SystemLib::throwInvalidArgumentExceptionObject( "Serializing Hack arrays requires the FB_SERIALIZE_HACK_ARRAYS " "option to be provided" );


  } catch (const HPHP::serialize::SerializeError&) {
    return init_null();
  }
}

Variant HHVM_FUNCTION(fb_unserialize, const Variant& thing, bool& success, int64_t options) {


  if (thing.isString()) {
    String sthing = thing.toString();

    if (sthing.size() && (sthing.data()[0] & 0x80)) {
      Variant error;
      return fb_compact_unserialize(sthing.data(), sthing.size(), success, error);
    } else {
      return fb_unserialize(sthing.data(), sthing.size(), success, options);
    }
  }

  success = false;
  return false;
}

Variant fb_unserialize(const char* str, int len, bool& success, int64_t options) {


  try {
    if (options & k_FB_SERIALIZE_HACK_ARRAYS) {
      auto res = HPHP::serialize ::FBUnserializer<VariantControllerUsingHackArrays> ::unserialize(folly::StringPiece(str, len));

      success = true;
      return res;
    } else if (options & k_FB_SERIALIZE_HACK_ARRAYS_AND_KEYSETS) {
      auto res = HPHP::serialize ::FBUnserializer<VariantControllerUsingHackArraysAndKeyset> ::unserialize(folly::StringPiece(str, len));

      success = true;
      return res;
    } else if (options & k_FB_SERIALIZE_VARRAY_DARRAY) {
      auto res = HPHP::serialize ::FBUnserializer<VariantControllerUsingVarrayDarray> ::unserialize(folly::StringPiece(str, len));

      success = true;
      return res;
    } else {
      auto res = HPHP::serialize::FBUnserializer<VariantController> ::unserialize(folly::StringPiece(str, len));
      success = true;
      return res;
    }
  } catch (const HPHP::serialize::UnserializeError&) {
    success = false;
    return false;
  }
}





enum FbCompactSerializeCode {
  FB_CS_INT16      = 0, FB_CS_INT32      = 1, FB_CS_INT64      = 2, FB_CS_NULL       = 3, FB_CS_TRUE       = 4, FB_CS_FALSE      = 5, FB_CS_DOUBLE     = 6, FB_CS_STRING_0   = 7, FB_CS_STRING_1   = 8, FB_CS_STRING_N   = 9, FB_CS_LIST_MAP   = 10, FB_CS_MAP        = 11, FB_CS_STOP       = 12, FB_CS_SKIP       = 13, FB_CS_VECTOR     = 14, FB_CS_OBJ        = 15, FB_CS_MAX_CODE   = 16, };


















const uint64_t kInt7Mask            = 0x7f;
const uint64_t kInt7Prefix          = 0x00;


const uint64_t kInt13Mask           = (1ULL << 13) - 1;
const uint64_t kInt13PrefixMsbMask  = 0xe0;
const uint64_t kInt13PrefixMsb      = 0xc0;
const uint64_t kInt13Prefix         = kInt13PrefixMsb << (1 * 8);


const uint64_t kInt20Mask           = (1ULL << 20) - 1;
const uint64_t kInt20PrefixMsbMask  = 0xf0;
const uint64_t kInt20PrefixMsb      = 0xe0;
const uint64_t kInt20Prefix         = kInt20PrefixMsb << (2 * 8);


const uint64_t kInt54Mask           = (1ULL << 54) - 1;
const uint64_t kInt54PrefixMsbMask  = 0xc0;
const uint64_t kInt54PrefixMsb      = 0x80;
const uint64_t kInt54Prefix         = kInt54PrefixMsb << (6 * 8);


const uint64_t kCodeMask            = 0x0f;
const uint64_t kCodePrefix          = 0xf0;

static void fb_compact_serialize_code(StringBuffer& sb, FbCompactSerializeCode code) {
  assertx(code == (code & kCodeMask));
  uint8_t v = (kCodePrefix | code);
  sb.append(reinterpret_cast<char*>(&v), 1);
}

static void fb_compact_serialize_int64(StringBuffer& sb, int64_t val) {
  if (val >= 0 && (uint64_t)val <= kInt7Mask) {
    uint8_t nval = val;
    sb.append(reinterpret_cast<char*>(&nval), 1);

  } else if (val >= 0 && (uint64_t)val <= kInt13Mask) {
    uint16_t nval = htons(kInt13Prefix | val);
    sb.append(reinterpret_cast<char*>(&nval), 2);

  } else if (val == (int64_t)(int16_t)val) {
    fb_compact_serialize_code(sb, FB_CS_INT16);
    uint16_t nval = htons(val);
    sb.append(reinterpret_cast<char*>(&nval), 2);

  } else if (val >= 0 && (uint64_t)val <= kInt20Mask) {
    uint32_t nval = htonl(kInt20Prefix | val);
    
    sb.append(reinterpret_cast<char*>(&nval) + 1, 3);

  } else if (val == (int64_t)(int32_t)val) {
    fb_compact_serialize_code(sb, FB_CS_INT32);
    uint32_t nval = htonl(val);
    sb.append(reinterpret_cast<char*>(&nval), 4);

  } else if (val >= 0 && (uint64_t)val <= kInt54Mask) {
    uint64_t nval = htonll(kInt54Prefix | val);
    
    sb.append(reinterpret_cast<char*>(&nval) + 1, 7);

  } else {
    fb_compact_serialize_code(sb, FB_CS_INT64);
    uint64_t nval = htonll(val);
    sb.append(reinterpret_cast<char*>(&nval), 8);
  }
}

static void fb_compact_serialize_string(StringBuffer& sb, const String& str) {
  int len = str.size();
  if (len == 0) {
    fb_compact_serialize_code(sb, FB_CS_STRING_0);
  } else {
    if (len == 1) {
      fb_compact_serialize_code(sb, FB_CS_STRING_1);
    } else {
      fb_compact_serialize_code(sb, FB_CS_STRING_N);
      fb_compact_serialize_int64(sb, len);
    }
    sb.append(str.data(), len);
  }
}

static bool fb_compact_serialize_is_list(const Array& arr, int64_t& index_limit) {
  index_limit = arr.size();
  int64_t max_index = 0;
  for (ArrayIter it(arr); it; ++it) {
    Variant key = it.first();
    if (!key.isNumeric()) {
      return false;
    }
    int64_t index = key.toInt64();
    if (index < max_index) {
      return false;
    }
    if (index > max_index) {
      max_index = index;
    }
  }

  if (max_index >= arr.size() * 2) {
    
    return false;
  }

  index_limit = max_index + 1;
  return true;
}

static int fb_compact_serialize_variant( StringBuffer& sd, const Variant& var, int depth);

static void fb_compact_serialize_array_as_list_map( StringBuffer& sb, const Array& arr, int64_t index_limit, int depth) {
  fb_compact_serialize_code(sb, FB_CS_LIST_MAP);
  for (int64_t i = 0; i < index_limit; ++i) {
    if (arr.exists(i)) {
      fb_compact_serialize_variant(sb, arr[i], depth + 1);
    } else {
      fb_compact_serialize_code(sb, FB_CS_SKIP);
    }
  }
  fb_compact_serialize_code(sb, FB_CS_STOP);
}

static void fb_compact_serialize_vec( StringBuffer& sb, const Array& arr, int depth) {
  fb_compact_serialize_code(sb, FB_CS_LIST_MAP);
  IterateV( arr.get(), [&](TypedValue v) {

      fb_compact_serialize_variant(sb, VarNR(v), depth + 1);
    }
  );
  fb_compact_serialize_code(sb, FB_CS_STOP);
}

static void fb_compact_serialize_array_as_map( StringBuffer& sb, const Array& arr, int depth) {
  fb_compact_serialize_code(sb, FB_CS_MAP);
  IterateKV( arr.get(), [&](TypedValue k, TypedValue v) {

      if (isStringType(k.m_type)) {
        fb_compact_serialize_string(sb, StrNR{k.m_data.pstr});
      } else {
        assertx(isIntType(k.m_type));
        fb_compact_serialize_int64(sb, k.m_data.num);
      }
      fb_compact_serialize_variant(sb, VarNR(v), depth + 1);
    }
  );
  fb_compact_serialize_code(sb, FB_CS_STOP);
}

static void fb_compact_serialize_keyset( StringBuffer& sb, const Array& arr) {
  fb_compact_serialize_code(sb, FB_CS_MAP);
  IterateV( arr.get(), [&](TypedValue v) {

      if (isStringType(v.m_type)) {
        fb_compact_serialize_string(sb, StrNR{v.m_data.pstr});
        fb_compact_serialize_string(sb, StrNR{v.m_data.pstr});
      } else {
        assertx(v.m_type == KindOfInt64);
        fb_compact_serialize_int64(sb, v.m_data.num);
        fb_compact_serialize_int64(sb, v.m_data.num);
      }
    }
  );
  fb_compact_serialize_code(sb, FB_CS_STOP);
}

static int fb_compact_serialize_variant( StringBuffer& sb, const Variant& var, int depth) {
  if (depth > 256) {
    return 1;
  }

  switch (var.getType()) {
    case KindOfUninit:
    case KindOfNull:
      fb_compact_serialize_code(sb, FB_CS_NULL);
      return 0;

    case KindOfBoolean:
      if (var.toInt64()) {
        fb_compact_serialize_code(sb, FB_CS_TRUE);
      } else {
        fb_compact_serialize_code(sb, FB_CS_FALSE);
      }
      return 0;

    case KindOfInt64:
      fb_compact_serialize_int64(sb, var.toInt64());
      return 0;

    case KindOfDouble: {
      fb_compact_serialize_code(sb, FB_CS_DOUBLE);
      double d = var.toDouble();
      sb.append(reinterpret_cast<char*>(&d), 8);
      return 0;
    }

    case KindOfPersistentString:
    case KindOfString:
    case KindOfFunc:
    case KindOfClass:
      fb_compact_serialize_string(sb, var.toString());
      return 0;

    case KindOfPersistentVec:
    case KindOfVec: {
      Array arr = var.toArray();
      assertx(arr->isVecType());
      if (UNLIKELY(RuntimeOption::EvalLogArrayProvenance)) {
        raise_array_serialization_notice(SerializationSite::FBCompactSerialize, arr.get());
      }
      fb_compact_serialize_vec(sb, std::move(arr), depth);
      return 0;
    }

    case KindOfPersistentDict:
    case KindOfDict: {
      Array arr = var.toArray();
      assertx(arr->isDictType());
      if (UNLIKELY(RuntimeOption::EvalLogArrayProvenance)) {
        raise_array_serialization_notice(SerializationSite::FBCompactSerialize, arr.get());
      }
      fb_compact_serialize_array_as_map(sb, std::move(arr), depth);
      return 0;
    }

    case KindOfPersistentKeyset:
    case KindOfKeyset: {
      Array arr = var.toArray();
      assertx(arr->isKeysetType());
      fb_compact_serialize_keyset(sb, std::move(arr));
      return 0;
    }

    case KindOfPersistentDArray:
    case KindOfDArray:
    case KindOfPersistentVArray:
    case KindOfVArray:
    case KindOfPersistentArray:
    case KindOfArray: {
      Array arr = var.toArray();
      assertx(arr->isPHPArrayType());
      int64_t index_limit;
      if (UNLIKELY(RuntimeOption::EvalLogArrayProvenance) && arrprov::arrayWantsTag(arr.get())) {
        raise_array_serialization_notice( SerializationSite::FBCompactSerialize, arr.get()

        );
      }
      if (fb_compact_serialize_is_list(arr, index_limit)) {
        fb_compact_serialize_array_as_list_map( sb, std::move(arr), index_limit, depth);
      } else {
        fb_compact_serialize_array_as_map(sb, std::move(arr), depth);
      }
      return 0;
    }

    case KindOfClsMeth: {
      Array arr = var.toArray();
      if (RuntimeOption::EvalHackArrDVArrs) {
        assertx(arr->isVecType());
        fb_compact_serialize_vec(sb, std::move(arr), depth);
      } else {
        assertx(arr->isPHPArrayType());
        int64_t index_limit;
        fb_compact_serialize_is_list(arr, index_limit);
        fb_compact_serialize_array_as_list_map( sb, std::move(arr), index_limit, depth);
      }
      return 0;
    }

    case KindOfObject:
    case KindOfResource:
    case KindOfRecord: 
      fb_compact_serialize_code(sb, FB_CS_NULL);
      raise_warning( "fb_compact_serialize(): unable to serialize " "object/resource/ref/func/class/record" );


      break;
    case KindOfRFunc:
      SystemLib::throwInvalidOperationExceptionObject( "Unable to serialize reified function pointer" );

      break;
  }

  return 1;
}

String fb_compact_serialize(const Variant& thing) {
  
  if (thing.getType() == KindOfInt64) {
    int64_t val = thing.toInt64();
    if (val >= 0 && (uint64_t)val <= kInt7Mask) {
      String s(2, ReserveString);
      *(uint16_t*)(s.mutableData()) = (uint16_t)htons(kInt13Prefix | val);
      s.setSize(2);
      return s;
    }
  }

  StringBuffer sb;
  if (fb_compact_serialize_variant(sb, thing, 0)) {
    return String();
  }

  return sb.detach();
}

Variant HHVM_FUNCTION(fb_compact_serialize, const Variant& thing) {
  return fb_compact_serialize(thing);
}








int fb_compact_unserialize_int64_from_buffer( int64_t& out, const char* buf, int n, int& p) {

  CHECK_ENOUGH(1, p, n);
  uint64_t first = (unsigned char)buf[p];
  if ((first & ~kInt7Mask) == kInt7Prefix) {
    p += 1;
    out = first & kInt7Mask;

  } else if ((first & kInt13PrefixMsbMask) == kInt13PrefixMsb) {
    CHECK_ENOUGH(2, p, n);
    uint16_t val = (uint16_t)ntohs(*reinterpret_cast<const uint16_t*>(buf + p));
    p += 2;
    out = val & kInt13Mask;

  } else if (first == (kCodePrefix | FB_CS_INT16)) {
    p += 1;
    CHECK_ENOUGH(2, p, n);
    int16_t val = (int16_t)ntohs(*reinterpret_cast<const int16_t*>(buf + p));
    p += 2;
    out = val;

  } else if ((first & kInt20PrefixMsbMask) == kInt20PrefixMsb) {
    CHECK_ENOUGH(3, p, n);
    uint32_t b = 0;
    memcpy(&b, buf + p, 3);
    uint32_t val = ntohl(b);
    p += 3;
    out = (val >> 8) & kInt20Mask;

  } else if (first == (kCodePrefix | FB_CS_INT32)) {
    p += 1;
    CHECK_ENOUGH(4, p, n);
    int32_t val = (int32_t)ntohl(*reinterpret_cast<const int32_t*>(buf + p));
    p += 4;
    out = val;

  } else if ((first & kInt54PrefixMsbMask) == kInt54PrefixMsb) {
    CHECK_ENOUGH(7, p, n);
    uint64_t b = 0;
    memcpy(&b, buf + p, 7);
    uint64_t val = ntohll(b);
    p += 7;
    out = (val >> 8) & kInt54Mask;

  } else if (first == (kCodePrefix | FB_CS_INT64)) {
    p += 1;
    CHECK_ENOUGH(8, p, n);
    int64_t val = (int64_t)ntohll(*reinterpret_cast<const int64_t*>(buf + p));
    p += 8;
    out = val;

  } else {
    return FB_UNSERIALIZE_UNRECOGNIZED_OBJECT_TYPE;
  }

  return 0;
}

const StaticString s_empty("");

int fb_compact_unserialize_from_buffer( Variant& out, const char* buf, int n, int& p) {

  CHECK_ENOUGH(1, p, n);
  int code = (unsigned char)buf[p];
  if ((code & ~kCodeMask) != kCodePrefix || (code & kCodeMask) == FB_CS_INT16 || (code & kCodeMask) == FB_CS_INT32 || (code & kCodeMask) == FB_CS_INT64) {



    int64_t val;
    int err = fb_compact_unserialize_int64_from_buffer(val, buf, n, p);
    if (err) {
      return err;
    }
    out = (int64_t)val;
    return 0;
  }
  p += 1;
  code &= kCodeMask;
  switch (code) {
    case FB_CS_NULL:
      out = uninit_null();
      break;

    case FB_CS_TRUE:
      out = true;
      break;

    case FB_CS_FALSE:
      out = false;
      break;

    case FB_CS_DOUBLE:
    {
      CHECK_ENOUGH(8, p, n);
      double d = *reinterpret_cast<const double*>(buf + p);
      p += 8;
      out = d;
      break;
    }

    case FB_CS_STRING_0:
    {
      out = s_empty;
      break;
    }

    case FB_CS_STRING_1:
    case FB_CS_STRING_N:
    {
      int64_t len = 1;
      if (code == FB_CS_STRING_N) {
        int err = fb_compact_unserialize_int64_from_buffer(len, buf, n, p);
        if (err) {
          return err;
        }
      }

    CHECK_ENOUGH(len, p, n);
      out = Variant::attach(StringData::Make(buf + p, len, CopyString));
      p += len;
      break;
    }

    case FB_CS_VECTOR:
    {
      Array arr = Array::CreateVArray();
      while (p < n && buf[p] != (char)(kCodePrefix | FB_CS_STOP)) {
        Variant value;
        int err = fb_compact_unserialize_from_buffer(value, buf, n, p);
        if (err) {
          return err;
        }
        arr.append(value);
      }

      
      CHECK_ENOUGH(1, p, n);
      p += 1;

      out = arr;
      break;
    }

    case FB_CS_LIST_MAP:
    {
      Array arr = Array::CreateDArray();
      int64_t i = 0;
      while (p < n && buf[p] != (char)(kCodePrefix | FB_CS_STOP)) {
        if (buf[p] == (char)(kCodePrefix | FB_CS_SKIP)) {
          ++i;
          ++p;
        } else {
          Variant value;
          int err = fb_compact_unserialize_from_buffer(value, buf, n, p);
          if (err) {
            return err;
          }
          arr.set(i++, value);
        }
      }

      
      CHECK_ENOUGH(1, p, n);
      p += 1;

      out = arr;
      break;
    }

    case FB_CS_MAP:
    {
      Array arr = Array::CreateDArray();
      while (p < n && buf[p] != (char)(kCodePrefix | FB_CS_STOP)) {
        Variant key;
        int err = fb_compact_unserialize_from_buffer(key, buf, n, p);
        if (err) {
          return err;
        }
        Variant value;
        err = fb_compact_unserialize_from_buffer(value, buf, n, p);
        if (err) {
          return err;
        }
        if (key.getType() == KindOfInt64) {
          arr.set(key.toInt64(), value);
        } else if (key.getType() == KindOfString || key.getType() == KindOfPersistentString) {
          mapSetAndConvertStaticKeys( arr, key.asStrRef().get(), std::move(value));
        } else {
          return FB_UNSERIALIZE_UNEXPECTED_ARRAY_KEY_TYPE;
        }
      }

      
      CHECK_ENOUGH(1, p, n);
      p += 1;

      out = arr;
      break;
    }

    default:
      return FB_UNSERIALIZE_UNRECOGNIZED_OBJECT_TYPE;
  }

  return 0;
}

Variant fb_compact_unserialize(const char* str, int len, bool& success, Variant& errcode) {


  Variant ret;
  int p = 0;
  int err = fb_compact_unserialize_from_buffer(ret, str, len, p);
  if (err) {
    success = false;
    errcode = err;
    return false;
  }
  success = true;
  errcode = init_null();
  return ret;
}

Variant HHVM_FUNCTION(fb_compact_unserialize, const Variant& thing, bool& success, Variant& errcode) {

  if (!thing.isString()) {
    success = false;
    errcode = FB_UNSERIALIZE_NONSTRING_VALUE;
    return false;
  }

  String s = thing.toString();
  return fb_compact_unserialize(s.data(), s.size(), success, errcode);
}



bool HHVM_FUNCTION(fb_utf8ize, Variant& input) {
  String s = input.toString();
  const char* const srcBuf = s.data();
  int32_t srcLenBytes = s.size();

  if (s.size() < 0 || s.size() > INT_MAX) {
    return false; 
  }

  
  int32_t srcPosBytes;
  for (srcPosBytes = 0; srcPosBytes < srcLenBytes; ) {
    
    if (srcBuf[srcPosBytes] != 0 && !(srcBuf[srcPosBytes] & 0x80)) {
      srcPosBytes++; 
      continue;
    }
    UChar32 curCodePoint;
    
    int32_t savedSrcPosBytes = srcPosBytes;
    U8_NEXT(srcBuf, srcPosBytes, srcLenBytes, curCodePoint);
    if (curCodePoint <= 0) {
      
      srcPosBytes = savedSrcPosBytes;
      break;
    }
  }

  if (srcPosBytes == srcLenBytes) {
    
    return true;
  }

  
  
  
  
  
  int32_t bytesRemaining = srcLenBytes - srcPosBytes;
  uint64_t dstMaxLenBytes = srcPosBytes + (RuntimeOption::Utf8izeReplace ? bytesRemaining * U8_LENGTH(SUBSTITUTION_CHARACTER) :
    bytesRemaining);
  if (dstMaxLenBytes > INT_MAX) {
    return false; 
  }
  String dstStr(dstMaxLenBytes, ReserveString);
  char *dstBuf = dstStr.mutableData();

  
  memcpy(dstBuf, srcBuf, srcPosBytes);

  
  int32_t dstPosBytes = srcPosBytes; 
  for (; srcPosBytes < srcLenBytes; ) {
    UChar32 curCodePoint;
    
    if (srcBuf[srcPosBytes] != 0 && !(srcBuf[srcPosBytes] & 0x80)) {
      curCodePoint = srcBuf[srcPosBytes++]; 
    } else {
      U8_NEXT(srcBuf, srcPosBytes, srcLenBytes, curCodePoint);
    }
    if (curCodePoint <= 0) {
      
      
      if (!RuntimeOption::Utf8izeReplace) {
        continue; 
      }
      curCodePoint = SUBSTITUTION_CHARACTER; 
    }
    
    U8_APPEND_UNSAFE(dstBuf, dstPosBytes, curCodePoint);
  }
  assertx(dstPosBytes <= dstMaxLenBytes);
  input = dstStr.shrink(dstPosBytes);
  return true;
}


static int fb_utf8_strlen_impl(const String& input, bool deprecated) {
  
  int32_t sourceLength = input.size();
  const char* const sourceBuffer = input.data();
  int64_t num_code_points = 0;

  for (int32_t sourceOffset = 0; sourceOffset < sourceLength; ) {
    UChar32 sourceCodePoint;
    
    
    U8_NEXT(sourceBuffer, sourceOffset, sourceLength, sourceCodePoint);
    if (deprecated && sourceCodePoint < 0) {
      return sourceLength; 
    }
    num_code_points++;
  }
  return num_code_points;
}

int64_t HHVM_FUNCTION(fb_utf8_strlen, const String& input) {
  return fb_utf8_strlen_impl(input,  false);
}

int64_t HHVM_FUNCTION(fb_utf8_strlen_deprecated, const String& input) {
  return fb_utf8_strlen_impl(input,  true);
}


static String fb_utf8_substr_simple(const String& str, int32_t firstCodePoint, int32_t numDesiredCodePoints) {

  const char* const srcBuf = str.data();
  int32_t srcLenBytes = str.size(); 

  assertx(firstCodePoint >= 0); 
  assertx(numDesiredCodePoints > 0); 
  if (str.size() <= 0 || str.size() > INT_MAX || firstCodePoint >= srcLenBytes) {

    return empty_string();
  }

  
  
  numDesiredCodePoints = std::min(numDesiredCodePoints, srcLenBytes - firstCodePoint);

  
  
  
  
  
  
  uint64_t dstMaxLenBytes = std::min((uint64_t)numDesiredCodePoints * 4, (uint64_t)srcLenBytes - firstCodePoint);

  dstMaxLenBytes = std::max(dstMaxLenBytes, (uint64_t)numDesiredCodePoints * U8_LENGTH(SUBSTITUTION_CHARACTER));

  if (dstMaxLenBytes > INT_MAX) {
    return empty_string(); 
  }
  String dstStr(dstMaxLenBytes, ReserveString);
  char* dstBuf = dstStr.mutableData();
  int32_t dstPosBytes = 0;

  
  for (int32_t srcPosBytes = 0, srcPosCodePoints = 0;
       srcPosBytes < srcLenBytes &&  srcPosCodePoints < firstCodePoint + numDesiredCodePoints;
       srcPosCodePoints++) {

    
    UChar32 curCodePoint;
    U8_NEXT(srcBuf, srcPosBytes, srcLenBytes, curCodePoint);

    if (srcPosCodePoints >= firstCodePoint) {
      
      if (curCodePoint < 0) {
        curCodePoint = SUBSTITUTION_CHARACTER; 
      }
      
      
      U8_APPEND_UNSAFE(dstBuf, dstPosBytes, curCodePoint);
    }
  }

  assertx(dstPosBytes <= dstMaxLenBytes);
  if (dstPosBytes > 0) {
    dstStr.shrink(dstPosBytes);
    return dstStr;
  }
  return empty_string();
}

String HHVM_FUNCTION(fb_utf8_substr, const String& str, int64_t start, int64_t length ) {
  if (length > INT_MAX) {
    length = INT_MAX;
  }
  
  
  if (start < 0 || length < 0) {
    
    Variant utf8StrlenResult = HHVM_FN(fb_utf8_strlen)(str);
    int32_t sourceNumCodePoints = utf8StrlenResult.toInt32();

    if (start < 0) {
      
      
      start = sourceNumCodePoints + start; 
    }
    if (length < 0) {
      
      length = sourceNumCodePoints - start + length; 
    }
  }
  if (start < 0 || length <= 0) {
    return empty_string(); 
  }

  return fb_utf8_substr_simple(str, start, length);
}



bool HHVM_FUNCTION(fb_intercept, const String& name, const Variant& handler, const Variant& data ) {
  return register_intercept(name, handler, data, true, false);
}

bool HHVM_FUNCTION(fb_intercept2, const String& name, const Variant& handler) {
  return register_intercept(name, handler, uninit_variant, true, true);
}

bool HHVM_FUNCTION(fb_rename_function, const String& orig_func_name, const String& new_func_name) {
  if (orig_func_name.empty() || new_func_name.empty() || orig_func_name.get()->isame(new_func_name.get())) {
    raise_invalid_argument_warning("unable to rename %s", orig_func_name.data());
    return false;
  }

  if (!function_exists(orig_func_name)) {
    raise_warning("fb_rename_function(%s, %s) failed: %s does not exist!", orig_func_name.data(), new_func_name.data(), orig_func_name.data());

    return false;
  }

  if (function_exists(new_func_name)) {
    if (new_func_name.data()[0] != '1') {
      raise_warning("fb_rename_function(%s, %s) failed: %s already exists!", orig_func_name.data(), new_func_name.data(), new_func_name.data());

      return false;
    }
  }

  rename_function(orig_func_name, new_func_name);
  return true;
}



Variant HHVM_FUNCTION(fb_get_code_coverage, bool flush) {
  RequestInfo *ti = RequestInfo::s_requestInfo.getNoCheck();
  if (ti->m_reqInjectionData.getCoverage()) {
    Array ret = ti->m_coverage.Report();
    if (flush) {
      ti->m_coverage.Reset();
    }
    return ret;
  }
  return false;
}

void HHVM_FUNCTION(fb_enable_code_coverage) {
  RequestInfo *ti = RequestInfo::s_requestInfo.getNoCheck();
  ti->m_coverage.Reset();
  ti->m_reqInjectionData.setCoverage(true);
  if (g_context->isNested()) {
    raise_notice("Calling fb_enable_code_coverage from a nested " "VM instance may cause unpredicable results");
  }
  if (RuntimeOption::EvalEnableCodeCoverage == 0) {
    SystemLib::throwRuntimeExceptionObject( "Calling fb_enable_code_coverage without enabling the setting " "Eval.EnableCodeCoverage");

  }
  if (RuntimeOption::EvalEnableCodeCoverage == 1) {
    auto const tport = g_context->getTransport();
    if (!tport || tport->getParam("enable_code_coverage").compare("true") != 0) {
      SystemLib::throwRuntimeExceptionObject( "Calling fb_enable_code_coverage without adding " "'enable_code_coverage' in request params");

    }
  }
}

Array disable_code_coverage_helper(bool report_frequency) {
  RequestInfo *ti = RequestInfo::s_requestInfo.getNoCheck();
  ti->m_reqInjectionData.setCoverage(false);
  auto ret = ti->m_coverage.Report(report_frequency);
  ti->m_coverage.Reset();
  return ret;
}

Array HHVM_FUNCTION(fb_disable_code_coverage) {
  return disable_code_coverage_helper( false);
}

Array HHVM_FUNCTION(HH_disable_code_coverage_with_frequency) {
  return disable_code_coverage_helper( true);
}



bool HHVM_FUNCTION(fb_output_compression, bool new_value) {
  Transport *transport = g_context->getTransport();
  if (transport) {
    bool rv = transport->isCompressionEnabled();
    if (new_value) {
      transport->enableCompression();
    } else {
      transport->disableCompression();
    }
    return rv;
  }
  return false;
}

void HHVM_FUNCTION(fb_set_exit_callback, const Variant& function) {
  g_context->setExitCallback(function);
}

const StaticString s_flush_stats("flush_stats"), s_chunk_stats("chunk_stats"), s_total("total"), s_sent("sent"), s_time("time");





int64_t HHVM_FUNCTION(fb_get_last_flush_size) {
  Transport *transport = g_context->getTransport();
  return transport ? transport->getLastChunkSentSize() : 0;
}

extern Array stat_impl(struct stat*); 

template<class Function> static Variant do_lazy_stat(Function dostat, const String& filename) {
  struct stat sb;
  if (dostat(File::TranslatePathWithFileCache(filename).c_str(), &sb)) {
    Logger::Verbose("%s/%d: %s", __FUNCTION__, __LINE__, folly::errnoStr(errno).c_str());
    return false;
  }
  return stat_impl(&sb);
}

Variant HHVM_FUNCTION(fb_lazy_lstat, const String& filename) {
  if (!FileUtil::checkPathAndWarn(filename, __FUNCTION__ + 2, 1)) {
    return false;
  }
  return do_lazy_stat(StatCache::lstat, filename);
}

Variant HHVM_FUNCTION(fb_lazy_realpath, const String& filename) {
  if (!FileUtil::checkPathAndWarn(filename, __FUNCTION__ + 2, 1)) {
    return false;
  }

  return StatCache::realpath(filename.c_str());
}

int64_t HHVM_FUNCTION(HH_non_crypto_md5_upper, StringArg str) {
  Md5Digest md5(str.get()->data(), str.get()->size());
  int64_t pre_decode;
  
  memcpy(&pre_decode, md5.digest, sizeof(pre_decode));
  
  
  return folly::Endian::big(pre_decode);
}

int64_t HHVM_FUNCTION(HH_non_crypto_md5_lower, StringArg str) {
  Md5Digest md5(str.get()->data(), str.get()->size());
  int64_t pre_decode;
  
  memcpy(&pre_decode, md5.digest + 8, sizeof(pre_decode));
  
  
  return folly::Endian::big(pre_decode);
}

int64_t HHVM_FUNCTION(HH_int_mul_overflow, int64_t a, int64_t b) {
  
  uint64_t ua = a;
  uint64_t ub = b;
  __uint128_t full_product = static_cast<__uint128_t>(ua) * static_cast<__uint128_t>(ub);
  
  return static_cast<int64_t>(full_product >> 64);
}

int64_t HHVM_FUNCTION(HH_int_mul_add_overflow, int64_t a, int64_t b, int64_t bias) {
  uint64_t ua = a;
  uint64_t ub = b;
  uint64_t umbias = static_cast<uint64_t>(-1 - bias);
  __uint128_t full = static_cast<__uint128_t>(ua) * static_cast<__uint128_t>(ub);
  
  
  uint64_t full_lower = static_cast<uint64_t>(full);
  return static_cast<int64_t>(full >> 64) + (full_lower > umbias);
}



EXTERNALLY_VISIBLE void const_load() {
  
}



struct FBExtension : Extension {
  FBExtension(): Extension("fb", "1.0.0") {}

  void moduleInit() override {
    HHVM_RC_BOOL_SAME(HHVM_FACEBOOK);
    HHVM_RC_BOOL(HHVM_ONE_BIT_REFCOUNT, one_bit_refcount);
    HHVM_RC_INT_SAME(FB_UNSERIALIZE_NONSTRING_VALUE);
    HHVM_RC_INT_SAME(FB_UNSERIALIZE_UNEXPECTED_END);
    HHVM_RC_INT_SAME(FB_UNSERIALIZE_UNRECOGNIZED_OBJECT_TYPE);
    HHVM_RC_INT_SAME(FB_UNSERIALIZE_UNEXPECTED_ARRAY_KEY_TYPE);

    HHVM_RC_INT(FB_SERIALIZE_HACK_ARRAYS, k_FB_SERIALIZE_HACK_ARRAYS);
    HHVM_RC_INT(FB_SERIALIZE_VARRAY_DARRAY, k_FB_SERIALIZE_VARRAY_DARRAY);
    HHVM_RC_INT(FB_SERIALIZE_HACK_ARRAYS_AND_KEYSETS, k_FB_SERIALIZE_HACK_ARRAYS_AND_KEYSETS);

    HHVM_FE(fb_serialize);
    HHVM_FE(fb_unserialize);
    HHVM_FE(fb_compact_serialize);
    HHVM_FE(fb_compact_unserialize);
    HHVM_FE(fb_utf8ize);
    HHVM_FE(fb_utf8_strlen);
    HHVM_FE(fb_utf8_strlen_deprecated);
    HHVM_FE(fb_utf8_substr);
    HHVM_FE(fb_intercept);
    HHVM_FE(fb_intercept2);
    HHVM_FE(fb_rename_function);
    HHVM_FE(fb_get_code_coverage);
    HHVM_FE(fb_enable_code_coverage);
    HHVM_FE(fb_disable_code_coverage);
    HHVM_FE(fb_output_compression);
    HHVM_FE(fb_set_exit_callback);
    HHVM_FE(fb_get_last_flush_size);
    HHVM_FE(fb_lazy_lstat);
    HHVM_FE(fb_lazy_realpath);

    HHVM_FALIAS(HH\\disable_code_coverage_with_frequency, HH_disable_code_coverage_with_frequency);
    HHVM_FALIAS(HH\\non_crypto_md5_upper, HH_non_crypto_md5_upper);
    HHVM_FALIAS(HH\\non_crypto_md5_lower, HH_non_crypto_md5_lower);
    HHVM_FALIAS(HH\\int_mul_overflow, HH_int_mul_overflow);
    HHVM_FALIAS(HH\\int_mul_add_overflow, HH_int_mul_add_overflow);

    loadSystemlib();
  }
} s_fb_extension;


}
