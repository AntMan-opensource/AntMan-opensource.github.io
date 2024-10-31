














namespace tensorflow {
namespace {

inline bool PyIsInstance(PyObject* obj, PyTypeObject* t) {
  return PyObject_IsInstance(obj, reinterpret_cast<PyObject*>(t));
}

inline PyObject* PyType(PyObject* obj) {
  return reinterpret_cast<PyObject*>(obj->ob_type);
}

bool IsPyString(PyObject* obj) {
  return PyBytes_Check(obj) || PyUnicode_Check(obj);
}

bool IsPyInt(PyObject* obj) {

  return PyLong_Check(obj) || PyIsInstance(obj, &PyIntegerArrType_Type);

  return PyInt_Check(obj) || PyLong_Check(obj) || PyIsInstance(obj, &PyIntegerArrType_Type);

}

bool IsPyDouble(PyObject* obj) {
  return PyIsInstance(obj, &PyDoubleArrType_Type);  
}

bool IsNumpyHalf(PyObject* obj) {
  return PyIsInstance(obj, &PyHalfArrType_Type);
}

bool IsPyFloat(PyObject* obj) {
  return PyFloat_Check(obj) || PyIsInstance(obj, &PyFloatingArrType_Type);
}

struct ConverterState {
  
  TensorShape inferred_shape;

  
  DataType inferred_dtype;

  
  
  
  
  
  PyTypeObject* last_zerodim_type;
  bool last_zerodim_check;

  ConverterState() : inferred_dtype(DT_INVALID), last_zerodim_type(nullptr) {}
};




PyObject* ZeroDimArrayToScalar(PyObject* obj, ConverterState* state) {
  auto type = Py_TYPE(obj);
  auto pyarray_obj = reinterpret_cast<PyArrayObject*>(obj);
  if (type != state->last_zerodim_type) {
    state->last_zerodim_type = type;
    state->last_zerodim_check = PyObject_TypeCheck(obj, &PyArray_Type) && !PyObject_TypeCheck(obj, &PyGenericArrType_Type);

  }

  if (state->last_zerodim_check && PyArray_NDIM(pyarray_obj) == 0) {
    obj = PyArray_ToScalar(PyArray_DATA(pyarray_obj), pyarray_obj);
  } else {
    Py_INCREF(obj);
  }
  return obj;
}



Status SampleElementFromSequence(PyObject* seq, PyObject** elem) {
  *elem = PySequence_GetItem(seq, 0);
  if (*elem != nullptr) return Status::OK();
  
  
  
  
  
  
  
  
  
  PyErr_Clear();
  Safe_PyObjectPtr iter(PyObject_GetIter(seq));
  if (PyErr_Occurred()) {
    return errors::InvalidArgument("Cannot infer dtype of a ", Py_TYPE(seq)->tp_name, " object: ", PyExceptionFetch());

  }
  *elem = PyIter_Next(iter.get());
  if (PyErr_Occurred()) {
    return errors::InvalidArgument( "Cannot infer dtype of a ", Py_TYPE(seq)->tp_name, " object, as iter(<object>).next() failed: ", PyExceptionFetch());

  }
  if (*elem == nullptr) {
    return errors::InvalidArgument("Cannot infer dtype of a ", Py_TYPE(seq)->tp_name, " object since it is an empty sequence");

  }
  return Status::OK();
}

tstring PyRepr(PyObject* obj);
bool IsPyDimension(PyObject* obj);

Status InferShapeAndType(PyObject* obj, ConverterState* state) {
  std::vector<Safe_PyObjectPtr> refs_to_clean;
  while (true) {
    
    
    obj = ZeroDimArrayToScalar(obj, state);
    refs_to_clean.push_back(make_safe(obj));
    
    if (IsPyString(obj)) {
      state->inferred_dtype = DT_STRING;
    } else if (PySequence_Check(obj)) {
      auto length = PySequence_Length(obj);
      if (length > 0) {
        state->inferred_shape.AddDim(length);
        PyObject* elem = nullptr;
        TF_RETURN_IF_ERROR(SampleElementFromSequence(obj, &elem));
        obj = elem;
        refs_to_clean.push_back(make_safe(obj));
        continue;
      } else if (length == 0) {
        state->inferred_shape.AddDim(length);
        state->inferred_dtype = DT_INVALID;  
      } else {
        
        if (PyErr_Occurred()) {
          
          
          return errors::InvalidArgument(PyExceptionFetch());
        } else {
          
          
          return errors::InvalidArgument( "Attempted to convert an invalid sequence to a Tensor.");
        }
      }
    } else if (IsPyDouble(obj)) {
      state->inferred_dtype = DT_DOUBLE;
    } else if (IsNumpyHalf(obj)) {
      state->inferred_dtype = DT_HALF;
    } else if (IsPyFloat(obj)) {
      state->inferred_dtype = DT_FLOAT;
    } else if (PyBool_Check(obj) || PyIsInstance(obj, &PyBoolArrType_Type)) {
      
      state->inferred_dtype = DT_BOOL;
    } else if (IsPyInt(obj)) {
      state->inferred_dtype = DT_INT64;
    } else if (IsPyDimension(obj)) {
      state->inferred_dtype = DT_INT64;
    } else if (PyComplex_Check(obj) || PyIsInstance(obj, &PyComplexFloatingArrType_Type)) {
      state->inferred_dtype = DT_COMPLEX128;
    } else {
      return errors::InvalidArgument("Attempt to convert a value (", PyRepr(obj), ") with an unsupported type (", PyRepr(PyType(obj)), ") to a Tensor.");


    }
    return Status::OK();
  }
}



const char ErrorConverting[] = "Error while converting Python sequence to Tensor.";
const char ErrorRectangular[] = "Can't convert non-rectangular Python sequence to Tensor.";
const char ErrorMixedTypes[] = "Can't convert Python sequence with mixed types to Tensor.";
const char ErrorOutOfRange[] = "Can't convert Python sequence with out-of-range integer to Tensor.";
const char ErrorOutOfRangeDouble[] = "Can't convert Python sequence with a value out of range for a " "double-precision float.";

const char ErrorConvertingUnicodeString[] = "Error converting unicode string while converting Python sequence to " "Tensor.";

const char ErrorFoundInt64[] = "Can't convert Python sequence with out-of-range integer to int32 Tensor.";
const char ErrorFoundFloat[] = "Can't convert Python sequence with floating point values to integer " "Tensor.";







template <class T> struct ConverterTraits {
  static const tensorflow::DataType kTypeEnum;
  static const char* ConvertScalar(PyObject* v, T* out);
};

template <class T> struct Converter {
  static const char* Helper(PyObject* obj, int depth, ConverterState* state, T** buf) {
    if (TF_PREDICT_FALSE(obj == nullptr)) {
      return ErrorConverting;
    }

    Safe_PyObjectPtr seq = make_safe(PySequence_Fast(obj, ""));
    if (TF_PREDICT_FALSE(seq == nullptr)) return ErrorRectangular;

    const int64 s = state->inferred_shape.dim_size(depth);
    if (TF_PREDICT_FALSE(s != PySequence_Fast_GET_SIZE(seq.get()))) {
      return ErrorRectangular;
    }

    if (state->inferred_shape.dims() - depth > 1) {
      
      for (int64 i = 0; i < s; ++i) {
        const char* error = Helper(PySequence_Fast_GET_ITEM(seq.get(), i), depth + 1, state, buf);
        if (TF_PREDICT_FALSE(error != nullptr)) return error;
      }
    } else {
      PyObject** l = PySequence_Fast_ITEMS(seq.get());
      for (int64 i = 0; i < s; ++i) {
        auto scalar = ZeroDimArrayToScalar(l[i], state);
        const char* error = ConverterTraits<T>::ConvertScalar(scalar, *buf);
        Py_DECREF(scalar);
        if (TF_PREDICT_FALSE(error != nullptr)) return error;
        ++*buf;
      }
    }
    return nullptr;
  }

  static const char* Convert(PyObject* obj, ConverterState* state, Tensor* dest) {
    
    Tensor result(ConverterTraits<T>::kTypeEnum, state->inferred_shape);
    if (state->inferred_shape.dims() == 0) { 
      T value;
      auto scalar = ZeroDimArrayToScalar(obj, state);
      const char* error = ConverterTraits<T>::ConvertScalar(scalar, &value);
      Py_DECREF(scalar);
      if (error != nullptr) return error;
      result.scalar<T>()() = value;
    } else {
      T* buf = result.flat<T>().data();
      const char* error = Helper(obj, 0, state, &buf);
      if (error != nullptr) return error;
    }
    *dest = result;
    return nullptr;
  }
};



template <> struct ConverterTraits<int64> {
  static const tensorflow::DataType kTypeEnum = DT_INT64;

  static const char* ConvertScalar(PyObject* v, int64* out) {

    if (TF_PREDICT_TRUE(PyInt_Check(v))) {
      *out = PyInt_AS_LONG(v);
      return nullptr;
    }

    if (TF_PREDICT_TRUE(PyLong_Check(v) || IsPyDimension(v))) {
      int overflow = 0;
      
      *out = PyLong_AsLongLongAndOverflow(v, &overflow);
      if (TF_PREDICT_FALSE(overflow)) return ErrorOutOfRange;
      return nullptr;
    }
    if (PyIsInstance(v, &PyIntegerArrType_Type)) {  

      Safe_PyObjectPtr as_int = make_safe(PyNumber_Int(v));

      Safe_PyObjectPtr as_int = make_safe(PyNumber_Long(v));

      return ConvertScalar(as_int.get(), out);
    }
    if (IsPyFloat(v)) return ErrorFoundFloat;
    return ErrorMixedTypes;
  }
};

typedef Converter<int64> Int64Converter;

template <> struct ConverterTraits<uint64> {
  static const tensorflow::DataType kTypeEnum = DT_UINT64;

  static const char* ConvertScalar(PyObject* v, uint64* out) {

    if (TF_PREDICT_TRUE(PyInt_Check(v))) {
      *out = PyInt_AsUnsignedLongLongMask(v);
      return nullptr;
    }

    if (TF_PREDICT_TRUE(PyLong_Check(v) || IsPyDimension(v))) {
      *out = PyLong_AsUnsignedLongLong(v);
      return nullptr;
    }
    if (PyIsInstance(v, &PyIntegerArrType_Type)) {  

      Safe_PyObjectPtr as_int = make_safe(PyNumber_Int(v));

      Safe_PyObjectPtr as_int = make_safe(PyNumber_Long(v));

      return ConvertScalar(as_int.get(), out);
    }
    if (IsPyFloat(v)) return ErrorFoundFloat;
    return ErrorMixedTypes;
  }
};

typedef Converter<uint64> UInt64Converter;

template <> struct ConverterTraits<int32> {
  static const tensorflow::DataType kTypeEnum = DT_INT32;

  static const char* ConvertScalar(PyObject* v, int32* out) {
    int64 i;

    if (TF_PREDICT_TRUE(PyInt_Check(v))) {
      i = PyInt_AS_LONG(v);
    } else  if (PyLong_Check(v) || IsPyDimension(v)) {

      int overflow = 0;
      
      i = PyLong_AsLongLongAndOverflow(v, &overflow);
      if (TF_PREDICT_FALSE(overflow)) return ErrorOutOfRange;
    } else if (PyIsInstance(v, &PyIntegerArrType_Type)) {  

      Safe_PyObjectPtr as_int = make_safe(PyNumber_Int(v));

      Safe_PyObjectPtr as_int = make_safe(PyNumber_Long(v));

      return ConvertScalar(as_int.get(), out);
    } else if (IsPyFloat(v)) {
      return ErrorFoundFloat;
    } else {
      return ErrorMixedTypes;
    }
    *out = static_cast<uint32>(static_cast<uint64>(i));
    
    if (TF_PREDICT_FALSE(i != *out)) return ErrorFoundInt64;
    return nullptr;
  }
};

typedef Converter<int32> Int32Converter;



template <class T> static const char* ConvertOneFloat(PyObject* v, T* out) {
  if (PyErr_Occurred()) {
    return nullptr;
  }
  if (TF_PREDICT_TRUE(PyFloat_Check(v))) {
    const double as_double = PyFloat_AS_DOUBLE(v);
    *out = static_cast<T>(as_double);
    
    if (TF_PREDICT_FALSE(sizeof(T) < sizeof(double) && std::isinf(*out) && std::isfinite(as_double))) {
      return ErrorOutOfRangeDouble;
    }
    return nullptr;
  }

  if (PyInt_Check(v)) {
    *out = PyInt_AS_LONG(v);
    return nullptr;
  }

  if (PyLong_Check(v)) {
    *out = PyLong_AsDouble(v);
    if (PyErr_Occurred()) return ErrorOutOfRangeDouble;
    return nullptr;
  }
  if (PyIsInstance(v, &PyFloatingArrType_Type)) {  
    Safe_PyObjectPtr as_float = make_safe(PyNumber_Float(v));
    if (PyErr_Occurred()) {
      return nullptr;
    }
    return ConvertOneFloat<T>(as_float.get(), out);
  }
  if (PyIsInstance(v, &PyIntegerArrType_Type)) {  

    Safe_PyObjectPtr as_int = make_safe(PyNumber_Int(v));

    Safe_PyObjectPtr as_int = make_safe(PyNumber_Long(v));

    if (PyErr_Occurred()) {
      return nullptr;
    }
    return ConvertOneFloat<T>(as_int.get(), out);
  }
  return ErrorMixedTypes;
}

template <> struct ConverterTraits<float> {
  static const tensorflow::DataType kTypeEnum = DT_FLOAT;
  static const char* ConvertScalar(PyObject* v, float* out) {
    return ConvertOneFloat<float>(v, out);
  }
};

template <> struct ConverterTraits<double> {
  static const tensorflow::DataType kTypeEnum = DT_DOUBLE;
  static const char* ConvertScalar(PyObject* v, double* out) {
    return ConvertOneFloat<double>(v, out);
  }
};

typedef Converter<double> DoubleConverter;
typedef Converter<float> FloatConverter;

template <> struct ConverterTraits<Eigen::half> {
  static const tensorflow::DataType kTypeEnum = DT_HALF;

  static const char* ConvertScalar(PyObject* v, Eigen::half* out) {
    
    
    Safe_PyObjectPtr as_float = make_safe(PyNumber_Float(v));
    double v_double = PyFloat_AS_DOUBLE(as_float.get());
    *out = Eigen::half(v_double);

    return nullptr;
  }
};

typedef Converter<Eigen::half> NumpyHalfConverter;



template <> struct ConverterTraits<tstring> {
  static const tensorflow::DataType kTypeEnum = DT_STRING;

  static const char* ConvertScalar(PyObject* v, tstring* out) {
    if (PyBytes_Check(v)) {
      out->assign(PyBytes_AS_STRING(v), PyBytes_GET_SIZE(v));
      return nullptr;
    }
    if (PyUnicode_Check(v)) {

      Py_ssize_t size;
      const char* str = PyUnicode_AsUTF8AndSize(v, &size);
      if (str == nullptr) return ErrorConvertingUnicodeString;
      out->assign(str, size);
      return nullptr;

      PyObject* py_str = PyUnicode_AsUTF8String(v);
      if (py_str == nullptr) return ErrorConvertingUnicodeString;
      out->assign(PyBytes_AS_STRING(py_str), PyBytes_GET_SIZE(py_str));
      Py_DECREF(py_str);
      return nullptr;

    }
    return ErrorMixedTypes;
  }
};

typedef Converter<tstring> StringConverter;




tstring PyRepr(PyObject* obj) {
  if (obj == nullptr) {
    return "<null>";
  }
  Safe_PyObjectPtr repr_obj = make_safe(PyObject_Repr(obj));
  if (repr_obj) {
    tstring repr_str;
    if (ConverterTraits<tstring>::ConvertScalar(repr_obj.get(), &repr_str) == nullptr) {
      return repr_str;
    }
  }
  return "<error computing repr()>";
}

bool IsPyDimension(PyObject* obj) {
  const char* tp_name = obj->ob_type->tp_name;
  if (strcmp(tp_name, "Dimension") != 0) return false;
  bool ret = str_util::EndsWith( PyRepr(PyType(obj)), "tensorflow.python.framework.tensor_shape.Dimension'>");

  return ret;
}



template <> struct ConverterTraits<complex128> {
  static const tensorflow::DataType kTypeEnum = DT_COMPLEX128;
  static const char* ConvertScalar(PyObject* v, complex128* out) {
    if (PyComplex_Check(v)) {
      *out = complex128(PyComplex_RealAsDouble(v), PyComplex_ImagAsDouble(v));
      return nullptr;
    } else if (PyIsInstance(v, &PyComplexFloatingArrType_Type)) {  
      auto as_complex = PyComplex_AsCComplex(v);
      *out = complex128(as_complex.real, as_complex.imag);
      return nullptr;
    }
    return ErrorMixedTypes;
  }
};

typedef Converter<complex128> Complex128Converter;



template <> struct ConverterTraits<bool> {
  typedef bool Type;
  static const tensorflow::DataType kTypeEnum = DT_BOOL;

  static const char* ConvertScalar(PyObject* v, bool* out) {
    if (v == Py_True) {
      *out = true;
    } else if (v == Py_False) {
      *out = false;
    } else if (PyIsInstance(v, &PyBoolArrType_Type)) {  
      *out = PyObject_IsTrue(v);
    } else {
      return ErrorMixedTypes;
    }
    return nullptr;
  }
};

typedef Converter<bool> BoolConverter;

}  







Status PySeqToTensor(PyObject* obj, DataType dtype, Tensor* ret) {
  ConverterState state;
  TF_RETURN_IF_ERROR(InferShapeAndType(obj, &state));
  DataType requested_dtype = DT_INVALID;
  if (dtype != DT_INVALID) {
    requested_dtype = dtype;
  }
  
  
  
  
  switch (requested_dtype) {
    case DT_FLOAT:
      if (FloatConverter::Convert(obj, &state, ret) == nullptr)
        return Status::OK();
      break;

    case DT_DOUBLE:
      if (DoubleConverter::Convert(obj, &state, ret) == nullptr)
        return Status::OK();
      break;

    case DT_HALF:
      RETURN_STRING_AS_STATUS(NumpyHalfConverter::Convert(obj, &state, ret));

    case DT_INT64:
      if (Int64Converter::Convert(obj, &state, ret) == nullptr)
        return Status::OK();
      break;

    case DT_INT32:
      if (Int32Converter::Convert(obj, &state, ret) == nullptr)
        return Status::OK();
      break;

    case DT_UINT64:
      if (UInt64Converter::Convert(obj, &state, ret) == nullptr)
        return Status::OK();
      break;

    case DT_COMPLEX128:
      if (Complex128Converter::Convert(obj, &state, ret) == nullptr)
        return Status::OK();
      break;

    case DT_STRING:
      if (StringConverter::Convert(obj, &state, ret) == nullptr)
        return Status::OK();
      break;

    case DT_BOOL:
      if (BoolConverter::Convert(obj, &state, ret) == nullptr)
        return Status::OK();
      break;

    default:
      break;
  }
  switch (state.inferred_dtype) {
    case DT_FLOAT:
      
      if (requested_dtype == DT_INVALID) {
        
        
        RETURN_STRING_AS_STATUS(FloatConverter::Convert(obj, &state, ret));
      } else {
        
        
        
        
        RETURN_STRING_AS_STATUS(DoubleConverter::Convert(obj, &state, ret));
      }

    case DT_DOUBLE:
      RETURN_STRING_AS_STATUS(DoubleConverter::Convert(obj, &state, ret));

    case DT_HALF:
      RETURN_STRING_AS_STATUS(NumpyHalfConverter::Convert(obj, &state, ret));

    case DT_INT64:
      if (requested_dtype == DT_INVALID) {
        const char* error = Int32Converter::Convert(obj, &state, ret);
        if (error == ErrorFoundInt64) {
          error = Int64Converter::Convert(obj, &state, ret);
        }
        if (error == ErrorFoundFloat) {
          error = FloatConverter::Convert(obj, &state, ret);
        }
        
        
        RETURN_STRING_AS_STATUS(error);
      } else {
        const char* error = Int64Converter::Convert(obj, &state, ret);
        if (error == ErrorFoundFloat) {
          error = DoubleConverter::Convert(obj, &state, ret);
        }
        RETURN_STRING_AS_STATUS(error);
      }

    case DT_STRING:
      RETURN_STRING_AS_STATUS(StringConverter::Convert(obj, &state, ret));

    case DT_COMPLEX128:
      RETURN_STRING_AS_STATUS(Complex128Converter::Convert(obj, &state, ret));

    case DT_BOOL:
      RETURN_STRING_AS_STATUS(BoolConverter::Convert(obj, &state, ret));

    case DT_INVALID:  
      *ret = Tensor(requested_dtype == DT_INVALID ? DT_FLOAT : requested_dtype, state.inferred_shape);
      return Status::OK();

    default:
      return errors::Unimplemented("Missing Python -> Tensor conversion for ", DataTypeString(state.inferred_dtype));
  }

  return Status::OK();
}

}  
