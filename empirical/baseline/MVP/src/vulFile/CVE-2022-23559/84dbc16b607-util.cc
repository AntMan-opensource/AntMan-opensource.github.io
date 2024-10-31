

















namespace tflite {
namespace {

TfLiteStatus UnresolvedOpInvoke(TfLiteContext* context, TfLiteNode* node) {
  context->ReportError(context, "Encountered an unresolved custom op. Did you miss " "a custom op or delegate?");

  return kTfLiteError;
}

}  

bool IsFlexOp(const char* custom_name) {
  return custom_name && strncmp(custom_name, kFlexCustomCodePrefix, strlen(kFlexCustomCodePrefix)) == 0;
}

std::unique_ptr<TfLiteIntArray, TfLiteIntArrayDeleter> BuildTfLiteIntArray( const std::vector<int>& data) {
  std::unique_ptr<TfLiteIntArray, TfLiteIntArrayDeleter> result( TfLiteIntArrayCreate(data.size()));
  std::copy(data.begin(), data.end(), result->data);
  return result;
}

TfLiteIntArray* ConvertVectorToTfLiteIntArray(const std::vector<int>& input) {
  return ConvertArrayToTfLiteIntArray(static_cast<int>(input.size()), input.data());
}

TfLiteIntArray* ConvertArrayToTfLiteIntArray(const int rank, const int* dims) {
  TfLiteIntArray* output = TfLiteIntArrayCreate(rank);
  for (size_t i = 0; i < rank; i++) {
    output->data[i] = dims[i];
  }
  return output;
}

bool EqualArrayAndTfLiteIntArray(const TfLiteIntArray* a, const int b_size, const int* b) {
  if (!a) return false;
  if (a->size != b_size) return false;
  for (int i = 0; i < a->size; ++i) {
    if (a->data[i] != b[i]) return false;
  }
  return true;
}

size_t CombineHashes(std::initializer_list<size_t> hashes) {
  size_t result = 0;
  
  for (size_t hash : hashes) {
    result = result ^ (hash + 0x9e3779b97f4a7800ULL + (result << 10) + (result >> 4));
  }
  return result;
}

TfLiteStatus GetSizeOfType(TfLiteContext* context, const TfLiteType type, size_t* bytes) {
  
  
  switch (type) {
    case kTfLiteFloat32:
      *bytes = sizeof(float);
      break;
    case kTfLiteInt32:
      *bytes = sizeof(int32_t);
      break;
    case kTfLiteUInt32:
      *bytes = sizeof(uint32_t);
      break;
    case kTfLiteUInt8:
      *bytes = sizeof(uint8_t);
      break;
    case kTfLiteInt64:
      *bytes = sizeof(int64_t);
      break;
    case kTfLiteUInt64:
      *bytes = sizeof(uint64_t);
      break;
    case kTfLiteBool:
      *bytes = sizeof(bool);
      break;
    case kTfLiteComplex64:
      *bytes = sizeof(std::complex<float>);
      break;
    case kTfLiteComplex128:
      *bytes = sizeof(std::complex<double>);
      break;
    case kTfLiteInt16:
      *bytes = sizeof(int16_t);
      break;
    case kTfLiteInt8:
      *bytes = sizeof(int8_t);
      break;
    case kTfLiteFloat16:
      *bytes = sizeof(TfLiteFloat16);
      break;
    case kTfLiteFloat64:
      *bytes = sizeof(double);
      break;
    default:
      if (context) {
        context->ReportError( context, "Type %d is unsupported. Only float16, float32, float64, int8, " "int16, int32, int64, uint8, uint64, bool, complex64 and " "complex128 supported currently.", type);




      }
      return kTfLiteError;
  }
  return kTfLiteOk;
}

TfLiteRegistration CreateUnresolvedCustomOp(const char* custom_op_name) {
  return TfLiteRegistration{nullptr, nullptr, nullptr, &UnresolvedOpInvoke, nullptr, BuiltinOperator_CUSTOM, custom_op_name, 1};






}

bool IsUnresolvedCustomOp(const TfLiteRegistration& registration) {
  return registration.builtin_code == tflite::BuiltinOperator_CUSTOM && registration.invoke == &UnresolvedOpInvoke;
}

std::string GetOpNameByRegistration(const TfLiteRegistration& registration) {
  auto op = registration.builtin_code;
  std::string result = EnumNameBuiltinOperator(static_cast<BuiltinOperator>(op));
  if ((op == kTfLiteBuiltinCustom || op == kTfLiteBuiltinDelegate) && registration.custom_name) {
    result += " " + std::string(registration.custom_name);
  }
  return result;
}

bool IsValidationSubgraph(const char* name) {
  
  return name && std::string(name).find(kValidationSubgraphNamePrefix) == 0;
}
}  
