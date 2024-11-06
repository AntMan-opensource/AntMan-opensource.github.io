




















namespace tflite {
namespace ops {
namespace builtin {
namespace pooling {


enum KernelType {
  kReference, kGenericOptimized, };


enum PoolType {
  kAverage, kMax, kL2, };



struct OpData {
  TfLitePaddingValues padding;
};

void* Init(TfLiteContext* context, const char* buffer, size_t length) {
  
  
  
  return new OpData;
}

void Free(TfLiteContext* context, void* buffer) {
  delete reinterpret_cast<OpData*>(buffer);
}

template <PoolType pool_type> TfLiteStatus GenericPrepare(TfLiteContext* context, TfLiteNode* node) {
  auto* params = reinterpret_cast<TfLitePoolParams*>(node->builtin_data);
  OpData* data = reinterpret_cast<OpData*>(node->user_data);

  TF_LITE_ENSURE_EQ(context, NumInputs(node), 1);
  TF_LITE_ENSURE_EQ(context, NumOutputs(node), 1);
  TfLiteTensor* output;
  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, 0, &output));
  const TfLiteTensor* input;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &input));
  TF_LITE_ENSURE_EQ(context, NumDimensions(input), 4);
  TF_LITE_ENSURE_TYPES_EQ(context, input->type, output->type);

  int batches = input->dims->data[0];
  int height = input->dims->data[1];
  int width = input->dims->data[2];
  int channels_out = input->dims->data[3];

  
  auto padding = params->padding;
  int out_width, out_height;

  
  TF_LITE_ENSURE(context, params->stride_height > 0);
  TF_LITE_ENSURE(context, params->stride_width > 0);

  data->padding = ComputePaddingHeightWidth( params->stride_height, params->stride_width, 1, 1, height, width, params->filter_height, params->filter_width, padding, &out_height, &out_width);



  if (input->type == kTfLiteUInt8 || input->type == kTfLiteInt8) {
    if (pool_type == kAverage || pool_type == kMax) {
      TFLITE_DCHECK_LE(std::abs(input->params.scale - output->params.scale), 1.0e-6);
      TFLITE_DCHECK_EQ(input->params.zero_point, output->params.zero_point);
    }
    if (pool_type == kL2) {
      
      TF_LITE_ENSURE_TYPES_EQ(context, input->type, kTfLiteFloat32);
    }
  }

  TfLiteIntArray* output_size = TfLiteIntArrayCreate(4);
  output_size->data[0] = batches;
  output_size->data[1] = out_height;
  output_size->data[2] = out_width;
  output_size->data[3] = channels_out;
  return context->ResizeTensor(context, output, output_size);
}

template <KernelType kernel_type> void AverageEvalFloat(TfLiteContext* context, TfLiteNode* node, TfLitePoolParams* params, OpData* data, const TfLiteTensor* input, TfLiteTensor* output) {


  float activation_min, activation_max;
  CalculateActivationRange(params->activation, &activation_min, &activation_max);












  if (kernel_type == kReference) {
    TF_LITE_AVERAGE_POOL(reference_ops);
  } else {
    TF_LITE_AVERAGE_POOL(optimized_ops);
  }

}

template <KernelType kernel_type> void AverageEvalQuantizedUint8(TfLiteContext* context, TfLiteNode* node, TfLitePoolParams* params, OpData* data, const TfLiteTensor* input, TfLiteTensor* output) {



  int32_t activation_min;
  int32_t activation_max;
  (void)CalculateActivationRangeQuantized(context, params->activation, output, &activation_min, &activation_max);












  if (kernel_type == kReference) {
    TF_LITE_AVERAGE_POOL(reference_ops);
  } else {
    TF_LITE_AVERAGE_POOL(optimized_ops);
  }

}

template <KernelType kernel_type> void AverageEvalQuantizedInt8(TfLiteContext* context, TfLiteNode* node, TfLitePoolParams* params, OpData* data, const TfLiteTensor* input, TfLiteTensor* output) {


  int32_t activation_min;
  int32_t activation_max;

  (void)CalculateActivationRangeQuantized(context, params->activation, output, &activation_min, &activation_max);












  if (kernel_type == kReference) {
    TF_LITE_AVERAGE_POOL(reference_integer_ops);
  } else {
    TF_LITE_AVERAGE_POOL(optimized_integer_ops);
  }

}

template <KernelType kernel_type> void AverageEvalQuantizedInt16(TfLiteContext* context, TfLiteNode* node, TfLitePoolParams* params, OpData* data, const TfLiteTensor* input, TfLiteTensor* output) {



  int32_t activation_min;
  int32_t activation_max;
  CalculateActivationRangeQuantized(context, params->activation, output, &activation_min, &activation_max);












  TF_LITE_AVERAGE_POOL(reference_integer_ops);

}

template <KernelType kernel_type> void MaxEvalFloat(TfLiteContext* context, TfLiteNode* node, TfLitePoolParams* params, OpData* data, const TfLiteTensor* input, TfLiteTensor* output) {


  float activation_min, activation_max;
  CalculateActivationRange(params->activation, &activation_min, &activation_max);











  if (kernel_type == kReference) {
    TF_LITE_MAX_POOL(reference_ops);
  } else {
    TF_LITE_MAX_POOL(optimized_ops);
  }

}

template <KernelType kernel_type> void MaxEvalQuantizedUInt8(TfLiteContext* context, TfLiteNode* node, TfLitePoolParams* params, OpData* data, const TfLiteTensor* input, TfLiteTensor* output) {


  int32_t activation_min;
  int32_t activation_max;
  (void)CalculateActivationRangeQuantized(context, params->activation, output, &activation_min, &activation_max);












  if (kernel_type == kReference) {
    TF_LITE_MAX_POOL(reference_ops);
  } else {
    TF_LITE_MAX_POOL(optimized_ops);
  }

}

template <KernelType kernel_type> void MaxEvalQuantizedInt8(TfLiteContext* context, TfLiteNode* node, TfLitePoolParams* params, OpData* data, const TfLiteTensor* input, TfLiteTensor* output) {


  int32_t activation_min;
  int32_t activation_max;
  (void)CalculateActivationRangeQuantized(context, params->activation, output, &activation_min, &activation_max);












  if (kernel_type == kReference) {
    TF_LITE_MAX_POOL(reference_integer_ops);
  } else {
    TF_LITE_MAX_POOL(optimized_integer_ops);
  }

}

template <KernelType kernel_type> void MaxEvalQuantizedInt16(TfLiteContext* context, TfLiteNode* node, TfLitePoolParams* params, OpData* data, const TfLiteTensor* input, TfLiteTensor* output) {


  int32_t activation_min;
  int32_t activation_max;
  CalculateActivationRangeQuantized(context, params->activation, output, &activation_min, &activation_max);












  TF_LITE_MAX_POOL(reference_integer_ops);

}

template <KernelType kernel_type> void L2EvalFloat(TfLiteContext* context, TfLiteNode* node, TfLitePoolParams* params, OpData* data, const TfLiteTensor* input, TfLiteTensor* output) {


  float activation_min, activation_max;
  CalculateActivationRange(params->activation, &activation_min, &activation_max);











  if (kernel_type == kReference) {
    TF_LITE_L2_POOL(reference_ops);
  } else {
    TF_LITE_L2_POOL(optimized_ops);
  }

}



template <KernelType kernel_type> TfLiteStatus AverageEval(TfLiteContext* context, TfLiteNode* node) {
  auto* params = reinterpret_cast<TfLitePoolParams*>(node->builtin_data);
  OpData* data = reinterpret_cast<OpData*>(node->user_data);

  TfLiteTensor* output;
  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, 0, &output));
  const TfLiteTensor* input;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &input));
  switch (input->type) {  
    case kTfLiteFloat32:
      AverageEvalFloat<kernel_type>(context, node, params, data, input, output);
      break;
    case kTfLiteUInt8:
      AverageEvalQuantizedUint8<kernel_type>(context, node, params, data, input, output);
      break;
    case kTfLiteInt8:
      AverageEvalQuantizedInt8<kernel_type>(context, node, params, data, input, output);
      break;
    case kTfLiteInt16:
      AverageEvalQuantizedInt16<kernel_type>(context, node, params, data, input, output);
      break;
    default:
      TF_LITE_KERNEL_LOG(context, "Type %s not currently supported.", TfLiteTypeGetName(input->type));
      return kTfLiteError;
  }
  return kTfLiteOk;
}

template <KernelType kernel_type> TfLiteStatus MaxEval(TfLiteContext* context, TfLiteNode* node) {
  auto* params = reinterpret_cast<TfLitePoolParams*>(node->builtin_data);
  OpData* data = reinterpret_cast<OpData*>(node->user_data);

  TfLiteTensor* output;
  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, 0, &output));
  const TfLiteTensor* input;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &input));
  switch (input->type) {  
    case kTfLiteFloat32:
      MaxEvalFloat<kernel_type>(context, node, params, data, input, output);
      break;
    case kTfLiteUInt8:
      MaxEvalQuantizedUInt8<kernel_type>(context, node, params, data, input, output);
      break;
    case kTfLiteInt8:
      MaxEvalQuantizedInt8<kernel_type>(context, node, params, data, input, output);
      break;
    case kTfLiteInt16:
      MaxEvalQuantizedInt16<kernel_type>(context, node, params, data, input, output);
      break;
    default:
      TF_LITE_KERNEL_LOG(context, "Type %s not currently supported.", TfLiteTypeGetName(input->type));
      return kTfLiteError;
  }
  return kTfLiteOk;
}

template <KernelType kernel_type> TfLiteStatus L2Eval(TfLiteContext* context, TfLiteNode* node) {
  auto* params = reinterpret_cast<TfLitePoolParams*>(node->builtin_data);
  OpData* data = reinterpret_cast<OpData*>(node->user_data);

  TfLiteTensor* output;
  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, 0, &output));
  const TfLiteTensor* input;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &input));
  switch (input->type) {  
    case kTfLiteFloat32:
      L2EvalFloat<kernel_type>(context, node, params, data, input, output);
      break;
    case kTfLiteUInt8:
    
    
    default:
      context->ReportError(context, "Type %d not currently supported.", input->type);
      return kTfLiteError;
  }
  return kTfLiteOk;
}

}  

TfLiteRegistration* Register_AVERAGE_POOL_REF() {
  static TfLiteRegistration r = {pooling::Init, pooling::Free, pooling::GenericPrepare<pooling::kAverage>, pooling::AverageEval<pooling::kReference>};

  return &r;
}

TfLiteRegistration* Register_MAX_POOL_REF() {
  static TfLiteRegistration r = {pooling::Init, pooling::Free, pooling::GenericPrepare<pooling::kMax>, pooling::MaxEval<pooling::kReference>};

  return &r;
}

TfLiteRegistration* Register_L2_POOL_REF() {
  static TfLiteRegistration r = {pooling::Init, pooling::Free, pooling::GenericPrepare<pooling::kL2>, pooling::L2Eval<pooling::kReference>};

  return &r;
}

TfLiteRegistration* Register_AVERAGE_POOL_GENERIC_OPT() {
  static TfLiteRegistration r = {
      pooling::Init, pooling::Free, pooling::GenericPrepare<pooling::kAverage>, pooling::AverageEval<pooling::kGenericOptimized>};
  return &r;
}

TfLiteRegistration* Register_MAX_POOL_GENERIC_OPT() {
  static TfLiteRegistration r = {pooling::Init, pooling::Free, pooling::GenericPrepare<pooling::kMax>, pooling::MaxEval<pooling::kGenericOptimized>};

  return &r;
}

TfLiteRegistration* Register_L2_POOL_GENERIC_OPT() {
  static TfLiteRegistration r = {pooling::Init, pooling::Free, pooling::GenericPrepare<pooling::kL2>, pooling::L2Eval<pooling::kGenericOptimized>};

  return &r;
}

TfLiteRegistration* Register_AVERAGE_POOL_2D() {
  return Register_AVERAGE_POOL_GENERIC_OPT();
}

TfLiteRegistration* Register_MAX_POOL_2D() {
  return Register_MAX_POOL_GENERIC_OPT();
}

TfLiteRegistration* Register_L2_POOL_2D() {
  return Register_L2_POOL_GENERIC_OPT();
}

}  
}  
}  
