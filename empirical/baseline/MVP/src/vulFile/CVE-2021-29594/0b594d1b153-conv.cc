



































namespace tflite {
namespace ops {
namespace builtin {
namespace conv {


enum KernelType {
  kReference, kGenericOptimized,   kMultithreadOptimized,     kCblasOptimized, };










const int kTensorNotAllocated = -1;

static constexpr size_t kMaxIm2colBufferSizeMobile = 1024 * 1024 * 1024;  

struct OpData {
  
  
  int im2col_id = kTensorNotAllocated;
  int hwcn_weights_id = kTensorNotAllocated;
  int input_quantized_id = kTensorNotAllocated;
  int scaling_factors_id = kTensorNotAllocated;
  int input_offset_id = kTensorNotAllocated;
  int accum_scratch_id = kTensorNotAllocated;
  
  int row_sums_id = kTensorNotAllocated;

  TfLitePaddingValues padding;
  
  
  int32_t output_multiplier;
  int output_shift;

  
  std::vector<int32_t> per_channel_output_multiplier;
  std::vector<int> per_channel_output_shift;

  
  
  int32_t output_activation_min;
  int32_t output_activation_max;
  
  
  int32_t im2col_index;
  int32_t hwcn_weights_index;
  int32_t input_quantized_index;
  int32_t scaling_factors_index;
  int32_t accum_scratch_index;
  int32_t input_offset_index;
  int32_t row_sums_index;

  bool need_hwcn_weights = false;
  bool have_weights_been_transposed = false;
  bool need_im2col = false;
  
  
  
  bool im2col_oversized = false;

  bool supports_multithreaded_kernel = false;
  bool is_hybrid_per_channel = false;
  bool compute_hybrid_row_sums = true;
};

inline PaddingType RuntimePaddingType(TfLitePadding padding) {
  switch (padding) {
    case TfLitePadding::kTfLitePaddingSame:
      return PaddingType::kSame;
    case TfLitePadding::kTfLitePaddingValid:
      return PaddingType::kValid;
    case TfLitePadding::kTfLitePaddingUnknown:
    default:
      return PaddingType::kNone;
  }
}

void* Init(TfLiteContext* context, const char* buffer, size_t length) {
  
  
  
  auto* data = new OpData;

  eigen_support::IncrementUsageCounter(context);

  return data;
}

void Free(TfLiteContext* context, void* buffer) {

  eigen_support::DecrementUsageCounter(context);

  delete reinterpret_cast<OpData*>(buffer);
}




void TransposeFloatTensor(const TfLiteTensor* input, TfLiteTensor* output) {
  const int rows = output->dims->data[1];
  const int cols = output->dims->data[0];
  const float* input_data = GetTensorData<float>(input);
  float* output_data = GetTensorData<float>(output);
  for (int i = 0; i < rows; ++i) {
    for (int j = 0; j < cols; ++j) {
      const float in_value = input_data[i * cols + j];
      output_data[j * rows + i] = in_value;
    }
  }
}




bool IsIm2ColRequired(const TfLiteTensor* input, TfLiteConvParams* params, const TfLiteTensor* filter, OpData* data, bool is_hybrid, KernelType kernel_type) {

  
  if (data->need_hwcn_weights) return false;

  
  const bool need_dilated_im2col = params->dilation_width_factor != 1 || params->dilation_height_factor != 1;
  const bool need_non_dilated_im2col = params->stride_width != 1 || params->stride_height != 1 || filter->dims->data[2] != 1 || filter->dims->data[1] != 1;


  const bool need_im2col = need_dilated_im2col || need_non_dilated_im2col;

  
  if (!need_im2col) return false;

  
  const bool is_hybrid_non_dilated = is_hybrid && need_non_dilated_im2col;
  const bool is_quantized = input->type == kTfLiteUInt8 || input->type == kTfLiteInt8;

  switch (kernel_type) {
    case kReference:
      if (is_hybrid) {
        return true;
      } else {
        return false;
      }
    case kGenericOptimized:
    case kCblasOptimized:
      if (is_hybrid && !need_non_dilated_im2col) {
        return false;
      } else {
        return true;
      }
    case kMultithreadOptimized:
      if (is_hybrid_non_dilated || is_quantized || !data->supports_multithreaded_kernel) {
        return true;
      } else {
        return false;
      }
    default:
      return false;
  }
}




static TfLiteStatus AllocateTemporaryTensorsIfRequired( TfLiteContext* context, TfLiteNode* node, bool is_hybrid, bool is_per_channel, KernelType kernel_type, size_t im2col_bytes) {

  auto* params = reinterpret_cast<TfLiteConvParams*>(node->builtin_data);
  OpData* data = reinterpret_cast<OpData*>(node->user_data);

  TF_LITE_ENSURE(context, node->inputs->size >= 2);
  const TfLiteTensor* input;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &input));
  const TfLiteTensor* filter;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 1, &filter));

  
  
  
  
  
  
  
  
  
  data->need_hwcn_weights = input->type == kTfLiteFloat32 && data->supports_multithreaded_kernel;

  
  
  
  data->need_im2col = IsIm2ColRequired(input, params, filter, data, is_hybrid, kernel_type);

  
  
  
  
  
  
  
  if (IsMobilePlatform() && !(is_hybrid && !is_per_channel) && data->need_im2col && im2col_bytes >= kMaxIm2colBufferSizeMobile) {
    data->need_im2col = false;
    data->im2col_oversized = true;
  }
  int temporaries_count = 0;
  if (data->need_im2col) {
    data->im2col_index = temporaries_count;
    if (data->im2col_id == kTensorNotAllocated) {
      context->AddTensors(context, 1, &data->im2col_id);
    }
    ++temporaries_count;
  }
  if (data->need_hwcn_weights) {
    data->hwcn_weights_index = temporaries_count;
    if (data->hwcn_weights_id == kTensorNotAllocated) {
      context->AddTensors(context, 1, &data->hwcn_weights_id);
    }
    ++temporaries_count;
  }

  if (is_hybrid) {
    
    data->input_quantized_index = temporaries_count;
    if (data->input_quantized_id == kTensorNotAllocated) {
      TF_LITE_ENSURE_OK( context, context->AddTensors(context, 1, &data->input_quantized_id));
    }
    ++temporaries_count;

    
    
    data->scaling_factors_index = temporaries_count;
    if (data->scaling_factors_id == kTensorNotAllocated) {
      TF_LITE_ENSURE_OK( context, context->AddTensors(context, 1, &data->scaling_factors_id));
    }
    ++temporaries_count;

    
    data->accum_scratch_index = temporaries_count;
    if (data->accum_scratch_id == kTensorNotAllocated) {
      TF_LITE_ENSURE_OK( context, context->AddTensors(context, 1, &data->accum_scratch_id));
    }
    ++temporaries_count;
    if (is_per_channel) {
      data->input_offset_index = temporaries_count;
      if (data->input_offset_id == kTensorNotAllocated) {
        TF_LITE_ENSURE_OK( context, context->AddTensors(context, 1, &data->input_offset_id));
      }
      ++temporaries_count;

      data->row_sums_index = temporaries_count;
      if (data->row_sums_id == kTensorNotAllocated) {
        TF_LITE_ENSURE_OK(context, context->AddTensors(context, 1, &data->row_sums_id));
      }
      ++temporaries_count;
    }
  }

  TfLiteIntArrayFree(node->temporaries);
  node->temporaries = TfLiteIntArrayCreate(temporaries_count);

  return kTfLiteOk;
}

TfLiteStatus Prepare(KernelType kernel_type, TfLiteContext* context, TfLiteNode* node) {
  auto* params = reinterpret_cast<TfLiteConvParams*>(node->builtin_data);
  OpData* data = reinterpret_cast<OpData*>(node->user_data);

  bool has_bias = node->inputs->size == 3;
  
  TF_LITE_ENSURE(context, has_bias || node->inputs->size == 2);
  TF_LITE_ENSURE_EQ(context, node->outputs->size, 1);
  TfLiteTensor* output;
  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, 0, &output));
  const TfLiteTensor* input;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &input));
  const TfLiteTensor* filter;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 1, &filter));

  
  TF_LITE_ENSURE_EQ(context, input->dims->size, 4);
  TF_LITE_ENSURE_EQ(context, filter->dims->size, 4);
  
  TF_LITE_ENSURE_EQ(context, input->dims->data[3], filter->dims->data[3]);

  
  TfLiteType input_type = input->type;
  TF_LITE_ENSURE(context, input_type == kTfLiteFloat32 || input_type == kTfLiteUInt8 || input_type == kTfLiteInt8 || input_type == kTfLiteInt16);

  TF_LITE_ENSURE_TYPES_EQ(context, output->type, input_type);

  if (input_type == kTfLiteInt16) {
    TF_LITE_ENSURE_EQ(context, input->params.zero_point, 0);
    TF_LITE_ENSURE_EQ(context, output->params.zero_point, 0);
  }

  const TfLiteTensor* bias = nullptr;

  
  
  TF_LITE_ENSURE(context, has_bias);

  if (has_bias) {
    TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 2, &bias));
    if (input_type == kTfLiteUInt8 || input_type == kTfLiteInt8) {
      TF_LITE_ENSURE_TYPES_EQ(context, bias->type, kTfLiteInt32);
      TF_LITE_ENSURE_EQ(context, bias->params.zero_point, 0);
    } else if (input_type == kTfLiteInt16) {
      TF_LITE_ENSURE_TYPES_EQ(context, bias->type, kTfLiteInt64);
      TF_LITE_ENSURE_EQ(context, bias->params.zero_point, 0);
    } else {
      TF_LITE_ENSURE_TYPES_EQ(context, bias->type, input_type);
    }
    TF_LITE_ENSURE_EQ(context, NumElements(bias), SizeOfDimension(filter, 0));
  }

  const bool is_hybrid = (input->type == kTfLiteFloat32 && (filter->type == kTfLiteUInt8 || filter->type == kTfLiteInt8));


  if (is_hybrid && filter->type == kTfLiteInt8 && filter->quantization.type == kTfLiteAffineQuantization && filter->quantization.params && reinterpret_cast<TfLiteAffineQuantization*>(filter->quantization.params)


          ->scale && reinterpret_cast<TfLiteAffineQuantization*>(filter->quantization.params)
              ->scale->size > 1) {
    const auto* affine_quantization = reinterpret_cast<TfLiteAffineQuantization*>( filter->quantization.params);

    const float scale = affine_quantization->scale->data[0];
    for (int i = 1; i < affine_quantization->scale->size; i++) {
      if (affine_quantization->scale->data[i] != scale) {
        data->is_hybrid_per_channel = true;
        break;
      }
    }
  }

  
  
  data->supports_multithreaded_kernel = (kernel_type == kMultithreadOptimized) && (context->recommended_num_threads != 1) && !is_hybrid && (params->dilation_width_factor == 1) && (params->dilation_height_factor == 1) && (filter->allocation_type != kTfLiteArenaRw) && !IsDynamicTensor(filter);





  int channels_in = filter->dims->data[3];
  int channels_out = filter->dims->data[0];
  int width = input->dims->data[2];
  int height = input->dims->data[1];
  int filter_width = filter->dims->data[2];
  int filter_height = filter->dims->data[1];
  int batches = input->dims->data[0];

  
  auto padding = params->padding;
  int out_width, out_height;
  data->padding = ComputePaddingHeightWidth( params->stride_height, params->stride_width, params->dilation_height_factor, params->dilation_width_factor, height, width, filter_height, filter_width, padding, &out_height, &out_width);



  size_t im2col_type_size;
  TF_LITE_ENSURE_STATUS(GetSizeOfType(context, input->type, &im2col_type_size));
  const size_t im2col_bytes = batches * out_height * out_width * channels_in * filter_height * filter_width * im2col_type_size;
  TF_LITE_ENSURE_STATUS(AllocateTemporaryTensorsIfRequired( context, node, is_hybrid, data->is_hybrid_per_channel, kernel_type, im2col_bytes));


  TF_LITE_ENSURE(context, has_bias);

  
  
  
  if (input_type != kTfLiteFloat32) {
    TF_LITE_ENSURE_EQ(context, filter->quantization.type, kTfLiteAffineQuantization);
    const auto* affine_quantization = reinterpret_cast<TfLiteAffineQuantization*>( filter->quantization.params);

    TF_LITE_ENSURE(context, affine_quantization);
    TF_LITE_ENSURE(context, affine_quantization->scale);
    TF_LITE_ENSURE(context, (affine_quantization->scale->size == 1 || affine_quantization->scale->size == channels_out));

    data->per_channel_output_multiplier.resize(channels_out);
    data->per_channel_output_shift.resize(channels_out);
    TF_LITE_ENSURE_STATUS(tflite::PopulateConvolutionQuantizationParams( context, input, filter, bias, output, params->activation, &data->output_multiplier, &data->output_shift, &data->output_activation_min, &data->output_activation_max, data->per_channel_output_multiplier.data(), data->per_channel_output_shift.data(), channels_out));




  }

  TfLiteIntArray* output_size = TfLiteIntArrayCreate(4);
  output_size->data[0] = batches;
  output_size->data[1] = out_height;
  output_size->data[2] = out_width;
  output_size->data[3] = channels_out;
  auto output_status = context->ResizeTensor(context, output, output_size);

  if (output_status != kTfLiteOk) return output_status;

  if (data->need_im2col) {
    node->temporaries->data[data->im2col_index] = data->im2col_id;

    TfLiteIntArray* im2col_size = TfLiteIntArrayCreate(4);

    int input_depth = input->dims->data[3];
    im2col_size->data[0] = output_size->data[0];
    im2col_size->data[1] = output_size->data[1];
    im2col_size->data[2] = output_size->data[2];
    im2col_size->data[3] = input_depth * filter_height * filter_width;

    TfLiteTensor* im2col = &context->tensors[node->temporaries->data[data->im2col_index]];
    im2col->type = input->type;
    if (is_hybrid) {
      im2col->type = filter->type;
    }
    im2col->allocation_type = kTfLiteArenaRw;
    auto im2col_status = context->ResizeTensor(context, im2col, im2col_size);
    if (im2col_status != kTfLiteOk) return im2col_status;
  }

  if (data->need_hwcn_weights) {
    node->temporaries->data[data->hwcn_weights_index] = data->hwcn_weights_id;
    TfLiteIntArray* hwcn_weights_size = TfLiteIntArrayCreate(2);

    
    
    
    
    int input_depth = input->dims->data[3];
    hwcn_weights_size->data[0] = (filter_height * filter_width * input_depth);
    hwcn_weights_size->data[1] = channels_out;

    TfLiteTensor* hwcn_weights = &context->tensors[node->temporaries->data[data->hwcn_weights_index]];
    hwcn_weights->type = input_type;
    hwcn_weights->allocation_type = kTfLiteArenaRwPersistent;

    auto hwcn_weights_status = context->ResizeTensor(context, hwcn_weights, hwcn_weights_size);
    if (hwcn_weights_status != kTfLiteOk) return hwcn_weights_status;

    
    
    data->have_weights_been_transposed = false;
  }

  if (is_hybrid) {
    node->temporaries->data[data->input_quantized_index] = data->input_quantized_id;
    TfLiteTensor* input_quantized;
    TF_LITE_ENSURE_OK( context, GetTemporarySafe(context, node, data->input_quantized_index, &input_quantized));

    input_quantized->type = kTfLiteInt8;
    input_quantized->allocation_type = kTfLiteArenaRw;
    if (!TfLiteIntArrayEqual(input_quantized->dims, input->dims)) {
      TfLiteIntArray* input_quantized_size = TfLiteIntArrayCopy(input->dims);
      TF_LITE_ENSURE_OK(context, context->ResizeTensor(context, input_quantized, input_quantized_size));
    }

    node->temporaries->data[data->scaling_factors_index] = data->scaling_factors_id;
    TfLiteTensor* scaling_factors;
    TF_LITE_ENSURE_OK( context, GetTemporarySafe(context, node, data->scaling_factors_index, &scaling_factors));

    scaling_factors->type = kTfLiteFloat32;
    scaling_factors->allocation_type = kTfLiteArenaRw;
    
    
    
    const int height = NumElements(input) / channels_in;
    int scaling_dims[1] = {height};
    if (!TfLiteIntArrayEqualsArray(scaling_factors->dims, 1, scaling_dims)) {
      TfLiteIntArray* scaling_factors_size = TfLiteIntArrayCreate(1);
      scaling_factors_size->data[0] = height;
      TF_LITE_ENSURE_OK(context, context->ResizeTensor(context, scaling_factors, scaling_factors_size));
    }

    node->temporaries->data[data->accum_scratch_index] = data->accum_scratch_id;
    TfLiteTensor* accum_scratch;
    TF_LITE_ENSURE_OK(context, GetTemporarySafe(context, node, data->accum_scratch_index, &accum_scratch));

    accum_scratch->type = kTfLiteInt32;
    accum_scratch->allocation_type = kTfLiteArenaRw;
    const int scratch_width = batches * out_height * out_width;
    int accum_scratch_dims[2] = {channels_out, scratch_width};
    if (!TfLiteIntArrayEqualsArray(accum_scratch->dims, 2, accum_scratch_dims)) {
      TfLiteIntArray* accum_scratch_size = TfLiteIntArrayCreate(2);
      accum_scratch_size->data[0] = channels_out;
      accum_scratch_size->data[1] = scratch_width;
      TF_LITE_ENSURE_OK(context, context->ResizeTensor(context, accum_scratch, accum_scratch_size));
    }

    if (data->is_hybrid_per_channel) {
      const auto* affine_quantization = reinterpret_cast<TfLiteAffineQuantization*>( filter->quantization.params);

      TF_LITE_ENSURE_EQ( context, affine_quantization->scale->size, filter->dims->data[affine_quantization->quantized_dimension]);

      node->temporaries->data[data->input_offset_index] = data->input_offset_id;
      TfLiteTensor* input_offsets;
      TF_LITE_ENSURE_OK( context, GetTemporarySafe(context, node, data->input_offset_index, &input_offsets));

      input_offsets->type = kTfLiteInt32;
      input_offsets->allocation_type = kTfLiteArenaRw;
      
      const int height = NumElements(input) / channels_in;
      const int input_offset_dims[1] = {height};
      if (!TfLiteIntArrayEqualsArray(input_offsets->dims, 1, input_offset_dims)) {
        TfLiteIntArray* input_offsets_size = TfLiteIntArrayCreate(1);
        input_offsets_size->data[0] = input_offset_dims[0];
        TF_LITE_ENSURE_OK(context, context->ResizeTensor(context, input_offsets, input_offsets_size));
      }
      node->temporaries->data[data->row_sums_index] = data->row_sums_id;
      TfLiteTensor* row_sums;
      TF_LITE_ENSURE_OK( context, GetTemporarySafe(context, node, data->row_sums_index, &row_sums));

      row_sums->type = kTfLiteInt32;
      row_sums->allocation_type = kTfLiteArenaRwPersistent;
      
      const int row_sums_dims[1] = {channels_out};
      if (!TfLiteIntArrayEqualsArray(row_sums->dims, 1, row_sums_dims)) {
        TfLiteIntArray* row_sums_size = TfLiteIntArrayCreate(1);
        row_sums_size->data[0] = row_sums_dims[0];
        TF_LITE_ENSURE_OK( context, context->ResizeTensor(context, row_sums, row_sums_size));
      }
    }
  }
  return kTfLiteOk;
}

template <KernelType kernel_type> TfLiteStatus Prepare(TfLiteContext* context, TfLiteNode* node) {
  return Prepare(kernel_type, context, node);
}

template <KernelType kernel_type> void EvalQuantized(TfLiteContext* context, TfLiteNode* node, TfLiteConvParams* params, OpData* data, const TfLiteTensor* input, const TfLiteTensor* filter, const TfLiteTensor* bias, TfLiteTensor* im2col, TfLiteTensor* output) {




  auto input_offset = -input->params.zero_point;
  auto filter_offset = -filter->params.zero_point;
  auto output_offset = output->params.zero_point;

  KernelType effective_kernel_type;
  if ((kernel_type == kMultithreadOptimized || kernel_type == kCblasOptimized) && (params->dilation_width_factor != 1 || params->dilation_height_factor != 1)) {


    
    
    effective_kernel_type = kGenericOptimized;
  } else {
    effective_kernel_type = kernel_type;
  }

  
  
  
  if (data->im2col_oversized) {
    effective_kernel_type = kReference;
  }

  ConvParams op_params;
  op_params.padding_type = PaddingType::kSame;
  op_params.padding_values.width = data->padding.width;
  op_params.padding_values.height = data->padding.height;
  op_params.dilation_width_factor = params->dilation_width_factor;
  op_params.dilation_height_factor = params->dilation_height_factor;
  op_params.stride_width = params->stride_width;
  op_params.stride_height = params->stride_height;
  op_params.input_offset = input_offset;
  op_params.weights_offset = filter_offset;
  op_params.output_offset = output_offset;
  op_params.output_multiplier = data->output_multiplier;
  op_params.output_shift = -data->output_shift;
  op_params.quantized_activation_min = data->output_activation_min;
  op_params.quantized_activation_max = data->output_activation_max;
  switch (effective_kernel_type) {
    case kReference: {
      reference_ops::Conv( op_params, GetTensorShape(input), GetTensorData<uint8_t>(input), GetTensorShape(filter), GetTensorData<uint8_t>(filter), GetTensorShape(bias), GetTensorData<int32_t>(bias), GetTensorShape(output), GetTensorData<uint8_t>(output), GetTensorShape(im2col), GetTensorData<uint8_t>(im2col), nullptr);





      break;
    }
    case kGenericOptimized:
    case kMultithreadOptimized:
    case kCblasOptimized: {
      
      optimized_ops::Conv( op_params, GetTensorShape(input), GetTensorData<uint8_t>(input), GetTensorShape(filter), GetTensorData<uint8_t>(filter), GetTensorShape(bias), GetTensorData<int32_t>(bias), GetTensorShape(output), GetTensorData<uint8_t>(output), GetTensorShape(im2col), GetTensorData<uint8_t>(im2col), CpuBackendContext::GetFromContext(context));





      break;
    }
  }
}

template <KernelType kernel_type> void EvalQuantizedPerChannel(TfLiteContext* context, TfLiteNode* node, TfLiteConvParams* params, OpData* data, const TfLiteTensor* input, const TfLiteTensor* filter, const TfLiteTensor* bias, TfLiteTensor* output, TfLiteTensor* im2col) {





  ConvParams op_params;
  op_params.input_offset = -input->params.zero_point;
  op_params.output_offset = output->params.zero_point;
  op_params.stride_height = params->stride_height;
  op_params.stride_width = params->stride_width;
  op_params.dilation_height_factor = params->dilation_height_factor;
  op_params.dilation_width_factor = params->dilation_width_factor;
  op_params.padding_values.height = data->padding.height;
  op_params.padding_values.width = data->padding.width;
  op_params.quantized_activation_min = data->output_activation_min;
  op_params.quantized_activation_max = data->output_activation_max;

  KernelType effective_kernel_type = kernel_type;
  
  
  
  if (data->im2col_oversized) {
    effective_kernel_type = kReference;
  }

  switch (effective_kernel_type) {
    case kReference: {
      reference_integer_ops::ConvPerChannel( op_params, data->per_channel_output_multiplier.data(), data->per_channel_output_shift.data(), GetTensorShape(input), GetTensorData<int8>(input), GetTensorShape(filter), GetTensorData<int8>(filter), GetTensorShape(bias), GetTensorData<int32>(bias), GetTensorShape(output), GetTensorData<int8>(output));





      break;
    }
    case kGenericOptimized:
    case kMultithreadOptimized:
    case kCblasOptimized: {
      optimized_integer_ops::ConvPerChannel( op_params, data->per_channel_output_multiplier.data(), data->per_channel_output_shift.data(), GetTensorShape(input), GetTensorData<int8>(input), GetTensorShape(filter), GetTensorData<int8>(filter), GetTensorShape(bias), GetTensorData<int32>(bias), GetTensorShape(output), GetTensorData<int8>(output), GetTensorShape(im2col), GetTensorData<int8>(im2col), CpuBackendContext::GetFromContext(context));







      break;
    }
  }
}

template <KernelType kernel_type> void EvalQuantizedPerChannel16x8(TfLiteContext* context, TfLiteNode* node, TfLiteConvParams* params, OpData* data, const TfLiteTensor* input, const TfLiteTensor* filter, const TfLiteTensor* bias, TfLiteTensor* output, TfLiteTensor* im2col) {





  ConvParams op_params;
  op_params.input_offset = -input->params.zero_point;
  op_params.output_offset = output->params.zero_point;
  op_params.stride_height = params->stride_height;
  op_params.stride_width = params->stride_width;
  op_params.dilation_height_factor = params->dilation_height_factor;
  op_params.dilation_width_factor = params->dilation_width_factor;
  op_params.padding_values.height = data->padding.height;
  op_params.padding_values.width = data->padding.width;
  op_params.quantized_activation_min = data->output_activation_min;
  op_params.quantized_activation_max = data->output_activation_max;

  switch (kernel_type) {
    case kGenericOptimized:
    case kMultithreadOptimized:
    case kCblasOptimized:
    case kReference: {
      reference_integer_ops::ConvPerChannel( op_params, data->per_channel_output_multiplier.data(), data->per_channel_output_shift.data(), GetTensorShape(input), GetTensorData<int16>(input), GetTensorShape(filter), GetTensorData<int8>(filter), GetTensorShape(bias), GetTensorData<std::int64_t>(bias), GetTensorShape(output), GetTensorData<int16>(output));





      break;
    }
  }
}

template <KernelType kernel_type> void EvalFloat(TfLiteContext* context, TfLiteNode* node, TfLiteConvParams* params, OpData* data, const TfLiteTensor* input, const TfLiteTensor* filter, const TfLiteTensor* bias, TfLiteTensor* im2col, TfLiteTensor* hwcn_weights, TfLiteTensor* output) {




  float output_activation_min, output_activation_max;
  CalculateActivationRange(params->activation, &output_activation_min, &output_activation_max);
  KernelType effective_kernel_type = kernel_type;
  
  if ((kernel_type == kMultithreadOptimized) && !data->supports_multithreaded_kernel) {
    effective_kernel_type = kGenericOptimized;
  }

  
  
  
  
  
  
  if (data->im2col_oversized) {
    effective_kernel_type = kReference;

    
    
    
    
    if (data->supports_multithreaded_kernel) {
      effective_kernel_type = kMultithreadOptimized;
    }

  }

  ConvParams op_params;
  op_params.padding_type = RuntimePaddingType(params->padding);
  op_params.padding_values.width = data->padding.width;
  op_params.padding_values.height = data->padding.height;
  op_params.stride_width = params->stride_width;
  op_params.stride_height = params->stride_height;
  op_params.dilation_width_factor = params->dilation_width_factor;
  op_params.dilation_height_factor = params->dilation_height_factor;
  op_params.float_activation_min = output_activation_min;
  op_params.float_activation_max = output_activation_max;
  switch (effective_kernel_type) {
    case kReference: {
      reference_ops::Conv(op_params, GetTensorShape(input), GetTensorData<float>(input), GetTensorShape(filter), GetTensorData<float>(filter), GetTensorShape(bias), GetTensorData<float>(bias), GetTensorShape(output), GetTensorData<float>(output), GetTensorShape(im2col), GetTensorData<float>(im2col));




      break;
    }
    case kCblasOptimized:
    case kGenericOptimized: {
      optimized_ops::Conv(op_params, GetTensorShape(input), GetTensorData<float>(input), GetTensorShape(filter), GetTensorData<float>(filter), GetTensorShape(bias), GetTensorData<float>(bias), GetTensorShape(output), GetTensorData<float>(output), GetTensorShape(im2col), GetTensorData<float>(im2col), CpuBackendContext::GetFromContext(context));





      break;
    }
    case kMultithreadOptimized: {

      const float* filter_data;
      if (data->need_hwcn_weights) {
        filter_data = GetTensorData<float>(hwcn_weights);
      } else {
        filter_data = GetTensorData<float>(filter);
      }
      multithreaded_ops::Conv( *eigen_support::GetThreadPoolDevice(context), op_params, GetTensorShape(input), GetTensorData<float>(input), GetTensorShape(filter), filter_data, GetTensorShape(bias), GetTensorData<float>(bias), GetTensorShape(output), GetTensorData<float>(output), GetTensorShape(im2col), GetTensorData<float>(im2col));





      break;

      
      
      
      TFLITE_DCHECK(false);

    }
  }
}

template <KernelType kernel_type> TfLiteStatus EvalHybridPerChannel(TfLiteContext* context, TfLiteNode* node, TfLiteConvParams* params, OpData* data, const TfLiteTensor* input, const TfLiteTensor* filter, const TfLiteTensor* bias, TfLiteTensor* im2col, TfLiteTensor* output) {





  float output_activation_min, output_activation_max;
  CalculateActivationRange(params->activation, &output_activation_min, &output_activation_max);

  const int input_size = NumElements(input) / SizeOfDimension(input, 0);
  const int batch_size = SizeOfDimension(input, 0);
  TfLiteTensor* quantized_input_tensor;
  TF_LITE_ENSURE_OK(context, GetTemporarySafe(context, node, data->input_quantized_index, &quantized_input_tensor));

  int8_t* quantized_input_ptr_batch = GetTensorData<int8_t>(quantized_input_tensor);
  TfLiteTensor* scaling_factors_tensor;
  TF_LITE_ENSURE_OK(context, GetTemporarySafe(context, node, data->scaling_factors_index, &scaling_factors_tensor));

  float* scaling_factors_ptr = GetTensorData<float>(scaling_factors_tensor);
  TfLiteTensor* input_offset_tensor;
  TF_LITE_ENSURE_OK(context, GetTemporarySafe(context, node, data->input_offset_index, &input_offset_tensor));

  int32_t* input_offset_ptr = GetTensorData<int32_t>(input_offset_tensor);

  for (int b = 0; b < batch_size; ++b) {
    const int offset = b * input_size;
    tensor_utils::AsymmetricQuantizeFloats( GetTensorData<float>(input) + offset, input_size, quantized_input_ptr_batch + offset, &scaling_factors_ptr[b], &input_offset_ptr[b]);


  }

  int8_t* im2col_ptr = nullptr;
  int8_t* filter_ptr = nullptr;
  if (im2col != nullptr) {
    im2col_ptr = im2col->data.int8;
  }
  filter_ptr = filter->data.int8;
  const auto* affine_quantization = reinterpret_cast<TfLiteAffineQuantization*>(filter->quantization.params);

  KernelType effective_kernel_type = kernel_type;
  
  
  
  if (data->im2col_oversized) {
    effective_kernel_type = kReference;
  }

  ConvParams op_params;
  op_params.padding_type = PaddingType::kSame;
  op_params.padding_values.width = data->padding.width;
  op_params.padding_values.height = data->padding.height;
  op_params.dilation_width_factor = params->dilation_width_factor;
  op_params.dilation_height_factor = params->dilation_height_factor;
  op_params.stride_width = params->stride_width;
  op_params.stride_height = params->stride_height;
  op_params.float_activation_min = output_activation_min;
  op_params.float_activation_max = output_activation_max;
  switch (effective_kernel_type) {
    case kReference:
      reference_ops::HybridConvPerChannel( op_params, scaling_factors_ptr, GetTensorShape(input), quantized_input_ptr_batch, GetTensorShape(filter), filter_ptr, GetTensorShape(bias), GetTensorData<float>(bias), GetTensorShape(output), GetTensorData<float>(output), GetTensorShape(im2col), im2col_ptr, affine_quantization->scale->data, input_offset_ptr);





      break;
    case kGenericOptimized:
    case kMultithreadOptimized:
    case kCblasOptimized: {
      TfLiteTensor* row_sums;
      TF_LITE_ENSURE_OK( context, GetTemporarySafe(context, node, data->row_sums_index, &row_sums));

      TfLiteTensor* scratch;
      TF_LITE_ENSURE_OK( context, GetTemporarySafe(context, node, data->accum_scratch_index, &scratch));

      optimized_ops::HybridConvPerChannel( op_params, scaling_factors_ptr, GetTensorShape(input), quantized_input_ptr_batch, GetTensorShape(filter), filter_ptr, GetTensorShape(bias), GetTensorData<float>(bias), GetTensorShape(output), GetTensorData<float>(output), GetTensorShape(im2col), im2col_ptr, affine_quantization->scale->data, input_offset_ptr, GetTensorShape(scratch), GetTensorData<int32>(scratch), GetTensorData<int32_t>(row_sums), &data->compute_hybrid_row_sums, CpuBackendContext::GetFromContext(context));








      data->compute_hybrid_row_sums = false;
      break;
    }
  }

  return kTfLiteOk;
}

template <KernelType kernel_type> TfLiteStatus EvalHybrid(TfLiteContext* context, TfLiteNode* node, TfLiteConvParams* params, OpData* data, const TfLiteTensor* input, const TfLiteTensor* filter, const TfLiteTensor* bias, TfLiteTensor* im2col, TfLiteTensor* accum_scratch, TfLiteTensor* output) {




  float output_activation_min, output_activation_max;
  CalculateActivationRange(params->activation, &output_activation_min, &output_activation_max);

  const int input_size = NumElements(input) / SizeOfDimension(input, 0);
  const int batch_size = SizeOfDimension(input, 0);

  const float* input_ptr = GetTensorData<float>(input);
  TfLiteTensor* quantized_input_tensor;
  TF_LITE_ENSURE_OK(context, GetTemporarySafe(context, node, data->input_quantized_index, &quantized_input_tensor));

  int8_t* quantized_input_ptr_batch = GetTensorData<int8_t>(quantized_input_tensor);
  TfLiteTensor* scaling_factors_tensor;
  TF_LITE_ENSURE_OK(context, GetTemporarySafe(context, node, data->scaling_factors_index, &scaling_factors_tensor));

  float* scaling_factors_ptr = GetTensorData<float>(scaling_factors_tensor);

  
  {
    ruy::profiler::ScopeLabel label("ConvHybridQuantizeInputs");
    for (int b = 0; b < batch_size; ++b) {
      float unused_min, unused_max;
      const int offset = b * input_size;
      tensor_utils::SymmetricQuantizeFloats( input_ptr + offset, input_size, quantized_input_ptr_batch + offset, &unused_min, &unused_max, &scaling_factors_ptr[b]);

      scaling_factors_ptr[b] *= filter->params.scale;
    }
  }

  switch (kernel_type) {
    case kReference:
    case kGenericOptimized:
    case kMultithreadOptimized:
    case kCblasOptimized: {
      
      ConvParams op_params;
      op_params.padding_type = PaddingType::kSame;
      op_params.padding_values.width = data->padding.width;
      op_params.padding_values.height = data->padding.height;
      op_params.stride_width = params->stride_width;
      op_params.stride_height = params->stride_height;
      op_params.dilation_width_factor = params->dilation_width_factor;
      op_params.dilation_height_factor = params->dilation_height_factor;
      op_params.float_activation_min = output_activation_min;
      op_params.float_activation_max = output_activation_max;
      optimized_ops::HybridConv( op_params, scaling_factors_ptr, GetTensorShape(input), quantized_input_ptr_batch, GetTensorShape(filter), GetTensorData<int8_t>(filter), GetTensorShape(bias), GetTensorData<float>(bias), GetTensorShape(accum_scratch), GetTensorData<int32_t>(accum_scratch), GetTensorShape(output), GetTensorData<float>(output), GetTensorShape(im2col), GetTensorData<int8_t>(im2col), CpuBackendContext::GetFromContext(context));







      break;
    }
  }

  return kTfLiteOk;
}

template <KernelType kernel_type, TfLiteType input_type> TfLiteStatus EvalImpl(TfLiteContext* context, TfLiteNode* node) {
  auto* params = reinterpret_cast<TfLiteConvParams*>(node->builtin_data);
  OpData* data = reinterpret_cast<OpData*>(node->user_data);

  TfLiteTensor* output;
  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, 0, &output));
  const TfLiteTensor* input;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &input));
  const TfLiteTensor* filter;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 1, &filter));
  bool has_bias = node->inputs->size == 3;
  const TfLiteTensor* bias = has_bias ? GetInput(context, node, 2) : nullptr;
  TfLiteTensor* im2col = data->need_im2col ? &context->tensors[node->temporaries->data[data->im2col_index]] : nullptr;


  TfLiteTensor* hwcn_weights = data->need_hwcn_weights ? &context->tensors[node->temporaries->data[data->hwcn_weights_index]] : nullptr;



  if (data->need_hwcn_weights && !data->have_weights_been_transposed) {
    TransposeFloatTensor(filter, hwcn_weights);
    data->have_weights_been_transposed = true;
  }

  TFLITE_DCHECK_EQ(input_type, input->type);
  switch (input_type) {  
    case kTfLiteFloat32:
      if (filter->type == kTfLiteUInt8 || filter->type == kTfLiteInt8) {
        if (data->is_hybrid_per_channel) {
          TF_LITE_ENSURE_OK(context, EvalHybridPerChannel<kernel_type>( context, node, params, data, input, filter, bias, im2col, output));

        } else {
          TfLiteTensor* accum_scratch = &context->tensors[node->temporaries ->data[data->accum_scratch_index]];

          TF_LITE_ENSURE_OK(context, EvalHybrid<kernel_type>(context, node, params, data, input, filter, bias, im2col, accum_scratch, output));


        }
      } else {
        EvalFloat<kernel_type>(context, node, params, data, input, filter, bias, im2col, hwcn_weights, output);
      }
      break;
    case kTfLiteUInt8:
      EvalQuantized<kernel_type>(context, node, params, data, input, filter, bias, im2col, output);
      break;
    case kTfLiteInt8:
      EvalQuantizedPerChannel<kernel_type>(context, node, params, data, input, filter, bias, output, im2col);
      break;
    case kTfLiteInt16:
      EvalQuantizedPerChannel16x8<kernel_type>( context, node, params, data, input, filter, bias, output, im2col);
      break;
    default:
      TF_LITE_KERNEL_LOG(context, "Type %s currently not supported.", TfLiteTypeGetName(input->type));
      return kTfLiteError;
  }
  return kTfLiteOk;
}

template <KernelType kernel_type> TfLiteStatus Eval(TfLiteContext* context, TfLiteNode* node) {
  const TfLiteTensor* input;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &input));

  switch (input->type) {
    case kTfLiteFloat32:
      return EvalImpl<kernel_type, kTfLiteFloat32>(context, node);
    case kTfLiteUInt8:
      return EvalImpl<kernel_type, kTfLiteUInt8>(context, node);
    case kTfLiteInt8:
      return EvalImpl<kernel_type, kTfLiteInt8>(context, node);
    case kTfLiteInt16:
      return EvalImpl<kernel_type, kTfLiteInt16>(context, node);
    default:
      TF_LITE_KERNEL_LOG(context, "Type %s not currently supported.", TfLiteTypeGetName(input->type));
      return kTfLiteError;
  }
}

}  

TfLiteRegistration* Register_CONVOLUTION_REF() {
  static TfLiteRegistration r = {conv::Init, conv::Free, conv::Prepare<conv::kReference>, conv::Eval<conv::kReference>};

  return &r;
}

TfLiteRegistration* Register_CONVOLUTION_GENERIC_OPT() {
  static TfLiteRegistration r = {conv::Init, conv::Free, conv::Prepare<conv::kGenericOptimized>, conv::Eval<conv::kGenericOptimized>};

  return &r;
}

TfLiteRegistration* Register_CONVOLUTION_GENERIC_OPT_UINT8() {
  static TfLiteRegistration r = {
      conv::Init, conv::Free, conv::Prepare<conv::kGenericOptimized>, conv::EvalImpl<conv::kGenericOptimized, kTfLiteUInt8>};
  return &r;
}

TfLiteRegistration* Register_CONVOLUTION_MULTITHREADED_OPT() {
  static TfLiteRegistration r = {conv::Init, conv::Free, conv::Prepare<conv::kMultithreadOptimized>, conv::Eval<conv::kMultithreadOptimized>};

  return &r;
}

TfLiteRegistration* Register_CONVOLUTION_CBLAS_OPT() {
  static TfLiteRegistration r = {conv::Init, conv::Free, conv::Prepare<conv::kCblasOptimized>, conv::Eval<conv::kCblasOptimized>};

  return &r;
}

TfLiteRegistration* Register_CONV_2D() {

  return Register_CONVOLUTION_CBLAS_OPT();

  return Register_CONVOLUTION_MULTITHREADED_OPT();

  return Register_CONVOLUTION_GENERIC_OPT();

}




TfLiteRegistration* Register_CONV_2D_UINT8() {

  
  return Register_CONVOLUTION_GENERIC_OPT_UINT8();

  return Register_CONV_2D();

}

}  
}  
}  
