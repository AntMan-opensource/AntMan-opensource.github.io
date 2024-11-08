





























































namespace tflite {
namespace ops {
namespace builtin {

namespace {

TfLiteStatus Prepare(TfLiteContext* context, TfLiteNode* node) {
  TF_LITE_ENSURE_EQ(context, NumInputs(node), 5);
  TF_LITE_ENSURE_EQ(context, NumOutputs(node), 1);

  const TfLiteTensor* ids;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &ids));
  TF_LITE_ENSURE_EQ(context, NumDimensions(ids), 1);
  TF_LITE_ENSURE_EQ(context, ids->type, kTfLiteInt32);

  const TfLiteTensor* indices;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 1, &indices));
  TF_LITE_ENSURE_EQ(context, NumDimensions(indices), 2);
  TF_LITE_ENSURE_EQ(context, indices->type, kTfLiteInt32);

  const TfLiteTensor* shape;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 2, &shape));
  TF_LITE_ENSURE_EQ(context, NumDimensions(shape), 1);
  TF_LITE_ENSURE_EQ(context, shape->type, kTfLiteInt32);

  const TfLiteTensor* weights;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 3, &weights));
  TF_LITE_ENSURE_EQ(context, NumDimensions(weights), 1);
  TF_LITE_ENSURE_EQ(context, weights->type, kTfLiteFloat32);

  TF_LITE_ENSURE_EQ(context, SizeOfDimension(indices, 0), SizeOfDimension(ids, 0));
  TF_LITE_ENSURE_EQ(context, SizeOfDimension(indices, 0), SizeOfDimension(weights, 0));

  const TfLiteTensor* value;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 4, &value));
  TF_LITE_ENSURE(context, NumDimensions(value) >= 2);

  
  TfLiteTensor* output;
  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, 0, &output));
  TF_LITE_ENSURE_TYPES_EQ(context, output->type, kTfLiteFloat32);
  output->allocation_type = kTfLiteDynamic;

  return kTfLiteOk;
}

void FinalizeAggregation(TfLiteCombinerType combiner, int num_elements, float current_total_weight, float current_squares_weight, int embedding_size, float* output) {


  if (combiner != kTfLiteCombinerTypeSum && num_elements > 0) {
    float multiplier = 1.0;
    switch (combiner) {
      case kTfLiteCombinerTypeMean:
        multiplier = current_total_weight;
        break;
      case kTfLiteCombinerTypeSqrtn:
        multiplier = std::sqrt(current_squares_weight);
        break;
      default:
        break;
    }
    for (int k = 0; k < embedding_size; k++) {
      output[k] /= multiplier;
    }
  }
}

TfLiteStatus Eval(TfLiteContext* context, TfLiteNode* node) {
  auto* params = reinterpret_cast<TfLiteEmbeddingLookupSparseParams*>(node->builtin_data);
  TfLiteTensor* output;
  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, 0, &output));
  const TfLiteTensor* ids;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 0, &ids));
  const TfLiteTensor* indices;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 1, &indices));
  const TfLiteTensor* dense_shape;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 2, &dense_shape));
  const TfLiteTensor* weights;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 3, &weights));
  const TfLiteTensor* value;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, 4, &value));

  const int lookup_rank = SizeOfDimension(indices, 1);
  const int embedding_rank = NumDimensions(value);
  const int num_lookups = SizeOfDimension(ids, 0);
  const int num_rows = SizeOfDimension(value, 0);

  
  const int output_rank = (lookup_rank - 1) + (embedding_rank - 1);

  
  
  TF_LITE_ENSURE_EQ(context, SizeOfDimension(dense_shape, 0), lookup_rank);

  
  TfLiteIntArray* output_shape = TfLiteIntArrayCreate(output_rank);
  int k = 0;
  int embedding_size = 1;
  int lookup_size = 1;
  for (int i = 0; i < lookup_rank - 1; i++, k++) {
    const int dim = dense_shape->data.i32[i];
    lookup_size *= dim;
    output_shape->data[k] = dim;
  }
  for (int i = 1; i < embedding_rank; i++, k++) {
    const int dim = SizeOfDimension(value, i);
    embedding_size *= dim;
    output_shape->data[k] = dim;
  }
  TF_LITE_ENSURE_STATUS(context->ResizeTensor(context, output, output_shape));
  const int output_size = lookup_size * embedding_size;
  TfLiteTensorRealloc(output_size * sizeof(float), output);

  float* output_ptr = GetTensorData<float>(output);
  const float* weights_ptr = GetTensorData<float>(weights);
  const float* value_ptr = GetTensorData<float>(value);

  std::fill_n(output_ptr, output_size, 0.0f);

  
  int current_output_offset = 0;
  float current_total_weight = 0.0;
  float current_squares_weight = 0.0;
  int num_elements = 0;

  for (int i = 0; i < num_lookups; i++) {
    int idx = ids->data.i32[i];
    if (idx >= num_rows || idx < 0) {
      context->ReportError(context, "Embedding Lookup Sparse: index out of bounds. " "Got %d, and bounds are [0, %d]", idx, num_rows - 1);


      return kTfLiteError;
    }

    
    const int example_indices_offset = i * lookup_rank;
    int output_bucket = 0;
    int stride = 1;
    for (int k = (lookup_rank - 1) - 1; k >= 0; k--) {
      output_bucket += indices->data.i32[example_indices_offset + k] * stride;
      stride *= dense_shape->data.i32[k];
    }
    const int output_offset = output_bucket * embedding_size;

    
    
    if (output_offset != current_output_offset) {
      FinalizeAggregation(params->combiner, num_elements, current_total_weight, current_squares_weight, embedding_size, &output_ptr[current_output_offset]);


      
      num_elements = 0;
      current_total_weight = 0.0;
      current_squares_weight = 0.0;
      current_output_offset = output_offset;
    }

    
    ++num_elements;
    const int example_embedding_offset = idx * embedding_size;
    const float w = weights_ptr[i];
    current_squares_weight += w * w;
    current_total_weight += w;
    for (int k = 0; k < embedding_size; k++) {
      output_ptr[current_output_offset + k] += value_ptr[example_embedding_offset + k] * w;
    }
  }

  
  FinalizeAggregation(params->combiner, num_elements, current_total_weight, current_squares_weight, embedding_size, &GetTensorData<float>(output)[current_output_offset]);


  return kTfLiteOk;
}

}  

TfLiteRegistration* Register_EMBEDDING_LOOKUP_SPARSE() {
  static TfLiteRegistration r = {nullptr, nullptr, Prepare, Eval};
  return &r;
}

}  
}  
}  
