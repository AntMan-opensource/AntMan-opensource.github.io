









namespace tflite {
namespace {

constexpr int kInputTensor = 0;
constexpr int kOutputTensor = 0;


constexpr int kBatchRank = 0;
constexpr int kHeightRank = 1;
constexpr int kWidthRank = 2;
constexpr int kDepthRank = 3;

TfLiteStatus CalculateOpData(TfLiteContext* context, TfLiteNode* node) {
  auto* params = reinterpret_cast<TfLiteDepthToSpaceParams*>(node->builtin_data);

  TF_LITE_ENSURE_EQ(context, NumInputs(node), 1);
  TF_LITE_ENSURE_EQ(context, NumOutputs(node), 1);

  const TfLiteTensor* input;
  TF_LITE_ENSURE_OK(context, GetInputSafe(context, node, kInputTensor, &input));
  TfLiteTensor* output;
  TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, kOutputTensor, &output));

  TF_LITE_ENSURE_EQ(context, NumDimensions(input), 4);

  auto data_type = output->type;
  TF_LITE_ENSURE(context, data_type == kTfLiteFloat32 || data_type == kTfLiteInt8);
  TF_LITE_ENSURE_TYPES_EQ(context, input->type, output->type);

  const int block_size = params->block_size;
  const int input_height = input->dims->data[kHeightRank];
  const int input_width = input->dims->data[kWidthRank];
  const int input_channels = input->dims->data[kDepthRank];
  int output_height = input_height * block_size;
  int output_width = input_width * block_size;
  int output_channels = input_channels / block_size / block_size;

  TF_LITE_ENSURE_EQ(context, input_height, output_height / block_size);
  TF_LITE_ENSURE_EQ(context, input_width, output_width / block_size);
  TF_LITE_ENSURE_EQ(context, input_channels, output_channels * block_size * block_size);

  
  
  
  
  
  
  
  TfLiteEvalTensor* output_eval = tflite::micro::GetEvalOutput(context, node, kOutputTensor);
  TF_LITE_ENSURE_OK(context, tflite::micro::CreateWritableTensorDimsWithCopy( context, output, output_eval));
  output->dims->data[kBatchRank] = input->dims->data[kBatchRank];
  output->dims->data[kHeightRank] = output_height;
  output->dims->data[kWidthRank] = output_width;
  output->dims->data[kDepthRank] = output_channels;

  return kTfLiteOk;
}

TfLiteStatus Prepare(TfLiteContext* context, TfLiteNode* node) {
  return CalculateOpData(context, node);
}

TfLiteStatus Eval(TfLiteContext* context, TfLiteNode* node) {
  auto* params = reinterpret_cast<TfLiteDepthToSpaceParams*>(node->builtin_data);

  const TfLiteEvalTensor* input = tflite::micro::GetEvalInput(context, node, kInputTensor);
  TfLiteEvalTensor* output = tflite::micro::GetEvalOutput(context, node, kOutputTensor);

  tflite::DepthToSpaceParams op_params;
  op_params.block_size = static_cast<int32_t>(params->block_size);

  switch (input->type) {  
    case kTfLiteFloat32:
      reference_ops::DepthToSpace(op_params, tflite::micro::GetTensorShape(input), tflite::micro::GetTensorData<float>(input), tflite::micro::GetTensorShape(output), tflite::micro::GetTensorData<float>(output));



      break;
    case kTfLiteInt8:
      reference_ops::DepthToSpace(op_params, tflite::micro::GetTensorShape(input), tflite::micro::GetTensorData<int8_t>(input), tflite::micro::GetTensorShape(output), tflite::micro::GetTensorData<int8_t>(output));



      break;
    default:
      TF_LITE_KERNEL_LOG( context, "DEPTH_TO_SPACE only supports FLOAT32 and INT8, got %s.", TfLiteTypeGetName(output->type));

      return kTfLiteError;
  }

  return kTfLiteOk;
}

}  

TfLiteRegistration Register_DEPTH_TO_SPACE() {
  return {nullptr, nullptr, Prepare, Eval, nullptr, 0, nullptr, 0};






}

}  
