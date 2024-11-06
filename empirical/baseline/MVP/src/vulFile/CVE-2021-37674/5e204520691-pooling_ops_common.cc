
























namespace tensorflow {

namespace {

template <typename T> struct RawType {
  using type = T;
};

template <> struct RawType<qint8> {
  using type = int8;
};



template <typename T> struct PadInputWithNegativeInf {
  Status operator()(const GPUDevice& d, typename TTypes<T, 4, int>::ConstTensor in, int input_pad_top, int input_pad_bottom, int input_pad_left, int input_pad_right, typename TTypes<T, 4, int>::Tensor out, TensorFormat format) {



    T padding_value = -std::numeric_limits<T>::infinity();
    functor::PadInput<GPUDevice, T, int, 4>()( d, in, {{input_pad_top, input_pad_left}}, {{input_pad_bottom, input_pad_right}}, out, format, padding_value);

    return Status::OK();
  }
};

template <> struct PadInputWithNegativeInf<qint8> {
  Status operator()(const GPUDevice& d, typename TTypes<qint8, 4, int>::ConstTensor in, int input_pad_top, int input_pad_bottom, int input_pad_left, int input_pad_right, typename TTypes<qint8, 4, int>::Tensor out, TensorFormat format) {




    return errors::InvalidArgument( "Explicit padding not yet supported with qint8");
  }
};



}  

Status CheckPaddingSize(int64_t window_rows, int64_t window_cols, int64_t pad_top, int64_t pad_bottom, int64_t pad_left, int64_t pad_right) {

  if (!FastBoundsCheck(pad_top, window_rows)) {
    return errors::InvalidArgument("Top padding ", pad_top, " needs to be smaller than the " "window size ", window_rows);


  }
  if (!FastBoundsCheck(pad_bottom, window_rows)) {
    return errors::InvalidArgument("Bottom padding ", pad_bottom, " needs to be smaller than the " "window size ", window_rows);


  }
  if (!FastBoundsCheck(pad_left, window_cols)) {
    return errors::InvalidArgument("Left padding ", pad_left, " needs to be smaller than the " "window size ", window_cols);


  }
  if (!FastBoundsCheck(pad_right, window_cols)) {
    return errors::InvalidArgument("Right padding ", pad_right, " needs to be smaller than the " "window size ", window_cols);


  }
  return Status::OK();
}

PoolParameters::PoolParameters(OpKernelContext* context, const std::vector<int32>& ksize, const std::vector<int32>& stride, Padding padding, std::vector<int64> explicit_paddings, TensorFormat data_format, const TensorShape& tensor_in_shape) {





  
  
  
  OP_REQUIRES(context, GetTensorSpatialDims(tensor_in_shape.dims(), data_format) == 2, errors::InvalidArgument( "tensor_in_shape must have 2 spatial dimensions. ", tensor_in_shape.dims(), " ", data_format));




  this->data_format = data_format;
  depth = GetTensorDim(tensor_in_shape, data_format, 'C') * (data_format == FORMAT_NCHW_VECT_C ? 4 : 1);
  tensor_in_cols = GetTensorDim(tensor_in_shape, data_format, 'W');
  tensor_in_rows = GetTensorDim(tensor_in_shape, data_format, 'H');
  tensor_in_batch = GetTensorDim(tensor_in_shape, data_format, 'N');
  window_rows = GetTensorDim(ksize, data_format, 'H');
  window_cols = GetTensorDim(ksize, data_format, 'W');
  depth_window = GetTensorDim(ksize, data_format, 'C');
  row_stride = GetTensorDim(stride, data_format, 'H');
  col_stride = GetTensorDim(stride, data_format, 'W');
  depth_stride = GetTensorDim(stride, data_format, 'C');

  
  
  OP_REQUIRES(context, (depth_window == 1 || (window_rows == 1 && window_cols == 1)), errors::Unimplemented( "MaxPooling supports exactly one of pooling across depth " "or pooling across width/height."));



  if (padding == Padding::EXPLICIT) {
    OP_REQUIRES_OK(context, CheckValidPadding(padding, explicit_paddings, 4, data_format));
    GetExplicitPaddingForDim(explicit_paddings, data_format, 'H', &pad_top, &pad_bottom);
    GetExplicitPaddingForDim(explicit_paddings, data_format, 'W', &pad_left, &pad_right);
    OP_REQUIRES_OK(context, CheckPaddingSize(window_rows, window_cols, pad_top, pad_bottom, pad_left, pad_right));
  }

  if (depth_window == 1) {
    OP_REQUIRES_OK(context, GetWindowedOutputSizeVerbose( tensor_in_rows, window_rows, row_stride, padding, &out_height, &pad_top, &pad_bottom));

    OP_REQUIRES_OK(context, GetWindowedOutputSizeVerbose( tensor_in_cols, window_cols, col_stride, padding, &out_width, &pad_left, &pad_right));

    pad_depth = 0;
    out_depth = depth;
  } else {
    
    
    
    OP_REQUIRES( context, depth % depth_window == 0, errors::Unimplemented("Depthwise max pooling requires the depth " "window to evenly divide the input depth"));


    OP_REQUIRES( context, depth_stride == depth_window, errors::Unimplemented("Depthwise max pooling requires the depth " "window to equal the depth stride"));



    
    OP_REQUIRES(context, (DeviceType(static_cast<Device*>(context->device())
                                ->attributes()
                                .device_type()) == DeviceType(DEVICE_CPU)), errors::Unimplemented("Depthwise max pooling is currently " "only implemented for CPU devices."));


    pad_depth = 0;
    out_depth = depth / depth_window;
  }
}

TensorShape PoolParameters::forward_output_shape() {
  if (depth_window == 1) {
    
    return ShapeFromFormat(data_format, tensor_in_batch, out_height, out_width, depth);
  } else {
    
    return TensorShape( {tensor_in_batch, tensor_in_rows, tensor_in_cols, out_depth});
  }
}



template <typename T> void DnnPoolingOp<T>::Compute(OpKernelContext* context, se::dnn::PoolingMode pooling_mode, const std::vector<int32>& size, const std::vector<int32>& stride, Padding padding, std::vector<int64> explicit_paddings, TensorFormat data_format, const Tensor& tensor_in, const TensorShape& tensor_out_shape, bool propagate_nans) {







  Tensor* tensor_out = nullptr;
  OP_REQUIRES_OK(context, context->allocate_output(0, tensor_out_shape, &tensor_out));
  if (tensor_in.shape().num_elements() == 0) {
    return;
  }

  PoolParameters params{
      context,           size,        stride,           padding, explicit_paddings, data_format, tensor_in.shape()};
  if (!context->status().ok()) {
    return;
  }

  int batch_size = params.tensor_in_batch;
  int depth = params.depth;
  int tensor_in_cols = params.tensor_in_cols;
  int tensor_in_rows = params.tensor_in_rows;


  
  
  Tensor transformed_input;
  if (data_format == FORMAT_NHWC) {
    OP_REQUIRES_OK(context, context->allocate_temp( DataTypeToEnum<T>::value, ShapeFromFormat(FORMAT_NCHW, tensor_in.shape(), data_format), &transformed_input));



    functor::NHWCToNCHW<GPUDevice, T, 4>()(context->eigen_device<Device>(), tensor_in.tensor<T, 4>(), transformed_input.tensor<T, 4>());

  } else {
    transformed_input = tensor_in;
  }
  Tensor transformed_output;
  if (data_format == FORMAT_NHWC) {
    OP_REQUIRES_OK(context, context->allocate_temp( DataTypeToEnum<T>::value, ShapeFromFormat(FORMAT_NCHW, tensor_out_shape, data_format), &transformed_output));



  } else {
    transformed_output = *tensor_out;
  }
  se::dnn::DataLayout data_layout = se::dnn::DataLayout::kBatchDepthYX;

  Tensor transformed_input = tensor_in;
  auto& transformed_output = *tensor_out;
  se::dnn::DataLayout data_layout;
  switch (data_format) {
    case FORMAT_NHWC:
      data_layout = se::dnn::DataLayout::kBatchYXDepth;
      break;
    case FORMAT_NCHW:
      data_layout = se::dnn::DataLayout::kBatchDepthYX;
      break;
    case FORMAT_NCHW_VECT_C:
      
      
      data_layout = se::dnn::DataLayout::kBatchYXDepth;
      batch_size *= depth / 4;
      depth = 4;
      break;
    default:
      OP_REQUIRES(context, false, errors::InvalidArgument("Unsupported format: ", ToString(data_format)));

  }


  int64_t vertical_padding = params.pad_top;
  int64_t horizontal_padding = params.pad_left;

  if (padding == EXPLICIT && (params.pad_top != params.pad_bottom || params.pad_left != params.pad_right)) {
    
    
    
    const int64_t common_padding_rows = std::min(params.pad_top, params.pad_bottom);
    const int64_t common_padding_cols = std::min(params.pad_left, params.pad_right);

    Tensor padded_input;
    const int64_t padding_rows_diff = std::abs(params.pad_top - params.pad_bottom);
    const int64_t padding_cols_diff = std::abs(params.pad_left - params.pad_right);

    const int64_t new_in_rows = tensor_in_rows + padding_rows_diff;
    const int64_t new_in_cols = tensor_in_cols + padding_cols_diff;

    OP_REQUIRES_OK( context, context->allocate_temp(DataTypeToEnum<T>::value, ShapeFromFormat(data_format, batch_size, new_in_rows, new_in_cols, depth), &padded_input));




    const int64_t input_pad_top = params.pad_top - common_padding_rows;
    const int64_t input_pad_bottom = params.pad_bottom - common_padding_rows;
    const int64_t input_pad_left = params.pad_left - common_padding_cols;
    const int64_t input_pad_right = params.pad_right - common_padding_cols;

    bool in_bounds = FastBoundsCheck(input_pad_top, std::numeric_limits<int>::max()) && FastBoundsCheck(input_pad_bottom, std::numeric_limits<int>::max()) && FastBoundsCheck(input_pad_left, std::numeric_limits<int>::max()) && FastBoundsCheck(input_pad_right, std::numeric_limits<int>::max());



    if (!in_bounds) {
      context->SetStatus(errors::InvalidArgument("Padding is too large."));
      return;
    }

    
    const Tensor& const_transformed_input = transformed_input;
    OP_REQUIRES_OK( context, PadInputWithNegativeInf<T>()( context->eigen_device<GPUDevice>(), To32Bit(const_transformed_input.tensor<T, 4>()), static_cast<int>(input_pad_top), static_cast<int>(input_pad_bottom), static_cast<int>(input_pad_left), static_cast<int>(input_pad_right), To32Bit(padded_input.tensor<T, 4>()), data_format));






    transformed_input = padded_input;
    vertical_padding = common_padding_rows;
    horizontal_padding = common_padding_cols;
    tensor_in_rows = new_in_rows;
    tensor_in_cols = new_in_cols;
  }

  se::dnn::PoolingDescriptor pooling_desc;
  pooling_desc.set_pooling_mode(pooling_mode)
      .set_window_height(params.window_rows)
      .set_window_width(params.window_cols)
      .set_vertical_stride(params.row_stride)
      .set_horizontal_stride(params.col_stride)
      .set_vertical_padding(vertical_padding)
      .set_horizontal_padding(horizontal_padding)
      .set_propagate_nans(propagate_nans);

  se::dnn::BatchDescriptor input_desc;
  input_desc.set_count(batch_size)
      .set_height(tensor_in_rows)
      .set_width(tensor_in_cols)
      .set_feature_map_count(depth)
      .set_layout(data_layout);

  se::dnn::BatchDescriptor output_desc;
  output_desc.set_count(batch_size)
      .set_height(params.out_height)
      .set_width(params.out_width)
      .set_feature_map_count(depth)
      .set_layout(data_layout);

  auto input_data = AsDeviceMemory(reinterpret_cast<const typename RawType<T>::type*>( transformed_input.template flat<T>().data()), transformed_input.template flat<T>().size());



  auto output_data = AsDeviceMemory(reinterpret_cast<const typename RawType<T>::type*>( transformed_output.template flat<T>().data()), transformed_output.template flat<T>().size());



  auto* stream = context->op_device_context()->stream();
  OP_REQUIRES(context, stream, errors::Internal("No GPU stream available."));


  static int64 PoolingScratchSize = GetDnnWorkspaceLimit(  "TF_CUDNN_WORKSPACE_LIMIT_IN_MB", 1LL << 32 );



  DnnScratchAllocator scratch_allocator(PoolingScratchSize, context);
  bool status = stream ->ThenPoolForward(pooling_desc, input_desc, input_data, output_desc, &output_data, &scratch_allocator)


          .ok();

  bool status = stream ->ThenPoolForward(pooling_desc, input_desc, input_data, output_desc, &output_data)

                    .ok();

  OP_REQUIRES(context, status, errors::Internal("dnn PoolForward launch failed"));

  if (data_format == FORMAT_NHWC) {
    
    auto toConstTensor = [](const Tensor& x) -> const Tensor { return x; };
    using RT = typename RawType<T>::type;
    functor::NCHWToNHWC<GPUDevice, RT, 4>()( context->eigen_device<Device>(), toConstTensor(transformed_output).template tensor<RT, 4>(), tensor_out->tensor<RT, 4>());


  }

}


namespace functor {









DECLARE_GPU_SPEC(float);
DECLARE_GPU_SPEC(Eigen::half);
DECLARE_GPU_SPEC(double);
DECLARE_GPU_SPEC(int32);
}  

template <typename T> void DnnPoolingGradOp<T>::Compute( OpKernelContext* context, se::dnn::PoolingMode pooling_mode, const std::vector<int32>& size, const std::vector<int32>& stride, Padding padding, std::vector<int64> explicit_paddings, TensorFormat data_format, const Tensor* tensor_in, const Tensor* tensor_out, const Tensor& out_backprop, const TensorShape& tensor_in_shape, bool propagate_nans) {






  CHECK((pooling_mode != se::dnn::PoolingMode::kMaximum) || (tensor_in && tensor_out))
      << "For MaxPoolGrad, both tensor_in and tensor_out needs to be " "specified";

  Tensor* input_backprop = nullptr;
  OP_REQUIRES_OK(context, context->allocate_output(0, tensor_in_shape, &input_backprop));
  if (tensor_in_shape.num_elements() == 0) {
    return;
  }

  PoolParameters params{context,           size,        stride,         padding, explicit_paddings, data_format, tensor_in_shape};
  if (!context->status().ok()) {
    return;
  }

  TensorFormat transformed_input_data_format = data_format;


  
  
  Tensor transformed_input;
  TensorShape transformed_input_shape;
  if (data_format == FORMAT_NHWC || !tensor_in) {
    transformed_input_shape = ShapeFromFormat(FORMAT_NCHW, tensor_in_shape, data_format);
    OP_REQUIRES_OK(context, context->allocate_temp(DataTypeToEnum<T>::value, transformed_input_shape, &transformed_input));

  } else {
    transformed_input = *tensor_in;
  }
  Tensor transformed_output;
  TensorShape transformed_output_shape;
  if (data_format == FORMAT_NHWC || !tensor_out) {
    transformed_output_shape = ShapeFromFormat(FORMAT_NCHW, out_backprop.shape(), data_format);
    OP_REQUIRES_OK(context, context->allocate_temp(DataTypeToEnum<T>::value, transformed_output_shape, &transformed_output));

  } else {
    transformed_output = *tensor_out;
  }
  Tensor transformed_input_backprop;
  if (data_format == FORMAT_NHWC) {
    OP_REQUIRES_OK(context, context->allocate_temp(DataTypeToEnum<T>::value, transformed_input_shape, &transformed_input_backprop));


  } else {
    transformed_input_backprop = *input_backprop;
  }
  Tensor transformed_output_backprop;
  if (data_format == FORMAT_NHWC) {
    OP_REQUIRES_OK(context, context->allocate_temp(DataTypeToEnum<T>::value, transformed_output_shape, &transformed_output_backprop));


  } else {
    transformed_output_backprop = out_backprop;
  }

  if (data_format == FORMAT_NHWC) {
    
    if (tensor_in) {
      
      
      
      functor::NHWCToNCHW<GPUDevice, T, 4>()(context->eigen_device<Device>(), tensor_in->tensor<T, 4>(), transformed_input.tensor<T, 4>());

      transformed_input_data_format = FORMAT_NCHW;
    }
    if (tensor_out) {
      
      
      
      functor::NHWCToNCHW<GPUDevice, T, 4>()(context->eigen_device<Device>(), tensor_out->tensor<T, 4>(), transformed_output.tensor<T, 4>());

    }
    functor::NHWCToNCHW<GPUDevice, T, 4>()( context->eigen_device<Device>(), out_backprop.tensor<T, 4>(), transformed_output_backprop.tensor<T, 4>());

  }
  se::dnn::DataLayout data_layout = se::dnn::DataLayout::kBatchDepthYX;

  Tensor transformed_input;
  if (!tensor_in) {
    OP_REQUIRES_OK(context, context->allocate_temp(DataTypeToEnum<T>::value, tensor_in_shape, &transformed_input));

  } else {
    transformed_input = *tensor_in;
  }
  Tensor transformed_output;
  if (!tensor_out) {
    OP_REQUIRES_OK(context, context->allocate_temp(DataTypeToEnum<T>::value, out_backprop.shape(), &transformed_output));

  } else {
    transformed_output = *tensor_out;
  }
  Tensor transformed_input_backprop = *input_backprop;
  Tensor transformed_output_backprop = out_backprop;
  se::dnn::DataLayout data_layout;
  switch (data_format) {
    case FORMAT_NHWC:
      data_layout = se::dnn::DataLayout::kBatchYXDepth;
      break;
    case FORMAT_NCHW:
      data_layout = se::dnn::DataLayout::kBatchDepthYX;
      break;
    default:
      OP_REQUIRES(context, false, errors::InvalidArgument("Unsupported format: ", ToString(data_format)));

  }


  int64_t vertical_padding = params.pad_top;
  int64_t horizontal_padding = params.pad_left;

  int batch_size = params.tensor_in_batch;
  int depth = params.depth;
  int tensor_in_cols = params.tensor_in_cols;
  int tensor_in_rows = params.tensor_in_rows;

  int64_t input_pad_top = 0;
  int64_t input_pad_bottom = 0;
  int64_t input_pad_left = 0;
  int64_t input_pad_right = 0;

  Tensor transformed_and_padded_input_backprop;

  if (padding == EXPLICIT && (params.pad_top != params.pad_bottom || params.pad_left != params.pad_right)) {
    
    
    
    const int64_t common_padding_rows = std::min(params.pad_top, params.pad_bottom);
    const int64_t common_padding_cols = std::min(params.pad_left, params.pad_right);

    Tensor padded_input;
    const int64_t padding_rows_diff = std::abs(params.pad_top - params.pad_bottom);
    const int64_t padding_cols_diff = std::abs(params.pad_left - params.pad_right);

    const int64_t new_in_rows = tensor_in_rows + padding_rows_diff;
    const int64_t new_in_cols = tensor_in_cols + padding_cols_diff;

    VLOG(2) << "Create new tensor: " << " original rows=" << tensor_in_rows << " original cols=" << tensor_in_cols << " padding_rows=" << new_in_rows << " padding_cols=" << new_in_cols << " depth= " << depth << " batch_size=" << batch_size << " kernel_rows" << params.window_rows << " kernel_col" << params.window_cols << " stride_rows" << params.row_stride;







    OP_REQUIRES_OK( context, context->allocate_temp( DataTypeToEnum<T>::value, ShapeFromFormat(transformed_input_data_format, batch_size, new_in_rows, new_in_cols, depth), &padded_input));





    OP_REQUIRES_OK( context, context->allocate_temp( DataTypeToEnum<T>::value, ShapeFromFormat(transformed_input_data_format, batch_size, new_in_rows, new_in_cols, depth), &transformed_and_padded_input_backprop));





    input_pad_top = params.pad_top - common_padding_rows;
    input_pad_bottom = params.pad_bottom - common_padding_rows;
    input_pad_left = params.pad_left - common_padding_cols;
    input_pad_right = params.pad_right - common_padding_cols;

    bool in_bounds = FastBoundsCheck(input_pad_top, std::numeric_limits<int>::max()) && FastBoundsCheck(input_pad_bottom, std::numeric_limits<int>::max()) && FastBoundsCheck(input_pad_left, std::numeric_limits<int>::max()) && FastBoundsCheck(input_pad_right, std::numeric_limits<int>::max());



    if (!in_bounds) {
      context->SetStatus(errors::InvalidArgument("Padding is too large."));
      return;
    }

    
    const Tensor& const_transformed_input = transformed_input;
    OP_REQUIRES_OK( context, PadInputWithNegativeInf<T>()( context->eigen_device<GPUDevice>(), To32Bit(const_transformed_input.tensor<T, 4>()), static_cast<int>(input_pad_top), static_cast<int>(input_pad_bottom), static_cast<int>(input_pad_left), static_cast<int>(input_pad_right), To32Bit(padded_input.tensor<T, 4>()), transformed_input_data_format));








    transformed_input = padded_input;

    vertical_padding = common_padding_rows;
    horizontal_padding = common_padding_cols;
    VLOG(2) << "vertical padding set to: " << vertical_padding << " horizontal padding set to: " << horizontal_padding;
    tensor_in_rows = new_in_rows;
    tensor_in_cols = new_in_cols;
  } else {
    transformed_and_padded_input_backprop = transformed_input_backprop;
  }

  
  se::dnn::PoolingDescriptor pooling_desc;
  pooling_desc.set_pooling_mode(pooling_mode)
      .set_window_height(params.window_rows)
      .set_window_width(params.window_cols)
      .set_vertical_stride(params.row_stride)
      .set_horizontal_stride(params.col_stride)
      .set_vertical_padding(vertical_padding)
      .set_horizontal_padding(horizontal_padding)
      .set_propagate_nans(propagate_nans);

  se::dnn::BatchDescriptor orig_output_desc;
  orig_output_desc.set_count(params.tensor_in_batch)
      .set_height(params.out_height)
      .set_width(params.out_width)
      .set_feature_map_count(params.depth)
      .set_layout(data_layout);

  se::dnn::BatchDescriptor orig_input_desc;
  orig_input_desc.set_count(params.tensor_in_batch)
      .set_height(tensor_in_rows)
      .set_width(tensor_in_cols)
      .set_feature_map_count(params.depth)
      .set_layout(data_layout);

  auto orig_output_data = AsDeviceMemory(transformed_output.template flat<T>().data(), transformed_output.template flat<T>().size());

  auto orig_input_data = AsDeviceMemory(transformed_input.template flat<T>().data(), transformed_input.template flat<T>().size());

  auto output_backprop_data = AsDeviceMemory(transformed_output_backprop.template flat<T>().data(), transformed_output_backprop.template flat<T>().size());

  auto input_backprop_data = AsDeviceMemory( transformed_and_padded_input_backprop.template flat<T>().data(), transformed_and_padded_input_backprop.template flat<T>().size());


  auto* stream = context->op_device_context()->stream();
  OP_REQUIRES(context, stream, errors::Internal("No GPU stream available."));


  static int64 PoolingScratchSize = GetDnnWorkspaceLimit(  "TF_CUDNN_WORKSPACE_LIMIT_IN_MB", 1LL << 32 );



  DnnScratchAllocator scratch_allocator(PoolingScratchSize, context);
  bool status = stream ->ThenPoolBackward(pooling_desc, orig_input_desc, orig_input_data, orig_output_desc, orig_output_data, output_backprop_data, &input_backprop_data, &scratch_allocator)



                    .ok();

  bool status = stream ->ThenPoolBackward(pooling_desc, orig_input_desc, orig_input_data, orig_output_desc, orig_output_data, output_backprop_data, &input_backprop_data)



          .ok();


  OP_REQUIRES(context, status, errors::Internal("dnn PoolBackward launch failed"));

  if (padding == EXPLICIT && (params.pad_top != params.pad_bottom || params.pad_left != params.pad_right)) {
    
    functor::PadInput<GPUDevice, T, int, 4>()( context->eigen_device<GPUDevice>(), To32Bit(const_cast<const Tensor&>(transformed_and_padded_input_backprop)

                    .tensor<T, 4>()), {{static_cast<int>(-input_pad_top), static_cast<int>(-input_pad_left)}}, {{static_cast<int>(-input_pad_bottom), static_cast<int>(-input_pad_right)}}, To32Bit(transformed_input_backprop.template tensor<T, 4>()), transformed_input_data_format, T{});




  }


  if (data_format == FORMAT_NHWC) {
    
    auto toConstTensor = [](const Tensor& x) -> const Tensor { return x; };
    functor::NCHWToNHWC<GPUDevice, T, 4>()( context->eigen_device<Device>(), toConstTensor(transformed_input_backprop).template tensor<T, 4>(), input_backprop->tensor<T, 4>());


  }

}



TF_CALL_GPU_NUMBER_TYPES(DEFINE_DNN_OPS)


template class DnnPoolingOp<qint8>;






}  
