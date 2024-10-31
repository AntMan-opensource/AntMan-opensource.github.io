


























































namespace tensorflow {

typedef Eigen::ThreadPoolDevice CPUDevice;
typedef Eigen::GpuDevice GPUDevice;

namespace {
template <typename Device, typename T> struct LaunchGeneric {
  void operator()(OpKernelContext* ctx, const Tensor& input, const Tensor& filter, int row_stride, int col_stride, int row_dilation, int col_dilation, const Padding& padding, const std::vector<int64>& explicit_paddings, Tensor* output, TensorFormat data_format) {



    CHECK(data_format == FORMAT_NHWC) << "Generic conv implementation only " "supports NHWC tensor format for now.";
    if (filter.dim_size(0) == 1 && filter.dim_size(1) == 1 && row_stride == 1 && col_stride == 1 && (padding == SAME || padding == VALID)) {
      
      
      
      
      
      
      int conv_width = 1;  
      for (int i = 0; i < 3; ++i) {
        conv_width *= output->dim_size(i);
      }

      Eigen::array<Eigen::IndexPair<Eigen::DenseIndex>, 1> dim_pair;
      dim_pair[0] = Eigen::IndexPair<Eigen::DenseIndex>(1, 0);
      functor::MatMulConvFunctor<Device, T>()( ctx->eigen_device<Device>(), output->shaped<T, 2>({conv_width, filter.dim_size(3)}), input.shaped<T, 2>({conv_width, filter.dim_size(2)}), filter.shaped<T, 2>({filter.dim_size(2), filter.dim_size(3)}), dim_pair);




    } else if (filter.dim_size(0) == input.dim_size(1) && filter.dim_size(1) == input.dim_size(2) && row_dilation == 1 && col_dilation == 1 && padding == VALID) {

      
      
      const int k =   filter.dim_size(0) * filter.dim_size(1) * filter.dim_size(2);

      Eigen::array<Eigen::IndexPair<Eigen::DenseIndex>, 1> dim_pair;
      dim_pair[0] = Eigen::IndexPair<Eigen::DenseIndex>(1, 0);
      functor::MatMulConvFunctor<Device, T>()( ctx->eigen_device<Device>(), output->shaped<T, 2>({input.dim_size(0), filter.dim_size(3)}), input.shaped<T, 2>({input.dim_size(0), k}), filter.shaped<T, 2>({k, filter.dim_size(3)}), dim_pair);



    } else {
      if (padding == EXPLICIT) {
        functor::SpatialConvolution<Device, T>()( ctx->eigen_device<Device>(), output->tensor<T, 4>(), input.tensor<T, 4>(), filter.tensor<T, 4>(), row_stride, col_stride, row_dilation, col_dilation, static_cast<int>(explicit_paddings[2]), static_cast<int>(explicit_paddings[3]), static_cast<int>(explicit_paddings[4]), static_cast<int>(explicit_paddings[5]));





      } else {
        functor::SpatialConvolution<Device, T>()( ctx->eigen_device<Device>(), output->tensor<T, 4>(), input.tensor<T, 4>(), filter.tensor<T, 4>(), row_stride, col_stride, row_dilation, col_dilation, BrainPadding2EigenPadding(padding));


      }
    }
  }
};





template <typename T> struct LaunchGrouped {
  void operator()(OpKernelContext* ctx, const Tensor& input, const Tensor& filter, int row_stride, int col_stride, int row_dilation, int col_dilation, const Padding& padding, const std::vector<int64>& explicit_paddings, Tensor* output, TensorFormat data_format) {



    DCHECK(data_format == FORMAT_NHWC)
        << "Grouped conv implementation only " "supports NHWC tensor format for now.";

    const int64 in_depth = input.dim_size(3);
    const int64 patch_depth = filter.dim_size(2);
    const int64 num_groups = in_depth / patch_depth;

    
    std::array<int64, 5> shuffle({3, 0, 1, 2, 4});

    
    auto pre_shuffle = [&](const Tensor& tensor) -> std::array<int64, 5> {
      return {tensor.dim_size(0), tensor.dim_size(1), tensor.dim_size(2), num_groups, tensor.dim_size(3) / num_groups};
    };

    
    auto post_shuffle = [&](const Tensor& tensor) -> std::array<int64, 5> {
      return {num_groups, tensor.dim_size(0), tensor.dim_size(1), tensor.dim_size(2), tensor.dim_size(3) / num_groups};
    };

    auto& device = ctx->eigen_device<CPUDevice>();

    absl::BlockingCounter shuffles_completed(2);
    auto on_shuffled = [&]() { shuffles_completed.DecrementCount(); };

    
    Tensor input_shuffled(input.dtype(), TensorShape(post_shuffle(input)));
    input_shuffled.tensor<T, 5>().device(device, on_shuffled) = input.shaped<T, 5>(pre_shuffle(input)).shuffle(shuffle);

    
    Tensor filter_shuffled(filter.dtype(), TensorShape(post_shuffle(filter)));
    filter_shuffled.tensor<T, 5>().device(device, on_shuffled) = filter.shaped<T, 5>(pre_shuffle(filter)).shuffle(shuffle);

    
    shuffles_completed.Wait();

    
    Tensor output_shuffled(output->dtype(), TensorShape(post_shuffle(*output)));

    for (int64 i = 0; i < num_groups; ++i) {
      
      
      
      

      
      

      auto input_slice = input_shuffled.tensor<T, 5>().template chip<0>(i);
      auto filter_slice = filter_shuffled.tensor<T, 5>().template chip<0>(i);
      auto output_slice = output_shuffled.tensor<T, 5>().template chip<0>(i);

      if (padding == EXPLICIT) {
        functor::SpatialConvolution<CPUDevice, T>()( ctx->eigen_device<CPUDevice>(), output_slice, input_slice, filter_slice, row_stride, col_stride, row_dilation, col_dilation, static_cast<int>(explicit_paddings[2]), static_cast<int>(explicit_paddings[3]), static_cast<int>(explicit_paddings[4]), static_cast<int>(explicit_paddings[5]));





      } else {
        functor::SpatialConvolution<CPUDevice, T>()( ctx->eigen_device<CPUDevice>(), output_slice, input_slice, filter_slice, row_stride, col_stride, row_dilation, col_dilation, BrainPadding2EigenPadding(padding));


      }
    }

    
    std::array<int64, 5> rev_shuffle({1, 2, 3, 0, 4});
    output->shaped<T, 5>(pre_shuffle(*output)).device(device) = output_shuffled.tensor<T, 5>().shuffle(rev_shuffle);
  }
};

}  

template <typename T> struct LaunchConv2DOp<CPUDevice, T> {
  void operator()(OpKernelContext* ctx, bool use_cudnn, bool cudnn_use_autotune, const Tensor& input, const Tensor& filter, int row_dilation, int col_dilation, int row_stride, int col_stride, const Padding& padding, const std::vector<int64>& explicit_paddings, Tensor* output, TensorFormat data_format) {




    if (data_format != FORMAT_NHWC) {
      ctx->SetStatus(errors::Unimplemented( "The Conv2D op currently only supports the NHWC tensor format on the " "CPU. The op was given the format: ", ToString(data_format)));


      return;
    }

    for (int64 explicit_padding : explicit_paddings) {
      if (!FastBoundsCheck(explicit_padding, std::numeric_limits<int>::max())) {
        ctx->SetStatus(errors::InvalidArgument("filter too large"));
        return;
      }
    }

    const int64 in_depth = input.dim_size(3);
    const int64 out_depth = output->dim_size(3);
    const int64 patch_depth = filter.dim_size(2);

    if (in_depth % patch_depth != 0) {
      ctx->SetStatus(errors::InvalidArgument( "input depth must be evenly divisible by filter depth: ", in_depth, " vs ", patch_depth));

      return;
    }

    const int64 num_groups = in_depth / patch_depth;
    if (out_depth % num_groups != 0 || out_depth < num_groups) {
      ctx->SetStatus(errors::InvalidArgument( "output depth must be evenly divisible by number of groups: ", out_depth, " vs ", num_groups));

      return;
    }

    if (in_depth != patch_depth) {
      LaunchGrouped<T>()(ctx, input, filter, row_stride, col_stride, row_dilation, col_dilation, padding, explicit_paddings, output, data_format);

    } else {
      LaunchGeneric<CPUDevice, T>()(ctx, input, filter, row_stride, col_stride, row_dilation, col_dilation, padding, explicit_paddings, output, data_format);

    }
  }
};


template <> struct LaunchConv2DOp<GPUDevice, int32> {
  void operator()(OpKernelContext* ctx, bool use_cudnn, bool cudnn_use_autotune, const Tensor& input, const Tensor& filter, int row_dilation, int col_dilation, int row_stride, int col_stride, const Padding& padding, const std::vector<int64>& explicit_paddings, Tensor* output, TensorFormat data_format) {




    if (data_format != FORMAT_NHWC) {
      ctx->SetStatus( errors::Unimplemented("The Conv2D op currently only supports the " "NHWC tensor format for integer types. " "The op was given the format: ", ToString(data_format)));



      return;
    }
    const int64 in_depth = GetTensorDim(input, data_format, 'C');
    OP_REQUIRES(ctx, in_depth == filter.dim_size(2), errors::Unimplemented( "The Conv2D op currently does not support grouped " "convolutions for integer types. A grouped convolution was " "attempted to be run because the input depth of ", in_depth, " does not match the filter input depth of ", filter.dim_size(2)));






    for (int64 explicit_padding : explicit_paddings) {
      if (!FastBoundsCheck(explicit_padding, std::numeric_limits<int>::max())) {
        ctx->SetStatus(errors::InvalidArgument("filter too large"));
        return;
      }
    }
    LaunchGeneric<GPUDevice, int32>()( ctx, input, filter, row_stride, col_stride, row_dilation, col_dilation, padding, explicit_paddings, output, data_format);

  }
};


template <typename Device, typename T> class LaunchDeepConvOp {
 public:
  static bool Run(OpKernelContext* ctx, const Tensor& input, const Tensor& filter, int batch, int input_rows, int input_cols, int in_depth, int filter_rows, int filter_cols, int pad_rows, int pad_cols, int out_rows, int , int , int , int , int , int , Tensor* , TensorFormat ) {






    return false;
  }
};


template <> class LaunchDeepConvOp<CPUDevice, float> {
 public:
  static bool Run(OpKernelContext* ctx, const Tensor& input, const Tensor& filter, int batch, int input_rows, int input_cols, int in_depth, int filter_rows, int filter_cols, int pad_rows, int pad_cols, int out_rows, int out_cols, int out_depth, int dilation_rows, int dilation_cols, int stride_rows, int stride_cols, Tensor* output, TensorFormat data_format) {





    if (data_format != FORMAT_NHWC || dilation_rows != 1 || dilation_cols != 1 || !CanUseDeepConv2D(stride_rows, stride_cols, filter_rows, filter_cols, in_depth, out_depth, out_rows, out_cols)) {


      return false;
    }

    Conv2DArgs args;
    args.batch = batch;
    args.in_rows = input_rows;
    args.in_cols = input_cols;
    args.in_depth = in_depth;
    args.filter_rows = filter_rows;
    args.filter_cols = filter_cols;
    args.pad_rows = pad_rows;
    args.pad_cols = pad_cols;
    args.out_rows = out_rows;
    args.out_cols = out_cols;
    args.out_depth = out_depth;

    auto input_ptr = input.template flat<float>().data();
    auto filter_ptr = filter.template flat<float>().data();
    auto output_ptr = output->template flat<float>().data();

    functor::DeepConv2D<CPUDevice, float>()(ctx, args, input_ptr, filter_ptr, output_ptr);
    return true;
  }
};


template <typename Device, typename T> class LaunchXsmmConvOp {
 public:
  static bool Run(OpKernelContext* ctx, const Tensor& input, const Tensor& filter, int batch, int input_rows, int input_cols, int in_depth, int filter_rows, int filter_cols, int pad_rows, int pad_cols, int out_rows, int out_cols, int out_depth, int stride_rows, int stride_cols, int dilation_rows, int dilation_cols, Tensor* output, TensorFormat data_format) {





    return false;
  }
};

template <> class LaunchXsmmConvOp<CPUDevice, float> {
 public:
  static bool Run(OpKernelContext* ctx, const Tensor& input, const Tensor& filter, int batch, int input_rows, int input_cols, int in_depth, int filter_rows, int filter_cols, int pad_rows, int pad_cols, int out_rows, int out_cols, int out_depth, int dilation_rows, int dilation_cols, int stride_rows, int stride_cols, Tensor* output, TensorFormat data_format) {





    auto num_threads = ctx->device()->tensorflow_cpu_worker_threads()->num_threads;
    
    libxsmm_dnn_conv_desc desc;
    desc.N = batch;
    desc.C = in_depth;
    desc.H = input_rows;
    desc.W = input_cols;
    desc.K = out_depth;
    desc.R = filter_rows;
    desc.S = filter_cols;
    desc.u = stride_rows;
    desc.v = stride_cols;
    desc.pad_h = pad_rows;
    desc.pad_w = pad_cols;
    desc.pad_h_in = 0;
    desc.pad_w_in = 0;
    desc.pad_h_out = 0;
    desc.pad_w_out = 0;
    desc.threads = num_threads;
    desc.algo = LIBXSMM_DNN_CONV_ALGO_DIRECT;
    desc.buffer_format = LIBXSMM_DNN_TENSOR_FORMAT_NHWC;
    desc.filter_format = LIBXSMM_DNN_TENSOR_FORMAT_LIBXSMM;
    desc.fuse_ops = LIBXSMM_DNN_CONV_FUSE_NONE;
    desc.options = LIBXSMM_DNN_CONV_OPTION_OVERWRITE;
    desc.datatype_out = LIBXSMM_DNN_DATATYPE_F32;
    desc.datatype_in = LIBXSMM_DNN_DATATYPE_F32;
    if (dilation_rows != 1 || dilation_cols != 1 || !CanUseXsmmConv2D(desc, data_format)) {
      return false;
    }

    auto input_ptr = input.template flat<float>().data();
    auto filter_ptr = filter.template flat<float>().data();
    auto output_ptr = output->template flat<float>().data();

    bool success = functor::XsmmFwdConv2D<CPUDevice, float>()( ctx, desc, input_ptr, filter_ptr, output_ptr);
    return success;
  }
};






Status InitConv2DParameters(const OpKernelConstruction* context, Conv2DParameters* params) {
  TF_RETURN_IF_ERROR(context->GetAttr("dilations", &params->dilations));
  TF_RETURN_IF_ERROR(context->GetAttr("strides", &params->strides));
  TF_RETURN_IF_ERROR(context->GetAttr("padding", &params->padding));
  if (context->HasAttr("explicit_paddings")) {
    TF_RETURN_IF_ERROR( context->GetAttr("explicit_paddings", &params->explicit_paddings));
  }
  string data_format_string;
  TF_RETURN_IF_ERROR(context->GetAttr("data_format", &data_format_string));
  TF_REQUIRES(FormatFromString(data_format_string, &params->data_format), errors::InvalidArgument("Invalid data format"));

  const auto& strides = params->strides;
  const auto& dilations = params->dilations;
  const auto& data_format = params->data_format;

  TF_REQUIRES(dilations.size() == 4, errors::InvalidArgument("Sliding window dilations field must " "specify 4 dimensions"));

  TF_REQUIRES(strides.size() == 4, errors::InvalidArgument("Sliding window strides field must " "specify 4 dimensions"));

  const int64 stride_n = GetTensorDim(strides, data_format, 'N');
  const int64 stride_c = GetTensorDim(strides, data_format, 'C');
  const int64 stride_h = GetTensorDim(strides, data_format, 'H');
  const int64 stride_w = GetTensorDim(strides, data_format, 'W');
  TF_REQUIRES( stride_n == 1 && stride_c == 1, errors::Unimplemented("Current implementation does not yet support " "strides in the batch and depth dimensions."));


  TF_REQUIRES(stride_h > 0 && stride_w > 0, errors::InvalidArgument( "Row and column strides should be larger than 0."));


  const int64 dilation_n = GetTensorDim(dilations, data_format, 'N');
  const int64 dilation_c = GetTensorDim(dilations, data_format, 'C');
  const int64 dilation_h = GetTensorDim(dilations, data_format, 'H');
  const int64 dilation_w = GetTensorDim(dilations, data_format, 'W');
  TF_REQUIRES( dilation_n == 1 && dilation_c == 1, errors::Unimplemented("Current implementation does not yet support " "dilations in the batch and depth dimensions."));


  TF_REQUIRES( dilation_h > 0 && dilation_w > 0, errors::InvalidArgument("Dilated rates should be larger than 0."));


  TF_RETURN_IF_ERROR(CheckValidPadding(params->padding, params->explicit_paddings, 4, data_format));


  return Status::OK();
}

Status ComputeConv2DDimension(const Conv2DParameters& params, const Tensor& input, const Tensor& filter, Conv2DDimensions* dimensions) {

  
  TF_REQUIRES(input.dims() == 4, errors::InvalidArgument("input must be 4-dimensional", input.shape().DebugString()));

  TF_REQUIRES(filter.dims() == 4, errors::InvalidArgument("filter must be 4-dimensional: ", filter.shape().DebugString()));

  for (int i = 0; i < 3; i++) {
    TF_REQUIRES( FastBoundsCheck(filter.dim_size(i), std::numeric_limits<int>::max()), errors::InvalidArgument("filter too large"));

  }

  
  
  const int64 in_depth_raw = GetTensorDim(input, params.data_format, 'C');
  const int64 patch_depth_raw = filter.dim_size(2);
  TF_REQUIRES(FastBoundsCheck(in_depth_raw, std::numeric_limits<int>::max()), errors::InvalidArgument("Input depth too large"));
  TF_REQUIRES(FastBoundsCheck(patch_depth_raw, std::numeric_limits<int>::max()), errors::InvalidArgument("Patch depth too large"));
  const int in_depth = static_cast<int>(in_depth_raw);
  const int patch_depth = static_cast<int>(patch_depth_raw);
  TF_REQUIRES(in_depth % patch_depth == 0, errors::InvalidArgument( "input depth must be evenly divisible by filter depth: ", in_depth, " vs ", patch_depth));



  
  const int out_depth = static_cast<int>(filter.dim_size(3));

  
  
  const int64 input_rows_raw = GetTensorDim(input, params.data_format, 'H');
  TF_REQUIRES(FastBoundsCheck(input_rows_raw, std::numeric_limits<int>::max()), errors::InvalidArgument("Input rows too large"));
  const int input_rows = static_cast<int>(input_rows_raw);
  const int filter_rows = static_cast<int>(filter.dim_size(0));

  
  
  const int64 input_cols_raw = GetTensorDim(input, params.data_format, 'W');
  TF_REQUIRES(FastBoundsCheck(input_cols_raw, std::numeric_limits<int>::max()), errors::InvalidArgument("Input cols too large"));
  const int input_cols = static_cast<int>(input_cols_raw);
  const int filter_cols = static_cast<int>(filter.dim_size(1));

  
  const int64 batch_raw = GetTensorDim(input, params.data_format, 'N');
  TF_REQUIRES(FastBoundsCheck(batch_raw, std::numeric_limits<int>::max()), errors::InvalidArgument("batch is too large"));
  const int batch = static_cast<int>(batch_raw);

  
  
  const int stride_rows = GetTensorDim(params.strides, params.data_format, 'H');
  const int stride_cols = GetTensorDim(params.strides, params.data_format, 'W');
  const int dilation_rows = GetTensorDim(params.dilations, params.data_format, 'H');
  const int dilation_cols = GetTensorDim(params.dilations, params.data_format, 'W');

  int64 pad_rows_before, pad_rows_after, pad_cols_before, pad_cols_after;
  if (params.padding == Padding::EXPLICIT) {
    GetExplicitPaddingForDim(params.explicit_paddings, params.data_format, 'H', &pad_rows_before, &pad_rows_after);
    GetExplicitPaddingForDim(params.explicit_paddings, params.data_format, 'W', &pad_cols_before, &pad_cols_after);
  }

  
  int64 out_rows = 0, out_cols = 0;
  TF_RETURN_IF_ERROR(GetWindowedOutputSizeVerboseV2( input_rows, filter_rows, dilation_rows, stride_rows, params.padding, &out_rows, &pad_rows_before, &pad_rows_after));

  TF_RETURN_IF_ERROR(GetWindowedOutputSizeVerboseV2( input_cols, filter_cols, dilation_cols, stride_cols, params.padding, &out_cols, &pad_cols_before, &pad_cols_after));


  dimensions->batch = batch;
  dimensions->input_rows = input_rows;
  dimensions->input_cols = input_cols;
  dimensions->in_depth = in_depth;
  dimensions->filter_rows = filter_rows;
  dimensions->filter_cols = filter_cols;
  dimensions->patch_depth = patch_depth;
  dimensions->out_depth = out_depth;
  dimensions->stride_rows = stride_rows;
  dimensions->stride_cols = stride_cols;
  dimensions->dilation_rows = dilation_rows;
  dimensions->dilation_cols = dilation_cols;
  dimensions->out_rows = out_rows;
  dimensions->out_cols = out_cols;
  dimensions->pad_rows_before = pad_rows_before;
  dimensions->pad_rows_after = pad_rows_after;
  dimensions->pad_cols_before = pad_cols_before;
  dimensions->pad_cols_after = pad_cols_after;

  return Status::OK();
}



template <typename Device, typename T> class Conv2DOp : public BinaryOp<T> {
 public:
  explicit Conv2DOp(OpKernelConstruction* context) : BinaryOp<T>(context) {
    OP_REQUIRES_OK(context, InitConv2DParameters(context, &params_));

    OP_REQUIRES_OK(context, context->GetAttr("use_cudnn_on_gpu", &use_cudnn_));
    cudnn_use_autotune_ = CudnnUseAutotune();
  }

  void Compute(OpKernelContext* context) override {
    
    
    const Tensor& input = context->input(0);

    
    
    const Tensor& filter = context->input(1);

    Conv2DDimensions dimensions;
    OP_REQUIRES_OK(context, ComputeConv2DDimension(params_, input, filter, &dimensions));

    TensorShape out_shape = ShapeFromFormat( params_.data_format, dimensions.batch, dimensions.out_rows, dimensions.out_cols, dimensions.out_depth);


    
    
    Tensor* output = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output(0, out_shape, &output));

    VLOG(2) << "Conv2D: in_depth = " << dimensions.in_depth << ", patch_depth = " << dimensions.patch_depth << ", input_cols = " << dimensions.input_cols << ", filter_cols = " << dimensions.filter_cols << ", input_rows = " << dimensions.input_rows << ", filter_rows = " << dimensions.filter_rows << ", stride_rows = " << dimensions.stride_rows << ", stride_cols = " << dimensions.stride_cols << ", dilation_rows = " << dimensions.dilation_rows << ", dilation_cols = " << dimensions.dilation_cols << ", out_depth = " << dimensions.out_depth;










    
    if (out_shape.num_elements() == 0) {
      return;
    }


    if (params_.padding != EXPLICIT && LaunchXsmmConvOp<Device, T>::Run( context, input, filter, dimensions.batch, dimensions.input_rows, dimensions.input_cols, dimensions.in_depth, dimensions.filter_rows, dimensions.filter_cols, dimensions.pad_rows_before, dimensions.pad_cols_before, dimensions.out_rows, dimensions.out_cols, dimensions.out_depth, dimensions.dilation_rows, dimensions.dilation_cols, dimensions.stride_rows, dimensions.stride_cols, output, params_.data_format)) {







      return;
    }


    if (params_.padding != EXPLICIT && LaunchDeepConvOp<Device, T>::Run( context, input, filter, dimensions.batch, dimensions.input_rows, dimensions.input_cols, dimensions.in_depth, dimensions.filter_rows, dimensions.filter_cols, dimensions.pad_rows_before, dimensions.pad_cols_before, dimensions.out_rows, dimensions.out_cols, dimensions.out_depth, dimensions.dilation_rows, dimensions.dilation_cols, dimensions.stride_rows, dimensions.stride_cols, output, params_.data_format)) {







      return;
    }

    launcher_(context, use_cudnn_, cudnn_use_autotune_, input, filter, dimensions.dilation_rows, dimensions.dilation_cols, dimensions.stride_rows, dimensions.stride_cols, params_.padding, params_.explicit_paddings, output, params_.data_format);


  }

 private:
  Conv2DParameters params_;
  bool use_cudnn_;
  bool cudnn_use_autotune_;

  LaunchConv2DOp<Device, T> launcher_;

  TF_DISALLOW_COPY_AND_ASSIGN(Conv2DOp);
};








TF_CALL_half(REGISTER_CPU);
TF_CALL_float(REGISTER_CPU);
TF_CALL_double(REGISTER_CPU);
TF_CALL_int32(REGISTER_CPU);



template struct LaunchConv2DOp<CPUDevice, Eigen::half>;
template struct LaunchConv2DOp<CPUDevice, float>;
template struct LaunchConv2DOp<CPUDevice, double>;



int64 GetDnnWorkspaceLimit(const string& envvar_in_mb, int64 default_value_in_bytes) {
  const char* workspace_limit_in_mb_str = getenv(envvar_in_mb.c_str());
  if (workspace_limit_in_mb_str != nullptr && strcmp(workspace_limit_in_mb_str, "") != 0) {
    int64 scratch_limit_in_mb = -1;
    if (strings::safe_strto64(workspace_limit_in_mb_str, &scratch_limit_in_mb)) {
      return scratch_limit_in_mb * (1 << 20);
    } else {
      LOG(WARNING) << "Invalid value for env-var " << envvar_in_mb << ": " << workspace_limit_in_mb_str;
    }
  }
  return default_value_in_bytes;
}


struct ConvAutoTuneGroup {
  static string name() { return "Conv"; }
};

typedef AutoTuneSingleton<ConvAutoTuneGroup, ConvParameters, se::dnn::AlgorithmConfig> AutoTuneConv;


template <typename T> void LaunchConv2DOp<GPUDevice, T>::operator()( OpKernelContext* ctx, bool use_cudnn, bool cudnn_use_autotune, const Tensor& input_param, const Tensor& filter, int row_dilation, int col_dilation, int row_stride, int col_stride, const Padding& padding, const std::vector<int64>& explicit_paddings, Tensor* output, TensorFormat data_format) {





  using se::dnn::AlgorithmConfig;
  using se::dnn::AlgorithmDesc;
  using se::dnn::ProfileResult;
  auto* stream = ctx->op_device_context()->stream();
  OP_REQUIRES(ctx, stream, errors::Internal("No GPU stream available."));

  if (!use_cudnn) {
    ctx->SetStatus( errors::Unimplemented("Conv2D for GPU is not currently supported " "without cudnn"));

    return;
  }

  Tensor input = input_param;
  const int64 in_batch = GetTensorDim(input, data_format, 'N');
  int64 in_rows = GetTensorDim(input, data_format, 'H');
  int64 in_cols = GetTensorDim(input, data_format, 'W');
  const int64 in_depths = GetTensorDim(input, data_format, 'C');
  const int64 patch_rows = filter.dim_size(0);
  const int64 patch_cols = filter.dim_size(1);
  const int64 patch_depths = filter.dim_size(2);

  
  
  
  bool is_grouped_convolution = patch_depths != in_depths;
  if (patch_rows == 1 && patch_cols == 1 && !is_grouped_convolution && row_dilation == 1 && col_dilation == 1 && row_stride == 1 && col_stride == 1 && data_format == FORMAT_NHWC && (padding == VALID || padding == SAME)) {


    
    const uint64 m = in_batch * in_rows * in_cols;
    const uint64 k = patch_depths;
    const uint64 n = filter.dim_size(3);

    auto a_ptr = AsDeviceMemory(input.template flat<T>().data(), input.template flat<T>().size());
    auto b_ptr = AsDeviceMemory(filter.template flat<T>().data(), filter.template flat<T>().size());
    auto c_ptr = AsDeviceMemory(output->template flat<T>().data(), output->template flat<T>().size());

    auto no_transpose = se::blas::Transpose::kNoTranspose;
    bool blas_launch_status = stream ->ThenBlasGemm(no_transpose, no_transpose, n, m, k, 1.0f, b_ptr, n, a_ptr, k, 0.0f, &c_ptr, n)


            .ok();
    if (!blas_launch_status) {
      ctx->SetStatus(errors::Internal("Blas SGEMM launch failed : m=", m, ", n=", n, ", k=", k));
    }
    return;
  } else if (patch_rows == in_rows && patch_cols == in_cols && !is_grouped_convolution && row_dilation == 1 && col_dilation == 1 && padding == VALID && data_format == FORMAT_NHWC) {


    
    
    const uint64 m = in_batch;
    const uint64 k = patch_rows * patch_cols * patch_depths;
    const uint64 n = filter.dim_size(3);

    auto a_ptr = AsDeviceMemory(input.template flat<T>().data(), input.template flat<T>().size());
    auto b_ptr = AsDeviceMemory(filter.template flat<T>().data(), filter.template flat<T>().size());
    auto c_ptr = AsDeviceMemory(output->template flat<T>().data(), output->template flat<T>().size());

    auto no_transpose = se::blas::Transpose::kNoTranspose;
    bool blas_launch_status = stream ->ThenBlasGemm(no_transpose, no_transpose, n, m, k, 1.0f, b_ptr, n, a_ptr, k, 0.0f, &c_ptr, n)


            .ok();
    if (!blas_launch_status) {
      ctx->SetStatus(errors::Internal("Blas SGEMM launch failed : m=", m, ", n=", n, ", k=", k));
    }
    return;
  }


  
  
  
  const bool compute_in_nhwc = DataTypeToEnum<T>::value == DT_HALF && IsVoltaOrLater(*stream->parent());

  
  const bool compute_in_nhwc = false;


  
  
  
  
  const TensorFormat compute_data_format = (compute_in_nhwc && data_format == FORMAT_NHWC) ? FORMAT_NHWC : FORMAT_NCHW;


  VLOG(3) << "Compute Conv2D with cuDNN:" << " data_format=" << ToString(data_format)
          << " compute_data_format=" << ToString(compute_data_format);

  const int64 out_batch = GetTensorDim(*output, data_format, 'N');
  const int64 out_rows = GetTensorDim(*output, data_format, 'H');
  const int64 out_cols = GetTensorDim(*output, data_format, 'W');
  const int64 out_depths = GetTensorDim(*output, data_format, 'C');
  int64 padding_top = -1, padding_bottom = -1;
  int64 padding_left = -1, padding_right = -1;
  if (padding == EXPLICIT) {
    GetExplicitPaddingForDim(explicit_paddings, data_format, 'H', &padding_top, &padding_bottom);
    GetExplicitPaddingForDim(explicit_paddings, data_format, 'W', &padding_left, &padding_right);
  }
  int64 out_rows_check, out_cols_check;
  Status status = GetWindowedOutputSizeVerboseV2( in_rows, patch_rows, row_dilation, row_stride, padding, &out_rows_check, &padding_top, &padding_bottom);

  
  
  TF_CHECK_OK(status);
  DCHECK_EQ(out_rows, out_rows_check);
  status = GetWindowedOutputSizeVerboseV2(in_cols, patch_cols, col_dilation, col_stride, padding, &out_cols_check, &padding_left, &padding_right);

  TF_CHECK_OK(status);
  DCHECK_EQ(out_cols, out_cols_check);

  const int64 common_padding_rows = std::min(padding_top, padding_bottom);
  const int64 common_padding_cols = std::min(padding_left, padding_right);
  if (padding_top != padding_bottom || padding_left != padding_right) {
    
    
    
    VLOG(4) << "Pad input tensor:" << " padding_top=" << padding_top << " padding_bottom=" << padding_bottom << " padding_left=" << padding_left << " padding_right=" << padding_right;




    
    
    
    
    
    Tensor transformed_input;
    const int64 padding_rows_diff = std::abs(padding_bottom - padding_top);
    const int64 padding_cols_diff = std::abs(padding_right - padding_left);
    const int64 new_in_rows = in_rows + padding_rows_diff;
    const int64 new_in_cols = in_cols + padding_cols_diff;
    OP_REQUIRES_OK(ctx, ctx->allocate_temp( DataTypeToEnum<T>::value, ShapeFromFormat(data_format, in_batch, new_in_rows, new_in_cols, in_depths), &transformed_input));




    const int64 input_pad_top = padding_top - common_padding_rows;
    const int64 input_pad_bottom = padding_bottom - common_padding_rows;
    const int64 input_pad_left = padding_left - common_padding_cols;
    const int64 input_pad_right = padding_right - common_padding_cols;
    bool in_bounds = FastBoundsCheck(input_pad_top, std::numeric_limits<int>::max()) && FastBoundsCheck(input_pad_bottom, std::numeric_limits<int>::max()) && FastBoundsCheck(input_pad_left, std::numeric_limits<int>::max()) && FastBoundsCheck(input_pad_right, std::numeric_limits<int>::max());



    if (!in_bounds) {
      ctx->SetStatus(errors::InvalidArgument("Padding is too large."));
      return;
    }
    functor::PadInput<GPUDevice, T, int, 4>()( ctx->eigen_device<GPUDevice>(), To32Bit(input_param.tensor<T, 4>()), {{static_cast<int>(input_pad_top), static_cast<int>(input_pad_left)}}, {{static_cast<int>(input_pad_bottom), static_cast<int>(input_pad_right)}}, To32Bit(transformed_input.tensor<T, 4>()), data_format, T{});





    input = transformed_input;
    in_rows = new_in_rows;
    in_cols = new_in_cols;
  }

  if (data_format == FORMAT_NHWC && compute_data_format == FORMAT_NCHW) {
    VLOG(4) << "Convert the input tensor from NHWC to NCHW.";

    TensorShape nchw_shape = ShapeFromFormat(FORMAT_NCHW, in_batch, in_rows, in_cols, in_depths);
    if (in_depths > 1) {
      Tensor transformed_input;
      OP_REQUIRES_OK(ctx, ctx->allocate_temp(DataTypeToEnum<T>::value, nchw_shape, &transformed_input));
      functor::NHWCToNCHW<GPUDevice, T, 4>()( ctx->eigen_device<GPUDevice>(), const_cast<const Tensor&>(input).tensor<T, 4>(), transformed_input.tensor<T, 4>());


      input = transformed_input;
    } else {
      
      CHECK(input.CopyFrom(input, nchw_shape));
    }
  } else {
    CHECK(data_format == compute_data_format)  
        << "Illegal data and compute format pair:" << " data_format=" << ToString(data_format)
        << " compute_data_format=" << ToString(compute_data_format);
  }

  CHECK(common_padding_rows >= 0 && common_padding_cols >= 0)  
      << "Negative row or col paddings: (" << common_padding_rows << ", " << common_padding_cols << ")";

  constexpr auto kComputeInNHWC = std::make_tuple(se::dnn::DataLayout::kBatchYXDepth, se::dnn::FilterLayout::kOutputYXInput);

  constexpr auto kComputeInNCHW = std::make_tuple(se::dnn::DataLayout::kBatchDepthYX, se::dnn::FilterLayout::kOutputInputYX);


  se::dnn::DataLayout compute_data_layout;
  se::dnn::FilterLayout filter_layout;

  std::tie(compute_data_layout, filter_layout) = compute_data_format == FORMAT_NHWC ? kComputeInNHWC : kComputeInNCHW;

  se::dnn::BatchDescriptor input_desc;
  input_desc.set_count(in_batch)
      .set_feature_map_count(in_depths)
      .set_height(in_rows)
      .set_width(in_cols)
      .set_layout(compute_data_layout);
  se::dnn::BatchDescriptor output_desc;
  output_desc.set_count(out_batch)
      .set_height(out_rows)
      .set_width(out_cols)
      .set_feature_map_count(out_depths)
      .set_layout(compute_data_layout);
  se::dnn::FilterDescriptor filter_desc;
  filter_desc.set_input_filter_height(patch_rows)
      .set_input_filter_width(patch_cols)
      .set_input_feature_map_count(patch_depths)
      .set_output_feature_map_count(filter.dim_size(3))
      .set_layout(filter_layout);
  se::dnn::ConvolutionDescriptor conv_desc;
  conv_desc.set_vertical_dilation_rate(row_dilation)
      .set_horizontal_dilation_rate(col_dilation)
      .set_vertical_filter_stride(row_stride)
      .set_horizontal_filter_stride(col_stride)
      .set_zero_padding_height(common_padding_rows)
      .set_zero_padding_width(common_padding_cols)
      .set_group_count(in_depths / patch_depths);

  Tensor transformed_filter;

  const auto transform_filter = [&](FilterTensorFormat dst_format) -> Status {
    VLOG(4) << "Transform filter tensor from " << ToString(FORMAT_HWIO)
            << " to " << ToString(dst_format);

    TensorShape dst_shape = dst_format == FORMAT_OIHW ? TensorShape({filter.dim_size(3), filter.dim_size(2), filter.dim_size(0), filter.dim_size(1)})


            : TensorShape({filter.dim_size(3), filter.dim_size(0), filter.dim_size(1), filter.dim_size(2)});

    TF_RETURN_IF_ERROR(ctx->allocate_temp(DataTypeToEnum<T>::value, dst_shape, &transformed_filter));
    functor::TransformFilter<GPUDevice, T, int, 4>()( ctx->eigen_device<GPUDevice>(), dst_format, To32Bit(filter.tensor<T, 4>()), To32Bit(transformed_filter.tensor<T, 4>()));



    return Status::OK();
  };

  if (compute_data_format == FORMAT_NCHW) {
    OP_REQUIRES_OK(ctx, transform_filter(FORMAT_OIHW));
  } else if (compute_data_format == FORMAT_NHWC) {
    OP_REQUIRES_OK(ctx, transform_filter(FORMAT_OHWI));
  } else {
    ctx->SetStatus(errors::InvalidArgument("Invalid compute data format: ", ToString(compute_data_format)));
    return;
  }

  Tensor transformed_output;
  if (data_format != compute_data_format) {
    VLOG(4) << "Allocate temporary memory for output in compute data format";
    OP_REQUIRES_OK( ctx, ctx->allocate_temp(DataTypeToEnum<T>::value, ShapeFromFormat(compute_data_format, out_batch, out_rows, out_cols, out_depths), &transformed_output));



  } else {
    transformed_output = *output;
  }

  auto input_ptr = AsDeviceMemory(input.template flat<T>().data(), input.template flat<T>().size());
  auto filter_ptr = AsDeviceMemory(transformed_filter.template flat<T>().data(), transformed_filter.template flat<T>().size());

  auto output_ptr = AsDeviceMemory(transformed_output.template flat<T>().data(), transformed_output.template flat<T>().size());


  static int64 ConvolveScratchSize = GetDnnWorkspaceLimit(  "TF_CUDNN_WORKSPACE_LIMIT_IN_MB", 1LL << 32 );



  int device_id = stream->parent()->device_ordinal();
  DataType dtype = input.dtype();
  ConvParameters conv_parameters = {in_batch,              in_depths, {{in_rows, in_cols}}, compute_data_format, out_depths, {{patch_rows, patch_cols, patch_depths}}, {{row_dilation, col_dilation}}, {{row_stride, col_stride}}, {{common_padding_rows, common_padding_cols}}, dtype, device_id, conv_desc.group_count()};
















  AlgorithmConfig algorithm_config;

  
  
  
  cudnn_use_autotune = true;


  if (cudnn_use_autotune && !AutoTuneConv::GetInstance()->Find(conv_parameters, &algorithm_config)) {
    std::vector<std::unique_ptr<se::dnn::ConvolveExecutionPlan>> plans;

    std::vector<AlgorithmDesc> algorithms;
    std::vector<AlgorithmConfig> configs;
    if (CudnnUseFrontend()) {
      OP_REQUIRES( ctx, stream->parent()->GetConvolveExecutionPlans( se::dnn::ConvolutionKind::FORWARD, se::dnn::ToDataType<T>::value, stream, input_desc, filter_desc, output_desc, conv_desc, &plans), errors::Unknown("Failed to get convolution algorithm. This is " "probably because cuDNN failed to initialize, so try " "looking to see if a warning log message was printed " "above."));







      for (const auto& plan : plans) {
        configs.push_back( AlgorithmConfig(AlgorithmDesc{plan->getTag(), plan->get_raw_desc()}, plan->getWorkspaceSize()));

      }
    } else {
      OP_REQUIRES( ctx, stream->parent()->GetConvolveAlgorithms( conv_parameters.ShouldIncludeWinogradNonfusedAlgo<T>( stream->parent()), &algorithms), errors::Unknown("Failed to get convolution algorithm. This is " "probably because cuDNN failed to initialize, so try " "looking to see if a warning log message was printed " "above."));








      for (const auto& algorithm : algorithms) {
        configs.push_back(AlgorithmConfig(algorithm));
      }
    }

    se::TfAllocatorAdapter tf_allocator_adapter(ctx->device()->GetAllocator({}), stream);
    se::RedzoneAllocator rz_allocator(stream, &tf_allocator_adapter, se::GpuAsmOpts());
    se::DeviceMemory<T> output_tensor( WrapRedzoneBestEffort(&rz_allocator, output_ptr));

    std::vector<tensorflow::AutotuneResult> results;
    for (const auto& profile_config : configs) {
      
      
      se::RedzoneAllocator rz_scratch_allocator( stream, &tf_allocator_adapter, se::GpuAsmOpts(), ConvolveScratchSize);

      DnnScratchAllocator scratch_allocator(ConvolveScratchSize, ctx);
      se::ScratchAllocator* allocator_used = !RedzoneCheckDisabled()
              ? static_cast<se::ScratchAllocator*>(&rz_scratch_allocator)
              : static_cast<se::ScratchAllocator*>(&scratch_allocator);

      ProfileResult profile_result;
      Status cudnn_launch_status;
      if (CudnnUseFrontend()) {
        cudnn_launch_status = stream->ConvolveWithExecutionPlan( input_desc, input_ptr, filter_desc, filter_ptr, conv_desc, output_desc, &output_tensor, allocator_used, profile_config, &profile_result);


      } else {
        cudnn_launch_status = stream->ConvolveWithAlgorithm( input_desc, input_ptr, filter_desc, filter_ptr, conv_desc, output_desc, &output_tensor, allocator_used, profile_config, &profile_result);


      }

      if (cudnn_launch_status.ok() && profile_result.is_valid()) {
        results.emplace_back();
        auto& result = results.back();
        if (CudnnUseFrontend()) {
          result.mutable_cuda_conv_plan()->set_exec_plan_id( profile_config.algorithm()->exec_plan_id());
        } else {
          result.mutable_conv()->set_algorithm( profile_config.algorithm()->algo_id());
          result.mutable_conv()->set_tensor_ops_enabled( profile_config.algorithm()->tensor_ops_enabled());
        }

        result.set_scratch_bytes( !RedzoneCheckDisabled()
                ? rz_scratch_allocator.TotalAllocatedBytesExcludingRedzones()
                : scratch_allocator.TotalByteSize());
        *result.mutable_run_time() = proto_utils::ToDurationProto( absl::Milliseconds(profile_result.elapsed_time_in_ms()));

        CheckRedzones(rz_scratch_allocator, &result);
        CheckRedzones(rz_allocator, &result);
      } else if (CudnnUseFrontend()) {
        
        
        
        results.emplace_back();
        auto& result = results.back();
        result.mutable_failure()->set_kind(AutotuneResult::UNKNOWN);
        result.mutable_failure()->set_msg( absl::StrCat("Profiling failure on CUDNN engine: ", profile_config.algorithm()->exec_plan_id()));

      }
    }


    DnnScratchAllocator scratch_allocator(ConvolveScratchSize, ctx);

    std::vector<ProfileResult> algorithms;
    OP_REQUIRES( ctx, stream->parent()->GetMIOpenConvolveAlgorithms( se::dnn::ConvolutionKind::FORWARD, se::dnn::ToDataType<T>::value, stream, input_desc, input_ptr, filter_desc, filter_ptr, output_desc, output_ptr, conv_desc, &scratch_allocator, &algorithms), errors::Unknown( "Failed to get convolution algorithm. This is probably " "because MIOpen failed to initialize, so try looking to " "see if a warning log message was printed above."));








    se::DeviceMemory<T> output_tensor = output_ptr;

    std::vector<tensorflow::AutotuneResult> results;
    if (algorithms.size() == 1) {
      auto profile_result = algorithms[0];
      results.emplace_back();
      auto& result = results.back();
      result.mutable_conv()->set_algorithm( profile_result.algorithm().algo_id());
      result.mutable_conv()->set_tensor_ops_enabled( profile_result.algorithm().tensor_ops_enabled());

      result.set_scratch_bytes(profile_result.scratch_size());
      *result.mutable_run_time() = proto_utils::ToDurationProto( absl::Milliseconds(profile_result.elapsed_time_in_ms()));
    } else {
      for (auto miopen_algorithm : algorithms) {
        auto profile_algorithm = miopen_algorithm.algorithm();
        ProfileResult profile_result;
        auto miopen_launch_status = stream->ConvolveWithAlgorithm( input_desc, input_ptr, filter_desc, filter_ptr, conv_desc, output_desc, &output_ptr, &scratch_allocator, AlgorithmConfig(profile_algorithm, miopen_algorithm.scratch_size()), &profile_result);



        if (miopen_launch_status.ok() && profile_result.is_valid()) {
          results.emplace_back();
          auto& result = results.back();
          result.mutable_conv()->set_algorithm(profile_algorithm.algo_id());
          result.mutable_conv()->set_tensor_ops_enabled( profile_algorithm.tensor_ops_enabled());

          result.set_scratch_bytes(scratch_allocator.TotalByteSize());
          *result.mutable_run_time() = proto_utils::ToDurationProto( absl::Milliseconds(profile_result.elapsed_time_in_ms()));
        }
      }
    }

    LogConvAutotuneResults(se::dnn::ConvolutionKind::FORWARD, se::dnn::ToDataType<T>::value, input_ptr, filter_ptr, output_tensor, input_desc, filter_desc, output_desc, conv_desc, stream->parent(), results);



    if (CudnnUseFrontend()) {
      OP_REQUIRES_OK( ctx, BestCudnnConvAlgorithm(results, &plans, &algorithm_config));

    } else {
      OP_REQUIRES_OK( ctx, BestCudnnConvAlgorithm(results, nullptr, &algorithm_config));
    }

    AutoTuneConv::GetInstance()->Insert(conv_parameters, algorithm_config);
  }

  Status cudnn_launch_status;
  DnnScratchAllocator scratch_allocator(ConvolveScratchSize, ctx);
  if (CudnnUseFrontend()) {
    if (algorithm_config.algorithm().has_value()) {
      VLOG(4) << "Conv2D Execution Plan: " << algorithm_config.algorithm()->exec_plan_id();
    } else {
      VLOG(4) << "Convolution AutoTune has been turned off";
    }
    cudnn_launch_status = stream->ConvolveWithExecutionPlan( input_desc, input_ptr, filter_desc, filter_ptr, conv_desc, output_desc, &output_ptr, &scratch_allocator, algorithm_config, nullptr);

  } else {
    VLOG(4) << "Convolution Algorithm: " << algorithm_config.algorithm()->algo_id();
    VLOG(4) << "tensor_ops_enabled: " << algorithm_config.algorithm()->tensor_ops_enabled();

    cudnn_launch_status = stream->ConvolveWithAlgorithm( input_desc, input_ptr, filter_desc, filter_ptr, conv_desc, output_desc, &output_ptr, &scratch_allocator, algorithm_config, nullptr);

  }

  if (!cudnn_launch_status.ok()) {
    ctx->SetStatus(cudnn_launch_status);
  }

  if (data_format == FORMAT_NHWC && compute_data_format == FORMAT_NCHW) {
    VLOG(4) << "Convert the output tensor back from NCHW to NHWC.";
    functor::NCHWToNHWC<GPUDevice, T, 4>()( ctx->eigen_device<GPUDevice>(), const_cast<const Tensor&>(transformed_output).tensor<T, 4>(), output->tensor<T, 4>());


  }
}


namespace functor {








































DECLARE_GPU_SPEC(float);
DECLARE_GPU_SPEC(Eigen::half);
DECLARE_GPU_SPEC(double);
DECLARE_GPU_SPEC(int32);


}  


REGISTER_KERNEL_BUILDER( Name("Conv2D").Device(DEVICE_GPU).TypeConstraint<Eigen::half>("T"), Conv2DOp<GPUDevice, Eigen::half>);

REGISTER_KERNEL_BUILDER( Name("Conv2D").Device(DEVICE_GPU).TypeConstraint<float>("T"), Conv2DOp<GPUDevice, float>);

REGISTER_KERNEL_BUILDER( Name("Conv2D").Device(DEVICE_GPU).TypeConstraint<double>("T"), Conv2DOp<GPUDevice, double>);

REGISTER_KERNEL_BUILDER( Name("Conv2D").Device(DEVICE_GPU).TypeConstraint<int32>("T"), Conv2DOp<GPUDevice, int32>);



template struct LaunchConv2DOp<GPUDevice, float>;
template struct LaunchConv2DOp<GPUDevice, Eigen::half>;
template struct LaunchConv2DOp<GPUDevice, double>;



}  
