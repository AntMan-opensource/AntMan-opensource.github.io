



























namespace tensorflow {
namespace {


class PoolingOp : public XlaOpKernel {
 public:
  PoolingOp(OpKernelConstruction* ctx, int num_spatial_dims, const DataType reduction_type)
      : XlaOpKernel(ctx), num_spatial_dims_(num_spatial_dims), reduction_type_(reduction_type) {

    if (ctx->num_inputs() == 1) {
      std::vector<int32> ksize_int;
      std::vector<int32> stride_int;
      OP_REQUIRES_OK(ctx, ctx->GetAttr("ksize", &ksize_int));
      OP_REQUIRES(ctx, ksize_int.size() == num_dims(), errors::InvalidArgument("Sliding window ksize field must " "specify ", num_dims(), " dimensions"));


      OP_REQUIRES_OK(ctx, ctx->GetAttr("strides", &stride_int));
      OP_REQUIRES(ctx, stride_int.size() == num_dims(), errors::InvalidArgument("Sliding window stride field must " "specify ", num_dims(), " dimensions"));


      for (int i = 0; i < num_dims(); ++i) {
        ksize_.push_back(ksize_int[i]);
        stride_.push_back(stride_int[i]);
      }
    }
    Padding padding;
    OP_REQUIRES_OK(ctx, ctx->GetAttr("padding", &padding));
    OP_REQUIRES(ctx, padding != EXPLICIT, errors::Unimplemented( "XLA does not support pooling ops with explicit padding."));

    padding_ = (padding == VALID) ? xla::Padding::kValid : xla::Padding::kSame;

    OP_REQUIRES_OK( ctx, DataTypeToPrimitiveType(reduction_type_, &xla_reduction_type_));
  }

  int num_dims() const { return num_spatial_dims_ + 2; }

 protected:
  StatusOr<std::vector<int64_t>> GetKernelSize(XlaOpKernelContext* ctx) {
    if (ctx->num_inputs() == 1) {
      return ksize_;
    }
    const TensorShape ksize_shape = ctx->InputShape(1);
    
    if (!TensorShapeUtils::IsVector(ksize_shape)) {
      return errors::InvalidArgument("ksize must be a vector, not shape ", ksize_shape.DebugString());
    }
    if (ksize_shape.num_elements() != num_dims()) {
      return errors::InvalidArgument( "Sliding window ksize field must " "specify ", num_dims(), " dimensions");


    }
    std::vector<int64_t> ksize;
    auto status = ctx->ConstantInputAsIntVector(1, &ksize);
    if (!status.ok()) {
      return status;
    }
    return ksize;
  }

  StatusOr<std::vector<int64_t>> GetStride(XlaOpKernelContext* ctx) {
    if (ctx->num_inputs() == 1) {
      return stride_;
    }
    const TensorShape stride_shape = ctx->InputShape(2);
    
    if (!TensorShapeUtils::IsVector(stride_shape)) {
      return errors::InvalidArgument("stride must be a vector, not shape ", stride_shape.DebugString());
    }
    if (stride_shape.num_elements() != num_dims()) {
      return errors::InvalidArgument( "Sliding window stride field must " "specify ", num_dims(), " dimensions");


    }
    std::vector<int64_t> stride;
    auto status = ctx->ConstantInputAsIntVector(2, &stride);
    if (!status.ok()) {
      return status;
    }
    return stride;
  }

 protected:
  const int num_spatial_dims_;
  std::vector<int64_t> ksize_;
  std::vector<int64_t> stride_;
  xla::Padding padding_;
  TensorFormat data_format_ = FORMAT_NHWC;
  DataType reduction_type_;
  xla::PrimitiveType xla_reduction_type_;
};



xla::TensorFormat XlaTensorFormat(tensorflow::TensorFormat data_format, int num_spatial_dims) {
  int num_dims = num_spatial_dims + 2;
  int batch_dimension = GetTensorBatchDimIndex(num_dims, data_format);
  int feature_dimension = GetTensorFeatureDimIndex(num_dims, data_format);
  absl::InlinedVector<int64_t, 4> spatial_dimensions(num_spatial_dims);
  for (int spatial_dim = 0; spatial_dim < num_spatial_dims; ++spatial_dim) {
    spatial_dimensions[spatial_dim] = GetTensorSpatialDimIndex(num_dims, data_format, spatial_dim);
  }
  return xla::TensorFormat(batch_dimension, feature_dimension, spatial_dimensions);

}

class MaxPoolOp : public PoolingOp {
 public:
  MaxPoolOp(OpKernelConstruction* ctx, int num_spatial_dims)
      : PoolingOp(ctx, num_spatial_dims, ctx->input_type(0)) {
    std::string data_format_str;
    OP_REQUIRES_OK(ctx, ctx->GetAttr("data_format", &data_format_str));
    OP_REQUIRES(ctx, FormatFromString(data_format_str, &data_format_), errors::InvalidArgument("Invalid data format"));
    OP_REQUIRES(ctx, data_format_ != FORMAT_NHWC_VECT_W, errors::Unimplemented( "XLA does not support the VECT_NHWC_VECT_W data format. " "Returning unimplemented from MaxPool to keep " "Tensorflow's intended optimized MaxPool here."));



  }

  void Compile(XlaOpKernelContext* ctx) override {
    auto ksize_or_error = GetKernelSize(ctx);
    OP_REQUIRES_OK(ctx, ksize_or_error.status());
    std::vector<int64_t> ksize = ksize_or_error.value();

    auto stride_or_error = GetStride(ctx);
    OP_REQUIRES_OK(ctx, stride_or_error.status());
    std::vector<int64_t> stride = stride_or_error.value();

    xla::XlaOp input = ctx->Input(0);

    StatusOr<xla::Shape> input_shape = ctx->builder()->GetShape(input);
    OP_REQUIRES_OK(ctx, input_shape.status());

    
    
    
    std::optional<int64_t> vect_width;
    if (data_format_ == FORMAT_NCHW_VECT_C) {
      vect_width = input_shape->dimensions().back();
      input = xla::Collapse(xla::Transpose(input, {0, 1, 4, 2, 3}), {1, 2});

      input_shape = ctx->builder()->GetShape(input);
      OP_REQUIRES_OK(ctx, input_shape.status());
    }

    OP_REQUIRES(ctx, input_shape->dimensions_size() == num_dims(), errors::InvalidArgument("Input to ", type_string(), " operator must have ", num_dims(), " dimensions"));


    auto pooling = xla::MaxPool( input, ksize, stride, padding_, XlaTensorFormat( data_format_ == FORMAT_NCHW_VECT_C ? FORMAT_NCHW : data_format_, input_shape->dimensions_size() - 2));




    if (data_format_ == FORMAT_NCHW_VECT_C) {
      StatusOr<xla::Shape> result_shape = ctx->builder()->GetShape(pooling);
      OP_REQUIRES_OK(ctx, result_shape.status());

      int64 num_channels = result_shape->dimensions(1);
      OP_REQUIRES( ctx, num_channels % *vect_width == 0, errors::FailedPrecondition("Result of NCHW_VECT_C op must have " "channels multiple of ", *vect_width, ", but was ", num_channels));




      absl::InlinedVector<int64, 5> new_dims(result_shape->dimensions().begin(), result_shape->dimensions().end());
      new_dims[1] /= *vect_width;
      new_dims.insert(new_dims.begin() + 2, *vect_width);
      pooling = xla::Transpose(xla::Reshape(pooling, new_dims), {0, 1, 3, 4, 2});
    }

    ctx->SetOutput(0, pooling);
  }
};

class MaxPool2DOp : public MaxPoolOp {
 public:
  explicit MaxPool2DOp(OpKernelConstruction* ctx)
      : MaxPoolOp(ctx, 2) {}
};
REGISTER_XLA_OP(Name("MaxPool"), MaxPool2DOp);
REGISTER_XLA_OP(Name("MaxPoolV2")
                    .CompileTimeConstantInput("ksize")
                    .CompileTimeConstantInput("strides"), MaxPool2DOp);

class MaxPool3DOp : public MaxPoolOp {
 public:
  explicit MaxPool3DOp(OpKernelConstruction* ctx)
      : MaxPoolOp(ctx, 3) {}
};
REGISTER_XLA_OP(Name("MaxPool3D"), MaxPool3DOp);

class AvgPoolOp : public PoolingOp {
 public:
  AvgPoolOp(OpKernelConstruction* ctx, int num_spatial_dims)
      : PoolingOp(ctx, num_spatial_dims,  XlaHelpers::SumAccumulationType(ctx->input_type(0))) {

    string data_format_str;
    OP_REQUIRES_OK(ctx, ctx->GetAttr("data_format", &data_format_str));
    OP_REQUIRES(ctx, FormatFromString(data_format_str, &data_format_), errors::InvalidArgument("Invalid data format"));
  }

  void Compile(XlaOpKernelContext* ctx) override {
    auto ksize_or_error = GetKernelSize(ctx);
    OP_REQUIRES_OK(ctx, ksize_or_error.status());
    std::vector<int64_t> ksize = ksize_or_error.value();

    auto stride_or_error = GetStride(ctx);
    OP_REQUIRES_OK(ctx, stride_or_error.status());
    std::vector<int64_t> stride = stride_or_error.value();

    const TensorShape input_shape = ctx->InputShape(0);
    OP_REQUIRES(ctx, input_shape.dims() == num_dims(), errors::InvalidArgument("Input to ", type_string(), " operator must have ", num_dims(), " dimensions"));



    auto xla_data_format = XlaTensorFormat(data_format_, input_shape.dims() - 2);
    auto spatial_padding = MakeSpatialPadding( input_shape.dim_sizes(), ksize, stride, padding_, xla_data_format);

    
    auto converted_input = ConvertElementType(ctx->Input(0), xla_reduction_type_);
    auto pooling = xla::AvgPool(converted_input, ksize, stride, spatial_padding, xla_data_format, padding_ == xla::Padding::kValid);

    
    ctx->SetOutput(0, ConvertElementType(pooling, ctx->input_xla_type(0)));
  }
};

class AvgPool2DOp : public AvgPoolOp {
 public:
  explicit AvgPool2DOp(OpKernelConstruction* ctx)
      : AvgPoolOp(ctx, 2) {}
};
REGISTER_XLA_OP(Name("AvgPool"), AvgPool2DOp);

REGISTER_XLA_OP(Name("AvgPool3D"), MlirXlaOpKernel);







class MaxPoolGradOp : public XlaOpKernel {
 public:
  MaxPoolGradOp(OpKernelConstruction* ctx, int num_spatial_dims)
      : XlaOpKernel(ctx), num_spatial_dims_(num_spatial_dims) {
    if (ctx->num_inputs() == 3) {
      OP_REQUIRES_OK(ctx, ctx->GetAttr("ksize", &ksize_));
      OP_REQUIRES_OK(ctx, ctx->GetAttr("strides", &stride_));
    }
    OP_REQUIRES_OK(ctx, ctx->GetAttr("padding", &padding_));
    OP_REQUIRES(ctx, padding_ != EXPLICIT, errors::Unimplemented( "XLA does not support maxpoolgrad with explicit padding."));

    
    
    
    OP_REQUIRES( ctx, !tensorflow::OpDeterminismRequired(), errors::Unimplemented("GPU MaxPool gradient ops do not yet have a " "deterministic XLA implementation."));


  }

  int num_dims() const { return num_spatial_dims_ + 2; }

  void Compile(XlaOpKernelContext* ctx) override {
    if (ctx->num_inputs() != 3) {
      OP_REQUIRES( ctx, ctx->num_inputs() == 5, errors::InvalidArgument("Must supply ksize and stride arguments."));

      const TensorShape ksize_shape = ctx->InputShape(3);
      
      OP_REQUIRES(ctx, TensorShapeUtils::IsVector(ksize_shape), errors::InvalidArgument("ksize must be a vector, not shape ", ksize_shape.DebugString()));

      OP_REQUIRES_OK(ctx, ctx->ConstantInputAsIntVector(3, &ksize_));

      const TensorShape stride_shape = ctx->InputShape(4);
      
      OP_REQUIRES(ctx, TensorShapeUtils::IsVector(stride_shape), errors::InvalidArgument("stride must be a vector, not shape ", stride_shape.DebugString()));

      OP_REQUIRES_OK(ctx, ctx->ConstantInputAsIntVector(4, &stride_));
    }

    OP_REQUIRES(ctx, ksize_.size() == num_dims(), errors::InvalidArgument("Sliding window ksize field must " "specify ", num_dims(), " dimensions"));


    OP_REQUIRES(ctx, stride_.size() == num_dims(), errors::InvalidArgument("Sliding window strides field must " "specify ", num_dims(), " dimensions"));



    const TensorShape tensor_in_shape = ctx->InputShape(0);
    const TensorShape tensor_out_shape = ctx->InputShape(1);
    const TensorShape out_backprop_shape = ctx->InputShape(2);

    
    OP_REQUIRES(ctx, tensor_in_shape.dims() == num_dims(), errors::InvalidArgument("tensor_in must be ", num_dims(), "-dimensional"));

    OP_REQUIRES(ctx, tensor_out_shape.dims() == num_dims(), errors::InvalidArgument("tensor_out must be ", num_dims(), "-dimensional"));

    
    OP_REQUIRES(ctx, out_backprop_shape.dims() == num_dims(), errors::InvalidArgument("out_backprop must be ", num_dims(), "-dimensional"));


    
    
    auto input = ctx->Input(0);
    auto out_backprop = ctx->Input(2);
    
    xla::Padding xla_padding = (padding_ == VALID) ? xla::Padding::kValid : xla::Padding::kSame;

    
    
    TensorShape expected_out_shape;
    auto pooling = xla::MaxPool(ctx->Input(0), ksize_, stride_, xla_padding, XlaTensorFormat(data_format_, tensor_in_shape.dims() - 2));

    auto status_or_shape = pooling.builder()->GetShape(pooling);
    OP_REQUIRES_OK(ctx, status_or_shape.status());
    OP_REQUIRES_OK(ctx, XLAShapeToTensorShape(status_or_shape.value(), &expected_out_shape));
    OP_REQUIRES(ctx, expected_out_shape == out_backprop_shape, errors::Unimplemented("The output dimensions do not match the " "other input values."));


    xla::PrimitiveType element_type;
    OP_REQUIRES_OK(ctx, DataTypeToPrimitiveType(input_type(2), &element_type));
    xla::XlaOp init_value = XlaHelpers::Zero(ctx->builder(), input_type(2));
    auto select = CreateScalarGeComputation(element_type, ctx->builder());
    auto scatter = CreateScalarAddComputation(element_type, ctx->builder());
    xla::XlaOp gradients = xla::SelectAndScatter(input, select, ksize_, stride_, xla_padding, out_backprop, init_value, scatter);


    ctx->SetOutput(0, gradients);
  }

 protected:
  const int num_spatial_dims_;
  std::vector<int64_t> ksize_;
  std::vector<int64_t> stride_;
  Padding padding_;
  TensorFormat data_format_ = FORMAT_NHWC;
};

class MaxPool2DGradOp : public MaxPoolGradOp {
 public:
  explicit MaxPool2DGradOp(OpKernelConstruction* ctx)
      : MaxPoolGradOp(ctx, 2) {
    string data_format;
    OP_REQUIRES_OK(ctx, ctx->GetAttr("data_format", &data_format));
    OP_REQUIRES(ctx, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
  }
};
REGISTER_XLA_OP(Name("MaxPoolGrad"), MaxPool2DGradOp);
REGISTER_XLA_OP(Name("MaxPoolGradV2")
                    .CompileTimeConstantInput("ksize")
                    .CompileTimeConstantInput("strides"), MaxPool2DGradOp);

REGISTER_XLA_OP(Name("MaxPool3DGrad"), MlirXlaOpKernel);


class AvgPoolGradOp : public XlaOpKernel {
 public:
  AvgPoolGradOp(OpKernelConstruction* ctx, int num_spatial_dims)
      : XlaOpKernel(ctx), num_spatial_dims_(num_spatial_dims) {
    OP_REQUIRES_OK(ctx, ctx->GetAttr("ksize", &ksize_));
    OP_REQUIRES(ctx, ksize_.size() == num_dims(), errors::InvalidArgument("Sliding window ksize field must " "specify ", num_dims(), " dimensions"));


    OP_REQUIRES_OK(ctx, ctx->GetAttr("strides", &stride_));
    OP_REQUIRES(ctx, stride_.size() == num_dims(), errors::InvalidArgument("Sliding window strides field must " "specify ", num_dims(), " dimensions"));


    OP_REQUIRES_OK(ctx, ctx->GetAttr("padding", &padding_));
    OP_REQUIRES(ctx, padding_ != EXPLICIT, errors::Unimplemented( "XLA does not support avgpoolgrad with explicit padding."));

    OP_REQUIRES(ctx, ksize_[0] == 1 && stride_[0] == 1, errors::Unimplemented( "Pooling is not yet supported on the batch dimension."));


    string data_format;
    OP_REQUIRES_OK(ctx, ctx->GetAttr("data_format", &data_format));
    OP_REQUIRES(ctx, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
  }

  int num_dims() const { return num_spatial_dims_ + 2; }

  void Compile(XlaOpKernelContext* ctx) override {
    TensorShape gradients_shape;
    OP_REQUIRES_OK( ctx, ctx->ConstantInputAsShape(0, &gradients_shape, xla::ValueInferenceMode::kUpperBound));


    const TensorShape out_backprop_shape = ctx->InputShape(1);

    
    OP_REQUIRES(ctx, gradients_shape.dims() == num_dims(), errors::InvalidArgument("orig_input_shape must be ", num_dims(), "-dimensional"));


    
    OP_REQUIRES(ctx, out_backprop_shape.dims() == num_dims(), errors::InvalidArgument("out_backprop must be ", num_dims(), "-dimensional"));


    auto out_backprop = ctx->Input(1);
    std::vector<int64_t> stride_int64s(stride_.begin(), stride_.end());
    xla::Padding xla_padding = (padding_ == VALID) ? xla::Padding::kValid : xla::Padding::kSame;
    xla::PrimitiveType xla_reduction_type;
    auto reduction_type = XlaHelpers::SumAccumulationType(ctx->input_type(1));
    OP_REQUIRES_OK( ctx, DataTypeToPrimitiveType(reduction_type, &xla_reduction_type));
    auto converted_out_backprop = xla::ConvertElementType(out_backprop, xla_reduction_type);
    auto xla_data_format = XlaTensorFormat(data_format_, gradients_shape.dims() - 2);
    auto padding_values = MakeSpatialPadding(gradients_shape.dim_sizes(), ksize_, stride_int64s, xla_padding, xla_data_format);

    auto in_backprop = xla::AvgPoolGrad(converted_out_backprop, gradients_shape.dim_sizes(), ksize_, stride_int64s, padding_values, xla_data_format, padding_ == VALID);


    
    xla::PrimitiveType xla_out_backprop_type;
    OP_REQUIRES_OK(ctx, DataTypeToPrimitiveType(ctx->input_type(1), &xla_out_backprop_type));
    ctx->SetOutput(0, xla::ConvertElementType(in_backprop, xla_out_backprop_type));
  }

 protected:
  const int num_spatial_dims_;
  std::vector<int64_t> ksize_;
  std::vector<int32> stride_;
  Padding padding_;
  TensorFormat data_format_ = FORMAT_NHWC;
};

class AvgPool2DGradOp : public AvgPoolGradOp {
 public:
  explicit AvgPool2DGradOp(OpKernelConstruction* ctx)
      : AvgPoolGradOp(ctx, 2) {}
};
REGISTER_XLA_OP( Name("AvgPoolGrad").CompileTimeConstantInput("orig_input_shape"), AvgPool2DGradOp);


class AvgPool3DGradOp : public AvgPoolGradOp {
 public:
  explicit AvgPool3DGradOp(OpKernelConstruction* ctx)
      : AvgPoolGradOp(ctx, 3) {}
};
REGISTER_XLA_OP( Name("AvgPool3DGrad").CompileTimeConstantInput("orig_input_shape"), AvgPool3DGradOp);


class MaxPoolGradGradOp : public XlaOpKernel {
 public:
  MaxPoolGradGradOp(OpKernelConstruction* ctx, int num_spatial_dims)
      : XlaOpKernel(ctx), num_spatial_dims_(num_spatial_dims) {
    if (ctx->num_inputs() == 3) {
      OP_REQUIRES_OK(ctx, ctx->GetAttr("ksize", &ksize_));
      OP_REQUIRES_OK(ctx, ctx->GetAttr("strides", &stride_));
    }
    OP_REQUIRES_OK(ctx, ctx->GetAttr("padding", &padding_));
    OP_REQUIRES( ctx, padding_ != EXPLICIT, errors::Unimplemented( "XLA does not support maxpoolgradgrad with explicit padding."));


  }

  int num_dims() const { return num_spatial_dims_ + 2; }

  void Compile(XlaOpKernelContext* ctx) override {
    if (ctx->num_inputs() != 3) {
      OP_REQUIRES( ctx, ctx->num_inputs() == 5, errors::InvalidArgument("Must supply ksize and stride arguments."));

      const TensorShape ksize_shape = ctx->InputShape(3);
      
      OP_REQUIRES(ctx, TensorShapeUtils::IsVector(ksize_shape), errors::InvalidArgument("ksize must be a vector, not shape ", ksize_shape.DebugString()));

      OP_REQUIRES_OK(ctx, ctx->ConstantInputAsIntVector(3, &ksize_));

      const TensorShape stride_shape = ctx->InputShape(4);
      
      OP_REQUIRES(ctx, TensorShapeUtils::IsVector(stride_shape), errors::InvalidArgument("stride must be a vector, not shape ", stride_shape.DebugString()));

      OP_REQUIRES_OK(ctx, ctx->ConstantInputAsIntVector(4, &stride_));
    }

    OP_REQUIRES(ctx, ksize_.size() == num_dims(), errors::InvalidArgument("Sliding window ksize field must " "specify ", num_dims(), " dimensions"));


    OP_REQUIRES(ctx, stride_.size() == num_dims(), errors::InvalidArgument("Sliding window strides field must " "specify ", num_dims(), " dimensions"));



    const TensorShape tensor_in_shape = ctx->InputShape(0);
    const TensorShape tensor_out_shape = ctx->InputShape(1);
    const TensorShape out_backprop_shape = ctx->InputShape(2);

    
    OP_REQUIRES(ctx, tensor_in_shape.dims() == num_dims(), errors::InvalidArgument("tensor_in must be ", num_dims(), "-dimensional"));

    OP_REQUIRES(ctx, tensor_out_shape.dims() == num_dims(), errors::InvalidArgument("tensor_out must be ", num_dims(), "-dimensional"));

    
    OP_REQUIRES(ctx, out_backprop_shape.dims() == num_dims(), errors::InvalidArgument("out_backprop must be ", num_dims(), "-dimensional"));


    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

    auto input = ctx->Input(0);
    auto out_backprop = ctx->Input(2);

    auto b = ctx->builder();

    auto sixteen = xla::ConstantR0<uint32>(b, 16);
    
    
    
    
    
    auto in_hi = xla::BitcastConvertType( xla::ReducePrecision(input, 8, 7), xla::U32);

    auto bp_int = xla::BitcastConvertType(out_backprop, xla::U32);
    auto bp_hi = xla::ShiftRightLogical(bp_int, sixteen);
    auto bp_lo = xla::ShiftRightLogical(xla::ShiftLeft(bp_int, sixteen), sixteen);
    auto in_hi_bp_hi = xla::Add(in_hi, bp_hi);  
    auto in_hi_bp_lo = xla::Add(in_hi, bp_lo);  

    auto init_value = xla::MinValue(b, xla::F32);
    
    
    auto rb = b->CreateSubBuilder("GreaterOrEqOf_ByFirst16Bits");
    {
      
      const xla::Shape scalar = xla::ShapeUtil::MakeShape(xla::F32, {});
      auto lhs = xla::Parameter(rb.get(), 0, scalar, "lhs");
      auto rhs = xla::Parameter(rb.get(), 1, scalar, "rhs");
      auto sixteen = xla::ConstantR0<int32>(rb.get(), 16);
      auto lhs_criteria = xla::ShiftLeft(xla::ShiftRightLogical( xla::BitcastConvertType(lhs, xla::S32), sixteen), sixteen);


      auto rhs_criteria = xla::ShiftLeft(xla::ShiftRightLogical( xla::BitcastConvertType(rhs, xla::S32), sixteen), sixteen);


      
      xla::Select(xla::Ge(xla::BitcastConvertType(lhs_criteria, xla::F32), xla::BitcastConvertType(rhs_criteria, xla::F32)), lhs, rhs);

    }
    auto reduce = rb->BuildAndNoteError();
    xla::Padding xla_padding = (padding_ == VALID) ? xla::Padding::kValid : xla::Padding::kSame;
    auto pooled_hi = xla::ReduceWindow(xla::BitcastConvertType(in_hi_bp_hi, xla::F32), init_value, reduce, ksize_, stride_, xla_padding);

    auto pooled_lo = xla::ReduceWindow(xla::BitcastConvertType(in_hi_bp_lo, xla::F32), init_value, reduce, ksize_, stride_, xla_padding);

    auto grads_hi = xla::ShiftLeft(xla::BitcastConvertType(pooled_hi, xla::U32), sixteen);
    auto grads_lo = xla::ShiftRightLogical( xla::ShiftLeft(xla::BitcastConvertType(pooled_lo, xla::U32), sixteen), sixteen);

    auto grads = xla::Add(grads_hi, grads_lo);  

    xla::PrimitiveType element_type;
    OP_REQUIRES_OK(ctx, DataTypeToPrimitiveType(input_type(2), &element_type));
    ctx->SetOutput(0, xla::BitcastConvertType(grads, element_type));
  }

 protected:
  const int num_spatial_dims_;
  std::vector<int64_t> ksize_;
  std::vector<int64_t> stride_;
  Padding padding_;
  TensorFormat data_format_ = FORMAT_NHWC;
};

class MaxPool2DGradGradOp : public MaxPoolGradGradOp {
 public:
  explicit MaxPool2DGradGradOp(OpKernelConstruction* ctx)
      : MaxPoolGradGradOp(ctx, 2) {
    string data_format;
    OP_REQUIRES_OK(ctx, ctx->GetAttr("data_format", &data_format));
    OP_REQUIRES(ctx, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
  }
};
REGISTER_XLA_OP(Name("MaxPoolGradGrad").TypeConstraint("T", DT_FLOAT), MaxPool2DGradGradOp);
REGISTER_XLA_OP(Name("MaxPoolGradGradV2")
                    .TypeConstraint("T", DT_FLOAT)
                    .CompileTimeConstantInput("ksize")
                    .CompileTimeConstantInput("strides"), MaxPool2DGradGradOp);

class MaxPool3DGradGradOp : public MaxPoolGradGradOp {
 public:
  explicit MaxPool3DGradGradOp(OpKernelConstruction* ctx)
      : MaxPoolGradGradOp(ctx, 3) {
    string data_format;
    OP_REQUIRES_OK(ctx, ctx->GetAttr("data_format", &data_format));
    OP_REQUIRES(ctx, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
  }
};
REGISTER_XLA_OP(Name("MaxPool3DGradGrad").TypeConstraint("T", DT_FLOAT), MaxPool3DGradGradOp);

}  
}  
