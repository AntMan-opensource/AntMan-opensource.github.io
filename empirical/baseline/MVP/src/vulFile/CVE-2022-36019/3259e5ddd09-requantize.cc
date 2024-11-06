















namespace tensorflow {

typedef Eigen::ThreadPoolDevice CPUDevice;

template <class T1, class T2> class RequantizeOp : public OpKernel {
 public:
  explicit RequantizeOp(OpKernelConstruction* ctx) : OpKernel(ctx) {}

  void Compute(OpKernelContext* ctx) override {
    const Tensor& input = ctx->input(0);
    const float input_min_float = ctx->input(1).flat<float>()(0);
    const float input_max_float = ctx->input(2).flat<float>()(0);
    const float requested_output_min_float = ctx->input(3).flat<float>()(0);
    const float requested_output_max_float = ctx->input(4).flat<float>()(0);

    Tensor* output = nullptr;
    OP_REQUIRES_OK(ctx, ctx->allocate_output(0, input.shape(), &output));
    Tensor* output_min = nullptr;
    OP_REQUIRES_OK(ctx, ctx->allocate_output(1, TensorShape({}), &output_min));
    Tensor* output_max = nullptr;
    OP_REQUIRES_OK(ctx, ctx->allocate_output(2, TensorShape({}), &output_max));

    OP_REQUIRES( ctx, requested_output_min_float <= 0.0f, errors::InvalidArgument("requested_output_min must be <= 0, but got ", requested_output_min_float));


    OP_REQUIRES( ctx, requested_output_max_float >= requested_output_min_float, errors::InvalidArgument( "requested_output_max must be >= requested_output_min, but got ", requested_output_max_float, " and ", requested_output_min_float));




    auto input_array = input.flat<T1>();


    
    auto output_array = output->flat<T2>();
    RequantizeManyInNewRange<T1, T2>( input_array.data(), input_array.size(), input_min_float, input_max_float, requested_output_min_float, requested_output_max_float, output_array.data());





    if (input_array.size() > 0) {
      if (meta::IsSupportedAndEnabled() && std::is_same<T1, qint32>() && std::is_same<T2, quint8>()) {
        auto input_i32_array = input.flat<qint32>();
        meta::Requantize(ctx, input_i32_array.data(), input_i32_array.size(), input_min_float, input_max_float, requested_output_min_float, requested_output_max_float, output->flat<quint8>().data());


      } else {
        RequantizeManyInNewRangeUsingEigen<T1, T2>( ctx->eigen_device<CPUDevice>(), input, input_min_float, input_max_float, requested_output_min_float, requested_output_max_float, output);


      }
    }

    output_min->flat<float>().setConstant(requested_output_min_float);
    output_max->flat<float>().setConstant(requested_output_max_float);
  }
};

REGISTER_KERNEL_BUILDER(Name("Requantize")
                            .Device(DEVICE_CPU)
                            .TypeConstraint<qint32>("Tinput")
                            .TypeConstraint<quint8>("out_type"), RequantizeOp<qint32, quint8>);

REGISTER_KERNEL_BUILDER(Name("Requantize")
                            .Device(DEVICE_CPU)
                            .TypeConstraint<qint32>("Tinput")
                            .TypeConstraint<qint8>("out_type"), RequantizeOp<qint32, qint8>);

}  
