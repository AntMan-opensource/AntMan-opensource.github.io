












namespace tensorflow {

typedef Eigen::ThreadPoolDevice CPUDevice;
typedef Eigen::GpuDevice GPUDevice;

namespace functor {

template <typename T, typename Tout> struct HistogramFixedWidthFunctor<CPUDevice, T, Tout> {
  static Status Compute(OpKernelContext* context, const typename TTypes<T, 1>::ConstTensor& values, const typename TTypes<T, 1>::ConstTensor& value_range, int32_t nbins, typename TTypes<Tout, 1>::Tensor& out) {


    const CPUDevice& d = context->eigen_device<CPUDevice>();

    Tensor index_to_bin_tensor;

    TF_RETURN_IF_ERROR(context->forward_input_or_allocate_temp( {0}, DataTypeToEnum<int32>::value, TensorShape({values.size()}), &index_to_bin_tensor));

    auto index_to_bin = index_to_bin_tensor.flat<int32>();

    const double step = static_cast<double>(value_range(1) - value_range(0)) / static_cast<double>(nbins);
    const double nbins_minus_1 = static_cast<double>(nbins - 1);

    
    
    
    
    

    
    
    index_to_bin.device(d) = ((values.cwiseMax(value_range(0)) - values.constant(value_range(0)))
             .template cast<double>() / step)
            .cwiseMin(nbins_minus_1)
            .template cast<int32>();

    out.setZero();
    for (int32_t i = 0; i < index_to_bin.size(); i++) {
      out(index_to_bin(i)) += Tout(1);
    }
    return Status::OK();
  }
};

}  

template <typename Device, typename T, typename Tout> class HistogramFixedWidthOp : public OpKernel {
 public:
  explicit HistogramFixedWidthOp(OpKernelConstruction* ctx) : OpKernel(ctx) {}

  void Compute(OpKernelContext* ctx) override {
    const Tensor& values_tensor = ctx->input(0);
    const Tensor& value_range_tensor = ctx->input(1);
    const Tensor& nbins_tensor = ctx->input(2);

    OP_REQUIRES(ctx, TensorShapeUtils::IsVector(value_range_tensor.shape()), errors::InvalidArgument("value_range should be a vector."));
    OP_REQUIRES(ctx, (value_range_tensor.shape().num_elements() == 2), errors::InvalidArgument( "value_range should be a vector of 2 elements."));

    OP_REQUIRES(ctx, TensorShapeUtils::IsScalar(nbins_tensor.shape()), errors::InvalidArgument("nbins should be a scalar."));

    const auto values = values_tensor.flat<T>();
    const auto value_range = value_range_tensor.flat<T>();
    const auto nbins = nbins_tensor.scalar<int32>()();

    OP_REQUIRES( ctx, (value_range(0) < value_range(1)), errors::InvalidArgument("value_range should satisfy value_range[0] < " "value_range[1], but got '[", value_range(0), ", ", value_range(1), "]'"));



    OP_REQUIRES( ctx, (nbins > 0), errors::InvalidArgument("nbins should be a positive number, but got '", nbins, "'"));



    Tensor* out_tensor;
    OP_REQUIRES_OK(ctx, ctx->allocate_output(0, TensorShape({nbins}), &out_tensor));
    auto out = out_tensor->flat<Tout>();

    OP_REQUIRES_OK( ctx, functor::HistogramFixedWidthFunctor<Device, T, Tout>::Compute( ctx, values, value_range, nbins, out));

  }
};












TF_CALL_REAL_NUMBER_TYPES(REGISTER_KERNELS);











TF_CALL_GPU_NUMBER_TYPES(REGISTER_KERNELS);




}  
