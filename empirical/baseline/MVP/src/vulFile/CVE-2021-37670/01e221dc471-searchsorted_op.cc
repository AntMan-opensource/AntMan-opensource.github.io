













namespace tensorflow {
typedef Eigen::ThreadPoolDevice CPUDevice;
typedef Eigen::GpuDevice GPUDevice;

namespace functor {
template <typename T, typename OutType> struct UpperBoundFunctor<CPUDevice, T, OutType> {
  static Status Compute(OpKernelContext* context, const typename TTypes<T, 1>::ConstTensor& sorted_inputs, const typename TTypes<T, 1>::ConstTensor& values, int batch_size, int num_inputs, int num_values, typename TTypes<OutType, 1>::Tensor* output) {



    
    for (int b = 0; b < batch_size; ++b) {
      const T* sorted_inputs_ptr = sorted_inputs.data() + b * num_inputs;
      OutType* output_ptr = output->data() + b * num_values;
      for (int i = 0; i < num_values; ++i) {
        output_ptr[i] = std::upper_bound(sorted_inputs_ptr, sorted_inputs_ptr + num_inputs, values(i + b * num_values)) - sorted_inputs_ptr;


      }
    }

    return Status::OK();
  }
};

template <typename T, typename OutType> struct LowerBoundFunctor<CPUDevice, T, OutType> {
  static Status Compute(OpKernelContext* context, const typename TTypes<T, 1>::ConstTensor& sorted_inputs, const typename TTypes<T, 1>::ConstTensor& values, int batch_size, int num_inputs, int num_values, typename TTypes<OutType, 1>::Tensor* output) {



    
    for (int b = 0; b < batch_size; ++b) {
      const T* sorted_inputs_ptr = sorted_inputs.data() + b * num_inputs;
      OutType* output_ptr = output->data() + b * num_values;
      for (int i = 0; i < num_values; ++i) {
        output_ptr[i] = std::lower_bound(sorted_inputs_ptr, sorted_inputs_ptr + num_inputs, values(i + b * num_values)) - sorted_inputs_ptr;


      }
    }

    return Status::OK();
  }
};
}  

template <typename Device, typename T, typename OutType> class UpperBoundOp : public OpKernel {
 public:
  explicit UpperBoundOp(OpKernelConstruction* ctx) : OpKernel(ctx) {}

  void Compute(OpKernelContext* ctx) override {
    const Tensor& sorted_inputs_t = ctx->input(0);
    const Tensor& values_t = ctx->input(1);

    
    OP_REQUIRES(ctx, sorted_inputs_t.dim_size(0) == values_t.dim_size(0), Status(error::INVALID_ARGUMENT, "Leading dim_size of both tensors must match."));


    
    OP_REQUIRES(ctx, values_t.NumElements() < std::numeric_limits<int>::max(), Status(error::INVALID_ARGUMENT, "values tensor size must less than INT_MAX"));


    Tensor* output_t;
    OP_REQUIRES_OK(ctx, ctx->allocate_output(0, values_t.shape(), &output_t));

    if (output_t->dtype() == DT_INT32) {
      OP_REQUIRES(ctx, FastBoundsCheck(sorted_inputs_t.dim_size(1), std::numeric_limits<int>::max()), errors::InvalidArgument("trailing dim_size must less than " "INT_MAX for int32 output type, was ", sorted_inputs_t.dim_size(1)));




    }

    auto output = output_t->template flat<OutType>();
    const auto sorted_inputs = sorted_inputs_t.template flat<T>();
    const auto values = values_t.template flat<T>();
    OP_REQUIRES_OK( ctx, functor::UpperBoundFunctor<Device, T, OutType>::Compute( ctx, sorted_inputs, values, sorted_inputs_t.dim_size(0), sorted_inputs_t.dim_size(1), values_t.dim_size(1), &output));


  }
};

template <typename Device, typename T, typename OutType> class LowerBoundOp : public OpKernel {
 public:
  explicit LowerBoundOp(OpKernelConstruction* ctx) : OpKernel(ctx) {}

  void Compute(OpKernelContext* ctx) override {
    const Tensor& sorted_inputs_t = ctx->input(0);
    const Tensor& values_t = ctx->input(1);

    
    OP_REQUIRES(ctx, sorted_inputs_t.dim_size(0) == values_t.dim_size(0), Status(error::INVALID_ARGUMENT, "Leading dim_size of both tensors must match."));


    
    OP_REQUIRES(ctx, values_t.NumElements() < std::numeric_limits<int>::max(), Status(error::INVALID_ARGUMENT, "values tensor size must less than INT_MAX"));


    Tensor* output_t;
    OP_REQUIRES_OK(ctx, ctx->allocate_output(0, values_t.shape(), &output_t));

    if (output_t->dtype() == DT_INT32) {
      OP_REQUIRES(ctx, FastBoundsCheck(sorted_inputs_t.dim_size(1), std::numeric_limits<int>::max()), errors::InvalidArgument("trailing dim_size must less than " "INT_MAX for int32 output type, was ", sorted_inputs_t.dim_size(1)));




    }

    auto output = output_t->template flat<OutType>();
    const auto sorted_inputs = sorted_inputs_t.template flat<T>();
    const auto values = values_t.template flat<T>();
    OP_REQUIRES_OK( ctx, functor::LowerBoundFunctor<Device, T, OutType>::Compute( ctx, sorted_inputs, values, sorted_inputs_t.dim_size(0), sorted_inputs_t.dim_size(1), values_t.dim_size(1), &output));


  }
};







TF_CALL_REAL_NUMBER_TYPES(REGISTER_KERNELS);








TF_CALL_REAL_NUMBER_TYPES(REGISTER_KERNELS);










TF_CALL_REAL_NUMBER_TYPES(REGISTER_KERNELS);








TF_CALL_REAL_NUMBER_TYPES(REGISTER_KERNELS);










TF_CALL_REAL_NUMBER_TYPES(REGISTER_KERNELS);








TF_CALL_REAL_NUMBER_TYPES(REGISTER_KERNELS);










TF_CALL_REAL_NUMBER_TYPES(REGISTER_KERNELS);








TF_CALL_REAL_NUMBER_TYPES(REGISTER_KERNELS);



}  
