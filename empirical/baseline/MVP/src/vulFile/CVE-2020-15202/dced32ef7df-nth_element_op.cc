














namespace tensorflow {

typedef Eigen::ThreadPoolDevice CPUDevice;

template <typename Device, typename T> class NthElementOp : public OpKernel {
 public:
  explicit NthElementOp(OpKernelConstruction* context) : OpKernel(context) {
    OP_REQUIRES_OK(context, context->GetAttr("reverse", &reverse_));
  }

  void Compute(OpKernelContext* context) override {
    
    const auto& n_in = context->input(1);
    OP_REQUIRES( context, TensorShapeUtils::IsScalar(n_in.shape()), errors::InvalidArgument("N must be scalar but has rank ", n_in.dims()));

    int n = n_in.scalar<int32>()();
    OP_REQUIRES(context, n >= 0, errors::InvalidArgument("n must be non-negative but is ", n));

    
    const Tensor& input_in = context->input(0);
    const int num_dims = input_in.dims();
    OP_REQUIRES(context, num_dims >= 1, errors::InvalidArgument( "Input must be at least rank 1 but is rank ", num_dims));

    
    OP_REQUIRES( context, input_in.dim_size(num_dims - 1) > n, errors::InvalidArgument("Input must have last dimension > n = ", n));


    
    if (reverse_) {
      n = input_in.dim_size(num_dims - 1) - n - 1;
    }

    
    TensorShape out_shape;
    for (int i = 0; i < num_dims - 1; ++i) {
      out_shape.AddDim(input_in.dim_size(i));
    }
    Tensor* output_tensor = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output(0, out_shape, &output_tensor));

    functor::NthElementFunctor<Device, T> nthElementFunc;
    nthElementFunc(context, input_in, *output_tensor, n, reverse_);
  }

 private:
  bool reverse_;
};

namespace functor {

template <typename T> struct NthElementFunctor<CPUDevice, T> {
  void operator()(OpKernelContext* context, const Tensor& input_tensor, Tensor& output_tensor, int n, bool reverse) {
    const T* input = input_tensor.flat<T>().data();
    T* output = output_tensor.flat<T>().data();

    
    
    const int num_rows = output_tensor.NumElements();
    const int last_dim = input_tensor.dim_size(input_tensor.dims() - 1);

    
    auto SubNthElement = [&, input, output, last_dim, n](int start, int limit) {
      
      std::vector<T> buf(last_dim);

      for (int b = start; b < limit; ++b) {
        
        const T* input_start = input + b * last_dim;
        const T* input_end = input + (b + 1) * last_dim;
        std::copy(input_start, input_end, buf.begin());

        std::nth_element(buf.begin(), buf.begin() + n, buf.end());
        
        
        output[b] = buf[n];
      }
    };

    auto worker_threads = *(context->device()->tensorflow_cpu_worker_threads());
    
    
    
    Shard(worker_threads.num_threads, worker_threads.workers, num_rows, 20 * last_dim, SubNthElement);
  }
};

}  





TF_CALL_REAL_NUMBER_TYPES(REGISTER_NTHOP);


}  
