











namespace tensorflow {

typedef Eigen::ThreadPoolDevice CPUDevice;
typedef Eigen::GpuDevice GPUDevice;

template <typename Device, typename T> class DataFormatDimMapOp : public OpKernel {
 public:
  explicit DataFormatDimMapOp(OpKernelConstruction* context)
      : OpKernel(context) {
    string src_format;
    OP_REQUIRES_OK(context, context->GetAttr("src_format", &src_format));
    string dst_format;
    OP_REQUIRES_OK(context, context->GetAttr("dst_format", &dst_format));
    OP_REQUIRES(context, src_format.size() == 4 || src_format.size() == 5, errors::InvalidArgument(strings::StrCat( "Source format must of length 4 or 5, received " "src_format = ", src_format)));



    OP_REQUIRES( context, dst_format.size() == 4 || dst_format.size() == 5, errors::InvalidArgument(strings::StrCat( "Destination format must of length 4 or 5, received dst_format = ", dst_format)));



    dst_idx_ = Tensor(DT_INT32, {static_cast<int64>(src_format.size())});
    for (int i = 0; i < src_format.size(); ++i) {
      for (int j = 0; j < dst_format.size(); ++j) {
        if (dst_format[j] == src_format[i]) {
          dst_idx_.vec<int>()(i) = j;
          break;
        }
      }
    }
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& input = context->input(0);
    Tensor* output;
    OP_REQUIRES_OK(context, context->allocate_output(0, input.shape(), &output));
    functor::DataFormatDimMap<Device, T>()(context->eigen_device<Device>(), input.flat<T>(), output->flat<T>(), dst_idx_.vec<int>());

  }

  Tensor dst_idx_;
};

template <typename Device, typename T> class DataFormatVecPermuteOp : public OpKernel {
 public:
  explicit DataFormatVecPermuteOp(OpKernelConstruction* context)
      : OpKernel(context) {
    string src_format;
    OP_REQUIRES_OK(context, context->GetAttr("src_format", &src_format));
    string dst_format;
    OP_REQUIRES_OK(context, context->GetAttr("dst_format", &dst_format));
    src_format_ = src_format;
    dst_format_ = dst_format;
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& input = context->input(0);
    OP_REQUIRES(context, input.dims() == 1 || input.dims() == 2, errors::InvalidArgument( "input must be a vector or 2D tensor, but got shape ", input.shape().DebugString()));


    if (input.dims() == 1) {
      OP_REQUIRES(context, input.NumElements() == 2 || input.NumElements() == 4 || input.NumElements() == 5, errors::InvalidArgument( "1D input must be of size 2, 4 or 5, but got shape ", input.shape().DebugString()));




    } else if (input.dims() == 2) {
      OP_REQUIRES(context, input.dim_size(0) == 2 || input.dim_size(0) == 4, errors::InvalidArgument("First dimension of 2D input must be " "of size 2 or 4, but got shape ", input.shape().DebugString()));


      OP_REQUIRES( context, input.dim_size(1) == 2, errors::InvalidArgument( "Second dimension of 2D input must be of size 2, but got shape ", input.shape().DebugString()));



    }

    Tensor* output = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output(0, input.shape(), &output));
    
    Eigen::DSizes<Eigen::DenseIndex, 8> dst_idx;
    string src_format_str = src_format_;
    string dst_format_str = dst_format_;
    if (input.dim_size(0) == 2) {
      
      
      auto keep_only_spatial_dimensions = [](string* format_str) -> void {
        auto new_end = std::remove_if( format_str->begin(), format_str->end(), [](const char dim) { return dim != 'H' && dim != 'W'; });

        format_str->erase(new_end, format_str->end());
      };
      keep_only_spatial_dimensions(&src_format_str);
      keep_only_spatial_dimensions(&dst_format_str);
    }
    ComputeDstIndex(src_format_str, dst_format_str, input.dims(), &dst_idx);

    functor::DataFormatVecPermute<Device, T>()(context->eigen_device<Device>(), input.flat<T>(), output->flat<T>(), dst_idx);

  }

 private:
  
  
  
  
  static void ComputeDstIndex(const string& src_format_str, const string& dst_format_str, int num_dim, Eigen::DSizes<Eigen::DenseIndex, 8>* dst) {

    for (int i = 0; i < src_format_str.size(); ++i) {
      for (int j = 0; j < dst_format_str.size(); ++j) {
        if (dst_format_str[j] != src_format_str[i]) continue;
        
        for (int k = 0; k < num_dim; ++k) {
          (*dst)[i * num_dim + k] = j * num_dim + k;
        }
      }
    }
  }

  string src_format_;
  string dst_format_;
};




TF_CALL_int32(REGISTER_KERNEL);
TF_CALL_int64(REGISTER_KERNEL);





TF_CALL_int32(REGISTER_KERNEL);
TF_CALL_int64(REGISTER_KERNEL);







TF_CALL_int32(REGISTER_KERNEL);
TF_CALL_int64(REGISTER_KERNEL);







TF_CALL_int32(REGISTER_KERNEL);
TF_CALL_int64(REGISTER_KERNEL);




namespace functor {






TF_CALL_int32(DECLARE_GPU_SPECS);
TF_CALL_int64(DECLARE_GPU_SPECS);









TF_CALL_int32(DECLARE_GPU_SPECS);
TF_CALL_int64(DECLARE_GPU_SPECS);

}  












TF_CALL_int32(REGISTER_GPU_KERNEL);
TF_CALL_int64(REGISTER_GPU_KERNEL);












TF_CALL_int32(REGISTER_GPU_KERNEL);
TF_CALL_int64(REGISTER_GPU_KERNEL);



}  
