






























using stream_executor::dnn::DimIndex;










namespace {
















template <typename T> void Col2im(const T* col_data, const int depth, const int planes, const int height, const int width, const int filter_p, const int filter_h, const int filter_w, const int pad_pt, const int pad_t, const int pad_l, const int pad_pb, const int pad_b, const int pad_r, const int stride_p, const int stride_h, const int stride_w, T* im_data) {





  const int planes_col = (planes + pad_pt + pad_pb - filter_p) / stride_p + 1;
  const int height_col = (height + pad_t + pad_b - filter_h) / stride_h + 1;
  const int width_col = (width + pad_l + pad_r - filter_w) / stride_w + 1;
  int p_pad = -pad_pt;
  for (int p = 0; p < planes_col; ++p) {
    int h_pad = -pad_t;
    for (int h = 0; h < height_col; ++h) {
      int w_pad = -pad_l;
      for (int w = 0; w < width_col; ++w) {
        T* im_patch_data = im_data + (p_pad * height * width + h_pad * width + w_pad) * depth;
        for (int ip = p_pad; ip < p_pad + filter_p; ++ip) {
          for (int ih = h_pad; ih < h_pad + filter_h; ++ih) {
            for (int iw = w_pad; iw < w_pad + filter_w; ++iw) {
              if (ip >= 0 && ip < planes && ih >= 0 && ih < height && iw >= 0 && iw < width) {
                for (int i = 0; i < depth; ++i) {
                  im_patch_data[i] += col_data[i];
                }
              }
              im_patch_data += depth;
              col_data += depth;
            }
            
            im_patch_data += depth * (width - filter_w);
          }
          
          im_patch_data += (depth * width) * (height - filter_h);
        }
        w_pad += stride_w;
      }
      h_pad += stride_h;
    }
    p_pad += stride_p;
  }
}






template <typename T> void Im2col(const T* input_data, const int depth, const int planes, const int height, const int width, const int filter_p, const int filter_h, const int filter_w, const int pad_pt, const int pad_t, const int pad_l, const int pad_pb, const int pad_b, const int pad_r, const int stride_p, const int stride_h, const int stride_w, T* col_data) {





  const int planes_col = (planes + pad_pt + pad_pb - filter_p) / stride_p + 1;
  const int height_col = (height + pad_t + pad_b - filter_h) / stride_h + 1;
  const int width_col = (width + pad_l + pad_r - filter_w) / stride_w + 1;

  int p_pad = -pad_pt;
  for (int p = 0; p < planes_col; ++p) {
    int h_pad = -pad_t;
    for (int h = 0; h < height_col; ++h) {
      int w_pad = -pad_l;
      for (int w = 0; w < width_col; ++w) {
        for (int ip = p_pad; ip < p_pad + filter_p; ++ip) {
          for (int ih = h_pad; ih < h_pad + filter_h; ++ih) {
            for (int iw = w_pad; iw < w_pad + filter_w; ++iw) {
              if (ip >= 0 && ip < planes && ih >= 0 && ih < height && iw >= 0 && iw < width) {
                memcpy(col_data, input_data + (ip * height * width + ih * width + iw) * depth, sizeof(T) * depth);


              } else {
                
                memset(col_data, 0, sizeof(T) * depth);
              }
              col_data += depth;
            }
          }
        }
        w_pad += stride_w;
      }
      h_pad += stride_h;
    }
    p_pad += stride_p;
  }
}

}  

namespace tensorflow {

typedef Eigen::ThreadPoolDevice CPUDevice;
typedef Eigen::GpuDevice GPUDevice;



template <typename Device, class T> class Conv3DBackpropInputOp : public OpKernel {
 public:
  explicit Conv3DBackpropInputOp(OpKernelConstruction* context)
      : OpKernel(context), data_format_(FORMAT_NHWC), takes_shape_(type_string().find("V2") != std::string::npos) {

    
    if (takes_shape_) {
      string data_format;
      OP_REQUIRES_OK(context, context->GetAttr("data_format", &data_format));
      OP_REQUIRES(context, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
      OP_REQUIRES( context, data_format_ == FORMAT_NHWC, errors::InvalidArgument( "Conv3DBackpropInputOpV2 only supports NDHWC on the CPU."));


    }

    OP_REQUIRES_OK(context, context->GetAttr("dilations", &dilation_));
    OP_REQUIRES(context, dilation_.size() == 5, errors::InvalidArgument("Dilation rates field must " "specify 5 dimensions"));

    OP_REQUIRES(context, (GetTensorDim(dilation_, data_format_, 'C') == 1 && GetTensorDim(dilation_, data_format_, 'N') == 1), errors::InvalidArgument( "Current implementation does not yet support " "dilation rates in the batch and depth dimensions."));





    
    OP_REQUIRES(context, (GetTensorDim(dilation_, data_format_, '0') == 1 && GetTensorDim(dilation_, data_format_, '1') == 1 && GetTensorDim(dilation_, data_format_, '2') == 1), errors::InvalidArgument( "Current CPU implementation does not yet support " "dilation rates larger than 1."));






    OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
    OP_REQUIRES(context, stride_.size() == 5, errors::InvalidArgument("Sliding window strides field must " "specify 5 dimensions"));

    OP_REQUIRES( context, (GetTensorDim(stride_, data_format_, 'C') == 1 && GetTensorDim(stride_, data_format_, 'N') == 1), errors::InvalidArgument("Current implementation does not yet support " "strides in the batch and depth dimensions."));




    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& filter = context->input(1);
    const TensorShape& filter_shape = filter.shape();

    const Tensor& out_backprop = context->input(2);
    const TensorShape& out_backprop_shape = out_backprop.shape();

    TensorShape input_shape;
    if (takes_shape_) {
      const Tensor& input_sizes = context->input(0);
      
      
      OP_REQUIRES_OK(context, tensor::MakeShape(input_sizes, &input_shape));
    } else {
      input_shape = context->input(0).shape();
    }

    ConvBackpropDimensions dims;
    OP_REQUIRES_OK(context, ConvBackpropComputeDimensions( "Conv3DBackpropInputOp", 3, input_shape, filter_shape, out_backprop_shape, stride_, padding_, data_format_, &dims));



    Tensor* in_backprop;
    OP_REQUIRES_OK(context, context->allocate_output(0, input_shape, &in_backprop));

    functor::CuboidConvolutionBackwardInput<Device, T>()( context->eigen_device<Device>(), in_backprop->tensor<T, 5>(), filter.tensor<T, 5>(), out_backprop.tensor<T, 5>(), static_cast<int>(dims.spatial_dims[0].stride), static_cast<int>(dims.spatial_dims[1].stride), static_cast<int>(dims.spatial_dims[2].stride));






  }

 private:
  std::vector<int32> dilation_;
  std::vector<int32> stride_;
  Padding padding_;
  TensorFormat data_format_;
  bool takes_shape_;

  TF_DISALLOW_COPY_AND_ASSIGN(Conv3DBackpropInputOp);
};



template <typename Device, class T> class Conv3DCustomBackpropInputOp : public OpKernel {
  
  
  
  
  static constexpr int kMaxTempAllocationOverhead = 25;

 public:
  explicit Conv3DCustomBackpropInputOp(OpKernelConstruction* context)
      : OpKernel(context), data_format_(FORMAT_NHWC), takes_shape_(type_string().find("V2") != std::string::npos) {

    
    if (takes_shape_) {
      string data_format;
      OP_REQUIRES_OK(context, context->GetAttr("data_format", &data_format));
      OP_REQUIRES(context, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
      OP_REQUIRES( context, data_format_ == FORMAT_NHWC, errors::InvalidArgument( "Conv3DBackpropInputOpV2 only supports NDHWC on the CPU."));


    }

    OP_REQUIRES_OK(context, context->GetAttr("dilations", &dilation_));
    OP_REQUIRES(context, dilation_.size() == 5, errors::InvalidArgument("Dilation rates field must " "specify 5 dimensions"));

    OP_REQUIRES(context, (GetTensorDim(dilation_, data_format_, 'C') == 1 && GetTensorDim(dilation_, data_format_, 'N') == 1), errors::InvalidArgument( "Current implementation does not yet support " "dilation rates in the batch and depth dimensions."));





    
    OP_REQUIRES(context, (GetTensorDim(dilation_, data_format_, '0') == 1 && GetTensorDim(dilation_, data_format_, '1') == 1 && GetTensorDim(dilation_, data_format_, '2') == 1), errors::InvalidArgument( "Current CPU implementation does not yet support " "dilation rates larger than 1."));






    OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
    OP_REQUIRES(context, stride_.size() == 5, errors::InvalidArgument("Sliding window strides field must " "specify 5 dimensions"));

    OP_REQUIRES( context, (GetTensorDim(stride_, data_format_, 'C') == 1 && GetTensorDim(stride_, data_format_, 'N') == 1), errors::InvalidArgument("Current implementation does not yet support " "strides in the batch and depth dimensions."));




    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& filter = context->input(1);
    const TensorShape& filter_shape = filter.shape();

    const Tensor& out_backprop = context->input(2);
    const TensorShape& out_backprop_shape = out_backprop.shape();

    TensorShape input_shape;
    if (takes_shape_) {
      const Tensor& input_sizes = context->input(0);
      
      
      OP_REQUIRES_OK(context, tensor::MakeShape(input_sizes, &input_shape));
    } else {
      input_shape = context->input(0).shape();
    }

    ConvBackpropDimensions dims;
    OP_REQUIRES_OK(context, ConvBackpropComputeDimensions( "Conv3DBackpropInputOp", 3, input_shape, filter_shape, out_backprop_shape, stride_, padding_, data_format_, &dims));



    Tensor* in_backprop;
    OP_REQUIRES_OK(context, context->allocate_output(0, input_shape, &in_backprop));

    int64 top_pad_planes, bottom_pad_planes;
    int64 top_pad_rows, bottom_pad_rows;
    int64 left_pad_cols, right_pad_cols;

    OP_REQUIRES_OK(context, GetWindowedOutputSizeVerbose( dims.spatial_dims[0].input_size, dims.spatial_dims[0].filter_size, dims.spatial_dims[0].stride, padding_, &dims.spatial_dims[0].output_size, &top_pad_planes, &bottom_pad_planes));




    OP_REQUIRES_OK(context, GetWindowedOutputSizeVerbose( dims.spatial_dims[1].input_size, dims.spatial_dims[1].filter_size, dims.spatial_dims[1].stride, padding_, &dims.spatial_dims[1].output_size, &top_pad_rows, &bottom_pad_rows));




    OP_REQUIRES_OK(context, GetWindowedOutputSizeVerbose( dims.spatial_dims[2].input_size, dims.spatial_dims[2].filter_size, dims.spatial_dims[2].stride, padding_, &dims.spatial_dims[2].output_size, &left_pad_cols, &right_pad_cols));





    
    

    
    const int64 filter_total_size = dims.spatial_dims[0].filter_size * dims.spatial_dims[1].filter_size * dims.spatial_dims[2].filter_size * dims.in_depth;


    
    const int64 output_image_size = dims.spatial_dims[0].output_size * dims.spatial_dims[1].output_size * dims.spatial_dims[2].output_size;


    const auto cache_sizes = Eigen::internal::CacheSizes();
    const ptrdiff_t l3_cache_size = cache_sizes.m_l3;

    
    const size_t target_working_set_size = l3_cache_size / sizeof(T);

    
    const int64 size_A = output_image_size * dims.out_depth;

    const int64 size_B = filter_total_size * dims.out_depth;

    const int64 size_C = output_image_size * filter_total_size;

    const int64 work_unit_size = size_A + size_B + size_C;

    auto worker_threads = *(context->device()->tensorflow_cpu_worker_threads());

    
    
    
    
    
    const bool use_parallel_contraction = dims.batch_size == 1;

    const size_t shard_size = use_parallel_contraction ? 1 : (target_working_set_size + work_unit_size - 1) / work_unit_size;



    
    int64 total_tensor_elements = input_shape.num_elements() + filter_shape.num_elements() + out_backprop_shape.num_elements();


    
    TensorShape col_buffer_shape = {static_cast<int64>(shard_size), static_cast<int64>(output_image_size), static_cast<int64>(filter_total_size)};

    int64 col_buffer_elements = col_buffer_shape.num_elements();

    
    
    int64 col_buffer_overhead = col_buffer_elements / total_tensor_elements;
    if (col_buffer_overhead > kMaxTempAllocationOverhead) {
      VLOG(2) << "Fallback on Eigen implementation of Conv3DBackpropInputOp: " "col_buffer_overhead=" << col_buffer_overhead;


      functor::CuboidConvolutionBackwardInput<Device, T>()( context->eigen_device<Device>(), in_backprop->tensor<T, 5>(), filter.tensor<T, 5>(), out_backprop.tensor<T, 5>(), static_cast<int>(dims.spatial_dims[0].stride), static_cast<int>(dims.spatial_dims[1].stride), static_cast<int>(dims.spatial_dims[2].stride));







      return;
    }

    Tensor col_buffer;
    OP_REQUIRES_OK(context, context->allocate_temp(DataTypeToEnum<T>::value, col_buffer_shape, &col_buffer));


    
    const int64 input_offset = dims.spatial_dims[0].input_size * dims.spatial_dims[1].input_size * dims.spatial_dims[2].input_size * dims.in_depth;


    
    const int64 output_offset = dims.spatial_dims[0].output_size * dims.spatial_dims[1].output_size * dims.spatial_dims[2].output_size * dims.out_depth;


    const T* filter_data = filter.template flat<T>().data();
    T* col_buffer_data = col_buffer.template flat<T>().data();
    const T* out_backprop_data = out_backprop.template flat<T>().data();

    auto in_backprop_flat = in_backprop->template flat<T>();
    T* input_backprop_data = in_backprop_flat.data();
    in_backprop_flat.device(context->eigen_device<Device>()) = in_backprop_flat.constant(T(0));

    if (use_parallel_contraction) {
      typedef Eigen::TensorMap<Eigen::Tensor<T, 2, Eigen::RowMajor>, Eigen::Unaligned> TensorMap;

      typedef Eigen::TensorMap<Eigen::Tensor<const T, 2, Eigen::RowMajor>, Eigen::Unaligned> ConstTensorMap;


      
      Eigen::array<Eigen::IndexPair<Eigen::DenseIndex>, 1> contract_dims;
      contract_dims[0].first = 1;
      contract_dims[0].second = 1;

      for (int image_id = 0; image_id < dims.batch_size; ++image_id) {
        
        TensorMap C(col_buffer_data, output_image_size, filter_total_size);

        ConstTensorMap A(out_backprop_data + output_offset * image_id, output_image_size, dims.out_depth);
        ConstTensorMap B(filter_data, filter_total_size, dims.out_depth);

        C.device(context->eigen_cpu_device()) = A.contract(B, contract_dims);

        Col2im<T>(col_buffer_data, dims.in_depth,  dims.spatial_dims[0].input_size, dims.spatial_dims[1].input_size, dims.spatial_dims[2].input_size,  dims.spatial_dims[0].filter_size, dims.spatial_dims[1].filter_size, dims.spatial_dims[2].filter_size,  top_pad_planes, top_pad_rows, left_pad_cols, bottom_pad_planes, bottom_pad_rows, right_pad_cols,  dims.spatial_dims[0].stride, dims.spatial_dims[1].stride, dims.spatial_dims[2].stride, input_backprop_data);
















        input_backprop_data += input_offset;
      }
    } else {
      typedef Eigen::Map< Eigen::Matrix<T, Eigen::Dynamic, Eigen::Dynamic, Eigen::RowMajor>> MatrixMap;

      typedef Eigen::Map<const Eigen::Matrix<T, Eigen::Dynamic, Eigen::Dynamic, Eigen::RowMajor>> ConstMatrixMap;


      for (int image_id = 0; image_id < dims.batch_size;
           image_id += shard_size) {
        const int shard_limit = std::min(static_cast<int>(shard_size), static_cast<int>(dims.batch_size) - image_id);


        auto shard = [&dims, &top_pad_planes, &top_pad_rows, &left_pad_cols, &bottom_pad_planes, &bottom_pad_rows, &right_pad_cols, &output_image_size, &filter_total_size, &input_backprop_data, &col_buffer_data, &out_backprop_data, &filter_data, &input_offset, &output_offset, &size_C](int64 start, int64 limit) {




          for (int shard_id = start; shard_id < limit; ++shard_id) {
            T* im2col_buf = col_buffer_data + shard_id * size_C;
            T* input_data = input_backprop_data + shard_id * input_offset;
            const T* out_data = out_backprop_data + shard_id * output_offset;

            
            MatrixMap C(im2col_buf, output_image_size, filter_total_size);

            ConstMatrixMap A(out_data, output_image_size, dims.out_depth);
            ConstMatrixMap B(filter_data, filter_total_size, dims.out_depth);

            C.noalias() = A * B.transpose();

            Col2im<T>(im2col_buf, dims.in_depth,  dims.spatial_dims[0].input_size, dims.spatial_dims[1].input_size, dims.spatial_dims[2].input_size,  dims.spatial_dims[0].filter_size, dims.spatial_dims[1].filter_size, dims.spatial_dims[2].filter_size,  top_pad_planes, top_pad_rows, left_pad_cols, bottom_pad_planes, bottom_pad_rows, right_pad_cols,  dims.spatial_dims[0].stride, dims.spatial_dims[1].stride, dims.spatial_dims[2].stride, input_data);















          }
        };
        Shard(worker_threads.num_threads, worker_threads.workers, shard_limit, work_unit_size, shard);

        input_backprop_data += input_offset * shard_limit;
        out_backprop_data += output_offset * shard_limit;
      }
    }
  }

 private:
  std::vector<int32> dilation_;
  std::vector<int32> stride_;
  Padding padding_;
  TensorFormat data_format_;
  bool takes_shape_;

  TF_DISALLOW_COPY_AND_ASSIGN(Conv3DCustomBackpropInputOp);
};































TF_CALL_half(REGISTER_CPU_KERNEL);
TF_CALL_float(REGISTER_CPU_KERNEL);
TF_CALL_double(REGISTER_CPU_KERNEL);




template <typename Device, class T> class Conv3DBackpropFilterOp : public OpKernel {
 public:
  explicit Conv3DBackpropFilterOp(OpKernelConstruction* context)
      : OpKernel(context), data_format_(FORMAT_NHWC), takes_shape_(type_string().find("V2") != std::string::npos) {

    
    if (takes_shape_) {
      string data_format;
      OP_REQUIRES_OK(context, context->GetAttr("data_format", &data_format));
      OP_REQUIRES(context, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
      OP_REQUIRES( context, data_format_ == FORMAT_NHWC, errors::InvalidArgument( "Conv3DBackpropFilterOpV2 only supports NDHWC on the CPU."));


    }

    OP_REQUIRES_OK(context, context->GetAttr("dilations", &dilation_));
    OP_REQUIRES(context, dilation_.size() == 5, errors::InvalidArgument("Dilation rates field must " "specify 5 dimensions"));

    OP_REQUIRES(context, (GetTensorDim(dilation_, data_format_, 'C') == 1 && GetTensorDim(dilation_, data_format_, 'N') == 1), errors::InvalidArgument( "Current implementation does not yet support " "dilation rates in the batch and depth dimensions."));





    
    OP_REQUIRES(context, (GetTensorDim(dilation_, data_format_, '0') == 1 && GetTensorDim(dilation_, data_format_, '1') == 1 && GetTensorDim(dilation_, data_format_, '2') == 1), errors::InvalidArgument( "Current CPU implementation does not yet support " "dilation rates larger than 1."));






    OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
    OP_REQUIRES(context, stride_.size() == 5, errors::InvalidArgument("Sliding window strides field must " "specify 5 dimensions"));

    OP_REQUIRES( context, (GetTensorDim(stride_, data_format_, 'C') == 1 && GetTensorDim(stride_, data_format_, 'N') == 1), errors::InvalidArgument("Current implementation does not yet support " "strides in the batch and depth dimensions."));




    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& input = context->input(0);
    const TensorShape& input_shape = input.shape();

    const Tensor& out_backprop = context->input(2);
    const TensorShape& out_backprop_shape = out_backprop.shape();

    TensorShape filter_shape;
    if (takes_shape_) {
      const Tensor& filter_sizes = context->input(1);
      OP_REQUIRES_OK(context, TensorShapeUtils::MakeShape( filter_sizes.vec<int32>(), &filter_shape));
    } else {
      filter_shape = context->input(1).shape();
    }

    ConvBackpropDimensions dims;
    OP_REQUIRES_OK(context, ConvBackpropComputeDimensions( "Conv3DBackpropFilterOp", 3, input_shape, filter_shape, out_backprop_shape, stride_, padding_, data_format_, &dims));




    Tensor* filter_backprop;
    OP_REQUIRES_OK(context, context->allocate_output(0, filter_shape, &filter_backprop));

    if (input_shape.num_elements() == 0) {
      filter_backprop->template flat<T>().setZero();
      return;
    }

    functor::CuboidConvolutionBackwardFilter<Device, T>()( context->eigen_device<Device>(), filter_backprop->tensor<T, 5>(), input.tensor<T, 5>(), out_backprop.tensor<T, 5>(), static_cast<int>(dims.spatial_dims[0].stride), static_cast<int>(dims.spatial_dims[1].stride), static_cast<int>(dims.spatial_dims[2].stride));






  }

 private:
  std::vector<int32> dilation_;
  std::vector<int32> stride_;
  Padding padding_;
  TensorFormat data_format_;
  bool takes_shape_;

  TF_DISALLOW_COPY_AND_ASSIGN(Conv3DBackpropFilterOp);
};



template <typename Device, class T> class Conv3DCustomBackpropFilterOp : public OpKernel {
  
  
  
  
  static constexpr int kMaxTempAllocationOverhead = 25;

 public:
  explicit Conv3DCustomBackpropFilterOp(OpKernelConstruction* context)
      : OpKernel(context), data_format_(FORMAT_NHWC), takes_shape_(type_string().find("V2") != std::string::npos) {

    
    if (takes_shape_) {
      string data_format;
      OP_REQUIRES_OK(context, context->GetAttr("data_format", &data_format));
      OP_REQUIRES(context, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
      OP_REQUIRES( context, data_format_ == FORMAT_NHWC, errors::InvalidArgument( "Conv3DBackpropFilterOpV2 only supports NDHWC on the CPU."));


    }

    OP_REQUIRES_OK(context, context->GetAttr("dilations", &dilation_));
    OP_REQUIRES(context, dilation_.size() == 5, errors::InvalidArgument("Dilation rates field must " "specify 5 dimensions"));

    OP_REQUIRES(context, (GetTensorDim(dilation_, data_format_, 'C') == 1 && GetTensorDim(dilation_, data_format_, 'N') == 1), errors::InvalidArgument( "Current implementation does not yet support " "dilation rates in the batch and depth dimensions."));





    
    OP_REQUIRES(context, (GetTensorDim(dilation_, data_format_, '0') == 1 && GetTensorDim(dilation_, data_format_, '1') == 1 && GetTensorDim(dilation_, data_format_, '2') == 1), errors::InvalidArgument( "Current CPU implementation does not yet support " "dilation rates larger than 1."));






    OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
    OP_REQUIRES(context, stride_.size() == 5, errors::InvalidArgument("Sliding window strides field must " "specify 5 dimensions"));

    OP_REQUIRES( context, (GetTensorDim(stride_, data_format_, 'C') == 1 && GetTensorDim(stride_, data_format_, 'N') == 1), errors::InvalidArgument("Current implementation does not yet support " "strides in the batch and depth dimensions."));




    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& input = context->input(0);
    const TensorShape& input_shape = input.shape();

    const Tensor& out_backprop = context->input(2);
    const TensorShape& out_backprop_shape = out_backprop.shape();

    TensorShape filter_shape;
    if (takes_shape_) {
      const Tensor& filter_sizes = context->input(1);
      OP_REQUIRES_OK(context, TensorShapeUtils::MakeShape( filter_sizes.vec<int32>(), &filter_shape));
    } else {
      filter_shape = context->input(1).shape();
    }

    ConvBackpropDimensions dims;
    OP_REQUIRES_OK(context, ConvBackpropComputeDimensions( "Conv3DBackpropFilterOp", 3, input_shape, filter_shape, out_backprop_shape, stride_, padding_, data_format_, &dims));




    Tensor* filter_backprop;
    OP_REQUIRES_OK(context, context->allocate_output(0, filter_shape, &filter_backprop));

    if (input_shape.num_elements() == 0) {
      filter_backprop->template flat<T>().setZero();
      return;
    }

    int64 top_pad_planes, bottom_pad_planes;
    int64 top_pad_rows, bottom_pad_rows;
    int64 left_pad_cols, right_pad_cols;

    OP_REQUIRES_OK(context, GetWindowedOutputSizeVerbose( dims.spatial_dims[0].input_size, dims.spatial_dims[0].filter_size, dims.spatial_dims[0].stride, padding_, &dims.spatial_dims[0].output_size, &top_pad_planes, &bottom_pad_planes));




    OP_REQUIRES_OK(context, GetWindowedOutputSizeVerbose( dims.spatial_dims[1].input_size, dims.spatial_dims[1].filter_size, dims.spatial_dims[1].stride, padding_, &dims.spatial_dims[1].output_size, &top_pad_rows, &bottom_pad_rows));




    OP_REQUIRES_OK(context, GetWindowedOutputSizeVerbose( dims.spatial_dims[2].input_size, dims.spatial_dims[2].filter_size, dims.spatial_dims[2].stride, padding_, &dims.spatial_dims[2].output_size, &left_pad_cols, &right_pad_cols));





    
    

    
    const int64 filter_total_size = dims.spatial_dims[0].filter_size * dims.spatial_dims[1].filter_size * dims.spatial_dims[2].filter_size * dims.in_depth;

    
    const int64 output_image_size = dims.spatial_dims[0].output_size * dims.spatial_dims[1].output_size * dims.spatial_dims[2].output_size;


    
    
    
    

    const auto cache_sizes = Eigen::internal::CacheSizes();
    const ptrdiff_t l3_cache_size = cache_sizes.m_l3;

    
    
    
    const size_t target_working_set_size = l3_cache_size / sizeof(T);

    const int64 size_A = output_image_size * filter_total_size;

    const int64 size_B = output_image_size * dims.out_depth;

    const int64 size_C = filter_total_size * dims.out_depth;

    const int64 work_unit_size = size_A + size_B + size_C;

    const size_t shard_size = (target_working_set_size + work_unit_size - 1) / work_unit_size;

    
    int64 total_tensor_elements = input_shape.num_elements() + filter_shape.num_elements() + out_backprop_shape.num_elements();


    
    TensorShape col_buffer_shape = {static_cast<int64>(shard_size), static_cast<int64>(output_image_size), static_cast<int64>(filter_total_size)};

    int64 col_buffer_elements = col_buffer_shape.num_elements();

    
    
    int64 col_buffer_overhead = col_buffer_elements / total_tensor_elements;
    if (col_buffer_overhead > kMaxTempAllocationOverhead) {
      VLOG(2) << "Fallback on Eigen implementation of Conv3DBackpropFilterOp: " "col_buffer_overhead=" << col_buffer_overhead;


      functor::CuboidConvolutionBackwardFilter<Device, T>()( context->eigen_device<Device>(), filter_backprop->tensor<T, 5>(), input.tensor<T, 5>(), out_backprop.tensor<T, 5>(), static_cast<int>(dims.spatial_dims[0].stride), static_cast<int>(dims.spatial_dims[1].stride), static_cast<int>(dims.spatial_dims[2].stride));







      return;
    }

    Tensor col_buffer;
    OP_REQUIRES_OK(context, context->allocate_temp(DataTypeToEnum<T>::value, col_buffer_shape, &col_buffer));


    
    const int64 input_offset = dims.spatial_dims[0].input_size * dims.spatial_dims[1].input_size * dims.spatial_dims[2].input_size * dims.in_depth;

    
    const int64 output_offset = dims.spatial_dims[0].output_size * dims.spatial_dims[1].output_size * dims.spatial_dims[2].output_size * dims.out_depth;


    const T* input_data = input.template flat<T>().data();
    T* col_buffer_data = col_buffer.template flat<T>().data();
    const T* out_backprop_data = out_backprop.template flat<T>().data();
    T* filter_backprop_data = filter_backprop->template flat<T>().data();

    typedef Eigen::TensorMap<Eigen::Tensor<T, 2, Eigen::RowMajor>, Eigen::Unaligned> TensorMap;

    typedef Eigen::TensorMap<Eigen::Tensor<const T, 2, Eigen::RowMajor>, Eigen::Unaligned> ConstTensorMap;


    TensorMap C(filter_backprop_data, filter_total_size, dims.out_depth);
    C.setZero();

    
    Eigen::array<Eigen::IndexPair<Eigen::DenseIndex>, 1> contract_dims;
    contract_dims[0].first = 0;
    contract_dims[0].second = 0;

    auto worker_threads = *(context->device()->tensorflow_cpu_worker_threads());

    for (int image_id = 0; image_id < dims.batch_size; image_id += shard_size) {
      const int shard_limit = std::min(static_cast<int>(shard_size), static_cast<int>(dims.batch_size) - image_id);


      auto shard = [&input_data, &col_buffer_data, &dims, &top_pad_planes, &top_pad_rows, &left_pad_cols, &bottom_pad_planes, &bottom_pad_rows, &right_pad_cols, &input_offset, &size_A](int64 start, int64 limit) {


        for (int shard_id = start; shard_id < limit; ++shard_id) {
          const T* input_data_shard = input_data + shard_id * input_offset;
          T* col_data_shard = col_buffer_data + shard_id * size_A;

          
          
          Im2col<T>(input_data_shard, dims.in_depth,  dims.spatial_dims[0].input_size, dims.spatial_dims[1].input_size, dims.spatial_dims[2].input_size,  dims.spatial_dims[0].filter_size, dims.spatial_dims[1].filter_size, dims.spatial_dims[2].filter_size,  top_pad_planes, top_pad_rows, left_pad_cols, bottom_pad_planes, bottom_pad_rows, right_pad_cols,  dims.spatial_dims[0].stride, dims.spatial_dims[1].stride, dims.spatial_dims[2].stride, col_data_shard);















        }
      };
      Shard(worker_threads.num_threads, worker_threads.workers, shard_limit, size_A, shard);

      ConstTensorMap A(col_buffer_data, output_image_size * shard_limit, filter_total_size);
      ConstTensorMap B(out_backprop_data, output_image_size * shard_limit, dims.out_depth);

      
      C.device(context->eigen_cpu_device()) += A.contract(B, contract_dims);

      input_data += input_offset * shard_limit;
      out_backprop_data += output_offset * shard_limit;
    }
  }

 private:
  std::vector<int32> dilation_;
  std::vector<int32> stride_;
  Padding padding_;
  TensorFormat data_format_;
  bool takes_shape_;

  TF_DISALLOW_COPY_AND_ASSIGN(Conv3DCustomBackpropFilterOp);
};
































TF_CALL_float(REGISTER_CPU_KERNEL);
TF_CALL_double(REGISTER_CPU_KERNEL);












TF_CALL_half(REGISTER_CPU_KERNEL);







namespace functor {


















DECLARE_GPU_SPEC(Eigen::half);
DECLARE_GPU_SPEC(float);
DECLARE_GPU_SPEC(double);

}  


struct Conv3dBackwardDataAutoTuneGroup {
  static string name() { return "Conv3dBwdData"; }
};

typedef AutoTuneSingleton<Conv3dBackwardDataAutoTuneGroup, ConvParameters, se::dnn::AlgorithmConfig>  AutoTuneConv3dBwdData;


template <typename T> class Conv3DBackpropInputOp<GPUDevice, T> : public OpKernel {
 public:
  explicit Conv3DBackpropInputOp(OpKernelConstruction* context)
      : OpKernel(context), data_format_(FORMAT_NHWC), takes_shape_(type_string().find("V2") != std::string::npos) {

    
    if (takes_shape_) {
      string data_format;
      OP_REQUIRES_OK(context, context->GetAttr("data_format", &data_format));
      OP_REQUIRES(context, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
    }
    OP_REQUIRES_OK(context, context->GetAttr("dilations", &dilation_));
    OP_REQUIRES(context, dilation_.size() == 5, errors::InvalidArgument("Dilation rates field must " "specify 5 dimensions"));

    OP_REQUIRES(context, (GetTensorDim(dilation_, data_format_, 'C') == 1 && GetTensorDim(dilation_, data_format_, 'N') == 1), errors::InvalidArgument( "Current implementation does not yet support " "dilation rates in the batch and depth dimensions."));




    OP_REQUIRES( context, (GetTensorDim(dilation_, data_format_, '0') > 0 && GetTensorDim(dilation_, data_format_, '1') > 0 && GetTensorDim(dilation_, data_format_, '2') > 0), errors::InvalidArgument("Dilated rates should be larger than 0."));




    OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
    OP_REQUIRES(context, stride_.size() == 5, errors::InvalidArgument("Sliding window strides field must " "specify 5 dimensions"));

    OP_REQUIRES( context, (GetTensorDim(stride_, data_format_, 'C') == 1 && GetTensorDim(stride_, data_format_, 'N') == 1), errors::InvalidArgument("Current implementation does not yet support " "strides in the batch and depth dimensions."));




    OP_REQUIRES( context, (GetTensorDim(stride_, data_format_, '0') > 0 && GetTensorDim(stride_, data_format_, '1') > 0 && GetTensorDim(stride_, data_format_, '2') > 0), errors::InvalidArgument("Spatial strides should be larger than 0."));




    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));
    cudnn_use_autotune_ = CudnnUseAutotune();
  }
  void Compute(OpKernelContext* context) override {
    const Tensor& filter = context->input(1);
    const TensorShape& filter_shape = filter.shape();

    const Tensor& out_backprop = context->input(2);
    const TensorShape& out_backprop_shape = out_backprop.shape();

    TensorShape input_shape;
    if (takes_shape_) {
      const Tensor& input_sizes = context->input(0);
      OP_REQUIRES_OK(context, tensor::MakeShape(input_sizes, &input_shape));
    } else {
      input_shape = context->input(0).shape();
    }

    ConvBackpropDimensions dims;
    OP_REQUIRES_OK(context, ConvBackpropComputeDimensionsV2( "Conv3DBackpropInputOp", 3, input_shape, filter_shape, out_backprop_shape, dilation_, stride_, padding_, , data_format_, &dims));




    Tensor* in_backprop;
    OP_REQUIRES_OK(context, context->allocate_output(0, input_shape, &in_backprop));

    auto* stream = context->op_device_context()->stream();
    OP_REQUIRES(context, stream, errors::Internal("No GPU stream available."));

    bool is_grouped_convolution = filter_shape.dim_size(3) != dims.in_depth;
    if (!is_grouped_convolution && dims.filter_size(0) == 1 && dims.filter_size(1) == 1 && dims.filter_size(2) == 1 && dims.dilation(0) == 1 && dims.dilation(1) == 1 && dims.dilation(2) == 1 && dims.stride(0) == 1 && dims.stride(1) == 1 && dims.stride(2) == 1 && data_format_ == FORMAT_NHWC) {



      const uint64 m = dims.batch_size * dims.input_size(0) * dims.input_size(1) * dims.input_size(2);
      const uint64 k = dims.out_depth;
      const uint64 n = dims.in_depth;

      auto a_ptr = AsDeviceMemory(out_backprop.template flat<T>().data(), out_backprop.template flat<T>().size());
      auto b_ptr = AsDeviceMemory(filter.template flat<T>().data(), filter.template flat<T>().size());
      auto c_ptr = AsDeviceMemory(in_backprop->template flat<T>().data(), in_backprop->template flat<T>().size());

      auto transpose = se::blas::Transpose::kTranspose;
      auto no_transpose = se::blas::Transpose::kNoTranspose;

      bool blas_launch_status = stream ->ThenBlasGemm(transpose, no_transpose, n, m, k, 1.0f, b_ptr, k, a_ptr, k, 0.0f, &c_ptr, n)


              .ok();
      if (!blas_launch_status) {
        context->SetStatus(errors::Internal("Blas SGEMM launch failed : m=", m, ", n=", n, ", k=", k));
      }
      return;
    } else if (!is_grouped_convolution && dims.filter_size(0) == dims.input_size(0) && dims.filter_size(1) == dims.input_size(1) && dims.filter_size(2) == dims.input_size(2) && padding_ == Padding::VALID && data_format_ == FORMAT_NHWC) {



      const uint64 m = dims.batch_size;
      const uint64 k = dims.out_depth;
      const uint64 n = dims.input_size(0) * dims.input_size(1) * dims.input_size(2) * dims.in_depth;

      auto a_ptr = AsDeviceMemory(out_backprop.template flat<T>().data(), out_backprop.template flat<T>().size());
      auto b_ptr = AsDeviceMemory(filter.template flat<T>().data(), filter.template flat<T>().size());
      auto c_ptr = AsDeviceMemory(in_backprop->template flat<T>().data(), in_backprop->template flat<T>().size());

      auto transpose = se::blas::Transpose::kTranspose;
      auto no_transpose = se::blas::Transpose::kNoTranspose;

      bool blas_launch_status = stream ->ThenBlasGemm(transpose, no_transpose, n, m, k, 1.0f, b_ptr, k, a_ptr, k, 0.0f, &c_ptr, n)


              .ok();
      if (!blas_launch_status) {
        context->SetStatus(errors::Internal("Blas SGEMM launch failed : m=", m, ", n=", n, ", k=", k));
      }
      return;
    }

    int padding_planes = dims.SpatialPadding(padding_, 0);
    int padding_rows = dims.SpatialPadding(padding_, 1);
    int padding_cols = dims.SpatialPadding(padding_, 2);
    const bool planes_odd = (padding_planes % 2 != 0);
    const bool rows_odd = (padding_rows % 2 != 0);
    const bool cols_odd = (padding_cols % 2 != 0);

    TensorShape compatible_input_shape;
    if (rows_odd || cols_odd || planes_odd) {
      
      compatible_input_shape = {
          dims.batch_size, dims.in_depth, dims.input_size(0) + planes_odd, dims.input_size(1) + rows_odd, dims.input_size(2) + cols_odd, };




    } else {
      compatible_input_shape = {dims.batch_size, dims.in_depth, dims.input_size(0), dims.input_size(1), dims.input_size(2)};

    }

    CHECK(padding_rows >= 0 && padding_cols >= 0 && padding_planes >= 0)
        << "Negative paddings: (" << padding_rows << ", " << padding_cols << ", " << padding_planes << ")";


    const bool compute_in_nhwc = CUDNN_VERSION >= 8000 && DataTypeToEnum<T>::value == DT_HALF;

    
    const bool compute_in_nhwc = false;

    const TensorFormat compute_data_format = (compute_in_nhwc && data_format_ == FORMAT_NHWC) ? FORMAT_NHWC : FORMAT_NCHW;


    VLOG(3) << "Compute Conv3DBackpropInput with cuDNN:" << " data_format=" << ToString(data_format_)
            << " compute_data_format=" << ToString(compute_data_format);

    constexpr auto kComputeInNHWC = std::make_tuple(se::dnn::DataLayout::kBatchYXDepth, se::dnn::FilterLayout::kOutputYXInput);

    constexpr auto kComputeInNCHW = std::make_tuple(se::dnn::DataLayout::kBatchDepthYX, se::dnn::FilterLayout::kOutputInputYX);


    se::dnn::DataLayout compute_data_layout;
    se::dnn::FilterLayout filter_layout;

    std::tie(compute_data_layout, filter_layout) = compute_data_format == FORMAT_NHWC ? kComputeInNHWC : kComputeInNCHW;

    se::dnn::BatchDescriptor input_desc(3);
    input_desc.set_count(dims.batch_size)
        .set_spatial_dim(DimIndex::X, compatible_input_shape.dim_size(4))
        .set_spatial_dim(DimIndex::Y, compatible_input_shape.dim_size(3))
        .set_spatial_dim(DimIndex::Z, compatible_input_shape.dim_size(2))
        .set_feature_map_count(dims.in_depth)
        .set_layout(compute_data_layout);
    se::dnn::BatchDescriptor output_desc(3);
    output_desc.set_count(dims.batch_size)
        .set_spatial_dim(DimIndex::X, dims.output_size(2))
        .set_spatial_dim(DimIndex::Y, dims.output_size(1))
        .set_spatial_dim(DimIndex::Z, dims.output_size(0))
        .set_feature_map_count(dims.out_depth)
        .set_layout(compute_data_layout);
    se::dnn::FilterDescriptor filter_desc(3);
    filter_desc.set_spatial_dim(DimIndex::X, dims.filter_size(2))
        .set_spatial_dim(DimIndex::Y, dims.filter_size(1))
        .set_spatial_dim(DimIndex::Z, dims.filter_size(0))
        .set_input_feature_map_count(filter_shape.dim_size(3))
        .set_output_feature_map_count(filter_shape.dim_size(4))
        .set_layout(filter_layout);
    se::dnn::ConvolutionDescriptor conv_desc(3);
    conv_desc.set_dilation_rate(DimIndex::X, dims.dilation(2))
        .set_dilation_rate(DimIndex::Y, dims.dilation(1))
        .set_dilation_rate(DimIndex::Z, dims.dilation(0))
        .set_filter_stride(DimIndex::X, dims.stride(2))
        .set_filter_stride(DimIndex::Y, dims.stride(1))
        .set_filter_stride(DimIndex::Z, dims.stride(0))
        .set_zero_padding(DimIndex::X, padding_cols / 2)
        .set_zero_padding(DimIndex::Y, padding_rows / 2)
        .set_zero_padding(DimIndex::Z, padding_planes / 2)
        .set_group_count(dims.in_depth / filter_shape.dim_size(3));

    
    Tensor transformed_filter;
    auto dst_format = compute_data_format == FORMAT_NCHW ? FORMAT_OIHW : FORMAT_OHWI;
    TensorShape dst_shape = dst_format == FORMAT_OIHW ? TensorShape({filter_shape.dim_size(4), filter_shape.dim_size(3), dims.filter_size(0), dims.filter_size(1), dims.filter_size(2)})



            : TensorShape({filter_shape.dim_size(4), dims.filter_size(0), dims.filter_size(1), dims.filter_size(2), filter_shape.dim_size(3)});

    OP_REQUIRES_OK(context, context->allocate_temp(DataTypeToEnum<T>::value, dst_shape, &transformed_filter));


    functor::TransformFilter<GPUDevice, T, int, 5>()( context->eigen_device<GPUDevice>(), dst_format, To32Bit(filter.tensor<T, 5>()), To32Bit(transformed_filter.tensor<T, 5>()));



    
    Tensor transformed_out_backprop;
    if (data_format_ == FORMAT_NHWC && compute_data_format == FORMAT_NCHW) {
      TensorShape nchw_shape = {dims.batch_size, dims.out_depth, dims.output_size(0), dims.output_size(1), dims.output_size(2)};

      if (dims.out_depth > 1) {
        OP_REQUIRES_OK(context, context->allocate_temp( DataTypeToEnum<T>::value, nchw_shape, &transformed_out_backprop));

        functor::NHWCToNCHW<GPUDevice, T, 5>()( context->eigen_device<GPUDevice>(), out_backprop.tensor<T, 5>(), transformed_out_backprop.tensor<T, 5>());

      } else {
        CHECK(transformed_out_backprop.CopyFrom(out_backprop, nchw_shape));
      }
    } else {
      transformed_out_backprop = out_backprop;
    }
    
    Tensor pre_transformed_in_backprop;
    OP_REQUIRES_OK(context, context->allocate_temp( DataTypeToEnum<T>::value, ShapeFromFormat(compute_data_format, compatible_input_shape.dim_size(0), {{compatible_input_shape.dim_size(2), compatible_input_shape.dim_size(3), compatible_input_shape.dim_size(4)}}, compatible_input_shape.dim_size(1)), &pre_transformed_in_backprop));









    auto out_backprop_ptr = AsDeviceMemory(transformed_out_backprop.template flat<T>().data(), transformed_out_backprop.template flat<T>().size());

    auto filter_ptr = AsDeviceMemory(transformed_filter.template flat<T>().data(), transformed_filter.template flat<T>().size());

    auto in_backprop_ptr = AsDeviceMemory(pre_transformed_in_backprop.template flat<T>().data(), pre_transformed_in_backprop.template flat<T>().size());


    static int64 ConvolveBackwardDataScratchSize = GetDnnWorkspaceLimit( "TF_CUDNN_WORKSPACE_LIMIT_IN_MB", 1LL << 32);

    const int device_id = stream->parent()->device_ordinal();
    
    
    DataType dtype = context->input(2).dtype();
    const ConvParameters conv_parameters = {
        dims.batch_size, dims.in_depth, {{dims.input_size(0), dims.input_size(1), dims.input_size(2)}}, compute_data_format, dims.out_depth, {{dims.filter_size(0), dims.filter_size(1), dims.filter_size(2)}}, {{dims.dilation(0), dims.dilation(1), dims.dilation(2)}}, {{dims.stride(0), dims.stride(1), dims.stride(2)}}, {{padding_planes, padding_rows, padding_cols}}, dtype, device_id, conv_desc.group_count()};











    using se::dnn::AlgorithmConfig;
    using se::dnn::AlgorithmDesc;
    using se::dnn::ProfileResult;

    
    
    
    cudnn_use_autotune_ = true;

    AlgorithmConfig algorithm_config;

    if (cudnn_use_autotune_ && !AutoTuneConv3dBwdData::GetInstance()->Find( conv_parameters, &algorithm_config)) {
      std::vector<std::unique_ptr<se::dnn::ConvolveExecutionPlan>> plans;

      std::vector<AlgorithmDesc> algorithms;
      std::vector<AlgorithmConfig> configs;
      if (CudnnUseFrontend()) {
        OP_REQUIRES(context, stream->parent()->GetConvolveExecutionPlans( se::dnn::ConvolutionKind::BACKWARD_DATA, se::dnn::ToDataType<T>::value, stream, input_desc, filter_desc, output_desc, conv_desc, &plans), errors::Unknown( "Failed to get convolution execution plan. This is " "probably because cuDNN failed to initialize, so try " "looking to see if a warning log message was printed " "above."));








        for (const auto& plan : plans) {
          configs.push_back(AlgorithmConfig( AlgorithmDesc{plan->getTag(), plan->get_raw_desc()}, plan->getWorkspaceSize()));

        }
      } else {
        OP_REQUIRES(context, stream->parent()->GetConvolveBackwardDataAlgorithms( conv_parameters.ShouldIncludeWinogradNonfusedAlgo<T>( stream->parent()), &algorithms), errors::Unknown( "Failed to get convolution execution plan. This is " "probably because cuDNN failed to initialize, so try " "looking to see if a warning log message was printed " "above."));








        for (const auto& algorithm : algorithms) {
          configs.push_back(AlgorithmConfig(algorithm));
        }
      }

      se::TfAllocatorAdapter tf_allocator_adapter( context->device()->GetAllocator({}), stream);
      se::RedzoneAllocator rz_allocator(stream, &tf_allocator_adapter, se::GpuAsmOpts());
      se::DeviceMemory<T> in_backprop_ptr_rz( WrapRedzoneBestEffort(&rz_allocator, in_backprop_ptr));

      std::vector<tensorflow::AutotuneResult> results;
      for (auto& profile_config : configs) {
        
        
        DnnScratchAllocator scratch_allocator(ConvolveBackwardDataScratchSize, context);
        se::RedzoneAllocator rz_scratch_allocator( stream, &tf_allocator_adapter, se::GpuAsmOpts(), ConvolveBackwardDataScratchSize);

        se::ScratchAllocator* allocator_used = !RedzoneCheckDisabled()
                ? static_cast<se::ScratchAllocator*>(&rz_scratch_allocator)
                : static_cast<se::ScratchAllocator*>(&scratch_allocator);
        ProfileResult profile_result;

        Status cudnn_launch_status;
        if (CudnnUseFrontend()) {
          cudnn_launch_status = stream->ConvolveBackwardDataWithExecutionPlan( filter_desc, filter_ptr, output_desc, out_backprop_ptr, conv_desc, input_desc, &in_backprop_ptr_rz, allocator_used, profile_config, &profile_result);


        } else {
          cudnn_launch_status = stream->ConvolveBackwardDataWithAlgorithm( filter_desc, filter_ptr, output_desc, out_backprop_ptr, conv_desc, input_desc, &in_backprop_ptr_rz, allocator_used, profile_config, &profile_result);


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
        } else {
          
          
          
          results.emplace_back();
          auto& result = results.back();
          result.mutable_failure()->set_kind(AutotuneResult::UNKNOWN);
          result.mutable_failure()->set_msg( absl::StrCat("Profiling failure on CUDNN engine: ", profile_config.algorithm()->exec_plan_id()));

        }
      }

      DnnScratchAllocator scratch_allocator(ConvolveBackwardDataScratchSize, context);
      std::vector<ProfileResult> algorithms;
      CHECK(stream->parent()->GetMIOpenConvolveAlgorithms( se::dnn::ConvolutionKind::BACKWARD_DATA, se::dnn::ToDataType<T>::value, stream, input_desc, in_backprop_ptr, filter_desc, filter_ptr, output_desc, out_backprop_ptr, conv_desc, &scratch_allocator, &algorithms));



      std::vector<tensorflow::AutotuneResult> results;
      for (auto miopen_algorithm : algorithms) {
        auto profile_algorithm = miopen_algorithm.algorithm();
        ProfileResult profile_result;
        auto miopen_launch_status = stream->ConvolveBackwardDataWithAlgorithm( filter_desc, filter_ptr, output_desc, out_backprop_ptr, conv_desc, input_desc, &in_backprop_ptr, &scratch_allocator, AlgorithmConfig(profile_algorithm, miopen_algorithm.scratch_size()), &profile_result);



        if (miopen_launch_status.ok()) {
          if (profile_result.is_valid()) {
            results.emplace_back();
            auto& result = results.back();
            result.mutable_conv()->set_algorithm(profile_algorithm.algo_id());
            result.mutable_conv()->set_tensor_ops_enabled( profile_algorithm.tensor_ops_enabled());
            result.set_scratch_bytes(scratch_allocator.TotalByteSize());
            *result.mutable_run_time() = proto_utils::ToDurationProto( absl::Milliseconds(profile_result.elapsed_time_in_ms()));
          }
        }
      }

      LogConvAutotuneResults(se::dnn::ConvolutionKind::BACKWARD_DATA, se::dnn::ToDataType<T>::value, in_backprop_ptr, filter_ptr, out_backprop_ptr, input_desc, filter_desc, output_desc, conv_desc, stream->parent(), results);



      if (CudnnUseFrontend()) {
        OP_REQUIRES_OK(context, BestCudnnConvAlgorithm(results, &plans, &algorithm_config));
      } else {
        OP_REQUIRES_OK(context, BestCudnnConvAlgorithm(results, nullptr, &algorithm_config));
      }
      AutoTuneConv3dBwdData::GetInstance()->Insert(conv_parameters, algorithm_config);
    }

    Status cudnn_launch_status;
    DnnScratchAllocator scratch_allocator(ConvolveBackwardDataScratchSize, context);
    if (CudnnUseFrontend()) {
      if (algorithm_config.algorithm().has_value()) {
        VLOG(4) << "Conv3DBackpropInput Execution Plan: " << algorithm_config.algorithm()->exec_plan_id();
      } else {
        VLOG(4) << "Convolution AutoTune has been turned off";
      }
      cudnn_launch_status = stream->ConvolveBackwardDataWithExecutionPlan( filter_desc, filter_ptr, output_desc, out_backprop_ptr, conv_desc, input_desc, &in_backprop_ptr, &scratch_allocator, algorithm_config, nullptr);


    } else {
      cudnn_launch_status = stream->ConvolveBackwardDataWithAlgorithm( filter_desc, filter_ptr, output_desc, out_backprop_ptr, conv_desc, input_desc, &in_backprop_ptr, &scratch_allocator, algorithm_config, nullptr);


    }

    if (!cudnn_launch_status.ok()) {
      context->SetStatus(cudnn_launch_status);
    }

    if (rows_odd || cols_odd || planes_odd) {
      Tensor in_backprop_remove_padding;
      OP_REQUIRES_OK( context, context->allocate_temp( DataTypeToEnum<T>::value, ShapeFromFormat(compute_data_format, dims.batch_size, {{dims.input_size(0), dims.input_size(1), dims.input_size(2)}}, dims.in_depth), &in_backprop_remove_padding));







      
      functor::PadInput<GPUDevice, T, int, 5>()( context->eigen_device<GPUDevice>(), To32Bit(const_cast<const Tensor&>(pre_transformed_in_backprop)

                      .tensor<T, 5>()), {{0, 0, 0}}, {{-planes_odd, -rows_odd, -cols_odd}}, To32Bit(in_backprop_remove_padding.tensor<T, 5>()), compute_data_format, T{});



      pre_transformed_in_backprop = in_backprop_remove_padding;
    }

    if (data_format_ == FORMAT_NHWC && compute_data_format == FORMAT_NCHW) {
      auto toConstTensor = [](const Tensor& x) -> const Tensor { return x; };
      functor::NCHWToNHWC<GPUDevice, T, 5>()( context->eigen_device<GPUDevice>(), toConstTensor(pre_transformed_in_backprop).template tensor<T, 5>(), in_backprop->tensor<T, 5>());


    } else {
      *in_backprop = pre_transformed_in_backprop;
    }
  }

 private:
  std::vector<int32> dilation_;
  std::vector<int32> stride_;
  Padding padding_;
  TensorFormat data_format_;
  bool takes_shape_;
  bool cudnn_use_autotune_;
};


struct Conv3dBackwardFilterAutoTuneGroup {
  static string name() { return "Conv3dBwdFilter"; }
};

typedef AutoTuneSingleton<Conv3dBackwardFilterAutoTuneGroup, ConvParameters, se::dnn::AlgorithmConfig> AutoTuneConv3dBwdFilter;


template <typename T> class Conv3DBackpropFilterOp<GPUDevice, T> : public OpKernel {
 public:
  explicit Conv3DBackpropFilterOp(OpKernelConstruction* context)
      : OpKernel(context), data_format_(FORMAT_NHWC), takes_shape_(type_string().find("V2") != std::string::npos) {

    
    if (takes_shape_) {
      string data_format;
      OP_REQUIRES_OK(context, context->GetAttr("data_format", &data_format));
      OP_REQUIRES(context, FormatFromString(data_format, &data_format_), errors::InvalidArgument("Invalid data format"));
    }
    OP_REQUIRES_OK(context, context->GetAttr("dilations", &dilation_));
    OP_REQUIRES(context, dilation_.size() == 5, errors::InvalidArgument("Dilation rates field must " "specify 5 dimensions"));

    OP_REQUIRES(context, (GetTensorDim(dilation_, data_format_, 'C') == 1 && GetTensorDim(dilation_, data_format_, 'N') == 1), errors::InvalidArgument( "Current implementation does not yet support " "dilation rates in the batch and depth dimensions."));




    OP_REQUIRES( context, (GetTensorDim(dilation_, data_format_, '0') > 0 && GetTensorDim(dilation_, data_format_, '1') > 0 && GetTensorDim(dilation_, data_format_, '2') > 0), errors::InvalidArgument("Dilated rates should be larger than 0."));




    OP_REQUIRES_OK(context, context->GetAttr("strides", &stride_));
    OP_REQUIRES(context, stride_.size() == 5, errors::InvalidArgument("Sliding window strides field must " "specify 5 dimensions"));

    OP_REQUIRES( context, (GetTensorDim(stride_, data_format_, 'C') == 1 && GetTensorDim(stride_, data_format_, 'N') == 1), errors::InvalidArgument("Current implementation does not yet support " "strides in the batch and depth dimensions."));




    OP_REQUIRES( context, (GetTensorDim(stride_, data_format_, '0') > 0 && GetTensorDim(stride_, data_format_, '1') > 0 && GetTensorDim(stride_, data_format_, '2') > 0), errors::InvalidArgument("Spatial strides should be larger than 0."));




    OP_REQUIRES_OK(context, context->GetAttr("padding", &padding_));
    cudnn_use_autotune_ = CudnnUseAutotune();
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& input = context->input(0);
    const TensorShape& input_shape = input.shape();

    const Tensor& out_backprop = context->input(2);
    const TensorShape& out_backprop_shape = out_backprop.shape();

    TensorShape filter_shape;
    if (takes_shape_) {
      const Tensor& filter_sizes = context->input(1);
      OP_REQUIRES_OK(context, tensor::MakeShape(filter_sizes, &filter_shape));
    } else {
      filter_shape = context->input(1).shape();
    }

    ConvBackpropDimensions dims;
    OP_REQUIRES_OK( context, ConvBackpropComputeDimensionsV2( "Conv3DBackpropFilterOp", 3, input_shape, filter_shape, out_backprop_shape, dilation_, stride_, padding_, , data_format_, &dims));





    Tensor* filter_backprop;
    OP_REQUIRES_OK(context, context->allocate_output(0, filter_shape, &filter_backprop));

    auto* stream = context->op_device_context()->stream();
    OP_REQUIRES(context, stream, errors::Internal("No GPU stream available."));

    bool is_grouped_convolution = filter_shape.dim_size(3) != dims.in_depth;
    if (!is_grouped_convolution && dims.filter_size(1) == 1 && dims.filter_size(2) == 1 && dims.filter_size(0) == 1 && dims.dilation(2) == 1 && dims.dilation(1) == 1 && dims.dilation(0) == 1 && dims.stride(2) == 1 && dims.stride(1) == 1 && dims.stride(0) == 1 && data_format_ == FORMAT_NHWC) {



      const uint64 m = dims.in_depth;
      const uint64 k = dims.batch_size * dims.input_size(1) * dims.input_size(2) * dims.input_size(0);
      const uint64 n = dims.out_depth;

      
      
      
      auto a_ptr = AsDeviceMemory(out_backprop.template flat<T>().data(), out_backprop.template flat<T>().size());

      
      
      
      auto b_ptr = AsDeviceMemory(input.template flat<T>().data(), input.template flat<T>().size());

      
      
      
      auto c_ptr = AsDeviceMemory(filter_backprop->template flat<T>().data(), filter_backprop->template flat<T>().size());

      bool blas_launch_status = stream ->ThenBlasGemm(se::blas::Transpose::kNoTranspose, se::blas::Transpose::kTranspose, n, m, k, 1.0f, a_ptr, n, b_ptr, m, 0.0f, &c_ptr, n)



              .ok();
      if (!blas_launch_status) {
        context->SetStatus(errors::Internal("Blas SGEMM launch failed : m=", m, ", n=", n, ", k=", k));
      }
      return;
    } else if (!is_grouped_convolution && dims.filter_size(0) == dims.input_size(0) && dims.filter_size(1) == dims.input_size(1) && dims.filter_size(2) == dims.input_size(2) && padding_ == Padding::VALID && data_format_ == FORMAT_NHWC) {



      const uint64 m = dims.input_size(0) * dims.input_size(1) * dims.input_size(2) * dims.in_depth;
      const uint64 k = dims.batch_size;
      const uint64 n = dims.out_depth;

      auto a_ptr = AsDeviceMemory(input.template flat<T>().data(), input.template flat<T>().size());
      auto b_ptr = AsDeviceMemory(out_backprop.template flat<T>().data(), out_backprop.template flat<T>().size());
      auto c_ptr = AsDeviceMemory(filter_backprop->template flat<T>().data(), filter_backprop->template flat<T>().size());

      bool blas_launch_status = stream ->ThenBlasGemm(se::blas::Transpose::kNoTranspose, se::blas::Transpose::kTranspose, n, m, k, 1.0f, b_ptr, n, a_ptr, m, 0.0f, &c_ptr, n)



              .ok();
      if (!blas_launch_status) {
        context->SetStatus(errors::Internal("Blas SGEMM launch failed : m=", m, ", n=", n, ", k=", k));
      }
      return;
    }

    int padding_planes = dims.SpatialPadding(padding_, 0);
    int padding_rows = dims.SpatialPadding(padding_, 1);
    int padding_cols = dims.SpatialPadding(padding_, 2);
    const bool planes_odd = (padding_planes % 2 != 0);
    const bool rows_odd = (padding_rows % 2 != 0);
    const bool cols_odd = (padding_cols % 2 != 0);

    Tensor compatible_input;
    if (rows_odd || cols_odd || planes_odd) {
      OP_REQUIRES_OK(context, context->allocate_temp( DataTypeToEnum<T>::value, ShapeFromFormat(data_format_, dims.batch_size, {{dims.input_size(0) + planes_odd, dims.input_size(1) + rows_odd, dims.input_size(2) + cols_odd}}, dims.in_depth), &compatible_input));







      functor::PadInput<GPUDevice, T, int, 5>()( context->template eigen_device<GPUDevice>(), To32Bit(input.tensor<T, 5>()), {{0, 0, 0}}, {{planes_odd, rows_odd, cols_odd}}, To32Bit(compatible_input.tensor<T, 5>()), data_format_, T{});



    } else {
      compatible_input = input;
    }

    CHECK(padding_rows >= 0 && padding_cols >= 0 && padding_planes >= 0)
        << "Negative paddings: (" << padding_rows << ", " << padding_cols << ", " << padding_planes << ")";


    const bool compute_in_nhwc = CUDNN_VERSION >= 8000 && DataTypeToEnum<T>::value == DT_HALF;

    
    const bool compute_in_nhwc = false;

    const TensorFormat compute_data_format = (compute_in_nhwc && data_format_ == FORMAT_NHWC) ? FORMAT_NHWC : FORMAT_NCHW;


    VLOG(3) << "Compute Conv3DBackpropFilter with cuDNN:" << " data_format=" << ToString(data_format_)
            << " compute_data_format=" << ToString(compute_data_format);

    constexpr auto kComputeInNHWC = std::make_tuple(se::dnn::DataLayout::kBatchYXDepth, se::dnn::FilterLayout::kOutputYXInput);

    constexpr auto kComputeInNCHW = std::make_tuple(se::dnn::DataLayout::kBatchDepthYX, se::dnn::FilterLayout::kOutputInputYX);


    se::dnn::DataLayout compute_data_layout;
    se::dnn::FilterLayout filter_layout;

    std::tie(compute_data_layout, filter_layout) = compute_data_format == FORMAT_NHWC ? kComputeInNHWC : kComputeInNCHW;

    se::dnn::BatchDescriptor input_desc(3);
    input_desc.set_count(dims.batch_size)
        .set_spatial_dim(DimIndex::X, GetTensorDim(compatible_input, data_format_, '2'))
        .set_spatial_dim(DimIndex::Y, GetTensorDim(compatible_input, data_format_, '1'))
        .set_spatial_dim(DimIndex::Z, GetTensorDim(compatible_input, data_format_, '0'))
        .set_feature_map_count(dims.in_depth)
        .set_layout(compute_data_layout);
    se::dnn::BatchDescriptor output_desc(3);
    output_desc.set_count(dims.batch_size)
        .set_spatial_dim(DimIndex::X, dims.output_size(2))
        .set_spatial_dim(DimIndex::Y, dims.output_size(1))
        .set_spatial_dim(DimIndex::Z, dims.output_size(0))
        .set_feature_map_count(dims.out_depth)
        .set_layout(compute_data_layout);
    se::dnn::FilterDescriptor filter_desc(3);
    filter_desc.set_spatial_dim(DimIndex::X, dims.filter_size(2))
        .set_spatial_dim(DimIndex::Y, dims.filter_size(1))
        .set_spatial_dim(DimIndex::Z, dims.filter_size(0))
        .set_input_feature_map_count(filter_shape.dim_size(3))
        .set_output_feature_map_count(filter_shape.dim_size(4))
        .set_layout(filter_layout);
    se::dnn::ConvolutionDescriptor conv_desc(3);
    conv_desc.set_dilation_rate(DimIndex::X, dims.dilation(2))
        .set_dilation_rate(DimIndex::Y, dims.dilation(1))
        .set_dilation_rate(DimIndex::Z, dims.dilation(0))
        .set_filter_stride(DimIndex::X, dims.stride(2))
        .set_filter_stride(DimIndex::Y, dims.stride(1))
        .set_filter_stride(DimIndex::Z, dims.stride(0))
        .set_zero_padding(DimIndex::X, padding_cols / 2)
        .set_zero_padding(DimIndex::Y, padding_rows / 2)
        .set_zero_padding(DimIndex::Z, padding_planes / 2)
        .set_group_count(dims.in_depth / filter_shape.dim_size(3));

    Tensor pre_transformed_filter_backprop;
    auto dst_format = compute_data_format == FORMAT_NCHW ? FORMAT_OIHW : FORMAT_OHWI;
    TensorShape dst_shape = dst_format == FORMAT_OIHW ? TensorShape({filter_shape.dim_size(4), filter_shape.dim_size(3), dims.filter_size(0), dims.filter_size(1), dims.filter_size(2)})



            : TensorShape({filter_shape.dim_size(4), dims.filter_size(0), dims.filter_size(1), dims.filter_size(2), filter_shape.dim_size(3)});

    OP_REQUIRES_OK(context, context->allocate_temp(DataTypeToEnum<T>::value, dst_shape, &pre_transformed_filter_backprop));


    Tensor transformed_out_backprop;
    if (data_format_ == FORMAT_NHWC && compute_data_format == FORMAT_NCHW) {
      VLOG(4) << "Convert the `out_backprop` tensor from NDHWC to NCDHW.";
      TensorShape nchw_shape = {dims.batch_size, dims.out_depth, dims.output_size(0), dims.output_size(1), dims.output_size(2)};

      OP_REQUIRES_OK( context, context->allocate_temp(DataTypeToEnum<T>::value, nchw_shape, &transformed_out_backprop));

      if (dims.out_depth > 1) {
        functor::NHWCToNCHW<GPUDevice, T, 5>()( context->eigen_device<GPUDevice>(), out_backprop.tensor<T, 5>(), transformed_out_backprop.tensor<T, 5>());

      } else {
        CHECK(transformed_out_backprop.CopyFrom(out_backprop, nchw_shape));
      }
    } else {
      transformed_out_backprop = out_backprop;
    }
    Tensor transformed_input;
    if (data_format_ == FORMAT_NHWC && compute_data_format == FORMAT_NCHW) {
      VLOG(4) << "Convert the `input` tensor from NDHWC to NCDHW.";
      TensorShape nchw_shape = {
          dims.batch_size, dims.in_depth, compatible_input.dim_size(1), compatible_input.dim_size(2), compatible_input.dim_size(3)};
      if (dims.in_depth > 1) {
        OP_REQUIRES_OK(context, context->allocate_temp(DataTypeToEnum<T>::value, nchw_shape, &transformed_input));

        functor::NHWCToNCHW<GPUDevice, T, 5>()( context->eigen_device<GPUDevice>(), const_cast<const Tensor&>(compatible_input).tensor<T, 5>(), transformed_input.tensor<T, 5>());


      } else {
        CHECK(transformed_input.CopyFrom(compatible_input, nchw_shape));
      }
    } else {
      transformed_input = compatible_input;
    }

    auto out_backprop_ptr = AsDeviceMemory(transformed_out_backprop.template flat<T>().data(), transformed_out_backprop.template flat<T>().size());

    auto filter_backprop_ptr = AsDeviceMemory( pre_transformed_filter_backprop.template flat<T>().data(), pre_transformed_filter_backprop.template flat<T>().size());

    auto input_ptr = AsDeviceMemory(transformed_input.template flat<T>().data(), transformed_input.template flat<T>().size());


    static int64 ConvolveBackwardFilterScratchSize = GetDnnWorkspaceLimit( "TF_CUDNN_WORKSPACE_LIMIT_IN_MB", 1LL << 32);

    const int device_id = stream->parent()->device_ordinal();
    DataType dtype = input.dtype();
    const ConvParameters conv_parameters = {
        dims.batch_size, dims.in_depth, {{dims.input_size(0), dims.input_size(1), dims.input_size(2)}}, compute_data_format, dims.out_depth, {{dims.filter_size(0), dims.filter_size(1), dims.filter_size(2)}}, {{dims.dilation(0), dims.dilation(1), dims.dilation(2)}}, {{dims.stride(0), dims.stride(1), dims.stride(2)}}, {{padding_planes, padding_rows, padding_cols}}, dtype, device_id, conv_desc.group_count()};











    using se::dnn::AlgorithmConfig;
    using se::dnn::AlgorithmDesc;
    using se::dnn::ProfileResult;

    
    
    
    cudnn_use_autotune_ = true;


    AlgorithmConfig algorithm_config;

    if (cudnn_use_autotune_ && !AutoTuneConv3dBwdFilter::GetInstance()->Find( conv_parameters, &algorithm_config)) {
      std::vector<std::unique_ptr<se::dnn::ConvolveExecutionPlan>> plans;

      std::vector<AlgorithmDesc> algorithms;
      std::vector<AlgorithmConfig> configs;
      if (CudnnUseFrontend()) {
        OP_REQUIRES(context, stream->parent()->GetConvolveExecutionPlans( se::dnn::ConvolutionKind::BACKWARD_FILTER, se::dnn::ToDataType<T>::value, stream, input_desc, filter_desc, output_desc, conv_desc, &plans), errors::Unknown( "Failed to get convolution execution plan. This is " "probably because cuDNN failed to initialize, so try " "looking to see if a warning log message was printed " "above."));








        for (const auto& plan : plans) {
          configs.push_back(AlgorithmConfig( AlgorithmDesc{plan->getTag(), plan->get_raw_desc()}, plan->getWorkspaceSize()));

        }
      } else {
        OP_REQUIRES(context, stream->parent()->GetConvolveBackwardFilterAlgorithms( conv_parameters.ShouldIncludeWinogradNonfusedAlgo<T>( stream->parent()), &algorithms), errors::Unknown( "Failed to get convolution execution plan. This is " "probably because cuDNN failed to initialize, so try " "looking to see if a warning log message was printed " "above."));








        for (const auto& algorithm : algorithms) {
          configs.push_back(AlgorithmConfig(algorithm));
        }
      }

      std::vector<tensorflow::AutotuneResult> results;
      for (auto& profile_config : configs) {
        
        
        DnnScratchAllocator scratch_allocator(ConvolveBackwardFilterScratchSize, context);
        ProfileResult profile_result;
        Status cudnn_launch_status;
        if (CudnnUseFrontend()) {
          cudnn_launch_status = stream->ConvolveBackwardFilterWithExecutionPlan( input_desc, input_ptr, output_desc, out_backprop_ptr, conv_desc, filter_desc, &filter_backprop_ptr, &scratch_allocator, profile_config, &profile_result);


        } else {
          cudnn_launch_status = stream->ConvolveBackwardFilterWithAlgorithm( input_desc, input_ptr, output_desc, out_backprop_ptr, conv_desc, filter_desc, &filter_backprop_ptr, &scratch_allocator, profile_config, &profile_result);


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

          result.set_scratch_bytes(scratch_allocator.TotalByteSize());
          *result.mutable_run_time() = proto_utils::ToDurationProto( absl::Milliseconds(profile_result.elapsed_time_in_ms()));

        } else if (CudnnUseFrontend()) {
          
          
          
          results.emplace_back();
          auto& result = results.back();
          result.mutable_failure()->set_kind(AutotuneResult::UNKNOWN);
          result.mutable_failure()->set_msg( absl::StrCat("Profiling failure on CUDNN engine: ", profile_config.algorithm()->exec_plan_id()));

        }
      }

      DnnScratchAllocator scratch_allocator(ConvolveBackwardFilterScratchSize, context);
      std::vector<ProfileResult> algorithms;
      CHECK(stream->parent()->GetMIOpenConvolveAlgorithms( se::dnn::ConvolutionKind::BACKWARD_FILTER, se::dnn::ToDataType<T>::value, stream, input_desc, input_ptr, filter_desc, filter_backprop_ptr, output_desc, out_backprop_ptr, conv_desc, &scratch_allocator, &algorithms));




      std::vector<tensorflow::AutotuneResult> results;
      for (auto miopen_algorithm : algorithms) {
        auto profile_algorithm = miopen_algorithm.algorithm();
        ProfileResult profile_result;
        auto cudnn_launch_status = stream->ConvolveBackwardFilterWithAlgorithm( input_desc, input_ptr, output_desc, out_backprop_ptr, conv_desc, filter_desc, &filter_backprop_ptr, &scratch_allocator, AlgorithmConfig(profile_algorithm, miopen_algorithm.scratch_size()), &profile_result);



        if (cudnn_launch_status.ok()) {
          if (profile_result.is_valid()) {
            results.emplace_back();
            auto& result = results.back();
            result.mutable_conv()->set_algorithm(profile_algorithm.algo_id());
            result.mutable_conv()->set_tensor_ops_enabled( profile_algorithm.tensor_ops_enabled());
            result.set_scratch_bytes(scratch_allocator.TotalByteSize());
            *result.mutable_run_time() = proto_utils::ToDurationProto( absl::Milliseconds(profile_result.elapsed_time_in_ms()));
          }
        }
      }

      LogConvAutotuneResults(se::dnn::ConvolutionKind::BACKWARD_FILTER, se::dnn::ToDataType<T>::value, input_ptr, filter_backprop_ptr, out_backprop_ptr, input_desc, filter_desc, output_desc, conv_desc, stream->parent(), results);



      if (CudnnUseFrontend()) {
        OP_REQUIRES_OK(context, BestCudnnConvAlgorithm(results, &plans, &algorithm_config));
      } else {
        Status s = BestCudnnConvAlgorithm(results, nullptr, &algorithm_config);

        if (s.code() == error::NOT_FOUND) {
          size_t version = cudnnGetVersion();
          
          
          
          
          if (version == 8003 || version == 8004) {
            std::string version_str = (version == 8003 ? "8.0.3" : "8.0.4");
            s = errors::NotFound( "No algorithm worked! Please try upgrading to cuDNN 8.0.5. You " "are using cuDNN ", version_str, ", which has a bug causing this error.");


          }
        }

        OP_REQUIRES_OK(context, s);
      }
      AutoTuneConv3dBwdFilter::GetInstance()->Insert(conv_parameters, algorithm_config);
    }

    Status cudnn_launch_status;
    DnnScratchAllocator scratch_allocator(ConvolveBackwardFilterScratchSize, context);
    if (CudnnUseFrontend()) {
      if (algorithm_config.algorithm().has_value()) {
        VLOG(4) << "Conv3DBackpropFilter Execution Plan: " << algorithm_config.algorithm()->exec_plan_id();
      } else {
        VLOG(4) << "Convolution AutoTune has been turned off";
      }
      cudnn_launch_status = stream->ConvolveBackwardFilterWithExecutionPlan( input_desc, input_ptr, output_desc, out_backprop_ptr, conv_desc, filter_desc, &filter_backprop_ptr, &scratch_allocator, algorithm_config, nullptr);


    } else {
      cudnn_launch_status = stream->ConvolveBackwardFilterWithAlgorithm( input_desc, input_ptr, output_desc, out_backprop_ptr, conv_desc, filter_desc, &filter_backprop_ptr, &scratch_allocator, algorithm_config, nullptr);


    }

    if (!cudnn_launch_status.ok()) {
      context->SetStatus(cudnn_launch_status);
    }

    auto toConstTensor = [](const Tensor& x) -> const Tensor { return x; };
    functor::ReverseTransformFilter<GPUDevice, T, 5>()( context->eigen_device<GPUDevice>(), dst_format, toConstTensor(pre_transformed_filter_backprop).template tensor<T, 5>(), filter_backprop->tensor<T, 5>());


  }

 private:
  std::vector<int32> dilation_;
  std::vector<int32> stride_;
  Padding padding_;
  TensorFormat data_format_;
  bool takes_shape_;
  bool cudnn_use_autotune_;
};

















TF_CALL_half(REGISTER_GPU_KERNEL);
TF_CALL_float(REGISTER_GPU_KERNEL);
TF_CALL_double(REGISTER_GPU_KERNEL);




}  
