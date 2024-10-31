



















namespace tensorflow {

typedef Eigen::ThreadPoolDevice CPUDevice;
typedef Eigen::GpuDevice GPUDevice;

template <typename Device, typename T> class TopK : public OpKernel {
 public:
  explicit TopK(OpKernelConstruction* context) : OpKernel(context) {
    OP_REQUIRES_OK(context, context->GetAttr("sorted", &sorted_));
    if (num_inputs() < 2) {  
      OP_REQUIRES_OK(context, context->GetAttr("k", &k_));
    } else {  
      k_ = -1;
    }
  }

  void Compute(OpKernelContext* context) override {
    int k = k_;
    if (num_inputs() >= 2) {
      const auto& k_in = context->input(1);
      OP_REQUIRES(context, TensorShapeUtils::IsScalar(k_in.shape()), errors::InvalidArgument("k must be scalar, got shape ", k_in.shape().DebugString()));

      k = k_in.scalar<int32>()();
    }
    OP_REQUIRES(context, k >= 0, errors::InvalidArgument("Need k >= 0, got ", k));
    const auto& input_in = context->input(0);
    OP_REQUIRES(context, input_in.dims() >= 1, errors::InvalidArgument("input must be >= 1-D, got shape ", input_in.shape().DebugString()));

    OP_REQUIRES(context, input_in.dim_size(input_in.dims() - 1) >= k, errors::InvalidArgument( "input must have at least k columns. Had ", input_in.dim_size(input_in.dims() - 1), ", needed ", k));



    const auto& input = input_in.flat_inner_dims<T>();

    const int64 num_rows = input.dimension(0);  
    const int64 num_cols = input.dimension(1);

    TensorShape output_shape = input_in.shape();
    output_shape.set_dim(input_in.dims() - 1, k);
    Tensor* values_out = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output(0, output_shape, &values_out));
    Tensor* indices_out = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output(1, output_shape, &indices_out));

    
    if (k == 0 || num_rows == 0) return;

    auto values = values_out->flat_inner_dims<T>();
    auto indices = indices_out->flat_inner_dims<int32>();
    Status s = functor::TopKFunctor<Device, T>::Compute( context, sorted_, k, input, num_rows, num_cols, values, indices);
    OP_REQUIRES_OK(context, s);
  }

 private:
  int k_;
  bool sorted_;
};

namespace functor {

template <typename T> struct TopKFunctor<CPUDevice, T> {
  static EIGEN_ALWAYS_INLINE Status Compute(OpKernelContext* context, bool sorted, int k, const typename TTypes<T, 2>::ConstTensor& input, const int64 num_rows, const int64 num_cols, typename TTypes<T, 2>::Tensor values, typename TTypes<int, 2>::Tensor indices) {



    const CPUDevice& d = context->eigen_device<CPUDevice>();

    
    if (k == 1) {

      typename Eigen::IndexList<Eigen::type2index<1>> reduce_on_cols;
      typename Eigen::IndexList<int, Eigen::type2index<1>> rows_by_one;
      rows_by_one.set(0, num_rows);

      Eigen::array<int, 1> reduce_on_cols = {1};
      Eigen::array<int, 2> rows_by_one = {static_cast<int>(num_rows), 1};


      values.device(d) = input.maximum(reduce_on_cols).eval().reshape(rows_by_one);
      
      for (int r = 0; r < num_rows; ++r) {
        indices(r, 0) = 0;
        for (int c = 0; c < num_cols; ++c) {
          if (values(r, 0) == input(r, c)) {
            indices(r, 0) = c;
            break;
          }
        }
        values(r, 0) = input(r, indices(r, 0));
      }

      return Status::OK();
    }

    auto SortIndices = [&](int start_batch, int limit_batch) {
      for (int32 b = start_batch; b < limit_batch; ++b) {
        const T* input_data = &input(b, 0);
        const auto stable_comp = [input_data](const int32 a, const int32 b) {
          if (input_data[b] < input_data[a]) {
            return true;
          } else if (input_data[b] > input_data[a]) {
            return false;
          } else {
            return a < b;
          }
        };
        const auto comp = [input_data](const int32 a, const int32 b) {
          return input_data[b] < input_data[a];
        };
        
        
        
        
        
        if (k == num_cols) {
          auto* begin = &indices(b, 0);
          auto* end = &indices(b, k);
          
          std::iota(begin, end, 0);
          
          
          
          std::sort(begin, end, comp);
          
          
          for (auto* run_begin = begin; run_begin != end;) {
            auto* run_end = run_begin + 1;
            if (run_end == end) break;
            if (input_data[*run_begin] == input_data[*run_end]) {
              while (++run_end != end) {
                if (input_data[*run_begin] != input_data[*run_end]) break;
              }
              std::sort(run_begin, run_end);
            }
            run_begin = run_end;
          }
        } else {
          
          gtl::TopN<int32, decltype(stable_comp)> filter(k, stable_comp);
          filter.reserve(num_cols);
          for (int32 c = 0; c < num_cols; ++c) {
            filter.push(c);
          }

          int32 i = 0;
          if (sorted) {
            std::unique_ptr<std::vector<int32>> top_k(filter.Extract());
            for (auto top_k_it = top_k->begin(); top_k_it != top_k->end();
                 ++top_k_it, ++i) {
              indices(b, i) = *top_k_it;
            }
          } else {
            for (auto top_k_it = filter.unsorted_begin();
                 top_k_it != filter.unsorted_end(); ++top_k_it, ++i) {
              indices(b, i) = *top_k_it;
            }
          }
        }
        
        
        std::transform(&indices(b, 0), &indices(b, k), &values(b, 0), [b, &input](const int32 loc) { return input(b, loc); });
      }  
    };

    
    
    const double cmp_cost = 3 * Eigen::TensorOpCost::AddCost<int32>() + Eigen::TensorOpCost::AddCost<T>();
    const double base_cost = cmp_cost * static_cast<double>(num_cols * Eigen::numext::log2(static_cast<float>(k + 1)));


    const double sort_cost = (k == num_cols) ? base_cost : 4 * base_cost;
    const double copy_cost = 2 * k * Eigen::TensorOpCost::AddCost<T>();
    const double total_cost = sort_cost + copy_cost;
    const int64 final_cost = (total_cost >= static_cast<double>(kint64max))
                                 ? kint64max : static_cast<int64>(total_cost);
    auto worker_threads = *(context->device()->tensorflow_cpu_worker_threads());
    Shard(worker_threads.num_threads, worker_threads.workers, num_rows, final_cost, SortIndices);

    return Status::OK();
  }
};

}  








TF_CALL_REAL_NUMBER_TYPES(REGISTER_KERNELS);





namespace functor {








TF_CALL_GPU_NUMBER_TYPES(DECLARE_GPU_SPEC);
TF_CALL_INTEGRAL_TYPES(DECLARE_GPU_SPEC);



}  










TF_CALL_GPU_NUMBER_TYPES(REGISTER_KERNELS);
TF_CALL_INTEGRAL_TYPES(REGISTER_KERNELS);




}  
