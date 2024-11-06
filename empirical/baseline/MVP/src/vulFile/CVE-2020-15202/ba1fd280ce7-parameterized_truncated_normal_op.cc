


























namespace tensorflow {

typedef Eigen::ThreadPoolDevice CPUDevice;
typedef Eigen::GpuDevice GPUDevice;

namespace functor {
using random::PhiloxRandom;

static constexpr int kMaxIterations = 1000;

template <typename T> struct TruncatedNormalFunctor<CPUDevice, T> {
  void operator()(OpKernelContext* ctx, const CPUDevice& d, int64 num_batches, int64 samples_per_batch, int64 num_elements, typename TTypes<T>::ConstFlat means, typename TTypes<T>::ConstFlat stddevs, typename TTypes<T>::ConstFlat minvals, typename TTypes<T>::ConstFlat maxvals, const random::PhiloxRandom& gen, typename TTypes<T>::Flat output) {






    
    
    
    
    
    
    
    const T kStdDevsInsideBoundsToUseRandnSampler = T(1.3);
    auto worker_threads = *(ctx->device()->tensorflow_cpu_worker_threads());

    auto do_work = [samples_per_batch, num_elements, &ctx, &means, &stddevs, &minvals, &maxvals, &gen, &output, kStdDevsInsideBoundsToUseRandnSampler](int start_batch, int limit_batch) {


      
      
      
      random::PhiloxRandom gen_copy = gen;
      
      
      
      gen_copy.Skip(start_batch * 2 * kMaxIterations * (samples_per_batch + 3) / 4);
      using Uniform = random::UniformDistribution<random::PhiloxRandom, T>;
      Uniform dist;
      using Normal = random::NormalDistribution<random::PhiloxRandom, T>;
      Normal normal_dist;

      
      
      Eigen::array<T, 4> z;
      Eigen::array<T, 4> g;

      for (int64 b = start_batch; b < limit_batch; ++b) {
        
        
        
        T mean = means((means.dimension(0) == 1) ? 0 : b);
        T stddev = stddevs((stddevs.dimension(0) == 1) ? 0 : b);
        T minval = minvals((minvals.dimension(0) == 1) ? 0 : b);
        T maxval = maxvals((maxvals.dimension(0) == 1) ? 0 : b);

        
        
        const int64 limit_sample = std::min((b + 1) * samples_per_batch, num_elements);
        int64 sample = b * samples_per_batch;

        
        OP_REQUIRES(ctx, stddev > T(0) && minval < maxval && (Eigen::numext::isfinite(minval) || Eigen::numext::isfinite(maxval)), errors::InvalidArgument("Invalid parameters"));




        int num_iterations = 0;

        
        
        
        if ((Eigen::numext::isinf(minval) && minval < T(0)) || maxval < mean) {
          
          std::swap(minval, maxval);
          stddev = -stddev;
        }

        
        const T normMin = (minval - mean) / stddev;
        const T normMax = (maxval - mean) / stddev;

        
        const T sqrtFactor = Eigen::numext::sqrt((normMin * normMin) + T(4));
        const T cutoff = T(2) * Eigen::numext::exp(T(0.5) + (normMin * (normMin - sqrtFactor)) / T(4)) / (normMin + sqrtFactor);



        const T diff = normMax - normMin;

        if (((normMin < -kStdDevsInsideBoundsToUseRandnSampler) && (normMax >= T(0.))) || ((normMax > kStdDevsInsideBoundsToUseRandnSampler) && (normMin <= T(0.)))) {


          
          
          
          
          
          
          

          while (sample < limit_sample) {
            const auto randn_sample = normal_dist(&gen_copy);
            const int size = randn_sample.size();

            for (int i = 0; i < size; i++) {
              if ((randn_sample[i] >= normMin) && (randn_sample[i] <= normMax)) {
                output(sample) = randn_sample[i] * stddev + mean;
                sample++;
                if (sample >= limit_sample) {
                  break;
                }
                num_iterations = 0;
              } else {
                num_iterations++;
                if (num_iterations > kMaxIterations) {
                  
                  
                  
                  
                  
                  LOG(ERROR) << "TruncatedNormal randn rejection sampler " << "exceeded maximum iterations for " << "normMin=" << normMin << " normMax=" << normMax << " kMaxIterations=" << kMaxIterations;


                  ctx->SetStatus(errors::Internal( "TruncatedNormal randn rejection sampler failed to accept" " a sample."));

                  return;
                }
              }
            }
          }
        } else if (diff < cutoff) {
          

          const T plusFactor = (normMin < T(0)) ? T(0) : normMin * normMin;

          while (sample < limit_sample) {
            const auto rand = dist(&gen_copy);
            const int size = rand.size();
            
            
            for (int i = 0; i < size; i++) {
              z[i] = rand[i] * diff + normMin;
            }
            for (int i = 0; i < size; i++) {
              g[i] = (plusFactor - z[i] * z[i]) / T(2.0);
            }

            const auto u = dist(&gen_copy);
            for (int i = 0; i < size; i++) {
              auto accept = u[i] <= Eigen::numext::exp(g[i]);
              if (accept || num_iterations + 1 >= kMaxIterations) {
                
                
                
                
                
                
                
                if (!accept) {
                  LOG(ERROR) << "TruncatedNormal uniform rejection sampler " << "exceeded max iterations. Sample may contain " << "outliers.";

                  ctx->SetStatus(errors::Internal( "TruncatedNormal uniform rejection sampler failed to " " accept a sample."));

                  return;
                }
                output(sample) = z[i] * stddev + mean;
                sample++;
                if (sample >= limit_sample) {
                  break;
                }
                num_iterations = 0;
              } else {
                num_iterations++;
              }
            }
          }
        } else {
          
          
          
          const T alpha = (normMin + Eigen::numext::sqrt((normMin * normMin) + T(4))) / T(2);

          while (sample < limit_sample) {
            auto rand = dist(&gen_copy);
            const int size = rand.size();
            int i = 0;
            while (i < size) {
              const T z = -Eigen::numext::log(rand[i]) / alpha + normMin;
              i++;
              const T x = normMin < alpha ? alpha - z : normMin - alpha;
              const T g = Eigen::numext::exp(-x * x / T(2.0));
              const T u = rand[i];
              i++;
              auto accept = (u <= g && z < normMax);
              if (accept || num_iterations + 1 >= kMaxIterations) {
                if (!accept) {
                  LOG(ERROR) << "TruncatedNormal exponential distribution " << "rejection sampler exceeds max iterations. " << "Sample may contain outliers.";

                  ctx->SetStatus(errors::Internal( "TruncatedNormal exponential distribution rejection" " sampler failed to accept a sample."));

                  return;
                }
                output(sample) = z * stddev + mean;
                sample++;
                if (sample >= limit_sample) {
                  break;
                }
                num_iterations = 0;
              } else {
                num_iterations++;
              }
            }
          }
        }
      }
    };
    
    const int64 batchInitCost =  (Eigen::TensorOpCost::AddCost<T>() + Eigen::TensorOpCost::MulCost<T>()) * 2  + Eigen::TensorOpCost::AddCost<T>() + Eigen::TensorOpCost::MulCost<T>() + Eigen::internal::functor_traits< Eigen::internal::scalar_sqrt_op<T>>::Cost  + Eigen::TensorOpCost::MulCost<T>() * 4 + Eigen::internal::functor_traits<Eigen::internal::scalar_exp_op<T>>::Cost  + Eigen::TensorOpCost::AddCost<T>();













    const int64 uniformSampleCost = random::PhiloxRandom::kElementCost + random::UniformDistribution<random::PhiloxRandom, T>::kElementCost;

    
    const int64 uniformRejectionSamplingCost = uniformSampleCost + Eigen::TensorOpCost::MulCost<T>() + Eigen::TensorOpCost::AddCost<T>() + Eigen::TensorOpCost::MulCost<T>() * 2 + Eigen::TensorOpCost::AddCost<T>() + uniformSampleCost + Eigen::internal::functor_traits< Eigen::internal::scalar_exp_op<T>>::Cost + Eigen::TensorOpCost::MulCost<T>() + Eigen::TensorOpCost::AddCost<T>();






    
    
    const int64 batchCost = batchInitCost + uniformRejectionSamplingCost * 2 * samples_per_batch;
    Shard(worker_threads.num_threads, worker_threads.workers, num_batches, batchCost, do_work);
  }
};

template <typename T> struct TruncatedNormalFunctorV2<CPUDevice, T> {
  void operator()(OpKernelContext* ctx, const CPUDevice& d, int64 num_batches, int64 samples_per_batch, int64 num_elements, const BCastList<4>& bcast, typename TTypes<T>::ConstFlat means, typename TTypes<T>::ConstFlat stddevs, typename TTypes<T>::ConstFlat minvals, typename TTypes<T>::ConstFlat maxvals, const random::PhiloxRandom& gen, typename TTypes<T>::Flat output) {







    
    
    
    
    
    
    
    const T kStdDevsInsideBoundsToUseRandnSampler = T(1.3);
    auto worker_threads = *(ctx->device()->tensorflow_cpu_worker_threads());

    auto do_work = [num_batches, samples_per_batch, &ctx, &bcast, &means, &stddevs, &minvals, &maxvals, &gen, &output, kStdDevsInsideBoundsToUseRandnSampler](int start_output, int limit_output) {


      
      
      
      random::PhiloxRandom gen_copy = gen;
      using Uniform = random::UniformDistribution<random::PhiloxRandom, T>;
      Uniform dist;
      using Normal = random::NormalDistribution<random::PhiloxRandom, T>;
      Normal normal_dist;
      
      
      
      
      gen_copy.Skip((start_output * 2 * kMaxIterations + Uniform::kResultElementCount - 1) / Uniform::kResultElementCount);


      
      
      Eigen::array<T, Uniform::kResultElementCount> z;
      Eigen::array<T, Uniform::kResultElementCount> g;

      const bool should_bcast = bcast.IsBroadcastingRequired();
      const auto& means_batch_indices = bcast.batch_indices(0);
      const auto& stddevs_batch_indices = bcast.batch_indices(1);
      const auto& minvals_batch_indices = bcast.batch_indices(2);
      const auto& maxvals_batch_indices = bcast.batch_indices(3);
      auto output_flat = output.data();

      
      
      for (int64 output_idx = start_output; output_idx < limit_output;
           
      ) {
        int64 batch_idx = output_idx / samples_per_batch;
        
        
        
        
        T* const output_batch_offset = output_flat + batch_idx;
        
        
        T mean, stddev, minval, maxval;
        if (should_bcast) {
          mean = means(means_batch_indices[batch_idx]);
          stddev = stddevs(stddevs_batch_indices[batch_idx]);
          minval = minvals(minvals_batch_indices[batch_idx]);
          maxval = maxvals(maxvals_batch_indices[batch_idx]);
        } else {
          mean = means(batch_idx);
          stddev = stddevs(batch_idx);
          minval = minvals(batch_idx);
          maxval = maxvals(batch_idx);
        }

        
        OP_REQUIRES(ctx, stddev > T(0) && minval < maxval && (Eigen::numext::isfinite(minval) || Eigen::numext::isfinite(maxval)), errors::InvalidArgument("Invalid parameters"));




        int num_iterations = 0;

        
        
        
        if ((Eigen::numext::isinf(minval) && minval < T(0)) || maxval < mean) {
          
          std::swap(minval, maxval);
          stddev = -stddev;
        }

        
        const T normMin = (minval - mean) / stddev;
        const T normMax = (maxval - mean) / stddev;

        
        const T sqrtFactor = Eigen::numext::sqrt((normMin * normMin) + T(4));
        const T cutoff = T(2) * Eigen::numext::exp(T(0.5) + (normMin * (normMin - sqrtFactor)) / T(4)) / (normMin + sqrtFactor);



        const T diff = normMax - normMin;

        if (((normMin < -kStdDevsInsideBoundsToUseRandnSampler) && (normMax >= T(0.))) || ((normMax > kStdDevsInsideBoundsToUseRandnSampler) && (normMin <= T(0.)))) {


          
          
          
          
          
          
          
          for (int64 sample_idx = output_idx % samples_per_batch;
               sample_idx < samples_per_batch && output_idx < limit_output;) {
            const auto randn_sample = normal_dist(&gen_copy);
            const int size = randn_sample.size();
            for (int i = 0; i < size; ++i) {
              if ((randn_sample[i] >= normMin) && (randn_sample[i] <= normMax)) {
                output_batch_offset[sample_idx * num_batches] = randn_sample[i] * stddev + mean;
                ++sample_idx;
                ++output_idx;
                if (sample_idx >= samples_per_batch || output_idx >= limit_output) {
                  break;
                }
                num_iterations = 0;
              } else {
                ++num_iterations;
                if (num_iterations > kMaxIterations) {
                  
                  
                  
                  
                  
                  LOG(ERROR) << "TruncatedNormal randn rejection sampler " << "exceeded maximum iterations for " << "normMin=" << normMin << " normMax=" << normMax << " kMaxIterations=" << kMaxIterations;


                  ctx->SetStatus(errors::Internal( "TruncatedNormal randn rejection sampler failed to accept" " a sample."));

                  return;
                }
              }
            }
          }
        } else if (diff < cutoff) {
          

          const T plusFactor = (normMin < T(0)) ? T(0) : normMin * normMin;

          for (int64 sample_idx = output_idx % samples_per_batch;
               sample_idx < samples_per_batch && output_idx < limit_output;) {
            const auto rand = dist(&gen_copy);
            const int size = rand.size();
            
            
            for (int i = 0; i < size; i++) {
              z[i] = rand[i] * diff + normMin;
              g[i] = (plusFactor - z[i] * z[i]) / T(2.0);
            }

            const auto u = dist(&gen_copy);
            for (int i = 0; i < size; i++) {
              auto accept = u[i] <= Eigen::numext::exp(g[i]);
              if (accept || num_iterations + 1 >= kMaxIterations) {
                
                
                
                
                
                
                
                if (!accept) {
                  LOG(ERROR) << "TruncatedNormal uniform rejection sampler " << "exceeded max iterations. Sample may contain " << "outliers.";

                  ctx->SetStatus(errors::Internal( "TruncatedNormal uniform rejection sampler failed to " " accept a sample."));

                  return;
                }
                output_batch_offset[sample_idx * num_batches] = z[i] * stddev + mean;
                ++sample_idx;
                ++output_idx;
                if (sample_idx >= samples_per_batch || output_idx >= limit_output) {
                  break;
                }
                num_iterations = 0;
              } else {
                num_iterations++;
              }
            }
          }
        } else {
          
          
          
          const T alpha = (normMin + Eigen::numext::sqrt((normMin * normMin) + T(4))) / T(2);

          for (int64 sample_idx = output_idx % samples_per_batch;
               sample_idx < samples_per_batch && output_idx < limit_output;) {
            auto rand = dist(&gen_copy);
            const int size = rand.size();
            int i = 0;
            while (i < size) {
              const T z = -Eigen::numext::log(rand[i]) / alpha + normMin;
              i++;
              const T x = normMin < alpha ? alpha - z : normMin - alpha;
              const T g = Eigen::numext::exp(-x * x / T(2.0));
              const T u = rand[i];
              i++;
              auto accept = (u <= g && z < normMax);
              if (accept || num_iterations + 1 >= kMaxIterations) {
                if (!accept) {
                  LOG(ERROR) << "TruncatedNormal exponential distribution " << "rejection sampler exceeds max iterations. " << "Sample may contain outliers.";

                  ctx->SetStatus(errors::Internal( "TruncatedNormal exponential distribution rejection" " sampler failed to accept a sample."));

                  return;
                }
                output_batch_offset[sample_idx * num_batches] = z * stddev + mean;
                ++sample_idx;
                ++output_idx;
                if (sample_idx >= samples_per_batch || output_idx >= limit_output) {
                  break;
                }
                num_iterations = 0;
              } else {
                num_iterations++;
              }
            }
          }
        }
      }
    };
    
    const int64 batchInitCost =  (Eigen::TensorOpCost::AddCost<T>() + Eigen::TensorOpCost::MulCost<T>()) * 2  + Eigen::TensorOpCost::AddCost<T>() + Eigen::TensorOpCost::MulCost<T>() + Eigen::internal::functor_traits< Eigen::internal::scalar_sqrt_op<T>>::Cost  + Eigen::TensorOpCost::MulCost<T>() * 4 + Eigen::internal::functor_traits<Eigen::internal::scalar_exp_op<T>>::Cost  + Eigen::TensorOpCost::AddCost<T>();













    const int64 uniformSampleCost = random::PhiloxRandom::kElementCost + random::UniformDistribution<random::PhiloxRandom, T>::kElementCost;

    
    const int64 uniformRejectionSamplingCost = uniformSampleCost + Eigen::TensorOpCost::MulCost<T>() + Eigen::TensorOpCost::AddCost<T>() + Eigen::TensorOpCost::MulCost<T>() * 2 + Eigen::TensorOpCost::AddCost<T>() + uniformSampleCost + Eigen::internal::functor_traits< Eigen::internal::scalar_exp_op<T>>::Cost + Eigen::TensorOpCost::MulCost<T>() + Eigen::TensorOpCost::AddCost<T>();






    
    
    const int64 batchCost = batchInitCost + uniformRejectionSamplingCost * 2;
    Shard(worker_threads.num_threads, worker_threads.workers, num_elements, batchCost, do_work);
  }
};

}  

namespace {


template <typename Device, typename T> class ParameterizedTruncatedNormalOp : public OpKernel {
  
  static constexpr int32 kDesiredBatchSize = 100;

 public:
  explicit ParameterizedTruncatedNormalOp(OpKernelConstruction* context)
      : OpKernel(context) {
    OP_REQUIRES_OK(context, generator_.Init(context));
  }

  void Compute(OpKernelContext* ctx) override {
    const Tensor& shape_tensor = ctx->input(0);
    const Tensor& means_tensor = ctx->input(1);
    const Tensor& stddevs_tensor = ctx->input(2);
    const Tensor& minvals_tensor = ctx->input(3);
    const Tensor& maxvals_tensor = ctx->input(4);

    OP_REQUIRES( ctx, TensorShapeUtils::IsVector(shape_tensor.shape()), errors::InvalidArgument("Input shape should be a vector, got shape: ", shape_tensor.shape().DebugString()));


    int32 num_batches = shape_tensor.flat<int32>()(0);

    int32 samples_per_batch = 1;
    const int32 num_dims = shape_tensor.dim_size(0);
    for (int32 i = 1; i < num_dims; i++) {
      samples_per_batch *= shape_tensor.flat<int32>()(i);
    }
    const int32 num_elements = num_batches * samples_per_batch;

    
    auto shape_vec = shape_tensor.flat<int32>();
    TensorShape tensor_shape;
    OP_REQUIRES_OK(ctx, TensorShapeUtils::MakeShape( shape_vec.data(), shape_vec.size(), &tensor_shape));
    Tensor* samples_tensor;
    OP_REQUIRES_OK(ctx, ctx->allocate_output(0, tensor_shape, &samples_tensor));

    
    OP_REQUIRES(ctx, means_tensor.dims() <= 1, errors::InvalidArgument( "Input means should be a scalar or vector, got shape: ", means_tensor.shape().DebugString()));


    OP_REQUIRES(ctx, stddevs_tensor.dims() <= 1, errors::InvalidArgument( "Input stddevs should be a scalar or vector, got shape: ", stddevs_tensor.shape().DebugString()));


    OP_REQUIRES(ctx, minvals_tensor.dims() <= 1, errors::InvalidArgument( "Input minvals should be a scalar or vector, got shape: ", minvals_tensor.shape().DebugString()));


    OP_REQUIRES(ctx, maxvals_tensor.dims() <= 1, errors::InvalidArgument( "Input maxvals should be a scalar or vector, got shape: ", maxvals_tensor.shape().DebugString()));



    if ((means_tensor.dims() == 0 || means_tensor.dim_size(0) == 1) && (stddevs_tensor.dims() == 0 || stddevs_tensor.dim_size(0) == 1) && minvals_tensor.dims() == 0 && maxvals_tensor.dims() == 0) {

      
      
      
      int32 size = num_batches * samples_per_batch;
      int32 adjusted_samples = kDesiredBatchSize;
      
      int32 adjusted_batches = Eigen::divup(size, adjusted_samples);
      num_batches = adjusted_batches;
      samples_per_batch = adjusted_samples;
    } else {
      
      OP_REQUIRES( ctx, TensorShapeUtils::IsScalar(means_tensor.shape()) || means_tensor.dim_size(0) == 1 || means_tensor.dim_size(0) == num_batches, errors::InvalidArgument( "Input means should have length 1 or shape[0], got shape: ", means_tensor.shape().DebugString()));






      OP_REQUIRES( ctx, TensorShapeUtils::IsScalar(stddevs_tensor.shape()) || stddevs_tensor.dim_size(0) == 1 || stddevs_tensor.dim_size(0) == num_batches, errors::InvalidArgument( "Input stddevs should have length 1 or shape[0], got shape: ", stddevs_tensor.shape().DebugString()));






      OP_REQUIRES( ctx, TensorShapeUtils::IsScalar(minvals_tensor.shape()) || minvals_tensor.dim_size(0) == 1 || minvals_tensor.dim_size(0) == num_batches, errors::InvalidArgument( "Input minvals should have length 1 or shape[0], got shape: ", minvals_tensor.shape().DebugString()));






      OP_REQUIRES( ctx, TensorShapeUtils::IsScalar(maxvals_tensor.shape()) || maxvals_tensor.dim_size(0) == 1 || maxvals_tensor.dim_size(0) == num_batches, errors::InvalidArgument( "Input maxvals should have length 1 or shape[0], got shape: ", maxvals_tensor.shape().DebugString()));






    }

    auto truncFunctor = functor::TruncatedNormalFunctor<Device, T>();
    
    random::PhiloxRandom rng = generator_.ReserveSamples128(num_batches * 2 * functor::kMaxIterations * (samples_per_batch + 3) / 4);

    truncFunctor(ctx, ctx->eigen_device<Device>(), num_batches, samples_per_batch, num_elements, means_tensor.flat<T>(), stddevs_tensor.flat<T>(), minvals_tensor.flat<T>(), maxvals_tensor.flat<T>(), rng, samples_tensor->flat<T>());


  }

 private:
  GuardedPhiloxRandom generator_;

  TF_DISALLOW_COPY_AND_ASSIGN(ParameterizedTruncatedNormalOp);
};


template <typename Device, typename T> class StatelessParameterizedTruncatedNormal : public OpKernel {
  
  static const int32 kDesiredBatchSize = 100;

 public:
  explicit StatelessParameterizedTruncatedNormal(OpKernelConstruction* context)
      : OpKernel(context) {}

  void Compute(OpKernelContext* ctx) override {
    const Tensor& shape_tensor = ctx->input(0);
    const Tensor& seed_tensor = ctx->input(1);
    const Tensor& means_tensor = ctx->input(2);
    const Tensor& stddevs_tensor = ctx->input(3);
    const Tensor& minvals_tensor = ctx->input(4);
    const Tensor& maxvals_tensor = ctx->input(5);

    OP_REQUIRES(ctx, seed_tensor.dims() == 1 && seed_tensor.dim_size(0) == 2, errors::InvalidArgument("seed must have shape [2], not ", seed_tensor.shape().DebugString()));


    tensorflow::BCastList<4> bcast( {means_tensor.shape().dim_sizes(), stddevs_tensor.shape().dim_sizes(), minvals_tensor.shape().dim_sizes(), maxvals_tensor.shape().dim_sizes()}, false, true);





    OP_REQUIRES(ctx, bcast.IsValid(), errors::InvalidArgument( "means, stddevs, minvals, maxvals must have compatible " "batch dimensions: ", means_tensor.shape().DebugString(), " vs. ", stddevs_tensor.shape().DebugString(), " vs. ", minvals_tensor.shape().DebugString(), " vs. ", maxvals_tensor.shape().DebugString()));







    
    TensorShape bcast_shape = BCast::ToShape(bcast.output_shape());
    OP_REQUIRES( ctx, TensorShapeUtils::IsVector(shape_tensor.shape()), errors::InvalidArgument("Input shape should be a vector, got shape: ", shape_tensor.shape().DebugString()));


    TensorShape output_shape;
    if (shape_tensor.dtype() == DataType::DT_INT32) {
      OP_REQUIRES_OK(ctx, TensorShapeUtils::MakeShape(shape_tensor.vec<int32>(), &output_shape));
    } else {
      OP_REQUIRES_OK(ctx, TensorShapeUtils::MakeShape(shape_tensor.vec<int64>(), &output_shape));
    }
    OP_REQUIRES(ctx, TensorShapeUtils::EndsWith(output_shape, bcast_shape), errors::InvalidArgument( "Shape passed in must end with broadcasted shape."));


    int64 samples_per_batch = 1;
    const int64 num_sample_dims = (shape_tensor.dim_size(0) - bcast.output_shape().size());
    for (int64 i = 0; i < num_sample_dims; ++i) {
      samples_per_batch *= output_shape.dim_size(i);
    }
    int64 num_batches = 1;
    for (int64 i = num_sample_dims; i < shape_tensor.dim_size(0); ++i) {
      num_batches *= output_shape.dim_size(i);
    }
    const int64 num_elements = num_batches * samples_per_batch;

    Tensor* samples_tensor;
    OP_REQUIRES_OK(ctx, ctx->allocate_output(0, output_shape, &samples_tensor));

    auto truncFunctor = functor::TruncatedNormalFunctorV2<Device, T>();
    
    random::PhiloxRandom::Key key;
    random::PhiloxRandom::ResultType counter;
    OP_REQUIRES_OK(ctx, GenerateKey(seed_tensor, &key, &counter));

    auto philox = random::PhiloxRandom(counter, key);

    truncFunctor(ctx, ctx->eigen_device<Device>(), num_batches, samples_per_batch, num_elements, bcast, means_tensor.flat<T>(), stddevs_tensor.flat<T>(), minvals_tensor.flat<T>(), maxvals_tensor.flat<T>(), philox, samples_tensor->flat<T>());


  }

 private:
  TF_DISALLOW_COPY_AND_ASSIGN(StatelessParameterizedTruncatedNormal);
};

}  

















TF_CALL_half(REGISTER);
TF_CALL_float(REGISTER);
TF_CALL_double(REGISTER);











TF_CALL_half(REGISTER);
TF_CALL_float(REGISTER);
TF_CALL_double(REGISTER);





}  
