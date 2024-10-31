






















namespace tensorflow {

using CPUDevice = Eigen::ThreadPoolDevice;
using GPUDevice = Eigen::GpuDevice;

Status GenerateKey(Tensor seed, random::PhiloxRandom::Key* out_key, random::PhiloxRandom::ResultType* out_counter) {
  
  uint64 seed0;
  uint64 seed1;
  if (seed.dtype() == DT_INT32) {
    const auto seed_vals = seed.flat<int32>();
    seed0 = internal::SubtleMustCopy(seed_vals(0));
    seed1 = internal::SubtleMustCopy(seed_vals(1));
  } else if (seed.dtype() == DT_INT64) {
    const auto seed_vals = seed.flat<int64>();
    seed0 = internal::SubtleMustCopy(seed_vals(0));
    seed1 = internal::SubtleMustCopy(seed_vals(1));
  } else {
    return errors::InvalidArgument("Invalid seed type: ", DataTypeString(seed.dtype()));
  }

  
  
  (*out_key)[0] = 0x3ec8f720;
  (*out_key)[1] = 0x02461e29;
  (*out_counter)[0] = static_cast<uint32>(seed0);
  (*out_counter)[1] = static_cast<uint32>(seed0 >> 32);
  (*out_counter)[2] = static_cast<uint32>(seed1);
  (*out_counter)[3] = static_cast<uint32>(seed1 >> 32);
  const auto mix = random::PhiloxRandom(*out_counter, *out_key)();
  (*out_key)[0] = mix[0];
  (*out_key)[1] = mix[1];
  (*out_counter)[0] = (*out_counter)[1] = 0;
  (*out_counter)[2] = mix[2];
  (*out_counter)[3] = mix[3];
  return Status::OK();
}

namespace {

class StatelessRandomOpBase : public OpKernel {
 public:
  explicit StatelessRandomOpBase(OpKernelConstruction* context)
      : OpKernel(context) {}

  void Compute(OpKernelContext* context) override {
    
    const Tensor& shape_t = context->input(0);
    const Tensor& seed_t = context->input(1);
    TensorShape shape;
    OP_REQUIRES_OK(context, tensor::MakeShape(shape_t, &shape));
    OP_REQUIRES(context, seed_t.dims() == 1 && seed_t.dim_size(0) == 2, errors::InvalidArgument("seed must have shape [2], not ", seed_t.shape().DebugString()));


    
    Tensor* output;
    OP_REQUIRES_OK(context, context->allocate_output(0, shape, &output));
    if (shape.num_elements() == 0) return;

    random::PhiloxRandom::Key key;
    random::PhiloxRandom::ResultType counter;
    OP_REQUIRES_OK(context, GenerateKey(seed_t, &key, &counter));

    
    Fill(context, random::PhiloxRandom(counter, key), output);
  }

  
  virtual void Fill(OpKernelContext* context, random::PhiloxRandom random, Tensor* output) = 0;
};

template <typename Device, class Distribution> class StatelessRandomOp : public StatelessRandomOpBase {
 public:
  using StatelessRandomOpBase::StatelessRandomOpBase;

  void Fill(OpKernelContext* context, random::PhiloxRandom random, Tensor* output) override {
    typedef typename Distribution::ResultElementType T;
    auto flat = output->flat<T>();
    
    functor::FillPhiloxRandom<Device, Distribution>()( context, context->eigen_device<Device>(), nullptr, nullptr, random, flat.data(), flat.size(), Distribution());

  }
};

template <typename Device, typename IntType> class StatelessRandomUniformIntOp : public StatelessRandomOpBase {
 public:
  using StatelessRandomOpBase::StatelessRandomOpBase;

  void Fill(OpKernelContext* context, random::PhiloxRandom random, Tensor* output) override {
    const Tensor& minval = context->input(2);
    const Tensor& maxval = context->input(3);
    OP_REQUIRES(context, TensorShapeUtils::IsScalar(minval.shape()), errors::InvalidArgument("minval must be 0-D, got shape ", minval.shape().DebugString()));

    OP_REQUIRES(context, TensorShapeUtils::IsScalar(maxval.shape()), errors::InvalidArgument("maxval must be 0-D, got shape ", maxval.shape().DebugString()));


    
    
    const auto lo = minval.scalar<IntType>()();
    const auto hi = maxval.scalar<IntType>()();
    OP_REQUIRES( context, lo < hi, errors::InvalidArgument("Need minval < maxval, got ", lo, " >= ", hi));


    
    typedef random::UniformDistribution<random::PhiloxRandom, IntType> Distribution;
    Distribution dist(lo, hi);

    auto flat = output->flat<IntType>();
    
    functor::FillPhiloxRandom<Device, Distribution>()( context, context->eigen_device<Device>(), nullptr, nullptr, random, flat.data(), flat.size(), dist);

  }
};

template <typename Device, typename IntType> class StatelessRandomUniformFullIntOp : public StatelessRandomOpBase {
 public:
  using StatelessRandomOpBase::StatelessRandomOpBase;

  void Fill(OpKernelContext* context, random::PhiloxRandom random, Tensor* output) override {
    
    typedef random::UniformFullIntDistribution<random::PhiloxRandom, IntType> Distribution;
    Distribution dist;

    auto flat = output->flat<IntType>();
    
    functor::FillPhiloxRandom<Device, Distribution>()( context, context->eigen_device<Device>(), nullptr, nullptr, random, flat.data(), flat.size(), dist);

  }
};


template <typename T, typename U> class StatelessRandomPoissonOp : public StatelessRandomOpBase {
 public:
  using StatelessRandomOpBase::StatelessRandomOpBase;

  void Fill(OpKernelContext* ctx, random::PhiloxRandom random, Tensor* output) override {
    const Tensor& rate_t = ctx->input(2);

    TensorShape samples_shape = output->shape();
    OP_REQUIRES(ctx, TensorShapeUtils::EndsWith(samples_shape, rate_t.shape()), errors::InvalidArgument( "Shape passed in must end with broadcasted shape."));


    const int64 num_rate = rate_t.NumElements();
    const int64 samples_per_rate = samples_shape.num_elements() / num_rate;
    const auto rate_flat = rate_t.flat<T>().data();
    auto samples_flat = output->flat<U>().data();

    functor::PoissonFunctor<CPUDevice, T, U>()( ctx, ctx->eigen_device<CPUDevice>(), rate_flat, num_rate, samples_per_rate, random, samples_flat);

  }

 private:
  TF_DISALLOW_COPY_AND_ASSIGN(StatelessRandomPoissonOp);
};

template <typename Device, typename T> class StatelessRandomGammaOp : public StatelessRandomOpBase {
 public:
  using StatelessRandomOpBase::StatelessRandomOpBase;

  void Fill(OpKernelContext* ctx, random::PhiloxRandom random, Tensor* output) override {
    const Tensor& alpha_t = ctx->input(2);

    TensorShape samples_shape = output->shape();
    OP_REQUIRES(ctx, TensorShapeUtils::EndsWith(samples_shape, alpha_t.shape()), errors::InvalidArgument( "Shape passed in must end with broadcasted shape."));


    typedef random::NormalDistribution<random::PhiloxRandom, double> Normal;
    typedef random::UniformDistribution<random::PhiloxRandom, double> Uniform;







    
    static constexpr int kReservedSamplesPerOutput = 256;

    const int64 num_alphas = alpha_t.NumElements();
    OP_REQUIRES(ctx, num_alphas > 0, errors::InvalidArgument( "Input alpha should have non-zero element count, got: ", num_alphas));


    const int64 samples_per_alpha = samples_shape.num_elements() / num_alphas;
    const auto alpha_flat = alpha_t.flat<T>().data();
    auto samples_flat = output->flat<T>().data();

    
    

    auto DoWork = [samples_per_alpha, num_alphas, &random, samples_flat, alpha_flat](int start_output, int limit_output) {
      
      
      

      using Eigen::numext::exp;
      using Eigen::numext::log;
      using Eigen::numext::log1p;
      using Eigen::numext::pow;

      Normal normal;
      Uniform uniform;
      typename Normal::ResultType norm_result;
      typename Uniform::ResultType uniform_result;
      for (int64 output_idx = start_output; output_idx < limit_output;
           ) {
        int64 alpha_idx = output_idx / samples_per_alpha;

        
        T* const samples_alpha_offset = samples_flat + alpha_idx;

        
        const double alpha = static_cast<double>(alpha_flat[alpha_idx]);

        DISABLE_FLOAT_EQUALITY_WARNING if (alpha == static_cast<double>(1.0)) {
          ENABLE_FLOAT_EQUALITY_WARNING  for (int64 sample_idx = output_idx % samples_per_alpha;

               sample_idx < samples_per_alpha && output_idx < limit_output;
               sample_idx++, output_idx++) {
            
            
            random::PhiloxRandom gen = random;
            gen.Skip(kReservedSamplesPerOutput * output_idx);
            int16 uniform_remaining = 0;
            UNIFORM(u);
            const double res = -log1p(-u);
            samples_alpha_offset[sample_idx * num_alphas] = static_cast<T>(res);
          }       
        } else {  
          
          
          
          
          
          
          
          
          
          const bool alpha_less_than_one = alpha < 1;
          const double d = alpha + (alpha_less_than_one ? 2.0 / 3 : -1.0 / 3);
          const double c = 1.0 / 3 / sqrt(d);

          
          for (int64 sample_idx = output_idx % samples_per_alpha;
               sample_idx < samples_per_alpha && output_idx < limit_output;
               sample_idx++, output_idx++) {
            
            
            
            random::PhiloxRandom gen = random;
            gen.Skip(kReservedSamplesPerOutput * output_idx);
            int16 norm_remaining = 0;
            int16 uniform_remaining = 0;

            
            
            while (true) {
              if (norm_remaining == 0) {
                norm_remaining = Normal::kResultElementCount;
                norm_result = normal(&gen);
              }
              norm_remaining--;
              const double x = norm_result[norm_remaining];
              double v = 1 + c * x;
              if (v <= 0) {
                continue;
              }
              v = v * v * v;
              UNIFORM(u);
              
              
              
              
              
              if ((u < 1 - 0.0331 * (x * x) * (x * x)) || (log(u) < 0.5 * x * x + d * (1 - v + log(v)))) {
                double res = d * v;
                if (alpha_less_than_one) {
                  UNIFORM(b);
                  res *= pow(b, 1 / alpha);
                }
                samples_alpha_offset[sample_idx * num_alphas] = static_cast<T>(res);
                break;
              }
            }  
          }    
        }      
      }        
    };         

    
    
    
    
    
    static const int kElementCost = 85 + 2 * Normal::kElementCost + Uniform::kElementCost + 3 * random::PhiloxRandom::kElementCost;

    auto worker_threads = *(ctx->device()->tensorflow_cpu_worker_threads());
    Shard(worker_threads.num_threads, worker_threads.workers, num_alphas * samples_per_alpha, kElementCost, DoWork);
  }
};





















































TF_CALL_half(REGISTER_CPU);
TF_CALL_bfloat16(REGISTER_CPU);
TF_CALL_float(REGISTER_CPU);
TF_CALL_double(REGISTER_CPU);
TF_CALL_int32(REGISTER_INT_CPU);
TF_CALL_int64(REGISTER_INT_CPU);
TF_CALL_uint32(REGISTER_FULL_INT_CPU);
TF_CALL_uint64(REGISTER_FULL_INT_CPU);
















TF_CALL_half(REGISTER_ALL_POISSON);
TF_CALL_float(REGISTER_ALL_POISSON);
TF_CALL_double(REGISTER_ALL_POISSON);
TF_CALL_int32(REGISTER_ALL_POISSON);
TF_CALL_int64(REGISTER_ALL_POISSON);












TF_CALL_half(REGISTER_GAMMA);
TF_CALL_bfloat16(REGISTER_GAMMA);
TF_CALL_float(REGISTER_GAMMA);
TF_CALL_double(REGISTER_GAMMA);





TF_CALL_half(REGISTER_GPU);
TF_CALL_float(REGISTER_GPU);
TF_CALL_double(REGISTER_GPU);
TF_CALL_int32(REGISTER_INT_GPU);
TF_CALL_int64(REGISTER_INT_GPU);
TF_CALL_uint32(REGISTER_FULL_INT_GPU);
TF_CALL_uint64(REGISTER_FULL_INT_GPU);












}  

}  
