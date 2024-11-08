






































namespace tensorflow {
namespace {

static constexpr int kReservedSamplesPerOutput = 256;

typedef Eigen::ThreadPoolDevice CPUDevice;

template <typename T> struct PoissonComputeType {
  typedef double ComputeType;
};

}  

namespace functor {

template <typename T, typename U> struct PoissonFunctor<CPUDevice, T, U> {
  void operator()(OpKernelContext* ctx, const CPUDevice& d, const T* rate_flat, int num_rate, int num_samples, const random::PhiloxRandom& rng, U* samples_flat) {

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

    typedef random::UniformDistribution<random::PhiloxRandom, CT> Uniform;

    auto DoWork = [num_samples, num_rate, &rng, samples_flat, rate_flat]( int start_output, int limit_output) {
      
      
      

      Uniform uniform;
      typename Uniform::ResultType uniform_result;
      for (int64 output_idx = start_output; output_idx < limit_output;
           ) {
        const int64 rate_idx = output_idx / num_samples;

        
        const CT rate = CT(rate_flat[rate_idx]);

        auto samples_rate_output = samples_flat + rate_idx;

        if (rate < CT(10)) {
          
          
          
          
          
          
          
          
          const CT exp_neg_rate = Eigen::numext::exp(-rate);

          
          for (int64 sample_idx = output_idx % num_samples;
               sample_idx < num_samples && output_idx < limit_output;
               sample_idx++, output_idx++) {
            random::PhiloxRandom gen = rng;
            gen.Skip(kReservedSamplesPerOutput * output_idx);
            int16 uniform_remaining = 0;

            CT prod = 1;
            CT x = 0;

            
            
            while (true) {
              UNIFORM(u);
              prod = prod * u;
              if (prod <= exp_neg_rate && x <= CT(Eigen::NumTraits<U>::highest())) {
                samples_rate_output[sample_idx * num_rate] = U(x);
                break;
              }
              x += 1;
            }
          }
          continue;
        }
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        

        using Eigen::numext::log;
        const CT log_rate = log(rate);

        
        
        
        const CT b = CT(0.931) + CT(2.53) * Eigen::numext::sqrt(rate);
        const CT a = CT(-0.059) + CT(0.02483) * b;

        
        
        
        const CT inv_alpha = CT(1.1239) + CT(1.1328) / (b - CT(3.4));

        
        for (int64 sample_idx = output_idx % num_samples;
             sample_idx < num_samples && output_idx < limit_output;
             sample_idx++, output_idx++) {
          random::PhiloxRandom gen = rng;
          gen.Skip(kReservedSamplesPerOutput * output_idx);
          int16 uniform_remaining = 0;

          while (true) {
            UNIFORM(u);
            u -= CT(0.5);
            UNIFORM(v);

            CT u_shifted = CT(0.5) - Eigen::numext::abs(u);
            CT k = Eigen::numext::floor((CT(2) * a / u_shifted + b) * u + rate + CT(0.43));

            if (k > CT(Eigen::NumTraits<U>::highest())) {
              
              continue;
            }

            
            
            
            
            if (u_shifted >= CT(0.07) && v <= CT(0.9277) - CT(3.6224) / (b - CT(2))) {
              samples_rate_output[sample_idx * num_rate] = U(k);
              break;
            }

            if (k < 0 || (u_shifted < CT(0.013) && v > u_shifted)) {
              continue;
            }

            
            
            CT s = log(v * inv_alpha / (a / (u_shifted * u_shifted) + b));
            CT t = -rate + k * log_rate - Eigen::numext::lgamma(k + 1);
            if (s <= t) {
              samples_rate_output[sample_idx * num_rate] = U(k);
              break;
            }
          }
        }
      }
    };

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    static const int kElementCost = 165 + 6 * Uniform::kElementCost + 6 * random::PhiloxRandom::kElementCost;
    auto worker_threads = *(ctx->device()->tensorflow_cpu_worker_threads());
    Shard(worker_threads.num_threads, worker_threads.workers, num_rate * num_samples, kElementCost, DoWork);
  }

 private:
  typedef typename PoissonComputeType<T>::ComputeType CT;
};

}  

namespace {


template <typename T, typename U> class RandomPoissonOp : public OpKernel {
 public:
  explicit RandomPoissonOp(OpKernelConstruction* context) : OpKernel(context) {
    OP_REQUIRES_OK(context, generator_.Init(context));
  }

  void Compute(OpKernelContext* ctx) override {
    const Tensor& shape_t = ctx->input(0);
    const Tensor& rate_t = ctx->input(1);

    TensorShape samples_shape;
    OP_REQUIRES_OK(ctx, tensor::MakeShape(shape_t, &samples_shape));
    const int64 num_samples = samples_shape.num_elements();

    samples_shape.AppendShape(rate_t.shape());
    
    Tensor* samples_t = nullptr;
    OP_REQUIRES_OK(ctx, ctx->allocate_output(0, samples_shape, &samples_t));
    if (num_samples == 0) return;

    const auto rate_flat = rate_t.flat<T>().data();
    const int64 num_rate = rate_t.NumElements();
    auto samples_flat = samples_t->flat<U>().data();
    random::PhiloxRandom rng = generator_.ReserveRandomOutputs( num_samples * num_rate, kReservedSamplesPerOutput);

    functor::PoissonFunctor<CPUDevice, T, U>()( ctx, ctx->eigen_device<CPUDevice>(), rate_flat, num_rate, num_samples, rng, samples_flat);

  }

 private:
  GuardedPhiloxRandom generator_;

  TF_DISALLOW_COPY_AND_ASSIGN(RandomPoissonOp);
};
}  







TF_CALL_half(REGISTER);
TF_CALL_float(REGISTER);
TF_CALL_double(REGISTER);














REGISTER_ALL(Eigen::half);
REGISTER_ALL(float);
REGISTER_ALL(double);
REGISTER_ALL(int32);
REGISTER_ALL(int64);





}  
