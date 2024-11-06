











































namespace tensorflow {

namespace {

using sdca::Example;
using sdca::Examples;
using sdca::ExampleStatistics;
using sdca::ModelWeights;
using sdca::Regularizations;

struct ComputeOptions {
  explicit ComputeOptions(OpKernelConstruction* const context) {
    string loss_type;
    OP_REQUIRES_OK(context, context->GetAttr("loss_type", &loss_type));
    if (loss_type == "logistic_loss") {
      loss_updater.reset(new LogisticLossUpdater);
    } else if (loss_type == "squared_loss") {
      loss_updater.reset(new SquaredLossUpdater);
    } else if (loss_type == "hinge_loss") {
      loss_updater.reset(new HingeLossUpdater);
    } else if (loss_type == "smooth_hinge_loss") {
      loss_updater.reset(new SmoothHingeLossUpdater);
    } else if (loss_type == "poisson_loss") {
      loss_updater.reset(new PoissonLossUpdater);
    } else {
      OP_REQUIRES( context, false, errors::InvalidArgument("Unsupported loss type: ", loss_type));

    }
    auto s = context->GetAttr("adaptative", &adaptive);
    if (!s.ok()) {
      s = context->GetAttr("adaptive", &adaptive);
    }
    OP_REQUIRES_OK(context, s);
    OP_REQUIRES_OK( context, context->GetAttr("num_sparse_features", &num_sparse_features));
    OP_REQUIRES_OK(context, context->GetAttr("num_sparse_features_with_values", &num_sparse_features_with_values));
    OP_REQUIRES_OK(context, context->GetAttr("num_dense_features", &num_dense_features));
    OP_REQUIRES( context, num_sparse_features + num_dense_features > 0, errors::InvalidArgument("Requires at least one feature to train."));


    OP_REQUIRES(context, static_cast<int64_t>(num_sparse_features) + static_cast<int64_t>(num_dense_features) <= std::numeric_limits<int>::max(), errors::InvalidArgument(absl::StrFormat( "Too many feature groups: %d > %d", static_cast<int64_t>(num_sparse_features) + static_cast<int64_t>(num_dense_features), std::numeric_limits<int>::max())));







    OP_REQUIRES_OK( context, context->GetAttr("num_loss_partitions", &num_loss_partitions));
    OP_REQUIRES_OK(context, context->GetAttr("num_inner_iterations", &num_inner_iterations));
    OP_REQUIRES_OK(context, regularizations.Initialize(context));
  }

  std::unique_ptr<DualLossUpdater> loss_updater;
  int num_sparse_features = 0;
  int num_sparse_features_with_values = 0;
  int num_dense_features = 0;
  int num_inner_iterations = 0;
  int num_loss_partitions = 0;
  bool adaptive = true;
  Regularizations regularizations;
};




void DoCompute(const ComputeOptions& options, OpKernelContext* const context) {
  ModelWeights model_weights;
  OP_REQUIRES_OK(context, model_weights.Initialize(context));

  Examples examples;
  OP_REQUIRES_OK( context, examples.Initialize(context, model_weights, options.num_sparse_features, options.num_sparse_features_with_values, options.num_dense_features));




  const Tensor* example_state_data_t;
  OP_REQUIRES_OK(context, context->input("example_state_data", &example_state_data_t));
  TensorShape expected_example_state_shape({examples.num_examples(), 4});
  OP_REQUIRES(context, example_state_data_t->shape() == expected_example_state_shape, errors::InvalidArgument( "Expected shape ", expected_example_state_shape.DebugString(), " for example_state_data, got ", example_state_data_t->shape().DebugString()));





  Tensor mutable_example_state_data_t(*example_state_data_t);
  auto example_state_data = mutable_example_state_data_t.matrix<float>();
  OP_REQUIRES_OK(context, context->set_output("out_example_state_data", mutable_example_state_data_t));

  if (options.adaptive) {
    OP_REQUIRES_OK(context, examples.SampleAdaptiveProbabilities( options.num_loss_partitions, options.regularizations, model_weights, example_state_data, options.loss_updater, 1));



  } else {
    examples.RandomShuffle();
  }
  struct {
    mutex mu;
    Status value TF_GUARDED_BY(mu);
  } train_step_status;
  std::atomic<std::int64_t> atomic_index(-1);
  auto train_step = [&](const int64_t begin, const int64_t end) {
    
    
    for (int id = static_cast<int>(begin); id < end; ++id) {
      const int64_t example_index = examples.sampled_index(++atomic_index);
      const Example& example = examples.example(example_index);
      const float dual = example_state_data(example_index, 0);
      const float example_weight = example.example_weight();
      float example_label = example.example_label();
      const Status conversion_status = options.loss_updater->ConvertLabel(&example_label);
      if (!conversion_status.ok()) {
        mutex_lock l(train_step_status.mu);
        train_step_status.value = conversion_status;
        
        
        return;
      }

      
      
      
      const ExampleStatistics example_statistics = example.ComputeWxAndWeightedExampleNorm( options.num_loss_partitions, model_weights, options.regularizations, 1 );



      const double new_dual = options.loss_updater->ComputeUpdatedDual( options.num_loss_partitions, example_label, example_weight, dual, example_statistics.wx[0], example_statistics.normalized_squared_norm);


      
      const double normalized_bounded_dual_delta = (new_dual - dual) * example_weight / options.regularizations.symmetric_l2();

      model_weights.UpdateDeltaWeights( context->eigen_cpu_device(), example, std::vector<double>{normalized_bounded_dual_delta});


      
      example_state_data(example_index, 0) = new_dual;
      example_state_data(example_index, 1) = options.loss_updater->ComputePrimalLoss( example_statistics.prev_wx[0], example_label, example_weight);

      example_state_data(example_index, 2) = options.loss_updater->ComputeDualLoss(dual, example_label, example_weight);

      example_state_data(example_index, 3) = example_weight;
    }
  };
  
  
  const int64_t kCostPerUnit = examples.num_features();
  const DeviceBase::CpuWorkerThreads& worker_threads = *context->device()->tensorflow_cpu_worker_threads();

  Shard(worker_threads.num_threads, worker_threads.workers, examples.num_examples(), kCostPerUnit, train_step);
  mutex_lock l(train_step_status.mu);
  OP_REQUIRES_OK(context, train_step_status.value);
}

}  

class SdcaOptimizer : public OpKernel {
 public:
  explicit SdcaOptimizer(OpKernelConstruction* const context)
      : OpKernel(context), options_(context) {}

  void Compute(OpKernelContext* context) override {
    DoCompute(options_, context);
  }

 private:
  
  
  
  ComputeOptions options_;
};
REGISTER_KERNEL_BUILDER(Name("SdcaOptimizer").Device(DEVICE_CPU), SdcaOptimizer);
REGISTER_KERNEL_BUILDER(Name("SdcaOptimizerV2").Device(DEVICE_CPU), SdcaOptimizer);

class SdcaShrinkL1 : public OpKernel {
 public:
  explicit SdcaShrinkL1(OpKernelConstruction* const context)
      : OpKernel(context) {
    OP_REQUIRES_OK(context, regularizations_.Initialize(context));
  }

  void Compute(OpKernelContext* context) override {
    OpMutableInputList weights_inputs;
    OP_REQUIRES_OK(context, context->mutable_input_list("weights", &weights_inputs));

    auto do_work = [&](const int64_t begin, const int64_t end) {
      for (int i = begin; i < end; ++i) {
        auto prox_w = weights_inputs.at(i, true).flat<float>();
        prox_w.device(context->eigen_cpu_device()) = regularizations_.EigenShrinkVector(prox_w);
      }
    };

    if (weights_inputs.size() > 0) {
      int64_t num_weights = 0;
      for (int i = 0; i < weights_inputs.size(); ++i) {
        num_weights += weights_inputs.at(i, true).NumElements();
      }
      
      const int64_t kCostPerUnit = (num_weights * 50) / weights_inputs.size();
      const DeviceBase::CpuWorkerThreads& worker_threads = *context->device()->tensorflow_cpu_worker_threads();
      Shard(worker_threads.num_threads, worker_threads.workers, weights_inputs.size(), kCostPerUnit, do_work);
    }
  }

 private:
  Regularizations regularizations_;
};
REGISTER_KERNEL_BUILDER(Name("SdcaShrinkL1").Device(DEVICE_CPU), SdcaShrinkL1);







class SdcaFprint : public OpKernel {
 public:
  explicit SdcaFprint(OpKernelConstruction* const context)
      : OpKernel(context) {}

  void Compute(OpKernelContext* context) override {
    const Tensor& input = context->input(0);
    OP_REQUIRES(context, TensorShapeUtils::IsVector(input.shape()), errors::InvalidArgument("Input must be a vector, got shape ", input.shape().DebugString()));

    Tensor* out;
    const int64_t num_elements = input.NumElements();
    OP_REQUIRES_OK(context, context->allocate_output( 0, TensorShape({num_elements, 2}), &out));

    const auto in_values = input.flat<tstring>();
    auto out_values = out->matrix<int64_t>();

    for (int64_t i = 0; i < num_elements; ++i) {
      const Fprint128 fprint = Fingerprint128(in_values(i));
      
      
      out_values(i, 0) = TF_PREDICT_TRUE(fprint.low64 >= 2)
                             ? fprint.low64 : fprint.low64 + ~static_cast<uint64>(1);
      out_values(i, 1) = fprint.high64;
    }
  }
};
REGISTER_KERNEL_BUILDER(Name("SdcaFprint").Device(DEVICE_CPU), SdcaFprint);

}  
