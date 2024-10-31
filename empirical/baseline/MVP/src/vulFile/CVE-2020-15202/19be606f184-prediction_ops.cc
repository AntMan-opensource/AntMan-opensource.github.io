






















namespace tensorflow {

static void ConvertVectorsToMatrices( const OpInputList bucketized_features_list, std::vector<tensorflow::TTypes<int32>::ConstMatrix>& bucketized_features) {

  for (const Tensor& tensor : bucketized_features_list) {
    if (tensor.dims() == 1) {
      const auto v = tensor.vec<int32>();
      bucketized_features.emplace_back( TTypes<int32>::ConstMatrix(v.data(), v.size(), 1));
    } else {
      bucketized_features.emplace_back(tensor.matrix<int32>());
    }
  }
}





class BoostedTreesTrainingPredictOp : public OpKernel {
 public:
  explicit BoostedTreesTrainingPredictOp(OpKernelConstruction* const context)
      : OpKernel(context) {
    OP_REQUIRES_OK(context, context->GetAttr("num_bucketized_features", &num_bucketized_features_));
    OP_REQUIRES_OK(context, context->GetAttr("logits_dimension", &logits_dimension_));
  }

  void Compute(OpKernelContext* const context) override {
    core::RefCountPtr<BoostedTreesEnsembleResource> resource;
    
    OP_REQUIRES_OK(context, LookupResource(context, HandleFromInput(context, 0), &resource));

    
    OpInputList bucketized_features_list;
    OP_REQUIRES_OK(context, context->input_list("bucketized_features", &bucketized_features_list));
    std::vector<tensorflow::TTypes<int32>::ConstMatrix> bucketized_features;
    bucketized_features.reserve(bucketized_features_list.size());
    ConvertVectorsToMatrices(bucketized_features_list, bucketized_features);
    const int batch_size = bucketized_features[0].dimension(0);

    const Tensor* cached_tree_ids_t;
    OP_REQUIRES_OK(context, context->input("cached_tree_ids", &cached_tree_ids_t));
    const auto cached_tree_ids = cached_tree_ids_t->vec<int32>();

    const Tensor* cached_node_ids_t;
    OP_REQUIRES_OK(context, context->input("cached_node_ids", &cached_node_ids_t));
    const auto cached_node_ids = cached_node_ids_t->vec<int32>();

    
    Tensor* output_partial_logits_t = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output("partial_logits", {batch_size, logits_dimension_}, &output_partial_logits_t));


    auto output_partial_logits = output_partial_logits_t->matrix<float>();

    Tensor* output_tree_ids_t = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output("tree_ids", {batch_size}, &output_tree_ids_t));
    auto output_tree_ids = output_tree_ids_t->vec<int32>();

    Tensor* output_node_ids_t = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output("node_ids", {batch_size}, &output_node_ids_t));
    auto output_node_ids = output_node_ids_t->vec<int32>();

    
    const int32 latest_tree = resource->num_trees() - 1;

    if (latest_tree < 0) {
      
      output_node_ids.setZero();
      output_tree_ids = cached_tree_ids;
      
      output_partial_logits.setZero();
    } else {
      output_tree_ids.setConstant(latest_tree);
      auto do_work = [&resource, &bucketized_features, &cached_tree_ids, &cached_node_ids, &output_partial_logits, &output_node_ids, latest_tree, this](int32 start, int32 end) {


        for (int32 i = start; i < end; ++i) {
          int32 tree_id = cached_tree_ids(i);
          int32 node_id = cached_node_ids(i);
          std::vector<float> partial_tree_logits(logits_dimension_, 0.0);

          if (node_id >= 0) {
            
            
            
            resource->GetPostPruneCorrection(tree_id, node_id, &node_id, &partial_tree_logits);
            
            
            
            const auto& node_logits = resource->node_value(tree_id, node_id);
            if (!node_logits.empty()) {
              DCHECK_EQ(node_logits.size(), logits_dimension_);
              for (int32 j = 0; j < logits_dimension_; ++j) {
                partial_tree_logits[j] -= node_logits[j];
              }
            }
          } else {
            
            node_id = 0;
          }
          std::vector<float> partial_all_logits(logits_dimension_, 0.0);
          while (true) {
            if (resource->is_leaf(tree_id, node_id)) {
              const auto& leaf_logits = resource->node_value(tree_id, node_id);
              DCHECK_EQ(leaf_logits.size(), logits_dimension_);
              
              const float tree_weight = resource->GetTreeWeight(tree_id);
              for (int32 j = 0; j < logits_dimension_; ++j) {
                partial_all_logits[j] += tree_weight * (partial_tree_logits[j] + leaf_logits[j]);
                partial_tree_logits[j] = 0;
              }
              
              if (tree_id == latest_tree) {
                break;
              }
              
              ++tree_id;
              node_id = 0;
            } else {
              node_id = resource->next_node(tree_id, node_id, i, bucketized_features);
            }
          }
          output_node_ids(i) = node_id;
          for (int32 j = 0; j < logits_dimension_; ++j) {
            output_partial_logits(i, j) = partial_all_logits[j];
          }
        }
      };
      
      
      
      const int64 cost = 30;
      thread::ThreadPool* const worker_threads = context->device()->tensorflow_cpu_worker_threads()->workers;
      Shard(worker_threads->NumThreads(), worker_threads, batch_size, cost, do_work);
    }
  }

 private:
  int32 logits_dimension_;         
  int32 num_bucketized_features_;  
};

REGISTER_KERNEL_BUILDER(Name("BoostedTreesTrainingPredict").Device(DEVICE_CPU), BoostedTreesTrainingPredictOp);


class BoostedTreesPredictOp : public OpKernel {
 public:
  explicit BoostedTreesPredictOp(OpKernelConstruction* const context)
      : OpKernel(context) {
    OP_REQUIRES_OK(context, context->GetAttr("num_bucketized_features", &num_bucketized_features_));
    OP_REQUIRES_OK(context, context->GetAttr("logits_dimension", &logits_dimension_));
  }

  void Compute(OpKernelContext* const context) override {
    core::RefCountPtr<BoostedTreesEnsembleResource> resource;
    
    OP_REQUIRES_OK(context, LookupResource(context, HandleFromInput(context, 0), &resource));

    
    OpInputList bucketized_features_list;
    OP_REQUIRES_OK(context, context->input_list("bucketized_features", &bucketized_features_list));
    std::vector<tensorflow::TTypes<int32>::ConstMatrix> bucketized_features;
    bucketized_features.reserve(bucketized_features_list.size());
    ConvertVectorsToMatrices(bucketized_features_list, bucketized_features);
    const int batch_size = bucketized_features[0].dimension(0);

    
    Tensor* output_logits_t = nullptr;
    OP_REQUIRES_OK(context, context->allocate_output( "logits", {batch_size, logits_dimension_}, &output_logits_t));

    auto output_logits = output_logits_t->matrix<float>();

    
    if (resource->num_trees() <= 0) {
      output_logits.setZero();
      return;
    }

    const int32 last_tree = resource->num_trees() - 1;
    auto do_work = [&resource, &bucketized_features, &output_logits, last_tree, this](int32 start, int32 end) {
      for (int32 i = start; i < end; ++i) {
        std::vector<float> tree_logits(logits_dimension_, 0.0);
        int32 tree_id = 0;
        int32 node_id = 0;
        while (true) {
          if (resource->is_leaf(tree_id, node_id)) {
            const float tree_weight = resource->GetTreeWeight(tree_id);
            const auto& leaf_logits = resource->node_value(tree_id, node_id);
            DCHECK_EQ(leaf_logits.size(), logits_dimension_);
            for (int32 j = 0; j < logits_dimension_; ++j) {
              tree_logits[j] += tree_weight * leaf_logits[j];
            }
            
            if (tree_id == last_tree) {
              break;
            }
            
            ++tree_id;
            node_id = 0;
          } else {
            node_id = resource->next_node(tree_id, node_id, i, bucketized_features);
          }
        }
        for (int32 j = 0; j < logits_dimension_; ++j) {
          output_logits(i, j) = tree_logits[j];
        }
      }
    };
    
    
    
    const int64 cost = (last_tree + 1) * 10;
    thread::ThreadPool* const worker_threads = context->device()->tensorflow_cpu_worker_threads()->workers;
    Shard(worker_threads->NumThreads(), worker_threads, batch_size, cost, do_work);
  }

 private:
  int32 logits_dimension_;
  int32 num_bucketized_features_;  
};

REGISTER_KERNEL_BUILDER(Name("BoostedTreesPredict").Device(DEVICE_CPU), BoostedTreesPredictOp);








class BoostedTreesExampleDebugOutputsOp : public OpKernel {
 public:
  explicit BoostedTreesExampleDebugOutputsOp( OpKernelConstruction* const context)
      : OpKernel(context) {
    OP_REQUIRES_OK(context, context->GetAttr("num_bucketized_features", &num_bucketized_features_));
    OP_REQUIRES_OK(context, context->GetAttr("logits_dimension", &logits_dimension_));
    OP_REQUIRES(context, logits_dimension_ == 1, errors::InvalidArgument( "Currently only one dimensional outputs are supported."));

  }

  void Compute(OpKernelContext* const context) override {
    core::RefCountPtr<BoostedTreesEnsembleResource> resource;
    
    OP_REQUIRES_OK(context, LookupResource(context, HandleFromInput(context, 0), &resource));

    
    OpInputList bucketized_features_list;
    OP_REQUIRES_OK(context, context->input_list("bucketized_features", &bucketized_features_list));
    std::vector<tensorflow::TTypes<int32>::ConstMatrix> bucketized_features;
    bucketized_features.reserve(bucketized_features_list.size());
    ConvertVectorsToMatrices(bucketized_features_list, bucketized_features);
    const int batch_size = bucketized_features[0].dimension(0);

    
    
    
    
    
    Tensor* output_debug_info_t = nullptr;
    OP_REQUIRES_OK( context, context->allocate_output("examples_debug_outputs_serialized", {batch_size}, &output_debug_info_t));

    
    auto output_debug_info = output_debug_info_t->flat<tstring>();
    const int32 last_tree = resource->num_trees() - 1;

    
    
    
    
    auto do_work = [&resource, &bucketized_features, &output_debug_info, last_tree](int32 start, int32 end) {
      for (int32 i = start; i < end; ++i) {
        
        boosted_trees::DebugOutput example_debug_info;
        
        const auto& tree_logits = resource->node_value(0, 0);
        DCHECK_EQ(tree_logits.size(), 1);
        float tree_logit = resource->GetTreeWeight(0) * tree_logits[0];
        example_debug_info.add_logits_path(tree_logit);
        int32 node_id = 0;
        int32 tree_id = 0;
        int32 feature_id;
        float past_trees_logit = 0;  
        
        while (tree_id <= last_tree) {
          if (resource->is_leaf(tree_id, node_id)) {  
            
            
            if (tree_id == 0 || node_id > 0) {
              past_trees_logit += tree_logit;
            }
            ++tree_id;
            node_id = 0;
          } else {  
            
            feature_id = resource->feature_id(tree_id, node_id);
            example_debug_info.add_feature_ids(feature_id);
            
            node_id = resource->next_node(tree_id, node_id, i, bucketized_features);
            const auto& tree_logits = resource->node_value(tree_id, node_id);
            DCHECK_EQ(tree_logits.size(), 1);
            tree_logit = resource->GetTreeWeight(tree_id) * tree_logits[0];
            
            example_debug_info.add_logits_path(tree_logit + past_trees_logit);
          }
        }
        
        string serialized = example_debug_info.SerializeAsString();
        output_debug_info(i) = serialized;
      }
    };

    
    
    
    const int64 cost = (last_tree + 1) * 10;
    thread::ThreadPool* const worker_threads = context->device()->tensorflow_cpu_worker_threads()->workers;
    Shard(worker_threads->NumThreads(), worker_threads, batch_size, cost, do_work);
  }

 private:
  int32 logits_dimension_;  
  int32 num_bucketized_features_;  
};

REGISTER_KERNEL_BUILDER( Name("BoostedTreesExampleDebugOutputs").Device(DEVICE_CPU), BoostedTreesExampleDebugOutputsOp);


}  
