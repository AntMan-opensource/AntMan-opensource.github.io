
































namespace tflite {

namespace {

struct TfLiteQuantizationDeleter {
  void operator()(TfLiteQuantization* q) {
    if (q) TfLiteQuantizationFree(q);
  }
};

using ScopedTfLiteQuantization = std::unique_ptr<TfLiteQuantization, TfLiteQuantizationDeleter>;

struct TfLiteSparsityDeleter {
  void operator()(TfLiteSparsity* s) {
    if (s) TfLiteSparsityFree(s);
  }
};

using ScopedTfLiteSparsity = std::unique_ptr<TfLiteSparsity, TfLiteSparsityDeleter>;

TfLiteStatus ReportOpError(TfLiteContext* context, const TfLiteNode& node, const TfLiteRegistration& registration, int node_index, const char* message) {

  context->ReportError( context, "Node number %d (%s) %s.\n", node_index, registration.custom_name ? registration.custom_name : EnumNameBuiltinOperator( static_cast<BuiltinOperator>(registration.builtin_code)), message);





  return kTfLiteError;
}






TfLiteStatus ForbiddenContextFunction(TfLiteContext* context, ...) {
  context->ReportError(context, "The function is forbidden if not calling in delegate.");
  return kTfLiteError;
}


template <typename FunctionType> void SetForbiddenContextFunction(FunctionType* func) {
  *func = reinterpret_cast<FunctionType>(ForbiddenContextFunction);
}


template <typename TensorIntArray> bool HasDynamicTensorImpl(const TfLiteContext& context, const TensorIntArray& int_array) {

  for (int i : int_array) {
    if (i == kTfLiteOptionalTensor) continue;
    const TfLiteTensor& tensor = context.tensors[i];
    if (tensor.allocation_type == kTfLiteDynamic) {
      return true;
    }
  }
  return false;
}

bool HasDynamicTensor(const TfLiteContext& context, const TfLiteIntArray* int_array) {
  return HasDynamicTensorImpl(context, TfLiteIntArrayView{int_array});
}


TfLiteQuantizationParams GetLegacyQuantization( const TfLiteQuantization& quantization) {
  TfLiteQuantizationParams legacy_quantization;
  legacy_quantization.scale = 0;
  legacy_quantization.zero_point = 0;

  
  
  if (quantization.type != kTfLiteAffineQuantization) {
    return legacy_quantization;
  }

  auto* affine_quantization = static_cast<TfLiteAffineQuantization*>(quantization.params);
  if (!affine_quantization || !affine_quantization->scale || !affine_quantization->zero_point || affine_quantization->scale->size != 1 || affine_quantization->zero_point->size != 1) {


    return legacy_quantization;
  }

  
  legacy_quantization.scale = affine_quantization->scale->data[0];
  legacy_quantization.zero_point = affine_quantization->zero_point->data[0];
  return legacy_quantization;
}

static constexpr const char kUnknownCustomOpName[] = "UnknownCustomOp";
const char* GetTFLiteOpName(const TfLiteRegistration& op_reg) {
  if (op_reg.builtin_code == tflite::BuiltinOperator_CUSTOM) {
    const char* const custom_name = op_reg.custom_name;
    return custom_name ? custom_name : kUnknownCustomOpName;
  }
  if (op_reg.builtin_code == tflite::BuiltinOperator_DELEGATE && op_reg.custom_name) {
    return op_reg.custom_name;
  }
  return tflite::EnumNamesBuiltinOperator()[op_reg.builtin_code];
}

}  






class InterpreterInfo : public GraphInfo {
 public:
  explicit InterpreterInfo(Subgraph* subgraph) : subgraph_(subgraph) {}

  size_t num_tensors() const override { return subgraph_->tensors_size(); }
  TfLiteTensor* tensor(size_t index) override {
    return subgraph_->tensor(index);
  }
  size_t num_execution_nodes() const override {
    return subgraph_->execution_plan().size();
  }
  size_t num_total_nodes() const override { return subgraph_->nodes_size(); }
  const TfLiteNode& node(size_t index) const override {
    int node_index = subgraph_->execution_plan()[index];
    return subgraph_->nodes_and_registration()[node_index].first;
  }
  size_t node_index(size_t index) const override {
    return subgraph_->execution_plan()[index];
  }
  const std::vector<int>& inputs() const override {
    return subgraph_->inputs();
  }
  const std::vector<int>& outputs() const override {
    return subgraph_->outputs();
  }
  const std::vector<int>& variables() const override {
    return subgraph_->variables();
  }

 public:
  Subgraph* subgraph_;
};

Subgraph::Subgraph(ErrorReporter* error_reporter, TfLiteExternalContext** external_contexts, std::vector<std::unique_ptr<Subgraph>>* subgraphs, resource::ResourceMap* resources)


    : external_contexts_(external_contexts), error_reporter_(error_reporter), next_execution_plan_index_to_prepare_(0), next_execution_plan_index_to_plan_allocation_(0), subgraphs_(subgraphs), resources_(resources) {




  
  context_.impl_ = static_cast<void*>(this);
  context_.ResizeTensor = ResizeTensor;
  context_.ReportError = ReportErrorC;
  context_.AddTensors = AddTensors;
  context_.tensors = nullptr;
  context_.tensors_size = 0;
  context_.allow_fp32_relax_to_fp16 = false;
  context_.recommended_num_threads = -1;
  context_.GetExternalContext = GetExternalContext;
  context_.SetExternalContext = SetExternalContext;
  context_.profiler = nullptr;
  context_.GetTensor = nullptr;
  context_.GetEvalTensor = nullptr;

  
  tensors_.reserve(kTensorsReservedCapacity);
  nodes_and_registration_.reserve(kTensorsReservedCapacity);
  
  SwitchToKernelContext();
}

Subgraph::~Subgraph() {
  for (int node_index = 0; node_index < nodes_and_registration_.size();
       ++node_index) {
    CleanupNode(node_index);
  }

  for (size_t i = 0; i < context_.tensors_size; i++) {
    TfLiteTensor* tensor = &context_.tensors[i];
    if (tensor->buffer_handle != kTfLiteNullBufferHandle && tensor->delegate->FreeBufferHandle != nullptr) {
      tensor->delegate->FreeBufferHandle(&context_, tensor->delegate, &tensor->buffer_handle);
    }
    TfLiteTensorFree(tensor);
  }
}

void Subgraph::CleanupNode(int node_index) {
  TfLiteNode& node = nodes_and_registration_[node_index].first;
  const TfLiteRegistration& registration = nodes_and_registration_[node_index].second;
  TfLiteIntArrayFree(node.inputs);
  TfLiteIntArrayFree(node.outputs);
  TfLiteIntArrayFree(node.temporaries);
  TfLiteIntArrayFree(node.intermediates);
  if (node.builtin_data) free(node.builtin_data);
  OpFree(registration, node.user_data);
  node.builtin_data = nullptr;
}

TfLiteStatus Subgraph::ReplaceNodeSubsetsWithDelegateKernels( TfLiteContext* context, TfLiteRegistration registration, const TfLiteIntArray* nodes_to_replace, TfLiteDelegate* delegate) {

  return static_cast<Subgraph*>(context->impl_)
      ->ReplaceNodeSubsetsWithDelegateKernels(registration, nodes_to_replace, delegate);
}

namespace {




void CopyVectorToTfLiteIntArray(const std::vector<int>& vec, TfLiteIntArray* arr) {
  arr->size = vec.size();
  memcpy(arr->data, vec.data(), sizeof(int) * arr->size);
}



















TfLiteDelegateParams* CreateDelegateParams(TfLiteDelegate* delegate, const NodeSubset& node_subset) {
  
  int allocation_size = sizeof(TfLiteDelegateParams);

  int nodes_to_replace_size = TfLiteIntArrayGetSizeInBytes(node_subset.nodes.size());
  allocation_size += nodes_to_replace_size;

  int input_tensors_size = TfLiteIntArrayGetSizeInBytes(node_subset.input_tensors.size());
  allocation_size += input_tensors_size;

  int output_tensors_size = TfLiteIntArrayGetSizeInBytes(node_subset.output_tensors.size());
  allocation_size += output_tensors_size;

  
  
  char* allocation = static_cast<char*>(malloc(allocation_size));

  
  TfLiteDelegateParams* params = reinterpret_cast<TfLiteDelegateParams*>(allocation);
  params->delegate = delegate;
  allocation += sizeof(TfLiteDelegateParams);

  params->nodes_to_replace = reinterpret_cast<TfLiteIntArray*>(allocation);
  CopyVectorToTfLiteIntArray(node_subset.nodes, params->nodes_to_replace);
  allocation += nodes_to_replace_size;

  params->input_tensors = reinterpret_cast<TfLiteIntArray*>(allocation);
  CopyVectorToTfLiteIntArray(node_subset.input_tensors, params->input_tensors);
  allocation += input_tensors_size;

  params->output_tensors = reinterpret_cast<TfLiteIntArray*>(allocation);
  CopyVectorToTfLiteIntArray(node_subset.output_tensors, params->output_tensors);
  allocation += output_tensors_size;

  return params;
}


void PopulatePreviewDelegateParams(const NodeSubset& node_subset, TfLiteDelegateParams* params) {
  
  
  params->delegate = nullptr;

  params->nodes_to_replace = TfLiteIntArrayCreate(node_subset.nodes.size());
  CopyVectorToTfLiteIntArray(node_subset.nodes, params->nodes_to_replace);

  params->input_tensors = TfLiteIntArrayCreate(node_subset.input_tensors.size());
  CopyVectorToTfLiteIntArray(node_subset.input_tensors, params->input_tensors);

  params->output_tensors = TfLiteIntArrayCreate(node_subset.output_tensors.size());
  CopyVectorToTfLiteIntArray(node_subset.output_tensors, params->output_tensors);
}

}  

TfLiteStatus Subgraph::ReplaceNodeSubsetsWithDelegateKernels( TfLiteRegistration registration, const TfLiteIntArray* nodes_to_replace, TfLiteDelegate* delegate) {

  
  if (!nodes_to_replace->size) {
    return kTfLiteOk;
  }

  
  registration.builtin_code = BuiltinOperator_DELEGATE;

  
  
  InterpreterInfo info(this);
  std::vector<NodeSubset> node_subsets;
  PartitionGraphIntoIndependentNodeSubsets(&info, nodes_to_replace, &node_subsets);

  TFLITE_LOG_PROD( tflite::TFLITE_LOG_INFO, "Replacing %d node(s) with delegate (%s) node, yielding %zu partitions.", nodes_to_replace->size, registration.custom_name ? registration.custom_name : "unknown", node_subsets.size());





  execution_plan_.clear();

  for (auto& node_subset : node_subsets) {
    
    
    
    switch (node_subset.type) {
      case NodeSubset::kTfNonPartition:
        for (auto it = node_subset.nodes.begin(); it != node_subset.nodes.end();
             ++it) {
          execution_plan_.push_back(*it);
        }
        break;
      case NodeSubset::kTfPartition: {
        int node_index;

        TfLiteDelegateParams* params = CreateDelegateParams(delegate, node_subset);
        TF_LITE_ENSURE_STATUS(AddNodeWithParameters( node_subset.input_tensors, node_subset.output_tensors, {}, nullptr, 0, params, &registration, &node_index));


        
        for (int tensor_index : node_subset.output_tensors) {
          TfLiteTensor* tensor = &tensors_[tensor_index];
          TF_LITE_ENSURE(&context_, tensor->delegate == nullptr || tensor->delegate == delegate);
          tensor->delegate = delegate;
        }

        
        TfLiteNode* node = &nodes_and_registration_[node_index].first;
        node->delegate = delegate;
      } break;
      case NodeSubset::kTfUnexplored:
        return kTfLiteError;
        break;
    }
  }
  return kTfLiteOk;
}

TfLiteExternalContext* Subgraph::GetExternalContext( TfLiteExternalContextType type) {
  if (static_cast<int>(type) >= 0 && type < kTfLiteMaxExternalContexts) {
    return external_contexts_[type];
  }
  return nullptr;
}

TfLiteExternalContext* Subgraph::GetExternalContext( struct TfLiteContext* context, TfLiteExternalContextType type) {
  return static_cast<Subgraph*>(context->impl_)->GetExternalContext(type);
}

void Subgraph::SetExternalContext(TfLiteExternalContextType type, TfLiteExternalContext* ctx) {
  if (static_cast<int>(type) >= 0 && type < kTfLiteMaxExternalContexts) {
    external_contexts_[type] = ctx;
  }
}

void Subgraph::SetExternalContext(struct TfLiteContext* context, TfLiteExternalContextType type, TfLiteExternalContext* ctx) {

  return static_cast<Subgraph*>(context->impl_)->SetExternalContext(type, ctx);
}




TfLiteStatus Subgraph::GetExecutionPlan(TfLiteIntArray** execution_plan) {
  plan_cache_.reset(TfLiteIntArrayCreate(execution_plan_.size()));
  *execution_plan = plan_cache_.get();
  static_assert(sizeof(plan_cache_->data[0]) == sizeof(execution_plan_[0]), "TfLiteIntArray and execution_plan do not contain same type.");
  std::memcpy(plan_cache_->data, execution_plan_.data(), sizeof(plan_cache_->data[0]) * execution_plan_.size());
  return kTfLiteOk;
}



TfLiteStatus Subgraph::GetExecutionPlan(struct TfLiteContext* context, TfLiteIntArray** execution_plan) {
  return static_cast<Subgraph*>(context->impl_)
      ->GetExecutionPlan(execution_plan);
}

void Subgraph::FreeDelegatePartitioningData() {
  for (auto& params : partitioning_preview_cache_) {
    TfLiteIntArrayFree(params.nodes_to_replace);
    TfLiteIntArrayFree(params.input_tensors);
    TfLiteIntArrayFree(params.output_tensors);
  }
  partitioning_preview_cache_.clear();
}

TfLiteStatus Subgraph::PreviewDelegatePartitioning( const TfLiteIntArray* nodes_to_replace, TfLiteDelegateParams** partition_params_array, int* num_partitions) {

  
  FreeDelegatePartitioningData();
  
  if (!partition_params_array || !num_partitions) return kTfLiteError;
  *partition_params_array = nullptr;
  *num_partitions = 0;
  if (!nodes_to_replace->size) {
    return kTfLiteOk;
  }

  
  InterpreterInfo info(this);
  std::vector<NodeSubset> node_subsets;
  PartitionGraphIntoIndependentNodeSubsets(&info, nodes_to_replace, &node_subsets);

  
  for (auto& node_subset : node_subsets) {
    if (node_subset.type != NodeSubset::kTfPartition) {
      continue;
    }
    partitioning_preview_cache_.emplace_back();
    PopulatePreviewDelegateParams(node_subset, &partitioning_preview_cache_.back());
    ++*num_partitions;
  }

  *partition_params_array = partitioning_preview_cache_.data();
  return kTfLiteOk;
}

TfLiteStatus Subgraph::PreviewDelegatePartitioning( struct TfLiteContext* context, const TfLiteIntArray* nodes_to_replace, TfLiteDelegateParams** partition_params_array, int* num_partitions) {

  return static_cast<Subgraph*>(context->impl_)
      ->PreviewDelegatePartitioning(nodes_to_replace, partition_params_array, num_partitions);
}

TfLiteStatus Subgraph::SetInputs(std::vector<int> inputs) {
  TF_LITE_ENSURE_OK(&context_, CheckTensorIndices("inputs", inputs.data(), inputs.size()));
  inputs_ = std::move(inputs);
  return kTfLiteOk;
}

TfLiteStatus Subgraph::SetOutputs(std::vector<int> outputs) {
  TF_LITE_ENSURE_OK( &context_, CheckTensorIndices("outputs", outputs.data(), outputs.size()));
  outputs_ = std::move(outputs);
  return kTfLiteOk;
}

TfLiteStatus Subgraph::SetVariables(std::vector<int> variables) {
  TF_LITE_ENSURE_OK(&context_, CheckTensorIndices("variables", variables.data(), variables.size()));
  variables_ = std::move(variables);
  return kTfLiteOk;
}

void Subgraph::SetCancellationFunction(void* data, bool (*check_cancelled_func)(void*)) {
  cancellation_data_ = data;
  check_cancelled_func_ = check_cancelled_func;
}

bool Subgraph::IsCancelled() {
  return (check_cancelled_func_ != nullptr) && (*check_cancelled_func_)(cancellation_data_);
}

void Subgraph::ReserveNodes(int count) {
  nodes_and_registration_.reserve(count);
}

TfLiteStatus Subgraph::CheckTensorIndices(const char* label, const int* indices, int length) {
  
  
  static_assert(kTfLiteOptionalTensor == -1, "kTfLiteOptionalTensor should be defined -1");

  for (int i = 0; i < length; i++) {
    int index = indices[i];
    
    
    if (index == kTfLiteOptionalTensor) {
      continue;
    }
    if (index < 0 || static_cast<size_t>(index) >= context_.tensors_size) {
      ReportError( "Invalid tensor index %d in %s. The subgraph has %d tensors\n", index, label, context_.tensors_size);

      consistent_ = false;
      return kTfLiteError;
    }
  }
  return kTfLiteOk;
}











TfLiteStatus Subgraph::CheckInputAndOutputForOverlap(const int* input_indices, int num_inputs, const int* output_indices, int num_outputs) {


  for (int i = 0; i < num_inputs; i++) {
    for (int j = 0; j < num_outputs; j++) {
      if (input_indices[i] == output_indices[j]) {
        ReportError("Tensor %d is both input %d and output %d\n", input_indices[i], i, j);
        consistent_ = false;
        return kTfLiteError;
      }
    }
  }
  return kTfLiteOk;
}

namespace {




TfLiteStatus MultiplyAndCheckOverflow(size_t a, size_t b, size_t* product) {
  
  
  
  constexpr size_t size_t_bits = 8 * sizeof(size_t);
  constexpr size_t overflow_upper_half_bit_position = size_t_bits / 2;
  *product = a * b;
  
  
  if (TFLITE_EXPECT_FALSE((a | b) >> overflow_upper_half_bit_position != 0)) {
    if (a != 0 && *product / a != b) return kTfLiteError;
  }
  return kTfLiteOk;
}
}  

TfLiteStatus Subgraph::BytesRequired(TfLiteType type, const int* dims, size_t dims_size, size_t* bytes) {
  TF_LITE_ENSURE(&context_, bytes != nullptr);
  size_t count = 1;
  for (int k = 0; k < dims_size; k++) {
    size_t old_count = count;
    TF_LITE_ENSURE_MSG( &context_, MultiplyAndCheckOverflow(old_count, dims[k], &count) == kTfLiteOk, "BytesRequired number of elements overflowed.\n");


  }
  size_t type_size = 0;
  TF_LITE_ENSURE_OK(&context_, GetSizeOfType(&context_, type, &type_size));
  TF_LITE_ENSURE_MSG( &context_, MultiplyAndCheckOverflow(type_size, count, bytes) == kTfLiteOk, "BytesRequired number of bytes overflowed.\n");

  return kTfLiteOk;
}

TfLiteStatus Subgraph::AllocateTensors() {
  TFLITE_SCOPED_TAGGED_DEFAULT_PROFILE(profiler_.get(), "AllocateTensors");
  if (!consistent_) {
    ReportError("AllocateTensors() called on inconsistent model.");
    return kTfLiteError;
  }

  
  TF_LITE_ENSURE_STATUS(RedoAllDelegates());

  
  
  
  if (state_ != kStateUninvokable && !HasDynamicTensorImpl(context_, inputs())) {
    if (memory_planner_ && !memory_planner_->HasNonPersistentMemory()) {
      
      
      
      
      memory_planner_->AcquireNonPersistentMemory();
    }
    return kTfLiteOk;
  }

  next_execution_plan_index_to_prepare_ = 0;
  next_execution_plan_index_to_plan_allocation_ = 0;
  next_original_execution_plan_index_to_prepare_ = 0;
  if (memory_planner_) {
    TF_LITE_ENSURE_STATUS(memory_planner_->ResetAllocations());
  }

  TF_LITE_ENSURE_STATUS(PrepareOpsAndTensors());

  state_ = kStateInvokable;

  
  
  
  
  ResetVariableTensors();

  return kTfLiteOk;
}


TfLiteStatus Subgraph::ResetVariableTensors() {
  for (auto& tensor : tensors_) {
    if (!tensor.is_variable) {
      continue;
    }

    if (tensor.allocation_type == kTfLiteArenaRwPersistent) {
      
      
      
      TF_LITE_ENSURE(&context_, tensor.data.raw != nullptr);
      tflite::ResetVariableTensor(&tensor);
    } else {
      
      
      TF_LITE_ENSURE_EQ(&context_, tensor.allocation_type, kTfLiteCustom);
    }
  }
  return kTfLiteOk;
}

TfLiteStatus Subgraph::AddNodeWithParameters( const std::vector<int>& inputs, const std::vector<int>& outputs, const std::vector<int>& intermediates, const char* init_data, size_t init_data_size, void* builtin_data, const TfLiteRegistration* registration, int* node_index) {



  std::unique_ptr<void, decltype(free)*> builtin_data_deleter(builtin_data, free);
  if (state_ == kStateInvokableAndImmutable) {
    ReportError("AddNodeWithParameters is disallowed when graph is immutable.");
    return kTfLiteError;
  }
  state_ = kStateUninvokable;

  TF_LITE_ENSURE_OK(&context_, CheckTensorIndices("node inputs", inputs.data(), inputs.size()));
  TF_LITE_ENSURE_OK( &context_, CheckTensorIndices("node outputs", outputs.data(), outputs.size()));


  
  
  
  
  if (builtin_data != nullptr) {
    TF_LITE_ENSURE_OK(&context_, CheckInputAndOutputForOverlap( inputs.data(), inputs.size(), outputs.data(), outputs.size()));

  }

  int new_node_index = nodes_and_registration_.size();
  if (node_index) *node_index = new_node_index;
  nodes_and_registration_.resize(nodes_and_registration_.size() + 1);
  auto& node_and_reg = nodes_and_registration_.back();
  TfLiteNode& node = node_and_reg.first;
  if (node.inputs) TfLiteIntArrayFree(node.inputs);
  if (node.outputs) TfLiteIntArrayFree(node.outputs);
  if (node.intermediates) TfLiteIntArrayFree(node.intermediates);
  if (node.temporaries) TfLiteIntArrayFree(node.temporaries);

  
  
  
  node.inputs = ConvertVectorToTfLiteIntArray(inputs);
  node.outputs = ConvertVectorToTfLiteIntArray(outputs);
  node.intermediates = ConvertVectorToTfLiteIntArray(intermediates);
  node.temporaries = TfLiteIntArrayCreate(0);
  if (init_data) {
    node.user_data = OpInit(*registration, init_data, init_data_size);
  } else {
    node.user_data = OpInit( *registration, static_cast<const char*>(builtin_data_deleter.get()), 0);
  }

  node.builtin_data = builtin_data_deleter.release();

  if (registration->builtin_code == BuiltinOperator_CUSTOM) {
    
    
    node.custom_initial_data = init_data;
    node.custom_initial_data_size = init_data_size;
  } else {
    node.custom_initial_data = nullptr;
    node.custom_initial_data_size = 0;
  }
  node.might_have_side_effect = OpMightHaveSideEffect(&node, registration);

  node.delegate = nullptr;
  
  node_and_reg.second = *registration;
  execution_plan_.push_back(new_node_index);
  return kTfLiteOk;
}

namespace {


bool AnyTensorOfTypeResource(const std::vector<TfLiteTensor>& tensors, const TfLiteIntArray* tensor_indexes) {
  for (int i = 0; i < tensor_indexes->size; ++i) {
    int tensor_index = tensor_indexes->data[i];
    if (tensor_index >= 0 && tensor_index < tensors.size() && tensors[tensor_index].type == kTfLiteResource)
      return true;
  }
  return false;
}

}  

bool Subgraph::OpMightHaveSideEffect( const TfLiteNode* node, const TfLiteRegistration* registration) const {
  
  if (AnyTensorOfTypeResource(tensors_, node->inputs)) return true;
  
  if (AnyTensorOfTypeResource(tensors_, node->outputs)) return true;
  
  
  if (registration->builtin_code == kTfLiteBuiltinIf || registration->builtin_code == kTfLiteBuiltinWhile || registration->builtin_code == kTfLiteBuiltinCallOnce)

    return true;
  return false;
}

TfLiteStatus Subgraph::ResizeInputTensor(int tensor_index, const std::vector<int>& dims) {
  const bool delegates_applied = !pre_delegation_execution_plan_.empty();
  const bool graph_is_immutable = state_ == kStateInvokableAndImmutable;
  if (graph_is_immutable && !delegates_applied) {
    ReportError("ResizeInputTensor is disallowed when graph is immutable.");
    return kTfLiteError;
  }

  TF_LITE_ENSURE(&context_, tensor_index < context_.tensors_size && tensor_index >= 0);
  TfLiteTensor* tensor = &context_.tensors[tensor_index];

  
  
  
  
  
  
  if (tensor->data.raw != nullptr && EqualArrayAndTfLiteIntArray(tensor->dims, dims.size(), dims.data())) {
    return kTfLiteOk;
  }

  if (graph_is_immutable) {
    
    TF_LITE_ENSURE_STATUS(UndoAllDelegates());
  }
  state_ = kStateUninvokable;
  return ResizeTensorImpl(tensor, ConvertVectorToTfLiteIntArray(dims));
}

TfLiteStatus Subgraph::ResizeInputTensorStrict(int tensor_index, const std::vector<int>& dims) {
  TF_LITE_ENSURE(&context_, tensor_index < context_.tensors_size && tensor_index >= 0);
  TfLiteTensor* tensor = &context_.tensors[tensor_index];

  
  TF_LITE_ENSURE_EQ(&context_, tensor->dims->size, dims.size());
  for (size_t idx = 0; idx < dims.size(); idx++) {
    
    int dim_signature;
    if (tensor->dims_signature && tensor->dims_signature->size) {
      dim_signature = tensor->dims_signature->data[idx];
    } else {
      dim_signature = tensor->dims->data[idx];
    }

    if (dim_signature != -1 && dim_signature != dims[idx]) {
      ReportError( "Attempting to resize dimension %d of tensor %d with value %d to %d. " "ResizeInputTensorStrict only allows mutating unknown dimensions " "identified by -1.", idx, tensor_index, dim_signature, dims[idx]);



      return kTfLiteError;
    }
  }

  return ResizeInputTensor(tensor_index, dims);
}

TfLiteStatus Subgraph::ReleaseNonPersistentMemory() {
  if (memory_planner_) {
    TF_LITE_ENSURE_STATUS(memory_planner_->ReleaseNonPersistentMemory());
  }
  return kTfLiteOk;
}

TfLiteStatus Subgraph::OpPrepare(const TfLiteRegistration& op_reg, TfLiteNode* node) {
  if (op_reg.prepare == nullptr) {
    
    if (IsUnresolvedCustomOp(op_reg)) {
      if (IsFlexOp(op_reg.custom_name)) {
        ReportError( "Regular TensorFlow ops are not supported by this interpreter. " "Make sure you apply/link the Flex delegate before inference.");

      } else {
        ReportError("Encountered unresolved custom op: %s.", op_reg.custom_name ? op_reg.custom_name : "UnknownOp");
      }
      return kTfLiteError;
    }
    
    return kTfLiteOk;
  }
  return op_reg.prepare(&context_, node);
}

TfLiteStatus Subgraph::PrepareOpsStartingAt( int first_execution_plan_index, const std::vector<int>& execution_plan, int* last_execution_plan_index_prepared) {

  if (first_execution_plan_index == 0) {
    
    
    
    has_dynamic_tensors_ = HasDynamicTensorImpl(context_, outputs());
  }
  for (int execution_plan_index = first_execution_plan_index;
       execution_plan_index < execution_plan.size(); execution_plan_index++) {
    int node_index = execution_plan[execution_plan_index];
    TfLiteNode& node = nodes_and_registration_[node_index].first;
    const TfLiteRegistration& registration = nodes_and_registration_[node_index].second;
    EnsureTensorsVectorCapacity();
    if (OpPrepare(registration, &node) != kTfLiteOk) {
      return ReportOpError(&context_, node, registration, node_index, "failed to prepare");
    }

    *last_execution_plan_index_prepared = execution_plan_index;

    
    
    
    if (HasDynamicTensor(context_, node.outputs)) {
      has_dynamic_tensors_ = true;
      return kTfLiteOk;
    }
  }
  return kTfLiteOk;
}

TfLiteStatus Subgraph::PrepareOpsAndTensors() {
  if (!memory_planner_) {
    memory_planner_.reset(new ArenaPlanner( &context_, std::unique_ptr<GraphInfo>(new InterpreterInfo(this)), preserve_all_tensors_, kDefaultTensorAlignment));

    memory_planner_->PlanAllocations();
  }

  
  
  
  
  bool prepare_original_plan = false;
  if (!pre_delegation_execution_plan_.empty()) {
    for (int i = 0; i < delegates_applied_.size(); ++i) {
      if ((delegates_applied_[i]->flags & kTfLiteDelegateFlagsRequirePropagatedShapes)) {
        prepare_original_plan = true;
        break;
      }
    }
  }
  if (prepare_original_plan) {
    int last_original_exec_plan_index_prepared = 0;
    TF_LITE_ENSURE_STATUS(PrepareOpsStartingAt( next_execution_plan_index_to_prepare_, pre_delegation_execution_plan_, &last_original_exec_plan_index_prepared));

    next_original_execution_plan_index_to_prepare_ = last_original_exec_plan_index_prepared + 1;
  }

  int last_exec_plan_index_prepared = 0;
  TF_LITE_ENSURE_STATUS( PrepareOpsStartingAt(next_execution_plan_index_to_prepare_, execution_plan_, &last_exec_plan_index_prepared));

  next_execution_plan_index_to_prepare_ = last_exec_plan_index_prepared + 1;

  
  TF_LITE_ENSURE_STATUS(memory_planner_->ExecuteAllocations( next_execution_plan_index_to_plan_allocation_, last_exec_plan_index_prepared));


  
  
  
  
  for (int i = 0; i < custom_allocations_.size(); ++i) {
    auto index_and_alloc = custom_allocations_[i];
    TfLiteTensor* tensor_at_index = tensor(index_and_alloc.first);
    const auto& alloc = index_and_alloc.second;
    TF_LITE_ENSURE_EQ(context(), tensor_at_index->allocation_type, kTfLiteCustom);
    if (alloc.bytes < tensor_at_index->bytes) {
      ReportError("Custom allocation is too small for tensor idx: %d", index_and_alloc.first);
      return kTfLiteError;
    }
  }

  next_execution_plan_index_to_plan_allocation_ = last_exec_plan_index_prepared + 1;

  return kTfLiteOk;
}

TfLiteStatus Subgraph::Invoke() {
  if (!consistent_) {
    ReportError("Invoke called on model that is not consistent.");
    return kTfLiteError;
  }

  TfLiteStatus status = kTfLiteOk;
  if (state_ == kStateUninvokable) {
    ReportError("Invoke called on model that is not ready.");
    return kTfLiteError;
  } else if (memory_planner_ && !memory_planner_->HasNonPersistentMemory()) {
    ReportError("Non-persistent memory is not available.");
    return kTfLiteError;
  }
  TFLITE_SCOPED_TAGGED_DEFAULT_PROFILE(profiler_.get(), "Invoke");

  
  
  
  
  for (int execution_plan_index = 0;
       execution_plan_index < execution_plan_.size(); execution_plan_index++) {
    if (execution_plan_index == next_execution_plan_index_to_prepare_) {
      TF_LITE_ENSURE_STATUS(PrepareOpsAndTensors());
      TF_LITE_ENSURE(&context_, next_execution_plan_index_to_prepare_ >= execution_plan_index);
    }
    int node_index = execution_plan_[execution_plan_index];
    TfLiteNode& node = nodes_and_registration_[node_index].first;
    const TfLiteRegistration& registration = nodes_and_registration_[node_index].second;

    const char* op_name = nullptr;
    if (profiler_) op_name = GetTFLiteOpName(registration);
    TFLITE_SCOPED_TAGGED_OPERATOR_PROFILE(profiler_.get(), op_name, node_index);

    for (int i = 0; i < node.inputs->size; ++i) {
      int tensor_index = node.inputs->data[i];
      if (tensor_index == kTfLiteOptionalTensor) {
        continue;
      }
      TfLiteTensor* tensor = &tensors_[tensor_index];
      if (tensor->delegate && tensor->delegate != node.delegate && tensor->data_is_stale) {
        TF_LITE_ENSURE_STATUS(EnsureTensorDataIsReadable(tensor_index));
      }
      if (tensor->data.raw == nullptr && tensor->bytes > 0) {
        if (registration.builtin_code == kTfLiteBuiltinReshape && i == 1 && tensor->dims->size != 1) {
          
          
          
          
          
          
          
          
          
          continue;
        } else {
          
          
          ReportError("Input tensor %d lacks data", tensor_index);
          return kTfLiteError;
        }
      }
    }

    if (check_cancelled_func_ != nullptr && check_cancelled_func_(cancellation_data_)) {
      ReportError("Client requested cancel during Invoke()");
      return kTfLiteError;
    }

    EnsureTensorsVectorCapacity();
    tensor_resized_since_op_invoke_ = false;
    if (OpInvoke(registration, &node) != kTfLiteOk) {
      return ReportOpError(&context_, node, registration, node_index, "failed to invoke");
    }

    
    
    if (tensor_resized_since_op_invoke_ && HasDynamicTensor(context_, node.outputs)) {
      next_execution_plan_index_to_prepare_ = execution_plan_index + 1;

      
      
      
      if (next_execution_plan_index_to_plan_allocation_ > next_execution_plan_index_to_prepare_) {
        next_execution_plan_index_to_plan_allocation_ = next_execution_plan_index_to_prepare_;
        if (memory_planner_) {
          TF_LITE_ENSURE_STATUS(memory_planner_->ResetAllocationsAfter( next_execution_plan_index_to_plan_allocation_ - 1));
        }
      }
    }
  }

  return status;
}

TfLiteStatus Subgraph::ResizeTensor(TfLiteContext* context, TfLiteTensor* tensor, TfLiteIntArray* new_size) {

  
  
  
  
  
  
  if (tensor->data.raw != nullptr && EqualArrayAndTfLiteIntArray(tensor->dims, new_size->size, new_size->data)) {

    
    
    TfLiteIntArrayFree(tensor->dims);
    tensor->dims = new_size;
    return kTfLiteOk;
  }

  
  
  
  return static_cast<Subgraph*>(context->impl_)
      ->ResizeTensorImpl(tensor, new_size);
}

void Subgraph::ReportErrorImpl(const char* format, va_list args) {
  error_reporter_->Report(format, args);
}

void Subgraph::ReportErrorC(TfLiteContext* context, const char* format, ...) {
  va_list args;
  va_start(args, format);
  auto* f = static_cast<Subgraph*>(context->impl_);
  
  
  
  f->ReportErrorImpl(format, args);
  va_end(args);
}


void Subgraph::ReportError(const char* format, ...) {
  va_list args;
  va_start(args, format);
  auto* f = static_cast<Subgraph*>(context_.impl_);
  
  
  
  f->ReportErrorImpl(format, args);
  va_end(args);
}

TfLiteStatus Subgraph::AddTensors(int tensors_to_add, int* first_new_tensor_index) {
  const size_t base_index = tensors_.size();
  if (first_new_tensor_index) *first_new_tensor_index = base_index;
  tensors_.resize(tensors_.size() + tensors_to_add);
  for (size_t i = base_index; i < tensors_.size(); i++) {
    memset(&tensors_[i], 0, sizeof(tensors_[i]));
    tensors_[i].buffer_handle = kTfLiteNullBufferHandle;
  }
  context_.tensors = tensors_.data();
  context_.tensors_size = tensors_.size();
  return kTfLiteOk;
}

TfLiteStatus Subgraph::AddTensors(TfLiteContext* context, int tensors_to_add, int* first_new_tensor_index) {
  
  
  
  return static_cast<Subgraph*>(context->impl_)
      ->AddTensors(tensors_to_add, first_new_tensor_index);
}

TfLiteStatus Subgraph::GetNodeAndRegistration( int node_index, TfLiteNode** node, TfLiteRegistration** registration) {
  TF_LITE_ENSURE(&context_, node_index >= 0);
  auto nodes_size = nodes_and_registration_.size();
  TF_LITE_ENSURE(&context_, static_cast<size_t>(node_index) < nodes_size);
  TF_LITE_ENSURE(&context_, node != nullptr && registration != nullptr);
  auto& node_and_reg = nodes_and_registration_[node_index];
  *node = &node_and_reg.first;
  *registration = &node_and_reg.second;
  return kTfLiteOk;
}

TfLiteStatus Subgraph::GetNodeAndRegistration( struct TfLiteContext* context, int node_index, TfLiteNode** node, TfLiteRegistration** registration) {

  return static_cast<Subgraph*>(context->impl_)
      ->GetNodeAndRegistration(node_index, node, registration);
}

TfLiteStatus Subgraph::SetTensorParametersReadOnly( int tensor_index, TfLiteType type, const char* name, const size_t rank, const int* dims, TfLiteQuantization quantization, const char* buffer, size_t bytes, const Allocation* allocation, TfLiteSparsity* sparsity) {


  
  ScopedTfLiteQuantization scoped_quantization(&quantization);
  ScopedTfLiteSparsity scoped_sparsity(sparsity);
  if (state_ == kStateInvokableAndImmutable) {
    ReportError( "SetTensorParametersReadOnly is disallowed when graph is immutable.");
    return kTfLiteError;
  }

  TF_LITE_ENSURE(&context_, tensor_index < context_.tensors_size && tensor_index >= 0);

  
  
  
  
  if (type != kTfLiteString && type != kTfLiteResource && type != kTfLiteVariant && sparsity == nullptr) {
    size_t required_bytes;
    TF_LITE_ENSURE_OK(&context_, BytesRequired(type, dims, rank, &required_bytes));
    TF_LITE_ENSURE_EQ(&context_, required_bytes, bytes);
  }

  TfLiteTensor& tensor = context_.tensors[tensor_index];
  if (type == tensor.type && EqualArrayAndTfLiteIntArray(tensor.dims, rank, dims)) {
    
    TfLiteTensorDataFree(&tensor);
    TfLiteQuantizationFree(&tensor.quantization);
    tensor.data.raw = const_cast<char*>(buffer);
    if (!tensor.dims) tensor.dims = ConvertArrayToTfLiteIntArray(rank, dims);
    tensor.params = GetLegacyQuantization(quantization);
    tensor.quantization = *scoped_quantization.release();
    tensor.sparsity = scoped_sparsity.release();
    tensor.allocation_type = kTfLiteMmapRo;
    tensor.allocation = allocation;
  } else {
    state_ = kStateUninvokable;
    TfLiteTensorReset(type, name, ConvertArrayToTfLiteIntArray(rank, dims), GetLegacyQuantization(quantization), const_cast<char*>(buffer), bytes, kTfLiteMmapRo, allocation, false, &tensor);


    
    
    tensor.quantization = *scoped_quantization.release();
    tensor.sparsity = scoped_sparsity.release();
  }
  return kTfLiteOk;
}





TfLiteStatus Subgraph::SetTensorParametersReadWrite( int tensor_index, TfLiteType type, const char* name, const size_t rank, const int* dims, TfLiteQuantization quantization, bool is_variable, const size_t rank_dims_signature, const int* dims_signature) {


  
  ScopedTfLiteQuantization scoped_quantization(&quantization);
  if (state_ == kStateInvokableAndImmutable) {
    ReportError( "SetTensorParametersReadWrite is disallowed when graph is immutable.");
    return kTfLiteError;
  }
  TF_LITE_ENSURE(&context_, tensor_index < context_.tensors_size && tensor_index >= 0);
  size_t required_bytes = 0;
  if (type != kTfLiteString && type != kTfLiteResource && type != kTfLiteVariant) {
    
    
    
    
    TF_LITE_ENSURE_OK(&context_, BytesRequired(type, dims, rank, &required_bytes));
  }

  TfLiteAllocationType allocation_type = kTfLiteArenaRw;
  if (type == kTfLiteString || type == kTfLiteResource || type == kTfLiteVariant) {
    if (is_variable) {
      
      ReportError("String variable tensor isn't supported.");
      return kTfLiteError;
    }
    allocation_type = kTfLiteDynamic;
  } else if (is_variable) {
    allocation_type = kTfLiteArenaRwPersistent;
  }

  TfLiteTensor& tensor = context_.tensors[tensor_index];
  TfLiteTensorReset(type, name, ConvertArrayToTfLiteIntArray(rank, dims), GetLegacyQuantization(quantization), nullptr, required_bytes, allocation_type, nullptr, is_variable, &tensor);


  
  
  tensor.quantization = *scoped_quantization.release();
  tensor.dims_signature = ConvertArrayToTfLiteIntArray(rank_dims_signature, dims_signature);
  return kTfLiteOk;
}

TfLiteStatus Subgraph::SetExecutionPlan(const std::vector<int>& new_plan) {
  for (int node_index : new_plan) {
    TF_LITE_ENSURE(&context_, node_index >= 0 && node_index < nodes_and_registration_.size());
  }
  execution_plan_ = new_plan;
  return kTfLiteOk;
}

TfLiteStatus Subgraph::ResizeTensorImpl(TfLiteTensor* tensor, TfLiteIntArray* new_size) {
  
  if (tensor->allocation_type == kTfLiteArenaRw || tensor->allocation_type == kTfLiteDynamic || tensor->allocation_type == kTfLiteArenaRwPersistent || tensor->allocation_type == kTfLitePersistentRo || tensor->allocation_type == kTfLiteCustom) {



    tensor_resized_since_op_invoke_ |= TfLiteIntArrayEqual(tensor->dims, new_size) == 0;
    if (tensor->type != kTfLiteString && tensor->type != kTfLiteResource && tensor->type != kTfLiteVariant) {
      size_t bytesRequired;
      TfLiteStatus status = BytesRequired(tensor->type, new_size->data, new_size->size, &bytesRequired);
      if (status != kTfLiteOk) {
        TfLiteIntArrayFree(new_size);
        return kTfLiteError;
      }

      
      TfLiteTensorRealloc(bytesRequired, tensor);
      tensor->bytes = bytesRequired;
    }
    if (tensor->dims) TfLiteIntArrayFree(tensor->dims);
    tensor->dims = new_size;

    
    if (tensor->allocation_type == kTfLiteArenaRw || tensor->allocation_type == kTfLiteArenaRwPersistent) {
      tensor->data.raw = nullptr;
    }
  } else {
    
    
    TfLiteIntArrayFree(new_size);
    ReportError("Attempting to resize a fixed-size tensor.");
    return kTfLiteError;
  }
  return kTfLiteOk;
}

void Subgraph::SwitchToDelegateContext() {
  context_.GetNodeAndRegistration = GetNodeAndRegistration;
  context_.ReplaceNodeSubsetsWithDelegateKernels = ReplaceNodeSubsetsWithDelegateKernels;
  context_.GetExecutionPlan = GetExecutionPlan;
  context_.PreviewDelegatePartitioning = PreviewDelegatePartitioning;
}

void Subgraph::SwitchToKernelContext() {
  context_.GetNodeAndRegistration = [](struct TfLiteContext* context, int node_index, TfLiteNode** node, TfLiteRegistration** registration) {

    return ForbiddenContextFunction(context);
  };
  context_.ReplaceNodeSubsetsWithDelegateKernels = [](TfLiteContext* context, TfLiteRegistration registration, const TfLiteIntArray* nodes_to_replace, TfLiteDelegate* delegate) {

        return ForbiddenContextFunction(context);
      };
  context_.GetExecutionPlan = [](struct TfLiteContext* context, TfLiteIntArray**) {
    return ForbiddenContextFunction(context);
  };
  context_.PreviewDelegatePartitioning = [](struct TfLiteContext* context, const TfLiteIntArray* nodes_to_replace, TfLiteDelegateParams** partition_params_array, int* num_partitions) { return ForbiddenContextFunction(context); };


  
  
  FreeDelegatePartitioningData();
}

TfLiteStatus Subgraph::UndoAllDelegates() {
  
  if (pre_delegation_execution_plan_.empty()) return kTfLiteOk;

  
  for (int execution_plan_index = 0;
       execution_plan_index < execution_plan_.size(); ++execution_plan_index) {
    int node_index = execution_plan_[execution_plan_index];
    TfLiteNode& node = nodes_and_registration_[node_index].first;
    if (node.delegate == nullptr) {
      continue;
    }
    CleanupNode(node_index);
  }

  
  execution_plan_ = pre_delegation_execution_plan_;
  pre_delegation_execution_plan_.clear();

  
  
  
  
  
  
  
  
  std::vector<int> fp16_to_fp32(tensors_size(), -1);
  for (int execution_plan_index = 0;
       execution_plan_index < execution_plan_.size(); ++execution_plan_index) {
    int node_index = execution_plan_[execution_plan_index];
    auto& node_and_reg = nodes_and_registration_[node_index];
    const TfLiteNode& node = node_and_reg.first;
    const TfLiteRegistration& reg = node_and_reg.second;
    if (reg.builtin_code == kTfLiteBuiltinDequantize && node.inputs->size == 1 && node.outputs->size == 1) {
      const int input_idx = node.inputs->data[0];
      if (tensors_[input_idx].type == kTfLiteFloat16) {
        fp16_to_fp32[input_idx] = node.outputs->data[0];
      }
    }
  }
  
  
  
  
  for (int execution_plan_index = 0;
       execution_plan_index < execution_plan_.size(); ++execution_plan_index) {
    int node_index = execution_plan_[execution_plan_index];
    auto& node_and_reg = nodes_and_registration_[node_index];
    const TfLiteNode& node = node_and_reg.first;
    const TfLiteRegistration& reg = node_and_reg.second;
    if (reg.builtin_code == kTfLiteBuiltinDequantize) continue;
    for (int i = 0; i < node.inputs->size; ++i) {
      const int original_input_idx = node.inputs->data[i];
      if (tensors_[original_input_idx].type == kTfLiteFloat16) {
        node.inputs->data[i] = fp16_to_fp32[original_input_idx];
      }
    }
  }

  
  
  
  int max_retained_node_index = 0;
  for (int execution_plan_index = 0;
       execution_plan_index < execution_plan_.size(); ++execution_plan_index) {
    max_retained_node_index = std::max(max_retained_node_index, execution_plan_[execution_plan_index]);
  }
  nodes_and_registration_.resize(max_retained_node_index + 1);
  
  state_ = kStateUninvokable;

  delegates_undone_ = true;
  return kTfLiteOk;
}

TfLiteStatus Subgraph::RedoAllDelegates() {
  if (!delegates_undone_) return kTfLiteOk;

  delegates_undone_ = false;
  std::vector<TfLiteDelegate*> delegates_to_apply;
  delegates_applied_.swap(delegates_to_apply);
  for (auto* delegate : delegates_to_apply) {
    TF_LITE_ENSURE_STATUS(ModifyGraphWithDelegate(delegate));
  }
  return kTfLiteOk;
}

TfLiteStatus Subgraph::RemoveAllDelegates() {
  TF_LITE_ENSURE_STATUS(UndoAllDelegates());
  delegates_applied_.clear();
  delegates_undone_ = false;
  TF_LITE_ENSURE_STATUS(EnsureMemoryAllocations());
  return kTfLiteOk;
}

bool Subgraph::HasDelegates() { return !delegates_applied_.empty(); }

void Subgraph::EnsureTensorsVectorCapacity() {
  const size_t required_capacity = tensors_.size() + kTensorsCapacityHeadroom;
  if (required_capacity > tensors_.capacity()) {
    
    
    
    
    size_t reserved_capacity = std::max(required_capacity, tensors_.capacity() * 2);
    tensors_.reserve(reserved_capacity);
    context_.tensors = tensors_.data();
  }
}

TfLiteStatus Subgraph::EnsureMemoryAllocations() {
  if (memory_planner_) {
    state_ = kStateUninvokable;
    TF_LITE_ENSURE_OK(&context_, memory_planner_->PlanAllocations());
  }
  TF_LITE_ENSURE_OK(&context_, AllocateTensors());
  TF_LITE_ENSURE_EQ(&context_, state_, kStateInvokable);
  return kTfLiteOk;
}

TfLiteStatus Subgraph::ModifyGraphWithDelegate(TfLiteDelegate* delegate) {
  TFLITE_SCOPED_TAGGED_DEFAULT_PROFILE(profiler_.get(), "ModifyGraphWithDelegate");

  if (delegate == nullptr) {
    ReportError("Null delegate.");
    return kTfLiteDelegateError;
  }

  
  TF_LITE_ENSURE_STATUS(RedoAllDelegates());

  if (state_ == kStateInvokableAndImmutable) {
    ReportError( "ModifyGraphWithDelegate is disallowed when graph is immutable.");
    return kTfLiteApplicationError;
  }

  if (!(delegate->flags & kTfLiteDelegateFlagsAllowDynamicTensors)) {
    int last_execution_plan_index_prepared;
    TF_LITE_ENSURE_OK( &context_, PrepareOpsStartingAt(0, execution_plan_, &last_execution_plan_index_prepared));

    if (has_dynamic_tensors_) {
      
      
      TF_LITE_ENSURE_OK(&context_, EnsureMemoryAllocations());
      ReportError( "Attempting to use a delegate that only supports static-sized " "tensors with a graph that has dynamic-sized tensors.");

      return kTfLiteApplicationError;
    }
  }

  const bool was_invokable_before_delegate = state_ == kStateInvokable;
  if (delegates_applied_.empty()) {
    
    
    
    
    pre_delegation_execution_plan_ = execution_plan_;
  }

  
  
  SwitchToDelegateContext();

  auto reset_delegation_if_not_ok = [this](TfLiteStatus status) {
    if (status != kTfLiteOk) {
      TF_LITE_ENSURE_STATUS(RemoveAllDelegates());
      ReportError( "Restored original execution plan after delegate application " "failure.");

      return kTfLiteDelegateError;
    }
    return kTfLiteOk;
  };

  TfLiteStatus status = delegate->Prepare(&context_, delegate);

  
  SwitchToKernelContext();

  TF_LITE_ENSURE_STATUS(reset_delegation_if_not_ok(status));

  if (!(delegate->flags & kTfLiteDelegateFlagsAllowDynamicTensors)) {
    
    state_ = kStateUninvokable;
    TF_LITE_ENSURE_STATUS( reset_delegation_if_not_ok(EnsureMemoryAllocations()));
    
    
    state_ = kStateInvokableAndImmutable;
  } else if (was_invokable_before_delegate) {
    
    
    TF_LITE_ENSURE_STATUS( reset_delegation_if_not_ok(EnsureMemoryAllocations()));
  }
  delegates_applied_.push_back(delegate);

  return status;
}

TfLiteStatus Subgraph::SetCustomAllocationForTensor( int tensor_index, const TfLiteCustomAllocation& allocation, int64_t flags) {
  TfLiteTensor* tensor = &context_.tensors[tensor_index];
  TF_LITE_ENSURE(context(), (tensor->allocation_type == kTfLiteArenaRw || tensor->allocation_type == kTfLiteArenaRwPersistent || tensor->allocation_type == kTfLiteCustom));


  
  
  TF_LITE_ENSURE(context(), allocation.data != nullptr);
  if (!(flags & kTfLiteCustomAllocationFlagsSkipAlignCheck)) {
    const intptr_t data_ptr_value = reinterpret_cast<intptr_t>(allocation.data);
    TF_LITE_ENSURE(context(), data_ptr_value % kDefaultTensorAlignment == 0);
  }

  
  const auto alloc_it = std::find_if( custom_allocations_.begin(), custom_allocations_.end(), [tensor_index]( const std::pair<int, TfLiteCustomAllocation>& existing_alloc) {


        return existing_alloc.first == tensor_index;
      });
  if (alloc_it == custom_allocations_.end()) {
    custom_allocations_.emplace_back(tensor_index, allocation);
  } else {
    
    alloc_it->second = allocation;
  }

  tensor->allocation_type = kTfLiteCustom;
  tensor->data.data = allocation.data;

  return kTfLiteOk;
}

void Subgraph::SetName(const char* name) {
  if (name) {
    name_ = name;
  } else {
    name_ = "";
  }
}

const std::string& Subgraph::GetName() const { return name_; }

TfLiteStatus Subgraph::PreserveAllTensorsExperimental() {
  if (memory_planner_) {
    ReportError( "PreserveAllTensorsExperimental called after memory was planned. ");
    return kTfLiteError;
  }
  preserve_all_tensors_ = true;
  return kTfLiteOk;
}

}  
