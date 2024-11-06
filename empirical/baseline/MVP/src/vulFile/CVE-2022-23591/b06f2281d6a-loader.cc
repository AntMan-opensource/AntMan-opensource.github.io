




























namespace tensorflow {
namespace {

auto* load_attempt_count = monitoring::Counter<2>::New( "/tensorflow/cc/saved_model/load_attempt_count", "The number of times a SavedModel was successfully loaded.", "model_path", "status");


auto* load_latency = monitoring::Counter<1>::New( "/tensorflow/cc/saved_model/load_latency", "Latency in microseconds for SavedModels that were successfully loaded.", "model_path");


auto* load_latency_by_stage = monitoring::Sampler<2>::New( {
        "/tensorflow/cc/saved_model/load_latency_by_stage",   "Distribution of wall time spent (in microseconds) in each stage " "(restore graph from disk, run init graph op, etc) when loading the " "model", "model_path", "stage", },  monitoring::Buckets::Exponential(10, 1.8, 33));








constexpr char kLoadAttemptFail[] = "fail";
constexpr char kLoadAttemptSuccess[] = "success";

constexpr char kCCLoadLabel[] = "cc_load";

uint64 GetLatencyMicroseconds(const uint64 start_microseconds) {
  const uint64 end_microseconds = EnvTime::NowMicros();
  
  if (end_microseconds < start_microseconds) return 0;
  return end_microseconds - start_microseconds;
}




static Status ValidateNode(const NodeDef& node) {
  const auto node_iterator = node.attr().find("value");
  if (node_iterator != node.attr().end()) {
    AttrValue node_value = node_iterator->second;
    if (node_value.has_tensor()) {
      const PartialTensorShape node_shape(node_value.tensor().tensor_shape());
      if (node_shape.num_elements() < 0) {
        return errors::FailedPrecondition( "Saved model contains node \"", node.name(), "\" (op \"", node.op(), "\") which initializes from a tensor with ", node_shape.num_elements(), " elements");


      }
    }
  } else if (node.op() == "Const") {
    return errors::FailedPrecondition( "Saved model contains node \"", node.name(), "\" which is a constant tensor but no value has been provided");

  }
  return Status::OK();
}

static Status ValidateSavedTensors(const GraphDef& graph_def) {
  for (const auto& node : graph_def.node()) {
    TF_RETURN_IF_ERROR(ValidateNode(node));
  }

  if (graph_def.has_library()) {
    const FunctionDefLibrary& library = graph_def.library();
    for (const auto& function : library.function()) {
      for (const auto& node : function.node_def()) {
        TF_RETURN_IF_ERROR(ValidateNode(node));
      }
    }
  }

  return Status::OK();
}

Tensor CreateStringTensor(const string& value) {
  Tensor tensor(DT_STRING, TensorShape({}));
  tensor.scalar<tstring>()() = value;
  return tensor;
}

void AddAssetsTensorsToInputs(const StringPiece export_dir, const std::vector<AssetFileDef>& asset_file_defs, std::vector<std::pair<string, Tensor>>* inputs) {

  if (asset_file_defs.empty()) {
    return;
  }
  for (auto& asset_file_def : asset_file_defs) {
    Tensor assets_file_path_tensor = CreateStringTensor(io::JoinPath( export_dir, kSavedModelAssetsDirectory, asset_file_def.filename()));
    inputs->push_back( {asset_file_def.tensor_info().name(), assets_file_path_tensor});
  }
}

















Status RunOnce(const RunOptions& run_options, const std::vector<std::pair<string, Tensor>>& inputs, const std::vector<string>& output_tensor_names, const std::vector<string>& target_node_names, std::vector<Tensor>* outputs, RunMetadata* run_metadata, Session* session) {




  CallableOptions callable_options;
  std::vector<Tensor> feed_tensors;
  *callable_options.mutable_run_options() = run_options;
  for (const auto& input : inputs) {
    const string& name = input.first;
    const Tensor& tensor = input.second;
    callable_options.add_feed(name);
    feed_tensors.push_back(tensor);
  }
  for (const string& output_tensor_name : output_tensor_names) {
    callable_options.add_fetch(output_tensor_name);
  }
  for (const string& target_node_name : target_node_names) {
    callable_options.add_target(target_node_name);
  }

  Session::CallableHandle callable_handle;
  TF_RETURN_IF_ERROR(session->MakeCallable(callable_options, &callable_handle));
  const Status run_status = session->RunCallable(callable_handle, feed_tensors, outputs, run_metadata);
  
  
  session->ReleaseCallable(callable_handle).IgnoreError();
  return run_status;
}



Status RunInitOp(const RunOptions& run_options, const string& export_dir, const MetaGraphDef& meta_graph_def, const std::vector<AssetFileDef>& asset_file_defs, Session* session, const string& init_op_name) {


  if (!init_op_name.empty()) {
    LOG(INFO) << "Running initialization op on SavedModel bundle at path: " << export_dir;
    std::vector<std::pair<string, Tensor>> inputs;
    AddAssetsTensorsToInputs(export_dir, asset_file_defs, &inputs);
    RunMetadata run_metadata;
    return RunOnce(run_options, inputs, {}, {init_op_name}, nullptr , &run_metadata, session);
  }
  return Status::OK();
}

Status RunRestore(const RunOptions& run_options, const string& export_dir, const StringPiece restore_op_name, const StringPiece variable_filename_const_op_name, const std::vector<AssetFileDef>& asset_file_defs, Session* session) {



  LOG(INFO) << "Restoring SavedModel bundle.";
  
  const string variables_directory = io::JoinPath(export_dir, kSavedModelVariablesDirectory);
  
  
  
  const string variables_index_path = io::JoinPath( variables_directory, MetaFilename(kSavedModelVariablesFilename));
  if (!Env::Default()->FileExists(variables_index_path).ok()) {
    LOG(INFO) << "The specified SavedModel has no variables; no checkpoints " "were restored. File does not exist: " << variables_index_path;

    return Status::OK();
  }
  const string variables_path = io::JoinPath(variables_directory, kSavedModelVariablesFilename);

  
  Tensor variables_path_tensor(DT_STRING, TensorShape({}));
  variables_path_tensor.scalar<tstring>()() = variables_path;

  std::vector<std::pair<string, Tensor>> inputs = {
      {string(variable_filename_const_op_name), variables_path_tensor}};

  AddAssetsTensorsToInputs(export_dir, asset_file_defs, &inputs);

  RunMetadata run_metadata;
  return RunOnce(run_options, inputs, {}, {string(restore_op_name)}, nullptr , &run_metadata, session);
}

}  

SavedModelBundleInterface::~SavedModelBundleInterface() {}

Status LoadMetagraphIntoSession(const SessionOptions& session_options, const MetaGraphDef& meta_graph, std::unique_ptr<Session>* session) {

  Session* session_p = nullptr;
  TF_RETURN_IF_ERROR(NewSession(session_options, &session_p));
  session->reset(session_p);
  TF_RETURN_IF_ERROR(ValidateSavedTensors(meta_graph.graph_def()));
  return (*session)->Create(meta_graph.graph_def());
}

Status LoadSavedModelInternal(const SessionOptions& session_options, const RunOptions& run_options, const string& export_dir, const std::unordered_set<string>& tags, SavedModelBundle* const bundle) {



  TF_RETURN_IF_ERROR(ReadMetaGraphDefFromSavedModel(export_dir, tags, &bundle->meta_graph_def));
  TF_RETURN_IF_ERROR( ReadSavedModelDebugInfoIfPresent(export_dir, &bundle->debug_info));
  TF_RETURN_IF_ERROR(LoadMetagraphIntoSession( session_options, bundle->meta_graph_def, &bundle->session));
  TF_RETURN_IF_ERROR(RestoreSession(run_options, bundle->meta_graph_def, export_dir, &bundle->session));
  return Status::OK();
}

Status LoadSavedModel(const SessionOptions& session_options, const RunOptions& run_options, const string& export_dir, const std::unordered_set<string>& tags, SavedModelBundle* const bundle) {


  metrics::SavedModelReadApi(kCCLoadLabel).IncrementBy(1);

  
  const uint64 start_microseconds = Env::Default()->NowMicros();
  const Status status = LoadSavedModelInternal(session_options, run_options, export_dir, tags, bundle);
  auto log_and_count = [&](const string& status_str) {
    LOG(INFO) << "SavedModel load for tags { " << absl::StrJoin(tags, " ")
              << " }; Status: " << status_str << ": " << status << ". Took " << GetLatencyMicroseconds(start_microseconds) << " microseconds.";
    load_attempt_count->GetCell(export_dir, status_str)->IncrementBy(1);
  };
  if (status.ok()) {
    log_and_count(kLoadAttemptSuccess);
  } else {
    log_and_count(kLoadAttemptFail);
  }
  load_latency->GetCell(export_dir)
      ->IncrementBy(GetLatencyMicroseconds(start_microseconds));
  return status;
}

namespace {






class LiteSessionWrapper : public Session {
 public:
  explicit LiteSessionWrapper(std::unique_ptr<Session> wrapped)
      : wrapped_(std::move(wrapped)) {}

  Status Create(const GraphDef& graph) override {
    return errors::Unimplemented("Session::Create()");
  }
  Status Create(GraphDef&& graph) override {
    return errors::Unimplemented("Session::Create()");
  }

  Status Extend(const GraphDef& graph) override {
    return errors::Unimplemented("Session::Extend()");
  }
  Status Extend(GraphDef&& graph) override {
    return errors::Unimplemented("Session::Extend()");
  }

  Status Run(const std::vector<std::pair<string, Tensor>>& inputs, const std::vector<string>& output_tensor_names, const std::vector<string>& target_node_names, std::vector<Tensor>* outputs) override {


    return wrapped_->Run(inputs, output_tensor_names, target_node_names, outputs);
  }

  Status Create(const RunOptions& run_options, const GraphDef& graph) override {
    return errors::Unimplemented("Session::Create()");
  }
  Status Extend(const RunOptions& run_options, const GraphDef& graph) override {
    return errors::Unimplemented("Session::Extend()");
  }
  Status Create(const RunOptions& run_options, GraphDef&& graph) override {
    return errors::Unimplemented("Session::Create()");
  }
  Status Extend(const RunOptions& run_options, GraphDef&& graph) override {
    return errors::Unimplemented("Session::Extend()");
  }
  Status Close(const RunOptions& run_options) override {
    return wrapped_->Close(run_options);
  }

  Status Run(const RunOptions& run_options, const std::vector<std::pair<string, Tensor>>& inputs, const std::vector<string>& output_tensor_names, const std::vector<string>& target_node_names, std::vector<Tensor>* outputs, RunMetadata* run_metadata) override {



    return wrapped_->Run(run_options, inputs, output_tensor_names, target_node_names, outputs, run_metadata);
  }

  Status PRunSetup(const std::vector<string>& input_names, const std::vector<string>& output_names, const std::vector<string>& target_nodes, string* handle) override {


    return errors::Unimplemented("Session::PRunSetup()");
  }

  Status PRun(const string& handle, const std::vector<std::pair<string, Tensor>>& inputs, const std::vector<string>& output_names, std::vector<Tensor>* outputs) override {


    return errors::Unimplemented("Session::PRun()");
  }

  Status ListDevices(std::vector<DeviceAttributes>* response) override {
    return wrapped_->ListDevices(response);
  }

  Status Close() override { return wrapped_->Close(); }

  Status MakeCallable(const CallableOptions& callable_options, CallableHandle* out_handle) override {
    return wrapped_->MakeCallable(callable_options, out_handle);
  }

  Status RunCallable(CallableHandle handle, const std::vector<Tensor>& feed_tensors, std::vector<Tensor>* fetch_tensors, RunMetadata* run_metadata) override {


    return wrapped_->RunCallable(handle, feed_tensors, fetch_tensors, run_metadata);
  }

  Status RunCallable( CallableHandle handle, const std::vector<Tensor>& feed_tensors, std::vector<Tensor>* fetch_tensors, RunMetadata* run_metadata, const thread::ThreadPoolOptions& threadpool_options) override {


    return wrapped_->RunCallable(handle, feed_tensors, fetch_tensors, run_metadata, threadpool_options);
  }

  Status ReleaseCallable(CallableHandle handle) override {
    return wrapped_->ReleaseCallable(handle);
  }

 private:
  const std::unique_ptr<Session> wrapped_;
};
}  

Status RestoreSession(const RunOptions& run_options, const MetaGraphDef& meta_graph, const string& export_dir, std::unique_ptr<Session>* session) {

  const uint64 read_start_microseconds = Env::Default()->NowMicros();
  std::vector<AssetFileDef> asset_file_defs;
  TF_RETURN_IF_ERROR(internal::GetAssetFileDefs(meta_graph, &asset_file_defs));
  if (meta_graph.has_saver_def()) {
    TF_RETURN_IF_ERROR(RunRestore(run_options, export_dir, meta_graph.saver_def().restore_op_name(), meta_graph.saver_def().filename_tensor_name(), asset_file_defs, session->get()));


  }
  
  
  const uint64 restore_graph_walltime = GetLatencyMicroseconds(read_start_microseconds);

  const uint64 graph_init_start_microseconds = Env::Default()->NowMicros();
  string init_op_name;
  TF_RETURN_IF_ERROR( internal::GetInitOp(export_dir, meta_graph, &init_op_name));
  TF_RETURN_IF_ERROR(RunInitOp(run_options, export_dir, meta_graph, asset_file_defs, session->get(), init_op_name));
  load_latency_by_stage->GetCell(export_dir, "restore_graph")
      ->Add(restore_graph_walltime);
  
  load_latency_by_stage->GetCell(export_dir, "init_graph")
      ->Add(GetLatencyMicroseconds(graph_init_start_microseconds));
  return Status::OK();
}

Status LoadSavedModel(const SessionOptions& session_options, const RunOptions& run_options, const string& export_dir, const std::unordered_set<string>& tags, SavedModelBundleLite* const bundle) {


  SavedModelBundle legacy_bundle;
  SessionOptions rewritten_options(session_options);
  
  
  rewritten_options.config.mutable_experimental()
      ->set_optimize_for_static_graph(true);
  
  
  
  rewritten_options.config.mutable_experimental()
      ->set_disable_output_partition_graphs(true);
  
  
  TF_RETURN_IF_ERROR(LoadSavedModel(rewritten_options, run_options, export_dir, tags, &legacy_bundle));
  *bundle = SavedModelBundleLite( absl::make_unique<LiteSessionWrapper>(std::move(legacy_bundle.session)), std::move(*legacy_bundle.meta_graph_def.mutable_signature_def()));

  return Status::OK();
}

bool MaybeSavedModelDirectory(const string& export_dir) {
  const string saved_model_pb_path = io::JoinPath(export_dir, kSavedModelFilenamePb);
  const string saved_model_pbtxt_path = io::JoinPath(export_dir, kSavedModelFilenamePbTxt);
  return Env::Default()->FileExists(saved_model_pb_path).ok() || Env::Default()->FileExists(saved_model_pbtxt_path).ok();
}

}  
