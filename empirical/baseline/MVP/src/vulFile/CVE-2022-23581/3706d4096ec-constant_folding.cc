











































namespace tensorflow {
namespace grappler {
using TensorVector = gtl::InlinedVector<TensorValue, 4>;


const int64_t kMaxConstantSize = 100 * 1024;

namespace {
template <typename T> bool AllValuesAre(const TensorProto& proto, const T& value) {
  Tensor tensor;
  if (!tensor.FromProto(proto)) {
    return false;
  }
  auto values = tensor.flat<T>();
  for (int i = 0; i < tensor.NumElements(); ++i) {
    if (values(i) != value) {
      return false;
    }
  }
  return true;
}




bool MaybeAddControlInput(const string& ctrl_input, NodeDef* node, GraphDef* graph, NodeMap* node_map) {
  bool already_exists = false;
  for (const string& input : node->input()) {
    if (input == ctrl_input || AsControlDependency(input) == ctrl_input) {
      already_exists = true;
      break;
    }
  }
  if (!already_exists) {
    const string ctrl_dep = ConstantFolding::AddControlDependency(ctrl_input, graph, node_map);
    node->add_input(ctrl_dep);
    node_map->AddOutput(NodeName(ctrl_input), node->name());
  }
  return !already_exists;
}


bool MaybeRemoveControlInput(const string& old_input, NodeDef* node, GraphDef* graph, NodeMap* node_map) {
  bool removed_input = false;
  bool update_node_map = true;
  const string old_input_ctrl_dep = AsControlDependency(NodeName(old_input));
  for (int i = 0; i < node->input_size(); ++i) {
    const string& input = node->input(i);
    if (old_input_ctrl_dep == input) {
      if (IsControlInput(input)) {
        node->mutable_input()->SwapElements(i, node->input_size() - 1);
        node->mutable_input()->RemoveLast();
        removed_input = true;
      } else {
        
        
        update_node_map = false;
      }
    }
  }
  if (update_node_map) {
    node_map->RemoveOutput(NodeName(old_input), node->name());
  }
  return removed_input;
}

bool HasTPUAttributes(const NodeDef& node) {
  AttrSlice attrs(node);
  for (const auto& attr : attrs) {
    if (attr.first.find("_tpu_") != attr.first.npos) {
      return true;
    }
  }
  return false;
}

template <typename T> bool PackedValuesNotEqual(T a, T b) {
  return a != b;
}

template <> bool PackedValuesNotEqual(float a, float b) {
  return reinterpret_cast<int32_t&>(a) != reinterpret_cast<int32_t&>(b);
}

template <> bool PackedValuesNotEqual(double a, double b) {
  return reinterpret_cast<int64_t&>(a) != reinterpret_cast<int64_t&>(b);
}

float QuantizedTypeMinAsFloat(DataType data_type) {
  switch (data_type) {
    case DT_QINT8:
      return Eigen::NumTraits<qint8>::lowest();
    case DT_QUINT8:
      return Eigen::NumTraits<quint8>::lowest();
    case DT_QINT16:
      return Eigen::NumTraits<qint16>::lowest();
    case DT_QUINT16:
      return Eigen::NumTraits<quint16>::lowest();
    case DT_QINT32:
      return Eigen::NumTraits<qint32>::lowest();
    default:
      return 0.0f;
  }
}

float QuantizedTypeMaxAsFloat(DataType data_type) {
  switch (data_type) {
    case DT_QINT8:
      return Eigen::NumTraits<qint8>::highest();
    case DT_QUINT8:
      return Eigen::NumTraits<quint8>::highest();
    case DT_QINT16:
      return Eigen::NumTraits<qint16>::highest();
    case DT_QUINT16:
      return Eigen::NumTraits<quint16>::highest();
    case DT_QINT32:
      return Eigen::NumTraits<qint32>::highest();
    default:
      return 0.0f;
  }
}

}  

ConstantFolding::ConstantFolding(RewriterConfig::Toggle opt_level, DeviceBase* cpu_device, bool disable_compressed_tensor_optimization, bool fold_quantization_emulation)


    : opt_level_(opt_level), cpu_device_(cpu_device), disable_compressed_tensor_optimization_( disable_compressed_tensor_optimization), fold_quantization_emulation_(fold_quantization_emulation) {



  resource_mgr_.reset(new ResourceMgr());
}

ConstantFolding::ConstantFolding(DeviceBase* cpu_device, bool disable_compressed_tensor_optimization, bool fold_quantization_ops)

    : ConstantFolding(RewriterConfig::ON, cpu_device, disable_compressed_tensor_optimization, fold_quantization_ops) {}



string ConstantFolding::AddControlDependency(const string& input_name, GraphDef* graph, NodeMap* node_map) {

  if (IsControlInput(input_name)) {
    return input_name;
  }
  const NodeDef* node = node_map->GetNode(input_name);
  
  if (!node) {
    return input_name;
  }
  if (!IsSwitch(*node)) {
    return AsControlDependency(*node);
  } else {
    
    
    
    
    
    
    for (const NodeDef* output : node_map->GetOutputs(node->name())) {
      if (IsIdentity(*output) || IsIdentityNSingleInput(*output)) {
        if (IsSameInput(node->input(0), input_name)) {
          return AsControlDependency(*output);
        }
      }
    }
    
    
    int port = 0;
    string ctrl_dep_name = ParseNodeName(input_name, &port);
    strings::StrAppend(&ctrl_dep_name, "_", port);
    ctrl_dep_name = AddPrefixToNodeName(ctrl_dep_name, kConstantFoldingCtrl);
    const DataType output_type = node->attr().at("T").type();

    NodeDef* added_node = node_map->GetNode(ctrl_dep_name);
    if (added_node == nullptr) {
      added_node = graph->add_node();
      added_node->set_name(ctrl_dep_name);
      added_node->set_op("Identity");
      added_node->set_device(node->device());

      (*added_node->mutable_attr())["T"].set_type(output_type);
      *added_node->add_input() = input_name;
      node_map->AddNode(added_node->name(), added_node);
      node_map->AddOutput(node->name(), added_node->name());
    }
    return AsControlDependency(*added_node);
  }
}



bool ConstantFolding::ForwardInputs(NodeDef* node, absl::Span<const int> inputs_to_forward) {
  for (int input_idx : inputs_to_forward) {
    if (input_idx < 0 || input_idx >= node->input_size()) {
      return false;
    }
  }

  const auto& tmp = node_map_->GetOutputs(node->name());
  const std::vector<NodeDef*> consumers(tmp.begin(), tmp.end());
  bool updated_graph = false;
  for (int input_idx : inputs_to_forward) {
    const string& input = node->input(input_idx);
    if (IsControlInput(input) && consumers.size() > 1) {
      continue;
    }
    const NodeDef* input_node = node_map_->GetNode(NodeName(input));
    if (input_node == nullptr) {
      LOG(ERROR) << "Bad input: " << input;
      break;
    }
    
    for (NodeDef* consumer : consumers) {
      bool add_dep = false;
      for (int consumer_input_idx = 0;
           consumer_input_idx < consumer->input_size(); ++consumer_input_idx) {
        const string& consumer_input = consumer->input(consumer_input_idx);
        if (IsControlInput(consumer_input)) {
          break;
        }
        
        
        if (IsRetval(*consumer)) {
          break;
        }
        int output_idx;
        const string input_node_name = ParseNodeName(consumer_input, &output_idx);
        if (input_node_name == node->name() && output_idx == input_idx) {
          consumer->set_input(consumer_input_idx, input);
          
          
          
          node_map_->AddOutput(NodeName(input), consumer->name());
          add_dep = true;
        }
      }
      if (add_dep) {
        consumer->add_input(AsControlDependency(node->name()));
        updated_graph = true;
      }
    }
  }

  if (updated_graph) {
    for (NodeDef* consumer : consumers) {
      DedupControlInputs(consumer);
    }
  }
  return updated_graph;
}


static Status PutValueIntoTensor(const int64_t value, const DataType& type, const int index, Tensor* tensor) {
  if (type == DT_INT32) {
    if (value >= INT_MAX) {
      return Status(error::INVALID_ARGUMENT, "int32 overflow");
    }
    tensor->flat<int32>()(index) = static_cast<int32>(value);
  } else {
    tensor->flat<int64_t>()(index) = value;
  }
  return Status::OK();
}



static Status ConvertShapeToConstant(const string& op, const DataType& type, const PartialTensorShape& shp, Tensor* tensor) {

  if (op == "Shape" || op == "ShapeN") {
    *tensor = Tensor(type, TensorShape({shp.dims()}));
    for (int i = 0; i < shp.dims(); ++i) {
      TF_RETURN_IF_ERROR(PutValueIntoTensor(shp.dim_size(i), type, i, tensor));
    }
  } else if (op == "Size") {
    int64_t size = 1;
    for (int i = 0; i < shp.dims(); ++i) {
      size *= shp.dim_size(i);
    }
    *tensor = Tensor(type, TensorShape({}));
    TF_RETURN_IF_ERROR(PutValueIntoTensor(size, type, 0, tensor));
  } else {
    CHECK_EQ(op, "Rank");
    *tensor = Tensor(type, TensorShape({}));
    TF_RETURN_IF_ERROR(PutValueIntoTensor(shp.dims(), type, 0, tensor));
  }
  return Status::OK();
}


bool ConstantFolding::OptimizedNodeExists(const NodeDef& node, StringPiece suffix) const {
  return node_map_->NodeExists(OptimizedNodeName(node, suffix));
}

string ConstantFolding::OptimizedNodeName(const NodeDef& node, StringPiece suffix) const {
  return AddPrefixToNodeName(strings::StrCat(node.name(), suffix), kConstantFoldingConst);
}

bool ConstantFolding::IsReallyConstant(const NodeDef& node) const {
  if (!IsConstant(node)) {
    return false;
  }
  
  return feed_nodes_.find(node.name()) == feed_nodes_.end();
}


bool ConstantFolding::GetTensorFromConstNode(const string& node_name_or_input, Tensor* tensor) {
  const NodeDef* node = node_map_->GetNode(node_name_or_input);
  return node != nullptr && IsReallyConstant(*node) && CheckAttrExists(*node, "value").ok() && tensor->FromProto(node->attr().at("value").tensor());

}


Status ConstantFolding::MaterializeShapes(const GraphProperties& properties) {
  
  
  
  const int node_count = graph_->node_size();
  for (int node_idx = 0; node_idx < node_count; ++node_idx) {
    NodeDef* node = graph_->mutable_node(node_idx);
    const string op = node->op();
    if (op != "Shape" && op != "Size" && op != "Rank" && op != "ShapeN" && op != "TensorArraySizeV3") {
      continue;
    }
    const std::vector<OpInfo::TensorProperties>& output = properties.GetOutputProperties(node->name());
    const std::vector<OpInfo::TensorProperties>& input = properties.GetInputProperties(node->name());
    if (input.empty() || output.empty()) {
      continue;
    }

    if (op == "Shape" || op == "Size" || op == "Rank") {
      CHECK_EQ(1, output.size());
      CHECK_EQ(1, input.size());

      const DataType type = output[0].dtype();
      CHECK(type == DT_INT32 || type == DT_INT64);
      const PartialTensorShape shape(input[0].shape());

      if ((op != "Rank" && !shape.IsFullyDefined()) || (op == "Rank" && shape.unknown_rank())) {
        continue;
      }

      Tensor constant_value(type);
      if (!ConvertShapeToConstant(op, type, shape, &constant_value).ok()) {
        continue;
      }

      
      
      
      if (op == "Shape") {
        if (shape.dims() > 0 && shape.dim_size(0) == 0) continue;
      }

      
      
      graph_modified_ = true;
      node->set_op("Const");
      EraseRegularNodeAttributes(node);
      (*node->mutable_attr())["dtype"].set_type(type);
      constant_value.AsProtoTensorContent( (*node->mutable_attr())["value"].mutable_tensor());

      
      
      
      
      string ctrl_dep = AddControlDependency(node->input(0), graph_, node_map_.get());
      node_map_->UpdateInput(node->name(), node->input(0), ctrl_dep);
      node->set_input(0, ctrl_dep);
      
      continue;
    }

    if (op == "TensorArraySizeV3") {
      const NodeDef* array = CHECK_NOTNULL(node_map_->GetNode(node->input(0)));
      if (array->input_size() == 0 || (array->attr().count("dynamic_size") != 0 && array->attr().at("dynamic_size").b())) {

        continue;
      }
      const NodeDef* array_size = CHECK_NOTNULL(node_map_->GetNode(array->input(0)));
      if (IsReallyConstant(*array_size)) {
        
        
        if (array_size->attr().count("value") == 0) {
          continue;
        }
        const TensorProto& raw_val = array_size->attr().at("value").tensor();
        if (raw_val.dtype() != DT_INT32) {
          continue;
        }
        Tensor value(raw_val.dtype(), raw_val.tensor_shape());
        if (!value.FromProto(raw_val)) {
          continue;
        }
        if (value.flat<int32>()(0) == 0) {
          continue;
        }

        graph_modified_ = true;
        node->set_op("Const");
        *node->mutable_attr() = array_size->attr();
        node->set_input(0, AsControlDependency(NodeName(node->input(0))));
        node->set_input(1, AddControlDependency(NodeName(node->input(1)), graph_, node_map_.get()));
      }
      continue;
    }

    
    
    CHECK_EQ(op, "ShapeN");
    CHECK_EQ(input.size(), output.size());
    const NodeDef* const shape_n_node = node;
    for (int port_idx = 0, idx_limit = output.size(); port_idx < idx_limit;
         ++port_idx) {
      const DataType type = output[port_idx].dtype();
      CHECK(type == DT_INT32 || type == DT_INT64);
      const PartialTensorShape shape(input[port_idx].shape());
      if (!shape.IsFullyDefined()) {
        continue;
      }
      Tensor constant_value(type);
      auto status = ConvertShapeToConstant(op, type, shape, &constant_value);
      if (!status.ok()) {
        continue;
      }

      
      auto fanouts = node_map_->GetOutputs(shape_n_node->name());
      
      
      for (NodeDef* output : fanouts) {
        
        
        bool direct_edges_exist = false;
        for (int k = 0; k < output->input_size(); ++k) {
          int port;
          const string node_name = ParseNodeName(output->input(k), &port);
          if (node_name == shape_n_node->name() && port == port_idx) {
            
            const string const_name = OptimizedNodeName( *shape_n_node, strings::StrCat("-matshapes-", port_idx));
            if (node_map_->GetNode(const_name) == nullptr) {
              NodeDef* added_node = graph_->add_node();
              added_node->set_name(const_name);
              added_node->set_op("Const");
              added_node->set_device(shape_n_node->device());
              node_map_->AddNode(added_node->name(), added_node);
              (*added_node->mutable_attr())["dtype"].set_type(type);
              constant_value.AsProtoTensorContent( (*added_node->mutable_attr())["value"].mutable_tensor());
              
              
              
              string ctrl_dep = AddControlDependency(shape_n_node->name(), graph_, node_map_.get());
              *added_node->add_input() = ctrl_dep;
              node_map_->AddOutput(NodeName(ctrl_dep), added_node->name());
            }
            *output->mutable_input(k) = const_name;
            node_map_->AddOutput(const_name, output->name());
            graph_modified_ = true;
          }
          if (node_name == shape_n_node->name() && port != port_idx) {
            direct_edges_exist = true;
          }
        }
        if (!direct_edges_exist) {
          node_map_->RemoveOutput(node->name(), output->name());
        }
      }
    }
  }

  return Status::OK();
}

namespace {
bool ExtractShape(const NodeDef& shape_node, const GraphProperties& properties, BCast::Vec* shape, int64_t* min_id) {
  if (shape_node.op() == "Shape") {
    const std::vector<OpInfo::TensorProperties>& prop1 = properties.GetInputProperties(shape_node.name());
    if (prop1.size() != 1) {
      return false;
    }
    const TensorShapeProto& shp = prop1[0].shape();
    if (shp.unknown_rank()) {
      return false;
    }
    for (const auto& dim : shp.dim()) {
      shape->push_back(dim.size());
      *min_id = std::min<int64_t>(*min_id, dim.size());
    }
  } else {
    if (shape_node.attr().count("value") == 0) {
      return false;
    }
    const TensorProto& raw_val = shape_node.attr().at("value").tensor();
    if (raw_val.dtype() != DT_INT64 && raw_val.dtype() != DT_INT32) {
      return false;
    }
    Tensor value(raw_val.dtype(), raw_val.tensor_shape());
    if (!value.FromProto(raw_val)) {
      return false;
    }
    for (int j = 0; j < value.NumElements(); ++j) {
      if (raw_val.dtype() == DT_INT64) {
        shape->push_back(value.vec<int64_t>()(j));
      } else {
        shape->push_back(value.vec<int>()(j));
      }
    }
  }
  return true;
}
}  

Status ConstantFolding::MaterializeBroadcastGradientArgs( const NodeDef& node, const GraphProperties& properties) {
  const NodeDef* shape_node1 = node_map_->GetNode(node.input(0));
  const NodeDef* shape_node2 = node_map_->GetNode(node.input(1));
  if (shape_node1 == nullptr || (shape_node1->op() != "Shape" && !IsReallyConstant(*shape_node1)) || shape_node2 == nullptr || (shape_node2->op() != "Shape" && !IsReallyConstant(*shape_node2))) {


    return Status::OK();
  }

  
  if (OptimizedNodeExists(node, "-folded-1") || OptimizedNodeExists(node, "-folded-2")) {
    return Status::OK();
  }
  int64_t min_id = 0;
  BCast::Vec shape1;
  if (!ExtractShape(*shape_node1, properties, &shape1, &min_id)) {
    return Status::OK();
  }
  BCast::Vec shape2;
  if (!ExtractShape(*shape_node2, properties, &shape2, &min_id)) {
    return Status::OK();
  }
  
  
  
  for (auto& id : shape1) {
    if (id == -1) {
      id = --min_id;
    }
  }
  for (auto& id : shape2) {
    if (id == -1) {
      id = --min_id;
    }
  }

  
  
  
  
  const int common_dims = std::min(shape1.size(), shape2.size());
  for (int i = 0; i < common_dims; ++i) {
    if (shape1[i] >= 0 && shape2[i] >= 0) {
      continue;
    }
    if (shape1[i] != shape2[i]) {
      
      
      
      return Status::OK();
    }
  }
  
  
  
  for (int i = common_dims, end = shape1.size(); i < end; ++i) {
    if (shape1[i] < 0) {
      return Status::OK();
    }
  }
  for (int i = common_dims, end = shape2.size(); i < end; ++i) {
    if (shape2[i] < 0) {
      return Status::OK();
    }
  }

  BCast bcast(shape1, shape2);
  if (!bcast.IsValid()) {
    return Status::OK();
  }

  BCast::Vec reduce_dims[2];
  reduce_dims[0] = bcast.grad_x_reduce_idx();
  reduce_dims[1] = bcast.grad_y_reduce_idx();

  TF_RETURN_IF_ERROR(CheckAttrExists(node, "T"));
  const DataType type = node.attr().at("T").type();
  NodeDef* out[2];
  for (int j = 0; j < 2; ++j) {
    int reduction_indices = reduce_dims[j].size();
    Tensor value(type, TensorShape({reduction_indices}));
    for (int i = 0; i < reduction_indices; ++i) {
      if (type == DT_INT32) {
        value.vec<int32>()(i) = reduce_dims[j][i];
      } else {
        value.vec<int64_t>()(i) = reduce_dims[j][i];
      }
    }
    string const_name = OptimizedNodeName(node, strings::StrCat("-bcastargs-", j));
    out[j] = node_map_->GetNode(const_name);
    if (out[j] == nullptr) {
      out[j] = graph_->add_node();
      TF_RETURN_IF_ERROR( CreateNodeDef(const_name, TensorValue(&value), out[j]));
      out[j]->set_device(node.device());
      node_map_->AddNode(const_name, out[j]);
      string ctrl_dep = AddControlDependency(node.name(), graph_, node_map_.get());
      *out[j]->add_input() = ctrl_dep;
      node_map_->AddOutput(NodeName(ctrl_dep), const_name);
    }
  }

  
  const auto outputs = node_map_->GetOutputs(node.name());
  for (NodeDef* output : outputs) {
    for (int k = 0; k < output->input_size(); ++k) {
      int port;
      string node_name = ParseNodeName(output->input(k), &port);
      if (node_name == node.name() && port >= 0 && port < 2 && out[port]) {
        *output->mutable_input(k) = out[port]->name();
        node_map_->UpdateInput(output->name(), node_name, out[port]->name());
      }
    }
  }

  return Status::OK();
}

Status ConstantFolding::MaterializeReductionIndices( NodeDef* node, const GraphProperties& properties) {
  if (node->input_size() < 2) {
    return Status::OK();
  }
  const NodeDef* indices = node_map_->GetNode(node->input(1));
  if (!indices || IsReallyConstant(*indices)) {
    
    return Status::OK();
  }

  const std::vector<OpInfo::TensorProperties>& input_props = properties.GetInputProperties(node->name());
  if (input_props.size() != 2) {
    return Status::OK();
  }
  const OpInfo::TensorProperties& input_prop = input_props[0];
  if (input_prop.shape().unknown_rank()) {
    
    return Status::OK();
  }
  const int input_rank = input_prop.shape().dim_size();
  if (input_rank < 1) {
    
    return Status::OK();
  }
  const OpInfo::TensorProperties& reduction_indices_prop = input_props[1];
  DataType dtype = reduction_indices_prop.dtype();
  if (dtype != DT_INT32 && dtype != DT_INT64) {
    return Status::OK();
  }
  PartialTensorShape reduction_indices_shape(reduction_indices_prop.shape());
  const int num_reduction_indices = reduction_indices_shape.num_elements();

  const std::vector<OpInfo::TensorProperties>& output_props = properties.GetOutputProperties(node->name());
  if (output_props.size() != 1) {
    return Status::OK();
  }
  const OpInfo::TensorProperties& output_prop = output_props[0];
  const int output_rank = output_prop.shape().unknown_rank() ? -1 : output_prop.shape().dim_size();

  bool full_reduction = output_rank == 0 || num_reduction_indices == input_rank;
  if (!full_reduction) {
    
    
    
    
    for (const NodeDef* fanout : node_map_->GetOutputs(node->name())) {
      full_reduction = false;
      if (!IsReshape(*fanout)) {
        return Status::OK();
      }
      const std::vector<OpInfo::TensorProperties>& reshape_props = properties.GetOutputProperties(fanout->name());
      if (reshape_props.size() != 1) {
        return Status::OK();
      }
      const OpInfo::TensorProperties& reshape_prop = reshape_props[0];
      PartialTensorShape shape(reshape_prop.shape());
      if (shape.num_elements() != 1) {
        return Status::OK();
      } else {
        full_reduction = true;
      }
    }
    if (!full_reduction) {
      return Status::OK();
    }
  }

  
  
  string const_name = OptimizedNodeName(*node, "-reduction_indices");
  if (node_map_->GetNode(const_name)) {
    return Status::OK();
  }
  NodeDef* reduction_indices = graph_->add_node();
  Tensor value(dtype, TensorShape({input_rank}));
  for (int i = 0; i < input_rank; ++i) {
    if (dtype == DT_INT32) {
      value.vec<int32>()(i) = i;
    } else {
      value.vec<int64_t>()(i) = i;
    }
  }
  TF_RETURN_IF_ERROR( CreateNodeDef(const_name, TensorValue(&value), reduction_indices));

  reduction_indices->set_device(node->device());
  string ctrl_dep = AddControlDependency(node->input(1), graph_, node_map_.get());
  *reduction_indices->add_input() = ctrl_dep;
  node_map_->AddNode(const_name, reduction_indices);
  node_map_->AddOutput(NodeName(ctrl_dep), const_name);

  node->set_input(1, reduction_indices->name());
  node_map_->UpdateInput(node->name(), indices->name(), reduction_indices->name());

  return Status::OK();
}

Status ConstantFolding::MaterializeConstantValuedNode( NodeDef* node, const GraphProperties& properties) {
  if (disable_compressed_tensor_optimization_) {
    return Status::OK();
  }
  
  
  const std::vector<OpInfo::TensorProperties>& output_props = properties.GetOutputProperties(node->name());
  if (output_props.size() != 1) return Status::OK();
  const auto& output_shape = output_props[0].shape();
  if (!PartialTensorShape(output_shape).IsFullyDefined()) {
    return Status::OK();
  }
  if (IsFill(*node)) {
    const auto output_dtype = output_props[0].dtype();
    NodeDef* input_node = nullptr;
    for (int i = 0; i < 2; ++i) {
      input_node = node_map_->GetNode(NodeName(node->input(i)));
      if (input_node == nullptr || !IsReallyConstant(*input_node)) {
        return Status::OK();
      }
    }
    TF_RETURN_IF_ERROR(CheckAttrExists(*input_node, "value"));

    
    
    TensorProto* tensor = (*node->mutable_attr())["value"].mutable_tensor();
    const TensorProto& input_tensor = input_node->attr().at("value").tensor();
    if (!input_tensor.tensor_content().empty()) {
      
      
      
      Tensor t;
      if (!t.FromProto(input_tensor)) {
        return errors::InvalidArgument( "Could not construct Tensor form TensorProto in node: ", input_node->name());

      }
      tensor->clear_tensor_content();
      t.AsProtoField(tensor);
    } else {
      *tensor = input_tensor;
    }
    *(tensor->mutable_tensor_shape()) = output_shape;
    (*node->mutable_attr())["dtype"].set_type(output_dtype);
    node->mutable_attr()->erase("T");
    node->mutable_attr()->erase("index_type");
    node->set_op("Const");
    for (int i = 0; i < 2; i++) {
      
      const string ctrl_dep = AsControlDependency(node->input(i));
      node_map_->UpdateInput(node->name(), node->input(i), ctrl_dep);
      node->set_input(i, ctrl_dep);
    }
    graph_modified_ = true;
  } else {
    double value = (IsZerosLike(*node) ? 0.0 : (IsOnesLike(*node) ? 1.0 : -1.0));
    if (value >= 0) {
      TF_RETURN_IF_ERROR(ReplaceOperationWithConstant( value, properties, output_shape, node, graph_));
    }
  }
  return Status::OK();
}


Status ConstantFolding::MaterializeOutputValues( NodeDef* node, const GraphProperties& properties) {
  const std::vector<OpInfo::TensorProperties>& output = properties.GetOutputProperties(node->name());
  if (output.size() != 1 || !output[0].has_value() || !IsFoldable(*node, &properties)) {
    return Status::OK();
  }

  
  
  if (IsIdentity(*node)) {
    NodeDef* input = node_map_->GetNode(node->input(0));
    if (IsReallyConstant(*input)) {
      std::vector<int> inputs_to_forward;
      std::iota(inputs_to_forward.begin(), inputs_to_forward.end(), 0);
      graph_modified_ = ForwardInputs(node, inputs_to_forward);
      return Status::OK();
    }
  }
  
  
  TensorProto value_copy = output[0].value();
  return ReplaceOperationWithConstantTensor(output[0].dtype(), &value_copy, node, graph_);
}

Status ConstantFolding::MaterializeConstants( const GraphProperties& properties) {
  const int node_count = graph_->node_size();
  for (int i = 0; i < node_count; ++i) {
    NodeDef& node = *graph_->mutable_node(i);
    const string& op = node.op();
    if (op == "BroadcastGradientArgs") {
      TF_RETURN_IF_ERROR(MaterializeBroadcastGradientArgs(node, properties));
    } else if (IsReduction(node)) {
      TF_RETURN_IF_ERROR(MaterializeReductionIndices(&node, properties));
    } else if (IsFill(node) || IsZerosLike(node) || IsOnesLike(node)) {
      TF_RETURN_IF_ERROR(MaterializeConstantValuedNode(&node, properties));
    } else {
      TF_RETURN_IF_ERROR(MaterializeOutputValues(&node, properties));
    }
  }
  return Status::OK();
}

bool ConstantFolding::IsFoldable(const NodeDef& node, const GraphProperties* properties) {
  string key = strings::StrCat(node.name(), "/", node.op());
  auto it = maybe_foldable_nodes_.find(key);
  if (it == maybe_foldable_nodes_.end()) {
    it = maybe_foldable_nodes_ .emplace(std::move(key), MaybeFoldable(node, properties))
             .first;
  }
  if (!it->second) {
    return false;
  } else {
    return IsFoldableUncached(node, properties);
  }
}

bool ConstantFolding::IsFoldableUncached( const NodeDef& node, const GraphProperties* properties) const {
  
  if (node.input().empty()) {
    return false;
  }
  
  
  
  
  bool merge_has_constant_input = false;
  const bool is_merge = IsMerge(node);
  for (const auto& input : node.input()) {
    if (IsControlInput(input)) {
      continue;
    }
    const NodeDef* input_node = node_map_->GetNode(input);
    if (!input_node) {
      return false;
    }
    bool is_const = IsReallyConstant(*input_node);
    if (is_const) {
      
      
      if (input_node->attr().count("dtype") == 0 || input_node->attr().at("dtype").type() == DT_STRING) {
        return false;
      }
      
      
      merge_has_constant_input |= !HasControlInputs(*input_node);
    } else if (!is_merge) {
      return false;
    }
  }
  if (is_merge && !merge_has_constant_input) return false;
  if (disable_compressed_tensor_optimization_ && (IsFill(node) || IsZerosLike(node) || IsOnesLike(node)))
    return false;

  
  
  if (properties != nullptr && properties->HasOutputProperties(node.name())) {
    const std::vector<OpInfo::TensorProperties>& input_props = properties->GetInputProperties(node.name());
    const std::vector<OpInfo::TensorProperties>& output_props = properties->GetOutputProperties(node.name());
    
    int64_t input_size_bytes = 0;
    for (const auto& input_prop : input_props) {
      const PartialTensorShape input_shape(input_prop.shape());
      if (input_shape.IsFullyDefined()) {
        input_size_bytes += input_shape.num_elements() * DataTypeSize(input_prop.dtype());
      }
    }
    for (const auto& output_prop : output_props) {
      const PartialTensorShape output_shape(output_prop.shape());
      if (output_shape.IsFullyDefined()) {
        const int64_t num_bytes = output_shape.num_elements() * DataTypeSize(output_prop.dtype());
        if (num_bytes > input_size_bytes && num_bytes > kMaxConstantSize) {
          
          
          
          return false;
        }
      }
    }
  }

  return true;
}

bool ConstantFolding::MaybeFoldable(const NodeDef& node, const GraphProperties* properties) const {
  
  if (IsConstant(node)) {
    return false;
  }
  
  if (!IsFreeOfSideEffect(node)) {
    return false;
  }

  
  if (nodes_to_preserve_.find(node.name()) != nodes_to_preserve_.end() && nodes_allowlist_.find(node.name()) == nodes_allowlist_.end()) {
    return false;
  }

  
  if (ModifiesFrameInfo(node)) {
    return false;
  }

  
  if (IsPlaceholder(node)) {
    return false;
  }
  
  
  if (IsFakeParam(node)) {
    return false;
  }

  if (node.op() == "AccumulateNV2") {
    return false;
  }
  
  if (node.op() == "LoopCond") {
    return false;
  }

  if (!fold_quantization_emulation_ && IsQuantizationEmulation(node)) {
    return false;
  }

  const string& op = node.op();
  if (op.find("Save") != string::npos || op.find("Restore") != string::npos || op.find("Reader") != string::npos) {
    return false;
  }
  if (op.find("Quantized") != string::npos || absl::StartsWith(op, "Sparse")) {
    return false;
  }

  
  
  
  if (HasTPUAttributes(node)) {
    return false;
  }

  const OpDef* op_def = nullptr;
  Status status = OpRegistry::Global()->LookUpOpDef(node.op(), &op_def);
  if (!status.ok()) {
    return false;
  }
  
  if (op_def->output_arg_size() == 0) {
    return false;
  }
  
  
  for (const OpDef::ArgDef& output_arg : op_def->output_arg()) {
    if (output_arg.type() == DT_VARIANT) {
      return false;
    }
  }

  
  
  
  
  const auto& outputs = node_map_->GetOutputs(node.name());
  if (outputs.empty() && nodes_allowlist_.find(node.name()) == nodes_allowlist_.end()) {
    return false;
  }
  return true;
}

namespace {





Status CreateConstantTensorAttrValue(DataType type, double value, const TensorShapeProto& shape, AttrValue* attr_tensor) {

  TensorProto* t = attr_tensor->mutable_tensor();
  t->set_dtype(type);
  *t->mutable_tensor_shape() = shape;
  switch (type) {
    case DT_HALF:
      t->add_half_val( Eigen::numext::bit_cast<uint16>(static_cast<Eigen::half>(value)));
      break;
    case DT_BFLOAT16:
      t->add_half_val( Eigen::numext::bit_cast<uint16>(static_cast<bfloat16>(value)));
      break;
      SET_TENSOR_VAL_CASE(DT_FLOAT, float, float);
      SET_TENSOR_VAL_CASE(DT_DOUBLE, double, double);
      SET_TENSOR_VAL_CASE(DT_INT64, int64_t, int64);
      SET_TENSOR_VAL_CASE(DT_UINT64, int64_t, int64);
      SET_TENSOR_VAL_CASE(DT_INT32, int32, int);
      SET_TENSOR_VAL_CASE(DT_UINT32, int32, int);
      SET_TENSOR_VAL_CASE(DT_INT16, int32, int);
      SET_TENSOR_VAL_CASE(DT_UINT16, int32, int);
      SET_TENSOR_VAL_CASE(DT_INT8, int32, int);
      SET_TENSOR_VAL_CASE(DT_UINT8, int32, int);
      SET_TENSOR_VAL_CASE(DT_QINT32, int32, int);
      SET_TENSOR_VAL_CASE(DT_QINT16, int32, int);
      SET_TENSOR_VAL_CASE(DT_QUINT16, int32, int);
      SET_TENSOR_VAL_CASE(DT_QINT8, int32, int);
      SET_TENSOR_VAL_CASE(DT_QUINT8, int32, int);
      SET_TENSOR_VAL_CASE(DT_BOOL, bool, bool);
    default:
      return errors::InvalidArgument( "Unsupported type in CreateConstantTensorAttrValue: ", DataTypeString(type));

  }
  return Status::OK();
}



DataType GetDataTypeFromNodeOrProps(const NodeDef& node, const GraphProperties& properties) {
  DataType dtype = DT_INVALID;
  if (node.attr().count("T") == 1) {
    dtype = node.attr().at("T").type();
  } else if (node.attr().count("dtype") == 1) {
    dtype = node.attr().at("dtype").type();
  } else if (IsLogicalOr(node) || IsLogicalAnd(node)) {
    dtype = DT_BOOL;
  } else {
    auto output_props = properties.GetOutputProperties(node.name());
    if (!output_props.empty()) {
      dtype = output_props[0].dtype();
    }
  }
  return dtype;
}



bool IsValidConstShapeForMulConvPushDown( const string& data_format, const TensorShapeProto& filter_shape, const TensorShapeProto& mul_const_input_shape) {

  
  
  
  if (mul_const_input_shape.dim_size() <= static_cast<int>(data_format.size()) && TensorShape(mul_const_input_shape).num_elements() == 1) {

    return true;
  }

  
  if (data_format == "NHWC" || data_format == "NDHWC") {
    TensorShapeProto new_filter_shape;
    if (!ShapeAfterBroadcast(filter_shape, mul_const_input_shape, &new_filter_shape)) {
      return false;
    }
    if (!ShapesSymbolicallyEqual(filter_shape, new_filter_shape)) {
      return false;
    }
    
    
    for (int i = 0; i < mul_const_input_shape.dim_size() - 1; ++i) {
      if (mul_const_input_shape.dim(i).size() > 1) return false;
    }
    return true;
  } else if (data_format == "NCHW" || data_format == "NCDHW") {
    
    return false;
  }
  return false;
}

}  


Status ConstantFolding::CreateNodeDef(const string& name, const TensorValue& tensor, NodeDef* node, size_t original_size) {

  node->set_name(name);
  node->set_op("Const");

  AttrValue attr_type;
  attr_type.set_type(tensor->dtype());
  node->mutable_attr()->insert({"dtype", attr_type});

  AttrValue attr_tensor;
  TensorProto* t = attr_tensor.mutable_tensor();
  bool optimized = false;
  size_t encoded_size;
  
  
  if (tensor->NumElements() > 4) {























    switch (tensor->dtype()) {
      case DT_FLOAT:
        POPULATE_TENSOR_PROTO(tensor, t, float, float);
      case DT_DOUBLE:
        POPULATE_TENSOR_PROTO(tensor, t, double, double);
      case DT_INT64:
        POPULATE_TENSOR_PROTO(tensor, t, int64_t, int64);
      case DT_UINT64:
        POPULATE_TENSOR_PROTO(tensor, t, uint64, uint64);
      case DT_INT32:
        POPULATE_TENSOR_PROTO(tensor, t, int32_t, int);
      case DT_UINT32:
        POPULATE_TENSOR_PROTO(tensor, t, uint32, uint32);
      case DT_INT16:
        POPULATE_TENSOR_PROTO(tensor, t, int16_t, int);
      case DT_UINT16:
        POPULATE_TENSOR_PROTO(tensor, t, uint16, int);
      case DT_INT8:
        POPULATE_TENSOR_PROTO(tensor, t, int8_t, int);
      case DT_UINT8:
        POPULATE_TENSOR_PROTO(tensor, t, uint8, int);
      case DT_BOOL:
        POPULATE_TENSOR_PROTO(tensor, t, bool, bool);
      default:
        
        break;
    }
  }
  if (optimized) {
    
    t->set_dtype(tensor->dtype());
    tensor->shape().AsProto(t->mutable_tensor_shape());
  } else {
    
    
    tensor->AsProtoTensorContent(t);
    encoded_size = t->tensor_content().size();
  }
  node->mutable_attr()->insert({"value", attr_tensor});

  if (encoded_size > original_size && encoded_size >= kMaxConstantSize) {
    return errors::InvalidArgument( strings::StrCat("Can't fold ", name, ", its size would be too large (", encoded_size, " >= ", kMaxConstantSize, " bytes)"));

  }
  return Status::OK();
}

Status ConstantFolding::EvaluateNode(const NodeDef& node, const TensorVector& inputs, TensorVector* output) const {

  return ::tensorflow::grappler::EvaluateNode(node, inputs, cpu_device_, resource_mgr_.get(), output);
}

Status ConstantFolding::EvaluateOneFoldable(const NodeDef& node, std::vector<NodeDef>* outputs, bool* result_too_large) {

  TensorVector inputs;
  TensorVector output_tensors;
  auto inputs_cleanup = gtl::MakeCleanup([&inputs, &output_tensors] {
    for (const auto& input : inputs) {
      delete input.tensor;
    }
    for (const auto& output : output_tensors) {
      if (output.tensor) {
        delete output.tensor;
      }
    }
  });

  size_t total_inputs_size = 0;
  for (const auto& input : node.input()) {
    const TensorId input_tensor = ParseTensorName(input);
    if (input_tensor.index() < 0) {
      
      break;
    }
    const NodeDef* input_node = node_map_->GetNode(input);
    if (!IsReallyConstant(*input_node)) {
      return Status(error::INVALID_ARGUMENT, strings::StrCat("Can't fold ", node.name(), ", its ", input, " isn't constant"));

    }
    TF_RETURN_IF_ERROR(CheckAttrExists(*input_node, "value"));
    const TensorProto& raw_val = input_node->attr().at("value").tensor();
    if (raw_val.dtype() == DT_INVALID) {
      return Status( error::INVALID_ARGUMENT, strings::StrCat("A tensor in the input node, with TensorId of ", input_tensor.ToString(), " has a dtype of DT_INVALID."));



    }
    Tensor* value = new Tensor(raw_val.dtype(), raw_val.tensor_shape());
    if (!value->FromProto(raw_val)) {
      delete (value);
      return errors::InvalidArgument("Unable to make Tensor from proto for ", node.name(), " with shape ", raw_val.tensor_shape().DebugString());

    }
    inputs.emplace_back(value);
    total_inputs_size += value->TotalBytes();
  }

  TF_RETURN_IF_ERROR(EvaluateNode(node, inputs, &output_tensors));
  if (output_tensors.empty()) {
    return Status(error::INVALID_ARGUMENT, "Expected at least one output.");
  }

  outputs->resize(output_tensors.size());
  for (size_t i = 0; i < output_tensors.size(); i++) {
    string node_name = OptimizedNodeName(node, "-folded");
    if (output_tensors.size() > 1) {
      node_name = strings::StrCat(node_name, "-", i);
    }
    if (output_tensors[i].tensor) {
      Status s = CreateNodeDef(node_name, output_tensors[i], &outputs->at(i), total_inputs_size);
      if (!s.ok()) {
        *result_too_large = true;
        return s;
      }
    } else {
      
      
      outputs->at(i) = NodeDef();
    }
  }
  return Status::OK();
}

Status ConstantFolding::FoldMergeNode(NodeDef* node, GraphDef* output_graph) {
  
  
  
  
  
  
  
  
  
  
  
  
  
  for (int input_index = 0; input_index < node->input_size(); ++input_index) {
    const auto& input = node->input(input_index);
    if (IsControlInput(input)) {
      
      continue;
    }
    NodeDef* input_node = node_map_->GetNode(input);
    if (!IsReallyConstant(*input_node)) {
      continue;
    }
    bool valid_input = true;
    for (const string& fanin_of_input : input_node->input()) {
      if (IsControlInput(fanin_of_input)) {
        valid_input = false;
        break;
      }
    }
    if (!valid_input) {
      
      continue;
    }

    string const_out_name = OptimizedNodeName(*node, "_const");
    string const_index_name = OptimizedNodeName(*node, "_index");
    if (node_map_->GetNode(const_out_name) || node_map_->GetNode(const_index_name)) {
      
      return errors::AlreadyExists( strings::StrCat(const_out_name, " or ", const_index_name, " already present in the graph"));

    }

    NodeDef* const_out = output_graph->add_node();
    *const_out = *input_node;
    const_out->set_name(const_out_name);
    const_out->set_device(node->device());
    *const_out->add_input() = AsControlDependency(*node);
    node_map_->AddNode(const_out->name(), const_out);
    node_map_->AddOutput(node->name(), const_out->name());

    NodeDef* const_index = output_graph->add_node();
    const_index->set_op("Const");
    Tensor index(DT_INT32, TensorShape({}));
    index.flat<int32>()(0) = input_index;
    (*const_index->mutable_attr())["dtype"].set_type(DT_INT32);
    index.AsProtoTensorContent( (*const_index->mutable_attr())["value"].mutable_tensor());
    const_index->set_name(const_index_name);
    const_index->set_device(node->device());
    *const_index->add_input() = AsControlDependency(*node);
    node_map_->AddNode(const_index->name(), const_index);
    node_map_->AddOutput(node->name(), const_index->name());

    
    auto outputs = node_map_->GetOutputs(node->name());
    for (NodeDef* output : outputs) {
      for (int i = 0; i < output->input_size(); i++) {
        int port;
        string node_name = ParseNodeName(output->input(i), &port);
        if (node_name == node->name()) {
          if (port == 0) {
            *output->mutable_input(i) = const_out->name();
            node_map_->AddOutput(const_out->name(), output->name());
          } else if (port == 1) {
            *output->mutable_input(i) = const_index->name();
            node_map_->AddOutput(const_index->name(), output->name());
          } else {
            
            
          }
        }
      }
    }
    return Status::OK();
  }
  return Status::OK();
}

Status ConstantFolding::FoldNode(NodeDef* node, GraphDef* output_graph, bool* result_too_large) {
  *result_too_large = false;
  if (IsMerge(*node)) {
    return FoldMergeNode(node, output_graph);
  }

  std::vector<NodeDef> const_nodes;
  TF_RETURN_IF_ERROR( EvaluateOneFoldable(*node, &const_nodes, result_too_large));
  VLOG(2) << "Folded node: " << SummarizeNodeDef(*node);

  NodeDef* constant_output = nullptr;
  for (int i = 0, end = const_nodes.size(); i < end; i++) {
    NodeDef* const_node = &const_nodes[i];
    VLOG(3) << "Generated constant node: " << SummarizeNodeDef(*const_node);
    if (const_node->name().empty()) {
      
      
      
      
      continue;
    }

    
    const auto is_duplicate_control_input = [&](const string& input) -> bool {
      auto it = absl::c_find(const_node->input(), input);
      return it != const_node->input().end();
    };

    
    for (const string& input : node->input()) {
      
      if (IsControlInput(input)) {
        if (!is_duplicate_control_input(input)) {
          *const_node->add_input() = input;
        }
      }

      
      if (!IsControlInput(input)) {
        NodeDef* input_node = node_map_->GetNode(input);
        for (const string& fanin_of_input : input_node->input()) {
          if (!is_duplicate_control_input(fanin_of_input)) {
            *const_node->add_input() = fanin_of_input;
          }
        }
      }
    }

    
    
    if (const_nodes.size() == 1) {
      node->set_op("Const");
      
      
      
      node_map_->RemoveInputs(node->name());
      node->clear_input();
      *node->mutable_input() = const_node->input();
      for (const auto& input : node->input()) {
        node_map_->AddOutput(NodeName(input), node->name());
      }
      *node->mutable_attr() = const_node->attr();
      break;
    } else {
      if (node_map_->GetNode(const_node->name())) {
        
        return errors::AlreadyExists(strings::StrCat( const_node->name(), " already present in the graph"));
      }
      NodeDef* added_node = output_graph->add_node();
      *added_node = *const_node;
      added_node->set_device(node->device());
      node_map_->AddNode(added_node->name(), added_node);
      for (const auto& input : added_node->input()) {
        node_map_->AddOutput(NodeName(input), added_node->name());
      }
      
      
      
      constant_output = added_node;
    }
  }

  if (const_nodes.size() > 1) {
    
    auto outputs = node_map_->GetOutputs(node->name());
    for (NodeDef* output : outputs) {
      for (int i = 0; i < output->input_size(); i++) {
        int port;
        string node_name = ParseNodeName(output->input(i), &port);
        if (node_name == node->name()) {
          if (port < 0) {
            
            
            if (constant_output != nullptr) {
              node_map_->UpdateInput(node_name, NodeName(output->input(i)), constant_output->name());
              *output->mutable_input(i) = AsControlDependency(*constant_output);
            }
          } else if (port < static_cast<int>(const_nodes.size()) && !const_nodes[port].name().empty()) {
            
            node_map_->UpdateInput(output->name(), NodeName(output->input(i)), const_nodes[port].name());
            *output->mutable_input(i) = const_nodes[port].name();
          } else {
            
            VLOG(3) << "Preserving edge from " << node->name() << ":" << port << "[" << node->op() << "] to " << output->name() << ":" << i << "[" << output->op() << "]";

          }
        }
      }
    }
    outputs = node_map_->GetOutputs(node->name());
    if (outputs.empty() && has_fetch_ && nodes_to_preserve_.find(node->name()) == nodes_to_preserve_.end()) {
      node_map_->RemoveInputs(node->name());
      node->clear_input();
    }
  }
  return Status::OK();
}

Status ConstantFolding::FoldGraph( const GraphProperties& properties, GraphDef* optimized_graph, absl::flat_hash_set<string>* nodes_to_not_simplify) {

  
  
  absl::flat_hash_set<string> processed_nodes;
  std::deque<NodeDef*> queue;
  for (int i = 0; i < graph_->node_size(); i++) {
    const NodeDef& node = graph_->node(i);
    if (IsFoldable(node, &properties) && !nodes_to_not_simplify->count(node.name())) {
      queue.push_back(graph_->mutable_node(i));
    }
  }
  while (!queue.empty()) {
    NodeDef* node = queue.front();
    queue.pop_front();
    if (processed_nodes.count(node->name())) {
      continue;
    }
    
    
    std::vector<NodeDef*> fanout = node_map_->GetOutputsOrderedByNodeName(node->name());
    bool result_too_large = false;
    Status s = FoldNode(node, optimized_graph, &result_too_large);
    processed_nodes.insert(node->name());
    if (!s.ok()) {
      VLOG(1) << "Failed to fold node " << node->DebugString()
              << "\nError message: " << s;
      if (result_too_large) {
        nodes_to_not_simplify->emplace(node->name());
      }
    } else {
      for (auto& fanout_node : fanout) {
        if (IsFoldable(*fanout_node, &properties) && !nodes_to_not_simplify->count(fanout_node->name())) {
          queue.push_back(fanout_node);
        }
      }
    }
  }

  
  std::vector<int> nodes_to_delete;
  for (int i = 0; i < optimized_graph->node_size(); i++) {
    const auto& fanout = node_map_->GetOutputs(optimized_graph->node(i).name());
    if (fanout.empty()) nodes_to_delete.push_back(i);
  }
  EraseNodesFromGraph(std::move(nodes_to_delete), optimized_graph);

  for (int i = 0; i < graph_->node_size(); ++i) {
    NodeDef* node = graph_->mutable_node(i);
    
    
    
    const auto& fanout = node_map_->GetOutputs(node->name());
    if (!fanout.empty() || !has_fetch_ || nodes_to_preserve_.find(node->name()) != nodes_to_preserve_.end()) {
      *(optimized_graph->add_node()) = std::move(*node);
    }
  }
  return Status::OK();
}

bool ConstantFolding::IsSimplifiableReshape( const NodeDef& node, const GraphProperties& properties) const {
  if (!IsReshape(node)) {
    return false;
  }
  CHECK_LE(2, node.input_size());
  const NodeDef* new_shape = node_map_->GetNode(node.input(1));
  if (!IsReallyConstant(*new_shape)) {
    return false;
  }
  TensorVector outputs;
  auto outputs_cleanup = gtl::MakeCleanup([&outputs] {
    for (const auto& output : outputs) {
      delete output.tensor;
    }
  });

  Status s = EvaluateNode(*new_shape, TensorVector(), &outputs);
  if (!s.ok()) {
    return false;
  }
  CHECK_EQ(1, outputs.size());

  const std::vector<OpInfo::TensorProperties>& props = properties.GetInputProperties(node.name());
  if (props.empty()) {
    return false;
  }
  const OpInfo::TensorProperties& prop = props[0];
  if (prop.dtype() == DT_INVALID) {
    return false;
  }
  const PartialTensorShape shape(prop.shape());
  if (!shape.IsFullyDefined()) {
    return false;
  }

  PartialTensorShape new_dims;
  if (outputs[0]->dtype() == DT_INT32) {
    std::vector<int32> shp;
    for (int i = 0; i < outputs[0]->NumElements(); ++i) {
      int32_t dim = outputs[0]->flat<int32>()(i);
      shp.push_back(dim);
    }
    TF_CHECK_OK(TensorShapeUtils::MakeShape(shp, &new_dims));
  } else {
    std::vector<int64_t> shp;
    for (int i = 0; i < outputs[0]->NumElements(); ++i) {
      int64_t dim = outputs[0]->flat<int64_t>()(i);
      shp.push_back(dim);
    }
    TF_CHECK_OK(TensorShapeUtils::MakeShape(shp, &new_dims));
  }

  return shape.IsCompatibleWith(new_dims);
}








bool ConstantFolding::IsOnes(const NodeDef& node) const {
  if (feed_nodes_.find(node.name()) != feed_nodes_.end()) {
    return false;
  }
  if (IsOnesLike(node)) return true;
  if (IsZerosLike(node)) return false;
  if (node.op() == "Fill") {
    NodeDef* values = node_map_->GetNode(NodeName(node.input(1)));
    return values != nullptr && IsOnes(*values);
  }
  if (node.op() != "Const") return false;
  if (node.attr().count("dtype") == 0) return false;
  const auto dtype = node.attr().at("dtype").type();
  switch (dtype) {
    IS_ONES_CASE(DT_BOOL);
    IS_ONES_CASE(DT_HALF);
    IS_ONES_CASE(DT_BFLOAT16);
    IS_ONES_CASE(DT_FLOAT);
    IS_ONES_CASE(DT_DOUBLE);
    IS_ONES_CASE(DT_COMPLEX64);
    IS_ONES_CASE(DT_COMPLEX128);
    IS_ONES_CASE(DT_UINT8);
    IS_ONES_CASE(DT_INT8);
    IS_ONES_CASE(DT_UINT16);
    IS_ONES_CASE(DT_INT16);
    IS_ONES_CASE(DT_INT32);
    IS_ONES_CASE(DT_INT64);
    IS_ONES_CASE(DT_QINT32);
    IS_ONES_CASE(DT_QINT16);
    IS_ONES_CASE(DT_QUINT16);
    IS_ONES_CASE(DT_QINT8);
    IS_ONES_CASE(DT_QUINT8);
    default:
      VLOG(1) << "Unsupported type " << DataTypeString(dtype);
      return false;
  }
  return false;
}

bool ConstantFolding::IsZeros(const NodeDef& node) const {
  if (feed_nodes_.find(node.name()) != feed_nodes_.end()) {
    return false;
  }
  if (IsOnesLike(node)) return false;
  if (IsZerosLike(node)) return true;
  if (node.op() == "Fill") {
    NodeDef* values = node_map_->GetNode(NodeName(node.input(1)));
    return values != nullptr && IsZeros(*values);
  }
  if (!IsConstant(node)) return false;
  if (node.attr().count("dtype") == 0) return false;
  const auto dtype = node.attr().at("dtype").type();
  switch (dtype) {
    IS_ZEROS_CASE(DT_BOOL);
    IS_ZEROS_CASE(DT_HALF);
    IS_ZEROS_CASE(DT_BFLOAT16);
    IS_ZEROS_CASE(DT_FLOAT);
    IS_ZEROS_CASE(DT_DOUBLE);
    IS_ZEROS_CASE(DT_COMPLEX64);
    IS_ZEROS_CASE(DT_COMPLEX128);
    IS_ZEROS_CASE(DT_UINT8);
    IS_ZEROS_CASE(DT_INT8);
    IS_ZEROS_CASE(DT_UINT16);
    IS_ZEROS_CASE(DT_INT16);
    IS_ZEROS_CASE(DT_INT32);
    IS_ZEROS_CASE(DT_INT64);
    IS_ZEROS_CASE(DT_QINT32);
    IS_ZEROS_CASE(DT_QINT16);
    IS_ZEROS_CASE(DT_QUINT16);
    IS_ZEROS_CASE(DT_QINT8);
    IS_ZEROS_CASE(DT_QUINT8);
    default:
      VLOG(1) << "Unsupported type " << DataTypeString(dtype);
      return false;
  }
  return false;
}

bool ConstantFolding::ReplaceOperationWithBroadcastTo( int input_to_broadcast, const GraphProperties& properties, NodeDef* node, GraphDef* graph) {

  const DataType dtype = GetDataTypeFromNodeOrProps(*node, properties);
  if (dtype == DT_INVALID) {
    return false;
  }
  const PartialTensorShape shape( properties.GetOutputProperties(node->name())[0].shape());
  if (!shape.IsFullyDefined()) {
    return false;
  }
  
  const string const_name = OptimizedNodeName( *node, strings::StrCat("-broadcastto_shape-", input_to_broadcast));
  if (node_map_->GetNode(const_name) != nullptr) {
    return false;
  }

  Tensor shape_t;
  if (!ConvertShapeToConstant("Shape", DT_INT32, shape, &shape_t).ok()) {
    return false;
  }
  NodeDef tmp;
  if (!CreateNodeDef(const_name, TensorValue(&shape_t), &tmp).ok()) {
    return false;
  }
  NodeDef* const_node = graph->add_node();
  const_node->Swap(&tmp);
  const_node->set_device(node->device());
  node_map_->AddNode(const_name, const_node);
  for (int i = 0; i < node->input_size(); ++i) {
    if (i != input_to_broadcast) {
      
      string ctrl_dep = AddControlDependency(NodeName(node->input(i)), graph, node_map_.get());
      *const_node->add_input() = ctrl_dep;
      node_map_->AddOutput(NodeName(ctrl_dep), const_name);
    }
  }

  
  node->set_op("BroadcastTo");
  EraseRegularNodeAttributes(node);
  (*node->mutable_attr())["T"].set_type(dtype);
  (*node->mutable_attr())["Tidx"].set_type(DT_INT32);
  
  node->mutable_input()->SwapElements(0, input_to_broadcast);
  
  for (int i = 1; i < node->input_size(); ++i) {
    if (IsControlInput(node->input(i))) {
      break;
    }
    const string ctrl_dep = AddControlDependency(node->input(i), graph, node_map_.get());
    node_map_->UpdateInput(node->name(), node->input(i), ctrl_dep);
    node->set_input(i, ctrl_dep);
  }
  
  *node->add_input() = const_node->name();
  node_map_->AddOutput(const_name, node->name());
  node->mutable_input()->SwapElements(1, node->input_size() - 1);
  return true;
}


void ConstantFolding::ReplaceOperationWithIdentity( int input_to_forward, const GraphProperties& properties, NodeDef* node, GraphDef* graph) {

  if (input_to_forward < 0 || input_to_forward >= node->input_size()) return;
  const DataType dtype = GetDataTypeFromNodeOrProps(*node, properties);
  if (dtype == DT_INVALID) return;

  node->set_op("Identity");
  EraseRegularNodeAttributes(node);
  (*node->mutable_attr())["T"].set_type(dtype);
  
  node->mutable_input()->SwapElements(0, input_to_forward);
  
  for (int i = 1; i < node->input_size(); ++i) {
    if (IsControlInput(node->input(i))) {
      break;
    }
    const string ctrl_dep = AddControlDependency(node->input(i), graph, node_map_.get());
    node_map_->UpdateInput(node->name(), node->input(i), ctrl_dep);
    node->set_input(i, ctrl_dep);
  }
  graph_modified_ = true;
}

void ConstantFolding::ReplaceOperationWithSnapshot( int input_to_forward, const GraphProperties& properties, NodeDef* node, GraphDef* graph) {

  
  
  if (!graph_contains_assign_or_inplace_op_) {
    ReplaceOperationWithIdentity(input_to_forward, properties, node, graph);
    return;
  }

  const DataType dtype = GetDataTypeFromNodeOrProps(*node, properties);
  if (dtype == DT_INVALID) return;

  node->set_op("Snapshot");
  EraseRegularNodeAttributes(node);
  (*node->mutable_attr())["T"].set_type(dtype);
  
  node->mutable_input()->SwapElements(0, input_to_forward);
  
  for (int i = 1; i < node->input_size(); ++i) {
    if (IsControlInput(node->input(i))) {
      break;
    }
    const string ctrl_dep = AddControlDependency(node->input(i), graph, node_map_.get());
    node_map_->UpdateInput(node->name(), node->input(i), ctrl_dep);
    node->set_input(i, ctrl_dep);
  }
  graph_modified_ = true;
}



void ConstantFolding::ReplaceOperationWithNoOp(NodeDef* node, GraphProperties* properties, GraphDef* graph) {

  if (HasRegularOutputs(*node, *node_map_)) return;
  node->set_op("NoOp");
  EraseRegularNodeAttributes(node);
  EraseNodeOutputAttributes(node);
  
  properties->ClearOutputProperties(node->name());
  
  for (int i = 0; i < node->input_size(); ++i) {
    if (IsControlInput(node->input(i))) {
      break;
    }
    const string ctrl_dep = AddControlDependency(node->input(i), graph, node_map_.get());
    node_map_->UpdateInput(node->name(), node->input(i), ctrl_dep);
    node->set_input(i, ctrl_dep);
  }
  DedupControlInputs(node);
  graph_modified_ = true;
}

void ConstantFolding::ReplaceBinaryOperationWithBroadcastTo( int input_to_broadcast, const GraphProperties& properties, NodeDef* node, GraphDef* graph) {

  if (!ReplaceOperationWithBroadcastTo(input_to_broadcast, properties, node, graph)) {
    return;
  }
  graph_modified_ = true;
}

void ConstantFolding::ReplaceDivisionOfOnesByReciprocal(NodeDef* node, GraphDef* graph) {
  node->set_op("Reciprocal");
  node->mutable_input()->SwapElements(0, 1);
  const string ctrl_dep = AddControlDependency(node->input(1), graph, node_map_.get());
  node_map_->UpdateInput(node->name(), node->input(1), ctrl_dep);
  node->set_input(1, ctrl_dep);
  graph_modified_ = true;
}

void ConstantFolding::ReplaceSubtractionFromZeroByNegation(NodeDef* node, GraphDef* graph) {
  node->set_op("Neg");
  node->mutable_input()->SwapElements(0, 1);
  const string ctrl_dep = AddControlDependency(node->input(1), graph, node_map_.get());
  node_map_->UpdateInput(node->name(), node->input(1), ctrl_dep);
  node->set_input(1, ctrl_dep);
  graph_modified_ = true;
}

Status ConstantFolding::ReplaceOperationWithConstantTensor(DataType dtype, TensorProto* value, NodeDef* node, GraphDef* graph) {


  if (dtype == DT_VARIANT) return Status::OK();
  node->set_op("Const");
  EraseRegularNodeAttributes(node);
  (*node->mutable_attr())["dtype"].set_type(dtype);
  (*node->mutable_attr())["value"].mutable_tensor()->Swap(value);
  
  for (int i = 0; i < node->input_size(); ++i) {
    if (IsControlInput(node->input(i))) {
      break;
    }
    const string ctrl_dep = AddControlDependency(node->input(i), graph, node_map_.get());
    node_map_->UpdateInput(node->name(), node->input(i), ctrl_dep);
    node->set_input(i, ctrl_dep);
  }
  DedupControlInputs(node);
  graph_modified_ = true;
  return Status::OK();
}

Status ConstantFolding::ReplaceOperationWithConstant( double value, const GraphProperties& properties, const TensorShapeProto& shape, NodeDef* node, GraphDef* graph) {

  const DataType dtype = GetDataTypeFromNodeOrProps(*node, properties);
  if (dtype == DT_VARIANT) return Status::OK();
  AttrValue tensor_attr;
  Status s = CreateConstantTensorAttrValue(dtype, value, shape, &tensor_attr);
  if (!s.ok()) {
    
    VLOG(1) << "Failed to replace node " << node->name() << " of type " << DataTypeString(dtype) << " with constant tensor of value " << value;

    return Status::OK();
  }
  return ReplaceOperationWithConstantTensor(dtype, tensor_attr.mutable_tensor(), node, graph);
}

Status ConstantFolding::SimplifyGraph( GraphDef* optimized_graph, GraphProperties* properties, absl::flat_hash_set<string>* nodes_to_not_simplify) {

  for (int i = 0; i < optimized_graph->node_size(); ++i) {
    NodeDef* node = optimized_graph->mutable_node(i);
    
    
    if (nodes_to_not_simplify->find(node->name()) == nodes_to_not_simplify->end()) {
      if (HasTPUAttributes(*node)) {
        nodes_to_not_simplify->insert(node->name());
        continue;
      }

      TF_RETURN_IF_ERROR(SimplifyNode(node, optimized_graph, properties));
    }
  }
  return Status::OK();
}










Status ConstantFolding::SimplifyNode(NodeDef* node, GraphDef* optimized_graph, GraphProperties* properties) {
  bool graph_modified_cached = graph_modified_;
  graph_modified_ = false;

  bool use_shape_info = properties->has_properties();
  RETURN_IF_MODIFIED(RemoveSplitOrSplitV(*properties, optimized_graph, node));
  RETURN_IF_ERROR_OR_MODIFIED(RemoveShuffleOrTranspose( *properties, use_shape_info, optimized_graph, node));
  RETURN_IF_MODIFIED( RemoveRandomShuffle(*properties, use_shape_info, optimized_graph, node));
  RETURN_IF_ERROR_OR_MODIFIED( RemoveReverse(*properties, use_shape_info, optimized_graph, node));
  RETURN_IF_ERROR_OR_MODIFIED( SimplifySlice(*properties, use_shape_info, optimized_graph, node));
  RETURN_IF_ERROR_OR_MODIFIED( SimplifyStridedSlice(*properties, use_shape_info, optimized_graph, node));
  RETURN_IF_ERROR_OR_MODIFIED( SimplifyTile(*properties, use_shape_info, optimized_graph, node));
  RETURN_IF_ERROR_OR_MODIFIED( SimplifyPad(*properties, use_shape_info, optimized_graph, node));
  RETURN_IF_MODIFIED( SimplifySqueeze(*properties, use_shape_info, optimized_graph, node));
  SET_AND_RETURN_IF_MODIFIED(SimplifyPack(optimized_graph, node));
  SET_AND_RETURN_IF_MODIFIED(MoveConstantsPastEnter(optimized_graph, node));
  SET_AND_RETURN_IF_MODIFIED(SimplifySwitch(optimized_graph, node));
  SET_AND_RETURN_IF_MODIFIED( SimplifyReduction(optimized_graph, *properties, node));
  SET_AND_RETURN_IF_MODIFIED( SimplifyReshape(*properties, use_shape_info, node));
  RETURN_IF_ERROR_OR_MODIFIED(SimplifyArithmeticOperations( *properties, use_shape_info, optimized_graph, node));
  SET_AND_RETURN_IF_MODIFIED(ReduceDivToReciprocalMul(optimized_graph, node));
  SET_AND_RETURN_IF_MODIFIED( ConstantPushDown(properties, optimized_graph, node));
  SET_AND_RETURN_IF_MODIFIED( MulConvPushDown(optimized_graph, node, *properties));
  SET_AND_RETURN_IF_MODIFIED(PartialConstPropThroughIdentityN(node));
  SET_AND_RETURN_IF_MODIFIED( PartialAssocOpConstFolding(optimized_graph, properties, node));
  SET_AND_RETURN_IF_MODIFIED( MergeConcat(use_shape_info, properties, optimized_graph, node));
  SET_AND_RETURN_IF_MODIFIED( PartialConcatConstFolding(optimized_graph, properties, node));
  SET_AND_RETURN_IF_MODIFIED( ConstantPushDownBiasAdd(properties, optimized_graph, node));
  SET_AND_RETURN_IF_MODIFIED(SimplifyCase(optimized_graph, node));
  SET_AND_RETURN_IF_MODIFIED( SimplifySelect(*properties, optimized_graph, node));
  RETURN_IF_MODIFIED( RemoveRedundantVariableUpdates(properties, optimized_graph, node));

  graph_modified_ = graph_modified_cached;
  return Status::OK();
}

void ConstantFolding::RemoveSplitOrSplitV(const GraphProperties& properties, GraphDef* optimized_graph, NodeDef* node) {

  if (node->attr().count("num_split") == 0) return;
  if (IsSplit(*node) && node->attr().at("num_split").i() == 1) {
    ReplaceOperationWithIdentity(1, properties, node, optimized_graph);
  }
  if (IsSplitV(*node) && node->attr().at("num_split").i() == 1) {
    ReplaceOperationWithIdentity(0, properties, node, optimized_graph);
  }
}

Status ConstantFolding::RemoveShuffleOrTranspose( const GraphProperties& properties, bool use_shape_info, GraphDef* optimized_graph, NodeDef* node) {

  if (!use_shape_info || !(IsShuffle(*node) || IsTranspose(*node)))
    return Status::OK();
  Tensor permutation_tensor;
  if (GetTensorFromConstNode(node->input(1), &permutation_tensor) && properties.HasInputProperties(node->name())) {
    const auto& shape = properties.GetInputProperties(node->name())[0].shape();
    std::vector<int> permutation;
    for (int j = 0; j < permutation_tensor.NumElements(); ++j) {
      if (permutation_tensor.dtype() == DT_INT64) {
        permutation.push_back(permutation_tensor.vec<int64_t>()(j));
      } else {
        permutation.push_back(permutation_tensor.vec<int>()(j));
      }
    }
    int permutation_size = permutation.size();
    if (permutation_size != shape.dim_size()) {
      
      return Status::OK();
    }
    
    
    
    bool replaceable = true;
    for (int j = 0; replaceable && j < shape.dim_size(); ++j) {
      replaceable &= shape.dim(j).size() == 1 || j == permutation[j];
    }
    if (replaceable) {
      ReplaceOperationWithIdentity(0, properties, node, optimized_graph);
    }
  }
  return Status::OK();
}

void ConstantFolding::RemoveRandomShuffle(const GraphProperties& properties, bool use_shape_info, GraphDef* optimized_graph, NodeDef* node) {


  if (use_shape_info && IsRandomShuffle(*node) && !properties.GetInputProperties(node->name()).empty()) {
    const auto& shape = properties.GetInputProperties(node->name())[0].shape();
    
    
    if (!shape.unknown_rank() && (shape.dim_size() == 0 || shape.dim(0).size() == 1)) {
      ReplaceOperationWithIdentity(0, properties, node, optimized_graph);
    }
  }
}

Status ConstantFolding::RemoveReverse(const GraphProperties& properties, bool use_shape_info, GraphDef* optimized_graph, NodeDef* node) {


  if (!use_shape_info || node->op() != "ReverseV2") return Status::OK();
  Tensor axis;
  if (properties.HasInputProperties(node->name()) && GetTensorFromConstNode(node->input(1), &axis)) {
    const auto& shape = properties.GetInputProperties(node->name())[0].shape();
    if (shape.unknown_rank()) return Status::OK();
    std::set<int> target_axes;
    for (int j = 0; j < axis.NumElements(); ++j) {
      
      if (axis.dtype() == DT_INT64) {
        target_axes.insert((axis.vec<int64_t>()(j) + shape.dim_size()) % shape.dim_size());
      } else {
        target_axes.insert((axis.vec<int>()(j) + shape.dim_size()) % shape.dim_size());
      }
    }

    
    
    
    
    bool replaceable = true;
    for (int j = 0; replaceable && j < shape.dim_size(); ++j) {
      replaceable &= shape.dim(j).size() == 1 || target_axes.find(j) == target_axes.end();
    }
    if (replaceable) {
      ReplaceOperationWithIdentity(0, properties, node, optimized_graph);
    }
  }
  return Status::OK();
}

Status ConstantFolding::SimplifySlice(const GraphProperties& properties, bool use_shape_info, GraphDef* optimized_graph, NodeDef* node) {


  if (!use_shape_info || !IsSlice(*node)) return Status::OK();
  Tensor begin;
  Tensor size;
  if (properties.HasInputProperties(node->name()) && GetTensorFromConstNode(node->input(1), &begin) && GetTensorFromConstNode(node->input(2), &size)) {

    const auto& input = properties.GetInputProperties(node->name())[0];
    
    
    bool replaceable = !input.shape().unknown_rank();
    for (int j = 0; replaceable && j < input.shape().dim_size(); ++j) {
      if (begin.dtype() == DT_INT32) {
        replaceable &= begin.vec<int>()(j) == 0;
      } else {
        replaceable &= begin.vec<int64_t>()(j) == 0;
      }
      if (size.dtype() == DT_INT32) {
        replaceable &= (size.vec<int>()(j) == -1 || size.vec<int>()(j) == input.shape().dim(j).size());
      } else {
        replaceable &= (size.vec<int64_t>()(j) == -1 || size.vec<int64_t>()(j) == input.shape().dim(j).size());
      }
    }
    if (replaceable) {
      ReplaceOperationWithIdentity(0, properties, node, optimized_graph);
    }
  }
  return Status::OK();
}

Status ConstantFolding::SimplifyStridedSlice(const GraphProperties& properties, bool use_shape_info, GraphDef* optimized_graph, NodeDef* node) {


  if (use_shape_info && IsStridedSlice(*node) && properties.GetInputProperties(node->name()).size() == 4) {
    TF_RETURN_IF_ERROR( CheckAttrsExist(*node, {"new_axis_mask", "shrink_axis_mask"));
    if (node->attr().at("new_axis_mask").i() != 0 || node->attr().at("shrink_axis_mask").i() != 0) {
      
      
      return Status::OK();
    }
    const auto& input = properties.GetInputProperties(node->name())[0];
    for (int j = 0; j < input.shape().dim_size(); ++j) {
      
      if (input.shape().dim(j).size() < 0) {
        return Status::OK();
      }
    }

    std::vector<Tensor> input_tensors(3);
    for (int i = 1; i < 4; ++i) {
      if (!GetTensorFromConstNode(node->input(i), &input_tensors[i - 1])) {
        return Status::OK();
      }
    }

    const Tensor& begin = input_tensors[0];
    const Tensor& end = input_tensors[1];
    const Tensor& strides = input_tensors[2];

    TF_RETURN_IF_ERROR( CheckAttrsExist(*node, {"begin_mask", "end_mask", "ellipsis_mask"));
    int begin_mask = node->attr().at("begin_mask").i();
    int end_mask = node->attr().at("end_mask").i();
    std::set<int> expanded_ellipsis_indices;
    int ellipsis_index = -1;
    for (int j = 0; j < input.shape().dim_size(); ++j) {
      
      
      if (node->attr().at("ellipsis_mask").i() & 1 << j || (ellipsis_index == -1 && j >= strides.NumElements())) {
        ellipsis_index = j;
      }
      
      
      if (ellipsis_index != -1 && input.shape().dim_size() > strides.NumElements() + j - ellipsis_index) {

        expanded_ellipsis_indices.insert(j);
      }
    }

    
    
    
    bool replaceable = !input.shape().unknown_rank();
    for (int j = 0; replaceable && j < input.shape().dim_size(); ++j) {
      if (expanded_ellipsis_indices.find(j) != expanded_ellipsis_indices.end()) {
        
        continue;
      }
      
      
      
      
      int i = j;
      int expanded_ellipsis_indices_size = expanded_ellipsis_indices.size();
      if (ellipsis_index != -1 && j >= ellipsis_index + expanded_ellipsis_indices_size) {
        i = j - expanded_ellipsis_indices_size;
      }
      int b = begin.dtype() == DT_INT32 ? begin.vec<int>()(i)
                                        : begin.vec<int64_t>()(i);
      int e = end.dtype() == DT_INT32 ? end.vec<int>()(i) : end.vec<int64_t>()(i);
      int s = strides.dtype() == DT_INT32 ? strides.vec<int>()(i)
                                          : strides.vec<int64_t>()(i);
      replaceable &= (begin_mask & 1 << i || b == 0) && (end_mask & 1 << i || e == input.shape().dim(j).size()) && s == 1;

    }
    if (replaceable) {
      ReplaceOperationWithIdentity(0, properties, node, optimized_graph);
    }
  }
  return Status::OK();
}

Status ConstantFolding::SimplifyTile(const GraphProperties& properties, bool use_shape_info, GraphDef* optimized_graph, NodeDef* node) {

  Tensor multiplies;
  if (use_shape_info && IsTile(*node) && GetTensorFromConstNode(node->input(1), &multiplies)) {
    
    bool replaceable = true;
    if (multiplies.dtype() == DT_INT32) {
      for (int j = 0; replaceable && j < multiplies.vec<int>().size(); ++j) {
        replaceable &= multiplies.vec<int>()(j) == 1;
      }
    } else {
      for (int j = 0; replaceable && j < multiplies.vec<int64_t>().size();
           ++j) {
        replaceable &= multiplies.vec<int64_t>()(j) == 1;
      }
    }
    if (replaceable) {
      ReplaceOperationWithIdentity(0, properties, node, optimized_graph);
    }
  }
  return Status::OK();
}

Status ConstantFolding::SimplifyPad(const GraphProperties& properties, bool use_shape_info, GraphDef* optimized_graph, NodeDef* node) {

  if (!use_shape_info || !IsPad(*node)) return Status::OK();

  Tensor paddings;
  if (GetTensorFromConstNode(node->input(1), &paddings)) {
    
    bool replaceable = true;
    if (paddings.dtype() == DT_INT32) {
      const auto flatten = paddings.flat<int32>();
      for (int j = 0; replaceable && j < flatten.size(); ++j) {
        replaceable &= flatten(j) == 0;
      }
    } else {
      const auto flatten = paddings.flat<int64_t>();
      for (int j = 0; replaceable && j < flatten.size(); ++j) {
        replaceable &= flatten(j) == 0;
      }
    }
    if (replaceable) {
      ReplaceOperationWithIdentity(0, properties, node, optimized_graph);
    }
  }
  return Status::OK();
}

void ConstantFolding::SimplifySqueeze(const GraphProperties& properties, bool use_shape_info, GraphDef* optimized_graph, NodeDef* node) {


  if (use_shape_info && IsSqueeze(*node) && !properties.GetInputProperties(node->name()).empty()) {
    
    
    
    const auto& shape = properties.GetInputProperties(node->name())[0].shape();
    
    
    bool replaceable = !shape.unknown_rank();
    for (int j = 0; replaceable && j < shape.dim_size(); ++j) {
      replaceable &= shape.dim(j).size() > 1;
    }
    if (replaceable) {
      ReplaceOperationWithIdentity(0, properties, node, optimized_graph);
    }
  }
}

bool ConstantFolding::SimplifyPack(GraphDef* optimized_graph, NodeDef* node) {
  const string axis_node_name = OptimizedNodeName(*node, "_const_axis");
  if (!IsPack(*node) || NumNonControlInputs(*node) != 1 || node_map_->NodeExists(axis_node_name)) {
    return false;
  }

  
  
  if (feed_nodes_.find(NodeName(node->input(0))) != feed_nodes_.end()) {
    return false;
  }

  
  Tensor axis_t(DT_INT32, TensorShape({}));
  const int axis = node->attr().count("axis") == 0 ? 0 : node->attr().at("axis").i();
  NodeDef new_node;
  if (!SetTensorValue(DT_INT32, axis, &axis_t).ok() || !CreateNodeDef(axis_node_name, TensorValue(&axis_t), &new_node).ok()) {
    return false;
  }
  NodeDef* axis_node = optimized_graph->add_node();
  *axis_node = std::move(new_node);
  axis_node->set_name(axis_node_name);
  node_map_->AddNode(axis_node->name(), axis_node);
  
  const string ctrl_dep = ConstantFolding::AddControlDependency( node->input(0), optimized_graph, node_map_.get());
  axis_node->add_input(ctrl_dep);
  axis_node->set_device(node->device());
  node_map_->AddOutput(NodeName(node->input(0)), axis_node->name());
  node->set_op("ExpandDims");
  if (node->attr().count("axis") != 0) {
    node->mutable_attr()->erase("axis");
  }
  if (node->attr().count("N") != 0) {
    node->mutable_attr()->erase("N");
  }
  (*node->mutable_attr())["Tdim"].set_type(DT_INT32);
  node->add_input(axis_node->name());
  node_map_->AddOutput(axis_node->name(), node->name());
  if (node->input_size() > 2) {
    node->mutable_input()->SwapElements(1, node->input_size() - 1);
  }
  return true;
}

bool ConstantFolding::SimplifyCase(GraphDef* optimized_graph, NodeDef* node) {
  if (node->op() != "Case") return false;
  const NodeDef* output_idx_node = node_map_->GetNode(node->input(0));
  if (output_idx_node == nullptr || !CheckAttrExists(*output_idx_node, "value").ok()) {
    return false;
  }
  Tensor output_idx_t;
  if (!output_idx_t.FromProto(output_idx_node->attr().at("value").tensor()))
    return false;
  int output_idx = output_idx_t.scalar<int>()();
  const auto& func_list = node->attr().at("branches").list();
  if (output_idx < 0 || output_idx >= func_list.func_size()) return false;
  NodeDef call_node = *node;
  call_node.set_op("PartitionedCall");
  call_node.clear_input();
  for (int i = 1; i < node->input_size(); ++i) {
    call_node.add_input(node->input(i));
  }
  auto* new_func = (*call_node.mutable_attr())["f"].mutable_func();
  *new_func = func_list.func(output_idx);

  
  const auto& output_shape_list = (*node->mutable_attr())["output_shapes"].list();
  if (output_shape_list.shape_size() > output_idx) {
    TensorShapeProto* new_output_shape = (*call_node.mutable_attr())["_output_shapes"] .mutable_list()

            ->add_shape();
    *new_output_shape = std::move(node->attr().at("output_shapes").list().shape(output_idx));
  }

  call_node.mutable_attr()->erase("output_shapes");
  call_node.mutable_attr()->erase("branches");

  *node = std::move(call_node);
  return true;
}

bool ConstantFolding::SimplifySelect(const GraphProperties& properties, GraphDef* optimized_graph, NodeDef* node) {
  if (!IsSelect(*node)) return false;
  const std::vector<OpInfo::TensorProperties>& input_props = properties.GetInputProperties(node->name());
  if (input_props.size() < 3) return false;
  const NodeDef* predicate_node = node_map_->GetNode(node->input(0));
  const bool is_all_true = IsOnes(*predicate_node);
  const bool is_all_false = IsZeros(*predicate_node);
  if (!is_all_true && !is_all_false) {
    return false;
  }
  const int live_input_idx = is_all_true ? 1 : 2;
  const int ignored_input_idx = is_all_true ? 2 : 1;
  const TensorShapeProto& predicate_shape = input_props[0].shape();
  const bool predicate_is_scalar = !predicate_shape.unknown_rank() && predicate_shape.dim_size() == 0;
  if (ShapesSymbolicallyEqual(input_props[1], input_props[2]) && (ShapesSymbolicallyEqual(input_props[0], input_props[1]) || predicate_is_scalar)) {

    
    node->set_op("Identity");
    *node->mutable_input(0) = AddControlDependency(node->input(0), optimized_graph, node_map_.get());
    *node->mutable_input(ignored_input_idx) = AddControlDependency( node->input(ignored_input_idx), optimized_graph, node_map_.get());
    node->mutable_input()->SwapElements(0, live_input_idx);
  } else if (!ReplaceOperationWithBroadcastTo(live_input_idx, properties, node, optimized_graph)) {
    return false;
  }
  DedupControlInputs(node);
  return true;
}

void ConstantFolding::RemoveRedundantVariableUpdates( GraphProperties* properties, GraphDef* optimized_graph, NodeDef* node) {
  static const absl::flat_hash_set<string>* kVariableReadOps = new absl::flat_hash_set<string>{"AssignAddVariableOp", "AssignSubVariableOp", "AssignAdd", "AssignSub", "ScatterAdd", "ScatterSub", "ScatterMul", "ScatterDiv", "ScatterNdAdd", "ScatterNdSub", "ScatterNdMul", "ScatterNdDiv", "ResourceScatterAdd", "ResourceScatterSub", "ResourceScatterMul", "ResourceScatterDiv", "ResourceScatterNdAdd", "ResourceScatterNdSub", "ResourceScatterNdMul", "ResourceScatterNdDiv";



















  if (kVariableReadOps == nullptr || kVariableReadOps->find(node->op()) == kVariableReadOps->end())
    return;
  const int value_index = absl::StrContains(node->op(), "Scatter") ? 2 : 1;
  const NodeDef* delta_node = node_map_->GetNode(node->input(value_index));
  if (delta_node == nullptr) return;
  const bool is_add_or_sub = absl::StrContains(node->op(), "Add") || absl::StrContains(node->op(), "Sub");
  if ((is_add_or_sub && IsZeros(*delta_node)) || (!is_add_or_sub && IsOnes(*delta_node))) {
    VLOG(1) << "Removing redundant variable update: " << node->DebugString();
    if (absl::StrContains(node->op(), "Variable") || absl::StrContains(node->op(), "Resource")) {
      ReplaceOperationWithNoOp(node, properties, optimized_graph);
    } else {
      ReplaceOperationWithIdentity(0 , *properties, node, optimized_graph);
    }
  }
}

bool ConstantFolding::MoveConstantsPastEnter(GraphDef* optimized_graph, NodeDef* node) {
  if (!IsEnter(*node) || node->input_size() == 0 || node->attr().count("is_constant") == 0 || !node->attr().at("is_constant").b()) {

    return false;
  }
  const string& node_name = node->name();
  const NodeDef* input = node_map_->GetNode(node->input(0));
  if (input == nullptr || !IsReallyConstant(*input) || OptimizedNodeExists(*input, "_enter")) {
    return false;
  }
  
  std::vector<NodeDef*> consumers;
  for (const NodeDef* fanout : node_map_->GetOutputs(node_name)) {
    if (!IsConstant(*fanout)) {
      for (int i = 0; i < fanout->input_size(); ++i) {
        if (fanout->input(i) == node_name) {
          consumers.push_back(const_cast<NodeDef*>(fanout));
          break;
        }
      }
    }
  }
  if (consumers.empty()) {
    return false;
  }
  graph_modified_ = true;
  NodeDef* new_node = optimized_graph->add_node();
  *new_node = *input;
  new_node->set_name(OptimizedNodeName(*input, "_enter"));
  new_node->set_device(node->device());
  new_node->clear_input();
  new_node->add_input(AsControlDependency(node_name));
  node_map_->AddNode(new_node->name(), new_node);
  node_map_->AddOutput(node_name, new_node->name());
  for (NodeDef* consumer : consumers) {
    for (int i = 0; i < consumer->input_size(); ++i) {
      if (NodeName(consumer->input(i)) == node_name) {
        node_map_->UpdateInput(consumer->name(), node_name, new_node->name());
        consumer->set_input(i, new_node->name());
      }
    }
  }
  return true;
}

bool ConstantFolding::SimplifySwitch(GraphDef* optimized_graph, NodeDef* node) {
  if (node->op() == "Switch" && node->input(0) == node->input(1) && !OptimizedNodeExists(*node, "_const_false") && !OptimizedNodeExists(*node, "_const_true")) {

    bool already_optimized = true;
    
    
    
    const auto& fanouts = node_map_->GetOutputs(node->name());
    if (fanouts.size() == 2) {
      for (const NodeDef* fanout : fanouts) {
        if ((!IsIdentity(*fanout) && !IsIdentityNSingleInput(*fanout)) || HasRegularOutputs(*fanout, *node_map_)) {
          already_optimized = false;
          break;
        }
      }
    }
    Tensor false_t(DT_BOOL, TensorShape({}));
    Tensor true_t(DT_BOOL, TensorShape({}));
    
    if (!already_optimized && SetTensorValue(DT_BOOL, true, &true_t).ok() && SetTensorValue(DT_BOOL, false, &false_t).ok()) {
      
      
      std::vector<NodeDef*> consumers = node_map_->GetOutputsOrderedByNodeName(node->name());
      
      NodeDef tmp_false_node;
      tmp_false_node.set_name(OptimizedNodeName(*node, "_const_false"));
      if (!CreateNodeDef(tmp_false_node.name(), TensorValue(&false_t), &tmp_false_node)
               .ok()) {
        return false;
      }
      tmp_false_node.set_device(node->device());
      NodeDef tmp_true_node;
      tmp_true_node.set_name(OptimizedNodeName(*node, "_const_true"));
      if (!CreateNodeDef(tmp_true_node.name(), TensorValue(&true_t), &tmp_true_node)
               .ok()) {
        return false;
      }
      tmp_true_node.set_device(node->device());

      
      NodeDef* false_node = optimized_graph->add_node();
      false_node->Swap(&tmp_false_node);
      NodeDef* true_node = optimized_graph->add_node();
      true_node->Swap(&tmp_true_node);

      
      
      const string false_port = node->name();
      const string true_port = strings::StrCat(node->name(), ":1");
      const string false_ctrl_dep = AddControlDependency(false_port, optimized_graph, node_map_.get());
      false_node->add_input(false_ctrl_dep);
      const string true_ctrl_dep = AddControlDependency(true_port, optimized_graph, node_map_.get());
      true_node->add_input(true_ctrl_dep);

      node_map_->AddNode(false_node->name(), false_node);
      node_map_->AddNode(true_node->name(), true_node);
      node_map_->AddOutput(NodeName(false_ctrl_dep), false_node->name());
      node_map_->AddOutput(NodeName(true_ctrl_dep), true_node->name());

      for (NodeDef* consumer : consumers) {
        for (int i = 0; i < consumer->input_size(); ++i) {
          const string& input = consumer->input(i);
          if (input == false_port) {
            consumer->set_input(i, false_node->name());
            node_map_->UpdateInput(consumer->name(), false_port, false_node->name());
          } else if (input == true_port) {
            consumer->set_input(i, true_node->name());
            node_map_->UpdateInput(consumer->name(), true_port, true_node->name());
          }
        }
      }
      return true;
    }
  }
  return false;
}

bool ConstantFolding::IsReductionWithConstantIndices( const NodeDef& node, bool* indices_is_empty) const {
  
  if (!IsReduction(node) || node.input_size() < 2) {
    return false;
  }
  
  NodeDef* reductions_indices = node_map_->GetNode(node.input(1));
  if (!IsReallyConstant(*reductions_indices) || !reductions_indices->attr().count("value")) {
    return false;
  }
  const TensorShapeProto& reduction_indices_shape = reductions_indices->attr().at("value").tensor().tensor_shape();
  *indices_is_empty = TensorShape(reduction_indices_shape).num_elements() == 0;
  return true;
}

bool ConstantFolding::IsReductionCandidateForSimplification( const NodeDef& node, const GraphProperties& properties, TensorShapeProto* input_tensor_shape, TensorShapeProto* output_tensor_shape, bool* is_single_element_op) const {


  
  
  if (!properties.HasInputProperties(node.name()) || !properties.HasOutputProperties(node.name())) {
    return false;
  }
  const auto& input_props = properties.GetInputProperties(node.name())[0];
  const auto& output_props = properties.GetOutputProperties(node.name())[0];
  if (!input_props.has_shape() || input_props.shape().unknown_rank() || !output_props.has_shape() || output_props.shape().unknown_rank()) {
    return false;
  }
  *input_tensor_shape = input_props.shape();
  *output_tensor_shape = output_props.shape();
  for (int i = 0; i < input_tensor_shape->dim_size(); ++i) {
    if (input_tensor_shape->dim(i).size() < 0) {
      return false;
    }
  }
  for (int i = 0; i < output_tensor_shape->dim_size(); ++i) {
    if (output_tensor_shape->dim(i).size() < 0) {
      return false;
    }
  }
  const int input_num_elements = TensorShape(*input_tensor_shape).num_elements();
  const int output_num_elements = TensorShape(*output_tensor_shape).num_elements();
  *is_single_element_op = input_num_elements == 1 && output_num_elements == 1;

  return true;
}

bool ConstantFolding::IsReductionSimplifiableToIdentity( const NodeDef& node, const TensorShapeProto& input_shape, bool keep_dims, const TensorVector& reduction_indices_vector) const {

  int output_size = reduction_indices_vector[0]->NumElements();
  if (output_size == 0) {
    return true;
  }

  if (!keep_dims) {
    return false;
  }
  bool simplifiable = true;
  for (int i = 0; i < output_size; ++i) {
    int64_t dim;
    if (reduction_indices_vector[0]->dtype() == DT_INT32) {
      dim = reduction_indices_vector[0]->flat<int32>()(i);
    } else {
      dim = reduction_indices_vector[0]->flat<int64_t>()(i);
    }
    if (dim < 0) {
      dim += input_shape.dim_size();
    }
    if (dim < 0 || dim >= input_shape.dim_size() || input_shape.dim(dim).size() != 1) {
      simplifiable = false;
      break;
    }
  }
  return simplifiable;
}

bool ConstantFolding::ReplaceReductionWithIdentity(NodeDef* node) const {
  
  
  DataType output_type;
  if (node->attr().count("T") != 0) {
    output_type = node->attr().at("T").type();
  } else if (IsAny(*node) || IsAll(*node)) {
    output_type = DT_BOOL;
  } else {
    return false;
  }
  node->set_op("Identity");
  EraseRegularNodeAttributes(node);
  (*node->mutable_attr())["T"].set_type(output_type);
  *node->mutable_input(1) = AsControlDependency(node->input(1));
  return true;
}

bool ConstantFolding::SimplifyReduction(GraphDef* optimized_graph, const GraphProperties& properties, NodeDef* node) {

  bool indices_is_empty = false;
  if (!IsReductionWithConstantIndices(*node, &indices_is_empty)) {
    return false;
  }
  if (indices_is_empty) {
    return ReplaceReductionWithIdentity(node);
  }
  bool is_single_element_op = false;
  TensorShapeProto input_tensor_shape, output_tensor_shape;
  if (!IsReductionCandidateForSimplification( *node, properties, &input_tensor_shape, &output_tensor_shape, &is_single_element_op)) {

    return false;
  }

  
  string reduction_indices_input = node->input(1);
  NodeDef* reduction_indices = node_map_->GetNode(reduction_indices_input);
  TensorVector reduction_indices_vector;
  auto outputs_cleanup = gtl::MakeCleanup([&reduction_indices_vector] {
    for (const auto& out : reduction_indices_vector) {
      delete out.tensor;
    }
  });
  if (!EvaluateNode(*reduction_indices, TensorVector(), &reduction_indices_vector)
           .ok() || reduction_indices_vector.size() != 1) {
    return false;
  }

  bool keep_dims = node->attr().count("keep_dims") > 0 && node->attr().at("keep_dims").b();
  bool simplifiable_to_reshape = is_single_element_op && !keep_dims && (node->attr().count("T") > 0);
  bool simplifiable_to_identity = IsReductionSimplifiableToIdentity( *node, input_tensor_shape, keep_dims, reduction_indices_vector);

  if (simplifiable_to_reshape) {
    
    const int new_num_dimensions = output_tensor_shape.dim_size();
    Tensor tensor(DT_INT32, TensorShape({new_num_dimensions}));
    for (int i = 0; i < new_num_dimensions; i++) {
      tensor.flat<int>()(i) = 1;
    }
    TensorValue shape_value(&tensor);
    NodeDef* shape_node = optimized_graph->add_node();
    if (!CreateNodeDef(OptimizedNodeName(*node, "_shape_const"), shape_value, shape_node)
             .ok()) {
      return false;
    }
    shape_node->set_device(node->device());
    node_map_->AddNode(shape_node->name(), shape_node);
    
    shape_node->add_input(AsControlDependency(reduction_indices_input));
    node_map_->AddOutput(NodeName(reduction_indices_input), shape_node->name());
    
    node->set_op("Reshape");
    node_map_->UpdateInput(node->name(), node->input(1), shape_node->name());
    node->set_input(1, shape_node->name());
    node->mutable_attr()->erase("keep_dims");
    node->mutable_attr()->erase("Tidx");
    AttrValue attr_type_indices;
    attr_type_indices.set_type(DT_INT32);
    (*node->mutable_attr())["Tshape"] = attr_type_indices;
    return true;
  } else if (simplifiable_to_identity) {
    return ReplaceReductionWithIdentity(node);
  }
  return false;
}

bool ConstantFolding::SimplifyReshape(const GraphProperties& properties, bool use_shape_info, NodeDef* node) {
  if (!use_shape_info || node->attr().count("T") == 0 || !IsSimplifiableReshape(*node, properties)) {
    return false;
  }
  DataType output_type = node->attr().at("T").type();
  node->set_op("Identity");
  EraseRegularNodeAttributes(node);
  (*node->mutable_attr())["T"].set_type(output_type);
  *node->mutable_input(1) = AsControlDependency(node->input(1));
  return true;
}

Status ConstantFolding::SimplifyArithmeticOperations( const GraphProperties& properties, bool use_shape_info, GraphDef* optimized_graph, NodeDef* node) {

  const bool is_mul = IsAnyMul(*node) || IsLogicalAnd(*node);
  const bool is_matmul = IsAnyMatMul(*node);
  const bool is_add = IsAdd(*node) || IsBiasAdd(*node) || IsLogicalOr(*node);
  const bool is_sub = IsSub(*node);
  const bool is_any_div = IsAnyDiv(*node) && !IsFloorDiv(*node);
  
  if (use_shape_info && (is_mul || is_matmul || is_add || is_sub || is_any_div) && properties.HasInputProperties(node->name()) && properties.HasOutputProperties(node->name())) {


    const NodeDef* x = node_map_->GetNode(node->input(0));
    const NodeDef* y = node_map_->GetNode(node->input(1));
    if (x == nullptr || y == nullptr) {
      return errors::InvalidArgument("Invalid inputs to node: ", node->DebugString());
    }
    const TensorShapeProto& output_shape = properties.GetOutputProperties(node->name())[0].shape();

    
    
    const TensorShapeProto& y_shape = properties.GetInputProperties(node->name())[1].shape();
    const TensorShapeProto& x_shape = properties.GetInputProperties(node->name())[0].shape();
    const bool y_matches_output_shape = ShapesSymbolicallyEqual(output_shape, y_shape);
    const bool x_matches_output_shape = ShapesSymbolicallyEqual(output_shape, x_shape);

    const bool x_is_zero = IsZeros(*x);
    const bool x_is_one = x_is_zero ? false : IsOnes(*x);
    if ((is_mul && x_is_one) || (is_add && x_is_zero)) {
      
      if (y_matches_output_shape) {
        ReplaceOperationWithSnapshot(1, properties, node, optimized_graph);
      } else if (x_matches_output_shape) {
        ReplaceBinaryOperationWithBroadcastTo(1, properties, node, optimized_graph);
      }
      return Status::OK();
    }

    if (y_matches_output_shape && (is_sub && x_is_zero)) {
      
      ReplaceSubtractionFromZeroByNegation(node, optimized_graph);
      return Status::OK();
    }

    
    if (y_matches_output_shape && is_any_div && x_is_one) {
      TF_RETURN_IF_ERROR(CheckAttrExists(*node, "T"));
      DataType type = node->attr().at("T").type();
      if (DataTypeIsFloating(type) || DataTypeIsComplex(type)) {
        ReplaceDivisionOfOnesByReciprocal(node, optimized_graph);
        return Status::OK();
      }
    }

    const bool y_is_zero = IsZeros(*y);
    const bool y_is_one = y_is_zero ? false : IsOnes(*y);
    if (((is_mul || is_any_div) && y_is_one) || ((is_add || is_sub) && y_is_zero)) {
      
      if (x_matches_output_shape) {
        ReplaceOperationWithSnapshot(0, properties, node, optimized_graph);
      } else if (y_matches_output_shape) {
        ReplaceBinaryOperationWithBroadcastTo(0, properties, node, optimized_graph);
      }
      return Status::OK();
    }

    
    const PartialTensorShape shp(output_shape);
    if (shp.IsFullyDefined() && IsLogicalOr(*node) && (y_is_one || x_is_one)) {
      TF_RETURN_IF_ERROR(ReplaceOperationWithConstant( 1, properties, output_shape, node, optimized_graph));
      return Status::OK();
    }

    
    
    
    const bool is_aggressive = opt_level_ == RewriterConfig::AGGRESSIVE;
    bool optimize_zeros_divided_by_y = is_any_div && x_is_zero && is_aggressive;
    if ((x_is_zero || y_is_zero) && (is_mul || is_matmul || optimize_zeros_divided_by_y)) {
      if (shp.IsFullyDefined()) {
        bool is_quantized = IsQuantizedMatMul(*node);
        TF_RETURN_IF_ERROR(ReplaceOperationWithConstant( 0, properties, output_shape, node, optimized_graph));
        if (is_quantized && graph_modified_) {
          TF_RETURN_IF_ERROR( AddQuantizedMatMulMinMaxOutConstNodes(node, optimized_graph));
        }
        return Status::OK();
      }
      
      
      
      if ((is_mul || is_any_div) && x_is_zero) {
        if (x_matches_output_shape) {
          ReplaceOperationWithIdentity(0, properties, node, optimized_graph);
        } else if (y_matches_output_shape) {
          ReplaceBinaryOperationWithBroadcastTo(0, properties, node, optimized_graph);
        }
        return Status::OK();
      } else if (is_mul && y_is_zero) {
        if (y_matches_output_shape) {
          ReplaceOperationWithIdentity(1, properties, node, optimized_graph);
        } else if (x_matches_output_shape) {
          ReplaceBinaryOperationWithBroadcastTo(1, properties, node, optimized_graph);
        }
        return Status::OK();
      }
    }
  }
  return Status::OK();
}

bool ConstantFolding::ReduceDivToReciprocalMul(GraphDef* optimized_graph, NodeDef* node) {
  
  
  
  if (node->input_size() >= 2 && (IsDiv(*node) || IsRealDiv(*node) || IsXdivy(*node))) {
    const string& const_input = node->input(1);
    const NodeDef* denom = node_map_->GetNode(const_input);
    CHECK(denom != nullptr);
    if (!IsReallyConstant(*denom)) {
      return false;
    }
    if (node->attr().count("T") == 0) {
      return false;
    }
    DataType type = node->attr().at("T").type();
    
    if (IsDiv(*node) && !(DataTypeIsFloating(type) || DataTypeIsComplex(type))) {
      return false;
    }
    
    NodeDef* reciprocal_node = optimized_graph->add_node();
    reciprocal_node->set_name(OptimizedNodeName(*node, "_recip"));
    reciprocal_node->set_op("Reciprocal");
    reciprocal_node->set_device(node->device());
    reciprocal_node->add_input(const_input);
    (*reciprocal_node->mutable_attr())["T"].set_type(type);

    
    if (IsXdivy(*node)) {
      node->set_op("MulNoNan");
      node->set_input(1, node->input(0));
      node->set_input(0, reciprocal_node->name());
    } else {
      node->set_op("Mul");
      node->set_input(1, reciprocal_node->name());
    }
    node_map_->AddNode(reciprocal_node->name(), reciprocal_node);
    node_map_->UpdateOutput(node->name(), const_input, reciprocal_node->name());

    return true;
  }

  return false;
}

bool ConstantFolding::PrepareConstantPushDown( const NodeDef& parent, const GraphProperties& properties, bool must_have_properties, ConstantPushDownContext* ctx) const {

  if (ctx == nullptr || !has_fetch_ || NumNonControlInputs(parent) != 2) {
    return false;
  }
  NodeDef* left_child = node_map_->GetNode(parent.input(0));
  NodeDef* right_child = node_map_->GetNode(parent.input(1));

  
  if (left_child == nullptr || right_child == nullptr) {
    return false;
  }

  ctx->left_child_is_const = IsReallyConstant(*left_child);
  ctx->right_child_is_const = IsReallyConstant(*right_child);
  ctx->op_child = ctx->left_child_is_const ? right_child : left_child;
  ctx->const_child = ctx->left_child_is_const ? left_child : right_child;

  
  if (!ctx->left_child_is_const && !ctx->right_child_is_const) {
    return false;
  }

  
  if (parent.device() != ctx->op_child->device() || parent.device() != ctx->const_child->device()) {
    return false;
  }

  
  if (ctx->op_child->input_size() < 2 || nodes_to_preserve_.find(ctx->op_child->name()) != nodes_to_preserve_.end() || NumNonControlOutputs(*ctx->op_child, *node_map_) > 1) {


    return false;
  }

  
  
  if (!CheckAttrExists(parent, "T").ok()) return false;
  DataType dtype = parent.attr().at("T").type();
  if (dtype == DT_BFLOAT16 || dtype == DT_HALF) {
    return false;
  }

  
  
  const auto& child_output = node_map_->GetOutputs(ctx->op_child->name());
  if (child_output.find(ctx->const_child) != child_output.end()) {
    return false;
  }

  
  ctx->left_leaf = node_map_->GetNode(ctx->op_child->input(0));
  ctx->right_leaf = node_map_->GetNode(ctx->op_child->input(1));
  ctx->left_leaf_is_const = IsReallyConstant(*ctx->left_leaf);
  ctx->right_leaf_is_const = IsReallyConstant(*ctx->right_leaf);

  if (ctx->left_leaf_is_const && ctx->right_leaf_is_const) {
    
    return false;
  }

  
  if (parent.device() != ctx->left_leaf->device() || parent.device() != ctx->right_leaf->device()) {
    return false;
  }

  
  ctx->parent_input_props = &properties.GetInputProperties(parent.name());
  ctx->op_child_input_props = &properties.GetInputProperties(ctx->op_child->name());
  if (must_have_properties && (ctx->parent_input_props == nullptr || ctx->parent_input_props->size() < 2 || ctx->op_child_input_props == nullptr || ctx->op_child_input_props->size() < 2)) {


    return false;
  }

  VLOG(1) << "\n++++++++ PushDown for node " << parent.name() << ": " << parent.op() << "(" << left_child->op() << ", " << right_child->op()
          << ")";

  return true;
}

bool ConstantFolding::ConstantPushDownBiasAdd(GraphProperties* properties, GraphDef* optimized_graph, NodeDef* node) {

  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  

  const bool parent_is_bias_add = IsBiasAdd(*node);
  if (!parent_is_bias_add && !IsAdd(*node)) return false;
  ConstantPushDownContext ctx;
  if (!PrepareConstantPushDown(*node, *properties, true, &ctx)) {
    return false;
  }
  
  
  if (ctx.left_child_is_const && parent_is_bias_add) return false;
  const bool child_is_bias_add = IsBiasAdd(*ctx.op_child);
  if (!child_is_bias_add && !IsAdd(*ctx.op_child)) return false;

  
  if (ctx.parent_input_props->empty() || ctx.op_child_input_props->empty() || (*ctx.parent_input_props)[0].shape().unknown_rank() || (*ctx.parent_input_props)[1].shape().unknown_rank() || (*ctx.op_child_input_props)[0].shape().unknown_rank() || (*ctx.op_child_input_props)[1].shape().unknown_rank()) {



    return false;
  }

  
  const int left_leaf_rank = (*ctx.op_child_input_props)[0].shape().dim_size();
  const int right_leaf_rank = (*ctx.op_child_input_props)[1].shape().dim_size();
  
  if (left_leaf_rank != 1 && right_leaf_rank != 1) return false;
  const int vector_idx = left_leaf_rank == 1 ? 0 : 1;
  const int matrix_idx = 1 - vector_idx;

  const auto& vector_prop = (*ctx.op_child_input_props)[vector_idx];
  const int vector_rank = vector_idx == 0 ? left_leaf_rank : right_leaf_rank;
  if (vector_rank != 1) return false;  
  const DataType vector_type = vector_prop.dtype();

  const auto& matrix_prop = (*ctx.op_child_input_props)[matrix_idx];
  const int matrix_rank = matrix_prop.shape().dim_size();
  const DataType matrix_type = matrix_prop.dtype();

  const int const_idx = ctx.left_child_is_const ? 0 : 1;
  const auto& const_prop = (*ctx.parent_input_props)[const_idx];
  const int const_rank = const_prop.shape().dim_size();
  const DataType const_type = const_prop.dtype();

  int input_to_swap = -1;

  if (!parent_is_bias_add && child_is_bias_add && const_rank == matrix_rank && const_type == matrix_type) {
    
    input_to_swap = matrix_idx;
  } else if (const_rank == 1 && const_type == vector_type) {
    
    input_to_swap = vector_idx;
  }
  if (input_to_swap == -1) return false;
  const NodeDef* leaf_to_swap = node_map_->GetNode(ctx.op_child->input(input_to_swap));
  if (IsConstant(*leaf_to_swap)) return false;

  node_map_->UpdateInput(node->name(), node->input(const_idx), ctx.op_child->input(input_to_swap));
  node_map_->AddOutput(node->input(const_idx), ctx.op_child->name());
  if (ctx.op_child->input(input_to_swap) != ctx.op_child->input(1 - input_to_swap)) {
    node_map_->RemoveOutput(ctx.op_child->input(input_to_swap), ctx.op_child->name());
  }
  std::swap(*node->mutable_input(const_idx), *ctx.op_child->mutable_input(input_to_swap));
  properties->ClearInputProperties(node->name());
  properties->ClearInputProperties(ctx.op_child->name());

  return true;
}

bool ConstantFolding::ConstantPushDown(GraphProperties* properties, GraphDef* optimized_graph, NodeDef* node) {

  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  

  
  const bool is_add = IsAdd(*node);
  const bool is_mul = IsMul(*node);
  const bool is_sub = IsSub(*node);
  const bool is_div = IsDiv(*node);
  if (!(is_add || is_sub || is_mul || is_div)) return false;
  const bool is_symmetric = is_add || is_mul;

  ConstantPushDownContext ctx;
  if (!PrepareConstantPushDown(*node, *properties, false, &ctx)) {
    return false;
  }

  
  const bool is_child_add = IsAdd(*ctx.op_child);
  const bool is_child_mul = IsMul(*ctx.op_child);
  const bool is_child_sub = IsSub(*ctx.op_child);
  const bool is_child_div = IsDiv(*ctx.op_child);
  const bool is_add_sub = (is_add || is_sub) && (is_child_add || is_child_sub);
  const bool is_mul_div = (is_mul || is_div) && (is_child_mul || is_child_div);
  if (!is_add_sub && !is_mul_div) {
    return false;
  }
  const bool is_child_symmetric = is_child_add || is_child_mul;

  if (!CheckAttrExists(*node, "T").ok()) return false;
  DataType dtype = node->attr().at("T").type();
  if (!(is_symmetric && is_child_symmetric) && !(DataTypeIsFloating(dtype) || DataTypeIsComplex(dtype))) {
    return false;
  }

  const NodeDef* y_node = ctx.left_leaf_is_const ? ctx.left_leaf : ctx.right_leaf;
  if (!IsReallyConstant(*y_node) && !ctx.parent_input_props->empty() && !ctx.op_child_input_props->empty()) {
    
    
    
    const PartialTensorShape c_shape( (*ctx.parent_input_props)[ctx.left_child_is_const ? 0 : 1].shape());
    const PartialTensorShape x_shape( (*ctx.op_child_input_props)[ctx.left_leaf_is_const ? 0 : 1].shape());

    if (c_shape.IsFullyDefined() && x_shape.IsFullyDefined() && c_shape.num_elements() > x_shape.num_elements()) {
      return false;
    } else if (!c_shape.unknown_rank() && !x_shape.unknown_rank() && c_shape.dims() > 0) {
      for (int idx = 0; idx < std::min(x_shape.dims(), c_shape.dims()); ++idx) {
        if (x_shape.dim_size(idx) >= 0 && c_shape.dim_size(idx) > x_shape.dim_size(idx)) {
          return false;
        }
      }
    }
  }

  
  const string input_x = ctx.left_leaf_is_const ? ctx.op_child->input(1) : ctx.op_child->input(0);
  const string input_y = input_x == ctx.op_child->input(0)
                             ? ctx.op_child->input(1)
                             : ctx.op_child->input(0);
  const string input_c = ctx.left_child_is_const ? node->input(0) : node->input(1);
  const string input_op = ctx.left_child_is_const ? node->input(1) : node->input(0);
  VLOG(1) << "input_c = " << input_c << "\ninput_x = " << input_x;

  
  node_map_->UpdateInput(node->name(), input_c, input_x);
  node_map_->AddOutput(input_c, ctx.op_child->name());
  if (input_x != input_y) {
    node_map_->RemoveOutput(input_x, ctx.op_child->name());
  }
  properties->ClearInputProperties(node->name());
  properties->ClearInputProperties(ctx.op_child->name());

  if (is_symmetric && is_child_symmetric) {
    
    
    
    
    
    
    node->set_input(0, input_x);
    node->set_input(1, input_op);
    ctx.op_child->set_input(0, input_c);
    ctx.op_child->set_input(1, input_y);
  } else {
    
    
    
    
    
    
    
    
    
    
    
    
    
    

    
    
    auto is_leaf_negated = [&](const bool is_right_leaf) -> bool {
      bool leaf_negated = !is_child_symmetric && is_right_leaf;
      bool child_negated = !is_symmetric && (ctx.left_child_is_const);
      return leaf_negated != child_negated;
    };
    const string symmetric_op = (is_add || is_sub) ? "Add" : "Mul";
    const string nonsymmetric_op = (is_add || is_sub) ? "Sub" : "Div";
    bool neg_c = !is_symmetric && !ctx.left_child_is_const;
    bool neg_x = is_leaf_negated(ctx.left_leaf_is_const);
    bool neg_y = is_leaf_negated(!ctx.left_leaf_is_const);
    
    node->set_op((neg_x || (neg_c && neg_y)) ? nonsymmetric_op : symmetric_op);
    node->set_input(0, neg_x ? input_op : input_x);
    node->set_input(1, neg_x ? input_x : input_op);
    
    ctx.op_child->set_op(neg_c != neg_y ? nonsymmetric_op : symmetric_op);
    ctx.op_child->set_input(0, neg_c ? input_y : input_c);
    ctx.op_child->set_input(1, neg_c ? input_c : input_y);
  }
  return true;
}

bool ConstantFolding::MulConvPushDown(GraphDef* optimized_graph, NodeDef* node, const GraphProperties& properties) {
  
  
  
  
  
  
  
  
  
  

  if (!IsAnyMul(*node) || NumNonControlInputs(*node) != 2) return false;

  NodeDef* mul_left_child = node_map_->GetNode(node->input(0));
  NodeDef* mul_right_child = node_map_->GetNode(node->input(1));
  
  const bool left_child_is_constant = IsReallyConstant(*mul_left_child);
  const bool right_child_is_constant = IsReallyConstant(*mul_right_child);
  if (!left_child_is_constant && !right_child_is_constant) {
    return false;
  }
  NodeDef* conv_node = left_child_is_constant ? mul_right_child : mul_left_child;
  if (!IsConv2D(*conv_node) && !IsConv3D(*conv_node)) {
    return false;
  }
  if (node->device() != mul_left_child->device() || node->device() != mul_right_child->device()) {
    return false;
  }

  
  
  if (conv_node->input_size() < 2 || NumNonControlOutputs(*conv_node, *node_map_) > 1 || nodes_to_preserve_.find(conv_node->name()) != nodes_to_preserve_.end()) {

    return false;
  }

  
  NodeDef* conv_left_child = node_map_->GetNode(conv_node->input(0));
  NodeDef* conv_right_child = node_map_->GetNode(conv_node->input(1));
  const bool conv_left_is_constant = IsReallyConstant(*conv_left_child);
  const bool conv_right_is_constant = IsReallyConstant(*conv_right_child);
  if (!conv_left_is_constant && !conv_right_is_constant) {
    
    return false;
  }
  if (conv_left_is_constant && conv_right_is_constant) {
    
    return false;
  }
  const auto& mul_props = properties.GetOutputProperties(node->name());
  const auto& conv_props = properties.GetOutputProperties(conv_node->name());
  if (mul_props.empty() || conv_props.empty()) {
    return false;
  }
  const auto& mul_shape = mul_props[0].shape();
  const auto& conv_shape = conv_props[0].shape();
  if (!ShapesSymbolicallyEqual(mul_shape, conv_shape)) {
    return false;
  }

  const auto& input_props = properties.GetInputProperties(conv_node->name());
  if (input_props.size() < 2) {
    return false;
  }
  const auto& filter_shape = input_props[1].shape();

  NodeDef* const_node = left_child_is_constant ? mul_left_child : mul_right_child;
  const auto& const_props = properties.GetOutputProperties(const_node->name());
  if (const_props.empty()) {
    return false;
  }
  const auto& const_shape = const_props[0].shape();
  if (!IsValidConstShapeForMulConvPushDown( conv_node->attr().at("data_format").s(), filter_shape, const_shape)) {
    return false;
  }

  string mul_new_name = AddPrefixToNodeName("merged_input", conv_node->name());
  if (node_map_->NodeExists(mul_new_name)) {
    return false;
  }
  
  
  string conv_const_input = conv_left_is_constant ? conv_node->input(0) : conv_node->input(1);
  if (MaybeRemoveControlInput(conv_node->name(), const_node, optimized_graph, node_map_.get())) {
    
    MaybeAddControlInput(conv_const_input, const_node, optimized_graph, node_map_.get());
  }

  conv_node->set_name(node->name());
  node->set_name(mul_new_name);
  if (conv_left_is_constant) {
    node_map_->UpdateInput(conv_node->name(), node->input(0), mul_new_name);
    conv_node->set_input(0, mul_new_name);
  } else {
    node_map_->UpdateInput(conv_node->name(), node->input(1), mul_new_name);
    conv_node->set_input(1, mul_new_name);
  }
  NodeDef* conv_const_node = conv_left_is_constant ? conv_left_child : conv_right_child;
  if (left_child_is_constant) {
    node->set_input(1, conv_const_node->name());
  } else {
    node->set_input(0, conv_const_node->name());
  }
  node_map_->AddNode(mul_new_name, node);

  return true;
}

bool ConstantFolding::PartialConstPropThroughIdentityN(NodeDef* node) {
  
  if (!(IsIdentityN(*node) || IsIdentityNSingleInput(*node)) || !HasRegularInputs(*node))
    return false;

  std::vector<int> inputs_to_forward;
  for (int input_idx = 0; input_idx < node->input_size(); ++input_idx) {
    const string& input = node->input(input_idx);
    if (IsControlInput(input)) {
      return false;
    }
    const NodeDef* input_node = node_map_->GetNode(NodeName(input));
    if (input_node == nullptr) {
      LOG(ERROR) << "Bad input: " << input;
      return false;
    }
    
    
    if (IsReallyConstant(*input_node)) {
      inputs_to_forward.push_back(input_idx);
    }
  }
  return ForwardInputs(node, inputs_to_forward);
}

bool ConstantFolding::PartialAssocOpConstFolding(GraphDef* optimized_graph, GraphProperties* properties, NodeDef* node) {

  
  
  
  
  
  if (!IsAggregate(*node) || !IsCommutative(*node)) return false;

  const int num_non_control_inputs = NumNonControlInputs(*node);
  if (num_non_control_inputs <= 2) return false;
  const int num_control_inputs = node->input_size() - num_non_control_inputs;
  std::vector<int> const_inputs;
  std::vector<int> nonconst_inputs;
  for (int i = 0; i < node->input_size(); ++i) {
    const string& input = node->input(i);
    const NodeDef* input_node = node_map_->GetNode(NodeName(input));
    if (input_node == nullptr) return false;
    if (!IsControlInput(input) && IsReallyConstant(*input_node)) {
      const_inputs.push_back(i);
    } else {
      
      nonconst_inputs.push_back(i);
    }
  }
  
  
  int const_inputs_size = const_inputs.size();
  if (const_inputs_size == num_non_control_inputs && node->op() == "AccumulateNV2") {
    node->set_op("AddN");
    node->mutable_attr()->erase("shape");
    return true;
  }
  const string new_node_name = OptimizedNodeName( *node, strings::StrCat("_partial_split_", const_inputs_size));
  if (const_inputs_size > 1 && const_inputs_size < num_non_control_inputs && !node_map_->NodeExists(new_node_name)) {
    NodeDef* added_node = optimized_graph->add_node();
    *added_node = *node;
    
    
    added_node->set_op("AddN");
    added_node->mutable_attr()->erase("shape");
    added_node->set_name(new_node_name);
    node_map_->AddNode(added_node->name(), added_node);
    added_node->clear_input();
    for (int i : const_inputs) {
      added_node->add_input(node->input(i));
      node_map_->UpdateOutput(NodeName(node->input(i)), node->name(), added_node->name());
    }

    
    node->set_input(const_inputs[0], added_node->name());
    node_map_->AddOutput(added_node->name(), node->name());
    nonconst_inputs.push_back(const_inputs[0]);
    
    std::sort(nonconst_inputs.begin(), nonconst_inputs.end());
    int idx = 0;
    for (int i : nonconst_inputs) {
      if (idx != i) {
        node->set_input(idx, node->input(i));
      }
      ++idx;
    }
    node->mutable_input()->DeleteSubrange(nonconst_inputs.size(), const_inputs.size() - 1);
    (*node->mutable_attr())["N"].set_i(node->input_size() - num_control_inputs);
    properties->ClearInputProperties(node->name());
    (*added_node->mutable_attr())["N"].set_i(const_inputs.size());
    return true;
  }
  return false;
}

bool ConstantFolding::PartialConcatConstFolding(GraphDef* optimized_graph, GraphProperties* properties, NodeDef* node) {

  
  
  
  if (!IsConcat(*node) || node->name().rfind("_partial_split_") != string::npos) {
    return false;
  }
  const int num_non_control_inputs = NumNonControlInputs(*node);
  if (num_non_control_inputs <= 3) return false;
  int axis_arg = -1;
  int begin = 0;
  int end = num_non_control_inputs;
  if (node->op() == "Concat") {
    begin = 1;
    axis_arg = 0;
  } else if (node->op() == "ConcatV2") {
    end = num_non_control_inputs - 1;
    axis_arg = num_non_control_inputs - 1;
  } else {
    return false;
  }

  
  
  std::vector<std::pair<int, int>> constant_input_runs;
  int first = begin;
  int last = begin;
  while (last < end) {
    while (first < end && !IsReallyConstant(*node_map_->GetNode( NodeName(node->input(first))))) {
      ++first;
    }
    
    last = first + 1;
    while (last < end && IsReallyConstant(*node_map_->GetNode(NodeName(node->input(last))))) {
      ++last;
    }
    
    
    if (first < end && (last - first) > 1) {
      constant_input_runs.emplace_back(first, last);
    }
    first = last;
  }

  
  if (constant_input_runs.empty() || (constant_input_runs.size() == 1 && constant_input_runs[0].first == begin && constant_input_runs[0].second == end)) {

    return false;
  }
  std::set<int> inputs_to_delete;
  for (auto interval : constant_input_runs) {
    
    
    string new_node_name = OptimizedNodeName(*node, "_partial_split");
    do {
      new_node_name += strings::StrCat("_", interval.first);
    } while (node_map_->NodeExists(new_node_name));

    NodeDef* added_node = optimized_graph->add_node();
    *added_node = *node;
    added_node->set_op("ConcatV2");
    added_node->set_name(new_node_name);
    node_map_->AddNode(added_node->name(), added_node);
    added_node->clear_input();
    for (int i = interval.first; i < interval.second; ++i) {
      added_node->add_input(node->input(i));
      node_map_->UpdateInput(node->name(), node->input(i), added_node->name());
      if (i != interval.first) {
        inputs_to_delete.insert(i);
      }
    }
    added_node->add_input(node->input(axis_arg));
    (*added_node->mutable_attr())["N"].set_i(interval.second - interval.first);
    node_map_->AddOutput(NodeName(node->input(axis_arg)), added_node->name());

    
    
    node->set_input(interval.first, added_node->name());
  }
  if (!inputs_to_delete.empty()) {
    
    protobuf::RepeatedPtrField<string> tmp;
    tmp.Swap(node->mutable_input());
    for (int i = 0; i < tmp.size(); ++i) {
      if (inputs_to_delete.find(i) == inputs_to_delete.end()) {
        node->add_input(tmp.Get(i));
      }
    }
    (*node->mutable_attr())["N"].set_i(node->input_size() - 1);
    properties->ClearInputProperties(node->name());
  }
  return true;
}

bool ConstantFolding::GetConcatAxis(const NodeDef& node, int* axis) {
  if (node.op() != "ConcatV2") {
    return false;
  }
  int axis_idx = node.input_size() - 1;
  while (axis_idx > 0 && IsControlInput(node.input(axis_idx))) {
    --axis_idx;
  }
  if (axis_idx <= 0) {
    return false;
  }
  Tensor axis_tensor;
  if (!GetTensorFromConstNode(node.input(axis_idx), &axis_tensor)) {
    return false;
  }
  *axis = axis_tensor.dtype() == DT_INT64 ? static_cast<int>(axis_tensor.scalar<int64_t>()())
              : axis_tensor.scalar<int32>()();
  return true;
}

bool ConstantFolding::MergeConcat(bool use_shape_info, GraphProperties* properties, GraphDef* optimized_graph, NodeDef* node) {

  
  int axis;
  if (!use_shape_info || !GetConcatAxis(*node, &axis) || nodes_to_preserve_.find(node->name()) != nodes_to_preserve_.end() || node_map_->GetOutputs(node->name()).size() != 1) {

    return false;
  }

  
  const int num_regular_inputs = NumNonControlInputs(*node);
  bool all_inputs_are_const = true;
  for (int i = 0; i < num_regular_inputs - 1; ++i) {
    const NodeDef* input_node = node_map_->GetNode(node->input(i));
    if (!IsReallyConstant(*input_node)) {
      all_inputs_are_const = false;
      break;
    }
  }
  if (all_inputs_are_const) return false;

  NodeDef* parent = *node_map_->GetOutputs(node->name()).begin();
  int parent_axis;
  if (!GetConcatAxis(*parent, &parent_axis) || axis != parent_axis) {
    return false;
  }

  
  
  
  
  string task, device;
  absl::flat_hash_set<string> unique_input_tasks;
  const int n_parent_inputs = NumNonControlInputs(*parent);
  
  
  
  for (int i = 0; i < n_parent_inputs - 1; ++i) {
    const NodeDef* input_node = node_map_->GetNode(parent->input(i));
    if (!input_node->device().empty() && tensorflow::DeviceNameUtils::SplitDeviceName(input_node->device(), &task, &device)) {

      unique_input_tasks.insert(task);
      if (unique_input_tasks.size() >= 2) {
        
        
        return false;
      }
    }
  }

  protobuf::RepeatedPtrField<string> parent_inputs;
  parent_inputs.Swap(parent->mutable_input());
  
  
  for (const auto& input : parent_inputs) {
    if (IsSameInput(input, node->name())) {
      for (int j = 0; j < num_regular_inputs - 1; ++j) {
        
        
        parent->add_input(node->input(j));
        node_map_->UpdateInput(parent->name(), node->name(), node->input(j));
      }
    } else {
      parent->add_input(input);
    }
  }
  
  const int num_inputs = node->input_size();
  for (int i = num_inputs - 1; i >= num_regular_inputs; --i) {
    parent->add_input(node->input(i));
    node_map_->UpdateInput(parent->name(), node->name(), node->input(i));
    node->mutable_input()->RemoveLast();
  }
  (*parent->mutable_attr())["N"].set_i(NumNonControlInputs(*parent) - 1);
  DedupControlInputs(parent);
  ReplaceOperationWithNoOp(node, properties, optimized_graph);

  return true;
}

Status ConstantFolding::AddQuantizedMatMulMinMaxOutConstNodes( NodeDef* node, GraphDef* optimized_graph) {
  auto add_quantized_out = [this, node, optimized_graph]( const string& out_const_name, int index) {
    NodeDef* out_node = optimized_graph->add_node();
    graph_modified_ = true;
    Tensor value(DT_FLOAT, TensorShape({}));
    const bool is_min = index == 1;
    const DataType type_attr = node->attr().at("dtype").type();

    value.flat<float>()(0) = is_min ? QuantizedTypeMinAsFloat(type_attr)
                                    : QuantizedTypeMaxAsFloat(type_attr);
    TF_RETURN_IF_ERROR( CreateNodeDef(out_const_name, TensorValue(&value), out_node));
    node_map_->AddNode(out_const_name, out_node);
    out_node->set_device(node->device());
    
    out_node->mutable_input()->CopyFrom(node->input());
    for (const string& input : out_node->input()) {
      node_map_->AddOutput(NodeName(input), out_const_name);
    }

    
    string old_input = absl::StrCat(node->name(), ":", index);
    int old_node_count = 0;
    
    auto outputs = node_map_->GetOutputs(node->name());
    for (const auto& output : outputs) {
      for (int i = 0; i < output->input_size(); ++i) {
        if (output->input(i) == old_input) {
          output->set_input(i, out_const_name);
          node_map_->AddOutput(out_const_name, output->name());
        } else if (NodeName(output->input(i)) == node->name()) {
          ++old_node_count;
        }
      }
      if (old_node_count == 0) {
        node_map_->RemoveOutput(node->name(), output->name());
      }
    }

    return Status::OK();
  };
  const string min_out_const_name = OptimizedNodeName(*node, "-quantized_matmul_min_out");
  const string max_out_const_name = OptimizedNodeName(*node, "-quantized_matmul_max_out");
  if (node_map_->GetNode(min_out_const_name) == nullptr && node_map_->GetNode(max_out_const_name) == nullptr) {
    TF_RETURN_IF_ERROR(add_quantized_out(min_out_const_name, 1));
    TF_RETURN_IF_ERROR(add_quantized_out(max_out_const_name, 2));
  } else {
    return errors::Internal(absl::Substitute( "Can't create Const for QuantizedMatMul min_out/max_out of " "node '$0' because of node name conflict", node->name()));


  }
  return Status::OK();
}

Status ConstantFolding::RunOptimizationPass(Cluster* cluster, GrapplerItem* item, GraphProperties* properties, GraphDef* optimized_graph) {


  optimized_graph->Clear();
  graph_ = &item->graph;
  node_map_.reset(new NodeMap(graph_));
  nodes_allowlist_.clear();
  
  
  
  
  
  
  
  for (const auto& fetch : item->fetch) {
    const NodeDef* fetch_node = node_map_->GetNode(fetch);
    if (fetch_node && NumOutputs(*fetch_node, graph_) == 1) {
      nodes_allowlist_.insert(fetch_node->name());
    }
  }

  absl::flat_hash_set<string> nodes_to_not_simplify;
  if (properties->has_properties()) {
    TF_RETURN_IF_ERROR(MaterializeShapes(*properties));
    TF_RETURN_IF_ERROR(MaterializeConstants(*properties));
    TF_RETURN_IF_ERROR( FoldGraph(*properties, optimized_graph, &nodes_to_not_simplify));
  } else {
    *optimized_graph = *graph_;
  }
  node_map_.reset(new NodeMap(optimized_graph));

  TF_RETURN_IF_ERROR( SimplifyGraph(optimized_graph, properties, &nodes_to_not_simplify));

  return Status::OK();
}

Status ConstantFolding::Optimize(Cluster* cluster, const GrapplerItem& item, GraphDef* optimized_graph) {
  
  
  port::ScopedFlushDenormal flush;
  port::ScopedSetRound round(FE_TONEAREST);
  nodes_to_preserve_ = item.NodesToPreserve();
  for (const auto& feed : item.feed) {
    feed_nodes_.insert(NodeName(feed.first));
  }

  if (cpu_device_ == nullptr) {
    owned_device_.reset(new DeviceSimple());
    cpu_device_ = owned_device_.get();
  }

  graph_contains_assign_or_inplace_op_ = false;
  for (const NodeDef& node : item.graph.node()) {
    if (ModifiesInputsInPlace(node) || HasRefInput(node)) {
      graph_contains_assign_or_inplace_op_ = true;
      break;
    }
  }

  has_fetch_ = !item.fetch.empty();
  GrapplerItem item_to_optimize = item;
  GraphProperties properties(item_to_optimize);
  
  
  
  const bool assume_valid_feeds = opt_level_ == RewriterConfig::AGGRESSIVE;
  if (!properties .InferStatically(assume_valid_feeds, false, false, true)



           .ok()) {
    properties.Clear();
  }

  *optimized_graph = GraphDef();
  item_to_optimize.graph.Swap(optimized_graph);
  int64_t node_count;

  do {
    GRAPPLER_RETURN_IF_DEADLINE_EXCEEDED();
    graph_modified_ = false;
    item_to_optimize.graph.Swap(optimized_graph);
    node_count = item_to_optimize.graph.node_size();
    TF_RETURN_IF_ERROR(RunOptimizationPass(cluster, &item_to_optimize, &properties, optimized_graph));
  } while (graph_modified_ || optimized_graph->node_size() != node_count);
  *optimized_graph->mutable_library() = item.graph.library();
  *optimized_graph->mutable_versions() = item.graph.versions();

  return Status::OK();
}

}  
}  
