












namespace tflite {
namespace ops {
namespace builtin {
namespace while_kernel {

namespace {










template <typename SrcVector, typename DstVector> TfLiteStatus CopyTensorsShapeAndType(TfLiteContext* context, Subgraph* src_subgraph, const SrcVector& src_tensor_indices, Subgraph* dst_subgraph, const DstVector& dst_tensor_indices, bool resize_subgraph_inputs) {





  TF_LITE_ENSURE_EQ(context, src_tensor_indices.size(), dst_tensor_indices.size());
  for (int i = 0; i < src_tensor_indices.size(); ++i) {
    const TfLiteTensor* src_tensor = src_subgraph->tensor(src_tensor_indices[i]);

    TfLiteTensor* dst_tensor = dst_subgraph->tensor(dst_tensor_indices[i]);
    if (resize_subgraph_inputs) {
      std::vector<int> dims(src_tensor->dims->data, src_tensor->dims->data + src_tensor->dims->size);
      dst_subgraph->ResizeInputTensor(dst_tensor_indices[i], dims);
    } else {
      TF_LITE_ENSURE_OK( context, context->ResizeTensor(context, dst_tensor, TfLiteIntArrayCopy(src_tensor->dims)));

    }
    dst_tensor->type = src_tensor->type;
  }
  return kTfLiteOk;
}



template <typename SrcVector, typename DstVector> TfLiteStatus CopyTensorsData(TfLiteContext* context, Subgraph* src_subgraph, const SrcVector& src_tensor_indices, Subgraph* dst_subgraph, const DstVector& dst_tensor_indices) {



  TF_LITE_ENSURE_EQ(context, src_tensor_indices.size(), dst_tensor_indices.size());
  for (int i = 0; i < src_tensor_indices.size(); ++i) {
    const TfLiteTensor* src_tensor = src_subgraph->tensor(src_tensor_indices[i]);
    TfLiteTensor* dst_tensor = dst_subgraph->tensor(dst_tensor_indices[i]);
    if (IsDynamicTensor(dst_tensor)) {
      TfLiteTensorRealloc(src_tensor->bytes, dst_tensor);
    }
    TF_LITE_ENSURE_EQ(context, src_tensor->bytes, dst_tensor->bytes);
    memcpy(dst_tensor->data.raw, src_tensor->data.raw, src_tensor->bytes);
  }
  return kTfLiteOk;
}

TfLiteStatus CheckCondOutput(TfLiteContext* context, const TfLiteTensor* cond_output) {
  
  TF_LITE_ENSURE_TYPES_EQ(context, cond_output->type, kTfLiteBool);
  if (cond_output->dims->size == 0) {
    
    return kTfLiteOk;
  }
  
  TF_LITE_ENSURE_EQ(context, cond_output->dims->size, 1);
  TF_LITE_ENSURE_EQ(context, cond_output->dims->data[0], 1);
  return kTfLiteOk;
}

}  

struct OpData {
  int cond_subgraph_index;
  int body_subgraph_index;
  bool cond_has_dynamic_output_tensors;
  bool body_has_dynamic_output_tensors;
};

void* Init(TfLiteContext* context, const char* buffer, size_t length) {
  auto* op_data = new OpData;
  const auto* params = reinterpret_cast<const TfLiteWhileParams*>(buffer);
  op_data->cond_subgraph_index = params->cond_subgraph_index;
  op_data->body_subgraph_index = params->body_subgraph_index;
  op_data->cond_has_dynamic_output_tensors = false;
  op_data->body_has_dynamic_output_tensors = false;
  return op_data;
}

void Free(TfLiteContext* context, void* buffer) {
  delete reinterpret_cast<OpData*>(buffer);
}

TfLiteStatus Prepare(TfLiteContext* context, TfLiteNode* node) {
  OpData* op_data = reinterpret_cast<OpData*>(node->user_data);
  int num_inputs = node->inputs->size;
  
  TF_LITE_ENSURE_EQ(context, node->outputs->size, num_inputs);

  
  Subgraph* this_subgraph = reinterpret_cast<Subgraph*>(context->impl_);
  auto* subgraphs = this_subgraph->GetSubgraphs();
  TF_LITE_ENSURE(context, op_data->cond_subgraph_index < subgraphs->size());
  TF_LITE_ENSURE(context, op_data->body_subgraph_index < subgraphs->size());
  TF_LITE_ENSURE(context, op_data->cond_subgraph_index != op_data->body_subgraph_index);

  Subgraph* cond_subgraph = (*subgraphs)[op_data->cond_subgraph_index].get();
  Subgraph* body_subgraph = (*subgraphs)[op_data->body_subgraph_index].get();

  
  TF_LITE_ENSURE_EQ(context, cond_subgraph->inputs().size(), num_inputs);
  TF_LITE_ENSURE_EQ(context, cond_subgraph->outputs().size(), 1);

  
  TF_LITE_ENSURE_EQ(context, body_subgraph->inputs().size(), num_inputs);
  TF_LITE_ENSURE_EQ(context, body_subgraph->outputs().size(), num_inputs);

  
  TF_LITE_ENSURE_OK( context, CopyTensorsShapeAndType( context, this_subgraph, TfLiteIntArrayView(node->inputs), cond_subgraph, cond_subgraph->inputs(), true));


  TF_LITE_ENSURE_OK(context, cond_subgraph->AllocateTensors());
  TfLiteTensor* cond_output = cond_subgraph->tensor(cond_subgraph->outputs()[0]);
  
  
  
  if (IsDynamicTensor(cond_output)) {
    op_data->cond_has_dynamic_output_tensors = true;
  } else {
    TF_LITE_ENSURE_STATUS(CheckCondOutput(context, cond_output));
  }

  
  TF_LITE_ENSURE_OK( context, CopyTensorsShapeAndType( context, this_subgraph, TfLiteIntArrayView(node->inputs), body_subgraph, body_subgraph->inputs(), true));


  TF_LITE_ENSURE_OK(context, body_subgraph->AllocateTensors());
  if (body_subgraph->HasDynamicTensors()) {
    op_data->body_has_dynamic_output_tensors = true;
  } else {
    for (int i = 0; i < num_inputs; ++i) {
      TfLiteTensor* body_input = body_subgraph->tensor(body_subgraph->inputs()[i]);
      TfLiteTensor* body_output = body_subgraph->tensor(body_subgraph->outputs()[i]);
      TF_LITE_ENSURE_TYPES_EQ(context, body_input->type, body_output->type);

      TF_LITE_ENSURE(context, !IsDynamicTensor(body_output));
      if (!TfLiteIntArrayEqual(body_input->dims, body_output->dims)) {
        
        
        
        
        
        op_data->body_has_dynamic_output_tensors = true;
        break;
      }
    }
  }
  for (int i = 0; i < num_inputs; ++i) {
    TfLiteTensor* output;
    TF_LITE_ENSURE_OK(context, GetOutputSafe(context, node, i, &output));
    if (op_data->body_has_dynamic_output_tensors) {
      SetTensorToDynamic(output);
    } else {
      TfLiteTensor* body_output = body_subgraph->tensor(body_subgraph->outputs()[i]);
      TfLiteIntArray* output_size = TfLiteIntArrayCopy(body_output->dims);
      TF_LITE_ENSURE_OK(context, context->ResizeTensor(context, output, output_size));
    }
  }
  return kTfLiteOk;
}

TfLiteStatus Eval(TfLiteContext* context, TfLiteNode* node) {
  const OpData* op_data = reinterpret_cast<OpData*>(node->user_data);
  Subgraph* this_subgraph = reinterpret_cast<Subgraph*>(context->impl_);
  auto* subgraphs = this_subgraph->GetSubgraphs();
  Subgraph* cond_subgraph = (*subgraphs)[op_data->cond_subgraph_index].get();
  Subgraph* body_subgraph = (*subgraphs)[op_data->body_subgraph_index].get();

  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  

  if (op_data->body_has_dynamic_output_tensors) {
    
    
    TF_LITE_ENSURE_OK( context, CopyTensorsShapeAndType( context, this_subgraph, TfLiteIntArrayView(node->inputs), cond_subgraph, cond_subgraph->inputs(), true));


    TF_LITE_ENSURE_OK(context, cond_subgraph->AllocateTensors());
  }
  TF_LITE_ENSURE_OK( context, CopyTensorsData(context, this_subgraph, TfLiteIntArrayView(node->inputs), cond_subgraph, cond_subgraph->inputs()));



  while (true) {
    TF_LITE_ENSURE_OK(context, cond_subgraph->Invoke());
    int cond_subgraph_output_index = cond_subgraph->outputs()[0];
    cond_subgraph->EnsureTensorDataIsReadable(cond_subgraph_output_index);
    TfLiteTensor* cond_output = cond_subgraph->tensor(cond_subgraph_output_index);
    if (op_data->cond_has_dynamic_output_tensors) {
      TF_LITE_ENSURE_STATUS(CheckCondOutput(context, cond_output));
    }

    if (!cond_output->data.b[0]) {
      break;
    }
    if (op_data->body_has_dynamic_output_tensors) {
      TF_LITE_ENSURE_OK(context, CopyTensorsShapeAndType( context, cond_subgraph, cond_subgraph->inputs(), body_subgraph, body_subgraph->inputs(), true));


      TF_LITE_ENSURE_OK(context, body_subgraph->AllocateTensors());
    }

    TF_LITE_ENSURE_OK( context, CopyTensorsData(context, cond_subgraph, cond_subgraph->inputs(), body_subgraph, body_subgraph->inputs()));



    TF_LITE_ENSURE_OK(context, body_subgraph->Invoke());

    for (int tensor_index : body_subgraph->outputs()) {
      body_subgraph->EnsureTensorDataIsReadable(tensor_index);
    }

    if (op_data->body_has_dynamic_output_tensors) {
      TF_LITE_ENSURE_OK(context, CopyTensorsShapeAndType( context, body_subgraph, body_subgraph->outputs(), cond_subgraph, cond_subgraph->inputs(), true));


      TF_LITE_ENSURE_OK(context, cond_subgraph->AllocateTensors());
    }

    TF_LITE_ENSURE_OK( context, CopyTensorsData(context, body_subgraph, body_subgraph->outputs(), cond_subgraph, cond_subgraph->inputs()));


  }

  
  
  if (op_data->body_has_dynamic_output_tensors) {
    TF_LITE_ENSURE_OK( context, CopyTensorsShapeAndType( context, cond_subgraph, cond_subgraph->inputs(), this_subgraph, TfLiteIntArrayView(node->outputs), false));


  }

  TF_LITE_ENSURE_OK( context, CopyTensorsData(context, cond_subgraph, cond_subgraph->inputs(), this_subgraph, TfLiteIntArrayView(node->outputs)));


  return kTfLiteOk;
}

}  

TfLiteRegistration* Register_WHILE() {
  static TfLiteRegistration r = {while_kernel::Init, while_kernel::Free, while_kernel::Prepare, while_kernel::Eval};
  return &r;
}

}  
}  
}  
