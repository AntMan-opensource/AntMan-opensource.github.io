





















namespace tensorflow {

namespace {


void ValidateInputs(bool is_save_op, OpKernelContext* context, const Tensor& prefix, const Tensor& tensor_names, const Tensor& shape_and_slices) {

  const int kFixedInputs = 3;  
  const int num_tensors = static_cast<int>(tensor_names.NumElements());
  OP_REQUIRES( context, prefix.NumElements() == 1, errors::InvalidArgument("Input prefix should have a single element, got ", prefix.NumElements(), " instead."));


  OP_REQUIRES(context, TensorShapeUtils::IsVector(tensor_names.shape()) && TensorShapeUtils::IsVector(shape_and_slices.shape()), errors::InvalidArgument( "Input tensor_names and shape_and_slices " "should be an 1-D tensors, got ", tensor_names.shape().DebugString(), " and ", shape_and_slices.shape().DebugString(), " instead."));






  OP_REQUIRES(context, tensor_names.NumElements() == shape_and_slices.NumElements(), errors::InvalidArgument("tensor_names and shape_and_slices " "have different number of elements: ", tensor_names.NumElements(), " vs. ", shape_and_slices.NumElements()));




  OP_REQUIRES(context, FastBoundsCheck(tensor_names.NumElements() + kFixedInputs, std::numeric_limits<int>::max()), errors::InvalidArgument("Too many inputs to the op"));


  OP_REQUIRES( context, shape_and_slices.NumElements() == num_tensors, errors::InvalidArgument("Expected ", num_tensors, " elements in shapes_and_slices, but got ", context->input(2).NumElements()));



  if (is_save_op) {
    OP_REQUIRES(context, context->num_inputs() == num_tensors + kFixedInputs, errors::InvalidArgument( "Got ", num_tensors, " tensor names but ", context->num_inputs() - kFixedInputs, " tensors."));


    OP_REQUIRES(context, context->num_inputs() == num_tensors + kFixedInputs, errors::InvalidArgument( "Expected a total of ", num_tensors + kFixedInputs, " inputs as input #1 (which is a string " "tensor of saved names) contains ", num_tensors, " names, but received ", context->num_inputs(), " inputs"));





  }
}

}  


class SaveV2 : public OpKernel {
 public:
  explicit SaveV2(OpKernelConstruction* context) : OpKernel(context) {}

  void Compute(OpKernelContext* context) override {
    const Tensor& prefix = context->input(0);
    const Tensor& tensor_names = context->input(1);
    const Tensor& shape_and_slices = context->input(2);
    ValidateInputs(true , context, prefix, tensor_names, shape_and_slices);

    const int kFixedInputs = 3;  
    const int num_tensors = static_cast<int>(tensor_names.NumElements());
    const string& prefix_string = prefix.scalar<tstring>()();
    const auto& tensor_names_flat = tensor_names.flat<tstring>();
    const auto& shape_and_slices_flat = shape_and_slices.flat<tstring>();

    BundleWriter writer(Env::Default(), prefix_string);
    OP_REQUIRES_OK(context, writer.status());
    VLOG(1) << "BundleWriter, prefix_string: " << prefix_string;

    for (int i = 0; i < num_tensors; ++i) {
      const string& tensor_name = tensor_names_flat(i);
      const Tensor& tensor = context->input(i + kFixedInputs);
      VLOG(2) << "Starting save of " << tensor_name;

      if (!shape_and_slices_flat(i).empty()) {
        const string& shape_spec = shape_and_slices_flat(i);
        TensorShape shape;
        TensorSlice slice(tensor.dims());
        TensorShape slice_shape;

        OP_REQUIRES_OK(context, checkpoint::ParseShapeAndSlice( shape_spec, &shape, &slice, &slice_shape));
        OP_REQUIRES(context, slice_shape.IsSameSize(tensor.shape()), errors::InvalidArgument("Slice in shape_and_slice " "specification does not match the " "shape of the tensor to  save: ", shape_spec, ", tensor: ", tensor.shape().DebugString()));





        OP_REQUIRES_OK(context, writer.AddSlice(tensor_name, shape, slice, tensor));
      } else {
        OP_REQUIRES_OK(context, writer.Add(tensor_name, tensor));
      }

      if (VLOG_IS_ON(5)) {
        if (tensor.dtype() == DT_FLOAT) {
          const float* t_data = tensor.flat<float>().data();
          float min = std::numeric_limits<float>::infinity();
          float max = -std::numeric_limits<float>::infinity();
          double avg = 0.0;
          for (int i = 0; i < tensor.NumElements(); ++i) {
            if (t_data[i] < min) min = t_data[i];
            if (t_data[i] > max) max = t_data[i];
            avg += t_data[i];
          }
          VLOG(5) << " min " << min << " max " << max << " avg " << avg / tensor.NumElements() << " total elts " << tensor.NumElements();

        }
      }

      VLOG(2) << "Done save of " << tensor_name;
    }
    OP_REQUIRES_OK(context, writer.Finish());
    VLOG(1) << "Done BundleWriter, prefix_string: " << prefix_string;
  }
};
REGISTER_KERNEL_BUILDER(Name("SaveV2").Device(DEVICE_CPU), SaveV2);


class RestoreV2 : public OpKernel {
 public:
  explicit RestoreV2(OpKernelConstruction* context) : OpKernel(context) {
    OP_REQUIRES_OK(context, context->GetAttr("dtypes", &dtypes_));
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& prefix = context->input(0);
    const Tensor& tensor_names = context->input(1);
    const Tensor& shape_and_slices = context->input(2);
    OP_REQUIRES(context, tensor_names.NumElements() == dtypes_.size(), errors::InvalidArgument("Got ", tensor_names.NumElements(), " tensor names, but ", dtypes_.size(), " expected dtypes."));


    ValidateInputs(false , context, prefix, tensor_names, shape_and_slices);

    const string& prefix_string = prefix.scalar<tstring>()();

    
    
    
    
    Env* env = Env::Default();
    std::vector<string> paths;
    if (!env->GetMatchingPaths(MetaFilename(prefix_string), &paths).ok() || paths.empty()) {
      
      
      for (size_t i = 0; i < tensor_names.NumElements(); ++i) {
        RestoreTensor(context, &checkpoint::OpenTableTensorSliceReader, -1,  true, i);

        if (!context->status().ok()) {
          return;
        }
      }
      return;
    }
    
    OP_REQUIRES_OK(context, RestoreTensorsV2(context, prefix, tensor_names, shape_and_slices, dtypes_));
  }

 private:
  
  std::vector<DataType> dtypes_;
};
REGISTER_KERNEL_BUILDER(Name("RestoreV2").Device(DEVICE_CPU), RestoreV2);


class MergeV2Checkpoints : public OpKernel {
 public:
  explicit MergeV2Checkpoints(OpKernelConstruction* context)
      : OpKernel(context) {
    OP_REQUIRES_OK(context, context->GetAttr("delete_old_dirs", &delete_old_dirs_));
  }

  void Compute(OpKernelContext* context) override {
    const Tensor& checkpoint_prefixes = context->input(0);
    const Tensor& destination_prefix = context->input(1);
    OP_REQUIRES(context, TensorShapeUtils::IsVector(checkpoint_prefixes.shape()), errors::InvalidArgument( "Input checkpoint_prefixes should be an 1-D tensor, got ", checkpoint_prefixes.shape().DebugString(), " instead."));



    OP_REQUIRES(context, TensorShapeUtils::IsScalar(destination_prefix.shape()), errors::InvalidArgument( "Input destination_prefix should be a scalar tensor, got ", destination_prefix.shape().DebugString(), " instead."));



    const gtl::ArraySlice<tstring> input_prefixes = gtl::ArraySlice<tstring>(checkpoint_prefixes.flat<tstring>());
    Env* env = Env::Default();
    const string& merged_prefix = destination_prefix.scalar<tstring>()();
    OP_REQUIRES_OK( context, tensorflow::MergeBundles(env, input_prefixes, merged_prefix));

    if (delete_old_dirs_) {
      const string merged_dir(io::Dirname(merged_prefix));
      for (const string& input_prefix : input_prefixes) {
        const string dirname(io::Dirname(input_prefix));
        if (dirname == merged_dir) continue;
        Status status = env->DeleteDir(dirname);
        
        
        if (!status.ok()) VLOG(1) << status;
      }
    }
  }

 private:
  
  bool delete_old_dirs_;
};
REGISTER_KERNEL_BUILDER(Name("MergeV2Checkpoints").Device(DEVICE_CPU), MergeV2Checkpoints);

}  
