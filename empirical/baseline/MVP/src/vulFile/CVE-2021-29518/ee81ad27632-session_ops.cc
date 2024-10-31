























namespace tensorflow {

class GetSessionHandleOp : public OpKernel {
 public:
  explicit GetSessionHandleOp(OpKernelConstruction* context)
      : OpKernel(context) {}

  void Compute(OpKernelContext* ctx) override {
    const Tensor& val = ctx->input(0);
    auto session_state = ctx->session_state();
    OP_REQUIRES(ctx, session_state != nullptr, errors::FailedPrecondition( "GetSessionHandle called on null session state"));

    int64 id = session_state->GetNewId();
    TensorStore::TensorAndKey tk{val, id, requested_device()};
    OP_REQUIRES_OK(ctx, ctx->tensor_store()->AddTensor(name(), tk));

    Tensor* handle = nullptr;
    OP_REQUIRES_OK(ctx, ctx->allocate_output(0, TensorShape({}), &handle));
    if (ctx->expected_output_dtype(0) == DT_RESOURCE) {
      ResourceHandle resource_handle = MakeResourceHandle<Tensor>( ctx, SessionState::kTensorHandleResourceTypeName, tk.GetHandle(name()));

      resource_handle.set_maybe_type_name( SessionState::kTensorHandleResourceTypeName);
      handle->scalar<ResourceHandle>()() = resource_handle;
    } else {
      
      handle->flat<tstring>().setConstant(tk.GetHandle(name()));
    }
  }

  TF_DISALLOW_COPY_AND_ASSIGN(GetSessionHandleOp);
};

REGISTER_KERNEL_BUILDER(Name("GetSessionHandle").Device(DEVICE_CPU), GetSessionHandleOp);
REGISTER_KERNEL_BUILDER(Name("GetSessionHandleV2").Device(DEVICE_CPU), GetSessionHandleOp);












TF_CALL_NUMBER_TYPES(REGISTER_GPU_KERNEL);
REGISTER_GPU_KERNEL(bool);



class GetSessionTensorOp : public OpKernel {
 public:
  explicit GetSessionTensorOp(OpKernelConstruction* context)
      : OpKernel(context) {}

  void Compute(OpKernelContext* ctx) override {
    const Tensor& handle = ctx->input(0);
    const string& name = handle.scalar<tstring>()();
    Tensor val;
    OP_REQUIRES_OK(ctx, ctx->session_state()->GetTensor(name, &val));
    ctx->set_output(0, val);
  }

  TF_DISALLOW_COPY_AND_ASSIGN(GetSessionTensorOp);
};

REGISTER_KERNEL_BUILDER(Name("GetSessionTensor").Device(DEVICE_CPU), GetSessionTensorOp);







TF_CALL_NUMBER_TYPES(REGISTER_GPU_KERNEL);
REGISTER_GPU_KERNEL(bool);



class DeleteSessionTensorOp : public OpKernel {
 public:
  explicit DeleteSessionTensorOp(OpKernelConstruction* context)
      : OpKernel(context) {}

  void Compute(OpKernelContext* ctx) override {
    const Tensor& handle = ctx->input(0);
    const string& name = handle.scalar<tstring>()();
    OP_REQUIRES_OK(ctx, ctx->session_state()->DeleteTensor(name));
  }

  TF_DISALLOW_COPY_AND_ASSIGN(DeleteSessionTensorOp);
};

REGISTER_KERNEL_BUILDER(Name("DeleteSessionTensor").Device(DEVICE_CPU), DeleteSessionTensorOp);
REGISTER_KERNEL_BUILDER( Name("DeleteSessionTensor").Device(DEVICE_GPU).HostMemory("handle"), DeleteSessionTensorOp);


}  
