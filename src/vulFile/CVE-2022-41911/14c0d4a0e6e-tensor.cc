















































namespace tensorflow {








REGISTER_UNARY_VARIANT_DECODE_FUNCTION(Tensor, "tensorflow::Tensor");

bool TensorBuffer::GetAllocatedBytes(size_t* out_bytes) const {
  AllocationDescription allocation_description;
  FillAllocationDescription(&allocation_description);
  if (allocation_description.allocated_bytes() > 0) {
    *out_bytes = allocation_description.allocated_bytes();
    return true;
  } else {
    return false;
  }
}

namespace {


class BufferBase : public TensorBuffer {
 public:
  explicit BufferBase(Allocator* alloc, void* data_ptr)
      : TensorBuffer(data_ptr), alloc_(alloc) {}

  TensorBuffer* root_buffer() override { return this; }

  bool GetAllocatedBytes(size_t* out_bytes) const override {
    if (alloc_->TracksAllocationSizes()) {
      *out_bytes = alloc_->AllocatedSize(data());
      return *out_bytes > 0;
    } else {
      return false;
    }
  }

  void FillAllocationDescription(AllocationDescription* proto) const override {
    void* data_ptr = data();
    int64_t rb = size();
    proto->set_requested_bytes(rb);
    proto->set_allocator_name(alloc_->Name());
    proto->set_ptr(reinterpret_cast<uintptr_t>(data_ptr));
    if (alloc_->TracksAllocationSizes()) {
      int64_t ab = alloc_->AllocatedSize(data_ptr);
      proto->set_allocated_bytes(ab);
      int64_t id = alloc_->AllocationId(data_ptr);
      if (id > 0) {
        proto->set_allocation_id(id);
      }
      if (RefCountIsOne()) {
        proto->set_has_single_reference(true);
      }
    }
  }

  
  AllocatorMemoryType GetMemoryType() const override {
    return alloc_->GetMemoryType();
  }

 protected:
  void RecordDeallocation() {
    LogMemory::RecordTensorDeallocation(alloc_->AllocationId(data()), alloc_->Name());
  }

  Allocator* const alloc_;
};


template <typename T> class Buffer : public BufferBase {
 public:
  Buffer(Allocator* a, int64_t n);
  Buffer(Allocator* a, int64_t n, const AllocationAttributes& allocation_attr);

  size_t size() const override { return sizeof(T) * elem_; }

 private:
  int64_t elem_;

  ~Buffer() override;

  TF_DISALLOW_COPY_AND_ASSIGN(Buffer);
};

void LogUnexpectedSize(int64_t actual, int64_t expected) {
  LOG(ERROR) << "Input size was " << actual << " and expected " << expected;
}

bool MemoryLoggingEnabled() {
  static bool memory_logging_enabled = LogMemory::IsEnabled();
  return memory_logging_enabled;
}


template <typename T> struct Helper {
  
  static_assert(is_simple_type<T>::value, "T is not a simple type.");
  typedef protobuf::RepeatedField<T> RepeatedFieldType;

  
  template <typename Destination> static void Encode(TensorBuffer* in, int64_t n, Destination* out) {
    DCHECK_EQ(in->size(), sizeof(T) * n);
    port::AssignRefCounted(StringPiece(in->base<const char>(), in->size()), in, out);
  }

  
  
  template <typename Source> static TensorBuffer* Decode(Allocator* a, const Source& in, int64_t n) {
    if (in.size() != sizeof(T) * n) {
      LogUnexpectedSize(in.size(), sizeof(T) * n);
      return nullptr;
    }
    Buffer<T>* buf = new Buffer<T>(a, n);
    char* data = buf->template base<char>();
    if (data == nullptr) {
      buf->Unref();
      return nullptr;
    }
    port::CopyToArray(in, data);
    return buf;
  }

  
  static int64_t TotalBytes(TensorBuffer* in, int64_t n) {
    DCHECK_EQ(in->size(), sizeof(T) * n);
    return in->size();
  }
};



template <> struct Helper<tstring> {
  
  typedef protobuf::RepeatedPtrField<string> RepeatedFieldType;

  
  
  template <typename Destination> static void Encode(TensorBuffer* in, int64_t n, Destination* out) {
    port::EncodeStringList(in->base<const tstring>(), n, out);
  }

  
  
  
  template <typename Source> static TensorBuffer* Decode(Allocator* a, const Source& in, int64_t n) {
    Buffer<tstring>* buf = new Buffer<tstring>(a, n);
    tstring* strings = buf->template base<tstring>();
    if (strings == nullptr || !port::DecodeStringList(in, strings, n)) {
      buf->Unref();
      return nullptr;
    }
    return buf;
  }

  
  
  static int64_t TotalBytes(TensorBuffer* in, int n) {
    int64_t tot = in->size();
    DCHECK_EQ(tot, sizeof(tstring) * n);
    const tstring* p = in->base<const tstring>();
    for (int i = 0; i < n; ++i, ++p) tot += p->size();
    return tot;
  }
};

template <> struct Helper<ResourceHandle> {
  
  typedef protobuf::RepeatedPtrField<string> RepeatedFieldType;

  
  
  template <typename Destination> static void Encode(TensorBuffer* in, int64_t n, Destination* out) {
    EncodeResourceHandleList(in->base<const ResourceHandle>(), n, port::NewStringListEncoder(out));
  }

  
  
  
  template <typename Source> static TensorBuffer* Decode(Allocator* a, const Source& in, int64_t n) {
    auto* buf = new Buffer<ResourceHandle>(a, n);
    ResourceHandle* ps = buf->template base<ResourceHandle>();
    if (ps == nullptr || !DecodeResourceHandleList(port::NewStringListDecoder(in), ps, n)) {
      buf->Unref();
      return nullptr;
    }
    return buf;
  }

  
  
  static int64_t TotalBytes(TensorBuffer* in, int n) {
    return n * sizeof(ResourceHandle);
  }
};

template <> struct Helper<Variant> {
  
  
  template <typename Destination> static void Encode(TensorBuffer* in, int64_t n, Destination* out) {
    EncodeVariantList(in->base<const Variant>(), n, port::NewStringListEncoder(out));
  }

  
  
  
  template <typename Source> static TensorBuffer* Decode(Allocator* a, const Source& in, int64_t n) {
    auto* buf = new Buffer<Variant>(a, n);
    Variant* ps = buf->template base<Variant>();
    if (ps == nullptr || !DecodeVariantList(port::NewStringListDecoder(in), ps, n)) {
      buf->Unref();
      return nullptr;
    }
    return buf;
  }

  
  
  static int64_t TotalBytes(TensorBuffer* in, int n) {
    return n * sizeof(Variant);
  }
};

template <typename T> struct ProtoHelper {};



















PROTO_TRAITS(float, float, float);
PROTO_TRAITS(double, double, double);
PROTO_TRAITS(int32, int32, int);
PROTO_TRAITS(uint8, int32, int);
PROTO_TRAITS(uint16, int32, int);
PROTO_TRAITS(uint32, uint32, uint32);
PROTO_TRAITS(int16, int32, int);
PROTO_TRAITS(int8, int32, int);
PROTO_TRAITS(bool, bool, bool);
PROTO_TRAITS(tstring, tstring, string);
PROTO_TRAITS(qint8, int32, int);
PROTO_TRAITS(quint8, int32, int);
PROTO_TRAITS(qint16, int32, int);
PROTO_TRAITS(quint16, int32, int);


template <> struct ProtoHelper<int64_t> {
  static protobuf::RepeatedField<int64_t>::const_iterator Begin( const TensorProto& proto) {
    return proto.int64_val().begin();
  }
  static size_t NumElements(const TensorProto& proto) {
    return proto.int64_val().size();
  }
  static void Fill(const int64_t* data, size_t n, TensorProto* proto) {
    protobuf::RepeatedField<protobuf_int64> copy(data, data + n);
    proto->mutable_int64_val()->Swap(&copy);
  }
};

template <> struct ProtoHelper<uint64> {
  static protobuf::RepeatedField<uint64_t>::const_iterator Begin( const TensorProto& proto) {
    return proto.uint64_val().begin();
  }
  static size_t NumElements(const TensorProto& proto) {
    return proto.uint64_val().size();
  }
  static void Fill(const uint64* data, size_t n, TensorProto* proto) {
    protobuf::RepeatedField<protobuf_uint64> copy(data, data + n);
    proto->mutable_uint64_val()->Swap(&copy);
  }
};

template <> struct ProtoHelper<ResourceHandle> {
  static protobuf::RepeatedPtrField<ResourceHandleProto>::const_iterator Begin( const TensorProto& proto) {
    return proto.resource_handle_val().begin();
  }
  static size_t NumElements(const TensorProto& proto) {
    return proto.resource_handle_val().size();
  }
  static void Fill(const ResourceHandle* data, size_t n, TensorProto* proto) {
    auto* handles = proto->mutable_resource_handle_val();
    handles->Clear();
    for (size_t i = 0; i < n; i++) {
      data[i].AsProto(handles->Add());
    }
  }
};

template <> struct ProtoHelper<Variant> {
  static protobuf::RepeatedPtrField<VariantTensorDataProto>::const_iterator Begin(const TensorProto& proto) {
    return proto.variant_val().begin();
  }
  static size_t NumElements(const TensorProto& proto) {
    return proto.variant_val().size();
  }
  static void Fill(const Variant* data, size_t n, TensorProto* proto) {
    auto* variant_values = proto->mutable_variant_val();
    variant_values->Clear();
    for (size_t i = 0; i < n; ++i) {
      VariantTensorData tmp;
      data[i].Encode(&tmp);
      tmp.ToProto(variant_values->Add());
    }
  }
};

template <> struct ProtoHelper<complex64> {
  typedef Helper<float>::RepeatedFieldType FieldType;
  static const complex64* Begin(const TensorProto& proto) {
    return reinterpret_cast<const complex64*>(proto.scomplex_val().data());
  }
  static size_t NumElements(const TensorProto& proto) {
    return proto.scomplex_val().size() / 2;
  }
  static void Fill(const complex64* data, size_t n, TensorProto* proto) {
    const float* p = reinterpret_cast<const float*>(data);
    FieldType copy(p, p + n * 2);
    proto->mutable_scomplex_val()->Swap(&copy);
  }
};

template <> struct ProtoHelper<complex128> {
  typedef Helper<double>::RepeatedFieldType FieldType;
  static const complex128* Begin(const TensorProto& proto) {
    return reinterpret_cast<const complex128*>(proto.dcomplex_val().data());
  }
  static size_t NumElements(const TensorProto& proto) {
    return proto.dcomplex_val().size() / 2;
  }
  static void Fill(const complex128* data, size_t n, TensorProto* proto) {
    const double* p = reinterpret_cast<const double*>(data);
    FieldType copy(p, p + n * 2);
    proto->mutable_dcomplex_val()->Swap(&copy);
  }
};

template <> struct ProtoHelper<qint32> {
  typedef Helper<int32>::RepeatedFieldType FieldType;
  static const qint32* Begin(const TensorProto& proto) {
    return reinterpret_cast<const qint32*>(proto.int_val().data());
  }
  static size_t NumElements(const TensorProto& proto) {
    return proto.int_val().size();
  }
  static void Fill(const qint32* data, size_t n, TensorProto* proto) {
    const int32* p = reinterpret_cast<const int32*>(data);
    FieldType copy(p, p + n);
    proto->mutable_int_val()->Swap(&copy);
  }
};

template <> struct ProtoHelper<bfloat16> {
  static void Fill(const bfloat16* data, size_t n, TensorProto* proto) {
    proto->mutable_half_val()->Reserve(n);
    for (size_t i = 0; i < n; ++i) {
      proto->mutable_half_val()->AddAlreadyReserved( Eigen::numext::bit_cast<uint16>(data[i]));
    }
  }
};

template <> struct ProtoHelper<Eigen::half> {
  static void Fill(const Eigen::half* data, size_t n, TensorProto* proto) {
    proto->mutable_half_val()->Reserve(n);
    for (size_t i = 0; i < n; ++i) {
      proto->mutable_half_val()->AddAlreadyReserved( Eigen::numext::bit_cast<uint16>(data[i]));
    }
  }
};

template <typename T> Buffer<T>::Buffer(Allocator* a, int64_t n)
    : BufferBase(a, TypedAllocator::Allocate<T>(a, n, AllocationAttributes())), elem_(n) {}

template <typename T> Buffer<T>::Buffer(Allocator* a, int64_t n, const AllocationAttributes& allocation_attr)

    : BufferBase(a, TypedAllocator::Allocate<T>(a, n, allocation_attr)), elem_(n) {}

template <typename T> Buffer<T>::~Buffer() {
  if (data()) {
    if (MemoryLoggingEnabled()) {
      RecordDeallocation();
    }
    TypedAllocator::Deallocate<T>(alloc_, static_cast<T*>(data()), elem_);
  }
}











template <typename T> TensorBuffer* FromProtoField(Allocator* a, const TensorProto& in, int64_t n) {
  CHECK_GT(n, 0);
  Buffer<T>* buf = new Buffer<T>(a, n);
  T* data = buf->template base<T>();
  if (data == nullptr) {
    buf->Unref();
    return nullptr;
  }

  const int64_t in_n = ProtoHelper<T>::NumElements(in);
  if (in_n <= 0) {
    std::fill_n(data, n, T());
  } else {
    auto begin = ProtoHelper<T>::Begin(in);
    if (n <= in_n) {
      std::copy_n(begin, n, data);
    } else {
      std::copy_n(begin, in_n, data);
      if (std::is_trivially_copyable<T>::value) {
        const T last = *(data + in_n - 1);
        std::fill_n(data + in_n, n - in_n, last);
      } else {
        const T& last = *(data + in_n - 1);
        std::fill_n(data + in_n, n - in_n, last);
      }
    }
  }

  return buf;
}




template <> TensorBuffer* FromProtoField<ResourceHandle>(Allocator* a, const TensorProto& in, int64_t n) {

  CHECK_GT(n, 0);
  Buffer<ResourceHandle>* buf = new Buffer<ResourceHandle>(a, n);
  ResourceHandle* data = buf->template base<ResourceHandle>();
  if (data == nullptr) {
    buf->Unref();
    return nullptr;
  }
  const int64_t in_n = ProtoHelper<ResourceHandle>::NumElements(in);
  if (in_n <= 0) {
    std::fill_n(data, n, ResourceHandle());
  } else {
    
    
    
    
    const int64_t real_n = n < in_n ? n : in_n;
    for (int64_t i = 0; i < real_n; ++i) {
      Status s = ResourceHandle::BuildResourceHandle(in.resource_handle_val(i), &data[i]);
      if (!s.ok()) {
        LOG(ERROR) << "Could not decode resource handle from proto \"" << in.resource_handle_val(i).ShortDebugString()
                   << "\", returned status: " << s.ToString();
        buf->Unref();
        return nullptr;
      }
    }
    for (int64_t i = in_n; i < n; ++i) {
      data[i] = ResourceHandle();
    }
  }
  return buf;
}

template <> TensorBuffer* FromProtoField<Variant>(Allocator* a, const TensorProto& in, int64_t n) {

  CHECK_GT(n, 0);
  Buffer<Variant>* buf = new Buffer<Variant>(a, n);
  Variant* data = buf->template base<Variant>();
  if (data == nullptr) {
    buf->Unref();
    return nullptr;
  }
  const int64_t in_n = ProtoHelper<Variant>::NumElements(in);
  if (in_n <= 0) {
    std::fill_n(data, n, Variant());
  } else {
    
    
    
    
    const int64_t real_n = n < in_n ? n : in_n;
    for (int64_t i = 0; i < real_n; ++i) {
      data[i] = in.variant_val(i);
      if (!DecodeUnaryVariant(&data[i])) {
        LOG(ERROR) << "Could not decode variant with type_name: \"" << data[i].TypeName()
                   << "\".  Perhaps you forgot to register a " "decoder via REGISTER_UNARY_VARIANT_DECODE_FUNCTION?";
        buf->Unref();
        return nullptr;
      }
    }
    for (int64_t i = in_n; i < n; ++i) {
      data[i] = Variant();
    }
  }
  return buf;
}




template <> TensorBuffer* FromProtoField<Eigen::half>(Allocator* a, const TensorProto& in, int64_t n) {

  CHECK_GT(n, 0);
  Buffer<Eigen::half>* buf = new Buffer<Eigen::half>(a, n);
  uint16* data = buf->template base<uint16>();
  if (data == nullptr) {
    buf->Unref();
    return nullptr;
  }
  const int64_t in_n = in.half_val().size();
  auto begin = in.half_val().begin();
  if (n <= in_n) {
    std::copy_n(begin, n, data);
  } else if (in_n > 0) {
    std::copy_n(begin, in_n, data);
    const uint16 last = *(data + in_n - 1);
    std::fill_n(data + in_n, n - in_n, last);
  } else {
    std::fill_n(data, n, 0);
  }
  return buf;
}

template <> TensorBuffer* FromProtoField<bfloat16>(Allocator* a, const TensorProto& in, int64_t n) {

  CHECK_GT(n, 0);
  Buffer<bfloat16>* buf = new Buffer<bfloat16>(a, n);
  uint16* data = buf->template base<uint16>();
  if (data == nullptr) {
    buf->Unref();
    return nullptr;
  }
  const int64_t in_n = in.half_val().size();
  auto begin = in.half_val().begin();
  if (n <= in_n) {
    std::copy_n(begin, n, data);
  } else if (in_n > 0) {
    std::copy_n(begin, in_n, data);
    const uint16 last = *(data + in_n - 1);
    std::fill_n(data + in_n, n - in_n, last);
  } else {
    std::fill_n(data, n, 0);
  }
  return buf;
}



template <typename T> void ToProtoField(const TensorBuffer& in, int64_t n, TensorProto* out) {
  const T* data = in.base<const T>();
  
  
  
  
  ProtoHelper<T>::Fill(data, n, out);
}

void RefIfNonNull(core::RefCounted* buf) {
  if (buf) buf->Ref();
}

void UnrefIfNonNull(core::RefCounted* buf) {
  if (buf) buf->Unref();
}

}  

Tensor::Tensor() : Tensor(DT_FLOAT) {}

Tensor::Tensor(DataType type) : shape_(type), buf_(nullptr) {}

Tensor::Tensor(DataType type, const TensorShape& shape, TensorBuffer* buf)
    : shape_(shape), buf_(buf) {
  set_dtype(type);
  RefIfNonNull(buf);
}

Tensor::Tensor(DataType type, TensorShape shape, core::RefCountPtr<TensorBuffer> buf)
    : shape_(std::move(shape)), buf_(buf.release()) {
  set_dtype(type);
}

bool Tensor::IsInitialized() const {
  return (buf_ != nullptr && buf_->data() != nullptr) || shape_.num_elements() == 0;
}

void Tensor::CheckType(DataType expected_dtype) const {
  CHECK_EQ(dtype(), expected_dtype)
      << " " << DataTypeString(expected_dtype) << " expected, got " << DataTypeString(dtype());
}

void Tensor::CheckTypeAndIsAligned(DataType expected_dtype) const {
  CHECK_EQ(dtype(), expected_dtype)
      << " " << DataTypeString(expected_dtype) << " expected, got " << DataTypeString(dtype());
  CHECK(IsAligned()) << "ptr = " << base<void>();
}

void Tensor::CheckIsAlignedAndSingleElement() const {
  CHECK(IsAligned()) << "Aligned and single element";
  CHECK_EQ(1, NumElements()) << "Must have a one element tensor";
}

Tensor::~Tensor() { UnrefIfNonNull(buf_); }

Status Tensor::BitcastFrom(const Tensor& other, DataType dtype, const TensorShape& shape) {
  int in_size = DataTypeSize(other.dtype());
  int out_size = DataTypeSize(dtype);
  if (in_size == 0) {
    return errors::InvalidArgument("other tensor has zero-sized data type");
  }
  if (out_size == 0) {
    return errors::InvalidArgument("specified output type is zero-sized");
  }
  if (shape.num_elements() * out_size != other.shape().num_elements() * in_size) {
    return errors::InvalidArgument( "input and output shapes/data type sizes are not compatible");
  }
  shape_ = shape;
  shape_.set_data_type(dtype);
  if (buf_ != other.buf_) {
    UnrefIfNonNull(buf_);
    buf_ = other.buf_;
    RefIfNonNull(buf_);
  }
  return OkStatus();
}




bool Tensor::RefCountIsOne() const {
  return buf_ != nullptr && buf_->RefCountIsOne() && buf_->root_buffer()->RefCountIsOne() && buf_->OwnsMemory();
}












































Tensor::Tensor(Allocator* a, DataType type, const TensorShape& shape)
    : shape_(shape), buf_(nullptr) {
  set_dtype(type);
  CHECK_NOTNULL(a);
  if (shape_.num_elements() > 0 || a->AllocatesOpaqueHandle()) {
    CASES(type, buf_ = new Buffer<T>(a, shape.num_elements()));
  }
  if (MemoryLoggingEnabled() && buf_ != nullptr && buf_->data() != nullptr) {
    LogMemory::RecordTensorAllocation("Unknown", LogMemory::UNKNOWN_STEP_ID, *this);
  }
}

Tensor::Tensor(Allocator* a, DataType type, const TensorShape& shape, const AllocationAttributes& allocation_attr)
    : shape_(shape), buf_(nullptr) {
  set_dtype(type);
  CHECK_NOTNULL(a);
  if (shape_.num_elements() > 0 || a->AllocatesOpaqueHandle()) {
    CASES(type, buf_ = new Buffer<T>(a, shape.num_elements(), allocation_attr));
  }
  if (MemoryLoggingEnabled() && !allocation_attr.allocation_will_be_logged && buf_ != nullptr && buf_->data() != nullptr) {
    LogMemory::RecordTensorAllocation("Unknown (with attributes)", LogMemory::UNKNOWN_STEP_ID, *this);
  }
}

Status Tensor::BuildTensor(DataType type, const TensorShape& shape, Tensor* out_tensor) {
  
  CASES_WITH_DEFAULT( type, {}, return errors::InvalidArgument("Type not set"), return errors::InvalidArgument("Unexpected type: ", DataType_Name(type)));

  *out_tensor = Tensor(type, shape);
  return OkStatus();
}









static Allocator* get_default_cpu_allocator() {
  static Allocator* default_cpu_allocator = cpu_allocator(tsl::port::kNUMANoAffinity);
  return default_cpu_allocator;
}

Tensor::Tensor(DataType type, const TensorShape& shape)
    : Tensor(get_default_cpu_allocator(), type, shape) {}

bool Tensor::HostScalarTensorBufferBase::GetAllocatedBytes( size_t* out_bytes) const {
  
  
  return false;
}

void Tensor::HostScalarTensorBufferBase::FillAllocationDescription( AllocationDescription* proto) const {
  proto->set_requested_bytes(size());
  proto->set_allocator_name("HostScalarTensorBuffer");
  proto->set_ptr(reinterpret_cast<uintptr_t>(data()));
}

template <typename T> class SubBuffer : public TensorBuffer {
 public:
  
  SubBuffer(TensorBuffer* buf, int64_t delta, int64_t n)
      : TensorBuffer(buf->base<T>() + delta), root_(buf->root_buffer()), elem_(n) {

    
    CHECK_LE(root_->base<T>(), this->base<T>());
    T* root_limit = root_->base<T>() + root_->size() / sizeof(T);
    CHECK_LE(this->base<T>(), root_limit);
    CHECK_LE(this->base<T>() + n, root_limit);
    
    
    root_->Ref();
  }

  size_t size() const override { return sizeof(T) * elem_; }
  TensorBuffer* root_buffer() override { return root_; }
  bool GetAllocatedBytes(size_t* out_bytes) const override {
    return root_->GetAllocatedBytes(out_bytes);
  }
  void FillAllocationDescription(AllocationDescription* proto) const override {
    root_->FillAllocationDescription(proto);
  }

 private:
  TensorBuffer* root_;
  int64_t elem_;

  ~SubBuffer() override { root_->Unref(); }

  TF_DISALLOW_COPY_AND_ASSIGN(SubBuffer);
};

Tensor Tensor::Slice(int64_t start, int64_t limit) const {
  CHECK_GE(dims(), 1);
  CHECK_LE(0, start);
  CHECK_LE(start, limit);
  int64_t dim0_size = shape_.dim_size(0);
  CHECK_LE(limit, dim0_size);
  if ((start == 0) && (limit == dim0_size)) {
    return *this;
  }
  Tensor ret;
  ret.shape_ = shape_;
  ret.set_dtype(dtype());
  ret.buf_ = nullptr;
  if (dim0_size > 0) {
    const int64_t elems_per_dim0 = NumElements() / dim0_size;
    const int64_t delta = start * elems_per_dim0;
    dim0_size = limit - start;
    ret.shape_.set_dim(0, dim0_size);
    const int64_t num_elems = dim0_size * elems_per_dim0;
    if (buf_) {
      DataType dt = dtype();
      CASES(dt, ret.buf_ = new SubBuffer<T>(buf_, delta, num_elems));
    }
  }
  return ret;
}

Tensor Tensor::SubSlice(int64_t index) const {
  CHECK_GE(dims(), 1);  
  CHECK_LE(0, index);   
  int64_t dim0_size = shape_.dim_size(0);
  CHECK_LE(index, dim0_size);  
  Tensor ret;
  ret.shape_ = shape_;
  ret.shape_.RemoveDim(0);
  ret.set_dtype(dtype());
  ret.buf_ = nullptr;
  if (dim0_size > 0) {
    const int64_t elems_per_dim0 = NumElements() / dim0_size;
    const int64_t delta = index * elems_per_dim0;
    const int64_t num_elems = elems_per_dim0;
    if (buf_) {
      DataType dt = dtype();
      CASES(dt, ret.buf_ = new SubBuffer<T>(buf_, delta, num_elems));
    }
  }
  return ret;
}

bool Tensor::FromProto(const TensorProto& proto) {
  return FromProto(get_default_cpu_allocator(), proto);
}

bool Tensor::FromProto(Allocator* a, const TensorProto& proto) {
  CHECK_NOTNULL(a);
  TensorBuffer* p = nullptr;
  if (!TensorShape::IsValid(proto.tensor_shape())) return false;
  if (proto.dtype() == DT_INVALID) return false;
  TensorShape shape(proto.tensor_shape());
  const int64_t N = shape.num_elements();
  if (N > 0 && proto.dtype()) {
    bool dtype_error = false;
    if (!proto.tensor_content().empty()) {
      const auto& content = proto.tensor_content();
      CASES_WITH_DEFAULT(proto.dtype(), p = Helper<T>::Decode(a, content, N), dtype_error = true, dtype_error = true);
    } else {
      CASES_WITH_DEFAULT(proto.dtype(), p = FromProtoField<T>(a, proto, N), dtype_error = true, dtype_error = true);
    }
    if (dtype_error || p == nullptr) return false;
  } else {
    
    
    
    
    bool dtype_error = false;
    CASES_WITH_DEFAULT(proto.dtype(), break, dtype_error = true, dtype_error = true);
    if (dtype_error) return false;
  }
  shape_ = shape;
  set_dtype(proto.dtype());
  UnrefIfNonNull(buf_);
  buf_ = p;
  
  
  if (MemoryLoggingEnabled() && buf_ != nullptr && buf_->data() != nullptr) {
    LogMemory::RecordTensorAllocation("Unknown (from Proto)", LogMemory::UNKNOWN_STEP_ID, *this);
  }
  return true;
}

void Tensor::AsProtoField(TensorProto* proto) const {
  proto->Clear();
  shape_.AsProto(proto->mutable_tensor_shape());
  proto->set_dtype(dtype());
  if (buf_) {
    CASES(dtype(), ToProtoField<T>(*buf_, shape_.num_elements(), proto));
  }
}

void Tensor::AsProtoTensorContent(TensorProto* proto) const {
  proto->Clear();
  proto->set_dtype(dtype());
  shape_.AsProto(proto->mutable_tensor_shape());
  if (buf_) {
    CASES(dtype(), Helper<T>::Encode(buf_, shape_.num_elements(), proto->mutable_tensor_content()));
  }
}

size_t Tensor::TotalBytes() const {
  if (shape_.num_elements() == 0) return 0;
  CHECK(buf_) << "null buf_ with non-zero shape size " << shape_.num_elements();
  CASES(dtype(), return Helper<T>::TotalBytes(buf_, shape_.num_elements()));
  return 0;  
}

size_t Tensor::AllocatedBytes() const {
  if (buf_) {
    size_t ret;
    if (buf_->GetAllocatedBytes(&ret)) {
      return ret;
    }
  }
  return TotalBytes();
}

bool Tensor::CanUseDMA() const {
  CASES(dtype(), return is_simple_type<T>::value);
  return false;  
}




namespace {







inline const strings::AlphaNum& PrintOneElement(const strings::AlphaNum& a, bool print_v2) {
  return a;
}
inline string PrintOneElement(const tstring& a, bool print_v2) {
  if (print_v2) {
    return "\"" + absl::Utf8SafeCEscape(a) + "\"";
  } else {
    return absl::Utf8SafeCEscape(a);
  }
}
inline float PrintOneElement(const Eigen::half& h, bool print_v2) {
  return static_cast<float>(h);
}

inline float PrintOneElement(bfloat16 f, bool print_v2) {
  return static_cast<float>(f);
}


template <typename T> void PrintOneDim(int dim_index, const gtl::InlinedVector<int64, 4>& shape, int64_t limit, int shape_size, const T* data, int64_t* data_index, string* result) {


  if (*data_index >= limit) return;
  int64_t element_count = shape[dim_index];
  
  if (dim_index == shape_size - 1) {
    for (int64_t i = 0; i < element_count; i++) {
      if (*data_index >= limit) {
        
        if (dim_index != 0) {
          strings::StrAppend(result, "...");
        }
        return;
      }
      if (i > 0) strings::StrAppend(result, " ");
      strings::StrAppend(result, PrintOneElement(data[(*data_index)++], false));
    }
    return;
  }
  
  for (int64_t i = 0; i < element_count; i++) {
    bool flag = false;
    if (*data_index < limit) {
      strings::StrAppend(result, "[");
      flag = true;
    }
    
    PrintOneDim(dim_index + 1, shape, limit, shape_size, data, data_index, result);
    if (*data_index < limit || flag) {
      strings::StrAppend(result, "]");
      flag = false;
    }
  }
}


void PrintDimSpacing(int dim_index, int num_dims, string* result) {
  if (dim_index == num_dims - 1) {
    strings::StrAppend(result, " ");
    return;
  }
  for (int j = 0; j < num_dims - dim_index - 1; j++) {
    strings::StrAppend(result, "\n");
  }
  for (int j = 0; j <= dim_index; j++) {
    strings::StrAppend(result, " ");
  }
}


template <typename T> void PrintOneDimV2(int dim_index, const gtl::InlinedVector<int64, 4>& shape, int64_t num_elts_at_ends, int num_dims, const T* data, int64_t data_index, string* result) {


  
  
  if (dim_index == num_dims) {
    strings::StrAppend(result, PrintOneElement(data[data_index], true));
    return;
  }

  strings::StrAppend(result, "[");
  int64_t element_count = shape[dim_index];
  int64_t start_of_end = std::max(num_elts_at_ends, element_count - num_elts_at_ends);

  
  int64_t elements_per_iter = 1;
  for (int i = dim_index + 1; i < num_dims; i++) {
    elements_per_iter *= shape[i];
  }
  for (int64_t i = 0; (i < num_elts_at_ends) && (i < element_count); i++) {
    if (i > 0) {
      PrintDimSpacing(dim_index, num_dims, result);
    }

    
    PrintOneDimV2(dim_index + 1, shape, num_elts_at_ends, num_dims, data, data_index + elements_per_iter * i, result);
  }
  if (element_count > 2 * num_elts_at_ends) {
    PrintDimSpacing(dim_index, num_dims, result);
    strings::StrAppend(result, "...");
  }
  for (int64_t i = start_of_end; i < element_count; i++) {
    
    PrintDimSpacing(dim_index, num_dims, result);
    PrintOneDimV2(dim_index + 1, shape, num_elts_at_ends, num_dims, data, data_index + elements_per_iter * i, result);
  }

  strings::StrAppend(result, "]");
}

template <typename T> string SummarizeArray(int64_t limit, int64_t num_elts, const TensorShape& tensor_shape, const char* data, const bool print_v2) {


  string ret;
  const T* array = reinterpret_cast<const T*>(data);

  const gtl::InlinedVector<int64_t, 4> shape = tensor_shape.dim_sizes();
  if (shape.empty()) {
    for (int64_t i = 0; i < limit; ++i) {
      if (i > 0) strings::StrAppend(&ret, " ");
      strings::StrAppend(&ret, PrintOneElement(array[i], print_v2));
    }
    if (num_elts > limit) strings::StrAppend(&ret, "...");
    return ret;
  }
  if (print_v2) {
    const int num_dims = tensor_shape.dims();
    PrintOneDimV2(0, shape, limit, num_dims, array, 0, &ret);
  } else {
    int64_t data_index = 0;
    const int shape_size = tensor_shape.dims();
    PrintOneDim(0, shape, limit, shape_size, array, &data_index, &ret);

    if (num_elts > limit) strings::StrAppend(&ret, "...");
  }

  return ret;
}
}  

string Tensor::SummarizeValue(int64_t max_entries, bool print_v2) const {
  const int64_t num_elts = NumElements();
  if (max_entries < 0) {
    max_entries = num_elts;
  }
  size_t limit = std::min(max_entries, num_elts);
  if ((limit > 0) && (buf_ == nullptr)) {
    return strings::StrCat("uninitialized Tensor of ", num_elts, " elements of type ", dtype());
  }
  const char* data = limit > 0 ? tensor_data().data() : nullptr;
  switch (dtype()) {
    case DT_BFLOAT16:
      return SummarizeArray<bfloat16>(limit, num_elts, shape_, data, print_v2);
      break;
    case DT_HALF:
      return SummarizeArray<Eigen::half>(limit, num_elts, shape_, data, print_v2);
      break;
    case DT_FLOAT:
      return SummarizeArray<float>(limit, num_elts, shape_, data, print_v2);
      break;
    case DT_DOUBLE:
      return SummarizeArray<double>(limit, num_elts, shape_, data, print_v2);
      break;
    case DT_UINT32:
      return SummarizeArray<uint32>(limit, num_elts, shape_, data, print_v2);
      break;
    case DT_INT32:
      return SummarizeArray<int32>(limit, num_elts, shape_, data, print_v2);
      break;
    case DT_UINT8:
    case DT_QUINT8:
      return SummarizeArray<uint8>(limit, num_elts, shape_, data, print_v2);
      break;
    case DT_UINT16:
    case DT_QUINT16:
      return SummarizeArray<uint16>(limit, num_elts, shape_, data, print_v2);
      break;
    case DT_INT16:
    case DT_QINT16:
      return SummarizeArray<int16>(limit, num_elts, shape_, data, print_v2);
      break;
    case DT_INT8:
    case DT_QINT8:
      return SummarizeArray<int8>(limit, num_elts, shape_, data, print_v2);
      break;
    case DT_UINT64:
      return SummarizeArray<uint64>(limit, num_elts, shape_, data, print_v2);
      break;
    case DT_INT64:
      return SummarizeArray<int64_t>(limit, num_elts, shape_, data, print_v2);
      break;
    case DT_BOOL:
      
      
      return SummarizeArray<bool>(limit, num_elts, shape_, data, print_v2);
      break;
    case DT_STRING:
      return SummarizeArray<tstring>(limit, num_elts, shape_, data, print_v2);
      break;
    default: {
      
      string ret;
      if (print_v2 && (dims() > 0)) {
        strings::StrAppend(&ret, "[");
      }
      
      
      for (size_t i = 0; i < limit; ++i) {
        if (i > 0) strings::StrAppend(&ret, " ");
        switch (dtype()) {
          case DT_VARIANT: {
            const Variant& v = flat<Variant>()(i);
            strings::StrAppend(&ret, "<", v.SummarizeValue(), ">");
          } break;
          case DT_RESOURCE: {
            const ResourceHandle& r = flat<ResourceHandle>()(i);
            strings::StrAppend(&ret, "<", r.SummarizeValue(), ">");
          } break;
          default:
            
            
            strings::StrAppend(&ret, "?");
        }
      }
      if (max_entries < num_elts) strings::StrAppend(&ret, "...");
      if (print_v2 && (dims() > 0)) {
        strings::StrAppend(&ret, "]");
      }
      return ret;
    }
  }
}

StringPiece Tensor::tensor_data() const {
  if (buf_ == nullptr) return StringPiece();  
  return StringPiece(static_cast<char*>(buf_->data()), TotalBytes());
}

void* Tensor::data() const {
  if (buf_ == nullptr) return nullptr;  
  return static_cast<void*>(buf_->data());
}

bool Tensor::SharesBufferWith(const Tensor& b) const {
  return buf_ != nullptr && b.buf_ != nullptr && buf_->root_buffer() == b.buf_->root_buffer();
}

string Tensor::DebugString(int num_values) const {
  return strings::StrCat("Tensor<type: ", DataTypeString(dtype()), " shape: ", shape().DebugString(), " values: ", SummarizeValue(num_values), ">");

}

string Tensor::DeviceSafeDebugString() const {
  return strings::StrCat("Tensor<type: ", DataTypeString(dtype()), " shape: ", shape().DebugString(), ">");
}

void Tensor::FillDescription(TensorDescription* description) const {
  description->set_dtype(dtype());
  shape().AsProto(description->mutable_shape());
  if (buf_ != nullptr && buf_->data() != nullptr) {
    buf_->FillAllocationDescription( description->mutable_allocation_description());
  }
}

gtl::InlinedVector<int64_t, 4> Tensor::ComputeFlatInnerDims( gtl::ArraySlice<int64_t> orig, int64_t num_out_dims) {
  gtl::InlinedVector<int64_t, 4> out_dims(num_out_dims, 0);
  int64_t offset = orig.size() - num_out_dims;
  for (int64_t out_dim = num_out_dims - 1; out_dim >= 0; --out_dim) {
    const int64_t in_dim = out_dim + offset;
    out_dims[out_dim] = in_dim < 0 ? 1 : orig[in_dim];
  }
  for (int64_t in_dim = 0; in_dim < offset; ++in_dim) {
    out_dims[0] *= orig[in_dim];
  }
  return out_dims;
}

gtl::InlinedVector<int64_t, 4> Tensor::ComputeFlatOuterDims( gtl::ArraySlice<int64_t> orig, int64_t num_out_dims) {
  gtl::InlinedVector<int64_t, 4> out_dims(num_out_dims, 0);
  for (int64_t out_dim = 0; out_dim <= num_out_dims - 1; ++out_dim) {
    out_dims[out_dim] = out_dim >= orig.size() ? 1 : orig[out_dim];
  }
  for (int64_t in_dim = num_out_dims; in_dim < orig.size(); ++in_dim) {
    out_dims[num_out_dims - 1] *= orig[in_dim];
  }
  return out_dims;
}

}  
