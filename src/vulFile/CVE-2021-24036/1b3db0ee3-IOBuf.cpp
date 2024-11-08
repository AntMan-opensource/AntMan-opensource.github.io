


























FOLLY_ATTR_WEAK void io_buf_alloc_cb(void* , size_t ) noexcept;
FOLLY_ATTR_WEAK void io_buf_free_cb(void* , size_t ) noexcept;

static void (*io_buf_alloc_cb)(void* , size_t ) noexcept = nullptr;
static void (*io_buf_free_cb)(void* , size_t ) noexcept = nullptr;


using std::unique_ptr;

namespace {

enum : uint16_t {
  kHeapMagic = 0xa5a5,  kIOBufInUse = 0x01,  kDataInUse = 0x02,  kSharedInfoInUse = 0x04, };







enum : std::size_t {
  
  
  
  
  
  
  
  
  
  kDefaultCombinedBufSize = 1024 };





void takeOwnershipError( bool freeOnError, void* buf, folly::IOBuf::FreeFunction freeFn, void* userData) noexcept {



  if (!freeOnError) {
    return;
  }
  if (!freeFn) {
    free(buf);
    return;
  }
  freeFn(buf, userData);
}

} 

namespace folly {



struct IOBuf::HeapPrefix {
  HeapPrefix(uint16_t flg, size_t sz)
      : magic(kHeapMagic), flags(flg), size((sz == ((size_t)(uint32_t)sz)) ? static_cast<uint32_t>(sz) : 0) {}

  ~HeapPrefix() {
    
    
    
    magic = 0;
  }

  uint16_t magic;
  std::atomic<uint16_t> flags;
  uint32_t size;
};

struct IOBuf::HeapStorage {
  HeapPrefix prefix;
  
  
  
  folly::IOBuf buf;
};

struct IOBuf::HeapFullStorage {
  
  
  static_assert(sizeof(HeapStorage) <= 64, "IOBuf may not grow over 56 bytes!");

  HeapStorage hs;
  SharedInfo shared;
  folly::max_align_t align;
};

IOBuf::SharedInfo::SharedInfo()
    : freeFn(nullptr), userData(nullptr), useHeapFullStorage(false) {
  
  
  refcount.store(1, std::memory_order_relaxed);
}

IOBuf::SharedInfo::SharedInfo(FreeFunction fn, void* arg, bool hfs)
    : freeFn(fn), userData(arg), useHeapFullStorage(hfs) {
  
  
  refcount.store(1, std::memory_order_relaxed);
}

void IOBuf::SharedInfo::invokeAndDeleteEachObserver( SharedInfoObserverEntryBase* observerListHead, ObserverCb cb) noexcept {
  if (observerListHead && cb) {
    
    observerListHead->prev->next = nullptr;
    auto entry = observerListHead;
    while (entry) {
      auto tmp = entry->next;
      cb(*entry);
      delete entry;
      entry = tmp;
    }
  }
}

void IOBuf::SharedInfo::releaseStorage(SharedInfo* info) noexcept {
  if (info->useHeapFullStorage) {
    auto storageAddr = reinterpret_cast<uint8_t*>(info) - offsetof(HeapFullStorage, shared);
    auto storage = reinterpret_cast<HeapFullStorage*>(storageAddr);
    info->~SharedInfo();
    IOBuf::releaseStorage(&storage->hs, kSharedInfoInUse);
  }
}

void* IOBuf::operator new(size_t size) {
  size_t fullSize = offsetof(HeapStorage, buf) + size;
  auto storage = static_cast<HeapStorage*>(checkedMalloc(fullSize));

  new (&storage->prefix) HeapPrefix(kIOBufInUse, fullSize);

  if (io_buf_alloc_cb) {
    io_buf_alloc_cb(storage, fullSize);
  }

  return &(storage->buf);
}

void* IOBuf::operator new(size_t , void* ptr) {
  return ptr;
}

void IOBuf::operator delete(void* ptr) {
  auto storageAddr = static_cast<uint8_t*>(ptr) - offsetof(HeapStorage, buf);
  auto storage = reinterpret_cast<HeapStorage*>(storageAddr);
  releaseStorage(storage, kIOBufInUse);
}

void IOBuf::operator delete(void* , void* ) {
  
  
  
}

void IOBuf::releaseStorage(HeapStorage* storage, uint16_t freeFlags) noexcept {
  CHECK_EQ(storage->prefix.magic, static_cast<uint16_t>(kHeapMagic));

  
  
  
  auto flags = storage->prefix.flags.load(std::memory_order_acquire);
  DCHECK_EQ((flags & freeFlags), freeFlags);

  while (true) {
    auto newFlags = uint16_t(flags & ~freeFlags);
    if (newFlags == 0) {
      
      size_t size = storage->prefix.size;
      
      storage->prefix.HeapPrefix::~HeapPrefix();
      if (FOLLY_LIKELY(size)) {
        if (io_buf_free_cb) {
          io_buf_free_cb(storage, size);
        }
        sizedFree(storage, size);
      } else {
        free(storage);
      }
      return;
    }

    
    
    auto ret = storage->prefix.flags.compare_exchange_weak( flags, newFlags, std::memory_order_acq_rel);
    if (ret) {
      
      return;
    }

    
    
    
  }
}

void IOBuf::freeInternalBuf(void* , void* userData) noexcept {
  auto storage = static_cast<HeapStorage*>(userData);
  releaseStorage(storage, kDataInUse);
}

IOBuf::IOBuf(CreateOp, std::size_t capacity)
    : next_(this), prev_(this), data_(nullptr), length_(0), flagsAndSharedInfo_(0) {



  SharedInfo* info;
  allocExtBuffer(capacity, &buf_, &info, &capacity_);
  setSharedInfo(info);
  data_ = buf_;
}

IOBuf::IOBuf( CopyBufferOp , const void* buf, std::size_t size, std::size_t headroom, std::size_t minTailroom)




    : IOBuf(CREATE, headroom + size + minTailroom) {
  advance(headroom);
  if (size > 0) {
    assert(buf != nullptr);
    memcpy(writableData(), buf, size);
    append(size);
  }
}

IOBuf::IOBuf( CopyBufferOp op, ByteRange br, std::size_t headroom, std::size_t minTailroom)



    : IOBuf(op, br.data(), br.size(), headroom, minTailroom) {}

unique_ptr<IOBuf> IOBuf::create(std::size_t capacity) {
  
  
  
  
  
  
  
  
  
  if (capacity <= kDefaultCombinedBufSize) {
    return createCombined(capacity);
  }

  
  
  
  if (canNallocx()) {
    auto mallocSize = goodMallocSize(capacity);
    
    size_t minSize = ((capacity + 7) & ~7) + sizeof(SharedInfo);
    
    if (mallocSize < minSize) {
      auto* buf = checkedMalloc(mallocSize);
      return takeOwnership(SIZED_FREE, buf, mallocSize, 0, 0);
    }
  }

  return createSeparate(capacity);
}

unique_ptr<IOBuf> IOBuf::createCombined(std::size_t capacity) {
  
  
  size_t requiredStorage = offsetof(HeapFullStorage, align) + capacity;
  size_t mallocSize = goodMallocSize(requiredStorage);
  auto storage = static_cast<HeapFullStorage*>(checkedMalloc(mallocSize));

  new (&storage->hs.prefix) HeapPrefix(kIOBufInUse | kDataInUse, mallocSize);
  new (&storage->shared) SharedInfo(freeInternalBuf, storage);

  if (io_buf_alloc_cb) {
    io_buf_alloc_cb(storage, mallocSize);
  }

  auto bufAddr = reinterpret_cast<uint8_t*>(&storage->align);
  uint8_t* storageEnd = reinterpret_cast<uint8_t*>(storage) + mallocSize;
  auto actualCapacity = size_t(storageEnd - bufAddr);
  unique_ptr<IOBuf> ret(new (&storage->hs.buf) IOBuf( InternalConstructor(), packFlagsAndSharedInfo(0, &storage->shared), bufAddr, actualCapacity, bufAddr, 0));





  return ret;
}

unique_ptr<IOBuf> IOBuf::createSeparate(std::size_t capacity) {
  return std::make_unique<IOBuf>(CREATE, capacity);
}

unique_ptr<IOBuf> IOBuf::createChain( size_t totalCapacity, std::size_t maxBufCapacity) {
  unique_ptr<IOBuf> out = create(std::min(totalCapacity, size_t(maxBufCapacity)));
  size_t allocatedCapacity = out->capacity();

  while (allocatedCapacity < totalCapacity) {
    unique_ptr<IOBuf> newBuf = create( std::min(totalCapacity - allocatedCapacity, size_t(maxBufCapacity)));
    allocatedCapacity += newBuf->capacity();
    out->prependChain(std::move(newBuf));
  }

  return out;
}

size_t IOBuf::goodSize(size_t minCapacity, CombinedOption combined) {
  if (combined == CombinedOption::DEFAULT) {
    combined = minCapacity <= kDefaultCombinedBufSize ? CombinedOption::COMBINED : CombinedOption::SEPARATE;

  }
  size_t overhead;
  if (combined == CombinedOption::COMBINED) {
    overhead = offsetof(HeapFullStorage, align);
  } else {
    
    minCapacity = (minCapacity + 7) & ~7;
    overhead = sizeof(SharedInfo);
  }
  size_t goodSize = folly::goodMallocSize(minCapacity + overhead);
  return goodSize - overhead;
}

IOBuf::IOBuf( TakeOwnershipOp, void* buf, std::size_t capacity, std::size_t offset, std::size_t length, FreeFunction freeFn, void* userData, bool freeOnError)







    : next_(this), prev_(this), data_(static_cast<uint8_t*>(buf) + offset), buf_(static_cast<uint8_t*>(buf)), length_(length), capacity_(capacity), flagsAndSharedInfo_( packFlagsAndSharedInfo(kFlagFreeSharedInfo, nullptr)) {






  
  
  DCHECK(!userData || (userData && freeFn));

  auto rollback = makeGuard([&] { 
    takeOwnershipError(freeOnError, buf, freeFn, userData);
  });
  setSharedInfo(new SharedInfo(freeFn, userData));
  rollback.dismiss();
}

IOBuf::IOBuf( TakeOwnershipOp, SizedFree, void* buf, std::size_t capacity, std::size_t offset, std::size_t length, bool freeOnError)






    : next_(this), prev_(this), data_(static_cast<uint8_t*>(buf) + offset), buf_(static_cast<uint8_t*>(buf)), length_(length), capacity_(capacity), flagsAndSharedInfo_( packFlagsAndSharedInfo(kFlagFreeSharedInfo, nullptr)) {






  auto rollback = makeGuard([&] { 
    takeOwnershipError(freeOnError, buf, nullptr, nullptr);
  });
  setSharedInfo(new SharedInfo(nullptr, reinterpret_cast<void*>(capacity)));
  rollback.dismiss();

  if (io_buf_alloc_cb && capacity) {
    io_buf_alloc_cb(buf, capacity);
  }
}

unique_ptr<IOBuf> IOBuf::takeOwnership( void* buf, std::size_t capacity, std::size_t offset, std::size_t length, FreeFunction freeFn, void* userData, bool freeOnError, TakeOwnershipOption option) {







  
  

  DCHECK( !userData || (userData && freeFn) || (userData && !freeFn && (option == TakeOwnershipOption::STORE_SIZE)));


  HeapFullStorage* storage = nullptr;
  auto rollback = makeGuard([&] {
    if (storage) {
      free(storage);
    }
    takeOwnershipError(freeOnError, buf, freeFn, userData);
  });

  size_t requiredStorage = sizeof(HeapFullStorage);
  size_t mallocSize = goodMallocSize(requiredStorage);
  storage = static_cast<HeapFullStorage*>(checkedMalloc(mallocSize));

  new (&storage->hs.prefix)
      HeapPrefix(kIOBufInUse | kSharedInfoInUse, mallocSize);
  new (&storage->shared)
      SharedInfo(freeFn, userData, true );

  auto result = unique_ptr<IOBuf>(new (&storage->hs.buf) IOBuf( InternalConstructor(), packFlagsAndSharedInfo(0, &storage->shared), static_cast<uint8_t*>(buf), capacity, static_cast<uint8_t*>(buf) + offset, length));






  rollback.dismiss();

  if (io_buf_alloc_cb) {
    io_buf_alloc_cb(storage, mallocSize);
    if (userData && !freeFn && (option == TakeOwnershipOption::STORE_SIZE)) {
      
      
      
      io_buf_alloc_cb(buf, capacity);
    }
  }

  return result;
}

IOBuf::IOBuf(WrapBufferOp, const void* buf, std::size_t capacity) noexcept : IOBuf( InternalConstructor(), 0,    static_cast<uint8_t*>(const_cast<void*>(buf)), capacity, static_cast<uint8_t*>(const_cast<void*>(buf)), capacity) {}










IOBuf::IOBuf(WrapBufferOp op, ByteRange br) noexcept : IOBuf(op, br.data(), br.size()) {}

unique_ptr<IOBuf> IOBuf::wrapBuffer(const void* buf, std::size_t capacity) {
  return std::make_unique<IOBuf>(WRAP_BUFFER, buf, capacity);
}

IOBuf IOBuf::wrapBufferAsValue(const void* buf, std::size_t capacity) noexcept {
  return IOBuf(WrapBufferOp::WRAP_BUFFER, buf, capacity);
}

IOBuf::IOBuf() noexcept = default;

IOBuf::IOBuf(IOBuf&& other) noexcept : data_(other.data_), buf_(other.buf_), length_(other.length_), capacity_(other.capacity_), flagsAndSharedInfo_(other.flagsAndSharedInfo_) {




  
  other.data_ = nullptr;
  other.buf_ = nullptr;
  other.length_ = 0;
  other.capacity_ = 0;
  other.flagsAndSharedInfo_ = 0;

  
  
  if (other.next_ != &other) {
    next_ = other.next_;
    next_->prev_ = this;
    other.next_ = &other;

    prev_ = other.prev_;
    prev_->next_ = this;
    other.prev_ = &other;
  }

  
  DCHECK_EQ(other.prev_, &other);
  DCHECK_EQ(other.next_, &other);
}

IOBuf::IOBuf(const IOBuf& other) {
  *this = other.cloneAsValue();
}

IOBuf::IOBuf( InternalConstructor, uintptr_t flagsAndSharedInfo, uint8_t* buf, std::size_t capacity, uint8_t* data, std::size_t length) noexcept : next_(this), prev_(this), data_(data), buf_(buf), length_(length), capacity_(capacity), flagsAndSharedInfo_(flagsAndSharedInfo) {












  assert(data >= buf);
  assert(data + length <= buf + capacity);

  CHECK(!folly::asan_region_is_poisoned(buf, capacity));
}

IOBuf::~IOBuf() {
  
  
  
  while (next_ != this) {
    
    
    (void)next_->unlink();
  }

  decrementRefcount();
}

IOBuf& IOBuf::operator=(IOBuf&& other) noexcept {
  if (this == &other) {
    return *this;
  }

  
  while (next_ != this) {
    
    
    (void)next_->unlink();
  }

  
  decrementRefcount();

  
  data_ = other.data_;
  buf_ = other.buf_;
  length_ = other.length_;
  capacity_ = other.capacity_;
  flagsAndSharedInfo_ = other.flagsAndSharedInfo_;
  
  other.data_ = nullptr;
  other.buf_ = nullptr;
  other.length_ = 0;
  other.capacity_ = 0;
  other.flagsAndSharedInfo_ = 0;

  
  
  if (other.next_ != &other) {
    next_ = other.next_;
    next_->prev_ = this;
    other.next_ = &other;

    prev_ = other.prev_;
    prev_->next_ = this;
    other.prev_ = &other;
  }

  
  DCHECK_EQ(other.prev_, &other);
  DCHECK_EQ(other.next_, &other);

  return *this;
}

IOBuf& IOBuf::operator=(const IOBuf& other) {
  if (this != &other) {
    *this = IOBuf(other);
  }
  return *this;
}

bool IOBuf::empty() const {
  const IOBuf* current = this;
  do {
    if (current->length() != 0) {
      return false;
    }
    current = current->next_;
  } while (current != this);
  return true;
}

size_t IOBuf::countChainElements() const {
  size_t numElements = 1;
  for (IOBuf* current = next_; current != this; current = current->next_) {
    ++numElements;
  }
  return numElements;
}

std::size_t IOBuf::computeChainDataLength() const {
  std::size_t fullLength = length_;
  for (IOBuf* current = next_; current != this; current = current->next_) {
    fullLength += current->length_;
  }
  return fullLength;
}

std::size_t IOBuf::computeChainCapacity() const {
  std::size_t fullCapacity = capacity_;
  for (IOBuf* current = next_; current != this; current = current->next_) {
    fullCapacity += current->capacity_;
  }
  return fullCapacity;
}

void IOBuf::prependChain(unique_ptr<IOBuf>&& iobuf) {
  
  IOBuf* other = iobuf.release();

  
  IOBuf* otherTail = other->prev_;

  
  
  prev_->next_ = other;
  other->prev_ = prev_;

  
  
  otherTail->next_ = this;
  prev_ = otherTail;
}

unique_ptr<IOBuf> IOBuf::clone() const {
  auto tmp = cloneOne();

  for (IOBuf* current = next_; current != this; current = current->next_) {
    tmp->prependChain(current->cloneOne());
  }

  return tmp;
}

unique_ptr<IOBuf> IOBuf::cloneOne() const {
  if (SharedInfo* info = sharedInfo()) {
    info->refcount.fetch_add(1, std::memory_order_acq_rel);
  }
  return std::unique_ptr<IOBuf>(new IOBuf( InternalConstructor(), flagsAndSharedInfo_, buf_, capacity_, data_, length_));





}

unique_ptr<IOBuf> IOBuf::cloneCoalesced() const {
  return std::make_unique<IOBuf>(cloneCoalescedAsValue());
}

unique_ptr<IOBuf> IOBuf::cloneCoalescedWithHeadroomTailroom( std::size_t newHeadroom, std::size_t newTailroom) const {
  return std::make_unique<IOBuf>( cloneCoalescedAsValueWithHeadroomTailroom(newHeadroom, newTailroom));
}

IOBuf IOBuf::cloneAsValue() const {
  auto tmp = cloneOneAsValue();

  for (IOBuf* current = next_; current != this; current = current->next_) {
    tmp.prependChain(current->cloneOne());
  }

  return tmp;
}

IOBuf IOBuf::cloneOneAsValue() const {
  if (SharedInfo* info = sharedInfo()) {
    info->refcount.fetch_add(1, std::memory_order_acq_rel);
  }
  return IOBuf( InternalConstructor(), flagsAndSharedInfo_, buf_, capacity_, data_, length_);





}

IOBuf IOBuf::cloneCoalescedAsValue() const {
  const std::size_t newHeadroom = headroom();
  const std::size_t newTailroom = prev()->tailroom();
  return cloneCoalescedAsValueWithHeadroomTailroom(newHeadroom, newTailroom);
}

IOBuf IOBuf::cloneCoalescedAsValueWithHeadroomTailroom( std::size_t newHeadroom, std::size_t newTailroom) const {
  if (!isChained() && newHeadroom <= headroom() && newTailroom <= tailroom()) {
    return cloneOneAsValue();
  }
  
  const std::size_t newLength = computeChainDataLength();
  const std::size_t newCapacity = newLength + newHeadroom + newTailroom;
  IOBuf newBuf{CREATE, newCapacity};
  newBuf.advance(newHeadroom);

  auto current = this;
  do {
    if (current->length() > 0) {
      DCHECK_NOTNULL(current->data());
      DCHECK_LE(current->length(), newBuf.tailroom());
      memcpy(newBuf.writableTail(), current->data(), current->length());
      newBuf.append(current->length());
    }
    current = current->next();
  } while (current != this);

  DCHECK_EQ(newLength, newBuf.length());
  DCHECK_EQ(newHeadroom, newBuf.headroom());
  DCHECK_LE(newTailroom, newBuf.tailroom());

  return newBuf;
}

void IOBuf::unshareOneSlow() {
  
  uint8_t* buf;
  SharedInfo* sharedInfo;
  std::size_t actualCapacity;
  allocExtBuffer(capacity_, &buf, &sharedInfo, &actualCapacity);

  
  
  
  std::size_t headlen = headroom();
  if (length_ > 0) {
    assert(data_ != nullptr);
    memcpy(buf + headlen, data_, length_);
  }

  
  decrementRefcount();
  
  setFlagsAndSharedInfo(0, sharedInfo);

  
  data_ = buf + headlen;
  buf_ = buf;
}

void IOBuf::unshareChained() {
  
  
  assert(isChained());

  IOBuf* current = this;
  while (true) {
    if (current->isSharedOne()) {
      
      break;
    }

    current = current->next_;
    if (current == this) {
      
      
      return;
    }
  }

  
  coalesceSlow();
}

void IOBuf::markExternallyShared() {
  IOBuf* current = this;
  do {
    current->markExternallySharedOne();
    current = current->next_;
  } while (current != this);
}

void IOBuf::makeManagedChained() {
  assert(isChained());

  IOBuf* current = this;
  while (true) {
    current->makeManagedOne();
    current = current->next_;
    if (current == this) {
      break;
    }
  }
}

void IOBuf::coalesceSlow() {
  
  
  DCHECK(isChained());

  
  std::size_t newLength = 0;
  IOBuf* end = this;
  do {
    newLength += end->length_;
    end = end->next_;
  } while (end != this);

  coalesceAndReallocate(newLength, end);
  
  DCHECK(!isChained());
}

void IOBuf::coalesceSlow(size_t maxLength) {
  
  
  DCHECK(isChained());
  DCHECK_LT(length_, maxLength);

  
  std::size_t newLength = 0;
  IOBuf* end = this;
  while (true) {
    newLength += end->length_;
    end = end->next_;
    if (newLength >= maxLength) {
      break;
    }
    if (end == this) {
      throw_exception<std::overflow_error>( "attempted to coalesce more data than " "available");

    }
  }

  coalesceAndReallocate(newLength, end);
  
  DCHECK_GE(length_, maxLength);
}

void IOBuf::coalesceAndReallocate( size_t newHeadroom, size_t newLength, IOBuf* end, size_t newTailroom) {
  std::size_t newCapacity = newLength + newHeadroom + newTailroom;

  
  
  
  uint8_t* newBuf;
  SharedInfo* newInfo;
  std::size_t actualCapacity;
  allocExtBuffer(newCapacity, &newBuf, &newInfo, &actualCapacity);

  
  uint8_t* newData = newBuf + newHeadroom;
  uint8_t* p = newData;
  IOBuf* current = this;
  size_t remaining = newLength;
  do {
    if (current->length_ > 0) {
      assert(current->length_ <= remaining);
      assert(current->data_ != nullptr);
      remaining -= current->length_;
      memcpy(p, current->data_, current->length_);
      p += current->length_;
    }
    current = current->next_;
  } while (current != end);
  assert(remaining == 0);

  
  decrementRefcount();

  
  setFlagsAndSharedInfo(0, newInfo);

  capacity_ = actualCapacity;
  buf_ = newBuf;
  data_ = newData;
  length_ = newLength;

  
  
  
  if (isChained()) {
    (void)separateChain(next_, current->prev_);
  }
}

void IOBuf::decrementRefcount() noexcept {
  
  
  SharedInfo* info = sharedInfo();
  if (!info) {
    return;
  }

  
  
  
  if (info->refcount.load(std::memory_order_acquire) > 1) {
    
    uint32_t newcnt = info->refcount.fetch_sub(1, std::memory_order_acq_rel);
    
    
    
    if (newcnt > 1) {
      return;
    }
  }

  
  
  bool useHeapFullStorage = info->useHeapFullStorage;

  
  freeExtBuffer();

  
  
  
  
  
  
  
  
  
  
  if (flags() & kFlagFreeSharedInfo) {
    delete info;
  } else {
    if (useHeapFullStorage) {
      SharedInfo::releaseStorage(info);
    }
  }
}

void IOBuf::reserveSlow(std::size_t minHeadroom, std::size_t minTailroom) {
  size_t newCapacity = (size_t)length_ + minHeadroom + minTailroom;
  DCHECK_LT(newCapacity, UINT32_MAX);

  
  
  
  DCHECK(!isSharedOne());

  
  
  
  
  
  
  
  
  
  
  
  
  
  
  if (headroom() + tailroom() >= minHeadroom + minTailroom) {
    uint8_t* newData = writableBuffer() + minHeadroom;
    memmove(newData, data_, length_);
    data_ = newData;
    return;
  }

  size_t newAllocatedCapacity = 0;
  uint8_t* newBuffer = nullptr;
  std::size_t newHeadroom = 0;
  std::size_t oldHeadroom = headroom();

  
  
  SharedInfo* info = sharedInfo();
  bool useHeapFullStorage = info && info->useHeapFullStorage;
  if (info && (info->freeFn == nullptr) && length_ != 0 && oldHeadroom >= minHeadroom) {
    size_t headSlack = oldHeadroom - minHeadroom;
    newAllocatedCapacity = goodExtBufferSize(newCapacity + headSlack);
    if (usingJEMalloc()) {
      
      
      
      
      
      if (headSlack * 4 <= newCapacity) {
        size_t allocatedCapacity = capacity() + sizeof(SharedInfo);
        void* p = buf_;
        if (allocatedCapacity >= jemallocMinInPlaceExpandable) {
          if (xallocx(p, newAllocatedCapacity, 0, 0) == newAllocatedCapacity) {
            if (io_buf_free_cb) {
              io_buf_free_cb(p, reinterpret_cast<size_t>(info->userData));
            }
            newBuffer = static_cast<uint8_t*>(p);
            newHeadroom = oldHeadroom;
            
            info->userData = reinterpret_cast<void*>(newAllocatedCapacity);
            if (io_buf_alloc_cb) {
              io_buf_alloc_cb(newBuffer, newAllocatedCapacity);
            }
          }
          
        }
      }
    } else { 
      size_t copySlack = capacity() - length_;
      if (copySlack * 2 <= length_) {
        void* p = realloc(buf_, newAllocatedCapacity);
        if (UNLIKELY(p == nullptr)) {
          throw_exception<std::bad_alloc>();
        }
        newBuffer = static_cast<uint8_t*>(p);
        newHeadroom = oldHeadroom;
      }
    }
  }

  
  
  if (newBuffer == nullptr) {
    newAllocatedCapacity = goodExtBufferSize(newCapacity);
    newBuffer = static_cast<uint8_t*>(checkedMalloc(newAllocatedCapacity));
    if (length_ > 0) {
      assert(data_ != nullptr);
      memcpy(newBuffer + minHeadroom, data_, length_);
    }
    if (sharedInfo()) {
      freeExtBuffer();
    }
    newHeadroom = minHeadroom;
  }

  std::size_t cap;
  initExtBuffer(newBuffer, newAllocatedCapacity, &info, &cap);

  if (flags() & kFlagFreeSharedInfo) {
    delete sharedInfo();
  } else {
    if (useHeapFullStorage) {
      SharedInfo::releaseStorage(sharedInfo());
    }
  }

  setFlagsAndSharedInfo(0, info);
  capacity_ = cap;
  buf_ = newBuffer;
  data_ = newBuffer + newHeadroom;
  
}




void IOBuf::freeExtBuffer() noexcept {
  SharedInfo* info = sharedInfo();
  DCHECK(info);

  
  
  auto observerListHead = info->observerListHead;
  info->observerListHead = nullptr;

  if (info->freeFn) {
    info->freeFn(buf_, info->userData);
  } else {
    
    size_t size = reinterpret_cast<size_t>(info->userData);
    if (size) {
      if (io_buf_free_cb) {
        io_buf_free_cb(buf_, size);
      }
      folly::sizedFree(buf_, size);
    } else {
      free(buf_);
    }
  }
  SharedInfo::invokeAndDeleteEachObserver( observerListHead, [](auto& entry) { entry.afterFreeExtBuffer(); });

  if (kIsMobile) {
    buf_ = nullptr;
  }
}

void IOBuf::allocExtBuffer( std::size_t minCapacity, uint8_t** bufReturn, SharedInfo** infoReturn, std::size_t* capacityReturn) {



  size_t mallocSize = goodExtBufferSize(minCapacity);
  auto buf = static_cast<uint8_t*>(checkedMalloc(mallocSize));
  initExtBuffer(buf, mallocSize, infoReturn, capacityReturn);

  
  
  (*infoReturn)->userData = reinterpret_cast<void*>(mallocSize);
  if (io_buf_alloc_cb) {
    io_buf_alloc_cb(buf, mallocSize);
  }

  *bufReturn = buf;
}

size_t IOBuf::goodExtBufferSize(std::size_t minCapacity) {
  
  
  
  
  size_t minSize = static_cast<size_t>(minCapacity) + sizeof(SharedInfo);
  
  
  minSize = (minSize + 7) & ~7;

  
  
  
  return goodMallocSize(minSize);
}

void IOBuf::initExtBuffer( uint8_t* buf, size_t mallocSize, SharedInfo** infoReturn, std::size_t* capacityReturn) {



  
  
  uint8_t* infoStart = (buf + mallocSize) - sizeof(SharedInfo);
  auto sharedInfo = new (infoStart) SharedInfo;

  *capacityReturn = std::size_t(infoStart - buf);
  *infoReturn = sharedInfo;
}

fbstring IOBuf::moveToFbString() {
  
  
  bool useHeapFullStorage = false;
  SharedInfoObserverEntryBase* observerListHead = nullptr;
  
  
  if (!sharedInfo() ||  sharedInfo()->freeFn || headroom() != 0 || tailroom() == 0 || isShared() || isChained()) {




    
    
    coalesceAndReallocate(0, computeChainDataLength(), this, 1);
  } else {
    auto info = sharedInfo();
    if (info) {
      
      
      
      useHeapFullStorage = info->useHeapFullStorage;
      
      
      
      
      observerListHead = info->observerListHead;
      info->observerListHead = nullptr;
    }
  }

  
  *writableTail() = 0;
  fbstring str( reinterpret_cast<char*>(writableData()), length(), capacity(), AcquireMallocatedString());




  if (io_buf_free_cb && sharedInfo() && sharedInfo()->userData) {
    io_buf_free_cb( writableData(), reinterpret_cast<size_t>(sharedInfo()->userData));
  }

  SharedInfo::invokeAndDeleteEachObserver( observerListHead, [](auto& entry) { entry.afterReleaseExtBuffer(); });

  if (flags() & kFlagFreeSharedInfo) {
    delete sharedInfo();
  } else {
    if (useHeapFullStorage) {
      SharedInfo::releaseStorage(sharedInfo());
    }
  }

  
  flagsAndSharedInfo_ = 0;
  buf_ = nullptr;
  clear();
  return str;
}

IOBuf::Iterator IOBuf::cbegin() const {
  return Iterator(this, this);
}

IOBuf::Iterator IOBuf::cend() const {
  return Iterator(nullptr, nullptr);
}

folly::fbvector<struct iovec> IOBuf::getIov() const {
  folly::fbvector<struct iovec> iov;
  iov.reserve(countChainElements());
  appendToIov(&iov);
  return iov;
}

void IOBuf::appendToIov(folly::fbvector<struct iovec>* iov) const {
  IOBuf const* p = this;
  do {
    
    if (p->length() > 0) {
      iov->push_back({(void*)p->data(), folly::to<size_t>(p->length())});
    }
    p = p->next();
  } while (p != this);
}

unique_ptr<IOBuf> IOBuf::wrapIov(const iovec* vec, size_t count) {
  unique_ptr<IOBuf> result = nullptr;
  for (size_t i = 0; i < count; ++i) {
    size_t len = vec[i].iov_len;
    void* data = vec[i].iov_base;
    if (len > 0) {
      auto buf = wrapBuffer(data, len);
      if (!result) {
        result = std::move(buf);
      } else {
        result->prependChain(std::move(buf));
      }
    }
  }
  if (UNLIKELY(result == nullptr)) {
    return create(0);
  }
  return result;
}

std::unique_ptr<IOBuf> IOBuf::takeOwnershipIov( const iovec* vec, size_t count, FreeFunction freeFn, void* userData, bool freeOnError) {




  unique_ptr<IOBuf> result = nullptr;
  for (size_t i = 0; i < count; ++i) {
    size_t len = vec[i].iov_len;
    void* data = vec[i].iov_base;
    if (len > 0) {
      auto buf = takeOwnership(data, len, freeFn, userData, freeOnError);
      if (!result) {
        result = std::move(buf);
      } else {
        result->prependChain(std::move(buf));
      }
    }
  }
  if (UNLIKELY(result == nullptr)) {
    return create(0);
  }
  return result;
}

IOBuf::FillIovResult IOBuf::fillIov(struct iovec* iov, size_t len) const {
  IOBuf const* p = this;
  size_t i = 0;
  size_t totalBytes = 0;
  while (i < len) {
    
    if (p->length() > 0) {
      iov[i].iov_base = const_cast<uint8_t*>(p->data());
      iov[i].iov_len = p->length();
      totalBytes += p->length();
      i++;
    }
    p = p->next();
    if (p == this) {
      return {i, totalBytes};
    }
  }
  return {0, 0};
}

uint32_t IOBuf::approximateShareCountOne() const {
  if (UNLIKELY(!sharedInfo())) {
    return 1U;
  }
  return sharedInfo()->refcount.load(std::memory_order_acquire);
}

size_t IOBufHash::operator()(const IOBuf& buf) const noexcept {
  folly::hash::SpookyHashV2 hasher;
  hasher.Init(0, 0);
  io::Cursor cursor(&buf);
  for (;;) {
    auto b = cursor.peekBytes();
    if (b.empty()) {
      break;
    }
    hasher.Update(b.data(), b.size());
    cursor.skip(b.size());
  }
  uint64_t h1;
  uint64_t h2;
  hasher.Final(&h1, &h2);
  return static_cast<std::size_t>(h1);
}

ordering IOBufCompare::impl(const IOBuf& a, const IOBuf& b) const noexcept {
  io::Cursor ca(&a);
  io::Cursor cb(&b);
  for (;;) {
    auto ba = ca.peekBytes();
    auto bb = cb.peekBytes();
    if (ba.empty() || bb.empty()) {
      return to_ordering(int(bb.empty()) - int(ba.empty()));
    }
    const size_t n = std::min(ba.size(), bb.size());
    DCHECK_GT(n, 0u);
    const ordering r = to_ordering(std::memcmp(ba.data(), bb.data(), n));
    if (r != ordering::eq) {
      return r;
    }
    
    ca.skip(n);
    cb.skip(n);
  }
}

} 
