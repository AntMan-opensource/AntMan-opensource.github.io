


















namespace hermes {
namespace vm {

using namespace hermes::inst;
using SLP = SerializedLiteralParser;



static void validateInstructions(ArrayRef<uint8_t> list, unsigned frameSize) {
  const OperandAddr32 listSize = (OperandAddr32)list.size();
  assert((size_t)listSize == list.size() && "more than 2GB instructions!");

  auto validateUInt8 = [](...) {};
  auto validateUInt16 = [](...) {};
  auto validateUInt32 = [](...) {};
  auto validateImm32 = [](...) {};
  auto validateDouble = [](...) {};
  auto validateReg8 = [&](OperandAddr32, OperandReg8 reg8) {
    assert(reg8 < frameSize && "invalid register index");
  };
  auto validateReg32 = [&](OperandAddr32, OperandReg32 reg32) {
    assert(reg32 < frameSize && "invalid register index");
  };
  auto validateAddr32 = [&](OperandAddr32 ip, OperandAddr32 offset) {
    
    assert( (offset < 0 ? ip + offset >= 0 : offset < listSize - ip) && "invalid jmp offset");

  };
  auto validateAddr8 = [&](OperandAddr32 ip, OperandAddr8 offset) {
    validateAddr32(ip, offset);
  };

  for (OperandAddr32 ip = 0; ip != listSize;) {
    assert(ip < listSize);
    auto *inst = reinterpret_cast<const Inst *>(&list[ip]);
    switch (inst->opCode) {













































      default:
        llvm_unreachable("invalid opcode");
    }
  }
}



CodeBlock *CodeBlock::createCodeBlock( RuntimeModule *runtimeModule, hbc::RuntimeFunctionHeader header, const uint8_t *bytecode, uint32_t functionID) {




  validateInstructions( {bytecode, header.bytecodeSizeInBytes()}, header.frameSize());


  
  
  
  
  auto sizeComputer = [](uint8_t highest) -> uint32_t {
    return highest == 0 ? 0 : highest + 1;
  };

  uint32_t readCacheSize = sizeComputer(header.highestReadCacheIndex());
  uint32_t cacheSize = readCacheSize + sizeComputer(header.highestWriteCacheIndex());


  bool isCodeBlockLazy = !bytecode;
  if (!runtimeModule->isInitialized() || isCodeBlockLazy) {
    readCacheSize = sizeComputer(std::numeric_limits<uint8_t>::max());
    cacheSize = 2 * readCacheSize;
  }


  return CodeBlock::create( runtimeModule, header, bytecode, functionID, cacheSize, readCacheSize);
}

int32_t CodeBlock::findCatchTargetOffset(uint32_t exceptionOffset) {
  return runtimeModule_->getBytecode()->findCatchTargetOffset( functionID_, exceptionOffset);
}

SLP CodeBlock::getArrayBufferIter(uint32_t idx, unsigned int numLiterals)
    const {
  return SLP{
      runtimeModule_->getBytecode()->getArrayBuffer().slice(idx), numLiterals, runtimeModule_};

}

SLP CodeBlock::getObjectBufferKeyIter(uint32_t idx, unsigned int numLiterals)
    const {
  return SLP{
      runtimeModule_->getBytecode()->getObjectKeyBuffer().slice(idx), numLiterals, nullptr};

}

SLP CodeBlock::getObjectBufferValueIter(uint32_t idx, unsigned int numLiterals)
    const {
  return SLP{
      runtimeModule_->getBytecode()->getObjectValueBuffer().slice(idx), numLiterals, runtimeModule_};

}

SymbolID CodeBlock::getNameMayAllocate() const {

  if (isLazy()) {
    return runtimeModule_->getLazyName();
  }

  return runtimeModule_->getSymbolIDFromStringIDMayAllocate( functionHeader_.functionName());
}

std::string CodeBlock::getNameString(GCBase::GCCallbacks &runtime) const {

  if (isLazy()) {
    return runtime.convertSymbolToUTF8(runtimeModule_->getLazyName());
  }

  return runtimeModule_->getStringFromStringID(functionHeader_.functionName());
}

OptValue<uint32_t> CodeBlock::getDebugSourceLocationsOffset() const {
  auto *debugOffsets = runtimeModule_->getBytecode()->getDebugOffsets(functionID_);
  if (!debugOffsets)
    return llvh::None;
  uint32_t ret = debugOffsets->sourceLocations;
  if (ret == hbc::DebugOffsets::NO_OFFSET)
    return llvh::None;
  return ret;
}

OptValue<hbc::DebugSourceLocation> CodeBlock::getSourceLocation( uint32_t offset) const {

  if (LLVM_UNLIKELY(isLazy())) {
    assert(offset == 0 && "Function is lazy, but debug offset >0 specified");

    auto *provider = (hbc::BCProviderLazy *)getRuntimeModule()->getBytecode();
    auto *func = provider->getBytecodeFunction();
    auto *lazyData = func->getLazyCompilationData();
    auto sourceLoc = lazyData->span.Start;

    SourceErrorManager::SourceCoords coords;
    if (!lazyData->context->getSourceErrorManager().findBufferLineAndLoc( sourceLoc, coords)) {
      return llvh::None;
    }

    hbc::DebugSourceLocation location;
    location.line = coords.line;
    location.column = coords.col;
    
    
    
    location.filenameId = facebook::hermes::debugger::kInvalidLocation;
    return location;
  }


  auto debugLocsOffset = getDebugSourceLocationsOffset();
  if (!debugLocsOffset) {
    return llvh::None;
  }

  return getRuntimeModule()
      ->getBytecode()
      ->getDebugInfo()
      ->getLocationForAddress(*debugLocsOffset, offset);
}

OptValue<uint32_t> CodeBlock::getFunctionSourceID() const {
  
  
  
  llvh::ArrayRef<std::pair<uint32_t, uint32_t>> table = runtimeModule_->getLazyRootModule()
          ->getBytecode()
          ->getFunctionSourceTable();

  
  
  
  auto it = std::lower_bound( table.begin(), table.end(), functionID_, [](std::pair<uint32_t, uint32_t> entry, uint32_t id) {



        return entry.first < id;
      });
  if (it == table.end() || it->first != functionID_) {
    return llvh::None;
  } else {
    return it->second;
  }
}

OptValue<uint32_t> CodeBlock::getDebugLexicalDataOffset() const {
  auto *debugOffsets = runtimeModule_->getBytecode()->getDebugOffsets(functionID_);
  if (!debugOffsets)
    return llvh::None;
  uint32_t ret = debugOffsets->lexicalData;
  if (ret == hbc::DebugOffsets::NO_OFFSET)
    return llvh::None;
  return ret;
}

SourceErrorManager::SourceCoords CodeBlock::getLazyFunctionLoc( bool start) const {
  assert(isLazy() && "Function must be lazy");
  SourceErrorManager::SourceCoords coords;

  auto *provider = (hbc::BCProviderLazy *)getRuntimeModule()->getBytecode();
  auto *func = provider->getBytecodeFunction();
  auto *lazyData = func->getLazyCompilationData();
  lazyData->context->getSourceErrorManager().findBufferLineAndLoc( start ? lazyData->span.Start : lazyData->span.End, coords);

  return coords;
}


namespace {
std::unique_ptr<hbc::BytecodeModule> compileLazyFunction( hbc::LazyCompilationData *lazyData) {
  assert(lazyData);
  LLVM_DEBUG( llvh::dbgs() << "Compiling lazy function " << lazyData->originalName << "\n");


  Module M{lazyData->context};
  auto pair = hermes::generateLazyFunctionIR(lazyData, &M);
  Function *entryPoint = pair.first;
  Function *lexicalRoot = pair.second;

  
  
  
  
  BytecodeGenerationOptions opts = BytecodeGenerationOptions::defaults();
  opts.stripSourceMappingURL = true;

  auto bytecodeModule = hbc::generateBytecodeModule(&M, lexicalRoot, entryPoint, opts);

  return bytecodeModule;
}
} 

void CodeBlock::lazyCompileImpl(Runtime &runtime) {
  assert(isLazy() && "Laziness has not been checked");
  PerfSection perf("Lazy function compilation");
  auto *provider = (hbc::BCProviderLazy *)runtimeModule_->getBytecode();
  auto *func = provider->getBytecodeFunction();
  auto *lazyData = func->getLazyCompilationData();
  auto bcModule = compileLazyFunction(lazyData);

  runtimeModule_->initializeLazyMayAllocate( hbc::BCProviderFromSrc::createBCProviderFromSrc(std::move(bcModule)));
  
  
  functionID_ = runtimeModule_->getBytecode()->getGlobalFunctionIndex();
  functionHeader_ = runtimeModule_->getBytecode()->getFunctionHeader(functionID_);
  bytecode_ = runtimeModule_->getBytecode()->getBytecode(functionID_);
}


void CodeBlock::markCachedHiddenClasses( Runtime &runtime, WeakRootAcceptor &acceptor) {

  for (auto &prop :
       llvh::makeMutableArrayRef(propertyCache(), propertyCacheSize_)) {
    if (prop.clazz) {
      acceptor.acceptWeak(prop.clazz);
    }
  }
}

uint32_t CodeBlock::getVirtualOffset() const {
  return getRuntimeModule()->getBytecode()->getVirtualOffsetForFunction( functionID_);
}



uint32_t CodeBlock::getNextOffset(uint32_t offset) const {
  auto opcodes = getOpcodeArray();
  assert(offset < opcodes.size() && "invalid offset to breakOnNextInstruction");

  auto opCode = reinterpret_cast<const Inst *>(&opcodes[offset])->opCode;
  assert(opCode < OpCode::_last && "invalid opcode");

  static const uint8_t sizes[] = {


  };

  return offset + sizes[(unsigned)opCode];
}



static void makeWritable(void *address, size_t length) {
  void *endAddress = static_cast<void *>(static_cast<char *>(address) + length);

  
  void *alignedAddress = reinterpret_cast<void *>(llvh::alignDown( reinterpret_cast<uintptr_t>(address), hermes::oscompat::page_size()));

  size_t totalLength = static_cast<char *>(endAddress) - static_cast<char *>(alignedAddress);

  bool success = oscompat::vm_protect( alignedAddress, totalLength, oscompat::ProtectMode::ReadWrite);
  if (!success) {
    hermes_fatal("mprotect failed before modifying breakpoint");
  }
}

void CodeBlock::installBreakpointAtOffset(uint32_t offset) {
  auto opcodes = getOpcodeArray();
  assert(offset < opcodes.size() && "patch offset out of bounds");
  hbc::opcode_atom_t *address = const_cast<hbc::opcode_atom_t *>(opcodes.begin() + offset);
  hbc::opcode_atom_t debuggerOpcode = static_cast<hbc::opcode_atom_t>(OpCode::Debugger);

  static_assert( sizeof(inst::DebuggerInst) == 1, "debugger instruction can only be a single opcode atom");


  makeWritable(address, sizeof(inst::DebuggerInst));
  *address = debuggerOpcode;
}

void CodeBlock::uninstallBreakpointAtOffset( uint32_t offset, hbc::opcode_atom_t opCode) {

  auto opcodes = getOpcodeArray();
  assert(offset < opcodes.size() && "unpatch offset out of bounds");
  hbc::opcode_atom_t *address = const_cast<hbc::opcode_atom_t *>(opcodes.begin() + offset);
  assert( *address == static_cast<hbc::opcode_atom_t>(OpCode::Debugger) && "can't uninstall a non-debugger instruction");


  
  
  *address = opCode;
}



} 
} 


