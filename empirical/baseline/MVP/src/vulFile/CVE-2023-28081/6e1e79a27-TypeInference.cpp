
















using namespace hermes;
using llvh::dbgs;
using llvh::SmallPtrSetImpl;

STATISTIC(NumTI, "Number of instructions type inferred");
STATISTIC(NumRT, "Number of call sites type inferred");
STATISTIC(NumPT, "Number of parameters type inferred");
STATISTIC( UniquePropertyValue, "Number of instances of loads where there is a " "unique store(own) to that value");



namespace {

class TypeInferenceImpl {
  
  
  CallGraphProvider *cgp_;

  
  
  bool inferCallInst(CallInst *CI);

  
  
  bool inferType(Instruction *I);

  
  
  bool inferParams(Function *F);

  
  bool inferLoadPropertyInst(LoadPropertyInst *LPI);

  bool runOnFunction(Function *F);

 public:
  bool runOnModule(Module *M);
};

static bool inferUnaryArith(UnaryOperatorInst *UOI, Type numberResultType) {
  Value *op = UOI->getSingleOperand();

  if (op->getType().isNumberType()) {
    UOI->setType(numberResultType);
    return true;
  }

  if (op->getType().isBigIntType()) {
    UOI->setType(Type::createBigInt());
    return true;
  }

  Type mayBeBigInt = op->getType().canBeBigInt() ? Type::createBigInt() : Type::createNoType();

  
  UOI->setType(Type::unionTy(numberResultType, mayBeBigInt));
  return true;
}

static bool inferUnaryArithDefault(UnaryOperatorInst *UOI) {
  
  
  
  return inferUnaryArith(UOI, Type::createNumber());
}

static bool inferTilde(UnaryOperatorInst *UOI) {
  
  
  
  return inferUnaryArith(UOI, Type::createInt32());
}
} 

static bool inferUnaryInst(UnaryOperatorInst *UOI) {
  using OpKind = UnaryOperatorInst::OpKind;

  switch (UOI->getOperatorKind()) {
    case OpKind::DeleteKind: 
      UOI->setType(Type::createBoolean());
      return true;
    case OpKind::VoidKind: 
      UOI->setType(Type::createUndefined());
      return true;
    case OpKind::TypeofKind: 
      UOI->setType(Type::createString());
      return true;
    
    
    case OpKind::IncKind: 
    
    
    case OpKind::DecKind: 
    
    case OpKind::MinusKind: 
      return inferUnaryArithDefault(UOI);
    
    case OpKind::PlusKind: 
      UOI->setType(Type::createNumber());
      return true;
    
    case OpKind::TildeKind: 
      return inferTilde(UOI);
    case OpKind::BangKind: 
      UOI->setType(Type::createBoolean());
      return true;
    default:
      break;
  }

  return false;
}



static Type inferMemoryLocationType(Value *addr) {
  bool first = true;
  Type T;

  for (auto *U : addr->getUsers()) {
    Value *storedVal = nullptr;

    switch (U->getKind()) {
      case ValueKind::StoreFrameInstKind: {
        auto *SF = cast<StoreFrameInst>(U);

        storedVal = SF->getValue();
        break;
      }

      case ValueKind::StoreStackInstKind: {
        auto *SS = cast<StoreStackInst>(U);
        storedVal = SS->getValue();
        break;
      }

      
      case ValueKind::LoadFrameInstKind:
      case ValueKind::LoadStackInstKind:
        continue;

      default:
        
        return Type::createAnyType();
    }

    if (!storedVal)
      continue;

    Type storedType = storedVal->getType();

    if (first) {
      
      T = storedType;
      first = false;
      continue;
    }

    T = Type::unionTy(T, storedType);
  }

  return T;
}

static bool inferMemoryType(Value *V) {
  Type T = inferMemoryLocationType(V);

  
  if (T.isProperSubsetOf(V->getType())) {
    V->setType(T);
    return true;
  }

  return false;
}

static bool inferLoadStackInst(LoadStackInst *LS) {
  Type T = LS->getSingleOperand()->getType();
  if (T.isProperSubsetOf(LS->getType())) {
    LS->setType(T);
    return true;
  }

  return false;
}

static bool inferLoadFrameInst(LoadFrameInst *LF) {
  Type T = LF->getLoadVariable()->getType();
  if (T.isProperSubsetOf(LF->getType())) {
    LF->setType(T);
    return true;
  }

  return false;
}



static void collectPHIInputs( SmallPtrSetImpl<Value *> &visited, SmallPtrSetImpl<Value *> &inputs, PhiInst *P) {


  
  if (!visited.insert(P).second)
    return;

  
  for (unsigned i = 0, e = P->getNumEntries(); i < e; i++) {
    auto E = P->getEntry(i);

    
    
    if (auto *PN = llvh::dyn_cast<PhiInst>(E.first)) {
      collectPHIInputs(visited, inputs, PN);
    } else {
      inputs.insert(E.first);
    }
  }
}

static bool inferPhiInstInst(PhiInst *P) {
  
  
  unsigned numEntries = P->getNumEntries();
  if (numEntries < 1)
    return false;

  llvh::SmallPtrSet<Value *, 8> visited;
  llvh::SmallPtrSet<Value *, 8> values;
  collectPHIInputs(visited, values, P);

  Type originalTy = P->getType();

  Type newTy;
  bool foundFirst = false;

  
  for (auto *input : values) {
    
    if (!foundFirst) {
      newTy = input->getType();
      foundFirst = true;
      continue;
    }

    Type T = input->getType();
    newTy = Type::unionTy(T, newTy);
  }

  if (newTy.isProperSubsetOf(originalTy)) {
    P->setType(newTy);
    return true;
  } else {
    return false;
  }
}

namespace {
static bool inferBinaryArith( BinaryOperatorInst *BOI, Type numberType = Type::createNumber()) {

  Type LeftTy = BOI->getLeftHandSide()->getType();
  Type RightTy = BOI->getRightHandSide()->getType();

  
  if (LeftTy.isNumberType() && RightTy.isNumberType()) {
    BOI->setType(numberType);
    return true;
  }

  
  if (LeftTy.isBigIntType() && RightTy.isBigIntType()) {
    BOI->setType(Type::createBigInt());
    return true;
  }

  Type mayBeBigInt = LeftTy.canBeBigInt() && RightTy.canBeBigInt()
      ? Type::createBigInt()
      : Type::createNoType();

  
  
  BOI->setType(Type::unionTy(numberType, mayBeBigInt));
  return true;
}

static bool inferBinaryBitwise(BinaryOperatorInst *BOI) {
  Type LeftTy = BOI->getLeftHandSide()->getType();
  Type RightTy = BOI->getRightHandSide()->getType();

  Type mayBeBigInt = LeftTy.canBeBigInt() && RightTy.canBeBigInt()
      ? Type::createBigInt()
      : Type::createNoType();

  
  
  BOI->setType(Type::unionTy(Type::createInt32(), mayBeBigInt));
  return true;
}
} 

static bool inferBinaryInst(BinaryOperatorInst *BOI) {
  switch (BOI->getOperatorKind()) {
    
    
    
    case BinaryOperatorInst::OpKind::EqualKind:
    case BinaryOperatorInst::OpKind::NotEqualKind:
    case BinaryOperatorInst::OpKind::StrictlyEqualKind:
    case BinaryOperatorInst::OpKind::StrictlyNotEqualKind:
    case BinaryOperatorInst::OpKind::LessThanKind:
    case BinaryOperatorInst::OpKind::LessThanOrEqualKind:
    case BinaryOperatorInst::OpKind::GreaterThanKind:
    case BinaryOperatorInst::OpKind::GreaterThanOrEqualKind:
    case BinaryOperatorInst::OpKind::InKind:
    case BinaryOperatorInst::OpKind::InstanceOfKind:
      
      
      
      BOI->setType(Type::createBoolean());
      return true;

    
    
    case BinaryOperatorInst::OpKind::DivideKind:
    case BinaryOperatorInst::OpKind::MultiplyKind:
    
    case BinaryOperatorInst::OpKind::SubtractKind:
    
    case BinaryOperatorInst::OpKind::LeftShiftKind:
    
    case BinaryOperatorInst::OpKind::RightShiftKind:
      return inferBinaryArith(BOI);

    case BinaryOperatorInst::OpKind::ModuloKind:
      return inferBinaryArith(BOI, Type::createInt32());

    
    case BinaryOperatorInst::OpKind::UnsignedRightShiftKind:
      BOI->setType(Type::createUint32());
      return true;

    
    
    case BinaryOperatorInst::OpKind::AddKind: {
      Type LeftTy = BOI->getLeftHandSide()->getType();
      Type RightTy = BOI->getRightHandSide()->getType();
      
      
      if (LeftTy.isStringType() || RightTy.isStringType()) {
        BOI->setType(Type::createString());
        return true;
      }

      
      if (LeftTy.isNumberType() && RightTy.isNumberType()) {
        BOI->setType(Type::createNumber());
        return true;
      }

      
      if (LeftTy.isBigIntType() && RightTy.isBigIntType()) {
        BOI->setType(Type::createBigInt());
        return true;
      }

      
      
      
      Type mayBeBigInt = (LeftTy.canBeBigInt() && RightTy.canBeBigInt())
          ? Type::createBigInt()
          : Type::createNoType();

      
      Type numeric = Type::unionTy(Type::createNumber(), mayBeBigInt);

      
      
      
      if (isSideEffectFree(LeftTy) && isSideEffectFree(RightTy) && !LeftTy.canBeString() && !RightTy.canBeString()) {
        BOI->setType(numeric);
        return true;
      }

      
      BOI->setType(Type::unionTy(numeric, Type::createString()));
      return false;
    }

    
    case BinaryOperatorInst::OpKind::AndKind:
    case BinaryOperatorInst::OpKind::OrKind:
    case BinaryOperatorInst::OpKind::XorKind:
      return inferBinaryBitwise(BOI);

    default:
      break;
  }
  return false;
}

static bool inferFunctionReturnType(Function *F) {
  Type originalTy = F->getType();
  Type returnTy;
  bool first = true;

  if (llvh::isa<GeneratorInnerFunction>(F)) {
    
    
    return false;
  }

  for (auto &bbit : *F) {
    for (auto &it : bbit) {
      Instruction *I = &it;
      if (auto *RI = llvh::dyn_cast<ReturnInst>(I)) {
        Type T = RI->getType();
        if (first) {
          returnTy = T;
          first = false;
        } else {
          returnTy = Type::unionTy(returnTy, T);
        }
      }
    }
  }
  if (returnTy.isProperSubsetOf(originalTy)) {
    F->setType(returnTy);
    return true;
  }
  return false;
}



static bool propagateArgs(llvh::DenseSet<CallInst *> &callSites, Function *F) {
  bool changed = false;

  
  
  
  
  
  
  if (!F->isStrictMode() && !F->getContext()
           .getOptimizationSettings()
           .aggressiveNonStrictModeOptimizations) {
    return changed;
  }

  IRBuilder builder(F);
  for (int i = 0, e = F->getParameters().size(); i < e; i++) {
    auto *P = F->getParameters()[i];

    Type paramTy;
    bool first = true;

    
    for (auto *call : callSites) {
      
      Value *arg = builder.getLiteralUndefined();

      
      unsigned argIdx = i + 1;

      
      if (argIdx < call->getNumArguments()) {
        arg = call->getArgument(argIdx);
      }

      if (first) {
        paramTy = arg->getType();
        first = false;
      } else {
        paramTy = Type::unionTy(paramTy, arg->getType());
      }
    }

    
    if (!first && paramTy.isProperSubsetOf(P->getType())) {
      P->setType(paramTy);
      LLVM_DEBUG( dbgs() << F->getInternalName().c_str() << "::" << P->getName().c_str()
                 << " changed to ");
      LLVM_DEBUG(paramTy.print(dbgs()));
      LLVM_DEBUG(dbgs() << "\n");
      changed = true;
    }
  }

  return changed;
}



bool TypeInferenceImpl::inferParams(Function *F) {
  bool changed;
  if (cgp_->hasUnknownCallsites(F)) {
    LLVM_DEBUG( dbgs() << F->getInternalName().str() << " has unknown call sites.\n");
    return false;
  }
  llvh::DenseSet<CallInst *> &callsites = cgp_->getKnownCallsites(F);
  LLVM_DEBUG( dbgs() << F->getInternalName().str() << " has " << callsites.size()
             << " call sites.\n");
  changed = propagateArgs(callsites, F);
  if (changed) {
    LLVM_DEBUG( dbgs() << "inferParams changed for function " << F->getInternalName().str() << "\n");

    NumPT++;
  }
  return changed;
}



static bool propagateReturn(llvh::DenseSet<Function *> &funcs, CallInst *CI) {
  bool changed = false;
  bool first = true;
  Type retTy;

  for (auto *F : funcs) {
    if (first) {
      retTy = F->getType();
      first = false;
    } else {
      retTy = Type::unionTy(retTy, F->getType());
    }
  }

  if (!first && retTy.isProperSubsetOf(CI->getType())) {
    CI->setType(retTy);
    LLVM_DEBUG(dbgs() << CI->getName().str() << " changed to ");
    LLVM_DEBUG(retTy.print(dbgs()));
    LLVM_DEBUG(dbgs() << "\n");
    changed = true;
  }

  return changed;
}



bool TypeInferenceImpl::inferCallInst(CallInst *CI) {
  bool changed = false;
  if (cgp_->hasUnknownCallees(CI)) {
    LLVM_DEBUG( dbgs() << "Unknown callees for : " << CI->getName().str() << "\n");
    return false;
  }
  llvh::DenseSet<Function *> &callees = cgp_->getKnownCallees(CI);
  LLVM_DEBUG( dbgs() << "Found " << callees.size()
             << " callees for : " << CI->getName().str() << "\n");
  changed = propagateReturn(callees, CI);
  if (changed) {
    LLVM_DEBUG(dbgs() << "inferCallInst changed!\n");
    NumRT++;
  }
  return changed;
}

static bool inferReturnInst(ReturnInst *RI) {
  Type originalTy = RI->getType();
  Value *operand = RI->getOperand(0);
  Type newTy = operand->getType();

  if (newTy.isProperSubsetOf(originalTy)) {
    RI->setType(newTy);
    return true;
  }
  return false;
}


static bool isOwnedProperty(AllocObjectInst *I, Value *prop) {
  for (auto *J : I->getUsers()) {
    if (auto *SOPI = llvh::dyn_cast<StoreOwnPropertyInst>(J)) {
      if (SOPI->getObject() == I) {
        if (prop == SOPI->getProperty())
          return true;
      }
    }
  }
  return false;
}

bool TypeInferenceImpl::inferLoadPropertyInst(LoadPropertyInst *LPI) {
  bool changed = false;
  bool first = true;
  Type retTy;
  Type originalTy = LPI->getType();
  bool unique = true;

  
  if (cgp_->hasUnknownReceivers(LPI))
    return false;

  
  for (auto *R : cgp_->getKnownReceivers(LPI)) {
    assert(llvh::isa<AllocObjectInst>(R));
    

    
    if (cgp_->hasUnknownStores(R))
      return false;

    Value *prop = LPI->getProperty();

    
    if (llvh::isa<AllocObjectInst>(R)) {
      if (!isOwnedProperty(cast<AllocObjectInst>(R), prop))
        return false;
    }

    
    for (auto *S : cgp_->getKnownStores(R)) {
      assert( llvh::isa<StoreOwnPropertyInst>(S) || llvh::isa<StorePropertyInst>(S));

      Value *storeVal = nullptr;

      if (llvh::isa<AllocObjectInst>(R)) {
        
        if (auto *SS = llvh::dyn_cast<StoreOwnPropertyInst>(S)) {
          storeVal = SS->getStoredValue();
          if (prop != SS->getProperty())
            continue;
        }
        if (auto *SS = llvh::dyn_cast<StorePropertyInst>(S)) {
          storeVal = SS->getStoredValue();
          if (prop != SS->getProperty())
            continue;
        }
      }

      if (llvh::isa<AllocArrayInst>(R)) {
        if (auto *SS = llvh::dyn_cast<StorePropertyInst>(S)) {
          storeVal = SS->getStoredValue();
        }
      }

      assert(storeVal != nullptr);

      if (first) {
        retTy = storeVal->getType();
        first = false;
      } else {
        retTy = Type::unionTy(retTy, storeVal->getType());
        unique = false;
      }
    }
  }
  if (!first && unique) {
    UniquePropertyValue++;
  }
  if (!first && retTy.isProperSubsetOf(originalTy)) {
    LPI->setType(retTy);
    return true;
  }
  return changed;
}



static bool inferThrowIfEmptyInst(ThrowIfEmptyInst *TIE) {
  TIE->setType( Type::subtractTy(TIE->getCheckedValue()->getType(), Type::createEmpty()));
  return true;
}





bool TypeInferenceImpl::inferType(Instruction *I) {
  Type originalTy = I->getType();

  switch (I->getKind()) {
    case ValueKind::BinaryOperatorInstKind:
      NumTI += inferBinaryInst(cast<BinaryOperatorInst>(I));
      return I->getType() != originalTy;

    case ValueKind::UnaryOperatorInstKind:
      NumTI += inferUnaryInst(cast<UnaryOperatorInst>(I));
      return I->getType() != originalTy;

    case ValueKind::PhiInstKind:
      NumTI += inferPhiInstInst(cast<PhiInst>(I));
      return I->getType() != originalTy;

    case ValueKind::AllocStackInstKind:
      NumTI += inferMemoryType(cast<AllocStackInst>(I));
      return I->getType() != originalTy;

    case ValueKind::LoadStackInstKind:
      NumTI += inferLoadStackInst(cast<LoadStackInst>(I));
      return I->getType() != originalTy;

    case ValueKind::LoadFrameInstKind:
      NumTI += inferLoadFrameInst(cast<LoadFrameInst>(I));
      return I->getType() != originalTy;

    case ValueKind::CallInstKind:
      NumTI += inferCallInst(cast<CallInst>(I));
      return I->getType() != originalTy;

    case ValueKind::ReturnInstKind:
      NumTI += inferReturnInst(cast<ReturnInst>(I));
      return I->getType() != originalTy;

    case ValueKind::LoadPropertyInstKind:
      NumTI += inferLoadPropertyInst(cast<LoadPropertyInst>(I));
      return I->getType() != originalTy;

    case ValueKind::ThrowIfEmptyInstKind:
      NumTI += inferThrowIfEmptyInst(cast<ThrowIfEmptyInst>(I));
      return I->getType() != originalTy;

    default:
      
      return false;
  }
}

bool TypeInferenceImpl::runOnFunction(Function *F) {
  bool changed = false;
  bool localChanged = false;

  LLVM_DEBUG( dbgs() << "\nStart Type Inference on " << F->getInternalName().c_str()
             << "\n");

  
  
  
  
  
  
  changed |= inferParams(F);

  
  
  
  do {
    localChanged = false;

    
    for (auto &bbit : *F) {
      for (auto &it : bbit) {
        Instruction *I = &it;
        localChanged |= inferType(I);
      }
    }

    
    
    localChanged |= inferFunctionReturnType(F);

    
    if (!F->isGlobalScope()) {
      for (auto *V : F->getFunctionScopeDesc()->getVariables()) {
        localChanged |= inferMemoryType(V);
      }
    }

    changed |= localChanged;
  } while (localChanged);

  return changed;
}

bool TypeInferenceImpl::runOnModule(Module *M) {
  bool changed = false;

  LLVM_DEBUG(dbgs() << "\nStart Type Inference on Module\n");

  for (auto &F : *M) {
    SimpleCallGraphProvider scgp(&F);
    cgp_ = &scgp;
    changed |= runOnFunction(&F);
  }
  return changed;
}

bool TypeInference::runOnModule(Module *M) {
  TypeInferenceImpl impl{};
  return impl.runOnModule(M);
}

std::unique_ptr<Pass> hermes::createTypeInference() {
  return std::make_unique<TypeInference>();
}


