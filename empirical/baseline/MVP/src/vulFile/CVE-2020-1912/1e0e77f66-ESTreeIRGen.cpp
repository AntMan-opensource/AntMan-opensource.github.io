







namespace hermes {
namespace irgen {




Instruction *emitLoad(IRBuilder &builder, Value *from, bool inhibitThrow) {
  if (auto *var = llvh::dyn_cast<Variable>(from)) {
    if (Variable::declKindNeedsTDZ(var->getDeclKind()) && var->getRelatedVariable()) {
      builder.createThrowIfUndefinedInst( builder.createLoadFrameInst(var->getRelatedVariable()));
    }
    return builder.createLoadFrameInst(var);
  } else if (auto *globalProp = llvh::dyn_cast<GlobalObjectProperty>(from)) {
    if (globalProp->isDeclared() || inhibitThrow)
      return builder.createLoadPropertyInst( builder.getGlobalObject(), globalProp->getName());
    else return builder.createTryLoadGlobalPropertyInst(globalProp);
  } else {
    llvm_unreachable("unvalid value to load from");
  }
}

Instruction * emitStore(IRBuilder &builder, Value *storedValue, Value *ptr, bool declInit) {
  if (auto *var = llvh::dyn_cast<Variable>(ptr)) {
    if (!declInit && Variable::declKindNeedsTDZ(var->getDeclKind()) && var->getRelatedVariable()) {
      
      builder.createThrowIfUndefinedInst( builder.createLoadFrameInst(var->getRelatedVariable()));
    }
    auto *store = builder.createStoreFrameInst(storedValue, var);
    if (declInit && Variable::declKindNeedsTDZ(var->getDeclKind()) && var->getRelatedVariable()) {
      builder.createStoreFrameInst( builder.getLiteralBool(true), var->getRelatedVariable());
    }

    return store;
  } else if (auto *globalProp = llvh::dyn_cast<GlobalObjectProperty>(ptr)) {
    if (globalProp->isDeclared() || !builder.getFunction()->isStrictMode())
      return builder.createStorePropertyInst( storedValue, builder.getGlobalObject(), globalProp->getName());
    else return builder.createTryStoreGlobalPropertyInst(storedValue, globalProp);
  } else {
    llvm_unreachable("unvalid value to load from");
  }
}


bool isConstantExpr(ESTree::Node *node) {
  
  switch (node->getKind()) {
    case ESTree::NodeKind::StringLiteral:
    case ESTree::NodeKind::NumericLiteral:
    case ESTree::NodeKind::NullLiteral:
    case ESTree::NodeKind::BooleanLiteral:
      return true;
    default:
      return false;
  }
}




IRBuilder &LReference::getBuilder() {
  return irgen_->Builder;
}

Value *LReference::emitLoad() {
  auto &builder = getBuilder();
  IRBuilder::ScopedLocationChange slc(builder, loadLoc_);

  switch (kind_) {
    case Kind::Empty:
      assert(false && "empty cannot be loaded");
      return builder.getLiteralUndefined();
    case Kind::Member:
      return builder.createLoadPropertyInst(base_, property_);
    case Kind::VarOrGlobal:
      return irgen::emitLoad(builder, base_);
    case Kind::Destructuring:
      assert(false && "destructuring cannot be loaded");
      return builder.getLiteralUndefined();
    case Kind::Error:
      return builder.getLiteralUndefined();
  }

  llvm_unreachable("invalid LReference kind");
}

void LReference::emitStore(Value *value) {
  auto &builder = getBuilder();

  switch (kind_) {
    case Kind::Empty:
      return;
    case Kind::Member:
      builder.createStorePropertyInst(value, base_, property_);
      return;
    case Kind::VarOrGlobal:
      irgen::emitStore(builder, value, base_, declInit_);
      return;
    case Kind::Error:
      return;
    case Kind::Destructuring:
      return irgen_->emitDestructuringAssignment( declInit_, destructuringTarget_, value);
  }

  llvm_unreachable("invalid LReference kind");
}

bool LReference::canStoreWithoutSideEffects() const {
  return kind_ == Kind::VarOrGlobal && llvh::isa<Variable>(base_);
}

Variable *LReference::castAsVariable() const {
  return kind_ == Kind::VarOrGlobal ? dyn_cast_or_null<Variable>(base_)
                                    : nullptr;
}
GlobalObjectProperty *LReference::castAsGlobalObjectProperty() const {
  return kind_ == Kind::VarOrGlobal ? dyn_cast_or_null<GlobalObjectProperty>(base_)
      : nullptr;
}




ESTreeIRGen::ESTreeIRGen( ESTree::Node *root, const DeclarationFileListTy &declFileList, Module *M, const ScopeChain &scopeChain)



    : Mod(M), Builder(Mod), instrumentIR_(M, Builder), Root(root), DeclarationFileList(declFileList), lexicalScopeChain(resolveScopeIdentifiers(scopeChain)), identEval_(Builder.createIdentifier("eval")), identLet_(Builder.createIdentifier("let")), identDefaultExport_(Builder.createIdentifier("?default")) {}








void ESTreeIRGen::doIt() {
  LLVM_DEBUG(dbgs() << "Processing top level program.\n");

  ESTree::ProgramNode *Program;

  Program = llvh::dyn_cast<ESTree::ProgramNode>(Root);

  if (!Program) {
    Builder.getModule()->getContext().getSourceErrorManager().error( SMLoc{}, "missing 'Program' AST node");
    return;
  }

  LLVM_DEBUG(dbgs() << "Found Program decl.\n");

  
  Function *topLevelFunction;

  
  
  llvh::Optional<FunctionContext> wrapperFunctionContext{};

  if (!lexicalScopeChain) {
    topLevelFunction = Builder.createTopLevelFunction( ESTree::isStrict(Program->strictness), Program->getSourceRange());
  } else {
    
    

    Function *wrapperFunction = Builder.createFunction( "", Function::DefinitionKind::ES5Function, ESTree::isStrict(Program->strictness), Program->getSourceRange(), true);





    
    wrapperFunctionContext.emplace(this, wrapperFunction, nullptr);

    
    genDummyFunction(wrapperFunction);

    
    materializeScopesInChain(wrapperFunction, lexicalScopeChain, -1);

    
    topLevelFunction = Builder.createFunction( "eval", Function::DefinitionKind::ES5Function, ESTree::isStrict(Program->strictness), Program->getSourceRange(), false);




  }

  Mod->setTopLevelFunction(topLevelFunction);

  
  FunctionContext topLevelFunctionContext{
      this, topLevelFunction, Program->getSemInfo()};

  
  
  
  
  
  llvh::SaveAndRestore<FunctionContext *> saveTopLevelContext( topLevelContext, !wrapperFunctionContext.hasValue() ? &topLevelFunctionContext : &wrapperFunctionContext.getValue());



  
  
  if (!lexicalScopeChain) {
    for (auto declFile : DeclarationFileList) {
      processDeclarationFile(declFile);
    }
  }

  emitFunctionPrologue( Program, Builder.createBasicBlock(topLevelFunction), InitES5CaptureState::Yes, DoEmitParameters::Yes);




  Value *retVal;
  {
    
    curFunction()->globalReturnRegister = Builder.createAllocStackInst(genAnonymousLabelName("ret"));
    Builder.createStoreStackInst( Builder.getLiteralUndefined(), curFunction()->globalReturnRegister);

    genBody(Program->_body);

    
    retVal = Builder.createLoadStackInst(curFunction()->globalReturnRegister);
  }

  emitFunctionEpilogue(retVal);
}

void ESTreeIRGen::doCJSModule( Function *topLevelFunction, sem::FunctionInfo *semInfo, uint32_t id, llvh::StringRef filename) {



  assert(Root && "no root in ESTreeIRGen");
  auto *func = cast<ESTree::FunctionExpressionNode>(Root);
  assert(func && "doCJSModule without a module");

  FunctionContext topLevelFunctionContext{this, topLevelFunction, semInfo};
  llvh::SaveAndRestore<FunctionContext *> saveTopLevelContext( topLevelContext, &topLevelFunctionContext);

  
  
  assert( !lexicalScopeChain && "Lexical scope chain not supported for CJS modules");

  for (auto declFile : DeclarationFileList) {
    processDeclarationFile(declFile);
  }

  Identifier functionName = Builder.createIdentifier("cjs_module");
  Function *newFunc = genES5Function(functionName, nullptr, func);

  Builder.getModule()->addCJSModule( id, Builder.createIdentifier(filename), newFunc);
}

static int getDepth(const std::shared_ptr<SerializedScope> chain) {
  int depth = 0;
  const SerializedScope *current = chain.get();
  while (current) {
    depth += 1;
    current = current->parentScope.get();
  }
  return depth;
}

std::pair<Function *, Function *> ESTreeIRGen::doLazyFunction( hbc::LazyCompilationData *lazyData) {
  
  
  
  Function *topLevel = Builder.createTopLevelFunction(lazyData->strictMode, {});

  FunctionContext topLevelFunctionContext{this, topLevel, nullptr};

  
  
  llvh::SaveAndRestore<FunctionContext *> saveTopLevelContext( topLevelContext, &topLevelFunctionContext);

  auto *node = cast<ESTree::FunctionLikeNode>(Root);

  
  
  
  
  
  
  
  lexicalScopeChain = lazyData->parentScope;
  materializeScopesInChain( topLevel, lexicalScopeChain, getDepth(lexicalScopeChain) - 1);

  
  
  
  Variable *parentVar = nullptr;
  if (lazyData->closureAlias.isValid()) {
    assert(lazyData->originalName.isValid() && "Original name invalid");
    assert( lazyData->originalName != lazyData->closureAlias && "Original name must be different from the alias");


    
    parentVar = cast<Variable>(nameTable_.lookup(lazyData->closureAlias));

    
    nameTable_.insert(lazyData->originalName, parentVar);
  }

  assert( !llvh::isa<ESTree::ArrowFunctionExpressionNode>(node) && "lazy compilation not supported for arrow functions");


  auto *func = genES5Function(lazyData->originalName, parentVar, node);
  addLexicalDebugInfo(func, topLevel, lexicalScopeChain);
  return {func, topLevel};
}

std::pair<Value *, bool> ESTreeIRGen::declareVariableOrGlobalProperty( Function *inFunc, VarDecl::Kind declKind, Identifier name) {


  Value *found = nameTable_.lookup(name);

  
  
  if (found) {
    if (auto *var = llvh::dyn_cast<Variable>(found)) {
      if (var->getParent()->getFunction() == inFunc)
        return {found, false};
    } else {
      assert( llvh::isa<GlobalObjectProperty>(found) && "Invalid value found in name table");

      if (inFunc->isGlobalScope())
        return {found, false};
    }
  }

  
  Value *res;
  if (inFunc->isGlobalScope() && declKind == VarDecl::Kind::Var) {
    res = Builder.createGlobalObjectProperty(name, true);
  } else {
    Variable::DeclKind vdc;
    if (declKind == VarDecl::Kind::Let)
      vdc = Variable::DeclKind::Let;
    else if (declKind == VarDecl::Kind::Const)
      vdc = Variable::DeclKind::Const;
    else {
      assert(declKind == VarDecl::Kind::Var);
      vdc = Variable::DeclKind::Var;
    }

    auto *var = Builder.createVariable(inFunc->getFunctionScope(), vdc, name);

    
    if (Variable::declKindNeedsTDZ(vdc) && Mod->getContext().getCodeGenerationSettings().enableTDZ) {
      llvh::SmallString<32> strBuf{"tdz$";
      strBuf.append(name.str());

      auto *related = Builder.createVariable( var->getParent(), Variable::DeclKind::Var, genAnonymousLabelName(strBuf));


      var->setRelatedVariable(related);
      related->setRelatedVariable(var);
    }

    res = var;
  }

  
  nameTable_.insert(name, res);
  return {res, true};
}

GlobalObjectProperty *ESTreeIRGen::declareAmbientGlobalProperty( Identifier name) {
  
  auto *prop = dyn_cast_or_null<GlobalObjectProperty>(nameTable_.lookup(name));
  if (prop)
    return prop;

  LLVM_DEBUG( llvh::dbgs() << "declaring ambient global property " << name << " " << name.getUnderlyingPointer() << "\n");


  prop = Builder.createGlobalObjectProperty(name, false);
  nameTable_.insertIntoScope(&topLevelContext->scope, name, prop);
  return prop;
}

namespace {


struct DeclHoisting {
  
  llvh::SmallVector<ESTree::VariableDeclaratorNode *, 8> decls{};

  
  
  llvh::SmallVector<ESTree::FunctionDeclarationNode *, 8> closures;

  explicit DeclHoisting() = default;
  ~DeclHoisting() = default;

  
  
  
  void collectDecls(ESTree::Node *V) {
    if (auto VD = llvh::dyn_cast<ESTree::VariableDeclaratorNode>(V)) {
      return decls.push_back(VD);
    }

    if (auto FD = llvh::dyn_cast<ESTree::FunctionDeclarationNode>(V)) {
      return closures.push_back(FD);
    }
  }

  bool shouldVisit(ESTree::Node *V) {
    
    collectDecls(V);

    
    
    if (llvh::isa<ESTree::FunctionDeclarationNode>(V) || llvh::isa<ESTree::FunctionExpressionNode>(V) || llvh::isa<ESTree::ArrowFunctionExpressionNode>(V))

      return false;
    return true;
  }

  void enter(ESTree::Node *V) {}
  void leave(ESTree::Node *V) {}
};

} 

void ESTreeIRGen::processDeclarationFile(ESTree::ProgramNode *programNode) {
  auto Program = dyn_cast_or_null<ESTree::ProgramNode>(programNode);
  if (!Program)
    return;

  DeclHoisting DH;
  Program->visit(DH);

  
  for (auto vd : DH.decls)
    declareAmbientGlobalProperty(getNameFieldFromID(vd->_id));
  for (auto fd : DH.closures)
    declareAmbientGlobalProperty(getNameFieldFromID(fd->_id));
}

Value *ESTreeIRGen::ensureVariableExists(ESTree::IdentifierNode *id) {
  assert(id && "id must be a valid Identifier node");
  Identifier name = getNameFieldFromID(id);

  
  if (auto *var = nameTable_.lookup(name))
    return var;

  if (curFunction()->function->isStrictMode()) {
    
    auto currentFunc = Builder.getInsertionBlock()->getParent();

    Builder.getModule()->getContext().getSourceErrorManager().warning( Warning::UndefinedVariable, id->getSourceRange(), Twine("the variable \"") + name.str() + "\" was not declared in " + currentFunc->getDescriptiveDefinitionKindStr() + " \"" + currentFunc->getInternalNameStr() + "\"");




  }

  
  return declareAmbientGlobalProperty(name);
}

Value *ESTreeIRGen::genMemberExpressionProperty( ESTree::MemberExpressionLikeNode *Mem) {
  
  
  
  
  
  

  if (getComputed(Mem)) {
    return genExpression(getProperty(Mem));
  }

  
  if (auto N = llvh::dyn_cast<ESTree::NumericLiteralNode>(getProperty(Mem))) {
    return Builder.getLiteralNumber(N->_value);
  }

  
  auto Id = cast<ESTree::IdentifierNode>(getProperty(Mem));

  Identifier fieldName = getNameFieldFromID(Id);
  LLVM_DEBUG( dbgs() << "Emitting direct label access to field '" << fieldName << "'\n");

  return Builder.getLiteralString(fieldName);
}

bool ESTreeIRGen::canCreateLRefWithoutSideEffects( hermes::ESTree::Node *target) {
  
  if (auto *iden = llvh::dyn_cast<ESTree::IdentifierNode>(target)) {
    return dyn_cast_or_null<Variable>( nameTable_.lookup(getNameFieldFromID(iden)));
  }

  return false;
}

LReference ESTreeIRGen::createLRef(ESTree::Node *node, bool declInit) {
  SMLoc sourceLoc = node->getDebugLoc();
  IRBuilder::ScopedLocationChange slc(Builder, sourceLoc);

  if (llvh::isa<ESTree::EmptyNode>(node)) {
    LLVM_DEBUG(dbgs() << "Creating an LRef for EmptyNode.\n");
    return LReference( LReference::Kind::Empty, this, false, nullptr, nullptr, sourceLoc);
  }

  
  if (auto *ME = llvh::dyn_cast<ESTree::MemberExpressionNode>(node)) {
    LLVM_DEBUG(dbgs() << "Creating an LRef for member expression.\n");
    Value *obj = genExpression(ME->_object);
    Value *prop = genMemberExpressionProperty(ME);
    return LReference( LReference::Kind::Member, this, false, obj, prop, sourceLoc);
  }

  
  if (auto *iden = llvh::dyn_cast<ESTree::IdentifierNode>(node)) {
    LLVM_DEBUG(dbgs() << "Creating an LRef for identifier.\n");
    LLVM_DEBUG( dbgs() << "Looking for identifier \"" << getNameFieldFromID(iden)
               << "\"\n");
    auto *var = ensureVariableExists(iden);
    return LReference( LReference::Kind::VarOrGlobal, this, declInit, var, nullptr, sourceLoc);
  }

  
  if (auto *V = llvh::dyn_cast<ESTree::VariableDeclarationNode>(node)) {
    LLVM_DEBUG(dbgs() << "Creating an LRef for variable declaration.\n");

    assert(V->_declarations.size() == 1 && "Malformed variable declaration");
    auto *decl = cast<ESTree::VariableDeclaratorNode>(&V->_declarations.front());

    return createLRef(decl->_id, true);
  }

  
  if (auto *pat = llvh::dyn_cast<ESTree::PatternNode>(node)) {
    return LReference(this, declInit, pat);
  }

  Builder.getModule()->getContext().getSourceErrorManager().error( node->getSourceRange(), "unsupported assignment target");

  return LReference( LReference::Kind::Error, this, false, nullptr, nullptr, sourceLoc);
}

Value *ESTreeIRGen::genHermesInternalCall( StringRef name, Value *thisValue, ArrayRef<Value *> args) {


  return Builder.createCallInst( Builder.createLoadPropertyInst( Builder.createTryLoadGlobalPropertyInst("HermesInternal"), name), thisValue, args);



}

Value *ESTreeIRGen::genBuiltinCall( hermes::BuiltinMethod::Enum builtinIndex, ArrayRef<Value *> args) {

  return Builder.createCallBuiltinInst(builtinIndex, args);
}

void ESTreeIRGen::emitEnsureObject(Value *value, StringRef message) {
  
  genBuiltinCall( BuiltinMethod::HermesBuiltin_ensureObject, {value, Builder.getLiteralString(message)});

}

Value *ESTreeIRGen::emitIteratorSymbol() {
  
  
  return Builder.createLoadPropertyInst( Builder.createTryLoadGlobalPropertyInst("Symbol"), "iterator");
}

ESTreeIRGen::IteratorRecordSlow ESTreeIRGen::emitGetIteratorSlow(Value *obj) {
  auto *method = Builder.createLoadPropertyInst(obj, emitIteratorSymbol());
  auto *iterator = Builder.createCallInst(method, obj, {});

  emitEnsureObject(iterator, "iterator is not an object");
  auto *nextMethod = Builder.createLoadPropertyInst(iterator, "next");

  return {iterator, nextMethod};
}

Value *ESTreeIRGen::emitIteratorNextSlow(IteratorRecordSlow iteratorRecord) {
  auto *nextResult = Builder.createCallInst( iteratorRecord.nextMethod, iteratorRecord.iterator, {});
  emitEnsureObject(nextResult, "iterator.next() did not return an object");
  return nextResult;
}

Value *ESTreeIRGen::emitIteratorCompleteSlow(Value *iterResult) {
  return Builder.createLoadPropertyInst(iterResult, "done");
}

Value *ESTreeIRGen::emitIteratorValueSlow(Value *iterResult) {
  return Builder.createLoadPropertyInst(iterResult, "value");
}

void ESTreeIRGen::emitIteratorCloseSlow( hermes::irgen::ESTreeIRGen::IteratorRecordSlow iteratorRecord, bool ignoreInnerException) {

  auto *haveReturn = Builder.createBasicBlock(Builder.getFunction());
  auto *noReturn = Builder.createBasicBlock(Builder.getFunction());

  auto *returnMethod = genBuiltinCall( BuiltinMethod::HermesBuiltin_getMethod, {iteratorRecord.iterator, Builder.getLiteralString("return")});

  Builder.createCompareBranchInst( returnMethod, Builder.getLiteralUndefined(), BinaryOperatorInst::OpKind::StrictlyEqualKind, noReturn, haveReturn);





  Builder.setInsertionBlock(haveReturn);
  if (ignoreInnerException) {
    emitTryCatchScaffolding( noReturn,  [this, returnMethod, &iteratorRecord]() {


          Builder.createCallInst(returnMethod, iteratorRecord.iterator, {});
        },  []() {},  [this](BasicBlock *nextBlock) {



          
          Builder.createCatchInst();
          Builder.createBranchInst(nextBlock);
        });
  } else {
    auto *innerResult = Builder.createCallInst(returnMethod, iteratorRecord.iterator, {});
    emitEnsureObject(innerResult, "iterator.return() did not return an object");
    Builder.createBranchInst(noReturn);
  }

  Builder.setInsertionBlock(noReturn);
}

ESTreeIRGen::IteratorRecord ESTreeIRGen::emitGetIterator(Value *obj) {
  
  auto *iterStorage = Builder.createAllocStackInst(genAnonymousLabelName("iter"));
  auto *sourceOrNext = Builder.createAllocStackInst(genAnonymousLabelName("sourceOrNext"));
  Builder.createStoreStackInst(obj, sourceOrNext);
  auto *iter = Builder.createIteratorBeginInst(sourceOrNext);
  Builder.createStoreStackInst(iter, iterStorage);
  return IteratorRecord{iterStorage, sourceOrNext};
}

void ESTreeIRGen::emitDestructuringAssignment( bool declInit, ESTree::PatternNode *target, Value *source) {


  if (auto *APN = llvh::dyn_cast<ESTree::ArrayPatternNode>(target))
    return emitDestructuringArray(declInit, APN, source);
  else if (auto *OPN = llvh::dyn_cast<ESTree::ObjectPatternNode>(target))
    return emitDestructuringObject(declInit, OPN, source);
  else {
    Mod->getContext().getSourceErrorManager().error( target->getSourceRange(), "unsupported destructuring target");
  }
}

void ESTreeIRGen::emitDestructuringArray( bool declInit, ESTree::ArrayPatternNode *targetPat, Value *source) {


  const IteratorRecord iteratorRecord = emitGetIterator(source);

  
  auto *iteratorDone = Builder.createAllocStackInst(genAnonymousLabelName("iterDone"));
  Builder.createStoreStackInst(Builder.getLiteralUndefined(), iteratorDone);

  auto *value = Builder.createAllocStackInst(genAnonymousLabelName("iterValue"));

  SharedExceptionHandler handler{};
  handler.exc = Builder.createAllocStackInst(genAnonymousLabelName("exc"));
  
  handler.exceptionBlock = Builder.createBasicBlock(Builder.getFunction());

  bool first = true;
  bool emittedRest = false;
  
  
  
  llvh::Optional<LReference> lref;

  
  
  auto storePreviousValue = [&lref, &handler, this, value]() {
    if (lref && !lref->isEmpty()) {
      if (lref->canStoreWithoutSideEffects()) {
        lref->emitStore(Builder.createLoadStackInst(value));
      } else {
        
        emitTryWithSharedHandler(&handler, [this, &lref, value]() {
          lref->emitStore(Builder.createLoadStackInst(value));
        });
      }
      lref.reset();
    }
  };

  for (auto &elem : targetPat->_elements) {
    ESTree::Node *target = &elem;
    ESTree::Node *init = nullptr;

    if (auto *rest = llvh::dyn_cast<ESTree::RestElementNode>(target)) {
      storePreviousValue();
      emitRestElement(declInit, rest, iteratorRecord, iteratorDone, &handler);
      emittedRest = true;
      break;
    }

    
    if (auto *assign = llvh::dyn_cast<ESTree::AssignmentPatternNode>(target)) {
      target = assign->_left;
      init = assign->_right;
    }

    
    
    
    if (canCreateLRefWithoutSideEffects(target)) {
      
      
      storePreviousValue();
      lref = createLRef(target, declInit);
    } else {
      
      
      if (lref && lref->canStoreWithoutSideEffects()) {
        lref->emitStore(Builder.createLoadStackInst(value));
        lref.reset();
      }
      emitTryWithSharedHandler( &handler, [this, &lref, value, target, declInit]() {
            
            if (lref && !lref->isEmpty())
              lref->emitStore(Builder.createLoadStackInst(value));
            lref = createLRef(target, declInit);
          });
    }

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

    auto *notDoneBlock = Builder.createBasicBlock(Builder.getFunction());
    auto *newValueBlock = Builder.createBasicBlock(Builder.getFunction());
    auto *nextBlock = Builder.createBasicBlock(Builder.getFunction());
    auto *getDefaultBlock = init ? Builder.createBasicBlock(Builder.getFunction()) : nullptr;
    auto *storeBlock = init ? Builder.createBasicBlock(Builder.getFunction()) : nullptr;

    Builder.createStoreStackInst(Builder.getLiteralUndefined(), value);

    
    if (first) {
      first = false;
      Builder.createBranchInst(notDoneBlock);
    } else {
      Builder.createCondBranchInst( Builder.createLoadStackInst(iteratorDone), nextBlock, notDoneBlock);
    }

    
    Builder.setInsertionBlock(notDoneBlock);
    auto *stepValue = emitIteratorNext(iteratorRecord);
    auto *stepDone = emitIteratorComplete(iteratorRecord);
    Builder.createStoreStackInst(stepDone, iteratorDone);
    Builder.createCondBranchInst( stepDone, init ? getDefaultBlock : nextBlock, newValueBlock);

    
    Builder.setInsertionBlock(newValueBlock);
    Builder.createStoreStackInst(stepValue, value);
    Builder.createBranchInst(nextBlock);

    
    Builder.setInsertionBlock(nextBlock);

    
    
    if (init) {
      
      
      
      Builder.createCondBranchInst( Builder.createBinaryOperatorInst( Builder.createLoadStackInst(value), Builder.getLiteralUndefined(), BinaryOperatorInst::OpKind::StrictlyNotEqualKind), storeBlock, getDefaultBlock);






      Identifier nameHint = llvh::isa<ESTree::IdentifierNode>(target)
          ? getNameFieldFromID(target)
          : Identifier{};

      
      Builder.setInsertionBlock(getDefaultBlock);
      Builder.createStoreStackInst(genExpression(init, nameHint), value);
      Builder.createBranchInst(storeBlock);

      
      Builder.setInsertionBlock(storeBlock);
    }
  }

  storePreviousValue();

  
  
  
  if (!emittedRest) {
    auto *notDoneBlock = Builder.createBasicBlock(Builder.getFunction());
    auto *doneBlock = Builder.createBasicBlock(Builder.getFunction());
    Builder.createCondBranchInst( Builder.createLoadStackInst(iteratorDone), doneBlock, notDoneBlock);

    Builder.setInsertionBlock(notDoneBlock);
    emitIteratorClose(iteratorRecord, false);
    Builder.createBranchInst(doneBlock);

    Builder.setInsertionBlock(doneBlock);
  }

  
  if (handler.emittedTry) {
    IRBuilder::SaveRestore saveRestore{Builder};
    Builder.setInsertionBlock(handler.exceptionBlock);

    auto *notDoneBlock = Builder.createBasicBlock(Builder.getFunction());
    auto *doneBlock = Builder.createBasicBlock(Builder.getFunction());

    Builder.createCondBranchInst( Builder.createLoadStackInst(iteratorDone), doneBlock, notDoneBlock);

    Builder.setInsertionBlock(notDoneBlock);
    emitIteratorClose(iteratorRecord, true);
    Builder.createBranchInst(doneBlock);

    Builder.setInsertionBlock(doneBlock);
    Builder.createThrowInst(Builder.createLoadStackInst(handler.exc));
  } else {
    
    
    handler.exceptionBlock->eraseFromParent();

    
    
    
    assert( !handler.exc->hasUsers() && "should not have any users if no try/catch was emitted");

    handler.exc->eraseFromParent();
  }
}

void ESTreeIRGen::emitRestElement( bool declInit, ESTree::RestElementNode *rest, hermes::irgen::ESTreeIRGen::IteratorRecord iteratorRecord, hermes::AllocStackInst *iteratorDone, SharedExceptionHandler *handler) {




  

  auto *notDoneBlock = Builder.createBasicBlock(Builder.getFunction());
  auto *newValueBlock = Builder.createBasicBlock(Builder.getFunction());
  auto *doneBlock = Builder.createBasicBlock(Builder.getFunction());

  llvh::Optional<LReference> lref;
  if (canCreateLRefWithoutSideEffects(rest->_argument)) {
    lref = createLRef(rest->_argument, declInit);
  } else {
    emitTryWithSharedHandler(handler, [this, &lref, rest, declInit]() {
      lref = createLRef(rest->_argument, declInit);
    });
  }

  auto *A = Builder.createAllocArrayInst({}, 0);
  auto *n = Builder.createAllocStackInst(genAnonymousLabelName("n"));

  
  Builder.createStoreStackInst(Builder.getLiteralPositiveZero(), n);

  Builder.createCondBranchInst( Builder.createLoadStackInst(iteratorDone), doneBlock, notDoneBlock);

  
  Builder.setInsertionBlock(notDoneBlock);
  auto *stepValue = emitIteratorNext(iteratorRecord);
  auto *stepDone = emitIteratorComplete(iteratorRecord);
  Builder.createStoreStackInst(stepDone, iteratorDone);
  Builder.createCondBranchInst(stepDone, doneBlock, newValueBlock);

  
  Builder.setInsertionBlock(newValueBlock);
  auto *nVal = Builder.createLoadStackInst(n);
  nVal->setType(Type::createNumber());
  
  
  
  
  
  
  emitTryWithSharedHandler(handler, [this, stepValue, A, nVal]() {
    Builder.createStorePropertyInst(stepValue, A, nVal);
  });
  
  auto add = Builder.createBinaryOperatorInst( nVal, Builder.getLiteralNumber(1), BinaryOperatorInst::OpKind::AddKind);
  add->setType(Type::createNumber());
  Builder.createStoreStackInst(add, n);
  Builder.createBranchInst(notDoneBlock);

  
  Builder.setInsertionBlock(doneBlock);
  if (lref->canStoreWithoutSideEffects()) {
    lref->emitStore(A);
  } else {
    emitTryWithSharedHandler(handler, [&lref, A]() { lref->emitStore(A); });
  }
}

void ESTreeIRGen::emitDestructuringObject( bool declInit, ESTree::ObjectPatternNode *target, Value *source) {


  
  llvh::SmallVector<Value *, 4> excludedItems{};

  if (target->_properties.empty() || llvh::isa<ESTree::RestElementNode>(target->_properties.front())) {
    
    

    
    
    
    
    
    auto *throwBB = Builder.createBasicBlock(Builder.getFunction());
    auto *doneBB = Builder.createBasicBlock(Builder.getFunction());

    
    Builder.createCondBranchInst( Builder.createBinaryOperatorInst( source, Builder.getLiteralNull(), BinaryOperatorInst::OpKind::EqualKind), throwBB, doneBB);






    Builder.setInsertionBlock(throwBB);
    genBuiltinCall( BuiltinMethod::HermesBuiltin_throwTypeError, {source, Builder.getLiteralString( "Cannot destructure 'undefined' or 'null'.")});



    
    
    Builder.createReturnInst(Builder.getLiteralUndefined());

    Builder.setInsertionBlock(doneBB);
  }

  for (auto &elem : target->_properties) {
    if (auto *rest = llvh::dyn_cast<ESTree::RestElementNode>(&elem)) {
      emitRestProperty(declInit, rest, excludedItems, source);
      break;
    }
    auto *propNode = cast<ESTree::PropertyNode>(&elem);

    ESTree::Node *valueNode = propNode->_value;
    ESTree::Node *init = nullptr;

    
    if (auto *assign = llvh::dyn_cast<ESTree::AssignmentPatternNode>(valueNode)) {
      valueNode = assign->_left;
      init = assign->_right;
    }

    Identifier nameHint = llvh::isa<ESTree::IdentifierNode>(valueNode)
        ? getNameFieldFromID(valueNode)
        : Identifier{};

    if (llvh::isa<ESTree::IdentifierNode>(propNode->_key) && !propNode->_computed) {
      Identifier key = getNameFieldFromID(propNode->_key);
      excludedItems.push_back(Builder.getLiteralString(key));
      auto *loadedValue = Builder.createLoadPropertyInst(source, key);
      createLRef(valueNode, declInit)
          .emitStore(emitOptionalInitialization(loadedValue, init, nameHint));
    } else {
      Value *key = genExpression(propNode->_key);
      excludedItems.push_back(key);
      auto *loadedValue = Builder.createLoadPropertyInst(source, key);
      createLRef(valueNode, declInit)
          .emitStore(emitOptionalInitialization(loadedValue, init, nameHint));
    }
  }
}

void ESTreeIRGen::emitRestProperty( bool declInit, ESTree::RestElementNode *rest, const llvh::SmallVectorImpl<Value *> &excludedItems, hermes::Value *source) {



  auto lref = createLRef(rest->_argument, declInit);

  
  HBCAllocObjectFromBufferInst::ObjectPropertyMap exMap{};
  llvh::SmallVector<Value *, 4> computedExcludedItems{};
  
  
  llvh::DenseSet<Literal *> keyDeDupeSet;
  auto *zeroValue = Builder.getLiteralPositiveZero();

  for (Value *key : excludedItems) {
    if (auto *lit = llvh::dyn_cast<Literal>(key)) {
      
      
      if (keyDeDupeSet.insert(lit).second) {
        exMap.emplace_back(std::make_pair(lit, zeroValue));
      }
    } else {
      
      
      computedExcludedItems.push_back(key);
    }
  }

  Value *excludedObj;
  if (excludedItems.empty()) {
    excludedObj = Builder.getLiteralUndefined();
  } else {
    
    
    auto excludedSizeHint = exMap.size() + computedExcludedItems.size();
    if (exMap.empty()) {
      excludedObj = Builder.createAllocObjectInst(excludedSizeHint);
    } else {
      excludedObj = Builder.createHBCAllocObjectFromBufferInst(exMap, excludedSizeHint);
    }
    for (Value *key : computedExcludedItems) {
      Builder.createStorePropertyInst(zeroValue, excludedObj, key);
    }
  }

  auto *restValue = genBuiltinCall( BuiltinMethod::HermesBuiltin_copyDataProperties, {Builder.createAllocObjectInst(0), source, excludedObj});


  lref.emitStore(restValue);
}

Value *ESTreeIRGen::emitOptionalInitialization( Value *value, ESTree::Node *init, Identifier nameHint) {


  if (!init)
    return value;

  auto *currentBlock = Builder.getInsertionBlock();
  auto *getDefaultBlock = Builder.createBasicBlock(Builder.getFunction());
  auto *storeBlock = Builder.createBasicBlock(Builder.getFunction());

  
  
  
  Builder.createCondBranchInst( Builder.createBinaryOperatorInst( value, Builder.getLiteralUndefined(), BinaryOperatorInst::OpKind::StrictlyNotEqualKind), storeBlock, getDefaultBlock);






  
  Builder.setInsertionBlock(getDefaultBlock);
  auto *defaultValue = genExpression(init, nameHint);
  auto *defaultResultBlock = Builder.getInsertionBlock();
  Builder.createBranchInst(storeBlock);

  
  Builder.setInsertionBlock(storeBlock);
  return Builder.createPhiInst( {value, defaultValue}, {currentBlock, defaultResultBlock});
}

std::shared_ptr<SerializedScope> ESTreeIRGen::resolveScopeIdentifiers( const ScopeChain &chain) {
  std::shared_ptr<SerializedScope> current{};
  for (auto it = chain.functions.rbegin(), end = chain.functions.rend();
       it < end;
       it++) {
    auto next = std::make_shared<SerializedScope>();
    next->variables.reserve(it->variables.size());
    for (auto var : it->variables) {
      next->variables.push_back(std::move(Builder.createIdentifier(var)));
    }
    next->parentScope = current;
    current = next;
  }
  return current;
}

void ESTreeIRGen::materializeScopesInChain( Function *wrapperFunction, const std::shared_ptr<const SerializedScope> &scope, int depth) {


  if (!scope)
    return;
  assert(depth < 1000 && "Excessive scope depth");

  
  materializeScopesInChain(wrapperFunction, scope->parentScope, depth - 1);

  
  
  
  
  
  
  
  if (scope->closureAlias.isValid()) {
    assert(scope->originalName.isValid() && "Original name invalid");
    assert( scope->originalName != scope->closureAlias && "Original name must be different from the alias");


    
    auto *closureVar = cast<Variable>(nameTable_.lookup(scope->closureAlias));

    
    nameTable_.insert(scope->originalName, closureVar);
  }

  
  ExternalScope *ES = Builder.createExternalScope(wrapperFunction, depth);
  for (auto variableId : scope->variables) {
    auto *variable = Builder.createVariable(ES, Variable::DeclKind::Var, variableId);
    nameTable_.insert(variableId, variable);
  }
}

namespace {
void buildDummyLexicalParent( IRBuilder &builder, Function *parent, Function *child) {


  
  
  auto *block = builder.createBasicBlock(parent);
  builder.setInsertionBlock(block);
  builder.createUnreachableInst();
  auto *inst = builder.createCreateFunctionInst(child);
  builder.createReturnInst(inst);
}
} 





void ESTreeIRGen::addLexicalDebugInfo( Function *child, Function *global, const std::shared_ptr<const SerializedScope> &scope) {


  if (!scope || !scope->parentScope) {
    buildDummyLexicalParent(Builder, global, child);
    return;
  }

  auto *current = Builder.createFunction( scope->originalName, Function::DefinitionKind::ES5Function, false, {}, false);





  for (auto &var : scope->variables) {
    Builder.createVariable( current->getFunctionScope(), Variable::DeclKind::Var, var);
  }

  buildDummyLexicalParent(Builder, current, child);
  addLexicalDebugInfo(current, global, scope->parentScope);
}

std::shared_ptr<SerializedScope> ESTreeIRGen::serializeScope( FunctionContext *ctx, bool includeGlobal) {

  
  
  
  if (!ctx || (ctx->function->isGlobalScope() && !includeGlobal))
    return lexicalScopeChain;

  auto scope = std::make_shared<SerializedScope>();
  auto *func = ctx->function;
  assert(func && "Missing function when saving scope");

  scope->originalName = func->getOriginalOrInferredName();
  if (auto *closure = func->getLazyClosureAlias()) {
    scope->closureAlias = closure->getName();
  }
  for (auto *var : func->getFunctionScope()->getVariables()) {
    scope->variables.push_back(var->getName());
  }
  scope->parentScope = serializeScope(ctx->getPreviousContext(), false);
  return scope;
}

} 
} 
