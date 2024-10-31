





namespace hermes {
namespace irgen {




FunctionContext::FunctionContext( ESTreeIRGen *irGen, Function *function, sem::FunctionInfo *semInfo)


    : irGen_(irGen), semInfo_(semInfo), oldContext_(irGen->functionContext_), builderSaveState_(irGen->Builder), function(function), scope(irGen->nameTable_) {




  irGen->functionContext_ = this;

  
  this->capturedNewTarget = irGen->Builder.getLiteralUndefined();

  if (semInfo_) {
    
    
    
    
    labels_.resize(semInfo_->labelCount);
  }
}

FunctionContext::~FunctionContext() {
  irGen_->functionContext_ = oldContext_;
}

Identifier FunctionContext::genAnonymousLabelName(StringRef hint) {
  llvh::SmallString<16> buf;
  llvh::raw_svector_ostream nameBuilder{buf};
  nameBuilder << "?anon_" << anonymousLabelCounter++ << "_" << hint;
  return function->getContext().getIdentifier(nameBuilder.str());
}




void ESTreeIRGen::genFunctionDeclaration( ESTree::FunctionDeclarationNode *func) {
  if (func->_async) {
    Builder.getModule()->getContext().getSourceErrorManager().error( func->getSourceRange(), Twine("async functions are unsupported"));
    return;
  }

  
  Identifier functionName = getNameFieldFromID(func->_id);
  LLVM_DEBUG(dbgs() << "IRGen function \"" << functionName << "\".\n");

  auto *funcStorage = nameTable_.lookup(functionName);
  assert( funcStorage && "function declaration variable should have been hoisted");

  Function *newFunc = func->_generator ? genGeneratorFunction(functionName, nullptr, func)
      : genES5Function(functionName, nullptr, func);

  
  auto *newClosure = Builder.createCreateFunctionInst(newFunc);

  emitStore(Builder, newClosure, funcStorage, true);
}

Value *ESTreeIRGen::genFunctionExpression( ESTree::FunctionExpressionNode *FE, Identifier nameHint) {

  if (FE->_async) {
    Builder.getModule()->getContext().getSourceErrorManager().error( FE->getSourceRange(), Twine("async functions are unsupported"));
    return Builder.getLiteralUndefined();
  }

  LLVM_DEBUG( dbgs() << "Creating anonymous closure. " << Builder.getInsertionBlock()->getParent()->getInternalName()

             << ".\n");

  NameTableScopeTy newScope(nameTable_);
  Variable *tempClosureVar = nullptr;

  Identifier originalNameIden = nameHint;
  if (FE->_id) {
    auto closureName = genAnonymousLabelName("closure");
    tempClosureVar = Builder.createVariable( curFunction()->function->getFunctionScope(), Variable::DeclKind::Var, closureName);



    
    
    nameTable_.insertIntoScope( &curFunction()->scope, tempClosureVar->getName(), tempClosureVar);

    
    originalNameIden = getNameFieldFromID(FE->_id);
    nameTable_.insert(originalNameIden, tempClosureVar);
  }

  Function *newFunc = FE->_generator ? genGeneratorFunction(originalNameIden, tempClosureVar, FE)
      : genES5Function(originalNameIden, tempClosureVar, FE);

  Value *closure = Builder.createCreateFunctionInst(newFunc);

  if (tempClosureVar)
    emitStore(Builder, closure, tempClosureVar, true);

  return closure;
}

Value *ESTreeIRGen::genArrowFunctionExpression( ESTree::ArrowFunctionExpressionNode *AF, Identifier nameHint) {

  LLVM_DEBUG( dbgs() << "Creating arrow function. " << Builder.getInsertionBlock()->getParent()->getInternalName()

             << ".\n");

  if (AF->_async) {
    Builder.getModule()->getContext().getSourceErrorManager().error( AF->getSourceRange(), Twine("async functions are unsupported"));
    return Builder.getLiteralUndefined();
  }

  auto *newFunc = Builder.createFunction( nameHint, Function::DefinitionKind::ES6Arrow, ESTree::isStrict(AF->strictness), AF->getSourceRange());




  {
    FunctionContext newFunctionContext{this, newFunc, AF->getSemInfo()};

    
    auto *prev = curFunction()->getPreviousContext();
    curFunction()->capturedThis = prev->capturedThis;
    curFunction()->capturedNewTarget = prev->capturedNewTarget;
    curFunction()->capturedArguments = prev->capturedArguments;

    emitFunctionPrologue( AF, Builder.createBasicBlock(newFunc), InitES5CaptureState::No, DoEmitParameters::Yes);




    genStatement(AF->_body);
    emitFunctionEpilogue(Builder.getLiteralUndefined());
  }

  
  return Builder.createCreateFunctionInst(newFunc);
}


namespace {
ESTree::NodeKind getLazyFunctionKind(ESTree::FunctionLikeNode *node) {
  if (node->isMethodDefinition) {
    
    
    
    return ESTree::NodeKind::Property;
  }
  return node->getKind();
}
} 
Function *ESTreeIRGen::genES5Function( Identifier originalName, Variable *lazyClosureAlias, ESTree::FunctionLikeNode *functionNode, bool isGeneratorInnerFunction) {



  assert(functionNode && "Function AST cannot be null");

  auto *body = ESTree::getBlockStatement(functionNode);
  assert(body && "body of ES5 function cannot be null");

  Function *newFunction = isGeneratorInnerFunction ? Builder.createGeneratorInnerFunction( originalName, Function::DefinitionKind::ES5Function, ESTree::isStrict(functionNode->strictness), functionNode->getSourceRange(), nullptr)





      : Builder.createFunction( originalName, Function::DefinitionKind::ES5Function, ESTree::isStrict(functionNode->strictness), functionNode->getSourceRange(), false, nullptr);






  newFunction->setLazyClosureAlias(lazyClosureAlias);

  if (auto *bodyBlock = llvh::dyn_cast<ESTree::BlockStatementNode>(body)) {
    if (bodyBlock->isLazyFunctionBody) {
      
      newFunction->setLazyScope(saveCurrentScope());
      auto &lazySource = newFunction->getLazySource();
      lazySource.bufferId = bodyBlock->bufferId;
      lazySource.nodeKind = getLazyFunctionKind(functionNode);
      lazySource.functionRange = functionNode->getSourceRange();

      
      newFunction->setExpectedParamCountIncludingThis( countExpectedArgumentsIncludingThis(functionNode));
      return newFunction;
    }
  }

  FunctionContext newFunctionContext{
      this, newFunction, functionNode->getSemInfo()};

  if (isGeneratorInnerFunction) {
    
    
    
    auto *initGenBB = Builder.createBasicBlock(newFunction);
    Builder.setInsertionBlock(initGenBB);
    Builder.createStartGeneratorInst();
    auto *prologueBB = Builder.createBasicBlock(newFunction);
    auto *prologueResumeIsReturn = Builder.createAllocStackInst( genAnonymousLabelName("isReturn_prologue"));
    genResumeGenerator(nullptr, prologueResumeIsReturn, prologueBB);

    if (hasSimpleParams(functionNode)) {
      
      
      Builder.setInsertionBlock(prologueBB);
      emitFunctionPrologue( functionNode, prologueBB, InitES5CaptureState::Yes, DoEmitParameters::Yes);



    } else {
      
      
      
      auto *entryPointBB = Builder.createBasicBlock(newFunction);
      auto *entryPointResumeIsReturn = Builder.createAllocStackInst(genAnonymousLabelName("isReturn_entry"));

      
      Builder.setInsertionBlock(prologueBB);
      emitFunctionPrologue( functionNode, prologueBB, InitES5CaptureState::Yes, DoEmitParameters::Yes);



      Builder.createSaveAndYieldInst( Builder.getLiteralUndefined(), entryPointBB);

      
      Builder.setInsertionBlock(entryPointBB);
      genResumeGenerator( nullptr, entryPointResumeIsReturn, Builder.createBasicBlock(newFunction));


    }
  } else {
    emitFunctionPrologue( functionNode, Builder.createBasicBlock(newFunction), InitES5CaptureState::Yes, DoEmitParameters::Yes);



  }

  genStatement(body);
  emitFunctionEpilogue(Builder.getLiteralUndefined());

  return curFunction()->function;
}


Function *ESTreeIRGen::genGeneratorFunction( Identifier originalName, Variable *lazyClosureAlias, ESTree::FunctionLikeNode *functionNode) {


  assert(functionNode && "Function AST cannot be null");

  
  
  auto *outerFn = Builder.createGeneratorFunction( originalName, Function::DefinitionKind::ES5Function, ESTree::isStrict(functionNode->strictness), nullptr);




  auto *innerFn = genES5Function( genAnonymousLabelName(originalName.isValid() ? originalName.str() : ""), lazyClosureAlias, functionNode, true);




  {
    FunctionContext outerFnContext{this, outerFn, functionNode->getSemInfo()};
    emitFunctionPrologue( functionNode, Builder.createBasicBlock(outerFn), InitES5CaptureState::Yes, DoEmitParameters::No);




    
    auto *gen = Builder.createCreateGeneratorInst(innerFn);

    if (!hasSimpleParams(functionNode)) {
      
      
      Value *next = Builder.createLoadPropertyInst(gen, "next");
      Builder.createCallInst(next, gen, {});
    }

    emitFunctionEpilogue(gen);
  }

  return outerFn;
}

void ESTreeIRGen::initCaptureStateInES5FunctionHelper() {
  
  if (!curFunction()->getSemInfo()->containsArrowFunctions)
    return;

  auto *scope = curFunction()->function->getFunctionScope();

  
  curFunction()->capturedThis = Builder.createVariable( scope, Variable::DeclKind::Var, genAnonymousLabelName("this"));
  emitStore( Builder, Builder.getFunction()->getThisParameter(), curFunction()->capturedThis, true);




  
  curFunction()->capturedNewTarget = Builder.createVariable( scope, Variable::DeclKind::Var, genAnonymousLabelName("new.target"));
  emitStore( Builder, Builder.createGetNewTargetInst(), curFunction()->capturedNewTarget, true);




  
  if (curFunction()->getSemInfo()->containsArrowFunctionsUsingArguments) {
    curFunction()->capturedArguments = Builder.createVariable( scope, Variable::DeclKind::Var, genAnonymousLabelName("arguments"));
    emitStore( Builder, curFunction()->createArgumentsInst, curFunction()->capturedArguments, true);



  }
}

void ESTreeIRGen::emitFunctionPrologue( ESTree::FunctionLikeNode *funcNode, BasicBlock *entry, InitES5CaptureState doInitES5CaptureState, DoEmitParameters doEmitParameters) {



  auto *newFunc = curFunction()->function;
  auto *semInfo = curFunction()->getSemInfo();
  LLVM_DEBUG( dbgs() << "Hoisting " << (semInfo->varDecls.size() + semInfo->closures.size())

             << " variable decls.\n");

  Builder.setLocation(newFunc->getSourceRange().Start);

  
  Builder.setInsertionBlock(entry);

  
  
  curFunction()->createArgumentsInst = Builder.createCreateArgumentsInst();

  
  
  for (auto decl : semInfo->varDecls) {
    auto res = declareVariableOrGlobalProperty( newFunc, decl.kind, getNameFieldFromID(decl.identifier));
    
    auto *var = llvh::dyn_cast<Variable>(res.first);
    if (!var || !res.second)
      continue;

    
    Builder.createStoreFrameInst(Builder.getLiteralUndefined(), var);
    if (var->getRelatedVariable()) {
      Builder.createStoreFrameInst( Builder.getLiteralUndefined(), var->getRelatedVariable());
    }
  }
  for (auto *fd : semInfo->closures) {
    declareVariableOrGlobalProperty( newFunc, VarDecl::Kind::Var, getNameFieldFromID(fd->_id));
  }

  
  
  Builder.createParameter(newFunc, "this");

  if (doInitES5CaptureState != InitES5CaptureState::No)
    initCaptureStateInES5FunctionHelper();

  
  
  if (doEmitParameters == DoEmitParameters::Yes) {
    emitParameters(funcNode);
  } else {
    newFunc->setExpectedParamCountIncludingThis( countExpectedArgumentsIncludingThis(funcNode));
  }

  
  
  for (auto importDecl : semInfo->imports) {
    genImportDeclaration(importDecl);
  }

  
  
  for (auto funcDecl : semInfo->closures) {
    genFunctionDeclaration(funcDecl);
  }
}

void ESTreeIRGen::emitParameters(ESTree::FunctionLikeNode *funcNode) {
  auto *newFunc = curFunction()->function;

  LLVM_DEBUG(dbgs() << "IRGen function parameters.\n");

  
  for (auto paramDecl : funcNode->getSemInfo()->paramNames) {
    Identifier paramName = getNameFieldFromID(paramDecl.identifier);
    LLVM_DEBUG(dbgs() << "Adding parameter: " << paramName << "\n");
    auto *paramStorage = Builder.createVariable( newFunc->getFunctionScope(), Variable::DeclKind::Var, paramName);
    
    nameTable_.insert(paramName, paramStorage);
  }

  
  uint32_t paramIndex = uint32_t{0} - 1;
  for (auto &elem : ESTree::getParams(funcNode)) {
    ESTree::Node *param = &elem;
    ESTree::Node *init = nullptr;
    ++paramIndex;

    if (auto *rest = llvh::dyn_cast<ESTree::RestElementNode>(param)) {
      createLRef(rest->_argument, true)
          .emitStore(genBuiltinCall( BuiltinMethod::HermesBuiltin_copyRestArgs, Builder.getLiteralNumber(paramIndex)));

      break;
    }

    
    if (auto *assign = llvh::dyn_cast<ESTree::AssignmentPatternNode>(param)) {
      param = assign->_left;
      init = assign->_right;
    }

    Identifier formalParamName = llvh::isa<ESTree::IdentifierNode>(param)
        ? getNameFieldFromID(param)
        : genAnonymousLabelName("param");

    auto *formalParam = Builder.createParameter(newFunc, formalParamName);
    createLRef(param, true)
        .emitStore( emitOptionalInitialization(formalParam, init, formalParamName));
  }

  newFunc->setExpectedParamCountIncludingThis( countExpectedArgumentsIncludingThis(funcNode));
}

uint32_t ESTreeIRGen::countExpectedArgumentsIncludingThis( ESTree::FunctionLikeNode *funcNode) {
  
  uint32_t count = 1;
  for (auto &param : ESTree::getParams(funcNode)) {
    if (llvh::isa<ESTree::AssignmentPatternNode>(param)) {
      
      break;
    }
    ++count;
  }
  return count;
}

void ESTreeIRGen::emitFunctionEpilogue(Value *returnValue) {
  if (returnValue) {
    Builder.setLocation(SourceErrorManager::convertEndToLocation( Builder.getFunction()->getSourceRange()));
    Builder.createReturnInst(returnValue);
  }

  
  if (!curFunction()->createArgumentsInst->hasUsers())
    curFunction()->createArgumentsInst->eraseFromParent();

  curFunction()->function->clearStatementCount();
}

void ESTreeIRGen::genDummyFunction(Function *dummy) {
  IRBuilder builder{dummy};

  builder.createParameter(dummy, "this");
  BasicBlock *firstBlock = builder.createBasicBlock(dummy);
  builder.setInsertionBlock(firstBlock);
  builder.createUnreachableInst();
  builder.createReturnInst(builder.getLiteralUndefined());
}



Function *ESTreeIRGen::genSyntaxErrorFunction( Module *M, Identifier originalName, SMRange sourceRange, StringRef error) {



  IRBuilder builder{M};

  Function *function = builder.createFunction( originalName, Function::DefinitionKind::ES5Function, true, sourceRange, false);





  builder.createParameter(function, "this");
  BasicBlock *firstBlock = builder.createBasicBlock(function);
  builder.setInsertionBlock(firstBlock);

  builder.createThrowInst(builder.createCallInst( emitLoad( builder, builder.createGlobalObjectProperty("SyntaxError", false)), builder.getLiteralUndefined(), builder.getLiteralString(error)));




  return function;
}

} 
} 
