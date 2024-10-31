



























using namespace hermes;
using namespace hbc;

namespace {





const unsigned kFastRegisterAllocationThreshold = 250;




const uint64_t kRegisterAllocationMemoryLimit = 10L * 1024 * 1024;

void lowerIR(Module *M, const BytecodeGenerationOptions &options) {
  if (M->isLowered())
    return;

  PassManager PM;
  PM.addPass(new LowerLoadStoreFrameInst());
  if (options.optimizationEnabled) {
    
    PM.addPass(new OptEnvironmentInit());
  }
  
  
  PM.addPass(new LowerExponentiationOperator());
  
  PM.addPass(new LowerBuiltinCalls());
  
  
  PM.addPass(new LowerNumericProperties());
  
  
  PM.addPass(new LowerAllocObjectLiteral());
  PM.addPass(new LowerConstruction());
  PM.addPass(new LowerArgumentsArray());
  PM.addPass(new LimitAllocArray(UINT16_MAX));
  PM.addPass(new DedupReifyArguments());
  PM.addPass(new LowerSwitchIntoJumpTables());
  PM.addPass(new SwitchLowering());
  PM.addPass(new LoadConstants(options.optimizationEnabled));
  PM.addPass(new LoadParameters());
  if (options.optimizationEnabled) {
    
    
    PM.addPass(new LowerAllocObject());
    
    PM.addPass(new LowerCondBranch());
    
    PM.addPass(new FuncCallNOpts());
    
    PM.addCodeMotion();
    
    PM.addCSE();
    
    PM.addDCE();
  }

  
  PM.addHoistStartGenerator();

  PM.run(M);
  M->setLowered(true);

  if (options.verifyIR && verifyModule(*M, &llvh::errs(), VerificationMode::IR_VALID)) {
    M->dump();
    llvm_unreachable("IR verification failed");
  }
}




UniquingStringLiteralAccumulator stringAccumulatorFromBCProvider( const BCProviderBase &bcProvider) {
  uint32_t count = bcProvider.getStringCount();

  std::vector<StringTableEntry> entries;
  std::vector<bool> isIdentifier;

  entries.reserve(count);
  isIdentifier.reserve(count);

  {
    unsigned i = 0;
    for (auto kindEntry : bcProvider.getStringKinds()) {
      bool isIdentRun = kindEntry.kind() != StringKind::String;
      for (unsigned j = 0; j < kindEntry.count(); ++j, ++i) {
        entries.push_back(bcProvider.getStringTableEntry(i));
        isIdentifier.push_back(isIdentRun);
      }
    }

    assert(i == count && "Did not initialise every string");
  }

  auto strStorage = bcProvider.getStringStorage();
  ConsecutiveStringStorage css{std::move(entries), strStorage.vec()};

  return UniquingStringLiteralAccumulator{
      std::move(css), std::move(isIdentifier)};
}

} 

std::unique_ptr<BytecodeModule> hbc::generateBytecodeModule( Module *M, Function *entryPoint, const BytecodeGenerationOptions &options, hermes::OptValue<uint32_t> segment, SourceMapGenerator *sourceMapGen, std::unique_ptr<BCProviderBase> baseBCProvider) {





  return generateBytecodeModule( M, entryPoint, entryPoint, options, segment, sourceMapGen, std::move(baseBCProvider));






}

std::unique_ptr<BytecodeModule> hbc::generateBytecodeModule( Module *M, Function *lexicalTopLevel, Function *entryPoint, const BytecodeGenerationOptions &options, hermes::OptValue<uint32_t> segment, SourceMapGenerator *sourceMapGen, std::unique_ptr<BCProviderBase> baseBCProvider) {






  PerfSection perf("Bytecode Generation");
  lowerIR(M, options);

  if (options.format == DumpLIR)
    M->dump();

  BytecodeModuleGenerator BMGen(options);

  if (segment) {
    BMGen.setSegmentID(*segment);
  }
  
  
  llvh::DenseSet<Function *> functionsToGenerate = segment ? M->getFunctionsInSegment(*segment)
      : llvh::DenseSet<Function *>{};

  
  std::function<bool(const Function *)> shouldGenerate;
  if (segment) {
    shouldGenerate = [entryPoint, &functionsToGenerate](const Function *f) {
      return f == entryPoint || functionsToGenerate.count(f) > 0;
    };
  } else {
    shouldGenerate = [](const Function *) { return true; };
  }

  { 
    
    
    auto strings = baseBCProvider ? stringAccumulatorFromBCProvider(*baseBCProvider)
        : UniquingStringLiteralAccumulator{};

    auto addStringOrIdent = [&strings](llvh::StringRef str, bool isIdentifier) {
      strings.addString(str, isIdentifier);
    };

    auto addString = [&strings](llvh::StringRef str) {
      strings.addString(str,  false);
    };

    traverseLiteralStrings(M, shouldGenerate, addStringOrIdent);

    if (options.stripFunctionNames) {
      addString(kStrippedFunctionName);
    }
    traverseFunctions(M, shouldGenerate, addString, options.stripFunctionNames);

    if (!M->getCJSModulesResolved()) {
      traverseCJSModuleNames(M, shouldGenerate, addString);
    }

    BMGen.initializeStringTable(UniquingStringLiteralAccumulator::toTable( std::move(strings), options.optimizationEnabled));
  }

  
  for (auto &F : *M) {
    if (!shouldGenerate(&F)) {
      continue;
    }

    unsigned index = BMGen.addFunction(&F);
    if (&F == entryPoint) {
      BMGen.setEntryPointIndex(index);
    }

    auto *cjsModule = M->findCJSModule(&F);
    if (cjsModule) {
      if (M->getCJSModulesResolved()) {
        BMGen.addCJSModuleStatic(cjsModule->id, index);
      } else {
        BMGen.addCJSModule(index, BMGen.getStringID(cjsModule->filename.str()));
      }
    }

    
    if (!F.isGlobalScope()) {
      if (auto source = F.getSourceRepresentationStr()) {
        BMGen.addFunctionSource(index, BMGen.getStringID(*source));
      }
    }
  }
  assert(BMGen.getEntryPointIndex() != -1 && "Entry point not added");

  
  FunctionScopeAnalysis scopeAnalysis{lexicalTopLevel};

  
  HBCISelDebugCache debugCache;

  
  for (auto &F : *M) {
    if (!shouldGenerate(&F)) {
      continue;
    }

    std::unique_ptr<BytecodeFunctionGenerator> funcGen;

    if (F.isLazy()) {
      funcGen = BytecodeFunctionGenerator::create(BMGen, 0);
    } else {
      HVMRegisterAllocator RA(&F);
      if (!options.optimizationEnabled) {
        RA.setFastPassThreshold(kFastRegisterAllocationThreshold);
        RA.setMemoryLimit(kRegisterAllocationMemoryLimit);
      }
      PostOrderAnalysis PO(&F);
      
      
      llvh::SmallVector<BasicBlock *, 16> order(PO.rbegin(), PO.rend());
      RA.allocate(order);

      if (options.format == DumpRA) {
        RA.dump();
      }

      PassManager PM;
      PM.addPass(new LowerStoreInstrs(RA));
      PM.addPass(new LowerCalls(RA));
      if (options.optimizationEnabled) {
        PM.addPass(new MovElimination(RA));
        PM.addPass(new RecreateCheapValues(RA));
        PM.addPass(new LoadConstantValueNumbering(RA));
      }
      PM.addPass(new SpillRegisters(RA));
      if (options.basicBlockProfiling) {
        
        
        PM.addPass(new InsertProfilePoint());
      }
      PM.run(&F);

      if (options.format == DumpLRA)
        RA.dump();

      if (options.format == DumpPostRA)
        F.dump();

      funcGen = BytecodeFunctionGenerator::create(BMGen, RA.getMaxRegisterUsage());
      HBCISel hbciSel(&F, funcGen.get(), RA, scopeAnalysis, options);
      hbciSel.populateDebugCache(debugCache);
      hbciSel.generate(sourceMapGen);
      debugCache = hbciSel.getDebugCache();
    }

    BMGen.setFunctionGenerator(&F, std::move(funcGen));
  }

  return BMGen.generate();
}

std::unique_ptr<BytecodeModule> hbc::generateBytecode( Module *M, raw_ostream &OS, const BytecodeGenerationOptions &options, const SHA1 &sourceHash, hermes::OptValue<uint32_t> segment, SourceMapGenerator *sourceMapGen, std::unique_ptr<BCProviderBase> baseBCProvider) {






  auto BM = generateBytecodeModule( M, M->getTopLevelFunction(), options, segment, sourceMapGen, std::move(baseBCProvider));






  if (options.format == OutputFormatKind::EmitBundle) {
    assert(BM != nullptr);
    BytecodeSerializer BS{OS, options};
    BS.serialize(*BM, sourceHash);
  }
  
  
  if (sourceMapGen)
    BM->populateSourceMap(sourceMapGen);
  return BM;
}


