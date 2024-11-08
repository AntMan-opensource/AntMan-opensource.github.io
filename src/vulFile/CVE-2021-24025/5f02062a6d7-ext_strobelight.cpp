















FOLLY_SDT_DEFINE_SEMAPHORE(hhvm, hhvm_stack);

namespace HPHP {

TRACE_SET_MOD(strobelight);

namespace {


const StaticString s_class("class"), s_function("function"), s_file("file"), s_line("line");





struct strobelight::backtrace_t bt_slab;
std::mutex usdt_mutex;

void onStrobelightSignal(int signo) {
  if (!RuntimeOption::StrobelightEnabled) {
    
    return;
  }

  if (signo == strobelight::kSignumCurrent) {
    
    if (rds::isFullyInitialized()) {
      
      if (!Strobelight::isXenonActive()) {
        
        setSurpriseFlag(XenonSignalFlag);
      }
    }
  }

  
  
  
  
  
  
  
  
  
  
}


bool logToUSDT(const Array& bt) {
  std::lock_guard<std::mutex> lock(usdt_mutex);

  memset(&bt_slab, 0, sizeof(bt_slab));

  int i = 0;
  IterateVNoInc( bt.get(), [&](TypedValue tv) -> bool {


      if (i >= strobelight::kMaxStackframes) {
        return true;
      }

      assertx(isArrayLikeType(type(tv)));
      ArrayData* bt_frame = val(tv).parr;
      strobelight::backtrace_frame_t* frame = &bt_slab.frames[i];

      auto const line = bt_frame->get(s_line.get());
      if (line.is_init()) {
        assertx(isIntType(type(line)));
        frame->line = val(line).num;
      }

      auto const file_name = bt_frame->get(s_file.get());
      if (file_name.is_init()) {
        assertx(isStringType(type(file_name)));
        strncpy(frame->file_name, val(file_name).pstr->data(), std::min(val(file_name).pstr->size(), strobelight::kFileNameMax));

        frame->file_name[strobelight::kFileNameMax - 1] = '\0';
      }

      auto const class_name = bt_frame->get(s_class.get());
      if (class_name.is_init()) {
        assertx(isStringType(type(class_name)));
        strncpy(frame->class_name, val(class_name).pstr->data(), std::min(val(class_name).pstr->size(), strobelight::kClassNameMax));

        frame->class_name[strobelight::kClassNameMax - 1] = '\0';
      }

      auto const function_name = bt_frame->get(s_function.get());
      if (function_name.is_init()) {
        assertx(isStringType(type(function_name)));
        strncpy(frame->function, val(function_name).pstr->data(), std::min(val(function_name).pstr->size(), strobelight::kFunctionMax));


        frame->function[strobelight::kFunctionMax - 1] = '\0';
      }

      i++;
      return false;
    }
  );
  bt_slab.len = i;

  
  FOLLY_SDT_WITH_SEMAPHORE(hhvm, hhvm_stack, &bt_slab);

  return true;
}

} 



Strobelight& Strobelight::getInstance() noexcept {
  static Strobelight instance;
  return instance;
}


void Strobelight::init() {

  signal(strobelight::kSignumCurrent, onStrobelightSignal);
  sync_signal(strobelight::kSignumAll, onStrobelightSignal);

}

bool Strobelight::active() {
  if (rds::isFullyInitialized() && isXenonActive()) {
    
    return false;
  }

  
  return FOLLY_SDT_IS_ENABLED(hhvm, hhvm_stack);
}

bool Strobelight::isXenonActive() {
  if (RuntimeOption::XenonForceAlwaysOn) {
    return true;
  }

  bool xenonProfiled = Xenon::getInstance().getIsProfiledRequest();
  if (xenonProfiled) {
    return true;
  }

  return false;
}

void Strobelight::log(c_WaitableWaitHandle* wh) const {
  if (RuntimeOption::XenonForceAlwaysOn) {
    
    
    return;
  }

  if (getSurpriseFlag(XenonSignalFlag)) {
    
    clearSurpriseFlag(XenonSignalFlag);
  }

  TRACE(1, "Strobelight::log\n");
  if (active()) {
    
    
    
    auto bt = createBacktrace(BacktraceArgs()
                              .fromWaitHandle(wh)
                              
                              
                              .ignoreArgs());
    logToUSDT(bt);
  }
}

void Strobelight::surpriseAll() {
  RequestInfo::ExecutePerRequest( [] (RequestInfo* t) {
      
      
      
      
      if (!isXenonActive()) {
        
        
        
        
        t->m_reqInjectionData.setFlag(XenonSignalFlag);
      }
    }
  );
}

void Strobelight::shutdown() {
  RuntimeOption::StrobelightEnabled = false;
}


}
