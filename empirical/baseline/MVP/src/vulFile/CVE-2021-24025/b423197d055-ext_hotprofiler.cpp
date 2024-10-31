





































namespace HPHP {

const StaticString s_hotprofiler("hotprofiler");





static long get_us_interval(struct timeval *start, struct timeval *end) {
  return (((end->tv_sec - start->tv_sec) * 1000000)
          + (end->tv_usec - start->tv_usec));
}


static void incr_us_interval(struct timeval *start, uint64_t incr) {
  incr += (start->tv_sec * 1000000 + start->tv_usec);
  start->tv_sec  = incr/1000000;
  start->tv_usec = incr%1000000;
  return;
}


static void hp_trunc_time(struct timeval *tv, uint64_t intr) {
  uint64_t time_in_micro;

  
  time_in_micro = (tv->tv_sec * 1000000) + tv->tv_usec;
  time_in_micro /= intr;
  time_in_micro *= intr;

  
  tv->tv_sec  = (time_in_micro / 1000000);
  tv->tv_usec = (time_in_micro % 1000000);
}





static int64_t get_cpu_frequency() {
  struct timeval start;
  struct timeval end;

  if (gettimeofday(&start, 0)) {
    perror("gettimeofday");
    return 0.0;
  }
  uint64_t tsc_start = cpuCycles();
  uint64_t tsc_end;
  volatile int i;
  
  
  do {
    for (i = 0; i < 1000000; i++);
    if (gettimeofday(&end, 0)) {
      perror("gettimeofday");
      return 0.0;
    }
    tsc_end = cpuCycles();
  } while (get_us_interval(&start, &end) < 5000);

  return nearbyint((tsc_end - tsc_start) * 1.0 / (get_us_interval(&start, &end)));
}



static int64_t* get_cpu_frequency_from_file(const char *file, int ncpus)
{
  std::ifstream cpuinfo(file);
  if (cpuinfo.fail()) {
    return nullptr;
  }
  char line[MAX_LINELENGTH];
  int64_t* freqs = new int64_t[ncpus];
  for (int i = 0; i < ncpus; ++i) {
    freqs[i] = 0;
  }
  int processor = -1;

  while (cpuinfo.getline(line, sizeof(line))) {
    if (sscanf(line, "processor : %d", &processor) == 1) {
      continue;
    }
    float freq;
    if ((sscanf(line, "cpu MHz : %f", &freq) == 1) || (sscanf(line, "clock         : %f", &freq) == 1)) {
      if (processor != -1 && processor < ncpus) {
         freqs[processor] = nearbyint(freq);
         processor = -1;
      }
    }
  }
  for (int i = 0; i < ncpus; ++i) {
    if (freqs[i] == 0) {
      delete[] freqs;
      return nullptr;
    }
  }
  return freqs;
}




struct MachineInfo {
  
  static void BindToCPU(uint32_t cpu_id) {
    cpu_set_t new_mask;
    CPU_ZERO(&new_mask);
    CPU_SET(cpu_id, &new_mask);
    SET_AFFINITY(0, sizeof(cpu_set_t), &new_mask);
  }

public:
  
  int m_cpu_num;
  
  int64_t* m_cpu_frequencies;

  MachineInfo() {
    m_cpu_num = sysconf(_SC_NPROCESSORS_CONF);
    m_cpu_frequencies = get_cpu_frequency_from_file("/proc/cpuinfo", m_cpu_num);

    if (m_cpu_frequencies)
      return;

    m_cpu_frequencies = new int64_t[m_cpu_num];
    for (int i = 0; i < m_cpu_num; i++) {
      cpu_set_t prev_mask;
      GET_AFFINITY(0, sizeof(cpu_set_t), &prev_mask);
      BindToCPU(i);
      
      
      usleep(0);
      m_cpu_frequencies[i] = get_cpu_frequency();
      SET_AFFINITY(0, sizeof(cpu_set_t), &prev_mask);
    }
  }

  ~MachineInfo() {
    delete[] m_cpu_frequencies;
  }
};
static MachineInfo s_machine;

static inline uint64_t tv_to_cycles(const struct timeval& tv, int64_t MHz)
{
  return (((uint64_t)tv.tv_sec * 1000000) + tv.tv_usec) * MHz;
}

static inline uint64_t to_usec(int64_t cycles, int64_t MHz, bool cpu_time = false)
{
  if (cpu_time) {
    return cycles / 1000;
  }
  return (cycles + MHz/2) / MHz;
}

static inline uint64_t cpuTime(int64_t ) {
  return gettime_ns(CLOCK_THREAD_CPUTIME_ID);
}

uint64_t get_allocs()
{

  return tl_heap->getAllocated();


  if (MallocExtensionInstance) {
    size_t stat;
    MallocExtensionInstance()->GetNumericProperty( "generic.thread_bytes_allocated", &stat);
    return stat;
  }

  return 0;
}

uint64_t get_frees()
{

  return tl_heap->getDeallocated();


  if (MallocExtensionInstance) {
    size_t stat;
    MallocExtensionInstance()->GetNumericProperty( "generic.thread_bytes_freed", &stat);
    return stat;
  }

  return 0;
}

size_t Frame::getName(char *result_buf, size_t result_len) {
  if (result_len <= 1) {
    return 0; 
  }

  
  
  if (m_recursion) {
    snprintf(result_buf, result_len, "%s@%d", m_name, m_recursion);
  } else {
    snprintf(result_buf, result_len, "%s", m_name);
  }

  
  result_buf[result_len - 1] = 0;
  return strlen(result_buf);
}

size_t Frame::getStack(int level, char *result_buf, size_t result_len) {
  
  
  if (!m_parent || level <= 1) {
    return getName(result_buf, result_len);
  }

  
  size_t len = m_parent->getStack(level - 1, result_buf, result_len);
  if (result_len < (len + HP_STACK_DELIM_LEN)) {
    return len; 
  }

  
  if (len) {
    strncat(result_buf + len, HP_STACK_DELIM, result_len - len);
    len += HP_STACK_DELIM_LEN;
  }

  
  return len + getName(result_buf + len, result_len - len);
}

const StaticString s_ct("ct"), s_wt("wt"), s_cpu("cpu"), s_mu("mu"), s_pmu("pmu"), s_alloc("alloc"), s_free("free"), s_compressed_trace("(compressed_trace)");









Profiler::Profiler(bool needCPUAffinity) : m_successful(true), m_stack(nullptr), m_frame_free_list(nullptr), m_has_affinity(needCPUAffinity) {


    if (!s_rand_initialized) {
      s_rand_initialized = true;
      srand(math_generate_seed());
    }

    if (m_has_affinity) {
      
      
      
      int cur_cpu_id = rand() % s_machine.m_cpu_num;
      GET_AFFINITY(0, sizeof(cpu_set_t), &m_prev_mask);
      MachineInfo::BindToCPU(cur_cpu_id);
      m_MHz = s_machine.m_cpu_frequencies[cur_cpu_id];
    } else {
      
      
      
      m_MHz = s_machine.m_cpu_frequencies[0];
    }

    memset(m_func_hash_counters, 0, sizeof(m_func_hash_counters));
}

Profiler::~Profiler() {
    if (m_has_affinity) {
      SET_AFFINITY(0, sizeof(cpu_set_t), &m_prev_mask);
    }

    endAllFrames();
    for (Frame *p = m_frame_free_list; p;) {
      Frame *cur = p;
      p = p->m_parent;
      delete cur;
    }
}


void Profiler::beginFrameEx(const char* ) {}


void Profiler::endFrameEx(const TypedValue* , const char* ) {}

void Profiler::writeStats(Array& ) {}

void Profiler::endAllFrames() {
    while (m_stack) {
      endFrame(nullptr, nullptr, true);
    }
}

template<class phpret, class Name, class Counts> void Profiler::returnVals(phpret& ret, const Name& name, const Counts& counts, int flags, int64_t MHz)

{
    ArrayInit arr(5, ArrayInit::Map{});
    arr.set(s_ct,  counts.count);
    arr.set(s_wt,  to_usec(counts.wall_time, MHz));
    if (flags & TrackCPU) {
      arr.set(s_cpu, to_usec(counts.cpu, MHz, true));
    }
    if (flags & TrackMemory) {
      arr.set(s_mu,  counts.memory);
      arr.set(s_pmu, counts.peak_memory);
    } else if (flags & TrackMalloc) {
      arr.set(s_alloc, counts.memory);
      arr.set(s_free, counts.peak_memory);
    }
    ret.set(String(name), arr.toArray());
}

template<class phpret, class StatsMap> bool Profiler::extractStats(phpret& ret, StatsMap& stats, int flags, int64_t MHz)

{
    for (typename StatsMap::const_iterator iter = stats.begin();
         iter != stats.end(); ++iter) {
      returnVals(ret, iter->first, iter->second, flags, MHz);
    }
    return true;
}

bool Profiler::s_rand_initialized = false;

void Profiler::beginFrame(const char *symbol) {
  Frame *current = createFrame(symbol);

  
  int recursion_level = 0;
  if (m_func_hash_counters[current->m_hash_code] > 0) {
    
    for (Frame *p = current->m_parent; p; p = p->m_parent) {
      if (strcmp(current->m_name, p->m_name) == 0) {
        recursion_level = p->m_recursion + 1;
        break;
      }
    }
  }
  current->m_recursion = recursion_level;

  m_func_hash_counters[current->m_hash_code]++;
  beginFrameEx(symbol);
}


void Profiler::endFrame(const TypedValue *retval, const char *symbol, bool endMain) {

  if (m_stack) {
    
    if (!endMain && m_stack->m_parent == nullptr) {
      return;
    }
    endFrameEx(retval, symbol);
    m_func_hash_counters[m_stack->m_hash_code]--;
    releaseFrame();
  }
}




struct HierarchicalProfiler final : Profiler {
private:
  struct CountMap {
    CountMap() : count(0), wall_time(0), cpu(0), memory(0), peak_memory(0) {}

    int64_t count;
    int64_t wall_time;
    int64_t cpu;
    int64_t memory;
    int64_t peak_memory;
  };

  struct HierarchicalProfilerFrame : Frame {
    ~HierarchicalProfilerFrame() override {
    }

    uint64_t        m_tsc_start;   
    int64_t         m_mu_start;    
    int64_t         m_pmu_start;   
    int64_t         m_vtsc_start;  
  };

  using StatsMap = hphp_hash_map<std::string, CountMap, string_hash>;
  StatsMap m_stats; 

public:
  explicit HierarchicalProfiler(int flags) : Profiler(true), m_flags(flags) {
  }

  Frame *allocateFrame() override {
    return new HierarchicalProfilerFrame();
  }

  void beginFrameEx(const char* ) override {
    HierarchicalProfilerFrame *frame = dynamic_cast<HierarchicalProfilerFrame *>(m_stack);
    frame->m_tsc_start = cpuCycles();

    if (m_flags & TrackCPU) {
      frame->m_vtsc_start = cpuTime(m_MHz);
    }

    if (m_flags & TrackMemory) {
      auto const stats = tl_heap->getStats();
      frame->m_mu_start  = stats.usage();
      frame->m_pmu_start = stats.peakUsage;
    } else if (m_flags & TrackMalloc) {
      frame->m_mu_start = get_allocs();
      frame->m_pmu_start = get_frees();
    }
  }

  void endFrameEx(const TypedValue* , const char* ) override {
    char symbol[512];
    HierarchicalProfilerFrame *frame = dynamic_cast<HierarchicalProfilerFrame *>(m_stack);
    frame->getStack(2, symbol, sizeof(symbol));
    CountMap &counts = m_stats[symbol];
    counts.count++;
    counts.wall_time += cpuCycles() - frame->m_tsc_start;

    if (m_flags & TrackCPU) {
      counts.cpu += cpuTime(m_MHz) - frame->m_vtsc_start;
    }

    if (m_flags & TrackMemory) {
      auto const stats = tl_heap->getStats();
      int64_t mu_end = stats.usage();
      int64_t pmu_end = stats.peakUsage;
      counts.memory += mu_end - frame->m_mu_start;
      counts.peak_memory += pmu_end - frame->m_pmu_start;
    } else if (m_flags & TrackMalloc) {
      counts.memory += get_allocs() - frame->m_mu_start;
      counts.peak_memory += get_frees() - frame->m_pmu_start;
    }
  }

  void writeStats(Array &ret) override {
    extractStats(ret, m_stats, m_flags, m_MHz);
  }

  bool shouldSkipBuiltins() const override {
    return m_flags & NoTrackBuiltins;
  }

private:
  uint32_t m_flags;
};






template <class TraceIterator, class Stats> struct TraceWalker {
  struct Frame {
    TraceIterator trace; 
    int level; 
    int len; 
  };

  TraceWalker()
    : m_arcBuffLen(200)
    , m_arcBuff((char*)malloc(200))
    , m_badArcCount(0)
  {};

  ~TraceWalker() {
    free(m_arcBuff);
    for (auto& r : m_recursion) delete[] r.first;
  }

  void walk(TraceIterator begin, TraceIterator end, TraceIterator final, Stats& stats) {
    if (begin == end) return;
    m_recursion.push_back(std::make_pair(nullptr, 0));
    
    
    std::map<const char*, unsigned> functionLevel;
    auto current = begin;
    while (current != end && !current->symbol) ++current;
    while (current != end) {
      if (!current->is_func_exit) {
        unsigned level = ++functionLevel[current->symbol];
        if (level >= m_recursion.size()) {
          constexpr size_t bufferSize = 12;
          char *level_string = new char[bufferSize];
          snprintf(level_string, bufferSize, "@%u", level);
          m_recursion.push_back(std::make_pair(level_string, strlen(level_string)));
        }
        Frame fr;
        fr.trace = current;
        fr.level = level - 1;
        fr.len = strlen(current->symbol);
        checkArcBuff(fr.len);
        m_stack.push_back(fr);
      } else if (m_stack.size() > 1) {
        validateStack(current, stats); 
        --functionLevel[m_stack.back().trace->symbol];
        popFrame(current, stats);
      }
      ++current;
    }
    
    
    --current;
    while (m_stack.size() > 1) {
      popFrame(current, stats);
    }
    
    
    
    if (!m_stack.empty()) {
      assertx(strcmp(m_stack.back().trace->symbol, "main()") == 0);
      incStats(m_stack.back().trace->symbol, final, m_stack.back(), stats);
    }
    if (m_badArcCount > 0) {
      stats["(trace has mismatched calls and returns)"].count = m_badArcCount;
    }
  }

 private:
  void checkArcBuff(int len) {
    len = 2*len + HP_STACK_DELIM_LEN + 2;
    if (len >= m_arcBuffLen) {
      m_arcBuffLen *= 2;
      m_arcBuff = (char *)realloc(m_arcBuff, m_arcBuffLen);
      if (m_arcBuff == nullptr) {
        throw std::bad_alloc();
      }
    }
  }

  void incStats(const char* arc, TraceIterator tr, const Frame& fr, Stats& stats) {
    auto& st = stats[arc];
    ++st.count;
    st.wall_time += tr->wall_time - fr.trace->wall_time;
    st.cpu += tr->cpu - fr.trace->cpu;
    st.memory += tr->memory - fr.trace->memory;
    st.peak_memory += tr->peak_memory - fr.trace->peak_memory;
  }

  
  
  
  void validateStack(TraceIterator tIt, Stats& stats) {
    auto enteredName = m_stack.back().trace->symbol;
    auto exitedName = tIt->symbol;
    if ((exitedName != nullptr) && ((enteredName == nullptr) || (strcmp(enteredName, exitedName) != 0))) {
      
      
      
      if ((enteredName != nullptr) && ((strncmp(enteredName, "run_init::", 10) == 0) || (strcmp(enteredName, "_") == 0))) return;

      bool fixed = false;
      if (m_stack.size() > 1) {
        auto callerName = (m_stack.end() - 2)->trace->symbol;
        if ((callerName != nullptr) && (strcmp(callerName, exitedName) == 0)) {
          
          
          
          
          
          m_stack.pop_back();
          fixed = true;
        }
      }
      
      
      if (++m_badArcCount < 20) {
        std::string badArc;
        if (fixed) {
          badArc = folly::format("(warning: corrected bad arc #{}: " "enter '{}', exit '{}')", m_badArcCount, enteredName, exitedName).str();


        } else {
          badArc = folly::format("(error: bad arc #{}: " "enter '{}', exit '{}')", m_badArcCount, enteredName, exitedName).str();


        }
        ++stats[badArc.data()].count;
      }
    }
  }

  void popFrame(TraceIterator tIt, Stats& stats) {
    Frame callee = m_stack.back();
    m_stack.pop_back();
    Frame& caller = m_stack.back();
    char *cp = m_arcBuff;
    memcpy(cp, caller.trace->symbol, caller.len);
    cp += caller.len;
    if (caller.level >= 1) {
      std::pair<char*, int>& lvl = m_recursion[caller.level];
      memcpy(cp, lvl.first, lvl.second);
      cp += lvl.second;
    }
    memcpy(cp, HP_STACK_DELIM, HP_STACK_DELIM_LEN);
    cp += HP_STACK_DELIM_LEN;
    memcpy(cp, callee.trace->symbol, callee.len);
    cp += callee.len;
    if (callee.level >= 1) {
      std::pair<char*, int>& lvl = m_recursion[callee.level];
      memcpy(cp, lvl.first, lvl.second);
      cp += lvl.second;
    }
    *cp = 0;
    incStats(m_arcBuff, tIt, callee, stats);
  }

  std::vector<std::pair<char*, int>> m_recursion;
  std::vector<Frame> m_stack;
  int m_arcBuffLen;
  char *m_arcBuff;
  int m_badArcCount;
};





struct TraceProfiler final : Profiler {
  explicit TraceProfiler(int flags)
    : Profiler(true)
    , m_traceBuffer(nullptr)
    , m_traceBufferSize(0)
    , m_nextTraceEntry(0)
    , m_traceBufferFilled(false)
    , m_maxTraceBuffer(0)
    , m_overflowCalls(0)
    , m_flags(flags)
  {
    if (!(m_flags & IHaveInfiniteMemory) && pthread_mutex_trylock(&s_inUse)) {
      
      
      m_successful = false;
    } else {
      m_maxTraceBuffer = RuntimeOption::ProfilerMaxTraceBuffer;
      Extension* ext = ExtensionRegistry::get(s_hotprofiler);
      assertx(ext);
      IniSetting::Bind(ext, IniSetting::PHP_INI_ALL, "profiler.max_trace_buffer", &m_maxTraceBuffer);

    }
  }

  ~TraceProfiler() override {
    if (m_successful) {
      free(m_traceBuffer);
      IniSetting::Unbind("profiler.max_trace_buffer");
      pthread_mutex_unlock(&s_inUse);
    }
  }

 private:
  
  struct TraceData {
    int64_t wall_time;
    int64_t cpu;

    
    
    
    
    
    uint64_t memory : 63;
    uint64_t is_func_exit : 1; 
    uint64_t peak_memory : 63;
    uint64_t unused : 1; 

    void clear() {
      wall_time = cpu = memory = peak_memory = 0;
    }
    static void compileTimeAssertions() {
      static_assert(sizeof(TraceData) == (sizeof(uint64_t) * 4), "");
    }
  };

  
  struct TraceEntry : TraceData {
    const char *symbol; 
  };

  bool isTraceSpaceAvailable() {
    
    return m_nextTraceEntry < m_traceBufferSize - 3;
  }

  bool ensureTraceSpace() {
    bool track_realloc = false;
    if (m_traceBufferFilled) {
      m_overflowCalls++;
      return false;
    }
    int new_array_size;
    if (m_traceBufferSize == 0) {
      new_array_size = RuntimeOption::ProfilerTraceBuffer;
    } else {
      new_array_size = m_traceBufferSize * RuntimeOption::ProfilerTraceExpansion;
      if (m_maxTraceBuffer != 0 && new_array_size > m_maxTraceBuffer) {
        new_array_size = m_maxTraceBuffer > m_traceBufferSize ? m_maxTraceBuffer : m_traceBufferSize;
      }
      if (new_array_size - m_nextTraceEntry <= 5) {
        
        
        
        m_traceBufferFilled = true;
        collectStats("(trace buffer terminated)", false, m_traceBuffer[m_nextTraceEntry++]);
        return false;
      }
      track_realloc = true;
    }
    if (track_realloc) {
      collectStats("(trace buffer realloc)", false, m_traceBuffer[m_nextTraceEntry++]);
    }
    {
      MemoryManager::MaskAlloc masker(*tl_heap);
      auto r = (TraceEntry*)realloc((void*)m_traceBuffer, new_array_size * sizeof(TraceEntry));

      if (!r) {
        m_traceBufferFilled = true;
        if (m_traceBuffer) {
          collectStats("(trace buffer terminated)", false, m_traceBuffer[m_nextTraceEntry++]);
        }
        return false;
      }
      m_traceBufferSize = new_array_size;
      m_traceBuffer = r;
    }
    if (track_realloc) {
      collectStats("(trace buffer realloc)", true, m_traceBuffer[m_nextTraceEntry++]);
    }
    return true;
  }

  void beginFrame(const char *symbol) override {
    doTrace(symbol, false);
  }

  void endFrame(const TypedValue* , const char* symbol, bool  = false) override {
    doTrace(symbol, true);
  }

  void endAllFrames() override {
    if (m_traceBuffer && m_nextTraceEntry < m_traceBufferSize - 1) {
      collectStats(nullptr, true, m_finalEntry);
      m_traceBufferFilled = true;
    }
  }

  void collectStats(const char *symbol, bool isFuncExit, TraceEntry& te) {
    te.symbol = symbol;
    te.is_func_exit = isFuncExit;
    collectStats(te);
  }

  void collectStats(TraceData& te) {
    te.wall_time = cpuCycles();
    te.cpu = 0;
    if (m_flags & TrackCPU) {
      te.cpu = cpuTime(m_MHz);
    }
    if (m_flags & TrackMemory) {
      auto const stats = tl_heap->getStats();
      te.memory = stats.usage();
      te.peak_memory = stats.peakUsage;
    } else if (m_flags & TrackMalloc) {
      te.memory = get_allocs();
      te.peak_memory = get_frees();
    } else {
      te.memory = 0;
      te.peak_memory = 0;
    }
  }

  TraceEntry* nextTraceEntry() {
    if (!isTraceSpaceAvailable() && !ensureTraceSpace()) {
      return 0;
    }
    return &m_traceBuffer[m_nextTraceEntry++];
  }

  void doTrace(const char *symbol, bool isFuncExit) {
    TraceEntry *te = nextTraceEntry();
    if (te != nullptr) {
      collectStats(symbol, isFuncExit, *te);
    }
  }

  template<class TraceIterator, class Stats> void walkTrace(TraceIterator begin, TraceIterator end, TraceIterator final, Stats& stats) {

    TraceWalker<TraceIterator, Stats> walker;
    walker.walk(begin, end, final, stats);
  }

  void writeStats(Array &ret) override {
    TraceData my_begin;
    collectStats(my_begin);
    walkTrace(m_traceBuffer, m_traceBuffer + m_nextTraceEntry, &m_finalEntry, m_stats);
    if (m_overflowCalls) {
      m_stats["(trace buffer terminated)"].count += m_overflowCalls/2;
    }
    extractStats(ret, m_stats, m_flags, m_MHz);
    CountedTraceData allocStats;
    allocStats.count = 0;
    allocStats.peak_memory = allocStats.memory = m_nextTraceEntry * sizeof(*m_traceBuffer);
    returnVals(ret, "(trace buffer alloc)", allocStats, m_flags, m_MHz);
    if (m_flags & MeasureXhprofDisable) {
      CountedTraceData my_end;
      collectStats(my_end);
      my_end.count = 1;
      my_end.cpu -= my_begin.cpu;
      my_end.wall_time -= my_begin.wall_time;
      my_end.memory -= my_begin.memory;
      my_end.peak_memory -= my_begin.peak_memory;
      returnVals(ret, "xhprof_post_processing()", my_end, m_flags, m_MHz);
    }
  }

  bool shouldSkipBuiltins() const override {
    return m_flags & NoTrackBuiltins;
  }

  TraceEntry* m_traceBuffer;
  TraceEntry m_finalEntry;
  int m_traceBufferSize;
  int m_nextTraceEntry;
  bool m_traceBufferFilled;
  int64_t m_maxTraceBuffer;
  int64_t m_overflowCalls;
  uint32_t m_flags;

  
  
  struct CountedTraceData : TraceData {
    int64_t count;
    CountedTraceData() : count(0)  { clear(); }
  };
  using StatsMap = hphp_hash_map<std::string, CountedTraceData, string_hash>;
  StatsMap m_stats; 

  static pthread_mutex_t s_inUse;
};

pthread_mutex_t TraceProfiler::s_inUse = PTHREAD_MUTEX_INITIALIZER;





struct SampleProfiler final : Profiler {
private:
  typedef std::pair<int64_t, int64_t> Timestamp;
  typedef req::vector<std::pair<Timestamp, std::string>> SampleVec;
  SampleVec m_samples; 

public:
  SampleProfiler() : Profiler(true) {
    struct timeval  now;
    uint64_t truncated_us;
    uint64_t truncated_tsc;

    
    m_last_sample_tsc = cpuCycles();

    
    gettimeofday(&m_last_sample_time, 0);
    now = m_last_sample_time;
    hp_trunc_time(&m_last_sample_time, SAMPLING_INTERVAL);

    
    truncated_us  = get_us_interval(&m_last_sample_time, &now);
    truncated_tsc = truncated_us * m_MHz;
    if (m_last_sample_tsc > truncated_tsc) {
      
      m_last_sample_tsc -= truncated_tsc;
    }

    
    m_sampling_interval_tsc = SAMPLING_INTERVAL * m_MHz;
  }

  void beginFrameEx(const char* ) override { sample_check(); }

  void endFrameEx(const TypedValue* , const char* ) override {
    sample_check();
  }

  void writeStats(Array &ret) override {
    for (auto const& sample : m_samples) {
      auto const& time = sample.first;
      char timestr[512];
      snprintf(timestr, sizeof(timestr), "%" PRId64 ".%06" PRId64, time.first, time.second);

      ret.set(String(timestr), String(sample.second));
    }
  }

private:
  static const int SAMPLING_INTERVAL = 100000; 

  struct timeval m_last_sample_time;
  uint64_t m_last_sample_tsc;
  uint64_t m_sampling_interval_tsc;

  
  void sample_stack() {
    char symbol[5120];
    m_stack->getStack(INT_MAX, symbol, sizeof(symbol));

    auto time = std::make_pair((int64_t)m_last_sample_time.tv_sec, (int64_t)m_last_sample_time.tv_usec);
    m_samples.push_back(std::make_pair(time, symbol));
  }

  
  void sample_check() {
    if (m_stack) {
      
      
      while ((cpuCycles() - m_last_sample_tsc) > m_sampling_interval_tsc) {
        m_last_sample_tsc += m_sampling_interval_tsc;
        
        incr_us_interval(&m_last_sample_time, SAMPLING_INTERVAL);
        sample_stack();
      }
    }
  }
};





























struct MemoProfiler final : Profiler {
  explicit MemoProfiler(int ) : Profiler(true) {}

  ~MemoProfiler() override {
  }

 private:
  void beginFrame(const char *symbol) override {
    VMRegAnchor _;
    ActRec *ar = vmfp();
    Frame f(symbol);
    if (ar->func()->cls() && ar->hasThis()) {
      auto& memo = m_memos[symbol];
      if (!memo.m_ignore) {
        ARRPROV_USE_RUNTIME_LOCATION();
        auto args = hhvm_get_frame_args(ar);
        args.append((int64_t)(ar->getThis())); 
        VariableSerializer vs(VariableSerializer::Type::DebuggerSerialize);
        String sdata;
        try {
          sdata = vs.serialize(VarNR{args}, true);
          f.m_args = sdata;
        } catch (...) {
          fprintf(stderr, "Args Serialization failure: %s\n", symbol);
        }
      }
    }
    m_stack.push_back(f);
  }

  void endFrame(const TypedValue* retval, const char* symbol, bool  = false) override {
    if (m_stack.empty()) {
      fprintf(stderr, "STACK IMBALANCE empty %s\n", symbol);
      return;
    }
    auto f = m_stack.back();
    m_stack.pop_back();
    if (strcmp(f.m_symbol, symbol) != 0) {
      fprintf(stderr, "STACK IMBALANCE %s\n", symbol);
      return;
    }
    auto& memo = m_memos[symbol];
    if (memo.m_ignore) return;
    ++memo.m_count;
    memo.m_ignore = true;
    VMRegAnchor _;
    ActRec *ar = vmfp();
    
    
    if (ar->func()->isCPPBuiltin() || isResumed(ar)) return;
    auto ret = tvAsCVarRef(retval);
    if (ret.isNull()) return;
    if (!(ret.isString() || ret.isObject() || ret.isArray())) return;
    VariableSerializer vs(VariableSerializer::Type::DebuggerSerialize);
    String sdata;
    try {
      sdata = vs.serialize(ret, true);
    } catch (...) {
      fprintf(stderr, "Serialization failure: %s\n", symbol);
      return;
    }
    if (sdata.length() < 3) return;
    if (ar->func()->cls() && ar->hasThis()) {
      memo.m_has_this = true;
      auto& member_memo = memo.m_member_memos[f.m_args.data()];
      ++member_memo.m_count;
      if (member_memo.m_return_value.length() == 0) { 
        member_memo.m_return_value = sdata;
        
        member_memo.m_ret_tv = *retval;
        memo.m_ignore = false;
      } else if (member_memo.m_return_value == sdata) { 
        memo.m_ignore = false;
        if ((member_memo.m_ret_tv.m_data.num != retval->m_data.num) || (member_memo.m_ret_tv.m_type != retval->m_type)) {
          memo.m_ret_tv_same = false;
        }
      } else {
        memo.m_member_memos.clear(); 
      }
    } else {
      if (memo.m_return_value.length() == 0) { 
        memo.m_return_value = sdata;
        
        memo.m_ret_tv = *retval;
        memo.m_ignore = false;
      } else if (memo.m_return_value == sdata) { 
        memo.m_ignore = false;
        if ((memo.m_ret_tv.m_data.num != retval->m_data.num) || (memo.m_ret_tv.m_type != retval->m_type)) {
          memo.m_ret_tv_same = false;
        }
      } else {
        memo.m_return_value = ""; 
      }
    }
  }

  void endAllFrames() override {
    
  }

  void writeStats(Array& ) override {
    fprintf(stderr, "writeStats start\n");
    
    
    
    
    fprintf(stderr, "Count Function MinSerLen MaxSerLen RetSame HasThis " "AllSame MemberCount\n");
    for (auto& me : m_memos) {
      if (me.second.m_ignore) continue;
      if (me.second.m_count == 1) continue;
      int min_ser_len = 999999999;
      int max_ser_len = 0;
      int count = 0;
      int member_count = 0;
      bool all_same = true;
      if (me.second.m_has_this) {
        bool any_multiple = false;
        auto& fr = me.second.m_member_memos.begin()->second.m_return_value;
        member_count = me.second.m_member_memos.size();
        for (auto& mme : me.second.m_member_memos) {
          if (mme.second.m_return_value != fr) all_same = false;
          count += mme.second.m_count;
          auto ser_len = mme.second.m_return_value.length();
          min_ser_len = std::min(min_ser_len, ser_len);
          max_ser_len = std::max(max_ser_len, ser_len);
          if (mme.second.m_count > 1) any_multiple = true;
        }
        if (!any_multiple && !all_same) continue;
      } else {
        min_ser_len = max_ser_len = me.second.m_return_value.length();
        count = me.second.m_count;
        all_same = me.second.m_ret_tv_same;
      }
      fprintf(stderr, "%d %s %d %d %s %s %s %d\n", count, me.first.data(), min_ser_len, max_ser_len, me.second.m_ret_tv_same ? " true" : "false", me.second.m_has_this ? " true" : "false", all_same ? " true" : "false", member_count );






    }
    fprintf(stderr, "writeStats end\n");
  }

  struct MemberMemoInfo {
    String m_return_value;
    TypedValue m_ret_tv;
    int m_count{0};
  };
  using MemberMemoMap = req::hash_map<std::string,MemberMemoInfo,string_hash>;

  struct MemoInfo {
    MemberMemoMap m_member_memos; 
    String m_return_value;
    TypedValue m_ret_tv;
    int m_count{0};
    bool m_ignore{false};
    bool m_has_this{false};
    bool m_ret_tv_same{true};
  };
  using MemoMap = req::hash_map<std::string, MemoInfo, string_hash>;

  struct Frame {
    explicit Frame(const char* symbol) : m_symbol(symbol) {}
    const char* m_symbol;
    String m_args;
  };

public:
  MemoMap m_memos; 
  req::vector<Frame> m_stack;
};




bool ProfilerFactory::start(ProfilerKind kind, long flags, bool beginFrame ) {

  if (m_profiler != nullptr) {
    return false;
  }

  switch (kind) {
  case ProfilerKind::Hierarchical:
    m_profiler = req::make_raw<HierarchicalProfiler>(flags);
    break;
  case ProfilerKind::Sample:
    m_profiler = req::make_raw<SampleProfiler>();
    break;
  case ProfilerKind::Trace:
    m_profiler = req::make_raw<TraceProfiler>(flags);
    break;
  case ProfilerKind::Memo:
    m_profiler = req::make_raw<MemoProfiler>(flags);
    break;
  case ProfilerKind::External:
    if (g_system_profiler) {
      m_profiler = g_system_profiler->getHotProfiler();
    } else if (m_external_profiler) {
      m_profiler = m_external_profiler;
    } else {
      raise_invalid_argument_warning( "ProfilerFactory::setExternalProfiler() not yet called");
      return false;
    }
    break;
  default:
    raise_invalid_argument_warning("level: %d", static_cast<int>(kind));
    return false;
  }
  if (m_profiler && m_profiler->m_successful) {
    
    HPHP::EventHook::Enable();
    RequestInfo::s_requestInfo->m_profiler = m_profiler;
    if (beginFrame) {
      m_profiler->beginFrame("main()");
    }
    return true;
  }
  req::destroy_raw(m_profiler);
  m_profiler = nullptr;
  return false;
}

Variant ProfilerFactory::stop() {
  if (m_profiler) {
    m_profiler->endAllFrames();

    Array ret;
    m_profiler->writeStats(ret);
    req::destroy_raw(m_profiler);
    m_profiler = nullptr;
    RequestInfo::s_requestInfo->m_profiler = nullptr;

    return ret;
  }
  return init_null();
}

bool ProfilerFactory::EnableNetworkProfiler = false;

IMPLEMENT_REQUEST_LOCAL(ProfilerFactory, s_profiler_factory);




void f_hotprofiler_enable(int ikind) {
  auto kind = static_cast<ProfilerKind>(ikind);
  long flags = 0;
  if (kind == ProfilerKind::Hierarchical) {
    flags = NoTrackBuiltins;
  } else if (kind == ProfilerKind::Memory) {
    kind = ProfilerKind::Hierarchical;
    flags = NoTrackBuiltins | TrackMemory;
  }
  if (RuntimeOption::EnableHotProfiler) {
    s_profiler_factory->start(kind, flags);
  }
}

Variant f_hotprofiler_disable() {
  return s_profiler_factory->stop();
}

void f_phprof_enable(int flags ) {
  if (RuntimeOption::EnableHotProfiler) {
    s_profiler_factory->start(ProfilerKind::Hierarchical, flags);
  }
}

Variant f_phprof_disable() {
  return s_profiler_factory->stop();
}




void begin_profiler_frame(Profiler *p, const char *symbol) {
  p->beginFrame(symbol);
}

void end_profiler_frame(Profiler *p, const TypedValue *retval, const char *symbol) {

  p->endFrame(retval, symbol);
}



static struct HotProfilerExtension : Extension {
  HotProfilerExtension(): Extension("hotprofiler") {}

  void moduleInit() override {

    HHVM_RC_INT_SAME(CLOCK_REALTIME);


    HHVM_RC_INT_SAME(CLOCK_MONOTONIC);


    HHVM_RC_INT_SAME(CLOCK_PROCESS_CPUTIME_ID);


    HHVM_RC_INT_SAME(CLOCK_THREAD_CPUTIME_ID);

  }
} s_hot_profiler_extension;


}
