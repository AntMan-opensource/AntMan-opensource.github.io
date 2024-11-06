
















namespace Envoy {
namespace Http {

namespace {
REGISTER_FACTORY(SkipActionFactory, Matcher::ActionFactory<Matching::HttpFilterActionContext>);

template <class T> using FilterList = std::list<std::unique_ptr<T>>;


template <class T> void recordLatestDataFilter(const typename FilterList<T>::iterator current_filter, T*& latest_filter, const FilterList<T>& filters) {

  
  if (latest_filter == nullptr) {
    latest_filter = current_filter->get();
    return;
  }

  
  
  
  
  
  
  
  
  
  
  if (current_filter != filters.begin() && latest_filter == std::prev(current_filter)->get()) {
    latest_filter = current_filter->get();
  }
}

} 

void ActiveStreamFilterBase::commonContinue() {
  
  if (!canContinue()) {
    ENVOY_STREAM_LOG(trace, "cannot continue filter chain: filter={}", *this, static_cast<const void*>(this));
    return;
  }

  
  ScopeTrackedObjectStack encapsulated_object;
  absl::optional<ScopeTrackerScopeState> state;
  if (parent_.dispatcher_.trackedObjectStackIsEmpty()) {
    restoreContextOnContinue(encapsulated_object);
    state.emplace(&encapsulated_object, parent_.dispatcher_);
  }

  ENVOY_STREAM_LOG(trace, "continuing filter chain: filter={}", *this, static_cast<const void*>(this));
  ASSERT(!canIterate(), "Attempting to continue iteration while the IterationState is already Continue");
  
  
  if (stoppedAll()) {
    iterate_from_current_filter_ = true;
  }
  allowIteration();

  
  if (has1xxHeaders()) {
    continued_1xx_headers_ = true;
    do1xxHeaders();
    
    
    if (!parent_.filter_manager_callbacks_.responseHeaders()) {
      return;
    }
  }

  
  
  
  if (!headers_continued_) {
    headers_continued_ = true;
    doHeaders(complete() && !bufferedData() && !hasTrailers());
  }

  doMetadata();

  
  
  
  
  const bool had_trailers_before_data = hasTrailers();
  if (bufferedData()) {
    doData(complete() && !had_trailers_before_data);
  }

  if (had_trailers_before_data) {
    doTrailers();
  }

  iterate_from_current_filter_ = false;
}

bool ActiveStreamFilterBase::commonHandleAfter1xxHeadersCallback(FilterHeadersStatus status) {
  ASSERT(parent_.state_.has_1xx_headers_);
  ASSERT(!continued_1xx_headers_);
  ASSERT(canIterate());

  if (status == FilterHeadersStatus::StopIteration) {
    iteration_state_ = IterationState::StopSingleIteration;
    return false;
  } else {
    ASSERT(status == FilterHeadersStatus::Continue);
    continued_1xx_headers_ = true;
    return true;
  }
}

bool ActiveStreamFilterBase::commonHandleAfterHeadersCallback(FilterHeadersStatus status, bool& end_stream) {
  ASSERT(!headers_continued_);
  ASSERT(canIterate());

  switch (status) {
  case FilterHeadersStatus::StopIteration:
    iteration_state_ = IterationState::StopSingleIteration;
    break;
  case FilterHeadersStatus::StopAllIterationAndBuffer:
    iteration_state_ = IterationState::StopAllBuffer;
    break;
  case FilterHeadersStatus::StopAllIterationAndWatermark:
    iteration_state_ = IterationState::StopAllWatermark;
    break;
  case FilterHeadersStatus::ContinueAndDontEndStream:
    end_stream = false;
    headers_continued_ = true;
    ENVOY_STREAM_LOG(debug, "converting to headers and body (body not available yet)", parent_);
    break;
  case FilterHeadersStatus::Continue:
    headers_continued_ = true;
    break;
  }

  handleMetadataAfterHeadersCallback();

  if (stoppedAll() || status == FilterHeadersStatus::StopIteration) {
    return false;
  } else {
    return true;
  }
}

void ActiveStreamFilterBase::commonHandleBufferData(Buffer::Instance& provided_data) {

  
  
  
  
  
  
  if (bufferedData().get() != &provided_data) {
    if (!bufferedData()) {
      bufferedData() = createBuffer();
    }
    bufferedData()->move(provided_data);
  }
}

bool ActiveStreamFilterBase::commonHandleAfterDataCallback(FilterDataStatus status, Buffer::Instance& provided_data, bool& buffer_was_streaming) {


  if (status == FilterDataStatus::Continue) {
    if (iteration_state_ == IterationState::StopSingleIteration) {
      commonHandleBufferData(provided_data);
      commonContinue();
      return false;
    } else {
      ASSERT(headers_continued_);
    }
  } else {
    iteration_state_ = IterationState::StopSingleIteration;
    if (status == FilterDataStatus::StopIterationAndBuffer || status == FilterDataStatus::StopIterationAndWatermark) {
      buffer_was_streaming = status == FilterDataStatus::StopIterationAndWatermark;
      commonHandleBufferData(provided_data);
    } else if (complete() && !hasTrailers() && !bufferedData() &&   !parent_.state_.destroyed_) {


      
      
      
      ASSERT(end_stream_);
      bufferedData() = createBuffer();
    }

    return false;
  }

  return true;
}

bool ActiveStreamFilterBase::commonHandleAfterTrailersCallback(FilterTrailersStatus status) {

  if (status == FilterTrailersStatus::Continue) {
    if (iteration_state_ == IterationState::StopSingleIteration) {
      commonContinue();
      return false;
    } else {
      ASSERT(headers_continued_);
    }
  } else if (status == FilterTrailersStatus::StopIteration) {
    if (canIterate()) {
      iteration_state_ = IterationState::StopSingleIteration;
    }
    return false;
  }

  return true;
}

const Network::Connection* ActiveStreamFilterBase::connection() { return parent_.connection(); }

Event::Dispatcher& ActiveStreamFilterBase::dispatcher() { return parent_.dispatcher_; }

StreamInfo::StreamInfo& ActiveStreamFilterBase::streamInfo() { return parent_.stream_info_; }

Tracing::Span& ActiveStreamFilterBase::activeSpan() {
  return parent_.filter_manager_callbacks_.activeSpan();
}

const ScopeTrackedObject& ActiveStreamFilterBase::scope() {
  return parent_.filter_manager_callbacks_.scope();
}

void ActiveStreamFilterBase::restoreContextOnContinue( ScopeTrackedObjectStack& tracked_object_stack) {
  parent_.contextOnContinue(tracked_object_stack);
}

Tracing::Config& ActiveStreamFilterBase::tracingConfig() {
  return parent_.filter_manager_callbacks_.tracingConfig();
}

Upstream::ClusterInfoConstSharedPtr ActiveStreamFilterBase::clusterInfo() {
  return parent_.filter_manager_callbacks_.clusterInfo();
}

Router::RouteConstSharedPtr ActiveStreamFilterBase::route() { return route(nullptr); }

Router::RouteConstSharedPtr ActiveStreamFilterBase::route(const Router::RouteCallback& cb) {
  return parent_.filter_manager_callbacks_.route(cb);
}

void ActiveStreamFilterBase::setRoute(Router::RouteConstSharedPtr route) {
  parent_.filter_manager_callbacks_.setRoute(std::move(route));
}

void ActiveStreamFilterBase::clearRouteCache() {
  parent_.filter_manager_callbacks_.clearRouteCache();
}

void ActiveStreamFilterBase::resetIdleTimer() {
  parent_.filter_manager_callbacks_.resetIdleTimer();
}

void FilterMatchState::evaluateMatchTreeWithNewData(MatchDataUpdateFunc update_func) {
  if (match_tree_evaluated_ || !matching_data_) {
    return;
  }

  update_func(*matching_data_);

  const auto match_result = Matcher::evaluateMatch<HttpMatchingData>(*match_tree_, *matching_data_);

  match_tree_evaluated_ = match_result.match_state_ == Matcher::MatchState::MatchComplete;

  if (match_tree_evaluated_ && match_result.result_) {
    const auto result = match_result.result_();
    if (SkipAction().typeUrl() == result->typeUrl()) {
      skip_filter_ = true;
    } else {
      filter_->onMatchCallback(*result);
    }
  }
}

bool ActiveStreamDecoderFilter::canContinue() {
  
  
  
  
  
  return !parent_.state_.local_complete_;
}

bool ActiveStreamEncoderFilter::canContinue() {
  
  
  return !parent_.state_.remote_encode_complete_;
}

Buffer::InstancePtr ActiveStreamDecoderFilter::createBuffer() {
  auto buffer = dispatcher().getWatermarkFactory().createBuffer( [this]() -> void { this->requestDataDrained(); }, [this]() -> void { this->requestDataTooLarge(); }, []() -> void {  });


  buffer->setWatermarks(parent_.buffer_limit_);
  return buffer;
}

Buffer::InstancePtr& ActiveStreamDecoderFilter::bufferedData() {
  return parent_.buffered_request_data_;
}

bool ActiveStreamDecoderFilter::complete() { return parent_.state_.remote_decode_complete_; }

void ActiveStreamDecoderFilter::doHeaders(bool end_stream) {
  parent_.decodeHeaders(this, *parent_.filter_manager_callbacks_.requestHeaders(), end_stream);
}

void ActiveStreamDecoderFilter::doData(bool end_stream) {
  parent_.decodeData(this, *parent_.buffered_request_data_, end_stream, FilterManager::FilterIterationStartState::CanStartFromCurrent);
}

void ActiveStreamDecoderFilter::doTrailers() {
  parent_.decodeTrailers(this, *parent_.filter_manager_callbacks_.requestTrailers());
}
bool ActiveStreamDecoderFilter::hasTrailers() {
  return parent_.filter_manager_callbacks_.requestTrailers().has_value();
}

void ActiveStreamDecoderFilter::drainSavedRequestMetadata() {
  ASSERT(saved_request_metadata_ != nullptr);
  for (auto& metadata_map : *getSavedRequestMetadata()) {
    parent_.decodeMetadata(this, *metadata_map);
  }
  getSavedRequestMetadata()->clear();
}

void ActiveStreamDecoderFilter::handleMetadataAfterHeadersCallback() {
  
  const bool saved_state = iterate_from_current_filter_;
  iterate_from_current_filter_ = true;
  
  
  if (!stoppedAll() && saved_request_metadata_ != nullptr && !getSavedRequestMetadata()->empty()) {
    drainSavedRequestMetadata();
  }
  
  iterate_from_current_filter_ = saved_state;
}

RequestTrailerMap& ActiveStreamDecoderFilter::addDecodedTrailers() {
  return parent_.addDecodedTrailers();
}

void ActiveStreamDecoderFilter::addDecodedData(Buffer::Instance& data, bool streaming) {
  parent_.addDecodedData(*this, data, streaming);
}

MetadataMapVector& ActiveStreamDecoderFilter::addDecodedMetadata() {
  return parent_.addDecodedMetadata();
}

void ActiveStreamDecoderFilter::injectDecodedDataToFilterChain(Buffer::Instance& data, bool end_stream) {
  if (!headers_continued_) {
    headers_continued_ = true;
    doHeaders(false);
  }
  parent_.decodeData(this, data, end_stream, FilterManager::FilterIterationStartState::CanStartFromCurrent);
}

void ActiveStreamDecoderFilter::continueDecoding() { commonContinue(); }
const Buffer::Instance* ActiveStreamDecoderFilter::decodingBuffer() {
  return parent_.buffered_request_data_.get();
}

void ActiveStreamDecoderFilter::modifyDecodingBuffer( std::function<void(Buffer::Instance&)> callback) {
  ASSERT(parent_.state_.latest_data_decoding_filter_ == this);
  callback(*parent_.buffered_request_data_.get());
}

void ActiveStreamDecoderFilter::sendLocalReply( Code code, absl::string_view body, std::function<void(ResponseHeaderMap& headers)> modify_headers, const absl::optional<Grpc::Status::GrpcStatus> grpc_status, absl::string_view details) {


  parent_.sendLocalReply(code, body, modify_headers, grpc_status, details);
}

void ActiveStreamDecoderFilter::encode1xxHeaders(ResponseHeaderMapPtr&& headers) {
  
  
  
  if (parent_.proxy_100_continue_) {
    parent_.filter_manager_callbacks_.setInformationalHeaders(std::move(headers));
    parent_.encode1xxHeaders(nullptr, *parent_.filter_manager_callbacks_.informationalHeaders());
  }
}

ResponseHeaderMapOptRef ActiveStreamDecoderFilter::informationalHeaders() const {
  return parent_.filter_manager_callbacks_.informationalHeaders();
}

void ActiveStreamDecoderFilter::encodeHeaders(ResponseHeaderMapPtr&& headers, bool end_stream, absl::string_view details) {
  parent_.stream_info_.setResponseCodeDetails(details);
  parent_.filter_manager_callbacks_.setResponseHeaders(std::move(headers));
  parent_.encodeHeaders(nullptr, *parent_.filter_manager_callbacks_.responseHeaders(), end_stream);
}

ResponseHeaderMapOptRef ActiveStreamDecoderFilter::responseHeaders() const {
  return parent_.filter_manager_callbacks_.responseHeaders();
}

void ActiveStreamDecoderFilter::encodeData(Buffer::Instance& data, bool end_stream) {
  parent_.encodeData(nullptr, data, end_stream, FilterManager::FilterIterationStartState::CanStartFromCurrent);
}

void ActiveStreamDecoderFilter::encodeTrailers(ResponseTrailerMapPtr&& trailers) {
  parent_.filter_manager_callbacks_.setResponseTrailers(std::move(trailers));
  parent_.encodeTrailers(nullptr, *parent_.filter_manager_callbacks_.responseTrailers());
}

ResponseTrailerMapOptRef ActiveStreamDecoderFilter::responseTrailers() const {
  return parent_.filter_manager_callbacks_.responseTrailers();
}

void ActiveStreamDecoderFilter::encodeMetadata(MetadataMapPtr&& metadata_map_ptr) {
  parent_.encodeMetadata(nullptr, std::move(metadata_map_ptr));
}

void ActiveStreamDecoderFilter::onDecoderFilterAboveWriteBufferHighWatermark() {
  parent_.filter_manager_callbacks_.onDecoderFilterAboveWriteBufferHighWatermark();
}

void ActiveStreamDecoderFilter::requestDataTooLarge() {
  ENVOY_STREAM_LOG(debug, "request data too large watermark exceeded", parent_);
  if (parent_.state_.decoder_filters_streaming_) {
    onDecoderFilterAboveWriteBufferHighWatermark();
  } else {
    parent_.filter_manager_callbacks_.onRequestDataTooLarge();
    sendLocalReply(Code::PayloadTooLarge, CodeUtility::toString(Code::PayloadTooLarge), nullptr, absl::nullopt, StreamInfo::ResponseCodeDetails::get().RequestPayloadTooLarge);
  }
}

void FilterManager::addStreamDecoderFilterWorker(StreamDecoderFilterSharedPtr filter, FilterMatchStateSharedPtr match_state, bool dual_filter) {

  ActiveStreamDecoderFilterPtr wrapper( new ActiveStreamDecoderFilter(*this, filter, match_state, dual_filter));

  
  
  if (match_state) {
    match_state->filter_ = filter.get();
  }

  filter->setDecoderFilterCallbacks(*wrapper);
  
  
  
  
  
  
  
  
  LinkedList::moveIntoListBack(std::move(wrapper), decoder_filters_);
}

void FilterManager::addStreamEncoderFilterWorker(StreamEncoderFilterSharedPtr filter, FilterMatchStateSharedPtr match_state, bool dual_filter) {

  ActiveStreamEncoderFilterPtr wrapper( new ActiveStreamEncoderFilter(*this, filter, match_state, dual_filter));

  if (match_state) {
    match_state->filter_ = filter.get();
  }

  filter->setEncoderFilterCallbacks(*wrapper);
  
  
  
  
  
  
  
  
  LinkedList::moveIntoList(std::move(wrapper), encoder_filters_);
}

void FilterManager::addAccessLogHandler(AccessLog::InstanceSharedPtr handler) {
  access_log_handlers_.push_back(handler);
}

void FilterManager::maybeContinueDecoding( const std::list<ActiveStreamDecoderFilterPtr>::iterator& continue_data_entry) {
  if (continue_data_entry != decoder_filters_.end()) {
    
    
    
    ASSERT(buffered_request_data_);
    (*continue_data_entry)->iteration_state_ = ActiveStreamFilterBase::IterationState::StopSingleIteration;
    (*continue_data_entry)->continueDecoding();
  }
}

void FilterManager::decodeHeaders(ActiveStreamDecoderFilter* filter, RequestHeaderMap& headers, bool end_stream) {
  
  std::list<ActiveStreamDecoderFilterPtr>::iterator entry = commonDecodePrefix(filter, FilterIterationStartState::AlwaysStartFromNext);
  std::list<ActiveStreamDecoderFilterPtr>::iterator continue_data_entry = decoder_filters_.end();

  for (; entry != decoder_filters_.end(); entry++) {
    (*entry)->maybeEvaluateMatchTreeWithNewData( [&](auto& matching_data) { matching_data.onRequestHeaders(headers); });

    if ((*entry)->skipFilter()) {
      continue;
    }

    ASSERT(!(state_.filter_call_state_ & FilterCallState::DecodeHeaders));
    state_.filter_call_state_ |= FilterCallState::DecodeHeaders;
    (*entry)->end_stream_ = (end_stream && continue_data_entry == decoder_filters_.end());
    FilterHeadersStatus status = (*entry)->decodeHeaders(headers, (*entry)->end_stream_);
    if (state_.decoder_filter_chain_aborted_) {
      ENVOY_STREAM_LOG(trace, "decodeHeaders filter iteration aborted due to local reply: filter={}", *this, static_cast<const void*>((*entry).get()));

      status = FilterHeadersStatus::StopIteration;
    }

    ASSERT(!(status == FilterHeadersStatus::ContinueAndDontEndStream && !(*entry)->end_stream_), "Filters should not return FilterHeadersStatus::ContinueAndDontEndStream from " "decodeHeaders when end_stream is already false");


    state_.filter_call_state_ &= ~FilterCallState::DecodeHeaders;
    ENVOY_STREAM_LOG(trace, "decode headers called: filter={} status={}", *this, static_cast<const void*>((*entry).get()), static_cast<uint64_t>(status));

    (*entry)->decode_headers_called_ = true;

    const auto continue_iteration = (*entry)->commonHandleAfterHeadersCallback(status, end_stream);
    ENVOY_BUG(!continue_iteration || !state_.local_complete_, "Filter did not return StopAll or StopIteration after sending a local reply.");

    
    if ((*entry)->end_stream_) {
      (*entry)->handle_->decodeComplete();
    }

    
    if (state_.local_complete_ && std::next(entry) != decoder_filters_.end()) {
      maybeContinueDecoding(continue_data_entry);
      return;
    }

    const bool new_metadata_added = processNewlyAddedMetadata();
    
    
    
    if ((*entry)->end_stream_ && new_metadata_added && !buffered_request_data_) {
      Buffer::OwnedImpl empty_data("");
      ENVOY_STREAM_LOG( trace, "inserting an empty data frame for end_stream due metadata being added.", *this);
      
      
      addDecodedData(*((*entry).get()), empty_data, true);
    }

    if (!continue_iteration && std::next(entry) != decoder_filters_.end()) {
      
      
      
      maybeContinueDecoding(continue_data_entry);
      return;
    }

    
    
    if (end_stream && buffered_request_data_ && continue_data_entry == decoder_filters_.end()) {
      continue_data_entry = entry;
    }
  }

  maybeContinueDecoding(continue_data_entry);

  if (end_stream) {
    disarmRequestTimeout();
  }
}

void FilterManager::decodeData(ActiveStreamDecoderFilter* filter, Buffer::Instance& data, bool end_stream, FilterIterationStartState filter_iteration_start_state) {

  ScopeTrackerScopeState scope(&*this, dispatcher_);
  filter_manager_callbacks_.resetIdleTimer();

  const bool fix_added_trailers = Runtime::runtimeFeatureEnabled("envoy.reloadable_features.fix_added_trailers");

  
  
  if (state_.local_complete_) {
    return;
  }

  auto trailers_added_entry = decoder_filters_.end();
  const bool trailers_exists_at_start = filter_manager_callbacks_.requestTrailers().has_value();
  
  std::list<ActiveStreamDecoderFilterPtr>::iterator entry = commonDecodePrefix(filter, filter_iteration_start_state);

  for (; entry != decoder_filters_.end(); entry++) {
    if ((*entry)->skipFilter()) {
      continue;
    }
    
    if (handleDataIfStopAll(**entry, data, state_.decoder_filters_streaming_)) {
      return;
    }
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    if ((*entry)->end_stream_) {
      return;
    }
    ASSERT(!(state_.filter_call_state_ & FilterCallState::DecodeData));

    
    
    
    if (end_stream) {
      state_.filter_call_state_ |= FilterCallState::LastDataFrame;
    }

    recordLatestDataFilter(entry, state_.latest_data_decoding_filter_, decoder_filters_);

    state_.filter_call_state_ |= FilterCallState::DecodeData;
    (*entry)->end_stream_ = end_stream && !filter_manager_callbacks_.requestTrailers();
    FilterDataStatus status = (*entry)->handle_->decodeData(data, (*entry)->end_stream_);
    if ((*entry)->end_stream_) {
      (*entry)->handle_->decodeComplete();
    }
    state_.filter_call_state_ &= ~FilterCallState::DecodeData;
    if (end_stream) {
      state_.filter_call_state_ &= ~FilterCallState::LastDataFrame;
    }
    ENVOY_STREAM_LOG(trace, "decode data called: filter={} status={}", *this, static_cast<const void*>((*entry).get()), static_cast<uint64_t>(status));
    if (state_.decoder_filter_chain_aborted_) {
      ENVOY_STREAM_LOG(trace, "decodeData filter iteration aborted due to local reply: filter={}", *this, static_cast<const void*>((*entry).get()));
      return;
    }

    processNewlyAddedMetadata();

    if (!trailers_exists_at_start && filter_manager_callbacks_.requestTrailers() && trailers_added_entry == decoder_filters_.end()) {
      if (fix_added_trailers) {
        end_stream = false;
      }
      trailers_added_entry = entry;
    }

    if (!(*entry)->commonHandleAfterDataCallback(status, data, state_.decoder_filters_streaming_) && std::next(entry) != decoder_filters_.end()) {
      
      
      
      if (fix_added_trailers) {
        break;
      } else {
        return;
      }
    }
  }

  
  
  if (trailers_added_entry != decoder_filters_.end()) {
    decodeTrailers(trailers_added_entry->get(), *filter_manager_callbacks_.requestTrailers());
  }

  if (end_stream) {
    disarmRequestTimeout();
  }
}

RequestTrailerMap& FilterManager::addDecodedTrailers() {
  
  ASSERT(state_.filter_call_state_ & FilterCallState::LastDataFrame);

  filter_manager_callbacks_.setRequestTrailers(RequestTrailerMapImpl::create());
  return *filter_manager_callbacks_.requestTrailers();
}

void FilterManager::addDecodedData(ActiveStreamDecoderFilter& filter, Buffer::Instance& data, bool streaming) {
  if (state_.filter_call_state_ == 0 || (state_.filter_call_state_ & FilterCallState::DecodeHeaders) || (state_.filter_call_state_ & FilterCallState::DecodeData) || ((state_.filter_call_state_ & FilterCallState::DecodeTrailers) && !filter.canIterate())) {


    
    state_.decoder_filters_streaming_ = streaming;
    
    
    filter.commonHandleBufferData(data);
  } else if (state_.filter_call_state_ & FilterCallState::DecodeTrailers) {
    
    
    decodeData(&filter, data, false, FilterIterationStartState::AlwaysStartFromNext);
  } else {
    IS_ENVOY_BUG("Invalid request data");
    sendLocalReply(Http::Code::BadGateway, "Filter error", nullptr, absl::nullopt, StreamInfo::ResponseCodeDetails::get().FilterAddedInvalidRequestData);
  }
}

MetadataMapVector& FilterManager::addDecodedMetadata() { return *getRequestMetadataMapVector(); }

void FilterManager::decodeTrailers(ActiveStreamDecoderFilter* filter, RequestTrailerMap& trailers) {
  
  if (state_.local_complete_) {
    return;
  }

  
  std::list<ActiveStreamDecoderFilterPtr>::iterator entry = commonDecodePrefix(filter, FilterIterationStartState::CanStartFromCurrent);

  for (; entry != decoder_filters_.end(); entry++) {
    (*entry)->maybeEvaluateMatchTreeWithNewData( [&](auto& matching_data) { matching_data.onRequestTrailers(trailers); });

    if ((*entry)->skipFilter()) {
      continue;
    }

    
    if ((*entry)->stoppedAll()) {
      return;
    }
    ASSERT(!(state_.filter_call_state_ & FilterCallState::DecodeTrailers));
    state_.filter_call_state_ |= FilterCallState::DecodeTrailers;
    FilterTrailersStatus status = (*entry)->handle_->decodeTrailers(trailers);
    (*entry)->handle_->decodeComplete();
    (*entry)->end_stream_ = true;
    state_.filter_call_state_ &= ~FilterCallState::DecodeTrailers;
    ENVOY_STREAM_LOG(trace, "decode trailers called: filter={} status={}", *this, static_cast<const void*>((*entry).get()), static_cast<uint64_t>(status));
    if (state_.decoder_filter_chain_aborted_) {
      ENVOY_STREAM_LOG(trace, "decodeTrailers filter iteration aborted due to local reply: filter={}", *this, static_cast<const void*>((*entry).get()));

      status = FilterTrailersStatus::StopIteration;
    }

    processNewlyAddedMetadata();

    if (!(*entry)->commonHandleAfterTrailersCallback(status)) {
      return;
    }
  }
  disarmRequestTimeout();
}

void FilterManager::decodeMetadata(ActiveStreamDecoderFilter* filter, MetadataMap& metadata_map) {
  
  std::list<ActiveStreamDecoderFilterPtr>::iterator entry = commonDecodePrefix(filter, FilterIterationStartState::CanStartFromCurrent);

  for (; entry != decoder_filters_.end(); entry++) {
    if ((*entry)->skipFilter()) {
      continue;
    }
    
    
    
    
    if (!(*entry)->decode_headers_called_ || (*entry)->stoppedAll()) {
      Http::MetadataMapPtr metadata_map_ptr = std::make_unique<Http::MetadataMap>(metadata_map);
      (*entry)->getSavedRequestMetadata()->emplace_back(std::move(metadata_map_ptr));
      return;
    }

    FilterMetadataStatus status = (*entry)->handle_->decodeMetadata(metadata_map);
    ENVOY_STREAM_LOG(trace, "decode metadata called: filter={} status={}, metadata: {}", *this, static_cast<const void*>((*entry).get()), static_cast<uint64_t>(status), metadata_map);

  }
}

void FilterManager::maybeEndDecode(bool end_stream) {
  ASSERT(!state_.remote_decode_complete_);
  state_.remote_decode_complete_ = end_stream;
  if (end_stream) {
    stream_info_.downstreamTiming().onLastDownstreamRxByteReceived(dispatcher().timeSource());
    ENVOY_STREAM_LOG(debug, "request end stream", *this);
  }
}

void FilterManager::disarmRequestTimeout() { filter_manager_callbacks_.disarmRequestTimeout(); }

std::list<ActiveStreamEncoderFilterPtr>::iterator FilterManager::commonEncodePrefix(ActiveStreamEncoderFilter* filter, bool end_stream, FilterIterationStartState filter_iteration_start_state) {

  
  
  if (filter == nullptr) {
    ASSERT(!state_.local_complete_);
    state_.local_complete_ = end_stream;
    return encoder_filters_.begin();
  }

  if (filter_iteration_start_state == FilterIterationStartState::CanStartFromCurrent && (*(filter->entry()))->iterate_from_current_filter_) {
    
    
    return filter->entry();
  }
  return std::next(filter->entry());
}

std::list<ActiveStreamDecoderFilterPtr>::iterator FilterManager::commonDecodePrefix(ActiveStreamDecoderFilter* filter, FilterIterationStartState filter_iteration_start_state) {

  if (!filter) {
    return decoder_filters_.begin();
  }
  if (filter_iteration_start_state == FilterIterationStartState::CanStartFromCurrent && (*(filter->entry()))->iterate_from_current_filter_) {
    
    
    return filter->entry();
  }
  return std::next(filter->entry());
}

void FilterManager::onLocalReply(StreamFilterBase::LocalReplyData& data) {
  state_.under_on_local_reply_ = true;
  filter_manager_callbacks_.onLocalReply(data.code_);

  for (auto entry : filters_) {
    if (entry->onLocalReply(data) == LocalErrorStatus::ContinueAndResetStream) {
      data.reset_imminent_ = true;
    }
  }
  state_.under_on_local_reply_ = false;
}

void FilterManager::sendLocalReply( Code code, absl::string_view body, const std::function<void(ResponseHeaderMap& headers)>& modify_headers, const absl::optional<Grpc::Status::GrpcStatus> grpc_status, absl::string_view details) {


  ASSERT(!state_.under_on_local_reply_);
  const bool is_head_request = state_.is_head_request_;
  const bool is_grpc_request = state_.is_grpc_request_;

  
  
  if (state_.filter_call_state_ & (FilterCallState::DecodeHeaders | FilterCallState::DecodeData | FilterCallState::DecodeTrailers)) {
    state_.decoder_filter_chain_aborted_ = true;
  } else if (state_.filter_call_state_ & (FilterCallState::EncodeHeaders | FilterCallState::EncodeData | FilterCallState::EncodeTrailers)) {

    state_.encoder_filter_chain_aborted_ = true;
  }

  stream_info_.setResponseCodeDetails(details);
  StreamFilterBase::LocalReplyData data{code, details, false};
  FilterManager::onLocalReply(data);
  if (data.reset_imminent_) {
    ENVOY_STREAM_LOG(debug, "Resetting stream due to {}. onLocalReply requested reset.", *this, details);
    filter_manager_callbacks_.resetStream();
    return;
  }

  if (!filter_manager_callbacks_.responseHeaders().has_value()) {
    
    sendLocalReplyViaFilterChain(is_grpc_request, code, body, modify_headers, is_head_request, grpc_status, details);
  } else if (!state_.non_100_response_headers_encoded_) {
    ENVOY_STREAM_LOG(debug, "Sending local reply with details {} directly to the encoder", *this, details);
    
    
    
    
    
    
    sendDirectLocalReply(code, body, modify_headers, state_.is_head_request_, grpc_status);
  } else {
    
    
    ENVOY_STREAM_LOG(debug, "Resetting stream due to {}. Prior headers have already been sent", *this, details);
    
    
    filter_manager_callbacks_.resetStream();
  }
}

void FilterManager::sendLocalReplyViaFilterChain( bool is_grpc_request, Code code, absl::string_view body, const std::function<void(ResponseHeaderMap& headers)>& modify_headers, bool is_head_request, const absl::optional<Grpc::Status::GrpcStatus> grpc_status, absl::string_view details) {


  ENVOY_STREAM_LOG(debug, "Sending local reply with details {}", *this, details);
  ASSERT(!filter_manager_callbacks_.responseHeaders().has_value());
  
  
  
  createFilterChain();

  Utility::sendLocalReply( state_.destroyed_, Utility::EncodeFunctions{

          [this, modify_headers](ResponseHeaderMap& headers) -> void {
            if (streamInfo().route() && streamInfo().route()->routeEntry()) {
              streamInfo().route()->routeEntry()->finalizeResponseHeaders(headers, streamInfo());
            }
            if (modify_headers) {
              modify_headers(headers);
            }
          }, [this](ResponseHeaderMap& response_headers, Code& code, std::string& body, absl::string_view& content_type) -> void {

            
            
            local_reply_.rewrite(filter_manager_callbacks_.requestHeaders().ptr(), response_headers, stream_info_, code, body, content_type);
          }, [this, modify_headers](ResponseHeaderMapPtr&& headers, bool end_stream) -> void {
            filter_manager_callbacks_.setResponseHeaders(std::move(headers));
            
            
            encodeHeaders(nullptr, filter_manager_callbacks_.responseHeaders().ref(), end_stream);
          }, [this](Buffer::Instance& data, bool end_stream) -> void {
            
            
            encodeData(nullptr, data, end_stream, FilterManager::FilterIterationStartState::CanStartFromCurrent);
          }}, Utility::LocalReplyData{is_grpc_request, code, body, grpc_status, is_head_request});
}

void FilterManager::sendDirectLocalReply( Code code, absl::string_view body, const std::function<void(ResponseHeaderMap&)>& modify_headers, bool is_head_request, const absl::optional<Grpc::Status::GrpcStatus> grpc_status) {


  
  state_.encoder_filters_streaming_ = true;
  Http::Utility::sendLocalReply( state_.destroyed_, Utility::EncodeFunctions{

          [this, modify_headers](ResponseHeaderMap& headers) -> void {
            if (streamInfo().route() && streamInfo().route()->routeEntry()) {
              streamInfo().route()->routeEntry()->finalizeResponseHeaders(headers, streamInfo());
            }
            if (modify_headers) {
              modify_headers(headers);
            }
          }, [&](ResponseHeaderMap& response_headers, Code& code, std::string& body, absl::string_view& content_type) -> void {

            local_reply_.rewrite(filter_manager_callbacks_.requestHeaders().ptr(), response_headers, stream_info_, code, body, content_type);
          }, [&](ResponseHeaderMapPtr&& response_headers, bool end_stream) -> void {
            
            
            filter_manager_callbacks_.setResponseHeaders(std::move(response_headers));

            state_.non_100_response_headers_encoded_ = true;
            filter_manager_callbacks_.encodeHeaders(*filter_manager_callbacks_.responseHeaders(), end_stream);
            if (state_.saw_downstream_reset_) {
              return;
            }
            maybeEndEncode(end_stream);
          }, [&](Buffer::Instance& data, bool end_stream) -> void {
            filter_manager_callbacks_.encodeData(data, end_stream);
            if (state_.saw_downstream_reset_) {
              return;
            }
            maybeEndEncode(end_stream);
          }}, Utility::LocalReplyData{state_.is_grpc_request_, code, body, grpc_status, is_head_request});
}

void FilterManager::encode1xxHeaders(ActiveStreamEncoderFilter* filter, ResponseHeaderMap& headers) {
  filter_manager_callbacks_.resetIdleTimer();
  ASSERT(proxy_100_continue_);
  
  ASSERT(!state_.has_1xx_headers_ || filter != nullptr);
  
  state_.has_1xx_headers_ = true;

  
  
  
  
  
  std::list<ActiveStreamEncoderFilterPtr>::iterator entry = commonEncodePrefix(filter, false, FilterIterationStartState::AlwaysStartFromNext);
  for (; entry != encoder_filters_.end(); entry++) {
    if ((*entry)->skipFilter()) {
      continue;
    }

    ASSERT(!(state_.filter_call_state_ & FilterCallState::Encode1xxHeaders));
    state_.filter_call_state_ |= FilterCallState::Encode1xxHeaders;
    FilterHeadersStatus status = (*entry)->handle_->encode1xxHeaders(headers);
    state_.filter_call_state_ &= ~FilterCallState::Encode1xxHeaders;
    ENVOY_STREAM_LOG(trace, "encode 1xx continue headers called: filter={} status={}", *this, static_cast<const void*>((*entry).get()), static_cast<uint64_t>(status));
    if (!(*entry)->commonHandleAfter1xxHeadersCallback(status)) {
      return;
    }
  }

  filter_manager_callbacks_.encode1xxHeaders(headers);
}

void FilterManager::maybeContinueEncoding( const std::list<ActiveStreamEncoderFilterPtr>::iterator& continue_data_entry) {
  if (continue_data_entry != encoder_filters_.end()) {
    
    
    
    ASSERT(buffered_response_data_);
    (*continue_data_entry)->iteration_state_ = ActiveStreamFilterBase::IterationState::StopSingleIteration;
    (*continue_data_entry)->continueEncoding();
  }
}

void FilterManager::encodeHeaders(ActiveStreamEncoderFilter* filter, ResponseHeaderMap& headers, bool end_stream) {
  
  ASSERT(!CodeUtility::is1xx(Utility::getResponseStatus(headers)) || Utility::getResponseStatus(headers) == enumToInt(Http::Code::SwitchingProtocols));
  filter_manager_callbacks_.resetIdleTimer();
  disarmRequestTimeout();

  
  std::list<ActiveStreamEncoderFilterPtr>::iterator entry = commonEncodePrefix(filter, end_stream, FilterIterationStartState::AlwaysStartFromNext);
  std::list<ActiveStreamEncoderFilterPtr>::iterator continue_data_entry = encoder_filters_.end();

  for (; entry != encoder_filters_.end(); entry++) {
    (*entry)->maybeEvaluateMatchTreeWithNewData( [&headers](auto& matching_data) { matching_data.onResponseHeaders(headers); });

    if ((*entry)->skipFilter()) {
      continue;
    }
    ASSERT(!(state_.filter_call_state_ & FilterCallState::EncodeHeaders));
    state_.filter_call_state_ |= FilterCallState::EncodeHeaders;
    (*entry)->end_stream_ = (end_stream && continue_data_entry == encoder_filters_.end());
    FilterHeadersStatus status = (*entry)->handle_->encodeHeaders(headers, (*entry)->end_stream_);
    if (state_.encoder_filter_chain_aborted_) {
      ENVOY_STREAM_LOG(trace, "encodeHeaders filter iteration aborted due to local reply: filter={}", *this, static_cast<const void*>((*entry).get()));

      status = FilterHeadersStatus::StopIteration;
    }

    ASSERT(!(status == FilterHeadersStatus::ContinueAndDontEndStream && !(*entry)->end_stream_), "Filters should not return FilterHeadersStatus::ContinueAndDontEndStream from " "encodeHeaders when end_stream is already false");


    state_.filter_call_state_ &= ~FilterCallState::EncodeHeaders;
    ENVOY_STREAM_LOG(trace, "encode headers called: filter={} status={}", *this, static_cast<const void*>((*entry).get()), static_cast<uint64_t>(status));

    (*entry)->encode_headers_called_ = true;

    const auto continue_iteration = (*entry)->commonHandleAfterHeadersCallback(status, end_stream);

    
    if ((*entry)->end_stream_) {
      (*entry)->handle_->encodeComplete();
    }

    if (!continue_iteration) {
      if (!(*entry)->end_stream_) {
        maybeContinueEncoding(continue_data_entry);
      }
      return;
    }

    
    
    if (end_stream && buffered_response_data_ && continue_data_entry == encoder_filters_.end()) {
      continue_data_entry = entry;
    }
  }

  
  
  
  
  
  const auto status = HeaderUtility::checkRequiredResponseHeaders(headers);
  if (!status.ok()) {
    
    sendLocalReply( Http::Code::BadGateway, status.message(), nullptr, absl::nullopt, absl::StrCat(StreamInfo::ResponseCodeDetails::get().FilterRemovedRequiredResponseHeaders, "{", StringUtil::replaceAllEmptySpace(status.message()), "}"));


    return;
  }

  const bool modified_end_stream = (end_stream && continue_data_entry == encoder_filters_.end());
  state_.non_100_response_headers_encoded_ = true;
  filter_manager_callbacks_.encodeHeaders(headers, modified_end_stream);
  if (state_.saw_downstream_reset_) {
    return;
  }
  maybeEndEncode(modified_end_stream);

  if (!modified_end_stream) {
    maybeContinueEncoding(continue_data_entry);
  }
}

void FilterManager::encodeMetadata(ActiveStreamEncoderFilter* filter, MetadataMapPtr&& metadata_map_ptr) {
  filter_manager_callbacks_.resetIdleTimer();

  std::list<ActiveStreamEncoderFilterPtr>::iterator entry = commonEncodePrefix(filter, false, FilterIterationStartState::CanStartFromCurrent);

  for (; entry != encoder_filters_.end(); entry++) {
    if ((*entry)->skipFilter()) {
      continue;
    }
    
    
    
    
    if (!(*entry)->encode_headers_called_ || (*entry)->stoppedAll()) {
      (*entry)->getSavedResponseMetadata()->emplace_back(std::move(metadata_map_ptr));
      return;
    }

    FilterMetadataStatus status = (*entry)->handle_->encodeMetadata(*metadata_map_ptr);
    ENVOY_STREAM_LOG(trace, "encode metadata called: filter={} status={}", *this, static_cast<const void*>((*entry).get()), static_cast<uint64_t>(status));
  }
  

  
  if (!metadata_map_ptr->empty()) {
    MetadataMapVector metadata_map_vector;
    metadata_map_vector.emplace_back(std::move(metadata_map_ptr));
    filter_manager_callbacks_.encodeMetadata(metadata_map_vector);
  }
}

ResponseTrailerMap& FilterManager::addEncodedTrailers() {
  
  ASSERT(state_.filter_call_state_ & FilterCallState::LastDataFrame);

  
  ASSERT(!filter_manager_callbacks_.responseTrailers());

  filter_manager_callbacks_.setResponseTrailers(ResponseTrailerMapImpl::create());
  return *filter_manager_callbacks_.responseTrailers();
}

void FilterManager::addEncodedData(ActiveStreamEncoderFilter& filter, Buffer::Instance& data, bool streaming) {
  if (state_.filter_call_state_ == 0 || (state_.filter_call_state_ & FilterCallState::EncodeHeaders) || (state_.filter_call_state_ & FilterCallState::EncodeData) || ((state_.filter_call_state_ & FilterCallState::EncodeTrailers) && !filter.canIterate())) {


    
    state_.encoder_filters_streaming_ = streaming;
    
    
    filter.commonHandleBufferData(data);
  } else if (state_.filter_call_state_ & FilterCallState::EncodeTrailers) {
    
    
    encodeData(&filter, data, false, FilterIterationStartState::AlwaysStartFromNext);
  } else {
    IS_ENVOY_BUG("Invalid response data");
    sendLocalReply(Http::Code::BadGateway, "Filter error", nullptr, absl::nullopt, StreamInfo::ResponseCodeDetails::get().FilterAddedInvalidResponseData);
  }
}

void FilterManager::encodeData(ActiveStreamEncoderFilter* filter, Buffer::Instance& data, bool end_stream, FilterIterationStartState filter_iteration_start_state) {

  filter_manager_callbacks_.resetIdleTimer();

  
  std::list<ActiveStreamEncoderFilterPtr>::iterator entry = commonEncodePrefix(filter, end_stream, filter_iteration_start_state);
  auto trailers_added_entry = encoder_filters_.end();

  const bool trailers_exists_at_start = filter_manager_callbacks_.responseTrailers().has_value();
  for (; entry != encoder_filters_.end(); entry++) {
    if ((*entry)->skipFilter()) {
      continue;
    }
    
    if (handleDataIfStopAll(**entry, data, state_.encoder_filters_streaming_)) {
      return;
    }
    
    
    if ((*entry)->end_stream_) {
      return;
    }
    ASSERT(!(state_.filter_call_state_ & FilterCallState::EncodeData));

    
    
    
    state_.filter_call_state_ |= FilterCallState::EncodeData;
    if (end_stream) {
      state_.filter_call_state_ |= FilterCallState::LastDataFrame;
    }

    recordLatestDataFilter(entry, state_.latest_data_encoding_filter_, encoder_filters_);

    (*entry)->end_stream_ = end_stream && !filter_manager_callbacks_.responseTrailers();
    FilterDataStatus status = (*entry)->handle_->encodeData(data, (*entry)->end_stream_);
    if (state_.encoder_filter_chain_aborted_) {
      ENVOY_STREAM_LOG(trace, "encodeData filter iteration aborted due to local reply: filter={}", *this, static_cast<const void*>((*entry).get()));
      status = FilterDataStatus::StopIterationNoBuffer;
    }
    if ((*entry)->end_stream_) {
      (*entry)->handle_->encodeComplete();
    }
    state_.filter_call_state_ &= ~FilterCallState::EncodeData;
    if (end_stream) {
      state_.filter_call_state_ &= ~FilterCallState::LastDataFrame;
    }
    ENVOY_STREAM_LOG(trace, "encode data called: filter={} status={}", *this, static_cast<const void*>((*entry).get()), static_cast<uint64_t>(status));

    if (!trailers_exists_at_start && filter_manager_callbacks_.responseTrailers() && trailers_added_entry == encoder_filters_.end()) {
      trailers_added_entry = entry;
    }

    if (!(*entry)->commonHandleAfterDataCallback(status, data, state_.encoder_filters_streaming_)) {
      return;
    }
  }

  const bool modified_end_stream = end_stream && trailers_added_entry == encoder_filters_.end();
  filter_manager_callbacks_.encodeData(data, modified_end_stream);
  if (state_.saw_downstream_reset_) {
    return;
  }
  maybeEndEncode(modified_end_stream);

  
  
  if (trailers_added_entry != encoder_filters_.end()) {
    encodeTrailers(trailers_added_entry->get(), *filter_manager_callbacks_.responseTrailers());
  }
}

void FilterManager::encodeTrailers(ActiveStreamEncoderFilter* filter, ResponseTrailerMap& trailers) {
  filter_manager_callbacks_.resetIdleTimer();

  
  std::list<ActiveStreamEncoderFilterPtr>::iterator entry = commonEncodePrefix(filter, true, FilterIterationStartState::CanStartFromCurrent);
  for (; entry != encoder_filters_.end(); entry++) {
    (*entry)->maybeEvaluateMatchTreeWithNewData( [&](auto& matching_data) { matching_data.onResponseTrailers(trailers); });

    if ((*entry)->skipFilter()) {
      continue;
    }

    
    if ((*entry)->stoppedAll()) {
      return;
    }
    ASSERT(!(state_.filter_call_state_ & FilterCallState::EncodeTrailers));
    state_.filter_call_state_ |= FilterCallState::EncodeTrailers;
    FilterTrailersStatus status = (*entry)->handle_->encodeTrailers(trailers);
    (*entry)->handle_->encodeComplete();
    (*entry)->end_stream_ = true;
    state_.filter_call_state_ &= ~FilterCallState::EncodeTrailers;
    ENVOY_STREAM_LOG(trace, "encode trailers called: filter={} status={}", *this, static_cast<const void*>((*entry).get()), static_cast<uint64_t>(status));
    if (!(*entry)->commonHandleAfterTrailersCallback(status)) {
      return;
    }
  }

  filter_manager_callbacks_.encodeTrailers(trailers);
  if (state_.saw_downstream_reset_) {
    return;
  }
  maybeEndEncode(true);
}

void FilterManager::maybeEndEncode(bool end_stream) {
  if (end_stream) {
    ASSERT(!state_.remote_encode_complete_);
    state_.remote_encode_complete_ = true;
    filter_manager_callbacks_.endStream();
  }
}

bool FilterManager::processNewlyAddedMetadata() {
  if (request_metadata_map_vector_ == nullptr) {
    return false;
  }
  for (const auto& metadata_map : *getRequestMetadataMapVector()) {
    decodeMetadata(nullptr, *metadata_map);
  }
  getRequestMetadataMapVector()->clear();
  return true;
}

bool FilterManager::handleDataIfStopAll(ActiveStreamFilterBase& filter, Buffer::Instance& data, bool& filter_streaming) {
  if (filter.stoppedAll()) {
    ASSERT(!filter.canIterate());
    filter_streaming = filter.iteration_state_ == ActiveStreamFilterBase::IterationState::StopAllWatermark;
    filter.commonHandleBufferData(data);
    return true;
  }
  return false;
}

void FilterManager::callHighWatermarkCallbacks() {
  ++high_watermark_count_;
  for (auto watermark_callbacks : watermark_callbacks_) {
    watermark_callbacks->onAboveWriteBufferHighWatermark();
  }
}

void FilterManager::callLowWatermarkCallbacks() {
  ASSERT(high_watermark_count_ > 0);
  --high_watermark_count_;
  for (auto watermark_callbacks : watermark_callbacks_) {
    watermark_callbacks->onBelowWriteBufferLowWatermark();
  }
}

void FilterManager::setBufferLimit(uint32_t new_limit) {
  ENVOY_STREAM_LOG(debug, "setting buffer limit to {}", *this, new_limit);
  buffer_limit_ = new_limit;
  if (buffered_request_data_) {
    buffered_request_data_->setWatermarks(buffer_limit_);
  }
  if (buffered_response_data_) {
    buffered_response_data_->setWatermarks(buffer_limit_);
  }
}

void FilterManager::contextOnContinue(ScopeTrackedObjectStack& tracked_object_stack) {
  tracked_object_stack.add(connection_);
  tracked_object_stack.add(filter_manager_callbacks_.scope());
}

bool FilterManager::createFilterChain() {
  if (state_.created_filter_chain_) {
    return false;
  }
  bool upgrade_rejected = false;
  const HeaderEntry* upgrade = nullptr;
  if (filter_manager_callbacks_.requestHeaders()) {
    upgrade = filter_manager_callbacks_.requestHeaders()->Upgrade();

    
    if (!upgrade && HeaderUtility::isConnect(*filter_manager_callbacks_.requestHeaders())) {
      upgrade = filter_manager_callbacks_.requestHeaders()->Method();
    }
  }

  state_.created_filter_chain_ = true;
  if (upgrade != nullptr) {
    const Router::RouteEntry::UpgradeMap* upgrade_map = filter_manager_callbacks_.upgradeMap();

    if (filter_chain_factory_.createUpgradeFilterChain(upgrade->value().getStringView(), upgrade_map, *this)) {
      filter_manager_callbacks_.upgradeFilterChainCreated();
      return true;
    } else {
      upgrade_rejected = true;
      
      
    }
  }

  filter_chain_factory_.createFilterChain(*this);
  return !upgrade_rejected;
}

void ActiveStreamDecoderFilter::requestDataDrained() {
  
  
  onDecoderFilterBelowWriteBufferLowWatermark();
}

void ActiveStreamDecoderFilter::onDecoderFilterBelowWriteBufferLowWatermark() {
  parent_.filter_manager_callbacks_.onDecoderFilterBelowWriteBufferLowWatermark();
}

void ActiveStreamDecoderFilter::addDownstreamWatermarkCallbacks( DownstreamWatermarkCallbacks& watermark_callbacks) {
  
  
  ASSERT(std::find(parent_.watermark_callbacks_.begin(), parent_.watermark_callbacks_.end(), &watermark_callbacks) == parent_.watermark_callbacks_.end());
  parent_.watermark_callbacks_.emplace(parent_.watermark_callbacks_.end(), &watermark_callbacks);
  for (uint32_t i = 0; i < parent_.high_watermark_count_; ++i) {
    watermark_callbacks.onAboveWriteBufferHighWatermark();
  }
}

void ActiveStreamDecoderFilter::removeDownstreamWatermarkCallbacks( DownstreamWatermarkCallbacks& watermark_callbacks) {
  ASSERT(std::find(parent_.watermark_callbacks_.begin(), parent_.watermark_callbacks_.end(), &watermark_callbacks) != parent_.watermark_callbacks_.end());
  parent_.watermark_callbacks_.remove(&watermark_callbacks);
}

void ActiveStreamDecoderFilter::setDecoderBufferLimit(uint32_t limit) {
  parent_.setBufferLimit(limit);
}

uint32_t ActiveStreamDecoderFilter::decoderBufferLimit() { return parent_.buffer_limit_; }

bool ActiveStreamDecoderFilter::recreateStream(const ResponseHeaderMap* headers) {
  
  
  
  if (!complete()) {
    return false;
  }

  parent_.stream_info_.setResponseCodeDetails( StreamInfo::ResponseCodeDetails::get().InternalRedirect);

  if (headers != nullptr) {
    
    
    
    
    
    
    ResponseHeaderMapPtr headers_copy = createHeaderMap<ResponseHeaderMapImpl>(*headers);
    parent_.filter_manager_callbacks_.setResponseHeaders(std::move(headers_copy));
    parent_.filter_manager_callbacks_.chargeStats(*headers);
  }

  parent_.filter_manager_callbacks_.recreateStream(parent_.stream_info_.filter_state_);

  return true;
}

void ActiveStreamDecoderFilter::addUpstreamSocketOptions( const Network::Socket::OptionsSharedPtr& options) {

  Network::Socket::appendOptions(parent_.upstream_options_, options);
}

Network::Socket::OptionsSharedPtr ActiveStreamDecoderFilter::getUpstreamSocketOptions() const {
  return parent_.upstream_options_;
}

void ActiveStreamDecoderFilter::requestRouteConfigUpdate( Http::RouteConfigUpdatedCallbackSharedPtr route_config_updated_cb) {
  parent_.filter_manager_callbacks_.requestRouteConfigUpdate(std::move(route_config_updated_cb));
}

absl::optional<Router::ConfigConstSharedPtr> ActiveStreamDecoderFilter::routeConfig() {
  return parent_.filter_manager_callbacks_.routeConfig();
}

Buffer::InstancePtr ActiveStreamEncoderFilter::createBuffer() {
  auto buffer = dispatcher().getWatermarkFactory().createBuffer( [this]() -> void { this->responseDataDrained(); }, [this]() -> void { this->responseDataTooLarge(); }, []() -> void {  });


  buffer->setWatermarks(parent_.buffer_limit_);
  return buffer;
}
Buffer::InstancePtr& ActiveStreamEncoderFilter::bufferedData() {
  return parent_.buffered_response_data_;
}
bool ActiveStreamEncoderFilter::complete() { return parent_.state_.local_complete_; }
bool ActiveStreamEncoderFilter::has1xxHeaders() {
  return parent_.state_.has_1xx_headers_ && !continued_1xx_headers_;
}
void ActiveStreamEncoderFilter::do1xxHeaders() {
  parent_.encode1xxHeaders(this, *parent_.filter_manager_callbacks_.informationalHeaders());
}
void ActiveStreamEncoderFilter::doHeaders(bool end_stream) {
  parent_.encodeHeaders(this, *parent_.filter_manager_callbacks_.responseHeaders(), end_stream);
}
void ActiveStreamEncoderFilter::doData(bool end_stream) {
  parent_.encodeData(this, *parent_.buffered_response_data_, end_stream, FilterManager::FilterIterationStartState::CanStartFromCurrent);
}
void ActiveStreamEncoderFilter::drainSavedResponseMetadata() {
  ASSERT(saved_response_metadata_ != nullptr);
  for (auto& metadata_map : *getSavedResponseMetadata()) {
    parent_.encodeMetadata(this, std::move(metadata_map));
  }
  getSavedResponseMetadata()->clear();
}

void ActiveStreamEncoderFilter::handleMetadataAfterHeadersCallback() {
  
  const bool saved_state = iterate_from_current_filter_;
  iterate_from_current_filter_ = true;
  
  
  if (!stoppedAll() && saved_response_metadata_ != nullptr && !getSavedResponseMetadata()->empty()) {
    drainSavedResponseMetadata();
  }
  
  iterate_from_current_filter_ = saved_state;
}
void ActiveStreamEncoderFilter::doTrailers() {
  parent_.encodeTrailers(this, *parent_.filter_manager_callbacks_.responseTrailers());
}
bool ActiveStreamEncoderFilter::hasTrailers() {
  return parent_.filter_manager_callbacks_.responseTrailers().has_value();
}
void ActiveStreamEncoderFilter::addEncodedData(Buffer::Instance& data, bool streaming) {
  return parent_.addEncodedData(*this, data, streaming);
}

void ActiveStreamEncoderFilter::injectEncodedDataToFilterChain(Buffer::Instance& data, bool end_stream) {
  if (!headers_continued_) {
    headers_continued_ = true;
    doHeaders(false);
  }
  parent_.encodeData(this, data, end_stream, FilterManager::FilterIterationStartState::CanStartFromCurrent);
}

ResponseTrailerMap& ActiveStreamEncoderFilter::addEncodedTrailers() {
  return parent_.addEncodedTrailers();
}

void ActiveStreamEncoderFilter::addEncodedMetadata(MetadataMapPtr&& metadata_map_ptr) {
  return parent_.encodeMetadata(this, std::move(metadata_map_ptr));
}

void ActiveStreamEncoderFilter::onEncoderFilterAboveWriteBufferHighWatermark() {
  ENVOY_STREAM_LOG(debug, "Disabling upstream stream due to filter callbacks.", parent_);
  parent_.callHighWatermarkCallbacks();
}

void ActiveStreamEncoderFilter::onEncoderFilterBelowWriteBufferLowWatermark() {
  ENVOY_STREAM_LOG(debug, "Enabling upstream stream due to filter callbacks.", parent_);
  parent_.callLowWatermarkCallbacks();
}

void ActiveStreamEncoderFilter::setEncoderBufferLimit(uint32_t limit) {
  parent_.setBufferLimit(limit);
}

uint32_t ActiveStreamEncoderFilter::encoderBufferLimit() { return parent_.buffer_limit_; }

void ActiveStreamEncoderFilter::continueEncoding() { commonContinue(); }

const Buffer::Instance* ActiveStreamEncoderFilter::encodingBuffer() {
  return parent_.buffered_response_data_.get();
}

void ActiveStreamEncoderFilter::modifyEncodingBuffer( std::function<void(Buffer::Instance&)> callback) {
  ASSERT(parent_.state_.latest_data_encoding_filter_ == this);
  callback(*parent_.buffered_response_data_.get());
}

void ActiveStreamEncoderFilter::sendLocalReply( Code code, absl::string_view body, std::function<void(ResponseHeaderMap& headers)> modify_headers, const absl::optional<Grpc::Status::GrpcStatus> grpc_status, absl::string_view details) {


  parent_.sendLocalReply(code, body, modify_headers, grpc_status, details);
}

Http1StreamEncoderOptionsOptRef ActiveStreamEncoderFilter::http1StreamEncoderOptions() {
  
  
  return parent_.filter_manager_callbacks_.http1StreamEncoderOptions();
}

void ActiveStreamEncoderFilter::responseDataTooLarge() {
  ENVOY_STREAM_LOG(debug, "response data too large watermark exceeded", parent_);
  if (parent_.state_.encoder_filters_streaming_) {
    onEncoderFilterAboveWriteBufferHighWatermark();
  } else {
    parent_.filter_manager_callbacks_.onResponseDataTooLarge();

    
    
    parent_.sendLocalReply( Http::Code::InternalServerError, CodeUtility::toString(Http::Code::InternalServerError), nullptr, absl::nullopt, StreamInfo::ResponseCodeDetails::get().ResponsePayloadTooLarge);

  }
}

void ActiveStreamEncoderFilter::responseDataDrained() {
  onEncoderFilterBelowWriteBufferLowWatermark();
}

void ActiveStreamFilterBase::resetStream() { parent_.filter_manager_callbacks_.resetStream(); }

uint64_t ActiveStreamFilterBase::streamId() const { return parent_.streamId(); }

Buffer::BufferMemoryAccountSharedPtr ActiveStreamDecoderFilter::account() const {
  return parent_.account();
}

void ActiveStreamDecoderFilter::setUpstreamOverrideHost(absl::string_view host) {
  parent_.upstream_override_host_.emplace(std::move(host));
}

absl::optional<absl::string_view> ActiveStreamDecoderFilter::upstreamOverrideHost() const {
  return parent_.upstream_override_host_;
}

} 
} 
