




















































namespace Envoy {
namespace Http {

bool requestWasConnect(const RequestHeaderMapPtr& headers, Protocol protocol) {
  if (!headers) {
    return false;
  }
  if (protocol <= Protocol::Http11) {
    return HeaderUtility::isConnect(*headers);
  }
  
  return HeaderUtility::isConnect(*headers) || Utility::isUpgrade(*headers);
}

ConnectionManagerStats ConnectionManagerImpl::generateStats(const std::string& prefix, Stats::Scope& scope) {
  return ConnectionManagerStats( {ALL_HTTP_CONN_MAN_STATS(POOL_COUNTER_PREFIX(scope, prefix), POOL_GAUGE_PREFIX(scope, prefix), POOL_HISTOGRAM_PREFIX(scope, prefix))}, prefix, scope);


}

ConnectionManagerTracingStats ConnectionManagerImpl::generateTracingStats(const std::string& prefix, Stats::Scope& scope) {
  return {CONN_MAN_TRACING_STATS(POOL_COUNTER_PREFIX(scope, prefix + "tracing."))};
}

ConnectionManagerListenerStats ConnectionManagerImpl::generateListenerStats(const std::string& prefix, Stats::Scope& scope) {
  return {CONN_MAN_LISTENER_STATS(POOL_COUNTER_PREFIX(scope, prefix))};
}

ConnectionManagerImpl::ConnectionManagerImpl(ConnectionManagerConfig& config, const Network::DrainDecision& drain_close, Random::RandomGenerator& random_generator, Http::Context& http_context, Runtime::Loader& runtime, const LocalInfo::LocalInfo& local_info, Upstream::ClusterManager& cluster_manager, Server::OverloadManager& overload_manager, TimeSource& time_source)






    : config_(config), stats_(config_.stats()), conn_length_(new Stats::HistogramCompletableTimespanImpl( stats_.named_.downstream_cx_length_ms_, time_source)), drain_close_(drain_close), user_agent_(http_context.userAgentContext()), random_generator_(random_generator), http_context_(http_context), runtime_(runtime), local_info_(local_info), cluster_manager_(cluster_manager), listener_stats_(config_.listenerStats()), overload_state_(overload_manager.getThreadLocalOverloadState()), overload_stop_accepting_requests_ref_( overload_state_.getState(Server::OverloadActionNames::get().StopAcceptingRequests)), overload_disable_keepalive_ref_( overload_state_.getState(Server::OverloadActionNames::get().DisableHttpKeepAlive)), time_source_(time_source), proxy_name_(StreamInfo::ProxyStatusUtils::makeProxyName( local_info_.node().id(), config_.serverName(), config_.proxyStatusConfig())) {}















const ResponseHeaderMap& ConnectionManagerImpl::continueHeader() {
  static const auto headers = createHeaderMap<ResponseHeaderMapImpl>( {{Http::Headers::get().Status, std::to_string(enumToInt(Code::Continue))}});
  return *headers;
}

void ConnectionManagerImpl::initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) {
  read_callbacks_ = &callbacks;
  stats_.named_.downstream_cx_total_.inc();
  stats_.named_.downstream_cx_active_.inc();
  if (read_callbacks_->connection().ssl()) {
    stats_.named_.downstream_cx_ssl_total_.inc();
    stats_.named_.downstream_cx_ssl_active_.inc();
  }

  read_callbacks_->connection().addConnectionCallbacks(*this);

  if (!read_callbacks_->connection()
           .streamInfo()
           .filterState()
           ->hasData<Network::ProxyProtocolFilterState>(Network::ProxyProtocolFilterState::key())) {
    read_callbacks_->connection().streamInfo().filterState()->setData( Network::ProxyProtocolFilterState::key(), std::make_unique<Network::ProxyProtocolFilterState>(Network::ProxyProtocolData{

            read_callbacks_->connection().connectionInfoProvider().remoteAddress(), read_callbacks_->connection().connectionInfoProvider().localAddress()}), StreamInfo::FilterState::StateType::ReadOnly, StreamInfo::FilterState::LifeSpan::Connection);


  }

  if (config_.idleTimeout()) {
    connection_idle_timer_ = read_callbacks_->connection().dispatcher().createScaledTimer( Event::ScaledTimerType::HttpDownstreamIdleConnectionTimeout, [this]() -> void { onIdleTimeout(); });

    connection_idle_timer_->enableTimer(config_.idleTimeout().value());
  }

  if (config_.maxConnectionDuration()) {
    connection_duration_timer_ = read_callbacks_->connection().dispatcher().createTimer( [this]() -> void { onConnectionDurationTimeout(); });
    connection_duration_timer_->enableTimer(config_.maxConnectionDuration().value());
  }

  read_callbacks_->connection().setDelayedCloseTimeout(config_.delayedCloseTimeout());

  read_callbacks_->connection().setConnectionStats( {stats_.named_.downstream_cx_rx_bytes_total_, stats_.named_.downstream_cx_rx_bytes_buffered_, stats_.named_.downstream_cx_tx_bytes_total_, stats_.named_.downstream_cx_tx_bytes_buffered_, nullptr, &stats_.named_.downstream_cx_delayed_close_timeout_});


}

ConnectionManagerImpl::~ConnectionManagerImpl() {
  stats_.named_.downstream_cx_destroy_.inc();

  stats_.named_.downstream_cx_active_.dec();
  if (read_callbacks_->connection().ssl()) {
    stats_.named_.downstream_cx_ssl_active_.dec();
  }

  if (codec_) {
    if (codec_->protocol() == Protocol::Http2) {
      stats_.named_.downstream_cx_http2_active_.dec();
    } else if (codec_->protocol() == Protocol::Http3) {
      stats_.named_.downstream_cx_http3_active_.dec();
    } else {
      stats_.named_.downstream_cx_http1_active_.dec();
    }
  }

  conn_length_->complete();
  user_agent_.completeConnectionLength(*conn_length_);
}

void ConnectionManagerImpl::checkForDeferredClose(bool skip_delay_close) {
  Network::ConnectionCloseType close = Network::ConnectionCloseType::FlushWriteAndDelay;
  if (Runtime::runtimeFeatureEnabled("envoy.reloadable_features.skip_delay_close") && skip_delay_close) {
    close = Network::ConnectionCloseType::FlushWrite;
  }
  if (drain_state_ == DrainState::Closing && streams_.empty() && !codec_->wantsToWrite()) {
    doConnectionClose(close, absl::nullopt, StreamInfo::ResponseCodeDetails::get().DownstreamLocalDisconnect);
  }
}

void ConnectionManagerImpl::doEndStream(ActiveStream& stream) {
  
  
  
  
  
  
  bool reset_stream = false;
  
  
  
  
  if (stream.response_encoder_ != nullptr && (!stream.filter_manager_.remoteComplete() || !stream.state_.codec_saw_local_complete_)) {
    
    
    ENVOY_STREAM_LOG(debug, "doEndStream() resetting stream", stream);
    
    stream.filter_manager_.setLocalComplete();
    stream.state_.codec_saw_local_complete_ = true;

    
    
    
    if (requestWasConnect(stream.request_headers_, codec_->protocol()) && (stream.filter_manager_.streamInfo().hasResponseFlag( StreamInfo::ResponseFlag::UpstreamConnectionFailure) || stream.filter_manager_.streamInfo().hasResponseFlag( StreamInfo::ResponseFlag::UpstreamConnectionTermination))) {



      stream.response_encoder_->getStream().resetStream(StreamResetReason::ConnectError);
    } else {
      if (stream.filter_manager_.streamInfo().hasResponseFlag( StreamInfo::ResponseFlag::UpstreamProtocolError)) {
        stream.response_encoder_->getStream().resetStream(StreamResetReason::ProtocolError);
      } else {
        stream.response_encoder_->getStream().resetStream(StreamResetReason::LocalReset);
      }
    }
    reset_stream = true;
  }

  if (!reset_stream) {
    doDeferredStreamDestroy(stream);
  }

  if (reset_stream && codec_->protocol() < Protocol::Http2) {
    drain_state_ = DrainState::Closing;
  }

  
  
  bool http_10_sans_cl = (codec_->protocol() == Protocol::Http10) && (!stream.response_headers_ || !stream.response_headers_->ContentLength());
  
  
  bool connection_close = stream.state_.saw_connection_close_;
  bool request_complete = stream.filter_manager_.remoteComplete();

  checkForDeferredClose(connection_close && (request_complete || http_10_sans_cl));
}

void ConnectionManagerImpl::doDeferredStreamDestroy(ActiveStream& stream) {
  if (stream.max_stream_duration_timer_) {
    stream.max_stream_duration_timer_->disableTimer();
    stream.max_stream_duration_timer_ = nullptr;
  }
  if (stream.stream_idle_timer_ != nullptr) {
    stream.stream_idle_timer_->disableTimer();
    stream.stream_idle_timer_ = nullptr;
  }
  stream.filter_manager_.disarmRequestTimeout();
  if (stream.request_header_timer_ != nullptr) {
    stream.request_header_timer_->disableTimer();
    stream.request_header_timer_ = nullptr;
  }

  stream.completeRequest();
  stream.filter_manager_.onStreamComplete();
  stream.filter_manager_.log();

  stream.filter_manager_.destroyFilters();

  read_callbacks_->connection().dispatcher().deferredDelete(stream.removeFromList(streams_));

  
  
  
  if (stream.response_encoder_) {
    stream.response_encoder_->getStream().removeCallbacks(stream);
  }

  if (connection_idle_timer_ && streams_.empty()) {
    connection_idle_timer_->enableTimer(config_.idleTimeout().value());
  }
}

RequestDecoder& ConnectionManagerImpl::newStream(ResponseEncoder& response_encoder, bool is_internally_created) {
  TRACE_EVENT("core", "ConnectionManagerImpl::newStream");
  if (connection_idle_timer_) {
    connection_idle_timer_->disableTimer();
  }

  ENVOY_CONN_LOG(debug, "new stream", read_callbacks_->connection());

  
  
  auto& buffer_factory = read_callbacks_->connection().dispatcher().getWatermarkFactory();
  Buffer::BufferMemoryAccountSharedPtr downstream_stream_account = buffer_factory.createAccount(response_encoder.getStream());
  response_encoder.getStream().setAccount(downstream_stream_account);
  ActiveStreamPtr new_stream(new ActiveStream(*this, response_encoder.getStream().bufferLimit(), std::move(downstream_stream_account)));

  accumulated_requests_++;
  if (config_.maxRequestsPerConnection() > 0 && accumulated_requests_ >= config_.maxRequestsPerConnection()) {
    if (codec_->protocol() < Protocol::Http2) {
      new_stream->state_.saw_connection_close_ = true;
      
      drain_state_ = DrainState::Closing;
    } else if (drain_state_ == DrainState::NotDraining) {
      startDrainSequence();
    }
    ENVOY_CONN_LOG(debug, "max requests per connection reached", read_callbacks_->connection());
    stats_.named_.downstream_cx_max_requests_reached_.inc();
  }

  new_stream->state_.is_internally_created_ = is_internally_created;
  new_stream->response_encoder_ = &response_encoder;
  new_stream->response_encoder_->getStream().addCallbacks(*new_stream);
  new_stream->response_encoder_->getStream().setFlushTimeout(new_stream->idle_timeout_ms_);
  new_stream->streamInfo().setDownstreamBytesMeter(response_encoder.getStream().bytesMeter());
  
  
  ASSERT(read_callbacks_->connection().aboveHighWatermark() == false || new_stream->filter_manager_.aboveHighWatermark());
  LinkedList::moveIntoList(std::move(new_stream), streams_);
  return **streams_.begin();
}

void ConnectionManagerImpl::handleCodecError(absl::string_view error) {
  ENVOY_CONN_LOG(debug, "dispatch error: {}", read_callbacks_->connection(), error);
  read_callbacks_->connection().streamInfo().setResponseFlag( StreamInfo::ResponseFlag::DownstreamProtocolError);

  
  
  doConnectionClose(Network::ConnectionCloseType::FlushWriteAndDelay, StreamInfo::ResponseFlag::DownstreamProtocolError, absl::StrCat("codec_error:", StringUtil::replaceAllEmptySpace(error)));

}

void ConnectionManagerImpl::createCodec(Buffer::Instance& data) {
  ASSERT(!codec_);
  codec_ = config_.createCodec(read_callbacks_->connection(), data, *this);

  switch (codec_->protocol()) {
  case Protocol::Http3:
    stats_.named_.downstream_cx_http3_total_.inc();
    stats_.named_.downstream_cx_http3_active_.inc();
    break;
  case Protocol::Http2:
    stats_.named_.downstream_cx_http2_total_.inc();
    stats_.named_.downstream_cx_http2_active_.inc();
    break;
  case Protocol::Http11:
  case Protocol::Http10:
    stats_.named_.downstream_cx_http1_total_.inc();
    stats_.named_.downstream_cx_http1_active_.inc();
    break;
  }
}

Network::FilterStatus ConnectionManagerImpl::onData(Buffer::Instance& data, bool) {
  if (!codec_) {
    
    createCodec(data);
  }

  bool redispatch;
  do {
    redispatch = false;

    const Status status = codec_->dispatch(data);

    if (isBufferFloodError(status) || isInboundFramesWithEmptyPayloadError(status)) {
      handleCodecError(status.message());
      return Network::FilterStatus::StopIteration;
    } else if (isCodecProtocolError(status)) {
      stats_.named_.downstream_cx_protocol_error_.inc();
      handleCodecError(status.message());
      return Network::FilterStatus::StopIteration;
    }
    ASSERT(status.ok());

    
    checkForDeferredClose(false);

    
    
    
    
    if (codec_->protocol() < Protocol::Http2) {
      if (read_callbacks_->connection().state() == Network::Connection::State::Open && data.length() > 0 && streams_.empty()) {
        redispatch = true;
      }
    }
  } while (redispatch);

  if (!read_callbacks_->connection().streamInfo().protocol()) {
    read_callbacks_->connection().streamInfo().protocol(codec_->protocol());
  }

  return Network::FilterStatus::StopIteration;
}

Network::FilterStatus ConnectionManagerImpl::onNewConnection() {
  if (!read_callbacks_->connection().streamInfo().protocol()) {
    
    return Network::FilterStatus::Continue;
  }
  
  Buffer::OwnedImpl dummy;
  createCodec(dummy);
  ASSERT(codec_->protocol() == Protocol::Http3);
  
  
  
  return Network::FilterStatus::StopIteration;
}

void ConnectionManagerImpl::resetAllStreams(absl::optional<StreamInfo::ResponseFlag> response_flag, absl::string_view details) {
  while (!streams_.empty()) {
    
    
    
    
    
    
    
    
    auto& stream = *streams_.front();
    stream.response_encoder_->getStream().removeCallbacks(stream);
    if (!stream.response_encoder_->getStream().responseDetails().empty()) {
      stream.filter_manager_.streamInfo().setResponseCodeDetails( stream.response_encoder_->getStream().responseDetails());
    } else if (!details.empty()) {
      stream.filter_manager_.streamInfo().setResponseCodeDetails(details);
    }
    if (response_flag.has_value()) {
      stream.filter_manager_.streamInfo().setResponseFlag(response_flag.value());
    }
    stream.onResetStream(StreamResetReason::ConnectionTermination, absl::string_view());
  }
}

void ConnectionManagerImpl::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::LocalClose) {
    stats_.named_.downstream_cx_destroy_local_.inc();
  }

  if (event == Network::ConnectionEvent::RemoteClose || event == Network::ConnectionEvent::LocalClose) {
    if (event == Network::ConnectionEvent::RemoteClose) {
      remote_close_ = true;
      stats_.named_.downstream_cx_destroy_remote_.inc();
    }
    absl::string_view details = event == Network::ConnectionEvent::RemoteClose ? StreamInfo::ResponseCodeDetails::get().DownstreamRemoteDisconnect : StreamInfo::ResponseCodeDetails::get().DownstreamLocalDisconnect;


    
    
    
    
    
    
    
    
    
    doConnectionClose(absl::nullopt, absl::nullopt, details);
  }
}

void ConnectionManagerImpl::doConnectionClose( absl::optional<Network::ConnectionCloseType> close_type, absl::optional<StreamInfo::ResponseFlag> response_flag, absl::string_view details) {

  if (connection_idle_timer_) {
    connection_idle_timer_->disableTimer();
    connection_idle_timer_.reset();
  }

  if (connection_duration_timer_) {
    connection_duration_timer_->disableTimer();
    connection_duration_timer_.reset();
  }

  if (drain_timer_) {
    drain_timer_->disableTimer();
    drain_timer_.reset();
  }

  if (!streams_.empty()) {
    const Network::ConnectionEvent event = close_type.has_value()
                                               ? Network::ConnectionEvent::LocalClose : Network::ConnectionEvent::RemoteClose;
    if (event == Network::ConnectionEvent::LocalClose) {
      stats_.named_.downstream_cx_destroy_local_active_rq_.inc();
    }
    if (event == Network::ConnectionEvent::RemoteClose) {
      stats_.named_.downstream_cx_destroy_remote_active_rq_.inc();
    }

    stats_.named_.downstream_cx_destroy_active_rq_.inc();
    user_agent_.onConnectionDestroy(event, true);
    
    
    
    resetAllStreams(response_flag, details);
  }

  if (close_type.has_value()) {
    read_callbacks_->connection().close(close_type.value());
  }
}

void ConnectionManagerImpl::onGoAway(GoAwayErrorCode) {
  
  
}

void ConnectionManagerImpl::onIdleTimeout() {
  ENVOY_CONN_LOG(debug, "idle timeout", read_callbacks_->connection());
  stats_.named_.downstream_cx_idle_timeout_.inc();
  if (!codec_) {
    
    
    doConnectionClose(Network::ConnectionCloseType::FlushWrite, absl::nullopt, "");
  } else if (drain_state_ == DrainState::NotDraining) {
    startDrainSequence();
  }
}

void ConnectionManagerImpl::onConnectionDurationTimeout() {
  ENVOY_CONN_LOG(debug, "max connection duration reached", read_callbacks_->connection());
  stats_.named_.downstream_cx_max_duration_reached_.inc();
  if (!codec_) {
    
    doConnectionClose(Network::ConnectionCloseType::FlushWrite, StreamInfo::ResponseFlag::DurationTimeout, StreamInfo::ResponseCodeDetails::get().DurationTimeout);

  } else if (drain_state_ == DrainState::NotDraining) {
    startDrainSequence();
  }
}

void ConnectionManagerImpl::onDrainTimeout() {
  ASSERT(drain_state_ != DrainState::NotDraining);
  codec_->goAway();
  drain_state_ = DrainState::Closing;
  checkForDeferredClose(false);
}

void ConnectionManagerImpl::chargeTracingStats(const Tracing::Reason& tracing_reason, ConnectionManagerTracingStats& tracing_stats) {
  switch (tracing_reason) {
  case Tracing::Reason::ClientForced:
    tracing_stats.client_enabled_.inc();
    break;
  case Tracing::Reason::Sampling:
    tracing_stats.random_sampling_.inc();
    break;
  case Tracing::Reason::ServiceForced:
    tracing_stats.service_forced_.inc();
    break;
  default:
    tracing_stats.not_traceable_.inc();
    break;
  }
}


void ConnectionManagerImpl::RdsRouteConfigUpdateRequester::requestRouteConfigUpdate( Http::RouteConfigUpdatedCallbackSharedPtr route_config_updated_cb) {
  absl::optional<Router::ConfigConstSharedPtr> route_config = parent_.routeConfig();
  Event::Dispatcher& thread_local_dispatcher = parent_.connection_manager_.read_callbacks_->connection().dispatcher();
  if (route_config.has_value() && route_config.value()->usesVhds()) {
    ASSERT(!parent_.request_headers_->Host()->value().empty());
    const auto& host_header = absl::AsciiStrToLower(parent_.request_headers_->getHostValue());
    requestVhdsUpdate(host_header, thread_local_dispatcher, std::move(route_config_updated_cb));
    return;
  } else if (parent_.snapped_scoped_routes_config_ != nullptr) {
    Router::ScopeKeyPtr scope_key = parent_.snapped_scoped_routes_config_->computeScopeKey(*parent_.request_headers_);
    
    if (scope_key != nullptr) {
      requestSrdsUpdate(std::move(scope_key), thread_local_dispatcher, std::move(route_config_updated_cb));
      return;
    }
  }
  
  (*route_config_updated_cb)(false);
}

void ConnectionManagerImpl::RdsRouteConfigUpdateRequester::requestVhdsUpdate( const std::string& host_header, Event::Dispatcher& thread_local_dispatcher, Http::RouteConfigUpdatedCallbackSharedPtr route_config_updated_cb) {

  route_config_provider_->requestVirtualHostsUpdate(host_header, thread_local_dispatcher, std::move(route_config_updated_cb));
}

void ConnectionManagerImpl::RdsRouteConfigUpdateRequester::requestSrdsUpdate( Router::ScopeKeyPtr scope_key, Event::Dispatcher& thread_local_dispatcher, Http::RouteConfigUpdatedCallbackSharedPtr route_config_updated_cb) {

  
  
  ASSERT(scoped_route_config_provider_ != nullptr);
  Http::RouteConfigUpdatedCallback scoped_route_config_updated_cb = Http::RouteConfigUpdatedCallback( [this, weak_route_config_updated_cb = std::weak_ptr<Http::RouteConfigUpdatedCallback>( route_config_updated_cb)](bool scope_exist) {


            
            if (auto cb = weak_route_config_updated_cb.lock()) {
              
              if (scope_exist) {
                parent_.refreshCachedRoute();
              }
              (*cb)(scope_exist && parent_.hasCachedRoute());
            }
          });
  scoped_route_config_provider_->onDemandRdsUpdate(std::move(scope_key), thread_local_dispatcher, std::move(scoped_route_config_updated_cb));
}

ConnectionManagerImpl::ActiveStream::ActiveStream(ConnectionManagerImpl& connection_manager, uint32_t buffer_limit, Buffer::BufferMemoryAccountSharedPtr account)

    : connection_manager_(connection_manager), stream_id_(connection_manager.random_generator_.random()), filter_manager_(*this, connection_manager_.read_callbacks_->connection().dispatcher(), connection_manager_.read_callbacks_->connection(), stream_id_, std::move(account), connection_manager_.config_.proxy100Continue(), buffer_limit, connection_manager_.config_.filterFactory(), connection_manager_.config_.localReply(), connection_manager_.codec_->protocol(), connection_manager_.timeSource(), connection_manager_.read_callbacks_->connection().streamInfo().filterState(), StreamInfo::FilterState::LifeSpan::Connection), request_response_timespan_(new Stats::HistogramCompletableTimespanImpl( connection_manager_.stats_.named_.downstream_rq_time_, connection_manager_.timeSource())) {











  ASSERT(!connection_manager.config_.isRoutable() || ((connection_manager.config_.routeConfigProvider() == nullptr && connection_manager.config_.scopedRouteConfigProvider() != nullptr) || (connection_manager.config_.routeConfigProvider() != nullptr && connection_manager.config_.scopedRouteConfigProvider() == nullptr)), "Either routeConfigProvider or scopedRouteConfigProvider should be set in " "ConnectionManagerImpl.");





  for (const AccessLog::InstanceSharedPtr& access_log : connection_manager_.config_.accessLogs()) {
    filter_manager_.addAccessLogHandler(access_log);
  }

  filter_manager_.streamInfo().setRequestIDProvider( connection_manager.config_.requestIDExtension());

  if (connection_manager_.config_.isRoutable() && connection_manager.config_.routeConfigProvider() != nullptr) {
    route_config_update_requester_ = std::make_unique<ConnectionManagerImpl::RdsRouteConfigUpdateRequester>( connection_manager.config_.routeConfigProvider(), *this);

  } else if (connection_manager_.config_.isRoutable() && connection_manager.config_.scopedRouteConfigProvider() != nullptr) {
    route_config_update_requester_ = std::make_unique<ConnectionManagerImpl::RdsRouteConfigUpdateRequester>( connection_manager.config_.scopedRouteConfigProvider(), *this);

  }
  ScopeTrackerScopeState scope(this, connection_manager_.read_callbacks_->connection().dispatcher());

  connection_manager_.stats_.named_.downstream_rq_total_.inc();
  connection_manager_.stats_.named_.downstream_rq_active_.inc();
  if (connection_manager_.codec_->protocol() == Protocol::Http2) {
    connection_manager_.stats_.named_.downstream_rq_http2_total_.inc();
  } else if (connection_manager_.codec_->protocol() == Protocol::Http3) {
    connection_manager_.stats_.named_.downstream_rq_http3_total_.inc();
  } else {
    connection_manager_.stats_.named_.downstream_rq_http1_total_.inc();
  }

  if (connection_manager_.config_.streamIdleTimeout().count()) {
    idle_timeout_ms_ = connection_manager_.config_.streamIdleTimeout();
    stream_idle_timer_ = connection_manager_.read_callbacks_->connection().dispatcher().createScaledTimer( Event::ScaledTimerType::HttpDownstreamIdleStreamTimeout, [this]() -> void { onIdleTimeout(); });


    resetIdleTimer();
  }

  if (connection_manager_.config_.requestTimeout().count()) {
    std::chrono::milliseconds request_timeout = connection_manager_.config_.requestTimeout();
    request_timer_ = connection_manager.read_callbacks_->connection().dispatcher().createTimer( [this]() -> void { onRequestTimeout(); });
    request_timer_->enableTimer(request_timeout, this);
  }

  if (connection_manager_.config_.requestHeadersTimeout().count()) {
    std::chrono::milliseconds request_headers_timeout = connection_manager_.config_.requestHeadersTimeout();
    request_header_timer_ = connection_manager.read_callbacks_->connection().dispatcher().createTimer( [this]() -> void { onRequestHeaderTimeout(); });

    request_header_timer_->enableTimer(request_headers_timeout, this);
  }

  const auto max_stream_duration = connection_manager_.config_.maxStreamDuration();
  if (max_stream_duration.has_value() && max_stream_duration.value().count()) {
    max_stream_duration_timer_ = connection_manager.read_callbacks_->connection().dispatcher().createTimer( [this]() -> void { onStreamMaxDurationReached(); });

    max_stream_duration_timer_->enableTimer(connection_manager_.config_.maxStreamDuration().value(), this);
  }
}

void ConnectionManagerImpl::ActiveStream::completeRequest() {
  filter_manager_.streamInfo().onRequestComplete();

  if (connection_manager_.remote_close_) {
    filter_manager_.streamInfo().setResponseCodeDetails( StreamInfo::ResponseCodeDetails::get().DownstreamRemoteDisconnect);
    filter_manager_.streamInfo().setResponseFlag( StreamInfo::ResponseFlag::DownstreamConnectionTermination);
  }
  connection_manager_.stats_.named_.downstream_rq_active_.dec();
  if (filter_manager_.streamInfo().healthCheck()) {
    connection_manager_.config_.tracingStats().health_check_.inc();
  }

  if (active_span_) {
    Tracing::HttpTracerUtility::finalizeDownstreamSpan( *active_span_, request_headers_.get(), response_headers_.get(), response_trailers_.get(), filter_manager_.streamInfo(), *this);

  }
  if (state_.successful_upgrade_) {
    connection_manager_.stats_.named_.downstream_cx_upgrades_active_.dec();
  }
}

void ConnectionManagerImpl::ActiveStream::resetIdleTimer() {
  if (stream_idle_timer_ != nullptr) {
    
    
    
    stream_idle_timer_->enableTimer(idle_timeout_ms_);
  }
}

void ConnectionManagerImpl::ActiveStream::onIdleTimeout() {
  connection_manager_.stats_.named_.downstream_rq_idle_timeout_.inc();
  
  if (responseHeaders().has_value()) {
    
    
    filter_manager_.streamInfo().setResponseCodeDetails( StreamInfo::ResponseCodeDetails::get().StreamIdleTimeout);
    connection_manager_.doEndStream(*this);
  } else {
    
    filter_manager_.streamInfo().setResponseFlag(StreamInfo::ResponseFlag::StreamIdleTimeout);
    sendLocalReply(Http::Code::RequestTimeout, "stream timeout", nullptr, absl::nullopt, StreamInfo::ResponseCodeDetails::get().StreamIdleTimeout);
  }
}

void ConnectionManagerImpl::ActiveStream::onRequestTimeout() {
  connection_manager_.stats_.named_.downstream_rq_timeout_.inc();
  sendLocalReply(Http::Code::RequestTimeout, "request timeout", nullptr, absl::nullopt, StreamInfo::ResponseCodeDetails::get().RequestOverallTimeout);
}

void ConnectionManagerImpl::ActiveStream::onRequestHeaderTimeout() {
  connection_manager_.stats_.named_.downstream_rq_header_timeout_.inc();
  sendLocalReply(Http::Code::RequestTimeout, "request header timeout", nullptr, absl::nullopt, StreamInfo::ResponseCodeDetails::get().RequestHeaderTimeout);
}

void ConnectionManagerImpl::ActiveStream::onStreamMaxDurationReached() {
  ENVOY_STREAM_LOG(debug, "Stream max duration time reached", *this);
  connection_manager_.stats_.named_.downstream_rq_max_duration_reached_.inc();
  sendLocalReply(Http::Code::RequestTimeout, "downstream duration timeout", nullptr, Grpc::Status::WellKnownGrpcStatus::DeadlineExceeded, StreamInfo::ResponseCodeDetails::get().MaxDurationTimeout);

}

void ConnectionManagerImpl::ActiveStream::chargeStats(const ResponseHeaderMap& headers) {
  uint64_t response_code = Utility::getResponseStatus(headers);
  filter_manager_.streamInfo().response_code_ = response_code;

  if (filter_manager_.streamInfo().health_check_request_) {
    return;
  }

  
  const absl::optional<std::string>& response_code_details = filter_manager_.streamInfo().responseCodeDetails();
  if (response_code_details.has_value() && response_code_details == Envoy::StreamInfo::ResponseCodeDetails::get().InternalRedirect) {
    return;
  }

  connection_manager_.stats_.named_.downstream_rq_completed_.inc();
  connection_manager_.listener_stats_.downstream_rq_completed_.inc();
  if (CodeUtility::is1xx(response_code)) {
    connection_manager_.stats_.named_.downstream_rq_1xx_.inc();
    connection_manager_.listener_stats_.downstream_rq_1xx_.inc();
  } else if (CodeUtility::is2xx(response_code)) {
    connection_manager_.stats_.named_.downstream_rq_2xx_.inc();
    connection_manager_.listener_stats_.downstream_rq_2xx_.inc();
  } else if (CodeUtility::is3xx(response_code)) {
    connection_manager_.stats_.named_.downstream_rq_3xx_.inc();
    connection_manager_.listener_stats_.downstream_rq_3xx_.inc();
  } else if (CodeUtility::is4xx(response_code)) {
    connection_manager_.stats_.named_.downstream_rq_4xx_.inc();
    connection_manager_.listener_stats_.downstream_rq_4xx_.inc();
  } else if (CodeUtility::is5xx(response_code)) {
    connection_manager_.stats_.named_.downstream_rq_5xx_.inc();
    connection_manager_.listener_stats_.downstream_rq_5xx_.inc();
  }
}

const Network::Connection* ConnectionManagerImpl::ActiveStream::connection() {
  return &connection_manager_.read_callbacks_->connection();
}

uint32_t ConnectionManagerImpl::ActiveStream::localPort() {
  auto ip = connection()->connectionInfoProvider().localAddress()->ip();
  if (ip == nullptr) {
    return 0;
  }
  return ip->port();
}











void ConnectionManagerImpl::ActiveStream::decodeHeaders(RequestHeaderMapPtr&& headers, bool end_stream) {
  ScopeTrackerScopeState scope(this, connection_manager_.read_callbacks_->connection().dispatcher());
  request_headers_ = std::move(headers);
  filter_manager_.requestHeadersInitialized();
  if (request_header_timer_ != nullptr) {
    request_header_timer_->disableTimer();
    request_header_timer_.reset();
  }

  
  
  const Protocol protocol = connection_manager_.codec_->protocol();
  state_.saw_connection_close_ = HeaderUtility::shouldCloseConnection(protocol, *request_headers_);

  
  if (connection_manager_.config_.isRoutable()) {
    if (connection_manager_.config_.routeConfigProvider() != nullptr) {
      snapped_route_config_ = connection_manager_.config_.routeConfigProvider()->configCast();
    } else if (connection_manager_.config_.scopedRouteConfigProvider() != nullptr) {
      snapped_scoped_routes_config_ = connection_manager_.config_.scopedRouteConfigProvider()->config<Router::ScopedConfig>();
      snapScopedRouteConfig();
    }
  } else {
    snapped_route_config_ = connection_manager_.config_.routeConfigProvider()->configCast();
  }

  ENVOY_STREAM_LOG(debug, "request headers complete (end_stream={}):\n{}", *this, end_stream, *request_headers_);

  
  
  
  filter_manager_.maybeEndDecode(end_stream);

  
  if (connection_manager_.random_generator_.bernoulli( connection_manager_.overload_stop_accepting_requests_ref_.value())) {
    
    
    filter_manager_.skipFilterChainCreation();
    connection_manager_.stats_.named_.downstream_rq_overload_close_.inc();
    sendLocalReply(Http::Code::ServiceUnavailable, "envoy overloaded", nullptr, absl::nullopt, StreamInfo::ResponseCodeDetails::get().Overload);
    return;
  }

  if (!connection_manager_.config_.proxy100Continue() && request_headers_->Expect() && request_headers_->Expect()->value() == Headers::get().ExpectValues._100Continue.c_str()) {
    
    
    chargeStats(continueHeader());
    response_encoder_->encode1xxHeaders(continueHeader());
    
    request_headers_->removeExpect();
  }

  connection_manager_.user_agent_.initializeFromHeaders(*request_headers_, connection_manager_.stats_.prefixStatName(), connection_manager_.stats_.scope_);


  
  if (protocol == Protocol::Http10) {
    
    
    
    
    
    filter_manager_.streamInfo().protocol(protocol);
    if (!connection_manager_.config_.http1Settings().accept_http_10_) {
      
      sendLocalReply(Code::UpgradeRequired, "", nullptr, absl::nullopt, StreamInfo::ResponseCodeDetails::get().LowVersion);
      return;
    }
    if (!request_headers_->Host() && !connection_manager_.config_.http1Settings().default_host_for_http_10_.empty()) {
      
      request_headers_->setHost( connection_manager_.config_.http1Settings().default_host_for_http_10_);
    }
  }

  if (!request_headers_->Host()) {
    
    sendLocalReply(Code::BadRequest, "", nullptr, absl::nullopt, StreamInfo::ResponseCodeDetails::get().MissingHost);
    return;
  }

  
  ASSERT(HeaderUtility::requestHeadersValid(*request_headers_).has_value() == false);

  
  
  
  
  if ((!HeaderUtility::isConnect(*request_headers_) || request_headers_->Path()) && request_headers_->getPathValue().empty()) {
    sendLocalReply(Code::NotFound, "", nullptr, absl::nullopt, StreamInfo::ResponseCodeDetails::get().MissingPath);
    return;
  }

  
  if (!request_headers_->getPathValue().empty() && request_headers_->getPathValue()[0] != '/') {
    connection_manager_.stats_.named_.downstream_rq_non_relative_path_.inc();
    sendLocalReply(Code::NotFound, "", nullptr, absl::nullopt, StreamInfo::ResponseCodeDetails::get().AbsolutePath);
    return;
  }

  
  const auto action = ConnectionManagerUtility::maybeNormalizePath(*request_headers_, connection_manager_.config_);
  
  
  if (action == ConnectionManagerUtility::NormalizePathAction::Reject || (action == ConnectionManagerUtility::NormalizePathAction::Redirect && Grpc::Common::hasGrpcContentType(*request_headers_))) {

    connection_manager_.stats_.named_.downstream_rq_failed_path_normalization_.inc();
    sendLocalReply(Code::BadRequest, "", nullptr, absl::nullopt, StreamInfo::ResponseCodeDetails::get().PathNormalizationFailed);
    return;
  } else if (action == ConnectionManagerUtility::NormalizePathAction::Redirect) {
    connection_manager_.stats_.named_.downstream_rq_redirected_with_normalized_path_.inc();
    sendLocalReply( Code::TemporaryRedirect, "", [new_path = request_headers_->Path()->value().getStringView()]( Http::ResponseHeaderMap& response_headers) -> void {


          response_headers.addReferenceKey(Http::Headers::get().Location, new_path);
        }, absl::nullopt, StreamInfo::ResponseCodeDetails::get().PathNormalizationFailed);
    return;
  }

  ASSERT(action == ConnectionManagerUtility::NormalizePathAction::Continue);
  auto optional_port = ConnectionManagerUtility::maybeNormalizeHost( *request_headers_, connection_manager_.config_, localPort());
  if (optional_port.has_value() && requestWasConnect(request_headers_, connection_manager_.codec_->protocol())) {
    filter_manager_.streamInfo().filterState()->setData( Router::OriginalConnectPort::key(), std::make_unique<Router::OriginalConnectPort>(optional_port.value()), StreamInfo::FilterState::StateType::ReadOnly, StreamInfo::FilterState::LifeSpan::Request);


  }

  if (!state_.is_internally_created_) { 
    
    const auto mutate_result = ConnectionManagerUtility::mutateRequestHeaders( *request_headers_, connection_manager_.read_callbacks_->connection(), connection_manager_.config_, *snapped_route_config_, connection_manager_.local_info_);


    
    if (mutate_result.reject_request.has_value()) {
      const auto& reject_request_params = mutate_result.reject_request.value();
      connection_manager_.stats_.named_.downstream_rq_rejected_via_ip_detection_.inc();
      sendLocalReply(reject_request_params.response_code, reject_request_params.body, nullptr, absl::nullopt, StreamInfo::ResponseCodeDetails::get().OriginalIPDetectionFailed);

      return;
    }

    filter_manager_.setDownstreamRemoteAddress(mutate_result.final_remote_address);
  }
  ASSERT(filter_manager_.streamInfo().downstreamAddressProvider().remoteAddress() != nullptr);

  ASSERT(!cached_route_);
  refreshCachedRoute();

  if (!state_.is_internally_created_) { 
    filter_manager_.streamInfo().setTraceReason( ConnectionManagerUtility::mutateTracingRequestHeader( *request_headers_, connection_manager_.runtime_, connection_manager_.config_, cached_route_.value().get()));


  }

  filter_manager_.streamInfo().setRequestHeaders(*request_headers_);

  const bool upgrade_rejected = filter_manager_.createFilterChain() == false;

  
  
  if (hasCachedRoute()) {
    
    if (upgrade_rejected) {
      
      
      
      
      state_.saw_connection_close_ = true;
      connection_manager_.stats_.named_.downstream_rq_ws_on_non_ws_route_.inc();
      sendLocalReply(Code::Forbidden, "", nullptr, absl::nullopt, StreamInfo::ResponseCodeDetails::get().UpgradeFailed);
      return;
    }
    
  }

  if (hasCachedRoute()) {
    const Router::RouteEntry* route_entry = cached_route_.value()->routeEntry();
    if (route_entry != nullptr && route_entry->idleTimeout()) {
      
      
      idle_timeout_ms_ = route_entry->idleTimeout().value();
      response_encoder_->getStream().setFlushTimeout(idle_timeout_ms_);
      if (idle_timeout_ms_.count()) {
        
        if (stream_idle_timer_ == nullptr) {
          stream_idle_timer_ = connection_manager_.read_callbacks_->connection().dispatcher().createScaledTimer( Event::ScaledTimerType::HttpDownstreamIdleStreamTimeout, [this]() -> void { onIdleTimeout(); });


        }
      } else if (stream_idle_timer_ != nullptr) {
        
        
        stream_idle_timer_->disableTimer();
        stream_idle_timer_ = nullptr;
      }
    }
  }

  
  if (connection_manager_.config_.tracingConfig()) {
    traceRequest();
  }

  filter_manager_.decodeHeaders(*request_headers_, end_stream);

  
  resetIdleTimer();
}

void ConnectionManagerImpl::ActiveStream::traceRequest() {
  const Tracing::Decision tracing_decision = Tracing::HttpTracerUtility::shouldTraceRequest(filter_manager_.streamInfo());
  ConnectionManagerImpl::chargeTracingStats(tracing_decision.reason, connection_manager_.config_.tracingStats());

  active_span_ = connection_manager_.tracer().startSpan( *this, *request_headers_, filter_manager_.streamInfo(), tracing_decision);

  if (!active_span_) {
    return;
  }

  
  

  
  if (hasCachedRoute() && cached_route_.value()->decorator()) {
    const Router::Decorator* decorator = cached_route_.value()->decorator();

    decorator->apply(*active_span_);

    state_.decorated_propagate_ = decorator->propagate();

    
    if (!decorator->getOperation().empty()) {
      decorated_operation_ = &decorator->getOperation();
    }
  }

  if (connection_manager_.config_.tracingConfig()->operation_name_ == Tracing::OperationName::Egress) {
    
    
    
    if (decorated_operation_ && state_.decorated_propagate_) {
      request_headers_->setEnvoyDecoratorOperation(*decorated_operation_);
    }
  } else {
    const HeaderEntry* req_operation_override = request_headers_->EnvoyDecoratorOperation();

    
    
    if (req_operation_override) {
      if (!req_operation_override->value().empty()) {
        active_span_->setOperation(req_operation_override->value().getStringView());

        
        
        decorated_operation_ = nullptr;
      }
      
      request_headers_->removeEnvoyDecoratorOperation();
    }
  }
}

void ConnectionManagerImpl::ActiveStream::decodeData(Buffer::Instance& data, bool end_stream) {
  ScopeTrackerScopeState scope(this, connection_manager_.read_callbacks_->connection().dispatcher());
  filter_manager_.maybeEndDecode(end_stream);
  filter_manager_.streamInfo().addBytesReceived(data.length());

  filter_manager_.decodeData(data, end_stream);
}

void ConnectionManagerImpl::ActiveStream::decodeTrailers(RequestTrailerMapPtr&& trailers) {
  ScopeTrackerScopeState scope(this, connection_manager_.read_callbacks_->connection().dispatcher());
  resetIdleTimer();

  ASSERT(!request_trailers_);
  request_trailers_ = std::move(trailers);
  filter_manager_.maybeEndDecode(true);
  filter_manager_.decodeTrailers(*request_trailers_);
}

void ConnectionManagerImpl::ActiveStream::decodeMetadata(MetadataMapPtr&& metadata_map) {
  resetIdleTimer();
  
  
  
  filter_manager_.decodeMetadata(*metadata_map);
}

void ConnectionManagerImpl::ActiveStream::disarmRequestTimeout() {
  if (request_timer_) {
    request_timer_->disableTimer();
  }
}

void ConnectionManagerImpl::startDrainSequence() {
  ASSERT(drain_state_ == DrainState::NotDraining);
  drain_state_ = DrainState::Draining;
  codec_->shutdownNotice();
  drain_timer_ = read_callbacks_->connection().dispatcher().createTimer( [this]() -> void { onDrainTimeout(); });
  drain_timer_->enableTimer(config_.drainTimeout());
}

void ConnectionManagerImpl::ActiveStream::snapScopedRouteConfig() {
  
  
  snapped_route_config_ = snapped_scoped_routes_config_->getRouteConfig(*request_headers_);
  if (snapped_route_config_ == nullptr) {
    ENVOY_STREAM_LOG(trace, "can't find SRDS scope.", *this);
    
    
    snapped_route_config_ = std::make_shared<Router::NullConfigImpl>();
  }
}

void ConnectionManagerImpl::ActiveStream::refreshCachedRoute() { refreshCachedRoute(nullptr); }

void ConnectionManagerImpl::ActiveStream::refreshDurationTimeout() {
  if (!filter_manager_.streamInfo().route() || !filter_manager_.streamInfo().route()->routeEntry() || !request_headers_) {
    return;
  }
  const auto& route = filter_manager_.streamInfo().route()->routeEntry();

  auto grpc_timeout = Grpc::Common::getGrpcTimeout(*request_headers_);
  std::chrono::milliseconds timeout;
  bool disable_timer = false;

  if (!grpc_timeout || !route->grpcTimeoutHeaderMax()) {
    
    
    if (route->maxStreamDuration()) {
      timeout = route->maxStreamDuration().value();
      if (timeout == std::chrono::milliseconds(0)) {
        
        disable_timer = true;
      }
    } else {
      
      
      const auto max_stream_duration = connection_manager_.config_.maxStreamDuration();
      if (max_stream_duration.has_value() && max_stream_duration.value().count()) {
        timeout = max_stream_duration.value();
      } else {
        disable_timer = true;
      }
    }
  } else {
    
    timeout = grpc_timeout.value();
    
    if (timeout > route->grpcTimeoutHeaderMax().value() && route->grpcTimeoutHeaderMax().value() != std::chrono::milliseconds(0)) {
      timeout = route->grpcTimeoutHeaderMax().value();
    }

    
    if (timeout != std::chrono::milliseconds(0) && route->grpcTimeoutHeaderOffset()) {
      const auto offset = route->grpcTimeoutHeaderOffset().value();
      if (offset < timeout) {
        timeout -= offset;
      } else {
        timeout = std::chrono::milliseconds(0);
      }
    }
  }

  
  if (disable_timer) {
    if (max_stream_duration_timer_) {
      max_stream_duration_timer_->disableTimer();
      if (route->usingNewTimeouts() && Grpc::Common::isGrpcRequestHeaders(*request_headers_)) {
        request_headers_->removeGrpcTimeout();
      }
    }
    return;
  }

  
  
  
  if (route->usingNewTimeouts() && Grpc::Common::isGrpcRequestHeaders(*request_headers_)) {
    Grpc::Common::toGrpcTimeout(std::chrono::milliseconds(timeout), *request_headers_);
  }

  
  
  std::chrono::duration time_used = std::chrono::duration_cast<std::chrono::milliseconds>( connection_manager_.timeSource().monotonicTime() - filter_manager_.streamInfo().startTimeMonotonic());

  if (timeout > time_used) {
    timeout -= time_used;
  } else {
    timeout = std::chrono::milliseconds(0);
  }

  
  if (!max_stream_duration_timer_) {
    max_stream_duration_timer_ = connection_manager_.read_callbacks_->connection().dispatcher().createTimer( [this]() -> void { onStreamMaxDurationReached(); });

  }
  max_stream_duration_timer_->enableTimer(timeout);
}

void ConnectionManagerImpl::ActiveStream::refreshCachedRoute(const Router::RouteCallback& cb) {
  Router::RouteConstSharedPtr route;
  if (request_headers_ != nullptr) {
    if (connection_manager_.config_.isRoutable() && connection_manager_.config_.scopedRouteConfigProvider() != nullptr) {
      
      snapScopedRouteConfig();
    }
    if (snapped_route_config_ != nullptr) {
      route = snapped_route_config_->route(cb, *request_headers_, filter_manager_.streamInfo(), stream_id_);
    }
  }

  setRoute(route);
}

void ConnectionManagerImpl::ActiveStream::refreshCachedTracingCustomTags() {
  if (!connection_manager_.config_.tracingConfig()) {
    return;
  }
  const Tracing::CustomTagMap& conn_manager_tags = connection_manager_.config_.tracingConfig()->custom_tags_;
  const Tracing::CustomTagMap* route_tags = nullptr;
  if (hasCachedRoute() && cached_route_.value()->tracingConfig()) {
    route_tags = &cached_route_.value()->tracingConfig()->getCustomTags();
  }
  const bool configured_in_conn = !conn_manager_tags.empty();
  const bool configured_in_route = route_tags && !route_tags->empty();
  if (!configured_in_conn && !configured_in_route) {
    return;
  }
  Tracing::CustomTagMap& custom_tag_map = getOrMakeTracingCustomTagMap();
  if (configured_in_route) {
    custom_tag_map.insert(route_tags->begin(), route_tags->end());
  }
  if (configured_in_conn) {
    custom_tag_map.insert(conn_manager_tags.begin(), conn_manager_tags.end());
  }
}


void ConnectionManagerImpl::ActiveStream::requestRouteConfigUpdate( Http::RouteConfigUpdatedCallbackSharedPtr route_config_updated_cb) {
  route_config_update_requester_->requestRouteConfigUpdate(route_config_updated_cb);
}

absl::optional<Router::ConfigConstSharedPtr> ConnectionManagerImpl::ActiveStream::routeConfig() {
  if (connection_manager_.config_.routeConfigProvider() != nullptr) {
    return absl::optional<Router::ConfigConstSharedPtr>( connection_manager_.config_.routeConfigProvider()->configCast());
  }
  return {};
}

void ConnectionManagerImpl::ActiveStream::onLocalReply(Code code) {
  
  if (code == Http::Code::BadRequest && connection_manager_.codec_->protocol() < Protocol::Http2 && !response_encoder_->streamErrorOnInvalidHttpMessage()) {
    state_.saw_connection_close_ = true;
  }
}

void ConnectionManagerImpl::ActiveStream::encode1xxHeaders(ResponseHeaderMap& response_headers) {
  
  
  ConnectionManagerUtility::mutateResponseHeaders( response_headers, request_headers_.get(), connection_manager_.config_, EMPTY_STRING, filter_manager_.streamInfo(), connection_manager_.proxy_name_, connection_manager_.clear_hop_by_hop_response_headers_);



  
  chargeStats(response_headers);

  ENVOY_STREAM_LOG(debug, "encoding 100 continue headers via codec:\n{}", *this, response_headers);

  
  response_encoder_->encode1xxHeaders(response_headers);
}

void ConnectionManagerImpl::ActiveStream::encodeHeaders(ResponseHeaderMap& headers, bool end_stream) {
  

  
  if (!headers.Date()) {
    connection_manager_.config_.dateProvider().setDateHeader(headers);
  }

  
  
  const auto transformation = connection_manager_.config_.serverHeaderTransformation();
  if (transformation == ConnectionManagerConfig::HttpConnectionManagerProto::OVERWRITE || (transformation == ConnectionManagerConfig::HttpConnectionManagerProto::APPEND_IF_ABSENT && headers.Server() == nullptr)) {

    headers.setReferenceServer(connection_manager_.config_.serverName());
  }
  ConnectionManagerUtility::mutateResponseHeaders( headers, request_headers_.get(), connection_manager_.config_, connection_manager_.config_.via(), filter_manager_.streamInfo(), connection_manager_.proxy_name_, connection_manager_.clear_hop_by_hop_response_headers_);



  bool drain_connection_due_to_overload = false;
  if (connection_manager_.drain_state_ == DrainState::NotDraining && connection_manager_.random_generator_.bernoulli( connection_manager_.overload_disable_keepalive_ref_.value())) {

    ENVOY_STREAM_LOG(debug, "disabling keepalive due to envoy overload", *this);
    drain_connection_due_to_overload = true;
    connection_manager_.stats_.named_.downstream_cx_overload_disable_keepalive_.inc();
  }

  
  
  if (connection_manager_.drain_state_ == DrainState::NotDraining && (connection_manager_.drain_close_.drainClose() || drain_connection_due_to_overload)) {

    
    
    
    connection_manager_.startDrainSequence();
    connection_manager_.stats_.named_.downstream_cx_drain_close_.inc();
    ENVOY_STREAM_LOG(debug, "drain closing connection", *this);
  }

  if (connection_manager_.codec_->protocol() == Protocol::Http10) {
    
    
    if (!headers.ContentLength()) {
      state_.saw_connection_close_ = true;
    }
    
    
    if (!state_.saw_connection_close_) {
      headers.setConnection(Headers::get().ConnectionValues.KeepAlive);
    }
  }

  if (connection_manager_.drain_state_ == DrainState::NotDraining && state_.saw_connection_close_) {
    ENVOY_STREAM_LOG(debug, "closing connection due to connection close header", *this);
    connection_manager_.drain_state_ = DrainState::Closing;
  }

  
  
  
  if (!filter_manager_.remoteComplete()) {
    if (connection_manager_.codec_->protocol() < Protocol::Http2) {
      connection_manager_.drain_state_ = DrainState::Closing;
    }

    connection_manager_.stats_.named_.downstream_rq_response_before_rq_complete_.inc();
  }

  if (connection_manager_.drain_state_ != DrainState::NotDraining && connection_manager_.codec_->protocol() < Protocol::Http2) {
    
    
    
    if (!Utility::isUpgrade(headers) && !HeaderUtility::isConnectResponse(request_headers_.get(), *responseHeaders())) {
      headers.setReferenceConnection(Headers::get().ConnectionValues.Close);
    }
  }

  if (connection_manager_.config_.tracingConfig()) {
    if (connection_manager_.config_.tracingConfig()->operation_name_ == Tracing::OperationName::Ingress) {
      
      
      
      
      if (decorated_operation_ && state_.decorated_propagate_) {
        headers.setEnvoyDecoratorOperation(*decorated_operation_);
      }
    } else if (connection_manager_.config_.tracingConfig()->operation_name_ == Tracing::OperationName::Egress) {
      const HeaderEntry* resp_operation_override = headers.EnvoyDecoratorOperation();

      
      
      if (resp_operation_override) {
        if (!resp_operation_override->value().empty() && active_span_) {
          active_span_->setOperation(resp_operation_override->value().getStringView());
        }
        
        headers.removeEnvoyDecoratorOperation();
      }
    }
  }

  chargeStats(headers);

  ENVOY_STREAM_LOG(debug, "encoding headers via codec (end_stream={}):\n{}", *this, end_stream, headers);

  
  filter_manager_.streamInfo().downstreamTiming().onFirstDownstreamTxByteSent( connection_manager_.time_source_);
  response_encoder_->encodeHeaders(headers, end_stream);
}

void ConnectionManagerImpl::ActiveStream::encodeData(Buffer::Instance& data, bool end_stream) {
  ENVOY_STREAM_LOG(trace, "encoding data via codec (size={} end_stream={})", *this, data.length(), end_stream);

  filter_manager_.streamInfo().addBytesSent(data.length());
  response_encoder_->encodeData(data, end_stream);
}

void ConnectionManagerImpl::ActiveStream::encodeTrailers(ResponseTrailerMap& trailers) {
  ENVOY_STREAM_LOG(debug, "encoding trailers via codec:\n{}", *this, trailers);

  response_encoder_->encodeTrailers(trailers);
}

void ConnectionManagerImpl::ActiveStream::encodeMetadata(MetadataMapVector& metadata) {
  ENVOY_STREAM_LOG(debug, "encoding metadata via codec:\n{}", *this, metadata);
  response_encoder_->encodeMetadata(metadata);
}

void ConnectionManagerImpl::ActiveStream::onDecoderFilterBelowWriteBufferLowWatermark() {
  ENVOY_STREAM_LOG(debug, "Read-enabling downstream stream due to filter callbacks.", *this);
  
  
  if (!filter_manager_.destroyed()) {
    response_encoder_->getStream().readDisable(false);
  }
  connection_manager_.stats_.named_.downstream_flow_control_resumed_reading_total_.inc();
}

void ConnectionManagerImpl::ActiveStream::onDecoderFilterAboveWriteBufferHighWatermark() {
  ENVOY_STREAM_LOG(debug, "Read-disabling downstream stream due to filter callbacks.", *this);
  response_encoder_->getStream().readDisable(true);
  connection_manager_.stats_.named_.downstream_flow_control_paused_reading_total_.inc();
}

void ConnectionManagerImpl::ActiveStream::onResetStream(StreamResetReason reset_reason, absl::string_view) {
  
  
  
  
  
  
  ENVOY_STREAM_LOG(debug, "stream reset", *this);
  connection_manager_.stats_.named_.downstream_rq_rx_reset_.inc();

  
  
  const absl::string_view encoder_details = response_encoder_->getStream().responseDetails();
  if (!encoder_details.empty() && reset_reason == StreamResetReason::LocalReset) {
    filter_manager_.streamInfo().setResponseFlag(StreamInfo::ResponseFlag::DownstreamProtocolError);
  }
  if (!encoder_details.empty()) {
    filter_manager_.streamInfo().setResponseCodeDetails(encoder_details);
  }

  
  
  if (encoder_details.empty() && reset_reason == StreamResetReason::OverloadManager) {
    filter_manager_.streamInfo().setResponseFlag(StreamInfo::ResponseFlag::OverloadManager);
    filter_manager_.streamInfo().setResponseCodeDetails( StreamInfo::ResponseCodeDetails::get().Overload);
  }
  if (Runtime::runtimeFeatureEnabled( "envoy.reloadable_features.handle_stream_reset_during_hcm_encoding")) {
    filter_manager_.onDownstreamReset();
  }

  connection_manager_.doDeferredStreamDestroy(*this);
}

void ConnectionManagerImpl::ActiveStream::onAboveWriteBufferHighWatermark() {
  ENVOY_STREAM_LOG(debug, "Disabling upstream stream due to downstream stream watermark.", *this);
  filter_manager_.callHighWatermarkCallbacks();
}

void ConnectionManagerImpl::ActiveStream::onBelowWriteBufferLowWatermark() {
  ENVOY_STREAM_LOG(debug, "Enabling upstream stream due to downstream stream watermark.", *this);
  filter_manager_.callLowWatermarkCallbacks();
}

Tracing::OperationName ConnectionManagerImpl::ActiveStream::operationName() const {
  return connection_manager_.config_.tracingConfig()->operation_name_;
}

const Tracing::CustomTagMap* ConnectionManagerImpl::ActiveStream::customTags() const {
  return tracing_custom_tags_.get();
}

bool ConnectionManagerImpl::ActiveStream::verbose() const {
  return connection_manager_.config_.tracingConfig()->verbose_;
}

uint32_t ConnectionManagerImpl::ActiveStream::maxPathTagLength() const {
  return connection_manager_.config_.tracingConfig()->max_path_tag_length_;
}

const Router::RouteEntry::UpgradeMap* ConnectionManagerImpl::ActiveStream::upgradeMap() {
  
  
  if (hasCachedRoute() && cached_route_.value()->routeEntry()) {
    return &cached_route_.value()->routeEntry()->upgradeMap();
  }

  return nullptr;
}

Tracing::Span& ConnectionManagerImpl::ActiveStream::activeSpan() {
  if (active_span_) {
    return *active_span_;
  } else {
    return Tracing::NullSpan::instance();
  }
}

Tracing::Config& ConnectionManagerImpl::ActiveStream::tracingConfig() { return *this; }

const ScopeTrackedObject& ConnectionManagerImpl::ActiveStream::scope() { return *this; }

Upstream::ClusterInfoConstSharedPtr ConnectionManagerImpl::ActiveStream::clusterInfo() {
  
  if (!cached_route_.has_value()) {
    refreshCachedRoute();
  }

  return cached_cluster_info_.value();
}

Router::RouteConstSharedPtr ConnectionManagerImpl::ActiveStream::route(const Router::RouteCallback& cb) {
  if (cached_route_.has_value()) {
    return cached_route_.value();
  }
  refreshCachedRoute(cb);
  return cached_route_.value();
}


void ConnectionManagerImpl::ActiveStream::setRoute(Router::RouteConstSharedPtr route) {
  filter_manager_.streamInfo().route_ = route;
  cached_route_ = std::move(route);
  if (nullptr == filter_manager_.streamInfo().route() || nullptr == filter_manager_.streamInfo().route()->routeEntry()) {
    cached_cluster_info_ = nullptr;
  } else {
    Upstream::ThreadLocalCluster* local_cluster = connection_manager_.cluster_manager_.getThreadLocalCluster( filter_manager_.streamInfo().route()->routeEntry()->clusterName());

    cached_cluster_info_ = (nullptr == local_cluster) ? nullptr : local_cluster->info();
  }

  filter_manager_.streamInfo().setUpstreamClusterInfo(cached_cluster_info_.value());
  refreshCachedTracingCustomTags();
  refreshDurationTimeout();
}

void ConnectionManagerImpl::ActiveStream::clearRouteCache() {
  cached_route_ = absl::optional<Router::RouteConstSharedPtr>();
  cached_cluster_info_ = absl::optional<Upstream::ClusterInfoConstSharedPtr>();
  if (tracing_custom_tags_) {
    tracing_custom_tags_->clear();
  }
}

void ConnectionManagerImpl::ActiveStream::onRequestDataTooLarge() {
  connection_manager_.stats_.named_.downstream_rq_too_large_.inc();
}

void ConnectionManagerImpl::ActiveStream::recreateStream( StreamInfo::FilterStateSharedPtr filter_state) {
  
  
  
  ResponseEncoder* response_encoder = response_encoder_;
  response_encoder_ = nullptr;

  Buffer::InstancePtr request_data = std::make_unique<Buffer::OwnedImpl>();
  const auto& buffered_request_data = filter_manager_.bufferedRequestData();
  const bool proxy_body = buffered_request_data != nullptr && buffered_request_data->length() > 0;
  if (proxy_body) {
    request_data->move(*buffered_request_data);
  }

  response_encoder->getStream().removeCallbacks(*this);
  
  
  connection_manager_.doEndStream(*this);

  RequestDecoder& new_stream = connection_manager_.newStream(*response_encoder, true);
  
  
  
  
  
  
  if (filter_state->hasDataAtOrAboveLifeSpan(StreamInfo::FilterState::LifeSpan::Request)) {
    (*connection_manager_.streams_.begin())->filter_manager_.streamInfo().filter_state_ = std::make_shared<StreamInfo::FilterStateImpl>( filter_state->parent(), StreamInfo::FilterState::LifeSpan::FilterChain);

  }

  new_stream.decodeHeaders(std::move(request_headers_), !proxy_body);
  if (proxy_body) {
    
    
    
    new_stream.decodeData(*request_data, true);
  }
}

Http1StreamEncoderOptionsOptRef ConnectionManagerImpl::ActiveStream::http1StreamEncoderOptions() {
  return response_encoder_->http1StreamEncoderOptions();
}

void ConnectionManagerImpl::ActiveStream::onResponseDataTooLarge() {
  connection_manager_.stats_.named_.rs_too_large_.inc();
}

void ConnectionManagerImpl::ActiveStream::resetStream() {
  connection_manager_.stats_.named_.downstream_rq_tx_reset_.inc();
  connection_manager_.doEndStream(*this);
}

} 
} 
