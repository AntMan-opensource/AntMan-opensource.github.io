







namespace Envoy {
namespace ConnectionPool {
namespace {
[[maybe_unused]] ssize_t connectingCapacity(const std::list<ActiveClientPtr>& connecting_clients) {
  ssize_t ret = 0;
  for (const auto& client : connecting_clients) {
    ret += client->effectiveConcurrentStreamLimit();
  }
  return ret;
}
} 

ConnPoolImplBase::ConnPoolImplBase( Upstream::HostConstSharedPtr host, Upstream::ResourcePriority priority, Event::Dispatcher& dispatcher, const Network::ConnectionSocket::OptionsSharedPtr& options, const Network::TransportSocketOptionsConstSharedPtr& transport_socket_options, Upstream::ClusterConnectivityState& state)



    : state_(state), host_(host), priority_(priority), dispatcher_(dispatcher), socket_options_(options), transport_socket_options_(transport_socket_options), upstream_ready_cb_(dispatcher_.createSchedulableCallback([this]() { onUpstreamReady(); })) {}


ConnPoolImplBase::~ConnPoolImplBase() {
  ASSERT(isIdleImpl());
  ASSERT(connecting_stream_capacity_ == 0);
}

void ConnPoolImplBase::deleteIsPendingImpl() {
  deferred_deleting_ = true;
  ASSERT(isIdleImpl());
  ASSERT(connecting_stream_capacity_ == 0);
}

void ConnPoolImplBase::destructAllConnections() {
  for (auto* list : {&ready_clients_, &busy_clients_, &connecting_clients_}) {
    while (!list->empty()) {
      list->front()->close();
    }
  }

  
  dispatcher_.clearDeferredDeleteList();
}

bool ConnPoolImplBase::shouldConnect(size_t pending_streams, size_t active_streams, int64_t connecting_and_connected_capacity, float preconnect_ratio, bool anticipate_incoming_stream) {

  
  
  
  
  
  
  int anticipated_streams = anticipate_incoming_stream ? 1 : 0;

  
  
  
  
  
  
  
  return (pending_streams + active_streams + anticipated_streams) * preconnect_ratio > connecting_and_connected_capacity + active_streams;
}

bool ConnPoolImplBase::shouldCreateNewConnection(float global_preconnect_ratio) const {
  
  
  
  
  if (host_->health() != Upstream::Host::Health::Healthy) {
    return pending_streams_.size() > connecting_stream_capacity_;
  }

  
  if (global_preconnect_ratio != 0) {
    
    
    
    
    
    
    return shouldConnect(pending_streams_.size(), num_active_streams_, connecting_stream_capacity_, global_preconnect_ratio, true);
  } else {
    
    
    
    
    
    return shouldConnect(pending_streams_.size(), num_active_streams_, connecting_stream_capacity_, perUpstreamPreconnectRatio());
  }
}

float ConnPoolImplBase::perUpstreamPreconnectRatio() const {
  return host_->cluster().perUpstreamPreconnectRatio();
}

ConnPoolImplBase::ConnectionResult ConnPoolImplBase::tryCreateNewConnections() {
  ASSERT(!is_draining_for_deletion_);
  ConnPoolImplBase::ConnectionResult result;
  
  
  
  
  
  
  for (int i = 0; i < 3; ++i) {
    result = tryCreateNewConnection();
    if (result != ConnectionResult::CreatedNewConnection) {
      break;
    }
  }
  return result;
}

ConnPoolImplBase::ConnectionResult ConnPoolImplBase::tryCreateNewConnection(float global_preconnect_ratio) {
  
  if (!shouldCreateNewConnection(global_preconnect_ratio)) {
    ENVOY_LOG(trace, "not creating a new connection, shouldCreateNewConnection returned false.");
    return ConnectionResult::ShouldNotConnect;
  }

  const bool can_create_connection = host_->cluster().resourceManager(priority_).connections().canCreate();
  if (!can_create_connection) {
    host_->cluster().stats().upstream_cx_overflow_.inc();
  }
  
  
  
  if (can_create_connection || (ready_clients_.empty() && busy_clients_.empty() && connecting_clients_.empty())) {
    ENVOY_LOG(debug, "creating a new connection");
    ActiveClientPtr client = instantiateActiveClient();
    if (client.get() == nullptr) {
      ENVOY_LOG(trace, "connection creation failed");
      return ConnectionResult::FailedToCreateConnection;
    }
    ASSERT(client->state() == ActiveClient::State::CONNECTING);
    ASSERT(std::numeric_limits<uint64_t>::max() - connecting_stream_capacity_ >= client->effectiveConcurrentStreamLimit());
    ASSERT(client->real_host_description_);
    
    state_.incrConnectingAndConnectedStreamCapacity(client->effectiveConcurrentStreamLimit());
    connecting_stream_capacity_ += client->effectiveConcurrentStreamLimit();
    LinkedList::moveIntoList(std::move(client), owningList(client->state()));
    return can_create_connection ? ConnectionResult::CreatedNewConnection : ConnectionResult::CreatedButRateLimited;
  } else {
    ENVOY_LOG(trace, "not creating a new connection: connection constrained");
    return ConnectionResult::NoConnectionRateLimited;
  }
}

void ConnPoolImplBase::attachStreamToClient(Envoy::ConnectionPool::ActiveClient& client, AttachContext& context) {
  ASSERT(client.state() == Envoy::ConnectionPool::ActiveClient::State::READY);

  if (enforceMaxRequests() && !host_->cluster().resourceManager(priority_).requests().canCreate()) {
    ENVOY_LOG(debug, "max streams overflow");
    onPoolFailure(client.real_host_description_, absl::string_view(), ConnectionPool::PoolFailureReason::Overflow, context);
    host_->cluster().stats().upstream_rq_pending_overflow_.inc();
    return;
  }
  ENVOY_CONN_LOG(debug, "creating stream", client);

  
  uint64_t capacity = client.currentUnusedCapacity();
  client.remaining_streams_--;
  if (client.remaining_streams_ == 0) {
    ENVOY_CONN_LOG(debug, "maximum streams per connection, DRAINING", client);
    host_->cluster().stats().upstream_cx_max_requests_.inc();
    transitionActiveClientState(client, Envoy::ConnectionPool::ActiveClient::State::DRAINING);
  } else if (capacity == 1) {
    
    transitionActiveClientState(client, Envoy::ConnectionPool::ActiveClient::State::BUSY);
  }

  
  
  if (trackStreamCapacity()) {
    state_.decrConnectingAndConnectedStreamCapacity(1);
  }
  
  state_.incrActiveStreams(1);
  num_active_streams_++;
  host_->stats().rq_total_.inc();
  host_->stats().rq_active_.inc();
  host_->cluster().stats().upstream_rq_total_.inc();
  host_->cluster().stats().upstream_rq_active_.inc();
  host_->cluster().resourceManager(priority_).requests().inc();

  onPoolReady(client, context);
}

void ConnPoolImplBase::onStreamClosed(Envoy::ConnectionPool::ActiveClient& client, bool delay_attaching_stream) {
  ENVOY_CONN_LOG(debug, "destroying stream: {} remaining", client, client.numActiveStreams());
  ASSERT(num_active_streams_ > 0);
  state_.decrActiveStreams(1);
  num_active_streams_--;
  host_->stats().rq_active_.dec();
  host_->cluster().stats().upstream_rq_active_.dec();
  host_->cluster().resourceManager(priority_).requests().dec();
  
  
  if (trackStreamCapacity()) {
    
    bool limited_by_concurrency = client.remaining_streams_ > client.concurrent_stream_limit_ - client.numActiveStreams() - 1;
    
    
    
    
    bool negative_capacity = client.concurrent_stream_limit_ < client.numActiveStreams() + 1;
    if (negative_capacity || limited_by_concurrency) {
      state_.incrConnectingAndConnectedStreamCapacity(1);
    }
  }
  if (client.state() == ActiveClient::State::DRAINING && client.numActiveStreams() == 0) {
    
    client.close();
  } else if (client.state() == ActiveClient::State::BUSY && client.currentUnusedCapacity() > 0) {
    transitionActiveClientState(client, ActiveClient::State::READY);
    if (!delay_attaching_stream) {
      onUpstreamReady();
    }
  }
}

ConnectionPool::Cancellable* ConnPoolImplBase::newStreamImpl(AttachContext& context, bool can_send_early_data) {
  ASSERT(!is_draining_for_deletion_);
  ASSERT(!deferred_deleting_);

  ASSERT(static_cast<ssize_t>(connecting_stream_capacity_) == connectingCapacity(connecting_clients_));
  if (!ready_clients_.empty()) {
    ActiveClient& client = *ready_clients_.front();
    ENVOY_CONN_LOG(debug, "using existing connection", client);
    attachStreamToClient(client, context);
    
    tryCreateNewConnections();
    return nullptr;
  }

  if (!host_->cluster().resourceManager(priority_).pendingRequests().canCreate()) {
    ENVOY_LOG(debug, "max pending streams overflow");
    onPoolFailure(nullptr, absl::string_view(), ConnectionPool::PoolFailureReason::Overflow, context);
    host_->cluster().stats().upstream_rq_pending_overflow_.inc();
    return nullptr;
  }

  ConnectionPool::Cancellable* pending = newPendingStream(context, can_send_early_data);
  ENVOY_LOG(debug, "trying to create new connection");
  ENVOY_LOG(trace, fmt::format("{}", *this));

  auto old_capacity = connecting_stream_capacity_;
  
  
  const ConnectionResult result = tryCreateNewConnections();
  
  
  ENVOY_BUG(pending_streams_.size() <= connecting_stream_capacity_ || connecting_stream_capacity_ > old_capacity || (result == ConnectionResult::NoConnectionRateLimited || result == ConnectionResult::FailedToCreateConnection), fmt::format("Failed to create expected connection: {}", *this));



  if (result == ConnectionResult::FailedToCreateConnection) {
    
    
    pending->cancel(Envoy::ConnectionPool::CancelPolicy::CloseExcess);
    onPoolFailure(nullptr, absl::string_view(), ConnectionPool::PoolFailureReason::Overflow, context);
    return nullptr;
  }

  return pending;
}

bool ConnPoolImplBase::maybePreconnectImpl(float global_preconnect_ratio) {
  ASSERT(!deferred_deleting_);
  return tryCreateNewConnection(global_preconnect_ratio) == ConnectionResult::CreatedNewConnection;
}

void ConnPoolImplBase::scheduleOnUpstreamReady() {
  upstream_ready_cb_->scheduleCallbackCurrentIteration();
}

void ConnPoolImplBase::onUpstreamReady() {
  while (!pending_streams_.empty() && !ready_clients_.empty()) {
    ActiveClientPtr& client = ready_clients_.front();
    ENVOY_CONN_LOG(debug, "attaching to next stream", *client);
    
    attachStreamToClient(*client, pending_streams_.back()->context());
    state_.decrPendingStreams(1);
    pending_streams_.pop_back();
  }
  if (!pending_streams_.empty()) {
    tryCreateNewConnections();
  }
}

std::list<ActiveClientPtr>& ConnPoolImplBase::owningList(ActiveClient::State state) {
  switch (state) {
  case ActiveClient::State::CONNECTING:
    return connecting_clients_;
  case ActiveClient::State::READY:
    return ready_clients_;
  case ActiveClient::State::BUSY:
    return busy_clients_;
  case ActiveClient::State::DRAINING:
    return busy_clients_;
  case ActiveClient::State::CLOSED:
    break; 
  }
  PANIC("unexpected");
}

void ConnPoolImplBase::transitionActiveClientState(ActiveClient& client, ActiveClient::State new_state) {
  auto& old_list = owningList(client.state());
  auto& new_list = owningList(new_state);
  client.setState(new_state);

  
  
  
  
  
  if (&old_list != &new_list) {
    client.moveBetweenLists(old_list, new_list);
  }
}

void ConnPoolImplBase::addIdleCallbackImpl(Instance::IdleCb cb) { idle_callbacks_.push_back(cb); }

void ConnPoolImplBase::closeIdleConnectionsForDrainingPool() {
  
  std::list<ActiveClient*> to_close;

  for (auto& client : ready_clients_) {
    if (client->numActiveStreams() == 0) {
      to_close.push_back(client.get());
    }
  }

  if (pending_streams_.empty()) {
    for (auto& client : connecting_clients_) {
      to_close.push_back(client.get());
    }
  }

  for (auto& entry : to_close) {
    ENVOY_LOG_EVENT(debug, "closing_idle_client", "closing idle client {} for cluster {}", entry->id(), host_->cluster().name());
    entry->close();
  }
}

void ConnPoolImplBase::drainConnectionsImpl(DrainBehavior drain_behavior) {
  if (drain_behavior == Envoy::ConnectionPool::DrainBehavior::DrainAndDelete) {
    is_draining_for_deletion_ = true;
    checkForIdleAndCloseIdleConnsIfDraining();
    return;
  }
  closeIdleConnectionsForDrainingPool();

  
  
  
  while (!ready_clients_.empty()) {
    ENVOY_LOG_EVENT(debug, "draining_ready_client", "draining active client {} for cluster {}", ready_clients_.front()->id(), host_->cluster().name());
    transitionActiveClientState(*ready_clients_.front(), ActiveClient::State::DRAINING);
  }

  
  
  ASSERT(&owningList(ActiveClient::State::DRAINING) == &busy_clients_);
  for (auto& busy_client : busy_clients_) {
    ENVOY_LOG_EVENT(debug, "draining_busy_client", "draining busy client {} for cluster {}", busy_client->id(), host_->cluster().name());
    transitionActiveClientState(*busy_client, ActiveClient::State::DRAINING);
  }
}

bool ConnPoolImplBase::isIdleImpl() const {
  return pending_streams_.empty() && ready_clients_.empty() && busy_clients_.empty() && connecting_clients_.empty();
}

void ConnPoolImplBase::checkForIdleAndCloseIdleConnsIfDraining() {
  if (is_draining_for_deletion_) {
    closeIdleConnectionsForDrainingPool();
  }

  if (isIdleImpl()) {
    ENVOY_LOG(debug, "invoking idle callbacks - is_draining_for_deletion_={}", is_draining_for_deletion_);
    for (const Instance::IdleCb& cb : idle_callbacks_) {
      cb();
    }
  }
}

void ConnPoolImplBase::onConnectionEvent(ActiveClient& client, absl::string_view failure_reason, Network::ConnectionEvent event) {
  if (client.state() == ActiveClient::State::CONNECTING) {
    ASSERT(connecting_stream_capacity_ >= client.effectiveConcurrentStreamLimit());
    connecting_stream_capacity_ -= client.effectiveConcurrentStreamLimit();
  }

  if (client.connect_timer_) {
    client.connect_timer_->disableTimer();
    client.connect_timer_.reset();
  }

  if (event == Network::ConnectionEvent::RemoteClose || event == Network::ConnectionEvent::LocalClose) {
    state_.decrConnectingAndConnectedStreamCapacity(client.currentUnusedCapacity());
    
    client.remaining_streams_ = 0;
    
    ENVOY_CONN_LOG(debug, "client disconnected, failure reason: {}", client, failure_reason);

    Envoy::Upstream::reportUpstreamCxDestroy(host_, event);
    const bool incomplete_stream = client.closingWithIncompleteStream();
    if (incomplete_stream) {
      Envoy::Upstream::reportUpstreamCxDestroyActiveRequest(host_, event);
    }

    if (client.state() == ActiveClient::State::CONNECTING) {
      host_->cluster().stats().upstream_cx_connect_fail_.inc();
      host_->stats().cx_connect_fail_.inc();

      ConnectionPool::PoolFailureReason reason;
      if (client.timed_out_) {
        reason = ConnectionPool::PoolFailureReason::Timeout;
      } else if (event == Network::ConnectionEvent::RemoteClose) {
        reason = ConnectionPool::PoolFailureReason::RemoteConnectionFailure;
      } else {
        reason = ConnectionPool::PoolFailureReason::LocalConnectionFailure;
      }

      
      
      
      
      
      
      purgePendingStreams(client.real_host_description_, failure_reason, reason);
      
      if (!is_draining_for_deletion_) {
        tryCreateNewConnections();
      }
    }

    
    
    
    
    client.releaseResources();

    
    
    
    
    
    if (client.connection_duration_timer_) {
      client.connection_duration_timer_->disableTimer();
      client.connection_duration_timer_.reset();
    }

    dispatcher_.deferredDelete(client.removeFromList(owningList(client.state())));

    checkForIdleAndCloseIdleConnsIfDraining();

    client.setState(ActiveClient::State::CLOSED);

    
    if (!pending_streams_.empty()) {
      tryCreateNewConnections();
    }
  } else if (event == Network::ConnectionEvent::Connected) {
    client.conn_connect_ms_->complete();
    client.conn_connect_ms_.reset();
    ASSERT(client.state() == ActiveClient::State::CONNECTING);
    bool streams_available = client.currentUnusedCapacity() > 0;
    transitionActiveClientState(client, streams_available ? ActiveClient::State::READY : ActiveClient::State::BUSY);

    
    const absl::optional<std::chrono::milliseconds> max_connection_duration = client.parent_.host()->cluster().maxConnectionDuration();
    if (max_connection_duration.has_value()) {
      client.connection_duration_timer_ = client.parent_.dispatcher().createTimer( [&client]() { client.onConnectionDurationTimeout(); });
      client.connection_duration_timer_->enableTimer(max_connection_duration.value());
    }

    
    
    onConnected(client);
    if (streams_available) {
      onUpstreamReady();
    }
    checkForIdleAndCloseIdleConnsIfDraining();
  }
}

PendingStream::PendingStream(ConnPoolImplBase& parent, bool can_send_early_data)
    : parent_(parent), can_send_early_data_(can_send_early_data) {
  parent_.host()->cluster().stats().upstream_rq_pending_total_.inc();
  parent_.host()->cluster().stats().upstream_rq_pending_active_.inc();
  parent_.host()->cluster().resourceManager(parent_.priority()).pendingRequests().inc();
}

PendingStream::~PendingStream() {
  parent_.host()->cluster().stats().upstream_rq_pending_active_.dec();
  parent_.host()->cluster().resourceManager(parent_.priority()).pendingRequests().dec();
}

void PendingStream::cancel(Envoy::ConnectionPool::CancelPolicy policy) {
  parent_.onPendingStreamCancel(*this, policy);
}

void ConnPoolImplBase::purgePendingStreams( const Upstream::HostDescriptionConstSharedPtr& host_description, absl::string_view failure_reason, ConnectionPool::PoolFailureReason reason) {

  
  
  state_.decrPendingStreams(pending_streams_.size());
  pending_streams_to_purge_ = std::move(pending_streams_);
  while (!pending_streams_to_purge_.empty()) {
    PendingStreamPtr stream = pending_streams_to_purge_.front()->removeFromList(pending_streams_to_purge_);
    host_->cluster().stats().upstream_rq_pending_failure_eject_.inc();
    onPoolFailure(host_description, failure_reason, reason, stream->context());
  }
}

bool ConnPoolImplBase::connectingConnectionIsExcess() const {
  ASSERT(connecting_stream_capacity_ >= connecting_clients_.front()->effectiveConcurrentStreamLimit());
  
  
  
  
  
  
  
  return (pending_streams_.size() + num_active_streams_) * perUpstreamPreconnectRatio() <= (connecting_stream_capacity_ - connecting_clients_.front()->effectiveConcurrentStreamLimit() + num_active_streams_);

}

void ConnPoolImplBase::onPendingStreamCancel(PendingStream& stream, Envoy::ConnectionPool::CancelPolicy policy) {
  ENVOY_LOG(debug, "cancelling pending stream");
  if (!pending_streams_to_purge_.empty()) {
    
    
    
    
    stream.removeFromList(pending_streams_to_purge_);
  } else {
    state_.decrPendingStreams(1);
    stream.removeFromList(pending_streams_);
  }
  if (policy == Envoy::ConnectionPool::CancelPolicy::CloseExcess && !connecting_clients_.empty() && connectingConnectionIsExcess()) {
    auto& client = *connecting_clients_.front();
    transitionActiveClientState(client, ActiveClient::State::DRAINING);
    client.close();
  }

  host_->cluster().stats().upstream_rq_cancelled_.inc();
  checkForIdleAndCloseIdleConnsIfDraining();
}

namespace {


uint32_t translateZeroToUnlimited(uint32_t limit) {
  return (limit != 0) ? limit : std::numeric_limits<uint32_t>::max();
}
} 

ActiveClient::ActiveClient(ConnPoolImplBase& parent, uint32_t lifetime_stream_limit, uint32_t concurrent_stream_limit)
    : parent_(parent), remaining_streams_(translateZeroToUnlimited(lifetime_stream_limit)), configured_stream_limit_(translateZeroToUnlimited(concurrent_stream_limit)), concurrent_stream_limit_(translateZeroToUnlimited(concurrent_stream_limit)), connect_timer_(parent_.dispatcher().createTimer([this]() { onConnectTimeout(); })) {


  conn_connect_ms_ = std::make_unique<Stats::HistogramCompletableTimespanImpl>( parent_.host()->cluster().stats().upstream_cx_connect_ms_, parent_.dispatcher().timeSource());
  conn_length_ = std::make_unique<Stats::HistogramCompletableTimespanImpl>( parent_.host()->cluster().stats().upstream_cx_length_ms_, parent_.dispatcher().timeSource());
  connect_timer_->enableTimer(parent_.host()->cluster().connectTimeout());
  parent_.host()->stats().cx_total_.inc();
  parent_.host()->stats().cx_active_.inc();
  parent_.host()->cluster().stats().upstream_cx_total_.inc();
  parent_.host()->cluster().stats().upstream_cx_active_.inc();
  parent_.host()->cluster().resourceManager(parent_.priority()).connections().inc();
}

ActiveClient::~ActiveClient() { releaseResourcesBase(); }

void ActiveClient::releaseResourcesBase() {
  if (!resources_released_) {
    resources_released_ = true;

    conn_length_->complete();

    parent_.host()->cluster().stats().upstream_cx_active_.dec();
    parent_.host()->stats().cx_active_.dec();
    parent_.host()->cluster().resourceManager(parent_.priority()).connections().dec();
  }
}

void ActiveClient::onConnectTimeout() {
  ENVOY_CONN_LOG(debug, "connect timeout", *this);
  parent_.host()->cluster().stats().upstream_cx_connect_timeout_.inc();
  timed_out_ = true;
  close();
}

void ActiveClient::onConnectionDurationTimeout() {
  
  ENVOY_BUG(state_ != ActiveClient::State::CONNECTING, "max connection duration reached while connecting");

  
  
  ENVOY_BUG(state_ != ActiveClient::State::CLOSED, "max connection duration reached while closed");

  
  
  if (state_ == ActiveClient::State::CONNECTING || state_ == ActiveClient::State::CLOSED || state_ == ActiveClient::State::DRAINING) {
    return;
  }

  ENVOY_CONN_LOG(debug, "max connection duration reached, DRAINING", *this);
  parent_.host()->cluster().stats().upstream_cx_max_duration_reached_.inc();
  parent_.transitionActiveClientState(*this, Envoy::ConnectionPool::ActiveClient::State::DRAINING);

  
  
  
  if (numActiveStreams() == 0) {
    close();
  }
}

void ActiveClient::drain() {
  if (currentUnusedCapacity() <= 0) {
    return;
  }
  if (state() == ActiveClient::State::CONNECTING) {
    
    
    parent_.decrConnectingAndConnectedStreamCapacity(currentUnusedCapacity());
  } else {
    parent_.state().decrConnectingAndConnectedStreamCapacity(currentUnusedCapacity());
  }

  remaining_streams_ = 0;
}

} 
} 
