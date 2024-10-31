




























namespace Envoy {
namespace Upstream {

namespace {


const std::string& getHostname(const HostSharedPtr& host, const std::string& config_hostname, const ClusterInfoConstSharedPtr& cluster) {
  if (!host->hostnameForHealthChecks().empty()) {
    return host->hostnameForHealthChecks();
  }

  if (!config_hostname.empty()) {
    return config_hostname;
  }

  return cluster->name();
}

const std::string& getHostname(const HostSharedPtr& host, const absl::optional<std::string>& config_hostname, const ClusterInfoConstSharedPtr& cluster) {

  if (config_hostname.has_value()) {
    return getHostname(host, config_hostname.value(), cluster);
  }
  return getHostname(host, EMPTY_STRING, cluster);
}

} 

class HealthCheckerFactoryContextImpl : public Server::Configuration::HealthCheckerFactoryContext {
public:
  HealthCheckerFactoryContextImpl(Upstream::Cluster& cluster, Envoy::Runtime::Loader& runtime, Event::Dispatcher& dispatcher, HealthCheckEventLoggerPtr&& event_logger, ProtobufMessage::ValidationVisitor& validation_visitor, Api::Api& api)



      : cluster_(cluster), runtime_(runtime), dispatcher_(dispatcher), event_logger_(std::move(event_logger)), validation_visitor_(validation_visitor), api_(api) {
  }
  Upstream::Cluster& cluster() override { return cluster_; }
  Envoy::Runtime::Loader& runtime() override { return runtime_; }
  Event::Dispatcher& mainThreadDispatcher() override { return dispatcher_; }
  HealthCheckEventLoggerPtr eventLogger() override { return std::move(event_logger_); }
  ProtobufMessage::ValidationVisitor& messageValidationVisitor() override {
    return validation_visitor_;
  }
  Api::Api& api() override { return api_; }

private:
  Upstream::Cluster& cluster_;
  Envoy::Runtime::Loader& runtime_;
  Event::Dispatcher& dispatcher_;
  HealthCheckEventLoggerPtr event_logger_;
  ProtobufMessage::ValidationVisitor& validation_visitor_;
  Api::Api& api_;
};

HealthCheckerSharedPtr HealthCheckerFactory::create( const envoy::config::core::v3::HealthCheck& health_check_config, Upstream::Cluster& cluster, Runtime::Loader& runtime, Event::Dispatcher& dispatcher, AccessLog::AccessLogManager& log_manager, ProtobufMessage::ValidationVisitor& validation_visitor, Api::Api& api) {



  HealthCheckEventLoggerPtr event_logger;
  if (!health_check_config.event_log_path().empty()) {
    event_logger = std::make_unique<HealthCheckEventLoggerImpl>( log_manager, dispatcher.timeSource(), health_check_config.event_log_path());
  }
  switch (health_check_config.health_checker_case()) {
  case envoy::config::core::v3::HealthCheck::HealthCheckerCase::HEALTH_CHECKER_NOT_SET:
    throw EnvoyException("invalid cluster config");
  case envoy::config::core::v3::HealthCheck::HealthCheckerCase::kHttpHealthCheck:
    return std::make_shared<ProdHttpHealthCheckerImpl>(cluster, health_check_config, dispatcher, runtime, api.randomGenerator(), std::move(event_logger));

  case envoy::config::core::v3::HealthCheck::HealthCheckerCase::kTcpHealthCheck:
    return std::make_shared<TcpHealthCheckerImpl>(cluster, health_check_config, dispatcher, runtime, api.randomGenerator(), std::move(event_logger));
  case envoy::config::core::v3::HealthCheck::HealthCheckerCase::kGrpcHealthCheck:
    if (!(cluster.info()->features() & Upstream::ClusterInfo::Features::HTTP2)) {
      throw EnvoyException(fmt::format("{} cluster must support HTTP/2 for gRPC healthchecking", cluster.info()->name()));
    }
    return std::make_shared<ProdGrpcHealthCheckerImpl>(cluster, health_check_config, dispatcher, runtime, api.randomGenerator(), std::move(event_logger));

  case envoy::config::core::v3::HealthCheck::HealthCheckerCase::kCustomHealthCheck: {
    auto& factory = Config::Utility::getAndCheckFactory<Server::Configuration::CustomHealthCheckerFactory>( health_check_config.custom_health_check());

    std::unique_ptr<Server::Configuration::HealthCheckerFactoryContext> context( new HealthCheckerFactoryContextImpl(cluster, runtime, dispatcher, std::move(event_logger), validation_visitor, api));

    return factory.createCustomHealthChecker(health_check_config, *context);
  }
  }
  PANIC_DUE_TO_CORRUPT_ENUM;
}

HttpHealthCheckerImpl::HttpHealthCheckerImpl(const Cluster& cluster, const envoy::config::core::v3::HealthCheck& config, Event::Dispatcher& dispatcher, Runtime::Loader& runtime, Random::RandomGenerator& random, HealthCheckEventLoggerPtr&& event_logger)




    : HealthCheckerImplBase(cluster, config, dispatcher, runtime, random, std::move(event_logger)), path_(config.http_health_check().path()), host_value_(config.http_health_check().host()), request_headers_parser_( Router::HeaderParser::configure(config.http_health_check().request_headers_to_add(), config.http_health_check().request_headers_to_remove())), http_status_checker_(config.http_health_check().expected_statuses(), config.http_health_check().retriable_statuses(), static_cast<uint64_t>(Http::Code::OK)), codec_client_type_(codecClientType(config.http_health_check().codec_client_type())), random_generator_(random) {








  if (config.http_health_check().has_service_name_matcher()) {
    service_name_matcher_.emplace(config.http_health_check().service_name_matcher());
  }
}

HttpHealthCheckerImpl::HttpStatusChecker::HttpStatusChecker( const Protobuf::RepeatedPtrField<envoy::type::v3::Int64Range>& expected_statuses, const Protobuf::RepeatedPtrField<envoy::type::v3::Int64Range>& retriable_statuses, uint64_t default_expected_status) {


  for (const auto& status_range : expected_statuses) {
    const auto start = static_cast<uint64_t>(status_range.start());
    const auto end = static_cast<uint64_t>(status_range.end());

    validateRange(start, end, "expected");

    expected_ranges_.emplace_back(std::make_pair(start, end));
  }

  if (expected_ranges_.empty()) {
    expected_ranges_.emplace_back( std::make_pair(default_expected_status, default_expected_status + 1));
  }

  for (const auto& status_range : retriable_statuses) {
    const auto start = static_cast<uint64_t>(status_range.start());
    const auto end = static_cast<uint64_t>(status_range.end());

    validateRange(start, end, "retriable");

    retriable_ranges_.emplace_back(std::make_pair(start, end));
  }
}

void HttpHealthCheckerImpl::HttpStatusChecker::validateRange(uint64_t start, uint64_t end, absl::string_view range_type) {
  if (start >= end) {
    throw EnvoyException(fmt::format("Invalid http {} status range: expecting start < " "end, but found start={} and end={}", range_type, start, end));

  }

  if (start < 100) {
    throw EnvoyException( fmt::format("Invalid http {} status range: expecting start >= 100, but found start={}", range_type, start));

  }

  if (end > 600) {
    throw EnvoyException(fmt::format( "Invalid http {} status range: expecting end <= 600, but found end={}", range_type, end));
  }
}

bool HttpHealthCheckerImpl::HttpStatusChecker::inRetriableRanges(uint64_t http_status) const {
  return inRanges(http_status, retriable_ranges_);
}

bool HttpHealthCheckerImpl::HttpStatusChecker::inExpectedRanges(uint64_t http_status) const {
  return inRanges(http_status, expected_ranges_);
}

bool HttpHealthCheckerImpl::HttpStatusChecker::inRanges( uint64_t http_status, const std::vector<std::pair<uint64_t, uint64_t>>& ranges) {
  for (const auto& range : ranges) {
    if (http_status >= range.first && http_status < range.second) {
      return true;
    }
  }

  return false;
}

Http::Protocol codecClientTypeToProtocol(Http::CodecType codec_client_type) {
  switch (codec_client_type) {
  case Http::CodecType::HTTP1:
    return Http::Protocol::Http11;
  case Http::CodecType::HTTP2:
    return Http::Protocol::Http2;
  case Http::CodecType::HTTP3:
    return Http::Protocol::Http3;
  }
  PANIC_DUE_TO_CORRUPT_ENUM }

HttpHealthCheckerImpl::HttpActiveHealthCheckSession::HttpActiveHealthCheckSession( HttpHealthCheckerImpl& parent, const HostSharedPtr& host)
    : ActiveHealthCheckSession(parent, host), parent_(parent), hostname_(getHostname(host, parent_.host_value_, parent_.cluster_.info())), protocol_(codecClientTypeToProtocol(parent_.codec_client_type_)), local_connection_info_provider_(std::make_shared<Network::ConnectionInfoSetterImpl>( Network::Utility::getCanonicalIpv4LoopbackAddress(), Network::Utility::getCanonicalIpv4LoopbackAddress())) {}





HttpHealthCheckerImpl::HttpActiveHealthCheckSession::~HttpActiveHealthCheckSession() {
  ASSERT(client_ == nullptr);
}

void HttpHealthCheckerImpl::HttpActiveHealthCheckSession::onDeferredDelete() {
  if (client_) {
    
    expect_reset_ = true;
    client_->close();
  }
}

void HttpHealthCheckerImpl::HttpActiveHealthCheckSession::decodeHeaders( Http::ResponseHeaderMapPtr&& headers, bool end_stream) {
  ASSERT(!response_headers_);
  response_headers_ = std::move(headers);
  if (end_stream) {
    onResponseComplete();
  }
}

void HttpHealthCheckerImpl::HttpActiveHealthCheckSession::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::RemoteClose || event == Network::ConnectionEvent::LocalClose) {
    
    
    
    response_headers_.reset();
    parent_.dispatcher_.deferredDelete(std::move(client_));
  }
}


void HttpHealthCheckerImpl::HttpActiveHealthCheckSession::onInterval() {
  if (!client_) {
    Upstream::Host::CreateConnectionData conn = host_->createHealthCheckConnection(parent_.dispatcher_, parent_.transportSocketOptions(), parent_.transportSocketMatchMetadata().get());

    client_.reset(parent_.createCodecClient(conn));
    client_->addConnectionCallbacks(connection_callback_impl_);
    client_->setCodecConnectionCallbacks(http_connection_callback_impl_);
    expect_reset_ = false;
    reuse_connection_ = parent_.reuse_connection_;
  }

  Http::RequestEncoder* request_encoder = &client_->newStream(*this);
  request_encoder->getStream().addCallbacks(*this);
  request_in_flight_ = true;

  const auto request_headers = Http::createHeaderMap<Http::RequestHeaderMapImpl>( {{Http::Headers::get().Method, "GET", {Http::Headers::get().Host, hostname_}, {Http::Headers::get().Path, parent_.path_}, {Http::Headers::get().UserAgent, Http::Headers::get().UserAgentValues.EnvoyHealthChecker}});



  Router::FilterUtility::setUpstreamScheme( *request_headers,   host_->transportSocketFactory().implementsSecureTransport());



  StreamInfo::StreamInfoImpl stream_info(protocol_, parent_.dispatcher_.timeSource(), local_connection_info_provider_);
  stream_info.setUpstreamInfo(std::make_shared<StreamInfo::UpstreamInfoImpl>());
  stream_info.upstreamInfo()->setUpstreamHost(host_);
  parent_.request_headers_parser_->evaluateHeaders(*request_headers, stream_info);
  auto status = request_encoder->encodeHeaders(*request_headers, true);
  
  ASSERT(status.ok());
}

void HttpHealthCheckerImpl::HttpActiveHealthCheckSession::onResetStream(Http::StreamResetReason, absl::string_view) {
  request_in_flight_ = false;
  ENVOY_CONN_LOG(debug, "connection/stream error health_flags={}", *client_, HostUtility::healthFlagsToString(*host_));
  if (expect_reset_) {
    return;
  }

  if (client_ && !reuse_connection_) {
    client_->close();
  }

  handleFailure(envoy::data::core::v3::NETWORK);
}

void HttpHealthCheckerImpl::HttpActiveHealthCheckSession::onGoAway( Http::GoAwayErrorCode error_code) {
  ENVOY_CONN_LOG(debug, "connection going away goaway_code={}, health_flags={}", *client_, static_cast<int>(error_code), HostUtility::healthFlagsToString(*host_));

  if (request_in_flight_ && error_code == Http::GoAwayErrorCode::NoError) {
    
    
    
    reuse_connection_ = false;
    return;
  }

  if (request_in_flight_) {
    
    handleFailure(envoy::data::core::v3::NETWORK);
  }

  if (client_) {
    expect_reset_ = true;
    client_->close();
  }
}

HttpHealthCheckerImpl::HttpActiveHealthCheckSession::HealthCheckResult HttpHealthCheckerImpl::HttpActiveHealthCheckSession::healthCheckResult() {
  const uint64_t response_code = Http::Utility::getResponseStatus(*response_headers_);
  ENVOY_CONN_LOG(debug, "hc response={} health_flags={}", *client_, response_code, HostUtility::healthFlagsToString(*host_));

  if (!parent_.http_status_checker_.inExpectedRanges(response_code)) {
    
    
    
    
    
    
    if (response_headers_->EnvoyImmediateHealthCheckFail() != nullptr) {
      host_->healthFlagSet(Host::HealthFlag::EXCLUDED_VIA_IMMEDIATE_HC_FAIL);
    }

    if (parent_.http_status_checker_.inRetriableRanges(response_code)) {
      return HealthCheckResult::Retriable;
    } else {
      return HealthCheckResult::Failed;
    }
  }

  const auto degraded = response_headers_->EnvoyDegraded() != nullptr;

  if (parent_.service_name_matcher_.has_value() && parent_.runtime_.snapshot().featureEnabled("health_check.verify_cluster", 100UL)) {
    parent_.stats_.verify_cluster_.inc();
    std::string service_cluster_healthchecked = response_headers_->EnvoyUpstreamHealthCheckedCluster()
            ? std::string(response_headers_->getEnvoyUpstreamHealthCheckedClusterValue())
            : EMPTY_STRING;
    if (parent_.service_name_matcher_->match(service_cluster_healthchecked)) {
      return degraded ? HealthCheckResult::Degraded : HealthCheckResult::Succeeded;
    } else {
      return HealthCheckResult::Failed;
    }
  }

  return degraded ? HealthCheckResult::Degraded : HealthCheckResult::Succeeded;
}

void HttpHealthCheckerImpl::HttpActiveHealthCheckSession::onResponseComplete() {
  request_in_flight_ = false;

  switch (healthCheckResult()) {
  case HealthCheckResult::Succeeded:
    handleSuccess(false);
    break;
  case HealthCheckResult::Degraded:
    handleSuccess(true);
    break;
  case HealthCheckResult::Failed:
    handleFailure(envoy::data::core::v3::ACTIVE, false);
    break;
  case HealthCheckResult::Retriable:
    handleFailure(envoy::data::core::v3::ACTIVE, true);
    break;
  }

  if (shouldClose()) {
    client_->close();
  }

  response_headers_.reset();
}



bool HttpHealthCheckerImpl::HttpActiveHealthCheckSession::shouldClose() const {
  if (client_ == nullptr) {
    return false;
  }

  if (!reuse_connection_) {
    return true;
  }

  return Http::HeaderUtility::shouldCloseConnection(client_->protocol(), *response_headers_);
}

void HttpHealthCheckerImpl::HttpActiveHealthCheckSession::onTimeout() {
  request_in_flight_ = false;
  if (client_) {
    ENVOY_CONN_LOG(debug, "connection/stream timeout health_flags={}", *client_, HostUtility::healthFlagsToString(*host_));

    
    expect_reset_ = true;

    client_->close();
  }
}

Http::CodecType HttpHealthCheckerImpl::codecClientType(const envoy::type::v3::CodecClientType& type) {
  switch (type) {
    PANIC_ON_PROTO_ENUM_SENTINEL_VALUES;
  case envoy::type::v3::HTTP3:
    return Http::CodecType::HTTP3;
  case envoy::type::v3::HTTP2:
    return Http::CodecType::HTTP2;
  case envoy::type::v3::HTTP1:
    return Http::CodecType::HTTP1;
  }
  PANIC_DUE_TO_CORRUPT_ENUM }

Http::CodecClient* ProdHttpHealthCheckerImpl::createCodecClient(Upstream::Host::CreateConnectionData& data) {
  return new Http::CodecClientProd(codec_client_type_, std::move(data.connection_), data.host_description_, dispatcher_, random_generator_);
}

TcpHealthCheckMatcher::MatchSegments TcpHealthCheckMatcher::loadProtoBytes( const Protobuf::RepeatedPtrField<envoy::config::core::v3::HealthCheck::Payload>& byte_array) {
  MatchSegments result;

  for (const auto& entry : byte_array) {
    const auto decoded = Hex::decode(entry.text());
    if (decoded.empty()) {
      throw EnvoyException(fmt::format("invalid hex string '{}'", entry.text()));
    }
    result.push_back(decoded);
  }

  return result;
}

bool TcpHealthCheckMatcher::match(const MatchSegments& expected, const Buffer::Instance& buffer) {
  uint64_t start_index = 0;
  for (const std::vector<uint8_t>& segment : expected) {
    ssize_t search_result = buffer.search(segment.data(), segment.size(), start_index);
    if (search_result == -1) {
      return false;
    }

    start_index = search_result + segment.size();
  }

  return true;
}

TcpHealthCheckerImpl::TcpHealthCheckerImpl(const Cluster& cluster, const envoy::config::core::v3::HealthCheck& config, Event::Dispatcher& dispatcher, Runtime::Loader& runtime, Random::RandomGenerator& random, HealthCheckEventLoggerPtr&& event_logger)



    : HealthCheckerImplBase(cluster, config, dispatcher, runtime, random, std::move(event_logger)), send_bytes_([&config] {
        Protobuf::RepeatedPtrField<envoy::config::core::v3::HealthCheck::Payload> send_repeated;
        if (!config.tcp_health_check().send().text().empty()) {
          send_repeated.Add()->CopyFrom(config.tcp_health_check().send());
        }
        return TcpHealthCheckMatcher::loadProtoBytes(send_repeated);
      }()), receive_bytes_(TcpHealthCheckMatcher::loadProtoBytes(config.tcp_health_check().receive())) {}

TcpHealthCheckerImpl::TcpActiveHealthCheckSession::~TcpActiveHealthCheckSession() {
  ASSERT(client_ == nullptr);
}

void TcpHealthCheckerImpl::TcpActiveHealthCheckSession::onDeferredDelete() {
  if (client_) {
    expect_close_ = true;
    client_->close(Network::ConnectionCloseType::NoFlush);
  }
}

void TcpHealthCheckerImpl::TcpActiveHealthCheckSession::onData(Buffer::Instance& data) {
  ENVOY_CONN_LOG(trace, "total pending buffer={}", *client_, data.length());
  
  
  
  if (TcpHealthCheckMatcher::match(parent_.receive_bytes_, data)) {
    ENVOY_CONN_LOG(trace, "healthcheck passed", *client_);
    data.drain(data.length());
    handleSuccess(false);
    if (!parent_.reuse_connection_) {
      expect_close_ = true;
      client_->close(Network::ConnectionCloseType::NoFlush);
    }
  }
}

void TcpHealthCheckerImpl::TcpActiveHealthCheckSession::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::RemoteClose || event == Network::ConnectionEvent::LocalClose) {
    if (!expect_close_) {
      handleFailure(envoy::data::core::v3::NETWORK);
    }
    parent_.dispatcher_.deferredDelete(std::move(client_));
  }

  if (event == Network::ConnectionEvent::Connected && parent_.receive_bytes_.empty()) {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    expect_close_ = true;
    client_->close(Network::ConnectionCloseType::NoFlush);
    handleSuccess(false);
  }
}


void TcpHealthCheckerImpl::TcpActiveHealthCheckSession::onInterval() {
  if (!client_) {
    client_ = host_ ->createHealthCheckConnection(parent_.dispatcher_, parent_.transportSocketOptions(), parent_.transportSocketMatchMetadata().get())


            .connection_;
    session_callbacks_ = std::make_shared<TcpSessionCallbacks>(*this);
    client_->addConnectionCallbacks(*session_callbacks_);
    client_->addReadFilter(session_callbacks_);

    expect_close_ = false;
    client_->connect();
    client_->noDelay(true);
  }

  if (!parent_.send_bytes_.empty()) {
    Buffer::OwnedImpl data;
    for (const std::vector<uint8_t>& segment : parent_.send_bytes_) {
      data.add(segment.data(), segment.size());
    }

    client_->write(data, false);
  }
}

void TcpHealthCheckerImpl::TcpActiveHealthCheckSession::onTimeout() {
  expect_close_ = true;
  client_->close(Network::ConnectionCloseType::NoFlush);
}

GrpcHealthCheckerImpl::GrpcHealthCheckerImpl(const Cluster& cluster, const envoy::config::core::v3::HealthCheck& config, Event::Dispatcher& dispatcher, Runtime::Loader& runtime, Random::RandomGenerator& random, HealthCheckEventLoggerPtr&& event_logger)




    : HealthCheckerImplBase(cluster, config, dispatcher, runtime, random, std::move(event_logger)), random_generator_(random), service_method_(*Protobuf::DescriptorPool::generated_pool()->FindMethodByName( "grpc.health.v1.Health.Check")), request_headers_parser_( Router::HeaderParser::configure(config.grpc_health_check().initial_metadata())) {




  if (!config.grpc_health_check().service_name().empty()) {
    service_name_ = config.grpc_health_check().service_name();
  }

  if (!config.grpc_health_check().authority().empty()) {
    authority_value_ = config.grpc_health_check().authority();
  }
}

GrpcHealthCheckerImpl::GrpcActiveHealthCheckSession::GrpcActiveHealthCheckSession( GrpcHealthCheckerImpl& parent, const HostSharedPtr& host)
    : ActiveHealthCheckSession(parent, host), parent_(parent), local_connection_info_provider_(std::make_shared<Network::ConnectionInfoSetterImpl>( Network::Utility::getCanonicalIpv4LoopbackAddress(), Network::Utility::getCanonicalIpv4LoopbackAddress())) {}



GrpcHealthCheckerImpl::GrpcActiveHealthCheckSession::~GrpcActiveHealthCheckSession() {
  ASSERT(client_ == nullptr);
}

void GrpcHealthCheckerImpl::GrpcActiveHealthCheckSession::onDeferredDelete() {
  if (client_) {
    
    expect_reset_ = true;
    client_->close();
  }
}

void GrpcHealthCheckerImpl::GrpcActiveHealthCheckSession::decodeHeaders( Http::ResponseHeaderMapPtr&& headers, bool end_stream) {
  const auto http_response_status = Http::Utility::getResponseStatus(*headers);
  if (http_response_status != enumToInt(Http::Code::OK)) {
    
    
    if (end_stream) {
      const auto grpc_status = Grpc::Common::getGrpcStatus(*headers);
      if (grpc_status) {
        onRpcComplete(grpc_status.value(), Grpc::Common::getGrpcMessage(*headers), true);
        return;
      }
    }
    onRpcComplete(Grpc::Utility::httpToGrpcStatus(http_response_status), "non-200 HTTP response", end_stream);
    return;
  }
  if (!Grpc::Common::isGrpcResponseHeaders(*headers, end_stream)) {
    onRpcComplete(Grpc::Status::WellKnownGrpcStatus::Internal, "not a gRPC request", false);
    return;
  }
  if (end_stream) {
    
    
    const auto grpc_status = Grpc::Common::getGrpcStatus(*headers);
    if (grpc_status) {
      onRpcComplete(grpc_status.value(), Grpc::Common::getGrpcMessage(*headers), true);
      return;
    }
    onRpcComplete(Grpc::Status::WellKnownGrpcStatus::Internal, "gRPC protocol violation: unexpected stream end", true);
  }
}

void GrpcHealthCheckerImpl::GrpcActiveHealthCheckSession::decodeData(Buffer::Instance& data, bool end_stream) {
  if (end_stream) {
    onRpcComplete(Grpc::Status::WellKnownGrpcStatus::Internal, "gRPC protocol violation: unexpected stream end", true);
    return;
  }
  
  std::vector<Grpc::Frame> decoded_frames;
  if (!decoder_.decode(data, decoded_frames)) {
    onRpcComplete(Grpc::Status::WellKnownGrpcStatus::Internal, "gRPC wire protocol decode error", false);
    return;
  }
  for (auto& frame : decoded_frames) {
    if (frame.length_ > 0) {
      if (health_check_response_) {
        
        onRpcComplete(Grpc::Status::WellKnownGrpcStatus::Internal, "unexpected streaming", false);
        return;
      }
      health_check_response_ = std::make_unique<grpc::health::v1::HealthCheckResponse>();
      Buffer::ZeroCopyInputStreamImpl stream(std::move(frame.data_));

      if (frame.flags_ != Grpc::GRPC_FH_DEFAULT || !health_check_response_->ParseFromZeroCopyStream(&stream)) {
        onRpcComplete(Grpc::Status::WellKnownGrpcStatus::Internal, "invalid grpc.health.v1 RPC payload", false);
        return;
      }
    }
  }
}

void GrpcHealthCheckerImpl::GrpcActiveHealthCheckSession::decodeTrailers( Http::ResponseTrailerMapPtr&& trailers) {
  auto maybe_grpc_status = Grpc::Common::getGrpcStatus(*trailers);
  auto grpc_status = maybe_grpc_status ? maybe_grpc_status.value()

          : static_cast<Grpc::Status::GrpcStatus>(Grpc::Status::WellKnownGrpcStatus::Internal);
  const std::string grpc_message = maybe_grpc_status ? Grpc::Common::getGrpcMessage(*trailers) : "invalid gRPC status";
  onRpcComplete(grpc_status, grpc_message, true);
}

void GrpcHealthCheckerImpl::GrpcActiveHealthCheckSession::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::RemoteClose || event == Network::ConnectionEvent::LocalClose) {
    
    
    
    parent_.dispatcher_.deferredDelete(std::move(client_));
  }
}

void GrpcHealthCheckerImpl::GrpcActiveHealthCheckSession::onInterval() {
  if (!client_) {
    Upstream::Host::CreateConnectionData conn = host_->createHealthCheckConnection(parent_.dispatcher_, parent_.transportSocketOptions(), parent_.transportSocketMatchMetadata().get());

    client_ = parent_.createCodecClient(conn);
    client_->addConnectionCallbacks(connection_callback_impl_);
    client_->setCodecConnectionCallbacks(http_connection_callback_impl_);
  }

  request_encoder_ = &client_->newStream(*this);
  request_encoder_->getStream().addCallbacks(*this);

  const std::string& authority = getHostname(host_, parent_.authority_value_, parent_.cluster_.info());
  auto headers_message = Grpc::Common::prepareHeaders(authority, parent_.service_method_.service()->full_name(), parent_.service_method_.name(), absl::nullopt);

  headers_message->headers().setReferenceUserAgent( Http::Headers::get().UserAgentValues.EnvoyHealthChecker);

  StreamInfo::StreamInfoImpl stream_info(Http::Protocol::Http2, parent_.dispatcher_.timeSource(), local_connection_info_provider_);
  stream_info.setUpstreamInfo(std::make_shared<StreamInfo::UpstreamInfoImpl>());
  stream_info.upstreamInfo()->setUpstreamHost(host_);
  parent_.request_headers_parser_->evaluateHeaders(headers_message->headers(), stream_info);

  Grpc::Common::toGrpcTimeout(parent_.timeout_, headers_message->headers());

  Router::FilterUtility::setUpstreamScheme( headers_message->headers(),   host_->transportSocketFactory().implementsSecureTransport());




  auto status = request_encoder_->encodeHeaders(headers_message->headers(), false);
  
  ASSERT(status.ok());

  grpc::health::v1::HealthCheckRequest request;
  if (parent_.service_name_.has_value()) {
    request.set_service(parent_.service_name_.value());
  }

  request_encoder_->encodeData(*Grpc::Common::serializeToGrpcFrame(request), true);
}

void GrpcHealthCheckerImpl::GrpcActiveHealthCheckSession::onResetStream(Http::StreamResetReason, absl::string_view) {
  const bool expected_reset = expect_reset_;
  const bool goaway = received_no_error_goaway_;
  resetState();

  if (expected_reset) {
    
    
    
    return;
  }

  ENVOY_CONN_LOG(debug, "connection/stream error health_flags={}", *client_, HostUtility::healthFlagsToString(*host_));

  if (goaway || !parent_.reuse_connection_) {
    
    
    client_->close();
  }

  
  
  
  
  
  handleFailure(envoy::data::core::v3::NETWORK);
}

void GrpcHealthCheckerImpl::GrpcActiveHealthCheckSession::onGoAway( Http::GoAwayErrorCode error_code) {
  ENVOY_CONN_LOG(debug, "connection going away health_flags={}", *client_, HostUtility::healthFlagsToString(*host_));
  
  
  
  
  if (request_encoder_ && error_code == Http::GoAwayErrorCode::NoError) {
    received_no_error_goaway_ = true;
    return;
  }

  
  if (request_encoder_) {
    handleFailure(envoy::data::core::v3::NETWORK);
    expect_reset_ = true;
    request_encoder_->getStream().resetStream(Http::StreamResetReason::LocalReset);
  }
  client_->close();
}

bool GrpcHealthCheckerImpl::GrpcActiveHealthCheckSession::isHealthCheckSucceeded( Grpc::Status::GrpcStatus grpc_status) const {
  if (grpc_status != Grpc::Status::WellKnownGrpcStatus::Ok) {
    return false;
  }

  if (!health_check_response_ || health_check_response_->status() != grpc::health::v1::HealthCheckResponse::SERVING) {
    return false;
  }

  return true;
}

void GrpcHealthCheckerImpl::GrpcActiveHealthCheckSession::onRpcComplete( Grpc::Status::GrpcStatus grpc_status, const std::string& grpc_message, bool end_stream) {
  logHealthCheckStatus(grpc_status, grpc_message);
  if (isHealthCheckSucceeded(grpc_status)) {
    handleSuccess(false);
  } else {
    handleFailure(envoy::data::core::v3::ACTIVE);
  }

  
  const bool goaway = received_no_error_goaway_;

  
  
  if (end_stream) {
    resetState();
  } else {
    
    expect_reset_ = true;
    request_encoder_->getStream().resetStream(Http::StreamResetReason::LocalReset);
  }

  if (!parent_.reuse_connection_ || goaway) {
    client_->close();
  }
}

void GrpcHealthCheckerImpl::GrpcActiveHealthCheckSession::resetState() {
  expect_reset_ = false;
  request_encoder_ = nullptr;
  decoder_ = Grpc::Decoder();
  health_check_response_.reset();
  received_no_error_goaway_ = false;
}

void GrpcHealthCheckerImpl::GrpcActiveHealthCheckSession::onTimeout() {
  ENVOY_CONN_LOG(debug, "connection/stream timeout health_flags={}", *client_, HostUtility::healthFlagsToString(*host_));
  expect_reset_ = true;
  if (received_no_error_goaway_ || !parent_.reuse_connection_) {
    client_->close();
  } else {
    request_encoder_->getStream().resetStream(Http::StreamResetReason::LocalReset);
  }
}

void GrpcHealthCheckerImpl::GrpcActiveHealthCheckSession::logHealthCheckStatus( Grpc::Status::GrpcStatus grpc_status, const std::string& grpc_message) {
  const char* service_status;
  if (!health_check_response_) {
    service_status = "rpc_error";
  } else {
    switch (health_check_response_->status()) {
    case grpc::health::v1::HealthCheckResponse::SERVING:
      service_status = "serving";
      break;
    case grpc::health::v1::HealthCheckResponse::NOT_SERVING:
      service_status = "not_serving";
      break;
    case grpc::health::v1::HealthCheckResponse::UNKNOWN:
      service_status = "unknown";
      break;
    case grpc::health::v1::HealthCheckResponse::SERVICE_UNKNOWN:
      service_status = "service_unknown";
      break;
    default:
      service_status = "unknown_healthcheck_response";
      break;
    }
  }
  std::string grpc_status_message;
  if (grpc_status != Grpc::Status::WellKnownGrpcStatus::Ok && !grpc_message.empty()) {
    grpc_status_message = fmt::format("{} ({})", grpc_status, grpc_message);
  } else {
    grpc_status_message = absl::StrCat("", grpc_status);
  }

  ENVOY_CONN_LOG(debug, "hc grpc_status={} service_status={} health_flags={}", *client_, grpc_status_message, service_status, HostUtility::healthFlagsToString(*host_));
}

Http::CodecClientPtr ProdGrpcHealthCheckerImpl::createCodecClient(Upstream::Host::CreateConnectionData& data) {
  return std::make_unique<Http::CodecClientProd>( Http::CodecType::HTTP2, std::move(data.connection_), data.host_description_, dispatcher_, random_generator_);

}

std::ostream& operator<<(std::ostream& out, HealthState state) {
  switch (state) {
  case HealthState::Unhealthy:
    out << "Unhealthy";
    break;
  case HealthState::Healthy:
    out << "Healthy";
    break;
  }
  return out;
}

std::ostream& operator<<(std::ostream& out, HealthTransition changed_state) {
  switch (changed_state) {
  case HealthTransition::Unchanged:
    out << "Unchanged";
    break;
  case HealthTransition::Changed:
    out << "Changed";
    break;
  case HealthTransition::ChangePending:
    out << "ChangePending";
    break;
  }
  return out;
}

} 
} 
