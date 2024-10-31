




























namespace Envoy {
namespace Http {
namespace Http1 {
namespace {



struct Http1ResponseCodeDetailValues {
  const absl::string_view TooManyHeaders = "http1.too_many_headers";
  const absl::string_view HeadersTooLarge = "http1.headers_too_large";
  const absl::string_view HttpCodecError = "http1.codec_error";
  const absl::string_view InvalidCharacters = "http1.invalid_characters";
  const absl::string_view ConnectionHeaderSanitization = "http1.connection_header_rejected";
  const absl::string_view InvalidUrl = "http1.invalid_url";
  const absl::string_view InvalidTransferEncoding = "http1.invalid_transfer_encoding";
  const absl::string_view BodyDisallowed = "http1.body_disallowed";
  const absl::string_view TransferEncodingNotAllowed = "http1.transfer_encoding_not_allowed";
  const absl::string_view ContentLengthNotAllowed = "http1.content_length_not_allowed";
  const absl::string_view InvalidUnderscore = "http1.unexpected_underscore";
  const absl::string_view ChunkedContentLength = "http1.content_length_and_chunked_not_allowed";
  const absl::string_view HttpsInPlaintext = "http1.https_url_on_plaintext_connection";
  const absl::string_view InvalidScheme = "http1.invalid_scheme";
};

struct Http1HeaderTypesValues {
  const absl::string_view Headers = "headers";
  const absl::string_view Trailers = "trailers";
};



static constexpr uint32_t kMaxOutboundResponses = 2;

using Http1ResponseCodeDetails = ConstSingleton<Http1ResponseCodeDetailValues>;
using Http1HeaderTypes = ConstSingleton<Http1HeaderTypesValues>;

const StringUtil::CaseUnorderedSet& caseUnorderdSetContainingUpgradeAndHttp2Settings() {
  CONSTRUCT_ON_FIRST_USE(StringUtil::CaseUnorderedSet, Http::Headers::get().ConnectionValues.Upgrade, Http::Headers::get().ConnectionValues.Http2Settings);

}

HeaderKeyFormatterConstPtr encodeOnlyFormatterFromSettings(const Http::Http1Settings& settings) {
  if (settings.header_key_format_ == Http1Settings::HeaderKeyFormat::ProperCase) {
    return std::make_unique<ProperCaseHeaderKeyFormatter>();
  }

  return nullptr;
}

StatefulHeaderKeyFormatterPtr statefulFormatterFromSettings(const Http::Http1Settings& settings) {
  if (settings.header_key_format_ == Http1Settings::HeaderKeyFormat::StatefulFormatter) {
    return settings.stateful_header_key_formatter_->create();
  }
  return nullptr;
}

constexpr size_t CRLF_SIZE = 2;

} 

static constexpr absl::string_view CRLF = "\r\n";

static constexpr absl::string_view LAST_CHUNK = "0\r\n";

static constexpr absl::string_view SPACE = " ";
static constexpr absl::string_view COLON_SPACE = ": ";

StreamEncoderImpl::StreamEncoderImpl(ConnectionImpl& connection, StreamInfo::BytesMeterSharedPtr&& bytes_meter)
    : connection_(connection), disable_chunk_encoding_(false), chunk_encoding_(true), connect_request_(false), is_tcp_tunneling_(false), is_response_to_head_request_(false), is_response_to_connect_request_(false), bytes_meter_(std::move(bytes_meter)) {

  if (!bytes_meter_) {
    bytes_meter_ = std::make_shared<StreamInfo::BytesMeter>();
  }
  if (connection_.connection().aboveHighWatermark()) {
    runHighWatermarkCallbacks();
  }
}

void StreamEncoderImpl::encodeHeader(absl::string_view key, absl::string_view value) {
  ASSERT(!key.empty());

  const uint64_t header_size = connection_.buffer().addFragments({key, COLON_SPACE, value, CRLF});

  bytes_meter_->addHeaderBytesSent(header_size);
}

void StreamEncoderImpl::encodeFormattedHeader(absl::string_view key, absl::string_view value, HeaderKeyFormatterOptConstRef formatter) {
  if (formatter.has_value()) {
    encodeHeader(formatter->format(key), value);
  } else {
    encodeHeader(key, value);
  }
}

void ResponseEncoderImpl::encode1xxHeaders(const ResponseHeaderMap& headers) {
  ASSERT(HeaderUtility::isSpecial1xx(headers));
  encodeHeaders(headers, false);
}

void StreamEncoderImpl::encodeHeadersBase(const RequestOrResponseHeaderMap& headers, absl::optional<uint64_t> status, bool end_stream, bool bodiless_request) {

  HeaderKeyFormatterOptConstRef formatter(headers.formatter());
  if (!formatter.has_value()) {
    formatter = connection_.formatter();
  }

  const Http::HeaderValues& header_values = Http::Headers::get();
  bool saw_content_length = false;
  headers.iterate( [this, &header_values, formatter](const HeaderEntry& header) -> HeaderMap::Iterate {
        absl::string_view key_to_use = header.key().getStringView();
        uint32_t key_size_to_use = header.key().size();
        
        if (key_size_to_use > 1 && key_to_use[0] == ':' && key_to_use[1] == 'a') {
          key_to_use = absl::string_view(header_values.HostLegacy.get());
          key_size_to_use = header_values.HostLegacy.get().size();
        }

        
        if (key_to_use[0] == ':') {
          return HeaderMap::Iterate::Continue;
        }

        encodeFormattedHeader(key_to_use, header.value().getStringView(), formatter);

        return HeaderMap::Iterate::Continue;
      });

  if (headers.ContentLength()) {
    saw_content_length = true;
  }

  ASSERT(!headers.TransferEncoding());

  
  
  
  
  
  
  
  
  
  
  
  if (saw_content_length || disable_chunk_encoding_) {
    chunk_encoding_ = false;
  } else {
    if (status && (*status < 200 || *status == 204)) {
      
      
      chunk_encoding_ = false;
    } else if (status && *status == 304) {
      
      
      chunk_encoding_ = false;
    } else if (end_stream && !is_response_to_head_request_) {
      
      
      
      
      
      
      if (!status || (*status >= 200 && *status != 204)) {
        if (!bodiless_request) {
          encodeFormattedHeader(header_values.ContentLength.get(), "0", formatter);
        }
      }
      chunk_encoding_ = false;
    } else if (connection_.protocol() == Protocol::Http10) {
      chunk_encoding_ = false;
    } else {
      
      
      if (!is_response_to_connect_request_) {
        encodeFormattedHeader(header_values.TransferEncoding.get(), header_values.TransferEncodingValues.Chunked, formatter);
      }
      
      
      
      
      
      
      
      chunk_encoding_ = !Utility::isUpgrade(headers) && !is_response_to_head_request_ && !is_response_to_connect_request_;
    }
  }

  connection_.buffer().add(CRLF);

  if (end_stream) {
    endEncode();
  } else {
    flushOutput();
  }
}

void StreamEncoderImpl::encodeData(Buffer::Instance& data, bool end_stream) {
  
  
  if (data.length() > 0) {
    if (chunk_encoding_) {
      std::string chunk_header = absl::StrCat(absl::Hex(data.length()), CRLF);
      connection_.buffer().add(std::move(chunk_header));
    }

    connection_.buffer().move(data);

    if (chunk_encoding_) {
      connection_.buffer().add(CRLF);
    }
  }

  if (end_stream) {
    endEncode();
  } else {
    flushOutput();
  }
}

void StreamEncoderImpl::flushOutput(bool end_encode) {
  auto encoded_bytes = connection_.flushOutput(end_encode);
  bytes_meter_->addWireBytesSent(encoded_bytes);
}

void StreamEncoderImpl::encodeTrailersBase(const HeaderMap& trailers) {
  if (!connection_.enableTrailers()) {
    return endEncode();
  }
  
  
  if (chunk_encoding_) {
    
    connection_.buffer().add(LAST_CHUNK);

    
    trailers.iterate([this](const HeaderEntry& header) -> HeaderMap::Iterate {
      encodeFormattedHeader(header.key().getStringView(), header.value().getStringView(), HeaderKeyFormatterOptConstRef());
      return HeaderMap::Iterate::Continue;
    });

    connection_.buffer().add(CRLF);
  }

  flushOutput();
  connection_.onEncodeComplete();
}

void StreamEncoderImpl::encodeMetadata(const MetadataMapVector&) {
  connection_.stats().metadata_not_supported_error_.inc();
}

void StreamEncoderImpl::endEncode() {
  if (chunk_encoding_) {
    connection_.buffer().addFragments({LAST_CHUNK, CRLF});
  }

  flushOutput(true);
  connection_.onEncodeComplete();
  
  if (connect_request_ || is_tcp_tunneling_) {
    connection_.connection().close(Network::ConnectionCloseType::FlushWriteAndDelay);
  }
}

void ServerConnectionImpl::maybeAddSentinelBufferFragment(Buffer::Instance& output_buffer) {
  
  
  
  
  
  auto fragment = Buffer::OwnedBufferFragmentImpl::create(absl::string_view("", 0), response_buffer_releasor_);
  output_buffer.addBufferFragment(*fragment.release());
  ASSERT(outbound_responses_ < kMaxOutboundResponses);
  outbound_responses_++;
}

Status ServerConnectionImpl::doFloodProtectionChecks() const {
  ASSERT(dispatching_);
  
  
  if (outbound_responses_ >= kMaxOutboundResponses) {
    ENVOY_CONN_LOG(trace, "error accepting request: too many pending responses queued", connection_);
    stats_.response_flood_.inc();
    return bufferFloodError("Too many responses queued.");
  }
  return okStatus();
}

uint64_t ConnectionImpl::flushOutput(bool end_encode) {
  if (end_encode) {
    
    
    maybeAddSentinelBufferFragment(*output_buffer_);
  }
  const uint64_t bytes_encoded = output_buffer_->length();
  connection().write(*output_buffer_, false);
  ASSERT(0UL == output_buffer_->length());
  return bytes_encoded;
}

void StreamEncoderImpl::resetStream(StreamResetReason reason) {
  connection_.onResetStreamBase(reason);
}

void ResponseEncoderImpl::resetStream(StreamResetReason reason) {
  
  if (buffer_memory_account_) {
    buffer_memory_account_->clearDownstream();
  }

  
  
  
  
  
  
  StreamEncoderImpl::resetStream(reason);
}

void StreamEncoderImpl::readDisable(bool disable) {
  if (disable) {
    ++read_disable_calls_;
  } else {
    ASSERT(read_disable_calls_ != 0);
    if (read_disable_calls_ != 0) {
      --read_disable_calls_;
    }
  }
  connection_.readDisable(disable);
}

uint32_t StreamEncoderImpl::bufferLimit() const { return connection_.bufferLimit(); }

const Network::Address::InstanceConstSharedPtr& StreamEncoderImpl::connectionLocalAddress() {
  return connection_.connection().connectionInfoProvider().localAddress();
}

static constexpr absl::string_view RESPONSE_PREFIX = "HTTP/1.1 ";
static constexpr absl::string_view HTTP_10_RESPONSE_PREFIX = "HTTP/1.0 ";

void ResponseEncoderImpl::encodeHeaders(const ResponseHeaderMap& headers, bool end_stream) {
  started_response_ = true;

  
  ASSERT(headers.Status() != nullptr);
  uint64_t numeric_status = Utility::getResponseStatus(headers);

  absl::string_view response_prefix;
  if (connection_.protocol() == Protocol::Http10 && connection_.supportsHttp10()) {
    response_prefix = HTTP_10_RESPONSE_PREFIX;
  } else {
    response_prefix = RESPONSE_PREFIX;
  }

  StatefulHeaderKeyFormatterOptConstRef formatter(headers.formatter());

  absl::string_view reason_phrase;
  if (formatter.has_value() && !formatter->getReasonPhrase().empty()) {
    reason_phrase = formatter->getReasonPhrase();
  } else {
    const char* status_string = CodeUtility::toString(static_cast<Code>(numeric_status));
    uint32_t status_string_len = strlen(status_string);
    reason_phrase = {status_string, status_string_len};
  }

  connection_.buffer().addFragments( {response_prefix, absl::StrCat(numeric_status), SPACE, reason_phrase, CRLF});

  if (numeric_status >= 300) {
    
    is_response_to_connect_request_ = false;
  }

  encodeHeadersBase(headers, absl::make_optional<uint64_t>(numeric_status), end_stream, false);
}

static constexpr absl::string_view REQUEST_POSTFIX = " HTTP/1.1\r\n";

Status RequestEncoderImpl::encodeHeaders(const RequestHeaderMap& headers, bool end_stream) {
  
  
  RETURN_IF_ERROR(HeaderUtility::checkRequiredRequestHeaders(headers));

  const HeaderEntry* method = headers.Method();
  const HeaderEntry* path = headers.Path();
  const HeaderEntry* host = headers.Host();
  bool is_connect = HeaderUtility::isConnect(headers);
  const Http::HeaderValues& header_values = Http::Headers::get();

  if (method->value() == header_values.MethodValues.Head) {
    head_request_ = true;
  } else if (method->value() == header_values.MethodValues.Connect) {
    disableChunkEncoding();
    connection_.connection().enableHalfClose(true);
    connect_request_ = true;
  }
  if (Utility::isUpgrade(headers)) {
    upgrade_request_ = true;
  }

  absl::string_view host_or_path_view;
  if (is_connect) {
    host_or_path_view = host->value().getStringView();
  } else {
    host_or_path_view = path->value().getStringView();
  }

  connection_.buffer().addFragments( {method->value().getStringView(), SPACE, host_or_path_view, REQUEST_POSTFIX});

  encodeHeadersBase(headers, absl::nullopt, end_stream, HeaderUtility::requestShouldHaveNoBody(headers));
  return okStatus();
}

int ConnectionImpl::setAndCheckCallbackStatus(Status&& status) {
  ASSERT(codec_status_.ok());
  codec_status_ = std::move(status);
  return codec_status_.ok() ? parser_->statusToInt(ParserStatus::Success)
                            : parser_->statusToInt(ParserStatus::Error);
}

int ConnectionImpl::setAndCheckCallbackStatusOr(Envoy::StatusOr<ParserStatus>&& statusor) {
  ASSERT(codec_status_.ok());
  if (statusor.ok()) {
    return parser_->statusToInt(statusor.value());
  } else {
    codec_status_ = std::move(statusor.status());
    return parser_->statusToInt(ParserStatus::Error);
  }
}

ConnectionImpl::ConnectionImpl(Network::Connection& connection, CodecStats& stats, const Http1Settings& settings, MessageType type, uint32_t max_headers_kb, const uint32_t max_headers_count)

    : connection_(connection), stats_(stats), codec_settings_(settings), encode_only_header_key_formatter_(encodeOnlyFormatterFromSettings(settings)), processing_trailers_(false), handling_upgrade_(false), reset_stream_called_(false), deferred_end_stream_headers_(false), dispatching_(false), output_buffer_(connection.dispatcher().getWatermarkFactory().createBuffer( [&]() -> void { this->onBelowLowWatermark(); }, [&]() -> void { this->onAboveHighWatermark(); }, []() -> void {  })), max_headers_kb_(max_headers_kb), max_headers_count_(max_headers_count) {







  output_buffer_->setWatermarks(connection.bufferLimit());
  parser_ = std::make_unique<LegacyHttpParserImpl>(type, this);
}

Status ConnectionImpl::completeLastHeader() {
  ASSERT(dispatching_);
  ENVOY_CONN_LOG(trace, "completed header: key={} value={}", connection_, current_header_field_.getStringView(), current_header_value_.getStringView());
  auto& headers_or_trailers = headersOrTrailers();

  
  getBytesMeter().addHeaderBytesReceived(CRLF_SIZE + 1);

  
  RETURN_IF_ERROR(checkHeaderNameForUnderscores());
  if (!current_header_field_.empty()) {
    
    
    
    current_header_value_.rtrim();

    
    
    auto formatter = headers_or_trailers.formatter();
    if (formatter.has_value()) {
      formatter->processKey(current_header_field_.getStringView());
    }
    current_header_field_.inlineTransform([](char c) { return absl::ascii_tolower(c); });

    headers_or_trailers.addViaMove(std::move(current_header_field_), std::move(current_header_value_));
  }

  
  if (headers_or_trailers.size() > max_headers_count_) {
    error_code_ = Http::Code::RequestHeaderFieldsTooLarge;
    RETURN_IF_ERROR(sendProtocolError(Http1ResponseCodeDetails::get().TooManyHeaders));
    const absl::string_view header_type = processing_trailers_ ? Http1HeaderTypes::get().Trailers : Http1HeaderTypes::get().Headers;
    return codecProtocolError(absl::StrCat(header_type, " count exceeds limit"));
  }

  header_parsing_state_ = HeaderParsingState::Field;
  ASSERT(current_header_field_.empty());
  ASSERT(current_header_value_.empty());
  return okStatus();
}

uint32_t ConnectionImpl::getHeadersSize() {
  return current_header_field_.size() + current_header_value_.size() + headersOrTrailers().byteSize();
}

Status ConnectionImpl::checkMaxHeadersSize() {
  const uint32_t total = getHeadersSize();
  if (total > (max_headers_kb_ * 1024)) {
    const absl::string_view header_type = processing_trailers_ ? Http1HeaderTypes::get().Trailers : Http1HeaderTypes::get().Headers;
    error_code_ = Http::Code::RequestHeaderFieldsTooLarge;
    RETURN_IF_ERROR(sendProtocolError(Http1ResponseCodeDetails::get().HeadersTooLarge));
    return codecProtocolError(absl::StrCat(header_type, " size exceeds limit"));
  }
  return okStatus();
}

bool ConnectionImpl::maybeDirectDispatch(Buffer::Instance& data) {
  if (!handling_upgrade_) {
    
    return false;
  }

  ENVOY_CONN_LOG(trace, "direct-dispatched {} bytes", connection_, data.length());
  onBody(data);
  data.drain(data.length());
  return true;
}

void ConnectionImpl::onDispatch(const Buffer::Instance& data) {
  getBytesMeter().addWireBytesReceived(data.length());
}

Http::Status ClientConnectionImpl::dispatch(Buffer::Instance& data) {
  Http::Status status = ConnectionImpl::dispatch(data);
  if (status.ok() && data.length() > 0) {
    
    
    return codecProtocolError("http/1.1 protocol error: extraneous data after response complete");
  }
  return status;
}

Http::Status ConnectionImpl::dispatch(Buffer::Instance& data) {
  
  ScopeTrackerScopeState scope(this, connection_.dispatcher());
  ENVOY_CONN_LOG(trace, "parsing {} bytes", connection_, data.length());
  
  
  Cleanup cleanup([this]() { dispatching_ = false; });
  ASSERT(!dispatching_);
  ASSERT(codec_status_.ok());
  ASSERT(buffered_body_.length() == 0);

  dispatching_ = true;
  onDispatch(data);
  if (maybeDirectDispatch(data)) {
    return Http::okStatus();
  }

  
  parser_->resume();

  ssize_t total_parsed = 0;
  if (data.length() > 0) {
    current_dispatching_buffer_ = &data;
    while (data.length() > 0) {
      auto slice = data.frontSlice();
      dispatching_slice_already_drained_ = false;
      auto statusor_parsed = dispatchSlice(static_cast<const char*>(slice.mem_), slice.len_);
      if (!statusor_parsed.ok()) {
        return statusor_parsed.status();
      }
      if (!dispatching_slice_already_drained_) {
        ASSERT(statusor_parsed.value() <= slice.len_);
        data.drain(statusor_parsed.value());
      }

      total_parsed += statusor_parsed.value();
      if (parser_->getStatus() != ParserStatus::Success) {
        
        
        ASSERT(parser_->getStatus() == ParserStatus::Paused);
        break;
      }
    }
    current_dispatching_buffer_ = nullptr;
    dispatchBufferedBody();
  } else {
    auto result = dispatchSlice(nullptr, 0);
    if (!result.ok()) {
      return result.status();
    }
  }
  ASSERT(buffered_body_.length() == 0);

  ENVOY_CONN_LOG(trace, "parsed {} bytes", connection_, total_parsed);

  
  
  maybeDirectDispatch(data);
  return Http::okStatus();
}

Envoy::StatusOr<size_t> ConnectionImpl::dispatchSlice(const char* slice, size_t len) {
  ASSERT(codec_status_.ok() && dispatching_);
  auto [nread, rc] = parser_->execute(slice, len);
  if (!codec_status_.ok()) {
    return codec_status_;
  }

  if (rc != parser_->statusToInt(ParserStatus::Success) && rc != parser_->statusToInt(ParserStatus::Paused)) {
    RETURN_IF_ERROR(sendProtocolError(Http1ResponseCodeDetails::get().HttpCodecError));
    
    ASSERT(codec_status_.ok());
    codec_status_ = codecProtocolError(absl::StrCat("http/1.1 protocol error: ", parser_->errnoName(rc)));
    return codec_status_;
  }

  return nread;
}

Status ConnectionImpl::onHeaderField(const char* data, size_t length) {
  ASSERT(dispatching_);

  getBytesMeter().addHeaderBytesReceived(length);

  
  
  if (header_parsing_state_ == HeaderParsingState::Done) {
    if (!enableTrailers()) {
      
      return okStatus();
    }
    processing_trailers_ = true;
    header_parsing_state_ = HeaderParsingState::Field;
    allocTrailers();
  }
  if (header_parsing_state_ == HeaderParsingState::Value) {
    RETURN_IF_ERROR(completeLastHeader());
  }

  current_header_field_.append(data, length);

  return checkMaxHeadersSize();
}

Status ConnectionImpl::onHeaderValue(const char* data, size_t length) {
  ASSERT(dispatching_);

  getBytesMeter().addHeaderBytesReceived(length);

  if (header_parsing_state_ == HeaderParsingState::Done && !enableTrailers()) {
    
    return okStatus();
  }

  absl::string_view header_value{data, length};
  if (!Http::HeaderUtility::headerValueIsValid(header_value)) {
    ENVOY_CONN_LOG(debug, "invalid header value: {}", connection_, header_value);
    error_code_ = Http::Code::BadRequest;
    RETURN_IF_ERROR(sendProtocolError(Http1ResponseCodeDetails::get().InvalidCharacters));
    return codecProtocolError("http/1.1 protocol error: header value contains invalid chars");
  }

  header_parsing_state_ = HeaderParsingState::Value;
  if (current_header_value_.empty()) {
    
    
    
    
    header_value = StringUtil::ltrim(header_value);
  }
  current_header_value_.append(header_value.data(), header_value.length());

  return checkMaxHeadersSize();
}

StatusOr<ParserStatus> ConnectionImpl::onHeadersComplete() {
  ASSERT(!processing_trailers_);
  ASSERT(dispatching_);
  ENVOY_CONN_LOG(trace, "onHeadersCompleteBase", connection_);
  RETURN_IF_ERROR(completeLastHeader());

  if (!(parser_->httpMajor() == 1 && parser_->httpMinor() == 1)) {
    
    
    protocol_ = Protocol::Http10;
  }
  RequestOrResponseHeaderMap& request_or_response_headers = requestOrResponseHeaders();
  const Http::HeaderValues& header_values = Http::Headers::get();
  if (Utility::isUpgrade(request_or_response_headers) && upgradeAllowed()) {
    
    
    if (absl::EqualsIgnoreCase(request_or_response_headers.getUpgradeValue(), header_values.UpgradeValues.H2c)) {
      ENVOY_CONN_LOG(trace, "removing unsupported h2c upgrade headers.", connection_);
      request_or_response_headers.removeUpgrade();
      if (request_or_response_headers.Connection()) {
        const auto& tokens_to_remove = caseUnorderdSetContainingUpgradeAndHttp2Settings();
        std::string new_value = StringUtil::removeTokens( request_or_response_headers.getConnectionValue(), ",", tokens_to_remove, ",");
        if (new_value.empty()) {
          request_or_response_headers.removeConnection();
        } else {
          request_or_response_headers.setConnection(new_value);
        }
      }
      request_or_response_headers.remove(header_values.Http2Settings);
    } else {
      ENVOY_CONN_LOG(trace, "codec entering upgrade mode.", connection_);
      handling_upgrade_ = true;
    }
  }
  if (parser_->methodName() == header_values.MethodValues.Connect) {
    if (request_or_response_headers.ContentLength()) {
      if (request_or_response_headers.getContentLengthValue() == "0") {
        request_or_response_headers.removeContentLength();
      } else {
        
        
        error_code_ = Http::Code::BadRequest;
        RETURN_IF_ERROR(sendProtocolError(Http1ResponseCodeDetails::get().BodyDisallowed));
        return codecProtocolError("http/1.1 protocol error: unsupported content length");
      }
    }
    ENVOY_CONN_LOG(trace, "codec entering upgrade mode for CONNECT request.", connection_);
    handling_upgrade_ = true;
  }

  
  
  
  
  
  
  
  

  
  
  
  if (parser_->hasTransferEncoding() != 0 && request_or_response_headers.ContentLength()) {
    if (parser_->isChunked() && codec_settings_.allow_chunked_length_) {
      request_or_response_headers.removeContentLength();
    } else {
      error_code_ = Http::Code::BadRequest;
      RETURN_IF_ERROR(sendProtocolError(Http1ResponseCodeDetails::get().ChunkedContentLength));
      return codecProtocolError( "http/1.1 protocol error: both 'Content-Length' and 'Transfer-Encoding' are set.");
    }
  }

  
  
  
  
  if (request_or_response_headers.TransferEncoding()) {
    const absl::string_view encoding = request_or_response_headers.getTransferEncodingValue();
    if (!absl::EqualsIgnoreCase(encoding, header_values.TransferEncodingValues.Chunked) || parser_->methodName() == header_values.MethodValues.Connect) {
      error_code_ = Http::Code::NotImplemented;
      RETURN_IF_ERROR(sendProtocolError(Http1ResponseCodeDetails::get().InvalidTransferEncoding));
      return codecProtocolError("http/1.1 protocol error: unsupported transfer encoding");
    }
  }

  auto statusor = onHeadersCompleteBase();
  if (!statusor.ok()) {
    RETURN_IF_ERROR(statusor.status());
  }

  header_parsing_state_ = HeaderParsingState::Done;

  
  
  return handling_upgrade_ ? ParserStatus::NoBodyData : statusor.value();
}

void ConnectionImpl::bufferBody(const char* data, size_t length) {
  auto slice = current_dispatching_buffer_->frontSlice();
  if (data == slice.mem_ && length == slice.len_) {
    buffered_body_.move(*current_dispatching_buffer_, length);
    dispatching_slice_already_drained_ = true;
  } else {
    buffered_body_.add(data, length);
  }
}

void ConnectionImpl::dispatchBufferedBody() {
  ASSERT(parser_->getStatus() == ParserStatus::Success || parser_->getStatus() == ParserStatus::Paused);
  ASSERT(codec_status_.ok());
  if (buffered_body_.length() > 0) {
    onBody(buffered_body_);
    buffered_body_.drain(buffered_body_.length());
  }
}

void ConnectionImpl::onChunkHeader(bool is_final_chunk) {
  if (is_final_chunk) {
    
    
    dispatchBufferedBody();
  }
}

StatusOr<ParserStatus> ConnectionImpl::onMessageComplete() {
  ENVOY_CONN_LOG(trace, "message complete", connection_);

  dispatchBufferedBody();

  if (handling_upgrade_) {
    
    
    ASSERT(!deferred_end_stream_headers_);
    ENVOY_CONN_LOG(trace, "Pausing parser due to upgrade.", connection_);
    return parser_->pause();
  }

  
  
  if (header_parsing_state_ == HeaderParsingState::Value) {
    RETURN_IF_ERROR(completeLastHeader());
  }

  return onMessageCompleteBase();
}

Status ConnectionImpl::onMessageBegin() {
  ENVOY_CONN_LOG(trace, "message begin", connection_);
  
  
  
  protocol_ = Protocol::Http11;
  processing_trailers_ = false;
  header_parsing_state_ = HeaderParsingState::Field;
  allocHeaders(statefulFormatterFromSettings(codec_settings_));
  return onMessageBeginBase();
}

void ConnectionImpl::onResetStreamBase(StreamResetReason reason) {
  ASSERT(!reset_stream_called_);
  reset_stream_called_ = true;
  onResetStream(reason);
}

void ConnectionImpl::dumpState(std::ostream& os, int indent_level) const {
  const char* spaces = spacesForLevel(indent_level);
  os << spaces << "Http1::ConnectionImpl " << this << DUMP_MEMBER(dispatching_)
     << DUMP_MEMBER(dispatching_slice_already_drained_) << DUMP_MEMBER(reset_stream_called_)
     << DUMP_MEMBER(handling_upgrade_) << DUMP_MEMBER(deferred_end_stream_headers_)
     << DUMP_MEMBER(processing_trailers_) << DUMP_MEMBER(buffered_body_.length());

  
  os << DUMP_MEMBER(header_parsing_state_);
  os << DUMP_MEMBER_AS(current_header_field_, current_header_field_.getStringView());
  os << DUMP_MEMBER_AS(current_header_value_, current_header_value_.getStringView());

  
  os << '\n';
  dumpAdditionalState(os, indent_level);

  
  
  if (current_dispatching_buffer_ == nullptr || dispatching_slice_already_drained_) {
    
    
    os << DUMP_NULLABLE_MEMBER(current_dispatching_buffer_, "drained");
    return;
  } else {
    absl::string_view front_slice = [](Buffer::RawSlice slice) {
      return absl::string_view(static_cast<const char*>(slice.mem_), slice.len_);
    }(current_dispatching_buffer_->frontSlice());

    
    
    
    os << spaces << "current_dispatching_buffer_ front_slice length: " << front_slice.length()
       << " contents: \"";
    StringUtil::escapeToOstream(os, front_slice);
    os << "\"\n";
  }
}

void ServerConnectionImpl::dumpAdditionalState(std::ostream& os, int indent_level) const {
  const char* spaces = spacesForLevel(indent_level);

  DUMP_DETAILS(active_request_);
  os << '\n';

  
  
  if (absl::holds_alternative<RequestHeaderMapPtr>(headers_or_trailers_)) {
    DUMP_DETAILS(absl::get<RequestHeaderMapPtr>(headers_or_trailers_));
  } else {
    DUMP_DETAILS(absl::get<RequestTrailerMapPtr>(headers_or_trailers_));
  }
}

void ClientConnectionImpl::dumpAdditionalState(std::ostream& os, int indent_level) const {
  const char* spaces = spacesForLevel(indent_level);
  
  if (absl::holds_alternative<ResponseHeaderMapPtr>(headers_or_trailers_)) {
    DUMP_DETAILS(absl::get<ResponseHeaderMapPtr>(headers_or_trailers_));
  } else {
    DUMP_DETAILS(absl::get<ResponseTrailerMapPtr>(headers_or_trailers_));
  }

  
  os << spaces << "Dumping corresponding downstream request:";
  if (pending_response_.has_value()) {
    os << '\n';
    const ResponseDecoder* decoder = pending_response_.value().decoder_;
    DUMP_DETAILS(decoder);
  } else {
    os << " null\n";
  }
}

ServerConnectionImpl::ServerConnectionImpl( Network::Connection& connection, CodecStats& stats, ServerConnectionCallbacks& callbacks, const Http1Settings& settings, uint32_t max_request_headers_kb, const uint32_t max_request_headers_count, envoy::config::core::v3::HttpProtocolOptions::HeadersWithUnderscoresAction headers_with_underscores_action)




    : ConnectionImpl(connection, stats, settings, MessageType::Request, max_request_headers_kb, max_request_headers_count), callbacks_(callbacks), response_buffer_releasor_([this](const Buffer::OwnedBufferFragmentImpl* fragment) {


        releaseOutboundResponse(fragment);
      }), headers_with_underscores_action_(headers_with_underscores_action), runtime_lazy_read_disable_( Runtime::runtimeFeatureEnabled("envoy.reloadable_features.http1_lazy_read_disable")) {}



uint32_t ServerConnectionImpl::getHeadersSize() {
  
  const uint32_t url_size = (!processing_trailers_ && active_request_) ? active_request_->request_url_.size() : 0;
  return url_size + ConnectionImpl::getHeadersSize();
}

void ServerConnectionImpl::onEncodeComplete() {
  if (active_request_->remote_complete_) {
    
    
    
    connection_.dispatcher().deferredDelete(std::move(active_request_));
  }
}

Status ServerConnectionImpl::handlePath(RequestHeaderMap& headers, absl::string_view method) {
  const Http::HeaderValues& header_values = Http::Headers::get();
  HeaderString path(header_values.Path);

  bool is_connect = (method == header_values.MethodValues.Connect);

  
  if (!is_connect && !active_request_->request_url_.getStringView().empty() && (active_request_->request_url_.getStringView()[0] == '/' || (method == header_values.MethodValues.Options && active_request_->request_url_.getStringView()[0] == '*'))) {


    headers.addViaMove(std::move(path), std::move(active_request_->request_url_));
    return okStatus();
  }

  
  
  
  
  if (!codec_settings_.allow_absolute_url_ && !is_connect) {
    headers.addViaMove(std::move(path), std::move(active_request_->request_url_));
    return okStatus();
  }

  Utility::Url absolute_url;
  if (!absolute_url.initialize(active_request_->request_url_.getStringView(), is_connect)) {
    RETURN_IF_ERROR(sendProtocolError(Http1ResponseCodeDetails::get().InvalidUrl));
    return codecProtocolError("http/1.1 protocol error: invalid url in request line");
  }
  
  
  
  
  
  
  
  headers.setHost(absolute_url.hostAndPort());
  
  
  if (!is_connect) {
    headers.setScheme(absolute_url.scheme());
    if (!HeaderUtility::schemeIsValid(absolute_url.scheme())) {
      RETURN_IF_ERROR(sendProtocolError(Http1ResponseCodeDetails::get().InvalidScheme));
      return codecProtocolError("http/1.1 protocol error: invalid scheme");
    }
    if (codec_settings_.validate_scheme_ && absolute_url.scheme() == header_values.SchemeValues.Https && !connection().ssl()) {
      error_code_ = Http::Code::Forbidden;
      RETURN_IF_ERROR(sendProtocolError(Http1ResponseCodeDetails::get().HttpsInPlaintext));
      return codecProtocolError("http/1.1 protocol error: https in the clear");
    }
  }

  if (!absolute_url.pathAndQueryParams().empty()) {
    headers.setPath(absolute_url.pathAndQueryParams());
  }
  active_request_->request_url_.clear();
  return okStatus();
}

Envoy::StatusOr<ParserStatus> ServerConnectionImpl::onHeadersCompleteBase() {
  
  
  
  if (active_request_) {
    auto& headers = absl::get<RequestHeaderMapPtr>(headers_or_trailers_);
    ENVOY_CONN_LOG(trace, "Server: onHeadersComplete size={}", connection_, headers->size());

    if (!handling_upgrade_ && headers->Connection()) {
      
      if (!Utility::sanitizeConnectionHeader(*headers)) {
        absl::string_view header_value = headers->getConnectionValue();
        ENVOY_CONN_LOG(debug, "Invalid nominated headers in Connection: {}", connection_, header_value);
        error_code_ = Http::Code::BadRequest;
        RETURN_IF_ERROR( sendProtocolError(Http1ResponseCodeDetails::get().ConnectionHeaderSanitization));
        return codecProtocolError("Invalid nominated headers in Connection.");
      }
    }

    
    
    const Http::HeaderValues& header_values = Http::Headers::get();
    active_request_->response_encoder_.setIsResponseToHeadRequest(parser_->methodName() == header_values.MethodValues.Head);
    active_request_->response_encoder_.setIsResponseToConnectRequest( parser_->methodName() == header_values.MethodValues.Connect);

    RETURN_IF_ERROR(handlePath(*headers, parser_->methodName()));
    ASSERT(active_request_->request_url_.empty());

    headers->setMethod(parser_->methodName());

    
    auto details = HeaderUtility::requestHeadersValid(*headers);
    if (details.has_value()) {
      RETURN_IF_ERROR(sendProtocolError(details.value().get()));
      return codecProtocolError( "http/1.1 protocol error: request headers failed spec compliance checks");
    }

    
    
    
    
    
    
    if (parser_->isChunked() || (parser_->contentLength().has_value() && parser_->contentLength().value() > 0) || handling_upgrade_) {

      active_request_->request_decoder_->decodeHeaders(std::move(headers), false);

      
      
      if (connection_.state() != Network::Connection::State::Open) {
        return parser_->pause();
      }
    } else {
      deferred_end_stream_headers_ = true;
    }
  }

  return ParserStatus::Success;
}

Status ServerConnectionImpl::onMessageBeginBase() {
  if (!resetStreamCalled()) {
    ASSERT(active_request_ == nullptr);
    active_request_ = std::make_unique<ActiveRequest>(*this, std::move(bytes_meter_before_stream_));
    if (resetStreamCalled()) {
      return codecClientError("cannot create new streams after calling reset");
    }
    active_request_->request_decoder_ = &callbacks_.newStream(active_request_->response_encoder_);

    
    
    
    RETURN_IF_ERROR(doFloodProtectionChecks());
  }
  return okStatus();
}

Status ServerConnectionImpl::onUrl(const char* data, size_t length) {
  if (active_request_) {
    active_request_->request_url_.append(data, length);

    RETURN_IF_ERROR(checkMaxHeadersSize());
  }

  return okStatus();
}

void ServerConnectionImpl::onBody(Buffer::Instance& data) {
  ASSERT(!deferred_end_stream_headers_);
  if (active_request_) {
    ENVOY_CONN_LOG(trace, "body size={}", connection_, data.length());
    active_request_->request_decoder_->decodeData(data, false);
  }
}

Http::Status ServerConnectionImpl::dispatch(Buffer::Instance& data) {
  if (runtime_lazy_read_disable_ && active_request_ != nullptr && active_request_->remote_complete_) {
    
    
    
    active_request_->response_encoder_.readDisable(true);
    return okStatus();
  }

  Http::Status status = ConnectionImpl::dispatch(data);

  if (runtime_lazy_read_disable_ && active_request_ != nullptr && active_request_->remote_complete_) {
    
    
    
    if (data.length() > 0) {
      active_request_->response_encoder_.readDisable(true);
    }
  }
  return status;
}

ParserStatus ServerConnectionImpl::onMessageCompleteBase() {
  ASSERT(!handling_upgrade_);
  if (active_request_) {

    
    ASSERT(active_request_->request_decoder_);
    if (!runtime_lazy_read_disable_) {
      active_request_->response_encoder_.readDisable(true);
    }
    active_request_->remote_complete_ = true;

    if (deferred_end_stream_headers_) {
      active_request_->request_decoder_->decodeHeaders( std::move(absl::get<RequestHeaderMapPtr>(headers_or_trailers_)), true);
      deferred_end_stream_headers_ = false;
    } else if (processing_trailers_) {
      active_request_->request_decoder_->decodeTrailers( std::move(absl::get<RequestTrailerMapPtr>(headers_or_trailers_)));
    } else {
      Buffer::OwnedImpl buffer;
      active_request_->request_decoder_->decodeData(buffer, true);
    }

    
    headers_or_trailers_.emplace<RequestHeaderMapPtr>(nullptr);
  }

  
  
  
  return parser_->pause();
}

void ServerConnectionImpl::onResetStream(StreamResetReason reason) {
  active_request_->response_encoder_.runResetCallbacks(reason);
  connection_.dispatcher().deferredDelete(std::move(active_request_));
}

Status ServerConnectionImpl::sendProtocolError(absl::string_view details) {
  
  if (active_request_ == nullptr) {
    RETURN_IF_ERROR(onMessageBegin());
  }
  ASSERT(active_request_);

  active_request_->response_encoder_.setDetails(details);
  if (!active_request_->response_encoder_.startedResponse()) {
    active_request_->request_decoder_->sendLocalReply( error_code_, CodeUtility::toString(error_code_), nullptr, absl::nullopt, details);
  }
  return okStatus();
}

void ServerConnectionImpl::onAboveHighWatermark() {
  if (active_request_) {
    active_request_->response_encoder_.runHighWatermarkCallbacks();
  }
}
void ServerConnectionImpl::onBelowLowWatermark() {
  if (active_request_) {
    active_request_->response_encoder_.runLowWatermarkCallbacks();
  }
}

void ServerConnectionImpl::releaseOutboundResponse( const Buffer::OwnedBufferFragmentImpl* fragment) {
  ASSERT(outbound_responses_ >= 1);
  --outbound_responses_;
  delete fragment;
}

Status ServerConnectionImpl::checkHeaderNameForUnderscores() {
  if (headers_with_underscores_action_ != envoy::config::core::v3::HttpProtocolOptions::ALLOW && Http::HeaderUtility::headerNameContainsUnderscore(current_header_field_.getStringView())) {
    if (headers_with_underscores_action_ == envoy::config::core::v3::HttpProtocolOptions::DROP_HEADER) {
      ENVOY_CONN_LOG(debug, "Dropping header with invalid characters in its name: {}", connection_, current_header_field_.getStringView());
      stats_.dropped_headers_with_underscores_.inc();
      current_header_field_.clear();
      current_header_value_.clear();
    } else {
      ENVOY_CONN_LOG(debug, "Rejecting request due to header name with underscores: {}", connection_, current_header_field_.getStringView());
      error_code_ = Http::Code::BadRequest;
      RETURN_IF_ERROR(sendProtocolError(Http1ResponseCodeDetails::get().InvalidUnderscore));
      stats_.requests_rejected_with_underscores_in_headers_.inc();
      return codecProtocolError("http/1.1 protocol error: header name contains underscores");
    }
  }
  return okStatus();
}

void ServerConnectionImpl::ActiveRequest::dumpState(std::ostream& os, int indent_level) const {
  (void)indent_level;
  os << DUMP_MEMBER_AS( request_url_, !request_url_.getStringView().empty() ? request_url_.getStringView() : "null");
  os << DUMP_MEMBER(response_encoder_.local_end_stream_);
}

ClientConnectionImpl::ClientConnectionImpl(Network::Connection& connection, CodecStats& stats, ConnectionCallbacks&, const Http1Settings& settings, const uint32_t max_response_headers_count)

    : ConnectionImpl(connection, stats, settings, MessageType::Response, MAX_RESPONSE_HEADERS_KB, max_response_headers_count) {}

bool ClientConnectionImpl::cannotHaveBody() {
  if (pending_response_.has_value() && pending_response_.value().encoder_.headRequest()) {
    ASSERT(!pending_response_done_);
    return true;
  } else if (parser_->statusCode() == 204 || parser_->statusCode() == 304 || (parser_->statusCode() >= 200 && (parser_->contentLength().has_value() && parser_->contentLength().value() == 0) && !parser_->isChunked())) {


    return true;
  } else {
    return false;
  }
}

RequestEncoder& ClientConnectionImpl::newStream(ResponseDecoder& response_decoder) {
  
  
  ASSERT(connection_.readEnabled());

  ASSERT(!pending_response_.has_value());
  ASSERT(pending_response_done_);
  pending_response_.emplace(*this, std::move(bytes_meter_before_stream_), &response_decoder);
  pending_response_done_ = false;
  return pending_response_.value().encoder_;
}

Status ClientConnectionImpl::onStatus(const char* data, size_t length) {
  auto& headers = absl::get<ResponseHeaderMapPtr>(headers_or_trailers_);
  StatefulHeaderKeyFormatterOptRef formatter(headers->formatter());
  if (formatter.has_value()) {
    formatter->setReasonPhrase(absl::string_view(data, length));
  }

  return okStatus();
}

Envoy::StatusOr<ParserStatus> ClientConnectionImpl::onHeadersCompleteBase() {
  ENVOY_CONN_LOG(trace, "status_code {}", connection_, parser_->statusCode());

  
  
  
  if (!pending_response_.has_value() && !resetStreamCalled()) {
    return prematureResponseError("", static_cast<Http::Code>(parser_->statusCode()));
  } else if (pending_response_.has_value()) {
    ASSERT(!pending_response_done_);
    auto& headers = absl::get<ResponseHeaderMapPtr>(headers_or_trailers_);
    ENVOY_CONN_LOG(trace, "Client: onHeadersComplete size={}", connection_, headers->size());
    headers->setStatus(parser_->statusCode());

    if (parser_->statusCode() >= 200 && parser_->statusCode() < 300 && pending_response_.value().encoder_.connectRequest()) {
      ENVOY_CONN_LOG(trace, "codec entering upgrade mode for CONNECT response.", connection_);
      handling_upgrade_ = true;
    }

    if (parser_->statusCode() < 200 || parser_->statusCode() == 204) {
      if (headers->TransferEncoding()) {
        RETURN_IF_ERROR( sendProtocolError(Http1ResponseCodeDetails::get().TransferEncodingNotAllowed));
        return codecProtocolError( "http/1.1 protocol error: transfer encoding not allowed in 1xx or 204");
      }

      if (headers->ContentLength()) {
        
        if (headers->ContentLength()->value().getStringView() != "0") {
          RETURN_IF_ERROR( sendProtocolError(Http1ResponseCodeDetails::get().ContentLengthNotAllowed));
          return codecProtocolError( "http/1.1 protocol error: content length not allowed in 1xx or 204");
        }

        headers->removeContentLength();
      }
    }

    if (HeaderUtility::isSpecial1xx(*headers)) {
      pending_response_.value().decoder_->decode1xxHeaders(std::move(headers));
    } else if (cannotHaveBody() && !handling_upgrade_) {
      deferred_end_stream_headers_ = true;
    } else {
      pending_response_.value().decoder_->decodeHeaders(std::move(headers), false);
    }

    
    
    
    
    if (CodeUtility::is1xx(parser_->statusCode()) && parser_->statusCode() != enumToInt(Http::Code::SwitchingProtocols)) {
      ignore_message_complete_for_1xx_ = true;
      
      headers_or_trailers_.emplace<ResponseHeaderMapPtr>(nullptr);
    }
  }

  
  
  return cannotHaveBody() ? ParserStatus::NoBody : ParserStatus::Success;
}

bool ClientConnectionImpl::upgradeAllowed() const {
  if (pending_response_.has_value()) {
    return pending_response_->encoder_.upgradeRequest();
  }
  return false;
}

void ClientConnectionImpl::onBody(Buffer::Instance& data) {
  ASSERT(!deferred_end_stream_headers_);
  if (pending_response_.has_value()) {
    ASSERT(!pending_response_done_);
    pending_response_.value().decoder_->decodeData(data, false);
  }
}

ParserStatus ClientConnectionImpl::onMessageCompleteBase() {
  ENVOY_CONN_LOG(trace, "message complete", connection_);
  if (ignore_message_complete_for_1xx_) {
    ignore_message_complete_for_1xx_ = false;
    return ParserStatus::Success;
  }
  if (pending_response_.has_value()) {
    ASSERT(!pending_response_done_);
    
    PendingResponse& response = pending_response_.value();
    
    
    pending_response_done_ = true;

    if (deferred_end_stream_headers_) {
      response.decoder_->decodeHeaders( std::move(absl::get<ResponseHeaderMapPtr>(headers_or_trailers_)), true);
      deferred_end_stream_headers_ = false;
    } else if (processing_trailers_) {
      response.decoder_->decodeTrailers( std::move(absl::get<ResponseTrailerMapPtr>(headers_or_trailers_)));
    } else {
      Buffer::OwnedImpl buffer;
      response.decoder_->decodeData(buffer, true);
    }

    
    pending_response_.reset();
    headers_or_trailers_.emplace<ResponseHeaderMapPtr>(nullptr);
  }

  
  return parser_->pause();
}

void ClientConnectionImpl::onResetStream(StreamResetReason reason) {
  
  if (pending_response_.has_value() && !pending_response_done_) {
    pending_response_.value().encoder_.runResetCallbacks(reason);
    pending_response_done_ = true;
    pending_response_.reset();
  }
}

Status ClientConnectionImpl::sendProtocolError(absl::string_view details) {
  if (pending_response_.has_value()) {
    ASSERT(!pending_response_done_);
    pending_response_.value().encoder_.setDetails(details);
  }
  return okStatus();
}

void ClientConnectionImpl::onAboveHighWatermark() {
  
  pending_response_.value().encoder_.runHighWatermarkCallbacks();
}

void ClientConnectionImpl::onBelowLowWatermark() {
  
  
  if (pending_response_.has_value() && !pending_response_done_) {
    pending_response_.value().encoder_.runLowWatermarkCallbacks();
  }
}

} 
} 
} 
