



































































using namespace arangodb;
using namespace arangodb::basics;
using namespace arangodb::rest;

static TRI_action_result_t ExecuteActionVocbase( TRI_vocbase_t*, v8::Isolate*, TRI_action_t const*, v8::Handle<v8::Function> callback, GeneralRequest*, GeneralResponse*);






class v8_action_t final : public TRI_action_t {
 public:
  explicit v8_action_t(ActionFeature const& actionFeature)
      : TRI_action_t(), _actionFeature(actionFeature), _callbacks(), _callbacksLock() {}



  void visit(void* data) override {
    v8::Isolate* isolate = static_cast<v8::Isolate*>(data);

    WRITE_LOCKER(writeLocker, _callbacksLock);

    auto it = _callbacks.find(isolate);

    if (it != _callbacks.end()) {
      (*it).second.Reset();  
      _callbacks.erase(it);  
    }
  }

  
  
  

  void createCallback(v8::Isolate* isolate, v8::Handle<v8::Function> callback) {
    WRITE_LOCKER(writeLocker, _callbacksLock);

    auto it = _callbacks.find(isolate);

    if (it == _callbacks.end()) {
      _callbacks[isolate].Reset(isolate, callback);
    } else {
      LOG_TOPIC("982a6", ERR, Logger::V8)
          << "cannot recreate callback for '" << _url << "'";
    }
  }

  TRI_action_result_t execute(TRI_vocbase_t* vocbase, GeneralRequest* request, GeneralResponse* response, Mutex* dataLock, void** data) override {

    TRI_action_result_t result;

    
    bool allowUseDatabase = _allowUseDatabase || _actionFeature.allowUseDatabase();

    
    V8ContextGuard guard( vocbase, _isSystem ? JavaScriptSecurityContext::createInternalContext()
                           : JavaScriptSecurityContext::createRestActionContext( allowUseDatabase));

    
    READ_LOCKER(readLocker, _callbacksLock);

    {
      auto it = _callbacks.find(guard.isolate());

      if (it == _callbacks.end()) {
        LOG_TOPIC("94556", WARN, arangodb::Logger::FIXME)
            << "no callback function for JavaScript action '" << _url << "'";

        result.isValid = true;
        response->setResponseCode(rest::ResponseCode::NOT_FOUND);

        return result;
      }

      
      {
        
        MUTEX_LOCKER(mutexLocker, *dataLock);

        if (*data != nullptr) {
          result.canceled = true;
          return result;
        }

        *data = (void*)guard.isolate();
      }
      v8::HandleScope scope(guard.isolate());
      auto localFunction = v8::Local<v8::Function>::New(guard.isolate(), it->second);

      
      
      readLocker.unlock();

      try {
        result = ExecuteActionVocbase(vocbase, guard.isolate(), this, localFunction, request, response);
      } catch (...) {
        result.isValid = false;
      }

      {
        
        MUTEX_LOCKER(mutexLocker, *dataLock);
        *data = nullptr;
      }
    }

    return result;
  }

  void cancel(Mutex* dataLock, void** data) override {
    {
      
      MUTEX_LOCKER(mutexLocker, *dataLock);

      
      if (*data == nullptr) {
        *data = (void*)1;  
      }

      
      else {
        if (!((v8::Isolate*)*data)->IsExecutionTerminating()) {
          ((v8::Isolate*)*data)->TerminateExecution();
        }
      }
    }
  }

 private:
  ActionFeature const& _actionFeature;

  
  
  

  std::unordered_map<v8::Isolate*, v8::Persistent<v8::Function>> _callbacks;

  
  
  

  ReadWriteLock _callbacksLock;
};





static void ParseActionOptions(v8::Isolate* isolate, TRI_v8_global_t* v8g, TRI_action_t* action, v8::Handle<v8::Object> options) {

  auto context = TRI_IGETC;
  TRI_GET_GLOBAL_STRING(PrefixKey);
  
  if (TRI_HasProperty(context, isolate, options, PrefixKey)) {
    action->_isPrefix = TRI_ObjectToBoolean( isolate, options->Get(context, PrefixKey).FromMaybe(v8::Local<v8::Value>()));

  } else {
    action->_isPrefix = false;
  }

  
  TRI_GET_GLOBAL_STRING(AllowUseDatabaseKey);
  if (TRI_HasProperty(context, isolate, options, AllowUseDatabaseKey)) {
    action->_allowUseDatabase = TRI_ObjectToBoolean(isolate, options->Get(context, AllowUseDatabaseKey)
                                         .FromMaybe(v8::Local<v8::Value>()));
  } else {
    action->_allowUseDatabase = false;
  }

  TRI_GET_GLOBAL_STRING(IsSystemKey);
  if (TRI_HasProperty(context, isolate, options, IsSystemKey)) {
    action->_isSystem = TRI_ObjectToBoolean( isolate, options->Get(context, IsSystemKey).FromMaybe(v8::Local<v8::Value>()));

  } else {
    action->_isSystem = false;
  }
}





static void AddCookie(v8::Isolate* isolate, TRI_v8_global_t const* v8g, HttpResponse* response, v8::Handle<v8::Object> data) {
  auto context = TRI_IGETC;
  std::string name;
  std::string value;
  int lifeTimeSeconds = 0;
  std::string path = "/";
  std::string domain = "";
  bool secure = false;
  bool httpOnly = false;

  TRI_GET_GLOBAL_STRING(NameKey);
  if (TRI_HasProperty(context, isolate, data, NameKey)) {
    v8::Handle<v8::Value> v = data->Get(context, NameKey).FromMaybe(v8::Handle<v8::Value>());
    name = TRI_ObjectToString(isolate, v);
  } else {
    
    return;
  }
  TRI_GET_GLOBAL_STRING(ValueKey);
  if (TRI_HasProperty(context, isolate, data, ValueKey)) {
    v8::Handle<v8::Value> v = data->Get(context, ValueKey).FromMaybe(v8::Local<v8::Value>());
    value = TRI_ObjectToString(isolate, v);
  } else {
    
    return;
  }
  TRI_GET_GLOBAL_STRING(LifeTimeKey);
  if (TRI_HasProperty(context, isolate, data, LifeTimeKey)) {
    v8::Handle<v8::Value> v = data->Get(context, LifeTimeKey).FromMaybe(v8::Local<v8::Value>());
    lifeTimeSeconds = (int)TRI_ObjectToInt64(isolate, v);
  }
  TRI_GET_GLOBAL_STRING(PathKey);
  if (TRI_HasProperty(context, isolate, data, PathKey) && !data->Get(context, PathKey)
           .FromMaybe(v8::Local<v8::Value>())
           ->IsUndefined()) {
    v8::Handle<v8::Value> v = data->Get(context, PathKey).FromMaybe(v8::Handle<v8::Value>());
    path = TRI_ObjectToString(isolate, v);
  }
  TRI_GET_GLOBAL_STRING(DomainKey);
  if (TRI_HasProperty(context, isolate, data, DomainKey) && !data->Get(context, DomainKey)
           .FromMaybe(v8::Local<v8::Value>())
           ->IsUndefined()) {
    v8::Handle<v8::Value> v = data->Get(context, DomainKey).FromMaybe(v8::Local<v8::Value>());
    domain = TRI_ObjectToString(isolate, v);
  }
  TRI_GET_GLOBAL_STRING(SecureKey);
  if (TRI_HasProperty(context, isolate, data, SecureKey)) {
    v8::Handle<v8::Value> v = data->Get(context, SecureKey).FromMaybe(v8::Local<v8::Value>());
    secure = TRI_ObjectToBoolean(isolate, v);
  }
  TRI_GET_GLOBAL_STRING(HttpOnlyKey);
  if (TRI_HasProperty(context, isolate, data, HttpOnlyKey)) {
    v8::Handle<v8::Value> v = data->Get(context, HttpOnlyKey).FromMaybe(v8::Local<v8::Value>());
    httpOnly = TRI_ObjectToBoolean(isolate, v);
  }

  response->setCookie(name, value, lifeTimeSeconds, path, domain, secure, httpOnly);
}





v8::Handle<v8::Object> TRI_RequestCppToV8(v8::Isolate* isolate, TRI_v8_global_t const* v8g, arangodb::GeneralRequest* request, TRI_action_t const* action) {


  
  v8::Handle<v8::Object> req = v8::Object::New(isolate);
  auto context = TRI_IGETC;
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  

  TRI_GET_GLOBAL_STRING(AuthorizedKey);
  if (request->authenticated()) {
    req->Set(context, AuthorizedKey, v8::True(isolate)).FromMaybe(false);
  } else {
    req->Set(context, AuthorizedKey, v8::False(isolate)).FromMaybe(false);
  }

  
  std::string const& user = request->user();

  TRI_GET_GLOBAL_STRING(UserKey);
  if (user.empty()) {
    req->Set(context, UserKey, v8::Null(isolate)).FromMaybe(false);
  } else {
    req->Set(context, UserKey, TRI_V8_STD_STRING(isolate, user))
        .FromMaybe(false);
  }

  TRI_GET_GLOBAL_STRING(IsAdminUser);
  if (request->authenticated()) {
    if (user.empty() || ExecContext::current().isAdminUser()) {
      req->Set(context, IsAdminUser, v8::True(isolate)).FromMaybe(false);
    } else {
      req->Set(context, IsAdminUser, v8::False(isolate)).FromMaybe(false);
    }
  } else {
    req->Set(context, IsAdminUser, ExecContext::isAuthEnabled() ? v8::False(isolate)
                                          : v8::True(isolate))
        .FromMaybe(false);
    ;
  }

  
  std::string const& database = request->databaseName();
  TRI_ASSERT(!database.empty());

  TRI_GET_GLOBAL_STRING(DatabaseKey);
  req->Set(context, DatabaseKey, TRI_V8_STD_STRING(isolate, database))
      .FromMaybe(false);

  
  std::string const& fullUrl = request->fullUrl();
  TRI_GET_GLOBAL_STRING(UrlKey);
  req->Set(context, UrlKey, TRI_V8_STD_STRING(isolate, fullUrl))
      .FromMaybe(false);

  
  TRI_GET_GLOBAL_STRING(ProtocolKey);
  if (request->transportType() == Endpoint::TransportType::HTTP) {
    req->Set(context, ProtocolKey, TRI_V8_ASCII_STRING(isolate, "http"))
        .FromMaybe(false);
  } else if (request->transportType() == Endpoint::TransportType::VST) {
    req->Set(context, ProtocolKey, TRI_V8_ASCII_STRING(isolate, "vst"))
        .FromMaybe(false);
  }

  
  ConnectionInfo const& info = request->connectionInfo();

  v8::Handle<v8::Object> serverArray = v8::Object::New(isolate);
  TRI_GET_GLOBAL_STRING(AddressKey);
  serverArray ->Set(context, AddressKey, TRI_V8_STD_STRING(isolate, info.serverAddress))
      .FromMaybe(false);
  TRI_GET_GLOBAL_STRING(PortKey);
  serverArray->Set(context, PortKey, v8::Number::New(isolate, info.serverPort))
      .FromMaybe(false);
  TRI_GET_GLOBAL_STRING(EndpointKey);
  serverArray ->Set(context, EndpointKey, TRI_V8_STD_STRING(isolate, Endpoint::uriForm(info.endpoint)))

      .FromMaybe(false);
  TRI_GET_GLOBAL_STRING(ServerKey);
  req->Set(context, ServerKey, serverArray).FromMaybe(false);

  TRI_GET_GLOBAL_STRING(PortTypeKey);
  req->DefineOwnProperty(TRI_IGETC, PortTypeKey, TRI_V8_STD_STRING(isolate, info.portType()), static_cast<v8::PropertyAttribute>(v8::ReadOnly))

      .FromMaybe(false);  

  v8::Handle<v8::Object> clientArray = v8::Object::New(isolate);
  clientArray ->Set(context, AddressKey, TRI_V8_STD_STRING(isolate, info.clientAddress))
      .FromMaybe(false);
  clientArray->Set(context, PortKey, v8::Number::New(isolate, info.clientPort))
      .FromMaybe(false);
  TRI_GET_GLOBAL_STRING(IdKey);
  clientArray->Set(context, IdKey, TRI_V8_STD_STRING(isolate, std::string("0")))
      .FromMaybe(false);
  TRI_GET_GLOBAL_STRING(ClientKey);
  req->Set(context, ClientKey, clientArray).FromMaybe(false);

  req->Set(context, TRI_V8_ASCII_STRING(isolate, "internals"), v8::External::New(isolate, request))
      .FromMaybe(false);

  
  std::string path = request->prefix();
  TRI_GET_GLOBAL_STRING(PrefixKey);
  req->Set(context, PrefixKey, TRI_V8_STD_STRING(isolate, path))
      .FromMaybe(false);

  
  v8::Handle<v8::Object> headerFields = v8::Object::New(isolate);
  
  auto headers = request->headers();

  std::string const& acceptPlain = request->contentTypeResponsePlain();

  if (!acceptPlain.empty()) {
    headers.emplace(StaticStrings::Accept, acceptPlain);
  } else {
    switch (request->contentTypeResponse()) {
      case ContentType::UNSET:
      case ContentType::CUSTOM:  
        break;
      case ContentType::JSON:  
        headers.emplace(StaticStrings::Accept, StaticStrings::MimeTypeJson);
        break;
      case ContentType::VPACK:  
        headers.emplace(StaticStrings::Accept, StaticStrings::MimeTypeVPack);
        break;
      case ContentType::TEXT:  
        headers.emplace(StaticStrings::Accept, StaticStrings::MimeTypeText);
        break;
      case ContentType::HTML:  
        headers.emplace(StaticStrings::Accept, StaticStrings::MimeTypeHtml);
        break;
      case ContentType::DUMP:  
        headers.emplace(StaticStrings::Accept, StaticStrings::MimeTypeDump);
        break;
    }
  }

  switch (request->contentType()) {
    case ContentType::UNSET:
    case ContentType::CUSTOM:  
      break;
    case ContentType::JSON:  
      headers.emplace(StaticStrings::ContentTypeHeader, StaticStrings::MimeTypeJson);
      break;
    case ContentType::VPACK:  
      headers.emplace(StaticStrings::ContentTypeHeader, StaticStrings::MimeTypeVPack);
      break;
    case ContentType::TEXT:  
      headers.emplace(StaticStrings::ContentTypeHeader, StaticStrings::MimeTypeText);
      break;
    case ContentType::HTML:  
      headers.emplace(StaticStrings::ContentTypeHeader, StaticStrings::MimeTypeHtml);
      break;
    case ContentType::DUMP:  
      headers.emplace(StaticStrings::ContentTypeHeader, StaticStrings::MimeTypeDump);
      break;
  }

  TRI_GET_GLOBAL_STRING(HeadersKey);
  req->Set(context, HeadersKey, headerFields).FromMaybe(false);
  TRI_GET_GLOBAL_STRING(RequestTypeKey);
  TRI_GET_GLOBAL_STRING(RequestBodyKey);

  auto setRequestBodyJsonOrVPack = [&]() {
    if (rest::ContentType::UNSET == request->contentType()) {
      bool digestable = false;
      try {
        auto parsed = request->payload(true);
        if (parsed.isObject() || parsed.isArray()) {
          request->setDefaultContentType();
          digestable = true;
        }
      } catch (...) {
      }
      
      auto raw = request->rawPayload();
      headers[StaticStrings::ContentLength] = StringUtils::itoa(raw.size());
      V8Buffer* buffer = V8Buffer::New(isolate, raw.data(), raw.size());
      auto bufObj = v8::Local<v8::Object>::New(isolate, buffer->_handle);
      TRI_GET_GLOBAL_STRING(RawRequestBodyKey);
      req->Set(context, RawRequestBodyKey, bufObj).FromMaybe(false);
      req->Set(context, RequestBodyKey, TRI_V8_PAIR_STRING(isolate, raw.data(), raw.size()))
          .FromMaybe(false);
      if (!digestable) {
        return;
      }
    }

    if (rest::ContentType::JSON == request->contentType()) {
      VPackStringRef body = request->rawPayload();
      req->Set(context, RequestBodyKey, TRI_V8_PAIR_STRING(isolate, body.data(), body.size()))
          .FromMaybe(false);
      headers[StaticStrings::ContentLength] = StringUtils::itoa(request->contentLength());
    } else if (rest::ContentType::VPACK == request->contentType()) {
      
      
      VPackSlice slice = request->payload(true);
      std::string jsonString = slice.toJson();

      LOG_TOPIC("8afce", DEBUG, Logger::COMMUNICATION)
          << "json handed into v8 request:\n" << jsonString;

      req->Set(context, RequestBodyKey, TRI_V8_STD_STRING(isolate, jsonString))
          .FromMaybe(false);
      headers[StaticStrings::ContentLength] = StringUtils::itoa(jsonString.size());
      headers[StaticStrings::ContentTypeHeader] = StaticStrings::MimeTypeJson;
    }
  };

  
  switch (request->requestType()) {
    case rest::RequestType::POST: {
      TRI_GET_GLOBAL_STRING(PostConstant);
      req->Set(context, RequestTypeKey, PostConstant).FromMaybe(false);
      setRequestBodyJsonOrVPack();
      break;
    }

    case rest::RequestType::PUT: {
      TRI_GET_GLOBAL_STRING(PutConstant);
      req->Set(context, RequestTypeKey, PutConstant).FromMaybe(false);
      setRequestBodyJsonOrVPack();
      break;
    }

    case rest::RequestType::PATCH: {
      TRI_GET_GLOBAL_STRING(PatchConstant);
      req->Set(context, RequestTypeKey, PatchConstant).FromMaybe(false);
      setRequestBodyJsonOrVPack();
      break;
    }
    case rest::RequestType::OPTIONS: {
      TRI_GET_GLOBAL_STRING(OptionsConstant);
      req->Set(context, RequestTypeKey, OptionsConstant).FromMaybe(false);
      break;
    }
    case rest::RequestType::DELETE_REQ: {
      TRI_GET_GLOBAL_STRING(DeleteConstant);
      req->Set(context, RequestTypeKey, DeleteConstant).FromMaybe(false);
      setRequestBodyJsonOrVPack();
      break;
    }
    case rest::RequestType::HEAD: {
      TRI_GET_GLOBAL_STRING(HeadConstant);
      req->Set(context, RequestTypeKey, HeadConstant).FromMaybe(false);
      break;
    }
    case rest::RequestType::GET:
    default: {
      TRI_GET_GLOBAL_STRING(GetConstant);
      req->Set(context, RequestTypeKey, GetConstant).FromMaybe(false);
      break;
    }
  }

  for (auto const& it : headers) {
    headerFields ->Set(context, TRI_V8_STD_STRING(isolate, it.first), TRI_V8_STD_STRING(isolate, it.second))

        .FromMaybe(false);
  }

  
  v8::Handle<v8::Object> valuesObject = v8::Object::New(isolate);

  for (auto& it : request->values()) {
    valuesObject ->Set(context, TRI_V8_STD_STRING(isolate, it.first), TRI_V8_STD_STRING(isolate, it.second))

        .FromMaybe(false);
  }

  
  for (auto& arrayValue : request->arrayValues()) {
    std::string const& k = arrayValue.first;
    std::vector<std::string> const& v = arrayValue.second;

    v8::Handle<v8::Array> list = v8::Array::New(isolate, static_cast<int>(v.size()));

    for (size_t i = 0; i < v.size(); ++i) {
      list->Set(context, (uint32_t)i, TRI_V8_STD_STRING(isolate, v[i]))
          .FromMaybe(false);
    }

    valuesObject->Set(context, TRI_V8_STD_STRING(isolate, k), list)
        .FromMaybe(false);
  }

  TRI_GET_GLOBAL_STRING(ParametersKey);
  req->Set(context, ParametersKey, valuesObject).FromMaybe(false);

  
  if (request->transportType() == Endpoint::TransportType::HTTP) {  
    v8::Handle<v8::Object> cookiesObject = v8::Object::New(isolate);

    HttpRequest* httpRequest = dynamic_cast<HttpRequest*>(request);
    if (httpRequest == nullptr) {
      
      THROW_ARANGO_EXCEPTION_MESSAGE(TRI_ERROR_INTERNAL, "invalid request type");
    } else {
      for (auto& it : httpRequest->cookieValues()) {
        cookiesObject ->Set(context, TRI_V8_STD_STRING(isolate, it.first), TRI_V8_STD_STRING(isolate, it.second))

            .FromMaybe(false);
      }
    }
    TRI_GET_GLOBAL_STRING(CookiesKey);
    req->Set(context, CookiesKey, cookiesObject).FromMaybe(false);
  }

  
  std::vector<std::string> const& suffixes = request->decodedSuffixes();
  std::vector<std::string> const& rawSuffixes = request->suffixes();

  uint32_t index = 0;
  char const* sep = "";

  size_t const n = suffixes.size();
  v8::Handle<v8::Array> suffixArray = v8::Array::New(isolate, static_cast<int>(n - action->_urlParts));
  v8::Handle<v8::Array> rawSuffixArray = v8::Array::New(isolate, static_cast<int>(n - action->_urlParts));

  for (size_t s = action->_urlParts; s < n; ++s) {
    suffixArray->Set(context, index, TRI_V8_STD_STRING(isolate, suffixes[s]))
        .FromMaybe(false);
    rawSuffixArray ->Set(context, index, TRI_V8_STD_STRING(isolate, rawSuffixes[s]))
        .FromMaybe(false);
    ++index;

    path += sep + suffixes[s];
    sep = "/";
  }

  TRI_GET_GLOBAL_STRING(SuffixKey);
  req->Set(context, SuffixKey, suffixArray).FromMaybe(false);
  TRI_GET_GLOBAL_STRING(RawSuffixKey);
  req->Set(context, RawSuffixKey, rawSuffixArray).FromMaybe(false);

  
  TRI_GET_GLOBAL_STRING(PathKey);
  req->Set(context, PathKey, TRI_V8_STD_STRING(isolate, path)).FromMaybe(false);

  return req;
}






static void ResponseV8ToCpp(v8::Isolate* isolate, TRI_v8_global_t const* v8g, GeneralRequest* request, v8::Handle<v8::Object> const res, GeneralResponse* response) {


  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  TRI_ASSERT(request != nullptr);

  using arangodb::Endpoint;

  
  TRI_GET_GLOBAL_STRING(ResponseCodeKey);
  if (TRI_HasProperty(context, isolate, res, ResponseCodeKey)) {
    uint64_t foxxcode = TRI_ObjectToInt64( isolate, res->Get(context, ResponseCodeKey).FromMaybe(v8::Local<v8::Value>()));

    if (GeneralResponse::isValidResponseCode(foxxcode)) {
      response->setResponseCode(static_cast<rest::ResponseCode>(foxxcode));
    } else {
      response->setResponseCode(rest::ResponseCode::SERVER_ERROR);
      LOG_TOPIC("37d37", ERR, Logger::V8)
          << "invalid http status code specified " << foxxcode << " diverting to 500";
    }
  } else {
    response->setResponseCode(rest::ResponseCode::OK);
  }

  
  std::string contentType = StaticStrings::MimeTypeJsonNoEncoding;
  bool autoContent = true;
  TRI_GET_GLOBAL_STRING(ContentTypeKey);
  if (TRI_HasProperty(context, isolate, res, ContentTypeKey)) {
    contentType = TRI_ObjectToString( isolate, res->Get(context, ContentTypeKey).FromMaybe(v8::Local<v8::Value>()));


    if ((contentType.find(StaticStrings::MimeTypeJsonNoEncoding) == std::string::npos) && (contentType.find(StaticStrings::MimeTypeVPack) == std::string::npos)) {

      autoContent = false;
    }
    switch (response->transportType()) {
      case Endpoint::TransportType::HTTP:
        if (autoContent) {
          response->setContentType(rest::ContentType::JSON);
        } else {
          response->setContentType(contentType);
        }
        break;

      case Endpoint::TransportType::VST:
        if (!autoContent) {
          response->setContentType(contentType);
        } else {
          response->setHeaderNC(arangodb::StaticStrings::ContentTypeHeader, contentType);
        }
        break;

      default:
        throw std::logic_error("unknown transport type");
    }
  }

  
  
  
  

  bool bodySet = false;
  TRI_GET_GLOBAL_STRING(BodyKey);
  if (TRI_HasProperty(context, isolate, res, BodyKey)) {
    
    
    
    
    
    TRI_GET_GLOBAL_STRING(TransformationsKey);
    v8::Handle<v8::Value> transformArray = res->Get(context, TransformationsKey).FromMaybe(v8::Local<v8::Value>());

    switch (response->transportType()) {
      case Endpoint::TransportType::HTTP: {
        
        

        HttpResponse* httpResponse = dynamic_cast<HttpResponse*>(response);
        if (transformArray->IsArray()) {
          TRI_GET_GLOBAL_STRING(BodyKey);
          std::string out(TRI_ObjectToString( isolate, res->Get(context, BodyKey).FromMaybe(v8::Local<v8::Value>())));

          v8::Handle<v8::Array> transformations = transformArray.As<v8::Array>();

          for (uint32_t i = 0; i < transformations->Length(); i++) {
            v8::Handle<v8::Value> transformator = transformations->Get(context, v8::Integer::New(isolate, i))
                    .FromMaybe(v8::Local<v8::Value>());
            std::string name = TRI_ObjectToString(isolate, transformator);

            
            if (name == "base64encode") {
              
              out = StringUtils::encodeBase64(out);
              
              response->setHeaderNC(StaticStrings::ContentEncoding, StaticStrings::Base64);
            } else if (name == "base64decode") {
              
              out = StringUtils::decodeBase64(out);
              
              response->setHeaderNC(StaticStrings::ContentEncoding, StaticStrings::Binary);
            }
          }

          
          httpResponse->body().appendText(out);
          httpResponse->sealBody();
        } else {
          TRI_GET_GLOBAL_STRING(BodyKey);
          v8::Handle<v8::Value> b = res->Get(context, BodyKey).FromMaybe(v8::Local<v8::Value>());
          if (V8Buffer::hasInstance(isolate, b)) {
            
            auto obj = b.As<v8::Object>();
            httpResponse->body().appendText(V8Buffer::data(isolate, obj), V8Buffer::length(isolate, obj));
            httpResponse->sealBody();
          } else if (autoContent && request->contentTypeResponse() == rest::ContentType::VPACK) {
            
            try {
              std::string json = TRI_ObjectToString( isolate, res->Get(context, BodyKey).FromMaybe(v8::Local<v8::Value>()));

              VPackBuffer<uint8_t> buffer;
              VPackBuilder builder(buffer);
              VPackParser parser(builder);
              parser.parse(json);
              httpResponse->setContentType(rest::ContentType::VPACK);
              httpResponse->setPayload(std::move(buffer));
            } catch (...) {
              httpResponse->body().appendText(TRI_ObjectToString( isolate, res->Get(context, BodyKey)
                               .FromMaybe(v8::Local<v8::Value>())));
              httpResponse->sealBody();
            }
          } else {
            
            httpResponse->body().appendText(TRI_ObjectToString( isolate, res->Get(context, BodyKey).FromMaybe(v8::Local<v8::Value>())));

            httpResponse->sealBody();
          }
        }
      } break;

      case Endpoint::TransportType::VST: {
        VPackBuffer<uint8_t> buffer;
        VPackBuilder builder(buffer);

        v8::Handle<v8::Value> v8Body = res->Get(context, BodyKey).FromMaybe(v8::Local<v8::Value>());
        std::string out;

        
        if (transformArray->IsArray()) {
          TRI_GET_GLOBAL_STRING(BodyKey);
          out = TRI_ObjectToString( isolate, res->Get(context, BodyKey)

                  .FromMaybe( v8::Local<v8::Value>()));
                                                 
          v8::Handle<v8::Array> transformations = transformArray.As<v8::Array>();

          for (uint32_t i = 0; i < transformations->Length(); i++) {
            v8::Handle<v8::Value> transformator = transformations->Get(context, v8::Integer::New(isolate, i))
                    .FromMaybe(v8::Local<v8::Value>());
            std::string name = TRI_ObjectToString(isolate, transformator);

            
            
            if (name == "base64decode") {
              out = StringUtils::decodeBase64(out);
            }
          }
        }

        
        if (out.empty()) {
          if (autoContent && !V8Buffer::hasInstance(isolate, v8Body)) {
            if (v8Body->IsString()) {
              out = TRI_ObjectToString( isolate, res->Get(context, BodyKey)

                      .FromMaybe(v8::Local<v8::Value>()));  
            } else {
              TRI_V8ToVPack(isolate, builder, v8Body, false);
              response->setContentType(rest::ContentType::VPACK);
            }
          } else if (V8Buffer::hasInstance( isolate, v8Body)) {

                                     
            
            auto obj = v8Body.As<v8::Object>();
            out = std::string(V8Buffer::data(isolate, obj), V8Buffer::length(isolate, obj));
          } else {  
            out = TRI_ObjectToString( isolate, res->Get(context, BodyKey)

                    .FromMaybe(v8::Local<v8::Value>()));  
          }
        }

        
        if (!out.empty()) {
          bool gotJson = false;
          if (autoContent) {  
            try {
              VPackParser parser(builder);  
              parser.parse(out, false);
              gotJson = true;
              response->setContentType(rest::ContentType::VPACK);
            } catch (...) {  
                             
                             
              LOG_TOPIC("32d35", DEBUG, Logger::COMMUNICATION)
                  << "failed to parse json:\n" << out;
            }
          }

          if (!gotJson) {
            
            buffer.reset();
            buffer.append(out);
          }
        }

        response->setPayload(std::move(buffer));
        break;
      }

      default: {
        throw std::logic_error("unknown transport type");
      }
    }
    bodySet = true;
  }

  
  
  
  TRI_GET_GLOBAL_STRING(BodyFromFileKey);
  if (!bodySet && TRI_HasProperty(context, isolate, res, BodyFromFileKey)) {
    TRI_Utf8ValueNFC filename( isolate, res->Get(context, BodyFromFileKey).FromMaybe(v8::Local<v8::Value>()));

    size_t length;
    char* content = TRI_SlurpFile(*filename, &length);

    if (content == nullptr) {
      THROW_ARANGO_EXCEPTION_MESSAGE( TRI_ERROR_FILE_NOT_FOUND, std::string("unable to read file '") + *filename + "'");

    }

    switch (response->transportType()) {
      case Endpoint::TransportType::HTTP: {
        HttpResponse* httpResponse = dynamic_cast<HttpResponse*>(response);
        httpResponse->body().appendText(content, length);
        TRI_FreeString(content);
        httpResponse->sealBody();
      } break;

      case Endpoint::TransportType::VST: {
        response->addRawPayload(velocypack::StringRef(content, length));
        TRI_FreeString(content);
      } break;

      default:
        TRI_FreeString(content);
        throw std::logic_error("unknown transport type");
    }
  }

  
  
  

  TRI_GET_GLOBAL_STRING(HeadersKey);

  if (TRI_HasProperty(context, isolate, res, HeadersKey)) {
    v8::Handle<v8::Value> val = res->Get(context, HeadersKey).FromMaybe(v8::Local<v8::Value>());
    v8::Handle<v8::Object> v8Headers = val.As<v8::Object>();

    if (v8Headers->IsObject()) {
      v8::Handle<v8::Array> props = v8Headers->GetPropertyNames(TRI_IGETC).FromMaybe( v8::Local<v8::Array>());


      for (uint32_t i = 0; i < props->Length(); i++) {
        v8::Handle<v8::Value> key = props->Get(context, v8::Integer::New(isolate, i))
                .FromMaybe(v8::Local<v8::Value>());
        response->setHeader( TRI_ObjectToString(isolate, key), TRI_ObjectToString(isolate, v8Headers->Get(context, key)


                                   .FromMaybe(v8::Local<v8::Value>())));
      }
    }
  }

  
  
  

  TRI_GET_GLOBAL_STRING(CookiesKey);
  if (TRI_HasProperty(context, isolate, res, CookiesKey)) {
    v8::Handle<v8::Value> val = res->Get(context, CookiesKey).FromMaybe(v8::Local<v8::Value>());
    v8::Handle<v8::Object> v8Cookies = val.As<v8::Object>();

    switch (response->transportType()) {
      case Endpoint::TransportType::HTTP: {
        HttpResponse* httpResponse = dynamic_cast<HttpResponse*>(response);
        if (v8Cookies->IsArray()) {
          v8::Handle<v8::Array> v8Array = v8Cookies.As<v8::Array>();

          for (uint32_t i = 0; i < v8Array->Length(); i++) {
            v8::Handle<v8::Value> v8Cookie = v8Array->Get(context, i).FromMaybe(v8::Local<v8::Value>());
            if (v8Cookie->IsObject()) {
              AddCookie(isolate, v8g, httpResponse, v8Cookie.As<v8::Object>());
            }
          }
        } else if (v8Cookies->IsObject()) {
          
          AddCookie(isolate, v8g, httpResponse, v8Cookies);
        }
      } break;

      case Endpoint::TransportType::VST:
        break;

      default:
        throw std::logic_error("unknown transport type");
    }
  }
}





static TRI_action_result_t ExecuteActionVocbase( TRI_vocbase_t* vocbase, v8::Isolate* isolate, TRI_action_t const* action, v8::Handle<v8::Function> callback, GeneralRequest* request, GeneralResponse* response) {


  v8::HandleScope scope(isolate);
  v8::TryCatch tryCatch(isolate);

  if (response == nullptr) {
    THROW_ARANGO_EXCEPTION_MESSAGE(TRI_ERROR_INTERNAL, "invalid response");
  }

  TRI_GET_GLOBALS();

  v8::Handle<v8::Object> req = TRI_RequestCppToV8(isolate, v8g, request, action);

  
  v8::Handle<v8::Object> res = v8::Object::New(isolate);

  
  v8g->_currentRequest = req;
  v8g->_currentResponse = res;

  
  v8::Handle<v8::Value> args[2] = {req, res};

  
  ErrorCode errorCode = TRI_ERROR_NO_ERROR;
  std::string errorMessage;

  try {
    callback->Call(TRI_IGETC, callback, 2, args)
        .FromMaybe(v8::Local<v8::Value>());
    ;
    errorCode = TRI_ERROR_NO_ERROR;
  } catch (arangodb::basics::Exception const& ex) {
    errorCode = ex.code();
    errorMessage = ex.what();
  } catch (std::bad_alloc const&) {
    errorCode = TRI_ERROR_OUT_OF_MEMORY;
  } catch (...) {
    errorCode = TRI_ERROR_INTERNAL;
  }

  
  v8g->_currentRequest = v8::Undefined(isolate);
  v8g->_currentResponse = v8::Undefined(isolate);

  
  TRI_action_result_t result;
  result.isValid = true;

  if (errorCode != TRI_ERROR_NO_ERROR) {
    result.isValid = false;
    result.canceled = false;

    response->setResponseCode(rest::ResponseCode::SERVER_ERROR);

    if (errorMessage.empty()) {
      errorMessage = TRI_errno_string(errorCode);
    }

    VPackBuffer<uint8_t> buffer;
    VPackBuilder b(buffer);
    b.add(VPackValue(errorMessage));
    response->addPayload(std::move(buffer));
  }

  else if (v8g->_canceled) {
    result.isValid = false;
    result.canceled = true;
  }

  else if (tryCatch.HasCaught()) {
    if (tryCatch.CanContinue()) {
      response->setResponseCode(rest::ResponseCode::SERVER_ERROR);

      std::string jsError = TRI_StringifyV8Exception(isolate, &tryCatch);
      LOG_TOPIC("b8286", WARN, arangodb::Logger::V8)
          << "Caught an error while executing an action: " << jsError;

      VPackBuilder b;
      b.add(VPackValue(TRI_StringifyV8Exception(isolate, &tryCatch)));
      response->addPayload(b.slice());

    } else {
      v8g->_canceled = true;
      result.isValid = false;
      result.canceled = true;
    }
  }

  else {
    ResponseV8ToCpp(isolate, v8g, request, res, response);
  }

  return result;
}







static void JS_DefineAction(v8::FunctionCallbackInfo<v8::Value> const& args) {
  TRI_V8_TRY_CATCH_BEGIN(isolate);
  v8::HandleScope scope(isolate);
  TRI_GET_GLOBALS();

  if (args.Length() != 3) {
    TRI_V8_THROW_EXCEPTION_USAGE( "defineAction(<name>, <callback>, <parameter>)");
  }

  V8SecurityFeature& v8security = v8g->_server.getFeature<V8SecurityFeature>();

  if (!v8security.isAllowedToDefineHttpAction(isolate)) {
    TRI_V8_THROW_EXCEPTION_MESSAGE( TRI_ERROR_FORBIDDEN, "operation only allowed for internal scripts");
  }

  
  TRI_Utf8ValueNFC utf8name(isolate, args[0]);

  if (*utf8name == nullptr) {
    TRI_V8_THROW_TYPE_ERROR("<name> must be an UTF-8 string");
  }

  std::string name = *utf8name;

  
  if (!args[1]->IsFunction()) {
    TRI_V8_THROW_TYPE_ERROR("<callback> must be a function");
  }

  v8::Handle<v8::Function> callback = v8::Handle<v8::Function>::Cast(args[1]);

  
  v8::Handle<v8::Object> options;

  if (args[2]->IsObject()) {
    options = args[2]->ToObject(TRI_IGETC).FromMaybe(v8::Local<v8::Object>());
  } else {
    options = v8::Object::New(isolate);
  }

  
  auto action = std::make_shared<v8_action_t>(v8g->_server.getFeature<ActionFeature>());
  ParseActionOptions(isolate, v8g, action.get(), options);

  
  
  std::shared_ptr<TRI_action_t> actionForName = TRI_DefineActionVocBase(name, action);

  v8_action_t* v8ActionForName = dynamic_cast<v8_action_t*>(actionForName.get());

  if (v8ActionForName != nullptr) {
    v8ActionForName->createCallback(isolate, callback);
  } else {
    LOG_TOPIC("43be9", WARN, arangodb::Logger::FIXME)
        << "cannot create callback for V8 action";
  }

  TRI_V8_RETURN_UNDEFINED();
  TRI_V8_TRY_CATCH_END }







static void JS_ExecuteGlobalContextFunction( v8::FunctionCallbackInfo<v8::Value> const& args) {
  TRI_V8_TRY_CATCH_BEGIN(isolate);
  v8::HandleScope scope(isolate);

  if (args.Length() != 1) {
    TRI_V8_THROW_EXCEPTION_USAGE( "executeGlobalContextFunction(<function-type>)");
  }

  
  v8::String::Utf8Value utf8def(isolate, args[0]);

  if (*utf8def == nullptr) {
    TRI_V8_THROW_TYPE_ERROR("<definition> must be a UTF-8 function definition");
  }

  std::string const def = std::string(*utf8def, utf8def.length());

  TRI_GET_GLOBALS();
  
  if (!v8g->_server.getFeature<V8DealerFeature>().addGlobalContextMethod(def)) {
    TRI_V8_THROW_EXCEPTION_MESSAGE(TRI_ERROR_INTERNAL, "invalid action definition");
  }

  TRI_V8_RETURN_UNDEFINED();
  TRI_V8_TRY_CATCH_END }







static void JS_GetCurrentRequest( v8::FunctionCallbackInfo<v8::Value> const& args) {
  TRI_V8_TRY_CATCH_BEGIN(isolate);
  v8::HandleScope scope(isolate);
  TRI_GET_GLOBALS();

  if (args.Length() != 0) {
    TRI_V8_THROW_EXCEPTION_USAGE("getCurrentRequest()");
  }

  TRI_V8_RETURN(v8g->_currentRequest);
  TRI_V8_TRY_CATCH_END }







static void JS_RawRequestBody(v8::FunctionCallbackInfo<v8::Value> const& args) {
  TRI_V8_TRY_CATCH_BEGIN(isolate);
  v8::HandleScope scope(isolate);
  auto context = TRI_IGETC;

  if (args.Length() != 1) {
    TRI_V8_THROW_EXCEPTION_USAGE("rawRequestBody(req)");
  }

  v8::Handle<v8::Value> current = args[0];
  if (current->IsObject()) {
    v8::Handle<v8::Object> obj = v8::Handle<v8::Object>::Cast(current);
    v8::Handle<v8::Value> property = obj->Get(context, TRI_V8_ASCII_STRING(isolate, "internals"))
            .FromMaybe(v8::Local<v8::Value>());
    if (property->IsExternal()) {
      v8::Handle<v8::External> e = v8::Handle<v8::External>::Cast(property);

      GeneralRequest* request = static_cast<GeneralRequest*>(e->Value());

      switch (request->transportType()) {
        case Endpoint::TransportType::HTTP: {
          auto httpRequest = static_cast<arangodb::HttpRequest*>(e->Value());
          if (httpRequest != nullptr) {
            V8Buffer* buffer;
            if (rest::ContentType::VPACK == request->contentType()) {
              VPackSlice slice = request->payload();
              std::string bodyStr = slice.toJson();
              buffer = V8Buffer::New(isolate, bodyStr.c_str(), bodyStr.size());
            } else {
              auto raw = httpRequest->rawPayload();
              buffer = V8Buffer::New(isolate, raw.data(), raw.size());
            }

            v8::Local<v8::Object> bufferObject = v8::Local<v8::Object>::New(isolate, buffer->_handle);
            TRI_V8_RETURN(bufferObject);
          }
        } break;

        case Endpoint::TransportType::VST: {
          if (request != nullptr) {
            auto raw = request->rawPayload();
            V8Buffer* buffer = V8Buffer::New(isolate, raw.data(), raw.size());
            v8::Local<v8::Object> bufferObject = v8::Local<v8::Object>::New(isolate, buffer->_handle);
            TRI_V8_RETURN(bufferObject);
          }
        } break;
      }
    }
  }

  
  
  TRI_V8_RETURN_UNDEFINED();
  TRI_V8_TRY_CATCH_END }







static void JS_RequestParts(v8::FunctionCallbackInfo<v8::Value> const& args) {
  TRI_V8_TRY_CATCH_BEGIN(isolate);
  v8::HandleScope scope(isolate);
  auto context = TRI_IGETC;

  if (args.Length() != 1) {
    TRI_V8_THROW_EXCEPTION_USAGE("requestParts(req)");
  }

  v8::Handle<v8::Value> current = args[0];
  if (current->IsObject()) {
    v8::Handle<v8::Object> obj = v8::Handle<v8::Object>::Cast(current);
    v8::Handle<v8::Value> property = obj->Get(context, TRI_V8_ASCII_STRING(isolate, "internals"))
            .FromMaybe(v8::Local<v8::Value>());
    if (property->IsExternal()) {
      v8::Handle<v8::External> e = v8::Handle<v8::External>::Cast(property);
      auto request = static_cast<arangodb::HttpRequest*>(e->Value());

      VPackStringRef bodyStr = request->rawPayload();
      char const* beg = bodyStr.data();
      char const* end = beg + bodyStr.size();

      while (beg < end && (*beg == '\r' || *beg == '\n' || *beg == ' ')) {
        ++beg;
      }

      
      char const* ptr = beg;
      while (ptr < end && *ptr == '-') {
        ++ptr;
      }

      while (ptr < end && *ptr != '\r' && *ptr != '\n') {
        ++ptr;
      }
      if (ptr == beg) {
        
        TRI_V8_THROW_EXCEPTION_PARAMETER("request is no multipart request");
      }

      std::string const delimiter(beg, ptr - beg);
      if (ptr < end && *ptr == '\r') {
        ++ptr;
      }
      if (ptr < end && *ptr == '\n') {
        ++ptr;
      }

      std::vector<std::pair<char const*, size_t>> parts;

      while (ptr < end) {
        char const* p = TRI_IsContainedMemory(ptr, end - ptr, delimiter.c_str(), delimiter.size());
        if (p == nullptr || p + delimiter.size() + 2 >= end || p - 2 <= ptr) {
          TRI_V8_THROW_EXCEPTION_PARAMETER("bad request data");
        }

        char const* q = p;
        if (*(q - 1) == '\n') {
          --q;
        }
        if (*(q - 1) == '\r') {
          --q;
        }

        parts.push_back(std::make_pair(ptr, q - ptr));
        ptr = p + delimiter.size();
        if (*ptr == '-' && *(ptr + 1) == '-') {
          
          break;
        }
        if (*ptr == '\r') {
          ++ptr;
        }
        if (ptr < end && *ptr == '\n') {
          ++ptr;
        }
      }

      v8::Handle<v8::Array> result = v8::Array::New(isolate);

      uint32_t j = 0;
      for (auto& part : parts) {
        v8::Handle<v8::Object> headersObject = v8::Object::New(isolate);

        auto ptr = part.first;
        auto end = part.first + part.second;
        char const* data = nullptr;

        while (ptr < end) {
          while (ptr < end && *ptr == ' ') {
            ++ptr;
          }
          if (ptr < end && (*ptr == '\r' || *ptr == '\n')) {
            
            if (*ptr == '\r') {
              ++ptr;
            }
            if (ptr < end && *ptr == '\n') {
              ++ptr;
            }
            data = ptr;
            break;
          }

          
          char const* eol = TRI_IsContainedMemory(ptr, end - ptr, "\r\n", 2);
          if (eol == nullptr) {
            eol = TRI_IsContainedMemory(ptr, end - ptr, "\n", 1);
          }
          if (eol == nullptr) {
            TRI_V8_THROW_EXCEPTION_PARAMETER("bad request data");
          }
          char const* colon = TRI_IsContainedMemory(ptr, end - ptr, ":", 1);
          if (colon == nullptr) {
            TRI_V8_THROW_EXCEPTION_PARAMETER("bad request data");
          }
          char const* p = colon;
          while (p > ptr && *(p - 1) == ' ') {
            --p;
          }
          ++colon;
          while (colon < eol && *colon == ' ') {
            ++colon;
          }
          char const* q = eol;
          while (q > ptr && *(q - 1) == ' ') {
            --q;
          }

          headersObject ->Set(context, TRI_V8_PAIR_STRING(isolate, ptr, (int)(p - ptr)), TRI_V8_PAIR_STRING(isolate, colon, (int)(eol - colon)))

              .FromMaybe(false);

          ptr = eol;
          if (*ptr == '\r') {
            ++ptr;
          }
          if (ptr < end && *ptr == '\n') {
            ++ptr;
          }
        }

        if (data == nullptr) {
          TRI_V8_THROW_EXCEPTION_PARAMETER("bad request data");
        }

        v8::Handle<v8::Object> partObject = v8::Object::New(isolate);
        partObject ->Set(context, TRI_V8_ASCII_STRING(isolate, "headers"), headersObject)

            .FromMaybe(false);

        
        
        V8Buffer* buffer = V8Buffer::New(isolate, data, end - data);
        auto localHandle = v8::Local<v8::Object>::New(isolate, buffer->_handle);

        partObject ->Set(context, TRI_V8_ASCII_STRING(isolate, "data"), localHandle)
            .FromMaybe(false);

        result->Set(context, j++, partObject).FromMaybe(false);
      }

      TRI_V8_RETURN(result);
    }
  }

  TRI_V8_RETURN_UNDEFINED();
  TRI_V8_TRY_CATCH_END }







static void JS_GetCurrentResponse( v8::FunctionCallbackInfo<v8::Value> const& args) {
  TRI_V8_TRY_CATCH_BEGIN(isolate);
  v8::HandleScope scope(isolate);
  TRI_GET_GLOBALS();

  if (args.Length() != 0) {
    TRI_V8_THROW_EXCEPTION_USAGE("getCurrentResponse()");
  }

  TRI_V8_RETURN(v8g->_currentResponse);
  TRI_V8_TRY_CATCH_END }





void TRI_InitV8Actions(v8::Isolate* isolate) {
  v8::HandleScope scope(isolate);

  
  
  

  TRI_AddGlobalFunctionVocbase( isolate, TRI_V8_ASCII_STRING(isolate, "SYS_DEFINE_ACTION"), JS_DefineAction);

  TRI_AddGlobalFunctionVocbase( isolate, TRI_V8_ASCII_STRING(isolate, "SYS_EXECUTE_GLOBAL_CONTEXT_FUNCTION"), JS_ExecuteGlobalContextFunction, true);


  TRI_AddGlobalFunctionVocbase( isolate, TRI_V8_ASCII_STRING(isolate, "SYS_GET_CURRENT_REQUEST"), JS_GetCurrentRequest);

  TRI_AddGlobalFunctionVocbase( isolate, TRI_V8_ASCII_STRING(isolate, "SYS_GET_CURRENT_RESPONSE"), JS_GetCurrentResponse);

  TRI_AddGlobalFunctionVocbase( isolate, TRI_V8_ASCII_STRING(isolate, "SYS_RAW_REQUEST_BODY"), JS_RawRequestBody, true);

  TRI_AddGlobalFunctionVocbase( isolate, TRI_V8_ASCII_STRING(isolate, "SYS_REQUEST_PARTS"), JS_RequestParts, true);

}






static ErrorCode clusterSendToAllServers( v8::Isolate* isolate, std::string const& dbname, std::string const& path, arangodb::rest::RequestType const& method, std::string const& body) {


  TRI_GET_GLOBALS();
  network::ConnectionPool* pool = v8g->_server.getFeature<NetworkFeature>().pool();
  if (!pool || !pool->config().clusterInfo) {
    LOG_TOPIC("98fc7", ERR, Logger::COMMUNICATION)
        << "Network pool unavailable.";
    return TRI_ERROR_SHUTTING_DOWN;
  }
  ClusterInfo& ci = *pool->config().clusterInfo;
  std::vector<ServerID> DBServers = ci.getCurrentDBServers();

  network::Headers headers;
  fuerte::RestVerb verb = network::arangoRestVerbToFuerte(method);

  network::RequestOptions reqOpts;

  reqOpts.database = dbname;
  reqOpts.timeout = network::Timeout(3600);
  reqOpts.contentType = StaticStrings::MimeTypeJsonNoEncoding;

  std::vector<futures::Future<network::Response>> futures;
  futures.reserve(DBServers.size());

  
  for (auto const& sid : DBServers) {
    VPackBuffer<uint8_t> buffer(body.size());
    buffer.append(body);
    auto f = network::sendRequestRetry(pool, "server:" + sid, verb, path, std::move(buffer), reqOpts, headers);
    futures.emplace_back(std::move(f));
  }

  for (auto& f : futures) {
    network::Response const& res = f.get();  
    auto commError = network::fuerteToArangoErrorCode(res);
    if (commError != TRI_ERROR_NO_ERROR) {
      return commError;
    }
  }
  return TRI_ERROR_NO_ERROR;
}











static void JS_DebugTerminate(v8::FunctionCallbackInfo<v8::Value> const& args) {
  TRI_V8_TRY_CATCH_BEGIN(isolate);
  v8::HandleScope scope(isolate);

  
  if (args.Length() != 1) {
    TRI_V8_THROW_EXCEPTION_USAGE("debugTerminate(<message>)");
  }

  std::string const message = TRI_ObjectToString(isolate, args[0]);

  TRI_TerminateDebugging(message.c_str());

  

  TRI_V8_RETURN_UNDEFINED();
  TRI_V8_TRY_CATCH_END }











static void JS_DebugSetFailAt(v8::FunctionCallbackInfo<v8::Value> const& args) {
  TRI_V8_TRY_CATCH_BEGIN(isolate);
  v8::HandleScope scope(isolate);

  TRI_GET_GLOBALS();

  if (v8g->_vocbase == nullptr) {
    TRI_V8_THROW_EXCEPTION_MEMORY();
  }
  std::string dbname(v8g->_vocbase->name());

  
  if (args.Length() != 1) {
    TRI_V8_THROW_EXCEPTION_USAGE("debugSetFailAt(<point>)");
  }

  std::string const point = TRI_ObjectToString(isolate, args[0]);

  TRI_AddFailurePointDebugging(point.c_str());

  if (ServerState::instance()->isCoordinator()) {
    auto res = clusterSendToAllServers( isolate, dbname, "_admin/debug/failat/" + StringUtils::urlEncode(point), arangodb::rest::RequestType::PUT, "");

    if (res != TRI_ERROR_NO_ERROR) {
      TRI_V8_THROW_EXCEPTION(res);
    }
  }

  TRI_V8_RETURN_UNDEFINED();
  TRI_V8_TRY_CATCH_END }











static void JS_DebugShouldFailAt( v8::FunctionCallbackInfo<v8::Value> const& args) {
  TRI_V8_TRY_CATCH_BEGIN(isolate);
  v8::HandleScope scope(isolate);

  TRI_GET_GLOBALS();

  if (v8g->_vocbase == nullptr) {
    TRI_V8_THROW_EXCEPTION_MEMORY();
  }

  
  if (args.Length() != 1) {
    TRI_V8_THROW_EXCEPTION_USAGE("debugShouldFailAt(<point>)");
  }

  std::string const point = TRI_ObjectToString(isolate, args[0]);

  TRI_V8_RETURN_BOOL(TRI_ShouldFailDebugging(point.c_str()));

  TRI_V8_TRY_CATCH_END }











static void JS_DebugRemoveFailAt( v8::FunctionCallbackInfo<v8::Value> const& args) {
  TRI_V8_TRY_CATCH_BEGIN(isolate);
  v8::HandleScope scope(isolate);

  TRI_GET_GLOBALS();

  if (v8g->_vocbase == nullptr) {
    TRI_V8_THROW_EXCEPTION_MEMORY();
  }
  std::string dbname(v8g->_vocbase->name());

  
  if (args.Length() != 1) {
    TRI_V8_THROW_EXCEPTION_USAGE("debugRemoveFailAt(<point>)");
  }

  std::string const point = TRI_ObjectToString(isolate, args[0]);

  TRI_RemoveFailurePointDebugging(point.c_str());

  if (ServerState::instance()->isCoordinator()) {
    auto res = clusterSendToAllServers( isolate, dbname, "_admin/debug/failat/" + StringUtils::urlEncode(point), arangodb::rest::RequestType::DELETE_REQ, "");

    if (res != TRI_ERROR_NO_ERROR) {
      TRI_V8_THROW_EXCEPTION(res);
    }
  }

  TRI_V8_RETURN_UNDEFINED();
  TRI_V8_TRY_CATCH_END }










static void JS_DebugClearFailAt( v8::FunctionCallbackInfo<v8::Value> const& args) {
  TRI_V8_TRY_CATCH_BEGIN(isolate);
  v8::HandleScope scope(isolate);

  
  if (args.Length() != 0) {
    TRI_V8_THROW_EXCEPTION_USAGE("debugClearFailAt()");
  }



  TRI_ClearFailurePointsDebugging();

  if (ServerState::instance()->isCoordinator()) {
    TRI_GET_GLOBALS();

    if (v8g->_vocbase == nullptr) {
      TRI_V8_THROW_EXCEPTION_MEMORY();
    }
    std::string dbname(v8g->_vocbase->name());

    auto res = clusterSendToAllServers(isolate, dbname, "_admin/debug/failat", arangodb::rest::RequestType::DELETE_REQ, "");

    if (res != TRI_ERROR_NO_ERROR) {
      TRI_V8_THROW_EXCEPTION(res);
    }
  }



  TRI_V8_RETURN_UNDEFINED();
  TRI_V8_TRY_CATCH_END }

static void JS_ClusterApiJwtPolicy( v8::FunctionCallbackInfo<v8::Value> const& args) {
  TRI_V8_TRY_CATCH_BEGIN(isolate)
  v8::HandleScope scope(isolate);

  TRI_GET_GLOBALS();

  ClusterFeature const& cf = v8g->_server.getFeature<ClusterFeature>();
  std::string const& policy = cf.apiJwtPolicy();
  TRI_V8_RETURN_STD_STRING(policy);

  TRI_V8_TRY_CATCH_END }

static void JS_IsFoxxApiDisabled( v8::FunctionCallbackInfo<v8::Value> const& args) {
  TRI_V8_TRY_CATCH_BEGIN(isolate)
  v8::HandleScope scope(isolate);

  TRI_GET_GLOBALS();
  ServerSecurityFeature& security = v8g->_server.getFeature<ServerSecurityFeature>();
  TRI_V8_RETURN_BOOL(security.isFoxxApiDisabled());

  TRI_V8_TRY_CATCH_END }

static void JS_IsFoxxStoreDisabled( v8::FunctionCallbackInfo<v8::Value> const& args) {
  TRI_V8_TRY_CATCH_BEGIN(isolate)
  v8::HandleScope scope(isolate);

  TRI_GET_GLOBALS();
  ServerSecurityFeature& security = v8g->_server.getFeature<ServerSecurityFeature>();
  TRI_V8_RETURN_BOOL(security.isFoxxStoreDisabled());

  TRI_V8_TRY_CATCH_END }

static void JS_RunInRestrictedContext( v8::FunctionCallbackInfo<v8::Value> const& args) {
  TRI_V8_TRY_CATCH_BEGIN(isolate)
  v8::HandleScope scope(isolate);

  if (args.Length() != 1 || !args[0]->IsFunction()) {
    TRI_V8_THROW_EXCEPTION_USAGE("runInRestrictedContext(<function>)");
  }

  v8::Handle<v8::Function> action = v8::Local<v8::Function>::Cast(args[0]);
  if (action.IsEmpty()) {
    THROW_ARANGO_EXCEPTION_MESSAGE( TRI_ERROR_INTERNAL, "cannot cannot function instance for runInRestrictedContext");

  }

  TRI_GET_GLOBALS();

  {
    
    auto oldContext = v8g->_securityContext;

    
    v8g->_securityContext = JavaScriptSecurityContext::createRestrictedContext();

    
    auto guard = scopeGuard( [&oldContext, &v8g]() noexcept { v8g->_securityContext = oldContext; });

    v8::Handle<v8::Object> current = isolate->GetCurrentContext()->Global();
    v8::Handle<v8::Value> callArgs[] = {v8::Null(isolate)};
    v8::Handle<v8::Value> rv = action->Call(TRI_IGETC, current, 0, callArgs)
                                   .FromMaybe(v8::Local<v8::Value>());
    TRI_V8_RETURN(rv);
  }

  TRI_V8_TRY_CATCH_END }





static void JS_CreateHotbackup( v8::FunctionCallbackInfo<v8::Value> const& args) {
  TRI_V8_TRY_CATCH_BEGIN(isolate);

  if (args.Length() != 1 || !args[0]->IsObject()) {
    TRI_V8_THROW_EXCEPTION_USAGE("createHotbackup(obj)");
  }
  VPackBuilder obj;
  try {
    TRI_V8ToVPack(isolate, obj, args[0], false, true);
  } catch (std::exception const& e) {
    TRI_V8_THROW_EXCEPTION_USAGE( std::string( "createHotbackup(obj): could not convert body to object: ") + e.what());


  }

  VPackBuilder result;

  TRI_GET_GLOBALS();
  HotBackup h(v8g->_server);
  auto r = h.execute("create", obj.slice(), result);
  if (r.fail()) {
    TRI_V8_THROW_EXCEPTION_MESSAGE(r.errorNumber(), r.errorMessage());
  }

  result.add(obj.slice());


  TRI_V8_RETURN(TRI_VPackToV8(isolate, result.slice()));
  TRI_V8_TRY_CATCH_END }

void TRI_InitV8ServerUtils(v8::Isolate* isolate) {
  TRI_AddGlobalFunctionVocbase( isolate, TRI_V8_ASCII_STRING(isolate, "SYS_CLUSTER_API_JWT_POLICY"), JS_ClusterApiJwtPolicy, true);

  TRI_AddGlobalFunctionVocbase( isolate, TRI_V8_ASCII_STRING(isolate, "SYS_IS_FOXX_API_DISABLED"), JS_IsFoxxApiDisabled, true);

  TRI_AddGlobalFunctionVocbase( isolate, TRI_V8_ASCII_STRING(isolate, "SYS_IS_FOXX_STORE_DISABLED"), JS_IsFoxxStoreDisabled, true);

  TRI_AddGlobalFunctionVocbase( isolate, TRI_V8_ASCII_STRING(isolate, "SYS_RUN_IN_RESTRICTED_CONTEXT"), JS_RunInRestrictedContext, true);


  TRI_AddGlobalFunctionVocbase( isolate, TRI_V8_ASCII_STRING(isolate, "SYS_CREATE_HOTBACKUP"), JS_CreateHotbackup);


  
  TRI_AddGlobalFunctionVocbase( isolate, TRI_V8_ASCII_STRING(isolate, "SYS_DEBUG_CLEAR_FAILAT"), JS_DebugClearFailAt);



  TRI_AddGlobalFunctionVocbase( isolate, TRI_V8_ASCII_STRING(isolate, "SYS_DEBUG_TERMINATE"), JS_DebugTerminate);

  TRI_AddGlobalFunctionVocbase( isolate, TRI_V8_ASCII_STRING(isolate, "SYS_DEBUG_SET_FAILAT"), JS_DebugSetFailAt);

  TRI_AddGlobalFunctionVocbase( isolate, TRI_V8_ASCII_STRING(isolate, "SYS_DEBUG_REMOVE_FAILAT"), JS_DebugRemoveFailAt);

  TRI_AddGlobalFunctionVocbase( isolate, TRI_V8_ASCII_STRING(isolate, "SYS_DEBUG_SHOULD_FAILAT"), JS_DebugShouldFailAt);



  
  TRI_GET_GLOBALS();
  FoxxFeature& foxxFeature = v8g->_server.getFeature<FoxxFeature>();

  isolate->GetCurrentContext()
      ->Global()
      ->DefineOwnProperty( TRI_IGETC, TRI_V8_ASCII_STRING(isolate, "FOXX_QUEUES_POLL_INTERVAL"), v8::Number::New(isolate, foxxFeature.pollInterval()), v8::ReadOnly)

      .FromMaybe(false);  

  isolate->GetCurrentContext()
      ->Global()
      ->DefineOwnProperty( TRI_IGETC, TRI_V8_ASCII_STRING(isolate, "FOXX_STARTUP_WAIT_FOR_SELF_HEAL"), v8::Boolean::New(isolate, foxxFeature.startupWaitForSelfHeal()), v8::ReadOnly)



      .FromMaybe(false);  
}
