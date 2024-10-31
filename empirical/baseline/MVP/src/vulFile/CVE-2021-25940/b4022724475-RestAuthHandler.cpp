




































using namespace arangodb;
using namespace arangodb::basics;
using namespace arangodb::rest;

RestAuthHandler::RestAuthHandler(application_features::ApplicationServer& server, GeneralRequest* request, GeneralResponse* response)
    : RestVocbaseBaseHandler(server, request, response), _validFor(60 * 60 * 24 * 30) {}

std::string RestAuthHandler::generateJwt(std::string const& username, std::string const& password) {
  AuthenticationFeature* af = AuthenticationFeature::instance();
  TRI_ASSERT(af != nullptr);
  return fuerte::jwt::generateUserToken(af->tokenCache().jwtSecret(), username, _validFor);
}

RestStatus RestAuthHandler::execute() {
  auto const type = _request->requestType();
  if (type != rest::RequestType::POST) {
    generateError(rest::ResponseCode::METHOD_NOT_ALLOWED, TRI_ERROR_HTTP_METHOD_NOT_ALLOWED);
    return RestStatus::DONE;
  }

  bool parseSuccess = false;
  VPackSlice slice = this->parseVPackBody(parseSuccess);
  if (!parseSuccess) { 
    return RestStatus::DONE;
  }

  if (!slice.isObject()) {
    return badRequest();
  }

  VPackSlice usernameSlice = slice.get("username");
  VPackSlice passwordSlice = slice.get("password");

  if (!usernameSlice.isString() || !passwordSlice.isString()) {
    return badRequest();
  }

  _username = usernameSlice.copyString();
  std::string const password = passwordSlice.copyString();

  auth::UserManager* um = AuthenticationFeature::instance()->userManager();
  if (um == nullptr) {
    std::string msg = "This server does not support users";
    LOG_TOPIC("2e7d4", ERR, Logger::AUTHENTICATION) << msg;
    generateError(rest::ResponseCode::UNAUTHORIZED, TRI_ERROR_HTTP_UNAUTHORIZED, msg);
  } else if (um->checkPassword(_username, password)) {
    VPackBuilder resultBuilder;
    {
      VPackObjectBuilder b(&resultBuilder);
      std::string jwt = generateJwt(_username, password);
      resultBuilder.add("jwt", VPackValue(jwt));
    }

    _isValid = true;
    generateDocument(resultBuilder.slice(), true, &VPackOptions::Defaults);
  } else {
    
    generateError(rest::ResponseCode::UNAUTHORIZED, TRI_ERROR_HTTP_UNAUTHORIZED, "Wrong credentials");
  }
  return RestStatus::DONE;
}

RestStatus RestAuthHandler::badRequest() {
  generateError(rest::ResponseCode::BAD, TRI_ERROR_HTTP_BAD_PARAMETER, "invalid JSON");
  return RestStatus::DONE;
}

void RestAuthHandler::shutdownExecute(bool isFinalized) noexcept {
  try {
    if (_isValid) {
      events::LoggedIn(*_request, _username);
    } else {
      events::CredentialsBad(*_request, _username);
    }
  } catch (...) {
  }
  RestVocbaseBaseHandler::shutdownExecute(isFinalized);
}
