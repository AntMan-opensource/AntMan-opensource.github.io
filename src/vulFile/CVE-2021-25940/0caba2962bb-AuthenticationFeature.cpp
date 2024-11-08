












































using namespace arangodb::options;

namespace arangodb {

AuthenticationFeature* AuthenticationFeature::INSTANCE = nullptr;

AuthenticationFeature::AuthenticationFeature(application_features::ApplicationServer& server)
    : ApplicationFeature(server, "Authentication"), _userManager(nullptr), _authCache(nullptr), _authenticationUnixSockets(true), _authenticationSystemOnly(true), _localAuthentication(true), _active(true), _authenticationTimeout(0.0) {






  setOptional(false);
  startsAfter<application_features::BasicFeaturePhaseServer>();


  startsAfter<LdapFeature>();

}

void AuthenticationFeature::collectOptions(std::shared_ptr<ProgramOptions> options) {
  options->addOldOption("server.disable-authentication", "server.authentication");
  options->addOldOption("server.disable-authentication-unix-sockets", "server.authentication-unix-sockets");
  options->addOldOption("server.authenticate-system-only", "server.authentication-system-only");
  options->addOldOption("server.allow-method-override", "http.allow-method-override");
  options->addOldOption("server.hide-product-header", "http.hide-product-header");
  options->addOldOption("server.keep-alive-timeout", "http.keep-alive-timeout");
  options->addOldOption("server.default-api-compatibility", "");
  options->addOldOption("no-server", "server.rest-server");

  options->addOption("--server.authentication", "enable authentication for ALL client requests", new BooleanParameter(&_active));


  options->addOption( "--server.authentication-timeout", "timeout for the authentication cache in seconds (0 = indefinitely)", new DoubleParameter(&_authenticationTimeout));



  options->addOption("--server.local-authentication", "enable authentication using the local user database", new BooleanParameter(&_localAuthentication));


  options->addOption( "--server.authentication-system-only", "use HTTP authentication only for requests to /_api and /_admin", new BooleanParameter(&_authenticationSystemOnly));




  options->addOption("--server.authentication-unix-sockets", "authentication for requests via UNIX domain sockets", new BooleanParameter(&_authenticationUnixSockets));



  
  options ->addOption("--server.jwt-secret", "secret to use when doing jwt authentication", new StringParameter(&_jwtSecretProgramOption))


      .setDeprecatedIn(30322)
      .setDeprecatedIn(30402);

  options->addOption( "--server.jwt-secret-keyfile", "file containing jwt secret to use when doing jwt authentication.", new StringParameter(&_jwtSecretKeyfileProgramOption));



  options->addOption( "--server.jwt-secret-folder", "folder containing one or more jwt secret files to use for jwt " "authentication. Files are sorted alphabetically: First secret " "is used for signing + verifying JWT tokens. The latter secrets " "are only used for verifying.", new StringParameter(&_jwtSecretFolderProgramOption), arangodb::options::makeDefaultFlags(arangodb::options::Flags::Enterprise))






      .setIntroducedIn(30700);
}

void AuthenticationFeature::validateOptions(std::shared_ptr<ProgramOptions> options) {
  if (!_jwtSecretKeyfileProgramOption.empty() && !_jwtSecretFolderProgramOption.empty()) {
    LOG_TOPIC("d3515", FATAL, Logger::STARTUP)
        << "please specify either '--server.jwt-" "secret-keyfile' or '--server.jwt-secret-folder' but not both.";
    FATAL_ERROR_EXIT();
  }

  if (!_jwtSecretKeyfileProgramOption.empty() || !_jwtSecretFolderProgramOption.empty()) {
    Result res = loadJwtSecretsFromFile();
    if (res.fail()) {
      LOG_TOPIC("d3617", FATAL, Logger::STARTUP) << res.errorMessage();
      FATAL_ERROR_EXIT();
    }
  }
  if (!_jwtSecretProgramOption.empty()) {
    if (_jwtSecretProgramOption.length() > _maxSecretLength) {
      LOG_TOPIC("9abfc", FATAL, arangodb::Logger::STARTUP)
          << "Given JWT secret too long. Max length is " << _maxSecretLength;
      FATAL_ERROR_EXIT();
    }
  }

  if (options->processingResult().touched("server.jwt-secret")) {
    LOG_TOPIC("1aaae", WARN, arangodb::Logger::AUTHENTICATION)
        << "--server.jwt-secret is insecure. Use --server.jwt-secret-keyfile " "instead.";
  }
}

void AuthenticationFeature::prepare() {
  TRI_ASSERT(isEnabled());
  TRI_ASSERT(_userManager == nullptr);

  ServerState::RoleEnum role = ServerState::instance()->getRole();
  TRI_ASSERT(role != ServerState::RoleEnum::ROLE_UNDEFINED);
  if (ServerState::isSingleServer(role) || ServerState::isCoordinator(role)) {

    if (server().getFeature<LdapFeature>().isEnabled()) {
      _userManager.reset( new auth::UserManager(server(), std::make_unique<LdapAuthenticationHandler>( server().getFeature<LdapFeature>())));

    } else {
      _userManager.reset(new auth::UserManager(server()));
    }

    _userManager.reset(new auth::UserManager(server()));

  } else {
    LOG_TOPIC("713c0", DEBUG, Logger::AUTHENTICATION)
        << "Not creating user manager";
  }

  TRI_ASSERT(_authCache == nullptr);
  _authCache.reset(new auth::TokenCache(_userManager.get(), _authenticationTimeout));

  if (_jwtSecretProgramOption.empty()) {
    LOG_TOPIC("43396", INFO, Logger::AUTHENTICATION)
        << "Jwt secret not specified, generating...";
    uint16_t m = 254;
    for (size_t i = 0; i < _maxSecretLength; i++) {
      _jwtSecretProgramOption += static_cast<char>(1 + RandomGenerator::interval(m));
    }
  }


  _authCache->setJwtSecrets(_jwtSecretProgramOption, _jwtPassiveSecrets);

  _authCache->setJwtSecret(_jwtSecretProgramOption);


  INSTANCE = this;
}

void AuthenticationFeature::start() {
  TRI_ASSERT(isEnabled());
  std::ostringstream out;

  out << "Authentication is turned " << (_active ? "on" : "off");

  if (_active && _authenticationSystemOnly) {
    out << " (system only)";
  }


  out << ", authentication for unix sockets is turned " << (_authenticationUnixSockets ? "on" : "off");


  LOG_TOPIC("3844e", INFO, arangodb::Logger::AUTHENTICATION) << out.str();
}

void AuthenticationFeature::unprepare() { INSTANCE = nullptr; }

bool AuthenticationFeature::hasUserdefinedJwt() const {
  std::lock_guard<std::mutex> guard(_jwtSecretsLock);
  return !_jwtSecretProgramOption.empty();
}


std::string AuthenticationFeature::jwtActiveSecret() const {
  std::lock_guard<std::mutex> guard(_jwtSecretsLock);
  return _jwtSecretProgramOption;
}



std::pair<std::string, std::vector<std::string>> AuthenticationFeature::jwtSecrets() const {
  std::lock_guard<std::mutex> guard(_jwtSecretsLock);
  return {_jwtSecretProgramOption, _jwtPassiveSecrets};
}


Result AuthenticationFeature::loadJwtSecretsFromFile() {
  std::lock_guard<std::mutex> guard(_jwtSecretsLock);
  if (!_jwtSecretFolderProgramOption.empty()) {
    return loadJwtSecretFolder();
  } else if (!_jwtSecretKeyfileProgramOption.empty()) {
    return loadJwtSecretKeyfile();
  }
  return Result(TRI_ERROR_BAD_PARAMETER, "no JWT secret file was specified");
}


Result AuthenticationFeature::loadJwtSecretKeyfile() {
  try {
    
    
    
    
    std::string contents = basics::FileUtils::slurp(_jwtSecretKeyfileProgramOption);
    _jwtSecretProgramOption = basics::StringUtils::trim(contents, " \t\n\r");
  } catch (std::exception const& ex) {
    std::string msg("unable to read content of jwt-secret file '");
    msg.append(_jwtSecretKeyfileProgramOption)
        .append("': ")
        .append(ex.what())
        .append(". please make sure the file/directory is readable for the ")
        .append("arangod process and user");
    return Result(TRI_ERROR_CANNOT_READ_FILE, std::move(msg));
  }
  return Result();
}


Result AuthenticationFeature::loadJwtSecretFolder() try {
  TRI_ASSERT(!_jwtSecretFolderProgramOption.empty());

  LOG_TOPIC("4922f", INFO, arangodb::Logger::AUTHENTICATION)
      << "loading JWT secrets from folder " << _jwtSecretFolderProgramOption;

  auto list = basics::FileUtils::listFiles(_jwtSecretFolderProgramOption);

  
  list.erase(std::remove_if(list.begin(), list.end(), [this](std::string const& file) {
        if (file.empty() || file[0] == '.') {
          return true;
        }
        if (file.size() >= 4 && file.substr(file.size() - 4, 4) == ".tmp") {
          return true;
        }
        auto p = basics::FileUtils::buildFilename(_jwtSecretFolderProgramOption, file);
        if (basics::FileUtils::isSymbolicLink(p)) {
          return true;
        }
        return false;
      }), list.end());

  if (list.empty()) {
    return Result(TRI_ERROR_BAD_PARAMETER, "empty JWT secrets directory");
  }

  auto slurpy = [&](std::string const& file) {
    auto p = basics::FileUtils::buildFilename(_jwtSecretFolderProgramOption, file);
    std::string contents = basics::FileUtils::slurp(p);
    return basics::StringUtils::trim(contents, " \t\n\r");
  };

  std::sort(std::begin(list), std::end(list));
  std::string activeSecret = slurpy(list[0]);

  const std::string msg = "Given JWT secret too long. Max length is 64";
  if (activeSecret.length() > _maxSecretLength) {
    return Result(TRI_ERROR_BAD_PARAMETER, msg);
  }


  std::vector<std::string> passiveSecrets;
  if (list.size() > 1) {
    list.erase(list.begin());
    for (auto const& file : list) {
      std::string secret = slurpy(file);
      if (secret.length() > _maxSecretLength) {
        return Result(TRI_ERROR_BAD_PARAMETER, msg);
      }
      if (!secret.empty()) {  
        passiveSecrets.push_back(std::move(secret));
      }
    }
  }
  _jwtPassiveSecrets = std::move(passiveSecrets);

  LOG_TOPIC("4a34f", INFO, arangodb::Logger::AUTHENTICATION)
      << "have " << _jwtPassiveSecrets.size() << " passive JWT secrets";


  _jwtSecretProgramOption = std::move(activeSecret);

  return Result();
} catch (basics::Exception const& ex) {
  std::string msg("unable to read content of jwt-secret-folder '");
  msg.append(_jwtSecretFolderProgramOption)
      .append("': ")
      .append(ex.what())
      .append(". please make sure the file/directory is readable for the ")
      .append("arangod process and user");
  return Result(TRI_ERROR_CANNOT_READ_FILE, std::move(msg));
}

}  
