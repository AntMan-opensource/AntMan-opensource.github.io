





























using namespace arangodb;
using namespace arangodb::basics;
using namespace arangodb::options;

ServerSecurityFeature::ServerSecurityFeature( application_features::ApplicationServer& server)
    : ApplicationFeature(server, "ServerSecurity"), _enableFoxxApi(true), _enableFoxxStore(true), _hardenedRestApi(false) {


  setOptional(false);
  startsAfter<application_features::GreetingsFeaturePhase>();
}

void ServerSecurityFeature::collectOptions( std::shared_ptr<ProgramOptions> options) {
  options ->addOption( "--server.harden", "lock down REST APIs that reveal version information or server " "internals for non-admin users", new BooleanParameter(&_hardenedRestApi))




      .setIntroducedIn(30500);

  options ->addOption("--foxx.api", "enables Foxx management REST APIs", new BooleanParameter(&_enableFoxxApi), arangodb::options::makeFlags( arangodb::options::Flags::DefaultNoComponents, arangodb::options::Flags::OnCoordinator, arangodb::options::Flags::OnSingle))





      .setIntroducedIn(30500);
  options ->addOption("--foxx.store", "enables Foxx store in web interface", new BooleanParameter(&_enableFoxxStore), arangodb::options::makeFlags( arangodb::options::Flags::DefaultNoComponents, arangodb::options::Flags::OnCoordinator, arangodb::options::Flags::OnSingle))





      .setIntroducedIn(30500);
}

bool ServerSecurityFeature::isFoxxApiDisabled() const {
  return !_enableFoxxApi;
}

bool ServerSecurityFeature::isFoxxStoreDisabled() const {
  return !_enableFoxxStore || !_enableFoxxApi;
}

bool ServerSecurityFeature::isRestApiHardened() const {
  return _hardenedRestApi;
}

bool ServerSecurityFeature::canAccessHardenedApi() const {
  bool allowAccess = !isRestApiHardened();

  if (!allowAccess) {
    ExecContext const& exec = ExecContext::current();
    if (exec.isAdminUser()) {
      
      
      allowAccess = true;
    }
  }
  return allowAccess;
}
