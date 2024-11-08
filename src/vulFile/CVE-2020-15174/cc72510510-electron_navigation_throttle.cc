








namespace electron {

ElectronNavigationThrottle::ElectronNavigationThrottle( content::NavigationHandle* navigation_handle)
    : content::NavigationThrottle(navigation_handle) {}

ElectronNavigationThrottle::~ElectronNavigationThrottle() = default;

const char* ElectronNavigationThrottle::GetNameForLogging() {
  return "ElectronNavigationThrottle";
}

content::NavigationThrottle::ThrottleCheckResult ElectronNavigationThrottle::WillRedirectRequest() {
  auto* handle = navigation_handle();
  auto* contents = handle->GetWebContents();
  if (!contents) {
    NOTREACHED();
    return PROCEED;
  }

  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  v8::HandleScope scope(isolate);
  auto api_contents = electron::api::WebContents::From(isolate, contents);
  if (api_contents.IsEmpty()) {
    
    return PROCEED;
  }

  if (api_contents->EmitNavigationEvent("will-redirect", handle)) {
    return CANCEL;
  }
  return PROCEED;
}

}  
