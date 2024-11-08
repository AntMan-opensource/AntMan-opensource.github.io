




























































































































































































namespace gin {


template <> struct Converter<printing::mojom::MarginType> {
  static bool FromV8(v8::Isolate* isolate, v8::Local<v8::Value> val, printing::mojom::MarginType* out) {

    std::string type;
    if (ConvertFromV8(isolate, val, &type)) {
      if (type == "default") {
        *out = printing::mojom::MarginType::kDefaultMargins;
        return true;
      }
      if (type == "none") {
        *out = printing::mojom::MarginType::kNoMargins;
        return true;
      }
      if (type == "printableArea") {
        *out = printing::mojom::MarginType::kPrintableAreaMargins;
        return true;
      }
      if (type == "custom") {
        *out = printing::mojom::MarginType::kCustomMargins;
        return true;
      }
    }
    return false;
  }
};

template <> struct Converter<printing::mojom::DuplexMode> {
  static bool FromV8(v8::Isolate* isolate, v8::Local<v8::Value> val, printing::mojom::DuplexMode* out) {

    std::string mode;
    if (ConvertFromV8(isolate, val, &mode)) {
      if (mode == "simplex") {
        *out = printing::mojom::DuplexMode::kSimplex;
        return true;
      }
      if (mode == "longEdge") {
        *out = printing::mojom::DuplexMode::kLongEdge;
        return true;
      }
      if (mode == "shortEdge") {
        *out = printing::mojom::DuplexMode::kShortEdge;
        return true;
      }
    }
    return false;
  }
};



template <> struct Converter<WindowOpenDisposition> {
  static v8::Local<v8::Value> ToV8(v8::Isolate* isolate, WindowOpenDisposition val) {
    std::string disposition = "other";
    switch (val) {
      case WindowOpenDisposition::CURRENT_TAB:
        disposition = "default";
        break;
      case WindowOpenDisposition::NEW_FOREGROUND_TAB:
        disposition = "foreground-tab";
        break;
      case WindowOpenDisposition::NEW_BACKGROUND_TAB:
        disposition = "background-tab";
        break;
      case WindowOpenDisposition::NEW_POPUP:
      case WindowOpenDisposition::NEW_WINDOW:
        disposition = "new-window";
        break;
      case WindowOpenDisposition::SAVE_TO_DISK:
        disposition = "save-to-disk";
        break;
      default:
        break;
    }
    return gin::ConvertToV8(isolate, disposition);
  }
};

template <> struct Converter<content::SavePageType> {
  static bool FromV8(v8::Isolate* isolate, v8::Local<v8::Value> val, content::SavePageType* out) {

    std::string save_type;
    if (!ConvertFromV8(isolate, val, &save_type))
      return false;
    save_type = base::ToLowerASCII(save_type);
    if (save_type == "htmlonly") {
      *out = content::SAVE_PAGE_TYPE_AS_ONLY_HTML;
    } else if (save_type == "htmlcomplete") {
      *out = content::SAVE_PAGE_TYPE_AS_COMPLETE_HTML;
    } else if (save_type == "mhtml") {
      *out = content::SAVE_PAGE_TYPE_AS_MHTML;
    } else {
      return false;
    }
    return true;
  }
};

template <> struct Converter<electron::api::WebContents::Type> {
  static v8::Local<v8::Value> ToV8(v8::Isolate* isolate, electron::api::WebContents::Type val) {
    using Type = electron::api::WebContents::Type;
    std::string type;
    switch (val) {
      case Type::kBackgroundPage:
        type = "backgroundPage";
        break;
      case Type::kBrowserWindow:
        type = "window";
        break;
      case Type::kBrowserView:
        type = "browserView";
        break;
      case Type::kRemote:
        type = "remote";
        break;
      case Type::kWebView:
        type = "webview";
        break;
      case Type::kOffScreen:
        type = "offscreen";
        break;
      default:
        break;
    }
    return gin::ConvertToV8(isolate, type);
  }

  static bool FromV8(v8::Isolate* isolate, v8::Local<v8::Value> val, electron::api::WebContents::Type* out) {

    using Type = electron::api::WebContents::Type;
    std::string type;
    if (!ConvertFromV8(isolate, val, &type))
      return false;
    if (type == "backgroundPage") {
      *out = Type::kBackgroundPage;
    } else if (type == "browserView") {
      *out = Type::kBrowserView;
    } else if (type == "webview") {
      *out = Type::kWebView;

    } else if (type == "offscreen") {
      *out = Type::kOffScreen;

    } else {
      return false;
    }
    return true;
  }
};

template <> struct Converter<scoped_refptr<content::DevToolsAgentHost>> {
  static v8::Local<v8::Value> ToV8( v8::Isolate* isolate, const scoped_refptr<content::DevToolsAgentHost>& val) {

    gin_helper::Dictionary dict(isolate, v8::Object::New(isolate));
    dict.Set("id", val->GetId());
    dict.Set("url", val->GetURL().spec());
    return dict.GetHandle();
  }
};

}  

namespace electron {

namespace api {

namespace {

base::IDMap<WebContents*>& GetAllWebContents() {
  static base::NoDestructor<base::IDMap<WebContents*>> s_all_web_contents;
  return *s_all_web_contents;
}


void OnCapturePageDone(gin_helper::Promise<gfx::Image> promise, const SkBitmap& bitmap) {
  
  promise.Resolve(gfx::Image::CreateFrom1xBitmap(bitmap));
}

base::Optional<base::TimeDelta> GetCursorBlinkInterval() {

  base::TimeDelta interval;
  if (ui::TextInsertionCaretBlinkPeriod(&interval))
    return interval;

  if (auto* linux_ui = views::LinuxUI::instance())
    return linux_ui->GetCursorBlinkInterval();

  const auto system_msec = ::GetCaretBlinkTime();
  if (system_msec != 0) {
    return (system_msec == INFINITE)
               ? base::TimeDelta()
               : base::TimeDelta::FromMilliseconds(system_msec);
  }

  return base::nullopt;
}





bool IsDeviceNameValid(const base::string16& device_name) {

  base::ScopedCFTypeRef<CFStringRef> new_printer_id( base::SysUTF16ToCFStringRef(device_name));
  PMPrinter new_printer = PMPrinterCreateFromPrinterID(new_printer_id.get());
  bool printer_exists = new_printer != nullptr;
  PMRelease(new_printer);
  return printer_exists;

  printing::ScopedPrinterHandle printer;
  return printer.OpenPrinterWithName(device_name.c_str());

  return true;
}

base::string16 GetDefaultPrinterAsync() {
  base::ScopedBlockingCall scoped_blocking_call(FROM_HERE, base::BlockingType::MAY_BLOCK);

  scoped_refptr<printing::PrintBackend> print_backend = printing::PrintBackend::CreateInstance( g_browser_process->GetApplicationLocale());

  std::string printer_name = print_backend->GetDefaultPrinterName();

  
  
  
  if (printer_name.empty()) {
    printing::PrinterList printers;
    print_backend->EnumeratePrinters(&printers);
    if (!printers.empty())
      printer_name = printers.front().printer_name;
  }
  return base::UTF8ToUTF16(printer_name);
}


struct UserDataLink : public base::SupportsUserData::Data {
  explicit UserDataLink(base::WeakPtr<WebContents> contents)
      : web_contents(contents) {}

  base::WeakPtr<WebContents> web_contents;
};
const void* kElectronApiWebContentsKey = &kElectronApiWebContentsKey;

const char kRootName[] = "<root>";

struct FileSystem {
  FileSystem() = default;
  FileSystem(const std::string& type, const std::string& file_system_name, const std::string& root_url, const std::string& file_system_path)


      : type(type), file_system_name(file_system_name), root_url(root_url), file_system_path(file_system_path) {}



  std::string type;
  std::string file_system_name;
  std::string root_url;
  std::string file_system_path;
};

std::string RegisterFileSystem(content::WebContents* web_contents, const base::FilePath& path) {
  auto* isolated_context = storage::IsolatedContext::GetInstance();
  std::string root_name(kRootName);
  storage::IsolatedContext::ScopedFSHandle file_system = isolated_context->RegisterFileSystemForPath( storage::kFileSystemTypeNativeLocal, std::string(), path, &root_name);


  content::ChildProcessSecurityPolicy* policy = content::ChildProcessSecurityPolicy::GetInstance();
  content::RenderViewHost* render_view_host = web_contents->GetRenderViewHost();
  int renderer_id = render_view_host->GetProcess()->GetID();
  policy->GrantReadFileSystem(renderer_id, file_system.id());
  policy->GrantWriteFileSystem(renderer_id, file_system.id());
  policy->GrantCreateFileForFileSystem(renderer_id, file_system.id());
  policy->GrantDeleteFromFileSystem(renderer_id, file_system.id());

  if (!policy->CanReadFile(renderer_id, path))
    policy->GrantReadFile(renderer_id, path);

  return file_system.id();
}

FileSystem CreateFileSystemStruct(content::WebContents* web_contents, const std::string& file_system_id, const std::string& file_system_path, const std::string& type) {


  const GURL origin = web_contents->GetURL().GetOrigin();
  std::string file_system_name = storage::GetIsolatedFileSystemName(origin, file_system_id);
  std::string root_url = storage::GetIsolatedFileSystemRootURIString( origin, file_system_id, kRootName);
  return FileSystem(type, file_system_name, root_url, file_system_path);
}

std::unique_ptr<base::DictionaryValue> CreateFileSystemValue( const FileSystem& file_system) {
  std::unique_ptr<base::DictionaryValue> file_system_value( new base::DictionaryValue());
  file_system_value->SetString("type", file_system.type);
  file_system_value->SetString("fileSystemName", file_system.file_system_name);
  file_system_value->SetString("rootURL", file_system.root_url);
  file_system_value->SetString("fileSystemPath", file_system.file_system_path);
  return file_system_value;
}

void WriteToFile(const base::FilePath& path, const std::string& content) {
  base::ScopedBlockingCall scoped_blocking_call(FROM_HERE, base::BlockingType::WILL_BLOCK);
  DCHECK(!path.empty());

  base::WriteFile(path, content.data(), content.size());
}

void AppendToFile(const base::FilePath& path, const std::string& content) {
  base::ScopedBlockingCall scoped_blocking_call(FROM_HERE, base::BlockingType::WILL_BLOCK);
  DCHECK(!path.empty());

  base::AppendToFile(path, content.data(), content.size());
}

PrefService* GetPrefService(content::WebContents* web_contents) {
  auto* context = web_contents->GetBrowserContext();
  return static_cast<electron::ElectronBrowserContext*>(context)->prefs();
}

std::map<std::string, std::string> GetAddedFileSystemPaths( content::WebContents* web_contents) {
  auto* pref_service = GetPrefService(web_contents);
  const base::DictionaryValue* file_system_paths_value = pref_service->GetDictionary(prefs::kDevToolsFileSystemPaths);
  std::map<std::string, std::string> result;
  if (file_system_paths_value) {
    base::DictionaryValue::Iterator it(*file_system_paths_value);
    for (; !it.IsAtEnd(); it.Advance()) {
      std::string type = it.value().is_string() ? it.value().GetString() : std::string();
      result[it.key()] = type;
    }
  }
  return result;
}

bool IsDevToolsFileSystemAdded(content::WebContents* web_contents, const std::string& file_system_path) {
  auto file_system_paths = GetAddedFileSystemPaths(web_contents);
  return file_system_paths.find(file_system_path) != file_system_paths.end();
}

}  



WebContents::Type GetTypeFromViewType(extensions::ViewType view_type) {
  switch (view_type) {
    case extensions::VIEW_TYPE_EXTENSION_BACKGROUND_PAGE:
      return WebContents::Type::kBackgroundPage;

    case extensions::VIEW_TYPE_APP_WINDOW:
    case extensions::VIEW_TYPE_COMPONENT:
    case extensions::VIEW_TYPE_EXTENSION_DIALOG:
    case extensions::VIEW_TYPE_EXTENSION_POPUP:
    case extensions::VIEW_TYPE_BACKGROUND_CONTENTS:
    case extensions::VIEW_TYPE_EXTENSION_GUEST:
    case extensions::VIEW_TYPE_TAB_CONTENTS:
    case extensions::VIEW_TYPE_INVALID:
      return WebContents::Type::kRemote;
  }
}



WebContents::WebContents(v8::Isolate* isolate, content::WebContents* web_contents)
    : content::WebContentsObserver(web_contents), type_(Type::kRemote), id_(GetAllWebContents().Add(this)), devtools_file_system_indexer_(new DevToolsFileSystemIndexer), file_task_runner_( base::ThreadPool::CreateSequencedTaskRunner({base::MayBlock()})), weak_factory_(this) {






  
  extensions::ViewType view_type = extensions::GetViewType(web_contents);
  if (view_type != extensions::VIEW_TYPE_INVALID) {
    InitWithExtensionView(isolate, web_contents, view_type);
  }

  extensions::ElectronExtensionWebContentsObserver::CreateForWebContents( web_contents);
  script_executor_.reset(new extensions::ScriptExecutor(web_contents));


  auto session = Session::CreateFrom(isolate, GetBrowserContext());
  session_.Reset(isolate, session.ToV8());

  web_contents->SetUserAgentOverride(blink::UserAgentOverride::UserAgentOnly( GetBrowserContext()->GetUserAgent()), false);

  web_contents->SetUserData(kElectronApiWebContentsKey, std::make_unique<UserDataLink>(GetWeakPtr()));
  InitZoomController(web_contents, gin::Dictionary::CreateEmpty(isolate));

  registry_.AddInterface(base::BindRepeating(&WebContents::BindElectronBrowser, base::Unretained(this)));
  receivers_.set_disconnect_handler(base::BindRepeating( &WebContents::OnElectronBrowserConnectionError, base::Unretained(this)));
}

WebContents::WebContents(v8::Isolate* isolate, std::unique_ptr<content::WebContents> web_contents, Type type)

    : content::WebContentsObserver(web_contents.get()), type_(type), id_(GetAllWebContents().Add(this)), devtools_file_system_indexer_(new DevToolsFileSystemIndexer), file_task_runner_( base::ThreadPool::CreateSequencedTaskRunner({base::MayBlock()})), weak_factory_(this) {





  DCHECK(type != Type::kRemote)
      << "Can't take ownership of a remote WebContents";
  auto session = Session::CreateFrom(isolate, GetBrowserContext());
  session_.Reset(isolate, session.ToV8());
  InitWithSessionAndOptions(isolate, std::move(web_contents), session, gin::Dictionary::CreateEmpty(isolate));
}

WebContents::WebContents(v8::Isolate* isolate, const gin_helper::Dictionary& options)
    : id_(GetAllWebContents().Add(this)), devtools_file_system_indexer_(new DevToolsFileSystemIndexer), file_task_runner_( base::ThreadPool::CreateSequencedTaskRunner({base::MayBlock()})), weak_factory_(this) {



  
  options.Get("backgroundThrottling", &background_throttling_);

  
  options.Get("type", &type_);


  bool b = false;
  if (options.Get(options::kOffscreen, &b) && b)
    type_ = Type::kOffScreen;


  
  options.Get("embedder", &embedder_);

  
  options.Get("devTools", &enable_devtools_);

  
  
  
  initially_shown_ = type_ != Type::kBrowserView;
  options.Get(options::kShow, &initially_shown_);

  
  std::string partition;
  gin::Handle<api::Session> session;
  if (options.Get("session", &session) && !session.IsEmpty()) {
  } else if (options.Get("partition", &partition)) {
    session = Session::FromPartition(isolate, partition);
  } else {
    
    session = Session::FromPartition(isolate, "");
  }
  session_.Reset(isolate, session.ToV8());

  std::unique_ptr<content::WebContents> web_contents;
  if (IsGuest()) {
    scoped_refptr<content::SiteInstance> site_instance = content::SiteInstance::CreateForURL(session->browser_context(), GURL("chrome-guest://fake-host"));

    content::WebContents::CreateParams params(session->browser_context(), site_instance);
    guest_delegate_ = std::make_unique<WebViewGuestDelegate>(embedder_->web_contents(), this);
    params.guest_delegate = guest_delegate_.get();


    if (embedder_ && embedder_->IsOffScreen()) {
      auto* view = new OffScreenWebContentsView( false, base::BindRepeating(&WebContents::OnPaint, base::Unretained(this)));

      params.view = view;
      params.delegate_view = view;

      web_contents = content::WebContents::Create(params);
      view->SetWebContents(web_contents.get());
    } else {

      web_contents = content::WebContents::Create(params);

    }
  } else if (IsOffScreen()) {
    bool transparent = false;
    options.Get("transparent", &transparent);

    content::WebContents::CreateParams params(session->browser_context());
    auto* view = new OffScreenWebContentsView( transparent, base::BindRepeating(&WebContents::OnPaint, base::Unretained(this)));

    params.view = view;
    params.delegate_view = view;

    web_contents = content::WebContents::Create(params);
    view->SetWebContents(web_contents.get());

  } else {
    content::WebContents::CreateParams params(session->browser_context());
    params.initially_hidden = !initially_shown_;
    web_contents = content::WebContents::Create(params);
  }

  InitWithSessionAndOptions(isolate, std::move(web_contents), session, options);
}

void WebContents::InitZoomController(content::WebContents* web_contents, const gin_helper::Dictionary& options) {
  WebContentsZoomController::CreateForWebContents(web_contents);
  zoom_controller_ = WebContentsZoomController::FromWebContents(web_contents);
  double zoom_factor;
  if (options.Get(options::kZoomFactor, &zoom_factor))
    zoom_controller_->SetDefaultZoomFactor(zoom_factor);
}

void WebContents::InitWithSessionAndOptions( v8::Isolate* isolate, std::unique_ptr<content::WebContents> owned_web_contents, gin::Handle<api::Session> session, const gin_helper::Dictionary& options) {



  Observe(owned_web_contents.get());
  
  
  
  InitWithWebContents(owned_web_contents.release(), session->browser_context(), IsGuest());

  inspectable_web_contents_->GetView()->SetDelegate(this);

  auto* prefs = web_contents()->GetMutableRendererPrefs();

  
  
  
  
  
  
  std::string accept_languages = g_browser_process->GetApplicationLocale() + ",";
  for (auto const& language : electron::GetPreferredLanguages()) {
    if (language == g_browser_process->GetApplicationLocale())
      continue;
    accept_languages += language + ",";
  }
  accept_languages.pop_back();
  prefs->accept_languages = accept_languages;


  
  static const base::NoDestructor<gfx::FontRenderParams> params( gfx::GetFontRenderParams(gfx::FontRenderParamsQuery(), nullptr));
  prefs->should_antialias_text = params->antialiasing;
  prefs->use_subpixel_positioning = params->subpixel_positioning;
  prefs->hinting = params->hinting;
  prefs->use_autohinter = params->autohinter;
  prefs->use_bitmaps = params->use_bitmaps;
  prefs->subpixel_rendering = params->subpixel_rendering;


  
  if (auto interval = GetCursorBlinkInterval())
    prefs->caret_blink_interval = *interval;

  
  
  
  if (!WebContentsPreferences::From(web_contents())) {
    new WebContentsPreferences(web_contents(), options);
  }
  
  web_contents()->NotifyPreferencesChanged();

  WebContentsPermissionHelper::CreateForWebContents(web_contents());
  SecurityStateTabHelper::CreateForWebContents(web_contents());
  InitZoomController(web_contents(), options);

  extensions::ElectronExtensionWebContentsObserver::CreateForWebContents( web_contents());
  script_executor_.reset(new extensions::ScriptExecutor(web_contents()));


  registry_.AddInterface(base::BindRepeating(&WebContents::BindElectronBrowser, base::Unretained(this)));
  receivers_.set_disconnect_handler(base::BindRepeating( &WebContents::OnElectronBrowserConnectionError, base::Unretained(this)));
  AutofillDriverFactory::CreateForWebContents(web_contents());

  web_contents()->SetUserAgentOverride(blink::UserAgentOverride::UserAgentOnly( GetBrowserContext()->GetUserAgent()), false);


  if (IsGuest()) {
    NativeWindow* owner_window = nullptr;
    if (embedder_) {
      
      auto* relay = NativeWindowRelay::FromWebContents(embedder_->web_contents());
      if (relay)
        owner_window = relay->GetNativeWindow();
    }
    if (owner_window)
      SetOwnerWindow(owner_window);
  }

  web_contents()->SetUserData(kElectronApiWebContentsKey, std::make_unique<UserDataLink>(GetWeakPtr()));
}


void WebContents::InitWithExtensionView(v8::Isolate* isolate, content::WebContents* web_contents, extensions::ViewType view_type) {

  
  type_ = GetTypeFromViewType(view_type);
  if (GetType() == Type::kRemote)
    return;

  
  Observe(web_contents);
  InitWithWebContents(web_contents, GetBrowserContext(), IsGuest());
  inspectable_web_contents_->GetView()->SetDelegate(this);
  SecurityStateTabHelper::CreateForWebContents(web_contents);
}


void WebContents::InitWithWebContents(content::WebContents* web_contents, ElectronBrowserContext* browser_context, bool is_guest) {

  browser_context_ = browser_context;
  web_contents->SetDelegate(this);


  PrintPreviewMessageHandler::CreateForWebContents(web_contents);
  printing::PrintViewManagerBasic::CreateForWebContents(web_contents);
  printing::CreateCompositeClientIfNeeded(web_contents, browser_context->GetUserAgent());



  pdf::PDFWebContentsHelper::CreateForWebContentsWithClient( web_contents, std::make_unique<ElectronPDFWebContentsHelperClient>());


  
  auto* web_preferences = WebContentsPreferences::From(web_contents);
  offscreen_ = web_preferences && web_preferences->IsEnabled(options::kOffscreen);

  
  inspectable_web_contents_.reset(new InspectableWebContents( web_contents, browser_context->prefs(), is_guest));
  inspectable_web_contents_->SetDelegate(this);
}

WebContents::~WebContents() {
  MarkDestroyed();
  
  if (inspectable_web_contents_) {

    if (type_ == Type::kBackgroundPage) {
      
      inspectable_web_contents_->ReleaseWebContents();
    }


    inspectable_web_contents_->GetView()->SetDelegate(nullptr);

    if (web_contents()) {
      RenderViewDeleted(web_contents()->GetRenderViewHost());
    }

    if (type_ == Type::kBrowserWindow && owner_window()) {
      
      
      for (ExtendedWebContentsObserver& observer : observers_)
        observer.OnCloseContents();
      
      
      WebContentsDestroyed();
    } else if (Browser::Get()->is_shutting_down()) {
      
      DestroyWebContents(false );
    } else {
      
      
      bool is_browser_view = type_ == Type::kBrowserView;
      DestroyWebContents(!(IsGuest() || is_browser_view) );
      
      
      
      WebContentsDestroyed();
    }
  }
}

void WebContents::DestroyWebContents(bool async) {
  
  
  Emit("will-destroy");
  ResetManagedWebContents(async);
}

bool WebContents::DidAddMessageToConsole( content::WebContents* source, blink::mojom::ConsoleMessageLevel level, const base::string16& message, int32_t line_no, const base::string16& source_id) {




  return Emit("console-message", static_cast<int32_t>(level), message, line_no, source_id);
}

void WebContents::OnCreateWindow( const GURL& target_url, const content::Referrer& referrer, const std::string& frame_name, WindowOpenDisposition disposition, const std::string& features, const scoped_refptr<network::ResourceRequestBody>& body) {





  Emit("-new-window", target_url, frame_name, disposition, features, referrer, body);
}

void WebContents::WebContentsCreatedWithFullParams( content::WebContents* source_contents, int opener_render_process_id, int opener_render_frame_id, const content::mojom::CreateNewWindowParams& params, content::WebContents* new_contents) {




  ChildWebContentsTracker::CreateForWebContents(new_contents);
  auto* tracker = ChildWebContentsTracker::FromWebContents(new_contents);
  tracker->url = params.target_url;
  tracker->frame_name = params.frame_name;
  tracker->referrer = params.referrer.To<content::Referrer>();
  tracker->raw_features = params.raw_features;
  tracker->body = params.body;

  v8::Isolate* isolate = JavascriptEnvironment::GetIsolate();
  v8::Locker locker(isolate);
  v8::HandleScope handle_scope(isolate);

  gin_helper::Dictionary dict;
  gin::ConvertFromV8(isolate, pending_child_web_preferences_.Get(isolate), &dict);
  pending_child_web_preferences_.Reset();

  
  
  
  
  new WebContentsPreferences(new_contents, dict);
}

bool WebContents::IsWebContentsCreationOverridden( content::SiteInstance* source_site_instance, content::mojom::WindowContainerType window_container_type, const GURL& opener_url, const content::mojom::CreateNewWindowParams& params) {



  bool default_prevented = Emit("-will-add-new-contents", params.target_url, params.frame_name, params.raw_features);
  
  
  
  return default_prevented;
}

void WebContents::SetNextChildWebPreferences( const gin_helper::Dictionary preferences) {
  v8::Isolate* isolate = JavascriptEnvironment::GetIsolate();
  v8::Locker locker(isolate);
  v8::HandleScope handle_scope(isolate);
  
  
  pending_child_web_preferences_.Reset(isolate, preferences.GetHandle());
}

content::WebContents* WebContents::CreateCustomWebContents( content::RenderFrameHost* opener, content::SiteInstance* source_site_instance, bool is_new_browsing_instance, const GURL& opener_url, const std::string& frame_name, const GURL& target_url, const std::string& partition_id, content::SessionStorageNamespace* session_storage_namespace) {







  return nullptr;
}

void WebContents::AddNewContents( content::WebContents* source, std::unique_ptr<content::WebContents> new_contents, const GURL& target_url, WindowOpenDisposition disposition, const gfx::Rect& initial_rect, bool user_gesture, bool* was_blocked) {






  auto* tracker = ChildWebContentsTracker::FromWebContents(new_contents.get());
  DCHECK(tracker);

  v8::Isolate* isolate = JavascriptEnvironment::GetIsolate();

  v8::Locker locker(isolate);
  v8::HandleScope handle_scope(isolate);
  auto api_web_contents = CreateAndTake(isolate, std::move(new_contents), Type::kBrowserWindow);
  if (Emit("-add-new-contents", api_web_contents, disposition, user_gesture, initial_rect.x(), initial_rect.y(), initial_rect.width(), initial_rect.height(), tracker->url, tracker->frame_name, tracker->referrer, tracker->raw_features, tracker->body)) {


    api_web_contents->DestroyWebContents(false );
  }
}

content::WebContents* WebContents::OpenURLFromTab( content::WebContents* source, const content::OpenURLParams& params) {

  auto weak_this = GetWeakPtr();
  if (params.disposition != WindowOpenDisposition::CURRENT_TAB) {
    Emit("-new-window", params.url, "", params.disposition, "", params.referrer, params.post_data);
    return nullptr;
  }

  if (!weak_this)
    return nullptr;

  content::NavigationController::LoadURLParams load_url_params(params.url);
  load_url_params.referrer = params.referrer;
  load_url_params.transition_type = params.transition;
  load_url_params.extra_headers = params.extra_headers;
  load_url_params.should_replace_current_entry = params.should_replace_current_entry;
  load_url_params.is_renderer_initiated = params.is_renderer_initiated;
  load_url_params.started_from_context_menu = params.started_from_context_menu;
  load_url_params.initiator_origin = params.initiator_origin;
  load_url_params.source_site_instance = params.source_site_instance;
  load_url_params.frame_tree_node_id = params.frame_tree_node_id;
  load_url_params.redirect_chain = params.redirect_chain;
  load_url_params.has_user_gesture = params.user_gesture;
  load_url_params.blob_url_loader_factory = params.blob_url_loader_factory;
  load_url_params.href_translate = params.href_translate;
  load_url_params.reload_type = params.reload_type;

  if (params.post_data) {
    load_url_params.load_type = content::NavigationController::LOAD_TYPE_HTTP_POST;
    load_url_params.post_data = params.post_data;
  }

  source->GetController().LoadURLWithParams(load_url_params);
  return source;
}

void WebContents::BeforeUnloadFired(content::WebContents* tab, bool proceed, bool* proceed_to_fire_unload) {

  if (type_ == Type::kBrowserWindow || type_ == Type::kOffScreen)
    *proceed_to_fire_unload = proceed;
  else *proceed_to_fire_unload = true;
  
  Emit("before-unload-fired", proceed);
}

void WebContents::SetContentsBounds(content::WebContents* source, const gfx::Rect& rect) {
  for (ExtendedWebContentsObserver& observer : observers_)
    observer.OnSetContentBounds(rect);
}

void WebContents::CloseContents(content::WebContents* source) {
  Emit("close");

  auto* autofill_driver_factory = AutofillDriverFactory::FromWebContents(web_contents());
  if (autofill_driver_factory) {
    autofill_driver_factory->CloseAllPopups();
  }

  if (inspectable_web_contents_)
    inspectable_web_contents_->GetView()->SetDelegate(nullptr);
  for (ExtendedWebContentsObserver& observer : observers_)
    observer.OnCloseContents();
}

void WebContents::ActivateContents(content::WebContents* source) {
  for (ExtendedWebContentsObserver& observer : observers_)
    observer.OnActivateContents();
}

void WebContents::UpdateTargetURL(content::WebContents* source, const GURL& url) {
  Emit("update-target-url", url);
}

bool WebContents::HandleKeyboardEvent( content::WebContents* source, const content::NativeWebKeyboardEvent& event) {

  if (type_ == Type::kWebView && embedder_) {
    
    return embedder_->HandleKeyboardEvent(source, event);
  } else {
    return PlatformHandleKeyboardEvent(source, event);
  }
}





bool WebContents::PlatformHandleKeyboardEvent( content::WebContents* source, const content::NativeWebKeyboardEvent& event) {

  
  if (event.windows_key_code == ui::VKEY_ESCAPE && is_html_fullscreen()) {
    ExitFullscreenModeForTab(source);
    return true;
  }

  
  auto* web_preferences = WebContentsPreferences::From(source);
  if (web_preferences && web_preferences->IsEnabled("ignoreMenuShortcuts", false))
    return false;

  
  if (owner_window()) {
    owner_window()->HandleKeyboardEvent(source, event);
    return true;
  }

  return false;
}


content::KeyboardEventProcessingResult WebContents::PreHandleKeyboardEvent( content::WebContents* source, const content::NativeWebKeyboardEvent& event) {

  if (event.GetType() == blink::WebInputEvent::Type::kRawKeyDown || event.GetType() == blink::WebInputEvent::Type::kKeyUp) {
    bool prevent_default = Emit("before-input-event", event);
    if (prevent_default) {
      return content::KeyboardEventProcessingResult::HANDLED;
    }
  }

  return content::KeyboardEventProcessingResult::NOT_HANDLED;
}

void WebContents::ContentsZoomChange(bool zoom_in) {
  Emit("zoom-changed", zoom_in ? "in" : "out");
}

void WebContents::EnterFullscreenModeForTab( content::RenderFrameHost* requesting_frame, const blink::mojom::FullscreenOptions& options) {

  auto* source = content::WebContents::FromRenderFrameHost(requesting_frame);
  auto* permission_helper = WebContentsPermissionHelper::FromWebContents(source);
  auto callback = base::BindRepeating(&WebContents::OnEnterFullscreenModeForTab, base::Unretained(this), requesting_frame, options);

  permission_helper->RequestFullscreenPermission(callback);
}

void WebContents::OnEnterFullscreenModeForTab( content::RenderFrameHost* requesting_frame, const blink::mojom::FullscreenOptions& options, bool allowed) {


  if (!allowed)
    return;
  if (!owner_window_)
    return;
  auto* source = content::WebContents::FromRenderFrameHost(requesting_frame);
  if (IsFullscreenForTabOrPending(source)) {
    DCHECK_EQ(fullscreen_frame_, source->GetFocusedFrame());
    return;
  }
  SetHtmlApiFullscreen(true);
  owner_window_->NotifyWindowEnterHtmlFullScreen();

  if (native_fullscreen_) {
    
    
    source->GetRenderViewHost()->GetWidget()->SynchronizeVisualProperties();
  }
  Emit("enter-html-full-screen");
}

void WebContents::ExitFullscreenModeForTab(content::WebContents* source) {
  if (!owner_window_)
    return;
  SetHtmlApiFullscreen(false);
  owner_window_->NotifyWindowLeaveHtmlFullScreen();

  if (native_fullscreen_) {
    
    
    
    source->GetRenderViewHost()->GetWidget()->SynchronizeVisualProperties();
  }
  Emit("leave-html-full-screen");
}

void WebContents::RendererUnresponsive( content::WebContents* source, content::RenderWidgetHost* render_widget_host, base::RepeatingClosure hang_monitor_restarter) {


  Emit("unresponsive");
}

void WebContents::RendererResponsive( content::WebContents* source, content::RenderWidgetHost* render_widget_host) {

  Emit("responsive");
}

bool WebContents::HandleContextMenu(content::RenderFrameHost* render_frame_host, const content::ContextMenuParams& params) {
  if (params.custom_context.is_pepper_menu) {
    Emit("pepper-context-menu", std::make_pair(params, web_contents()), base::BindOnce(&content::WebContents::NotifyContextMenuClosed, base::Unretained(web_contents()), params.custom_context));


  } else {
    Emit("context-menu", std::make_pair(params, web_contents()));
  }

  return true;
}

bool WebContents::OnGoToEntryOffset(int offset) {
  GoToOffset(offset);
  return false;
}

void WebContents::FindReply(content::WebContents* web_contents, int request_id, int number_of_matches, const gfx::Rect& selection_rect, int active_match_ordinal, bool final_update) {




  if (!final_update)
    return;

  v8::Isolate* isolate = JavascriptEnvironment::GetIsolate();
  v8::Locker locker(isolate);
  v8::HandleScope handle_scope(isolate);
  gin_helper::Dictionary result = gin::Dictionary::CreateEmpty(isolate);
  result.Set("requestId", request_id);
  result.Set("matches", number_of_matches);
  result.Set("selectionArea", selection_rect);
  result.Set("activeMatchOrdinal", active_match_ordinal);
  result.Set("finalUpdate", final_update);  
  Emit("found-in-page", result.GetHandle());
}

bool WebContents::CheckMediaAccessPermission( content::RenderFrameHost* render_frame_host, const GURL& security_origin, blink::mojom::MediaStreamType type) {


  auto* web_contents = content::WebContents::FromRenderFrameHost(render_frame_host);
  auto* permission_helper = WebContentsPermissionHelper::FromWebContents(web_contents);
  return permission_helper->CheckMediaAccessPermission(security_origin, type);
}

void WebContents::RequestMediaAccessPermission( content::WebContents* web_contents, const content::MediaStreamRequest& request, content::MediaResponseCallback callback) {


  auto* permission_helper = WebContentsPermissionHelper::FromWebContents(web_contents);
  permission_helper->RequestMediaAccessPermission(request, std::move(callback));
}

void WebContents::RequestToLockMouse(content::WebContents* web_contents, bool user_gesture, bool last_unlocked_by_target) {

  auto* permission_helper = WebContentsPermissionHelper::FromWebContents(web_contents);
  permission_helper->RequestPointerLockPermission(user_gesture);
}

content::JavaScriptDialogManager* WebContents::GetJavaScriptDialogManager( content::WebContents* source) {
  if (!dialog_manager_)
    dialog_manager_ = std::make_unique<ElectronJavaScriptDialogManager>();

  return dialog_manager_.get();
}

void WebContents::OnAudioStateChanged(bool audible) {
  Emit("-audio-state-changed", audible);
}

void WebContents::BeforeUnloadFired(bool proceed, const base::TimeTicks& proceed_time) {
  
  
}

void WebContents::RenderViewCreated(content::RenderViewHost* render_view_host) {
  if (!background_throttling_)
    render_view_host->SetSchedulerThrottling(false);
}

void WebContents::RenderFrameCreated( content::RenderFrameHost* render_frame_host) {
  auto* rwhv = render_frame_host->GetView();
  if (!rwhv)
    return;

  auto* rwh_impl = static_cast<content::RenderWidgetHostImpl*>(rwhv->GetRenderWidgetHost());
  if (rwh_impl)
    rwh_impl->disable_hidden_ = !background_throttling_;
}

void WebContents::RenderViewDeleted(content::RenderViewHost* render_view_host) {
  
  
  
  Emit("render-view-deleted", render_view_host->GetProcess()->GetID());

  if (web_contents()->GetRenderViewHost() == render_view_host) {
    
    
    
    
    Emit("current-render-view-deleted", render_view_host->GetProcess()->GetID());
  }
}

void WebContents::RenderProcessGone(base::TerminationStatus status) {
  Emit("crashed", status == base::TERMINATION_STATUS_PROCESS_WAS_KILLED);
  v8::Isolate* isolate = JavascriptEnvironment::GetIsolate();
  v8::HandleScope handle_scope(isolate);
  gin_helper::Dictionary details = gin_helper::Dictionary::CreateEmpty(isolate);
  details.Set("reason", status);
  Emit("render-process-gone", details);
}

void WebContents::PluginCrashed(const base::FilePath& plugin_path, base::ProcessId plugin_pid) {

  content::WebPluginInfo info;
  auto* plugin_service = content::PluginService::GetInstance();
  plugin_service->GetPluginInfoByPath(plugin_path, &info);
  Emit("plugin-crashed", info.name, info.version);

}

void WebContents::MediaStartedPlaying(const MediaPlayerInfo& video_type, const content::MediaPlayerId& id) {
  Emit("media-started-playing");
}

void WebContents::MediaStoppedPlaying( const MediaPlayerInfo& video_type, const content::MediaPlayerId& id, content::WebContentsObserver::MediaStoppedReason reason) {


  Emit("media-paused");
}

void WebContents::DidChangeThemeColor() {
  auto theme_color = web_contents()->GetThemeColor();
  if (theme_color) {
    Emit("did-change-theme-color", electron::ToRGBHex(theme_color.value()));
  } else {
    Emit("did-change-theme-color", nullptr);
  }
}

void WebContents::OnInterfaceRequestFromFrame( content::RenderFrameHost* render_frame_host, const std::string& interface_name, mojo::ScopedMessagePipeHandle* interface_pipe) {


  registry_.TryBindInterface(interface_name, interface_pipe, render_frame_host);
}

void WebContents::DidAcquireFullscreen(content::RenderFrameHost* rfh) {
  set_fullscreen_frame(rfh);
}

void WebContents::DOMContentLoaded( content::RenderFrameHost* render_frame_host) {
  if (!render_frame_host->GetParent())
    Emit("dom-ready");
}

void WebContents::DidFinishLoad(content::RenderFrameHost* render_frame_host, const GURL& validated_url) {
  bool is_main_frame = !render_frame_host->GetParent();
  int frame_process_id = render_frame_host->GetProcess()->GetID();
  int frame_routing_id = render_frame_host->GetRoutingID();
  auto weak_this = GetWeakPtr();
  Emit("did-frame-finish-load", is_main_frame, frame_process_id, frame_routing_id);

  
  
  
  if (is_main_frame && weak_this)
    Emit("did-finish-load");
}

void WebContents::DidFailLoad(content::RenderFrameHost* render_frame_host, const GURL& url, int error_code) {

  bool is_main_frame = !render_frame_host->GetParent();
  int frame_process_id = render_frame_host->GetProcess()->GetID();
  int frame_routing_id = render_frame_host->GetRoutingID();
  Emit("did-fail-load", error_code, "", url, is_main_frame, frame_process_id, frame_routing_id);
}

void WebContents::DidStartLoading() {
  Emit("did-start-loading");
}

void WebContents::DidStopLoading() {
  auto* web_preferences = WebContentsPreferences::From(web_contents());
  if (web_preferences && web_preferences->IsEnabled(options::kEnablePreferredSizeMode))
    web_contents()->GetRenderViewHost()->EnablePreferredSizeMode();

  Emit("did-stop-loading");
}

bool WebContents::EmitNavigationEvent( const std::string& event, content::NavigationHandle* navigation_handle) {

  bool is_main_frame = navigation_handle->IsInMainFrame();
  int frame_tree_node_id = navigation_handle->GetFrameTreeNodeId();
  content::FrameTreeNode* frame_tree_node = content::FrameTreeNode::GloballyFindByID(frame_tree_node_id);
  content::RenderFrameHostManager* render_manager = frame_tree_node->render_manager();
  content::RenderFrameHost* frame_host = nullptr;
  if (render_manager) {
    frame_host = render_manager->speculative_frame_host();
    if (!frame_host)
      frame_host = render_manager->current_frame_host();
  }
  int frame_process_id = -1, frame_routing_id = -1;
  if (frame_host) {
    frame_process_id = frame_host->GetProcess()->GetID();
    frame_routing_id = frame_host->GetRoutingID();
  }
  bool is_same_document = navigation_handle->IsSameDocument();
  auto url = navigation_handle->GetURL();
  return Emit(event, url, is_same_document, is_main_frame, frame_process_id, frame_routing_id);
}

void WebContents::BindElectronBrowser( mojo::PendingReceiver<mojom::ElectronBrowser> receiver, content::RenderFrameHost* render_frame_host) {

  auto id = receivers_.Add(this, std::move(receiver), render_frame_host);
  frame_to_receivers_map_[render_frame_host].push_back(id);
}

void WebContents::OnElectronBrowserConnectionError() {
  auto receiver_id = receivers_.current_receiver();
  auto* frame_host = receivers_.current_context();
  base::Erase(frame_to_receivers_map_[frame_host], receiver_id);
}

void WebContents::Message(bool internal, const std::string& channel, blink::CloneableMessage arguments) {

  TRACE_EVENT1("electron", "WebContents::Message", "channel", channel);
  
  
  EmitWithSender("-ipc-message", receivers_.current_context(), InvokeCallback(), internal, channel, std::move(arguments));
}

void WebContents::Invoke(bool internal, const std::string& channel, blink::CloneableMessage arguments, InvokeCallback callback) {


  TRACE_EVENT1("electron", "WebContents::Invoke", "channel", channel);
  
  EmitWithSender("-ipc-invoke", receivers_.current_context(), std::move(callback), internal, channel, std::move(arguments));
}

void WebContents::OnFirstNonEmptyLayout() {
  if (receivers_.current_context() == web_contents()->GetMainFrame()) {
    Emit("ready-to-show");
  }
}

void WebContents::ReceivePostMessage(const std::string& channel, blink::TransferableMessage message) {
  v8::Isolate* isolate = JavascriptEnvironment::GetIsolate();
  v8::HandleScope handle_scope(isolate);
  auto wrapped_ports = MessagePort::EntanglePorts(isolate, std::move(message.ports));
  v8::Local<v8::Value> message_value = electron::DeserializeV8Value(isolate, message);
  EmitWithSender("-ipc-ports", receivers_.current_context(), InvokeCallback(), false, channel, message_value, std::move(wrapped_ports));
}

void WebContents::PostMessage(const std::string& channel, v8::Local<v8::Value> message_value, base::Optional<v8::Local<v8::Value>> transfer) {

  v8::Isolate* isolate = JavascriptEnvironment::GetIsolate();
  blink::TransferableMessage transferable_message;
  if (!electron::SerializeV8Value(isolate, message_value, &transferable_message)) {
    
    return;
  }

  std::vector<gin::Handle<MessagePort>> wrapped_ports;
  if (transfer) {
    if (!gin::ConvertFromV8(isolate, *transfer, &wrapped_ports)) {
      isolate->ThrowException(v8::Exception::Error( gin::StringToV8(isolate, "Invalid value for transfer")));
      return;
    }
  }

  bool threw_exception = false;
  transferable_message.ports = MessagePort::DisentanglePorts(isolate, wrapped_ports, &threw_exception);
  if (threw_exception)
    return;

  content::RenderFrameHost* frame_host = web_contents()->GetMainFrame();
  mojo::AssociatedRemote<mojom::ElectronRenderer> electron_renderer;
  frame_host->GetRemoteAssociatedInterfaces()->GetInterface(&electron_renderer);
  electron_renderer->ReceivePostMessage(channel, std::move(transferable_message));
}

void WebContents::MessageSync(bool internal, const std::string& channel, blink::CloneableMessage arguments, MessageSyncCallback callback) {


  TRACE_EVENT1("electron", "WebContents::MessageSync", "channel", channel);
  
  
  EmitWithSender("-ipc-message-sync", receivers_.current_context(), std::move(callback), internal, channel, std::move(arguments));
}

void WebContents::MessageTo(bool internal, int32_t web_contents_id, const std::string& channel, blink::CloneableMessage arguments) {


  TRACE_EVENT1("electron", "WebContents::MessageTo", "channel", channel);
  auto* web_contents = FromID(web_contents_id);

  if (web_contents) {
    web_contents->SendIPCMessageWithSender(internal, channel, std::move(arguments), ID());
  }
}

void WebContents::MessageHost(const std::string& channel, blink::CloneableMessage arguments) {
  TRACE_EVENT1("electron", "WebContents::MessageHost", "channel", channel);
  
  EmitWithSender("ipc-message-host", receivers_.current_context(), InvokeCallback(), channel, std::move(arguments));
}

void WebContents::UpdateDraggableRegions( std::vector<mojom::DraggableRegionPtr> regions) {
  for (ExtendedWebContentsObserver& observer : observers_)
    observer.OnDraggableRegionsUpdated(regions);
}

void WebContents::RenderFrameDeleted( content::RenderFrameHost* render_frame_host) {
  
  
  WebFrameMain::RenderFrameDeleted(render_frame_host);

  
  
  
  
  
  auto it = frame_to_receivers_map_.find(render_frame_host);
  if (it == frame_to_receivers_map_.end())
    return;
  for (auto id : it->second)
    receivers_.Remove(id);
  frame_to_receivers_map_.erase(it);
}

void WebContents::DidStartNavigation( content::NavigationHandle* navigation_handle) {
  EmitNavigationEvent("did-start-navigation", navigation_handle);
}

void WebContents::DidRedirectNavigation( content::NavigationHandle* navigation_handle) {
  EmitNavigationEvent("did-redirect-navigation", navigation_handle);
}

void WebContents::DidFinishNavigation( content::NavigationHandle* navigation_handle) {
  if (!navigation_handle->HasCommitted())
    return;
  bool is_main_frame = navigation_handle->IsInMainFrame();
  content::RenderFrameHost* frame_host = navigation_handle->GetRenderFrameHost();
  int frame_process_id = -1, frame_routing_id = -1;
  if (frame_host) {
    frame_process_id = frame_host->GetProcess()->GetID();
    frame_routing_id = frame_host->GetRoutingID();
  }
  if (!navigation_handle->IsErrorPage()) {
    
    
    
    auto url = navigation_handle->GetURL();
    bool is_same_document = navigation_handle->IsSameDocument();
    if (is_same_document) {
      Emit("did-navigate-in-page", url, is_main_frame, frame_process_id, frame_routing_id);
    } else {
      const net::HttpResponseHeaders* http_response = navigation_handle->GetResponseHeaders();
      std::string http_status_text;
      int http_response_code = -1;
      if (http_response) {
        http_status_text = http_response->GetStatusText();
        http_response_code = http_response->response_code();
      }
      Emit("did-frame-navigate", url, http_response_code, http_status_text, is_main_frame, frame_process_id, frame_routing_id);
      if (is_main_frame) {
        Emit("did-navigate", url, http_response_code, http_status_text);
      }
    }
    if (IsGuest())
      Emit("load-commit", url, is_main_frame);
  } else {
    auto url = navigation_handle->GetURL();
    int code = navigation_handle->GetNetErrorCode();
    auto description = net::ErrorToShortString(code);
    Emit("did-fail-provisional-load", code, description, url, is_main_frame, frame_process_id, frame_routing_id);

    
    if (code != net::ERR_ABORTED)
      Emit("did-fail-load", code, description, url, is_main_frame, frame_process_id, frame_routing_id);
  }
}

void WebContents::TitleWasSet(content::NavigationEntry* entry) {
  base::string16 final_title;
  bool explicit_set = true;
  if (entry) {
    auto title = entry->GetTitle();
    auto url = entry->GetURL();
    if (url.SchemeIsFile() && title.empty()) {
      final_title = base::UTF8ToUTF16(url.ExtractFileName());
      explicit_set = false;
    } else {
      final_title = title;
    }
  }
  for (ExtendedWebContentsObserver& observer : observers_)
    observer.OnPageTitleUpdated(final_title, explicit_set);
  Emit("page-title-updated", final_title, explicit_set);
}

void WebContents::DidUpdateFaviconURL( content::RenderFrameHost* render_frame_host, const std::vector<blink::mojom::FaviconURLPtr>& urls) {

  std::set<GURL> unique_urls;
  for (const auto& iter : urls) {
    if (iter->icon_type != blink::mojom::FaviconIconType::kFavicon)
      continue;
    const GURL& url = iter->icon_url;
    if (url.is_valid())
      unique_urls.insert(url);
  }
  Emit("page-favicon-updated", unique_urls);
}

void WebContents::DevToolsReloadPage() {
  Emit("devtools-reload-page");
}

void WebContents::DevToolsFocused() {
  Emit("devtools-focused");
}

void WebContents::DevToolsOpened() {
  v8::Isolate* isolate = JavascriptEnvironment::GetIsolate();
  v8::Locker locker(isolate);
  v8::HandleScope handle_scope(isolate);
  DCHECK(inspectable_web_contents_);
  auto handle = FromOrCreate( isolate, inspectable_web_contents_->GetDevToolsWebContents());
  devtools_web_contents_.Reset(isolate, handle.ToV8());

  
  base::Value tab_id(ID());
  inspectable_web_contents_->CallClientFunction("DevToolsAPI.setInspectedTabId", &tab_id, nullptr, nullptr);

  
  auto* devtools = inspectable_web_contents_->GetDevToolsWebContents();
  bool has_window = devtools->GetUserData(NativeWindowRelay::UserDataKey());
  if (owner_window() && !has_window)
    handle->SetOwnerWindow(devtools, owner_window());

  Emit("devtools-opened");
}

void WebContents::DevToolsClosed() {
  v8::Isolate* isolate = JavascriptEnvironment::GetIsolate();
  v8::Locker locker(isolate);
  v8::HandleScope handle_scope(isolate);
  devtools_web_contents_.Reset();

  Emit("devtools-closed");
}

void WebContents::DevToolsResized() {
  for (ExtendedWebContentsObserver& observer : observers_)
    observer.OnDevToolsResized();
}

bool WebContents::OnMessageReceived(const IPC::Message& message) {
  bool handled = true;
  IPC_BEGIN_MESSAGE_MAP(WebContents, message)
    IPC_MESSAGE_UNHANDLED(handled = false)
  IPC_END_MESSAGE_MAP()

  return handled;
}

void WebContents::SetOwnerWindow(NativeWindow* owner_window) {
  SetOwnerWindow(GetWebContents(), owner_window);
}

void WebContents::SetOwnerWindow(content::WebContents* web_contents, NativeWindow* owner_window) {
  if (owner_window) {
    owner_window_ = owner_window->GetWeakPtr();
    NativeWindowRelay::CreateForWebContents(web_contents, owner_window->GetWeakPtr());
  } else {
    owner_window_ = nullptr;
    web_contents->RemoveUserData(NativeWindowRelay::UserDataKey());
  }

  auto* osr_wcv = GetOffScreenWebContentsView();
  if (osr_wcv)
    osr_wcv->SetNativeWindow(owner_window);

}

void WebContents::ResetManagedWebContents(bool async) {
  if (async) {
    
    
    
    
    
    
    base::ThreadTaskRunnerHandle::Get()->DeleteSoon( FROM_HERE, inspectable_web_contents_.release());
  } else {
    inspectable_web_contents_.reset();
  }
}

content::WebContents* WebContents::GetWebContents() const {
  if (!inspectable_web_contents_)
    return nullptr;
  return inspectable_web_contents_->GetWebContents();
}

content::WebContents* WebContents::GetDevToolsWebContents() const {
  if (!inspectable_web_contents_)
    return nullptr;
  return inspectable_web_contents_->GetDevToolsWebContents();
}

void WebContents::MarkDestroyed() {
  if (GetAllWebContents().Lookup(id_))
    GetAllWebContents().Remove(id_);
  v8::Isolate* isolate = JavascriptEnvironment::GetIsolate();
  v8::HandleScope scope(isolate);
  v8::Local<v8::Object> wrapper;
  if (!GetWrapper(isolate).ToLocal(&wrapper))
    return;
  wrapper->SetAlignedPointerInInternalField(0, nullptr);
}















void WebContents::WebContentsDestroyed() {
  
  
  if (guest_delegate_)
    guest_delegate_->WillDestroy();

  

  
  
  MarkDestroyed();

  Emit("destroyed");

  
  
  if (IsGuest() && inspectable_web_contents_) {
    inspectable_web_contents_->ReleaseWebContents();
    ResetManagedWebContents(false);
  }

  
  base::ThreadTaskRunnerHandle::Get()->PostTask( FROM_HERE, base::BindOnce( [](base::WeakPtr<WebContents> wc) {

                       if (wc)
                         delete wc.get();
                     }, GetWeakPtr()));
}

void WebContents::NavigationEntryCommitted( const content::LoadCommittedDetails& details) {
  Emit("navigation-entry-committed", details.entry->GetURL(), details.is_same_document, details.did_replace_entry);
}

bool WebContents::GetBackgroundThrottling() const {
  return background_throttling_;
}

void WebContents::SetBackgroundThrottling(bool allowed) {
  background_throttling_ = allowed;

  auto* rfh = web_contents()->GetMainFrame();
  if (!rfh)
    return;

  auto* rwhv = rfh->GetView();
  if (!rwhv)
    return;

  auto* rwh_impl = static_cast<content::RenderWidgetHostImpl*>(rwhv->GetRenderWidgetHost());
  if (!rwh_impl)
    return;

  rwh_impl->disable_hidden_ = !background_throttling_;
  web_contents()->GetRenderViewHost()->SetSchedulerThrottling(allowed);

  if (rwh_impl->is_hidden()) {
    rwh_impl->WasShown({});
  }
}

int WebContents::GetProcessID() const {
  return web_contents()->GetMainFrame()->GetProcess()->GetID();
}

base::ProcessId WebContents::GetOSProcessID() const {
  base::ProcessHandle process_handle = web_contents()->GetMainFrame()->GetProcess()->GetProcess().Handle();
  return base::GetProcId(process_handle);
}

WebContents::Type WebContents::GetType() const {
  return type_;
}

bool WebContents::Equal(const WebContents* web_contents) const {
  return ID() == web_contents->ID();
}

void WebContents::LoadURL(const GURL& url, const gin_helper::Dictionary& options) {
  if (!url.is_valid() || url.spec().size() > url::kMaxURLChars) {
    Emit("did-fail-load", static_cast<int>(net::ERR_INVALID_URL), net::ErrorToShortString(net::ERR_INVALID_URL), url.possibly_invalid_spec(), true);

    return;
  }

  content::NavigationController::LoadURLParams params(url);

  if (!options.Get("httpReferrer", &params.referrer)) {
    GURL http_referrer;
    if (options.Get("httpReferrer", &http_referrer))
      params.referrer = content::Referrer(http_referrer.GetAsReferrer(), network::mojom::ReferrerPolicy::kDefault);

  }

  std::string user_agent;
  if (options.Get("userAgent", &user_agent))
    web_contents()->SetUserAgentOverride( blink::UserAgentOverride::UserAgentOnly(user_agent), false);

  std::string extra_headers;
  if (options.Get("extraHeaders", &extra_headers))
    params.extra_headers = extra_headers;

  scoped_refptr<network::ResourceRequestBody> body;
  if (options.Get("postData", &body)) {
    params.post_data = body;
    params.load_type = content::NavigationController::LOAD_TYPE_HTTP_POST;
  }

  GURL base_url_for_data_url;
  if (options.Get("baseURLForDataURL", &base_url_for_data_url)) {
    params.base_url_for_data_url = base_url_for_data_url;
    params.load_type = content::NavigationController::LOAD_TYPE_DATA;
  }

  bool reload_ignoring_cache = false;
  if (options.Get("reloadIgnoringCache", &reload_ignoring_cache) && reload_ignoring_cache) {
    params.reload_type = content::ReloadType::BYPASSING_CACHE;
  }

  
  auto weak_this = GetWeakPtr();

  
  NotifyUserActivation();

  params.transition_type = ui::PAGE_TRANSITION_TYPED;
  params.should_clear_history_list = true;
  params.override_user_agent = content::NavigationController::UA_OVERRIDE_TRUE;
  
  
  web_contents()->GetController().DiscardNonCommittedEntries();
  web_contents()->GetController().LoadURLWithParams(params);

  
  
  
  if (!weak_this)
    return;

  
  
  
  auto* const view = weak_this->web_contents()->GetRenderWidgetHostView();
  if (view) {
    auto* web_preferences = WebContentsPreferences::From(web_contents());
    std::string color_name;
    if (web_preferences->GetPreference(options::kBackgroundColor, &color_name)) {
      view->SetBackgroundColor(ParseHexColor(color_name));
    } else {
      view->SetBackgroundColor(SK_ColorTRANSPARENT);
    }
  }
}

void WebContents::DownloadURL(const GURL& url) {
  auto* browser_context = web_contents()->GetBrowserContext();
  auto* download_manager = content::BrowserContext::GetDownloadManager(browser_context);
  std::unique_ptr<download::DownloadUrlParameters> download_params( content::DownloadRequestUtils::CreateDownloadForWebContentsMainFrame( web_contents(), url, MISSING_TRAFFIC_ANNOTATION));

  download_manager->DownloadUrl(std::move(download_params));
}

GURL WebContents::GetURL() const {
  return web_contents()->GetURL();
}

base::string16 WebContents::GetTitle() const {
  return web_contents()->GetTitle();
}

bool WebContents::IsLoading() const {
  return web_contents()->IsLoading();
}

bool WebContents::IsLoadingMainFrame() const {
  return web_contents()->IsLoadingToDifferentDocument();
}

bool WebContents::IsWaitingForResponse() const {
  return web_contents()->IsWaitingForResponse();
}

void WebContents::Stop() {
  web_contents()->Stop();
}

void WebContents::GoBack() {
  if (!ElectronBrowserClient::Get()->CanUseCustomSiteInstance()) {
    electron::ElectronBrowserClient::SuppressRendererProcessRestartForOnce();
  }
  web_contents()->GetController().GoBack();
}

void WebContents::GoForward() {
  if (!ElectronBrowserClient::Get()->CanUseCustomSiteInstance()) {
    electron::ElectronBrowserClient::SuppressRendererProcessRestartForOnce();
  }
  web_contents()->GetController().GoForward();
}

void WebContents::GoToOffset(int offset) {
  if (!ElectronBrowserClient::Get()->CanUseCustomSiteInstance()) {
    electron::ElectronBrowserClient::SuppressRendererProcessRestartForOnce();
  }
  web_contents()->GetController().GoToOffset(offset);
}

const std::string WebContents::GetWebRTCIPHandlingPolicy() const {
  return web_contents()->GetMutableRendererPrefs()->webrtc_ip_handling_policy;
}

void WebContents::SetWebRTCIPHandlingPolicy( const std::string& webrtc_ip_handling_policy) {
  if (GetWebRTCIPHandlingPolicy() == webrtc_ip_handling_policy)
    return;
  web_contents()->GetMutableRendererPrefs()->webrtc_ip_handling_policy = webrtc_ip_handling_policy;

  web_contents()->SyncRendererPrefs();
}

bool WebContents::IsCrashed() const {
  return web_contents()->IsCrashed();
}

void WebContents::ForcefullyCrashRenderer() {
  content::RenderWidgetHostView* view = web_contents()->GetRenderWidgetHostView();
  if (!view)
    return;

  content::RenderWidgetHost* rwh = view->GetRenderWidgetHost();
  if (!rwh)
    return;

  content::RenderProcessHost* rph = rwh->GetProcess();
  if (rph) {

    
    
    rph->ForceCrash();

    

    CrashDumpHungChildProcess(rph->GetProcess().Handle());

    rph->Shutdown(content::RESULT_CODE_HUNG);

  }
}

void WebContents::SetUserAgent(const std::string& user_agent) {
  web_contents()->SetUserAgentOverride( blink::UserAgentOverride::UserAgentOnly(user_agent), false);
}

std::string WebContents::GetUserAgent() {
  return web_contents()->GetUserAgentOverride().ua_string_override;
}

v8::Local<v8::Promise> WebContents::SavePage( const base::FilePath& full_file_path, const content::SavePageType& save_type) {

  v8::Isolate* isolate = JavascriptEnvironment::GetIsolate();
  gin_helper::Promise<void> promise(isolate);
  v8::Local<v8::Promise> handle = promise.GetHandle();

  auto* handler = new SavePageHandler(web_contents(), std::move(promise));
  handler->Handle(full_file_path, save_type);

  return handle;
}

void WebContents::OpenDevTools(gin::Arguments* args) {
  if (type_ == Type::kRemote)
    return;

  if (!enable_devtools_)
    return;

  std::string state;
  if (type_ == Type::kWebView || type_ == Type::kBackgroundPage || !owner_window()) {
    state = "detach";
  }
  bool activate = true;
  if (args && args->Length() == 1) {
    gin_helper::Dictionary options;
    if (args->GetNext(&options)) {
      options.Get("mode", &state);
      options.Get("activate", &activate);
    }
  }

  DCHECK(inspectable_web_contents_);
  inspectable_web_contents_->SetDockState(state);
  inspectable_web_contents_->ShowDevTools(activate);
}

void WebContents::CloseDevTools() {
  if (type_ == Type::kRemote)
    return;

  DCHECK(inspectable_web_contents_);
  inspectable_web_contents_->CloseDevTools();
}

bool WebContents::IsDevToolsOpened() {
  if (type_ == Type::kRemote)
    return false;

  DCHECK(inspectable_web_contents_);
  return inspectable_web_contents_->IsDevToolsViewShowing();
}

bool WebContents::IsDevToolsFocused() {
  if (type_ == Type::kRemote)
    return false;

  DCHECK(inspectable_web_contents_);
  return inspectable_web_contents_->GetView()->IsDevToolsViewFocused();
}

void WebContents::EnableDeviceEmulation( const blink::DeviceEmulationParams& params) {
  if (type_ == Type::kRemote)
    return;

  DCHECK(web_contents());
  auto* frame_host = web_contents()->GetMainFrame();
  if (frame_host) {
    auto* widget_host_impl = frame_host ? static_cast<content::RenderWidgetHostImpl*>( frame_host->GetView()->GetRenderWidgetHost())

                   : nullptr;
    if (widget_host_impl) {
      auto& frame_widget = widget_host_impl->GetAssociatedFrameWidget();
      frame_widget->EnableDeviceEmulation(params);
    }
  }
}

void WebContents::DisableDeviceEmulation() {
  if (type_ == Type::kRemote)
    return;

  DCHECK(web_contents());
  auto* frame_host = web_contents()->GetMainFrame();
  if (frame_host) {
    auto* widget_host_impl = frame_host ? static_cast<content::RenderWidgetHostImpl*>( frame_host->GetView()->GetRenderWidgetHost())

                   : nullptr;
    if (widget_host_impl) {
      auto& frame_widget = widget_host_impl->GetAssociatedFrameWidget();
      frame_widget->DisableDeviceEmulation();
    }
  }
}

void WebContents::ToggleDevTools() {
  if (IsDevToolsOpened())
    CloseDevTools();
  else OpenDevTools(nullptr);
}

void WebContents::InspectElement(int x, int y) {
  if (type_ == Type::kRemote)
    return;

  if (!enable_devtools_)
    return;

  DCHECK(inspectable_web_contents_);
  if (!inspectable_web_contents_->GetDevToolsWebContents())
    OpenDevTools(nullptr);
  inspectable_web_contents_->InspectElement(x, y);
}

void WebContents::InspectSharedWorkerById(const std::string& workerId) {
  if (type_ == Type::kRemote)
    return;

  if (!enable_devtools_)
    return;

  for (const auto& agent_host : content::DevToolsAgentHost::GetOrCreateAll()) {
    if (agent_host->GetType() == content::DevToolsAgentHost::kTypeSharedWorker) {
      if (agent_host->GetId() == workerId) {
        OpenDevTools(nullptr);
        inspectable_web_contents_->AttachTo(agent_host);
        break;
      }
    }
  }
}

std::vector<scoped_refptr<content::DevToolsAgentHost>> WebContents::GetAllSharedWorkers() {
  std::vector<scoped_refptr<content::DevToolsAgentHost>> shared_workers;

  if (type_ == Type::kRemote)
    return shared_workers;

  if (!enable_devtools_)
    return shared_workers;

  for (const auto& agent_host : content::DevToolsAgentHost::GetOrCreateAll()) {
    if (agent_host->GetType() == content::DevToolsAgentHost::kTypeSharedWorker) {
      shared_workers.push_back(agent_host);
    }
  }
  return shared_workers;
}

void WebContents::InspectSharedWorker() {
  if (type_ == Type::kRemote)
    return;

  if (!enable_devtools_)
    return;

  for (const auto& agent_host : content::DevToolsAgentHost::GetOrCreateAll()) {
    if (agent_host->GetType() == content::DevToolsAgentHost::kTypeSharedWorker) {
      OpenDevTools(nullptr);
      inspectable_web_contents_->AttachTo(agent_host);
      break;
    }
  }
}

void WebContents::InspectServiceWorker() {
  if (type_ == Type::kRemote)
    return;

  if (!enable_devtools_)
    return;

  for (const auto& agent_host : content::DevToolsAgentHost::GetOrCreateAll()) {
    if (agent_host->GetType() == content::DevToolsAgentHost::kTypeServiceWorker) {
      OpenDevTools(nullptr);
      inspectable_web_contents_->AttachTo(agent_host);
      break;
    }
  }
}

void WebContents::SetIgnoreMenuShortcuts(bool ignore) {
  auto* web_preferences = WebContentsPreferences::From(web_contents());
  DCHECK(web_preferences);
  web_preferences->preference()->SetKey("ignoreMenuShortcuts", base::Value(ignore));
}

void WebContents::SetAudioMuted(bool muted) {
  web_contents()->SetAudioMuted(muted);
}

bool WebContents::IsAudioMuted() {
  return web_contents()->IsAudioMuted();
}

bool WebContents::IsCurrentlyAudible() {
  return web_contents()->IsCurrentlyAudible();
}


void WebContents::OnGetDefaultPrinter( base::Value print_settings, printing::CompletionCallback print_callback, base::string16 device_name, bool silent, base::string16 default_printer) {




  
  
  if (!web_contents()) {
    if (print_callback)
      std::move(print_callback).Run(false, "failed");
    return;
  }

  base::string16 printer_name = device_name.empty() ? default_printer : device_name;

  
  if (printer_name.empty() || !IsDeviceNameValid(printer_name)) {
    if (print_callback)
      std::move(print_callback).Run(false, "no valid printers available");
    return;
  }

  print_settings.SetStringKey(printing::kSettingDeviceName, printer_name);

  auto* print_view_manager = printing::PrintViewManagerBasic::FromWebContents(web_contents());
  auto* focused_frame = web_contents()->GetFocusedFrame();
  auto* rfh = focused_frame && focused_frame->HasSelection()
                  ? focused_frame : web_contents()->GetMainFrame();

  print_view_manager->PrintNow(rfh, silent, std::move(print_settings), std::move(print_callback));
}

void WebContents::Print(gin::Arguments* args) {
  gin_helper::Dictionary options = gin::Dictionary::CreateEmpty(args->isolate());
  base::Value settings(base::Value::Type::DICTIONARY);

  if (args->Length() >= 1 && !args->GetNext(&options)) {
    gin_helper::ErrorThrower(args->isolate())
        .ThrowError("webContents.print(): Invalid print settings specified.");
    return;
  }

  printing::CompletionCallback callback;
  if (args->Length() == 2 && !args->GetNext(&callback)) {
    gin_helper::ErrorThrower(args->isolate())
        .ThrowError("webContents.print(): Invalid optional callback provided.");
    return;
  }

  
  bool silent = false;
  options.Get("silent", &silent);

  bool print_background = false;
  options.Get("printBackground", &print_background);
  settings.SetBoolKey(printing::kSettingShouldPrintBackgrounds, print_background);

  
  gin_helper::Dictionary margins = gin::Dictionary::CreateEmpty(args->isolate());
  if (options.Get("margins", &margins)) {
    printing::mojom::MarginType margin_type = printing::mojom::MarginType::kDefaultMargins;
    margins.Get("marginType", &margin_type);
    settings.SetIntKey(printing::kSettingMarginsType, static_cast<int>(margin_type));

    if (margin_type == printing::mojom::MarginType::kCustomMargins) {
      base::Value custom_margins(base::Value::Type::DICTIONARY);
      int top = 0;
      margins.Get("top", &top);
      custom_margins.SetIntKey(printing::kSettingMarginTop, top);
      int bottom = 0;
      margins.Get("bottom", &bottom);
      custom_margins.SetIntKey(printing::kSettingMarginBottom, bottom);
      int left = 0;
      margins.Get("left", &left);
      custom_margins.SetIntKey(printing::kSettingMarginLeft, left);
      int right = 0;
      margins.Get("right", &right);
      custom_margins.SetIntKey(printing::kSettingMarginRight, right);
      settings.SetPath(printing::kSettingMarginsCustom, std::move(custom_margins));
    }
  } else {
    settings.SetIntKey( printing::kSettingMarginsType, static_cast<int>(printing::mojom::MarginType::kDefaultMargins));

  }

  
  bool print_color = true;
  options.Get("color", &print_color);
  auto const color_model = print_color ? printing::mojom::ColorModel::kColor : printing::mojom::ColorModel::kGray;
  settings.SetIntKey(printing::kSettingColor, static_cast<int>(color_model));

  
  bool landscape = false;
  options.Get("landscape", &landscape);
  settings.SetBoolKey(printing::kSettingLandscape, landscape);

  
  
  
  base::string16 device_name;
  options.Get("deviceName", &device_name);
  if (!device_name.empty() && !IsDeviceNameValid(device_name)) {
    gin_helper::ErrorThrower(args->isolate())
        .ThrowError("webContents.print(): Invalid deviceName provided.");
    return;
  }

  int scale_factor = 100;
  options.Get("scaleFactor", &scale_factor);
  settings.SetIntKey(printing::kSettingScaleFactor, scale_factor);

  int pages_per_sheet = 1;
  options.Get("pagesPerSheet", &pages_per_sheet);
  settings.SetIntKey(printing::kSettingPagesPerSheet, pages_per_sheet);

  
  bool collate = true;
  options.Get("collate", &collate);
  settings.SetBoolKey(printing::kSettingCollate, collate);

  
  int copies = 1;
  options.Get("copies", &copies);
  settings.SetIntKey(printing::kSettingCopies, copies);

  
  std::string header;
  options.Get("header", &header);
  std::string footer;
  options.Get("footer", &footer);

  if (!(header.empty() && footer.empty())) {
    settings.SetBoolKey(printing::kSettingHeaderFooterEnabled, true);

    settings.SetStringKey(printing::kSettingHeaderFooterTitle, header);
    settings.SetStringKey(printing::kSettingHeaderFooterURL, footer);
  } else {
    settings.SetBoolKey(printing::kSettingHeaderFooterEnabled, false);
  }

  
  
  settings.SetIntKey(printing::kSettingPrinterType, static_cast<int>(printing::PrinterType::kLocal));
  settings.SetBoolKey(printing::kSettingShouldPrintSelectionOnly, false);
  settings.SetBoolKey(printing::kSettingRasterizePdf, false);

  
  std::vector<gin_helper::Dictionary> page_ranges;
  if (options.Get("pageRanges", &page_ranges)) {
    base::Value page_range_list(base::Value::Type::LIST);
    for (auto& range : page_ranges) {
      int from, to;
      if (range.Get("from", &from) && range.Get("to", &to)) {
        base::Value range(base::Value::Type::DICTIONARY);
        
        range.SetIntKey(printing::kSettingPageRangeFrom, from + 1);
        range.SetIntKey(printing::kSettingPageRangeTo, to + 1);
        page_range_list.Append(std::move(range));
      } else {
        continue;
      }
    }
    if (!page_range_list.GetList().empty())
      settings.SetPath(printing::kSettingPageRange, std::move(page_range_list));
  }

  
  printing::mojom::DuplexMode duplex_mode = printing::mojom::DuplexMode::kSimplex;
  options.Get("duplexMode", &duplex_mode);
  settings.SetIntKey(printing::kSettingDuplexMode, static_cast<int>(duplex_mode));

  
  
  base::Value media_size(base::Value::Type::DICTIONARY);
  if (options.Get("mediaSize", &media_size))
    settings.SetKey(printing::kSettingMediaSize, std::move(media_size));

  
  gin_helper::Dictionary dpi_settings;
  int dpi = 72;
  if (options.Get("dpi", &dpi_settings)) {
    int horizontal = 72;
    dpi_settings.Get("horizontal", &horizontal);
    settings.SetIntKey(printing::kSettingDpiHorizontal, horizontal);
    int vertical = 72;
    dpi_settings.Get("vertical", &vertical);
    settings.SetIntKey(printing::kSettingDpiVertical, vertical);
  } else {
    settings.SetIntKey(printing::kSettingDpiHorizontal, dpi);
    settings.SetIntKey(printing::kSettingDpiVertical, dpi);
  }

  base::ThreadPool::PostTaskAndReplyWithResult( FROM_HERE, {base::MayBlock(), base::TaskPriority::USER_BLOCKING}, base::BindOnce(&GetDefaultPrinterAsync), base::BindOnce(&WebContents::OnGetDefaultPrinter, weak_factory_.GetWeakPtr(), std::move(settings), std::move(callback), device_name, silent));




}

v8::Local<v8::Promise> WebContents::PrintToPDF(base::DictionaryValue settings) {
  v8::Isolate* isolate = JavascriptEnvironment::GetIsolate();
  gin_helper::Promise<v8::Local<v8::Value>> promise(isolate);
  v8::Local<v8::Promise> handle = promise.GetHandle();
  PrintPreviewMessageHandler::FromWebContents(web_contents())
      ->PrintToPDF(std::move(settings), std::move(promise));
  return handle;
}


void WebContents::AddWorkSpace(gin::Arguments* args, const base::FilePath& path) {
  if (path.empty()) {
    gin_helper::ErrorThrower(args->isolate())
        .ThrowError("path cannot be empty");
    return;
  }
  DevToolsAddFileSystem(std::string(), path);
}

void WebContents::RemoveWorkSpace(gin::Arguments* args, const base::FilePath& path) {
  if (path.empty()) {
    gin_helper::ErrorThrower(args->isolate())
        .ThrowError("path cannot be empty");
    return;
  }
  DevToolsRemoveFileSystem(path);
}

void WebContents::Undo() {
  web_contents()->Undo();
}

void WebContents::Redo() {
  web_contents()->Redo();
}

void WebContents::Cut() {
  web_contents()->Cut();
}

void WebContents::Copy() {
  web_contents()->Copy();
}

void WebContents::Paste() {
  web_contents()->Paste();
}

void WebContents::PasteAndMatchStyle() {
  web_contents()->PasteAndMatchStyle();
}

void WebContents::Delete() {
  web_contents()->Delete();
}

void WebContents::SelectAll() {
  web_contents()->SelectAll();
}

void WebContents::Unselect() {
  web_contents()->CollapseSelection();
}

void WebContents::Replace(const base::string16& word) {
  web_contents()->Replace(word);
}

void WebContents::ReplaceMisspelling(const base::string16& word) {
  web_contents()->ReplaceMisspelling(word);
}

uint32_t WebContents::FindInPage(gin::Arguments* args) {
  base::string16 search_text;
  if (!args->GetNext(&search_text) || search_text.empty()) {
    gin_helper::ErrorThrower(args->isolate())
        .ThrowError("Must provide a non-empty search content");
    return 0;
  }

  uint32_t request_id = ++find_in_page_request_id_;
  gin_helper::Dictionary dict;
  auto options = blink::mojom::FindOptions::New();
  if (args->GetNext(&dict)) {
    dict.Get("forward", &options->forward);
    dict.Get("matchCase", &options->match_case);
    dict.Get("findNext", &options->new_session);
  }

  web_contents()->Find(request_id, search_text, std::move(options));
  return request_id;
}

void WebContents::StopFindInPage(content::StopFindAction action) {
  web_contents()->StopFinding(action);
}

void WebContents::ShowDefinitionForSelection() {

  auto* const view = web_contents()->GetRenderWidgetHostView();
  if (view)
    view->ShowDefinitionForSelection();

}

void WebContents::CopyImageAt(int x, int y) {
  auto* const host = web_contents()->GetMainFrame();
  if (host)
    host->CopyImageAt(x, y);
}

void WebContents::Focus() {
  
  

  if (owner_window())
    owner_window()->Focus(true);

  web_contents()->Focus();
}


bool WebContents::IsFocused() const {
  auto* view = web_contents()->GetRenderWidgetHostView();
  if (!view)
    return false;

  if (GetType() != Type::kBackgroundPage) {
    auto* window = web_contents()->GetNativeView()->GetToplevelWindow();
    if (window && !window->IsVisible())
      return false;
  }

  return view->HasFocus();
}


bool WebContents::SendIPCMessage(bool internal, const std::string& channel, v8::Local<v8::Value> args) {

  v8::Isolate* isolate = JavascriptEnvironment::GetIsolate();
  blink::CloneableMessage message;
  if (!gin::ConvertFromV8(isolate, args, &message)) {
    isolate->ThrowException(v8::Exception::Error( gin::StringToV8(isolate, "Failed to serialize arguments")));
    return false;
  }
  return SendIPCMessageWithSender(internal, channel, std::move(message));
}

bool WebContents::SendIPCMessageWithSender(bool internal, const std::string& channel, blink::CloneableMessage args, int32_t sender_id) {


  auto* frame_host = web_contents()->GetMainFrame();
  mojo::AssociatedRemote<mojom::ElectronRenderer> electron_renderer;
  frame_host->GetRemoteAssociatedInterfaces()->GetInterface(&electron_renderer);
  electron_renderer->Message(internal, channel, std::move(args), sender_id);
  return true;
}

bool WebContents::SendIPCMessageToFrame(bool internal, int32_t frame_id, const std::string& channel, v8::Local<v8::Value> args) {


  v8::Isolate* isolate = JavascriptEnvironment::GetIsolate();
  blink::CloneableMessage message;
  if (!gin::ConvertFromV8(isolate, args, &message)) {
    isolate->ThrowException(v8::Exception::Error( gin::StringToV8(isolate, "Failed to serialize arguments")));
    return false;
  }
  auto frames = web_contents()->GetAllFrames();
  auto iter = std::find_if(frames.begin(), frames.end(), [frame_id](auto* f) {
    return f->GetRoutingID() == frame_id;
  });
  if (iter == frames.end())
    return false;
  if (!(*iter)->IsRenderFrameLive())
    return false;

  mojo::AssociatedRemote<mojom::ElectronRenderer> electron_renderer;
  (*iter)->GetRemoteAssociatedInterfaces()->GetInterface(&electron_renderer);
  electron_renderer->Message(internal, channel, std::move(message), 0 );
  return true;
}

void WebContents::SendInputEvent(v8::Isolate* isolate, v8::Local<v8::Value> input_event) {
  content::RenderWidgetHostView* view = web_contents()->GetRenderWidgetHostView();
  if (!view)
    return;

  content::RenderWidgetHost* rwh = view->GetRenderWidgetHost();
  blink::WebInputEvent::Type type = gin::GetWebInputEventType(isolate, input_event);
  if (blink::WebInputEvent::IsMouseEventType(type)) {
    blink::WebMouseEvent mouse_event;
    if (gin::ConvertFromV8(isolate, input_event, &mouse_event)) {
      if (IsOffScreen()) {

        GetOffScreenRenderWidgetHostView()->SendMouseEvent(mouse_event);

      } else {
        rwh->ForwardMouseEvent(mouse_event);
      }
      return;
    }
  } else if (blink::WebInputEvent::IsKeyboardEventType(type)) {
    content::NativeWebKeyboardEvent keyboard_event( blink::WebKeyboardEvent::Type::kRawKeyDown, blink::WebInputEvent::Modifiers::kNoModifiers, ui::EventTimeForNow());

    if (gin::ConvertFromV8(isolate, input_event, &keyboard_event)) {
      rwh->ForwardKeyboardEvent(keyboard_event);
      return;
    }
  } else if (type == blink::WebInputEvent::Type::kMouseWheel) {
    blink::WebMouseWheelEvent mouse_wheel_event;
    if (gin::ConvertFromV8(isolate, input_event, &mouse_wheel_event)) {
      if (IsOffScreen()) {

        GetOffScreenRenderWidgetHostView()->SendMouseWheelEvent( mouse_wheel_event);

      } else {
        
        
        mouse_wheel_event.phase = blink::WebMouseWheelEvent::kPhaseBegan;
        mouse_wheel_event.dispatch_type = blink::WebInputEvent::DispatchType::kBlocking;
        rwh->ForwardWheelEvent(mouse_wheel_event);

        
        mouse_wheel_event.has_synthetic_phase = true;
        mouse_wheel_event.delta_x = 0;
        mouse_wheel_event.delta_y = 0;
        mouse_wheel_event.phase = blink::WebMouseWheelEvent::kPhaseEnded;
        mouse_wheel_event.dispatch_type = blink::WebInputEvent::DispatchType::kEventNonBlocking;
        rwh->ForwardWheelEvent(mouse_wheel_event);
      }
      return;
    }
  }

  isolate->ThrowException( v8::Exception::Error(gin::StringToV8(isolate, "Invalid event object")));
}

void WebContents::BeginFrameSubscription(gin::Arguments* args) {
  bool only_dirty = false;
  FrameSubscriber::FrameCaptureCallback callback;

  if (args->Length() > 1) {
    if (!args->GetNext(&only_dirty)) {
      args->ThrowError();
      return;
    }
  }
  if (!args->GetNext(&callback)) {
    args->ThrowError();
    return;
  }

  frame_subscriber_ = std::make_unique<FrameSubscriber>(web_contents(), callback, only_dirty);
}

void WebContents::EndFrameSubscription() {
  frame_subscriber_.reset();
}

void WebContents::StartDrag(const gin_helper::Dictionary& item, gin::Arguments* args) {
  base::FilePath file;
  std::vector<base::FilePath> files;
  if (!item.Get("files", &files) && item.Get("file", &file)) {
    files.push_back(file);
  }

  gin::Handle<NativeImage> icon;
  if (!item.Get("icon", &icon) || icon->image().IsEmpty()) {
    gin_helper::ErrorThrower(args->isolate())
        .ThrowError("Must specify non-empty 'icon' option");
    return;
  }

  
  if (!files.empty()) {
    base::CurrentThread::ScopedNestableTaskAllower allow;
    DragFileItems(files, icon->image(), web_contents()->GetNativeView());
  } else {
    gin_helper::ErrorThrower(args->isolate())
        .ThrowError("Must specify either 'file' or 'files' option");
  }
}

v8::Local<v8::Promise> WebContents::CapturePage(gin::Arguments* args) {
  gfx::Rect rect;
  gin_helper::Promise<gfx::Image> promise(args->isolate());
  v8::Local<v8::Promise> handle = promise.GetHandle();

  
  args->GetNext(&rect);

  auto* const view = web_contents()->GetRenderWidgetHostView();
  if (!view) {
    promise.Resolve(gfx::Image());
    return handle;
  }

  
  const gfx::Size view_size = rect.IsEmpty() ? view->GetViewBounds().size() : rect.size();

  
  
  
  gfx::Size bitmap_size = view_size;
  const gfx::NativeView native_view = view->GetNativeView();
  const float scale = display::Screen::GetScreen()
                          ->GetDisplayNearestView(native_view)
                          .device_scale_factor();
  if (scale > 1.0f)
    bitmap_size = gfx::ScaleToCeiledSize(view_size, scale);

  view->CopyFromSurface(gfx::Rect(rect.origin(), view_size), bitmap_size, base::BindOnce(&OnCapturePageDone, std::move(promise)));
  return handle;
}

void WebContents::IncrementCapturerCount(gin::Arguments* args) {
  gfx::Size size;
  bool stay_hidden = false;

  
  args->GetNext(&size);
  
  args->GetNext(&stay_hidden);

  web_contents()->IncrementCapturerCount(size, stay_hidden);
}

void WebContents::DecrementCapturerCount(gin::Arguments* args) {
  bool stay_hidden = false;

  
  args->GetNext(&stay_hidden);

  web_contents()->DecrementCapturerCount(stay_hidden);
}

bool WebContents::IsBeingCaptured() {
  return web_contents()->IsBeingCaptured();
}

void WebContents::OnCursorChanged(const content::WebCursor& webcursor) {
  const ui::Cursor& cursor = webcursor.cursor();

  if (cursor.type() == ui::mojom::CursorType::kCustom) {
    Emit("cursor-changed", CursorTypeToString(cursor), gfx::Image::CreateFrom1xBitmap(cursor.custom_bitmap()), cursor.image_scale_factor(), gfx::Size(cursor.custom_bitmap().width(), cursor.custom_bitmap().height()), cursor.custom_hotspot());




  } else {
    Emit("cursor-changed", CursorTypeToString(cursor));
  }
}

bool WebContents::IsGuest() const {
  return type_ == Type::kWebView;
}

void WebContents::AttachToIframe(content::WebContents* embedder_web_contents, int embedder_frame_id) {
  if (guest_delegate_)
    guest_delegate_->AttachToIframe(embedder_web_contents, embedder_frame_id);
}

bool WebContents::IsOffScreen() const {

  return type_ == Type::kOffScreen;

  return false;

}


void WebContents::OnPaint(const gfx::Rect& dirty_rect, const SkBitmap& bitmap) {
  Emit("paint", dirty_rect, gfx::Image::CreateFrom1xBitmap(bitmap));
}

void WebContents::StartPainting() {
  auto* osr_wcv = GetOffScreenWebContentsView();
  if (osr_wcv)
    osr_wcv->SetPainting(true);
}

void WebContents::StopPainting() {
  auto* osr_wcv = GetOffScreenWebContentsView();
  if (osr_wcv)
    osr_wcv->SetPainting(false);
}

bool WebContents::IsPainting() const {
  auto* osr_wcv = GetOffScreenWebContentsView();
  return osr_wcv && osr_wcv->IsPainting();
}

void WebContents::SetFrameRate(int frame_rate) {
  auto* osr_wcv = GetOffScreenWebContentsView();
  if (osr_wcv)
    osr_wcv->SetFrameRate(frame_rate);
}

int WebContents::GetFrameRate() const {
  auto* osr_wcv = GetOffScreenWebContentsView();
  return osr_wcv ? osr_wcv->GetFrameRate() : 0;
}


void WebContents::Invalidate() {
  if (IsOffScreen()) {

    auto* osr_rwhv = GetOffScreenRenderWidgetHostView();
    if (osr_rwhv)
      osr_rwhv->Invalidate();

  } else {
    auto* const window = owner_window();
    if (window)
      window->Invalidate();
  }
}

gfx::Size WebContents::GetSizeForNewRenderView(content::WebContents* wc) {
  if (IsOffScreen() && wc == web_contents()) {
    auto* relay = NativeWindowRelay::FromWebContents(web_contents());
    if (relay) {
      auto* owner_window = relay->GetNativeWindow();
      return owner_window ? owner_window->GetSize() : gfx::Size();
    }
  }

  return gfx::Size();
}

void WebContents::SetZoomLevel(double level) {
  zoom_controller_->SetZoomLevel(level);
}

double WebContents::GetZoomLevel() const {
  return zoom_controller_->GetZoomLevel();
}

void WebContents::SetZoomFactor(gin_helper::ErrorThrower thrower, double factor) {
  if (factor < std::numeric_limits<double>::epsilon()) {
    thrower.ThrowError("'zoomFactor' must be a double greater than 0.0");
    return;
  }

  auto level = blink::PageZoomFactorToZoomLevel(factor);
  SetZoomLevel(level);
}

double WebContents::GetZoomFactor() const {
  auto level = GetZoomLevel();
  return blink::PageZoomLevelToZoomFactor(level);
}

void WebContents::SetTemporaryZoomLevel(double level) {
  zoom_controller_->SetTemporaryZoomLevel(level);
}

void WebContents::DoGetZoomLevel(DoGetZoomLevelCallback callback) {
  std::move(callback).Run(GetZoomLevel());
}

std::vector<base::FilePath> WebContents::GetPreloadPaths() const {
  auto result = SessionPreferences::GetValidPreloads(GetBrowserContext());

  if (auto* web_preferences = WebContentsPreferences::From(web_contents())) {
    base::FilePath preload;
    if (web_preferences->GetPreloadPath(&preload)) {
      result.emplace_back(preload);
    }
  }

  return result;
}

v8::Local<v8::Value> WebContents::GetWebPreferences( v8::Isolate* isolate) const {
  auto* web_preferences = WebContentsPreferences::From(web_contents());
  if (!web_preferences)
    return v8::Null(isolate);
  return gin::ConvertToV8(isolate, *web_preferences->preference());
}

v8::Local<v8::Value> WebContents::GetLastWebPreferences( v8::Isolate* isolate) const {
  auto* web_preferences = WebContentsPreferences::From(web_contents());
  if (!web_preferences)
    return v8::Null(isolate);
  return gin::ConvertToV8(isolate, *web_preferences->last_preference());
}

v8::Local<v8::Value> WebContents::GetOwnerBrowserWindow( v8::Isolate* isolate) const {
  if (owner_window())
    return BrowserWindow::From(isolate, owner_window());
  else return v8::Null(isolate);
}

v8::Local<v8::Value> WebContents::Session(v8::Isolate* isolate) {
  return v8::Local<v8::Value>::New(isolate, session_);
}

content::WebContents* WebContents::HostWebContents() const {
  if (!embedder_)
    return nullptr;
  return embedder_->web_contents();
}

void WebContents::SetEmbedder(const WebContents* embedder) {
  if (embedder) {
    NativeWindow* owner_window = nullptr;
    auto* relay = NativeWindowRelay::FromWebContents(embedder->web_contents());
    if (relay) {
      owner_window = relay->GetNativeWindow();
    }
    if (owner_window)
      SetOwnerWindow(owner_window);

    content::RenderWidgetHostView* rwhv = web_contents()->GetRenderWidgetHostView();
    if (rwhv) {
      rwhv->Hide();
      rwhv->Show();
    }
  }
}

void WebContents::SetDevToolsWebContents(const WebContents* devtools) {
  if (inspectable_web_contents_)
    inspectable_web_contents_->SetDevToolsWebContents(devtools->web_contents());
}

v8::Local<v8::Value> WebContents::GetNativeView(v8::Isolate* isolate) const {
  gfx::NativeView ptr = web_contents()->GetNativeView();
  auto buffer = node::Buffer::Copy(isolate, reinterpret_cast<char*>(&ptr), sizeof(gfx::NativeView));
  if (buffer.IsEmpty())
    return v8::Null(isolate);
  else return buffer.ToLocalChecked();
}

v8::Local<v8::Value> WebContents::DevToolsWebContents(v8::Isolate* isolate) {
  if (devtools_web_contents_.IsEmpty())
    return v8::Null(isolate);
  else return v8::Local<v8::Value>::New(isolate, devtools_web_contents_);
}

v8::Local<v8::Value> WebContents::Debugger(v8::Isolate* isolate) {
  if (debugger_.IsEmpty()) {
    auto handle = electron::api::Debugger::Create(isolate, web_contents());
    debugger_.Reset(isolate, handle.ToV8());
  }
  return v8::Local<v8::Value>::New(isolate, debugger_);
}

bool WebContents::WasInitiallyShown() {
  return initially_shown_;
}

content::RenderFrameHost* WebContents::MainFrame() {
  return web_contents()->GetMainFrame();
}

void WebContents::GrantOriginAccess(const GURL& url) {
  content::ChildProcessSecurityPolicy::GetInstance()->GrantCommitOrigin( web_contents()->GetMainFrame()->GetProcess()->GetID(), url::Origin::Create(url));

}

void WebContents::NotifyUserActivation() {
  auto* frame = web_contents()->GetMainFrame();
  if (!frame)
    return;
  mojo::AssociatedRemote<mojom::ElectronRenderer> renderer;
  frame->GetRemoteAssociatedInterfaces()->GetInterface(&renderer);
  renderer->NotifyUserActivation();
}

v8::Local<v8::Promise> WebContents::TakeHeapSnapshot( v8::Isolate* isolate, const base::FilePath& file_path) {

  gin_helper::Promise<void> promise(isolate);
  v8::Local<v8::Promise> handle = promise.GetHandle();

  base::ThreadRestrictions::ScopedAllowIO allow_io;
  base::File file(file_path, base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
  if (!file.IsValid()) {
    promise.RejectWithErrorMessage("takeHeapSnapshot failed");
    return handle;
  }

  auto* frame_host = web_contents()->GetMainFrame();
  if (!frame_host) {
    promise.RejectWithErrorMessage("takeHeapSnapshot failed");
    return handle;
  }

  
  
  
  auto electron_renderer = std::make_unique<mojo::AssociatedRemote<mojom::ElectronRenderer>>();
  frame_host->GetRemoteAssociatedInterfaces()->GetInterface( electron_renderer.get());
  auto* raw_ptr = electron_renderer.get();
  (*raw_ptr)->TakeHeapSnapshot( mojo::WrapPlatformFile(base::ScopedPlatformFile(file.TakePlatformFile())), base::BindOnce( [](mojo::AssociatedRemote<mojom::ElectronRenderer>* ep, gin_helper::Promise<void> promise, bool success) {



            if (success) {
              promise.Resolve();
            } else {
              promise.RejectWithErrorMessage("takeHeapSnapshot failed");
            }
          }, base::Owned(std::move(electron_renderer)), std::move(promise)));
  return handle;
}

void WebContents::UpdatePreferredSize(content::WebContents* web_contents, const gfx::Size& pref_size) {
  Emit("preferred-size-changed", pref_size);
}

bool WebContents::CanOverscrollContent() {
  return false;
}

content::ColorChooser* WebContents::OpenColorChooser( content::WebContents* web_contents, SkColor color, const std::vector<blink::mojom::ColorSuggestionPtr>& suggestions) {



  return chrome::ShowColorChooser(web_contents, color);

  return nullptr;

}

void WebContents::RunFileChooser( content::RenderFrameHost* render_frame_host, scoped_refptr<content::FileSelectListener> listener, const blink::mojom::FileChooserParams& params) {


  if (!web_dialog_helper_)
    web_dialog_helper_ = std::make_unique<WebDialogHelper>(owner_window(), offscreen_);
  web_dialog_helper_->RunFileChooser(render_frame_host, std::move(listener), params);
}

void WebContents::EnumerateDirectory( content::WebContents* guest, scoped_refptr<content::FileSelectListener> listener, const base::FilePath& path) {


  if (!web_dialog_helper_)
    web_dialog_helper_ = std::make_unique<WebDialogHelper>(owner_window(), offscreen_);
  web_dialog_helper_->EnumerateDirectory(guest, std::move(listener), path);
}

bool WebContents::IsFullscreenForTabOrPending( const content::WebContents* source) {
  return html_fullscreen_;
}

blink::SecurityStyle WebContents::GetSecurityStyle( content::WebContents* web_contents, content::SecurityStyleExplanations* security_style_explanations) {

  SecurityStateTabHelper* helper = SecurityStateTabHelper::FromWebContents(web_contents);
  DCHECK(helper);
  return security_state::GetSecurityStyle(helper->GetSecurityLevel(), *helper->GetVisibleSecurityState(), security_style_explanations);

}

bool WebContents::TakeFocus(content::WebContents* source, bool reverse) {
  if (source && source->GetOutermostWebContents() == source) {
    
    
    
    source->FocusThroughTabTraversal(reverse);
    return true;
  }

  return false;
}

content::PictureInPictureResult WebContents::EnterPictureInPicture( content::WebContents* web_contents, const viz::SurfaceId& surface_id, const gfx::Size& natural_size) {



  return PictureInPictureWindowManager::GetInstance()->EnterPictureInPicture( web_contents, surface_id, natural_size);

  return content::PictureInPictureResult::kNotSupported;

}

void WebContents::ExitPictureInPicture() {

  PictureInPictureWindowManager::GetInstance()->ExitPictureInPicture();

}

void WebContents::DevToolsSaveToFile(const std::string& url, const std::string& content, bool save_as) {

  base::FilePath path;
  auto it = saved_files_.find(url);
  if (it != saved_files_.end() && !save_as) {
    path = it->second;
  } else {
    file_dialog::DialogSettings settings;
    settings.parent_window = owner_window();
    settings.force_detached = offscreen_;
    settings.title = url;
    settings.default_path = base::FilePath::FromUTF8Unsafe(url);
    if (!file_dialog::ShowSaveDialogSync(settings, &path)) {
      base::Value url_value(url);
      inspectable_web_contents_->CallClientFunction( "DevToolsAPI.canceledSaveURL", &url_value, nullptr, nullptr);
      return;
    }
  }

  saved_files_[url] = path;
  
  base::Value url_value(url);
  base::Value file_system_path_value(path.AsUTF8Unsafe());
  inspectable_web_contents_->CallClientFunction( "DevToolsAPI.savedURL", &url_value, &file_system_path_value, nullptr);
  file_task_runner_->PostTask(FROM_HERE, base::BindOnce(&WriteToFile, path, content));
}

void WebContents::DevToolsAppendToFile(const std::string& url, const std::string& content) {
  auto it = saved_files_.find(url);
  if (it == saved_files_.end())
    return;

  
  base::Value url_value(url);
  inspectable_web_contents_->CallClientFunction("DevToolsAPI.appendedToURL", &url_value, nullptr, nullptr);
  file_task_runner_->PostTask( FROM_HERE, base::BindOnce(&AppendToFile, it->second, content));
}

void WebContents::DevToolsRequestFileSystems() {
  auto file_system_paths = GetAddedFileSystemPaths(GetDevToolsWebContents());
  if (file_system_paths.empty()) {
    base::ListValue empty_file_system_value;
    inspectable_web_contents_->CallClientFunction( "DevToolsAPI.fileSystemsLoaded", &empty_file_system_value, nullptr, nullptr);

    return;
  }

  std::vector<FileSystem> file_systems;
  for (const auto& file_system_path : file_system_paths) {
    base::FilePath path = base::FilePath::FromUTF8Unsafe(file_system_path.first);
    std::string file_system_id = RegisterFileSystem(GetDevToolsWebContents(), path);
    FileSystem file_system = CreateFileSystemStruct(GetDevToolsWebContents(), file_system_id, file_system_path.first, file_system_path.second);

    file_systems.push_back(file_system);
  }

  base::ListValue file_system_value;
  for (const auto& file_system : file_systems)
    file_system_value.Append(CreateFileSystemValue(file_system));
  inspectable_web_contents_->CallClientFunction( "DevToolsAPI.fileSystemsLoaded", &file_system_value, nullptr, nullptr);
}

void WebContents::DevToolsAddFileSystem( const std::string& type, const base::FilePath& file_system_path) {

  base::FilePath path = file_system_path;
  if (path.empty()) {
    std::vector<base::FilePath> paths;
    file_dialog::DialogSettings settings;
    settings.parent_window = owner_window();
    settings.force_detached = offscreen_;
    settings.properties = file_dialog::OPEN_DIALOG_OPEN_DIRECTORY;
    if (!file_dialog::ShowOpenDialogSync(settings, &paths))
      return;

    path = paths[0];
  }

  std::string file_system_id = RegisterFileSystem(GetDevToolsWebContents(), path);
  if (IsDevToolsFileSystemAdded(GetDevToolsWebContents(), path.AsUTF8Unsafe()))
    return;

  FileSystem file_system = CreateFileSystemStruct( GetDevToolsWebContents(), file_system_id, path.AsUTF8Unsafe(), type);
  std::unique_ptr<base::DictionaryValue> file_system_value( CreateFileSystemValue(file_system));

  auto* pref_service = GetPrefService(GetDevToolsWebContents());
  DictionaryPrefUpdate update(pref_service, prefs::kDevToolsFileSystemPaths);
  update.Get()->SetWithoutPathExpansion(path.AsUTF8Unsafe(), std::make_unique<base::Value>(type));
  inspectable_web_contents_->CallClientFunction( "DevToolsAPI.fileSystemAdded", nullptr, file_system_value.get(), nullptr);
}

void WebContents::DevToolsRemoveFileSystem( const base::FilePath& file_system_path) {
  if (!inspectable_web_contents_)
    return;

  std::string path = file_system_path.AsUTF8Unsafe();
  storage::IsolatedContext::GetInstance()->RevokeFileSystemByPath( file_system_path);

  auto* pref_service = GetPrefService(GetDevToolsWebContents());
  DictionaryPrefUpdate update(pref_service, prefs::kDevToolsFileSystemPaths);
  update.Get()->RemoveWithoutPathExpansion(path, nullptr);

  base::Value file_system_path_value(path);
  inspectable_web_contents_->CallClientFunction("DevToolsAPI.fileSystemRemoved", &file_system_path_value, nullptr, nullptr);

}

void WebContents::DevToolsIndexPath( int request_id, const std::string& file_system_path, const std::string& excluded_folders_message) {


  if (!IsDevToolsFileSystemAdded(GetDevToolsWebContents(), file_system_path)) {
    OnDevToolsIndexingDone(request_id, file_system_path);
    return;
  }
  if (devtools_indexing_jobs_.count(request_id) != 0)
    return;
  std::vector<std::string> excluded_folders;
  std::unique_ptr<base::Value> parsed_excluded_folders = base::JSONReader::ReadDeprecated(excluded_folders_message);
  if (parsed_excluded_folders && parsed_excluded_folders->is_list()) {
    for (const base::Value& folder_path : parsed_excluded_folders->GetList()) {
      if (folder_path.is_string())
        excluded_folders.push_back(folder_path.GetString());
    }
  }
  devtools_indexing_jobs_[request_id] = scoped_refptr<DevToolsFileSystemIndexer::FileSystemIndexingJob>( devtools_file_system_indexer_->IndexPath( file_system_path, excluded_folders, base::BindRepeating( &WebContents::OnDevToolsIndexingWorkCalculated, weak_factory_.GetWeakPtr(), request_id, file_system_path), base::BindRepeating(&WebContents::OnDevToolsIndexingWorked, weak_factory_.GetWeakPtr(), request_id, file_system_path), base::BindRepeating(&WebContents::OnDevToolsIndexingDone, weak_factory_.GetWeakPtr(), request_id, file_system_path)));











}

void WebContents::DevToolsStopIndexing(int request_id) {
  auto it = devtools_indexing_jobs_.find(request_id);
  if (it == devtools_indexing_jobs_.end())
    return;
  it->second->Stop();
  devtools_indexing_jobs_.erase(it);
}

void WebContents::DevToolsSearchInPath(int request_id, const std::string& file_system_path, const std::string& query) {

  if (!IsDevToolsFileSystemAdded(GetDevToolsWebContents(), file_system_path)) {
    OnDevToolsSearchCompleted(request_id, file_system_path, std::vector<std::string>());
    return;
  }
  devtools_file_system_indexer_->SearchInPath( file_system_path, query, base::BindRepeating(&WebContents::OnDevToolsSearchCompleted, weak_factory_.GetWeakPtr(), request_id, file_system_path));



}


gfx::ImageSkia WebContents::GetDevToolsWindowIcon() {
  if (!owner_window())
    return gfx::ImageSkia();
  return owner_window()->GetWindowAppIcon();
}



void WebContents::GetDevToolsWindowWMClass(std::string* name, std::string* class_name) {
  *class_name = Browser::Get()->GetName();
  *name = base::ToLowerASCII(*class_name);
}


void WebContents::OnDevToolsIndexingWorkCalculated( int request_id, const std::string& file_system_path, int total_work) {


  base::Value request_id_value(request_id);
  base::Value file_system_path_value(file_system_path);
  base::Value total_work_value(total_work);
  inspectable_web_contents_->CallClientFunction( "DevToolsAPI.indexingTotalWorkCalculated", &request_id_value, &file_system_path_value, &total_work_value);

}

void WebContents::OnDevToolsIndexingWorked(int request_id, const std::string& file_system_path, int worked) {

  base::Value request_id_value(request_id);
  base::Value file_system_path_value(file_system_path);
  base::Value worked_value(worked);
  inspectable_web_contents_->CallClientFunction( "DevToolsAPI.indexingWorked", &request_id_value, &file_system_path_value, &worked_value);

}

void WebContents::OnDevToolsIndexingDone(int request_id, const std::string& file_system_path) {
  devtools_indexing_jobs_.erase(request_id);
  base::Value request_id_value(request_id);
  base::Value file_system_path_value(file_system_path);
  inspectable_web_contents_->CallClientFunction( "DevToolsAPI.indexingDone", &request_id_value, &file_system_path_value, nullptr);

}

void WebContents::OnDevToolsSearchCompleted( int request_id, const std::string& file_system_path, const std::vector<std::string>& file_paths) {


  base::ListValue file_paths_value;
  for (const auto& file_path : file_paths) {
    file_paths_value.AppendString(file_path);
  }
  base::Value request_id_value(request_id);
  base::Value file_system_path_value(file_system_path);
  inspectable_web_contents_->CallClientFunction( "DevToolsAPI.searchCompleted", &request_id_value, &file_system_path_value, &file_paths_value);

}

void WebContents::SetHtmlApiFullscreen(bool enter_fullscreen) {
  
  if (enter_fullscreen && owner_window_->IsFullscreen()) {
    native_fullscreen_ = true;
    html_fullscreen_ = true;
    return;
  }

  
  if (!enter_fullscreen && native_fullscreen_) {
    html_fullscreen_ = false;
    return;
  }

  
  auto* web_preferences = WebContentsPreferences::From(GetWebContents());
  bool html_fullscreenable = web_preferences ? !web_preferences->IsEnabled( options::kDisableHtmlFullscreenWindowResize)

                      : true;

  if (html_fullscreenable) {
    owner_window_->SetFullScreen(enter_fullscreen);
  }

  html_fullscreen_ = enter_fullscreen;
  native_fullscreen_ = false;
}


v8::Local<v8::ObjectTemplate> WebContents::FillObjectTemplate( v8::Isolate* isolate, v8::Local<v8::ObjectTemplate> templ) {

  gin::InvokerOptions options;
  options.holder_is_first_argument = true;
  options.holder_type = "WebContents";
  templ->Set( gin::StringToSymbol(isolate, "isDestroyed"), gin::CreateFunctionTemplate( isolate, base::BindRepeating(&gin_helper::Destroyable::IsDestroyed), options));



  templ->Set( gin::StringToSymbol(isolate, "destroy"), gin::CreateFunctionTemplate( isolate, base::BindRepeating([](gin::Handle<WebContents> handle) {


            delete handle.get();
          }), options));
  
  
  
  return gin_helper::ObjectTemplateBuilder(isolate, templ)
      .SetMethod("getBackgroundThrottling", &WebContents::GetBackgroundThrottling)
      .SetMethod("setBackgroundThrottling", &WebContents::SetBackgroundThrottling)
      .SetMethod("getProcessId", &WebContents::GetProcessID)
      .SetMethod("getOSProcessId", &WebContents::GetOSProcessID)
      .SetMethod("equal", &WebContents::Equal)
      .SetMethod("_loadURL", &WebContents::LoadURL)
      .SetMethod("downloadURL", &WebContents::DownloadURL)
      .SetMethod("_getURL", &WebContents::GetURL)
      .SetMethod("getTitle", &WebContents::GetTitle)
      .SetMethod("isLoading", &WebContents::IsLoading)
      .SetMethod("isLoadingMainFrame", &WebContents::IsLoadingMainFrame)
      .SetMethod("isWaitingForResponse", &WebContents::IsWaitingForResponse)
      .SetMethod("_stop", &WebContents::Stop)
      .SetMethod("_goBack", &WebContents::GoBack)
      .SetMethod("_goForward", &WebContents::GoForward)
      .SetMethod("_goToOffset", &WebContents::GoToOffset)
      .SetMethod("isCrashed", &WebContents::IsCrashed)
      .SetMethod("forcefullyCrashRenderer", &WebContents::ForcefullyCrashRenderer)
      .SetMethod("setUserAgent", &WebContents::SetUserAgent)
      .SetMethod("getUserAgent", &WebContents::GetUserAgent)
      .SetMethod("savePage", &WebContents::SavePage)
      .SetMethod("openDevTools", &WebContents::OpenDevTools)
      .SetMethod("closeDevTools", &WebContents::CloseDevTools)
      .SetMethod("isDevToolsOpened", &WebContents::IsDevToolsOpened)
      .SetMethod("isDevToolsFocused", &WebContents::IsDevToolsFocused)
      .SetMethod("enableDeviceEmulation", &WebContents::EnableDeviceEmulation)
      .SetMethod("disableDeviceEmulation", &WebContents::DisableDeviceEmulation)
      .SetMethod("toggleDevTools", &WebContents::ToggleDevTools)
      .SetMethod("inspectElement", &WebContents::InspectElement)
      .SetMethod("setIgnoreMenuShortcuts", &WebContents::SetIgnoreMenuShortcuts)
      .SetMethod("setAudioMuted", &WebContents::SetAudioMuted)
      .SetMethod("isAudioMuted", &WebContents::IsAudioMuted)
      .SetMethod("isCurrentlyAudible", &WebContents::IsCurrentlyAudible)
      .SetMethod("undo", &WebContents::Undo)
      .SetMethod("redo", &WebContents::Redo)
      .SetMethod("cut", &WebContents::Cut)
      .SetMethod("copy", &WebContents::Copy)
      .SetMethod("paste", &WebContents::Paste)
      .SetMethod("pasteAndMatchStyle", &WebContents::PasteAndMatchStyle)
      .SetMethod("delete", &WebContents::Delete)
      .SetMethod("selectAll", &WebContents::SelectAll)
      .SetMethod("unselect", &WebContents::Unselect)
      .SetMethod("replace", &WebContents::Replace)
      .SetMethod("replaceMisspelling", &WebContents::ReplaceMisspelling)
      .SetMethod("findInPage", &WebContents::FindInPage)
      .SetMethod("stopFindInPage", &WebContents::StopFindInPage)
      .SetMethod("focus", &WebContents::Focus)
      .SetMethod("isFocused", &WebContents::IsFocused)
      .SetMethod("_send", &WebContents::SendIPCMessage)
      .SetMethod("_postMessage", &WebContents::PostMessage)
      .SetMethod("_sendToFrame", &WebContents::SendIPCMessageToFrame)
      .SetMethod("sendInputEvent", &WebContents::SendInputEvent)
      .SetMethod("beginFrameSubscription", &WebContents::BeginFrameSubscription)
      .SetMethod("endFrameSubscription", &WebContents::EndFrameSubscription)
      .SetMethod("startDrag", &WebContents::StartDrag)
      .SetMethod("attachToIframe", &WebContents::AttachToIframe)
      .SetMethod("detachFromOuterFrame", &WebContents::DetachFromOuterFrame)
      .SetMethod("isOffscreen", &WebContents::IsOffScreen)

      .SetMethod("startPainting", &WebContents::StartPainting)
      .SetMethod("stopPainting", &WebContents::StopPainting)
      .SetMethod("isPainting", &WebContents::IsPainting)
      .SetMethod("setFrameRate", &WebContents::SetFrameRate)
      .SetMethod("getFrameRate", &WebContents::GetFrameRate)

      .SetMethod("invalidate", &WebContents::Invalidate)
      .SetMethod("setZoomLevel", &WebContents::SetZoomLevel)
      .SetMethod("getZoomLevel", &WebContents::GetZoomLevel)
      .SetMethod("setZoomFactor", &WebContents::SetZoomFactor)
      .SetMethod("getZoomFactor", &WebContents::GetZoomFactor)
      .SetMethod("getType", &WebContents::GetType)
      .SetMethod("_getPreloadPaths", &WebContents::GetPreloadPaths)
      .SetMethod("getWebPreferences", &WebContents::GetWebPreferences)
      .SetMethod("getLastWebPreferences", &WebContents::GetLastWebPreferences)
      .SetMethod("getOwnerBrowserWindow", &WebContents::GetOwnerBrowserWindow)
      .SetMethod("inspectServiceWorker", &WebContents::InspectServiceWorker)
      .SetMethod("inspectSharedWorker", &WebContents::InspectSharedWorker)
      .SetMethod("inspectSharedWorkerById", &WebContents::InspectSharedWorkerById)
      .SetMethod("getAllSharedWorkers", &WebContents::GetAllSharedWorkers)

      .SetMethod("_print", &WebContents::Print)
      .SetMethod("_printToPDF", &WebContents::PrintToPDF)

      .SetMethod("_setNextChildWebPreferences", &WebContents::SetNextChildWebPreferences)
      .SetMethod("addWorkSpace", &WebContents::AddWorkSpace)
      .SetMethod("removeWorkSpace", &WebContents::RemoveWorkSpace)
      .SetMethod("showDefinitionForSelection", &WebContents::ShowDefinitionForSelection)
      .SetMethod("copyImageAt", &WebContents::CopyImageAt)
      .SetMethod("capturePage", &WebContents::CapturePage)
      .SetMethod("setEmbedder", &WebContents::SetEmbedder)
      .SetMethod("setDevToolsWebContents", &WebContents::SetDevToolsWebContents)
      .SetMethod("getNativeView", &WebContents::GetNativeView)
      .SetMethod("incrementCapturerCount", &WebContents::IncrementCapturerCount)
      .SetMethod("decrementCapturerCount", &WebContents::DecrementCapturerCount)
      .SetMethod("isBeingCaptured", &WebContents::IsBeingCaptured)
      .SetMethod("setWebRTCIPHandlingPolicy", &WebContents::SetWebRTCIPHandlingPolicy)
      .SetMethod("getWebRTCIPHandlingPolicy", &WebContents::GetWebRTCIPHandlingPolicy)
      .SetMethod("_grantOriginAccess", &WebContents::GrantOriginAccess)
      .SetMethod("takeHeapSnapshot", &WebContents::TakeHeapSnapshot)
      .SetProperty("id", &WebContents::ID)
      .SetProperty("session", &WebContents::Session)
      .SetProperty("hostWebContents", &WebContents::HostWebContents)
      .SetProperty("devToolsWebContents", &WebContents::DevToolsWebContents)
      .SetProperty("debugger", &WebContents::Debugger)
      .SetProperty("_initiallyShown", &WebContents::WasInitiallyShown)
      .SetProperty("mainFrame", &WebContents::MainFrame)
      .Build();
}

const char* WebContents::GetTypeName() {
  return "WebContents";
}

ElectronBrowserContext* WebContents::GetBrowserContext() const {
  return static_cast<ElectronBrowserContext*>( web_contents()->GetBrowserContext());
}


gin::Handle<WebContents> WebContents::New( v8::Isolate* isolate, const gin_helper::Dictionary& options) {

  gin::Handle<WebContents> handle = gin::CreateHandle(isolate, new WebContents(isolate, options));
  gin_helper::CallMethod(isolate, handle.get(), "_init");
  return handle;
}


gin::Handle<WebContents> WebContents::CreateAndTake( v8::Isolate* isolate, std::unique_ptr<content::WebContents> web_contents, Type type) {


  gin::Handle<WebContents> handle = gin::CreateHandle( isolate, new WebContents(isolate, std::move(web_contents), type));
  gin_helper::CallMethod(isolate, handle.get(), "_init");
  return handle;
}


WebContents* WebContents::From(content::WebContents* web_contents) {
  if (!web_contents)
    return nullptr;
  auto* data = static_cast<UserDataLink*>( web_contents->GetUserData(kElectronApiWebContentsKey));
  return data ? data->web_contents.get() : nullptr;
}


gin::Handle<WebContents> WebContents::FromOrCreate( v8::Isolate* isolate, content::WebContents* web_contents) {

  WebContents* api_web_contents = From(web_contents);
  if (!api_web_contents) {
    api_web_contents = new WebContents(isolate, web_contents);
    gin_helper::CallMethod(isolate, api_web_contents, "_init");
  }
  return gin::CreateHandle(isolate, api_web_contents);
}


WebContents* WebContents::FromID(int32_t id) {
  return GetAllWebContents().Lookup(id);
}


gin::WrapperInfo WebContents::kWrapperInfo = {gin::kEmbedderNativeGin};

}  

}  

namespace {

using electron::api::GetAllWebContents;
using electron::api::WebContents;

gin::Handle<WebContents> WebContentsFromID(v8::Isolate* isolate, int32_t id) {
  WebContents* contents = WebContents::FromID(id);
  return contents ? gin::CreateHandle(isolate, contents)
                  : gin::Handle<WebContents>();
}

std::vector<gin::Handle<WebContents>> GetAllWebContentsAsV8( v8::Isolate* isolate) {
  std::vector<gin::Handle<WebContents>> list;
  for (auto iter = base::IDMap<WebContents*>::iterator(&GetAllWebContents());
       !iter.IsAtEnd(); iter.Advance()) {
    list.push_back(gin::CreateHandle(isolate, iter.GetCurrentValue()));
  }
  return list;
}

void Initialize(v8::Local<v8::Object> exports, v8::Local<v8::Value> unused, v8::Local<v8::Context> context, void* priv) {


  v8::Isolate* isolate = context->GetIsolate();
  gin_helper::Dictionary dict(isolate, exports);
  dict.Set("WebContents", WebContents::GetConstructor(context));
  dict.SetMethod("fromId", &WebContentsFromID);
  dict.SetMethod("getAllWebContents", &GetAllWebContentsAsV8);
}

}  

NODE_LINKED_MODULE_CONTEXT_AWARE(electron_browser_web_contents, Initialize)
