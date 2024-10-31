










namespace gin_helper {

namespace internal {

namespace {

v8::Persistent<v8::ObjectTemplate> event_template;

void PreventDefault(gin_helper::Arguments* args) {
  Dictionary self;
  if (args->GetHolder(&self))
    self.Set("defaultPrevented", true);
}

}  

v8::Local<v8::Object> CreateEvent(v8::Isolate* isolate, v8::Local<v8::Object> sender, v8::Local<v8::Object> custom_event) {

  if (event_template.IsEmpty()) {
    event_template.Reset( isolate, ObjectTemplateBuilder(isolate, v8::ObjectTemplate::New(isolate))

            .SetMethod("preventDefault", &PreventDefault)
            .Build());
  }

  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  CHECK(!context.IsEmpty());
  v8::Local<v8::Object> event = v8::Local<v8::ObjectTemplate>::New(isolate, event_template)
          ->NewInstance(context)
          .ToLocalChecked();
  if (!sender.IsEmpty())
    Dictionary(isolate, event).Set("sender", sender);
  if (!custom_event.IsEmpty())
    event->SetPrototype(context, custom_event).IsJust();
  return event;
}

v8::Local<v8::Object> CreateNativeEvent( v8::Isolate* isolate, v8::Local<v8::Object> sender, content::RenderFrameHost* frame, electron::mojom::ElectronBrowser::MessageSyncCallback callback) {



  v8::Local<v8::Object> event;
  if (frame && callback) {
    gin::Handle<Event> native_event = Event::Create(isolate);
    native_event->SetCallback(std::move(callback));
    event = v8::Local<v8::Object>::Cast(native_event.ToV8());
  } else {
    
    event = CreateEvent(isolate);
  }

  Dictionary dict(isolate, event);
  dict.Set("sender", sender);
  
  if (frame)
    dict.Set("frameId", frame->GetRoutingID());
  return event;
}

}  

}  
