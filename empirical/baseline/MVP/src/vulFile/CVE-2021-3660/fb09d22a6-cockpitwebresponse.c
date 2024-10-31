























const gchar *cockpit_web_failure_resource = NULL;

static const gchar default_failure_template[] = "<html><head><title>@@message@@</title></head><body>@@message@@</body></html>\n";



struct _CockpitWebResponse {
  GObject parent;
  GIOStream *io;
  const gchar *logname;
  const gchar *path;
  gchar *full_path;
  gchar *query;
  gchar *url_root;
  gchar *method;
  gchar *origin;

  CockpitWebResponseFlags flags;
  CockpitCacheType cache_type;

  
  GPollableOutputStream *out;
  GQueue *queue;
  gsize out_queued;
  gsize out_queueable;
  gsize partial_offset;
  GSource *source;

  
  guint count;
  gboolean complete;
  gboolean failed;
  gboolean done;
  gboolean chunked;
  gboolean keep_alive;

  GList *filters;
};




static guint signal__done;

static void      cockpit_web_response_flow_iface_init      (CockpitFlowInterface *iface);

G_DEFINE_TYPE_WITH_CODE (CockpitWebResponse, cockpit_web_response, G_TYPE_OBJECT, G_IMPLEMENT_INTERFACE (COCKPIT_TYPE_FLOW, cockpit_web_response_flow_iface_init));

static void cockpit_web_response_init (CockpitWebResponse *self)
{
  self->queue = g_queue_new ();
  self->out_queueable = G_MAXSIZE;
  self->cache_type = COCKPIT_WEB_RESPONSE_CACHE_UNSET;
}

static void cockpit_web_response_done (CockpitWebResponse *self)
{
  gboolean reusable = FALSE;

  g_object_ref (self);

  g_assert (!self->done);
  self->done = TRUE;

  if (self->source)
    {
      g_source_destroy (self->source);
      g_source_unref (self->source);
      self->source = NULL;
    }

  if (self->complete)
    {
      reusable = !self->failed && self->keep_alive;
      g_object_unref (self);
    }
  else if (!self->failed)
    {
      g_critical ("A CockpitWebResponse was freed without being completed properly. " "This is a programming error.");
    }

  g_signal_emit (self, signal__done, 0, reusable);

  g_object_unref (self->io);
  self->io = NULL;
  self->out = NULL;

  g_object_unref (self);
}

static void cockpit_web_response_dispose (GObject *object)
{
  CockpitWebResponse *self = COCKPIT_WEB_RESPONSE (object);

  if (!self->done)
    cockpit_web_response_done (self);
  g_list_free_full (self->filters, g_object_unref);
  self->filters = NULL;

  G_OBJECT_CLASS (cockpit_web_response_parent_class)->dispose (object);
}

static void cockpit_web_response_finalize (GObject *object)
{
  CockpitWebResponse *self = COCKPIT_WEB_RESPONSE (object);

  g_free (self->full_path);
  g_free (self->query);
  g_free (self->url_root);
  g_free (self->method);
  g_free (self->origin);
  g_assert (self->io == NULL);
  g_assert (self->out == NULL);
  g_queue_free_full (self->queue, (GDestroyNotify)g_bytes_unref);
  self->out_queued = 0;

  G_OBJECT_CLASS (cockpit_web_response_parent_class)->finalize (object);
}

static void cockpit_web_response_class_init (CockpitWebResponseClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->dispose = cockpit_web_response_dispose;
  gobject_class->finalize = cockpit_web_response_finalize;

  signal__done = g_signal_new ("done", COCKPIT_TYPE_WEB_RESPONSE, G_SIGNAL_RUN_LAST, 0, NULL, NULL, NULL, G_TYPE_NONE, 1, G_TYPE_BOOLEAN);


}


CockpitWebResponse * cockpit_web_response_new (GIOStream *io, const gchar *original_path, const gchar *path, const gchar *query, GHashTable *in_headers, CockpitWebResponseFlags flags)





{
  CockpitWebResponse *self;
  GOutputStream *out;
  const gchar *connection;
  const gchar *protocol = NULL;
  const gchar *host = NULL;
  gint offset;

  
  self = g_object_new (COCKPIT_TYPE_WEB_RESPONSE, NULL);
  self->io = g_object_ref (io);

  out = g_io_stream_get_output_stream (io);
  if (G_IS_POLLABLE_OUTPUT_STREAM (out))
    {
      self->out = (GPollableOutputStream *)out;
    }
  else if (out)
    {
      g_critical ("Cannot send web response over non-pollable output stream: %s", G_OBJECT_TYPE_NAME (out));
    }
  else {
      g_critical ("Cannot send web response: no output stream available");
    }

  self->url_root = NULL;
  self->full_path = g_strdup (path);
  self->path = self->full_path;

  if (path && original_path)
    {
      offset = strlen (original_path) - strlen (path);
      if (offset > 0 && g_strcmp0 (original_path + offset, path) == 0)
        self->url_root = g_strndup (original_path, offset);
    }

  self->query = g_strdup (query);
  if (self->path)
    self->logname = self->path;
  else self->logname = "response";

  self->keep_alive = TRUE;
  if (in_headers)
    {
      connection = g_hash_table_lookup (in_headers, "Connection");
      if (connection)
        self->keep_alive = g_str_equal (connection, "keep-alive");
      host = g_hash_table_lookup (in_headers, "Host");
    }

  self->flags = flags;
  protocol = cockpit_web_response_get_protocol (self, in_headers);
  if (protocol && host)
    self->origin = g_strdup_printf ("%s://%s", protocol, host);

  return self;
}

void cockpit_web_response_set_method (CockpitWebResponse *response, const gchar *method)

{
  g_return_if_fail (g_strcmp0 (method, "GET") == 0 || g_strcmp0 (method, "HEAD") == 0);
  response->method = g_strdup (method);
}


const gchar * cockpit_web_response_get_path (CockpitWebResponse *self)
{
  g_return_val_if_fail (COCKPIT_IS_WEB_RESPONSE (self), NULL);
  return self->path;
}


const gchar * cockpit_web_response_get_url_root (CockpitWebResponse *self) {
  return self->url_root;
}


const gchar * cockpit_web_response_get_query (CockpitWebResponse *self)
{
  g_return_val_if_fail (COCKPIT_IS_WEB_RESPONSE (self), NULL);
  return self->query;
}


GIOStream * cockpit_web_response_get_stream  (CockpitWebResponse *self)
{
  g_return_val_if_fail (COCKPIT_IS_WEB_RESPONSE (self), NULL);
  return self->io;
}





gboolean cockpit_web_should_suppress_output_error (const gchar *logname, GError *error)

{
  if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED) || g_error_matches (error, G_IO_ERROR, G_IO_ERROR_BROKEN_PIPE))
    {
      g_debug ("%s: output error: %s", logname, error->message);
      return TRUE;
    }


  if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_FAILED) && strstr (error->message, g_strerror (ECONNRESET)))
    {
      g_debug ("%s: output error: %s", logname, error->message);
      return TRUE;
    }


  return FALSE;
}

static void on_output_flushed (GObject *stream, GAsyncResult *result, gpointer user_data)


{
  CockpitWebResponse *self = COCKPIT_WEB_RESPONSE (user_data);
  GOutputStream *output = G_OUTPUT_STREAM (stream);
  GError *error = NULL;

  if (g_output_stream_flush_finish (output, result, &error))
    {
      g_debug ("%s: flushed output", self->logname);
    }
  else {
      if (!cockpit_web_should_suppress_output_error (self->logname, error))
        g_message ("%s: couldn't flush web output: %s", self->logname, error->message);
      self->failed = TRUE;
      g_error_free (error);
    }

  cockpit_web_response_done (self);
  g_object_unref (self);
}

static gboolean on_response_output (GObject *pollable, gpointer user_data)

{
  CockpitWebResponse *self = user_data;
  GError *error = NULL;
  const guint8 *data;
  GBytes *block;
  gssize count;
  gsize before, size, len;

  block = g_queue_peek_head (self->queue);
  if (block)
    {
      data = g_bytes_get_data (block, &len);
      g_assert (len == 0 || self->partial_offset < len);
      data += self->partial_offset;
      len -= self->partial_offset;

      before = self->out_queued;

      if (len > 0)
        {
          count = g_pollable_output_stream_write_nonblocking (self->out, data, len, NULL, &error);
        }
      else {
          count = 0;
        }

      if (count < 0)
        {
          if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
            {
              g_error_free (error);
              return TRUE;
            }

          if (!cockpit_web_should_suppress_output_error (self->logname, error))
            g_message ("%s: couldn't write web output: %s", self->logname, error->message);

          self->failed = TRUE;
          cockpit_web_response_done (self);

          g_error_free (error);
          return FALSE;
        }

      if (count == len)
        {
          g_debug ("%s: sent %d bytes", self->logname, (int)len);
          self->partial_offset = 0;
          block = g_queue_pop_head (self->queue);
          size = g_bytes_get_size (block);
          g_assert (size <= self->out_queued);
          self->out_queued -= size;
          g_bytes_unref (block);
        }
      else {
          g_debug ("%s: sent %d partial", self->logname, (int)count);
          g_assert (count < len);
          self->partial_offset += count;
        }

      
      if (before >= QUEUE_PRESSURE && self->out_queued < QUEUE_PRESSURE)
        cockpit_flow_emit_pressure (COCKPIT_FLOW (self), FALSE);

      return TRUE;
    }
  else {
      g_source_destroy (self->source);
      g_source_unref (self->source);
      self->source = NULL;

      if (self->complete)
        {
          g_debug ("%s: complete flushing output", self->logname);
          g_output_stream_flush_async (G_OUTPUT_STREAM (self->out), G_PRIORITY_DEFAULT, NULL, on_output_flushed, g_object_ref (self));
        }

      return FALSE;
    }
}

static void queue_bytes (CockpitWebResponse *self, GBytes *block)

{
  gsize size, before;

  size = g_bytes_get_size (block);
  before = self->out_queued;
  g_return_if_fail (G_MAXSIZE - size > self->out_queued);
  self->out_queued += size;

  g_queue_push_tail (self->queue, g_bytes_ref (block));

  self->count++;

  if (!self->source)
    {
      self->source = g_pollable_output_stream_create_source (self->out, NULL);
      g_source_set_callback (self->source, (GSourceFunc)on_response_output, self, NULL);
      g_source_attach (self->source, NULL);
    }

  if (before < QUEUE_PRESSURE && self->out_queued >= QUEUE_PRESSURE)
    cockpit_flow_emit_pressure (COCKPIT_FLOW (self), TRUE);
}

static void queue_block (CockpitWebResponse *self, GBytes *block)

{
  gsize length = g_bytes_get_size (block);
  GBytes *bytes;
  gchar *data;

  
  if (length == 0)
    return;

  if (self->out_queueable < length)
    {
      g_critical ("Too much data queuing in HTTP response. This is a programmer error.");
      return;
    }

  self->out_queueable -= length;
  g_debug ("%s: queued %d bytes", self->logname, (int)length);

  if (!self->chunked)
    {
      queue_bytes (self, block);
    }
  else {
      
      data = g_strdup_printf ("%x\r\n", (unsigned int)length);
      bytes = g_bytes_new_take (data, strlen (data));
      queue_bytes (self, bytes);
      g_bytes_unref (bytes);

      queue_bytes (self, block);

      bytes = g_bytes_new_static ("\r\n", 2);
      queue_bytes (self, bytes);
      g_bytes_unref (bytes);
    }
}

typedef struct {
  CockpitWebResponse *response;
  GList *filters;
} QueueStep;

static void queue_filter (gpointer data, GBytes *bytes)

{
  QueueStep *qs = data;
  QueueStep qn = { .response = qs->response };

  g_return_if_fail (bytes != NULL);

  if (qs->filters)
    {
      qn.filters = qs->filters->next;
      cockpit_web_filter_push (qs->filters->data, bytes, queue_filter, &qn);
    }
  else {
      queue_block (qs->response, bytes);
    }
}


gboolean cockpit_web_response_queue (CockpitWebResponse *self, GBytes *block)

{
  QueueStep qn = { .response = self };

  g_return_val_if_fail (COCKPIT_IS_WEB_RESPONSE (self), FALSE);
  g_return_val_if_fail (block != NULL, FALSE);
  g_return_val_if_fail (self->complete == FALSE, FALSE);

  if (self->failed)
    {
      g_debug ("%s: ignoring queued block after failure", self->logname);
      return FALSE;
    }

  if (g_strcmp0 (self->method, "HEAD") == 0)
    {
      g_debug ("%s: ignoring queued block for method HEAD", self->logname);
      return TRUE;
    }

  qn.filters = self->filters;
  queue_filter (&qn, block);
  return TRUE;
}


void cockpit_web_response_complete (CockpitWebResponse *self)
{
  GBytes *bytes;

  g_return_if_fail (COCKPIT_IS_WEB_RESPONSE (self));
  g_return_if_fail (self->complete == FALSE);

  if (self->failed)
    return;

  
  g_object_ref (self);
  self->complete = TRUE;

  if (self->chunked)
    {
      bytes = g_bytes_new_static ("0\r\n\r\n", 5);
      queue_bytes (self, bytes);
      g_bytes_unref (bytes);
    }

  if (self->source)
    {
      g_debug ("%s: queueing complete", self->logname);
    }
  else {
      g_debug ("%s: complete closing io", self->logname);
      g_output_stream_flush_async (G_OUTPUT_STREAM (self->out), G_PRIORITY_DEFAULT, NULL, on_output_flushed, g_object_ref (self));
    }
}


void cockpit_web_response_abort (CockpitWebResponse *self)
{
  g_return_if_fail (COCKPIT_IS_WEB_RESPONSE (self));
  g_return_if_fail (self->complete == FALSE);

  if (self->failed)
    return;

  
  g_object_ref (self);

  self->complete = TRUE;
  self->failed = TRUE;

  g_debug ("%s: aborted", self->logname);
  cockpit_web_response_done (self);
}




CockpitWebResponding cockpit_web_response_get_state (CockpitWebResponse *self)
{
  g_return_val_if_fail (COCKPIT_IS_WEB_RESPONSE (self), 0);

  if (self->done)
    return COCKPIT_WEB_RESPONSE_SENT;
  else if (self->complete)
    return COCKPIT_WEB_RESPONSE_COMPLETE;
  else if (self->count == 0)
    return COCKPIT_WEB_RESPONSE_READY;
  else return COCKPIT_WEB_RESPONSE_QUEUING;
}

gboolean cockpit_web_response_is_simple_token (const gchar *string)
{
  string += strcspn (string, " \t\r\n\v");
  return string[0] == '\0';
}

gboolean cockpit_web_response_is_header_value (const gchar *string)
{
  string += strcspn (string, "\r\n\v");
  return string[0] == '\0';
}

enum {
    HEADER_CONTENT_TYPE = 1 << 0, HEADER_CONTENT_ENCODING = 1 << 1, HEADER_VARY = 1 << 2, HEADER_CACHE_CONTROL = 1 << 3, HEADER_DNS_PREFETCH_CONTROL = 1 << 4, HEADER_REFERRER_POLICY = 1 << 5, HEADER_CONTENT_TYPE_OPTIONS = 1 << 6, HEADER_CROSS_ORIGIN_RESOURCE_POLICY = 1 << 7, };








static GString * begin_headers (CockpitWebResponse *response, guint status, const gchar *reason)


{
  GString *string;

  string = g_string_sized_new (1024);
  g_string_printf (string, "HTTP/1.1 %d %s\r\n", status, reason);

  return string;
}

static guint append_header (GString *string, const gchar *name, const gchar *value)


{
  if (value)
    {
      g_return_val_if_fail (cockpit_web_response_is_simple_token (name), 0);
      g_return_val_if_fail (cockpit_web_response_is_header_value (value), 0);
      g_string_append_printf (string, "%s: %s\r\n", name, value);
    }
  if (g_ascii_strcasecmp ("Content-Type", name) == 0)
    return HEADER_CONTENT_TYPE;
  if (g_ascii_strcasecmp ("Cache-Control", name) == 0)
    return HEADER_CACHE_CONTROL;
  if (g_ascii_strcasecmp ("Vary", name) == 0)
    return HEADER_VARY;
  if (g_ascii_strcasecmp ("Content-Encoding", name) == 0)
    return HEADER_CONTENT_ENCODING;
  if (g_ascii_strcasecmp ("X-DNS-Prefetch-Control", name) == 0)
    return HEADER_DNS_PREFETCH_CONTROL;
  if (g_ascii_strcasecmp ("Referrer-Policy", name) == 0)
    return HEADER_REFERRER_POLICY;
  if (g_ascii_strcasecmp ("X-Content-Type-Options", name) == 0)
    return HEADER_CONTENT_TYPE_OPTIONS;
  if (g_ascii_strcasecmp ("Cross-Origin-Resource-Policy", name) == 0)
    return HEADER_CROSS_ORIGIN_RESOURCE_POLICY;
  if (g_ascii_strcasecmp ("Content-Length", name) == 0 || g_ascii_strcasecmp ("Transfer-Encoding", name) == 0 || g_ascii_strcasecmp ("Connection", name) == 0)

    {
      g_critical ("Don't set %s header manually. This is a programmer error.", name);
    }
  return 0;
}

static guint append_table (GString *string, GHashTable *headers)

{
  GHashTableIter iter;
  gpointer key;
  gpointer value;
  guint seen = 0;

  if (headers)
    {
      g_hash_table_iter_init (&iter, headers);
      while (g_hash_table_iter_next (&iter, &key, &value))
        seen |= append_header (string, key, value);
    }

  return seen;
}

static guint append_va (GString *string, va_list va)

{
  const gchar *name;
  const gchar *value;
  guint seen = 0;

  for (;;)
    {
      name = va_arg (va, const gchar *);
      if (!name)
        break;
      value = va_arg (va, const gchar *);
      seen |= append_header (string, name, value);
    }

  return seen;
}

static GBytes * finish_headers (CockpitWebResponse *self, GString *string, gssize length, gint status, guint seen)




{
  const gchar *content_type;

  
  if ((seen & HEADER_CONTENT_TYPE) == 0 && self->full_path != NULL && status >= 200 && status <= 299)
    {
      content_type = cockpit_web_response_content_type (self->full_path);
      if (content_type)
        g_string_append_printf (string, "Content-Type: %s\r\n", content_type);
    }

  if (status != 304)
    {
      if (length < 0 || seen & HEADER_CONTENT_ENCODING || self->filters)
        {
          self->chunked = TRUE;
          g_string_append_printf (string, "Transfer-Encoding: chunked\r\n");
        }
      else {
          self->chunked = FALSE;
          g_string_append_printf (string, "Content-Length: %" G_GSSIZE_FORMAT "\r\n", length);
          self->out_queueable = length;
        }
    }

  if ((seen & HEADER_CACHE_CONTROL) == 0 && status >= 200 && status <= 299)
    {
      if (self->cache_type == COCKPIT_WEB_RESPONSE_CACHE_FOREVER)
        g_string_append (string, "Cache-Control: max-age=31556926, public\r\n");
      else if (self->cache_type == COCKPIT_WEB_RESPONSE_NO_CACHE)
        g_string_append (string, "Cache-Control: no-cache, no-store\r\n");
      else if (self->cache_type == COCKPIT_WEB_RESPONSE_CACHE_PRIVATE)
        g_string_append (string, "Cache-Control: max-age=86400, private\r\n");
    }

  if ((seen & HEADER_VARY) == 0 && status >= 200 && status <= 299 && self->cache_type == COCKPIT_WEB_RESPONSE_CACHE_PRIVATE)
    {
      g_string_append (string, "Vary: Cookie\r\n");
    }

  if (!self->keep_alive)
    g_string_append (string, "Connection: close\r\n");

  
  if ((seen & HEADER_DNS_PREFETCH_CONTROL) == 0)
    g_string_append (string, "X-DNS-Prefetch-Control: off\r\n");
  if ((seen & HEADER_REFERRER_POLICY) == 0)
    g_string_append (string, "Referrer-Policy: no-referrer\r\n");
  if ((seen & HEADER_CONTENT_TYPE_OPTIONS) == 0)
    g_string_append (string, "X-Content-Type-Options: nosniff\r\n");
  
  if ((seen & HEADER_CROSS_ORIGIN_RESOURCE_POLICY) == 0)
    g_string_append (string, "Cross-Origin-Resource-Policy: same-origin\r\n");

  g_string_append (string, "\r\n");
  return g_string_free_to_bytes (string);
}


void cockpit_web_response_set_cache_type (CockpitWebResponse *self, CockpitCacheType cache_type)

{
  self->cache_type = cache_type;
}


void cockpit_web_response_headers (CockpitWebResponse *self, guint status, const gchar *reason, gssize length, ...)




{
  GString *string;
  GBytes *block;
  va_list va;

  g_return_if_fail (COCKPIT_IS_WEB_RESPONSE (self));

  if (self->count > 0)
    {
      g_critical ("Headers should be sent first. This is a programmer error.");
      return;
    }

  string = begin_headers (self, status, reason);

  va_start (va, length);
  block = finish_headers (self, string, length, status, append_va (string, va));
  va_end (va);

  queue_bytes (self, block);
  g_bytes_unref (block);
}


void cockpit_web_response_headers_full  (CockpitWebResponse *self, guint status, const gchar *reason, gssize length, GHashTable *headers)




{
  GString *string;
  GBytes *block;

  g_return_if_fail (COCKPIT_IS_WEB_RESPONSE (self));

  if (self->count > 0)
    {
      g_critical ("Headers should be sent first. This is a programmer error.");
      return;
    }

  string = begin_headers (self, status, reason);

  block = finish_headers (self, string, length, status, append_table (string, headers));

  queue_bytes (self, block);
  g_bytes_unref (block);
}


void cockpit_web_response_content (CockpitWebResponse *self, GHashTable *headers, GBytes *block, ...)



{
  GBytes *first;
  gsize length = 0;
  va_list va;
  va_list va2;

  g_return_if_fail (COCKPIT_IS_WEB_RESPONSE (self));

  first = block;
  va_start (va, block);
  va_copy (va2, va);

  while (block)
    {
      length += g_bytes_get_size (block);
      block = va_arg (va, GBytes *);
    }
  va_end (va);

  cockpit_web_response_headers_full (self, 200, "OK", length, headers);

  block = first;
  for (;;)
    {
      if (!block)
        {
          cockpit_web_response_complete (self);
          break;
        }
      if (!cockpit_web_response_queue (self, block))
        break;
      block = va_arg (va2, GBytes *);
    }
  va_end (va2);
}

static GBytes * substitute_message (const gchar *variable, gpointer user_data)

{
  const gchar *message = user_data;
  if (g_str_equal (variable, "message"))
    return g_bytes_new (message, strlen (message));
  return NULL;
}

static GBytes * substitute_hash_value (const gchar *variable, gpointer user_data)

{
  GHashTable *data = user_data;
  gchar *value = g_hash_table_lookup (data, variable);
  if (value)
    return g_bytes_new (value, strlen (value));
  return g_bytes_new ("", 0);
}


void cockpit_web_response_error (CockpitWebResponse *self, guint code, GHashTable *headers, const gchar *format, ...)




{
  va_list var_args;
  gchar *reason = NULL;
  gchar *escaped = NULL;
  const gchar *message;
  GBytes *input = NULL;
  GList *output, *l;
  GError *error = NULL;

  g_return_if_fail (COCKPIT_IS_WEB_RESPONSE (self));

  if (format)
    {
      va_start (var_args, format);
      reason = g_strdup_vprintf (format, var_args);
      va_end (var_args);
      message = reason;
    }
  else {
      switch (code)
        {
        case 400:
          message = "Bad request";
          break;
        case 401:
          message = "Not Authorized";
          break;
        case 403:
          message = "Forbidden";
          break;
        case 404:
          message = "Not Found";
          break;
        case 405:
          message = "Method Not Allowed";
          break;
        case 413:
          message = "Request Entity Too Large";
          break;
        case 502:
          message = "Remote Page is Unavailable";
          break;
        case 500:
          message = "Internal Server Error";
          break;
        default:
          if (code < 100)
            reason = g_strdup_printf ("%u Continue", code);
          else if (code < 200)
            reason = g_strdup_printf ("%u OK", code);
          else if (code < 300)
            reason = g_strdup_printf ("%u Moved", code);
          else reason = g_strdup_printf ("%u Failed", code);
          message = reason;
          break;
        }
    }

  g_debug ("%s: returning error: %u %s", self->logname, code, message);

  if (cockpit_web_failure_resource)
    {
      input = g_resources_lookup_data (cockpit_web_failure_resource, G_RESOURCE_LOOKUP_FLAGS_NONE, &error);
      if (input == NULL)
        {
          g_critical ("couldn't load: %s: %s", cockpit_web_failure_resource, error->message);
          g_error_free (error);
        }
    }

  if (!input)
    input = g_bytes_new_static (default_failure_template, strlen (default_failure_template));
  output = cockpit_template_expand (input, "@@", "@@", substitute_message, (gpointer) message);
  g_bytes_unref (input);

  
  if (reason)
    {
      g_strstrip (reason);
      escaped = g_uri_escape_string (reason, " :", FALSE);
      message = escaped;
    }

  if (headers)
    {
      if (!g_hash_table_lookup (headers, "Content-Type"))
        g_hash_table_replace (headers, g_strdup ("Content-Type"), g_strdup ("text/html; charset=utf8"));
      cockpit_web_response_headers_full (self, code, message, -1, headers);
    }
  else {
      cockpit_web_response_headers (self, code, message, -1, "Content-Type", "text/html; charset=utf8", NULL);
    }

  for (l = output; l != NULL; l = g_list_next (l))
    {
      if (!cockpit_web_response_queue (self, l->data))
        break;
    }
  if (l == NULL)
    cockpit_web_response_complete (self);
  g_list_free_full (output, (GDestroyNotify)g_bytes_unref);

  g_free (reason);
  g_free (escaped);
}


void cockpit_web_response_gerror (CockpitWebResponse *self, GHashTable *headers, GError *error)


{
  int code;

  g_return_if_fail (COCKPIT_IS_WEB_RESPONSE (self));

  if (g_error_matches (error, COCKPIT_ERROR, COCKPIT_ERROR_AUTHENTICATION_FAILED))
    code = 401;
  else if (g_error_matches (error, COCKPIT_ERROR, COCKPIT_ERROR_PERMISSION_DENIED))
    code = 403;
  else if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA))
    code = 400;
  else if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_NO_SPACE))
    code = 413;
  else code = 500;

  cockpit_web_response_error (self, code, headers, "%s", error->message);
}

static gboolean path_has_prefix (const gchar *path, const gchar *prefix)

{
  gsize len;
  if (prefix == NULL)
    return FALSE;
  len = strlen (prefix);
  if (len == 0)
    return FALSE;
  if (!g_str_has_prefix (path, prefix))
    return FALSE;
  if (prefix[len - 1] == '/' || path[len] == '/')
    return TRUE;
  return FALSE;
}

gchar ** cockpit_web_response_resolve_roots (const gchar **input)
{
  GPtrArray *roots;
  char *path;
  gint i;

  roots = g_ptr_array_new ();
  for (i = 0; input && input[i]; i++)
    {
      path = realpath (input[i], NULL);
      if (path == NULL)
        g_debug ("couldn't resolve document root: %s: %m", input[i]);
      else g_ptr_array_add (roots, path);
    }
  g_ptr_array_add (roots, NULL);
  return (gchar **)g_ptr_array_free (roots, FALSE);
}

static void web_response_file (CockpitWebResponse *response, const gchar *escaped, const gchar **roots, CockpitTemplateFunc template_func, gpointer user_data)




{
  const gchar *default_policy = "default-src 'self' 'unsafe-inline';";

  const gchar *headers[5] = { NULL };
  GError *error = NULL;
  gchar *unescaped = NULL;
  gchar *path = NULL;
  gchar *alloc = NULL;
  GMappedFile *file = NULL;
  const gchar *root;
  GBytes *body;
  GList *output = NULL;
  GList *l = NULL;
  gint content_length = -1;
  gint at = 0;

  g_return_if_fail (COCKPIT_IS_WEB_RESPONSE (response));

  if (!escaped)
    escaped = cockpit_web_response_get_path (response);

  g_return_if_fail (escaped != NULL);

  
  unescaped = g_uri_unescape_string (escaped, "/");
  if (!unescaped || strstr (unescaped, "/.") || strstr (unescaped, "../") || strstr (unescaped, "//"))
    {
      g_debug ("%s: invalid path request", escaped);
      cockpit_web_response_error (response, 404, NULL, "Not Found");
      goto out;
    }

again:
  root = *(roots++);
  if (root == NULL)
    {
      cockpit_web_response_error (response, 404, NULL, "Not Found");
      goto out;
    }

  g_free (path);
  path = g_build_filename (root, unescaped, NULL);

  if (g_file_test (path, G_FILE_TEST_IS_DIR))
    {
      cockpit_web_response_error (response, 403, NULL, "Directory Listing Denied");
      goto out;
    }

  
  g_assert (path_has_prefix (path, root));

  g_clear_error (&error);
  file = g_mapped_file_new (path, FALSE, &error);
  if (file == NULL)
    {
      if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT) || g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NAMETOOLONG))
        {
          g_debug ("%s: file not found in root: %s", escaped, root);
          goto again;
        }
      else if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_PERM) || g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_ACCES) || g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_ISDIR))

        {
          cockpit_web_response_error (response, 403, NULL, "Access denied");
          goto out;
        }
      else {
          g_warning ("%s: %s", path, error->message);
          cockpit_web_response_error (response, 500, NULL, "Internal server error");
          goto out;
        }
    }

  body = g_mapped_file_get_bytes (file);
  if (template_func)
    {
      output = cockpit_template_expand (body, "${", "}", template_func, user_data);
    }
  else {
      output = g_list_prepend (output, g_bytes_ref (body));
      content_length = g_bytes_get_size (body);
    }
  g_bytes_unref (body);

  if (response->origin)
    {
      headers[at++] = "Access-Control-Allow-Origin";
      headers[at++] = response->origin;
    }

  
  if (g_str_has_suffix (unescaped, ".html"))
    {
      headers[at++] = "Content-Security-Policy";
      headers[at++] = alloc = cockpit_web_response_security_policy (default_policy, response->origin);
    }

  cockpit_web_response_headers (response, 200, "OK", content_length, headers[0], headers[1], headers[2], headers[3], NULL);

  for (l = output; l != NULL; l = g_list_next (l))
    {
      if (!cockpit_web_response_queue (response, l->data))
        break;
    }
  if (l == NULL)
    cockpit_web_response_complete (response);

out:
  g_free (alloc);
  g_free (unescaped);
  g_clear_error (&error);
  g_free (path);
  if (file)
    g_mapped_file_unref (file);

  if (output)
    g_list_free_full (output, (GDestroyNotify)g_bytes_unref);
}


void cockpit_web_response_file (CockpitWebResponse *response, const gchar *escaped, const gchar **roots)


{
  web_response_file (response, escaped, roots, NULL, NULL);
}

void cockpit_web_response_template (CockpitWebResponse *response, const gchar *escaped, const gchar **roots, GHashTable *values)



{
  web_response_file (response, escaped, roots, substitute_hash_value, values);
}

static gboolean response_next_path (CockpitWebResponse *self, gchar **component)

{
  const gchar *beg = NULL;
  const gchar *path;

  g_return_val_if_fail (COCKPIT_IS_WEB_RESPONSE (self), FALSE);

  path = self->path;

  if (path && path[0] == '/')
    {
      beg = path + 1;
      path = strchr (beg, '/');
    }
  else {
      path = NULL;
    }

  if (!beg || path == beg)
    return FALSE;

  self->path = path;

  if (self->path)
    {
      if (component)
        *component = g_strndup (beg, path - beg);
    }
  else if (beg && beg[0])
    {
      if (component)
        *component = g_strdup (beg);
    }
  else {
      return FALSE;
    }

  return TRUE;
}

gboolean cockpit_web_response_skip_path (CockpitWebResponse *self)
{
  return response_next_path (self, NULL);
}

gchar * cockpit_web_response_pop_path (CockpitWebResponse *self)
{
  gchar *component = NULL;
  if (!response_next_path (self, &component))
    return NULL;
  return component;
}

void cockpit_web_response_add_filter (CockpitWebResponse *self, CockpitWebFilter *filter)

{
  g_return_if_fail (COCKPIT_IS_WEB_RESPONSE (self));
  g_return_if_fail (COCKPIT_IS_WEB_FILTER (filter));
  g_return_if_fail (self->count == 0);
  self->filters = g_list_append (self->filters, g_object_ref (filter));
}


GBytes * cockpit_web_response_gunzip (GBytes *bytes, GError **error)

{
  GConverter *converter;
  GConverterResult result;
  const guint8 *in;
  gsize inl, outl, read, written;
  GByteArray *out;

  converter = G_CONVERTER (g_zlib_decompressor_new (G_ZLIB_COMPRESSOR_FORMAT_GZIP));

  in = g_bytes_get_data (bytes, &inl);
  out = g_byte_array_new ();

  do {
      outl = out->len;
      g_byte_array_set_size (out, outl + inl);

      result = g_converter_convert (converter, in, inl, out->data + outl, inl, G_CONVERTER_INPUT_AT_END, &read, &written, error);
      if (result == G_CONVERTER_ERROR)
        break;

      g_byte_array_set_size (out, outl + written);
      in += read;
      inl -= read;
    }
  while (result != G_CONVERTER_FINISHED);

  g_object_unref (converter);

  if (result != G_CONVERTER_FINISHED)
    {
      g_byte_array_unref (out);
      return NULL;
    }
  else {
      return g_byte_array_free_to_bytes (out);
    }
}

static const gchar * find_extension (const gchar *path)
{
  const gchar *dot;
  const gchar *slash;

  dot = strrchr (path, '.');
  slash = strrchr (path, '/');

  
  if (dot && slash && dot < slash)
    dot = NULL;

  
  if (dot && (dot == path || dot == slash + 1))
    dot = NULL;

  return dot;
}

static GBytes * load_file (const gchar *filename, GError **error)

{
  GError *local_error = NULL;

  g_autoptr(GMappedFile) mapped = g_mapped_file_new (filename, FALSE, &local_error);

  if (mapped)
    
    return g_mapped_file_get_bytes (mapped);

  if (g_error_matches (local_error, G_FILE_ERROR, G_FILE_ERROR_NOENT) || g_error_matches (local_error, G_FILE_ERROR, G_FILE_ERROR_ISDIR) || g_error_matches (local_error, G_FILE_ERROR, G_FILE_ERROR_NAMETOOLONG) || g_error_matches (local_error, G_FILE_ERROR, G_FILE_ERROR_LOOP) || g_error_matches (local_error, G_FILE_ERROR, G_FILE_ERROR_INVAL))



    {
      g_clear_error (&local_error);
    }

  
  else {
      g_propagate_error (error, local_error);
    }

  return NULL;
}


GBytes * cockpit_web_response_negotiation (const gchar *path, GHashTable *existing, const gchar *language, gchar **actual, GError **error)




{
  gchar *base = NULL;
  const gchar *ext;
  gchar *dot;
  gchar *name = NULL;
  GBytes *bytes = NULL;
  GError *local_error = NULL;
  gchar *locale = NULL;
  gchar *shorter = NULL;
  gchar *lang = NULL;
  gchar *lang_region = NULL;

  gint i;

  if (language)
      locale = cockpit_locale_from_language (language, NULL, &shorter);

  ext = find_extension (path);
  if (ext)
    {
      base = g_strndup (path, ext - path);
    }
  else {
      ext = "";
      base = g_strdup (path);
    }

  while (!bytes)
    {
      

      if (locale && shorter && g_strcmp0 (locale, shorter) != 0) {
        lang = shorter;
        lang_region = locale;
        i = 0;
      } else if (locale) {
        lang = locale;
        i = 2;
      } else {
        i = 4;
      }

      for (; i < 8; i++)
        {
          g_free (name);
          switch (i)
            {
            case 0:
              name = g_strconcat (base, ".", lang_region, ext, NULL);
              break;
            case 1:
              name = g_strconcat (base, ".", lang_region, ext, ".gz", NULL);
              break;
            case 2:
              name = g_strconcat (base, ".", lang, ext, NULL);
              break;
            case 3:
              name = g_strconcat (base, ".", lang, ext, ".gz", NULL);
              break;
            case 4:
              name = g_strconcat (base, ext, NULL);
              break;
            case 5:
              name = g_strconcat (base, ".min", ext, NULL);
              break;
            case 6:
              name = g_strconcat (base, ext, ".gz", NULL);
              break;
            case 7:
              name = g_strconcat (base, ".min", ext, ".gz", NULL);
              break;
            default:
              g_assert_not_reached ();
            }

          if (existing)
            {
              if (!g_hash_table_lookup (existing, name))
                continue;
            }

          bytes = load_file (name, &local_error);
          if (bytes)
            break;
          if (local_error)
            goto out;
        }

      
      dot = (gchar *)find_extension (base);
      if (!dot)
        break;

      dot[0] = '\0';
    }

out:
  if (local_error)
    g_propagate_error (error, local_error);
  if (bytes && name && actual)
    {
      *actual = name;
      name = NULL;
    }
  g_free (name);
  g_free (base);
  g_free (locale);
  g_free (shorter);
  return bytes;
}

const gchar * cockpit_web_response_content_type (const gchar *path)
{
  static const struct {
    const gchar *extension;
    const gchar *content_type;
  } content_types[] = {
    { ".css", "text/css" }, { ".gif", "image/gif" }, { ".eot", "application/vnd.ms-fontobject" }, { ".html", "text/html" },  { ".jpg", "image/jpg" }, { ".js", "application/javascript" }, { ".json", "application/json" }, { ".otf", "font/opentype" }, { ".png", "image/png" }, { ".svg", "image/svg+xml" }, { ".ttf", "application/octet-stream" }, { ".txt", "text/plain" }, { ".wasm", "application/wasm" }, { ".woff", "application/font-woff" }, { ".xml", "text/xml" }, };
















  gint i;

  for (i = 0; i < G_N_ELEMENTS (content_types); i++)
    {
      if (g_str_has_suffix (path, content_types[i].extension))
          return content_types[i].content_type;
    }

  return NULL;
}

static gboolean strv_have_prefix (gchar **strv, const gchar *prefix)

{
  gint i;

  for (i = 0; strv && strv[i] != NULL; i++)
    {
      if (g_str_has_prefix (strv[i], prefix))
        return TRUE;
    }
  return FALSE;
}

static void string_inject_origin (GString *string, const gchar *origin)

{
  const gchar *found;
  gsize pos = 0;

  for (;;)
    {
      found = strstr (string->str + pos, "'self'");
      if (!found)
        break;

      pos = (found - string->str) + 6;
      g_string_insert (string, pos, " ");
      g_string_insert (string, pos + 1, origin);
      pos += strlen (origin) + 1;
    }
}


gchar * cockpit_web_response_security_policy (const gchar *content_security_policy, const gchar *self_origin)

{
  const gchar *default_src = "default-src 'self'";
  const gchar *form_action = "form-action 'self'";
  const gchar *base_uri = "base-uri 'self'";
  const gchar *object_src = "object-src 'none'";
  const gchar *font_src = "font-src 'self' data:";
  const gchar *img_src = "img-src 'self' data:";
  const gchar *block_all_mixed_content = "block-all-mixed-content";
  gchar **parts = NULL;
  GString *result;
  gint i;

  result = g_string_sized_new (128);

  

  if (content_security_policy)
    parts = g_strsplit (content_security_policy, ";", -1);

  for (i = 0; parts && parts[i] != NULL; i++)
    g_strstrip (parts[i]);

  if (!strv_have_prefix (parts, "default-src "))
    g_string_append_printf (result, "%s; ", default_src);
  if (!strv_have_prefix (parts, "connect-src "))
    {
      g_string_append (result, "connect-src 'self'");
      if (self_origin && g_str_has_prefix (self_origin, "http"))
        g_string_append_printf (result, " ws%s", self_origin + 4);
      g_string_append (result, "; ");
    }
  if (!strv_have_prefix (parts, "form-action "))
    g_string_append_printf (result, "%s; ", form_action);
  if (!strv_have_prefix (parts, "base-uri "))
    g_string_append_printf (result, "%s; ", base_uri);
  if (!strv_have_prefix (parts, "object-src "))
    g_string_append_printf (result, "%s; ", object_src);
  if (!strv_have_prefix (parts, "font-src "))
    g_string_append_printf (result, "%s; ", font_src);
  if (!strv_have_prefix (parts, "img-src "))
    g_string_append_printf (result, "%s; ", img_src);
  if (!strv_have_prefix (parts, "block-all-mixed-content"))
    g_string_append_printf (result, "%s; ", block_all_mixed_content);

  for (i = 0; parts && parts[i] != NULL; i++)
    g_string_append_printf (result, "%s; ", parts[i]);

  g_strfreev (parts);

  
  g_string_set_size (result, result->len - 2);

  
  if (self_origin)
    string_inject_origin (result, self_origin);

  return g_string_free (result, FALSE);
}

const gchar * cockpit_web_response_get_origin (CockpitWebResponse *self)
{
  g_return_val_if_fail (COCKPIT_IS_WEB_RESPONSE (self), NULL);
  return self->origin;
}

const gchar * cockpit_web_response_get_protocol (CockpitWebResponse *self, GHashTable *headers)

{
  return cockpit_connection_get_protocol (self->io, headers, self->flags & COCKPIT_WEB_RESPONSE_FOR_TLS_PROXY);
}

static void cockpit_web_response_flow_iface_init (CockpitFlowInterface *iface)
{
  
}

const gchar * cockpit_connection_get_protocol (GIOStream *connection, GHashTable *headers, gboolean for_tls_proxy)


{
  const gchar *protocol = NULL;
  const gchar *protocol_header;

  if (connection && G_IS_TLS_CONNECTION (connection))
    {
      protocol = "https";
    }
  else {
      protocol_header = cockpit_conf_string ("WebService", "ProtocolHeader");
      if (protocol_header && headers)
         protocol = g_hash_table_lookup (headers, protocol_header);
    }

  return protocol ?: (for_tls_proxy ? "https" : "http");
}
