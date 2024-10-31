




















enum {
  RUNTIME_UPDATE, RUNTIME_INSTALL, APP_UPDATE, APP_INSTALL };




struct _FlatpakTransactionOperation {
  GObject                         parent;

  char                           *remote;
  FlatpakDecomposed              *ref;
  
  char                          **subpaths;
  char                          **previous_ids;
  char                           *commit;
  GFile                          *bundle;
  GBytes                         *external_metadata;
  FlatpakTransactionOperationType kind;
  gboolean                        non_fatal;
  gboolean                        failed;
  gboolean                        skip;
  gboolean                        update_only_deploy;
  gboolean                        pin_on_deploy;

  gboolean                        resolved;
  char                           *resolved_commit;
  GFile                          *resolved_sideload_path;
  GBytes                         *resolved_metadata;
  GKeyFile                       *resolved_metakey;
  GBytes                         *resolved_old_metadata;
  GKeyFile                       *resolved_old_metakey;
  char                           *resolved_token;
  gboolean                        requested_token; 
  guint64                         download_size;
  guint64                         installed_size;
  char                           *eol;
  char                           *eol_rebase;
  gint32                          token_type;
  GVariant                       *summary_metadata; 
  int                             run_after_count;
  int                             run_after_prio; 
  GList                          *run_before_ops;
  gboolean                        run_last;  
  FlatpakTransactionOperation    *fail_if_op_fails; 
  
  GPtrArray                      *related_to_ops;  
};

typedef struct _FlatpakTransactionPrivate FlatpakTransactionPrivate;

typedef struct _BundleData                BundleData;

struct _BundleData {
  GFile  *file;
  GBytes *gpg_data;
};

typedef struct {
  FlatpakTransaction *transaction;
  const char *remote;
  FlatpakAuthenticatorRequest *request;
  gboolean done;
  guint response;
  GVariant *results;
} RequestData;

struct _FlatpakTransactionPrivate {
  GObject                      parent;

  FlatpakInstallation         *installation;
  FlatpakDir                  *dir;
  GHashTable                  *last_op_for_ref;
  GHashTable                  *remote_states; 
  GPtrArray                   *extra_dependency_dirs;
  GPtrArray                   *extra_sideload_repos;
  GList                       *ops;
  GPtrArray                   *added_origin_remotes;

  GList                       *flatpakrefs; 
  GList                       *bundles; 

  guint                        next_request_id;
  guint                        active_request_id;
  RequestData                 *active_request;

  FlatpakTransactionOperation *current_op;

  char                        *parent_window;
  gboolean                     no_pull;
  gboolean                     no_deploy;
  gboolean                     disable_auto_pin;
  gboolean                     disable_static_deltas;
  gboolean                     disable_prune;
  gboolean                     disable_deps;
  gboolean                     disable_related;
  gboolean                     reinstall;
  gboolean                     force_uninstall;
  gboolean                     can_run;
  gboolean                     include_unused_uninstall_ops;
  char                        *default_arch;
  guint                        max_op;

  gboolean                     needs_resolve;
  gboolean                     needs_tokens;
};

enum {
  NEW_OPERATION, OPERATION_DONE, OPERATION_ERROR, CHOOSE_REMOTE_FOR_REF, END_OF_LIFED, END_OF_LIFED_WITH_REBASE, READY, READY_PRE_AUTH, ADD_NEW_REMOTE, WEBFLOW_START, WEBFLOW_DONE, BASIC_AUTH_START, INSTALL_AUTHENTICATOR, LAST_SIGNAL };














enum {
  PROP_0, PROP_INSTALLATION, };


struct _FlatpakTransactionProgress {
  GObject              parent;

  FlatpakProgress     *progress_obj;
};

enum {
  CHANGED, LAST_PROGRESS_SIGNAL };


static gboolean op_may_need_token (FlatpakTransactionOperation *op);

static void flatpak_transaction_normalize_ops (FlatpakTransaction *self);
static gboolean request_required_tokens (FlatpakTransaction *self, const char         *optional_remote, GCancellable       *cancellable, GError            **error);




static BundleData * bundle_data_new (GFile  *file, GBytes *gpg_data)

{
  BundleData *data = g_new0 (BundleData, 1);

  data->file = g_object_ref (file);
  if (gpg_data)
    data->gpg_data = g_bytes_ref (gpg_data);

  return data;
}

static void bundle_data_free (BundleData *data)
{
  g_clear_object (&data->file);
  g_clear_object (&data->gpg_data);
  g_free (data);
}

static guint progress_signals[LAST_SIGNAL] = { 0 };



G_DEFINE_TYPE (FlatpakTransactionProgress, flatpak_transaction_progress, G_TYPE_OBJECT)


void flatpak_transaction_progress_set_update_frequency (FlatpakTransactionProgress *self, guint                       update_interval)

{
  flatpak_progress_set_update_interval (self->progress_obj, update_interval);
}


char * flatpak_transaction_progress_get_status (FlatpakTransactionProgress *self)
{
  return g_strdup (flatpak_progress_get_status (self->progress_obj));
}


gboolean flatpak_transaction_progress_get_is_estimating (FlatpakTransactionProgress *self)
{
  return flatpak_progress_get_estimating (self->progress_obj);
}


int flatpak_transaction_progress_get_progress (FlatpakTransactionProgress *self)
{
  return flatpak_progress_get_progress (self->progress_obj);
}


guint64 flatpak_transaction_progress_get_bytes_transferred (FlatpakTransactionProgress *self)
{
  guint64 bytes_transferred, transferred_extra_data_bytes;

  bytes_transferred = flatpak_progress_get_bytes_transferred (self->progress_obj);
  transferred_extra_data_bytes = flatpak_progress_get_transferred_extra_data_bytes (self->progress_obj);

  return bytes_transferred + transferred_extra_data_bytes;
}


guint64 flatpak_transaction_progress_get_start_time (FlatpakTransactionProgress *self)
{
  return flatpak_progress_get_start_time (self->progress_obj);
}

static void flatpak_transaction_progress_finalize (GObject *object)
{
  FlatpakTransactionProgress *self = (FlatpakTransactionProgress *) object;

  g_object_unref (self->progress_obj);

  G_OBJECT_CLASS (flatpak_transaction_progress_parent_class)->finalize (object);
}

static void flatpak_transaction_progress_class_init (FlatpakTransactionProgressClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = flatpak_transaction_progress_finalize;

  
  progress_signals[CHANGED] = g_signal_new ("changed", G_TYPE_FROM_CLASS (object_class), G_SIGNAL_RUN_LAST, 0, NULL, NULL, NULL, G_TYPE_NONE, 0);






}

static void got_progress_cb (const char *status, guint       progress, gboolean    estimating, gpointer    user_data)



{
  FlatpakTransactionProgress *p = user_data;

  if (!flatpak_progress_is_done (p->progress_obj))
    g_signal_emit (p, progress_signals[CHANGED], 0);
}

static void flatpak_transaction_progress_init (FlatpakTransactionProgress *self)
{
  self->progress_obj = flatpak_progress_new (got_progress_cb, self);
}

static void flatpak_transaction_progress_done (FlatpakTransactionProgress *self)
{
  flatpak_progress_done (self->progress_obj);
}

static FlatpakTransactionProgress * flatpak_transaction_progress_new (void)
{
  return g_object_new (FLATPAK_TYPE_TRANSACTION_PROGRESS, NULL);
}

static guint signals[LAST_SIGNAL] = { 0 };

static void initable_iface_init (GInitableIface *initable_iface);

G_DEFINE_TYPE_WITH_CODE (FlatpakTransaction, flatpak_transaction, G_TYPE_OBJECT, G_ADD_PRIVATE (FlatpakTransaction)
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, initable_iface_init))

static gboolean transaction_is_local_only (FlatpakTransaction             *self, FlatpakTransactionOperationType kind)

{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  return priv->no_pull || kind == FLATPAK_TRANSACTION_OPERATION_UNINSTALL;
}

static gboolean remote_name_is_file (const char *remote_name)
{
  return remote_name != NULL && g_str_has_prefix (remote_name, "file://");
}


void flatpak_transaction_add_dependency_source (FlatpakTransaction  *self, FlatpakInstallation *installation)

{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  g_ptr_array_add (priv->extra_dependency_dirs, flatpak_installation_clone_dir_noensure (installation));
}


void flatpak_transaction_add_sideload_repo (FlatpakTransaction  *self, const char          *path)

{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  g_ptr_array_add (priv->extra_sideload_repos, g_strdup (path));
}


void flatpak_transaction_add_default_dependency_sources (FlatpakTransaction *self)
{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autoptr(GPtrArray) system_dirs = NULL;
  GFile *path = flatpak_dir_get_path (priv->dir);
  int i;

  system_dirs = flatpak_dir_get_system_list (NULL, NULL);
  if (system_dirs == NULL)
    return;

  for (i = 0; i < system_dirs->len; i++)
    {
      FlatpakDir *system_dir = g_ptr_array_index (system_dirs, i);
      GFile *system_path = flatpak_dir_get_path (system_dir);

      if (g_file_equal (path, system_path))
        continue;

      g_ptr_array_add (priv->extra_dependency_dirs, g_object_ref (system_dir));
    }
}


static gboolean ref_is_installed (FlatpakTransaction *self, FlatpakDecomposed *ref)

{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autoptr(GFile) deploy_dir = NULL;
  FlatpakDir *dir = priv->dir;
  int i;

  deploy_dir = flatpak_dir_get_if_deployed (dir, ref, NULL, NULL);
  if (deploy_dir != NULL)
    return TRUE;

  for (i = 0; i < priv->extra_dependency_dirs->len; i++)
    {
      FlatpakDir *dependency_dir = g_ptr_array_index (priv->extra_dependency_dirs, i);

      deploy_dir = flatpak_dir_get_if_deployed (dependency_dir, ref, NULL, NULL);
      if (deploy_dir != NULL)
        return TRUE;
    }

  return FALSE;
}

static gboolean dir_ref_is_installed (FlatpakDir *dir, FlatpakDecomposed *ref, char **remote_out, GBytes **deploy_data_out)
{
  g_autoptr(GBytes) deploy_data = NULL;

  deploy_data = flatpak_dir_get_deploy_data (dir, ref, FLATPAK_DEPLOY_VERSION_ANY, NULL, NULL);
  if (deploy_data == NULL)
    return FALSE;

  if (remote_out)
    *remote_out = g_strdup (flatpak_deploy_data_get_origin (deploy_data));

  if (deploy_data_out)
    *deploy_data_out = g_bytes_ref (deploy_data);

  return TRUE;
}



G_DEFINE_TYPE (FlatpakTransactionOperation, flatpak_transaction_operation, G_TYPE_OBJECT)

static void flatpak_transaction_operation_finalize (GObject *object)
{
  FlatpakTransactionOperation *self = (FlatpakTransactionOperation *) object;

  g_free (self->remote);
  flatpak_decomposed_unref (self->ref);
  g_free (self->commit);
  g_strfreev (self->subpaths);
  g_clear_object (&self->bundle);
  g_free (self->eol);
  g_free (self->eol_rebase);
  if (self->previous_ids)
    g_strfreev (self->previous_ids);
  if (self->external_metadata)
    g_bytes_unref (self->external_metadata);
  g_free (self->resolved_commit);
  if (self->resolved_sideload_path)
    g_object_unref (self->resolved_sideload_path);
  if (self->resolved_metadata)
    g_bytes_unref (self->resolved_metadata);
  if (self->resolved_metakey)
    g_key_file_unref (self->resolved_metakey);
  if (self->resolved_old_metadata)
    g_bytes_unref (self->resolved_old_metadata);
  if (self->resolved_old_metakey)
    g_key_file_unref (self->resolved_old_metakey);
  g_free (self->resolved_token);
  g_list_free (self->run_before_ops);
  if (self->related_to_ops)
    g_ptr_array_unref (self->related_to_ops);
  if (self->summary_metadata)
    g_variant_unref (self->summary_metadata);

  G_OBJECT_CLASS (flatpak_transaction_operation_parent_class)->finalize (object);
}

static void flatpak_transaction_operation_class_init (FlatpakTransactionOperationClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = flatpak_transaction_operation_finalize;
}

static void flatpak_transaction_operation_init (FlatpakTransactionOperation *self)
{
}

static FlatpakTransactionOperation * flatpak_transaction_operation_new (const char                     *remote, FlatpakDecomposed              *ref, const char                    **subpaths, const char                    **previous_ids, const char                     *commit, GFile                          *bundle, FlatpakTransactionOperationType kind, gboolean                        pin_on_deploy)







{
  FlatpakTransactionOperation *self;

  self = g_object_new (FLATPAK_TYPE_TRANSACTION_OPERATION, NULL);

  self->remote = g_strdup (remote);
  self->ref = flatpak_decomposed_ref (ref);
  self->subpaths = g_strdupv ((char **) subpaths);
  self->previous_ids = g_strdupv ((char **) previous_ids);
  self->commit = g_strdup (commit);
  if (bundle)
    self->bundle = g_object_ref (bundle);
  self->kind = kind;
  self->pin_on_deploy = pin_on_deploy;

  return self;
}


FlatpakTransactionOperationType flatpak_transaction_operation_get_operation_type (FlatpakTransactionOperation *self)
{
  return self->kind;
}


const char * flatpak_transaction_operation_get_ref (FlatpakTransactionOperation *self)
{
  return flatpak_decomposed_get_ref (self->ref);
}

FlatpakDecomposed * flatpak_transaction_operation_get_decomposed (FlatpakTransactionOperation *self)
{
  return self->ref;
}


GPtrArray * flatpak_transaction_operation_get_related_to_ops (FlatpakTransactionOperation *self)
{
  return self->related_to_ops;
}

static void flatpak_transaction_operation_add_related_to_op (FlatpakTransactionOperation *op, FlatpakTransactionOperation *related_op)

{
  if (op->related_to_ops == NULL)
    op->related_to_ops = g_ptr_array_new ();
  g_ptr_array_add (op->related_to_ops, related_op);
}


gboolean flatpak_transaction_operation_get_is_skipped (FlatpakTransactionOperation *self)
{
  return self->skip;
}


const char * flatpak_transaction_operation_get_remote (FlatpakTransactionOperation *self)
{
  return self->remote;
}


const char * flatpak_transaction_operation_type_to_string (FlatpakTransactionOperationType kind)
{
  if (kind == FLATPAK_TRANSACTION_OPERATION_INSTALL)
    return "install";
  if (kind == FLATPAK_TRANSACTION_OPERATION_UPDATE)
    return "update";
  if (kind == FLATPAK_TRANSACTION_OPERATION_INSTALL_BUNDLE)
    return "install-bundle";
  if (kind == FLATPAK_TRANSACTION_OPERATION_UNINSTALL)
    return "uninstall";
  return NULL;
}


GFile * flatpak_transaction_operation_get_bundle_path (FlatpakTransactionOperation *self)
{
  return self->bundle;
}


const char * flatpak_transaction_operation_get_commit (FlatpakTransactionOperation *self)
{
  return self->resolved_commit;
}


guint64 flatpak_transaction_operation_get_download_size (FlatpakTransactionOperation *self)
{
  return self->download_size;
}


guint64 flatpak_transaction_operation_get_installed_size (FlatpakTransactionOperation *self)
{
  return self->installed_size;
}


GKeyFile * flatpak_transaction_operation_get_metadata (FlatpakTransactionOperation *self)
{
  return self->resolved_metakey;
}


GKeyFile * flatpak_transaction_operation_get_old_metadata (FlatpakTransactionOperation *self)
{
  return self->resolved_old_metakey;
}


const char * const * flatpak_transaction_operation_get_subpaths (FlatpakTransactionOperation *self)
{
  if (self->subpaths == NULL || self->subpaths[0] == NULL)
    return NULL;

  return (const char * const *) self->subpaths;
}



gboolean flatpak_transaction_operation_get_requires_authentication (FlatpakTransactionOperation *self)
{
  return op_may_need_token (self) && self->token_type != 0 && !self->requested_token;


}


gboolean flatpak_transaction_is_empty (FlatpakTransaction *self)
{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  GList *l;

  for (l = priv->ops; l; l = l->next)
    {
      FlatpakTransactionOperation *op = l->data;

      if (!op->skip)
        return FALSE;
    }

  return TRUE;
}

static void flatpak_transaction_finalize (GObject *object)
{
  FlatpakTransaction *self = (FlatpakTransaction *) object;
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  g_clear_object (&priv->installation);

  g_free (priv->parent_window);
  g_list_free_full (priv->flatpakrefs, (GDestroyNotify) g_key_file_unref);
  g_list_free_full (priv->bundles, (GDestroyNotify) bundle_data_free);
  g_free (priv->default_arch);
  g_hash_table_unref (priv->last_op_for_ref);
  g_hash_table_unref (priv->remote_states);
  g_list_free_full (priv->ops, (GDestroyNotify) g_object_unref);
  g_clear_object (&priv->dir);

  g_ptr_array_unref (priv->added_origin_remotes);

  g_ptr_array_free (priv->extra_dependency_dirs, TRUE);
  g_ptr_array_free (priv->extra_sideload_repos, TRUE);

  G_OBJECT_CLASS (flatpak_transaction_parent_class)->finalize (object);
}

static void flatpak_transaction_set_property (GObject      *object, guint         prop_id, const GValue *value, GParamSpec   *pspec)



{
  FlatpakTransaction *self = FLATPAK_TRANSACTION (object);
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  switch (prop_id)
    {
    case PROP_INSTALLATION:
      g_clear_object (&priv->installation);
      priv->installation = g_value_dup_object (value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static gboolean signal_accumulator_false_abort (GSignalInvocationHint *ihint, GValue                *return_accu, const GValue          *handler_return, gpointer               dummy)



{
  gboolean continue_emission;
  gboolean signal_continue;

  signal_continue = g_value_get_boolean (handler_return);
  g_value_set_boolean (return_accu, signal_continue);
  continue_emission = signal_continue;

  return continue_emission;
}

static void flatpak_transaction_get_property (GObject    *object, guint       prop_id, GValue     *value, GParamSpec *pspec)



{
  FlatpakTransaction *self = FLATPAK_TRANSACTION (object);
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  switch (prop_id)
    {
    case PROP_INSTALLATION:
      g_value_set_object (value, priv->installation);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
    }
}

static gboolean flatpak_transaction_ready (FlatpakTransaction *transaction)
{
  return TRUE;
}

static gboolean flatpak_transaction_ready_pre_auth (FlatpakTransaction *transaction)
{
  return TRUE;
}

static gboolean flatpak_transaction_add_new_remote (FlatpakTransaction            *transaction, FlatpakTransactionRemoteReason reason, const char                    *from_id, const char                    *suggested_remote_name, const char                    *url)




{
  return FALSE;
}

static void flatpak_transaction_install_authenticator  (FlatpakTransaction *transaction, const char         *remote, const char         *authenticator_ref)


{
}

static gboolean flatpak_transaction_real_run (FlatpakTransaction *transaction, GCancellable       *cancellable, GError            **error);


static void flatpak_transaction_class_init (FlatpakTransactionClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  klass->ready = flatpak_transaction_ready;
  klass->ready_pre_auth = flatpak_transaction_ready_pre_auth;
  klass->add_new_remote = flatpak_transaction_add_new_remote;
  klass->install_authenticator = flatpak_transaction_install_authenticator;
  klass->run = flatpak_transaction_real_run;
  object_class->finalize = flatpak_transaction_finalize;
  object_class->get_property = flatpak_transaction_get_property;
  object_class->set_property = flatpak_transaction_set_property;

  
  g_object_class_install_property (object_class, PROP_INSTALLATION, g_param_spec_object ("installation", "Installation", "The installation instance", FLATPAK_TYPE_INSTALLATION, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));






  
  signals[NEW_OPERATION] = g_signal_new ("new-operation", G_TYPE_FROM_CLASS (object_class), G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (FlatpakTransactionClass, new_operation), NULL, NULL, NULL, G_TYPE_NONE, 2, FLATPAK_TYPE_TRANSACTION_OPERATION, FLATPAK_TYPE_TRANSACTION_PROGRESS);







  
  signals[OPERATION_ERROR] = g_signal_new ("operation-error", G_TYPE_FROM_CLASS (object_class), G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (FlatpakTransactionClass, operation_error), NULL, NULL, NULL, G_TYPE_BOOLEAN, 3, FLATPAK_TYPE_TRANSACTION_OPERATION, G_TYPE_ERROR, G_TYPE_INT);







  
  signals[OPERATION_DONE] = g_signal_new ("operation-done", G_TYPE_FROM_CLASS (object_class), G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (FlatpakTransactionClass, operation_done), NULL, NULL, NULL, G_TYPE_NONE, 3, FLATPAK_TYPE_TRANSACTION_OPERATION, G_TYPE_STRING, G_TYPE_INT);







  
  signals[CHOOSE_REMOTE_FOR_REF] = g_signal_new ("choose-remote-for-ref", G_TYPE_FROM_CLASS (object_class), G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (FlatpakTransactionClass, choose_remote_for_ref), NULL, NULL, NULL, G_TYPE_INT, 3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRV);







  
  signals[END_OF_LIFED] = g_signal_new ("end-of-lifed", G_TYPE_FROM_CLASS (object_class), G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (FlatpakTransactionClass, end_of_lifed), NULL, NULL, NULL, G_TYPE_NONE, 3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);







  
  signals[END_OF_LIFED_WITH_REBASE] = g_signal_new ("end-of-lifed-with-rebase", G_TYPE_FROM_CLASS (object_class), G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (FlatpakTransactionClass, end_of_lifed_with_rebase), NULL, NULL, NULL, G_TYPE_BOOLEAN, 5, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRV);







  
  signals[READY] = g_signal_new ("ready", G_TYPE_FROM_CLASS (object_class), G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (FlatpakTransactionClass, ready), signal_accumulator_false_abort, NULL, NULL, G_TYPE_BOOLEAN, 0);







  
  signals[READY_PRE_AUTH] = g_signal_new ("ready-pre-auth", G_TYPE_FROM_CLASS (object_class), G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (FlatpakTransactionClass, ready_pre_auth), signal_accumulator_false_abort, NULL, NULL, G_TYPE_BOOLEAN, 0);







  
  signals[ADD_NEW_REMOTE] = g_signal_new ("add-new-remote", G_TYPE_FROM_CLASS (object_class), G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (FlatpakTransactionClass, add_new_remote), g_signal_accumulator_first_wins, NULL, NULL, G_TYPE_BOOLEAN, 4, G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);







  
  signals[INSTALL_AUTHENTICATOR] = g_signal_new ("install-authenticator", G_TYPE_FROM_CLASS (object_class), G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (FlatpakTransactionClass, install_authenticator), NULL, NULL, NULL, G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_STRING);







  
  signals[WEBFLOW_START] = g_signal_new ("webflow-start", G_TYPE_FROM_CLASS (object_class), G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (FlatpakTransactionClass, webflow_start), NULL, NULL, NULL, G_TYPE_BOOLEAN, 4, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_VARIANT, G_TYPE_INT);






  
  signals[WEBFLOW_DONE] = g_signal_new ("webflow-done", G_TYPE_FROM_CLASS (object_class), G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (FlatpakTransactionClass, webflow_done), NULL, NULL, NULL, G_TYPE_NONE, 2, G_TYPE_VARIANT, G_TYPE_INT);






  
  signals[BASIC_AUTH_START] = g_signal_new ("basic-auth-start", G_TYPE_FROM_CLASS (object_class), G_SIGNAL_RUN_LAST, G_STRUCT_OFFSET (FlatpakTransactionClass, basic_auth_start), NULL, NULL, NULL, G_TYPE_BOOLEAN, 4, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_VARIANT, G_TYPE_INT);







}

static void flatpak_transaction_init (FlatpakTransaction *self)
{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  priv->last_op_for_ref = g_hash_table_new_full ((GHashFunc)flatpak_decomposed_hash, (GEqualFunc)flatpak_decomposed_equal, (GDestroyNotify) flatpak_decomposed_unref, NULL);
  priv->remote_states = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, (GDestroyNotify) flatpak_remote_state_unref);
  priv->added_origin_remotes = g_ptr_array_new_with_free_func (g_free);
  priv->extra_dependency_dirs = g_ptr_array_new_with_free_func (g_object_unref);
  priv->extra_sideload_repos = g_ptr_array_new_with_free_func (g_free);
  priv->can_run = TRUE;
}


static gboolean initable_init (GInitable    *initable, GCancellable *cancellable, GError      **error)


{
  FlatpakTransaction *self = FLATPAK_TRANSACTION (initable);
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autoptr(FlatpakDir) dir = NULL;

  if (priv->installation == NULL)
    return flatpak_fail (error, "No installation specified");

  dir = flatpak_installation_clone_dir (priv->installation, cancellable, error);
  if (dir == NULL)
    return FALSE;

  priv->dir = g_steal_pointer (&dir);

  return TRUE;
}

static void initable_iface_init (GInitableIface *initable_iface)
{
  initable_iface->init = initable_init;
}


FlatpakTransaction * flatpak_transaction_new_for_installation (FlatpakInstallation *installation, GCancellable        *cancellable, GError             **error)


{
  return g_initable_new (FLATPAK_TYPE_TRANSACTION, cancellable, error, "installation", installation, NULL);


}


void flatpak_transaction_set_no_pull (FlatpakTransaction *self, gboolean            no_pull)

{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  priv->no_pull = no_pull;
}


gboolean flatpak_transaction_get_no_pull (FlatpakTransaction *self)
{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  return priv->no_pull;
}


void flatpak_transaction_set_parent_window (FlatpakTransaction *self, const char *parent_window)

{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  g_free (priv->parent_window);
  priv->parent_window = g_strdup (parent_window);
}


const char * flatpak_transaction_get_parent_window (FlatpakTransaction *self)
{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  return priv->parent_window;
}


void flatpak_transaction_set_no_deploy (FlatpakTransaction *self, gboolean            no_deploy)

{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  priv->no_deploy = no_deploy;
}


gboolean flatpak_transaction_get_no_deploy (FlatpakTransaction *self)
{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  return priv->no_deploy;
}


void flatpak_transaction_set_disable_static_deltas (FlatpakTransaction *self, gboolean            disable_static_deltas)

{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  priv->disable_static_deltas = disable_static_deltas;
}


void flatpak_transaction_set_disable_prune (FlatpakTransaction *self, gboolean            disable_prune)

{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  priv->disable_prune = disable_prune;
}


void flatpak_transaction_set_disable_auto_pin  (FlatpakTransaction *self, gboolean            disable_pin)

{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  priv->disable_auto_pin = disable_pin;
}


void flatpak_transaction_set_disable_dependencies (FlatpakTransaction *self, gboolean            disable_dependencies)

{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  priv->disable_deps = disable_dependencies;
}


void flatpak_transaction_set_disable_related (FlatpakTransaction *self, gboolean            disable_related)

{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  priv->disable_related = disable_related;
}


void flatpak_transaction_set_reinstall (FlatpakTransaction *self, gboolean            reinstall)

{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  priv->reinstall = reinstall;
}


void flatpak_transaction_set_no_interaction (FlatpakTransaction *self, gboolean            no_interaction)

{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  flatpak_dir_set_no_interaction (priv->dir, no_interaction);
}


void flatpak_transaction_set_force_uninstall (FlatpakTransaction *self, gboolean            force_uninstall)

{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  priv->force_uninstall = force_uninstall;
}


void flatpak_transaction_set_default_arch (FlatpakTransaction *self, const char         *arch)

{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  g_free (priv->default_arch);
  priv->default_arch = g_strdup (arch);
}


void flatpak_transaction_set_include_unused_uninstall_ops (FlatpakTransaction *self, gboolean            include_unused_uninstall_ops)

{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  priv->include_unused_uninstall_ops = include_unused_uninstall_ops;
}


gboolean flatpak_transaction_get_include_unused_uninstall_ops (FlatpakTransaction *self)
{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  return priv->include_unused_uninstall_ops;
}

static FlatpakTransactionOperation * flatpak_transaction_get_last_op_for_ref (FlatpakTransaction *self, FlatpakDecomposed *ref)

{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  FlatpakTransactionOperation *op;

  op = g_hash_table_lookup (priv->last_op_for_ref, ref);

  return op;
}

static char * subpaths_to_string (const char **subpaths)
{
  GString *s = NULL;
  int i;

  if (subpaths == NULL)
    return g_strdup ("[$old]");

  if (*subpaths == 0)
    return g_strdup ("[*]");

  s = g_string_new ("[");
  for (i = 0; subpaths[i] != NULL; i++)
    {
      if (i != 0)
        g_string_append (s, ", ");
      g_string_append (s, subpaths[i]);
    }
  g_string_append (s, "]");

  return g_string_free (s, FALSE);
}

static const char * kind_to_str (FlatpakTransactionOperationType kind)
{
  switch ((int) kind)
    {
    case FLATPAK_TRANSACTION_OPERATION_INSTALL:
      return "install";

    case FLATPAK_TRANSACTION_OPERATION_UPDATE:
      return "update";

    case FLATPAK_TRANSACTION_OPERATION_INSTALL_OR_UPDATE:
      return "install/update";

    case FLATPAK_TRANSACTION_OPERATION_INSTALL_BUNDLE:
      return "install bundle";

    case FLATPAK_TRANSACTION_OPERATION_UNINSTALL:
      return "uninstall";

    case FLATPAK_TRANSACTION_OPERATION_LAST_TYPE:
    default:
      return "unknown";
    }
}

FlatpakRemoteState * flatpak_transaction_ensure_remote_state (FlatpakTransaction             *self, FlatpakTransactionOperationType kind, const char                     *remote, const char                     *opt_arch, GError                        **error)




{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autoptr(FlatpakRemoteState) state = NULL;
  FlatpakRemoteState *cached_state;

  
  if (transaction_is_local_only (self, kind))
    return flatpak_dir_get_remote_state_local_only (priv->dir, remote, NULL, error);

  cached_state = g_hash_table_lookup (priv->remote_states, remote);
  if (cached_state)
    state = flatpak_remote_state_ref (cached_state);
  else {
      state = flatpak_dir_get_remote_state_optional (priv->dir, remote, FALSE, NULL, error);
      if (state == NULL)
        return NULL;

      g_hash_table_insert (priv->remote_states, state->remote_name, flatpak_remote_state_ref (state));

      for (int i = 0; i < priv->extra_sideload_repos->len; i++)
        {
          const char *path = g_ptr_array_index (priv->extra_sideload_repos, i);
          g_autoptr(GFile) f = g_file_new_for_path (path);
          flatpak_remote_state_add_sideload_repo (state, f);
        }
    }

  if (opt_arch != NULL && !flatpak_remote_state_ensure_subsummary (state, priv->dir, opt_arch, FALSE, NULL, error))
    return FALSE;

  return g_steal_pointer (&state);
}

static gboolean kind_compatible (FlatpakTransactionOperationType a, FlatpakTransactionOperationType b, gboolean                        b_is_rebase)


{
  if (a == b)
    return TRUE;

  if (a == FLATPAK_TRANSACTION_OPERATION_INSTALL_OR_UPDATE && (b == FLATPAK_TRANSACTION_OPERATION_INSTALL || b == FLATPAK_TRANSACTION_OPERATION_UPDATE))

    return TRUE;

  if (b == FLATPAK_TRANSACTION_OPERATION_INSTALL_OR_UPDATE && (a == FLATPAK_TRANSACTION_OPERATION_INSTALL || a == FLATPAK_TRANSACTION_OPERATION_UPDATE))

    return TRUE;

  
  if (b_is_rebase && (a == FLATPAK_TRANSACTION_OPERATION_INSTALL || a == FLATPAK_TRANSACTION_OPERATION_UPDATE || a == FLATPAK_TRANSACTION_OPERATION_INSTALL_OR_UPDATE))


    return TRUE;

  return FALSE;
}

static FlatpakTransactionOperation * flatpak_transaction_add_op (FlatpakTransaction             *self, const char                     *remote, FlatpakDecomposed              *ref, const char                    **subpaths, const char                    **previous_ids, const char                     *commit, GFile                          *bundle, FlatpakTransactionOperationType kind, gboolean                        pin_on_deploy, GError                        **error)









{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  FlatpakTransactionOperation *op;
  g_autofree char *subpaths_str = NULL;

  subpaths_str = subpaths_to_string (subpaths);
  g_debug ("Transaction: %s %s:%s%s%s%s", kind_to_str (kind), remote, flatpak_decomposed_get_ref (ref), commit != NULL ? "@" : "", commit != NULL ? commit : "", subpaths_str);




  op = flatpak_transaction_get_last_op_for_ref (self, ref);
  
  if (op != NULL && kind_compatible (kind, op->kind, previous_ids != NULL))
    {
      g_auto(GStrv) old_subpaths = NULL;
      g_auto(GStrv) old_previous_ids = NULL;

      old_subpaths = op->subpaths;
      op->subpaths = flatpak_subpaths_merge (old_subpaths, (char **) subpaths);

      old_previous_ids = op->previous_ids;
      op->previous_ids = flatpak_strv_merge (old_previous_ids, (char **) previous_ids);

      return op;
    }

  op = flatpak_transaction_operation_new (remote, ref, subpaths, previous_ids, commit, bundle, kind, pin_on_deploy);
  g_hash_table_insert (priv->last_op_for_ref, flatpak_decomposed_ref (ref), op);

  priv->ops = g_list_prepend (priv->ops, op);

  priv->needs_resolve = TRUE;

  return op;
}

static void run_operation_before (FlatpakTransactionOperation *op, FlatpakTransactionOperation *before_this, int                          prio)


{
  if (op == before_this)
    return; 
  op->run_before_ops = g_list_prepend (op->run_before_ops, before_this);
  before_this->run_after_count++;
  before_this->run_after_prio = MAX (before_this->run_after_prio, prio);
}

static void run_operation_last (FlatpakTransactionOperation *op)
{
  op->run_last = TRUE;
}

static gboolean op_get_related (FlatpakTransaction           *self, FlatpakTransactionOperation  *op, GPtrArray                   **out_related, GError                      **error)



{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autoptr(FlatpakRemoteState) state = NULL;
  g_autoptr(GPtrArray) related = NULL;
  g_autoptr(GError) related_error = NULL;

  if (op->kind != FLATPAK_TRANSACTION_OPERATION_UNINSTALL)
    {
      state = flatpak_transaction_ensure_remote_state (self, op->kind, op->remote, NULL, error);
      if (state == NULL)
        return FALSE;
    }

  if (op->resolved_metakey == NULL)
    {
      g_debug ("no resolved metadata for related to %s", flatpak_decomposed_get_ref (op->ref));
      return TRUE;
    }

  if (transaction_is_local_only (self, op->kind))
    related = flatpak_dir_find_local_related_for_metadata (priv->dir, op->ref, NULL, op->resolved_metakey, NULL, &related_error);


  else related = flatpak_dir_find_remote_related_for_metadata (priv->dir, state, op->ref, op->resolved_metakey, NULL, &related_error);


  if (related_error != NULL)
    g_message (_("Warning: Problem looking for related refs: %s"), related_error->message);

  if (out_related)
    *out_related = g_steal_pointer (&related);

  return TRUE;
}

static gboolean add_related (FlatpakTransaction          *self, FlatpakTransactionOperation *op, GError                     **error)


{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autoptr(GPtrArray) related = NULL;
  int i;

  if (priv->disable_related)
    return TRUE;

  if (!op_get_related (self, op, &related, error))
    return FALSE;

  if (related == NULL)
    return TRUE;

  if (op->kind == FLATPAK_TRANSACTION_OPERATION_UNINSTALL)
    {
      for (i = 0; i < related->len; i++)
        {
          FlatpakRelated *rel = g_ptr_array_index (related, i);
          FlatpakTransactionOperation *related_op;

          if (!rel->delete)
            continue;

          related_op = flatpak_transaction_add_op (self, rel->remote, rel->ref, NULL, NULL, NULL, NULL, FLATPAK_TRANSACTION_OPERATION_UNINSTALL, FALSE, error);


          if (related_op == NULL)
            return FALSE;

          related_op->non_fatal = TRUE;
          related_op->fail_if_op_fails = op;
          flatpak_transaction_operation_add_related_to_op (related_op, op);
          run_operation_before (op, related_op, 1);
        }
    }
  else  {
      for (i = 0; i < related->len; i++)
        {
          FlatpakRelated *rel = g_ptr_array_index (related, i);
          FlatpakTransactionOperation *related_op;

          if (!rel->download)
            continue;

          related_op = flatpak_transaction_add_op (self, rel->remote, rel->ref, (const char **) rel->subpaths, NULL, NULL, NULL, FLATPAK_TRANSACTION_OPERATION_INSTALL_OR_UPDATE, FALSE, error);



          if (related_op == NULL)
            return FALSE;

          related_op->non_fatal = TRUE;
          related_op->fail_if_op_fails = op;
          flatpak_transaction_operation_add_related_to_op (related_op, op);
          run_operation_before (related_op, op, 1);
        }
    }

  return TRUE;
}

typedef struct {
  FlatpakDir *dir;
  const char *prioritized_remote;
} RemoteSortData;

static gint cmp_remote_with_prioritized (gconstpointer a, gconstpointer b, gpointer      user_data)


{
  RemoteSortData *rsd = user_data;
  FlatpakDir *self = rsd->dir;
  const char *a_name = *(const char **) a;
  const char *b_name = *(const char **) b;
  int prio_a, prio_b;

  prio_a = flatpak_dir_get_remote_prio (self, a_name);
  prio_b = flatpak_dir_get_remote_prio (self, b_name);

  
  if (prio_b != prio_a)
    return prio_b - prio_a;
  else {
      if (strcmp (a_name, rsd->prioritized_remote) == 0)
        return -1;
      if (strcmp (b_name, rsd->prioritized_remote) == 0)
        return 1;
    }

  return 0;
}

static char ** search_for_dependency (FlatpakTransaction  *self, char               **remotes, FlatpakDecomposed   *runtime_ref, GCancellable        *cancellable, GError             **error)




{
  g_autoptr(GPtrArray) found = g_ptr_array_new_with_free_func (g_free);
  int i;
  g_autofree char *arch = flatpak_decomposed_dup_arch (runtime_ref);

  for (i = 0; remotes != NULL && remotes[i] != NULL; i++)
    {
      const char *remote = remotes[i];
      g_autoptr(GError) local_error = NULL;
      g_autoptr(FlatpakRemoteState) state = NULL;

      state = flatpak_transaction_ensure_remote_state (self, FLATPAK_TRANSACTION_OPERATION_INSTALL, remote, arch, &local_error);
      if (state == NULL)
        {
          g_debug ("Can't get state for remote %s, ignoring: %s", remote, local_error->message);
          continue;
        }

      if (flatpak_remote_state_lookup_ref (state, flatpak_decomposed_get_ref (runtime_ref), NULL, NULL, NULL, NULL, NULL))
        g_ptr_array_add (found, g_strdup (remote));
    }

  g_ptr_array_add (found, NULL);

  return (char **) g_ptr_array_free (g_steal_pointer (&found), FALSE);
}

static char ** search_for_local_dependency (FlatpakTransaction *self, char              **remotes, FlatpakDecomposed  *runtime_ref, GCancellable       *cancellable, GError            **error)




{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autoptr(GPtrArray) found = g_ptr_array_new_with_free_func (g_free);
  int i;

  for (i = 0; remotes != NULL && remotes[i] != NULL; i++)
    {
      const char *remote = remotes[i];
      g_autofree char *commit = NULL;

      commit = flatpak_dir_read_latest (priv->dir, remote, flatpak_decomposed_get_ref (runtime_ref), NULL, NULL, NULL);
      if (commit != NULL)
        g_ptr_array_add (found, g_strdup (remote));
    }

  g_ptr_array_add (found, NULL);

  return (char **) g_ptr_array_free (g_steal_pointer (&found), FALSE);
}

static char * find_runtime_remote (FlatpakTransaction             *self, FlatpakDecomposed              *app_ref, const char                     *app_remote, FlatpakDecomposed              *runtime_ref, FlatpakTransactionOperationType source_kind, GCancellable                   *cancellable, GError                        **error)






{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_auto(GStrv) all_remotes = NULL;
  g_auto(GStrv) found_remotes = NULL;
  const char *app_pref;
  const char *runtime_pref;
  RemoteSortData rsd = { NULL };
  int res = -1;

  all_remotes = flatpak_dir_list_dependency_remotes (priv->dir, cancellable, error);
  if (all_remotes == NULL)
    return NULL;

  
  rsd.dir = priv->dir;
  rsd.prioritized_remote = app_remote;
  g_qsort_with_data (all_remotes, g_strv_length (all_remotes), sizeof (char *), cmp_remote_with_prioritized, &rsd);


  app_pref = flatpak_decomposed_get_pref (app_ref);
  runtime_pref = flatpak_decomposed_get_pref (runtime_ref);

  
  if (transaction_is_local_only (self, source_kind))
    found_remotes = search_for_local_dependency (self, all_remotes, runtime_ref, NULL, NULL);
  else found_remotes = search_for_dependency (self, all_remotes, runtime_ref, NULL, NULL);

  if (found_remotes == NULL || *found_remotes == NULL)
    {
      flatpak_fail_error (error, FLATPAK_ERROR_RUNTIME_NOT_FOUND, _("The application %s requires the runtime %s which was not found"), app_pref, runtime_pref);

      return NULL;
    }

  
  if (priv->no_pull && g_strv_length (found_remotes) == 1)
    res = 0;
  else g_signal_emit (self, signals[CHOOSE_REMOTE_FOR_REF], 0, flatpak_decomposed_get_ref (app_ref), flatpak_decomposed_get_ref (runtime_ref), found_remotes, &res);

  if (res >= 0 && res < g_strv_length (found_remotes))
    return g_strdup (found_remotes[res]);

  flatpak_fail_error (error, FLATPAK_ERROR_RUNTIME_NOT_FOUND, _("The application %s requires the runtime %s which is not installed"), app_pref, runtime_pref);

  return NULL;
}

static FlatpakDecomposed * op_get_runtime_ref (FlatpakTransactionOperation *op)
{
  g_autofree char *runtime_pref = NULL;
  FlatpakDecomposed *decomposed;

  if (!op->resolved_metakey)
    return NULL;

  
  if (flatpak_decomposed_is_app (op->ref))
    runtime_pref = g_key_file_get_string (op->resolved_metakey, "Application", "runtime", NULL);
  else if (g_key_file_has_group (op->resolved_metakey, "Extra Data") && !g_key_file_get_boolean (op->resolved_metakey, "Extra Data", "NoRuntime", NULL))
    runtime_pref = g_key_file_get_string (op->resolved_metakey, "ExtensionOf", "runtime", NULL);

  if (runtime_pref == NULL)
    return NULL;

  decomposed = flatpak_decomposed_new_from_pref (FLATPAK_KINDS_RUNTIME, runtime_pref, NULL);
  if (decomposed == NULL)
    g_debug ("Invalid runtime ref %s in metadata", runtime_pref);

  return decomposed;
}

static gboolean add_deps (FlatpakTransaction          *self, FlatpakTransactionOperation *op, GError                     **error)


{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autoptr(FlatpakDecomposed) runtime_ref = NULL;
  g_autofree char *runtime_remote = NULL;
  FlatpakTransactionOperation *runtime_op = NULL;

  if (!op->resolved_metakey)
    return TRUE;

  runtime_ref = op_get_runtime_ref (op);
  if (runtime_ref == NULL)
    return TRUE;

  runtime_op = flatpak_transaction_get_last_op_for_ref (self, runtime_ref);

  if (op->kind == FLATPAK_TRANSACTION_OPERATION_UNINSTALL)
    {
      
      if (runtime_op && runtime_op->kind == FLATPAK_TRANSACTION_OPERATION_UNINSTALL)
        run_operation_before (op, runtime_op, 1);

      return TRUE;
    }

  if (priv->disable_deps)
    return TRUE;

  if (runtime_op == NULL)
    {
      if (!ref_is_installed (self, runtime_ref))
        {
          runtime_remote = find_runtime_remote (self, op->ref, op->remote, runtime_ref, op->kind, NULL, error);
          if (runtime_remote == NULL)
            return FALSE;

          runtime_op = flatpak_transaction_add_op (self, runtime_remote, runtime_ref, NULL, NULL, NULL, NULL, FLATPAK_TRANSACTION_OPERATION_INSTALL_OR_UPDATE, FALSE, error);
          if (runtime_op == NULL)
            return FALSE;
        }
      else {
          
          if (dir_ref_is_installed (priv->dir, runtime_ref, &runtime_remote, NULL))
            {
              g_debug ("Updating dependent runtime %s", flatpak_decomposed_get_pref (runtime_ref));
              runtime_op = flatpak_transaction_add_op (self, runtime_remote, runtime_ref, NULL, NULL, NULL, NULL, FLATPAK_TRANSACTION_OPERATION_UPDATE, FALSE, error);
              if (runtime_op == NULL)
                return FALSE;
              runtime_op->non_fatal = TRUE;
            }
        }
    }

  
  if (runtime_op)
    {
      if (runtime_op->kind == FLATPAK_TRANSACTION_OPERATION_UNINSTALL)
        return flatpak_fail_error (error, FLATPAK_ERROR_RUNTIME_USED, _("Can't uninstall %s which is needed by %s"), flatpak_decomposed_get_pref (runtime_op->ref), flatpak_decomposed_get_pref (op->ref));


      op->fail_if_op_fails = runtime_op;
      flatpak_transaction_operation_add_related_to_op (runtime_op, op);
      run_operation_before (runtime_op, op, 2);
    }

  return TRUE;
}

static gboolean flatpak_transaction_add_ref (FlatpakTransaction             *self, const char                     *remote, FlatpakDecomposed              *ref, const char                    **subpaths, const char                    **previous_ids, const char                     *commit, FlatpakTransactionOperationType kind, GFile                          *bundle, const char                     *external_metadata, gboolean                        pin_on_deploy, GError                        **error)










{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autofree char *origin = NULL;
  g_auto(GStrv) new_subpaths = NULL;
  const char *pref;
  g_autofree char *origin_remote = NULL;
  g_autoptr(FlatpakRemoteState) state = NULL;
  FlatpakTransactionOperation *op;

  if (remote_name_is_file (remote))
    {
      gboolean changed_config;
      g_autofree char *id = flatpak_decomposed_dup_id (ref);
      origin_remote = flatpak_dir_create_origin_remote (priv->dir, remote, id, "Local repo", flatpak_decomposed_get_ref (ref), NULL, NULL, &changed_config, NULL, error);







      if (origin_remote == NULL)
        return FALSE;

      
      if (changed_config)
        flatpak_installation_drop_caches (priv->installation, NULL, NULL);

      g_ptr_array_add (priv->added_origin_remotes, g_strdup (origin_remote));

      remote = origin_remote;
    }

  pref = flatpak_decomposed_get_pref (ref);

  
  if (kind == FLATPAK_TRANSACTION_OPERATION_UPDATE)
    {
      g_autoptr(GBytes) deploy_data = NULL;

      if (!dir_ref_is_installed (priv->dir, ref, &origin, &deploy_data))
        return flatpak_fail_error (error, FLATPAK_ERROR_NOT_INSTALLED, _("%s not installed"), pref);

      if (flatpak_dir_get_remote_disabled (priv->dir, origin))
        {
          g_debug (_("Remote %s disabled, ignoring %s update"), origin, pref);
          return TRUE;
        }
      remote = origin;

      if (subpaths == NULL)
        {
          g_autofree const char **old_subpaths = flatpak_deploy_data_get_subpaths (deploy_data);

          
          if (flatpak_decomposed_id_has_suffix (ref, ".Locale"))
            {
              g_auto(GStrv) extra_subpaths = flatpak_dir_get_locale_subpaths (priv->dir);
              new_subpaths = flatpak_subpaths_merge ((char **)old_subpaths, extra_subpaths);
            }
          else {
              
              new_subpaths = g_strdupv ((char **)old_subpaths);
            }
          subpaths = (const char **)new_subpaths;
        }
    }
  else if (kind == FLATPAK_TRANSACTION_OPERATION_INSTALL)
    {
      if (!priv->reinstall && dir_ref_is_installed (priv->dir, ref, &origin, NULL))
        {
          if (g_strcmp0 (remote, origin) == 0)
            return flatpak_fail_error (error, FLATPAK_ERROR_ALREADY_INSTALLED, _("%s is already installed"), pref);
          else return flatpak_fail_error (error, FLATPAK_ERROR_DIFFERENT_REMOTE, _("%s is already installed from remote %s"), pref, origin);


        }
    }
  else if (kind == FLATPAK_TRANSACTION_OPERATION_UNINSTALL)
    {
      if (!dir_ref_is_installed (priv->dir, ref, &origin, NULL))
        return flatpak_fail_error (error, FLATPAK_ERROR_NOT_INSTALLED, _("%s not installed"), pref);

      remote = origin;
    }

  
  g_assert (remote != NULL);

  
  if (kind != FLATPAK_TRANSACTION_OPERATION_UNINSTALL)
    {
      g_autofree char *arch = flatpak_decomposed_dup_arch (ref);

      state = flatpak_transaction_ensure_remote_state (self, kind, remote, arch, error);
      if (state == NULL)
        return FALSE;
    }

  op = flatpak_transaction_add_op (self, remote, ref, subpaths, previous_ids, commit, bundle, kind, pin_on_deploy, error);
  if (op == NULL)
    return FALSE;

  if (external_metadata)
    op->external_metadata = g_bytes_new (external_metadata, strlen (external_metadata) + 1);

  return TRUE;
}


gboolean flatpak_transaction_add_install (FlatpakTransaction *self, const char         *remote, const char         *ref, const char        **subpaths, GError            **error)




{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autoptr(FlatpakDecomposed) decomposed = NULL;
  const char *all_paths[] = { NULL };
  gboolean pin_on_deploy;

  g_return_val_if_fail (ref != NULL, FALSE);
  g_return_val_if_fail (remote != NULL, FALSE);

  decomposed = flatpak_decomposed_new_from_ref (ref, error);
  if (decomposed == NULL)
    return FALSE;

  
  if (subpaths == NULL)
    subpaths = all_paths;

  pin_on_deploy = flatpak_decomposed_is_runtime (decomposed) && !priv->disable_auto_pin;

  if (!flatpak_transaction_add_ref (self, remote, decomposed, subpaths, NULL, NULL, FLATPAK_TRANSACTION_OPERATION_INSTALL, NULL, NULL, pin_on_deploy, error))

    return FALSE;

  return TRUE;
}


gboolean flatpak_transaction_add_rebase (FlatpakTransaction *self, const char         *remote, const char         *ref, const char        **subpaths, const char        **previous_ids, GError            **error)





{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  const char *all_paths[] = { NULL };
  g_autoptr(FlatpakDecomposed) decomposed = NULL;
  g_autofree char *installed_origin = NULL;

  g_return_val_if_fail (ref != NULL, FALSE);
  g_return_val_if_fail (remote != NULL, FALSE);
  
  g_return_val_if_fail (previous_ids != NULL, FALSE);

  decomposed = flatpak_decomposed_new_from_ref (ref, error);
  if (decomposed == NULL)
    return FALSE;

  
  if (subpaths == NULL)
    subpaths = all_paths;

  if (dir_ref_is_installed (priv->dir, decomposed, &installed_origin, NULL))
    remote = installed_origin;

  return flatpak_transaction_add_ref (self, remote, decomposed, subpaths, previous_ids, NULL, FLATPAK_TRANSACTION_OPERATION_INSTALL_OR_UPDATE, NULL, NULL, FALSE, error);
}


gboolean flatpak_transaction_add_install_bundle (FlatpakTransaction *self, GFile              *file, GBytes             *gpg_data, GError            **error)



{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  priv->bundles = g_list_append (priv->bundles, bundle_data_new (file, gpg_data));

  return TRUE;
}


gboolean flatpak_transaction_add_install_flatpakref (FlatpakTransaction *self, GBytes             *flatpakref_data, GError            **error)


{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autoptr(GKeyFile) keyfile = g_key_file_new ();
  g_autoptr(GError) local_error = NULL;

  g_return_val_if_fail (flatpakref_data != NULL, FALSE);

  if (!g_key_file_load_from_data (keyfile, g_bytes_get_data (flatpakref_data, NULL), g_bytes_get_size (flatpakref_data), 0, &local_error))

    return flatpak_fail_error (error, FLATPAK_ERROR_INVALID_DATA, _("Invalid .flatpakref: %s"), local_error->message);

  priv->flatpakrefs = g_list_append (priv->flatpakrefs, g_steal_pointer (&keyfile));

  return TRUE;
}


gboolean flatpak_transaction_add_update (FlatpakTransaction *self, const char         *ref, const char        **subpaths, const char         *commit, GError            **error)




{
  const char *all_paths[] = { NULL };
  g_autoptr(FlatpakDecomposed) decomposed = NULL;

  g_return_val_if_fail (ref != NULL, FALSE);

  
  if (subpaths != NULL && subpaths[0] != NULL && subpaths[0][0] == 0)
    subpaths = all_paths;

  decomposed = flatpak_decomposed_new_from_ref (ref, error);
  if (decomposed == NULL)
    return FALSE;

  
  return flatpak_transaction_add_ref (self, NULL, decomposed, subpaths, NULL, commit, FLATPAK_TRANSACTION_OPERATION_UPDATE, NULL, NULL, FALSE, error);
}


gboolean flatpak_transaction_add_uninstall (FlatpakTransaction *self, const char         *ref, GError            **error)


{
  g_autoptr(FlatpakDecomposed) decomposed = NULL;

  g_return_val_if_fail (ref != NULL, FALSE);

  decomposed = flatpak_decomposed_new_from_ref (ref, error);
  if (decomposed == NULL)
    return FALSE;

  return flatpak_transaction_add_ref (self, NULL, decomposed, NULL, NULL, NULL, FLATPAK_TRANSACTION_OPERATION_UNINSTALL, NULL, NULL, FALSE, error);
}

static gboolean flatpak_transaction_update_metadata (FlatpakTransaction *self, GCancellable       *cancellable, GError            **error)


{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_auto(GStrv) remotes = NULL;
  int i;
  GList *l;
  gboolean some_updated = FALSE;
  g_autoptr(GHashTable) ht = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  gboolean local_only = TRUE;

  

  if (!flatpak_dir_migrate_config (priv->dir, &some_updated, cancellable, error))
    return FALSE;

  for (l = priv->ops; l != NULL; l = l->next)
    {
      FlatpakTransactionOperation *op = l->data;
      if (!g_hash_table_contains (ht, op->remote))
        g_hash_table_add (ht, g_strdup (op->remote));
      local_only = local_only && transaction_is_local_only (self, op->kind);
    }
  remotes = (char **) g_hash_table_get_keys_as_array (ht, NULL);
  g_hash_table_steal_all (ht); 

  
  if (local_only)
    return TRUE;

  
  for (i = 0; remotes[i] != NULL; i++)
    {
      char *remote = remotes[i];
      gboolean updated = FALSE;
      g_autoptr(GError) my_error = NULL;
      g_autoptr(FlatpakRemoteState) state = flatpak_transaction_ensure_remote_state (self, FLATPAK_TRANSACTION_OPERATION_UPDATE, remote, NULL, NULL);

      g_debug ("Looking for remote metadata updates for %s", remote);
      if (!flatpak_dir_update_remote_configuration (priv->dir, remote, state, &updated, cancellable, &my_error))
        g_debug (_("Error updating remote metadata for '%s': %s"), remote, my_error->message);

      if (updated)
        {
          g_debug ("Got updated metadata for %s", remote);
          some_updated = TRUE;
        }
    }

  if (some_updated)
    {
      
      if (!flatpak_dir_recreate_repo (priv->dir, cancellable, error))
        return FALSE;

      flatpak_installation_drop_caches (priv->installation, NULL, NULL);

      
      g_hash_table_remove_all (priv->remote_states);
    }

  return TRUE;
}

static gboolean flatpak_transaction_add_auto_install (FlatpakTransaction *self, GCancellable       *cancellable, GError            **error)


{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_auto(GStrv) remotes = NULL;

  remotes = flatpak_dir_list_remotes (priv->dir, cancellable, error);
  if (remotes == NULL)
    return FALSE;

  
  for (int i = 0; remotes[i] != NULL; i++)
    {
      char *remote = remotes[i];
      g_autoptr(FlatpakDecomposed) auto_install_ref = NULL;

      if (flatpak_dir_get_remote_disabled (priv->dir, remote))
        continue;

      auto_install_ref = flatpak_dir_get_remote_auto_install_authenticator_ref (priv->dir, remote);
      if (auto_install_ref != NULL)
        {
          g_autoptr(GError) local_error = NULL;
          g_autoptr(GFile) deploy = NULL;

          deploy = flatpak_dir_get_if_deployed (priv->dir, auto_install_ref, NULL, cancellable);
          if (deploy == NULL)
            {
              g_autoptr(FlatpakRemoteState) state = flatpak_transaction_ensure_remote_state (self, FLATPAK_TRANSACTION_OPERATION_UPDATE, remote, NULL, NULL);

              if (state != NULL && flatpak_remote_state_lookup_ref (state, flatpak_decomposed_get_ref (auto_install_ref), NULL, NULL, NULL, NULL, NULL))
                {
                  g_debug ("Auto adding install of %s from remote %s", flatpak_decomposed_get_ref (auto_install_ref), remote);

                  if (!flatpak_transaction_add_ref (self, remote, auto_install_ref, NULL, NULL, NULL, FLATPAK_TRANSACTION_OPERATION_INSTALL_OR_UPDATE, NULL, NULL, FALSE, &local_error))


                    g_debug ("Failed to add auto-install ref %s: %s", flatpak_decomposed_get_ref (auto_install_ref), local_error->message);
                }
            }
        }
    }

  return TRUE;
}

static void emit_new_op (FlatpakTransaction *self, FlatpakTransactionOperation *op, FlatpakTransactionProgress *progress)
{
  g_signal_emit (self, signals[NEW_OPERATION], 0, op, progress);
}

static void emit_op_done (FlatpakTransaction          *self, FlatpakTransactionOperation *op, FlatpakTransactionResult     details)


{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autofree char *commit = NULL;

  if (priv->no_deploy)
    commit = flatpak_dir_read_latest (priv->dir, op->remote, flatpak_decomposed_get_ref (op->ref), NULL, NULL, NULL);
  else {
      g_autoptr(GBytes) deploy_data = flatpak_dir_get_deploy_data (priv->dir, op->ref, FLATPAK_DEPLOY_VERSION_ANY, NULL, NULL);
      if (deploy_data)
        commit = g_strdup (flatpak_deploy_data_get_commit (deploy_data));
    }

  g_signal_emit (self, signals[OPERATION_DONE], 0, op, commit, details);
}

static GBytes * load_deployed_metadata (FlatpakTransaction *self, FlatpakDecomposed *ref, char **out_commit, char **out_remote)
{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autoptr(GFile) deploy_dir = NULL;
  g_autoptr(GFile) metadata_file = NULL;
  g_autofree char *metadata_contents = NULL;
  gsize metadata_contents_length;

  deploy_dir = flatpak_dir_get_if_deployed (priv->dir, ref, NULL, NULL);
  if (deploy_dir == NULL)
    return NULL;

  if (out_commit || out_remote)
    {
      g_autoptr(GBytes) deploy_data = NULL;
      deploy_data = flatpak_load_deploy_data (deploy_dir, ref, flatpak_dir_get_repo (priv->dir), FLATPAK_DEPLOY_VERSION_ANY, NULL, NULL);

      if (deploy_data == NULL)
        return NULL;

      if (out_commit)
        *out_commit = g_strdup (flatpak_deploy_data_get_commit (deploy_data));
      if (out_remote)
        *out_remote = g_strdup (flatpak_deploy_data_get_origin (deploy_data));
    }

  metadata_file = g_file_get_child (deploy_dir, "metadata");

  if (!g_file_load_contents (metadata_file, NULL, &metadata_contents, &metadata_contents_length, NULL, NULL))
    {
      g_debug ("No metadata in local deploy of %s", flatpak_decomposed_get_ref (ref));
      return NULL;
    }

  return g_bytes_new_take (g_steal_pointer (&metadata_contents), metadata_contents_length + 1);
}

static void emit_eol_and_maybe_skip (FlatpakTransaction          *self, FlatpakTransactionOperation *op)

{
  g_autofree char *id = NULL;
  const char *previous_ids[] = { NULL, NULL };

  if (op->skip || (!op->eol && !op->eol_rebase) || op->kind == FLATPAK_TRANSACTION_OPERATION_UNINSTALL)
    return;

  id = flatpak_decomposed_dup_id (op->ref);
  previous_ids[0] = id;

  g_signal_emit (self, signals[END_OF_LIFED_WITH_REBASE], 0, op->remote, flatpak_decomposed_get_ref (op->ref), op->eol, op->eol_rebase, previous_ids, &op->skip);
}

static void mark_op_resolved (FlatpakTransactionOperation *op, const char                  *commit, GFile                       *sideload_path, GBytes                      *metadata, GBytes                      *old_metadata)




{
  g_debug ("marking op %s:%s resolved to %s", kind_to_str (op->kind), flatpak_decomposed_get_ref (op->ref), commit ? commit : "-");

  g_assert (op != NULL);

  g_assert (commit != NULL);

  op->resolved = TRUE;

  if (op->resolved_commit != commit)
    {
      g_free (op->resolved_commit); 
      op->resolved_commit = g_strdup (commit);
    }

  if (sideload_path)
    op->resolved_sideload_path = g_object_ref (sideload_path);

  if (metadata)
    {
      g_autoptr(GKeyFile) metakey = g_key_file_new ();
      if (g_key_file_load_from_bytes (metakey, metadata, G_KEY_FILE_NONE, NULL))
        {
          op->resolved_metadata = g_bytes_ref (metadata);
          op->resolved_metakey = g_steal_pointer (&metakey);
        }
      else g_message ("Warning: Failed to parse metadata for %s\n", flatpak_decomposed_get_ref (op->ref));
    }
  if (old_metadata)
    {
      g_autoptr(GKeyFile) metakey = g_key_file_new ();
      if (g_key_file_load_from_bytes (metakey, old_metadata, G_KEY_FILE_NONE, NULL))
        {
          op->resolved_old_metadata = g_bytes_ref (old_metadata);
          op->resolved_old_metakey = g_steal_pointer (&metakey);
        }
      else g_message ("Warning: Failed to parse old metadata for %s\n", flatpak_decomposed_get_ref (op->ref));
    }
}

static void resolve_op_end (FlatpakTransaction *self, FlatpakTransactionOperation *op, const char *checksum, GFile *sideload_path, GBytes *metadata_bytes)




{
  g_autoptr(GBytes) old_metadata_bytes = NULL;

  old_metadata_bytes = load_deployed_metadata (self, op->ref, NULL, NULL);
  mark_op_resolved (op, checksum, sideload_path, metadata_bytes, old_metadata_bytes);
  emit_eol_and_maybe_skip (self, op);
 }


static void resolve_op_from_commit (FlatpakTransaction *self, FlatpakTransactionOperation *op, const char *checksum, GFile *sideload_path, GVariant *commit_data)




{
  g_autoptr(GBytes) metadata_bytes = NULL;
  g_autoptr(GVariant) commit_metadata = NULL;
  const char *xa_metadata = NULL;
  guint64 download_size = 0;
  guint64 installed_size = 0;

  commit_metadata = g_variant_get_child_value (commit_data, 0);
  g_variant_lookup (commit_metadata, "xa.metadata", "&s", &xa_metadata);
  if (xa_metadata == NULL)
    g_message ("Warning: No xa.metadata in local commit %s ref %s", checksum, flatpak_decomposed_get_ref (op->ref));
  else metadata_bytes = g_bytes_new (xa_metadata, strlen (xa_metadata) + 1);

  if (g_variant_lookup (commit_metadata, "xa.download-size", "t", &download_size))
    op->download_size = GUINT64_FROM_BE (download_size);
  if (g_variant_lookup (commit_metadata, "xa.installed-size", "t", &installed_size))
    op->installed_size = GUINT64_FROM_BE (installed_size);

  g_variant_lookup (commit_metadata, OSTREE_COMMIT_META_KEY_ENDOFLIFE, "s", &op->eol);
  g_variant_lookup (commit_metadata, OSTREE_COMMIT_META_KEY_ENDOFLIFE_REBASE, "s", &op->eol_rebase);

  resolve_op_end (self, op, checksum, sideload_path, metadata_bytes);
}

static gboolean try_resolve_op_from_metadata (FlatpakTransaction *self, FlatpakTransactionOperation *op, const char *checksum, GFile *sideload_path, FlatpakRemoteState *state)




{
  g_autoptr(GBytes) metadata_bytes = NULL;
  guint64 download_size = 0;
  guint64 installed_size = 0;
  const char *metadata = NULL;
  VarMetadataRef sparse_cache;
  VarRefInfoRef info;
  g_autofree char *summary_checksum = NULL;

  
  if ((state->summary == NULL && state->index == NULL) || !flatpak_remote_state_lookup_ref (state, flatpak_decomposed_get_ref (op->ref), &summary_checksum, NULL, NULL, NULL, NULL) || strcmp (summary_checksum, checksum) != 0)


    return FALSE;

  
  if (!flatpak_remote_state_lookup_cache (state, flatpak_decomposed_get_ref (op->ref), &download_size, &installed_size, &metadata, NULL))
      return FALSE;

  metadata_bytes = g_bytes_new (metadata, strlen (metadata) + 1);

  if (flatpak_remote_state_lookup_ref (state, flatpak_decomposed_get_ref (op->ref), NULL, NULL, &info, NULL, NULL))
    op->summary_metadata = var_metadata_dup_to_gvariant (var_ref_info_get_metadata (info));

  op->installed_size = installed_size;
  op->download_size = download_size;

  op->token_type = state->default_token_type;

  if (flatpak_remote_state_lookup_sparse_cache (state, flatpak_decomposed_get_ref (op->ref), &sparse_cache, NULL))
    {
      op->eol = g_strdup (var_metadata_lookup_string (sparse_cache, FLATPAK_SPARSE_CACHE_KEY_ENDOFLINE, NULL));
      op->eol_rebase = g_strdup (var_metadata_lookup_string (sparse_cache, FLATPAK_SPARSE_CACHE_KEY_ENDOFLINE_REBASE, NULL));
      op->token_type = GINT32_FROM_LE (var_metadata_lookup_int32 (sparse_cache, FLATPAK_SPARSE_CACHE_KEY_TOKEN_TYPE, op->token_type));
    }

  resolve_op_end (self, op, checksum, sideload_path, metadata_bytes);
  return TRUE;
}

static gboolean op_may_need_token (FlatpakTransactionOperation *op)
{
  return !op->skip && !op->update_only_deploy && (op->kind == FLATPAK_TRANSACTION_OPERATION_INSTALL || op->kind == FLATPAK_TRANSACTION_OPERATION_UPDATE  || op->kind == FLATPAK_TRANSACTION_OPERATION_INSTALL_OR_UPDATE);




}


static gboolean resolve_ops (FlatpakTransaction *self, GCancellable       *cancellable, GError            **error)


{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  GList *l;

  for (l = priv->ops; l != NULL; l = l->next)
    {
      FlatpakTransactionOperation *op = l->data;
      g_autoptr(FlatpakRemoteState) state = NULL;
      g_autofree char *checksum = NULL;
      g_autoptr(GBytes) metadata_bytes = NULL;

      if (op->resolved)
        continue;

      if (op->skip)
        {
          
          g_assert (op->resolved_commit != NULL);
          mark_op_resolved (op, op->resolved_commit, NULL, NULL, NULL);
          continue;
        }

      if (op->kind == FLATPAK_TRANSACTION_OPERATION_UNINSTALL)
        {
          

          metadata_bytes = load_deployed_metadata (self, op->ref, &checksum, NULL);
          if (metadata_bytes == NULL)
            {
              op->skip = TRUE;
              continue;
            }
          mark_op_resolved (op, checksum, NULL, metadata_bytes, NULL);
          continue;
        }

      if (op->kind == FLATPAK_TRANSACTION_OPERATION_INSTALL_BUNDLE)
        {
          g_assert (op->commit != NULL);
          mark_op_resolved (op, op->commit, NULL, op->external_metadata, NULL);
          continue;
        }

      

      if (flatpak_decomposed_is_app (op->ref))
        {
          if (op->kind == FLATPAK_TRANSACTION_OPERATION_INSTALL)
            priv->max_op = APP_INSTALL;
          else priv->max_op = MAX (priv->max_op, APP_UPDATE);
        }
      else if (flatpak_decomposed_is_runtime (op->ref))
        {
          if (op->kind == FLATPAK_TRANSACTION_OPERATION_INSTALL)
            priv->max_op = MAX (priv->max_op, RUNTIME_INSTALL);
        }

      state = flatpak_transaction_ensure_remote_state (self, op->kind, op->remote, NULL, error);
      if (state == NULL)
        return FALSE;

      
      if (transaction_is_local_only (self, op->kind))
        {
          g_autoptr(GVariant) commit_data = flatpak_dir_read_latest_commit (priv->dir, op->remote, op->ref, &checksum, NULL, error);
          if (commit_data == NULL)
            return FALSE;

          resolve_op_from_commit (self, op, checksum, NULL, commit_data);
        }
      else {
          g_autoptr(GError) local_error = NULL;
          g_autoptr(GFile) sideload_path = NULL;

          if (op->commit != NULL)
            {
              checksum = g_strdup (op->commit);
              
              sideload_path = flatpak_remote_state_lookup_sideload_checksum (state, op->commit);
            }
          else {
              g_autofree char *latest_checksum = NULL;
              g_autoptr(GFile) latest_sideload_path = NULL;
              g_autofree char *local_checksum = NULL;
              guint64 latest_timestamp;
              g_autoptr(GVariant) local_commit_data = flatpak_dir_read_latest_commit (priv->dir, op->remote, op->ref, &local_checksum, NULL, NULL);

              if (flatpak_dir_find_latest_rev (priv->dir, state, flatpak_decomposed_get_ref (op->ref), op->commit, &latest_checksum, &latest_timestamp, &latest_sideload_path, cancellable, &local_error))

                {
                  
                  if (latest_sideload_path != NULL && local_commit_data && latest_timestamp != 0 && ostree_commit_get_timestamp (local_commit_data) > latest_timestamp)
                    {
                      g_debug ("Installed commit %s newer than sideloaded %s, ignoring", local_checksum, latest_checksum);
                      checksum = g_steal_pointer (&local_checksum);
                    }
                  else {
                      
                      checksum = g_steal_pointer (&latest_checksum);
                      sideload_path = g_steal_pointer (&latest_sideload_path);
                    }
                }
              else {
                  
                  if (local_commit_data == NULL)
                    {
                      g_propagate_error (error, g_steal_pointer (&local_error));
                      return FALSE;
                    }

                  g_message (_("Warning: Treating remote fetch error as non-fatal since %s is already installed: %s"), flatpak_decomposed_get_ref (op->ref), local_error->message);
                  g_clear_error (&local_error);

                  checksum = g_steal_pointer (&local_checksum);
                }
            }

          
          if (!try_resolve_op_from_metadata (self, op, checksum, sideload_path, state))
            {
              
              g_autoptr(GVariant) commit_data = NULL;
              VarRefInfoRef ref_info;

              
              if (op->summary_metadata == NULL && flatpak_remote_state_lookup_ref (state, flatpak_decomposed_get_ref (op->ref), NULL, NULL, &ref_info, NULL, NULL))

                op->summary_metadata = var_metadata_dup_to_gvariant (var_ref_info_get_metadata (ref_info));

              commit_data = flatpak_remote_state_load_ref_commit (state, priv->dir, flatpak_decomposed_get_ref (op->ref), checksum,  op->resolved_token, NULL, NULL, &local_error);


              if (commit_data == NULL)
                {
                  if (g_error_matches (local_error, FLATPAK_HTTP_ERROR, FLATPAK_HTTP_ERROR_UNAUTHORIZED) && !op->requested_token)
                    {

                      g_debug ("Unauthorized access during resolve by commit of %s, retrying with token", flatpak_decomposed_get_ref (op->ref));
                      priv->needs_resolve = TRUE;
                      priv->needs_tokens = TRUE;

                      
                      op->token_type = G_MAXINT32;
                      op->resolved_commit = g_strdup (checksum);

                      g_clear_error (&local_error);
                      continue;
                    }
                  g_propagate_error (error, g_steal_pointer (&local_error));
                  return FALSE;
                }

              resolve_op_from_commit (self, op, checksum, sideload_path, commit_data);
            }
        }
    }

  return TRUE;
}

static gboolean resolve_all_ops (FlatpakTransaction *self, GCancellable       *cancellable, GError            **error)


{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  while (priv->needs_resolve)
    {
      priv->needs_resolve = FALSE;
      priv->needs_tokens = FALSE;
      if (!resolve_ops (self, cancellable, error))
        return FALSE;

      
      if (priv->needs_tokens)
        {
          if (!request_required_tokens (self, NULL, cancellable, error))
            return FALSE;
        }
    }

  return TRUE;
}

static void request_tokens_response (FlatpakAuthenticatorRequest *object, guint response, GVariant *results, RequestData *data)



{
  FlatpakTransaction *transaction = data->transaction;
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (transaction);

  if (data->done)
    return; 

  g_assert (priv->active_request_id == 0); 

  data->response = response;
  data->results = g_variant_ref (results);
  data->done = TRUE;
  g_main_context_wakeup (g_main_context_get_thread_default ());
}

static void request_tokens_webflow (FlatpakAuthenticatorRequest *object, const gchar *arg_uri, GVariant *options, RequestData *data)



{
  g_autoptr(FlatpakTransaction) transaction = g_object_ref (data->transaction);
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (transaction);
  gboolean retval = FALSE;

  if (data->done)
    return; 

  g_assert (priv->active_request_id == 0);
  priv->active_request_id = ++priv->next_request_id;

  g_debug ("Webflow start %s", arg_uri);
  g_signal_emit (transaction, signals[WEBFLOW_START], 0, data->remote, arg_uri, options, priv->active_request_id, &retval);
  if (!retval)
    {
      g_autoptr(GError) local_error = NULL;

      priv->active_request_id = 0;

      
      if (!flatpak_authenticator_request_call_close_sync (data->request, NULL, &local_error))
        g_debug ("Failed to close auth request: %s", local_error->message);
    }
}

static void request_tokens_webflow_done (FlatpakAuthenticatorRequest *object, GVariant *options, RequestData *data)


{
  g_autoptr(FlatpakTransaction) transaction = g_object_ref (data->transaction);
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (transaction);
  guint id;

  if (data->done)
    return; 

  g_assert (priv->active_request_id != 0);
  id = priv->active_request_id;
  priv->active_request_id = 0;

  g_debug ("Webflow done");
  g_signal_emit (transaction, signals[WEBFLOW_DONE], 0, options, id);
}

static void request_tokens_basic_auth (FlatpakAuthenticatorRequest *object, const gchar *arg_realm, GVariant *options, RequestData *data)



{
  g_autoptr(FlatpakTransaction) transaction = g_object_ref (data->transaction);
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (transaction);
  gboolean retval = FALSE;

  if (data->done)
    return; 

  g_assert (priv->active_request_id == 0);
  priv->active_request_id = ++priv->next_request_id;

  g_debug ("BasicAuth start %s", arg_realm);
  g_signal_emit (transaction, signals[BASIC_AUTH_START], 0, data->remote, arg_realm, options, priv->active_request_id, &retval);
  if (!retval)
    {
      g_autoptr(GError) local_error = NULL;

      priv->active_request_id = 0;

      
      if (!flatpak_authenticator_request_call_close_sync (data->request, NULL, &local_error))
        g_debug ("Failed to close auth request: %s", local_error->message);
    }

}


void flatpak_transaction_abort_webflow (FlatpakTransaction *self, guint id)

{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autoptr(GError) local_error = NULL;

  if (priv->active_request_id == id)
    {
      RequestData *data = priv->active_request;

      g_assert (data != NULL);
      priv->active_request_id = 0;

      if (!data->done)
        {
          if (!flatpak_authenticator_request_call_close_sync (data->request, NULL, &local_error))
            g_debug ("Failed to close auth request: %s", local_error->message);
        }
    }
}


void flatpak_transaction_complete_basic_auth (FlatpakTransaction *self, guint id, const char *user, const char *password, GVariant *options)




{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autoptr(GError) local_error = NULL;
  g_autoptr(GVariant) default_options = NULL;

  if (options == NULL)
    {
      default_options = g_variant_ref_sink (g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0));
      options = default_options;
    }

  if (priv->active_request_id == id)
    {
      RequestData *data = priv->active_request;

      g_assert (data != NULL);
      priv->active_request_id = 0;

      if (user == NULL)
        {
          if (!flatpak_authenticator_request_call_close_sync (data->request, NULL, &local_error))
            g_debug ("Failed to abort basic auth request: %s", local_error->message);
        }
      else {
          if (!flatpak_authenticator_request_call_basic_auth_reply_sync (data->request, user, password, options, NULL, &local_error))


            g_debug ("Failed to reply to basic auth request: %s", local_error->message);
        }
    }
}

static void copy_summary_data (GVariantBuilder *builder, GVariant *summary, const char *key)
{
  g_autoptr(GVariant) extensions = g_variant_get_child_value (summary, 1);
  g_autoptr(GVariant) value = NULL;

  value = g_variant_lookup_value (extensions, key, NULL);
  if (value)
    g_variant_builder_add (builder, "{s@v}", key, g_variant_new_variant (value));
}


static gboolean request_tokens_for_remote (FlatpakTransaction *self, const char         *remote, GList              *ops, GCancellable       *cancellable, GError            **error)




{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autoptr(GString) refs_as_str = g_string_new ("");
  GList *l;
  g_autoptr(AutoFlatpakAuthenticatorRequest) request = NULL;
  g_autoptr(AutoFlatpakAuthenticator) authenticator = NULL;
  g_autoptr(GMainContextPopDefault) context = NULL;
  RequestData data = { self, remote };
  g_autoptr(GVariant) tokens = NULL;
  g_autoptr(GVariant) results = NULL;
  g_autoptr(GVariant) refs = NULL;
  GVariantBuilder refs_builder;
  g_autofree char *remote_url = NULL;
  g_autoptr(GVariantBuilder) extra_builder = NULL;
  FlatpakRemoteState *state;
  g_autoptr(FlatpakDecomposed) auto_install_ref = NULL;

  auto_install_ref = flatpak_dir_get_remote_auto_install_authenticator_ref (priv->dir, remote);
  if (auto_install_ref != NULL)
    {
      g_autoptr(GFile) deploy = NULL;
      deploy = flatpak_dir_get_if_deployed (priv->dir, auto_install_ref, NULL, cancellable);
      if (deploy == NULL)
        g_signal_emit (self, signals[INSTALL_AUTHENTICATOR], 0, remote, flatpak_decomposed_get_ref (auto_install_ref));
      deploy = flatpak_dir_get_if_deployed (priv->dir, auto_install_ref, NULL, cancellable);
      if (deploy == NULL)
        return flatpak_fail (error, _("No authenticator installed for remote '%s'"), remote);
    }

  if (!ostree_repo_remote_get_url (flatpak_dir_get_repo (priv->dir), remote, &remote_url, error))
    return FALSE;

  g_variant_builder_init (&refs_builder, G_VARIANT_TYPE ("a(ssia{sv})"));

  for (l = ops; l != NULL; l = l->next)
    {
      FlatpakTransactionOperation *op = l->data;
      g_autoptr(GVariantBuilder) metadata_builder = g_variant_builder_new (G_VARIANT_TYPE ("a{sv}"));

      if (op->summary_metadata)
        {
          const int n = g_variant_n_children (op->summary_metadata);
          for (int i = 0; i < n; i++)
            {
              const char *key;
              g_autofree char *new_key = NULL;
              g_autoptr(GVariant) value = NULL;

              g_variant_get_child (op->summary_metadata, i, "{&s@v}", &key, &value);

              new_key = g_strconcat ("summary.", key, NULL);
              g_variant_builder_add (metadata_builder, "{s@v}", new_key, value);
            }
        }

      g_variant_builder_add (&refs_builder, "(ssi@a{sv})", flatpak_decomposed_get_ref (op->ref), op->resolved_commit ? op->resolved_commit : "", (gint32)op->token_type, g_variant_builder_end (metadata_builder));
      g_string_append_printf (refs_as_str, "(%s, %s %d)", flatpak_decomposed_get_ref (op->ref), op->resolved_commit ? op->resolved_commit : "", op->token_type);
      if (l->next != NULL)
        g_string_append (refs_as_str, ", ");
    }

  g_debug ("Requesting tokens for remote %s: %s", remote, refs_as_str->str);
  refs = g_variant_ref_sink (g_variant_builder_end (&refs_builder));

  extra_builder = g_variant_builder_new (G_VARIANT_TYPE ("a{sv}"));

  state = g_hash_table_lookup (priv->remote_states, remote);
  if (state && state->summary)
    {
      copy_summary_data (extra_builder, state->summary, "xa.oci-registry-uri");
    }

  if (flatpak_dir_get_no_interaction (priv->dir))
    g_variant_builder_add (extra_builder, "{sv}", "no-interaction", g_variant_new_boolean (TRUE));

  context = flatpak_main_context_new_default ();

  authenticator = flatpak_auth_new_for_remote (priv->dir, remote, cancellable, error);
  if (authenticator == NULL)
    return FALSE;

  request = flatpak_auth_create_request (authenticator, cancellable, error);
  if (request == NULL)
    return FALSE;

  g_signal_connect (request, "webflow", (GCallback)request_tokens_webflow, &data);
  g_signal_connect (request, "webflow-done", (GCallback)request_tokens_webflow_done, &data);
  g_signal_connect (request, "response", (GCallback)request_tokens_response, &data);
  g_signal_connect (request, "basic-auth", (GCallback)request_tokens_basic_auth, &data);

  priv->active_request = &data;

  data.request = request;
  if (!flatpak_auth_request_ref_tokens (authenticator, request, remote, remote_url, refs, g_variant_builder_end (extra_builder), priv->parent_window, cancellable, error))
    return FALSE;

  while (!data.done)
    g_main_context_iteration (context, TRUE);

  g_assert (priv->active_request_id == 0); 
  priv->active_request = NULL;

  results = data.results; 

  {
    g_autofree char *results_str = results != NULL ? g_variant_print (results, FALSE) : g_strdup ("NULL");
    g_debug ("Response from request_tokens: %d - %s\n", data.response, results_str);
  }

  if (data.response == FLATPAK_AUTH_RESPONSE_CANCELLED)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED, "User cancelled authentication request");
      return FALSE;
    }

  if (data.response != FLATPAK_AUTH_RESPONSE_OK)
    {
      const char *error_message;
      gint32 error_code;

      if (!g_variant_lookup (results, "error-message", "&s", &error_message))
        error_message = NULL;

      if (g_variant_lookup (results, "error-code", "i", &error_code) && error_code != -1)
        {
          if (error_message)
            return flatpak_fail_error (error, error_code, _("Failed to get tokens for ref: %s"), error_message);
          else return flatpak_fail_error (error, error_code, _("Failed to get tokens for ref"));
        }
      else {
          if (error_message)
            return flatpak_fail (error, _("Failed to get tokens for ref: %s"), error_message);
          else return flatpak_fail (error, _("Failed to get tokens for ref"));
        }
    }

  tokens = g_variant_lookup_value (results, "tokens", G_VARIANT_TYPE ("a{sas}"));
  if (tokens == NULL)
    return flatpak_fail (error, "Authenticator didn't send requested tokens");

  for (l = ops; l != NULL; l = l->next)
    {
      FlatpakTransactionOperation *op = l->data;
      GVariantIter iter;
      const char *token = NULL;
      const char *token_for_refs;
      g_autofree const char **refs_strv;

      g_variant_iter_init (&iter, tokens);
      while (g_variant_iter_next (&iter, "{&s^a&s}", &token_for_refs, &refs_strv))
        {
          if (g_strv_contains (refs_strv, flatpak_decomposed_get_ref (op->ref)))
            {
              token = token_for_refs;
              break;
            }
        }

      if (token == NULL)
        return flatpak_fail (error, "Authenticator didn't send tokens for ref");

      

      op->resolved_token = *token == 0 ? NULL : g_strdup (token);
      op->requested_token = TRUE;
    }

  return TRUE;
}

static gboolean request_required_tokens (FlatpakTransaction *self, const char         *optional_remote, GCancellable       *cancellable, GError            **error)



{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  GList *l;
  g_autoptr(GHashTable) need_token_ht = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, (GDestroyNotify) g_list_free); 

  
  flatpak_transaction_normalize_ops (self);

  for (l = priv->ops; l != NULL; l = l->next)
    {
      FlatpakTransactionOperation *op = l->data;
      GList *old;

      if (!flatpak_transaction_operation_get_requires_authentication (op))
        continue;

      if (optional_remote != NULL && g_strcmp0 (op->remote, optional_remote) != 0)
        continue;

      old = g_hash_table_lookup (need_token_ht, op->remote);
      if (old == NULL)
        g_hash_table_insert (need_token_ht, op->remote, g_list_append (NULL, op));
      else old = g_list_append (old, op);
    }

  GLNX_HASH_TABLE_FOREACH_KV(need_token_ht, const char *, remote, GList *, remote_ops)
    {
      if (!request_tokens_for_remote (self, remote, remote_ops, cancellable, error))
        return FALSE;
    }

  return TRUE;
}

static int compare_op_ref (FlatpakTransactionOperation *a, FlatpakTransactionOperation *b)
{
  const char *aa = flatpak_decomposed_get_pref (a->ref);
  const char *bb = flatpak_decomposed_get_pref (b->ref);

  if (a->run_last != b->run_last)
    {
      if (a->run_last)
        return 1;
      return -1;
    }

  return g_strcmp0 (aa, bb);
}

static int compare_op_prio (FlatpakTransactionOperation *a, FlatpakTransactionOperation *b)
{
  return b->run_after_prio - a->run_after_prio;
}

static void sort_ops (FlatpakTransaction *self)
{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  GList *sorted = NULL;
  GList *remaining;
  GList *runnable = NULL;
  GList *l, *next;

  remaining = priv->ops;
  priv->ops = NULL;

  
  for (l = remaining; l != NULL; l = next)
    {
      FlatpakTransactionOperation *op = l->data;
      next = l->next;

      if (op->run_after_count == 0)
        {
          remaining = g_list_remove_link (remaining, l);
          runnable = g_list_concat (l, runnable);
        }
    }

  
  runnable = g_list_sort (runnable, (GCompareFunc) compare_op_ref);

  while (runnable)
    {
      GList *run = runnable;
      FlatpakTransactionOperation *run_op = run->data;

      
      runnable = g_list_remove_link (runnable, run);
      sorted = g_list_concat (run, sorted); 

      
      run_op->run_before_ops = g_list_sort (run_op->run_before_ops, (GCompareFunc) compare_op_prio);
      for (l = run_op->run_before_ops; l != NULL; l = l->next)
        {
          FlatpakTransactionOperation *after_op = l->data;
          after_op->run_after_count--;
          if (after_op->run_after_count == 0)
            {
              GList *after_l = g_list_find (remaining, after_op);
              g_assert (after_l != NULL);
              remaining = g_list_remove_link (remaining, after_l);
              runnable = g_list_concat (after_l, runnable);
            }
        }
    }

  if (remaining != NULL)
    {
      g_warning ("ops remaining after sort, maybe there is a dependency loop?");
      sorted = g_list_concat (remaining, sorted);
    }

  priv->ops = g_list_reverse (sorted);
}


GList * flatpak_transaction_get_operations (FlatpakTransaction *self)
{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  GList *l;
  GList *non_skipped = NULL;

  non_skipped = NULL;
  for (l = priv->ops; l != NULL; l = l->next)
    {
      FlatpakTransactionOperation *op = l->data;
      if (!op->skip)
        non_skipped = g_list_prepend (non_skipped, g_object_ref (op));
    }
  return g_list_reverse (non_skipped);
}


FlatpakTransactionOperation * flatpak_transaction_get_current_operation (FlatpakTransaction *self)
{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  if (priv->current_op)
    return g_object_ref (priv->current_op);

  return NULL;
}


FlatpakInstallation * flatpak_transaction_get_installation (FlatpakTransaction *self)
{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);

  return g_object_ref (priv->installation);
}

static gboolean remote_is_already_configured (FlatpakTransaction *self, const char         *url)

{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autofree char *old_remote = NULL;

  old_remote = flatpak_dir_find_remote_by_uri (priv->dir, url);

  

  return old_remote != NULL;
}

static gboolean handle_suggested_remote_name (FlatpakTransaction *self, GKeyFile *keyfile, GKeyFile *runtime_repo_keyfile, GError **error)



{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autofree char *suggested_name = NULL;
  g_autofree char *name = NULL;
  g_autofree char *url = NULL;
  g_autoptr(GKeyFile) config = NULL;
  g_autoptr(GBytes) gpg_key = NULL;
  gboolean res;

  suggested_name = g_key_file_get_string (keyfile, FLATPAK_REF_GROUP, FLATPAK_REF_SUGGEST_REMOTE_NAME_KEY, NULL);
  if (suggested_name == NULL)
    return TRUE;

  name = g_key_file_get_string (keyfile, FLATPAK_REF_GROUP, FLATPAK_REF_NAME_KEY, NULL);
  if (name == NULL)
    return TRUE;

  url = g_key_file_get_string (keyfile, FLATPAK_REF_GROUP, FLATPAK_REF_URL_KEY, NULL);
  if (url == NULL)
    return TRUE;

  if (remote_is_already_configured (self, url))
    return TRUE;

  
  if (ostree_repo_remote_get_url (flatpak_dir_get_repo (priv->dir), suggested_name, NULL, NULL))
    return TRUE;

  res = FALSE;
  g_signal_emit (self, signals[ADD_NEW_REMOTE], 0, FLATPAK_TRANSACTION_REMOTE_GENERIC_REPO, name, suggested_name, url, &res);
  if (res)
    {
      g_autofree char *runtime_repo_url = NULL;

      
      runtime_repo_url = g_key_file_get_string (runtime_repo_keyfile, FLATPAK_REPO_GROUP, FLATPAK_REPO_URL_KEY, NULL);
      if (runtime_repo_url != NULL && flatpak_uri_equal (runtime_repo_url, url))
        config = flatpak_parse_repofile (suggested_name, FALSE, runtime_repo_keyfile, &gpg_key, NULL, error);
      else config = flatpak_parse_repofile (suggested_name, TRUE, keyfile, &gpg_key, NULL, error);

      if (config == NULL)
        return FALSE;

      if (!flatpak_dir_modify_remote (priv->dir, suggested_name, config, gpg_key, NULL, error))
        return FALSE;

      if (!flatpak_dir_recreate_repo (priv->dir, NULL, error))
        return FALSE;

      flatpak_installation_drop_caches (priv->installation, NULL, NULL);
    }

  return TRUE;
}

static gboolean load_flatpakrepo_file (FlatpakTransaction *self, const char         *dep_url, GKeyFile          **out_keyfile, GCancellable       *cancellable, GError            **error)




{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autoptr(GBytes) dep_data = NULL;
  g_autoptr(GKeyFile) dep_keyfile = g_key_file_new ();
  g_autoptr(GError) local_error = NULL;
  g_autoptr(SoupSession) soup_session = NULL;

  if (priv->disable_deps)
    return TRUE;

  if (!g_str_has_prefix (dep_url, "http:") && !g_str_has_prefix (dep_url, "https:") && !g_str_has_prefix (dep_url, "file:"))

    return flatpak_fail_error (error, FLATPAK_ERROR_INVALID_DATA, _("Flatpakrepo URL %s not file, HTTP or HTTPS"), dep_url);

  soup_session = flatpak_create_soup_session (PACKAGE_STRING);
  dep_data = flatpak_load_uri (soup_session, dep_url, 0, NULL, NULL, NULL, NULL, cancellable, error);
  if (dep_data == NULL)
    {
      g_prefix_error (error, _("Can't load dependent file %s: "), dep_url);
      return FALSE;
    }

  if (!g_key_file_load_from_data (dep_keyfile, g_bytes_get_data (dep_data, NULL), g_bytes_get_size (dep_data), 0, &local_error))


    return flatpak_fail_error (error, FLATPAK_ERROR_INVALID_DATA, _("Invalid .flatpakrepo: %s"), local_error->message);

  if (out_keyfile)
    *out_keyfile = g_steal_pointer (&dep_keyfile);

  return TRUE;
}

static gboolean handle_runtime_repo_deps (FlatpakTransaction *self, const char         *id, const char         *dep_url, GKeyFile           *dep_keyfile, GCancellable       *cancellable, GError            **error)





{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autofree char *runtime_url = NULL;
  g_autofree char *new_remote = NULL;
  g_autofree char *basename = NULL;
  g_autoptr(SoupURI) uri = NULL;
  g_auto(GStrv) remotes = NULL;
  g_autoptr(GKeyFile) config = NULL;
  g_autoptr(GBytes) gpg_key = NULL;
  g_autofree char *group = NULL;
  char *t;
  int i;
  gboolean res;

  if (priv->disable_deps)
    return TRUE;

  g_assert (dep_keyfile != NULL);

  uri = soup_uri_new (dep_url);
  basename = g_path_get_basename (soup_uri_get_path (uri));
  
  t = strchr (basename, '.');
  if (t != NULL)
    *t = 0;

  
  remotes = flatpak_dir_list_remotes (priv->dir, NULL, NULL);
  i = 0;
  do {
      g_clear_pointer (&new_remote, g_free);

      if (i == 0)
        new_remote = g_strdup (basename);
      else new_remote = g_strdup_printf ("%s-%d", basename, i);
      i++;
    }
  while (remotes != NULL && g_strv_contains ((const char * const *) remotes, new_remote));

  config = flatpak_parse_repofile (new_remote, FALSE, dep_keyfile, &gpg_key, NULL, error);
  if (config == NULL)
    {
      g_prefix_error (error, "Can't parse dependent file %s: ", dep_url);
      return FALSE;
    }

  
  group = g_strdup_printf ("remote \"%s\"", new_remote);
  runtime_url = g_key_file_get_string (config, group, "url", NULL);
  g_assert (runtime_url != NULL);

  if (remote_is_already_configured (self, runtime_url))
    return TRUE;

  res = FALSE;
  g_signal_emit (self, signals[ADD_NEW_REMOTE], 0, FLATPAK_TRANSACTION_REMOTE_RUNTIME_DEPS, id, new_remote, runtime_url, &res);
  if (res)
    {
      if (!flatpak_dir_modify_remote (priv->dir, new_remote, config, gpg_key, NULL, error))
        return FALSE;

      if (!flatpak_dir_recreate_repo (priv->dir, NULL, error))
        return FALSE;

      flatpak_installation_drop_caches (priv->installation, NULL, NULL);
    }

  return TRUE;
}

static gboolean handle_runtime_repo_deps_from_keyfile (FlatpakTransaction *self, GKeyFile           *flatpakref_keyfile, const char         *runtime_repo_url, GKeyFile           *runtime_repo_keyfile, GCancellable       *cancellable, GError            **error)





{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autofree char *name = NULL;

  if (priv->disable_deps)
    return TRUE;

  name = g_key_file_get_string (flatpakref_keyfile, FLATPAK_REF_GROUP, FLATPAK_REF_NAME_KEY, NULL);
  if (name == NULL)
    return TRUE;

  return handle_runtime_repo_deps (self, name, runtime_repo_url, runtime_repo_keyfile, cancellable, error);
}

static gboolean flatpak_transaction_resolve_flatpakrefs (FlatpakTransaction *self, GCancellable       *cancellable, GError            **error)


{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  GList *l;

  for (l = priv->flatpakrefs; l != NULL; l = l->next)
    {
      GKeyFile *flatpakref = l->data;
      g_autofree char *remote = NULL;
      g_autofree char *runtime_repo_url = NULL;
      g_autoptr(FlatpakDecomposed) ref = NULL;
      g_autoptr(GKeyFile) runtime_repo_keyfile = NULL;

      if (!priv->disable_deps)
        {
          runtime_repo_url = g_key_file_get_string (flatpakref, FLATPAK_REF_GROUP, FLATPAK_REF_RUNTIME_REPO_KEY, NULL);
          if (runtime_repo_url == NULL)
            g_warning ("Flatpakref file does not contain a %s", FLATPAK_REF_RUNTIME_REPO_KEY);
          else if (!load_flatpakrepo_file (self, runtime_repo_url, &runtime_repo_keyfile, cancellable, error))
            return FALSE;
        }

      
      if (!handle_suggested_remote_name (self, flatpakref, runtime_repo_keyfile, error))
        return FALSE;

      if (runtime_repo_keyfile != NULL && !handle_runtime_repo_deps_from_keyfile (self, flatpakref, runtime_repo_url, runtime_repo_keyfile, cancellable, error))


        return FALSE;

      if (!flatpak_dir_create_remote_for_ref_file (priv->dir, flatpakref, priv->default_arch, &remote, NULL, &ref, error))
        return FALSE;

      
      if (!flatpak_dir_recreate_repo (priv->dir, NULL, error))
        return FALSE;

      flatpak_installation_drop_caches (priv->installation, NULL, NULL);

      if (!flatpak_transaction_add_install (self, remote, flatpak_decomposed_get_ref (ref), NULL, error))
        return FALSE;
    }

  return TRUE;
}

static gboolean handle_runtime_repo_deps_from_bundle (FlatpakTransaction *self, GFile              *file, GCancellable       *cancellable, GError            **error)



{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autofree char *dep_url = NULL;
  g_autoptr(FlatpakDecomposed) ref = NULL;
  g_autoptr(GVariant) metadata = NULL;
  g_autoptr(GKeyFile) runtime_repo_keyfile = NULL;
  g_autofree char *id = NULL;

  if (priv->disable_deps)
    return TRUE;

  metadata = flatpak_bundle_load (file, NULL, &ref, NULL, &dep_url, NULL, NULL, NULL, NULL, NULL);









  if (metadata == NULL || dep_url == NULL || ref == NULL)
    return TRUE;

  id = flatpak_decomposed_dup_id (ref);

  if (!load_flatpakrepo_file (self, dep_url, &runtime_repo_keyfile, cancellable, error))
    return FALSE;

  return handle_runtime_repo_deps (self, id, dep_url, runtime_repo_keyfile, cancellable, error);
}

static gboolean flatpak_transaction_resolve_bundles (FlatpakTransaction *self, GCancellable       *cancellable, GError            **error)


{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  GList *l;

  for (l = priv->bundles; l != NULL; l = l->next)
    {
      BundleData *data = l->data;
      g_autofree char *remote = NULL;
      g_autofree char *commit = NULL;
      g_autofree char *metadata = NULL;
      g_autoptr(FlatpakDecomposed) ref = NULL;
      gboolean created_remote;

      if (!handle_runtime_repo_deps_from_bundle (self, data->file, cancellable, error))
        return FALSE;

      if (!flatpak_dir_ensure_repo (priv->dir, cancellable, error))
        return FALSE;

      remote = flatpak_dir_ensure_bundle_remote (priv->dir, data->file, data->gpg_data, &ref, &commit, &metadata, &created_remote, NULL, error);

      if (remote == NULL)
        return FALSE;

      if (created_remote)
        flatpak_installation_drop_caches (priv->installation, NULL, NULL);

      if (!flatpak_transaction_add_ref (self, remote, ref, NULL, NULL, commit, FLATPAK_TRANSACTION_OPERATION_INSTALL_BUNDLE, data->file, metadata, FALSE, error))

        return FALSE;
    }

  return TRUE;
}


gboolean flatpak_transaction_run (FlatpakTransaction *transaction, GCancellable       *cancellable, GError            **error)


{
  return FLATPAK_TRANSACTION_GET_CLASS (transaction)->run (transaction, cancellable, error);
}

static gboolean _run_op_kind (FlatpakTransaction           *self, FlatpakTransactionOperation  *op, FlatpakRemoteState           *remote_state, gboolean                     *out_needs_prune, gboolean                     *out_needs_triggers, gboolean                     *out_needs_cache_drop, GCancellable                 *cancellable, GError                      **error)







{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  gboolean res = TRUE;

  g_return_val_if_fail (remote_state != NULL || op->kind == FLATPAK_TRANSACTION_OPERATION_UNINSTALL, FALSE);

  if (op->kind == FLATPAK_TRANSACTION_OPERATION_INSTALL)
    {
      g_autoptr(FlatpakTransactionProgress) progress = flatpak_transaction_progress_new ();
      FlatpakTransactionResult result_details = 0;
      g_autoptr(GError) local_error = NULL;

      emit_new_op (self, op, progress);

      g_assert (op->resolved_commit != NULL); 

      if (op->resolved_metakey && !flatpak_check_required_version (flatpak_decomposed_get_ref (op->ref), op->resolved_metakey, &local_error))
        res = FALSE;
      else res = flatpak_dir_install (priv->dir, priv->no_pull, priv->no_deploy, priv->disable_static_deltas, priv->reinstall, priv->max_op >= APP_UPDATE, op->pin_on_deploy, remote_state, op->ref, op->resolved_commit, (const char **) op->subpaths, (const char **) op->previous_ids, op->resolved_sideload_path, op->resolved_metadata, op->resolved_token, progress->progress_obj, cancellable, &local_error);
















      flatpak_transaction_progress_done (progress);

      
      if (!res && g_error_matches (local_error, FLATPAK_ERROR, FLATPAK_ERROR_ALREADY_INSTALLED))
        {
          res = TRUE;
          g_clear_error (&local_error);

          result_details |= FLATPAK_TRANSACTION_RESULT_NO_CHANGE;
        }
      else if (!res)
        {
          g_propagate_error (error, g_steal_pointer (&local_error));
        }

      if (res)
        {
          emit_op_done (self, op, result_details);

          
          if (!priv->no_pull && priv->reinstall)
            *out_needs_prune = TRUE;

          if (flatpak_decomposed_is_app (op->ref))
            *out_needs_triggers = TRUE;

          if (op->pin_on_deploy)
            *out_needs_cache_drop = TRUE;
        }
    }
  else if (op->kind == FLATPAK_TRANSACTION_OPERATION_UPDATE)
    {
      g_assert (op->resolved_commit != NULL); 

      if (flatpak_dir_needs_update_for_commit_and_subpaths (priv->dir, op->remote, op->ref, op->resolved_commit, (const char **) op->subpaths))
        {
          g_autoptr(FlatpakTransactionProgress) progress = flatpak_transaction_progress_new ();
          FlatpakTransactionResult result_details = 0;
          g_autoptr(GError) local_error = NULL;

          emit_new_op (self, op, progress);

          if (op->resolved_metakey && !flatpak_check_required_version (flatpak_decomposed_get_ref (op->ref), op->resolved_metakey, &local_error))
            res = FALSE;
          else if (op->update_only_deploy)
            res = flatpak_dir_deploy_update (priv->dir, op->ref, op->resolved_commit, (const char **) op->subpaths, (const char **) op->previous_ids, cancellable, &local_error);



          else res = flatpak_dir_update (priv->dir, priv->no_pull, priv->no_deploy, priv->disable_static_deltas, op->commit != NULL, priv->max_op >= APP_UPDATE, priv->max_op == APP_INSTALL || priv->max_op == RUNTIME_INSTALL, remote_state, op->ref, op->resolved_commit, (const char **) op->subpaths, (const char **) op->previous_ids, op->resolved_sideload_path, op->resolved_metadata, op->resolved_token, progress->progress_obj, cancellable, &local_error);
















          flatpak_transaction_progress_done (progress);

          
          if (!res && g_error_matches (local_error, FLATPAK_ERROR, FLATPAK_ERROR_ALREADY_INSTALLED))
            {
              res = TRUE;
              g_clear_error (&local_error);

              result_details |= FLATPAK_TRANSACTION_RESULT_NO_CHANGE;
            }
          else if (!res)
            {
              g_propagate_error (error, g_steal_pointer (&local_error));
            }

          if (res)
            {
              emit_op_done (self, op, result_details);

              if (!priv->no_pull)
                *out_needs_prune = TRUE;

              if (flatpak_decomposed_is_app (op->ref))
                *out_needs_triggers = TRUE;
            }
        }
      else g_debug ("%s need no update", flatpak_decomposed_get_ref (op->ref));
    }
  else if (op->kind == FLATPAK_TRANSACTION_OPERATION_INSTALL_BUNDLE)
    {
      g_autoptr(FlatpakTransactionProgress) progress = flatpak_transaction_progress_new ();
      emit_new_op (self, op, progress);
      if (op->resolved_metakey && !flatpak_check_required_version (flatpak_decomposed_get_ref (op->ref), op->resolved_metakey, error))
        res = FALSE;
      else res = flatpak_dir_install_bundle (priv->dir, op->bundle, op->remote, NULL, cancellable, error);


      flatpak_transaction_progress_done (progress);

      if (res)
        {
          emit_op_done (self, op, 0);
          *out_needs_prune = TRUE;
          *out_needs_triggers = TRUE;
        }
    }
  else if (op->kind == FLATPAK_TRANSACTION_OPERATION_UNINSTALL)
    {
      g_autoptr(FlatpakTransactionProgress) progress = flatpak_transaction_progress_new ();
      FlatpakHelperUninstallFlags flags = 0;

      if (priv->disable_prune)
        flags |= FLATPAK_HELPER_UNINSTALL_FLAGS_KEEP_REF;

      if (priv->force_uninstall)
        flags |= FLATPAK_HELPER_UNINSTALL_FLAGS_FORCE_REMOVE;

      emit_new_op (self, op, progress);

      res = flatpak_dir_uninstall (priv->dir, op->ref, flags, cancellable, error);

      flatpak_transaction_progress_done (progress);

      if (res)
        {
          emit_op_done (self, op, 0);
          *out_needs_prune = TRUE;

          if (flatpak_decomposed_is_app (op->ref))
            *out_needs_triggers = TRUE;
        }
    }
  else g_assert_not_reached ();

  return res;
}


static void flatpak_transaction_normalize_ops (FlatpakTransaction *self)
{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  GList *l, *next;

  for (l = priv->ops; l != NULL; l = next)
    {
      FlatpakTransactionOperation *op = l->data;
      next = l->next;

      if (op->kind == FLATPAK_TRANSACTION_OPERATION_INSTALL_OR_UPDATE)
        {
          g_autoptr(GBytes) deploy_data = NULL;

          if (dir_ref_is_installed (priv->dir, op->ref, NULL, &deploy_data))
            {
              
              g_assert (g_strcmp0 (op->remote, flatpak_deploy_data_get_origin (deploy_data)) == 0);

              op->kind = FLATPAK_TRANSACTION_OPERATION_UPDATE;
            }
          else op->kind = FLATPAK_TRANSACTION_OPERATION_INSTALL;
        }

      if (op->kind == FLATPAK_TRANSACTION_OPERATION_UPDATE && !flatpak_dir_needs_update_for_commit_and_subpaths (priv->dir, op->remote, op->ref, op->resolved_commit, (const char **) op->subpaths))

        {
          
          if (op->previous_ids)
            op->update_only_deploy = TRUE;
          else op->skip = TRUE;
        }
    }
}

static gboolean add_uninstall_unused_ops (FlatpakTransaction  *self, GCancellable        *cancellable, GError             **error)


{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  g_autoptr(GHashTable) metadata_injection = NULL;
  g_autoptr(GHashTable) eol_injection = NULL;
  g_autoptr(GPtrArray) to_be_excluded = NULL;
  g_auto(GStrv) old_unused_refs = NULL;
  g_auto(GStrv) unused_refs = NULL;
  const char * const *to_be_excluded_strv = NULL;
  GList *l, *next;
  int i;

  if (priv->disable_deps)
    return TRUE;

  if (!priv->include_unused_uninstall_ops)
    {
      old_unused_refs = flatpak_dir_list_unused_refs (priv->dir, NULL, NULL, NULL, NULL, TRUE, cancellable, error);





      if (old_unused_refs == NULL)
        return FALSE;
    }

  
  metadata_injection = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, NULL);

  eol_injection = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, NULL);

  
  to_be_excluded = g_ptr_array_new ();

  for (l = priv->ops; l != NULL; l = next)
    {
      FlatpakTransactionOperation *op = l->data;
      FlatpakTransactionOperationType op_type = flatpak_transaction_operation_get_operation_type (op);

      next = l->next;

      if (op->skip)
        continue;

      g_assert (op_type == FLATPAK_TRANSACTION_OPERATION_UNINSTALL || op_type == FLATPAK_TRANSACTION_OPERATION_INSTALL || op_type == FLATPAK_TRANSACTION_OPERATION_INSTALL_BUNDLE || op_type == FLATPAK_TRANSACTION_OPERATION_UPDATE);



      if (op_type == FLATPAK_TRANSACTION_OPERATION_UNINSTALL)
        g_ptr_array_add (to_be_excluded, (char *)flatpak_decomposed_get_ref (op->ref));
      else {
          if (op->resolved_metakey)
            g_hash_table_insert (metadata_injection, (char *)flatpak_decomposed_get_ref (op->ref), op->resolved_metakey);
          g_hash_table_insert (eol_injection, (char *)flatpak_decomposed_get_ref (op->ref), GINT_TO_POINTER (op->eol != NULL || op->eol_rebase != NULL));
        }
    }

  if (to_be_excluded->len > 0)
    {
      g_ptr_array_add (to_be_excluded, NULL);
      to_be_excluded_strv = (const char * const *) to_be_excluded->pdata;
    }

  
  unused_refs = flatpak_dir_list_unused_refs (priv->dir, NULL, metadata_injection, eol_injection, to_be_excluded_strv, TRUE, cancellable, error);





  if (unused_refs == NULL)
    return FALSE;

  
  for (i = 0; unused_refs[i] != NULL; i++)
    {
      FlatpakTransactionOperation *uninstall_op;
      const char *unused_ref_str = unused_refs[i];
      g_autoptr(FlatpakDecomposed) unused_ref = flatpak_decomposed_new_from_ref (unused_ref_str, NULL);
      g_autofree char *origin = NULL;

      if (unused_ref == NULL)
        continue;

      
      if (old_unused_refs && g_strv_contains ((const char * const*)old_unused_refs, flatpak_decomposed_get_ref (unused_ref)))
        continue;

      origin = flatpak_dir_get_origin (priv->dir, unused_ref, NULL, NULL);
      if (origin)
        {
          
          uninstall_op = flatpak_transaction_add_op (self, origin, unused_ref, NULL, NULL, NULL, NULL, FLATPAK_TRANSACTION_OPERATION_UNINSTALL, FALSE, NULL);


          if (uninstall_op)
            run_operation_last (uninstall_op);
        }
    }

  return TRUE;
}

static gboolean flatpak_transaction_real_run (FlatpakTransaction *self, GCancellable       *cancellable, GError            **error)


{
  FlatpakTransactionPrivate *priv = flatpak_transaction_get_instance_private (self);
  GList *l;
  gboolean succeeded = TRUE;
  gboolean needs_prune = FALSE;
  gboolean needs_triggers = FALSE;
  gboolean needs_cache_drop = FALSE;
  gboolean ready_res = FALSE;
  int i;

  if (!priv->can_run)
    return flatpak_fail (error, _("Transaction already executed"));

  priv->can_run = FALSE;

  priv->current_op = NULL;

  if (flatpak_dir_is_user (priv->dir) && getuid () == 0)
    {
      struct stat st_buf;
      g_autofree char *dir_path = NULL;

      
      dir_path = g_file_get_path (flatpak_dir_get_path (priv->dir));
      if (stat (dir_path, &st_buf) == 0 && st_buf.st_uid != 0)
        return flatpak_fail_error (error, FLATPAK_ERROR_WRONG_USER, _("Refusing to operate on a user installation as root! " "This can lead to incorrect file ownership and permission errors."));

    }

  if (!priv->no_pull && !flatpak_transaction_update_metadata (self, cancellable, error))
    {
      g_assert (error == NULL || *error != NULL);
      return FALSE;
    }

  if (!flatpak_transaction_add_auto_install (self, cancellable, error))
    {
      g_assert (error == NULL || *error != NULL);
      return FALSE;
    }

  if (!flatpak_transaction_resolve_flatpakrefs (self, cancellable, error))
    {
      g_assert (error == NULL || *error != NULL);
      return FALSE;
    }

  if (!flatpak_transaction_resolve_bundles (self, cancellable, error))
    {
      g_assert (error == NULL || *error != NULL);
      return FALSE;
    }

  
  if (!resolve_all_ops (self, cancellable, error))
    {
      g_assert (error == NULL || *error != NULL);
      return FALSE;
    }

  
  for (l = priv->ops; l != NULL; l = l->next)
    {
      FlatpakTransactionOperation *op = l->data;

      if (!op->skip && !add_deps (self, op, error))
        {
          g_assert (error == NULL || *error != NULL);
          return FALSE;
        }
    }

  
  if (!resolve_all_ops (self, cancellable, error))
    {
      g_assert (error == NULL || *error != NULL);
      return FALSE;
    }

  
  for (l = priv->ops; l != NULL; l = l->next)
    {
      FlatpakTransactionOperation *op = l->data;

      if (!op->skip && !add_related (self, op, error))
        {
          g_assert (error == NULL || *error != NULL);
          return FALSE;
        }
    }

  
  if (!resolve_all_ops (self, cancellable, error))
    {
      g_assert (error == NULL || *error != NULL);
      return FALSE;
    }

  
  flatpak_transaction_normalize_ops (self);

  
  if (!add_uninstall_unused_ops (self, cancellable, error))
    {
      g_assert (error == NULL || *error != NULL);
      return FALSE;
    }

  sort_ops (self);

  ready_res = FALSE;
  g_signal_emit (self, signals[READY_PRE_AUTH], 0, &ready_res);
  if (!ready_res)
    return flatpak_fail_error (error, FLATPAK_ERROR_ABORTED, _("Aborted by user"));

  
  if (!request_required_tokens (self, NULL, cancellable, error))
    {
      g_assert (error == NULL || *error != NULL);
      return FALSE;
    }

  ready_res = FALSE;
  g_signal_emit (self, signals[READY], 0, &ready_res);
  if (!ready_res)
    return flatpak_fail_error (error, FLATPAK_ERROR_ABORTED, _("Aborted by user"));

  for (l = priv->ops; l != NULL; l = l->next)
    {
      FlatpakTransactionOperation *op = l->data;
      g_autoptr(GError) local_error = NULL;
      gboolean res = TRUE;
      const char *pref;
      g_autoptr(FlatpakRemoteState) state = NULL;

      if (op->skip)
        continue;

      priv->current_op = op;

      pref = flatpak_decomposed_get_pref (op->ref);

      if (op->fail_if_op_fails && (op->fail_if_op_fails->failed) &&  !(op->fail_if_op_fails->kind == FLATPAK_TRANSACTION_OPERATION_UPDATE && flatpak_decomposed_is_app (op->ref)))


        {
          flatpak_fail_error (&local_error, FLATPAK_ERROR_SKIPPED, _("Skipping %s due to previous error"), pref);
          res = FALSE;
        }
      else if (op->kind != FLATPAK_TRANSACTION_OPERATION_UNINSTALL && (state = flatpak_transaction_ensure_remote_state (self, op->kind, op->remote, NULL, &local_error)) == NULL)
        {
          res = FALSE;
        }

      
      if (res && !_run_op_kind (self, op, state, &needs_prune, &needs_triggers, &needs_cache_drop, cancellable, &local_error))

        res = FALSE;

      if (res)
        {
          g_autoptr(GBytes) deploy_data = NULL;
          
          deploy_data = flatpak_dir_get_deploy_data (priv->dir, op->ref, 4, NULL, NULL);

          if (deploy_data)
            {
              const char *eol =  flatpak_deploy_data_get_eol (deploy_data);
              const char *eol_rebase = flatpak_deploy_data_get_eol_rebase (deploy_data);

              if (eol || eol_rebase)
                g_signal_emit (self, signals[END_OF_LIFED], 0, flatpak_decomposed_get_ref (op->ref), eol, eol_rebase);
            }
        }

      if (!res)
        {
          gboolean do_cont = FALSE;
          FlatpakTransactionErrorDetails error_details = 0;

          op->failed = TRUE;

          if (op->non_fatal)
            error_details |= FLATPAK_TRANSACTION_ERROR_DETAILS_NON_FATAL;

          g_signal_emit (self, signals[OPERATION_ERROR], 0, op, local_error, error_details, &do_cont);


          if (!do_cont)
            {
              if (g_cancellable_set_error_if_cancelled (cancellable, error))
                {
                  succeeded = FALSE;
                  break;
                }

              flatpak_fail_error (error, FLATPAK_ERROR_ABORTED, _("Aborted due to failure (%s)"), local_error->message);
              succeeded = FALSE;
              break;
            }
        }
    }
  priv->current_op = NULL;

  if (needs_triggers)
    flatpak_dir_run_triggers (priv->dir, cancellable, NULL);

  if (needs_prune && !priv->disable_prune)
    flatpak_dir_prune (priv->dir, cancellable, NULL);

  for (i = 0; i < priv->added_origin_remotes->len; i++)
    flatpak_dir_prune_origin_remote (priv->dir, g_ptr_array_index (priv->added_origin_remotes, i));

  
  if (needs_cache_drop || priv->added_origin_remotes->len > 0)
    flatpak_installation_drop_caches (priv->installation, NULL, NULL);

  return succeeded;
}
