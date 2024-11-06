


























subscriptionPtr subscription_new (const gchar *source, const gchar *filter, updateOptionsPtr options)


{
	subscriptionPtr	subscription;

	subscription = g_new0 (struct subscription, 1);
	subscription->type = feed_get_subscription_type ();
	subscription->updateOptions = options;

	if (!subscription->updateOptions)
		subscription->updateOptions = g_new0 (struct updateOptions, 1);

	subscription->updateState = update_state_new ();
	subscription->updateInterval = -1;
	subscription->defaultInterval = -1;

	if (source) {
		gboolean feedPrefix = FALSE;
		gchar *uri = g_strdup (source);
		g_strstrip (uri);	

		
		if (uri == strstr (uri, FEED_PROTOCOL_PREFIX)) {
			gchar *tmp = uri;
			uri = g_strdup (uri + strlen (FEED_PROTOCOL_PREFIX));
			g_free (tmp);
			feedPrefix = TRUE;
		}

		
		if (uri == strstr (uri, FEED_PROTOCOL_PREFIX2)) {
			gchar *tmp = uri;
			uri = g_strdup (uri + strlen (FEED_PROTOCOL_PREFIX2));
			g_free (tmp);
			feedPrefix = TRUE;
		}

		
		if (feedPrefix && !strstr (uri, "://")) {
			gchar *tmp = uri;
			uri = g_strdup_printf ("http://%s", uri);
			g_free (tmp);
		}

		subscription_set_source (subscription, uri);
		g_free (uri);
	}

	if (filter)
		subscription_set_filter (subscription, filter);

	return subscription;
}


static gboolean subscription_can_be_updated (subscriptionPtr subscription)
{
	if (subscription->updateJob) {
		liferea_shell_set_status_bar (_("Subscription \"%s\" is already being updated!"), node_get_title (subscription->node));
		return FALSE;
	}

	if (subscription->discontinued) {
		liferea_shell_set_status_bar (_("The subscription \"%s\" was discontinued. Liferea won't update it anymore!"), node_get_title (subscription->node));
		return FALSE;
	}

	if (!subscription_get_source (subscription)) {
		g_warning ("Feed source is NULL! This should never happen - cannot update!");
		return FALSE;
	}
	return TRUE;
}

void subscription_reset_update_counter (subscriptionPtr subscription, guint64 *now)
{
	if (!subscription)
		return;

	subscription->updateState->lastPoll = *now;
	debug2 (DEBUG_UPDATE, "Resetting last poll counter of %s to %lld.", subscription->source, subscription->updateState->lastPoll);
}


static void subscription_update_error_status (subscriptionPtr subscription, gint httpstatus, gchar *filterError)


{
	if (subscription->filterError)
		g_free (subscription->filterError);
	if (subscription->httpError)
		g_free (subscription->httpError);
	if (subscription->updateError)
		g_free (subscription->updateError);

	subscription->filterError = g_strdup (filterError);
	subscription->updateError = NULL;	
	subscription->httpError = NULL;
	subscription->httpErrorCode = httpstatus;

	

	if (!((httpstatus >= 200) && (httpstatus < 400)))
		subscription->httpError = g_strdup (network_strerror (httpstatus));
}

static void subscription_process_update_result (const struct updateResult * const result, gpointer user_data, guint32 flags)
{
	subscriptionPtr subscription = (subscriptionPtr)user_data;
	nodePtr		node = subscription->node;
	gboolean	processing = FALSE;
	guint		count, maxcount;
	gchar		*statusbar;

	
	statusbar = g_strdup ("");

	g_assert (subscription->updateJob);
	
	if ((301 == result->httpstatus || 308 == result->httpstatus) && result->source && !g_str_equal (result->source, subscription->updateJob->request->source)) {
		debug2 (DEBUG_UPDATE, "The URL of \"%s\" has changed permanently and was updated to \"%s\"", node_get_title(node), result->source);
		subscription_set_source (subscription, result->source);
    statusbar = g_strdup_printf (_("The URL of \"%s\" has changed permanently and was updated"), node_get_title(node));
  }

	
	if (result->httpstatus >= 400 || !result->data) {
		
		subscription->error = FETCH_ERROR_NET;
		node->available = FALSE;

		
		if (401 == result->httpstatus) { 
			subscription->error = FETCH_ERROR_AUTH;
			auth_dialog_new (subscription, flags);
		}
		if (410 == result->httpstatus) { 
			subscription_set_discontinued (subscription, TRUE);
			statusbar = g_strdup_printf (_("\"%s\" is discontinued. Liferea won't updated it anymore!"), node_get_title (node));
		}
	} else if (304 == result->httpstatus) {
		node->available = TRUE;
		statusbar = g_strdup_printf (_("\"%s\" has not changed since last update"), node_get_title(node));
	} else if (result->filterErrors) {
		node->available = FALSE;
		subscription->error = FETCH_ERROR_NET;
	} else {
		processing = TRUE;
	}

	
	update_jobs_get_count (&count, &maxcount);
	if (1 >= count)
		liferea_shell_set_status_bar (statusbar);
	else liferea_shell_set_status_bar (_("Updating (%d / %d) ..."), maxcount - count, maxcount);
	g_free (statusbar);

	subscription_update_error_status (subscription, result->httpstatus, result->filterErrors);

	subscription->updateJob = NULL;

	
	if (processing)
		SUBSCRIPTION_TYPE (subscription)->process_update_result (subscription, result, flags);

	
	if (g_get_real_time() > (subscription->updateState->lastFaviconPoll + ONE_MONTH_MICROSECONDS))
		subscription_icon_update (subscription);

	
	update_state_set_lastmodified (subscription->updateState, update_state_get_lastmodified (result->updateState));
	update_state_set_cookies (subscription->updateState, update_state_get_cookies (result->updateState));
	update_state_set_etag (subscription->updateState, update_state_get_etag (result->updateState));
	subscription->updateState->lastPoll = g_get_real_time();

	
	itemview_update_node_info (subscription->node);
	itemview_update ();

	db_subscription_update (subscription);
	db_node_update (subscription->node);

	feed_list_view_update_node (node->id);	

	if (processing && subscription->node->newCount > 0) {
		
		feedlist_new_items (node->newCount);
		feedlist_node_was_updated (node);
	}
}

void subscription_update (subscriptionPtr subscription, guint flags)
{
	UpdateRequest	*request;
	guint64		now;
	guint		count, maxcount;

	if (!subscription)
		return;

	if (subscription->updateJob)
		return;

	debug1 (DEBUG_UPDATE, "Scheduling %s to be updated", node_get_title (subscription->node));

	if (subscription_can_be_updated (subscription)) {
		now = g_get_real_time();
		subscription_reset_update_counter (subscription, &now);

		request = update_request_new ( subscription_get_source (subscription), subscription->updateState, subscription->updateOptions );




		if (subscription_get_filter (subscription))
			request->filtercmd = g_strdup (subscription_get_filter (subscription));

		if (SUBSCRIPTION_TYPE (subscription)->prepare_update_request (subscription, request))
			subscription->updateJob = update_execute_request (subscription, request, subscription_process_update_result, subscription, flags);
		else g_object_unref (request);

		update_jobs_get_count (&count, &maxcount);
		if (count > 1)
			liferea_shell_set_status_bar (_("Updating (%d / %d) ..."), maxcount - count, maxcount);
		else liferea_shell_set_status_bar (_("Updating '%s'..."), node_get_title (subscription->node));
	}
}

void subscription_auto_update (subscriptionPtr subscription)
{
	gint		interval;
	guint		flags = 0;
	guint64	now;

	if (!subscription)
		return;

	interval = subscription_get_update_interval (subscription);
	if (-1 == interval)
		conf_get_int_value (DEFAULT_UPDATE_INTERVAL, &interval);

	if (-2 >= interval || 0 == interval)
		return;		

	now = g_get_real_time();

	if (subscription->updateState->lastPoll + (guint64)interval * (guint64)(60 * G_USEC_PER_SEC) <= now)
		subscription_update (subscription, flags);
}

void subscription_cancel_update (subscriptionPtr subscription)
{
	if (!subscription->updateJob)
		return;

	update_job_cancel_by_owner (subscription);
	subscription->updateJob = NULL;
}

gint subscription_get_update_interval (subscriptionPtr subscription)
{
	return subscription->updateInterval;
}

void subscription_set_update_interval (subscriptionPtr subscription, gint interval)
{
	if (0 == interval) {
		interval = -1;	
	}
	subscription->updateInterval = interval;
	feedlist_schedule_save ();
}

guint subscription_get_default_update_interval (subscriptionPtr subscription)
{
	return subscription->defaultInterval;
}

void subscription_set_default_update_interval (subscriptionPtr subscription, guint interval)
{
	subscription->defaultInterval = interval;
}

void subscription_set_discontinued (subscriptionPtr subscription, gboolean newState)
{
	subscription->discontinued = newState;
}

static const gchar * subscription_get_orig_source (subscriptionPtr subscription)
{
	return subscription->origSource;
}

const gchar * subscription_get_source (subscriptionPtr subscription)
{
	return subscription->source;
}

const gchar * subscription_get_homepage (subscriptionPtr subscription)
{
	return metadata_list_get (subscription->metadata, "homepage");
}

const gchar * subscription_get_filter (subscriptionPtr subscription)
{
	return subscription->filtercmd;
}

static void subscription_set_orig_source (subscriptionPtr subscription, const gchar *source)
{
	g_free (subscription->origSource);
	subscription->origSource = g_strchomp (g_strdup (source));
	feedlist_schedule_save ();
}

void subscription_set_source (subscriptionPtr subscription, const gchar *source)
{
	g_free (subscription->source);
	subscription->source = g_strchomp (g_strdup (source));
	feedlist_schedule_save ();

	update_state_set_cookies (subscription->updateState, NULL);

	if (NULL == subscription_get_orig_source (subscription))
		subscription_set_orig_source (subscription, source);
}

void subscription_set_homepage (subscriptionPtr subscription, const gchar *newHtmlUrl)
{
	gchar 	*htmlUrl = NULL;

	if (newHtmlUrl) {
		if (strstr (newHtmlUrl, "://")) {
			
			htmlUrl = g_strchomp (g_strdup (newHtmlUrl));
		} else {
			
			gchar *tmp, *source;

			source = g_strdup (subscription_get_source (subscription));
			tmp = strrchr (source, '/');
			if (tmp)
				*(tmp+1) = '\0';

			htmlUrl = (gchar *)common_build_url (newHtmlUrl, source);
			g_free (source);
		}

		metadata_list_set (&subscription->metadata, "homepage", htmlUrl);
		g_free (htmlUrl);
	}
}

void subscription_set_filter (subscriptionPtr subscription, const gchar *filter)
{
	g_free (subscription->filtercmd);
	subscription->filtercmd = g_strdup (filter);
	feedlist_schedule_save ();
}

void subscription_set_auth_info (subscriptionPtr subscription, const gchar *username, const gchar *password)


{
	g_assert (NULL != subscription->updateOptions);

	g_free (subscription->updateOptions->username);
	g_free (subscription->updateOptions->password);

	subscription->updateOptions->username = g_strdup (username);
	subscription->updateOptions->password = g_strdup (password);

	liferea_auth_info_store (subscription);
}

subscriptionPtr subscription_import (xmlNodePtr xml, gboolean trusted)
{
	subscriptionPtr	subscription;
	xmlChar		*source, *homepage, *filter, *intervalStr, *tmp;

	subscription = subscription_new (NULL, NULL, NULL);

	source = xmlGetProp (xml, BAD_CAST "xmlUrl");
	if (!source)
		source = xmlGetProp (xml, BAD_CAST "xmlurl");	

	if (source) {
		if (!trusted && source[0] == '|') {
			
			tmp = (xmlChar *)g_strdup_printf ("unsafe command: %s", source);
			xmlFree (source);
			source = tmp;
		}

		subscription_set_source (subscription, (gchar *)source);
		xmlFree (source);

		homepage = xmlGetProp (xml, BAD_CAST "htmlUrl");
		if (homepage && xmlStrcmp (homepage, BAD_CAST ""))
			subscription_set_homepage (subscription, (gchar *)homepage);
		xmlFree (homepage);

		if ((filter = xmlGetProp (xml, BAD_CAST "filtercmd"))) {
			if (!trusted) {
				
				tmp = (xmlChar *)g_strdup_printf ("unsafe command: %s", filter);
				xmlFree (filter);
				filter = tmp;
			}

			subscription_set_filter (subscription, (gchar *)filter);
			xmlFree (filter);
		}

		intervalStr = xmlGetProp (xml, BAD_CAST "updateInterval");
		subscription_set_update_interval (subscription, common_parse_long ((gchar *)intervalStr, -1));
		xmlFree (intervalStr);

		
		tmp = xmlGetProp (xml, BAD_CAST "dontUseProxy");
		if (tmp && !xmlStrcmp (tmp, BAD_CAST "true"))
			subscription->updateOptions->dontUseProxy = TRUE;
		xmlFree (tmp);

		
		subscription->updateOptions->username = (gchar *)xmlGetProp (xml, BAD_CAST "username");
		subscription->updateOptions->password = (gchar *)xmlGetProp (xml, BAD_CAST "password");
	}

	return subscription;
}

void subscription_export (subscriptionPtr subscription, xmlNodePtr xml, gboolean trusted)
{
	gchar *interval = g_strdup_printf ("%d", subscription_get_update_interval (subscription));

	xmlNewProp (xml, BAD_CAST "xmlUrl", BAD_CAST subscription_get_source (subscription));

	if (subscription_get_homepage (subscription))
		xmlNewProp (xml, BAD_CAST"htmlUrl", BAD_CAST subscription_get_homepage (subscription));
	else xmlNewProp (xml, BAD_CAST"htmlUrl", BAD_CAST "");

	if (subscription_get_filter (subscription))
		xmlNewProp (xml, BAD_CAST"filtercmd", BAD_CAST subscription_get_filter (subscription));

	if(trusted) {
		xmlNewProp (xml, BAD_CAST"updateInterval", BAD_CAST interval);

		if (subscription->updateOptions->dontUseProxy)
			xmlNewProp (xml, BAD_CAST"dontUseProxy", BAD_CAST"true");

		if (!liferea_auth_has_active_store ()) {
			if (subscription->updateOptions->username)
				xmlNewProp (xml, BAD_CAST"username", (xmlChar *)subscription->updateOptions->username);
			if (subscription->updateOptions->password)
				xmlNewProp (xml, BAD_CAST"password", (xmlChar *)subscription->updateOptions->password);
		}
	}

	g_free (interval);
}

void subscription_to_xml (subscriptionPtr subscription, xmlNodePtr xml)
{
	gchar	*tmp;

	xmlNewTextChild (xml, NULL, BAD_CAST "feedSource", (xmlChar *)subscription_get_source (subscription));
	xmlNewTextChild (xml, NULL, BAD_CAST "feedOrigSource", (xmlChar *)subscription_get_orig_source (subscription));

	tmp = g_strdup_printf ("%d", subscription_get_default_update_interval (subscription));
	xmlNewTextChild (xml, NULL, BAD_CAST "feedUpdateInterval", (xmlChar *)tmp);
	g_free (tmp);

	if (subscription->updateError)
		xmlNewTextChild (xml, NULL, BAD_CAST "updateError", (xmlChar *)subscription->updateError);
	if (subscription->httpError) {
		xmlNewTextChild (xml, NULL, BAD_CAST "httpError", (xmlChar *)subscription->httpError);

		tmp = g_strdup_printf ("%d", subscription->httpErrorCode);
		xmlNewTextChild (xml, NULL, BAD_CAST "httpErrorCode", (xmlChar *)tmp);
		g_free (tmp);
	}
	if (subscription->filterError)
		xmlNewTextChild (xml, NULL, BAD_CAST "filterError", (xmlChar *)subscription->filterError);

	metadata_add_xml_nodes (subscription->metadata, xml);
}

void subscription_free (subscriptionPtr subscription)
{
	if (!subscription)
		return;

	g_free (subscription->updateError);
	g_free (subscription->filterError);
	g_free (subscription->httpError);
	g_free (subscription->source);
	g_free (subscription->origSource);
	g_free (subscription->filtercmd);

	update_job_cancel_by_owner (subscription);
	update_options_free (subscription->updateOptions);
	update_state_free (subscription->updateState);
	metadata_list_free (subscription->metadata);

	g_free (subscription);
}
