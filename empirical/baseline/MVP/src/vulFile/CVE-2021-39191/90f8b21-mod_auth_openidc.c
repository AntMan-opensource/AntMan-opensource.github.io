























static int oidc_handle_logout_request(request_rec *r, oidc_cfg *c, oidc_session_t *session, const char *url);








extern module AP_MODULE_DECLARE_DATA auth_openidc_module;


static void oidc_scrub_request_headers(request_rec *r, const char *claim_prefix, apr_hash_t *scrub) {

	const int prefix_len = claim_prefix ? strlen(claim_prefix) : 0;

	
	const apr_array_header_t *const h = apr_table_elts(r->headers_in);

	
	apr_table_t *clean_headers = apr_table_make(r->pool, h->nelts);

	
	const apr_table_entry_t *const e = (const apr_table_entry_t*) h->elts;
	int i;
	for (i = 0; i < h->nelts; i++) {
		const char *const k = e[i].key;

		
		const char *hdr = (k != NULL) && (scrub != NULL) ? apr_hash_get(scrub, k, APR_HASH_KEY_STRING) : NULL;

		const int header_matches = (hdr != NULL)
						&& (oidc_strnenvcmp(k, hdr, -1) == 0);

		
		const int prefix_matches = (k != NULL) && prefix_len && (oidc_strnenvcmp(k, claim_prefix, prefix_len) == 0);

		
		if (!prefix_matches && !header_matches) {
			apr_table_addn(clean_headers, k, e[i].val);
		} else {
			oidc_warn(r, "scrubbed suspicious request header (%s: %.32s)", k, e[i].val);
		}
	}

	
	r->headers_in = clean_headers;
}


void oidc_scrub_headers(request_rec *r) {
	oidc_cfg *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	const char *prefix = oidc_cfg_claim_prefix(r);
	apr_hash_t *hdrs = apr_hash_make(r->pool);

	if (apr_strnatcmp(prefix, "") == 0) {
		if ((cfg->white_listed_claims != NULL)
				&& (apr_hash_count(cfg->white_listed_claims) > 0))
			hdrs = apr_hash_overlay(r->pool, cfg->white_listed_claims, hdrs);
		else oidc_warn(r, "both " OIDCClaimPrefix " and " OIDCWhiteListedClaims " are empty: this renders an insecure setup!");

	}

	char *authn_hdr = oidc_cfg_dir_authn_header(r);
	if (authn_hdr != NULL)
		apr_hash_set(hdrs, authn_hdr, APR_HASH_KEY_STRING, authn_hdr);

	
	oidc_scrub_request_headers(r, OIDC_DEFAULT_HEADER_PREFIX, hdrs);

	
	if ((strstr(prefix, OIDC_DEFAULT_HEADER_PREFIX) != prefix)) {
		oidc_scrub_request_headers(r, prefix, NULL);
	}
}


void oidc_strip_cookies(request_rec *r) {

	char *cookie, *ctx, *result = NULL;
	const char *name = NULL;
	int i;

	apr_array_header_t *strip = oidc_dir_cfg_strip_cookies(r);

	char *cookies = apr_pstrdup(r->pool, oidc_util_hdr_in_cookie_get(r));

	if ((cookies != NULL) && (strip != NULL)) {

		oidc_debug(r, "looking for the following cookies to strip from cookie header: %s", apr_array_pstrcat(r->pool, strip, OIDC_CHAR_COMMA));


		cookie = apr_strtok(cookies, OIDC_STR_SEMI_COLON, &ctx);

		do {
			while (cookie != NULL && *cookie == OIDC_CHAR_SPACE)
				cookie++;

			for (i = 0; i < strip->nelts; i++) {
				name = ((const char**) strip->elts)[i];
				if ((strncmp(cookie, name, strlen(name)) == 0)
						&& (cookie[strlen(name)] == OIDC_CHAR_EQUAL)) {
					oidc_debug(r, "stripping: %s", name);
					break;
				}
			}

			if (i == strip->nelts) {
				result = result ? apr_psprintf(r->pool, "%s%s %s", result, OIDC_STR_SEMI_COLON, cookie) :
						cookie;
			}

			cookie = apr_strtok(NULL, OIDC_STR_SEMI_COLON, &ctx);
		} while (cookie != NULL);

		oidc_util_hdr_in_cookie_set(r, result);
	}
}




static char* oidc_get_browser_state_hash(request_rec *r, oidc_cfg *c, const char *nonce) {

	oidc_debug(r, "enter");

	
	const char *value = NULL;
	
	apr_sha1_ctx_t sha1;

	
	apr_sha1_init(&sha1);

	if (c->state_input_headers & OIDC_STATE_INPUT_HEADERS_X_FORWARDED_FOR) {
		
		value = oidc_util_hdr_in_x_forwarded_for_get(r);
		
		if (value != NULL)
			apr_sha1_update(&sha1, value, strlen(value));
	}

	if (c->state_input_headers & OIDC_STATE_INPUT_HEADERS_USER_AGENT) {
		
		value = oidc_util_hdr_in_user_agent_get(r);
		
		if (value != NULL)
			apr_sha1_update(&sha1, value, strlen(value));
	}

	
	

	
	apr_sha1_update(&sha1, nonce, strlen(nonce));

	
	value = oidc_util_get_provided_token_binding_id(r);
	if (value != NULL) {
		oidc_debug(r, "Provided Token Binding ID environment variable found; adding its value to the state");
		apr_sha1_update(&sha1, value, strlen(value));
	}

	
	unsigned char hash[OIDC_SHA1_LEN];
	apr_sha1_final(hash, &sha1);

	
	char *result = NULL;
	oidc_base64url_encode(r, &result, (const char*) hash, OIDC_SHA1_LEN, TRUE);
	return result;
}


static char* oidc_get_state_cookie_name(request_rec *r, const char *state) {
	return apr_psprintf(r->pool, "%s%s", oidc_cfg_dir_state_cookie_prefix(r), state);
}


static apr_byte_t oidc_provider_static_config(request_rec *r, oidc_cfg *c, oidc_provider_t **provider) {

	json_t *j_provider = NULL;
	char *s_json = NULL;

	
	if ((c->metadata_dir != NULL) || (c->provider.metadata_url == NULL)) {
		*provider = &c->provider;
		return TRUE;
	}

	oidc_cache_get_provider(r, c->provider.metadata_url, &s_json);

	if (s_json == NULL) {

		if (oidc_metadata_provider_retrieve(r, c, NULL, c->provider.metadata_url, &j_provider, &s_json) == FALSE) {
			oidc_error(r, "could not retrieve metadata from url: %s", c->provider.metadata_url);
			return FALSE;
		}

		oidc_cache_set_provider(r, c->provider.metadata_url, s_json, apr_time_now() + (c->provider_metadata_refresh_interval <= 0 ? apr_time_from_sec( OIDC_CACHE_PROVIDER_METADATA_EXPIRY_DEFAULT) : c->provider_metadata_refresh_interval));

	} else {

		oidc_util_decode_json_object(r, s_json, &j_provider);

		
		if (oidc_metadata_provider_is_valid(r, c, j_provider, NULL) == FALSE) {
			oidc_error(r, "cache corruption detected: invalid metadata from url: %s", c->provider.metadata_url);

			return FALSE;
		}
	}

	*provider = apr_pcalloc(r->pool, sizeof(oidc_provider_t));
	memcpy(*provider, &c->provider, sizeof(oidc_provider_t));

	if (oidc_metadata_provider_parse(r, c, j_provider, *provider) == FALSE) {
		oidc_error(r, "could not parse metadata from url: %s", c->provider.metadata_url);
		if (j_provider)
			json_decref(j_provider);
		return FALSE;
	}

	json_decref(j_provider);

	return TRUE;
}


static oidc_provider_t* oidc_get_provider_for_issuer(request_rec *r, oidc_cfg *c, const char *issuer, apr_byte_t allow_discovery) {

	
	oidc_provider_t *provider = NULL;
	if (oidc_provider_static_config(r, c, &provider) == FALSE)
		return NULL;

	
	if (c->metadata_dir != NULL) {

		
		if ((oidc_metadata_get(r, c, issuer, &provider, allow_discovery)
				== FALSE) || (provider == NULL)) {

			
			oidc_error(r, "no provider metadata found for issuer \"%s\"", issuer);

			return NULL;
		}
	}

	return provider;
}


static apr_byte_t oidc_is_discovery_response(request_rec *r, oidc_cfg *cfg) {
	
	return oidc_util_request_has_parameter(r, OIDC_DISC_OP_PARAM)
			|| oidc_util_request_has_parameter(r, OIDC_DISC_USER_PARAM);
}


static const char* oidc_original_request_method(request_rec *r, oidc_cfg *cfg, apr_byte_t handle_discovery_response) {
	const char *method = OIDC_METHOD_GET;

	char *m = NULL;
	if ((handle_discovery_response == TRUE)
			&& (oidc_util_request_matches_url(r, oidc_get_redirect_uri(r, cfg)))
			&& (oidc_is_discovery_response(r, cfg))) {
		oidc_util_get_request_parameter(r, OIDC_DISC_RM_PARAM, &m);
		if (m != NULL)
			method = apr_pstrdup(r->pool, m);
	} else {

		
		if (oidc_cfg_dir_preserve_post(r) == 0)
			return OIDC_METHOD_GET;

		const char *content_type = oidc_util_hdr_in_content_type_get(r);
		if ((r->method_number == M_POST) && (apr_strnatcmp(content_type, OIDC_CONTENT_TYPE_FORM_ENCODED) == 0))
			method = OIDC_METHOD_FORM_POST;
	}

	oidc_debug(r, "return: %s", method);

	return method;
}


apr_byte_t oidc_post_preserve_javascript(request_rec *r, const char *location, char **javascript, char **javascript_method) {

	if (oidc_cfg_dir_preserve_post(r) == 0)
		return FALSE;

	oidc_debug(r, "enter");

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	const char *method = oidc_original_request_method(r, cfg, FALSE);

	if (apr_strnatcmp(method, OIDC_METHOD_FORM_POST) != 0)
		return FALSE;

	
	apr_table_t *params = apr_table_make(r->pool, 8);
	if (oidc_util_read_post_params(r, params, FALSE, NULL) == FALSE) {
		oidc_error(r, "something went wrong when reading the POST parameters");
		return FALSE;
	}

	const apr_array_header_t *arr = apr_table_elts(params);
	const apr_table_entry_t *elts = (const apr_table_entry_t*) arr->elts;
	int i;
	char *json = "";
	for (i = 0; i < arr->nelts; i++) {
		json = apr_psprintf(r->pool, "%s'%s': '%s'%s", json, oidc_util_escape_string(r, elts[i].key), oidc_util_escape_string(r, elts[i].val), i < arr->nelts - 1 ? "," : "");


	}
	json = apr_psprintf(r->pool, "{ %s }", json);

	const char *jmethod = "preserveOnLoad";
	const char *jscript = apr_psprintf(r->pool, "    <script type=\"text/javascript\">\n" "      function %s() {\n" "        sessionStorage.setItem('mod_auth_openidc_preserve_post_params', JSON.stringify(%s));\n" "        %s" "      }\n" "    </script>\n", jmethod, json, location ? apr_psprintf(r->pool, "window.location='%s';\n", oidc_util_javascript_escape(r->pool, location)) :









									"");
	if (location == NULL) {
		if (javascript_method)
			*javascript_method = apr_pstrdup(r->pool, jmethod);
		if (javascript)
			*javascript = apr_pstrdup(r->pool, jscript);
	} else {
		oidc_util_html_send(r, "Preserving...", jscript, jmethod, "<p>Preserving...</p>", OK);
	}

	return TRUE;
}


static int oidc_request_post_preserved_restore(request_rec *r, const char *original_url) {

	oidc_debug(r, "enter: original_url=%s", original_url);

	const char *method = "postOnLoad";
	const char *script = apr_psprintf(r->pool, "    <script type=\"text/javascript\">\n" "      function str_decode(string) {\n" "        try {\n" "          result = decodeURIComponent(string);\n" "        } catch (e) {\n" "          result =  unescape(string);\n" "        }\n" "        return result;\n" "      }\n" "      function %s() {\n" "        var mod_auth_openidc_preserve_post_params = JSON.parse(sessionStorage.getItem('mod_auth_openidc_preserve_post_params'));\n" "		 sessionStorage.removeItem('mod_auth_openidc_preserve_post_params');\n" "        for (var key in mod_auth_openidc_preserve_post_params) {\n" "          var input = document.createElement(\"input\");\n" "          input.name = str_decode(key);\n" "          input.value = str_decode(mod_auth_openidc_preserve_post_params[key]);\n" "          input.type = \"hidden\";\n" "          document.forms[0].appendChild(input);\n" "        }\n" "        document.forms[0].action = \"%s\";\n" "        document.forms[0].submit();\n" "      }\n" "    </script>\n", method, oidc_util_javascript_escape(r->pool, original_url));
























	const char *body = "    <p>Restoring...</p>\n" "    <form method=\"post\"></form>\n";

	return oidc_util_html_send(r, "Restoring...", script, method, body, OK);
}

typedef struct oidc_state_cookies_t {
	char *name;
	apr_time_t timestamp;
	struct oidc_state_cookies_t *next;
} oidc_state_cookies_t;

static int oidc_delete_oldest_state_cookies(request_rec *r, int number_of_valid_state_cookies, int max_number_of_state_cookies, oidc_state_cookies_t *first) {

	oidc_state_cookies_t *cur = NULL, *prev = NULL, *prev_oldest = NULL, *oldest = NULL;
	while (number_of_valid_state_cookies >= max_number_of_state_cookies) {
		oldest = first;
		prev_oldest = NULL;
		prev = first;
		cur = first->next;
		while (cur) {
			if ((cur->timestamp < oldest->timestamp)) {
				oldest = cur;
				prev_oldest = prev;
			}
			prev = cur;
			cur = cur->next;
		}
		oidc_warn(r, "deleting oldest state cookie: %s (time until expiry %" APR_TIME_T_FMT " seconds)", oldest->name, apr_time_sec(oldest->timestamp - apr_time_now()));

		oidc_util_set_cookie(r, oldest->name, "", 0, OIDC_COOKIE_EXT_SAME_SITE_NONE(r));
		if (prev_oldest)
			prev_oldest->next = oldest->next;
		else first = first->next;
		number_of_valid_state_cookies--;
	}
	return number_of_valid_state_cookies;
}


static int oidc_clean_expired_state_cookies(request_rec *r, oidc_cfg *c, const char *currentCookieName, int delete_oldest) {
	int number_of_valid_state_cookies = 0;
	oidc_state_cookies_t *first = NULL, *last = NULL;
	char *cookie, *tokenizerCtx = NULL;
	char *cookies = apr_pstrdup(r->pool, oidc_util_hdr_in_cookie_get(r));
	if (cookies != NULL) {
		cookie = apr_strtok(cookies, OIDC_STR_SEMI_COLON, &tokenizerCtx);
		while (cookie != NULL) {
			while (*cookie == OIDC_CHAR_SPACE)
				cookie++;
			if (strstr(cookie, oidc_cfg_dir_state_cookie_prefix(r)) == cookie) {
				char *cookieName = cookie;
				while (cookie != NULL && *cookie != OIDC_CHAR_EQUAL)
					cookie++;
				if (*cookie == OIDC_CHAR_EQUAL) {
					*cookie = '\0';
					cookie++;
					if ((currentCookieName == NULL)
							|| (apr_strnatcmp(cookieName, currentCookieName)
									!= 0)) {
						oidc_proto_state_t *proto_state = oidc_proto_state_from_cookie(r, c, cookie);
						if (proto_state != NULL) {
							json_int_t ts = oidc_proto_state_get_timestamp( proto_state);
							if (apr_time_now() > ts + apr_time_from_sec(c->state_timeout)) {
								oidc_warn(r, "state (%s) has expired (original_url=%s)", cookieName, oidc_proto_state_get_original_url( proto_state));



								oidc_util_set_cookie(r, cookieName, "", 0, OIDC_COOKIE_EXT_SAME_SITE_NONE(r));
							} else {
								if (first == NULL) {
									first = apr_pcalloc(r->pool, sizeof(oidc_state_cookies_t));
									last = first;
								} else {
									last->next = apr_pcalloc(r->pool, sizeof(oidc_state_cookies_t));
									last = last->next;
								}
								last->name = cookieName;
								last->timestamp = ts;
								last->next = NULL;
								number_of_valid_state_cookies++;
							}
							oidc_proto_state_destroy(proto_state);
						} else {
							oidc_warn(r, "state cookie could not be retrieved/decoded, deleting: %s", cookieName);

							oidc_util_set_cookie(r, cookieName, "", 0, OIDC_COOKIE_EXT_SAME_SITE_NONE(r));
						}
					}
				}
			}
			cookie = apr_strtok(NULL, OIDC_STR_SEMI_COLON, &tokenizerCtx);
		}
	}

	if (delete_oldest > 0)
		number_of_valid_state_cookies = oidc_delete_oldest_state_cookies(r, number_of_valid_state_cookies, c->max_number_of_state_cookies, first);


	return number_of_valid_state_cookies;
}


static apr_byte_t oidc_restore_proto_state(request_rec *r, oidc_cfg *c, const char *state, oidc_proto_state_t **proto_state) {

	oidc_debug(r, "enter");

	const char *cookieName = oidc_get_state_cookie_name(r, state);

	
	oidc_clean_expired_state_cookies(r, c, cookieName, FALSE);

	
	char *cookieValue = oidc_util_get_cookie(r, cookieName);
	if (cookieValue == NULL) {
		oidc_error(r, "no \"%s\" state cookie found: check domain and samesite cookie settings", cookieName);

		return FALSE;
	}

	
	oidc_util_set_cookie(r, cookieName, "", 0, OIDC_COOKIE_EXT_SAME_SITE_NONE(r));

	*proto_state = oidc_proto_state_from_cookie(r, c, cookieValue);
	if (*proto_state == NULL)
		return FALSE;

	const char *nonce = oidc_proto_state_get_nonce(*proto_state);

	
	char *calc = oidc_get_browser_state_hash(r, c, nonce);
	
	if (apr_strnatcmp(calc, state) != 0) {
		oidc_error(r, "calculated state from cookie does not match state parameter passed back in URL: \"%s\" != \"%s\"", state, calc);

		oidc_proto_state_destroy(*proto_state);
		return FALSE;
	}

	apr_time_t ts = oidc_proto_state_get_timestamp(*proto_state);

	
	if (apr_time_now() > ts + apr_time_from_sec(c->state_timeout)) {
		oidc_error(r, "state has expired");
		if ((c->default_sso_url == NULL)
				|| (apr_table_get(r->subprocess_env, "OIDC_NO_DEFAULT_URL_ON_STATE_TIMEOUT") != NULL)) {
			oidc_util_html_send_error(r, c->error_template, "Invalid Authentication Response", apr_psprintf(r->pool, "This is due to a timeout; please restart your authentication session by re-entering the URL/bookmark you originally wanted to access: %s", oidc_proto_state_get_original_url(*proto_state)), OK);
			
			r->header_only = 1;
		}
		oidc_proto_state_destroy(*proto_state);
		return FALSE;
	}

	
	oidc_proto_state_set_state(*proto_state, state);

	
	oidc_debug(r, "restored state: %s", oidc_proto_state_to_string(r, *proto_state));

	
	return TRUE;
}


static int oidc_authorization_request_set_cookie(request_rec *r, oidc_cfg *c, const char *state, oidc_proto_state_t *proto_state) {
	
	char *cookieValue = oidc_proto_state_to_cookie(r, c, proto_state);
	if (cookieValue == NULL)
		return HTTP_INTERNAL_SERVER_ERROR;

	
	int number_of_cookies = oidc_clean_expired_state_cookies(r, c, NULL, oidc_cfg_delete_oldest_state_cookies(c));
	int max_number_of_cookies = oidc_cfg_max_number_of_state_cookies(c);
	if ((max_number_of_cookies > 0)
			&& (number_of_cookies >= max_number_of_cookies)) {

		oidc_warn(r, "the number of existing, valid state cookies (%d) has exceeded the limit (%d), no additional authorization request + state cookie can be generated, aborting the request", number_of_cookies, max_number_of_cookies);

		

		

		return HTTP_SERVICE_UNAVAILABLE;
	}

	
	const char *cookieName = oidc_get_state_cookie_name(r, state);

	
	oidc_util_set_cookie(r, cookieName, cookieValue, -1, OIDC_COOKIE_SAMESITE_LAX(c, r));

	return OK;
}


static apr_table_t* oidc_request_state(request_rec *rr) {

	
	request_rec *r = (rr->main != NULL) ? rr->main : rr;

	
	apr_table_t *state = NULL;
	apr_pool_userdata_get((void**) &state, OIDC_USERDATA_KEY, r->pool);

	
	if (state == NULL) {
		state = apr_table_make(r->pool, 5);
		apr_pool_userdata_set(state, OIDC_USERDATA_KEY, NULL, r->pool);
	}

	
	return state;
}


void oidc_request_state_set(request_rec *r, const char *key, const char *value) {

	
	apr_table_t *state = oidc_request_state(r);

	
	apr_table_set(state, key, value);
}


const char* oidc_request_state_get(request_rec *r, const char *key) {

	
	apr_table_t *state = oidc_request_state(r);

	
	return apr_table_get(state, key);
}


static apr_byte_t oidc_set_app_claims(request_rec *r, const oidc_cfg *const cfg, oidc_session_t *session, const char *s_claims) {

	json_t *j_claims = NULL;

	
	if (s_claims != NULL) {
		if (oidc_util_decode_json_object(r, s_claims, &j_claims) == FALSE)
			return FALSE;
	}

	
	if (j_claims != NULL) {
		oidc_util_set_app_infos(r, j_claims, oidc_cfg_claim_prefix(r), cfg->claim_delimiter, oidc_cfg_dir_pass_info_in_headers(r), oidc_cfg_dir_pass_info_in_envvars(r), oidc_cfg_dir_pass_info_base64url(r));



		
		json_decref(j_claims);
	}

	return TRUE;
}

static int oidc_authenticate_user(request_rec *r, oidc_cfg *c, oidc_provider_t *provider, const char *original_url, const char *login_hint, const char *id_token_hint, const char *prompt, const char *auth_request_params, const char *path_scope);




static void oidc_log_session_expires(request_rec *r, const char *msg, apr_time_t session_expires) {
	char buf[APR_RFC822_DATE_LEN + 1];
	apr_rfc822_date(buf, session_expires);
	oidc_debug(r, "%s: %s (in %" APR_TIME_T_FMT " secs from now)", msg, buf, apr_time_sec(session_expires - apr_time_now()));
}


static apr_byte_t oidc_is_xml_http_request(request_rec *r) {

	if ((oidc_util_hdr_in_x_requested_with_get(r) != NULL)
			&& (apr_strnatcasecmp(oidc_util_hdr_in_x_requested_with_get(r), OIDC_HTTP_HDR_VAL_XML_HTTP_REQUEST) == 0))
		return TRUE;

	if ((oidc_util_hdr_in_accept_contains(r, OIDC_CONTENT_TYPE_TEXT_HTML)
			== FALSE) && (oidc_util_hdr_in_accept_contains(r, OIDC_CONTENT_TYPE_APP_XHTML_XML) == FALSE)
					&& (oidc_util_hdr_in_accept_contains(r, OIDC_CONTENT_TYPE_ANY) == FALSE))
		return TRUE;

	return FALSE;
}


static int oidc_handle_unauthenticated_user(request_rec *r, oidc_cfg *c) {

	
	switch (oidc_dir_cfg_unauth_action(r)) {
	case OIDC_UNAUTH_RETURN410:
		return HTTP_GONE;
	case OIDC_UNAUTH_RETURN407:
		return HTTP_PROXY_AUTHENTICATION_REQUIRED;
	case OIDC_UNAUTH_RETURN401:
		return HTTP_UNAUTHORIZED;
	case OIDC_UNAUTH_PASS:
		r->user = "";

		
		oidc_scrub_headers(r);

		return OK;

	case OIDC_UNAUTH_AUTHENTICATE:

		
		if ((oidc_dir_cfg_unauth_expr_is_set(r) == FALSE)
				&& (oidc_is_xml_http_request(r) == TRUE))
			return HTTP_UNAUTHORIZED;
	}

	
	return oidc_authenticate_user(r, c, NULL, oidc_get_current_url(r), NULL, NULL, NULL, oidc_dir_cfg_path_auth_request_params(r), oidc_dir_cfg_path_scope(r));

}


static int oidc_check_max_session_duration(request_rec *r, oidc_cfg *cfg, oidc_session_t *session) {

	
	apr_time_t session_expires = oidc_session_get_session_expires(r, session);

	
	if (apr_time_now() > session_expires) {
		oidc_warn(r, "maximum session duration exceeded for user: %s", session->remote_user);
		oidc_session_kill(r, session);
		return oidc_handle_unauthenticated_user(r, cfg);
	}

	
	oidc_log_session_expires(r, "session max lifetime", session_expires);

	return OK;
}


static apr_byte_t oidc_check_cookie_domain(request_rec *r, oidc_cfg *cfg, oidc_session_t *session) {
	const char *c_cookie_domain = cfg->cookie_domain ? cfg->cookie_domain : oidc_get_current_url_host(r);

	const char *s_cookie_domain = oidc_session_get_cookie_domain(r, session);
	if ((s_cookie_domain == NULL)
			|| (apr_strnatcmp(c_cookie_domain, s_cookie_domain) != 0)) {
		oidc_warn(r, "aborting: detected attempt to play cookie against a different domain/host than issued for! (issued=%s, current=%s)", s_cookie_domain, c_cookie_domain);

		return FALSE;
	}

	return TRUE;
}


apr_byte_t oidc_get_provider_from_session(request_rec *r, oidc_cfg *c, oidc_session_t *session, oidc_provider_t **provider) {

	oidc_debug(r, "enter");

	
	const char *issuer = oidc_session_get_issuer(r, session);
	if (issuer == NULL) {
		oidc_warn(r, "empty or invalid session: no issuer found");
		return FALSE;
	}

	
	oidc_provider_t *p = oidc_get_provider_for_issuer(r, c, issuer, FALSE);
	if (p == NULL) {
		oidc_error(r, "session corrupted: no provider found for issuer: %s", issuer);
		return FALSE;
	}

	*provider = p;

	return TRUE;
}


static void oidc_store_userinfo_claims(request_rec *r, oidc_cfg *c, oidc_session_t *session, oidc_provider_t *provider, const char *claims, const char *userinfo_jwt) {


	oidc_debug(r, "enter");

	
	if (claims != NULL) {
		
		oidc_session_set_userinfo_claims(r, session, claims);

		if (c->session_type != OIDC_SESSION_TYPE_CLIENT_COOKIE) {
			
			oidc_session_set_userinfo_jwt(r, session, userinfo_jwt);
		}

	} else {
		
		oidc_session_set_userinfo_claims(r, session, NULL);

		oidc_session_set_userinfo_jwt(r, session, NULL);
	}

	
	if (provider->userinfo_refresh_interval > 0)
		oidc_session_reset_userinfo_last_refresh(r, session);
}


static apr_byte_t oidc_refresh_access_token(request_rec *r, oidc_cfg *c, oidc_session_t *session, oidc_provider_t *provider, char **new_access_token) {


	oidc_debug(r, "enter");

	
	const char *refresh_token = oidc_session_get_refresh_token(r, session);
	if (refresh_token == NULL) {
		oidc_warn(r, "refresh token routine called but no refresh_token found in the session");
		return FALSE;
	}

	
	char *s_id_token = NULL;
	int expires_in = -1;
	char *s_token_type = NULL;
	char *s_access_token = NULL;
	char *s_refresh_token = NULL;

	
	if (oidc_proto_refresh_request(r, c, provider, refresh_token, &s_id_token, &s_access_token, &s_token_type, &expires_in, &s_refresh_token)
			== FALSE) {
		oidc_error(r, "access_token could not be refreshed");
		return FALSE;
	}

	
	oidc_session_set_access_token(r, session, s_access_token);
	oidc_session_set_access_token_expires(r, session, expires_in);

	
	oidc_session_reset_access_token_last_refresh(r, session);

	
	if (new_access_token != NULL)
		*new_access_token = s_access_token;

	
	if (s_refresh_token != NULL)
		oidc_session_set_refresh_token(r, session, s_refresh_token);

	
	if (s_id_token != NULL) {
		
		if (c->session_type != OIDC_SESSION_TYPE_CLIENT_COOKIE) 
			oidc_session_set_idtoken(r, session, s_id_token);
		
		oidc_jwt_t *id_token_jwt = NULL;
		oidc_jose_error_t err;
		if (oidc_jwt_parse(r->pool, s_id_token, &id_token_jwt, NULL, &err) == TRUE) {

			
			oidc_session_set_idtoken_claims(r, session, id_token_jwt->payload.value.str);

			if (provider->session_max_duration == 0) {
				
				apr_time_t session_expires = apr_time_from_sec(id_token_jwt->payload.exp);
				oidc_session_set_session_expires(r, session, session_expires);

				
				oidc_log_session_expires(r, "session max lifetime", session_expires);
			}		
		} else { 
			oidc_warn(r, "parsing of id_token failed");
		}
	}

	return TRUE;
}


static const char* oidc_retrieve_claims_from_userinfo_endpoint(request_rec *r, oidc_cfg *c, oidc_provider_t *provider, const char *access_token, oidc_session_t *session, char *id_token_sub, char **userinfo_jwt) {


	oidc_debug(r, "enter");

	char *result = NULL;
	char *refreshed_access_token = NULL;

	
	if (provider->userinfo_endpoint_url == NULL) {
		oidc_debug(r, "not retrieving userinfo claims because userinfo_endpoint is not set");
		return NULL;
	}

	
	if (access_token == NULL) {
		oidc_debug(r, "not retrieving userinfo claims because access_token is not provided");
		return NULL;
	}

	if ((id_token_sub == NULL) && (session != NULL)) {

		
		json_t *id_token_claims = oidc_session_get_idtoken_claims_json(r, session);
		if (id_token_claims == NULL) {
			oidc_error(r, "no id_token_claims found in session");
			return NULL;
		}

		oidc_jose_get_string(r->pool, id_token_claims, OIDC_CLAIM_SUB, FALSE, &id_token_sub, NULL);
	}

	
	

	
	if (oidc_proto_resolve_userinfo(r, c, provider, id_token_sub, access_token, &result, userinfo_jwt) == FALSE) {

		
		if (session != NULL) {

			
			if (oidc_refresh_access_token(r, c, session, provider, &refreshed_access_token) == TRUE) {

				
				if (oidc_proto_resolve_userinfo(r, c, provider, id_token_sub, refreshed_access_token, &result, userinfo_jwt)
						== FALSE) {

					oidc_error(r, "resolving user info claims with the refreshed access token failed, nothing will be stored in the session");
					result = NULL;

				}

			} else {

				oidc_warn(r, "refreshing access token failed, claims will not be retrieved/refreshed from the userinfo endpoint");
				result = NULL;

			}

		} else {

			oidc_error(r, "resolving user info claims with the existing/provided access token failed, nothing will be stored in the session");
			result = NULL;

		}
	}

	return result;
}


static apr_byte_t oidc_refresh_claims_from_userinfo_endpoint(request_rec *r, oidc_cfg *cfg, oidc_session_t *session) {

	oidc_provider_t *provider = NULL;
	const char *claims = NULL;
	const char *access_token = NULL;
	char *userinfo_jwt = NULL;

	
	if (oidc_get_provider_from_session(r, cfg, session, &provider) == FALSE)
		return FALSE;

	
	apr_time_t interval = apr_time_from_sec( provider->userinfo_refresh_interval);

	oidc_debug(r, "userinfo_endpoint=%s, interval=%d", provider->userinfo_endpoint_url, provider->userinfo_refresh_interval);


	if ((provider->userinfo_endpoint_url != NULL) && (interval > 0)) {

		
		apr_time_t last_refresh = oidc_session_get_userinfo_last_refresh(r, session);

		oidc_debug(r, "refresh needed in: %" APR_TIME_T_FMT " seconds", apr_time_sec(last_refresh + interval - apr_time_now()));

		
		if (last_refresh + interval < apr_time_now()) {

			
			access_token = oidc_session_get_access_token(r, session);

			
			claims = oidc_retrieve_claims_from_userinfo_endpoint(r, cfg, provider, access_token, session, NULL, &userinfo_jwt);

			
			oidc_store_userinfo_claims(r, cfg, session, provider, claims, userinfo_jwt);

			
			return TRUE;
		}
	}
	return FALSE;
}


static void oidc_copy_tokens_to_request_state(request_rec *r, oidc_session_t *session, const char **s_id_token, const char **s_claims) {

	const char *id_token = oidc_session_get_idtoken_claims(r, session);
	const char *claims = oidc_session_get_userinfo_claims(r, session);

	oidc_debug(r, "id_token=%s claims=%s", id_token, claims);

	if (id_token != NULL) {
		oidc_request_state_set(r, OIDC_REQUEST_STATE_KEY_IDTOKEN, id_token);
		if (s_id_token != NULL)
			*s_id_token = id_token;
	}

	if (claims != NULL) {
		oidc_request_state_set(r, OIDC_REQUEST_STATE_KEY_CLAIMS, claims);
		if (s_claims != NULL)
			*s_claims = claims;
	}
}


static apr_byte_t oidc_session_pass_tokens(request_rec *r, oidc_cfg *cfg, oidc_session_t *session, apr_byte_t *needs_save) {

	apr_byte_t pass_headers = oidc_cfg_dir_pass_info_in_headers(r);
	apr_byte_t pass_envvars = oidc_cfg_dir_pass_info_in_envvars(r);
	apr_byte_t pass_base64url = oidc_cfg_dir_pass_info_base64url(r);

	
	const char *refresh_token = oidc_session_get_refresh_token(r, session);
	if ((oidc_cfg_dir_pass_refresh_token(r) != 0) && (refresh_token != NULL)) {
		
		oidc_util_set_app_info(r, OIDC_APP_INFO_REFRESH_TOKEN, refresh_token, OIDC_DEFAULT_HEADER_PREFIX, pass_headers, pass_envvars, pass_base64url);
	}

	
	const char *access_token = oidc_session_get_access_token(r, session);
	if (access_token != NULL) {
		
		oidc_util_set_app_info(r, OIDC_APP_INFO_ACCESS_TOKEN, access_token, OIDC_DEFAULT_HEADER_PREFIX, pass_headers, pass_envvars, pass_base64url);
	}

	
	const char *access_token_expires = oidc_session_get_access_token_expires(r, session);
	if (access_token_expires != NULL) {
		
		oidc_util_set_app_info(r, OIDC_APP_INFO_ACCESS_TOKEN_EXP, access_token_expires, OIDC_DEFAULT_HEADER_PREFIX, pass_headers, pass_envvars, pass_base64url);


	}

	
	apr_time_t interval = apr_time_from_sec(cfg->session_inactivity_timeout);
	apr_time_t now = apr_time_now();
	apr_time_t slack = interval / 10;
	if (slack > apr_time_from_sec(60))
		slack = apr_time_from_sec(60);
	if (session->expiry - now < interval - slack) {
		session->expiry = now + interval;
		*needs_save = TRUE;
	}

	
	oidc_log_session_expires(r, "session inactivity timeout", session->expiry);

	return TRUE;
}

static apr_byte_t oidc_refresh_access_token_before_expiry(request_rec *r, oidc_cfg *cfg, oidc_session_t *session, int ttl_minimum, int logout_on_error) {


	const char *s_access_token_expires = NULL;
	apr_time_t t_expires = -1;
	oidc_provider_t *provider = NULL;

	oidc_debug(r, "ttl_minimum=%d", ttl_minimum);

	if (ttl_minimum < 0)
		return FALSE;

	s_access_token_expires = oidc_session_get_access_token_expires(r, session);
	if (s_access_token_expires == NULL) {
		oidc_debug(r, "no access token expires_in stored in the session (i.e. returned from in the authorization response), so cannot refresh the access token based on TTL requirement");
		return FALSE;
	}

	if (oidc_session_get_refresh_token(r, session) == NULL) {
		oidc_debug(r, "no refresh token stored in the session, so cannot refresh the access token based on TTL requirement");
		return FALSE;
	}

	if (sscanf(s_access_token_expires, "%" APR_TIME_T_FMT, &t_expires) != 1) {
		oidc_error(r, "could not parse s_access_token_expires %s", s_access_token_expires);
		return FALSE;
	}

	t_expires = apr_time_from_sec(t_expires - ttl_minimum);

	oidc_debug(r, "refresh needed in: %" APR_TIME_T_FMT " seconds", apr_time_sec(t_expires - apr_time_now()));

	if (t_expires > apr_time_now())
		return FALSE;

	if (oidc_get_provider_from_session(r, cfg, session, &provider) == FALSE)
		return FALSE;

	if (oidc_refresh_access_token(r, cfg, session, provider, NULL) == FALSE) {
		oidc_warn(r, "access_token could not be refreshed, logout=%d", logout_on_error & OIDC_LOGOUT_ON_ERROR_REFRESH);
		if (logout_on_error & OIDC_LOGOUT_ON_ERROR_REFRESH)
			return OIDC_REFRESH_ERROR;
		else return FALSE;
	}

	return TRUE;
}


static int oidc_handle_existing_session(request_rec *r, oidc_cfg *cfg, oidc_session_t *session, apr_byte_t *needs_save) {

	apr_byte_t rv = FALSE;

	oidc_debug(r, "enter");

	
	r->user = apr_pstrdup(r->pool, session->remote_user);
	oidc_debug(r, "set remote_user to \"%s\"", r->user);

	
	char *authn_header = oidc_cfg_dir_authn_header(r);
	apr_byte_t pass_headers = oidc_cfg_dir_pass_info_in_headers(r);
	apr_byte_t pass_envvars = oidc_cfg_dir_pass_info_in_envvars(r);
	apr_byte_t pass_base64url = oidc_cfg_dir_pass_info_base64url(r);

	
	if (oidc_check_cookie_domain(r, cfg, session) == FALSE)
		return HTTP_UNAUTHORIZED;

	
	int rc = oidc_check_max_session_duration(r, cfg, session);
	if (rc != OK)
		return rc;

	
	rv = oidc_refresh_access_token_before_expiry(r, cfg, session, oidc_cfg_dir_refresh_access_token_before_expiry(r), oidc_cfg_dir_logout_on_error_refresh(r));


	if (rv == OIDC_REFRESH_ERROR) {
		*needs_save = FALSE;
		return oidc_handle_logout_request(r, cfg, session, cfg->default_slo_url);
	}

	*needs_save |= rv;

	
	if (oidc_refresh_claims_from_userinfo_endpoint(r, cfg, session) == TRUE)
		*needs_save = TRUE;

	
	oidc_scrub_headers(r);

	
	if ((r->user != NULL) && (authn_header != NULL))
		oidc_util_hdr_in_set(r, authn_header, r->user);

	const char *s_claims = NULL;
	const char *s_id_token = NULL;

	
	oidc_copy_tokens_to_request_state(r, session, &s_id_token, &s_claims);

	if ((cfg->pass_userinfo_as & OIDC_PASS_USERINFO_AS_CLAIMS)) {
		
		if (oidc_set_app_claims(r, cfg, session, s_claims) == FALSE)
			return HTTP_INTERNAL_SERVER_ERROR;
	}

	if ((cfg->pass_userinfo_as & OIDC_PASS_USERINFO_AS_JSON_OBJECT)) {
		
		oidc_util_set_app_info(r, OIDC_APP_INFO_USERINFO_JSON, s_claims, OIDC_DEFAULT_HEADER_PREFIX, pass_headers, pass_envvars, pass_base64url);
	}

	if ((cfg->pass_userinfo_as & OIDC_PASS_USERINFO_AS_JWT)) {
		if (cfg->session_type != OIDC_SESSION_TYPE_CLIENT_COOKIE) {
			
			const char *s_userinfo_jwt = oidc_session_get_userinfo_jwt(r, session);
			if (s_userinfo_jwt != NULL) {
				
				oidc_util_set_app_info(r, OIDC_APP_INFO_USERINFO_JWT, s_userinfo_jwt, OIDC_DEFAULT_HEADER_PREFIX, pass_headers, pass_envvars, pass_base64url);


			} else {
				oidc_debug(r, "configured to pass userinfo in a JWT, but no such JWT was found in the session (probably no such JWT was returned from the userinfo endpoint)");
			}
		} else {
			oidc_error(r, "session type \"client-cookie\" does not allow storing/passing a userinfo JWT; use \"" OIDCSessionType " server-cache\" for that");
		}
	}

	if ((cfg->pass_idtoken_as & OIDC_PASS_IDTOKEN_AS_CLAIMS)) {
		
		if (oidc_set_app_claims(r, cfg, session, s_id_token) == FALSE)
			return HTTP_INTERNAL_SERVER_ERROR;
	}

	if ((cfg->pass_idtoken_as & OIDC_PASS_IDTOKEN_AS_PAYLOAD)) {
		
		oidc_util_set_app_info(r, OIDC_APP_INFO_ID_TOKEN_PAYLOAD, s_id_token, OIDC_DEFAULT_HEADER_PREFIX, pass_headers, pass_envvars, pass_base64url);
	}

	if ((cfg->pass_idtoken_as & OIDC_PASS_IDTOKEN_AS_SERIALIZED)) {
		if (cfg->session_type != OIDC_SESSION_TYPE_CLIENT_COOKIE) {
			
			const char *s_id_token = oidc_session_get_idtoken(r, session);
			
			oidc_util_set_app_info(r, OIDC_APP_INFO_ID_TOKEN, s_id_token, OIDC_DEFAULT_HEADER_PREFIX, pass_headers, pass_envvars, pass_base64url);

		} else {
			oidc_error(r, "session type \"client-cookie\" does not allow storing/passing the id_token; use \"" OIDCSessionType " server-cache\" for that");
		}
	}

	
	if (oidc_session_pass_tokens(r, cfg, session, needs_save) == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

	
	return OK;
}


static apr_byte_t oidc_authorization_response_match_state(request_rec *r, oidc_cfg *c, const char *state, struct oidc_provider_t **provider, oidc_proto_state_t **proto_state) {


	oidc_debug(r, "enter (state=%s)", state);

	if ((state == NULL) || (apr_strnatcmp(state, "") == 0)) {
		oidc_error(r, "state parameter is not set");
		return FALSE;
	}

	
	if (oidc_restore_proto_state(r, c, state, proto_state) == FALSE) {
		oidc_error(r, "unable to restore state");
		return FALSE;
	}

	*provider = oidc_get_provider_for_issuer(r, c, oidc_proto_state_get_issuer(*proto_state), FALSE);

	if (*provider == NULL) {
		oidc_proto_state_destroy(*proto_state);
		*proto_state = NULL;
		return FALSE;
	}

	return TRUE;
}


static int oidc_session_redirect_parent_window_to_logout(request_rec *r, oidc_cfg *c) {

	oidc_debug(r, "enter");

	char *java_script = apr_psprintf(r->pool, "    <script type=\"text/javascript\">\n" "      window.top.location.href = '%s?session=logout';\n" "    </script>\n", oidc_util_javascript_escape(r->pool, oidc_get_redirect_uri(r, c)));



	return oidc_util_html_send(r, "Redirecting...", java_script, NULL, NULL, OK);
}


static int oidc_authorization_response_error(request_rec *r, oidc_cfg *c, oidc_proto_state_t *proto_state, const char *error, const char *error_description) {

	const char *prompt = oidc_proto_state_get_prompt(proto_state);
	if (prompt != NULL)
		prompt = apr_pstrdup(r->pool, prompt);
	oidc_proto_state_destroy(proto_state);
	if ((prompt != NULL)
			&& (apr_strnatcmp(prompt, OIDC_PROTO_PROMPT_NONE) == 0)) {
		return oidc_session_redirect_parent_window_to_logout(r, c);
	}
	return oidc_util_html_send_error(r, c->error_template, apr_psprintf(r->pool, "OpenID Connect Provider error: %s", error), error_description, OK);

}


apr_byte_t oidc_get_remote_user(request_rec *r, const char *claim_name, const char *reg_exp, const char *replace, json_t *json, char **request_user) {


	
	json_t *username = json_object_get(json, claim_name);
	if ((username == NULL) || (!json_is_string(username))) {
		oidc_warn(r, "JSON object did not contain a \"%s\" string", claim_name);
		return FALSE;
	}

	*request_user = apr_pstrdup(r->pool, json_string_value(username));

	if (reg_exp != NULL) {

		char *error_str = NULL;

		if (replace == NULL) {

			if (oidc_util_regexp_first_match(r->pool, *request_user, reg_exp, request_user, &error_str) == FALSE) {
				oidc_error(r, "oidc_util_regexp_first_match failed: %s", error_str);
				*request_user = NULL;
				return FALSE;
			}

		} else if (oidc_util_regexp_substitute(r->pool, *request_user, reg_exp, replace, request_user, &error_str) == FALSE) {

			oidc_error(r, "oidc_util_regexp_substitute failed: %s", error_str);
			*request_user = NULL;
			return FALSE;
		}

	}

	return TRUE;
}


static apr_byte_t oidc_set_request_user(request_rec *r, oidc_cfg *c, oidc_provider_t *provider, oidc_jwt_t *jwt, const char *s_claims) {

	char *issuer = provider->issuer;
	char *claim_name = apr_pstrdup(r->pool, c->remote_user_claim.claim_name);
	int n = strlen(claim_name);
	apr_byte_t post_fix_with_issuer = (claim_name[n - 1] == OIDC_CHAR_AT);
	if (post_fix_with_issuer == TRUE) {
		claim_name[n - 1] = '\0';
		issuer = (strstr(issuer, "https://") == NULL) ? apr_pstrdup(r->pool, issuer) :

						apr_pstrdup(r->pool, issuer + strlen("https://"));
	}

	
	apr_byte_t rc = FALSE;
	char *remote_user = NULL;
	json_t *claims = NULL;
	oidc_util_decode_json_object(r, s_claims, &claims);
	if (claims == NULL) {
		rc = oidc_get_remote_user(r, claim_name, c->remote_user_claim.reg_exp, c->remote_user_claim.replace, jwt->payload.value.json, &remote_user);

	} else {
		oidc_util_json_merge(r, jwt->payload.value.json, claims);
		rc = oidc_get_remote_user(r, claim_name, c->remote_user_claim.reg_exp, c->remote_user_claim.replace, claims, &remote_user);
		json_decref(claims);
	}

	if ((rc == FALSE) || (remote_user == NULL)) {
		oidc_error(r, "" OIDCRemoteUserClaim "is set to \"%s\", but could not set the remote user based on the requested claim \"%s\" and the available claims for the user", c->remote_user_claim.claim_name, claim_name);

		return FALSE;
	}

	if (post_fix_with_issuer == TRUE)
		remote_user = apr_psprintf(r->pool, "%s%s%s", remote_user, OIDC_STR_AT, issuer);

	r->user = apr_pstrdup(r->pool, remote_user);

	oidc_debug(r, "set remote_user to \"%s\" based on claim: \"%s\"%s", r->user, c->remote_user_claim.claim_name, c->remote_user_claim.reg_exp ? apr_psprintf(r->pool, " and expression: \"%s\" and replace string: \"%s\"", c->remote_user_claim.reg_exp, c->remote_user_claim.replace) :





							"");

	return TRUE;
}

static char* oidc_make_sid_iss_unique(request_rec *r, const char *sid, const char *issuer) {
	return apr_psprintf(r->pool, "%s@%s", sid, issuer);
}


static apr_byte_t oidc_save_in_session(request_rec *r, oidc_cfg *c, oidc_session_t *session, oidc_provider_t *provider, const char *remoteUser, const char *id_token, oidc_jwt_t *id_token_jwt, const char *claims, const char *access_token, const int expires_in, const char *refresh_token, const char *session_state, const char *state, const char *original_url, const char *userinfo_jwt) {





	
	session->remote_user = remoteUser;

	
	session->expiry = apr_time_now() + apr_time_from_sec(c->session_inactivity_timeout);

	
	oidc_session_set_idtoken_claims(r, session, id_token_jwt->payload.value.str);

	if (c->session_type != OIDC_SESSION_TYPE_CLIENT_COOKIE) {
		
		oidc_session_set_idtoken(r, session, id_token);
	}

	
	oidc_session_set_issuer(r, session, provider->issuer);

	
	oidc_session_set_request_state(r, session, state);
	oidc_session_set_original_url(r, session, original_url);

	if ((session_state != NULL) && (provider->check_session_iframe != NULL)) {
		
		oidc_session_set_session_state(r, session, session_state);
		oidc_debug(r, "session management enabled: stored session_state (%s), check_session_iframe (%s) and client_id (%s) in the session", session_state, provider->check_session_iframe, provider->client_id);


	} else if (provider->check_session_iframe == NULL) {
		oidc_debug(r, "session management disabled: \"check_session_iframe\" is not set in provider configuration");
	} else {
		oidc_debug(r, "session management disabled: no \"session_state\" value is provided in the authentication response even though \"check_session_iframe\" (%s) is set in the provider configuration", provider->check_session_iframe);

	}

	
	oidc_store_userinfo_claims(r, c, session, provider, claims, userinfo_jwt);

	
	if (access_token != NULL) {
		
		oidc_session_set_access_token(r, session, access_token);
		
		oidc_session_set_access_token_expires(r, session, expires_in);
		
		oidc_session_reset_access_token_last_refresh(r, session);
	}

	
	if (refresh_token != NULL) {
		
		oidc_session_set_refresh_token(r, session, refresh_token);
	}

	
	apr_time_t session_expires = (provider->session_max_duration == 0) ? apr_time_from_sec(id_token_jwt->payload.exp) :

					(apr_time_now()
							+ apr_time_from_sec(provider->session_max_duration));
	oidc_session_set_session_expires(r, session, session_expires);

	oidc_debug(r, "provider->session_max_duration = %d, session_expires=%" APR_TIME_T_FMT, provider->session_max_duration, session_expires);


	
	oidc_log_session_expires(r, "session max lifetime", session_expires);

	
	oidc_session_set_cookie_domain(r, session, c->cookie_domain ? c->cookie_domain : oidc_get_current_url_host(r));

	char *sid = NULL;
	oidc_debug(r, "provider->backchannel_logout_supported=%d", provider->backchannel_logout_supported);
	if (provider->backchannel_logout_supported > 0) {
		oidc_jose_get_string(r->pool, id_token_jwt->payload.value.json, OIDC_CLAIM_SID, FALSE, &sid, NULL);
		if (sid == NULL)
			sid = id_token_jwt->payload.sub;
		session->sid = oidc_make_sid_iss_unique(r, sid, provider->issuer);
	}

	
	return oidc_session_save(r, session, TRUE);
}


static int oidc_parse_expires_in(request_rec *r, const char *expires_in) {
	if (expires_in != NULL) {
		char *ptr = NULL;
		long number = strtol(expires_in, &ptr, 10);
		if (number <= 0) {
			oidc_warn(r, "could not convert \"expires_in\" value (%s) to a number", expires_in);

			return -1;
		}
		return number;
	}
	return -1;
}


static apr_byte_t oidc_handle_flows(request_rec *r, oidc_cfg *c, oidc_proto_state_t *proto_state, oidc_provider_t *provider, apr_table_t *params, const char *response_mode, oidc_jwt_t **jwt) {


	apr_byte_t rc = FALSE;

	const char *requested_response_type = oidc_proto_state_get_response_type( proto_state);

	
	if (oidc_util_spaced_string_equals(r->pool, requested_response_type, OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN_TOKEN)) {
		rc = oidc_proto_authorization_response_code_idtoken_token(r, c, proto_state, provider, params, response_mode, jwt);
	} else if (oidc_util_spaced_string_equals(r->pool, requested_response_type, OIDC_PROTO_RESPONSE_TYPE_CODE_IDTOKEN)) {
		rc = oidc_proto_authorization_response_code_idtoken(r, c, proto_state, provider, params, response_mode, jwt);
	} else if (oidc_util_spaced_string_equals(r->pool, requested_response_type, OIDC_PROTO_RESPONSE_TYPE_CODE_TOKEN)) {
		rc = oidc_proto_handle_authorization_response_code_token(r, c, proto_state, provider, params, response_mode, jwt);
	} else if (oidc_util_spaced_string_equals(r->pool, requested_response_type, OIDC_PROTO_RESPONSE_TYPE_CODE)) {
		rc = oidc_proto_handle_authorization_response_code(r, c, proto_state, provider, params, response_mode, jwt);
	} else if (oidc_util_spaced_string_equals(r->pool, requested_response_type, OIDC_PROTO_RESPONSE_TYPE_IDTOKEN_TOKEN)) {
		rc = oidc_proto_handle_authorization_response_idtoken_token(r, c, proto_state, provider, params, response_mode, jwt);
	} else if (oidc_util_spaced_string_equals(r->pool, requested_response_type, OIDC_PROTO_RESPONSE_TYPE_IDTOKEN)) {
		rc = oidc_proto_handle_authorization_response_idtoken(r, c, proto_state, provider, params, response_mode, jwt);
	} else {
		oidc_error(r, "unsupported response type: \"%s\"", requested_response_type);
	}

	if ((rc == FALSE) && (*jwt != NULL)) {
		oidc_jwt_destroy(*jwt);
		*jwt = NULL;
	}

	return rc;
}


static apr_byte_t oidc_handle_browser_back(request_rec *r, const char *r_state, oidc_session_t *session) {

	
	const char *s_state = NULL, *o_url = NULL;

	if (session->remote_user != NULL) {

		s_state = oidc_session_get_request_state(r, session);
		o_url = oidc_session_get_original_url(r, session);

		if ((r_state != NULL) && (s_state != NULL)
				&& (apr_strnatcmp(r_state, s_state) == 0)) {

			
			oidc_warn(r, "browser back detected, redirecting to original URL: %s", o_url);


			
			oidc_util_hdr_out_location_set(r, o_url);

			return TRUE;
		}
	}

	return FALSE;
}


static int oidc_handle_authorization_response(request_rec *r, oidc_cfg *c, oidc_session_t *session, apr_table_t *params, const char *response_mode) {

	oidc_debug(r, "enter, response_mode=%s", response_mode);

	oidc_provider_t *provider = NULL;
	oidc_proto_state_t *proto_state = NULL;
	oidc_jwt_t *jwt = NULL;

	
	if (oidc_handle_browser_back(r, apr_table_get(params, OIDC_PROTO_STATE), session) == TRUE)
		return HTTP_MOVED_TEMPORARILY;

	
	if (oidc_authorization_response_match_state(r, c, apr_table_get(params, OIDC_PROTO_STATE), &provider, &proto_state)
			== FALSE) {
		if (c->default_sso_url != NULL) {
			oidc_warn(r, "invalid authorization response state; a default SSO URL is set, sending the user there: %s", c->default_sso_url);

			oidc_util_hdr_out_location_set(r, c->default_sso_url);
			
			return HTTP_MOVED_TEMPORARILY;
		}
		oidc_error(r, "invalid authorization response state and no default SSO URL is set, sending an error...");
		
		
		return ((r->user) && (strncmp(r->user, "", 1) == 0)) ? OK :
				HTTP_BAD_REQUEST;
	}

	
	if (apr_table_get(params, OIDC_PROTO_ERROR) != NULL)
		return oidc_authorization_response_error(r, c, proto_state, apr_table_get(params, OIDC_PROTO_ERROR), apr_table_get(params, OIDC_PROTO_ERROR_DESCRIPTION));


	
	if (oidc_handle_flows(r, c, proto_state, provider, params, response_mode, &jwt) == FALSE)
		return oidc_authorization_response_error(r, c, proto_state, "Error in handling response type.", NULL);

	if (jwt == NULL) {
		oidc_error(r, "no id_token was provided");
		return oidc_authorization_response_error(r, c, proto_state, "No id_token was provided.", NULL);
	}

	int expires_in = oidc_parse_expires_in(r, apr_table_get(params, OIDC_PROTO_EXPIRES_IN));
	char *userinfo_jwt = NULL;

	
	const char *claims = oidc_retrieve_claims_from_userinfo_endpoint(r, c, provider, apr_table_get(params, OIDC_PROTO_ACCESS_TOKEN), NULL, jwt->payload.sub, &userinfo_jwt);


	
	const char *original_url = oidc_proto_state_get_original_url(proto_state);
	if (original_url != NULL)
		original_url = apr_pstrdup(r->pool, original_url);
	const char *original_method = oidc_proto_state_get_original_method( proto_state);
	if (original_method != NULL)
		original_method = apr_pstrdup(r->pool, original_method);
	const char *prompt = oidc_proto_state_get_prompt(proto_state);

	
	if (oidc_set_request_user(r, c, provider, jwt, claims) == TRUE) {

		
		if ((prompt != NULL)
				&& (apr_strnatcmp(prompt, OIDC_PROTO_PROMPT_NONE) == 0)) {
			
			
			
			
			if (apr_strnatcmp(session->remote_user, r->user) != 0) {
				oidc_warn(r, "user set from new id_token is different from current one");
				oidc_jwt_destroy(jwt);
				return oidc_authorization_response_error(r, c, proto_state, "User changed!", NULL);
			}
		}

		
		if (oidc_save_in_session(r, c, session, provider, r->user, apr_table_get(params, OIDC_PROTO_ID_TOKEN), jwt, claims, apr_table_get(params, OIDC_PROTO_ACCESS_TOKEN), expires_in, apr_table_get(params, OIDC_PROTO_REFRESH_TOKEN), apr_table_get(params, OIDC_PROTO_SESSION_STATE), apr_table_get(params, OIDC_PROTO_STATE), original_url, userinfo_jwt) == FALSE) {





			oidc_proto_state_destroy(proto_state);
			oidc_jwt_destroy(jwt);
			return HTTP_INTERNAL_SERVER_ERROR;
		}

	} else {
		oidc_error(r, "remote user could not be set");
		oidc_jwt_destroy(jwt);
		return oidc_authorization_response_error(r, c, proto_state, "Remote user could not be set: contact the website administrator", NULL);

	}

	
	oidc_proto_state_destroy(proto_state);
	oidc_jwt_destroy(jwt);

	
	if (r->user == NULL)
		return HTTP_UNAUTHORIZED;

	
	oidc_debug(r, "session created and stored, returning to original URL: %s, original method: %s", original_url, original_method);


	
	if (apr_strnatcmp(original_method, OIDC_METHOD_FORM_POST) == 0) {
		return oidc_request_post_preserved_restore(r, original_url);
	}

	
	oidc_util_hdr_out_location_set(r, original_url);

	
	return HTTP_MOVED_TEMPORARILY;
}


static int oidc_handle_post_authorization_response(request_rec *r, oidc_cfg *c, oidc_session_t *session) {

	oidc_debug(r, "enter");

	
	char *response_mode = NULL;

	
	apr_table_t *params = apr_table_make(r->pool, 8);
	if (oidc_util_read_post_params(r, params, FALSE, NULL) == FALSE) {
		oidc_error(r, "something went wrong when reading the POST parameters");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	
	if ((apr_table_elts(params)->nelts < 1)
			|| ((apr_table_elts(params)->nelts == 1)
					&& apr_table_get(params, OIDC_PROTO_RESPONSE_MODE)
					&& (apr_strnatcmp( apr_table_get(params, OIDC_PROTO_RESPONSE_MODE), OIDC_PROTO_RESPONSE_MODE_FRAGMENT) == 0))) {

		return oidc_util_html_send_error(r, c->error_template, "Invalid Request", "You've hit an OpenID Connect Redirect URI with no parameters, this is an invalid request; you should not open this URL in your browser directly, or have the server administrator use a different " OIDCRedirectURI " setting.", HTTP_INTERNAL_SERVER_ERROR);


	}

	
	response_mode = (char*) apr_table_get(params, OIDC_PROTO_RESPONSE_MODE);

	
	return oidc_handle_authorization_response(r, c, session, params, response_mode ? response_mode : OIDC_PROTO_RESPONSE_MODE_FORM_POST);
}


static int oidc_handle_redirect_authorization_response(request_rec *r, oidc_cfg *c, oidc_session_t *session) {

	oidc_debug(r, "enter");

	
	apr_table_t *params = apr_table_make(r->pool, 8);
	oidc_util_read_form_encoded_params(r, params, r->args);

	
	return oidc_handle_authorization_response(r, c, session, params, OIDC_PROTO_RESPONSE_MODE_QUERY);
}


static int oidc_discovery(request_rec *r, oidc_cfg *cfg) {

	oidc_debug(r, "enter");

	
	char *current_url = oidc_get_current_url(r);
	const char *method = oidc_original_request_method(r, cfg, FALSE);

	
	char *csrf = NULL;
	if (oidc_proto_generate_nonce(r, &csrf, 8) == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

	char *path_scopes = oidc_dir_cfg_path_scope(r);
	char *path_auth_request_params = oidc_dir_cfg_path_auth_request_params(r);

	char *discover_url = oidc_cfg_dir_discover_url(r);
	
	if (discover_url != NULL) {

		
		char *url = apr_psprintf(r->pool, "%s%s%s=%s&%s=%s&%s=%s&%s=%s", discover_url, strchr(discover_url, OIDC_CHAR_QUERY) != NULL ? OIDC_STR_AMP :


						OIDC_STR_QUERY, OIDC_DISC_RT_PARAM, oidc_util_escape_string(r, current_url), OIDC_DISC_RM_PARAM, method, OIDC_DISC_CB_PARAM, oidc_util_escape_string(r, oidc_get_redirect_uri(r, cfg)), OIDC_CSRF_NAME, oidc_util_escape_string(r, csrf));





		if (path_scopes != NULL)
			url = apr_psprintf(r->pool, "%s&%s=%s", url, OIDC_DISC_SC_PARAM, oidc_util_escape_string(r, path_scopes));
		if (path_auth_request_params != NULL)
			url = apr_psprintf(r->pool, "%s&%s=%s", url, OIDC_DISC_AR_PARAM, oidc_util_escape_string(r, path_auth_request_params));

		
		oidc_debug(r, "redirecting to external discovery page: %s", url);

		
		oidc_util_set_cookie(r, OIDC_CSRF_NAME, csrf, -1, OIDC_COOKIE_SAMESITE_STRICT(cfg, r));

		
		if (oidc_post_preserve_javascript(r, url, NULL, NULL) == TRUE)
			return OK;

		
		oidc_util_hdr_out_location_set(r, url);

		return HTTP_MOVED_TEMPORARILY;
	}

	
	apr_array_header_t *arr = NULL;
	if (oidc_metadata_list(r, cfg, &arr) == FALSE)
		return oidc_util_html_send_error(r, cfg->error_template, "Configuration Error", "No configured providers found, contact your administrator", HTTP_UNAUTHORIZED);



	
	const char *s = "			<h3>Select your OpenID Connect Identity Provider</h3>\n";

	
	int i;
	for (i = 0; i < arr->nelts; i++) {

		const char *issuer = ((const char**) arr->elts)[i];
		

		char *href = apr_psprintf(r->pool, "%s?%s=%s&amp;%s=%s&amp;%s=%s&amp;%s=%s", oidc_get_redirect_uri(r, cfg), OIDC_DISC_OP_PARAM, oidc_util_escape_string(r, issuer), OIDC_DISC_RT_PARAM, oidc_util_escape_string(r, current_url), OIDC_DISC_RM_PARAM, method, OIDC_CSRF_NAME, csrf);






		if (path_scopes != NULL)
			href = apr_psprintf(r->pool, "%s&amp;%s=%s", href, OIDC_DISC_SC_PARAM, oidc_util_escape_string(r, path_scopes));
		if (path_auth_request_params != NULL)
			href = apr_psprintf(r->pool, "%s&amp;%s=%s", href, OIDC_DISC_AR_PARAM, oidc_util_escape_string(r, path_auth_request_params));


		char *display = (strstr(issuer, "https://") == NULL) ? apr_pstrdup(r->pool, issuer) :

						apr_pstrdup(r->pool, issuer + strlen("https://"));

		
		
		
		
		s = apr_psprintf(r->pool, "%s<p><a href=\"%s\">%s</a></p>\n", s, href, display);
	}

	
	s = apr_psprintf(r->pool, "%s<form method=\"get\" action=\"%s\">\n", s, oidc_get_redirect_uri(r, cfg));
	s = apr_psprintf(r->pool, "%s<p><input type=\"hidden\" name=\"%s\" value=\"%s\"><p>\n", s, OIDC_DISC_RT_PARAM, current_url);

	s = apr_psprintf(r->pool, "%s<p><input type=\"hidden\" name=\"%s\" value=\"%s\"><p>\n", s, OIDC_DISC_RM_PARAM, method);

	s = apr_psprintf(r->pool, "%s<p><input type=\"hidden\" name=\"%s\" value=\"%s\"><p>\n", s, OIDC_CSRF_NAME, csrf);


	if (path_scopes != NULL)
		s = apr_psprintf(r->pool, "%s<p><input type=\"hidden\" name=\"%s\" value=\"%s\"><p>\n", s, OIDC_DISC_SC_PARAM, path_scopes);

	if (path_auth_request_params != NULL)
		s = apr_psprintf(r->pool, "%s<p><input type=\"hidden\" name=\"%s\" value=\"%s\"><p>\n", s, OIDC_DISC_AR_PARAM, path_auth_request_params);


	s = apr_psprintf(r->pool, "%s<p>Or enter your account name (eg. &quot;mike@seed.gluu.org&quot;, or an IDP identifier (eg. &quot;mitreid.org&quot;):</p>\n", s);


	s = apr_psprintf(r->pool, "%s<p><input type=\"text\" name=\"%s\" value=\"%s\"></p>\n", s, OIDC_DISC_OP_PARAM, "");

	s = apr_psprintf(r->pool, "%s<p><input type=\"submit\" value=\"Submit\"></p>\n", s);
	s = apr_psprintf(r->pool, "%s</form>\n", s);

	oidc_util_set_cookie(r, OIDC_CSRF_NAME, csrf, -1, OIDC_COOKIE_SAMESITE_STRICT(cfg, r));

	char *javascript = NULL, *javascript_method = NULL;
	char *html_head = "<style type=\"text/css\">body {text-align: center}</style>";
	if (oidc_post_preserve_javascript(r, NULL, &javascript, &javascript_method)
			== TRUE)
		html_head = apr_psprintf(r->pool, "%s%s", html_head, javascript);

	
	return oidc_util_html_send(r, "OpenID Connect Provider Discovery", html_head, javascript_method, s, OK);
}


static int oidc_authenticate_user(request_rec *r, oidc_cfg *c, oidc_provider_t *provider, const char *original_url, const char *login_hint, const char *id_token_hint, const char *prompt, const char *auth_request_params, const char *path_scope) {



	oidc_debug(r, "enter");

	if (provider == NULL) {

		
		if (c->metadata_dir != NULL) {
			
			oidc_debug(r, "defer discovery to the content handler");
			oidc_request_state_set(r, OIDC_REQUEST_STATE_KEY_DISCOVERY, "");
			r->user = "";
			return OK;
		}

		
		if (oidc_provider_static_config(r, c, &provider) == FALSE)
			return HTTP_INTERNAL_SERVER_ERROR;
	}

	
	char *nonce = NULL;
	if (oidc_proto_generate_nonce(r, &nonce, OIDC_PROTO_NONCE_LENGTH) == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

	char *pkce_state = NULL;
	char *code_challenge = NULL;

	if ((oidc_util_spaced_string_contains(r->pool, provider->response_type, OIDC_PROTO_CODE) == TRUE) && (provider->pkce != NULL)) {

		
		if (provider->pkce->state(r, &pkce_state) == FALSE)
			return HTTP_INTERNAL_SERVER_ERROR;

		
		if (provider->pkce->challenge(r, pkce_state, &code_challenge) == FALSE)
			return HTTP_INTERNAL_SERVER_ERROR;
	}

	
	oidc_proto_state_t *proto_state = oidc_proto_state_new();
	oidc_proto_state_set_original_url(proto_state, original_url);
	oidc_proto_state_set_original_method(proto_state, oidc_original_request_method(r, c, TRUE));
	oidc_proto_state_set_issuer(proto_state, provider->issuer);
	oidc_proto_state_set_response_type(proto_state, provider->response_type);
	oidc_proto_state_set_nonce(proto_state, nonce);
	oidc_proto_state_set_timestamp_now(proto_state);
	if (provider->response_mode)
		oidc_proto_state_set_response_mode(proto_state, provider->response_mode);
	if (prompt)
		oidc_proto_state_set_prompt(proto_state, prompt);
	if (pkce_state)
		oidc_proto_state_set_pkce_state(proto_state, pkce_state);

	
	char *state = oidc_get_browser_state_hash(r, c, nonce);

	
	int rc = oidc_authorization_request_set_cookie(r, c, state, proto_state);
	if (rc != OK) {
		oidc_proto_state_destroy(proto_state);
		return rc;
	}

	
	apr_uri_t o_uri;
	memset(&o_uri, 0, sizeof(apr_uri_t));
	apr_uri_t r_uri;
	memset(&r_uri, 0, sizeof(apr_uri_t));
	apr_uri_parse(r->pool, original_url, &o_uri);
	apr_uri_parse(r->pool, oidc_get_redirect_uri(r, c), &r_uri);
	if ((apr_strnatcmp(o_uri.scheme, r_uri.scheme) != 0)
			&& (apr_strnatcmp(r_uri.scheme, "https") == 0)) {
		oidc_error(r, "the URL scheme (%s) of the configured " OIDCRedirectURI " does not match the URL scheme of the URL being accessed (%s): the \"state\" and \"session\" cookies will not be shared between the two!", r_uri.scheme, o_uri.scheme);

		oidc_proto_state_destroy(proto_state);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (c->cookie_domain == NULL) {
		if (apr_strnatcmp(o_uri.hostname, r_uri.hostname) != 0) {
			char *p = strstr(o_uri.hostname, r_uri.hostname);
			if ((p == NULL) || (apr_strnatcmp(r_uri.hostname, p) != 0)) {
				oidc_error(r, "the URL hostname (%s) of the configured " OIDCRedirectURI " does not match the URL hostname of the URL being accessed (%s): the \"state\" and \"session\" cookies will not be shared between the two!", r_uri.hostname, o_uri.hostname);

				oidc_proto_state_destroy(proto_state);
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		}
	} else {
		if (!oidc_util_cookie_domain_valid(r_uri.hostname, c->cookie_domain)) {
			oidc_error(r, "the domain (%s) configured in " OIDCCookieDomain " does not match the URL hostname (%s) of the URL being accessed (%s): setting \"state\" and \"session\" cookies will not work!!", c->cookie_domain, o_uri.hostname, original_url);

			oidc_proto_state_destroy(proto_state);
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	
	
	return oidc_proto_authorization_request(r, provider, login_hint, oidc_get_redirect_uri_iss(r, c, provider), state, proto_state, id_token_hint, code_challenge, auth_request_params, path_scope);

}


static int oidc_target_link_uri_matches_configuration(request_rec *r, oidc_cfg *cfg, const char *target_link_uri) {

	apr_uri_t o_uri;
	apr_uri_parse(r->pool, target_link_uri, &o_uri);
	if (o_uri.hostname == NULL) {
		oidc_error(r, "could not parse the \"target_link_uri\" (%s) in to a valid URL: aborting.", target_link_uri);

		return FALSE;
	}

	apr_uri_t r_uri;
	apr_uri_parse(r->pool, oidc_get_redirect_uri(r, cfg), &r_uri);

	if (cfg->cookie_domain == NULL) {
		
		if (apr_strnatcmp(o_uri.hostname, r_uri.hostname) != 0) {
			char *p = strstr(o_uri.hostname, r_uri.hostname);
			if ((p == NULL) || (apr_strnatcmp(r_uri.hostname, p) != 0)) {
				oidc_error(r, "the URL hostname (%s) of the configured " OIDCRedirectURI " does not match the URL hostname of the \"target_link_uri\" (%s): aborting to prevent an open redirect.", r_uri.hostname, o_uri.hostname);

				return FALSE;
			}
		}
	} else {
		
		char *p = strstr(o_uri.hostname, cfg->cookie_domain);
		if ((p == NULL) || (apr_strnatcmp(cfg->cookie_domain, p) != 0)) {
			oidc_error(r, "the domain (%s) configured in " OIDCCookieDomain " does not match the URL hostname (%s) of the \"target_link_uri\" (%s): aborting to prevent an open redirect.", cfg->cookie_domain, o_uri.hostname, target_link_uri);

			return FALSE;
		}
	}

	
	char *cookie_path = oidc_cfg_dir_cookie_path(r);
	if (cookie_path != NULL) {
		char *p = (o_uri.path != NULL) ? strstr(o_uri.path, cookie_path) : NULL;
		if ((p == NULL) || (p != o_uri.path)) {
			oidc_error(r, "the path (%s) configured in " OIDCCookiePath " does not match the URL path (%s) of the \"target_link_uri\" (%s): aborting to prevent an open redirect.", cfg->cookie_domain, o_uri.path, target_link_uri);

			return FALSE;
		} else if (strlen(o_uri.path) > strlen(cookie_path)) {
			int n = strlen(cookie_path);
			if (cookie_path[n - 1] == OIDC_CHAR_FORWARD_SLASH)
				n--;
			if (o_uri.path[n] != OIDC_CHAR_FORWARD_SLASH) {
				oidc_error(r, "the path (%s) configured in " OIDCCookiePath " does not match the URL path (%s) of the \"target_link_uri\" (%s): aborting to prevent an open redirect.", cfg->cookie_domain, o_uri.path, target_link_uri);

				return FALSE;
			}
		}
	}
	return TRUE;
}


static int oidc_handle_discovery_response(request_rec *r, oidc_cfg *c) {

	
	char *issuer = NULL, *target_link_uri = NULL, *login_hint = NULL, *auth_request_params = NULL, *csrf_cookie, *csrf_query = NULL, *user = NULL, *path_scopes;

	oidc_provider_t *provider = NULL;

	oidc_util_get_request_parameter(r, OIDC_DISC_OP_PARAM, &issuer);
	oidc_util_get_request_parameter(r, OIDC_DISC_USER_PARAM, &user);
	oidc_util_get_request_parameter(r, OIDC_DISC_RT_PARAM, &target_link_uri);
	oidc_util_get_request_parameter(r, OIDC_DISC_LH_PARAM, &login_hint);
	oidc_util_get_request_parameter(r, OIDC_DISC_SC_PARAM, &path_scopes);
	oidc_util_get_request_parameter(r, OIDC_DISC_AR_PARAM, &auth_request_params);
	oidc_util_get_request_parameter(r, OIDC_CSRF_NAME, &csrf_query);
	csrf_cookie = oidc_util_get_cookie(r, OIDC_CSRF_NAME);

	
	if (csrf_cookie) {

		
		oidc_util_set_cookie(r, OIDC_CSRF_NAME, "", 0, OIDC_COOKIE_EXT_SAME_SITE_NONE(r));

		
		if ((csrf_query == NULL)
				|| apr_strnatcmp(csrf_query, csrf_cookie) != 0) {
			oidc_warn(r, "CSRF protection failed, no Discovery and dynamic client registration will be allowed");
			csrf_cookie = NULL;
		}
	}

	

	oidc_debug(r, "issuer=\"%s\", target_link_uri=\"%s\", login_hint=\"%s\", user=\"%s\"", issuer, target_link_uri, login_hint, user);


	if (target_link_uri == NULL) {
		if (c->default_sso_url == NULL) {
			return oidc_util_html_send_error(r, c->error_template, "Invalid Request", "SSO to this module without specifying a \"target_link_uri\" parameter is not possible because " OIDCDefaultURL " is not set.", HTTP_INTERNAL_SERVER_ERROR);


		}
		target_link_uri = c->default_sso_url;
	}

	
	if (oidc_target_link_uri_matches_configuration(r, c, target_link_uri)
			== FALSE) {
		return oidc_util_html_send_error(r, c->error_template, "Invalid Request", "\"target_link_uri\" parameter does not match configuration settings, aborting to prevent an open redirect.", HTTP_UNAUTHORIZED);


	}

	
	if (c->metadata_dir == NULL) {
		if ((oidc_provider_static_config(r, c, &provider) == TRUE)
				&& (issuer != NULL)) {
			if (apr_strnatcmp(provider->issuer, issuer) != 0) {
				return oidc_util_html_send_error(r, c->error_template, "Invalid Request", apr_psprintf(r->pool, "The \"iss\" value must match the configured providers' one (%s != %s).", issuer, c->provider.issuer), HTTP_INTERNAL_SERVER_ERROR);




			}
		}
		return oidc_authenticate_user(r, c, NULL, target_link_uri, login_hint, NULL, NULL, auth_request_params, path_scopes);
	}

	
	if (user != NULL) {

		if (login_hint == NULL)
			login_hint = apr_pstrdup(r->pool, user);

		
		if (strstr(user, "https://") != user)
			user = apr_psprintf(r->pool, "https://%s", user);

		
		if (oidc_proto_url_based_discovery(r, c, user, &issuer) == FALSE) {

			
			return oidc_util_html_send_error(r, c->error_template, "Invalid Request", "Could not resolve the provided user identifier to an OpenID Connect provider; check your syntax.", HTTP_NOT_FOUND);


		}

		

	} else if (strstr(issuer, OIDC_STR_AT) != NULL) {

		if (login_hint == NULL) {
			login_hint = apr_pstrdup(r->pool, issuer);
			
			
		}

		
		if (oidc_proto_account_based_discovery(r, c, issuer, &issuer)
				== FALSE) {

			
			return oidc_util_html_send_error(r, c->error_template, "Invalid Request", "Could not resolve the provided account name to an OpenID Connect provider; check your syntax.", HTTP_NOT_FOUND);


		}

		

	}

	
	int n = strlen(issuer);
	if (issuer[n - 1] == OIDC_CHAR_FORWARD_SLASH)
		issuer[n - 1] = '\0';

	
	if ((oidc_metadata_get(r, c, issuer, &provider, csrf_cookie != NULL) == TRUE)
			&& (provider != NULL)) {

		
		return oidc_authenticate_user(r, c, provider, target_link_uri, login_hint, NULL, NULL, auth_request_params, path_scopes);
	}

	
	return oidc_util_html_send_error(r, c->error_template, "Invalid Request", "Could not find valid provider metadata for the selected OpenID Connect provider; contact the administrator", HTTP_NOT_FOUND);

}

static apr_uint32_t oidc_transparent_pixel[17] = { 0x474e5089, 0x0a1a0a0d, 0x0d000000, 0x52444849, 0x01000000, 0x01000000, 0x00000408, 0x0c1cb500, 0x00000002, 0x4144490b, 0x639c7854, 0x0000cffa, 0x02010702, 0x71311c9a, 0x00000000, 0x444e4549, 0x826042ae };



static apr_byte_t oidc_is_front_channel_logout(const char *logout_param_value) {
	return ((logout_param_value != NULL)
			&& ((apr_strnatcmp(logout_param_value, OIDC_GET_STYLE_LOGOUT_PARAM_VALUE) == 0)
					|| (apr_strnatcmp(logout_param_value, OIDC_IMG_STYLE_LOGOUT_PARAM_VALUE) == 0)));
}

static apr_byte_t oidc_is_back_channel_logout(const char *logout_param_value) {
	return ((logout_param_value != NULL) && (apr_strnatcmp(logout_param_value, OIDC_BACKCHANNEL_STYLE_LOGOUT_PARAM_VALUE) == 0));
}


static void oidc_revoke_tokens(request_rec *r, oidc_cfg *c, oidc_session_t *session) {

	char *response = NULL;
	char *basic_auth = NULL;
	char *bearer_auth = NULL;
	apr_table_t *params = NULL;
	const char *token = NULL;
	oidc_provider_t *provider = NULL;

	oidc_debug(r, "enter");

	if (oidc_get_provider_from_session(r, c, session, &provider) == FALSE)
		goto out;

	oidc_debug(r, "revocation_endpoint=%s", provider->revocation_endpoint_url ? provider->revocation_endpoint_url : "(null)");


	if (provider->revocation_endpoint_url == NULL)
		goto out;

	params = apr_table_make(r->pool, 4);

	
	if (oidc_proto_token_endpoint_auth(r, c, provider->token_endpoint_auth, provider->client_id, provider->client_secret, provider->client_signing_keys, provider->token_endpoint_url, params, NULL, &basic_auth, &bearer_auth) == FALSE)


		goto out;

	
	token = oidc_session_get_refresh_token(r, session);
	if (token != NULL) {
		apr_table_setn(params, OIDC_PROTO_TOKEN_TYPE_HINT, OIDC_PROTO_REFRESH_TOKEN);
		apr_table_setn(params, OIDC_PROTO_TOKEN, token);

		if (oidc_util_http_post_form(r, provider->revocation_endpoint_url, params, basic_auth, bearer_auth, c->oauth.ssl_validate_server, &response, c->http_timeout_long, c->outgoing_proxy, oidc_dir_cfg_pass_cookies(r), NULL, NULL, NULL) == FALSE) {



			oidc_warn(r, "revoking refresh token failed");
		}
		apr_table_unset(params, OIDC_PROTO_TOKEN_TYPE_HINT);
		apr_table_unset(params, OIDC_PROTO_TOKEN);
	}

	token = oidc_session_get_access_token(r, session);
	if (token != NULL) {
		apr_table_setn(params, OIDC_PROTO_TOKEN_TYPE_HINT, OIDC_PROTO_ACCESS_TOKEN);
		apr_table_setn(params, OIDC_PROTO_TOKEN, token);

		if (oidc_util_http_post_form(r, provider->revocation_endpoint_url, params, basic_auth, bearer_auth, c->oauth.ssl_validate_server, &response, c->http_timeout_long, c->outgoing_proxy, oidc_dir_cfg_pass_cookies(r), NULL, NULL, NULL) == FALSE) {



			oidc_warn(r, "revoking access token failed");
		}
	}

out:

	oidc_debug(r, "leave");
}


static int oidc_handle_logout_request(request_rec *r, oidc_cfg *c, oidc_session_t *session, const char *url) {

	oidc_debug(r, "enter (url=%s)", url);

	
	if (session->remote_user != NULL)
		oidc_revoke_tokens(r, c, session);

	
	oidc_session_kill(r, session);

	
	if (oidc_is_front_channel_logout(url)) {

		
		oidc_util_hdr_err_out_add(r, OIDC_HTTP_HDR_CACHE_CONTROL, "no-cache, no-store");
		oidc_util_hdr_err_out_add(r, OIDC_HTTP_HDR_PRAGMA, "no-cache");
		oidc_util_hdr_err_out_add(r, OIDC_HTTP_HDR_P3P, "CAO PSA OUR");
		oidc_util_hdr_err_out_add(r, OIDC_HTTP_HDR_EXPIRES, "0");
		oidc_util_hdr_err_out_add(r, OIDC_HTTP_HDR_X_FRAME_OPTIONS, "DENY");

		
		const char *accept = oidc_util_hdr_in_accept_get(r);
		if ((apr_strnatcmp(url, OIDC_IMG_STYLE_LOGOUT_PARAM_VALUE) == 0)
				|| ((accept) && strstr(accept, OIDC_CONTENT_TYPE_IMAGE_PNG))) {
			return oidc_util_http_send(r, (const char*) &oidc_transparent_pixel, sizeof(oidc_transparent_pixel), OIDC_CONTENT_TYPE_IMAGE_PNG, OK);

		}

		
		return oidc_util_html_send(r, "Logged Out", NULL, NULL, "<p>Logged Out</p>", OK);
	}

	
	if (url == NULL)
		return oidc_util_html_send(r, "Logged Out", NULL, NULL, "<p>Logged Out</p>", OK);

	
	oidc_util_hdr_out_location_set(r, url);

	return HTTP_MOVED_TEMPORARILY;
}




static int oidc_handle_logout_backchannel(request_rec *r, oidc_cfg *cfg) {

	oidc_debug(r, "enter");

	const char *logout_token = NULL;
	oidc_jwt_t *jwt = NULL;
	oidc_jose_error_t err;
	oidc_jwk_t *jwk = NULL;
	oidc_provider_t *provider = NULL;
	char *sid = NULL, *uuid = NULL;
	oidc_session_t session;
	int rc = HTTP_BAD_REQUEST;

	apr_table_t *params = apr_table_make(r->pool, 8);
	if (oidc_util_read_post_params(r, params, FALSE, NULL) == FALSE) {
		oidc_error(r, "could not read POST-ed parameters to the logout endpoint");
		goto out;
	}

	logout_token = apr_table_get(params, OIDC_PROTO_LOGOUT_TOKEN);
	if (logout_token == NULL) {
		oidc_error(r, "backchannel lggout endpoint was called but could not find a parameter named \"%s\"", OIDC_PROTO_LOGOUT_TOKEN);

		goto out;
	}

	

	if (oidc_jwt_parse(r->pool, logout_token, &jwt, oidc_util_merge_symmetric_key(r->pool, cfg->private_keys, NULL), &err) == FALSE) {

		oidc_error(r, "oidc_jwt_parse failed: %s", oidc_jose_e2s(r->pool, err));
		goto out;
	}

	if ((jwt->header.alg == NULL) || (strcmp(jwt->header.alg, "none") == 0)) {
		oidc_error(r, "logout token is not signed");
		goto out;
	}

	provider = oidc_get_provider_for_issuer(r, cfg, jwt->payload.iss, FALSE);
	if (provider == NULL) {
		oidc_error(r, "no provider found for issuer: %s", jwt->payload.iss);
		goto out;
	}

	

	jwk = NULL;
	if (oidc_util_create_symmetric_key(r, provider->client_secret, 0, NULL, TRUE, &jwk) == FALSE)
		return FALSE;

	oidc_jwks_uri_t jwks_uri = { provider->jwks_uri, provider->jwks_refresh_interval, provider->ssl_validate_server };
	if (oidc_proto_jwt_verify(r, cfg, jwt, &jwks_uri, oidc_util_merge_symmetric_key(r->pool, NULL, jwk), provider->id_token_signed_response_alg) == FALSE) {


		oidc_error(r, "id_token signature could not be validated, aborting");
		goto out;
	}

	
	
	if (oidc_proto_validate_jwt(r, jwt, provider->validate_issuer ? provider->issuer : NULL, FALSE, FALSE, provider->idtoken_iat_slack, OIDC_TOKEN_BINDING_POLICY_DISABLED) == FALSE)


		goto out;

	
	if (oidc_proto_validate_aud_and_azp(r, cfg, provider, &jwt->payload)
			== FALSE)
		goto out;

	json_t *events = json_object_get(jwt->payload.value.json, OIDC_CLAIM_EVENTS);
	if (events == NULL) {
		oidc_error(r, "\"%s\" claim could not be found in logout token", OIDC_CLAIM_EVENTS);
		goto out;
	}

	json_t *blogout = json_object_get(events, OIDC_EVENTS_BLOGOUT_KEY);
	if (!json_is_object(blogout)) {
		oidc_error(r, "\"%s\" object could not be found in \"%s\" claim", OIDC_EVENTS_BLOGOUT_KEY, OIDC_CLAIM_EVENTS);
		goto out;
	}

	char *nonce = NULL;
	oidc_json_object_get_string(r->pool, jwt->payload.value.json, OIDC_CLAIM_NONCE, &nonce, NULL);
	if (nonce != NULL) {
		oidc_error(r, "rejecting logout request/token since it contains a \"%s\" claim", OIDC_CLAIM_NONCE);

		goto out;
	}

	char *jti = NULL;
	oidc_json_object_get_string(r->pool, jwt->payload.value.json, OIDC_CLAIM_JTI, &jti, NULL);
	if (jti != NULL) {
		char *replay = NULL;
		oidc_cache_get_jti(r, jti, &replay);
		if (replay != NULL) {
			oidc_error(r, "the \"%s\" value (%s) passed in logout token was found in the cache already; possible replay attack!?", OIDC_CLAIM_JTI, jti);

			goto out;
		}
	}

	
	apr_time_t jti_cache_duration = apr_time_from_sec( provider->idtoken_iat_slack * 2 + 10);

	
	oidc_cache_set_jti(r, jti, jti, apr_time_now() + jti_cache_duration);

	oidc_json_object_get_string(r->pool, jwt->payload.value.json, OIDC_CLAIM_EVENTS, &sid, NULL);

	
	
	
	
	
	
	

	oidc_json_object_get_string(r->pool, jwt->payload.value.json, OIDC_CLAIM_SID, &sid, NULL);
	if (sid == NULL)
		sid = jwt->payload.sub;

	if (sid == NULL) {
		oidc_error(r, "no \"sub\" and no \"sid\" claim found in logout token");
		goto out;
	}

	
	
	
	
	
	

	sid = oidc_make_sid_iss_unique(r, sid, provider->issuer);
	oidc_cache_get_sid(r, sid, &uuid);
	if (uuid == NULL) {
		
		oidc_warn(r, "could not (or no longer) find a session based on sid/sub provided in logout token: %s", sid);

		r->user = "";
		rc = OK;
		goto out;
	}

	
	if (cfg->session_type != OIDC_SESSION_TYPE_CLIENT_COOKIE) {
		if (oidc_session_load_cache_by_uuid(r, cfg, uuid, &session) != FALSE)
			if (oidc_session_extract(r, &session) != FALSE)
				oidc_revoke_tokens(r, cfg, &session);
	}

	
	oidc_cache_set_sid(r, sid, NULL, 0);
	oidc_cache_set_session(r, uuid, NULL, 0);

	r->user = "";
	rc = OK;

out:

	if (jwk != NULL) {
		oidc_jwk_destroy(jwk);
		jwk = NULL;

	}
	if (jwt != NULL) {
		oidc_jwt_destroy(jwt);
		jwt = NULL;
	}

	oidc_util_hdr_err_out_add(r, OIDC_HTTP_HDR_CACHE_CONTROL, "no-cache, no-store");
	oidc_util_hdr_err_out_add(r, OIDC_HTTP_HDR_PRAGMA, "no-cache");

	return rc;
}



static apr_byte_t oidc_validate_redirect_url(request_rec *r, oidc_cfg *c, const char *redirect_to_url, apr_byte_t restrict_to_host, char **err_str, char **err_desc) {

	apr_uri_t uri;
	const char *c_host = NULL;
	apr_hash_index_t *hi = NULL;
	size_t i = 0;
	char *url = apr_pstrndup(r->pool, redirect_to_url, OIDC_MAX_URL_LENGTH);

	
	for (i = 0; i < strlen(url); i++)
		if (url[i] == '\\')
			url[i] = '/';

	if (apr_uri_parse(r->pool, url, &uri) != APR_SUCCESS) {
		*err_str = apr_pstrdup(r->pool, "Malformed URL");
		*err_desc = apr_psprintf(r->pool, "not a valid URL value: %s", url);
		oidc_error(r, "%s: %s", *err_str, *err_desc);
		return FALSE;
	}

	if (c->redirect_urls_allowed != NULL) {
		for (hi = apr_hash_first(NULL, c->redirect_urls_allowed); hi; hi = apr_hash_next(hi)) {
			apr_hash_this(hi, (const void**) &c_host, NULL, NULL);
			if (oidc_util_regexp_first_match(r->pool, url, c_host, NULL, err_str) == TRUE)
				break;
		}
		if (hi == NULL) {
			*err_str = apr_pstrdup(r->pool, "URL not allowed");
			*err_desc = apr_psprintf(r->pool, "value does not match the list of allowed redirect URLs: %s", url);


			oidc_error(r, "%s: %s", *err_str, *err_desc);
			return FALSE;
		}
	} else if ((uri.hostname != NULL) && (restrict_to_host == TRUE)) {
		c_host = oidc_get_current_url_host(r);
		if ((strstr(c_host, uri.hostname) == NULL)
				|| (strstr(uri.hostname, c_host) == NULL)) {
			*err_str = apr_pstrdup(r->pool, "Invalid Request");
			*err_desc = apr_psprintf(r->pool, "URL value \"%s\" does not match the hostname of the current request \"%s\"", apr_uri_unparse(r->pool, &uri, 0), c_host);


			oidc_error(r, "%s: %s", *err_str, *err_desc);
			return FALSE;
		}
	}

	if ((uri.hostname == NULL) && (strstr(url, "/") != url)) {
		*err_str = apr_pstrdup(r->pool, "Malformed URL");
		*err_desc = apr_psprintf(r->pool, "No hostname was parsed and it does not seem to be relative, i.e starting with '/': %s", url);


		oidc_error(r, "%s: %s", *err_str, *err_desc);
		return FALSE;
	} else if ((uri.hostname == NULL) && (strstr(url, "//") == url)) {
		*err_str = apr_pstrdup(r->pool, "Malformed URL");
		*err_desc = apr_psprintf(r->pool, "No hostname was parsed and starting with '//': %s", url);
		oidc_error(r, "%s: %s", *err_str, *err_desc);
		return FALSE;
	} else if ((uri.hostname == NULL) && (strstr(url, "/\\") == url)) {
		*err_str = apr_pstrdup(r->pool, "Malformed URL");
		*err_desc = apr_psprintf(r->pool, "No hostname was parsed and starting with '/\\': %s", url);
		oidc_error(r, "%s: %s", *err_str, *err_desc);
		return FALSE;
	}

	
	if (((strstr(url, "\n") != NULL) || strstr(url, "\r") != NULL)) {
		*err_str = apr_pstrdup(r->pool, "Invalid URL");
		*err_desc = apr_psprintf(r->pool, "URL value \"%s\" contains illegal \"\n\" or \"\r\" character(s)", url);


		oidc_error(r, "%s: %s", *err_str, *err_desc);
		return FALSE;
	}

	return TRUE;
}


static int oidc_handle_logout(request_rec *r, oidc_cfg *c, oidc_session_t *session) {

	oidc_provider_t *provider = NULL;
	
	char *url = NULL;
	char *error_str = NULL;
	char *error_description = NULL;

	oidc_util_get_request_parameter(r, OIDC_REDIRECT_URI_REQUEST_LOGOUT, &url);

	oidc_debug(r, "enter (url=%s)", url);

	if (oidc_is_front_channel_logout(url)) {
		return oidc_handle_logout_request(r, c, session, url);
	} else if (oidc_is_back_channel_logout(url)) {
		return oidc_handle_logout_backchannel(r, c);
	}

	if ((url == NULL) || (apr_strnatcmp(url, "") == 0)) {

		url = c->default_slo_url;

	} else {

		
		if (oidc_validate_redirect_url(r, c, url, TRUE, &error_str, &error_description) == FALSE) {
			return oidc_util_html_send_error(r, c->error_template, error_str, error_description, HTTP_BAD_REQUEST);

		}
	}

	oidc_get_provider_from_session(r, c, session, &provider);

	if ((provider != NULL) && (provider->end_session_endpoint != NULL)) {

		const char *id_token_hint = oidc_session_get_idtoken(r, session);

		char *logout_request = apr_pstrdup(r->pool, provider->end_session_endpoint);
		if (id_token_hint != NULL) {
			logout_request = apr_psprintf(r->pool, "%s%sid_token_hint=%s", logout_request, strchr(logout_request ? logout_request : "", OIDC_CHAR_QUERY) != NULL ? OIDC_STR_AMP :


									OIDC_STR_QUERY, oidc_util_escape_string(r, id_token_hint));
		}

		if (url != NULL) {
			logout_request = apr_psprintf(r->pool, "%s%spost_logout_redirect_uri=%s", logout_request, strchr(logout_request ? logout_request : "", OIDC_CHAR_QUERY) != NULL ? OIDC_STR_AMP :



									OIDC_STR_QUERY, oidc_util_escape_string(r, url));
		}
		
		
		
		url = logout_request;
	}

	return oidc_handle_logout_request(r, c, session, url);
}


int oidc_handle_jwks(request_rec *r, oidc_cfg *c) {

	
	
	
	char *jwks = apr_pstrdup(r->pool, "{ \"keys\" : [");
	int i = 0;
	apr_byte_t first = TRUE;
	oidc_jose_error_t err;

	if (c->public_keys != NULL) {

		
		for (i = 0; i < c->public_keys->nelts; i++) {
			const oidc_jwk_t *jwk = ((const oidc_jwk_t**) c->public_keys->elts)[i];
			char *s_json = NULL;

			if (oidc_jwk_to_json(r->pool, jwk, &s_json, &err) == TRUE) {
				jwks = apr_psprintf(r->pool, "%s%s %s ", jwks, first ? "" : ",", s_json);
				first = FALSE;
			} else {
				oidc_error(r, "could not convert RSA JWK to JSON using oidc_jwk_to_json: %s", oidc_jose_e2s(r->pool, err));

			}
		}
	}

	
	jwks = apr_psprintf(r->pool, "%s ] }", jwks);

	return oidc_util_http_send(r, jwks, strlen(jwks), OIDC_CONTENT_TYPE_JSON, OK);
}

static int oidc_handle_session_management_iframe_op(request_rec *r, oidc_cfg *c, oidc_session_t *session, const char *check_session_iframe) {
	oidc_debug(r, "enter");
	oidc_util_hdr_out_location_set(r, check_session_iframe);
	return HTTP_MOVED_TEMPORARILY;
}

static int oidc_handle_session_management_iframe_rp(request_rec *r, oidc_cfg *c, oidc_session_t *session, const char *client_id, const char *check_session_iframe) {


	oidc_debug(r, "enter");

	const char *java_script = "    <script type=\"text/javascript\">\n" "      var targetOrigin  = '%s';\n" "      var clientId  = '%s';\n" "      var sessionId  = '%s';\n" "      var loginUrl  = '%s';\n" "      var message = clientId + ' ' + sessionId;\n" "	   var timerID;\n" "\n" "      function checkSession() {\n" "        console.debug('checkSession: posting ' + message + ' to ' + targetOrigin);\n" "        var win = window.parent.document.getElementById('%s').contentWindow;\n" "        win.postMessage( message, targetOrigin);\n" "      }\n" "\n" "      function setTimer() {\n" "        checkSession();\n" "        timerID = setInterval('checkSession()', %d);\n" "      }\n" "\n" "      function receiveMessage(e) {\n" "        console.debug('receiveMessage: ' + e.data + ' from ' + e.origin);\n" "        if (e.origin !== targetOrigin ) {\n" "          console.debug('receiveMessage: cross-site scripting attack?');\n" "          return;\n" "        }\n" "        if (e.data != 'unchanged') {\n" "          clearInterval(timerID);\n" "          if (e.data == 'changed' && sessionId == '' ) {\n" "			 // 'changed' + no session: enforce a login (if we have a login url...)\n" "            if (loginUrl != '') {\n" "              window.top.location.replace(loginUrl);\n" "            }\n" "		   } else {\n" "              // either 'changed' + active session, or 'error': enforce a logout\n" "              window.top.location.replace('%s?logout=' + encodeURIComponent(window.top.location.href));\n" "          }\n" "        }\n" "      }\n" "\n" "      window.addEventListener('message', receiveMessage, false);\n" "\n" "    </script>\n";










































	
	char *origin = apr_pstrdup(r->pool, check_session_iframe);
	apr_uri_t uri;
	apr_uri_parse(r->pool, check_session_iframe, &uri);
	char *p = strstr(origin, uri.path);
	*p = '\0';

	
	const char *op_iframe_id = "openidc-op";

	
	const char *session_state = oidc_session_get_session_state(r, session);
	if (session_state == NULL) {
		oidc_warn(r, "no session_state found in the session; the OP does probably not support session management!?");
		
	}

	char *s_poll_interval = NULL;
	oidc_util_get_request_parameter(r, "poll", &s_poll_interval);
	int poll_interval = s_poll_interval ? strtol(s_poll_interval, NULL, 10) : 0;
	if ((poll_interval <= 0) || (poll_interval > 3600 * 24))
		poll_interval = 3000;

	char *login_uri = NULL, *error_str = NULL, *error_description = NULL;
	oidc_util_get_request_parameter(r, "login_uri", &login_uri);
	if ((login_uri != NULL)
			&& (oidc_validate_redirect_url(r, c, login_uri, FALSE, &error_str, &error_description) == FALSE)) {
		return HTTP_BAD_REQUEST;
	}

	const char *redirect_uri = oidc_get_redirect_uri(r, c);

	java_script = apr_psprintf(r->pool, java_script, origin, client_id, session_state ? session_state : "", login_uri ? login_uri : "", op_iframe_id, poll_interval, redirect_uri, redirect_uri);


	return oidc_util_html_send(r, NULL, java_script, "setTimer", NULL, OK);
}


static int oidc_handle_session_management(request_rec *r, oidc_cfg *c, oidc_session_t *session) {
	char *cmd = NULL;
	const char *id_token_hint = NULL;
	oidc_provider_t *provider = NULL;

	
	oidc_util_get_request_parameter(r, OIDC_REDIRECT_URI_REQUEST_SESSION, &cmd);
	if (cmd == NULL) {
		oidc_error(r, "session management handler called with no command");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	
	if (apr_strnatcmp("logout", cmd) == 0) {
		oidc_debug(r, "[session=logout] calling oidc_handle_logout_request because of session mgmt local logout call.");
		return oidc_handle_logout_request(r, c, session, c->default_slo_url);
	}

	if (oidc_get_provider_from_session(r, c, session, &provider) == FALSE) {
		if ((oidc_provider_static_config(r, c, &provider) == FALSE)
				|| (provider == NULL))
			return HTTP_NOT_FOUND;
	}

	
	if (apr_strnatcmp("iframe_op", cmd) == 0) {
		if (provider->check_session_iframe != NULL) {
			return oidc_handle_session_management_iframe_op(r, c, session, provider->check_session_iframe);
		}
		return HTTP_NOT_FOUND;
	}

	
	if (apr_strnatcmp("iframe_rp", cmd) == 0) {
		if ((provider->client_id != NULL)
				&& (provider->check_session_iframe != NULL)) {
			return oidc_handle_session_management_iframe_rp(r, c, session, provider->client_id, provider->check_session_iframe);
		}
		oidc_debug(r, "iframe_rp command issued but no client (%s) and/or no check_session_iframe (%s) set", provider->client_id, provider->check_session_iframe);

		return HTTP_NOT_FOUND;
	}

	
	if (apr_strnatcmp("check", cmd) == 0) {
		id_token_hint = oidc_session_get_idtoken(r, session);
		
		return oidc_authenticate_user(r, c, provider, apr_psprintf(r->pool, "%s?session=iframe_rp", oidc_get_redirect_uri_iss(r, c, provider)), NULL, id_token_hint, "none", oidc_dir_cfg_path_auth_request_params(r), oidc_dir_cfg_path_scope(r));



	}

	
	oidc_error(r, "unknown command: %s", cmd);

	return HTTP_INTERNAL_SERVER_ERROR;
}


static int oidc_handle_refresh_token_request(request_rec *r, oidc_cfg *c, oidc_session_t *session) {

	char *return_to = NULL;
	char *r_access_token = NULL;
	char *error_code = NULL;
	char *error_str = NULL;
	char *error_description = NULL;
	apr_byte_t needs_save = TRUE;

	
	oidc_util_get_request_parameter(r, OIDC_REDIRECT_URI_REQUEST_REFRESH, &return_to);
	oidc_util_get_request_parameter(r, OIDC_PROTO_ACCESS_TOKEN, &r_access_token);

	
	if (return_to == NULL) {
		oidc_error(r, "refresh token request handler called with no URL to return to");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	
	if (oidc_validate_redirect_url(r, c, return_to, TRUE, &error_str, &error_description) == FALSE) {
		oidc_error(r, "return_to URL validation failed: %s: %s", error_str, error_description);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (r_access_token == NULL) {
		oidc_error(r, "refresh token request handler called with no access_token parameter");
		error_code = "no_access_token";
		goto end;
	}

	const char *s_access_token = oidc_session_get_access_token(r, session);
	if (s_access_token == NULL) {
		oidc_error(r, "no existing access_token found in the session, nothing to refresh");
		error_code = "no_access_token_exists";
		goto end;
	}

	
	if (apr_strnatcmp(s_access_token, r_access_token) != 0) {
		oidc_error(r, "access_token passed in refresh request does not match the one stored in the session");
		error_code = "no_access_token_match";
		goto end;
	}

	
	oidc_provider_t *provider = NULL;
	if (oidc_get_provider_from_session(r, c, session, &provider) == FALSE) {
		error_code = "session_corruption";
		goto end;
	}

	
	if (oidc_refresh_access_token(r, c, session, provider, NULL) == FALSE) {
		oidc_error(r, "access_token could not be refreshed");
		error_code = "refresh_failed";
		goto end;
	}

	
	if (oidc_session_pass_tokens(r, c, session, &needs_save) == FALSE) {
		error_code = "session_corruption";
		goto end;
	}

	if (oidc_session_save(r, session, FALSE) == FALSE) {
		error_code = "error saving session";
		goto end;
	}

end:

	
	if (error_code != NULL)
		return_to = apr_psprintf(r->pool, "%s%serror_code=%s", return_to, strchr(return_to ? return_to : "", OIDC_CHAR_QUERY) ? OIDC_STR_AMP :

						OIDC_STR_QUERY, oidc_util_escape_string(r, error_code));

	
	oidc_util_hdr_out_location_set(r, return_to);

	return HTTP_MOVED_TEMPORARILY;
}


static int oidc_handle_request_uri(request_rec *r, oidc_cfg *c) {

	char *request_ref = NULL;
	oidc_util_get_request_parameter(r, OIDC_REDIRECT_URI_REQUEST_REQUEST_URI, &request_ref);
	if (request_ref == NULL) {
		oidc_error(r, "no \"%s\" parameter found", OIDC_REDIRECT_URI_REQUEST_REQUEST_URI);
		return HTTP_BAD_REQUEST;
	}

	char *jwt = NULL;
	oidc_cache_get_request_uri(r, request_ref, &jwt);
	if (jwt == NULL) {
		oidc_error(r, "no cached JWT found for %s reference: %s", OIDC_REDIRECT_URI_REQUEST_REQUEST_URI, request_ref);
		return HTTP_NOT_FOUND;
	}

	oidc_cache_set_request_uri(r, request_ref, NULL, 0);

	return oidc_util_http_send(r, jwt, strlen(jwt), OIDC_CONTENT_TYPE_JWT, OK);
}


int oidc_handle_remove_at_cache(request_rec *r, oidc_cfg *c) {
	char *access_token = NULL;
	oidc_util_get_request_parameter(r, OIDC_REDIRECT_URI_REQUEST_REMOVE_AT_CACHE, &access_token);

	char *cache_entry = NULL;
	oidc_cache_get_access_token(r, access_token, &cache_entry);
	if (cache_entry == NULL) {
		oidc_error(r, "no cached access token found for value: %s", access_token);
		return HTTP_NOT_FOUND;
	}

	oidc_cache_set_access_token(r, access_token, NULL, 0);

	return OK;
}




static int oidc_handle_info_request(request_rec *r, oidc_cfg *c, oidc_session_t *session, apr_byte_t needs_save) {
	int rc = HTTP_UNAUTHORIZED;
	char *s_format = NULL, *s_interval = NULL, *r_value = NULL;
	oidc_util_get_request_parameter(r, OIDC_REDIRECT_URI_REQUEST_INFO, &s_format);
	oidc_util_get_request_parameter(r, OIDC_INFO_PARAM_ACCESS_TOKEN_REFRESH_INTERVAL, &s_interval);

	
	if ((apr_strnatcmp(OIDC_HOOK_INFO_FORMAT_JSON, s_format) != 0)
			&& (apr_strnatcmp(OIDC_HOOK_INFO_FORMAT_HTML, s_format) != 0)) {
		oidc_warn(r, "request for unknown format: %s", s_format);
		return HTTP_UNSUPPORTED_MEDIA_TYPE;
	}

	
	if (session->remote_user == NULL) {
		oidc_warn(r, "no user session found");
		return HTTP_UNAUTHORIZED;
	}

	
	r->user = apr_pstrdup(r->pool, session->remote_user);

	if (c->info_hook_data == NULL) {
		oidc_warn(r, "no data configured to return in " OIDCInfoHook);
		return HTTP_NOT_FOUND;
	}

	
	if ((s_interval != NULL)
			&& (oidc_session_get_refresh_token(r, session) != NULL)) {

		apr_time_t t_interval;
		if (sscanf(s_interval, "%" APR_TIME_T_FMT, &t_interval) == 1) {
			t_interval = apr_time_from_sec(t_interval);

			
			apr_time_t last_refresh = oidc_session_get_access_token_last_refresh(r, session);

			oidc_debug(r, "refresh needed in: %" APR_TIME_T_FMT " seconds", apr_time_sec(last_refresh + t_interval - apr_time_now()));

			
			if (last_refresh + t_interval < apr_time_now()) {

				
				oidc_provider_t *provider = NULL;
				if (oidc_get_provider_from_session(r, c, session, &provider)
						== FALSE)
					return HTTP_INTERNAL_SERVER_ERROR;

				
				if (oidc_refresh_access_token(r, c, session, provider, NULL) == FALSE)
					oidc_warn(r, "access_token could not be refreshed");
				else needs_save = TRUE;
			}
		}
	}

	
	json_t *json = json_object();

	
	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_TIMESTAMP, APR_HASH_KEY_STRING)) {
		json_object_set_new(json, OIDC_HOOK_INFO_TIMESTAMP, json_integer(apr_time_sec(apr_time_now())));
	}

	
	needs_save |= oidc_refresh_claims_from_userinfo_endpoint(r, c, session);

	
	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_ACCES_TOKEN, APR_HASH_KEY_STRING)) {
		const char *access_token = oidc_session_get_access_token(r, session);
		if (access_token != NULL)
			json_object_set_new(json, OIDC_HOOK_INFO_ACCES_TOKEN, json_string(access_token));
	}

	
	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_ACCES_TOKEN_EXP, APR_HASH_KEY_STRING)) {
		const char *access_token_expires = oidc_session_get_access_token_expires(r, session);
		if (access_token_expires != NULL)
			json_object_set_new(json, OIDC_HOOK_INFO_ACCES_TOKEN_EXP, json_string(access_token_expires));
	}

	
	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_ID_TOKEN, APR_HASH_KEY_STRING)) {
		json_t *id_token = oidc_session_get_idtoken_claims_json(r, session);
		if (id_token)
			json_object_set_new(json, OIDC_HOOK_INFO_ID_TOKEN, id_token);
	}

	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_USER_INFO, APR_HASH_KEY_STRING)) {
		
		json_t *claims = oidc_session_get_userinfo_claims_json(r, session);
		if (claims)
			json_object_set_new(json, OIDC_HOOK_INFO_USER_INFO, claims);
	}

	
	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_SESSION_EXP, APR_HASH_KEY_STRING)) {
		apr_time_t session_expires = oidc_session_get_session_expires(r, session);
		json_object_set_new(json, OIDC_HOOK_INFO_SESSION_EXP, json_integer(apr_time_sec(session_expires)));
	}

	
	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_SESSION_TIMEOUT, APR_HASH_KEY_STRING)) {
		json_object_set_new(json, OIDC_HOOK_INFO_SESSION_TIMEOUT, json_integer(apr_time_sec(session->expiry)));
	}

	
	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_SESSION_REMOTE_USER, APR_HASH_KEY_STRING)) {
		json_object_set_new(json, OIDC_HOOK_INFO_SESSION_REMOTE_USER, json_string(session->remote_user));
	}

	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_SESSION, APR_HASH_KEY_STRING)) {
		json_t *j_session = json_object();
		json_object_set(j_session, OIDC_HOOK_INFO_SESSION_STATE, session->state);
		json_object_set_new(j_session, OIDC_HOOK_INFO_SESSION_UUID, json_string(session->uuid));
		json_object_set_new(json, OIDC_HOOK_INFO_SESSION, j_session);

	}

	if (apr_hash_get(c->info_hook_data, OIDC_HOOK_INFO_REFRESH_TOKEN, APR_HASH_KEY_STRING)) {
		
		const char *refresh_token = oidc_session_get_refresh_token(r, session);
		if (refresh_token != NULL)
			json_object_set_new(json, OIDC_HOOK_INFO_REFRESH_TOKEN, json_string(refresh_token));
	}

	
	if (oidc_session_pass_tokens(r, c, session, &needs_save) == FALSE)
		oidc_warn(r, "error passing tokens");

	
	if (needs_save) {
		if (oidc_session_save(r, session, FALSE) == FALSE) {
			oidc_warn(r, "error saving session");
			rc = HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	if (apr_strnatcmp(OIDC_HOOK_INFO_FORMAT_JSON, s_format) == 0) {
		
		r_value = oidc_util_encode_json_object(r, json, 0);
		
		rc = oidc_util_http_send(r, r_value, strlen(r_value), OIDC_CONTENT_TYPE_JSON, OK);
	} else if (apr_strnatcmp(OIDC_HOOK_INFO_FORMAT_HTML, s_format) == 0) {
		
		r_value = oidc_util_encode_json_object(r, json, JSON_INDENT(2));
		rc = oidc_util_html_send(r, "Session Info", NULL, NULL, apr_psprintf(r->pool, "<pre>%s</pre>", r_value), OK);
	}

	
	json_decref(json);

	return rc;
}


int oidc_handle_redirect_uri_request(request_rec *r, oidc_cfg *c, oidc_session_t *session) {

	if (oidc_proto_is_redirect_authorization_response(r, c)) {

		
		return oidc_handle_redirect_authorization_response(r, c, session);
		
	} else if (oidc_util_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_LOGOUT)) {
		
		return oidc_handle_logout(r, c, session);

	} else if (oidc_proto_is_post_authorization_response(r, c)) {

		
		return oidc_handle_post_authorization_response(r, c, session);

	} else if (oidc_is_discovery_response(r, c)) {

		
		return oidc_handle_discovery_response(r, c);

	} else if (oidc_util_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_JWKS)) {
		
		r->user = "";
		return OK;

	} else if (oidc_util_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_SESSION)) {

		
		return oidc_handle_session_management(r, c, session);

	} else if (oidc_util_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_REFRESH)) {

		
		return oidc_handle_refresh_token_request(r, c, session);

	} else if (oidc_util_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_REQUEST_URI)) {

		
		return oidc_handle_request_uri(r, c);

	} else if (oidc_util_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_REMOVE_AT_CACHE)) {

		
		return oidc_handle_remove_at_cache(r, c);

	} else if (oidc_util_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_INFO)) {

		if (session->remote_user == NULL)
			return HTTP_UNAUTHORIZED;

		
		r->user = "";
		return OK;

	} else if ((r->args == NULL) || (apr_strnatcmp(r->args, "") == 0)) {

		
		return oidc_proto_javascript_implicit(r, c);
	}

	

	
	if (oidc_util_request_has_parameter(r, OIDC_PROTO_ERROR)) {

		
		
		
		
		
		
		return oidc_handle_redirect_authorization_response(r, c, session);
	}

	oidc_error(r, "The OpenID Connect callback URL received an invalid request: %s; returning HTTP_INTERNAL_SERVER_ERROR", r->args);


	
	return oidc_util_html_send_error(r, c->error_template, "Invalid Request", apr_psprintf(r->pool, "The OpenID Connect callback URL received an invalid request"), HTTP_INTERNAL_SERVER_ERROR);


}






static int oidc_check_userid_openidc(request_rec *r, oidc_cfg *c) {

	if (oidc_get_redirect_uri(r, c) == NULL) {
		oidc_error(r, "configuration error: the authentication type is set to \"" OIDC_AUTH_TYPE_OPENID_CONNECT "\" but " OIDCRedirectURI " has not been set");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	
	if (!ap_is_initial_req(r)) {

		
		if (r->main != NULL)
			r->user = r->main->user;
		else if (r->prev != NULL)
			r->user = r->prev->user;

		if (r->user != NULL) {

			
			oidc_debug(r, "recycling user '%s' from initial request for sub-request", r->user);


			
			const char *s_id_token = oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_IDTOKEN);
			if (s_id_token == NULL) {

				oidc_session_t *session = NULL;
				oidc_session_load(r, &session);

				oidc_copy_tokens_to_request_state(r, session, NULL, NULL);

				
				oidc_session_free(r, session);
			}

			
			oidc_strip_cookies(r);

			return OK;
		}
		
	}

	int rc = OK;
	apr_byte_t needs_save = FALSE;

	
	oidc_session_t *session = NULL;
	oidc_session_load(r, &session);

	
	if (oidc_util_request_matches_url(r, oidc_get_redirect_uri(r, c))) {

		
		rc = oidc_handle_redirect_uri_request(r, c, session);

		
		oidc_session_free(r, session);

		return rc;

		
	} else if (session->remote_user != NULL) {

		
		rc = oidc_handle_existing_session(r, c, session, &needs_save);
		if (rc == OK) {

			
			if (needs_save) {
				if (oidc_session_save(r, session, FALSE) == FALSE) {
					oidc_warn(r, "error saving session");
					rc = HTTP_INTERNAL_SERVER_ERROR;
				}
			}
		}

		
		oidc_session_free(r, session);

		
		oidc_strip_cookies(r);

		return rc;
	}

	
	oidc_session_free(r, session);

	

	return oidc_handle_unauthenticated_user(r, c);
}


static int oidc_check_mixed_userid_oauth(request_rec *r, oidc_cfg *c) {

	
	const char *access_token = NULL;
	if (oidc_oauth_get_bearer_token(r, &access_token) == TRUE) {

		r->ap_auth_type = apr_pstrdup(r->pool, OIDC_AUTH_TYPE_OPENID_OAUTH20);
		return oidc_oauth_check_userid(r, c, access_token);
	}

	
	r->ap_auth_type = apr_pstrdup(r->pool, OIDC_AUTH_TYPE_OPENID_CONNECT);
	return oidc_check_userid_openidc(r, c);
}


int oidc_check_user_id(request_rec *r) {

	oidc_cfg *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	
	oidc_debug(r, "incoming request: \"%s?%s\", ap_is_initial_req(r)=%d", r->parsed_uri.path, r->args, ap_is_initial_req(r));

	
	const char *current_auth = ap_auth_type(r);
	if (current_auth == NULL)
		return DECLINED;

	
	if (strcasecmp(current_auth, OIDC_AUTH_TYPE_OPENID_CONNECT) == 0) {

		r->ap_auth_type = (char*) current_auth;
		return oidc_check_userid_openidc(r, c);
	}

	
	if (strcasecmp(current_auth, OIDC_AUTH_TYPE_OPENID_OAUTH20) == 0) {

		r->ap_auth_type = (char*) current_auth;
		return oidc_oauth_check_userid(r, c, NULL);
	}

	
	if (strcasecmp(current_auth, OIDC_AUTH_TYPE_OPENID_BOTH) == 0)
		return oidc_check_mixed_userid_oauth(r, c);

	
	return DECLINED;
}


static void oidc_authz_get_claims_and_idtoken(request_rec *r, json_t **claims, json_t **id_token) {

	const char *s_claims = oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_CLAIMS);
	if (s_claims != NULL)
		oidc_util_decode_json_object(r, s_claims, claims);

	const char *s_id_token = oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_IDTOKEN);
	if (s_id_token != NULL)
		oidc_util_decode_json_object(r, s_id_token, id_token);
}







static authz_status oidc_handle_unauthorized_user24(request_rec *r) {

	oidc_debug(r, "enter");

	oidc_cfg *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	if (apr_strnatcasecmp((const char*) ap_auth_type(r), OIDC_AUTH_TYPE_OPENID_OAUTH20) == 0) {
		oidc_debug(r, "setting environment variable %s to \"%s\" for usage in mod_headers", OIDC_OAUTH_BEARER_SCOPE_ERROR, OIDC_OAUTH_BEARER_SCOPE_ERROR_VALUE);
		apr_table_set(r->subprocess_env, OIDC_OAUTH_BEARER_SCOPE_ERROR, OIDC_OAUTH_BEARER_SCOPE_ERROR_VALUE);
		return AUTHZ_DENIED;
	}

	
	switch (oidc_dir_cfg_unautz_action(r)) {
		
		case OIDC_UNAUTZ_RETURN403:
		case OIDC_UNAUTZ_RETURN401:
			return AUTHZ_DENIED;
			break;
		case OIDC_UNAUTZ_AUTHENTICATE:
			
			if (oidc_is_xml_http_request(r) == TRUE)
				return AUTHZ_DENIED;
			break;
	}

	oidc_authenticate_user(r, c, NULL, oidc_get_current_url(r), NULL, NULL, NULL, oidc_dir_cfg_path_auth_request_params(r), oidc_dir_cfg_path_scope(r));

	if (oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_DISCOVERY) != NULL)
		return AUTHZ_GRANTED;

	const char *location = oidc_util_hdr_out_location_get(r);
	if (location != NULL) {
		oidc_debug(r, "send HTML refresh with authorization redirect: %s", location);

		char *html_head = apr_psprintf(r->pool, "<meta http-equiv=\"refresh\" content=\"0; url=%s\">", location);
		oidc_util_html_send(r, "Stepup Authentication", html_head, NULL, NULL, HTTP_UNAUTHORIZED);
		
		r->header_only = 1;
	}

	return AUTHZ_DENIED;
}


authz_status oidc_authz_checker(request_rec *r, const char *require_args, const void *parsed_require_args, oidc_authz_match_claim_fn_type match_claim_fn) {


	oidc_debug(r, "enter: require_args=\"%s\"", require_args);

	
	if (r->user != NULL && strlen(r->user) == 0) {
		r->user = NULL;
		if (oidc_dir_cfg_unauth_action(r) == OIDC_UNAUTH_PASS)
			return AUTHZ_GRANTED;
		if (oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_DISCOVERY) != NULL)
			return AUTHZ_GRANTED;
	}

	
	json_t *claims = NULL, *id_token = NULL;
	oidc_authz_get_claims_and_idtoken(r, &claims, &id_token);

	
	if (claims)
		oidc_util_json_merge(r, id_token, claims);

	
	authz_status rc = oidc_authz_worker24(r, claims ? claims : id_token, require_args, parsed_require_args, match_claim_fn);

	
	if (claims)
		json_decref(claims);
	if (id_token)
		json_decref(id_token);

	if ((rc == AUTHZ_DENIED) && ap_auth_type(r))
		rc = oidc_handle_unauthorized_user24(r);

	return rc;
}

authz_status oidc_authz_checker_claim(request_rec *r, const char *require_args, const void *parsed_require_args) {
	return oidc_authz_checker(r, require_args, parsed_require_args, oidc_authz_match_claim);
}


authz_status oidc_authz_checker_claims_expr(request_rec *r, const char *require_args, const void *parsed_require_args) {
	return oidc_authz_checker(r, require_args, parsed_require_args, oidc_authz_match_claims_expr);
}





static int oidc_handle_unauthorized_user22(request_rec *r) {

	oidc_cfg *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	if (apr_strnatcasecmp((const char *) ap_auth_type(r), OIDC_AUTH_TYPE_OPENID_OAUTH20) == 0) {
		oidc_oauth_return_www_authenticate(r, "insufficient_scope", "Different scope(s) or other claims required");
		return HTTP_UNAUTHORIZED;
	}

	
	switch (oidc_dir_cfg_unautz_action(r)) {
	case OIDC_UNAUTZ_RETURN403:
		return HTTP_FORBIDDEN;
	case OIDC_UNAUTZ_RETURN401:
		return HTTP_UNAUTHORIZED;
	case OIDC_UNAUTZ_AUTHENTICATE:
		
		if (oidc_is_xml_http_request(r) == TRUE)
			return HTTP_UNAUTHORIZED;
	}

	return oidc_authenticate_user(r, c, NULL, oidc_get_current_url(r), NULL, NULL, NULL, oidc_dir_cfg_path_auth_request_params(r), oidc_dir_cfg_path_scope(r));
}


int oidc_auth_checker(request_rec *r) {

	oidc_cfg *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);

	
	if (r->user != NULL && strlen(r->user) == 0) {
		r->user = NULL;
		if (oidc_dir_cfg_unauth_action(r) == OIDC_UNAUTH_PASS)
			return OK;
		if if (oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_DISCOVERY) != NULL)
			return OK;
	}

	
	json_t *claims = NULL, *id_token = NULL;
	oidc_authz_get_claims_and_idtoken(r, &claims, &id_token);

	
	const apr_array_header_t * const reqs_arr = ap_requires(r);

	
	const require_line * const reqs = reqs_arr ? (require_line *) reqs_arr->elts : NULL;
	if (!reqs_arr) {
		oidc_debug(r, "no require statements found, so declining to perform authorization.");
		return DECLINED;
	}

	
	if (claims)
		oidc_util_json_merge(r, id_token, claims);

	
	int rc = oidc_authz_worker22(r, claims ? claims : id_token, reqs, reqs_arr->nelts);

	
	if (claims)
		json_decref(claims);
	if (id_token)
		json_decref(id_token);

	if ((rc == HTTP_UNAUTHORIZED) && ap_auth_type(r))
		rc = oidc_handle_unauthorized_user22(r);

	return rc;
}



apr_byte_t oidc_enabled(request_rec *r) {
	if (ap_auth_type(r) == NULL)
		return FALSE;

	if (apr_strnatcasecmp((const char*) ap_auth_type(r), OIDC_AUTH_TYPE_OPENID_CONNECT) == 0)
		return TRUE;

	if (apr_strnatcasecmp((const char*) ap_auth_type(r), OIDC_AUTH_TYPE_OPENID_OAUTH20) == 0)
		return TRUE;

	if (apr_strnatcasecmp((const char*) ap_auth_type(r), OIDC_AUTH_TYPE_OPENID_BOTH) == 0)
		return TRUE;

	return FALSE;
}

int oidc_content_handler(request_rec *r) {
	oidc_cfg *c = ap_get_module_config(r->server->module_config, &auth_openidc_module);
	int rc = DECLINED;
	
	apr_byte_t needs_save = FALSE;
	oidc_session_t *session = NULL;

	if (oidc_enabled(r) == TRUE) {

		if (oidc_util_request_matches_url(r, oidc_get_redirect_uri(r, c)) == TRUE) {

			if (oidc_util_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_INFO)) {

				oidc_session_load(r, &session);

				rc = oidc_handle_existing_session(r, c, session, &needs_save);
				if (rc == OK)
					
					rc = oidc_handle_info_request(r, c, session, needs_save);

				
				oidc_session_free(r, session);

			} else if (oidc_util_request_has_parameter(r, OIDC_REDIRECT_URI_REQUEST_JWKS)) {

				
				rc = oidc_handle_jwks(r, c);

			} else {

				rc = OK;

			}

		} else if (oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_DISCOVERY) != NULL) {

			rc = oidc_discovery(r, c);

		} else if (oidc_request_state_get(r, OIDC_REQUEST_STATE_KEY_AUTHN) != NULL) {

			rc = OK;

		}

	}

	return rc;
}

extern const command_rec oidc_config_cmds[];

module AP_MODULE_DECLARE_DATA auth_openidc_module = {
		STANDARD20_MODULE_STUFF, oidc_create_dir_config, oidc_merge_dir_config, oidc_create_server_config, oidc_merge_server_config, oidc_config_cmds, oidc_register_hooks };






