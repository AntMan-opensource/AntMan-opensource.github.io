





































using namespace std ;
 
namespace {
    unsigned int json_allocs = 0 ;
    unsigned int json_bytes = 0 ;
    std::mutex  json_lock ;
} ;

namespace drachtio {
    
    typedef std::unordered_map<string,tag_type_t> mapHdr2Tag ;

    typedef std::unordered_set<string> setHdr ;

    typedef std::unordered_map<string,sip_method_t> mapMethod2Type ;

	
	mapHdr2Tag m_mapHdr2Tag({
		{string("user_agent"), siptag_user_agent_str},  {string("subject"), siptag_subject_str}, {string("max_forwards"), siptag_max_forwards_str}, {string("proxy_require"), siptag_proxy_require_str}, {string("accept_contact"), siptag_accept_contact_str}, {string("reject_contact"), siptag_reject_contact_str}, {string("expires"), siptag_expires_str}, {string("date"), siptag_date_str}, {string("retry_after"), siptag_retry_after_str}, {string("timestamp"), siptag_timestamp_str}, {string("min_expires"), siptag_min_expires_str}, {string("priority"), siptag_priority_str}, {string("call_info"), siptag_call_info_str}, {string("organization"), siptag_organization_str}, {string("server"), siptag_server_str}, {string("in_reply_to"), siptag_in_reply_to_str}, {string("accept"), siptag_accept_str}, {string("accept_encoding"), siptag_accept_encoding_str}, {string("accept_language"), siptag_accept_language_str}, {string("allow"), siptag_allow_str}, {string("require"), siptag_require_str}, {string("supported"), siptag_supported_str}, {string("unsupported"), siptag_unsupported_str}, {string("event"), siptag_event_str}, {string("allow_events"), siptag_allow_events_str}, {string("subscription_state"), siptag_subscription_state_str}, {string("proxy_authenticate"), siptag_proxy_authenticate_str}, {string("proxy_authentication_info"), siptag_proxy_authentication_info_str}, {string("proxy_authorization"), siptag_proxy_authorization_str}, {string("authorization"), siptag_authorization_str}, {string("www_authenticate"), siptag_www_authenticate_str}, {string("authentication_info"), siptag_authentication_info_str}, {string("error_info"), siptag_error_info_str}, {string("warning"), siptag_warning_str}, {string("refer_to"), siptag_refer_to_str}, {string("referred_by"), siptag_referred_by_str}, {string("replaces"), siptag_replaces_str}, {string("session_expires"), siptag_session_expires_str}, {string("min_se"), siptag_min_se_str}, {string("path"), siptag_path_str}, {string("service_route"), siptag_service_route_str}, {string("reason"), siptag_reason_str}, {string("security_client"), siptag_security_client_str}, {string("security_server"), siptag_security_server_str}, {string("security_verify"), siptag_security_verify_str}, {string("privacy"), siptag_privacy_str}, {string("sip_etag"), siptag_etag_str}, {string("sip_if_match"), siptag_if_match_str}, {string("mime_version"), siptag_mime_version_str}, {string("content_type"), siptag_content_type_str}, {string("content_encoding"), siptag_content_encoding_str}, {string("content_language"), siptag_content_language_str}, {string("content_disposition"), siptag_content_disposition_str}, {string("request_disposition"), siptag_request_disposition_str}, {string("error"), siptag_error_str}, {string("refer_sub"), siptag_refer_sub_str}, {string("alert_info"), siptag_alert_info_str}, {string("reply_to"), siptag_reply_to_str}, {string("p_asserted_identity"), siptag_p_asserted_identity_str}, {string("p_preferred_identity"), siptag_p_preferred_identity_str}, {string("remote_party_id"), siptag_remote_party_id_str}, {string("payload"), siptag_payload_str}, {string("from"), siptag_from_str}, {string("to"), siptag_to_str}, {string("call_id"), siptag_call_id_str}, {string("cseq"), siptag_cseq_str}, {string("via"), siptag_via_str}, {string("route"), siptag_route_str}, {string("contact"), siptag_contact_str}, {string("from"), siptag_from_str}, {string("to"), siptag_to_str}, {string("rseq"), siptag_rseq_str}, {string("rack"), siptag_rack_str}, {string("record_route"), siptag_record_route_str}, {string("content_length"), siptag_content_length_str}









































































	});

	
	setHdr m_setImmutableHdrs({
        {string("via")}, {string("route")}, {string("rseq")}, {string("record_route")}, {string("content_length")}



	});

   mapMethod2Type m_mapMethod2Type({
        {string("INVITE"), sip_method_invite}, {string("ACK"), sip_method_ack}, {string("CANCEL"), sip_method_cancel}, {string("BYE"), sip_method_bye}, {string("OPTIONS"), sip_method_options}, {string("REGISTER"), sip_method_register}, {string("INFO"), sip_method_info}, {string("PRACK"), sip_method_prack}, {string("UPDATE"), sip_method_update}, {string("MESSAGE"), sip_method_message}, {string("SUBSCRIBE"), sip_method_subscribe}, {string("NOTIFY"), sip_method_notify}, {string("REFER"), sip_method_refer}, {string("PUBLISH"), sip_method_publish}












    });


	bool isImmutableHdr( const string& hdr ) {
		return m_setImmutableHdrs.end() != m_setImmutableHdrs.find( hdr ) ;
	}

	bool getTagTypeForHdr( const string& hdr, tag_type_t& tag ) {
		mapHdr2Tag::const_iterator it = m_mapHdr2Tag.find( hdr ) ;
		if( it != m_mapHdr2Tag.end() ) {
		    tag = it->second ;
		    return true ;
		}		
		return false ;
	}

	void getSourceAddressForMsg(msg_t *msg, string& host) {
        char name[SU_ADDRSIZE] = "";
        su_sockaddr_t const *su = msg_addr(msg);
        su_inet_ntop(su->su_family, SU_ADDR(su), name, sizeof(name));
        host.assign(name);
    }

    void makeUniqueSipTransactionIdentifier(sip_t* sip, string& str) {
        str = sip->sip_call_id->i_id ;
        str.append("|") ;
        str.append((sip->sip_request && sip_method_cancel == sip->sip_request->rq_method) ? "INVITE" :
          sip->sip_cseq->cs_method_name) ;
        str.append("|") ;
        str.append( boost::lexical_cast<std::string>(sip->sip_cseq->cs_seq) ) ;
    }

	void generateUuid(string& uuid) {

	    boost::uuids::uuid id = boost::uuids::random_generator()();
        uuid = boost::lexical_cast<string>(id) ;

        su_guid_t guid[1];
        char b[su_guid_strlen + 1] ;

        su_guid_generate(guid);

        
        su_guid_sprintf(b, su_guid_strlen + 1, guid);
        uuid.assign( b ) ;


    }	

    void getTransportDescription( const tport_t* tp, string& desc ) {
        if( tp ) {
            const tp_name_t* tn = tport_name(tp) ;
            char name[255] ;
            sprintf(name, TPN_FORMAT, TPN_ARGS(tn) ) ;
            desc.assign( name ) ;            
        }
    }
    bool parseTransportDescription( const string& desc, string& proto, string& host, string& port ) {
        try {
            std::regex re("^(.*)/(.*):(\\d+)");
            std::smatch mr;
            if (std::regex_search(desc, mr, re) && mr.size() > 1) {
                proto = mr[1] ;
                host = mr[2] ;
                port = mr[3] ;
                return true ;  
            }
        } catch (std::regex_error& e) {
            DR_LOG(log_error) << "parseTransportDescription - regex error: " << e.what();
        }
        return false;
    }
    bool parseSipUri(const string& uri, string& scheme, string& userpart, string& hostpart, string& port,  vector< pair<string,string> >& params) {

        try {
            std::regex re("^<?(sip|sips):(?:([^;]+)@)?([^;|^>|^:]+)(?::(\\d+))?(?:;([^>]+))?>?$");
            std::regex re2("^<?(sip|sips):(?:([^;]+)@)?(\\[[0-9a-fA-F:]+\\])(?::(\\d+))?(?:;([^>]+))?>?$");
            std::smatch mr;
            if (std::regex_search(uri, mr, re) || std::regex_search(uri, mr, re2)) {
                scheme = mr[1] ;
                userpart = mr[2] ;
                hostpart = mr[3] ;
                port = mr[4] ; 

                string paramString = mr[5] ;
                if (paramString.length() > 0) {
                  vector<string> strs;
                  boost::split(strs, paramString, boost::is_any_of(";"));
                  for (vector<string>::iterator it = strs.begin(); it != strs.end(); ++it) {
                    vector<string> kv ;
                    boost::split(kv, *it, boost::is_any_of("="));
                    std::pair<string, string> kvpair(kv[0], kv.size() == 2 ? kv[1] : "");
                    params.push_back(kvpair);
                  }
                }
                return true ;
            }
        } catch (std::regex_error& e) {
            DR_LOG(log_error) << "parseSipUri - regex error: " << e.what();
        }
        return false;
    }

	void parseGenericHeader( msg_common_t* p, string& hvalue) {
		string str((const char*) p->h_data, p->h_len) ;
		boost::char_separator<char> sep(": \r\n") ;
        tokenizer tok( str, sep) ;
        if( std::distance( tok.begin(), tok.end() ) > 1 ) hvalue = *(++tok.begin() ) ;
 	}

    bool FindCSeqMethod( const string& headers, string& method ) {
        try {
            std::regex re("^CSeq:\\s+\\d+\\s+(\\w+)$");
            std::smatch mr;
            if (std::regex_search(headers, mr, re) && mr.size() > 1) {
                method = mr[1] ;
                return true ;                
            }
        } catch (std::regex_error& e) {
            DR_LOG(log_error) << "FindCSeqMethod - regex error: " << e.what();
        }
        return false;
    }

    void EncodeStackMessage( const sip_t* sip, string& encodedMessage ) {
        encodedMessage.clear() ;
        const sip_common_t* p = NULL ;
        if( sip->sip_request ) {
            sip_header_t* hdr = (sip_header_t *) sip->sip_request ;
            p = hdr->sh_common ;
        }
        else if( sip->sip_status ) {
            sip_header_t* hdr = (sip_header_t *) sip->sip_status ;
            p = hdr->sh_common ;
        }

        while( NULL != p) {
            if( NULL != p->h_data ) {
                
               encodedMessage.append( (char *)p->h_data, p->h_len ) ;            
            }
            else {
                
                char buf[8192] ;
                issize_t n = msg_header_e(buf, 8192, reinterpret_cast<const msg_header_t *>(p), 0) ;
                encodedMessage.append( buf, n ) ;
            }
            p = p->h_succ->sh_common ;
        }
    }

    bool normalizeSipUri( std::string& uri, int brackets ) {
        su_home_t* home = theOneAndOnlyController->getHome() ;
        char *s ;
        char buf[255];
        char obuf[255] ;
        char hp[64] ;
        char const *display = NULL;
        url_t url[1];
        msg_param_t const *params = NULL;
        char const *comment = NULL;
        int rc ;

        
        s = strncpy( buf, uri.c_str(), 255 ) ;

        
        rc = sip_name_addr_d(home, &s, &display, url, &params, &comment) ;
        if( rc < 0 ) {  
            
            return false ;
        }

        
        if( NULL == url->url_scheme && NULL == url->url_user && NULL != url->url_host ) {
            url->url_scheme = "sip" ;
            url->url_user = url->url_host ;
            url->url_host = "localhost" ;   
         }

        
        int nChars = sip_name_addr_e(obuf, 255, 0, display, brackets, url, params, comment) ;

        
        if( params ) {
            su_free(home, (void *) params) ;
        }

        if( nChars <= 0 ) {
            return false ;
        }
        uri.assign( obuf ) ;
        return true ;
    }

    bool replaceHostInUri( std::string& uri, const char* szHost, const char* szPort ) {
        su_home_t* home = theOneAndOnlyController->getHome() ;
        char *s ;
        char buf[255];
        char obuf[255] ;
        char hp[64] ;
        char const *display = NULL;
        url_t url[1];
        msg_param_t const *params = NULL;
        char const *comment = NULL;
        int rc ;

        
        s = strncpy( buf, uri.c_str(), 255 ) ;

        
        rc = sip_name_addr_d(home, &s, &display, url, &params, &comment) ;
        if( rc < 0 ) {  
            
            return false ;
        }

        
        url->url_host = szHost ;
        url->url_port = szPort ;

        
        int nChars = sip_name_addr_e(obuf, 255, 0, display, 1, url, params, comment) ;

        
        if( params ) {
            su_free(home, (void *) params) ;
        }

        if( nChars <= 0 ) {
            return false ;
        }
        uri.assign( obuf ) ;
        return true ;
    }

    sip_method_t methodType( const string& method ) {
        mapMethod2Type::const_iterator it = m_mapMethod2Type.find( method ) ;
        if( m_mapMethod2Type.end() == it ) return sip_method_unknown ;
        return it->second ;
    }
 
    bool isLocalSipUri( const string& requestUri ) {

        static bool initialized = false ;
        static vector< pair<string, string> > vecLocalUris ;

        DR_LOG(log_debug) << "isLocalSipUri: checking to see if this is one of mine: " << requestUri ;

        if( !initialized ) {
            initialized = true ;

            nta_agent_t* agent = theOneAndOnlyController->getAgent() ;
            tport_t *t = nta_agent_tports( agent ) ;
            for (tport_t* tport = t; tport; tport = tport_next(tport) ) {
                const tp_name_t* tpn = tport_name( tport );
                if( 0 == strcmp( tpn->tpn_host, "*") ) 
                    continue ;

                string localUri = tpn->tpn_host ;
                string localPort = NULL != tpn->tpn_port ? tpn->tpn_port : "5060" ;

                


                vecLocalUris.push_back(make_pair(localUri, localPort)) ;

                if( 0 == strcmp(tpn->tpn_host,"127.0.0.1") ) {
                    vecLocalUris.push_back(make_pair("localhost", localPort)) ;
                }
            }

            
            vector< pair<string, string> > vecIps ;
            SipTransport::getAllExternalContacts(vecIps) ;
            for(vector< pair<string, string> >::const_iterator it = vecIps.begin(); it != vecIps.end(); ++it) {
                vecLocalUris.push_back(*it) ;
            }
       }

       if( 0 == requestUri.find("tel:")) {
        DR_LOG(log_debug) << "isLocalSipUri: tel: scheme, so we are  assuming it is not local (will cause it to be carried forward in proxy request): " << requestUri ;
        return false;
       }

        su_home_t* home = theOneAndOnlyController->getHome() ;
        char *s ;
        char buf[255];
        char const *display = NULL;
        url_t url[1];
        msg_param_t const *params = NULL;
        char const *comment = NULL;
        int rc ;

        
        s = strncpy( buf, requestUri.c_str(), 255 ) ;

        
        rc = sip_name_addr_d(home, &s, &display, url, &params, &comment) ;
        if( rc < 0 ) {  
            
            return false ;
        }

        
        if( params ) {
            su_free(home, (void *) params) ;
        }

        for(vector< pair<string, string> >::const_iterator it = vecLocalUris.begin(); it != vecLocalUris.end(); ++it) {
            string host = it->first ;
            string port = it->second ;

            if (port.empty()) port = "5060";

            

            if ((0 == host.compare(url->url_host)) && ( (!url->url_port && 0 == port.compare("5060")) || (url->url_port && 0 == port.compare(url->url_port)))

            ) {
                return true ;
            }
        }
        return false ;
    }

    void* my_json_malloc( size_t bytes ) {
        std::lock_guard<std::mutex> l( json_lock ) ;

        json_allocs++ ;
        json_bytes += bytes ;
        

        
        void *ptr = malloc( bytes + 8 ) ;
        *((size_t *)ptr) = bytes ;
 
        return (void*) ((char*) ptr + 8);
    }

    void my_json_free( void* ptr ) {
       std::lock_guard<std::mutex> l( json_lock ) ;

        size_t size;
        ptr = (void *) ((char *) ptr - 8) ;
        size = *((size_t *)ptr);

        json_allocs-- ;
        json_bytes -= size ;
        

        
        memset( ptr, 0, size + 8 ) ;

    }

    void splitLines( const string& s, vector<string>& vec ) {
        if( s.length() ) {
            split( vec, s, boost::is_any_of("\r\n"), boost::token_compress_on ); 
        }
    }

    void splitTokens( const string& s, vector<string>& vec ) {
        split( vec, s, boost::is_any_of("|") ); 
    }

    void splitMsg( const string& msg, string& meta, string& startLine, string& headers, string& body ) {
        size_t pos = msg.find( DR_CRLF ) ;
        if( string::npos == pos ) {
            meta = msg ;
            return ;
        }
        meta = msg.substr(0, pos) ;
        string chunk = msg.substr(pos+DR_CRLF.length()) ;

        pos = chunk.find( DR_CRLF2 ) ;
        if( string::npos != pos  ) {
            body = chunk.substr( pos + DR_CRLF2.length() ) ;
            chunk = chunk.substr( 0, pos ) ;
        }

        pos = chunk.find( DR_CRLF ) ;
        if( string::npos == pos ) {
            startLine = chunk ;
        }
        else {
            startLine = chunk.substr(0, pos) ;
            headers = chunk.substr(pos + DR_CRLF.length()) ;
        }
    }

    sip_method_t parseStartLine( const string& startLine, string& methodName, string& requestUri ) {
        boost::char_separator<char> sep(" ");
        boost::tokenizer< boost::char_separator<char> > tokens(startLine, sep);
        int i = 0 ;
        sip_method_t method = sip_method_invalid ;
        BOOST_FOREACH (const string& t, tokens) {
            switch( i++ ) {
                case 0:
                    methodName = t ;
                    if( 0 == t.compare("INVITE") ) method = sip_method_invite ;
                    else if( 0 == t.compare("ACK") ) method = sip_method_ack ;
                    else if( 0 == t.compare("PRACK") ) method = sip_method_prack ;
                    else if( 0 == t.compare("CANCEL") ) method = sip_method_cancel ;
                    else if( 0 == t.compare("BYE") ) method = sip_method_bye ;
                    else if( 0 == t.compare("OPTIONS") ) method = sip_method_options ;
                    else if( 0 == t.compare("REGISTER") ) method = sip_method_register ;
                    else if( 0 == t.compare("INFO") ) method = sip_method_info ;
                    else if( 0 == t.compare("UPDATE") ) method = sip_method_update ;
                    else if( 0 == t.compare("MESSAGE") ) method = sip_method_message ;
                    else if( 0 == t.compare("SUBSCRIBE") ) method = sip_method_subscribe ;
                    else if( 0 == t.compare("NOTIFY") ) method = sip_method_notify ;
                    else if( 0 == t.compare("REFER") ) method = sip_method_refer ;
                    else if( 0 == t.compare("PUBLISH") ) method = sip_method_publish ;
                    else method = sip_method_unknown ;
                    break ;

                case 1:
                    requestUri = t ;
                    break ;

                default:
                break ;
            }
        }
        return method ;
    }

    bool GetValueForHeader( const string& headers, const char *szHeaderName, string& headerValue ) {
        vector<string> vec ;
        splitLines( headers, vec ) ;
        for( std::vector<string>::const_iterator it = vec.begin(); it != vec.end(); ++it )  {
            string hdrName ;
            size_t pos = (*it).find_first_of(":") ;
            if( string::npos != pos ) {
                hdrName = (*it).substr(0,pos) ;
                boost::trim( hdrName );

                if( boost::iequals( hdrName, szHeaderName ) ) {
                    headerValue = (*it).substr(pos+1) ;
                    boost::trim( headerValue ) ;    
                    return true ;                
                }
            }
        }
        return false ;
    }
    void deleteTags( tagi_t* tags ) {
        if (!tags) return;
        int i = 0 ;
        while( tags[i].t_tag != tag_null ) {
            if( tags[i].t_value ) {
                char *p = (char *) tags[i].t_value ;
                delete [] p ;
            }
             i++ ;
        }       
        delete [] tags ; 
    }

    tagi_t* makeSafeTags( const string&  hdrs) {
        vector<string> vec ;
        
        splitLines( hdrs, vec ) ;
        int nHdrs = vec.size() ;
        tagi_t *tags = new tagi_t[nHdrs+1] ;
        int i = 0; 
        for( std::vector<string>::const_iterator it = vec.begin(); it != vec.end(); ++it )  {
            tags[i].t_tag = tag_skip ;
            tags[i].t_value = (tag_value_t) 0 ;                     
            bool bValid = true ;
            string hdrName, hdrValue ;

            
            size_t pos = (*it).find_first_of(":") ;
            if( string::npos == pos ) {
                bValid = false ;
            }
            else {
                hdrName = (*it).substr(0,pos) ;
                boost::trim( hdrName );
                if( string::npos != hdrName.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890-_") ) {
                    bValid = false ;
                }
                else {
                    hdrValue = (*it).substr(pos+1) ;
                    boost::trim( hdrValue ) ;
                }
            }
            if( !bValid ) {
                DR_LOG(log_error) << "makeTags - invalid header: '" << *it << "'"  ;
                i++ ;
                continue ;
            }
            else if( string::npos != hdrValue.find(DR_CRLF) ) {
                DR_LOG(log_error) << "SipDialogController::makeTags - client supplied invalid custom header value (contains CR or LF) for header '" << hdrName << "'" ;
                i++ ;
                continue ;
            }

            
            tag_type_t tt ;
            string hdr = boost::to_lower_copy( boost::replace_all_copy( hdrName, "-", "_" ) );
            if( isImmutableHdr( hdr ) ) {
                if( 0 != hdr.compare("content_length") ) {
                    DR_LOG(log_debug) << "makeTags - discarding header because client is not allowed to set dialog-level headers: '" << hdrName  ;
                }
            }
            else if( getTagTypeForHdr( hdr, tt ) ) {
                
                
                
                if( 0 == hdr.compare("from") ||  0 == hdr.compare("contact") || 0 == hdr.compare("to") || 0 == hdr.compare("p_asserted_identity") ) {



                    DR_LOG(log_debug) << "makeSafeTags - hdr '" << hdrName << "' can not be modified";
                }
                else {
                    int len = hdrValue.length() ;
                    char *p = new char[len+1] ;
                    memset(p, '\0', len+1) ;
                    strncpy( p, hdrValue.c_str(), len ) ;
                    tags[i].t_tag = tt;
                    tags[i].t_value = (tag_value_t) p ;
                    DR_LOG(log_debug) << "makeTags - Adding well-known header '" << hdrName << "' with value '" << p << "'"  ;
                }
            }
            else {
                
                int len = (*it).length() ;                  
                char *p = new char[len+1] ;
                memset(p, '\0', len+1) ;
                strncpy( p, (*it).c_str(), len) ;

                tags[i].t_tag = siptag_unknown_str ;
                tags[i].t_value = (tag_value_t) p ;
                DR_LOG(log_debug) << "makeTags - custom header: '" << hdrName << "', value: " << hdrValue  ;  
            }
            i++ ;
        }
        tags[nHdrs].t_tag = tag_null ;
        tags[nHdrs].t_value = (tag_value_t) 0 ;       

        return tags ;   
    }

    tagi_t* makeTags( const string&  hdrs, const string& transport, const char* szExternalIP ) {
        vector<string> vec ;
        string proto, host, port, myHostport ;
        
        parseTransportDescription(transport, proto, host, port ) ;

        if (szExternalIP) {
            host = szExternalIP;
            DR_LOG(log_debug) << "makeTags - using external IP as replacement for 'localhost': " << szExternalIP  ;
        }

        splitLines( hdrs, vec ) ;
        int nHdrs = vec.size() ;
        tagi_t *tags = new tagi_t[nHdrs+1] ;
        int i = 0; 
        for( std::vector<string>::const_iterator it = vec.begin(); it != vec.end(); ++it )  {
            tags[i].t_tag = tag_skip ;
            tags[i].t_value = (tag_value_t) 0 ;                     
            bool bValid = true ;
            string hdrName, hdrValue ;

            
            size_t pos = (*it).find_first_of(":") ;
            if( string::npos == pos ) {
                bValid = false ;
            }
            else {
                hdrName = (*it).substr(0,pos) ;
                boost::trim( hdrName );
                if( string::npos != hdrName.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890-_") ) {
                    bValid = false ;
                }
                else {
                    hdrValue = (*it).substr(pos+1) ;
                    boost::trim( hdrValue ) ;
                }
            }
            if( !bValid ) {
                DR_LOG(log_error) << "makeTags - invalid header: '" << *it << "'"  ;
                i++ ;
                continue ;
            }
            else if( string::npos != hdrValue.find(DR_CRLF) ) {
                DR_LOG(log_error) << "SipDialogController::makeTags - client supplied invalid custom header value (contains CR or LF) for header '" << hdrName << "'" ;
                i++ ;
                continue ;
            }

            
            tag_type_t tt ;
            string hdr = boost::to_lower_copy( boost::replace_all_copy( hdrName, "-", "_" ) );
            if( isImmutableHdr( hdr ) ) {
                if( 0 != hdr.compare("content_length") ) {
                    DR_LOG(log_debug) << "makeTags - discarding header because client is not allowed to set dialog-level headers: '" << hdrName  ;
                }
            }
            else if( getTagTypeForHdr( hdr, tt ) ) {
                
                
                
                if( string::npos != hdrValue.find("@localhost") && (0 == hdr.compare("from") ||  0 == hdr.compare("contact") || 0 == hdr.compare("to") || 0 == hdr.compare("p_asserted_identity") ) ) {



                    DR_LOG(log_debug) << "makeTags - hdr '" << hdrName << "' replacing host with " << host;
                    replaceHostInUri( hdrValue, host.c_str(), port.c_str() ) ;
                }
                int len = hdrValue.length() ;
                char *p = new char[len+1] ;
                memset(p, '\0', len+1) ;
                strncpy( p, hdrValue.c_str(), len ) ;
                tags[i].t_tag = tt;
                tags[i].t_value = (tag_value_t) p ;
                DR_LOG(log_debug) << "makeTags - Adding well-known header '" << hdrName << "' with value '" << p << "'"  ;
            }
            else {
                
                int len = (*it).length() ;                  
                char *p = new char[len+1] ;
                memset(p, '\0', len+1) ;
                strncpy( p, (*it).c_str(), len) ;

                tags[i].t_tag = siptag_unknown_str ;
                tags[i].t_value = (tag_value_t) p ;
                DR_LOG(log_debug) << "makeTags - custom header: '" << hdrName << "', value: " << hdrValue  ;  
            }

            i++ ;
        }
        tags[nHdrs].t_tag = tag_null ;
        tags[nHdrs].t_value = (tag_value_t) 0 ;       

        return tags ;   
    }
 	bool isRfc1918(const char* szHost) {
        string str = szHost;
        boost::char_separator<char> sep(".") ;
        tokenizer tok(str, sep) ;
        vector<int> vec;
        for (tokenizer::iterator it = tok.begin(); it != tok.end(); it++) {
            try {
                vec.push_back(boost::lexical_cast<int>(*it));
            }
            catch (boost::bad_lexical_cast &e) {
                
                DR_LOG(log_debug) << "isRfc1918: hostname '" << szHost << "' is not dot decimal: " << e.what();
                return false;
            }
        }
        if (vec.size() == 4) {

            
            if (vec[0] == 10) return true;

            
            if (vec[0] == 172 && (vec[1] > 15 || vec[1] < 32)) return true;

            
            if (vec[0] == 192 && vec[1] == 168) return true;
        }
        return false;
     }

	bool sipMsgHasNatEqualsYes( const sip_t* sip, bool weAreUac, bool checkContact ) {
        if (!sip->sip_record_route && !checkContact) return false;

        if (sip->sip_record_route) {
            sip_record_route_t *r = sip->sip_record_route;

            if (weAreUac) {
                for (; r; r = r->r_next) {
                    if (r->r_next == NULL) break ;
                }
            }
            if (r && r->r_url->url_params && NULL != ::strstr(r->r_url->url_params, "nat=yes")) {
                return true;
            }
        }

        if (checkContact && !sip->sip_record_route) {
            if (sip->sip_contact && sip->sip_contact->m_url->url_params && NULL != ::strstr(sip->sip_contact->m_url->url_params, "nat=yes")) {

                
                return true;
            }
        }
        return false;
    }

    string urlencode(const string &s) {
        static const char lookup[]= "0123456789abcdef";
        std::stringstream e;
        for(int i=0, ix=s.length(); i<ix; i++)
        {
            const char& c = s[i];
            if ( (48 <= c && c <= 57) || (65 <= c && c <= 90) || (97 <= c && c <= 122) || (c=='-' || c=='_' || c=='.' || c=='~')


            )
            {
                e << c;
            }
            else {
                e << '%';
                e << lookup[ (c&0xF0)>>4 ];
                e << lookup[ (c&0x0F) ];
            }
        }
        return e.str();
    }

    SipMsgData_t::SipMsgData_t(const string& str ) {
        boost::char_separator<char> sep(" []//:") ;
        tokenizer tok( str, sep) ;
        tokenizer::iterator it = tok.begin() ;

        m_source = 0 == (*it).compare("recv") ? "network" : "application" ;
        it++ ;
        m_bytes = *(it) ;
        it++; it++; it++ ;
        m_protocol = *(it) ;
        m_address = *(++it) ;
        m_port = *(++it) ;
        it++ ;  
        string t = *(++it) + ":" + *(++it) + ":" + *(++it) + "." + *(++it) ;
        m_time = t.substr(0, t.size()-2);
    }

    SipMsgData_t::SipMsgData_t( msg_t* msg ) : m_source("network") {
        su_time_t now = su_now() ;
        unsigned short second, minute, hour;
        char time[64] ;
        tport_t *tport = nta_incoming_transport(theOneAndOnlyController->getAgent(), NULL, msg) ;        
        assert(NULL != tport) ;

        second = (unsigned short)(now.tv_sec % 60);
        minute = (unsigned short)((now.tv_sec / 60) % 60);
        hour = (unsigned short)((now.tv_sec / 3600) % 24);
        sprintf(time, "%02u:%02u:%02u.%06lu", hour, minute, second, now.tv_usec) ;
 
        m_time.assign( time ) ;
        if( tport_is_udp(tport ) ) m_protocol = "udp" ;
        else if( tport_has_tls( tport ) ) m_protocol = "tls" ;
        else if( tport_is_tcp( tport)  ) m_protocol = "tcp" ;

        tport_unref( tport ) ;

        init( msg ) ;
    }
    SipMsgData_t::SipMsgData_t( msg_t* msg, nta_incoming_t* irq, const char* source ) : m_source(source) {
        su_time_t now = su_now() ;
        unsigned short second, minute, hour;
        char time[64] ;
        tport_t *tport = nta_incoming_transport(theOneAndOnlyController->getAgent(), irq, msg) ;  

        second = (unsigned short)(now.tv_sec % 60);
        minute = (unsigned short)((now.tv_sec / 60) % 60);
        hour = (unsigned short)((now.tv_sec / 3600) % 24);
        sprintf(time, "%02u:%02u:%02u.%06lu", hour, minute, second, now.tv_usec) ;
 
        m_time.assign( time ) ;
        if( tport_is_udp(tport ) ) m_protocol = "udp" ;
        else if( tport_is_tcp( tport)  ) m_protocol = "tcp" ;
        else if( tport_has_tls( tport ) ) m_protocol = "tls" ;

        tport_unref( tport ) ;

        init( msg ) ;
    }
    SipMsgData_t::SipMsgData_t( msg_t* msg, nta_outgoing_t* orq, const char* source ) : m_source(source) {
        su_time_t now = su_now() ;
        unsigned short second, minute, hour;
        char time[64] ;
        tport_t *tport = nta_outgoing_transport( orq ) ;    
        

        second = (unsigned short)(now.tv_sec % 60);
        minute = (unsigned short)((now.tv_sec / 60) % 60);
        hour = (unsigned short)((now.tv_sec / 3600) % 24);
        sprintf(time, "%02u:%02u:%02u.%06lu", hour, minute, second, now.tv_usec) ;
 
        m_time.assign( time ) ;

        if( tport_is_udp(tport ) ) m_protocol = "udp" ;
        else if( tport_is_tcp( tport)  ) m_protocol = "tcp" ;
        else if( tport_has_tls( tport ) ) m_protocol = "tls" ;
        else m_protocol = "unknown";

        init( msg ) ;

        if( 0 == strcmp(source, "application") ) {
            if( NULL != tport ) {
                const tp_name_t* name = tport_name(tport) ;
                m_address = name->tpn_host ;
                m_port = name->tpn_port ;                
            }
            
            
        }


        tport_unref( tport ) ;

    }
    void SipMsgData_t::init( msg_t* msg ) {
        su_sockaddr_t const *su = msg_addr(msg);
        short port ;
        char name[SU_ADDRSIZE] = "";
        char szTmp[10] ;

        su_inet_ntop(su->su_family, SU_ADDR(su), name, sizeof(name));

        m_address.assign( name ) ;
        sprintf( szTmp, "%u", ntohs(su->su_port) ) ;
        m_port.assign( szTmp );
        sprintf( szTmp, "%u", msg_size( msg ) ) ;
        m_bytes.assign( szTmp ) ;
    }

     int ackResponse( msg_t* msg ) {
        nta_agent_t* nta = theOneAndOnlyController->getAgent() ;
        sip_t *sip = sip_object(msg);
        msg_t *amsg = nta_msg_create(nta, 0);
        sip_t *asip = sip_object(amsg);
        url_string_t const *ruri;
        nta_outgoing_t *ack = NULL, *bye = NULL;
        sip_cseq_t *cseq;
        sip_request_t *rq;
        sip_route_t *route = NULL, *r, r0[1];
        su_home_t *home = msg_home(amsg);
        tport_t* tp_incoming = nta_incoming_transport(nta, NULL, msg);

        if (asip == NULL)
        return -1;

        sip_add_tl(amsg, asip, SIPTAG_TO(sip->sip_to), SIPTAG_FROM(sip->sip_from), SIPTAG_CALL_ID(sip->sip_call_id), TAG_END());




        if (sip->sip_contact && sip->sip_status->st_status > 399 ) {
            ruri = (url_string_t const *)sip->sip_contact->m_url;
        } else {
            su_sockaddr_t const *su = msg_addr(msg);
            char name[SU_ADDRSIZE] = "";
            char uri[SU_ADDRSIZE+20] = "" ;
            char szTmp[10] ;

            su_inet_ntop(su->su_family, SU_ADDR(su), name, sizeof(name));
            sprintf( szTmp, "%u", ntohs(su->su_port) ) ;
            sprintf(uri, "sip:%s:%s", name, szTmp) ;
            ruri = URL_STRING_MAKE(uri) ;
        }

        if (!(cseq = sip_cseq_create(home, sip->sip_cseq->cs_seq, SIP_METHOD_ACK)))
            goto err;
        else msg_header_insert(amsg, (msg_pub_t *)asip, (msg_header_t *)cseq);

        if (!(rq = sip_request_create(home, SIP_METHOD_ACK, ruri, NULL)))
            goto err;
        else msg_header_insert(amsg, (msg_pub_t *)asip, (msg_header_t *)rq);

        DR_LOG(log_debug) << "ackResponse - sending ack via tport " << std::hex << (void *) tp_incoming ;

        if( nta_msg_tsend( nta, amsg, NULL,  NTATAG_BRANCH_KEY(sip->sip_via->v_branch), NTATAG_TPORT(tp_incoming), TAG_END() ) < 0 )


 
            goto err ;

         return 0;

        err:
            if( amsg ) msg_destroy(amsg);
            return -1;
    }

    int utf8_strlen(const string& str)
    {
        int c,i,ix,q;
        for (q=0, i=0, ix=str.length(); i < ix; i++, q++)
        {
            c = (unsigned char) str[i];
            if      (c>=0   && c<=127) i+=0;
            else if ((c & 0xE0) == 0xC0) i+=1;
            else if ((c & 0xF0) == 0xE0) i+=2;
            else if ((c & 0xF8) == 0xF0) i+=3;
            
            
            else {
                DR_LOG(log_error) << "utf8_strlen - code 0x" << std::hex << c << " at position " << std::dec << q << " is not a valid UTF-8 character";
                DR_LOG(log_error) << "utf8_strlen - in string: " << str ;
                return 0;
            }
        }
        return q;
    }
 }

