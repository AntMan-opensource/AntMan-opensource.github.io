

















struct rdp_nego {
	UINT16 port;
	UINT32 flags;
	const char* hostname;
	char* cookie;
	BYTE* RoutingToken;
	DWORD RoutingTokenLength;
	BOOL SendPreconnectionPdu;
	UINT32 PreconnectionId;
	char* PreconnectionBlob;

	NEGO_STATE state;
	BOOL TcpConnected;
	BOOL SecurityConnected;
	UINT32 CookieMaxLength;

	BOOL sendNegoData;
	UINT32 SelectedProtocol;
	UINT32 RequestedProtocols;
	BOOL NegotiateSecurityLayer;
	BOOL EnabledProtocols[16];
	BOOL RestrictedAdminModeRequired;
	BOOL GatewayEnabled;
	BOOL GatewayBypassLocal;

	rdpTransport* transport;
};

static const char* nego_state_string(NEGO_STATE state)
{
	static const char* const NEGO_STATE_STRINGS[] = { "NEGO_STATE_INITIAL", "NEGO_STATE_EXT", "NEGO_STATE_NLA",     "NEGO_STATE_TLS", "NEGO_STATE_RDP",     "NEGO_STATE_FAIL", "NEGO_STATE_FINAL",   "NEGO_STATE_INVALID" };


	if (state >= ARRAYSIZE(NEGO_STATE_STRINGS))
		return NEGO_STATE_STRINGS[ARRAYSIZE(NEGO_STATE_STRINGS) - 1];
	return NEGO_STATE_STRINGS[state];
}

static const char* protocol_security_string(UINT32 security)
{
	static const char* PROTOCOL_SECURITY_STRINGS[] = { "RDP", "TLS", "NLA", "UNK", "UNK", "UNK", "UNK", "UNK", "EXT", "UNK" };
	if (security >= ARRAYSIZE(PROTOCOL_SECURITY_STRINGS))
		return PROTOCOL_SECURITY_STRINGS[ARRAYSIZE(PROTOCOL_SECURITY_STRINGS) - 1];
	return PROTOCOL_SECURITY_STRINGS[security];
}

static BOOL nego_transport_connect(rdpNego* nego);
static BOOL nego_transport_disconnect(rdpNego* nego);
static BOOL nego_security_connect(rdpNego* nego);
static BOOL nego_send_preconnection_pdu(rdpNego* nego);
static BOOL nego_recv_response(rdpNego* nego);
static void nego_send(rdpNego* nego);
static void nego_process_negotiation_request(rdpNego* nego, wStream* s);
static void nego_process_negotiation_response(rdpNego* nego, wStream* s);
static void nego_process_negotiation_failure(rdpNego* nego, wStream* s);



BOOL nego_connect(rdpNego* nego)
{
	rdpSettings* settings = nego->transport->settings;

	if (nego->state == NEGO_STATE_INITIAL)
	{
		if (nego->EnabledProtocols[PROTOCOL_HYBRID_EX])
		{
			nego->state = NEGO_STATE_EXT;
		}
		else if (nego->EnabledProtocols[PROTOCOL_HYBRID])
		{
			nego->state = NEGO_STATE_NLA;
		}
		else if (nego->EnabledProtocols[PROTOCOL_SSL])
		{
			nego->state = NEGO_STATE_TLS;
		}
		else if (nego->EnabledProtocols[PROTOCOL_RDP])
		{
			nego->state = NEGO_STATE_RDP;
		}
		else {
			WLog_ERR(TAG, "No security protocol is enabled");
			nego->state = NEGO_STATE_FAIL;
			return FALSE;
		}

		if (!nego->NegotiateSecurityLayer)
		{
			WLog_DBG(TAG, "Security Layer Negotiation is disabled");
			
			nego->EnabledProtocols[PROTOCOL_HYBRID] = FALSE;
			nego->EnabledProtocols[PROTOCOL_SSL] = FALSE;
			nego->EnabledProtocols[PROTOCOL_RDP] = FALSE;
			nego->EnabledProtocols[PROTOCOL_HYBRID_EX] = FALSE;

			if (nego->state == NEGO_STATE_EXT)
			{
				nego->EnabledProtocols[PROTOCOL_HYBRID_EX] = TRUE;
				nego->EnabledProtocols[PROTOCOL_HYBRID] = TRUE;
				nego->SelectedProtocol = PROTOCOL_HYBRID_EX;
			}
			else if (nego->state == NEGO_STATE_NLA)
			{
				nego->EnabledProtocols[PROTOCOL_HYBRID] = TRUE;
				nego->SelectedProtocol = PROTOCOL_HYBRID;
			}
			else if (nego->state == NEGO_STATE_TLS)
			{
				nego->EnabledProtocols[PROTOCOL_SSL] = TRUE;
				nego->SelectedProtocol = PROTOCOL_SSL;
			}
			else if (nego->state == NEGO_STATE_RDP)
			{
				nego->EnabledProtocols[PROTOCOL_RDP] = TRUE;
				nego->SelectedProtocol = PROTOCOL_RDP;
			}
		}

		if (nego->SendPreconnectionPdu)
		{
			if (!nego_send_preconnection_pdu(nego))
			{
				WLog_ERR(TAG, "Failed to send preconnection pdu");
				nego->state = NEGO_STATE_FINAL;
				return FALSE;
			}
		}
	}

	if (!nego->NegotiateSecurityLayer)
	{
		nego->state = NEGO_STATE_FINAL;
	}
	else {
		do {
			WLog_DBG(TAG, "state: %s", nego_state_string(nego->state));
			nego_send(nego);

			if (nego->state == NEGO_STATE_FAIL)
			{
				if (freerdp_get_last_error(nego->transport->context) == FREERDP_ERROR_SUCCESS)
					WLog_ERR(TAG, "Protocol Security Negotiation Failure");

				nego->state = NEGO_STATE_FINAL;
				return FALSE;
			}
		} while (nego->state != NEGO_STATE_FINAL);
	}

	WLog_DBG(TAG, "Negotiated %s security", protocol_security_string(nego->SelectedProtocol));
	
	settings->RequestedProtocols = nego->RequestedProtocols;
	settings->SelectedProtocol = nego->SelectedProtocol;
	settings->NegotiationFlags = nego->flags;

	if (nego->SelectedProtocol == PROTOCOL_RDP)
	{
		settings->UseRdpSecurityLayer = TRUE;

		if (!settings->EncryptionMethods)
		{
			
			settings->EncryptionMethods = ENCRYPTION_METHOD_40BIT | ENCRYPTION_METHOD_56BIT | ENCRYPTION_METHOD_128BIT | ENCRYPTION_METHOD_FIPS;
		}
	}

	
	if (!nego_security_connect(nego))
	{
		WLog_DBG(TAG, "Failed to connect with %s security", protocol_security_string(nego->SelectedProtocol));
		return FALSE;
	}

	return TRUE;
}

BOOL nego_disconnect(rdpNego* nego)
{
	nego->state = NEGO_STATE_INITIAL;
	return nego_transport_disconnect(nego);
}


BOOL nego_security_connect(rdpNego* nego)
{
	if (!nego->TcpConnected)
	{
		nego->SecurityConnected = FALSE;
	}
	else if (!nego->SecurityConnected)
	{
		if (nego->SelectedProtocol == PROTOCOL_HYBRID)
		{
			WLog_DBG(TAG, "nego_security_connect with PROTOCOL_HYBRID");
			nego->SecurityConnected = transport_connect_nla(nego->transport);
		}
		else if (nego->SelectedProtocol == PROTOCOL_SSL)
		{
			WLog_DBG(TAG, "nego_security_connect with PROTOCOL_SSL");
			nego->SecurityConnected = transport_connect_tls(nego->transport);
		}
		else if (nego->SelectedProtocol == PROTOCOL_RDP)
		{
			WLog_DBG(TAG, "nego_security_connect with PROTOCOL_RDP");
			nego->SecurityConnected = transport_connect_rdp(nego->transport);
		}
		else {
			WLog_ERR(TAG, "cannot connect security layer because no protocol has been selected yet.");
		}
	}

	return nego->SecurityConnected;
}



static BOOL nego_tcp_connect(rdpNego* nego)
{
	if (!nego->TcpConnected)
	{
		if (nego->GatewayEnabled)
		{
			if (nego->GatewayBypassLocal)
			{
				
				WLog_INFO(TAG, "Detecting if host can be reached locally. - This might take some time.");
				WLog_INFO(TAG, "To disable auto detection use /gateway-usage-method:direct");
				transport_set_gateway_enabled(nego->transport, FALSE);
				nego->TcpConnected = transport_connect(nego->transport, nego->hostname, nego->port, 1);
			}

			if (!nego->TcpConnected)
			{
				transport_set_gateway_enabled(nego->transport, TRUE);
				nego->TcpConnected = transport_connect(nego->transport, nego->hostname, nego->port, 15);
			}
		}
		else {
			nego->TcpConnected = transport_connect(nego->transport, nego->hostname, nego->port, 15);
		}
	}

	return nego->TcpConnected;
}



BOOL nego_transport_connect(rdpNego* nego)
{
	if (!nego_tcp_connect(nego))
		return FALSE;

	if (nego->TcpConnected && !nego->NegotiateSecurityLayer)
		return nego_security_connect(nego);

	return nego->TcpConnected;
}



BOOL nego_transport_disconnect(rdpNego* nego)
{
	if (nego->TcpConnected)
		transport_disconnect(nego->transport);

	nego->TcpConnected = FALSE;
	nego->SecurityConnected = FALSE;
	return TRUE;
}



BOOL nego_send_preconnection_pdu(rdpNego* nego)
{
	wStream* s;
	UINT32 cbSize;
	UINT16 cchPCB = 0;
	WCHAR* wszPCB = NULL;
	WLog_DBG(TAG, "Sending preconnection PDU");

	if (!nego_tcp_connect(nego))
		return FALSE;

	
	cbSize = PRECONNECTION_PDU_V2_MIN_SIZE;

	if (nego->PreconnectionBlob)
	{
		cchPCB = (UINT16)ConvertToUnicode(CP_UTF8, 0, nego->PreconnectionBlob, -1, &wszPCB, 0);
		cchPCB += 1; 
		cbSize += cchPCB * 2;
	}

	s = Stream_New(NULL, cbSize);

	if (!s)
	{
		free(wszPCB);
		WLog_ERR(TAG, "Stream_New failed!");
		return FALSE;
	}

	Stream_Write_UINT32(s, cbSize);                
	Stream_Write_UINT32(s, 0);                     
	Stream_Write_UINT32(s, PRECONNECTION_PDU_V2);  
	Stream_Write_UINT32(s, nego->PreconnectionId); 
	Stream_Write_UINT16(s, cchPCB);                

	if (wszPCB)
	{
		Stream_Write(s, wszPCB, cchPCB * 2); 
		free(wszPCB);
	}

	Stream_SealLength(s);

	if (transport_write(nego->transport, s) < 0)
	{
		Stream_Free(s, TRUE);
		return FALSE;
	}

	Stream_Free(s, TRUE);
	return TRUE;
}



static void nego_attempt_ext(rdpNego* nego)
{
	nego->RequestedProtocols = PROTOCOL_HYBRID | PROTOCOL_SSL | PROTOCOL_HYBRID_EX;
	WLog_DBG(TAG, "Attempting NLA extended security");

	if (!nego_transport_connect(nego))
	{
		nego->state = NEGO_STATE_FAIL;
		return;
	}

	if (!nego_send_negotiation_request(nego))
	{
		nego->state = NEGO_STATE_FAIL;
		return;
	}

	if (!nego_recv_response(nego))
	{
		nego->state = NEGO_STATE_FAIL;
		return;
	}

	WLog_DBG(TAG, "state: %s", nego_state_string(nego->state));

	if (nego->state != NEGO_STATE_FINAL)
	{
		nego_transport_disconnect(nego);

		if (nego->EnabledProtocols[PROTOCOL_HYBRID])
			nego->state = NEGO_STATE_NLA;
		else if (nego->EnabledProtocols[PROTOCOL_SSL])
			nego->state = NEGO_STATE_TLS;
		else if (nego->EnabledProtocols[PROTOCOL_RDP])
			nego->state = NEGO_STATE_RDP;
		else nego->state = NEGO_STATE_FAIL;
	}
}



static void nego_attempt_nla(rdpNego* nego)
{
	nego->RequestedProtocols = PROTOCOL_HYBRID | PROTOCOL_SSL;
	WLog_DBG(TAG, "Attempting NLA security");

	if (!nego_transport_connect(nego))
	{
		nego->state = NEGO_STATE_FAIL;
		return;
	}

	if (!nego_send_negotiation_request(nego))
	{
		nego->state = NEGO_STATE_FAIL;
		return;
	}

	if (!nego_recv_response(nego))
	{
		nego->state = NEGO_STATE_FAIL;
		return;
	}

	WLog_DBG(TAG, "state: %s", nego_state_string(nego->state));

	if (nego->state != NEGO_STATE_FINAL)
	{
		nego_transport_disconnect(nego);

		if (nego->EnabledProtocols[PROTOCOL_SSL])
			nego->state = NEGO_STATE_TLS;
		else if (nego->EnabledProtocols[PROTOCOL_RDP])
			nego->state = NEGO_STATE_RDP;
		else nego->state = NEGO_STATE_FAIL;
	}
}



static void nego_attempt_tls(rdpNego* nego)
{
	nego->RequestedProtocols = PROTOCOL_SSL;
	WLog_DBG(TAG, "Attempting TLS security");

	if (!nego_transport_connect(nego))
	{
		nego->state = NEGO_STATE_FAIL;
		return;
	}

	if (!nego_send_negotiation_request(nego))
	{
		nego->state = NEGO_STATE_FAIL;
		return;
	}

	if (!nego_recv_response(nego))
	{
		nego->state = NEGO_STATE_FAIL;
		return;
	}

	if (nego->state != NEGO_STATE_FINAL)
	{
		nego_transport_disconnect(nego);

		if (nego->EnabledProtocols[PROTOCOL_RDP])
			nego->state = NEGO_STATE_RDP;
		else nego->state = NEGO_STATE_FAIL;
	}
}



static void nego_attempt_rdp(rdpNego* nego)
{
	nego->RequestedProtocols = PROTOCOL_RDP;
	WLog_DBG(TAG, "Attempting RDP security");

	if (!nego_transport_connect(nego))
	{
		nego->state = NEGO_STATE_FAIL;
		return;
	}

	if (!nego_send_negotiation_request(nego))
	{
		nego->state = NEGO_STATE_FAIL;
		return;
	}

	if (!nego_recv_response(nego))
	{
		nego->state = NEGO_STATE_FAIL;
		return;
	}
}



BOOL nego_recv_response(rdpNego* nego)
{
	int status;
	wStream* s;
	s = Stream_New(NULL, 1024);

	if (!s)
	{
		WLog_ERR(TAG, "Stream_New failed!");
		return FALSE;
	}

	status = transport_read_pdu(nego->transport, s);

	if (status < 0)
	{
		Stream_Free(s, TRUE);
		return FALSE;
	}

	status = nego_recv(nego->transport, s, nego);
	Stream_Free(s, TRUE);

	if (status < 0)
		return FALSE;

	return TRUE;
}



int nego_recv(rdpTransport* transport, wStream* s, void* extra)
{
	BYTE li;
	BYTE type;
	UINT16 length;
	rdpNego* nego = (rdpNego*)extra;

	if (!tpkt_read_header(s, &length))
		return -1;

	if (!tpdu_read_connection_confirm(s, &li, length))
		return -1;

	if (li > 6)
	{
		
		Stream_Read_UINT8(s, type); 

		switch (type)
		{
			case TYPE_RDP_NEG_RSP:
				nego_process_negotiation_response(nego, s);
				WLog_DBG(TAG, "selected_protocol: %" PRIu32 "", nego->SelectedProtocol);

				

				if (nego->SelectedProtocol)
				{
					if ((nego->SelectedProtocol == PROTOCOL_HYBRID) && (!nego->EnabledProtocols[PROTOCOL_HYBRID]))
					{
						nego->state = NEGO_STATE_FAIL;
					}

					if ((nego->SelectedProtocol == PROTOCOL_SSL) && (!nego->EnabledProtocols[PROTOCOL_SSL]))
					{
						nego->state = NEGO_STATE_FAIL;
					}
				}
				else if (!nego->EnabledProtocols[PROTOCOL_RDP])
				{
					nego->state = NEGO_STATE_FAIL;
				}

				break;

			case TYPE_RDP_NEG_FAILURE:
				nego_process_negotiation_failure(nego, s);
				break;
		}
	}
	else if (li == 6)
	{
		WLog_DBG(TAG, "no rdpNegData");

		if (!nego->EnabledProtocols[PROTOCOL_RDP])
			nego->state = NEGO_STATE_FAIL;
		else nego->state = NEGO_STATE_FINAL;
	}
	else {
		WLog_ERR(TAG, "invalid negotiation response");
		nego->state = NEGO_STATE_FAIL;
	}

	if (!tpkt_ensure_stream_consumed(s, length))
		return -1;
	return 0;
}



static BOOL nego_read_request_token_or_cookie(rdpNego* nego, wStream* s)
{
	
	BYTE* str = NULL;
	UINT16 crlf = 0;
	size_t pos, len;
	BOOL result = FALSE;
	BOOL isToken = FALSE;
	size_t remain = Stream_GetRemainingLength(s);
	str = Stream_Pointer(s);
	pos = Stream_GetPosition(s);

	
	if (remain < 15)
		return TRUE;

	if (memcmp(Stream_Pointer(s), "Cookie: mstshash=", 17) != 0)
	{
		isToken = TRUE;
	}
	else {
		
		if (remain < 19)
			return TRUE;

		Stream_Seek(s, 17);
	}

	while ((remain = Stream_GetRemainingLength(s)) >= 2)
	{
		Stream_Read_UINT16(s, crlf);

		if (crlf == 0x0A0D)
			break;

		Stream_Rewind(s, 1);
	}

	if (crlf == 0x0A0D)
	{
		Stream_Rewind(s, 2);
		len = Stream_GetPosition(s) - pos;
		remain = Stream_GetRemainingLength(s);
		Stream_Write_UINT16(s, 0);

		if (strnlen((char*)str, len) == len)
		{
			if (isToken)
				result = nego_set_routing_token(nego, str, len);
			else result = nego_set_cookie(nego, (char*)str);
		}
	}

	if (!result)
	{
		Stream_SetPosition(s, pos);
		WLog_ERR(TAG, "invalid %s received", isToken ? "routing token" : "cookie");
	}
	else {
		WLog_DBG(TAG, "received %s [%s]", isToken ? "routing token" : "cookie", str);
	}

	return result;
}



BOOL nego_read_request(rdpNego* nego, wStream* s)
{
	BYTE li;
	BYTE type;
	UINT16 length;

	if (!tpkt_read_header(s, &length))
		return FALSE;

	if (!tpdu_read_connection_request(s, &li, length))
		return FALSE;

	if (li != Stream_GetRemainingLength(s) + 6)
	{
		WLog_ERR(TAG, "Incorrect TPDU length indicator.");
		return FALSE;
	}

	if (!nego_read_request_token_or_cookie(nego, s))
	{
		WLog_ERR(TAG, "Failed to parse routing token or cookie.");
		return FALSE;
	}

	if (Stream_GetRemainingLength(s) >= 8)
	{
		
		Stream_Read_UINT8(s, type); 

		if (type != TYPE_RDP_NEG_REQ)
		{
			WLog_ERR(TAG, "Incorrect negotiation request type %" PRIu8 "", type);
			return FALSE;
		}

		nego_process_negotiation_request(nego, s);
	}

	return tpkt_ensure_stream_consumed(s, length);
}



void nego_send(rdpNego* nego)
{
	if (nego->state == NEGO_STATE_EXT)
		nego_attempt_ext(nego);
	else if (nego->state == NEGO_STATE_NLA)
		nego_attempt_nla(nego);
	else if (nego->state == NEGO_STATE_TLS)
		nego_attempt_tls(nego);
	else if (nego->state == NEGO_STATE_RDP)
		nego_attempt_rdp(nego);
	else WLog_ERR(TAG, "invalid negotiation state for sending");
}



BOOL nego_send_negotiation_request(rdpNego* nego)
{
	BOOL rc = FALSE;
	wStream* s;
	size_t length;
	size_t bm, em;
	BYTE flags = 0;
	size_t cookie_length;
	s = Stream_New(NULL, 512);

	if (!s)
	{
		WLog_ERR(TAG, "Stream_New failed!");
		return FALSE;
	}

	length = TPDU_CONNECTION_REQUEST_LENGTH;
	bm = Stream_GetPosition(s);
	Stream_Seek(s, length);

	if (nego->RoutingToken)
	{
		Stream_Write(s, nego->RoutingToken, nego->RoutingTokenLength);

		

		if ((nego->RoutingTokenLength > 2) && (nego->RoutingToken[nego->RoutingTokenLength - 2] == 0x0D) && (nego->RoutingToken[nego->RoutingTokenLength - 1] == 0x0A))

		{
			WLog_DBG(TAG, "Routing token looks correctly terminated - use verbatim");
			length += nego->RoutingTokenLength;
		}
		else {
			WLog_DBG(TAG, "Adding terminating CRLF to routing token");
			Stream_Write_UINT8(s, 0x0D); 
			Stream_Write_UINT8(s, 0x0A); 
			length += nego->RoutingTokenLength + 2;
		}
	}
	else if (nego->cookie)
	{
		cookie_length = strlen(nego->cookie);

		if (cookie_length > nego->CookieMaxLength)
			cookie_length = nego->CookieMaxLength;

		Stream_Write(s, "Cookie: mstshash=", 17);
		Stream_Write(s, (BYTE*)nego->cookie, cookie_length);
		Stream_Write_UINT8(s, 0x0D); 
		Stream_Write_UINT8(s, 0x0A); 
		length += cookie_length + 19;
	}

	WLog_DBG(TAG, "RequestedProtocols: %" PRIu32 "", nego->RequestedProtocols);

	if ((nego->RequestedProtocols > PROTOCOL_RDP) || (nego->sendNegoData))
	{
		
		if (nego->RestrictedAdminModeRequired)
			flags |= RESTRICTED_ADMIN_MODE_REQUIRED;

		Stream_Write_UINT8(s, TYPE_RDP_NEG_REQ);
		Stream_Write_UINT8(s, flags);
		Stream_Write_UINT16(s, 8);                        
		Stream_Write_UINT32(s, nego->RequestedProtocols); 
		length += 8;
	}

	if (length > UINT16_MAX)
		goto fail;

	em = Stream_GetPosition(s);
	Stream_SetPosition(s, bm);
	tpkt_write_header(s, (UINT16)length);
	tpdu_write_connection_request(s, (UINT16)length - 5);
	Stream_SetPosition(s, em);
	Stream_SealLength(s);
	rc = (transport_write(nego->transport, s) >= 0);
fail:
	Stream_Free(s, TRUE);
	return rc;
}



void nego_process_negotiation_request(rdpNego* nego, wStream* s)
{
	BYTE flags;
	UINT16 length;
	Stream_Read_UINT8(s, flags);
	Stream_Read_UINT16(s, length);
	Stream_Read_UINT32(s, nego->RequestedProtocols);
	WLog_DBG(TAG, "RDP_NEG_REQ: RequestedProtocol: 0x%08" PRIX32 "", nego->RequestedProtocols);
	nego->state = NEGO_STATE_FINAL;
}



void nego_process_negotiation_response(rdpNego* nego, wStream* s)
{
	UINT16 length;
	WLog_DBG(TAG, "RDP_NEG_RSP");

	if (Stream_GetRemainingLength(s) < 7)
	{
		WLog_ERR(TAG, "Invalid RDP_NEG_RSP");
		nego->state = NEGO_STATE_FAIL;
		return;
	}

	Stream_Read_UINT8(s, nego->flags);
	Stream_Read_UINT16(s, length);
	Stream_Read_UINT32(s, nego->SelectedProtocol);
	nego->state = NEGO_STATE_FINAL;
}



void nego_process_negotiation_failure(rdpNego* nego, wStream* s)
{
	BYTE flags;
	UINT16 length;
	UINT32 failureCode;
	WLog_DBG(TAG, "RDP_NEG_FAILURE");
	Stream_Read_UINT8(s, flags);
	Stream_Read_UINT16(s, length);
	Stream_Read_UINT32(s, failureCode);

	switch (failureCode)
	{
		case SSL_REQUIRED_BY_SERVER:
			WLog_WARN(TAG, "Error: SSL_REQUIRED_BY_SERVER");
			break;

		case SSL_NOT_ALLOWED_BY_SERVER:
			WLog_WARN(TAG, "Error: SSL_NOT_ALLOWED_BY_SERVER");
			nego->sendNegoData = TRUE;
			break;

		case SSL_CERT_NOT_ON_SERVER:
			WLog_ERR(TAG, "Error: SSL_CERT_NOT_ON_SERVER");
			nego->sendNegoData = TRUE;
			break;

		case INCONSISTENT_FLAGS:
			WLog_ERR(TAG, "Error: INCONSISTENT_FLAGS");
			break;

		case HYBRID_REQUIRED_BY_SERVER:
			WLog_WARN(TAG, "Error: HYBRID_REQUIRED_BY_SERVER");
			break;

		default:
			WLog_ERR(TAG, "Error: Unknown protocol security error %" PRIu32 "", failureCode);
			break;
	}

	nego->state = NEGO_STATE_FAIL;
}



BOOL nego_send_negotiation_response(rdpNego* nego)
{
	UINT16 length;
	size_t bm, em;
	BOOL status;
	wStream* s;
	BYTE flags;
	rdpSettings* settings;
	status = TRUE;
	settings = nego->transport->settings;
	s = Stream_New(NULL, 512);

	if (!s)
	{
		WLog_ERR(TAG, "Stream_New failed!");
		return FALSE;
	}

	length = TPDU_CONNECTION_CONFIRM_LENGTH;
	bm = Stream_GetPosition(s);
	Stream_Seek(s, length);

	if (nego->SelectedProtocol & PROTOCOL_FAILED_NEGO)
	{
		UINT32 errorCode = (nego->SelectedProtocol & ~PROTOCOL_FAILED_NEGO);
		flags = 0;
		Stream_Write_UINT8(s, TYPE_RDP_NEG_FAILURE);
		Stream_Write_UINT8(s, flags); 
		Stream_Write_UINT16(s, 8);    
		Stream_Write_UINT32(s, errorCode);
		length += 8;
		status = FALSE;
	}
	else {
		flags = EXTENDED_CLIENT_DATA_SUPPORTED;

		if (settings->SupportGraphicsPipeline)
			flags |= DYNVC_GFX_PROTOCOL_SUPPORTED;

		
		Stream_Write_UINT8(s, TYPE_RDP_NEG_RSP);
		Stream_Write_UINT8(s, flags);                   
		Stream_Write_UINT16(s, 8);                      
		Stream_Write_UINT32(s, nego->SelectedProtocol); 
		length += 8;
	}

	em = Stream_GetPosition(s);
	Stream_SetPosition(s, bm);
	tpkt_write_header(s, length);
	tpdu_write_connection_confirm(s, length - 5);
	Stream_SetPosition(s, em);
	Stream_SealLength(s);

	if (transport_write(nego->transport, s) < 0)
	{
		Stream_Free(s, TRUE);
		return FALSE;
	}

	Stream_Free(s, TRUE);

	if (status)
	{
		
		settings->RequestedProtocols = nego->RequestedProtocols;
		settings->SelectedProtocol = nego->SelectedProtocol;

		if (settings->SelectedProtocol == PROTOCOL_RDP)
		{
			settings->TlsSecurity = FALSE;
			settings->NlaSecurity = FALSE;
			settings->RdpSecurity = TRUE;
			settings->UseRdpSecurityLayer = TRUE;

			if (settings->EncryptionLevel == ENCRYPTION_LEVEL_NONE)
			{
				
				settings->EncryptionLevel = ENCRYPTION_LEVEL_CLIENT_COMPATIBLE;
			}

			if (settings->LocalConnection)
			{
				
				WLog_INFO(TAG, "Turning off encryption for local peer with standard rdp security");
				settings->UseRdpSecurityLayer = FALSE;
				settings->EncryptionLevel = ENCRYPTION_LEVEL_NONE;
			}

			if (!settings->RdpServerRsaKey && !settings->RdpKeyFile && !settings->RdpKeyContent)
			{
				WLog_ERR(TAG, "Missing server certificate");
				return FALSE;
			}
		}
		else if (settings->SelectedProtocol == PROTOCOL_SSL)
		{
			settings->TlsSecurity = TRUE;
			settings->NlaSecurity = FALSE;
			settings->RdpSecurity = FALSE;
			settings->UseRdpSecurityLayer = FALSE;
			settings->EncryptionLevel = ENCRYPTION_LEVEL_NONE;
		}
		else if (settings->SelectedProtocol == PROTOCOL_HYBRID)
		{
			settings->TlsSecurity = TRUE;
			settings->NlaSecurity = TRUE;
			settings->RdpSecurity = FALSE;
			settings->UseRdpSecurityLayer = FALSE;
			settings->EncryptionLevel = ENCRYPTION_LEVEL_NONE;
		}
	}

	return status;
}



void nego_init(rdpNego* nego)
{
	nego->state = NEGO_STATE_INITIAL;
	nego->RequestedProtocols = PROTOCOL_RDP;
	nego->CookieMaxLength = DEFAULT_COOKIE_MAX_LENGTH;
	nego->sendNegoData = FALSE;
	nego->flags = 0;
}



rdpNego* nego_new(rdpTransport* transport)
{
	rdpNego* nego = (rdpNego*)calloc(1, sizeof(rdpNego));

	if (!nego)
		return NULL;

	nego->transport = transport;
	nego_init(nego);
	return nego;
}



void nego_free(rdpNego* nego)
{
	if (nego)
	{
		free(nego->RoutingToken);
		free(nego->cookie);
		free(nego);
	}
}



BOOL nego_set_target(rdpNego* nego, const char* hostname, UINT16 port)
{
	if (!nego || !hostname)
		return FALSE;

	nego->hostname = hostname;
	nego->port = port;
	return TRUE;
}



void nego_set_negotiation_enabled(rdpNego* nego, BOOL NegotiateSecurityLayer)
{
	WLog_DBG(TAG, "Enabling security layer negotiation: %s", NegotiateSecurityLayer ? "TRUE" : "FALSE");
	nego->NegotiateSecurityLayer = NegotiateSecurityLayer;
}



void nego_set_restricted_admin_mode_required(rdpNego* nego, BOOL RestrictedAdminModeRequired)
{
	WLog_DBG(TAG, "Enabling restricted admin mode: %s", RestrictedAdminModeRequired ? "TRUE" : "FALSE");
	nego->RestrictedAdminModeRequired = RestrictedAdminModeRequired;
}

void nego_set_gateway_enabled(rdpNego* nego, BOOL GatewayEnabled)
{
	nego->GatewayEnabled = GatewayEnabled;
}

void nego_set_gateway_bypass_local(rdpNego* nego, BOOL GatewayBypassLocal)
{
	nego->GatewayBypassLocal = GatewayBypassLocal;
}



void nego_enable_rdp(rdpNego* nego, BOOL enable_rdp)
{
	WLog_DBG(TAG, "Enabling RDP security: %s", enable_rdp ? "TRUE" : "FALSE");
	nego->EnabledProtocols[PROTOCOL_RDP] = enable_rdp;
}



void nego_enable_tls(rdpNego* nego, BOOL enable_tls)
{
	WLog_DBG(TAG, "Enabling TLS security: %s", enable_tls ? "TRUE" : "FALSE");
	nego->EnabledProtocols[PROTOCOL_SSL] = enable_tls;
}



void nego_enable_nla(rdpNego* nego, BOOL enable_nla)
{
	WLog_DBG(TAG, "Enabling NLA security: %s", enable_nla ? "TRUE" : "FALSE");
	nego->EnabledProtocols[PROTOCOL_HYBRID] = enable_nla;
}



void nego_enable_ext(rdpNego* nego, BOOL enable_ext)
{
	WLog_DBG(TAG, "Enabling NLA extended security: %s", enable_ext ? "TRUE" : "FALSE");
	nego->EnabledProtocols[PROTOCOL_HYBRID_EX] = enable_ext;
}



BOOL nego_set_routing_token(rdpNego* nego, BYTE* RoutingToken, DWORD RoutingTokenLength)
{
	if (RoutingTokenLength == 0)
		return FALSE;

	free(nego->RoutingToken);
	nego->RoutingTokenLength = RoutingTokenLength;
	nego->RoutingToken = (BYTE*)malloc(nego->RoutingTokenLength);

	if (!nego->RoutingToken)
		return FALSE;

	CopyMemory(nego->RoutingToken, RoutingToken, nego->RoutingTokenLength);
	return TRUE;
}



BOOL nego_set_cookie(rdpNego* nego, char* cookie)
{
	if (nego->cookie)
	{
		free(nego->cookie);
		nego->cookie = NULL;
	}

	if (!cookie)
		return TRUE;

	nego->cookie = _strdup(cookie);

	if (!nego->cookie)
		return FALSE;

	return TRUE;
}



void nego_set_cookie_max_length(rdpNego* nego, UINT32 CookieMaxLength)
{
	nego->CookieMaxLength = CookieMaxLength;
}



void nego_set_send_preconnection_pdu(rdpNego* nego, BOOL SendPreconnectionPdu)
{
	nego->SendPreconnectionPdu = SendPreconnectionPdu;
}



void nego_set_preconnection_id(rdpNego* nego, UINT32 PreconnectionId)
{
	nego->PreconnectionId = PreconnectionId;
}



void nego_set_preconnection_blob(rdpNego* nego, char* PreconnectionBlob)
{
	nego->PreconnectionBlob = PreconnectionBlob;
}

UINT32 nego_get_selected_protocol(rdpNego* nego)
{
	if (!nego)
		return 0;

	return nego->SelectedProtocol;
}

BOOL nego_set_selected_protocol(rdpNego* nego, UINT32 SelectedProtocol)
{
	if (!nego)
		return FALSE;

	nego->SelectedProtocol = SelectedProtocol;
	return TRUE;
}

UINT32 nego_get_requested_protocols(rdpNego* nego)
{
	if (!nego)
		return 0;

	return nego->RequestedProtocols;
}

BOOL nego_set_requested_protocols(rdpNego* nego, UINT32 RequestedProtocols)
{
	if (!nego)
		return FALSE;

	nego->RequestedProtocols = RequestedProtocols;
	return TRUE;
}

NEGO_STATE nego_get_state(rdpNego* nego)
{
	if (!nego)
		return NEGO_STATE_FAIL;

	return nego->state;
}

BOOL nego_set_state(rdpNego* nego, NEGO_STATE state)
{
	if (!nego)
		return FALSE;

	nego->state = state;
	return TRUE;
}

SEC_WINNT_AUTH_IDENTITY* nego_get_identity(rdpNego* nego)
{
	if (!nego)
		return NULL;

	return nla_get_identity(nego->transport->nla);
}

void nego_free_nla(rdpNego* nego)
{
	if (!nego || !nego->transport)
		return;

	nla_free(nego->transport->nla);
	nego->transport->nla = NULL;
}

const BYTE* nego_get_routing_token(rdpNego* nego, DWORD* RoutingTokenLength)
{
	if (!nego)
		return NULL;
	if (RoutingTokenLength)
		*RoutingTokenLength = nego->RoutingTokenLength;
	return nego->RoutingToken;
}
