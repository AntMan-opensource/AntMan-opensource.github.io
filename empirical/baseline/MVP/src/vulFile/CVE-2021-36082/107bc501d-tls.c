










extern char *strptime(const char *s, const char *format, struct tm *tm);
extern int processClientServerHello(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow, uint32_t quic_version);
extern int http_process_user_agent(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow, const u_int8_t *ua_ptr, u_int16_t ua_ptr_len);


extern int quic_len(const uint8_t *buf, uint64_t *value);
extern int quic_len_buffer_still_required(uint8_t value);
extern int is_version_with_var_int_transport_params(uint32_t version);



















union ja3_info {
  struct {
    u_int16_t tls_handshake_version;
    u_int16_t num_cipher, cipher[MAX_NUM_JA3];
    u_int16_t num_tls_extension, tls_extension[MAX_NUM_JA3];
    u_int16_t num_elliptic_curve, elliptic_curve[MAX_NUM_JA3];
    u_int16_t num_elliptic_curve_point_format, elliptic_curve_point_format[MAX_NUM_JA3];
    char signature_algorithms[MAX_JA3_STRLEN], supported_versions[MAX_JA3_STRLEN], alpn[MAX_JA3_STRLEN];
  } client;

  struct {
    u_int16_t tls_handshake_version;
    u_int16_t num_cipher, cipher[MAX_NUM_JA3];
    u_int16_t num_tls_extension, tls_extension[MAX_NUM_JA3];
    u_int16_t tls_supported_version;
    u_int16_t num_elliptic_curve_point_format, elliptic_curve_point_format[MAX_NUM_JA3];
    char alpn[MAX_JA3_STRLEN];
  } server; 
};






extern u_int8_t is_skype_flow(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);


extern u_int32_t get_stun_lru_key(struct ndpi_flow_struct *flow, u_int8_t rev);

static void ndpi_int_tls_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow, u_int32_t protocol);



static u_int32_t ndpi_tls_refine_master_protocol(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow, u_int32_t protocol) {
  struct ndpi_packet_struct *packet = &flow->packet;

  

  if(packet->tcp != NULL) {
    switch(protocol) {
    case NDPI_PROTOCOL_TLS:
      {
	
	u_int16_t sport = ntohs(packet->tcp->source);
	u_int16_t dport = ntohs(packet->tcp->dest);

	if((sport == 465) || (dport == 465) || (sport == 587) || (dport == 587))
	  protocol = NDPI_PROTOCOL_MAIL_SMTPS;
	else if((sport == 993) || (dport == 993)
		|| (flow->l4.tcp.mail_imap_starttls)
		) protocol = NDPI_PROTOCOL_MAIL_IMAPS;
	else if((sport == 995) || (dport == 995)) protocol = NDPI_PROTOCOL_MAIL_POPS;
      }
      break;
    }
  }

  return(protocol);
}



void ndpi_search_tls_tcp_memory(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int avail_bytes;

  

  printf("[TLS Mem] Handling TCP/TLS flow [payload_len: %u][buffer_len: %u][direction: %u]\n", packet->payload_packet_len, flow->l4.tcp.tls.message.buffer_len, packet->packet_direction);




  if(flow->l4.tcp.tls.message.buffer == NULL) {
    
    flow->l4.tcp.tls.message.buffer_len = 2048, flow->l4.tcp.tls.message.buffer_used = 0;
    flow->l4.tcp.tls.message.buffer = (u_int8_t*)ndpi_malloc(flow->l4.tcp.tls.message.buffer_len);

    if(flow->l4.tcp.tls.message.buffer == NULL)
      return;


    printf("[TLS Mem] Allocating %u buffer\n", flow->l4.tcp.tls.message.buffer_len);

  }

  avail_bytes = flow->l4.tcp.tls.message.buffer_len - flow->l4.tcp.tls.message.buffer_used;

  if(avail_bytes < packet->payload_packet_len) {
    u_int new_len = flow->l4.tcp.tls.message.buffer_len + packet->payload_packet_len - avail_bytes + 1;
    void *newbuf  = ndpi_realloc(flow->l4.tcp.tls.message.buffer, flow->l4.tcp.tls.message.buffer_len, new_len);
    if(!newbuf) return;


    printf("[TLS Mem] Enlarging %u -> %u buffer\n", flow->l4.tcp.tls.message.buffer_len, new_len);


    flow->l4.tcp.tls.message.buffer = (u_int8_t*)newbuf;
    flow->l4.tcp.tls.message.buffer_len = new_len;
    avail_bytes = flow->l4.tcp.tls.message.buffer_len - flow->l4.tcp.tls.message.buffer_used;
  }

  if(packet->payload_packet_len > 0 && avail_bytes >= packet->payload_packet_len) {
    u_int8_t ok = 0;

    if(flow->l4.tcp.tls.message.next_seq[packet->packet_direction] != 0) {
      if(ntohl(packet->tcp->seq) == flow->l4.tcp.tls.message.next_seq[packet->packet_direction])
	ok = 1;
    } else ok = 1;

    if(ok) {
      memcpy(&flow->l4.tcp.tls.message.buffer[flow->l4.tcp.tls.message.buffer_used], packet->payload, packet->payload_packet_len);

      flow->l4.tcp.tls.message.buffer_used += packet->payload_packet_len;

      printf("[TLS Mem] Copied data to buffer [%u/%u bytes][direction: %u][tcp_seq: %u][next: %u]\n", flow->l4.tcp.tls.message.buffer_used, flow->l4.tcp.tls.message.buffer_len, packet->packet_direction, ntohl(packet->tcp->seq), ntohl(packet->tcp->seq)+packet->payload_packet_len);





      flow->l4.tcp.tls.message.next_seq[packet->packet_direction] = ntohl(packet->tcp->seq)+packet->payload_packet_len;
    } else {

      printf("[TLS Mem] Skipping packet [%u bytes][direction: %u][tcp_seq: %u][expected next: %u]\n", flow->l4.tcp.tls.message.buffer_len, packet->packet_direction, ntohl(packet->tcp->seq), ntohl(packet->tcp->seq)+packet->payload_packet_len);




    }
  }
}















static void cleanupServerName(char *buffer, int buffer_len) {
  u_int i;

  
  for(i=0; i<buffer_len; i++)
    buffer[i] = tolower(buffer[i]);
}




static int extractRDNSequence(struct ndpi_packet_struct *packet, u_int offset, char *buffer, u_int buffer_len, char *rdnSeqBuf, u_int *rdnSeqBuf_offset, u_int rdnSeqBuf_len, const char *label) {



  u_int8_t str_len = packet->payload[offset+4], is_printable = 1;
  char *str;
  u_int len, j;

  if (*rdnSeqBuf_offset >= rdnSeqBuf_len) {

    printf("[TLS] %s() [buffer capacity reached][%u]\n", __FUNCTION__, rdnSeqBuf_len);

    return -1;
  }

  
  if((offset+4+str_len) >= packet->payload_packet_len)
    return(-1);

  str = (char*)&packet->payload[offset+5];

  len = (u_int)ndpi_min(str_len, buffer_len-1);
  strncpy(buffer, str, len);
  buffer[len] = '\0';

  
  for(j = 0; j < len; j++) {
    if(!ndpi_isprint(buffer[j])) {
      is_printable = 0;
      break;
    }
  }

  if(is_printable) {
    int rc = snprintf(&rdnSeqBuf[*rdnSeqBuf_offset], rdnSeqBuf_len-(*rdnSeqBuf_offset), "%s%s=%s", (*rdnSeqBuf_offset > 0) ? ", " : "", label, buffer);



    if(rc > 0)
      (*rdnSeqBuf_offset) += rc;
  }

  return(is_printable);
}



static void checkTLSSubprotocol(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  if(flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN) {
    

    if(ndpi_struct->tls_cert_cache && flow->packet.iph) {
      u_int32_t key = flow->packet.iph->daddr + flow->packet.tcp->dest;
      u_int16_t cached_proto;

      if(ndpi_lru_find_cache(ndpi_struct->tls_cert_cache, key, &cached_proto, 0 )) {
	ndpi_protocol ret = { NDPI_PROTOCOL_TLS, cached_proto, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED };

	flow->detected_protocol_stack[0] = cached_proto, flow->detected_protocol_stack[1] = NDPI_PROTOCOL_TLS;

	flow->category = ndpi_get_proto_category(ndpi_struct, ret);
	ndpi_check_subprotocol_risk(flow, cached_proto);
      }
    }
  }
}




static void processCertificateElements(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow, u_int16_t p_offset, u_int16_t certificate_len) {

  struct ndpi_packet_struct *packet = &flow->packet;
  u_int num_found = 0, i;
  char buffer[64] = { '\0' }, rdnSeqBuf[2048] = { '\0' };
  u_int rdn_len = 0;


  printf("[TLS] %s() [offset: %u][certificate_len: %u]\n", __FUNCTION__, p_offset, certificate_len);


  
  for(i = p_offset; i < certificate_len; i++) {
    
    if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x03)) {
      
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "CN");
      if(rc == -1) break;


      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "Common Name", buffer);

    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x06)) {
      
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "C");
      if(rc == -1) break;


      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "Country", buffer);

    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x07)) {
      
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "L");
      if(rc == -1) break;


      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "Locality", buffer);

    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x08)) {
      
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "ST");
      if(rc == -1) break;


      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "State or Province", buffer);

    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x0a)) {
      
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "O");
      if(rc == -1) break;


      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "Organization Name", buffer);


    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x04) && (packet->payload[i+2] == 0x0b)) {
      
      int rc = extractRDNSequence(packet, i, buffer, sizeof(buffer), rdnSeqBuf, &rdn_len, sizeof(rdnSeqBuf), "OU");
      if(rc == -1) break;


      printf("[TLS] %s() [%s][%s: %s]\n", __FUNCTION__, (num_found == 0) ? "Subject" : "Issuer", "Organization Unit", buffer);

    } else if((packet->payload[i] == 0x30) && (packet->payload[i+1] == 0x1e) && (packet->payload[i+2] == 0x17)) {
      
      u_int8_t len = packet->payload[i+3];
      u_int offset = i+4;

      if(num_found == 0) {
	num_found++;


	printf("[TLS] %s() IssuerDN [%s]\n", __FUNCTION__, rdnSeqBuf);


	if(rdn_len && (flow->protos.tls_quic_stun.tls_quic.issuerDN == NULL))
	  flow->protos.tls_quic_stun.tls_quic.issuerDN = ndpi_strdup(rdnSeqBuf);

	rdn_len = 0; 
      }

      if((offset+len) < packet->payload_packet_len) {
	char utcDate[32];


	u_int j;

	printf("[CERTIFICATE] notBefore [len: %u][", len);
	for(j=0; j<len; j++) printf("%c", packet->payload[i+4+j]);
	printf("]\n");


	if(len < (sizeof(utcDate)-1)) {
	  struct tm utc;
	  utc.tm_isdst = -1; 

	  strncpy(utcDate, (const char*)&packet->payload[i+4], len);
	  utcDate[len] = '\0';

	  
	  if(strptime(utcDate, "%y%m%d%H%M%SZ", &utc) != NULL) {
	    flow->protos.tls_quic_stun.tls_quic.notBefore = timegm(&utc);

	    printf("[CERTIFICATE] notBefore %u [%s]\n", flow->protos.tls_quic_stun.tls_quic.notBefore, utcDate);

	  }
	}

	offset += len;

	if((offset+1) < packet->payload_packet_len) {
	  len = packet->payload[offset+1];

	  offset += 2;

	  if((offset+len) < packet->payload_packet_len) {
	    u_int32_t time_sec = flow->packet.current_time_ms / 1000;

	    u_int j;

	    printf("[CERTIFICATE] notAfter [len: %u][", len);
	    for(j=0; j<len; j++) printf("%c", packet->payload[offset+j]);
	    printf("]\n");


	    if(len < (sizeof(utcDate)-1)) {
	      struct tm utc;
	      utc.tm_isdst = -1; 

	      strncpy(utcDate, (const char*)&packet->payload[offset], len);
	      utcDate[len] = '\0';

	      
	      if(strptime(utcDate, "%y%m%d%H%M%SZ", &utc) != NULL) {
		flow->protos.tls_quic_stun.tls_quic.notAfter = timegm(&utc);

		printf("[CERTIFICATE] notAfter %u [%s]\n", flow->protos.tls_quic_stun.tls_quic.notAfter, utcDate);

	      }
	    }


	    if((time_sec < flow->protos.tls_quic_stun.tls_quic.notBefore)
	       || (time_sec > flow->protos.tls_quic_stun.tls_quic.notAfter))
	    ndpi_set_risk(flow, NDPI_TLS_CERTIFICATE_EXPIRED); 
	  }
	}
      }
    } else if((packet->payload[i] == 0x55) && (packet->payload[i+1] == 0x1d) && (packet->payload[i+2] == 0x11)) {
      
      u_int8_t matched_name = 0;


      printf("******* [TLS] Found subjectAltName\n");


      i += 3 ;
      i++; 
      if(i < packet->payload_packet_len) {
	i += (packet->payload[i] & 0x80) ? (packet->payload[i] & 0x7F) : 0; 
	if(i < packet->payload_packet_len) {
	  i += 2; 
	  if(i < packet->payload_packet_len) {
	    i += (packet->payload[i] & 0x80) ? (packet->payload[i] & 0x7F) : 0; 
	    i++;

	    while(i < packet->payload_packet_len) {
	      if(packet->payload[i] == 0x82) {
		if((i < (packet->payload_packet_len - 1))
		   && ((i + packet->payload[i + 1] + 2) < packet->payload_packet_len)) {
		  u_int8_t len = packet->payload[i + 1];
		  char dNSName[256];

		  i += 2;

		  
		  if((len == 0 )
		     || ((i+len) >  packet->payload_packet_len))
		    break;

		  strncpy(dNSName, (const char*)&packet->payload[i], len);
		  dNSName[len] = '\0';

		  cleanupServerName(dNSName, len);


		  printf("[TLS] dNSName %s [%s][len: %u][leftover: %d]\n", dNSName, flow->protos.tls_quic_stun.tls_quic.client_requested_server_name, len, packet->payload_packet_len-i-len);


		  if(matched_name == 0) {
		    if(flow->protos.tls_quic_stun.tls_quic.client_requested_server_name[0] == '\0')
		      matched_name = 1;	
		    else if (dNSName[0] == '*')
		    {
		      char * label = strstr(flow->protos.tls_quic_stun.tls_quic.client_requested_server_name, &dNSName[1]);

		      if (label != NULL)
		      {
		        char * first_dot = strchr(flow->protos.tls_quic_stun.tls_quic.client_requested_server_name, '.');

		        if (first_dot == NULL || first_dot >= label)
		        {
		          matched_name = 1;
		        }
		      }
		    }
		    else if(strcmp(flow->protos.tls_quic_stun.tls_quic.client_requested_server_name, dNSName) == 0)
		      matched_name = 1;
		  }

		  if(flow->protos.tls_quic_stun.tls_quic.server_names == NULL)
		    flow->protos.tls_quic_stun.tls_quic.server_names = ndpi_strdup(dNSName), flow->protos.tls_quic_stun.tls_quic.server_names_len = strlen(dNSName);
		  else {
		    u_int16_t dNSName_len = strlen(dNSName);
		    u_int16_t newstr_len = flow->protos.tls_quic_stun.tls_quic.server_names_len + dNSName_len + 1;
		    char *newstr = (char*)ndpi_realloc(flow->protos.tls_quic_stun.tls_quic.server_names, flow->protos.tls_quic_stun.tls_quic.server_names_len+1, newstr_len+1);

		    if(newstr) {
		      flow->protos.tls_quic_stun.tls_quic.server_names = newstr;
		      flow->protos.tls_quic_stun.tls_quic.server_names[flow->protos.tls_quic_stun.tls_quic.server_names_len] = ',';
		      strncpy(&flow->protos.tls_quic_stun.tls_quic.server_names[flow->protos.tls_quic_stun.tls_quic.server_names_len+1], dNSName, dNSName_len+1);
		      flow->protos.tls_quic_stun.tls_quic.server_names[newstr_len] = '\0';
		      flow->protos.tls_quic_stun.tls_quic.server_names_len = newstr_len;
		    }
		  }

		  if(!flow->l4.tcp.tls.subprotocol_detected)
		    if(ndpi_match_hostname_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TLS, dNSName, len))
		      flow->l4.tcp.tls.subprotocol_detected = 1;

		  i += len;
		} else {

		  printf("[TLS] Leftover %u bytes", packet->payload_packet_len - i);

		  break;
		}
	      } else {
		break;
	      }
	    } 

	    if(!matched_name)
	      ndpi_set_risk(flow, NDPI_TLS_CERTIFICATE_MISMATCH); 
	  }
	}
      }
    }
  }

  if(rdn_len && (flow->protos.tls_quic_stun.tls_quic.subjectDN == NULL)) {
    flow->protos.tls_quic_stun.tls_quic.subjectDN = ndpi_strdup(rdnSeqBuf);

    if(flow->detected_protocol_stack[1] == NDPI_PROTOCOL_UNKNOWN) {
      
      u_int32_t proto_id;
      int rc = ndpi_match_string_value(ndpi_struct->tls_cert_subject_automa.ac_automa, rdnSeqBuf, strlen(rdnSeqBuf),&proto_id);

      if(rc == 0) {
	
	ndpi_protocol ret = { NDPI_PROTOCOL_TLS, proto_id, NDPI_PROTOCOL_CATEGORY_UNSPECIFIED};

	flow->detected_protocol_stack[0] = proto_id, flow->detected_protocol_stack[1] = NDPI_PROTOCOL_TLS;

	flow->category = ndpi_get_proto_category(ndpi_struct, ret);
	ndpi_check_subprotocol_risk(flow, proto_id);

	if(ndpi_struct->tls_cert_cache == NULL)
	  ndpi_struct->tls_cert_cache = ndpi_lru_cache_init(1024);

	if(ndpi_struct->tls_cert_cache && flow->packet.iph) {
	  u_int32_t key = flow->packet.iph->daddr + flow->packet.tcp->dest;

	  ndpi_lru_add_to_cache(ndpi_struct->tls_cert_cache, key, proto_id);
	}
      }
    }
  }

  if(flow->protos.tls_quic_stun.tls_quic.subjectDN && flow->protos.tls_quic_stun.tls_quic.issuerDN && (!strcmp(flow->protos.tls_quic_stun.tls_quic.subjectDN, flow->protos.tls_quic_stun.tls_quic.issuerDN)))
    ndpi_set_risk(flow, NDPI_TLS_SELFSIGNED_CERTIFICATE);


  printf("[TLS] %s() SubjectDN [%s]\n", __FUNCTION__, rdnSeqBuf);

}




int processCertificate(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  int is_dtls = packet->udp ? 1 : 0;
  u_int32_t certificates_length, length = (packet->payload[1] << 16) + (packet->payload[2] << 8) + packet->payload[3];
  u_int32_t certificates_offset = 7 + (is_dtls ? 8 : 0);
  u_int8_t num_certificates_found = 0;
  SHA1_CTX srv_cert_fingerprint_ctx ;


  printf("[TLS] %s() [payload_packet_len=%u][direction: %u][%02X %02X %02X %02X %02X %02X...]\n", __FUNCTION__, packet->payload_packet_len, packet->packet_direction, packet->payload[0], packet->payload[1], packet->payload[2], packet->payload[3], packet->payload[4], packet->payload[5]);





  if((packet->payload_packet_len != (length + 4 + (is_dtls ? 8 : 0))) || (packet->payload[1] != 0x0)) {
    ndpi_set_risk(flow, NDPI_MALFORMED_PACKET);
    return(-1); 
  }

  certificates_length = (packet->payload[certificates_offset - 3] << 16) + (packet->payload[certificates_offset - 2] << 8) + packet->payload[certificates_offset - 1];


  if((packet->payload[certificates_offset - 3] != 0x0) || ((certificates_length+3) != length)) {
    ndpi_set_risk(flow, NDPI_MALFORMED_PACKET);
    return(-2); 
  }

  
  while(certificates_offset < certificates_length) {
    u_int32_t certificate_len = (packet->payload[certificates_offset] << 16) + (packet->payload[certificates_offset+1] << 8) + packet->payload[certificates_offset+2];

    
    if((certificate_len == 0)
       || (packet->payload[certificates_offset] != 0x0)
       || ((certificates_offset+certificate_len) > (4+certificates_length+(is_dtls ? 8 : 0)))) {

      printf("[TLS] Invalid length [certificate_len: %u][certificates_offset: %u][%u vs %u]\n", certificate_len, certificates_offset, (certificates_offset+certificate_len), certificates_length);



      break;
    }

    certificates_offset += 3;

    printf("[TLS] Processing %u bytes certificate [%02X %02X %02X]\n", certificate_len, packet->payload[certificates_offset], packet->payload[certificates_offset+1], packet->payload[certificates_offset+2]);





    if(num_certificates_found++ == 0)  {
      

      SHA1Init(&srv_cert_fingerprint_ctx);


      {
	int i;

	for(i=0;i<certificate_len;i++)
	  printf("%02X ", packet->payload[certificates_offset+i]);

	printf("\n");
      }


      SHA1Update(&srv_cert_fingerprint_ctx, &packet->payload[certificates_offset], certificate_len);


      SHA1Final(flow->protos.tls_quic_stun.tls_quic.sha1_certificate_fingerprint, &srv_cert_fingerprint_ctx);

      flow->l4.tcp.tls.fingerprint_set = 1;

      uint8_t * sha1 = flow->protos.tls_quic_stun.tls_quic.sha1_certificate_fingerprint;
      const size_t sha1_siz = sizeof(flow->protos.tls_quic_stun.tls_quic.sha1_certificate_fingerprint);
      char sha1_str[20  * 2 + 1];
      static const char hexalnum[] = "0123456789ABCDEF";
      for (size_t i = 0; i < sha1_siz; ++i) {
        u_int8_t lower = (sha1[i] & 0x0F);
        u_int8_t upper = (sha1[i] & 0xF0) >> 4;
        sha1_str[i*2] = hexalnum[upper];
        sha1_str[i*2 + 1] = hexalnum[lower];
      }
      sha1_str[sha1_siz * 2] = '\0';


      printf("[TLS] SHA-1: %s\n", sha1_str);


      if (ndpi_struct->malicious_sha1_automa.ac_automa != NULL) {
        u_int16_t rc1 = ndpi_match_string(ndpi_struct->malicious_sha1_automa.ac_automa, sha1_str);

        if(rc1 > 0)
          ndpi_set_risk(flow, NDPI_MALICIOUS_SHA1_CERTIFICATE);
      }

      processCertificateElements(ndpi_struct, flow, certificates_offset, certificate_len);
    }

    certificates_offset += certificate_len;
  }

  if((ndpi_struct->num_tls_blocks_to_follow != 0)
     && (flow->l4.tcp.tls.num_tls_blocks >= ndpi_struct->num_tls_blocks_to_follow)) {

    printf("*** [TLS Block] Enough blocks dissected\n");


    flow->extra_packets_func = NULL; 
  }

  return(1);
}



static int processTLSBlock(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  int ret;

  switch(packet->payload[0] ) {
  case 0x01: 
  case 0x02: 
    processClientServerHello(ndpi_struct, flow, 0);
    flow->l4.tcp.tls.hello_processed = 1;
    ndpi_int_tls_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_TLS);


    printf("*** TLS [version: %02X][%s Hello]\n", flow->protos.tls_quic_stun.tls_quic.ssl_version, (packet->payload[0] == 0x01) ? "Client" : "Server");



    if((flow->protos.tls_quic_stun.tls_quic.ssl_version >= 0x0304 )
       && (packet->payload[0] == 0x02 )) {
      flow->l4.tcp.tls.certificate_processed = 1; 
    }

    checkTLSSubprotocol(ndpi_struct, flow);
    break;

  case 0x0b: 
    
    if(flow->l4.tcp.tls.hello_processed) {
      ret = processCertificate(ndpi_struct, flow);
      if (ret != 1) {

        printf("[TLS] Error processing certificate: %d\n", ret);

      }
      flow->l4.tcp.tls.certificate_processed = 1;
    }
    break;

  default:
    return(-1);
  }

  return(0);
}



static void ndpi_looks_like_tls(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  

  if(flow->guessed_protocol_id == NDPI_PROTOCOL_UNKNOWN)
    flow->guessed_protocol_id = NDPI_PROTOCOL_TLS;
}



static int ndpi_search_tls_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int8_t something_went_wrong = 0;


  printf("[TLS Mem] ndpi_search_tls_tcp() Processing new packet [payload_packet_len: %u]\n", packet->payload_packet_len);


  if(packet->payload_packet_len == 0)
    return(1); 

  ndpi_search_tls_tcp_memory(ndpi_struct, flow);

  while(!something_went_wrong) {
    u_int16_t len, p_len;
    const u_int8_t *p;
    u_int8_t content_type;

    if(flow->l4.tcp.tls.message.buffer_used < 5)
      return(1); 

    len = (flow->l4.tcp.tls.message.buffer[3] << 8) + flow->l4.tcp.tls.message.buffer[4] + 5;

    if(len > flow->l4.tcp.tls.message.buffer_used) {

      printf("[TLS Mem] Not enough TLS data [%u < %u][%02X %02X %02X %02X %02X]\n", len, flow->l4.tcp.tls.message.buffer_used, flow->l4.tcp.tls.message.buffer[0], flow->l4.tcp.tls.message.buffer[1], flow->l4.tcp.tls.message.buffer[2], flow->l4.tcp.tls.message.buffer[3], flow->l4.tcp.tls.message.buffer[4]);






      break;
    }

    if(len == 0) {
      something_went_wrong = 1;
      break;
    }


    printf("[TLS Mem] Processing %u bytes message\n", len);


    content_type = flow->l4.tcp.tls.message.buffer[0];

    
    p = packet->payload;
    p_len = packet->payload_packet_len; 

    if(content_type == 0x14 ) {
      if(ndpi_struct->skip_tls_blocks_until_change_cipher) {
	
	flow->l4.tcp.tls.num_tls_blocks = 0;
      }
    }

    if((len > 9)
       && (content_type != 0x17 )
       && (!flow->l4.tcp.tls.certificate_processed)) {
      
      u_int16_t processed = 5;

      while((processed+4) <= len) {
	const u_int8_t *block = (const u_int8_t *)&flow->l4.tcp.tls.message.buffer[processed];
	u_int32_t block_len   = (block[1] << 16) + (block[2] << 8) + block[3];

	if(  (block_len > len) || ((block[1] != 0x0))) {
	  something_went_wrong = 1;
	  break;
	}

	packet->payload = block;
	packet->payload_packet_len = ndpi_min(block_len+4, flow->l4.tcp.tls.message.buffer_used);

	if((processed+packet->payload_packet_len) > len) {
	  something_went_wrong = 1;
	  break;
	}

	processTLSBlock(ndpi_struct, flow);
	ndpi_looks_like_tls(ndpi_struct, flow);

	processed += packet->payload_packet_len;
      }
    } else {
      
      if(content_type == 0x17 ) {
	ndpi_looks_like_tls(ndpi_struct, flow);

	if(flow->l4.tcp.tls.certificate_processed) {
	  if(flow->l4.tcp.tls.num_tls_blocks < ndpi_struct->num_tls_blocks_to_follow)
	    flow->l4.tcp.tls.tls_application_blocks_len[flow->l4.tcp.tls.num_tls_blocks++] = (packet->packet_direction == 0) ? (len-5) : -(len-5);


	  printf("*** [TLS Block] [len: %u][num_tls_blocks: %u/%u]\n", len-5, flow->l4.tcp.tls.num_tls_blocks, ndpi_struct->num_tls_blocks_to_follow);

	}
      }
    }

    packet->payload = p;
    packet->payload_packet_len = p_len; 
    flow->l4.tcp.tls.message.buffer_used -= len;

    if(flow->l4.tcp.tls.message.buffer_used > 0)
      memmove(flow->l4.tcp.tls.message.buffer, &flow->l4.tcp.tls.message.buffer[len], flow->l4.tcp.tls.message.buffer_used);

    else break;


    printf("[TLS Mem] Left memory buffer %u bytes\n", flow->l4.tcp.tls.message.buffer_used);

  }

  if(something_went_wrong || ((ndpi_struct->num_tls_blocks_to_follow > 0)
	 && (flow->l4.tcp.tls.num_tls_blocks == ndpi_struct->num_tls_blocks_to_follow))
     ) {

    printf("*** [TLS Block] No more blocks\n");

    flow->check_extra_packets = 0;
    flow->extra_packets_func = NULL;
    return(0); 
  } else return(1);
}



static int ndpi_search_tls_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t handshake_len;
  u_int16_t p_len, processed;
  const u_int8_t *p;
  u_int8_t no_dtls = 0, change_cipher_found = 0;


  printf("[TLS] %s()\n", __FUNCTION__);


  
  p = packet->payload, p_len = packet->payload_packet_len; 

  
  processed = 0;
  while(processed + 13 < p_len) {
    u_int32_t block_len;
    const u_int8_t *block = (const u_int8_t *)&p[processed];

    if((block[0] != 0x16 && block[0] != 0x14) ||  (block[1] != 0xfe) || ((block[2] != 0xff) && (block[2] != 0xfd))) {


      printf("[TLS] DTLS invalid block 0x%x or old version 0x%x-0x%x-0x%x\n", block[0], block[1], block[2], block[3]);

      no_dtls = 1;
      break;
    }
    block_len = ntohs(*((u_int16_t*)&block[11]));

    printf("[TLS] DTLS block len: %d\n", block_len);

    if (block_len == 0 || (processed + block_len + 12 >= p_len)) {

      printf("[TLS] DTLS invalid block len %d (processed %d, p_len %d)\n", block_len, processed, p_len);

      no_dtls = 1;
      break;
    }
    
    if(block[0] == 0x16) {
      if (processed + block_len + 13 > p_len) {

        printf("[TLS] DTLS invalid len %d %d %d\n", processed, block_len, p_len);

        no_dtls = 1;
        break;
     }
      
      handshake_len = (block[14] << 16) + (block[15] << 8) + block[16];
      if((handshake_len + 12) != block_len) {

        printf("[TLS] DTLS invalid handshake_len %d, %d)\n", handshake_len, block_len);

        no_dtls = 1;
        break;
      }
      packet->payload = &block[13];
      packet->payload_packet_len = block_len;
      processTLSBlock(ndpi_struct, flow);
    } else {
      

      printf("[TLS] Change-cipher-spec\n");

      change_cipher_found = 1;
      processed += block_len + 13;
      break;
    }

    processed += block_len + 13;
  }
  if(processed != p_len) {

    printf("[TLS] DTLS invalid processed len %d/%d (%d)\n", processed, p_len, change_cipher_found);

    if(!change_cipher_found)
      no_dtls = 1;
  }

  packet->payload = p;
  packet->payload_packet_len = p_len; 

  if(no_dtls || change_cipher_found) {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return(0); 
  } else {
    return(1); 
  }
}



static void tlsInitExtraPacketProcessing(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  flow->check_extra_packets = 1;

  
  flow->max_extra_packets_to_check = 12 + (ndpi_struct->num_tls_blocks_to_follow*4);
  flow->extra_packets_func = (flow->packet.udp != NULL) ? ndpi_search_tls_udp : ndpi_search_tls_tcp;
}



static void tlsCheckUncommonALPN(struct ndpi_flow_struct *flow)
{
  
  static char const * const common_alpns[] = {
    "http/0.9", "http/1.0", "http/1.1", "spdy/1", "spdy/2", "spdy/3", "spdy/3.1", "stun.turn", "stun.nat-discovery", "h2", "h2c", "h2-16", "h2-15", "h2-14", "webrtc", "c-webrtc", "ftp", "imap", "pop3", "managesieve", "coap", "xmpp-client", "xmpp-server", "acme-tls/1", "mqtt", "dot", "ntske/1", "sunrpc", "h3", "smb", "irc",   "h3-T051", "h3-T050", "h3-32", "h3-30", "h3-29", "h3-28", "h3-27", "h3-24", "h3-22", "hq-30", "hq-29", "hq-28", "hq-27", "h3-fb-05", "h1q-fb", "doq-i00" };



















  

  char * alpn_start = flow->protos.tls_quic_stun.tls_quic.alpn;
  char * comma_or_nul = alpn_start;
  do {
    comma_or_nul = strchr(comma_or_nul, ',');
    if (comma_or_nul == NULL)
    {
      comma_or_nul = alpn_start + strlen(alpn_start);
    }

    int alpn_found = 0;
    int alpn_len = comma_or_nul - alpn_start;
    char const * const alpn = alpn_start;
    for (size_t i = 0; i < sizeof(common_alpns)/sizeof(common_alpns[0]); ++i)
    {
      if (strlen(common_alpns[i]) == alpn_len && strncmp(alpn, common_alpns[i], alpn_len) == 0)
      {
        alpn_found = 1;
        break;
      }
    }

    if (alpn_found == 0)
    {

      printf("TLS uncommon ALPN found: %.*s\n", alpn_len, alpn);

      ndpi_set_risk(flow, NDPI_TLS_UNCOMMON_ALPN);
      break;
    }

    alpn_start = comma_or_nul + 1;
  } while (*(comma_or_nul++) != '\0');
}



static void ndpi_int_tls_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow, u_int32_t protocol) {

  printf("[TLS] %s()\n", __FUNCTION__);


  if((flow->packet.udp != NULL) && (protocol == NDPI_PROTOCOL_TLS))
    protocol = NDPI_PROTOCOL_DTLS;

  if((flow->detected_protocol_stack[0] == protocol)
     || (flow->detected_protocol_stack[1] == protocol)) {
    if(!flow->check_extra_packets)
      tlsInitExtraPacketProcessing(ndpi_struct, flow);
    return;
  }

  if(protocol != NDPI_PROTOCOL_TLS)
    ;
  else protocol = ndpi_tls_refine_master_protocol(ndpi_struct, flow, protocol);

  ndpi_set_detected_protocol(ndpi_struct, flow, protocol, protocol);

  tlsInitExtraPacketProcessing(ndpi_struct, flow);
}



int processClientServerHello(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow, uint32_t quic_version) {
  struct ndpi_packet_struct *packet = &flow->packet;
  union ja3_info ja3;
  u_int8_t invalid_ja3 = 0;
  u_int16_t tls_version, ja3_str_len;
  char ja3_str[JA3_STR_LEN];
  ndpi_MD5_CTX ctx;
  u_char md5_hash[16];
  int i;
  u_int16_t total_len;
  u_int8_t handshake_type;
  char buffer[64] = { '\0' };
  int is_quic = (quic_version != 0);
  int is_dtls = packet->udp && (!is_quic);


  printf("TLS %s() called\n", __FUNCTION__);


  memset(&ja3, 0, sizeof(ja3));

  handshake_type = packet->payload[0];
  total_len = (packet->payload[1] << 16) +  (packet->payload[2] << 8) + packet->payload[3];

  if((total_len > packet->payload_packet_len) || (packet->payload[1] != 0x0))
    return(0); 

  total_len = packet->payload_packet_len;

  
  if(total_len > 4) {
    u_int16_t base_offset    = (!is_dtls) ? 38 : 46;
    u_int16_t version_offset = (!is_dtls) ? 4 : 12;
    u_int16_t offset = (!is_dtls) ? 38 : 46, extension_len, j;
    u_int8_t  session_id_len =  0;

    if((base_offset >= total_len) || (version_offset + 1) >= total_len)
      return 0; 

    session_id_len = packet->payload[base_offset];


    printf("TLS [len: %u][handshake_type: %02X]\n", packet->payload_packet_len, handshake_type);


    tls_version = ntohs(*((u_int16_t*)&packet->payload[version_offset]));

    if(handshake_type == 0x02 ) {
      int i, rc;

      ja3.server.tls_handshake_version = tls_version;


      printf("TLS Server Hello [version: 0x%04X]\n", tls_version);


      
      if(packet->udp)
	offset += session_id_len + 1;
      else {
	if(tls_version < 0x7F15 )
	  offset += session_id_len+1;
      }

      if((offset+3) > packet->payload_packet_len)
	return(0); 

      ja3.server.num_cipher = 1, ja3.server.cipher[0] = ntohs(*((u_int16_t*)&packet->payload[offset]));
      if((flow->protos.tls_quic_stun.tls_quic.server_unsafe_cipher = ndpi_is_safe_ssl_cipher(ja3.server.cipher[0])) == 1)
	ndpi_set_risk(flow, NDPI_TLS_WEAK_CIPHER);

      flow->protos.tls_quic_stun.tls_quic.server_cipher = ja3.server.cipher[0];


      printf("TLS [server][session_id_len: %u][cipher: %04X]\n", session_id_len, ja3.server.cipher[0]);


      offset += 2 + 1;

      if((offset + 1) < packet->payload_packet_len) 
	extension_len = ntohs(*((u_int16_t*)&packet->payload[offset]));
      else extension_len = 0;


      printf("TLS [server][extension_len: %u]\n", extension_len);

      offset += 2;

      for(i=0; i<extension_len; ) {
	u_int16_t extension_id, extension_len;

	if((offset+4) > packet->payload_packet_len) break;

	extension_id  = ntohs(*((u_int16_t*)&packet->payload[offset]));
	extension_len = ntohs(*((u_int16_t*)&packet->payload[offset+2]));

	if(ja3.server.num_tls_extension < MAX_NUM_JA3)
	  ja3.server.tls_extension[ja3.server.num_tls_extension++] = extension_id;


	printf("TLS [server][extension_id: %u/0x%04X][len: %u]\n", extension_id, extension_id, extension_len);


	if(extension_id == 43 ) {
	  if(extension_len >= 2) {
	    u_int16_t tls_version = ntohs(*((u_int16_t*)&packet->payload[offset+4]));


	    printf("TLS [server] [TLS version: 0x%04X]\n", tls_version);


	    flow->protos.tls_quic_stun.tls_quic.ssl_version = ja3.server.tls_supported_version = tls_version;
	  }
	} else if(extension_id == 16 ) {
	  u_int16_t s_offset = offset+4;
	  u_int16_t tot_alpn_len = ntohs(*((u_int16_t*)&packet->payload[s_offset]));
	  char alpn_str[256];
	  u_int8_t alpn_str_len = 0, i;


	  printf("Server TLS [ALPN: block_len=%u/len=%u]\n", extension_len, tot_alpn_len);

	  s_offset += 2;
	  tot_alpn_len += s_offset;

	  while(s_offset < tot_alpn_len && s_offset < total_len) {
	    u_int8_t alpn_i, alpn_len = packet->payload[s_offset++];

	    if((s_offset + alpn_len) <= tot_alpn_len) {

	      printf("Server TLS [ALPN: %u]\n", alpn_len);


	      if((alpn_str_len+alpn_len+1) < (sizeof(alpn_str)-1)) {
	        if(alpn_str_len > 0) {
	          alpn_str[alpn_str_len] = ',';
	          alpn_str_len++;
	        }

	        for(alpn_i=0; alpn_i<alpn_len; alpn_i++)
	        {
	          alpn_str[alpn_str_len+alpn_i] = packet->payload[s_offset+alpn_i];
	        }

	        s_offset += alpn_len, alpn_str_len += alpn_len;;
	      } else {
	        ndpi_set_risk(flow, NDPI_TLS_UNCOMMON_ALPN);
	        break;
	      }
	    } else {
	      ndpi_set_risk(flow, NDPI_TLS_UNCOMMON_ALPN);
	      break;
	    }
	  } 

	  alpn_str[alpn_str_len] = '\0';


	  printf("Server TLS [ALPN: %s][len: %u]\n", alpn_str, alpn_str_len);

	  if(flow->protos.tls_quic_stun.tls_quic.alpn == NULL)
	    flow->protos.tls_quic_stun.tls_quic.alpn = ndpi_strdup(alpn_str);

	  if(flow->protos.tls_quic_stun.tls_quic.alpn != NULL)
	    tlsCheckUncommonALPN(flow);

	  snprintf(ja3.server.alpn, sizeof(ja3.server.alpn), "%s", alpn_str);

	  
	  for(i=0; ja3.server.alpn[i] != '\0'; i++)
	    if(ja3.server.alpn[i] == ',') ja3.server.alpn[i] = '-';
	} else if(extension_id == 11 ) {
	  u_int16_t s_offset = offset+4 + 1;


	  printf("Server TLS [EllipticCurveFormat: len=%u]\n", extension_len);

	  if((s_offset+extension_len-1) <= total_len) {
	    for(i=0; i<extension_len-1; i++) {
	      u_int8_t s_group = packet->payload[s_offset+i];


	      printf("Server TLS [EllipticCurveFormat: %u]\n", s_group);


	      if(ja3.server.num_elliptic_curve_point_format < MAX_NUM_JA3)
		ja3.server.elliptic_curve_point_format[ja3.server.num_elliptic_curve_point_format++] = s_group;
	      else {
		invalid_ja3 = 1;

		printf("Server TLS Invalid num elliptic %u\n", ja3.server.num_elliptic_curve_point_format);

	      }
	    }
	  } else {
	    invalid_ja3 = 1;

	    printf("Server TLS Invalid len %u vs %u\n", s_offset+extension_len, total_len);

	  }
	}

	i += 4 + extension_len, offset += 4 + extension_len;
      } 

      ja3_str_len = snprintf(ja3_str, sizeof(ja3_str), "%u,", ja3.server.tls_handshake_version);

      for(i=0; i<ja3.server.num_cipher; i++) {
	rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.server.cipher[i]);

	if(rc <= 0) break; else ja3_str_len += rc;
      }

      rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, ",");
      if(rc > 0 && ja3_str_len + rc < JA3_STR_LEN) ja3_str_len += rc;

      

      for(i=0; i<ja3.server.num_tls_extension; i++) {
	int rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.server.tls_extension[i]);

	if(rc <= 0) break; else ja3_str_len += rc;
      }

      if(ndpi_struct->enable_ja3_plus) {
	for(i=0; i<ja3.server.num_elliptic_curve_point_format; i++) {
	  rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.server.elliptic_curve_point_format[i]);
	  if((rc > 0) && (ja3_str_len + rc < JA3_STR_LEN)) ja3_str_len += rc; else break;
	}

	if(ja3.server.alpn[0] != '\0') {
	  rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, ",%s", ja3.server.alpn);
	  if((rc > 0) && (ja3_str_len + rc < JA3_STR_LEN)) ja3_str_len += rc;
	}


	printf("[JA3+] Server: %s \n", ja3_str);

      } else {

	printf("[JA3] Server: %s \n", ja3_str);

      }

      ndpi_MD5Init(&ctx);
      ndpi_MD5Update(&ctx, (const unsigned char *)ja3_str, strlen(ja3_str));
      ndpi_MD5Final(md5_hash, &ctx);

      for(i=0, j=0; i<16; i++) {
	int rc = snprintf(&flow->protos.tls_quic_stun.tls_quic.ja3_server[j], sizeof(flow->protos.tls_quic_stun.tls_quic.ja3_server)-j, "%02x", md5_hash[i]);
	if(rc <= 0) break; else j += rc;
      }


      printf("[JA3] Server: %s \n", flow->protos.tls_quic_stun.tls_quic.ja3_server);

    } else if(handshake_type == 0x01 ) {
      u_int16_t cipher_len, cipher_offset;
      u_int8_t cookie_len = 0;

      flow->protos.tls_quic_stun.tls_quic.ssl_version = ja3.client.tls_handshake_version = tls_version;
      if(flow->protos.tls_quic_stun.tls_quic.ssl_version < 0x0302) 
	ndpi_set_risk(flow, NDPI_TLS_OBSOLETE_VERSION);

      if((session_id_len+base_offset+3) > packet->payload_packet_len)
	return(0); 

      if(!is_dtls) {
	cipher_len = packet->payload[session_id_len+base_offset+2] + (packet->payload[session_id_len+base_offset+1] << 8);
	cipher_offset = base_offset + session_id_len + 3;
      } else {
	cookie_len = packet->payload[base_offset+session_id_len+1];

	printf("[JA3] Client: DTLS cookie len %d\n", cookie_len);

	if((session_id_len+base_offset+cookie_len+4) > packet->payload_packet_len)
	  return(0); 
	cipher_len = ntohs(*((u_int16_t*)&packet->payload[base_offset+session_id_len+cookie_len+2]));
	cipher_offset = base_offset + session_id_len + cookie_len + 4;
      }


      printf("Client TLS [client cipher_len: %u][tls_version: 0x%04X]\n", cipher_len, tls_version);


      if((cipher_offset+cipher_len) <= total_len) {
	u_int8_t safari_ciphers = 0, chrome_ciphers = 0;

	for(i=0; i<cipher_len;) {
	  u_int16_t *id = (u_int16_t*)&packet->payload[cipher_offset+i];


	  printf("Client TLS [cipher suite: %u/0x%04X] [%d/%u]\n", ntohs(*id), ntohs(*id), i, cipher_len);

	  if((*id == 0) || (packet->payload[cipher_offset+i] != packet->payload[cipher_offset+i+1])) {
	    u_int16_t cipher_id = ntohs(*id);
	    

	    if(ja3.client.num_cipher < MAX_NUM_JA3)
	      ja3.client.cipher[ja3.client.num_cipher++] = cipher_id;
	    else {
	      invalid_ja3 = 1;

	      printf("Client TLS Invalid cipher %u\n", ja3.client.num_cipher);

	    }

	    switch(cipher_id) {
	    case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
	    case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
	      safari_ciphers++;
	      break;

	    case TLS_CIPHER_GREASE_RESERVED_0:
	    case TLS_AES_128_GCM_SHA256:
	    case TLS_AES_256_GCM_SHA384:
	    case TLS_CHACHA20_POLY1305_SHA256:
	      chrome_ciphers++;
	      break;

	    case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
	    case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
	    case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
	    case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
	    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
	    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
	    case TLS_RSA_WITH_AES_128_CBC_SHA:
	    case TLS_RSA_WITH_AES_256_CBC_SHA:
	    case TLS_RSA_WITH_AES_128_GCM_SHA256:
	    case TLS_RSA_WITH_AES_256_GCM_SHA384:
	      safari_ciphers++, chrome_ciphers++;
	      break;
	    }
	  }

	  i += 2;
	} 

	if(chrome_ciphers == 13)
	  flow->protos.tls_quic_stun.tls_quic.browser_euristics.is_chrome_tls = 1;
	else if(safari_ciphers == 12)
	  flow->protos.tls_quic_stun.tls_quic.browser_euristics.is_safari_tls = 1;
      } else {
	invalid_ja3 = 1;

	printf("Client TLS Invalid len %u vs %u\n", (cipher_offset+cipher_len), total_len);

      }

      offset = base_offset + session_id_len + cookie_len + cipher_len + 2;
      offset += (!is_dtls) ? 1 : 2;

      if(offset < total_len) {
	u_int16_t compression_len;
	u_int16_t extensions_len;

	compression_len = packet->payload[offset];
	offset++;


	printf("Client TLS [compression_len: %u]\n", compression_len);


	
	offset += compression_len;

	if(offset+1 < total_len) {
	  extensions_len = ntohs(*((u_int16_t*)&packet->payload[offset]));
	  offset += 2;


	  printf("Client TLS [extensions_len: %u]\n", extensions_len);


	  if((extensions_len+offset) <= total_len) {
	    
	    u_int extension_offset = 0;
	    u_int32_t j;

	    while(extension_offset < extensions_len && offset+extension_offset+4 <= total_len) {
	      u_int16_t extension_id, extension_len, extn_off = offset+extension_offset;


	      extension_id = ntohs(*((u_int16_t*)&packet->payload[offset+extension_offset]));
	      extension_offset += 2;

	      extension_len = ntohs(*((u_int16_t*)&packet->payload[offset+extension_offset]));
	      extension_offset += 2;


	      printf("Client TLS [extension_id: %u][extension_len: %u]\n", extension_id, extension_len);


	      if((extension_id == 0) || (packet->payload[extn_off] != packet->payload[extn_off+1])) {
		

		if(ja3.client.num_tls_extension < MAX_NUM_JA3)
		  ja3.client.tls_extension[ja3.client.num_tls_extension++] = extension_id;
		else {
		  invalid_ja3 = 1;

		  printf("Client TLS Invalid extensions %u\n", ja3.client.num_tls_extension);

		}
	      }

	      if(extension_id == 0 ) {
		u_int16_t len;


		printf("[TLS] Extensions: found server name\n");

		if((offset+extension_offset+4) < packet->payload_packet_len) {

		  len = (packet->payload[offset+extension_offset+3] << 8) + packet->payload[offset+extension_offset+4];
		  len = (u_int)ndpi_min(len, sizeof(buffer)-1);

		  if((offset+extension_offset+5+len) <= packet->payload_packet_len) {
		    strncpy(buffer, (char*)&packet->payload[offset+extension_offset+5], len);
		    buffer[len] = '\0';

		    cleanupServerName(buffer, sizeof(buffer));

		    snprintf(flow->protos.tls_quic_stun.tls_quic.client_requested_server_name, sizeof(flow->protos.tls_quic_stun.tls_quic.client_requested_server_name), "%s", buffer);


		    printf("[TLS] SNI: [%s]\n", buffer);

		    if(!is_quic) {
		      if(ndpi_match_hostname_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TLS, buffer, strlen(buffer)))
		        flow->l4.tcp.tls.subprotocol_detected = 1;
		    } else {
		      if(ndpi_match_hostname_protocol(ndpi_struct, flow, NDPI_PROTOCOL_QUIC, buffer, strlen(buffer)))
		        flow->l4.tcp.tls.subprotocol_detected = 1;
		    }

		    if(ndpi_check_dga_name(ndpi_struct, flow, flow->protos.tls_quic_stun.tls_quic.client_requested_server_name, 1)) {
		      char *sni = flow->protos.tls_quic_stun.tls_quic.client_requested_server_name;
		      int len = strlen(sni);


		      printf("[TLS] SNI: (DGA) [%s]\n", flow->protos.tls_quic_stun.tls_quic.client_requested_server_name);


		      if((len >= 4)
		         
		         && ((strcmp(&sni[len-4], ".com") == 0) || (strcmp(&sni[len-4], ".net") == 0))
		         && (strncmp(sni, "www.", 4) == 0)) 
		        ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TOR, NDPI_PROTOCOL_TLS);
		    } else {

		      printf("[TLS] SNI: (NO DGA) [%s]\n", flow->protos.tls_quic_stun.tls_quic.client_requested_server_name);

		    }
		  } else {

		    printf("[TLS] Extensions server len too short: %u vs %u\n", offset+extension_offset+5+len, packet->payload_packet_len);


		  }
		}
	      } else if(extension_id == 10 ) {
		u_int16_t s_offset = offset+extension_offset + 2;


		printf("Client TLS [EllipticCurveGroups: len=%u]\n", extension_len);


		if((s_offset+extension_len-2) <= total_len) {
		  for(i=0; i<extension_len-2;) {
		    u_int16_t s_group = ntohs(*((u_int16_t*)&packet->payload[s_offset+i]));


		    printf("Client TLS [EllipticCurve: %u/0x%04X]\n", s_group, s_group);

		    if((s_group == 0) || (packet->payload[s_offset+i] != packet->payload[s_offset+i+1])) {
		      
		      if(ja3.client.num_elliptic_curve < MAX_NUM_JA3)
			ja3.client.elliptic_curve[ja3.client.num_elliptic_curve++] = s_group;
		      else {
			invalid_ja3 = 1;

			printf("Client TLS Invalid num elliptic %u\n", ja3.client.num_elliptic_curve);

		      }
		    }

		    i += 2;
		  }
		} else {
		  invalid_ja3 = 1;

		  printf("Client TLS Invalid len %u vs %u\n", (s_offset+extension_len-1), total_len);

		}
	      } else if(extension_id == 11 ) {
		u_int16_t s_offset = offset+extension_offset + 1;


		printf("Client TLS [EllipticCurveFormat: len=%u]\n", extension_len);

		if((s_offset+extension_len-1) <= total_len) {
		  for(i=0; i<extension_len-1; i++) {
		    u_int8_t s_group = packet->payload[s_offset+i];


		    printf("Client TLS [EllipticCurveFormat: %u]\n", s_group);


		    if(ja3.client.num_elliptic_curve_point_format < MAX_NUM_JA3)
		      ja3.client.elliptic_curve_point_format[ja3.client.num_elliptic_curve_point_format++] = s_group;
		    else {
		      invalid_ja3 = 1;

		      printf("Client TLS Invalid num elliptic %u\n", ja3.client.num_elliptic_curve_point_format);

		    }
		  }
		} else {
		  invalid_ja3 = 1;

		  printf("Client TLS Invalid len %u vs %u\n", s_offset+extension_len, total_len);

		}
	      } else if(extension_id == 13 ) {
		u_int16_t s_offset = offset+extension_offset, safari_signature_algorithms = 0, chrome_signature_algorithms = 0;
		u_int16_t tot_signature_algorithms_len = ntohs(*((u_int16_t*)&packet->payload[s_offset]));


		printf("Client TLS [SIGNATURE_ALGORITHMS: block_len=%u/len=%u]\n", extension_len, tot_signature_algorithms_len);


		s_offset += 2;
		tot_signature_algorithms_len = ndpi_min((sizeof(ja3.client.signature_algorithms) / 2) - 1, tot_signature_algorithms_len);


		flow->protos.tls_quic_stun.tls_quic.num_tls_signature_algorithms = ndpi_min(tot_signature_algorithms_len / 2, MAX_NUM_TLS_SIGNATURE_ALGORITHMS);

		memcpy(flow->protos.tls_quic_stun.tls_quic.client_signature_algorithms, &packet->payload[s_offset], 2 *flow->protos.tls_quic_stun.tls_quic.num_tls_signature_algorithms);


		for(i=0; i<tot_signature_algorithms_len; i++) {
		  int rc = snprintf(&ja3.client.signature_algorithms[i*2], sizeof(ja3.client.signature_algorithms)-i*2, "%02X", packet->payload[s_offset+i]);

		  if(rc < 0) break;
		}

		for(i=0; i<tot_signature_algorithms_len; i+=2) {
		  u_int16_t cipher_id = (u_int16_t)ntohs(*((u_int16_t*)&packet->payload[s_offset+i]));

		  

		  switch(cipher_id) {
		  case ECDSA_SECP521R1_SHA512:
		    flow->protos.tls_quic_stun.tls_quic.browser_euristics.is_firefox_tls = 1;
		    break;

		  case ECDSA_SECP256R1_SHA256:
		  case ECDSA_SECP384R1_SHA384:
		  case RSA_PKCS1_SHA256:
		  case RSA_PKCS1_SHA384:
		  case RSA_PKCS1_SHA512:
		  case RSA_PSS_RSAE_SHA256:
		  case RSA_PSS_RSAE_SHA384:
		  case RSA_PSS_RSAE_SHA512:
		    chrome_signature_algorithms++, safari_signature_algorithms++;
		    break;
		  }
		}

		if(flow->protos.tls_quic_stun.tls_quic.browser_euristics.is_firefox_tls)
		  flow->protos.tls_quic_stun.tls_quic.browser_euristics.is_safari_tls = 0, flow->protos.tls_quic_stun.tls_quic.browser_euristics.is_chrome_tls = 0;

		if(safari_signature_algorithms != 8)
		   flow->protos.tls_quic_stun.tls_quic.browser_euristics.is_safari_tls = 0;

		if(chrome_signature_algorithms != 8)
		   flow->protos.tls_quic_stun.tls_quic.browser_euristics.is_chrome_tls = 0;

		ja3.client.signature_algorithms[i*2] = '\0';


		printf("Client TLS [SIGNATURE_ALGORITHMS: %s]\n", ja3.client.signature_algorithms);

	      } else if(extension_id == 16 ) {
		u_int16_t s_offset = offset+extension_offset;
		u_int16_t tot_alpn_len = ntohs(*((u_int16_t*)&packet->payload[s_offset]));
		char alpn_str[256];
		u_int8_t alpn_str_len = 0, i;


		printf("Client TLS [ALPN: block_len=%u/len=%u]\n", extension_len, tot_alpn_len);

		s_offset += 2;
		tot_alpn_len += s_offset;

		while(s_offset < tot_alpn_len && s_offset < total_len) {
		  u_int8_t alpn_i, alpn_len = packet->payload[s_offset++];

		  if((s_offset + alpn_len) <= tot_alpn_len && (s_offset + alpn_len) <= total_len) {

		    printf("Client TLS [ALPN: %u]\n", alpn_len);


		    if((alpn_str_len+alpn_len+1) < (sizeof(alpn_str)-1)) {
		      if(alpn_str_len > 0) {
			alpn_str[alpn_str_len] = ',';
			alpn_str_len++;
		      }

		      for(alpn_i=0; alpn_i<alpn_len; alpn_i++)
			alpn_str[alpn_str_len+alpn_i] = packet->payload[s_offset+alpn_i];

		      s_offset += alpn_len, alpn_str_len += alpn_len;;
		    } else break;
		  } else break;
		} 

		alpn_str[alpn_str_len] = '\0';


		printf("Client TLS [ALPN: %s][len: %u]\n", alpn_str, alpn_str_len);

		if(flow->protos.tls_quic_stun.tls_quic.alpn == NULL)
		  flow->protos.tls_quic_stun.tls_quic.alpn = ndpi_strdup(alpn_str);

		snprintf(ja3.client.alpn, sizeof(ja3.client.alpn), "%s", alpn_str);

		
		for(i=0; ja3.client.alpn[i] != '\0'; i++)
		  if(ja3.client.alpn[i] == ',') ja3.client.alpn[i] = '-';

	      } else if(extension_id == 43 ) {
		u_int16_t s_offset = offset+extension_offset;
		u_int8_t version_len = packet->payload[s_offset];
		char version_str[256];
		u_int8_t version_str_len = 0;
		version_str[0] = 0;

		printf("Client TLS [TLS version len: %u]\n", version_len);


		if(version_len == (extension_len-1)) {
		  u_int8_t j;
		  u_int16_t supported_versions_offset = 0;

		  s_offset++;

		  
		  for(j=0; j+1<version_len; j += 2) {
		    u_int16_t tls_version = ntohs(*((u_int16_t*)&packet->payload[s_offset+j]));
		    u_int8_t unknown_tls_version;


		    printf("Client TLS [TLS version: %s/0x%04X]\n", ndpi_ssl_version2str(flow, tls_version, &unknown_tls_version), tls_version);


		    if((version_str_len+8) < sizeof(version_str)) {
		      int rc = snprintf(&version_str[version_str_len], sizeof(version_str) - version_str_len, "%s%s", (version_str_len > 0) ? "," : "", ndpi_ssl_version2str(flow, tls_version, &unknown_tls_version));


		      if(rc <= 0)
			break;
		      else version_str_len += rc;

		      rc = snprintf(&ja3.client.supported_versions[supported_versions_offset], sizeof(ja3.client.supported_versions)-supported_versions_offset, "%s%04X", (j > 0) ? "-" : "", tls_version);


		      if(rc > 0)
			supported_versions_offset += rc;
		    }
		  }


		  printf("Client TLS [SUPPORTED_VERSIONS: %s]\n", ja3.client.supported_versions);


		  if(flow->protos.tls_quic_stun.tls_quic.tls_supported_versions == NULL)
		    flow->protos.tls_quic_stun.tls_quic.tls_supported_versions = ndpi_strdup(version_str);
		}
	      } else if(extension_id == 65486 ) {
		
		u_int16_t e_offset = offset+extension_offset;
		u_int16_t initial_offset = e_offset;
		u_int16_t e_sni_len, cipher_suite = ntohs(*((u_int16_t*)&packet->payload[e_offset]));

		flow->protos.tls_quic_stun.tls_quic.encrypted_sni.cipher_suite = cipher_suite;

		e_offset += 2; 

		
		e_offset += 2; 
		e_offset +=  ntohs(*((u_int16_t*)&packet->payload[e_offset])) + 2; 

		if((e_offset+4) < packet->payload_packet_len) {
		  
		  e_offset +=  ntohs(*((u_int16_t*)&packet->payload[e_offset])) + 2; 

		  if((e_offset+4) < packet->payload_packet_len) {
		    e_sni_len = ntohs(*((u_int16_t*)&packet->payload[e_offset]));
		    e_offset += 2;

		    if((e_offset+e_sni_len-extension_len-initial_offset) >= 0 && e_offset+e_sni_len < packet->payload_packet_len) {

		      printf("Client TLS [Encrypted Server Name len: %u]\n", e_sni_len);


		      if(flow->protos.tls_quic_stun.tls_quic.encrypted_sni.esni == NULL) {
			flow->protos.tls_quic_stun.tls_quic.encrypted_sni.esni = (char*)ndpi_malloc(e_sni_len*2+1);

			if(flow->protos.tls_quic_stun.tls_quic.encrypted_sni.esni) {
			  u_int16_t i, off;

			  for(i=e_offset, off=0; i<(e_offset+e_sni_len); i++) {
			    int rc = sprintf(&flow->protos.tls_quic_stun.tls_quic.encrypted_sni.esni[off], "%02X", packet->payload[i] & 0XFF);

			    if(rc <= 0) {
			      flow->protos.tls_quic_stun.tls_quic.encrypted_sni.esni[off] = '\0';
			      break;
			    } else off += rc;
			  }
			}
		      }
		    }
		  }
		}
	      } else if(extension_id == 65445 ||  extension_id == 57) {
		u_int16_t s_offset = offset+extension_offset;
		uint16_t final_offset;
		int using_var_int = is_version_with_var_int_transport_params(quic_version);

		if(!using_var_int) {
		  if(s_offset+1 >= total_len) {
		    final_offset = 0; 
		  } else {
		    u_int16_t seq_len = ntohs(*((u_int16_t*)&packet->payload[s_offset]));
		    s_offset += 2;
	            final_offset = MIN(total_len, s_offset + seq_len);
		  }
		} else {
	          final_offset = MIN(total_len, s_offset + extension_len);
		}

		while(s_offset < final_offset) {
		  u_int64_t param_type, param_len;

                  if(!using_var_int) {
		    if(s_offset+3 >= final_offset)
		      break;
		    param_type = ntohs(*((u_int16_t*)&packet->payload[s_offset]));
		    param_len = ntohs(*((u_int16_t*)&packet->payload[s_offset + 2]));
		    s_offset += 4;
		  } else {
		    if(s_offset >= final_offset || (s_offset + quic_len_buffer_still_required(packet->payload[s_offset])) >= final_offset)
		      break;
		    s_offset += quic_len(&packet->payload[s_offset], &param_type);

		    if(s_offset >= final_offset || (s_offset + quic_len_buffer_still_required(packet->payload[s_offset])) >= final_offset)
		      break;
		    s_offset += quic_len(&packet->payload[s_offset], &param_len);
		  }


		  printf("Client TLS [QUIC TP: Param 0x%x Len %d]\n", (int)param_type, (int)param_len);

		  if(s_offset+param_len > final_offset)
		    break;

		  if(param_type==0x3129) {

		      printf("UA [%.*s]\n", (int)param_len, &packet->payload[s_offset]);

		      http_process_user_agent(ndpi_struct, flow, &packet->payload[s_offset], param_len);
		      break;
		  }
		  s_offset += param_len;
		}
	      }

	      extension_offset += extension_len; 


	      printf("Client TLS [extension_offset/len: %u/%u]\n", extension_offset, extension_len);

	    } 

	    if(!invalid_ja3) {
	      int rc;

	    compute_ja3c:
	      ja3_str_len = snprintf(ja3_str, sizeof(ja3_str), "%u,", ja3.client.tls_handshake_version);

	      for(i=0; i<ja3.client.num_cipher; i++) {
		rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.client.cipher[i]);
		if((rc > 0) && (ja3_str_len + rc < JA3_STR_LEN)) ja3_str_len += rc; else break;
	      }

	      rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, ",");
	      if((rc > 0) && (ja3_str_len + rc < JA3_STR_LEN)) ja3_str_len += rc;

	      

	      for(i=0; i<ja3.client.num_tls_extension; i++) {
		rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.client.tls_extension[i]);
		if((rc > 0) && (ja3_str_len + rc < JA3_STR_LEN)) ja3_str_len += rc; else break;
	      }

	      rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, ",");
	      if((rc > 0) && (ja3_str_len + rc < JA3_STR_LEN)) ja3_str_len += rc;

	      

	      for(i=0; i<ja3.client.num_elliptic_curve; i++) {
		rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.client.elliptic_curve[i]);
		if((rc > 0) && (ja3_str_len + rc < JA3_STR_LEN)) ja3_str_len += rc; else break;
	      }

	      rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, ",");
	      if((rc > 0) && (ja3_str_len + rc < JA3_STR_LEN)) ja3_str_len += rc;

	      for(i=0; i<ja3.client.num_elliptic_curve_point_format; i++) {
		rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.client.elliptic_curve_point_format[i]);
		if((rc > 0) && (ja3_str_len + rc < JA3_STR_LEN)) ja3_str_len += rc; else break;
	      }

	      if(ndpi_struct->enable_ja3_plus) {
		rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, ",%s,%s,%s", ja3.client.signature_algorithms, ja3.client.supported_versions, ja3.client.alpn);
		if((rc > 0) && (ja3_str_len + rc < JA3_STR_LEN)) ja3_str_len += rc;
	      }


	      printf("[JA3+] Client: %s \n", ja3_str);


	      ndpi_MD5Init(&ctx);
	      ndpi_MD5Update(&ctx, (const unsigned char *)ja3_str, strlen(ja3_str));
	      ndpi_MD5Final(md5_hash, &ctx);

	      for(i=0, j=0; i<16; i++) {
		rc = snprintf(&flow->protos.tls_quic_stun.tls_quic.ja3_client[j], sizeof(flow->protos.tls_quic_stun.tls_quic.ja3_client)-j, "%02x", md5_hash[i]);

		if(rc > 0) j += rc; else break;
	      }


	      printf("[JA3] Client: %s \n", flow->protos.tls_quic_stun.tls_quic.ja3_client);


	      if(ndpi_struct->malicious_ja3_automa.ac_automa != NULL) {
		u_int16_t rc1 = ndpi_match_string(ndpi_struct->malicious_ja3_automa.ac_automa, flow->protos.tls_quic_stun.tls_quic.ja3_client);

		if(rc1 > 0)
		  ndpi_set_risk(flow, NDPI_MALICIOUS_JA3);
	      }
	    }

	    
	    if((flow->protos.tls_quic_stun.tls_quic.ssl_version >= 0x0303) 
	       && (flow->protos.tls_quic_stun.tls_quic.alpn == NULL) ) {
	      ndpi_set_risk(flow, NDPI_TLS_NOT_CARRYING_HTTPS);
	    }

	    
	    if(flow->protos.tls_quic_stun.tls_quic.encrypted_sni.esni && flow->protos.tls_quic_stun.tls_quic.client_requested_server_name[0] != '\0') {
	      ndpi_set_risk(flow, NDPI_TLS_SUSPICIOUS_ESNI_USAGE);
	    }

	    
	    if((flow->protos.tls_quic_stun.tls_quic.client_requested_server_name[0] == 0)
	       && (flow->protos.tls_quic_stun.tls_quic.ssl_version >= 0x0302) 
	       && (flow->protos.tls_quic_stun.tls_quic.encrypted_sni.esni == NULL) 
	       ) {
	      
	      ndpi_set_risk(flow, NDPI_TLS_MISSING_SNI);
	    }

	    return(2 );
	  } else {

	    printf("[TLS] Client: too short [%u vs %u]\n", (extensions_len+offset), total_len);

	  }
	} else if(offset == total_len) {
	  
	  goto compute_ja3c;
	}
      } else {

	printf("[JA3] Client: invalid length detected\n");

      }
    }
  }

  return(0); 
}



static void ndpi_search_tls_wrapper(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;


  printf("==>> %s() %u [len: %u][version: %u]\n", __FUNCTION__, flow->guessed_host_protocol_id, packet->payload_packet_len, flow->protos.tls_quic_stun.tls_quic.ssl_version);





  if(packet->udp != NULL)
    ndpi_search_tls_udp(ndpi_struct, flow);
  else ndpi_search_tls_tcp(ndpi_struct, flow);
}



void init_tls_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("TLS", ndpi_struct, detection_bitmask, *id, NDPI_PROTOCOL_TLS, ndpi_search_tls_wrapper, NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);





  *id += 1;

  

  ndpi_set_bitmask_protocol_detection("DTLS", ndpi_struct, detection_bitmask, *id, NDPI_PROTOCOL_DTLS, ndpi_search_tls_wrapper, NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD, SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);





  *id += 1;
}
