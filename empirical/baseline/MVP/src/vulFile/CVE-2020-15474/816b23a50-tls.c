










extern char *strptime(const char *s, const char *format, struct tm *tm);
extern int processClientServerHello(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow);














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

  

  printf("[TLS Mem] Handling TCP/TLS flow [payload_len: %u][buffer_len: %u][direction: %u]\n", packet->payload_packet_len, flow->l4.tcp.tls.message.buffer_len, packet->packet_direction);




  if(flow->l4.tcp.tls.message.buffer == NULL) {
    
    flow->l4.tcp.tls.message.buffer_len = 2048, flow->l4.tcp.tls.message.buffer_used = 0;
    flow->l4.tcp.tls.message.buffer = (u_int8_t*)ndpi_malloc(flow->l4.tcp.tls.message.buffer_len);

    if(flow->l4.tcp.tls.message.buffer == NULL)
      return;


    printf("[TLS Mem] Allocating %u buffer\n", flow->l4.tcp.tls.message.buffer_len);

  }

  u_int avail_bytes = flow->l4.tcp.tls.message.buffer_len - flow->l4.tcp.tls.message.buffer_used;
  if(avail_bytes < packet->payload_packet_len) {
    u_int new_len = flow->l4.tcp.tls.message.buffer_len + packet->payload_packet_len;
    void *newbuf  = ndpi_realloc(flow->l4.tcp.tls.message.buffer, flow->l4.tcp.tls.message.buffer_len, new_len);
    if(!newbuf) return;

    flow->l4.tcp.tls.message.buffer = (u_int8_t*)newbuf, flow->l4.tcp.tls.message.buffer_len = new_len;
    avail_bytes = flow->l4.tcp.tls.message.buffer_len - flow->l4.tcp.tls.message.buffer_used;


    printf("[TLS Mem] Enlarging %u -> %u buffer\n", flow->l4.tcp.tls.message.buffer_len, new_len);

  }

  if(avail_bytes >= packet->payload_packet_len) {
    memcpy(&flow->l4.tcp.tls.message.buffer[flow->l4.tcp.tls.message.buffer_used], packet->payload, packet->payload_packet_len);

    flow->l4.tcp.tls.message.buffer_used += packet->payload_packet_len;

    printf("[TLS Mem] Copied data to buffer [%u/%u bytes]\n", flow->l4.tcp.tls.message.buffer_used, flow->l4.tcp.tls.message.buffer_len);

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




static void processCertificateElements(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow, u_int16_t p_offset, u_int16_t certificate_len) {

  struct ndpi_packet_struct *packet = &flow->packet;
  u_int num_found = 0, i;
  char buffer[64] = { '\0' }, rdnSeqBuf[1024] = { '\0' };
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


	if(rdn_len) flow->protos.stun_ssl.ssl.issuerDN = ndpi_strdup(rdnSeqBuf);
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
	    flow->protos.stun_ssl.ssl.notBefore = timegm(&utc);

	    printf("[CERTIFICATE] notBefore %u [%s]\n", flow->protos.stun_ssl.ssl.notBefore, utcDate);

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
		flow->protos.stun_ssl.ssl.notAfter = timegm(&utc);

		printf("[CERTIFICATE] notAfter %u [%s]\n", flow->protos.stun_ssl.ssl.notAfter, utcDate);

	      }
	    }


	    if((time_sec < flow->protos.stun_ssl.ssl.notBefore)
	       || (time_sec > flow->protos.stun_ssl.ssl.notAfter))
	    NDPI_SET_BIT(flow->risk, NDPI_TLS_CERTIFICATE_EXPIRED); 
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

		  
		  if(len == 0 )
		    break;

		  strncpy(dNSName, (const char*)&packet->payload[i], len);
		  dNSName[len] = '\0';

		  cleanupServerName(dNSName, len);


		  printf("[TLS] dNSName %s [%s]\n", dNSName, flow->protos.stun_ssl.ssl.client_requested_server_name);

		  if(matched_name == 0) {
		    if((dNSName[0] == '*') && strstr(flow->protos.stun_ssl.ssl.client_requested_server_name, &dNSName[1]))
		      matched_name = 1;
		    else if(strcmp(flow->protos.stun_ssl.ssl.client_requested_server_name, dNSName) == 0)
		      matched_name = 1;
		  }

		  if(flow->protos.stun_ssl.ssl.server_names == NULL)
		    flow->protos.stun_ssl.ssl.server_names = ndpi_strdup(dNSName), flow->protos.stun_ssl.ssl.server_names_len = strlen(dNSName);
		  else {
		    u_int16_t dNSName_len = strlen(dNSName);
		    u_int16_t newstr_len = flow->protos.stun_ssl.ssl.server_names_len + dNSName_len + 1;
		    char *newstr = (char*)ndpi_realloc(flow->protos.stun_ssl.ssl.server_names, flow->protos.stun_ssl.ssl.server_names_len+1, newstr_len+1);

		    if(newstr) {
		      flow->protos.stun_ssl.ssl.server_names = newstr;
		      flow->protos.stun_ssl.ssl.server_names[flow->protos.stun_ssl.ssl.server_names_len] = ',';
		      strncpy(&flow->protos.stun_ssl.ssl.server_names[flow->protos.stun_ssl.ssl.server_names_len+1], dNSName, dNSName_len+1);
		      flow->protos.stun_ssl.ssl.server_names[newstr_len] = '\0';
		      flow->protos.stun_ssl.ssl.server_names_len = newstr_len;
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
	      NDPI_SET_BIT(flow->risk, NDPI_TLS_CERTIFICATE_MISMATCH); 
	  }
	}
      }
    }
  }

  if(rdn_len) flow->protos.stun_ssl.ssl.subjectDN = ndpi_strdup(rdnSeqBuf);

  if(flow->protos.stun_ssl.ssl.subjectDN && flow->protos.stun_ssl.ssl.issuerDN && (!strcmp(flow->protos.stun_ssl.ssl.subjectDN, flow->protos.stun_ssl.ssl.issuerDN)))
    NDPI_SET_BIT(flow->risk, NDPI_TLS_SELFSIGNED_CERTIFICATE);


  printf("[TLS] %s() SubjectDN [%s]\n", __FUNCTION__, rdnSeqBuf);

}




int processCertificate(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int32_t certificates_length, length = (packet->payload[1] << 16) + (packet->payload[2] << 8) + packet->payload[3];
  u_int16_t certificates_offset = 7;
  u_int8_t num_certificates_found = 0;


  printf("[TLS] %s() [payload_packet_len=%u][direction: %u][%02X %02X %02X %02X %02X %02X...]\n", __FUNCTION__, packet->payload_packet_len, packet->packet_direction, packet->payload[0], packet->payload[1], packet->payload[2], packet->payload[3], packet->payload[4], packet->payload[5]);





  if((packet->payload_packet_len != (length + 4)) || (packet->payload[1] != 0x0))
    return(-1); 

  certificates_length = (packet->payload[4] << 16) + (packet->payload[5] << 8) + packet->payload[6];

  if((packet->payload[4] != 0x0) || ((certificates_length+3) != length))
    return(-2); 

  if(!flow->l4.tcp.tls.srv_cert_fingerprint_ctx) {
    if((flow->l4.tcp.tls.srv_cert_fingerprint_ctx = (void*)ndpi_malloc(sizeof(SHA1_CTX))) == NULL)
      return(-3); 
  }

  
  while(certificates_offset < certificates_length) {
    u_int32_t certificate_len = (packet->payload[certificates_offset] << 16) + (packet->payload[certificates_offset+1] << 8) + packet->payload[certificates_offset+2];

    
    if((certificate_len == 0)
       || (packet->payload[certificates_offset] != 0x0)
       || ((certificates_offset+certificate_len) > (4+certificates_length))) {

      printf("[TLS] Invalid length [certificate_len: %u][certificates_offset: %u][%u vs %u]\n", certificate_len, certificates_offset, (certificates_offset+certificate_len), certificates_length);



      break;
    }

    certificates_offset += 3;

    printf("[TLS] Processing %u bytes certificate [%02X %02X %02X]\n", certificate_len, packet->payload[certificates_offset], packet->payload[certificates_offset+1], packet->payload[certificates_offset+2]);





    if(num_certificates_found++ == 0)  {
      

      SHA1Init(flow->l4.tcp.tls.srv_cert_fingerprint_ctx);


      {
	int i;

	for(i=0;i<certificate_len;i++)
	  printf("%02X ", packet->payload[certificates_offset+i]);

	printf("\n");
      }


      SHA1Update(flow->l4.tcp.tls.srv_cert_fingerprint_ctx, &packet->payload[certificates_offset], certificate_len);


      SHA1Final(flow->l4.tcp.tls.sha1_certificate_fingerprint, flow->l4.tcp.tls.srv_cert_fingerprint_ctx);

      flow->l4.tcp.tls.fingerprint_set = 1;


      {
	int i;

	printf("[TLS] SHA-1: ");
	for(i=0;i<20;i++)
	  printf("%s%02X", (i > 0) ? ":" : "", flow->l4.tcp.tls.sha1_certificate_fingerprint[i]);
	printf("\n");
      }


      processCertificateElements(ndpi_struct, flow, certificates_offset, certificate_len);
    }

    certificates_offset += certificate_len;
  }

  flow->extra_packets_func = NULL; 
  return(1);
}



static int processTLSBlock(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;

  switch(packet->payload[0] ) {
  case 0x01: 
  case 0x02: 
    processClientServerHello(ndpi_struct, flow);
    flow->l4.tcp.tls.hello_processed = 1;
    ndpi_int_tls_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_TLS);
    break;

  case 0x0b: 
    
    if(flow->l4.tcp.tls.hello_processed) {
      processCertificate(ndpi_struct, flow);
      flow->l4.tcp.tls.certificate_processed = 1;
    }
    break;

  default:
    return(-1);
  }

  return(0);
}



static int ndpi_search_tls_tcp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int8_t something_went_wrong = 0;


  printf("[TLS Mem] ndpi_search_tls_tcp() [payload_packet_len: %u]\n", packet->payload_packet_len);


  if(packet->payload_packet_len == 0)
    return(1); 

  ndpi_search_tls_tcp_memory(ndpi_struct, flow);

  while(!something_went_wrong) {
    u_int16_t len, p_len;
    const u_int8_t *p;

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


    
    p = packet->payload, p_len = packet->payload_packet_len; 

    
    u_int16_t processed = 5;

    while((processed+4) < len) {
      const u_int8_t *block = (const u_int8_t *)&flow->l4.tcp.tls.message.buffer[processed];
      u_int32_t block_len   = (block[1] << 16) + (block[2] << 8) + block[3];

      if((block_len == 0) || (block_len > len) || ((block[1] != 0x0))) {
	something_went_wrong = 1;
	break;
      }

      packet->payload = block, packet->payload_packet_len = ndpi_min(block_len+4, flow->l4.tcp.tls.message.buffer_used);

      if((processed+packet->payload_packet_len) > len) {
	something_went_wrong = 1;
	break;
      }


      printf("*** [TLS Mem] Processing %u bytes block [%02X %02X %02X %02X %02X]\n", packet->payload_packet_len, packet->payload[0], packet->payload[1], packet->payload[2], packet->payload[3], packet->payload[4]);




      processTLSBlock(ndpi_struct, flow);
      processed += packet->payload_packet_len;
    }

    packet->payload = p, packet->payload_packet_len = p_len; 
    flow->l4.tcp.tls.message.buffer_used -= len;

    if(flow->l4.tcp.tls.message.buffer_used > 0)
      memmove(flow->l4.tcp.tls.message.buffer, &flow->l4.tcp.tls.message.buffer[len], flow->l4.tcp.tls.message.buffer_used);

    else break;


    printf("[TLS Mem] Left memory buffer %u bytes\n", flow->l4.tcp.tls.message.buffer_used);

  }

  if(something_went_wrong) {
    flow->check_extra_packets = 0, flow->extra_packets_func = NULL;
    return(0); 
  } else return(1);
}



static int ndpi_search_tls_udp(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  
  u_int32_t handshake_len;
  u_int16_t p_len;
  const u_int8_t *p;


  printf("[TLS] %s()\n", __FUNCTION__);


  
  if((packet->payload_packet_len < 17)
     || (packet->payload[0]  != 0x16)
     || (packet->payload[1]  != 0xfe) 
     || ((packet->payload[2] != 0xff) && (packet->payload[2] != 0xfd))
     || ((ntohs(*((u_int16_t*)&packet->payload[11]))+13) != packet->payload_packet_len)
    ) {
  no_dtls:


    printf("[TLS] No DTLS found\n");


    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return(0); 
  }

  
  handshake_len  = (packet->payload[14] << 16) + (packet->payload[15] << 8) + packet->payload[16];

  if((handshake_len+25) != packet->payload_packet_len)
    goto no_dtls;

  
  p = packet->payload, p_len = packet->payload_packet_len; 
  packet->payload = &packet->payload[13], packet->payload_packet_len -= 13;

  processTLSBlock(ndpi_struct, flow);

  packet->payload = p, packet->payload_packet_len = p_len; 

  ndpi_int_tls_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_TLS);

  return(1); 
}



static void tlsInitExtraPacketProcessing(struct ndpi_flow_struct *flow) {
  flow->check_extra_packets = 1;

  
  flow->max_extra_packets_to_check = 12;
  flow->extra_packets_func = (flow->packet.udp != NULL) ? ndpi_search_tls_udp : ndpi_search_tls_tcp;
}



static void ndpi_int_tls_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow, u_int32_t protocol) {

  printf("[TLS] %s()\n", __FUNCTION__);


  if((flow->detected_protocol_stack[0] == protocol)
     || (flow->detected_protocol_stack[1] == protocol)) {
    if(!flow->check_extra_packets)
      tlsInitExtraPacketProcessing(flow);
    return;
  }

  if(protocol != NDPI_PROTOCOL_TLS)
    ;
  else protocol = ndpi_tls_refine_master_protocol(ndpi_struct, flow, protocol);

  ndpi_set_detected_protocol(ndpi_struct, flow, protocol, NDPI_PROTOCOL_TLS);
  tlsInitExtraPacketProcessing(flow);
}








struct ja3_info {
  u_int16_t tls_handshake_version;
  u_int16_t num_cipher, cipher[MAX_NUM_JA3];
  u_int16_t num_tls_extension, tls_extension[MAX_NUM_JA3];
  u_int16_t num_elliptic_curve, elliptic_curve[MAX_NUM_JA3];
  u_int8_t num_elliptic_curve_point_format, elliptic_curve_point_format[MAX_NUM_JA3];
};



int processClientServerHello(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  struct ja3_info ja3;
  u_int8_t invalid_ja3 = 0;
  u_int16_t tls_version, ja3_str_len;
  char ja3_str[JA3_STR_LEN];
  ndpi_MD5_CTX ctx;
  u_char md5_hash[16];
  int i;
  u_int16_t total_len;
  u_int8_t handshake_type;
  char buffer[64] = { '\0' };


  printf("SSL %s() called\n", __FUNCTION__);


  memset(&ja3, 0, sizeof(ja3));

  handshake_type = packet->payload[0];
  total_len = (packet->payload[1] << 16) +  (packet->payload[2] << 8) + packet->payload[3];

  if((total_len > packet->payload_packet_len) || (packet->payload[1] != 0x0))
    return(0); 

  total_len = packet->payload_packet_len;

  
  if(total_len > 4) {
    u_int16_t base_offset    = packet->tcp ? 38 : 46;
    u_int16_t version_offset = packet->tcp ? 4 : 12;
    u_int16_t offset = packet->tcp ? 38 : 46, extension_len, j;
    u_int8_t  session_id_len =  0;
    if (base_offset < total_len)
      session_id_len = packet->payload[base_offset];


    printf("SSL [len: %u][handshake_type: %02X]\n", packet->payload_packet_len, handshake_type);


    tls_version = ntohs(*((u_int16_t*)&packet->payload[version_offset]));
    flow->protos.stun_ssl.ssl.ssl_version = ja3.tls_handshake_version = tls_version;
    if(flow->protos.stun_ssl.ssl.ssl_version < 0x0302) 
      NDPI_SET_BIT(flow->risk, NDPI_TLS_OBSOLETE_VERSION);

    if(handshake_type == 0x02 ) {
      int i, rc;


      printf("SSL Server Hello [version: 0x%04X]\n", tls_version);


      
      if(packet->udp)
	offset += 1;
      else {
	if(tls_version < 0x7F15 )
	  offset += session_id_len+1;
      }

      if((offset+3) > packet->payload_packet_len)
	return(0); 

      ja3.num_cipher = 1, ja3.cipher[0] = ntohs(*((u_int16_t*)&packet->payload[offset]));
      if((flow->protos.stun_ssl.ssl.server_unsafe_cipher = ndpi_is_safe_ssl_cipher(ja3.cipher[0])) == 1)
	NDPI_SET_BIT(flow->risk, NDPI_TLS_WEAK_CIPHER);

      flow->protos.stun_ssl.ssl.server_cipher = ja3.cipher[0];


      printf("TLS [server][session_id_len: %u][cipher: %04X]\n", session_id_len, ja3.cipher[0]);


      offset += 2 + 1;

      if((offset + 1) < packet->payload_packet_len) 
	extension_len = ntohs(*((u_int16_t*)&packet->payload[offset]));
      else extension_len = 0;


      printf("TLS [server][extension_len: %u]\n", extension_len);

      offset += 2;

      for(i=0; i<extension_len; ) {
	u_int16_t extension_id, extension_len;

	if(offset >= (packet->payload_packet_len+4)) break;

	extension_id  = ntohs(*((u_int16_t*)&packet->payload[offset]));
	extension_len = ntohs(*((u_int16_t*)&packet->payload[offset+2]));

	if(ja3.num_tls_extension < MAX_NUM_JA3)
	  ja3.tls_extension[ja3.num_tls_extension++] = extension_id;


	printf("TLS [server][extension_id: %u/0x%04X][len: %u]\n", extension_id, extension_id, extension_len);


	if(extension_id == 43 ) {
	  if(extension_len >= 2) {
	    u_int16_t tls_version = ntohs(*((u_int16_t*)&packet->payload[offset+4]));


	    printf("TLS [server] [TLS version: 0x%04X]\n", tls_version);


	    flow->protos.stun_ssl.ssl.ssl_version = tls_version;
	  }
	}

	i += 4 + extension_len, offset += 4 + extension_len;
      }

      ja3_str_len = snprintf(ja3_str, sizeof(ja3_str), "%u,", ja3.tls_handshake_version);

      for(i=0; i<ja3.num_cipher; i++) {
	rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.cipher[i]);

	if(rc <= 0) break; else ja3_str_len += rc;
      }

      rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, ",");
      if(rc > 0 && ja3_str_len + rc < JA3_STR_LEN) ja3_str_len += rc;

      

      for(i=0; i<ja3.num_tls_extension; i++) {
	int rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.tls_extension[i]);

	if(rc <= 0) break; else ja3_str_len += rc;
      }


      printf("TLS [server] %s\n", ja3_str);



      printf("[JA3] Server: %s \n", ja3_str);


      ndpi_MD5Init(&ctx);
      ndpi_MD5Update(&ctx, (const unsigned char *)ja3_str, strlen(ja3_str));
      ndpi_MD5Final(md5_hash, &ctx);

      for(i=0, j=0; i<16; i++) {
	int rc = snprintf(&flow->protos.stun_ssl.ssl.ja3_server[j], sizeof(flow->protos.stun_ssl.ssl.ja3_server)-j, "%02x", md5_hash[i]);
	if(rc <= 0) break; else j += rc;
      }


      printf("[JA3] Server: %s \n", flow->protos.stun_ssl.ssl.ja3_server);

    } else if(handshake_type == 0x01 ) {
      u_int16_t cipher_len, cipher_offset;

      if((session_id_len+base_offset+3) > packet->payload_packet_len)
	return(0); 

      if(packet->tcp) {
	cipher_len = packet->payload[session_id_len+base_offset+2] + (packet->payload[session_id_len+base_offset+1] << 8);
	cipher_offset = base_offset + session_id_len + 3;
      } else {
	cipher_len = ntohs(*((u_int16_t*)&packet->payload[base_offset+2]));
	cipher_offset = base_offset+4;
      }


      printf("Client SSL [client cipher_len: %u][tls_version: 0x%04X]\n", cipher_len, tls_version);


      if((cipher_offset+cipher_len) <= total_len) {
	for(i=0; i<cipher_len;) {
	  u_int16_t *id = (u_int16_t*)&packet->payload[cipher_offset+i];


	  printf("Client SSL [cipher suite: %u/0x%04X] [%d/%u]\n", ntohs(*id), ntohs(*id), i, cipher_len);

	  if((*id == 0) || (packet->payload[cipher_offset+i] != packet->payload[cipher_offset+i+1])) {
	    

	    if(ja3.num_cipher < MAX_NUM_JA3)
	      ja3.cipher[ja3.num_cipher++] = ntohs(*id);
	    else {
	      invalid_ja3 = 1;

	      printf("Client SSL Invalid cipher %u\n", ja3.num_cipher);

	    }
	  }

	  i += 2;
	}
      } else {
	invalid_ja3 = 1;

	printf("Client SSL Invalid len %u vs %u\n", (cipher_offset+cipher_len), total_len);

      }

      offset = base_offset + session_id_len + cipher_len + 2;

      if(offset < total_len) {
	u_int16_t compression_len;
	u_int16_t extensions_len;

	offset += packet->tcp ? 1 : 2;
	compression_len = packet->payload[offset];
	offset++;


	printf("Client SSL [compression_len: %u]\n", compression_len);


	
	offset += compression_len;

	if(offset < total_len) {
	  extensions_len = ntohs(*((u_int16_t*)&packet->payload[offset]));
	  offset += 2;


	  printf("Client SSL [extensions_len: %u]\n", extensions_len);


	  if((extensions_len+offset) <= total_len) {
	    
	    u_int extension_offset = 0;
	    u_int32_t j;

	    while(extension_offset < extensions_len) {
	      u_int16_t extension_id, extension_len, extn_off = offset+extension_offset;

	      extension_id = ntohs(*((u_int16_t*)&packet->payload[offset+extension_offset]));
	      extension_offset += 2;

	      extension_len = ntohs(*((u_int16_t*)&packet->payload[offset+extension_offset]));
	      extension_offset += 2;


	      printf("Client SSL [extension_id: %u][extension_len: %u]\n", extension_id, extension_len);


	      if((extension_id == 0) || (packet->payload[extn_off] != packet->payload[extn_off+1])) {
		

		if(ja3.num_tls_extension < MAX_NUM_JA3)
		  ja3.tls_extension[ja3.num_tls_extension++] = extension_id;
		else {
		  invalid_ja3 = 1;

		  printf("Client SSL Invalid extensions %u\n", ja3.num_tls_extension);

		}
	      }

	      if(extension_id == 0 ) {
		u_int16_t len;


		printf("[TLS] Extensions: found server name\n");


		len = (packet->payload[offset+extension_offset+3] << 8) + packet->payload[offset+extension_offset+4];
		len = (u_int)ndpi_min(len, sizeof(buffer)-1);

		if((offset+extension_offset+5+len) <= packet->payload_packet_len) {
		  strncpy(buffer, (char*)&packet->payload[offset+extension_offset+5], len);
		  buffer[len] = '\0';

		  cleanupServerName(buffer, sizeof(buffer));

		  snprintf(flow->protos.stun_ssl.ssl.client_requested_server_name, sizeof(flow->protos.stun_ssl.ssl.client_requested_server_name), "%s", buffer);


		  if(ndpi_match_hostname_protocol(ndpi_struct, flow, NDPI_PROTOCOL_TLS, buffer, strlen(buffer)))
		    flow->l4.tcp.tls.subprotocol_detected = 1;

		  ndpi_check_dga_name(ndpi_struct, flow, flow->protos.stun_ssl.ssl.client_requested_server_name);
		} else {

		  printf("[TLS] Extensions server len too short: %u vs %u\n", offset+extension_offset+5+len, packet->payload_packet_len);


		}
	      } else if(extension_id == 10 ) {
		u_int16_t s_offset = offset+extension_offset + 2;


		printf("Client SSL [EllipticCurveGroups: len=%u]\n", extension_len);


		if((s_offset+extension_len-2) <= total_len) {
		  for(i=0; i<extension_len-2;) {
		    u_int16_t s_group = ntohs(*((u_int16_t*)&packet->payload[s_offset+i]));


		    printf("Client SSL [EllipticCurve: %u/0x%04X]\n", s_group, s_group);

		    if((s_group == 0) || (packet->payload[s_offset+i] != packet->payload[s_offset+i+1])) {
		      
		      if(ja3.num_elliptic_curve < MAX_NUM_JA3)
			ja3.elliptic_curve[ja3.num_elliptic_curve++] = s_group;
		      else {
			invalid_ja3 = 1;

			printf("Client SSL Invalid num elliptic %u\n", ja3.num_elliptic_curve);

		      }
		    }

		    i += 2;
		  }
		} else {
		  invalid_ja3 = 1;

		  printf("Client SSL Invalid len %u vs %u\n", (s_offset+extension_len-1), total_len);

		}
	      } else if(extension_id == 11 ) {
		u_int16_t s_offset = offset+extension_offset + 1;


		printf("Client SSL [EllipticCurveFormat: len=%u]\n", extension_len);

		if((s_offset+extension_len) < total_len) {
		  for(i=0; i<extension_len-1;i++) {
		    u_int8_t s_group = packet->payload[s_offset+i];


		    printf("Client SSL [EllipticCurveFormat: %u]\n", s_group);


		    if(ja3.num_elliptic_curve_point_format < MAX_NUM_JA3)
		      ja3.elliptic_curve_point_format[ja3.num_elliptic_curve_point_format++] = s_group;
		    else {
		      invalid_ja3 = 1;

		      printf("Client SSL Invalid num elliptic %u\n", ja3.num_elliptic_curve_point_format);

		    }
		  }
		} else {
		  invalid_ja3 = 1;

		  printf("Client SSL Invalid len %u vs %u\n", s_offset+extension_len, total_len);

		}
	      } else if(extension_id == 16 ) {
		u_int16_t s_offset = offset+extension_offset;
		u_int16_t tot_alpn_len = ntohs(*((u_int16_t*)&packet->payload[s_offset]));
		char alpn_str[256];
		u_int8_t alpn_str_len = 0;


		printf("Client SSL [ALPN: block_len=%u/len=%u]\n", extension_len, tot_alpn_len);

		s_offset += 2;
		tot_alpn_len += s_offset;

		while(s_offset < tot_alpn_len && s_offset < total_len) {
		  u_int8_t alpn_i, alpn_len = packet->payload[s_offset++];

		  if((s_offset + alpn_len) <= tot_alpn_len) {

		    printf("Client SSL [ALPN: %u]\n", alpn_len);


		    if((alpn_str_len+alpn_len+1) < sizeof(alpn_str)) {
		      if(alpn_str_len > 0) {
			alpn_str[alpn_str_len] = ',';
			alpn_str_len++;
		      }

		      for(alpn_i=0; alpn_i<alpn_len; alpn_i++)
			alpn_str[alpn_str_len+alpn_i] =  packet->payload[s_offset+alpn_i];

		      s_offset += alpn_len, alpn_str_len += alpn_len;;
		    } else break;
		  } else break;
		} 

		alpn_str[alpn_str_len] = '\0';


		printf("Client SSL [ALPN: %s][len: %u]\n", alpn_str, alpn_str_len);

		if(flow->protos.stun_ssl.ssl.alpn == NULL)
		  flow->protos.stun_ssl.ssl.alpn = ndpi_strdup(alpn_str);
	      } else if(extension_id == 43 ) {
		u_int16_t s_offset = offset+extension_offset;
		u_int8_t version_len = packet->payload[s_offset];
		char version_str[256];
		u_int8_t version_str_len = 0;
		version_str[0] = 0;

		printf("Client SSL [TLS version len: %u]\n", version_len);


		if(version_len == (extension_len-1)) {
		  u_int8_t j;

		  s_offset++;

		  
		  for(j=0; j+1<version_len; j += 2) {
		    u_int16_t tls_version = ntohs(*((u_int16_t*)&packet->payload[s_offset+j]));
		    u_int8_t unknown_tls_version;


		    printf("Client SSL [TLS version: %s/0x%04X]\n", ndpi_ssl_version2str(tls_version, &unknown_tls_version), tls_version);


		    if((version_str_len+8) < sizeof(version_str)) {
		      int rc = snprintf(&version_str[version_str_len], sizeof(version_str) - version_str_len, "%s%s", (version_str_len > 0) ? "," : "", ndpi_ssl_version2str(tls_version, &unknown_tls_version));


		      if(rc <= 0)
			break;
		      else version_str_len += rc;
		    }
		  }
		if(flow->protos.stun_ssl.ssl.tls_supported_versions == NULL)
		  flow->protos.stun_ssl.ssl.tls_supported_versions = ndpi_strdup(version_str);
		}
	      } else if(extension_id == 65486 ) {
		
		u_int16_t e_offset = offset+extension_offset;
		u_int16_t initial_offset = e_offset;
		u_int16_t e_sni_len, cipher_suite = ntohs(*((u_int16_t*)&packet->payload[e_offset]));

		flow->protos.stun_ssl.ssl.encrypted_sni.cipher_suite = cipher_suite;

		e_offset += 2; 

		
		e_offset += 2; 
		e_offset +=  ntohs(*((u_int16_t*)&packet->payload[e_offset])) + 2; 

		if((e_offset+4) < packet->payload_packet_len) {
		  
		  e_offset +=  ntohs(*((u_int16_t*)&packet->payload[e_offset])) + 2; 

		  if((e_offset+4) < packet->payload_packet_len) {
		    e_sni_len = ntohs(*((u_int16_t*)&packet->payload[e_offset]));
		    e_offset += 2;

		    if((e_offset+e_sni_len-extension_len-initial_offset) >= 0) {

		      printf("Client SSL [Encrypted Server Name len: %u]\n", e_sni_len);


		      if(flow->protos.stun_ssl.ssl.encrypted_sni.esni == NULL) {
			flow->protos.stun_ssl.ssl.encrypted_sni.esni = (char*)ndpi_malloc(e_sni_len*2+1);

			if(flow->protos.stun_ssl.ssl.encrypted_sni.esni) {
			  u_int16_t i, off;

			  for(i=e_offset, off=0; i<(e_offset+e_sni_len); i++) {
			    int rc = sprintf(&flow->protos.stun_ssl.ssl.encrypted_sni.esni[off], "%02X", packet->payload[i] & 0XFF);

			    if(rc <= 0) {
			      flow->protos.stun_ssl.ssl.encrypted_sni.esni[off] = '\0';
			      break;
			    } else off += rc;
			  }
			}
		      }
		    }
		  }
		}
	      }

	      extension_offset += extension_len; 


	      printf("Client SSL [extension_offset/len: %u/%u]\n", extension_offset, extension_len);

	    } 

	    if(!invalid_ja3) {
	      int rc;

	    compute_ja3c:
	      ja3_str_len = snprintf(ja3_str, sizeof(ja3_str), "%u,", ja3.tls_handshake_version);

	      for(i=0; i<ja3.num_cipher; i++) {
		rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.cipher[i]);
		if(rc > 0 && ja3_str_len + rc < JA3_STR_LEN) ja3_str_len += rc; else break;
	      }

	      rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, ",");
	      if(rc > 0 && ja3_str_len + rc < JA3_STR_LEN) ja3_str_len += rc;

	      

	      for(i=0; i<ja3.num_tls_extension; i++) {
		rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.tls_extension[i]);
		if(rc > 0 && ja3_str_len + rc < JA3_STR_LEN) ja3_str_len += rc; else break;
	      }

	      rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, ",");
	      if(rc > 0 && ja3_str_len + rc < JA3_STR_LEN) ja3_str_len += rc;

	      

	      for(i=0; i<ja3.num_elliptic_curve; i++) {
		rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.elliptic_curve[i]);
		if(rc > 0 && ja3_str_len + rc < JA3_STR_LEN) ja3_str_len += rc; else break;
	      }

	      rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, ",");
	      if(rc > 0 && ja3_str_len + rc < JA3_STR_LEN) ja3_str_len += rc;

	      for(i=0; i<ja3.num_elliptic_curve_point_format; i++) {
		rc = snprintf(&ja3_str[ja3_str_len], sizeof(ja3_str)-ja3_str_len, "%s%u", (i > 0) ? "-" : "", ja3.elliptic_curve_point_format[i]);
		if(rc > 0 && ja3_str_len + rc < JA3_STR_LEN) ja3_str_len += rc; else break;
	      }


	      printf("[JA3] Client: %s \n", ja3_str);


	      ndpi_MD5Init(&ctx);
	      ndpi_MD5Update(&ctx, (const unsigned char *)ja3_str, strlen(ja3_str));
	      ndpi_MD5Final(md5_hash, &ctx);

	      for(i=0, j=0; i<16; i++) {
		rc = snprintf(&flow->protos.stun_ssl.ssl.ja3_client[j], sizeof(flow->protos.stun_ssl.ssl.ja3_client)-j, "%02x", md5_hash[i]);

		if(rc > 0) j += rc; else break;
	      }

	      printf("[JA3] Client: %s \n", flow->protos.stun_ssl.ssl.ja3_client);

	    }

	    
	    if((flow->protos.stun_ssl.ssl.ssl_version >= 0x0303) 
	       && (flow->protos.stun_ssl.ssl.alpn == NULL) ) {
	      NDPI_SET_BIT(flow->risk, NDPI_TLS_NOT_CARRYING_HTTPS);
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


  printf("==>> %s() %u [len: %u][version: %u]\n", __FUNCTION__, flow->guessed_host_protocol_id, packet->payload_packet_len, flow->protos.stun_ssl.ssl.ssl_version);





  if(packet->udp != NULL)
    ndpi_search_tls_udp(ndpi_struct, flow);
  else ndpi_search_tls_tcp(ndpi_struct, flow);
}



void init_tls_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask) {
  ndpi_set_bitmask_protocol_detection("TLS", ndpi_struct, detection_bitmask, *id, NDPI_PROTOCOL_TLS, ndpi_search_tls_wrapper, NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION, SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);





  *id += 1;

  

  ndpi_set_bitmask_protocol_detection("TLS", ndpi_struct, detection_bitmask, *id, NDPI_PROTOCOL_TLS, ndpi_search_tls_wrapper, NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_UDP_WITH_PAYLOAD, SAVE_DETECTION_BITMASK_AS_UNKNOWN, ADD_TO_DETECTION_BITMASK);





  *id += 1;
}
