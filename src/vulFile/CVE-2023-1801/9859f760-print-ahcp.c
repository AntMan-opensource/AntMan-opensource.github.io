





























static const struct tok ahcp1_msg_str[] = {
	{ AHCP1_MSG_DISCOVER, "Discover" }, { AHCP1_MSG_OFFER,    "Offer"    }, { AHCP1_MSG_REQUEST,  "Request"  }, { AHCP1_MSG_ACK,      "Ack"      }, { AHCP1_MSG_NACK,     "Nack"     }, { AHCP1_MSG_RELEASE,  "Release"  }, { 0, NULL }





};

















static const struct tok ahcp1_opt_str[] = {
	{ AHCP1_OPT_PAD,                    "Pad"                    }, { AHCP1_OPT_MANDATORY,              "Mandatory"              }, { AHCP1_OPT_ORIGIN_TIME,            "Origin Time"            }, { AHCP1_OPT_EXPIRES,                "Expires"                }, { AHCP1_OPT_MY_IPV6_ADDRESS,        "My-IPv6-Address"        }, { AHCP1_OPT_MY_IPV4_ADDRESS,        "My-IPv4-Address"        }, { AHCP1_OPT_IPV6_PREFIX,            "IPv6 Prefix"            }, { AHCP1_OPT_IPV4_PREFIX,            "IPv4 Prefix"            }, { AHCP1_OPT_IPV6_ADDRESS,           "IPv6 Address"           }, { AHCP1_OPT_IPV4_ADDRESS,           "IPv4 Address"           }, { AHCP1_OPT_IPV6_PREFIX_DELEGATION, "IPv6 Prefix Delegation" }, { AHCP1_OPT_IPV4_PREFIX_DELEGATION, "IPv4 Prefix Delegation" }, { AHCP1_OPT_NAME_SERVER,            "Name Server"            }, { AHCP1_OPT_NTP_SERVER,             "NTP Server"             }, { 0, NULL }













};

static void ahcp_time_print(netdissect_options *ndo, const u_char *cp, uint8_t len)

{
	time_t t;
	struct tm *tm;
	char buf[BUFSIZE];

	if (len != 4)
		goto invalid;
	t = GET_BE_U_4(cp);
	if (NULL == (tm = gmtime(&t)))
		ND_PRINT(": gmtime() error");
	else if (0 == strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm))
		ND_PRINT(": strftime() error");
	else ND_PRINT(": %s UTC", buf);
	return;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, len);
}

static void ahcp_seconds_print(netdissect_options *ndo, const u_char *cp, uint8_t len)

{
	if (len != 4)
		goto invalid;
	ND_PRINT(": %us", GET_BE_U_4(cp));
	return;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, len);
}

static void ahcp_ipv6_addresses_print(netdissect_options *ndo, const u_char *cp, uint8_t len)

{
	const char *sep = ": ";

	while (len) {
		if (len < 16)
			goto invalid;
		ND_PRINT("%s%s", sep, GET_IP6ADDR_STRING(cp));
		cp += 16;
		len -= 16;
		sep = ", ";
	}
	return;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, len);
}

static void ahcp_ipv4_addresses_print(netdissect_options *ndo, const u_char *cp, uint8_t len)

{
	const char *sep = ": ";

	while (len) {
		if (len < 4)
			goto invalid;
		ND_PRINT("%s%s", sep, GET_IPADDR_STRING(cp));
		cp += 4;
		len -= 4;
		sep = ", ";
	}
	return;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, len);
}

static void ahcp_ipv6_prefixes_print(netdissect_options *ndo, const u_char *cp, uint8_t len)

{
	const char *sep = ": ";

	while (len) {
		if (len < 17)
			goto invalid;
		ND_PRINT("%s%s/%u", sep, GET_IP6ADDR_STRING(cp), GET_U_1(cp + 16));
		cp += 17;
		len -= 17;
		sep = ", ";
	}
	return;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, len);
}

static void ahcp_ipv4_prefixes_print(netdissect_options *ndo, const u_char *cp, uint8_t len)

{
	const char *sep = ": ";

	while (len) {
		if (len < 5)
			goto invalid;
		ND_PRINT("%s%s/%u", sep, GET_IPADDR_STRING(cp), GET_U_1(cp + 4));
		cp += 5;
		len -= 5;
		sep = ", ";
	}
	return;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, len);
}

static void (* const data_decoders[AHCP1_OPT_MAX + 1])(netdissect_options *, const u_char *, uint8_t) = {
	  NULL, NULL, ahcp_time_print, ahcp_seconds_print, ahcp_ipv6_addresses_print, ahcp_ipv4_addresses_print, ahcp_ipv6_prefixes_print, NULL, ahcp_ipv6_addresses_print, ahcp_ipv4_addresses_print, ahcp_ipv6_prefixes_print, ahcp_ipv4_prefixes_print, ahcp_ipv6_addresses_print, ahcp_ipv6_addresses_print, };














static void ahcp1_options_print(netdissect_options *ndo, const u_char *cp, uint16_t len)

{
	while (len) {
		uint8_t option_no, option_len;

		
		option_no = GET_U_1(cp);
		cp += 1;
		len -= 1;
		ND_PRINT("\n\t %s", tok2str(ahcp1_opt_str, "Unknown-%u", option_no));
		if (option_no == AHCP1_OPT_PAD || option_no == AHCP1_OPT_MANDATORY)
			continue;
		
		if (!len)
			goto invalid;
		option_len = GET_U_1(cp);
		cp += 1;
		len -= 1;
		if (option_len > len)
			goto invalid;
		
		if (option_no <= AHCP1_OPT_MAX && data_decoders[option_no] != NULL) {
			data_decoders[option_no](ndo, cp, option_len);
		} else {
			ND_PRINT(" (Length %u)", option_len);
			ND_TCHECK_LEN(cp, option_len);
		}
		cp += option_len;
		len -= option_len;
	}
	return;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, len);
}

static void ahcp1_body_print(netdissect_options *ndo, const u_char *cp, u_int len)

{
	uint8_t type, mbz;
	uint16_t body_len;

	if (len < AHCP1_BODY_MIN_LEN)
		goto invalid;
	
	type = GET_U_1(cp);
	cp += 1;
	len -= 1;
	
	mbz = GET_U_1(cp);
	cp += 1;
	len -= 1;
	
	body_len = GET_BE_U_2(cp);
	cp += 2;
	len -= 2;

	if (ndo->ndo_vflag) {
		ND_PRINT("\n\t%s", tok2str(ahcp1_msg_str, "Unknown-%u", type));
		if (mbz != 0)
			ND_PRINT(", MBZ %u", mbz);
		ND_PRINT(", Length %u", body_len);
	}
	if (body_len > len)
		goto invalid;

	
	
	if (ndo->ndo_vflag >= 2)
		ahcp1_options_print(ndo, cp, body_len);
	else ND_TCHECK_LEN(cp, body_len);
	return;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, len);

}

void ahcp_print(netdissect_options *ndo, const u_char *cp, u_int len)

{
	uint8_t version;

	ndo->ndo_protocol = "ahcp";
	nd_print_protocol_caps(ndo);
	if (len < 2)
		goto invalid;
	
	if (GET_U_1(cp) != AHCP_MAGIC_NUMBER)
		goto invalid;
	cp += 1;
	len -= 1;
	
	version = GET_U_1(cp);
	cp += 1;
	len -= 1;
	switch (version) {
		case AHCP_VERSION_1: {
			ND_PRINT(" Version 1");
			if (len < AHCP1_HEADER_FIX_LEN - 2)
				goto invalid;
			if (!ndo->ndo_vflag) {
				ND_TCHECK_LEN(cp, AHCP1_HEADER_FIX_LEN - 2);
				cp += AHCP1_HEADER_FIX_LEN - 2;
				len -= AHCP1_HEADER_FIX_LEN - 2;
			} else {
				
				ND_PRINT("\n\tHopcount %u", GET_U_1(cp));
				cp += 1;
				len -= 1;
				
				ND_PRINT(", Original Hopcount %u", GET_U_1(cp));
				cp += 1;
				len -= 1;
				
				ND_PRINT(", Nonce 0x%08x", GET_BE_U_4(cp));
				cp += 4;
				len -= 4;
				
				ND_PRINT(", Source Id %s", GET_LINKADDR_STRING(cp, LINKADDR_OTHER, 8));
				cp += 8;
				len -= 8;
				
				ND_PRINT(", Destination Id %s", GET_LINKADDR_STRING(cp, LINKADDR_OTHER, 8));
				cp += 8;
				len -= 8;
			}
			
			ahcp1_body_print(ndo, cp, len);
			break;
		}
		default:
			ND_PRINT(" Version %u (unknown)", version);
			ND_TCHECK_LEN(cp, len);
			break;
	}
	return;

invalid:
	nd_print_invalid(ndo);
	ND_TCHECK_LEN(cp, len);
}
