



















static void zep_print_ts(netdissect_options *ndo, const u_char *p)
{
	int32_t i;
	uint32_t uf;
	uint32_t f;
	float ff;

	i = GET_BE_U_4(p);
	uf = GET_BE_U_4(p + 4);
	ff = (float) uf;
	if (ff < 0.0)           
		ff += FMAXINT;
	ff = (float) (ff / FMAXINT); 
	f = (uint32_t) (ff * 1000000000.0);  
	ND_PRINT("%u.%09d", i, f);

	
	if (i) {
		time_t seconds = i - JAN_1970;
		struct tm *tm;
		char time_buf[128];

		tm = localtime(&seconds);
		strftime(time_buf, sizeof (time_buf), "%Y/%m/%d %H:%M:%S", tm);
		ND_PRINT(" (%s)", time_buf);
	}
}



void zep_print(netdissect_options *ndo, const u_char *bp, u_int len)

{
	uint8_t version, inner_len;
	uint32_t seq_no;

	ndo->ndo_protocol = "zep";

	nd_print_protocol_caps(ndo);

	
	if (GET_U_1(bp) != 'E' || GET_U_1(bp + 1) != 'X') {
		ND_PRINT(" [Preamble Code: ");
		fn_print_char(ndo, GET_U_1(bp));
		fn_print_char(ndo, GET_U_1(bp + 1));
		ND_PRINT("]");
		nd_print_invalid(ndo);
		return;
	}

	version = GET_U_1(bp + 2);
	ND_PRINT("v%u ", version);

	if (version == 1) {
		
		ND_ICHECK_U(len, <, 16);
		ND_PRINT("Channel ID %u, Device ID 0x%04x, ", GET_U_1(bp + 3), GET_BE_U_2(bp + 4));
		if (GET_U_1(bp + 6))
			ND_PRINT("CRC, ");
		else ND_PRINT("LQI %u, ", GET_U_1(bp + 7));
		inner_len = GET_U_1(bp + 15);
		ND_PRINT("inner len = %u", inner_len);

		bp += 16;
		len -= 16;
	} else {
		
		if (GET_U_1(bp + 3) == 2) {
			
			ND_ICHECK_U(len, <, 8);
			seq_no = GET_BE_U_4(bp + 4);
			ND_PRINT("ACK, seq# = %u", seq_no);
			inner_len = 0;
			bp += 8;
			len -= 8;
		} else {
			
			ND_ICHECK_U(len, <, 32);
			ND_PRINT("Type %u, Channel ID %u, Device ID 0x%04x, ", GET_U_1(bp + 3), GET_U_1(bp + 4), GET_BE_U_2(bp + 5));

			if (GET_U_1(bp + 7))
				ND_PRINT("CRC, ");
			else ND_PRINT("LQI %u, ", GET_U_1(bp + 8));

			zep_print_ts(ndo, bp + 9);
			seq_no = GET_BE_U_4(bp + 17);
			inner_len = GET_U_1(bp + 31);
			ND_PRINT(", seq# = %u, inner len = %u", seq_no, inner_len);
			bp += 32;
			len -= 32;
		}
	}

	if (inner_len != 0) {
		
		ND_PRINT("\n\t");
		if (ieee802_15_4_print(ndo, bp, inner_len)) {
			ND_TCHECK_LEN(bp, len);
			bp += len;
			len = 0;
		}
	}

	if (!ndo->ndo_suppress_default_print)
		ND_DEFAULTPRINT(bp, len);
	return;
invalid:
	nd_print_invalid(ndo);
}
