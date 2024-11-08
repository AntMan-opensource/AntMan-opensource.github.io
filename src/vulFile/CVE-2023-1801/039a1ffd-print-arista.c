
















static const struct tok subtype_str[] = {
	{ ARISTA_SUBTYPE_TIMESTAMP, "Timestamp" }, { 0, NULL }
};

static const struct tok ts_timescale_str[] = {
	{ 0, "TAI" }, { 1, "UTC" }, { 0, NULL }

};



static const struct tok ts_format_str[] = {
	{ FORMAT_64BIT, "64-bit" }, { FORMAT_48BIT, "48-bit" }, { 0, NULL }

};

static const struct tok hw_info_str[] = {
	{ 0, "R/R2" }, { 1, "R3" }, { 0, NULL }

};

static inline void arista_print_date_hms_time(netdissect_options *ndo, uint32_t seconds, uint32_t nanoseconds)

{
	time_t ts;
	struct tm *tm;
	char buf[BUFSIZE];

	ts = seconds + (nanoseconds / 1000000000);
	nanoseconds %= 1000000000;
	if (NULL == (tm = gmtime(&ts)))
		ND_PRINT("gmtime() error");
	else if (0 == strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm))
		ND_PRINT("strftime() error");
	else ND_PRINT("%s.%09u", buf, nanoseconds);
}

int arista_ethertype_print(netdissect_options *ndo, const u_char *bp, u_int len _U_)
{
	uint16_t subTypeId;
	u_short bytesConsumed = 0;

	ndo->ndo_protocol = "arista";

	subTypeId = GET_BE_U_2(bp);
	bp += 2;
	bytesConsumed += 2;

	ND_PRINT("SubType %s (0x%04x), ", tok2str(subtype_str, "Unknown", subTypeId), subTypeId);


	
	if (subTypeId == ARISTA_SUBTYPE_TIMESTAMP) {
		uint64_t seconds;
		uint32_t nanoseconds;
		uint8_t ts_timescale = GET_U_1(bp);
		bp += 1;
		bytesConsumed += 1;
		ND_PRINT("Timescale %s (%u), ", tok2str(ts_timescale_str, "Unknown", ts_timescale), ts_timescale);


		uint8_t ts_format = GET_U_1(bp) >> 4;
		uint8_t hw_info = GET_U_1(bp) & 0x0f;
		bp += 1;
		bytesConsumed += 1;

		
		ND_PRINT("Format %s (%u), HwInfo %s (%u), Timestamp ", tok2str(ts_format_str, "Unknown", ts_format), ts_format, tok2str(hw_info_str, "Unknown", hw_info), hw_info);



		switch (ts_format) {
		case FORMAT_64BIT:
			seconds = GET_BE_U_4(bp);
			nanoseconds = GET_BE_U_4(bp + 4);
			arista_print_date_hms_time(ndo, seconds, nanoseconds);
			bytesConsumed += 8;
			break;
		case FORMAT_48BIT:
			seconds = GET_BE_U_2(bp);
			nanoseconds = GET_BE_U_4(bp + 2);
			seconds += nanoseconds / 1000000000;
			nanoseconds %= 1000000000;
			ND_PRINT("%" PRIu64 ".%09u", seconds, nanoseconds);
			bytesConsumed += 6;
			break;
		default:
			return -1;
		}
	} else {
		return -1;
	}
	ND_PRINT(": ");
	return bytesConsumed;
}
