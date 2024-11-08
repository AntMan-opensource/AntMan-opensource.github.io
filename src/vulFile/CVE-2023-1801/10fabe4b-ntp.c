











void p_ntp_time(netdissect_options *ndo, const struct l_fixedpt *lfp)

{
	uint32_t i;
	uint32_t uf;
	uint32_t f;
	double ff;

	i = GET_BE_U_4(lfp->int_part);
	uf = GET_BE_U_4(lfp->fraction);
	ff = uf;
	if (ff < 0.0)		
		ff += FMAXINT;
	ff = ff / FMAXINT;			
	f = (uint32_t)(ff * 1000000000.0);	
	ND_PRINT("%u.%09u", i, f);

	
	if (i) {
	    int64_t seconds_64bit = (int64_t)i - JAN_1970;
	    time_t seconds;
	    struct tm *tm;
	    char time_buf[128];

	    seconds = (time_t)seconds_64bit;
	    if (seconds != seconds_64bit) {
		
		ND_PRINT(" (unrepresentable)");
	    } else {
		tm = gmtime(&seconds);
		if (tm == NULL) {
		    
		    ND_PRINT(" (unrepresentable)");
		} else {
		    
		    strftime(time_buf, sizeof (time_buf), "%Y-%m-%dT%H:%M:%SZ", tm);
		    ND_PRINT(" (%s)", time_buf);
		}
	    }
	}
}
