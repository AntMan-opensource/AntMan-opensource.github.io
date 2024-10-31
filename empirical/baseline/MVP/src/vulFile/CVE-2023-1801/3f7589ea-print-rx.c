












































struct rx_header {
	nd_uint32_t epoch;
	nd_uint32_t cid;
	nd_uint32_t callNumber;
	nd_uint32_t seq;
	nd_uint32_t serial;
	nd_uint8_t type;










	nd_uint8_t flags;







	nd_uint8_t userStatus;
	nd_uint8_t securityIndex;
	nd_uint16_t spare;		
	nd_uint16_t serviceId;		
};					
					
					





struct rx_ackPacket {
	nd_uint16_t bufferSpace;	
	nd_uint16_t maxSkew;		
					
	nd_uint32_t firstPacket;	
	nd_uint32_t previousPacket;	
	nd_uint32_t serial;		
	nd_uint8_t reason;		
	nd_uint8_t nAcks;		
	

	uint8_t acks[RX_MAXACKS];	

};






static const struct tok rx_types[] = {
	{ RX_PACKET_TYPE_DATA,		"data" }, { RX_PACKET_TYPE_ACK,		"ack" }, { RX_PACKET_TYPE_BUSY,		"busy" }, { RX_PACKET_TYPE_ABORT,		"abort" }, { RX_PACKET_TYPE_ACKALL,	"ackall" }, { RX_PACKET_TYPE_CHALLENGE,	"challenge" }, { RX_PACKET_TYPE_RESPONSE,	"response" }, { RX_PACKET_TYPE_DEBUG,		"debug" }, { RX_PACKET_TYPE_PARAMS,	"params" }, { RX_PACKET_TYPE_VERSION,	"version" }, { 0,				NULL }, };











static const struct double_tok {
	uint32_t flag;		
	uint32_t packetType;	
	const char *s;		
} rx_flags[] = {
	{ RX_CLIENT_INITIATED,	0,			"client-init" }, { RX_REQUEST_ACK,	0,			"req-ack" }, { RX_LAST_PACKET,	0,			"last-pckt" }, { RX_MORE_PACKETS,	0,			"more-pckts" }, { RX_FREE_PACKET,	0,			"free-pckt" }, { RX_SLOW_START_OK,	RX_PACKET_TYPE_ACK,	"slow-start" }, { RX_JUMBO_PACKET,	RX_PACKET_TYPE_DATA,	"jumbogram" }





};

static const struct tok fs_req[] = {
	{ 130,		"fetch-data" }, { 131,		"fetch-acl" }, { 132,		"fetch-status" }, { 133,		"store-data" }, { 134,		"store-acl" }, { 135,		"store-status" }, { 136,		"remove-file" }, { 137,		"create-file" }, { 138,		"rename" }, { 139,		"symlink" }, { 140,		"link" }, { 141,		"makedir" }, { 142,		"rmdir" }, { 143,		"oldsetlock" }, { 144,		"oldextlock" }, { 145,		"oldrellock" }, { 146,		"get-stats" }, { 147,		"give-cbs" }, { 148,		"get-vlinfo" }, { 149,		"get-vlstats" }, { 150,		"set-vlstats" }, { 151,		"get-rootvl" }, { 152,		"check-token" }, { 153,		"get-time" }, { 154,		"nget-vlinfo" }, { 155,		"bulk-stat" }, { 156,		"setlock" }, { 157,		"extlock" }, { 158,		"rellock" }, { 159,		"xstat-ver" }, { 160,		"get-xstat" }, { 161,		"dfs-lookup" }, { 162,		"dfs-flushcps" }, { 163,		"dfs-symlink" }, { 220,		"residency" }, { 65536,        "inline-bulk-status" }, { 65537,        "fetch-data-64" }, { 65538,        "store-data-64" }, { 65539,        "give-up-all-cbs" }, { 65540,        "get-caps" }, { 65541,        "cb-rx-conn-addr" }, { 0,		NULL }, };










































static const struct tok cb_req[] = {
	{ 204,		"callback" }, { 205,		"initcb" }, { 206,		"probe" }, { 207,		"getlock" }, { 208,		"getce" }, { 209,		"xstatver" }, { 210,		"getxstat" }, { 211,		"initcb2" }, { 212,		"whoareyou" }, { 213,		"initcb3" }, { 214,		"probeuuid" }, { 215,		"getsrvprefs" }, { 216,		"getcellservdb" }, { 217,		"getlocalcell" }, { 218,		"getcacheconf" }, { 65536,        "getce64" }, { 65537,        "getcellbynum" }, { 65538,        "tellmeaboutyourself" }, { 0,		NULL }, };



















static const struct tok pt_req[] = {
	{ 500,		"new-user" }, { 501,		"where-is-it" }, { 502,		"dump-entry" }, { 503,		"add-to-group" }, { 504,		"name-to-id" }, { 505,		"id-to-name" }, { 506,		"delete" }, { 507,		"remove-from-group" }, { 508,		"get-cps" }, { 509,		"new-entry" }, { 510,		"list-max" }, { 511,		"set-max" }, { 512,		"list-entry" }, { 513,		"change-entry" }, { 514,		"list-elements" }, { 515,		"same-mbr-of" }, { 516,		"set-fld-sentry" }, { 517,		"list-owned" }, { 518,		"get-cps2" }, { 519,		"get-host-cps" }, { 520,		"update-entry" }, { 521,		"list-entries" }, { 530,		"list-super-groups" }, { 0,		NULL }, };
























static const struct tok vldb_req[] = {
	{ 501,		"create-entry" }, { 502,		"delete-entry" }, { 503,		"get-entry-by-id" }, { 504,		"get-entry-by-name" }, { 505,		"get-new-volume-id" }, { 506,		"replace-entry" }, { 507,		"update-entry" }, { 508,		"setlock" }, { 509,		"releaselock" }, { 510,		"list-entry" }, { 511,		"list-attrib" }, { 512,		"linked-list" }, { 513,		"get-stats" }, { 514,		"probe" }, { 515,		"get-addrs" }, { 516,		"change-addr" }, { 517,		"create-entry-n" }, { 518,		"get-entry-by-id-n" }, { 519,		"get-entry-by-name-n" }, { 520,		"replace-entry-n" }, { 521,		"list-entry-n" }, { 522,		"list-attrib-n" }, { 523,		"linked-list-n" }, { 524,		"update-entry-by-name" }, { 525,		"create-entry-u" }, { 526,		"get-entry-by-id-u" }, { 527,		"get-entry-by-name-u" }, { 528,		"replace-entry-u" }, { 529,		"list-entry-u" }, { 530,		"list-attrib-u" }, { 531,		"linked-list-u" }, { 532,		"regaddr" }, { 533,		"get-addrs-u" }, { 534,		"list-attrib-n2" }, { 0,		NULL }, };



































static const struct tok kauth_req[] = {
	{ 1,		"auth-old" }, { 21,		"authenticate" }, { 22,		"authenticate-v2" }, { 2,		"change-pw" }, { 3,		"get-ticket-old" }, { 23,		"get-ticket" }, { 4,		"set-pw" }, { 5,		"set-fields" }, { 6,		"create-user" }, { 7,		"delete-user" }, { 8,		"get-entry" }, { 9,		"list-entry" }, { 10,		"get-stats" }, { 11,		"debug" }, { 12,		"get-pw" }, { 13,		"get-random-key" }, { 14,		"unlock" }, { 15,		"lock-status" }, { 0,		NULL }, };



















static const struct tok vol_req[] = {
	{ 100,		"create-volume" }, { 101,		"delete-volume" }, { 102,		"restore" }, { 103,		"forward" }, { 104,		"end-trans" }, { 105,		"clone" }, { 106,		"set-flags" }, { 107,		"get-flags" }, { 108,		"trans-create" }, { 109,		"dump" }, { 110,		"get-nth-volume" }, { 111,		"set-forwarding" }, { 112,		"get-name" }, { 113,		"get-status" }, { 114,		"sig-restore" }, { 115,		"list-partitions" }, { 116,		"list-volumes" }, { 117,		"set-id-types" }, { 118,		"monitor" }, { 119,		"partition-info" }, { 120,		"reclone" }, { 121,		"list-one-volume" }, { 122,		"nuke" }, { 123,		"set-date" }, { 124,		"x-list-volumes" }, { 125,		"x-list-one-volume" }, { 126,		"set-info" }, { 127,		"x-list-partitions" }, { 128,		"forward-multiple" }, { 65536,	"convert-ro" }, { 65537,	"get-size" }, { 65538,	"dump-v2" }, { 0,		NULL }, };

































static const struct tok bos_req[] = {
	{ 80,		"create-bnode" }, { 81,		"delete-bnode" }, { 82,		"set-status" }, { 83,		"get-status" }, { 84,		"enumerate-instance" }, { 85,		"get-instance-info" }, { 86,		"get-instance-parm" }, { 87,		"add-superuser" }, { 88,		"delete-superuser" }, { 89,		"list-superusers" }, { 90,		"list-keys" }, { 91,		"add-key" }, { 92,		"delete-key" }, { 93,		"set-cell-name" }, { 94,		"get-cell-name" }, { 95,		"get-cell-host" }, { 96,		"add-cell-host" }, { 97,		"delete-cell-host" }, { 98,		"set-t-status" }, { 99,		"shutdown-all" }, { 100,		"restart-all" }, { 101,		"startup-all" }, { 102,		"set-noauth-flag" }, { 103,		"re-bozo" }, { 104,		"restart" }, { 105,		"start-bozo-install" }, { 106,		"uninstall" }, { 107,		"get-dates" }, { 108,		"exec" }, { 109,		"prune" }, { 110,		"set-restart-time" }, { 111,		"get-restart-time" }, { 112,		"start-bozo-log" }, { 113,		"wait-all" }, { 114,		"get-instance-strings" }, { 115,		"get-restricted" }, { 116,		"set-restricted" }, { 0,		NULL }, };






































static const struct tok ubik_req[] = {
	{ 10000,	"vote-beacon" }, { 10001,	"vote-debug-old" }, { 10002,	"vote-sdebug-old" }, { 10003,	"vote-getsyncsite" }, { 10004,	"vote-debug" }, { 10005,	"vote-sdebug" }, { 10006,	"vote-xdebug" }, { 10007,	"vote-xsdebug" }, { 20000,	"disk-begin" }, { 20001,	"disk-commit" }, { 20002,	"disk-lock" }, { 20003,	"disk-write" }, { 20004,	"disk-getversion" }, { 20005,	"disk-getfile" }, { 20006,	"disk-sendfile" }, { 20007,	"disk-abort" }, { 20008,	"disk-releaselocks" }, { 20009,	"disk-truncate" }, { 20010,	"disk-probe" }, { 20011,	"disk-writev" }, { 20012,	"disk-interfaceaddr" }, { 20013,	"disk-setversion" }, { 0,		NULL }, };




























static const struct tok cb_types[] = {
	{ 1,		"exclusive" }, { 2,		"shared" }, { 3,		"dropped" }, { 0,		NULL }, };




static const struct tok ubik_lock_types[] = {
	{ 1,		"read" }, { 2,		"write" }, { 3,		"wait" }, { 0,		NULL }, };




static const char *voltype[] = { "read-write", "read-only", "backup" };

static const struct tok afs_fs_errors[] = {
	{ 101,		"salvage volume" }, { 102, 		"no such vnode" }, { 103, 		"no such volume" }, { 104, 		"volume exist" }, { 105, 		"no service" }, { 106, 		"volume offline" }, { 107, 		"voline online" }, { 108, 		"diskfull" }, { 109, 		"diskquota exceeded" }, { 110, 		"volume busy" }, { 111, 		"volume moved" }, { 112, 		"AFS IO error" }, { 0xffffff9c,	"restarting fileserver" }, { 0,		NULL }












};



static const struct tok rx_ack_reasons[] = {
	{ 1,		"ack requested" }, { 2,		"duplicate packet" }, { 3,		"out of sequence" }, { 4,		"exceeds window" }, { 5,		"no buffer space" }, { 6,		"ping" }, { 7,		"ping response" }, { 8,		"delay" }, { 9,		"idle" }, { 0,		NULL }, };












struct rx_cache_entry {
	uint32_t	callnum;	
	uint32_t	client;		
	uint32_t	server;		
	uint16_t	dport;		
	uint16_t	serviceId;	
	uint32_t	opcode;		
};



static struct rx_cache_entry	rx_cache[RX_CACHE_SIZE];

static uint32_t	rx_cache_next = 0;
static uint32_t	rx_cache_hint = 0;
static void	rx_cache_insert(netdissect_options *, const u_char *, const struct ip *, uint16_t);
static int	rx_cache_find(netdissect_options *, const struct rx_header *, const struct ip *, uint16_t, uint32_t *);

static void fs_print(netdissect_options *, const u_char *, u_int);
static void fs_reply_print(netdissect_options *, const u_char *, u_int, uint32_t);
static void acl_print(netdissect_options *, u_char *, const u_char *);
static void cb_print(netdissect_options *, const u_char *, u_int);
static void cb_reply_print(netdissect_options *, const u_char *, u_int, uint32_t);
static void prot_print(netdissect_options *, const u_char *, u_int);
static void prot_reply_print(netdissect_options *, const u_char *, u_int, uint32_t);
static void vldb_print(netdissect_options *, const u_char *, u_int);
static void vldb_reply_print(netdissect_options *, const u_char *, u_int, uint32_t);
static void kauth_print(netdissect_options *, const u_char *, u_int);
static void kauth_reply_print(netdissect_options *, const u_char *, u_int, uint32_t);
static void vol_print(netdissect_options *, const u_char *, u_int);
static void vol_reply_print(netdissect_options *, const u_char *, u_int, uint32_t);
static void bos_print(netdissect_options *, const u_char *, u_int);
static void bos_reply_print(netdissect_options *, const u_char *, u_int, uint32_t);
static void ubik_print(netdissect_options *, const u_char *);
static void ubik_reply_print(netdissect_options *, const u_char *, u_int, uint32_t);

static void rx_ack_print(netdissect_options *, const u_char *, u_int);

static int is_ubik(uint32_t);



void rx_print(netdissect_options *ndo, const u_char *bp, u_int length, uint16_t sport, uint16_t dport, const u_char *bp2)


{
	const struct rx_header *rxh;
	uint32_t i;
	uint8_t type, flags;
	uint32_t opcode;

	ndo->ndo_protocol = "rx";
	if (!ND_TTEST_LEN(bp, sizeof(struct rx_header))) {
		ND_PRINT(" [|rx] (%u)", length);
		return;
	}

	rxh = (const struct rx_header *) bp;

	type = GET_U_1(rxh->type);
	ND_PRINT(" rx %s", tok2str(rx_types, "type %u", type));

	flags = GET_U_1(rxh->flags);
	if (ndo->ndo_vflag) {
		int firstflag = 0;

		if (ndo->ndo_vflag > 1)
			ND_PRINT(" cid %08x call# %u", GET_BE_U_4(rxh->cid), GET_BE_U_4(rxh->callNumber));


		ND_PRINT(" seq %u ser %u", GET_BE_U_4(rxh->seq), GET_BE_U_4(rxh->serial));


		if (ndo->ndo_vflag > 2)
			ND_PRINT(" secindex %u serviceid %hu", GET_U_1(rxh->securityIndex), GET_BE_U_2(rxh->serviceId));


		if (ndo->ndo_vflag > 1)
			for (i = 0; i < NUM_RX_FLAGS; i++) {
				if (flags & rx_flags[i].flag && (!rx_flags[i].packetType || type == rx_flags[i].packetType)) {

					if (!firstflag) {
						firstflag = 1;
						ND_PRINT(" ");
					} else {
						ND_PRINT(",");
					}
					ND_PRINT("<%s>", rx_flags[i].s);
				}
			}
	}

	

	if (type == RX_PACKET_TYPE_DATA && GET_BE_U_4(rxh->seq) == 1 && flags & RX_CLIENT_INITIATED) {


		

		rx_cache_insert(ndo, bp, (const struct ip *) bp2, dport);

		switch (dport) {
			case FS_RX_PORT:	
				fs_print(ndo, bp, length);
				break;
			case CB_RX_PORT:	
				cb_print(ndo, bp, length);
				break;
			case PROT_RX_PORT:	
				prot_print(ndo, bp, length);
				break;
			case VLDB_RX_PORT:	
				vldb_print(ndo, bp, length);
				break;
			case KAUTH_RX_PORT:	
				kauth_print(ndo, bp, length);
				break;
			case VOL_RX_PORT:	
				vol_print(ndo, bp, length);
				break;
			case BOS_RX_PORT:	
				bos_print(ndo, bp, length);
				break;
			default:
				;
		}

	

	} else if (((type == RX_PACKET_TYPE_DATA && GET_BE_U_4(rxh->seq) == 1) || type == RX_PACKET_TYPE_ABORT) && (flags & RX_CLIENT_INITIATED) == 0 && rx_cache_find(ndo, rxh, (const struct ip *) bp2, sport, &opcode)) {





		switch (sport) {
			case FS_RX_PORT:	
				fs_reply_print(ndo, bp, length, opcode);
				break;
			case CB_RX_PORT:	
				cb_reply_print(ndo, bp, length, opcode);
				break;
			case PROT_RX_PORT:	
				prot_reply_print(ndo, bp, length, opcode);
				break;
			case VLDB_RX_PORT:	
				vldb_reply_print(ndo, bp, length, opcode);
				break;
			case KAUTH_RX_PORT:	
				kauth_reply_print(ndo, bp, length, opcode);
				break;
			case VOL_RX_PORT:	
				vol_reply_print(ndo, bp, length, opcode);
				break;
			case BOS_RX_PORT:	
				bos_reply_print(ndo, bp, length, opcode);
				break;
			default:
				;
		}

	

	} else if (type == RX_PACKET_TYPE_ACK)
		rx_ack_print(ndo, bp, length);


	ND_PRINT(" (%u)", length);
}



static void rx_cache_insert(netdissect_options *ndo, const u_char *bp, const struct ip *ip, uint16_t dport)

{
	struct rx_cache_entry *rxent;
	const struct rx_header *rxh = (const struct rx_header *) bp;

	if (!ND_TTEST_4(bp + sizeof(struct rx_header)))
		return;

	rxent = &rx_cache[rx_cache_next];

	if (++rx_cache_next >= RX_CACHE_SIZE)
		rx_cache_next = 0;

	rxent->callnum = GET_BE_U_4(rxh->callNumber);
	rxent->client = GET_IPV4_TO_NETWORK_ORDER(ip->ip_src);
	rxent->server = GET_IPV4_TO_NETWORK_ORDER(ip->ip_dst);
	rxent->dport = dport;
	rxent->serviceId = GET_BE_U_2(rxh->serviceId);
	rxent->opcode = GET_BE_U_4(bp + sizeof(struct rx_header));
}



static int rx_cache_find(netdissect_options *ndo, const struct rx_header *rxh, const struct ip *ip, uint16_t sport, uint32_t *opcode)

{
	uint32_t i;
	struct rx_cache_entry *rxent;
	uint32_t clip;
	uint32_t sip;

	clip = GET_IPV4_TO_NETWORK_ORDER(ip->ip_dst);
	sip = GET_IPV4_TO_NETWORK_ORDER(ip->ip_src);

	

	i = rx_cache_hint;
	do {
		rxent = &rx_cache[i];
		if (rxent->callnum == GET_BE_U_4(rxh->callNumber) && rxent->client == clip && rxent->server == sip && rxent->serviceId == GET_BE_U_2(rxh->serviceId) && rxent->dport == sport) {




			

			rx_cache_hint = i;
			*opcode = rxent->opcode;
			return(1);
		}
		if (++i >= RX_CACHE_SIZE)
			i = 0;
	} while (i != rx_cache_hint);

	
	return(0);
}




















































































































static void fs_print(netdissect_options *ndo, const u_char *bp, u_int length)

{
	uint32_t fs_op;
	uint32_t i;

	if (length <= sizeof(struct rx_header))
		return;

	

	fs_op = GET_BE_U_4(bp + sizeof(struct rx_header));

	ND_PRINT(" fs call %s", tok2str(fs_req, "op#%u", fs_op));

	

	bp += sizeof(struct rx_header) + 4;

	

	switch (fs_op) {
		case 130:	
			FIDOUT();
			ND_PRINT(" offset");
			UINTOUT();
			ND_PRINT(" length");
			UINTOUT();
			break;
		case 131:	
		case 132:	
		case 143:	
		case 144:	
		case 145:	
		case 156:	
		case 157:	
		case 158:	
			FIDOUT();
			break;
		case 135:	
			FIDOUT();
			STOREATTROUT();
			break;
		case 133:	
			FIDOUT();
			STOREATTROUT();
			ND_PRINT(" offset");
			UINTOUT();
			ND_PRINT(" length");
			UINTOUT();
			ND_PRINT(" flen");
			UINTOUT();
			break;
		case 134:	
		{
			char a[AFSOPAQUEMAX+1];
			FIDOUT();
			i = GET_BE_U_4(bp);
			bp += sizeof(uint32_t);
			ND_TCHECK_LEN(bp, i);
			i = ND_MIN(AFSOPAQUEMAX, i);
			strncpy(a, (const char *) bp, i);
			a[i] = '\0';
			acl_print(ndo, (u_char *) a, (u_char *) a + i);
			break;
		}
		case 137:	
		case 141:	
			FIDOUT();
			STROUT(AFSNAMEMAX);
			STOREATTROUT();
			break;
		case 136:	
		case 142:	
			FIDOUT();
			STROUT(AFSNAMEMAX);
			break;
		case 138:	
			ND_PRINT(" old");
			FIDOUT();
			STROUT(AFSNAMEMAX);
			ND_PRINT(" new");
			FIDOUT();
			STROUT(AFSNAMEMAX);
			break;
		case 139:	
			FIDOUT();
			STROUT(AFSNAMEMAX);
			ND_PRINT(" link to");
			STROUT(AFSNAMEMAX);
			break;
		case 140:	
			FIDOUT();
			STROUT(AFSNAMEMAX);
			ND_PRINT(" link to");
			FIDOUT();
			break;
		case 148:	
			STROUT(AFSNAMEMAX);
			break;
		case 149:	
		case 150:	
			ND_PRINT(" volid");
			UINTOUT();
			break;
		case 154:	
			ND_PRINT(" volname");
			STROUT(AFSNAMEMAX);
			break;
		case 155:	
		case 65536:     
		{
			uint32_t j;
			j = GET_BE_U_4(bp);
			bp += sizeof(uint32_t);

			for (i = 0; i < j; i++) {
				FIDOUT();
				if (i != j - 1)
					ND_PRINT(",");
			}
			if (j == 0)
				ND_PRINT(" <none!>");
			break;
		}
		case 65537:	
			FIDOUT();
			ND_PRINT(" offset");
			UINT64OUT();
			ND_PRINT(" length");
			UINT64OUT();
			break;
		case 65538:	
			FIDOUT();
			STOREATTROUT();
			ND_PRINT(" offset");
			UINT64OUT();
			ND_PRINT(" length");
			UINT64OUT();
			ND_PRINT(" flen");
			UINT64OUT();
			break;
		case 65541:    
			ND_PRINT(" addr");
			UINTOUT();
		default:
			;
	}

	return;

trunc:
	ND_PRINT(" [|fs]");
}



static void fs_reply_print(netdissect_options *ndo, const u_char *bp, u_int length, uint32_t opcode)

{
	uint32_t i;
	const struct rx_header *rxh;
	uint8_t type;

	if (length <= sizeof(struct rx_header))
		return;

	rxh = (const struct rx_header *) bp;

	

	ND_PRINT(" fs reply %s", tok2str(fs_req, "op#%u", opcode));

	type = GET_U_1(rxh->type);
	bp += sizeof(struct rx_header);

	

	if (type == RX_PACKET_TYPE_DATA) {
		switch (opcode) {
		case 131:	
		{
			char a[AFSOPAQUEMAX+1];
			i = GET_BE_U_4(bp);
			bp += sizeof(uint32_t);
			ND_TCHECK_LEN(bp, i);
			i = ND_MIN(AFSOPAQUEMAX, i);
			strncpy(a, (const char *) bp, i);
			a[i] = '\0';
			acl_print(ndo, (u_char *) a, (u_char *) a + i);
			break;
		}
		case 137:	
		case 141:	
			ND_PRINT(" new");
			FIDOUT();
			break;
		case 151:	
			ND_PRINT(" root volume");
			STROUT(AFSNAMEMAX);
			break;
		case 153:	
			DATEOUT();
			break;
		default:
			;
		}
	} else if (type == RX_PACKET_TYPE_ABORT) {
		
		int32_t errcode;

		errcode = GET_BE_S_4(bp);
		bp += sizeof(int32_t);

		ND_PRINT(" error %s", tok2str(afs_fs_errors, "#%d", errcode));
	} else {
		ND_PRINT(" strange fs reply of type %u", type);
	}

	return;

trunc:
	ND_PRINT(" [|fs]");
}






static void acl_print(netdissect_options *ndo, u_char *s, const u_char *end)

{
	int pos, neg, acl;
	int n, i;
	char user[USERNAMEMAX+1];

	if (sscanf((char *) s, "%d %d\n%n", &pos, &neg, &n) != 2)
		return;

	s += n;

	if (s > end)
		return;

	










	for (i = 0; i < pos; i++) {
		if (sscanf((char *) s, "%" NUMSTRINGIFY(USERNAMEMAX) "s %d\n%n", user, &acl, &n) != 2)
			return;
		s += n;
		ND_PRINT(" +{");
		fn_print_str(ndo, (u_char *)user);
		ND_PRINT(" ");
		ACLOUT(acl);
		ND_PRINT("}");
		if (s > end)
			return;
	}

	for (i = 0; i < neg; i++) {
		if (sscanf((char *) s, "%" NUMSTRINGIFY(USERNAMEMAX) "s %d\n%n", user, &acl, &n) != 2)
			return;
		s += n;
		ND_PRINT(" -{");
		fn_print_str(ndo, (u_char *)user);
		ND_PRINT(" ");
		ACLOUT(acl);
		ND_PRINT("}");
		if (s > end)
			return;
	}
}





static void cb_print(netdissect_options *ndo, const u_char *bp, u_int length)

{
	uint32_t cb_op;
	uint32_t i;

	if (length <= sizeof(struct rx_header))
		return;

	

	cb_op = GET_BE_U_4(bp + sizeof(struct rx_header));

	ND_PRINT(" cb call %s", tok2str(cb_req, "op#%u", cb_op));

	bp += sizeof(struct rx_header) + 4;

	

	switch (cb_op) {
		case 204:		
		{
			uint32_t j, t;
			j = GET_BE_U_4(bp);
			bp += sizeof(uint32_t);

			for (i = 0; i < j; i++) {
				FIDOUT();
				if (i != j - 1)
					ND_PRINT(",");
			}

			if (j == 0)
				ND_PRINT(" <none!>");

			j = GET_BE_U_4(bp);
			bp += sizeof(uint32_t);

			if (j != 0)
				ND_PRINT(";");

			for (i = 0; i < j; i++) {
				ND_PRINT(" ver");
				INTOUT();
				ND_PRINT(" expires");
				DATEOUT();
				t = GET_BE_U_4(bp);
				bp += sizeof(uint32_t);
				tok2str(cb_types, "type %u", t);
			}
			break;
		}
		case 214: {
			ND_PRINT(" afsuuid");
			AFSUUIDOUT();
			break;
		}
		default:
			;
	}

	return;

trunc:
	ND_PRINT(" [|cb]");
}



static void cb_reply_print(netdissect_options *ndo, const u_char *bp, u_int length, uint32_t opcode)

{
	const struct rx_header *rxh;
	uint8_t type;

	if (length <= sizeof(struct rx_header))
		return;

	rxh = (const struct rx_header *) bp;

	

	ND_PRINT(" cb reply %s", tok2str(cb_req, "op#%u", opcode));

	type = GET_U_1(rxh->type);
	bp += sizeof(struct rx_header);

	

	if (type == RX_PACKET_TYPE_DATA)
		switch (opcode) {
		case 213:	
			AFSUUIDOUT();
			break;
		default:
		;
		}
	else {
		
		ND_PRINT(" errcode");
		INTOUT();
	}

	return;

trunc:
	ND_PRINT(" [|cb]");
}



static void prot_print(netdissect_options *ndo, const u_char *bp, u_int length)

{
	uint32_t i;
	uint32_t pt_op;

	if (length <= sizeof(struct rx_header))
		return;

	

	pt_op = GET_BE_U_4(bp + sizeof(struct rx_header));

	ND_PRINT(" pt");

	if (is_ubik(pt_op)) {
		ubik_print(ndo, bp);
		return;
	}

	ND_PRINT(" call %s", tok2str(pt_req, "op#%u", pt_op));

	

	bp += sizeof(struct rx_header) + 4;

	switch (pt_op) {
		case 500:	
			STROUT(PRNAMEMAX);
			ND_PRINT(" id");
			INTOUT();
			ND_PRINT(" oldid");
			INTOUT();
			break;
		case 501:	
		case 506:	
		case 508:	
		case 512:	
		case 514:	
		case 517:	
		case 518:	
		case 519:	
		case 530:	
			ND_PRINT(" id");
			INTOUT();
			break;
		case 502:	
			ND_PRINT(" pos");
			INTOUT();
			break;
		case 503:	
		case 507:	
		case 515:	
			ND_PRINT(" uid");
			INTOUT();
			ND_PRINT(" gid");
			INTOUT();
			break;
		case 504:	
		{
			uint32_t j;
			j = GET_BE_U_4(bp);
			bp += sizeof(uint32_t);

			

			for (i = 0; i < j; i++) {
				VECOUT(PRNAMEMAX);
			}
			if (j == 0)
				ND_PRINT(" <none!>");
		}
			break;
		case 505:	
		{
			uint32_t j;
			ND_PRINT(" ids:");
			i = GET_BE_U_4(bp);
			bp += sizeof(uint32_t);
			for (j = 0; j < i; j++)
				INTOUT();
			if (j == 0)
				ND_PRINT(" <none!>");
		}
			break;
		case 509:	
			STROUT(PRNAMEMAX);
			ND_PRINT(" flag");
			INTOUT();
			ND_PRINT(" oid");
			INTOUT();
			break;
		case 511:	
			ND_PRINT(" id");
			INTOUT();
			ND_PRINT(" gflag");
			INTOUT();
			break;
		case 513:	
			ND_PRINT(" id");
			INTOUT();
			STROUT(PRNAMEMAX);
			ND_PRINT(" oldid");
			INTOUT();
			ND_PRINT(" newid");
			INTOUT();
			break;
		case 520:	
			ND_PRINT(" id");
			INTOUT();
			STROUT(PRNAMEMAX);
			break;
		default:
			;
	}


	return;

trunc:
	ND_PRINT(" [|pt]");
}



static void prot_reply_print(netdissect_options *ndo, const u_char *bp, u_int length, uint32_t opcode)

{
	const struct rx_header *rxh;
	uint8_t type;
	uint32_t i;

	if (length < sizeof(struct rx_header))
		return;

	rxh = (const struct rx_header *) bp;

	

	ND_PRINT(" pt");

	if (is_ubik(opcode)) {
		ubik_reply_print(ndo, bp, length, opcode);
		return;
	}

	ND_PRINT(" reply %s", tok2str(pt_req, "op#%u", opcode));

	type = GET_U_1(rxh->type);
	bp += sizeof(struct rx_header);

	

	if (type == RX_PACKET_TYPE_DATA)
		switch (opcode) {
		case 504:		
		{
			uint32_t j;
			ND_PRINT(" ids:");
			i = GET_BE_U_4(bp);
			bp += sizeof(uint32_t);
			for (j = 0; j < i; j++)
				INTOUT();
			if (j == 0)
				ND_PRINT(" <none!>");
		}
			break;
		case 505:		
		{
			uint32_t j;
			j = GET_BE_U_4(bp);
			bp += sizeof(uint32_t);

			

			for (i = 0; i < j; i++) {
				VECOUT(PRNAMEMAX);
			}
			if (j == 0)
				ND_PRINT(" <none!>");
		}
			break;
		case 508:		
		case 514:		
		case 517:		
		case 518:		
		case 519:		
		{
			uint32_t j;
			j = GET_BE_U_4(bp);
			bp += sizeof(uint32_t);
			for (i = 0; i < j; i++) {
				INTOUT();
			}
			if (j == 0)
				ND_PRINT(" <none!>");
		}
			break;
		case 510:		
			ND_PRINT(" maxuid");
			INTOUT();
			ND_PRINT(" maxgid");
			INTOUT();
			break;
		default:
			;
		}
	else {
		
		ND_PRINT(" errcode");
		INTOUT();
	}

	return;

trunc:
	ND_PRINT(" [|pt]");
}



static void vldb_print(netdissect_options *ndo, const u_char *bp, u_int length)

{
	uint32_t vldb_op;
	uint32_t i;

	if (length <= sizeof(struct rx_header))
		return;

	

	vldb_op = GET_BE_U_4(bp + sizeof(struct rx_header));

	ND_PRINT(" vldb");

	if (is_ubik(vldb_op)) {
		ubik_print(ndo, bp);
		return;
	}
	ND_PRINT(" call %s", tok2str(vldb_req, "op#%u", vldb_op));

	

	bp += sizeof(struct rx_header) + 4;

	switch (vldb_op) {
		case 501:	
		case 517:	
			VECOUT(VLNAMEMAX);
			break;
		case 502:	
		case 503:	
		case 507:	
		case 508:	
		case 509:	
		case 518:	
			ND_PRINT(" volid");
			INTOUT();
			i = GET_BE_U_4(bp);
			bp += sizeof(uint32_t);
			if (i <= 2)
				ND_PRINT(" type %s", voltype[i]);
			break;
		case 504:	
		case 519:	
		case 524:	
		case 527:	
			STROUT(VLNAMEMAX);
			break;
		case 505:	
			ND_PRINT(" bump");
			INTOUT();
			break;
		case 506:	
		case 520:	
			ND_PRINT(" volid");
			INTOUT();
			i = GET_BE_U_4(bp);
			bp += sizeof(uint32_t);
			if (i <= 2)
				ND_PRINT(" type %s", voltype[i]);
			VECOUT(VLNAMEMAX);
			break;
		case 510:	
		case 521:	
			ND_PRINT(" index");
			INTOUT();
			break;
		default:
			;
	}

	return;

trunc:
	ND_PRINT(" [|vldb]");
}



static void vldb_reply_print(netdissect_options *ndo, const u_char *bp, u_int length, uint32_t opcode)

{
	const struct rx_header *rxh;
	uint8_t type;
	uint32_t i;

	if (length < sizeof(struct rx_header))
		return;

	rxh = (const struct rx_header *) bp;

	

	ND_PRINT(" vldb");

	if (is_ubik(opcode)) {
		ubik_reply_print(ndo, bp, length, opcode);
		return;
	}

	ND_PRINT(" reply %s", tok2str(vldb_req, "op#%u", opcode));

	type = GET_U_1(rxh->type);
	bp += sizeof(struct rx_header);

	

	if (type == RX_PACKET_TYPE_DATA)
		switch (opcode) {
		case 510:	
			ND_PRINT(" count");
			INTOUT();
			ND_PRINT(" nextindex");
			INTOUT();
			ND_FALL_THROUGH;
		case 503:	
		case 504:	
		{	uint32_t nservers, j;
			VECOUT(VLNAMEMAX);
			ND_TCHECK_4(bp);
			bp += sizeof(uint32_t);
			ND_PRINT(" numservers");
			nservers = GET_BE_U_4(bp);
			bp += sizeof(uint32_t);
			ND_PRINT(" %u", nservers);
			ND_PRINT(" servers");
			for (i = 0; i < 8; i++) {
				ND_TCHECK_4(bp);
				if (i < nservers)
					ND_PRINT(" %s", intoa(GET_IPV4_TO_NETWORK_ORDER(bp)));
				bp += sizeof(nd_ipv4);
			}
			ND_PRINT(" partitions");
			for (i = 0; i < 8; i++) {
				j = GET_BE_U_4(bp);
				if (i < nservers && j <= 26)
					ND_PRINT(" %c", 'a' + j);
				else if (i < nservers)
					ND_PRINT(" %u", j);
				bp += sizeof(uint32_t);
			}
			ND_TCHECK_LEN(bp, 8 * sizeof(uint32_t));
			bp += 8 * sizeof(uint32_t);
			ND_PRINT(" rwvol");
			UINTOUT();
			ND_PRINT(" rovol");
			UINTOUT();
			ND_PRINT(" backup");
			UINTOUT();
		}
			break;
		case 505:	
			ND_PRINT(" newvol");
			UINTOUT();
			break;
		case 521:	
		case 529:	
			ND_PRINT(" count");
			INTOUT();
			ND_PRINT(" nextindex");
			INTOUT();
			ND_FALL_THROUGH;
		case 518:	
		case 519:	
		{	uint32_t nservers, j;
			VECOUT(VLNAMEMAX);
			ND_PRINT(" numservers");
			nservers = GET_BE_U_4(bp);
			bp += sizeof(uint32_t);
			ND_PRINT(" %u", nservers);
			ND_PRINT(" servers");
			for (i = 0; i < 13; i++) {
				ND_TCHECK_4(bp);
				if (i < nservers)
					ND_PRINT(" %s", intoa(GET_IPV4_TO_NETWORK_ORDER(bp)));
				bp += sizeof(nd_ipv4);
			}
			ND_PRINT(" partitions");
			for (i = 0; i < 13; i++) {
				j = GET_BE_U_4(bp);
				if (i < nservers && j <= 26)
					ND_PRINT(" %c", 'a' + j);
				else if (i < nservers)
					ND_PRINT(" %u", j);
				bp += sizeof(uint32_t);
			}
			ND_TCHECK_LEN(bp, 13 * sizeof(uint32_t));
			bp += 13 * sizeof(uint32_t);
			ND_PRINT(" rwvol");
			UINTOUT();
			ND_PRINT(" rovol");
			UINTOUT();
			ND_PRINT(" backup");
			UINTOUT();
		}
			break;
		case 526:	
		case 527:	
		{	uint32_t nservers, j;
			VECOUT(VLNAMEMAX);
			ND_PRINT(" numservers");
			nservers = GET_BE_U_4(bp);
			bp += sizeof(uint32_t);
			ND_PRINT(" %u", nservers);
			ND_PRINT(" servers");
			for (i = 0; i < 13; i++) {
				if (i < nservers) {
					ND_PRINT(" afsuuid");
					AFSUUIDOUT();
				} else {
					ND_TCHECK_LEN(bp, 44);
					bp += 44;
				}
			}
			ND_TCHECK_LEN(bp, 4 * 13);
			bp += 4 * 13;
			ND_PRINT(" partitions");
			for (i = 0; i < 13; i++) {
				j = GET_BE_U_4(bp);
				if (i < nservers && j <= 26)
					ND_PRINT(" %c", 'a' + j);
				else if (i < nservers)
					ND_PRINT(" %u", j);
				bp += sizeof(uint32_t);
			}
			ND_TCHECK_LEN(bp, 13 * sizeof(uint32_t));
			bp += 13 * sizeof(uint32_t);
			ND_PRINT(" rwvol");
			UINTOUT();
			ND_PRINT(" rovol");
			UINTOUT();
			ND_PRINT(" backup");
			UINTOUT();
		}
		default:
			;
		}

	else {
		
		ND_PRINT(" errcode");
		INTOUT();
	}

	return;

trunc:
	ND_PRINT(" [|vldb]");
}



static void kauth_print(netdissect_options *ndo, const u_char *bp, u_int length)

{
	uint32_t kauth_op;

	if (length <= sizeof(struct rx_header))
		return;

	

	kauth_op = GET_BE_U_4(bp + sizeof(struct rx_header));

	ND_PRINT(" kauth");

	if (is_ubik(kauth_op)) {
		ubik_print(ndo, bp);
		return;
	}


	ND_PRINT(" call %s", tok2str(kauth_req, "op#%u", kauth_op));

	

	bp += sizeof(struct rx_header) + 4;

	switch (kauth_op) {
		case 1:		
		case 21:	
		case 22:	
		case 2:		
		case 5:		
		case 6:		
		case 7:		
		case 8:		
		case 14:	
		case 15:	
			ND_PRINT(" principal");
			STROUT(KANAMEMAX);
			STROUT(KANAMEMAX);
			break;
		case 3:		
		case 23:	
		{
			uint32_t i;
			ND_PRINT(" kvno");
			INTOUT();
			ND_PRINT(" domain");
			STROUT(KANAMEMAX);
			i = GET_BE_U_4(bp);
			bp += sizeof(uint32_t);
			ND_TCHECK_LEN(bp, i);
			bp += i;
			ND_PRINT(" principal");
			STROUT(KANAMEMAX);
			STROUT(KANAMEMAX);
			break;
		}
		case 4:		
			ND_PRINT(" principal");
			STROUT(KANAMEMAX);
			STROUT(KANAMEMAX);
			ND_PRINT(" kvno");
			INTOUT();
			break;
		case 12:	
			ND_PRINT(" name");
			STROUT(KANAMEMAX);
			break;
		default:
			;
	}

	return;

trunc:
	ND_PRINT(" [|kauth]");
}



static void kauth_reply_print(netdissect_options *ndo, const u_char *bp, u_int length, uint32_t opcode)

{
	const struct rx_header *rxh;
	uint8_t type;

	if (length <= sizeof(struct rx_header))
		return;

	rxh = (const struct rx_header *) bp;

	

	ND_PRINT(" kauth");

	if (is_ubik(opcode)) {
		ubik_reply_print(ndo, bp, length, opcode);
		return;
	}

	ND_PRINT(" reply %s", tok2str(kauth_req, "op#%u", opcode));

	type = GET_U_1(rxh->type);
	bp += sizeof(struct rx_header);

	

	if (type == RX_PACKET_TYPE_DATA)
		
		;
	else {
		
		ND_PRINT(" errcode");
		INTOUT();
	}
}



static void vol_print(netdissect_options *ndo, const u_char *bp, u_int length)

{
	uint32_t vol_op;

	if (length <= sizeof(struct rx_header))
		return;

	

	vol_op = GET_BE_U_4(bp + sizeof(struct rx_header));

	ND_PRINT(" vol call %s", tok2str(vol_req, "op#%u", vol_op));

	bp += sizeof(struct rx_header) + 4;

	switch (vol_op) {
		case 100:	
			ND_PRINT(" partition");
			UINTOUT();
			ND_PRINT(" name");
			STROUT(AFSNAMEMAX);
			ND_PRINT(" type");
			UINTOUT();
			ND_PRINT(" parent");
			UINTOUT();
			break;
		case 101:	
		case 107:	
			ND_PRINT(" trans");
			UINTOUT();
			break;
		case 102:	
			ND_PRINT(" totrans");
			UINTOUT();
			ND_PRINT(" flags");
			UINTOUT();
			break;
		case 103:	
			ND_PRINT(" fromtrans");
			UINTOUT();
			ND_PRINT(" fromdate");
			DATEOUT();
			DESTSERVEROUT();
			ND_PRINT(" desttrans");
			INTOUT();
			break;
		case 104:	
			ND_PRINT(" trans");
			UINTOUT();
			break;
		case 105:	
			ND_PRINT(" trans");
			UINTOUT();
			ND_PRINT(" purgevol");
			UINTOUT();
			ND_PRINT(" newtype");
			UINTOUT();
			ND_PRINT(" newname");
			STROUT(AFSNAMEMAX);
			break;
		case 106:	
			ND_PRINT(" trans");
			UINTOUT();
			ND_PRINT(" flags");
			UINTOUT();
			break;
		case 108:	
			ND_PRINT(" vol");
			UINTOUT();
			ND_PRINT(" partition");
			UINTOUT();
			ND_PRINT(" flags");
			UINTOUT();
			break;
		case 109:	
		case 655537:	
			ND_PRINT(" fromtrans");
			UINTOUT();
			ND_PRINT(" fromdate");
			DATEOUT();
			break;
		case 110:	
			ND_PRINT(" index");
			UINTOUT();
			break;
		case 111:	
			ND_PRINT(" tid");
			UINTOUT();
			ND_PRINT(" newsite");
			UINTOUT();
			break;
		case 112:	
		case 113:	
			ND_PRINT(" tid");
			break;
		case 114:	
			ND_PRINT(" name");
			STROUT(AFSNAMEMAX);
			ND_PRINT(" type");
			UINTOUT();
			ND_PRINT(" pid");
			UINTOUT();
			ND_PRINT(" cloneid");
			UINTOUT();
			break;
		case 116:	
			ND_PRINT(" partition");
			UINTOUT();
			ND_PRINT(" flags");
			UINTOUT();
			break;
		case 117:	
			ND_PRINT(" tid");
			UINTOUT();
			ND_PRINT(" name");
			STROUT(AFSNAMEMAX);
			ND_PRINT(" type");
			UINTOUT();
			ND_PRINT(" pid");
			UINTOUT();
			ND_PRINT(" clone");
			UINTOUT();
			ND_PRINT(" backup");
			UINTOUT();
			break;
		case 119:	
			ND_PRINT(" name");
			STROUT(AFSNAMEMAX);
			break;
		case 120:	
			ND_PRINT(" tid");
			UINTOUT();
			break;
		case 121:	
		case 122:	
		case 124:	
		case 125:	
		case 65536:	
			ND_PRINT(" partid");
			UINTOUT();
			ND_PRINT(" volid");
			UINTOUT();
			break;
		case 123:	
			ND_PRINT(" tid");
			UINTOUT();
			ND_PRINT(" date");
			DATEOUT();
			break;
		case 126:	
			ND_PRINT(" tid");
			UINTOUT();
			break;
		case 128:	
			ND_PRINT(" fromtrans");
			UINTOUT();
			ND_PRINT(" fromdate");
			DATEOUT();
			{
				uint32_t i, j;
				j = GET_BE_U_4(bp);
				bp += sizeof(uint32_t);
				for (i = 0; i < j; i++) {
					DESTSERVEROUT();
					if (i != j - 1)
						ND_PRINT(",");
				}
				if (j == 0)
					ND_PRINT(" <none!>");
			}
			break;
		case 65538:	
			ND_PRINT(" fromtrans");
			UINTOUT();
			ND_PRINT(" fromdate");
			DATEOUT();
			ND_PRINT(" flags");
			UINTOUT();
			break;
		default:
			;
	}
	return;

trunc:
	ND_PRINT(" [|vol]");
}



static void vol_reply_print(netdissect_options *ndo, const u_char *bp, u_int length, uint32_t opcode)

{
	const struct rx_header *rxh;
	uint8_t type;

	if (length <= sizeof(struct rx_header))
		return;

	rxh = (const struct rx_header *) bp;

	

	ND_PRINT(" vol reply %s", tok2str(vol_req, "op#%u", opcode));

	type = GET_U_1(rxh->type);
	bp += sizeof(struct rx_header);

	

	if (type == RX_PACKET_TYPE_DATA) {
		switch (opcode) {
			case 100:	
				ND_PRINT(" volid");
				UINTOUT();
				ND_PRINT(" trans");
				UINTOUT();
				break;
			case 104:	
				UINTOUT();
				break;
			case 105:	
				ND_PRINT(" newvol");
				UINTOUT();
				break;
			case 107:	
				UINTOUT();
				break;
			case 108:	
				ND_PRINT(" trans");
				UINTOUT();
				break;
			case 110:	
				ND_PRINT(" volume");
				UINTOUT();
				ND_PRINT(" partition");
				UINTOUT();
				break;
			case 112:	
				STROUT(AFSNAMEMAX);
				break;
			case 113:	
				ND_PRINT(" volid");
				UINTOUT();
				ND_PRINT(" nextuniq");
				UINTOUT();
				ND_PRINT(" type");
				UINTOUT();
				ND_PRINT(" parentid");
				UINTOUT();
				ND_PRINT(" clone");
				UINTOUT();
				ND_PRINT(" backup");
				UINTOUT();
				ND_PRINT(" restore");
				UINTOUT();
				ND_PRINT(" maxquota");
				UINTOUT();
				ND_PRINT(" minquota");
				UINTOUT();
				ND_PRINT(" owner");
				UINTOUT();
				ND_PRINT(" create");
				DATEOUT();
				ND_PRINT(" access");
				DATEOUT();
				ND_PRINT(" update");
				DATEOUT();
				ND_PRINT(" expire");
				DATEOUT();
				ND_PRINT(" backup");
				DATEOUT();
				ND_PRINT(" copy");
				DATEOUT();
				break;
			case 115:	
				break;
			case 116:	
			case 121:	
				{
					uint32_t i, j;
					j = GET_BE_U_4(bp);
					bp += sizeof(uint32_t);
					for (i = 0; i < j; i++) {
						ND_PRINT(" name");
						VECOUT(32);
						ND_PRINT(" volid");
						UINTOUT();
						ND_PRINT(" type");
						bp += sizeof(uint32_t) * 21;
						if (i != j - 1)
							ND_PRINT(",");
					}
					if (j == 0)
						ND_PRINT(" <none!>");
				}
				break;


			default:
				;
		}
	} else {
		
		ND_PRINT(" errcode");
		INTOUT();
	}

	return;

trunc:
	ND_PRINT(" [|vol]");
}



static void bos_print(netdissect_options *ndo, const u_char *bp, u_int length)

{
	uint32_t bos_op;

	if (length <= sizeof(struct rx_header))
		return;

	

	bos_op = GET_BE_U_4(bp + sizeof(struct rx_header));

	ND_PRINT(" bos call %s", tok2str(bos_req, "op#%u", bos_op));

	

	bp += sizeof(struct rx_header) + 4;

	switch (bos_op) {
		case 80:	
			ND_PRINT(" type");
			STROUT(BOSNAMEMAX);
			ND_PRINT(" instance");
			STROUT(BOSNAMEMAX);
			break;
		case 81:	
		case 83:	
		case 85:	
		case 87:	
		case 88:	
		case 93:	
		case 96:	
		case 97:	
		case 104:	
		case 106:	
		case 108:	
		case 112:	
		case 114:	
			STROUT(BOSNAMEMAX);
			break;
		case 82:	
		case 98:	
			STROUT(BOSNAMEMAX);
			ND_PRINT(" status");
			INTOUT();
			break;
		case 86:	
			STROUT(BOSNAMEMAX);
			ND_PRINT(" num");
			INTOUT();
			break;
		case 84:	
		case 89:	
		case 90:	
		case 91:	
		case 92:	
		case 95:	
			INTOUT();
			break;
		case 105:	
			STROUT(BOSNAMEMAX);
			ND_PRINT(" size");
			INTOUT();
			ND_PRINT(" flags");
			INTOUT();
			ND_PRINT(" date");
			INTOUT();
			break;
		default:
			;
	}

	return;

trunc:
	ND_PRINT(" [|bos]");
}



static void bos_reply_print(netdissect_options *ndo, const u_char *bp, u_int length, uint32_t opcode)

{
	const struct rx_header *rxh;
	uint8_t type;

	if (length <= sizeof(struct rx_header))
		return;

	rxh = (const struct rx_header *) bp;

	

	ND_PRINT(" bos reply %s", tok2str(bos_req, "op#%u", opcode));

	type = GET_U_1(rxh->type);
	bp += sizeof(struct rx_header);

	

	if (type == RX_PACKET_TYPE_DATA)
		
		;
	else {
		
		ND_PRINT(" errcode");
		INTOUT();
	}
}



static int is_ubik(uint32_t opcode)
{
	if ((opcode >= VOTE_LOW && opcode <= VOTE_HIGH) || (opcode >= DISK_LOW && opcode <= DISK_HIGH))
		return(1);
	else return(0);
}



static void ubik_print(netdissect_options *ndo, const u_char *bp)

{
	uint32_t ubik_op;
	uint32_t temp;

	

	
	ubik_op = GET_BE_U_4(bp + sizeof(struct rx_header));

	ND_PRINT(" ubik call %s", tok2str(ubik_req, "op#%u", ubik_op));

	

	bp += sizeof(struct rx_header) + 4;

	switch (ubik_op) {
		case 10000:		
			temp = GET_BE_U_4(bp);
			bp += sizeof(uint32_t);
			ND_PRINT(" syncsite %s", temp ? "yes" : "no");
			ND_PRINT(" votestart");
			DATEOUT();
			ND_PRINT(" dbversion");
			UBIK_VERSIONOUT();
			ND_PRINT(" tid");
			UBIK_VERSIONOUT();
			break;
		case 10003:		
			ND_PRINT(" site");
			UINTOUT();
			break;
		case 20000:		
		case 20001:		
		case 20007:		
		case 20008:		
		case 20010:		
			ND_PRINT(" tid");
			UBIK_VERSIONOUT();
			break;
		case 20002:		
			ND_PRINT(" tid");
			UBIK_VERSIONOUT();
			ND_PRINT(" file");
			INTOUT();
			ND_PRINT(" pos");
			INTOUT();
			ND_PRINT(" length");
			INTOUT();
			temp = GET_BE_U_4(bp);
			bp += sizeof(uint32_t);
			tok2str(ubik_lock_types, "type %u", temp);
			break;
		case 20003:		
			ND_PRINT(" tid");
			UBIK_VERSIONOUT();
			ND_PRINT(" file");
			INTOUT();
			ND_PRINT(" pos");
			INTOUT();
			break;
		case 20005:		
			ND_PRINT(" file");
			INTOUT();
			break;
		case 20006:		
			ND_PRINT(" file");
			INTOUT();
			ND_PRINT(" length");
			INTOUT();
			ND_PRINT(" dbversion");
			UBIK_VERSIONOUT();
			break;
		case 20009:		
			ND_PRINT(" tid");
			UBIK_VERSIONOUT();
			ND_PRINT(" file");
			INTOUT();
			ND_PRINT(" length");
			INTOUT();
			break;
		case 20012:		
			ND_PRINT(" tid");
			UBIK_VERSIONOUT();
			ND_PRINT(" oldversion");
			UBIK_VERSIONOUT();
			ND_PRINT(" newversion");
			UBIK_VERSIONOUT();
			break;
		default:
			;
	}

	return;

trunc:
	ND_PRINT(" [|ubik]");
}



static void ubik_reply_print(netdissect_options *ndo, const u_char *bp, u_int length, uint32_t opcode)

{
	const struct rx_header *rxh;
	uint8_t type;

	if (length < sizeof(struct rx_header))
		return;

	rxh = (const struct rx_header *) bp;

	

	ND_PRINT(" ubik reply %s", tok2str(ubik_req, "op#%u", opcode));

	type = GET_U_1(rxh->type);
	bp += sizeof(struct rx_header);

	

	if (type == RX_PACKET_TYPE_DATA)
		switch (opcode) {
		case 10000:		
			ND_PRINT(" vote no");
			break;
		case 20004:		
			ND_PRINT(" dbversion");
			UBIK_VERSIONOUT();
			break;
		default:
			;
		}

	

	else switch (opcode) {
		case 10000:		
			ND_PRINT(" vote yes until");
			DATEOUT();
			break;
		default:
			ND_PRINT(" errcode");
			INTOUT();
		}

	return;

trunc:
	ND_PRINT(" [|ubik]");
}



static void rx_ack_print(netdissect_options *ndo, const u_char *bp, u_int length)

{
	const struct rx_ackPacket *rxa;
	uint8_t nAcks;
	int i, start, last;
	uint32_t firstPacket;

	if (length < sizeof(struct rx_header))
		return;

	bp += sizeof(struct rx_header);

	ND_TCHECK_LEN(bp, sizeof(struct rx_ackPacket));

	rxa = (const struct rx_ackPacket *) bp;
	bp += sizeof(struct rx_ackPacket);

	

	if (ndo->ndo_vflag > 2)
		ND_PRINT(" bufspace %u maxskew %u", GET_BE_U_2(rxa->bufferSpace), GET_BE_U_2(rxa->maxSkew));


	firstPacket = GET_BE_U_4(rxa->firstPacket);
	ND_PRINT(" first %u serial %u reason %s", firstPacket, GET_BE_U_4(rxa->serial), tok2str(rx_ack_reasons, "#%u", GET_U_1(rxa->reason)));


	

	nAcks = GET_U_1(rxa->nAcks);
	if (nAcks != 0) {

		ND_TCHECK_LEN(bp, nAcks);

		

		for (i = 0, start = last = -2; i < nAcks; i++)
			if (GET_U_1(bp + i) == RX_ACK_TYPE_ACK) {

				

				if (last == -2) {
					ND_PRINT(" acked %u", firstPacket + i);
					start = i;
				}

				

				else if (last != i - 1) {
					ND_PRINT(",%u", firstPacket + i);
					start = i;
				}

				

				last = i;

				
			} else if (last == i - 1 && start != last)
				ND_PRINT("-%u", firstPacket + i - 1);

		

		if (last == i - 1 && start != last)
			ND_PRINT("-%u", firstPacket + i - 1);

		

		for (i = 0, start = last = -2; i < nAcks; i++)
			if (GET_U_1(bp + i) == RX_ACK_TYPE_NACK) {
				if (last == -2) {
					ND_PRINT(" nacked %u", firstPacket + i);
					start = i;
				} else if (last != i - 1) {
					ND_PRINT(",%u", firstPacket + i);
					start = i;
				}
				last = i;
			} else if (last == i - 1 && start != last)
				ND_PRINT("-%u", firstPacket + i - 1);

		if (last == i - 1 && start != last)
			ND_PRINT("-%u", firstPacket + i - 1);

		bp += nAcks;
	}

	
	bp += 3;

	



	if (ndo->ndo_vflag > 1) {
		TRUNCRET(4);
		ND_PRINT(" ifmtu");
		UINTOUT();

		TRUNCRET(4);
		ND_PRINT(" maxmtu");
		UINTOUT();

		TRUNCRET(4);
		ND_PRINT(" rwind");
		UINTOUT();

		TRUNCRET(4);
		ND_PRINT(" maxpackets");
		UINTOUT();
	}

	return;

trunc:
	ND_PRINT(" [|ack]");
}

