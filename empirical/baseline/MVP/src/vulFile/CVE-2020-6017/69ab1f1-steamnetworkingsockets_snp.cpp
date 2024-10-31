








namespace SteamNetworkingSocketsLib {

struct SNPAckSerializerHelper {
	struct Block {
		
		uint32 m_nAck;
		uint32 m_nNack;

		
		
		uint32 m_nLatestPktNum; 
		uint16 m_nEncodedTimeSinceLatestPktNum;

		
		
		int16 m_cbTotalEncodedSize;
	};

	enum { k_cbHeaderSize = 5 };
	enum { k_nMaxBlocks = 64 };
	int m_nBlocks;
	int m_nBlocksNeedToAck; 
	Block m_arBlocks[ k_nMaxBlocks ];

	static uint16 EncodeTimeSince( SteamNetworkingMicroseconds usecNow, SteamNetworkingMicroseconds usecWhenSentLast )
	{

		
		SteamNetworkingMicroseconds usecElapsedSinceLast = usecNow - usecWhenSentLast;
		Assert( usecElapsedSinceLast >= 0 );
		Assert( usecNow > 0x20000*k_usecAckDelayPrecision ); 
		if ( usecElapsedSinceLast > 0xfffell<<k_nAckDelayPrecisionShift )
			return 0xffff;
		return uint16( usecElapsedSinceLast >> k_nAckDelayPrecisionShift );
	}

};




inline SteamNetworkingMicroseconds GetUsecPingWithFallback( CSteamNetworkConnectionBase *pConnection )
{
	int nPingMS = pConnection->m_statsEndToEnd.m_ping.m_nSmoothedPing;
	if ( nPingMS < 0 )
		return 200*1000; 
	if ( nPingMS < 1 )
		return 500; 
	return nPingMS*1000;
}


void SSNPSenderState::Shutdown()
{
	m_unackedReliableMessages.PurgeMessages();
	m_messagesQueued.PurgeMessages();
	m_mapInFlightPacketsByPktNum.clear();
	m_listInFlightReliableRange.clear();
	m_cbPendingUnreliable = 0;
	m_cbPendingReliable = 0;
	m_cbSentUnackedReliable = 0;
}


void SSNPSenderState::RemoveAckedReliableMessageFromUnackedList()
{

	
	
	
	
	
	while ( !m_unackedReliableMessages.empty() )
	{
		CSteamNetworkingMessage *pMsg = m_unackedReliableMessages.m_pFirst;
		Assert( pMsg->SNPSend_ReliableStreamPos() > 0 );
		int64 nReliableEnd = pMsg->SNPSend_ReliableStreamPos() + pMsg->m_cbSize;

		
		
		if ( !m_listInFlightReliableRange.empty() )
		{
			auto head = m_listInFlightReliableRange.begin();
			Assert( head->first.m_nBegin >= pMsg->SNPSend_ReliableStreamPos() );
			if ( head->second == pMsg )
			{
				Assert( head->first.m_nBegin < nReliableEnd );
				return;
			}
			Assert( head->first.m_nBegin >= nReliableEnd );
		}

		
		if ( !m_listReadyRetryReliableRange.empty() )
		{
			auto head = m_listReadyRetryReliableRange.begin();
			Assert( head->first.m_nBegin >= pMsg->SNPSend_ReliableStreamPos() );
			if ( head->second == pMsg )
			{
				Assert( head->first.m_nBegin < nReliableEnd );
				return;
			}
			Assert( head->first.m_nBegin >= nReliableEnd );
		}

		
		DbgVerify( m_unackedReliableMessages.pop_front() == pMsg );
		pMsg->Release();
	}
}


SSNPSenderState::SSNPSenderState()
{
	
	m_mapInFlightPacketsByPktNum.clear();
	SNPInFlightPacket_t &sentinel = m_mapInFlightPacketsByPktNum[INT64_MIN];
	sentinel.m_bNack = false;
	sentinel.m_pTransport = nullptr;
	sentinel.m_usecWhenSent = 0;
	m_itNextInFlightPacketToTimeout = m_mapInFlightPacketsByPktNum.end();
	DebugCheckInFlightPacketMap();
}


void SSNPSenderState::DebugCheckInFlightPacketMap() const {
	Assert( !m_mapInFlightPacketsByPktNum.empty() );
	bool bFoundNextToTimeout = false;
	auto it = m_mapInFlightPacketsByPktNum.begin();
	Assert( it->first == INT64_MIN );
	Assert( m_itNextInFlightPacketToTimeout != it );
	int64 prevPktNum = it->first;
	SteamNetworkingMicroseconds prevWhenSent = it->second.m_usecWhenSent;
	while ( ++it != m_mapInFlightPacketsByPktNum.end() )
	{
		Assert( prevPktNum < it->first );
		Assert( prevWhenSent <= it->second.m_usecWhenSent );
		if ( it == m_itNextInFlightPacketToTimeout )
		{
			Assert( !bFoundNextToTimeout );
			bFoundNextToTimeout = true;
		}
		prevPktNum = it->first;
		prevWhenSent = it->second.m_usecWhenSent;
	}
	if ( !bFoundNextToTimeout )
	{
		Assert( m_itNextInFlightPacketToTimeout == m_mapInFlightPacketsByPktNum.end() );
	}
}



SSNPReceiverState::SSNPReceiverState()
{
	
	SSNPPacketGap &sentinel = m_mapPacketGaps[INT64_MAX];
	sentinel.m_nEnd = INT64_MAX; 
	sentinel.m_usecWhenOKToNack = INT64_MAX; 
	sentinel.m_usecWhenAckPrior = INT64_MAX; 

	
	m_itPendingAck = m_mapPacketGaps.end();
	--m_itPendingAck;
	m_itPendingNack = m_itPendingAck;
}


void SSNPReceiverState::Shutdown()
{
	m_mapUnreliableSegments.clear();
	m_bufReliableStream.clear();
	m_mapReliableStreamGaps.clear();
	m_mapPacketGaps.clear();
}


void CSteamNetworkConnectionBase::SNP_InitializeConnection( SteamNetworkingMicroseconds usecNow )
{
	m_senderState.TokenBucket_Init( usecNow );

	SteamNetworkingMicroseconds usecPing = GetUsecPingWithFallback( this );

	
	Assert( usecPing > 0 );
	int64 w_init = Clamp( 4380, 2 * k_cbSteamNetworkingSocketsMaxEncryptedPayloadSend, 4 * k_cbSteamNetworkingSocketsMaxEncryptedPayloadSend );
	m_senderState.m_n_x = int( k_nMillion * w_init / usecPing );

	
	SNP_ClampSendRate();
}


void CSteamNetworkConnectionBase::SNP_ShutdownConnection()
{
	m_senderState.Shutdown();
	m_receiverState.Shutdown();
}


int64 CSteamNetworkConnectionBase::SNP_SendMessage( CSteamNetworkingMessage *pSendMessage, SteamNetworkingMicroseconds usecNow, bool *pbThinkImmediately )
{
	int cbData = (int)pSendMessage->m_cbSize;

	
	if ( pbThinkImmediately )
		*pbThinkImmediately = false;

	
	if ( m_senderState.PendingBytesTotal() + cbData > m_connectionConfig.m_SendBufferSize.Get() )
	{
		SpewWarningRateLimited( usecNow, "Connection already has %u bytes pending, cannot queue any more messages\n", m_senderState.PendingBytesTotal() );
		pSendMessage->Release();
		return -k_EResultLimitExceeded; 
	}

	
	if ( cbData > k_cbMaxUnreliableMsgSize && !( pSendMessage->m_nFlags & k_nSteamNetworkingSend_Reliable )  )
	{
		SpewWarningRateLimited( usecNow, "Trying to send a very large (%d bytes) unreliable message.  Sending as reliable instead.\n", cbData );
		pSendMessage->m_nFlags |= k_nSteamNetworkingSend_Reliable;
	}

	if ( pSendMessage->m_nFlags & k_nSteamNetworkingSend_NoDelay )
	{
		
		
		
	}

	
	
	SNP_ClampSendRate();
	SNP_TokenBucket_Accumulate( usecNow );

	
	pSendMessage->m_nMessageNumber = ++m_senderState.m_nLastSentMsgNum;

	
	if ( pSendMessage->m_nFlags & k_nSteamNetworkingSend_Reliable )
	{
		pSendMessage->SNPSend_SetReliableStreamPos( m_senderState.m_nReliableStreamPos );

		
		byte *hdr = pSendMessage->SNPSend_ReliableHeader();
		hdr[0] = 0;
		byte *hdrEnd = hdr+1;
		int64 nMsgNumGap = pSendMessage->m_nMessageNumber - m_senderState.m_nLastSendMsgNumReliable;
		Assert( nMsgNumGap >= 1 );
		if ( nMsgNumGap > 1 )
		{
			hdrEnd = SerializeVarInt( hdrEnd, (uint64)nMsgNumGap );
			hdr[0] |= 0x40;
		}
		if ( cbData < 0x20 )
		{
			hdr[0] |= (byte)cbData;
		}
		else {
			hdr[0] |= (byte)( 0x20 | ( cbData & 0x1f ) );
			hdrEnd = SerializeVarInt( hdrEnd, cbData>>5U );
		}
		pSendMessage->m_cbSNPSendReliableHeader = hdrEnd - hdr;

		
		pSendMessage->m_cbSize += pSendMessage->m_cbSNPSendReliableHeader;

		
		m_senderState.m_nReliableStreamPos += pSendMessage->m_cbSize;

		
		++m_senderState.m_nMessagesSentReliable;
		m_senderState.m_cbPendingReliable += pSendMessage->m_cbSize;

		
		
		m_senderState.m_nLastSendMsgNumReliable = pSendMessage->m_nMessageNumber;

		Assert( pSendMessage->SNPSend_IsReliable() );
	}
	else {
		pSendMessage->SNPSend_SetReliableStreamPos( 0 );
		pSendMessage->m_cbSNPSendReliableHeader = 0;

		++m_senderState.m_nMessagesSentUnreliable;
		m_senderState.m_cbPendingUnreliable += pSendMessage->m_cbSize;

		Assert( !pSendMessage->SNPSend_IsReliable() );
	}

	
	m_senderState.m_messagesQueued.push_back( pSendMessage );
	SpewVerboseGroup( m_connectionConfig.m_LogLevel_Message.Get(), "[%s] SendMessage %s: MsgNum=%lld sz=%d\n", GetDescription(), pSendMessage->SNPSend_IsReliable() ? "RELIABLE" : "UNRELIABLE", (long long)pSendMessage->m_nMessageNumber, pSendMessage->m_cbSize );




	
	
	
	
	
	
	
	pSendMessage->SNPSend_SetUsecNagle( usecNow + m_connectionConfig.m_NagleTime.Get() );
	if ( pSendMessage->m_nFlags & k_nSteamNetworkingSend_NoNagle )
		m_senderState.ClearNagleTimers();

	
	int64 result = pSendMessage->m_nMessageNumber;

	
	
	
	
	
	
	
	if ( GetState() == k_ESteamNetworkingConnectionState_Connected )
	{
		SteamNetworkingMicroseconds usecNextThink = SNP_GetNextThinkTime( usecNow );

		
		if ( usecNextThink > usecNow )
		{

			
			if ( m_senderState.m_messagesQueued.m_pFirst->SNPSend_UsecNagle() == 0 )
			{
				SpewVerbose( "[%s] RATELIM QueueTime is %.1fms, SendRate=%.1fk, BytesQueued=%d\n",  GetDescription(), m_senderState.CalcTimeUntilNextSend() * 1e-3, m_senderState.m_n_x * ( 1.0/1024.0), m_senderState.PendingBytesTotal()



				);
			}

			
			EnsureMinThinkTime( usecNextThink );
		}
		else {

			
			if ( pSendMessage->m_nFlags & k_nSteamNetworkingSend_UseCurrentThread )
			{

				
				
				if ( pbThinkImmediately )
				{
					
					*pbThinkImmediately = true;
				}
				else {
					
					CheckConnectionStateAndSetNextThinkTime( usecNow );
				}
			}
			else {
				
				SetNextThinkTimeASAP();
			}
		}
	}

	return result;
}

EResult CSteamNetworkConnectionBase::SNP_FlushMessage( SteamNetworkingMicroseconds usecNow )
{
	
	
	if ( GetState() != k_ESteamNetworkingConnectionState_Connected )
	{
		m_senderState.ClearNagleTimers();
		return k_EResultIgnored;
	}

	if ( m_senderState.m_messagesQueued.empty() )
		return k_EResultOK;

	
	
	if ( m_senderState.m_messagesQueued.m_pLast->SNPSend_UsecNagle() == 0 )
		return k_EResultOK;

	
	
	
	
	SNP_ClampSendRate();
	SNP_TokenBucket_Accumulate( usecNow );

	
	m_senderState.ClearNagleTimers();

	
	SteamNetworkingMicroseconds usecNextThink = SNP_GetNextThinkTime( usecNow );
	EnsureMinThinkTime( usecNextThink );
	return k_EResultOK;
}

bool CSteamNetworkConnectionBase::ProcessPlainTextDataChunk( int usecTimeSinceLast, RecvPacketContext_t &ctx )
{
	#define DECODE_ERROR( ... ) do {  ConnectionState_ProblemDetectedLocally( k_ESteamNetConnectionEnd_Misc_InternalError, __VA_ARGS__ ); return false; } while(false


	#define EXPECT_BYTES(n,pszWhatFor)  do { if ( pDecode + (n) > pEnd ) DECODE_ERROR( "SNP decode overrun, %d bytes for %s", (n), pszWhatFor ); } while (false




	#define READ_8BITU( var, pszWhatFor )  do { EXPECT_BYTES(1,pszWhatFor); var = *(uint8 *)pDecode; pDecode += 1; } while(false

	#define READ_16BITU( var, pszWhatFor )  do { EXPECT_BYTES(2,pszWhatFor); var = LittleWord(*(uint16 *)pDecode); pDecode += 2; } while(false

	#define READ_24BITU( var, pszWhatFor )  do { EXPECT_BYTES(3,pszWhatFor); var = *(uint8 *)pDecode; pDecode += 1; var |= uint32( LittleWord(*(uint16 *)pDecode) ) << 8U; pDecode += 2; } while(false




	#define READ_32BITU( var, pszWhatFor )  do { EXPECT_BYTES(4,pszWhatFor); var = LittleDWord(*(uint32 *)pDecode); pDecode += 4; } while(false

	#define READ_48BITU( var, pszWhatFor )  do { EXPECT_BYTES(6,pszWhatFor); var = LittleWord( *(uint16 *)pDecode ); pDecode += 2; var |= uint64( LittleDWord(*(uint32 *)pDecode) ) << 16U; pDecode += 4; } while(false




	#define READ_64BITU( var, pszWhatFor )  do { EXPECT_BYTES(8,pszWhatFor); var = LittleQWord(*(uint64 *)pDecode); pDecode += 8; } while(false

	#define READ_VARINT( var, pszWhatFor )  do { pDecode = DeserializeVarInt( pDecode, pEnd, var ); if ( !pDecode ) { DECODE_ERROR( "SNP data chunk decode overflow, varint for %s", pszWhatFor ); } } while(false

	#define READ_SEGMENT_DATA_SIZE( is_reliable )  int cbSegmentSize; { int sizeFlags = nFrameType & 7; if ( sizeFlags <= 4 ) { uint8 lowerSizeBits; READ_8BITU( lowerSizeBits, #is_reliable " size lower bits" ); cbSegmentSize = (sizeFlags<<8) + lowerSizeBits; if ( pDecode + cbSegmentSize > pEnd ) { DECODE_ERROR( "SNP decode overrun %d bytes for %s segment data.", cbSegmentSize, #is_reliable ); } } else if ( sizeFlags == 7 ) { cbSegmentSize = pEnd - pDecode; } else { DECODE_ERROR( "Invalid SNP frame lead byte 0x%02x. (size bits)", nFrameType ); } } const uint8 *pSegmentData = pDecode; pDecode += cbSegmentSize
























	
	Assert( BStateIsActive() );

	const SteamNetworkingMicroseconds usecNow = ctx.m_usecNow;
	const int64 nPktNum = ctx.m_nPktNum;
	bool bInhibitMarkReceived = false;

	const int nLogLevelPacketDecode = m_connectionConfig.m_LogLevel_PacketDecode.Get();
	SpewVerboseGroup( nLogLevelPacketDecode, "[%s] decode pkt %lld\n", GetDescription(), (long long)nPktNum );

	
	const byte *pDecode = (const byte *)ctx.m_pPlainText;
	const byte *pEnd = pDecode + ctx.m_cbPlainText;
	int64 nCurMsgNum = 0;
	int64 nDecodeReliablePos = 0;
	while ( pDecode < pEnd )
	{

		uint8 nFrameType = *pDecode;
		++pDecode;
		if ( ( nFrameType & 0xc0 ) == 0x00 )
		{

			
			
			

			
			if ( nCurMsgNum == 0 )
			{
				
				static const char szUnreliableMsgNumOffset[] = "unreliable msgnum";
				int64 nLowerBits, nMask;
				if ( nFrameType & 0x10 )
				{
					READ_32BITU( nLowerBits, szUnreliableMsgNumOffset );
					nMask = 0xffffffff;
					nCurMsgNum = NearestWithSameLowerBits( (int32)nLowerBits, m_receiverState.m_nHighestSeenMsgNum );
				}
				else {
					READ_16BITU( nLowerBits, szUnreliableMsgNumOffset );
					nMask = 0xffff;
					nCurMsgNum = NearestWithSameLowerBits( (int16)nLowerBits, m_receiverState.m_nHighestSeenMsgNum );
				}
				Assert( ( nCurMsgNum & nMask ) == nLowerBits );

				if ( nCurMsgNum <= 0 )
				{
					DECODE_ERROR( "SNP decode unreliable msgnum underflow.  %llx mod %llx, highest seen %llx", (unsigned long long)nLowerBits, (unsigned long long)( nMask+1 ), (unsigned long long)m_receiverState.m_nHighestSeenMsgNum );
				}
				if ( std::abs( nCurMsgNum - m_receiverState.m_nHighestSeenMsgNum ) > (nMask>>2) )
				{
					
					SpewWarningRateLimited( usecNow, "Sender sent abs unreliable message number using %llx mod %llx, highest seen %llx\n", (unsigned long long)nLowerBits, (unsigned long long)( nMask+1 ), (unsigned long long)m_receiverState.m_nHighestSeenMsgNum );
				}

			}
			else {
				if ( nFrameType & 0x10 )
				{
					uint64 nMsgNumOffset;
					READ_VARINT( nMsgNumOffset, "unreliable msgnum offset" );
					nCurMsgNum += nMsgNumOffset;
				}
				else {
					++nCurMsgNum;
				}
			}
			if ( nCurMsgNum > m_receiverState.m_nHighestSeenMsgNum )
				m_receiverState.m_nHighestSeenMsgNum = nCurMsgNum;

			
			
			
			uint32 nOffset = 0;
			if ( nFrameType & 0x08 )
				READ_VARINT( nOffset, "unreliable data offset" );

			
			
			
			READ_SEGMENT_DATA_SIZE( unreliable )
			Assert( cbSegmentSize > 0 ); 

			
			bool bLastSegmentInMessage = ( nFrameType & 0x20 ) != 0;
			SNP_ReceiveUnreliableSegment( nCurMsgNum, nOffset, pSegmentData, cbSegmentSize, bLastSegmentInMessage, usecNow );
		}
		else if ( ( nFrameType & 0xe0 ) == 0x40 )
		{

			
			
			

			
			if ( nDecodeReliablePos == 0 )
			{

				
				static const char szFirstReliableStreamPos[] = "first reliable streampos";
				int64 nOffset, nMask;
				switch ( nFrameType & (3<<3) )
				{
					case 0<<3: READ_24BITU( nOffset, szFirstReliableStreamPos ); nMask = (1ll<<24)-1; break;
					case 1<<3: READ_32BITU( nOffset, szFirstReliableStreamPos ); nMask = (1ll<<32)-1; break;
					case 2<<3: READ_48BITU( nOffset, szFirstReliableStreamPos ); nMask = (1ll<<48)-1; break;
					default: DECODE_ERROR( "Reserved reliable stream pos size" );
				}

				
				int64 nExpectNextStreamPos = m_receiverState.m_nReliableStreamPos + len( m_receiverState.m_bufReliableStream );

				
				nDecodeReliablePos = ( nExpectNextStreamPos & ~nMask ) + nOffset;
				if ( nDecodeReliablePos + (nMask>>1) < nExpectNextStreamPos )
				{
					nDecodeReliablePos += nMask+1;
					Assert( ( nDecodeReliablePos & nMask ) == nOffset );
					Assert( nExpectNextStreamPos < nDecodeReliablePos );
					Assert( nExpectNextStreamPos + (nMask>>1) >= nDecodeReliablePos );
				}
				if ( nDecodeReliablePos <= 0 )
				{
					DECODE_ERROR( "SNP decode first reliable stream pos underflow.  %llx mod %llx, expected next %llx", (unsigned long long)nOffset, (unsigned long long)( nMask+1 ), (unsigned long long)nExpectNextStreamPos );
				}
				if ( std::abs( nDecodeReliablePos - nExpectNextStreamPos ) > (nMask>>2) )
				{
					
					SpewWarningRateLimited( usecNow, "Sender sent reliable stream pos using %llx mod %llx, expected next %llx\n", (unsigned long long)nOffset, (unsigned long long)( nMask+1 ), (unsigned long long)nExpectNextStreamPos );
				}
			}
			else {
				
				static const char szOtherReliableStreamPos[] = "reliable streampos offset";
				int64 nOffset;
				switch ( nFrameType & (3<<3) )
				{
					case 0<<3: nOffset = 0; break;
					case 1<<3: READ_8BITU( nOffset, szOtherReliableStreamPos ); break;
					case 2<<3: READ_16BITU( nOffset, szOtherReliableStreamPos ); break;
					default: READ_32BITU( nOffset, szOtherReliableStreamPos ); break;
				}
				nDecodeReliablePos += nOffset;
			}

			
			
			
			READ_SEGMENT_DATA_SIZE( reliable )

			
			if ( !SNP_ReceiveReliableSegment( nPktNum, nDecodeReliablePos, pSegmentData, cbSegmentSize, usecNow ) )
			{
				if ( !BStateIsActive() )
					return false; 

				
				
				
				bInhibitMarkReceived = true;
			}

			
			nDecodeReliablePos += cbSegmentSize;

			
			
			if ( nCurMsgNum > 0 ) 
				++nCurMsgNum;
		}
		else if ( ( nFrameType & 0xfc ) == 0x80 )
		{
			
			
			

			int64 nOffset = 0;
			static const char szStopWaitingOffset[] = "stop_waiting offset";
			switch ( nFrameType & 3 )
			{
				case 0: READ_8BITU( nOffset, szStopWaitingOffset ); break;
				case 1: READ_16BITU( nOffset, szStopWaitingOffset ); break;
				case 2: READ_24BITU( nOffset, szStopWaitingOffset ); break;
				case 3: READ_64BITU( nOffset, szStopWaitingOffset ); break;
			}
			if ( nOffset >= nPktNum )
			{
				DECODE_ERROR( "stop_waiting pktNum %llu offset %llu", nPktNum, nOffset );
			}
			++nOffset;
			int64 nMinPktNumToSendAcks = nPktNum-nOffset;
			if ( nMinPktNumToSendAcks == m_receiverState.m_nMinPktNumToSendAcks )
				continue;
			if ( nMinPktNumToSendAcks < m_receiverState.m_nMinPktNumToSendAcks )
			{
				
				if ( nPktNum >= m_receiverState.m_nPktNumUpdatedMinPktNumToSendAcks )
				{
					DECODE_ERROR( "SNP stop waiting reduced %lld (pkt %lld) -> %lld (pkt %lld)", (long long)m_receiverState.m_nMinPktNumToSendAcks, (long long)m_receiverState.m_nPktNumUpdatedMinPktNumToSendAcks, (long long)nMinPktNumToSendAcks, (long long)nPktNum );




				}
				continue;
			}
			SpewDebugGroup( nLogLevelPacketDecode, "[%s]   decode pkt %lld stop waiting: %lld (was %lld)", GetDescription(), (long long)nPktNum, (long long)nMinPktNumToSendAcks, (long long)m_receiverState.m_nMinPktNumToSendAcks );


			m_receiverState.m_nMinPktNumToSendAcks = nMinPktNumToSendAcks;
			m_receiverState.m_nPktNumUpdatedMinPktNumToSendAcks = nPktNum;

			
			
			auto h = m_receiverState.m_mapPacketGaps.begin();
			while ( h->first <= m_receiverState.m_nMinPktNumToSendAcks )
			{
				if ( h->second.m_nEnd > m_receiverState.m_nMinPktNumToSendAcks )
				{
					
					
					
					const_cast<int64 &>( h->first ) = m_receiverState.m_nMinPktNumToSendAcks;
					break;
				}

				
				if ( m_receiverState.m_itPendingAck == h )
					++m_receiverState.m_itPendingAck;

				
				if ( m_receiverState.m_itPendingNack == h )
				{
					
					AssertMsg( false, "Expiring packet gap, which had pending NACK" );

					
					++m_receiverState.m_itPendingNack;
				}

				
				h = m_receiverState.m_mapPacketGaps.erase(h);
			}
		}
		else if ( ( nFrameType & 0xf0 ) == 0x90 )
		{

			
			
			

			#if STEAMNETWORKINGSOCKETS_SNP_PARANOIA > 0
				m_senderState.DebugCheckInFlightPacketMap();
				#if STEAMNETWORKINGSOCKETS_SNP_PARANOIA == 1
				if ( ( nPktNum & 255 ) == 0 ) 
				#endif
				{
					m_senderState.DebugCheckInFlightPacketMap();
				}
			#endif

			
			int64 nLatestRecvSeqNum;
			{
				static const char szAckLatestPktNum[] = "ack latest pktnum";
				int64 nLowerBits, nMask;
				if ( nFrameType & 0x40 )
				{
					READ_32BITU( nLowerBits, szAckLatestPktNum );
					nMask = 0xffffffff;
					nLatestRecvSeqNum = NearestWithSameLowerBits( (int32)nLowerBits, m_statsEndToEnd.m_nNextSendSequenceNumber );
				}
				else {
					READ_16BITU( nLowerBits, szAckLatestPktNum );
					nMask = 0xffff;
					nLatestRecvSeqNum = NearestWithSameLowerBits( (int16)nLowerBits, m_statsEndToEnd.m_nNextSendSequenceNumber );
				}
				Assert( ( nLatestRecvSeqNum & nMask ) == nLowerBits );

				
				if ( nLatestRecvSeqNum < 0 )
				{
					DECODE_ERROR( "SNP decode ack latest pktnum underflow.  %llx mod %llx, next send %llx", (unsigned long long)nLowerBits, (unsigned long long)( nMask+1 ), (unsigned long long)m_statsEndToEnd.m_nNextSendSequenceNumber );
				}
				if ( std::abs( nLatestRecvSeqNum - m_statsEndToEnd.m_nNextSendSequenceNumber ) > (nMask>>2) )
				{
					
					SpewWarningRateLimited( usecNow, "Sender sent abs latest recv pkt number using %llx mod %llx, next send %llx\n", (unsigned long long)nLowerBits, (unsigned long long)( nMask+1 ), (unsigned long long)m_statsEndToEnd.m_nNextSendSequenceNumber );
				}
				if ( nLatestRecvSeqNum >= m_statsEndToEnd.m_nNextSendSequenceNumber )
				{
					DECODE_ERROR( "SNP decode ack latest pktnum %lld (%llx mod %llx), but next outoing packet is %lld (%llx).", (long long)nLatestRecvSeqNum, (unsigned long long)nLowerBits, (unsigned long long)( nMask+1 ), (long long)m_statsEndToEnd.m_nNextSendSequenceNumber, (unsigned long long)m_statsEndToEnd.m_nNextSendSequenceNumber );


				}
			}

			SpewDebugGroup( nLogLevelPacketDecode, "[%s]   decode pkt %lld latest recv %lld\n", GetDescription(), (long long)nPktNum, (long long)nLatestRecvSeqNum );



			
			
			Assert( !m_senderState.m_mapInFlightPacketsByPktNum.empty() );
			auto inFlightPkt = m_senderState.m_mapInFlightPacketsByPktNum.upper_bound( nLatestRecvSeqNum );
			--inFlightPkt;
			Assert( inFlightPkt->first <= nLatestRecvSeqNum );

			
			{
				uint16 nPackedDelay;
				READ_16BITU( nPackedDelay, "ack delay" );
				if ( nPackedDelay != 0xffff && inFlightPkt->first == nLatestRecvSeqNum && inFlightPkt->second.m_pTransport == ctx.m_pTransport )
				{
					SteamNetworkingMicroseconds usecDelay = SteamNetworkingMicroseconds( nPackedDelay ) << k_nAckDelayPrecisionShift;
					SteamNetworkingMicroseconds usecElapsed = usecNow - inFlightPkt->second.m_usecWhenSent;
					Assert( usecElapsed >= 0 );

					
					int msPing = ( usecElapsed - usecDelay ) / 1000;

					
					
					
					
					
					
					
					
					if ( msPing < -1 || msPing > 2000 )
					{
						
						

						SpewMsgGroup( m_connectionConfig.m_LogLevel_AckRTT.Get(), "[%s] decode pkt %lld latest recv %lld delay %lluusec INVALID ping %lldusec\n", GetDescription(), (long long)nPktNum, (long long)nLatestRecvSeqNum, (unsigned long long)usecDelay, (long long)usecElapsed );




					}
					else {
						
						if ( msPing < 0 )
							msPing = 0;
						ProcessSNPPing( msPing, ctx );

						
						SpewVerboseGroup( m_connectionConfig.m_LogLevel_AckRTT.Get(), "[%s] decode pkt %lld latest recv %lld delay %.1fms elapsed %.1fms ping %dms\n", GetDescription(), (long long)nPktNum, (long long)nLatestRecvSeqNum, (float)(usecDelay * 1e-3 ), (float)(usecElapsed * 1e-3 ), msPing );





					}
				}
			}

			
			int nBlocks = nFrameType&7;
			if ( nBlocks == 7 )
				READ_8BITU( nBlocks, "ack num blocks" );

			
			
			
			if ( nBlocks > 0 )
			{
				
				
				
				
				
				SteamNetworkingMicroseconds usecDelay = 250*1000 / nBlocks;
				QueueFlushAllAcks( usecNow + usecDelay );
			}

			
			
			
			
			bool bAckedReliableRange = false;
			int64 nPktNumAckEnd = nLatestRecvSeqNum+1;
			while ( nBlocks >= 0 )
			{

				
				
				int64 nPktNumAckBegin, nPktNumNackBegin;
				if ( nBlocks == 0 )
				{
					
					
					if ( nPktNumAckEnd <= m_senderState.m_nMinPktWaitingOnAck )
						break;

					nPktNumAckBegin = m_senderState.m_nMinPktWaitingOnAck;
					nPktNumNackBegin = nPktNumAckBegin;
					SpewDebugGroup( nLogLevelPacketDecode, "[%s]   decode pkt %lld ack last block ack begin %lld\n", GetDescription(), (long long)nPktNum, (long long)nPktNumAckBegin );

				}
				else {
					uint8 nBlockHeader;
					READ_8BITU( nBlockHeader, "ack block header" );

					
					int64 numAcks = ( nBlockHeader>> 4 ) & 7;
					if ( nBlockHeader & 0x80 )
					{
						uint64 nUpperBits;
						READ_VARINT( nUpperBits, "ack count upper bits" );
						if ( nUpperBits > 100000 )
							DECODE_ERROR( "Ack count of %llu<<3 is crazy", (unsigned long long)nUpperBits );
						numAcks |= nUpperBits<<3;
					}
					nPktNumAckBegin = nPktNumAckEnd - numAcks;
					if ( nPktNumAckBegin < 0 )
						DECODE_ERROR( "Ack range underflow, end=%lld, num=%lld", (long long)nPktNumAckEnd, (long long)numAcks );

					
					int64 numNacks = nBlockHeader & 7;
					if ( nBlockHeader & 0x08)
					{
						uint64 nUpperBits;
						READ_VARINT( nUpperBits, "nack count upper bits" );
						if ( nUpperBits > 100000 )
							DECODE_ERROR( "Nack count of %llu<<3 is crazy", nUpperBits );
						numNacks |= nUpperBits<<3;
					}
					nPktNumNackBegin = nPktNumAckBegin - numNacks;
					if ( nPktNumNackBegin < 0 )
						DECODE_ERROR( "Nack range underflow, end=%lld, num=%lld", (long long)nPktNumAckBegin, (long long)numAcks );

					SpewDebugGroup( nLogLevelPacketDecode, "[%s]   decode pkt %lld nack [%lld,%lld) ack [%lld,%lld)\n", GetDescription(), (long long)nPktNum, (long long)nPktNumNackBegin, (long long)( nPktNumNackBegin + numNacks ), (long long)nPktNumAckBegin, (long long)( nPktNumAckBegin + numAcks )



					);
				}

				
				Assert( nPktNumAckBegin >= 0 );
				while ( inFlightPkt->first >= nPktNumAckBegin )
				{
					Assert( inFlightPkt->first < nPktNumAckEnd );

					
					for ( const SNPRange_t &relRange: inFlightPkt->second.m_vecReliableSegments )
					{

						
						if ( m_senderState.m_listInFlightReliableRange.erase( relRange ) == 0 )
						{
							if ( m_senderState.m_listReadyRetryReliableRange.erase( relRange ) > 0 )
							{

								
								
								m_senderState.m_cbPendingReliable -= int( relRange.length() );
								Assert( m_senderState.m_cbPendingReliable >= 0 );

								bAckedReliableRange = true;
							}
						}
						else {
							bAckedReliableRange = true;
							Assert( m_senderState.m_listReadyRetryReliableRange.count( relRange ) == 0 );
						}
					}

					
					
					if ( inFlightPkt == m_senderState.m_itNextInFlightPacketToTimeout )
						++m_senderState.m_itNextInFlightPacketToTimeout;

					
					inFlightPkt = m_senderState.m_mapInFlightPacketsByPktNum.erase( inFlightPkt );
					--inFlightPkt;
					m_senderState.MaybeCheckInFlightPacketMap();
				}

				
				if ( nPktNumAckBegin <= m_statsEndToEnd.m_pktNumInFlight && m_statsEndToEnd.m_pktNumInFlight < nPktNumAckEnd )
					m_statsEndToEnd.InFlightPktAck( usecNow );

				
				Assert( nPktNumNackBegin >= 0 );
				while ( inFlightPkt->first >= nPktNumNackBegin )
				{
					Assert( inFlightPkt->first < nPktNumAckEnd );
					SNP_SenderProcessPacketNack( inFlightPkt->first, inFlightPkt->second, "NACK" );

					
					--inFlightPkt;
				}

				
				nPktNumAckEnd = nPktNumNackBegin;
				--nBlocks;
			}

			
			
			if ( bAckedReliableRange )
			{
				m_senderState.RemoveAckedReliableMessageFromUnackedList();

				
				if ( nLogLevelPacketDecode >= k_ESteamNetworkingSocketsDebugOutputType_Debug )
				{

					int64 nPeerReliablePos = m_senderState.m_nReliableStreamPos;
					if ( !m_senderState.m_listInFlightReliableRange.empty() )
						nPeerReliablePos = std::min( nPeerReliablePos, m_senderState.m_listInFlightReliableRange.begin()->first.m_nBegin );
					if ( !m_senderState.m_listReadyRetryReliableRange.empty() )
						nPeerReliablePos = std::min( nPeerReliablePos, m_senderState.m_listReadyRetryReliableRange.begin()->first.m_nBegin );

					SpewDebugGroup( nLogLevelPacketDecode, "[%s]   decode pkt %lld peer reliable pos = %lld\n", GetDescription(), (long long)nPktNum, (long long)nPeerReliablePos );

				}
			}

			
			if ( nLatestRecvSeqNum > m_senderState.m_nMinPktWaitingOnAck )
			{
				SpewVerboseGroup( nLogLevelPacketDecode, "[%s]   updating min_waiting_on_ack %lld -> %lld\n", GetDescription(), (long long)m_senderState.m_nMinPktWaitingOnAck, (long long)nLatestRecvSeqNum );

				m_senderState.m_nMinPktWaitingOnAck = nLatestRecvSeqNum;
			}
		}
		else {
			DECODE_ERROR( "Invalid SNP frame lead byte 0x%02x", nFrameType );
		}
	}

	
	if ( bInhibitMarkReceived )
	{
		
		
		
		
		
		
		
	}
	else {

		
		
		bool bScheduleAck = nDecodeReliablePos > 0;
		SNP_RecordReceivedPktNum( nPktNum, usecNow, bScheduleAck );
	}

	
	
	
	
	
	
	
	m_statsEndToEnd.TrackProcessSequencedPacket( nPktNum, usecNow, usecTimeSinceLast );

	
	return true;

	
	#undef DECODE_ERROR
	#undef EXPECT_BYTES
	#undef READ_8BITU
	#undef READ_16BITU
	#undef READ_24BITU
	#undef READ_32BITU
	#undef READ_64BITU
	#undef READ_VARINT
	#undef READ_SEGMENT_DATA_SIZE
}

void CSteamNetworkConnectionBase::SNP_SenderProcessPacketNack( int64 nPktNum, SNPInFlightPacket_t &pkt, const char *pszDebug )
{

	
	if ( pkt.m_bNack )
		return;

	
	pkt.m_bNack = true;

	
	if ( m_statsEndToEnd.m_pktNumInFlight == nPktNum )
		m_statsEndToEnd.InFlightPktTimeout();

	
	for ( const SNPRange_t &relRange: pkt.m_vecReliableSegments )
	{

		
		auto inFlightRange = m_senderState.m_listInFlightReliableRange.find( relRange );
		if ( inFlightRange == m_senderState.m_listInFlightReliableRange.end() )
			continue;

		SpewMsgGroup( m_connectionConfig.m_LogLevel_PacketDecode.Get(), "[%s] pkt %lld %s, queueing retry of reliable range [%lld,%lld)\n",  GetDescription(), nPktNum, pszDebug, relRange.m_nBegin, relRange.m_nEnd );




		
		m_senderState.m_cbPendingReliable += int( relRange.length() );

		
		
		Assert( m_senderState.m_listReadyRetryReliableRange.count( relRange ) == 0 );
		m_senderState.m_listReadyRetryReliableRange[ inFlightRange->first ] = inFlightRange->second;
		m_senderState.m_listInFlightReliableRange.erase( inFlightRange );
	}
}

SteamNetworkingMicroseconds CSteamNetworkConnectionBase::SNP_SenderCheckInFlightPackets( SteamNetworkingMicroseconds usecNow )
{
	
	m_senderState.MaybeCheckInFlightPacketMap();
	if ( m_senderState.m_mapInFlightPacketsByPktNum.size() <= 1 )
	{
		Assert( m_senderState.m_itNextInFlightPacketToTimeout == m_senderState.m_mapInFlightPacketsByPktNum.end() );
		return k_nThinkTime_Never;
	}
	Assert( m_senderState.m_mapInFlightPacketsByPktNum.begin()->first < 0 );

	SteamNetworkingMicroseconds usecNextRetry = k_nThinkTime_Never;

	
	
	
	SteamNetworkingMicroseconds usecRTO = m_statsEndToEnd.CalcSenderRetryTimeout();
	while ( m_senderState.m_itNextInFlightPacketToTimeout != m_senderState.m_mapInFlightPacketsByPktNum.end() )
	{
		Assert( m_senderState.m_itNextInFlightPacketToTimeout->first > 0 );

		
		if ( !m_senderState.m_itNextInFlightPacketToTimeout->second.m_bNack )
		{

			
			SteamNetworkingMicroseconds usecRetryPkt = m_senderState.m_itNextInFlightPacketToTimeout->second.m_usecWhenSent + usecRTO;
			if ( usecRetryPkt > usecNow )
			{
				usecNextRetry = usecRetryPkt;
				break;
			}

			
			
			SNP_SenderProcessPacketNack( m_senderState.m_itNextInFlightPacketToTimeout->first, m_senderState.m_itNextInFlightPacketToTimeout->second, "AckTimeout" );
		}

		
		++m_senderState.m_itNextInFlightPacketToTimeout;
	}

	
	auto inFlightPkt = m_senderState.m_mapInFlightPacketsByPktNum.begin();
	Assert( inFlightPkt->first < 0 );
	++inFlightPkt;

	
	SteamNetworkingMicroseconds usecWhenExpiry = usecNow - usecRTO*2;
	for (;;)
	{
		if ( inFlightPkt->second.m_usecWhenSent > usecWhenExpiry )
			break;

		
		Assert( inFlightPkt->second.m_bNack );
		Assert( inFlightPkt != m_senderState.m_itNextInFlightPacketToTimeout );

		
		inFlightPkt = m_senderState.m_mapInFlightPacketsByPktNum.erase( inFlightPkt );
		Assert( !m_senderState.m_mapInFlightPacketsByPktNum.empty() );

		
		if ( inFlightPkt == m_senderState.m_mapInFlightPacketsByPktNum.end() )
			break;
	}

	
	m_senderState.MaybeCheckInFlightPacketMap();

	
	
	
	
	
	
	return usecNextRetry;
}

struct EncodedSegment {
	static constexpr int k_cbMaxHdr = 16; 
	uint8 m_hdr[ k_cbMaxHdr ];
	int m_cbHdr; 
	CSteamNetworkingMessage *m_pMsg;
	int m_cbSegSize;
	int m_nOffset;

	inline void SetupReliable( CSteamNetworkingMessage *pMsg, int64 nBegin, int64 nEnd, int64 nLastReliableStreamPosEnd )
	{
		Assert( nBegin < nEnd );
		
		Assert( pMsg->SNPSend_IsReliable() );

		
		
		uint8 *pHdr = m_hdr;
		*(pHdr++) = 0x40;

		
		if ( nLastReliableStreamPosEnd == 0 )
		{
			
			
			m_hdr[0] |= 0x10;
			*(uint16*)pHdr = LittleWord( uint16( nBegin ) ); pHdr += 2;
			*(uint32*)pHdr = LittleDWord( uint32( nBegin>>16 ) ); pHdr += 4;
		}
		else {
			
			Assert( nBegin >= nLastReliableStreamPosEnd );
			int64 nOffset = nBegin - nLastReliableStreamPosEnd;
			if ( nOffset == 0)
			{
				
			}
			else if ( nOffset < 0x100 )
			{
				m_hdr[0] |= (1<<3);
				*pHdr = uint8( nOffset ); pHdr += 1;
			}
			else if ( nOffset < 0x10000 )
			{
				m_hdr[0] |= (2<<3);
				*(uint16*)pHdr = LittleWord( uint16( nOffset ) ); pHdr += 2;
			}
			else {
				m_hdr[0] |= (3<<3);
				*(uint32*)pHdr = LittleDWord( uint32( nOffset ) ); pHdr += 4;
			}
		}

		m_cbHdr = pHdr-m_hdr;

		
		
		int cbSegData = nEnd - nBegin;
		Assert( cbSegData > 0 );
		Assert( nBegin >= pMsg->SNPSend_ReliableStreamPos() );
		Assert( nEnd <= pMsg->SNPSend_ReliableStreamPos() + pMsg->m_cbSize );

		m_pMsg = pMsg;
		m_nOffset = nBegin - pMsg->SNPSend_ReliableStreamPos();
		m_cbSegSize = cbSegData;
	}

	inline void SetupUnreliable( CSteamNetworkingMessage *pMsg, int nOffset, int64 nLastMsgNum )
	{

		
		
		uint8 *pHdr = m_hdr;
		*(pHdr++) = 0x00;

		
		if ( nLastMsgNum == 0 )
		{

			
			
			*(uint32*)pHdr = LittleDWord( (uint32)pMsg->m_nMessageNumber ); pHdr += 4;
			m_hdr[0] |= 0x10;
		}
		else {
			
			Assert( pMsg->m_nMessageNumber > nLastMsgNum );
			uint64 nDelta = pMsg->m_nMessageNumber - nLastMsgNum;
			if ( nDelta == 1 )
			{
				
			}
			else {
				pHdr = SerializeVarInt( pHdr, nDelta, m_hdr+k_cbMaxHdr );
				Assert( pHdr ); 
				m_hdr[0] |= 0x10;
			}
		}

		
		if ( nOffset > 0 )
		{
			pHdr = SerializeVarInt( pHdr, (uint32)( nOffset ), m_hdr+k_cbMaxHdr );
			Assert( pHdr ); 
			m_hdr[0] |= 0x08;
		}

		m_cbHdr = pHdr-m_hdr;

		
		int cbSegData = pMsg->m_cbSize - nOffset;
		Assert( cbSegData > 0 || ( cbSegData == 0 && pMsg->m_cbSize == 0 ) ); 

		m_pMsg = pMsg;
		m_cbSegSize = cbSegData;
		m_nOffset = nOffset;
	}

};

template <typename T, typename L> inline bool HasOverlappingRange( const SNPRange_t &range, const std::map<SNPRange_t,T,L> &map )
{
	auto l = map.lower_bound( range );
	if ( l != map.end() )
	{
		Assert( l->first.m_nBegin >= range.m_nBegin );
		if ( l->first.m_nBegin < range.m_nEnd )
			return true;
	}
	auto u = map.upper_bound( range );
	if ( u != map.end() )
	{
		Assert( range.m_nBegin < u->first.m_nBegin );
		if ( range.m_nEnd > l->first.m_nBegin )
			return true;
	}

	return false;
}

bool CSteamNetworkConnectionBase::SNP_SendPacket( CConnectionTransport *pTransport, SendPacketContext_t &ctx )
{
	
	if ( !BStateIsActive() || m_senderState.m_mapInFlightPacketsByPktNum.empty() || !pTransport )
	{
		Assert( BStateIsActive() );
		Assert( !m_senderState.m_mapInFlightPacketsByPktNum.empty() );
		Assert( pTransport );
		return false;
	}

	SteamNetworkingMicroseconds usecNow = ctx.m_usecNow;

	
	
	
	int cbMaxPlaintextPayload = std::max( 0, ctx.m_cbMaxEncryptedPayload-k_cbSteamNetwokingSocketsEncrytionTagSize );
	cbMaxPlaintextPayload = std::min( cbMaxPlaintextPayload, m_cbMaxPlaintextPayloadSend );

	uint8 payload[ k_cbSteamNetworkingSocketsMaxPlaintextPayloadSend ];
	uint8 *pPayloadEnd = payload + cbMaxPlaintextPayload;
	uint8 *pPayloadPtr = payload;

	int nLogLevelPacketDecode = m_connectionConfig.m_LogLevel_PacketDecode.Get();
	SpewVerboseGroup( nLogLevelPacketDecode, "[%s] encode pkt %lld", GetDescription(), (long long)m_statsEndToEnd.m_nNextSendSequenceNumber );


	
	pPayloadPtr = SNP_SerializeStopWaitingFrame( pPayloadPtr, pPayloadEnd, usecNow );
	if ( pPayloadPtr == nullptr )
		return false;

	
	
	SNPAckSerializerHelper ackHelper;
	SNP_GatherAckBlocks( ackHelper, usecNow );

	#ifdef SNP_ENABLE_PACKETSENDLOG
		PacketSendLog *pLog = push_back_get_ptr( m_vecSendLog );
		pLog->m_usecTime = usecNow;
		pLog->m_cbPendingReliable = m_senderState.m_cbPendingReliable;
		pLog->m_cbPendingUnreliable = m_senderState.m_cbPendingUnreliable;
		pLog->m_nPacketGaps = len( m_receiverState.m_mapPacketGaps )-1;
		pLog->m_nAckBlocksNeeded = ackHelper.m_nBlocksNeedToAck;
		pLog->m_nPktNumNextPendingAck = m_receiverState.m_itPendingAck->first;
		pLog->m_usecNextPendingAckTime = m_receiverState.m_itPendingAck->second.m_usecWhenAckPrior;
		pLog->m_fltokens = m_senderState.m_flTokenBucket;
		pLog->m_nMaxPktRecv = m_statsEndToEnd.m_nMaxRecvPktNum;
		pLog->m_nMinPktNumToSendAcks = m_receiverState.m_nMinPktNumToSendAcks;
		pLog->m_nReliableSegmentsRetry = 0;
		pLog->m_nSegmentsSent = 0;
	#endif

	
	int cbReserveForAcks = 0;
	if ( m_statsEndToEnd.m_nMaxRecvPktNum > 0 )
	{
		int cbPayloadRemainingForAcks = pPayloadEnd - pPayloadPtr;
		if ( cbPayloadRemainingForAcks >= SNPAckSerializerHelper::k_cbHeaderSize )
		{
			cbReserveForAcks = SNPAckSerializerHelper::k_cbHeaderSize;
			int n = 3; 
			n = std::max( n, ackHelper.m_nBlocksNeedToAck ); 
			n = std::min( n, ackHelper.m_nBlocks ); 
			while ( n > 0 )
			{
				--n;
				if ( ackHelper.m_arBlocks[n].m_cbTotalEncodedSize <= cbPayloadRemainingForAcks )
				{
					cbReserveForAcks = ackHelper.m_arBlocks[n].m_cbTotalEncodedSize;
					break;
				}
			}
		}
	}

	
	if ( m_senderState.m_flTokenBucket < 0.0 || !BStateIsConnectedForWirePurposes()

		|| pTransport != m_pTransport  ) {

		
		if ( cbReserveForAcks > 0 )
		{
			
			
			pPayloadPtr = SNP_SerializeAckBlocks( ackHelper, pPayloadPtr, pPayloadEnd, usecNow );
			if ( pPayloadPtr == nullptr )
				return false; 

			
			cbReserveForAcks = 0;
		}

		
		
		
		pPayloadEnd = pPayloadPtr;
	}

	int64 nLastReliableStreamPosEnd = 0;
	int cbBytesRemainingForSegments = pPayloadEnd - pPayloadPtr - cbReserveForAcks;
	vstd::small_vector<EncodedSegment,8> vecSegments;

	
	
	while ( !m_senderState.m_listReadyRetryReliableRange.empty() && cbBytesRemainingForSegments > 2 )
	{
		auto h = m_senderState.m_listReadyRetryReliableRange.begin();

		
		EncodedSegment &seg = *push_back_get_ptr( vecSegments );
		seg.SetupReliable( h->second, h->first.m_nBegin, h->first.m_nEnd, nLastReliableStreamPosEnd );
		int cbSegTotalWithoutSizeField = seg.m_cbHdr + seg.m_cbSegSize;
		if ( cbSegTotalWithoutSizeField > cbBytesRemainingForSegments )
		{
			
			vecSegments.pop_back();

			
			
			
			
			
			
			

			
			
			
			
			
			AssertMsg2( nLastReliableStreamPosEnd > 0 || cbMaxPlaintextPayload < m_cbMaxPlaintextPayloadSend || ( cbReserveForAcks > 15 && ackHelper.m_nBlocksNeedToAck > 8 ), "We cannot fit reliable segment, need %d bytes, only %d remaining", cbSegTotalWithoutSizeField, cbBytesRemainingForSegments );





			
			
			
			
			break;
		}

		
		cbBytesRemainingForSegments -= cbSegTotalWithoutSizeField;
		nLastReliableStreamPosEnd = h->first.m_nEnd;

		
		
		
		
		cbBytesRemainingForSegments -= 1;

		
		m_senderState.m_listReadyRetryReliableRange.erase( h );

		#ifdef SNP_ENABLE_PACKETSENDLOG
			++pLog->m_nReliableSegmentsRetry;
		#endif
	}

	
	
	if ( m_senderState.m_listReadyRetryReliableRange.empty() )
	{

		
		int64 nLastMsgNum = 0;
		while ( cbBytesRemainingForSegments > 4 )
		{
			if ( m_senderState.m_messagesQueued.empty() )
			{
				m_senderState.m_cbCurrentSendMessageSent = 0;
				break;
			}
			CSteamNetworkingMessage *pSendMsg = m_senderState.m_messagesQueued.m_pFirst;
			Assert( m_senderState.m_cbCurrentSendMessageSent < pSendMsg->m_cbSize );

			
			EncodedSegment &seg = *push_back_get_ptr( vecSegments );

			
			bool bLastSegment = false;
			if ( pSendMsg->SNPSend_IsReliable() )
			{

				

				int64 nBegin = pSendMsg->SNPSend_ReliableStreamPos() + m_senderState.m_cbCurrentSendMessageSent;

				
				
				
				
				
				int cbDesiredSegSize = pSendMsg->m_cbSize - m_senderState.m_cbCurrentSendMessageSent;
				if ( cbDesiredSegSize > m_cbMaxReliableMessageSegment )
				{
					cbDesiredSegSize = m_cbMaxReliableMessageSegment;
					bLastSegment = true;
				}

				int64 nEnd = nBegin + cbDesiredSegSize;
				seg.SetupReliable( pSendMsg, nBegin, nEnd, nLastReliableStreamPosEnd );

				
				nLastReliableStreamPosEnd = nEnd;
			}
			else {
				seg.SetupUnreliable( pSendMsg, m_senderState.m_cbCurrentSendMessageSent, nLastMsgNum );
			}

			
			if ( bLastSegment || seg.m_cbHdr + seg.m_cbSegSize > cbBytesRemainingForSegments )
			{

				
				
				
				
				
				
				int cbMinSegDataSizeToSend = std::min( 16, seg.m_cbSegSize );
				if ( seg.m_cbHdr + cbMinSegDataSizeToSend > cbBytesRemainingForSegments )
				{
					
					vecSegments.pop_back();
					break;
				}

				#ifdef SNP_ENABLE_PACKETSENDLOG
					++pLog->m_nSegmentsSent;
				#endif

				
				seg.m_cbSegSize = std::min( seg.m_cbSegSize, cbBytesRemainingForSegments - seg.m_cbHdr );
				m_senderState.m_cbCurrentSendMessageSent += seg.m_cbSegSize;
				Assert( m_senderState.m_cbCurrentSendMessageSent < pSendMsg->m_cbSize );
				cbBytesRemainingForSegments -= seg.m_cbHdr + seg.m_cbSegSize;
				break;
			}

			
			
			Assert( m_senderState.m_cbCurrentSendMessageSent + seg.m_cbSegSize == pSendMsg->m_cbSize );
			m_senderState.m_cbCurrentSendMessageSent = 0;

			
			
			m_senderState.m_messagesQueued.pop_front();

			
			cbBytesRemainingForSegments -= seg.m_cbHdr + seg.m_cbSegSize;

			
			
			
			cbBytesRemainingForSegments -= 1;

			
			if ( pSendMsg->SNPSend_IsReliable() )
			{
				
				
				if ( nLastMsgNum > 0 )
					++nLastMsgNum;

				
				m_senderState.m_unackedReliableMessages.push_back( seg.m_pMsg );
			}
			else {
				nLastMsgNum = pSendMsg->m_nMessageNumber;

				
				seg.m_hdr[0] |= 0x20;
			}
		}
	}

	
	
	
	
	
	if ( cbReserveForAcks > 0 )
	{

		
		int cbAvailForAcks = cbReserveForAcks;
		if ( cbBytesRemainingForSegments > 0 )
			cbAvailForAcks += cbBytesRemainingForSegments;
		uint8 *pAckEnd = pPayloadPtr + cbAvailForAcks;
		Assert( pAckEnd <= pPayloadEnd );

		uint8 *pAfterAcks = SNP_SerializeAckBlocks( ackHelper, pPayloadPtr, pAckEnd, usecNow );
		if ( pAfterAcks == nullptr )
			return false; 

		int cbAckBytesWritten = pAfterAcks - pPayloadPtr;
		if ( cbAckBytesWritten > cbReserveForAcks )
		{
			
			
			cbBytesRemainingForSegments -= ( cbAckBytesWritten - cbReserveForAcks );
			Assert( cbBytesRemainingForSegments >= -1 ); 
		}
		else {
			Assert( cbAckBytesWritten == cbReserveForAcks ); 
		}

		pPayloadPtr = pAfterAcks;
	}

	
	
	Assert( m_senderState.m_mapInFlightPacketsByPktNum.lower_bound( m_statsEndToEnd.m_nNextSendSequenceNumber ) == m_senderState.m_mapInFlightPacketsByPktNum.end() );
	std::pair<int64,SNPInFlightPacket_t> pairInsert( m_statsEndToEnd.m_nNextSendSequenceNumber, SNPInFlightPacket_t{ usecNow, false, pTransport, {} } );
	SNPInFlightPacket_t &inFlightPkt = pairInsert.second;

	
	
	Assert( cbBytesRemainingForSegments >= 0 || ( cbBytesRemainingForSegments == -1 && vecSegments.size() > 0 ) );

	
	int nSegments = len( vecSegments );
	for ( int idx = 0 ; idx < nSegments ; ++idx )
	{
		EncodedSegment &seg = vecSegments[ idx ];

		
		bool bStillInQueue = ( seg.m_pMsg == m_senderState.m_messagesQueued.m_pFirst );

		
		if ( idx < nSegments-1 )
		{
			
			int nUpper3Bits = ( seg.m_cbSegSize>>8 );
			Assert( nUpper3Bits <= 4 ); 
			seg.m_hdr[0] |= nUpper3Bits;

			
			seg.m_hdr[ seg.m_cbHdr++ ] = uint8( seg.m_cbSegSize );
		}
		else {
			
			seg.m_hdr[0] |= 7;
		}

		
		Assert( seg.m_cbHdr <= seg.k_cbMaxHdr );

		
		memcpy( pPayloadPtr, seg.m_hdr, seg.m_cbHdr ); pPayloadPtr += seg.m_cbHdr;
		Assert( pPayloadPtr+seg.m_cbSegSize <= pPayloadEnd );

		
		if ( seg.m_pMsg->SNPSend_IsReliable() )
		{
			
			
			Assert( seg.m_cbSegSize > 0 );

			
			
			if ( seg.m_nOffset < seg.m_pMsg->m_cbSNPSendReliableHeader )
			{
				int cbCopyHdr = std::min( seg.m_cbSegSize, seg.m_pMsg->m_cbSNPSendReliableHeader - seg.m_nOffset );

				memcpy( pPayloadPtr, seg.m_pMsg->SNPSend_ReliableHeader() + seg.m_nOffset, cbCopyHdr );
				pPayloadPtr += cbCopyHdr;

				int cbCopyBody = seg.m_cbSegSize - cbCopyHdr;
				if ( cbCopyBody > 0 )
				{
					memcpy( pPayloadPtr, seg.m_pMsg->m_pData, cbCopyBody );
					pPayloadPtr += cbCopyBody;
				}
			}
			else {
				
				memcpy( pPayloadPtr, (char*)seg.m_pMsg->m_pData + seg.m_nOffset - seg.m_pMsg->m_cbSNPSendReliableHeader, seg.m_cbSegSize );
				pPayloadPtr += seg.m_cbSegSize;
			}


			
			SNPRange_t range;
			range.m_nBegin = seg.m_pMsg->SNPSend_ReliableStreamPos() + seg.m_nOffset;
			range.m_nEnd = range.m_nBegin + seg.m_cbSegSize;

			
			
			
			Assert( !HasOverlappingRange( range, m_senderState.m_listInFlightReliableRange ) );
			Assert( !HasOverlappingRange( range, m_senderState.m_listReadyRetryReliableRange ) );

			
			SpewDebugGroup( nLogLevelPacketDecode, "[%s]   encode pkt %lld reliable msg %lld offset %d+%d=%d range [%lld,%lld)\n", GetDescription(), (long long)m_statsEndToEnd.m_nNextSendSequenceNumber, (long long)seg.m_pMsg->m_nMessageNumber, seg.m_nOffset, seg.m_cbSegSize, seg.m_nOffset+seg.m_cbSegSize, (long long)range.m_nBegin, (long long)range.m_nEnd );



			
			m_senderState.m_listInFlightReliableRange[ range ] = seg.m_pMsg;

			
			inFlightPkt.m_vecReliableSegments.push_back( range );

			
			m_senderState.m_cbPendingReliable -= seg.m_cbSegSize;
			Assert( m_senderState.m_cbPendingReliable >= 0 );
		}
		else {
			
			Assert( seg.m_cbSegSize > 0 || ( seg.m_cbSegSize == 0 && seg.m_pMsg->m_cbSize == 0 ) );

			
			Assert( bStillInQueue == ( seg.m_nOffset + seg.m_cbSegSize < seg.m_pMsg->m_cbSize ) ); 
			Assert( bStillInQueue == ( ( seg.m_hdr[0] & 0x20 ) == 0 ) );
			Assert( bStillInQueue || seg.m_pMsg->m_links.m_pNext == nullptr ); 
			Assert( seg.m_pMsg->m_links.m_pPrev == nullptr ); 

			
			memcpy( pPayloadPtr, (char*)seg.m_pMsg->m_pData + seg.m_nOffset, seg.m_cbSegSize );
			pPayloadPtr += seg.m_cbSegSize;

			
			SpewDebugGroup( nLogLevelPacketDecode, "[%s]   encode pkt %lld unreliable msg %lld offset %d+%d=%d\n", GetDescription(), (long long)m_statsEndToEnd.m_nNextSendSequenceNumber, (long long)seg.m_pMsg->m_nMessageNumber, seg.m_nOffset, seg.m_cbSegSize, seg.m_nOffset+seg.m_cbSegSize );


			
			m_senderState.m_cbPendingUnreliable -= seg.m_cbSegSize;
			Assert( m_senderState.m_cbPendingUnreliable >= 0 );

			
			if ( !bStillInQueue )
				seg.m_pMsg->Release();
		}
	}

	
	Assert( pPayloadPtr <= pPayloadEnd );
	int cbPlainText = pPayloadPtr - payload;
	if ( cbPlainText > cbMaxPlaintextPayload )
	{
		AssertMsg1( false, "Payload exceeded max size of %d\n", cbMaxPlaintextPayload );
		return 0;
	}

	
	
	int nBytesSent = 0;
	switch ( m_eNegotiatedCipher )
	{
		default:
			AssertMsg1( false, "Bogus cipher %d", m_eNegotiatedCipher );
			break;

		case k_ESteamNetworkingSocketsCipher_NULL:
		{

			
			
			nBytesSent = pTransport->SendEncryptedDataChunk( payload, cbPlainText, ctx );
		}
		break;

		case k_ESteamNetworkingSocketsCipher_AES_256_GCM:
		{

			Assert( m_bCryptKeysValid );

			
			*(uint64 *)&m_cryptIVSend.m_buf += LittleQWord( m_statsEndToEnd.m_nNextSendSequenceNumber );

			
			uint8 arEncryptedChunk[ k_cbSteamNetworkingSocketsMaxEncryptedPayloadSend + 64 ]; 
			uint32 cbEncrypted = sizeof(arEncryptedChunk);
			DbgVerify( m_cryptContextSend.Encrypt( payload, cbPlainText, m_cryptIVSend.m_buf, arEncryptedChunk, &cbEncrypted, nullptr, 0 ) );





			
			
			
			
			
			

			
			*(uint64 *)&m_cryptIVSend.m_buf -= LittleQWord( m_statsEndToEnd.m_nNextSendSequenceNumber );

			Assert( (int)cbEncrypted >= cbPlainText );
			Assert( (int)cbEncrypted <= k_cbSteamNetworkingSocketsMaxEncryptedPayloadSend ); 

			
			nBytesSent = pTransport->SendEncryptedDataChunk( arEncryptedChunk, cbEncrypted, ctx );
		}
	}
	if ( nBytesSent <= 0 )
		return false;

	
	auto pairInsertResult = m_senderState.m_mapInFlightPacketsByPktNum.insert( pairInsert );
	Assert( pairInsertResult.second ); 

	
	if ( !inFlightPkt.m_vecReliableSegments.empty() )
	{
		m_statsEndToEnd.TrackSentMessageExpectingSeqNumAck( usecNow, true );
		
	}

	
	if ( m_senderState.m_itNextInFlightPacketToTimeout == m_senderState.m_mapInFlightPacketsByPktNum.end() )
		m_senderState.m_itNextInFlightPacketToTimeout = pairInsertResult.first;

	#ifdef SNP_ENABLE_PACKETSENDLOG
		pLog->m_cbSent = nBytesSent;
	#endif

	
	m_senderState.m_flTokenBucket -= (float)nBytesSent;
	return true;
}

void CSteamNetworkConnectionBase::SNP_SentNonDataPacket( CConnectionTransport *pTransport, SteamNetworkingMicroseconds usecNow )
{
	std::pair<int64,SNPInFlightPacket_t> pairInsert( m_statsEndToEnd.m_nNextSendSequenceNumber-1, SNPInFlightPacket_t{ usecNow, false, pTransport, {} } );
	auto pairInsertResult = m_senderState.m_mapInFlightPacketsByPktNum.insert( pairInsert );
	Assert( pairInsertResult.second ); 
}

void CSteamNetworkConnectionBase::SNP_GatherAckBlocks( SNPAckSerializerHelper &helper, SteamNetworkingMicroseconds usecNow )
{
	helper.m_nBlocks = 0;
	helper.m_nBlocksNeedToAck = 0;

	
	int n = len( m_receiverState.m_mapPacketGaps ) - 1;
	if ( n <= 0 )
		return;

	
	
	
	SteamNetworkingMicroseconds usecSendAcksDueBefore = usecNow;
	SteamNetworkingMicroseconds usecTimeUntilNextPacket = SteamNetworkingMicroseconds( ( m_senderState.m_flTokenBucket - (float)m_cbMTUPacketSize ) / (float)m_senderState.m_n_x * -1e6 );
	if ( usecTimeUntilNextPacket > 0 )
		usecSendAcksDueBefore += usecTimeUntilNextPacket;

	m_receiverState.DebugCheckPackGapMap();

	n = std::min( (int)helper.k_nMaxBlocks, n );
	auto itNext = m_receiverState.m_mapPacketGaps.begin();

	int cbEncodedSize = helper.k_cbHeaderSize;
	while ( n > 0 )
	{
		--n;
		auto itCur = itNext;
		++itNext;

		Assert( itCur->first < itCur->second.m_nEnd );

		
		bool bNeedToReport = ( itNext->second.m_usecWhenAckPrior <= usecSendAcksDueBefore );

		
		if ( itCur == m_receiverState.m_itPendingNack )
		{

			
			if ( !bNeedToReport )
			{
				if ( usecNow < itCur->second.m_usecWhenOKToNack )
					break;
				bNeedToReport = true;
			}

			
			
			++m_receiverState.m_itPendingNack;
		}

		SNPAckSerializerHelper::Block &block = helper.m_arBlocks[ helper.m_nBlocks ];
		block.m_nNack = uint32( itCur->second.m_nEnd - itCur->first );

		int64 nAckEnd;
		SteamNetworkingMicroseconds usecWhenSentLast;
		if ( n == 0 )
		{
			
			Assert( itNext->first == INT64_MAX );
			nAckEnd = m_statsEndToEnd.m_nMaxRecvPktNum+1;
			usecWhenSentLast = m_statsEndToEnd.m_usecTimeLastRecvSeq;
		}
		else {
			nAckEnd = itNext->first;
			usecWhenSentLast = itNext->second.m_usecWhenReceivedPktBefore;
		}
		Assert( itCur->second.m_nEnd < nAckEnd );
		block.m_nAck = uint32( nAckEnd - itCur->second.m_nEnd );

		block.m_nLatestPktNum = uint32( nAckEnd-1 );
		block.m_nEncodedTimeSinceLatestPktNum = SNPAckSerializerHelper::EncodeTimeSince( usecNow, usecWhenSentLast );

		
		
		if ( helper.m_nBlocks == 6 )
			++cbEncodedSize;

		
		++cbEncodedSize;
		if ( block.m_nAck > 7 )
			cbEncodedSize += VarIntSerializedSize( block.m_nAck>>3 );
		if ( block.m_nNack > 7 )
			cbEncodedSize += VarIntSerializedSize( block.m_nNack>>3 );
		block.m_cbTotalEncodedSize = cbEncodedSize;

		
		
		

		++helper.m_nBlocks;

		
		if ( bNeedToReport )
			helper.m_nBlocksNeedToAck = helper.m_nBlocks;
	}
}

uint8 *CSteamNetworkConnectionBase::SNP_SerializeAckBlocks( const SNPAckSerializerHelper &helper, uint8 *pOut, const uint8 *pOutEnd, SteamNetworkingMicroseconds usecNow )
{

	
	Assert( m_statsEndToEnd.m_nMaxRecvPktNum > 0 );

	
	if ( pOut + SNPAckSerializerHelper::k_cbHeaderSize > pOutEnd )
		return pOut;

	
	
	COMPILE_TIME_ASSERT( SNPAckSerializerHelper::k_cbHeaderSize == 5 );
	uint8 *pAckHeaderByte = pOut;
	++pOut;
	uint16 *pLatestPktNum = (uint16 *)pOut;
	pOut += 2;
	uint16 *pTimeSinceLatestPktNum = (uint16 *)pOut;
	pOut += 2;

	
	*pAckHeaderByte = 0x98;

	int nLogLevelPacketDecode = m_connectionConfig.m_LogLevel_PacketDecode.Get();

	#ifdef SNP_ENABLE_PACKETSENDLOG
		PacketSendLog *pLog = &m_vecSendLog[ m_vecSendLog.size()-1 ];
	#endif

	
	if ( m_receiverState.m_mapPacketGaps.size() == 1 )
	{
		int64 nLastRecvPktNum = m_statsEndToEnd.m_nMaxRecvPktNum;
		*pLatestPktNum = LittleWord( (uint16)nLastRecvPktNum );
		*pTimeSinceLatestPktNum = LittleWord( (uint16)SNPAckSerializerHelper::EncodeTimeSince( usecNow, m_statsEndToEnd.m_usecTimeLastRecvSeq ) );

		SpewDebugGroup( nLogLevelPacketDecode, "[%s]   encode pkt %lld last recv %lld (no loss)\n", GetDescription(), (long long)m_statsEndToEnd.m_nNextSendSequenceNumber, (long long)nLastRecvPktNum );


		m_receiverState.m_mapPacketGaps.rbegin()->second.m_usecWhenAckPrior = INT64_MAX; 

		#ifdef SNP_ENABLE_PACKETSENDLOG
			pLog->m_nAckBlocksSent = 0;
			pLog->m_nAckEnd = nLastRecvPktNum;
		#endif

		return pOut;
	}

	
	
	
	int nBlocks = helper.m_nBlocks;
	uint8 *pExpectedOutEnd;
	for (;;)
	{

		
		
		if ( nBlocks == 0 )
		{
			auto itOldestGap = m_receiverState.m_mapPacketGaps.begin();
			int64 nLastRecvPktNum = itOldestGap->first-1;
			*pLatestPktNum = LittleWord( uint16( nLastRecvPktNum ) );
			*pTimeSinceLatestPktNum = LittleWord( (uint16)SNPAckSerializerHelper::EncodeTimeSince( usecNow, itOldestGap->second.m_usecWhenReceivedPktBefore ) );

			SpewDebugGroup( nLogLevelPacketDecode, "[%s]   encode pkt %lld last recv %lld (no blocks, actual last recv=%lld)\n", GetDescription(), (long long)m_statsEndToEnd.m_nNextSendSequenceNumber, (long long)nLastRecvPktNum, (long long)m_statsEndToEnd.m_nMaxRecvPktNum );



			#ifdef SNP_ENABLE_PACKETSENDLOG
				pLog->m_nAckBlocksSent = 0;
				pLog->m_nAckEnd = nLastRecvPktNum;
			#endif

			
			if ( itOldestGap == m_receiverState.m_itPendingAck )
			{
				
				m_receiverState.m_itPendingAck->second.m_usecWhenAckPrior = INT64_MAX;
				++m_receiverState.m_itPendingAck;
			}

			
			return pOut;
		}

		int cbTotalEncoded = helper.m_arBlocks[nBlocks-1].m_cbTotalEncodedSize;
		pExpectedOutEnd = pAckHeaderByte + cbTotalEncoded; 
		if ( pExpectedOutEnd <= pOutEnd )
			break;

		
		--nBlocks;
	}

	
	Assert( nBlocks == uint8(nBlocks) );
	if ( nBlocks > 6 )
	{
		*pAckHeaderByte |= 7;
		*(pOut++) = uint8( nBlocks );
	}
	else {
		*pAckHeaderByte |= uint8( nBlocks );
	}

	
	
	const SNPAckSerializerHelper::Block *pBlock = &helper.m_arBlocks[nBlocks-1];

	
	*pLatestPktNum = LittleWord( uint16( pBlock->m_nLatestPktNum ) );
	*pTimeSinceLatestPktNum = LittleWord( pBlock->m_nEncodedTimeSinceLatestPktNum );

	
	int64 nAckEnd = ( m_statsEndToEnd.m_nMaxRecvPktNum & ~(int64)(~(uint32)0) ) | pBlock->m_nLatestPktNum;
	++nAckEnd;

	#ifdef SNP_ENABLE_PACKETSENDLOG
		pLog->m_nAckBlocksSent = nBlocks;
		pLog->m_nAckEnd = nAckEnd;
	#endif

	SpewDebugGroup( nLogLevelPacketDecode, "[%s]   encode pkt %lld last recv %lld (%d blocks, actual last recv=%lld)\n", GetDescription(), (long long)m_statsEndToEnd.m_nNextSendSequenceNumber, (long long)(nAckEnd-1), nBlocks, (long long)m_statsEndToEnd.m_nMaxRecvPktNum );



	
	if ( nAckEnd > m_statsEndToEnd.m_nMaxRecvPktNum )
	{
		Assert( nAckEnd == m_statsEndToEnd.m_nMaxRecvPktNum+1 );
		for (;;)
		{
			m_receiverState.m_itPendingAck->second.m_usecWhenAckPrior = INT64_MAX;
			if ( m_receiverState.m_itPendingAck->first == INT64_MAX )
				break;
			++m_receiverState.m_itPendingAck;
		}
		m_receiverState.m_itPendingNack = m_receiverState.m_itPendingAck;
	}
	else {

		
		
		if ( m_receiverState.m_itPendingAck->first <= nAckEnd )
		{
			do {
				m_receiverState.m_itPendingAck->second.m_usecWhenAckPrior = INT64_MAX;
				++m_receiverState.m_itPendingAck;
			} while ( m_receiverState.m_itPendingAck->first <= nAckEnd );
		}

		
		
		while ( m_receiverState.m_itPendingNack->first < nAckEnd )
			++m_receiverState.m_itPendingNack;
	}

	
	while ( pBlock >= helper.m_arBlocks )
	{
		uint8 *pAckBlockHeaderByte = pOut;
		++pOut;

		
		{
			if ( pBlock->m_nAck < 8 )
			{
				
				*pAckBlockHeaderByte = uint8(pBlock->m_nAck << 4);
			}
			else {
				
				
				
				*pAckBlockHeaderByte = 0x80 | ( uint8(pBlock->m_nAck & 7) << 4 );
				pOut = SerializeVarInt( pOut, pBlock->m_nAck>>3, pOutEnd );
				if ( pOut == nullptr )
				{
					AssertMsg( false, "Overflow serializing packet ack varint count" );
					return nullptr;
				}
			}
		}

		
		{
			if ( pBlock->m_nNack < 8 )
			{
				
				*pAckBlockHeaderByte |= uint8(pBlock->m_nNack);
			}
			else {
				
				
				
				
				*pAckBlockHeaderByte |= 0x08 | uint8(pBlock->m_nNack & 7);
				pOut = SerializeVarInt( pOut, pBlock->m_nNack >> 3, pOutEnd );
				if ( pOut == nullptr )
				{
					AssertMsg( false, "Overflow serializing packet nack varint count" );
					return nullptr;
				}
			}
		}

		
		int64 nAckBegin = nAckEnd - pBlock->m_nAck;
		int64 nNackBegin = nAckBegin - pBlock->m_nNack;
		SpewDebugGroup( nLogLevelPacketDecode, "[%s]   encode pkt %lld nack [%lld,%lld) ack [%lld,%lld) \n", GetDescription(), (long long)m_statsEndToEnd.m_nNextSendSequenceNumber, (long long)nNackBegin, (long long)nAckBegin, (long long)nAckBegin, (long long)nAckEnd );




		nAckEnd = nNackBegin;
		Assert( nAckEnd > 0 ); 

		
		--pBlock;
	}

	
	Assert( pOut == pExpectedOutEnd );

	return pOut;
}

uint8 *CSteamNetworkConnectionBase::SNP_SerializeStopWaitingFrame( uint8 *pOut, const uint8 *pOutEnd, SteamNetworkingMicroseconds usecNow )
{
	
	
	

	
	int64 nOffset = m_statsEndToEnd.m_nNextSendSequenceNumber - m_senderState.m_nMinPktWaitingOnAck;
	AssertMsg2( nOffset > 0, "Told peer to stop acking up to %lld, but latest packet we have sent is %lld", (long long)m_senderState.m_nMinPktWaitingOnAck, (long long)m_statsEndToEnd.m_nNextSendSequenceNumber );
	SpewVerboseGroup( m_connectionConfig.m_LogLevel_PacketDecode.Get(), "[%s]   encode pkt %lld stop_waiting offset %lld = %lld", GetDescription(), (long long)m_statsEndToEnd.m_nNextSendSequenceNumber, (long long)nOffset, (long long)m_senderState.m_nMinPktWaitingOnAck );


	
	
	--nOffset;

	
	if ( nOffset < 0x100 )
	{
		if ( pOut + 2 > pOutEnd )
			return pOut;
		*pOut = 0x80;
		++pOut;
		*pOut = uint8( nOffset );
		++pOut;
	}
	else if ( nOffset < 0x10000 )
	{
		if ( pOut + 3 > pOutEnd )
			return pOut;
		*pOut = 0x81;
		++pOut;
		*(uint16*)pOut = LittleWord( uint16( nOffset ) );
		pOut += 2;
	}
	else if ( nOffset < 0x1000000 )
	{
		if ( pOut + 4 > pOutEnd )
			return pOut;
		*pOut = 0x82;
		++pOut;
		*pOut = uint8( nOffset ); 
		++pOut;
		*(uint16*)pOut = LittleWord( uint16( nOffset>>8 ) );
		pOut += 2;
	}
	else {
		if ( pOut + 9 > pOutEnd )
			return pOut;
		*pOut = 0x83;
		++pOut;
		*(uint64*)pOut = LittleQWord( nOffset );
		pOut += 8;
	}

	Assert( pOut <= pOutEnd );
	return pOut;
}

void CSteamNetworkConnectionBase::SNP_ReceiveUnreliableSegment( int64 nMsgNum, int nOffset, const void *pSegmentData, int cbSegmentSize, bool bLastSegmentInMessage, SteamNetworkingMicroseconds usecNow )
{
	SpewDebugGroup( m_connectionConfig.m_LogLevel_PacketDecode.Get(), "[%s] RX msg %lld offset %d+%d=%d %02x ... %02x\n", GetDescription(), nMsgNum, nOffset, cbSegmentSize, nOffset+cbSegmentSize, ((byte*)pSegmentData)[0], ((byte*)pSegmentData)[cbSegmentSize-1] );

	
	if ( GetState() != k_ESteamNetworkingConnectionState_Connected )
	{
		SpewDebugGroup( m_connectionConfig.m_LogLevel_PacketDecode.Get(), "[%s] discarding msg %lld [%d,%d) as connection is in state %d\n", GetDescription(), nMsgNum, nOffset, nOffset+cbSegmentSize, (int)GetState() );



		return;
	}

	
	if ( nOffset == 0 && bLastSegmentInMessage )
	{

		
		
		ReceivedMessage( pSegmentData, cbSegmentSize, nMsgNum, k_nSteamNetworkingSend_Unreliable, usecNow );
		return;
	}

	
	
	if ( len( m_receiverState.m_mapUnreliableSegments ) > k_nMaxBufferedUnreliableSegments )
	{
		auto itDelete = m_receiverState.m_mapUnreliableSegments.begin();

		
		
		int64 nDeleteMsgNum = itDelete->first.m_nMsgNum;
		do {
			itDelete = m_receiverState.m_mapUnreliableSegments.erase( itDelete );
		} while ( itDelete != m_receiverState.m_mapUnreliableSegments.end() && itDelete->first.m_nMsgNum == nDeleteMsgNum );

		
		
		
		if ( nDeleteMsgNum >= nMsgNum )
		{
			
			SpewWarningRateLimited( usecNow, "[%s] SNP expiring unreliable segments for msg %lld, while receiving unreliable segments for msg %lld\n", GetDescription(), (long long)nDeleteMsgNum, (long long)nMsgNum );
		}
	}

	
	
	SSNPRecvUnreliableSegmentKey key;
	key.m_nMsgNum = nMsgNum;
	key.m_nOffset = nOffset;
	SSNPRecvUnreliableSegmentData &data = m_receiverState.m_mapUnreliableSegments[ key ];
	if ( data.m_cbSegSize >= 0 )
	{
		
		
		
		SpewWarningRateLimited( usecNow, "[%s] Received unreliable msg %lld segment offset %d twice.  Sizes %d,%d, last=%d,%d\n", GetDescription(), nMsgNum, nOffset, data.m_cbSegSize, cbSegmentSize, (int)data.m_bLast, (int)bLastSegmentInMessage );

		
		
		
		
		return;
	}

	
	
	data.m_cbSegSize = cbSegmentSize;
	Assert( !data.m_bLast );
	data.m_bLast = bLastSegmentInMessage;
	memcpy( data.m_buf, pSegmentData, cbSegmentSize );

	
	key.m_nOffset = 0;
	auto itMsgStart = m_receiverState.m_mapUnreliableSegments.lower_bound( key );
	auto end = m_receiverState.m_mapUnreliableSegments.end();
	Assert( itMsgStart != end );
	auto itMsgLast = itMsgStart;
	int cbMessageSize = 0;
	for (;;)
	{
		
		if ( itMsgLast->first.m_nMsgNum != nMsgNum || itMsgLast->first.m_nOffset > cbMessageSize )
			return; 

		
		
		cbMessageSize = std::max( cbMessageSize, itMsgLast->first.m_nOffset + itMsgLast->second.m_cbSegSize );

		
		if ( itMsgLast->second.m_bLast )
			break;

		
		++itMsgLast;
		if ( itMsgLast == end )
			return;
	}

	CSteamNetworkingMessage *pMsg = CSteamNetworkingMessage::New( this, cbMessageSize, nMsgNum, k_nSteamNetworkingSend_Unreliable, usecNow );
	if ( !pMsg )
		return;

	
	
	for (;;)
	{
		Assert( itMsgStart->first.m_nMsgNum == nMsgNum );
		memcpy( (char *)pMsg->m_pData + itMsgStart->first.m_nOffset, itMsgStart->second.m_buf, itMsgStart->second.m_cbSegSize );

		
		if ( itMsgStart->second.m_bLast )
			break;

		
		itMsgStart = m_receiverState.m_mapUnreliableSegments.erase( itMsgStart );
	}

	
	
	do {
		itMsgStart = m_receiverState.m_mapUnreliableSegments.erase( itMsgStart );
	} while ( itMsgStart != end && itMsgStart->first.m_nMsgNum == nMsgNum );

	
	ReceivedMessage( pMsg );
}

bool CSteamNetworkConnectionBase::SNP_ReceiveReliableSegment( int64 nPktNum, int64 nSegBegin, const uint8 *pSegmentData, int cbSegmentSize, SteamNetworkingMicroseconds usecNow )
{
	int nLogLevelPacketDecode = m_connectionConfig.m_LogLevel_PacketDecode.Get();

	
	int64 nSegEnd = nSegBegin + cbSegmentSize;

	
	SpewVerboseGroup( nLogLevelPacketDecode, "[%s]   decode pkt %lld reliable range [%lld,%lld)\n", GetDescription(), (long long)nPktNum, (long long)nSegBegin, (long long)nSegEnd );



	
	Assert( cbSegmentSize >= 0 );
	if ( cbSegmentSize <= 0 )
	{
		
		SpewWarningRateLimited( usecNow, "[%s] decode pkt %lld empty reliable segment?\n", GetDescription(), (long long)nPktNum );

		return true;
	}

	
	if ( GetState() != k_ESteamNetworkingConnectionState_Connected )
	{
		SpewVerboseGroup( nLogLevelPacketDecode, "[%s]   discarding pkt %lld [%lld,%lld) as connection is in state %d\n", GetDescription(), (long long)nPktNum, (long long)nSegBegin, (long long)nSegEnd, (int)GetState() );



		return true;
	}

	
	
	if ( nSegEnd <= m_receiverState.m_nReliableStreamPos )
		return true;

	
	
	

	
	const int64 nExpectNextStreamPos = m_receiverState.m_nReliableStreamPos + len( m_receiverState.m_bufReliableStream );

	
	if ( nSegEnd > nExpectNextStreamPos )
	{
		int64 cbNewSize = nSegEnd - m_receiverState.m_nReliableStreamPos;
		Assert( cbNewSize > len( m_receiverState.m_bufReliableStream ) );

		
		
		
		
		
		if ( cbNewSize > k_cbMaxBufferedReceiveReliableData )
		{
			
			
			
			SpewWarningRateLimited( usecNow, "[%s] decode pkt %lld abort.  %lld bytes reliable data buffered [%lld-%lld), new size would be %lld to %lld\n", GetDescription(), (long long)nPktNum, (long long)m_receiverState.m_bufReliableStream.size(), (long long)m_receiverState.m_nReliableStreamPos, (long long)( m_receiverState.m_nReliableStreamPos + m_receiverState.m_bufReliableStream.size() ), (long long)cbNewSize, (long long)nSegEnd );






			return false;  
		}

		
		if ( nSegBegin > nExpectNextStreamPos )
		{
			if ( !m_receiverState.m_mapReliableStreamGaps.empty() )
			{

				
				
				
				Assert( m_receiverState.m_mapReliableStreamGaps.rbegin()->second < nExpectNextStreamPos );

				
				if ( len( m_receiverState.m_mapReliableStreamGaps ) >= k_nMaxReliableStreamGaps_Extend )
				{
					
					
					
					SpewWarningRateLimited( usecNow, "[%s] decode pkt %lld abort.  Reliable stream already has %d fragments, first is [%lld,%lld), last is [%lld,%lld), new segment is [%lld,%lld)\n", GetDescription(), (long long)nPktNum, len( m_receiverState.m_mapReliableStreamGaps ), (long long)m_receiverState.m_mapReliableStreamGaps.begin()->first, (long long)m_receiverState.m_mapReliableStreamGaps.begin()->second, (long long)m_receiverState.m_mapReliableStreamGaps.rbegin()->first, (long long)m_receiverState.m_mapReliableStreamGaps.rbegin()->second, (long long)nSegBegin, (long long)nSegEnd );






					return false;  
				}
			}

			
			m_receiverState.m_mapReliableStreamGaps[ nExpectNextStreamPos ] = nSegBegin;
		}
		m_receiverState.m_bufReliableStream.resize( size_t( cbNewSize ) );
	}

	
	
	if ( nSegBegin < nExpectNextStreamPos )
	{

		
		if ( nSegBegin < m_receiverState.m_nReliableStreamPos )
		{
			int nSkip = m_receiverState.m_nReliableStreamPos - nSegBegin;
			cbSegmentSize -= nSkip;
			pSegmentData += nSkip;
			nSegBegin += nSkip;
		}
		Assert( nSegBegin < nSegEnd );

		
		if ( !m_receiverState.m_mapReliableStreamGaps.empty() )
		{
			auto gapFilled = m_receiverState.m_mapReliableStreamGaps.upper_bound( nSegBegin );
			if ( gapFilled != m_receiverState.m_mapReliableStreamGaps.begin() )
			{
				--gapFilled;
				Assert( gapFilled->first < gapFilled->second ); 
				Assert( gapFilled->first <= nSegBegin ); 
				if ( gapFilled->second > nSegBegin ) 
				{
					do {

						
						if ( nSegBegin == gapFilled->first )
						{
							if ( nSegEnd < gapFilled->second )
							{
								
								
								const_cast<int64&>( gapFilled->first ) = nSegEnd;
								break;
							}

							
							
							
							
							gapFilled = m_receiverState.m_mapReliableStreamGaps.erase( gapFilled );
						}
						else if ( nSegEnd >= gapFilled->second )
						{
							
							Assert( nSegBegin < gapFilled->second );
							gapFilled->second = nSegBegin;

							
							++gapFilled;
						}
						else {
							
							Assert( nSegBegin > gapFilled->first );
							Assert( nSegEnd < gapFilled->second );

							
							
							
							if ( len( m_receiverState.m_mapReliableStreamGaps ) >= k_nMaxReliableStreamGaps_Fragment )
							{
								
								SpewWarningRateLimited( usecNow, "[%s] decode pkt %lld abort.  Reliable stream already has %d fragments, first is [%lld,%lld), last is [%lld,%lld).  We don't want to fragment [%lld,%lld) with new segment [%lld,%lld)\n", GetDescription(), (long long)nPktNum, len( m_receiverState.m_mapReliableStreamGaps ), (long long)m_receiverState.m_mapReliableStreamGaps.begin()->first, (long long)m_receiverState.m_mapReliableStreamGaps.begin()->second, (long long)m_receiverState.m_mapReliableStreamGaps.rbegin()->first, (long long)m_receiverState.m_mapReliableStreamGaps.rbegin()->second, (long long)gapFilled->first, (long long)gapFilled->second, (long long)nSegBegin, (long long)nSegEnd );







								return false;  
							}

							
							int64 nRightHandBegin = nSegEnd;
							int64 nRightHandEnd = gapFilled->second;

							
							gapFilled->second = nSegBegin;

							
							m_receiverState.m_mapReliableStreamGaps[ nRightHandBegin ] = nRightHandEnd;

							
							break;
						}

						
						
					} while ( gapFilled != m_receiverState.m_mapReliableStreamGaps.end() && gapFilled->first < nSegEnd );
				}
			}
		}
	}

	
	
	
	int nBufOffset = nSegBegin - m_receiverState.m_nReliableStreamPos;
	Assert( nBufOffset >= 0 );
	Assert( nBufOffset+cbSegmentSize <= len( m_receiverState.m_bufReliableStream ) );
	memcpy( &m_receiverState.m_bufReliableStream[nBufOffset], pSegmentData, cbSegmentSize );

	
	int nNumReliableBytes;
	if ( m_receiverState.m_mapReliableStreamGaps.empty() )
	{
		nNumReliableBytes = len( m_receiverState.m_bufReliableStream );
	}
	else {
		auto firstGap = m_receiverState.m_mapReliableStreamGaps.begin();
		Assert( firstGap->first >= m_receiverState.m_nReliableStreamPos );
		if ( firstGap->first < nSegBegin )
		{
			
			
			Assert( firstGap->second <= nSegBegin );
			return true;
		}

		
		Assert( firstGap->first >= nSegEnd );
		nNumReliableBytes = firstGap->first - m_receiverState.m_nReliableStreamPos;
		Assert( nNumReliableBytes > 0 );
		Assert( nNumReliableBytes < len( m_receiverState.m_bufReliableStream ) ); 
	}
	Assert( nNumReliableBytes > 0 );

	
	do {

		
		
		
		
		
		uint8 *pReliableStart = &m_receiverState.m_bufReliableStream[0];
		uint8 *pReliableDecode = pReliableStart;
		uint8 *pReliableEnd = pReliableDecode + nNumReliableBytes;

		
		SpewDebugGroup( nLogLevelPacketDecode, "[%s]   decode pkt %lld valid reliable bytes = %d [%lld,%lld)\n", GetDescription(), (long long)nPktNum, nNumReliableBytes, (long long)m_receiverState.m_nReliableStreamPos, (long long)( m_receiverState.m_nReliableStreamPos + nNumReliableBytes ) );




		
		uint8 nHeaderByte = *(pReliableDecode++);
		if ( nHeaderByte & 0x80 )
		{
			ConnectionState_ProblemDetectedLocally( k_ESteamNetConnectionEnd_Misc_InternalError, "Invalid reliable message header byte 0x%02x", nHeaderByte );
			return false;
		}

		
		int64 nMsgNum = m_receiverState.m_nLastRecvReliableMsgNum;
		if ( nHeaderByte & 0x40 )
		{
			uint64 nOffset;
			pReliableDecode = DeserializeVarInt( pReliableDecode, pReliableEnd, nOffset );
			if ( pReliableDecode == nullptr )
			{
				
				return true; 
			}

			nMsgNum += nOffset;

			
			
			
			
			
			
			
			if ( nOffset > 1000000 || nMsgNum > m_receiverState.m_nHighestSeenMsgNum+10000 )
			{
				ConnectionState_ProblemDetectedLocally( k_ESteamNetConnectionEnd_Misc_InternalError, "Reliable message number lurch.  Last reliable %lld, offset %llu, highest seen %lld", (long long)m_receiverState.m_nLastRecvReliableMsgNum, (unsigned long long)nOffset, (long long)m_receiverState.m_nHighestSeenMsgNum );


				return false;
			}
		}
		else {
			++nMsgNum;
		}

		
		
		
		if ( nMsgNum > m_receiverState.m_nHighestSeenMsgNum )
			m_receiverState.m_nHighestSeenMsgNum = nMsgNum;

		
		int cbMsgSize = nHeaderByte&0x1f;
		if ( nHeaderByte & 0x20 )
		{
			uint64 nMsgSizeUpperBits;
			pReliableDecode = DeserializeVarInt( pReliableDecode, pReliableEnd, nMsgSizeUpperBits );
			if ( pReliableDecode == nullptr )
			{
				
				return true; 
			}

			
			
			
			if ( nMsgSizeUpperBits > (uint64)k_cbMaxMessageSizeRecv<<5 )
			{
				ConnectionState_ProblemDetectedLocally( k_ESteamNetConnectionEnd_Misc_InternalError, "Reliable message size too large.  (%llu<<5 + %d)", (unsigned long long)nMsgSizeUpperBits, cbMsgSize );

				return false;
			}

			
			cbMsgSize += int( nMsgSizeUpperBits<<5 );
			if ( cbMsgSize > k_cbMaxMessageSizeRecv )
			{
				ConnectionState_ProblemDetectedLocally( k_ESteamNetConnectionEnd_Misc_InternalError, "Reliable message size %d too large.", cbMsgSize );
				return false;
			}
		}

		
		if ( pReliableDecode+cbMsgSize > pReliableEnd )
		{
			
			return true; 
		}

		
		if ( !ReceivedMessage( pReliableDecode, cbMsgSize, nMsgNum, k_nSteamNetworkingSend_Reliable, usecNow ) )
			return false; 
		pReliableDecode += cbMsgSize;
		int cbStreamConsumed = pReliableDecode-pReliableStart;

		
		m_receiverState.m_nLastRecvReliableMsgNum = nMsgNum;
		m_receiverState.m_nReliableStreamPos += cbStreamConsumed;

		
		pop_from_front( m_receiverState.m_bufReliableStream, cbStreamConsumed );

		
		nNumReliableBytes -= cbStreamConsumed;
	} while ( nNumReliableBytes > 0 );

	return true; 
}

void CSteamNetworkConnectionBase::SNP_RecordReceivedPktNum( int64 nPktNum, SteamNetworkingMicroseconds usecNow, bool bScheduleAck )
{

	
	
	if ( unlikely( nPktNum < m_receiverState.m_nMinPktNumToSendAcks ) )
		return;

	
	if ( likely( nPktNum == m_statsEndToEnd.m_nMaxRecvPktNum+1 ) )
	{
		if ( bScheduleAck ) 
		{
			
			
			QueueFlushAllAcks( usecNow + k_usecMaxDataAckDelay );
		}
		return;
	}

	
	m_receiverState.DebugCheckPackGapMap();

	
	
	SteamNetworkingMicroseconds usecScheduleAck = bScheduleAck ? usecNow + k_usecMaxDataAckDelay : INT64_MAX;

	
	if ( nPktNum > m_statsEndToEnd.m_nMaxRecvPktNum )
	{

		
		if ( len( m_receiverState.m_mapPacketGaps ) >= k_nMaxPacketGaps )
			return; 

		
		int64 nBegin = m_statsEndToEnd.m_nMaxRecvPktNum+1;
		std::pair<int64,SSNPPacketGap> x;
		x.first = nBegin;
		x.second.m_nEnd = nPktNum;
		x.second.m_usecWhenReceivedPktBefore = m_statsEndToEnd.m_usecTimeLastRecvSeq;
		x.second.m_usecWhenAckPrior = m_receiverState.m_mapPacketGaps.rbegin()->second.m_usecWhenAckPrior;

		
		x.second.m_usecWhenOKToNack = usecNow;
		if ( nPktNum < m_statsEndToEnd.m_nMaxRecvPktNum + 3 )
			x.second.m_usecWhenOKToNack += k_usecNackFlush;

		auto iter = m_receiverState.m_mapPacketGaps.insert( x ).first;

		SpewMsgGroup( m_connectionConfig.m_LogLevel_PacketGaps.Get(), "[%s] drop %d pkts [%lld-%lld)", GetDescription(), (int)( nPktNum - nBegin ), (long long)nBegin, (long long)nPktNum );



		
		if ( m_receiverState.m_itPendingNack->first == INT64_MAX )
		{
			m_receiverState.m_itPendingNack = iter;
		}
		else {
			
			Assert( m_receiverState.m_itPendingNack->first < nBegin );
		}

		
		if ( m_receiverState.m_itPendingAck->first == INT64_MAX && m_receiverState.m_itPendingAck->second.m_usecWhenAckPrior < INT64_MAX )
		{
			Assert( iter->second.m_usecWhenAckPrior == m_receiverState.m_itPendingAck->second.m_usecWhenAckPrior );
			m_receiverState.m_itPendingAck = iter;
		}

		
		m_receiverState.DebugCheckPackGapMap();

		
		
		
		QueueFlushAllAcks( usecScheduleAck );
	}
	else {

		
		auto itGap = m_receiverState.m_mapPacketGaps.upper_bound( nPktNum );
		if ( itGap == m_receiverState.m_mapPacketGaps.end() )
		{
			AssertMsg( false, "[%s] Cannot locate gap, or processing packet %lld multiple times. %s | %s", GetDescription(), (long long)nPktNum, m_statsEndToEnd.RecvPktNumStateDebugString().c_str(), m_statsEndToEnd.HistoryRecvSeqNumDebugString(8).c_str() );

			return;
		}
		if ( itGap == m_receiverState.m_mapPacketGaps.begin() )
		{
			AssertMsg( false, "[%s] Cannot locate gap, or processing packet %lld multiple times. [%lld,%lld) %s | %s", GetDescription(), (long long)nPktNum, (long long)itGap->first, (long long)itGap->second.m_nEnd, m_statsEndToEnd.RecvPktNumStateDebugString().c_str(), m_statsEndToEnd.HistoryRecvSeqNumDebugString(8).c_str() );

			return;
		}
		--itGap;
		if ( itGap->first > nPktNum || itGap->second.m_nEnd <= nPktNum )
		{
			
			
			AssertMsg( false, "[%s] Packet gap bug.  %lld [%lld,%lld) %s | %s", GetDescription(), (long long)nPktNum, (long long)itGap->first, (long long)itGap->second.m_nEnd, m_statsEndToEnd.RecvPktNumStateDebugString().c_str(), m_statsEndToEnd.HistoryRecvSeqNumDebugString(8).c_str() );

			return;
		}

		
		

		
		if ( itGap->second.m_nEnd-1 == nPktNum )
		{
			
			if ( itGap->first == nPktNum )
			{
				
				usecScheduleAck = std::min( usecScheduleAck, itGap->second.m_usecWhenAckPrior );
				if ( m_receiverState.m_itPendingAck == itGap )
					++m_receiverState.m_itPendingAck;
				if ( m_receiverState.m_itPendingNack == itGap )
					++m_receiverState.m_itPendingNack;

				
				SteamNetworkingMicroseconds usecWhenAckPrior = itGap->second.m_usecWhenAckPrior;

				
				
				itGap = m_receiverState.m_mapPacketGaps.erase( itGap );

				
				
				
				
				
				
				
				
				
				
				
				if ( usecWhenAckPrior < itGap->second.m_usecWhenAckPrior )
				{
					itGap->second.m_usecWhenAckPrior = usecWhenAckPrior;
				}
				else {
					
					
					if ( m_receiverState.m_itPendingAck->second.m_usecWhenAckPrior == INT64_MAX )
					{
						m_receiverState.m_itPendingAck = m_receiverState.m_mapPacketGaps.end();
						--m_receiverState.m_itPendingAck;
						Assert( m_receiverState.m_itPendingAck->first == INT64_MAX );
					}
				}

				SpewVerboseGroup( m_connectionConfig.m_LogLevel_PacketGaps.Get(), "[%s] decode pkt %lld, single pkt gap filled", GetDescription(), (long long)nPktNum );

				
				m_receiverState.DebugCheckPackGapMap();
			}
			else {
				
				--itGap->second.m_nEnd;
				Assert( itGap->first < itGap->second.m_nEnd );

				SpewVerboseGroup( m_connectionConfig.m_LogLevel_PacketGaps.Get(), "[%s] decode pkt %lld, last packet in gap, reduced to [%lld,%lld)", GetDescription(), (long long)nPktNum, (long long)itGap->first, (long long)itGap->second.m_nEnd );

				
				++itGap;

				
				m_receiverState.DebugCheckPackGapMap();
			}
		}
		else if ( itGap->first == nPktNum )
		{
			
			
			
			
			++const_cast<int64&>( itGap->first );
			Assert( itGap->first < itGap->second.m_nEnd );
			itGap->second.m_usecWhenReceivedPktBefore = usecNow;

			SpewVerboseGroup( m_connectionConfig.m_LogLevel_PacketGaps.Get(), "[%s] decode pkt %lld, first packet in gap, reduced to [%lld,%lld)", GetDescription(), (long long)nPktNum, (long long)itGap->first, (long long)itGap->second.m_nEnd );

			
			m_receiverState.DebugCheckPackGapMap();
		}
		else {
			
			
			if ( len( m_receiverState.m_mapPacketGaps ) >= k_nMaxPacketGaps )
				return; 

			
			auto itNext = itGap;
			++itNext;

			
			std::pair<int64,SSNPPacketGap> upper;
			upper.first = nPktNum+1;
			upper.second.m_nEnd = itGap->second.m_nEnd;
			upper.second.m_usecWhenReceivedPktBefore = usecNow;
			if ( itNext == m_receiverState.m_itPendingAck )
				upper.second.m_usecWhenAckPrior = INT64_MAX;
			else upper.second.m_usecWhenAckPrior = itNext->second.m_usecWhenAckPrior;
			upper.second.m_usecWhenOKToNack = itGap->second.m_usecWhenOKToNack;

			
			itGap->second.m_nEnd = nPktNum;
			Assert( itGap->first < itGap->second.m_nEnd );

			SpewVerboseGroup( m_connectionConfig.m_LogLevel_PacketGaps.Get(), "[%s] decode pkt %lld, gap split [%lld,%lld) and [%lld,%lld)", GetDescription(), (long long)nPktNum, (long long)itGap->first, (long long)itGap->second.m_nEnd, upper.first, upper.second.m_nEnd );

			
			
			itGap = m_receiverState.m_mapPacketGaps.insert( upper ).first;

			
			m_receiverState.DebugCheckPackGapMap();
		}

		Assert( itGap != m_receiverState.m_mapPacketGaps.end() );

		
		if ( usecScheduleAck < itGap->second.m_usecWhenAckPrior )
		{

			
			if ( usecScheduleAck <= m_receiverState.m_itPendingAck->second.m_usecWhenAckPrior )
			{

				
				itGap->second.m_usecWhenAckPrior = usecScheduleAck;

				
				
				if ( m_receiverState.m_itPendingAck->first <= itGap->first )
				{
					while ( m_receiverState.m_itPendingAck != itGap )
					{
						m_receiverState.m_itPendingAck->second.m_usecWhenAckPrior = INT64_MAX;
						++m_receiverState.m_itPendingAck;
					}
				}
				else {
					
					
					
					SteamNetworkingMicroseconds usecOldSched = m_receiverState.m_itPendingAck->second.m_usecWhenAckPrior;
					while ( --m_receiverState.m_itPendingAck != itGap )
					{
						m_receiverState.m_itPendingAck->second.m_usecWhenAckPrior = usecOldSched;
					}
				}
			}
			else {
				
				
				if ( itGap->first < m_receiverState.m_itPendingAck->first )
				{
					
					
					

				}
				else {

					
					itGap->second.m_usecWhenAckPrior = usecScheduleAck;

					
					
					Assert( itGap != m_receiverState.m_mapPacketGaps.begin() );
					while ( (--itGap)->second.m_usecWhenAckPrior > usecScheduleAck )
					{
						Assert( itGap != m_receiverState.m_mapPacketGaps.begin() );
						itGap->second.m_usecWhenAckPrior = usecScheduleAck;
					}
				}
			}

			
			m_receiverState.DebugCheckPackGapMap();
		}

		
		if ( bScheduleAck )
			EnsureMinThinkTime( m_receiverState.TimeWhenFlushAcks() );
	}
}

int CSteamNetworkConnectionBase::SNP_ClampSendRate()
{
	
	
	int nMin = Clamp( m_connectionConfig.m_SendRateMin.Get(), 1024, 100*1024*1024 );
	int nMax = Clamp( m_connectionConfig.m_SendRateMax.Get(), nMin, 100*1024*1024 );

	
	m_senderState.m_n_x = Clamp( m_senderState.m_n_x, nMin, nMax );

	
	return m_senderState.m_n_x;
}


SteamNetworkingMicroseconds CSteamNetworkConnectionBase::SNP_ThinkSendState( SteamNetworkingMicroseconds usecNow )
{
	
	SNP_ClampSendRate();
	SNP_TokenBucket_Accumulate( usecNow );

	
	
	SteamNetworkingMicroseconds usecNextThink = SNP_GetNextThinkTime( usecNow );
	if ( usecNextThink > usecNow )
		return usecNextThink;

	
	int nPacketsSent = 0;
	while ( m_pTransport )
	{

		if ( nPacketsSent > k_nMaxPacketsPerThink )
		{
			
			
			
			
			m_senderState.m_flTokenBucket = m_senderState.m_n_x * -0.0005f;
			return usecNow + 1000;
		}

		
		if ( usecNow < m_receiverState.TimeWhenFlushAcks() && usecNow < SNP_TimeWhenWantToSendNextPacket() )
		{

			
			
			
			m_senderState.TokenBucket_Limit();
			break;
		}

		
		if ( !m_pTransport->SendDataPacket( usecNow ) )
		{
			
			
			m_senderState.m_flTokenBucket = m_senderState.m_n_x * -0.001f;
			return usecNow + 2000;
		}

		
		if ( m_senderState.m_flTokenBucket < 0.0f )
			break;

		
		
		++nPacketsSent;
	}

	
	SteamNetworkingMicroseconds usecNextAction = SNP_GetNextThinkTime( usecNow );
	Assert( usecNextAction > usecNow );
	return usecNextAction;
}

void CSteamNetworkConnectionBase::SNP_TokenBucket_Accumulate( SteamNetworkingMicroseconds usecNow )
{
	
	if ( !BStateIsConnectedForWirePurposes() )
	{
		m_senderState.m_flTokenBucket = k_flSendRateBurstOverageAllowance;
		m_senderState.m_usecTokenBucketTime = usecNow;
		return;
	}

	float flElapsed = ( usecNow - m_senderState.m_usecTokenBucketTime ) * 1e-6;
	m_senderState.m_flTokenBucket += (float)m_senderState.m_n_x * flElapsed;
	m_senderState.m_usecTokenBucketTime = usecNow;

	
	
	
	
	
	
	if ( SNP_TimeWhenWantToSendNextPacket() > usecNow )
		m_senderState.TokenBucket_Limit();
}

void SSNPReceiverState::QueueFlushAllAcks( SteamNetworkingMicroseconds usecWhen )
{
	DebugCheckPackGapMap();

	Assert( usecWhen > 0 ); 

	
	auto it = m_mapPacketGaps.end();
	--it;
	if ( it->second.m_usecWhenAckPrior <= usecWhen )
		return;
	it->second.m_usecWhenAckPrior = usecWhen;

	
	if ( m_itPendingAck == it )
		return;

	if ( m_itPendingAck->second.m_usecWhenAckPrior >= usecWhen )
	{
		do {
			m_itPendingAck->second.m_usecWhenAckPrior = INT64_MAX;
			++m_itPendingAck;
		} while ( m_itPendingAck != it );
		DebugCheckPackGapMap();
	}
	else {
		
		while ( (--it)->second.m_usecWhenAckPrior >= usecWhen )
			it->second.m_usecWhenAckPrior = usecWhen;
		DebugCheckPackGapMap();
	}
}


void SSNPReceiverState::DebugCheckPackGapMap() const {
	int64 nPrevEnd = 0;
	SteamNetworkingMicroseconds usecPrevAck = 0;
	bool bFoundPendingAck = false;
	for ( auto it: m_mapPacketGaps )
	{
		Assert( it.first > nPrevEnd );
		if ( it.first == m_itPendingAck->first )
		{
			Assert( !bFoundPendingAck );
			bFoundPendingAck = true;
			if ( it.first < INT64_MAX )
				Assert( it.second.m_usecWhenAckPrior < INT64_MAX );
		}
		else if ( !bFoundPendingAck )
		{
			Assert( it.second.m_usecWhenAckPrior == INT64_MAX );
		}
		else {
			Assert( it.second.m_usecWhenAckPrior >= usecPrevAck );
		}
		usecPrevAck = it.second.m_usecWhenAckPrior;
		if ( it.first == INT64_MAX )
		{
			Assert( it.second.m_nEnd == INT64_MAX );
		}
		else {
			Assert( it.first < it.second.m_nEnd );
		}
		nPrevEnd = it.second.m_nEnd;
	}
	Assert( nPrevEnd == INT64_MAX );
}


SteamNetworkingMicroseconds CSteamNetworkConnectionBase::SNP_TimeWhenWantToSendNextPacket() const {
	
	if ( !BStateIsConnectedForWirePurposes() )
	{
		AssertMsg( false, "We shouldn't be asking about sending packets when not fully connected" );
		return k_nThinkTime_Never;
	}

	
	if ( !m_senderState.m_listReadyRetryReliableRange.empty() )
		return 0;

	
	SteamNetworkingMicroseconds usecNextSend;
	if ( m_senderState.m_messagesQueued.empty() )
	{

		
		Assert( m_senderState.PendingBytesTotal() == 0 );
		usecNextSend = INT64_MAX;
	}
	else {

		

		
		if ( m_senderState.PendingBytesTotal() >= m_cbMaxPlaintextPayloadSend )
			
			return 0;

		
		
		usecNextSend = m_senderState.m_messagesQueued.m_pFirst->SNPSend_UsecNagle();
	}

	
	usecNextSend = std::min( usecNextSend, m_receiverState.m_itPendingNack->second.m_usecWhenOKToNack );

	
	return usecNextSend;
}

SteamNetworkingMicroseconds CSteamNetworkConnectionBase::SNP_GetNextThinkTime( SteamNetworkingMicroseconds usecNow )
{
	
	if ( !BStateIsConnectedForWirePurposes() )
	{
		AssertMsg( false, "We shouldn't be trying to think SNP when not fully connected" );
		return k_nThinkTime_Never;
	}

	
	if ( !m_pTransport )
		return k_nThinkTime_Never;

	
	SteamNetworkingMicroseconds usecNextThink = m_receiverState.TimeWhenFlushAcks();

	
	
	
	
	
	SteamNetworkingMicroseconds usecNextRetry = SNP_SenderCheckInFlightPackets( usecNow );

	
	SteamNetworkingMicroseconds usecTimeWantToSend = SNP_TimeWhenWantToSendNextPacket();
	usecTimeWantToSend = std::min( usecNextRetry, usecTimeWantToSend );
	if ( usecTimeWantToSend < usecNextThink )
	{

		
		SteamNetworkingMicroseconds usecNextSend = usecNow;
		SteamNetworkingMicroseconds usecQueueTime = m_senderState.CalcTimeUntilNextSend();
		if ( usecQueueTime > 0 )
		{
			usecNextSend += usecQueueTime;

			
			
			
			
			usecNextSend += 25;
		}

		
		usecNextSend = std::max( usecNextSend, usecTimeWantToSend );

		
		usecNextThink = std::min( usecNextThink, usecNextSend );
	}

	return usecNextThink;
}

void CSteamNetworkConnectionBase::SNP_PopulateDetailedStats( SteamDatagramLinkStats &info )
{
	info.m_latest.m_nSendRate = SNP_ClampSendRate();
	info.m_latest.m_nPendingBytes = m_senderState.m_cbPendingUnreliable + m_senderState.m_cbPendingReliable;
	info.m_lifetime.m_nMessagesSentReliable    = m_senderState.m_nMessagesSentReliable;
	info.m_lifetime.m_nMessagesSentUnreliable  = m_senderState.m_nMessagesSentUnreliable;
	info.m_lifetime.m_nMessagesRecvReliable    = m_receiverState.m_nMessagesRecvReliable;
	info.m_lifetime.m_nMessagesRecvUnreliable  = m_receiverState.m_nMessagesRecvUnreliable;
}

void CSteamNetworkConnectionBase::SNP_PopulateQuickStats( SteamNetworkingQuickConnectionStatus &info, SteamNetworkingMicroseconds usecNow )
{
	info.m_nSendRateBytesPerSecond = SNP_ClampSendRate();
	info.m_cbPendingUnreliable = m_senderState.m_cbPendingUnreliable;
	info.m_cbPendingReliable = m_senderState.m_cbPendingReliable;
	info.m_cbSentUnackedReliable = m_senderState.m_cbSentUnackedReliable;
	if ( GetState() == k_ESteamNetworkingConnectionState_Connected )
	{

		
		SNP_TokenBucket_Accumulate( usecNow );

		
		
		
		
		
		
		
		
		
		int cbPendingTotal = m_senderState.PendingBytesTotal() / m_cbMaxMessageNoFragment * m_cbMaxMessageNoFragment;

		
		
		cbPendingTotal -= (int)m_senderState.m_flTokenBucket;
		if ( cbPendingTotal <= 0 )
		{
			
			info.m_usecQueueTime = 0;
		}
		else {

			info.m_usecQueueTime = (int64)cbPendingTotal * k_nMillion / SNP_ClampSendRate();
		}
	}
	else {
		
		info.m_usecQueueTime = INT64_MAX;
	}
}

} 
