








































enum eLoRaMacState {
    LORAMAC_IDLE          = 0x00000000, LORAMAC_STOPPED       = 0x00000001, LORAMAC_TX_RUNNING    = 0x00000002, LORAMAC_RX            = 0x00000004, LORAMAC_ACK_RETRY     = 0x00000010, LORAMAC_TX_DELAYED    = 0x00000020, LORAMAC_TX_CONFIG     = 0x00000040, LORAMAC_RX_ABORT      = 0x00000080, };









typedef enum eLoRaMacRequestHandling {
    LORAMAC_REQUEST_HANDLING_OFF = 0, LORAMAC_REQUEST_HANDLING_ON = !LORAMAC_REQUEST_HANDLING_OFF }LoRaMacRequestHandling_t;


typedef struct sLoRaMacNvmCtx {
    
    LoRaMacRegion_t Region;
    
    LoRaMacParams_t MacParamsDefaults;
    
    uint32_t NetID;
    
    uint32_t DevAddr;
    
    MulticastCtx_t MulticastChannelList[LORAMAC_MAX_MC_CTX];
    
    DeviceClass_t DeviceClass;
    
    bool PublicNetwork;
    
    bool AdrCtrlOn;
    
    uint32_t AdrAckCounter;

    
    LoRaMacParams_t MacParams;
    
    uint8_t MaxDCycle;
    
    bool DutyCycleOn;
    
    uint8_t LastTxChannel;
    
    uint8_t MacCommandsBuffer[LORA_MAC_COMMAND_MAX_LENGTH];
    
    bool SrvAckRequested;
    
    uint16_t AggregatedDCycle;
    
    TimerTime_t LastTxDoneTime;
    TimerTime_t AggregatedTimeOff;
    
    SysTime_t InitializationTime;
    
    Version_t Version;
    
    ActivationType_t NetworkActivation;
    
    uint32_t LastRxMic;
}LoRaMacNvmCtx_t;

typedef struct sLoRaMacCtx {
    
    uint16_t PktBufferLen;
    
    uint8_t PktBuffer[LORAMAC_PHY_MAXPAYLOAD];
    
    LoRaMacMessage_t TxMsg;
    
    uint8_t AppData[LORAMAC_PHY_MAXPAYLOAD];
    
    uint8_t AppDataSize;
    
    uint8_t RxPayload[LORAMAC_PHY_MAXPAYLOAD];
    SysTime_t LastTxSysTime;
    
    uint32_t MacState;
    
    LoRaMacPrimitives_t* MacPrimitives;
    
    LoRaMacCallback_t* MacCallbacks;
    
    RadioEvents_t RadioEvents;
    
    TimerEvent_t TxDelayedTimer;
    
    TimerEvent_t RxWindowTimer1;
    TimerEvent_t RxWindowTimer2;
    
    uint32_t RxWindow1Delay;
    uint32_t RxWindow2Delay;
    
    RxConfigParams_t RxWindow1Config;
    RxConfigParams_t RxWindow2Config;
    RxConfigParams_t RxWindowCConfig;
    
    uint16_t AdrAckLimit;
    
    uint16_t AdrAckDelay;
    
    TimerEvent_t AckTimeoutTimer;
    
    uint8_t ChannelsNbTransCounter;
    
    uint8_t AckTimeoutRetries;
    
    uint8_t AckTimeoutRetriesCounter;
    
    bool AckTimeoutRetry;
    
    bool NodeAckRequested;
    
    uint8_t Channel;
    
    TimerTime_t TxTimeOnAir;
    
    McpsIndication_t McpsIndication;
    
    McpsConfirm_t McpsConfirm;
    
    MlmeConfirm_t MlmeConfirm;
    
    MlmeIndication_t MlmeIndication;
    
    LoRaMacRxSlot_t RxSlot;
    
    LoRaMacFlags_t MacFlags;
    
    LoRaMacRequestHandling_t AllowRequests;
    
    LoRaMacNvmCtx_t* NvmCtx;
}LoRaMacCtx_t;


static LoRaMacCtx_t MacCtx;


static LoRaMacNvmCtx_t NvmMacCtx;




LoRaMacCtxs_t Contexts;


typedef union uLoRaMacRadioEvents {
    uint32_t Value;
    struct sEvents {
        uint32_t RxTimeout : 1;
        uint32_t RxError   : 1;
        uint32_t TxTimeout : 1;
        uint32_t RxDone    : 1;
        uint32_t TxDone    : 1;
    }Events;
}LoRaMacRadioEvents_t;


LoRaMacRadioEvents_t LoRaMacRadioEvents = { .Value = 0 };


static void OnRadioTxDone( void );


static void PrepareRxDoneAbort( void );


static void OnRadioRxDone( uint8_t* payload, uint16_t size, int16_t rssi, int8_t snr );


static void OnRadioTxTimeout( void );


static void OnRadioRxError( void );


static void OnRadioRxTimeout( void );


static void OnTxDelayedTimerEvent( void* context );


static void OnRxWindow1TimerEvent( void* context );


static void OnRxWindow2TimerEvent( void* context );


static void OnAckTimeoutTimerEvent( void* context );


static void SetMlmeScheduleUplinkIndication( void );


static LoRaMacCryptoStatus_t GetFCntDown( AddressIdentifier_t addrID, FType_t fType, LoRaMacMessageData_t* macMsg, Version_t lrWanVersion, uint16_t maxFCntGap, FCntIdentifier_t* fCntID, uint32_t* currentDown );


static LoRaMacStatus_t SwitchClass( DeviceClass_t deviceClass );


static uint8_t GetMaxAppPayloadWithoutFOptsLength( int8_t datarate );


static bool ValidatePayloadLength( uint8_t lenN, int8_t datarate, uint8_t fOptsLen );


static void ProcessMacCommands( uint8_t* payload, uint8_t macIndex, uint8_t commandsSize, int8_t snr, LoRaMacRxSlot_t rxSlot );


LoRaMacStatus_t Send( LoRaMacHeader_t* macHdr, uint8_t fPort, void* fBuffer, uint16_t fBufferSize );


LoRaMacStatus_t SendReJoinReq( JoinReqIdentifier_t joinReqType );


LoRaMacStatus_t PrepareFrame( LoRaMacHeader_t* macHdr, LoRaMacFrameCtrl_t* fCtrl, uint8_t fPort, void* fBuffer, uint16_t fBufferSize );


static LoRaMacStatus_t ScheduleTx( bool allowDelayedTx );


static LoRaMacStatus_t SecureFrame( uint8_t txDr, uint8_t txCh );


static void CalculateBackOff( uint8_t channel );


static void RemoveMacCommands( LoRaMacRxSlot_t rxSlot, LoRaMacFrameCtrl_t fCtrl, Mcps_t request );


LoRaMacStatus_t SendFrameOnChannel( uint8_t channel );


LoRaMacStatus_t SetTxContinuousWave( uint16_t timeout );


LoRaMacStatus_t SetTxContinuousWave1( uint16_t timeout, uint32_t frequency, uint8_t power );


static void ResetMacParameters( void );


static void RxWindowSetup( TimerEvent_t* rxTimer, RxConfigParams_t* rxConfig );


static void OpenContinuousRxCWindow( void );


LoRaMacCtxs_t* GetCtxs( void );


LoRaMacStatus_t RestoreCtxs( LoRaMacCtxs_t* contexts );


LoRaMacStatus_t DetermineFrameType( LoRaMacMessageData_t* macMsg, FType_t* fType );


static bool CheckRetransUnconfirmedUplink( void );


static bool CheckRetransConfirmedUplink( void );


static bool StopRetransmission( void );


static void AckTimeoutRetriesProcess( void );


static void AckTimeoutRetriesFinalize( void );


static void CallNvmCtxCallback( LoRaMacNvmCtxModule_t module );


static void EventMacNvmCtxChanged( void );


static void EventRegionNvmCtxChanged( void );


static void EventCryptoNvmCtxChanged( void );


static void EventSecureElementNvmCtxChanged( void );


static void EventCommandsNvmCtxChanged( void );


static void EventClassBNvmCtxChanged( void );


static void EventConfirmQueueNvmCtxChanged( void );


static uint8_t IsRequestPending( void );


static void LoRaMacEnableRequests( LoRaMacRequestHandling_t requestState );


static void LoRaMacCheckForRxAbort( void );


static uint8_t LoRaMacCheckForBeaconAcquisition( void );


static void LoRaMacHandleMlmeRequest( void );


static void LoRaMacHandleMcpsRequest( void );


static void LoRaMacHandleRequestEvents( void );


static void LoRaMacHandleIndicationEvents( void );


struct {
    TimerTime_t CurTime;
}TxDoneParams;


struct {
    TimerTime_t LastRxDone;
    uint8_t *Payload;
    uint16_t Size;
    int16_t Rssi;
    int8_t Snr;
}RxDoneParams;

static void OnRadioTxDone( void )
{
    TxDoneParams.CurTime = TimerGetCurrentTime( );
    MacCtx.LastTxSysTime = SysTimeGet( );

    LoRaMacRadioEvents.Events.TxDone = 1;

    if( ( MacCtx.MacCallbacks != NULL ) && ( MacCtx.MacCallbacks->MacProcessNotify != NULL ) )
    {
        MacCtx.MacCallbacks->MacProcessNotify( );
    }
}

static void OnRadioRxDone( uint8_t *payload, uint16_t size, int16_t rssi, int8_t snr )
{
    RxDoneParams.LastRxDone = TimerGetCurrentTime( );
    RxDoneParams.Payload = payload;
    RxDoneParams.Size = size;
    RxDoneParams.Rssi = rssi;
    RxDoneParams.Snr = snr;

    LoRaMacRadioEvents.Events.RxDone = 1;

    if( ( MacCtx.MacCallbacks != NULL ) && ( MacCtx.MacCallbacks->MacProcessNotify != NULL ) )
    {
        MacCtx.MacCallbacks->MacProcessNotify( );
    }
}

static void OnRadioTxTimeout( void )
{
    LoRaMacRadioEvents.Events.TxTimeout = 1;

    if( ( MacCtx.MacCallbacks != NULL ) && ( MacCtx.MacCallbacks->MacProcessNotify != NULL ) )
    {
        MacCtx.MacCallbacks->MacProcessNotify( );
    }
}

static void OnRadioRxError( void )
{
    LoRaMacRadioEvents.Events.RxError = 1;

    if( ( MacCtx.MacCallbacks != NULL ) && ( MacCtx.MacCallbacks->MacProcessNotify != NULL ) )
    {
        MacCtx.MacCallbacks->MacProcessNotify( );
    }
}

static void OnRadioRxTimeout( void )
{
    LoRaMacRadioEvents.Events.RxTimeout = 1;

    if( ( MacCtx.MacCallbacks != NULL ) && ( MacCtx.MacCallbacks->MacProcessNotify != NULL ) )
    {
        MacCtx.MacCallbacks->MacProcessNotify( );
    }
}

static void UpdateRxSlotIdleState( void )
{
    if( MacCtx.NvmCtx->DeviceClass != CLASS_C )
    {
        MacCtx.RxSlot = RX_SLOT_NONE;
    }
    else {
        MacCtx.RxSlot = RX_SLOT_WIN_CLASS_C;
    }
}

static void ProcessRadioTxDone( void )
{
    GetPhyParams_t getPhy;
    PhyParam_t phyParam;
    SetBandTxDoneParams_t txDone;

    if( MacCtx.NvmCtx->DeviceClass != CLASS_C )
    {
        Radio.Sleep( );
    }
    
    TimerSetValue( &MacCtx.RxWindowTimer1, MacCtx.RxWindow1Delay );
    TimerStart( &MacCtx.RxWindowTimer1 );
    TimerSetValue( &MacCtx.RxWindowTimer2, MacCtx.RxWindow2Delay );
    TimerStart( &MacCtx.RxWindowTimer2 );

    if( ( MacCtx.NvmCtx->DeviceClass == CLASS_C ) || ( MacCtx.NodeAckRequested == true ) )
    {
        getPhy.Attribute = PHY_ACK_TIMEOUT;
        phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
        TimerSetValue( &MacCtx.AckTimeoutTimer, MacCtx.RxWindow2Delay + phyParam.Value );
        TimerStart( &MacCtx.AckTimeoutTimer );
    }

    
    MacCtx.NvmCtx->LastTxChannel = MacCtx.Channel;
    
    txDone.Channel = MacCtx.Channel;
    if( MacCtx.NvmCtx->NetworkActivation == ACTIVATION_TYPE_NONE )
    {
        txDone.Joined  = false;
    }
    else {
        txDone.Joined  = true;
    }
    txDone.LastTxDoneTime = TxDoneParams.CurTime;
    RegionSetBandTxDone( MacCtx.NvmCtx->Region, &txDone );
    
    MacCtx.NvmCtx->LastTxDoneTime = TxDoneParams.CurTime;

    if( MacCtx.NodeAckRequested == false )
    {
        MacCtx.McpsConfirm.Status = LORAMAC_EVENT_INFO_STATUS_OK;
    }
}

static void PrepareRxDoneAbort( void )
{
    MacCtx.MacState |= LORAMAC_RX_ABORT;

    if( MacCtx.NodeAckRequested == true )
    {
        OnAckTimeoutTimerEvent( NULL );
    }

    MacCtx.MacFlags.Bits.McpsInd = 1;
    MacCtx.MacFlags.Bits.MacDone = 1;

    UpdateRxSlotIdleState( );
}

static void ProcessRadioRxDone( void )
{
    LoRaMacHeader_t macHdr;
    ApplyCFListParams_t applyCFList;
    GetPhyParams_t getPhy;
    PhyParam_t phyParam;
    LoRaMacCryptoStatus_t macCryptoStatus = LORAMAC_CRYPTO_ERROR;

    LoRaMacMessageData_t macMsgData;
    LoRaMacMessageJoinAccept_t macMsgJoinAccept;
    uint8_t *payload = RxDoneParams.Payload;
    uint16_t size = RxDoneParams.Size;
    int16_t rssi = RxDoneParams.Rssi;
    int8_t snr = RxDoneParams.Snr;

    uint8_t pktHeaderLen = 0;

    uint32_t downLinkCounter = 0;
    uint32_t address = MacCtx.NvmCtx->DevAddr;
    uint8_t multicast = 0;
    AddressIdentifier_t addrID = UNICAST_DEV_ADDR;
    FCntIdentifier_t fCntID;

    MacCtx.McpsConfirm.AckReceived = false;
    MacCtx.McpsIndication.Rssi = rssi;
    MacCtx.McpsIndication.Snr = snr;
    MacCtx.McpsIndication.RxSlot = MacCtx.RxSlot;
    MacCtx.McpsIndication.Port = 0;
    MacCtx.McpsIndication.Multicast = 0;
    MacCtx.McpsIndication.FramePending = 0;
    MacCtx.McpsIndication.Buffer = NULL;
    MacCtx.McpsIndication.BufferSize = 0;
    MacCtx.McpsIndication.RxData = false;
    MacCtx.McpsIndication.AckReceived = false;
    MacCtx.McpsIndication.DownLinkCounter = 0;
    MacCtx.McpsIndication.McpsIndication = MCPS_UNCONFIRMED;
    MacCtx.McpsIndication.DevAddress = 0;
    MacCtx.McpsIndication.DeviceTimeAnsReceived = false;

    Radio.Sleep( );
    TimerStop( &MacCtx.RxWindowTimer2 );

    
    if( LoRaMacClassBRxBeacon( payload, size ) == true )
    {
        MacCtx.MlmeIndication.BeaconInfo.Rssi = rssi;
        MacCtx.MlmeIndication.BeaconInfo.Snr = snr;
        return;
    }
    
    if( MacCtx.NvmCtx->DeviceClass == CLASS_B )
    {
        if( LoRaMacClassBIsPingExpected( ) == true )
        {
            LoRaMacClassBSetPingSlotState( PINGSLOT_STATE_CALC_PING_OFFSET );
            LoRaMacClassBPingSlotTimerEvent( NULL );
            MacCtx.McpsIndication.RxSlot = RX_SLOT_WIN_CLASS_B_PING_SLOT;
        }
        else if( LoRaMacClassBIsMulticastExpected( ) == true )
        {
            LoRaMacClassBSetMulticastSlotState( PINGSLOT_STATE_CALC_PING_OFFSET );
            LoRaMacClassBMulticastSlotTimerEvent( NULL );
            MacCtx.McpsIndication.RxSlot = RX_SLOT_WIN_CLASS_B_MULTICAST_SLOT;
        }
    }

    macHdr.Value = payload[pktHeaderLen++];

    switch( macHdr.Bits.MType )
    {
        case FRAME_TYPE_JOIN_ACCEPT:
            macMsgJoinAccept.Buffer = payload;
            macMsgJoinAccept.BufSize = size;

            
            if( MacCtx.NvmCtx->NetworkActivation != ACTIVATION_TYPE_NONE )
            {
                MacCtx.McpsIndication.Status = LORAMAC_EVENT_INFO_STATUS_ERROR;
                PrepareRxDoneAbort( );
                return;
            }
            macCryptoStatus = LoRaMacCryptoHandleJoinAccept( JOIN_REQ, SecureElementGetJoinEui( ), &macMsgJoinAccept );

            if( LORAMAC_CRYPTO_SUCCESS == macCryptoStatus )
            {
                
                MacCtx.NvmCtx->NetID = ( uint32_t ) macMsgJoinAccept.NetID[0];
                MacCtx.NvmCtx->NetID |= ( ( uint32_t ) macMsgJoinAccept.NetID[1] << 8 );
                MacCtx.NvmCtx->NetID |= ( ( uint32_t ) macMsgJoinAccept.NetID[2] << 16 );

                
                MacCtx.NvmCtx->DevAddr = macMsgJoinAccept.DevAddr;

                
                MacCtx.NvmCtx->MacParams.Rx1DrOffset = macMsgJoinAccept.DLSettings.Bits.RX1DRoffset;
                MacCtx.NvmCtx->MacParams.Rx2Channel.Datarate = macMsgJoinAccept.DLSettings.Bits.RX2DataRate;
                MacCtx.NvmCtx->MacParams.RxCChannel.Datarate = macMsgJoinAccept.DLSettings.Bits.RX2DataRate;

                
                MacCtx.NvmCtx->MacParams.ReceiveDelay1 = macMsgJoinAccept.RxDelay;
                if( MacCtx.NvmCtx->MacParams.ReceiveDelay1 == 0 )
                {
                    MacCtx.NvmCtx->MacParams.ReceiveDelay1 = 1;
                }
                MacCtx.NvmCtx->MacParams.ReceiveDelay1 *= 1000;
                MacCtx.NvmCtx->MacParams.ReceiveDelay2 = MacCtx.NvmCtx->MacParams.ReceiveDelay1 + 1000;

                MacCtx.NvmCtx->Version.Fields.Minor = 0;

                
                applyCFList.Payload = macMsgJoinAccept.CFList;
                
                applyCFList.Size = size - 17;

                RegionApplyCFList( MacCtx.NvmCtx->Region, &applyCFList );

                MacCtx.NvmCtx->NetworkActivation = ACTIVATION_TYPE_OTAA;

                
                if( LoRaMacConfirmQueueIsCmdActive( MLME_JOIN ) == true )
                {
                    LoRaMacConfirmQueueSetStatus( LORAMAC_EVENT_INFO_STATUS_OK, MLME_JOIN );
                }
            }
            else {
                
                if( LoRaMacConfirmQueueIsCmdActive( MLME_JOIN ) == true )
                {
                    LoRaMacConfirmQueueSetStatus( LORAMAC_EVENT_INFO_STATUS_JOIN_FAIL, MLME_JOIN );
                }
            }
            break;
        case FRAME_TYPE_DATA_CONFIRMED_DOWN:
            MacCtx.McpsIndication.McpsIndication = MCPS_CONFIRMED;
            
        case FRAME_TYPE_DATA_UNCONFIRMED_DOWN:
            
            getPhy.UplinkDwellTime = MacCtx.NvmCtx->MacParams.DownlinkDwellTime;
            getPhy.Datarate = MacCtx.McpsIndication.RxDatarate;
            getPhy.Attribute = PHY_MAX_PAYLOAD;
            phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
            if( MAX( 0, ( int16_t )( ( int16_t ) size - ( int16_t ) LORA_MAC_FRMPAYLOAD_OVERHEAD ) ) > ( int16_t )phyParam.Value )
            {
                MacCtx.McpsIndication.Status = LORAMAC_EVENT_INFO_STATUS_ERROR;
                PrepareRxDoneAbort( );
                return;
            }
            macMsgData.Buffer = payload;
            macMsgData.BufSize = size;
            macMsgData.FRMPayload = MacCtx.RxPayload;
            macMsgData.FRMPayloadSize = LORAMAC_PHY_MAXPAYLOAD;

            if( LORAMAC_PARSER_SUCCESS != LoRaMacParserData( &macMsgData ) )
            {
                MacCtx.McpsIndication.Status = LORAMAC_EVENT_INFO_STATUS_ERROR;
                PrepareRxDoneAbort( );
                return;
            }

            
            MacCtx.McpsIndication.DevAddress = macMsgData.FHDR.DevAddr;

            FType_t fType;
            if( LORAMAC_STATUS_OK != DetermineFrameType( &macMsgData, &fType ) )
            {
                MacCtx.McpsIndication.Status = LORAMAC_EVENT_INFO_STATUS_ERROR;
                PrepareRxDoneAbort( );
                return;
            }

            
            multicast = 0;
            downLinkCounter = 0;
            for( uint8_t i = 0; i < LORAMAC_MAX_MC_CTX; i++ )
            {
                if( ( MacCtx.NvmCtx->MulticastChannelList[i].ChannelParams.Address == macMsgData.FHDR.DevAddr ) && ( MacCtx.NvmCtx->MulticastChannelList[i].ChannelParams.IsEnabled == true ) )
                {
                    multicast = 1;
                    addrID = MacCtx.NvmCtx->MulticastChannelList[i].ChannelParams.GroupID;
                    downLinkCounter = *( MacCtx.NvmCtx->MulticastChannelList[i].DownLinkCounter );
                    address = MacCtx.NvmCtx->MulticastChannelList[i].ChannelParams.Address;
                    if( MacCtx.NvmCtx->DeviceClass == CLASS_C )
                    {
                        MacCtx.McpsIndication.RxSlot = RX_SLOT_WIN_CLASS_C_MULTICAST;
                    }
                    break;
                }
            }

            
            if( ( multicast == 1 ) && ( ( fType != FRAME_TYPE_D ) || ( macMsgData.FHDR.FCtrl.Bits.Ack == true ) || ( macMsgData.FHDR.FCtrl.Bits.AdrAckReq == true ) ) )

            {
                MacCtx.McpsIndication.Status = LORAMAC_EVENT_INFO_STATUS_ERROR;
                PrepareRxDoneAbort( );
                return;
            }

            
            getPhy.Attribute = PHY_MAX_FCNT_GAP;
            phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );

            
            macCryptoStatus = GetFCntDown( addrID, fType, &macMsgData, MacCtx.NvmCtx->Version, phyParam.Value, &fCntID, &downLinkCounter );
            if( macCryptoStatus != LORAMAC_CRYPTO_SUCCESS )
            {
                if( macCryptoStatus == LORAMAC_CRYPTO_FAIL_FCNT_DUPLICATED )
                {
                    
                    MacCtx.McpsIndication.Status = LORAMAC_EVENT_INFO_STATUS_DOWNLINK_REPEATED;
                    if( ( MacCtx.NvmCtx->Version.Fields.Minor == 0 ) && ( macHdr.Bits.MType == FRAME_TYPE_DATA_CONFIRMED_DOWN ) && ( MacCtx.NvmCtx->LastRxMic == macMsgData.MIC ) )
                    {
                        MacCtx.NvmCtx->SrvAckRequested = true;
                    }
                }
                else if( macCryptoStatus == LORAMAC_CRYPTO_FAIL_MAX_GAP_FCNT )
                {
                    
                    MacCtx.McpsIndication.Status = LORAMAC_EVENT_INFO_STATUS_DOWNLINK_TOO_MANY_FRAMES_LOSS;
                }
                else {
                    
                    MacCtx.McpsIndication.Status = LORAMAC_EVENT_INFO_STATUS_ERROR;
                }
                MacCtx.McpsIndication.DownLinkCounter = downLinkCounter;
                PrepareRxDoneAbort( );
                return;
            }

            macCryptoStatus = LoRaMacCryptoUnsecureMessage( addrID, address, fCntID, downLinkCounter, &macMsgData );
            if( macCryptoStatus != LORAMAC_CRYPTO_SUCCESS )
            {
                if( macCryptoStatus == LORAMAC_CRYPTO_FAIL_ADDRESS )
                {
                    
                    MacCtx.McpsIndication.Status = LORAMAC_EVENT_INFO_STATUS_ADDRESS_FAIL;
                }
                else {
                    
                    MacCtx.McpsIndication.Status = LORAMAC_EVENT_INFO_STATUS_MIC_FAIL;
                }
                PrepareRxDoneAbort( );
                return;
            }

            
            MacCtx.McpsIndication.Status = LORAMAC_EVENT_INFO_STATUS_OK;
            MacCtx.McpsIndication.Multicast = multicast;
            MacCtx.McpsIndication.FramePending = macMsgData.FHDR.FCtrl.Bits.FPending;
            MacCtx.McpsIndication.Buffer = NULL;
            MacCtx.McpsIndication.BufferSize = 0;
            MacCtx.McpsIndication.DownLinkCounter = downLinkCounter;
            MacCtx.McpsIndication.AckReceived = macMsgData.FHDR.FCtrl.Bits.Ack;

            MacCtx.McpsConfirm.Status = LORAMAC_EVENT_INFO_STATUS_OK;
            MacCtx.McpsConfirm.AckReceived = macMsgData.FHDR.FCtrl.Bits.Ack;

            
            if( ( MacCtx.McpsIndication.RxSlot == RX_SLOT_WIN_1 ) || ( MacCtx.McpsIndication.RxSlot == RX_SLOT_WIN_2 ) )
            {
                MacCtx.NvmCtx->AdrAckCounter = 0;
            }

            
            if( multicast == 1 )
            {
                MacCtx.McpsIndication.McpsIndication = MCPS_MULTICAST;
            }
            else {
                if( macHdr.Bits.MType == FRAME_TYPE_DATA_CONFIRMED_DOWN )
                {
                    MacCtx.NvmCtx->SrvAckRequested = true;
                    if( MacCtx.NvmCtx->Version.Fields.Minor == 0 )
                    {
                        MacCtx.NvmCtx->LastRxMic = macMsgData.MIC;
                    }
                    MacCtx.McpsIndication.McpsIndication = MCPS_CONFIRMED;
                }
                else {
                    MacCtx.NvmCtx->SrvAckRequested = false;
                    MacCtx.McpsIndication.McpsIndication = MCPS_UNCONFIRMED;
                }
            }

            RemoveMacCommands( MacCtx.McpsIndication.RxSlot, macMsgData.FHDR.FCtrl, MacCtx.McpsConfirm.McpsRequest );

            switch( fType )
            {
                case FRAME_TYPE_A:
                {  

                    
                    ProcessMacCommands( macMsgData.FHDR.FOpts, 0, macMsgData.FHDR.FCtrl.Bits.FOptsLen, snr, MacCtx.McpsIndication.RxSlot );
                    MacCtx.McpsIndication.Port = macMsgData.FPort;
                    MacCtx.McpsIndication.Buffer = macMsgData.FRMPayload;
                    MacCtx.McpsIndication.BufferSize = macMsgData.FRMPayloadSize;
                    MacCtx.McpsIndication.RxData = true;
                    break;
                }
                case FRAME_TYPE_B:
                {  

                    
                    ProcessMacCommands( macMsgData.FHDR.FOpts, 0, macMsgData.FHDR.FCtrl.Bits.FOptsLen, snr, MacCtx.McpsIndication.RxSlot );
                    MacCtx.McpsIndication.Port = macMsgData.FPort;
                    break;
                }
                case FRAME_TYPE_C:
                {  

                    
                    ProcessMacCommands( macMsgData.FRMPayload, 0, macMsgData.FRMPayloadSize, snr, MacCtx.McpsIndication.RxSlot );
                    MacCtx.McpsIndication.Port = macMsgData.FPort;
                    break;
                }
                case FRAME_TYPE_D:
                {  

                    
                    MacCtx.McpsIndication.Port = macMsgData.FPort;
                    MacCtx.McpsIndication.Buffer = macMsgData.FRMPayload;
                    MacCtx.McpsIndication.BufferSize = macMsgData.FRMPayloadSize;
                    MacCtx.McpsIndication.RxData = true;
                    break;
                }
                default:
                    MacCtx.McpsIndication.Status = LORAMAC_EVENT_INFO_STATUS_ERROR;
                    PrepareRxDoneAbort( );
                    break;
            }

            
            
            MacCtx.MacFlags.Bits.McpsInd = 1;

            break;
        case FRAME_TYPE_PROPRIETARY:
            memcpy1( MacCtx.RxPayload, &payload[pktHeaderLen], size - pktHeaderLen );

            MacCtx.McpsIndication.McpsIndication = MCPS_PROPRIETARY;
            MacCtx.McpsIndication.Status = LORAMAC_EVENT_INFO_STATUS_OK;
            MacCtx.McpsIndication.Buffer = MacCtx.RxPayload;
            MacCtx.McpsIndication.BufferSize = size - pktHeaderLen;

            MacCtx.MacFlags.Bits.McpsInd = 1;
            break;
        default:
            MacCtx.McpsIndication.Status = LORAMAC_EVENT_INFO_STATUS_ERROR;
            PrepareRxDoneAbort( );
            break;
    }

    
    if( MacCtx.NodeAckRequested == true )
    {
        if( MacCtx.McpsConfirm.AckReceived == true )
        {
            OnAckTimeoutTimerEvent( NULL );
        }
    }
    else {
        if( MacCtx.NvmCtx->DeviceClass == CLASS_C )
        {
            OnAckTimeoutTimerEvent( NULL );
        }
    }
    MacCtx.MacFlags.Bits.MacDone = 1;

    UpdateRxSlotIdleState( );
}

static void ProcessRadioTxTimeout( void )
{
    if( MacCtx.NvmCtx->DeviceClass != CLASS_C )
    {
        Radio.Sleep( );
    }
    UpdateRxSlotIdleState( );

    MacCtx.McpsConfirm.Status = LORAMAC_EVENT_INFO_STATUS_TX_TIMEOUT;
    LoRaMacConfirmQueueSetStatusCmn( LORAMAC_EVENT_INFO_STATUS_TX_TIMEOUT );
    if( MacCtx.NodeAckRequested == true )
    {
        MacCtx.AckTimeoutRetry = true;
    }
    MacCtx.MacFlags.Bits.MacDone = 1;
}

static void HandleRadioRxErrorTimeout( LoRaMacEventInfoStatus_t rx1EventInfoStatus, LoRaMacEventInfoStatus_t rx2EventInfoStatus )
{
    bool classBRx = false;

    if( MacCtx.NvmCtx->DeviceClass != CLASS_C )
    {
        Radio.Sleep( );
    }

    if( LoRaMacClassBIsBeaconExpected( ) == true )
    {
        LoRaMacClassBSetBeaconState( BEACON_STATE_TIMEOUT );
        LoRaMacClassBBeaconTimerEvent( NULL );
        classBRx = true;
    }
    if( MacCtx.NvmCtx->DeviceClass == CLASS_B )
    {
        if( LoRaMacClassBIsPingExpected( ) == true )
        {
            LoRaMacClassBSetPingSlotState( PINGSLOT_STATE_CALC_PING_OFFSET );
            LoRaMacClassBPingSlotTimerEvent( NULL );
            classBRx = true;
        }
        if( LoRaMacClassBIsMulticastExpected( ) == true )
        {
            LoRaMacClassBSetMulticastSlotState( PINGSLOT_STATE_CALC_PING_OFFSET );
            LoRaMacClassBMulticastSlotTimerEvent( NULL );
            classBRx = true;
        }
    }

    if( classBRx == false )
    {
        if( MacCtx.RxSlot == RX_SLOT_WIN_1 )
        {
            if( MacCtx.NodeAckRequested == true )
            {
                MacCtx.McpsConfirm.Status = rx1EventInfoStatus;
            }
            LoRaMacConfirmQueueSetStatusCmn( rx1EventInfoStatus );

            if( TimerGetElapsedTime( MacCtx.NvmCtx->LastTxDoneTime ) >= MacCtx.RxWindow2Delay )
            {
                TimerStop( &MacCtx.RxWindowTimer2 );
                MacCtx.MacFlags.Bits.MacDone = 1;
            }
        }
        else {
            if( MacCtx.NodeAckRequested == true )
            {
                MacCtx.McpsConfirm.Status = rx2EventInfoStatus;
            }
            LoRaMacConfirmQueueSetStatusCmn( rx2EventInfoStatus );

            if( MacCtx.NvmCtx->DeviceClass != CLASS_C )
            {
                MacCtx.MacFlags.Bits.MacDone = 1;
            }
        }
    }

    UpdateRxSlotIdleState( );
}

static void ProcessRadioRxError( void )
{
    HandleRadioRxErrorTimeout( LORAMAC_EVENT_INFO_STATUS_RX1_ERROR, LORAMAC_EVENT_INFO_STATUS_RX2_ERROR );
}

static void ProcessRadioRxTimeout( void )
{
    HandleRadioRxErrorTimeout( LORAMAC_EVENT_INFO_STATUS_RX1_TIMEOUT, LORAMAC_EVENT_INFO_STATUS_RX2_TIMEOUT );
}

static void LoRaMacHandleIrqEvents( void )
{
    LoRaMacRadioEvents_t events;

    CRITICAL_SECTION_BEGIN( );
    events = LoRaMacRadioEvents;
    LoRaMacRadioEvents.Value = 0;
    CRITICAL_SECTION_END( );

    if( events.Value != 0 )
    {
        if( events.Events.TxDone == 1 )
        {
            ProcessRadioTxDone( );
        }
        if( events.Events.RxDone == 1 )
        {
            ProcessRadioRxDone( );
        }
        if( events.Events.TxTimeout == 1 )
        {
            ProcessRadioTxTimeout( );
        }
        if( events.Events.RxError == 1 )
        {
            ProcessRadioRxError( );
        }
        if( events.Events.RxTimeout == 1 )
        {
            ProcessRadioRxTimeout( );
        }
    }
}

bool LoRaMacIsBusy( void )
{
    if( ( MacCtx.MacState == LORAMAC_IDLE ) && ( MacCtx.AllowRequests == LORAMAC_REQUEST_HANDLING_ON ) )
    {
        return false;
    }
    return true;
}


static void LoRaMacEnableRequests( LoRaMacRequestHandling_t requestState )
{
    MacCtx.AllowRequests = requestState;
}

static void LoRaMacHandleRequestEvents( void )
{
    
    LoRaMacFlags_t reqEvents = MacCtx.MacFlags;

    if( MacCtx.MacState == LORAMAC_IDLE )
    {
        
        if( MacCtx.MacFlags.Bits.McpsReq == 1 )
        {
            MacCtx.MacFlags.Bits.McpsReq = 0;
        }

        if( MacCtx.MacFlags.Bits.MlmeReq == 1 )
        {
            MacCtx.MacFlags.Bits.MlmeReq = 0;
        }

        
        LoRaMacEnableRequests( LORAMAC_REQUEST_HANDLING_ON );

        
        if( reqEvents.Bits.McpsReq == 1 )
        {
            MacCtx.MacPrimitives->MacMcpsConfirm( &MacCtx.McpsConfirm );
        }

        if( reqEvents.Bits.MlmeReq == 1 )
        {
            LoRaMacConfirmQueueHandleCb( &MacCtx.MlmeConfirm );
            if( LoRaMacConfirmQueueGetCnt( ) > 0 )
            {
                MacCtx.MacFlags.Bits.MlmeReq = 1;
            }
        }

        
        LoRaMacClassBResumeBeaconing( );

        
        MacCtx.MacFlags.Bits.MacDone = 0;
    }
}

static void LoRaMacHandleScheduleUplinkEvent( void )
{
    
    if( MacCtx.MacState == LORAMAC_IDLE )
    {
        
        bool isStickyMacCommandPending = false;
        LoRaMacCommandsStickyCmdsPending( &isStickyMacCommandPending );
        if( isStickyMacCommandPending == true )
        {
            SetMlmeScheduleUplinkIndication( );
        }
    }
}

static void LoRaMacHandleIndicationEvents( void )
{
    
    if( MacCtx.MacFlags.Bits.MlmeInd == 1 )
    {
        MacCtx.MacFlags.Bits.MlmeInd = 0;
        MacCtx.MacPrimitives->MacMlmeIndication( &MacCtx.MlmeIndication );
    }

    if( MacCtx.MacFlags.Bits.MlmeSchedUplinkInd == 1 )
    {
        MlmeIndication_t schduleUplinkIndication;
        schduleUplinkIndication.MlmeIndication = MLME_SCHEDULE_UPLINK;
        schduleUplinkIndication.Status = LORAMAC_EVENT_INFO_STATUS_OK;

        MacCtx.MacPrimitives->MacMlmeIndication( &schduleUplinkIndication );
        MacCtx.MacFlags.Bits.MlmeSchedUplinkInd = 0;
    }

    
    if( MacCtx.MacFlags.Bits.McpsInd == 1 )
    {
        MacCtx.MacFlags.Bits.McpsInd = 0;
        MacCtx.MacPrimitives->MacMcpsIndication( &MacCtx.McpsIndication );
    }
}

static void LoRaMacHandleMcpsRequest( void )
{
    
    if( MacCtx.MacFlags.Bits.McpsReq == 1 )
    {
        bool stopRetransmission = false;
        bool waitForRetransmission = false;

        if( ( MacCtx.McpsConfirm.McpsRequest == MCPS_UNCONFIRMED ) || ( MacCtx.McpsConfirm.McpsRequest == MCPS_PROPRIETARY ) )
        {
            stopRetransmission = CheckRetransUnconfirmedUplink( );
        }
        else if( MacCtx.McpsConfirm.McpsRequest == MCPS_CONFIRMED )
        {
            if( MacCtx.AckTimeoutRetry == true )
            {
                stopRetransmission = CheckRetransConfirmedUplink( );

                if( MacCtx.NvmCtx->Version.Fields.Minor == 0 )
                {
                    if( stopRetransmission == false )
                    {
                        AckTimeoutRetriesProcess( );
                    }
                    else {
                        AckTimeoutRetriesFinalize( );
                    }
                }
            }
            else {
                waitForRetransmission = true;
            }
        }

        if( stopRetransmission == true )
        {
            TimerStop( &MacCtx.TxDelayedTimer );
            MacCtx.MacState &= ~LORAMAC_TX_DELAYED;
            StopRetransmission( );
        }
        else if( waitForRetransmission == false )
        {
            MacCtx.MacFlags.Bits.MacDone = 0;
            
            MacCtx.AckTimeoutRetry = false;
            
            OnTxDelayedTimerEvent( NULL );
        }
    }
}

static void LoRaMacHandleMlmeRequest( void )
{
    
    if( MacCtx.MacFlags.Bits.MlmeReq == 1 )
    {
        if( ( LoRaMacConfirmQueueIsCmdActive( MLME_JOIN ) == true ) )
        {
            if( LoRaMacConfirmQueueGetStatus( MLME_JOIN ) == LORAMAC_EVENT_INFO_STATUS_OK )
            {
                MacCtx.ChannelsNbTransCounter = 0;
            }
            MacCtx.MacState &= ~LORAMAC_TX_RUNNING;
        }
        else if( ( LoRaMacConfirmQueueIsCmdActive( MLME_TXCW ) == true ) || ( LoRaMacConfirmQueueIsCmdActive( MLME_TXCW_1 ) == true ) )
        {
            MacCtx.MacState &= ~LORAMAC_TX_RUNNING;
        }
    }
}

static uint8_t LoRaMacCheckForBeaconAcquisition( void )
{
    if( ( LoRaMacConfirmQueueIsCmdActive( MLME_BEACON_ACQUISITION ) == true ) && ( MacCtx.MacFlags.Bits.McpsReq == 0 ) )
    {
        if( MacCtx.MacFlags.Bits.MlmeReq == 1 )
        {
            MacCtx.MacState &= ~LORAMAC_TX_RUNNING;
            return 0x01;
        }
    }
    return 0x00;
}

static void LoRaMacCheckForRxAbort( void )
{
    
    if( ( MacCtx.MacState & LORAMAC_RX_ABORT ) == LORAMAC_RX_ABORT )
    {
        MacCtx.MacState &= ~LORAMAC_RX_ABORT;
        MacCtx.MacState &= ~LORAMAC_TX_RUNNING;
    }
}


void LoRaMacProcess( void )
{
    uint8_t noTx = false;

    LoRaMacHandleIrqEvents( );
    LoRaMacClassBProcess( );

    
    if( MacCtx.MacFlags.Bits.MacDone == 1 )
    {
        LoRaMacEnableRequests( LORAMAC_REQUEST_HANDLING_OFF );
        LoRaMacCheckForRxAbort( );

        
        if( IsRequestPending( ) > 0 )
        {
            noTx |= LoRaMacCheckForBeaconAcquisition( );
        }

        if( noTx == 0x00 )
        {
            LoRaMacHandleMlmeRequest( );
            LoRaMacHandleMcpsRequest( );
        }
        LoRaMacHandleRequestEvents( );
        LoRaMacHandleScheduleUplinkEvent( );
        LoRaMacEnableRequests( LORAMAC_REQUEST_HANDLING_ON );
    }
    LoRaMacHandleIndicationEvents( );
    if( MacCtx.RxSlot == RX_SLOT_WIN_CLASS_C )
    {
        OpenContinuousRxCWindow( );
    }
}

static void OnTxDelayedTimerEvent( void* context )
{
    TimerStop( &MacCtx.TxDelayedTimer );
    MacCtx.MacState &= ~LORAMAC_TX_DELAYED;

    
    switch( ScheduleTx( true ) )
    {
        case LORAMAC_STATUS_OK:
        case LORAMAC_STATUS_DUTYCYCLE_RESTRICTED:
        {
            break;
        }
        default:
        {
            
            MacCtx.McpsConfirm.Datarate = MacCtx.NvmCtx->MacParams.ChannelsDatarate;
            MacCtx.McpsConfirm.NbRetries = MacCtx.AckTimeoutRetriesCounter;
            MacCtx.McpsConfirm.Status = LORAMAC_EVENT_INFO_STATUS_TX_DR_PAYLOAD_SIZE_ERROR;
            LoRaMacConfirmQueueSetStatusCmn( LORAMAC_EVENT_INFO_STATUS_TX_DR_PAYLOAD_SIZE_ERROR );
            StopRetransmission( );
            break;
        }
    }
}

static void OnRxWindow1TimerEvent( void* context )
{
    MacCtx.RxWindow1Config.Channel = MacCtx.Channel;
    MacCtx.RxWindow1Config.DrOffset = MacCtx.NvmCtx->MacParams.Rx1DrOffset;
    MacCtx.RxWindow1Config.DownlinkDwellTime = MacCtx.NvmCtx->MacParams.DownlinkDwellTime;
    MacCtx.RxWindow1Config.RxContinuous = false;
    MacCtx.RxWindow1Config.RxSlot = RX_SLOT_WIN_1;

    RxWindowSetup( &MacCtx.RxWindowTimer1, &MacCtx.RxWindow1Config );
}

static void OnRxWindow2TimerEvent( void* context )
{
    
    
    if( MacCtx.RxSlot == RX_SLOT_WIN_1 )
    {
        return;
    }
    MacCtx.RxWindow2Config.Channel = MacCtx.Channel;
    MacCtx.RxWindow2Config.Frequency = MacCtx.NvmCtx->MacParams.Rx2Channel.Frequency;
    MacCtx.RxWindow2Config.DownlinkDwellTime = MacCtx.NvmCtx->MacParams.DownlinkDwellTime;
    MacCtx.RxWindow2Config.RxContinuous = false;
    MacCtx.RxWindow2Config.RxSlot = RX_SLOT_WIN_2;

    RxWindowSetup( &MacCtx.RxWindowTimer2, &MacCtx.RxWindow2Config );
}

static void OnAckTimeoutTimerEvent( void* context )
{
    TimerStop( &MacCtx.AckTimeoutTimer );

    if( MacCtx.NodeAckRequested == true )
    {
        MacCtx.AckTimeoutRetry = true;
    }
    if( MacCtx.NvmCtx->DeviceClass == CLASS_C )
    {
        MacCtx.MacFlags.Bits.MacDone = 1;
    }
    if( ( MacCtx.MacCallbacks != NULL ) && ( MacCtx.MacCallbacks->MacProcessNotify != NULL ) )
    {
        MacCtx.MacCallbacks->MacProcessNotify( );
    }
}

static LoRaMacCryptoStatus_t GetFCntDown( AddressIdentifier_t addrID, FType_t fType, LoRaMacMessageData_t* macMsg, Version_t lrWanVersion, uint16_t maxFCntGap, FCntIdentifier_t* fCntID, uint32_t* currentDown )
{
    if( ( macMsg == NULL ) || ( fCntID == NULL ) || ( currentDown == NULL ) )
    {
        return LORAMAC_CRYPTO_ERROR_NPE;
    }

    
    switch( addrID )
    {
        case UNICAST_DEV_ADDR:
            if( lrWanVersion.Fields.Minor == 1 )
            {
                if( ( fType == FRAME_TYPE_A ) || ( fType == FRAME_TYPE_D ) )
                {
                    *fCntID = A_FCNT_DOWN;
                }
                else {
                    *fCntID = N_FCNT_DOWN;
                }
            }
            else {
                *fCntID = FCNT_DOWN;
            }
            break;
        case MULTICAST_0_ADDR:
            *fCntID = MC_FCNT_DOWN_0;
            break;
        case MULTICAST_1_ADDR:
            *fCntID = MC_FCNT_DOWN_1;
            break;
        case MULTICAST_2_ADDR:
            *fCntID = MC_FCNT_DOWN_2;
            break;
        case MULTICAST_3_ADDR:
            *fCntID = MC_FCNT_DOWN_3;
            break;
        default:
            return LORAMAC_CRYPTO_FAIL_FCNT_ID;
    }

    return LoRaMacCryptoGetFCntDown( *fCntID, maxFCntGap, macMsg->FHDR.FCnt, currentDown );
}

static LoRaMacStatus_t SwitchClass( DeviceClass_t deviceClass )
{
    LoRaMacStatus_t status = LORAMAC_STATUS_PARAMETER_INVALID;

    switch( MacCtx.NvmCtx->DeviceClass )
    {
        case CLASS_A:
        {
            if( deviceClass == CLASS_A )
            {
                
                MacCtx.NvmCtx->MacParams.RxCChannel = MacCtx.NvmCtx->MacParams.Rx2Channel;
            }
            if( deviceClass == CLASS_B )
            {
                status = LoRaMacClassBSwitchClass( deviceClass );
                if( status == LORAMAC_STATUS_OK )
                {
                    MacCtx.NvmCtx->DeviceClass = deviceClass;
                }
            }

            if( deviceClass == CLASS_C )
            {
                MacCtx.NvmCtx->DeviceClass = deviceClass;

                MacCtx.RxWindowCConfig = MacCtx.RxWindow2Config;
                MacCtx.RxWindowCConfig.RxSlot = RX_SLOT_WIN_CLASS_C;

                for( int8_t i = 0; i < LORAMAC_MAX_MC_CTX; i++ )
                {
                    if( MacCtx.NvmCtx->MulticastChannelList[i].ChannelParams.IsEnabled == true )
                    
                    {
                        MacCtx.NvmCtx->MacParams.RxCChannel.Frequency = MacCtx.NvmCtx->MulticastChannelList[i].ChannelParams.RxParams.ClassC.Frequency;
                        MacCtx.NvmCtx->MacParams.RxCChannel.Datarate = MacCtx.NvmCtx->MulticastChannelList[i].ChannelParams.RxParams.ClassC.Datarate;

                        MacCtx.RxWindowCConfig.Channel = MacCtx.Channel;
                        MacCtx.RxWindowCConfig.Frequency = MacCtx.NvmCtx->MacParams.RxCChannel.Frequency;
                        MacCtx.RxWindowCConfig.DownlinkDwellTime = MacCtx.NvmCtx->MacParams.DownlinkDwellTime;
                        MacCtx.RxWindowCConfig.RxSlot = RX_SLOT_WIN_CLASS_C_MULTICAST;
                        MacCtx.RxWindowCConfig.RxContinuous = true;
                        break;
                    }
                }

                
                MacCtx.NodeAckRequested = false;
                
                Radio.Sleep( );

                OpenContinuousRxCWindow( );

                status = LORAMAC_STATUS_OK;
            }
            break;
        }
        case CLASS_B:
        {
            status = LoRaMacClassBSwitchClass( deviceClass );
            if( status == LORAMAC_STATUS_OK )
            {
                MacCtx.NvmCtx->DeviceClass = deviceClass;
            }
            break;
        }
        case CLASS_C:
        {
            if( deviceClass == CLASS_A )
            {
                MacCtx.NvmCtx->DeviceClass = deviceClass;

                
                Radio.Sleep( );

                status = LORAMAC_STATUS_OK;
            }
            break;
        }
    }

    return status;
}

static uint8_t GetMaxAppPayloadWithoutFOptsLength( int8_t datarate )
{
    GetPhyParams_t getPhy;
    PhyParam_t phyParam;

    
    getPhy.UplinkDwellTime = MacCtx.NvmCtx->MacParams.UplinkDwellTime;
    getPhy.Datarate = datarate;
    getPhy.Attribute = PHY_MAX_PAYLOAD;
    phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );

    return phyParam.Value;
}

static bool ValidatePayloadLength( uint8_t lenN, int8_t datarate, uint8_t fOptsLen )
{
    uint16_t maxN = 0;
    uint16_t payloadSize = 0;

    maxN = GetMaxAppPayloadWithoutFOptsLength( datarate );

    
    payloadSize = ( lenN + fOptsLen );

    
    if( ( payloadSize <= maxN ) && ( payloadSize <= LORAMAC_PHY_MAXPAYLOAD ) )
    {
        return true;
    }
    return false;
}

static void SetMlmeScheduleUplinkIndication( void )
{
    MacCtx.MacFlags.Bits.MlmeSchedUplinkInd = 1;
}

static void ProcessMacCommands( uint8_t *payload, uint8_t macIndex, uint8_t commandsSize, int8_t snr, LoRaMacRxSlot_t rxSlot )
{
    uint8_t status = 0;
    bool adrBlockFound = false;
    uint8_t macCmdPayload[2] = { 0x00, 0x00 };

    while( macIndex < commandsSize )
    {
        
        if( ( LoRaMacCommandsGetCmdSize( payload[macIndex] ) + macIndex ) > commandsSize )
        {
            return;
        }

        
        switch( payload[macIndex++] )
        {
            case SRV_MAC_LINK_CHECK_ANS:
            {
                if( LoRaMacConfirmQueueIsCmdActive( MLME_LINK_CHECK ) == true )
                {
                    LoRaMacConfirmQueueSetStatus( LORAMAC_EVENT_INFO_STATUS_OK, MLME_LINK_CHECK );
                    MacCtx.MlmeConfirm.DemodMargin = payload[macIndex++];
                    MacCtx.MlmeConfirm.NbGateways = payload[macIndex++];
                }
                break;
            }
            case SRV_MAC_LINK_ADR_REQ:
            {
                LinkAdrReqParams_t linkAdrReq;
                int8_t linkAdrDatarate = DR_0;
                int8_t linkAdrTxPower = TX_POWER_0;
                uint8_t linkAdrNbRep = 0;
                uint8_t linkAdrNbBytesParsed = 0;

                if( adrBlockFound == false )
                {
                    adrBlockFound = true;

                    
                    linkAdrReq.Payload = &payload[macIndex - 1];
                    linkAdrReq.PayloadSize = commandsSize - ( macIndex - 1 );
                    linkAdrReq.AdrEnabled = MacCtx.NvmCtx->AdrCtrlOn;
                    linkAdrReq.UplinkDwellTime = MacCtx.NvmCtx->MacParams.UplinkDwellTime;
                    linkAdrReq.CurrentDatarate = MacCtx.NvmCtx->MacParams.ChannelsDatarate;
                    linkAdrReq.CurrentTxPower = MacCtx.NvmCtx->MacParams.ChannelsTxPower;
                    linkAdrReq.CurrentNbRep = MacCtx.NvmCtx->MacParams.ChannelsNbTrans;
                    linkAdrReq.Version = MacCtx.NvmCtx->Version;

                    
                    status = RegionLinkAdrReq( MacCtx.NvmCtx->Region, &linkAdrReq, &linkAdrDatarate, &linkAdrTxPower, &linkAdrNbRep, &linkAdrNbBytesParsed );

                    if( ( status & 0x07 ) == 0x07 )
                    {
                        MacCtx.NvmCtx->MacParams.ChannelsDatarate = linkAdrDatarate;
                        MacCtx.NvmCtx->MacParams.ChannelsTxPower = linkAdrTxPower;
                        MacCtx.NvmCtx->MacParams.ChannelsNbTrans = linkAdrNbRep;
                    }

                    
                    for( uint8_t i = 0; i < ( linkAdrNbBytesParsed / 5 ); i++ )
                    {
                        LoRaMacCommandsAddCmd( MOTE_MAC_LINK_ADR_ANS, &status, 1 );
                    }
                    
                    macIndex += linkAdrNbBytesParsed - 1;
                }
                break;
            }
            case SRV_MAC_DUTY_CYCLE_REQ:
            {
                MacCtx.NvmCtx->MaxDCycle = payload[macIndex++] & 0x0F;
                MacCtx.NvmCtx->AggregatedDCycle = 1 << MacCtx.NvmCtx->MaxDCycle;
                LoRaMacCommandsAddCmd( MOTE_MAC_DUTY_CYCLE_ANS, macCmdPayload, 0 );
                break;
            }
            case SRV_MAC_RX_PARAM_SETUP_REQ:
            {
                RxParamSetupReqParams_t rxParamSetupReq;
                status = 0x07;

                rxParamSetupReq.DrOffset = ( payload[macIndex] >> 4 ) & 0x07;
                rxParamSetupReq.Datarate = payload[macIndex] & 0x0F;
                macIndex++;

                rxParamSetupReq.Frequency = ( uint32_t ) payload[macIndex++];
                rxParamSetupReq.Frequency |= ( uint32_t ) payload[macIndex++] << 8;
                rxParamSetupReq.Frequency |= ( uint32_t ) payload[macIndex++] << 16;
                rxParamSetupReq.Frequency *= 100;

                
                status = RegionRxParamSetupReq( MacCtx.NvmCtx->Region, &rxParamSetupReq );

                if( ( status & 0x07 ) == 0x07 )
                {
                    MacCtx.NvmCtx->MacParams.Rx2Channel.Datarate = rxParamSetupReq.Datarate;
                    MacCtx.NvmCtx->MacParams.RxCChannel.Datarate = rxParamSetupReq.Datarate;
                    MacCtx.NvmCtx->MacParams.Rx2Channel.Frequency = rxParamSetupReq.Frequency;
                    MacCtx.NvmCtx->MacParams.RxCChannel.Frequency = rxParamSetupReq.Frequency;
                    MacCtx.NvmCtx->MacParams.Rx1DrOffset = rxParamSetupReq.DrOffset;
                }
                macCmdPayload[0] = status;
                LoRaMacCommandsAddCmd( MOTE_MAC_RX_PARAM_SETUP_ANS, macCmdPayload, 1 );
                
                SetMlmeScheduleUplinkIndication( );
                break;
            }
            case SRV_MAC_DEV_STATUS_REQ:
            {
                uint8_t batteryLevel = BAT_LEVEL_NO_MEASURE;
                if( ( MacCtx.MacCallbacks != NULL ) && ( MacCtx.MacCallbacks->GetBatteryLevel != NULL ) )
                {
                    batteryLevel = MacCtx.MacCallbacks->GetBatteryLevel( );
                }
                macCmdPayload[0] = batteryLevel;
                macCmdPayload[1] = ( uint8_t )( snr & 0x3F );
                LoRaMacCommandsAddCmd( MOTE_MAC_DEV_STATUS_ANS, macCmdPayload, 2 );
                break;
            }
            case SRV_MAC_NEW_CHANNEL_REQ:
            {
                NewChannelReqParams_t newChannelReq;
                ChannelParams_t chParam;
                status = 0x03;

                newChannelReq.ChannelId = payload[macIndex++];
                newChannelReq.NewChannel = &chParam;

                chParam.Frequency = ( uint32_t ) payload[macIndex++];
                chParam.Frequency |= ( uint32_t ) payload[macIndex++] << 8;
                chParam.Frequency |= ( uint32_t ) payload[macIndex++] << 16;
                chParam.Frequency *= 100;
                chParam.Rx1Frequency = 0;
                chParam.DrRange.Value = payload[macIndex++];

                status = RegionNewChannelReq( MacCtx.NvmCtx->Region, &newChannelReq );

                macCmdPayload[0] = status;
                LoRaMacCommandsAddCmd( MOTE_MAC_NEW_CHANNEL_ANS, macCmdPayload, 1 );
                break;
            }
            case SRV_MAC_RX_TIMING_SETUP_REQ:
            {
                uint8_t delay = payload[macIndex++] & 0x0F;

                if( delay == 0 )
                {
                    delay++;
                }
                MacCtx.NvmCtx->MacParams.ReceiveDelay1 = delay * 1000;
                MacCtx.NvmCtx->MacParams.ReceiveDelay2 = MacCtx.NvmCtx->MacParams.ReceiveDelay1 + 1000;
                LoRaMacCommandsAddCmd( MOTE_MAC_RX_TIMING_SETUP_ANS, macCmdPayload, 0 );
                
                SetMlmeScheduleUplinkIndication( );
                break;
            }
            case SRV_MAC_TX_PARAM_SETUP_REQ:
            {
                TxParamSetupReqParams_t txParamSetupReq;
                GetPhyParams_t getPhy;
                PhyParam_t phyParam;
                uint8_t eirpDwellTime = payload[macIndex++];

                txParamSetupReq.UplinkDwellTime = 0;
                txParamSetupReq.DownlinkDwellTime = 0;

                if( ( eirpDwellTime & 0x20 ) == 0x20 )
                {
                    txParamSetupReq.DownlinkDwellTime = 1;
                }
                if( ( eirpDwellTime & 0x10 ) == 0x10 )
                {
                    txParamSetupReq.UplinkDwellTime = 1;
                }
                txParamSetupReq.MaxEirp = eirpDwellTime & 0x0F;

                
                if( RegionTxParamSetupReq( MacCtx.NvmCtx->Region, &txParamSetupReq ) != -1 )
                {
                    
                    MacCtx.NvmCtx->MacParams.UplinkDwellTime = txParamSetupReq.UplinkDwellTime;
                    MacCtx.NvmCtx->MacParams.DownlinkDwellTime = txParamSetupReq.DownlinkDwellTime;
                    MacCtx.NvmCtx->MacParams.MaxEirp = LoRaMacMaxEirpTable[txParamSetupReq.MaxEirp];
                    
                    getPhy.Attribute = PHY_MIN_TX_DR;
                    getPhy.UplinkDwellTime = MacCtx.NvmCtx->MacParams.UplinkDwellTime;
                    phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
                    MacCtx.NvmCtx->MacParams.ChannelsDatarate = MAX( MacCtx.NvmCtx->MacParams.ChannelsDatarate, ( int8_t )phyParam.Value );

                    
                    LoRaMacCommandsAddCmd( MOTE_MAC_TX_PARAM_SETUP_ANS, macCmdPayload, 0 );
                }
                break;
            }
            case SRV_MAC_DL_CHANNEL_REQ:
            {
                DlChannelReqParams_t dlChannelReq;
                status = 0x03;

                dlChannelReq.ChannelId = payload[macIndex++];
                dlChannelReq.Rx1Frequency = ( uint32_t ) payload[macIndex++];
                dlChannelReq.Rx1Frequency |= ( uint32_t ) payload[macIndex++] << 8;
                dlChannelReq.Rx1Frequency |= ( uint32_t ) payload[macIndex++] << 16;
                dlChannelReq.Rx1Frequency *= 100;

                status = RegionDlChannelReq( MacCtx.NvmCtx->Region, &dlChannelReq );
                macCmdPayload[0] = status;
                LoRaMacCommandsAddCmd( MOTE_MAC_DL_CHANNEL_ANS, macCmdPayload, 1 );
                
                SetMlmeScheduleUplinkIndication( );
                break;
            }
            case SRV_MAC_DEVICE_TIME_ANS:
            {
                SysTime_t gpsEpochTime = { 0 };
                SysTime_t sysTime = { 0 };
                SysTime_t sysTimeCurrent = { 0 };

                gpsEpochTime.Seconds = ( uint32_t )payload[macIndex++];
                gpsEpochTime.Seconds |= ( uint32_t )payload[macIndex++] << 8;
                gpsEpochTime.Seconds |= ( uint32_t )payload[macIndex++] << 16;
                gpsEpochTime.Seconds |= ( uint32_t )payload[macIndex++] << 24;
                gpsEpochTime.SubSeconds = payload[macIndex++];

                
                
                gpsEpochTime.SubSeconds = ( int16_t )( ( ( int32_t )gpsEpochTime.SubSeconds * 1000 ) >> 8 );

                
                sysTime = gpsEpochTime;
                
                sysTime.Seconds += UNIX_GPS_EPOCH_OFFSET;

                
                sysTimeCurrent = SysTimeGet( );
                sysTime = SysTimeAdd( sysTimeCurrent, SysTimeSub( sysTime, MacCtx.LastTxSysTime ) );

                
                SysTimeSet( sysTime );
                LoRaMacClassBDeviceTimeAns( );
                MacCtx.McpsIndication.DeviceTimeAnsReceived = true;
                break;
            }
            case SRV_MAC_PING_SLOT_INFO_ANS:
            {
                
                
                if( ( MacCtx.RxSlot != RX_SLOT_WIN_CLASS_B_PING_SLOT ) && ( MacCtx.RxSlot != RX_SLOT_WIN_CLASS_B_MULTICAST_SLOT ) )
                {
                    LoRaMacClassBPingSlotInfoAns( );
                }
                break;
            }
            case SRV_MAC_PING_SLOT_CHANNEL_REQ:
            {
                uint8_t status = 0x03;
                uint32_t frequency = 0;
                uint8_t datarate;

                frequency = ( uint32_t )payload[macIndex++];
                frequency |= ( uint32_t )payload[macIndex++] << 8;
                frequency |= ( uint32_t )payload[macIndex++] << 16;
                frequency *= 100;
                datarate = payload[macIndex++] & 0x0F;

                status = LoRaMacClassBPingSlotChannelReq( datarate, frequency );
                macCmdPayload[0] = status;
                LoRaMacCommandsAddCmd( MOTE_MAC_PING_SLOT_FREQ_ANS, macCmdPayload, 1 );
                break;
            }
            case SRV_MAC_BEACON_TIMING_ANS:
            {
                uint16_t beaconTimingDelay = 0;
                uint8_t beaconTimingChannel = 0;

                beaconTimingDelay = ( uint16_t )payload[macIndex++];
                beaconTimingDelay |= ( uint16_t )payload[macIndex++] << 8;
                beaconTimingChannel = payload[macIndex++];

                LoRaMacClassBBeaconTimingAns( beaconTimingDelay, beaconTimingChannel, RxDoneParams.LastRxDone );
                break;
            }
            case SRV_MAC_BEACON_FREQ_REQ:
                {
                    uint32_t frequency = 0;

                    frequency = ( uint32_t )payload[macIndex++];
                    frequency |= ( uint32_t )payload[macIndex++] << 8;
                    frequency |= ( uint32_t )payload[macIndex++] << 16;
                    frequency *= 100;

                    if( LoRaMacClassBBeaconFreqReq( frequency ) == true )
                    {
                        macCmdPayload[0] = 1;
                    }
                    else {
                        macCmdPayload[0] = 0;
                    }
                    LoRaMacCommandsAddCmd( MOTE_MAC_BEACON_FREQ_ANS, macCmdPayload, 1 );
                }
                break;
            default:
                
                return;
        }
    }
}

LoRaMacStatus_t Send( LoRaMacHeader_t* macHdr, uint8_t fPort, void* fBuffer, uint16_t fBufferSize )
{
    LoRaMacFrameCtrl_t fCtrl;
    LoRaMacStatus_t status = LORAMAC_STATUS_PARAMETER_INVALID;
    int8_t datarate = MacCtx.NvmCtx->MacParams.ChannelsDatarate;
    int8_t txPower = MacCtx.NvmCtx->MacParams.ChannelsTxPower;
    uint32_t adrAckCounter = MacCtx.NvmCtx->AdrAckCounter;
    CalcNextAdrParams_t adrNext;

    
    if( MacCtx.NvmCtx->NetworkActivation == ACTIVATION_TYPE_NONE )
    {
        return LORAMAC_STATUS_NO_NETWORK_JOINED;
    }
    if( MacCtx.NvmCtx->MaxDCycle == 0 )
    {
        MacCtx.NvmCtx->AggregatedTimeOff = 0;
    }

    fCtrl.Value = 0;
    fCtrl.Bits.FOptsLen      = 0;
    fCtrl.Bits.Adr           = MacCtx.NvmCtx->AdrCtrlOn;

    
    if( MacCtx.NvmCtx->DeviceClass == CLASS_B )
    {
        fCtrl.Bits.FPending      = 1;
    }
    else {
        fCtrl.Bits.FPending      = 0;
    }

    
    if( MacCtx.NvmCtx->SrvAckRequested == true )
    {
        fCtrl.Bits.Ack = 1;
    }

    
    adrNext.Version = MacCtx.NvmCtx->Version;
    adrNext.UpdateChanMask = true;
    adrNext.AdrEnabled = fCtrl.Bits.Adr;
    adrNext.AdrAckCounter = MacCtx.NvmCtx->AdrAckCounter;
    adrNext.AdrAckLimit = MacCtx.AdrAckLimit;
    adrNext.AdrAckDelay = MacCtx.AdrAckDelay;
    adrNext.Datarate = MacCtx.NvmCtx->MacParams.ChannelsDatarate;
    adrNext.TxPower = MacCtx.NvmCtx->MacParams.ChannelsTxPower;
    adrNext.UplinkDwellTime = MacCtx.NvmCtx->MacParams.UplinkDwellTime;
    adrNext.Region = MacCtx.NvmCtx->Region;

    fCtrl.Bits.AdrAckReq = LoRaMacAdrCalcNext( &adrNext, &MacCtx.NvmCtx->MacParams.ChannelsDatarate, &MacCtx.NvmCtx->MacParams.ChannelsTxPower, &adrAckCounter );

    
    status = PrepareFrame( macHdr, &fCtrl, fPort, fBuffer, fBufferSize );

    
    if( ( status == LORAMAC_STATUS_OK ) || ( status == LORAMAC_STATUS_SKIPPED_APP_DATA ) )
    {
        
        status = ScheduleTx( false );
    }

    
    if( status != LORAMAC_STATUS_OK )
    {
        
        
        MacCtx.NvmCtx->MacParams.ChannelsDatarate = datarate;
        MacCtx.NvmCtx->MacParams.ChannelsTxPower = txPower;
    }
    else {
        
        MacCtx.NvmCtx->SrvAckRequested = false;
        MacCtx.NvmCtx->AdrAckCounter = adrAckCounter;
        
        if( LoRaMacCommandsRemoveNoneStickyCmds( ) != LORAMAC_COMMANDS_SUCCESS )
        {
            return LORAMAC_STATUS_MAC_COMMAD_ERROR;
        }
    }
    return status;
}

LoRaMacStatus_t SendReJoinReq( JoinReqIdentifier_t joinReqType )
{
    LoRaMacStatus_t status = LORAMAC_STATUS_OK;
    LoRaMacHeader_t macHdr;
    macHdr.Value = 0;
    bool allowDelayedTx = true;

    
    switch( joinReqType )
    {
        case JOIN_REQ:
        {
            SwitchClass( CLASS_A );

            MacCtx.TxMsg.Type = LORAMAC_MSG_TYPE_JOIN_REQUEST;
            MacCtx.TxMsg.Message.JoinReq.Buffer = MacCtx.PktBuffer;
            MacCtx.TxMsg.Message.JoinReq.BufSize = LORAMAC_PHY_MAXPAYLOAD;

            macHdr.Bits.MType = FRAME_TYPE_JOIN_REQ;
            MacCtx.TxMsg.Message.JoinReq.MHDR.Value = macHdr.Value;

            memcpy1( MacCtx.TxMsg.Message.JoinReq.JoinEUI, SecureElementGetJoinEui( ), LORAMAC_JOIN_EUI_FIELD_SIZE );
            memcpy1( MacCtx.TxMsg.Message.JoinReq.DevEUI, SecureElementGetDevEui( ), LORAMAC_DEV_EUI_FIELD_SIZE );

            allowDelayedTx = false;

            break;
        }
        default:
            status = LORAMAC_STATUS_SERVICE_UNKNOWN;
            break;
    }

    
    status = ScheduleTx( allowDelayedTx );
    return status;
}

static LoRaMacStatus_t CheckForClassBCollision( void )
{
    if( LoRaMacClassBIsBeaconExpected( ) == true )
    {
        return LORAMAC_STATUS_BUSY_BEACON_RESERVED_TIME;
    }

    if( MacCtx.NvmCtx->DeviceClass == CLASS_B )
    {
        if( LoRaMacClassBIsPingExpected( ) == true )
        {
            return LORAMAC_STATUS_BUSY_PING_SLOT_WINDOW_TIME;
        }
        else if( LoRaMacClassBIsMulticastExpected( ) == true )
        {
            return LORAMAC_STATUS_BUSY_PING_SLOT_WINDOW_TIME;
        }
    }
    return LORAMAC_STATUS_OK;
}

static LoRaMacStatus_t ScheduleTx( bool allowDelayedTx )
{
    LoRaMacStatus_t status = LORAMAC_STATUS_PARAMETER_INVALID;
    TimerTime_t dutyCycleTimeOff = 0;
    NextChanParams_t nextChan;
    size_t macCmdsSize = 0;

    
    status = CheckForClassBCollision( );

    if( status != LORAMAC_STATUS_OK )
    {
        return status;
    }

    
    CalculateBackOff( MacCtx.NvmCtx->LastTxChannel );

    nextChan.AggrTimeOff = MacCtx.NvmCtx->AggregatedTimeOff;
    nextChan.Datarate = MacCtx.NvmCtx->MacParams.ChannelsDatarate;
    nextChan.DutyCycleEnabled = MacCtx.NvmCtx->DutyCycleOn;
    nextChan.QueryNextTxDelayOnly = false;
    nextChan.Joined = false;
    if( MacCtx.NvmCtx->NetworkActivation != ACTIVATION_TYPE_NONE )
    {
        nextChan.Joined = true;
    }
    nextChan.LastAggrTx = MacCtx.NvmCtx->LastTxDoneTime;

    
    status = RegionNextChannel( MacCtx.NvmCtx->Region, &nextChan, &MacCtx.Channel, &dutyCycleTimeOff, &MacCtx.NvmCtx->AggregatedTimeOff );

    if( status != LORAMAC_STATUS_OK )
    {
        if( ( status == LORAMAC_STATUS_DUTYCYCLE_RESTRICTED ) && ( allowDelayedTx == true ) )
        {
            
            
            if( dutyCycleTimeOff != 0 )
            {
                MacCtx.MacState |= LORAMAC_TX_DELAYED;
                TimerSetValue( &MacCtx.TxDelayedTimer, dutyCycleTimeOff );
                TimerStart( &MacCtx.TxDelayedTimer );
            }
            return LORAMAC_STATUS_OK;
        }
        else {
            return status;
        }
    }

    
    RegionComputeRxWindowParameters( MacCtx.NvmCtx->Region, RegionApplyDrOffset( MacCtx.NvmCtx->Region, MacCtx.NvmCtx->MacParams.DownlinkDwellTime, MacCtx.NvmCtx->MacParams.ChannelsDatarate, MacCtx.NvmCtx->MacParams.Rx1DrOffset ), MacCtx.NvmCtx->MacParams.MinRxSymbols, MacCtx.NvmCtx->MacParams.SystemMaxRxError, &MacCtx.RxWindow1Config );



    
    RegionComputeRxWindowParameters( MacCtx.NvmCtx->Region, MacCtx.NvmCtx->MacParams.Rx2Channel.Datarate, MacCtx.NvmCtx->MacParams.MinRxSymbols, MacCtx.NvmCtx->MacParams.SystemMaxRxError, &MacCtx.RxWindow2Config );




    if( MacCtx.NvmCtx->NetworkActivation == ACTIVATION_TYPE_NONE )
    {
        MacCtx.RxWindow1Delay = MacCtx.NvmCtx->MacParams.JoinAcceptDelay1 + MacCtx.RxWindow1Config.WindowOffset;
        MacCtx.RxWindow2Delay = MacCtx.NvmCtx->MacParams.JoinAcceptDelay2 + MacCtx.RxWindow2Config.WindowOffset;
    }
    else {
        if( LoRaMacCommandsGetSizeSerializedCmds( &macCmdsSize ) != LORAMAC_COMMANDS_SUCCESS )
        {
            return LORAMAC_STATUS_MAC_COMMAD_ERROR;
        }

        if( ValidatePayloadLength( MacCtx.AppDataSize, MacCtx.NvmCtx->MacParams.ChannelsDatarate, macCmdsSize ) == false )
        {
            return LORAMAC_STATUS_LENGTH_ERROR;
        }
        MacCtx.RxWindow1Delay = MacCtx.NvmCtx->MacParams.ReceiveDelay1 + MacCtx.RxWindow1Config.WindowOffset;
        MacCtx.RxWindow2Delay = MacCtx.NvmCtx->MacParams.ReceiveDelay2 + MacCtx.RxWindow2Config.WindowOffset;
    }

    
    LoRaMacStatus_t retval = SecureFrame( MacCtx.NvmCtx->MacParams.ChannelsDatarate, MacCtx.Channel );
    if( retval != LORAMAC_STATUS_OK )
    {
        return retval;
    }

    
    return SendFrameOnChannel( MacCtx.Channel );
}

static LoRaMacStatus_t SecureFrame( uint8_t txDr, uint8_t txCh )
{
    LoRaMacCryptoStatus_t macCryptoStatus = LORAMAC_CRYPTO_ERROR;
    uint32_t fCntUp = 0;

    switch( MacCtx.TxMsg.Type )
    {
        case LORAMAC_MSG_TYPE_JOIN_REQUEST:
            macCryptoStatus = LoRaMacCryptoPrepareJoinRequest( &MacCtx.TxMsg.Message.JoinReq );
            if( LORAMAC_CRYPTO_SUCCESS != macCryptoStatus )
            {
                return LORAMAC_STATUS_CRYPTO_ERROR;
            }
            MacCtx.PktBufferLen = MacCtx.TxMsg.Message.JoinReq.BufSize;
            break;
        case LORAMAC_MSG_TYPE_DATA:

            if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoGetFCntUp( &fCntUp ) )
            {
                return LORAMAC_STATUS_FCNT_HANDLER_ERROR;
            }

            if( ( MacCtx.ChannelsNbTransCounter >= 1 ) || ( MacCtx.AckTimeoutRetriesCounter > 1 ) )
            {
                fCntUp -= 1;
            }

            macCryptoStatus = LoRaMacCryptoSecureMessage( fCntUp, txDr, txCh, &MacCtx.TxMsg.Message.Data );
            if( LORAMAC_CRYPTO_SUCCESS != macCryptoStatus )
            {
                return LORAMAC_STATUS_CRYPTO_ERROR;
            }
            MacCtx.PktBufferLen = MacCtx.TxMsg.Message.Data.BufSize;
            break;
        case LORAMAC_MSG_TYPE_JOIN_ACCEPT:
        case LORAMAC_MSG_TYPE_UNDEF:
        default:
            return LORAMAC_STATUS_PARAMETER_INVALID;
    }
    return LORAMAC_STATUS_OK;
}

static void CalculateBackOff( uint8_t channel )
{
    CalcBackOffParams_t calcBackOff;

    if( MacCtx.NvmCtx->NetworkActivation == ACTIVATION_TYPE_NONE )
    {
        calcBackOff.Joined = false;
    }
    else {
        calcBackOff.Joined = true;
    }
    calcBackOff.DutyCycleEnabled = MacCtx.NvmCtx->DutyCycleOn;
    calcBackOff.Channel = channel;
    calcBackOff.ElapsedTime = SysTimeSub( SysTimeGetMcuTime( ), MacCtx.NvmCtx->InitializationTime );
    calcBackOff.TxTimeOnAir = MacCtx.TxTimeOnAir;
    calcBackOff.LastTxIsJoinRequest = false;

    if( MacCtx.NvmCtx->NetworkActivation == ACTIVATION_TYPE_NONE )
    {
        calcBackOff.LastTxIsJoinRequest = true;
    }

    
    RegionCalcBackOff( MacCtx.NvmCtx->Region, &calcBackOff );

    
    
    MacCtx.NvmCtx->AggregatedTimeOff = ( MacCtx.TxTimeOnAir * MacCtx.NvmCtx->AggregatedDCycle - MacCtx.TxTimeOnAir );
}

static void RemoveMacCommands( LoRaMacRxSlot_t rxSlot, LoRaMacFrameCtrl_t fCtrl, Mcps_t request )
{
    if( rxSlot == RX_SLOT_WIN_1 || rxSlot == RX_SLOT_WIN_2  )
    {
        
        
        if( request == MCPS_CONFIRMED )
        {
            if( fCtrl.Bits.Ack == 1 )
            {  
                LoRaMacCommandsRemoveStickyAnsCmds( );
            }
        }
        else {
            LoRaMacCommandsRemoveStickyAnsCmds( );
        }
    }
}


static void ResetMacParameters( void )
{
    MacCtx.NvmCtx->NetworkActivation = ACTIVATION_TYPE_NONE;

    
    MacCtx.NvmCtx->AdrAckCounter = 0;

    MacCtx.ChannelsNbTransCounter = 0;
    MacCtx.AckTimeoutRetries = 1;
    MacCtx.AckTimeoutRetriesCounter = 1;
    MacCtx.AckTimeoutRetry = false;

    MacCtx.NvmCtx->MaxDCycle = 0;
    MacCtx.NvmCtx->AggregatedDCycle = 1;

    MacCtx.NvmCtx->MacParams.ChannelsTxPower = MacCtx.NvmCtx->MacParamsDefaults.ChannelsTxPower;
    MacCtx.NvmCtx->MacParams.ChannelsDatarate = MacCtx.NvmCtx->MacParamsDefaults.ChannelsDatarate;
    MacCtx.NvmCtx->MacParams.Rx1DrOffset = MacCtx.NvmCtx->MacParamsDefaults.Rx1DrOffset;
    MacCtx.NvmCtx->MacParams.Rx2Channel = MacCtx.NvmCtx->MacParamsDefaults.Rx2Channel;
    MacCtx.NvmCtx->MacParams.RxCChannel = MacCtx.NvmCtx->MacParamsDefaults.RxCChannel;
    MacCtx.NvmCtx->MacParams.UplinkDwellTime = MacCtx.NvmCtx->MacParamsDefaults.UplinkDwellTime;
    MacCtx.NvmCtx->MacParams.DownlinkDwellTime = MacCtx.NvmCtx->MacParamsDefaults.DownlinkDwellTime;
    MacCtx.NvmCtx->MacParams.MaxEirp = MacCtx.NvmCtx->MacParamsDefaults.MaxEirp;
    MacCtx.NvmCtx->MacParams.AntennaGain = MacCtx.NvmCtx->MacParamsDefaults.AntennaGain;

    MacCtx.NodeAckRequested = false;
    MacCtx.NvmCtx->SrvAckRequested = false;

    
    InitDefaultsParams_t params;
    params.Type = INIT_TYPE_INIT;
    params.NvmCtx = NULL;
    RegionInitDefaults( MacCtx.NvmCtx->Region, &params );

    
    MacCtx.Channel = 0;
    MacCtx.NvmCtx->LastTxChannel = MacCtx.Channel;

    
    MacCtx.RxWindow2Config.Channel = MacCtx.Channel;
    MacCtx.RxWindow2Config.Frequency = MacCtx.NvmCtx->MacParams.Rx2Channel.Frequency;
    MacCtx.RxWindow2Config.DownlinkDwellTime = MacCtx.NvmCtx->MacParams.DownlinkDwellTime;
    MacCtx.RxWindow2Config.RxContinuous = false;
    MacCtx.RxWindow2Config.RxSlot = RX_SLOT_WIN_2;

    
    MacCtx.RxWindowCConfig = MacCtx.RxWindow2Config;
    MacCtx.RxWindowCConfig.RxContinuous = true;
    MacCtx.RxWindowCConfig.RxSlot = RX_SLOT_WIN_CLASS_C;

}


static void RxWindowSetup( TimerEvent_t* rxTimer, RxConfigParams_t* rxConfig )
{
    TimerStop( rxTimer );

    
    Radio.Standby( );

    if( RegionRxConfig( MacCtx.NvmCtx->Region, rxConfig, ( int8_t* )&MacCtx.McpsIndication.RxDatarate ) == true )
    {
        Radio.Rx( MacCtx.NvmCtx->MacParams.MaxRxWindow );
        MacCtx.RxSlot = rxConfig->RxSlot;
    }
}

static void OpenContinuousRxCWindow( void )
{
    
    RegionComputeRxWindowParameters( MacCtx.NvmCtx->Region, MacCtx.NvmCtx->MacParams.RxCChannel.Datarate, MacCtx.NvmCtx->MacParams.MinRxSymbols, MacCtx.NvmCtx->MacParams.SystemMaxRxError, &MacCtx.RxWindowCConfig );




    MacCtx.RxWindowCConfig.RxSlot = RX_SLOT_WIN_CLASS_C;
    
    MacCtx.RxWindowCConfig.RxContinuous = true;

    
    
    if( RegionRxConfig( MacCtx.NvmCtx->Region, &MacCtx.RxWindowCConfig, ( int8_t* )&MacCtx.McpsIndication.RxDatarate ) == true )
    {
        Radio.Rx( 0 ); 
        MacCtx.RxSlot = MacCtx.RxWindowCConfig.RxSlot;
    }
}

LoRaMacStatus_t PrepareFrame( LoRaMacHeader_t* macHdr, LoRaMacFrameCtrl_t* fCtrl, uint8_t fPort, void* fBuffer, uint16_t fBufferSize )
{
    MacCtx.PktBufferLen = 0;
    MacCtx.NodeAckRequested = false;
    uint32_t fCntUp = 0;
    size_t macCmdsSize = 0;
    uint8_t availableSize = 0;

    if( fBuffer == NULL )
    {
        fBufferSize = 0;
    }

    memcpy1( MacCtx.AppData, ( uint8_t* ) fBuffer, fBufferSize );
    MacCtx.AppDataSize = fBufferSize;
    MacCtx.PktBuffer[0] = macHdr->Value;

    switch( macHdr->Bits.MType )
    {
        case FRAME_TYPE_DATA_CONFIRMED_UP:
            MacCtx.NodeAckRequested = true;
            
        case FRAME_TYPE_DATA_UNCONFIRMED_UP:
            MacCtx.TxMsg.Type = LORAMAC_MSG_TYPE_DATA;
            MacCtx.TxMsg.Message.Data.Buffer = MacCtx.PktBuffer;
            MacCtx.TxMsg.Message.Data.BufSize = LORAMAC_PHY_MAXPAYLOAD;
            MacCtx.TxMsg.Message.Data.MHDR.Value = macHdr->Value;
            MacCtx.TxMsg.Message.Data.FPort = fPort;
            MacCtx.TxMsg.Message.Data.FHDR.DevAddr = MacCtx.NvmCtx->DevAddr;
            MacCtx.TxMsg.Message.Data.FHDR.FCtrl.Value = fCtrl->Value;
            MacCtx.TxMsg.Message.Data.FRMPayloadSize = MacCtx.AppDataSize;
            MacCtx.TxMsg.Message.Data.FRMPayload = MacCtx.AppData;

            if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoGetFCntUp( &fCntUp ) )
            {
                return LORAMAC_STATUS_FCNT_HANDLER_ERROR;
            }
            MacCtx.TxMsg.Message.Data.FHDR.FCnt = ( uint16_t )fCntUp;

            
            MacCtx.McpsConfirm.NbRetries = 0;
            MacCtx.McpsConfirm.AckReceived = false;
            MacCtx.McpsConfirm.UpLinkCounter = fCntUp;

            
            if( LoRaMacCommandsGetSizeSerializedCmds( &macCmdsSize ) != LORAMAC_COMMANDS_SUCCESS )
            {
                return LORAMAC_STATUS_MAC_COMMAD_ERROR;
            }

            if( macCmdsSize > 0 )
            {
                availableSize = GetMaxAppPayloadWithoutFOptsLength( MacCtx.NvmCtx->MacParams.ChannelsDatarate );

                
                if( ( MacCtx.AppDataSize > 0 ) && ( macCmdsSize <= LORA_MAC_COMMAND_MAX_FOPTS_LENGTH ) )
                {
                    if( LoRaMacCommandsSerializeCmds( LORA_MAC_COMMAND_MAX_FOPTS_LENGTH, &macCmdsSize, MacCtx.TxMsg.Message.Data.FHDR.FOpts ) != LORAMAC_COMMANDS_SUCCESS )
                    {
                        return LORAMAC_STATUS_MAC_COMMAD_ERROR;
                    }
                    fCtrl->Bits.FOptsLen = macCmdsSize;
                    
                    MacCtx.TxMsg.Message.Data.FHDR.FCtrl.Value = fCtrl->Value;
                }
                
                else if( ( MacCtx.AppDataSize > 0 ) && ( macCmdsSize > LORA_MAC_COMMAND_MAX_FOPTS_LENGTH ) )
                {

                    if( LoRaMacCommandsSerializeCmds( availableSize, &macCmdsSize, MacCtx.NvmCtx->MacCommandsBuffer ) != LORAMAC_COMMANDS_SUCCESS )
                    {
                        return LORAMAC_STATUS_MAC_COMMAD_ERROR;
                    }
                    return LORAMAC_STATUS_SKIPPED_APP_DATA;
                }
                
                else {
                    if( LoRaMacCommandsSerializeCmds( availableSize, &macCmdsSize, MacCtx.NvmCtx->MacCommandsBuffer ) != LORAMAC_COMMANDS_SUCCESS )
                    {
                        return LORAMAC_STATUS_MAC_COMMAD_ERROR;
                    }
                    
                    MacCtx.TxMsg.Message.Data.FPort = 0;

                    MacCtx.TxMsg.Message.Data.FRMPayload = MacCtx.NvmCtx->MacCommandsBuffer;
                    MacCtx.TxMsg.Message.Data.FRMPayloadSize = macCmdsSize;
                }
            }

            break;
        case FRAME_TYPE_PROPRIETARY:
            if( ( fBuffer != NULL ) && ( MacCtx.AppDataSize > 0 ) )
            {
                memcpy1( MacCtx.PktBuffer + LORAMAC_MHDR_FIELD_SIZE, ( uint8_t* ) fBuffer, MacCtx.AppDataSize );
                MacCtx.PktBufferLen = LORAMAC_MHDR_FIELD_SIZE + MacCtx.AppDataSize;
            }
            break;
        default:
            return LORAMAC_STATUS_SERVICE_UNKNOWN;
    }

    return LORAMAC_STATUS_OK;
}

LoRaMacStatus_t SendFrameOnChannel( uint8_t channel )
{
    TxConfigParams_t txConfig;
    int8_t txPower = 0;

    txConfig.Channel = channel;
    txConfig.Datarate = MacCtx.NvmCtx->MacParams.ChannelsDatarate;
    txConfig.TxPower = MacCtx.NvmCtx->MacParams.ChannelsTxPower;
    txConfig.MaxEirp = MacCtx.NvmCtx->MacParams.MaxEirp;
    txConfig.AntennaGain = MacCtx.NvmCtx->MacParams.AntennaGain;
    txConfig.PktLen = MacCtx.PktBufferLen;

    RegionTxConfig( MacCtx.NvmCtx->Region, &txConfig, &txPower, &MacCtx.TxTimeOnAir );

    MacCtx.McpsConfirm.Status = LORAMAC_EVENT_INFO_STATUS_ERROR;
    MacCtx.McpsConfirm.Datarate = MacCtx.NvmCtx->MacParams.ChannelsDatarate;
    MacCtx.McpsConfirm.TxPower = txPower;
    MacCtx.McpsConfirm.Channel = channel;

    
    MacCtx.McpsConfirm.TxTimeOnAir = MacCtx.TxTimeOnAir;
    MacCtx.MlmeConfirm.TxTimeOnAir = MacCtx.TxTimeOnAir;

    if( LoRaMacClassBIsBeaconModeActive( ) == true )
    {
        
        
        TimerTime_t collisionTime = LoRaMacClassBIsUplinkCollision( MacCtx.TxTimeOnAir );

        if( collisionTime > 0 )
        {
            return LORAMAC_STATUS_BUSY_UPLINK_COLLISION;
        }
    }

    if( MacCtx.NvmCtx->DeviceClass == CLASS_B )
    {
        
        LoRaMacClassBStopRxSlots( );
    }

    LoRaMacClassBHaltBeaconing( );

    MacCtx.MacState |= LORAMAC_TX_RUNNING;
    if( MacCtx.NodeAckRequested == false )
    {
        MacCtx.ChannelsNbTransCounter++;
    }

    
    Radio.Send( MacCtx.PktBuffer, MacCtx.PktBufferLen );

    return LORAMAC_STATUS_OK;
}

LoRaMacStatus_t SetTxContinuousWave( uint16_t timeout )
{
    ContinuousWaveParams_t continuousWave;

    continuousWave.Channel = MacCtx.Channel;
    continuousWave.Datarate = MacCtx.NvmCtx->MacParams.ChannelsDatarate;
    continuousWave.TxPower = MacCtx.NvmCtx->MacParams.ChannelsTxPower;
    continuousWave.MaxEirp = MacCtx.NvmCtx->MacParams.MaxEirp;
    continuousWave.AntennaGain = MacCtx.NvmCtx->MacParams.AntennaGain;
    continuousWave.Timeout = timeout;

    RegionSetContinuousWave( MacCtx.NvmCtx->Region, &continuousWave );

    MacCtx.MacState |= LORAMAC_TX_RUNNING;

    return LORAMAC_STATUS_OK;
}

LoRaMacStatus_t SetTxContinuousWave1( uint16_t timeout, uint32_t frequency, uint8_t power )
{
    Radio.SetTxContinuousWave( frequency, power, timeout );

    MacCtx.MacState |= LORAMAC_TX_RUNNING;

    return LORAMAC_STATUS_OK;
}

LoRaMacCtxs_t* GetCtxs( void )
{
    Contexts.MacNvmCtx = &NvmMacCtx;
    Contexts.MacNvmCtxSize = sizeof( NvmMacCtx );
    Contexts.CryptoNvmCtx = LoRaMacCryptoGetNvmCtx( &Contexts.CryptoNvmCtxSize );
    GetNvmCtxParams_t params ={ 0 };
    Contexts.RegionNvmCtx = RegionGetNvmCtx( MacCtx.NvmCtx->Region, &params );
    Contexts.RegionNvmCtxSize = params.nvmCtxSize;
    Contexts.SecureElementNvmCtx = SecureElementGetNvmCtx( &Contexts.SecureElementNvmCtxSize );
    Contexts.CommandsNvmCtx = LoRaMacCommandsGetNvmCtx( &Contexts.CommandsNvmCtxSize );
    Contexts.ClassBNvmCtx = LoRaMacClassBGetNvmCtx( &Contexts.ClassBNvmCtxSize );
    Contexts.ConfirmQueueNvmCtx = LoRaMacConfirmQueueGetNvmCtx( &Contexts.ConfirmQueueNvmCtxSize );
    return &Contexts;
}

LoRaMacStatus_t RestoreCtxs( LoRaMacCtxs_t* contexts )
{
    if( contexts == NULL )
    {
        return LORAMAC_STATUS_PARAMETER_INVALID;
    }
    if( MacCtx.MacState != LORAMAC_STOPPED )
    {
        return LORAMAC_STATUS_BUSY;
    }

    if( contexts->MacNvmCtx != NULL )
    {
        memcpy1( ( uint8_t* ) &NvmMacCtx, ( uint8_t* ) contexts->MacNvmCtx, contexts->MacNvmCtxSize );
    }

    InitDefaultsParams_t params;
    params.Type = INIT_TYPE_RESTORE_CTX;
    params.NvmCtx = contexts->RegionNvmCtx;
    RegionInitDefaults( MacCtx.NvmCtx->Region, &params );

    
    MacCtx.RxWindowCConfig.Channel = MacCtx.Channel;
    MacCtx.RxWindowCConfig.Frequency = MacCtx.NvmCtx->MacParams.RxCChannel.Frequency;
    MacCtx.RxWindowCConfig.DownlinkDwellTime = MacCtx.NvmCtx->MacParams.DownlinkDwellTime;
    MacCtx.RxWindowCConfig.RxContinuous = true;
    MacCtx.RxWindowCConfig.RxSlot = RX_SLOT_WIN_CLASS_C;

    if( SecureElementRestoreNvmCtx( contexts->SecureElementNvmCtx ) != SECURE_ELEMENT_SUCCESS )
    {
        return LORAMAC_STATUS_CRYPTO_ERROR;
    }

    if( LoRaMacCryptoRestoreNvmCtx( contexts->CryptoNvmCtx ) != LORAMAC_CRYPTO_SUCCESS )
    {
        return LORAMAC_STATUS_CRYPTO_ERROR;
    }

    if( LoRaMacCommandsRestoreNvmCtx( contexts->CommandsNvmCtx ) != LORAMAC_COMMANDS_SUCCESS )
    {
        return LORAMAC_STATUS_MAC_COMMAD_ERROR;
    }

    if( LoRaMacClassBRestoreNvmCtx( contexts->ClassBNvmCtx ) != true )
    {
        return LORAMAC_STATUS_CLASS_B_ERROR;
    }

    if( LoRaMacConfirmQueueRestoreNvmCtx( contexts->ConfirmQueueNvmCtx ) != true )
    {
        return LORAMAC_STATUS_CONFIRM_QUEUE_ERROR;
    }

    return LORAMAC_STATUS_OK;
}

LoRaMacStatus_t DetermineFrameType( LoRaMacMessageData_t* macMsg, FType_t* fType )
{
    if( ( macMsg == NULL ) || ( fType == NULL ) )
    {
        return LORAMAC_STATUS_PARAMETER_INVALID;
    }

    

    if( ( macMsg->FHDR.FCtrl.Bits.FOptsLen > 0 ) && ( macMsg->FPort > 0 ) )
    {
        *fType = FRAME_TYPE_A;
    }
    else if( macMsg->FRMPayloadSize == 0 )
    {
        *fType = FRAME_TYPE_B;
    }
    else if( ( macMsg->FHDR.FCtrl.Bits.FOptsLen == 0 ) && ( macMsg->FPort == 0 ) )
    {
        *fType = FRAME_TYPE_C;
    }
    else if( ( macMsg->FHDR.FCtrl.Bits.FOptsLen == 0 ) && ( macMsg->FPort > 0 ) )
    {
        *fType = FRAME_TYPE_D;
    }
    else {
        
        return LORAMAC_STATUS_ERROR;
    }

    return LORAMAC_STATUS_OK;
}

static bool CheckRetransUnconfirmedUplink( void )
{
    
    if( MacCtx.ChannelsNbTransCounter >= MacCtx.NvmCtx->MacParams.ChannelsNbTrans )
    {
        return true;
    }
    else if( MacCtx.MacFlags.Bits.McpsInd == 1 )
    {
        
        if( MacCtx.NvmCtx->DeviceClass == CLASS_A )
        {
            return true;
        }
        else {
            if( MacCtx.McpsIndication.RxSlot == RX_SLOT_WIN_1 )
            {
                return true;
            }
        }
    }
    return false;
}

static bool CheckRetransConfirmedUplink( void )
{
    
    if( MacCtx.AckTimeoutRetriesCounter >= MacCtx.AckTimeoutRetries )
    {
        return true;
    }
    else if( MacCtx.MacFlags.Bits.McpsInd == 1 )
    {
        if( MacCtx.McpsConfirm.AckReceived == true )
        {
            return true;
        }
    }
    return false;
}

static bool StopRetransmission( void )
{
    if( ( MacCtx.MacFlags.Bits.McpsInd == 0 ) || ( ( MacCtx.McpsIndication.RxSlot != RX_SLOT_WIN_1 ) && ( MacCtx.McpsIndication.RxSlot != RX_SLOT_WIN_2 ) ) )

    {   
        
        if( MacCtx.NvmCtx->AdrCtrlOn == true )
        {
            MacCtx.NvmCtx->AdrAckCounter++;
        }
    }

    MacCtx.ChannelsNbTransCounter = 0;
    MacCtx.NodeAckRequested = false;
    MacCtx.AckTimeoutRetry = false;
    MacCtx.MacState &= ~LORAMAC_TX_RUNNING;

    return true;
}

static void AckTimeoutRetriesProcess( void )
{
    if( MacCtx.AckTimeoutRetriesCounter < MacCtx.AckTimeoutRetries )
    {
        MacCtx.AckTimeoutRetriesCounter++;
        if( ( MacCtx.AckTimeoutRetriesCounter % 2 ) == 1 )
        {
            GetPhyParams_t getPhy;
            PhyParam_t phyParam;

            getPhy.Attribute = PHY_NEXT_LOWER_TX_DR;
            getPhy.UplinkDwellTime = MacCtx.NvmCtx->MacParams.UplinkDwellTime;
            getPhy.Datarate = MacCtx.NvmCtx->MacParams.ChannelsDatarate;
            phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
            MacCtx.NvmCtx->MacParams.ChannelsDatarate = phyParam.Value;
        }
    }
}

static void AckTimeoutRetriesFinalize( void )
{
    if( MacCtx.McpsConfirm.AckReceived == false )
    {
        InitDefaultsParams_t params;
        params.Type = INIT_TYPE_RESTORE_DEFAULT_CHANNELS;
        params.NvmCtx = Contexts.RegionNvmCtx;
        RegionInitDefaults( MacCtx.NvmCtx->Region, &params );

        MacCtx.NodeAckRequested = false;
        MacCtx.McpsConfirm.AckReceived = false;
    }
    MacCtx.McpsConfirm.NbRetries = MacCtx.AckTimeoutRetriesCounter;
}

static void CallNvmCtxCallback( LoRaMacNvmCtxModule_t module )
{
    if( ( MacCtx.MacCallbacks != NULL ) && ( MacCtx.MacCallbacks->NvmContextChange != NULL ) )
    {
        MacCtx.MacCallbacks->NvmContextChange( module );
    }
}

static void EventMacNvmCtxChanged( void )
{
    CallNvmCtxCallback( LORAMAC_NVMCTXMODULE_MAC );
}

static void EventRegionNvmCtxChanged( void )
{
    CallNvmCtxCallback( LORAMAC_NVMCTXMODULE_REGION );
}

static void EventCryptoNvmCtxChanged( void )
{
    CallNvmCtxCallback( LORAMAC_NVMCTXMODULE_CRYPTO );
}

static void EventSecureElementNvmCtxChanged( void )
{
    CallNvmCtxCallback( LORAMAC_NVMCTXMODULE_SECURE_ELEMENT );
}

static void EventCommandsNvmCtxChanged( void )
{
    CallNvmCtxCallback( LORAMAC_NVMCTXMODULE_COMMANDS );
}

static void EventClassBNvmCtxChanged( void )
{
    CallNvmCtxCallback( LORAMAC_NVMCTXMODULE_CLASS_B );
}

static void EventConfirmQueueNvmCtxChanged( void )
{
    CallNvmCtxCallback( LORAMAC_NVMCTXMODULE_CONFIRM_QUEUE );
}

static uint8_t IsRequestPending( void )
{
    if( ( MacCtx.MacFlags.Bits.MlmeReq == 1 ) || ( MacCtx.MacFlags.Bits.McpsReq == 1 ) )
    {
        return 1;
    }
    return 0;
}


LoRaMacStatus_t LoRaMacInitialization( LoRaMacPrimitives_t* primitives, LoRaMacCallback_t* callbacks, LoRaMacRegion_t region )
{
    GetPhyParams_t getPhy;
    PhyParam_t phyParam;
    LoRaMacClassBCallback_t classBCallbacks;
    LoRaMacClassBParams_t classBParams;

    if( ( primitives == NULL ) || ( callbacks == NULL ) )
    {
        return LORAMAC_STATUS_PARAMETER_INVALID;
    }

    if( ( primitives->MacMcpsConfirm == NULL ) || ( primitives->MacMcpsIndication == NULL ) || ( primitives->MacMlmeConfirm == NULL ) || ( primitives->MacMlmeIndication == NULL ) )


    {
        return LORAMAC_STATUS_PARAMETER_INVALID;
    }
    
    if( RegionIsActive( region ) == false )
    {
        return LORAMAC_STATUS_REGION_NOT_SUPPORTED;
    }

    
    LoRaMacConfirmQueueInit( primitives, EventConfirmQueueNvmCtxChanged );

    
    memset1( ( uint8_t* ) &NvmMacCtx, 0x00, sizeof( LoRaMacNvmCtx_t ) );
    memset1( ( uint8_t* ) &MacCtx, 0x00, sizeof( LoRaMacCtx_t ) );
    MacCtx.NvmCtx = &NvmMacCtx;

    
    MacCtx.AckTimeoutRetriesCounter = 1;
    MacCtx.AckTimeoutRetries = 1;
    MacCtx.NvmCtx->Region = region;
    MacCtx.NvmCtx->DeviceClass = CLASS_A;

    
    MacCtx.NvmCtx->Version.Value = LORAMAC_VERSION;

    
    getPhy.Attribute = PHY_DUTY_CYCLE;
    phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
    MacCtx.NvmCtx->DutyCycleOn = ( bool ) phyParam.Value;

    getPhy.Attribute = PHY_DEF_TX_POWER;
    phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
    MacCtx.NvmCtx->MacParamsDefaults.ChannelsTxPower = phyParam.Value;

    getPhy.Attribute = PHY_DEF_TX_DR;
    phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
    MacCtx.NvmCtx->MacParamsDefaults.ChannelsDatarate = phyParam.Value;

    getPhy.Attribute = PHY_MAX_RX_WINDOW;
    phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
    MacCtx.NvmCtx->MacParamsDefaults.MaxRxWindow = phyParam.Value;

    getPhy.Attribute = PHY_RECEIVE_DELAY1;
    phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
    MacCtx.NvmCtx->MacParamsDefaults.ReceiveDelay1 = phyParam.Value;

    getPhy.Attribute = PHY_RECEIVE_DELAY2;
    phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
    MacCtx.NvmCtx->MacParamsDefaults.ReceiveDelay2 = phyParam.Value;

    getPhy.Attribute = PHY_JOIN_ACCEPT_DELAY1;
    phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
    MacCtx.NvmCtx->MacParamsDefaults.JoinAcceptDelay1 = phyParam.Value;

    getPhy.Attribute = PHY_JOIN_ACCEPT_DELAY2;
    phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
    MacCtx.NvmCtx->MacParamsDefaults.JoinAcceptDelay2 = phyParam.Value;

    getPhy.Attribute = PHY_DEF_DR1_OFFSET;
    phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
    MacCtx.NvmCtx->MacParamsDefaults.Rx1DrOffset = phyParam.Value;

    getPhy.Attribute = PHY_DEF_RX2_FREQUENCY;
    phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
    MacCtx.NvmCtx->MacParamsDefaults.Rx2Channel.Frequency = phyParam.Value;
    MacCtx.NvmCtx->MacParamsDefaults.RxCChannel.Frequency = phyParam.Value;

    getPhy.Attribute = PHY_DEF_RX2_DR;
    phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
    MacCtx.NvmCtx->MacParamsDefaults.Rx2Channel.Datarate = phyParam.Value;
    MacCtx.NvmCtx->MacParamsDefaults.RxCChannel.Datarate = phyParam.Value;

    getPhy.Attribute = PHY_DEF_UPLINK_DWELL_TIME;
    phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
    MacCtx.NvmCtx->MacParamsDefaults.UplinkDwellTime = phyParam.Value;

    getPhy.Attribute = PHY_DEF_DOWNLINK_DWELL_TIME;
    phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
    MacCtx.NvmCtx->MacParamsDefaults.DownlinkDwellTime = phyParam.Value;

    getPhy.Attribute = PHY_DEF_MAX_EIRP;
    phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
    MacCtx.NvmCtx->MacParamsDefaults.MaxEirp = phyParam.fValue;

    getPhy.Attribute = PHY_DEF_ANTENNA_GAIN;
    phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
    MacCtx.NvmCtx->MacParamsDefaults.AntennaGain = phyParam.fValue;

    getPhy.Attribute = PHY_DEF_ADR_ACK_LIMIT;
    phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
    MacCtx.AdrAckLimit = phyParam.Value;

    getPhy.Attribute = PHY_DEF_ADR_ACK_DELAY;
    phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
    MacCtx.AdrAckDelay = phyParam.Value;

    
    MacCtx.NvmCtx->MacParamsDefaults.ChannelsNbTrans = 1;
    MacCtx.NvmCtx->MacParamsDefaults.SystemMaxRxError = 10;
    MacCtx.NvmCtx->MacParamsDefaults.MinRxSymbols = 6;

    MacCtx.NvmCtx->MacParams.SystemMaxRxError = MacCtx.NvmCtx->MacParamsDefaults.SystemMaxRxError;
    MacCtx.NvmCtx->MacParams.MinRxSymbols = MacCtx.NvmCtx->MacParamsDefaults.MinRxSymbols;
    MacCtx.NvmCtx->MacParams.MaxRxWindow = MacCtx.NvmCtx->MacParamsDefaults.MaxRxWindow;
    MacCtx.NvmCtx->MacParams.ReceiveDelay1 = MacCtx.NvmCtx->MacParamsDefaults.ReceiveDelay1;
    MacCtx.NvmCtx->MacParams.ReceiveDelay2 = MacCtx.NvmCtx->MacParamsDefaults.ReceiveDelay2;
    MacCtx.NvmCtx->MacParams.JoinAcceptDelay1 = MacCtx.NvmCtx->MacParamsDefaults.JoinAcceptDelay1;
    MacCtx.NvmCtx->MacParams.JoinAcceptDelay2 = MacCtx.NvmCtx->MacParamsDefaults.JoinAcceptDelay2;
    MacCtx.NvmCtx->MacParams.ChannelsNbTrans = MacCtx.NvmCtx->MacParamsDefaults.ChannelsNbTrans;

    InitDefaultsParams_t params;
    params.Type = INIT_TYPE_BANDS;
    params.NvmCtx = NULL;
    RegionInitDefaults( MacCtx.NvmCtx->Region, &params );

    ResetMacParameters( );

    MacCtx.NvmCtx->PublicNetwork = true;

    MacCtx.MacPrimitives = primitives;
    MacCtx.MacCallbacks = callbacks;
    MacCtx.MacFlags.Value = 0;
    MacCtx.MacState = LORAMAC_STOPPED;

    
    MacCtx.NvmCtx->LastTxDoneTime = 0;
    MacCtx.NvmCtx->AggregatedTimeOff = 0;

    
    TimerInit( &MacCtx.TxDelayedTimer, OnTxDelayedTimerEvent );
    TimerInit( &MacCtx.RxWindowTimer1, OnRxWindow1TimerEvent );
    TimerInit( &MacCtx.RxWindowTimer2, OnRxWindow2TimerEvent );
    TimerInit( &MacCtx.AckTimeoutTimer, OnAckTimeoutTimerEvent );

    
    MacCtx.NvmCtx->InitializationTime = SysTimeGetMcuTime( );

    
    MacCtx.RadioEvents.TxDone = OnRadioTxDone;
    MacCtx.RadioEvents.RxDone = OnRadioRxDone;
    MacCtx.RadioEvents.RxError = OnRadioRxError;
    MacCtx.RadioEvents.TxTimeout = OnRadioTxTimeout;
    MacCtx.RadioEvents.RxTimeout = OnRadioRxTimeout;
    Radio.Init( &MacCtx.RadioEvents );

    
    if( SecureElementInit( EventSecureElementNvmCtxChanged ) != SECURE_ELEMENT_SUCCESS )
    {
        return LORAMAC_STATUS_CRYPTO_ERROR;
    }

    
    if( LoRaMacCryptoInit( EventCryptoNvmCtxChanged ) != LORAMAC_CRYPTO_SUCCESS )
    {
        return LORAMAC_STATUS_CRYPTO_ERROR;
    }

    
    if( LoRaMacCommandsInit( EventCommandsNvmCtxChanged ) != LORAMAC_COMMANDS_SUCCESS )
    {
        return LORAMAC_STATUS_MAC_COMMAD_ERROR;
    }

    
    if( LoRaMacCryptoSetMulticastReference( MacCtx.NvmCtx->MulticastChannelList ) != LORAMAC_CRYPTO_SUCCESS )
    {
        return LORAMAC_STATUS_CRYPTO_ERROR;
    }

    
    srand1( Radio.Random( ) );

    Radio.SetPublicNetwork( MacCtx.NvmCtx->PublicNetwork );
    Radio.Sleep( );

    
    
    classBCallbacks.GetTemperatureLevel = NULL;
    classBCallbacks.MacProcessNotify = NULL;
    if( callbacks != NULL )
    {
        classBCallbacks.GetTemperatureLevel = callbacks->GetTemperatureLevel;
        classBCallbacks.MacProcessNotify = callbacks->MacProcessNotify;
    }

    
    classBParams.MlmeIndication = &MacCtx.MlmeIndication;
    classBParams.McpsIndication = &MacCtx.McpsIndication;
    classBParams.MlmeConfirm = &MacCtx.MlmeConfirm;
    classBParams.LoRaMacFlags = &MacCtx.MacFlags;
    classBParams.LoRaMacDevAddr = &MacCtx.NvmCtx->DevAddr;
    classBParams.LoRaMacRegion = &MacCtx.NvmCtx->Region;
    classBParams.LoRaMacParams = &MacCtx.NvmCtx->MacParams;
    classBParams.MulticastChannels = &MacCtx.NvmCtx->MulticastChannelList[0];

    LoRaMacClassBInit( &classBParams, &classBCallbacks, &EventClassBNvmCtxChanged );

    LoRaMacEnableRequests( LORAMAC_REQUEST_HANDLING_ON );

    return LORAMAC_STATUS_OK;
}

LoRaMacStatus_t LoRaMacStart( void )
{
    MacCtx.MacState = LORAMAC_IDLE;
    return LORAMAC_STATUS_OK;
}

LoRaMacStatus_t LoRaMacStop( void )
{
    if( LoRaMacIsBusy( ) == false )
    {
        MacCtx.MacState = LORAMAC_STOPPED;
        return LORAMAC_STATUS_OK;
    }
    else if(  MacCtx.MacState == LORAMAC_STOPPED )
    {
        return LORAMAC_STATUS_OK;
    }
    return LORAMAC_STATUS_BUSY;
}

LoRaMacStatus_t LoRaMacQueryNextTxDelay( int8_t datarate, TimerTime_t* time )
{
    NextChanParams_t nextChan;
    uint8_t channel = 0;

    CalcNextAdrParams_t adrNext;
    uint32_t adrAckCounter = MacCtx.NvmCtx->AdrAckCounter;
    int8_t txPower = MacCtx.NvmCtx->MacParamsDefaults.ChannelsTxPower;

    if( time == NULL )
    {
        return LORAMAC_STATUS_PARAMETER_INVALID;
    }

    if( MacCtx.NvmCtx->LastTxDoneTime == 0 )
    {
        *time = 0;
        return LORAMAC_STATUS_OK;
    }

    
    CalculateBackOff( MacCtx.NvmCtx->LastTxChannel );

    nextChan.AggrTimeOff = MacCtx.NvmCtx->AggregatedTimeOff;
    nextChan.Datarate = datarate;
    nextChan.DutyCycleEnabled = MacCtx.NvmCtx->DutyCycleOn;
    nextChan.QueryNextTxDelayOnly = true;
    nextChan.Joined = true;
    nextChan.LastAggrTx = MacCtx.NvmCtx->LastTxDoneTime;

    if( MacCtx.NvmCtx->NetworkActivation == ACTIVATION_TYPE_NONE )
    {
        nextChan.Joined = false;
    }
    if( MacCtx.NvmCtx->AdrCtrlOn == true )
    {
        
        adrNext.UpdateChanMask = false;
        adrNext.AdrEnabled = MacCtx.NvmCtx->AdrCtrlOn;
        adrNext.AdrAckCounter = MacCtx.NvmCtx->AdrAckCounter;
        adrNext.AdrAckLimit = MacCtx.AdrAckLimit;
        adrNext.AdrAckDelay = MacCtx.AdrAckDelay;
        adrNext.Datarate = MacCtx.NvmCtx->MacParams.ChannelsDatarate;
        adrNext.TxPower = MacCtx.NvmCtx->MacParams.ChannelsTxPower;
        adrNext.UplinkDwellTime = MacCtx.NvmCtx->MacParams.UplinkDwellTime;
        adrNext.Region = MacCtx.NvmCtx->Region;

        
        
        LoRaMacAdrCalcNext( &adrNext, &nextChan.Datarate, &txPower, &adrAckCounter );
    }

    
    return RegionNextChannel( MacCtx.NvmCtx->Region, &nextChan, &channel, time, &MacCtx.NvmCtx->AggregatedTimeOff );
}

LoRaMacStatus_t LoRaMacQueryTxPossible( uint8_t size, LoRaMacTxInfo_t* txInfo )
{
    CalcNextAdrParams_t adrNext;
    uint32_t adrAckCounter = MacCtx.NvmCtx->AdrAckCounter;
    int8_t datarate = MacCtx.NvmCtx->MacParamsDefaults.ChannelsDatarate;
    int8_t txPower = MacCtx.NvmCtx->MacParamsDefaults.ChannelsTxPower;
    size_t macCmdsSize = 0;

    if( txInfo == NULL )
    {
        return LORAMAC_STATUS_PARAMETER_INVALID;
    }

    
    adrNext.Version = MacCtx.NvmCtx->Version;
    adrNext.UpdateChanMask = false;
    adrNext.AdrEnabled = MacCtx.NvmCtx->AdrCtrlOn;
    adrNext.AdrAckCounter = MacCtx.NvmCtx->AdrAckCounter;
    adrNext.AdrAckLimit = MacCtx.AdrAckLimit;
    adrNext.AdrAckDelay = MacCtx.AdrAckDelay;
    adrNext.Datarate = MacCtx.NvmCtx->MacParams.ChannelsDatarate;
    adrNext.TxPower = MacCtx.NvmCtx->MacParams.ChannelsTxPower;
    adrNext.UplinkDwellTime = MacCtx.NvmCtx->MacParams.UplinkDwellTime;
    adrNext.Region = MacCtx.NvmCtx->Region;

    
    
    LoRaMacAdrCalcNext( &adrNext, &datarate, &txPower, &adrAckCounter );

    txInfo->CurrentPossiblePayloadSize = GetMaxAppPayloadWithoutFOptsLength( datarate );

    if( LoRaMacCommandsGetSizeSerializedCmds( &macCmdsSize ) != LORAMAC_COMMANDS_SUCCESS )
    {
        return LORAMAC_STATUS_MAC_COMMAD_ERROR;
    }

    
    if( ( LORA_MAC_COMMAND_MAX_FOPTS_LENGTH >= macCmdsSize ) && ( txInfo->CurrentPossiblePayloadSize >= macCmdsSize ) )
    {
        txInfo->MaxPossibleApplicationDataSize = txInfo->CurrentPossiblePayloadSize - macCmdsSize;

        
        if( txInfo->CurrentPossiblePayloadSize >= ( macCmdsSize + size ) )
        {
            return LORAMAC_STATUS_OK;
        }
        else {
           return LORAMAC_STATUS_LENGTH_ERROR;
        }
    }
    else {
        txInfo->MaxPossibleApplicationDataSize = 0;
        return LORAMAC_STATUS_LENGTH_ERROR;
    }
}

LoRaMacStatus_t LoRaMacMibGetRequestConfirm( MibRequestConfirm_t* mibGet )
{
    LoRaMacStatus_t status = LORAMAC_STATUS_OK;
    GetPhyParams_t getPhy;
    PhyParam_t phyParam;

    if( mibGet == NULL )
    {
        return LORAMAC_STATUS_PARAMETER_INVALID;
    }

    switch( mibGet->Type )
    {
        case MIB_DEVICE_CLASS:
        {
            mibGet->Param.Class = MacCtx.NvmCtx->DeviceClass;
            break;
        }
        case MIB_NETWORK_ACTIVATION:
        {
            mibGet->Param.NetworkActivation = MacCtx.NvmCtx->NetworkActivation;
            break;
        }
        case MIB_DEV_EUI:
        {
            mibGet->Param.DevEui = SecureElementGetDevEui( );
            break;
        }
        case MIB_JOIN_EUI:
        {
            mibGet->Param.JoinEui = SecureElementGetJoinEui( );
            break;
        }
        case MIB_SE_PIN:
        {
            mibGet->Param.JoinEui = SecureElementGetPin( );
            break;
        }
        case MIB_ADR:
        {
            mibGet->Param.AdrEnable = MacCtx.NvmCtx->AdrCtrlOn;
            break;
        }
        case MIB_NET_ID:
        {
            mibGet->Param.NetID = MacCtx.NvmCtx->NetID;
            break;
        }
        case MIB_DEV_ADDR:
        {
            mibGet->Param.DevAddr = MacCtx.NvmCtx->DevAddr;
            break;
        }
        case MIB_PUBLIC_NETWORK:
        {
            mibGet->Param.EnablePublicNetwork = MacCtx.NvmCtx->PublicNetwork;
            break;
        }
        case MIB_CHANNELS:
        {
            getPhy.Attribute = PHY_CHANNELS;
            phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );

            mibGet->Param.ChannelList = phyParam.Channels;
            break;
        }
        case MIB_RX2_CHANNEL:
        {
            mibGet->Param.Rx2Channel = MacCtx.NvmCtx->MacParams.Rx2Channel;
            break;
        }
        case MIB_RX2_DEFAULT_CHANNEL:
        {
            mibGet->Param.Rx2Channel = MacCtx.NvmCtx->MacParamsDefaults.Rx2Channel;
            break;
        }
        case MIB_RXC_CHANNEL:
        {
            mibGet->Param.RxCChannel = MacCtx.NvmCtx->MacParams.RxCChannel;
            break;
        }
        case MIB_RXC_DEFAULT_CHANNEL:
        {
            mibGet->Param.RxCChannel = MacCtx.NvmCtx->MacParamsDefaults.RxCChannel;
            break;
        }
        case MIB_CHANNELS_DEFAULT_MASK:
        {
            getPhy.Attribute = PHY_CHANNELS_DEFAULT_MASK;
            phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );

            mibGet->Param.ChannelsDefaultMask = phyParam.ChannelsMask;
            break;
        }
        case MIB_CHANNELS_MASK:
        {
            getPhy.Attribute = PHY_CHANNELS_MASK;
            phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );

            mibGet->Param.ChannelsMask = phyParam.ChannelsMask;
            break;
        }
        case MIB_CHANNELS_NB_TRANS:
        {
            mibGet->Param.ChannelsNbTrans = MacCtx.NvmCtx->MacParams.ChannelsNbTrans;
            break;
        }
        case MIB_MAX_RX_WINDOW_DURATION:
        {
            mibGet->Param.MaxRxWindow = MacCtx.NvmCtx->MacParams.MaxRxWindow;
            break;
        }
        case MIB_RECEIVE_DELAY_1:
        {
            mibGet->Param.ReceiveDelay1 = MacCtx.NvmCtx->MacParams.ReceiveDelay1;
            break;
        }
        case MIB_RECEIVE_DELAY_2:
        {
            mibGet->Param.ReceiveDelay2 = MacCtx.NvmCtx->MacParams.ReceiveDelay2;
            break;
        }
        case MIB_JOIN_ACCEPT_DELAY_1:
        {
            mibGet->Param.JoinAcceptDelay1 = MacCtx.NvmCtx->MacParams.JoinAcceptDelay1;
            break;
        }
        case MIB_JOIN_ACCEPT_DELAY_2:
        {
            mibGet->Param.JoinAcceptDelay2 = MacCtx.NvmCtx->MacParams.JoinAcceptDelay2;
            break;
        }
        case MIB_CHANNELS_DEFAULT_DATARATE:
        {
            mibGet->Param.ChannelsDefaultDatarate = MacCtx.NvmCtx->MacParamsDefaults.ChannelsDatarate;
            break;
        }
        case MIB_CHANNELS_DATARATE:
        {
            mibGet->Param.ChannelsDatarate = MacCtx.NvmCtx->MacParams.ChannelsDatarate;
            break;
        }
        case MIB_CHANNELS_DEFAULT_TX_POWER:
        {
            mibGet->Param.ChannelsDefaultTxPower = MacCtx.NvmCtx->MacParamsDefaults.ChannelsTxPower;
            break;
        }
        case MIB_CHANNELS_TX_POWER:
        {
            mibGet->Param.ChannelsTxPower = MacCtx.NvmCtx->MacParams.ChannelsTxPower;
            break;
        }
        case MIB_SYSTEM_MAX_RX_ERROR:
        {
            mibGet->Param.SystemMaxRxError = MacCtx.NvmCtx->MacParams.SystemMaxRxError;
            break;
        }
        case MIB_MIN_RX_SYMBOLS:
        {
            mibGet->Param.MinRxSymbols = MacCtx.NvmCtx->MacParams.MinRxSymbols;
            break;
        }
        case MIB_ANTENNA_GAIN:
        {
            mibGet->Param.AntennaGain = MacCtx.NvmCtx->MacParams.AntennaGain;
            break;
        }
        case MIB_NVM_CTXS:
        {
            mibGet->Param.Contexts = GetCtxs( );
            break;
        }
        case MIB_DEFAULT_ANTENNA_GAIN:
        {
            mibGet->Param.DefaultAntennaGain = MacCtx.NvmCtx->MacParamsDefaults.AntennaGain;
            break;
        }
        case MIB_LORAWAN_VERSION:
        {
            mibGet->Param.LrWanVersion.LoRaWan = MacCtx.NvmCtx->Version;
            mibGet->Param.LrWanVersion.LoRaWanRegion = RegionGetVersion( );
            break;
        }
        default:
        {
            status = LoRaMacClassBMibGetRequestConfirm( mibGet );
            break;
        }
    }
    return status;
}

LoRaMacStatus_t LoRaMacMibSetRequestConfirm( MibRequestConfirm_t* mibSet )
{
    LoRaMacStatus_t status = LORAMAC_STATUS_OK;
    ChanMaskSetParams_t chanMaskSet;
    VerifyParams_t verify;

    if( mibSet == NULL )
    {
        return LORAMAC_STATUS_PARAMETER_INVALID;
    }
    if( ( MacCtx.MacState & LORAMAC_TX_RUNNING ) == LORAMAC_TX_RUNNING )
    {
        return LORAMAC_STATUS_BUSY;
    }

    switch( mibSet->Type )
    {
        case MIB_DEVICE_CLASS:
        {
            status = SwitchClass( mibSet->Param.Class );
            break;
        }
        case MIB_NETWORK_ACTIVATION:
        {
            if( mibSet->Param.NetworkActivation != ACTIVATION_TYPE_OTAA  )
            {
                MacCtx.NvmCtx->NetworkActivation = mibSet->Param.NetworkActivation;
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_DEV_EUI:
        {
            if( SecureElementSetDevEui( mibSet->Param.DevEui ) != SECURE_ELEMENT_SUCCESS )
            {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_JOIN_EUI:
        {
            if( SecureElementSetJoinEui( mibSet->Param.JoinEui ) != SECURE_ELEMENT_SUCCESS )
            {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_SE_PIN:
        {
            if( SecureElementSetPin( mibSet->Param.SePin ) != SECURE_ELEMENT_SUCCESS )
            {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_ADR:
        {
            MacCtx.NvmCtx->AdrCtrlOn = mibSet->Param.AdrEnable;
            break;
        }
        case MIB_NET_ID:
        {
            MacCtx.NvmCtx->NetID = mibSet->Param.NetID;
            break;
        }
        case MIB_DEV_ADDR:
        {
            MacCtx.NvmCtx->DevAddr = mibSet->Param.DevAddr;
            break;
        }
        case MIB_APP_KEY:
        {
            if( mibSet->Param.AppKey != NULL )
            {
                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( APP_KEY, mibSet->Param.AppKey ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_NWK_KEY:
        {
            if( mibSet->Param.NwkKey != NULL )
            {
                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( NWK_KEY, mibSet->Param.NwkKey ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_J_S_INT_KEY:
        {
            if( mibSet->Param.JSIntKey != NULL )
            {
                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( J_S_INT_KEY, mibSet->Param.JSIntKey ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_J_S_ENC_KEY:
        {
            if( mibSet->Param.JSEncKey != NULL )
            {
                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( J_S_ENC_KEY, mibSet->Param.JSEncKey ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_F_NWK_S_INT_KEY:
        {
            if( mibSet->Param.FNwkSIntKey != NULL )
            {
                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( F_NWK_S_INT_KEY, mibSet->Param.FNwkSIntKey ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_S_NWK_S_INT_KEY:
        {
            if( mibSet->Param.SNwkSIntKey != NULL )
            {
                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( S_NWK_S_INT_KEY, mibSet->Param.SNwkSIntKey ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_NWK_S_ENC_KEY:
        {
            if( mibSet->Param.NwkSEncKey != NULL )
            {
                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( NWK_S_ENC_KEY, mibSet->Param.NwkSEncKey ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_APP_S_KEY:
        {
            if( mibSet->Param.AppSKey != NULL )
            {
                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( APP_S_KEY, mibSet->Param.AppSKey ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_MC_KE_KEY:
        {
            if( mibSet->Param.McKEKey != NULL )
            {
                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( MC_KE_KEY, mibSet->Param.McKEKey ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_MC_KEY_0:
        {
            if( mibSet->Param.McKey0 != NULL )
            {
                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( MC_KEY_0, mibSet->Param.McKey0 ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_MC_APP_S_KEY_0:
        {
            if( mibSet->Param.McAppSKey0 != NULL )
            {
                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( MC_APP_S_KEY_0, mibSet->Param.McAppSKey0 ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_MC_NWK_S_KEY_0:
        {
            if( mibSet->Param.McNwkSKey0 != NULL )
            {
                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( MC_NWK_S_KEY_0, mibSet->Param.McNwkSKey0 ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_MC_KEY_1:
        {
            if( mibSet->Param.McKey1 != NULL )
            {
                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( MC_KEY_1, mibSet->Param.McKey1 ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_MC_APP_S_KEY_1:
        {
            if( mibSet->Param.McAppSKey1 != NULL )
            {
                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( MC_APP_S_KEY_1, mibSet->Param.McAppSKey1 ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_MC_NWK_S_KEY_1:
        {
            if( mibSet->Param.McNwkSKey1 != NULL )
            {
                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( MC_NWK_S_KEY_1, mibSet->Param.McNwkSKey1 ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_MC_KEY_2:
        {
            if( mibSet->Param.McKey2 != NULL )
            {
                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( MC_KEY_2, mibSet->Param.McKey2 ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_MC_APP_S_KEY_2:
        {
            if( mibSet->Param.McAppSKey2 != NULL )
            {
                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( MC_APP_S_KEY_2, mibSet->Param.McAppSKey2 ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_MC_NWK_S_KEY_2:
        {
            if( mibSet->Param.McNwkSKey2 != NULL )
            {
                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( MC_NWK_S_KEY_2, mibSet->Param.McNwkSKey2 ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_MC_KEY_3:
        {
            if( mibSet->Param.McKey3 != NULL )
            {
                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( MC_KEY_3, mibSet->Param.McKey3 ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_MC_APP_S_KEY_3:
        {
            if( mibSet->Param.McAppSKey3 != NULL )
            {
                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( MC_APP_S_KEY_3, mibSet->Param.McAppSKey3 ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_MC_NWK_S_KEY_3:
        {
            if( mibSet->Param.McNwkSKey3 != NULL )
            {
                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( MC_NWK_S_KEY_3, mibSet->Param.McNwkSKey3 ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_PUBLIC_NETWORK:
        {
            MacCtx.NvmCtx->PublicNetwork = mibSet->Param.EnablePublicNetwork;
            Radio.SetPublicNetwork( MacCtx.NvmCtx->PublicNetwork );
            break;
        }
        case MIB_RX2_CHANNEL:
        {
            verify.DatarateParams.Datarate = mibSet->Param.Rx2Channel.Datarate;
            verify.DatarateParams.DownlinkDwellTime = MacCtx.NvmCtx->MacParams.DownlinkDwellTime;

            if( RegionVerify( MacCtx.NvmCtx->Region, &verify, PHY_RX_DR ) == true )
            {
                MacCtx.NvmCtx->MacParams.Rx2Channel = mibSet->Param.Rx2Channel;
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_RX2_DEFAULT_CHANNEL:
        {
            verify.DatarateParams.Datarate = mibSet->Param.Rx2Channel.Datarate;
            verify.DatarateParams.DownlinkDwellTime = MacCtx.NvmCtx->MacParams.DownlinkDwellTime;

            if( RegionVerify( MacCtx.NvmCtx->Region, &verify, PHY_RX_DR ) == true )
            {
                MacCtx.NvmCtx->MacParamsDefaults.Rx2Channel = mibSet->Param.Rx2DefaultChannel;
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_RXC_CHANNEL:
        {
            verify.DatarateParams.Datarate = mibSet->Param.RxCChannel.Datarate;
            verify.DatarateParams.DownlinkDwellTime = MacCtx.NvmCtx->MacParams.DownlinkDwellTime;

            if( RegionVerify( MacCtx.NvmCtx->Region, &verify, PHY_RX_DR ) == true )
            {
                MacCtx.NvmCtx->MacParams.RxCChannel = mibSet->Param.RxCChannel;

                if( ( MacCtx.NvmCtx->DeviceClass == CLASS_C ) && ( MacCtx.NvmCtx->NetworkActivation != ACTIVATION_TYPE_NONE ) )
                {
                    
                    
                    
                    
                    Radio.Sleep( );

                    OpenContinuousRxCWindow( );
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_RXC_DEFAULT_CHANNEL:
        {
            verify.DatarateParams.Datarate = mibSet->Param.RxCChannel.Datarate;
            verify.DatarateParams.DownlinkDwellTime = MacCtx.NvmCtx->MacParams.DownlinkDwellTime;

            if( RegionVerify( MacCtx.NvmCtx->Region, &verify, PHY_RX_DR ) == true )
            {
                MacCtx.NvmCtx->MacParamsDefaults.RxCChannel = mibSet->Param.RxCDefaultChannel;
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_CHANNELS_DEFAULT_MASK:
        {
            chanMaskSet.ChannelsMaskIn = mibSet->Param.ChannelsDefaultMask;
            chanMaskSet.ChannelsMaskType = CHANNELS_DEFAULT_MASK;

            if( RegionChanMaskSet( MacCtx.NvmCtx->Region, &chanMaskSet ) == false )
            {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_CHANNELS_MASK:
        {
            chanMaskSet.ChannelsMaskIn = mibSet->Param.ChannelsMask;
            chanMaskSet.ChannelsMaskType = CHANNELS_MASK;

            if( RegionChanMaskSet( MacCtx.NvmCtx->Region, &chanMaskSet ) == false )
            {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_CHANNELS_NB_TRANS:
        {
            if( ( mibSet->Param.ChannelsNbTrans >= 1 ) && ( mibSet->Param.ChannelsNbTrans <= 15 ) )
            {
                MacCtx.NvmCtx->MacParams.ChannelsNbTrans = mibSet->Param.ChannelsNbTrans;
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_MAX_RX_WINDOW_DURATION:
        {
            MacCtx.NvmCtx->MacParams.MaxRxWindow = mibSet->Param.MaxRxWindow;
            break;
        }
        case MIB_RECEIVE_DELAY_1:
        {
            MacCtx.NvmCtx->MacParams.ReceiveDelay1 = mibSet->Param.ReceiveDelay1;
            break;
        }
        case MIB_RECEIVE_DELAY_2:
        {
            MacCtx.NvmCtx->MacParams.ReceiveDelay2 = mibSet->Param.ReceiveDelay2;
            break;
        }
        case MIB_JOIN_ACCEPT_DELAY_1:
        {
            MacCtx.NvmCtx->MacParams.JoinAcceptDelay1 = mibSet->Param.JoinAcceptDelay1;
            break;
        }
        case MIB_JOIN_ACCEPT_DELAY_2:
        {
            MacCtx.NvmCtx->MacParams.JoinAcceptDelay2 = mibSet->Param.JoinAcceptDelay2;
            break;
        }
        case MIB_CHANNELS_DEFAULT_DATARATE:
        {
            verify.DatarateParams.Datarate = mibSet->Param.ChannelsDefaultDatarate;

            if( RegionVerify( MacCtx.NvmCtx->Region, &verify, PHY_DEF_TX_DR ) == true )
            {
                MacCtx.NvmCtx->MacParamsDefaults.ChannelsDatarate = verify.DatarateParams.Datarate;
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_CHANNELS_DATARATE:
        {
            verify.DatarateParams.Datarate = mibSet->Param.ChannelsDatarate;
            verify.DatarateParams.UplinkDwellTime = MacCtx.NvmCtx->MacParams.UplinkDwellTime;

            if( RegionVerify( MacCtx.NvmCtx->Region, &verify, PHY_TX_DR ) == true )
            {
                MacCtx.NvmCtx->MacParams.ChannelsDatarate = verify.DatarateParams.Datarate;
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_CHANNELS_DEFAULT_TX_POWER:
        {
            verify.TxPower = mibSet->Param.ChannelsDefaultTxPower;

            if( RegionVerify( MacCtx.NvmCtx->Region, &verify, PHY_DEF_TX_POWER ) == true )
            {
                MacCtx.NvmCtx->MacParamsDefaults.ChannelsTxPower = verify.TxPower;
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_CHANNELS_TX_POWER:
        {
            verify.TxPower = mibSet->Param.ChannelsTxPower;

            if( RegionVerify( MacCtx.NvmCtx->Region, &verify, PHY_TX_POWER ) == true )
            {
                MacCtx.NvmCtx->MacParams.ChannelsTxPower = verify.TxPower;
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_SYSTEM_MAX_RX_ERROR:
        {
            MacCtx.NvmCtx->MacParams.SystemMaxRxError = MacCtx.NvmCtx->MacParamsDefaults.SystemMaxRxError = mibSet->Param.SystemMaxRxError;
            break;
        }
        case MIB_MIN_RX_SYMBOLS:
        {
            MacCtx.NvmCtx->MacParams.MinRxSymbols = MacCtx.NvmCtx->MacParamsDefaults.MinRxSymbols = mibSet->Param.MinRxSymbols;
            break;
        }
        case MIB_ANTENNA_GAIN:
        {
            MacCtx.NvmCtx->MacParams.AntennaGain = mibSet->Param.AntennaGain;
            break;
        }
        case MIB_DEFAULT_ANTENNA_GAIN:
        {
            MacCtx.NvmCtx->MacParamsDefaults.AntennaGain = mibSet->Param.DefaultAntennaGain;
            break;
        }
        case MIB_NVM_CTXS:
        {
            if( mibSet->Param.Contexts != 0 )
            {
                status = RestoreCtxs( mibSet->Param.Contexts );
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        case MIB_ABP_LORAWAN_VERSION:
        {
            if( mibSet->Param.AbpLrWanVersion.Fields.Minor <= 1 )
            {
                MacCtx.NvmCtx->Version = mibSet->Param.AbpLrWanVersion;

                if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetLrWanVersion( mibSet->Param.AbpLrWanVersion ) )
                {
                    return LORAMAC_STATUS_CRYPTO_ERROR;
                }
            }
            else {
                status = LORAMAC_STATUS_PARAMETER_INVALID;
            }
            break;
        }
        default:
        {
            status = LoRaMacMibClassBSetRequestConfirm( mibSet );
            break;
        }
    }
    EventRegionNvmCtxChanged( );
    EventMacNvmCtxChanged( );
    return status;
}

LoRaMacStatus_t LoRaMacChannelAdd( uint8_t id, ChannelParams_t params )
{
    ChannelAddParams_t channelAdd;

    
    if( ( MacCtx.MacState & LORAMAC_TX_RUNNING ) == LORAMAC_TX_RUNNING )
    {
        if( ( MacCtx.MacState & LORAMAC_TX_CONFIG ) != LORAMAC_TX_CONFIG )
        {
            return LORAMAC_STATUS_BUSY;
        }
    }

    channelAdd.NewChannel = &params;
    channelAdd.ChannelId = id;

    EventRegionNvmCtxChanged( );
    return RegionChannelAdd( MacCtx.NvmCtx->Region, &channelAdd );
}

LoRaMacStatus_t LoRaMacChannelRemove( uint8_t id )
{
    ChannelRemoveParams_t channelRemove;

    if( ( MacCtx.MacState & LORAMAC_TX_RUNNING ) == LORAMAC_TX_RUNNING )
    {
        if( ( MacCtx.MacState & LORAMAC_TX_CONFIG ) != LORAMAC_TX_CONFIG )
        {
            return LORAMAC_STATUS_BUSY;
        }
    }

    channelRemove.ChannelId = id;

    if( RegionChannelsRemove( MacCtx.NvmCtx->Region, &channelRemove ) == false )
    {
        return LORAMAC_STATUS_PARAMETER_INVALID;
    }

    EventRegionNvmCtxChanged( );
    return LORAMAC_STATUS_OK;
}

LoRaMacStatus_t LoRaMacMcChannelSetup( McChannelParams_t *channel )
{
    if( ( MacCtx.MacState & LORAMAC_TX_RUNNING ) == LORAMAC_TX_RUNNING )
    {
        return LORAMAC_STATUS_BUSY;
    }

    if( channel->GroupID >= LORAMAC_MAX_MC_CTX )
    {
        return LORAMAC_STATUS_MC_GROUP_UNDEFINED;
    }

    MacCtx.NvmCtx->MulticastChannelList[channel->GroupID].ChannelParams = *channel;

    if( channel->IsRemotelySetup == true )
    {
        const KeyIdentifier_t mcKeys[LORAMAC_MAX_MC_CTX] = { MC_KEY_0, MC_KEY_1, MC_KEY_2, MC_KEY_3 };
        if( LoRaMacCryptoSetKey( mcKeys[channel->GroupID], channel->McKeys.McKeyE ) != LORAMAC_CRYPTO_SUCCESS )
        {
            return LORAMAC_STATUS_CRYPTO_ERROR;
        }

        if( LoRaMacCryptoDeriveMcSessionKeyPair( channel->GroupID, channel->Address ) != LORAMAC_CRYPTO_SUCCESS )
        {
            return LORAMAC_STATUS_CRYPTO_ERROR;
        }
    }
    else {
        const KeyIdentifier_t mcAppSKeys[LORAMAC_MAX_MC_CTX] = { MC_APP_S_KEY_0, MC_APP_S_KEY_1, MC_APP_S_KEY_2, MC_APP_S_KEY_3 };
        const KeyIdentifier_t mcNwkSKeys[LORAMAC_MAX_MC_CTX] = { MC_NWK_S_KEY_0, MC_NWK_S_KEY_1, MC_NWK_S_KEY_2, MC_NWK_S_KEY_3 };
        if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( mcAppSKeys[channel->GroupID], channel->McKeys.Session.McAppSKey ) )
        {
            return LORAMAC_STATUS_CRYPTO_ERROR;
        }
        if( LORAMAC_CRYPTO_SUCCESS != LoRaMacCryptoSetKey( mcNwkSKeys[channel->GroupID], channel->McKeys.Session.McNwkSKey ) )
        {
            return LORAMAC_STATUS_CRYPTO_ERROR;
        }
    }

    if( channel->Class == CLASS_B )
    {
        
        LoRaMacClassBSetMulticastPeriodicity( &MacCtx.NvmCtx->MulticastChannelList[channel->GroupID] );
    }

    
    *MacCtx.NvmCtx->MulticastChannelList[channel->GroupID].DownLinkCounter = FCNT_DOWN_INITAL_VALUE;

    EventMacNvmCtxChanged( );
    EventRegionNvmCtxChanged( );
    return LORAMAC_STATUS_OK;
}

LoRaMacStatus_t LoRaMacMcChannelDelete( AddressIdentifier_t groupID )
{
    if( ( MacCtx.MacState & LORAMAC_TX_RUNNING ) == LORAMAC_TX_RUNNING )
    {
        return LORAMAC_STATUS_BUSY;
    }

    if( ( groupID >= LORAMAC_MAX_MC_CTX ) ||  ( MacCtx.NvmCtx->MulticastChannelList[groupID].ChannelParams.IsEnabled == false ) )
    {
        return LORAMAC_STATUS_MC_GROUP_UNDEFINED;
    }

    McChannelParams_t channel;

    
    memset1( ( uint8_t* )&channel, 0, sizeof( McChannelParams_t ) );

    MacCtx.NvmCtx->MulticastChannelList[groupID].ChannelParams = channel;

    EventMacNvmCtxChanged( );
    EventRegionNvmCtxChanged( );
    return LORAMAC_STATUS_OK;
}

uint8_t LoRaMacMcChannelGetGroupId( uint32_t mcAddress )
{
    for( uint8_t i = 0; i < LORAMAC_MAX_MC_CTX; i++ )
    {
        if( mcAddress == MacCtx.NvmCtx->MulticastChannelList[i].ChannelParams.Address )
        {
            return i;
        }
    }
    return 0xFF;
}

LoRaMacStatus_t LoRaMacMcChannelSetupRxParams( AddressIdentifier_t groupID, McRxParams_t *rxParams, uint8_t *status )
{
   *status = 0x1C + ( groupID & 0x03 );

    if( ( MacCtx.MacState & LORAMAC_TX_RUNNING ) == LORAMAC_TX_RUNNING )
    {
        return LORAMAC_STATUS_BUSY;
    }

    DeviceClass_t devClass = MacCtx.NvmCtx->MulticastChannelList[groupID].ChannelParams.Class;
    if( ( devClass == CLASS_A ) || ( devClass > CLASS_C ) )
    {
        return LORAMAC_STATUS_PARAMETER_INVALID;
    }

    if( ( groupID >= LORAMAC_MAX_MC_CTX ) ||  ( MacCtx.NvmCtx->MulticastChannelList[groupID].ChannelParams.IsEnabled == false ) )
    {
        return LORAMAC_STATUS_MC_GROUP_UNDEFINED;
    }
    *status &= 0x0F; 

    VerifyParams_t verify;
    
    if( devClass == CLASS_B )
    {
        verify.DatarateParams.Datarate = rxParams->ClassB.Datarate;
    }
    else {
        verify.DatarateParams.Datarate = rxParams->ClassC.Datarate;
    }
    verify.DatarateParams.DownlinkDwellTime = MacCtx.NvmCtx->MacParams.DownlinkDwellTime;

    if( RegionVerify( MacCtx.NvmCtx->Region, &verify, PHY_RX_DR ) == true )
    {
        *status &= 0xFB; 
    }

    
    if( devClass == CLASS_B )
    {
        verify.Frequency = rxParams->ClassB.Frequency;
    }
    else {
        verify.Frequency = rxParams->ClassC.Frequency;
    }
    if( RegionVerify( MacCtx.NvmCtx->Region, &verify, PHY_FREQUENCY ) == true )
    {
        *status &= 0xF7; 
    }

    if( *status == ( groupID & 0x03 ) )
    {
        
        MacCtx.NvmCtx->MulticastChannelList[groupID].ChannelParams.RxParams = *rxParams;
    }

    EventMacNvmCtxChanged( );
    EventRegionNvmCtxChanged( );
    return LORAMAC_STATUS_OK;
}

LoRaMacStatus_t LoRaMacMlmeRequest( MlmeReq_t* mlmeRequest )
{
    LoRaMacStatus_t status = LORAMAC_STATUS_SERVICE_UNKNOWN;
    MlmeConfirmQueue_t queueElement;
    uint8_t macCmdPayload[2] = { 0x00, 0x00 };

    if( mlmeRequest == NULL )
    {
        return LORAMAC_STATUS_PARAMETER_INVALID;
    }
    if( LoRaMacIsBusy( ) == true )
    {
        return LORAMAC_STATUS_BUSY;
    }
    if( LoRaMacConfirmQueueIsFull( ) == true )
    {
        return LORAMAC_STATUS_BUSY;
    }

    if( LoRaMacConfirmQueueGetCnt( ) == 0 )
    {
        memset1( ( uint8_t* ) &MacCtx.MlmeConfirm, 0, sizeof( MacCtx.MlmeConfirm ) );
    }
    MacCtx.MlmeConfirm.Status = LORAMAC_EVENT_INFO_STATUS_ERROR;

    MacCtx.MacFlags.Bits.MlmeReq = 1;
    queueElement.Request = mlmeRequest->Type;
    queueElement.Status = LORAMAC_EVENT_INFO_STATUS_ERROR;
    queueElement.RestrictCommonReadyToHandle = false;

    switch( mlmeRequest->Type )
    {
        case MLME_JOIN:
        {
            if( ( MacCtx.MacState & LORAMAC_TX_DELAYED ) == LORAMAC_TX_DELAYED )
            {
                return LORAMAC_STATUS_BUSY;
            }

            ResetMacParameters( );

            MacCtx.NvmCtx->MacParams.ChannelsDatarate = RegionAlternateDr( MacCtx.NvmCtx->Region, mlmeRequest->Req.Join.Datarate, ALTERNATE_DR );

            queueElement.Status = LORAMAC_EVENT_INFO_STATUS_JOIN_FAIL;

            status = SendReJoinReq( JOIN_REQ );

            if( status != LORAMAC_STATUS_OK )
            {
                
                MacCtx.NvmCtx->MacParams.ChannelsDatarate = RegionAlternateDr( MacCtx.NvmCtx->Region, mlmeRequest->Req.Join.Datarate, ALTERNATE_DR_RESTORE );
            }
            break;
        }
        case MLME_LINK_CHECK:
        {
            
            status = LORAMAC_STATUS_OK;
            if( LoRaMacCommandsAddCmd( MOTE_MAC_LINK_CHECK_REQ, macCmdPayload, 0 ) != LORAMAC_COMMANDS_SUCCESS )
            {
                status = LORAMAC_STATUS_MAC_COMMAD_ERROR;
            }
            break;
        }
        case MLME_TXCW:
        {
            status = SetTxContinuousWave( mlmeRequest->Req.TxCw.Timeout );
            break;
        }
        case MLME_TXCW_1:
        {

            status = SetTxContinuousWave1( mlmeRequest->Req.TxCw.Timeout, mlmeRequest->Req.TxCw.Frequency, mlmeRequest->Req.TxCw.Power );
            break;
        }
        case MLME_DEVICE_TIME:
        {
            
            status = LORAMAC_STATUS_OK;
            if( LoRaMacCommandsAddCmd( MOTE_MAC_DEVICE_TIME_REQ, macCmdPayload, 0 ) != LORAMAC_COMMANDS_SUCCESS )
            {
                status = LORAMAC_STATUS_MAC_COMMAD_ERROR;
            }
            break;
        }
        case MLME_PING_SLOT_INFO:
        {
            if( MacCtx.NvmCtx->DeviceClass == CLASS_A )
            {
                uint8_t value = mlmeRequest->Req.PingSlotInfo.PingSlot.Value;

                
                LoRaMacClassBSetPingSlotInfo( mlmeRequest->Req.PingSlotInfo.PingSlot.Fields.Periodicity );
                macCmdPayload[0] = value;
                status = LORAMAC_STATUS_OK;
                if( LoRaMacCommandsAddCmd( MOTE_MAC_PING_SLOT_INFO_REQ, macCmdPayload, 1 ) != LORAMAC_COMMANDS_SUCCESS )
                {
                    status = LORAMAC_STATUS_MAC_COMMAD_ERROR;
                }
            }
            break;
        }
        case MLME_BEACON_TIMING:
        {
            
            status = LORAMAC_STATUS_OK;
            if( LoRaMacCommandsAddCmd( MOTE_MAC_BEACON_TIMING_REQ, macCmdPayload, 0 ) != LORAMAC_COMMANDS_SUCCESS )
            {
                status = LORAMAC_STATUS_MAC_COMMAD_ERROR;
            }
            break;
        }
        case MLME_BEACON_ACQUISITION:
        {
            
            queueElement.RestrictCommonReadyToHandle = true;

            if( LoRaMacClassBIsAcquisitionInProgress( ) == false )
            {
                
                LoRaMacClassBSetBeaconState( BEACON_STATE_ACQUISITION );
                LoRaMacClassBBeaconTimerEvent( NULL );

                status = LORAMAC_STATUS_OK;
            }
            else {
                status = LORAMAC_STATUS_BUSY;
            }
            break;
        }
        default:
            break;
    }

    if( status != LORAMAC_STATUS_OK )
    {
        if( LoRaMacConfirmQueueGetCnt( ) == 0 )
        {
            MacCtx.NodeAckRequested = false;
            MacCtx.MacFlags.Bits.MlmeReq = 0;
        }
    }
    else {
        LoRaMacConfirmQueueAdd( &queueElement );
        EventMacNvmCtxChanged( );
    }
    return status;
}

LoRaMacStatus_t LoRaMacMcpsRequest( McpsReq_t* mcpsRequest )
{
    GetPhyParams_t getPhy;
    PhyParam_t phyParam;
    LoRaMacStatus_t status = LORAMAC_STATUS_SERVICE_UNKNOWN;
    LoRaMacHeader_t macHdr;
    VerifyParams_t verify;
    uint8_t fPort = 0;
    void* fBuffer;
    uint16_t fBufferSize;
    int8_t datarate = DR_0;
    bool readyToSend = false;

    if( mcpsRequest == NULL )
    {
        return LORAMAC_STATUS_PARAMETER_INVALID;
    }
    if( LoRaMacIsBusy( ) == true )
    {
        return LORAMAC_STATUS_BUSY;
    }

    macHdr.Value = 0;
    memset1( ( uint8_t* ) &MacCtx.McpsConfirm, 0, sizeof( MacCtx.McpsConfirm ) );
    MacCtx.McpsConfirm.Status = LORAMAC_EVENT_INFO_STATUS_ERROR;

    
    MacCtx.AckTimeoutRetriesCounter = 1;

    switch( mcpsRequest->Type )
    {
        case MCPS_UNCONFIRMED:
        {
            readyToSend = true;
            MacCtx.AckTimeoutRetries = 1;

            macHdr.Bits.MType = FRAME_TYPE_DATA_UNCONFIRMED_UP;
            fPort = mcpsRequest->Req.Unconfirmed.fPort;
            fBuffer = mcpsRequest->Req.Unconfirmed.fBuffer;
            fBufferSize = mcpsRequest->Req.Unconfirmed.fBufferSize;
            datarate = mcpsRequest->Req.Unconfirmed.Datarate;
            break;
        }
        case MCPS_CONFIRMED:
        {
            readyToSend = true;
            MacCtx.AckTimeoutRetries = MIN( mcpsRequest->Req.Confirmed.NbTrials, MAX_ACK_RETRIES );

            macHdr.Bits.MType = FRAME_TYPE_DATA_CONFIRMED_UP;
            fPort = mcpsRequest->Req.Confirmed.fPort;
            fBuffer = mcpsRequest->Req.Confirmed.fBuffer;
            fBufferSize = mcpsRequest->Req.Confirmed.fBufferSize;
            datarate = mcpsRequest->Req.Confirmed.Datarate;
            break;
        }
        case MCPS_PROPRIETARY:
        {
            readyToSend = true;
            MacCtx.AckTimeoutRetries = 1;

            macHdr.Bits.MType = FRAME_TYPE_PROPRIETARY;
            fBuffer = mcpsRequest->Req.Proprietary.fBuffer;
            fBufferSize = mcpsRequest->Req.Proprietary.fBufferSize;
            datarate = mcpsRequest->Req.Proprietary.Datarate;
            break;
        }
        default:
            break;
    }

    
    getPhy.Attribute = PHY_MIN_TX_DR;
    getPhy.UplinkDwellTime = MacCtx.NvmCtx->MacParams.UplinkDwellTime;
    phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
    
    
    datarate = MAX( datarate, ( int8_t )phyParam.Value );

    if( readyToSend == true )
    {
        if( MacCtx.NvmCtx->AdrCtrlOn == false )
        {
            verify.DatarateParams.Datarate = datarate;
            verify.DatarateParams.UplinkDwellTime = MacCtx.NvmCtx->MacParams.UplinkDwellTime;

            if( RegionVerify( MacCtx.NvmCtx->Region, &verify, PHY_TX_DR ) == true )
            {
                MacCtx.NvmCtx->MacParams.ChannelsDatarate = verify.DatarateParams.Datarate;
            }
            else {
                return LORAMAC_STATUS_PARAMETER_INVALID;
            }
        }

        status = Send( &macHdr, fPort, fBuffer, fBufferSize );
        if( status == LORAMAC_STATUS_OK )
        {
            MacCtx.McpsConfirm.McpsRequest = mcpsRequest->Type;
            MacCtx.MacFlags.Bits.McpsReq = 1;
        }
        else {
            MacCtx.NodeAckRequested = false;
        }
    }

    EventMacNvmCtxChanged( );
    return status;
}

void LoRaMacTestSetDutyCycleOn( bool enable )
{
    VerifyParams_t verify;

    verify.DutyCycle = enable;

    if( RegionVerify( MacCtx.NvmCtx->Region, &verify, PHY_DUTY_CYCLE ) == true )
    {
        MacCtx.NvmCtx->DutyCycleOn = enable;
    }
}

LoRaMacStatus_t LoRaMacDeInitialization( void )
{
    
    if ( LoRaMacStop( ) == LORAMAC_STATUS_OK )
    {
        
        TimerStop( &MacCtx.TxDelayedTimer );
        TimerStop( &MacCtx.RxWindowTimer1 );
        TimerStop( &MacCtx.RxWindowTimer2 );
        TimerStop( &MacCtx.AckTimeoutTimer );

        
        LoRaMacClassBHaltBeaconing( );

        
        ResetMacParameters( );

        
        Radio.Sleep( );

        
        return LORAMAC_STATUS_OK;
    }
    else {
        return LORAMAC_STATUS_BUSY;
    }
}
