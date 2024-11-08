
























typedef struct sSecureElementNvCtx {
    
    uint8_t DevEui[SE_EUI_SIZE];
    
    uint8_t JoinEui[SE_EUI_SIZE];
    
    uint8_t Pin[SE_PIN_SIZE];
} SecureElementNvCtx_t;

static SecureElementNvCtx_t SeContext = {
    
    .DevEui = LORAWAN_DEVICE_EUI,  .JoinEui = LORAWAN_JOIN_EUI,  .Pin = SECURE_ELEMENT_PIN, };





static SecureElementNvmEvent SeNvmCtxChanged;


extern lr1110_t LR1110;


static lr1110_crypto_keys_idx_t convert_key_id_from_se_to_lr1110( KeyIdentifier_t key_id );


static void DummyCB( void )
{
    return;
}

SecureElementStatus_t SecureElementInit( SecureElementNvmEvent seNvmCtxChanged )
{
    lr1110_crypto_status_t status = LR1110_CRYPTO_STATUS_ERROR;

    
    if( seNvmCtxChanged != 0 )
    {
        SeNvmCtxChanged = seNvmCtxChanged;
    }
    else {
        SeNvmCtxChanged = DummyCB;
    }

    lr1110_crypto_restore_from_flash( &LR1110, &status );


    
    lr1110_system_read_uid( &LR1110, SeContext.DevEui );
    lr1110_system_read_join_eui( &LR1110, SeContext.JoinEui );
    lr1110_system_read_pin( &LR1110, SeContext.Pin );


    
    LR1110SeHalGetUniqueId( SeContext.DevEui );



    SeNvmCtxChanged( );

    return ( SecureElementStatus_t ) status;
}

SecureElementStatus_t SecureElementRestoreNvmCtx( void* seNvmCtx )
{
    lr1110_crypto_status_t status = LR1110_CRYPTO_STATUS_ERROR;

    if( seNvmCtx == NULL )
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }

    
    lr1110_crypto_restore_from_flash( &LR1110, &status );

    
    memcpy1( ( uint8_t* ) &SeContext, ( uint8_t* ) seNvmCtx, sizeof( SeContext ) );

    return ( SecureElementStatus_t ) status;
}

void* SecureElementGetNvmCtx( size_t* seNvmCtxSize )
{
    *seNvmCtxSize = sizeof( SeContext );
    return &SeContext;
}

SecureElementStatus_t SecureElementSetKey( KeyIdentifier_t keyID, uint8_t* key )
{
    if( key == NULL )
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }

    SecureElementStatus_t status = SECURE_ELEMENT_ERROR;

    if( ( keyID == MC_KEY_0 ) || ( keyID == MC_KEY_1 ) || ( keyID == MC_KEY_2 ) || ( keyID == MC_KEY_3 ) )
    {  

        lr1110_crypto_derive_and_store_key( &LR1110, ( lr1110_crypto_status_t* ) &status, convert_key_id_from_se_to_lr1110( MC_KE_KEY ), convert_key_id_from_se_to_lr1110( keyID ), key );


        if( status == SECURE_ELEMENT_SUCCESS )
        {
            lr1110_crypto_store_to_flash( &LR1110, ( lr1110_crypto_status_t* ) &status );
        }
        return status;
    }
    else {
        lr1110_crypto_set_key( &LR1110, ( lr1110_crypto_status_t* ) &status, convert_key_id_from_se_to_lr1110( keyID ), key );
        if( status == SECURE_ELEMENT_SUCCESS )
        {
            lr1110_crypto_store_to_flash( &LR1110, ( lr1110_crypto_status_t* ) &status );
        }
        return status;
    }
}

SecureElementStatus_t SecureElementComputeAesCmac( uint8_t* micBxBuffer, uint8_t* buffer, uint16_t size, KeyIdentifier_t keyID, uint32_t* cmac )
{
    SecureElementStatus_t status      = SECURE_ELEMENT_ERROR;
    uint16_t              localSize   = size;
    uint8_t*              localbuffer = buffer;

    if( micBxBuffer != NULL )
    {
        uint8_t micBuff[CRYPTO_BUFFER_SIZE];

        memset1( micBuff, 0, CRYPTO_BUFFER_SIZE );

        memcpy1( micBuff, micBxBuffer, MIC_BLOCK_BX_SIZE );
        memcpy1( ( micBuff + MIC_BLOCK_BX_SIZE ), buffer, size );
        localSize += MIC_BLOCK_BX_SIZE;
        localbuffer = micBuff;
    }

    lr1110_crypto_compute_aes_cmac( &LR1110, ( lr1110_crypto_status_t* ) &status, convert_key_id_from_se_to_lr1110( keyID ), localbuffer, localSize, ( uint8_t* ) cmac );


    return status;
}

SecureElementStatus_t SecureElementVerifyAesCmac( uint8_t* buffer, uint16_t size, uint32_t expectedCmac, KeyIdentifier_t keyID )
{
    SecureElementStatus_t status = SECURE_ELEMENT_ERROR;

    if( buffer == NULL )
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }

    lr1110_crypto_verify_aes_cmac( &LR1110, ( lr1110_crypto_status_t* ) &status, convert_key_id_from_se_to_lr1110( keyID ), buffer, size, ( uint8_t* ) &expectedCmac );


    return status;
}

SecureElementStatus_t SecureElementAesEncrypt( uint8_t* buffer, uint16_t size, KeyIdentifier_t keyID, uint8_t* encBuffer )
{
    SecureElementStatus_t status = SECURE_ELEMENT_ERROR;

    if( ( buffer == NULL ) || ( encBuffer == NULL ) )
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }

    lr1110_crypto_aes_encrypt_01( &LR1110, ( lr1110_crypto_status_t* ) &status, convert_key_id_from_se_to_lr1110( keyID ), buffer, size, encBuffer );

    return status;
}

SecureElementStatus_t SecureElementDeriveAndStoreKey( Version_t version, uint8_t* input, KeyIdentifier_t rootKeyID, KeyIdentifier_t targetKeyID )
{
    SecureElementStatus_t status = SECURE_ELEMENT_ERROR;

    if( input == NULL )
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }

    lr1110_crypto_derive_and_store_key( &LR1110, ( lr1110_crypto_status_t* ) &status, convert_key_id_from_se_to_lr1110( rootKeyID ), convert_key_id_from_se_to_lr1110( targetKeyID ), input );


    lr1110_crypto_store_to_flash( &LR1110, ( lr1110_crypto_status_t* ) &status );
    return status;
}

SecureElementStatus_t SecureElementProcessJoinAccept( JoinReqIdentifier_t joinReqType, uint8_t* joinEui, uint16_t devNonce, uint8_t* encJoinAccept, uint8_t encJoinAcceptSize, uint8_t* decJoinAccept, uint8_t* versionMinor )


{
    SecureElementStatus_t status = SECURE_ELEMENT_ERROR;

    if( ( encJoinAccept == NULL ) || ( decJoinAccept == NULL ) || ( versionMinor == NULL ) )
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }

    
    KeyIdentifier_t encKeyID = NWK_KEY;

    if( joinReqType != JOIN_REQ )
    {
        encKeyID = J_S_ENC_KEY;
    }

    
    
    

    
    uint8_t micHeader10[1] = { 0x20 };

    
    
    lr1110_crypto_process_join_accept( &LR1110, ( lr1110_crypto_status_t* ) &status, convert_key_id_from_se_to_lr1110( encKeyID ), convert_key_id_from_se_to_lr1110( NWK_KEY ), ( lr1110_crypto_lorawan_version_t ) 0, micHeader10, encJoinAccept + 1, encJoinAcceptSize - 1, decJoinAccept + 1 );



    if( status == SECURE_ELEMENT_SUCCESS )
    {
        *versionMinor = ( ( decJoinAccept[11] & 0x80 ) == 0x80 ) ? 1 : 0;
        if( *versionMinor == 0 )
        {
            
            return SECURE_ELEMENT_SUCCESS;
        }
    }


    
    uint8_t  micHeader11[JOIN_ACCEPT_MIC_COMPUTATION_OFFSET] = { 0 };
    uint16_t bufItr                                     = 0;

    
    
    micHeader11[bufItr++] = ( uint8_t ) joinReqType;

    memcpyr( micHeader11 + bufItr, joinEui, LORAMAC_JOIN_EUI_FIELD_SIZE );
    bufItr += LORAMAC_JOIN_EUI_FIELD_SIZE;

    micHeader11[bufItr++] = devNonce & 0xFF;
    micHeader11[bufItr++] = ( devNonce >> 8 ) & 0xFF;

    micHeader11[bufItr++] = 0x20;

    lr1110_crypto_process_join_accept( &LR1110, ( lr1110_crypto_status_t* ) &status, convert_key_id_from_se_to_lr1110( encKeyID ), convert_key_id_from_se_to_lr1110( J_S_INT_KEY ), ( lr1110_crypto_lorawan_version_t ) 1, micHeader11, encJoinAccept + 1, encJoinAcceptSize - 1, decJoinAccept + 1 );



    if( status == SECURE_ELEMENT_SUCCESS )
    {
        *versionMinor = ( ( decJoinAccept[11] & 0x80 ) == 0x80 ) ? 1 : 0;
        if( *versionMinor == 1 )
        {
            
            return SECURE_ELEMENT_SUCCESS;
        }
    }


    return status;
}

SecureElementStatus_t SecureElementRandomNumber( uint32_t* randomNum )
{
    if( randomNum == NULL )
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }
    *randomNum = LR1110SeHalGetRandomNumber( );
    return SECURE_ELEMENT_SUCCESS;
}

SecureElementStatus_t SecureElementSetDevEui( uint8_t* devEui )
{
    if( devEui == NULL )
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }
    memcpy1( SeContext.DevEui, devEui, SE_EUI_SIZE );
    SeNvmCtxChanged( );
    return SECURE_ELEMENT_SUCCESS;
}

uint8_t* SecureElementGetDevEui( void )
{
    return SeContext.DevEui;
}

SecureElementStatus_t SecureElementSetJoinEui( uint8_t* joinEui )
{
    if( joinEui == NULL )
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }
    memcpy1( SeContext.JoinEui, joinEui, SE_EUI_SIZE );
    SeNvmCtxChanged( );
    return SECURE_ELEMENT_SUCCESS;
}

uint8_t* SecureElementGetJoinEui( void )
{
    return SeContext.JoinEui;
}

SecureElementStatus_t SecureElementSetPin( uint8_t* pin )
{
    if( pin == NULL )
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }

    memcpy1( SeContext.Pin, pin, SE_PIN_SIZE );
    SeNvmCtxChanged( );
    return SECURE_ELEMENT_SUCCESS;
}

uint8_t* SecureElementGetPin( void )
{
    return SeContext.Pin;
}

static lr1110_crypto_keys_idx_t convert_key_id_from_se_to_lr1110( KeyIdentifier_t key_id )
{
    lr1110_crypto_keys_idx_t id = LR1110_CRYPTO_KEYS_IDX_GP0;

    switch( key_id )
    {
        case APP_KEY:
            id = LR1110_CRYPTO_KEYS_IDX_APP_KEY;
            break;
        case NWK_KEY:
            id = LR1110_CRYPTO_KEYS_IDX_NWK_KEY;
            break;
        case J_S_INT_KEY:
            id = LR1110_CRYPTO_KEYS_IDX_J_S_INT_KEY;
            break;
        case J_S_ENC_KEY:
            id = LR1110_CRYPTO_KEYS_IDX_J_S_ENC_KEY;
            break;
        case F_NWK_S_INT_KEY:
            id = LR1110_CRYPTO_KEYS_IDX_F_NWK_S_INT_KEY;
            break;
        case S_NWK_S_INT_KEY:
            id = LR1110_CRYPTO_KEYS_IDX_S_NWK_S_INT_KEY;
            break;
        case NWK_S_ENC_KEY:
            id = LR1110_CRYPTO_KEYS_IDX_NWK_S_ENC_KEY;
            break;
        case APP_S_KEY:
            id = LR1110_CRYPTO_KEYS_IDX_APP_S_KEY;
            break;
        case MC_ROOT_KEY:
            id = LR1110_CRYPTO_KEYS_IDX_GP_KE_KEY_5;
            break;
        case MC_KE_KEY:
            id = LR1110_CRYPTO_KEYS_IDX_GP_KE_KEY_4;
            break;
        case MC_KEY_0:
            id = LR1110_CRYPTO_KEYS_IDX_GP_KE_KEY_0;
            break;
        case MC_APP_S_KEY_0:
            id = LR1110_CRYPTO_KEYS_IDX_MC_APP_S_KEY_0;
            break;
        case MC_NWK_S_KEY_0:
            id = LR1110_CRYPTO_KEYS_IDX_MC_NWK_S_KEY_0;
            break;
        case MC_KEY_1:
            id = LR1110_CRYPTO_KEYS_IDX_GP_KE_KEY_1;
            break;
        case MC_APP_S_KEY_1:
            id = LR1110_CRYPTO_KEYS_IDX_MC_APP_S_KEY_1;
            break;
        case MC_NWK_S_KEY_1:
            id = LR1110_CRYPTO_KEYS_IDX_MC_NWK_S_KEY_1;
            break;
        case MC_KEY_2:
            id = LR1110_CRYPTO_KEYS_IDX_GP_KE_KEY_2;
            break;
        case MC_APP_S_KEY_2:
            id = LR1110_CRYPTO_KEYS_IDX_MC_APP_S_KEY_2;
            break;
        case MC_NWK_S_KEY_2:
            id = LR1110_CRYPTO_KEYS_IDX_MC_NWK_S_KEY_2;
            break;
        case MC_KEY_3:
            id = LR1110_CRYPTO_KEYS_IDX_GP_KE_KEY_3;
            break;
        case MC_APP_S_KEY_3:
            id = LR1110_CRYPTO_KEYS_IDX_MC_APP_S_KEY_3;
            break;
        case MC_NWK_S_KEY_3:
            id = LR1110_CRYPTO_KEYS_IDX_MC_NWK_S_KEY_3;
            break;
        case SLOT_RAND_ZERO_KEY:
            id = LR1110_CRYPTO_KEYS_IDX_GP0;
            break;
        default:
            id = LR1110_CRYPTO_KEYS_IDX_GP1;
            break;
    }
    return id;
}
