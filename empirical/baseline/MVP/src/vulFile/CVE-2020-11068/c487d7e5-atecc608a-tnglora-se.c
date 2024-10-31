















typedef struct sKey {
    
    KeyIdentifier_t KeyID;
    
    uint16_t KeySlotNumber;
    
    uint8_t KeyBlockIndex;
} Key_t;


typedef struct sSecureElementNvCtx {
    
    uint8_t DevEui[SE_EUI_SIZE];
    
    uint8_t JoinEui[SE_EUI_SIZE];
    
    uint8_t Pin[SE_PIN_SIZE];
    
    atca_aes_cmac_ctx_t AtcaAesCmacCtx;
    
    Key_t KeyList[NUM_OF_KEYS];
} SecureElementNvCtx_t;


static SecureElementNvCtx_t SeNvmCtx = {
    
    .DevEui = { 0 },  .JoinEui = { 0 },  .Pin = SECURE_ELEMENT_PIN,  .KeyList = ATECC608A_SE_KEY_LIST };







static SecureElementNvmEvent SeNvmCtxChanged;

static ATCAIfaceCfg atecc608_i2c_config;

static ATCA_STATUS convert_ascii_devEUI( uint8_t* devEUI_ascii, uint8_t* devEUI );

static ATCA_STATUS atcab_read_joinEUI( uint8_t* joinEUI )
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t     read_buf[ATCA_BLOCK_SIZE];

    if( joinEUI == NULL )
    {
        return ATCA_BAD_PARAM;
    }

    do {
        status = atcab_read_zone( ATCA_ZONE_DATA, TNGLORA_JOIN_EUI_SLOT, 0, 0, read_buf, ATCA_BLOCK_SIZE );
        if( status != ATCA_SUCCESS )
        {
            break;
        }
        memcpy1( joinEUI, read_buf, SE_EUI_SIZE );
    } while( 0 );

    return status;
}

static ATCA_STATUS atcab_read_ascii_devEUI( uint8_t* devEUI_ascii )
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t     read_buf[ATCA_BLOCK_SIZE];

    if( devEUI_ascii == NULL )
    {
        return ATCA_BAD_PARAM;
    }

    do {
        status = atcab_read_zone( ATCA_ZONE_DATA, TNGLORA_DEV_EUI_SLOT, 0, 0, read_buf, ATCA_BLOCK_SIZE );
        if( status != ATCA_SUCCESS )
        {
            break;
        }
        memcpy1( devEUI_ascii, read_buf, DEV_EUI_ASCII_SIZE_BYTE );
    } while( 0 );

    return status;
}

static ATCA_STATUS convert_ascii_devEUI( uint8_t* devEUI_ascii, uint8_t* devEUI )
{
    for( size_t pos = 0; pos < DEV_EUI_ASCII_SIZE_BYTE; pos += 2 )
    {
        uint8_t temp = 0;
        if( ( devEUI_ascii[pos] >= '0' ) && ( devEUI_ascii[pos] <= '9' ) )
        {
            temp = ( devEUI_ascii[pos] - '0' ) << 4;
        }
        else if( ( devEUI_ascii[pos] >= 'A' ) && ( devEUI_ascii[pos] <= 'F' ) )
        {
            temp = ( ( devEUI_ascii[pos] - 'A' ) + 10 ) << 4;
        }
        else {
            return ATCA_BAD_PARAM;
        }
        if( ( devEUI_ascii[pos + 1] >= '0' ) && ( devEUI_ascii[pos + 1] <= '9' ) )
        {
            temp |= devEUI_ascii[pos + 1] - '0';
        }
        else if( ( devEUI_ascii[pos + 1] >= 'A' ) && ( devEUI_ascii[pos + 1] <= 'F' ) )
        {
            temp |= ( devEUI_ascii[pos + 1] - 'A' ) + 10;
        }
        else {
            return ATCA_BAD_PARAM;
        }
        devEUI[pos / 2] = temp;
    }
    return ATCA_SUCCESS;
}

static ATCA_STATUS atcab_read_devEUI( uint8_t* devEUI )
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t     devEUI_ascii[DEV_EUI_ASCII_SIZE_BYTE];

    status = atcab_read_ascii_devEUI( devEUI_ascii );
    if( status != ATCA_SUCCESS )
    {
        return status;
    }
    status = convert_ascii_devEUI( devEUI_ascii, devEUI );
    return status;
}


SecureElementStatus_t GetKeyByID( KeyIdentifier_t keyID, Key_t** keyItem )
{
    for( uint8_t i = 0; i < NUM_OF_KEYS; i++ )
    {
        if( SeNvmCtx.KeyList[i].KeyID == keyID )
        {
            *keyItem = &( SeNvmCtx.KeyList[i] );
            return SECURE_ELEMENT_SUCCESS;
        }
    }
    return SECURE_ELEMENT_ERROR_INVALID_KEY_ID;
}


static void DummyCB( void )
{
    return;
}


static SecureElementStatus_t ComputeCmac( uint8_t* micBxBuffer, uint8_t* buffer, uint16_t size, KeyIdentifier_t keyID, uint32_t* cmac )
{
    if( ( buffer == NULL ) || ( cmac == NULL ) )
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }

    uint8_t Cmac[16] = { 0 };

    Key_t*                keyItem;
    SecureElementStatus_t retval = GetKeyByID( keyID, &keyItem );
    if( retval != SECURE_ELEMENT_SUCCESS )
    {
        return retval;
    }

    ATCA_STATUS status = atcab_aes_cmac_init( &SeNvmCtx.AtcaAesCmacCtx, keyItem->KeySlotNumber, keyItem->KeyBlockIndex );

    if( ATCA_SUCCESS == status )
    {
        if( micBxBuffer != NULL )
        {
            atcab_aes_cmac_update( &SeNvmCtx.AtcaAesCmacCtx, micBxBuffer, 16 );
        }

        atcab_aes_cmac_update( &SeNvmCtx.AtcaAesCmacCtx, buffer, size );

        atcab_aes_cmac_finish( &SeNvmCtx.AtcaAesCmacCtx, Cmac, 16 );

        *cmac = ( uint32_t )( ( uint32_t ) Cmac[3] << 24 | ( uint32_t ) Cmac[2] << 16 | ( uint32_t ) Cmac[1] << 8 | ( uint32_t ) Cmac[0] );
        return SECURE_ELEMENT_SUCCESS;
    }
    else {
        return SECURE_ELEMENT_ERROR;
    }
}

SecureElementStatus_t SecureElementInit( SecureElementNvmEvent seNvmCtxChanged )
{



    atecc608_i2c_config.iface_type            = ATCA_I2C_IFACE;
    atecc608_i2c_config.atcai2c.baud          = ATCA_HAL_ATECC608A_I2C_FREQUENCY;
    atecc608_i2c_config.atcai2c.bus           = ATCA_HAL_ATECC608A_I2C_BUS_PINS;
    atecc608_i2c_config.atcai2c.slave_address = ATCA_HAL_ATECC608A_I2C_ADDRESS;
    atecc608_i2c_config.devtype               = ATECC608A;
    atecc608_i2c_config.rx_retries            = ATCA_HAL_ATECC608A_I2C_RX_RETRIES;
    atecc608_i2c_config.wake_delay            = ATCA_HAL_ATECC608A_I2C_WAKEUP_DELAY;

    if( atcab_init( &atecc608_i2c_config ) != ATCA_SUCCESS )
    {
        return SECURE_ELEMENT_ERROR;
    }

    if( atcab_read_devEUI( SeNvmCtx.DevEui ) != ATCA_SUCCESS )
    {
        return SECURE_ELEMENT_ERROR;
    }

    if( atcab_read_joinEUI( SeNvmCtx.JoinEui ) != ATCA_SUCCESS )
    {
        return SECURE_ELEMENT_ERROR;
    }

    
    if( seNvmCtxChanged != 0 )
    {
        SeNvmCtxChanged = seNvmCtxChanged;
    }
    else {
        SeNvmCtxChanged = DummyCB;
    }

    return SECURE_ELEMENT_SUCCESS;
}

SecureElementStatus_t SecureElementRestoreNvmCtx( void* seNvmCtx )
{
    
    if( seNvmCtx != 0 )
    {
        memcpy1( ( uint8_t* ) &SeNvmCtx, ( uint8_t* ) seNvmCtx, sizeof( SeNvmCtx ) );
        return SECURE_ELEMENT_SUCCESS;
    }
    else {
        return SECURE_ELEMENT_ERROR_NPE;
    }
}

void* SecureElementGetNvmCtx( size_t* seNvmCtxSize )
{
    *seNvmCtxSize = sizeof( SeNvmCtx );
    return &SeNvmCtx;
}

SecureElementStatus_t SecureElementSetKey( KeyIdentifier_t keyID, uint8_t* key )
{
    
    return SECURE_ELEMENT_SUCCESS;
}

SecureElementStatus_t SecureElementComputeAesCmac( uint8_t* micBxBuffer, uint8_t* buffer, uint16_t size, KeyIdentifier_t keyID, uint32_t* cmac )
{
    if( keyID >= LORAMAC_CRYPTO_MULTICAST_KEYS )
    {
        
        return SECURE_ELEMENT_ERROR_INVALID_KEY_ID;
    }
    return ComputeCmac( micBxBuffer, buffer, size, keyID, cmac );
}

SecureElementStatus_t SecureElementVerifyAesCmac( uint8_t* buffer, uint16_t size, uint32_t expectedCmac, KeyIdentifier_t keyID )
{
    if( buffer == NULL )
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }

    SecureElementStatus_t retval   = SECURE_ELEMENT_ERROR;
    uint32_t              compCmac = 0;

    retval = ComputeCmac( NULL, buffer, size, keyID, &compCmac );
    if( retval != SECURE_ELEMENT_SUCCESS )
    {
        return retval;
    }

    if( expectedCmac != compCmac )
    {
        retval = SECURE_ELEMENT_FAIL_CMAC;
    }

    return retval;
}

SecureElementStatus_t SecureElementAesEncrypt( uint8_t* buffer, uint16_t size, KeyIdentifier_t keyID, uint8_t* encBuffer )
{
    if( buffer == NULL || encBuffer == NULL )
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }

    
    if( ( size % 16 ) != 0 )
    {
        return SECURE_ELEMENT_ERROR_BUF_SIZE;
    }

    Key_t*                pItem;
    SecureElementStatus_t retval = GetKeyByID( keyID, &pItem );

    if( retval == SECURE_ELEMENT_SUCCESS )
    {
        uint8_t block = 0;

        while( size != 0 )
        {
            atcab_aes_encrypt( pItem->KeySlotNumber, pItem->KeyBlockIndex, &buffer[block], &encBuffer[block] );
            block = block + 16;
            size  = size - 16;
        }
    }
    return retval;
}

SecureElementStatus_t SecureElementDeriveAndStoreKey( Version_t version, uint8_t* input, KeyIdentifier_t rootKeyID, KeyIdentifier_t targetKeyID )
{
    if( input == NULL )
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }

    
    uint16_t    source_target_ids = 0;
    Key_t*      source_key;
    Key_t*      target_key;
    ATCA_STATUS status = ATCA_SUCCESS;

    
    if( targetKeyID == MC_KE_KEY )
    {
        if( rootKeyID != MC_ROOT_KEY )
        {
            return SECURE_ELEMENT_ERROR_INVALID_KEY_ID;
        }
    }

    if( ( rootKeyID == APP_KEY ) || ( rootKeyID == MC_ROOT_KEY ) || ( rootKeyID == MC_KE_KEY ) )
    {
        
        return SECURE_ELEMENT_SUCCESS;
    }

    if( GetKeyByID( rootKeyID, &source_key ) != SECURE_ELEMENT_SUCCESS )
    {
        return SECURE_ELEMENT_ERROR_INVALID_KEY_ID;
    }

    if( GetKeyByID( targetKeyID, &target_key ) != SECURE_ELEMENT_SUCCESS )
    {
        return SECURE_ELEMENT_ERROR_INVALID_KEY_ID;
    }

    source_target_ids = target_key->KeySlotNumber << 8;
    source_target_ids += source_key->KeySlotNumber;

    uint32_t detail = source_key->KeyBlockIndex;

    status = atcab_kdf( KDF_MODE_ALG_AES | KDF_MODE_SOURCE_SLOT | KDF_MODE_TARGET_SLOT, source_target_ids, detail, input, NULL, NULL );
    if( status == ATCA_SUCCESS )
    {
        return SECURE_ELEMENT_SUCCESS;
    }
    else {
        return SECURE_ELEMENT_ERROR;
    }
}

SecureElementStatus_t SecureElementProcessJoinAccept( JoinReqIdentifier_t joinReqType, uint8_t* joinEui, uint16_t devNonce, uint8_t* encJoinAccept, uint8_t encJoinAcceptSize, uint8_t* decJoinAccept, uint8_t* versionMinor )


{
    if( ( encJoinAccept == NULL ) || ( decJoinAccept == NULL ) || ( versionMinor == NULL ) )
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }

    
    KeyIdentifier_t encKeyID = NWK_KEY;

    if( joinReqType != JOIN_REQ )
    {
        encKeyID = J_S_ENC_KEY;
    }

    memcpy1( decJoinAccept, encJoinAccept, encJoinAcceptSize );

    
    if( SecureElementAesEncrypt( encJoinAccept + LORAMAC_MHDR_FIELD_SIZE, encJoinAcceptSize - LORAMAC_MHDR_FIELD_SIZE, encKeyID, decJoinAccept + LORAMAC_MHDR_FIELD_SIZE ) != SECURE_ELEMENT_SUCCESS )
    {
        return SECURE_ELEMENT_FAIL_ENCRYPT;
    }

    *versionMinor = ( ( decJoinAccept[11] & 0x80 ) == 0x80 ) ? 1 : 0;

    uint32_t mic = 0;

    mic = ( ( uint32_t ) decJoinAccept[encJoinAcceptSize - LORAMAC_MIC_FIELD_SIZE] << 0 );
    mic |= ( ( uint32_t ) decJoinAccept[encJoinAcceptSize - LORAMAC_MIC_FIELD_SIZE + 1] << 8 );
    mic |= ( ( uint32_t ) decJoinAccept[encJoinAcceptSize - LORAMAC_MIC_FIELD_SIZE + 2] << 16 );
    mic |= ( ( uint32_t ) decJoinAccept[encJoinAcceptSize - LORAMAC_MIC_FIELD_SIZE + 3] << 24 );

    
    
    

    
    if( *versionMinor == 0 )
    {
        
        
        
        if( SecureElementVerifyAesCmac( decJoinAccept, ( encJoinAcceptSize - LORAMAC_MIC_FIELD_SIZE ), mic, NWK_KEY ) != SECURE_ELEMENT_SUCCESS )
        {
            return SECURE_ELEMENT_FAIL_CMAC;
        }
    }

    else if( *versionMinor == 1 )
    {
        uint8_t  micHeader11[JOIN_ACCEPT_MIC_COMPUTATION_OFFSET] = { 0 };
        uint16_t bufItr                                          = 0;

        micHeader11[bufItr++] = ( uint8_t ) joinReqType;

        memcpyr( micHeader11 + bufItr, joinEui, LORAMAC_JOIN_EUI_FIELD_SIZE );
        bufItr += LORAMAC_JOIN_EUI_FIELD_SIZE;

        micHeader11[bufItr++] = devNonce & 0xFF;
        micHeader11[bufItr++] = ( devNonce >> 8 ) & 0xFF;

        
        
        
        
        uint8_t localBuffer[LORAMAC_JOIN_ACCEPT_FRAME_MAX_SIZE + JOIN_ACCEPT_MIC_COMPUTATION_OFFSET] = { 0 };

        memcpy1( localBuffer, micHeader11, JOIN_ACCEPT_MIC_COMPUTATION_OFFSET );
        memcpy1( localBuffer + JOIN_ACCEPT_MIC_COMPUTATION_OFFSET - 1, decJoinAccept, encJoinAcceptSize );

        if( SecureElementVerifyAesCmac( localBuffer, encJoinAcceptSize + JOIN_ACCEPT_MIC_COMPUTATION_OFFSET - LORAMAC_MHDR_FIELD_SIZE - LORAMAC_MIC_FIELD_SIZE, mic, J_S_INT_KEY ) != SECURE_ELEMENT_SUCCESS )


        {
            return SECURE_ELEMENT_FAIL_CMAC;
        }
    }

    else {
        return SECURE_ELEMENT_ERROR_INVALID_LORAWAM_SPEC_VERSION;
    }

    return SECURE_ELEMENT_SUCCESS;
}

SecureElementStatus_t SecureElementRandomNumber( uint32_t* randomNum )
{
    if( randomNum == NULL )
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }
    *randomNum = ATECC608ASeHalGetRandomNumber( );
    return SECURE_ELEMENT_SUCCESS;
}

SecureElementStatus_t SecureElementSetDevEui( uint8_t* devEui )
{
    if( devEui == NULL )
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }
    memcpy1( SeNvmCtx.DevEui, devEui, SE_EUI_SIZE );
    SeNvmCtxChanged( );
    return SECURE_ELEMENT_SUCCESS;
}

uint8_t* SecureElementGetDevEui( void )
{
    return SeNvmCtx.DevEui;
}

SecureElementStatus_t SecureElementSetJoinEui( uint8_t* joinEui )
{
    if( joinEui == NULL )
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }
    memcpy1( SeNvmCtx.JoinEui, joinEui, SE_EUI_SIZE );
    SeNvmCtxChanged( );
    return SECURE_ELEMENT_SUCCESS;
}

uint8_t* SecureElementGetJoinEui( void )
{
    return SeNvmCtx.JoinEui;
}

SecureElementStatus_t SecureElementSetPin( uint8_t* pin )
{
    if( pin == NULL )
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }

    memcpy1( SeNvmCtx.Pin, pin, SE_PIN_SIZE );
    SeNvmCtxChanged( );
    return SECURE_ELEMENT_SUCCESS;
}

uint8_t* SecureElementGetPin( void )
{
    return SeNvmCtx.Pin;
}
