

















typedef struct sKey {
    
    KeyIdentifier_t KeyID;
    
    uint8_t KeyValue[SE_KEY_SIZE];
} Key_t;


typedef struct sSecureElementNvCtx {
    
    uint8_t DevEui[SE_EUI_SIZE];
    
    uint8_t JoinEui[SE_EUI_SIZE];
    
    uint8_t Pin[SE_PIN_SIZE];
    
    aes_context AesContext;
    
    AES_CMAC_CTX AesCmacCtx[1];
    
    Key_t KeyList[NUM_OF_KEYS];
} SecureElementNvCtx_t;


static SecureElementNvCtx_t SeNvmCtx = {
    
    .DevEui = LORAWAN_DEVICE_EUI,  .JoinEui = LORAWAN_JOIN_EUI,  .Pin = SECURE_ELEMENT_PIN,  .KeyList = SOFT_SE_KEY_LIST };







static SecureElementNvmEvent SeNvmCtxChanged;




static SecureElementStatus_t GetKeyByID( KeyIdentifier_t keyID, Key_t** keyItem )
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

    uint8_t Cmac[16];

    AES_CMAC_Init( SeNvmCtx.AesCmacCtx );

    Key_t*                keyItem;
    SecureElementStatus_t retval = GetKeyByID( keyID, &keyItem );

    if( retval == SECURE_ELEMENT_SUCCESS )
    {
        AES_CMAC_SetKey( SeNvmCtx.AesCmacCtx, keyItem->KeyValue );

        if( micBxBuffer != NULL )
        {
            AES_CMAC_Update( SeNvmCtx.AesCmacCtx, micBxBuffer, 16 );
        }

        AES_CMAC_Update( SeNvmCtx.AesCmacCtx, buffer, size );

        AES_CMAC_Final( Cmac, SeNvmCtx.AesCmacCtx );

        
        *cmac = ( uint32_t )( ( uint32_t ) Cmac[3] << 24 | ( uint32_t ) Cmac[2] << 16 | ( uint32_t ) Cmac[1] << 8 | ( uint32_t ) Cmac[0] );
    }

    return retval;
}



SecureElementStatus_t SecureElementInit( SecureElementNvmEvent seNvmCtxChanged )
{
    
    if( seNvmCtxChanged != 0 )
    {
        SeNvmCtxChanged = seNvmCtxChanged;
    }
    else {
        SeNvmCtxChanged = DummyCB;
    }



    
    SoftSeHalGetUniqueId( SeNvmCtx.DevEui );



    SeNvmCtxChanged( );

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
    if( key == NULL )
    {
        return SECURE_ELEMENT_ERROR_NPE;
    }

    for( uint8_t i = 0; i < NUM_OF_KEYS; i++ )
    {
        if( SeNvmCtx.KeyList[i].KeyID == keyID )
        {
            if( ( keyID == MC_KEY_0 ) || ( keyID == MC_KEY_1 ) || ( keyID == MC_KEY_2 ) || ( keyID == MC_KEY_3 ) )
            {  
                SecureElementStatus_t retval           = SECURE_ELEMENT_ERROR;
                uint8_t               decryptedKey[16] = { 0 };

                retval = SecureElementAesEncrypt( key, 16, MC_KE_KEY, decryptedKey );

                memcpy1( SeNvmCtx.KeyList[i].KeyValue, decryptedKey, SE_KEY_SIZE );
                SeNvmCtxChanged( );

                return retval;
            }
            else {
                memcpy1( SeNvmCtx.KeyList[i].KeyValue, key, SE_KEY_SIZE );
                SeNvmCtxChanged( );
                return SECURE_ELEMENT_SUCCESS;
            }
        }
    }

    return SECURE_ELEMENT_ERROR_INVALID_KEY_ID;
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
    retval                         = ComputeCmac( NULL, buffer, size, keyID, &compCmac );
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

    memset1( SeNvmCtx.AesContext.ksch, '\0', 240 );

    Key_t*                pItem;
    SecureElementStatus_t retval = GetKeyByID( keyID, &pItem );

    if( retval == SECURE_ELEMENT_SUCCESS )
    {
        aes_set_key( pItem->KeyValue, 16, &SeNvmCtx.AesContext );

        uint8_t block = 0;

        while( size != 0 )
        {
            aes_encrypt( &buffer[block], &encBuffer[block], &SeNvmCtx.AesContext );
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

    SecureElementStatus_t retval  = SECURE_ELEMENT_ERROR;
    uint8_t               key[16] = { 0 };

    
    if( targetKeyID == MC_KE_KEY )
    {
        if( rootKeyID != MC_ROOT_KEY )
        {
            return SECURE_ELEMENT_ERROR_INVALID_KEY_ID;
        }
    }

    
    retval = SecureElementAesEncrypt( input, 16, rootKeyID, key );
    if( retval != SECURE_ELEMENT_SUCCESS )
    {
        return retval;
    }

    
    retval = SecureElementSetKey( targetKeyID, key );
    if( retval != SECURE_ELEMENT_SUCCESS )
    {
        return retval;
    }

    return SECURE_ELEMENT_SUCCESS;
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
    *randomNum = SoftSeHalGetRandomNumber( );
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
