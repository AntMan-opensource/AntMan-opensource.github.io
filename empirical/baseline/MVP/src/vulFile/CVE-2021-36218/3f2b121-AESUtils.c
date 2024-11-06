









sgx_aes_gcm_128bit_key_t AES_key;
sgx_aes_gcm_128bit_key_t AES_DH_key;

int AES_encrypt(char *message, uint8_t *encr_message, uint64_t encrLen) {

    if (!message) {
        LOG_ERROR("Null message in AES_encrypt");
        return -1;
    }

    if (!encr_message) {
        LOG_ERROR("Null encr message in AES_encrypt");
        return -2;
    }

    uint64_t len = strlen(message) + 1;

    if (len + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE > encrLen ) {
        LOG_ERROR("Output buffer too small");
        return -3;
    }

    sgx_read_rand(encr_message + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE);

    sgx_status_t status = sgx_rijndael128GCM_encrypt(&AES_key, (uint8_t*)message, strlen(message), encr_message + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE, encr_message + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE, NULL, 0, (sgx_aes_gcm_128bit_tag_t *) encr_message);




    return status;
}

int AES_decrypt(uint8_t *encr_message, uint64_t length, char *message, uint64_t msgLen) {

    if (!message) {
        LOG_ERROR("Null message in AES_encrypt");
        return -1;
    }

    if (!encr_message) {
        LOG_ERROR("Null encr message in AES_encrypt");
        return -2;
    }


  if (length < SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE) {
      LOG_ERROR("length < SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE");
      return -1;
  }



  uint64_t len = length - SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE;

  if (msgLen < len) {
        LOG_ERROR("Output buffer not large enough");
        return -2;
  }

  sgx_status_t status = sgx_rijndael128GCM_decrypt(&AES_key, encr_message + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE, len, (unsigned char*) message, encr_message + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE, NULL, 0, (sgx_aes_gcm_128bit_tag_t *)encr_message);





  return status;
}




int AES_encrypt_DH(char *message, uint8_t *encr_message, uint64_t encrLen) {

    if (!message) {
        LOG_ERROR("Null message in AES_encrypt_DH");
        return -1;
    }

    if (!encr_message) {
        LOG_ERROR("Null encr message in AES_encrypt_DH");
        return -2;
    }

    uint64_t len = strlen(message) + 1;

    if (len + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE > encrLen ) {
        LOG_ERROR("Output buffer too small");
        return -3;
    }

    sgx_read_rand(encr_message + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE);

    sgx_status_t status = sgx_rijndael128GCM_encrypt(&AES_DH_key, (uint8_t*)message, strlen(message), encr_message + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE, encr_message + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE, NULL, 0, (sgx_aes_gcm_128bit_tag_t *) encr_message);




    return status;
}

int AES_decrypt_DH(uint8_t *encr_message, uint64_t length, char *message, uint64_t msgLen) {

    if (!message) {
        LOG_ERROR("Null message in AES_encrypt_DH");
        return -1;
    }

    if (!encr_message) {
        LOG_ERROR("Null encr message in AES_encrypt_DH");
        return -2;
    }


    if (length < SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE) {
        LOG_ERROR("length < SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE");
        return -1;
    }



    uint64_t len = length - SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE;

    if (msgLen < len) {
        LOG_ERROR("Output buffer not large enough");
        return -2;
    }

    sgx_status_t status = sgx_rijndael128GCM_decrypt(&AES_DH_key, encr_message + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE, len, (unsigned char*) message, encr_message + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE, NULL, 0, (sgx_aes_gcm_128bit_tag_t *)encr_message);





    return status;
}






void derive_DH_Key() {
    memcpy(AES_DH_key, AES_key, SGX_AESGCM_KEY_SIZE );
    
}

