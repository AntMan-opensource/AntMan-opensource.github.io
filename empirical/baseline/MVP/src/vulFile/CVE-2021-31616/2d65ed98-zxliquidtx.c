



















static HDNode *zx_getDerivedNode(const char *curve, const uint32_t *address_n, size_t address_n_count, uint32_t *fingerprint) {

    static HDNode CONFIDENTIAL node;
    if (fingerprint) {
        *fingerprint = 0;
    }

    if (!get_curve_by_name(curve)) {
       return 0;
    }

    if (!storage_getRootNode(curve, true, &node)) {
        return 0;
    }

    if (!address_n || address_n_count == 0) {
        return &node;
    }

    if (hdnode_private_ckd_cached(&node, address_n, address_n_count, fingerprint) == 0) {
        return 0;
    }

    return &node;
}

static bool isAddLiquidityEthCall(const EthereumSignTx *msg) {
    if (memcmp(msg->data_initial_chunk.bytes, "\xf3\x05\xd7\x19", 4) == 0)
        return true;

    return false;
}

static bool isRemoveLiquidityEthCall(const EthereumSignTx *msg) {
    if (memcmp(msg->data_initial_chunk.bytes, "\x02\x75\x1c\xec", 4) == 0)
        return true;

    return false;
}

static bool confirmFromAccountMatch(const EthereumSignTx *msg, char *addremStr) {
    
    char addressStr[43] = {'0', 'x', '\0';
    char *fromSrc;
    uint8_t *fromAddress;
    uint8_t addressBytes[20];

    HDNode *node = zx_getDerivedNode(SECP256K1_NAME, msg->address_n, msg->address_n_count, NULL);
    if (!node) return false;

    if (!hdnode_get_ethereum_pubkeyhash(node, addressBytes)) {
        memzero(node, sizeof(*node));
    }

    fromAddress = (uint8_t *)(msg->data_initial_chunk.bytes + 4 + 5*32 - 20);

    if (memcmp(fromAddress, addressBytes, 20) == 0) {
        fromSrc = "self";
    } else {
        fromSrc = "NOT this wallet";
    }

    for (uint32_t ctr=0; ctr<20; ctr++) {
        snprintf(&addressStr[2+ctr*2], 3, "%02x", fromAddress[ctr]);
    }

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, addremStr, "Confirming ETH address is %s: %s", fromSrc, addressStr)) {
       return false;
    }
    return true;
}

bool zx_isZxLiquidTx(const EthereumSignTx *msg) {
    if (memcmp(msg->to.bytes, UNISWAP_ROUTER_ADDRESS, 20) == 0) {   

        if (isAddLiquidityEthCall(msg)) return true;
    
        if (isRemoveLiquidityEthCall(msg)) return true;
    }
    return false;
}

bool zx_confirmZxLiquidTx(uint32_t data_total, const EthereumSignTx *msg) {
    (void)data_total;
    const TokenType *token;
    char constr1[40], constr2[40], *arStr = "";
    uint8_t *tokenAddress, *deadlineBytes;
    bignum256 tokenAmount, tokenMinAmount, ethMinAmount;
    uint64_t deadline;

    if (isAddLiquidityEthCall(msg)) {
        arStr = "uniswap add liquidity";
    } else if (isRemoveLiquidityEthCall(msg)) {
        arStr = "uniswap remove liquidity";
    } else {
        return false;
    }

    tokenAddress = (uint8_t *)(msg->data_initial_chunk.bytes + 4 + 32 - 20);
    token = tokenByChainAddress(msg->chain_id, tokenAddress);
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 32, 32, &tokenAmount);
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 2*32, 32, &tokenMinAmount);
    bn_from_bytes(msg->data_initial_chunk.bytes + 4 + 3*32, 32, &ethMinAmount);
    deadlineBytes = (uint8_t *)(msg->data_initial_chunk.bytes + 4 + 6*32 - 8);
    deadline = ((uint64_t)deadlineBytes[0] << 8*7) | ((uint64_t)deadlineBytes[1] << 8*6) | ((uint64_t)deadlineBytes[2] << 8*5) | ((uint64_t)deadlineBytes[3] << 8*4) | ((uint64_t)deadlineBytes[4] << 8*3) | ((uint64_t)deadlineBytes[5] << 8*2) | ((uint64_t)deadlineBytes[6] << 8*1) | ((uint64_t)deadlineBytes[7]);






        
    char tokbuf[32];
    ethereumFormatAmount(&tokenAmount, token, msg->chain_id, tokbuf, sizeof(tokbuf));
    snprintf(constr1, 32, "%s", tokbuf);
    ethereumFormatAmount(&tokenMinAmount, token, msg->chain_id, tokbuf, sizeof(tokbuf));
    snprintf(constr2, 32, "%s", tokbuf);
    confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, arStr, "%s\nMinimum %s", constr1, constr2);
    if (!confirmFromAccountMatch(msg, arStr)) {
        return false;
    }
    
    ethereumFormatAmount(&ethMinAmount, NULL, msg->chain_id, tokbuf, sizeof(tokbuf));
    snprintf(constr1, 32, "%s", tokbuf);
    confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, arStr, "Minimum %s", constr1);

    snprintf(constr1, 32, "%lld", deadline);
    confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, arStr, "Deadline %s", ctime((const time_t *)&deadline));
    
    return true;
}
