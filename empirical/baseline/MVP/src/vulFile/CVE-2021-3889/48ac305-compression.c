









MOBI_RET mobi_decompress_lz77(unsigned char *out, const unsigned char *in, size_t *len_out, const size_t len_in) {
    MOBI_RET ret = MOBI_SUCCESS;
    MOBIBuffer *buf_in = mobi_buffer_init_null((unsigned char *) in, len_in);
    if (buf_in == NULL) {
        debug_print("%s\n", "Memory allocation failed");
        return MOBI_MALLOC_FAILED;
    }
    MOBIBuffer *buf_out = mobi_buffer_init_null(out, *len_out);
    if (buf_out == NULL) {
        mobi_buffer_free_null(buf_in);
        debug_print("%s\n", "Memory allocation failed");
        return MOBI_MALLOC_FAILED;
    }
    while (ret == MOBI_SUCCESS && buf_in->offset < buf_in->maxlen) {
        uint8_t byte = mobi_buffer_get8(buf_in);
        
        if (byte >= 0xc0) {
            mobi_buffer_add8(buf_out, ' ');
            mobi_buffer_add8(buf_out, byte ^ 0x80);
        }
        
        
        else if (byte >= 0x80) {
            uint8_t next = mobi_buffer_get8(buf_in);
            uint16_t distance = ((((byte << 8) | ((uint8_t)next)) >> 3) & 0x7ff);
            uint8_t length = (next & 0x7) + 3;
            while (length--) {
                mobi_buffer_move(buf_out, -distance, 1);
            }
        }
        
        else if (byte >= 0x09) {
            mobi_buffer_add8(buf_out, byte);
        }
        
        else if (byte >= 0x01) {
            mobi_buffer_copy(buf_out, buf_in, byte);
        }
        
        else {
            mobi_buffer_add8(buf_out, byte);
        }
        if (buf_in->error || buf_out->error) {
            ret = MOBI_BUFFER_END;
        }
    }
    *len_out = buf_out->offset;
    mobi_buffer_free_null(buf_out);
    mobi_buffer_free_null(buf_in);
    return ret;
}


static MOBI_INLINE uint64_t mobi_buffer_fill64(MOBIBuffer *buf) {
    uint64_t val = 0;
    uint8_t i = 8;
    size_t bytesleft = buf->maxlen - buf->offset;
    unsigned char *ptr = buf->data + buf->offset;
    while (i-- && bytesleft--) {
        val |= (uint64_t) *ptr++ << (i * 8);
    }
    
    buf->offset += 4;
    return val;
}


static MOBI_RET mobi_decompress_huffman_internal(MOBIBuffer *buf_out, MOBIBuffer *buf_in, const MOBIHuffCdic *huffcdic, size_t depth) {
    if (depth > MOBI_HUFFMAN_MAXDEPTH) {
        debug_print("Too many levels of recursion: %zu\n", depth);
        return MOBI_DATA_CORRUPT;
    }
    MOBI_RET ret = MOBI_SUCCESS;
    int8_t bitcount = 32;
    
    int bitsleft = (int) (buf_in->maxlen * 8);
    uint8_t code_length = 0;
    uint64_t buffer = mobi_buffer_fill64(buf_in);
    while (ret == MOBI_SUCCESS) {
        if (bitcount <= 0) {
            bitcount += 32;
            buffer = mobi_buffer_fill64(buf_in);
        }
        uint32_t code = (buffer >> bitcount) & 0xffffffffU;
        
        uint32_t t1 = huffcdic->table1[code >> 24];
        
        code_length = t1 & 0x1f;
        uint32_t maxcode = (((t1 >> 8) + 1) << (32 - code_length)) - 1;
        
        if (!(t1 & 0x80)) {
            
            while (code < huffcdic->mincode_table[code_length]) {
                code_length++;
            }
            maxcode = huffcdic->maxcode_table[code_length];
        }
        bitcount -= code_length;
        bitsleft -= code_length;
        if (bitsleft < 0) {
            break;
        }
        
        uint32_t index = (uint32_t) (maxcode - code) >> (32 - code_length);
        
        uint16_t cdic_index = (uint16_t) ((uint32_t)index >> huffcdic->code_length);
        if (index >= huffcdic->index_count) {
            debug_print("Wrong symbol offsets index: %u\n", index);
            return MOBI_DATA_CORRUPT;
        }
        
        uint32_t offset = huffcdic->symbol_offsets[index];
        uint32_t symbol_length = (uint32_t) huffcdic->symbols[cdic_index][offset] << 8 | (uint32_t) huffcdic->symbols[cdic_index][offset + 1];
        
        int is_decompressed = symbol_length >> 15;
        
        symbol_length &= 0x7fff;
        if (is_decompressed) {
            
            mobi_buffer_addraw(buf_out, (huffcdic->symbols[cdic_index] + offset + 2), symbol_length);
            ret = buf_out->error;
        } else {
            
            
            MOBIBuffer buf_sym;
            buf_sym.data = huffcdic->symbols[cdic_index] + offset + 2;
            buf_sym.offset = 0;
            buf_sym.maxlen = symbol_length;
            buf_sym.error = MOBI_SUCCESS;
            ret = mobi_decompress_huffman_internal(buf_out, &buf_sym, huffcdic, depth + 1);
        }
    }
    return ret;
}


MOBI_RET mobi_decompress_huffman(unsigned char *out, const unsigned char *in, size_t *len_out, size_t len_in, const MOBIHuffCdic *huffcdic) {
    MOBIBuffer *buf_in = mobi_buffer_init_null((unsigned char *) in, len_in);
    if (buf_in == NULL) {
        debug_print("%s\n", "Memory allocation failed");
        return MOBI_MALLOC_FAILED;
    }
    MOBIBuffer *buf_out = mobi_buffer_init_null(out, *len_out);
    if (buf_out == NULL) {
        mobi_buffer_free_null(buf_in);
        debug_print("%s\n", "Memory allocation failed");
        return MOBI_MALLOC_FAILED;
    }
    MOBI_RET ret = mobi_decompress_huffman_internal(buf_out, buf_in, huffcdic, 0);
    *len_out = buf_out->offset;
    mobi_buffer_free_null(buf_out);
    mobi_buffer_free_null(buf_in);
    return ret;
}
