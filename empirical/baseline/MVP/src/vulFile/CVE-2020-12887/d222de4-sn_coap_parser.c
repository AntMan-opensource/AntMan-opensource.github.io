






















static void     sn_coap_parser_header_parse(uint8_t **packet_data_pptr, sn_coap_hdr_s *dst_coap_msg_ptr, coap_version_e *coap_version_ptr);
static int8_t   sn_coap_parser_options_parse(struct coap_s *handle, uint8_t **packet_data_pptr, sn_coap_hdr_s *dst_coap_msg_ptr, uint8_t *packet_data_start_ptr, uint16_t packet_len);
static int8_t   sn_coap_parser_options_parse_multiple_options(struct coap_s *handle, uint8_t **packet_data_pptr, uint16_t packet_left_len,  uint8_t **dst_pptr, uint16_t *dst_len_ptr, sn_coap_option_numbers_e option, uint16_t option_number_len);
static int16_t  sn_coap_parser_options_count_needed_memory_multiple_option(uint8_t *packet_data_ptr, uint16_t packet_left_len, sn_coap_option_numbers_e option, uint16_t option_number_len);
static int8_t   sn_coap_parser_payload_parse(uint16_t packet_data_len, uint8_t *packet_data_start_ptr, uint8_t **packet_data_pptr, sn_coap_hdr_s *dst_coap_msg_ptr);

sn_coap_hdr_s *sn_coap_parser_init_message(sn_coap_hdr_s *coap_msg_ptr)
{
    
    if (coap_msg_ptr == NULL) {
        tr_error("sn_coap_parser_init_message - message null!");
        return NULL;
    }

    
    memset(coap_msg_ptr, 0x00, sizeof(sn_coap_hdr_s));

    coap_msg_ptr->content_format = COAP_CT_NONE;

    return coap_msg_ptr;
}

sn_coap_hdr_s *sn_coap_parser_alloc_message_with_options(struct coap_s *handle)
{
    
    if (handle == NULL) {
        return NULL;
    }

    sn_coap_hdr_s *coap_msg_ptr = sn_coap_parser_alloc_message(handle);

    sn_coap_options_list_s *options_list_ptr = sn_coap_parser_alloc_options(handle, coap_msg_ptr);

    if ((coap_msg_ptr == NULL) || (options_list_ptr == NULL)) {

        
        handle->sn_coap_protocol_free(coap_msg_ptr);
        handle->sn_coap_protocol_free(options_list_ptr);

        coap_msg_ptr = NULL;
    }

    return coap_msg_ptr;
}

sn_coap_hdr_s *sn_coap_parser_alloc_message(struct coap_s *handle)
{
    sn_coap_hdr_s *returned_coap_msg_ptr;

    
    if (handle == NULL) {
        return NULL;
    }

    
    returned_coap_msg_ptr = handle->sn_coap_protocol_malloc(sizeof(sn_coap_hdr_s));

    return sn_coap_parser_init_message(returned_coap_msg_ptr);
}

sn_coap_options_list_s *sn_coap_parser_alloc_options(struct coap_s *handle, sn_coap_hdr_s *coap_msg_ptr)
{
    sn_coap_options_list_s *options_list_ptr;

    
    if (handle == NULL || coap_msg_ptr == NULL) {
        return NULL;
    }

    
    if (coap_msg_ptr->options_list_ptr) {
        return coap_msg_ptr->options_list_ptr;
    }

    
    
    options_list_ptr = sn_coap_protocol_calloc(handle, sizeof(sn_coap_options_list_s));

    if (options_list_ptr == NULL) {
        tr_error("sn_coap_parser_alloc_options - failed to allocate options list!");
        return NULL;
    }

    coap_msg_ptr->options_list_ptr = options_list_ptr;

    options_list_ptr->uri_port = COAP_OPTION_URI_PORT_NONE;
    options_list_ptr->observe = COAP_OBSERVE_NONE;
    options_list_ptr->accept = COAP_CT_NONE;
    options_list_ptr->block2 = COAP_OPTION_BLOCK_NONE;
    options_list_ptr->block1 = COAP_OPTION_BLOCK_NONE;

    return options_list_ptr;
}

sn_coap_hdr_s *sn_coap_parser(struct coap_s *handle, uint16_t packet_data_len, uint8_t *packet_data_ptr, coap_version_e *coap_version_ptr)
{
    uint8_t       *data_temp_ptr                    = packet_data_ptr;
    sn_coap_hdr_s *parsed_and_returned_coap_msg_ptr = NULL;

    
    if (packet_data_ptr == NULL || packet_data_len < 4 || handle == NULL) {
        return NULL;
    }

    
    parsed_and_returned_coap_msg_ptr = sn_coap_parser_alloc_message(handle);

    if (parsed_and_returned_coap_msg_ptr == NULL) {
        tr_error("sn_coap_parser - failed to allocate message!");
        return NULL;
    }

    
    sn_coap_parser_header_parse(&data_temp_ptr, parsed_and_returned_coap_msg_ptr, coap_version_ptr);
    
    if (sn_coap_parser_options_parse(handle, &data_temp_ptr, parsed_and_returned_coap_msg_ptr, packet_data_ptr, packet_data_len) != 0) {
        parsed_and_returned_coap_msg_ptr->coap_status = COAP_STATUS_PARSER_ERROR_IN_HEADER;
        return parsed_and_returned_coap_msg_ptr;
    }

    
    if (sn_coap_parser_payload_parse(packet_data_len, packet_data_ptr, &data_temp_ptr, parsed_and_returned_coap_msg_ptr) == -1) {
        parsed_and_returned_coap_msg_ptr->coap_status = COAP_STATUS_PARSER_ERROR_IN_HEADER;
        return parsed_and_returned_coap_msg_ptr;
    }

    parsed_and_returned_coap_msg_ptr->coap_status = COAP_STATUS_OK;

    
    return parsed_and_returned_coap_msg_ptr;
}

void sn_coap_parser_release_allocated_coap_msg_mem(struct coap_s *handle, sn_coap_hdr_s *freed_coap_msg_ptr)
{
    if (handle == NULL) {
        return;
    }

    if (freed_coap_msg_ptr != NULL) {

        
        
        void (*local_free)(void *) = handle->sn_coap_protocol_free;

        local_free(freed_coap_msg_ptr->uri_path_ptr);
        local_free(freed_coap_msg_ptr->token_ptr);

        
        sn_coap_options_list_s *options_list_ptr = freed_coap_msg_ptr->options_list_ptr;

        if (options_list_ptr != NULL) {

            local_free(options_list_ptr->proxy_uri_ptr);

            local_free(options_list_ptr->etag_ptr);

            local_free(options_list_ptr->uri_host_ptr);

            local_free(options_list_ptr->location_path_ptr);

            local_free(options_list_ptr->location_query_ptr);

            local_free(options_list_ptr->uri_query_ptr);

            local_free(options_list_ptr);
        }

        local_free(freed_coap_msg_ptr);
    }
}


static void sn_coap_parser_header_parse(uint8_t **packet_data_pptr, sn_coap_hdr_s *dst_coap_msg_ptr, coap_version_e *coap_version_ptr)
{
    
    *coap_version_ptr = (coap_version_e)(**packet_data_pptr & COAP_HEADER_VERSION_MASK);
    dst_coap_msg_ptr->msg_type = (sn_coap_msg_type_e)(**packet_data_pptr & COAP_HEADER_MSG_TYPE_MASK);
    (*packet_data_pptr) += 1;

    
    dst_coap_msg_ptr->msg_code = (sn_coap_msg_code_e) **packet_data_pptr;
    (*packet_data_pptr) += 1;

    
    dst_coap_msg_ptr->msg_id = *(*packet_data_pptr + 1);
    dst_coap_msg_ptr->msg_id += **packet_data_pptr << COAP_HEADER_MSG_ID_MSB_SHIFT;
    (*packet_data_pptr) += 2;

}


static uint32_t sn_coap_parser_options_parse_uint(uint8_t **packet_data_pptr, uint8_t option_len)
{
    uint32_t value = 0;
    while (option_len--) {
        value <<= 8;
        value |= *(*packet_data_pptr)++;
    }
    return value;
}



static int8_t sn_coap_parser_check_packet_ptr(uint8_t *packet_data_ptr, uint8_t *packet_data_start_ptr, uint16_t packet_len, uint16_t delta)
{
    uint8_t *packet_end = packet_data_start_ptr + packet_len;
    uint8_t *new_data_ptr = packet_data_ptr + delta;

    if (delta > packet_len) {
        return -1;
    }

    if (new_data_ptr < packet_data_start_ptr || new_data_ptr > packet_end) {
        return -1;
    }

    return 0;
}


static uint16_t sn_coap_parser_move_packet_ptr(uint8_t **packet_data_pptr, uint8_t *packet_data_start_ptr, uint16_t packet_len, uint16_t delta)
{
    uint8_t *packet_end = packet_data_start_ptr + packet_len;
    uint8_t *new_data_ptr = *packet_data_pptr + delta;

    if (new_data_ptr < packet_data_start_ptr){
        return 0;
    } else if (new_data_ptr >= packet_end) {
        *packet_data_pptr = packet_end;
        return 0;
    }

    *packet_data_pptr = new_data_ptr;

    return (uint16_t)(packet_end - new_data_ptr);
}


static int8_t sn_coap_parser_read_packet_u8(uint8_t *dst, uint8_t *packet_data_ptr, uint8_t *packet_data_start_ptr, uint16_t packet_len)
{
    int8_t ptr_check_result;

    ptr_check_result = sn_coap_parser_check_packet_ptr(packet_data_ptr, packet_data_start_ptr, packet_len, 1);

    if (ptr_check_result != 0) {
        return ptr_check_result;
    }

    *dst = *packet_data_ptr;

    return 0;
}


static int8_t sn_coap_parser_read_packet_u16(uint16_t *dst, uint8_t *packet_data_ptr, uint8_t *packet_data_start_ptr, uint16_t packet_len)
{
    int8_t ptr_check_result;
    uint16_t value;

    ptr_check_result = sn_coap_parser_check_packet_ptr(packet_data_ptr, packet_data_start_ptr, packet_len, 2);

    if (ptr_check_result != 0) {
        return ptr_check_result;
    }

    value = *(packet_data_ptr) << 8;
    value |= *(packet_data_ptr + 1);
    *dst = value;

    return 0;
}


static int8_t parse_ext_option(uint16_t *dst, uint8_t **packet_data_pptr, uint8_t *packet_data_start_ptr, uint16_t packet_len, uint16_t *message_left)
{
    uint16_t option_number = *dst;

    if (option_number == 13) {
        uint8_t option_ext;
        int8_t read_result = sn_coap_parser_read_packet_u8(&option_ext, *packet_data_pptr, packet_data_start_ptr, packet_len);


        if (read_result != 0) {
            
            tr_error("sn_coap_parser_options_parse - **packet_data_pptr overflow !");
            return -1;
        }
        else {
                option_number += option_ext;
                *message_left = sn_coap_parser_move_packet_ptr(packet_data_pptr, packet_data_start_ptr, packet_len, 1);


        }
    } else if (option_number == 14) {
            int8_t read_result = sn_coap_parser_read_packet_u16(&option_number, *packet_data_pptr, packet_data_start_ptr, packet_len);


            if (read_result != 0) {
                
                tr_error("sn_coap_parser_options_parse - **packet_data_pptr overflow !");
                return -1;
            }
            else {
            option_number += 269;
            *message_left = sn_coap_parser_move_packet_ptr(packet_data_pptr, packet_data_start_ptr, packet_len, 2);


            }
    }
    
    else if (option_number == 15) {
        tr_error("sn_coap_parser_options_parse - invalid option number(15)!");
        return -1;
    }

    *dst = option_number;
    return 0;
}


static int8_t sn_coap_parser_options_parse(struct coap_s *handle, uint8_t **packet_data_pptr, sn_coap_hdr_s *dst_coap_msg_ptr, uint8_t *packet_data_start_ptr, uint16_t packet_len)
{
    uint8_t previous_option_number = 0;
    int8_t  ret_status             = 0;
    uint16_t message_left          = sn_coap_parser_move_packet_ptr(packet_data_pptr, packet_data_start_ptr, packet_len, 0);



    
    dst_coap_msg_ptr->token_len = *packet_data_start_ptr & COAP_HEADER_TOKEN_LENGTH_MASK;

    if (dst_coap_msg_ptr->token_len) {
        int8_t ptr_check_result;
        if ((dst_coap_msg_ptr->token_len > 8) || dst_coap_msg_ptr->token_ptr) {
            tr_error("sn_coap_parser_options_parse - token not valid!");
            return -1;
        }

        ptr_check_result = sn_coap_parser_check_packet_ptr(*packet_data_pptr, packet_data_start_ptr, packet_len, dst_coap_msg_ptr->token_len);
        if (0 != ptr_check_result) {
            tr_error("sn_coap_parser_options_parse - **packet_data_pptr overflow !");
            return -1;
        }

        dst_coap_msg_ptr->token_ptr = sn_coap_protocol_malloc_copy(handle, *packet_data_pptr, dst_coap_msg_ptr->token_len);

        if (dst_coap_msg_ptr->token_ptr == NULL) {
            tr_error("sn_coap_parser_options_parse - failed to allocate token!");
            return -1;
        }

        message_left = sn_coap_parser_move_packet_ptr(packet_data_pptr, packet_data_start_ptr, packet_len, dst_coap_msg_ptr->token_len);


    }

    
    while (message_left && (**packet_data_pptr != 0xff)) {
        
        uint16_t option_len = (**packet_data_pptr & 0x0F);
        
        uint16_t  option_number = (**packet_data_pptr >> COAP_OPTIONS_OPTION_NUMBER_SHIFT);

        message_left = sn_coap_parser_move_packet_ptr(packet_data_pptr, packet_data_start_ptr, packet_len, 1);

        int8_t    option_parse_result;
        
        option_parse_result = parse_ext_option(&option_number, packet_data_pptr, packet_data_start_ptr, packet_len, &message_left);



        if (option_parse_result != 0) {
            return -1;
        }
        
        option_number += previous_option_number;

        
        option_parse_result = parse_ext_option(&option_len, packet_data_pptr, packet_data_start_ptr, packet_len, &message_left);



        if (option_parse_result != 0) {
            return -1;
        }

        
        
        previous_option_number = option_number;
        
        switch (option_number) {
            case COAP_OPTION_MAX_AGE:
            case COAP_OPTION_PROXY_URI:
            case COAP_OPTION_ETAG:
            case COAP_OPTION_URI_HOST:
            case COAP_OPTION_LOCATION_PATH:
            case COAP_OPTION_URI_PORT:
            case COAP_OPTION_LOCATION_QUERY:
            case COAP_OPTION_OBSERVE:
            case COAP_OPTION_URI_QUERY:
            case COAP_OPTION_BLOCK2:
            case COAP_OPTION_BLOCK1:
            case COAP_OPTION_ACCEPT:
            case COAP_OPTION_SIZE1:
            case COAP_OPTION_SIZE2:
                if (sn_coap_parser_alloc_options(handle, dst_coap_msg_ptr) == NULL) {
                    tr_error("sn_coap_parser_options_parse - failed to allocate options!");
                    return -1;
                }
                break;
        }

        if (message_left < option_len){
            
            tr_error("sn_coap_parser_options_parse - **packet_data_pptr would overflow when parsing options!");
            return -1;
        }

        
        switch (option_number) {
            case COAP_OPTION_CONTENT_FORMAT:
                if ((option_len > 2) || (dst_coap_msg_ptr->content_format != COAP_CT_NONE)) {
                    tr_error("sn_coap_parser_options_parse - COAP_OPTION_CONTENT_FORMAT not valid!");
                    return -1;
                }
                dst_coap_msg_ptr->content_format = (sn_coap_content_format_e) sn_coap_parser_options_parse_uint(packet_data_pptr, option_len);
                break;

            case COAP_OPTION_MAX_AGE:
                if (option_len > 4) {
                    tr_error("sn_coap_parser_options_parse - COAP_OPTION_MAX_AGE not valid!");
                    return -1;
                }
                dst_coap_msg_ptr->options_list_ptr->max_age = sn_coap_parser_options_parse_uint(packet_data_pptr, option_len);
                break;

            case COAP_OPTION_PROXY_URI:
                if ((option_len > 1034) || (option_len < 1) || dst_coap_msg_ptr->options_list_ptr->proxy_uri_ptr) {
                    tr_error("sn_coap_parser_options_parse - COAP_OPTION_PROXY_URI not valid!");
                    return -1;
                }
                dst_coap_msg_ptr->options_list_ptr->proxy_uri_len = option_len;
                dst_coap_msg_ptr->options_list_ptr->proxy_uri_ptr = sn_coap_protocol_malloc_copy(handle, *packet_data_pptr, option_len);

                if (dst_coap_msg_ptr->options_list_ptr->proxy_uri_ptr == NULL) {
                    tr_error("sn_coap_parser_options_parse - COAP_OPTION_PROXY_URI allocation failed!");
                    return -1;
                }
                message_left = sn_coap_parser_move_packet_ptr(packet_data_pptr, packet_data_start_ptr, packet_len, option_len);
                break;

            case COAP_OPTION_ETAG:
                
                ret_status = sn_coap_parser_options_parse_multiple_options(handle, packet_data_pptr, message_left, &dst_coap_msg_ptr->options_list_ptr->etag_ptr, (uint16_t *)&dst_coap_msg_ptr->options_list_ptr->etag_len, COAP_OPTION_ETAG, option_len);



                if (ret_status < 0) {
                    tr_error("sn_coap_parser_options_parse - COAP_OPTION_ETAG not valid!");
                    return -1;
                }
                break;

            case COAP_OPTION_URI_HOST:
                if ((option_len > 255) || (option_len < 1) || dst_coap_msg_ptr->options_list_ptr->uri_host_ptr) {
                    tr_error("sn_coap_parser_options_parse - COAP_OPTION_URI_HOST not valid!");
                    return -1;
                }
                dst_coap_msg_ptr->options_list_ptr->uri_host_len = option_len;
                dst_coap_msg_ptr->options_list_ptr->uri_host_ptr = sn_coap_protocol_malloc_copy(handle, *packet_data_pptr, option_len);

                if (dst_coap_msg_ptr->options_list_ptr->uri_host_ptr == NULL) {
                    tr_error("sn_coap_parser_options_parse - COAP_OPTION_URI_HOST allocation failed!");
                    return -1;
                }
                message_left = sn_coap_parser_move_packet_ptr(packet_data_pptr, packet_data_start_ptr, packet_len, option_len);
                break;

            case COAP_OPTION_LOCATION_PATH:
                if (dst_coap_msg_ptr->options_list_ptr->location_path_ptr) {
                    tr_error("sn_coap_parser_options_parse - COAP_OPTION_LOCATION_PATH exists!");
                    return -1;
                }
                
                ret_status = sn_coap_parser_options_parse_multiple_options(handle, packet_data_pptr, message_left, &dst_coap_msg_ptr->options_list_ptr->location_path_ptr, &dst_coap_msg_ptr->options_list_ptr->location_path_len, COAP_OPTION_LOCATION_PATH, option_len);

                if (ret_status <0) {
                    tr_error("sn_coap_parser_options_parse - COAP_OPTION_LOCATION_PATH not valid!");
                    return -1;
                }
                break;

            case COAP_OPTION_URI_PORT:
                if ((option_len > 2) || dst_coap_msg_ptr->options_list_ptr->uri_port != COAP_OPTION_URI_PORT_NONE) {
                    tr_error("sn_coap_parser_options_parse - COAP_OPTION_URI_PORT not valid!");
                    return -1;
                }
                dst_coap_msg_ptr->options_list_ptr->uri_port = sn_coap_parser_options_parse_uint(packet_data_pptr, option_len);
                break;

            case COAP_OPTION_LOCATION_QUERY:
                ret_status = sn_coap_parser_options_parse_multiple_options(handle, packet_data_pptr, message_left, &dst_coap_msg_ptr->options_list_ptr->location_query_ptr, &dst_coap_msg_ptr->options_list_ptr->location_query_len, COAP_OPTION_LOCATION_QUERY, option_len);

                if (ret_status < 0) {
                    tr_error("sn_coap_parser_options_parse - COAP_OPTION_LOCATION_QUERY not valid!");
                    return -1;
                }

                break;

            case COAP_OPTION_URI_PATH:
                ret_status = sn_coap_parser_options_parse_multiple_options(handle, packet_data_pptr, message_left, &dst_coap_msg_ptr->uri_path_ptr, &dst_coap_msg_ptr->uri_path_len, COAP_OPTION_URI_PATH, option_len);

                if (ret_status < 0) {
                    tr_error("sn_coap_parser_options_parse - COAP_OPTION_URI_PATH not valid!");
                    return -1;
                }
                break;

            case COAP_OPTION_OBSERVE:
                if ((option_len > 2) || dst_coap_msg_ptr->options_list_ptr->observe != COAP_OBSERVE_NONE) {
                    tr_error("sn_coap_parser_options_parse - COAP_OPTION_OBSERVE not valid!");
                    return -1;
                }
                dst_coap_msg_ptr->options_list_ptr->observe = sn_coap_parser_options_parse_uint(packet_data_pptr, option_len);
                break;

            case COAP_OPTION_URI_QUERY:
                ret_status = sn_coap_parser_options_parse_multiple_options(handle, packet_data_pptr, message_left, &dst_coap_msg_ptr->options_list_ptr->uri_query_ptr, &dst_coap_msg_ptr->options_list_ptr->uri_query_len, COAP_OPTION_URI_QUERY, option_len);

                if (ret_status < 0) {
                    tr_error("sn_coap_parser_options_parse - COAP_OPTION_URI_QUERY not valid!");
                    return -1;
                }
                break;

            case COAP_OPTION_BLOCK2:
                if ((option_len > 3) || dst_coap_msg_ptr->options_list_ptr->block2 != COAP_OPTION_BLOCK_NONE) {
                    tr_error("sn_coap_parser_options_parse - COAP_OPTION_BLOCK2 not valid!");
                    return -1;
                }
                dst_coap_msg_ptr->options_list_ptr->block2 = sn_coap_parser_options_parse_uint(packet_data_pptr, option_len);
                break;

            case COAP_OPTION_BLOCK1:
                if ((option_len > 3) || dst_coap_msg_ptr->options_list_ptr->block1 != COAP_OPTION_BLOCK_NONE) {
                    tr_error("sn_coap_parser_options_parse - COAP_OPTION_BLOCK1 not valid!");
                    return -1;
                }
                dst_coap_msg_ptr->options_list_ptr->block1 = sn_coap_parser_options_parse_uint(packet_data_pptr, option_len);
                break;

            case COAP_OPTION_ACCEPT:
                if ((option_len > 2) || (dst_coap_msg_ptr->options_list_ptr->accept != COAP_CT_NONE)) {
                    tr_error("sn_coap_parser_options_parse - COAP_OPTION_ACCEPT not valid!");
                    return -1;
                }
                dst_coap_msg_ptr->options_list_ptr->accept = (sn_coap_content_format_e) sn_coap_parser_options_parse_uint(packet_data_pptr, option_len);
                break;

            case COAP_OPTION_SIZE1:
                if ((option_len > 4) || dst_coap_msg_ptr->options_list_ptr->use_size1) {
                    tr_error("sn_coap_parser_options_parse - COAP_OPTION_SIZE1 not valid!");
                    return -1;
                }
                dst_coap_msg_ptr->options_list_ptr->use_size1 = true;
                dst_coap_msg_ptr->options_list_ptr->size1 = sn_coap_parser_options_parse_uint(packet_data_pptr, option_len);
                break;

            case COAP_OPTION_SIZE2:
                if ((option_len > 4) || dst_coap_msg_ptr->options_list_ptr->use_size2) {
                    tr_error("sn_coap_parser_options_parse - COAP_OPTION_SIZE2 not valid!");
                    return -1;
                }
                dst_coap_msg_ptr->options_list_ptr->use_size2 = true;
                dst_coap_msg_ptr->options_list_ptr->size2 = sn_coap_parser_options_parse_uint(packet_data_pptr, option_len);
                break;

            default:
                tr_error("sn_coap_parser_options_parse - unknown option!");
                return -1;
        }

        
        if ((*packet_data_pptr - packet_data_start_ptr) > packet_len) {
            return -1;
        }
        message_left = sn_coap_parser_move_packet_ptr(packet_data_pptr, packet_data_start_ptr, packet_len, 0);


    }
    return 0;
}



static int8_t sn_coap_parser_options_parse_multiple_options(struct coap_s *handle, uint8_t **packet_data_pptr, uint16_t packet_left_len,  uint8_t **dst_pptr, uint16_t *dst_len_ptr, sn_coap_option_numbers_e option, uint16_t option_number_len)
{
    int16_t     uri_query_needed_heap       = sn_coap_parser_options_count_needed_memory_multiple_option(*packet_data_pptr, packet_left_len, option, option_number_len);
    uint8_t    *temp_parsed_uri_query_ptr   = NULL;
    uint8_t     returned_option_counter     = 0;
    uint8_t    *start_ptr = *packet_data_pptr;
    uint16_t    message_left = packet_left_len;

    if (uri_query_needed_heap == -1) {
        return -1;
    }

    if (uri_query_needed_heap) {
        *dst_pptr = (uint8_t *) handle->sn_coap_protocol_malloc(uri_query_needed_heap);

        if (*dst_pptr == NULL) {
            tr_error("sn_coap_parser_options_parse_multiple_options - failed to allocate options!");
            return -1;
        }
    }

    *dst_len_ptr = uri_query_needed_heap;
    temp_parsed_uri_query_ptr = *dst_pptr;

    
    while ((temp_parsed_uri_query_ptr - *dst_pptr) < uri_query_needed_heap && message_left) {
        
        if (returned_option_counter > 0) {
            
            
            if (option == COAP_OPTION_URI_QUERY || option == COAP_OPTION_LOCATION_QUERY || option == COAP_OPTION_ETAG || option == COAP_OPTION_ACCEPT) {
                *temp_parsed_uri_query_ptr = '&';
            } else if (option == COAP_OPTION_URI_PATH || option == COAP_OPTION_LOCATION_PATH) {
                *temp_parsed_uri_query_ptr = '/';
            }

            temp_parsed_uri_query_ptr++;
        }

        returned_option_counter++;

        if (((temp_parsed_uri_query_ptr - *dst_pptr) + option_number_len) > uri_query_needed_heap) {
            return -1;
        }

        if (0 != sn_coap_parser_check_packet_ptr(*packet_data_pptr, start_ptr, packet_left_len, option_number_len))
        {
            
            return -1;
        }

        
        memcpy(temp_parsed_uri_query_ptr, *packet_data_pptr, option_number_len);

        message_left = sn_coap_parser_move_packet_ptr(packet_data_pptr, start_ptr, packet_left_len, option_number_len);


        temp_parsed_uri_query_ptr += option_number_len;

        
        if ( message_left == 0 || ((**packet_data_pptr >> COAP_OPTIONS_OPTION_NUMBER_SHIFT) != 0)) {
            return returned_option_counter;
        }

        
        option_number_len = (**packet_data_pptr & 0x0F);
        message_left = sn_coap_parser_move_packet_ptr(packet_data_pptr,  start_ptr, packet_left_len, 1);



        
        int8_t option_parse_result = parse_ext_option(&option_number_len, packet_data_pptr, start_ptr, packet_left_len, &message_left);



        if (option_parse_result != 0)
        {
            
            return -1;
        }
    }

    return returned_option_counter;
}


static int16_t sn_coap_parser_options_count_needed_memory_multiple_option(uint8_t *packet_data_ptr, uint16_t packet_left_len, sn_coap_option_numbers_e option, uint16_t option_number_len)
{
    uint16_t ret_value              = 0;
    uint16_t message_left           = packet_left_len;
    uint8_t *start_ptr              = packet_data_ptr;

    
    while (message_left > 0) {
        if (option == COAP_OPTION_LOCATION_PATH && option_number_len > 255) {
            return -1;
        }
        if (option == COAP_OPTION_URI_PATH && option_number_len > 255) {
            return -1;
        }
        if (option == COAP_OPTION_URI_QUERY && option_number_len > 255) {
            return -1;
        }
        if (option == COAP_OPTION_LOCATION_QUERY && option_number_len > 255) {
            return -1;
        }
        if (option == COAP_OPTION_ACCEPT && option_number_len > 2) {
            return -1;
        }
        if (option == COAP_OPTION_ETAG && option_number_len > 8) {
            return -1;
        }

        
        int8_t ptr_check_result = sn_coap_parser_check_packet_ptr(packet_data_ptr, start_ptr, packet_left_len, option_number_len);


        if (ptr_check_result != 0) {
            return -1;
        }

        ret_value += option_number_len + 1; 

        
        message_left = sn_coap_parser_move_packet_ptr(&packet_data_ptr, start_ptr, packet_left_len, option_number_len);


        if(message_left == 0) {
            break;
        }

        
        if (((*packet_data_ptr) >> COAP_OPTIONS_OPTION_NUMBER_SHIFT) != 0) {
            break;
        }

        
        option_number_len = (*packet_data_ptr & 0x0F);

        
        message_left = sn_coap_parser_move_packet_ptr(&packet_data_ptr, start_ptr, packet_left_len, 1);



        
        int8_t option_parse_result = parse_ext_option(&option_number_len, &packet_data_ptr, start_ptr, packet_left_len, &message_left);



        if (option_parse_result != 0) {
            return -1;
        }
    }

    if (ret_value != 0) {
        return (ret_value - 1);    
    } else {
        return 0;
    }
}


static int8_t sn_coap_parser_payload_parse(uint16_t packet_data_len, uint8_t *packet_data_start_ptr, uint8_t **packet_data_pptr, sn_coap_hdr_s *dst_coap_msg_ptr)
{
    
    if ((*packet_data_pptr - packet_data_start_ptr) < packet_data_len) {
        if (**packet_data_pptr == 0xff) {
            (*packet_data_pptr)++;
            
            dst_coap_msg_ptr->payload_len = packet_data_len - (*packet_data_pptr - packet_data_start_ptr);

            
            if (dst_coap_msg_ptr->payload_len == 0) {
                return -1;
            }

            
            dst_coap_msg_ptr->payload_ptr = *packet_data_pptr;
        }
        
        else {
            tr_error("sn_coap_parser_payload_parse - payload marker not found!");
            return -1;
        }
    }
    return 0;
}

