























static void generate_form_error(Dwarf_Debug dbg, Dwarf_Error *error, unsigned form, int err_code, const char *errname, const char *funcname)





{
    dwarfstring m;
    char mbuf[DWARFSTRING_ALLOC_SIZE];
    const char * defaultname = "<unknown form>";

    dwarfstring_constructor_static(&m,mbuf, sizeof(mbuf));
    dwarfstring_append(&m,(char *)errname);
    dwarfstring_append(&m,": In function ");
    dwarfstring_append(&m,(char *)funcname);
    dwarfstring_append_printf_u(&m, " on seeing form  0x%x ",form);
    dwarf_get_FORM_name(form,&defaultname);
    dwarfstring_append_printf_s(&m, " (%s)",(char *)defaultname);
    _dwarf_error_string(dbg,error,err_code, dwarfstring_string(&m));
    dwarfstring_destructor(&m);
}


static int get_attr_dbg(Dwarf_Debug *dbg_out, Dwarf_CU_Context * cu_context_out, Dwarf_Attribute attr, Dwarf_Error *error)



{
    Dwarf_CU_Context cup = 0;
    Dwarf_Debug dbg = 0;

    if (!attr) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NULL);
        return DW_DLV_ERROR;
    }
    cup = attr->ar_cu_context;
    if (!cup) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NO_CU_CONTEXT);
        return DW_DLV_ERROR;
    }
    dbg = cup->cc_dbg;
    if (!dbg  || dbg->de_magic != DBG_IS_VALID) {
        _dwarf_error_string(NULL, error, DW_DLE_ATTR_DBG_NULL, "DW_DLE_ATTR_DBG_NULL: Stale or null Dwarf_Debug" "in a Dwarf_CU_Context" );

        return DW_DLV_ERROR;
    }
    if (dbg != attr->ar_dbg) {
        _dwarf_error_string(NULL, error, DW_DLE_ATTR_DBG_NULL, "DW_DLE_ATTR_DBG_NULL: an attribute and its " "cu_context do not have the same Dwarf_Debug" );

        return DW_DLV_ERROR;
    }
    *cu_context_out = cup;
    *dbg_out        = dbg;
    return DW_DLV_OK;

}

int dwarf_hasform(Dwarf_Attribute attr, Dwarf_Half form, Dwarf_Bool * return_bool, Dwarf_Error * error)


{
    Dwarf_Debug dbg = 0;
    Dwarf_CU_Context cu_context = 0;

    int res  =get_attr_dbg(&dbg,&cu_context, attr,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    *return_bool = (attr->ar_attribute_form == form);
    return DW_DLV_OK;
}


int dwarf_whatform_direct(Dwarf_Attribute attr, Dwarf_Half * return_form, Dwarf_Error * error)

{
    int res = dwarf_whatform(attr, return_form, error);

    if (res != DW_DLV_OK) {
        return res;
    }

    *return_form = attr->ar_attribute_form_direct;
    return DW_DLV_OK;
}


int dwarf_uncompress_integer_block_a(Dwarf_Debug dbg, Dwarf_Unsigned     input_length_in_bytes, void             * input_block, Dwarf_Unsigned   * value_count, Dwarf_Signed    ** value_array, Dwarf_Error      * error)





{
    Dwarf_Unsigned output_length_in_units = 0;
    Dwarf_Signed * output_block = 0;
    unsigned i = 0;
    char * ptr = 0;
    int remain = 0;
    Dwarf_Signed * array = 0;
    Dwarf_Byte_Ptr endptr = (Dwarf_Byte_Ptr)input_block+ input_length_in_bytes;

    output_length_in_units = 0;
    remain = input_length_in_bytes;
    ptr = input_block;
    while (remain > 0) {
        Dwarf_Unsigned len = 0;
        Dwarf_Signed value = 0;
        int rres = 0;

        rres = dwarf_decode_signed_leb128((char *)ptr, &len, &value,(char *)endptr);
        if (rres != DW_DLV_OK) {
            _dwarf_error(NULL, error, DW_DLE_LEB_IMPROPER);
            return DW_DLV_ERROR;
        }
        ptr += len;
        remain -= len;
        output_length_in_units++;
    }
    if (remain != 0) {
        _dwarf_error(NULL, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    output_block = (Dwarf_Signed*)
        _dwarf_get_alloc(dbg, DW_DLA_STRING, output_length_in_units * sizeof(Dwarf_Signed));

    if (!output_block) {
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    array = output_block;
    remain = input_length_in_bytes;
    ptr = input_block;
    for (i=0; i<output_length_in_units && remain>0; i++) {
        Dwarf_Signed num;
        Dwarf_Unsigned len;
        int sres = 0;

        sres = dwarf_decode_signed_leb128((char *)ptr, &len, &num,(char *)endptr);
        if (sres != DW_DLV_OK) {
            dwarf_dealloc(dbg,output_block,DW_DLA_STRING);
            _dwarf_error(NULL, error, DW_DLE_LEB_IMPROPER);
            return DW_DLV_ERROR;
        }
        ptr += len;
        remain -= len;
        array[i] = num;
    }

    if (remain != 0) {
        dwarf_dealloc(dbg, (unsigned char *)output_block, DW_DLA_STRING);
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    *value_count = output_length_in_units;
    *value_array = output_block;
    return DW_DLV_OK;
}



void dwarf_dealloc_uncompressed_block(Dwarf_Debug dbg, void * space)
{
    dwarf_dealloc(dbg, space, DW_DLA_STRING);
}


int dwarf_whatform(Dwarf_Attribute attr, Dwarf_Half * return_form, Dwarf_Error * error)

{
    Dwarf_CU_Context cu_context = 0;
    Dwarf_Debug dbg = 0;

    int res  =get_attr_dbg(&dbg,&cu_context, attr,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    *return_form = attr->ar_attribute_form;
    return DW_DLV_OK;
}


int dwarf_whatattr(Dwarf_Attribute attr, Dwarf_Half * return_attr, Dwarf_Error * error)

{
    Dwarf_CU_Context cu_context = 0;
    Dwarf_Debug dbg = 0;

    int res  =get_attr_dbg(&dbg,&cu_context, attr,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    *return_attr = (attr->ar_attribute);
    return DW_DLV_OK;
}


int dwarf_convert_to_global_offset(Dwarf_Attribute attr, Dwarf_Off offset, Dwarf_Off * ret_offset, Dwarf_Error * error)



{
    Dwarf_Debug dbg = 0;
    Dwarf_CU_Context cu_context = 0;
    int res = 0;

    res  = get_attr_dbg(&dbg,&cu_context,attr,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    switch (attr->ar_attribute_form) {
    case DW_FORM_ref1:
    case DW_FORM_ref2:
    case DW_FORM_ref4:
    case DW_FORM_ref8:
    case DW_FORM_ref_udata:
        
        
        
        offset += cu_context->cc_debug_offset;

        break;

    case DW_FORM_ref_addr:
        
        break;
    default: {
        dwarfstring m;

        dwarfstring_constructor(&m);
        dwarfstring_append_printf_u(&m, "DW_DLE_BAD_REF_FORM. The form " "code is 0x%x which cannot be converted to a global " " offset by " "dwarf_convert_to_global_offset()", attr->ar_attribute_form);




        _dwarf_error_string(dbg, error, DW_DLE_BAD_REF_FORM, dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        return DW_DLV_ERROR;
        }
    }

    *ret_offset = (offset);
    return DW_DLV_OK;
}



int dwarf_formref(Dwarf_Attribute attr, Dwarf_Off * ret_offset, Dwarf_Bool * ret_is_info, Dwarf_Error * error)



{
    Dwarf_Debug dbg = 0;
    Dwarf_Unsigned offset = 0;
    Dwarf_CU_Context cu_context = 0;
    Dwarf_Unsigned maximumoffset = 0;
    int res = DW_DLV_ERROR;
    Dwarf_Byte_Ptr section_end = 0;
    Dwarf_Bool is_info = TRUE;

    *ret_offset = 0;
    res  = get_attr_dbg(&dbg,&cu_context,attr,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    section_end = _dwarf_calculate_info_section_end_ptr(cu_context);
    is_info = cu_context->cc_is_info;

    switch (attr->ar_attribute_form) {

    case DW_FORM_ref1:
        offset = *(Dwarf_Small *) attr->ar_debug_ptr;
        break;

    case DW_FORM_ref2:
        READ_UNALIGNED_CK(dbg, offset, Dwarf_Unsigned, attr->ar_debug_ptr, DWARF_HALF_SIZE, error,section_end);

        break;

    case DW_FORM_ref4:
        READ_UNALIGNED_CK(dbg, offset, Dwarf_Unsigned, attr->ar_debug_ptr, DWARF_32BIT_SIZE, error,section_end);

        break;

    case DW_FORM_ref8:
        READ_UNALIGNED_CK(dbg, offset, Dwarf_Unsigned, attr->ar_debug_ptr, DWARF_64BIT_SIZE, error,section_end);

        break;

    case DW_FORM_ref_udata: {
        Dwarf_Byte_Ptr ptr = attr->ar_debug_ptr;
        Dwarf_Unsigned localoffset = 0;

        DECODE_LEB128_UWORD_CK(ptr,localoffset, dbg,error,section_end);
        offset = localoffset;
        break;
    }
    case DW_FORM_ref_sig8: {
        

        Dwarf_Sig8 sig8;
        memcpy(&sig8,ptr,sizeof(Dwarf_Sig8));
        res = dwarf_find_die_given_sig8(dbg, &sig8, ... We could look, then determine if resulting offset is actually local.    _dwarf_error(dbg, error, DW_DLE_REF_SIG8_NOT_HANDLED);






        return DW_DLV_ERROR;
    }
    default: {
        dwarfstring m;

        dwarfstring_constructor(&m);
        dwarfstring_append_printf_u(&m, "DW_DLE_BAD_REF_FORM. The form " "code is 0x%x which does not have an offset " " for " "dwarf_formref() to return.", attr->ar_attribute_form);




        _dwarf_error_string(dbg, error, DW_DLE_BAD_REF_FORM, dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        return DW_DLV_ERROR;
        }
    }

    

    maximumoffset = cu_context->cc_length + cu_context->cc_length_size + cu_context->cc_extension_size;

    if (offset >= maximumoffset) {
        
        Dwarf_Half tag = 0;
        int tres = dwarf_tag(attr->ar_die,&tag,error);
        if (tres != DW_DLV_OK) {
            if (tres == DW_DLV_NO_ENTRY) {
                _dwarf_error(dbg, error, DW_DLE_NO_TAG_FOR_DIE);
                return DW_DLV_ERROR;
            }
            return DW_DLV_ERROR;
        }

        if (DW_TAG_compile_unit != tag && DW_AT_sibling != attr->ar_attribute && offset > maximumoffset) {

            _dwarf_error(dbg, error, DW_DLE_ATTR_FORM_OFFSET_BAD);
            
            *ret_offset = (offset);
            return DW_DLV_ERROR;
        }
    }
    *ret_is_info = is_info;
    *ret_offset = (offset);
    return DW_DLV_OK;
}

static int _dwarf_formsig8_internal(Dwarf_Attribute attr, int formexpected, Dwarf_Sig8 * returned_sig_bytes, Dwarf_Error*     error)



{
    Dwarf_Debug dbg = 0;
    Dwarf_CU_Context cu_context = 0;
    Dwarf_Byte_Ptr  field_end = 0;
    Dwarf_Byte_Ptr  section_end = 0;

    int res  = get_attr_dbg(&dbg,&cu_context,attr,error);
    if (res != DW_DLV_OK) {
        return res;
    }

    if (attr->ar_attribute_form != formexpected) {
        return DW_DLV_NO_ENTRY;
    }
    section_end = _dwarf_calculate_info_section_end_ptr(cu_context);
    field_end = attr->ar_debug_ptr + sizeof(Dwarf_Sig8);
    if (field_end > section_end) {
        _dwarf_error(dbg, error, DW_DLE_ATTR_FORM_OFFSET_BAD);
        return DW_DLV_ERROR;
    }

    memcpy(returned_sig_bytes, attr->ar_debug_ptr, sizeof(*returned_sig_bytes));
    return DW_DLV_OK;
}

int dwarf_formsig8_const(Dwarf_Attribute attr, Dwarf_Sig8 * returned_sig_bytes, Dwarf_Error* error)


{
    int res  =_dwarf_formsig8_internal(attr, DW_FORM_data8, returned_sig_bytes,error);
    return res;
}


int dwarf_formsig8(Dwarf_Attribute attr, Dwarf_Sig8 * returned_sig_bytes, Dwarf_Error* error)


{
    int res  = _dwarf_formsig8_internal(attr, DW_FORM_ref_sig8, returned_sig_bytes,error);
    return res;
}


static int find_sig8_target_as_global_offset(Dwarf_Attribute attr, Dwarf_Sig8  *sig8, Dwarf_Bool  *is_info, Dwarf_Off   *targoffset, Dwarf_Error *error)




{
    Dwarf_Die  targdie = 0;
    Dwarf_Bool targ_is_info = 0;
    Dwarf_Off  localoff = 0;
    int res = 0;

    targ_is_info = attr->ar_cu_context->cc_is_info;
    memcpy(sig8,attr->ar_debug_ptr,sizeof(*sig8));
    res = dwarf_find_die_given_sig8(attr->ar_dbg, sig8,&targdie,&targ_is_info,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    res = dwarf_die_offsets(targdie,targoffset,&localoff,error);
    if (res != DW_DLV_OK) {
        dwarf_dealloc_die(targdie);
        return res;
    }
    *is_info = targdie->di_cu_context->cc_is_info;
    dwarf_dealloc_die(targdie);
    return DW_DLV_OK;
}




int dwarf_global_formref(Dwarf_Attribute attr, Dwarf_Off * ret_offset, Dwarf_Error * error)


{
    Dwarf_Bool is_info = 0;
    int res = 0;

    res = dwarf_global_formref_b(attr,ret_offset, &is_info,error);
    return res;
}
int dwarf_global_formref_b(Dwarf_Attribute attr, Dwarf_Off * ret_offset, Dwarf_Bool * offset_is_info, Dwarf_Error * error)



{
    Dwarf_Debug dbg = 0;
    Dwarf_Unsigned offset = 0;
    Dwarf_CU_Context cu_context = 0;
    Dwarf_Half context_version = 0;
    Dwarf_Byte_Ptr section_end = 0;
    Dwarf_Bool is_info = TRUE;

    int res  = get_attr_dbg(&dbg,&cu_context,attr,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    section_end = _dwarf_calculate_info_section_end_ptr(cu_context);
    context_version = cu_context->cc_version_stamp;
    is_info = cu_context->cc_is_info;
    switch (attr->ar_attribute_form) {

    case DW_FORM_ref1:
        offset = *(Dwarf_Small *) attr->ar_debug_ptr;
        goto fixoffset;

    case DW_FORM_ref2:
        READ_UNALIGNED_CK(dbg, offset, Dwarf_Unsigned, attr->ar_debug_ptr, DWARF_HALF_SIZE, error,section_end);

        goto fixoffset;

    case DW_FORM_ref4:
        READ_UNALIGNED_CK(dbg, offset, Dwarf_Unsigned, attr->ar_debug_ptr, DWARF_32BIT_SIZE, error,section_end);

        goto fixoffset;

    case DW_FORM_ref8:
        READ_UNALIGNED_CK(dbg, offset, Dwarf_Unsigned, attr->ar_debug_ptr, DWARF_64BIT_SIZE, error,section_end);

        goto fixoffset;

    case DW_FORM_ref_udata:
        {
        Dwarf_Byte_Ptr ptr = attr->ar_debug_ptr;
        Dwarf_Unsigned localoffset = 0;

        DECODE_LEB128_UWORD_CK(ptr,localoffset, dbg,error,section_end);
        offset = localoffset;

        fixoffset: 

        
        if (offset >= cu_context->cc_length + cu_context->cc_length_size + cu_context->cc_extension_size) {

            _dwarf_error(dbg, error, DW_DLE_ATTR_FORM_OFFSET_BAD);
            return DW_DLV_ERROR;
        }

        
        offset += cu_context->cc_debug_offset;
        }
        break;

    
    case DW_FORM_data4:
        if (context_version >= DW_CU_VERSION4) {
            _dwarf_error(dbg, error, DW_DLE_NOT_REF_FORM);
            return DW_DLV_ERROR;
        }
        READ_UNALIGNED_CK(dbg, offset, Dwarf_Unsigned, attr->ar_debug_ptr, DWARF_32BIT_SIZE, error, section_end);

        
        break;
    case DW_FORM_data8:
        if (context_version >= DW_CU_VERSION4) {
            _dwarf_error(dbg, error, DW_DLE_NOT_REF_FORM);
            return DW_DLV_ERROR;
        }
        READ_UNALIGNED_CK(dbg, offset, Dwarf_Unsigned, attr->ar_debug_ptr, DWARF_64BIT_SIZE, error,section_end);

        
        break;
    case DW_FORM_ref_addr:
        {
            
            unsigned length_size = 0;
            if (context_version == 2) {
                length_size = cu_context->cc_address_size;
            } else {
                length_size = cu_context->cc_length_size;
            }
            if (length_size == 4) {
                READ_UNALIGNED_CK(dbg, offset, Dwarf_Unsigned, attr->ar_debug_ptr, DWARF_32BIT_SIZE, error,section_end);

            } else if (length_size == 8) {
                READ_UNALIGNED_CK(dbg, offset, Dwarf_Unsigned, attr->ar_debug_ptr, DWARF_64BIT_SIZE, error,section_end);

            } else {
                _dwarf_error(dbg, error, DW_DLE_FORM_SEC_OFFSET_LENGTH_BAD);
                return DW_DLV_ERROR;
            }
        }
        break;
    
    case DW_FORM_loclistx:
    case DW_FORM_rnglistx: {
        unsigned length_size = cu_context->cc_length_size;
        READ_UNALIGNED_CK(dbg, offset, Dwarf_Unsigned, attr->ar_debug_ptr, length_size, error,section_end);

        }
        break;
    case DW_FORM_sec_offset:
    case DW_FORM_GNU_ref_alt:  
    case DW_FORM_GNU_strp_alt: 
    case DW_FORM_strp_sup:     
    case DW_FORM_line_strp:    
        {
            
            
            unsigned length_size = cu_context->cc_length_size;
            if (length_size == 4) {
                READ_UNALIGNED_CK(dbg, offset, Dwarf_Unsigned, attr->ar_debug_ptr, DWARF_32BIT_SIZE, error,section_end);

            } else if (length_size == 8) {
                READ_UNALIGNED_CK(dbg, offset, Dwarf_Unsigned, attr->ar_debug_ptr, DWARF_64BIT_SIZE, error,section_end);

            } else {
                _dwarf_error(dbg, error, DW_DLE_FORM_SEC_OFFSET_LENGTH_BAD);
                return DW_DLV_ERROR;
            }
        }
        break;
    case DW_FORM_ref_sig8: {
        
        Dwarf_Sig8 sig8;
        Dwarf_Bool t_is_info = TRUE;
        Dwarf_Unsigned t_offset = 0;

        memcpy(&sig8,attr->ar_debug_ptr,sizeof(Dwarf_Sig8));
        res = find_sig8_target_as_global_offset(attr, &sig8,&t_is_info,&t_offset,error);
        if (res == DW_DLV_ERROR) {
            _dwarf_error_string(dbg, error, DW_DLE_REF_SIG8_NOT_HANDLED, "DW_DLE_REF_SIG8_NOT_HANDLED: " " problem finding target");


            return DW_DLV_ERROR;
        }
        if (res == DW_DLV_NO_ENTRY) {
            return res;
        }
        is_info = t_is_info;
        offset = t_offset;
        break;
    }
    default: {
        dwarfstring m;
        int formcode = attr->ar_attribute_form;
        int fcres = 0;
        const char *name = 0;

        dwarfstring_constructor(&m);
        dwarfstring_append_printf_u(&m, "DW_DLE_BAD_REF_FORM: The form code is 0x%x ", formcode);

        fcres  = dwarf_get_FORM_name (formcode,&name);
        if (fcres != DW_DLV_OK) {
            name="<UnknownFormCode>";
        }
        dwarfstring_append_printf_s(&m, " %s.",(char *)name);
        _dwarf_error_string(dbg, error, DW_DLE_BAD_REF_FORM, dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        return DW_DLV_ERROR;
        }
    }

    *offset_is_info = is_info;
    *ret_offset = offset;
    return DW_DLV_OK;
}



int _dwarf_get_addr_index_itself(int theform, Dwarf_Small *info_ptr, Dwarf_Debug dbg, Dwarf_CU_Context cu_context, Dwarf_Unsigned *val_out, Dwarf_Error * error)





{
    Dwarf_Unsigned index = 0;
    Dwarf_Byte_Ptr section_end = 0;

    section_end = _dwarf_calculate_info_section_end_ptr(cu_context);
    switch(theform){
    case DW_FORM_LLVM_addrx_offset: {
        Dwarf_Unsigned tmp = 0;
        Dwarf_Unsigned tmp2 = 0;
        DECODE_LEB128_UWORD_CK(info_ptr,tmp, dbg,error,section_end);
        READ_UNALIGNED_CK(dbg, tmp2, Dwarf_Unsigned, info_ptr, SIZEOFT32, error,section_end);

        index = (tmp<<32) | tmp2;
        break;
    }
    case DW_FORM_GNU_addr_index:
    case DW_FORM_addrx:
        DECODE_LEB128_UWORD_CK(info_ptr,index, dbg,error,section_end);
        break;
    case DW_FORM_addrx1:
        READ_UNALIGNED_CK(dbg, index, Dwarf_Unsigned, info_ptr, 1, error,section_end);

        break;
    case DW_FORM_addrx2:
        READ_UNALIGNED_CK(dbg, index, Dwarf_Unsigned, info_ptr, 2, error,section_end);

        break;
    case DW_FORM_addrx3:
        READ_UNALIGNED_CK(dbg, index, Dwarf_Unsigned, info_ptr, 3, error,section_end);

        break;
    case DW_FORM_addrx4:
        READ_UNALIGNED_CK(dbg, index, Dwarf_Unsigned, info_ptr, 4, error,section_end);

        break;
    default:
        _dwarf_error(dbg, error, DW_DLE_ATTR_FORM_NOT_ADDR_INDEX);
        return DW_DLV_ERROR;
    }
    *val_out = index;
    return DW_DLV_OK;
}

int dwarf_get_debug_addr_index(Dwarf_Attribute attr, Dwarf_Unsigned * return_index, Dwarf_Error * error)


{
    int theform = 0;
    Dwarf_CU_Context cu_context = 0;
    Dwarf_Debug dbg = 0;

    int res  = get_attr_dbg(&dbg,&cu_context,attr,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    theform = attr->ar_attribute_form;
    if (dwarf_addr_form_is_indexed(theform)) {
        Dwarf_Unsigned index = 0;

        res = _dwarf_get_addr_index_itself(theform, attr->ar_debug_ptr,dbg,cu_context,&index,error);
        *return_index = index;
        return res;
    }

    _dwarf_error(dbg, error, DW_DLE_ATTR_FORM_NOT_ADDR_INDEX);
    return DW_DLV_ERROR;
}

static int dw_read_str_index_val_itself(Dwarf_Debug dbg, unsigned theform, Dwarf_Small *info_ptr, Dwarf_Small *section_end, Dwarf_Unsigned *return_index, Dwarf_Error *error)





{
    Dwarf_Unsigned index = 0;

    switch(theform) {
    case DW_FORM_strx:
    case DW_FORM_GNU_str_index:
        DECODE_LEB128_UWORD_CK(info_ptr,index, dbg,error,section_end);
        break;
    case DW_FORM_strx1:
        READ_UNALIGNED_CK(dbg, index, Dwarf_Unsigned, info_ptr, 1, error,section_end);

        break;
    case DW_FORM_strx2:
        READ_UNALIGNED_CK(dbg, index, Dwarf_Unsigned, info_ptr, 2, error,section_end);

        break;
    case DW_FORM_strx3:
        READ_UNALIGNED_CK(dbg, index, Dwarf_Unsigned, info_ptr, 3, error,section_end);

        break;
    case DW_FORM_strx4:
        READ_UNALIGNED_CK(dbg, index, Dwarf_Unsigned, info_ptr, 4, error,section_end);

        break;
    default:
        _dwarf_error(dbg, error, DW_DLE_ATTR_FORM_NOT_STR_INDEX);
        return DW_DLV_ERROR;
    }
    *return_index = index;
    return DW_DLV_OK;
}


int dwarf_get_debug_str_index(Dwarf_Attribute attr, Dwarf_Unsigned *return_index, Dwarf_Error *error)


{
    int theform = attr->ar_attribute_form;
    Dwarf_CU_Context cu_context = 0;
    Dwarf_Debug dbg = 0;
    int res  = 0;
    Dwarf_Byte_Ptr section_end =  0;
    Dwarf_Unsigned index = 0;
    Dwarf_Small *info_ptr = 0;
    int indxres = 0;

    res = get_attr_dbg(&dbg,&cu_context,attr,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    section_end = _dwarf_calculate_info_section_end_ptr(cu_context);
    info_ptr = attr->ar_debug_ptr;

    indxres = dw_read_str_index_val_itself(dbg, theform, info_ptr, section_end, &index,error);
    if (indxres == DW_DLV_OK) {
        *return_index = index;
        return indxres;
    }
    return indxres;
}

int _dwarf_extract_data16(Dwarf_Debug dbg, Dwarf_Small *data, Dwarf_Small *section_start, Dwarf_Small *section_end, Dwarf_Form_Data16  * returned_val, Dwarf_Error *error)





{
    Dwarf_Small *data16end = 0;

    data16end = data + sizeof(Dwarf_Form_Data16);
    if (data  < section_start || section_end < data16end) {
        _dwarf_error(dbg, error,DW_DLE_DATA16_OUTSIDE_SECTION);
        return DW_DLV_ERROR;
    }
    memcpy(returned_val, data, sizeof(*returned_val));
    return DW_DLV_OK;

}

int dwarf_formdata16(Dwarf_Attribute attr, Dwarf_Form_Data16  * returned_val, Dwarf_Error*     error)


{
    Dwarf_Half attrform = 0;
    Dwarf_CU_Context cu_context = 0;
    Dwarf_Debug dbg = 0;
    int res  = 0;
    Dwarf_Small *section_end = 0;
    Dwarf_Unsigned section_length = 0;
    Dwarf_Small *section_start = 0;

    if (!attr) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NULL);
        return DW_DLV_ERROR;
    }
    if (!returned_val ) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NULL);
        return DW_DLV_ERROR;
    }
    res  = get_attr_dbg(&dbg,&cu_context,attr,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    attrform = attr->ar_attribute_form;
    if (attrform != DW_FORM_data16) {
        generate_form_error(dbg,error,attrform, DW_DLE_ATTR_FORM_BAD, "DW_DLE_ATTR_FORM_BAD", "dwarf_formdata16");


        return DW_DLV_ERROR;
    }
    section_start = _dwarf_calculate_info_section_start_ptr( cu_context,&section_length);
    section_end = section_start + section_length;

    res = _dwarf_extract_data16(dbg, attr->ar_debug_ptr, section_start, section_end, returned_val,  error);

    return res;
}


Dwarf_Bool dwarf_addr_form_is_indexed(int form)
{
    switch(form) {
    case DW_FORM_addrx:
    case DW_FORM_addrx1:
    case DW_FORM_addrx2:
    case DW_FORM_addrx3:
    case DW_FORM_addrx4:
    case DW_FORM_GNU_addr_index:
    case DW_FORM_LLVM_addrx_offset:
        return TRUE;
    default: break;
    }
    return FALSE;
}

int dwarf_formaddr(Dwarf_Attribute attr, Dwarf_Addr * return_addr, Dwarf_Error * error)

{
    Dwarf_Debug dbg = 0;
    Dwarf_Addr ret_addr = 0;
    Dwarf_CU_Context cu_context = 0;
    Dwarf_Half attrform = 0;
    int res = 0;

    res  = get_attr_dbg(&dbg,&cu_context,attr,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    attrform = attr->ar_attribute_form;
    if (dwarf_addr_form_is_indexed(attrform)) {
        res = _dwarf_look_in_local_and_tied( attrform, cu_context, attr->ar_debug_ptr, return_addr, error);




        return res;
    }
    if (attrform == DW_FORM_addr  ) {

        Dwarf_Small *section_end = _dwarf_calculate_info_section_end_ptr(cu_context);

        READ_UNALIGNED_CK(dbg, ret_addr, Dwarf_Addr, attr->ar_debug_ptr, cu_context->cc_address_size, error,section_end);


        *return_addr = ret_addr;
        return DW_DLV_OK;
    }
    generate_form_error(dbg,error,attrform, DW_DLE_ATTR_FORM_BAD, "DW_DLE_ATTR_FORM_BAD", "dwarf_formaddr");


    return DW_DLV_ERROR;
}

int dwarf_formflag(Dwarf_Attribute attr, Dwarf_Bool * ret_bool, Dwarf_Error * error)

{
    Dwarf_CU_Context cu_context = 0;
    Dwarf_Debug dbg = 0;

    if (!attr) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NULL);
        return DW_DLV_ERROR;
    }
    cu_context = attr->ar_cu_context;
    if (!cu_context) {
        _dwarf_error(NULL, error, DW_DLE_ATTR_NO_CU_CONTEXT);
        return DW_DLV_ERROR;
    }
    dbg = cu_context->cc_dbg;
    if (!dbg || dbg->de_magic != DBG_IS_VALID) {
        _dwarf_error_string(NULL, error, DW_DLE_ATTR_DBG_NULL, "DW_DLE_ATTR_DBG_NULL: dwarf_formflag() attribute" " passed in has NULL or stale Dwarf_Debug pointer");

        return DW_DLV_ERROR;
    }
    if (dbg != attr->ar_dbg) {
        _dwarf_error_string(NULL, error, DW_DLE_ATTR_DBG_NULL, "DW_DLE_ATTR_DBG_NULL: an attribute and its " "cu_context do not have the same Dwarf_Debug" );

        return DW_DLV_ERROR;
    }
    if (attr->ar_attribute_form == DW_FORM_flag_present) {
        
        *ret_bool = 1;
        return DW_DLV_OK;
    }

    if (attr->ar_attribute_form == DW_FORM_flag) {
        *ret_bool = *(Dwarf_Small *)(attr->ar_debug_ptr);
        return DW_DLV_OK;
    }
    generate_form_error(dbg,error,attr->ar_attribute_form, DW_DLE_ATTR_FORM_BAD, "DW_DLE_ATTR_FORM_BAD", "dwarf_formflat");


    return DW_DLV_ERROR;
}

Dwarf_Bool _dwarf_allow_formudata(unsigned form)
{
    switch(form) {
    case DW_FORM_data1:
    case DW_FORM_data2:
    case DW_FORM_data4:
    case DW_FORM_data8:
    case DW_FORM_udata:
    case DW_FORM_loclistx:
    case DW_FORM_rnglistx:
        return TRUE;
    default:
        break;
    }
    return FALSE;
}


int _dwarf_formudata_internal(Dwarf_Debug dbg, Dwarf_Attribute attr, unsigned form, Dwarf_Byte_Ptr data, Dwarf_Byte_Ptr section_end, Dwarf_Unsigned *return_uval, Dwarf_Unsigned *bytes_read, Dwarf_Error *error)







{
    Dwarf_Unsigned ret_value = 0;

    switch (form) {
    case DW_FORM_data1:
        READ_UNALIGNED_CK(dbg, ret_value, Dwarf_Unsigned, data, sizeof(Dwarf_Small), error,section_end);

        *return_uval = ret_value;
        *bytes_read = 1;
        return DW_DLV_OK;

    
    case DW_FORM_data2:{
        READ_UNALIGNED_CK(dbg, ret_value, Dwarf_Unsigned, data, DWARF_HALF_SIZE, error,section_end);

        *return_uval = ret_value;
        *bytes_read = DWARF_HALF_SIZE;
        return DW_DLV_OK;
        }

    case DW_FORM_data4:{
        READ_UNALIGNED_CK(dbg, ret_value, Dwarf_Unsigned, data, DWARF_32BIT_SIZE, error,section_end);


        *return_uval = ret_value;
        *bytes_read = DWARF_32BIT_SIZE;;
        return DW_DLV_OK;
        }

    case DW_FORM_data8:{
        READ_UNALIGNED_CK(dbg, ret_value, Dwarf_Unsigned, data, DWARF_64BIT_SIZE, error,section_end);


        *return_uval = ret_value;
        *bytes_read = DWARF_64BIT_SIZE;
        return DW_DLV_OK;
        }
        break;
    
    case DW_FORM_loclistx:
    case DW_FORM_rnglistx:
    case DW_FORM_udata: {
        Dwarf_Unsigned leblen = 0;
        DECODE_LEB128_UWORD_LEN_CK(data, ret_value,leblen, dbg,error,section_end);
        *return_uval = ret_value;
        *bytes_read = leblen;
        return DW_DLV_OK;
    }
    
    default:
        break;
    }
    if (attr) {
        int res = 0;
        Dwarf_Signed s = 0;
        res = dwarf_formsdata(attr,&s,error);
        if (res != DW_DLV_OK) {
            return res;
        }
        if (s < 0 ) {
            _dwarf_error(dbg, error, DW_DLE_UDATA_VALUE_NEGATIVE);
            return DW_DLV_ERROR;
        }
        *return_uval = (Dwarf_Unsigned)s;
        *bytes_read = 0;
        return DW_DLV_OK;
    }
    generate_form_error(dbg,error,form, DW_DLE_ATTR_FORM_BAD, "DW_DLE_ATTR_FORM_BAD", "formudata (internal function)");


    return DW_DLV_ERROR;
}

int dwarf_formudata(Dwarf_Attribute attr, Dwarf_Unsigned * return_uval, Dwarf_Error * error)

{
    Dwarf_Debug dbg = 0;
    Dwarf_CU_Context cu_context = 0;
    Dwarf_Byte_Ptr section_end = 0;
    Dwarf_Unsigned bytes_read = 0;
    Dwarf_Byte_Ptr data =  attr->ar_debug_ptr;
    unsigned form = 0;

    int res  = get_attr_dbg(&dbg,&cu_context,attr,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    section_end = _dwarf_calculate_info_section_end_ptr(cu_context);
    form = attr->ar_attribute_form;

    res = _dwarf_formudata_internal(dbg, attr, form, data, section_end, return_uval, &bytes_read, error);


    return res;
}

int dwarf_formsdata(Dwarf_Attribute attr, Dwarf_Signed * return_sval, Dwarf_Error * error)

{
    Dwarf_Signed ret_value = 0;
    Dwarf_Debug dbg = 0;
    Dwarf_CU_Context cu_context = 0;
    Dwarf_Byte_Ptr section_end = 0;

    int res  = get_attr_dbg(&dbg,&cu_context,attr,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    section_end = _dwarf_calculate_info_section_end_ptr(cu_context);
    switch (attr->ar_attribute_form) {

    case DW_FORM_data1:
        if ( attr->ar_debug_ptr >= section_end) {
            _dwarf_error(dbg, error, DW_DLE_DIE_BAD);
            return DW_DLV_ERROR;
        }
        *return_sval = (*(Dwarf_Sbyte *) attr->ar_debug_ptr);
        return DW_DLV_OK;

    
    case DW_FORM_data2:{
        READ_UNALIGNED_CK(dbg, ret_value, Dwarf_Signed, attr->ar_debug_ptr, DWARF_HALF_SIZE, error,section_end);


        *return_sval = (Dwarf_Shalf) ret_value;
        return DW_DLV_OK;

        }

    case DW_FORM_data4:{
        READ_UNALIGNED_CK(dbg, ret_value, Dwarf_Signed, attr->ar_debug_ptr, DWARF_32BIT_SIZE, error,section_end);


        SIGN_EXTEND(ret_value,DWARF_32BIT_SIZE);
        *return_sval = (Dwarf_Signed) ret_value;
        return DW_DLV_OK;
        }

    case DW_FORM_data8:{
        READ_UNALIGNED_CK(dbg, ret_value, Dwarf_Signed, attr->ar_debug_ptr, DWARF_64BIT_SIZE, error,section_end);


        
        *return_sval = (Dwarf_Signed) ret_value;
        return DW_DLV_OK;
        }

    
    case DW_FORM_implicit_const:
        *return_sval = attr->ar_implicit_const;
        return DW_DLV_OK;

    case DW_FORM_sdata: {
        Dwarf_Byte_Ptr tmp = attr->ar_debug_ptr;

        DECODE_LEB128_SWORD_CK(tmp, ret_value, dbg,error,section_end);
        *return_sval = ret_value;
        return DW_DLV_OK;

    }

        

    default:
        break;
    }
    generate_form_error(dbg,error,attr->ar_attribute_form, DW_DLE_ATTR_FORM_BAD, "DW_DLE_ATTR_FORM_BAD", "dwarf_formsdata");


    return DW_DLV_ERROR;
}

int _dwarf_formblock_internal(Dwarf_Debug dbg, Dwarf_Attribute attr, Dwarf_CU_Context cu_context, Dwarf_Block * return_block, Dwarf_Error * error)




{
    Dwarf_Small *section_start = 0;
    Dwarf_Small *section_end = 0;
    Dwarf_Unsigned section_length = 0;
    Dwarf_Unsigned length = 0;
    Dwarf_Small *data = 0;

    section_end = _dwarf_calculate_info_section_end_ptr(cu_context);
    section_start = _dwarf_calculate_info_section_start_ptr(cu_context, &section_length);


    switch (attr->ar_attribute_form) {

    case DW_FORM_block1:
        length = *(Dwarf_Small *) attr->ar_debug_ptr;
        data = attr->ar_debug_ptr + sizeof(Dwarf_Small);
        break;

    case DW_FORM_block2:
        READ_UNALIGNED_CK(dbg, length, Dwarf_Unsigned, attr->ar_debug_ptr, DWARF_HALF_SIZE, error,section_end);

        data = attr->ar_debug_ptr + DWARF_HALF_SIZE;
        break;

    case DW_FORM_block4:
        READ_UNALIGNED_CK(dbg, length, Dwarf_Unsigned, attr->ar_debug_ptr, DWARF_32BIT_SIZE, error,section_end);

        data = attr->ar_debug_ptr + DWARF_32BIT_SIZE;
        break;

    case DW_FORM_exprloc:
    case DW_FORM_block: {
        Dwarf_Byte_Ptr tmp = attr->ar_debug_ptr;
        Dwarf_Unsigned leblen = 0;

        DECODE_LEB128_UWORD_LEN_CK(tmp, length, leblen, dbg,error,section_end);
        data = attr->ar_debug_ptr + leblen;
        break;
        }
    default:
        generate_form_error(dbg,error,attr->ar_attribute_form, DW_DLE_ATTR_FORM_BAD, "DW_DLE_ATTR_FORM_BAD", "dwarf_formblock");


        return DW_DLV_ERROR;
    }
    
    if (length >= section_length) {
        
        _dwarf_error_string(dbg, error, DW_DLE_FORM_BLOCK_LENGTH_ERROR, "DW_DLE_FORM_BLOCK_LENGTH_ERROR: " "The length of the block is greater " "than the section length! Corrupt Dwarf.");



        return DW_DLV_ERROR;
    }
    if ((attr->ar_debug_ptr + length) > section_end) {
        _dwarf_error_string(dbg, error, DW_DLE_FORM_BLOCK_LENGTH_ERROR, "DW_DLE_FORM_BLOCK_LENGTH_ERROR: " "The block length means the block " "runs off the end of the section length!" " Corrupt Dwarf.");




        return DW_DLV_ERROR;
    }
    if (data > section_end) {
        _dwarf_error_string(dbg, error, DW_DLE_FORM_BLOCK_LENGTH_ERROR, "DW_DLE_FORM_BLOCK_LENGTH_ERROR: " "The block content is " "past the end of the section!" " Corrupt Dwarf.");




        _dwarf_error(dbg, error, DW_DLE_FORM_BLOCK_LENGTH_ERROR);
        return DW_DLV_ERROR;
    }
    if ((data + length) > section_end) {
        _dwarf_error_string(dbg, error, DW_DLE_FORM_BLOCK_LENGTH_ERROR, "DW_DLE_FORM_BLOCK_LENGTH_ERROR: " "The end of the block content is " "past the end of the section!" " Corrupt Dwarf.");




        return DW_DLV_ERROR;
    }
    return_block->bl_len = length;
    return_block->bl_data = data;
    
    return_block->bl_from_loclist =  DW_LKIND_expression;
    return_block->bl_section_offset =  data - section_start;
    return DW_DLV_OK;
}

int dwarf_formblock(Dwarf_Attribute attr, Dwarf_Block ** return_block, Dwarf_Error * error)

{
    Dwarf_CU_Context cu_context = 0;
    Dwarf_Debug dbg = 0;
    Dwarf_Block local_block;
    Dwarf_Block *out_block = 0;
    int res = 0;

    memset(&local_block,0,sizeof(local_block));
    res  = get_attr_dbg(&dbg,&cu_context,attr,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    res = _dwarf_formblock_internal(dbg,attr, cu_context, &local_block, error);
    if (res != DW_DLV_OK) {
        return res;
    }
    out_block = (Dwarf_Block *)
        _dwarf_get_alloc(dbg, DW_DLA_BLOCK, 1);
    if (!out_block) {
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    *out_block = local_block;
    *return_block = out_block;
    return DW_DLV_OK;
}

int _dwarf_extract_string_offset_via_str_offsets(Dwarf_Debug dbg, Dwarf_Small *data_ptr, Dwarf_Small *end_data_ptr, Dwarf_Half   attrnum UNUSEDARG, Dwarf_Half   attrform, Dwarf_CU_Context cu_context, Dwarf_Unsigned *str_sect_offset_out, Dwarf_Error *error)







{
    Dwarf_Unsigned index_to_offset_entry = 0;
    Dwarf_Unsigned offsetintable = 0;
    Dwarf_Unsigned end_offsetintable = 0;
    Dwarf_Unsigned indexoffset = 0;
    Dwarf_Unsigned baseoffset = 0;
    int res = 0;
    int idxres = 0;
    Dwarf_Small *sof_start = 0;
    Dwarf_Unsigned sof_len = 0;
    Dwarf_Small   *sof_end = 0;

    res = _dwarf_load_section(dbg, &dbg->de_debug_str_offsets,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    
    sof_start = dbg->de_debug_str_offsets.dss_data;
    sof_len = dbg->de_debug_str_offsets.dss_size;
    sof_end = sof_start+sof_len;
    idxres = dw_read_str_index_val_itself(dbg, attrform,data_ptr,end_data_ptr,&index_to_offset_entry,error);
    if ( idxres != DW_DLV_OK) {
        return idxres;
    }

    if (cu_context->cc_str_offsets_base_present) {
        baseoffset = cu_context->cc_str_offsets_base;
    }
    indexoffset = index_to_offset_entry* cu_context->cc_length_size;
    baseoffset = cu_context->cc_str_offsets_base;
    if (!baseoffset) {
        if (cu_context->cc_version_stamp ==  DW_CU_VERSION5 ) {
            
            Dwarf_Small * ststart = dbg->de_debug_str_offsets.dss_data;
            Dwarf_Small * stend = 0;
            Dwarf_Unsigned  stsize = dbg->de_debug_str_offsets.dss_size;
            Dwarf_Unsigned length            = 0;
            Dwarf_Half local_offset_size = 0;
            Dwarf_Half local_extension_size = 0;
            Dwarf_Half version               = 0;
            Dwarf_Half padding               = 0;

            stend = ststart + stsize;
            res = _dwarf_trial_read_dwarf_five_hdr(dbg, ststart,stsize,stend, &length, &local_offset_size, &local_extension_size, &version, &padding, error);





            if (res == DW_DLV_OK) {
                baseoffset = local_extension_size + local_offset_size + 2*DWARF_HALF_SIZE;

            } else {
                if (res == DW_DLV_ERROR) {
                    dwarf_dealloc_error(dbg,*error);
                    *error = 0;
                } else {}
            }
        }
    }
    offsetintable = baseoffset +indexoffset;
    end_offsetintable = offsetintable + cu_context->cc_str_offsets_offset_size;
    
    if (end_offsetintable > dbg->de_debug_str_offsets.dss_size ) {
        dwarfstring m;

        dwarfstring_constructor(&m);
        dwarfstring_append_printf_u(&m, "DW_DLE_ATTR_FORM_SIZE_BAD: The end offset of " "a .debug_str_offsets table is 0x%x ", end_offsetintable);


        dwarfstring_append_printf_u(&m, "but the object section is just 0x%x " "bytes long", dbg->de_debug_str_offsets.dss_size);


        _dwarf_error_string(dbg, error, DW_DLE_ATTR_FORM_SIZE_BAD, dwarfstring_string(&m));

        dwarfstring_destructor(&m);
        return DW_DLV_ERROR;
    }

    {
        Dwarf_Unsigned offsettostr = baseoffset+offsetintable;

        
        READ_UNALIGNED_CK(dbg,offsettostr,Dwarf_Unsigned, sof_start+ offsetintable, cu_context->cc_length_size,error,sof_end);

        *str_sect_offset_out = offsettostr;
    }
    return DW_DLV_OK;
}

int _dwarf_extract_local_debug_str_string_given_offset(Dwarf_Debug dbg, unsigned attrform, Dwarf_Unsigned offset, char ** return_str, Dwarf_Error * error)




{
    if (attrform == DW_FORM_strp || attrform == DW_FORM_line_strp || attrform == DW_FORM_GNU_str_index || attrform == DW_FORM_strx1 || attrform == DW_FORM_strx2 || attrform == DW_FORM_strx3 || attrform == DW_FORM_strx4 || attrform == DW_FORM_strx) {






        
        Dwarf_Small   *secend = 0;
        Dwarf_Small   *secbegin = 0;
        Dwarf_Small   *strbegin = 0;
        Dwarf_Unsigned secsize = 0;
        int errcode = 0;
        const char *errname = 0;
        int res = 0;

        if (attrform == DW_FORM_line_strp) {
            res = _dwarf_load_section(dbg, &dbg->de_debug_line_str,error);
            if (res != DW_DLV_OK) {
                return res;
            }
            errcode = DW_DLE_STRP_OFFSET_BAD;
            errname = "DW_DLE_STRP_OFFSET_BAD";
            secsize = dbg->de_debug_line_str.dss_size;
            secbegin = dbg->de_debug_line_str.dss_data;
            strbegin= dbg->de_debug_line_str.dss_data + offset;
            secend = dbg->de_debug_line_str.dss_data + secsize;
        } else {
            
            res = _dwarf_load_section(dbg, &dbg->de_debug_str,error);
            if (res != DW_DLV_OK) {
                return res;
            }
            errcode = DW_DLE_STRING_OFFSET_BAD;
            errname = "DW_DLE_STRING_OFFSET_BAD";
            secsize = dbg->de_debug_str.dss_size;
            secbegin = dbg->de_debug_str.dss_data;
            strbegin= dbg->de_debug_str.dss_data + offset;
            secend = dbg->de_debug_str.dss_data + secsize;
        }
        if (offset >= secsize) {
            dwarfstring m;
            const char *name = "<unknownform>";

            dwarf_get_FORM_name(attrform,&name);

            dwarfstring_constructor(&m);
            dwarfstring_append(&m,(char *)errname);
            dwarfstring_append_printf_s(&m, " Form %s ",(char *)name);
            dwarfstring_append_printf_u(&m, "string offset of 0x%" DW_PR_DUx " ", offset);

            dwarfstring_append_printf_u(&m, "is larger than the string section " "size of  0x%" DW_PR_DUx, secsize);


            _dwarf_error_string(dbg, error, errcode, dwarfstring_string(&m));
            dwarfstring_destructor(&m);
            
            return DW_DLV_ERROR;
        }
        res= _dwarf_check_string_valid(dbg,secbegin,strbegin, secend, errcode,error);
        if (res != DW_DLV_OK) {
            return res;
        }

        *return_str = (char *)strbegin;
        return DW_DLV_OK;
    }
    generate_form_error(dbg,error,attrform, DW_DLE_ATTR_FORM_BAD, "DW_DLE_ATTR_FORM_BAD", "extract debug_str string");


    return DW_DLV_ERROR;
}


int dwarf_formstring(Dwarf_Attribute attr, char **return_str, Dwarf_Error * error)

{
    Dwarf_CU_Context cu_context = 0;
    Dwarf_Debug dbg = 0;
    Dwarf_Unsigned offset = 0;
    int res = DW_DLV_ERROR;
    Dwarf_Small *secdataptr = 0;
    Dwarf_Small *secend = 0;
    Dwarf_Unsigned secdatalen = 0;
    Dwarf_Small *infoptr = attr->ar_debug_ptr;
    Dwarf_Small *contextend = 0;

    res  = get_attr_dbg(&dbg,&cu_context,attr,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    if (cu_context->cc_is_info) {
        secdataptr = (Dwarf_Small *)dbg->de_debug_info.dss_data;
        secdatalen = dbg->de_debug_info.dss_size;
    } else {
        secdataptr = (Dwarf_Small *)dbg->de_debug_types.dss_data;
        secdatalen = dbg->de_debug_types.dss_size;
    }
    contextend = secdataptr + cu_context->cc_debug_offset + cu_context->cc_length + cu_context->cc_length_size + cu_context->cc_extension_size;



    secend = secdataptr + secdatalen;
    if (contextend < secend) {
        secend = contextend;
    }
    switch(attr->ar_attribute_form) {
    case DW_FORM_string: {
        Dwarf_Small *begin = attr->ar_debug_ptr;

        res= _dwarf_check_string_valid(dbg,secdataptr,begin, secend, DW_DLE_FORM_STRING_BAD_STRING,error);
        if (res != DW_DLV_OK) {
            return res;
        }
        *return_str = (char *) (begin);
        return DW_DLV_OK;
    }
    case DW_FORM_GNU_strp_alt:
    case DW_FORM_strp_sup:  {
        Dwarf_Error alterr = 0;
        Dwarf_Bool is_info = TRUE;
        
        Dwarf_Off soffset = 0;

        res = dwarf_global_formref_b(attr, &soffset, &is_info,error);
        if (res != DW_DLV_OK) {
            return res;
        }
        res = _dwarf_get_string_from_tied(dbg, soffset, return_str, &alterr);
        if (res == DW_DLV_ERROR) {
            if (dwarf_errno(alterr) == DW_DLE_NO_TIED_FILE_AVAILABLE) {
                dwarf_dealloc(dbg,alterr,DW_DLA_ERROR);
                if ( attr->ar_attribute_form == DW_FORM_GNU_strp_alt) {
                    *return_str = (char *)"<DW_FORM_GNU_strp_alt-no-tied-file>";
                } else {
                    *return_str = (char *)"<DW_FORM_strp_sup-no-tied-file>";
                }
                return DW_DLV_OK;
            }
            if (error) {
                *error = alterr;
            } else {
                dwarf_dealloc_error(dbg,alterr);
                alterr = 0;
            }
            return res;
        }
        if (res == DW_DLV_NO_ENTRY) {
            if ( attr->ar_attribute_form == DW_FORM_GNU_strp_alt) {
                *return_str = (char *)"<DW_FORM_GNU_strp_alt-no-tied-file>";
            }else {
                *return_str = (char *)"<DW_FORM_strp_sup-no-tied-file>";
            }
        }
        return res;
    }
    case DW_FORM_GNU_str_index:
    case DW_FORM_strx:
    case DW_FORM_strx1:
    case DW_FORM_strx2:
    case DW_FORM_strx3:
    case DW_FORM_strx4: {
        Dwarf_Unsigned offsettostr= 0;

        res = _dwarf_extract_string_offset_via_str_offsets(dbg, infoptr, secend, attr->ar_attribute, attr->ar_attribute_form, cu_context, &offsettostr, error);






        if (res != DW_DLV_OK) {
            return res;
        }
        offset = offsettostr;
        break;
    }
    case DW_FORM_strp:
    case DW_FORM_line_strp:{
        READ_UNALIGNED_CK(dbg, offset, Dwarf_Unsigned, infoptr, cu_context->cc_length_size,error,secend);

        break;
    }
    default:
        _dwarf_error(dbg, error, DW_DLE_STRING_FORM_IMPROPER);
        return DW_DLV_ERROR;
    }
    
    res = _dwarf_extract_local_debug_str_string_given_offset(dbg, attr->ar_attribute_form, offset, return_str, error);



    return res;
}

int _dwarf_get_string_from_tied(Dwarf_Debug dbg, Dwarf_Unsigned offset, char **return_str, Dwarf_Error*error)



{
    Dwarf_Debug tieddbg = 0;
    Dwarf_Small *secend = 0;
    Dwarf_Small *secbegin = 0;
    Dwarf_Small *strbegin = 0;
    int res = DW_DLV_ERROR;
    Dwarf_Error localerror = 0;

    
    tieddbg = dbg->de_tied_data.td_tied_object;
    if (!tieddbg) {
        _dwarf_error(dbg, error, DW_DLE_NO_TIED_FILE_AVAILABLE);
        return  DW_DLV_ERROR;
    }
    
    res = _dwarf_load_section(tieddbg, &tieddbg->de_debug_str, &localerror);
    if (res == DW_DLV_ERROR) {
        Dwarf_Unsigned lerrno = dwarf_errno(localerror);
        dwarf_dealloc(tieddbg,localerror,DW_DLA_ERROR);
        _dwarf_error(dbg,error,lerrno);
        return res;
    }
    if (res == DW_DLV_NO_ENTRY) {
        return res;
    }
    if (offset >= tieddbg->de_debug_str.dss_size) {
        
        _dwarf_error(dbg, error,  DW_DLE_NO_TIED_STRING_AVAILABLE);
        return DW_DLV_ERROR;
    }
    secbegin = tieddbg->de_debug_str.dss_data;
    strbegin= tieddbg->de_debug_str.dss_data + offset;
    secend = tieddbg->de_debug_str.dss_data + tieddbg->de_debug_str.dss_size;

    
    if (offset >= tieddbg->de_debug_str.dss_size) {
        _dwarf_error(dbg, error,  DW_DLE_NO_TIED_STRING_AVAILABLE);
        return DW_DLV_ERROR;
    }
    res= _dwarf_check_string_valid(tieddbg,secbegin,strbegin, secend, DW_DLE_NO_TIED_STRING_AVAILABLE, &localerror);

    if (res == DW_DLV_ERROR) {
        Dwarf_Unsigned lerrno = dwarf_errno(localerror);
        dwarf_dealloc(tieddbg,localerror,DW_DLA_ERROR);
        _dwarf_error(dbg,error,lerrno);
        return res;
    }
    if (res == DW_DLV_NO_ENTRY) {
        return res;
    }
    *return_str = (char *) (tieddbg->de_debug_str.dss_data + offset);
    return DW_DLV_OK;
}

int dwarf_formexprloc(Dwarf_Attribute attr, Dwarf_Unsigned * return_exprlen, Dwarf_Ptr  * block_ptr, Dwarf_Error * error)



{
    Dwarf_Debug dbg = 0;
    Dwarf_CU_Context cu_context = 0;

    int res  = get_attr_dbg(&dbg,&cu_context,attr,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    if (attr->ar_attribute_form == DW_FORM_exprloc ) {
        Dwarf_Die die = 0;
        Dwarf_Unsigned leb_len = 0;
        Dwarf_Byte_Ptr section_start = 0;
        Dwarf_Unsigned section_len = 0;
        Dwarf_Byte_Ptr section_end = 0;
        Dwarf_Byte_Ptr info_ptr = 0;
        Dwarf_Unsigned exprlen = 0;
        Dwarf_Small * addr = attr->ar_debug_ptr;

        info_ptr = addr;
        section_start = _dwarf_calculate_info_section_start_ptr(cu_context, &section_len);

        section_end = section_start + section_len;

        DECODE_LEB128_UWORD_LEN_CK(info_ptr, exprlen, leb_len, dbg,error,section_end);
        if (exprlen > section_len) {
            
            dwarfstring m;

            dwarfstring_constructor(&m);
            dwarfstring_append_printf_u(&m, "DW_DLE_ATTR_OUTSIDE_SECTION: " "The expression length is %u,",exprlen);

            dwarfstring_append_printf_u(&m, " but the section length is just %u. " "Corrupt Dwarf.",section_len);

            _dwarf_error_string(dbg, error, DW_DLE_ATTR_OUTSIDE_SECTION, dwarfstring_string(&m));

            dwarfstring_destructor(&m);
            return DW_DLV_ERROR;
        }
        die = attr->ar_die;
        
        if (_dwarf_reference_outside_section(die, (Dwarf_Small *)addr, ((Dwarf_Small *)addr)+exprlen +leb_len)) {

            dwarfstring m;

            dwarfstring_constructor(&m);
            dwarfstring_append_printf_u(&m, "DW_DLE_ATTR_OUTSIDE_SECTION: " "The expression length %u,",exprlen);

            dwarfstring_append_printf_u(&m, " plus the leb value length of " "%u ",leb_len);

            dwarfstring_append(&m, " runs past the end of the section. " "Corrupt Dwarf.");

            _dwarf_error_string(dbg, error, DW_DLE_ATTR_OUTSIDE_SECTION, dwarfstring_string(&m));

            dwarfstring_destructor(&m);
            return DW_DLV_ERROR;
        }
        *return_exprlen = exprlen;
        *block_ptr = addr + leb_len;
        return DW_DLV_OK;

    }
    {
        dwarfstring m;
        const char *name = "<name not known>";
        unsigned  mform = attr->ar_attribute_form;

        dwarfstring_constructor(&m);

        dwarf_get_FORM_name (mform,&name);
        dwarfstring_append_printf_u(&m, "DW_DLE_ATTR_EXPRLOC_FORM_BAD: " "The form is 0x%x ", mform);

        dwarfstring_append_printf_s(&m, "(%s) but should be DW_FORM_exprloc. " "Corrupt Dwarf.",(char *)name);

        _dwarf_error_string(dbg, error, DW_DLE_ATTR_EXPRLOC_FORM_BAD, dwarfstring_string(&m));
        dwarfstring_destructor(&m);
    }
    return DW_DLV_ERROR;
}
