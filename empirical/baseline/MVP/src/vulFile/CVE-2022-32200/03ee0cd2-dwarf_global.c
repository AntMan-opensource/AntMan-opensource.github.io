






















void _dwarf_fix_up_offset_irix(Dwarf_Debug dbg, Dwarf_Unsigned * varp, char *caller_site_name)

{

    Dwarf_Unsigned var = *varp;



    
    if ((var & UPPER33) == UPPER33) {
        var &= LOWER32;
        
        *varp = var;
    }


    return;
}


static void dealloc_globals_chain(Dwarf_Debug dbg, Dwarf_Chain head_chain)

{
    Dwarf_Chain curr_chain = 0;
    int chaintype = DW_DLA_CHAIN;
    Dwarf_Global_Context lastcontext = 0;
    Dwarf_Global_Context curcontext = 0;

    curr_chain = head_chain;
    for (; curr_chain; ) {
        Dwarf_Global item = 0;
        int itemtype = 0;
        Dwarf_Chain prev = 0;

        item = (Dwarf_Global)curr_chain->ch_item;
        itemtype = curr_chain->ch_itemtype;
        curcontext = item->gl_context;
        if (curcontext && curcontext != lastcontext) {
            
            lastcontext = curcontext;
            dwarf_dealloc(dbg,curcontext,curcontext->pu_alloc_type);
        }
        prev = curr_chain;
        dwarf_dealloc(dbg, item,itemtype);
        prev->ch_item = 0;
        curr_chain = curr_chain->ch_next;
        dwarf_dealloc(dbg, prev, chaintype);
    }
}

int dwarf_get_globals(Dwarf_Debug dbg, Dwarf_Global ** globals, Dwarf_Signed * return_count, Dwarf_Error * error)


{
    int res = 0;

    if (!dbg || dbg->de_magic != DBG_IS_VALID) {
        _dwarf_error_string(NULL, error, DW_DLE_DBG_NULL, "DW_DLE_DBG_NULL: " "calling dwarf_get_globals " "Dwarf_Debug either null or it is" "a stale Dwarf_Debug pointer");



        return DW_DLV_ERROR;
    }
    res = _dwarf_load_section(dbg, &dbg->de_debug_pubnames,error);
    if (res != DW_DLV_OK) {
        return res;
    }
    if (!dbg->de_debug_pubnames.dss_size) {
        return DW_DLV_NO_ENTRY;
    }

    res = _dwarf_internal_get_pubnames_like_data(dbg, ".debug_pubnames", dbg->de_debug_pubnames.dss_data, dbg->de_debug_pubnames.dss_size, globals, return_count, error, DW_DLA_GLOBAL_CONTEXT, DW_DLA_GLOBAL, DW_DLE_PUBNAMES_LENGTH_BAD, DW_DLE_PUBNAMES_VERSION_ERROR);









    return res;

}



void dwarf_globals_dealloc(Dwarf_Debug dbg, Dwarf_Global * dwgl, Dwarf_Signed count)

{
    _dwarf_internal_globals_dealloc(dbg, dwgl, count);
    return;
}

void _dwarf_internal_globals_dealloc(Dwarf_Debug dbg, Dwarf_Global * dwgl, Dwarf_Signed count)


{
    Dwarf_Signed i = 0;
    struct Dwarf_Global_Context_s *glcp = 0;
    struct Dwarf_Global_Context_s *lastglcp = 0;

    if (!dwgl) {
        return;
    }
    for (i = 0; i < count; i++) {
        Dwarf_Global dgd = dwgl[i];

        if (!dgd) {
            continue;
        }
        
        glcp = dgd->gl_context;
        if (glcp && lastglcp != glcp) {
            lastglcp = glcp;
            dwarf_dealloc(dbg, glcp, glcp->pu_alloc_type);
        }
        dwarf_dealloc(dbg, dgd, dgd->gl_alloc_type);
    }
    dwarf_dealloc(dbg, dwgl, DW_DLA_LIST);
    return;
}
static void pubnames_error_length(Dwarf_Debug dbg, Dwarf_Error *error, Dwarf_Unsigned spaceneeded, const char *secname, const char *specificloc)




{
    dwarfstring m;

    dwarfstring_constructor(&m);
    dwarfstring_append(&m,"DW_DLE_PUBNAMES_LENGTH_BAD: " " In section ");
    dwarfstring_append(&m,(char *)secname);
    dwarfstring_append_printf_u(&m, " %u bytes of space needed " "but the section is out of space ", spaceneeded);


    dwarfstring_append(&m, "reading ");
    dwarfstring_append(&m, (char *)specificloc);
    dwarfstring_append(&m, ".");
    _dwarf_error_string(dbg,error,DW_DLE_PUBNAMES_LENGTH_BAD, dwarfstring_string(&m));
    dwarfstring_destructor(&m);
}


static int _dwarf_make_global_add_to_chain(Dwarf_Debug dbg, Dwarf_Unsigned       global_DLA_code, Dwarf_Global_Context pubnames_context, Dwarf_Off            die_offset_in_cu, unsigned char   *    glname, Dwarf_Unsigned      *global_count, Dwarf_Bool          *pubnames_context_on_list, Dwarf_Chain         **plast_chain, Dwarf_Error         *error)








{
    Dwarf_Chain  curr_chain = 0;
    Dwarf_Global global = 0;

    global = (Dwarf_Global)
        _dwarf_get_alloc(dbg, global_DLA_code, 1);
    if (!global) {
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    (*global_count)++;
    
    global->gl_context = pubnames_context;
    global->gl_alloc_type = global_DLA_code;
    global->gl_named_die_offset_within_cu = die_offset_in_cu;
    global->gl_name = glname;
    
    curr_chain = (Dwarf_Chain) _dwarf_get_alloc(dbg, DW_DLA_CHAIN, 1);
    if (!curr_chain) {
        dwarf_dealloc(dbg,global,global_DLA_code);
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }
    
    curr_chain->ch_item = (Dwarf_Global) global;
    curr_chain->ch_itemtype = global_DLA_code;
    (**plast_chain) = curr_chain;
    *plast_chain = &(curr_chain->ch_next);
    *pubnames_context_on_list = TRUE;
    return DW_DLV_OK;
}


int _dwarf_internal_get_pubnames_like_data(Dwarf_Debug dbg, const char *secname, Dwarf_Small * section_data_ptr, Dwarf_Unsigned section_length, Dwarf_Global ** globals, Dwarf_Signed * return_count, Dwarf_Error * error, int context_DLA_code, int global_DLA_code, int length_err_num, int version_err_num)










{
    Dwarf_Small *pubnames_like_ptr = 0;
    Dwarf_Off pubnames_section_offset = 0;
    Dwarf_Small *section_end_ptr = section_data_ptr +section_length;

    
    Dwarf_Global_Context pubnames_context = 0;
    Dwarf_Bool           pubnames_context_on_list = FALSE;

    Dwarf_Unsigned version = 0;

    
    Dwarf_Off die_offset_in_cu = 0;

    Dwarf_Unsigned global_count = 0;

    
    Dwarf_Chain head_chain = 0;
    Dwarf_Chain *plast_chain = &head_chain;

    
    Dwarf_Global *ret_globals = 0;
    int mres = 0;

    
    Dwarf_Unsigned i = 0;

    if (!dbg || dbg->de_magic != DBG_IS_VALID) {
        _dwarf_error_string(NULL, error, DW_DLE_DBG_NULL, "DW_DLE_DBG_NULL: " "calling for pubnames-like data Dwarf_Debug " "either null or it contains" "a stale Dwarf_Debug pointer");



        return DW_DLV_ERROR;
    }
    
    if (!dbg->de_debug_info.dss_data) {
        int res = _dwarf_load_debug_info(dbg, error);

        if (res != DW_DLV_OK) {
            return res;
        }
    }
    if (section_data_ptr == NULL) {
        return DW_DLV_NO_ENTRY;
    }
    pubnames_like_ptr = section_data_ptr;
    do {
        Dwarf_Unsigned length = 0;
        int local_extension_size = 0;
        int local_length_size = 0;

        
        Dwarf_Small *pubnames_ptr_past_end_cu = 0;

        pubnames_context_on_list = FALSE;
        pubnames_context = (Dwarf_Global_Context)
            _dwarf_get_alloc(dbg, context_DLA_code, 1);
        if (pubnames_context == NULL) {
            dealloc_globals_chain(dbg,head_chain);
            _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
            return DW_DLV_ERROR;
        }
        
        
        if ((pubnames_like_ptr + DWARF_32BIT_SIZE + DWARF_HALF_SIZE + DWARF_32BIT_SIZE) >  section_end_ptr) {


            pubnames_error_length(dbg,error, DWARF_32BIT_SIZE + DWARF_HALF_SIZE + DWARF_32BIT_SIZE, secname, "header-record");


            dealloc_globals_chain(dbg,head_chain);
            if (!pubnames_context_on_list) {
                dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            }
            return DW_DLV_ERROR;
        }
        mres = _dwarf_read_area_length_ck_wrapper(dbg, &length,&pubnames_like_ptr,&local_length_size, &local_extension_size,section_length,section_end_ptr, error);


        if (mres != DW_DLV_OK) {
            dealloc_globals_chain(dbg,head_chain);
            if (!pubnames_context_on_list) {
                dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            }
            return mres;
        }
        pubnames_context->pu_alloc_type = context_DLA_code;
        pubnames_context->pu_length_size = local_length_size;
        pubnames_context->pu_length = length;
        pubnames_context->pu_extension_size = local_extension_size;
        pubnames_context->pu_dbg = dbg;
        pubnames_context->pu_pub_offset = pubnames_section_offset;
        pubnames_ptr_past_end_cu = pubnames_like_ptr + length;
        pubnames_context->pu_pub_entries_end_ptr = pubnames_ptr_past_end_cu;

        if ((pubnames_like_ptr + (DWARF_HALF_SIZE) ) >  section_end_ptr) {

            pubnames_error_length(dbg,error, DWARF_HALF_SIZE, secname,"version-number");

            dealloc_globals_chain(dbg,head_chain);
            if (!pubnames_context_on_list) {
                dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            }
            return DW_DLV_ERROR;
        }
        mres = _dwarf_read_unaligned_ck_wrapper(dbg, &version,pubnames_like_ptr,DWARF_HALF_SIZE, section_end_ptr,error);

        if (mres != DW_DLV_OK) {
            dealloc_globals_chain(dbg,head_chain);
            if (!pubnames_context_on_list) {
                dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            }
            return mres;
        }
        pubnames_context->pu_version = version;
        pubnames_like_ptr += DWARF_HALF_SIZE;
        
        if (version != DW_PUBNAMES_VERSION2) {
            dealloc_globals_chain(dbg,head_chain);
            if (!pubnames_context_on_list) {
                dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            }
            _dwarf_error(dbg, error, version_err_num);
            return DW_DLV_ERROR;
        }

        
        if ((pubnames_like_ptr + 3*pubnames_context->pu_length_size)> section_end_ptr) {
            pubnames_error_length(dbg,error, 3*pubnames_context->pu_length_size, secname, "header/DIE offsets");


            dealloc_globals_chain(dbg,head_chain);
            if (!pubnames_context_on_list) {
                dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            }
            return DW_DLV_ERROR;
        }
        mres = _dwarf_read_unaligned_ck_wrapper(dbg, &pubnames_context->pu_offset_of_cu_header, pubnames_like_ptr, pubnames_context->pu_length_size, section_end_ptr,error);



        if (mres != DW_DLV_OK) {
            dealloc_globals_chain(dbg,head_chain);
            if (!pubnames_context_on_list) {
                dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            }
            return mres;
        }

        pubnames_like_ptr += pubnames_context->pu_length_size;

        FIX_UP_OFFSET_IRIX_BUG(dbg, pubnames_context->pu_offset_of_cu_header, "pubnames cu header offset");

        mres = _dwarf_read_unaligned_ck_wrapper(dbg, &pubnames_context->pu_info_length, pubnames_like_ptr, pubnames_context->pu_length_size, section_end_ptr,error);



        if (mres != DW_DLV_OK) {
            dealloc_globals_chain(dbg,head_chain);
            if (!pubnames_context_on_list) {
                dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            }
            return mres;
        }
        pubnames_like_ptr += pubnames_context->pu_length_size;

        if (pubnames_like_ptr > (section_data_ptr + section_length)) {
            dealloc_globals_chain(dbg,head_chain);
            if (!pubnames_context_on_list) {
                dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            }
            _dwarf_error(dbg, error, length_err_num);
            return DW_DLV_ERROR;
        }

        
        
        mres = _dwarf_read_unaligned_ck_wrapper(dbg, &die_offset_in_cu, pubnames_like_ptr, pubnames_context->pu_length_size, pubnames_context->pu_pub_entries_end_ptr,error);



        if (mres != DW_DLV_OK) {
            dealloc_globals_chain(dbg,head_chain);
            if (!pubnames_context_on_list) {
                dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            }
            return mres;
        }
        pubnames_like_ptr += pubnames_context->pu_length_size;
        FIX_UP_OFFSET_IRIX_BUG(dbg, die_offset_in_cu, "offset of die in cu");
        if (pubnames_like_ptr > (section_data_ptr + section_length)) {
            dealloc_globals_chain(dbg,head_chain);
            if (!pubnames_context_on_list) {
                dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            }
            _dwarf_error(dbg, error, length_err_num);
            return DW_DLV_ERROR;
        }

        
        if (!die_offset_in_cu) {
            if (dbg->de_return_empty_pubnames) {
                int res = 0;

                
                res = _dwarf_make_global_add_to_chain(dbg, global_DLA_code, pubnames_context, die_offset_in_cu,  (unsigned char *)"", &global_count, &pubnames_context_on_list, &plast_chain, error);








                if (res != DW_DLV_OK) {
                    dealloc_globals_chain(dbg,head_chain);
                    if (!pubnames_context_on_list) {
                        dwarf_dealloc(dbg,pubnames_context, context_DLA_code);
                    }
                    return res;
                }
                
            } else {
                
                dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
                pubnames_context = 0;
                continue;
            }
        }
        while (die_offset_in_cu) {
            int res = 0;
            unsigned char *glname = 0;

            
            res = _dwarf_check_string_valid(dbg,section_data_ptr, pubnames_like_ptr, pubnames_context->pu_pub_entries_end_ptr, DW_DLE_STRING_OFF_END_PUBNAMES_LIKE,error);


            if (res != DW_DLV_OK) {
                dealloc_globals_chain(dbg,head_chain);
                if (!pubnames_context_on_list) {
                    dwarf_dealloc(dbg,pubnames_context, context_DLA_code);
                }
                return res;
            }
            glname = (unsigned char *)pubnames_like_ptr;
            pubnames_like_ptr = pubnames_like_ptr + strlen((char *) pubnames_like_ptr) + 1;
            
            res = _dwarf_make_global_add_to_chain(dbg, global_DLA_code, pubnames_context, die_offset_in_cu, glname, &global_count, &pubnames_context_on_list, &plast_chain, error);







            if (res != DW_DLV_OK) {
                dealloc_globals_chain(dbg,head_chain);
                if (!pubnames_context_on_list) {
                    dwarf_dealloc(dbg,pubnames_context, context_DLA_code);
                }
                return res;
            }
            
            
            if ((pubnames_like_ptr + pubnames_context->pu_length_size ) > section_end_ptr) {

                pubnames_error_length(dbg,error, 2*pubnames_context->pu_length_size, secname, "global record offset");


                dealloc_globals_chain(dbg,head_chain);
                if (!pubnames_context_on_list) {
                    dwarf_dealloc(dbg,pubnames_context, context_DLA_code);
                }
                return DW_DLV_ERROR;
            }
            
            mres = _dwarf_read_unaligned_ck_wrapper(dbg, &die_offset_in_cu, pubnames_like_ptr, pubnames_context->pu_length_size, pubnames_context->pu_pub_entries_end_ptr, error);




            if (mres != DW_DLV_OK) {
                if (!pubnames_context_on_list) {
                    dwarf_dealloc(dbg,pubnames_context, context_DLA_code);
                }
                dealloc_globals_chain(dbg,head_chain);
                return mres;
            }
            pubnames_like_ptr += pubnames_context->pu_length_size;
            FIX_UP_OFFSET_IRIX_BUG(dbg, die_offset_in_cu, "offset of next die in cu");
            if (pubnames_like_ptr > (section_data_ptr + section_length)) {
                if (!pubnames_context_on_list) {
                    dwarf_dealloc(dbg,pubnames_context, context_DLA_code);
                }
                dealloc_globals_chain(dbg,head_chain);
                _dwarf_error(dbg, error, length_err_num);
                return DW_DLV_ERROR;
            }
        }
        
        if (pubnames_like_ptr > pubnames_ptr_past_end_cu) {
            
            _dwarf_error(dbg, error, length_err_num);
            if (!pubnames_context_on_list) {
                dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
            }
            dealloc_globals_chain(dbg,head_chain);
            return DW_DLV_ERROR;
        }
        
        {
            Dwarf_Unsigned increment = pubnames_context->pu_length_size + pubnames_context->pu_length + pubnames_context->pu_extension_size;


            pubnames_section_offset += increment;
        }
        pubnames_like_ptr = pubnames_ptr_past_end_cu;
    } while (pubnames_like_ptr < section_end_ptr);

    
    ret_globals = (Dwarf_Global *)
        _dwarf_get_alloc(dbg, DW_DLA_LIST, global_count);
    if (ret_globals == NULL) {
        if (!pubnames_context_on_list) {
            dwarf_dealloc(dbg,pubnames_context,context_DLA_code);
        }
        dealloc_globals_chain(dbg,head_chain);
        _dwarf_error(dbg, error, DW_DLE_ALLOC_FAIL);
        return DW_DLV_ERROR;
    }

    
    {
        Dwarf_Chain curr_chain = 0;
        curr_chain = head_chain;
        for (i = 0; i < global_count; i++) {
            Dwarf_Chain prev = 0;

            *(ret_globals + i) = curr_chain->ch_item;
            prev = curr_chain;
            curr_chain = curr_chain->ch_next;
            prev->ch_item = 0; 
            dwarf_dealloc(dbg, prev, DW_DLA_CHAIN);
        }
    }
    *globals = ret_globals;
    *return_count = (Dwarf_Signed) global_count;
    return DW_DLV_OK;
}


int dwarf_globname(Dwarf_Global glob, char **ret_name, Dwarf_Error * error)


{
    if (glob == NULL) {
        _dwarf_error(NULL, error, DW_DLE_GLOBAL_NULL);
        return DW_DLV_ERROR;
    }

    *ret_name = (char *) (glob->gl_name);
    return DW_DLV_OK;
}


int dwarf_global_die_offset(Dwarf_Global global, Dwarf_Off * ret_off, Dwarf_Error * error)

{
    if (global == NULL) {
        _dwarf_error(NULL, error, DW_DLE_GLOBAL_NULL);
        return DW_DLV_ERROR;
    }

    if (global->gl_context == NULL) {
        _dwarf_error(NULL, error, DW_DLE_GLOBAL_CONTEXT_NULL);
        return DW_DLV_ERROR;
    }

    *ret_off = (global->gl_named_die_offset_within_cu + global->gl_context->pu_offset_of_cu_header);
    return DW_DLV_OK;
}


int dwarf_global_cu_offset(Dwarf_Global global, Dwarf_Off * cu_header_offset, Dwarf_Error * error)


{
    Dwarf_Global_Context con = 0;

    if (global == NULL) {
        _dwarf_error(NULL, error, DW_DLE_GLOBAL_NULL);
        return DW_DLV_ERROR;
    }
    con = global->gl_context;
    if (con == NULL) {
        _dwarf_error(NULL, error, DW_DLE_GLOBAL_CONTEXT_NULL);
        return DW_DLV_ERROR;
    }
    *cu_header_offset = con->pu_offset_of_cu_header;
    return DW_DLV_OK;
}

static void build_off_end_msg(Dwarf_Unsigned offval, Dwarf_Unsigned withincr, Dwarf_Unsigned secsize, dwarfstring *m)



{
    const char *msg = "past";
    if (offval < secsize){
        msg = "too near";
    }
    dwarfstring_append_printf_u(m,"DW_DLE_OFFSET_BAD: " "The CU header offset of %u in a pubnames-like entry ", withincr);

    dwarfstring_append_printf_s(m, "would put us %s the end of .debug_info. " "No room for a DIE there... " "Corrupt Dwarf.",(char *)msg);


    return;
}


int dwarf_global_name_offsets(Dwarf_Global global, char **ret_name, Dwarf_Off * die_offset, Dwarf_Off * cu_die_offset, Dwarf_Error * error)




{
    Dwarf_Global_Context con = 0;
    Dwarf_Debug dbg = 0;
    Dwarf_Off cuhdr_off = 0;

    if (global == NULL) {
        _dwarf_error(NULL, error, DW_DLE_GLOBAL_NULL);
        return DW_DLV_ERROR;
    }

    con = global->gl_context;
    if (con == NULL) {
        _dwarf_error(NULL, error, DW_DLE_GLOBAL_CONTEXT_NULL);
        return DW_DLV_ERROR;
    }

    cuhdr_off = con->pu_offset_of_cu_header;
    

    dbg = con->pu_dbg;
    if (!dbg || dbg->de_magic != DBG_IS_VALID) {
        _dwarf_error_string(NULL, error, DW_DLE_DBG_NULL, "DW_DLE_DBG_NULL: Either null or it contains" "a stale Dwarf_Debug pointer");

        return DW_DLV_ERROR;
    }
    
    if (dbg->de_debug_info.dss_size && ((cuhdr_off + MIN_CU_HDR_SIZE) >= dbg->de_debug_info.dss_size)) {

        dwarfstring m;

        dwarfstring_constructor(&m);
        build_off_end_msg(cuhdr_off,cuhdr_off+MIN_CU_HDR_SIZE, dbg->de_debug_info.dss_size,&m);
        _dwarf_error_string(dbg, error, DW_DLE_OFFSET_BAD, dwarfstring_string(&m));
        dwarfstring_destructor(&m);
        return DW_DLV_ERROR;
    }

    
    if (die_offset) {
        if (global->gl_named_die_offset_within_cu) {
            *die_offset = global->gl_named_die_offset_within_cu + cuhdr_off;
        } else {
            *die_offset = 0;
        }
    }
    *ret_name = (char *) global->gl_name;
    if (cu_die_offset) {
        
        int cres = 0;
        Dwarf_Unsigned headerlen = 0;
        int res = _dwarf_load_debug_info(dbg, error);

        if (res != DW_DLV_OK) {
            return res;
        }
        
        
        if ((cuhdr_off + 10) >= dbg->de_debug_info.dss_size) {
            dwarfstring m;

            dwarfstring_constructor(&m);
            build_off_end_msg(cuhdr_off,cuhdr_off+10, dbg->de_debug_info.dss_size,&m);
            _dwarf_error_string(dbg, error, DW_DLE_OFFSET_BAD, dwarfstring_string(&m));
            dwarfstring_destructor(&m);
            return DW_DLV_ERROR;
        }
        cres = _dwarf_length_of_cu_header(dbg, cuhdr_off,true, &headerlen,error);
        if (cres != DW_DLV_OK) {
            return cres;
        }
        *cu_die_offset = cuhdr_off + headerlen;
    }
    return DW_DLV_OK;
}


int dwarf_get_globals_header(Dwarf_Global global, Dwarf_Off      *pub_section_hdr_offset, Dwarf_Unsigned *pub_offset_size, Dwarf_Unsigned *pub_cu_length, Dwarf_Unsigned *version, Dwarf_Off      *info_header_offset, Dwarf_Unsigned *info_length, Dwarf_Error*   error)







{
    Dwarf_Global_Context con = 0;
    Dwarf_Debug dbg = 0;

    if (global == NULL) {
        _dwarf_error(NULL, error, DW_DLE_GLOBAL_NULL);
        return DW_DLV_ERROR;
    }
    con = global->gl_context;
    if (con == NULL) {
        _dwarf_error(NULL, error, DW_DLE_GLOBAL_CONTEXT_NULL);
        return DW_DLV_ERROR;
    }
    dbg = con->pu_dbg;
    if (!dbg || dbg->de_magic != DBG_IS_VALID) {
        _dwarf_error_string(NULL, error, DW_DLE_DBG_NULL, "DW_DLE_DBG_NULL: " "calling dwarf_get_globals_header() " "either null or it contains" "a stale Dwarf_Debug pointer");



        return DW_DLV_ERROR;
    }
    if (pub_section_hdr_offset) {
        *pub_section_hdr_offset = con->pu_pub_offset;
    }
    if (pub_offset_size) {
        *pub_offset_size = con->pu_length_size;
    }
    if (pub_cu_length) {
        *pub_cu_length = con->pu_length;
    }
    if (version) {
        *version = con->pu_version;
    }
    if (info_header_offset) {
        *info_header_offset = con->pu_offset_of_cu_header;
    }
    if (info_length) {
        *info_length = con->pu_info_length;
    }
    return DW_DLV_OK;
}





int dwarf_get_cu_die_offset_given_cu_header_offset_b(Dwarf_Debug dbg, Dwarf_Off in_cu_header_offset, Dwarf_Bool is_info, Dwarf_Off * out_cu_die_offset, Dwarf_Error * error)




{
    Dwarf_Off headerlen = 0;
    int cres = 0;

    if (!dbg || dbg->de_magic != DBG_IS_VALID) {
        _dwarf_error_string(NULL, error, DW_DLE_DBG_NULL, "DW_DLE_DBG_NULL: " "calling dwarf_get_cu_die_offset_given" "cu_header_offset_b Dwarf_Debug is" "either null or it is" "a stale Dwarf_Debug pointer");




        return DW_DLV_ERROR;
    }
    cres = _dwarf_length_of_cu_header(dbg, in_cu_header_offset,is_info, &headerlen,error);
    if (cres != DW_DLV_OK) {
        return cres;
    }
    *out_cu_die_offset = in_cu_header_offset + headerlen;
    return DW_DLV_OK;
}

int dwarf_CU_dieoffset_given_die(Dwarf_Die die, Dwarf_Off*       return_offset, Dwarf_Error*     error)


{
    Dwarf_Off  dieoff = 0;
    Dwarf_CU_Context cucontext = 0;

    CHECK_DIE(die, DW_DLV_ERROR);
    cucontext = die->di_cu_context;
    dieoff =  cucontext->cc_debug_offset;
    
    dwarf_get_cu_die_offset_given_cu_header_offset_b( cucontext->cc_dbg, dieoff, die->di_is_info, return_offset,error);

    return DW_DLV_OK;
}

int dwarf_return_empty_pubnames(Dwarf_Debug dbg, int flag)
{
    if (dbg == NULL) {
        return DW_DLV_OK;
    }
    if (flag && flag != 1) {
        return DW_DLV_OK;
    }
    dbg->de_return_empty_pubnames = (unsigned char)flag;
    return DW_DLV_OK;
}
