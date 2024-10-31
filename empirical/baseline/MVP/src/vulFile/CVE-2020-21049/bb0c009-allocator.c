





















SIXELSTATUS sixel_allocator_new( sixel_allocator_t    **ppallocator, sixel_malloc_t        fn_malloc, sixel_calloc_t        fn_calloc, sixel_realloc_t       fn_realloc, sixel_free_t          fn_free)





{
    SIXELSTATUS status = SIXEL_FALSE;

    if (ppallocator == NULL) {
        sixel_helper_set_additional_message( "sixel_allocator_new: given argument ppallocator is null.");
        status = SIXEL_BAD_ARGUMENT;
        goto end;
    }

    if (fn_malloc == NULL) {
        fn_malloc = malloc;
    }

    if (fn_calloc == NULL) {
        fn_calloc = calloc;
    }

    if (fn_realloc == NULL) {
        fn_realloc = realloc;
    }

    if (fn_free == NULL) {
        fn_free = free;
    }

    *ppallocator = fn_malloc(sizeof(sixel_allocator_t));
    if (*ppallocator == NULL) {
        sixel_helper_set_additional_message( "sixel_allocator_new: fn_malloc() failed.");
        status = SIXEL_BAD_ALLOCATION;
        goto end;
    }

    (*ppallocator)->ref         = 1;
    (*ppallocator)->fn_malloc   = fn_malloc;
    (*ppallocator)->fn_calloc   = fn_calloc;
    (*ppallocator)->fn_realloc  = fn_realloc;
    (*ppallocator)->fn_free     = fn_free;

    status = SIXEL_OK;

end:
    return status;
}



static void sixel_allocator_destroy( sixel_allocator_t  *allocator)

{
    
    assert(allocator);
    assert(allocator->fn_free);

    allocator->fn_free(allocator);
}



SIXELAPI void sixel_allocator_ref( sixel_allocator_t  *allocator)

{
    
    assert(allocator);

    
    ++allocator->ref;
}



SIXELAPI void sixel_allocator_unref( sixel_allocator_t  *allocator)

{
    
    if (allocator) {
        assert(allocator->ref > 0);
        --allocator->ref;
        if (allocator->ref == 0) {
            sixel_allocator_destroy(allocator);
        }
    }
}



SIXELAPI void * sixel_allocator_malloc( sixel_allocator_t    *allocator, size_t               n)


{
    
    assert(allocator);
    assert(allocator->fn_malloc);

    if (n == 0) {
        sixel_helper_set_additional_message( "sixel_allocator_malloc: called with n == 0");
        return NULL;
    }
    return allocator->fn_malloc(n);
}



SIXELAPI void * sixel_allocator_calloc( sixel_allocator_t    *allocator, size_t               nelm, size_t               elsize)



{
    
    assert(allocator);
    assert(allocator->fn_calloc);

    return allocator->fn_calloc(nelm, elsize);
}



SIXELAPI void * sixel_allocator_realloc( sixel_allocator_t    *allocator, void                 *p, size_t               n)



{
    
    assert(allocator);
    assert(allocator->fn_realloc);

    return allocator->fn_realloc(p, n);
}



SIXELAPI void sixel_allocator_free( sixel_allocator_t    *allocator, void                 *p)


{
    
    assert(allocator);
    assert(allocator->fn_free);

    allocator->fn_free(p);
}



volatile int sixel_debug_malloc_counter;

void * sixel_bad_malloc(size_t size)
{
    return sixel_debug_malloc_counter-- == 0 ? NULL: malloc(size);
}


void * sixel_bad_calloc(size_t count, size_t size)
{
    (void) count;
    (void) size;

    return NULL;
}


void * sixel_bad_realloc(void *ptr, size_t size)
{
    (void) ptr;
    (void) size;

    return NULL;
}



int rpl_posix_memalign(void **memptr, size_t alignment, size_t size)
{

    return posix_memalign(memptr, alignment, size);

    *memptr = aligned_alloc(alignment, size);
    return *memptr ? 0: ENOMEM;

    *memptr = memalign(alignment, size);
    return *memptr ? 0: ENOMEM;

    return _aligned_malloc(size, alignment);



}




static int test1(void)
{
    int nret = EXIT_FAILURE;
    SIXELSTATUS status;
    sixel_allocator_t *allocator = NULL;

    status = sixel_allocator_new(NULL, malloc, calloc, realloc, free);
    if (status != SIXEL_BAD_ARGUMENT) {
        goto error;
    }

    status = sixel_allocator_new(&allocator, NULL, calloc, realloc, free);
    if (SIXEL_FAILED(status)) {
        goto error;
    }

    status = sixel_allocator_new(&allocator, malloc, NULL, realloc, free);
    if (SIXEL_FAILED(status)) {
        goto error;
    }

    status = sixel_allocator_new(&allocator, malloc, calloc, NULL, free);
    if (SIXEL_FAILED(status)) {
        goto error;
    }

    status = sixel_allocator_new(&allocator, malloc, calloc, realloc, NULL);
    if (SIXEL_FAILED(status)) {
        goto error;
    }

    nret = EXIT_SUCCESS;

error:
    return nret;
}


static int test2(void)
{
    int nret = EXIT_FAILURE;
    SIXELSTATUS status;
    sixel_allocator_t *allocator = NULL;

    sixel_debug_malloc_counter = 1;

    status = sixel_allocator_new(&allocator, sixel_bad_malloc, calloc, realloc, free);
    if (status == SIXEL_BAD_ALLOCATION) {
        goto error;
    }

    nret = EXIT_SUCCESS;

error:
    return nret;
}


SIXELAPI int sixel_allocator_tests_main(void)
{
    int nret = EXIT_FAILURE;
    size_t i;
    typedef int (* testcase)(void);

    static testcase const testcases[] = {
        test1, test2 };


    for (i = 0; i < sizeof(testcases) / sizeof(testcase); ++i) {
        nret = testcases[i]();
        if (nret != EXIT_SUCCESS) {
            goto error;
        }
    }

    nret = EXIT_SUCCESS;

error:
    return nret;
}










