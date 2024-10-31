













    #error This file must not be used if configSUPPORT_DYNAMIC_ALLOCATION is 0






static void prvHeapInit( void );





    extern uint8_t ucHeap[ configTOTAL_HEAP_SIZE ];

    static uint8_t ucHeap[ configTOTAL_HEAP_SIZE ];




typedef struct A_BLOCK_LINK {
    struct A_BLOCK_LINK * pxNextFreeBlock; 
    size_t xBlockSize;                     
} BlockLink_t;


static const uint16_t heapSTRUCT_SIZE = ( ( sizeof( BlockLink_t ) + ( portBYTE_ALIGNMENT - 1 ) ) & ~portBYTE_ALIGNMENT_MASK );



static BlockLink_t xStart, xEnd;


static size_t xFreeBytesRemaining = configADJUSTED_HEAP_SIZE;
























void * pvPortMalloc( size_t xWantedSize )
{
    BlockLink_t * pxBlock, * pxPreviousBlock, * pxNewBlockLink;
    static BaseType_t xHeapHasBeenInitialised = pdFALSE;
    void * pvReturn = NULL;

    vTaskSuspendAll();
    {
        
        if( xHeapHasBeenInitialised == pdFALSE )
        {
            prvHeapInit();
            xHeapHasBeenInitialised = pdTRUE;
        }

        
        if( xWantedSize > 0 )
        {
            xWantedSize += heapSTRUCT_SIZE;

            
            if( ( xWantedSize & portBYTE_ALIGNMENT_MASK ) != 0 )
            {
                
                xWantedSize += ( portBYTE_ALIGNMENT - ( xWantedSize & portBYTE_ALIGNMENT_MASK ) );
            }
        }

        if( ( xWantedSize > 0 ) && ( xWantedSize < configADJUSTED_HEAP_SIZE ) )
        {
            
            pxPreviousBlock = &xStart;
            pxBlock = xStart.pxNextFreeBlock;

            while( ( pxBlock->xBlockSize < xWantedSize ) && ( pxBlock->pxNextFreeBlock != NULL ) )
            {
                pxPreviousBlock = pxBlock;
                pxBlock = pxBlock->pxNextFreeBlock;
            }

            
            if( pxBlock != &xEnd )
            {
                
                pvReturn = ( void * ) ( ( ( uint8_t * ) pxPreviousBlock->pxNextFreeBlock ) + heapSTRUCT_SIZE );

                
                pxPreviousBlock->pxNextFreeBlock = pxBlock->pxNextFreeBlock;

                
                if( ( pxBlock->xBlockSize - xWantedSize ) > heapMINIMUM_BLOCK_SIZE )
                {
                    
                    pxNewBlockLink = ( void * ) ( ( ( uint8_t * ) pxBlock ) + xWantedSize );

                    
                    pxNewBlockLink->xBlockSize = pxBlock->xBlockSize - xWantedSize;
                    pxBlock->xBlockSize = xWantedSize;

                    
                    prvInsertBlockIntoFreeList( ( pxNewBlockLink ) );
                }

                xFreeBytesRemaining -= pxBlock->xBlockSize;
            }
        }

        traceMALLOC( pvReturn, xWantedSize );
    }
    ( void ) xTaskResumeAll();

    #if ( configUSE_MALLOC_FAILED_HOOK == 1 )
        {
            if( pvReturn == NULL )
            {
                extern void vApplicationMallocFailedHook( void );
                vApplicationMallocFailedHook();
            }
        }
    #endif

    return pvReturn;
}


void vPortFree( void * pv )
{
    uint8_t * puc = ( uint8_t * ) pv;
    BlockLink_t * pxLink;

    if( pv != NULL )
    {
        
        puc -= heapSTRUCT_SIZE;

        
        pxLink = ( void * ) puc;

        vTaskSuspendAll();
        {
            
            prvInsertBlockIntoFreeList( ( ( BlockLink_t * ) pxLink ) );
            xFreeBytesRemaining += pxLink->xBlockSize;
            traceFREE( pv, pxLink->xBlockSize );
        }
        ( void ) xTaskResumeAll();
    }
}


size_t xPortGetFreeHeapSize( void )
{
    return xFreeBytesRemaining;
}


void vPortInitialiseBlocks( void )
{
    
}


static void prvHeapInit( void )
{
    BlockLink_t * pxFirstFreeBlock;
    uint8_t * pucAlignedHeap;

    
    pucAlignedHeap = ( uint8_t * ) ( ( ( portPOINTER_SIZE_TYPE ) & ucHeap[ portBYTE_ALIGNMENT ] ) & ( ~( ( portPOINTER_SIZE_TYPE ) portBYTE_ALIGNMENT_MASK ) ) );

    
    xStart.pxNextFreeBlock = ( void * ) pucAlignedHeap;
    xStart.xBlockSize = ( size_t ) 0;

    
    xEnd.xBlockSize = configADJUSTED_HEAP_SIZE;
    xEnd.pxNextFreeBlock = NULL;

    
    pxFirstFreeBlock = ( void * ) pucAlignedHeap;
    pxFirstFreeBlock->xBlockSize = configADJUSTED_HEAP_SIZE;
    pxFirstFreeBlock->pxNextFreeBlock = &xEnd;
}

