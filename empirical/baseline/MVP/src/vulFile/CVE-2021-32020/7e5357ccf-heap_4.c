













    #error This file must not be used if configSUPPORT_DYNAMIC_ALLOCATION is 0












    extern uint8_t ucHeap[ configTOTAL_HEAP_SIZE ];

    PRIVILEGED_DATA static uint8_t ucHeap[ configTOTAL_HEAP_SIZE ];



typedef struct A_BLOCK_LINK {
    struct A_BLOCK_LINK * pxNextFreeBlock; 
    size_t xBlockSize;                     
} BlockLink_t;




static void prvInsertBlockIntoFreeList( BlockLink_t * pxBlockToInsert ) PRIVILEGED_FUNCTION;


static void prvHeapInit( void ) PRIVILEGED_FUNCTION;




static const size_t xHeapStructSize = ( sizeof( BlockLink_t ) + ( ( size_t ) ( portBYTE_ALIGNMENT - 1 ) ) ) & ~( ( size_t ) portBYTE_ALIGNMENT_MASK );


PRIVILEGED_DATA static BlockLink_t xStart, * pxEnd = NULL;


PRIVILEGED_DATA static size_t xFreeBytesRemaining = 0U;
PRIVILEGED_DATA static size_t xMinimumEverFreeBytesRemaining = 0U;
PRIVILEGED_DATA static size_t xNumberOfSuccessfulAllocations = 0;
PRIVILEGED_DATA static size_t xNumberOfSuccessfulFrees = 0;


PRIVILEGED_DATA static size_t xBlockAllocatedBit = 0;



void * pvPortMalloc( size_t xWantedSize )
{
    BlockLink_t * pxBlock, * pxPreviousBlock, * pxNewBlockLink;
    void * pvReturn = NULL;

    vTaskSuspendAll();
    {
        
        if( pxEnd == NULL )
        {
            prvHeapInit();
        }
        else {
            mtCOVERAGE_TEST_MARKER();
        }

        
        if( ( xWantedSize & xBlockAllocatedBit ) == 0 )
        {
            
            if( xWantedSize > 0 )
            {
                xWantedSize += xHeapStructSize;

                
                if( ( xWantedSize & portBYTE_ALIGNMENT_MASK ) != 0x00 )
                {
                    
                    xWantedSize += ( portBYTE_ALIGNMENT - ( xWantedSize & portBYTE_ALIGNMENT_MASK ) );
                    configASSERT( ( xWantedSize & portBYTE_ALIGNMENT_MASK ) == 0 );
                }
                else {
                    mtCOVERAGE_TEST_MARKER();
                }
            }
            else {
                mtCOVERAGE_TEST_MARKER();
            }

            if( ( xWantedSize > 0 ) && ( xWantedSize <= xFreeBytesRemaining ) )
            {
                
                pxPreviousBlock = &xStart;
                pxBlock = xStart.pxNextFreeBlock;

                while( ( pxBlock->xBlockSize < xWantedSize ) && ( pxBlock->pxNextFreeBlock != NULL ) )
                {
                    pxPreviousBlock = pxBlock;
                    pxBlock = pxBlock->pxNextFreeBlock;
                }

                
                if( pxBlock != pxEnd )
                {
                    
                    pvReturn = ( void * ) ( ( ( uint8_t * ) pxPreviousBlock->pxNextFreeBlock ) + xHeapStructSize );

                    
                    pxPreviousBlock->pxNextFreeBlock = pxBlock->pxNextFreeBlock;

                    
                    if( ( pxBlock->xBlockSize - xWantedSize ) > heapMINIMUM_BLOCK_SIZE )
                    {
                        
                        pxNewBlockLink = ( void * ) ( ( ( uint8_t * ) pxBlock ) + xWantedSize );
                        configASSERT( ( ( ( size_t ) pxNewBlockLink ) & portBYTE_ALIGNMENT_MASK ) == 0 );

                        
                        pxNewBlockLink->xBlockSize = pxBlock->xBlockSize - xWantedSize;
                        pxBlock->xBlockSize = xWantedSize;

                        
                        prvInsertBlockIntoFreeList( pxNewBlockLink );
                    }
                    else {
                        mtCOVERAGE_TEST_MARKER();
                    }

                    xFreeBytesRemaining -= pxBlock->xBlockSize;

                    if( xFreeBytesRemaining < xMinimumEverFreeBytesRemaining )
                    {
                        xMinimumEverFreeBytesRemaining = xFreeBytesRemaining;
                    }
                    else {
                        mtCOVERAGE_TEST_MARKER();
                    }

                    
                    pxBlock->xBlockSize |= xBlockAllocatedBit;
                    pxBlock->pxNextFreeBlock = NULL;
                    xNumberOfSuccessfulAllocations++;
                }
                else {
                    mtCOVERAGE_TEST_MARKER();
                }
            }
            else {
                mtCOVERAGE_TEST_MARKER();
            }
        }
        else {
            mtCOVERAGE_TEST_MARKER();
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
            else {
                mtCOVERAGE_TEST_MARKER();
            }
        }
    #endif 

    configASSERT( ( ( ( size_t ) pvReturn ) & ( size_t ) portBYTE_ALIGNMENT_MASK ) == 0 );
    return pvReturn;
}


void vPortFree( void * pv )
{
    uint8_t * puc = ( uint8_t * ) pv;
    BlockLink_t * pxLink;

    if( pv != NULL )
    {
        
        puc -= xHeapStructSize;

        
        pxLink = ( void * ) puc;

        
        configASSERT( ( pxLink->xBlockSize & xBlockAllocatedBit ) != 0 );
        configASSERT( pxLink->pxNextFreeBlock == NULL );

        if( ( pxLink->xBlockSize & xBlockAllocatedBit ) != 0 )
        {
            if( pxLink->pxNextFreeBlock == NULL )
            {
                
                pxLink->xBlockSize &= ~xBlockAllocatedBit;

                vTaskSuspendAll();
                {
                    
                    xFreeBytesRemaining += pxLink->xBlockSize;
                    traceFREE( pv, pxLink->xBlockSize );
                    prvInsertBlockIntoFreeList( ( ( BlockLink_t * ) pxLink ) );
                    xNumberOfSuccessfulFrees++;
                }
                ( void ) xTaskResumeAll();
            }
            else {
                mtCOVERAGE_TEST_MARKER();
            }
        }
        else {
            mtCOVERAGE_TEST_MARKER();
        }
    }
}


size_t xPortGetFreeHeapSize( void )
{
    return xFreeBytesRemaining;
}


size_t xPortGetMinimumEverFreeHeapSize( void )
{
    return xMinimumEverFreeBytesRemaining;
}


void vPortInitialiseBlocks( void )
{
    
}


static void prvHeapInit( void ) 
{
    BlockLink_t * pxFirstFreeBlock;
    uint8_t * pucAlignedHeap;
    size_t uxAddress;
    size_t xTotalHeapSize = configTOTAL_HEAP_SIZE;

    
    uxAddress = ( size_t ) ucHeap;

    if( ( uxAddress & portBYTE_ALIGNMENT_MASK ) != 0 )
    {
        uxAddress += ( portBYTE_ALIGNMENT - 1 );
        uxAddress &= ~( ( size_t ) portBYTE_ALIGNMENT_MASK );
        xTotalHeapSize -= uxAddress - ( size_t ) ucHeap;
    }

    pucAlignedHeap = ( uint8_t * ) uxAddress;

    
    xStart.pxNextFreeBlock = ( void * ) pucAlignedHeap;
    xStart.xBlockSize = ( size_t ) 0;

    
    uxAddress = ( ( size_t ) pucAlignedHeap ) + xTotalHeapSize;
    uxAddress -= xHeapStructSize;
    uxAddress &= ~( ( size_t ) portBYTE_ALIGNMENT_MASK );
    pxEnd = ( void * ) uxAddress;
    pxEnd->xBlockSize = 0;
    pxEnd->pxNextFreeBlock = NULL;

    
    pxFirstFreeBlock = ( void * ) pucAlignedHeap;
    pxFirstFreeBlock->xBlockSize = uxAddress - ( size_t ) pxFirstFreeBlock;
    pxFirstFreeBlock->pxNextFreeBlock = pxEnd;

    
    xMinimumEverFreeBytesRemaining = pxFirstFreeBlock->xBlockSize;
    xFreeBytesRemaining = pxFirstFreeBlock->xBlockSize;

    
    xBlockAllocatedBit = ( ( size_t ) 1 ) << ( ( sizeof( size_t ) * heapBITS_PER_BYTE ) - 1 );
}


static void prvInsertBlockIntoFreeList( BlockLink_t * pxBlockToInsert ) 
{
    BlockLink_t * pxIterator;
    uint8_t * puc;

    
    for( pxIterator = &xStart; pxIterator->pxNextFreeBlock < pxBlockToInsert; pxIterator = pxIterator->pxNextFreeBlock )
    {
        
    }

    
    puc = ( uint8_t * ) pxIterator;

    if( ( puc + pxIterator->xBlockSize ) == ( uint8_t * ) pxBlockToInsert )
    {
        pxIterator->xBlockSize += pxBlockToInsert->xBlockSize;
        pxBlockToInsert = pxIterator;
    }
    else {
        mtCOVERAGE_TEST_MARKER();
    }

    
    puc = ( uint8_t * ) pxBlockToInsert;

    if( ( puc + pxBlockToInsert->xBlockSize ) == ( uint8_t * ) pxIterator->pxNextFreeBlock )
    {
        if( pxIterator->pxNextFreeBlock != pxEnd )
        {
            
            pxBlockToInsert->xBlockSize += pxIterator->pxNextFreeBlock->xBlockSize;
            pxBlockToInsert->pxNextFreeBlock = pxIterator->pxNextFreeBlock->pxNextFreeBlock;
        }
        else {
            pxBlockToInsert->pxNextFreeBlock = pxEnd;
        }
    }
    else {
        pxBlockToInsert->pxNextFreeBlock = pxIterator->pxNextFreeBlock;
    }

    
    if( pxIterator != pxBlockToInsert )
    {
        pxIterator->pxNextFreeBlock = pxBlockToInsert;
    }
    else {
        mtCOVERAGE_TEST_MARKER();
    }
}


void vPortGetHeapStats( HeapStats_t * pxHeapStats )
{
    BlockLink_t * pxBlock;
    size_t xBlocks = 0, xMaxSize = 0, xMinSize = portMAX_DELAY; 

    vTaskSuspendAll();
    {
        pxBlock = xStart.pxNextFreeBlock;

        
        if( pxBlock != NULL )
        {
            do {
                
                xBlocks++;

                if( pxBlock->xBlockSize > xMaxSize )
                {
                    xMaxSize = pxBlock->xBlockSize;
                }

                if( pxBlock->xBlockSize < xMinSize )
                {
                    xMinSize = pxBlock->xBlockSize;
                }

                
                pxBlock = pxBlock->pxNextFreeBlock;
            } while( pxBlock != pxEnd );
        }
    }
    ( void ) xTaskResumeAll();

    pxHeapStats->xSizeOfLargestFreeBlockInBytes = xMaxSize;
    pxHeapStats->xSizeOfSmallestFreeBlockInBytes = xMinSize;
    pxHeapStats->xNumberOfFreeBlocks = xBlocks;

    taskENTER_CRITICAL();
    {
        pxHeapStats->xAvailableHeapSpaceInBytes = xFreeBytesRemaining;
        pxHeapStats->xNumberOfSuccessfulAllocations = xNumberOfSuccessfulAllocations;
        pxHeapStats->xNumberOfSuccessfulFrees = xNumberOfSuccessfulFrees;
        pxHeapStats->xMinimumEverFreeBytesRemaining = xMinimumEverFreeBytesRemaining;
    }
    taskEXIT_CRITICAL();
}
