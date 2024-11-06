















static void flash_lock(void)
{
    FLASH->CR |= (1U<<31);
}

static void flash_unlock(void)
{
    if (FLASH->CR & FLASH_CR_LOCK)
    {
        FLASH->KEYR = 0x45670123;
        FLASH->KEYR = 0xCDEF89AB;
    }
}


void flash_option_bytes_init(int boot_from_dfu)
{
    uint32_t val = 0xfffff8aa;

    if (boot_from_dfu){
        val &= ~(1<<27); 
    }
    else {
        if (solo_is_locked())
        {
            val = 0xfffff8cc;
        }
    }

    val &= ~(1<<26); 
    val &= ~(1<<25); 
    val &= ~(1<<24); 

    if (FLASH->OPTR == val)
    {
        return;
    }

    __disable_irq();
    while (FLASH->SR & (1<<16))
        ;
    flash_unlock();
    if (FLASH->CR & (1<<30))
    {
        FLASH->OPTKEYR = 0x08192A3B;
        FLASH->OPTKEYR = 0x4C5D6E7F;
    }

    FLASH->OPTR =val;
    FLASH->CR |= (1<<17);

    while (FLASH->SR & (1<<16))
        ;

    flash_lock();

    __enable_irq();
}

void flash_erase_page(uint8_t page)
{
    __disable_irq();

    
    while (FLASH->SR & (1<<16))
        ;
    flash_unlock();

    FLASH->SR = FLASH->SR;

    
    FLASH->CR &= ~((0xff<<3) | 7);
    FLASH->CR |= (page<<3) | (1<<1);

    
    FLASH->CR |= (1<<16);
    while (FLASH->SR & (1<<16))
        ;

    if(FLASH->SR & (1<<1))
    {
        printf2(TAG_ERR,"erase NOT successful %lx\r\n", FLASH->SR);
    }

    FLASH->CR &= ~(0x7);
    __enable_irq();
}

void flash_write_dword(uint32_t addr, uint64_t data)
{
    __disable_irq();
    while (FLASH->SR & (1<<16))
        ;
    FLASH->SR = FLASH->SR;

    
    FLASH->CR |= (1<<0);

    *(volatile uint32_t*)addr = data;
    *(volatile uint32_t*)(addr+4) = data>>32;

    while (FLASH->SR & (1<<16))
        ;

    if(FLASH->SR & (1<<1))
    {
        printf2(TAG_ERR,"program NOT successful %lx\r\n", FLASH->SR);
    }

    FLASH->SR = (1<<0);
    FLASH->CR &= ~(1<<0);
    __enable_irq();
}

void flash_write(uint32_t addr, uint8_t * data, size_t sz)
{
    unsigned int i;
    uint8_t buf[8];
    while (FLASH->SR & (1<<16))
        ;
    flash_unlock();

    
    addr &= ~(0x07);

    for(i = 0; i < sz; i+=8)
    {
        memmove(buf, data + i, (sz - i) > 8 ? 8 : sz - i);
        if (sz - i < 8)
        {
            memset(buf + sz - i, 0xff, 8 - (sz - i));
        }
        flash_write_dword(addr, *(uint64_t*)buf);
        addr += 8;
    }

}


void flash_write_fast(uint32_t addr, uint32_t * data)
{
    __disable_irq();
    while (FLASH->SR & (1<<16))
        ;
    FLASH->SR = FLASH->SR;

    
    FLASH->CR |= (1<<18);

    int i;
    for(i = 0; i < 64; i++)
    {
        *(volatile uint32_t*)addr = (*data);
        addr+=4;
        data++;
    }

    while (FLASH->SR & (1<<16))
        ;

    if(FLASH->SR & (1<<1))
    {
        printf2(TAG_ERR,"program NOT successful %lx\r\n", FLASH->SR);
    }

    FLASH->SR = (1<<0);
    FLASH->CR &= ~(1<<18);
    __enable_irq();

}
