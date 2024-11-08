







































typedef struct partition_list_item_ {
    esp_partition_t info;
    bool user_registered;
    SLIST_ENTRY(partition_list_item_) next;
} partition_list_item_t;

typedef struct esp_partition_iterator_opaque_ {
    esp_partition_type_t type;                  
    esp_partition_subtype_t subtype;               
    const char* label;                          
    partition_list_item_t* next_item;     
    esp_partition_t* info;                
} esp_partition_iterator_opaque_t;


static esp_partition_iterator_opaque_t* iterator_create(esp_partition_type_t type, esp_partition_subtype_t subtype, const char* label);
static esp_err_t load_partitions(void);
static esp_err_t ensure_partitions_loaded(void);


static const char* TAG = "partition";
static SLIST_HEAD(partition_list_head_, partition_list_item_) s_partition_list = SLIST_HEAD_INITIALIZER(s_partition_list);
static _lock_t s_partition_list_lock;


static esp_err_t ensure_partitions_loaded(void)
{
    esp_err_t err = ESP_OK;
    if (SLIST_EMPTY(&s_partition_list)) {
        
        _lock_acquire(&s_partition_list_lock);
        if (SLIST_EMPTY(&s_partition_list)) {
            ESP_LOGD(TAG, "Loading the partition table");
            err = load_partitions();
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "load_partitions returned 0x%x", err);
            }
        }
        _lock_release(&s_partition_list_lock);
    }
    return err;
}

esp_partition_iterator_t esp_partition_find(esp_partition_type_t type, esp_partition_subtype_t subtype, const char* label)
{
    if (ensure_partitions_loaded() != ESP_OK) {
        return NULL;
    }
    
    
    if (type == ESP_PARTITION_TYPE_ANY && subtype != ESP_PARTITION_SUBTYPE_ANY) {
        return NULL;
    }
    
    
    esp_partition_iterator_t it = iterator_create(type, subtype, label);
    
    it = esp_partition_next(it);
    
    return it;
}

esp_partition_iterator_t esp_partition_next(esp_partition_iterator_t it)
{
    assert(it);
    
    if (it->next_item == NULL) {
        esp_partition_iterator_release(it);
        return NULL;
    }
    _lock_acquire(&s_partition_list_lock);
    for (; it->next_item != NULL; it->next_item = SLIST_NEXT(it->next_item, next)) {
        esp_partition_t* p = &it->next_item->info;
        if (it->type != ESP_PARTITION_TYPE_ANY && it->type != p->type) {
            continue;
        }
        if (it->subtype != ESP_PARTITION_SUBTYPE_ANY && it->subtype != p->subtype) {
            continue;
        }
        if (it->label != NULL && strcmp(it->label, p->label) != 0) {
            continue;
        }
        
        break;
    }
    _lock_release(&s_partition_list_lock);
    if (it->next_item == NULL) {
        esp_partition_iterator_release(it);
        return NULL;
    }
    it->info = &it->next_item->info;
    it->next_item = SLIST_NEXT(it->next_item, next);
    return it;
}

const esp_partition_t* esp_partition_find_first(esp_partition_type_t type, esp_partition_subtype_t subtype, const char* label)
{
    esp_partition_iterator_t it = esp_partition_find(type, subtype, label);
    if (it == NULL) {
        return NULL;
    }
    const esp_partition_t* res = esp_partition_get(it);
    esp_partition_iterator_release(it);
    return res;
}

static esp_partition_iterator_opaque_t* iterator_create(esp_partition_type_t type, esp_partition_subtype_t subtype, const char* label)
{
    esp_partition_iterator_opaque_t* it = (esp_partition_iterator_opaque_t*) malloc(sizeof(esp_partition_iterator_opaque_t));
    it->type = type;
    it->subtype = subtype;
    it->label = label;
    it->next_item = SLIST_FIRST(&s_partition_list);
    it->info = NULL;
    return it;
}



static esp_err_t load_partitions(void)
{
    const uint32_t* ptr;
    spi_flash_mmap_handle_t handle;
    
    esp_err_t err = spi_flash_mmap(ESP_PARTITION_TABLE_OFFSET & 0xffff0000, SPI_FLASH_SEC_SIZE, SPI_FLASH_MMAP_DATA, (const void**) &ptr, &handle);
    if (err != ESP_OK) {
        return err;
    }
    
    const esp_partition_info_t* it = (const esp_partition_info_t*)
            (ptr + (ESP_PARTITION_TABLE_OFFSET & 0xffff) / sizeof(*ptr));
    const esp_partition_info_t* end = it + SPI_FLASH_SEC_SIZE / sizeof(*it);
    
    partition_list_item_t* last = NULL;
    for (; it != end; ++it) {
        if (it->magic != ESP_PARTITION_MAGIC) {
            break;
        }
        
        partition_list_item_t* item = (partition_list_item_t*) calloc(sizeof(partition_list_item_t), 1);
        if (item == NULL) {
            err = ESP_ERR_NO_MEM;
            break;
        }
        item->info.flash_chip = esp_flash_default_chip;
        item->info.address = it->pos.offset;
        item->info.size = it->pos.size;
        item->info.type = it->type;
        item->info.subtype = it->subtype;
        item->info.encrypted = it->flags & PART_FLAG_ENCRYPTED;
        item->user_registered = false;

        if (!esp_flash_encryption_enabled()) {
            
            item->info.encrypted = false;
        } else if (it->type == PART_TYPE_APP || (it->type == PART_TYPE_DATA && it->subtype == PART_SUBTYPE_DATA_OTA)
                || (it->type == PART_TYPE_DATA && it->subtype == PART_SUBTYPE_DATA_NVS_KEYS)) {
            
            item->info.encrypted = true;
        }

        
        strncpy(item->info.label, (const char*) it->label, sizeof(item->info.label) - 1);
        item->info.label[sizeof(it->label)] = 0;
        
        if (last == NULL) {
            SLIST_INSERT_HEAD(&s_partition_list, item, next);
        } else {
            SLIST_INSERT_AFTER(last, item, next);
        }
        last = item;
    }
    spi_flash_munmap(handle);
    return err;
}

void esp_partition_iterator_release(esp_partition_iterator_t iterator)
{
    
    free(iterator);
}

const esp_partition_t* esp_partition_get(esp_partition_iterator_t iterator)
{
    assert(iterator != NULL);
    return iterator->info;
}

esp_err_t esp_partition_register_external(esp_flash_t* flash_chip, size_t offset, size_t size, const char* label, esp_partition_type_t type, esp_partition_subtype_t subtype, const esp_partition_t** out_partition)

{
    if (out_partition != NULL) {
        *out_partition = NULL;
    }

    return ESP_ERR_NOT_SUPPORTED;


    if (offset + size > flash_chip->size) {
        return ESP_ERR_INVALID_SIZE;
    }

    esp_err_t err = ensure_partitions_loaded();
    if (err != ESP_OK) {
        return err;
    }

    partition_list_item_t* item = (partition_list_item_t*) calloc(sizeof(partition_list_item_t), 1);
    if (item == NULL) {
        return ESP_ERR_NO_MEM;
    }
    item->info.flash_chip = flash_chip;
    item->info.address = offset;
    item->info.size = size;
    item->info.type = type;
    item->info.subtype = subtype;
    item->info.encrypted = false;
    item->user_registered = true;
    strlcpy(item->info.label, label, sizeof(item->info.label));

    _lock_acquire(&s_partition_list_lock);
    partition_list_item_t *it, *last = NULL;
    SLIST_FOREACH(it, &s_partition_list, next) {
        
        if (it->info.flash_chip == flash_chip && bootloader_util_regions_overlap(offset, offset + size, it->info.address, it->info.address + it->info.size)) {

            _lock_release(&s_partition_list_lock);
            free(item);
            return ESP_ERR_INVALID_ARG;
        }
        last = it;
    }
    if (last == NULL) {
        SLIST_INSERT_HEAD(&s_partition_list, item, next);
    } else {
        SLIST_INSERT_AFTER(last, item, next);
    }
    _lock_release(&s_partition_list_lock);
    if (out_partition != NULL) {
        *out_partition = &item->info;
    }
    return ESP_OK;
}

esp_err_t esp_partition_deregister_external(const esp_partition_t* partition)
{
    esp_err_t result = ESP_ERR_NOT_FOUND;
    _lock_acquire(&s_partition_list_lock);
    partition_list_item_t *it;
    SLIST_FOREACH(it, &s_partition_list, next) {
        if (&it->info == partition) {
            if (!it->user_registered) {
                result = ESP_ERR_INVALID_ARG;
                break;
            }
            SLIST_REMOVE(&s_partition_list, it, partition_list_item_, next);
            free(it);
            result = ESP_OK;
            break;
        }
    }
    _lock_release(&s_partition_list_lock);
    return result;
}

const esp_partition_t *esp_partition_verify(const esp_partition_t *partition)
{
    assert(partition != NULL);
    const char *label = (strlen(partition->label) > 0) ? partition->label : NULL;
    esp_partition_iterator_t it = esp_partition_find(partition->type, partition->subtype, label);

    while (it != NULL) {
        const esp_partition_t *p = esp_partition_get(it);
        
        if (p->flash_chip == partition->flash_chip && p->address == partition->address && partition->size == p->size && partition->encrypted == p->encrypted) {


            esp_partition_iterator_release(it);
            return p;
        }
        it = esp_partition_next(it);
    }
    esp_partition_iterator_release(it);
    return NULL;
}

esp_err_t esp_partition_read(const esp_partition_t* partition, size_t src_offset, void* dst, size_t size)
{
    assert(partition != NULL);
    if (src_offset > partition->size) {
        return ESP_ERR_INVALID_ARG;
    }
    if (src_offset + size > partition->size) {
        return ESP_ERR_INVALID_SIZE;
    }

    if (!partition->encrypted) {

        return esp_flash_read(partition->flash_chip, dst, partition->address + src_offset, size);

        return spi_flash_read(partition->address + src_offset, dst, size);

    } else {

        if (partition->flash_chip != esp_flash_default_chip) {
            return ESP_ERR_NOT_SUPPORTED;
        }

        
        const void *buf;
        spi_flash_mmap_handle_t handle;
        esp_err_t err;

        err = esp_partition_mmap(partition, src_offset, size, SPI_FLASH_MMAP_DATA, &buf, &handle);
        if (err != ESP_OK) {
            return err;
        }
        memcpy(dst, buf, size);
        spi_flash_munmap(handle);
        return ESP_OK;

        return ESP_ERR_NOT_SUPPORTED;

    }
}

esp_err_t esp_partition_write(const esp_partition_t* partition, size_t dst_offset, const void* src, size_t size)
{
    assert(partition != NULL);
    if (dst_offset > partition->size) {
        return ESP_ERR_INVALID_ARG;
    }
    if (dst_offset + size > partition->size) {
        return ESP_ERR_INVALID_SIZE;
    }
    dst_offset = partition->address + dst_offset;
    if (!partition->encrypted) {

        return esp_flash_write(partition->flash_chip, src, dst_offset, size);

        return spi_flash_write(dst_offset, src, size);

    } else {

        if (partition->flash_chip != esp_flash_default_chip) {
            return ESP_ERR_NOT_SUPPORTED;
        }

        return esp_flash_write_encrypted(partition->flash_chip, dst_offset, src, size);

        return spi_flash_write_encrypted(dst_offset, src, size);


        return ESP_ERR_NOT_SUPPORTED;

    }
}

esp_err_t esp_partition_read_raw(const esp_partition_t* partition, size_t src_offset, void* dst, size_t size)
{
    assert(partition != NULL);
    if (src_offset > partition->size) {
        return ESP_ERR_INVALID_ARG;
    }
    if (src_offset + size > partition->size) {
        return ESP_ERR_INVALID_SIZE;
    }


    return esp_flash_read(partition->flash_chip, dst, partition->address + src_offset, size);

    return spi_flash_read(partition->address + src_offset, dst, size);

}

esp_err_t esp_partition_write_raw(const esp_partition_t* partition, size_t dst_offset, const void* src, size_t size)
{
    assert(partition != NULL);
    if (dst_offset > partition->size) {
        return ESP_ERR_INVALID_ARG;
    }
    if (dst_offset + size > partition->size) {
        return ESP_ERR_INVALID_SIZE;
    }
    dst_offset = partition->address + dst_offset;


    return esp_flash_write(partition->flash_chip, src, dst_offset, size);

    return spi_flash_write(dst_offset, src, size);

}

esp_err_t esp_partition_erase_range(const esp_partition_t* partition, size_t offset, size_t size)
{
    assert(partition != NULL);
    if (offset > partition->size) {
        return ESP_ERR_INVALID_ARG;
    }
    if (offset + size > partition->size) {
        return ESP_ERR_INVALID_SIZE;
    }
    if (size % SPI_FLASH_SEC_SIZE != 0) {
        return ESP_ERR_INVALID_SIZE;
    }
    if (offset % SPI_FLASH_SEC_SIZE != 0) {
        return ESP_ERR_INVALID_ARG;
    }

    return esp_flash_erase_region(partition->flash_chip, partition->address + offset, size);

    return spi_flash_erase_range(partition->address + offset, size);

}


esp_err_t esp_partition_mmap(const esp_partition_t* partition, size_t offset, size_t size, spi_flash_mmap_memory_t memory, const void** out_ptr, spi_flash_mmap_handle_t* out_handle)

{
    assert(partition != NULL);
    if (offset > partition->size) {
        return ESP_ERR_INVALID_ARG;
    }
    if (offset + size > partition->size) {
        return ESP_ERR_INVALID_SIZE;
    }
    if (partition->flash_chip != esp_flash_default_chip) {
        return ESP_ERR_NOT_SUPPORTED;
    }
    size_t phys_addr = partition->address + offset;
    
    size_t region_offset = phys_addr & 0xffff;
    size_t mmap_addr = phys_addr & 0xffff0000;
    esp_err_t rc = spi_flash_mmap(mmap_addr, size+region_offset, memory, out_ptr, out_handle);
    
    if (rc == ESP_OK) {
        *out_ptr = (void*) (((ptrdiff_t) *out_ptr) + region_offset);
    }
    return rc;
}

esp_err_t esp_partition_get_sha256(const esp_partition_t *partition, uint8_t *sha_256)
{
    return bootloader_common_get_sha256_of_partition(partition->address, partition->size, partition->type, sha_256);
}

bool esp_partition_check_identity(const esp_partition_t *partition_1, const esp_partition_t *partition_2)
{
    uint8_t sha_256[2][HASH_LEN] = { 0 };

    if (esp_partition_get_sha256(partition_1, sha_256[0]) == ESP_OK && esp_partition_get_sha256(partition_2, sha_256[1]) == ESP_OK) {

        if (memcmp(sha_256[0], sha_256[1], HASH_LEN) == 0) {
            
            return true;
        }
    }
    return false;
}

bool esp_partition_main_flash_region_safe(size_t addr, size_t size)
{
    bool result = true;
    if (addr <= ESP_PARTITION_TABLE_OFFSET + ESP_PARTITION_TABLE_MAX_LEN) {
        return false;
    }
    const esp_partition_t *p = esp_ota_get_running_partition();
    if (addr >= p->address && addr < p->address + p->size) {
        return false;
    }
    if (addr < p->address && addr + size > p->address) {
        return false;
    }
    return result;
}
