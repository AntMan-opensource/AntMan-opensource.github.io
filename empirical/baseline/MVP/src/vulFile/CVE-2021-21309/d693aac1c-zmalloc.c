






void zlibc_free(void *ptr) {
    free(ptr);
}










































static size_t used_memory = 0;
pthread_mutex_t used_memory_mutex = PTHREAD_MUTEX_INITIALIZER;

static void zmalloc_default_oom(size_t size) {
    fprintf(stderr, "zmalloc: Out of memory trying to allocate %zu bytes\n", size);
    fflush(stderr);
    abort();
}

static void (*zmalloc_oom_handler)(size_t) = zmalloc_default_oom;

void *zmalloc(size_t size) {
    void *ptr = malloc(size+PREFIX_SIZE);

    if (!ptr) zmalloc_oom_handler(size);

    update_zmalloc_stat_alloc(zmalloc_size(ptr));
    return ptr;

    *((size_t*)ptr) = size;
    update_zmalloc_stat_alloc(size+PREFIX_SIZE);
    return (char*)ptr+PREFIX_SIZE;

}



void *zmalloc_no_tcache(size_t size) {
    void *ptr = mallocx(size+PREFIX_SIZE, MALLOCX_TCACHE_NONE);
    if (!ptr) zmalloc_oom_handler(size);
    update_zmalloc_stat_alloc(zmalloc_size(ptr));
    return ptr;
}

void zfree_no_tcache(void *ptr) {
    if (ptr == NULL) return;
    update_zmalloc_stat_free(zmalloc_size(ptr));
    dallocx(ptr, MALLOCX_TCACHE_NONE);
}


void *zcalloc(size_t size) {
    void *ptr = calloc(1, size+PREFIX_SIZE);

    if (!ptr) zmalloc_oom_handler(size);

    update_zmalloc_stat_alloc(zmalloc_size(ptr));
    return ptr;

    *((size_t*)ptr) = size;
    update_zmalloc_stat_alloc(size+PREFIX_SIZE);
    return (char*)ptr+PREFIX_SIZE;

}

void *zrealloc(void *ptr, size_t size) {

    void *realptr;

    size_t oldsize;
    void *newptr;

    if (size == 0 && ptr != NULL) {
        zfree(ptr);
        return NULL;
    }
    if (ptr == NULL) return zmalloc(size);

    oldsize = zmalloc_size(ptr);
    newptr = realloc(ptr,size);
    if (!newptr) zmalloc_oom_handler(size);

    update_zmalloc_stat_free(oldsize);
    update_zmalloc_stat_alloc(zmalloc_size(newptr));
    return newptr;

    realptr = (char*)ptr-PREFIX_SIZE;
    oldsize = *((size_t*)realptr);
    newptr = realloc(realptr,size+PREFIX_SIZE);
    if (!newptr) zmalloc_oom_handler(size);

    *((size_t*)newptr) = size;
    update_zmalloc_stat_free(oldsize+PREFIX_SIZE);
    update_zmalloc_stat_alloc(size+PREFIX_SIZE);
    return (char*)newptr+PREFIX_SIZE;

}



size_t zmalloc_size(void *ptr) {
    void *realptr = (char*)ptr-PREFIX_SIZE;
    size_t size = *((size_t*)realptr);
    return size+PREFIX_SIZE;
}
size_t zmalloc_usable(void *ptr) {
    return zmalloc_size(ptr)-PREFIX_SIZE;
}


void zfree(void *ptr) {

    void *realptr;
    size_t oldsize;


    if (ptr == NULL) return;

    update_zmalloc_stat_free(zmalloc_size(ptr));
    free(ptr);

    realptr = (char*)ptr-PREFIX_SIZE;
    oldsize = *((size_t*)realptr);
    update_zmalloc_stat_free(oldsize+PREFIX_SIZE);
    free(realptr);

}

char *zstrdup(const char *s) {
    size_t l = strlen(s)+1;
    char *p = zmalloc(l);

    memcpy(p,s,l);
    return p;
}

size_t zmalloc_used_memory(void) {
    size_t um;
    atomicGet(used_memory,um);
    return um;
}

void zmalloc_set_oom_handler(void (*oom_handler)(size_t)) {
    zmalloc_oom_handler = oom_handler;
}









size_t zmalloc_get_rss(void) {
    int page = sysconf(_SC_PAGESIZE);
    size_t rss;
    char buf[4096];
    char filename[256];
    int fd, count;
    char *p, *x;

    snprintf(filename,256,"/proc/%d/stat",getpid());
    if ((fd = open(filename,O_RDONLY)) == -1) return 0;
    if (read(fd,buf,4096) <= 0) {
        close(fd);
        return 0;
    }
    close(fd);

    p = buf;
    count = 23; 
    while(p && count--) {
        p = strchr(p,' ');
        if (p) p++;
    }
    if (!p) return 0;
    x = strchr(p,' ');
    if (!x) return 0;
    *x = '\0';

    rss = strtoll(p,NULL,10);
    rss *= page;
    return rss;
}









size_t zmalloc_get_rss(void) {
    task_t task = MACH_PORT_NULL;
    struct task_basic_info t_info;
    mach_msg_type_number_t t_info_count = TASK_BASIC_INFO_COUNT;

    if (task_for_pid(current_task(), getpid(), &task) != KERN_SUCCESS)
        return 0;
    task_info(task, TASK_BASIC_INFO, (task_info_t)&t_info, &t_info_count);

    return t_info.resident_size;
}






size_t zmalloc_get_rss(void) {
    struct kinfo_proc info;
    size_t infolen = sizeof(info);
    int mib[4];
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();

    if (sysctl(mib, 4, &info, &infolen, NULL, 0) == 0)
        return (size_t)info.ki_rssize;

    return 0L;
}





size_t zmalloc_get_rss(void) {
    struct kinfo_proc2 info;
    size_t infolen = sizeof(info);
    int mib[6];
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();
    mib[4] = sizeof(info);
    mib[5] = 1;
    if (sysctl(mib, 4, &info, &infolen, NULL, 0) == 0)
        return (size_t)info.p_vm_rssize;

    return 0L;
}

size_t zmalloc_get_rss(void) {
    
    return zmalloc_used_memory();
}




int zmalloc_get_allocator_info(size_t *allocated, size_t *active, size_t *resident) {

    uint64_t epoch = 1;
    size_t sz;
    *allocated = *resident = *active = 0;
    
    sz = sizeof(epoch);
    je_mallctl("epoch", &epoch, &sz, &epoch, sz);
    sz = sizeof(size_t);
    
    je_mallctl("stats.resident", resident, &sz, NULL, 0);
    
    je_mallctl("stats.active", active, &sz, NULL, 0);
    
    je_mallctl("stats.allocated", allocated, &sz, NULL, 0);
    return 1;
}

void set_jemalloc_bg_thread(int enable) {
    
    char val = !!enable;
    je_mallctl("background_thread", NULL, 0, &val, 1);
}

int jemalloc_purge() {
    
    char tmp[32];
    unsigned narenas = 0;
    size_t sz = sizeof(unsigned);
    if (!je_mallctl("arenas.narenas", &narenas, &sz, NULL, 0)) {
        sprintf(tmp, "arena.%d.purge", narenas);
        if (!je_mallctl(tmp, NULL, 0, NULL, 0))
            return 0;
    }
    return -1;
}



int zmalloc_get_allocator_info(size_t *allocated, size_t *active, size_t *resident) {

    *allocated = *resident = *active = 0;
    return 1;
}

void set_jemalloc_bg_thread(int enable) {
    ((void)(enable));
}

int jemalloc_purge() {
    return 0;
}










size_t zmalloc_get_smap_bytes_by_field(char *field, long pid) {
    char line[1024];
    size_t bytes = 0;
    int flen = strlen(field);
    FILE *fp;

    if (pid == -1) {
        fp = fopen("/proc/self/smaps","r");
    } else {
        char filename[128];
        snprintf(filename,sizeof(filename),"/proc/%ld/smaps",pid);
        fp = fopen(filename,"r");
    }

    if (!fp) return 0;
    while(fgets(line,sizeof(line),fp) != NULL) {
        if (strncmp(line,field,flen) == 0) {
            char *p = strchr(line,'k');
            if (p) {
                *p = '\0';
                bytes += strtol(line+flen,NULL,10) * 1024;
            }
        }
    }
    fclose(fp);
    return bytes;
}


size_t zmalloc_get_smap_bytes_by_field(char *field, long pid) {

    struct proc_regioninfo pri;
    if (proc_pidinfo(pid, PROC_PIDREGIONINFO, 0, &pri, PROC_PIDREGIONINFO_SIZE) == PROC_PIDREGIONINFO_SIZE) {
	if (!strcmp(field, "Private_Dirty:")) {
            return (size_t)pri.pri_pages_dirtied * 4096;
	} else if (!strcmp(field, "Rss:")) {
            return (size_t)pri.pri_pages_resident * 4096;
	} else if (!strcmp(field, "AnonHugePages:")) {
            return 0;
	}
    }
    return 0;

    ((void) field);
    ((void) pid);
    return 0;
}


size_t zmalloc_get_private_dirty(long pid) {
    return zmalloc_get_smap_bytes_by_field("Private_Dirty:",pid);
}


size_t zmalloc_get_memory_size(void) {


    int mib[2];
    mib[0] = CTL_HW;

    mib[1] = HW_MEMSIZE;            

    mib[1] = HW_PHYSMEM64;          

    int64_t size = 0;               
    size_t len = sizeof(size);
    if (sysctl( mib, 2, &size, &len, NULL, 0) == 0)
        return (size_t)size;
    return 0L;          


    
    return (size_t)sysconf(_SC_PHYS_PAGES) * (size_t)sysconf(_SC_PAGESIZE);


    
    int mib[2];
    mib[0] = CTL_HW;

    mib[1] = HW_REALMEM;        

    mib[1] = HW_PHYSMEM;        

    unsigned int size = 0;      
    size_t len = sizeof(size);
    if (sysctl(mib, 2, &size, &len, NULL, 0) == 0)
        return (size_t)size;
    return 0L;          

    return 0L;          


    return 0L;          

}



int zmalloc_test(int argc, char **argv) {
    void *ptr;

    UNUSED(argc);
    UNUSED(argv);
    printf("Initial used memory: %zu\n", zmalloc_used_memory());
    ptr = zmalloc(123);
    printf("Allocated 123 bytes; used: %zu\n", zmalloc_used_memory());
    ptr = zrealloc(ptr, 456);
    printf("Reallocated to 456 bytes; used: %zu\n", zmalloc_used_memory());
    zfree(ptr);
    printf("Freed pointer; used: %zu\n", zmalloc_used_memory());
    return 0;
}

