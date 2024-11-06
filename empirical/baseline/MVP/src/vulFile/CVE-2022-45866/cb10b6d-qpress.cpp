







































    #include <unistd.h>


using namespace std;


  #include <fcntl.h>
  #include <time.h>
  #include <windows.h>
  #include <io.h>
  #include "dirent_win.h"
  #include "pthread.h"

  #include "dirent.h"
  #include <pthread.h>







	#define CURDIR ".\\"
    #define DELIM_STR "\\"
    #define DELIM_CHAR '\\'
    #define LONGLONG "%I64d"
	#ifndef PROCESS_MODE_BACKGROUND_BEGIN
	    #define PROCESS_MODE_BACKGROUND_BEGIN   0x00100000
    #endif

	#define CURDIR "./"
    #define DELIM_STR "/"
    #define DELIM_CHAR '/'
    #define LONGLONG "%lld"


typedef struct {
    string path;
    string pattern;
} search_type;


bool continue_flag = false;
bool cache_flag = true;
bool force_flag = false;
bool recursive_flag = false;
bool decompress_flag = false;
bool recover_flag = false;
bool benchmark_flag = false;
unsigned long long compress_chunk_size = DEFAULT_COMPRESS_CHUNK_SIZE;
unsigned int compression_level = DEFAULT_COMPRESSION_LEVEL;
unsigned int threads = DEFAULT_THREAD_COUNT;
bool verbose_flag = false;
bool flags_exist = false;
bool tty_stderr;
bool input_pipe;
bool output_pipe;


char *src[MAX_THREAD_COUNT];
char *dst[MAX_THREAD_COUNT];
char *scratch[MAX_THREAD_COUNT];


unsigned int files = 0;
unsigned long long payload_counter = 0;


pthread_mutex_t disk_read_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t disk_write_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t disk_order_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t disk_order_cond;
unsigned long long chunks_read;
unsigned long long chunks_written;
bool end_of_file;


string destination_file;


unsigned long long bench_size;


unsigned long long recovery_file_written;
unsigned long long recovery_bad_bytes = 0;
unsigned long long current_file_payload;
char tmp[200000];

enum {FATAL_ERROR, COUNTER_UPDATE, FILES_PROCESSED, RESULT, WARNING};

void PRINT(int MESSAGE_TYPE, const char *fmt, ...)
{
    va_list arg;
    va_start(arg, fmt);

    if(MESSAGE_TYPE == FATAL_ERROR)
    {
        vfprintf(stderr, fmt, arg);
    }
    else if(MESSAGE_TYPE == COUNTER_UPDATE)
    {
        
        if(verbose_flag && tty_stderr)
            vfprintf(stderr, fmt, arg);
    }
    else if(MESSAGE_TYPE == FILES_PROCESSED)
    {
        if(verbose_flag)
            vfprintf(stderr, fmt, arg);
    }
    else if(MESSAGE_TYPE == RESULT)
    {
        if(verbose_flag)
	        vfprintf(stderr, fmt, arg);
    }
    else if(MESSAGE_TYPE == WARNING)
    {
        vfprintf(stderr, fmt, arg);
    }
    va_end(arg);
}

void abort(const char *fmt, ...)
{
    va_list arg;
    va_start(arg, fmt);
    PRINT(FATAL_ERROR, "\r%s\r%s: ", BLANK_LINE, "qpress");
    vfprintf(stderr, fmt, arg); 
    va_end(arg);
    PRINT(FATAL_ERROR, "\n");
    adelete_write();
    exit(-1);
}


int int_flag(string arg, string flag)
{
    int r;
    size_t s0 = arg.find_first_of(flag);
    if (s0 != string::npos)
    {
        string s1 = arg.substr(s0);
        r = atoi(s1.substr(1, s1.find_first_not_of("0123456789", 1) - 1).c_str());
        if(r == 0)
            abort("Invalid value for -%s flag", flag.c_str());
        else return r;
    }
    return -1;
}

void parse_flags(int argc, char* argv[])
{
    string *arg = new string[argc];

    for(int i = 0; i < argc; i++)
        arg[i] = argv[i];

    if(argc > 1 && arg[1].substr(0, 1) == "-")
    {
        size_t o = 0;

        flags_exist = true;
        size_t e = arg[1].find_first_not_of("-iodrvcmRfKCBPLT0123456789");
        if(e != string::npos)
            abort("Unknown flag -%s", arg[1].substr(e, 1).c_str());

        
        do {
            string c = "-";
            o = arg[1].find_first_of("0123456789", o + 1);
            if(o != string::npos)
                c = arg[1].substr(o - 1, 1);
            if(c != "-" && c != "L" && c != "P" && c != "T" && c != "K" && (c < "0" || c > "9"))
                abort("Numeric values must be preceded by L, P, T or K");
        } while (o != string::npos);

        decompress_flag = arg[1].find_first_of("d") != string::npos ? true : false;
        recursive_flag = arg[1].find_first_of("r") != string::npos ? true : false;
        verbose_flag = arg[1].find_first_of("v") != string::npos ? true : false;
        output_pipe = arg[1].find_first_of("o") != string::npos ? true : false;
        benchmark_flag = arg[1].find_first_of("m") != string::npos ? true : false;
        recover_flag = arg[1].find_first_of("R") != string::npos ? true : false;
        force_flag = arg[1].find_first_of("f") != string::npos ? true : false;
        continue_flag = arg[1].find_first_of("C") != string::npos ? true : false;
        cache_flag = arg[1].find_first_of("B") != string::npos ? false : true;
        input_pipe = arg[1].find_first_of("i") != string::npos ? true : false;
        output_pipe = arg[1].find_first_of("o") != string::npos ? true : false;


        if(int_flag(arg[1], "P") != -1)
        {
            switch(int_flag(arg[1], "P"))
            {
                case 1:
					if (!SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN))
					{
						PRINT(WARNING, "%s%s: -P1 not supported by this OS - using -P2 instead\n", BLANK_LINE, "qpress");
						SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS);
					}
					break;
                case 2: SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS); break;
                case 3: SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS); break;
                case 4: SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS); break;
                default: abort("Invalid -P flag value");
            }
        }


        if(int_flag(arg[1], "L") != -1)
        {
            if (int_flag(arg[1], "L") > 0 && int_flag(arg[1], "L") < 4)
                if(decompress_flag || recover_flag)
                    abort("-d or -R flag cannot be used with -L flag");
                else compression_level = int_flag(arg[1], "L");
            else abort("Invalid -L flag value");
        }

        if(int_flag(arg[1], "T") != -1)
        {
            if (int_flag(arg[1], "T") >= 1 && int_flag(arg[1], "T") <= MAX_THREAD_COUNT)
                    threads = int_flag(arg[1], "T");
            else abort("Invalid -T flag value");
        }

        if(int_flag(arg[1], "K") != -1)
        {
            if (1024*int_flag(arg[1], "K") >= AIO_MAX_SECTOR_SIZE && 1024*int_flag(arg[1], "K") <= MAX_COMPRESS_CHUNK_SIZE)
                if(decompress_flag || benchmark_flag || recover_flag )
                    abort("-d, -m or -R flag cannot be used with -K flag");
                else compress_chunk_size = (1024*int_flag(arg[1], "K"));
            else abort("Invalid -K flag value");
        }
    }

    if((decompress_flag && (recursive_flag || benchmark_flag || recover_flag || continue_flag)) || (benchmark_flag && (recursive_flag || verbose_flag || output_pipe || recover_flag || continue_flag)) || (recover_flag && (recursive_flag || continue_flag)))

            abort("Flag combination does not make sense");
}

void print_usage()
{
    string usage = "Compression:\n" "    qpress [-rovfCBPLKT] <source file/dir search pattern> <destination file>\n" "    qpress -i[ovfBPLKT] <filename to give stdin data> <destination file>\n\n" "Decompression:\n" "    qpress -d[ovfBPTn] <source file> <destination directory>\n\n" "Benchmark and recovery:\n" "    qpress -m[LT] <source file>\n" "    qpress -R <corrupted compressed file> <destination directory>\n\n" "Flags:\n" "    -d   Decompress\n" "    -Ln  Set compression level to n where n = 1, 2 or 3 (default = 1)\n" "    -r   Include sub directories during compression\n" "    -v   Show progress information during compression and decompression\n" "    -i   Read from stdin (omit source file or file/dir search pattern)\n" "    -o   Write to stdout (omit destination file or directory)\n" "    -f   Overwrite existing files during compression and decompression (default\n" "         is to abort)\n" "    -C   Continue if a source file cannot be opened during compression (default\n" "         is to abort)\n" "    -Tn  Use n threads/cores where n = 1 to " + str(MAX_THREAD_COUNT) + " (default = " + str(DEFAULT_THREAD_COUNT) + "). Be aware of\n" "         memory usage with large n\n" "    -Kn  Read from disk in n KiB chunks during compression where n = " + str(AIO_MAX_SECTOR_SIZE >> 10) + " to\n" + "         " + str(MAX_COMPRESS_CHUNK_SIZE >> 10) + " (default = " + str(DEFAULT_COMPRESS_CHUNK_SIZE >> 10) + "). Be aware of memory usage with large n\n"  "    -B   Windows only: Disable file system caching (FILE_FLAG_NO_BUFFERING) to\n" "         prevent cache of other applications from being be flushed. Keep\n" "         enabled if files are small and need further processing\n" "    -Pn  Windows only: Set CPU and disk I/O priority to n where 1 = BACKGORUND\n" "         (Vista, 7, 2008 only), 2 = IDLE, 3 = NORMAL or 4 = ABOVE (default = 3)\n\n" "Examples of compression:\n"  "    qpress -rv d:\\dir\\* database.qp\n" "    qpress -vfK4096T2 ../dir/*.xml database.qp 2> log.txt\n" "    qpress -ovL3K *.xml > database.qp\n" "    type database.xml | qpress -io database.xml > database.qp\n" "    type database.xml | qpress -i database.xml database.qp\n\n" "Examples of decompression:\n" "    qpress -d database.qp d:\\dir\n" "    qpress -do database.qp > database.xml\n" "    type database.qp | qpress -di .\n\n"  "    qpress -v file1.xml file2.xml file3.xml database.qp\n" "    qpress -vfK4096T2 *.xml database.qp 2> log.txt\n" "    qpress -ovL3K *.xml > database.qp\n" "    cat database.xml | qpress -i database.xml database.qp\n" "    cat database.xml | qpress -io database.xml > database.qp\n\n" "Examples of decompression:\n" "    qpress -d database.qp ./dir\n" "    qpress -do database.qp > database.xml\n" "    cat database.qp | qpress -di .\n\n"  "Notes:\n" "When compressing on *nix with -r flag, file/dir search pattern only filters in\n" "top level directory (directories matching in top level will be included fully).\n\n"  "If a compressed file contains multiple files and is decompressed to stdout, all\n" "files will be concatenated in a continuous stream.\n\n" "It's recommended to use .qp as filename suffix.\n";

























































    PRINT(FATAL_ERROR, "qpress 1.1 - Copyright 2006-2010 Lasse Reinhold - www.quicklz.com\n");
    PRINT(FATAL_ERROR, "Using QuickLZ 1.4.1 compression library\n");

	PRINT(FATAL_ERROR, "Compiled for: ");
	#ifdef WINDOWS
		PRINT(FATAL_ERROR, "[Windows] *nix    ");
	#else
		PRINT(FATAL_ERROR, "Windows [*nix]    ");
	#endif

	#ifdef X86X64
		PRINT(FATAL_ERROR, "[x86/x64] RISC    ");
	#else
		PRINT(FATAL_ERROR, "x86/x64 [RISC]    ");
	#endif

	if(sizeof(size_t) == 8)
		PRINT(FATAL_ERROR, "32-bit [64-bit]");
	else PRINT(FATAL_ERROR, "[32-bit] 64-bit");

    PRINT(FATAL_ERROR, "\n\n%s", usage.c_str());
	exit(-1);
}



void try_aopen(const char *file, char mode)
{
    if(mode == 'w')
    {
        if (!aopen_write(file))
            abort("Error creating destination file '%s' - aborted", file);
    }
    else {
        if (!aopen_read(file))
            abort("Error opening source file '%s' - aborted", file);
    }
}

void mem_init(size_t chunk_size)
{
    for(unsigned int i = 0; i < threads; i++)
    {
        scratch[i] = (char *)malloc(QLZ_SCRATCH_COMPRESS());
        src[i] = (char *)malloc((size_t)chunk_size + QLZ_SIZE_OVERHEAD);
        dst[i] = (char *)malloc((size_t)chunk_size + QLZ_SIZE_OVERHEAD);
        if(dst[i] == 0 || src[i] == 0 || scratch[i] == 0)
            abort("Error allocating memory - decrease -T and -K flags");
    }
}

void *benchmark_compress_thread(void *arg)
{
    unsigned long long y = 0;
    size_t id = (size_t)arg;
    double t = GetTickCount();
	while(GetTickCount() == t) {};
    t = GetTickCount();

	while(GetTickCount() - t < BENCHMARK_MILLISECONDS)
    {
        QLZ_COMPRESS(src[id], dst[id], bench_size / threads, compression_level, scratch[id]);
        y += bench_size / threads;
    }
	t = GetTickCount() - t;
	y = (unsigned long long)(y / t * 1000. / 1024.);
    return (void *)(size_t)y;
}

void *benchmark_decompress_thread(void *arg)
{
    unsigned long long y = 0;
    size_t id = (size_t)arg;
    double t = GetTickCount();
	while(GetTickCount() == t) {};
    t = GetTickCount();

	while(GetTickCount() - t < BENCHMARK_MILLISECONDS)
    {
        QLZ_DECOMPRESS(dst[id], src[id], scratch[id]);
        y += QLZ_SIZE_DECOMPRESSED(dst[id]);
    }

	t = GetTickCount() - t;
	y = (unsigned long long)(y / t * 1000. / 1024.);
    return (void *)(size_t)y;
}

void benchmark(char *source_file)
{
    unsigned long long y = 0, u = 0;
    double speed = 0.0;
    void *status[MAX_THREAD_COUNT];
    pthread_t thread[MAX_THREAD_COUNT];
    FILE *ifile = fopen(source_file, "rb");

	if((ifile) == 0)
        abort("Error opening source file '%s' - aborted", source_file);

    fseek(ifile, 0, SEEK_END);
    size_t file_len = ftell(ifile);
    fseek(ifile, 0, SEEK_SET);

    if(file_len == 0 || file_len > 512*1024*1024)
        abort("File too large for benchmark");

    if(file_len < 256*1024)
        PRINT(WARNING, "Note: File size should be at least 256 KiB for accurate results.\n");

    mem_init(file_len / threads);

    if(src[0] == 0 || dst[0] == 0 || scratch[0] == 0)
        abort("Error allocating memory - file too large");

    PRINT(FATAL_ERROR, "Using %d threads/cores (change with -T flag). Please wait...\n", threads);

    for(size_t i = 0; i < threads; i++)
    {
        size_t t = fread(src[i], 1, file_len / threads, ifile);
        if(t != file_len / threads)
            abort("Error reading source file '%s'", source_file);
    }

    bench_size = file_len;

	for(int j = 0; j < BENCHMARK_BESTOF; j++)
	{
		double tmp_speed = 0.;
		for(size_t i = 0; i < threads; i++)
			pthread_create(&thread[i], NULL, benchmark_compress_thread, (void*)i);
		y = 0;
		u = 0;
		for(size_t i = 0; i < threads; i++)
		{
			pthread_join(thread[i], &status[i]);
			y += (size_t)status[i];
			u += QLZ_SIZE_COMPRESSED(dst[i]);
		}
		tmp_speed = (double)y / 1024.;
		if (tmp_speed > speed)
			speed = tmp_speed;
	}

	PRINT(FATAL_ERROR, "Compressed %s bytes into %s (%.1f%%) at %.1f MiB/s\n", delimiter(file_len).c_str(), delimiter(u).c_str(), (double)u/(double)file_len*100., speed);

	for(int j = 0; j < BENCHMARK_BESTOF; j++)
	{
		double tmp_speed = 0.;
		for(size_t i = 0; i < threads; i++)
			pthread_create(&thread[i], NULL, benchmark_decompress_thread, (void*)i);
		y = 0;
		for(size_t i = 0; i < threads; i++)
		{
			pthread_join(thread[i], &status[i]);
			y += (size_t)status[i];
		}
		tmp_speed = (double)y / 1024.;
		if (tmp_speed > speed)
			speed = tmp_speed;
	}

	PRINT(FATAL_ERROR, "Decompressed at %.1f MiB/s\n", speed);
}

void update_statusbar(string description, bool force_update)
{
    static unsigned int last_tick = 0, last_speed_tick = 0, speed = 0;
    static long long last_payload_counter_mbs = 0;
    static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
    unsigned int t = GetTickCount() - last_tick;
    unsigned int s = GetTickCount() - last_speed_tick;

    pthread_mutex_lock(&mu);

    if (s > 3000)
    {
        
        speed = (unsigned int)((payload_counter - last_payload_counter_mbs) / (s == 0 ? 1 : s));
        last_payload_counter_mbs = payload_counter;
        last_speed_tick = GetTickCount();
    }

    if (force_update || t > 400)
    {
        
        last_tick = GetTickCount();
        if(description == "c")
            PRINT(COUNTER_UPDATE, "%s    Compressed %s MiB (%d MiB/s) into %s MiB\r", BLANK_LINE, delimiter(payload_counter >> 20).c_str(), speed >> 10, delimiter(awritten() >> 20).c_str());
        else PRINT(COUNTER_UPDATE, "%s    Wrote %s MiB (%d MiB/s)\r", BLANK_LINE, delimiter(payload_counter >> 20).c_str(), speed >> 10);
    }

    pthread_mutex_unlock(&mu);
}

void recover(void)
{
    if(recover_flag)
    {
        char search[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
        unsigned long long p;
        do {
            memmove(search, search + 1, 8);
            size_t y = aread(search + 8, 1);
            if (y == 0)
            {
                aclose_write();
                abort("Unexpected end of source file - destination data and/or files missing");
            }
        } while (strncmp(search + 1, "NEWBNEWB", 8) != 0);

        p = fread64(); 
        if(p - recovery_file_written < 1024*1024*1024) 
        {
            for(unsigned long long g = 0; g < p - recovery_file_written; g++)
                try_awrite("!", 1);
            PRINT(WARNING, "%s%s bytes at offset %s bad - replaced with '!'\n\n", BLANK_LINE, delimiter(p - recovery_file_written).c_str(), delimiter(recovery_file_written).c_str());
            recovery_bad_bytes += (p - recovery_file_written);
            recovery_file_written = p;
        }
        else {
            PRINT(WARNING, "%sData from other files may be appended to this file\n\n", BLANK_LINE);
            recovery_file_written = p; 
        }
    }
    else abort("Source file is corrupted - try the -R flag to recover");
}

void *decompress_file_thread(void *arg)
{
    size_t thread_id = (size_t)arg;
    bool just_recovered_block = false;
    recovery_file_written = 0;

    update_statusbar("d", true);

    for(;;)
    {
        unsigned long long my_chunk;
        unsigned int crc_r, crc_original;
        size_t decomp_size;

        pthread_mutex_lock(&disk_read_mutex);
        update_statusbar("d", false);

        if (end_of_file)
        {
            pthread_mutex_unlock(&disk_read_mutex);
            break;
        }

        if(!just_recovered_block)
        {
            
            try_aread(src[thread_id], 1);
            try_aread(tmp, 7);
        }

        if (*src[thread_id] == 'N') 
        {
            fread64(); 
        }
        else if(*src[thread_id] == 'E') 
        {
            end_of_file = true;
            try_aread(tmp, 8); 
            files++;
            pthread_mutex_unlock(&disk_read_mutex);
            break;
        }
        else if(just_recovered_block)
            just_recovered_block = false;
        else abort("Data error, not recoverable");

        crc_original = fread32();
        try_aread(src[thread_id], 9);
        if (QLZ_SIZE_COMPRESSED(src[thread_id]) > compress_chunk_size + QLZ_SIZE_OVERHEAD)
            abort("Data error, not recoverable"); 

        try_aread(src[thread_id] + 9, QLZ_SIZE_COMPRESSED(src[thread_id]) - 9);

        my_chunk = chunks_read;
        chunks_read++;
        pthread_mutex_unlock(&disk_read_mutex);

        crc_r = adler((unsigned char *)src[thread_id], QLZ_SIZE_COMPRESSED(src[thread_id]), 0x00010000);
        if (crc_r != crc_original)
        {
            just_recovered_block = true;
            recover();
        }
        decomp_size = QLZ_DECOMPRESS(src[thread_id], dst[thread_id], scratch[thread_id]);

        
        for(;;)
        {
            pthread_mutex_lock(&disk_write_mutex);
            if(my_chunk == chunks_written)
                break;
            else {
                pthread_mutex_unlock(&disk_write_mutex);
                utils_yield();
            }
        }
        chunks_written++;
        if(!just_recovered_block)
        {
            payload_counter += decomp_size;
            recovery_file_written += decomp_size;
            try_awrite(dst[thread_id], decomp_size);
        }
        pthread_mutex_unlock(&disk_write_mutex);
    }
    return 0;
}


void decompress_file(string dest_file)
{
    pthread_t thread[MAX_THREAD_COUNT];
    size_t i;
    end_of_file = false;
    chunks_read = 0;
    chunks_written = 0;
    void *status;

	try_aopen(dest_file.c_str(), 'w');

    for(i = 0; i < threads; i++)
    {
        pthread_create(&thread[i], NULL, decompress_file_thread, (void *)i);
    }

    for(i = 0; i < threads; i++)
    {
        pthread_join(thread[i], &status);
    }

	if(dest_file != "<stdout>")
		aclose_write();
}

void *compress_file_thread(void *arg)
{
    size_t read;
    do {
        size_t u, thread_id = (size_t)arg;
        unsigned int crc_r;
        unsigned long long my_chunk;

        update_statusbar("c", false);

        pthread_mutex_lock(&disk_write_mutex);
        my_chunk = chunks_read;
        chunks_read++;

        pthread_mutex_lock(&disk_read_mutex);
        pthread_mutex_unlock(&disk_write_mutex);
        read = aread(src[thread_id], compress_chunk_size);
        pthread_mutex_unlock(&disk_read_mutex);

        if (read == 0)
            return 0;

        u = QLZ_COMPRESS(src[thread_id], dst[thread_id], read, compression_level, scratch[thread_id]);
        crc_r = adler((unsigned char *)dst[thread_id], u, 0x00010000);

        
        for(;;)
        {
            pthread_mutex_lock(&disk_write_mutex);
            if(my_chunk == chunks_written)
                break;
            else {
                pthread_mutex_unlock(&disk_write_mutex);
                utils_yield();
            }
        }

        try_awrite("NEWBNEWB", 8);
        fwrite64(current_file_payload);
        payload_counter += read;
        current_file_payload += read;
        fwrite32(crc_r);
        chunks_written++;
        try_awrite(dst[thread_id], u);
        pthread_mutex_unlock(&disk_write_mutex);
    } while (read == compress_chunk_size);

    return 0;
}

void compress_file(string input_file, string filename)
{
    pthread_t thread[MAX_THREAD_COUNT];
    unsigned long long bytes_written = 0;
    void *status;

	if(aopen_read(input_file.c_str()))
	{
		PRINT(FILES_PROCESSED, "%s    %s\n", BLANK_LINE, filename.c_str());
		update_statusbar("c", true);
		try_awrite("F", 1);
		fwrite32((unsigned int)filename.length());
		try_awrite(filename.c_str(), filename.length());
		try_awrite("\0", 1);

		files++;
		chunks_read = 0;
		chunks_written = 0;
		current_file_payload = 0;

		for(size_t i = 0; i < threads; i++)
			pthread_create(&thread[i], NULL, compress_file_thread, (void*)i);

		for(size_t i = 0; i < threads; i++)
			pthread_join(thread[i], &status);

		try_awrite("ENDSENDS", 8);
		fwrite64(bytes_written);
		aclose_read(); 
	}
	else if (continue_flag && input_file != "<stdin>")
		PRINT(WARNING, "%s%s: Error opening source file '%s' - skipped\n", BLANK_LINE, "qpress", input_file.c_str());
	else abort("Error opening source file '%s' - aborted", input_file.c_str());
}

string void2curdir(string path)
{
	return path == "" ? CURDIR : path;
}

void godown(const char *dir)
{
	size_t chunk_size = strlen(dir);
	try_awrite("D", 1);
	fwrite32((unsigned int)chunk_size);
	try_awrite(dir, strlen(dir));
	try_awrite("\0", 1);
}

void goup(void)
{
	try_awrite("U", 1);
}


string remove_curdir(string dir)
{
	if(dir.length() >= 2 && dir.substr(0, 2) == CURDIR)
		return dir.substr(2, dir.length() - 2);
	else return dir;
}

void compress_directory(string base_dir, string pattern)
{
    string path;
    struct dirent *entry;
	DIR *dir;

	base_dir = remove_curdir(base_dir);

	string api_path = (base_dir == "" ? "" : remove_delimitor(base_dir) + DELIM_STR);

	if(base_dir != "")
		PRINT(FILES_PROCESSED, "%s%s%s\n", BLANK_LINE, base_dir.c_str(), DELIM_STR);

	
	if((dir = opendir(void2curdir(api_path).c_str())))
	{

        while((entry = readdir_wildcard(dir, (char *)pattern.c_str())))

        while((entry = readdir(dir)))

		{
			if(string(entry->d_name) != "." && string(entry->d_name) != "..")
			{
				path = api_path + string(entry->d_name);
				if (!is_dir(path))
				{
					
					absolute_path((char *)path.c_str(), tmp);

					if(lcase(string(tmp)) != lcase(destination_file))

					if(string(tmp) != destination_file)

						compress_file(path, string(entry->d_name));
				}
			}
		}
	    closedir(dir);
	}



	
    if(recursive_flag && (dir = opendir(void2curdir(api_path).c_str())))
	{

        while((entry = readdir_wildcard(dir, "*")))

        while((entry = readdir(dir)))

		{
			path = api_path + string(entry->d_name);

			if(is_dir(path) && string(entry->d_name) != "." && string(entry->d_name) != "..")
			{
				godown(entry->d_name);
				compress_directory(path, pattern);
				goup();
			}
		}
		closedir(dir);
	}
 }


void decompress_directory(string extract_dir, bool std_out)
{
    char c;
    string curdir;
    size_t r = 0;
    unsigned int chunk_size;

    curdir = string(extract_dir);

    for(;;)
    {
        r = aread(&c, 1);
        if (r == 0)
            return;

        if(c == 'D')
        {
			
            chunk_size = fread32();
            try_aread(tmp, chunk_size + 1);
            curdir = curdir + DELIM_STR + tmp;
            PRINT(FILES_PROCESSED, "%s%s%s\n", BLANK_LINE, remove_leading_curdir(curdir).c_str(), DELIM_STR);
            if(!std_out)
            {

                CreateDirectory(curdir.c_str(), 0);

                mkdir(curdir.c_str(), 509);

            }
        }
        else if(c == 'U')
            curdir = curdir.substr(0, curdir.find_last_of(DELIM_STR)); 
        else if(c == 'F')
        {
            chunk_size = fread32(); 
            try_aread(tmp, chunk_size + 1); 
            string buf2 = curdir + DELIM_STR + tmp;
            PRINT(FILES_PROCESSED, "%s    %s\n", BLANK_LINE, tmp);
            if(!std_out)
            {
                if(exists(buf2) && !force_flag)
                    abort("Destination file '%s' already exists - aborted", buf2.c_str());
                else decompress_file(buf2);
            }
            else decompress_file("<stdout>");
        }
        else abort("Source file is corrupted - try the -R flag to recover");
    }
}

string filenamepart(string filenamepath)
{
    size_t r = filenamepath.find_last_of("/\\");
    if(r == string::npos)
        return filenamepath;
    else return filenamepath.substr(r + 1);
}


search_type split(string source)
{
    search_type ret;

	if(is_dir(source))
	{
		ret.path = source;
		ret.pattern = "";
		return ret;
	}

	source = remove_leading_curdir(source);

    size_t r = source.find_last_of("/\\");

    if(r == string::npos)
    {
		ret.path = "";
		ret.pattern = source;
		return ret;
	}
	else {
		
		ret.path = source.substr(0, r);
		ret.pattern = source.substr(r + 1);
		return ret;
	}
}

int main(int argc, char* argv[])
{
    string *arg = new string[argc];
    for(int i = 0; i < argc; i++)
        arg[i] = argv[i];

    parse_flags(argc, argv);

    tty_stderr = isatty(fileno(stderr));




    setmode(fileno(stdin), _O_BINARY);
    setmode(fileno(stdout), _O_BINARY);
    pthread_win32_process_attach_np ();




    if (benchmark_flag && (!input_pipe) && argc == 3)
    {
        benchmark(argv[2]);
    }



    else if ((decompress_flag || recover_flag) && argc == 2 + (!input_pipe) + (1 - output_pipe))
    {
        if(recover_flag)
            threads = 1;

        aio_init(compress_chunk_size + QLZ_SIZE_OVERHEAD, cache_flag);
        if(!input_pipe)
        {
            try_aopen(arg[2].c_str(), 'r');
            aread(tmp, 8);
            compress_chunk_size = fread64();
            aclose_read();
            aio_init(compress_chunk_size + QLZ_SIZE_OVERHEAD, cache_flag);
            try_aopen(arg[2].c_str(), 'r');
            aread(tmp, 16);
        }
        else {
            try_aopen("<stdin>", 'r');
            aread(tmp, 8);
            compress_chunk_size = fread64();
            aio_init(compress_chunk_size + QLZ_SIZE_OVERHEAD, cache_flag);
        }

        if(strncmp(tmp, "qpress", 6) != 0)
            abort("Source file was not compressed with qpress");

        if(tmp[6] != '1')
            abort("Version %d.x.x is required to decompress this file", tmp[6] - 48);

        if(compress_chunk_size > 512*1024*1024)
            abort("Source file is corrupted - try the -R flag to recover");

        mem_init(compress_chunk_size);

        if(output_pipe)
            decompress_directory("", true);
        else {
            string s = remove_delimitor(arg[2 + (!input_pipe)]);
            decompress_directory(s, false);
        }

        aclose_read();
        if(recover_flag)
        {
            PRINT(RESULT, "%sWrote %s bytes in %s file(s) of which %s bytes are bad\n", BLANK_LINE, delimiter(payload_counter + recovery_bad_bytes).c_str(), delimiter(files).c_str(), delimiter(recovery_bad_bytes).c_str());
            PRINT(RESULT, "\nNote: There may be more errors than listed. Files may be missing or placed\nin wrong directories and files may contain fragments of other files.");
        }
        else PRINT(RESULT, "%sWrote %s bytes in %s file(s).", BLANK_LINE, delimiter(payload_counter).c_str(), delimiter(files).c_str());
    }



    else if(!decompress_flag && argc >= 2 + flags_exist + (1 - output_pipe))
    {
        string output_file;

        mem_init(compress_chunk_size);
        aio_init(compress_chunk_size + QLZ_SIZE_OVERHEAD, cache_flag);

        if(output_pipe)
            try_aopen("<stdout>", 'w');
        else {
			output_file = arg[argc - 1];
            if(exists(output_file) && !force_flag)
                abort("Destination file '%s' already exists", output_file.c_str());

            try_aopen(output_file.c_str(), 'w');
        }

        try_awrite("qpress10", 8);
		fwrite64(compress_chunk_size);

        if(!input_pipe)
        {
			absolute_path((char *)output_file.c_str(), tmp);
			destination_file = string(tmp);

			if(split(arg[1 + flags_exist]).pattern != "")
				compress_directory(split(arg[1 + flags_exist]).path, split(arg[1 + flags_exist]).pattern);

			for(int i = 1 + flags_exist; i < argc - ((!output_pipe) == true ? 1 : 0); i++)
			{
				if (!is_dir(arg[i]))
					compress_file(arg[i], filenamepart(arg[i]));
			}

			if(recursive_flag)
			{
				for(int i = 1 + flags_exist; i < argc - ((!output_pipe)== true ? 1 : 0); i++)
				{
					if(is_dir(arg[i]))
					{
						arg[i] = remove_delimitor(arg[i]);
						if(filenamepart(arg[i]) == "." || filenamepart(arg[i]) == "..")
							compress_directory(arg[i], "*");
						else {
							godown(filenamepart(arg[i]).c_str());
							compress_directory(arg[i], "*");
							goup();
						}
					}
				}
			}

        }
        else {
            compress_file("<stdin>", arg[1 + flags_exist]);
        }

		if(files == 0)
			abort("0 files found. Are you missing a search pattern such as '*'?");
		else {
	        PRINT(RESULT, "%sCompressed %s bytes in %s file(s) into %s bytes", BLANK_LINE, delimiter(payload_counter).c_str(), delimiter(files).c_str(), delimiter(awritten()).c_str());
		    aclose_write();
		}
    }
    else print_usage();

    PRINT(RESULT, "\n");
}

