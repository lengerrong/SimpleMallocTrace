#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif 

#include "Symbolize.h"

#include <cxxabi.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <map>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include "SimpleMallocTrace.h"

using namespace std;
using std::map;
using std::string;
using std::vector;

extern "C" {

#define PATH_MAX 256
#define BTSZ 10
#define BTAL 20
#define COLOR_NONE "\033[0;0m"
#define COLOR_RED "\033[5;31m"
#define COLOR_GREEN "\033[0;42m"
#define COLOR_YELLOW "\033[0;33m"
#define SMTLOG(...) printf(__VA_ARGS__)

typedef void * (*MALLOC_FUNCTION) (size_t);
typedef void * (*CALLOC_FUNCTION) (size_t, size_t);
typedef void * (*REALLOC_FUNCTION) (void*, size_t);
typedef void (*FREE_FUNCTION) (void*);
typedef void (*CFREE_FUNCTION) (void*);
typedef void * (*MEMALIGN_FUNCTION) (size_t, size_t);
typedef void * (*ALIGNED_ALLOC_FUNCTION) (size_t, size_t);
typedef int (*POSIX_MEMALIGN_FUNCTION) (void**, size_t, size_t);

static  MALLOC_FUNCTION libc_malloc = 0;
static  CALLOC_FUNCTION libc_calloc = 0;
static  REALLOC_FUNCTION libc_realloc = 0;
static  FREE_FUNCTION libc_free = 0;
static  CFREE_FUNCTION libc_cfree = 0;
static  MEMALIGN_FUNCTION libc_memalign = 0;
static  ALIGNED_ALLOC_FUNCTION libc_aligned_alloc = 0;
static  POSIX_MEMALIGN_FUNCTION libc_posix_memalign = 0;

static __thread int use_origin_malloc = 0;
static __thread int calloc_for_dlsym = 0;

static const char* malloc_symbol = "malloc";
static const char* free_symbol = "free";
static const char* realloc_symbol = "realloc";
static const char* calloc_symbol = "calloc";
static const char* posix_memalign_symbol = "posix_memalign";
static const char* aligned_alloc_symbol = "aligned_alloc";
static const char* memalign_symbol = "memalign";
static const char* cfree_symbol = "cfree";

pthread_mutex_t maplock;
class MallocNode {
public:
    MallocNode()
        : sz(0)
    {
    }
    MallocNode(size_t _sz, void* _bt[])
        : sz(_sz)
    {
        memcpy(bt, _bt, sizeof(bt));
    }
public:
    size_t sz;
    void* bt[BTSZ];
};

typedef std::map<void*, MallocNode> MMap;
class SMTMap {
public:
    SMTMap()
    {
        startfile[0] = '\0';
        startfunction[0] = '\0';
        startline = -1;
        stopfile[0] = 'm';
        stopfile[1] = 'a';
        stopfile[2] = 'i';
        stopfile[3] = 'n';
        stopfile[4] = '\0';
        stopfunction[0] = 'm';
        stopfunction[1] = 'a';
        stopfunction[2] = 'i';
        stopfunction[3] = 'n';
        stopfunction[4] = '\0';
        stopline = -1;
    }
    SMTMap(const char* file, const char* function, size_t line)
    {
        snprintf(startfile, sizeof(stopfile), "%s", file);
        snprintf(startfunction, sizeof(stopfunction), "%s", function);
        startline = line;
    }
    void insert(void* p, size_t sz, void** bt)
    {
        mmap.insert(std::pair<void*, MallocNode>(p, MallocNode(sz, bt)));
    }
    void erase(void* p)
    {
        mmap.erase(p);
    }
    void stopAt(const char* file, const char* function, size_t line)
    {
        snprintf(stopfile, sizeof(stopfile), "%s", file);
        snprintf(stopfunction, sizeof(stopfunction), "%s", function);
        stopline = line;
    }
    char startfile[PATH_MAX];
    char startfunction[PATH_MAX];
    size_t startline;
    char stopfile[PATH_MAX];
    char stopfunction[PATH_MAX];
    size_t stopline;
    MMap mmap;
};

static std::vector<SMTMap*>* smtmaplist = 0;
static sem_t smtinit_sem;

static void detectmemoryleak(SMTMap*);
static char* getlogpath(SMTMap*);
static void malloc_hook();
static void childafterfork();

// simplemalloctrace_initialize will be called before main()
static void __attribute__((constructor)) simplemalloctrace_initialize()
{
    malloc_hook();
    if (pthread_mutex_init(&maplock, 0)) {
        SMTLOG("Mutex init failed!\n");
        exit(1);
    }
    pthread_atfork(0, 0, childafterfork);
}

// avoid dead lock in backtrace()
// #0 0x424a84b8 in __lll_lock_wait () from /lib/libpthread.so.0
// No symbol table info available.
// #1 0x424a1a30 in pthread_mutex_lock () from /lib/libpthread.so.0
// No symbol table info available.
// #2 0x41013840 in _dl_open () from /lib/ld-linux.so.3
// No symbol table info available.
// #3 0x4224e890 in do_dlopen () from /lib/libc.so.6
// No symbol table info available.
// #4 0x4100fb60 in _dl_catch_error () from /lib/ld-linux.so.3
// No symbol table info available.
// #5 0x4224e970 in dlerror_run () from /lib/libc.so.6
// No symbol table info available.
// #6 0x4224e9f0 in __libc_dlopen_mode () from /lib/libc.so.6
// No symbol table info available.
// #7 0x42227bd0 in init () from /lib/libc.so.6
// No symbol table info available.
// #8 0x424a69c4 in pthread_once () from /lib/libpthread.so.0
// No symbol table info available.
// #9 0x42227ce0 in backtrace () from /lib/libc.so.6
// No symbol table info available.
// #10 0xb551a47a in tr_where (c=43 '+', sz=4, p=0x9c840) at 
static void __attribute__((constructor)) backtrace_init()
{
    void* buffer[1];
    backtrace(buffer, 1);
}

// simplemalloctrace_finalize will be called after main()
static void __attribute__((destructor)) simplemalloctrace_finalize()
{
    SMTLOG(COLOR_YELLOW"exit main function, let's check memory leak\n");
    pthread_mutex_destroy(&maplock);
    use_origin_malloc = 1;
    if (smtmaplist) {
        std::vector<SMTMap*>::iterator it;
        for (it = smtmaplist->begin(); it != smtmaplist->end(); ++it) {
            SMTMap* smtmap = *it;
            if (smtmap) {
                detectmemoryleak(smtmap);
                delete smtmap;
                smtmap = 0;
            }
        }
        delete smtmaplist;
        smtmaplist = 0;
    }
}

static void childafterfork()
{
    SMTLOG("In a forked child, let's clean mmap and mutex\n");
    pthread_mutex_unlock(&maplock);
    pthread_mutex_destroy(&maplock);
    if (pthread_mutex_init(&maplock, 0)) {
        SMTLOG("fail to init mutex\n");
        exit(1);
    }
    use_origin_malloc = 1;
    smtmaplist = new std::vector<SMTMap*>();
    if (!smtmaplist) {
        SMTLOG("fail to new mmap\n");
        exit(1);
    }
    SMTMap* globalmap = new SMTMap("before main()", "main()", 0);
    if (globalmap) {
        globalmap->stopAt("after main()", "main()", 0);
        smtmaplist->push_back(globalmap);
    }
    use_origin_malloc = 0;
	SMTLOG("child process after fork callback done\n");
}

static void malloc_hook()
{
    static int simplemalloctrace_init_begined = 0;
    int r = 0;

    if (simplemalloctrace_init_begined) {
        SMTLOG("malloc hook init begined, let's wait for semaphore\n");
        sem_wait(&smtinit_sem);
        SMTLOG("wait semaphore done!\n");
        return;
    }
    
    SMTLOG("malloc hook begin\n");

    simplemalloctrace_init_begined = 1;

    calloc_for_dlsym = 1;
    do {
        libc_malloc = (MALLOC_FUNCTION)dlsym(RTLD_NEXT, malloc_symbol);
        if (!libc_malloc) {
            SMTLOG("*** wrapper does not find [%s] in libc.so\n", malloc_symbol);
            r = 1;
            break;
        }
        libc_realloc = (REALLOC_FUNCTION)dlsym(RTLD_NEXT, realloc_symbol);
        if (!libc_realloc) {
            SMTLOG("*** wrapper does not find [%s] in libc.so\n", realloc_symbol);
            r = 1;
            break;
        }
        libc_calloc = (CALLOC_FUNCTION)dlsym(RTLD_NEXT, calloc_symbol);
        if (!libc_calloc) {
            SMTLOG("*** wrapper does not find [%s] in libc.so\n", calloc_symbol);
            r = 1;
            break;
        }
        libc_posix_memalign = (POSIX_MEMALIGN_FUNCTION)dlsym(RTLD_NEXT, posix_memalign_symbol);
        if (!libc_posix_memalign) {
            SMTLOG("*** wrapper does not find [%s] in libc.so\n", posix_memalign_symbol);
            r = 1;
            break;
        }
        libc_aligned_alloc = (ALIGNED_ALLOC_FUNCTION)dlsym(RTLD_NEXT, aligned_alloc_symbol);
        if (!libc_aligned_alloc) {
            SMTLOG("*** wrapper does not find [%s] in libc.so\n", aligned_alloc_symbol);
            r = 1;
            break;
        }
        libc_memalign = (MEMALIGN_FUNCTION)dlsym(RTLD_NEXT, memalign_symbol);
        if (!libc_memalign) {
            SMTLOG("*** wrapper does not find [%s] in libc.so\n", memalign_symbol);
            r = 1;
            break;
        }
        libc_free = (FREE_FUNCTION)dlsym(RTLD_NEXT, free_symbol);
        if (!libc_free) {
            SMTLOG("*** wrapper does not find [%s] in libc.so\n", free_symbol);
            r = 1;
            break;
        }
        libc_cfree = (CFREE_FUNCTION)dlsym(RTLD_NEXT, cfree_symbol);
        if (!libc_cfree) {
            SMTLOG("*** wrapper does not find [%s] in libc.so\n", cfree_symbol);
            r = 1;
            break;
        }

        if (sem_init(&smtinit_sem, 0, 0)) {
            SMTLOG("*** semaphore init failed\n");
            r = 1;
            break;
        }

        r = 0;
    } while(0);
    calloc_for_dlsym = 0;

    if (r)
        exit(1);

    SMTLOG("malloc hook done, let's post the semaphore\n");
    sem_post(&smtinit_sem);
    
    use_origin_malloc = 1;
    smtmaplist = new std::vector<SMTMap*>();
    if (!smtmaplist) {
        SMTLOG("new AddressMap failed\n");
        exit(1);
    }
    SMTMap* globalmap = new SMTMap("before main()", "main()", 0);
    if (globalmap) {
        globalmap->stopAt("after main()", "main()", 0);
        smtmaplist->push_back(globalmap);
    }
    use_origin_malloc = 0;
}

static char* getlogpath(SMTMap* mmap)
{
    static char logpath[PATH_MAX] = {0, };
    memset(logpath, 0x0, sizeof(logpath));
        char pp[PATH_MAX];
        char buf[PATH_MAX];
        FILE* fp = 0;
        pid_t pid = getpid();
        snprintf(pp, sizeof(pp), "/proc/%d/status", pid);
        fp = fopen(pp, "r");
        if (fp) {
            if (fgets(buf, sizeof(buf)-1, fp))
                sscanf(buf, "%*s %s", pp);
            sprintf(logpath, "%s.%d.memoryleak.%p", pp, pid, mmap);
            fclose(fp);
        }
    return logpath;
}

static void detectmemoryleak(SMTMap* smtmap)
{
    static std::map<void*, std::string> smap;
    size_t lc = 0;
    size_t i = 0;
    char buf[1024];
    std::map<void*, std::string>::iterator sit;
    std::map<void*, MallocNode>::iterator it;
    FILE* f = 0;
    struct timespec before, after;
    char* filepath = 0;
    MMap* mmap = 0;
    if (!smtmap)
        return;
    mmap = &(smtmap->mmap);
    SMTLOG("Found [%ld] Memory Leak \n", mmap->size());
    SMTLOG("From [%s %s %ld]\n", smtmap->startfile, smtmap->startfunction, smtmap->startline);
    SMTLOG("To [%s %s %ld]\n", smtmap->stopfile, smtmap->stopfunction, smtmap->stopline);
    clock_gettime(CLOCK_REALTIME, &before);
    if (!mmap->empty()) {
        filepath = getlogpath(smtmap);
        f = fopen(filepath, "w");
        if (!f) {
            SMTLOG("*** Fail to open log file %s to write\n", filepath);
            return;
        }
    }
    for (it = mmap->begin(); it != mmap->end(); ++it) {
        void* p = it->first;
        size_t sz = it->second.sz;
        void** bt = it->second.bt;
        int j;
        i++;
        fprintf(f, "MEMORYLEAK[%ld][%p, %ld] with BT:\n", i, p, sz);
        for (j = 0; j < BTSZ; j++) {
            Dl_info info;
            const char* cxaDemangled = 0;
            const char* objectpath = 0;
            const char* functionname = 0;
            if (!bt[j])
                break;
            dladdr(bt[j], &info);
            objectpath = info.dli_fname ? info.dli_fname : "(nul)";
            cxaDemangled = info.dli_sname ? abi::__cxa_demangle(info.dli_sname, 0, 0, 0) : 0;
            functionname = cxaDemangled ? cxaDemangled : info.dli_sname ? info.dli_sname : 0;
            if (!functionname)
                if (sit = smap.find(bt[j]), sit != smap.end())
                    functionname = sit->second.c_str();
            if (!functionname) {
                void* address = static_cast<char*>(bt[j]) - 1;
                if (WTF::Symbolize(address, buf, sizeof(buf))) {
                    functionname = buf;
                    smap.insert(std::pair<void*, std::string>(bt[j], std::string(functionname)));
                }
            }
            fprintf(f, "#%d\t%p\t%s\t%s\n", j+1, bt[j], objectpath ? objectpath : "(null)", functionname ? functionname : "(null)");
        }
        lc += sz;
    }
    clock_gettime(CLOCK_REALTIME, &after);
    SMTLOG("Use %lus and %luns and found %ld memory leak\n", after.tv_sec - before.tv_sec, after.tv_nsec - before.tv_nsec, i);
    if (lc) {
        SMTLOG(COLOR_RED"!!!!!!ERROR ERROR ERROR!!!!!!\n");
        SMTLOG(COLOR_RED"!!!!!!ERROR ERROR ERROR!!!!!!\n");
        SMTLOG(COLOR_RED"[%ld]bytes memory leak deteckted\n", lc);
        SMTLOG(COLOR_RED"[%ld]bytes memory leak deteckted\n", lc);
        SMTLOG(COLOR_RED"please check [%s] for more detail\n", filepath);
        SMTLOG(COLOR_RED"!!!!!!ERROR ERROR ERROR!!!!!!\n");
        SMTLOG(COLOR_RED"!!!!!!ERROR ERROR ERROR!!!!!!\n");
    }
    SMTLOG(COLOR_NONE"\n");
    if (f)
        fclose(f);
}

void tr_where(char c, void* p, size_t sz)
{
    void* bt[BTSZ];
    std::vector<SMTMap*>::iterator it;
    SMTMap* smtmap = 0;
    if (!smtmaplist || smtmaplist->empty())
        return;
    use_origin_malloc = 1;
    if (c == '+') {
        backtrace(bt, BTSZ);
        pthread_mutex_lock(&maplock);
        for (it = smtmaplist->begin(); it != smtmaplist->end(); ++it) {
            smtmap = *it;
            if (smtmap)
                smtmap->insert(p, sz, bt);
        }
        pthread_mutex_unlock(&maplock);
    } else {
        pthread_mutex_lock(&maplock);
        for (it = smtmaplist->begin(); it != smtmaplist->end(); ++it) {
            smtmap = *it;
            if (smtmap)
                smtmap->erase(p);
        }
        pthread_mutex_unlock(&maplock);
    }
    use_origin_malloc = 0;
}

void* malloc(size_t sz)
{
    void* r = 0;
    if (!libc_malloc) {
        SMTLOG("wait for smtinit_sem %s %d\n", __FUNCTION__, __LINE__);
        malloc_hook();
    }
    r = libc_malloc(sz);
    if (!use_origin_malloc && r) {
        tr_where('+', r, sz);
    }
    return r;
}

void* realloc(void* p, size_t sz)
{
    void* r = 0;
    if (!libc_realloc) {
        SMTLOG("wait for smtinit_sem %s %d\n", __FUNCTION__, __LINE__);
        malloc_hook();
    }
    r = libc_realloc(p, sz);
    if (!use_origin_malloc && r && r != p) {
        tr_where('+', r, sz);
    }
    return r;
}

static void* static_calloc(size_t size)
{
    static char memory_pool[1024] = {0, };
    static size_t pool_index = 0;
    void* r = 0;
    if (size % 8)
        size += size % 8;
    if (pool_index >= 1024) {
        SMTLOG("*** memory pool is not enough\n");
        return 0;
    }
    r = memory_pool + pool_index + sizeof(size_t) + 2;
    *((size_t*)(memory_pool + pool_index)) = size;
    *(memory_pool + pool_index + sizeof(size_t) + 1) = '+';
    return r;
}

void* calloc(size_t nitems, size_t size)
{
    void* r = 0;
    if (!libc_calloc) {
        if (calloc_for_dlsym)
            return static_calloc(nitems*size);
        SMTLOG("wait for smtinit_sem %s %d\n", __FUNCTION__, __LINE__);
        malloc_hook();
    }
    r = libc_calloc(nitems, size);
    if (!use_origin_malloc && r)
        tr_where('+', r, nitems*size);
    return r;
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    int r;
    if (!libc_posix_memalign) {
        SMTLOG("wait for smtinit_sem %s %d\n", __FUNCTION__, __LINE__);
        malloc_hook();
    }
    r = libc_posix_memalign(memptr, alignment, size);
    if (!use_origin_malloc && *memptr)
        tr_where('+', *memptr, size);
    return r;
}

void *aligned_alloc(size_t alignment, size_t size)
{
    void* r = 0;
    if (!libc_aligned_alloc) {
        SMTLOG("wait for smtinit_sem %s %d\n", __FUNCTION__, __LINE__);
        malloc_hook();
    }
    r = libc_aligned_alloc(alignment, size);
    if (!use_origin_malloc && r)
        tr_where('+', r, size);
    return r;
}

void *memalign(size_t alignment, size_t size)
{
    void* r = 0;
    if (!libc_memalign) {
        SMTLOG("wait for smtinit_sem %s %d\n", __FUNCTION__, __LINE__);
        malloc_hook();
        sem_wait(&smtinit_sem);
    }
    r = libc_memalign(alignment, size);
    if (!use_origin_malloc && r)
        tr_where('+', r, size);
    return r;
}

void free(void* p)
{
    if (p) {
        if (!libc_free) {
            SMTLOG("wait for smtinit_sem %s %d\n", __FUNCTION__, __LINE__);
            malloc_hook();
        }
        libc_free(p);
        if (!use_origin_malloc)
            tr_where('-', p, 0);
    }
}

void cfree(void* p)
{
    if (p) {
        if (!libc_cfree) {
            SMTLOG("wait for smtinit_sem %s %d\n", __FUNCTION__, __LINE__);
            malloc_hook();
        }
        libc_cfree(p);
        if (!use_origin_malloc)
            tr_where('-', p, 0);
    }
}

size_t smtstart(const char* file, const char* function, size_t line)
{
    size_t index = -1;
    SMTLOG("start simple trace malloc from [%s, %s, %ld]\n", file, function, line);
    if (smtmaplist) {
        use_origin_malloc = 1;
        SMTMap* smtmap = new SMTMap(file, function, line);
        if (smtmap) {
            pthread_mutex_lock(&maplock);
            smtmaplist->push_back(smtmap);
            index = smtmaplist->size() - 1;
            pthread_mutex_unlock(&maplock);
        }
        use_origin_malloc = 0;
    }
    return index;
}

void smtstop(size_t index, const char* file, const char* function, size_t line)
{
    SMTLOG("stop simple trace malloc from [%s, %s, %ld]\n", file, function, line);
    SMTMap* smtmap = 0;
    pthread_mutex_lock(&maplock);
    if (!smtmaplist || index >= smtmaplist->size()  || !(smtmap = (*smtmaplist)[index])) {
        pthread_mutex_unlock(&maplock);
        return;
    }
    (*smtmaplist)[index] = 0;
    pthread_mutex_unlock(&maplock);
    SMTLOG("Let's detect memory leak\n");
    SMTLOG("From [%s %s %ld]\n", smtmap->startfile, smtmap->startfunction, smtmap->startline);
    SMTLOG("To [%s %s %ld]\n", file, function, line);
    smtmap->stopAt(file, function, line);
    detectmemoryleak(smtmap);
    use_origin_malloc = 1;
    delete smtmap;
    smtmap = 0;
    use_origin_malloc = 0;
}

}
