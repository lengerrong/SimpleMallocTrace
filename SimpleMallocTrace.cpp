#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif 

#include <cxxabi.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <execinfo.h>
#include <pthread.h>

#include "Symbolize.h"
#include "AddressMap.h"
#include "semaphore.h"

extern "C" {

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
static AddressMap* smtmap = 0;
static sem_t smtinit_sem;

#define SMTLOG(...) printf(__VA_ARGS__)

static size_t detectmemoryleak();

// simplemalloctrace_initialize will be called before main()
static int simplemalloctrace_initialize() __attribute__((constructor));

static int __attribute__((constructor)) backtrace_init()
{
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
    void* buffer[1];
    backtrace(buffer, 1);
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
    smtmap = new AddressMap;
    if (!smtmap) {
        SMTLOG("new AddressMap failed\n");
        exit(1);
    }
    use_origin_malloc = 0;
}

static int simplemalloctrace_initialize()
{
    malloc_hook();

    if (pthread_mutex_init(&maplock, 0)) {
        SMTLOG("Mutex init failed!\n");
        exit(1);
    }

    return 0;
}

// simplemalloctrace_finalize will be called after main()
static int simplemalloctrace_finalize() __attribute__((destructor));

static int simplemalloctrace_finalize()
{
#define COLOR_NONE "\033[0;0m"
#define COLOR_RED "\033[5;31m"
#define COLOR_GREEN "\033[0;42m"
#define COLOR_YELLOW "\033[0;33m"
    size_t memoryleaked = 0;

    SMTLOG(COLOR_YELLOW"exit main function, let's check memory leak\n");

    pthread_mutex_destroy(&maplock);

    use_origin_malloc = 1;
    if (smtmap) {
        memoryleaked = detectmemoryleak();
        delete smtmap;
        smtmap = 0;
    }

    if (memoryleaked) {
        SMTLOG(COLOR_RED"!!!!!!ERROR ERROR ERROR!!!!!!\n");
        SMTLOG(COLOR_RED"!!!!!!ERROR ERROR ERROR!!!!!!\n");
        SMTLOG(COLOR_RED"[%ld]bytes memory leak deteckted\n", memoryleaked);
        SMTLOG(COLOR_RED"[%ld]bytes memory leak deteckted\n", memoryleaked);
        SMTLOG(COLOR_RED"!!!!!!ERROR ERROR ERROR!!!!!!\n");
        SMTLOG(COLOR_RED"!!!!!!ERROR ERROR ERROR!!!!!!\n");
    } else
        SMTLOG(COLOR_GREEN"GOOD PROGRAM, NO MEMORY LEAK\n");
    SMTLOG(COLOR_NONE"\n");

    return 0;
}

#define BTSZ 10
#define BTAL 20

typedef struct _mnode{
    void* p;
    size_t sz;
    void* bt[BTSZ];
    struct _mnode* next;
}mnode;

void addmnode(mnode** mlp, char* line)
{
    int i;
    char* endptr;
    mnode* mn = (mnode*)malloc(sizeof(mnode));
    if (!mn) {
        return;
    }
    memset(mn, 0x00, sizeof(mnode));

    endptr = line+1;
    mn->p = (void*)strtoll(endptr, &endptr, 16);
    mn->sz = strtoll(endptr, &endptr, 16);
    i = 0;
    while ((mn->bt[i++] = (void*)strtoll(endptr, &endptr, 16)));

    if (*mlp) {
        mnode* t = *mlp;
        while (t && t->next)
            t = t->next;
        t->next = mn;
    } else
        *mlp = mn;
}

void delmnode(mnode** mlp, char* line)
{
    void* p = (void*)strtoll(line+1, 0, 16);
    mnode* ml = *mlp;
    mnode* mp = 0;
    while (ml) {
        if (ml->p == p) {
            if (mp) {
                mp->next = ml->next;
            } else {
                *mlp = ml->next;
            }
            free(ml);
            break;
        }
        mp = ml;
        ml = ml->next;
    }
}

typedef struct _Symbol {
    void* address;
    char symbol[1024];
    struct _Symbol* next;
} Symbol;

char* findSymbol(Symbol* head, void* address)
{
    if (!head)
        return 0;
    while (head) {
        if (head->address == address)
            return head->symbol;
        head = head->next;
    }
    return 0;
}

void addSymbol(Symbol** phead, void* address, char* symbol)
{
    Symbol* h = *phead;
    Symbol* s = (Symbol*)malloc(sizeof(Symbol));
    if (!s)
        return;
    s->address = address;
    snprintf(s->symbol, sizeof(s->symbol), "%s", symbol);
    s->next = 0;
    if (h) {
        while (h && h->next)
            h = h->next;
        h->next = s;
    } else {
        *phead = s;
    }
}

void freeSymbols(Symbol* head)
{
    while (head) {
        Symbol* s = head;
        head = head->next;
        free(s);
    }
}

static size_t detectmemoryleak()
{
    size_t lc = 0;
    size_t i;
    size_t sz = smtmap->size();
    Symbol* sl = 0;

    for (i = 0; i < sz; i++) {
        SMTLOG("MEMORYLEAK[%ld]###########################################################################\n", i+1);
        AddressInfo* ai = (*smtmap)[i];
        SMTLOG("leak memory [%p, %ld]", ai->addr, ai->sz);
        lc += ai->sz;
        SMTLOG("back trace:\n");
        int j;
        for (j = 0; j < BTSZ; j++) {
            Dl_info info;
            const char* cxaDemangled = 0;
            const char* objectpath = 0;
            const char* functionname = 0;
            char buf[1024] = { '\0' };
            if (!ai->bt[j])
                break;
            dladdr(ai->bt[j], &info);
            objectpath = info.dli_fname ? info.dli_fname : "(nul)";
            cxaDemangled = info.dli_sname ? abi::__cxa_demangle(info.dli_sname, 0, 0, 0) : 0;
            functionname = cxaDemangled ? cxaDemangled : info.dli_sname ? info.dli_sname : 0;
            if (!functionname) {
                functionname = findSymbol(sl, static_cast<char*>(ai->bt[j]) - 1);
            }
            if (!functionname) {
                void* address = static_cast<char*>(ai->bt[j]) - 1;
                if (WTF::Symbolize(address, buf, sizeof(buf))) {
                    functionname = buf;
                    addSymbol(&sl, address, buf);
                }
            }
            SMTLOG("#%d\t%p\t%s\t%s\n", j+1, ai->bt[j], objectpath, functionname ? functionname : "(null)");
        }
        SMTLOG("MEMORYLEAK[%ld]###########################################################################\n", i+1);
    }

    freeSymbols(sl);

    return lc;
}

void tr_where(char c, void* p, size_t sz)
{
#define BTSZ 10
#define BTAL 20
    void* bt[BTSZ];
    if (!smtmap)
        return;

    use_origin_malloc = 1;
    if (c == '+') {
        backtrace(bt, BTSZ);
        pthread_mutex_lock(&maplock);
        smtmap->append(p, sz, bt);
        pthread_mutex_unlock(&maplock);
    } else {
        pthread_mutex_lock(&maplock);
        smtmap->remove(p);
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
    if (!use_origin_malloc && r) {
        tr_where('+', r, nitems*size);
    }
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
    if (!use_origin_malloc && *memptr) {
        tr_where('+', *memptr, size);
    }
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
    if (!use_origin_malloc && r) {
        tr_where('+', r, size);
    }
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
    if (!use_origin_malloc && r) {
        tr_where('+', r, size);
    }
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
        if (!use_origin_malloc) {
            tr_where('-', p, 0);
        }
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
        if (!use_origin_malloc) {
            tr_where('-', p, 0);
        }
    }
}

}
