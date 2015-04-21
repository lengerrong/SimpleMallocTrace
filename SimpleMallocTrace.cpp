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
#include <errno.h>

#include "Symbolize.h"

extern "C" {

typedef void * (*MALLOC_FUNCTION) (size_t);
typedef void * (*CALLOC_FUNCTION) (size_t, size_t);
typedef void * (*REALLOC_FUNCTION) (void*, size_t);
typedef void (*FREE_FUNCTION) (void*);
typedef void (*CFREE_FUNCTION) (void*);
typedef void * (*MEMALIGN_FUNCTION) (size_t, size_t);
typedef void * (*ALIGNED_ALLOC_FUNCTION) (size_t, size_t);
typedef int (*POSIX_MEMALIGN_FUNCTION) (void**, size_t, size_t);

static __thread MALLOC_FUNCTION libc_malloc = 0;
static __thread CALLOC_FUNCTION libc_calloc = 0;
static __thread REALLOC_FUNCTION libc_realloc = 0;
static __thread FREE_FUNCTION libc_free = 0;
static __thread CFREE_FUNCTION libc_cfree = 0;
static __thread MEMALIGN_FUNCTION libc_memalign = 0;
static __thread ALIGNED_ALLOC_FUNCTION libc_aligned_alloc = 0;
static __thread POSIX_MEMALIGN_FUNCTION libc_posix_memalign = 0;

static __thread int use_origin_malloc = 0;
static __thread int malloc_for_dlsym = 0;

static const char* malloc_symbol = "malloc";
static const char* free_symbol = "free";
static const char* realloc_symbol = "realloc";
static const char* calloc_symbol = "calloc";
static const char* posix_memalign_symbol = "posix_memalign";
static const char* aligned_alloc_symbol = "aligned_alloc";
static const char* memalign_symbol = "memalign";
static const char* cfree_symbol = "cfree";

static FILE* mallstream = 0;
static char logpath[1024] = {'\0', };

#define SMTLOG(...) printf(__VA_ARGS__)

static void getProcessName(pid_t pid, char* processName);
static size_t detectmemoryleak();


// simplemtrace_init will be called before main()
static int simplemalloctrace_initialize() __attribute__((constructor));

static int simplemalloctrace_initialize()
{
    char processName[1024] = {'\0', };
    pid_t pid = getpid();

    if (mallstream)
        return 0;

    use_origin_malloc = 1;

    getProcessName(pid, processName);
    snprintf(logpath, sizeof(logpath), "%s.%d.malloctrace", processName, pid);
    mallstream = fopen(logpath, "w");
    if (!mallstream) {
        SMTLOG("*** can't open mall file[%s]\n", logpath);
        exit(1);
        return 1;
    }

    use_origin_malloc = 0;

    return 0;
}

// simplemtrace_finalize will be called after main()
static int simplemalloctrace_finalize() __attribute__((destructor));

static int simplemalloctrace_finalize()
{
#define COLOR_NONE "\033[0;0m"
#define COLOR_RED "\033[5;31m"
#define COLOR_GREEN "\033[0;42m"
#define COLOR_YELLOW "\033[0;33m"
    size_t memoryleaked = 0;

    if (!mallstream)
        return 0;

    SMTLOG(COLOR_YELLOW"exit main function, let's check memory leak\n");
    use_origin_malloc = 1;
    fclose(mallstream);
    mallstream = fopen(logpath, "r");
    if (mallstream) {
        memoryleaked = detectmemoryleak();
        fclose(mallstream);
        mallstream = 0;
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

static void getProcessName(pid_t pid, char* processName)
{
    char pp[1024];
    char buf[1024];
    FILE* fp = 0;
    snprintf(pp, sizeof(pp), "/proc/%d/status", pid);
    fp = fopen(pp, "r");
    if (!fp)
        return;
    if (fgets(buf, sizeof(buf)-1, fp))
        sscanf(buf, "%*s %s", processName);
    fclose(fp);
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
    if (!mallstream)
        return 0;
    char* line = 0;
    mnode* list = 0;
    size_t lc = 0;
    int index = 0;
    Symbol* sl = 0;

    fseek(mallstream, 0, SEEK_SET);
    
    size_t n = 0;
    while (getline(&line, &n, mallstream) != -1) {
        if (line) {
            switch (*line) {
            case '+':
                addmnode(&list, line);
                break;
            case '-':
                delmnode(&list, line);
                break;
            default:
                break;
            }
        }
    }
    if (line)
        free(line);

    while (list) {
        int i;
        mnode* mn = list;
        list = list->next;
        lc += mn->sz;
        index++;
        SMTLOG("MEMORYLEAK[%d]###########################################################################\n", index);
        SMTLOG("leak memory [%p, %ld]", mn->p, mn->sz);
        SMTLOG("back trace:\n");
        for (i = 0; i < BTSZ; i++) {
            Dl_info info;
            const char* cxaDemangled = 0;
            const char* objectpath = 0;
            const char* functionname = 0;
            char buf[1024] = { '\0' };
            if (!mn->bt[i])
                break;
            dladdr(mn->bt[i], &info);
            objectpath = info.dli_fname ? info.dli_fname : "(nul)";
            cxaDemangled = info.dli_sname ? abi::__cxa_demangle(info.dli_sname, 0, 0, 0) : 0;
            functionname = cxaDemangled ? cxaDemangled : info.dli_sname ? info.dli_sname : 0;
            if (!functionname) {
                functionname = findSymbol(sl, static_cast<char*>(mn->bt[i]) - 1);
            }
            if (!functionname) {
                void* address = static_cast<char*>(mn->bt[i]) - 1;
                if (WTF::Symbolize(address, buf, sizeof(buf))) {
                    functionname = buf;
                    addSymbol(&sl, address, buf);
                }
            }
            SMTLOG("#%d\t%p\t%s\t%s\n", i+1, mn->bt[i], objectpath, functionname ? functionname : "(null)");
        }
        free(mn);
        SMTLOG("MEMORYLEAK[%d]###########################################################################\n", index);
    }

    freeSymbols(sl);

    return lc;
}

void tr_where(char c, void* p, size_t sz)
{
#define BTSZ 10
#define BTAL 20
    void* bt[BTSZ];
    int btc, i;
    char btstr[BTSZ*BTAL];

    if (!mallstream)
        return;

    memset(btstr, ' ', BTSZ*BTAL);

    sprintf(btstr, "%c %p %zx ", c, p, sz);

    if (c == '+') {
        use_origin_malloc = 1;
        btc = backtrace(bt, BTSZ);
        use_origin_malloc = 0;
        for (i = 2; i < btc; ++i) {
            snprintf(btstr+i*BTAL, BTAL, "%p", bt[i]);
        }
        for (i = 0; i <BTSZ*BTAL; i++) {
            if (btstr[i] == '\0' || btstr[i] == '\n')
                btstr[i] = ' ';
        }
    }

    fprintf(mallstream, "%s \n", btstr);
}

void* malloc(size_t sz)
{
    void* r = 0;
    if (!libc_malloc) {
        libc_malloc = (MALLOC_FUNCTION)dlsym(RTLD_NEXT, malloc_symbol);
        if (!libc_malloc) {
            SMTLOG("*** wrapper does not find [%s] in libc.so\n", malloc_symbol);
            exit(1);
            return 0;
        }
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
        libc_realloc = (REALLOC_FUNCTION)dlsym(RTLD_NEXT, realloc_symbol);
        if (!libc_realloc) {
            SMTLOG("*** wrapper does not find [%s] in libc.so\n", realloc_symbol);
            exit(1);
            return 0;
        }
    }
    r = libc_realloc(p, sz);
    if (!use_origin_malloc && r && r != p) {
        tr_where('+', r, sz);
    }
    return r;
}

static void* static_alloc(size_t size)
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
        if (malloc_for_dlsym) {
            return static_alloc(nitems*size);
        }
        malloc_for_dlsym = 1;
        libc_calloc = (CALLOC_FUNCTION)dlsym(RTLD_NEXT, calloc_symbol);
        malloc_for_dlsym = 0;
        if (!libc_calloc) {
            SMTLOG("*** wrapper does not find [%s] in libc.so\n", calloc_symbol);
            exit(1);
            return 0;
        }
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
        libc_posix_memalign = (POSIX_MEMALIGN_FUNCTION)dlsym(RTLD_NEXT, posix_memalign_symbol);
        if (!libc_posix_memalign) {
            SMTLOG("*** wrapper does not find [%s] in libc.so\n", posix_memalign_symbol);
            exit(1);
            return -1;
        }
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
        libc_aligned_alloc = (ALIGNED_ALLOC_FUNCTION)dlsym(RTLD_NEXT, aligned_alloc_symbol);
        if (!libc_aligned_alloc) {
            SMTLOG("*** wrapper does not find [%s] in libc.so\n", aligned_alloc_symbol);
            exit(1);
            return 0;
        }
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
        libc_memalign = (MEMALIGN_FUNCTION)dlsym(RTLD_NEXT, memalign_symbol);
        if (!libc_memalign) {
            SMTLOG("*** wrapper does not find [%s] in libc.so\n", memalign_symbol);
            exit(1);
            return 0;
        }
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
            libc_free = (FREE_FUNCTION)dlsym(RTLD_NEXT, free_symbol);
            if (!libc_free) {
                SMTLOG("*** wrapper does not find [%s] in libc.so\n", free_symbol);
                exit(1);
                return;
            }
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
            libc_cfree = (CFREE_FUNCTION)dlsym(RTLD_NEXT, cfree_symbol);
            if (!libc_cfree) {
                SMTLOG("*** wrapper does not find [%s] in libc.so\n", cfree_symbol);
                exit(1);
                return;
            }
        }
        libc_cfree(p);
        if (!use_origin_malloc) {
            tr_where('-', p, 0);
        }
    }
}

}
