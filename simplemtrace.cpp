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

extern "C" {

static void *(*libc_malloc) (size_t) = 0;
static void (*libc_free) (void *) = 0;
static void *(*libc_realloc) (void*, size_t) = 0;
static void *(*libc_calloc) (size_t, size_t) = 0;
static int (*libc_posix_memalign) (void**, size_t, size_t);
static void *(*libc_aligned_alloc) (size_t, size_t);
static void *(*libc_memalign) (size_t, size_t);

static __thread int use_origin_malloc = 0;
static FILE* mallstream = 0;

#define SMTLOG(...) printf(__VA_ARGS__)

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

// simplemtrace_init will be called before main()
static int simplemtrace_initialize() __attribute__((constructor));

static int simplemtrace_initialize()
{
    const char *err;
    const char* malloc_symbol = "malloc";
    const char* free_symbol = "free";
    const char* realloc_symbol = "realloc";
    const char* calloc_symbol = "calloc";
    const char* posix_memalign_symbol = "posix_memalign";
    const char* aligned_alloc_symbol = "aligned_alloc";
    const char* memalign_symbol = "memalign";

    char logpath[1024] = {'\0', };
    char processName[1024] = {'\0', };
    pid_t pid = getpid();

    if (mallstream)
        return 0;

    use_origin_malloc = 1;
    
    libc_malloc = (void *(*)(size_t))dlsym(RTLD_NEXT, malloc_symbol);
    if ((err = dlerror()))
    {
        SMTLOG("*** wrapper does not find `");
        SMTLOG("%s", malloc_symbol);
        SMTLOG("' in `libc.so'!\n");
        exit(1);
        return 1;
    }
    
    libc_free = (void (*)(void *))dlsym(RTLD_NEXT, free_symbol);
    if ((err = dlerror()))
    {
        SMTLOG("*** wrapper does not find `");
        SMTLOG("%s", free_symbol);
        SMTLOG("' in `libc.so'!\n");
        exit(1);
        return 1;
    }

    libc_realloc = (void*(*)(void*, size_t))dlsym(RTLD_NEXT, realloc_symbol);
    if ((err = dlerror()))
    {
        SMTLOG("*** wrapper does not find `");
        SMTLOG("%s", realloc_symbol);
        SMTLOG("' in `libc.so'!\n");
        exit(1);
        return 1;
    }

    libc_calloc = (void*(*)(size_t, size_t))dlsym(RTLD_NEXT, calloc_symbol);
    if ((err = dlerror()))
    {
        SMTLOG("*** wrapper does not find `");
        SMTLOG("%s", calloc_symbol);
        SMTLOG("' in `libc.so'!\n");
        exit(1);
        return 1;
    }

    libc_posix_memalign = (int (*)(void**, size_t, size_t))dlsym(RTLD_NEXT, posix_memalign_symbol);
    if ((err = dlerror()))
    {
        SMTLOG("*** wrapper does not find `");
        SMTLOG("%s", posix_memalign_symbol);
        SMTLOG("' in `libc.so'!\n");
        exit(1);
        return 1;
    }

    libc_aligned_alloc = (void*(*)(size_t, size_t))dlsym(RTLD_NEXT, aligned_alloc_symbol);
    if ((err = dlerror()))
    {
        SMTLOG("*** wrapper does not find `");
        SMTLOG("%s", aligned_alloc_symbol);
        SMTLOG("' in `libc.so'!\n");
        exit(1);
        return 1;
    }

    libc_memalign = (void*(*)(size_t, size_t))dlsym(RTLD_NEXT, memalign_symbol);
    if ((err = dlerror()))
    {
        SMTLOG("*** wrapper does not find `");
        SMTLOG("%s", memalign_symbol);
        SMTLOG("' in `libc.so'!\n");
        exit(1);
        return 1;
    }

    getProcessName(pid, processName);
    snprintf(logpath, sizeof(logpath), "%s.%d.malloctrace", processName, pid);
    mallstream = fopen(logpath, "w+");
    if (!mallstream) {
        SMTLOG("*** can't open mall file[%s]\n", logpath);
        exit(1);
        return 1;
    }

    use_origin_malloc = 0;

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

static int detectmemoryleak()
{
    if (!mallstream)
        return 0;
    char* line = 0;
    mnode* list = 0;
    size_t lc = 0;
    int index = 0;
    Symbol* sl = 0;

    fflush(mallstream);
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

// memory pool for malloc/ccalloc before simpletrace initialized
static char memorypool[1024*1024];
static int pool_index = 0;
static void* poolmax = (void*)(memorypool + 1024*1024);

void* mfp_memalign(size_t alignment, size_t size)
{
    if ((alignment == 0) || (alignment & (alignment - 1)))
        return 0;

    void* ptr = 0;
    while (1) {
        ptr = memorypool + pool_index;
        if (ptr >= poolmax)
            return 0;
        if (((size_t) ptr & (alignment - 1)) == (size_t) ptr)
            break;
        pool_index++;
    }
    
    if (size % 8)
        size += size % 8;
    pool_index += size;

    return ptr;
}

int mfp_p_align(void** memptr, size_t alignment, size_t size)
{
    void* r = mfp_memalign(alignment, size);
    if (r) {
        *memptr = r;
        return 0;
    }
    return -1;
}

void* mfp_align(size_t alignment, size_t size)
{
    size = size + alignment - (size % alignment);
    return mfp_memalign(alignment, size);
}

void* mfp(size_t sz)
{
    if (sz % 8) {
        sz += sz % 8;
    }
    if ((memorypool + pool_index + sz) >= poolmax) {
        SMTLOG("memory pool is not enough\n");
        return 0;
    }
    void* r = (void*)(memorypool + pool_index);
    pool_index += sz;
    return r;
}

void* malloc(size_t sz)
{
    void* r = 0;
    if (!libc_malloc) {
        return mfp(sz);
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
        return mfp(sz);
    }
    r = libc_realloc(p, sz);
    if (!use_origin_malloc && r && r != p) {
        tr_where('+', r, sz);
    }
    return r;
}

void* calloc(size_t nitems, size_t size)
{
    void* r = 0;
    if (!libc_calloc) {
        return mfp(nitems*size);
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
        return mfp_p_align(memptr, alignment, size);
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
        return mfp_align(alignment, size);
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
        return mfp_memalign(alignment, size);
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
        if (p >= memorypool && p < poolmax) {
            return;
        }
        if (!use_origin_malloc) {
            tr_where('-', p, 0);
        }
        libc_free(p);
    }
}

// simplemtrace_finalize will be called after main()
static int simplemtrace_finalize() __attribute__((destructor));

static int simplemtrace_finalize()
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

}
