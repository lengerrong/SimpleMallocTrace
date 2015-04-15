#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif 

#include <cxxabi.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <execinfo.h>
#include <pthread.h>

#ifdef NDEBUG
#define LOG(...) ((void)0)
#else
#define LOG(...) {\
    printf("T(%#lx) ", pthread_self()); \
    printf(__VA_ARGS__); \
}
#endif

static void *(*libc_malloc) (size_t) = 0;
static void (*libc_free) (void *) = 0;
static void *(*libc_calloc) (size_t, size_t) = 0;

static __thread int use_origin_malloc = 0;
static void *handle = 0;
static FILE* mallstream = 0;

// simplemtrace_init will be called before main()
static int simplemtrace_initialize() __attribute__((constructor));

static int simplemtrace_initialize()
{
    const char *err;
    const char *libcname;
    const char* mallfile = "malloctrace.log";
    const char* malloc_symbol = "malloc";
    const char* free_symbol = "free";
    const char* calloc_symbol = "calloc";

// TODO...
// define NAME_OF_LIBC in Makefile
#define NAME_OF_LIBC "/lib/x86_64-linux-gnu/libc.so.6"
    libcname = NAME_OF_LIBC;

    printf("before enter main(), let's initialize simple malloc trace\n");

    if (mallstream)
        return 0;

    use_origin_malloc = 1;
    handle = dlopen(libcname, RTLD_NOW);
    if ((err = dlerror()))
    {
        printf("*** wrapper can not open `");
        printf("%s", libcname);
        printf("'!\n");
        printf("*** dlerror() reports: ");
        printf("%s", err);
        printf("\n");
        exit(1);
        return 1;
    }
    
    libc_malloc = (void *(*)(size_t))dlsym(handle, malloc_symbol);
    if ((err = dlerror()))
    {
        printf("*** wrapper does not find `");
        printf("%s", malloc_symbol);
        printf("' in `libc.so'!\n");
        exit(1);
        return 1;
    }
    
    libc_free = (void (*)(void *))dlsym(handle, free_symbol);
    if ((err = dlerror()))
    {
        printf("*** wrapper does not find `");
        printf("%s", free_symbol);
        printf("' in `libc.so'!\n");
        exit(1);
        return 1;
    }

    libc_calloc = (void *(*)(size_t, size_t))dlsym(handle, calloc_symbol);
    if ((err = dlerror()))
    {
        printf("*** wrapper does not find `");
        printf("%s", calloc_symbol);
        printf("' in `libc.so'!\n");
        exit(1);
        return 1;
    }

    mallstream = fopen(mallfile, "w+");
    if (!mallstream) {
        printf("*** can't open mall file\n");
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
    while (mn->bt[i++] = (void*)strtoll(endptr, &endptr, 16));

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

static int detectmemoryleak()
{
    if (!mallstream)
        return 0;
    char* line = 0;
    mnode* list = 0;
    size_t lc = 0;
    int index = 0;

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
        printf("MEMORYLEAK[%d]###########################################################################\n", index);
        printf("leak memory [%p, %ld]", mn->p, mn->sz);
        printf("back trace:\n");
        for (i = 0; i < BTSZ; i++) {
            Dl_info info;
            const char* cxaDemangled = 0;
            const char* objectpath = 0;
            const char* functionname = 0;
            if (!mn->bt[i])
                break;
            dladdr(mn->bt[i], &info);
            objectpath = info.dli_fname ? info.dli_fname : "(nul)";
            cxaDemangled = info.dli_sname ? abi::__cxa_demangle(info.dli_sname, 0, 0, 0) : "(nul)";
            functionname = cxaDemangled ? cxaDemangled : info.dli_sname ? info.dli_sname : "(nul)";
            printf("#%d\t%p\t%s\t%s\n", i+1, mn->bt[i], objectpath, functionname);
        }
        free(mn);
        printf("MEMORYLEAK[%d]###########################################################################\n", index);
    }

    return lc;
}

void tr_where(char c, void* p, size_t sz)
{
#define BTSZ 10
#define BTAL 20
    void* bt[BTSZ];
    int btc, i;
    char btstr[BTSZ*BTAL];
    int l = 0;
    memset(btstr, ' ', BTSZ*BTAL);

    sprintf(btstr, "%c %p %#lx ", c, p, sz);

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
static char memorypool[1024];
static int pool_index = 0;
static void* poolmax = (void*)(memorypool + 1024);
void* mfp(size_t sz)
{
    if ((memorypool + pool_index + sz) >= poolmax) {
        LOG("memory pool is not big enough");
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
        LOG("malloc(%ld) return %p\n", sz, r);
        tr_where('+', r, sz);
    }
    return r;
}

void* calloc(size_t nitems, size_t sz)
{
    void* r = 0;
    if (!libc_calloc) {
        return mfp(sz*nitems);
    }
    r = libc_calloc(nitems, sz);
    if (!use_origin_malloc && r) {
        LOG("calloc(%ld, %ld) return %p\n", nitems, sz, r);
        tr_where('+', r, sz*nitems);
    }
    return r;
}

void free(void* p)
{
    if (p) {
        if (p >= memorypool && p < poolmax) {
            LOG("free %p is in memory pool [%p, %p], do nothing!\n", p, memorypool, poolmax);
            return;
        }
        if (!use_origin_malloc) {
            LOG("free %p\n", p);
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

    printf(COLOR_YELLOW"exit main function, let's check memory leak\n");
    use_origin_malloc = 1;
    if (mallstream) {
        memoryleaked = detectmemoryleak();
        fclose(mallstream);
        mallstream = 0;
    }
    
    if (memoryleaked) {
        printf(COLOR_RED"!!!!!!ERROR ERROR ERROR!!!!!!\n");
        printf(COLOR_RED"!!!!!!ERROR ERROR ERROR!!!!!!\n");
        printf(COLOR_RED"[%ld]bytes memory leak deteckted\n", memoryleaked);
        printf(COLOR_RED"[%ld]bytes memory leak deteckted\n", memoryleaked);
        printf(COLOR_RED"!!!!!!ERROR ERROR ERROR!!!!!!\n");
        printf(COLOR_RED"!!!!!!ERROR ERROR ERROR!!!!!!\n");
    } else
        printf(COLOR_GREEN"GOOD PROGRAM, NO MEMORY LEAK\n");
    printf(COLOR_NONE"\n");

    if (handle)
        dlclose(handle);

    return 0;
}
