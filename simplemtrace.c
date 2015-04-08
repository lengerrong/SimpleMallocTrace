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

#define MALLOC_SYMBOL "malloc"
#define FREE_SYMBOL "free"
#define REALLOC_SYMBOL "realloc"

enum WrapperState {
    WRAPPER_UNINITIALIZED,
    WRAPPER_INITIALIZING,
    WRAPPER_INITIALIZED
};

static void *(*libc_malloc) (size_t) = 0;
static void (*libc_free) (void *) = 0;
static void *(*libc_realloc) (void*, size_t) = 0;

static enum WrapperState wrapper_state = WRAPPER_UNINITIALIZED;
#define WRAPPER_INITIALIZING_INTERVAL 10 // 10 ms

static int use_origin_malloc = 0;
static FILE* mallstream = 0;

#define NAME_OF_LIBC "/lib/x86_64-linux-gnu/libc.so.6"
#define MALL_FILE "malloctrace.log"

#if 0
static pthread_mutex_t lock;
static int lock_result;


#define TRYLOCKMUTEX {\
    lock_resutl = pthread_mutex_trylock(&lock);\
    use_origin_malloc = 1;\
}
#define UNLOCKMUTEX {\
    use_origin_malloc = 0;\
    if (!lock_resutl)\
        pthread_mutex_unlock(&lock);\
}
#endif

void trwhere()
{
#define BTSZ 10
#define BTAL 20
    void* bt[BTSZ];
    int btc, i;
    char btstr[BTSZ*BTAL];
    memset(btstr, ' ', BTSZ*BTAL);

    use_origin_malloc = 1;   
    btc = backtrace(bt, BTSZ);
    use_origin_malloc = 0;

    for (i = 3; i < btc; ++i) {
        snprintf(btstr+(i-3)*BTAL, BTAL, "%p", bt[i]);
    }
    for (i = 0; i <BTSZ*BTAL; i++) {
        if (btstr[i] == '\0')
            btstr[i] = ' ';
    }
    *(btstr+BTSZ*BTAL-1) = '\n';
    fwrite(btstr, 1, BTSZ*BTAL, mallstream);
}

static void load_libc()
{
    void *handle;
    const char *err;
    const char *libcname;
    
    libcname = NAME_OF_LIBC;
    
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
    }
    
    libc_malloc = (void *(*)(size_t))dlsym(handle, MALLOC_SYMBOL);
    if ((err = dlerror()))
    {
        printf("*** wrapper does not find `");
        printf("%s", MALLOC_SYMBOL);
        printf("' in `libc.so'!\n");
        exit(1);
    }
    
    libc_free = (void (*)(void *))dlsym(handle, FREE_SYMBOL);
    if ((err = dlerror()))
    {
        printf("*** wrapper does not find `");
        printf("%s", FREE_SYMBOL);
        printf("' in `libc.so'!\n");
        exit(1);
    }

    use_origin_malloc = true;
    if (!mallstream) {
        mallstream = fopen(MALL_FILE, "w+");
        if (!mallstream) {
            printf("*** can't open mall file\n");
            exit(1);
        }
    }
    use_origin_malloc = false;   
}

static size_t er_malloc_cc = 0;
static size_t er_free_cc = 0;

static void* er_malloc(size_t sz)
{
    void* p = libc_malloc(sz);
    if (p) {
        fprintf(mallstream, "+%p %#lx ", p, (unsigned long int)sz);
        trwhere();
        er_malloc_cc++;
    }
    return p;
}

static char s_mem_pool[1024];
char* s_mem_bottom = s_mem_pool;
char* s_mem_top = s_mem_pool + 1024;
char* s_mem_next = s_mem_pool;

static void* er_static_malloc(size_t sz)
{
    if (s_mem_next + sz > s_mem_top) {
        printf("static memory pool is full");
        return 0;
    }
    void* p = (void*)s_mem_next;
    printf("malloc %p from static memory pool[%p ---> %p]\n", p, s_mem_bottom, s_mem_top);
    s_mem_next += sz;
    return p;
}

static void er_free(void* p)
{
    if (((char*)p - s_mem_bottom) >= 0 && (s_mem_top - (char*)p) >= 0) {
        printf("free %p which is static memory pool[%p ---> %p], do nothing\n", p, s_mem_bottom, s_mem_top);
        return;
    }

    if (p) {
        if (!use_origin_malloc) {
            fprintf(mallstream, "-%p\n", p);
            er_free_cc++;
        }
    }

    return libc_free(p);
}

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
    int lc = 0;

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
        lc++;
        printf("MEMORYLEAK[%d]###########################################################################\n", lc);
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
        printf("MEMORYLEAK[%d]###########################################################################\n", lc);
    }

    return lc;
}

static void aexit_callback(void)
{
#define COLOR_NONE "\033[0;0m"
#define COLOR_RED "\033[5;31m"
#define COLOR_GREEN "\033[0;42m"
#define COLOR_YELLOW "\033[0;33m"
    int memoryleaked = 0;

    printf(COLOR_YELLOW"exit main function, let's check memory leak\n");
    use_origin_malloc = 1;
    if (mallstream) {
        memoryleaked = detectmemoryleak();
        fclose(mallstream);
    }
    
    if (memoryleaked) {
        printf(COLOR_RED"!!!!!!ERROR ERROR ERROR!!!!!!\n");
        printf(COLOR_RED"!!!!!!ERROR ERROR ERROR!!!!!!\n");
        printf(COLOR_RED"[%ld] memory leak deteckted\n", er_malloc_cc - er_free_cc);
        printf(COLOR_RED"[%ld] memory leak deteckted\n", er_malloc_cc - er_free_cc);
        printf(COLOR_RED"!!!!!!ERROR ERROR ERROR!!!!!!\n");
        printf(COLOR_RED"!!!!!!ERROR ERROR ERROR!!!!!!\n");
    } else
        printf(COLOR_GREEN"GOOD PROGRAM, NO MEMORY LEAK\n");
    printf(COLOR_NONE"\n");
}

void* malloc(size_t sz)
{
    void* p = 0;
    if (use_origin_malloc) {
        return libc_malloc(sz);
    }
    switch (wrapper_state) {
    case WRAPPER_UNINITIALIZED:
        wrapper_state = WRAPPER_INITIALIZING;
        load_libc();
        atexit(aexit_callback);
        wrapper_state = WRAPPER_INITIALIZED;
    case WRAPPER_INITIALIZED:
        p = er_malloc(sz);
        break;
    case WRAPPER_INITIALIZING:
        p = er_static_malloc(sz);
        break;
    default:
        break;
    }
    return p;
}

void free(void* p)
{
    if (wrapper_state == WRAPPER_INITIALIZED)
        er_free(p);
    else {
        printf("call free before malloc\n");
        exit(1);
    }
}
