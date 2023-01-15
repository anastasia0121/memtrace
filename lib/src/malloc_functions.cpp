#include "tracing_internal.h"

#include <dlfcn.h>
#include <fstream>
#include <iomanip>
#include <limits.h>
#include <link.h>
#include <math.h>
#include <ostream>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

/**
   int posix_memalign(void **ptr, size_t alignment, size_t size);
   void *aligned_alloc(size_t alignment, size_t size);
   void *rallocx(void *ptr, size_t size, int flags);
   size_t xallocx(void *ptr, size_t size, size_t extra, int flags);
   void sdallocx(void *ptr, size_t size, int flags);
   int mallctl(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
   int mallctlnametomib(const char *name, size_t *mibp, size_t *miblenp);
   int mallctlbymib(const size_t *mib, size_t miblen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
*/

using calloc_f = void *(*)(size_t, size_t);
using dallocx_f = void *(*)(void *, int);
using free_f = void *(*)(void *);
using malloc_f = void *(*)(size_t);
using mallocx_f = void *(*)(size_t, int);
using memalign_f = void *(*)(size_t, size_t);
using rallocx_f = void *(*)(void *, size_t, int);
using realloc_f = void *(*)(void *, size_t);
using pthread_getattr_np_f = int (*)(pthread_t, pthread_attr_t *);

static calloc_f s_calloc_p;
static malloc_f s_malloc_p;
static mallocx_f s_mallocx_p;
static memalign_f s_memalign_p; 
static rallocx_f s_rallocx_p;
static dallocx_f s_dallocx_p;
static realloc_f s_realloc_p;
static free_f s_free_p;
static pthread_getattr_np_f pthread_getattr_np_p;

static __attribute__((always_inline)) inline bool initialize()
{
    if (UNLIKELY(!s_malloc_p)) {
        static bool s_init = false;
        if (UNLIKELY(s_init)) {
            return false;
        }

        s_init = true;

        calloc_f calloc_p = reinterpret_cast<calloc_f>(dlsym(RTLD_NEXT, "calloc"));
        malloc_f malloc_p = reinterpret_cast<malloc_f>(dlsym(RTLD_NEXT, "malloc"));
        mallocx_f mallocx_p = reinterpret_cast<mallocx_f>(dlsym(RTLD_NEXT, "mallocx"));
        memalign_f memalign_p = reinterpret_cast<memalign_f>(dlsym(RTLD_NEXT, "memalign"));
        rallocx_f rallocx_p = reinterpret_cast<rallocx_f>(dlsym(RTLD_NEXT, "rallocx"));
        dallocx_f dallocx_p = reinterpret_cast<dallocx_f>(dlsym(RTLD_NEXT, "dallocx"));
        realloc_f realloc_p = reinterpret_cast<realloc_f>(dlsym(RTLD_NEXT, "realloc"));
        free_f free_p = reinterpret_cast<free_f>(dlsym(RTLD_NEXT, "free"));

        s_init = false;

        s_calloc_p = calloc_p;
        s_malloc_p = malloc_p;
        s_mallocx_p = mallocx_p;
        s_memalign_p = memalign_p;
        s_rallocx_p = rallocx_p;
        s_dallocx_p = dallocx_p;
        s_realloc_p = realloc_p;
        s_free_p = free_p;
    }
    return true;
}


extern "C"
{

void *malloc(size_t size)
{
    if (LIKELY(initialize())) {
        void *ptr = s_malloc_p(size);
        memtrace::storage::alloc_ptr(nullptr, size, ptr);
        return ptr;
    }
    return nullptr;
}

void *calloc(size_t number, size_t size)
{
    if (LIKELY(initialize())) {
        void *ptr = s_calloc_p(number, size);
        memtrace::storage::alloc_ptr(nullptr, number * size, ptr);
        return ptr;
    }
    return nullptr;
}

void *mallocx(size_t size, int flags)
{
    if (LIKELY(initialize())) {
        void *ptr = s_mallocx_p(size, flags);
        memtrace::storage::alloc_ptr(nullptr, size, ptr);
        return ptr;
    }
    return nullptr;
}

void *memalign(size_t align, size_t size)
{
    if (LIKELY(initialize())) {
        void *ptr = s_memalign_p(align, size);
        memtrace::storage::alloc_ptr(nullptr, size, ptr);
        return ptr;
    }
    return nullptr;
}

void free(void *ptr)
{
    memtrace::storage::free_ptr(ptr);
    s_free_p(ptr);
}

void dallocx(void *ptr, int flags)
{
    memtrace::storage::free_ptr(ptr);
    s_dallocx_p(ptr, flags);
}

void *realloc(void *ptr, size_t size)
{
    if (LIKELY(initialize())) {
        void *new_ptr = s_realloc_p(ptr, size);
        memtrace::storage::alloc_ptr(ptr, size, new_ptr);
        return new_ptr;
    }
    return nullptr;
}

void *rallocx(void *ptr, size_t size, int flags)
{
    if (LIKELY(initialize())) {
        void *new_ptr = s_rallocx_p(ptr, size, flags);
        memtrace::storage::alloc_ptr(ptr, size, new_ptr);
        return new_ptr;
    }
    return nullptr;
}

/**
 * The function is called on the stack initialization.
 * If someone calles the function earlier then stack bounds are initialized,
 * it can be deadlock.
 */
int pthread_getattr_np(pthread_t thread, pthread_attr_t *attr)
{
    pthread_getattr_np_p = reinterpret_cast<pthread_getattr_np_f>(dlsym(RTLD_NEXT, "pthread_getattr_np"));

    thread_local bool t_in_pthread_getattr_np = false;
    if (UNLIKELY(t_in_pthread_getattr_np)) {
        return -1;
    }

    t_in_pthread_getattr_np = true;
    int ret = pthread_getattr_np_p(thread, attr);
    t_in_pthread_getattr_np = false;

    return ret;
}

}
