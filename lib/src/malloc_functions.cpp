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
using aligned_alloc_f = void* (*)(size_t, size_t);
using posix_memalign_f = int (*)(void**, size_t, size_t);
using pthread_getattr_np_f = int (*)(pthread_t, pthread_attr_t *);
using valloc_f = void* (*)(size_t);
using pvalloc_f = void* (*)(size_t);
using reallocarray_f = void* (*)(void*, size_t, size_t);

static calloc_f s_calloc_p;
static malloc_f s_malloc_p;
static mallocx_f s_mallocx_p;
static memalign_f s_memalign_p; 
static rallocx_f s_rallocx_p;
static dallocx_f s_dallocx_p;
static realloc_f s_realloc_p;
static free_f s_free_p;
static aligned_alloc_f s_aligned_alloc_p;
static posix_memalign_f s_posix_memalign_p;
static pthread_getattr_np_f pthread_getattr_np_p;
static valloc_f s_valloc_p;
static pvalloc_f s_pvalloc_p;
static reallocarray_f s_reallocarray_p;

// Type definitions for C++ new/delete operators
using new_operator_f = void* (*)(std::size_t);
using new_array_operator_f = void* (*)(std::size_t);
using new_nothrow_operator_f = void* (*)(std::size_t, const std::nothrow_t&);
using new_array_nothrow_operator_f = void* (*)(std::size_t, const std::nothrow_t&);
using delete_operator_f = void (*)(void*);
using delete_array_operator_f = void (*)(void*);
using delete_nothrow_operator_f = void (*)(void*, const std::nothrow_t&);
using delete_array_nothrow_operator_f = void (*)(void*, const std::nothrow_t&);

#if __cpp_sized_deallocation >= 201309
using delete_sized_operator_f = void (*)(void*, std::size_t);
using delete_array_sized_operator_f = void (*)(void*, std::size_t);
#endif

#if __cpp_aligned_new >= 201606
using new_aligned_operator_f = void* (*)(std::size_t, std::align_val_t);
using new_aligned_nothrow_operator_f = void* (*)(std::size_t, std::align_val_t, const std::nothrow_t &);
using new_array_aligned_operator_f = void* (*)(std::size_t, std::align_val_t);
using new_array_aligned_nothrow_operator_f = void* (*)(std::size_t, std::align_val_t, const std::nothrow_t &);
using delete_aligned_operator_f = void (*)(void*, std::align_val_t);
using delete_aligned_nothrow_operator_f = void (*)(void*, std::align_val_t, const std::nothrow_t &);
using delete_aligned_sized_operator_f = void (*)(void*, std::size_t, std::align_val_t);
using delete_array_aligned_operator_f = void (*)(void*, std::align_val_t);
using delete_array_aligned_nothrow_operator_f = void (*)(void*, std::align_val_t, const std::nothrow_t &);
using delete_array_aligned_sized_operator_f = void (*)(void*, std::size_t, std::align_val_t);
#endif

// Static function pointers for C++ new/delete operators
static new_operator_f s_new_operator_p;
static new_array_operator_f s_new_array_operator_p;
static new_nothrow_operator_f s_new_nothrow_operator_p;
static new_array_nothrow_operator_f s_new_array_nothrow_operator_p;
static delete_operator_f s_delete_operator_p;
static delete_array_operator_f s_delete_array_operator_p;
static delete_nothrow_operator_f s_delete_nothrow_operator_p;
static delete_array_nothrow_operator_f s_delete_array_nothrow_operator_p;

#if __cpp_sized_deallocation >= 201309
static delete_sized_operator_f s_delete_sized_operator_p;
static delete_array_sized_operator_f s_delete_array_sized_operator_p;
#endif

#if __cpp_aligned_new >= 201606
static new_aligned_operator_f s_new_aligned_operator_p;
static new_aligned_nothrow_operator_f s_new_aligned_nothrow_operator_p;
static new_array_aligned_operator_f s_new_array_aligned_operator_p;
static new_array_aligned_nothrow_operator_f s_new_array_aligned_nothrow_operator_p;
static delete_aligned_operator_f s_delete_aligned_operator_p;
static delete_aligned_nothrow_operator_f s_delete_aligned_nothrow_operator_p;
static delete_aligned_sized_operator_f s_delete_aligned_sized_operator_p;
static delete_array_aligned_operator_f s_delete_array_aligned_operator_p;
static delete_array_aligned_nothrow_operator_f s_delete_array_aligned_nothrow_operator_p;
static delete_array_aligned_sized_operator_f s_delete_array_aligned_sized_operator_p;
#endif

static __attribute__((always_inline)) inline void initialize_new_operators()
{
    new_operator_f new_operator_p = reinterpret_cast<new_operator_f>(dlsym(RTLD_NEXT, "_Znwm"));
    new_array_operator_f new_array_operator_p = reinterpret_cast<new_array_operator_f>(dlsym(RTLD_NEXT, "_Znam"));
    new_nothrow_operator_f new_nothrow_operator_p = reinterpret_cast<new_nothrow_operator_f>(dlsym(RTLD_NEXT, "_ZnwmRKSt9nothrow_t"));
    new_array_nothrow_operator_f new_array_nothrow_operator_p = reinterpret_cast<new_array_nothrow_operator_f>(dlsym(RTLD_NEXT, "_ZnamRKSt9nothrow_t"));
    delete_operator_f delete_operator_p = reinterpret_cast<delete_operator_f>(dlsym(RTLD_NEXT, "_ZdlPv"));
    delete_array_operator_f delete_array_operator_p = reinterpret_cast<delete_array_operator_f>(dlsym(RTLD_NEXT, "_ZdaPv"));
    delete_nothrow_operator_f delete_nothrow_operator_p = reinterpret_cast<delete_nothrow_operator_f>(dlsym(RTLD_NEXT, "_ZdlPvRKSt9nothrow_t"));
    delete_array_nothrow_operator_f delete_array_nothrow_operator_p = reinterpret_cast<delete_array_nothrow_operator_f>(dlsym(RTLD_NEXT, "_ZdaPvRKSt9nothrow_t"));

    #if __cpp_sized_deallocation >= 201309
    delete_sized_operator_f delete_sized_operator_p = reinterpret_cast<delete_sized_operator_f>(dlsym(RTLD_NEXT, "_ZdlPvm"));
    delete_array_sized_operator_f delete_array_sized_operator_p = reinterpret_cast<delete_array_sized_operator_f>(dlsym(RTLD_NEXT, "_ZdaPvm"));
    #endif

    #if __cpp_aligned_new >= 201606
    new_aligned_operator_f new_aligned_operator_p = reinterpret_cast<new_aligned_operator_f>(dlsym(RTLD_NEXT, "_ZnwmSt11align_val_t"));
    new_aligned_nothrow_operator_f new_aligned_nothrow_operator_p = reinterpret_cast<new_aligned_nothrow_operator_f>(dlsym(RTLD_NEXT, "_ZnwmSt11align_val_tRKSt9nothrow_t"));
    new_array_aligned_operator_f new_array_aligned_operator_p = reinterpret_cast<new_array_aligned_operator_f>(dlsym(RTLD_NEXT, "_ZnamSt11align_val_t"));
    new_array_aligned_nothrow_operator_f new_array_aligned_nothrow_operator_p = reinterpret_cast<new_array_aligned_nothrow_operator_f>(dlsym(RTLD_NEXT, "_ZnamSt11align_val_tRKSt9nothrow_t"));
    delete_aligned_operator_f delete_aligned_operator_p = reinterpret_cast<delete_aligned_operator_f>(dlsym(RTLD_NEXT, "_ZdlPvSt11align_val_t"));
    delete_aligned_nothrow_operator_f delete_aligned_nothrow_operator_p = reinterpret_cast<delete_aligned_nothrow_operator_f>(dlsym(RTLD_NEXT, "_ZdlPvSt11align_val_tRKSt9nothrow_t"));
    delete_aligned_sized_operator_f delete_aligned_sized_operator_p = reinterpret_cast<delete_aligned_sized_operator_f>(dlsym(RTLD_NEXT, "_ZdlPvmSt11align_val_t"));
    delete_array_aligned_operator_f delete_array_aligned_operator_p = reinterpret_cast<delete_array_aligned_operator_f>(dlsym(RTLD_NEXT, "_ZdaPvSt11align_val_t"));
    delete_array_aligned_nothrow_operator_f delete_array_aligned_nothrow_operator_p = reinterpret_cast<delete_array_aligned_nothrow_operator_f>(dlsym(RTLD_NEXT, "_ZdaPvSt11align_val_tRKSt9nothrow_t"));
    delete_array_aligned_sized_operator_f delete_array_aligned_sized_operator_p = reinterpret_cast<delete_array_aligned_sized_operator_f>(dlsym(RTLD_NEXT, "_ZdaPvmSt11align_val_t"));
    #endif

    s_new_operator_p = new_operator_p;
    s_new_array_operator_p = new_array_operator_p;
    s_new_nothrow_operator_p = new_nothrow_operator_p;
    s_new_array_nothrow_operator_p = new_array_nothrow_operator_p;
    s_delete_operator_p = delete_operator_p;
    s_delete_array_operator_p = delete_array_operator_p;
    s_delete_nothrow_operator_p = delete_nothrow_operator_p;
    s_delete_array_nothrow_operator_p = delete_array_nothrow_operator_p;

    #if __cpp_sized_deallocation >= 201309
    s_delete_sized_operator_p = delete_sized_operator_p;
    s_delete_array_sized_operator_p = delete_array_sized_operator_p;
    #endif

    #if __cpp_aligned_new >= 201606
    s_new_aligned_operator_p = new_aligned_operator_p;
    s_new_aligned_nothrow_operator_p = new_aligned_nothrow_operator_p;
    s_new_array_aligned_operator_p = new_array_aligned_operator_p;
    s_new_array_aligned_nothrow_operator_p = new_array_aligned_nothrow_operator_p;
    s_delete_aligned_operator_p = delete_aligned_operator_p;
    s_delete_aligned_nothrow_operator_p = delete_aligned_nothrow_operator_p;
    s_delete_aligned_sized_operator_p = delete_aligned_sized_operator_p;
    s_delete_array_aligned_operator_p = delete_array_aligned_operator_p;
    s_delete_array_aligned_nothrow_operator_p = delete_array_aligned_nothrow_operator_p;
    s_delete_array_aligned_sized_operator_p = delete_array_aligned_sized_operator_p;
    #endif
}

static __attribute__((always_inline)) inline bool initialize()
{
    if (UNLIKELY(!s_malloc_p)) {
        static bool s_init = false;
        if (UNLIKELY(s_init)) {
            return false;
        }

        s_init = true;

        initialize_new_operators();

        calloc_f calloc_p = reinterpret_cast<calloc_f>(dlsym(RTLD_NEXT, "calloc"));
        malloc_f malloc_p = reinterpret_cast<malloc_f>(dlsym(RTLD_NEXT, "malloc"));
        mallocx_f mallocx_p = reinterpret_cast<mallocx_f>(dlsym(RTLD_NEXT, "mallocx"));
        memalign_f memalign_p = reinterpret_cast<memalign_f>(dlsym(RTLD_NEXT, "memalign"));
        rallocx_f rallocx_p = reinterpret_cast<rallocx_f>(dlsym(RTLD_NEXT, "rallocx"));
        dallocx_f dallocx_p = reinterpret_cast<dallocx_f>(dlsym(RTLD_NEXT, "dallocx"));
        realloc_f realloc_p = reinterpret_cast<realloc_f>(dlsym(RTLD_NEXT, "realloc"));
        free_f free_p = reinterpret_cast<free_f>(dlsym(RTLD_NEXT, "free"));
        aligned_alloc_f aligned_alloc_p = reinterpret_cast<aligned_alloc_f>(dlsym(RTLD_NEXT, "aligned_alloc"));
        posix_memalign_f posix_memalign_p = reinterpret_cast<posix_memalign_f>(dlsym(RTLD_NEXT, "posix_memalign"));
        valloc_f valloc_p = reinterpret_cast<valloc_f>(dlsym(RTLD_NEXT, "valloc"));
        pvalloc_f pvalloc_p = reinterpret_cast<pvalloc_f>(dlsym(RTLD_NEXT, "pvalloc"));
        reallocarray_f reallocarray_p = reinterpret_cast<reallocarray_f>(dlsym(RTLD_NEXT, "reallocarray"));

        s_init = false;

        s_calloc_p = calloc_p;
        s_malloc_p = malloc_p;
        s_mallocx_p = mallocx_p;
        s_memalign_p = memalign_p;
        s_rallocx_p = rallocx_p;
        s_dallocx_p = dallocx_p;
        s_realloc_p = realloc_p;
        s_free_p = free_p;
        s_aligned_alloc_p = aligned_alloc_p;
        s_posix_memalign_p = posix_memalign_p;
        s_valloc_p = valloc_p;
        s_pvalloc_p = pvalloc_p;
        s_reallocarray_p = reallocarray_p;
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
    if (LIKELY(initialize())) {
        memtrace::storage::free_ptr(ptr);
        s_free_p(ptr);
    }
}

void dallocx(void *ptr, int flags)
{
    if (LIKELY(initialize())) {
        memtrace::storage::free_ptr(ptr);
        s_dallocx_p(ptr, flags);
    }
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

void *aligned_alloc(size_t alignment, size_t size)
{
    if (LIKELY(initialize())) {
        void* ptr = s_aligned_alloc_p(alignment, size);
        memtrace::storage::alloc_ptr(nullptr, size, ptr);
        return ptr;
    }
    return nullptr;
}

int posix_memalign(void** memptr, size_t alignment, size_t size)
{
    if (LIKELY(initialize())) {
        int ret = s_posix_memalign_p(memptr, alignment, size);
        if (ret == 0) {
            memtrace::storage::alloc_ptr(nullptr, size, *memptr);
        }
        return ret;
    }
    return ENOMEM;
}

void *valloc(size_t size)
{
    if (LIKELY(initialize())) {
        void* ptr = s_valloc_p(size);
        memtrace::storage::alloc_ptr(nullptr, size, ptr);
        return ptr;
    }
    return nullptr;
}

void *pvalloc(size_t size)
{
    if (LIKELY(initialize())) {
        void* ptr = s_pvalloc_p(size);
        memtrace::storage::alloc_ptr(nullptr, size, ptr);
        return ptr;
    }
    return nullptr;
}

void *reallocarray(void* ptr, size_t nmemb, size_t size)
{
    if (LIKELY(initialize())) {
        void* new_ptr = s_reallocarray_p(ptr, nmemb, size);
        memtrace::storage::alloc_ptr(ptr, nmemb * size, new_ptr);
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

void *operator new(std::size_t size)
{
    if (LIKELY(initialize())) {
        void *ptr = s_new_operator_p(size);
        memtrace::storage::alloc_ptr(nullptr, size, ptr);
        return ptr;
    }
    return nullptr;
}

void *operator new[](std::size_t size)
{
    if (LIKELY(initialize())) {
        void *ptr = s_new_array_operator_p(size);
        memtrace::storage::alloc_ptr(nullptr, size, ptr);
        return ptr;
    }
    return nullptr;
}

void *operator new(std::size_t size, const std::nothrow_t &nothrow) noexcept
{
    if (LIKELY(initialize())) {
        void *ptr = s_new_nothrow_operator_p(size, nothrow);
        memtrace::storage::alloc_ptr(nullptr, size, ptr);
        return ptr;
    }
    return nullptr;
}

void *operator new[](std::size_t size, const std::nothrow_t &nothrow) noexcept
{
    if (LIKELY(initialize())) {
        void *ptr = s_new_array_nothrow_operator_p(size, nothrow);
        memtrace::storage::alloc_ptr(nullptr, size, ptr);
        return ptr;
    }
    return nullptr;
}

void operator delete(void *ptr) noexcept
{
    if (LIKELY(initialize())) {
        memtrace::storage::free_ptr(ptr);
        s_delete_operator_p(ptr);
    }
}

void operator delete[](void *ptr) noexcept
{
    if (LIKELY(initialize())) {
        memtrace::storage::free_ptr(ptr);
        s_delete_array_operator_p(ptr);
    }
}

void operator delete(void *ptr, const std::nothrow_t &nothrow) noexcept
{
    if (LIKELY(initialize())) {
        memtrace::storage::free_ptr(ptr);
        s_delete_nothrow_operator_p(ptr, nothrow);
    }
}

void operator delete[](void *ptr, const std::nothrow_t &nothrow) noexcept
{
    if (LIKELY(initialize())) {
        memtrace::storage::free_ptr(ptr);
        s_delete_array_nothrow_operator_p(ptr, nothrow);
    }
}

#if __cpp_sized_deallocation >= 201309
/* C++14's sized-delete operators. */
void operator delete(void *ptr, std::size_t size) noexcept
{
    if (LIKELY(initialize())) {
        memtrace::storage::free_ptr(ptr);
        s_delete_sized_operator_p(ptr, size);
    }
}

void operator delete[](void *ptr, std::size_t size) noexcept
{
    if (LIKELY(initialize())) {
        memtrace::storage::free_ptr(ptr);
        s_delete_array_sized_operator_p(ptr, size);
    }
}
#endif

#if __cpp_aligned_new >= 201606
/* C++17's over-aligned operators. */
void *operator new(std::size_t size, std::align_val_t align)
{
    if (LIKELY(initialize())) {
        void *ptr = s_new_aligned_operator_p(size, align);
        memtrace::storage::alloc_ptr(nullptr, size, ptr);
        return ptr;
    }
    return nullptr;

}

void *operator new(std::size_t size, std::align_val_t align, const std::nothrow_t &nothrow) noexcept
{
    if (LIKELY(initialize())) {
        void *ptr = s_new_aligned_nothrow_operator_p(size, align, nothrow);
        memtrace::storage::alloc_ptr(nullptr, size, ptr);
        return ptr;
    }
    return nullptr;
}

void *operator new[](std::size_t size, std::align_val_t align)
{
    if (LIKELY(initialize())) {
        void *ptr = s_new_array_aligned_operator_p(size, align);
        memtrace::storage::alloc_ptr(nullptr, size, ptr);
        return ptr;
    }
    return nullptr;
}

void *operator new[](std::size_t size, std::align_val_t align, const std::nothrow_t &nothrow) noexcept
{
    if (LIKELY(initialize())) {
        void *ptr = s_new_array_aligned_nothrow_operator_p(size, align, nothrow);
        memtrace::storage::alloc_ptr(nullptr, size, ptr);
        return ptr;
    }
    return nullptr;
}

void operator delete(void* ptr, std::align_val_t align) noexcept
{
    if (LIKELY(initialize())) {
        memtrace::storage::free_ptr(ptr);
        s_delete_aligned_operator_p(ptr, align);
    }
}

void operator delete(void* ptr, std::align_val_t align, const std::nothrow_t &nothrow) noexcept
{
    if (LIKELY(initialize())) {
        memtrace::storage::free_ptr(ptr);
        s_delete_aligned_nothrow_operator_p(ptr, align, nothrow);
    }
}

void operator delete(void* ptr, std::size_t size, std::align_val_t align) noexcept
{
    if (LIKELY(initialize())) {
        memtrace::storage::free_ptr(ptr);
        s_delete_aligned_sized_operator_p(ptr, size, align);
    }
}

void operator delete[](void* ptr, std::align_val_t align) noexcept
{
    if (LIKELY(initialize())) {
        memtrace::storage::free_ptr(ptr);
        s_delete_array_aligned_operator_p(ptr, align);
    }
}

void operator delete[](void* ptr, std::align_val_t align, const std::nothrow_t &nothrow) noexcept
{
    if (LIKELY(initialize())) {
        memtrace::storage::free_ptr(ptr);
        s_delete_array_aligned_nothrow_operator_p(ptr, align, nothrow);
    }
}

void operator delete[](void* ptr, std::size_t size, std::align_val_t align) noexcept
{
    if (LIKELY(initialize())) {
        memtrace::storage::free_ptr(ptr);
        s_delete_array_aligned_sized_operator_p(ptr, size, align);
    }
}
#endif
