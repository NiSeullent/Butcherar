/*
 * 고깃ZIP (GogitZIP) - core base definitions
 * Portable, freestanding-friendly C (no libc required).
 */
#ifndef GZ_BASE_H
#define GZ_BASE_H

#include <stddef.h>
#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   i8;
typedef int32_t  i32;
typedef int64_t  i64;

#if defined(__x86_64__) || defined(_M_X64)
#  define GZ_X64 1
#elif defined(__i386__) || defined(_M_IX86)
#  define GZ_X86 1
#endif

#define GZ_INLINE   static inline __attribute__((always_inline))
#define GZ_NOINLINE __attribute__((noinline))
#define GZ_LIKELY(x)   __builtin_expect(!!(x), 1)
#define GZ_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define GZ_ALIGN(n) __attribute__((aligned(n)))
#define GZ_COUNTOF(a) (sizeof(a) / sizeof((a)[0]))

/* Little-endian unaligned loads (x86 only target). */
GZ_INLINE u16 rd16(const void *p) { u16 v; __builtin_memcpy(&v, p, 2); return v; }
GZ_INLINE u32 rd32(const void *p) { u32 v; __builtin_memcpy(&v, p, 4); return v; }
GZ_INLINE u64 rd64(const void *p) { u64 v; __builtin_memcpy(&v, p, 8); return v; }
GZ_INLINE void wr16(void *p, u16 v) { __builtin_memcpy(p, &v, 2); }
GZ_INLINE void wr32(void *p, u32 v) { __builtin_memcpy(p, &v, 4); }
GZ_INLINE void wr64(void *p, u64 v) { __builtin_memcpy(p, &v, 8); }

/* Error codes shared by every format decoder. */
enum {
    GZ_OK = 0,
    GZ_E_IO = 1,          /* read/write failure                  */
    GZ_E_FORMAT = 2,      /* corrupt / not an archive            */
    GZ_E_DATA = 3,        /* corrupt compressed stream           */
    GZ_E_CRC = 4,         /* checksum mismatch                   */
    GZ_E_METHOD = 5,      /* unsupported compression method      */
    GZ_E_PASSWORD = 6,    /* wrong / missing password            */
    GZ_E_NOMEM = 7,
    GZ_E_CANCEL = 8,
    GZ_E_TRUNC = 9,       /* unexpected end of data              */
    GZ_E_SKIP = 10,       /* entry intentionally skipped         */
    GZ_E_CREATE = 11,     /* cannot create output file           */
    GZ_E_AUTH = 12,       /* AES authentication code mismatch    */
    GZ_E_DISK = 13        /* disk full                           */
};

/* Memory hooks implemented by the platform layer. */
void *gz_alloc(size_t n);          /* zero-initialised */
void *gz_realloc(void *p, size_t n);
void  gz_free(void *p);
void *gz_alloc_big(size_t n);      /* page-aligned, zeroed (VirtualAlloc) */
void  gz_free_big(void *p, size_t n);

#endif
