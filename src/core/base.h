/*
 * 고깃ZIP (GogitZIP) - core base definitions
 * Portable, freestanding-friendly C11 (no libc required by the core).
 * Targets: x86 / x86-64 (Windows 2000+, Linux, macOS) and AArch64 (Linux, macOS).
 * All supported targets are little-endian.
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
typedef int16_t  i16;
typedef int32_t  i32;
typedef int64_t  i64;

/* UTF-16 code unit. Same type as wchar_t on Windows (MinGW: unsigned short),
 * and as C11 char16_t, so u"text" literals can be used everywhere. */
typedef unsigned short gzch;

#if defined(__x86_64__) || defined(_M_X64)
#  define GZ_X64 1
#  define GZ_X86_ANY 1
#elif defined(__i386__) || defined(_M_IX86)
#  define GZ_X86 1
#  define GZ_X86_ANY 1
#elif defined(__aarch64__) || defined(_M_ARM64)
#  define GZ_ARM64 1
#endif

#if defined(_WIN32)
#  define GZ_OS_WIN 1
#elif defined(__APPLE__)
#  define GZ_OS_MAC 1
#  define GZ_OS_POSIX 1
#else
#  define GZ_OS_LINUX 1
#  define GZ_OS_POSIX 1
#endif

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#  error "GogitZIP assumes a little-endian target"
#endif

#define GZ_INLINE   static inline __attribute__((always_inline))
#define GZ_NOINLINE __attribute__((noinline))
#define GZ_LIKELY(x)   __builtin_expect(!!(x), 1)
#define GZ_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define GZ_ALIGN(n) __attribute__((aligned(n)))
#define GZ_COUNTOF(a) (sizeof(a) / sizeof((a)[0]))
#define GZ_MIN(a, b) ((a) < (b) ? (a) : (b))
#define GZ_MAX(a, b) ((a) > (b) ? (a) : (b))

/* "size not known" marker for decoders and entries */
#define GZ_SIZE_UNKNOWN (~(u64)0)

/* Little-endian unaligned loads/stores. */
GZ_INLINE u16 rd16(const void *p) { u16 v; __builtin_memcpy(&v, p, 2); return v; }
GZ_INLINE u32 rd32(const void *p) { u32 v; __builtin_memcpy(&v, p, 4); return v; }
GZ_INLINE u64 rd64(const void *p) { u64 v; __builtin_memcpy(&v, p, 8); return v; }
GZ_INLINE void wr16(void *p, u16 v) { __builtin_memcpy(p, &v, 2); }
GZ_INLINE void wr32(void *p, u32 v) { __builtin_memcpy(p, &v, 4); }
GZ_INLINE void wr64(void *p, u64 v) { __builtin_memcpy(p, &v, 8); }
/* Big-endian loads/stores (ISO, HFS, APFS, squashfs-be, ...). */
GZ_INLINE u16 rd16be(const void *p) { return __builtin_bswap16(rd16(p)); }
GZ_INLINE u32 rd32be(const void *p) { return __builtin_bswap32(rd32(p)); }
GZ_INLINE u64 rd64be(const void *p) { return __builtin_bswap64(rd64(p)); }
GZ_INLINE void wr16be(void *p, u16 v) { wr16(p, __builtin_bswap16(v)); }
GZ_INLINE void wr32be(void *p, u32 v) { wr32(p, __builtin_bswap32(v)); }
GZ_INLINE void wr64be(void *p, u64 v) { wr64(p, __builtin_bswap64(v)); }

/* Error codes shared by every codec, format, writer and the engines. */
enum {
    GZ_OK = 0,
    GZ_E_IO = 1,          /* read/write failure                          */
    GZ_E_FORMAT = 2,      /* corrupt / not an archive                    */
    GZ_E_DATA = 3,        /* corrupt compressed stream                   */
    GZ_E_CRC = 4,         /* checksum mismatch                           */
    GZ_E_METHOD = 5,      /* unsupported compression method / feature    */
    GZ_E_PASSWORD = 6,    /* wrong / missing password                    */
    GZ_E_NOMEM = 7,
    GZ_E_CANCEL = 8,
    GZ_E_TRUNC = 9,       /* unexpected end of data                      */
    GZ_E_SKIP = 10,       /* entry intentionally skipped                 */
    GZ_E_CREATE = 11,     /* cannot create output file                   */
    GZ_E_AUTH = 12,       /* authentication code (HMAC) mismatch         */
    GZ_E_DISK = 13,       /* disk full                                   */
    GZ_E_VOLUME = 14,     /* next volume of a multi-volume set missing   */
    GZ_E_LIMIT = 15,      /* exceeds a safety limit (dictionary, size)   */
    GZ_E_COUNT
};

/* Memory hooks implemented by the platform layer. */
void *gz_alloc(size_t n);          /* zero-initialised, NULL on failure     */
void *gz_realloc(void *p, size_t n);
void  gz_free(void *p);
void *gz_alloc_big(size_t n);      /* page-aligned, zeroed (VirtualAlloc/mmap) */
void  gz_free_big(void *p, size_t n);

#endif
