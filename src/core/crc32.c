/*
 * 고깃ZIP - CRC-32 (IEEE 802.3, reflected 0xEDB88320)
 *
 *   gz_crc32_slice8   portable slice-by-8 tables          (any x86)
 *   gz_crc32_pclmul   4x128-bit carry-less folding        (SSE4.1 + PCLMULQDQ)
 *   gz_crc32_avx      same, VEX encoded                   (AVX, Win7 SP1+)
 *   gz_crc32_vpclmul  4x256-bit folding with VPCLMULQDQ   (AVX2 + VPCLMULQDQ)
 *
 * Folding method: V. Gopal et al., "Fast CRC Computation for Generic
 * Polynomials Using PCLMULQDQ Instruction", Intel 2009.
 */
#include "crc32.h"

#if defined(__i386__) || defined(__x86_64__)
#include <immintrin.h>
#define GZ_HAVE_CLMUL 1
#endif

u32 gz_crc_table[8][256];
gz_crc32_fn gz_crc32_kernel = gz_crc32_slice8;

void gz_crc32_init(void)
{
    for (u32 i = 0; i < 256; i++) {
        u32 c = i;
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1)));
        gz_crc_table[0][i] = c;
    }
    for (u32 i = 0; i < 256; i++) {
        u32 c = gz_crc_table[0][i];
        for (int t = 1; t < 8; t++) {
            c = gz_crc_table[0][c & 0xff] ^ (c >> 8);
            gz_crc_table[t][i] = c;
        }
    }
}

u32 gz_crc32_byte(u32 s, u8 b)
{
    return gz_crc_table[0][(s ^ b) & 0xff] ^ (s >> 8);
}

static u32 crc_raw_slice8(u32 c, const u8 *p, size_t n)
{
    while (n && ((uintptr_t)p & 7)) {
        c = gz_crc_table[0][(c ^ *p++) & 0xff] ^ (c >> 8);
        n--;
    }
    while (n >= 8) {
        u32 a = rd32(p) ^ c;
        u32 b = rd32(p + 4);
        c = gz_crc_table[7][a & 0xff] ^ gz_crc_table[6][(a >> 8) & 0xff] ^
            gz_crc_table[5][(a >> 16) & 0xff] ^ gz_crc_table[4][a >> 24] ^
            gz_crc_table[3][b & 0xff] ^ gz_crc_table[2][(b >> 8) & 0xff] ^
            gz_crc_table[1][(b >> 16) & 0xff] ^ gz_crc_table[0][b >> 24];
        p += 8; n -= 8;
    }
    while (n--) c = gz_crc_table[0][(c ^ *p++) & 0xff] ^ (c >> 8);
    return c;
}

u32 gz_crc32_slice8(u32 crc, const u8 *p, size_t n)
{
    return ~crc_raw_slice8(~crc, p, n);
}

#ifdef GZ_HAVE_CLMUL

/* (x^(D+32) mod P)' << 1, (x^(D-32) mod P)' << 1 for the fold distances D. */
#define K_FOLD512_LO  0x0154442bd4ULL
#define K_FOLD512_HI  0x01c6e41596ULL
#define K_FOLD128_LO  0x01751997d0ULL
#define K_FOLD128_HI  0x00ccaa009eULL
#define K_FOLD64      0x0163cd6124ULL
#define K_POLY_P      0x01db710641ULL   /* P(x)' */
#define K_POLY_MU     0x01f7011641ULL   /* Barrett mu' */
#define K_FOLD1024_LO 0x01e88ef372ULL
#define K_FOLD1024_HI 0x014a7fe880ULL
#define K_FOLD256_LO  0x00f1da05aaULL
#define K_FOLD256_HI  0x015a546366ULL

#define CLMUL_TAIL_BODY                                                       \
    /* single 16-byte folds */                                                \
    while (len >= 16) {                                                       \
        __m128i y = _mm_loadu_si128((const __m128i *)buf);                    \
        __m128i t = _mm_clmulepi64_si128(x1, k128, 0x00);                     \
        x1 = _mm_clmulepi64_si128(x1, k128, 0x11);                            \
        x1 = _mm_xor_si128(_mm_xor_si128(x1, t), y);                          \
        buf += 16; len -= 16;                                                 \
    }                                                                         \
    /* 128 -> 64 bits */                                                      \
    {                                                                         \
        __m128i mask32 = _mm_setr_epi32(-1, 0, -1, 0);                        \
        __m128i x2 = _mm_clmulepi64_si128(x1, k128, 0x10);                    \
        x1 = _mm_srli_si128(x1, 8);                                           \
        x1 = _mm_xor_si128(x1, x2);                                           \
        __m128i k5 = _mm_set_epi64x(0, (long long)K_FOLD64);                  \
        x2 = _mm_srli_si128(x1, 4);                                           \
        x1 = _mm_and_si128(x1, mask32);                                       \
        x1 = _mm_clmulepi64_si128(x1, k5, 0x00);                              \
        x1 = _mm_xor_si128(x1, x2);                                           \
        /* Barrett reduction to 32 bits */                                    \
        __m128i pm = _mm_set_epi64x((long long)K_POLY_MU, (long long)K_POLY_P);\
        x2 = _mm_and_si128(x1, mask32);                                       \
        x2 = _mm_clmulepi64_si128(x2, pm, 0x10);                              \
        x2 = _mm_and_si128(x2, mask32);                                       \
        x2 = _mm_clmulepi64_si128(x2, pm, 0x00);                              \
        x1 = _mm_xor_si128(x1, x2);                                           \
        crc = (u32)_mm_extract_epi32(x1, 1);                                  \
    }

/* raw state in/out; len >= 64 and a multiple of 16 */
#define CLMUL_FOLD_BODY                                                       \
    __m128i k512 = _mm_set_epi64x((long long)K_FOLD512_HI, (long long)K_FOLD512_LO); \
    __m128i k128 = _mm_set_epi64x((long long)K_FOLD128_HI, (long long)K_FOLD128_LO); \
    __m128i x1 = _mm_loadu_si128((const __m128i *)(buf + 0x00));              \
    __m128i x2 = _mm_loadu_si128((const __m128i *)(buf + 0x10));              \
    __m128i x3 = _mm_loadu_si128((const __m128i *)(buf + 0x20));              \
    __m128i x4 = _mm_loadu_si128((const __m128i *)(buf + 0x30));              \
    x1 = _mm_xor_si128(x1, _mm_cvtsi32_si128((int)crc));                      \
    buf += 64; len -= 64;                                                     \
    while (len >= 64) {                                                       \
        __m128i t1 = _mm_clmulepi64_si128(x1, k512, 0x00);                    \
        __m128i t2 = _mm_clmulepi64_si128(x2, k512, 0x00);                    \
        __m128i t3 = _mm_clmulepi64_si128(x3, k512, 0x00);                    \
        __m128i t4 = _mm_clmulepi64_si128(x4, k512, 0x00);                    \
        x1 = _mm_clmulepi64_si128(x1, k512, 0x11);                            \
        x2 = _mm_clmulepi64_si128(x2, k512, 0x11);                            \
        x3 = _mm_clmulepi64_si128(x3, k512, 0x11);                            \
        x4 = _mm_clmulepi64_si128(x4, k512, 0x11);                            \
        x1 = _mm_xor_si128(_mm_xor_si128(x1, t1), _mm_loadu_si128((const __m128i *)(buf + 0x00))); \
        x2 = _mm_xor_si128(_mm_xor_si128(x2, t2), _mm_loadu_si128((const __m128i *)(buf + 0x10))); \
        x3 = _mm_xor_si128(_mm_xor_si128(x3, t3), _mm_loadu_si128((const __m128i *)(buf + 0x20))); \
        x4 = _mm_xor_si128(_mm_xor_si128(x4, t4), _mm_loadu_si128((const __m128i *)(buf + 0x30))); \
        buf += 64; len -= 64;                                                 \
    }                                                                         \
    /* fold 4 -> 1 */                                                         \
    {                                                                         \
        __m128i t = _mm_clmulepi64_si128(x1, k128, 0x00);                     \
        x1 = _mm_clmulepi64_si128(x1, k128, 0x11);                            \
        x1 = _mm_xor_si128(_mm_xor_si128(x1, t), x2);                         \
        t = _mm_clmulepi64_si128(x1, k128, 0x00);                             \
        x1 = _mm_clmulepi64_si128(x1, k128, 0x11);                            \
        x1 = _mm_xor_si128(_mm_xor_si128(x1, t), x3);                         \
        t = _mm_clmulepi64_si128(x1, k128, 0x00);                             \
        x1 = _mm_clmulepi64_si128(x1, k128, 0x11);                            \
        x1 = _mm_xor_si128(_mm_xor_si128(x1, t), x4);                         \
    }                                                                         \
    CLMUL_TAIL_BODY

__attribute__((target("sse4.1,pclmul")))
static u32 crc_raw_pclmul(u32 crc, const u8 *buf, size_t len)
{
    CLMUL_FOLD_BODY
    return crc;
}

__attribute__((target("avx,pclmul")))
static u32 crc_raw_avx(u32 crc, const u8 *buf, size_t len)
{
    CLMUL_FOLD_BODY
    return crc;
}

/* len >= 256, multiple of 16 */
__attribute__((target("avx2,pclmul,vpclmulqdq")))
static u32 crc_raw_vpclmul(u32 crc, const u8 *buf, size_t len)
{
    const __m256i k1024 = _mm256_set_epi64x((long long)K_FOLD1024_HI, (long long)K_FOLD1024_LO,
                                            (long long)K_FOLD1024_HI, (long long)K_FOLD1024_LO);
    const __m256i k256 = _mm256_set_epi64x((long long)K_FOLD256_HI, (long long)K_FOLD256_LO,
                                           (long long)K_FOLD256_HI, (long long)K_FOLD256_LO);
    __m128i k128 = _mm_set_epi64x((long long)K_FOLD128_HI, (long long)K_FOLD128_LO);

    __m256i y1 = _mm256_loadu_si256((const __m256i *)(buf + 0x00));
    __m256i y2 = _mm256_loadu_si256((const __m256i *)(buf + 0x20));
    __m256i y3 = _mm256_loadu_si256((const __m256i *)(buf + 0x40));
    __m256i y4 = _mm256_loadu_si256((const __m256i *)(buf + 0x60));
    y1 = _mm256_xor_si256(y1, _mm256_zextsi128_si256(_mm_cvtsi32_si128((int)crc)));
    buf += 128; len -= 128;

    while (len >= 128) {
        __m256i t1 = _mm256_clmulepi64_epi128(y1, k1024, 0x00);
        __m256i t2 = _mm256_clmulepi64_epi128(y2, k1024, 0x00);
        __m256i t3 = _mm256_clmulepi64_epi128(y3, k1024, 0x00);
        __m256i t4 = _mm256_clmulepi64_epi128(y4, k1024, 0x00);
        y1 = _mm256_clmulepi64_epi128(y1, k1024, 0x11);
        y2 = _mm256_clmulepi64_epi128(y2, k1024, 0x11);
        y3 = _mm256_clmulepi64_epi128(y3, k1024, 0x11);
        y4 = _mm256_clmulepi64_epi128(y4, k1024, 0x11);
        y1 = _mm256_xor_si256(_mm256_xor_si256(y1, t1), _mm256_loadu_si256((const __m256i *)(buf + 0x00)));
        y2 = _mm256_xor_si256(_mm256_xor_si256(y2, t2), _mm256_loadu_si256((const __m256i *)(buf + 0x20)));
        y3 = _mm256_xor_si256(_mm256_xor_si256(y3, t3), _mm256_loadu_si256((const __m256i *)(buf + 0x40)));
        y4 = _mm256_xor_si256(_mm256_xor_si256(y4, t4), _mm256_loadu_si256((const __m256i *)(buf + 0x60)));
        buf += 128; len -= 128;
    }
    /* 4 ymm -> 1 ymm (fold by 256 bits) */
    __m256i t;
    t = _mm256_clmulepi64_epi128(y1, k256, 0x00);
    y1 = _mm256_clmulepi64_epi128(y1, k256, 0x11);
    y1 = _mm256_xor_si256(_mm256_xor_si256(y1, t), y2);
    t = _mm256_clmulepi64_epi128(y1, k256, 0x00);
    y1 = _mm256_clmulepi64_epi128(y1, k256, 0x11);
    y1 = _mm256_xor_si256(_mm256_xor_si256(y1, t), y3);
    t = _mm256_clmulepi64_epi128(y1, k256, 0x00);
    y1 = _mm256_clmulepi64_epi128(y1, k256, 0x11);
    y1 = _mm256_xor_si256(_mm256_xor_si256(y1, t), y4);
    /* 2 lanes -> 1 (fold low lane by 128 bits into high lane) */
    __m128i lo = _mm256_castsi256_si128(y1);
    __m128i hi = _mm256_extracti128_si256(y1, 1);
    __m128i x1;
    {
        __m128i a = _mm_clmulepi64_si128(lo, k128, 0x00);
        x1 = _mm_clmulepi64_si128(lo, k128, 0x11);
        x1 = _mm_xor_si128(_mm_xor_si128(x1, a), hi);
    }
    CLMUL_TAIL_BODY
    return crc;
}

u32 gz_crc32_pclmul(u32 crc, const u8 *p, size_t n)
{
    u32 c = ~crc;
    if (n >= 64) {
        size_t blk = n & ~(size_t)15;
        c = crc_raw_pclmul(c, p, blk);
        p += blk; n -= blk;
    }
    return ~crc_raw_slice8(c, p, n);
}

u32 gz_crc32_avx(u32 crc, const u8 *p, size_t n)
{
    u32 c = ~crc;
    if (n >= 64) {
        size_t blk = n & ~(size_t)15;
        c = crc_raw_avx(c, p, blk);
        p += blk; n -= blk;
    }
    return ~crc_raw_slice8(c, p, n);
}

u32 gz_crc32_vpclmul(u32 crc, const u8 *p, size_t n)
{
    u32 c = ~crc;
    if (n >= 256) {
        size_t blk = n & ~(size_t)15;
        c = crc_raw_vpclmul(c, p, blk);
        p += blk; n -= blk;
    } else if (n >= 64) {
        size_t blk = n & ~(size_t)15;
        c = crc_raw_avx(c, p, blk);
        p += blk; n -= blk;
    }
    return ~crc_raw_slice8(c, p, n);
}

#else
u32 gz_crc32_pclmul(u32 crc, const u8 *p, size_t n) { return gz_crc32_slice8(crc, p, n); }
u32 gz_crc32_avx(u32 crc, const u8 *p, size_t n) { return gz_crc32_slice8(crc, p, n); }
u32 gz_crc32_vpclmul(u32 crc, const u8 *p, size_t n) { return gz_crc32_slice8(crc, p, n); }
#endif
