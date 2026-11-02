/*
 * 고깃ZIP - CRC-64/XZ (ECMA-182, reflected 0xC96C5795D7870F42)
 *
 *   gz_crc64_slice8   portable slice-by-8 tables                 (any CPU)
 *   gz_crc64_pclmul   4x128-bit carry-less folding               (SSE4.1 + PCLMULQDQ)
 *   gz_crc64_vpclmul  4x256-bit folding                          (AVX2 + VPCLMULQDQ)
 *   gz_crc64_pmull    8x128-bit folding                          (AArch64 PMULL)
 *
 * Folding as in Gopal et al. (Intel 2009) for a reflected 64-bit CRC. A 128-bit
 * lane L = H + L' (H = first 8 bytes) moved D bits forward becomes
 * clmul(H, x^(D+63) mod P) ^ clmul(L', x^(D-1) mod P); the constants are stored
 * bit-reflected (clmul of reflected operands yields the product times x).
 * The last 128 bits are reduced to 64 with a Barrett step.
 */
#include "crc64.h"

#if defined(__i386__) || defined(__x86_64__)
#include <immintrin.h>
#endif
#if defined(__aarch64__)
#include <arm_neon.h>
#if defined(__clang__)
#define GZ_TARGET_PMULL __attribute__((target("aes")))
#else
#define GZ_TARGET_PMULL __attribute__((target("+crypto")))
#endif
#endif

#define POLY64R 0xC96C5795D7870F42ULL

u64 gz_crc64_table[8][256];
gz_crc64_fn gz_crc64_kernel = gz_crc64_slice8;

void gz_crc64_init(void)
{
    for (u32 i = 0; i < 256; i++) {
        u64 c = i;
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (POLY64R & (0ULL - (c & 1)));
        gz_crc64_table[0][i] = c;
    }
    for (u32 i = 0; i < 256; i++) {
        u64 c = gz_crc64_table[0][i];
        for (int t = 1; t < 8; t++) {
            c = gz_crc64_table[0][c & 0xff] ^ (c >> 8);
            gz_crc64_table[t][i] = c;
        }
    }
}

/* raw (non-inverted) state */
static u64 crc64_raw_slice8(u64 c, const u8 *p, size_t n)
{
    const u64 (*T)[256] = gz_crc64_table;
    while (n && ((uintptr_t)p & 7)) {
        c = T[0][(c ^ *p++) & 0xff] ^ (c >> 8);
        n--;
    }
    while (n >= 8) {
        /* two 32-bit halves keep the indexing cheap on i386 too */
        u32 lo = (u32)c ^ rd32(p), hi = (u32)(c >> 32) ^ rd32(p + 4);
        c = T[7][lo & 0xff] ^ T[6][(lo >> 8) & 0xff] ^ T[5][(lo >> 16) & 0xff] ^ T[4][lo >> 24] ^
            T[3][hi & 0xff] ^ T[2][(hi >> 8) & 0xff] ^ T[1][(hi >> 16) & 0xff] ^ T[0][hi >> 24];
        p += 8; n -= 8;
    }
    while (n--) c = T[0][(c ^ *p++) & 0xff] ^ (c >> 8);
    return c;
}

u64 gz_crc64_slice8(u64 crc, const u8 *p, size_t n)
{
    return ~crc64_raw_slice8(~crc, p, n);
}

/* fold constants: {lo qword (multiplies the first 8 bytes), hi qword} */
#define K128_LO  0xe05dd497ca393ae4ULL    /* x^191 mod P */
#define K128_HI  0xdabe95afc7875f40ULL    /* x^127 mod P */
#define K256_LO  0x60095b008a9efa44ULL
#define K256_HI  0x3be653a30fe1af51ULL
#define K512_LO  0x6ae3efbb9dd441f3ULL
#define K512_HI  0x081f6054a7842df4ULL
#define K1024_LO 0x8757d71d4fcc1000ULL
#define K1024_HI 0xd7d86b2af73de740ULL
#define K_MU     0x9c3e466c172963d5ULL    /* floor(x^128 / P) >> 1 */
#define K_P      0x92d8af2baf0e1e85ULL    /* P >> 1                */

#if defined(__i386__) || defined(__x86_64__)

#define CLMUL_FOLD(x, k) _mm_xor_si128(_mm_clmulepi64_si128(x, k, 0x00), _mm_clmulepi64_si128(x, k, 0x11))

/* single 16-byte folds, then 128 -> 64 Barrett reduction; returns the raw state */
#define CRC64_TAIL                                                             \
    while (len >= 16) {                                                        \
        x = _mm_xor_si128(CLMUL_FOLD(x, k128), _mm_loadu_si128((const __m128i *)buf)); \
        buf += 16; len -= 16;                                                  \
    }                                                                          \
    {                                                                          \
        const __m128i kb = _mm_set_epi64x((long long)K_P, (long long)K_MU);    \
        __m128i v = _mm_xor_si128(_mm_clmulepi64_si128(x, k128, 0x10), _mm_srli_si128(x, 8)); \
        __m128i c = _mm_clmulepi64_si128(v, kb, 0x00);                         \
        __m128i c2 = _mm_clmulepi64_si128(c, kb, 0x10);                        \
        v = _mm_xor_si128(_mm_xor_si128(v, c2), _mm_slli_si128(c, 8));         \
        return ((u64)(u32)_mm_extract_epi32(v, 3) << 32) | (u32)_mm_extract_epi32(v, 2); \
    }

/* len >= 64, multiple of 16; raw state in/out */
__attribute__((target("sse4.1,pclmul")))
static u64 crc64_fold_pclmul(u64 crc, const u8 *buf, size_t len)
{
    const __m128i k512 = _mm_set_epi64x((long long)K512_HI, (long long)K512_LO);
    const __m128i k128 = _mm_set_epi64x((long long)K128_HI, (long long)K128_LO);
    __m128i x0 = _mm_loadu_si128((const __m128i *)(buf + 0x00));
    __m128i x1 = _mm_loadu_si128((const __m128i *)(buf + 0x10));
    __m128i x2 = _mm_loadu_si128((const __m128i *)(buf + 0x20));
    __m128i x3 = _mm_loadu_si128((const __m128i *)(buf + 0x30));
    x0 = _mm_xor_si128(x0, _mm_set_epi64x(0, (long long)crc));
    buf += 64; len -= 64;
    while (len >= 64) {
        x0 = _mm_xor_si128(CLMUL_FOLD(x0, k512), _mm_loadu_si128((const __m128i *)(buf + 0x00)));
        x1 = _mm_xor_si128(CLMUL_FOLD(x1, k512), _mm_loadu_si128((const __m128i *)(buf + 0x10)));
        x2 = _mm_xor_si128(CLMUL_FOLD(x2, k512), _mm_loadu_si128((const __m128i *)(buf + 0x20)));
        x3 = _mm_xor_si128(CLMUL_FOLD(x3, k512), _mm_loadu_si128((const __m128i *)(buf + 0x30)));
        buf += 64; len -= 64;
    }
    __m128i x = _mm_xor_si128(CLMUL_FOLD(x0, k128), x1);
    x = _mm_xor_si128(CLMUL_FOLD(x, k128), x2);
    x = _mm_xor_si128(CLMUL_FOLD(x, k128), x3);
    CRC64_TAIL
}

/* len >= 128, multiple of 16 */
__attribute__((target("avx2,pclmul,vpclmulqdq")))
static u64 crc64_fold_vpclmul(u64 crc, const u8 *buf, size_t len)
{
    const __m256i k1024 = _mm256_set_epi64x((long long)K1024_HI, (long long)K1024_LO,
                                            (long long)K1024_HI, (long long)K1024_LO);
    const __m256i k256 = _mm256_set_epi64x((long long)K256_HI, (long long)K256_LO,
                                           (long long)K256_HI, (long long)K256_LO);
    const __m128i k128 = _mm_set_epi64x((long long)K128_HI, (long long)K128_LO);
#define YFOLD(y, k) _mm256_xor_si256(_mm256_clmulepi64_epi128(y, k, 0x00), _mm256_clmulepi64_epi128(y, k, 0x11))
    __m256i y0 = _mm256_loadu_si256((const __m256i *)(buf + 0x00));
    __m256i y1 = _mm256_loadu_si256((const __m256i *)(buf + 0x20));
    __m256i y2 = _mm256_loadu_si256((const __m256i *)(buf + 0x40));
    __m256i y3 = _mm256_loadu_si256((const __m256i *)(buf + 0x60));
    y0 = _mm256_xor_si256(y0, _mm256_zextsi128_si256(_mm_set_epi64x(0, (long long)crc)));
    buf += 128; len -= 128;
    while (len >= 128) {
        y0 = _mm256_xor_si256(YFOLD(y0, k1024), _mm256_loadu_si256((const __m256i *)(buf + 0x00)));
        y1 = _mm256_xor_si256(YFOLD(y1, k1024), _mm256_loadu_si256((const __m256i *)(buf + 0x20)));
        y2 = _mm256_xor_si256(YFOLD(y2, k1024), _mm256_loadu_si256((const __m256i *)(buf + 0x40)));
        y3 = _mm256_xor_si256(YFOLD(y3, k1024), _mm256_loadu_si256((const __m256i *)(buf + 0x60)));
        buf += 128; len -= 128;
    }
    y0 = _mm256_xor_si256(YFOLD(y0, k256), y1);
    y0 = _mm256_xor_si256(YFOLD(y0, k256), y2);
    y0 = _mm256_xor_si256(YFOLD(y0, k256), y3);
#undef YFOLD
    __m128i x = _mm_xor_si128(CLMUL_FOLD(_mm256_castsi256_si128(y0), k128), _mm256_extracti128_si256(y0, 1));
    CRC64_TAIL
}

u64 gz_crc64_pclmul(u64 crc, const u8 *p, size_t n)
{
    u64 c = ~crc;
    if (n >= 64) {
        size_t blk = n & ~(size_t)15;
        c = crc64_fold_pclmul(c, p, blk);
        p += blk; n -= blk;
    }
    return ~crc64_raw_slice8(c, p, n);
}

u64 gz_crc64_vpclmul(u64 crc, const u8 *p, size_t n)
{
    u64 c = ~crc;
    if (n >= 256) {
        size_t blk = n & ~(size_t)15;
        c = crc64_fold_vpclmul(c, p, blk);
        p += blk; n -= blk;
    } else if (n >= 64) {
        size_t blk = n & ~(size_t)15;
        c = crc64_fold_pclmul(c, p, blk);
        p += blk; n -= blk;
    }
    return ~crc64_raw_slice8(c, p, n);
}

#else
u64 gz_crc64_pclmul(u64 crc, const u8 *p, size_t n) { return gz_crc64_slice8(crc, p, n); }
u64 gz_crc64_vpclmul(u64 crc, const u8 *p, size_t n) { return gz_crc64_slice8(crc, p, n); }
#endif

#if defined(__aarch64__)

#define PM_LO(x, k) vreinterpretq_u64_p128(vmull_p64((poly64_t)vgetq_lane_u64(x, 0), (poly64_t)vgetq_lane_u64(k, 0)))
#define PM_HI(x, k) vreinterpretq_u64_p128(vmull_high_p64(vreinterpretq_p64_u64(x), vreinterpretq_p64_u64(k)))
#define PM_FOLD(x, k, d) veorq_u64(veorq_u64(PM_LO(x, k), PM_HI(x, k)), d)
#define PM_LD(o) vreinterpretq_u64_u8(vld1q_u8(buf + (o)))

/* len >= 128, multiple of 16; raw state in/out */
GZ_TARGET_PMULL
static u64 crc64_fold_pmull(u64 crc, const u8 *buf, size_t len)
{
    const uint64x2_t k1024 = vcombine_u64(vcreate_u64(K1024_LO), vcreate_u64(K1024_HI));
    const uint64x2_t k128 = vcombine_u64(vcreate_u64(K128_LO), vcreate_u64(K128_HI));
    uint64x2_t x0 = PM_LD(0x00), x1 = PM_LD(0x10), x2 = PM_LD(0x20), x3 = PM_LD(0x30);
    uint64x2_t x4 = PM_LD(0x40), x5 = PM_LD(0x50), x6 = PM_LD(0x60), x7 = PM_LD(0x70);
    x0 = veorq_u64(x0, vcombine_u64(vcreate_u64(crc), vcreate_u64(0)));
    buf += 128; len -= 128;
    while (len >= 128) {
        x0 = PM_FOLD(x0, k1024, PM_LD(0x00)); x1 = PM_FOLD(x1, k1024, PM_LD(0x10));
        x2 = PM_FOLD(x2, k1024, PM_LD(0x20)); x3 = PM_FOLD(x3, k1024, PM_LD(0x30));
        x4 = PM_FOLD(x4, k1024, PM_LD(0x40)); x5 = PM_FOLD(x5, k1024, PM_LD(0x50));
        x6 = PM_FOLD(x6, k1024, PM_LD(0x60)); x7 = PM_FOLD(x7, k1024, PM_LD(0x70));
        buf += 128; len -= 128;
    }
    uint64x2_t x = PM_FOLD(x0, k128, x1);
    x = PM_FOLD(x, k128, x2); x = PM_FOLD(x, k128, x3); x = PM_FOLD(x, k128, x4);
    x = PM_FOLD(x, k128, x5); x = PM_FOLD(x, k128, x6); x = PM_FOLD(x, k128, x7);
    for (; len >= 16; buf += 16, len -= 16) x = PM_FOLD(x, k128, PM_LD(0));
    /* Barrett: v = H * x^128 + L * x^64 (128 bits), then reduce */
    u64 h = vgetq_lane_u64(x, 0), l = vgetq_lane_u64(x, 1);
    uint64x2_t v = vreinterpretq_u64_p128(vmull_p64((poly64_t)h, (poly64_t)K128_HI));
    v = veorq_u64(v, vcombine_u64(vcreate_u64(l), vcreate_u64(0)));
    u64 t1 = vgetq_lane_u64(vreinterpretq_u64_p128(vmull_p64((poly64_t)vgetq_lane_u64(v, 0), (poly64_t)K_MU)), 0);
    u64 c2 = vgetq_lane_u64(vreinterpretq_u64_p128(vmull_p64((poly64_t)t1, (poly64_t)K_P)), 1);
    return vgetq_lane_u64(v, 1) ^ c2 ^ t1;
}

u64 gz_crc64_pmull(u64 crc, const u8 *p, size_t n)
{
    u64 c = ~crc;
    if (n >= 256) {
        size_t blk = n & ~(size_t)15;
        c = crc64_fold_pmull(c, p, blk);
        p += blk; n -= blk;
    }
    return ~crc64_raw_slice8(c, p, n);
}
#else
u64 gz_crc64_pmull(u64 crc, const u8 *p, size_t n) { return gz_crc64_slice8(crc, p, n); }
#endif
