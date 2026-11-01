/*
 * 고깃ZIP - BLAKE2s / BLAKE2sp
 *
 * The BLAKE2sp kernels keep the 8 leaf states transposed (one SIMD lane per
 * leaf), transpose each 512-byte superblock into 16 message vectors and run
 * the BLAKE2s rounds on all leaves at once; no shuffles inside the rounds.
 */
#include "blake2.h"

#if defined(__i386__) || defined(__x86_64__)
#include <immintrin.h>
#endif
#if defined(__aarch64__)
#include <arm_neon.h>
#endif

static const u32 B2IV[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
};

static const u8 b2_sigma[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
};

gz_blake2sp_fn gz_blake2sp_kernel = gz_blake2sp_c;

/* G mixing function and the 10 rounds, written once for scalars and vectors.
 * The including code defines ADD, XOR, ROR16/12/8/7 and M(i) (message word i). */
#define B2G(a, b, c, d, x, y)                                                  \
    a = ADD(ADD(a, b), x); d = ROR16(XOR(d, a)); c = ADD(c, d); b = ROR12(XOR(b, c)); \
    a = ADD(ADD(a, b), y); d = ROR8(XOR(d, a));  c = ADD(c, d); b = ROR7(XOR(b, c));
#define B2_ROUNDS                                                              \
    for (int r_ = 0; r_ < 10; r_++) {                                          \
        const u8 *s_ = b2_sigma[r_];                                           \
        B2G(v0, v4, v8,  v12, M(s_[0]),  M(s_[1]))                             \
        B2G(v1, v5, v9,  v13, M(s_[2]),  M(s_[3]))                             \
        B2G(v2, v6, v10, v14, M(s_[4]),  M(s_[5]))                             \
        B2G(v3, v7, v11, v15, M(s_[6]),  M(s_[7]))                             \
        B2G(v0, v5, v10, v15, M(s_[8]),  M(s_[9]))                             \
        B2G(v1, v6, v11, v12, M(s_[10]), M(s_[11]))                            \
        B2G(v2, v7, v8,  v13, M(s_[12]), M(s_[13]))                            \
        B2G(v3, v4, v9,  v14, M(s_[14]), M(s_[15]))                            \
    }

/* ---------------- scalar compression ---------------- */

#define ADD(a, b) ((a) + (b))
#define XOR(a, b) ((a) ^ (b))
#define RORS(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROR16(x) RORS(x, 16)
#define ROR12(x) RORS(x, 12)
#define ROR8(x)  RORS(x, 8)
#define ROR7(x)  RORS(x, 7)
#define M(i) m[i]

static void b2s_compress(u32 h[8], const u8 *blk, u64 t, u32 f0, u32 f1)
{
    u32 m[16];
    for (int i = 0; i < 16; i++) m[i] = rd32(blk + 4 * i);
    u32 v0 = h[0], v1 = h[1], v2 = h[2], v3 = h[3], v4 = h[4], v5 = h[5], v6 = h[6], v7 = h[7];
    u32 v8 = B2IV[0], v9 = B2IV[1], v10 = B2IV[2], v11 = B2IV[3];
    u32 v12 = B2IV[4] ^ (u32)t, v13 = B2IV[5] ^ (u32)(t >> 32), v14 = B2IV[6] ^ f0, v15 = B2IV[7] ^ f1;
    B2_ROUNDS
    h[0] ^= v0 ^ v8;  h[1] ^= v1 ^ v9;  h[2] ^= v2 ^ v10; h[3] ^= v3 ^ v11;
    h[4] ^= v4 ^ v12; h[5] ^= v5 ^ v13; h[6] ^= v6 ^ v14; h[7] ^= v7 ^ v15;
}

#undef ADD
#undef XOR
#undef ROR16
#undef ROR12
#undef ROR8
#undef ROR7
#undef M

void gz_blake2sp_c(u32 h[8][8], u64 t, const u8 *p, size_t ns)
{
    for (; ns; ns--, p += 512) {
        t += 64;
        for (int l = 0; l < 8; l++) {
            u32 hl[8];
            for (int w = 0; w < 8; w++) hl[w] = h[w][l];
            b2s_compress(hl, p + 64 * l, t, 0, 0);
            for (int w = 0; w < 8; w++) h[w][l] = hl[w];
        }
    }
}

/* ---------------- x86 lane-parallel kernels ---------------- */
#if defined(__i386__) || defined(__x86_64__)

#define ADD(a, b) _mm_add_epi32(a, b)
#define XOR(a, b) _mm_xor_si128(a, b)
#define RORV(x, n) _mm_or_si128(_mm_srli_epi32(x, n), _mm_slli_epi32(x, 32 - (n)))
#define ROR12(x) RORV(x, 12)
#define ROR7(x)  RORV(x, 7)
#define M(i) m[i]

/* 4 leaves (lanes) of one superblock half: q points at the first leaf's block */
#define B2_X4_BODY                                                             \
    for (int qq = 0; qq < 4; qq++) {                                           \
        __m128i r0 = _mm_loadu_si128((const __m128i *)(q + 0 + 16 * qq));      \
        __m128i r1 = _mm_loadu_si128((const __m128i *)(q + 64 + 16 * qq));     \
        __m128i r2 = _mm_loadu_si128((const __m128i *)(q + 128 + 16 * qq));    \
        __m128i r3 = _mm_loadu_si128((const __m128i *)(q + 192 + 16 * qq));    \
        __m128i t0 = _mm_unpacklo_epi32(r0, r1), t1 = _mm_unpackhi_epi32(r0, r1); \
        __m128i t2 = _mm_unpacklo_epi32(r2, r3), t3 = _mm_unpackhi_epi32(r2, r3); \
        m[4 * qq + 0] = _mm_unpacklo_epi64(t0, t2);                            \
        m[4 * qq + 1] = _mm_unpackhi_epi64(t0, t2);                            \
        m[4 * qq + 2] = _mm_unpacklo_epi64(t1, t3);                            \
        m[4 * qq + 3] = _mm_unpackhi_epi64(t1, t3);                            \
    }                                                                          \
    __m128i v0 = _mm_loadu_si128((const __m128i *)&h[0][l0]);                  \
    __m128i v1 = _mm_loadu_si128((const __m128i *)&h[1][l0]);                  \
    __m128i v2 = _mm_loadu_si128((const __m128i *)&h[2][l0]);                  \
    __m128i v3 = _mm_loadu_si128((const __m128i *)&h[3][l0]);                  \
    __m128i v4 = _mm_loadu_si128((const __m128i *)&h[4][l0]);                  \
    __m128i v5 = _mm_loadu_si128((const __m128i *)&h[5][l0]);                  \
    __m128i v6 = _mm_loadu_si128((const __m128i *)&h[6][l0]);                  \
    __m128i v7 = _mm_loadu_si128((const __m128i *)&h[7][l0]);                  \
    __m128i v8 = _mm_set1_epi32((int)B2IV[0]), v9 = _mm_set1_epi32((int)B2IV[1]); \
    __m128i v10 = _mm_set1_epi32((int)B2IV[2]), v11 = _mm_set1_epi32((int)B2IV[3]); \
    __m128i v12 = _mm_set1_epi32((int)(B2IV[4] ^ (u32)t));                     \
    __m128i v13 = _mm_set1_epi32((int)(B2IV[5] ^ (u32)(t >> 32)));             \
    __m128i v14 = _mm_set1_epi32((int)B2IV[6]), v15 = _mm_set1_epi32((int)B2IV[7]); \
    B2_ROUNDS                                                                  \
    _mm_storeu_si128((__m128i *)&h[0][l0], XOR(v0, XOR(v8, _mm_loadu_si128((const __m128i *)&h[0][l0]))));  \
    _mm_storeu_si128((__m128i *)&h[1][l0], XOR(v1, XOR(v9, _mm_loadu_si128((const __m128i *)&h[1][l0]))));  \
    _mm_storeu_si128((__m128i *)&h[2][l0], XOR(v2, XOR(v10, _mm_loadu_si128((const __m128i *)&h[2][l0])))); \
    _mm_storeu_si128((__m128i *)&h[3][l0], XOR(v3, XOR(v11, _mm_loadu_si128((const __m128i *)&h[3][l0])))); \
    _mm_storeu_si128((__m128i *)&h[4][l0], XOR(v4, XOR(v12, _mm_loadu_si128((const __m128i *)&h[4][l0])))); \
    _mm_storeu_si128((__m128i *)&h[5][l0], XOR(v5, XOR(v13, _mm_loadu_si128((const __m128i *)&h[5][l0])))); \
    _mm_storeu_si128((__m128i *)&h[6][l0], XOR(v6, XOR(v14, _mm_loadu_si128((const __m128i *)&h[6][l0])))); \
    _mm_storeu_si128((__m128i *)&h[7][l0], XOR(v7, XOR(v15, _mm_loadu_si128((const __m128i *)&h[7][l0]))));

#define ROR16(x) _mm_shufflehi_epi16(_mm_shufflelo_epi16(x, 0xB1), 0xB1)
#define ROR8(x)  RORV(x, 8)
__attribute__((target("sse2")))
void gz_blake2sp_sse2(u32 h[8][8], u64 t, const u8 *p, size_t ns)
{
    __m128i m[16];
    for (; ns; ns--, p += 512) {
        t += 64;
        for (int l0 = 0; l0 < 8; l0 += 4) {
            const u8 *q = p + 64 * l0;
            B2_X4_BODY
        }
    }
}
#undef ROR16
#undef ROR8

#define ROR16(x) _mm_shuffle_epi8(x, rot16)
#define ROR8(x)  _mm_shuffle_epi8(x, rot8)
__attribute__((target("ssse3")))
void gz_blake2sp_ssse3(u32 h[8][8], u64 t, const u8 *p, size_t ns)
{
    const __m128i rot16 = _mm_setr_epi8(2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);
    const __m128i rot8 = _mm_setr_epi8(1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12);
    __m128i m[16];
    for (; ns; ns--, p += 512) {
        t += 64;
        for (int l0 = 0; l0 < 8; l0 += 4) {
            const u8 *q = p + 64 * l0;
            B2_X4_BODY
        }
    }
}
#undef ROR16
#undef ROR8
#undef ADD
#undef XOR
#undef RORV
#undef ROR12
#undef ROR7

/* AVX2: all 8 leaves in one ymm per state word */
#define ADD(a, b) _mm256_add_epi32(a, b)
#define XOR(a, b) _mm256_xor_si256(a, b)
#define RORV(x, n) _mm256_or_si256(_mm256_srli_epi32(x, n), _mm256_slli_epi32(x, 32 - (n)))
#define ROR16(x) _mm256_shuffle_epi8(x, rot16)
#define ROR12(x) RORV(x, 12)
#define ROR8(x)  _mm256_shuffle_epi8(x, rot8)
#define ROR7(x)  RORV(x, 7)
#define HLD(w) _mm256_loadu_si256((const __m256i *)h[w])

__attribute__((target("avx2")))
void gz_blake2sp_avx2(u32 h[8][8], u64 t, const u8 *p, size_t ns)
{
    const __m256i rot16 = _mm256_setr_epi8(2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
                                           2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);
    const __m256i rot8 = _mm256_setr_epi8(1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12,
                                          1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12);
    __m256i m[16];
    for (; ns; ns--, p += 512) {
        t += 64;
        /* 8x8 transpose of 32-bit words, twice (words 0-7 and 8-15 of every leaf) */
        for (int hw = 0; hw < 2; hw++) {
            const u8 *q = p + 32 * hw;
            __m256i r0 = _mm256_loadu_si256((const __m256i *)(q + 0 * 64));
            __m256i r1 = _mm256_loadu_si256((const __m256i *)(q + 1 * 64));
            __m256i r2 = _mm256_loadu_si256((const __m256i *)(q + 2 * 64));
            __m256i r3 = _mm256_loadu_si256((const __m256i *)(q + 3 * 64));
            __m256i r4 = _mm256_loadu_si256((const __m256i *)(q + 4 * 64));
            __m256i r5 = _mm256_loadu_si256((const __m256i *)(q + 5 * 64));
            __m256i r6 = _mm256_loadu_si256((const __m256i *)(q + 6 * 64));
            __m256i r7 = _mm256_loadu_si256((const __m256i *)(q + 7 * 64));
            __m256i t0 = _mm256_unpacklo_epi32(r0, r1), t1 = _mm256_unpackhi_epi32(r0, r1);
            __m256i t2 = _mm256_unpacklo_epi32(r2, r3), t3 = _mm256_unpackhi_epi32(r2, r3);
            __m256i t4 = _mm256_unpacklo_epi32(r4, r5), t5 = _mm256_unpackhi_epi32(r4, r5);
            __m256i t6 = _mm256_unpacklo_epi32(r6, r7), t7 = _mm256_unpackhi_epi32(r6, r7);
            __m256i u0 = _mm256_unpacklo_epi64(t0, t2), u1 = _mm256_unpackhi_epi64(t0, t2);
            __m256i u2 = _mm256_unpacklo_epi64(t1, t3), u3 = _mm256_unpackhi_epi64(t1, t3);
            __m256i u4 = _mm256_unpacklo_epi64(t4, t6), u5 = _mm256_unpackhi_epi64(t4, t6);
            __m256i u6 = _mm256_unpacklo_epi64(t5, t7), u7 = _mm256_unpackhi_epi64(t5, t7);
            __m256i *mm = m + 8 * hw;
            mm[0] = _mm256_permute2x128_si256(u0, u4, 0x20);
            mm[1] = _mm256_permute2x128_si256(u1, u5, 0x20);
            mm[2] = _mm256_permute2x128_si256(u2, u6, 0x20);
            mm[3] = _mm256_permute2x128_si256(u3, u7, 0x20);
            mm[4] = _mm256_permute2x128_si256(u0, u4, 0x31);
            mm[5] = _mm256_permute2x128_si256(u1, u5, 0x31);
            mm[6] = _mm256_permute2x128_si256(u2, u6, 0x31);
            mm[7] = _mm256_permute2x128_si256(u3, u7, 0x31);
        }
        __m256i v0 = HLD(0), v1 = HLD(1), v2 = HLD(2), v3 = HLD(3);
        __m256i v4 = HLD(4), v5 = HLD(5), v6 = HLD(6), v7 = HLD(7);
        __m256i v8 = _mm256_set1_epi32((int)B2IV[0]), v9 = _mm256_set1_epi32((int)B2IV[1]);
        __m256i v10 = _mm256_set1_epi32((int)B2IV[2]), v11 = _mm256_set1_epi32((int)B2IV[3]);
        __m256i v12 = _mm256_set1_epi32((int)(B2IV[4] ^ (u32)t));
        __m256i v13 = _mm256_set1_epi32((int)(B2IV[5] ^ (u32)(t >> 32)));
        __m256i v14 = _mm256_set1_epi32((int)B2IV[6]), v15 = _mm256_set1_epi32((int)B2IV[7]);
        B2_ROUNDS
        _mm256_storeu_si256((__m256i *)h[0], XOR(HLD(0), XOR(v0, v8)));
        _mm256_storeu_si256((__m256i *)h[1], XOR(HLD(1), XOR(v1, v9)));
        _mm256_storeu_si256((__m256i *)h[2], XOR(HLD(2), XOR(v2, v10)));
        _mm256_storeu_si256((__m256i *)h[3], XOR(HLD(3), XOR(v3, v11)));
        _mm256_storeu_si256((__m256i *)h[4], XOR(HLD(4), XOR(v4, v12)));
        _mm256_storeu_si256((__m256i *)h[5], XOR(HLD(5), XOR(v5, v13)));
        _mm256_storeu_si256((__m256i *)h[6], XOR(HLD(6), XOR(v6, v14)));
        _mm256_storeu_si256((__m256i *)h[7], XOR(HLD(7), XOR(v7, v15)));
    }
}
#undef ADD
#undef XOR
#undef RORV
#undef ROR16
#undef ROR12
#undef ROR8
#undef ROR7
#undef M
#undef HLD

#else
void gz_blake2sp_sse2(u32 h[8][8], u64 t, const u8 *p, size_t ns) { gz_blake2sp_c(h, t, p, ns); }
void gz_blake2sp_ssse3(u32 h[8][8], u64 t, const u8 *p, size_t ns) { gz_blake2sp_c(h, t, p, ns); }
void gz_blake2sp_avx2(u32 h[8][8], u64 t, const u8 *p, size_t ns) { gz_blake2sp_c(h, t, p, ns); }
#endif

/* ---------------- AArch64 NEON ---------------- */
#if defined(__aarch64__)

#define ADD(a, b) vaddq_u32(a, b)
#define XOR(a, b) veorq_u32(a, b)
#define RORV(x, n) vsriq_n_u32(vshlq_n_u32(x, 32 - (n)), x, n)
#define ROR16(x) vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x)))
#define ROR12(x) RORV(x, 12)
#define ROR8(x)  vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(x), rot8))
#define ROR7(x)  RORV(x, 7)
#define M(i) m[i]

void gz_blake2sp_neon(u32 h[8][8], u64 t, const u8 *p, size_t ns)
{
    static const u8 rot8_tab[16] = { 1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12 };
    const uint8x16_t rot8 = vld1q_u8(rot8_tab);
    uint32x4_t m[16];
    for (; ns; ns--, p += 512) {
        t += 64;
        for (int l0 = 0; l0 < 8; l0 += 4) {
            const u8 *q = p + 64 * l0;
            for (int qq = 0; qq < 4; qq++) {
                uint32x4_t r0 = vreinterpretq_u32_u8(vld1q_u8(q + 0 + 16 * qq));
                uint32x4_t r1 = vreinterpretq_u32_u8(vld1q_u8(q + 64 + 16 * qq));
                uint32x4_t r2 = vreinterpretq_u32_u8(vld1q_u8(q + 128 + 16 * qq));
                uint32x4_t r3 = vreinterpretq_u32_u8(vld1q_u8(q + 192 + 16 * qq));
                uint32x4x2_t a = vtrnq_u32(r0, r1), b = vtrnq_u32(r2, r3);
                m[4 * qq + 0] = vcombine_u32(vget_low_u32(a.val[0]), vget_low_u32(b.val[0]));
                m[4 * qq + 1] = vcombine_u32(vget_low_u32(a.val[1]), vget_low_u32(b.val[1]));
                m[4 * qq + 2] = vcombine_u32(vget_high_u32(a.val[0]), vget_high_u32(b.val[0]));
                m[4 * qq + 3] = vcombine_u32(vget_high_u32(a.val[1]), vget_high_u32(b.val[1]));
            }
            uint32x4_t v0 = vld1q_u32(&h[0][l0]), v1 = vld1q_u32(&h[1][l0]);
            uint32x4_t v2 = vld1q_u32(&h[2][l0]), v3 = vld1q_u32(&h[3][l0]);
            uint32x4_t v4 = vld1q_u32(&h[4][l0]), v5 = vld1q_u32(&h[5][l0]);
            uint32x4_t v6 = vld1q_u32(&h[6][l0]), v7 = vld1q_u32(&h[7][l0]);
            uint32x4_t v8 = vdupq_n_u32(B2IV[0]), v9 = vdupq_n_u32(B2IV[1]);
            uint32x4_t v10 = vdupq_n_u32(B2IV[2]), v11 = vdupq_n_u32(B2IV[3]);
            uint32x4_t v12 = vdupq_n_u32(B2IV[4] ^ (u32)t), v13 = vdupq_n_u32(B2IV[5] ^ (u32)(t >> 32));
            uint32x4_t v14 = vdupq_n_u32(B2IV[6]), v15 = vdupq_n_u32(B2IV[7]);
            B2_ROUNDS
            vst1q_u32(&h[0][l0], XOR(vld1q_u32(&h[0][l0]), XOR(v0, v8)));
            vst1q_u32(&h[1][l0], XOR(vld1q_u32(&h[1][l0]), XOR(v1, v9)));
            vst1q_u32(&h[2][l0], XOR(vld1q_u32(&h[2][l0]), XOR(v2, v10)));
            vst1q_u32(&h[3][l0], XOR(vld1q_u32(&h[3][l0]), XOR(v3, v11)));
            vst1q_u32(&h[4][l0], XOR(vld1q_u32(&h[4][l0]), XOR(v4, v12)));
            vst1q_u32(&h[5][l0], XOR(vld1q_u32(&h[5][l0]), XOR(v5, v13)));
            vst1q_u32(&h[6][l0], XOR(vld1q_u32(&h[6][l0]), XOR(v6, v14)));
            vst1q_u32(&h[7][l0], XOR(vld1q_u32(&h[7][l0]), XOR(v7, v15)));
        }
    }
}
#else
void gz_blake2sp_neon(u32 h[8][8], u64 t, const u8 *p, size_t ns) { gz_blake2sp_c(h, t, p, ns); }
#endif

/* ---------------- BLAKE2s ---------------- */

void gz_blake2s_init(gz_blake2s *s, size_t outlen)
{
    if (outlen < 1 || outlen > 32) outlen = 32;
    for (int i = 0; i < 8; i++) s->h[i] = B2IV[i];
    s->h[0] ^= 0x01010000u ^ (u32)outlen;          /* fanout 1, depth 1 */
    s->t[0] = s->t[1] = 0;
    s->buflen = 0;
    s->outlen = (u32)outlen;
}

static inline u64 b2s_count(const gz_blake2s *s) { return ((u64)s->t[1] << 32) | s->t[0]; }
static inline void b2s_set_count(gz_blake2s *s, u64 t) { s->t[0] = (u32)t; s->t[1] = (u32)(t >> 32); }

void gz_blake2s_update(gz_blake2s *s, const void *pv, size_t n)
{
    const u8 *p = (const u8 *)pv;
    if (!n) return;
    u64 t = b2s_count(s);
    if (s->buflen + n > 64) {
        size_t fill = 64 - s->buflen;
        __builtin_memcpy(s->buf + s->buflen, p, fill);
        p += fill; n -= fill;
        t += 64;
        b2s_compress(s->h, s->buf, t, 0, 0);
        s->buflen = 0;
        for (; n > 64; p += 64, n -= 64) {     /* keep the last block for final */
            t += 64;
            b2s_compress(s->h, p, t, 0, 0);
        }
    }
    __builtin_memcpy(s->buf + s->buflen, p, n);
    s->buflen += (u32)n;
    b2s_set_count(s, t);
}

void gz_blake2s_final(gz_blake2s *s, u8 *out)
{
    u8 d[32];
    u64 t = b2s_count(s) + s->buflen;
    __builtin_memset(s->buf + s->buflen, 0, 64 - s->buflen);
    b2s_compress(s->h, s->buf, t, ~0u, 0);
    for (int i = 0; i < 8; i++) wr32(d + 4 * i, s->h[i]);
    __builtin_memcpy(out, d, s->outlen);
}

void gz_blake2s_calc(const void *p, size_t n, u8 *out, size_t outlen)
{
    gz_blake2s s;
    gz_blake2s_init(&s, outlen);
    gz_blake2s_update(&s, p, n);
    gz_blake2s_final(&s, out);
}

/* ---------------- BLAKE2sp ---------------- */
/* Each leaf must finalize its own last block, so a superblock is only compressed
 * when more than 7*64 bytes follow it (every leaf then still has data ahead);
 * at most 960 bytes are buffered. */
#define SP_HOLD 448

void gz_blake2sp_init(gz_blake2sp *s)
{
    /* leaf parameter block: digest 32, fanout 8, depth 2, node offset = leaf, inner 32 */
    for (int w = 0; w < 8; w++)
        for (int l = 0; l < 8; l++) s->h[w][l] = B2IV[w];
    for (int l = 0; l < 8; l++) {
        s->h[0][l] ^= 0x02080020u;
        s->h[2][l] ^= (u32)l;
        s->h[3][l] ^= 0x20000000u;
    }
    s->t = 0;
    s->buflen = 0;
}

static void sp_append(gz_blake2sp *s, const u8 *p, size_t n)
{
    if (n) __builtin_memcpy(s->buf + s->buflen, p, n);
    s->buflen += (u32)n;
}

void gz_blake2sp_update(gz_blake2sp *s, const void *pv, size_t n)
{
    const u8 *p = (const u8 *)pv;
    if (s->buflen + n <= 512 + SP_HOLD) { sp_append(s, p, n); return; }
    if (s->buflen) {
        /* complete the buffered superblock(s), compress what may be compressed */
        size_t fill = (s->buflen <= 512 ? 512 : 1024) - s->buflen, off = 0;
        if (fill > n) fill = n;
        sp_append(s, p, fill);
        p += fill; n -= fill;
        while (off + 512 <= s->buflen && s->buflen - off - 512 + n > SP_HOLD) {
            gz_blake2sp_kernel(s->h, s->t, s->buf + off, 1);
            s->t += 64;
            off += 512;
        }
        if (off) {
            __builtin_memmove(s->buf, s->buf + off, s->buflen - off);
            s->buflen -= (u32)off;
        }
        if (s->buflen) { sp_append(s, p, n); return; }   /* fits: see the cases above */
    }
    if (n > 512 + SP_HOLD) {
        size_t ns = (n - SP_HOLD - 1) >> 9;
        gz_blake2sp_kernel(s->h, s->t, p, ns);
        s->t += (u64)ns << 6;
        p += ns << 9; n -= ns << 9;
    }
    sp_append(s, p, n);
}

void gz_blake2sp_final(gz_blake2sp *s, u8 out[32])
{
    u8 leaves[8 * 32], blk[64];
    u32 r = s->buflen;
    for (u32 l = 0; l < 8; l++) {
        u32 hl[8];
        u64 t = s->t;
        for (int w = 0; w < 8; w++) hl[w] = s->h[w][l];
        u32 off = 64 * l;
        while (off + 512 < r) {          /* another block of this leaf follows */
            t += 64;
            b2s_compress(hl, s->buf + off, t, 0, 0);
            off += 512;
        }
        u32 len = off < r ? GZ_MIN(64, r - off) : 0;
        __builtin_memset(blk, 0, 64);
        if (len) __builtin_memcpy(blk, s->buf + off, len);
        t += len;
        b2s_compress(hl, blk, t, ~0u, l == 7 ? ~0u : 0);
        for (int w = 0; w < 8; w++) wr32(leaves + 32 * l + 4 * w, hl[w]);
    }
    /* root node: node depth 1, last node */
    u32 hr[8];
    for (int w = 0; w < 8; w++) hr[w] = B2IV[w];
    hr[0] ^= 0x02080020u;
    hr[3] ^= 0x20010000u;
    b2s_compress(hr, leaves, 64, 0, 0);
    b2s_compress(hr, leaves + 64, 128, 0, 0);
    b2s_compress(hr, leaves + 128, 192, 0, 0);
    b2s_compress(hr, leaves + 192, 256, ~0u, ~0u);
    for (int w = 0; w < 8; w++) wr32(out + 4 * w, hr[w]);
}

void gz_blake2sp_calc(const void *p, size_t n, u8 out[32])
{
    gz_blake2sp s;
    gz_blake2sp_init(&s);
    gz_blake2sp_update(&s, p, n);
    gz_blake2sp_final(&s, out);
}
