/*
 * 고깃ZIP - SHA-256 (FIPS 180-4) with portable / SHA-NI / ARMv8 block kernels,
 * HMAC-SHA256 and PBKDF2-HMAC-SHA256 (7z AES, RAR 5.0 encryption)
 */
#include "sha256.h"

#if defined(__i386__) || defined(__x86_64__)
#include <immintrin.h>
#endif
#if defined(__aarch64__)
#include <arm_neon.h>
#if defined(__clang__)
#define GZ_TARGET_SHA2 __attribute__((target("sha2")))
#else
#define GZ_TARGET_SHA2 __attribute__((target("+sha2")))
#endif
#endif

gz_sha_blocks_fn gz_sha256_kernel = gz_sha256_blocks_c;

static const u32 K256[64] GZ_ALIGN(16) = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const u32 H256[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/* ---------------- portable kernel ---------------- */

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define BS0(x) (ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22))
#define BS1(x) (ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25))
#define SS0(x) (ROR(x, 7) ^ ROR(x, 18) ^ ((x) >> 3))
#define SS1(x) (ROR(x, 17) ^ ROR(x, 19) ^ ((x) >> 10))
#define CH(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define MAJ(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))

#define RND(a, b, c, d, e, f, g, h, j) do {                                   \
        u32 t1_ = h + BS1(e) + CH(e, f, g) + k[j] + w[j];                     \
        d += t1_;                                                             \
        h = t1_ + BS0(a) + MAJ(a, b, c);                                      \
    } while (0)

void gz_sha256_blocks_c(u32 *st, const u8 *p, size_t nb)
{
    u32 w[16];
    while (nb--) {
        u32 a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
        for (int j = 0; j < 16; j++) w[j] = rd32be(p + 4 * j);
        for (int r = 0; r < 64; r += 16) {
            const u32 *k = K256 + r;
            if (r)   /* next 16 schedule words in place (see FIPS 180-4 6.2.2) */
                for (int j = 0; j < 16; j++)
                    w[j] += SS1(w[(j + 14) & 15]) + w[(j + 9) & 15] + SS0(w[(j + 1) & 15]);
            RND(a, b, c, d, e, f, g, h, 0);  RND(h, a, b, c, d, e, f, g, 1);
            RND(g, h, a, b, c, d, e, f, 2);  RND(f, g, h, a, b, c, d, e, 3);
            RND(e, f, g, h, a, b, c, d, 4);  RND(d, e, f, g, h, a, b, c, 5);
            RND(c, d, e, f, g, h, a, b, 6);  RND(b, c, d, e, f, g, h, a, 7);
            RND(a, b, c, d, e, f, g, h, 8);  RND(h, a, b, c, d, e, f, g, 9);
            RND(g, h, a, b, c, d, e, f, 10); RND(f, g, h, a, b, c, d, e, 11);
            RND(e, f, g, h, a, b, c, d, 12); RND(d, e, f, g, h, a, b, c, 13);
            RND(c, d, e, f, g, h, a, b, 14); RND(b, c, d, e, f, g, h, a, 15);
        }
        st[0] += a; st[1] += b; st[2] += c; st[3] += d;
        st[4] += e; st[5] += f; st[6] += g; st[7] += h;
        p += 64;
    }
}

/* ---------------- x86 SHA-NI ---------------- */
#if defined(__i386__) || defined(__x86_64__)

/* 4 rounds with message vector M (W + K added here) */
#define NI_RND4(i, M) do {                                                     \
        __m128i m_ = _mm_add_epi32(M, _mm_load_si128((const __m128i *)(K256 + 4 * (i)))); \
        s1 = _mm_sha256rnds2_epu32(s1, s0, m_);                               \
        s0 = _mm_sha256rnds2_epu32(s0, s1, _mm_shuffle_epi32(m_, 0x0E));      \
    } while (0)
/* M0 <- next 4 schedule words from W[t-16..t-1] = M0 M1 M2 M3 */
#define NI_SCHED(M0, M1, M2, M3)                                               \
    M0 = _mm_sha256msg2_epu32(_mm_add_epi32(_mm_sha256msg1_epu32(M0, M1),     \
                                            _mm_alignr_epi8(M3, M2, 4)), M3)

__attribute__((target("sha,sse4.1")))
void gz_sha256_blocks_shani(u32 *st, const u8 *p, size_t nb)
{
    const __m128i bswap = _mm_set_epi64x(0x0c0d0e0f08090a0bLL, 0x0405060700010203LL);
    __m128i t = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i *)st), 0xB1);        /* CDAB */
    __m128i s1 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i *)(st + 4)), 0x1B); /* EFGH */
    __m128i s0 = _mm_alignr_epi8(t, s1, 8);                                          /* ABEF */
    s1 = _mm_blend_epi16(s1, t, 0xF0);                                               /* CDGH */
    while (nb--) {
        __m128i sv0 = s0, sv1 = s1;
        __m128i m0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(p + 0)), bswap);
        __m128i m1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(p + 16)), bswap);
        __m128i m2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(p + 32)), bswap);
        __m128i m3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(p + 48)), bswap);
        NI_RND4(0, m0); NI_RND4(1, m1); NI_RND4(2, m2); NI_RND4(3, m3);
        for (int i = 4; i < 16; i += 4) {
            NI_SCHED(m0, m1, m2, m3); NI_RND4(i + 0, m0);
            NI_SCHED(m1, m2, m3, m0); NI_RND4(i + 1, m1);
            NI_SCHED(m2, m3, m0, m1); NI_RND4(i + 2, m2);
            NI_SCHED(m3, m0, m1, m2); NI_RND4(i + 3, m3);
        }
        s0 = _mm_add_epi32(s0, sv0);
        s1 = _mm_add_epi32(s1, sv1);
        p += 64;
    }
    t = _mm_shuffle_epi32(s0, 0x1B);                       /* FEBA */
    s1 = _mm_shuffle_epi32(s1, 0xB1);                      /* DCHG */
    _mm_storeu_si128((__m128i *)st, _mm_blend_epi16(t, s1, 0xF0));        /* DCBA */
    _mm_storeu_si128((__m128i *)(st + 4), _mm_alignr_epi8(s1, t, 8));     /* HGFE */
}
#else
void gz_sha256_blocks_shani(u32 *st, const u8 *p, size_t nb) { gz_sha256_blocks_c(st, p, nb); }
#endif

/* ---------------- ARMv8 SHA2 ---------------- */
#if defined(__aarch64__)

#define ARM_RND4(i, M) do {                                                    \
        uint32x4_t m_ = vaddq_u32(M, vld1q_u32(K256 + 4 * (i)));             \
        uint32x4_t t_ = s0;                                                   \
        s0 = vsha256hq_u32(s0, s1, m_);                                       \
        s1 = vsha256h2q_u32(s1, t_, m_);                                      \
    } while (0)
#define ARM_SCHED(M0, M1, M2, M3) M0 = vsha256su1q_u32(vsha256su0q_u32(M0, M1), M2, M3)

GZ_TARGET_SHA2
void gz_sha256_blocks_arm(u32 *st, const u8 *p, size_t nb)
{
    uint32x4_t s0 = vld1q_u32(st), s1 = vld1q_u32(st + 4);
    while (nb--) {
        uint32x4_t sv0 = s0, sv1 = s1;
        uint32x4_t m0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 0)));
        uint32x4_t m1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 16)));
        uint32x4_t m2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 32)));
        uint32x4_t m3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 48)));
        ARM_RND4(0, m0); ARM_RND4(1, m1); ARM_RND4(2, m2); ARM_RND4(3, m3);
        for (int i = 4; i < 16; i += 4) {
            ARM_SCHED(m0, m1, m2, m3); ARM_RND4(i + 0, m0);
            ARM_SCHED(m1, m2, m3, m0); ARM_RND4(i + 1, m1);
            ARM_SCHED(m2, m3, m0, m1); ARM_RND4(i + 2, m2);
            ARM_SCHED(m3, m0, m1, m2); ARM_RND4(i + 3, m3);
        }
        s0 = vaddq_u32(s0, sv0);
        s1 = vaddq_u32(s1, sv1);
        p += 64;
    }
    vst1q_u32(st, s0);
    vst1q_u32(st + 4, s1);
}
#else
void gz_sha256_blocks_arm(u32 *st, const u8 *p, size_t nb) { gz_sha256_blocks_c(st, p, nb); }
#endif

/* ---------------- streaming interface ---------------- */

void gz_sha256_init(gz_sha256 *s)
{
    for (int i = 0; i < 8; i++) s->h[i] = H256[i];
    s->len = 0;
    s->n = 0;
}

void gz_sha256_update(gz_sha256 *s, const void *pv, size_t n)
{
    const u8 *p = (const u8 *)pv;
    s->len += n;
    if (s->n) {
        size_t take = 64 - s->n;
        if (take > n) take = n;
        __builtin_memcpy(s->buf + s->n, p, take);
        s->n += (u32)take; p += take; n -= take;
        if (s->n < 64) return;
        gz_sha256_kernel(s->h, s->buf, 1);
        s->n = 0;
    }
    if (n >= 64) {
        size_t nb = n >> 6;
        gz_sha256_kernel(s->h, p, nb);
        p += nb << 6;
        n &= 63;
    }
    if (n) { __builtin_memcpy(s->buf, p, n); s->n = (u32)n; }
}

void gz_sha256_final(gz_sha256 *s, u8 out[32])
{
    u32 n = s->n;
    u64 bits = s->len << 3;
    s->buf[n++] = 0x80;
    if (n > 56) {
        __builtin_memset(s->buf + n, 0, 64 - n);
        gz_sha256_kernel(s->h, s->buf, 1);
        n = 0;
    }
    __builtin_memset(s->buf + n, 0, 56 - n);
    wr64be(s->buf + 56, bits);
    gz_sha256_kernel(s->h, s->buf, 1);
    for (int i = 0; i < 8; i++) wr32be(out + 4 * i, s->h[i]);
    s->n = 0;
}

void gz_sha256_calc(const void *p, size_t n, u8 out[32])
{
    gz_sha256 s;
    gz_sha256_init(&s);
    gz_sha256_update(&s, p, n);
    gz_sha256_final(&s, out);
}

/* ---------------- HMAC / PBKDF2 ---------------- */

void gz_hmac_sha256_pads(const void *key, size_t n, u32 ist[8], u32 ost[8])
{
    u8 k[64], blk[64];
    __builtin_memset(k, 0, 64);
    if (n > 64) gz_sha256_calc(key, n, k);
    else if (n) __builtin_memcpy(k, key, n);
    for (int i = 0; i < 8; i++) { ist[i] = H256[i]; ost[i] = H256[i]; }
    for (int i = 0; i < 64; i++) blk[i] = k[i] ^ 0x36;
    gz_sha256_kernel(ist, blk, 1);
    for (int i = 0; i < 64; i++) blk[i] = k[i] ^ 0x5c;
    gz_sha256_kernel(ost, blk, 1);
}

void gz_hmac_sha256_init(gz_hmac_sha256 *h, const void *key, size_t n)
{
    gz_hmac_sha256_pads(key, n, h->in.h, h->out.h);
    h->in.len = h->out.len = 64;
    h->in.n = h->out.n = 0;
}

void gz_hmac_sha256_update(gz_hmac_sha256 *h, const void *p, size_t n)
{
    gz_sha256_update(&h->in, p, n);
}

void gz_hmac_sha256_final(gz_hmac_sha256 *h, u8 out[32])
{
    u8 d[32];
    gz_sha256_final(&h->in, d);
    gz_sha256_update(&h->out, d, 32);
    gz_sha256_final(&h->out, out);
}

void gz_hmac_sha256_calc(const void *key, size_t kn, const void *p, size_t n, u8 out[32])
{
    gz_hmac_sha256 h;
    gz_hmac_sha256_init(&h, key, kn);
    gz_hmac_sha256_update(&h, p, n);
    gz_hmac_sha256_final(&h, out);
}

/* Each iteration is exactly two compressions: the inner and outer messages are
 * both 32 bytes after a 64-byte pad block, so one padded block serves both. */
void gz_pbkdf2_sha256_iterate(const u32 ist[8], const u32 ost[8], u32 u[8], u32 f[8], u32 iter)
{
    gz_sha_blocks_fn blocks = gz_sha256_kernel;
    u8 blk[64];
    u32 s[8];
    __builtin_memset(blk + 32, 0, 32);
    blk[32] = 0x80;
    wr32be(blk + 60, (64 + 32) * 8);
    while (iter--) {
        for (int i = 0; i < 8; i++) { wr32be(blk + 4 * i, u[i]); s[i] = ist[i]; }
        blocks(s, blk, 1);
        for (int i = 0; i < 8; i++) { wr32be(blk + 4 * i, s[i]); u[i] = ost[i]; }
        blocks(u, blk, 1);
        for (int i = 0; i < 8; i++) f[i] ^= u[i];
    }
}

void gz_pbkdf2_sha256(const void *pw, size_t pwn, const void *salt, size_t sn,
                      u32 iter, u8 *out, size_t outn)
{
    u32 ist[8], ost[8];
    gz_hmac_sha256_pads(pw, pwn, ist, ost);
    if (!iter) iter = 1;
    for (u32 blk = 1; outn; blk++) {
        gz_hmac_sha256 h;
        u8 be[4], t[32];
        u32 u[8], f[8];
        for (int i = 0; i < 8; i++) { h.in.h[i] = ist[i]; h.out.h[i] = ost[i]; }
        h.in.len = h.out.len = 64;
        h.in.n = h.out.n = 0;
        wr32be(be, blk);
        gz_hmac_sha256_update(&h, salt, sn);
        gz_hmac_sha256_update(&h, be, 4);
        gz_hmac_sha256_final(&h, t);
        for (int i = 0; i < 8; i++) f[i] = u[i] = rd32be(t + 4 * i);
        gz_pbkdf2_sha256_iterate(ist, ost, u, f, iter - 1);
        for (int i = 0; i < 8; i++) wr32be(t + 4 * i, f[i]);
        size_t take = outn < 32 ? outn : 32;
        __builtin_memcpy(out, t, take);
        out += take; outn -= take;
    }
}
