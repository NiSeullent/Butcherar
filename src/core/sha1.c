/*
 * 고깃ZIP - SHA-1 with portable / SHA-NI / ARMv8 block kernels, HMAC-SHA1 and
 * PBKDF2-HMAC-SHA1 (WinZip AES, RAR 3.x key derivation)
 */
#include "crypto.h"

#if defined(__i386__) || defined(__x86_64__)
#include <immintrin.h>
#endif
#if defined(__aarch64__)
#include <arm_neon.h>
#if defined(__clang__)
#define GZ_TARGET_SHA1 __attribute__((target("sha2")))
#else
#define GZ_TARGET_SHA1 __attribute__((target("+crypto")))
#endif
#endif

gz_sha_blocks_fn gz_sha1_kernel = gz_sha1_blocks_c;

static const u32 H1[5] = { 0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u };

/* ---------------- portable kernel ---------------- */

static inline u32 rol32(u32 x, int n) { return (x << n) | (x >> (32 - n)); }

#define F1(b, c, d) ((d) ^ ((b) & ((c) ^ (d))))
#define F2(b, c, d) ((b) ^ (c) ^ (d))
#define F3(b, c, d) (((b) & (c)) | ((d) & ((b) | (c))))
/* w[] is a 16-word ring: rounds >= 16 expand in place */
#define WX(i) (w[(i) & 15] = rol32(w[((i) + 13) & 15] ^ w[((i) + 8) & 15] ^ w[((i) + 2) & 15] ^ w[(i) & 15], 1))
#define R1(F, K, a, b, c, d, e, W) do { e += rol32(a, 5) + F(b, c, d) + (K) + (W); b = rol32(b, 30); } while (0)
/* five rounds rotate the variable roles back to the start */
#define R5(F, K, i, WF) do {                                                  \
        R1(F, K, a, b, c, d, e, WF(i));     R1(F, K, e, a, b, c, d, WF(i + 1)); \
        R1(F, K, d, e, a, b, c, WF(i + 2)); R1(F, K, c, d, e, a, b, WF(i + 3)); \
        R1(F, K, b, c, d, e, a, WF(i + 4));                                   \
    } while (0)
#define W0(i) (w[i])

void gz_sha1_blocks_c(u32 *st, const u8 *p, size_t nb)
{
    u32 w[16];
    while (nb--) {
        u32 a = st[0], b = st[1], c = st[2], d = st[3], e = st[4];
        int i;
        for (i = 0; i < 16; i++) w[i] = rd32be(p + 4 * i);
        R5(F1, 0x5A827999u, 0, W0);
        R5(F1, 0x5A827999u, 5, W0);
        R5(F1, 0x5A827999u, 10, W0);
        R1(F1, 0x5A827999u, a, b, c, d, e, w[15]);
        R1(F1, 0x5A827999u, e, a, b, c, d, WX(16));
        R1(F1, 0x5A827999u, d, e, a, b, c, WX(17));
        R1(F1, 0x5A827999u, c, d, e, a, b, WX(18));
        R1(F1, 0x5A827999u, b, c, d, e, a, WX(19));
        for (i = 20; i < 40; i += 5) R5(F2, 0x6ED9EBA1u, i, WX);
        for (; i < 60; i += 5) R5(F3, 0x8F1BBCDCu, i, WX);
        for (; i < 80; i += 5) R5(F2, 0xCA62C1D6u, i, WX);
        st[0] += a; st[1] += b; st[2] += c; st[3] += d; st[4] += e;
        p += 64;
    }
}

/* ---------------- x86 SHA-NI ---------------- */
#if defined(__i386__) || defined(__x86_64__)

/* M0 <- W[t..t+3] from M0..M3 = W[t-16..t-1] */
#define NI_SCHED(M0, M1, M2, M3) M0 = _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32(M0, M1), M2), M3)
/* 4 rounds; `prev` keeps ABCD of the previous group to derive E */
#define NI_G(f, M) do { e = _mm_sha1nexte_epu32(prev, M); prev = abcd;       \
                        abcd = _mm_sha1rnds4_epu32(abcd, e, f); } while (0)

__attribute__((target("sha,sse4.1")))
void gz_sha1_blocks_shani(u32 *st, const u8 *p, size_t nb)
{
    const __m128i bswap = _mm_set_epi64x(0x0001020304050607LL, 0x08090a0b0c0d0e0fLL);
    __m128i abcd = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i *)st), 0x1B);
    __m128i e0 = _mm_set_epi32((int)st[4], 0, 0, 0);
    while (nb--) {
        __m128i abcd_sv = abcd, e0_sv = e0, e, prev;
        __m128i m0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(p + 0)), bswap);
        __m128i m1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(p + 16)), bswap);
        __m128i m2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(p + 32)), bswap);
        __m128i m3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(p + 48)), bswap);
        e = _mm_add_epi32(e0, m0);
        prev = abcd;
        abcd = _mm_sha1rnds4_epu32(abcd, e, 0);
        NI_G(0, m1); NI_G(0, m2); NI_G(0, m3);
        NI_SCHED(m0, m1, m2, m3); NI_G(0, m0);                                   /* 16-19 */
        NI_SCHED(m1, m2, m3, m0); NI_G(1, m1);
        NI_SCHED(m2, m3, m0, m1); NI_G(1, m2);
        NI_SCHED(m3, m0, m1, m2); NI_G(1, m3);
        NI_SCHED(m0, m1, m2, m3); NI_G(1, m0);
        NI_SCHED(m1, m2, m3, m0); NI_G(1, m1);                                   /* 36-39 */
        NI_SCHED(m2, m3, m0, m1); NI_G(2, m2);
        NI_SCHED(m3, m0, m1, m2); NI_G(2, m3);
        NI_SCHED(m0, m1, m2, m3); NI_G(2, m0);
        NI_SCHED(m1, m2, m3, m0); NI_G(2, m1);
        NI_SCHED(m2, m3, m0, m1); NI_G(2, m2);                                   /* 56-59 */
        NI_SCHED(m3, m0, m1, m2); NI_G(3, m3);
        NI_SCHED(m0, m1, m2, m3); NI_G(3, m0);
        NI_SCHED(m1, m2, m3, m0); NI_G(3, m1);
        NI_SCHED(m2, m3, m0, m1); NI_G(3, m2);
        NI_SCHED(m3, m0, m1, m2); NI_G(3, m3);                                   /* 76-79 */
        e0 = _mm_sha1nexte_epu32(prev, e0_sv);
        abcd = _mm_add_epi32(abcd, abcd_sv);
        p += 64;
    }
    _mm_storeu_si128((__m128i *)st, _mm_shuffle_epi32(abcd, 0x1B));
    st[4] = (u32)_mm_extract_epi32(e0, 3);
}
#else
void gz_sha1_blocks_shani(u32 *st, const u8 *p, size_t nb) { gz_sha1_blocks_c(st, p, nb); }
#endif

/* ---------------- ARMv8 SHA1 ---------------- */
#if defined(__aarch64__)

#define ARM_SCHED(M0, M1, M2, M3) M0 = vsha1su1q_u32(vsha1su0q_u32(M0, M1, M2), M3)
#define ARM_G(OP, K, M) do {                                                  \
        uint32x4_t t_ = vaddq_u32(M, K);                                      \
        u32 en_ = vsha1h_u32(vgetq_lane_u32(abcd, 0));                        \
        abcd = OP(abcd, e, t_);                                               \
        e = en_;                                                              \
    } while (0)

GZ_TARGET_SHA1
void gz_sha1_blocks_arm(u32 *st, const u8 *p, size_t nb)
{
    const uint32x4_t k0 = vdupq_n_u32(0x5A827999u), k1 = vdupq_n_u32(0x6ED9EBA1u);
    const uint32x4_t k2 = vdupq_n_u32(0x8F1BBCDCu), k3 = vdupq_n_u32(0xCA62C1D6u);
    uint32x4_t abcd = vld1q_u32(st);
    u32 e = st[4];
    while (nb--) {
        uint32x4_t abcd_sv = abcd;
        u32 e_sv = e;
        uint32x4_t m0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 0)));
        uint32x4_t m1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 16)));
        uint32x4_t m2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 32)));
        uint32x4_t m3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p + 48)));
        ARM_G(vsha1cq_u32, k0, m0); ARM_G(vsha1cq_u32, k0, m1);
        ARM_G(vsha1cq_u32, k0, m2); ARM_G(vsha1cq_u32, k0, m3);
        ARM_SCHED(m0, m1, m2, m3); ARM_G(vsha1cq_u32, k0, m0);
        ARM_SCHED(m1, m2, m3, m0); ARM_G(vsha1pq_u32, k1, m1);
        ARM_SCHED(m2, m3, m0, m1); ARM_G(vsha1pq_u32, k1, m2);
        ARM_SCHED(m3, m0, m1, m2); ARM_G(vsha1pq_u32, k1, m3);
        ARM_SCHED(m0, m1, m2, m3); ARM_G(vsha1pq_u32, k1, m0);
        ARM_SCHED(m1, m2, m3, m0); ARM_G(vsha1pq_u32, k1, m1);
        ARM_SCHED(m2, m3, m0, m1); ARM_G(vsha1mq_u32, k2, m2);
        ARM_SCHED(m3, m0, m1, m2); ARM_G(vsha1mq_u32, k2, m3);
        ARM_SCHED(m0, m1, m2, m3); ARM_G(vsha1mq_u32, k2, m0);
        ARM_SCHED(m1, m2, m3, m0); ARM_G(vsha1mq_u32, k2, m1);
        ARM_SCHED(m2, m3, m0, m1); ARM_G(vsha1mq_u32, k2, m2);
        ARM_SCHED(m3, m0, m1, m2); ARM_G(vsha1pq_u32, k3, m3);
        ARM_SCHED(m0, m1, m2, m3); ARM_G(vsha1pq_u32, k3, m0);
        ARM_SCHED(m1, m2, m3, m0); ARM_G(vsha1pq_u32, k3, m1);
        ARM_SCHED(m2, m3, m0, m1); ARM_G(vsha1pq_u32, k3, m2);
        ARM_SCHED(m3, m0, m1, m2); ARM_G(vsha1pq_u32, k3, m3);
        abcd = vaddq_u32(abcd, abcd_sv);
        e += e_sv;
        p += 64;
    }
    vst1q_u32(st, abcd);
    st[4] = e;
}
#else
void gz_sha1_blocks_arm(u32 *st, const u8 *p, size_t nb) { gz_sha1_blocks_c(st, p, nb); }
#endif

/* ---------------- streaming interface ---------------- */

void gz_sha1_init(gz_sha1 *s)
{
    for (int i = 0; i < 5; i++) s->h[i] = H1[i];
    s->len = 0;
    s->n = 0;
}

void gz_sha1_update(gz_sha1 *s, const void *pv, size_t n)
{
    const u8 *p = (const u8 *)pv;
    s->len += n;
    if (s->n) {
        size_t take = 64 - s->n;
        if (take > n) take = n;
        __builtin_memcpy(s->buf + s->n, p, take);
        s->n += (u32)take; p += take; n -= take;
        if (s->n < 64) return;
        gz_sha1_kernel(s->h, s->buf, 1);
        s->n = 0;
    }
    if (n >= 64) {
        size_t nb = n >> 6;
        gz_sha1_kernel(s->h, p, nb);
        p += nb << 6;
        n &= 63;
    }
    if (n) { __builtin_memcpy(s->buf, p, n); s->n = (u32)n; }
}

void gz_sha1_final(gz_sha1 *s, u8 out[20])
{
    u32 n = s->n;
    u64 bits = s->len << 3;
    s->buf[n++] = 0x80;
    if (n > 56) {
        __builtin_memset(s->buf + n, 0, 64 - n);
        gz_sha1_kernel(s->h, s->buf, 1);
        n = 0;
    }
    __builtin_memset(s->buf + n, 0, 56 - n);
    wr64be(s->buf + 56, bits);
    gz_sha1_kernel(s->h, s->buf, 1);
    for (int i = 0; i < 5; i++) wr32be(out + 4 * i, s->h[i]);
    s->n = 0;
}

void gz_sha1_calc(const void *p, size_t n, u8 out[20])
{
    gz_sha1 s;
    gz_sha1_init(&s);
    gz_sha1_update(&s, p, n);
    gz_sha1_final(&s, out);
}

/* ---------------- HMAC / PBKDF2 ---------------- */

static void hmac_sha1_pads(const void *key, size_t n, u32 ist[5], u32 ost[5])
{
    u8 k[64], blk[64];
    __builtin_memset(k, 0, 64);
    if (n > 64) gz_sha1_calc(key, n, k);
    else if (n) __builtin_memcpy(k, key, n);
    for (int i = 0; i < 5; i++) { ist[i] = H1[i]; ost[i] = H1[i]; }
    for (int i = 0; i < 64; i++) blk[i] = k[i] ^ 0x36;
    gz_sha1_kernel(ist, blk, 1);
    for (int i = 0; i < 64; i++) blk[i] = k[i] ^ 0x5c;
    gz_sha1_kernel(ost, blk, 1);
}

void gz_hmac_init(gz_hmac_sha1 *h, const void *key, size_t n)
{
    hmac_sha1_pads(key, n, h->in.h, h->out.h);
    h->in.len = h->out.len = 64;
    h->in.n = h->out.n = 0;
}

void gz_hmac_update(gz_hmac_sha1 *h, const void *p, size_t n) { gz_sha1_update(&h->in, p, n); }

void gz_hmac_final(gz_hmac_sha1 *h, u8 out[20])
{
    u8 d[20];
    gz_sha1_final(&h->in, d);
    gz_sha1_update(&h->out, d, 20);
    gz_sha1_final(&h->out, out);
}

void gz_hmac_sha1_calc(const void *key, size_t kn, const void *p, size_t n, u8 out[20])
{
    gz_hmac_sha1 h;
    gz_hmac_init(&h, key, kn);
    gz_hmac_update(&h, p, n);
    gz_hmac_final(&h, out);
}

/* Iterations after the first: two compressions each with a pre-padded block
 * (inner and outer messages are both 20 bytes after the 64-byte pad block). */
void gz_pbkdf2_sha1(const void *pw, size_t pwn, const void *salt, size_t sn,
                    u32 iter, u8 *out, size_t outn)
{
    gz_sha_blocks_fn blocks = gz_sha1_kernel;
    u32 ist[5], ost[5];
    u8 blk[64];
    hmac_sha1_pads(pw, pwn, ist, ost);
    if (!iter) iter = 1;
    __builtin_memset(blk + 20, 0, 44);
    blk[20] = 0x80;
    wr32be(blk + 60, (64 + 20) * 8);
    for (u32 bi = 1; outn; bi++) {
        gz_hmac_sha1 h;
        u8 be[4], t[20];
        u32 u[5], f[5], s[5];
        for (int i = 0; i < 5; i++) { h.in.h[i] = ist[i]; h.out.h[i] = ost[i]; }
        h.in.len = h.out.len = 64;
        h.in.n = h.out.n = 0;
        wr32be(be, bi);
        gz_hmac_update(&h, salt, sn);
        gz_hmac_update(&h, be, 4);
        gz_hmac_final(&h, t);
        for (int i = 0; i < 5; i++) f[i] = u[i] = rd32be(t + 4 * i);
        for (u32 it = 1; it < iter; it++) {
            for (int i = 0; i < 5; i++) { wr32be(blk + 4 * i, u[i]); s[i] = ist[i]; }
            blocks(s, blk, 1);
            for (int i = 0; i < 5; i++) { wr32be(blk + 4 * i, s[i]); u[i] = ost[i]; }
            blocks(u, blk, 1);
            for (int i = 0; i < 5; i++) f[i] ^= u[i];
        }
        for (int i = 0; i < 5; i++) wr32be(t + 4 * i, f[i]);
        size_t take = outn < 20 ? outn : 20;
        __builtin_memcpy(out, t, take);
        out += take; outn -= take;
    }
}
