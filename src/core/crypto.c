/*
 * 고깃ZIP - ZipCrypto, SHA-1, HMAC, PBKDF2, AES-CTR (T-table / AES-NI / VAES)
 */
#include "crypto.h"
#include "crc32.h"

#if defined(__i386__) || defined(__x86_64__)
#include <immintrin.h>
#define GZ_HAVE_AESNI 1
#endif

/* ======================= ZipCrypto ======================= */

#define ZC_UPDATE(c, b) do {                                                   \
        (c)->k0 = gz_crc32_byte((c)->k0, (u8)(b));                             \
        (c)->k1 = ((c)->k1 + ((c)->k0 & 0xff)) * 134775813u + 1;               \
        (c)->k2 = gz_crc32_byte((c)->k2, (u8)((c)->k1 >> 24));                 \
    } while (0)

void gz_zc_init(gz_zipcrypto *c, const u8 *pw, size_t n)
{
    c->k0 = 0x12345678u;
    c->k1 = 0x23456789u;
    c->k2 = 0x34567890u;
    for (size_t i = 0; i < n; i++) ZC_UPDATE(c, pw[i]);
}

void gz_zc_decrypt(gz_zipcrypto *c, u8 *buf, size_t n)
{
    gz_zipcrypto k = *c;
    for (size_t i = 0; i < n; i++) {
        u32 t = (k.k2 | 2) & 0xffff;
        u8 d = buf[i] ^ (u8)((t * (t ^ 1)) >> 8);
        ZC_UPDATE(&k, d);
        buf[i] = d;
    }
    *c = k;
}

/* ======================= SHA-1 ======================= */

static inline u32 rol32(u32 x, int n) { return (x << n) | (x >> (32 - n)); }
static inline u32 be32(const u8 *p) { return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3]; }

static void sha1_block(u32 h[5], const u8 *p)
{
    u32 w[80], a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], t;
    int i;
    for (i = 0; i < 16; i++) w[i] = be32(p + 4 * i);
    for (; i < 80; i++) w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    for (i = 0; i < 20; i++) { t = rol32(a, 5) + ((b & c) | (~b & d)) + e + w[i] + 0x5A827999u; e = d; d = c; c = rol32(b, 30); b = a; a = t; }
    for (; i < 40; i++) { t = rol32(a, 5) + (b ^ c ^ d) + e + w[i] + 0x6ED9EBA1u; e = d; d = c; c = rol32(b, 30); b = a; a = t; }
    for (; i < 60; i++) { t = rol32(a, 5) + ((b & c) | (b & d) | (c & d)) + e + w[i] + 0x8F1BBCDCu; e = d; d = c; c = rol32(b, 30); b = a; a = t; }
    for (; i < 80; i++) { t = rol32(a, 5) + (b ^ c ^ d) + e + w[i] + 0xCA62C1D6u; e = d; d = c; c = rol32(b, 30); b = a; a = t; }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

void gz_sha1_init(gz_sha1 *s)
{
    s->h[0] = 0x67452301u; s->h[1] = 0xEFCDAB89u; s->h[2] = 0x98BADCFEu;
    s->h[3] = 0x10325476u; s->h[4] = 0xC3D2E1F0u;
    s->len = 0; s->n = 0;
}

void gz_sha1_update(gz_sha1 *s, const u8 *p, size_t n)
{
    s->len += n;
    if (s->n) {
        while (n && s->n < 64) { s->buf[s->n++] = *p++; n--; }
        if (s->n < 64) return;
        sha1_block(s->h, s->buf);
        s->n = 0;
    }
    while (n >= 64) { sha1_block(s->h, p); p += 64; n -= 64; }
    while (n--) s->buf[s->n++] = *p++;
}

void gz_sha1_final(gz_sha1 *s, u8 out[20])
{
    u64 bits = s->len * 8;
    u8 pad = 0x80;
    gz_sha1_update(s, &pad, 1);
    pad = 0;
    while (s->n != 56) gz_sha1_update(s, &pad, 1);
    u8 lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (u8)(bits >> (56 - 8 * i));
    gz_sha1_update(s, lb, 8);
    for (int i = 0; i < 5; i++) {
        out[4 * i] = (u8)(s->h[i] >> 24); out[4 * i + 1] = (u8)(s->h[i] >> 16);
        out[4 * i + 2] = (u8)(s->h[i] >> 8); out[4 * i + 3] = (u8)s->h[i];
    }
}

void gz_hmac_init(gz_hmac_sha1 *h, const u8 *key, size_t n)
{
    u8 k[64], pad[64];
    u32 i;
    for (i = 0; i < 64; i++) k[i] = 0;
    if (n > 64) { gz_sha1 t; gz_sha1_init(&t); gz_sha1_update(&t, key, n); gz_sha1_final(&t, k); }
    else for (i = 0; i < n; i++) k[i] = key[i];
    for (i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    gz_sha1_init(&h->in); gz_sha1_update(&h->in, pad, 64);
    for (i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
    gz_sha1_init(&h->out); gz_sha1_update(&h->out, pad, 64);
}

void gz_hmac_update(gz_hmac_sha1 *h, const u8 *p, size_t n) { gz_sha1_update(&h->in, p, n); }

void gz_hmac_final(gz_hmac_sha1 *h, u8 out[20])
{
    u8 d[20];
    gz_sha1_final(&h->in, d);
    gz_sha1_update(&h->out, d, 20);
    gz_sha1_final(&h->out, out);
}

void gz_pbkdf2_sha1(const u8 *pw, size_t pwn, const u8 *salt, size_t sn,
                    u32 iter, u8 *out, size_t outn)
{
    gz_hmac_sha1 base, h;
    gz_hmac_init(&base, pw, pwn);
    for (u32 blk = 1; outn; blk++) {
        u8 u[20], t[20], be[4] = { (u8)(blk >> 24), (u8)(blk >> 16), (u8)(blk >> 8), (u8)blk };
        h = base;
        gz_hmac_update(&h, salt, sn);
        gz_hmac_update(&h, be, 4);
        gz_hmac_final(&h, u);
        for (int i = 0; i < 20; i++) t[i] = u[i];
        for (u32 it = 1; it < iter; it++) {
            h = base;
            gz_hmac_update(&h, u, 20);
            gz_hmac_final(&h, u);
            for (int i = 0; i < 20; i++) t[i] ^= u[i];
        }
        size_t take = outn < 20 ? outn : 20;
        for (size_t i = 0; i < take; i++) *out++ = t[i];
        outn -= take;
    }
}

/* ======================= AES ======================= */

static u8 s_sbox[256];
static u32 s_te0[256], s_te1[256], s_te2[256], s_te3[256];
gz_aes_ctr_fn gz_aes_ctr_kernel = gz_aes_ctr_soft;

static u8 gmul2(u8 x) { return (u8)((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }

void gz_aes_init(void)
{
    /* S-box from multiplicative inverse + affine transform */
    u8 p = 1, q = 1;
    do {
        p = p ^ (u8)(p << 1) ^ ((p & 0x80) ? 0x1b : 0);          /* p *= 3   */
        q ^= q << 1; q ^= q << 2; q ^= q << 4;                   /* q /= 3   */
        if (q & 0x80) q ^= 0x09;
        u8 x = q ^ (u8)((q << 1) | (q >> 7)) ^ (u8)((q << 2) | (q >> 6)) ^
               (u8)((q << 3) | (q >> 5)) ^ (u8)((q << 4) | (q >> 4));
        s_sbox[p] = x ^ 0x63;
    } while (p != 1);
    s_sbox[0] = 0x63;

    for (u32 i = 0; i < 256; i++) {
        u32 s = s_sbox[i], s2 = gmul2((u8)s), s3 = s2 ^ s;
        u32 t = s2 | (s << 8) | (s << 16) | (s3 << 24);
        s_te0[i] = t;
        s_te1[i] = (t << 8) | (t >> 24);
        s_te2[i] = (t << 16) | (t >> 16);
        s_te3[i] = (t << 24) | (t >> 8);
    }
}

void gz_aes_ctr_setup(gz_aes_ctr *a, const u8 *key, int keylen)
{
    static const u8 rcon[11] = { 0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54 };
    int nk = keylen / 4, nr = nk + 6, total = 4 * (nr + 1);
    u8 *w = a->rk;
    for (int i = 0; i < keylen; i++) w[i] = key[i];
    for (int i = nk; i < total; i++) {
        u8 t[4] = { w[4 * i - 4], w[4 * i - 3], w[4 * i - 2], w[4 * i - 1] };
        if (i % nk == 0) {
            u8 t0 = t[0];
            t[0] = s_sbox[t[1]] ^ rcon[i / nk];
            t[1] = s_sbox[t[2]];
            t[2] = s_sbox[t[3]];
            t[3] = s_sbox[t0];
        } else if (nk > 6 && i % nk == 4) {
            for (int j = 0; j < 4; j++) t[j] = s_sbox[t[j]];
        }
        for (int j = 0; j < 4; j++) w[4 * i + j] = w[4 * (i - nk) + j] ^ t[j];
    }
    a->rounds = nr;
    for (int i = 0; i < 16; i++) a->ctr[i] = 0;
    a->ks_pos = 16;
}

/* WinZip/Gladman counter: little endian, low 8 bytes */
static inline void ctr_inc(u8 *c)
{
    for (int j = 0; j < 8; j++) if (++c[j]) break;
}

static void aes_encrypt_soft(const gz_aes_ctr *a, const u8 *in, u8 *out)
{
    const u8 *rk = a->rk;
    u32 s0 = rd32(in) ^ rd32(rk), s1 = rd32(in + 4) ^ rd32(rk + 4),
        s2 = rd32(in + 8) ^ rd32(rk + 8), s3 = rd32(in + 12) ^ rd32(rk + 12);
    for (int r = 1; r < a->rounds; r++) {
        rk += 16;
        u32 t0 = s_te0[s0 & 0xff] ^ s_te1[(s1 >> 8) & 0xff] ^ s_te2[(s2 >> 16) & 0xff] ^ s_te3[s3 >> 24] ^ rd32(rk);
        u32 t1 = s_te0[s1 & 0xff] ^ s_te1[(s2 >> 8) & 0xff] ^ s_te2[(s3 >> 16) & 0xff] ^ s_te3[s0 >> 24] ^ rd32(rk + 4);
        u32 t2 = s_te0[s2 & 0xff] ^ s_te1[(s3 >> 8) & 0xff] ^ s_te2[(s0 >> 16) & 0xff] ^ s_te3[s1 >> 24] ^ rd32(rk + 8);
        u32 t3 = s_te0[s3 & 0xff] ^ s_te1[(s0 >> 8) & 0xff] ^ s_te2[(s1 >> 16) & 0xff] ^ s_te3[s2 >> 24] ^ rd32(rk + 12);
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    rk += 16;
#define SB(x) ((u32)s_sbox[(x)])
    wr32(out,      (SB(s0 & 0xff) | SB((s1 >> 8) & 0xff) << 8 | SB((s2 >> 16) & 0xff) << 16 | SB(s3 >> 24) << 24) ^ rd32(rk));
    wr32(out + 4,  (SB(s1 & 0xff) | SB((s2 >> 8) & 0xff) << 8 | SB((s3 >> 16) & 0xff) << 16 | SB(s0 >> 24) << 24) ^ rd32(rk + 4));
    wr32(out + 8,  (SB(s2 & 0xff) | SB((s3 >> 8) & 0xff) << 8 | SB((s0 >> 16) & 0xff) << 16 | SB(s1 >> 24) << 24) ^ rd32(rk + 8));
    wr32(out + 12, (SB(s3 & 0xff) | SB((s0 >> 8) & 0xff) << 8 | SB((s1 >> 16) & 0xff) << 16 | SB(s2 >> 24) << 24) ^ rd32(rk + 12));
#undef SB
}

/* consume left-over key stream; returns bytes handled */
static size_t ctr_drain(gz_aes_ctr *a, u8 *buf, size_t n)
{
    size_t k = 0;
    while (k < n && a->ks_pos < 16) buf[k++] ^= a->ks[a->ks_pos++];
    return k;
}

void gz_aes_ctr_soft(gz_aes_ctr *a, u8 *buf, size_t n)
{
    size_t k = ctr_drain(a, buf, n);
    buf += k; n -= k;
    while (n) {
        ctr_inc(a->ctr);
        aes_encrypt_soft(a, a->ctr, a->ks);
        size_t take = n < 16 ? n : 16;
        for (size_t i = 0; i < take; i++) buf[i] ^= a->ks[i];
        a->ks_pos = (u32)take;
        buf += take; n -= take;
    }
}

#ifdef GZ_HAVE_AESNI

#define AESNI_CTR_BODY(ENC4)                                                    \
    size_t k = ctr_drain(a, buf, n);                                            \
    buf += k; n -= k;                                                           \
    const int nr = a->rounds;                                                   \
    __m128i rk[15];                                                             \
    for (int i = 0; i <= nr; i++) rk[i] = _mm_loadu_si128((const __m128i *)(a->rk + 16 * i)); \
    u64 lo = rd64(a->ctr), hi = rd64(a->ctr + 8);                               \
    while (n >= 64) {                                                           \
        __m128i b0 = _mm_set_epi64x((long long)hi, (long long)(lo + 1));        \
        __m128i b1 = _mm_set_epi64x((long long)hi, (long long)(lo + 2));        \
        __m128i b2 = _mm_set_epi64x((long long)hi, (long long)(lo + 3));        \
        __m128i b3 = _mm_set_epi64x((long long)hi, (long long)(lo + 4));        \
        lo += 4;                                                                \
        ENC4                                                                    \
        _mm_storeu_si128((__m128i *)(buf +  0), _mm_xor_si128(b0, _mm_loadu_si128((const __m128i *)(buf +  0)))); \
        _mm_storeu_si128((__m128i *)(buf + 16), _mm_xor_si128(b1, _mm_loadu_si128((const __m128i *)(buf + 16)))); \
        _mm_storeu_si128((__m128i *)(buf + 32), _mm_xor_si128(b2, _mm_loadu_si128((const __m128i *)(buf + 32)))); \
        _mm_storeu_si128((__m128i *)(buf + 48), _mm_xor_si128(b3, _mm_loadu_si128((const __m128i *)(buf + 48)))); \
        buf += 64; n -= 64;                                                     \
    }                                                                           \
    while (n) {                                                                 \
        lo++;                                                                   \
        __m128i b = _mm_set_epi64x((long long)hi, (long long)lo);               \
        b = _mm_xor_si128(b, rk[0]);                                            \
        for (int r = 1; r < nr; r++) b = _mm_aesenc_si128(b, rk[r]);            \
        b = _mm_aesenclast_si128(b, rk[nr]);                                    \
        _mm_storeu_si128((__m128i *)a->ks, b);                                  \
        size_t take = n < 16 ? n : 16;                                          \
        for (size_t i = 0; i < take; i++) buf[i] ^= a->ks[i];                   \
        a->ks_pos = (u32)take;                                                  \
        buf += take; n -= take;                                                 \
    }                                                                           \
    wr64(a->ctr, lo); wr64(a->ctr + 8, hi);

#define ENC4_XMM                                                                \
    b0 = _mm_xor_si128(b0, rk[0]); b1 = _mm_xor_si128(b1, rk[0]);               \
    b2 = _mm_xor_si128(b2, rk[0]); b3 = _mm_xor_si128(b3, rk[0]);               \
    for (int r = 1; r < nr; r++) {                                              \
        b0 = _mm_aesenc_si128(b0, rk[r]); b1 = _mm_aesenc_si128(b1, rk[r]);     \
        b2 = _mm_aesenc_si128(b2, rk[r]); b3 = _mm_aesenc_si128(b3, rk[r]);     \
    }                                                                           \
    b0 = _mm_aesenclast_si128(b0, rk[nr]); b1 = _mm_aesenclast_si128(b1, rk[nr]); \
    b2 = _mm_aesenclast_si128(b2, rk[nr]); b3 = _mm_aesenclast_si128(b3, rk[nr]);

__attribute__((target("sse4.1,aes")))
void gz_aes_ctr_aesni(gz_aes_ctr *a, u8 *buf, size_t n)
{
    AESNI_CTR_BODY(ENC4_XMM)
}

__attribute__((target("avx,aes")))
void gz_aes_ctr_aesni_avx(gz_aes_ctr *a, u8 *buf, size_t n)
{
    AESNI_CTR_BODY(ENC4_XMM)
}

#else
void gz_aes_ctr_aesni(gz_aes_ctr *a, u8 *buf, size_t n) { gz_aes_ctr_soft(a, buf, n); }
void gz_aes_ctr_aesni_avx(gz_aes_ctr *a, u8 *buf, size_t n) { gz_aes_ctr_soft(a, buf, n); }
#endif
