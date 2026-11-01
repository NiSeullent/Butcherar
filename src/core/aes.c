/*
 * 고깃ZIP - AES-128/192/256 (FIPS-197): ECB, CBC and WinZip CTR
 *
 *   soft    4+4 T-tables built at start-up (8 KiB, no static data in the binary)
 *   AES-NI  8 blocks in flight on x86-64 (4 on i386: only 8 xmm registers)
 *   VAES    16 blocks in 8 ymm registers (CBC decrypt, CTR)
 *   ARMv8   AESE/AESMC and AESD/AESIMC, 8 blocks in flight
 *
 * Decryption uses the "equivalent inverse cipher" key schedule (InvMixColumns
 * applied to the middle round keys), which is the layout AESDEC and AESD expect.
 */
#include "crypto.h"

#if defined(__i386__) || defined(__x86_64__)
#include <immintrin.h>
#endif
#if defined(__aarch64__)
#include <arm_neon.h>
#if defined(__clang__)
#define GZ_TARGET_AES __attribute__((target("aes")))
#else
#define GZ_TARGET_AES __attribute__((target("+aes")))
#endif
#endif

static u8 s_sbox[256], s_isbox[256];
static u32 s_te[4][256], s_td[4][256];

gz_aes_ecb_fn gz_aes_ecb_enc_kernel = gz_aes_ecb_enc_soft;
gz_aes_ecb_fn gz_aes_ecb_dec_kernel = gz_aes_ecb_dec_soft;
gz_aes_cbc_fn gz_aes_cbc_enc_kernel = gz_aes_cbc_enc_soft;
gz_aes_cbc_fn gz_aes_cbc_dec_kernel = gz_aes_cbc_dec_soft;
gz_aes_ctr_fn gz_aes_ctr_kernel = gz_aes_ctr_soft;

static u8 gmul(u8 a, u8 b)
{
    u8 r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = (u8)((a << 1) ^ ((a & 0x80) ? 0x1b : 0));
        b >>= 1;
    }
    return r;
}

static inline u32 rotl8(u32 x) { return (x << 8) | (x >> 24); }

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
    for (u32 i = 0; i < 256; i++) s_isbox[s_sbox[i]] = (u8)i;

    for (u32 i = 0; i < 256; i++) {
        u8 s = s_sbox[i], y = s_isbox[i];
        u32 t = gmul(s, 2) | ((u32)s << 8) | ((u32)s << 16) | ((u32)gmul(s, 3) << 24);
        u32 d = gmul(y, 14) | ((u32)gmul(y, 9) << 8) | ((u32)gmul(y, 13) << 16) | ((u32)gmul(y, 11) << 24);
        for (int j = 0; j < 4; j++) {
            s_te[j][i] = t; t = rotl8(t);
            s_td[j][i] = d; d = rotl8(d);
        }
    }
}

/* ---------------- key schedule ---------------- */

static int expand_key(u8 *w, const u8 *key, int keylen)
{
    static const u8 rcon[11] = { 0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54 };
    int nk = keylen / 4, nr = nk + 6, total = 4 * (nr + 1);
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
    return nr;
}

int gz_aes_set_encrypt_key(gz_aes *a, const u8 *key, int keylen)
{
    if (keylen != 16 && keylen != 24 && keylen != 32) return GZ_E_METHOD;
    a->rounds = expand_key(a->rk, key, keylen);
    return GZ_OK;
}

/* InvMixColumns of one column: Td includes InvSubBytes, cancelled by the S-box */
static u32 inv_mix(u32 w)
{
    return s_td[0][s_sbox[w & 0xff]] ^ s_td[1][s_sbox[(w >> 8) & 0xff]] ^
           s_td[2][s_sbox[(w >> 16) & 0xff]] ^ s_td[3][s_sbox[w >> 24]];
}

int gz_aes_set_decrypt_key(gz_aes *a, const u8 *key, int keylen)
{
    u8 ek[16 * 15];
    if (keylen != 16 && keylen != 24 && keylen != 32) return GZ_E_METHOD;
    int nr = expand_key(ek, key, keylen);
    a->rounds = nr;
    __builtin_memcpy(a->rk, ek + 16 * nr, 16);
    for (int i = 1; i < nr; i++)
        for (int c = 0; c < 16; c += 4)
            wr32(a->rk + 16 * i + c, inv_mix(rd32(ek + 16 * (nr - i) + c)));
    __builtin_memcpy(a->rk + 16 * nr, ek, 16);
    return GZ_OK;
}

/* ---------------- portable block functions ---------------- */

static void enc_soft(const u8 *rk, int nr, const u8 *in, u8 *out)
{
    const u32 *T0 = s_te[0], *T1 = s_te[1], *T2 = s_te[2], *T3 = s_te[3];
    u32 s0 = rd32(in) ^ rd32(rk), s1 = rd32(in + 4) ^ rd32(rk + 4),
        s2 = rd32(in + 8) ^ rd32(rk + 8), s3 = rd32(in + 12) ^ rd32(rk + 12);
    for (int r = 1; r < nr; r++) {
        rk += 16;
        u32 t0 = T0[s0 & 0xff] ^ T1[(s1 >> 8) & 0xff] ^ T2[(s2 >> 16) & 0xff] ^ T3[s3 >> 24] ^ rd32(rk);
        u32 t1 = T0[s1 & 0xff] ^ T1[(s2 >> 8) & 0xff] ^ T2[(s3 >> 16) & 0xff] ^ T3[s0 >> 24] ^ rd32(rk + 4);
        u32 t2 = T0[s2 & 0xff] ^ T1[(s3 >> 8) & 0xff] ^ T2[(s0 >> 16) & 0xff] ^ T3[s1 >> 24] ^ rd32(rk + 8);
        u32 t3 = T0[s3 & 0xff] ^ T1[(s0 >> 8) & 0xff] ^ T2[(s1 >> 16) & 0xff] ^ T3[s2 >> 24] ^ rd32(rk + 12);
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

static void dec_soft(const u8 *rk, int nr, const u8 *in, u8 *out)
{
    const u32 *T0 = s_td[0], *T1 = s_td[1], *T2 = s_td[2], *T3 = s_td[3];
    u32 s0 = rd32(in) ^ rd32(rk), s1 = rd32(in + 4) ^ rd32(rk + 4),
        s2 = rd32(in + 8) ^ rd32(rk + 8), s3 = rd32(in + 12) ^ rd32(rk + 12);
    for (int r = 1; r < nr; r++) {
        rk += 16;
        u32 t0 = T0[s0 & 0xff] ^ T1[(s3 >> 8) & 0xff] ^ T2[(s2 >> 16) & 0xff] ^ T3[s1 >> 24] ^ rd32(rk);
        u32 t1 = T0[s1 & 0xff] ^ T1[(s0 >> 8) & 0xff] ^ T2[(s3 >> 16) & 0xff] ^ T3[s2 >> 24] ^ rd32(rk + 4);
        u32 t2 = T0[s2 & 0xff] ^ T1[(s1 >> 8) & 0xff] ^ T2[(s0 >> 16) & 0xff] ^ T3[s3 >> 24] ^ rd32(rk + 8);
        u32 t3 = T0[s3 & 0xff] ^ T1[(s2 >> 8) & 0xff] ^ T2[(s1 >> 16) & 0xff] ^ T3[s0 >> 24] ^ rd32(rk + 12);
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    rk += 16;
#define IS(x) ((u32)s_isbox[(x)])
    wr32(out,      (IS(s0 & 0xff) | IS((s3 >> 8) & 0xff) << 8 | IS((s2 >> 16) & 0xff) << 16 | IS(s1 >> 24) << 24) ^ rd32(rk));
    wr32(out + 4,  (IS(s1 & 0xff) | IS((s0 >> 8) & 0xff) << 8 | IS((s3 >> 16) & 0xff) << 16 | IS(s2 >> 24) << 24) ^ rd32(rk + 4));
    wr32(out + 8,  (IS(s2 & 0xff) | IS((s1 >> 8) & 0xff) << 8 | IS((s0 >> 16) & 0xff) << 16 | IS(s3 >> 24) << 24) ^ rd32(rk + 8));
    wr32(out + 12, (IS(s3 & 0xff) | IS((s2 >> 8) & 0xff) << 8 | IS((s1 >> 16) & 0xff) << 16 | IS(s0 >> 24) << 24) ^ rd32(rk + 12));
#undef IS
}

static inline void xor16(u8 *d, const u8 *s)
{
    wr32(d, rd32(d) ^ rd32(s)); wr32(d + 4, rd32(d + 4) ^ rd32(s + 4));
    wr32(d + 8, rd32(d + 8) ^ rd32(s + 8)); wr32(d + 12, rd32(d + 12) ^ rd32(s + 12));
}

void gz_aes_ecb_enc_soft(const gz_aes *a, u8 *buf, size_t nb)
{
    for (; nb; nb--, buf += 16) enc_soft(a->rk, a->rounds, buf, buf);
}

void gz_aes_ecb_dec_soft(const gz_aes *a, u8 *buf, size_t nb)
{
    for (; nb; nb--, buf += 16) dec_soft(a->rk, a->rounds, buf, buf);
}

void gz_aes_cbc_enc_soft(const gz_aes *a, u8 iv[16], u8 *buf, size_t nb)
{
    const u8 *prev = iv;
    for (; nb; nb--, buf += 16) {
        xor16(buf, prev);
        enc_soft(a->rk, a->rounds, buf, buf);
        prev = buf;
    }
    if (prev != iv) __builtin_memcpy(iv, prev, 16);
}

void gz_aes_cbc_dec_soft(const gz_aes *a, u8 iv[16], u8 *buf, size_t nb)
{
    u8 c[16];
    for (; nb; nb--, buf += 16) {
        __builtin_memcpy(c, buf, 16);
        dec_soft(a->rk, a->rounds, buf, buf);
        xor16(buf, iv);
        __builtin_memcpy(iv, c, 16);
    }
}

void gz_aes_encrypt_block(const gz_aes *a, const u8 in[16], u8 out[16])
{
    if (out != in) __builtin_memcpy(out, in, 16);
    gz_aes_ecb_enc_kernel(a, out, 1);
}

void gz_aes_decrypt_block(const gz_aes *a, const u8 in[16], u8 out[16])
{
    if (out != in) __builtin_memcpy(out, in, 16);
    gz_aes_ecb_dec_kernel(a, out, 1);
}

/* ---------------- CTR (WinZip / Gladman) ---------------- */

void gz_aes_ctr_setup(gz_aes_ctr *a, const u8 *key, int keylen)
{
    if (keylen != 16 && keylen != 24 && keylen != 32) keylen = 16;   /* callers validate */
    a->rounds = expand_key(a->rk, key, keylen);
    __builtin_memset(a->ctr, 0, 16);
    a->ks_pos = 16;
}

/* little-endian counter in the low 8 bytes */
static inline void ctr_inc(u8 *c)
{
    for (int j = 0; j < 8; j++) if (++c[j]) break;
}

/* consume left-over key stream; returns bytes handled */
static size_t ctr_drain(gz_aes_ctr *a, u8 *buf, size_t n)
{
    size_t k = 0;
    while (k < n && a->ks_pos < 16) buf[k++] ^= a->ks[a->ks_pos++];
    return k;
}

/* encrypt the next counter block into a->ks and xor up to 16 bytes */
static size_t ctr_tail(gz_aes_ctr *a, u8 *buf, size_t n)
{
    size_t take = n < 16 ? n : 16;
    for (size_t i = 0; i < take; i++) buf[i] ^= a->ks[i];
    a->ks_pos = (u32)take;
    return take;
}

void gz_aes_ctr_soft(gz_aes_ctr *a, u8 *buf, size_t n)
{
    size_t k = ctr_drain(a, buf, n);
    buf += k; n -= k;
    while (n >= 16) {
        u8 ks[16];
        ctr_inc(a->ctr);
        enc_soft(a->rk, a->rounds, a->ctr, ks);
        xor16(buf, ks);
        buf += 16; n -= 16;
    }
    if (n) {
        ctr_inc(a->ctr);
        enc_soft(a->rk, a->rounds, a->ctr, a->ks);
        ctr_tail(a, buf, n);
    }
}

/* ---------------- x86 AES-NI / VAES ---------------- */
#if defined(__i386__) || defined(__x86_64__)

#define LDU(p) _mm_loadu_si128((const __m128i *)(p))
#define STU(p, v) _mm_storeu_si128((__m128i *)(p), v)
#if defined(__x86_64__)
#define NI_W 8
#define XW(OP) OP(0) OP(1) OP(2) OP(3) OP(4) OP(5) OP(6) OP(7)
#else
#define NI_W 4
#define XW(OP) OP(0) OP(1) OP(2) OP(3)
#endif

#define NI_KEYS                                                                \
    const int nr = a->rounds;                                                  \
    __m128i k[15];                                                             \
    for (int i_ = 0; i_ <= nr; i_++) k[i_] = LDU(a->rk + 16 * i_);

#define NI_LD(j)   __m128i b##j = _mm_xor_si128(LDU(buf + 16 * j), k[0]);
#define NI_ENC(j)  b##j = _mm_aesenc_si128(b##j, kr);
#define NI_ENCL(j) b##j = _mm_aesenclast_si128(b##j, kr);
#define NI_DEC(j)  b##j = _mm_aesdec_si128(b##j, kr);
#define NI_DECL(j) b##j = _mm_aesdeclast_si128(b##j, kr);
#define NI_ST(j)   STU(buf + 16 * j, b##j);
/* CBC: load ciphertext j before overwriting it, xor the previous one */
#define NI_CBC_ST(j) { __m128i c_ = LDU(buf + 16 * j); STU(buf + 16 * j, _mm_xor_si128(b##j, pv)); pv = c_; }

#define NI_ROUNDS(OP, OPL)                                                     \
    for (int r_ = 1; r_ < nr; r_++) { __m128i kr = k[r_]; XW(OP) }             \
    { __m128i kr = k[nr]; XW(OPL) }

#define NI_ONE(x, OP, OPL)                                                     \
    x = _mm_xor_si128(x, k[0]);                                                \
    for (int r_ = 1; r_ < nr; r_++) x = OP(x, k[r_]);                          \
    x = OPL(x, k[nr]);

#define NI_ECB_BODY(OP, OPL, OPF, OPLF)                                        \
    NI_KEYS                                                                    \
    for (; nb >= NI_W; nb -= NI_W, buf += 16 * NI_W) {                         \
        XW(NI_LD) NI_ROUNDS(OP, OPL) XW(NI_ST)                                 \
    }                                                                          \
    for (; nb; nb--, buf += 16) {                                              \
        __m128i x = LDU(buf);                                                  \
        NI_ONE(x, OPF, OPLF)                                                   \
        STU(buf, x);                                                           \
    }

#define NI_CBC_ENC_BODY                                                        \
    NI_KEYS                                                                    \
    __m128i v = LDU(iv);                                                       \
    for (; nb; nb--, buf += 16) {                                              \
        v = _mm_xor_si128(v, LDU(buf));                                        \
        NI_ONE(v, _mm_aesenc_si128, _mm_aesenclast_si128)                      \
        STU(buf, v);                                                           \
    }                                                                          \
    STU(iv, v);

#define NI_CBC_DEC_BODY                                                        \
    NI_KEYS                                                                    \
    __m128i pv = LDU(iv);                                                      \
    for (; nb >= NI_W; nb -= NI_W, buf += 16 * NI_W) {                         \
        XW(NI_LD) NI_ROUNDS(NI_DEC, NI_DECL) XW(NI_CBC_ST)                     \
    }                                                                          \
    for (; nb; nb--, buf += 16) {                                              \
        __m128i c = LDU(buf), x = c;                                           \
        NI_ONE(x, _mm_aesdec_si128, _mm_aesdeclast_si128)                      \
        STU(buf, _mm_xor_si128(x, pv));                                        \
        pv = c;                                                                \
    }                                                                          \
    STU(iv, pv);

/* only the low 64 bits count (Gladman's fcrypt), so a 64-bit lane add is exact */
#define NI_CTR_LD(j) __m128i b##j = _mm_xor_si128(_mm_add_epi64(cb, _mm_set_epi64x(0, j + 1)), k[0]);
#define NI_CTR_ST(j) STU(buf + 16 * j, _mm_xor_si128(b##j, LDU(buf + 16 * j)));

#define NI_CTR_BODY                                                            \
    size_t d_ = ctr_drain(a, buf, n);                                          \
    buf += d_; n -= d_;                                                        \
    NI_KEYS                                                                    \
    u64 lo = rd64(a->ctr), hi = rd64(a->ctr + 8);                              \
    __m128i cb = LDU(a->ctr);                                                  \
    for (; n >= 16 * NI_W; n -= 16 * NI_W, buf += 16 * NI_W) {                 \
        XW(NI_CTR_LD) NI_ROUNDS(NI_ENC, NI_ENCL) XW(NI_CTR_ST)                 \
        lo += NI_W;                                                            \
        cb = _mm_add_epi64(cb, _mm_set_epi64x(0, NI_W));                       \
    }                                                                          \
    while (n) {                                                                \
        __m128i x = _mm_set_epi64x((long long)hi, (long long)++lo);            \
        NI_ONE(x, _mm_aesenc_si128, _mm_aesenclast_si128)                      \
        if (n >= 16) {                                                         \
            STU(buf, _mm_xor_si128(x, LDU(buf)));                              \
            buf += 16; n -= 16;                                                \
        } else {                                                               \
            STU(a->ks, x);                                                     \
            n -= ctr_tail(a, buf, n);                                          \
        }                                                                      \
    }                                                                          \
    wr64(a->ctr, lo); wr64(a->ctr + 8, hi);

#define AESNI_FUNCS(SUF, TGT)                                                                      \
TGT void gz_aes_ecb_enc_##SUF(const gz_aes *a, u8 *buf, size_t nb)                                 \
    { NI_ECB_BODY(NI_ENC, NI_ENCL, _mm_aesenc_si128, _mm_aesenclast_si128) }                       \
TGT void gz_aes_ecb_dec_##SUF(const gz_aes *a, u8 *buf, size_t nb)                                 \
    { NI_ECB_BODY(NI_DEC, NI_DECL, _mm_aesdec_si128, _mm_aesdeclast_si128) }                       \
TGT void gz_aes_cbc_enc_##SUF(const gz_aes *a, u8 iv[16], u8 *buf, size_t nb) { NI_CBC_ENC_BODY }  \
TGT void gz_aes_cbc_dec_##SUF(const gz_aes *a, u8 iv[16], u8 *buf, size_t nb) { NI_CBC_DEC_BODY }

AESNI_FUNCS(aesni, __attribute__((target("sse4.1,aes"))))
AESNI_FUNCS(avx, __attribute__((target("avx,aes"))))

__attribute__((target("sse4.1,aes")))
void gz_aes_ctr_aesni(gz_aes_ctr *a, u8 *buf, size_t n) { NI_CTR_BODY }

__attribute__((target("avx,aes")))
void gz_aes_ctr_aesni_avx(gz_aes_ctr *a, u8 *buf, size_t n) { NI_CTR_BODY }

/* VAES: two blocks per ymm register */
#define LDU2(p) _mm256_loadu_si256((const __m256i *)(p))
#define STU2(p, v) _mm256_storeu_si256((__m256i *)(p), v)
#define VA_KEYS                                                                \
    const int nr = a->rounds;                                                  \
    __m256i k[15];                                                             \
    for (int i_ = 0; i_ <= nr; i_++) k[i_] = _mm256_broadcastsi128_si256(LDU(a->rk + 16 * i_));
#define VA_ROUNDS(OP, OPL)                                                     \
    for (int r_ = 1; r_ < nr; r_++) { __m256i kr = k[r_]; XW(OP) }             \
    { __m256i kr = k[nr]; XW(OPL) }
#define VA_LD(j)   __m256i y##j = _mm256_xor_si256(LDU2(buf + 32 * j), k[0]);
#define VA_DEC(j)  y##j = _mm256_aesdec_epi128(y##j, kr);
#define VA_DECL(j) y##j = _mm256_aesdeclast_epi128(y##j, kr);
#define VA_ENC(j)  y##j = _mm256_aesenc_epi128(y##j, kr);
#define VA_ENCL(j) y##j = _mm256_aesenclast_epi128(y##j, kr);

__attribute__((target("avx2,vaes,aes")))
void gz_aes_cbc_dec_vaes(const gz_aes *a, u8 iv[16], u8 *buf, size_t nb)
{
    if (nb >= 2 * NI_W) {
        VA_KEYS
        __m128i v = LDU(iv);
        for (; nb >= 2 * NI_W; nb -= 2 * NI_W, buf += 32 * NI_W) {
            XW(VA_LD)
            VA_ROUNDS(VA_DEC, VA_DECL)
            /* store from the end: ymm j needs ciphertext blocks 2j-1, 2j intact */
            __m128i nv = LDU(buf + 32 * NI_W - 16);
#define VA_CBC_ST(j) if (j) STU2(buf + 32 * j, _mm256_xor_si256(y##j, LDU2(buf + 32 * j - 16)));
#define VA_CBC_REV(OP) OP(7) OP(6) OP(5) OP(4) OP(3) OP(2) OP(1)
#if defined(__x86_64__)
            VA_CBC_REV(VA_CBC_ST)
#else
            VA_CBC_ST(3) VA_CBC_ST(2) VA_CBC_ST(1)
#endif
            STU2(buf, _mm256_xor_si256(y0, _mm256_inserti128_si256(_mm256_castsi128_si256(v), LDU(buf), 1)));
            v = nv;
        }
        STU(iv, v);
    }
    if (nb) gz_aes_cbc_dec_avx(a, iv, buf, nb);
}

__attribute__((target("avx2,vaes,aes")))
void gz_aes_ctr_vaes(gz_aes_ctr *a, u8 *buf, size_t n)
{
    size_t d = ctr_drain(a, buf, n);
    buf += d; n -= d;
    if (n >= 32 * NI_W) {
        VA_KEYS
        u64 lo = rd64(a->ctr);
        __m256i cb = _mm256_broadcastsi128_si256(LDU(a->ctr));
#define VA_CTR_LD(j) __m256i y##j = _mm256_xor_si256(_mm256_add_epi64(cb, _mm256_set_epi64x(0, 2 * j + 2, 0, 2 * j + 1)), k[0]);
#define VA_CTR_ST(j) STU2(buf + 32 * j, _mm256_xor_si256(y##j, LDU2(buf + 32 * j)));
        for (; n >= 32 * NI_W; n -= 32 * NI_W, buf += 32 * NI_W) {
            XW(VA_CTR_LD)
            VA_ROUNDS(VA_ENC, VA_ENCL)
            XW(VA_CTR_ST)
            lo += 2 * NI_W;
            cb = _mm256_add_epi64(cb, _mm256_set_epi64x(0, 2 * NI_W, 0, 2 * NI_W));
        }
        wr64(a->ctr, lo);
    }
    if (n) gz_aes_ctr_aesni_avx(a, buf, n);
}

#else   /* not x86 */
void gz_aes_ecb_enc_aesni(const gz_aes *a, u8 *buf, size_t nb) { gz_aes_ecb_enc_soft(a, buf, nb); }
void gz_aes_ecb_dec_aesni(const gz_aes *a, u8 *buf, size_t nb) { gz_aes_ecb_dec_soft(a, buf, nb); }
void gz_aes_cbc_enc_aesni(const gz_aes *a, u8 iv[16], u8 *buf, size_t nb) { gz_aes_cbc_enc_soft(a, iv, buf, nb); }
void gz_aes_cbc_dec_aesni(const gz_aes *a, u8 iv[16], u8 *buf, size_t nb) { gz_aes_cbc_dec_soft(a, iv, buf, nb); }
void gz_aes_ecb_enc_avx(const gz_aes *a, u8 *buf, size_t nb) { gz_aes_ecb_enc_soft(a, buf, nb); }
void gz_aes_ecb_dec_avx(const gz_aes *a, u8 *buf, size_t nb) { gz_aes_ecb_dec_soft(a, buf, nb); }
void gz_aes_cbc_enc_avx(const gz_aes *a, u8 iv[16], u8 *buf, size_t nb) { gz_aes_cbc_enc_soft(a, iv, buf, nb); }
void gz_aes_cbc_dec_avx(const gz_aes *a, u8 iv[16], u8 *buf, size_t nb) { gz_aes_cbc_dec_soft(a, iv, buf, nb); }
void gz_aes_cbc_dec_vaes(const gz_aes *a, u8 iv[16], u8 *buf, size_t nb) { gz_aes_cbc_dec_soft(a, iv, buf, nb); }
void gz_aes_ctr_aesni(gz_aes_ctr *a, u8 *buf, size_t n) { gz_aes_ctr_soft(a, buf, n); }
void gz_aes_ctr_aesni_avx(gz_aes_ctr *a, u8 *buf, size_t n) { gz_aes_ctr_soft(a, buf, n); }
void gz_aes_ctr_vaes(gz_aes_ctr *a, u8 *buf, size_t n) { gz_aes_ctr_soft(a, buf, n); }
#endif

/* ---------------- ARMv8 AES ---------------- */
#if defined(__aarch64__)

#define A_LD(j)   uint8x16_t b##j = vld1q_u8(buf + 16 * j);
#define A_ST(j)   vst1q_u8(buf + 16 * j, b##j);
#define A_ENC(j)  b##j = vaesmcq_u8(vaeseq_u8(b##j, kr));
#define A_ENCL(j) b##j = veorq_u8(vaeseq_u8(b##j, kr), kl);
#define A_DEC(j)  b##j = vaesimcq_u8(vaesdq_u8(b##j, kr));
#define A_DECL(j) b##j = veorq_u8(vaesdq_u8(b##j, kr), kl);
#define AX8(OP) OP(0) OP(1) OP(2) OP(3) OP(4) OP(5) OP(6) OP(7)
#define A_KEYS                                                                 \
    const int nr = a->rounds;                                                  \
    uint8x16_t k[15];                                                          \
    for (int i_ = 0; i_ <= nr; i_++) k[i_] = vld1q_u8(a->rk + 16 * i_);
#define A_ROUNDS(OP, OPL)                                                      \
    for (int r_ = 0; r_ < nr - 1; r_++) { uint8x16_t kr = k[r_]; AX8(OP) }     \
    { uint8x16_t kr = k[nr - 1], kl = k[nr]; AX8(OPL) }
#define A_ONE_ENC(x)                                                           \
    for (int r_ = 0; r_ < nr - 1; r_++) x = vaesmcq_u8(vaeseq_u8(x, k[r_]));   \
    x = veorq_u8(vaeseq_u8(x, k[nr - 1]), k[nr]);
#define A_ONE_DEC(x)                                                           \
    for (int r_ = 0; r_ < nr - 1; r_++) x = vaesimcq_u8(vaesdq_u8(x, k[r_]));  \
    x = veorq_u8(vaesdq_u8(x, k[nr - 1]), k[nr]);

GZ_TARGET_AES
void gz_aes_ecb_enc_arm(const gz_aes *a, u8 *buf, size_t nb)
{
    A_KEYS
    for (; nb >= 8; nb -= 8, buf += 128) { AX8(A_LD) A_ROUNDS(A_ENC, A_ENCL) AX8(A_ST) }
    for (; nb; nb--, buf += 16) { uint8x16_t x = vld1q_u8(buf); A_ONE_ENC(x) vst1q_u8(buf, x); }
}

GZ_TARGET_AES
void gz_aes_ecb_dec_arm(const gz_aes *a, u8 *buf, size_t nb)
{
    A_KEYS
    for (; nb >= 8; nb -= 8, buf += 128) { AX8(A_LD) A_ROUNDS(A_DEC, A_DECL) AX8(A_ST) }
    for (; nb; nb--, buf += 16) { uint8x16_t x = vld1q_u8(buf); A_ONE_DEC(x) vst1q_u8(buf, x); }
}

GZ_TARGET_AES
void gz_aes_cbc_enc_arm(const gz_aes *a, u8 iv[16], u8 *buf, size_t nb)
{
    A_KEYS
    uint8x16_t v = vld1q_u8(iv);
    for (; nb; nb--, buf += 16) {
        v = veorq_u8(v, vld1q_u8(buf));
        A_ONE_ENC(v)
        vst1q_u8(buf, v);
    }
    vst1q_u8(iv, v);
}

GZ_TARGET_AES
void gz_aes_cbc_dec_arm(const gz_aes *a, u8 iv[16], u8 *buf, size_t nb)
{
    A_KEYS
    uint8x16_t pv = vld1q_u8(iv);
#define A_CBC_ST(j) { uint8x16_t c_ = vld1q_u8(buf + 16 * j); vst1q_u8(buf + 16 * j, veorq_u8(b##j, pv)); pv = c_; }
    for (; nb >= 8; nb -= 8, buf += 128) { AX8(A_LD) A_ROUNDS(A_DEC, A_DECL) AX8(A_CBC_ST) }
    for (; nb; nb--, buf += 16) {
        uint8x16_t c = vld1q_u8(buf), x = c;
        A_ONE_DEC(x)
        vst1q_u8(buf, veorq_u8(x, pv));
        pv = c;
    }
    vst1q_u8(iv, pv);
}

GZ_TARGET_AES
void gz_aes_ctr_arm(gz_aes_ctr *a, u8 *buf, size_t n)
{
    size_t d = ctr_drain(a, buf, n);
    buf += d; n -= d;
    A_KEYS
    u64 lo = rd64(a->ctr), hi = rd64(a->ctr + 8);
    uint64x1_t vhi = vcreate_u64(hi);
#define A_CTR_LD(j) uint8x16_t b##j = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(lo + j + 1), vhi));
#define A_CTR_ST(j) vst1q_u8(buf + 16 * j, veorq_u8(b##j, vld1q_u8(buf + 16 * j)));
    for (; n >= 128; n -= 128, buf += 128) {
        AX8(A_CTR_LD) A_ROUNDS(A_ENC, A_ENCL) AX8(A_CTR_ST)
        lo += 8;
    }
    while (n) {
        uint8x16_t x = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(++lo), vhi));
        A_ONE_ENC(x)
        if (n >= 16) {
            vst1q_u8(buf, veorq_u8(x, vld1q_u8(buf)));
            buf += 16; n -= 16;
        } else {
            vst1q_u8(a->ks, x);
            n -= ctr_tail(a, buf, n);
        }
    }
    wr64(a->ctr, lo); wr64(a->ctr + 8, hi);
}

#else   /* not AArch64 */
void gz_aes_ecb_enc_arm(const gz_aes *a, u8 *buf, size_t nb) { gz_aes_ecb_enc_soft(a, buf, nb); }
void gz_aes_ecb_dec_arm(const gz_aes *a, u8 *buf, size_t nb) { gz_aes_ecb_dec_soft(a, buf, nb); }
void gz_aes_cbc_enc_arm(const gz_aes *a, u8 iv[16], u8 *buf, size_t nb) { gz_aes_cbc_enc_soft(a, iv, buf, nb); }
void gz_aes_cbc_dec_arm(const gz_aes *a, u8 iv[16], u8 *buf, size_t nb) { gz_aes_cbc_dec_soft(a, iv, buf, nb); }
void gz_aes_ctr_arm(gz_aes_ctr *a, u8 *buf, size_t n) { gz_aes_ctr_soft(a, buf, n); }
#endif
