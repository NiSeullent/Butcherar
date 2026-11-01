/*
 * crypto_test - driver for the core crypto / checksum primitives
 *
 *   crypto_test info                                   CPU, tiers, selected kernels
 *   crypto_test selftest [quick]                       every kernel vs the portable one,
 *                                                      every forced tier, streaming splits
 *   crypto_test hash <alg> <tier> <file>...            hex digest per file (random chunking)
 *        alg: sha1 sha256 blake2s blake2sp crc32 crc64
 *   crypto_test hmac <sha1|sha256> <tier> <keyhex> <file>...
 *   crypto_test pbkdf2 <sha1|sha256> <tier> <iter> <pwhex> <salthex> <outlen>
 *   crypto_test aes <ecb-enc|ecb-dec|cbc-enc|cbc-dec|ctr> <tier> <keyhex> <ivhex> <in> <out>
 *   crypto_test kdf7z <tier> <power> <salthex> <pwhex>
 *   crypto_test kdfrar3 <tier> <salthex|-> <pwhex>
 *   crypto_test kdfrar5 <tier> <lg2> <salthex> <pwhex>
 *   crypto_test zcenc <pwhex> <in> <out>                ZipCrypto encryption (chunked)
 *   crypto_test bench [MiB]                            MB/s per kernel, KDF timings
 *
 * tier: -1 = automatic, >= 0 = gz_dispatch_init(tier), -2 = portable C only.
 * Built against build/host objects, or standalone (-DCT_STANDALONE) for
 * cross targets (qemu-aarch64).
 */
#include "cpu.h"
#include "crc32.h"
#include "crc64.h"
#include "crypto.h"
#include "sha256.h"
#include "blake2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef CT_STANDALONE
/* built from the crypto sources only: platform hooks and the inflate kernels
 * gz_dispatch_init refers to */
#include "inflate.h"
void *gz_alloc(size_t n) { return calloc(1, n); }
void *gz_realloc(void *p, size_t n) { return realloc(p, n); }
void gz_free(void *p) { free(p); }
void *gz_alloc_big(size_t n) { return calloc(1, n); }
void gz_free_big(void *p, size_t n) { (void)n; free(p); }
static int no_inflate(gz_inflater *z, const gz_stream_io *io) { (void)z; (void)io; return GZ_E_METHOD; }
gz_inflate_fn gz_inflate_kernel = no_inflate;
int gz_inflate_x86(gz_inflater *z, const gz_stream_io *io) { return no_inflate(z, io); }
int gz_inflate_mmx(gz_inflater *z, const gz_stream_io *io) { return no_inflate(z, io); }
int gz_inflate_sse(gz_inflater *z, const gz_stream_io *io) { return no_inflate(z, io); }
int gz_inflate_sse2(gz_inflater *z, const gz_stream_io *io) { return no_inflate(z, io); }
int gz_inflate_avx(gz_inflater *z, const gz_stream_io *io) { return no_inflate(z, io); }
int gz_inflate_avx2(gz_inflater *z, const gz_stream_io *io) { return no_inflate(z, io); }
int gz_inflate_neon(gz_inflater *z, const gz_stream_io *io) { return no_inflate(z, io); }
#endif

static u32 g_feat0;   /* features as detected */

static void setup(int tier)
{
    g_cpu.features = g_feat0;
    if (tier == -2) {
        g_cpu.features &= ~(u32)(CPUF_PCLMUL | CPUF_AESNI | CPUF_SHA | CPUF_VPCLMUL | CPUF_VAES |
                                 CPUF_ARM_CRC32 | CPUF_ARM_PMULL | CPUF_ARM_AES | CPUF_ARM_SHA1 | CPUF_ARM_SHA2);
        gz_dispatch_init(-1);
        gz_blake2sp_kernel = gz_blake2sp_c;
    } else {
        gz_dispatch_init(tier);
    }
}

/* ---------------- helpers ---------------- */

static u64 g_rng = 0x9E3779B97F4A7C15ull;
static u32 rnd(void)
{
    g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17;
    return (u32)(g_rng >> 16);
}
static void fill(u8 *p, size_t n) { for (size_t i = 0; i < n; i++) p[i] = (u8)rnd(); }

static size_t unhex(const char *s, u8 *out, size_t cap)
{
    size_t n = 0;
    if (!strcmp(s, "-")) return 0;
    while (s[0] && s[1] && n < cap) {
        unsigned v;
        if (sscanf(s, "%2x", &v) != 1) break;
        out[n++] = (u8)v;
        s += 2;
    }
    return n;
}
static void phex(const u8 *p, size_t n)
{
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
}
static u8 *read_file(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(2); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *b = malloc(sz + 64);
    if (fread(b, 1, sz, f) != (size_t)sz) { fprintf(stderr, "read error\n"); exit(2); }
    fclose(f);
    *n = (size_t)sz;
    return b;
}
static double now(void)
{
#ifdef _WIN32
    return (double)clock() / CLOCKS_PER_SEC;    /* MinGW build run under wine */
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
#endif
}
/* next chunk length for streaming tests: mix of tiny, odd and large pieces */
static size_t chunk(size_t left)
{
    size_t c;
    switch (rnd() % 4) {
    case 0: c = rnd() % 8; break;
    case 1: c = rnd() % 130; break;
    case 2: c = rnd() % 1100; break;
    default: c = rnd() % 70000; break;
    }
    return c > left ? left : c;
}

/* ---------------- streaming digests via the dispatched kernels ---------------- */

static int digest(const char *alg, const u8 *p, size_t n, u8 *out)
{
    size_t off = 0;
    if (!strcmp(alg, "sha1")) {
        gz_sha1 s; gz_sha1_init(&s);
        while (off < n) { size_t c = chunk(n - off); gz_sha1_update(&s, p + off, c); off += c; }
        gz_sha1_final(&s, out); return 20;
    }
    if (!strcmp(alg, "sha256")) {
        gz_sha256 s; gz_sha256_init(&s);
        while (off < n) { size_t c = chunk(n - off); gz_sha256_update(&s, p + off, c); off += c; }
        gz_sha256_final(&s, out); return 32;
    }
    if (!strcmp(alg, "blake2s")) {
        gz_blake2s s; gz_blake2s_init(&s, 32);
        while (off < n) { size_t c = chunk(n - off); gz_blake2s_update(&s, p + off, c); off += c; }
        gz_blake2s_final(&s, out); return 32;
    }
    if (!strcmp(alg, "blake2sp")) {
        gz_blake2sp *s = malloc(sizeof(*s)); gz_blake2sp_init(s);
        while (off < n) { size_t c = chunk(n - off); gz_blake2sp_update(s, p + off, c); off += c; }
        gz_blake2sp_final(s, out); free(s); return 32;
    }
    if (!strcmp(alg, "crc32")) {
        u32 c32 = 0;
        while (off < n) { size_t c = chunk(n - off); c32 = gz_crc32(c32, p + off, c); off += c; }
        wr32be(out, c32); return 4;
    }
    if (!strcmp(alg, "crc64")) {
        u64 c64 = 0;
        while (off < n) { size_t c = chunk(n - off); c64 = gz_crc64(c64, p + off, c); off += c; }
        wr64be(out, c64); return 8;
    }
    return -1;
}

/* ---------------- self test ---------------- */

static int g_fail, g_checks;
#define CHECK(cond, ...) do { g_checks++; if (!(cond)) { g_fail++; if (g_fail < 30) { printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } } } while (0)

typedef struct { const char *name; void *fn; int ok; } kern;

static int x86_ok(u32 need, int tier)
{
    return (g_feat0 & need) == need && g_cpu.tier >= tier;
}

#if defined(__aarch64__)
#define ARM_OK(f) ((g_feat0 & (f)) == (f))
#else
#define ARM_OK(f) 0
#endif

static void test_crc(int quick)
{
    kern k32[] = {
        { "pclmul", (void *)gz_crc32_pclmul, x86_ok(CPUF_PCLMUL | CPUF_SSE41, GZ_TIER_SSE41) },
        { "avx", (void *)gz_crc32_avx, x86_ok(CPUF_PCLMUL | CPUF_AVX, GZ_TIER_AVX) },
        { "vpclmul", (void *)gz_crc32_vpclmul, x86_ok(CPUF_PCLMUL | CPUF_VPCLMUL | CPUF_AVX2, GZ_TIER_AVX2) },
        { "arm", (void *)gz_crc32_arm, ARM_OK(CPUF_ARM_CRC32) },
        { "pmull", (void *)gz_crc32_pmull, ARM_OK(CPUF_ARM_CRC32 | CPUF_ARM_PMULL) },
    };
    kern k64[] = {
        { "pclmul", (void *)gz_crc64_pclmul, x86_ok(CPUF_PCLMUL | CPUF_SSE41, GZ_TIER_SSE41) },
        { "vpclmul", (void *)gz_crc64_vpclmul, x86_ok(CPUF_PCLMUL | CPUF_VPCLMUL | CPUF_AVX2, GZ_TIER_AVX2) },
        { "pmull", (void *)gz_crc64_pmull, ARM_OK(CPUF_ARM_PMULL) },
    };
    size_t cap = (1 << 20) + 64;
    u8 *buf = malloc(cap);
    fill(buf, cap);
    CHECK(gz_crc32_slice8(0, (const u8 *)"123456789", 9) == 0xCBF43926u, "crc32 check value");
    CHECK(gz_crc64_slice8(0, (const u8 *)"123456789", 9) == 0x995DC9BBDF1939FAull, "crc64 check value");
    for (size_t n = 0; n <= (quick ? 600 : 2100); n += (n < 300 ? 1 : 7)) {
        for (int al = 0; al < 16; al += (n < 300 ? 5 : 1)) {
            const u8 *p = buf + al;
            u32 init32 = rnd();
            u64 init64 = ((u64)rnd() << 32) | rnd();
            u32 r32 = gz_crc32_slice8(init32, p, n);
            u64 r64 = gz_crc64_slice8(init64, p, n);
            for (size_t i = 0; i < GZ_COUNTOF(k32); i++) if (k32[i].ok)
                CHECK(((gz_crc32_fn)k32[i].fn)(init32, p, n) == r32, "crc32 %s n=%zu al=%d", k32[i].name, n, al);
            for (size_t i = 0; i < GZ_COUNTOF(k64); i++) if (k64[i].ok)
                CHECK(((gz_crc64_fn)k64[i].fn)(init64, p, n) == r64, "crc64 %s n=%zu al=%d", k64[i].name, n, al);
        }
    }
    static const size_t big[] = { 4095, 4096, 65536 + 13, 1 << 20 };
    for (size_t b = 0; b < GZ_COUNTOF(big); b++) {
        u32 r32 = gz_crc32_slice8(0, buf + 3, big[b]);
        u64 r64 = gz_crc64_slice8(0, buf + 3, big[b]);
        for (size_t i = 0; i < GZ_COUNTOF(k32); i++) if (k32[i].ok)
            CHECK(((gz_crc32_fn)k32[i].fn)(0, buf + 3, big[b]) == r32, "crc32 %s big %zu", k32[i].name, big[b]);
        for (size_t i = 0; i < GZ_COUNTOF(k64); i++) if (k64[i].ok)
            CHECK(((gz_crc64_fn)k64[i].fn)(0, buf + 3, big[b]) == r64, "crc64 %s big %zu", k64[i].name, big[b]);
    }
    free(buf);
}

static void test_sha_blocks(void)
{
    kern k1[] = {
        { "shani", (void *)gz_sha1_blocks_shani, x86_ok(CPUF_SHA | CPUF_SSE41, GZ_TIER_SSE41) },
        { "arm", (void *)gz_sha1_blocks_arm, ARM_OK(CPUF_ARM_SHA1) },
    };
    kern k2[] = {
        { "shani", (void *)gz_sha256_blocks_shani, x86_ok(CPUF_SHA | CPUF_SSE41, GZ_TIER_SSE41) },
        { "arm", (void *)gz_sha256_blocks_arm, ARM_OK(CPUF_ARM_SHA2) },
    };
    u8 buf[64 * 40 + 16];
    for (int trial = 0; trial < 200; trial++) {
        size_t nb = rnd() % 40, al = rnd() % 16;
        u32 st0[8], ref[8], got[8];
        fill(buf, sizeof buf);
        for (int i = 0; i < 8; i++) st0[i] = rnd();
        memcpy(ref, st0, 32); gz_sha1_blocks_c(ref, buf + al, nb);
        for (size_t i = 0; i < GZ_COUNTOF(k1); i++) if (k1[i].ok) {
            memcpy(got, st0, 32); ((gz_sha_blocks_fn)k1[i].fn)(got, buf + al, nb);
            CHECK(!memcmp(got, ref, 20), "sha1 %s nb=%zu", k1[i].name, nb);
        }
        memcpy(ref, st0, 32); gz_sha256_blocks_c(ref, buf + al, nb);
        for (size_t i = 0; i < GZ_COUNTOF(k2); i++) if (k2[i].ok) {
            memcpy(got, st0, 32); ((gz_sha_blocks_fn)k2[i].fn)(got, buf + al, nb);
            CHECK(!memcmp(got, ref, 32), "sha256 %s nb=%zu", k2[i].name, nb);
        }
    }
}

static void test_blake2sp_kernels(void)
{
    kern kb[] = {
        { "sse2", (void *)gz_blake2sp_sse2, x86_ok(CPUF_SSE2, GZ_TIER_SSE2) },
        { "ssse3", (void *)gz_blake2sp_ssse3, x86_ok(CPUF_SSSE3, GZ_TIER_SSE41) },
        { "avx2", (void *)gz_blake2sp_avx2, x86_ok(CPUF_AVX2, GZ_TIER_AVX2) },
#if defined(__aarch64__)
        { "neon", (void *)gz_blake2sp_neon, 1 },
#endif
    };
    u8 *buf = malloc(512 * 9 + 16);
    for (int trial = 0; trial < 60; trial++) {
        size_t ns = rnd() % 9, al = rnd() % 16;
        u64 t = trial == 7 ? 0xFFFFFF80ull : ((u64)rnd() << (trial & 1 ? 20 : 0));   /* counter carry */
        u32 h0[8][8], ref[8][8], got[8][8];
        fill(buf, 512 * 9 + 16);
        for (int i = 0; i < 64; i++) h0[i / 8][i % 8] = rnd();
        memcpy(ref, h0, sizeof ref); gz_blake2sp_c(ref, t, buf + al, ns);
        for (size_t i = 0; i < GZ_COUNTOF(kb); i++) if (kb[i].ok) {
            memcpy(got, h0, sizeof got); ((gz_blake2sp_fn)kb[i].fn)(got, t, buf + al, ns);
            CHECK(!memcmp(got, ref, sizeof ref), "blake2sp %s ns=%zu", kb[i].name, ns);
        }
    }
    free(buf);
}

typedef struct {
    const char *name;
    gz_aes_ecb_fn ee, ed;
    gz_aes_cbc_fn ce, cd;
    gz_aes_ctr_fn ctr;
    int ok;
} aes_kern;

static void test_aes(void)
{
    aes_kern ks[] = {
        { "aesni", gz_aes_ecb_enc_aesni, gz_aes_ecb_dec_aesni, gz_aes_cbc_enc_aesni, gz_aes_cbc_dec_aesni,
          gz_aes_ctr_aesni, x86_ok(CPUF_AESNI | CPUF_SSE41, GZ_TIER_SSE41) },
        { "avx", gz_aes_ecb_enc_avx, gz_aes_ecb_dec_avx, gz_aes_cbc_enc_avx, gz_aes_cbc_dec_avx,
          gz_aes_ctr_aesni_avx, x86_ok(CPUF_AESNI | CPUF_AVX, GZ_TIER_AVX) },
        { "vaes", gz_aes_ecb_enc_avx, gz_aes_ecb_dec_avx, gz_aes_cbc_enc_avx, gz_aes_cbc_dec_vaes,
          gz_aes_ctr_vaes, x86_ok(CPUF_AESNI | CPUF_VAES | CPUF_AVX2, GZ_TIER_AVX2) },
        { "arm", gz_aes_ecb_enc_arm, gz_aes_ecb_dec_arm, gz_aes_cbc_enc_arm, gz_aes_cbc_dec_arm,
          gz_aes_ctr_arm, ARM_OK(CPUF_ARM_AES) },
    };
    /* FIPS-197 appendix C vectors */
    static const char *fk[3] = { "000102030405060708090a0b0c0d0e0f",
                                 "000102030405060708090a0b0c0d0e0f1011121314151617",
                                 "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" };
    static const char *fc[3] = { "69c4e0d86a7b0430d8cdb78070b4c55a", "dda97ca4864cdfe06eaf70a0ec0d7191",
                                 "8ea2b7ca516745bfeafc49904b496089" };
    for (int i = 0; i < 3; i++) {
        u8 key[32], pt[16], ct[16], b[16];
        size_t kl = unhex(fk[i], key, 32);
        unhex("00112233445566778899aabbccddeeff", pt, 16);
        unhex(fc[i], ct, 16);
        gz_aes e, d;
        gz_aes_set_encrypt_key(&e, key, (int)kl);
        gz_aes_set_decrypt_key(&d, key, (int)kl);
        memcpy(b, pt, 16); gz_aes_ecb_enc_soft(&e, b, 1);
        CHECK(!memcmp(b, ct, 16), "fips197 enc %d", i);
        gz_aes_ecb_dec_soft(&d, b, 1);
        CHECK(!memcmp(b, pt, 16), "fips197 dec %d", i);
        for (size_t k = 0; k < GZ_COUNTOF(ks); k++) if (ks[k].ok) {
            memcpy(b, pt, 16); ks[k].ee(&e, b, 1);
            CHECK(!memcmp(b, ct, 16), "fips197 enc %s %d", ks[k].name, i);
            ks[k].ed(&d, b, 1);
            CHECK(!memcmp(b, pt, 16), "fips197 dec %s %d", ks[k].name, i);
        }
    }
    gz_aes tmp;
    CHECK(gz_aes_set_encrypt_key(&tmp, (const u8 *)"0123456789abcdef", 20) == GZ_E_METHOD, "bad key length");

    size_t cap = 16 * 300 + 16;
    u8 *src = malloc(cap), *ref = malloc(cap), *got = malloc(cap);
    for (int trial = 0; trial < 120; trial++) {
        int kl = 16 + 8 * (trial % 3);
        u8 key[32], iv[16], ivr[16], ivg[16];
        size_t nb = trial < 20 ? (size_t)trial : rnd() % 300, al = rnd() % 16;
        fill(key, 32); fill(iv, 16); fill(src, cap);
        gz_aes e, d;
        gz_aes_set_encrypt_key(&e, key, kl);
        gz_aes_set_decrypt_key(&d, key, kl);
        u8 *s = src + al;
        /* soft round trips */
        memcpy(ref, s, nb * 16); memcpy(ivr, iv, 16);
        gz_aes_cbc_enc_soft(&e, ivr, ref, nb);
        memcpy(ivg, iv, 16); gz_aes_cbc_dec_soft(&d, ivg, ref, nb);
        CHECK(!memcmp(ref, s, nb * 16), "soft cbc roundtrip nb=%zu", nb);
        for (size_t k = 0; k < GZ_COUNTOF(ks); k++) if (ks[k].ok) {
            /* ECB enc/dec */
            memcpy(ref, s, nb * 16); gz_aes_ecb_enc_soft(&e, ref, nb);
            memcpy(got + al, s, nb * 16); ks[k].ee(&e, got + al, nb);
            CHECK(!memcmp(got + al, ref, nb * 16), "ecb enc %s kl=%d nb=%zu", ks[k].name, kl, nb);
            gz_aes_ecb_dec_soft(&d, ref, nb); ks[k].ed(&d, got + al, nb);
            CHECK(!memcmp(got + al, ref, nb * 16) && !memcmp(ref, s, nb * 16), "ecb dec %s kl=%d nb=%zu", ks[k].name, kl, nb);
            /* CBC enc in two pieces (iv chaining) */
            size_t cut = nb ? rnd() % (nb + 1) : 0;
            memcpy(ref, s, nb * 16); memcpy(ivr, iv, 16); gz_aes_cbc_enc_soft(&e, ivr, ref, nb);
            memcpy(got + al, s, nb * 16); memcpy(ivg, iv, 16);
            ks[k].ce(&e, ivg, got + al, cut); ks[k].ce(&e, ivg, got + al + 16 * cut, nb - cut);
            CHECK(!memcmp(got + al, ref, nb * 16) && !memcmp(ivg, ivr, 16), "cbc enc %s kl=%d nb=%zu", ks[k].name, kl, nb);
            /* CBC dec in two pieces */
            memcpy(ivr, iv, 16); gz_aes_cbc_dec_soft(&d, ivr, ref, nb);
            memcpy(ivg, iv, 16); ks[k].cd(&d, ivg, got + al, cut); ks[k].cd(&d, ivg, got + al + 16 * cut, nb - cut);
            CHECK(!memcmp(got + al, ref, nb * 16) && !memcmp(ivg, ivr, 16) && !memcmp(ref, s, nb * 16),
                  "cbc dec %s kl=%d nb=%zu", ks[k].name, kl, nb);
            /* CTR with arbitrary chunking */
            size_t n = nb * 16 + rnd() % 16;
            gz_aes_ctr cr, cg;
            gz_aes_ctr_setup(&cr, key, kl);
            gz_aes_ctr_setup(&cg, key, kl);
            if (trial & 1) { memset(cr.ctr, 0xff, 7); memset(cg.ctr, 0xff, 7); }   /* carry */
            memcpy(ref, s, n); gz_aes_ctr_soft(&cr, ref, n);
            memcpy(got + al, s, n);
            for (size_t off = 0; off < n;) {
                size_t c = rnd() % 3 ? rnd() % 40 : rnd() % 2000;
                if (c > n - off) c = n - off;
                ks[k].ctr(&cg, got + al + off, c);
                off += c;
            }
            CHECK(!memcmp(got + al, ref, n), "ctr %s kl=%d n=%zu", ks[k].name, kl, n);
        }
    }
    free(src); free(ref); free(got);
}

/* dispatched results at every forced tier vs the portable reference */
static void test_tiers(void)
{
    size_t n = 70000 + rnd() % 5000;
    u8 *buf = malloc(n), *ref = malloc(n), *got = malloc(n);
    fill(buf, n);
    static const char *algs[] = { "sha1", "sha256", "blake2s", "blake2sp", "crc32", "crc64" };
    u8 dref[6][32], d[32];
    u64 save = g_rng;
    setup(-2);
    for (int a = 0; a < 6; a++) { g_rng = save + a; digest(algs[a], buf, n, dref[a]); }
    u8 key[32], iv[16], iv2[16];
    fill(key, 32); fill(iv, 16);
    gz_aes e, dk;
    gz_aes_set_encrypt_key(&e, key, 32);
    gz_aes_set_decrypt_key(&dk, key, 32);
    size_t nb = n / 16;
    memcpy(ref, buf, n); memcpy(iv2, iv, 16);
    gz_aes_cbc_encrypt(&e, iv2, ref, nb * 16);
    gz_aes_ctr cr; gz_aes_ctr_setup(&cr, key, 32); gz_aes_ctr_kernel(&cr, ref, n);
    u8 k7[32], k7r[32], r3k[16], r3i[16], r3kr[16], r3ir[16], r5[32], r5r[32];
    gz_7z_kdf(key, 16, buf, 20, 12, k7r);
    gz_rar3_kdf(buf, 20, key, r3kr, r3ir);
    gz_rar5_kdf(buf, 9, key, 16, 6, r5r, 0, 0);
    int maxt = g_cpu.tier;
#if defined(__aarch64__)
    maxt = 0;
#endif
    for (int t = -1; t <= maxt; t++) {
        setup(t);
        for (int a = 0; a < 6; a++) {
            g_rng = save + a;
            int dl = digest(algs[a], buf, n, d);
            CHECK(!memcmp(d, dref[a], dl), "tier %d %s (%s/%s/%s)", t, algs[a], gz_dispatch_crc_name(),
                  gz_dispatch_sha_name(), gz_dispatch_blake2_name());
        }
        memcpy(got, buf, n); memcpy(iv2, iv, 16);
        gz_aes_cbc_encrypt(&e, iv2, got, nb * 16);
        gz_aes_ctr cg; gz_aes_ctr_setup(&cg, key, 32); gz_aes_ctr_kernel(&cg, got, n);
        CHECK(!memcmp(got, ref, n), "tier %d aes cbc-enc + ctr (%s)", t, gz_dispatch_aes_name());
        gz_aes_ctr_setup(&cg, key, 32); gz_aes_ctr_kernel(&cg, got, n);
        memcpy(iv2, iv, 16);
        gz_aes_cbc_decrypt(&dk, iv2, got, nb * 16);
        CHECK(!memcmp(got, buf, n), "tier %d aes cbc-dec (%s)", t, gz_dispatch_aes_name());
        gz_7z_kdf(key, 16, buf, 20, 12, k7);
        CHECK(!memcmp(k7, k7r, 32), "tier %d 7z kdf", t);
        gz_rar3_kdf(buf, 20, key, r3k, r3i);
        CHECK(!memcmp(r3k, r3kr, 16) && !memcmp(r3i, r3ir, 16), "tier %d rar3 kdf", t);
        gz_rar5_kdf(buf, 9, key, 16, 6, r5, 0, 0);
        CHECK(!memcmp(r5, r5r, 32), "tier %d rar5 kdf", t);
    }
    setup(-1);
    free(buf); free(ref); free(got);
}

/* known answers for the KDFs and hashes with fixed inputs */
static void test_known(void)
{
    u8 d[32], e[32];
    gz_sha256_calc("abc", 3, d);
    unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", e, 32);
    CHECK(!memcmp(d, e, 32), "sha256 abc");
    gz_sha1_calc("abc", 3, d);
    unhex("a9993e364706816aba3e25717850c26c9cd0d89d", e, 20);
    CHECK(!memcmp(d, e, 20), "sha1 abc");
    gz_blake2s_calc("abc", 3, d, 32);
    unhex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982", e, 32);
    CHECK(!memcmp(d, e, 32), "blake2s abc");
    /* RFC 7914 / 6070 style PBKDF2 vectors */
    gz_pbkdf2_sha256("passwd", 6, "salt", 4, 1, d, 32);
    unhex("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc", e, 32);
    CHECK(!memcmp(d, e, 32), "pbkdf2-sha256 c=1");
    gz_pbkdf2_sha1("password", 8, "salt", 4, 4096, d, 20);
    unhex("4b007901b765489abead49d926f721d065a429c1", e, 20);
    CHECK(!memcmp(d, e, 20), "pbkdf2-sha1 c=4096");
    /* 7z 0x3F mode */
    u8 k[32];
    CHECK(gz_7z_kdf((const u8 *)"SALT", 4, (const u8 *)"p\0w\0", 4, 0x3F, k) == GZ_OK &&
          !memcmp(k, "SALTp\0w\0\0\0", 10) && k[31] == 0, "7z kdf 0x3F");
    CHECK(gz_7z_kdf(0, 0, 0, 0, 25, k) == GZ_E_LIMIT, "7z kdf limit");
    CHECK(gz_rar5_kdf(0, 0, k, 16, 25, k, 0, 0) == GZ_E_LIMIT, "rar5 kdf limit");
    /* ZipCrypto: encrypt/decrypt round trip keeps both key states in step */
    {
        u8 zb[300], zc0[300];
        fill(zb, sizeof zb);
        memcpy(zc0, zb, sizeof zb);
        gz_zipcrypto e, dd;
        gz_zc_init(&e, (const u8 *)"pw", 2);
        gz_zc_init(&dd, (const u8 *)"pw", 2);
        gz_zc_encrypt(&e, zb, 100); gz_zc_encrypt(&e, zb + 100, 200);
        CHECK(memcmp(zb, zc0, sizeof zb) != 0, "zipcrypto changes data");
        gz_zc_decrypt(&dd, zb, 300);
        CHECK(!memcmp(zb, zc0, sizeof zb) && e.k0 == dd.k0 && e.k1 == dd.k1 && e.k2 == dd.k2, "zipcrypto round trip");
    }
    /* streaming splits of the dispatched hashes vs one-shot */
    u8 *buf = malloc(5000);
    fill(buf, 5000);
    for (int trial = 0; trial < 300; trial++) {
        size_t n = rnd() % 5000;
        u8 a[32], b[32];
        gz_blake2sp_calc(buf, n, a);
        digest("blake2sp", buf, n, b);
        CHECK(!memcmp(a, b, 32), "blake2sp split n=%zu", n);
        gz_blake2s_calc(buf, n, a, 32);
        digest("blake2s", buf, n, b);
        CHECK(!memcmp(a, b, 32), "blake2s split n=%zu", n);
        gz_sha256_calc(buf, n, a);
        digest("sha256", buf, n, b);
        CHECK(!memcmp(a, b, 32), "sha256 split n=%zu", n);
    }
    free(buf);
}

static int selftest(int quick)
{
    test_known();
    test_crc(quick);
    test_sha_blocks();
    test_blake2sp_kernels();
    test_aes();
    test_tiers();
    printf("selftest: %d checks, %d failed\n", g_checks, g_fail);
    return g_fail != 0;
}

/* ---------------- benchmark ---------------- */

static double mbps(double bytes, double sec) { return bytes / sec / 1e6; }

#define BENCH(label, ok, expr) do {                                            \
        if (ok) {                                                              \
            double t0_ = now(), t1_; size_t it_ = 0;                           \
            do { expr; it_++; t1_ = now(); } while (t1_ - t0_ < 0.25);         \
            printf("  %-26s %8.0f MB/s\n", label, mbps((double)it_ * bsz, t1_ - t0_)); \
        }                                                                      \
    } while (0)

static volatile u64 g_sink;

static void bench(size_t mib)
{
    size_t bsz = mib << 20;
    u8 *buf = malloc(bsz + 64);
    fill(buf, bsz + 64);
    printf("CPU: %s (tier %s)\n", g_cpu.brand, gz_tier_name(g_cpu.tier));
    printf("CRC-32\n");
    BENCH("slice-by-8", 1, g_sink += gz_crc32_slice8(0, buf, bsz));
    BENCH("pclmul", x86_ok(CPUF_PCLMUL | CPUF_SSE41, GZ_TIER_SSE41), g_sink += gz_crc32_pclmul(0, buf, bsz));
    BENCH("avx+pclmul", x86_ok(CPUF_PCLMUL | CPUF_AVX, GZ_TIER_AVX), g_sink += gz_crc32_avx(0, buf, bsz));
    BENCH("vpclmul", x86_ok(CPUF_VPCLMUL | CPUF_PCLMUL | CPUF_AVX2, GZ_TIER_AVX2), g_sink += gz_crc32_vpclmul(0, buf, bsz));
    BENCH("armv8 crc32", ARM_OK(CPUF_ARM_CRC32), g_sink += gz_crc32_arm(0, buf, bsz));
    BENCH("pmull+crc32", ARM_OK(CPUF_ARM_CRC32 | CPUF_ARM_PMULL), g_sink += gz_crc32_pmull(0, buf, bsz));
    printf("CRC-64\n");
    BENCH("slice-by-8", 1, g_sink += gz_crc64_slice8(0, buf, bsz));
    BENCH("pclmul", x86_ok(CPUF_PCLMUL | CPUF_SSE41, GZ_TIER_SSE41), g_sink += gz_crc64_pclmul(0, buf, bsz));
    BENCH("vpclmul", x86_ok(CPUF_VPCLMUL | CPUF_PCLMUL | CPUF_AVX2, GZ_TIER_AVX2), g_sink += gz_crc64_vpclmul(0, buf, bsz));
    BENCH("pmull", ARM_OK(CPUF_ARM_PMULL), g_sink += gz_crc64_pmull(0, buf, bsz));
    u32 st[8] = { 0 };
    printf("SHA-1 / SHA-256\n");
    BENCH("sha1 c", 1, gz_sha1_blocks_c(st, buf, bsz / 64));
    BENCH("sha1 sha-ni", x86_ok(CPUF_SHA | CPUF_SSE41, GZ_TIER_SSE41), gz_sha1_blocks_shani(st, buf, bsz / 64));
    BENCH("sha1 armv8", ARM_OK(CPUF_ARM_SHA1), gz_sha1_blocks_arm(st, buf, bsz / 64));
    BENCH("sha256 c", 1, gz_sha256_blocks_c(st, buf, bsz / 64));
    BENCH("sha256 sha-ni", x86_ok(CPUF_SHA | CPUF_SSE41, GZ_TIER_SSE41), gz_sha256_blocks_shani(st, buf, bsz / 64));
    BENCH("sha256 armv8", ARM_OK(CPUF_ARM_SHA2), gz_sha256_blocks_arm(st, buf, bsz / 64));
    g_sink += st[0];
    printf("BLAKE2sp\n");
    u32 bh[8][8] = { { 0 } };
    BENCH("c", 1, gz_blake2sp_c(bh, 0, buf, bsz / 512));
    BENCH("sse2", x86_ok(CPUF_SSE2, GZ_TIER_SSE2), gz_blake2sp_sse2(bh, 0, buf, bsz / 512));
    BENCH("ssse3", x86_ok(CPUF_SSSE3, GZ_TIER_SSE41), gz_blake2sp_ssse3(bh, 0, buf, bsz / 512));
    BENCH("avx2", x86_ok(CPUF_AVX2, GZ_TIER_AVX2), gz_blake2sp_avx2(bh, 0, buf, bsz / 512));
#if defined(__aarch64__)
    BENCH("neon", 1, gz_blake2sp_neon(bh, 0, buf, bsz / 512));
#endif
    g_sink += bh[0][0];
    printf("AES-256\n");
    gz_aes e, d;
    u8 key[32], iv[16] = { 0 };
    fill(key, 32);
    gz_aes_set_encrypt_key(&e, key, 32);
    gz_aes_set_decrypt_key(&d, key, 32);
    gz_aes_ctr c;
    gz_aes_ctr_setup(&c, key, 32);
    int ni = x86_ok(CPUF_AESNI | CPUF_SSE41, GZ_TIER_SSE41), nav = x86_ok(CPUF_AESNI | CPUF_AVX, GZ_TIER_AVX);
    int va = x86_ok(CPUF_AESNI | CPUF_VAES | CPUF_AVX2, GZ_TIER_AVX2), ar = ARM_OK(CPUF_ARM_AES);
    BENCH("cbc-dec soft", 1, gz_aes_cbc_dec_soft(&d, iv, buf, bsz / 16));
    BENCH("cbc-dec aes-ni", ni, gz_aes_cbc_dec_aesni(&d, iv, buf, bsz / 16));
    BENCH("cbc-dec aes-ni avx", nav, gz_aes_cbc_dec_avx(&d, iv, buf, bsz / 16));
    BENCH("cbc-dec vaes", va, gz_aes_cbc_dec_vaes(&d, iv, buf, bsz / 16));
    BENCH("cbc-dec armv8", ar, gz_aes_cbc_dec_arm(&d, iv, buf, bsz / 16));
    BENCH("cbc-enc soft", 1, gz_aes_cbc_enc_soft(&e, iv, buf, bsz / 16));
    BENCH("cbc-enc aes-ni", ni, gz_aes_cbc_enc_aesni(&e, iv, buf, bsz / 16));
    BENCH("cbc-enc armv8", ar, gz_aes_cbc_enc_arm(&e, iv, buf, bsz / 16));
    BENCH("ecb-enc aes-ni", ni, gz_aes_ecb_enc_aesni(&e, buf, bsz / 16));
    BENCH("ctr soft", 1, gz_aes_ctr_soft(&c, buf, bsz));
    BENCH("ctr aes-ni", ni, gz_aes_ctr_aesni(&c, buf, bsz));
    BENCH("ctr aes-ni avx", nav, gz_aes_ctr_aesni_avx(&c, buf, bsz));
    BENCH("ctr vaes", va, gz_aes_ctr_vaes(&c, buf, bsz));
    BENCH("ctr armv8", ar, gz_aes_ctr_arm(&c, buf, bsz));

    printf("Key derivation (dispatched: %s)\n", gz_dispatch_sha_name());
    static const u8 pw16[] = "p\0a\0s\0s\0w\0o\0r\0d\0" "1\0" "2\0";   /* 10 chars UTF-16LE */
    u8 k[32], k2[16];
    double t0 = now();
    gz_7z_kdf(key, 16, pw16, 20, 19, k);
    printf("  %-26s %8.1f ms\n", "7z AES 2^19", (now() - t0) * 1e3);
    t0 = now();
    gz_rar3_kdf(pw16, 20, key, k, k2);
    printf("  %-26s %8.1f ms\n", "RAR3 (10 chars)", (now() - t0) * 1e3);
    t0 = now();
    gz_rar3_kdf(buf, 254, key, k, k2);
    printf("  %-26s %8.1f ms\n", "RAR3 (127 chars, rewrite)", (now() - t0) * 1e3);
    t0 = now();
    gz_rar5_kdf((const u8 *)"password12", 10, key, 16, 15, k, k, k2);
    printf("  %-26s %8.1f ms\n", "RAR5 2^15", (now() - t0) * 1e3);
    u8 dk[66];
    t0 = now();
    gz_pbkdf2_sha1("password12", 10, key, 16, 1000, dk, 66);
    printf("  %-26s %8.1f ms\n", "WinZip AES-256 (1000 it)", (now() - t0) * 1e3);
    free(buf);
}

/* ---------------- main ---------------- */

static int aes_cmd(char **argv)
{
    const char *mode = argv[0];
    u8 key[32], iv[16] = { 0 };
    int kl = (int)unhex(argv[2], key, 32);
    unhex(argv[3], iv, 16);
    size_t n;
    u8 *buf = read_file(argv[4], &n);
    if (!strcmp(mode, "ctr")) {
        gz_aes_ctr c;
        gz_aes_ctr_setup(&c, key, kl);
        for (size_t off = 0; off < n;) { size_t k = chunk(n - off); gz_aes_ctr_kernel(&c, buf + off, k); off += k; }
    } else {
        gz_aes a;
        int enc = strstr(mode, "enc") != 0;
        if ((enc ? gz_aes_set_encrypt_key : gz_aes_set_decrypt_key)(&a, key, kl)) { fprintf(stderr, "bad key\n"); return 2; }
        n &= ~(size_t)15;
        for (size_t off = 0; off < n;) {
            size_t k = chunk(n - off) & ~(size_t)15;
            if (!k) k = 16;
            if (!strcmp(mode, "ecb-enc")) gz_aes_ecb_encrypt(&a, buf + off, k);
            else if (!strcmp(mode, "ecb-dec")) gz_aes_ecb_decrypt(&a, buf + off, k);
            else if (!strcmp(mode, "cbc-enc")) gz_aes_cbc_encrypt(&a, iv, buf + off, k);
            else if (!strcmp(mode, "cbc-dec")) gz_aes_cbc_decrypt(&a, iv, buf + off, k);
            else { fprintf(stderr, "bad mode\n"); return 2; }
            off += k;
        }
    }
    FILE *f = fopen(argv[5], "wb");
    if (!f || fwrite(buf, 1, n, f) != n) return 2;
    fclose(f);
    free(buf);
    return 0;
}

int main(int argc, char **argv)
{
    gz_cpu_detect();
    gz_crc32_init();
    gz_aes_init();
    g_feat0 = g_cpu.features;
    gz_dispatch_init(-1);
    if (argc < 2) { fprintf(stderr, "usage: see source\n"); return 2; }
    const char *cmd = argv[1];
    if (!strcmp(cmd, "info")) {
        printf("brand=%s tier=%s features=%08x\n", g_cpu.brand, gz_tier_name(g_cpu.tier), g_cpu.features);
        printf("tiers=");
        for (int t = 0; t <= g_cpu.tier; t++) if (gz_cpu_tier_supported(t)) printf("%d ", t);
        printf("\ncrc32=%s crc64=%s sha=%s aes=%s blake2=%s\n", gz_dispatch_crc_name(), gz_dispatch_crc64_name(),
               gz_dispatch_sha_name(), gz_dispatch_aes_name(), gz_dispatch_blake2_name());
        return 0;
    }
    if (!strcmp(cmd, "selftest")) return selftest(argc > 2 && !strcmp(argv[2], "quick"));
    if (!strcmp(cmd, "bench")) { bench(argc > 2 ? (size_t)atoi(argv[2]) : 4); return 0; }
    if (argc < 3) return 2;
    if (!strcmp(cmd, "hash") && argc >= 4) {
        setup(atoi(argv[3]));
        for (int i = 4; i < argc; i++) {
            size_t n;
            u8 *b = read_file(argv[i], &n), d[32];
            g_rng = 0x1234567 + n * 31;
            int dl = digest(argv[2], b, n, d);
            if (dl < 0) { fprintf(stderr, "bad alg\n"); return 2; }
            phex(d, dl); printf("\n");
            free(b);
        }
        return 0;
    }
    if (!strcmp(cmd, "hmac") && argc >= 5) {
        u8 key[1024], d[32];
        setup(atoi(argv[3]));
        size_t kl = unhex(argv[4], key, sizeof key);
        for (int i = 5; i < argc; i++) {
            size_t n;
            u8 *b = read_file(argv[i], &n);
            if (!strcmp(argv[2], "sha1")) { gz_hmac_sha1_calc(key, kl, b, n, d); phex(d, 20); }
            else { gz_hmac_sha256_calc(key, kl, b, n, d); phex(d, 32); }
            printf("\n");
            free(b);
        }
        return 0;
    }
    if (!strcmp(cmd, "pbkdf2") && argc >= 8) {
        u8 pw[1024], salt[1024], out[256];
        setup(atoi(argv[3]));
        u32 iter = (u32)strtoul(argv[4], 0, 10);
        size_t pl = unhex(argv[5], pw, sizeof pw), sl = unhex(argv[6], salt, sizeof salt);
        size_t ol = (size_t)atoi(argv[7]);
        if (ol > sizeof out) return 2;
        if (!strcmp(argv[2], "sha1")) gz_pbkdf2_sha1(pw, pl, salt, sl, iter, out, ol);
        else gz_pbkdf2_sha256(pw, pl, salt, sl, iter, out, ol);
        phex(out, ol); printf("\n");
        return 0;
    }
    if (!strcmp(cmd, "aes") && argc >= 8) { setup(atoi(argv[3])); return aes_cmd(argv + 2); }
    if (!strcmp(cmd, "kdf7z") && argc >= 6) {
        u8 salt[64], pw[1024], key[32];
        setup(atoi(argv[2]));
        size_t sl = unhex(argv[4], salt, sizeof salt), pl = unhex(argv[5], pw, sizeof pw);
        int r = gz_7z_kdf(salt, sl, pw, pl, (unsigned)atoi(argv[3]), key);
        if (r) { printf("error %d\n", r); return 1; }
        phex(key, 32); printf("\n");
        return 0;
    }
    if (!strcmp(cmd, "kdfrar3") && argc >= 5) {
        u8 salt[8], pw[1024], key[16], iv[16];
        setup(atoi(argv[2]));
        size_t sl = unhex(argv[3], salt, sizeof salt), pl = unhex(argv[4], pw, sizeof pw);
        gz_rar3_kdf(pw, pl, sl ? salt : 0, key, iv);
        phex(key, 16); printf(" "); phex(iv, 16); printf("\n");
        return 0;
    }
    if (!strcmp(cmd, "kdfrar5") && argc >= 6) {
        u8 salt[64], pw[1024], key[32], hk[32], pc[8];
        setup(atoi(argv[2]));
        size_t sl = unhex(argv[4], salt, sizeof salt), pl = unhex(argv[5], pw, sizeof pw);
        int r = gz_rar5_kdf(pw, pl, salt, sl, (unsigned)atoi(argv[3]), key, hk, pc);
        if (r) { printf("error %d\n", r); return 1; }
        phex(key, 32); printf(" "); phex(hk, 32); printf(" "); phex(pc, 8); printf("\n");
        return 0;
    }
    if (!strcmp(cmd, "zcenc") && argc >= 5) {
        u8 pw[1024];
        size_t pl = unhex(argv[2], pw, sizeof pw), n;
        u8 *b = read_file(argv[3], &n);
        gz_zipcrypto z;
        gz_zc_init(&z, pw, pl);
        for (size_t off = 0; off < n;) { size_t k = chunk(n - off); gz_zc_encrypt(&z, b + off, k); off += k; }
        FILE *f = fopen(argv[4], "wb");
        if (!f || fwrite(b, 1, n, f) != n) return 2;
        fclose(f);
        free(b);
        return 0;
    }
    fprintf(stderr, "bad command\n");
    return 2;
}
