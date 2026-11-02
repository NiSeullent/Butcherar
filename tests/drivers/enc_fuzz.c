/*
 * enc_fuzz - round-trip fuzz target for the encoders: Deflate (deflate_enc.c), LZMA / LZMA2
 * (lzma_enc.c + lz_mf.c), BZip2 (bzip2_enc.c) and Zstandard (zstd_enc.c).
 *
 * Each input picks a codec, a level and options; the rest is the data. The data is encoded
 * (read in pieces of a chosen size), decoded with our own decoders and compared; with
 * "reuse" the same encoder object encodes it a second time and both outputs must match.
 * Any encoder error, decoder error or mismatch aborts (so sanitizers and libFuzzer report
 * the input).
 *
 *   libFuzzer (clang + compiler-rt), one format-free target over the four encoders:
 *     clang -std=gnu11 -O1 -g -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined \
 *       -fno-omit-frame-pointer -Isrc/core -Isrc/codec -o build/fuzz/enc_fuzz tests/drivers/enc_fuzz.c \
 *       src/core/cpu.c src/core/crc32.c src/core/crc64.c src/core/sha1.c src/core/sha256.c \
 *       src/core/aes.c src/core/blake2.c src/codec/inflate.c src/codec/deflate_enc.c \
 *       src/codec/lzma.c src/codec/lzma_enc.c src/codec/lz_mf.c src/codec/bzip2.c src/codec/bzip2_enc.c \
 *       src/codec/zstd.c src/codec/zstd_enc.c src/codec/xxhash.c
 *     build/fuzz/enc_fuzz -max_len=65536 -timeout=60 -rss_limit_mb=1500 CORPUS
 *   Plain build (the same sources plus -DENC_FUZZ_MAIN; tests/cases/regress_codecs_enc.py builds
 *   it with clang -fsanitize=undefined -fno-sanitize-recover=all):
 *     enc_fuzz FILE...                    every file is one input
 *     enc_fuzz rand SEED COUNT [MAXLEN]   generated inputs (all codecs, levels, option bytes)
 *     enc_fuzz one CODEC LEVEL FILE [F2 F3 F4 F5 F6 F7]   FILE's bytes with an explicit header
 *   exit 0: all inputs round-tripped; abort() on the first failure (message on stderr).
 *
 * Environment: GZ_TIER=n forces a dispatch tier (Deflate kernels, CRC-32, inflater).
 *
 * Input layout (8 header bytes, then the data; shorter inputs are padded with zeros):
 *   h[0] codec % 6: 0 Deflate, 1 LZMA + end marker, 2 LZMA without end marker (decoded with
 *        the size), 3 LZMA2, 4 BZip2, 5 Zstandard
 *   h[1] level: Deflate/LZMA % 10 (LZMA: bit 7 = extreme), BZip2 1 + % 9, Zstandard % 20
 *   h[2] bit 0 LZMA fast parser, bit 1 LZMA normal parser, bit 2 other match finder,
 *        bit 3 inexact size hint (h[6]), bit 4 BZip2 randomized / Zstandard no checksum and
 *        unknown content size, bit 5 encode twice with one encoder (outputs must match),
 *        bits 6-7 read sizes: whole buffer, 1..7, 1..4096, 1..65536 bytes
 *   h[3] LZMA: lc/lp/pb = h % 9, h / 9 % 5, h / 45 when h < 225 (else 3/0/2);
 *        Zstandard: window log 9 + h % 14 (h % 14 == 0: level default)
 *   h[4] LZMA nice length: 0 level default, else 5 + (h - 1) (255: 273)
 *   h[5] LZMA match finder depth: 0 automatic, else h (deeper chains only cost time:
 *        HC4 at depth 1020 on long runs takes seconds per MiB, in xz as well)
 *   h[6] with h[2] bit 3: size hint none (dictionary capped at 4 MiB) / n/3+1 / n*5+1 / 1
 *        (low 2 bits); bits 2-7 != 0: LZMA match-finder renormalisation every
 *        4096 + 997 * (h >> 2) positions
 *   h[7] 0: data as is; else the data is repeated (each copy slightly changed) up to
 *        h * 4 KiB (1 MiB), to reach block / chunk / window boundaries from small inputs
 */
#include "deflate_enc.h"
#include "inflate.h"
#include "lzma_enc.h"
#include "lzma.h"
#include "bzip2_enc.h"
#include "bzip2.h"
#include "zstd_enc.h"
#include "zstd.h"
#include "cpu.h"
#include "crc32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* built from the codec sources alone (not linked with src/posix): libc allocator; big blocks
 * are page-aligned as base.h promises (the Deflate rebase kernels use aligned SIMD loads) */
void *gz_alloc(size_t n) { return calloc(1, n ? n : 1); }
void *gz_realloc(void *p, size_t n) { return realloc(p, n); }
void gz_free(void *p) { free(p); }
void *gz_alloc_big(size_t n)
{
    void *p = 0;
    if (posix_memalign(&p, 4096, n ? n : 1)) return 0;
    memset(p, 0, n);
    return p;
}
void gz_free_big(void *p, size_t n) { (void)n; free(p); }

#define HDR 8
#define EXPAND_UNIT (4u << 10)

static void fail(const char *what, int code)
{
    fprintf(stderr, "enc_fuzz: %s (%d)\n", what, code);
    abort();
}

/* ---------------- I/O ---------------- */

typedef struct {
    const u8 *in; size_t in_n, in_pos;
    u32 chunk_mode; u64 rng;           /* read sizes */
    u8 *out; size_t out_n, out_cap;    /* growing output (encode) */
    const u8 *want; size_t want_n, got_n; int mismatch;   /* comparing sink (decode) */
} io_t;

static u32 io_rnd(io_t *x)
{
    x->rng ^= x->rng << 13; x->rng ^= x->rng >> 7; x->rng ^= x->rng << 17;
    return (u32)(x->rng >> 16);
}

static int rd(void *c, u8 *buf, u32 cap, u32 *got)
{
    io_t *x = (io_t *)c;
    size_t n = x->in_n - x->in_pos;
    if (x->chunk_mode == 1) cap = cap < 7 ? cap : 1 + io_rnd(x) % 7;
    else if (x->chunk_mode == 2) cap = cap < 4096 ? cap : 1 + io_rnd(x) % 4096;
    else if (x->chunk_mode == 3) cap = cap < 65536 ? cap : 1 + io_rnd(x) % 65536;
    if (n > cap) n = cap;
    memcpy(buf, x->in + x->in_pos, n);
    x->in_pos += n;
    *got = (u32)n;
    return GZ_OK;
}

static int wr_grow(void *c, const u8 *p, size_t n)
{
    io_t *x = (io_t *)c;
    if (x->out_n + n > x->out_cap) {
        size_t nc = x->out_cap ? x->out_cap * 2 : 65536;
        while (nc < x->out_n + n) nc *= 2;
        u8 *q = (u8 *)realloc(x->out, nc);
        if (!q) fail("out of memory", 0);
        x->out = q;
        x->out_cap = nc;
    }
    memcpy(x->out + x->out_n, p, n);
    x->out_n += n;
    return GZ_OK;
}

static int wr_cmp(void *c, const u8 *p, size_t n)
{
    io_t *x = (io_t *)c;
    if (n > x->want_n - x->got_n || memcmp(p, x->want + x->got_n, n)) {
        x->mismatch = 1;
        return GZ_E_DATA;
    }
    x->got_n += n;
    return GZ_OK;
}

/* ---------------- one input ---------------- */

typedef struct {
    int codec;
    u8 h[HDR];
    u8 props[5], dprop;
} job_t;

static gz_inflater *g_inf;
static gz_lzma_dec *g_lzd;
static gz_bzip2_dec *g_bzd;
static gz_zstd_dec *g_zsd;

static void init_once(void)
{
    static int done;
    if (done) return;
    done = 1;
    const char *t = getenv("GZ_TIER");
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_dispatch_init(t ? atoi(t) : -1);
    g_inf = gz_inflater_new();
    g_lzd = gz_lzma_dec_new();
    g_bzd = gz_bzip2_dec_new();
    g_zsd = gz_zstd_dec_new();
    if (!g_inf || !g_lzd || !g_bzd || !g_zsd) fail("decoder allocation", 0);
}

static u64 hint_of(const u8 *h, size_t n, int *capped)
{
    *capped = 0;
    if (!(h[2] & 8)) return n ? n : 1;
    switch (h[6] & 3) {
    case 0: *capped = 1; return 0;
    case 1: return n / 3 + 1;
    case 2: return (u64)n * 5 + 1;
    default: return 1;
    }
}

/* Encoder objects live for one input (reuse: two encode calls on the same object). */
typedef struct {
    gz_deflate_enc *de;
    gz_lzma_enc *le;
    gz_bzip2_enc *be;
    gz_zstd_enc *ze;
    u64 zsize;                         /* content size passed to the Zstandard encoder */
} encs_t;

/* 0: encoder created, 1: options rejected as invalid (fine), 2: LZMA encoder created for
 * LZMA2 with lc + lp > 4 (the encode call must refuse it); aborts on anything else */
static int make_encoder(job_t *j, encs_t *E, size_t n)
{
    const u8 *h = j->h;
    int capped;
    u64 hint = hint_of(h, n, &capped);
    memset(E, 0, sizeof *E);
    switch (j->codec) {
    case 0:
        E->de = gz_deflate_enc_new(h[1] % 10);
        if (!E->de) fail("deflate_enc_new", 0);
        return 0;
    case 1: case 2: case 3: {
        gz_lzma_enc_opts o;
        gz_lzma_enc_opts_init(&o, (h[1] & 0x7F) % 10 | (h[1] & 0x80 ? GZ_LZMA_EXTREME : 0));
        if (h[2] & 1) o.mode = GZ_LZMA_FAST;
        if (h[2] & 2) o.mode = GZ_LZMA_NORMAL;
        if (h[2] & 4) o.mf = o.mf == GZ_MF_BT4 ? GZ_MF_HC4 : GZ_MF_BT4;
        if (h[3] < 225) {
            o.lc = (u8)(h[3] % 9);
            o.lp = (u8)(h[3] / 9 % 5);
            o.pb = (u8)(h[3] / 45);
        }
        if (h[4]) o.nice_len = h[4] == 255 ? 273 : 5 + (h[4] - 1u);
        if (h[5]) o.depth = h[5];
        o.size_hint = hint;
        if (capped && o.dict_size > (4u << 20)) o.dict_size = 4u << 20;
        if (h[2] & 8 && h[6] >> 2) o.test_norm_step = 4096 + 997u * (h[6] >> 2);
        int chk = gz_lzma_enc_check(&o, j->codec == 3);
        E->le = gz_lzma_enc_new(&o);
        if (chk != GZ_OK) {
            /* invalid for this codec: LZMA2 still creates the encoder (lc + lp is checked by
             * gz_lzma2_encode), everything else must be refused by gz_lzma_enc_new */
            if (E->le && !(j->codec == 3 && gz_lzma_enc_check(&o, 0) == GZ_OK))
                fail("lzma_enc_new accepted invalid options", chk);
            if (!E->le) return 1;
            return 2;                  /* LZMA2 with lc + lp > 4: encode must say GZ_E_METHOD */
        }
        if (!E->le) fail("lzma_enc_new", 0);
        gz_lzma_enc_props(E->le, j->props);
        j->dprop = gz_lzma2_enc_dict_prop(E->le);
        return 0;
    }
    case 4:
        E->be = gz_bzip2_enc_new(1 + h[1] % 9);
        if (!E->be) fail("bzip2_enc_new", 0);
        if (h[2] & 16) gz_bzip2_enc_set_randomized(E->be, 1);
        return 0;
    default: {
        gz_zstd_enc_opts o;
        gz_zstd_enc_opts_init(&o, h[1] % 20);
        if (h[3] % 14) o.window_log = 9 + h[3] % 14;
        if (h[2] & 16) o.checksum = 0;
        o.size_hint = hint;
        E->zsize = h[2] & 16 ? GZ_SIZE_UNKNOWN : n;
        E->ze = gz_zstd_enc_new(&o);
        if (!E->ze) fail("zstd_enc_new", 0);
        return 0;
    }
    }
}

static void free_encoder(encs_t *E)
{
    if (E->de) gz_deflate_enc_free(E->de);
    if (E->le) gz_lzma_enc_free(E->le);
    if (E->be) gz_bzip2_enc_free(E->be);
    if (E->ze) gz_zstd_enc_free(E->ze);
}

static int encode(job_t *j, encs_t *E, const u8 *data, size_t n, io_t *x, u64 seed)
{
    memset(x, 0, sizeof *x);
    x->in = data;
    x->in_n = n;
    x->chunk_mode = j->h[2] >> 6;
    x->rng = seed | 1;
    gz_stream_io io = { rd, wr_grow, x };
    switch (j->codec) {
    case 0: {
        u32 crc = 0;
        u64 in = 0, out = 0;
        int r = gz_deflate_encode(E->de, &io, &crc, &in, &out);
        if (r == GZ_OK && (in != n || out != x->out_n || crc != gz_crc32(0, data, n)))
            fail("deflate counters / CRC", 0);
        return r;
    }
    case 1: case 2: {
        u8 p[5];
        int r = gz_lzma_encode(E->le, &io, p, j->codec == 1);
        if (r == GZ_OK && (memcmp(p, j->props, 5) || gz_lzma_enc_in_size(E->le) != n ||
                           gz_lzma_enc_out_size(E->le) != x->out_n))
            fail("lzma props / counters", 0);
        return r;
    }
    case 3: {
        u8 dp = 0xFF;
        int r = gz_lzma2_encode(E->le, &io, &dp);
        if (r == GZ_OK && (dp != j->dprop || gz_lzma_enc_in_size(E->le) != n ||
                           gz_lzma_enc_out_size(E->le) != x->out_n))
            fail("lzma2 dict prop / counters", 0);
        return r;
    }
    case 4:
        return gz_bzip2_encode(E->be, &io);
    default: {
        int r = gz_zstd_encode(E->ze, &io, E->zsize);
        if (r == GZ_OK && (gz_zstd_enc_in_size(E->ze) != n || gz_zstd_enc_out_size(E->ze) != x->out_n))
            fail("zstd counters", 0);
        return r;
    }
    }
}

static void decode_check(job_t *j, const u8 *comp, size_t cn, const u8 *data, size_t n)
{
    io_t x;
    memset(&x, 0, sizeof x);
    x.in = comp;
    x.in_n = cn;
    x.want = data;
    x.want_n = n;
    x.chunk_mode = j->h[2] >> 6;
    x.rng = 0x9E3779B97F4A7C15ull ^ cn;
    gz_stream_io io = { rd, wr_cmp, &x };
    u64 used = 0;
    int r;
    switch (j->codec) {
    case 0:
        r = gz_inflate_run(g_inf, &io, 0);
        used = cn;                     /* the inflater reads ahead: no exact count */
        break;
    case 1: r = gz_lzma_decode(g_lzd, j->props, &io, GZ_SIZE_UNKNOWN, &used); break;
    case 2: r = gz_lzma_decode(g_lzd, j->props, &io, n, &used); break;
    case 3: r = gz_lzma2_decode(g_lzd, j->dprop, &io, (n & 1) ? n : GZ_SIZE_UNKNOWN, &used); break;
    case 4: r = gz_bzip2_decode(g_bzd, &io, GZ_SIZE_UNKNOWN, 0, &used); break;
    default: r = gz_zstd_decode(g_zsd, &io, GZ_SIZE_UNKNOWN, &used); break;
    }
    if (x.mismatch) fail("decoded data differs from the input", r);
    if (r != GZ_OK) fail("decoder rejected the encoder's output", r);
    if (x.got_n != n) fail("decoded size differs from the input size", (int)(x.got_n - n));
    if (used != cn) fail("decoder did not consume the whole stream", (int)(cn - used));
}

static void run_one(const u8 *buf, size_t size)
{
    job_t j;
    memset(&j, 0, sizeof j);
    memcpy(j.h, buf, size < HDR ? size : HDR);
    const u8 *data = size > HDR ? buf + HDR : buf;
    size_t n = size > HDR ? size - HDR : 0;
    u8 *big = 0;
    if (j.h[7] && n) {                 /* repeat the data (each copy changed a little) */
        size_t want = (size_t)j.h[7] * EXPAND_UNIT;
        if (want > n) {
            big = (u8 *)malloc(want);
            if (!big) fail("out of memory", 0);
            for (size_t k = 0, copy = 0; k < want; copy++) {
                size_t m = want - k < n ? want - k : n;
                memcpy(big + k, data, m);
                if (copy) big[k + (copy * 7919) % m] ^= (u8)copy;
                k += m;
            }
            data = big;
            n = want;
        }
    }
    j.codec = j.h[0] % 6;

    encs_t E;
    int mk = make_encoder(&j, &E, n);
    if (mk == 1) { free(big); return; }
    io_t a, b;
    int r = encode(&j, &E, data, n, &a, 0x1234567ull + n);
    if (mk == 2) {                     /* LZMA2 with lc + lp > 4 */
        if (r != GZ_E_METHOD) fail("lzma2 accepted lc + lp > 4", r);
        free(a.out); free_encoder(&E); free(big);
        return;
    }
    if (r != GZ_OK) fail("encoder failed", r);
    if (j.h[2] & 32) {                 /* reuse: same bytes from the same encoder object */
        r = encode(&j, &E, data, n, &b, 0xABCDEFull + n);
        if (r != GZ_OK) fail("encoder failed on reuse", r);
        if (b.out_n != a.out_n || (a.out_n && memcmp(a.out, b.out, a.out_n)))
            fail("encoder reuse gave different output", 0);
        free(b.out);
    }
    free_encoder(&E);
    decode_check(&j, a.out, a.out_n, data, n);
    free(a.out);
    free(big);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    init_once();
    run_one(data, size);
    return 0;
}

#ifdef ENC_FUZZ_MAIN
static u64 g_s;
static u32 rnd(void)
{
    g_s = g_s * 6364136223846793005ull + 1442695040888963407ull;
    return (u32)(g_s >> 33);
}

/* data shapes: text-like words, random, runs, small alphabet, repeats of a random block */
static void gen(u8 *p, size_t n)
{
    static const char *w[] = { "the ", "archive ", "고기 ", "압축 ", "match ", "literal ", "\n",
                               "0x1F ", "dictionary ", "window " };
    int kind = rnd() % 5;
    size_t i = 0;
    if (kind == 4 && n > 1) {
        size_t blk = 1 + rnd() % (n < 300 ? n : 300);
        for (; i < blk; i++) p[i] = (u8)rnd();
        for (; i < n; i++) p[i] = rnd() % 64 ? p[i - blk] : (u8)rnd();
        return;
    }
    while (i < n) {
        if (kind == 0) {
            const char *s = w[rnd() % 10];
            for (size_t k = 0; s[k] && i < n; k++) p[i++] = (u8)s[k];
        } else if (kind == 1) {
            p[i++] = (u8)rnd();
        } else if (kind == 2) {
            u8 c = (u8)rnd();
            for (size_t k = 1 + rnd() % 400; k && i < n; k--) p[i++] = c;
        } else {
            p[i++] = (u8)('a' + rnd() % 4);
        }
    }
}

static u8 *load(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *p = (u8 *)malloc(sz > 0 ? (size_t)sz : 1);
    if (p && sz > 0 && fread(p, 1, (size_t)sz, f) != (size_t)sz) { free(p); p = 0; }
    fclose(f);
    *n = sz > 0 ? (size_t)sz : 0;
    return p;
}

int main(int argc, char **argv)
{
    init_once();
    if (argc >= 4 && !strcmp(argv[1], "rand")) {
        g_s = strtoull(argv[2], 0, 10) * 2654435761u + 1;
        long count = atol(argv[3]);
        size_t maxlen = argc > 4 ? (size_t)atol(argv[4]) : 70000;
        u8 *buf = (u8 *)malloc(HDR + maxlen + 1);
        for (long it = 0; it < count; it++) {
            u8 *h = buf;
            for (int k = 0; k < HDR; k++) h[k] = (u8)rnd();
            h[0] = (u8)(it % 6);                       /* every codec in turn */
            h[1] = (u8)((it / 6) % 20);                /* and every level */
            if (h[0] >= 1 && h[0] <= 3 && rnd() % 4 == 0) h[1] = (u8)(h[1] % 10 | 0x80);
            if (rnd() % 3) h[3] = 225;                 /* mostly default lc/lp/pb */
            if (rnd() % 2) h[4] = 0;
            if (rnd() % 2) h[5] = 0;
            h[7] = rnd() % 8 ? 0 : (u8)(1 + rnd() % 24);
            size_t n = rnd() % 4 ? rnd() % (maxlen + 1) : rnd() % 64;
            gen(buf + HDR, n);
            run_one(buf, HDR + n);
        }
        printf("enc_fuzz: %ld inputs ok\n", count);
        free(buf);
        return 0;
    }
    if (argc >= 5 && !strcmp(argv[1], "one")) {
        size_t n;
        u8 *p = load(argv[4], &n);
        if (!p) { fprintf(stderr, "cannot read %s\n", argv[4]); return 1; }
        u8 *buf = (u8 *)malloc(HDR + n + 1);
        memset(buf, 0, HDR);
        buf[0] = (u8)atoi(argv[2]);
        buf[1] = (u8)atoi(argv[3]);
        buf[3] = 225;
        for (int k = 5; k < argc && k - 3 < HDR; k++) buf[k - 3] = (u8)strtol(argv[k], 0, 0);
        memcpy(buf + HDR, p, n);
        run_one(buf, HDR + n);
        printf("enc_fuzz: ok\n");
        free(p); free(buf);
        return 0;
    }
    if (argc < 2) {
        fprintf(stderr, "usage: enc_fuzz FILE... | rand SEED COUNT [MAXLEN] | one CODEC LEVEL FILE [h2..h7]\n");
        return 1;
    }
    for (int i = 1; i < argc; i++) {
        size_t n;
        u8 *p = load(argv[i], &n);
        if (!p) { fprintf(stderr, "cannot read %s\n", argv[i]); return 1; }
        run_one(p, n);
        free(p);
    }
    printf("enc_fuzz: %d inputs ok\n", argc - 1);
    return 0;
}
#endif
