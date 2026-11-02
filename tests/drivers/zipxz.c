/*
 * zipxz - test driver for the ZIP reader (methods, split sets) and the
 * XZ / LZMA / LZIP stream formats
 *
 *   zipxz xzio <file.xz> <mode> [seed]
 *        decode through gz_xz_decode_io (the ZIP method 95 path) with a reader that
 *        returns odd-sized pieces: mode 0 = 1..13 bytes, 1 = 1..70000 bytes, 2 = whole
 *        reads. Prints "status=<n> size=<n> crc=<hex>".
 *   zipxz stream <file>
 *        decode with the stream codec chosen by gz_stream_codec_find, without a
 *        gz_ctx (c == NULL). Same output.
 *   zipxz fuzz <file> <iterations> <seed> <name>
 *        mutate a copy (bit flips, magic values, smashed bytes, truncation, inserts),
 *        open it from memory as <name>, extract everything (solid pass when a->solid),
 *        read through entry views. Must not crash, hang or allocate without bound.
 *        Prints "fuzz iters=<n> opened=<n> ok=<n> e<code>=<n>... sec=<s>".
 *        FUZZ_ONLY=<iteration> + FUZZ_DUMP=<path> writes that iteration's input.
 */
#include "arc.h"
#include "cpu.h"
#include "crc32.h"
#include "streamfmt.h"
#include "cpio.h"
#include "xz.h"
#include "plat_posix.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

#define OUT_CAP (64u << 20)

static u64 g_rng;
static u64 rnd(void)
{
    g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17;
    return g_rng;
}

static void init_core(void)
{
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_aes_init();
    gz_dispatch_init(-1);
}

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static u8 *load(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 0; }
    fseek(f, 0, SEEK_END);
    *n = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *b = (u8 *)malloc(*n + 1);
    if (fread(b, 1, *n, f) != *n) { fclose(f); free(b); return 0; }
    fclose(f);
    return b;
}

/* ---- sinks ---- */

typedef struct { u64 n; u32 crc; } crc_sink;
static int cs_write(void *u, const u8 *p, size_t n)
{
    crc_sink *k = (crc_sink *)u;
    k->crc = gz_crc32(k->crc, p, n);
    k->n += n;
    return k->n > (4ull << 30) ? GZ_E_LIMIT : GZ_OK;
}

/* reader over memory handing out pieces of random size */
typedef struct { const u8 *p; size_t n, pos; int mode; } piece_rd;
static int pr_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    piece_rd *r = (piece_rd *)ctx;
    size_t left = r->n - r->pos, k = cap;
    if (r->mode == 0) k = 1 + rnd() % 13;
    else if (r->mode == 1) k = 1 + rnd() % 70000;
    if (k > cap) k = cap;
    if (k > left) k = left;
    memcpy(buf, r->p + r->pos, k);
    r->pos += k;
    *got = (u32)k;
    return GZ_OK;
}

static int cmd_xzio(int argc, char **argv)
{
    if (argc < 4) return 2;
    size_t n;
    u8 *b = load(argv[2], &n);
    if (!b) return 2;
    g_rng = argc > 4 ? strtoull(argv[4], 0, 0) | 1 : 12345;
    piece_rd pr = { b, n, 0, atoi(argv[3]) };
    gz_stream_io in = { pr_read, 0, &pr };
    crc_sink k = { 0, 0 };
    gz_ctx *c = gz_ctx_new();
    int r = gz_xz_decode_io(&in, cs_write, &k, c);
    printf("status=%d size=%llu crc=%08x\n", r, (unsigned long long)k.n, k.crc);
    gz_ctx_free(c);
    free(b);
    return 0;
}

static int cmd_stream(int argc, char **argv)
{
    if (argc < 3) return 2;
    size_t n;
    u8 *b = load(argv[2], &n);
    if (!b) return 2;
    gz_src *s = gz_src_mem(b, n, 1);
    const gz_stream_codec *sc = gz_stream_codec_find(s);
    crc_sink k = { 0, 0 };
    int r = sc ? sc->decode(s, cs_write, &k, 0) : -1;
    printf("status=%d size=%llu crc=%08x\n", r, (unsigned long long)k.n, k.crc);
    gz_src_free(s);
    return 0;
}

/* ---- fuzzing ---- */

static size_t mutate(u8 *b, const u8 *orig, size_t on)
{
    static const u32 big[] = { 0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0xFFFF, 0x10000, 0x7FFFFFFF,
                               0x80000000u, 0xFFFFFFFFu, 0xFFFFFFFEu, 22, 46, 512 };
    memcpy(b, orig, on);
    size_t n = on;
    int k = 1 + (int)(rnd() % 4);
    while (k-- && n) {
        /* half of the edits hit the first or last 512 bytes (headers, index, directory) */
        size_t i = rnd() % n;
        if ((rnd() & 1) && n > 1024) i = rnd() & 1 ? rnd() % 512 : n - 1 - rnd() % 512;
        switch (rnd() % 9) {
        case 0: case 1: case 2:
            b[i] ^= (u8)(1u << (rnd() & 7));
            break;
        case 3:
            b[i] = (u8)big[rnd() % GZ_COUNTOF(big)];
            break;
        case 4: {
            u32 v = big[rnd() % GZ_COUNTOF(big)];
            size_t w = rnd() & 1 ? 2 : 4;
            if (i + w <= n) memcpy(b + i, &v, w);
            break;
        }
        case 5:
            n = rnd() % n;
            break;
        case 6: {
            size_t len = 1 + rnd() % 64;
            for (size_t j = 0; j < len && i + j < n; j++) b[i + j] = (u8)rnd();
            break;
        }
        case 7: {
            size_t from = rnd() % n, len = 1 + rnd() % 256;
            if (from + len > n) len = n - from;
            if (i + len > n) len = n - i;
            memmove(b + i, b + from, len);
            break;
        }
        case 8: {
            size_t len = 1 + rnd() % 16;
            if (rnd() & 1) {
                if (n + len > on + 4096) break;
                memmove(b + i + len, b + i, n - i);
                for (size_t j = 0; j < len; j++) b[i + j] = (u8)rnd();
                n += len;
            } else if (i + len <= n) {
                memmove(b + i, b + i + len, n - i - len);
                n -= len;
            }
            break;
        }
        }
    }
    return n;
}

typedef struct { gz_out o; u64 n; } cap_out;
static int c_open(gz_out *o, u32 idx) { (void)idx; ((cap_out *)o)->n = 0; return 0; }
static int c_write(gz_out *o, const u8 *p, size_t n)
{
    cap_out *c = (cap_out *)o;
    (void)p;
    c->n += n;
    return c->n > OUT_CAP ? GZ_E_CANCEL : GZ_OK;
}
static int c_close(gz_out *o, u32 idx, int st) { (void)o; (void)idx; (void)st; return 0; }

static gzch g_pw[] = { 'p', 'w', '1', '2', '3', '4', 0 };

static int arc_one(const u8 *buf, size_t n, const gzch *name, gz_ctx *c, int *nent)
{
    gz_src *s = gz_src_mem(buf, n, 0);
    gz_open_opts o;
    memset(&o, 0, sizeof o);
    o.file_name = name;
    o.password = g_pw;
    gz_archive *a = 0;
    int r = gz_arc_open(&a, s, &o, c);
    *nent = 0;
    if (r) { gz_src_free(s); return r; }
    *nent = (int)a->n;
    c->password = g_pw;
    cap_out co = { { c_open, c_write, c_close, 0 }, 0 };
    if (a->solid) {
        u8 *sel = (u8 *)calloc(1, a->n + 1);
        memset(sel, 1, a->n);
        r = gz_arc_extract_solid(a, s, sel, &co.o, c);
        free(sel);
    } else {
        for (u32 i = 0; i < a->n && i < 2000; i++) {
            int e = gz_arc_extract(a, s, i, &co.o, c);
            if (!r) r = e;
            gz_arc_check_password(a, s, i, c);
            gz_src *v = gz_arc_view(a, s, i, c);
            if (v) {
                u8 tmp[4096];
                u32 got;
                for (int k = 0; k < 4 && v->size; k++) v->read_at(v, rnd() % v->size, tmp, sizeof tmp, &got);
                gz_src_free(v);
            }
        }
    }
    c->password = 0;
    gz_arc_close(a);
    gz_src_free(s);
    return r;
}

static volatile long g_iter;
static void on_alarm(int sig)
{
    (void)sig;
    char msg[96];
    int k = snprintf(msg, sizeof msg, "fuzz: iteration %ld timed out (hang)\n", g_iter);
    if (write(2, msg, (size_t)k) < 0) { /* nothing */ }
    _exit(3);
}

static int cmd_fuzz(int argc, char **argv)
{
    if (argc < 6) return 2;
    size_t on;
    u8 *orig = load(argv[2], &on);
    if (!orig) return 2;
    long iters = atol(argv[3]);
    u64 seed = strtoull(argv[4], 0, 0);
    gzch *name = gz_posix_wide(argv[5]);
    const char *only = getenv("FUZZ_ONLY"), *dump = getenv("FUZZ_DUMP");
    u8 *buf = (u8 *)malloc(on + 4096);
    gz_ctx *c = gz_ctx_new();
    signal(SIGALRM, on_alarm);
    long hist[GZ_E_COUNT + 2] = { 0 }, opened = 0;
    double t0 = now();
    for (long it = 0; it < iters; it++) {
        if (only && it != atol(only)) continue;
        g_rng = (seed + 1) * 0x9E3779B97F4A7C15ull ^ (u64)(it + 1) * 0xD1B54A32D192ED03ull;
        for (int w = 0; w < 4; w++) rnd();
        size_t n = mutate(buf, orig, on);
        if (only && dump) {
            FILE *f = fopen(dump, "wb");
            if (f) { fwrite(buf, 1, n, f); fclose(f); }
        }
        g_iter = it;
        alarm(30);
        int nent = 0;
        int st = arc_one(buf, n, name, c, &nent);
        alarm(0);
        opened += nent > 0;
        hist[st >= 0 && st < GZ_E_COUNT ? st : GZ_E_COUNT]++;
    }
    printf("fuzz iters=%ld opened=%ld ok=%ld", iters, opened, hist[0]);
    for (int k = 1; k <= GZ_E_COUNT; k++) if (hist[k]) printf(" e%d=%ld", k, hist[k]);
    printf(" sec=%.1f\n", now() - t0);
    gz_ctx_free(c);
    free(name);
    free(buf);
    free(orig);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    init_core();
    if (!strcmp(argv[1], "xzio")) return cmd_xzio(argc, argv);
    if (!strcmp(argv[1], "stream")) return cmd_stream(argc, argv);
    if (!strcmp(argv[1], "fuzz")) return cmd_fuzz(argc, argv);
    return 2;
}
