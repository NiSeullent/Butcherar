/*
 * legacy_codec - raw stream driver and in-process fuzzer for the legacy codecs
 * and formats (fmt_legacy.py)
 *
 *   legacy_codec shrink  <in> <out> <size>
 *   legacy_codec implode <in> <out> <size> <large 0|1> <three 0|1>
 *   legacy_codec lzh     <in> <out> <size> <GZ_LZH_* method number>
 *   legacy_codec lzw     <in> <out> <size> <flags byte>
 *   legacy_codec bench   <codec args as above, out ignored> <repeat>
 *       size: decimal or -1 (GZ_SIZE_UNKNOWN). Prints "status=<n> out=<bytes>".
 *
 *   legacy_codec fuzz <codec> <in> <iters> <seed> <size> [params]   codec as above
 *   legacy_codec fuzz arc <in> <iters> <seed> <archive name> [password]
 *       Decodes <iters> mutated copies of <in> (bit flips, extreme field values,
 *       truncation, chunk copies, insertions) with one reused decoder / gz_ctx;
 *       "arc" opens each copy with gz_arc_open and extracts every entry. Every
 *       iteration has a time limit; FUZZ_ONLY=<i> runs one iteration and
 *       FUZZ_DUMP=<path> writes its input. Prints "fuzz iters=<n> ok=<n> ...".
 */
#include "arc.h"
#include "lzw.h"
#include "implode.h"
#include "lzh.h"
#include "cpu.h"
#include "crc32.h"
#include "inflate.h"
#include "plat_posix.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define FUZZ_OUT_CAP (256ull << 20)   /* per iteration: stops decompression bombs */

typedef struct { gz_range_reader rd; FILE *f; unsigned long long n, cap; } drv_io;

static int w_cb(void *ctx, const u8 *p, size_t n)
{
    drv_io *x = (drv_io *)ctx;
    x->n += n;
    if (x->cap && x->n > x->cap) return GZ_E_LIMIT;
    if (x->f && fwrite(p, 1, n, x->f) != n) return GZ_E_IO;
    return GZ_OK;
}

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

typedef struct { gz_lzw_dec *lzw; gz_implode_dec *imp; gz_lzh_dec *lzh; } decs;

/* one raw decode: a = { codec, size, params... } */
static int decode_one(decs *d, char **a, int ac, gz_src *s, drv_io *x, int alt)
{
    long long sz = atoll(a[1]);
    u64 out_size = sz < 0 ? GZ_SIZE_UNKNOWN : (u64)sz;
    x->rd.src = s;
    x->rd.pos = 0;
    x->rd.end = s->size;
    gz_stream_io io = { gz_range_read, w_cb, x };
    const char *codec = a[0];
    if (!strcmp(codec, "shrink")) return gz_shrink_decode(alt ? d->lzw : 0, &io, out_size);
    if (!strcmp(codec, "implode") && ac > 3)
        return gz_implode_decode(alt ? 0 : d->imp, &io, out_size, atoi(a[2]), atoi(a[3]));
    if (!strcmp(codec, "lzh") && ac > 2) return gz_lzh_decode(d->lzh, &io, out_size, atoi(a[2]));
    if (!strcmp(codec, "lzw") && ac > 2) return gz_lzw_decode(d->lzw, &io, out_size, atoi(a[2]));
    return -1;
}

/* ---------------- archive extraction to nowhere ---------------- */

typedef struct { gz_out o; unsigned long long n; int opened; } null_out;

static int n_open(gz_out *o, u32 idx) { (void)idx; ((null_out *)o)->opened++; return GZ_OK; }
static int n_write(gz_out *o, const u8 *p, size_t n)
{
    null_out *k = (null_out *)o;
    (void)p;
    k->n += n;
    return k->n > FUZZ_OUT_CAP ? GZ_E_LIMIT : GZ_OK;
}
static int n_close(gz_out *o, u32 idx, int st) { (void)idx; (void)st; ((null_out *)o)->opened--; return GZ_OK; }

static int arc_one(const u8 *p, size_t n, const gzch *name, const gzch *pw, gz_ctx *c, int *nent)
{
    gz_src *s = gz_src_mem(p, n, 0);
    if (!s) return GZ_E_NOMEM;
    gz_open_opts oo;
    memset(&oo, 0, sizeof oo);
    oo.file_name = name;
    oo.password = pw;
    gz_archive *a = 0;
    int r = gz_arc_open(&a, s, &oo, c);
    *nent = 0;
    if (r) { gz_src_free(s); return r; }
    *nent = (int)a->n;
    c->password = pw;
    null_out no = { { n_open, n_write, n_close, 0 }, 0, 0 };
    gzch m[64];
    for (u32 i = 0; i < a->n; i++) {
        gz_arc_method(a, &a->e[i], m, 64);
        if (a->e[i].enc) gz_arc_check_password(a, s, i, c);
        gz_src *v = a->solid ? 0 : gz_arc_view(a, s, i, c);
        if (v) {
            u8 tmp[512];
            u32 got;
            v->read_at(v, 0, tmp, sizeof tmp, &got);
            gz_src_free(v);
        }
    }
    if (a->solid) {
        u8 *sel = (u8 *)calloc(1, a->n + 1);
        memset(sel, 1, a->n);
        r = gz_arc_extract_solid(a, s, sel, &no.o, c);
        free(sel);
    } else {
        for (u32 i = 0; i < a->n && no.n <= FUZZ_OUT_CAP; i++) {
            int er = gz_arc_extract(a, s, i, &no.o, c);
            if (er && !r) r = er;
        }
    }
    if (no.opened) { fprintf(stderr, "out->open/close unbalanced (%d)\n", no.opened); abort(); }
    gz_arc_close(a);
    gz_src_free(s);
    return r;
}

/* ---------------- mutations ---------------- */

static u64 g_rng;
static u32 rnd(void)
{
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return (u32)(g_rng >> 16);
}

/* orig[0..on) -> b (capacity on + 4096), returns the new length */
static size_t mutate(u8 *b, const u8 *orig, size_t on)
{
    static const u32 big[] = { 0, 1, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0x80000000u, 0xFFFFFFFFu };
    memcpy(b, orig, on);
    size_t n = on;
    int k = 1 + (int)(rnd() % 4);
    while (k-- && n) {
        size_t lim = (rnd() & 1) && n > 512 ? 512 : n;      /* half the edits hit the headers */
        size_t i = rnd() % lim;
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
        case 7: {                                   /* copy a chunk over another place */
            size_t from = rnd() % n, len = 1 + rnd() % 256;
            if (from + len > n) len = n - from;
            if (i + len > n) len = n - i;
            memmove(b + i, b + from, len);
            break;
        }
        case 8: {                                   /* insert or delete a few bytes */
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

static volatile long g_iter;
static const u8 *volatile g_cur;
static volatile size_t g_cur_n;
static const char *g_dump;

static void on_alarm(int sig)
{
    (void)sig;
    char msg[96];
    int k = snprintf(msg, sizeof msg, "fuzz: iteration %ld timed out (hang)\n", g_iter);
    if (write(2, msg, (size_t)k) < 0) { /* nothing */ }
    if (g_dump && g_cur) {
        FILE *f = fopen(g_dump, "wb");
        if (f) { fwrite((const void *)g_cur, 1, g_cur_n, f); fclose(f); }
    }
    _exit(3);
}

static int cmd_fuzz(int argc, char **argv)
{
    /* fuzz <target> <in> <iters> <seed> <rest...> */
    if (argc < 7) return 2;
    const char *target = argv[2];
    FILE *f = fopen(argv[3], "rb");
    if (!f) { perror(argv[3]); return 2; }
    fseek(f, 0, SEEK_END);
    size_t on = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *orig = (u8 *)malloc(on + 1);
    if (fread(orig, 1, on, f) != on) { fclose(f); return 2; }
    fclose(f);
    long iters = atol(argv[4]);
    u64 seed = strtoull(argv[5], 0, 0);
    char **rest = argv + 6;
    int nrest = argc - 6;
    const char *only = getenv("FUZZ_ONLY");
    g_dump = getenv("FUZZ_DUMP");
    u8 *buf = (u8 *)malloc(on + 4096);
    decs d = { gz_lzw_dec_new(), gz_implode_dec_new(), gz_lzh_dec_new() };
    gz_ctx *c = gz_ctx_new();
    gzch *name = 0, *pw = 0;
    int is_arc = !strcmp(target, "arc");
    if (is_arc) {
        name = gz_posix_wide(rest[0]);
        if (nrest > 1 && rest[1][0]) pw = gz_posix_wide(rest[1]);
    }
    signal(SIGALRM, on_alarm);
    long hist[GZ_E_COUNT + 2] = { 0 };
    long opened = 0;
    double t0 = now();
    for (long it = 0; it < iters; it++) {
        if (only && it != atol(only)) continue;
        g_rng = (seed + 1) * 0x9E3779B97F4A7C15ull ^ (u64)(it + 1) * 0xD1B54A32D192ED03ull;
        for (int w = 0; w < 4; w++) rnd();
        size_t n = mutate(buf, orig, on);
        g_iter = it;
        g_cur = buf;
        g_cur_n = n;
        if (only && g_dump) {
            FILE *df = fopen(g_dump, "wb");
            if (df) { fwrite(buf, 1, n, df); fclose(df); }
        }
        alarm(20);
        int st;
        if (is_arc) {
            int nent = 0;
            st = arc_one(buf, n, name, pw, c, &nent);
            opened += nent > 0;
        } else {
            gz_src *s = gz_src_mem(buf, n, 0);
            drv_io x;
            memset(&x, 0, sizeof x);
            x.cap = FUZZ_OUT_CAP;
            /* every 4th iteration: size unknown, so the stream must end by itself */
            char sz[32];
            char *a2[8];
            int ac = nrest + 1 > 8 ? 8 : nrest + 1;
            a2[0] = (char *)target;
            for (int k = 1; k < ac; k++) a2[k] = rest[k - 1];
            if ((it & 3) == 3) { snprintf(sz, sizeof sz, "-1"); a2[1] = sz; }
            st = decode_one(&d, a2, ac, s, &x, (int)(it & 1));
            gz_src_free(s);
            if (st < 0) return 2;
        }
        alarm(0);
        hist[st >= 0 && st < GZ_E_COUNT ? st : GZ_E_COUNT]++;
    }
    double dt = now() - t0;
    printf("fuzz iters=%ld ok=%ld", iters, hist[0]);
    if (is_arc) printf(" opened=%ld", opened);
    for (int k = 1; k <= GZ_E_COUNT; k++) if (hist[k]) printf(" e%d=%ld", k, hist[k]);
    printf(" sec=%.1f\n", dt);
    gz_lzw_dec_free(d.lzw);
    gz_implode_dec_free(d.imp);
    gz_lzh_dec_free(d.lzh);
    gz_ctx_free(c);
    free(name);
    free(pw);
    free(buf);
    free(orig);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 5) return 2;
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_aes_init();
    gz_dispatch_init(-1);
    if (!strcmp(argv[1], "fuzz")) return cmd_fuzz(argc, argv);
    int bench = !strcmp(argv[1], "bench");
    char **a = argv + bench;
    int ac = argc - bench;
    int repeat = bench ? atoi(argv[argc - 1]) : 1;
    if (bench) ac--;
    gz_src *s = gz_posix_open_src(a[2]);
    if (!s) { perror(a[2]); return 2; }
    decs d = { gz_lzw_dec_new(), gz_implode_dec_new(), gz_lzh_dec_new() };
    /* decode_one takes { codec, size, params... } */
    char *a2[8];
    int ac2 = ac - 3 > 8 ? 8 : ac - 3;
    a2[0] = a[1];
    for (int k = 1; k < ac2; k++) a2[k] = a[3 + k];
    int st = 0;
    unsigned long long produced = 0;
    double t0 = now();
    for (int it = 0; it < repeat; it++) {
        drv_io x;
        memset(&x, 0, sizeof x);
        x.f = bench ? 0 : fopen(a[3], "wb");
        st = decode_one(&d, a2, ac2, s, &x, it & 1);
        if (x.f) fclose(x.f);
        if (st < 0) return 2;
        produced = x.n;
    }
    double dt = now() - t0;
    printf("status=%d out=%llu", st, produced);
    if (bench) printf(" MB/s=%.1f", produced * (double)repeat / dt / 1e6);
    printf("\n");
    gz_lzw_dec_free(d.lzw);
    gz_implode_dec_free(d.imp);
    gz_lzh_dec_free(d.lzh);
    gz_src_free(s);
    return 0;
}
