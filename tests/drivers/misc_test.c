/*
 * misc_test - driver for the small block codecs (ADC, LZNT1, LZO1X, LZFSE, LZVN,
 * XPRESS plain / Huffman). Buffers are allocated with their exact sizes so that
 * AddressSanitizer catches any read or write outside them.
 *
 *   misc_test d     <codec> <in> <out> <out_cap>       decode a file
 *   misc_test batch <codec> <blob> <jobs> <out>        decode "off len out_len" lines of jobs
 *   misc_test fuzz  <codec> <in> <out_cap> <iters> <seed>   mutated inputs must not crash
 *   misc_test bench <codec> <in> <out_cap> <ms>        output MB/s
 *   misc_test size  <in>                               gz_lzfse_size
 * codec: adc lznt1 lzo lzfse lzvn xpress xhuff
 * Prints "rc=<code> out=<bytes> used=<bytes>" (d), failures / histograms otherwise.
 */
#include "adc.h"
#include "lznt1.h"
#include "lzo.h"
#include "lzfse.h"
#include "xpress.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef int (*dec_fn)(const u8 *in, size_t n, u8 *out, size_t cap, size_t *on, size_t *iu);

static int d_adc(const u8 *in, size_t n, u8 *out, size_t cap, size_t *on, size_t *iu)
{ return gz_adc_decode(in, n, out, cap, on, iu); }
static int d_lznt1(const u8 *in, size_t n, u8 *out, size_t cap, size_t *on, size_t *iu)
{ *iu = n; return gz_lznt1_decode(in, n, out, cap, on); }
static int d_lzo(const u8 *in, size_t n, u8 *out, size_t cap, size_t *on, size_t *iu)
{ return gz_lzo1x_decode(in, n, out, cap, on, iu); }
static int d_lzfse(const u8 *in, size_t n, u8 *out, size_t cap, size_t *on, size_t *iu)
{ return gz_lzfse_decode(in, n, out, cap, on, iu); }
static int d_lzvn(const u8 *in, size_t n, u8 *out, size_t cap, size_t *on, size_t *iu)
{ return gz_lzvn_decode(in, n, out, cap, on, iu); }
static int d_xpress(const u8 *in, size_t n, u8 *out, size_t cap, size_t *on, size_t *iu)
{ *iu = n; return gz_xpress_decode(in, n, out, cap, on); }
static int d_xhuff(const u8 *in, size_t n, u8 *out, size_t cap, size_t *on, size_t *iu)
{ int r = gz_xpress_huff_decode(in, n, out, cap); *on = r ? 0 : cap; *iu = n; return r; }

static dec_fn codec(const char *s)
{
    static const struct { const char *n; dec_fn f; } t[] = {
        { "adc", d_adc }, { "lznt1", d_lznt1 }, { "lzo", d_lzo }, { "lzfse", d_lzfse },
        { "lzvn", d_lzvn }, { "xpress", d_xpress }, { "xhuff", d_xhuff } };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) if (!strcmp(s, t[i].n)) return t[i].f;
    fprintf(stderr, "unknown codec %s\n", s);
    exit(2);
}

static u8 *load(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *p = (u8 *)malloc(sz ? (size_t)sz : 1);
    if (sz && fread(p, 1, (size_t)sz, f) != (size_t)sz) { perror(path); exit(2); }
    fclose(f);
    *n = (size_t)sz;
    return p;
}

/* exact-size copy so that ASan sees the true end of the buffer */
static u8 *dup_exact(const u8 *p, size_t n)
{
    u8 *q = (u8 *)malloc(n);
    if (n) memcpy(q, p, n);
    return q;
}

static void *gz_malloc_exact(size_t n) { return malloc(n); }

static u64 rnd_state;
static u32 rnd(void)
{
    rnd_state = rnd_state * 6364136223846793005ull + 1442695040888963407ull;
    return (u32)(rnd_state >> 33);
}

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static int cmd_d(int argc, char **argv)
{
    if (argc < 6) return 2;
    dec_fn f = codec(argv[2]);
    size_t n, cap = (size_t)strtoull(argv[5], 0, 0), on = 0, iu = 0;
    u8 *raw = load(argv[3], &n), *in = dup_exact(raw, n);
    u8 *out = (u8 *)gz_malloc_exact(cap);
    int r = f(in, n, out, cap, &on, &iu);
    FILE *o = fopen(argv[4], "wb");
    if (o) { fwrite(out, 1, on, o); fclose(o); }
    printf("rc=%d out=%zu used=%zu\n", r, on, iu);
    free(raw); free(in); free(out);
    return 0;
}

static int cmd_batch(int argc, char **argv)
{
    if (argc < 6) return 2;
    dec_fn f = codec(argv[2]);
    size_t n;
    u8 *blob = load(argv[3], &n);
    FILE *j = fopen(argv[4], "r"), *o = fopen(argv[5], "wb");
    if (!j || !o) { perror("batch"); return 2; }
    unsigned long long off, len, olen;
    int bad = 0, cnt = 0;
    while (fscanf(j, "%llu %llu %llu", &off, &len, &olen) == 3) {
        cnt++;
        if (off + len > n) { printf("job %d out of range\n", cnt); bad++; continue; }
        u8 *in = dup_exact(blob + off, (size_t)len), *out = (u8 *)gz_malloc_exact((size_t)olen);
        size_t on = 0, iu = 0;
        int r = f(in, (size_t)len, out, (size_t)olen, &on, &iu);
        if (r || on != olen) { printf("job %d: rc=%d out=%zu/%llu used=%zu/%llu\n", cnt, r, on, olen, iu, len); bad++; }
        fwrite(out, 1, on, o);
        free(in); free(out);
    }
    fclose(j); fclose(o);
    printf("jobs=%d bad=%d\n", cnt, bad);
    free(blob);
    return 0;
}

static void mutate(u8 *p, size_t *n, size_t cap)
{
    size_t len = *n;
    int k = (int)(rnd() % 8);
    if (!len) { k = 6; }
    switch (k) {
    case 0: case 1: {                                   /* flip 1-4 bits */
        int m = 1 + (int)(rnd() % 4);
        for (int i = 0; i < m; i++) p[rnd() % len] ^= (u8)(1u << (rnd() % 8));
        break;
    }
    case 2: p[rnd() % len] = (u8)rnd(); break;          /* random byte */
    case 3: p[rnd() % len] = (u8)((rnd() & 1) ? 0xff : 0); break;
    case 4: *n = rnd() % (len + 1); break;              /* truncate */
    case 5: {                                           /* zero / 0xff a range */
        size_t a = rnd() % len, b = a + rnd() % 64;
        if (b > len) b = len;
        memset(p + a, (rnd() & 1) ? 0xff : 0, b - a);
        break;
    }
    case 6: {                                           /* insert random bytes */
        size_t at = len ? rnd() % (len + 1) : 0, m = 1 + rnd() % 8;
        if (len + m > cap) break;
        memmove(p + at + m, p + at, len - at);
        for (size_t i = 0; i < m; i++) p[at + i] = (u8)rnd();
        *n = len + m;
        break;
    }
    default: {                                          /* copy a range over another */
        size_t a = rnd() % len, b = rnd() % len, m = 1 + rnd() % 32;
        if (a + m > len) m = len - a;
        if (b + m > len) m = len - b;
        memmove(p + b, p + a, m);
        break;
    }
    }
}

static int cmd_fuzz(int argc, char **argv)
{
    if (argc < 7) return 2;
    dec_fn f = codec(argv[2]);
    size_t n, cap = (size_t)strtoull(argv[4], 0, 0);
    long iters = atol(argv[5]);
    rnd_state = strtoull(argv[6], 0, 0) * 2654435761u + 1;
    u8 *orig = load(argv[3], &n);
    u8 *work = (u8 *)malloc(n + 64);
    int hist[GZ_E_COUNT + 1] = { 0 };
    int is_lzfse = !strcmp(argv[2], "lzfse");
    for (long it = 0; it < iters; it++) {
        size_t m = n;
        memcpy(work, orig, n);
        int rounds = 1 + (int)(rnd() % 3);
        for (int k = 0; k < rounds; k++) mutate(work, &m, n + 64);
        u8 *in = dup_exact(work, m);
        /* output capacity: the true size, or a random smaller/larger one */
        size_t oc = cap;
        if ((rnd() % 4) == 0) oc = rnd() % (cap + cap / 2 + 1);
        u8 *out = (u8 *)gz_malloc_exact(oc);
        size_t on = 0, iu = 0;
        int r = f(in, m, out, oc, &on, &iu);
        if (on > oc || iu > m) { printf("FAIL it=%ld: out=%zu/%zu used=%zu/%zu\n", it, on, oc, iu, m); return 1; }
        if (is_lzfse) { u64 rs; size_t su; gz_lzfse_size(in, m, &rs, &su); if (su > m) { printf("FAIL size\n"); return 1; } }
        hist[r >= 0 && r < GZ_E_COUNT ? r : GZ_E_COUNT]++;
        free(in);
        free(out);
    }
    printf("iters=%ld", iters);
    for (int i = 0; i <= GZ_E_COUNT; i++) if (hist[i]) printf(" rc%d=%d", i, hist[i]);
    printf("\n");
    free(orig); free(work);
    return 0;
}

static int cmd_bench(int argc, char **argv)
{
    if (argc < 6) return 2;
    dec_fn f = codec(argv[2]);
    size_t n, cap = (size_t)strtoull(argv[4], 0, 0);
    double ms = atof(argv[5]);
    u8 *in = load(argv[3], &n), *out = (u8 *)gz_malloc_exact(cap);
    size_t on = 0, iu = 0;
    double total = 0, t0 = now_ms(), t;
    long it = 0;
    do {
        int r = f(in, n, out, cap, &on, &iu);
        if (r) { printf("rc=%d\n", r); return 1; }
        total += (double)on;
        it++;
        t = now_ms();
    } while (t - t0 < ms);
    printf("MBps=%.1f iters=%ld out=%zu\n", total / ((t - t0) / 1e3) / 1e6, it, on);
    free(in); free(out);
    return 0;
}

static int cmd_size(int argc, char **argv)
{
    if (argc < 3) return 2;
    size_t n, used = 0;
    u8 *in = load(argv[2], &n);
    u64 rs = 0;
    int r = gz_lzfse_size(in, n, &rs, &used);
    printf("rc=%d size=%llu used=%zu\n", r, (unsigned long long)rs, used);
    free(in);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "d")) return cmd_d(argc, argv);
    if (!strcmp(argv[1], "batch")) return cmd_batch(argc, argv);
    if (!strcmp(argv[1], "fuzz")) return cmd_fuzz(argc, argv);
    if (!strcmp(argv[1], "bench")) return cmd_bench(argc, argv);
    if (!strcmp(argv[1], "size")) return cmd_size(argc, argv);
    return 2;
}
