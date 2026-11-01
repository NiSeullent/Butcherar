/*
 * lzma_test - codec driver for src/codec/lzma.c, bcj.c and bcj2.c
 *
 *   lzma_test dec   [opts] <in> <out> <spec>
 *       spec: "<codec>[+<filter>:<param>]..." in data-flow (decoding) order
 *         codec : alone            .lzma file: 13-byte header (props, u64 size / all FF)
 *                 lzma1:<10 hex>   raw LZMA with these 5 property bytes
 *                 lzma2:<prop>     raw LZMA2 with this dictionary property
 *                 copy             no compression
 *         filter: x86 ppc ia64 arm armt sparc arm64 riscv delta (decoding direction)
 *       prints "rc=<code> used=<compressed bytes consumed> out=<bytes>"
 *   lzma_test filt  [opts] <in> <out> <filter> <param> <enc 0|1>
 *       in-place conversion of the whole file (with -k N: push mode, random pieces)
 *   lzma_test bcj2  [opts] <archive> <out> <out_size> <main> <call> <jump> <rc>
 *       each stream: "<offset>:<size>:<copy|lzma1:<hex>|lzma2:<prop>>:<unpack size>"
 *       (the 7z BCJ2 folder layout: MAIN decoded and pushed, CALL/JUMP/RC in memory)
 *   lzma_test fuzz  [opts] <in> <spec> <iterations> <seed>
 *       mutated / truncated copies of <in> decoded in-process; prints result counts
 *   lzma_test bench [opts] <in> <spec> <repeats>
 *       decode to a null sink, prints MB/s of output
 *
 * opts: -r N  read callback returns at most N bytes (negative: random 1..|N|)
 *       -s N  skip N bytes of the input file      -n N  use only N input bytes
 *       -o N  known output size (overrides the .lzma header; -1 = unknown)
 *       -k N  split every sink write into random pieces of 1..N bytes
 *       -L    GZ_LZMA_LENIENT_END                 -m N  dictionary limit (bytes)
 *       -c N  output cap in bytes (GZ_E_LIMIT beyond, default 1 GiB)
 */
#include "lzma.h"
#include "bcj.h"
#include "bcj2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef LZMA_TEST_STANDALONE
/* built without the core objects (cross / -m32 runs): minimal platform hooks */
void *gz_alloc(size_t n) { return calloc(1, n ? n : 1); }
void *gz_realloc(void *p, size_t n) { return realloc(p, n ? n : 1); }
void gz_free(void *p) { free(p); }
void *gz_alloc_big(size_t n) { return calloc(1, n ? n : 1); }
void gz_free_big(void *p, size_t n) { (void)n; free(p); }
#endif

typedef unsigned long long ull;

/* ---------------- options ---------------- */

static long o_rchunk = 0, o_split = 0;
static long long o_skip = 0, o_len = -1, o_out = -2;     /* -2: not given */
static int o_lenient = 0;
static long long o_limit = 0, o_cap = 1ll << 30;

static u32 g_rng = 12345;
static u32 rnd(void) { g_rng = g_rng * 1103515245u + 12345u; return g_rng >> 8; }

/* ---------------- I/O helpers ---------------- */

static u8 *load(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *p = (u8 *)malloc(sz > 0 ? (size_t)sz : 1);
    if (sz > 0 && fread(p, 1, (size_t)sz, f) != (size_t)sz) { perror(path); exit(2); }
    fclose(f);
    *n = (size_t)sz;
    return p;
}

static void save(const char *path, const u8 *p, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); exit(2); }
    if (n && fwrite(p, 1, n, f) != n) { perror(path); exit(2); }
    fclose(f);
}

typedef struct { u8 *p; size_t n, cap, limit; int null; } t_sink;

static int t_write(void *ctx, const u8 *p, size_t n)
{
    t_sink *s = (t_sink *)ctx;
    if (n > s->limit - s->n) return GZ_E_LIMIT;
    if (s->null) { s->n += n; return GZ_OK; }
    if (s->n + n > s->cap) {
        size_t c = s->cap ? s->cap : 65536;
        while (c < s->n + n) c *= 2;
        u8 *q = (u8 *)realloc(s->p, c);
        if (!q) return GZ_E_NOMEM;
        s->p = q;
        s->cap = c;
    }
    memcpy(s->p + s->n, p, n);
    s->n += n;
    return GZ_OK;
}

static void sink_init(t_sink *s, int null)
{
    memset(s, 0, sizeof *s);
    s->limit = (unsigned long long)o_cap > (size_t)-1 ? (size_t)-1 : (size_t)o_cap;
    s->null = null;
}

/* reader + sink pair behind one gz_stream_io ctx */
typedef struct {
    const u8 *p;
    size_t n;
    long chunk;
    int (*sink)(void *, const u8 *, size_t);
    void *sctx;
} t_io;

static int t_io_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    t_io *r = (t_io *)ctx;
    size_t k = r->n < cap ? r->n : cap;
    if (r->chunk > 0 && k > (size_t)r->chunk) k = (size_t)r->chunk;
    if (r->chunk < 0 && k) {
        size_t m = 1 + rnd() % (size_t)(-r->chunk);
        if (k > m) k = m;
    }
    memcpy(buf, r->p, k);
    r->p += k;
    r->n -= k;
    *got = (u32)k;
    return GZ_OK;
}

static int t_io_write(void *ctx, const u8 *p, size_t n)
{
    t_io *r = (t_io *)ctx;
    return r->sink(r->sctx, p, n);
}

/* splits writes into random pieces (exercises filter carry handling) */
typedef struct { int (*next)(void *, const u8 *, size_t); void *ctx; size_t max; } t_split;

static int t_split_write(void *ctx, const u8 *p, size_t n)
{
    t_split *s = (t_split *)ctx;
    while (n) {
        size_t k = 1 + rnd() % s->max;
        if (k > n) k = n;
        int r = s->next(s->ctx, p, k);
        if (r) return r;
        p += k;
        n -= k;
    }
    return GZ_OK;
}

/* ---------------- spec parsing ---------------- */

enum { C_ALONE, C_LZMA1, C_LZMA2, C_COPY };

typedef struct {
    int codec;
    u8 props[5];
    u8 dprop;
    int nf;
    int ftype[8];
    u32 fparam[8];
} t_spec;

static int filter_type(const char *s)
{
    static const char *names[] = { "", "x86", "ppc", "ia64", "arm", "armt", "sparc", "arm64",
                                   "riscv", "delta" };
    for (int i = 1; i < GZ_BCJ_COUNT; i++)
        if (!strcmp(s, names[i])) return i;
    fprintf(stderr, "unknown filter %s\n", s);
    exit(2);
}

static void hex5(const char *h, u8 *out)
{
    if (strlen(h) < 10) { fprintf(stderr, "props need 10 hex digits\n"); exit(2); }
    for (int i = 0; i < 5; i++) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1) exit(2);
        out[i] = (u8)v;
    }
}

/* codec part only ("alone", "copy", "lzma1:hex", "lzma2:prop") */
static void parse_codec(const char *tok, t_spec *t)
{
    if (!strcmp(tok, "alone")) t->codec = C_ALONE;
    else if (!strcmp(tok, "copy")) t->codec = C_COPY;
    else if (!strncmp(tok, "lzma1:", 6)) { t->codec = C_LZMA1; hex5(tok + 6, t->props); }
    else if (!strncmp(tok, "lzma2:", 6)) { t->codec = C_LZMA2; t->dprop = (u8)atoi(tok + 6); }
    else { fprintf(stderr, "bad codec %s\n", tok); exit(2); }
}

static void parse_spec(const char *spec, t_spec *t)
{
    char buf[512];
    snprintf(buf, sizeof buf, "%s", spec);
    memset(t, 0, sizeof *t);
    char *sp = 0;
    char *tok = strtok_r(buf, "+", &sp);
    if (!tok) exit(2);
    parse_codec(tok, t);
    while ((tok = strtok_r(0, "+", &sp))) {
        char *c = strchr(tok, ':');
        u32 param = 0;
        if (c) { *c = 0; param = (u32)strtoul(c + 1, 0, 0); }
        if (t->nf == 8) exit(2);
        t->ftype[t->nf] = filter_type(tok);
        t->fparam[t->nf++] = param;
    }
}

/* ---------------- decoding pipeline ---------------- */

/* Decode in[0..n) with the codec of t into sink. *used: compressed bytes consumed
 * (including a .lzma header). */
static int run_codec(gz_lzma_dec *d, const t_spec *t, const u8 *in, size_t n,
                     int (*sink)(void *, const u8 *, size_t), void *sctx, ull *used)
{
    t_io io_ctx = { in, n, o_rchunk, sink, sctx };
    gz_stream_io io = { t_io_read, t_io_write, &io_ctx };
    *used = 0;
    if (t->codec == C_COPY) {
        *used = n;
        return n ? sink(sctx, in, n) : GZ_OK;
    }
    u8 props[5];
    u64 out_size = GZ_SIZE_UNKNOWN;
    ull hdr = 0;
    if (t->codec == C_ALONE) {
        if (n < 13) return GZ_E_TRUNC;
        memcpy(props, in, 5);
        out_size = rd64(in + 5);            /* all FF = unknown */
        io_ctx.p += 13;
        io_ctx.n -= 13;
        hdr = 13;
    } else {
        memcpy(props, t->props, 5);
    }
    if (o_out >= 0) out_size = (u64)o_out;
    if (o_out == -1) out_size = GZ_SIZE_UNKNOWN;
    u64 u = 0;
    int r = t->codec == C_LZMA2 ? gz_lzma2_decode(d, t->dprop, &io, out_size, &u)
                                : gz_lzma_decode(d, props, &io, out_size, &u);
    *used = u + hdr;
    return r;
}

typedef struct {
    gz_filter_push fp[8];
    t_split sp[9];
} t_chain;

/* codec -> [split] -> filter0 -> [split] -> filter1 ... -> out */
static int run_spec(gz_lzma_dec *d, const t_spec *t, t_chain *ch, const u8 *in, size_t n,
                    t_sink *out, ull *used)
{
    int (*fn)(void *, const u8 *, size_t) = t_write;
    void *ctx = out;
    for (int i = t->nf; i >= 0; i--) {
        if (o_split > 0) {
            ch->sp[i].next = fn;
            ch->sp[i].ctx = ctx;
            ch->sp[i].max = (size_t)o_split;
            fn = t_split_write;
            ctx = &ch->sp[i];
        }
        if (i == 0) break;
        gz_filter_push_init(&ch->fp[i - 1], t->ftype[i - 1], t->fparam[i - 1], 0, fn, ctx);
        fn = gz_filter_push_write;
        ctx = &ch->fp[i - 1];
    }
    int r = run_codec(d, t, in, n, fn, ctx, used);
    for (int i = 0; i < t->nf && !r; i++) r = gz_filter_push_finish(&ch->fp[i]);
    return r;
}

static gz_lzma_dec *new_dec(void)
{
    gz_lzma_dec *d = gz_lzma_dec_new();
    if (!d) exit(3);
    if (o_limit) gz_lzma_dec_set_limit(d, (u64)o_limit);
    if (o_lenient) gz_lzma_dec_set_flags(d, GZ_LZMA_LENIENT_END);
    return d;
}

static const u8 *input_window(const u8 *p, size_t n, size_t *wn)
{
    size_t skip = (size_t)o_skip > n ? n : (size_t)o_skip;
    size_t len = n - skip;
    if (o_len >= 0 && (size_t)o_len < len) len = (size_t)o_len;
    *wn = len;
    return p + skip;
}

/* ---------------- commands ---------------- */

static int cmd_dec(int argc, char **argv)
{
    if (argc < 3) return 2;
    size_t n, wn;
    u8 *data = load(argv[0], &n);
    const u8 *in = input_window(data, n, &wn);
    t_spec t;
    parse_spec(argv[2], &t);
    gz_lzma_dec *d = new_dec();
    t_chain *ch = (t_chain *)calloc(1, sizeof(t_chain));
    t_sink out;
    sink_init(&out, 0);
    ull used = 0;
    int r = run_spec(d, &t, ch, in, wn, &out, &used);
    save(argv[1], out.p, out.n);
    printf("rc=%d used=%llu out=%llu\n", r, used, (ull)out.n);
    gz_lzma_dec_free(d);
    free(ch);
    free(out.p);
    free(data);
    return 0;
}

static int cmd_filt(int argc, char **argv)
{
    if (argc < 5) return 2;
    size_t n;
    u8 *data = load(argv[0], &n);
    int type = filter_type(argv[2]);
    u32 param = (u32)strtoul(argv[3], 0, 0);
    int enc = atoi(argv[4]);
    if (o_split > 0) {
        gz_filter_push *fp = (gz_filter_push *)calloc(1, sizeof *fp);
        t_sink out;
        sink_init(&out, 0);
        gz_filter_push_init(fp, type, param, enc, t_write, &out);
        size_t i = 0;
        int r = 0;
        while (i < n && !r) {
            size_t k = 1 + rnd() % (size_t)o_split;
            if (k > n - i) k = n - i;
            r = gz_filter_push_write(fp, data + i, k);
            i += k;
        }
        if (!r) r = gz_filter_push_finish(fp);
        save(argv[1], out.p, out.n);
        printf("rc=%d out=%llu\n", r, (ull)out.n);
        free(out.p);
        free(fp);
    } else {
        gz_bcj f;
        gz_bcj_init(&f, type, param, enc);
        size_t done = gz_bcj_code(&f, data, n);
        save(argv[1], data, n);
        printf("rc=0 done=%llu out=%llu\n", (ull)done, (ull)n);
    }
    free(data);
    return 0;
}

typedef struct { ull off, size, usize; t_spec t; } t_stream;

static void parse_stream(const char *s, t_stream *st)
{
    char buf[256];
    snprintf(buf, sizeof buf, "%s", s);
    memset(st, 0, sizeof *st);
    char *p = buf;
    st->off = strtoull(p, &p, 0);
    if (*p++ != ':') exit(2);
    st->size = strtoull(p, &p, 0);
    if (*p++ != ':') exit(2);
    char *last = strrchr(p, ':');
    if (!last) exit(2);
    *last = 0;
    st->usize = strtoull(last + 1, 0, 0);
    parse_codec(p, &st->t);
}

static int cmd_bcj2(int argc, char **argv)
{
    if (argc < 7) return 2;
    size_t n;
    u8 *arc = load(argv[0], &n);
    ull out_size = strtoull(argv[2], 0, 0);
    t_stream st[4];
    for (int i = 0; i < 4; i++) {
        parse_stream(argv[3 + i], &st[i]);
        if (st[i].off > n || st[i].size > n - st[i].off) { fprintf(stderr, "bad range\n"); return 2; }
    }
    gz_lzma_dec *d = new_dec();
    /* CALL, JUMP, RC into memory */
    t_sink mem[3];
    int r = 0;
    o_out = -2;
    for (int i = 0; i < 3; i++) sink_init(&mem[i], 0);
    for (int i = 0; i < 3 && !r; i++) {
        ull used;
        o_out = (long long)st[i + 1].usize;
        r = run_codec(d, &st[i + 1].t, arc + st[i + 1].off, (size_t)st[i + 1].size, t_write, &mem[i], &used);
        if (!r && mem[i].n != st[i + 1].usize) r = GZ_E_DATA;
    }
    t_sink out;
    sink_init(&out, 0);
    if (!r) {
        gz_bcj2_mem m[3];
        gz_stream_io io[3];
        for (int i = 0; i < 3; i++) {
            m[i].p = mem[i].p;
            m[i].n = mem[i].n;
            io[i].read = gz_bcj2_mem_read;
            io[i].write = 0;
            io[i].ctx = &m[i];
        }
        gz_bcj2_dec *b = gz_bcj2_dec_new();
        gz_bcj2_dec_init(b, &io[0], &io[1], &io[2], out_size, t_write, &out);
        ull used;
        o_out = (long long)st[0].usize;
        r = run_codec(d, &st[0].t, arc + st[0].off, (size_t)st[0].size, gz_bcj2_dec_write, b, &used);
        if (!r) r = gz_bcj2_dec_finish(b);
        gz_bcj2_dec_free(b);
    }
    save(argv[1], out.p, out.n);
    printf("rc=%d out=%llu\n", r, (ull)out.n);
    for (int i = 0; i < 3; i++) free(mem[i].p);
    free(out.p);
    gz_lzma_dec_free(d);
    free(arc);
    return 0;
}

static int cmd_fuzz(int argc, char **argv)
{
    if (argc < 4) return 2;
    size_t n;
    u8 *data = load(argv[0], &n);
    t_spec t;
    parse_spec(argv[1], &t);
    long iters = atol(argv[2]);
    g_rng = (u32)strtoul(argv[3], 0, 0);
    gz_lzma_dec *d = new_dec();
    t_chain *ch = (t_chain *)calloc(1, sizeof(t_chain));
    u8 *buf = (u8 *)malloc(n + 64);
    long counts[GZ_E_COUNT + 1] = { 0 };
    for (long it = 0; it < iters; it++) {
        size_t m = n;
        memcpy(buf, data, n);
        u32 kind = rnd() % 8;
        if (kind == 0 && n) {
            m = rnd() % n;                              /* truncation */
        } else if (kind == 1 && n) {
            buf[rnd() % n] = (u8)rnd();                 /* one random byte */
        } else if (kind == 2 && n > 16) {               /* zero a run */
            size_t a = rnd() % n, l = 1 + rnd() % 16;
            if (a + l > n) l = n - a;
            memset(buf + a, 0, l);
        } else if (n) {                                 /* 1..8 bit flips, header-heavy */
            int flips = 1 + rnd() % 8;
            for (int k = 0; k < flips; k++) {
                size_t at = (rnd() & 1) ? rnd() % (n < 64 ? n : 64) : rnd() % n;
                buf[at] ^= (u8)(1u << (rnd() % 8));
            }
        }
        t_sink out;
        sink_init(&out, 1);
        long long save_out = o_out;
        if (rnd() % 4 == 0) o_out = (long long)(rnd() % (4u << 20));   /* wrong known size */
        o_rchunk = (rnd() % 3 == 0) ? -(long)(1 + rnd() % 300) : 0;
        long long o_out_used = o_out;
        ull used;
        int r = run_spec(d, &t, ch, buf, m, &out, &used);
        o_out = save_out;
        if (used > m) {
            fprintf(stderr, "used %llu > input %llu (iteration %ld, out %lld, rchunk %ld, rc %d): "
                    "input saved to fuzz_fail.bin\n", used, (ull)m, it, o_out_used, o_rchunk, r);
            save("fuzz_fail.bin", buf, m);
            return 1;
        }
        counts[r >= 0 && r < GZ_E_COUNT ? r : GZ_E_COUNT]++;
    }
    printf("rc=0");
    for (int i = 0; i <= GZ_E_COUNT; i++)
        if (counts[i]) printf(" e%d=%ld", i, counts[i]);
    printf("\n");
    gz_lzma_dec_free(d);
    free(ch);
    free(buf);
    free(data);
    return 0;
}

/* process CPU time: stable on a loaded machine (single-threaded decoder) */
static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static int cmd_bench(int argc, char **argv)
{
    if (argc < 3) return 2;
    size_t n;
    u8 *data = load(argv[0], &n);
    t_spec t;
    parse_spec(argv[1], &t);
    int reps = atoi(argv[2]);
    gz_lzma_dec *d = new_dec();
    t_chain *ch = (t_chain *)calloc(1, sizeof(t_chain));
    double best = 1e30;
    ull outn = 0;
    int r = 0;
    o_cap = 1ll << 62;
    for (int i = 0; i < reps; i++) {
        t_sink out;
        sink_init(&out, 1);
        ull used;
        double t0 = now_s();
        r = run_spec(d, &t, ch, data, n, &out, &used);
        double dt = now_s() - t0;
        if (dt < best) best = dt;
        outn = out.n;
        if (r) break;
    }
    printf("rc=%d out=%llu best=%.3fs %.1f MB/s\n", r, outn, best, outn / best / 1e6);
    gz_lzma_dec_free(d);
    free(ch);
    free(data);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    const char *cmd = argv[1];
    int i = 2;
    while (i < argc && argv[i][0] == '-' && argv[i][1] && !argv[i][2]) {
        char o = argv[i][1];
        if (o == 'L') { o_lenient = 1; i++; continue; }
        if (i + 1 >= argc) return 2;
        long long v = strtoll(argv[i + 1], 0, 0);
        switch (o) {
        case 'r': o_rchunk = (long)v; break;
        case 's': o_skip = v; break;
        case 'n': o_len = v; break;
        case 'o': o_out = v; break;
        case 'k': o_split = (long)v; break;
        case 'm': o_limit = v; break;
        case 'c': o_cap = v; break;
        default: return 2;
        }
        i += 2;
    }
    argc -= i;
    argv += i;
    if (!strcmp(cmd, "dec")) return cmd_dec(argc, argv);
    if (!strcmp(cmd, "filt")) return cmd_filt(argc, argv);
    if (!strcmp(cmd, "bcj2")) return cmd_bcj2(argc, argv);
    if (!strcmp(cmd, "fuzz")) return cmd_fuzz(argc, argv);
    if (!strcmp(cmd, "bench")) return cmd_bench(argc, argv);
    return 2;
}
