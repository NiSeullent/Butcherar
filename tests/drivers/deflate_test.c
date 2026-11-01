/*
 * deflate_test - driver for the Deflate encoder (src/codec/deflate_enc.c)
 *
 *   deflate_test enc LEVEL IN OUT [chunk]   compress IN to raw Deflate OUT, verify with our
 *                                          inflater; prints "crc in out ms kernel"
 *   deflate_test bench LEVELS IN [secs]     compression speed/size per level (e.g. 0123456789)
 *   deflate_test fuzz SEED COUNT [maxsize]  random data shapes, sizes and read chunking:
 *                                          encode + decode + compare, every level
 *   deflate_test errors                     read/write error propagation, misbehaving reader
 *   deflate_test stream LEVEL MBYTES        generated input never held in memory; decoded
 *                                          output checked by CRC and length
 *   deflate_test reuse                      one encoder, many streams of varied sizes
 * Environment: GZ_TIER=n forces a dispatch tier (kernel selection).
 */
#include "deflate_enc.h"
#include "inflate.h"
#include "crc32.h"
#include "cpu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static u64 g_rng = 88172645463325252ull;
static u32 rnd(void)
{
    g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17;
    return (u32)(g_rng >> 11);
}

/* ---- memory reader / writer ---- */

typedef struct {
    const u8 *src; size_t n, pos;
    u32 chunk;                 /* 0: give what is asked; else random 1..chunk */
    int read_err_at;           /* -1 none, else fail when pos >= this */
    u8 *dst; size_t dn, dcap;
    size_t write_limit;        /* 0 none: else GZ_E_CANCEL once exceeded */
    int overfill;              /* reader claims more than cap */
} mio;

static int m_read(void *c, u8 *buf, u32 cap, u32 *got)
{
    mio *m = (mio *)c;
    *got = 0;
    if (m->read_err_at >= 0 && m->pos >= (size_t)m->read_err_at) return GZ_E_IO;
    size_t n = m->n - m->pos;
    if (n > cap) n = cap;
    if (m->chunk && n > 1) n = 1 + rnd() % (n < m->chunk ? n : m->chunk);
    memcpy(buf, m->src + m->pos, n);
    m->pos += n;
    *got = (u32)n;
    if (m->overfill && n) *got = cap + 1;
    return 0;
}

static int m_write(void *c, const u8 *p, size_t n)
{
    mio *m = (mio *)c;
    if (m->write_limit && m->dn + n > m->write_limit) return GZ_E_CANCEL;
    if (m->dn + n > m->dcap) {
        size_t nc = m->dcap ? m->dcap * 2 : 1 << 16;
        while (nc < m->dn + n) nc *= 2;
        m->dst = realloc(m->dst, nc);
        if (!m->dst) { fprintf(stderr, "oom\n"); exit(3); }
        m->dcap = nc;
    }
    memcpy(m->dst + m->dn, p, n);
    m->dn += n;
    return 0;
}

static int encode(gz_deflate_enc *e, const u8 *in, size_t n, u32 chunk, u8 **out, size_t *outn, u32 *crc)
{
    mio m = { in, n, 0, chunk, -1, 0, 0, 0, 0, 0 };
    gz_stream_io io = { m_read, m_write, &m };
    u64 ni = 0, no = 0;
    int r = gz_deflate_encode(e, &io, crc, &ni, &no);
    if (!r && (ni != n || no != m.dn)) { fprintf(stderr, "size accounting mismatch\n"); r = 99; }
    *out = m.dst;
    *outn = m.dn;
    return r;
}

/* decode with our inflater; 0 = identical */
static gz_inflater *g_inf;
static int verify(const u8 *comp, size_t cn, const u8 *orig, size_t n, u32 crc, u32 chunk)
{
    if (!g_inf) g_inf = gz_inflater_new();
    mio m = { comp, cn, 0, chunk, -1, 0, 0, 0, 0, 0 };
    gz_stream_io io = { m_read, m_write, &m };
    int r = gz_inflate_run(g_inf, &io, 0);
    int bad = 0;
    if (r) { fprintf(stderr, "inflate error %d\n", r); bad = 1; }
    else if (m.dn != n || (n && memcmp(m.dst, orig, n))) { fprintf(stderr, "data mismatch (%zu vs %zu)\n", m.dn, n); bad = 1; }
    else if (g_inf->crc != crc || crc != gz_crc32(0, orig, n)) { fprintf(stderr, "crc mismatch\n"); bad = 1; }
    else if (m.pos - g_inf->rest_len != cn) { fprintf(stderr, "stream length mismatch\n"); bad = 1; }
    free(m.dst);
    return bad;
}

static u8 *read_file(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *p = malloc(sz ? sz : 1);
    if ((long)fread(p, 1, sz, f) != sz) { perror("read"); exit(2); }
    fclose(f);
    *n = (size_t)sz;
    return p;
}

static void init(void)
{
    const char *t = getenv("GZ_TIER");
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_dispatch_init(t ? atoi(t) : -1);
}

/* ---- data shapes for fuzzing ---- */

static void gen(u8 *p, size_t n, int kind)
{
    static const char *words[] = { "the ", "of ", "and ", "deflate ", "고기 ", "삼겹살 ", "zip ",
                                   "archive ", "\n", "compression ", "목살 ", "{ ", "} ", "return ", ";\n" };
    size_t i = 0;
    switch (kind) {
    case 0: for (; i < n; i++) p[i] = (u8)rnd(); break;                 /* random */
    case 1: memset(p, 0, n); break;                                      /* zeros */
    case 2: for (; i < n; i++) p[i] = (u8)(rnd() % 4 + 'A'); break;      /* tiny alphabet */
    case 3:                                                              /* text */
        while (i < n) {
            const char *w = words[rnd() % 15];
            size_t l = strlen(w);
            if (l > n - i) l = n - i;
            memcpy(p + i, w, l);
            i += l;
        }
        break;
    case 4:                                                              /* long repeats */
        for (; i < n; i++) p[i] = (u8)(i < 300 ? rnd() : (rnd() % 64 ? p[i - 1 - (rnd() % 3 ? 0 : rnd() % 280)] : (u8)rnd()));
        break;
    case 5:                                                              /* period-N runs */
        { u32 per = 1 + rnd() % 300; for (; i < n; i++) p[i] = i < per ? (u8)rnd() : p[i - per]; }
        break;
    case 6:                                                              /* far matches (~32K) */
        for (; i < n; i++) {
            if (i >= 32768 && rnd() % 8) p[i] = p[i - 32768 + (rnd() % 3)];
            else p[i] = (u8)rnd();
        }
        break;
    default:                                                             /* mixed segments */
        while (i < n) {
            size_t l = 1 + rnd() % 20000;
            if (l > n - i) l = n - i;
            gen(p + i, l, rnd() % 7);
            i += l;
        }
        break;
    }
}

static int cmd_fuzz(u32 seed, int count, size_t maxsize)
{
    gz_deflate_enc *enc[10];
    for (int l = 0; l < 10; l++) enc[l] = gz_deflate_enc_new(l);
    g_rng ^= (u64)seed * 0x9E3779B97F4A7C15ull;
    int fails = 0;
    u8 *buf = malloc(maxsize + 1);
    for (int it = 0; it < count; it++) {
        size_t n;
        u32 sel = rnd() % 10;
        if (sel < 3) n = rnd() % 64;
        else if (sel < 6) n = rnd() % 70000;
        else n = rnd() % (maxsize + 1);
        int kind = rnd() % 8;
        gen(buf, n, kind);
        int level = it % 10;
        u32 chunk = rnd() % 3 ? 0 : 1 + rnd() % 70000;
        u8 *c; size_t cn; u32 crc;
        int r = encode(enc[level], buf, n, chunk, &c, &cn, &crc);
        if (r || verify(c, cn, buf, n, crc, rnd() % 2 ? 0 : 1 + rnd() % 5000)) {
            fprintf(stderr, "FAIL it=%d level=%d n=%zu kind=%d chunk=%u r=%d\n", it, level, n, kind, chunk, r);
            fails++;
        }
        free(c);
    }
    for (int l = 0; l < 10; l++) gz_deflate_enc_free(enc[l]);
    free(buf);
    printf("fuzz: %d/%d failed\n", fails, count);
    return fails != 0;
}

static int cmd_errors(void)
{
    int fails = 0;
    size_t n = 3 << 20;
    u8 *buf = malloc(n);
    gen(buf, n, 7);
    for (int l = 0; l < 10; l++) {
        gz_deflate_enc *e = gz_deflate_enc_new(l);
        /* read error mid-stream */
        mio m = { buf, n, 0, 0, 1 << 20, 0, 0, 0, 0, 0 };
        gz_stream_io io = { m_read, m_write, &m };
        int r = gz_deflate_encode(e, &io, 0, 0, 0);
        if (r != GZ_E_IO) { fprintf(stderr, "L%d read error not propagated (%d)\n", l, r); fails++; }
        free(m.dst);
        /* writer cancels */
        mio m2 = { buf, n, 0, 0, -1, 0, 0, 0, 1000, 0 };
        io.ctx = &m2;
        r = gz_deflate_encode(e, &io, 0, 0, 0);
        if (r != GZ_E_CANCEL) { fprintf(stderr, "L%d cancel not propagated (%d)\n", l, r); fails++; }
        free(m2.dst);
        /* reader claims more than it was asked for */
        mio m3 = { buf, n, 0, 0, -1, 0, 0, 0, 0, 1 };
        io.ctx = &m3;
        r = gz_deflate_encode(e, &io, 0, 0, 0);
        if (r != GZ_E_IO) { fprintf(stderr, "L%d overfill not caught (%d)\n", l, r); fails++; }
        free(m3.dst);
        /* still usable afterwards */
        u8 *c; size_t cn; u32 crc;
        r = encode(e, buf, n, 0, &c, &cn, &crc);
        if (r || verify(c, cn, buf, n, crc, 0)) { fprintf(stderr, "L%d reuse after error failed\n", l); fails++; }
        free(c);
        gz_deflate_enc_free(e);
    }
    free(buf);
    printf("errors: %d failed\n", fails);
    return fails != 0;
}

/* generated input stream: text-like with long-range repeats, never fully in memory */
typedef struct { u64 left, total; u8 hist[65536]; u32 hpos; } genr;
static int g_read(void *c, u8 *buf, u32 cap, u32 *got)
{
    genr *g = (genr *)c;
    u32 n = cap > 100000 ? 100000 : cap;
    if (n > g->left) n = (u32)g->left;
    for (u32 i = 0; i < n; i++) {
        u32 r = rnd();
        u8 b;
        if ((r & 7) < 5 && g->total > 70000) b = g->hist[(g->hpos - 1 - ((r >> 8) % 40000)) & 65535];
        else b = (u8)("etaoinshrdlu \n"[(r >> 3) % 14]);
        if ((r & 0xff00) == 0) b = (u8)(r >> 16);
        buf[i] = b;
        g->hist[g->hpos++ & 65535] = b;
        g->total++;
    }
    g->left -= n;
    *got = n;
    return 0;
}
/* generator + collected output share the one io ctx */
typedef struct { genr gen; mio out; } pair;
static int pr_read(void *c, u8 *buf, u32 cap, u32 *got) { return g_read(&((pair *)c)->gen, buf, cap, got); }
static int pr_write(void *c, const u8 *p, size_t n) { return m_write(&((pair *)c)->out, p, n); }

typedef struct { const u8 *src; size_t n, pos; u32 crc; u64 total; } crcsink;
static int k_read(void *c, u8 *buf, u32 cap, u32 *got)
{
    crcsink *k = (crcsink *)c;
    size_t n = k->n - k->pos;
    if (n > cap) n = cap;
    memcpy(buf, k->src + k->pos, n);
    k->pos += n;
    *got = (u32)n;
    return 0;
}
static int k_write(void *c, const u8 *p, size_t n)
{
    crcsink *k = (crcsink *)c;
    k->crc = gz_crc32(k->crc, p, n);
    k->total += n;
    return 0;
}

static int cmd_stream(int level, u64 mbytes)
{
    pair *pr = calloc(1, sizeof(pair));
    pr->gen.left = mbytes << 20;
    pr->out.read_err_at = -1;
    gz_stream_io io = { pr_read, pr_write, pr };
    gz_deflate_enc *e = gz_deflate_enc_new(level);
    u32 crc = 0;
    u64 ni = 0, no = 0;
    double t0 = now();
    int r = gz_deflate_encode(e, &io, &crc, &ni, &no);
    double t1 = now();
    if (r || ni != (mbytes << 20) || no != pr->out.dn) { fprintf(stderr, "stream encode failed %d\n", r); return 1; }
    crcsink k = { pr->out.dst, pr->out.dn, 0, 0, 0 };
    gz_stream_io dio = { k_read, k_write, &k };
    gz_inflater *z = gz_inflater_new();
    r = gz_inflate_run(z, &dio, 0);
    int bad = r || k.total != ni || k.crc != crc;
    printf("stream L%d: %llu -> %llu bytes, %.1f MB/s, %s\n", level, (unsigned long long)ni,
           (unsigned long long)no, ni / 1e6 / (t1 - t0), bad ? "MISMATCH" : "ok");
    gz_inflater_free(z);
    gz_deflate_enc_free(e);
    free(pr->out.dst);
    free(pr);
    return bad;
}

static int cmd_reuse(void)
{
    int fails = 0;
    size_t maxn = 900000;
    u8 *buf = malloc(maxn);
    for (int l = 0; l < 10; l++) {
        gz_deflate_enc *e = gz_deflate_enc_new(l);
        for (int it = 0; it < 30; it++) {
            size_t n = it % 3 == 0 ? rnd() % 100 : rnd() % maxn;
            gen(buf, n, rnd() % 8);
            u8 *c; size_t cn; u32 crc;
            int r = encode(e, buf, n, 0, &c, &cn, &crc);
            /* same input on a fresh encoder must give identical output (no state leaks) */
            gz_deflate_enc *f = gz_deflate_enc_new(l);
            u8 *c2; size_t cn2; u32 crc2;
            int r2 = encode(f, buf, n, 0, &c2, &cn2, &crc2);
            if (r || r2 || verify(c, cn, buf, n, crc, 0) || cn != cn2 || memcmp(c, c2, cn)) {
                fprintf(stderr, "reuse L%d it %d n=%zu failed\n", l, it, n);
                fails++;
            }
            gz_deflate_enc_free(f);
            free(c);
            free(c2);
        }
        gz_deflate_enc_free(e);
    }
    free(buf);
    printf("reuse: %d failed\n", fails);
    return fails != 0;
}

int main(int argc, char **argv)
{
    init();
    if (argc < 2) { fprintf(stderr, "usage: see source\n"); return 2; }
    if (!strcmp(argv[1], "enc") && argc >= 5) {
        int level = atoi(argv[2]);
        size_t n;
        u8 *in = read_file(argv[3], &n);
        u32 chunk = argc > 5 ? (u32)atoi(argv[5]) : 0;
        gz_deflate_enc *e = gz_deflate_enc_new(level);
        if (!e) { fprintf(stderr, "alloc failed\n"); return 3; }
        u8 *c; size_t cn; u32 crc;
        double t0 = now();
        int r = encode(e, in, n, chunk, &c, &cn, &crc);
        double t1 = now();
        if (r) { fprintf(stderr, "encode error %d\n", r); return 1; }
        FILE *f = fopen(argv[4], "wb");
        if (!f || fwrite(c, 1, cn, f) != cn) { perror(argv[4]); return 2; }
        fclose(f);
        int bad = verify(c, cn, in, n, crc, 0);
        printf("%08x %zu %zu %.3f %s\n", crc, n, cn, (t1 - t0) * 1000, gz_deflate_enc_kernel(e));
        gz_deflate_enc_free(e);
        gz_inflater_free(g_inf);
        free(c);
        free(in);
        return bad;
    }
    if (!strcmp(argv[1], "bench") && argc >= 4) {
        size_t n;
        u8 *in = read_file(argv[3], &n);
        double secs = argc > 4 ? atof(argv[4]) : 0.5;
        for (const char *lv = argv[2]; *lv; lv++) {
            int level = *lv - '0';
            gz_deflate_enc *e = gz_deflate_enc_new(level);
            u8 *c = 0; size_t cn = 0; u32 crc;
            double best = 1e30, total = 0;
            int reps = 0;
            while (total < secs || reps < 2) {
                free(c);
                double t0 = now();
                encode(e, in, n, 0, &c, &cn, &crc);
                double dt = now() - t0;
                if (dt < best) best = dt;
                total += dt;
                reps++;
            }
            int bad = verify(c, cn, in, n, crc, 0);
            printf("%d %zu %zu %.2f %s\n", level, n, cn, n / 1e6 / best, bad ? "BAD" : "ok");
            free(c);
            gz_deflate_enc_free(e);
            if (bad) return 1;
        }
        gz_inflater_free(g_inf);
        free(in);
        return 0;
    }
    int rc = 2;
    if (!strcmp(argv[1], "fuzz") && argc >= 4)
        rc = cmd_fuzz((u32)atoi(argv[2]), atoi(argv[3]), argc > 4 ? (size_t)atol(argv[4]) : 2000000);
    else if (!strcmp(argv[1], "errors")) rc = cmd_errors();
    else if (!strcmp(argv[1], "stream") && argc >= 4) rc = cmd_stream(atoi(argv[2]), (u64)atoll(argv[3]));
    else if (!strcmp(argv[1], "reuse")) rc = cmd_reuse();
    else fprintf(stderr, "bad command\n");
    gz_inflater_free(g_inf);
    return rc;
}
