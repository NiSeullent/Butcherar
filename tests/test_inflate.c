/*
 * Native (Linux) test-bench for the 고깃ZIP core decoder.
 *   - compares every SIMD kernel against zlib on many data shapes
 *   - random read-chunk sizes to stress the refill logic
 *   - corrupt / truncated streams must fail cleanly (run under ASan)
 *   - decodes raw Deflate64 streams given on the command line
 */
#include "../src/core/inflate.h"
#include "../src/core/crc32.h"
#include "../src/core/cpu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zlib.h>

void *gz_alloc(size_t n) { return calloc(1, n); }
void *gz_realloc(void *p, size_t n) { return realloc(p, n); }
void gz_free(void *p) { free(p); }
void *gz_alloc_big(size_t n) { return calloc(1, n); }
void gz_free_big(void *p, size_t n) { (void)n; free(p); }

typedef struct {
    const u8 *src; size_t src_len, pos;
    int chunky;
    u8 *dst; size_t dst_cap, dst_len;
} mem_io;

static int m_read(void *c, u8 *buf, u32 cap, u32 *got)
{
    mem_io *m = c;
    size_t n = m->src_len - m->pos;
    if (n > cap) n = cap;
    if (m->chunky && n > 1) n = 1 + (size_t)rand() % (n < 3000 ? n : 3000);
    memcpy(buf, m->src + m->pos, n);
    m->pos += n;
    *got = (u32)n;
    return 0;
}
static int m_write(void *c, const u8 *buf, size_t n)
{
    mem_io *m = c;
    if (m->dst_len + n > m->dst_cap) return GZ_E_DATA;   /* overflow = bug */
    memcpy(m->dst + m->dst_len, buf, n);
    m->dst_len += n;
    return 0;
}

static u8 *deflate_raw(const u8 *src, size_t n, int level, int strat, size_t *outn)
{
    z_stream s; memset(&s, 0, sizeof s);
    deflateInit2(&s, level, Z_DEFLATED, -15, 9, strat);
    size_t cap = deflateBound(&s, n) + 64;
    u8 *o = malloc(cap);
    s.next_in = (u8 *)src; s.avail_in = (uInt)n; s.next_out = o; s.avail_out = (uInt)cap;
    deflate(&s, Z_FINISH);
    *outn = s.total_out;
    deflateEnd(&s);
    return o;
}

static gz_inflate_fn kernels[] = { gz_inflate_x86, gz_inflate_mmx, gz_inflate_sse,
                                   gz_inflate_sse2, gz_inflate_avx, gz_inflate_avx2 };
static const char *knames[] = { "x86", "mmx", "sse", "sse2", "avx", "avx2" };
static int nkern = 6;

static void gen(u8 *b, size_t n, int kind)
{
    size_t i;
    switch (kind) {
    case 0: for (i = 0; i < n; i++) b[i] = (u8)rand(); break;                     /* random */
    case 1: memset(b, 'A', n); break;                                              /* run */
    case 2: for (i = 0; i < n; i++) b[i] = "the quick brown fox "[i % 20]; break;  /* period 20 */
    case 3: for (i = 0; i < n; i++) b[i] = (u8)(rand() % 4 + 'a'); break;          /* low entropy */
    case 4: for (i = 0; i < n; i++) b[i] = (i % 1000 < 500) ? (u8)rand() : b[i > 3000 ? i - 3000 : 0]; break;
    default: /* text-ish with long matches & short distances */
        for (i = 0; i < n; i++) {
            int r = rand() % 100;
            if (i > 40000 && r < 30) { size_t d = 1 + rand() % 40000, l = 3 + rand() % 300;
                while (l-- && i < n) { b[i] = b[i - d]; i++; } i--; }
            else if (i > 3 && r < 40) b[i] = b[i - 1 - rand() % 3];
            else b[i] = (u8)(" etaoinshrdlu\n"[rand() % 14]);
        }
    }
}

static int check(const u8 *orig, size_t n, const u8 *comp, size_t cn, int chunky, int d64, const char *what)
{
    int bad = 0;
    gz_inflater *z = gz_inflater_new();
    for (int k = 0; k < nkern; k++) {
        mem_io m = { comp, cn, 0, chunky, malloc(n + 1), n + 1, 0 };
        gz_stream_io io = { m_read, m_write, &m };
        gz_inflate_kernel = kernels[k];
        int r = gz_inflate_run(z, &io, d64);
        u32 crc = (u32)crc32(0, orig, n);
        if (r || m.dst_len != n || memcmp(m.dst, orig, n) || z->crc != crc) {
            printf("FAIL %s kernel=%s r=%d len=%zu/%zu\n", what, knames[k], r, m.dst_len, n);
            bad++;
        }
        free(m.dst);
    }
    gz_inflater_free(z);
    return bad;
}

static u8 *read_file(const char *p, size_t *n)
{
    FILE *f = fopen(p, "rb"); if (!f) return 0;
    fseek(f, 0, SEEK_END); *n = ftell(f); fseek(f, 0, SEEK_SET);
    u8 *b = malloc(*n + 1); if (fread(b, 1, *n, f) != *n) { fclose(f); free(b); return 0; } fclose(f); return b;
}

int main(int argc, char **argv)
{
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_dispatch_init(-1);
    printf("CPU: %s  tier=%s  inflate=%s crc=%s\n", g_cpu.brand, gz_tier_name(g_cpu.tier),
           gz_dispatch_inflate_name(), gz_dispatch_crc_name());
    int bad = 0;

    /* Deflate64 mode: argv = pairs of raw-stream original */
    if (argc >= 3 && !strcmp(argv[1], "d64")) {
        for (int i = 2; i + 1 < argc; i += 2) {
            size_t cn, n;
            u8 *c = read_file(argv[i], &cn), *o = read_file(argv[i + 1], &n);
            if (!c || !o) { printf("missing %s\n", argv[i]); return 1; }
            bad += check(o, n, c, cn, 0, 1, argv[i + 1]);
            bad += check(o, n, c, cn, 1, 1, argv[i + 1]);
            free(c); free(o);
        }
        printf("deflate64: %s\n", bad ? "FAILED" : "all ok");
        return bad != 0;
    }

    srand(1234);
    static const size_t sizes[] = { 0, 1, 2, 3, 7, 100, 258, 1000, 32768, 65536, 65537,
                                    100000, 1 << 20, (1 << 20) + 12345, 3 << 20 };
    static const int levels[] = { 0, 1, 6, 9 };
    static const int strats[] = { Z_DEFAULT_STRATEGY, Z_FILTERED, Z_HUFFMAN_ONLY, Z_RLE, Z_FIXED };
    int cases = 0;
    for (size_t si = 0; si < sizeof sizes / sizeof *sizes; si++)
        for (int kind = 0; kind < 6; kind++)
            for (int li = 0; li < 4; li++)
                for (int st = 0; st < 5; st++) {
                    if (levels[li] == 0 && st) continue;
                    size_t n = sizes[si];
                    u8 *b = malloc(n + 1);
                    gen(b, n, kind);
                    size_t cn;
                    u8 *c = deflate_raw(b, n, levels[li], strats[st], &cn);
                    char what[64];
                    snprintf(what, sizeof what, "n=%zu kind=%d lvl=%d st=%d", n, kind, levels[li], st);
                    bad += check(b, n, c, cn, (cases & 1), 0, what);
                    cases++;
                    free(b); free(c);
                }
    printf("zlib cross-check: %d cases, %d failures\n", cases, bad);

    /* corruption / truncation fuzz: must never crash, never overflow */
    {
        size_t n = 200000; u8 *b = malloc(n); gen(b, n, 5);
        size_t cn; u8 *c = deflate_raw(b, n, 6, 0, &cn);
        gz_inflater *z = gz_inflater_new();
        int ok_trunc = 0;
        for (int t = 0; t < 3000; t++) {
            u8 *cc = malloc(cn); memcpy(cc, c, cn);
            size_t len = cn;
            if (t % 3 == 0) len = (size_t)rand() % cn;                       /* truncate */
            else for (int f = 0; f < 1 + t % 5; f++) cc[rand() % cn] ^= (u8)(1 << (rand() % 8));
            mem_io m = { cc, len, 0, t & 1, malloc(n * 4 + 1024), n * 4 + 1024, 0 };
            gz_stream_io io = { m_read, m_write, &m };
            gz_inflate_kernel = kernels[t % nkern];
            int r = gz_inflate_run(z, &io, t & 2);
            if (t % 3 == 0 && r != 0) ok_trunc++;
            free(m.dst); free(cc);
        }
        printf("fuzz: done (truncations rejected: %d/1000)\n", ok_trunc);
        gz_inflater_free(z); free(b); free(c);
    }

    /* speed */
    {
        size_t n = 64 << 20; u8 *b = malloc(n); gen(b, n, 5);
        size_t cn; u8 *c = deflate_raw(b, n, 6, 0, &cn);
        gz_inflater *z = gz_inflater_new();
        u8 *dst = malloc(n);
        for (int k = 0; k < nkern; k++) {
            mem_io m = { c, cn, 0, 0, dst, n, 0 };
            gz_stream_io io = { m_read, m_write, &m };
            gz_inflate_kernel = kernels[k];
            struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
            int r = gz_inflate_run(z, &io, 0);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            double s = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
            printf("  %-5s %7.0f MB/s %s\n", knames[k], n / 1e6 / s, r ? "ERR" : "");
        }
        /* zlib reference */
        {
            z_stream s; memset(&s, 0, sizeof s); inflateInit2(&s, -15);
            s.next_in = c; s.avail_in = (uInt)cn; s.next_out = dst; s.avail_out = (uInt)n;
            struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
            inflate(&s, Z_FINISH);
            u32 crc = (u32)crc32(0, dst, n); (void)crc;
            clock_gettime(CLOCK_MONOTONIC, &t1);
            double sec = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
            printf("  zlib  %7.0f MB/s (incl. crc)\n", n / 1e6 / sec);
            inflateEnd(&s);
        }
        gz_inflater_free(z); free(b); free(c); free(dst);
    }
    printf(bad ? "RESULT: FAILED\n" : "RESULT: OK\n");
    return bad != 0;
}
