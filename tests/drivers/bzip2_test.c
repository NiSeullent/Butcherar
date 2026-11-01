/*
 * bzip2_test - codec-level driver for tests/cases/codec_bzip2.py
 *
 *   bzip2_test dec  <in> <out> [multi=1] [out_size=-1]   decode (prints "RC <r> USED <n> OUT <n>")
 *   bzip2_test nsis <in> <off> <out> [out_size=-1]        NSIS variant starting at byte off
 *   bzip2_test enc  <level> <in> <out> [rand|tiny|-] [again]  encode (prints "RC <r> OUT <n>");
 *                                                         rand: randomized blocks, tiny: 1..7 byte reads,
 *                                                         again: encode twice with one object, compare
 *   bzip2_test bench-dec <in> <iters>                     decode speed (MB/s of output)
 *   bzip2_test bench-enc <level> <in> <iters>             encode speed (MB/s of input)
 *   bzip2_test fuzz <in> <iters> <seed>                   decode mutated copies (truncations,
 *                                                         bit flips, byte noise) in-process
 *   bzip2_test chunks <in> <out>                          decode with 1..7 byte reads
 */
#include "bzip2.h"
#include "bzip2_enc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static u8 *load(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *p = (u8 *)malloc(sz + 1);
    if (sz && fread(p, 1, sz, f) != (size_t)sz) { perror(path); exit(2); }
    fclose(f);
    *n = (size_t)sz;
    return p;
}

/* memory reader + growable memory writer (or counting sink); small chunks on request */
typedef struct {
    const u8 *in; size_t in_n, in_pos;
    u8 *out; size_t out_n, out_cap;
    int keep, tiny;
    u64 written;
    u32 seed;
} mio;

static int m_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    mio *m = (mio *)ctx;
    size_t n = m->in_n - m->in_pos;
    if (n > cap) n = cap;
    if (m->tiny && n) { m->seed = m->seed * 1103515245u + 12345u; size_t t = 1 + (m->seed >> 16) % 7; if (n > t) n = t; }
    memcpy(buf, m->in + m->in_pos, n);
    m->in_pos += n;
    *got = (u32)n;
    return 0;
}

static int m_write(void *ctx, const u8 *p, size_t n)
{
    mio *m = (mio *)ctx;
    m->written += n;
    if (!m->keep) return 0;
    if (m->out_n + n > m->out_cap) {
        size_t c = m->out_cap ? m->out_cap : 65536;
        while (c < m->out_n + n) c *= 2;
        m->out = (u8 *)realloc(m->out, c);
        m->out_cap = c;
    }
    memcpy(m->out + m->out_n, p, n);
    m->out_n += n;
    return 0;
}

static void save(const char *path, const u8 *p, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); exit(2); }
    if (n && fwrite(p, 1, n, f) != n) { perror(path); exit(2); }
    fclose(f);
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    const char *cmd = argv[1];
    if (!strcmp(cmd, "dec") || !strcmp(cmd, "chunks")) {
        if (argc < 4) return 2;
        size_t n;
        u8 *in = load(argv[2], &n);
        mio m = { in, n, 0, 0, 0, 0, 1, !strcmp(cmd, "chunks"), 0, 7 };
        int multi = argc > 4 ? atoi(argv[4]) : 1;
        u64 osz = argc > 5 && atoll(argv[5]) >= 0 ? (u64)atoll(argv[5]) : GZ_SIZE_UNKNOWN;
        gz_bzip2_dec *d = gz_bzip2_dec_new();
        gz_stream_io io = { m_read, m_write, &m };
        u64 used = ~(u64)0;
        int r = gz_bzip2_decode(d, &io, osz, multi, &used);
        save(argv[3], m.out, m.out_n);
        printf("RC %d USED %lld OUT %llu\n", r, r ? -1LL : (long long)used, (unsigned long long)m.out_n);
        gz_bzip2_dec_free(d);
        free(m.out);
        free(in);
        return 0;
    }
    if (!strcmp(cmd, "nsis")) {
        if (argc < 5) return 2;
        size_t n;
        u8 *in = load(argv[2], &n);
        size_t off = (size_t)atoll(argv[3]);
        if (off > n) off = n;
        mio m = { in + off, n - off, 0, 0, 0, 0, 1, 0, 0, 7 };
        u64 osz = argc > 5 && atoll(argv[5]) >= 0 ? (u64)atoll(argv[5]) : GZ_SIZE_UNKNOWN;
        gz_bzip2_dec *d = gz_bzip2_dec_new();
        gz_stream_io io = { m_read, m_write, &m };
        u64 used = 0;
        int r = gz_bzip2_decode_nsis(d, &io, osz, &used);
        save(argv[4], m.out, m.out_n);
        printf("RC %d USED %lld OUT %llu\n", r, r ? -1LL : (long long)used, (unsigned long long)m.out_n);
        gz_bzip2_dec_free(d);
        free(m.out);
        free(in);
        return 0;
    }
    if (!strcmp(cmd, "enc")) {
        if (argc < 5) return 2;
        size_t n;
        u8 *in = load(argv[3], &n);
        mio m = { in, n, 0, 0, 0, 0, 1, 0, 0, 7 };
        gz_bzip2_enc *e = gz_bzip2_enc_new(atoi(argv[2]));
        if (argc > 5 && !strcmp(argv[5], "rand")) gz_bzip2_enc_set_randomized(e, 1);
        if (argc > 5 && !strcmp(argv[5], "tiny")) m.tiny = 1;
        gz_stream_io io = { m_read, m_write, &m };
        int r = gz_bzip2_encode(e, &io);
        if (argc > 6) {             /* encode a second time with the same object */
            mio m2 = { in, n, 0, 0, 0, 0, 1, 0, 0, 7 };
            gz_stream_io io2 = { m_read, m_write, &m2 };
            int r2 = gz_bzip2_encode(e, &io2);
            if (r2 || m2.out_n != m.out_n || memcmp(m2.out, m.out, m.out_n)) { printf("REUSE MISMATCH %d\n", r2); return 1; }
            free(m2.out);
        }
        save(argv[4], m.out, m.out_n);
        printf("RC %d OUT %llu\n", r, (unsigned long long)m.out_n);
        gz_bzip2_enc_free(e);
        free(m.out);
        free(in);
        return 0;
    }
    if (!strcmp(cmd, "bench-dec")) {
        if (argc < 4) return 2;
        size_t n;
        u8 *in = load(argv[2], &n);
        int iters = atoi(argv[3]);
        gz_bzip2_dec *d = gz_bzip2_dec_new();
        double best = 1e9;
        u64 out = 0;
        for (int i = 0; i < iters; i++) {
            mio m = { in, n, 0, 0, 0, 0, 0, 0, 0, 7 };
            gz_stream_io io = { m_read, m_write, &m };
            double t0 = now();
            int r = gz_bzip2_decode(d, &io, GZ_SIZE_UNKNOWN, 1, 0);
            double t = now() - t0;
            if (r) { printf("RC %d\n", r); return 1; }
            if (t < best) best = t;
            out = m.written;
        }
        printf("DEC %llu bytes %.3f s %.1f MB/s\n", (unsigned long long)out, best, out / best / 1e6);
        gz_bzip2_dec_free(d);
        free(in);
        return 0;
    }
    if (!strcmp(cmd, "bench-enc")) {
        if (argc < 5) return 2;
        size_t n;
        u8 *in = load(argv[3], &n);
        int iters = atoi(argv[4]);
        gz_bzip2_enc *e = gz_bzip2_enc_new(atoi(argv[2]));
        double best = 1e9;
        u64 out = 0;
        for (int i = 0; i < iters; i++) {
            mio m = { in, n, 0, 0, 0, 0, 0, 0, 0, 7 };
            gz_stream_io io = { m_read, m_write, &m };
            double t0 = now();
            int r = gz_bzip2_encode(e, &io);
            double t = now() - t0;
            if (r) { printf("RC %d\n", r); return 1; }
            if (t < best) best = t;
            out = m.written;
        }
        printf("ENC %zu -> %llu bytes %.3f s %.1f MB/s\n", n, (unsigned long long)out, best, n / best / 1e6);
        gz_bzip2_enc_free(e);
        free(in);
        return 0;
    }
    if (!strcmp(cmd, "fuzz")) {
        if (argc < 5) return 2;
        size_t n;
        u8 *in = load(argv[2], &n);
        int iters = atoi(argv[3]);
        srand((unsigned)atoi(argv[4]));
        u8 *buf = (u8 *)malloc(n + 64);
        gz_bzip2_dec *d = gz_bzip2_dec_new();
        int hist[GZ_E_COUNT + 1];
        memset(hist, 0, sizeof hist);
        for (int i = 0; i < iters; i++) {
            size_t len = n;
            memcpy(buf, in, n);
            int kind = rand() % 4;
            if (kind == 0) len = (size_t)rand() % (n + 1);
            else if (kind == 1) { int k = 1 + rand() % 4; while (k--) buf[(size_t)rand() % n] ^= (u8)(1u << (rand() % 8)); }
            else if (kind == 2) { size_t p = (size_t)rand() % n; int k = 1 + rand() % 16; while (k-- && p < n) buf[p++] = (u8)rand(); }
            else { size_t p = 4 + (size_t)rand() % (n > 64 ? 64 : n); if (p < n) buf[p] ^= (u8)(1u << (rand() % 8)); }
            mio m = { buf, len, 0, 0, 0, 0, 0, i & 1, 0, (u32)i };
            gz_stream_io io = { m_read, m_write, &m };
            int r = (i % 7 == 3) ? gz_bzip2_decode_nsis(d, &io, GZ_SIZE_UNKNOWN, 0)
                                 : gz_bzip2_decode(d, &io, (i % 5 == 1) ? (u64)(n * 3) : GZ_SIZE_UNKNOWN, i & 2 ? 1 : 0, 0);
            if (r < 0 || r >= GZ_E_COUNT) { printf("BAD RC %d\n", r); return 1; }
            hist[r]++;
        }
        printf("FUZZ %d:", iters);
        for (int i = 0; i < GZ_E_COUNT; i++) if (hist[i]) printf(" e%d=%d", i, hist[i]);
        printf("\n");
        gz_bzip2_dec_free(d);
        free(buf);
        free(in);
        return 0;
    }
    if (!strcmp(cmd, "selftest")) {
        /* encode + decode many generated strings (small alphabets, periodic, Fibonacci,
         * runs, random) of length 1..maxlen; every SA-IS recursion shape gets hit */
        if (argc < 5) return 2;
        int iters = atoi(argv[2]);
        size_t maxlen = (size_t)atoll(argv[3]);
        srand((unsigned)atoi(argv[4]));
        u8 *src = (u8 *)malloc(maxlen + 1);
        gz_bzip2_dec *d = gz_bzip2_dec_new();
        gz_bzip2_enc *encs[10] = { 0 };
        int fails = 0;
        for (int i = 0; i < iters; i++) {
            size_t n = 1 + (size_t)rand() % (rand() % 8 ? (maxlen < 3000 ? maxlen : 3000) : maxlen);
            int kind = rand() % 6, sigma = (int[]){ 1, 2, 3, 4, 16, 256 }[rand() % 6];
            if (kind == 0) for (size_t k = 0; k < n; k++) src[k] = (u8)(rand() % sigma);
            else if (kind == 1) {                       /* periodic, maybe with a mutation */
                size_t per = 1 + (size_t)rand() % 12;
                for (size_t k = 0; k < n; k++) src[k] = k < per ? (u8)(rand() % sigma) : src[k - per];
                if (rand() & 1) src[(size_t)rand() % n] ^= 1;
            } else if (kind == 2) {                     /* Fibonacci word over two symbols */
                size_t a = 1, b = 1;
                src[0] = 'a';
                if (n > 1) src[1] = 'b';
                b = n > 1 ? 2 : 1;
                while (b < n) { size_t c = b + a < n ? a : n - b; memcpy(src + b, src, c); a = b; b += c; }
            } else if (kind == 3) {                     /* runs of random lengths */
                for (size_t k = 0; k < n;) { u8 c = (u8)(rand() % sigma); size_t r = 1 + (size_t)rand() % 300; while (r-- && k < n) src[k++] = c; }
            } else if (kind == 4) {                     /* repeated block with a different tail */
                size_t per = 1 + (size_t)rand() % 40;
                for (size_t k = 0; k < n; k++) src[k] = k < per ? (u8)(rand() % sigma) : src[k - per];
                src[n - 1] = (u8)(rand() % 256);
            } else {                                    /* (x^k y)^m patterns */
                size_t k1 = 1 + (size_t)rand() % 5;
                for (size_t k = 0; k < n; k++) src[k] = (k % (k1 + 1)) == k1 ? 1 : 0;
            }
            int lv = 1 + rand() % 9;
            if (!encs[lv]) encs[lv] = gz_bzip2_enc_new(lv);
            gz_bzip2_enc_set_randomized(encs[lv], rand() % 16 == 0);
            mio me = { src, n, 0, 0, 0, 0, 1, 0, 0, 7 };
            gz_stream_io ie = { m_read, m_write, &me };
            int r = gz_bzip2_encode(encs[lv], &ie);
            mio md = { me.out, me.out_n, 0, 0, 0, 0, 1, 0, 0, 7 };
            gz_stream_io id = { m_read, m_write, &md };
            int r2 = r ? r : gz_bzip2_decode(d, &id, GZ_SIZE_UNKNOWN, 1, 0);
            if (r || r2 || md.out_n != n || memcmp(md.out, src, n)) {
                if (fails++ < 5) printf("MISMATCH iter %d kind %d sigma %d n %zu level %d rc %d/%d\n", i, kind, sigma, n, lv, r, r2);
            }
            free(me.out);
            free(md.out);
        }
        printf("SELFTEST %d cases, %d failures\n", iters, fails);
        for (int i = 0; i < 10; i++) gz_bzip2_enc_free(encs[i]);
        gz_bzip2_dec_free(d);
        free(src);
        return fails != 0;
    }
    return 2;
}
