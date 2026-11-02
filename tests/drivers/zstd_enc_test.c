/*
 * Zstandard encoder driver (src/codec/zstd_enc.c)
 *
 *   zstd_enc_test enc LEVEL IN OUT [size|-] [wlog] [chunk]
 *       compress IN into one frame; "size" stores the content size; wlog sets the
 *       window; chunk > 0 feeds the encoder in reads of 1..chunk bytes.
 *       prints: in_bytes out_bytes seconds MB/s
 *   zstd_enc_test rt LEVEL IN
 *       compress in memory, decode with our decoder, compare (prints OK / FAIL)
 *   zstd_enc_test fuzz SEED COUNT [outdir]
 *       random inputs (text, binary, runs, repeats, noise) through every level, decoded
 *       by our decoder; with outdir every frame is also written there for zstd -t
 *   zstd_enc_test multi LEVEL IN OUT
 *       the same encoder writes two frames of IN back to back (encoder reuse)
 *   zstd_enc_test err LEVEL
 *       read / write errors are returned unchanged, wrong content size gives GZ_E_DATA
 *
 * Built with -DZSTDENC_STANDALONE from zstd_enc.c + xxhash.c alone (i586 -m32, AArch64
 * under QEMU): "enc" and "fuzz" (frames written, not decoded) to compare the bytes
 * with the native build.
 */
#include "zstd_enc.h"
#ifndef ZSTDENC_STANDALONE
#include "zstd.h"
#include "cpu.h"
#include "crc32.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef ZSTDENC_STANDALONE
void *gz_alloc(size_t n) { return calloc(1, n ? n : 1); }
void *gz_realloc(void *p, size_t n) { return realloc(p, n); }
void gz_free(void *p) { free(p); }
void *gz_alloc_big(size_t n) { return calloc(1, n); }
void gz_free_big(void *p, size_t n) { (void)n; free(p); }
#endif

typedef struct {
    const u8 *in;
    size_t n, pos, chunk;
    u8 *out;
    size_t on, ocap;
    u32 rng;
    int fail_read_at, fail_write;   /* error injection */
} mio;

static u32 rnd(u32 *s) { *s = *s * 1103515245u + 12345u; return *s >> 8; }

static int m_read(void *ctx, u8 *buf, u32 cap, u32 *got)
{
    mio *m = (mio *)ctx;
    size_t k = m->n - m->pos;
    if (m->fail_read_at >= 0 && m->pos >= (size_t)m->fail_read_at) return GZ_E_IO;
    if (k > cap) k = cap;
    if (m->chunk && k) {
        size_t c = 1 + rnd(&m->rng) % m->chunk;
        if (k > c) k = c;
    }
    memcpy(buf, m->in + m->pos, k);
    m->pos += k;
    *got = (u32)k;
    return GZ_OK;
}

static int m_write(void *ctx, const u8 *p, size_t n)
{
    mio *m = (mio *)ctx;
    if (m->fail_write) return GZ_E_DISK;
    if (m->on + n > m->ocap) {
        size_t nc = (m->ocap + n) * 2;
        m->out = (u8 *)realloc(m->out, nc);
        m->ocap = nc;
    }
    memcpy(m->out + m->on, p, n);
    m->on += n;
    return GZ_OK;
}

static u8 *slurp(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *p = (u8 *)malloc(sz + 1);
    if (fread(p, 1, sz, f) != (size_t)sz) { perror(path); exit(2); }
    fclose(f);
    *n = (size_t)sz;
    return p;
}

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static int encode(int level, const u8 *in, size_t n, int known, u32 wlog, size_t chunk, u8 **out, size_t *on)
{
    gz_zstd_enc_opts o;
    gz_zstd_enc_opts_init(&o, level);
    o.window_log = wlog;
    if (known) o.size_hint = n;
    gz_zstd_enc *e = gz_zstd_enc_new(&o);
    if (!e) return GZ_E_NOMEM;
    mio m;
    memset(&m, 0, sizeof m);
    m.in = in; m.n = n; m.chunk = chunk; m.rng = 12345; m.fail_read_at = -1;
    gz_stream_io io = { m_read, m_write, &m };
    int r = gz_zstd_encode(e, &io, known ? (u64)n : GZ_SIZE_UNKNOWN);
    if (!r && (gz_zstd_enc_in_size(e) != n || gz_zstd_enc_out_size(e) != m.on)) r = 99;
    gz_zstd_enc_free(e);
    *out = m.out;
    *on = m.on;
    return r;
}

static int decode_cmp(const u8 *z, size_t zn, const u8 *ref, size_t n)
{
#ifdef ZSTDENC_STANDALONE
    (void)z; (void)zn; (void)ref; (void)n;
    return 1;                 /* the caller compares the bytes with the native build */
#else
    gz_zstd_dec *d = gz_zstd_dec_new();
    u8 *dst = (u8 *)malloc(n + 16);
    size_t dn = 0;
    int r = gz_zstd_decode_mem(d, z, zn, dst, n + 16, &dn);
    gz_zstd_dec_free(d);
    int ok = !r && dn == n && !memcmp(dst, ref, n);
    if (!ok) fprintf(stderr, "decode r=%d dn=%zu n=%zu\n", r, dn, n);
    free(dst);
    return ok;
#endif
}

/* ---- random inputs ---- */
static void gen(u8 *p, size_t n, u32 *s)
{
    static const char *words[] = { "the ", "zstd ", "encoder ", "고깃", "ZIP ", "\n", "archive ", "0123", "{}", "  " };
    int kind = rnd(s) % 7;
    size_t i = 0;
    while (i < n) {
        int k = kind == 6 ? (int)(rnd(s) % 6) : kind;
        size_t run = 1 + rnd(s) % 4096;
        if (run > n - i) run = n - i;
        switch (k) {
        case 0:   /* noise */
            for (size_t j = 0; j < run; j++) p[i + j] = (u8)rnd(s);
            break;
        case 1:   /* text-like */
            for (size_t j = 0; j < run;) {
                const char *w = words[rnd(s) % 10];
                size_t l = strlen(w);
                for (size_t t = 0; t < l && j < run; t++) p[i + j++] = (u8)w[t];
            }
            break;
        case 2:   /* byte runs */
            memset(p + i, (int)(rnd(s) & 3), run);
            break;
        case 3:   /* copies from earlier (near and far) */
            if (i > 16) {
                size_t off = 1 + rnd(s) % (i < 1000000 ? i : 1000000);
                for (size_t j = 0; j < run; j++) p[i + j] = p[i + j - off];
            } else {
                memset(p + i, 'a', run);
            }
            break;
        case 4:   /* small alphabet */
            for (size_t j = 0; j < run; j++) p[i + j] = (u8)("ACGT"[rnd(s) & 3]);
            break;
        default:  /* structured binary */
            for (size_t j = 0; j < run; j++) p[i + j] = (u8)((i + j) * 7 + ((i + j) >> 9));
            break;
        }
        i += run;
    }
}

int main(int argc, char **argv)
{
#ifndef ZSTDENC_STANDALONE
    gz_cpu_detect();
    gz_crc32_init();
    gz_dispatch_init(-1);
#endif
    if (argc < 3) return 2;
    if (!strcmp(argv[1], "enc") && argc >= 5) {
        size_t n, on;
        u8 *in = slurp(argv[3], &n), *out;
        int known = argc > 5 && strcmp(argv[5], "-");
        u32 wlog = argc > 6 ? (u32)atoi(argv[6]) : 0;
        size_t chunk = argc > 7 ? (size_t)atol(argv[7]) : 0;
        double t0 = now();
        int r = encode(atoi(argv[2]), in, n, known, wlog, chunk, &out, &on);
        double dt = now() - t0;
        if (r) { printf("ERROR %d\n", r); return 1; }
        FILE *f = fopen(argv[4], "wb");
        fwrite(out, 1, on, f);
        fclose(f);
        printf("%zu %zu %.4f %.1f\n", n, on, dt, n / 1e6 / (dt > 0 ? dt : 1e-9));
        free(in);
        free(out);
        return 0;
    }
    if (!strcmp(argv[1], "rt") && argc >= 4) {
        size_t n, on;
        u8 *in = slurp(argv[3], &n), *out;
        int r = encode(atoi(argv[2]), in, n, 1, 0, 0, &out, &on);
        if (r) { printf("ERROR %d\n", r); return 1; }
        int ok = decode_cmp(out, on, in, n);
        printf("%s %zu -> %zu\n", ok ? "OK" : "FAIL", n, on);
        free(in);
        free(out);
        return ok ? 0 : 1;
    }
    if (!strcmp(argv[1], "multi") && argc >= 5) {
        size_t n;
        u8 *in = slurp(argv[3], &n);
        gz_zstd_enc_opts o;
        gz_zstd_enc_opts_init(&o, atoi(argv[2]));
        gz_zstd_enc *e = gz_zstd_enc_new(&o);
        mio m;
        memset(&m, 0, sizeof m);
        m.fail_read_at = -1;
        gz_stream_io io = { m_read, m_write, &m };
        for (int k = 0; k < 3; k++) {
            m.in = in; m.n = k == 1 ? n / 3 : n; m.pos = 0;
            int r = gz_zstd_encode(e, &io, k == 2 ? (u64)n : GZ_SIZE_UNKNOWN);
            if (r) { printf("ERROR %d\n", r); return 1; }
        }
        gz_zstd_enc_free(e);
        FILE *f = fopen(argv[4], "wb");
        fwrite(m.out, 1, m.on, f);
        fclose(f);
        printf("OK %zu\n", m.on);
        free(m.out);
        free(in);
        return 0;
    }
    if (!strcmp(argv[1], "err")) {
        int level = atoi(argv[2]), bad = 0;
        size_t n = 3 << 20;
        u8 *in = (u8 *)malloc(n);
        u32 s = 7;
        gen(in, n, &s);
        for (int k = 0; k < 4; k++) {
            gz_zstd_enc_opts o;
            gz_zstd_enc_opts_init(&o, level);
            gz_zstd_enc *e = gz_zstd_enc_new(&o);
            mio m;
            memset(&m, 0, sizeof m);
            m.in = in; m.n = n; m.fail_read_at = -1;
            u64 cs = GZ_SIZE_UNKNOWN;
            int want;
            if (k == 0) { m.fail_read_at = 1 << 20; want = GZ_E_IO; }
            else if (k == 1) { m.fail_write = 1; want = GZ_E_DISK; }
            else if (k == 2) { cs = n - 1; want = GZ_E_DATA; }
            else { cs = n + 1; want = GZ_E_DATA; }
            gz_stream_io io = { m_read, m_write, &m };
            int r = gz_zstd_encode(e, &io, cs);
            if (r != want) { printf("case %d: got %d want %d\n", k, r, want); bad++; }
            /* the encoder stays usable after an error */
            m.fail_read_at = -1; m.fail_write = 0; m.pos = 0; m.on = 0; m.n = n / 2;
            r = gz_zstd_encode(e, &io, GZ_SIZE_UNKNOWN);
            if (r || !decode_cmp(m.out, m.on, in, n / 2)) { printf("case %d: reuse failed %d\n", k, r); bad++; }
            free(m.out);
            gz_zstd_enc_free(e);
        }
        printf("%s\n", bad ? "FAIL" : "OK");
        free(in);
        return bad ? 1 : 0;
    }
    if (!strcmp(argv[1], "fuzz") && argc >= 4) {
        u32 s = (u32)atoi(argv[2]);
        int count = atoi(argv[3]), bad = 0;
        const char *dir = argc > 4 ? argv[4] : 0;
        for (int i = 0; i < count; i++) {
            size_t n = rnd(&s) % 5 == 0 ? rnd(&s) % 64 : rnd(&s) % 5 == 0 ? rnd(&s) % (3 << 20) : rnd(&s) % 300000;
            u8 *in = (u8 *)malloc(n + 1);
            gen(in, n, &s);
            int level = (int)(rnd(&s) % 20);
            int known = rnd(&s) & 1;
            u32 wlog = rnd(&s) % 4 == 0 ? 10 + rnd(&s) % 12 : 0;
            size_t chunk = rnd(&s) % 3 == 0 ? 1 + rnd(&s) % 70000 : 0;
            u8 *out;
            size_t on;
            int r = encode(level, in, n, known, wlog, chunk, &out, &on);
            int ok = !r && decode_cmp(out, on, in, n);
            if (!ok) {
                printf("FAIL case %d: level %d n %zu known %d wlog %u chunk %zu r %d\n", i, level, n, known, wlog, chunk, r);
                bad++;
            }
            if (dir) {
                char p[512];
                snprintf(p, sizeof p, "%s/f%04d_L%d.zst", dir, i, level);
                FILE *f = fopen(p, "wb");
                fwrite(out, 1, on, f);
                fclose(f);
                snprintf(p, sizeof p, "%s/f%04d_L%d.raw", dir, i, level);
                f = fopen(p, "wb");
                fwrite(in, 1, n, f);
                fclose(f);
            }
            free(out);
            free(in);
        }
        printf("%s %d/%d\n", bad ? "FAIL" : "OK", count - bad, count);
        return bad ? 1 : 0;
    }
    return 2;
}
