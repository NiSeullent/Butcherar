/*
 * misc_ref - differential tests and benchmarks against reference libraries, when present:
 *   -DHAVE_LZFSE (Apple's liblzfse, -llzfse), -DHAVE_LZO (liblzo2, -l:liblzo2.so.2),
 *   -DHAVE_WIM (wimlib's XPRESS, -l:libwim.so.15).
 *
 *   misc_ref lzfse <stream> <iters> <seed>   mutate a .lzfse stream; whenever we accept
 *                                            an input the reference must give the same bytes
 *   misc_ref lzo   <block>  <iters> <seed>   mutate a raw LZO1X block; both decoders must
 *                                            agree on success, consumed input and bytes
 *   misc_ref lzogen <iters> <seed>           random data through lzo1x_1/1_11/1_12/1_15/999
 *   misc_ref xhuffgen <iters> <seed>         random data through wimlib's XPRESS compressor
 *   misc_ref xhuff <data> <iters> <seed>     mutate wimlib XPRESS chunks of data; when we accept,
 *                                            wimlib must give the same bytes
 *   misc_ref bench <lzo|lzfse|xhuff> <data> <ms>   MB/s of output, ours and the reference
 */
#include "lzo.h"
#include "lzfse.h"
#include "xpress.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef HAVE_WIM
int wimlib_create_compressor(int ctype, size_t max_block, unsigned level, void **c);
size_t wimlib_compress(const void *in, size_t n, void *out, size_t avail, void *c);
int wimlib_create_decompressor(int ctype, size_t max_block, void **d);
int wimlib_decompress(const void *in, size_t n, void *out, size_t out_n, void *d);
#define WIM_XPRESS 1
#endif
#ifdef HAVE_LZFSE
/* Apple's lzfse.h has the same name as ours: declare the two functions used */
size_t lzfse_decode_scratch_size(void);
size_t lzfse_decode_buffer(uint8_t *dst, size_t dst_size, const uint8_t *src, size_t src_size, void *scratch);
#endif

#ifdef HAVE_LZO
typedef unsigned long lzo_uint;
int lzo1x_decompress_safe(const unsigned char *src, lzo_uint src_len, unsigned char *dst, lzo_uint *dst_len, void *wrk);
int lzo1x_1_compress(const unsigned char *src, lzo_uint src_len, unsigned char *dst, lzo_uint *dst_len, void *wrk);
int lzo1x_1_11_compress(const unsigned char *src, lzo_uint src_len, unsigned char *dst, lzo_uint *dst_len, void *wrk);
int lzo1x_1_12_compress(const unsigned char *src, lzo_uint src_len, unsigned char *dst, lzo_uint *dst_len, void *wrk);
int lzo1x_1_15_compress(const unsigned char *src, lzo_uint src_len, unsigned char *dst, lzo_uint *dst_len, void *wrk);
int lzo1x_999_compress(const unsigned char *src, lzo_uint src_len, unsigned char *dst, lzo_uint *dst_len, void *wrk);
#endif

/* long-lived buffers stay reachable from here (no leak reports from early returns) */
static void *kept[1024];
static unsigned nkept;
static void *xmalloc(size_t n)
{
    void *p = malloc(n);
    if (!p) { fprintf(stderr, "out of memory\n"); exit(2); }
    if (nkept < sizeof kept / sizeof kept[0]) kept[nkept++] = p;
    return p;
}

static u64 rs;
static u32 rnd(void)
{
    rs = rs * 6364136223846793005ull + 1442695040888963407ull;
    return (u32)(rs >> 33);
}

static u8 *load(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *p = (u8 *)xmalloc((size_t)sz + 1);
    if (sz && fread(p, 1, (size_t)sz, f) != (size_t)sz) exit(2);
    fclose(f);
    *n = (size_t)sz;
    return p;
}

static void mutate(u8 *p, size_t *n)
{
    size_t len = *n;
    if (!len) return;
    switch (rnd() % 5) {
    case 0: case 1: p[rnd() % len] ^= (u8)(1u << (rnd() % 8)); break;
    case 2: p[rnd() % len] = (u8)rnd(); break;
    case 3: *n = rnd() % (len + 1); break;
    default: {
        size_t a = rnd() % len, m = 1 + rnd() % 16;
        if (a + m > len) m = len - a;
        memset(p + a, (rnd() & 1) ? 0xff : 0, m);
    }
    }
}

#ifdef HAVE_LZFSE
static int cmd_lzfse(int argc, char **argv)
{
    size_t n;
    u8 *orig = load(argv[2], &n), *w = (u8 *)xmalloc(n + 1);
    long iters = atol(argv[3]);
    rs = strtoull(argv[4], 0, 0) + 7;
    u64 raw = 0;
    gz_lzfse_size(orig, n, &raw, 0);
    size_t cap = (size_t)raw * 2 + 65536;
    u8 *a = (u8 *)xmalloc(cap), *b = (u8 *)xmalloc(cap);
    void *scratch = xmalloc(lzfse_decode_scratch_size());
    long ok = 0, stricter = 0;
    for (long it = 0; it < iters; it++) {
        size_t m = n;
        memcpy(w, orig, n);
        int k = 1 + (int)(rnd() % 3);
        for (int j = 0; j < k; j++) mutate(w, &m);
        size_t on = 0;
        int r = gz_lzfse_decode(w, m, a, cap, &on, 0);
        size_t rn = lzfse_decode_buffer(b, cap, w, m, scratch);
        if (r == GZ_OK) {
            ok++;
            if (rn != on || memcmp(a, b, on)) {
                printf("MISMATCH it=%ld ours=%zu ref=%zu\n", it, on, rn);
                FILE *f = fopen("lzfse_mismatch.bin", "wb");
                if (f) { fwrite(w, 1, m, f); fclose(f); }
                return 1;
            }
        } else if (rn && rn < cap) {
            /* the reference accepted what we rejected (we are stricter on corrupt blocks) */
            stricter++;
            if (getenv("MISC_REF_DUMP") && stricter < 20) {
                char nm[64];
                snprintf(nm, sizeof nm, "lzfse_strict_%ld_rc%d.bin", stricter, r);
                FILE *f = fopen(nm, "wb");
                if (f) { fwrite(w, 1, m, f); fclose(f); }
            }
        }
    }
    printf("iters=%ld accepted=%ld ref_only=%ld\n", iters, ok, stricter);
    return 0;
}
#endif

#ifdef HAVE_LZO
static int lzo_compare(const u8 *w, size_t m, u8 *a, u8 *b, size_t cap, long it)
{
    size_t on = 0, iu = 0;
    int r = gz_lzo1x_decode(w, m, a, cap, &on, &iu);
    lzo_uint rn = cap;
    int rr = lzo1x_decompress_safe(w, m, b, &rn, 0);
    /* LZO_E_OK = 0, LZO_E_INPUT_NOT_CONSUMED = -8 */
    int ours_ok = r == GZ_OK, ref_ok = rr == 0 || rr == -8;
    if (ours_ok != ref_ok || (ours_ok && ((rr == 0) != (iu == m) || rn != on || memcmp(a, b, on)))) {
        printf("MISMATCH it=%ld ours=%d/%zu/%zu ref=%d/%lu\n", it, r, on, iu, rr, (unsigned long)rn);
        FILE *f = fopen("lzo_mismatch.bin", "wb");
        if (f) { fwrite(w, 1, m, f); fclose(f); }
        return 1;
    }
    return 0;
}

static int cmd_lzo(int argc, char **argv)
{
    size_t n;
    u8 *orig = load(argv[2], &n), *w = (u8 *)xmalloc(n + 1);
    long iters = atol(argv[3]);
    rs = strtoull(argv[4], 0, 0) + 11;
    size_t cap = 4 << 20;
    u8 *a = (u8 *)xmalloc(cap), *b = (u8 *)xmalloc(cap);
    long ok = 0;
    for (long it = 0; it < iters; it++) {
        size_t m = n;
        memcpy(w, orig, n);
        int k = 1 + (int)(rnd() % 3);
        for (int j = 0; j < k; j++) mutate(w, &m);
        size_t c2 = (rnd() % 4) ? cap : rnd() % cap;
        if (lzo_compare(w, m, a, b, c2, it)) return 1;
        size_t on, iu;
        ok += gz_lzo1x_decode(w, m, a, c2, &on, &iu) == GZ_OK;
    }
    printf("iters=%ld accepted=%ld\n", iters, ok);
    return 0;
}

static int cmd_lzogen(int argc, char **argv)
{
    long iters = atol(argv[2]);
    rs = strtoull(argv[3], 0, 0) + 13;
    size_t cap = 1 << 20;
    u8 *src = (u8 *)xmalloc(cap), *z = (u8 *)xmalloc(cap + cap / 16 + 64 + 3), *a = (u8 *)xmalloc(cap);
    void *wrk = xmalloc(1 << 20);
    typedef int (*cfn)(const unsigned char *, lzo_uint, unsigned char *, lzo_uint *, void *);
    static const cfn fns[5] = { lzo1x_1_compress, lzo1x_1_11_compress, lzo1x_1_12_compress,
                                lzo1x_1_15_compress, lzo1x_999_compress };
    for (long it = 0; it < iters; it++) {
        size_t n = rnd() % ((it % 8) ? 70000 : cap);
        int kind = (int)(rnd() % 4);
        for (size_t i = 0; i < n; i++) {
            u32 x = rnd();
            src[i] = kind == 0 ? (u8)x : kind == 1 ? (u8)("abcdefgh"[x % 8]) :
                     kind == 2 ? (i > 300 && (x & 3) ? src[i - 1 - (x >> 8) % 300] : (u8)x) : (u8)(i / 97);
        }
        lzo_uint zn = cap + cap / 16 + 64 + 3;
        if (fns[it % 5](src, n, z, &zn, wrk) != 0) { printf("compress failed\n"); return 1; }
        size_t on, iu;
        int r = gz_lzo1x_decode(z, zn, a, n, &on, &iu);
        if (r || on != n || iu != zn || memcmp(a, src, n)) {
            printf("FAIL it=%ld fn=%ld n=%zu rc=%d out=%zu used=%zu/%lu\n", it, it % 5, n, r, on, iu, (unsigned long)zn);
            return 1;
        }
        if (lzo_compare(z, zn, a, src, n, it)) return 1;     /* src reused as ref output */
    }
    printf("iters=%ld ok\n", iters);
    return 0;
}
#endif

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static void fill(u8 *p, size_t n, int kind)
{
    for (size_t i = 0; i < n; i++) {
        u32 x = rnd();
        p[i] = kind == 0 ? (u8)x : kind == 1 ? (u8)("abcdefgh"[x % 8]) :
               kind == 2 ? (i > 300 && (x & 3) ? p[i - 1 - (x >> 8) % 300] : (u8)x) : (u8)(i / 97);
    }
}

#ifdef HAVE_WIM
static int cmd_xhuffgen(int argc, char **argv)
{
    long iters = atol(argv[2]);
    rs = strtoull(argv[3], 0, 0) + 17;
    static void *cm[3], *dm;          /* static: stay reachable for the leak checker */
    unsigned lv[3] = { 10, 50, 100 };
    for (int i = 0; i < 3; i++) if (wimlib_create_compressor(WIM_XPRESS, 65536, lv[i], &cm[i])) return 2;
    u8 *src = (u8 *)xmalloc(65536), *z = (u8 *)xmalloc(65536), *a;
    for (long it = 0; it < iters; it++) {
        size_t n = 1 + rnd() % 65536;
        fill(src, n, (int)(rnd() % 4));
        size_t zn = wimlib_compress(src, n, z, n - 1, cm[it % 3]);
        if (!zn) continue;                       /* incompressible: stored by WIM writers */
        a = (u8 *)malloc(n);
        int r = gz_xpress_huff_decode(z, zn, a, n);
        if (r || memcmp(a, src, n)) { printf("FAIL it=%ld n=%zu rc=%d\n", it, n, r); return 1; }
        free(a);
    }
    (void)dm;
    printf("iters=%ld ok\n", iters);
    return 0;
}

static int cmd_xhuff(int argc, char **argv)
{
    size_t n;
    u8 *data = load(argv[2], &n);
    long iters = atol(argv[3]);
    rs = strtoull(argv[4], 0, 0) + 19;
    static void *cm, *dm;
    if (wimlib_create_compressor(WIM_XPRESS, 65536, 50, &cm) || wimlib_create_decompressor(WIM_XPRESS, 65536, &dm)) return 2;
    long ok = 0, chunks = 0;
    u8 *z = (u8 *)xmalloc(65536), *w = (u8 *)xmalloc(65536 + 1), *a = (u8 *)xmalloc(65536), *b = (u8 *)xmalloc(65536);
    for (size_t off = 0; off < n && iters > 0; off += 65536) {
        size_t cn = n - off < 65536 ? n - off : 65536;
        size_t zn = wimlib_compress(data + off, cn, z, cn - 1, cm);
        if (!zn) continue;
        chunks++;
        for (long it = 0; it < iters; it++) {
            size_t m = zn;
            memcpy(w, z, zn);
            int k = 1 + (int)(rnd() % 3);
            for (int j = 0; j < k; j++) mutate(w, &m);
            int r = gz_xpress_huff_decode(w, m, a, cn);
            if (r) continue;
            ok++;
            if (wimlib_decompress(w, m, b, cn, dm) || memcmp(a, b, cn)) {
                printf("MISMATCH off=%zu it=%ld\n", off, it);
                FILE *f = fopen("xhuff_mismatch.bin", "wb");
                if (f) { fwrite(w, 1, m, f); fclose(f); }
                return 1;
            }
        }
    }
    printf("chunks=%ld iters=%ld accepted=%ld\n", chunks, iters, ok);
    return 0;
}
#endif

/* MB/s of decoded output for ours and the reference on the same compressed data */
static int cmd_bench(int argc, char **argv)
{
    size_t n;
    u8 *data = load(argv[3], &n);
    double ms = atof(argv[4]);
    const char *c = argv[2];
    u8 *out = (u8 *)xmalloc(n + 65536);
    double t0, t, tot;
#ifdef HAVE_LZO
    if (!strcmp(c, "lzo")) {
        static char wrk[1 << 20];
        u8 *z = (u8 *)xmalloc(n + n / 16 + 67);
        lzo_uint zn = n + n / 16 + 67;
        lzo1x_999_compress(data, n, z, &zn, wrk);
        for (int pass = 0; pass < 2; pass++) {
            tot = 0; t0 = now_ms();
            do {
                if (pass == 0) { size_t on, iu; gz_lzo1x_decode(z, zn, out, n, &on, &iu); }
                else { lzo_uint rn = n; lzo1x_decompress_safe(z, zn, out, &rn, 0); }
                tot += n; t = now_ms();
            } while (t - t0 < ms);
            printf("%s %.0f MB/s\n", pass ? "liblzo2" : "ours", tot / ((t - t0) / 1e3) / 1e6);
        }
        return memcmp(out, data, n) != 0;
    }
#endif
#ifdef HAVE_LZFSE
    if (!strcmp(c, "lzfse")) {
        size_t zn;
        u8 *z = load(argv[5], &zn);
        void *scratch = xmalloc(lzfse_decode_scratch_size());
        gz_lzfse_dec *d = gz_lzfse_dec_new();
        for (int pass = 0; pass < 2; pass++) {
            tot = 0; t0 = now_ms();
            do {
                if (pass == 0) { size_t on, iu; gz_lzfse_decode_ex(d, z, zn, out, n, &on, &iu); }
                else lzfse_decode_buffer(out, n + 1, z, zn, scratch);
                tot += n; t = now_ms();
            } while (t - t0 < ms);
            printf("%s %.0f MB/s\n", pass ? "liblzfse" : "ours", tot / ((t - t0) / 1e3) / 1e6);
        }
        return memcmp(out, data, n) != 0;
    }
#endif
#ifdef HAVE_WIM
    if (!strcmp(c, "xhuff")) {
        static void *cm, *dm;
        if (wimlib_create_compressor(WIM_XPRESS, 65536, 50, &cm) || wimlib_create_decompressor(WIM_XPRESS, 65536, &dm)) return 2;
        size_t nc = (n + 65535) / 65536;
        u8 **z = (u8 **)xmalloc(nc * sizeof *z);
        size_t *zn = (size_t *)xmalloc(nc * sizeof *zn);
        for (size_t i = 0; i < nc; i++) {
            size_t cn = n - i * 65536 < 65536 ? n - i * 65536 : 65536;
            z[i] = (u8 *)xmalloc(65536);
            zn[i] = wimlib_compress(data + i * 65536, cn, z[i], 65536, cm);
        }
        for (int pass = 0; pass < 2; pass++) {
            tot = 0; t0 = now_ms();
            do {
                for (size_t i = 0; i < nc; i++) {
                    size_t cn = n - i * 65536 < 65536 ? n - i * 65536 : 65536;
                    if (!zn[i]) { memcpy(out + i * 65536, data + i * 65536, cn); continue; }
                    if (pass == 0) gz_xpress_huff_decode(z[i], zn[i], out + i * 65536, cn);
                    else wimlib_decompress(z[i], zn[i], out + i * 65536, cn, dm);
                }
                tot += n; t = now_ms();
            } while (t - t0 < ms);
            printf("%s %.0f MB/s\n", pass ? "wimlib" : "ours", tot / ((t - t0) / 1e3) / 1e6);
        }
        return memcmp(out, data, n) != 0;
    }
#endif
    printf("unsupported\n");
    return 3;
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "bench") && argc >= 5) return cmd_bench(argc, argv);
#ifdef HAVE_WIM
    if (!strcmp(argv[1], "xhuffgen") && argc >= 4) return cmd_xhuffgen(argc, argv);
    if (!strcmp(argv[1], "xhuff") && argc >= 5) return cmd_xhuff(argc, argv);
#endif
#ifdef HAVE_LZFSE
    if (!strcmp(argv[1], "lzfse") && argc >= 5) return cmd_lzfse(argc, argv);
#endif
#ifdef HAVE_LZO
    if (!strcmp(argv[1], "lzo") && argc >= 5) return cmd_lzo(argc, argv);
    if (!strcmp(argv[1], "lzogen") && argc >= 4) return cmd_lzogen(argc, argv);
#endif
    printf("unsupported\n");
    return 3;
}
