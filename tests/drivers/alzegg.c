/*
 * alzegg - test driver for the ALZ / EGG readers and their codecs
 *
 *   alzegg lea                         LEA-128/192/256 test vectors (KS X 3246) + CTR
 *   alzegg azo <in> <out>              decode a raw AZO stream (gz_azo_decode)
 *   alzegg x <archive> <outdir> [pw] [order]
 *       extract with the gz_out contract checked (open / write / close strictly in
 *       sequence, close exactly once); order: solid (one pass, default), each
 *       (gz_arc_extract per entry, forward), rev (backward). Prints
 *       n <TAB> status <TAB> is_dir <TAB> size <TAB> name
 *   alzegg fuzz <archive> <iterations> <seed> [pw]
 *       mutate the archive in memory (bit flips, byte runs, cuts, big numbers) and
 *       list + extract every variant; prints "FUZZ OK <n>" when nothing crashed
 */
#include "arc.h"
#include "cpu.h"
#include "crc32.h"
#include "azo.h"
#include "lea.h"
#include "plat_posix.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void init_core(void)
{
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_aes_init();
    gz_dispatch_init(-1);
}

static int hex2(const char *h, u8 *o)
{
    int n = 0;
    for (; h[0] && h[1]; h += 2) {
        unsigned v;
        sscanf(h, "%2x", &v);
        o[n++] = (u8)v;
    }
    return n;
}

static int cmd_lea(void)
{
    static const char *v[3][3] = {
        { "0f1e2d3c4b5a69788796a5b4c3d2e1f0", "101112131415161718191a1b1c1d1e1f", "9fc84e3528c6c6185532c7a704648bfd" },
        { "0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a59687", "202122232425262728292a2b2c2d2e2f", "6fb95e325aad1b878cdcf5357674c6f2" },
        { "0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a5968778695a4b3c2d1e0f", "303132333435363738393a3b3c3d3e3f", "d651aff647b189c13a8900ca27f9e197" },
    };
    int bad = 0;
    for (int i = 0; i < 3; i++) {
        u8 k[32], p[16], x[16], o[16];
        int kl = hex2(v[i][0], k);
        hex2(v[i][1], p);
        hex2(v[i][2], x);
        gz_lea lea;
        if (gz_lea_set_key(&lea, k, (u32)kl)) { printf("LEA key %d rejected\n", kl); bad = 1; continue; }
        gz_lea_encrypt_block(&lea, p, o);
        if (memcmp(o, x, 16)) { printf("LEA-%d mismatch\n", kl * 8); bad = 1; }
    }
    /* CTR: keystream = E(0), E(1) ..., the counter is big-endian; odd chunk sizes */
    u8 key[16] = { 1, 2, 3 }, buf[100], ref[100];
    gz_lea lk;
    gz_lea_set_key(&lk, key, 16);
    for (int b = 0; b < 7; b++) {
        u8 ctr[16] = { 0 }, ks[16];
        ctr[15] = (u8)b;
        gz_lea_encrypt_block(&lk, ctr, ks);
        for (int j = 0; j < 16 && b * 16 + j < 100; j++) ref[b * 16 + j] = ks[j];
    }
    memset(buf, 0, sizeof buf);
    gz_lea_ctr c;
    gz_lea_ctr_init(&c, key, 16);
    gz_lea_ctr_crypt(&c, buf, 3);
    gz_lea_ctr_crypt(&c, buf + 3, 30);
    gz_lea_ctr_crypt(&c, buf + 33, 67);
    if (memcmp(buf, ref, 100)) { printf("LEA CTR mismatch\n"); bad = 1; }
    if (gz_lea_set_key(&lk, key, 20) != GZ_E_METHOD) { printf("LEA bad key length accepted\n"); bad = 1; }
    printf(bad ? "LEA FAIL\n" : "LEA OK\n");
    return bad;
}

typedef struct { FILE *f; } file_ctx;
static int rd_file(void *ctx, u8 *buf, u32 cap, u32 *got) { *got = (u32)fread(buf, 1, cap, ((file_ctx *)ctx)->f); return 0; }
static int wr_file(void *ctx, const u8 *p, size_t n) { return fwrite(p, 1, n, ((file_ctx *)ctx)->f) == n ? 0 : GZ_E_IO; }

typedef struct { FILE *in, *out; } azo_io;
static int az_rd(void *ctx, u8 *buf, u32 cap, u32 *got) { file_ctx f = { ((azo_io *)ctx)->in }; return rd_file(&f, buf, cap, got); }
static int az_wr(void *ctx, const u8 *p, size_t n) { file_ctx f = { ((azo_io *)ctx)->out }; return wr_file(&f, p, n); }

static int cmd_azo(const char *in, const char *out)
{
    azo_io x = { fopen(in, "rb"), fopen(out, "wb") };
    if (!x.in || !x.out) { perror("open"); return 1; }
    gz_azo_dec *d = gz_azo_dec_new();
    gz_stream_io io = { az_rd, az_wr, &x };
    u64 used = 0;
    int r = gz_azo_decode(d, &io, GZ_SIZE_UNKNOWN, &used);
    printf("AZO %d used %llu\n", r, (unsigned long long)used);
    gz_azo_dec_free(d);
    fclose(x.in);
    fclose(x.out);
    return 0;
}

/* ---- gz_out with contract checks ---- */

typedef struct {
    gz_out o;
    const char *dir;
    FILE *f;
    i64 open_idx;          /* -1 = none */
    int *status;
    u8 *closed;
    u32 n;
    int violations;
} c_out;

static int c_open(gz_out *o, u32 idx)
{
    c_out *t = (c_out *)o;
    if (t->open_idx >= 0) { printf("VIOLATION open %u while %lld is open\n", idx, (long long)t->open_idx); t->violations++; }
    if (idx >= t->n || t->closed[idx]) { printf("VIOLATION open %u again\n", idx); t->violations++; }
    t->open_idx = idx;
    if (t->dir) {
        char p[4096];
        snprintf(p, sizeof p, "%s/%u.bin", t->dir, idx);
        t->f = fopen(p, "wb");
        if (!t->f) return GZ_E_CREATE;
    }
    return GZ_OK;
}

static int c_write(gz_out *o, const u8 *p, size_t n)
{
    c_out *t = (c_out *)o;
    if (t->open_idx < 0) { printf("VIOLATION write with nothing open\n"); t->violations++; return GZ_E_IO; }
    if (t->f && fwrite(p, 1, n, t->f) != n) return GZ_E_IO;
    return GZ_OK;
}

static int c_close(gz_out *o, u32 idx, int st)
{
    c_out *t = (c_out *)o;
    if (t->open_idx != (i64)idx) { printf("VIOLATION close %u, open is %lld\n", idx, (long long)t->open_idx); t->violations++; }
    if (t->f) fclose(t->f);
    t->f = 0;
    t->open_idx = -1;
    if (idx < t->n) {
        t->closed[idx] = 1;
        t->status[idx] = st ? st : 100;
    }
    return GZ_OK;
}

static gzch g_pw[512];

static int ask_pw(void *user, gzch *buf, u32 cap, int retry)
{
    (void)user;
    if (retry || !g_pw[0]) return GZ_E_PASSWORD;
    u32 i = 0;
    for (; g_pw[i] && i + 1 < cap; i++) buf[i] = g_pw[i];
    buf[i] = 0;
    return GZ_OK;
}

static void set_pw(const char *pw)
{
    g_pw[0] = 0;
    if (!pw || !pw[0]) return;
    gzch *w = gz_posix_wide(pw);
    size_t i = 0;
    for (; w[i] && i + 1 < GZ_COUNTOF(g_pw); i++) g_pw[i] = w[i];
    g_pw[i] = 0;
    free(w);
}

static void to_utf8(const gzch *w, char *o, size_t cap)
{
    size_t n = gz_wcslen(w);
    if (n * 3 + 1 > cap) n = (cap - 1) / 3;
    int k = gz_utf16_to_utf8(w, n, (u8 *)o);
    o[k] = 0;
}

/* extract everything; returns contract violations */
static int extract_all(gz_archive *a, gz_src *src, gz_ctx *c, const char *dir, const char *order, int print)
{
    c_out *o = (c_out *)calloc(1, sizeof(c_out));
    o->o.open = c_open; o->o.write = c_write; o->o.close = c_close;
    o->dir = dir;
    o->open_idx = -1;
    o->n = a->n;
    o->status = (int *)calloc(a->n + 1, sizeof(int));
    o->closed = (u8 *)calloc(a->n + 1, 1);
    if (!strcmp(order, "solid")) {
        u8 *sel = (u8 *)calloc(1, a->n + 1);
        memset(sel, 1, a->n);
        gz_arc_extract_solid(a, src, sel, &o->o, c);
        free(sel);
    } else {
        int rev = !strcmp(order, "rev");
        for (u32 k = 0; k < a->n; k++) {
            u32 i = rev ? a->n - 1 - k : k;
            int r = gz_arc_extract(a, src, i, &o->o, c);
            if (o->open_idx >= 0) { printf("VIOLATION %u left open\n", i); o->violations++; o->open_idx = -1; }
            if (r && !o->status[i]) o->status[i] = r;
        }
    }
    if (o->open_idx >= 0) { printf("VIOLATION %lld left open\n", (long long)o->open_idx); o->violations++; }
    if (print) {
        char nm[8192];
        for (u32 i = 0; i < a->n; i++) {
            to_utf8(a->e[i].name, nm, sizeof nm);
            int s = o->status[i] == 100 ? 0 : (o->status[i] ? o->status[i] : -1);
            unsigned long long sz = a->e[i].usize == GZ_SIZE_UNKNOWN ? 0 : (unsigned long long)a->e[i].usize;
            printf("%u\t%d\t%d\t%llu\t%s\n", i, s, a->e[i].is_dir, sz, nm);
        }
    }
    int v = o->violations;
    free(o->status);
    free(o->closed);
    free(o);
    return v;
}

static int cmd_x(int argc, char **argv)
{
    set_pw(argc > 4 ? argv[4] : 0);
    const char *order = argc > 5 ? argv[5] : "solid";
    gz_src *src = gz_posix_open_src(argv[2]);
    if (!src) { perror(argv[2]); return 1; }
    gzch *wname = gz_posix_wide(argv[2]);
    gz_open_opts oo;
    memset(&oo, 0, sizeof oo);
    oo.file_name = wname;
    oo.open_volume = gz_posix_open_volume;
    oo.ask_password = ask_pw;
    gz_ctx *c = gz_ctx_new();
    gz_archive *a;
    int r = gz_arc_open(&a, src, &oo, c);
    free(wname);
    if (r) { printf("OPEN_ERROR %d\n", r); return 1; }
    if (g_pw[0]) c->password = g_pw;
    mkdir(argv[3], 0755);
    int v = extract_all(a, src, c, argv[3], order, 1);
    printf("TYPE %s VIOLATIONS %d\n", gz_arc_type_name(a), v);
    gz_arc_close(a);
    gz_src_free(src);
    gz_ctx_free(c);
    return v ? 1 : 0;
}

static u64 rng_state;
static u32 rnd(void)
{
    rng_state = rng_state * 6364136223846793005ull + 1442695040888963407ull;
    return (u32)(rng_state >> 33);
}

static int cmd_fuzz(int argc, char **argv)
{
    FILE *f = fopen(argv[2], "rb");
    if (!f) { perror(argv[2]); return 1; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *orig = (u8 *)malloc((size_t)n + 1);
    if (fread(orig, 1, (size_t)n, f) != (size_t)n) return 1;
    fclose(f);
    int iters = atoi(argv[3]);
    rng_state = (u64)atoll(argv[4]) * 0x9E3779B97F4A7C15ull + 1;
    set_pw(argc > 5 ? argv[5] : 0);
    u8 *buf = (u8 *)malloc((size_t)n + 64);
    int viol = 0;
    for (int it = 0; it < iters; it++) {
        long m = n;
        memcpy(buf, orig, (size_t)n);
        u32 kind = rnd() % 6, cnt = 1 + rnd() % 8;
        for (u32 k = 0; k < cnt && m > 0; k++) {
            u32 p = rnd() % (u32)m;
            switch (kind) {
            case 0: buf[p] ^= (u8)(1u << (rnd() % 8)); break;            /* bit flip */
            case 1: buf[p] = (u8)rnd(); break;                           /* random byte */
            case 2: m = p; break;                                        /* cut */
            case 3: {                                                    /* big 32-bit number */
                static const u32 vals[] = { 0xFFFFFFFFu, 0x7FFFFFFFu, 0x80000000u, 0x10000u, 0xFFFFu, 0 };
                if (p + 4 <= (u32)m) wr32(buf + p, vals[rnd() % 6]);
                break;
            }
            case 4: if (p + 2 <= (u32)m) wr16(buf + p, (u16)(rnd() & 1 ? 0xFFFF : rnd())); break;
            default: {                                                   /* byte run */
                u32 len = 1 + rnd() % 64;
                u8 v = (u8)rnd();
                for (u32 j = 0; j < len && p + j < (u32)m; j++) buf[p + j] = v;
            }
            }
        }
        gz_src *src = gz_src_mem(buf, (u64)m, 0);
        gz_ctx *c = gz_ctx_new();
        gz_open_opts oo;
        memset(&oo, 0, sizeof oo);
        oo.ask_password = ask_pw;
        gz_archive *a;
        if (!gz_arc_open(&a, src, &oo, c)) {
            if (g_pw[0]) c->password = g_pw;
            viol += extract_all(a, src, c, 0, it & 1 ? "each" : "solid", 0);
            gz_arc_close(a);
        }
        gz_ctx_free(c);
        gz_src_free(src);
    }
    printf("FUZZ %s %d\n", viol ? "VIOLATIONS" : "OK", iters);
    free(buf);
    free(orig);
    return viol ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    init_core();
    if (!strcmp(argv[1], "lea")) return cmd_lea();
    if (!strcmp(argv[1], "azo") && argc >= 4) return cmd_azo(argv[2], argv[3]);
    if (!strcmp(argv[1], "x") && argc >= 4) return cmd_x(argc, argv);
    if (!strcmp(argv[1], "fuzz") && argc >= 5) return cmd_fuzz(argc, argv);
    return 2;
}
