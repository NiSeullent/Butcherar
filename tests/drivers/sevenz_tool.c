/*
 * sevenz_tool - 7z reader checks beyond what gzt shows (tests/cases/fmt_7z.py)
 *
 *   sevenz_tool l <arc> [pw]
 *       header line: TYPE <type> n=<n> solid=<0|1> henc=<0|1> sfx=<shift>
 *       then: idx dir size csize crc(-) mtime attr mode enc link method name
 *   sevenz_tool sel <arc> <outdir|-> <pw|-> <i,j,...|all>
 *       gz_arc_extract_solid with a selection; prints "idx status" for every
 *       opened entry and PROTO lines when open/write/close are misused
 *   sevenz_tool one <arc> <outdir|-> <pw|-> <i,j,...|all>
 *       gz_arc_extract per entry (random access, also in solid archives)
 *   sevenz_tool pw <arc> <pw|->        gz_arc_check_password for every entry
 *   sevenz_tool view <arc> <idx>       size and CRC-32 of gz_arc_view's data
 *   sevenz_tool bench <arc> [pw] [reps]  decode everything to a CRC sink, MB/s
 *   sevenz_tool fuzz <arc> <iters> <seed> [pw]
 *       in-process mutations (bit flips, byte runs, truncation) of the archive:
 *       open + extract everything; must not crash, hang or leak
 */
#include "arc.h"
#include "cpu.h"
#include "crc32.h"
#include "plat_posix.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static gzch g_pw[512];

static void set_pw(const char *s)
{
    g_pw[0] = 0;
    if (!s || !strcmp(s, "-")) return;
    gzch *w = gz_posix_wide(s);
    size_t i = 0;
    for (; w[i] && i + 1 < 512; i++) g_pw[i] = w[i];
    g_pw[i] = 0;
    free(w);
}

static int ask_pw(void *user, gzch *buf, u32 cap, int retry)
{
    (void)user;
    if (retry || !g_pw[0]) return GZ_E_PASSWORD;
    u32 i = 0;
    for (; g_pw[i] && i + 1 < cap; i++) buf[i] = g_pw[i];
    buf[i] = 0;
    return GZ_OK;
}

static void to_utf8(const gzch *w, char *o, size_t cap)
{
    size_t n = gz_wcslen(w);
    if (n * 3 + 1 > cap) n = (cap - 1) / 3;
    int k = gz_utf16_to_utf8(w, n, (u8 *)o);
    o[k] = 0;
}

static int open_arc_src(gz_src *src, const char *path, gz_archive **pa, gz_ctx *c)
{
    gzch *wname = gz_posix_wide(path);
    gz_open_opts oo;
    memset(&oo, 0, sizeof oo);
    oo.file_name = wname;
    oo.password = g_pw[0] ? g_pw : 0;
    oo.ask_password = ask_pw;
    int r = gz_arc_open(pa, src, &oo, c);
    free(wname);
    return r;
}

/* ---- output with protocol checks ---- */

typedef struct {
    gz_out o;
    const char *dir;            /* NULL: CRC only */
    FILE *f;
    u32 n, cur;
    u8 *opened, *closed;
    int *st;
    u32 *crc;
    u64 *size, bytes;
    int bad;
} t_out;

static int o_open(gz_out *o, u32 idx)
{
    t_out *t = (t_out *)o;
    if (idx >= t->n || t->opened[idx] || t->cur != 0xFFFFFFFFu) { printf("PROTO open %u\n", idx); t->bad = 1; }
    if (idx < t->n) t->opened[idx] = 1;
    t->cur = idx;
    if (t->dir) {
        char p[4096];
        snprintf(p, sizeof p, "%s/%u.bin", t->dir, idx);
        t->f = fopen(p, "wb");
        if (!t->f) return GZ_E_CREATE;
    }
    if (idx < t->n) { t->crc[idx] = 0; t->size[idx] = 0; }
    return GZ_OK;
}

static int o_write(gz_out *o, const u8 *p, size_t n)
{
    t_out *t = (t_out *)o;
    if (t->cur == 0xFFFFFFFFu) { printf("PROTO write without open\n"); t->bad = 1; return GZ_OK; }
    t->crc[t->cur] = gz_crc32(t->crc[t->cur], p, n);
    t->size[t->cur] += n;
    t->bytes += n;
    if (t->f && fwrite(p, 1, n, t->f) != n) return GZ_E_IO;
    return GZ_OK;
}

static int o_close(gz_out *o, u32 idx, int st)
{
    t_out *t = (t_out *)o;
    if (idx >= t->n || idx != t->cur || t->closed[idx]) { printf("PROTO close %u\n", idx); t->bad = 1; }
    if (idx < t->n) { t->closed[idx] = 1; t->st[idx] = st; }
    if (t->f) fclose(t->f);
    t->f = 0;
    t->cur = 0xFFFFFFFFu;
    return GZ_OK;
}

static t_out *new_out(u32 n, const char *dir)
{
    t_out *t = (t_out *)calloc(1, sizeof(t_out));
    t->o.open = o_open; t->o.write = o_write; t->o.close = o_close;
    t->dir = dir;
    t->n = n;
    t->cur = 0xFFFFFFFFu;
    t->opened = (u8 *)calloc(n + 1, 1);
    t->closed = (u8 *)calloc(n + 1, 1);
    t->st = (int *)calloc(n + 1, sizeof(int));
    t->crc = (u32 *)calloc(n + 1, 4);
    t->size = (u64 *)calloc(n + 1, 8);
    if (dir) mkdir(dir, 0755);
    return t;
}

static void free_out(t_out *t)
{
    free(t->opened); free(t->closed); free(t->st); free(t->crc); free(t->size); free(t);
}

static u8 *parse_sel(const char *s, u32 n)
{
    u8 *sel = (u8 *)calloc(n + 1, 1);
    if (!strcmp(s, "all")) { memset(sel, 1, n); return sel; }
    while (*s) {
        unsigned long v = strtoul(s, (char **)&s, 10);
        if (v < n) sel[v] = 1;
        if (*s == ',') s++;
        else if (*s) break;
    }
    return sel;
}

static void init_core(void)
{
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_aes_init();
    gz_dispatch_init(-1);
}

static int cmd_list(gz_archive *a)
{
    printf("TYPE %s n=%u solid=%d henc=%d sfx=%llu\n", gz_arc_type_name(a), a->n, a->solid, a->headers_enc,
           (unsigned long long)a->sfx_shift);
    char nm[8192], m[300];
    for (u32 i = 0; i < a->n; i++) {
        gz_entry *e = &a->e[i];
        gzch mw[96];
        gz_arc_method(a, e, mw, 96);
        to_utf8(mw, m, sizeof m);
        to_utf8(e->name, nm, sizeof nm);
        char crc[16] = "-";
        if (e->has_crc) snprintf(crc, sizeof crc, "%08X", e->crc);
        printf("%u\t%d\t%llu\t%llu\t%s\t%llu\t%x\t%o\t%d\t%d\t%s\t%s\n", i, e->is_dir, (unsigned long long)e->usize,
               (unsigned long long)e->csize, crc, (unsigned long long)(e->mtime_kind == GZ_MT_FILETIME ? e->mtime : 0),
               e->attr, e->unix_mode, e->enc, e->is_link, m, nm);
    }
    return 0;
}

static void report(gz_archive *a, t_out *t)
{
    for (u32 i = 0; i < a->n; i++) {
        if (t->opened[i] && !t->closed[i]) { printf("PROTO unclosed %u\n", i); t->bad = 1; }
        if (!t->opened[i]) continue;
        printf("%u\t%d\t%llu\t%08X\n", i, t->st[i], (unsigned long long)t->size[i], t->crc[i]);
    }
    if (t->bad) printf("PROTO_BAD\n");
}

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

/* ---- fuzzing ---- */

static u64 rng_state;
static u32 rnd(void)
{
    rng_state = rng_state * 6364136223846793005ull + 1442695040888963407ull;
    return (u32)(rng_state >> 33);
}

static int fuzz_one(const u8 *data, size_t n, gz_ctx *c)
{
    gz_src *s = gz_src_mem(data, n, 0);
    gz_archive *a = 0;
    int r = open_arc_src(s, "fuzz.7z", &a, c);
    if (!r) {
        t_out *t = new_out(a->n, 0);
        c->password = g_pw[0] ? g_pw : a->password;
        if (a->solid) {
            u8 *sel = (u8 *)malloc(a->n + 1);
            memset(sel, 1, a->n);
            gz_arc_extract_solid(a, s, sel, &t->o, c);
            free(sel);
        } else {
            for (u32 i = 0; i < a->n; i++) gz_arc_extract(a, s, i, &t->o, c);
        }
        for (u32 i = 0; i < a->n && i < 64; i++) gz_arc_check_password(a, s, i, c);
        for (u32 i = 0; i < a->n; i++) {
            if (t->opened[i] && !t->closed[i]) t->bad = 1;
            gzch mw[96];
            gz_arc_method(a, &a->e[i], mw, 96);
            gz_src *v = gz_arc_view(a, s, i, c);
            if (v) {
                u8 b[512];
                u32 got;
                v->read_at(v, 0, b, sizeof b, &got);
                gz_src_free(v);
            }
        }
        if (t->bad) { printf("PROTO violation in fuzz case\n"); fflush(stdout); abort(); }
        c->password = 0;
        free_out(t);
        gz_arc_close(a);
    }
    gz_src_free(s);
    return r;
}

static int cmd_fuzz(const char *path, long iters, u64 seed)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *orig = (u8 *)malloc(n + 1), *buf = (u8 *)malloc(n + 1);
    if (fread(orig, 1, n, f) != (size_t)n) return 1;
    fclose(f);
    rng_state = seed * 2654435761u + 1;
    gz_ctx *c = gz_ctx_new();
    long opened = 0;
    for (long it = 0; it < iters; it++) {
        memcpy(buf, orig, n);
        size_t len = n;
        u32 kind = rnd() % 6;
        if (kind == 0) {
            len = rnd() % (n + 1);
        } else if (kind <= 2) {
            u32 flips = 1 + rnd() % (kind == 1 ? 2 : 16);
            for (u32 k = 0; k < flips; k++) { size_t p = rnd() % n; buf[p] ^= (u8)(1u << (rnd() % 8)); }
        } else if (kind == 3) {
            /* corrupt near the end (the header) */
            size_t span = n < 512 ? n : 512;
            for (u32 k = 0; k < 1 + rnd() % 8; k++) buf[n - 1 - rnd() % span] = (u8)rnd();
        } else if (kind == 4) {
            size_t p = rnd() % n, l = 1 + rnd() % 8;
            u8 v = (rnd() & 1) ? 0xFF : 0;
            for (size_t k = 0; k < l && p + k < (size_t)n; k++) buf[p + k] = v;
        } else {
            size_t p = rnd() % n;
            buf[p] = (u8)rnd();
            len = n - rnd() % (n < 64 ? n : 64);
        }
        if (!fuzz_one(buf, len, c)) opened++;
    }
    printf("FUZZ iters=%ld opened=%ld\n", iters, opened);
    gz_ctx_free(c);
    free(orig);
    free(buf);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    init_core();
    const char *cmd = argv[1], *path = argv[2];
    if (!strcmp(cmd, "fuzz")) {
        if (argc > 5) set_pw(argv[5]);
        return cmd_fuzz(path, argc > 3 ? atol(argv[3]) : 1000, argc > 4 ? strtoull(argv[4], 0, 10) : 1);
    }
    const char *pw = !strcmp(cmd, "l") || !strcmp(cmd, "pw") || !strcmp(cmd, "bench") ? (argc > 3 ? argv[3] : 0)
                   : (argc > 4 ? argv[4] : 0);
    set_pw(pw);
    gz_src *src = gz_posix_open_src(path);
    if (!src) { perror(path); return 1; }
    gz_ctx *c = gz_ctx_new();
    gz_archive *a = 0;
    int r = open_arc_src(src, path, &a, c);
    if (r) { printf("OPEN_ERROR %d\n", r); gz_src_free(src); gz_ctx_free(c); return 1; }
    if (g_pw[0]) c->password = g_pw;
    else if (a->password) c->password = a->password;
    int rc = 0;
    if (!strcmp(cmd, "l")) {
        rc = cmd_list(a);
    } else if (!strcmp(cmd, "sel") || !strcmp(cmd, "one")) {
        if (argc < 6) return 2;
        t_out *t = new_out(a->n, strcmp(argv[3], "-") ? argv[3] : 0);     /* "-": CRC only */
        u8 *sel = parse_sel(argv[5], a->n);
        if (!strcmp(cmd, "sel")) {
            r = gz_arc_extract_solid(a, src, sel, &t->o, c);
            printf("RESULT %d\n", r);
        } else {
            for (u32 i = 0; i < a->n; i++) {
                if (!sel[i]) continue;
                r = gz_arc_extract(a, src, i, &t->o, c);
                if (!t->opened[i]) printf("%u\t%d\tunopened\n", i, r);
                else if (r != t->st[i]) printf("PROTO ret %u %d %d\n", i, r, t->st[i]);
            }
        }
        report(a, t);
        free(sel);
        free_out(t);
    } else if (!strcmp(cmd, "pw")) {
        for (u32 i = 0; i < a->n; i++) printf("%u\t%d\n", i, gz_arc_check_password(a, src, i, c));
    } else if (!strcmp(cmd, "view")) {
        u32 idx = (u32)atoi(argv[3]);
        gz_src *v = idx < a->n ? gz_arc_view(a, src, idx, c) : 0;
        if (!v) printf("NOVIEW\n");
        else {
            u8 *b = (u8 *)malloc(1 << 16);
            u32 crc = 0;
            u64 off = 0;
            while (off < v->size) {
                u32 n = v->size - off < (1 << 16) ? (u32)(v->size - off) : (1 << 16);
                if (gz_src_read_exact(v, off, b, n)) break;
                crc = gz_crc32(crc, b, n);
                off += n;
            }
            printf("VIEW %llu %08X\n", (unsigned long long)off, crc);
            free(b);
            gz_src_free(v);
        }
    } else if (!strcmp(cmd, "bench")) {
        int reps = argc > 4 ? atoi(argv[4]) : 1;
        double best = 1e9;
        u64 bytes = 0;
        for (int k = 0; k < reps; k++) {
            t_out *t = new_out(a->n, 0);
            u8 *sel = (u8 *)malloc(a->n + 1);
            memset(sel, 1, a->n);
            double t0 = now();
            if (a->solid) gz_arc_extract_solid(a, src, sel, &t->o, c);
            else for (u32 i = 0; i < a->n; i++) gz_arc_extract(a, src, i, &t->o, c);
            double dt = now() - t0;
            for (u32 i = 0; i < a->n; i++) if (t->opened[i] && t->st[i]) { printf("ERR %u %d\n", i, t->st[i]); rc = 1; }
            if (dt < best) best = dt;
            bytes = t->bytes;
            free(sel);
            free_out(t);
        }
        printf("BENCH bytes=%llu sec=%.4f MBps=%.1f\n", (unsigned long long)bytes, best, bytes / best / 1e6);
    }
    gz_arc_close(a);
    gz_src_free(src);
    gz_ctx_free(c);
    return rc;
}
