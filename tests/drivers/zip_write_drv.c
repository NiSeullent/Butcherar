/*
 * ZIP writer test driver (tests/cases/writer_zip.py).
 *
 *   zip_write_drv c [opts] out.zip basedir rel...   files from disk (lstat: symlinks are kept)
 *   zip_write_drv many [opts] out.zip N             N virtual small files in folders of 1000
 *   zip_write_drv big [opts] out.zip SIZE [NAFTER]  one virtual file of SIZE zero bytes, then
 *                                                   NAFTER small files (their headers land after it);
 *                                                   zero runs become holes of a sparse output
 *   zip_write_drv verify archive [pw] [cp]          our reader: every entry into a CRC sink
 *                                                   (prints idx status size crc name)
 *   zip_write_drv fuzz SEED COUNT                   random items, options, read errors, changing
 *                                                   files and failing sinks; every archive that
 *                                                   was written is checked with our reader
 *
 * opts: -m store|deflate|bzip2|lzma|ppmd|default  -l level  -e none|zc|aes  -p password
 *       -L legacy names   -s streaming sink (no write_at)   -H size hints 0 (unknown)
 *       -d dict   -E rel:N read error after N bytes   -G rel content changes on the 2nd open
 *       -a on_error aborts   -t atime/ctime from stat   -c N cancel after N progress bytes
 * Prints CREATE <result>, PROGRESS <done> <total> <calls> <monotonic>, ONERR <name> <err>.
 */
#define _FILE_OFFSET_BITS 64      /* 32-bit builds: large files, 64-bit inodes, */
#define _TIME_BITS 64             /* times after 2038 */
#include "gz_write.h"
#include "arc.h"
#include "cpu.h"
#include "crc32.h"
#include "plat_posix.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#ifdef __APPLE__
#define NSEC(st, f) ((st).f##timespec.tv_nsec)
#else
#define NSEC(st, f) ((st).f##tim.tv_nsec)
#endif

/* ---------------- items ---------------- */

typedef struct ditem {
    char *path;            /* disk file, or NULL: virtual                         */
    u64 vsize;             /* virtual: size                                        */
    u32 seed;              /* virtual: content seed                                */
    int kind;              /* virtual: 0 zeros, 1 text, 2 random, 3 text+random    */
    u64 fail_at;           /* read error after this many bytes (~0 = never)        */
    int change2;           /* content differs from the 2nd open on                 */
    int opens, fail_open;  /* open count; fail_open: open_item fails               */
    int errs;              /* on_error calls                                       */
    u32 crc; u64 n;        /* CRC / size of what the last open delivered           */
} ditem;

typedef struct dsrc {
    gz_wsrc w;
    ditem *d;
    FILE *f;
    u64 pos;
    u32 rng;
    int changed;
    const char *word; u32 wl;  /* text: rest of the current word */
} dsrc;

static u32 xs(u32 *s) { u32 x = *s; x ^= x << 13; x ^= x >> 17; x ^= x << 5; return *s = x ? x : 0x9E3779B9u; }

static const char *const k_words[] = { "고기", "삼겹살", "zip", "archive", "목살", "hello ", "world\n", "갈비 ", "data ",
                                       "the ", "quick ", "brown ", "fox " };

/* virtual content byte stream (deterministic per seed and position, generated in order) */
static void gen(dsrc *s, u8 *buf, u32 n)
{
    ditem *d = s->d;
    for (u32 i = 0; i < n; i++) {
        u64 p = s->pos + i;
        u8 b;
        int k = d->kind == 3 ? ((p >> 16) & 1 ? 2 : 1) : d->kind;
        if (k == 0) b = 0;
        else if (k == 2) b = (u8)xs(&s->rng);
        else {
            if (!s->wl) { s->word = k_words[xs(&s->rng) % (sizeof k_words / sizeof *k_words)]; s->wl = (u32)strlen(s->word); }
            b = (u8)*s->word++;
            s->wl--;
        }
        buf[i] = b;
    }
    if (s->changed && n && s->pos == 0) buf[0] ^= 0x5A;
}

static int ds_read(gz_wsrc *w, u8 *buf, u32 cap, u32 *got)
{
    dsrc *s = (dsrc *)w;
    ditem *d = s->d;
    *got = 0;
    if (d->fail_at != ~(u64)0 && s->pos >= d->fail_at) return GZ_E_IO;
    u32 want = cap;
    if (d->fail_at != ~(u64)0 && d->fail_at - s->pos < want) want = (u32)(d->fail_at - s->pos);
    u32 g;
    if (s->f) {
        g = (u32)fread(buf, 1, want, s->f);
        if (ferror(s->f)) return GZ_E_IO;
        if (s->changed && g && s->pos == 0) buf[0] ^= 0x5A;
    } else {
        u64 left = d->vsize - s->pos;
        g = left < want ? (u32)left : want;
        if (d->kind == 0) {
            memset(buf, 0, g);
            if (s->changed && g && s->pos == 0) buf[0] ^= 0x5A;
        } else {
            gen(s, buf, g);
        }
    }
    s->pos += g;
    d->crc = gz_crc32(d->crc, buf, g);
    d->n += g;
    *got = g;
    return GZ_OK;
}

static int open_item(void *user, const gz_witem *it, gz_wsrc **src)
{
    (void)user;
    ditem *d = (ditem *)it->user;
    d->opens++;
    if (d->fail_open) return GZ_E_IO;
    dsrc *s = (dsrc *)calloc(1, sizeof *s);
    s->w.read = ds_read;
    s->d = d;
    s->rng = d->seed * 2654435761u + 1;
    s->changed = d->change2 && d->opens >= 2;
    if (d->path) {
        s->f = fopen(d->path, "rb");
        if (!s->f) { free(s); return GZ_E_IO; }
    }
    d->crc = 0;
    d->n = 0;
    *src = &s->w;
    return GZ_OK;
}

static void close_item(void *user, const gz_witem *it, gz_wsrc *src)
{
    (void)user; (void)it;
    dsrc *s = (dsrc *)src;
    if (s->f) fclose(s->f);
    free(s);
}

static int g_abort_on_error, g_quiet;
static int on_error(void *user, const gz_witem *it, int err)
{
    (void)user;
    ditem *d = (ditem *)it->user;
    if (d) d->errs++;
    if (!g_quiet) {
        char *n = gz_posix_utf8(it->name);
        printf("ONERR %s %d\n", n, err);
        free(n);
    }
    return g_abort_on_error ? err : GZ_OK;
}

static u64 g_pdone, g_ptotal, g_pcalls, g_cancel_at = ~(u64)0;
static int g_pmono = 1;
static volatile long g_cancel;
static void on_progress(void *user, u64 done, u64 total)
{
    (void)user;
    if (done < g_pdone || (g_pcalls && total != g_ptotal)) g_pmono = 0;
    g_pdone = done;
    g_ptotal = total;
    g_pcalls++;
    if (done >= g_cancel_at) g_cancel = 1;
}

/* ---------------- sinks ---------------- */

typedef struct fsink { gz_sink k; int fd; u64 end; int sparse; } fsink;

static int fk_write(gz_sink *k, const void *p, size_t n)
{
    fsink *s = (fsink *)k;
    const u8 *b = (const u8 *)p;
    int zero = s->sparse && n >= 65536;
    for (size_t i = 0; zero && i < 4096; i++) if (b[i] || b[n - 1 - i]) zero = 0;
    if (zero) {
        if (lseek(s->fd, (off_t)n, SEEK_CUR) < 0) return GZ_E_IO;
    } else {
        size_t done = 0;
        while (done < n) {
            ssize_t w = write(s->fd, b + done, n - done);
            if (w <= 0) return GZ_E_IO;
            done += (size_t)w;
        }
    }
    s->end += n;
    return GZ_OK;
}

static int fk_write_at(gz_sink *k, u64 off, const void *p, size_t n)
{
    fsink *s = (fsink *)k;
    if (off + n > s->end) return GZ_E_IO;           /* never past what was appended */
    return pwrite(s->fd, p, n, (off_t)off) == (ssize_t)n ? GZ_OK : GZ_E_IO;
}

/* ---------------- options ---------------- */

typedef struct dopts {
    gz_wopts o;
    int stream, hints0, atimes;
    const char *err_rel; u64 err_at;
    const char *chg_rel;
    gzch *pw;
} dopts;

static int method_id(const char *s)
{
    static const char *const n[] = { "default", "store", "deflate", "deflate64", "bzip2", "lzma", "lzma2", "ppmd", "zstd" };
    for (int i = 0; i < GZ_WM_COUNT; i++) if (!strcmp(s, n[i])) return i;
    return atoi(s);
}

static void init_core(void)
{
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_aes_init();
    gz_dispatch_init(-1);
}

/* parse options from argv[*i]; returns 0 when the options end */
static int parse_opt(dopts *d, int argc, char **argv, int *i)
{
    const char *a = argv[*i];
    if (a[0] != '-' || !a[1]) return 0;
    const char *v = *i + 1 < argc ? argv[*i + 1] : "";
    switch (a[1]) {
    case 'm': d->o.method = method_id(v); break;
    case 'l': d->o.level = atoi(v); break;
    case 'e': d->o.encryption = !strcmp(v, "zc") ? GZ_WE_ZIPCRYPTO : !strcmp(v, "aes") ? GZ_WE_AES256 : GZ_WE_NONE; break;
    case 'p': d->pw = gz_posix_wide(v); d->o.password = d->pw; break;
    case 'd': d->o.dict_size = (u32)strtoul(v, 0, 0); break;
    case 'E': { const char *c = strrchr(v, ':'); d->err_rel = strndup(v, (size_t)(c - v)); d->err_at = strtoull(c + 1, 0, 0); break; }
    case 'G': d->chg_rel = v; break;
    case 'c': g_cancel_at = strtoull(v, 0, 0); break;
    case 'L': d->o.legacy_names = 1; return 1;
    case 's': d->stream = 1; return 1;
    case 'H': d->hints0 = 1; return 1;
    case 'a': g_abort_on_error = 1; return 1;
    case 't': d->atimes = 1; return 1;
    default: fprintf(stderr, "bad option %s\n", a); exit(2);
    }
    (*i)++;
    return 1;
}

/* names, link targets and paths are malloc'ed; frees everything (LeakSanitizer stays quiet) */
static void free_items(dopts *d, gz_witem *it, ditem *di, u32 n)
{
    for (u32 k = 0; k < n; k++) {
        free((void *)it[k].name);
        free((void *)it[k].link_target);
        free(di[k].path);
    }
    free(it);
    free(di);
    free(d->pw);
    free((void *)d->err_rel);
}

static int run_write(dopts *d, const char *out, gz_witem *it, u32 n, int sparse)
{
    d->o.format = GZ_WF_ZIP;
    d->o.open_item = open_item;
    d->o.close_item = close_item;
    d->o.on_error = on_error;
    d->o.progress = on_progress;
    d->o.cancel = &g_cancel;
    int fd = open(out, O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (fd < 0) { perror(out); return 1; }
    fsink k;
    memset(&k, 0, sizeof k);
    k.k.write = fk_write;
    k.k.write_at = d->stream ? 0 : fk_write_at;
    k.fd = fd;
    k.sparse = sparse;
    int r = gz_write_archive(&d->o, it, n, &k.k, 0);
    if (ftruncate(fd, (off_t)k.end)) r = r ? r : GZ_E_IO;
    close(fd);
    printf("CREATE %d size=%llu\n", r, (unsigned long long)k.k.pos);
    printf("PROGRESS %llu %llu %llu %d\n", (unsigned long long)g_pdone, (unsigned long long)g_ptotal,
           (unsigned long long)g_pcalls, g_pmono);
    return r ? 1 : 0;
}

/* ---------------- c: files from disk ---------------- */

static int cmd_c(int argc, char **argv)
{
    dopts d;
    memset(&d, 0, sizeof d);
    d.o.level = 5;
    int i = 2;
    for (; i < argc && parse_opt(&d, argc, argv, &i); i++) {}
    if (argc - i < 2) return 2;
    const char *out = argv[i++], *base = argv[i++];
    u32 n = (u32)(argc - i);
    gz_witem *it = (gz_witem *)calloc(n + 1, sizeof(gz_witem));
    ditem *di = (ditem *)calloc(n + 1, sizeof(ditem));
    for (u32 k = 0; k < n; k++) {
        const char *rel = argv[i + k];
        char *full = (char *)malloc(strlen(base) + strlen(rel) + 2);
        sprintf(full, "%s/%s", base, rel);
        struct stat st;
        if (lstat(full, &st)) { perror(full); return 1; }
        di[k].path = full;
        di[k].fail_at = ~(u64)0;
        if (d.err_rel && !strcmp(d.err_rel, rel)) di[k].fail_at = d.err_at;
        if (d.chg_rel && !strcmp(d.chg_rel, rel)) di[k].change2 = 1;
        it[k].name = gz_posix_wide(rel);
        it[k].size = S_ISREG(st.st_mode) && !d.hints0 ? (u64)st.st_size : 0;
        it[k].mtime = gz_unix_to_filetime(st.st_mtime) + (u64)NSEC(st, st_m) / 100;
        if (d.atimes) {
            it[k].atime = gz_unix_to_filetime(st.st_atime) + (u64)NSEC(st, st_a) / 100;
            it[k].ctime = gz_unix_to_filetime(st.st_ctime) + (u64)NSEC(st, st_c) / 100;
        }
        it[k].unix_mode = st.st_mode;
        it[k].is_dir = S_ISDIR(st.st_mode);
        it[k].attr = it[k].is_dir ? 0x10 : 0x20;
        if (S_ISLNK(st.st_mode)) {
            char t[4096];
            ssize_t tl = readlink(full, t, sizeof t - 1);
            if (tl < 0) { perror(full); return 1; }
            t[tl] = 0;
            it[k].is_link = 1;
            it[k].link_target = gz_posix_wide(t);
        }
        it[k].user = &di[k];
    }
    init_core();
    int r = run_write(&d, out, it, n, 0);
    free_items(&d, it, di, n);
    return r;
}

/* ---------------- many: N virtual small files ---------------- */

static int cmd_many(int argc, char **argv)
{
    dopts d;
    memset(&d, 0, sizeof d);
    d.o.level = 1;
    int i = 2;
    for (; i < argc && parse_opt(&d, argc, argv, &i); i++) {}
    if (argc - i < 2) return 2;
    const char *out = argv[i];
    u32 n = (u32)strtoul(argv[i + 1], 0, 0);
    u32 ndir = (n + 999) / 1000;
    gz_witem *it = (gz_witem *)calloc((size_t)n + ndir, sizeof(gz_witem));
    ditem *di = (ditem *)calloc((size_t)n + ndir, sizeof(ditem));
    u32 m = 0;
    for (u32 k = 0; k < n; k++) {
        char nm[64];
        if (k % 1000 == 0) {
            snprintf(nm, sizeof nm, "d%03u", k / 1000);
            it[m].name = gz_posix_wide(nm);
            it[m].is_dir = 1;
            it[m].attr = 0x10;
            it[m].mtime = gz_unix_to_filetime(1700000000);
            it[m].user = &di[m];
            m++;
        }
        snprintf(nm, sizeof nm, "d%03u/f%06u.txt", k / 1000, k);
        di[m].kind = 1;
        di[m].seed = k + 1;
        di[m].vsize = k % 7;
        di[m].fail_at = ~(u64)0;
        it[m].name = gz_posix_wide(nm);
        it[m].size = di[m].vsize;
        it[m].attr = 0x20;
        it[m].mtime = gz_unix_to_filetime(1700000000 + k);
        it[m].user = &di[m];
        m++;
    }
    init_core();
    int r = run_write(&d, out, it, m, 0);
    free_items(&d, it, di, m);
    return r;
}

/* ---------------- big: one huge virtual zero file ---------------- */

static int cmd_big(int argc, char **argv)
{
    dopts d;
    memset(&d, 0, sizeof d);
    d.o.level = 1;
    int i = 2;
    for (; i < argc && parse_opt(&d, argc, argv, &i); i++) {}
    if (argc - i < 2) return 2;
    const char *out = argv[i];
    u64 size = strtoull(argv[i + 1], 0, 0);
    u32 after = argc - i > 2 ? (u32)atoi(argv[i + 2]) : 0;
    gz_witem *it = (gz_witem *)calloc(after + 2, sizeof(gz_witem));
    ditem *di = (ditem *)calloc(after + 2, sizeof(ditem));
    it[0].name = gz_posix_wide("huge.bin");
    it[0].size = d.hints0 ? 0 : size;
    it[0].mtime = gz_unix_to_filetime(1600000000);
    it[0].attr = 0x20;
    it[0].user = &di[0];
    di[0].vsize = size;
    di[0].fail_at = ~(u64)0;
    for (u32 k = 1; k <= after; k++) {
        char nm[32];
        snprintf(nm, sizeof nm, "after%u.txt", k);
        it[k].name = gz_posix_wide(nm);
        di[k].kind = 1;
        di[k].seed = k;
        di[k].vsize = 1000 * k;
        di[k].fail_at = ~(u64)0;
        it[k].size = di[k].vsize;
        it[k].mtime = gz_unix_to_filetime(1600000000);
        it[k].attr = 0x20;
        it[k].user = &di[k];
    }
    init_core();
    int r = run_write(&d, out, it, after + 1, 1);
    printf("ITEM0 %llu %08x\n", (unsigned long long)di[0].n, di[0].crc);
    free_items(&d, it, di, after + 1);
    return r;
}

/* ---------------- verify: our reader ---------------- */

typedef struct vout { gz_out o; u32 crc; u64 n; } vout;
static int v_open(gz_out *o, u32 idx) { vout *v = (vout *)o; (void)idx; v->crc = 0; v->n = 0; return GZ_OK; }
static int v_write(gz_out *o, const u8 *p, size_t n) { vout *v = (vout *)o; v->crc = gz_crc32(v->crc, p, n); v->n += n; return GZ_OK; }
static int v_close(gz_out *o, u32 idx, int st) { (void)o; (void)idx; (void)st; return GZ_OK; }

static int verify_src(gz_src *src, const gzch *pw, int cp, int print, gz_archive **pa, u32 **crcs, int **sts)
{
    gz_ctx *c = gz_ctx_new();
    gz_open_opts oo;
    memset(&oo, 0, sizeof oo);
    oo.codepage = cp;
    oo.password = pw;
    gz_archive *a = 0;
    int r = gz_arc_open(&a, src, &oo, c);
    if (r) { if (print) printf("OPEN_ERROR %d\n", r); gz_ctx_free(c); return r; }
    c->password = pw;
    if (print) printf("TYPE %s %u\n", gz_arc_type_name(a), a->n);
    vout v;
    memset(&v, 0, sizeof v);
    v.o.open = v_open; v.o.write = v_write; v.o.close = v_close;
    if (crcs) { *crcs = (u32 *)calloc(a->n + 1, sizeof(u32)); *sts = (int *)calloc(a->n + 1, sizeof(int)); }
    for (u32 i = 0; i < a->n; i++) {
        v.crc = 0; v.n = 0;
        int st = gz_arc_extract(a, src, i, &v.o, c);
        if (crcs) { (*crcs)[i] = v.crc; (*sts)[i] = st; }
        if (print) {
            char *nm = gz_posix_utf8(a->e[i].name);
            printf("%u\t%d\t%llu\t%08x\t%s\n", i, st, (unsigned long long)v.n, v.crc, nm);
            free(nm);
        }
    }
    gz_ctx_free(c);
    if (pa) *pa = a;
    else gz_arc_close(a);
    return GZ_OK;
}

static int cmd_verify(int argc, char **argv)
{
    if (argc < 3) return 2;
    init_core();
    gz_src *src = gz_posix_open_src(argv[2]);
    if (!src) { perror(argv[2]); return 1; }
    gzch *pw = argc > 3 && argv[3][0] ? gz_posix_wide(argv[3]) : 0;
    int r = verify_src(src, pw, argc > 4 ? atoi(argv[4]) : 0, 1, 0, 0, 0);
    gz_src_free(src);
    free(pw);
    return r ? 1 : 0;
}

/* ---------------- fuzz ---------------- */

typedef struct msink { gz_sink k; u8 *p; size_t n, cap; u64 fail_at; int writes; } msink;
static int ms_write(gz_sink *k, const void *p, size_t n)
{
    msink *m = (msink *)k;
    m->writes++;
    if (m->n + n > m->fail_at) return GZ_E_DISK;
    if (m->n + n > m->cap) {
        size_t nc = m->cap ? m->cap : 65536;
        while (nc < m->n + n) nc *= 2;
        m->p = (u8 *)realloc(m->p, nc);
        m->cap = nc;
    }
    memcpy(m->p + m->n, p, n);
    m->n += n;
    return GZ_OK;
}
static int ms_write_at(gz_sink *k, u64 off, const void *p, size_t n)
{
    msink *m = (msink *)k;
    if (off + n > m->n) return GZ_E_IO;
    memcpy(m->p + off, p, n);
    return GZ_OK;
}

static const char *const k_frag[] = { "a", "dir", "한글", "テスト", "Ünï", "x y", "😀", "f.txt", "B.BIN", "깊은/폴더",
                                      "deep/sub", "é", "長い名前" };

static int cmd_fuzz(int argc, char **argv)
{
    if (argc < 4) return 2;
    u32 seed = (u32)strtoul(argv[2], 0, 0), count = (u32)strtoul(argv[3], 0, 0);
    init_core();
    g_quiet = 1;
    u32 rng = seed * 747796405u + 2891336453u;
    int bad = 0, written = 0, failed = 0;
    for (u32 iter = 0; iter < count; iter++) {
        u32 n = xs(&rng) % 12;
        gz_witem it[16];
        ditem di[16];
        static gzch names[16][256];
        memset(it, 0, sizeof it);
        memset(di, 0, sizeof di);
        for (u32 k = 0; k < n; k++) {
            char nm[200];
            int l = snprintf(nm, sizeof nm, "i%02u_", k);
            u32 parts = xs(&rng) % 3;
            for (u32 p = 0; p < parts && l < 150; p++)
                l += snprintf(nm + l, sizeof nm - l, "%s%s", p ? "/" : "", k_frag[xs(&rng) % (sizeof k_frag / sizeof *k_frag)]);
            gzch *w = gz_posix_wide(nm);
            size_t wl = 0;
            for (; w[wl] && wl < 255; wl++) names[k][wl] = w[wl];
            names[k][wl] = 0;
            free(w);
            it[k].name = names[k];
            u32 t = xs(&rng) % 16;
            it[k].mtime = t == 0 ? 0 : t == 1 ? gz_unix_to_filetime(-100000000) : t == 2 ? gz_unix_to_filetime((i64)1 << 33)
                                                                               : gz_unix_to_filetime(1500000000 + xs(&rng) % 300000000);
            it[k].atime = xs(&rng) & 1 ? it[k].mtime + 12345 : 0;
            it[k].unix_mode = xs(&rng) & 1 ? 0100644 : 0;
            it[k].attr = xs(&rng) % 4 == 0 ? 0x21 : 0x20;
            it[k].user = &di[k];
            di[k].fail_at = ~(u64)0;
            u32 kind = xs(&rng) % 10;
            if (kind == 0) { it[k].is_dir = 1; it[k].attr = 0x10; continue; }
            if (kind == 1) { it[k].is_link = 1; it[k].link_target = names[(k + 1) % 16][0] ? names[(k + 1) % 16] : u"target"; continue; }
            u32 sz = xs(&rng) % 8;
            di[k].vsize = sz < 3 ? xs(&rng) % 40 : sz < 6 ? xs(&rng) % 70000 : sz < 7 ? xs(&rng) % 600000
                                                                    : (4u << 20) - 1000 + xs(&rng) % 300000;
            di[k].kind = (int)(xs(&rng) % 4);
            di[k].seed = xs(&rng);
            u32 h = xs(&rng) % 8;
            it[k].size = h == 0 ? 0 : h == 1 ? di[k].vsize / 2 : h == 2 ? di[k].vsize + 1000 : di[k].vsize;
            u32 f = xs(&rng) % 16;
            if (f == 0) di[k].fail_at = xs(&rng) % (di[k].vsize + 1);
            if (f == 1) di[k].fail_open = 1;
            if (f == 2) di[k].change2 = 1;
        }
        dopts d;
        memset(&d, 0, sizeof d);
        static const int meth[] = { GZ_WM_DEFAULT, GZ_WM_STORE, GZ_WM_DEFLATE, GZ_WM_DEFLATE, GZ_WM_BZIP2, GZ_WM_LZMA, GZ_WM_PPMD };
        d.o.method = meth[xs(&rng) % 7];
        d.o.level = (int)(xs(&rng) % 4);
        d.o.encryption = (int)(xs(&rng) % 3);
        d.o.password = d.o.encryption ? u"비밀 pw" : 0;
        d.o.legacy_names = xs(&rng) & 1;
        d.o.format = GZ_WF_ZIP;
        d.o.open_item = open_item;
        d.o.close_item = close_item;
        d.o.on_error = on_error;
        d.o.progress = on_progress;
        g_abort_on_error = xs(&rng) % 8 == 0;
        msink m;
        memset(&m, 0, sizeof m);
        m.k.write = ms_write;
        m.k.write_at = xs(&rng) % 3 == 0 ? 0 : ms_write_at;
        m.fail_at = xs(&rng) % 10 == 0 ? xs(&rng) % 300000 : ~(u64)0;
        g_pdone = g_ptotal = g_pcalls = 0;
        g_pmono = 1;
        int r = gz_write_archive(&d.o, it, n, &m.k, 0);
        if (!g_pmono) { printf("iter %u: progress not monotonic\n", iter); bad++; }
        if (r) {
            failed++;
            int expected = m.fail_at != ~(u64)0 || g_abort_on_error;
            if (!expected) { printf("iter %u: write failed %d\n", iter, r); bad++; }
            free(m.p);
            continue;
        }
        written++;
        if (m.k.pos != m.n) { printf("iter %u: pos %llu != size %zu\n", iter, (unsigned long long)m.k.pos, m.n); bad++; }
        gz_src *src = gz_src_mem(m.p, m.n, 0);
        gz_archive *a = 0;
        u32 *crcs = 0;
        int *sts = 0;
        int vr = verify_src(src, d.o.password, 0, 0, &a, &crcs, &sts);
        if (vr) { printf("iter %u: reader cannot open (%d)\n", iter, vr); bad++; gz_src_free(src); free(m.p); continue; }
        /* every item is in the archive with the data its last open delivered, or was reported */
        u8 seen[16] = { 0 };
        for (u32 e = 0; e < a->n; e++) {
            const gzch *nm = a->e[e].name;
            if (nm[0] != 'i' || nm[3] != '_') continue;
            u32 k = (u32)((nm[1] - '0') * 10 + (nm[2] - '0'));
            if (k >= n) { printf("iter %u: bad entry\n", iter); bad++; continue; }
            if (seen[k]++) continue;            /* folder entries implied by deeper names */
            if (it[k].is_dir || it[k].is_link) continue;
            int st = sts[e];
            if (st == GZ_E_METHOD) continue;    /* reader without this method */
            if (st || crcs[e] != di[k].crc || a->e[e].usize != di[k].n) {
                printf("iter %u: entry %u (item %u) st=%d crc %08x/%08x size %llu/%llu errs=%d\n", iter, e, k, st,
                       crcs[e], di[k].crc, (unsigned long long)a->e[e].usize, (unsigned long long)di[k].n, di[k].errs);
                bad++;
            }
        }
        for (u32 k = 0; k < n; k++)
            if (!seen[k] && !di[k].errs && !it[k].is_dir) {
                printf("iter %u: item %u missing without error\n", iter, k);
                bad++;
            }
        free(crcs);
        free(sts);
        gz_arc_close(a);
        gz_src_free(src);
        free(m.p);
    }
    printf("FUZZ written=%d failed=%d bad=%d\n", written, failed, bad);
    return bad ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "c")) return cmd_c(argc, argv);
    if (!strcmp(argv[1], "many")) return cmd_many(argc, argv);
    if (!strcmp(argv[1], "big")) return cmd_big(argc, argv);
    if (!strcmp(argv[1], "verify")) return cmd_verify(argc, argv);
    if (!strcmp(argv[1], "fuzz")) return cmd_fuzz(argc, argv);
    return 2;
}
