/*
 * gzt - native test driver for the portable core
 *
 *   gzt x <archive> <outdir> [password] [codepage] [tier]
 *       extract every entry to <outdir>/<n>.bin and print a manifest:
 *       n <TAB> status <TAB> is_dir <TAB> size <TAB> utf8-name
 *       (stderr: type, counts, chosen code page and kernels)
 *   gzt l <archive> [codepage]
 *       list: n <TAB> is_dir <TAB> size <TAB> csize <TAB> method <TAB> mode <TAB> name [-> link]
 *   gzt c <format> <out> <level> <password|-> <basedir> <relpath>...
 *       create an archive from files under basedir (format: zip 7z tar tgz tbz2 txz tzst gz bz2 xz zst iso)
 *
 * Environment: GZ_TEST_ACP=949 (system code page), GZ_NO_DESCEND=1 (list image partitions).
 */
#include "arc.h"
#include "cpu.h"
#include "crc32.h"
#include "gz_write.h"
#include "plat_posix.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static void init_core(int tier)
{
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_aes_init();
    gz_dispatch_init(tier);
}

static void to_utf8(const gzch *w, char *o, size_t cap)
{
    size_t n = gz_wcslen(w);
    if (n * 3 + 1 > cap) n = (cap - 1) / 3;
    int k = gz_utf16_to_utf8(w, n, (u8 *)o);
    o[k] = 0;
}

typedef struct { gz_out o; const char *dir; FILE *f; int *status; u32 n; } t_out;

static int o_open(gz_out *o, u32 idx)
{
    t_out *t = (t_out *)o;
    char p[4096];
    snprintf(p, sizeof p, "%s/%u.bin", t->dir, idx);
    if (t->f) fclose(t->f);
    t->f = fopen(p, "wb");
    return t->f ? 0 : GZ_E_CREATE;
}
static int o_write(gz_out *o, const u8 *p, size_t n)
{
    t_out *t = (t_out *)o;
    if (!t->f) return GZ_E_IO;
    return fwrite(p, 1, n, t->f) == n ? 0 : GZ_E_IO;
}
static int o_close(gz_out *o, u32 idx, int st)
{
    t_out *t = (t_out *)o;
    if (t->f) fclose(t->f);
    t->f = 0;
    if (idx < t->n) t->status[idx] = st ? st : 100;   /* 100 = closed OK */
    return 0;
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

static int open_arc(const char *path, int cp, gz_src **ps, gz_archive **pa, gz_ctx *c)
{
    gz_src *src = gz_posix_open_src(path);
    if (!src) { perror(path); return 1; }
    gzch *wname = gz_posix_wide(path);
    gz_open_opts oo;
    memset(&oo, 0, sizeof oo);
    oo.codepage = cp;
    oo.file_name = wname;
    oo.password = g_pw[0] ? g_pw : 0;
    oo.ask_password = ask_pw;
    oo.open_volume = gz_posix_open_volume;
    if (getenv("GZ_NO_DESCEND")) oo.flags |= GZ_OPEN_NO_DESCEND;
    int r = gz_arc_open(pa, src, &oo, c);
    free(wname);
    if (r) { printf("OPEN_ERROR %d\n", r); gz_src_free(src); gz_ctx_free(c); return 1; }
    *ps = src;
    return 0;
}

static int cmd_x(int argc, char **argv)
{
    if (argc < 4) return 2;
    if (argc > 4 && argv[4][0]) {
        gzch *w = gz_posix_wide(argv[4]);
        size_t i = 0;
        for (; w[i] && i + 1 < GZ_COUNTOF(g_pw); i++) g_pw[i] = w[i];
        g_pw[i] = 0;
        free(w);
    }
    int cp = argc > 5 ? atoi(argv[5]) : 0;
    init_core(argc > 6 ? atoi(argv[6]) : -1);
    gz_ctx *c = gz_ctx_new();
    gz_src *src;
    gz_archive *a;
    if (open_arc(argv[2], cp, &src, &a, c)) return 1;
    fprintf(stderr, "type=%s entries=%u files=%u dirs=%u cp=%d inflate=%s crc=%s aes=%s\n", gz_arc_type_name(a), a->n,
            a->nfiles, a->ndirs, a->used_cp, gz_dispatch_inflate_name(), gz_dispatch_crc_name(), gz_dispatch_aes_name());
    mkdir(argv[3], 0755);
    t_out *o = (t_out *)calloc(1, sizeof(t_out));
    o->o.open = o_open; o->o.write = o_write; o->o.close = o_close; o->dir = argv[3];
    o->status = (int *)calloc(a->n + 1, sizeof(int));
    o->n = a->n;
    if (g_pw[0]) c->password = g_pw;
    else if (a->password) c->password = a->password;
    int r;
    if (a->solid) {
        u8 *sel = (u8 *)calloc(1, a->n + 1);
        memset(sel, 1, a->n);
        r = gz_arc_extract_solid(a, src, sel, &o->o, c);
        if (r) fprintf(stderr, "solid result %d\n", r);
        free(sel);
    } else {
        for (u32 i = 0; i < a->n; i++) {
            r = gz_arc_extract(a, src, i, &o->o, c);
            if (r && !o->status[i]) o->status[i] = r;
        }
    }
    char nm[8192];
    for (u32 i = 0; i < a->n; i++) {
        to_utf8(a->e[i].name, nm, sizeof nm);
        int s = o->status[i] == 100 ? 0 : (o->status[i] ? o->status[i] : -1);
        unsigned long long sz = a->e[i].usize == GZ_SIZE_UNKNOWN ? 0 : (unsigned long long)a->e[i].usize;
        printf("%u\t%d\t%d\t%llu\t%s\n", i, s, a->e[i].is_dir, sz, nm);
    }
    if (a->comment) { to_utf8(a->comment, nm, sizeof nm); fprintf(stderr, "comment: %s\n", nm); }
    gz_arc_close(a);
    gz_src_free(src);
    gz_ctx_free(c);
    free(o->status);
    free(o);
    return 0;
}

static int cmd_l(int argc, char **argv)
{
    if (argc < 3) return 2;
    init_core(-1);
    gz_ctx *c = gz_ctx_new();
    gz_src *src;
    gz_archive *a;
    if (open_arc(argv[2], argc > 3 ? atoi(argv[3]) : 0, &src, &a, c)) return 1;
    printf("TYPE\t%s\t%u\t%u\t%u\n", gz_arc_type_name(a), a->n, a->nfiles, a->ndirs);
    char nm[8192], lk[4096];
    for (u32 i = 0; i < a->n; i++) {
        gz_entry *e = &a->e[i];
        to_utf8(e->name, nm, sizeof nm);
        gzch mw[96];
        char m[300];
        gz_arc_method(a, e, mw, 96);
        to_utf8(mw, m, sizeof m);
        lk[0] = 0;
        if (e->is_link && e->link_len) {
            u32 n = e->link_len < sizeof lk - 1 ? e->link_len : (u32)sizeof lk - 1;
            memcpy(lk, a->raw + e->link_off, n);
            lk[n] = 0;
        }
        long long us = e->usize == GZ_SIZE_UNKNOWN ? -1 : (long long)e->usize;
        long long cs = e->csize == GZ_SIZE_UNKNOWN ? -1 : (long long)e->csize;
        printf("%u\t%d\t%lld\t%lld\t%s\t%o\t%s%s%s\n", i, e->is_dir, us, cs, m, e->unix_mode, nm,
               lk[0] ? " -> " : "", lk);
    }
    gz_arc_close(a);
    gz_src_free(src);
    gz_ctx_free(c);
    return 0;
}

/* ---- create ---- */

typedef struct { gz_wsrc w; FILE *f; } file_src;
static int fs_read(gz_wsrc *w, u8 *buf, u32 cap, u32 *got)
{
    file_src *f = (file_src *)w;
    size_t r = fread(buf, 1, cap, f->f);
    *got = (u32)r;
    return ferror(f->f) ? GZ_E_IO : GZ_OK;
}
static int open_item(void *user, const gz_witem *it, gz_wsrc **src)
{
    (void)user;
    file_src *f = (file_src *)calloc(1, sizeof(file_src));
    f->f = fopen((const char *)it->user, "rb");
    if (!f->f) { free(f); return GZ_E_IO; }
    f->w.read = fs_read;
    *src = &f->w;
    return GZ_OK;
}
static void close_item(void *user, const gz_witem *it, gz_wsrc *src)
{
    (void)user; (void)it;
    file_src *f = (file_src *)src;
    fclose(f->f);
    free(f);
}
static int k_write(gz_sink *k, const void *p, size_t n)
{
    return fwrite(p, 1, n, (FILE *)k->h) == n ? GZ_OK : GZ_E_IO;
}
static int k_write_at(gz_sink *k, u64 off, const void *p, size_t n)
{
    FILE *f = (FILE *)k->h;
    long cur = ftell(f);
    if (fseeko(f, (off_t)off, SEEK_SET)) return GZ_E_IO;
    int ok = fwrite(p, 1, n, f) == n;
    fseek(f, cur, SEEK_SET);
    return ok ? GZ_OK : GZ_E_IO;
}

static int fmt_id(const char *s)
{
    const char *names[] = { "", "zip", "7z", "tar", "tgz", "tbz2", "txz", "tzst", "gz", "bz2", "xz", "zst", "iso" };
    for (int i = 1; i < GZ_WF_COUNT; i++) if (!strcmp(s, names[i])) return i;
    return 0;
}

static int cmd_c(int argc, char **argv)
{
    if (argc < 8) return 2;
    init_core(-1);
    gz_wopts o;
    memset(&o, 0, sizeof o);
    o.format = fmt_id(argv[2]);
    o.level = atoi(argv[4]);
    gzch *pw = 0;
    if (strcmp(argv[5], "-")) { pw = gz_posix_wide(argv[5]); o.password = pw; o.encryption = GZ_WE_AES256; }
    if (getenv("GZ_METHOD")) o.method = atoi(getenv("GZ_METHOD"));
    if (getenv("GZ_ENC")) o.encryption = atoi(getenv("GZ_ENC"));
    if (getenv("GZ_SOLID")) o.solid = atoi(getenv("GZ_SOLID"));
    else o.solid = 1;
    if (getenv("GZ_ENC_NAMES")) o.encrypt_names = 1;
    o.open_item = open_item;
    o.close_item = close_item;
    const char *base = argv[6];
    u32 n = (u32)(argc - 7);
    gz_witem *it = (gz_witem *)calloc(n, sizeof(gz_witem));
    for (u32 i = 0; i < n; i++) {
        char *full = (char *)malloc(strlen(base) + strlen(argv[7 + i]) + 2);
        sprintf(full, "%s/%s", base, argv[7 + i]);
        struct stat st;
        if (lstat(full, &st)) { perror(full); return 1; }
        it[i].name = gz_posix_wide(argv[7 + i]);
        it[i].size = S_ISREG(st.st_mode) ? (u64)st.st_size : 0;
        it[i].mtime = gz_unix_to_filetime(st.st_mtime);
        it[i].unix_mode = st.st_mode;
        it[i].is_dir = S_ISDIR(st.st_mode);
        it[i].attr = it[i].is_dir ? 0x10 : 0x20;
        it[i].user = full;
    }
    FILE *f = fopen(argv[3], "w+b");
    if (!f) { perror(argv[3]); return 1; }
    gz_sink k = { k_write, k_write_at, 0, f };
    int r = gz_write_archive(&o, it, n, &k, 0);
    fclose(f);
    printf("CREATE %d\n", r);
    return r ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "x")) return cmd_x(argc, argv);
    if (!strcmp(argv[1], "l")) return cmd_l(argc, argv);
    if (!strcmp(argv[1], "c")) return cmd_c(argc, argv);
    return 2;
}
