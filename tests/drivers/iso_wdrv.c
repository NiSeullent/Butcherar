/*
 * iso_wdrv - drives the ISO writer (gz_write_archive, GZ_WF_ISO) from a spec file
 *
 *   iso_wdrv <out.iso> <spec>
 *
 * spec: one item or option per line, fields separated by TAB (UTF-8):
 *   opt  label    <text>          volume label (o->label)
 *   opt  onerror  skip|abort|none  on_error returns GZ_OK / GZ_E_IO / is NULL
 *   opt  cancel   <bytes>         raise the cancel flag once progress reaches this
 *   opt  sparse   1               leave all-zero 4 KiB blocks of the output as holes
 *   opt  wide     1               later names/targets are hex UTF-16 units ("0041d800")
 *   t <base> <rel>                item from disk (lstat: directory, file or symlink)
 *   d <mode> <mtime> <attr> <name>
 *   l <mode> <mtime> <attr> <target> <name>
 *   v <mode> <mtime> <attr> <size> <name>              virtual pattern file (pat())
 *   s <mode> <mtime> <attr> <size> <actual> <name>     announces size, gives actual
 *   e <mode> <mtime> <attr> <size> <name>              open_item fails (GZ_E_IO)
 *   r <mode> <mtime> <attr> <size> <failat> <name>     read fails after failat bytes
 * mode is octal (0 = derive), mtime Unix seconds (-1 = unknown).
 * Prints "ERR <idx> <code>" per on_error call, "PROG <calls> <done> <total> <monotonic>",
 * "OPENS <open_item calls> CLOSES <close_item calls>" and "CREATE <rc> <bytes>".
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

#define EXT 0xFFFFF800ull

/* deterministic content: sparse-friendly pattern (zero outside a few windows) */
static unsigned char pat(unsigned long long o, unsigned long long size)
{
    int win = (o & ((1ull << 30) - 1)) < 65536 || (o + 65536 >= EXT && o < EXT + 65536) || o + 65536 >= size;
    return win ? (unsigned char)((o * 7 + (o >> 11) * 13 + 1) & 0xFF) : 0;
}

/* does [a, b) touch a non-zero window of pat()? */
static int overlaps(unsigned long long a, unsigned long long b, unsigned long long size)
{
    unsigned long long k = a >> 30;
    if (a < (k << 30) + 65536 || ((b - 1) >> 30) != k) return 1;
    if (a < EXT + 65536 && b > EXT - 65536) return 1;
    return b + 65536 > size;
}

typedef struct {
    char kind;
    unsigned long long size, actual, failat;
    char *path;
} spec_item;

typedef struct { gz_wsrc w; spec_item *s; FILE *f; unsigned long long pos; } drv_src;

static int src_read(gz_wsrc *w, u8 *buf, u32 cap, u32 *got)
{
    drv_src *d = (drv_src *)w;
    *got = 0;
    if (d->f) {
        size_t r = fread(buf, 1, cap, d->f);
        *got = (u32)r;
        return ferror(d->f) ? GZ_E_IO : GZ_OK;
    }
    unsigned long long end = d->s->kind == 's' ? d->s->actual : d->s->size;
    if (d->s->kind == 'r' && d->pos >= d->s->failat) return GZ_E_IO;
    if (d->s->kind == 'r' && end > d->s->failat) end = d->s->failat;
    unsigned long long n = end > d->pos ? end - d->pos : 0;
    if (n > cap) n = cap;
    /* zero regions of big virtual files are filled block-wise */
    unsigned long long o = d->pos;
    for (unsigned long long i = 0; i < n;) {
        unsigned long long blk = 4096 - ((o + i) & 4095);
        if (blk > n - i) blk = n - i;
        if (!overlaps(o + i, o + i + blk, d->s->size)) memset(buf + i, 0, blk);
        else for (unsigned long long j = 0; j < blk; j++) buf[i + j] = pat(o + i + j, d->s->size);
        i += blk;
    }
    d->pos += n;
    *got = (u32)n;
    return GZ_OK;
}

static int g_opens, g_closes;
static int open_item(void *user, const gz_witem *it, gz_wsrc **src)
{
    (void)user;
    spec_item *s = (spec_item *)it->user;
    g_opens++;
    if (s->kind == 'e') return GZ_E_IO;
    drv_src *d = (drv_src *)calloc(1, sizeof *d);
    d->s = s;
    if (s->kind == 't') {
        d->f = fopen(s->path, "rb");
        if (!d->f) { free(d); return GZ_E_IO; }
    }
    d->w.read = src_read;
    *src = &d->w;
    return GZ_OK;
}

static void close_item(void *user, const gz_witem *it, gz_wsrc *src)
{
    (void)user; (void)it;
    drv_src *d = (drv_src *)src;
    if (d->f) fclose(d->f);
    free(d);
    g_closes++;
}

static int g_onerror = 0;   /* 0 skip, 1 abort, 2 none */
static const gz_witem *g_items;
static int on_error(void *user, const gz_witem *it, int err)
{
    (void)user;
    printf("ERR %d %d\n", (int)(it - g_items), err);
    return g_onerror == 1 ? GZ_E_IO : GZ_OK;
}

static unsigned long long g_cancel_at, g_last_done, g_total;
static long g_prog_calls;
static int g_monotonic = 1;
static volatile long g_cancel;
static void progress(void *user, u64 done, u64 total)
{
    (void)user;
    if (done < g_last_done || done > total) g_monotonic = 0;
    g_last_done = done;
    g_total = total;
    g_prog_calls++;
    if (g_cancel_at && done >= g_cancel_at) g_cancel = 1;
}

/* output: plain or sparse (all-zero aligned 4 KiB blocks are skipped) */
typedef struct { int fd; int sparse; unsigned long long end; } out_t;
static int k_write(gz_sink *k, const void *p, size_t n)
{
    out_t *o = (out_t *)k->h;
    const unsigned char *b = (const unsigned char *)p;
    unsigned long long off = k->pos;
    size_t i = 0;
    while (i < n) {
        size_t blk = 4096 - (size_t)((off + i) & 4095);
        if (blk > n - i) blk = n - i;
        int zero = 0;
        if (o->sparse && blk == 4096) {
            zero = 1;
            for (size_t j = 0; j < blk; j++) if (b[i + j]) { zero = 0; break; }
        }
        if (!zero && pwrite(o->fd, b + i, blk, (off_t)(off + i)) != (ssize_t)blk) return GZ_E_IO;
        i += blk;
    }
    if (off + n > o->end) o->end = off + n;
    return GZ_OK;
}

static int g_wide;
static gzch *name_of(const char *s)                /* UTF-8, or hex UTF-16 units (opt wide) */
{
    if (!g_wide) return gz_posix_wide(s);
    size_t n = strlen(s) / 4, k = 0;
    gzch *w = (gzch *)calloc(n + 1, sizeof(gzch));
    for (size_t i = 0; i < n; i++) {
        char h[5] = { s[4 * i], s[4 * i + 1], s[4 * i + 2], s[4 * i + 3], 0 };
        unsigned v = (unsigned)strtoul(h, 0, 16);
        if (v) w[k++] = (gzch)v;
    }
    w[k] = 0;
    return w;
}

static char *field(char **p)
{
    char *s = *p, *t = strchr(s, '\t');
    if (t) { *t = 0; *p = t + 1; } else *p = s + strlen(s);
    return s;
}

int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    gz_cpu_detect();
    gz_crc32_init();
    gz_dispatch_init(-1);
    FILE *sf = fopen(argv[2], "rb");
    if (!sf) { perror(argv[2]); return 2; }
    gz_witem *it = (gz_witem *)calloc(1u << 20, sizeof(gz_witem));
    u32 n = 0;
    gz_wopts o;
    memset(&o, 0, sizeof o);
    o.format = GZ_WF_ISO;
    o.open_item = open_item;
    o.close_item = close_item;
    o.on_error = on_error;
    o.progress = progress;
    o.cancel = &g_cancel;
    int sparse = 0;
    static char line[1 << 16];
    while (fgets(line, sizeof line, sf)) {
        size_t L = strlen(line);
        while (L && (line[L - 1] == '\n' || line[L - 1] == '\r')) line[--L] = 0;
        if (!L) continue;
        char *p = line, *k = field(&p);
        if (!strcmp(k, "opt")) {
            char *name = field(&p), *val = field(&p);
            if (!strcmp(name, "label")) o.label = gz_posix_wide(val);
            else if (!strcmp(name, "onerror")) {
                g_onerror = !strcmp(val, "abort") ? 1 : !strcmp(val, "none") ? 2 : 0;
                if (g_onerror == 2) o.on_error = 0;
            } else if (!strcmp(name, "cancel")) g_cancel_at = strtoull(val, 0, 10);
            else if (!strcmp(name, "sparse")) sparse = atoi(val);
            else if (!strcmp(name, "wide")) g_wide = atoi(val);
            continue;
        }
        spec_item *s = (spec_item *)calloc(1, sizeof *s);
        gz_witem *w = &it[n];
        s->kind = k[0];
        if (s->kind == 't') {
            char *base = field(&p), *rel = field(&p);
            s->path = (char *)malloc(strlen(base) + strlen(rel) + 2);
            sprintf(s->path, "%s/%s", base, rel);
            struct stat st;
            if (lstat(s->path, &st)) { perror(s->path); return 2; }
            w->name = gz_posix_wide(rel);
            w->mtime = gz_unix_to_filetime(st.st_mtime);
            w->unix_mode = st.st_mode;
            w->is_dir = S_ISDIR(st.st_mode);
            w->attr = w->is_dir ? 0x10 : 0x20;
            if (S_ISLNK(st.st_mode)) {
                char tgt[8192];
                ssize_t r = readlink(s->path, tgt, sizeof tgt - 1);
                tgt[r < 0 ? 0 : r] = 0;
                w->is_link = 1;
                w->link_target = gz_posix_wide(tgt);
            } else if (S_ISREG(st.st_mode)) {
                w->size = (u64)st.st_size;
            }
        } else {
            unsigned mode = (unsigned)strtoul(field(&p), 0, 8);
            long long mt = strtoll(field(&p), 0, 10);
            unsigned attr = (unsigned)strtoul(field(&p), 0, 0);
            w->unix_mode = mode;
            w->mtime = mt == -1 ? 0 : gz_unix_to_filetime(mt);
            w->attr = attr;
            if (s->kind == 'd') w->is_dir = 1;
            else if (s->kind == 'l') { w->is_link = 1; w->link_target = name_of(field(&p)); }
            else {
                s->size = strtoull(field(&p), 0, 10);
                if (s->kind == 's') s->actual = strtoull(field(&p), 0, 10);
                if (s->kind == 'r') s->failat = strtoull(field(&p), 0, 10);
                w->size = s->size;
            }
            w->name = name_of(field(&p));
        }
        w->user = s;
        n++;
    }
    fclose(sf);
    g_items = it;
    out_t ot = { open(argv[1], O_RDWR | O_CREAT | O_TRUNC, 0644), sparse, 0 };
    if (ot.fd < 0) { perror(argv[1]); return 2; }
    gz_sink k = { k_write, 0, 0, &ot };            /* append only: no write_at */
    int r = gz_write_archive(&o, it, n, &k, 0);
    if (ftruncate(ot.fd, (off_t)ot.end)) r = r ? r : GZ_E_IO;
    close(ot.fd);
    printf("PROG %ld %llu %llu %d\n", g_prog_calls, g_last_done, g_total, g_monotonic);
    printf("OPENS %d CLOSES %d\n", g_opens, g_closes);
    printf("CREATE %d %llu\n", r, (unsigned long long)k.pos);
    for (u32 i = 0; i < n; i++) {                  /* leak-free, so LeakSanitizer checks the writer */
        spec_item *s = (spec_item *)it[i].user;
        free((void *)it[i].name);
        free((void *)it[i].link_target);
        free(s->path);
        free(s);
    }
    free(it);
    free((void *)o.label);
    return r ? 1 : 0;
}
