/*
 * ntfs_dump - test driver for the NTFS reader (tests/cases/fmt_ntfs.py)
 *
 *   ntfs_dump l <img>                 entries with metadata:
 *        idx is_dir is_link is_aux usize csize mtime_kind mtime attr method name [-> target]
 *   ntfs_dump v <img>                 every file: CRC of extraction vs. CRC of its view read
 *                                     in shuffled odd-sized chunks:
 *        idx status size crc_x view|noview view_size crc_v err name
 *   ntfs_dump x <img> <name>          stream one entry (no disk writes): status size crc
 *   ntfs_dump r <img> <name> <off> <len>...   read view ranges, print err crc of each
 *   ntfs_dump n <img> <name>          open the entry as a nested archive through its view,
 *                                     then idx status size crc name for every inner file
 *   ntfs_dump m <img> <threads>       extract every file from several threads at once (own
 *                                     source and context each, different orders) and compare
 *                                     with a single-threaded pass: "OK files" or mismatches
 *   ntfs_dump s <img> [cap_mb]        survival (hostile images): list, extract every entry and
 *                                     read every view, at most cap_mb MiB per entry (default 64)
 */
#include "arc.h"
#include "cpu.h"
#include "crc32.h"
#include "plat_posix.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void init_core(void)
{
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_aes_init();
    gz_dispatch_init(-1);
}

static void to_utf8(const gzch *w, char *o, size_t cap)
{
    size_t n = gz_wcslen(w);
    if (n * 3 + 1 > cap) n = (cap - 1) / 3;
    int k = gz_utf16_to_utf8(w, n, (u8 *)o);
    o[k] = 0;
}

typedef struct { gz_out o; u32 crc; u64 n, cap; } crc_out;
static int c_open(gz_out *o, u32 idx) { crc_out *c = (crc_out *)o; c->crc = 0; c->n = 0; (void)idx; return 0; }
static int c_write(gz_out *o, const u8 *p, size_t n)
{
    crc_out *c = (crc_out *)o;
    c->crc = gz_crc32(c->crc, p, n);
    c->n += n;
    return c->cap && c->n >= c->cap ? GZ_E_SKIP : 0;
}
static int c_close(gz_out *o, u32 idx, int st) { (void)o; (void)idx; return st; }

static int open_img(const char *path, gz_src **ps, gz_archive **pa, gz_ctx *c)
{
    gz_src *src = gz_posix_open_src(path);
    if (!src) { perror(path); return 1; }
    gz_open_opts oo;
    memset(&oo, 0, sizeof oo);
    gzch *w = gz_posix_wide(path);
    oo.file_name = w;
    int r = gz_arc_open(pa, src, &oo, c);
    free(w);
    if (r) { printf("OPEN_ERROR %d\n", r); gz_src_free(src); return 1; }
    *ps = src;
    return 0;
}

static i32 find(gz_archive *a, const char *name)
{
    char nm[8192];
    for (u32 i = 0; i < a->n; i++) {
        to_utf8(a->e[i].name, nm, sizeof nm);
        if (!strcmp(nm, name)) return (i32)i;
    }
    return -1;
}

static u32 view_crc(gz_src *v, u64 off, u64 len, int *err)
{
    static u8 buf[1 << 20];
    u32 crc = 0;
    while (len) {
        u32 n = len < sizeof buf ? (u32)len : (u32)sizeof buf;
        if (gz_src_read_exact(v, off, buf, n)) { *err = 1; return 0; }
        crc = gz_crc32(crc, buf, n);
        off += n; len -= n;
    }
    return crc;
}

/* read the whole view in shuffled chunks of odd sizes, CRC in order */
static u32 view_crc_shuffled(gz_src *v, u64 size, int *err)
{
    if (size > (64u << 20)) return view_crc(v, 0, size, err);
    u8 *all = (u8 *)malloc((size_t)size + 1);
    u64 cap = 1024, nch = 0, off = 0;
    u64 *offs = (u64 *)malloc(sizeof(u64) * cap);
    u32 seed = 12345;
    while (off < size) {
        seed = seed * 1103515245u + 12345u;
        if (nch + 1 >= cap) { cap *= 2; offs = (u64 *)realloc(offs, sizeof(u64) * cap); }
        offs[nch++] = off;
        off += 1 + (seed >> 8) % 70001;
    }
    u64 *ord = (u64 *)malloc(sizeof(u64) * (nch + 1));
    for (u64 i = 0; i < nch; i++) ord[i] = i;
    for (u64 i = nch; i > 1; i--) {
        seed = seed * 1103515245u + 12345u;
        u64 j = (seed >> 4) % i, t = ord[i - 1];
        ord[i - 1] = ord[j]; ord[j] = t;
    }
    for (u64 k = 0; k < nch; k++) {
        u64 i = ord[k];
        u64 o = offs[i], n = (i + 1 < nch ? offs[i + 1] : size) - o;
        if (gz_src_read_exact(v, o, all + o, (u32)n)) { *err = 1; break; }
    }
    u32 crc = *err ? 0 : gz_crc32(0, all, (size_t)size);
    u32 got = 1;
    u8 b[4];
    if (v->read_at(v, size, b, 4, &got) || got) *err = 2;     /* a read at the end returns nothing */
    free(all); free(offs); free(ord);
    return crc;
}

/* ---- multithreaded extraction ---- */

typedef struct {
    const char *path;
    gz_archive *a;
    u32 *ref_crc;
    u64 *ref_n;
    int *ref_st;
    u32 seed;
    int bad;
} mt_job;

static void *mt_run(void *p)
{
    mt_job *j = (mt_job *)p;
    gz_src *src = gz_posix_open_src(j->path);
    gz_ctx *c = gz_ctx_new();
    gz_archive *a = j->a;
    u32 *ord = (u32 *)malloc(sizeof(u32) * (a->n + 1));
    for (u32 i = 0; i < a->n; i++) ord[i] = i;
    u32 seed = j->seed;
    for (u32 i = a->n; i > 1; i--) {
        seed = seed * 1103515245u + 12345u;
        u32 k = (seed >> 4) % i, t = ord[i - 1];
        ord[i - 1] = ord[k]; ord[k] = t;
    }
    crc_out o = { { c_open, c_write, c_close, 0 }, 0, 0, 0 };
    for (u32 k = 0; k < a->n; k++) {
        u32 i = ord[k];
        if (a->e[i].is_dir) continue;
        int st = gz_arc_extract(a, src, i, &o.o, c);
        if (st != j->ref_st[i] || (!st && (o.crc != j->ref_crc[i] || o.n != j->ref_n[i]))) j->bad++;
    }
    free(ord);
    gz_ctx_free(c);
    gz_src_free(src);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    init_core();
    gz_ctx *c = gz_ctx_new();
    gz_src *src;
    gz_archive *a;
    if (open_img(argv[2], &src, &a, c)) { gz_ctx_free(c); return 1; }
    char nm[8192], lk[4096];
    const char *cmd = argv[1];
    int rc = 0;
    if (!strcmp(cmd, "l")) {
        printf("TYPE\t%s\t%u\n", gz_arc_type_name(a), a->n);
        if (a->comment) { to_utf8(a->comment, nm, sizeof nm); printf("COMMENT\t%s\n", nm); }
        for (u32 i = 0; i < a->n; i++) {
            gz_entry *e = &a->e[i];
            to_utf8(e->name, nm, sizeof nm);
            lk[0] = 0;
            if (e->is_link && e->link_len) {
                u32 n = e->link_len < sizeof lk - 1 ? e->link_len : (u32)sizeof lk - 1;
                memcpy(lk, a->raw + e->link_off, n);
                lk[n] = 0;
            }
            gzch mw[96];
            char m[300];
            gz_arc_method(a, e, mw, 96);
            to_utf8(mw, m, sizeof m);
            printf("%u\t%d\t%d\t%d\t%llu\t%llu\t%d\t%llu\t%u\t%s\t%s%s%s\n", i, e->is_dir, e->is_link, e->is_aux,
                   (unsigned long long)e->usize, (unsigned long long)e->csize, e->mtime_kind,
                   (unsigned long long)e->mtime, e->attr, m[0] ? m : "-", nm, lk[0] ? " -> " : "", lk);
        }
    } else if (!strcmp(cmd, "v")) {
        crc_out o = { { c_open, c_write, c_close, 0 }, 0, 0, 0 };
        for (u32 i = 0; i < a->n; i++) {
            gz_entry *e = &a->e[i];
            if (e->is_dir || e->is_link) continue;
            int st = gz_arc_extract(a, src, i, &o.o, c);
            gz_src *v = gz_arc_view(a, src, i, c);
            int err = 0;
            u32 vc = 0;
            unsigned long long vs = 0;
            if (v) { vs = v->size; vc = view_crc_shuffled(v, v->size, &err); gz_src_free(v); }
            to_utf8(e->name, nm, sizeof nm);
            printf("%u\t%d\t%llu\t%08x\t%s\t%llu\t%08x\t%d\t%s\n", i, st, (unsigned long long)o.n, o.crc,
                   v ? "view" : "noview", vs, vc, err, nm);
        }
    } else if (!strcmp(cmd, "x") && argc > 3) {
        i32 i = find(a, argv[3]);
        if (i < 0) { printf("NOTFOUND\n"); rc = 1; }
        else {
            crc_out o = { { c_open, c_write, c_close, 0 }, 0, 0, 0 };
            int st = gz_arc_extract(a, src, (u32)i, &o.o, c);
            printf("%d\t%llu\t%08x\n", st, (unsigned long long)o.n, o.crc);
        }
    } else if (!strcmp(cmd, "r") && argc > 3) {
        i32 i = find(a, argv[3]);
        gz_src *v = i >= 0 ? gz_arc_view(a, src, (u32)i, c) : 0;
        if (!v) { printf("NOVIEW\n"); rc = 1; }
        else {
            printf("SIZE\t%llu\n", (unsigned long long)v->size);
            for (int k = 4; k + 1 < argc; k += 2) {
                u64 off = strtoull(argv[k], 0, 0), len = strtoull(argv[k + 1], 0, 0);
                int err = 0;
                u32 crc = view_crc(v, off, len, &err);
                printf("%d\t%08x\n", err, crc);
            }
            gz_src_free(v);
        }
    } else if (!strcmp(cmd, "n") && argc > 3) {
        i32 i = find(a, argv[3]);
        gz_archive *ch = 0;
        int r = i >= 0 ? gz_arc_open_child(&ch, a, src, (u32)i, 0, c) : GZ_E_FORMAT;
        if (r) { printf("CHILD_ERROR %d\n", r); rc = 1; }
        else {
            printf("TYPE\t%s\t%u\n", gz_arc_type_name(ch), ch->n);
            crc_out o = { { c_open, c_write, c_close, 0 }, 0, 0, 0 };
            for (u32 k = 0; k < ch->n; k++) {
                if (ch->e[k].is_dir) continue;
                int st = gz_arc_extract(ch, src, k, &o.o, c);
                to_utf8(ch->e[k].name, nm, sizeof nm);
                printf("%u\t%d\t%llu\t%08x\t%s\n", k, st, (unsigned long long)o.n, o.crc, nm);
            }
            gz_arc_close(ch);
        }
    } else if (!strcmp(cmd, "m") && argc > 3) {
        int nt = atoi(argv[3]);
        if (nt < 1) nt = 1;
        if (nt > 64) nt = 64;
        u32 *crc = (u32 *)calloc(a->n + 1, sizeof(u32));
        u64 *len = (u64 *)calloc(a->n + 1, sizeof(u64));
        int *sts = (int *)calloc(a->n + 1, sizeof(int));
        crc_out o = { { c_open, c_write, c_close, 0 }, 0, 0, 0 };
        u32 files = 0;
        for (u32 i = 0; i < a->n; i++) {
            if (a->e[i].is_dir) continue;
            sts[i] = gz_arc_extract(a, src, i, &o.o, c);
            crc[i] = o.crc;
            len[i] = o.n;
            files++;
        }
        mt_job jobs[64];
        pthread_t th[64];
        for (int k = 0; k < nt; k++) {
            jobs[k] = (mt_job){ argv[2], a, crc, len, sts, 777u + 31u * (u32)k, 0 };
            pthread_create(&th[k], 0, mt_run, &jobs[k]);
        }
        int bad = 0;
        for (int k = 0; k < nt; k++) { pthread_join(th[k], 0); bad += jobs[k].bad; }
        if (bad) { printf("MISMATCH %d\n", bad); rc = 1; }
        else printf("OK %u\n", files);
        free(crc); free(len); free(sts);
    } else if (!strcmp(cmd, "s")) {
        u64 cap = (u64)(argc > 3 ? atoi(argv[3]) : 64) << 20;
        crc_out o = { { c_open, c_write, c_close, 0 }, 0, 0, cap };
        u32 ok = 0;
        for (u32 i = 0; i < a->n; i++) {
            gz_entry *e = &a->e[i];
            to_utf8(e->name, nm, sizeof nm);
            gzch mw[96];
            gz_arc_method(a, e, mw, 96);
            if (!gz_arc_extract(a, src, i, &o.o, c)) ok++;
            gz_src *v = gz_arc_view(a, src, i, c);
            if (v) {
                int err = 0;
                u64 n = v->size < cap ? v->size : cap;
                view_crc(v, 0, n, &err);
                if (v->size > 4096) view_crc(v, v->size - 4096, 4096, &err);
                gz_src_free(v);
            }
        }
        printf("SURVIVED %u %u\n", a->n, ok);
    } else {
        rc = 2;
    }
    gz_arc_close(a);
    gz_src_free(src);
    gz_ctx_free(c);
    return rc;
}
