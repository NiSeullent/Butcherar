/*
 * apfs_drv - test driver for the APFS reader (tests/cases/fmt_apfs.py)
 *
 *   apfs_drv l <img>            TYPE, COMMENT, then per entry:
 *        idx is_dir is_link usize csize mtime_kind mtime attr mode aux aux32 flags method name [-> target]
 *   apfs_drv x <img>            extract every entry in memory: idx status size crc32 name
 *   apfs_drv v <img>            per file: extraction CRC vs CRC of its view read in shuffled chunks
 *   apfs_drv n <img> <name>     open the entry as a nested archive through its view
 *   apfs_drv fuzz <img> <iters> <seed>
 *        in-process mutations (bit flips / boundary values in checksummed blocks, then the
 *        Fletcher-64 checksum is fixed so the parser sees the damage; raw flips; truncation),
 *        each variant listed, fully extracted and viewed. Prints a summary.
 *   apfs_drv bench <img> <reps> open + extract all entries reps times, prints MB/s
 */
#include "arc.h"
#include "cpu.h"
#include "crc32.h"
#include "plat_posix.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

typedef struct { gz_out o; u32 crc; u64 n; } crc_out;
static int c_open(gz_out *o, u32 idx) { crc_out *c = (crc_out *)o; c->crc = 0; c->n = 0; (void)idx; return 0; }
/* entries stop at 64 MiB (like a user cancelling a 5 EB sparse file a fuzzer made) */
#define OUT_CAP (64ull << 20)
static int c_write(gz_out *o, const u8 *p, size_t n)
{
    crc_out *c = (crc_out *)o;
    if (c->n + n > OUT_CAP) return GZ_E_LIMIT;
    c->crc = gz_crc32(c->crc, p, n);
    c->n += n;
    return 0;
}
static int c_close(gz_out *o, u32 idx, int st) { (void)o; (void)idx; return st; }

static u8 *load(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 0; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *p = (u8 *)malloc((size_t)sz + 1);
    if (fread(p, 1, (size_t)sz, f) != (size_t)sz) { fclose(f); free(p); return 0; }
    fclose(f);
    *n = (size_t)sz;
    return p;
}

static u32 view_crc(gz_src *v, u64 size, int *err)
{
    u8 *all = (u8 *)malloc((size_t)size + 1);
    u64 off = 0;
    u32 seed = 777;
    /* forward pass in odd-sized chunks, then a few random re-reads that must agree */
    while (off < size) {
        seed = seed * 1103515245u + 12345u;
        u64 n = 1 + (seed >> 8) % 70001;
        if (n > size - off) n = size - off;
        if (gz_src_read_exact(v, off, all + off, (u32)n)) { *err = 1; break; }
        off += n;
    }
    for (int k = 0; k < 16 && !*err && size; k++) {
        seed = seed * 1103515245u + 12345u;
        u64 o = ((u64)seed << 7) % size, n = 1 + (seed >> 3) % 9000;
        if (n > size - o) n = size - o;
        u8 tmp[9001];
        if (gz_src_read_exact(v, o, tmp, (u32)n) || memcmp(tmp, all + o, (size_t)n)) *err = 3;
    }
    u32 crc = *err ? 0 : gz_crc32(0, all, (size_t)size);
    u32 got = 1;
    u8 b[4];
    if (!*err && (v->read_at(v, size, b, 4, &got) || got)) *err = 2;
    free(all);
    return crc;
}

/* list + extract + view everything (fuzzing / bench); returns bytes extracted */
static u64 exercise(gz_src *src, gz_ctx *c, int views, int *opened)
{
    gz_archive *a;
    *opened = 0;
    if (gz_arc_open(&a, src, 0, c)) return 0;
    *opened = 1;
    crc_out o = { { c_open, c_write, c_close, 0 }, 0, 0 };
    u64 total = 0;
    gzch mw[96];
    for (u32 i = 0; i < a->n; i++) {
        gz_arc_method(a, &a->e[i], mw, 96);
        gz_arc_extract(a, src, i, &o.o, c);
        total += o.n;
        if (views && !a->e[i].is_dir) {
            gz_src *v = gz_arc_view(a, src, i, c);
            if (v) {
                if (v->size <= (8u << 20)) { int err = 0; view_crc(v, v->size, &err); }
                gz_src_free(v);
            }
        }
    }
    gz_arc_close(a);
    return total;
}

/* Fletcher-64 as APFS stores it */
static u64 fl64(const u8 *b, u32 n)
{
    u64 s1 = 0, s2 = 0;
    for (u32 i = 8; i < n; i += 4) {
        u32 w;
        memcpy(&w, b + i, 4);
        s1 = (s1 + w) % 0xFFFFFFFFu;
        s2 = (s2 + s1) % 0xFFFFFFFFu;
    }
    u64 c1 = 0xFFFFFFFFu - (s1 + s2) % 0xFFFFFFFFu;
    u64 c2 = 0xFFFFFFFFu - (s1 + c1) % 0xFFFFFFFFu;
    return c2 << 32 | c1;
}

static u32 rnd(u64 *s)
{
    *s = *s * 6364136223846793005ull + 1442695040888963407ull;
    return (u32)(*s >> 33);
}

static int cmd_fuzz(const char *path, int iters, u64 seed)
{
    size_t n;
    u8 *img = load(path, &n);
    if (!img || n < 4096) return 1;
    u32 bs = 4096;
    memcpy(&bs, img + 36, 4);
    if (bs < 4096 || bs > 65536 || (bs & (bs - 1))) bs = 4096;
    /* checksummed blocks = metadata objects */
    u32 nb = (u32)(n / bs), nmeta = 0;
    u32 *meta = (u32 *)malloc(sizeof(u32) * (nb + 1));
    for (u32 i = 0; i < nb; i++) {
        u64 ck;
        memcpy(&ck, img + (size_t)i * bs, 8);
        if (ck && ck == fl64(img + (size_t)i * bs, bs)) meta[nmeta++] = i;
    }
    u8 *m = (u8 *)malloc(n);
    gz_ctx *c = gz_ctx_new();
    int opened_n = 0;
    u64 bytes = 0;
    static const u64 vals[] = { 0, 1, 2, 3, 0xFF, 0xFFFF, 0x7FFF, 0x8000, 0xFFFFFFFFull, 0x80000000ull,
                                0xFFFFFFFFFFFFFFFFull, 0x7FFFFFFFFFFFFFFFull, 0x1000, 0x10000 };
    for (int it = 0; it < iters; it++) {
        memcpy(m, img, n);
        size_t len = n;
        u32 mode = rnd(&seed) % 10;
        if (mode == 9) {
            len = 4096 + rnd(&seed) % (n - 4096 + 1);
        } else if (mode == 8 || !nmeta) {
            for (int k = 0, cnt = 1 + rnd(&seed) % 16; k < cnt; k++) m[rnd(&seed) % n] ^= (u8)(1u << (rnd(&seed) % 8));
        } else {
            /* damage 1-3 metadata blocks, then fix their checksums */
            for (int b = 0, nbk = 1 + rnd(&seed) % 3; b < nbk; b++) {
                u32 blk = meta[rnd(&seed) % nmeta];
                u8 *p = m + (size_t)blk * bs;
                for (int k = 0, cnt = 1 + rnd(&seed) % 6; k < cnt; k++) {
                    u32 off = 8 + rnd(&seed) % (bs - 16);
                    u32 kind = rnd(&seed) % 4;
                    if (kind == 0) p[off] ^= (u8)(1u << (rnd(&seed) % 8));
                    else if (kind == 1) p[off] = (u8)rnd(&seed);
                    else {
                        u64 v = vals[rnd(&seed) % (sizeof vals / sizeof vals[0])];
                        u32 w = kind == 2 ? 2 : 8;
                        off &= ~(w - 1);
                        if (off + w <= bs) memcpy(p + off, &v, w);
                    }
                }
                u64 ck = fl64(p, bs);
                memcpy(p, &ck, 8);
            }
        }
        gz_src *s = gz_src_mem(m, len, 0);
        int op;
        bytes += exercise(s, c, 1, &op);
        opened_n += op;
        gz_src_free(s);
    }
    printf("FUZZ\t%d\t%d\t%llu\t%u\n", iters, opened_n, (unsigned long long)bytes, nmeta);
    gz_ctx_free(c);
    free(m);
    free(meta);
    free(img);
    return 0;
}

static int cmd_bench(const char *path, int reps)
{
    size_t n;
    u8 *img = load(path, &n);
    if (!img) return 1;
    gz_ctx *c = gz_ctx_new();
    gz_src *s = gz_src_mem(img, n, 0);
    struct timespec t0, t1;
    u64 bytes = 0;
    int op;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < reps; i++) bytes += exercise(s, c, 0, &op);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    /* listing only */
    struct timespec t2, t3;
    u32 ents = 0;
    clock_gettime(CLOCK_MONOTONIC, &t2);
    for (int i = 0; i < reps; i++) {
        gz_archive *a;
        if (!gz_arc_open(&a, s, 0, c)) { ents = a->n; gz_arc_close(a); }
    }
    clock_gettime(CLOCK_MONOTONIC, &t3);
    double sec = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    double lsec = (t3.tv_sec - t2.tv_sec) + (t3.tv_nsec - t2.tv_nsec) / 1e9;
    printf("BENCH\t%.1f MB/s\t%.3f s\t%u entries\tlist %.2f ms\n", bytes / 1e6 / sec, sec, ents, lsec * 1e3 / reps);
    gz_src_free(s);
    gz_ctx_free(c);
    free(img);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    init_core();
    if (!strcmp(argv[1], "fuzz") && argc > 4) return cmd_fuzz(argv[2], atoi(argv[3]), strtoull(argv[4], 0, 0));
    if (!strcmp(argv[1], "bench") && argc > 3) return cmd_bench(argv[2], atoi(argv[3]));
    gz_ctx *c = gz_ctx_new();
    gz_src *src = gz_posix_open_src(argv[2]);
    if (!src) { perror(argv[2]); return 1; }
    gz_archive *a;
    gz_open_opts oo;
    memset(&oo, 0, sizeof oo);
    if (getenv("GZ_NO_DESCEND")) oo.flags |= GZ_OPEN_NO_DESCEND;
    int r = gz_arc_open(&a, src, &oo, c);
    if (r) { printf("OPEN_ERROR %d\n", r); gz_src_free(src); gz_ctx_free(c); return 1; }
    char nm[8192], lk[4096], mt[300];
    gzch mw[96];
    const char *cmd = argv[1];
    int rc = 0;
    if (!strcmp(cmd, "l")) {
        printf("TYPE\t%s\t%u\n", gz_arc_type_name(a), a->n);
        if (a->comment) { to_utf8(a->comment, nm, sizeof nm); printf("COMMENT\t%s\n", nm); }
        for (u32 i = 0; i < a->n; i++) {
            gz_entry *e = &a->e[i];
            to_utf8(e->name, nm, sizeof nm);
            gz_arc_method(a, e, mw, 96);
            to_utf8(mw, mt, sizeof mt);
            lk[0] = 0;
            if (e->is_link && e->link_len) {
                u32 k = e->link_len < sizeof lk - 1 ? e->link_len : (u32)sizeof lk - 1;
                memcpy(lk, a->raw + e->link_off, k);
                lk[k] = 0;
            }
            printf("%u\t%d\t%d\t%llu\t%llu\t%d\t%llu\t%u\t%o\t%llu\t%u\t%u\t%s\t%s%s%s\n", i, e->is_dir, e->is_link,
                   (unsigned long long)e->usize, (unsigned long long)e->csize, e->mtime_kind,
                   (unsigned long long)e->mtime, e->attr, e->unix_mode, (unsigned long long)e->aux, e->aux32,
                   e->flags, mt, nm, lk[0] ? " -> " : "", lk);
        }
    } else if (!strcmp(cmd, "x")) {
        crc_out o = { { c_open, c_write, c_close, 0 }, 0, 0 };
        for (u32 i = 0; i < a->n; i++) {
            o.crc = 0; o.n = 0;
            int st = gz_arc_extract(a, src, i, &o.o, c);
            to_utf8(a->e[i].name, nm, sizeof nm);
            printf("%u\t%d\t%llu\t%08x\t%s\n", i, st, (unsigned long long)o.n, o.crc, nm);
        }
    } else if (!strcmp(cmd, "v")) {
        crc_out o = { { c_open, c_write, c_close, 0 }, 0, 0 };
        for (u32 i = 0; i < a->n; i++) {
            gz_entry *e = &a->e[i];
            if (e->is_dir || e->is_link) continue;
            int st = gz_arc_extract(a, src, i, &o.o, c);
            gz_src *v = gz_arc_view(a, src, i, c);
            int err = 0;
            u32 vc = 0;
            unsigned long long vs = 0;
            if (v) { vs = v->size; vc = view_crc(v, v->size, &err); gz_src_free(v); }
            to_utf8(e->name, nm, sizeof nm);
            printf("%u\t%d\t%llu\t%08x\t%s\t%llu\t%08x\t%d\t%s\n", i, st, (unsigned long long)o.n, o.crc,
                   v ? "view" : "noview", vs, vc, err, nm);
        }
    } else if (!strcmp(cmd, "n") && argc > 3) {
        i32 idx = -1;
        for (u32 i = 0; i < a->n && idx < 0; i++) {
            to_utf8(a->e[i].name, nm, sizeof nm);
            if (!strcmp(nm, argv[3])) idx = (i32)i;
        }
        gz_archive *ch = 0;
        r = idx >= 0 ? gz_arc_open_child(&ch, a, src, (u32)idx, 0, c) : GZ_E_FORMAT;
        if (r) { printf("CHILD_ERROR %d\n", r); rc = 1; }
        else {
            printf("TYPE\t%s\t%u\n", gz_arc_type_name(ch), ch->n);
            crc_out o = { { c_open, c_write, c_close, 0 }, 0, 0 };
            for (u32 k = 0; k < ch->n; k++) {
                if (ch->e[k].is_dir) continue;
                int st = gz_arc_extract(ch, src, k, &o.o, c);
                to_utf8(ch->e[k].name, nm, sizeof nm);
                printf("%u\t%d\t%llu\t%08x\t%s\n", k, st, (unsigned long long)o.n, o.crc, nm);
            }
            gz_arc_close(ch);
        }
    } else {
        rc = 2;
    }
    gz_arc_close(a);
    gz_src_free(src);
    gz_ctx_free(c);
    return rc;
}
