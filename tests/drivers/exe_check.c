/*
 * exe_check - test driver for the executable readers (PE/TE, ELF, Mach-O)
 *
 *   exe_check view <file>
 *       every entry: extract it, then read the view (sequential random-size chunks,
 *       random seeks, a read past the end) and compare. Prints "VIEW OK <n>".
 *   exe_check child <file> <entry-name> <outdir>
 *       open the entry as a nested archive (gz_arc_open_child, i.e. through view()),
 *       extract every entry to <outdir>/<n>.bin; prints TYPE and a manifest like "gzt x".
 *   exe_check fuzz <file> <iterations> <seed>
 *       mutate the file in memory (bit flips, special values, truncation; most of them in
 *       the headers, section tables and the resource directory), then open, extract
 *       everything and read views. Prints "FUZZ <iters> opened <n>"; fails when one open
 *       produces more output than a bound derived from the input size.
 */
#include "arc.h"
#include "cpu.h"
#include "crc32.h"
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

static u64 g_rng = 88172645463325252ull;
static u32 rnd(void)
{
    g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17;
    return (u32)(g_rng >> 11);
}

typedef struct { gz_out o; u8 *p; size_t n, cap, limit; int st; } m_out;
static int m_open(gz_out *o, u32 idx) { m_out *m = (m_out *)o; m->n = 0; m->st = -1; (void)idx; return 0; }
static int m_write(gz_out *o, const u8 *p, size_t n)
{
    m_out *m = (m_out *)o;
    if (m->limit && m->n + n > m->limit) return GZ_E_LIMIT;
    if (m->n + n > m->cap) {
        size_t nc = m->cap ? m->cap : 65536;
        while (nc < m->n + n) nc *= 2;
        m->p = (u8 *)realloc(m->p, nc);
        m->cap = nc;
    }
    memcpy(m->p + m->n, p, n);
    m->n += n;
    return 0;
}
static int m_close(gz_out *o, u32 idx, int st) { ((m_out *)o)->st = st; (void)idx; return 0; }

static void to_utf8(const gzch *w, char *o, size_t cap)
{
    size_t n = gz_wcslen(w);
    if (n * 3 + 1 > cap) n = (cap - 1) / 3;
    int k = gz_utf16_to_utf8(w, n, (u8 *)o);
    o[k] = 0;
}

static int read_view_all(gz_src *v, u8 *dst, u64 size)
{
    u64 off = 0;
    while (off < size) {
        u32 want = 1 + rnd() % 70000, got = 0;
        if (want > size - off) want = (u32)(size - off);
        if (v->read_at(v, off, dst + off, want, &got)) return 1;
        if (got != want) return 2;
        off += got;
    }
    return 0;
}

static int cmd_view(const char *path)
{
    gz_src *src = gz_posix_open_src(path);
    if (!src) { perror(path); return 1; }
    gz_ctx *c = gz_ctx_new();
    gz_archive *a;
    int r = gz_arc_open(&a, src, 0, c);
    if (r) { printf("OPEN_ERROR %d\n", r); return 1; }
    m_out m = { { m_open, m_write, m_close, 0 }, 0, 0, 0, 0, 0 };
    u32 checked = 0, bad = 0;
    char nm[4096];
    for (u32 i = 0; i < a->n; i++) {
        if (a->e[i].is_dir) continue;
        to_utf8(a->e[i].name, nm, sizeof nm);
        r = gz_arc_extract(a, src, i, &m.o, c);
        gz_src *v = gz_arc_view(a, src, i, c);
        if (!v) { printf("%u %s: no view\n", i, nm); bad++; continue; }
        if (r || m.st || v->size != m.n || m.n != a->e[i].usize) {
            printf("%u %s: status %d/%d size %llu/%llu/%llu\n", i, nm, r, m.st, (unsigned long long)v->size,
                   (unsigned long long)m.n, (unsigned long long)a->e[i].usize);
            bad++;
            gz_src_free(v);
            continue;
        }
        u8 *buf = (u8 *)malloc(m.n + 1);
        int e = read_view_all(v, buf, m.n);
        if (e || memcmp(buf, m.p, m.n)) { printf("%u %s: sequential mismatch %d\n", i, nm, e); bad++; }
        for (int k = 0; k < 32 && m.n && !e; k++) {
            u64 off = rnd() % m.n;
            u32 len = 1 + rnd() % 9000, got = 0;
            if (len > m.n - off) len = (u32)(m.n - off);
            memset(buf, 0, len);
            if (v->read_at(v, off, buf, len, &got) || got != len || memcmp(buf, m.p + off, len)) {
                printf("%u %s: seek mismatch at %llu+%u\n", i, nm, (unsigned long long)off, len);
                bad++;
                break;
            }
        }
        u32 got = 7;
        if (v->read_at(v, v->size, buf, 1, &got) || got) { printf("%u %s: read past end\n", i, nm); bad++; }
        free(buf);
        gz_src_free(v);
        checked++;
    }
    printf(bad ? "VIEW FAIL %u\n" : "VIEW OK %u\n", bad ? bad : checked);
    free(m.p);
    gz_arc_close(a);
    gz_src_free(src);
    gz_ctx_free(c);
    return bad ? 1 : 0;
}

static int cmd_child(const char *path, const char *name, const char *outdir)
{
    gz_src *src = gz_posix_open_src(path);
    if (!src) { perror(path); return 1; }
    gz_ctx *c = gz_ctx_new();
    gz_archive *a, *ch;
    int r = gz_arc_open(&a, src, 0, c);
    if (r) { printf("OPEN_ERROR %d\n", r); return 1; }
    char nm[8192];
    u32 idx = a->n;
    for (u32 i = 0; i < a->n; i++) {
        to_utf8(a->e[i].name, nm, sizeof nm);
        if (!strcmp(nm, name)) { idx = i; break; }
    }
    if (idx == a->n) { printf("NO_ENTRY\n"); return 1; }
    r = gz_arc_open_child(&ch, a, src, idx, 0, c);
    if (r) { printf("CHILD_ERROR %d\n", r); return 1; }
    printf("TYPE\t%s\t%u\n", gz_arc_type_name(ch), ch->n);
    mkdir(outdir, 0755);
    m_out m = { { m_open, m_write, m_close, 0 }, 0, 0, 0, 0, 0 };
    for (u32 i = 0; i < ch->n; i++) {
        r = gz_arc_extract(ch, src, i, &m.o, c);
        to_utf8(ch->e[i].name, nm, sizeof nm);
        printf("%u\t%d\t%d\t%llu\t%s\n", i, r ? r : m.st, ch->e[i].is_dir, (unsigned long long)m.n, nm);
        if (ch->e[i].is_dir) continue;
        char fp[4096];
        snprintf(fp, sizeof fp, "%s/%u.bin", outdir, i);
        FILE *f = fopen(fp, "wb");
        if (f) { fwrite(m.p, 1, m.n, f); fclose(f); }
    }
    free(m.p);
    gz_arc_close(ch);
    gz_arc_close(a);
    gz_src_free(src);
    gz_ctx_free(c);
    return 0;
}

/* ---- fuzzing ---- */

static const u32 k_special[] = { 0, 1, 2, 7, 0x10, 0x40, 0x1000, 0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000u,
                                 0x80000010u, 0xFFFFFFF0u, 0xFFFFFFFEu, 0xFFFFFFFFu };

static u64 g_hot[8][2];
static int g_nhot;

static void hot(u64 a, u64 b, size_t n)
{
    if (g_nhot >= 8 || a >= n) return;
    if (b > n) b = n;
    if (b <= a) return;
    g_hot[g_nhot][0] = a;
    g_hot[g_nhot][1] = b;
    g_nhot++;
}

/* structures the readers parse: headers, section/segment tables, resource directory */
static void find_hot(const u8 *p, size_t n)
{
    g_nhot = 0;
    hot(0, 1024, n);
    if (n >= 64 && p[0] == 'M' && p[1] == 'Z') {
        u32 lf = rd32(p + 0x3C);
        if (lf + 24 > n) return;
        u32 ns = rd16(p + lf + 6), opt = rd16(p + lf + 20);
        u64 st = (u64)lf + 24 + opt;
        hot(lf, st + 40 * (u64)ns, n);
        for (u32 i = 0; i < ns && st + 40 * (i + 1) <= n; i++) {
            const u8 *s = p + st + 40 * i;
            if (!memcmp(s, ".rsrc", 6)) hot(rd32(s + 20), (u64)rd32(s + 20) + 6144, n);
        }
    } else if (n >= 64 && rd32(p) == 0x464C457Fu && p[5] == 1) {
        u64 sh = p[4] == 2 ? rd64(p + 40) : rd32(p + 32);
        hot(sh, sh + 4096, n);
    }
}

static void mutate(u8 *p, size_t *pn)
{
    size_t n = *pn;
    int k = 1 + rnd() % 6;
    for (int i = 0; i < k && n > 2; i++) {
        u32 kind = rnd() % 10;
        size_t pos;
        if (rnd() % 4) {
            int h = (int)(rnd() % (u32)g_nhot);
            pos = (size_t)(g_hot[h][0] + rnd() % (g_hot[h][1] - g_hot[h][0]));
            if (pos < 2) pos = 2;
        } else {
            pos = 2 + rnd() % (n - 2);
        }
        if (pos >= n) continue;
        if (kind < 4) p[pos] ^= (u8)(1u << (rnd() & 7));
        else if (kind < 8 && (pos & ~(size_t)3) + 4 <= n && (pos & ~(size_t)3) >= 2)
            wr32(p + (pos & ~(size_t)3), rnd() % 3 ? k_special[rnd() % GZ_COUNTOF(k_special)] : rnd() % 256);
        else if (kind == 8) p[pos] = (u8)rnd();
        else if (rnd() % 4 == 0) n = 2 + rnd() % (n - 2);
    }
    *pn = n;
}

static int cmd_fuzz(const char *path, int iters, unsigned seed)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 1; }
    fseek(f, 0, SEEK_END);
    size_t n0 = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *orig = (u8 *)malloc(n0 + 1), *buf = (u8 *)malloc(n0 + 1);
    if (fread(orig, 1, n0, f) != n0) return 1;
    fclose(f);
    g_rng ^= (u64)seed * 0x9E3779B97F4A7C15ull;
    find_hot(orig, n0);
    gz_ctx *c = gz_ctx_new();
    m_out m = { { m_open, m_write, m_close, 0 }, 0, 0, 0, 0, 0 };
    int opened = 0, fail = 0;
    for (int it = 0; it < iters; it++) {
        memcpy(buf, orig, n0);
        size_t n = n0;
        mutate(buf, &n);
        gz_src *s = gz_src_mem(buf, n, 0);
        gz_archive *a;
        if (gz_arc_open(&a, s, 0, c)) { gz_src_free(s); continue; }
        opened++;
        /* file bytes are covered at most ~4x (budget) plus generated headers and texts */
        u64 total = 0, bound = 5 * (u64)n + (256u << 20);
        m.limit = (size_t)bound;
        for (u32 i = 0; i < a->n; i++) {
            gz_arc_extract(a, s, i, &m.o, c);
            total += m.n;
            gz_src *v = gz_arc_view(a, s, i, c);
            if (v) {
                u8 tmp[512];
                for (int k = 0; k < 4 && v->size; k++) {
                    u32 got;
                    v->read_at(v, rnd() % v->size, tmp, 1 + rnd() % 512, &got);
                }
                gz_src_free(v);
            }
        }
        if (total > bound) { printf("iteration %d: output %llu > bound %llu\n", it, (unsigned long long)total,
                                    (unsigned long long)bound); fail++; }
        gz_arc_close(a);
        gz_src_free(s);
    }
    printf("FUZZ %d opened %d%s\n", iters, opened, fail ? " FAIL" : "");
    free(m.p);
    free(orig);
    free(buf);
    gz_ctx_free(c);
    return fail ? 1 : 0;
}

int main(int argc, char **argv)
{
    init_core();
    if (argc >= 3 && !strcmp(argv[1], "view")) return cmd_view(argv[2]);
    if (argc >= 5 && !strcmp(argv[1], "child")) return cmd_child(argv[2], argv[3], argv[4]);
    if (argc >= 5 && !strcmp(argv[1], "fuzz")) return cmd_fuzz(argv[2], atoi(argv[3]), (unsigned)atoi(argv[4]));
    fprintf(stderr, "usage: exe_check view|child|fuzz ...\n");
    return 2;
}
