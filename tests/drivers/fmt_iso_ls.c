/*
 * fmt_iso_ls - ISO / UDF reader checks that gzt does not cover
 *
 *   fmt_iso_ls ls <image>        n  is_dir  usize  attr(hex)  mode(oct)  is_aux  is_link  mtime(unix)  name  link
 *   fmt_iso_ls crc <image>       n  status  usize  crc32  name   (streamed: works for files > 4 GiB)
 *   fmt_iso_ls view <image> <n> <off> <len>    hex bytes read through gz_arc_view
 *   fmt_iso_ls viewcheck <image> compare every file's view (random chunk sizes) with its extraction
 *
 * First line: TYPE <type> <entries>. Exit code 1 when the image does not open.
 */
#include "arc.h"
#include "cpu.h"
#include "crc32.h"
#include "plat_posix.h"
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

static void utf8(const gzch *w, char *o, size_t cap)
{
    size_t n = gz_wcslen(w);
    if (n * 3 + 1 > cap) n = (cap - 1) / 3;
    o[gz_utf16_to_utf8(w, n, (u8 *)o)] = 0;
}

typedef struct { gz_out o; u32 crc; u64 n; u8 *mem; size_t cap; int status; } sink;

static int s_open(gz_out *o, u32 idx) { (void)idx; sink *s = (sink *)o; s->crc = 0; s->n = 0; return 0; }
static int s_write(gz_out *o, const u8 *p, size_t n)
{
    sink *s = (sink *)o;
    s->crc = gz_crc32(s->crc, p, n);
    if (s->mem) {
        if (s->n + n > s->cap) return GZ_E_LIMIT;
        memcpy(s->mem + s->n, p, n);
    }
    s->n += n;
    return 0;
}
static int s_close(gz_out *o, u32 idx, int st) { (void)idx; ((sink *)o)->status = st; return 0; }

int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    init_core();
    gz_src *src = gz_posix_open_src(argv[2]);
    if (!src) { perror(argv[2]); return 1; }
    gz_ctx *c = gz_ctx_new();
    gz_archive *a = 0;
    gz_open_opts oo;
    memset(&oo, 0, sizeof oo);
    int r = gz_arc_open(&a, src, &oo, c);
    if (r) {
        printf("OPEN_ERROR %d\n", r);
        gz_ctx_free(c);
        gz_src_free(src);
        return 1;
    }
    printf("TYPE\t%s\t%u\n", gz_arc_type_name(a), a->n);
    char nm[8192];
    if (!strcmp(argv[1], "ls")) {
        for (u32 i = 0; i < a->n; i++) {
            gz_entry *e = &a->e[i];
            utf8(e->name, nm, sizeof nm);
            char lk[4096] = "";
            if (e->is_link && e->link_len) {
                u32 n = e->link_len < sizeof lk - 1 ? e->link_len : (u32)sizeof lk - 1;
                memcpy(lk, a->raw + e->link_off, n);
                lk[n] = 0;
            }
            long long mt = e->mtime_kind == GZ_MT_FILETIME ? (long long)gz_filetime_to_unix(e->mtime) : -1;
            unsigned frac = e->mtime_kind == GZ_MT_FILETIME ? (unsigned)(e->mtime % 10000000u) : 0;
            printf("%u\t%d\t%llu\t%x\t%o\t%d\t%d\t%lld.%07u\t%s\t%s\n", i, e->is_dir, (unsigned long long)e->usize, e->attr,
                   e->unix_mode, e->is_aux, e->is_link, mt, frac, nm, lk);
        }
    } else if (!strcmp(argv[1], "crc")) {
        sink s = { { s_open, s_write, s_close, 0 }, 0, 0, 0, 0, 0 };
        for (u32 i = 0; i < a->n; i++) {
            s.status = -1;
            s.crc = 0;
            s.n = 0;
            int rr = gz_arc_extract(a, src, i, &s.o, c);
            utf8(a->e[i].name, nm, sizeof nm);
            printf("%u\t%d\t%llu\t%08x\t%s\n", i, rr ? rr : s.status, (unsigned long long)s.n, s.crc, nm);
        }
    } else if (!strcmp(argv[1], "view") && argc >= 6) {
        u32 idx = (u32)atoi(argv[3]);
        u64 off = strtoull(argv[4], 0, 0);
        u32 len = (u32)atoi(argv[5]);
        gz_src *v = idx < a->n ? gz_arc_view(a, src, idx, c) : 0;
        if (!v) { printf("NOVIEW\n"); return 1; }
        u8 *b = malloc(len + 1);
        u32 got = 0;
        int rr = v->read_at(v, off, b, len, &got);
        printf("SIZE %llu RC %d GOT %u\n", (unsigned long long)v->size, rr, got);
        for (u32 i = 0; i < got; i++) printf("%02x", b[i]);
        printf("\n");
        free(b);
        gz_src_free(v);
    } else if (!strcmp(argv[1], "viewcheck")) {
        unsigned ok = 0, bad = 0;
        srand(1);
        for (u32 i = 0; i < a->n; i++) {
            gz_entry *e = &a->e[i];
            if (e->is_dir || e->is_link || e->usize > (64u << 20)) continue;
            sink s = { { s_open, s_write, s_close, 0 }, 0, 0, 0, 0, 0 };
            s.cap = (size_t)e->usize + 1;
            s.mem = malloc(s.cap);
            int rr = gz_arc_extract(a, src, i, &s.o, c);
            gz_src *v = gz_arc_view(a, src, i, c);
            int good = !rr && v && v->size == e->usize && s.n == e->usize;
            u8 *b = malloc((size_t)e->usize + 1);
            u64 pos = 0;
            while (good && pos < e->usize) {
                u32 want = 1 + (u32)(rand() % 70000);
                u32 got = 0;
                if (v->read_at(v, pos, b, want, &got) || !got) { good = 0; break; }
                if (got > want || memcmp(b, s.mem + pos, got)) good = 0;
                pos += got;
            }
            if (good && e->usize) {                       /* random access */
                for (int k = 0; k < 20 && good; k++) {
                    u64 o = (u64)rand() % e->usize;
                    u32 want = 1 + (u32)(rand() % 5000), got = 0;
                    if (v->read_at(v, o, b, want, &got)) good = 0;
                    else if (memcmp(b, s.mem + o, got) || got != (e->usize - o < want ? e->usize - o : want)) good = 0;
                }
            }
            utf8(e->name, nm, sizeof nm);
            if (good) ok++; else { bad++; printf("VIEW_BAD\t%u\t%s\n", i, nm); }
            free(b);
            free(s.mem);
            gz_src_free(v);
        }
        printf("VIEW_OK %u BAD %u\n", ok, bad);
    }
    gz_arc_close(a);
    gz_src_free(src);
    gz_ctx_free(c);
    return 0;
}
