/*
 * Native test driver for the archive layer.
 *   test_arc <archive> <outdir> [password] [codepage]
 * Extracts every entry to <outdir>/<n>.bin and prints a manifest:
 *   n <TAB> status <TAB> is_dir <TAB> size <TAB> utf8-name
 * Compile with -fshort-wchar so wchar_t matches Windows (UTF-16).
 */
#include "../src/core/arc.h"
#include "../src/core/cpu.h"
#include "../src/core/crc32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iconv.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

void *gz_alloc(size_t n) { return calloc(1, n); }
void *gz_realloc(void *p, size_t n) { return realloc(p, n); }
void gz_free(void *p) { free(p); }
void *gz_alloc_big(size_t n) { return calloc(1, n); }
void gz_free_big(void *p, size_t n) { (void)n; free(p); }

int gz_plat_acp(void) { return 949; }
int gz_plat_oemcp(void) { return 437; }
int gz_plat_cp_valid(int cp) { return cp == 949 || cp == 437 || cp == 932 || cp == 936 || cp == 1252 || cp == 65001; }
int gz_plat_mb2wc(int cp, const u8 *s, int n, wchar_t *out, int cap)
{
    char name[16];
    snprintf(name, sizeof name, "CP%d", cp);
    iconv_t ic = iconv_open("UTF-16LE", name);
    if (ic == (iconv_t)-1) return 0;
    char *in = (char *)s, *o = (char *)out;
    size_t inl = n, outl = (size_t)cap * 2;
    size_t r = iconv(ic, &in, &inl, &o, &outl);
    iconv_close(ic);
    if (r == (size_t)-1) return 0;
    return (int)(((size_t)cap * 2 - outl) / 2);
}

static void to_utf8(const wchar_t *w, char *o)
{
    for (; *w; w++) {
        unsigned c = (unsigned short)*w;
        if (c >= 0xD800 && c < 0xDC00 && w[1]) {
            c = 0x10000 + ((c - 0xD800) << 10) + ((unsigned short)w[1] - 0xDC00);
            w++;
        }
        if (c < 0x80) *o++ = (char)c;
        else if (c < 0x800) { *o++ = (char)(0xC0 | (c >> 6)); *o++ = (char)(0x80 | (c & 63)); }
        else if (c < 0x10000) { *o++ = (char)(0xE0 | (c >> 12)); *o++ = (char)(0x80 | ((c >> 6) & 63)); *o++ = (char)(0x80 | (c & 63)); }
        else { *o++ = (char)(0xF0 | (c >> 18)); *o++ = (char)(0x80 | ((c >> 12) & 63)); *o++ = (char)(0x80 | ((c >> 6) & 63)); *o++ = (char)(0x80 | (c & 63)); }
    }
    *o = 0;
}

static int f_read_at(gz_src *s, u64 off, void *buf, u32 n, u32 *got)
{
    ssize_t r = pread((int)(intptr_t)s->h, buf, n, (off_t)off);
    if (r < 0) return GZ_E_IO;
    *got = (u32)r;
    return 0;
}

typedef struct { gz_out o; const char *dir; FILE *f; int status[1 << 20]; } t_out;

static int o_open(gz_out *o, u32 idx)
{
    t_out *t = (t_out *)o;
    char p[4096];
    snprintf(p, sizeof p, "%s/%u.bin", t->dir, idx);
    t->f = fopen(p, "wb");
    return t->f ? 0 : GZ_E_CREATE;
}
static int o_write(gz_out *o, const u8 *p, size_t n)
{
    t_out *t = (t_out *)o;
    return fwrite(p, 1, n, t->f) == n ? 0 : GZ_E_IO;
}
static int o_close(gz_out *o, u32 idx, int st)
{
    t_out *t = (t_out *)o;
    if (t->f) fclose(t->f);
    t->f = 0;
    t->status[idx] = st ? st : 100;   /* 100 = closed OK */
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    gz_cpu_detect(); gz_crc32_init(); gz_inflate_init(); gz_aes_init();
    gz_dispatch_init(argc > 5 ? atoi(argv[5]) : -1);
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    struct stat st; fstat(fd, &st);
    gz_src src = { f_read_at, (u64)st.st_size, (void *)(intptr_t)fd };
    gz_inflater *z = gz_inflater_new();
    gz_archive *a;
    int cp = argc > 4 ? atoi(argv[4]) : 0;
    wchar_t wname[1024];
    {   int i = 0; for (const char *p = argv[1]; *p && i < 1000; p++) wname[i++] = (unsigned char)*p; wname[i] = 0; }
    int r = gz_arc_open(&a, &src, wname, cp, z, 0);
    if (r) { printf("OPEN_ERROR %d\n", r); return 1; }
    fprintf(stderr, "type=%s entries=%u files=%u dirs=%u cp=%d inflate=%s crc=%s aes=%s\n", gz_arc_type_name(a), a->n,
            a->nfiles, a->ndirs, a->used_cp, gz_dispatch_inflate_name(), gz_dispatch_crc_name(), gz_dispatch_aes_name());
    mkdir(argv[2], 0755);
    t_out *o = calloc(1, sizeof(t_out));
    o->o.open = o_open; o->o.write = o_write; o->o.close = o_close; o->dir = argv[2];
    const char *pw = argc > 3 && argv[3][0] ? argv[3] : 0;
    if (a->solid) {
        u8 *sel = calloc(1, a->n + 1);
        memset(sel, 1, a->n);
        r = gz_arc_extract_solid(a, &src, sel, &o->o, z, 0);
        if (r) fprintf(stderr, "solid result %d\n", r);
    } else {
        for (u32 i = 0; i < a->n; i++) {
            r = gz_arc_extract(a, &src, i, &o->o, (const u8 *)pw, pw ? strlen(pw) : 0, z);
            if (r && !o->status[i]) o->status[i] = r;
        }
    }
    char nm[8192];
    for (u32 i = 0; i < a->n; i++) {
        to_utf8(a->e[i].name, nm);
        int s = o->status[i] == 100 ? 0 : (o->status[i] ? o->status[i] : -1);
        printf("%u\t%d\t%d\t%llu\t%s\n", i, s, a->e[i].is_dir, (unsigned long long)a->e[i].usize, nm);
    }
    if (a->comment) { to_utf8(a->comment, nm); fprintf(stderr, "comment: %s\n", nm); }
    gz_arc_close(a);
    gz_inflater_free(z);
    return 0;
}
