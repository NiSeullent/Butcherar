/*
 * arc_random <archive> <outdir> <fwd|rev|shuffle> [seed]
 *
 * Extracts every entry on its own with gz_arc_extract (the random-access path,
 * even for solid formats) in the given order and prints a gzt-style manifest:
 *   n <TAB> status <TAB> is_dir <TAB> size <TAB> name
 */
#include "arc.h"
#include "cpu.h"
#include "crc32.h"
#include "plat_posix.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

typedef struct { gz_out o; const char *dir; FILE *f; } t_out;

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
    (void)idx; (void)st;
    if (t->f) fclose(t->f);
    t->f = 0;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 4) return 2;
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_aes_init();
    gz_dispatch_init(-1);
    gz_src *src = gz_posix_open_src(argv[1]);
    if (!src) { perror(argv[1]); return 1; }
    gzch *wname = gz_posix_wide(argv[1]);
    gz_open_opts oo;
    memset(&oo, 0, sizeof oo);
    oo.file_name = wname;
    oo.open_volume = gz_posix_open_volume;
    gz_ctx *c = gz_ctx_new();
    gz_archive *a;
    int r = gz_arc_open(&a, src, &oo, c);
    if (r) {
        printf("OPEN_ERROR %d\n", r);
        gz_ctx_free(c);
        gz_src_free(src);
        free(wname);
        return 1;
    }
    mkdir(argv[2], 0755);
    u32 *order = (u32 *)malloc((a->n + 1) * sizeof(u32));
    for (u32 i = 0; i < a->n; i++) order[i] = i;
    if (!strcmp(argv[3], "rev")) {
        for (u32 i = 0; i < a->n / 2; i++) { u32 t = order[i]; order[i] = order[a->n - 1 - i]; order[a->n - 1 - i] = t; }
    } else if (!strcmp(argv[3], "shuffle")) {
        srand(argc > 4 ? atoi(argv[4]) : 1);
        for (u32 i = a->n; i > 1; i--) { u32 j = (u32)rand() % i, t = order[i - 1]; order[i - 1] = order[j]; order[j] = t; }
    }
    int *st = (int *)calloc(a->n + 1, sizeof(int));
    t_out o = { { o_open, o_write, o_close, 0 }, argv[2], 0 };
    for (u32 k = 0; k < a->n; k++) st[order[k]] = gz_arc_extract(a, src, order[k], &o.o, c);
    for (u32 i = 0; i < a->n; i++) {
        char *nm = gz_posix_utf8(a->e[i].name);
        unsigned long long sz = a->e[i].usize == GZ_SIZE_UNKNOWN ? 0 : (unsigned long long)a->e[i].usize;
        printf("%u\t%d\t%d\t%llu\t%s\n", i, st[i], a->e[i].is_dir, sz, nm);
        free(nm);
    }
    gz_arc_close(a);
    gz_src_free(src);
    gz_ctx_free(c);
    free(wname);
    free(order);
    free(st);
    return 0;
}
