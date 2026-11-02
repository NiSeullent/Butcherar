/*
 * win_selmask - the Windows main window's "selected folders -> entries" mask
 * (src/win/selmask.c), built natively against the host core
 *
 *   win_selmask check <archive> <seed> <rounds>
 *       compares sel_mask_folders with the former per-folder scan of every entry name
 *       (folder name as an ASCII case-folded prefix followed by '/' or the end) for
 *       each folder alone and for <rounds> random sets of folders.
 *       Prints "ok folders=<n> entries=<n> rounds=<n>" or the first difference.
 *   win_selmask time <archive>
 *       selects every folder directly under the root (Ctrl+A in the main window);
 *       prints "ms=<t> selected=<n> entries=<n>"
 */
#include "arc.h"
#include "cpu.h"
#include "crc32.h"
#include "inflate.h"
#include "crypto.h"
#include "plat_posix.h"
#include "../../src/win/selmask.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static u64 g_rng = 88172645463325252ull;
static u64 rnd(void)
{
    g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17;
    return g_rng;
}

/* the algorithm the main window used before (mainwnd.c collect_selection) */
static int prefix_ieq(const gzch *s, const gzch *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        gzch x = s[i], y = p[i];
        if (x >= 'A' && x <= 'Z') x += 32;
        if (y >= 'A' && y <= 'Z') y += 32;
        if (x != y || !x) return 0;
    }
    return 1;
}

static void ref_mask(const gz_archive *a, const i32 *sel, u32 nsel, u8 *m)
{
    for (u32 i = 0; i < nsel; i++) {
        const gzch *fn = a->f[sel[i]].name;
        size_t fl = gz_wcslen(fn);
        for (u32 k = 0; k < a->n; k++) {
            const gzch *n = a->e[k].name;
            if (prefix_ieq(n, fn, fl) && (n[fl] == '/' || n[fl] == 0)) m[k] = 1;
        }
    }
}

static int compare(const gz_archive *a, const i32 *sel, u32 nsel, u8 *m1, u8 *m2)
{
    memset(m1, 0, a->n + 1);
    memset(m2, 0, a->n + 1);
    if (sel_mask_folders(a, sel, nsel, m1)) { printf("sel_mask_folders failed\n"); return 1; }
    ref_mask(a, sel, nsel, m2);
    for (u32 k = 0; k < a->n; k++) {
        if (m1[k] == m2[k]) continue;
        char nm[512];
        int l = gz_utf16_to_utf8(a->e[k].name, gz_wcslen(a->e[k].name) < 160 ? gz_wcslen(a->e[k].name) : 160, (u8 *)nm);
        nm[l > 0 ? l : 0] = 0;
        printf("DIFF entry %u '%s' (dir %d): new %d, before %d; %u folder(s) selected, first '%u'\n", k, nm,
               a->e[k].is_dir, m1[k], m2[k], nsel, (unsigned)sel[0]);
        return 1;
    }
    return 0;
}

static int open_arc(const char *path, gz_archive **pa, gz_src **ps, gz_ctx **pc)
{
    gz_src *src = gz_posix_open_src(path);
    if (!src) { perror(path); return 1; }
    gzch *wname = gz_posix_wide(path);
    gz_ctx *c = gz_ctx_new();
    gz_open_opts oo;
    memset(&oo, 0, sizeof oo);
    oo.file_name = wname;
    oo.open_volume = gz_posix_open_volume;
    int r = gz_arc_open(pa, src, &oo, c);
    free(wname);
    if (r) { printf("OPEN_ERROR %d\n", r); gz_src_free(src); gz_ctx_free(c); return 1; }
    *ps = src;
    *pc = c;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr, "usage: win_selmask check|time <archive> [seed rounds]\n"); return 2; }
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_aes_init();
    gz_dispatch_init(-1);
    gz_archive *a;
    gz_src *s;
    gz_ctx *c;
    if (open_arc(argv[2], &a, &s, &c)) return 1;
    u8 *m1 = (u8 *)malloc(a->n + 1), *m2 = (u8 *)malloc(a->n + 1);
    i32 *sel = (i32 *)malloc((a->nf + 1) * sizeof(i32));
    int bad = 0;
    if (!strcmp(argv[1], "check") && argc > 4) {
        g_rng ^= (u64)strtoul(argv[3], 0, 10) * 0x9E3779B97F4A7C15ull;
        u32 rounds = (u32)strtoul(argv[4], 0, 10);
        for (u32 f = 1; f < a->nf && !bad; f++) { sel[0] = (i32)f; bad = compare(a, sel, 1, m1, m2); }
        for (u32 r = 0; r < rounds && !bad && a->nf > 1; r++) {
            u32 n = 1 + (u32)(rnd() % (a->nf - 1 < 40 ? a->nf - 1 : 40));
            for (u32 i = 0; i < n; i++) sel[i] = (i32)(1 + rnd() % (a->nf - 1));     /* repeats allowed */
            bad = compare(a, sel, n, m1, m2);
        }
        if (!bad) printf("ok folders=%u entries=%u rounds=%u\n", a->nf, a->n, rounds);
    } else if (!strcmp(argv[1], "time")) {
        u32 n = 0;
        for (i32 f = a->f[0].first_sub; f >= 0 && n < a->nf; f = a->f[f].next_sib) sel[n++] = f;
        memset(m1, 0, a->n + 1);
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        bad = sel_mask_folders(a, sel, n, m1) != GZ_OK;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        u32 cnt = 0;
        for (u32 k = 0; k < a->n; k++) cnt += m1[k];
        printf("ms=%.1f folders=%u selected=%u entries=%u\n",
               (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6, n, cnt, a->n);
    } else {
        fprintf(stderr, "bad arguments\n");
        bad = 2;
    }
    free(m1);
    free(m2);
    free(sel);
    gz_arc_close(a);
    gz_src_free(s);
    gz_ctx_free(c);
    return bad;
}
