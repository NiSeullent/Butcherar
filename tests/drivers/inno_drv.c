/*
 * inno_drv - Inno Setup reader test driver (includes src/fmt/inno.c to reach its internals)
 *
 *   inno_drv info <installer>
 *       loader offsets, data version, header counts and the layout that parsed
 *   inno_drv layout <installer>
 *       key=value positions used by the fixture synthesizer in fmt_inno.py
 *   inno_drv list <installer> [password]
 *       idx <TAB> is_dir <TAB> usize <TAB> csize <TAB> method <TAB> filetime <TAB> attr <TAB> name
 *   inno_drv subsets <installer> [password]
 *       SHA-1 of every entry from a full pass, then from single-entry extraction and
 *       from extract_solid with several selections (skipped and cancelled entries
 *       included): all must agree; prints "ok <entries>"
 *   inno_drv fuzz <installer> <iterations> <seed>
 *       mutation fuzzer (bit flips, smashed 32-bit fields, truncation) over the header
 *       blocks and the file data; prints "ok <iterations> opened=<n>"
 *   inno_drv filter <kind> <in> <out>
 *       apply the call-instruction decoder (4108 / 5200 / 5309) to a file
 *   inno_drv hash <in>
 *       MD5 of a file (checks the private MD5)
 */
#define gz_fmt_inno gz_fmt_inno_drv
#include "../../src/fmt/inno.c"
#undef gz_fmt_inno
#include "cpu.h"
#include "plat_posix.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static u8 *load(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    fseek(f, 0, SEEK_END);
    *n = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);
    u8 *p = (u8 *)malloc(*n + 1);
    if (fread(p, 1, *n, f) != *n) exit(2);
    fclose(f);
    return p;
}

static void init_core(void)
{
    gz_cpu_detect();
    gz_crc32_init();
    gz_inflate_init();
    gz_aes_init();
    gz_dispatch_init(-1);
}

static gzch g_pw[256];

static gz_archive *open_src(gz_src *s, gz_ctx *c, int *err, const char *path)
{
    gz_archive *a = 0;
    gz_open_opts o;
    memset(&o, 0, sizeof o);
    gzch *wn = path ? gz_posix_wide(path) : 0;
    o.file_name = wn;
    o.open_volume = gz_posix_open_volume;
    *err = gz_arc_open(&a, s, &o, c);
    free(wn);
    if (!*err && strcmp(gz_arc_type_name(a), "Inno Setup")) { *err = -1; gz_arc_close(a); return 0; }
    return *err ? 0 : a;
}

static int cmd_info(const char *path)
{
    gz_src *s = gz_posix_open_src(path);
    if (!s) return 2;
    gz_ctx *c = gz_ctx_new();
    u64 o0 = 0, o1 = 0;
    int r = ino_locate(s, &o0, &o1);
    printf("locate %d o0=%llu o1=%llu size=%llu\n", r, (unsigned long long)o0, (unsigned long long)o1,
           (unsigned long long)s->size);
    if (r) return 1;
    u8 vs[64];
    gz_src_read_exact(s, o0, vs, 64);
    u32 v, hl;
    u8 uni, isx;
    r = parse_version(vs, &v, &uni, &isx, &hl);
    printf("version %d %u.%u.%u.%u uni=%d isx=%d '%.*s'\n", r, v >> 24, (v >> 16) & 255, (v >> 8) & 255,
           v & 255, uni, isx, (int)strnlen((char *)vs, 64), (char *)vs);
    if (r) return 1;
    u64 pos = o0 + hl + (v >= V(6, 5, 0) ? 53 : 0);
    u32 tv = v, variant = (u32)uni | (u32)isx << 1;
    for (int t = 0; t < 6 && tv; t++, tv = next_version(tv, variant)) {
        u8 *b0, *b1;
        size_t n0, n1;
        r = load_headers(s, pos, tv, c, &b0, &n0, &b1, &n1);
        printf("try %u.%u.%u.%u: blocks %d n0=%zu n1=%zu", tv >> 24, (tv >> 16) & 255, (tv >> 8) & 255, tv & 255,
               r, r ? 0 : n0, r ? 0 : n1);
        if (r) { printf("\n"); continue; }
        ino_parse P;
        memset(&P, 0, sizeof P);
        int pr = parse_all(&P, b0, n0, b1, n1, tv, uni, isx);
        /* where did it stop? re-run the header only */
        ird rr = { b0, b0 + n0, b0, tv, uni, isx, 0, 0 };
        ino_hdr h;
        parse_header(&rr, &h);
        printf(" parse=%d hdr_end=%zu bad=%d comp=%d files=%u data=%u dirs=%u langs=%u msgs=%u types=%u comps=%u tasks=%u icons=%u ini=%u reg=%u del=%u/%u run=%u/%u enc=%d\n",
               pr, (size_t)(rr.p - b0), rr.bad, h.comp, h.n_file, h.n_data, h.n_dir, h.n_lang, h.n_msg, h.n_type,
               h.n_comp, h.n_task, h.n_icon, h.n_ini, h.n_reg, h.n_del, h.n_udel, h.n_run, h.n_urun, h.enc_used);
        parse_free(&P);
        free(b0); free(b1);
        if (!pr) break;
    }
    gz_src_free(s);
    gz_ctx_free(c);
    return 0;
}

/* field positions for the test fixture synthesizer (fmt_inno.py) */
static int cmd_layout(const char *path)
{
    gz_src *s = gz_posix_open_src(path);
    if (!s) return 2;
    gz_ctx *c = gz_ctx_new();
    gz_archive *a;
    int err;
    a = open_src(s, c, &err, path);
    if (!a) { printf("OPEN_ERROR %d\n", err); return 1; }
    const ino_priv *p = (const ino_priv *)a->priv;
    u64 o0, o1, tab = 0;
    ino_locate(s, &o0, &o1);
    u8 b[12];
    if (!gz_src_read_exact(s, 0x30, b, 12) && rd32(b) == 0x6f6e6e49u && rd32(b + 4) == ~rd32(b + 8)) tab = rd32(b + 4);
    else find_rcdata(s, &tab);
    u8 vs[64];
    gz_src_read_exact(s, o0, vs, 64);
    u32 v, hl;
    u8 uni, isx;
    parse_version(vs, &v, &uni, &isx, &hl);
    u64 pos = o0 + hl + (p->ver >= V(6, 5, 0) ? 53 : 0), b0pos = pos;
    u8 *b0, *b1;
    size_t n0, n1;
    read_block(s, &pos, p->ver, c, &b0, &n0);
    u64 b1pos = pos;
    read_block(s, &pos, p->ver, c, &b1, &n1);
    ino_parse P;
    memset(&P, 0, sizeof P);
    parse_all(&P, b0, n0, b1, n1, p->ver, uni, isx);
    printf("ver=%u uni=%d isx=%d hl=%u o0=%llu o1=%llu table=%llu blk0=%llu blk1=%llu end=%llu n0=%zu n1=%zu "
           "ndata=%u comp=%d at_comp=%u at_pw=%u at_flags=%u enc_bit=%u enc=%d at_lead=%u lead=%d\n",
           p->ver, uni, isx, hl, (unsigned long long)o0, (unsigned long long)o1, (unsigned long long)tab,
           (unsigned long long)b0pos, (unsigned long long)b1pos, (unsigned long long)pos, n0, n1, P.ndt, P.h.comp,
           P.h.at_comp, P.h.at_pw, P.h.at_flags, P.h.enc_bit, P.h.enc_used, P.h.at_lead, P.h.has_lead);
    /* file entries: positions of the destination and Languages strings (length prefix) */
    for (u32 i = 0; i < P.nf; i++)
        printf("file %u dst=%zu dn=%u lang=%zu ln=%u loc=%u\n", i, (size_t)(P.f[i].dst - b0) - 4, P.f[i].dn,
               P.f[i].lang ? (size_t)(P.f[i].lang - b0) - 4 : (size_t)0, P.f[i].ln, P.f[i].loc);
    parse_free(&P);
    gz_free(b0); gz_free(b1);
    gz_arc_close(a);
    gz_src_free(s);
    gz_ctx_free(c);
    return 0;
}

static void to_utf8(const gzch *w, char *o, size_t cap)
{
    size_t n = gz_wcslen(w);
    if (n * 3 + 1 > cap) n = (cap - 1) / 3;
    int k = gz_utf16_to_utf8(w, n, (u8 *)o);
    o[k] = 0;
}

static int cmd_list(const char *path)
{
    gz_src *s = gz_posix_open_src(path);
    if (!s) return 2;
    gz_ctx *c = gz_ctx_new();
    int err;
    gz_archive *a = open_src(s, c, &err, path);
    if (!a) { printf("OPEN_ERROR %d\n", err); return 1; }
    printf("TYPE\t%s\t%u\tsolid=%d\n", gz_arc_type_name(a), a->n, a->solid);
    char nm[4096];
    for (u32 i = 0; i < a->n; i++) {
        gz_entry *e = &a->e[i];
        gzch mw[96];
        char m[300];
        gz_arc_method(a, e, mw, 96);
        to_utf8(mw, m, sizeof m);
        to_utf8(e->name, nm, sizeof nm);
        printf("%u\t%d\t%lld\t%lld\t%s\t%llu\t%x\t%s\n", i, e->is_dir,
               e->usize == GZ_SIZE_UNKNOWN ? -1LL : (long long)e->usize,
               e->csize == GZ_SIZE_UNKNOWN ? -1LL : (long long)e->csize, m,
               (unsigned long long)e->mtime, e->attr, nm);
    }
    gz_arc_close(a);
    gz_src_free(s);
    gz_ctx_free(c);
    return 0;
}

/* ---- hashing output ---- */

typedef struct {
    gz_out o;
    u32 n;
    gz_sha1 *h;
    int *st;            /* -1 never opened, -2 open, else close status */
    u64 *size;
    long cancel_after;  /* cancel when this many entries were closed (-1 = never) */
    long closed;
    volatile long *cancel;
    u8 *skip;           /* open returns GZ_E_SKIP */
    int bad;            /* protocol violation */
} h_out;

static int h_open(gz_out *o, u32 idx)
{
    h_out *h = (h_out *)o;
    if (idx >= h->n) { h->bad = 1; return GZ_E_IO; }
    if (h->st[idx] == -2) h->bad = 1;
    if (h->skip && h->skip[idx]) return GZ_E_SKIP;
    gz_sha1_init(&h->h[idx]);
    h->size[idx] = 0;
    h->st[idx] = -2;
    return GZ_OK;
}

static int h_write(gz_out *o, const u8 *p, size_t n)
{
    h_out *h = (h_out *)o;
    for (u32 i = 0; i < h->n; i++)
        if (h->st[i] == -2) { gz_sha1_update(&h->h[i], p, n); h->size[i] += n; return GZ_OK; }
    h->bad = 1;
    return GZ_OK;
}

static int h_close(gz_out *o, u32 idx, int st)
{
    h_out *h = (h_out *)o;
    if (idx >= h->n || h->st[idx] != -2) { h->bad = 1; return GZ_OK; }
    h->st[idx] = st;
    h->closed++;
    if (h->cancel_after >= 0 && h->closed >= h->cancel_after && h->cancel) *h->cancel = 1;
    return GZ_OK;
}

static h_out *h_new(u32 n)
{
    h_out *h = (h_out *)calloc(1, sizeof *h);
    h->o.open = h_open; h->o.write = h_write; h->o.close = h_close;
    h->n = n;
    h->h = (gz_sha1 *)calloc(n + 1, sizeof(gz_sha1));
    h->st = (int *)malloc((n + 1) * sizeof(int));
    h->size = (u64 *)calloc(n + 1, sizeof(u64));
    for (u32 i = 0; i < n; i++) h->st[i] = -1;
    h->cancel_after = -1;
    return h;
}

static void h_free(h_out *h)
{
    free(h->h); free(h->st); free(h->size); free(h->skip); free(h);
}

static void h_digest(h_out *h, u32 i, u8 d[20])
{
    gz_sha1 t = h->h[i];
    gz_sha1_final(&t, d);
}

static int cmd_subsets(const char *path)
{
    gz_src *s = gz_posix_open_src(path);
    if (!s) return 2;
    gz_ctx *c = gz_ctx_new();
    if (g_pw[0]) c->password = g_pw;
    int err;
    gz_archive *a = open_src(s, c, &err, path);
    if (!a) { printf("OPEN_ERROR %d\n", err); return 1; }
    u32 n = a->n;
    u8 *sel = (u8 *)calloc(n + 1, 1);
    memset(sel, 1, n);
    h_out *full = h_new(n);
    int r = gz_arc_extract_solid(a, s, sel, &full->o, c);
    if (r || full->bad) { printf("FAIL full pass r=%d bad=%d\n", r, full->bad); return 1; }
    int fails = 0;
    for (u32 i = 0; i < n; i++) {
        if (full->st[i] != 0) { printf("FAIL entry %u status %d\n", i, full->st[i]); fails++; }
        else if (!a->e[i].is_dir && full->size[i] != a->e[i].usize) { printf("FAIL entry %u size\n", i); fails++; }
    }
    /* single entries (a sample when there are many) */
    u32 step = n > 64 ? n / 64 : 1;
    for (u32 i = 0; i < n; i += step) {
        h_out *one = h_new(n);
        r = gz_arc_extract(a, s, i, &one->o, c);
        u8 d1[20], d2[20];
        h_digest(full, i, d1);
        h_digest(one, i, d2);
        if (r || one->bad || one->st[i] != 0 || memcmp(d1, d2, 20)) {
            printf("FAIL single %u r=%d st=%d bad=%d\n", i, r, one->st[i], one->bad);
            fails++;
        }
        for (u32 k = 0; k < n; k++) if (k != i && one->st[k] != -1) { printf("FAIL single %u touched %u\n", i, k); fails++; break; }
        h_free(one);
    }
    /* selections: every other entry, last half, random subsets with skipped entries */
    srand(1);
    for (int t = 0; t < 6; t++) {
        memset(sel, 0, n);
        for (u32 i = 0; i < n; i++)
            sel[i] = t == 0 ? (i & 1) : t == 1 ? i >= n / 2 : (rand() % 3 == 0);
        h_out *part = h_new(n);
        part->skip = (u8 *)calloc(n + 1, 1);
        if (t >= 3) for (u32 i = 0; i < n; i++) part->skip[i] = rand() % 4 == 0;
        r = gz_arc_extract_solid(a, s, sel, &part->o, c);
        if (r || part->bad) { printf("FAIL subset %d r=%d bad=%d\n", t, r, part->bad); fails++; }
        for (u32 i = 0; i < n; i++) {
            int want = sel[i] && !part->skip[i];
            if (!want) {
                if (part->st[i] != -1) { printf("FAIL subset %d: %u touched\n", t, i); fails++; }
                continue;
            }
            u8 d1[20], d2[20];
            h_digest(full, i, d1);
            h_digest(part, i, d2);
            if (part->st[i] != 0 || memcmp(d1, d2, 20)) { printf("FAIL subset %d entry %u st=%d\n", t, i, part->st[i]); fails++; }
        }
        h_free(part);
    }
    /* cancel after a few entries */
    {
        volatile long cancel = 0;
        h_out *cc = h_new(n);
        cc->cancel = &cancel;
        cc->cancel_after = n / 3 + 1;
        c->cancel = &cancel;
        memset(sel, 1, n);
        r = gz_arc_extract_solid(a, s, sel, &cc->o, c);
        c->cancel = 0;
        if (n > 3 && r != GZ_E_CANCEL) { printf("FAIL cancel r=%d\n", r); fails++; }
        if (cc->bad) { printf("FAIL cancel protocol\n"); fails++; }
        h_free(cc);
    }
    for (u32 i = 0; i < n; i++) {
        u8 d[20];
        h_digest(full, i, d);
        printf("H\t%u\t", i);
        for (int k = 0; k < 20; k++) printf("%02x", d[k]);
        printf("\n");
    }
    if (!fails) printf("ok %u\n", n);
    h_free(full);
    free(sel);
    gz_arc_close(a);
    gz_src_free(s);
    gz_ctx_free(c);
    return fails ? 1 : 0;
}

/* ---- fuzz ---- */

static u64 rng_state;
static u32 rnd(void)
{
    rng_state = rng_state * 6364136223846793005ull + 1442695040888963407ull;
    return (u32)(rng_state >> 33);
}

typedef struct { gz_out o; u64 bytes; int open; int bad; } f_out;
static int f_open(gz_out *o, u32 idx) { f_out *f = (f_out *)o; if (f->open) f->bad = 1; f->open = 1; (void)idx; return GZ_OK; }
static int f_write(gz_out *o, const u8 *p, size_t n)
{
    f_out *f = (f_out *)o;
    (void)p;
    if (!f->open) f->bad = 1;
    f->bytes += n;
    return f->bytes > ((u64)1 << 31) ? GZ_E_LIMIT : GZ_OK;
}
static int f_close(gz_out *o, u32 idx, int st) { f_out *f = (f_out *)o; if (!f->open) f->bad = 1; f->open = 0; (void)idx; (void)st; return GZ_OK; }

static int cmd_fuzz(const char *path, long iters, u64 seed)
{
    size_t n;
    u8 *orig = load(path, &n);
    rng_state = seed;
    /* regions: the header blocks (o0 ..) and the start of the data */
    gz_src *s0 = gz_src_mem(orig, n, 0);
    u64 o0 = 0, o1 = 0;
    if (ino_locate(s0, &o0, &o1)) { printf("not inno\n"); return 1; }
    gz_src_free(s0);
    long opened = 0;
    u8 *buf = (u8 *)malloc(n + 1);
    for (long it = 0; it < iters; it++) {
        memcpy(buf, orig, n);
        size_t len = n;
        int kind = (int)(rnd() % 6);
        u64 lo = o0, hi = n;
        if (kind == 5 && o1) { lo = o1; hi = o1 + 4096 < n ? o1 + 4096 : n; }
        else if (rnd() & 1) hi = o0 + 2048 < n ? o0 + 2048 : n;
        int muts = 1 + (int)(rnd() % 4);
        for (int m = 0; m < muts; m++) {
            size_t at = (size_t)(lo + rnd() % (hi - lo));
            switch (kind) {
            case 0: buf[at] ^= (u8)(1u << (rnd() % 8)); break;
            case 1: buf[at] = (u8)rnd(); break;
            case 2: if (at + 4 <= n) wr32(buf + at, rnd() % 3 == 0 ? 0xFFFFFFFFu : rnd() % 2 ? rnd() : rnd() % 4096); break;
            case 3: len = (size_t)(lo + rnd() % (n - lo)); break;
            default: buf[at] ^= (u8)(1u << (rnd() % 8)); break;
            }
        }
        gz_src *s = gz_src_mem(buf, len, 0);
        gz_ctx *c = gz_ctx_new();
        gz_archive *a = 0;
        gz_open_opts o;
        memset(&o, 0, sizeof o);
        /* the reader directly: other formats would claim mutated files */
        a = (gz_archive *)gz_alloc(sizeof(gz_archive));
        a->fmt = &gz_fmt_inno_drv;
        int r = gz_fmt_inno_drv.open(a, s, &o, c);
        if (!r) r = gz_arc_build_tree(a);
        if (!r) {
            opened++;
            f_out f;
            memset(&f, 0, sizeof f);
            f.o.open = f_open; f.o.write = f_write; f.o.close = f_close;
            u8 *sel = (u8 *)calloc(a->n + 1, 1);
            memset(sel, 1, a->n);
            gz_fmt_inno_drv.extract_solid(a, s, sel, &f.o, c);
            for (u32 i = 0; i < a->n && i < 8; i++) gz_fmt_inno_drv.extract(a, s, (u32)(rnd() % a->n), &f.o, c);
            if (f.bad || f.open) { printf("FAIL protocol at iteration %ld\n", it); return 1; }
            free(sel);
        }
        if (a->fmt && a->fmt->close) a->fmt->close(a);
        gz_free(a->e); gz_free(a->f); gz_free(a->raw); gz_free(a->fhash);
        for (u32 i = 0; i < a->nvols; i++) gz_src_free(a->vols[i]);
        gz_free(a->vols);
        gz_arena_free(&a->names);
        gz_free(a);
        gz_ctx_free(c);
        gz_src_free(s);
    }
    printf("ok %ld opened=%ld\n", iters, opened);
    free(buf);
    free(orig);
    return 0;
}

static int cmd_filter(const char *kind, const char *in, const char *outp)
{
    size_t n;
    u8 *p = load(in, &n);
    ino_fo f;
    memset(&f, 0, sizeof f);
    f.filter = !strcmp(kind, "4108") ? FI_4108 : !strcmp(kind, "5200") ? FI_5200 : FI_5309;
    f.f_off = f.filter == FI_4108 ? 5 : 0;
    f.fbuf = (u8 *)malloc(FBUF + 8);
    f.ck_type = CK_NONE;
    FILE *o = fopen(outp, "wb");
    if (!o) return 2;
    size_t off = 0;
    u8 *res = (u8 *)malloc(n + 16);
    size_t rn = 0;
    while (off < n) {
        /* odd-sized pieces exercise the carry; same steps as fo_write without an output */
        size_t k = 1 + rnd() % 70000;
        if (k > n - off) k = n - off;
        const u8 *q = p + off;
        size_t left = k;
        while (left) {
            size_t t = GZ_MIN(left, (size_t)FBUF - f.f_hold);
            memcpy(f.fbuf + f.f_hold, q, t);
            q += t; left -= t;
            size_t tot = f.f_hold + t, done;
            if (f.filter == FI_4108) { filt_4108(&f, f.fbuf, tot); done = tot; }
            else done = filt_5200(&f, f.fbuf, tot, 0);
            memcpy(res + rn, f.fbuf, done); rn += done;
            f.f_hold = (u32)(tot - done);
            if (f.f_hold) memmove(f.fbuf, f.fbuf + done, f.f_hold);
        }
        off += k;
    }
    if (f.f_hold) { size_t d = filt_5200(&f, f.fbuf, f.f_hold, 1); memcpy(res + rn, f.fbuf, d); rn += d; }
    fwrite(res, 1, rn, o);
    fclose(o);
    printf("ok %zu\n", rn);
    free(res); free(p); free(f.fbuf);
    return 0;
}

static int cmd_hash(const char *in)
{
    size_t n;
    u8 *p = load(in, &n);
    ino_md5 m;
    u8 d[16];
    md5_init(&m);
    /* uneven pieces */
    size_t off = 0;
    while (off < n) { size_t k = 1 + rnd() % 200; if (k > n - off) k = n - off; md5_update(&m, p + off, k); off += k; }
    md5_final(&m, d);
    for (int i = 0; i < 16; i++) printf("%02x", d[i]);
    printf(" %08x\n", adler32(1, p, n));
    free(p);
    return 0;
}

int main(int argc, char **argv)
{
    init_core();
    if (argc < 3) return 2;
    rng_state = 12345;
    if (!strcmp(argv[1], "info")) return cmd_info(argv[2]);
    if (!strcmp(argv[1], "layout")) return cmd_layout(argv[2]);
    if ((!strcmp(argv[1], "list") || !strcmp(argv[1], "subsets")) && argc > 3) {
        gzch *w = gz_posix_wide(argv[3]);
        size_t i = 0;
        for (; w[i] && i + 1 < GZ_COUNTOF(g_pw); i++) g_pw[i] = w[i];
        g_pw[i] = 0;
        free(w);
    }
    if (!strcmp(argv[1], "list")) return cmd_list(argv[2]);
    if (!strcmp(argv[1], "subsets")) return cmd_subsets(argv[2]);
    if (!strcmp(argv[1], "fuzz") && argc > 4) return cmd_fuzz(argv[2], atol(argv[3]), (u64)atoll(argv[4]));
    if (!strcmp(argv[1], "filter") && argc > 4) return cmd_filter(argv[2], argv[3], argv[4]);
    if (!strcmp(argv[1], "hash")) return cmd_hash(argv[2]);
    return 2;
}
